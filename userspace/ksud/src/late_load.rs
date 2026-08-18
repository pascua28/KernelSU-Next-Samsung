use anyhow::{Context, Result};
use log::{info, warn};
use rustix::cstr;

use crate::module::{handle_updated_modules, prune_modules};
use crate::{assets, defs, init_event, metamodule, restorecon, utils};

fn dump_process_info(label: &str) {
    use rustix::process::{getgid, getgroups, getpid, getuid};

    let pid = getpid().as_raw_nonzero();
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    let groups: Vec<String> = getgroups()
        .unwrap_or_default()
        .iter()
        .map(|g| g.as_raw().to_string())
        .collect();
    let selinux = std::fs::read_to_string("/proc/self/attr/current")
        .unwrap_or_else(|_| "unknown".to_string());
    let seccomp = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Seccomp:"))
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    info!(
        "[{label}] pid={pid}, uid={uid}, gid={gid}, groups=[{}], selinux={}, {seccomp}",
        groups.join(","),
        selinux.trim(),
    );
}

pub fn run(_package_name: &String, kmi: Option<String>, allow_shell: bool) -> Result<()> {
    info!("late-load command triggered!");
    dump_process_info("late-load start");

    // Copy the daemon before loading the module changes this process's
    // security context. The remaining install steps require KernelSU policy.
    utils::stage_daemon_from("/data/local/tmp/.ksud-stage").context("Failed to stage ksud")?;

    // 1. Check if KernelSU is already loaded
    if ksuinit::has_kernelsu() {
        info!("KernelSU already loaded, skip loading ko");
    } else {
        // 2. Detect current KMI version
        let kmi = kmi.map_or_else(
            || crate::boot_patch::get_current_kmi().context("Failed to detect current KMI version"),
            Ok,
        )?;
        info!("Detected KMI: {kmi}");


        // 3. Get kernelsu.ko from embedded assets
        let ko_name = format!("{kmi}_kernelsu.ko");
        let ko_data = assets::get_asset_data(&ko_name)
            .with_context(|| format!("Failed to get {ko_name} from assets"))?;

        // 4. Load kernelsu.ko from memory with manual relocation
        info!("Loading kernelsu.ko for KMI {kmi}...");
        let params = if allow_shell {
            cstr!("allow_shell=1")
        } else {
            cstr!("")
        };
        ksuinit::load_module(&ko_data, params).context("Failed to load kernelsu.ko")?;
        info!("kernelsu.ko loaded successfully!");
        dump_process_info("after load_module");
    }

    // Say what the module actually reports, now that it is in. Everything
    // below can fail without KernelSU being at fault, and the caller's
    // descriptors stop working the moment the sepolicy is reloaded, so this
    // is the one line that says "it is loaded and answering" somewhere that
    // survives.
    {
        let info = crate::ksucalls::get_info();
        info!(
            "KernelSU live: version={} uapi={} flags=0x{:x} features=0x{:x} late_load={}",
            crate::ksucalls::get_version(),
            info.uapi_version,
            info.flags,
            info.features,
            crate::ksucalls::is_late_load()
        );
    }

    // Rejoin init's mount namespace before touching modules.
    //
    // A late-load is exec'd from a throwaway private namespace: the caller has
    // to unshare(CLONE_NEWNS) to bind-mount this binary over a path it is
    // allowed to exec, and marks / as MS_REC|MS_PRIVATE so that cover does not
    // escape. Everything below -- the metamodule mount, and every module
    // script, which inherits this namespace -- would then run against mounts
    // that die with this process, while the daemons those scripts start keep
    // running and expect them. At boot ksud is already in init's namespace and
    // none of this arises; rejoining reproduces that.
    if let Err(e) = utils::switch_mnt_ns(1) {
        warn!("failed to rejoin init mount namespace: {e}");
    }

    // We need to reset stdin/stdout/stderr; otherwise, sending file descriptors via cmd transactions
    // will be blocked by SELinux because its fsec->sid is still u:r:su:s0 instead of u:r:ksu:s0.
    utils::reset_std()?;

    utils::umask(0);

    if let Err(e) = crate::module_config::clear_all_temp_configs() {
        warn!("clear temp configs failed: {e}");
    }

    utils::finish_install(None).context("Failed to finish ksud installation")?;

    // 5. Handle module updates
    if let Err(e) = handle_updated_modules() {
        warn!("handle updated modules failed: {e}");
    }

    if let Err(e) = prune_modules() {
        warn!("prune modules failed: {e}");
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {e}");
    }

    // 6. Load SELinux rules
    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    if let Err(e) = crate::profile::apply_sepolies() {
        warn!("apply root profile sepolicy failed: {e}");
    }

    // 7. Initialize features
    if let Err(e) = crate::feature::init_features() {
        warn!("init features failed: {e}");
    }

    // 8. Execute late-load stage scripts (blocking)
    //
    // Module stage scripts assume the environment a boot gives them: their
    // module mounts already established, and no framework running yet. A
    // late-load can offer neither. What they do instead is start daemons --
    // a Zygisk implementation, LSPosed's lspd, Sui -- against a zygote that
    // is already serving, and those daemons restart it to inject. On warhol
    // that reliably kills system_server: it comes back up and dies in
    // ApplicationSharedMemory.nativeCreate with ENOENT, every time, until
    // the device is rebooted.
    //
    // So they are off unless asked for. KernelSU itself -- su, the manager,
    // the allowlist -- needs none of this; only modules do, and a module
    // that a late-load cannot mount is not one this should be starting.
    let run_module_scripts = std::env::var("KSU_LATE_LOAD_MODULES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !run_module_scripts {
        warn!(
            "late-load: skipping module stage scripts (set KSU_LATE_LOAD_MODULES=1 to run them)"
        );
    }

    if run_module_scripts {
        init_event::run_stage("late-load", true);
    }

    // 9. Load system.prop
    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {e}");
    }

    // 10. Execute metamodule mount script (OverlayFS)
    if let Err(e) = metamodule::exec_mount_script(defs::MODULE_DIR) {
        warn!("execute metamodule mount failed: {e}");
    }

    // 11. Execute post-mount stage scripts (blocking)
    if run_module_scripts {
        init_event::run_stage("post-mount", true);
    }

    // 12. Execute service stage scripts (non-blocking)
    if run_module_scripts {
        init_event::run_stage("service", false);
    }

    // 13. Execute boot-completed stage scripts (non-blocking)
    if run_module_scripts {
        init_event::run_stage("boot-completed", false);
    }

    Ok(())
}
