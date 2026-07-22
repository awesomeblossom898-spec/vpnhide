use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::CString;
use std::fs;
use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::raw::{c_char, c_int, c_long, c_void};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::ptr;
use std::thread;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::Deserialize;
use vpnhide_protocol::Target;
use vpnhide_protocol::hook_ids::{HOOK_NAMES, KERNEL_HOOK_MASK, KPM_HOOK_MASK, ZYGISK_HOOK_MASK};
use vpnhide_protocol::{
    Kind, MAX_PREFIX_RULES, MAX_TARGET_UIDS, PrefixRule, format_config_ex, parse_config, peek_kind,
};

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

pub const CANONICAL_CONFIG: &str = "/data/system/vpnhide_config.json";
pub const KMOD_CTL: &str = "/proc/vpnhide_ctl";
pub const KMOD_MODULE_DIR: &str = "/data/adb/modules/vpnhide_kmod";
pub const ZYGISK_RUNTIME_CONFIG: &str = "/data/adb/modules/vpnhide_zygisk/targets.txt";
pub const KPM_MODULE_FILE: &str = "/data/adb/modules/vpnhide_kpm/vpnhide.kpm";
pub const SUPERKEY_FILE: &str = "/data/adb/vpnhide/superkey";
const APATCH_DIR: &str = "/data/adb/ap";
const APP_PACKAGE: &str = "dev.privtools.veil";
const KPM_NAME: &str = "vpnhide";
const PORTS_CHAIN4: &str = "vpnhide_out";
const PORTS_CHAIN6: &str = "vpnhide_out6";
const PORTS_STATUS_DIR: &str = "/data/adb/vpnhide_ports";
const PORTS_LOAD_STATUS: &str = "/data/adb/vpnhide_ports/load_status";
const PORTS_LOAD_LOG: &str = "/data/adb/vpnhide_ports/load_log";
const KPM_CTL_LOCK: &str = "/data/adb/vpnhide_kpm/ctl.lock";
const KPM_TRUNCATION_MARKER: &str = "# vpnhide truncated";
// The native-target cap is owned by the shared protocol crate (and mirrored by
// the C backends' `#define MAX_TARGET_UIDS`); alias it here so all three stay in
// lock-step instead of restating the literal 64.
const MAX_NATIVE_TARGETS: usize = MAX_TARGET_UIDS;
const PM_READY_ATTEMPTS: u32 = 60;
const APATCH_SUPERCALL_NR: c_long = 45;
const APATCH_SUPERCALL_DEFAULT_VERSION_CODE: c_long = 0x000d00;
const APATCH_SUPERCALL_MAGIC: c_long = 0x1158;
const APATCH_TRUSTED_SU_KEY: &str = "su";
const SUPERCALL_HELLO: c_long = 0x1000;
const SUPERCALL_HELLO_MAGIC: c_long = 0x11581158;
const SUPERCALL_KPM_LOAD: c_long = 0x1020;
const SUPERCALL_KPM_CONTROL: c_long = 0x1022;
const SUPERCALL_KPM_LIST: c_long = 0x1031;
const APATCH_SUPERCALL_VERSION_FALLBACKS: &[c_long] = &[
    0x000d02, 0x000d01, 0x000c02, 0x000c01, 0x000c00, 0x000b01, 0x000b00, 0x000a05,
];

unsafe extern "C" {
    fn syscall(num: c_long, ...) -> c_long;
    fn flock(fd: c_int, operation: c_int) -> c_int;
}

const LOCK_EX: c_int = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ApatchCommandStyle {
    Versioned(c_long),
    Raw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PmReadyWait {
    Bounded(u32),
    Forever,
}

mod kpm;
mod model;
mod ports;

use kpm::*;
pub use model::*;
use ports::*;

pub fn read_canonical() -> Result<String> {
    match fs::read_to_string(CANONICAL_CONFIG) {
        Ok(raw) => Ok(raw),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(empty_canonical_json().to_owned()),
        Err(e) => Err(e.into()),
    }
}

pub fn activate_kmod() -> Result<()> {
    activate_kmod_with_pm_wait(PmReadyWait::Bounded(PM_READY_ATTEMPTS))
}

pub fn activate_kmod_boot() -> Result<()> {
    wait_for_path(KMOD_CTL);
    activate_kmod_with_pm_wait(PmReadyWait::Forever)
}

fn activate_kmod_with_pm_wait(wait: PmReadyWait) -> Result<()> {
    let wire = project_native_with_pm_wait(&read_canonical()?, NativeHookFamily::Kernel, wait)?;
    // /proc/vpnhide_ctl replaces the entire config per write(), so keep this
    // bounded to MAX_NATIVE_TARGETS and deliver one complete snapshot.
    fs::write(KMOD_CTL, wire)?;
    Ok(())
}

pub fn activate_zygisk() -> Result<()> {
    activate_zygisk_with_pm_wait(PmReadyWait::Bounded(PM_READY_ATTEMPTS))
}

pub fn activate_zygisk_boot() -> Result<()> {
    activate_zygisk_with_pm_wait(PmReadyWait::Forever)
}

fn activate_zygisk_with_pm_wait(wait: PmReadyWait) -> Result<()> {
    let wire = project_native_with_pm_wait(&read_canonical()?, NativeHookFamily::Zygisk, wait)?;
    write_atomic(Path::new(ZYGISK_RUNTIME_CONFIG), wire.as_bytes(), 0o644)
}

/// Outcome of a KPM boot activation. A kmod conflict is a legitimate,
/// non-error result (the KPM deliberately stands down — see §1.5), so it must
/// be distinguishable from a successful configure: the boot script reports
/// each as a different `load_status`, and reporting a deferral as "configured"
/// would lie to the diagnostics screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KpmBootOutcome {
    /// Wire snapshot was delivered to the KPM over ctl0.
    Configured,
    /// The .ko backend is present, so the KPM stood down without loading or
    /// configuring (co-residence freezes the kernel — protocol §1.5).
    DeferredConflict,
    /// APatch/FolkPatch is installed, but neither a saved superkey nor the
    /// trusted `su` supercall grant authenticated yet. Boot may legitimately
    /// reach this state before the user unlocks the device and supplies the
    /// key, so the service records it as deferred rather than parsing an error
    /// message to guess what happened.
    AwaitingAuthentication,
}

pub fn activate_kpm() -> Result<()> {
    // App / manual path: a conflict is a hard error (conflict_is_error=true),
    // so this only ever returns Configured on success.
    activate_kpm_with_pm_wait(PmReadyWait::Bounded(PM_READY_ATTEMPTS), true).map(|_| ())
}

pub fn activate_kpm_boot() -> Result<KpmBootOutcome> {
    activate_kpm_with_pm_wait(PmReadyWait::Forever, false)
}

pub fn read_kpm_status() -> Result<String> {
    read_kpm_payload("vpnhide 1 status")
}

pub fn read_kpm_stats() -> Result<String> {
    read_kpm_payload("vpnhide 1 stats")
}

pub fn read_kpm_state() -> Result<String> {
    let client = KpmClient::detect()?;
    let mut out = client.ctl0_read("vpnhide 1 status")?;
    out.push_str(&client.ctl0_read("vpnhide 1 stats")?);
    Ok(out)
}

fn read_kpm_payload(wire: &str) -> Result<String> {
    let client = KpmClient::detect()?;
    client.ctl0_read(wire)
}

fn activate_kpm_with_pm_wait(wait: PmReadyWait, conflict_is_error: bool) -> Result<KpmBootOutcome> {
    if skip_kpm_for_kmod_conflict(conflict_is_error)? {
        return Ok(KpmBootOutcome::DeferredConflict);
    }
    let wire = project_native_with_pm_wait(&read_canonical()?, NativeHookFamily::Kpm, wait)?;
    // Re-check after the (possibly long) PackageManager wait: the .ko may have
    // been loaded meanwhile, in which case we must not configure the KPM.
    if skip_kpm_for_kmod_conflict(conflict_is_error)? {
        return Ok(KpmBootOutcome::DeferredConflict);
    }
    let client = match KpmClient::detect_outcome()? {
        KpmClientDetection::Ready(client) => client,
        KpmClientDetection::AwaitingAuthentication(_) if !conflict_is_error => {
            return Ok(KpmBootOutcome::AwaitingAuthentication);
        }
        KpmClientDetection::AwaitingAuthentication(detail) => return Err(detail.into()),
    };
    client.ensure_loaded()?;
    client.ctl0_config(&wire)?;
    Ok(KpmBootOutcome::Configured)
}

pub fn activate_ports() -> Result<PortsActivationReport> {
    activate_ports_with_pm_wait(PmReadyWait::Bounded(PM_READY_ATTEMPTS))
}

pub fn activate_ports_boot() -> Result<PortsActivationReport> {
    activate_ports_with_pm_wait(PmReadyWait::Forever)
}

fn activate_ports_with_pm_wait(wait: PmReadyWait) -> Result<PortsActivationReport> {
    let rules = project_ports_with_pm_wait(&read_canonical()?, wait)?;
    apply_ports_rules(&rules)
}

pub fn activate_ports_recorded(boot_wait: bool) -> Result<()> {
    let source = if boot_wait { "boot" } else { "app" };
    let result = if boot_wait {
        activate_ports_boot()
    } else {
        activate_ports()
    };
    match result {
        Ok(report) => {
            write_ports_load_status(
                source,
                true,
                Some(report.target_count),
                "configured",
                &report.log,
            );
            Ok(())
        }
        Err(err) => {
            let detail = err.to_string();
            write_ports_load_status(source, false, None, &detail, &detail);
            Err(err)
        }
    }
}

pub fn boot_wait_requested_from_env() -> Result<bool> {
    let mut boot_wait = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--boot-wait" => boot_wait = true,
            _ => {
                return Err(
                    format!("unknown argument {arg}; usage: activator [--boot-wait]").into(),
                );
            }
        }
    }
    Ok(boot_wait)
}

fn has_native_targets(cfg: &CanonicalConfig, family: NativeHookFamily) -> bool {
    cfg.apps
        .values()
        .any(|app| app.native.hookmask(family).is_some())
}

fn has_ports_targets(cfg: &CanonicalConfig) -> bool {
    cfg.apps.values().any(|app| app.ports)
}

fn empty_canonical_json() -> &'static str {
    "{\"version\":1,\"debug\":false,\"apps\":{},\"settings\":{\"rememberSuperkey\":false}}\n"
}

fn wait_for_pm_ready(wait: PmReadyWait) -> Result<()> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        if let Ok(stdout) = pm_list_packages(&["list", "packages", "-U"])
            && pm_output_has_package(&stdout, APP_PACKAGE)
        {
            return Ok(());
        }
        if matches!(wait, PmReadyWait::Bounded(max) if attempts >= max) {
            return Err(
                format!("PackageManager did not expose {APP_PACKAGE} within {attempts}s").into(),
            );
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn wait_for_path(path: &str) {
    while !Path::new(path).exists() {
        thread::sleep(Duration::from_secs(1));
    }
}

fn pm_list_packages(args: &[&str]) -> Result<String> {
    let out = Command::new("pm").args(args).output()?;
    if !out.status.success() {
        return Err(format!("pm list packages failed with status {}", out.status).into());
    }
    Ok(String::from_utf8(out.stdout)?)
}

fn pm_output_has_package(output: &str, package: &str) -> bool {
    let expected = format!("package:{package}");
    output
        .lines()
        .any(|line| line.split_whitespace().next() == Some(expected.as_str()))
}

/// True when the .ko backend is present and not disabled. This is the most
/// complete of the project's "is the kmod here?" checks: it catches both an
/// installed-and-enabled module directory *and* a live `/proc/vpnhide_ctl`
/// (e.g. a manually-loaded .ko whose module dir is gone). The boot scripts
/// keep a cheaper directory-only check as a fail-safe floor (it cannot error
/// and is ordering-independent); this superset is the authoritative gate on
/// the config-delivery path. See protocol §1.5.
pub fn kmod_backend_present() -> bool {
    Path::new(KMOD_CTL).exists()
        || (Path::new(KMOD_MODULE_DIR).is_dir()
            && !Path::new(KMOD_MODULE_DIR).join("disable").exists())
}

fn skip_kpm_for_kmod_conflict(conflict_is_error: bool) -> Result<bool> {
    if !kmod_backend_present() {
        return Ok(false);
    }
    // .ko present. App/manual path treats this as a hard error; boot path
    // signals a (non-error) deferral to the caller.
    if conflict_is_error {
        return Err("kmod backend present; refusing to load/configure KPM".into());
    }
    Ok(true)
}

pub fn write_atomic(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or("path has no parent")?;
    fs::create_dir_all(parent)?;
    // Per-process temp name: the boot service and an app-triggered activation run
    // the same binary and both write e.g. load_status; a shared `.tmp` would let
    // them truncate/interleave each other. Each process gets its own temp and the
    // final rename stays atomic, so a concurrent run can only ever leave one
    // complete file, never a partial one.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(content)?;
        file.sync_all()?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

// Locate the KPatch-Next `kpatch` CLI. This is the KPatch-Next-Module path only
// (Magisk / KSU / KSU-Next all install the same module — bin path confirmed on a
// Pixel 8 Pro). APatch is NOT covered here: it has no kpatch CLI on disk (the
// binary lives in the manager app's private libs) and loads KPMs via the
// supercall instead, so KpmClient::detect() routes APatch through that path.

#[cfg(test)]
mod tests;
