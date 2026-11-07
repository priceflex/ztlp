//! `ztlp agent machine-setup` / `machine-teardown` / `machine-status`:
//! the one-time, admin-only part of a Windows install
//! (plan `docs/plans/2026-10-29-windows-agent-per-user-unelevated.md`).
//!
//! The installer runs `machine-setup` once, elevated (one UAC prompt). It
//! does everything that needs admin so the per-user agent never does:
//!
//! 1. Remove the legacy `ZtlpAgent` LocalSystem service if present (old
//!    installs), together with its ProgramData state.
//! 2. Create the machine CA (root + intermediate, nameConstraints `.ztlp`)
//!    in `C:\ProgramData\ZTLP\ca` if it does not exist.
//! 3. Lock its ACL down: the directory is readable by Users (each user's
//!    agent mints leaf certs from the intermediate), the root key is
//!    Administrators + SYSTEM only.
//! 4. Trust the root in `LocalMachine\Root`.
//! 5. Add the umbrella NRPT rule `.ztlp` -> the agent's DNS stub.
//!
//! The desktop app runs the same command again (one UAC prompt) when its
//! DNS or HTTPS check is red ("Fix"). Every step is idempotent.
//!
//! Plans are pure and unit-tested on every OS; the executor is Windows-only.

#![deny(unsafe_code)]

use std::path::{Path, PathBuf};

/// The DNS stub address NRPT points `.ztlp` at. Windows NRPT can only name
/// a bare IP (port 53); the agent binds its resolver on `127.0.0.55:53`.
pub const NRPT_DNS_SERVER: &str = "127.0.0.55";

/// CN of the machine root. Different from the per-device root
/// (`ZTLP Root CA (this device)`) so the two are easy to tell apart in
/// `certmgr`.
pub const MACHINE_ROOT_CN: &str = "ZTLP Root CA (this machine)";
/// CN of the machine intermediate.
pub const MACHINE_INTERMEDIATE_CN: &str = "ZTLP Intermediate CA (this machine)";
/// The only DNS subtree the chain may sign.
pub const PERMITTED_SUBTREE: &str = ".ztlp";

/// PEM-encoded CA chain.
pub struct CaChainPem {
    pub root_cert: String,
    pub root_key: String,
    pub intermediate_cert: String,
    pub intermediate_key: String,
}

/// Generate a fresh ECDSA P-256 root + intermediate, both name-constrained
/// to `.ztlp` (so the chain can never sign a public name), 10-year validity,
/// intermediate pathlen 0.
pub fn generate_ca_chain(
    root_cn: &str,
    intermediate_cn: &str,
) -> Result<CaChainPem, Box<dyn std::error::Error>> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa,
        KeyPair, KeyUsagePurpose, NameConstraints,
    };
    let ztlp_only = || NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(PERMITTED_SUBTREE.to_string())],
        excluded_subtrees: Vec::new(),
    };
    let now = time::OffsetDateTime::now_utc();
    let ten_years = time::Duration::days(365 * 10);

    let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut root_params = CertificateParams::new(Vec::<String>::new())?;
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    root_params.name_constraints = Some(ztlp_only());
    let mut root_dn = DistinguishedName::new();
    root_dn.push(DnType::CommonName, root_cn);
    root_dn.push(DnType::OrganizationName, "ZTLP");
    root_params.distinguished_name = root_dn;
    root_params.not_before = now;
    root_params.not_after = now + ten_years;
    let root_cert = root_params.self_signed(&root_key)?;

    let int_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut int_params = CertificateParams::new(Vec::<String>::new())?;
    int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    int_params.name_constraints = Some(ztlp_only());
    let mut int_dn = DistinguishedName::new();
    int_dn.push(DnType::CommonName, intermediate_cn);
    int_dn.push(DnType::OrganizationName, "ZTLP");
    int_params.distinguished_name = int_dn;
    int_params.not_before = now;
    int_params.not_after = now + ten_years;
    let int_cert = int_params.signed_by(&int_key, &root_cert, &root_key)?;

    Ok(CaChainPem {
        root_cert: root_cert.pem(),
        root_key: root_key.serialize_pem(),
        intermediate_cert: int_cert.pem(),
        intermediate_key: int_key.serialize_pem(),
    })
}

/// Write a chain into `dir` with the file names the agent's minting code
/// expects (`root.pem`, `root.key`, `intermediate.pem`, `intermediate.key`)
/// plus `ca.json` and an empty `certs/index.json`. Refuses to overwrite an
/// existing root key.
pub fn write_ca_chain(
    dir: &Path,
    chain: &CaChainPem,
    root_cn: &str,
    intermediate_cn: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    if dir.join("root.key").exists() {
        return Err(format!("CA already initialized at {}", dir.display()).into());
    }
    // root.key is written LAST: its presence means the chain is complete,
    // so a run that died half-way (disk full, AV) is simply redone.
    std::fs::write(dir.join("root.pem"), &chain.root_cert)?;
    std::fs::write(dir.join("intermediate.pem"), &chain.intermediate_cert)?;
    std::fs::write(dir.join("intermediate.key"), &chain.intermediate_key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("intermediate.key"),
            std::fs::Permissions::from_mode(0o600),
        )?;
    }
    let meta = serde_json::json!({
        "scope": "machine",
        "root_cn": root_cn,
        "intermediate_cn": intermediate_cn,
        "algorithm": "ECDSA P-256",
        "permitted_subtree": PERMITTED_SUBTREE,
    });
    std::fs::write(dir.join("ca.json"), serde_json::to_string_pretty(&meta)?)?;
    std::fs::create_dir_all(dir.join("certs"))?;
    std::fs::write(dir.join("certs").join("index.json"), "[]")?;
    std::fs::write(dir.join("root.key"), &chain.root_key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.join("root.key"), std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// What `machine-status` reports, and what the plans are computed from.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MachineState {
    /// The old `ZtlpAgent` LocalSystem service is registered.
    pub legacy_service_installed: bool,
    /// The machine CA can mint (intermediate cert + key present).
    pub ca_present: bool,
    /// The machine root is in `LocalMachine\Root`.
    pub ca_trusted: bool,
    /// The `.ztlp` NRPT rule exists and points at [`NRPT_DNS_SERVER`].
    pub nrpt_present: bool,
}

impl MachineState {
    /// Everything the per-user agent needs from the machine is in place.
    pub fn ready(&self) -> bool {
        !self.legacy_service_installed && self.ca_present && self.ca_trusted && self.nrpt_present
    }
}

/// One admin step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineAction {
    RemoveLegacyService,
    CreateCa,
    LockDownCaAcl,
    TrustCa,
    SetupNrpt,
    RemoveNrpt,
    UntrustCa,
    RemoveCaDir,
}

/// `machine-setup`: what to do from the current state. The ACL step always
/// runs (cheap, idempotent, repairs a hand-edited ACL); the rest only when
/// missing. Legacy service removal comes first: its uninstall deletes the
/// whole `C:\ProgramData\ZTLP` tree, which would take a freshly made CA
/// with it.
pub fn setup_plan(s: &MachineState) -> Vec<MachineAction> {
    let mut plan = Vec::new();
    if s.legacy_service_installed {
        plan.push(MachineAction::RemoveLegacyService);
    }
    // After a legacy removal the CA dir is gone, whatever the probe said.
    let ca_present = s.ca_present && !s.legacy_service_installed;
    if !ca_present {
        plan.push(MachineAction::CreateCa);
    }
    plan.push(MachineAction::LockDownCaAcl);
    if !ca_present || !s.ca_trusted {
        plan.push(MachineAction::TrustCa);
    }
    if !s.nrpt_present {
        plan.push(MachineAction::SetupNrpt);
    }
    plan
}

/// `machine-teardown` (uninstaller): remove everything `machine-setup`
/// added, plus a legacy service if one is still there.
pub fn teardown_plan(s: &MachineState) -> Vec<MachineAction> {
    let mut plan = vec![MachineAction::RemoveNrpt];
    if s.ca_present || s.ca_trusted {
        plan.push(MachineAction::UntrustCa);
    }
    plan.push(MachineAction::RemoveCaDir);
    if s.legacy_service_installed {
        plan.push(MachineAction::RemoveLegacyService);
    }
    plan
}

/// Stop the rest of `machine-setup` when this step fails? Yes for the CA
/// steps: a root must not be trusted machine-wide unless it was created and
/// its key locked down.
pub fn stop_after_failure(action: &MachineAction) -> bool {
    matches!(
        action,
        MachineAction::CreateCa | MachineAction::LockDownCaAcl | MachineAction::RemoveLegacyService
    )
}

/// Well-known SIDs (locale-independent, unlike group names).
const SID_ADMINISTRATORS: &str = "*S-1-5-32-544";
const SID_SYSTEM: &str = "*S-1-5-18";
const SID_USERS: &str = "*S-1-5-32-545";

/// `icacls` argv lists that lock the machine CA down:
/// directory (inherited by every file) = Admins+SYSTEM full, Users read;
/// `root.key` = Admins+SYSTEM only (inheritance removed).
pub fn ca_acl_commands(dir: &Path) -> Vec<Vec<String>> {
    let d = dir.to_string_lossy().into_owned();
    let root_key = dir.join("root.key").to_string_lossy().into_owned();
    vec![
        vec![
            "icacls".into(),
            d,
            "/inheritance:r".into(),
            "/grant:r".into(),
            format!("{SID_ADMINISTRATORS}:(OI)(CI)F"),
            format!("{SID_SYSTEM}:(OI)(CI)F"),
            format!("{SID_USERS}:(OI)(CI)RX"),
            "/C".into(),
            "/Q".into(),
        ],
        // Files inherit the directory ACL (no /T, which would stamp an
        // explicit Users grant onto every file). For root.key: drop the
        // inherited ACEs and any explicit Users grant, admins + SYSTEM only.
        vec![
            "icacls".into(),
            root_key,
            "/inheritance:r".into(),
            "/remove:g".into(),
            SID_USERS.into(),
            "/grant:r".into(),
            format!("{SID_ADMINISTRATORS}:F"),
            format!("{SID_SYSTEM}:F"),
            "/C".into(),
            "/Q".into(),
        ],
    ]
}

/// Does the NRPT rule list contain a usable `.ztlp` umbrella rule?
pub fn nrpt_has_umbrella(rules: &[crate::agent::dns_setup_windows::NrptRule]) -> bool {
    rules.iter().any(|r| {
        r.namespace
            .trim_start_matches('.')
            .eq_ignore_ascii_case("ztlp")
            && r.name_servers.iter().any(|s| s.trim() == NRPT_DNS_SERVER)
    })
}

/// The machine CA directory (see [`crate::agent::peruser::machine_ca_dir`]),
/// or the Windows default when unset.
pub fn ca_dir() -> PathBuf {
    crate::agent::peruser::machine_ca_dir()
        .unwrap_or_else(|| PathBuf::from(crate::agent::peruser::WINDOWS_MACHINE_CA_DIR))
}

/// macOS: the machine CA directory. Honors `ZTLP_MACHINE_CA_DIR` (same
/// contract as [`ca_dir`], so tests can redirect it to a temp path); when
/// unset, the machine CA lives in the existing system ZTLP tree
/// (`/Library/Application Support/ZTLP/ca`), NOT the Windows ProgramData
/// path. The constant is platform-neutral so the executor compiles on every
/// OS; only the runtime default is macOS's.
pub fn macos_machine_ca_dir() -> PathBuf {
    if let Ok(p) = std::env::var("ZTLP_MACHINE_CA_DIR") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(MACOS_MACHINE_CA_DIR)
}

/// The macOS machine CA directory default (see [`macos_machine_ca_dir`]).
pub const MACOS_MACHINE_CA_DIR: &str = "/Library/Application Support/ZTLP/ca";

// ── Windows executor ──────────────────────────────────────────────────

/// Probe the real machine state (read-only; works unelevated).
#[cfg(windows)]
pub fn probe_state() -> MachineState {
    use crate::agent::dns_setup_windows::{NrptApi, WindowsNrptApi};
    let dir = ca_dir();
    let ca_present = crate::agent::peruser::ca_dir_can_mint(&dir);
    let ca_trusted = ca_present && crate::agent::ca_trust::is_cert_trusted(&dir.join("root.pem"));
    let api = WindowsNrptApi::with_powershell_path(POWERSHELL);
    let nrpt_present = api
        .list_rules()
        .map(|r| nrpt_has_umbrella(&r))
        .unwrap_or(false);
    MachineState {
        legacy_service_installed: legacy_service_installed(),
        ca_present,
        ca_trusted,
        nrpt_present,
    }
}

#[cfg(windows)]
const POWERSHELL: &str = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";

#[cfg(windows)]
fn legacy_service_installed() -> bool {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    let Ok(m) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else {
        return false;
    };
    m.open_service(
        crate::agent::windows_service_install::WINDOWS_SERVICE_NAME,
        ServiceAccess::QUERY_STATUS,
    )
    .is_ok()
}

/// Run one action. Returns a one-line description or the error.
#[cfg(windows)]
pub fn execute(action: &MachineAction) -> Result<String, String> {
    use crate::agent::dns_setup_windows::{setup_zones, teardown_managed, WindowsNrptApi};
    let dir = ca_dir();
    match action {
        MachineAction::RemoveLegacyService => {
            crate::agent::windows_service_install::windows_service_uninstall(
                crate::agent::windows_service_install::WINDOWS_SERVICE_NAME,
            )
            .map_err(|e| format!("could not remove the old ZtlpAgent service: {e}"))?;
            crate::agent::windows_service_install::remove_programdata_dir();
            Ok("removed the old ZtlpAgent service and its ProgramData state".into())
        }
        MachineAction::CreateCa => {
            let chain = generate_ca_chain(MACHINE_ROOT_CN, MACHINE_INTERMEDIATE_CN)
                .map_err(|e| format!("CA generation failed: {e}"))?;
            write_ca_chain(&dir, &chain, MACHINE_ROOT_CN, MACHINE_INTERMEDIATE_CN)
                .map_err(|e| format!("writing the CA failed: {e}"))?;
            Ok(format!("created the machine CA in {}", dir.display()))
        }
        MachineAction::LockDownCaAcl => {
            for argv in ca_acl_commands(&dir) {
                let out = std::process::Command::new(&argv[0])
                    .args(&argv[1..])
                    .output()
                    .map_err(|e| format!("icacls: {e}"))?;
                if !out.status.success() {
                    return Err(format!(
                        "icacls failed: {}",
                        String::from_utf8_lossy(&out.stdout).trim()
                    ));
                }
            }
            Ok("machine CA permissions set (root key: admins only)".into())
        }
        MachineAction::TrustCa => {
            crate::agent::ca_trust::install_ca_cert_with_scope(
                &dir.join("root.pem"),
                crate::agent::ca_trust::CertStoreScope::Machine,
            )
            .map_err(|e| format!("trusting the machine CA failed: {e}"))?;
            Ok("machine CA trusted in LocalMachine\\Root".into())
        }
        MachineAction::SetupNrpt => {
            let api = WindowsNrptApi::with_powershell_path(POWERSHELL);
            setup_zones(&api, &["ztlp".to_string()], NRPT_DNS_SERVER)
                .map_err(|e| format!("NRPT setup failed: {e}"))?;
            Ok(format!("DNS rule .ztlp -> {NRPT_DNS_SERVER} added"))
        }
        MachineAction::RemoveNrpt => {
            let api = WindowsNrptApi::with_powershell_path(POWERSHELL);
            let removed =
                teardown_managed(&api).map_err(|e| format!("NRPT removal failed: {e}"))?;
            Ok(format!("removed DNS rules: {removed:?}"))
        }
        MachineAction::UntrustCa => {
            let root = dir.join("root.pem");
            if root.exists() {
                crate::agent::ca_trust::remove_ca_cert(&root)
                    .map_err(|e| format!("removing the machine CA from trust failed: {e}"))?;
            }
            Ok("machine CA removed from LocalMachine\\Root".into())
        }
        MachineAction::RemoveCaDir => {
            if dir.exists() {
                std::fs::remove_dir_all(&dir)
                    .map_err(|e| format!("removing {} failed: {e}", dir.display()))?;
            }
            // Remove C:\ProgramData\ZTLP too when nothing else is left in it.
            if let Some(parent) = dir.parent() {
                let _ = std::fs::remove_dir(parent);
            }
            Ok(format!("removed {}", dir.display()))
        }
    }
}

// ── macOS executor ─────────────────────────────────────────────────────

/// macOS machine CA dir (see [`macos_machine_ca_dir`]).
#[cfg(target_os = "macos")]
fn macos_ca_dir() -> PathBuf {
    macos_machine_ca_dir()
}

/// Probe the real macOS machine state (read-only; safe unelevated).
///
/// Field mapping (Windows → macOS):
/// - `legacy_service_installed` → the old root `org.ztlp.agent` LaunchDaemon
///   plist is present (its removal drops the whole legacy data plane).
/// - `ca_present` → the machine CA can mint (intermediate cert + key present).
/// - `ca_trusted` → the machine root is trusted in the System keychain.
/// - `nrpt_present` → the `/etc/resolver/ztlp` umbrella file exists (macOS has
///   no NRPT; the per-domain resolver file is the equivalent DNS anchor).
#[cfg(target_os = "macos")]
pub fn probe_state() -> MachineState {
    let dir = macos_ca_dir();
    let ca_present = crate::agent::peruser::ca_dir_can_mint(&dir);
    // `is_ca_installed` probes the System keychain (macOS branch uses
    // `security verify-cert`), gated on the default CA path's presence.
    let ca_trusted = ca_present && crate::agent::ca_trust::is_ca_installed();
    let nrpt_present =
        Path::new(crate::agent::dns_setup::MACOS_RESOLVER_DIR_PUB).join("ztlp").exists();
    MachineState {
        legacy_service_installed: Path::new(crate::agent::macos_daemon::MACOS_LAUNCHDAEMON_PLIST_PATH)
            .exists(),
        ca_present,
        ca_trusted,
        nrpt_present,
    }
}

/// Run one action (macOS). Returns a one-line description or the error.
///
/// Every step is idempotent. The CA dir and resolver file already exist
/// (reused from the current root agent's `macos_daemon` startup hooks);
/// `machine-setup` re-derives them from the shared plan so a fresh machine
/// and a Fix both converge to the same state.
#[cfg(target_os = "macos")]
pub fn execute(action: &MachineAction) -> Result<String, String> {
    let dir = macos_ca_dir();
    match action {
        MachineAction::RemoveLegacyService => {
            crate::agent::macos_daemon::macos_daemon_uninstall()
                .map_err(|e| format!("could not remove the old org.ztlp.agent LaunchDaemon: {e}"))?;
            Ok("removed the old org.ztlp.agent LaunchDaemon".into())
        }
        MachineAction::CreateCa => {
            let chain = generate_ca_chain(MACHINE_ROOT_CN, MACHINE_INTERMEDIATE_CN)
                .map_err(|e| format!("CA generation failed: {e}"))?;
            write_ca_chain(&dir, &chain, MACHINE_ROOT_CN, MACHINE_INTERMEDIATE_CN)
                .map_err(|e| format!("writing the CA failed: {e}"))?;
            Ok(format!("created the machine CA in {}", dir.display()))
        }
        MachineAction::LockDownCaAcl => {
            // macOS has no icacls/ACLs: the "lockdown" is the Unix mode bits
            // (root.key 0600 root:wheel, dir 0755). `write_ca_chain` already
            // set root.key 0600 on the Unix path; re-assert it here so a
            // hand-loosened mode is repaired idempotently.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if dir.join("root.key").exists() {
                    std::fs::set_permissions(
                        dir.join("root.key"),
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .map_err(|e| format!("setting root.key 0600 failed: {e}"))?;
                }
                if dir.join("intermediate.key").exists() {
                    std::fs::set_permissions(
                        dir.join("intermediate.key"),
                        std::fs::Permissions::from_mode(0o600),
                    )
                    .map_err(|e| format!("setting intermediate.key 0600 failed: {e}"))?;
                }
            }
            Ok("machine CA permissions set (root key: root only)".into())
        }
        MachineAction::TrustCa => {
            crate::agent::ca_trust::install_ca_cert_with_scope(
                &dir.join("root.pem"),
                crate::agent::ca_trust::CertStoreScope::Machine,
            )
            .map_err(|e| format!("trusting the machine CA failed: {e}"))?;
            Ok("machine CA trusted in the System keychain".into())
        }
        MachineAction::SetupNrpt => {
            // macOS: the "NRPT umbrella" is the /etc/resolver/ztlp per-domain
            // resolver file (umbrella, no per-zone files). Reuse the existing
            // resolver writer; the umbrella zone set is `.ztlp` -> the DNS
            // stub on 127.0.0.55.
            let listen = format!("{NRPT_DNS_SERVER}:15353");
            crate::agent::dns_setup::setup_dns(&listen, &["ztlp".to_string()])
                .map_err(|e| format!("resolver setup failed: {e}"))?;
            Ok(format!("DNS resolver .ztlp -> {NRPT_DNS_SERVER} added"))
        }
        MachineAction::RemoveNrpt => {
            let removed =
                crate::agent::dns_setup::teardown_dns().map_err(|e| format!("resolver removal failed: {e}"))?;
            Ok(format!("removed DNS resolver files: {:?}", removed.len()))
        }
        MachineAction::UntrustCa => {
            let root = dir.join("root.pem");
            if root.exists() {
                crate::agent::ca_trust::remove_ca_cert(&root)
                    .map_err(|e| format!("removing the machine CA from trust failed: {e}"))?;
            }
            Ok("machine CA removed from the System keychain".into())
        }
        MachineAction::RemoveCaDir => {
            if dir.exists() {
                std::fs::remove_dir_all(&dir)
                    .map_err(|e| format!("removing {} failed: {e}", dir.display()))?;
            }
            // Remove the parent Application Support/ZTLP dir too when it's
            // now empty (the daemon state may still live under .ztlp/).
            if let Some(parent) = dir.parent() {
                let _ = std::fs::remove_dir(parent);
            }
            Ok(format!("removed {}", dir.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::dns_setup_windows::NrptRule;

    fn st(legacy: bool, ca: bool, trusted: bool, nrpt: bool) -> MachineState {
        MachineState {
            legacy_service_installed: legacy,
            ca_present: ca,
            ca_trusted: trusted,
            nrpt_present: nrpt,
        }
    }

    #[test]
    fn fresh_machine_gets_every_step_in_order() {
        assert_eq!(
            setup_plan(&st(false, false, false, false)),
            vec![
                MachineAction::CreateCa,
                MachineAction::LockDownCaAcl,
                MachineAction::TrustCa,
                MachineAction::SetupNrpt
            ]
        );
    }

    #[test]
    fn ready_machine_only_reapplies_the_acl() {
        let s = st(false, true, true, true);
        assert!(s.ready());
        assert_eq!(setup_plan(&s), vec![MachineAction::LockDownCaAcl]);
    }

    #[test]
    fn legacy_service_is_removed_first_and_ca_recreated_after() {
        let plan = setup_plan(&st(true, true, true, true));
        assert_eq!(plan[0], MachineAction::RemoveLegacyService);
        let create = plan.iter().position(|a| *a == MachineAction::CreateCa);
        let trust = plan.iter().position(|a| *a == MachineAction::TrustCa);
        assert!(create.is_some() && trust.is_some() && create < trust);
        assert!(!plan.contains(&MachineAction::SetupNrpt));
    }

    #[test]
    fn untrusted_existing_ca_is_trusted_not_recreated() {
        let plan = setup_plan(&st(false, true, false, true));
        assert!(!plan.contains(&MachineAction::CreateCa));
        assert!(plan.contains(&MachineAction::TrustCa));
    }

    #[test]
    fn missing_nrpt_alone_only_adds_the_rule() {
        assert_eq!(
            setup_plan(&st(false, true, true, false)),
            vec![MachineAction::LockDownCaAcl, MachineAction::SetupNrpt]
        );
    }

    #[test]
    fn teardown_removes_everything_setup_added() {
        assert_eq!(
            teardown_plan(&st(true, true, true, true)),
            vec![
                MachineAction::RemoveNrpt,
                MachineAction::UntrustCa,
                MachineAction::RemoveCaDir,
                MachineAction::RemoveLegacyService
            ]
        );
        assert_eq!(
            teardown_plan(&st(false, false, false, false)),
            vec![MachineAction::RemoveNrpt, MachineAction::RemoveCaDir]
        );
    }

    #[test]
    fn failed_ca_steps_stop_setup_before_trust() {
        assert!(stop_after_failure(&MachineAction::LockDownCaAcl));
        assert!(stop_after_failure(&MachineAction::CreateCa));
        assert!(!stop_after_failure(&MachineAction::SetupNrpt));
        assert!(!stop_after_failure(&MachineAction::TrustCa));
        // and the ACL step always comes before trust in the plan
        let plan = setup_plan(&st(false, false, false, false));
        let acl = plan
            .iter()
            .position(|a| *a == MachineAction::LockDownCaAcl)
            .unwrap();
        let trust = plan
            .iter()
            .position(|a| *a == MachineAction::TrustCa)
            .unwrap();
        assert!(acl < trust);
    }

    #[test]
    fn acl_commands_use_sids_and_lock_root_key() {
        let cmds = ca_acl_commands(Path::new(r"C:\ProgramData\ZTLP\ca"));
        assert_eq!(cmds.len(), 2);
        let dir = cmds[0].join(" ");
        assert!(dir.contains("/inheritance:r"));
        assert!(
            dir.contains("*S-1-5-32-545:(OI)(CI)RX"),
            "Users read: {dir}"
        );
        assert!(dir.contains("*S-1-5-32-544:(OI)(CI)F"));
        let key = cmds[1].join(" ");
        assert!(key.contains("root.key"));
        assert!(key.contains("/inheritance:r"));
        assert!(
            key.contains("/remove:g *S-1-5-32-545"),
            "an explicit Users grant must be removed from the root key: {key}"
        );
        assert!(
            !key.contains("*S-1-5-32-545:"),
            "Users must not be granted the root key: {key}"
        );
        assert!(!dir.contains("/T"), "no explicit per-file grants: {dir}");
    }

    #[test]
    fn nrpt_umbrella_detection() {
        let r = |ns: &str, srv: &str| NrptRule {
            namespace: ns.into(),
            name_servers: vec![srv.into()],
            comment: String::new(),
        };
        assert!(nrpt_has_umbrella(&[r(".ztlp", "127.0.0.55")]));
        assert!(nrpt_has_umbrella(&[
            r(".trs.ztlp", "127.0.0.55"),
            r(".ZTLP", "127.0.0.55")
        ]));
        assert!(!nrpt_has_umbrella(&[r(".trs.ztlp", "127.0.0.55")]));
        assert!(!nrpt_has_umbrella(&[r(".ztlp", "127.0.0.53")]));
        assert!(!nrpt_has_umbrella(&[]));
    }

    #[test]
    fn generated_chain_is_written_and_mintable() {
        let dir = std::env::temp_dir().join(format!("ztlp-machine-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let chain = generate_ca_chain(MACHINE_ROOT_CN, MACHINE_INTERMEDIATE_CN).unwrap();
        write_ca_chain(&dir, &chain, MACHINE_ROOT_CN, MACHINE_INTERMEDIATE_CN).unwrap();
        assert!(crate::agent::peruser::ca_dir_can_mint(&dir));
        let ca = crate::agent::cert_mint::IntermediateCa::load_from_dir(&dir).unwrap();
        let leaf = ca.mint_leaf("ztlp-health.ztlp").unwrap();
        assert!(!leaf.leaf_pem.is_empty());
        // never overwrite an existing root
        assert!(write_ca_chain(&dir, &chain, MACHINE_ROOT_CN, MACHINE_INTERMEDIATE_CN).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_half_written_chain_can_be_written_again() {
        // root.key is the completion marker: a run that died before it
        // must not block the next Fix / machine-setup.
        let dir = std::env::temp_dir().join(format!("ztlp-machine-ca-half-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("root.pem"), "partial").unwrap();
        std::fs::write(dir.join("intermediate.pem"), "partial").unwrap();
        let chain = generate_ca_chain(MACHINE_ROOT_CN, MACHINE_INTERMEDIATE_CN).unwrap();
        write_ca_chain(&dir, &chain, MACHINE_ROOT_CN, MACHINE_INTERMEDIATE_CN).unwrap();
        assert!(dir.join("root.key").exists());
        crate::agent::cert_mint::IntermediateCa::load_from_dir(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── macOS machine-setup (Task 1) ───────────────────────────────────────
    // The plans (setup_plan/teardown_plan/stop_after_failure/ca_acl_commands)
    // are already pure and cross-platform (verified: no cfg gate). These pin
    // the macOS-specific pieces the executor consumes: the machine CA dir and
    // the plan shape macOS runs through it.

    #[test]
    fn macos_machine_ca_dir_is_under_application_support_ztlp() {
        // Env override must win (same contract as Windows/`machine_ca_dir`),
        // so a test can point the dir at a temp path without touching the
        // system location.
        let tmp = std::env::temp_dir().join(format!("ztlp-macos-ca-{}", std::process::id()));
        let _ = std::env::set_var("ZTLP_MACHINE_CA_DIR", &tmp);
        let d = macos_machine_ca_dir();
        let _ = std::env::remove_var("ZTLP_MACHINE_CA_DIR");
        assert_eq!(d, tmp, "ZTLP_MACHINE_CA_DIR must win on macOS too: {d:?}");
    }

    #[test]
    fn macos_machine_ca_dir_defaults_to_library_application_support() {
        // When the override is unset, the macOS default is the existing
        // system ZTLP tree, NOT the Windows ProgramData path.
        let _ = std::env::remove_var("ZTLP_MACHINE_CA_DIR");
        if cfg!(target_os = "macos") {
            assert_eq!(
                macos_machine_ca_dir(),
                PathBuf::from("/Library/Application Support/ZTLP/ca")
            );
        } else {
            // On non-macOS builds the constant still resolves and is a
            // macOS-style path (so the executor is compilable anywhere);
            // only the runtime default is platform-selected.
            assert!(macos_machine_ca_dir()
                .to_string_lossy()
                .contains("Application Support/ZTLP"));
        }
    }

    #[test]
    fn macos_setup_plan_from_fresh_state_covers_ca_and_resolver() {
        // A brand-new macOS machine: no legacy daemon, no CA, no resolver.
        // The shared plan must produce exactly the machine bits the macOS
        // executor implements — CA create + lockdown + trust + resolver.
        // `nrpt_present` maps to the /etc/resolver/ztlp umbrella on macOS.
        let s = MachineState {
            legacy_service_installed: false,
            ca_present: false,
            ca_trusted: false,
            nrpt_present: false,
        };
        let plan = setup_plan(&s);
        // CA is created before it is trusted (the invariant the ACL step
        // protects — a root must exist + be locked down before it's trusted).
        let create = plan
            .iter()
            .position(|a| *a == MachineAction::CreateCa)
            .unwrap_or_else(|| panic!("fresh machine must create the CA: {plan:?}"));
        let lock = plan
            .iter()
            .position(|a| *a == MachineAction::LockDownCaAcl)
            .unwrap_or_else(|| panic!("CA must be locked down: {plan:?}"));
        let trust = plan
            .iter()
            .position(|a| *a == MachineAction::TrustCa)
            .unwrap_or_else(|| panic!("CA must be trusted: {plan:?}"));
        let resolver = plan
            .iter()
            .position(|a| *a == MachineAction::SetupNrpt)
            .unwrap_or_else(|| panic!("macOS must add the resolver umbrella: {plan:?}"));
        assert!(create < lock && lock < trust, "create < lock < trust: {plan:?}");
        assert!(
            trust < resolver,
            "resolver after trust: {plan:?}"
        );
        // No legacy-service step on a fresh macOS machine.
        assert!(!plan.contains(&MachineAction::RemoveLegacyService));
    }

    #[test]
    fn macos_ready_state_reapplies_lockdown_only() {
        // A healthy macOS machine (CA present+trusted, resolver umbrella in
        // place): only the idempotent lockdown step runs.
        let s = MachineState {
            legacy_service_installed: false,
            ca_present: true,
            ca_trusted: true,
            nrpt_present: true,
        };
        assert!(s.ready());
        assert_eq!(setup_plan(&s), vec![MachineAction::LockDownCaAcl]);
    }

    #[test]
    fn macos_teardown_removes_resolver_ca_and_daemon() {
        // Teardown reverses setup: resolver first, then CA untrust + removal,
        // and the legacy root daemon if it's still registered (upgrade path).
        let s = MachineState {
            legacy_service_installed: true,
            ca_present: true,
            ca_trusted: true,
            nrpt_present: true,
        };
        let plan = teardown_plan(&s);
        assert_eq!(
            plan[0],
            MachineAction::RemoveNrpt,
            "resolver comes off first: {plan:?}"
        );
        let untrust = plan
            .iter()
            .position(|a| *a == MachineAction::UntrustCa)
            .unwrap_or_else(|| panic!("CA must be untrusted: {plan:?}"));
        let remove = plan
            .iter()
            .position(|a| *a == MachineAction::RemoveCaDir)
            .unwrap_or_else(|| panic!("CA dir must be removed: {plan:?}"));
        let legacy = plan
            .iter()
            .position(|a| *a == MachineAction::RemoveLegacyService)
            .unwrap_or_else(|| panic!("legacy daemon must be removed: {plan:?}"));
        assert!(untrust < remove);
        assert!(remove < legacy);
    }
}
