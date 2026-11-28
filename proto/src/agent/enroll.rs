//! Token enrollment ("join an existing network") shared by the `ztlp setup`
//! CLI and the iOS native agent.
//!
//! The desktop daemon enrolls by running `ztlp setup --token ...` as a child
//! process; an iOS Network Extension cannot exec, so the enrollment core
//! lives here and both callers use it. The code was MOVED from
//! `src/bin/ztlp-cli.rs` unchanged apart from where its progress lines go:
//! instead of printing to stderr it reports through [`EnrollUi`], which the
//! CLI implements with the same coloured `eprintln!` lines as before.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::identity::NodeId;

/// Where enrollment progress lines go, and how they are styled.
///
/// The CLI prints each line to stderr with ANSI colours; other hosts (the
/// iOS agent) keep the default plain styling and send lines to their log.
pub trait EnrollUi {
    /// One progress line (no trailing newline).
    fn say(&self, line: &str);
    fn green(&self, s: &str) -> String {
        s.to_string()
    }
    fn yellow(&self, s: &str) -> String {
        s.to_string()
    }
    fn cyan(&self, s: &str) -> String {
        s.to_string()
    }
    fn dim(&self, s: &str) -> String {
        s.to_string()
    }
    fn bold(&self, s: &str) -> String {
        s.to_string()
    }
}

/// What a successful enrollment produced (everything the caller needs to
/// print its own summary).
#[derive(Debug, Clone)]
pub struct EnrollOutcome {
    /// The name the device was enrolled as (`<device>.<zone>`; may carry a
    /// disambiguating suffix when the requested name was taken).
    pub full_name: String,
    pub zone: String,
    pub node_id: String,
    /// The device's Noise static PUBLIC key, hex.
    pub public_key_hex: String,
    pub key_path: PathBuf,
    pub config_path: PathBuf,
    pub agent_config_path: PathBuf,
}

/// File (in the `.ztlp` directory) holding an enrollment callback that this
/// host could not deliver itself. See [`defer_enrollment_callback`].
pub const PENDING_CALLBACK_FILE: &str = "enroll_callback.json";

/// Parse an enrollment token (bare base64url or a `ztlp://enroll/...` URI)
/// and reject an expired one.
pub fn parse_enrollment_token(
    token_str: &str,
) -> Result<crate::enrollment::EnrollmentToken, Box<dyn std::error::Error>> {
    use crate::enrollment::EnrollmentToken;

    // Parse token
    let token = EnrollmentToken::from_base64url(token_str)
        .map_err(|e| format!("invalid enrollment token: {}", e))?;

    if token.is_expired() {
        return Err("enrollment token has expired".into());
    }
    Ok(token)
}

/// Enroll this device with a parsed token: generate the identity, register
/// with the name server, establish name-server trust, and write
/// `identity.json`, `config.toml`, `agent.toml` (and the trust file) into
/// `ztlp_dir`. This is the body of `ztlp setup --token ...` after the device
/// name is known.
// The body is the CLI's code moved as-is; its early `return`s are kept.
#[allow(clippy::needless_return)]
pub async fn enroll_with_token(
    token: &crate::enrollment::EnrollmentToken,
    device_name: &str,
    ztlp_dir: &std::path::Path,
    bind_user: bool,
    opts: &SetupOpts,
    ui: &dyn EnrollUi,
) -> Result<EnrollOutcome, Box<dyn std::error::Error>> {
    use crate::identity::NodeIdentity;

    // Full ZTLP name
    let mut full_name = format!("{}.{}", device_name, token.zone);
    ui.say(&format!(
        "  {} Enrolling as {}",
        ui.cyan("→"),
        ui.bold(&full_name)
    ));

    // Determine ZTLP config directory
    std::fs::create_dir_all(ztlp_dir)
        .map_err(|e| format!("failed to create {}: {}", ztlp_dir.display(), e))?;

    let key_path = ztlp_dir.join("identity.json");
    let config_path = ztlp_dir.join("config.toml");
    let agent_config_path = ztlp_dir.join("agent.toml");

    // Never silently clobber an enrolled identity (was the behaviour of
    // `--yes` before 2026-09-12). --force moves the old files aside first.
    if let Some(backed_up) = guard_existing_identity(ztlp_dir, opts.force)? {
        ui.say(&format!(
            "  {} Existing enrollment backed up:",
            ui.yellow("⚠")
        ));
        for p in &backed_up {
            ui.say(&format!("      {}", p.display()));
        }
    }

    // Generate identity
    ui.say("");
    ui.say(&format!("  {} Generating identity...", ui.dim("→")));
    let mut identity = NodeIdentity::generate()?;

    // D3.T1: --bind-user records the current OS user's SID/UID so the daemon
    // refuses to operate under any other user. We resolve eagerly here so an
    // unenrollable environment fails BEFORE we touch the gateway.
    if bind_user {
        let sid = crate::agent::user_binding::current_user_sid().map_err(|e| {
            format!(
                "--bind-user requires a working user-resolution shim: {}\n\
                 Hint: run `id -u` (Unix) or `whoami /user` (Windows) manually to diagnose.",
                e
            )
        })?;
        ui.say(&format!(
            "  {} Binding identity to user {}",
            ui.dim("→"),
            ui.cyan(&sid)
        ));
        identity.bound_user_sid = Some(sid);
    }

    identity.save(&key_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&key_path, perms).ok();
    }

    ui.say(&format!(
        "  {} Identity saved to {}",
        ui.green("✓"),
        key_path.display()
    ));
    ui.say(&format!("    {} {}", ui.cyan("NodeID:"), identity.node_id));

    // Send enrollment request to NS
    ui.say("");
    ui.say(&format!(
        "  {} Registering with namespace server...",
        ui.dim("→")
    ));

    let ns_addr: std::net::SocketAddr = token
        .ns_addr
        .parse()
        .map_err(|e| format!("invalid NS address '{}': {}", token.ns_addr, e))?;

    let sock = UdpSocket::bind("0.0.0.0:0").await?;

    // Build enrollment request
    let token_bin = token.serialize();

    // Use the X25519 static public key as the enrollment identity (32 bytes)
    let pubkey_bytes = identity.static_public_key.as_slice();

    let node_id_bytes: &[u8; 16] = identity.node_id.as_bytes();

    // Determine address to register (optional)
    let addr_str = ""; // Empty = no address for now (device may be behind NAT)

    // Pre-check the name via a plain lookup (0x01) BEFORE spending the
    // single-use enroll token (0x07). Live bug (2026-09-20): retrying the
    // *enroll* packet itself on 0x08 0x05 sent a second 0x07 with the same
    // token, and NS had already consumed it on the first send — every retry
    // then failed as "token has been used up" and burned a fresh token per
    // attempt. A name collision is knowable without touching the token.
    if ns_name_is_taken_by_other_key(&token.ns_addr, &full_name, pubkey_bytes).await {
        let node_hex = hex::encode(identity.node_id.as_bytes());
        let new_device = disambiguated_device_name(device_name, &node_hex);
        full_name = format!("{}.{}", new_device, token.zone);
        ui.say(&format!(
            "  {} name already taken by another device — enrolling as {}",
            ui.yellow("⚠"),
            ui.bold(&full_name)
        ));
    }

    // v0.35.19: send the identity's Ed25519 signing key too, so the NS can
    // authorize this device's hourly check-in (sliding one-year lifetime).
    let signing_pubkey = identity.signing_key().verifying_key().to_bytes();
    let enroll_body = build_enroll_packet(
        &token_bin,
        pubkey_bytes,
        node_id_bytes,
        &full_name,
        addr_str,
        Some(&signing_pubkey),
    );
    let packet = [&[0x07u8][..], &enroll_body].concat();
    sock.send_to(&packet, ns_addr).await?;

    let mut buf = vec![0u8; 65535];
    let mut reply = timeout(Duration::from_secs(10), sock.recv_from(&mut buf)).await;
    if let Ok(Ok((len, _))) = &reply {
        if should_retry_enroll_without_signing_key(&buf[..*len]) {
            // Older NS: enroll with the legacy request (no automatic renewal).
            let legacy_body = build_enroll_packet(
                &token_bin,
                pubkey_bytes,
                node_id_bytes,
                &full_name,
                addr_str,
                None,
            );
            let legacy = [&[0x07u8][..], &legacy_body].concat();
            sock.send_to(&legacy, ns_addr).await?;
            reply = timeout(Duration::from_secs(10), sock.recv_from(&mut buf)).await;
        }
    }
    match reply {
        Ok(Ok((len, _))) => {
            let resp = &buf[..len];
            match resp {
                [0x08, 0x00, config @ ..] => {
                    ui.say(&format!(
                        "  {} Enrolled as {}",
                        ui.green("✓"),
                        ui.bold(&full_name)
                    ));

                    // Parse config from response
                    let (ns_relays, gateway_addrs) = parse_enroll_config(config)?;
                    let relay_addrs =
                        effective_relays(opts.relay.as_deref(), &ns_relays, &token.relay_addrs);

                    // NS-anchored gateway trust: a token minted with --ns-key
                    // makes the device trust only answers signed by that key.
                    // Establish (and prove) that trust BEFORE writing any
                    // config; a reply that does not verify aborts setup.
                    let ns_trust_store = match token.ns_key {
                        Some(ns_key) => {
                            use crate::agent::enroll_trust;
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            let nsset = enroll_trust::nsset_from_enroll_config(config)?;
                            let store = enroll_trust::initial_trust_store(
                                &token.ns_addr,
                                &token.zone,
                                ns_key,
                                nsset,
                                now,
                            )?;
                            enroll_trust::confirm_home_key(
                                &ns_addr.to_string(),
                                &full_name,
                                ns_key,
                                &hex::encode(pubkey_bytes),
                            )
                            .await
                            .map_err(|e| {
                                format!(
                                    "enrollment could not be verified: {e}. The device is NOT configured; \
                                     if this persists, ask for a new enrollment token."
                                )
                            })?;
                            ui.say(&format!(
                                "  {} name server verified against the token's key ({} trusted server{})",
                                ui.green("✓"),
                                store.servers.len(),
                                if store.servers.len() == 1 { "" } else { "s" }
                            ));
                            Some(store)
                        }
                        None => {
                            ui.say(&format!(
                                "  {} token has no name-server key: this device cannot verify name-server \
                                 answers (legacy trust). Ask for a token made with `ztlp admin enroll --ns-key`.",
                                ui.yellow("⚠")
                            ));
                            None
                        }
                    };
                    if let Some(ref store) = ns_trust_store {
                        let trust_path = agent_config_path
                            .parent()
                            .map(|d| d.join(crate::agent::ns_trust::FILE_NAME))
                            .unwrap_or_else(crate::agent::ns_trust::default_path);
                        store.save(&trust_path)?;
                        ui.say(&format!(
                            "  {} name-server trust written to {}",
                            ui.green("✓"),
                            trust_path.display()
                        ));
                    }

                    // Write config file
                    write_config_file(
                        &config_path,
                        &key_path,
                        &token.zone,
                        &token.ns_addr,
                        &relay_addrs,
                        &gateway_addrs,
                    )?;
                    ui.say(&format!(
                        "  {} Config written to {}",
                        ui.green("✓"),
                        config_path.display()
                    ));

                    // agent.toml so `ztlp agent start` works with zero hand
                    // edits (relay HMAC secret, DNS zone). Existing file is
                    // left alone (hand-tuned configs win).
                    if agent_config_path.exists() {
                        ui.say(&format!(
                            "  {} {} already exists — left untouched",
                            ui.yellow("⚠"),
                            agent_config_path.display()
                        ));
                    } else {
                        // ZT-01: the token carries the relay secret, so a user
                        // who only enrolls gets a working relay path. An explicit
                        // --relay-secret / --relay-secret-file still wins.
                        let (effective_secret, from_token) = effective_relay_secret(
                            opts.relay_secret.as_deref(),
                            token.relay_secret.as_deref(),
                        );
                        write_agent_config_file(
                            &agent_config_path,
                            &key_path,
                            &token.zone,
                            &token.ns_addr,
                            &relay_addrs,
                            effective_secret.as_deref(),
                        )?;
                        ui.say(&format!(
                            "  {} Agent config written to {}",
                            ui.green("✓"),
                            agent_config_path.display()
                        ));
                        if from_token {
                            ui.say(&format!(
                                "  {} relay secret taken from the enrollment token",
                                ui.green("✓")
                            ));
                        } else if effective_secret.is_none() {
                            ui.say(&format!(
                                "  {} no relay secret (not in the token, no --relay-secret): agent.toml has no relay_secret. \
                                 Fine for dev/staging relays; prod-HMAC relays will reject every route.",
                                ui.yellow("⚠")
                            ));
                        }
                    }

                    // Confirm enrollment with Bootstrap (best-effort)
                    if let Some(ref url) = token.callback_url {
                        // v0.30.12: pass the device's Noise static pubkey so
                        // Launch can auto-bind it for passwordless gateway
                        // sign-in. Bootstrap (Rails) ignores unknown fields,
                        // so this is safe to send unconditionally.
                        let pubkey_hex = hex::encode(identity.static_public_key.as_slice());
                        if cfg!(target_os = "ios") {
                            // No child processes on iOS (the desktop path
                            // runs curl): leave the callback for the app.
                            defer_enrollment_callback(
                                ztlp_dir,
                                url,
                                token,
                                &full_name,
                                &identity.node_id,
                                &pubkey_hex,
                                ui,
                            );
                        } else {
                            confirm_enrollment(
                                url,
                                token,
                                &full_name,
                                &identity.node_id,
                                &pubkey_hex,
                                ui,
                            )
                            .await;
                        }
                    }

                    // Test connectivity
                    ui.say("");
                    ui.say(&format!("  {} Testing connectivity...", ui.dim("→")));
                    test_connectivity(&relay_addrs, ui).await;

                    return Ok(EnrollOutcome {
                        full_name,
                        zone: token.zone.clone(),
                        node_id: identity.node_id.to_string(),
                        public_key_hex: hex::encode(identity.static_public_key.as_slice()),
                        key_path,
                        config_path,
                        agent_config_path,
                    });
                }
                [0x08, 0x01] => {
                    return Err("enrollment failed: token expired".into());
                }
                [0x08, 0x02] => {
                    return Err(
                        "enrollment failed: token has been used up (max uses reached)".into(),
                    );
                }
                [0x08, 0x03] => {
                    return Err(
                        "enrollment failed: invalid token (wrong secret or tampered)".into(),
                    );
                }
                [0x08, 0x04] => {
                    return Err(format!(
                        "enrollment failed: name '{}' is not in zone '{}'",
                        full_name, token.zone
                    )
                    .into());
                }
                [0x08, 0x05] => {
                    return Err(format!(
                        "enrollment failed: name '{}' is already taken by another device",
                        full_name
                    )
                    .into());
                }
                [0x08, 0x06] => {
                    return Err("enrollment failed: NS server rejected the request (enrollment may not be configured)".into());
                }
                _ => {
                    return Err(format!(
                        "unexpected response from NS server: {:02x?}",
                        &resp[..resp.len().min(16)]
                    )
                    .into());
                }
            }
        }
        Ok(Err(e)) => {
            return Err(format!(
                "network error contacting NS server at {}: {}",
                token.ns_addr, e
            )
            .into());
        }
        Err(_) => {
            return Err(format!(
                "timeout: NS server at {} did not respond within 10 seconds.\n  \
                 Is the NS server running? Check: ztlp ns lookup test.{} --ns-server {}",
                token.ns_addr, token.zone, token.ns_addr
            )
            .into());
        }
    }
}

/// Record an enrollment callback this host cannot send itself.
///
/// The desktop CLI POSTs the token-redemption callback with `curl`. A host
/// that cannot run child processes (iOS) writes the URL and form body to
/// [`PENDING_CALLBACK_FILE`] in the `.ztlp` directory instead, so the app
/// can send the same POST (`Content-Type:
/// application/x-www-form-urlencoded`) and then delete the file. The body
/// carries identifiers and the device PUBLIC key only. Best-effort, like
/// the callback itself: the device is enrolled at the name server either
/// way.
pub fn defer_enrollment_callback(
    ztlp_dir: &std::path::Path,
    callback_url: &str,
    token: &crate::enrollment::EnrollmentToken,
    device_name: &str,
    node_id: &NodeId,
    pubkey_hex: &str,
    ui: &dyn EnrollUi,
) {
    let token_id = match &token.token_id {
        Some(id) => id.clone(),
        None => return,
    };
    let body = format!(
        "token_id={}&node_id={}&name={}&pubkey_hex={}",
        token_id, node_id, device_name, pubkey_hex
    );
    let doc = serde_json::json!({
        "url": callback_url,
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "body": body,
    });
    let path = ztlp_dir.join(PENDING_CALLBACK_FILE);
    match std::fs::write(&path, doc.to_string()) {
        Ok(()) => ui.say(&format!(
            "  {} Enrollment callback left for the app to send ({})",
            ui.dim("·"),
            path.display()
        )),
        Err(e) => ui.say(&format!(
            "  {} Could not record the enrollment callback at {}: {}",
            ui.yellow("!"),
            path.display(),
            e
        )),
    }
}

/// Confirm enrollment with the Bootstrap app.
///
/// Phase B: this used to be a `_ = result;`-style best-effort callback that
/// silently swallowed every failure mode (DNS, TLS, 4xx, 5xx, timeout).
/// That made the redemption bug invisible — Steve's CLI said "enrolled"
/// while the Bootstrap dashboard still showed `active` because this
/// callback either was never sent (callback URL nil) or failed in a way
/// no operator could see.
///
/// New behavior:
///   * If `callback_url` is missing/empty, do nothing (legacy tokens predate
///     Phase B and have no callback path; print one diagnostic line).
///   * Drop `-f` (curl's fail-on-error) so we get the response body on 4xx/5xx.
///   * On HTTP success, print "Redeemed" line so the operator can see it.
///   * On HTTP failure, print a *visible* warning with status + body so the
///     bug — if any — is loud, not silent. Enrollment is still considered
///     successful at the NS layer (the device IS enrolled in NS), so we do
///     not return an error; we just warn loudly.
pub async fn confirm_enrollment(
    callback_url: &str,
    token: &crate::enrollment::EnrollmentToken,
    device_name: &str,
    node_id: &NodeId,
    pubkey_hex: &str,
    ui: &dyn EnrollUi,
) {
    let token_id = match &token.token_id {
        Some(id) => id.clone(),
        None => return,
    };

    // Use curl for HTTPS support (TLS without adding deps). We deliberately
    // do NOT pass `-f` here — Phase B made silent 4xx/5xx the whole problem.
    // We want to see what the Bootstrap actually said.
    //
    // v0.30.12 — body now carries `pubkey_hex`. When the callback URL
    // resolves to Launch, Launch will treat this as an implicit first-bind
    // of the admin's Noise static pubkey (skips the manual
    // /api/admin-pubkey + force-recreate dance). When the callback
    // resolves to Bootstrap (Rails), the field is silently dropped by
    // strong-params — sending it everywhere is safe and avoids the CLI
    // needing to know which kind of callback it's hitting.
    let body = format!(
        "token_id={}&node_id={}&name={}&pubkey_hex={}",
        token_id, node_id, device_name, pubkey_hex
    );

    let result = tokio::process::Command::new("curl")
        .args([
            "-s",
            // v0.30.12: bumped from 5s to 60s. With the v0.30.12 server-side
            // change, /api/enrollment/confirm runs `docker compose up -d
            // --force-recreate gateway` inline when pubkey_hex is present —
            // which can take 10-30s. The 5s budget the original Phase B
            // landed with is fine for the no-op status flip, but reliably
            // times out the auto-bind path. The endpoint is still
            // best-effort from the CLI's POV (the device IS enrolled at NS
            // regardless), so a wider timeout doesn't make us *less*
            // resilient; it just lets the happy path complete.
            "--max-time",
            "60",
            "-w",
            "\n%{http_code}", // append HTTP code on its own line so we can split body/code
            "-X",
            "POST",
            "-H",
            "Content-Type: application/x-www-form-urlencoded",
            "-d",
            &body,
            callback_url,
        ])
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            // curl-level success — now check the HTTP status code curl printed.
            // Format: <response_body>\n<http_code>
            let combined = String::from_utf8_lossy(&output.stdout);
            let (response_body, code_str) = match combined.rsplit_once('\n') {
                Some((body, code)) => (body, code),
                None => ("", combined.as_ref()),
            };
            let code: u16 = code_str.trim().parse().unwrap_or(0);
            if (200..300).contains(&code) {
                ui.say(&format!(
                    "  {} Bootstrap confirmed token redemption (HTTP {})",
                    ui.green("✓"),
                    code
                ));
                // v0.30.12: surface the Launch autobind result so operators
                // can tell whether passwordless dashboard sign-in is wired
                // up without having to read the gateway env. We do best-
                // effort JSON parsing — Bootstrap (Rails) returns a redirect
                // body with no JSON, so we just skip silently if the response
                // doesn't look like a Launch ack.
                if let Some(autobind) = extract_json_string_field(response_body, "autobind") {
                    match autobind.as_str() {
                        "applied" => {
                            ui.say(&format!(
                                "  {} Admin pubkey auto-bound for passwordless dashboard sign-in",
                                ui.green("✓"),
                            ));
                        }
                        "already_bound" => {
                            ui.say(&format!(
                                "  {} Admin pubkey was already bound on this tenant — skipped (first-bind only)",
                                ui.dim("·"),
                            ));
                        }
                        "invalid" => {
                            ui.say(&format!(
                                "  {} Launch rejected the device pubkey as invalid — passwordless sign-in not configured",
                                ui.yellow("!"),
                            ));
                        }
                        "provisioning_incomplete" => {
                            ui.say(&format!(
                                "  {} Tenant gateway not provisioned yet — passwordless sign-in deferred",
                                ui.yellow("!"),
                            ));
                        }
                        "skipped" => { /* Legacy server, no message needed. */ }
                        other => {
                            ui.say(&format!(
                                "  {} Launch autobind returned status '{}' — passwordless sign-in may not be active",
                                ui.yellow("!"),
                                other,
                            ));
                        }
                    }
                }
            } else if code == 429 {
                // v0.30.13 (issue #55): Launch rate-limits this endpoint
                // per token_id. The device IS enrolled at NS — Launch
                // just refused the bookkeeping callback. Honour the
                // retry-after hint if Launch returned one; otherwise
                // default to 60s (the documented bucket window).
                let retry_after =
                    extract_json_number_field(response_body, "retry_after_seconds").unwrap_or(60);
                ui.say(&format!(
                    "  {} Bootstrap callback rate-limited (HTTP 429). The device is enrolled, but the dashboard \
                     bookkeeping + admin-pubkey autobind will retry after {}s. Re-run `ztlp setup` if this is unexpected.",
                    ui.yellow("!"),
                    retry_after,
                ));
            } else {
                // Loud but non-fatal: device IS enrolled in NS, but the dashboard
                // bookkeeping callback did not stick. Operator can see this.
                ui.say(&format!(
                    "  {} Bootstrap callback returned HTTP {} ({}). The device is enrolled, but the dashboard token may still show 'active' until the next TokenReconciler sweep.",
                    ui.yellow("!"),
                    code,
                    callback_url
                ));
            }
        }
        Ok(output) => {
            // curl itself failed (network, DNS, TLS). Loud but non-fatal.
            let stderr = String::from_utf8_lossy(&output.stderr);
            ui.say(&format!(
                "  {} Bootstrap callback failed to connect to {} (curl exit {}): {}",
                ui.yellow("!"),
                callback_url,
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }
        Err(e) => {
            // Couldn't even spawn curl. Almost certainly a packaging bug.
            ui.say(&format!(
                "  {} Could not spawn curl for Bootstrap callback: {}",
                ui.yellow("!"),
                e
            ));
        }
    }
}

/// Tiny JSON string-field extractor for the confirm-callback response.
///
/// Avoids pulling in `serde_json` just to read one field from a known-shape
/// Launch ack like `{"status":"redeemed","name":"admin","autobind":"applied"}`.
/// Returns None if the body isn't JSON-ish or the field is missing.
///
/// Only matches `"field":"value"` — does NOT handle nested objects, escape
/// sequences, or numeric/bool values. That's intentional: the Launch ack
/// shape is fixed and tiny, and we explicitly do NOT want to fail
/// enrollment over a parsing edge case.
pub fn extract_json_string_field(body: &str, field: &str) -> Option<String> {
    let needle = format!("\"{}\"", field);
    let start = body.find(&needle)?;
    let after_key = &body[start + needle.len()..];
    // Skip whitespace and the colon.
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    // Expect an opening quote.
    let after_quote = after_colon.strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(after_quote[..end].to_string())
}

/// Tiny JSON number-field extractor for the confirm-callback 429 ack.
///
/// Same constraints as `extract_json_string_field` — sibling helper for
/// the v0.30.13 rate-limit response, which carries:
/// `{"error":"rate_limited","scope":"enrollment_confirm","retry_after_seconds":60}`.
///
/// Returns None if the field is missing, malformed, or non-integer.
pub fn extract_json_number_field(body: &str, field: &str) -> Option<u64> {
    let needle = format!("\"{}\"", field);
    let start = body.find(&needle)?;
    let after_key = &body[start + needle.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?.trim_start();
    // Take the leading digit run, stop at the first non-digit (`,`, `}`, etc.).
    let digits: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Build the 0x07 ENROLL request body (without the 0x07 prefix).
///
/// `signing_pubkey` (v0.35.19+) appends `<<32::16, ed25519_pubkey::32>>`
/// after the address. The NS stores it in the enrolled KEY record as
/// `signing_public_key`, which is what authorizes the agent's hourly
/// check-in and keeps the device registered for a sliding year. `None`
/// produces the exact pre-v0.35.19 wire format.
pub fn build_enroll_packet(
    token: &[u8],
    pubkey: &[u8],
    node_id: &[u8; 16],
    name: &str,
    addr: &str,
    signing_pubkey: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Token length + token
    buf.extend_from_slice(&(token.len() as u16).to_be_bytes());
    buf.extend_from_slice(token);

    // Public key (padded to 32 bytes if needed)
    let mut pk = [0u8; 32];
    let copy_len = pubkey.len().min(32);
    pk[..copy_len].copy_from_slice(&pubkey[..copy_len]);
    buf.extend_from_slice(&pk);

    // Node ID (16 bytes)
    buf.extend_from_slice(node_id);

    // Name
    let name_bytes = name.as_bytes();
    buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(name_bytes);

    // Address (may be empty)
    let addr_bytes = addr.as_bytes();
    buf.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(addr_bytes);

    // Optional Ed25519 signing pubkey (v0.35.19 extension)
    if let Some(sk) = signing_pubkey {
        buf.extend_from_slice(&(sk.len() as u16).to_be_bytes());
        buf.extend_from_slice(sk);
    }

    buf
}

/// An NS older than v0.35.19 does not know the signing-key extension and
/// answers the longer ENROLL request with 0x08 0x06 (invalid format). It
/// does so while PARSING, before the token is validated, so the token is
/// not consumed and the legacy request can be sent once more.
pub fn should_retry_enroll_without_signing_key(resp: &[u8]) -> bool {
    resp == [0x08, 0x06]
}

/// Parse the config section of an ENROLL response.
pub fn parse_enroll_config(
    data: &[u8],
) -> Result<(Vec<String>, Vec<String>), Box<dyn std::error::Error>> {
    let mut pos = 0;

    // Relay addresses
    if pos >= data.len() {
        return Ok((vec![], vec![]));
    }
    let relay_count = data[pos] as usize;
    pos += 1;

    let mut relays = Vec::with_capacity(relay_count);
    for _ in 0..relay_count {
        if pos + 2 > data.len() {
            break;
        }
        let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            break;
        }
        let addr = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
        pos += len;
        relays.push(addr);
    }

    // Gateway addresses
    let mut gateways = Vec::new();
    if pos < data.len() {
        let gw_count = data[pos] as usize;
        pos += 1;

        for _ in 0..gw_count {
            if pos + 2 > data.len() {
                break;
            }
            let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if pos + len > data.len() {
                break;
            }
            let addr = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
            pos += len;
            gateways.push(addr);
        }
    }

    Ok((relays, gateways))
}

/// Plain NS lookup (0x01 via `ns_query_raw`, never consumes the enroll
/// token) to check whether `full_name` already resolves to a DIFFERENT
/// public key than the one about to enroll. Best-effort: any lookup
/// failure (timeout, not found, unparseable record) is treated as "not
/// taken" — the real enroll attempt is still the source of truth; this
/// only avoids burning a single-use token on a name we can already see is
/// claimed by someone else.
pub async fn ns_name_is_taken_by_other_key(
    ns_server: &str,
    full_name: &str,
    our_pubkey: &[u8],
) -> bool {
    // KEY record (type 1) carries the owning identity's public_key.
    let Ok(Some(result)) = ns_query_raw(full_name, ns_server, 1).await else {
        return false;
    };
    let Some(existing) = cbor_extract_string(&result.data_bytes, "public_key") else {
        return false;
    };
    existing.to_ascii_lowercase() != hex::encode(our_pubkey)
}

/// On NS `0x08 0x05` (name taken by a DIFFERENT key — e.g. this very Mac
/// was wiped and re-enrolled, so the old key still owns the hostname) retry
/// once with a short, stable, per-identity suffix instead of failing:
/// `stevens-macbook-pro-2` -> `stevens-macbook-pro-2-4c44`. Stable because
/// it derives from the node id, so a second retry on the same identity is
/// idempotent (same pubkey re-enroll is allowed by NS).
pub fn disambiguated_device_name(device_name: &str, node_id_hex: &str) -> String {
    let suffix: String = node_id_hex.chars().take(4).collect();
    format!("{}-{}", device_name.trim_end_matches('-'), suffix)
}

/// Write a config.toml file with the enrollment results.
pub fn write_config_file(
    path: &std::path::Path,
    key_path: &std::path::Path,
    zone: &str,
    ns_server: &str,
    relay_addrs: &[String],
    gateway_addrs: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let relay_str = if relay_addrs.len() == 1 {
        toml_string(&relay_addrs[0])
    } else {
        format!(
            "[{}]",
            relay_addrs
                .iter()
                .map(|a| toml_string(a))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let mut content = format!(
        r#"# ZTLP Configuration — generated by `ztlp setup`
# Zone: {zone_comment}

identity = {key_path}
ns_server = {ns_server}
{relay_str}
zone = {zone}
"#,
        zone_comment = zone,
        key_path = toml_string(&key_path.display().to_string()),
        ns_server = toml_string(ns_server),
        relay_str = if relay_str == "[]" {
            "".to_string()
        } else {
            format!("relay = {}", relay_str)
        },
        zone = toml_string(zone),
    );

    if !gateway_addrs.is_empty() {
        content.push_str(&format!("gateway = {}\n", toml_string(&gateway_addrs[0])));
    }

    std::fs::write(path, &content)?;

    Ok(())
}

/// Options for `ztlp setup` that don't fit the legacy positional signature.
pub struct SetupOpts {
    /// Allow re-enrolling over an existing ~/.ztlp identity (with backup).
    pub force: bool,
    /// Relay CLIENT_ROUTE HMAC secret to persist in agent.toml (as given —
    /// 64-hex, `base64:`, or raw; the agent decodes it at load time).
    pub relay_secret: Option<String>,
    /// `--relay` override (empty token/NS relays).
    pub relay: Option<String>,
}

/// Relay list to persist after enrollment. Precedence: explicit `--relay`,
/// then the NS enroll response, then the token's own relays. The last step
/// is the fix for the Mac field report (2026-10-13): when the NS answered
/// with no relays, agent.toml got `relays = []` even though the token
/// carried one.
pub fn effective_relays(
    override_relay: Option<&str>,
    from_ns: &[String],
    from_token: &[String],
) -> Vec<String> {
    if let Some(r) = override_relay.map(str::trim).filter(|s| !s.is_empty()) {
        return vec![r.to_string()];
    }
    if !from_ns.is_empty() {
        return from_ns.to_vec();
    }
    from_token.to_vec()
}

/// Which relay secret `ztlp setup` should persist, and whether it came from
/// the enrollment token (ZT-01). An explicit `--relay-secret` /
/// `--relay-secret-file` always wins; otherwise the token's secret is used so
/// a user who only enrolls ends up with a working relay path.
pub fn effective_relay_secret(
    explicit: Option<&str>,
    from_token: Option<&str>,
) -> (Option<String>, bool) {
    let explicit = explicit.map(str::trim).filter(|s| !s.is_empty());
    let from_token = from_token.map(str::trim).filter(|s| !s.is_empty());
    match (explicit, from_token) {
        (Some(e), _) => (Some(e.to_string()), false),
        (None, Some(t)) => (Some(t.to_string()), true),
        (None, None) => (None, false),
    }
}

/// Refuse to overwrite an existing enrollment unless `force`.
///
/// Returns `Ok(None)` when there is nothing to protect, `Ok(Some(paths))`
/// with the backup paths when `force` moved identity.json / config.toml /
/// agent.toml aside, or `Err` (nothing touched) when an identity exists and
/// `force` is false. `--yes` deliberately does NOT imply force: the old
/// behaviour ("--yes overwrites") orphaned enrolled devices on NS.
pub fn guard_existing_identity(
    ztlp_dir: &std::path::Path,
    force: bool,
) -> Result<Option<Vec<PathBuf>>, Box<dyn std::error::Error>> {
    let identity = ztlp_dir.join("identity.json");
    if !identity.exists() {
        return Ok(None);
    }
    if !force {
        return Err(format!(
            "this machine is already enrolled ({} exists).\n  \
             Re-run with --force to re-enroll (the current identity.json, config.toml, \
             agent.toml and zone.key are backed up to *.<timestamp>.bak first), \
             or `ztlp status --identity` to see what it is.",
            identity.display()
        )
        .into());
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut backed = Vec::new();
    for name in ["identity.json", "config.toml", "agent.toml", "zone.key"] {
        let src = ztlp_dir.join(name);
        if src.exists() {
            let dst = ztlp_dir.join(format!("{}.{}.bak", name, ts));
            std::fs::rename(&src, &dst)
                .map_err(|e| format!("backup {} -> {}: {}", src.display(), dst.display(), e))?;
            backed.push(dst);
        }
    }
    Ok(Some(backed))
}

/// Default agent DNS listen address written by `ztlp setup`.
///
/// 127.0.0.53:53 belongs to systemd-resolved and 127.0.0.54:53 to its
/// extra stub on recent Ubuntu, so the agent uses its own loopback alias +
/// high port. Matches what the demo docs hand-wrote before setup did it.
pub const SETUP_DEFAULT_DNS_LISTEN: &str = "127.0.0.55:15353";

/// Write `~/.ztlp/agent.toml` for a freshly enrolled device so `ztlp agent
/// start` works without hand edits. Refuses to overwrite an existing file.
pub fn write_agent_config_file(
    path: &std::path::Path,
    key_path: &std::path::Path,
    zone: &str,
    ns_server: &str,
    relay_addrs: &[String],
    relay_secret: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Err(format!("{} already exists; not overwriting", path.display()).into());
    }
    // CA already initialised alongside this config (ca-init ran first)?
    // Then https just works; otherwise default off (enabling without an
    // intermediate makes every https request fail).
    let tls_enabled = path
        .parent()
        .map(|d| d.join("ca").join("intermediate.pem").exists())
        .unwrap_or(false);
    let relays = relay_addrs
        .iter()
        .map(|a| toml_string(a))
        .collect::<Vec<_>>()
        .join(", ");
    let secret_line = match relay_secret {
        Some(s) => format!("relay_secret = {}", toml_string(s)),
        None => "# relay_secret = \"<64-hex shared with the relay's ZTLP_RELAY_REGISTRATION_SECRET>\"  # required for prod-HMAC relays".to_string(),
    };
    let content = format!(
        r#"# ZTLP agent configuration — generated by `ztlp setup`
# Zone: {zone_c}

[identity]
path = {key_path}

[ns]
servers = [{ns_server}]

[tunnel]
relays = [{relays}]
{secret_line}

[dns]
enabled = true
listen = {dns_listen}
zones = [{zone}]

[tls]
# Local TLS termination on the VIP. Needs a local CA: `ztlp admin ca-init
# --zone {zone_c}` (it flips this to true for you), then restart the agent.
enabled = {tls_enabled}
"#,
        zone_c = zone,
        tls_enabled = tls_enabled,
        key_path = toml_string(&key_path.display().to_string()),
        ns_server = toml_string(ns_server),
        relays = relays,
        secret_line = secret_line,
        dns_listen = toml_string(SETUP_DEFAULT_DNS_LISTEN),
        zone = toml_string(zone),
    );
    std::fs::write(path, &content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // holds the relay secret
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).ok();
    }
    Ok(())
}

/// Test connectivity to relay addresses.
pub async fn test_connectivity(relay_addrs: &[String], ui: &dyn EnrollUi) {
    use tokio::net::UdpSocket;
    use tokio::time::{timeout, Duration, Instant};

    for addr in relay_addrs {
        match addr.parse::<std::net::SocketAddr>() {
            Ok(sock_addr) => {
                match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(sock) => {
                        // Send a ZTLP magic check (just the magic bytes — relay will drop it
                        // but we can measure if the port is reachable)
                        let ping = [0x5A, 0x37, 0x00, 0x00];
                        let start = Instant::now();
                        let _ = sock.send_to(&ping, sock_addr).await;

                        // Try to receive any response (relay won't reply to bad packets,
                        // but if we get ICMP port unreachable, the recv will fail)
                        match timeout(Duration::from_millis(500), sock.recv_from(&mut [0u8; 64]))
                            .await
                        {
                            Ok(Ok(_)) => {
                                let rtt = start.elapsed();
                                ui.say(&format!(
                                    "  {} Relay {}: {}ms",
                                    ui.green("✓"),
                                    addr,
                                    rtt.as_millis()
                                ));
                            }
                            _ => {
                                // No response is normal — relay drops malformed packets silently
                                ui.say(&format!(
                                    "  {} Relay {}: reachable (no reply expected)",
                                    ui.green("✓"),
                                    addr
                                ));
                            }
                        }
                    }
                    Err(_) => {
                        ui.say(&format!(
                            "  {} Relay {}: could not bind socket",
                            ui.yellow("⚠"),
                            addr
                        ));
                    }
                }
            }
            Err(_) => {
                ui.say(&format!(
                    "  {} Relay {}: invalid address",
                    ui.yellow("⚠"),
                    addr
                ));
            }
        }
    }
}

// ─── Name-server lookup helpers (moved with the enrollment code) ───────────

pub fn toml_string(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len() + 2);
    rendered.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => rendered.push_str("\\\\"),
            '"' => rendered.push_str("\\\""),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            c if c.is_control() => rendered.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => rendered.push(c),
        }
    }
    rendered.push('"');
    rendered
}

/// Extract a string value for a given text key from a CBOR-encoded map.
///
/// Supports the subset of RFC 8949 CBOR used by ZTLP-NS:
/// - Maps (major type 5) with text string keys/values (major type 3)
///
/// Returns None if the key is not found or the format doesn't match.
pub fn cbor_extract_string(data: &[u8], target_key: &str) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let mut pos = 0;

    // Parse initial byte
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    pos += 1;

    // Must be a map (major type 5)
    if major != 5 {
        return None;
    }

    let (arity, new_pos) = cbor_read_uint(additional, data, pos)?;
    pos = new_pos;

    for _ in 0..arity {
        // Parse key
        let (key_str, new_pos) = cbor_read_text(data, pos)?;
        pos = new_pos;

        // Parse value
        let (val_str, new_pos) = cbor_read_text(data, pos)?;
        pos = new_pos;

        if key_str == target_key {
            return Some(val_str);
        }
    }

    None
}

/// Read a CBOR unsigned integer argument from the additional info byte.
pub fn cbor_read_uint(additional: u8, data: &[u8], pos: usize) -> Option<(usize, usize)> {
    if additional < 24 {
        Some((additional as usize, pos))
    } else if additional == 24 {
        if pos >= data.len() {
            return None;
        }
        Some((data[pos] as usize, pos + 1))
    } else if additional == 25 {
        if pos + 2 > data.len() {
            return None;
        }
        let n = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        Some((n, pos + 2))
    } else if additional == 26 {
        if pos + 4 > data.len() {
            return None;
        }
        let n =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        Some((n, pos + 4))
    } else {
        None
    }
}

/// Read a CBOR text string (major type 3) from data at the given position.
pub fn cbor_read_text(data: &[u8], pos: usize) -> Option<(String, usize)> {
    if pos >= data.len() {
        return None;
    }
    let initial = data[pos];
    let major = initial >> 5;
    let additional = initial & 0x1F;
    if major != 3 {
        return None;
    } // Must be text string
    let (len, new_pos) = cbor_read_uint(additional, data, pos + 1)?;
    if new_pos + len > data.len() {
        return None;
    }
    let s = std::str::from_utf8(&data[new_pos..new_pos + len]).ok()?;
    Some((s.to_string(), new_pos + len))
}

/// Query result from NS containing the raw CBOR data field.
pub struct NsQueryResult {
    /// Raw CBOR-encoded data bytes from the record
    pub data_bytes: Vec<u8>,
}

/// Check if a byte is a valid ZTLP-NS record type byte.
/// Core types: 1-7 (KEY, SVC, RELAY, POLICY, REVOKE, BOOTSTRAP, OPERATOR)
/// Identity types: 0x10-0x12 (DEVICE, USER, GROUP)
pub fn is_valid_record_type(type_byte: u8) -> bool {
    (1..=7).contains(&type_byte) || (0x10..=0x12).contains(&type_byte)
}

/// Pad length for unauthenticated NS 0x01 queries.
///
/// The NS applies amplification prevention: it caps a 0x01 query response to
/// `request_size * 8` and sets the truncation flag past that (see
/// `ns/lib/ztlp_ns/server.ex` `@amplification_threshold`). Stage-2
/// multi-candidate SVC records (v0.35.0+) can exceed 300 bytes, so a bare
/// ~26-byte query gets a ~208-byte cap and the fat record is silently
/// truncated, making the box unreachable by name. The server ignores trailing
/// query bytes specifically so clients can pad to raise their own cap. 256
/// bytes => a 2048-byte cap, above any realistic record (32 candidates) while
/// staying under the UDP MTU and at the server's sanctioned 8x ceiling.
pub const NS_QUERY_PAD_BYTES: usize = 256;

/// Resolve an `--ns-server` value to a concrete `SocketAddr`.
///
/// Accepts either `IP:PORT` (fast path — `SocketAddr::parse`) or
/// `HOSTNAME:PORT` (DNS-resolved). The hostname form is required for
/// Docker Compose / service-name deployments (e.g. `ns:23096` on a
/// compose network) where the NS is reached by service name rather than IP.
///
/// TDD-pinned by `mod tests::resolve_ns_address` (3 tests).
pub async fn resolve_ns_address(ns_server: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    // Fast path: already an IP:PORT.
    if let Ok(addr) = ns_server.parse::<SocketAddr>() {
        return Ok(addr);
    }
    // Hostname:PORT — split on the last ':' (hostname may be IPv6-in-brackets).
    let (host, port) = match ns_server.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p),
        None => {
            return Err(format!(
                "invalid --ns-server '{}': expected HOST:PORT or IP:PORT",
                ns_server
            )
            .into())
        }
    };
    let port: u16 = port
        .parse()
        .map_err(|_| format!("invalid --ns-server port '{}' in '{}'", port, ns_server))?;
    // Resolve the hostname. `lookup_host` handles both A and AAAA; take the
    // first result (deterministic enough for an NS bootstrap address).
    let mut it = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| {
            format!(
                "DNS resolution failed for --ns-server '{}': {}",
                ns_server, e
            )
        })?;
    it.next()
        .ok_or_else(|| format!("DNS returned no addresses for --ns-server '{}'", ns_server).into())
}

/// Perform an NS query for a given record type. Returns the raw CBOR data field if found.
pub async fn ns_query_raw(
    name: &str,
    ns_server: &str,
    record_type: u8,
) -> Result<Option<NsQueryResult>, Box<dyn std::error::Error>> {
    let ns_addr = resolve_ns_address(ns_server).await?;
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len() as u16;
    let mut query = Vec::with_capacity(4 + name_bytes.len());
    query.push(0x01);
    query.extend_from_slice(&name_len.to_be_bytes());
    query.extend_from_slice(name_bytes);
    query.push(record_type);

    // Amplification-prevention padding.
    //
    // The NS caps unauthenticated 0x01 query responses to
    // `request_size * 8` (server.ex @amplification_threshold) and sets the
    // truncation flag when a record exceeds that. Stage-2 multi-candidate
    // SVC records (v0.35.0+) can carry a large `addresses` ICE list (LAN +
    // multiple IPv6 + relay), pushing a record past 300 bytes. A bare query
    // (~26 bytes for a typical name) yields only a ~208-byte cap, so the fat
    // SVC record comes back TRUNCATED and `resolve_target` then reports
    // "no SVC record" even though the record exists — the box is
    // unreachable by name. (Observed on DEES / adms.trs.ztlp, 2026-06-16:
    // declared SVC data_len=320, only 177 bytes delivered.)
    //
    // The server explicitly ignores trailing bytes after the query
    // (process_query `_rest::binary`) precisely so clients can pad to raise
    // their own cap. Pad every query to NS_QUERY_PAD_BYTES so the cap is at
    // least NS_QUERY_PAD_BYTES * 8 — comfortably above any realistic record
    // (32 candidates * ~50 bytes + CBOR overhead) while staying well under
    // the UDP MTU and keeping the amplification factor at the server's
    // sanctioned 8x ceiling.
    if query.len() < NS_QUERY_PAD_BYTES {
        query.resize(NS_QUERY_PAD_BYTES, 0u8);
    }

    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    // Connected socket: the kernel drops datagrams from any other sender, so a
    // reply is only ever read from the name server we asked.
    sock.connect(ns_addr).await?;
    sock.send(&query).await?;
    let mut buf = vec![0u8; 65535];
    match timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
        Ok(Ok(len)) => {
            let data = &buf[..len];

            if data.is_empty() {
                return Ok(None);
            }
            if data[0] != 0x02 {
                return Ok(None);
            }
            // NS amplification prevention may insert a 0x01 truncation flag
            // after the 0x02 response code: <<0x02, 0x01, record...>>.
            // Detect by trying to parse from offset 2 first (with flag),
            // then fall back to offset 1 (no flag).
            let record = 'parse: {
                if data.len() > 5 && data[1] == 0x01 {
                    // Possible truncation flag — check if offset 2 yields a valid type_byte
                    // (1-7 for core types, 0x10-0x12 for identity types)
                    // and a reasonable name_len
                    let maybe_type = data[2];
                    if is_valid_record_type(maybe_type) && data.len() > 4 {
                        let maybe_name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
                        if maybe_name_len < 1024 && data.len() >= 5 + maybe_name_len {
                            break 'parse &data[2..];
                        }
                    }
                }
                &data[1..]
            };
            // Wire format: <<type_byte, name_len::16, name, data_len::32, data, ...>>
            if record.len() < 4 {
                return Ok(None);
            }
            let _type_byte = record[0];
            let rname_len = u16::from_be_bytes([record[1], record[2]]) as usize;
            if record.len() < 3 + rname_len + 4 {
                return Ok(None);
            }
            let offset = 3 + rname_len;
            let data_len = u32::from_be_bytes([
                record[offset],
                record[offset + 1],
                record[offset + 2],
                record[offset + 3],
            ]) as usize;
            if record.len() < offset + 4 + data_len {
                return Ok(None);
            }
            let data_start = offset + 4;
            let data_bytes = record[data_start..data_start + data_len].to_vec();
            Ok(Some(NsQueryResult { data_bytes }))
        }
        _ => Ok(None),
    }
}
