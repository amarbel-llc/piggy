//! Direct-PCSC ECDH oracle, sibling to [`crate::agent_client`].
//!
//! When no piggy-agent (or other `ecdh@joyent.com`-speaking SSH agent) is
//! reachable on `SSH_AUTH_SOCK`, `piggy box stream decrypt` falls through
//! to this oracle: it talks straight to a PIV card over PCSC, prompts for
//! the PIN, and runs ECDH on the card. Closes the agentless gap that
//! issue #31 tracks; the on-card primitives all live in `piggy_piv`
//! (`PinSession::verify_pin`, `PinSession::ecdh_derive`, bracketed in a
//! PC/SC transaction — piggy#56).
//!
//! ## PIN supply
//!
//! [`CardEcdhOracle::new`] takes a `pin_supplier` closure that the oracle
//! calls the first time it needs to authenticate to a given token. The
//! closure receives a prompt string and returns a `Zeroizing<String>` so
//! the PIN is wiped from memory once it falls out of scope on the card
//! side. Each `ecdh` call opens its own PC/SC transaction (a
//! [`piggy_piv::PinSession`]) and re-verifies the PIN inside it, so a
//! co-resident PIV agent's `SCARD_RESET_CARD` can't clear PIN state
//! mid-operation (piggy#56). The PIN is cached per token GUID, so a
//! multi-part decrypt still prompts the user only once.
//!
//! [`askpass_pin_supplier`] returns the default supplier: spawn the
//! program named in `SSH_ASKPASS` with the prompt as argv[1]. That
//! composes with both the user-facing `contrib/piggy-askpass.sh` (#33)
//! and the test-harness `zz-tests_bats/helpers/piggy-test-askpass.sh`
//! (#35) — neither requires any new Rust dependency.
//!
//! ## Token matching
//!
//! [`EcdhOracle::ecdh`] hands us only the `self_pubkey_ssh_blob` —
//! there's no GUID hint in the trait. We enumerate connected PIV tokens,
//! read the 0x9D (Key Management) slot pubkey from each, and match by
//! SEC1-uncompressed-byte equality. Pubkey collision implies the same
//! private key, so the match is unambiguous. Templates with slots other
//! than 0x9D are out of scope for v1 (matches `template::DEFAULT_SLOT`).

use std::collections::HashMap;
use std::io::Read;
use std::process::{Command, Stdio};

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcPoint, PointConversionForm};
use piggy_box::agent_ext::extract_point_from_sshkey_blob;
use piggy_box::oracle::{EcdhOracle, OracleError};
use piggy_box::piv_box::EcCurve;
use piggy_box::template::DEFAULT_SLOT;
use piggy_piv::{Guid, PivContext, PivError, PivToken};
use ssh_key::public::{EcdsaPublicKey, KeyData};
use zeroize::Zeroizing;

/// Closure type for supplying a PIN on demand.
///
/// `FnMut` so a supplier can carry mutable state (e.g. cache the PIN
/// across calls within a single decrypt invocation, or count attempts).
/// The argument is the prompt string the oracle would like to display;
/// suppliers may render it however they want, or ignore it.
pub type PinSupplier = Box<dyn FnMut(&str) -> Result<Zeroizing<String>, OracleError>>;

/// ECDH oracle backed by a directly-connected PIV card via PCSC.
pub struct CardEcdhOracle {
    ctx: PivContext,
    pin_supplier: PinSupplier,
    /// PIN cache keyed by token GUID. Populated on first authentication to a
    /// token; lets a multi-part decrypt reuse the PIN (one prompt) even
    /// though each `ecdh` call now runs in its own PC/SC transaction
    /// (piggy#56). `Zeroizing` wipes each cached PIN when the oracle drops.
    pin_cache: HashMap<Guid, Zeroizing<String>>,
}

impl CardEcdhOracle {
    /// Build an oracle. Establishes a PCSC context up front; returns
    /// `OracleError::Transport` if the resource manager is unreachable
    /// (no pcscd, no `PCSCLITE_CSOCK_NAME`, etc).
    pub fn new(pin_supplier: PinSupplier) -> Result<Self, OracleError> {
        let ctx =
            PivContext::new().map_err(|e| OracleError::Transport(format!("PCSC context: {e}")))?;
        Ok(Self {
            ctx,
            pin_supplier,
            pin_cache: HashMap::new(),
        })
    }

    /// Find the connected PIV token whose 0x9D slot pubkey matches
    /// `target_uncompressed`. Returns `None` if nothing matches.
    fn find_token_by_pubkey(
        &self,
        target_uncompressed: &[u8],
    ) -> Result<Option<PivToken>, OracleError> {
        let tokens = self
            .ctx
            .enumerate_tokens()
            .map_err(|e| OracleError::Transport(format!("enumerate tokens: {e}")))?;
        for token in tokens {
            let slot = match token.read_slot(DEFAULT_SLOT) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let candidate = match slot.public_key().key_data() {
                KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => p.as_bytes().to_vec(),
                KeyData::Ecdsa(EcdsaPublicKey::NistP384(p)) => p.as_bytes().to_vec(),
                _ => continue,
            };
            if candidate == target_uncompressed {
                return Ok(Some(token));
            }
        }
        Ok(None)
    }
}

impl EcdhOracle for CardEcdhOracle {
    fn ecdh(
        &mut self,
        self_pubkey_ssh_blob: &[u8],
        partner_pubkey_ssh_blob: &[u8],
    ) -> Result<Vec<u8>, OracleError> {
        let self_point_raw = extract_point_from_sshkey_blob(self_pubkey_ssh_blob)?;
        let self_uncompressed = canonicalize_uncompressed(&self_point_raw)?;

        let mut token = match self.find_token_by_pubkey(&self_uncompressed)? {
            Some(t) => t,
            None => return Err(OracleError::NoKey),
        };

        let token_guid = token.guid().clone();

        // Prompt for the PIN only the first time we authenticate to a given
        // token; reuse the cached PIN on later parts so the user is prompted
        // once even though each part now runs in its own transaction (piggy#56).
        let pin = match self.pin_cache.get(&token_guid) {
            Some(p) => p.clone(),
            None => {
                let prompt = format!("PIV PIN for token {}", token_guid.to_hex());
                let p = (self.pin_supplier)(&prompt)?;
                self.pin_cache.insert(token_guid, p.clone());
                p
            }
        };

        let partner_point_raw = extract_point_from_sshkey_blob(partner_pubkey_ssh_blob)?;
        let partner_uncompressed = canonicalize_uncompressed(&partner_point_raw)?;

        // Bracket verify-PIN + ECDH in one PC/SC transaction so a co-resident
        // PIV agent's SCARD_RESET_CARD cannot clear PIN state between them
        // (piggy#56). The session ends (ResetCard) when it drops at scope exit.
        let mut session = token
            .begin_pin_session()
            .map_err(|e| OracleError::Transport(format!("begin_pin_session: {e}")))?;
        session.verify_pin(&pin).map_err(piv_to_oracle_pin_error)?;
        let secret = session
            .ecdh_derive(DEFAULT_SLOT, &partner_uncompressed)
            .map_err(|e| OracleError::Transport(format!("ecdh_derive: {e}")))?;
        Ok(secret)
    }
}

/// Convert a PIV PIN error into the closest `OracleError` variant we have.
/// We use `Other` rather than `Transport` for PIN-shaped failures because
/// retransmitting won't help — the wire is fine, the human got it wrong.
///
/// `pub` because [`crate::show_batch`]'s `BatchOracle` reuses the same
/// mapping: when `PinSession::verify_pin` returns `PinIncorrect`/
/// `PinBlocked`, the oracle surface needs the equivalent `OracleError`
/// shape so `unlock_ebox` propagates it as a normal oracle failure
/// rather than dressing it up as a transport problem.
pub fn piv_to_oracle_pin_error(e: PivError) -> OracleError {
    match e {
        PivError::PinIncorrect { retries } => {
            OracleError::Other(format!("wrong PIN, {retries} retries remaining"))
        }
        PivError::PinBlocked => OracleError::Other("PIN blocked".into()),
        other => OracleError::Transport(format!("verify_pin: {other}")),
    }
}

/// Ensure an EC point is in SEC1-uncompressed form (`0x04 || X || Y`).
///
/// `piggy-piv::PinSession::ecdh_derive` rejects compressed inputs explicitly
/// (see `crates/piggy-piv/src/token.rs::validate_ec_point`). The pubkey
/// blobs `unlock_ebox` hands us are already uncompressed in practice
/// (`agent_ext::ec_point_to_ssh_pubkey_blob` is fed uncompressed bytes
/// after `decompress_ec_point`), but be tolerant here in case a future
/// caller passes compressed bytes through.
///
/// `pub` because [`crate::show_batch`]'s `BatchOracle` reuses this for
/// the partner-point canonicalization step before handing the point to
/// `PinSession::ecdh_derive`.
pub fn canonicalize_uncompressed(point: &[u8]) -> Result<Vec<u8>, OracleError> {
    if point.first() == Some(&0x04) {
        return Ok(point.to_vec());
    }
    let curve = match point.len() {
        33 => EcCurve::NistP256, // 0x02/0x03 || X(32)
        49 => EcCurve::NistP384, // 0x02/0x03 || X(48)
        n => {
            return Err(OracleError::InvalidPubkey(format!(
                "compressed point of length {n} does not match P-256 or P-384"
            )));
        }
    };
    let group = EcGroup::from_curve_name(curve.nid())
        .map_err(|e| OracleError::Other(format!("openssl group: {e}")))?;
    let mut ctx =
        BigNumContext::new().map_err(|e| OracleError::Other(format!("openssl bn ctx: {e}")))?;
    let ec = EcPoint::from_bytes(&group, point, &mut ctx)
        .map_err(|e| OracleError::InvalidPubkey(format!("decompress: {e}")))?;
    let bytes = ec
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|e| OracleError::Other(format!("openssl encode: {e}")))?;
    Ok(bytes)
}

/// Run `$SSH_ASKPASS` with `prompt` as `argv[1]` and return the PIN it
/// prints on stdout (trailing CR/LF trimmed, must be non-empty).
///
/// When `context` is `Some`, it is exported to the askpass child as
/// `PIGGY_ASKPASS_CONTEXT`, which `contrib/piggy-askpass.sh` renders as
/// origin info on the prompt (#33) and the test askpass surfaces in its
/// banner (#35). The Rust `piggy agent`'s prompt-on-demand path sets this
/// to identify the request (piggy#58); the agentless oracle passes `None`.
///
/// Synchronous (forks + waits). Async callers (the agent) wrap this in
/// `tokio::task::spawn_blocking`. Reference impl: pivy's
/// `vendor/pivy/src/ebox-cmd.c::run_askpass`.
pub fn run_askpass(prompt: &str, context: Option<&str>) -> Result<Zeroizing<String>, OracleError> {
    let askpass = match std::env::var_os("SSH_ASKPASS") {
        Some(v) if !v.is_empty() => v,
        _ => {
            return Err(OracleError::Other(
                "no PIN source: SSH_ASKPASS not set".into(),
            ));
        }
    };
    let mut cmd = Command::new(&askpass);
    cmd.arg(prompt)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(ctx) = context {
        cmd.env("PIGGY_ASKPASS_CONTEXT", ctx);
    }
    let mut child = cmd.spawn().map_err(|e| {
        OracleError::Other(format!("spawn askpass {}: {e}", askpass.to_string_lossy()))
    })?;

    let mut buf = String::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_string(&mut buf)
            .map_err(|e| OracleError::Other(format!("read askpass stdout: {e}")))?;
    }
    let status = child
        .wait()
        .map_err(|e| OracleError::Other(format!("await askpass: {e}")))?;
    if !status.success() {
        return Err(OracleError::Other(format!("askpass exited with {status}")));
    }
    let trimmed = buf.trim_end_matches(['\r', '\n']).to_string();
    if trimmed.is_empty() {
        return Err(OracleError::Other("askpass returned empty PIN".into()));
    }
    Ok(Zeroizing::new(trimmed))
}

/// Default PIN supplier: spawn `$SSH_ASKPASS` with the prompt as `argv[1]`,
/// read one line of stdout, return as `Zeroizing<String>`.
///
/// Returns an error closure (deferred until first call) if `SSH_ASKPASS`
/// is unset, so callers can construct the oracle once and let the supplier
/// fail lazily — useful for the agent-then-card fallback in
/// `cmd_stream_decrypt` where the card oracle may never be exercised.
///
/// Composes with `contrib/piggy-askpass.sh` (#33) and
/// `zz-tests_bats/helpers/piggy-test-askpass.sh` (#35). Thin wrapper over
/// [`run_askpass`] with no `PIGGY_ASKPASS_CONTEXT` (the agentless path has
/// no agent-side request context to propagate).
pub fn askpass_pin_supplier() -> PinSupplier {
    Box::new(|prompt: &str| run_askpass(prompt, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Write `body` to a tempfile under `dir`, mark it executable,
    /// return its path as a `String`.
    fn write_executable(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).expect("write helper script");
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod +x");
        path
    }

    /// `mktemp -d` equivalent that auto-cleans on drop.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "piggy-card-oracle-test-{}-{}",
                std::process::id(),
                rand_suffix(),
            ));
            std::fs::create_dir_all(&p).expect("mkdir tempdir");
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn rand_suffix() -> String {
        use std::time::SystemTime;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        format!("{nanos:x}")
    }

    /// Mutex-protected env mutation helper. Tests run on multiple threads
    /// by default; SSH_ASKPASS is process-global, so serialize.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn askpass_supplier_returns_pin_from_stdout() {
        let _guard = env_lock();
        let dir = TempDir::new();
        let askpass = write_executable(&dir.0, "askpass-ok.sh", "#!/bin/sh\necho 654321\n");

        let prev = std::env::var_os("SSH_ASKPASS");
        std::env::set_var("SSH_ASKPASS", &askpass);

        let mut supplier = askpass_pin_supplier();
        let pin = supplier("test prompt").expect("askpass should succeed");
        assert_eq!(pin.as_str(), "654321");

        match prev {
            Some(v) => std::env::set_var("SSH_ASKPASS", v),
            None => std::env::remove_var("SSH_ASKPASS"),
        }
    }

    #[test]
    fn askpass_supplier_errors_when_unset() {
        let _guard = env_lock();
        let prev = std::env::var_os("SSH_ASKPASS");
        std::env::remove_var("SSH_ASKPASS");

        let mut supplier = askpass_pin_supplier();
        let err = supplier("test prompt").expect_err("must error without SSH_ASKPASS");
        match err {
            OracleError::Other(msg) => assert!(
                msg.contains("SSH_ASKPASS"),
                "error should mention SSH_ASKPASS, got: {msg}"
            ),
            other => panic!("expected OracleError::Other, got {other:?}"),
        }

        if let Some(v) = prev {
            std::env::set_var("SSH_ASKPASS", v);
        }
    }

    #[test]
    fn askpass_supplier_errors_on_nonzero_exit() {
        let _guard = env_lock();
        let dir = TempDir::new();
        let askpass = write_executable(&dir.0, "askpass-fail.sh", "#!/bin/sh\nexit 1\n");

        let prev = std::env::var_os("SSH_ASKPASS");
        std::env::set_var("SSH_ASKPASS", &askpass);

        let mut supplier = askpass_pin_supplier();
        let err = supplier("test prompt").expect_err("nonzero exit must surface as error");
        match err {
            OracleError::Other(msg) => {
                assert!(
                    msg.contains("exit"),
                    "error should mention exit, got: {msg}"
                );
            }
            other => panic!("expected OracleError::Other, got {other:?}"),
        }

        match prev {
            Some(v) => std::env::set_var("SSH_ASKPASS", v),
            None => std::env::remove_var("SSH_ASKPASS"),
        }
    }

    #[test]
    fn canonicalize_passthrough_uncompressed() {
        let group = EcGroup::from_curve_name(EcCurve::NistP256.nid()).unwrap();
        let priv_key = openssl::ec::EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let uncompressed = priv_key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let out = canonicalize_uncompressed(&uncompressed).unwrap();
        assert_eq!(out, uncompressed);
    }

    #[test]
    fn canonicalize_decompresses_p256() {
        let group = EcGroup::from_curve_name(EcCurve::NistP256.nid()).unwrap();
        let priv_key = openssl::ec::EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let compressed = priv_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        let uncompressed = priv_key
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .unwrap();
        let out = canonicalize_uncompressed(&compressed).unwrap();
        assert_eq!(out, uncompressed);
    }
}
