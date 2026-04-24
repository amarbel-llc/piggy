//! Unlock flow for a deserialized [`Ebox`].
//!
//! Checkpoint 3A of issue #32 wires the abstract
//! [`EcdhOracle`](crate::oracle::EcdhOracle) trait into this code path so
//! callers can plug in any ECDH backend — the concrete
//! `AgentEcdhOracle` in the `piggy` crate is today's only consumer, but
//! future checkpoints will add a direct-PCSC oracle alongside it.
//!
//! The function walks each PRIMARY config in order and tries the
//! oracle-backed agent path first, then falls back to the (still-stubbed)
//! direct-card path. Interactive recovery (challenge-response, Shamir
//! reassembly) stays out of scope for v1.

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcPoint, PointConversionForm};

use crate::agent_ext::ec_point_to_ssh_pubkey_blob;
use crate::ebox::Ebox;
use crate::error::{BoxError, Result};
use crate::oracle::{EcdhOracle, OracleError};
use crate::piv_box::EcCurve;
use crate::template::EboxConfigType;

/// Attempt to unlock an ebox by trying each PRIMARY config in order:
///
///   1. If an ECDH oracle is supplied, ask it for the shared secret of
///      each part. The oracle is the abstraction that hides "SSH agent
///      over SSH_AUTH_SOCK" from this layer — no sockets, no tokio
///      runtime, no transport concerns.
///   2. Otherwise (or if the oracle had no matching key) fall through to
///      `try_card_unlock`, which will one day talk to a PCSC-backed PIV
///      card directly.
///
/// Returns `Ok(())` as soon as any config succeeds; returns
/// [`BoxError::UnlockFailed`] if every config was exhausted.
pub fn unlock_ebox(ebox: &mut Ebox, mut agent_oracle: Option<&mut dyn EcdhOracle>) -> Result<()> {
    let primary_indices: Vec<usize> = ebox
        .configs
        .iter()
        .enumerate()
        .filter(|(_, c)| c.config_type == EboxConfigType::Primary)
        .map(|(i, _)| i)
        .collect();

    for idx in primary_indices {
        if let Some(oracle) = agent_oracle.as_deref_mut() {
            match try_agent_unlock(ebox, idx, oracle) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::debug!("agent unlock failed for config {idx}: {e}");
                }
            }
        }

        match try_card_unlock(ebox, idx) {
            Ok(()) => return Ok(()),
            Err(e) => {
                tracing::debug!("card unlock failed for config {idx}: {e}");
            }
        }
    }

    Err(BoxError::UnlockFailed)
}

/// Try to unlock a single PRIMARY config via the supplied ECDH oracle.
///
/// For each part in the config, we:
///
///   1. Pull the card (self) pubkey and the partner (ephemeral) pubkey
///      out of `part.piv_box`. Both are stored there as SEC1-compressed
///      EC points (see [`crate::piv_box::PivBox::to_bytes`]); we
///      decompress to SEC1-uncompressed (`0x04 || X || Y`) before
///      wrapping because that's the format the `ecdh@joyent.com`
///      extension and `ssh_key::PublicKey::to_bytes` both require.
///
///   2. Build OpenSSH sshkey-wire blobs via
///      [`ec_point_to_ssh_pubkey_blob`] and hand them to the oracle.
///
///   3. On a returned shared secret, open the [`crate::piv_box::PivBox`]
///      with `open_with_secret` (which runs the KDF + ChaCha20-Poly1305
///      decrypt), then fall through so the outer `ebox.unlock(idx)` call
///      can lift the plaintext key into the Ebox.
///
/// Errors are localized: a single part failing does not abort the
/// config. That's essential because an oracle may legitimately lack a
/// key for one card while holding another in the same M-of-N Primary
/// config (or because a part may be a placeholder from an old template).
///
/// We prefer `part.piv_box.recipient_pubkey` / `part.piv_box.curve` over
/// `part.pubkey` / `part.pubkey_curve` because `piv_box` always gets
/// populated during seal (see
/// [`crate::piv_box::PivBox::seal_offline_with_ephemeral`]) whereas the
/// `EboxPart` mirror fields may be `None` on eboxes re-materialized from
/// the wire if the serializer decided to drop them — the piv_box copy is
/// the load-bearing one.
fn try_agent_unlock(ebox: &mut Ebox, config_idx: usize, oracle: &mut dyn EcdhOracle) -> Result<()> {
    let mut any_opened = false;

    // Version-2+ eboxes hoist per-curve ephemeral pubkeys to the Ebox
    // level (see `read_ebox_part`'s `PART_BOX` branch — each part's
    // piv_box.ephemeral_pubkey is reset to empty on deserialize, and
    // we have to look it up by curve in `ebox.ephemeral_keys`).
    // Precompute a snapshot so we can still iterate parts mutably below
    // without fighting the borrow checker over a concurrent ebox
    // reference.
    let ephemeral_by_curve: Vec<(EcCurve, Vec<u8>)> = ebox
        .ephemeral_keys
        .iter()
        .map(|ek| (ek.curve, ek.pubkey.clone()))
        .collect();

    for part in &mut ebox.configs[config_idx].parts {
        let curve = part.piv_box.curve;

        // Resolve the ephemeral pubkey: prefer the per-part copy, fall
        // back to the Ebox-level shared ephemeral for this curve. This
        // mirrors how `open_offline` would resolve it — the on-disk
        // format never duplicates the ephemeral, so deserialized
        // eboxes always fall through to the ebox-level lookup.
        let mut ephemeral_pubkey: Vec<u8> = part.piv_box.ephemeral_pubkey.clone();
        if ephemeral_pubkey.is_empty() {
            if let Some((_, pk)) = ephemeral_by_curve.iter().find(|(c, _)| *c == curve) {
                ephemeral_pubkey = pk.clone();
            }
        }
        if ephemeral_pubkey.is_empty() || part.piv_box.recipient_pubkey.is_empty() {
            tracing::debug!(
                "config {config_idx} part skipped: no ephemeral or recipient pubkey available"
            );
            continue;
        }

        let self_uncompressed = match decompress_ec_point(curve, &part.piv_box.recipient_pubkey) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!("config {config_idx} part: cannot decompress recipient pubkey: {e}");
                continue;
            }
        };
        let partner_uncompressed = match decompress_ec_point(curve, &ephemeral_pubkey) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!("config {config_idx} part: cannot decompress ephemeral pubkey: {e}");
                continue;
            }
        };

        let self_blob = ec_point_to_ssh_pubkey_blob(curve, &self_uncompressed);
        let partner_blob = ec_point_to_ssh_pubkey_blob(curve, &partner_uncompressed);

        let secret = match oracle.ecdh(&self_blob, &partner_blob) {
            Ok(s) => s,
            Err(OracleError::NoKey) => {
                tracing::debug!(
                    "config {config_idx} part: oracle has no matching key — trying next part"
                );
                continue;
            }
            Err(e) => {
                tracing::warn!("config {config_idx} part: oracle ecdh failed: {e}");
                continue;
            }
        };

        if let Err(e) = part.piv_box.open_with_secret(&secret) {
            tracing::warn!(
                "config {config_idx} part: open_with_secret failed after successful oracle call: {e}"
            );
            continue;
        }
        any_opened = true;
        // A single opened part is enough for a PRIMARY config
        // (n=1 by construction). Break so we don't waste PIN retries
        // or network round-trips on parts we don't need.
        break;
    }

    if !any_opened {
        return Err(BoxError::UnlockFailed);
    }
    ebox.unlock(config_idx)
}

/// Direct-PCSC fallback. Tracked by issue #31; PR 3A intentionally leaves
/// the body stubbed so the oracle path can land first.
// TODO(#31): implement direct PCSC card unlock path.
fn try_card_unlock(_ebox: &mut Ebox, _config_idx: usize) -> Result<()> {
    Err(BoxError::UnlockFailed)
}

/// Convert a SEC1-compressed EC point (33 or 49 bytes, starting with
/// `0x02`/`0x03`) to the SEC1-uncompressed encoding (`0x04 || X || Y`,
/// 65 or 97 bytes).
///
/// No-op when `point` is already uncompressed — we check `point[0]`
/// rather than length because OpenSSL is happy to round-trip either
/// form and we'd rather be tolerant of future callers that hand us the
/// uncompressed bytes directly.
fn decompress_ec_point(curve: EcCurve, point: &[u8]) -> Result<Vec<u8>> {
    if point.first() == Some(&0x04) {
        return Ok(point.to_vec());
    }
    let group = EcGroup::from_curve_name(curve.nid())?;
    let mut ctx = BigNumContext::new()?;
    let ec = EcPoint::from_bytes(&group, point, &mut ctx)?;
    let uncompressed = ec.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    Ok(uncompressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebox::{Ebox, EboxType};
    use crate::oracle::{EcdhOracle, OracleError};
    use crate::piv_box::EcCurve;
    use crate::template::{EboxConfigType, EboxTemplate, EboxTplConfig, EboxTplPart, DEFAULT_SLOT};
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, PointConversionForm};
    use piggy_piv::Guid;

    /// Build a P-256 Primary template + the matching private scalar, so
    /// `Ebox::create` seals against a key we hold.
    fn seed_tpl_and_priv() -> (EboxTemplate, EcKey<openssl::pkey::Private>) {
        let curve = EcCurve::NistP256;
        let group = EcGroup::from_curve_name(curve.nid()).unwrap();
        let priv_key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let pubkey = priv_key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();

        let tpl = EboxTemplate {
            version: 1,
            configs: vec![EboxTplConfig {
                config_type: EboxConfigType::Primary,
                n: 1,
                parts: vec![EboxTplPart {
                    guid: Guid::from_hex("AABBCCDD11223344AABBCCDD11223344").unwrap(),
                    slot: DEFAULT_SLOT,
                    name: Some("piggy-test:unlock-unit".into()),
                    pubkey,
                    pubkey_curve: curve,
                    cak: None,
                }],
            }],
        };
        (tpl, priv_key)
    }

    /// Oracle that computes the real shared secret locally from a
    /// preloaded private scalar. Used to exercise unlock without
    /// standing up an agent — the integration test covers the real
    /// agent path.
    struct LocalEcdhOracle {
        priv_key: EcKey<openssl::pkey::Private>,
        curve: EcCurve,
    }

    impl EcdhOracle for LocalEcdhOracle {
        fn ecdh(
            &mut self,
            _self_blob: &[u8],
            partner_blob: &[u8],
        ) -> std::result::Result<Vec<u8>, OracleError> {
            // The blob is three concatenated ssh-strings:
            //   string(key_type) | string(curve_name) | string(point)
            // Unpack by walking length prefixes.
            let point = extract_point_from_sshkey_blob(partner_blob)?;

            let group = EcGroup::from_curve_name(self.curve.nid())
                .map_err(|e| OracleError::Other(e.to_string()))?;
            let mut ctx = BigNumContext::new().map_err(|e| OracleError::Other(e.to_string()))?;
            let ec_point = openssl::ec::EcPoint::from_bytes(&group, &point, &mut ctx)
                .map_err(|e| OracleError::InvalidPubkey(e.to_string()))?;
            let peer_pub = EcKey::from_public_key(&group, &ec_point)
                .map_err(|e| OracleError::Other(e.to_string()))?;

            let pkey_priv = openssl::pkey::PKey::from_ec_key(self.priv_key.clone())
                .map_err(|e| OracleError::Other(e.to_string()))?;
            let pkey_pub = openssl::pkey::PKey::from_ec_key(peer_pub)
                .map_err(|e| OracleError::Other(e.to_string()))?;
            let mut d = openssl::derive::Deriver::new(&pkey_priv)
                .map_err(|e| OracleError::Other(e.to_string()))?;
            d.set_peer(&pkey_pub)
                .map_err(|e| OracleError::Other(e.to_string()))?;
            d.derive_to_vec()
                .map_err(|e| OracleError::Other(e.to_string()))
        }
    }

    /// Strip the (key_type, curve_name) ssh-strings off the front of an
    /// sshkey blob and return just the raw SEC1 point. Used by the
    /// `LocalEcdhOracle` test harness to recover the ephemeral point
    /// from what `unlock_ebox` hands to the oracle.
    fn extract_point_from_sshkey_blob(blob: &[u8]) -> std::result::Result<Vec<u8>, OracleError> {
        fn take_string(b: &[u8]) -> std::result::Result<(&[u8], &[u8]), OracleError> {
            if b.len() < 4 {
                return Err(OracleError::InvalidPubkey(
                    "blob too short for length".into(),
                ));
            }
            let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize;
            if b.len() < 4 + n {
                return Err(OracleError::InvalidPubkey("blob string underflow".into()));
            }
            Ok((&b[4..4 + n], &b[4 + n..]))
        }
        let (_key_type, rest) = take_string(blob)?;
        let (_curve_name, rest) = take_string(rest)?;
        let (point, _tail) = take_string(rest)?;
        Ok(point.to_vec())
    }

    /// End-to-end happy path: seal with the template, deserialize through
    /// the wire format, unlock via a LocalEcdhOracle. Proves the unlock
    /// path wires partner/self blobs correctly *and* that it handles the
    /// compressed → uncompressed EC-point conversion.
    #[test]
    fn unlock_ebox_with_local_oracle_recovers_key() {
        let (tpl, priv_key) = seed_tpl_and_priv();
        let secret_key: Vec<u8> = (0..32).map(|i| (i as u8).wrapping_mul(7)).collect();

        // Seal.
        let sealed = Ebox::create(&tpl, &secret_key, EboxType::Stream).unwrap();
        // Drop the in-memory key so unlock actually has to do work.
        assert!(sealed.key().is_none(), "create() should not set key");

        // Wire round-trip.
        let bytes = sealed.to_bytes().unwrap();
        let mut deserialized = Ebox::from_bytes(&bytes).unwrap();

        let mut oracle = LocalEcdhOracle {
            priv_key,
            curve: EcCurve::NistP256,
        };
        unlock_ebox(&mut deserialized, Some(&mut oracle)).expect("unlock");
        assert!(deserialized.is_unlocked(), "ebox must be unlocked");
        assert_eq!(
            deserialized.key(),
            Some(secret_key.as_slice()),
            "recovered key must match the sealed key"
        );
    }

    /// If the oracle refuses every part with `NoKey`, `unlock_ebox` must
    /// surface [`BoxError::UnlockFailed`] rather than silently succeeding.
    #[test]
    fn unlock_ebox_returns_unlock_failed_when_oracle_lacks_key() {
        struct NoKeyOracle;
        impl EcdhOracle for NoKeyOracle {
            fn ecdh(&mut self, _: &[u8], _: &[u8]) -> std::result::Result<Vec<u8>, OracleError> {
                Err(OracleError::NoKey)
            }
        }

        let (tpl, _) = seed_tpl_and_priv();
        let secret_key: Vec<u8> = vec![0xAB; 32];
        let sealed = Ebox::create(&tpl, &secret_key, EboxType::Stream).unwrap();
        let mut deserialized = Ebox::from_bytes(&sealed.to_bytes().unwrap()).unwrap();

        let mut oracle = NoKeyOracle;
        let err = unlock_ebox(&mut deserialized, Some(&mut oracle))
            .expect_err("missing key should be UnlockFailed");
        assert!(matches!(err, BoxError::UnlockFailed));
    }

    /// With no oracle supplied, the fallback `try_card_unlock` (still a
    /// stub) runs and fails cleanly.
    #[test]
    fn unlock_ebox_without_oracle_falls_through_to_card_stub() {
        let (tpl, _) = seed_tpl_and_priv();
        let secret_key: Vec<u8> = vec![0x01; 32];
        let sealed = Ebox::create(&tpl, &secret_key, EboxType::Stream).unwrap();
        let mut deserialized = Ebox::from_bytes(&sealed.to_bytes().unwrap()).unwrap();

        let err =
            unlock_ebox(&mut deserialized, None).expect_err("no oracle + stubbed card must fail");
        assert!(matches!(err, BoxError::UnlockFailed));
    }
}
