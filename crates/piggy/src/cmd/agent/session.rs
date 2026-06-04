//! SSH-agent session state for `piggy agent`.
//!
//! Ported from the original `pivy-agent/src/agent.rs`; `PivyAgent` renamed
//! to `PiggyAgent` and the `pivy_piv` crate dependency relabelled to
//! `piggy_piv`. No behavioural changes.

use std::sync::Arc;
use tokio::sync::Mutex;

use ssh_agent_lib::{
    agent::Session,
    error::AgentError,
    proto::{Extension, Identity, SignRequest, signature},
};
use ssh_key::{Algorithm, PublicKey, Signature, public::KeyData};

use piggy_box::piv_box::{EcCurve, PivBox};
use piggy_piv::{Guid, PivAlgorithm, PivContext, PivError};
use zeroize::{Zeroize, Zeroizing};

/// Extra PIN prompts after the first one, on `PinIncorrect`, within a single
/// agent request — matching the C pivy-agent's one-retry behaviour (initial
/// attempt + one retry = 2 card PIN attempts max). Kept low because every
/// wrong attempt decrements the card's PIN retry counter (piggy#142).
const PIN_RETRY_LIMIT: u32 = 1;

/// Cached key info from a PIV token (populated at startup)
#[derive(Clone)]
pub struct CachedKey {
    pub guid: Guid,
    #[allow(dead_code)]
    pub reader_name: String,
    pub slot_id: u8,
    pub algorithm: PivAlgorithm,
    pub public_key: KeyData,
    pub comment: String,
}

#[derive(Clone)]
pub struct PiggyAgent {
    keys: Arc<Mutex<Vec<CachedKey>>>,
    pin: Arc<Mutex<Option<String>>>,
    /// Serializes on-demand askpass prompts so a burst of concurrent ops
    /// that all need the PIN forks at most one dialog (piggy#58).
    prompt_lock: Arc<Mutex<()>>,
}

/// A PIN acquired for a card op, plus whether it came from an on-demand
/// prompt (and so should be cached only after a successful on-card verify).
struct AcquiredPin {
    pin: Zeroizing<String>,
    fresh: bool,
}

impl PiggyAgent {
    pub fn new(keys: Vec<CachedKey>) -> Self {
        Self {
            keys: Arc::new(Mutex::new(keys)),
            pin: Arc::new(Mutex::new(None)),
            prompt_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn pin_handle(&self) -> Arc<Mutex<Option<String>>> {
        self.pin.clone()
    }

    fn find_key(keys: &[CachedKey], pubkey: &KeyData) -> Option<CachedKey> {
        keys.iter().find(|k| k.public_key == *pubkey).cloned()
    }

    /// Acquire the PIV PIN for an op on `guid`: the cached PIN if one is
    /// present, otherwise prompt the user on demand via SSH_ASKPASS (#58),
    /// mirroring the C pivy-agent's "get PIN at first use".
    ///
    /// The prompt is taken OUTSIDE any PC/SC transaction: it can block on a
    /// human for many seconds, and holding the card txn across it would
    /// wedge the card (the pivy#105 concern). Concurrent requests serialize
    /// on `prompt_lock` so a burst forks at most one dialog; the returned
    /// `fresh` flag tells the caller to cache the PIN only after an on-card
    /// verify succeeds (so a wrong prompted PIN is never cached). `op` is a
    /// short request label propagated as `PIGGY_ASKPASS_CONTEXT`.
    async fn ensure_pin(&self, op: &str, guid: &Guid) -> Result<AcquiredPin, AgentError> {
        if let Some(p) = self.pin.lock().await.as_ref() {
            return Ok(AcquiredPin {
                pin: Zeroizing::new(p.clone()),
                fresh: false,
            });
        }
        // No cached PIN; serialize prompts and re-check (another request may
        // have just prompted and cached one while we waited).
        let _prompt_guard = self.prompt_lock.lock().await;
        if let Some(p) = self.pin.lock().await.as_ref() {
            return Ok(AcquiredPin {
                pin: Zeroizing::new(p.clone()),
                fresh: false,
            });
        }
        let prompt = format!("Enter PIN for token {}", guid.short_id());
        let context = format!("piggy-agent:{op}:{}", guid.short_id());
        let pin = tokio::task::spawn_blocking(move || {
            crate::card_oracle::run_askpass(&prompt, Some(&context))
        })
        .await
        .map_err(|e| AgentError::Other(format!("askpass task: {e}").into()))?
        .map_err(|e| AgentError::Other(e.to_string().into()))?;
        Ok(AcquiredPin { pin, fresh: true })
    }

    /// Cache a freshly-prompted PIN after its on-card verify succeeded.
    async fn cache_pin(&self, acquired: &AcquiredPin) {
        if acquired.fresh {
            *self.pin.lock().await = Some(acquired.pin.as_str().to_string());
        }
    }

    /// Drop any cached PIN so the next `ensure_pin` re-prompts. Called on a
    /// `PinIncorrect` retry: a freshly-prompted wrong PIN was never cached,
    /// but a stale cached PIN that the card now rejects must be cleared
    /// before the re-prompt (piggy#142).
    async fn forget_pin(&self) {
        *self.pin.lock().await = None;
    }
}

#[ssh_agent_lib::async_trait]
impl Session for PiggyAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        let start = std::time::Instant::now();
        let res = self.request_identities_inner().await;
        crate::stats::agent_op(
            "request_identities",
            crate::stats::outcome_of(&res),
            start.elapsed(),
        );
        res
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let start = std::time::Instant::now();
        let res = self.sign_inner(request).await;
        crate::stats::agent_op("sign", crate::stats::outcome_of(&res), start.elapsed());
        res
    }

    async fn lock(&mut self, key: String) -> Result<(), AgentError> {
        let start = std::time::Instant::now();
        let res = self.lock_inner(key).await;
        crate::stats::agent_op("lock", crate::stats::outcome_of(&res), start.elapsed());
        res
    }

    async fn unlock(&mut self, key: String) -> Result<(), AgentError> {
        let start = std::time::Instant::now();
        let res = self.unlock_inner(key).await;
        crate::stats::agent_op("unlock", crate::stats::outcome_of(&res), start.elapsed());
        res
    }

    async fn extension(&mut self, extension: Extension) -> Result<Option<Extension>, AgentError> {
        let start = std::time::Instant::now();
        // Label the metric with the extension name (bare, so it matches
        // the C agent: e.g. ecdh@joyent.com -> piggy.agent.ecdh_joyent_com).
        let op = extension.name.as_str().to_owned();
        let res = self.extension_inner(extension).await;
        crate::stats::agent_op(&op, crate::stats::outcome_of(&res), start.elapsed());
        res
    }
}

impl PiggyAgent {
    async fn request_identities_inner(&mut self) -> Result<Vec<Identity>, AgentError> {
        let keys = self.keys.lock().await;
        let identities = keys
            .iter()
            .map(|k| Identity {
                pubkey: k.public_key.clone(),
                comment: k.comment.clone(),
            })
            .collect();
        Ok(identities)
    }

    async fn sign_inner(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let key = self.find_cached_key(&request.pubkey).await?;

        // Prepare data for signing (independent of the card session).
        let sign_data = prepare_sign_data(key.algorithm, &request.data, request.flags)?;

        // Acquire-verify-sign with a bounded re-prompt on a wrong PIN (#142).
        // The PIN is acquired (cached or prompted) OUTSIDE the transaction —
        // the prompt must not be held across the card txn (piggy#105) — then
        // verify+sign are bracketed in one PC/SC transaction (piggy#56). On
        // PinIncorrect we forget the PIN and re-loop, re-prompting outside a
        // fresh transaction.
        let mut attempt = 0u32;
        loop {
            let acquired = if key.slot_id != 0x9E {
                Some(self.ensure_pin("sign", &key.guid).await?)
            } else {
                None
            };

            let mut token = reconnect_to_token(&key.guid)?;
            // The session drops at end of scope: ResetCard if a PIN was
            // verified, LeaveCard for the 9E no-PIN path.
            let mut session = token
                .begin_pin_session()
                .map_err(|e| AgentError::Other(e.to_string().into()))?;

            if let Some(acq) = &acquired {
                match session.verify_pin(&acq.pin) {
                    Ok(()) => self.cache_pin(acq).await,
                    Err(PivError::PinIncorrect { .. }) if attempt < PIN_RETRY_LIMIT => {
                        attempt += 1;
                        self.forget_pin().await;
                        continue;
                    }
                    Err(e) => return Err(AgentError::Other(e.to_string().into())),
                }
            }

            let sig_bytes = session
                .sign_prehash(key.slot_id, &sign_data)
                .map_err(|e| AgentError::Other(e.to_string().into()))?;
            return to_ssh_signature(key.algorithm, &sig_bytes, request.flags);
        }
    }

    async fn lock_inner(&mut self, _key: String) -> Result<(), AgentError> {
        let mut pin = self.pin.lock().await;
        *pin = None;
        Ok(())
    }

    async fn unlock_inner(&mut self, key: String) -> Result<(), AgentError> {
        let mut pin = self.pin.lock().await;
        *pin = Some(key);
        Ok(())
    }

    async fn extension_inner(
        &mut self,
        extension: Extension,
    ) -> Result<Option<Extension>, AgentError> {
        match extension.name.as_str() {
            "query" => {
                let supported: &[&str] = &[
                    "query",
                    "session-bind@openssh.com",
                    "pin-status@joyent.com",
                    "ecdh@joyent.com",
                    "ecdh-rebox@joyent.com",
                    "ykpiv-attest@joyent.com",
                ];
                let mut buf = Vec::new();
                for name in supported {
                    let bytes = name.as_bytes();
                    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                    buf.extend_from_slice(bytes);
                }
                Ok(Some(Extension {
                    name: "query".into(),
                    details: buf.into(),
                }))
            }
            "session-bind@openssh.com" => Ok(None),
            "pin-status@joyent.com" => {
                let pin_guard = self.pin.lock().await;
                let has_pin: u8 = if pin_guard.is_some() { 1 } else { 0 };
                let has_card: u8 = if !self.keys.lock().await.is_empty() {
                    1
                } else {
                    0
                };
                Ok(Some(Extension {
                    name: "pin-status@joyent.com".into(),
                    details: vec![has_pin, has_card].into(),
                }))
            }
            "ecdh@joyent.com" => {
                self.handle_ecdh(&extension.details.clone().into_bytes())
                    .await
            }
            "ecdh-rebox@joyent.com" => {
                self.handle_ecdh_rebox(&extension.details.clone().into_bytes())
                    .await
            }
            "ykpiv-attest@joyent.com" => {
                self.handle_attest(&extension.details.clone().into_bytes())
                    .await
            }
            _ => Err(AgentError::from(
                ssh_agent_lib::proto::ProtoError::UnsupportedCommand { command: 27 },
            )),
        }
    }
}

impl PiggyAgent {
    async fn find_cached_key(&self, pubkey: &KeyData) -> Result<CachedKey, AgentError> {
        let keys = self.keys.lock().await;
        Self::find_key(&keys, pubkey).ok_or_else(|| AgentError::Other("key not found".into()))
    }

    async fn handle_ecdh(&mut self, details: &[u8]) -> Result<Option<Extension>, AgentError> {
        let inner = read_ssh_string(details, 0)
            .map_err(|e| AgentError::Other(e.into()))?
            .0;

        let (card_key_blob, pos) =
            read_ssh_string(inner, 0).map_err(|e| AgentError::Other(e.into()))?;
        let (partner_blob, pos) =
            read_ssh_string(inner, pos).map_err(|e| AgentError::Other(e.into()))?;
        let _flags = read_u32_be(inner, pos, "ecdh")?;

        let card_pubkey = PublicKey::from_bytes(card_key_blob)
            .map_err(|e| AgentError::Other(format!("ecdh: bad card key: {e}").into()))?;

        let key = self
            .find_cached_key(card_pubkey.key_data())
            .await
            .map_err(|_| AgentError::Other("ecdh: key not found".into()))?;

        let ec_point = extract_ec_point_from_ssh_blob(partner_blob)
            .map_err(|e| AgentError::Other(e.into()))?;

        match key.algorithm {
            PivAlgorithm::EcP256 | PivAlgorithm::EcP384 => {}
            _ => {
                return Err(AgentError::Other("ecdh: key is not an EC key".into()));
            }
        }

        // Acquire-verify-ECDH with a bounded re-prompt on a wrong PIN (#142).
        // PIN acquired OUTSIDE the txn (piggy#105); verify+ECDH bracketed in
        // one transaction (piggy#56). Slot 9E needs no PIN.
        let mut secret = {
            let mut attempt = 0u32;
            loop {
                let acquired = if key.slot_id != 0x9E {
                    Some(self.ensure_pin("ecdh", &key.guid).await?)
                } else {
                    None
                };

                let mut token = reconnect_to_token(&key.guid)?;
                let mut session = token
                    .begin_pin_session()
                    .map_err(|e| AgentError::Other(e.to_string().into()))?;

                if let Some(acq) = &acquired {
                    match session.verify_pin(&acq.pin) {
                        Ok(()) => self.cache_pin(acq).await,
                        Err(PivError::PinIncorrect { .. }) if attempt < PIN_RETRY_LIMIT => {
                            attempt += 1;
                            self.forget_pin().await;
                            continue;
                        }
                        Err(e) => return Err(AgentError::Other(e.to_string().into())),
                    }
                }

                break session
                    .ecdh_derive(key.slot_id, &ec_point)
                    .map_err(|e| AgentError::Other(e.to_string().into()))?;
            }
        };

        let mut resp = Vec::new();
        resp.extend_from_slice(&(secret.len() as u32).to_be_bytes());
        resp.extend_from_slice(&secret);
        secret.zeroize();

        Ok(Some(Extension {
            name: "ecdh@joyent.com".into(),
            details: resp.into(),
        }))
    }

    async fn handle_attest(&mut self, details: &[u8]) -> Result<Option<Extension>, AgentError> {
        let inner = read_ssh_string(details, 0)
            .map_err(|e| AgentError::Other(e.into()))?
            .0;

        let (card_key_blob, pos) =
            read_ssh_string(inner, 0).map_err(|e| AgentError::Other(e.into()))?;
        let _flags = read_u32_be(inner, pos, "attest")?;

        let card_pubkey = PublicKey::from_bytes(card_key_blob)
            .map_err(|e| AgentError::Other(format!("attest: bad card key: {e}").into()))?;

        let key = self
            .find_cached_key(card_pubkey.key_data())
            .await
            .map_err(|_| AgentError::Other("attest: key not found".into()))?;

        let token = reconnect_to_token(&key.guid)?;

        let attest_cert = token
            .yk_attest(key.slot_id)
            .map_err(|e| AgentError::Other(e.to_string().into()))?;

        let mut certs: Vec<Vec<u8>> = vec![attest_cert];

        if let Ok(f9_slot) = token.read_slot(0xF9) {
            certs.push(f9_slot.cert_der().to_vec());
        }

        let mut resp = Vec::new();
        resp.extend_from_slice(&(certs.len() as u32).to_be_bytes());
        for cert in &certs {
            resp.extend_from_slice(&(cert.len() as u32).to_be_bytes());
            resp.extend_from_slice(cert);
        }

        Ok(Some(Extension {
            name: "ykpiv-attest@joyent.com".into(),
            details: resp.into(),
        }))
    }

    async fn handle_ecdh_rebox(&mut self, details: &[u8]) -> Result<Option<Extension>, AgentError> {
        let inner = read_ssh_string(details, 0)
            .map_err(|e| AgentError::Other(e.into()))?
            .0;

        let (boxbuf, pos) = read_ssh_string(inner, 0).map_err(|e| AgentError::Other(e.into()))?;
        let (guid_bytes, pos) =
            read_ssh_string(inner, pos).map_err(|e| AgentError::Other(e.into()))?;
        let slot_id = *inner
            .get(pos)
            .ok_or_else(|| AgentError::Other("ecdh-rebox: truncated slot_id".into()))?;
        let pos = pos + 1;
        let (partner_blob, pos) =
            read_ssh_string(inner, pos).map_err(|e| AgentError::Other(e.into()))?;
        let flags = read_u32_be(inner, pos, "ecdh-rebox")?;

        if flags != 0 {
            return Err(AgentError::Other(
                format!("ecdh-rebox: unsupported flags {flags:#x}").into(),
            ));
        }

        let mut piv_box = PivBox::from_bytes(boxbuf)
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: bad box: {e}").into()))?;

        // Resolve the agent key + slot for this box. A GUID/slot hint (legacy
        // boxes) matches directly; piggy 2.x boxes are guidless, so match the
        // cached key by the box's recipient pubkey (SEC1-uncompressed
        // equality) — the same pubkey-matching the agentless card_oracle and
        // `handle_ecdh` use. Without this the agent can't decrypt guidless
        // piggy boxes (piggy#58).
        let (key, box_slot) = match piv_box.guid_slot.as_ref() {
            Some((box_guid, slot)) => {
                let key = self.find_key_by_guid(box_guid).await.ok_or_else(|| {
                    AgentError::Other("ecdh-rebox: no matching key for GUID".into())
                })?;
                (key, *slot)
            }
            None => self
                .find_key_by_recipient_pubkey(&piv_box.recipient_pubkey)
                .await
                .ok_or_else(|| {
                    AgentError::Other("ecdh-rebox: no agent key matches the box recipient".into())
                })?,
        };

        let ec_point = decompress_ec_point(&piv_box.ephemeral_pubkey, piv_box.curve)?;

        // Acquire-verify-ECDH with a bounded re-prompt on a wrong PIN (#142).
        // PIN acquired OUTSIDE the txn (piggy#105); verify+ECDH bracketed in
        // one transaction (piggy#56). The transaction is released when the loop
        // block ends (ResetCard if a PIN was verified) before the offline
        // reseal below, which is pure CPU and needs no card. Slot 9E needs no PIN.
        let shared_secret = {
            let mut attempt = 0u32;
            loop {
                let acquired = if box_slot != 0x9E {
                    Some(self.ensure_pin("ecdh-rebox", &key.guid).await?)
                } else {
                    None
                };

                let mut token = reconnect_to_token(&key.guid)?;
                let mut session = token
                    .begin_pin_session()
                    .map_err(|e| AgentError::Other(e.to_string().into()))?;

                if let Some(acq) = &acquired {
                    match session.verify_pin(&acq.pin) {
                        Ok(()) => self.cache_pin(acq).await,
                        Err(PivError::PinIncorrect { .. }) if attempt < PIN_RETRY_LIMIT => {
                            attempt += 1;
                            self.forget_pin().await;
                            continue;
                        }
                        Err(e) => return Err(AgentError::Other(e.to_string().into())),
                    }
                }

                break session
                    .ecdh_derive(box_slot, &ec_point)
                    .map_err(|e| AgentError::Other(e.to_string().into()))?;
            }
        };

        piv_box
            .open_with_secret(&shared_secret)
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: decrypt: {e}").into()))?;

        let partner_point = extract_ec_point_from_ssh_blob(partner_blob)
            .map_err(|e| AgentError::Other(e.into()))?;

        let partner_ec_pub = ec_public_key_from_point(&partner_point, piv_box.curve)
            .map_err(|e| AgentError::Other(e.into()))?;

        let mut new_box = PivBox::new(piv_box.curve);
        if !guid_bytes.is_empty() {
            let target_guid = Guid::from_bytes(guid_bytes).map_err(|e| {
                AgentError::Other(format!("ecdh-rebox: bad target GUID: {e}").into())
            })?;
            new_box.guid_slot = Some((target_guid, slot_id));
        }
        let plaintext = piv_box
            .take_data()
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: take_data: {e}").into()))?;
        new_box.set_data(&plaintext);

        new_box
            .seal_offline(&partner_ec_pub)
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: seal: {e}").into()))?;

        let new_box_bytes = new_box
            .to_bytes()
            .map_err(|e| AgentError::Other(format!("ecdh-rebox: serialize: {e}").into()))?;

        let mut resp = Vec::new();
        resp.extend_from_slice(&(new_box_bytes.len() as u32).to_be_bytes());
        resp.extend_from_slice(&new_box_bytes);

        Ok(Some(Extension {
            name: "ecdh-rebox@joyent.com".into(),
            details: resp.into(),
        }))
    }

    async fn find_key_by_guid(&self, guid: &Guid) -> Option<CachedKey> {
        let keys = self.keys.lock().await;
        keys.iter().find(|k| &k.guid == guid).cloned()
    }

    /// Match a cached EC key by a box recipient pubkey (raw SEC1 bytes from a
    /// guidless box), returning the key and the slot it lives in. The
    /// recipient bytes (compressed on the wire) and each cached key's pubkey
    /// are both reduced to SEC1-uncompressed form before comparison, so the
    /// encodings agree (mirrors `card_oracle`'s pubkey matching).
    async fn find_key_by_recipient_pubkey(&self, recipient: &[u8]) -> Option<(CachedKey, u8)> {
        let want = crate::card_oracle::canonicalize_uncompressed(recipient).ok()?;
        let keys = self.keys.lock().await;
        keys.iter().find_map(|k| match &k.public_key {
            KeyData::Ecdsa(ec) if ec.as_sec1_bytes() == want.as_slice() => {
                Some((k.clone(), k.slot_id))
            }
            _ => None,
        })
    }
}

/// Hash data and prepare it for the PIV card's GENERAL AUTHENTICATE.
/// For ECDSA: returns the hash digest.
/// For RSA: returns PKCS#1 v1.5 DigestInfo padded to key size.
fn prepare_sign_data(alg: PivAlgorithm, data: &[u8], flags: u32) -> Result<Vec<u8>, AgentError> {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    match alg {
        PivAlgorithm::EcP256 => {
            let hash = Sha256::digest(data);
            Ok(hash.to_vec())
        }
        PivAlgorithm::EcP384 => {
            let hash = Sha384::digest(data);
            Ok(hash.to_vec())
        }
        PivAlgorithm::Rsa1024 | PivAlgorithm::Rsa2048 => {
            let key_size = match alg {
                PivAlgorithm::Rsa1024 => 128,
                PivAlgorithm::Rsa2048 => 256,
                _ => unreachable!(),
            };

            let (hash_bytes, digest_prefix) = if flags & signature::RSA_SHA2_512 != 0 {
                let hash = Sha512::digest(data);
                (hash.to_vec(), RSA_DIGEST_PREFIX_SHA512)
            } else {
                let hash = Sha256::digest(data);
                (hash.to_vec(), RSA_DIGEST_PREFIX_SHA256)
            };

            // Build PKCS#1 v1.5 DigestInfo + pad
            pkcs1_v15_pad(&hash_bytes, digest_prefix, key_size)
        }
        PivAlgorithm::Ed25519 => {
            // Ed25519 does its own hashing on card; pass raw data
            Ok(data.to_vec())
        }
    }
}

// DER-encoded DigestInfo AlgorithmIdentifier prefixes for PKCS#1 v1.5
// SHA-256: SEQUENCE { SEQUENCE { OID sha256, NULL }, OCTET STRING }
const RSA_DIGEST_PREFIX_SHA256: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

// SHA-512: SEQUENCE { SEQUENCE { OID sha512, NULL }, OCTET STRING }
const RSA_DIGEST_PREFIX_SHA512: &[u8] = &[
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

/// Build PKCS#1 v1.5 padded signing block:
/// 0x00 0x01 [0xFF padding] 0x00 [DigestInfo]
fn pkcs1_v15_pad(
    hash: &[u8],
    digest_prefix: &[u8],
    key_size: usize,
) -> Result<Vec<u8>, AgentError> {
    let digest_info_len = digest_prefix.len() + hash.len();
    if key_size < digest_info_len + 11 {
        return Err(AgentError::Other("key too small for digest".into()));
    }

    let mut padded = vec![0u8; key_size];
    padded[0] = 0x00;
    padded[1] = 0x01;

    let pad_len = key_size - digest_info_len - 3;
    for byte in &mut padded[2..2 + pad_len] {
        *byte = 0xFF;
    }
    padded[2 + pad_len] = 0x00;

    let di_start = 3 + pad_len;
    padded[di_start..di_start + digest_prefix.len()].copy_from_slice(digest_prefix);
    padded[di_start + digest_prefix.len()..].copy_from_slice(hash);

    Ok(padded)
}

/// Convert raw card signature bytes to ssh_key::Signature.
fn to_ssh_signature(
    alg: PivAlgorithm,
    sig_bytes: &[u8],
    flags: u32,
) -> Result<Signature, AgentError> {
    match alg {
        PivAlgorithm::EcP256 | PivAlgorithm::EcP384 => {
            let algo_name = match alg {
                PivAlgorithm::EcP256 => "ecdsa-sha2-nistp256",
                PivAlgorithm::EcP384 => "ecdsa-sha2-nistp384",
                _ => unreachable!(),
            };
            let algo = Algorithm::new(algo_name).map_err(AgentError::other)?;
            let (r, s) = decode_der_ecdsa_signature(sig_bytes)?;
            let ssh_sig = encode_ecdsa_ssh_signature(&r, &s);
            Signature::new(algo, ssh_sig).map_err(AgentError::other)
        }
        PivAlgorithm::Rsa1024 | PivAlgorithm::Rsa2048 => {
            let algo_name = if flags & signature::RSA_SHA2_512 != 0 {
                "rsa-sha2-512"
            } else {
                "rsa-sha2-256"
            };
            let algo = Algorithm::new(algo_name).map_err(AgentError::other)?;
            Signature::new(algo, sig_bytes.to_vec()).map_err(AgentError::other)
        }
        PivAlgorithm::Ed25519 => {
            let algo = Algorithm::new("ssh-ed25519").map_err(AgentError::other)?;
            Signature::new(algo, sig_bytes.to_vec()).map_err(AgentError::other)
        }
    }
}

/// Decode a DER-encoded ECDSA signature into (r, s) as big-endian byte arrays.
/// DER format: SEQUENCE { INTEGER r, INTEGER s }.
///
/// Every bounds check is explicit — the card may return arbitrary bytes, and
/// a malformed length field (e.g. `r_len = 0xFF` on a short buffer) must be
/// rejected with an error, never cause an index-out-of-bounds panic.
///
/// Supports DER long-form SEQUENCE / INTEGER lengths (0x81 LL, 0x82 LL LL)
/// so P-384 signatures at or beyond the short-form 0-127 threshold decode
/// correctly.
fn decode_der_ecdsa_signature(der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), AgentError> {
    // Outer SEQUENCE tag.
    if der.first().copied() != Some(0x30) {
        return Err(AgentError::Other(
            "invalid DER ECDSA signature: not a SEQUENCE".into(),
        ));
    }

    // Parse SEQUENCE length and its header size (tag + length-of-length).
    let (seq_len, seq_hdr) = parse_der_length(&der[1..])?;
    let seq_start = 1 + seq_hdr;
    let seq_end = seq_start
        .checked_add(seq_len)
        .ok_or_else(|| AgentError::Other("DER SEQUENCE length overflows usize".into()))?;
    if der.len() < seq_end {
        return Err(AgentError::Other(
            "invalid DER ECDSA signature: truncated body".into(),
        ));
    }

    let (r, after_r) = read_der_integer(der, seq_start, seq_end, "r")?;
    let (s, after_s) = read_der_integer(der, after_r, seq_end, "s")?;
    if after_s != seq_end {
        return Err(AgentError::Other(
            "invalid DER ECDSA signature: trailing bytes after s".into(),
        ));
    }

    Ok((r, s))
}

/// Read a DER INTEGER `{ 0x02 len bytes }` starting at `pos`. Returns the
/// integer bytes and the position just past the integer. `end` caps the
/// enclosing SEQUENCE body so we never read past it.
fn read_der_integer(
    der: &[u8],
    pos: usize,
    end: usize,
    label: &str,
) -> Result<(Vec<u8>, usize), AgentError> {
    if pos >= end {
        return Err(AgentError::Other(
            format!("invalid DER ECDSA signature: missing INTEGER for {}", label).into(),
        ));
    }
    if der[pos] != 0x02 {
        return Err(AgentError::Other(
            format!("expected INTEGER tag for {}", label).into(),
        ));
    }
    let (int_len, int_hdr) = parse_der_length(&der[pos + 1..end])?;
    let int_start = pos + 1 + int_hdr;
    let int_end = int_start
        .checked_add(int_len)
        .ok_or_else(|| AgentError::Other("DER INTEGER length overflows usize".into()))?;
    if int_end > end {
        return Err(AgentError::Other(
            format!(
                "invalid DER ECDSA signature: {} INTEGER length exceeds SEQUENCE",
                label
            )
            .into(),
        ));
    }
    Ok((der[int_start..int_end].to_vec(), int_end))
}

/// Parse a DER length prefix. Returns `(length, header_byte_count)` where
/// `header_byte_count` is 1 (short form), 2 (0x81 LL), or 3 (0x82 LL LL).
/// Rejects indefinite form (0x80) and lengths > 0x82 (longer than needed
/// for any realistic ECDSA signature).
fn parse_der_length(bytes: &[u8]) -> Result<(usize, usize), AgentError> {
    let first = *bytes
        .first()
        .ok_or_else(|| AgentError::Other("DER length: missing length byte".into()))?;
    if first < 0x80 {
        Ok((first as usize, 1))
    } else if first == 0x81 {
        let b = *bytes
            .get(1)
            .ok_or_else(|| AgentError::Other("DER length: truncated 0x81".into()))?;
        // 0x81 MUST be used only for lengths >= 128; reject non-canonical encoding.
        if b < 0x80 {
            return Err(AgentError::Other(
                "DER length: non-canonical 0x81 short length".into(),
            ));
        }
        Ok((b as usize, 2))
    } else if first == 0x82 {
        let hi = *bytes
            .get(1)
            .ok_or_else(|| AgentError::Other("DER length: truncated 0x82".into()))?;
        let lo = *bytes
            .get(2)
            .ok_or_else(|| AgentError::Other("DER length: truncated 0x82".into()))?;
        // 0x82 MUST be used only for lengths >= 256.
        if hi == 0 {
            return Err(AgentError::Other(
                "DER length: non-canonical 0x82 encoding".into(),
            ));
        }
        Ok((u16::from_be_bytes([hi, lo]) as usize, 3))
    } else {
        Err(AgentError::Other(
            format!("DER length: unsupported form 0x{:02x}", first).into(),
        ))
    }
}

/// Read an SSH string (u32 length prefix + payload) from `data` at `offset`.
/// Returns `(&payload_slice, next_offset)`.
fn read_ssh_string(data: &[u8], offset: usize) -> Result<(&[u8], usize), String> {
    let hdr_end = offset
        .checked_add(4)
        .filter(|&e| e <= data.len())
        .ok_or("SSH string: not enough data for length")?;
    let len = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]) as usize;
    let end = hdr_end
        .checked_add(len)
        .filter(|&e| e <= data.len())
        .ok_or_else(|| {
            format!(
                "SSH string: length {len} exceeds remaining data {}",
                data.len() - hdr_end
            )
        })?;
    Ok((&data[hdr_end..end], end))
}

/// Read a big-endian u32 from `data` at `offset`, returning the value.
fn read_u32_be(data: &[u8], offset: usize, label: &str) -> Result<u32, AgentError> {
    let end = offset.checked_add(4).filter(|&e| e <= data.len());
    if end.is_none() {
        return Err(AgentError::Other(
            format!("{label}: truncated flags field").into(),
        ));
    }
    Ok(u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]))
}

/// Establish a fresh PCSC context and find the token matching `guid`.
fn reconnect_to_token(guid: &Guid) -> Result<piggy_piv::PivToken, AgentError> {
    let ctx = PivContext::new().map_err(|e| AgentError::Other(e.to_string().into()))?;
    let tokens = ctx
        .enumerate_tokens()
        .map_err(|e| AgentError::Other(e.to_string().into()))?;
    tokens
        .into_iter()
        .find(|t| t.guid() == guid)
        .ok_or_else(|| AgentError::Other("PIV token no longer available".into()))
}

/// Extract the raw SEC1 EC point from an SSH ECDSA public key blob.
///
/// SSH ECDSA public key wire format:
///   ssh_string("ecdsa-sha2-nistp256")  (or nistp384)
///   ssh_string("nistp256")             (curve identifier)
///   ssh_string(<SEC1 EC point>)        (04 || x || y)
fn extract_ec_point_from_ssh_blob(blob: &[u8]) -> Result<Vec<u8>, String> {
    let (_algo, pos) = read_ssh_string(blob, 0)?;
    let (_curve, pos) = read_ssh_string(blob, pos)?;
    let (point, _) = read_ssh_string(blob, pos)?;
    Ok(point.to_vec())
}

fn decompress_ec_point(compressed: &[u8], curve: EcCurve) -> Result<Vec<u8>, AgentError> {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcPoint, PointConversionForm};

    let group = EcGroup::from_curve_name(curve.nid())
        .map_err(|e| AgentError::Other(format!("ec group: {e}").into()))?;
    let mut ctx =
        BigNumContext::new().map_err(|e| AgentError::Other(format!("bn ctx: {e}").into()))?;
    let point = EcPoint::from_bytes(&group, compressed, &mut ctx)
        .map_err(|e| AgentError::Other(format!("ec decompress: {e}").into()))?;
    point
        .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)
        .map_err(|e| AgentError::Other(format!("ec to_bytes: {e}").into()))
}

fn ec_public_key_from_point(
    point: &[u8],
    curve: EcCurve,
) -> Result<openssl::ec::EcKey<openssl::pkey::Public>, String> {
    use openssl::bn::BigNumContext;
    use openssl::ec::{EcGroup, EcKey, EcPoint};

    let group = EcGroup::from_curve_name(curve.nid()).map_err(|e| format!("ec group: {e}"))?;
    let mut ctx = BigNumContext::new().map_err(|e| format!("bn ctx: {e}"))?;
    let ec_point =
        EcPoint::from_bytes(&group, point, &mut ctx).map_err(|e| format!("ec point: {e}"))?;
    EcKey::from_public_key(&group, &ec_point).map_err(|e| format!("ec key: {e}"))
}

/// Encode (r, s) as SSH mpint-pair for ECDSA signature blob.
/// SSH ECDSA signature blob = string(r as mpint) || string(s as mpint)
fn encode_ecdsa_ssh_signature(r: &[u8], s: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // r as SSH mpint
    let r_len = r.len() as u32;
    buf.extend_from_slice(&r_len.to_be_bytes());
    buf.extend_from_slice(r);
    // s as SSH mpint
    let s_len = s.len() as u32;
    buf.extend_from_slice(&s_len.to_be_bytes());
    buf.extend_from_slice(s);
    buf
}

#[cfg(test)]
#[allow(
    clippy::vec_init_then_push,
    clippy::manual_repeat_n,
    clippy::needless_range_loop
)]
mod tests {
    //! Unit tests for the pure signing-path helpers plus the
    //! non-PCSC-touching portions of the `Session` impl.
    //!
    //! Tests DO NOT touch PCSC or real hardware. `PiggyAgent::sign`
    //! internally calls `PivContext::new()` once a matching key has
    //! been found; the tests here only exercise the *pre-PCSC*
    //! branch (key not found in cache) and the pure helpers.

    use super::*;
    use sha2::{Digest, Sha256, Sha384, Sha512};
    use ssh_agent_lib::proto::{Extension, SignRequest, signature};
    use ssh_key::public::{Ed25519PublicKey, KeyData};

    // -------- Helpers --------

    /// Build an arbitrary Ed25519 KeyData for testing. All zeroes is
    /// not a cryptographically valid public key, but `Session` never
    /// verifies that — it only uses `KeyData` for equality matching.
    fn ed25519_key_data(seed: u8) -> KeyData {
        KeyData::Ed25519(Ed25519PublicKey([seed; 32]))
    }

    fn sample_guid() -> Guid {
        Guid::from_hex("995E171383029CDA0D9CDBDBAD580813").unwrap()
    }

    fn cached_ed25519(seed: u8, slot: u8) -> CachedKey {
        CachedKey {
            guid: sample_guid(),
            reader_name: "MockReader".into(),
            slot_id: slot,
            algorithm: PivAlgorithm::Ed25519,
            public_key: ed25519_key_data(seed),
            comment: format!("seed-{seed}"),
        }
    }

    // -------- prepare_sign_data --------

    #[test]
    fn prepare_sign_data_ecp256_returns_sha256_digest() {
        let data = b"hello world";
        let out = prepare_sign_data(PivAlgorithm::EcP256, data, 0).unwrap();
        let expected = Sha256::digest(data).to_vec();
        assert_eq!(out, expected);
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn prepare_sign_data_ecp384_returns_sha384_digest() {
        let data = b"hello world";
        let out = prepare_sign_data(PivAlgorithm::EcP384, data, 0).unwrap();
        let expected = Sha384::digest(data).to_vec();
        assert_eq!(out, expected);
        assert_eq!(out.len(), 48);
    }

    #[test]
    fn prepare_sign_data_ed25519_is_passthrough() {
        let data = b"\x00\x01\x02ascii and binary\xff";
        let out = prepare_sign_data(PivAlgorithm::Ed25519, data, 0).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn prepare_sign_data_ed25519_passthrough_empty() {
        let out = prepare_sign_data(PivAlgorithm::Ed25519, b"", 0).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn prepare_sign_data_rsa2048_default_sha256() {
        // flags=0 should default to SHA-256
        let data = b"test message";
        let out = prepare_sign_data(PivAlgorithm::Rsa2048, data, 0).unwrap();
        assert_eq!(out.len(), 256);

        // PKCS#1 v1.5 header: 00 01 FF ... FF 00 <DigestInfo> <hash>
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x01);

        let hash = Sha256::digest(data);
        let digest_info_len = RSA_DIGEST_PREFIX_SHA256.len() + hash.len();
        // Tail must equal digest prefix + hash
        let tail_start = out.len() - digest_info_len;
        assert_eq!(
            &out[tail_start..tail_start + RSA_DIGEST_PREFIX_SHA256.len()],
            RSA_DIGEST_PREFIX_SHA256
        );
        assert_eq!(
            &out[tail_start + RSA_DIGEST_PREFIX_SHA256.len()..],
            hash.as_slice()
        );

        // Byte just before DigestInfo must be 0x00 separator
        assert_eq!(out[tail_start - 1], 0x00);
        // All bytes between 0x01 and the 0x00 separator are 0xFF padding
        for &b in &out[2..tail_start - 1] {
            assert_eq!(b, 0xFF);
        }
    }

    #[test]
    fn prepare_sign_data_rsa2048_explicit_sha256_flag() {
        let data = b"test message";
        let default_out = prepare_sign_data(PivAlgorithm::Rsa2048, data, 0).unwrap();
        let flagged_out =
            prepare_sign_data(PivAlgorithm::Rsa2048, data, signature::RSA_SHA2_256).unwrap();
        assert_eq!(default_out, flagged_out);
    }

    #[test]
    fn prepare_sign_data_rsa2048_sha512_flag() {
        let data = b"test message";
        let out = prepare_sign_data(PivAlgorithm::Rsa2048, data, signature::RSA_SHA2_512).unwrap();
        assert_eq!(out.len(), 256);

        let hash = Sha512::digest(data);
        let digest_info_len = RSA_DIGEST_PREFIX_SHA512.len() + hash.len();
        let tail_start = out.len() - digest_info_len;
        assert_eq!(
            &out[tail_start..tail_start + RSA_DIGEST_PREFIX_SHA512.len()],
            RSA_DIGEST_PREFIX_SHA512
        );
        assert_eq!(
            &out[tail_start + RSA_DIGEST_PREFIX_SHA512.len()..],
            hash.as_slice()
        );
    }

    /// When both SHA-256 and SHA-512 flags are set, the production code
    /// (match arm order: SHA-512 first) picks SHA-512. Pins this so a
    /// future refactor that flips branch order would fail — the
    /// precedence is not documented anywhere else.
    #[test]
    fn prepare_sign_data_rsa2048_sha512_wins_when_both_flags_set() {
        let data = b"precedence test";
        let out = prepare_sign_data(
            PivAlgorithm::Rsa2048,
            data,
            signature::RSA_SHA2_256 | signature::RSA_SHA2_512,
        )
        .unwrap();
        // If SHA-512 wins, the tail of the padded block is the SHA-512
        // DigestInfo + SHA-512 hash — NOT the SHA-256 version.
        let hash = Sha512::digest(data);
        let digest_info_len = RSA_DIGEST_PREFIX_SHA512.len() + hash.len();
        let tail_start = out.len() - digest_info_len;
        assert_eq!(
            &out[tail_start..tail_start + RSA_DIGEST_PREFIX_SHA512.len()],
            RSA_DIGEST_PREFIX_SHA512,
            "SHA-512 must take precedence over SHA-256 when both flags set"
        );
        assert_eq!(
            &out[tail_start + RSA_DIGEST_PREFIX_SHA512.len()..],
            hash.as_slice()
        );
    }

    /// Unknown flag bits must default to SHA-256 — verify by comparing
    /// to the pure-default (flags=0) output.
    #[test]
    fn prepare_sign_data_rsa2048_unknown_flags_default_to_sha256() {
        let data = b"unknown flags";
        let default_out = prepare_sign_data(PivAlgorithm::Rsa2048, data, 0).unwrap();
        // Pick a flag bit that is NOT RSA_SHA2_256 or RSA_SHA2_512.
        // The SSH agent protocol defines those as bits 1 and 2; bit 31
        // is guaranteed-unused territory.
        let noise_flags: u32 = 1 << 31;
        let noisy_out = prepare_sign_data(PivAlgorithm::Rsa2048, data, noise_flags).unwrap();
        assert_eq!(
            default_out, noisy_out,
            "unknown flag bits must be ignored (default to SHA-256)"
        );
    }

    #[test]
    fn prepare_sign_data_rsa1024_default_sha256() {
        let data = b"rsa1024 message";
        let out = prepare_sign_data(PivAlgorithm::Rsa1024, data, 0).unwrap();
        assert_eq!(out.len(), 128);
        assert_eq!(out[0], 0x00);
        assert_eq!(out[1], 0x01);
    }

    #[test]
    fn prepare_sign_data_rsa1024_rejects_sha512_digest_too_large() {
        // SHA-512 DigestInfo (19 + 64 = 83 bytes) plus the minimum 11
        // bytes of PKCS#1 overhead equals 94 bytes, which fits in a
        // 128-byte block. The current impl accepts it. Regression
        // guard: ensure no panic and correct tail.
        let data = b"rsa1024 sha512";
        let out = prepare_sign_data(PivAlgorithm::Rsa1024, data, signature::RSA_SHA2_512).unwrap();
        assert_eq!(out.len(), 128);
        let hash = Sha512::digest(data);
        assert!(out.ends_with(hash.as_slice()));
    }

    // -------- pkcs1_v15_pad (direct) --------

    #[test]
    fn pkcs1_v15_pad_exact_structure_sha256() {
        // Pad a SHA-256 hash (32 bytes) into a 256-byte RSA-2048 block.
        let hash = vec![0xAB; 32];
        let padded = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, 256).unwrap();
        assert_eq!(padded.len(), 256);
        assert_eq!(padded[0..2], [0x00, 0x01]);

        // Expect 0xFF padding of length: 256 - 3 - 19 - 32 = 202 bytes
        let pad_len = 256 - 3 - RSA_DIGEST_PREFIX_SHA256.len() - 32;
        assert_eq!(pad_len, 202);
        for i in 2..2 + pad_len {
            assert_eq!(padded[i], 0xFF, "byte {i} should be 0xFF");
        }
        // Separator
        assert_eq!(padded[2 + pad_len], 0x00);
        // DigestInfo + hash at tail
        assert_eq!(
            &padded[3 + pad_len..3 + pad_len + RSA_DIGEST_PREFIX_SHA256.len()],
            RSA_DIGEST_PREFIX_SHA256
        );
        assert_eq!(&padded[padded.len() - 32..], hash.as_slice());
    }

    #[test]
    fn pkcs1_v15_pad_rejects_undersized_key() {
        // Key too small: need at least digest_info_len + 11. A
        // 40-byte key cannot fit 32 byte hash + 19 byte prefix + 11.
        let hash = vec![0; 32];
        let err = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, 40).unwrap_err();
        assert!(
            format!("{err}").contains("key too small for digest"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pkcs1_v15_pad_minimum_viable_size() {
        // Exactly at the minimum: digest_info_len + 11
        let hash = vec![0xCC; 32];
        let key_size = RSA_DIGEST_PREFIX_SHA256.len() + hash.len() + 11; // 62
        let out = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, key_size).unwrap();
        assert_eq!(out.len(), key_size);
        assert_eq!(out[0..2], [0x00, 0x01]);
        // Padding length is exactly 8 bytes (the minimum allowed)
        for i in 2..10 {
            assert_eq!(out[i], 0xFF);
        }
        assert_eq!(out[10], 0x00);
    }

    /// Boundary: one byte below the minimum viable size MUST be rejected.
    /// Pins the exact cutoff at `digest_info_len + 11` — an off-by-one
    /// in the production check at line 227 (`<` vs `<=`) would accept
    /// this input and corrupt the padding layout.
    #[test]
    fn pkcs1_v15_pad_rejects_one_byte_below_minimum() {
        let hash = vec![0xCC; 32];
        let key_size = RSA_DIGEST_PREFIX_SHA256.len() + hash.len() + 10; // 61, one below
        let err = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, key_size).unwrap_err();
        assert!(
            format!("{err}").contains("key too small for digest"),
            "unexpected error: {err}"
        );
    }

    /// Independent structural parser for a PKCS#1 v1.5 signature block.
    /// Walks the bytes end-to-end without using any of the constants or
    /// helpers from the production module, so any circular-reference
    /// concern (the self-referential-structure critique) is eliminated.
    ///
    /// Returns the embedded hash on success, panics on any layout
    /// violation — tests assert both that the layout is valid and the
    /// hash at the tail matches the input.
    fn parse_pkcs1_v15_padded(block: &[u8], expected_digest_info_prefix_len: usize) -> Vec<u8> {
        assert!(block.len() >= 12, "block too short: {}", block.len());
        assert_eq!(block[0], 0x00, "leading byte must be 0x00");
        assert_eq!(block[1], 0x01, "block type must be 0x01 for signature");
        let mut i = 2;
        while i < block.len() && block[i] == 0xFF {
            i += 1;
        }
        assert!(
            i >= 2 + 8,
            "padding must be at least 8 bytes (got {})",
            i - 2
        );
        assert!(i < block.len(), "no separator byte found");
        assert_eq!(block[i], 0x00, "separator byte must be 0x00");
        let digest_info_start = i + 1;
        let hash_start = digest_info_start + expected_digest_info_prefix_len;
        assert!(hash_start <= block.len(), "DigestInfo prefix exceeds block");
        block[hash_start..].to_vec()
    }

    /// Independent round-trip: pad a SHA-256 hash, then parse the block
    /// with a structure walker that does NOT share code with
    /// pkcs1_v15_pad. Confirms the emitted bytes form a well-formed
    /// PKCS#1 v1.5 signature block and that the trailing hash matches
    /// what we put in — circular assertions avoided.
    #[test]
    fn pkcs1_v15_pad_roundtrips_through_independent_parser() {
        let hash = Sha256::digest(b"hello world").to_vec();
        let padded = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA256, 256).unwrap();
        let extracted_hash = parse_pkcs1_v15_padded(&padded, RSA_DIGEST_PREFIX_SHA256.len());
        assert_eq!(extracted_hash, hash);
    }

    /// Same for SHA-512 so the DigestInfo prefix length variation is
    /// exercised.
    #[test]
    fn pkcs1_v15_pad_roundtrips_through_independent_parser_sha512() {
        let hash = Sha512::digest(b"hello world").to_vec();
        let padded = pkcs1_v15_pad(&hash, RSA_DIGEST_PREFIX_SHA512, 256).unwrap();
        let extracted_hash = parse_pkcs1_v15_padded(&padded, RSA_DIGEST_PREFIX_SHA512.len());
        assert_eq!(extracted_hash, hash);
    }

    // -------- decode_der_ecdsa_signature --------

    /// Build a DER-encoded ECDSA signature from r, s byte slices.
    /// Assumes r.len() + s.len() + 4 < 128 so single-byte lengths work.
    fn make_der_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x30); // SEQUENCE
        v.push((r.len() + s.len() + 4) as u8);
        v.push(0x02); // INTEGER
        v.push(r.len() as u8);
        v.extend_from_slice(r);
        v.push(0x02);
        v.push(s.len() as u8);
        v.extend_from_slice(s);
        v
    }

    #[test]
    fn decode_der_ecdsa_signature_minimal_valid() {
        let r = vec![0x11; 32];
        let s = vec![0x22; 32];
        let der = make_der_sig(&r, &s);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        assert_eq!(dr, r);
        assert_eq!(ds, s);
    }

    #[test]
    fn decode_der_ecdsa_signature_with_integer_leading_zero_padding() {
        // DER INTEGER encoding prepends 0x00 if the high bit of the
        // first byte is set (to distinguish from negative). Those
        // bytes are part of the decoded integer — the decoder should
        // preserve them verbatim so the caller can re-encode as SSH
        // mpint (which also prefers the same convention).
        let r = vec![0x00, 0x80, 0x12, 0x34];
        let s = vec![0x00, 0xFF, 0xCC];
        let der = make_der_sig(&r, &s);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        assert_eq!(dr, r);
        assert_eq!(ds, s);
    }

    #[test]
    fn decode_der_ecdsa_signature_short_integers() {
        // Small r/s — well within range of the algorithm but under
        // the curve's expected byte count. The decoder must accept
        // whatever length the INTEGER TLV reports.
        let r = vec![0x01];
        let s = vec![0x02, 0x03];
        let der = make_der_sig(&r, &s);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        assert_eq!(dr, r);
        assert_eq!(ds, s);
    }

    #[test]
    fn decode_der_ecdsa_signature_rejects_non_sequence() {
        // First byte should be 0x30 (SEQUENCE)
        let bad = vec![0x31, 0x04, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("not a SEQUENCE"));
    }

    #[test]
    fn decode_der_ecdsa_signature_rejects_too_short() {
        // Each length hits a different bounds check; assert the error
        // message matches the expected one so a change in the control
        // flow stands out.
        let cases: &[(usize, &str)] = &[
            (0, "not a SEQUENCE"),
            (1, "missing length byte"),
            // len 2-5: SEQUENCE claims length >= the byte value of
            // der[1] (48, since vec![0x30; len]) and the buffer
            // undershoots — truncated body.
            (2, "truncated body"),
            (3, "truncated body"),
            (4, "truncated body"),
            (5, "truncated body"),
        ];
        for &(len, expected_fragment) in cases {
            let bad = vec![0x30; len];
            let err = decode_der_ecdsa_signature(&bad).unwrap_err();
            assert!(
                format!("{err}").contains(expected_fragment),
                "len={len}: expected {expected_fragment:?}, got: {err}"
            );
        }
    }

    #[test]
    fn decode_der_ecdsa_signature_rejects_missing_r_integer_tag() {
        // 0x30 seq_len  <not 0x02>  ...
        let bad = vec![0x30, 0x06, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("expected INTEGER tag for r"));
    }

    #[test]
    fn decode_der_ecdsa_signature_rejects_missing_s_integer_tag() {
        // 0x30 seq  0x02 r_len r 0x03 s_len s
        let bad = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x03, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("expected INTEGER tag for s"));
    }

    /// Regression (specific bounds check): an INTEGER length that claims
    /// more payload than fits inside the advertised SEQUENCE must error,
    /// NOT panic with index-out-of-bounds. Use a short-form length (0x64
    /// = 100) so we exercise the `int_end > end` bounds check directly
    /// rather than the "unsupported form" filter.
    #[test]
    fn decode_der_ecdsa_signature_rejects_r_len_exceeding_sequence() {
        // 0x30 seq=0x06  0x02 r_len=0x64 (100 — lies)  0x00  0x02 0x01 0x00
        let bad = vec![0x30, 0x06, 0x02, 0x64, 0x00, 0x02, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("r INTEGER length exceeds SEQUENCE"));
    }

    /// Regression (specific bounds check): same as the r case but for s.
    #[test]
    fn decode_der_ecdsa_signature_rejects_s_len_exceeding_sequence() {
        // 0x30 seq=0x06  0x02 0x01 0x00  0x02 s_len=0x64 (lies)  0x00
        let bad = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x64, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("s INTEGER length exceeds SEQUENCE"));
    }

    /// Regression (fuzz-style panic-safety): a set of adversarial inputs
    /// that pre-fix code would have panicked on (index-out-of-bounds when
    /// the length byte claims more content than the buffer holds). Any
    /// panic here is a DoS — we only assert that the function returns
    /// without panicking.
    #[test]
    fn decode_der_ecdsa_signature_never_panics_on_malformed_input() {
        let fuzz_inputs: &[&[u8]] = &[
            &[],
            &[0x30],
            &[0x30, 0xFF],
            &[0x30, 0x06, 0x02, 0xFF, 0x00, 0x02, 0x01, 0x00],
            &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0xFF, 0x00],
            &[0x30, 0x81, 0xFF, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
            &[0x30, 0x82, 0xFF, 0xFF, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00],
            &[0x30, 0x80],                         // indefinite form (unsupported)
            &[0x30, 0x04, 0x02, 0x02, 0x00, 0x01], // s missing entirely
        ];
        for (i, input) in fuzz_inputs.iter().enumerate() {
            // If this panics, the test fails with a clear backtrace.
            let result = decode_der_ecdsa_signature(input);
            assert!(
                result.is_err(),
                "fuzz input #{i} unexpectedly succeeded: {input:?}"
            );
        }
    }

    /// Regression: a SEQUENCE that claims a length larger than the buffer
    /// must be caught up front.
    #[test]
    fn decode_der_ecdsa_signature_rejects_truncated_sequence_body() {
        // 0x30 seq=0x20  then only 4 payload bytes
        let bad = vec![0x30, 0x20, 0x02, 0x01, 0x00, 0x02];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("truncated"));
    }

    /// Build a DER signature using long-form SEQUENCE length (0x81 LL).
    /// Real P-384 signatures hit this when SEQUENCE payload ≥ 128 bytes
    /// (two 48-byte integers + overhead easily exceeds 127).
    fn make_der_sig_long_form(r: &[u8], s: &[u8]) -> Vec<u8> {
        let body_len = 4 + r.len() + s.len(); // two INTEGERs with 1-byte length headers each
        assert!(
            body_len >= 128,
            "long-form test requires body >= 128, got {body_len}"
        );
        let mut v = Vec::new();
        v.push(0x30); // SEQUENCE
        v.push(0x81); // long-form length: next byte is the length
        v.push(body_len as u8);
        v.push(0x02); // INTEGER
        v.push(r.len() as u8);
        v.extend_from_slice(r);
        v.push(0x02);
        v.push(s.len() as u8);
        v.extend_from_slice(s);
        v
    }

    /// P-384-shaped signature with SEQUENCE length ≥ 128 must decode
    /// correctly. The previous `pos = 2` implementation would silently
    /// mis-parse long-form DER. DER short-form lengths cap at 127; the
    /// smallest long-form encoding is 0x81 0x80. Pick r+s so body length
    /// = 4 + 63 + 63 = 130, comfortably above the threshold.
    #[test]
    fn decode_der_ecdsa_signature_handles_long_form_sequence_length() {
        let r: Vec<u8> = std::iter::repeat(0x11).take(63).collect();
        let s: Vec<u8> = std::iter::repeat(0x22).take(63).collect();
        let der = make_der_sig_long_form(&r, &s);
        // sanity: long-form marker actually in use
        assert_eq!(der[1], 0x81);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        assert_eq!(dr, r);
        assert_eq!(ds, s);
    }

    /// Non-canonical DER is rejected: 0x81 with a length < 128 is not a
    /// valid long-form encoding (should have been short form). Reject to
    /// avoid ambiguity.
    #[test]
    fn decode_der_ecdsa_signature_rejects_non_canonical_long_form() {
        // 0x30 0x81 0x06 {valid body} — 0x81 should never be used for len < 128.
        let bad = vec![0x30, 0x81, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        let err = decode_der_ecdsa_signature(&bad).unwrap_err();
        assert!(format!("{err}").contains("non-canonical"));
    }

    /// Trailing bytes inside the SEQUENCE (beyond s) must be rejected so
    /// we don't silently accept malformed or extended signatures.
    #[test]
    fn decode_der_ecdsa_signature_rejects_trailing_bytes_in_sequence() {
        // SEQUENCE body = 0x02 0x01 0x00 0x02 0x01 0x00 0xDE  (7 bytes).
        // r and s parse fine, but 0xDE sits inside the SEQUENCE past s.
        let inner: Vec<u8> = vec![0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0xDE];
        let mut der = Vec::with_capacity(2 + inner.len());
        der.push(0x30);
        der.push(inner.len() as u8);
        der.extend_from_slice(&inner);
        let err = decode_der_ecdsa_signature(&der).unwrap_err();
        assert!(format!("{err}").contains("trailing bytes"));
    }

    // -------- encode_ecdsa_ssh_signature --------

    #[test]
    fn encode_ecdsa_ssh_signature_format() {
        // SSH ECDSA sig blob = uint32(r_len) || r || uint32(s_len) || s
        let r = vec![0x01, 0x02, 0x03];
        let s = vec![0xAA, 0xBB];
        let blob = encode_ecdsa_ssh_signature(&r, &s);
        // 4 (r_len) + 3 (r) + 4 (s_len) + 2 (s) = 13
        assert_eq!(blob.len(), 13);
        assert_eq!(&blob[0..4], &3u32.to_be_bytes());
        assert_eq!(&blob[4..7], r.as_slice());
        assert_eq!(&blob[7..11], &2u32.to_be_bytes());
        assert_eq!(&blob[11..13], s.as_slice());
    }

    #[test]
    fn encode_ecdsa_ssh_signature_roundtrip_from_der() {
        let r = vec![0x00, 0xAB, 0xCD, 0xEF];
        let s = vec![0x12, 0x34, 0x56];
        let der = make_der_sig(&r, &s);
        let (dr, ds) = decode_der_ecdsa_signature(&der).unwrap();
        let blob = encode_ecdsa_ssh_signature(&dr, &ds);
        assert_eq!(&blob[0..4], &(r.len() as u32).to_be_bytes());
        assert_eq!(&blob[4..4 + r.len()], r.as_slice());
        let s_off = 4 + r.len();
        assert_eq!(&blob[s_off..s_off + 4], &(s.len() as u32).to_be_bytes());
        assert_eq!(&blob[s_off + 4..], s.as_slice());
    }

    // -------- to_ssh_signature --------

    #[test]
    fn to_ssh_signature_ecp256_decodes_der() {
        // DER INTEGERs with their high bit set carry a leading 0x00 byte
        // (to disambiguate from negative two's-complement). SSH mpint
        // encoding uses the same convention, so the raw DER integer
        // bytes are also a valid SSH mpint body. Build r/s with a
        // leading zero so `Signature::new` validation accepts the
        // resulting blob.
        let mut r = vec![0x00];
        r.extend(std::iter::repeat(0xAB).take(32));
        let mut s = vec![0x00];
        s.extend(std::iter::repeat(0xCD).take(32));
        let der = make_der_sig(&r, &s);
        let sig = to_ssh_signature(PivAlgorithm::EcP256, &der, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "ecdsa-sha2-nistp256");
        // Signature body is the SSH ECDSA encoding of (r, s)
        let expected = encode_ecdsa_ssh_signature(&r, &s);
        assert_eq!(sig.as_bytes(), expected.as_slice());
    }

    #[test]
    fn to_ssh_signature_ecp256_decodes_der_low_high_bit() {
        // When the high bit is clear, DER omits the leading zero.
        let r = vec![0x11; 32]; // high bit 0
        let s = vec![0x22; 32]; // high bit 0
        let der = make_der_sig(&r, &s);
        let sig = to_ssh_signature(PivAlgorithm::EcP256, &der, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "ecdsa-sha2-nistp256");
        let expected = encode_ecdsa_ssh_signature(&r, &s);
        assert_eq!(sig.as_bytes(), expected.as_slice());
    }

    #[test]
    fn to_ssh_signature_ecp384_decodes_der() {
        // Low high bit -> no leading zero in DER.
        let r = vec![0x11; 48];
        let s = vec![0x22; 48];
        let der = make_der_sig(&r, &s);
        let sig = to_ssh_signature(PivAlgorithm::EcP384, &der, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "ecdsa-sha2-nistp384");
        let expected = encode_ecdsa_ssh_signature(&r, &s);
        assert_eq!(sig.as_bytes(), expected.as_slice());
    }

    #[test]
    fn to_ssh_signature_ecdsa_rejects_bad_der() {
        // 0xFF...: not a SEQUENCE. Check the exact error so a refactor
        // that returns a different error (e.g. a post-decode panic path)
        // still fails the test.
        let bad_der = vec![0xFF; 8];
        let err = to_ssh_signature(PivAlgorithm::EcP256, &bad_der, 0).unwrap_err();
        assert!(format!("{err}").contains("not a SEQUENCE"));
    }

    /// Extra coverage: DER that passes the SEQUENCE tag check but has a
    /// malformed inner INTEGER. Pre-fix code could panic here; confirms
    /// the error propagates cleanly through to_ssh_signature.
    #[test]
    fn to_ssh_signature_ecdsa_rejects_malformed_inner_der() {
        let bad_der = vec![0x30, 0x06, 0x02, 0x64, 0x00, 0x02, 0x01, 0x00];
        let err = to_ssh_signature(PivAlgorithm::EcP256, &bad_der, 0).unwrap_err();
        assert!(format!("{err}").contains("r INTEGER length exceeds SEQUENCE"));
    }

    #[test]
    fn to_ssh_signature_ed25519_passthrough() {
        let raw = vec![0x33; 64];
        let sig = to_ssh_signature(PivAlgorithm::Ed25519, &raw, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "ssh-ed25519");
        assert_eq!(sig.as_bytes(), raw.as_slice());
    }

    #[test]
    fn to_ssh_signature_rsa2048_default_labels_sha256() {
        let raw = vec![0xBB; 256];
        let sig = to_ssh_signature(PivAlgorithm::Rsa2048, &raw, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
        assert_eq!(sig.as_bytes(), raw.as_slice());
    }

    #[test]
    fn to_ssh_signature_rsa2048_sha512_flag_labels_sha512() {
        let raw = vec![0xAB; 256];
        let sig = to_ssh_signature(PivAlgorithm::Rsa2048, &raw, signature::RSA_SHA2_512).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-512");
        assert_eq!(sig.as_bytes(), raw.as_slice());
    }

    #[test]
    fn to_ssh_signature_rsa2048_sha256_flag_labels_sha256() {
        let raw = vec![0x01; 256];
        let sig = to_ssh_signature(PivAlgorithm::Rsa2048, &raw, signature::RSA_SHA2_256).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
    }

    #[test]
    fn to_ssh_signature_rsa1024_sha256_default() {
        let raw = vec![0x01; 128];
        let sig = to_ssh_signature(PivAlgorithm::Rsa1024, &raw, 0).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
    }

    /// Mirror of `prepare_sign_data_rsa2048_sha512_wins_when_both_flags_set`
    /// for the to_ssh_signature label path: when both flags are set, the
    /// produced SSH algorithm label is rsa-sha2-512.
    #[test]
    fn to_ssh_signature_rsa2048_sha512_wins_when_both_flags_set() {
        let raw = vec![0xAB; 256];
        let sig = to_ssh_signature(
            PivAlgorithm::Rsa2048,
            &raw,
            signature::RSA_SHA2_256 | signature::RSA_SHA2_512,
        )
        .unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-512");
    }

    /// Mirror of `prepare_sign_data_rsa2048_unknown_flags_default_to_sha256`:
    /// unknown flag bits label the signature as rsa-sha2-256.
    #[test]
    fn to_ssh_signature_rsa2048_unknown_flags_default_to_sha256() {
        let raw = vec![0xAB; 256];
        let sig = to_ssh_signature(PivAlgorithm::Rsa2048, &raw, 1 << 31).unwrap();
        assert_eq!(sig.algorithm().as_str(), "rsa-sha2-256");
    }

    // -------- Session impl: request_identities --------

    #[tokio::test]
    async fn request_identities_empty() {
        let mut agent = PiggyAgent::new(Vec::new());
        let ids = agent.request_identities().await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn request_identities_returns_all_cached_keys() {
        let keys = vec![
            cached_ed25519(0x11, 0x9A),
            cached_ed25519(0x22, 0x9C),
            cached_ed25519(0x33, 0x9D),
        ];
        let comments: Vec<String> = keys.iter().map(|k| k.comment.clone()).collect();
        let pubs: Vec<KeyData> = keys.iter().map(|k| k.public_key.clone()).collect();

        let mut agent = PiggyAgent::new(keys);
        let ids = agent.request_identities().await.unwrap();
        assert_eq!(ids.len(), 3);
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(id.comment, comments[i]);
            assert_eq!(id.pubkey, pubs[i]);
        }
    }

    #[tokio::test]
    async fn request_identities_idempotent() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x42, 0x9E)]);
        let first = agent.request_identities().await.unwrap();
        let second = agent.request_identities().await.unwrap();
        assert_eq!(first.len(), second.len());
        assert_eq!(first[0].pubkey, second[0].pubkey);
    }

    // -------- Session impl: sign (pre-PCSC branch) --------

    /// Assert that an `AgentError` is the `::Other` variant AND that its
    /// rendered message equals `expected`. The variant check uses the
    /// `{:?}` Debug representation (which starts with the variant name),
    /// the message check uses `{}` Display. Tighter than a raw
    /// `.contains()` on Display alone — a refactor that moves the error
    /// to a different variant but keeps a similar message would fail
    /// this assertion.
    fn assert_agent_error_other_eq(err: &AgentError, expected: &str) {
        let debug = format!("{err:?}");
        let display = format!("{err}");
        assert!(
            debug.trim_start().starts_with("Other"),
            "expected AgentError::Other variant, got debug={debug}"
        );
        assert!(
            display.contains(expected),
            "error message mismatch: expected to contain {expected:?}, got {display}"
        );
    }

    #[tokio::test]
    async fn sign_unknown_key_errors_before_touching_pcsc() {
        // An empty cache plus any pubkey must short-circuit at
        // find_key returning "key not found" -- importantly, this
        // branch never calls PivContext::new(), so the test runs
        // in environments without PCSC.
        let mut agent = PiggyAgent::new(Vec::new());
        let req = SignRequest {
            pubkey: ed25519_key_data(0x01),
            data: b"whatever".to_vec(),
            flags: 0,
        };
        let err = agent.sign(req).await.unwrap_err();
        assert_agent_error_other_eq(&err, "key not found");
    }

    #[tokio::test]
    async fn sign_mismatched_key_errors_before_touching_pcsc() {
        // Cache has seed 0x11, request asks for seed 0x99 -- must
        // still short-circuit before PCSC.
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x11, 0x9A)]);
        let req = SignRequest {
            pubkey: ed25519_key_data(0x99),
            data: b"whatever".to_vec(),
            flags: 0,
        };
        let err = agent.sign(req).await.unwrap_err();
        assert_agent_error_other_eq(&err, "key not found");
    }

    // -------- Session impl: lock / unlock --------

    #[tokio::test]
    async fn unlock_populates_pin() {
        let mut agent = PiggyAgent::new(Vec::new());
        agent.unlock("1234".into()).await.unwrap();
        assert_eq!(*agent.pin_handle().lock().await, Some("1234".into()));
    }

    #[tokio::test]
    async fn lock_clears_pin() {
        let mut agent = PiggyAgent::new(Vec::new());
        agent.unlock("abcd".into()).await.unwrap();
        agent.lock("ignored-by-impl".into()).await.unwrap();
        assert_eq!(*agent.pin_handle().lock().await, None);
    }

    #[tokio::test]
    async fn unlock_overwrites_existing_pin() {
        let mut agent = PiggyAgent::new(Vec::new());
        agent.unlock("first".into()).await.unwrap();
        agent.unlock("second".into()).await.unwrap();
        assert_eq!(*agent.pin_handle().lock().await, Some("second".into()));
    }

    #[tokio::test]
    async fn lock_when_empty_is_noop() {
        let mut agent = PiggyAgent::new(Vec::new());
        agent.lock("anything".into()).await.unwrap();
        assert_eq!(*agent.pin_handle().lock().await, None);
        // Lock again, still None.
        agent.lock("again".into()).await.unwrap();
        assert_eq!(*agent.pin_handle().lock().await, None);
    }

    #[tokio::test]
    async fn lock_unlock_lock_cycle() {
        let mut agent = PiggyAgent::new(Vec::new());
        let handle = agent.pin_handle();

        assert_eq!(*handle.lock().await, None);
        agent.unlock("pin1".into()).await.unwrap();
        assert_eq!(*handle.lock().await, Some("pin1".into()));
        agent.lock("x".into()).await.unwrap();
        assert_eq!(*handle.lock().await, None);
        agent.unlock("pin2".into()).await.unwrap();
        assert_eq!(*handle.lock().await, Some("pin2".into()));
    }

    #[tokio::test]
    async fn pin_handle_shares_state_with_clone() {
        // `pin_handle()` must hand out an Arc that reflects live
        // state — otherwise the background `probe_loop` could never
        // clear the PIN.
        let mut agent = PiggyAgent::new(Vec::new());
        let handle = agent.pin_handle();
        agent.unlock("shared".into()).await.unwrap();
        assert_eq!(*handle.lock().await, Some("shared".into()));

        // Mutate via the handle, observe via the agent.
        *handle.lock().await = Some("via-handle".into());
        let handle2 = agent.pin_handle();
        assert_eq!(*handle2.lock().await, Some("via-handle".into()));
    }

    // -------- Session impl: extension --------

    #[tokio::test]
    async fn extension_query_lists_supported_names() {
        let mut agent = PiggyAgent::new(Vec::new());
        let resp = agent
            .extension(Extension {
                name: "query".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap()
            .expect("query extension must produce a response");
        assert_eq!(resp.name, "query");

        // Body is a sequence of uint32-length-prefixed ASCII names.
        let body: Vec<u8> = resp.details.into_bytes();
        let mut names = Vec::new();
        let mut i = 0;
        while i + 4 <= body.len() {
            let len = u32::from_be_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]) as usize;
            i += 4;
            names.push(String::from_utf8(body[i..i + len].to_vec()).unwrap());
            i += len;
        }
        assert_eq!(
            i,
            body.len(),
            "body must fully parse with no trailing bytes"
        );
        assert!(names.iter().any(|n| n == "query"));
        assert!(names.iter().any(|n| n == "session-bind@openssh.com"));
        assert!(names.iter().any(|n| n == "pin-status@joyent.com"));
    }

    #[tokio::test]
    async fn extension_session_bind_returns_none() {
        let mut agent = PiggyAgent::new(Vec::new());
        let resp = agent
            .extension(Extension {
                name: "session-bind@openssh.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap();
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn extension_pin_status_empty_agent() {
        let mut agent = PiggyAgent::new(Vec::new());
        let resp = agent
            .extension(Extension {
                name: "pin-status@joyent.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap()
            .expect("pin-status must produce a response");
        let body: Vec<u8> = resp.details.into_bytes();
        assert_eq!(body.len(), 2);
        assert_eq!(body[0], 0, "no PIN -> has_pin=0");
        assert_eq!(body[1], 0, "no keys -> has_card=0");
    }

    #[tokio::test]
    async fn extension_pin_status_with_keys_and_pin() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x77, 0x9A)]);
        agent.unlock("cached".into()).await.unwrap();

        let resp = agent
            .extension(Extension {
                name: "pin-status@joyent.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap()
            .unwrap();
        let body: Vec<u8> = resp.details.into_bytes();
        assert_eq!(body, vec![1, 1]);
    }

    #[tokio::test]
    async fn extension_pin_status_with_keys_no_pin() {
        let mut agent = PiggyAgent::new(vec![cached_ed25519(0x77, 0x9A)]);
        let resp = agent
            .extension(Extension {
                name: "pin-status@joyent.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap()
            .unwrap();
        let body: Vec<u8> = resp.details.into_bytes();
        assert_eq!(body, vec![0, 1]);
    }

    #[tokio::test]
    async fn extension_unknown_returns_error() {
        let mut agent = PiggyAgent::new(Vec::new());
        let err = agent
            .extension(Extension {
                name: "bogus@example.com".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap_err();
        // Specifically the UnsupportedCommand protocol error, not any
        // random other AgentError variant.
        let debug = format!("{err:?}");
        assert!(
            debug.contains("UnsupportedCommand"),
            "expected UnsupportedCommand, got {debug}"
        );
    }

    /// Matching on extension names is case-sensitive — "Query" must NOT
    /// match the "query" arm. Pins the exact-match semantics so a later
    /// refactor to case-insensitive lookup (which would be a protocol
    /// violation per the SSH agent spec) fails loudly.
    #[tokio::test]
    async fn extension_name_is_case_sensitive() {
        let mut agent = PiggyAgent::new(Vec::new());
        let err = agent
            .extension(Extension {
                name: "Query".into(),
                details: Vec::<u8>::new().into(),
            })
            .await
            .unwrap_err();
        assert!(format!("{err:?}").contains("UnsupportedCommand"));
    }

    // -------- Sanity: RSA DigestInfo prefixes match RFC 8017 --------

    #[test]
    fn rsa_digest_prefix_sha256_matches_rfc_8017() {
        // RFC 8017 § 9.2 (PKCS#1 v2.2) EMSA-PKCS1-v1_5 DigestInfo for SHA-256:
        //   30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        let expected: [u8; 19] = [
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ];
        assert_eq!(RSA_DIGEST_PREFIX_SHA256, &expected);
    }

    #[test]
    fn rsa_digest_prefix_sha512_matches_rfc_8017() {
        // RFC 8017 § 9.2 EMSA-PKCS1-v1_5 DigestInfo for SHA-512:
        //   30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
        let expected: [u8; 19] = [
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ];
        assert_eq!(RSA_DIGEST_PREFIX_SHA512, &expected);
    }
}
