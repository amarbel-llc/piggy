//! pigpen document model, hyphence codec, and seal/open (RFC 0008 §2).

use piggy_markl::{FormatId, Id, PurposeId, blech32};

use crate::crypto;
use crate::hyphence::{HyphenceDoc, MetaLine};
use crate::{Error, Result};

const TYPE_TAG: &str = "pigpen-v1";
const POINTER_TYPE_TAG: &str = "pigpen-pointer-v1";
const HRP_WRAP_P256: &str = "pigpen_wrap_p256";
const HRP_WRAP_X25519: &str = "pigpen_wrap_x25519";
const HRP_HEADER_MAC: &str = "pigpen_header_mac";
const PURPOSE_WRAP: &str = "pigpen-wrap-v1";

/// Card-bound ECDH for a P-256 recipient (RFC 0008 §4.3, §7). A wasm host
/// wires this to piggy-agent's `ecdh@joyent.com`; the slot-9D scalar
/// never leaves the card.
pub trait EcdhOracle {
    /// X-coordinate of (self_private · partner_epk), 32 bytes.
    fn ecdh(&self, self_recipient: &Id, partner_epk: &[u8]) -> Result<[u8; 32]>;
}

/// A software age identity for the pure-software open path (RFC 0008 §4.4).
pub struct X25519Identity {
    pub public: Vec<u8>,
    pub secret: Vec<u8>,
}

/// One recipient line.
pub struct Recipient {
    pub id: Id,
    pub comment: Option<String>,
    pub wrap: Option<Vec<u8>>, // Epk‖AEAD(file key); None in recipient-set mode
}

/// In-memory model of a pigpen-v1 document.
pub struct Document {
    pub description: Option<String>,
    pub recipients: Vec<Recipient>,
    pub payload: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

impl Document {
    pub fn sealed(&self) -> bool {
        self.mac.is_some()
    }

    /// A payload-less recipient set — the drop-in for a `piggy-ids` file.
    pub fn new_recipient_set(recipients: Vec<Recipient>) -> Self {
        Document {
            description: None,
            recipients,
            payload: Vec::new(),
            mac: None,
        }
    }

    /// Encrypt `plaintext` to `recipients`, producing a sealed document.
    /// All wraps are pure software (P-256 encrypt needs no card).
    pub fn seal(plaintext: &[u8], recipients: &[Id]) -> Result<Document> {
        if recipients.is_empty() {
            return Err(Error::Malformed(
                "at least one recipient is required".into(),
            ));
        }
        // Wrap in Zeroizing so the file key is scrubbed from memory when it
        // drops — including on any early `?` return below — matching the Go
        // impl's `defer zero(fileKey)`.
        let file_key = zeroize::Zeroizing::new(crypto::random_file_key());

        let mut recs = Vec::with_capacity(recipients.len());
        for id in recipients {
            let wrap = match id.format() {
                FormatId::PivyEcdhP256Pub => crypto::wrap_p256(&file_key[..], id.data())?,
                FormatId::AgeX25519Pub => crypto::wrap_x25519(&file_key[..], id.data())?,
                other => return Err(Error::UnsupportedFormat(format!("{other:?}"))),
            };
            recs.push(Recipient {
                id: id.clone(),
                comment: None,
                wrap: Some(wrap),
            });
        }

        let payload = crypto::seal_payload(&file_key[..], plaintext)?;
        let mut doc = Document {
            description: None,
            recipients: recs,
            payload,
            mac: None,
        };
        let canon = doc.canonical_header()?;
        doc.mac = Some(crypto::header_mac(&file_key[..], &canon).to_vec());
        Ok(doc)
    }

    /// Recover the plaintext, trying each recipient against the supplied
    /// X25519 identities and, for P-256 recipients, the oracle.
    pub fn open(
        &self,
        oracle: Option<&dyn EcdhOracle>,
        x25519: &[X25519Identity],
    ) -> Result<Vec<u8>> {
        if !self.sealed() {
            return Err(Error::Malformed(
                "document is a recipient set, not sealed".into(),
            ));
        }
        let mac = self.mac.as_ref().unwrap();
        for r in &self.recipients {
            let Some(wrap) = &r.wrap else { continue };
            let file_key = match r.id.format() {
                FormatId::AgeX25519Pub => {
                    let Some(id) = x25519.iter().find(|i| i.public == r.id.data()) else {
                        continue;
                    };
                    crypto::unwrap_x25519(wrap, r.id.data(), &id.secret)
                }
                FormatId::PivyEcdhP256Pub => {
                    let Some(oracle) = oracle else { continue };
                    let epk = crypto::p256_wrap_epk(wrap)?;
                    let shared = oracle.ecdh(&r.id, epk)?;
                    crypto::unwrap_p256_with_shared(wrap, r.id.data(), &shared)
                }
                _ => continue,
            };
            let Ok(file_key) = file_key else { continue }; // not our key / tampered

            let canon = self.canonical_header()?;
            if !crypto::verify_mac(&file_key, &canon, mac) {
                return Err(Error::MacMismatch);
            }
            return crypto::open_payload(&file_key, &self.payload);
        }
        Err(Error::NoRecipient)
    }

    // --- hyphence codec --------------------------------------------------

    fn build(&self, include_mac: bool) -> Result<HyphenceDoc> {
        let mut h = HyphenceDoc::default();
        // An empty description is equivalent to none (the Go impl models the
        // description as a bare String, so `""` renders nothing): emitting a
        // "# " line for it would desync the header MAC across implementations.
        if let Some(desc) = &self.description {
            if !desc.is_empty() {
                reject_control("description", desc)?;
                h.meta.push(MetaLine {
                    prefix: b'#',
                    body: desc.clone(),
                });
            }
        }
        for r in &self.recipients {
            let mut body = r.id.to_wire();
            if let Some(wrap) = &r.wrap {
                body.push_str(" < ");
                body.push_str(&encode_wrap(r.id.format(), wrap)?);
            } else if let Some(c) = &r.comment {
                if !c.is_empty() {
                    reject_control("comment", c)?;
                    body.push_str("  # ");
                    body.push_str(c);
                }
            }
            h.meta.push(MetaLine { prefix: b'-', body });
        }
        let mut type_body = TYPE_TAG.to_string();
        if include_mac {
            if let Some(mac) = &self.mac {
                type_body.push('@');
                type_body.push_str(&encode_mac(mac)?);
            }
        }
        h.meta.push(MetaLine {
            prefix: b'!',
            body: type_body,
        });
        if include_mac && self.sealed() {
            h.body = self.payload.clone();
        }
        Ok(h)
    }

    fn canonical_header(&self) -> Result<Vec<u8>> {
        Ok(self.build(false)?.marshal_metadata())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.build(true)?.marshal()
    }

    pub fn parse(raw: &[u8]) -> Result<Document> {
        let h = crate::hyphence::parse(raw)?;
        let mut doc = Document {
            description: None,
            recipients: Vec::new(),
            payload: Vec::new(),
            mac: None,
        };
        let mut saw_type = false;
        for l in &h.meta {
            match l.prefix {
                b'#' => {
                    // Skip empty "# " lines so an empty description stays None
                    // (symmetric with Go), keeping the canonical header — and
                    // thus the MAC — identical across implementations.
                    if !l.body.is_empty() {
                        let d = doc.description.get_or_insert_with(String::new);
                        if !d.is_empty() {
                            d.push(' ');
                        }
                        d.push_str(&l.body);
                    }
                }
                b'-' => doc.recipients.push(parse_recipient_line(&l.body)?),
                b'@' => {
                    return Err(Error::Malformed(
                        "'@'-referenced payload not supported in prototype (inline only)".into(),
                    ));
                }
                b'!' => {
                    parse_type_line(&mut doc, &l.body)?;
                    saw_type = true;
                }
                _ => {}
            }
        }
        if !saw_type {
            return Err(Error::Malformed("missing '! pigpen-v1' type line".into()));
        }
        doc.payload = h.body;
        doc.validate()?;
        Ok(doc)
    }

    fn validate(&self) -> Result<()> {
        let wrapped = self.recipients.iter().filter(|r| r.wrap.is_some()).count();
        let unwrapped = self.recipients.len() - wrapped;
        let sealed = self.mac.is_some() || !self.payload.is_empty() || wrapped > 0;
        if !sealed {
            return Ok(());
        }
        if unwrapped > 0 {
            return Err(Error::Malformed("mixed sealed/unsealed recipients".into()));
        }
        if self.mac.is_none() {
            return Err(Error::Malformed(
                "sealed document missing header MAC".into(),
            ));
        }
        if self.payload.is_empty() {
            return Err(Error::Malformed("sealed document missing payload".into()));
        }
        Ok(())
    }
}

/// A pigpen pointer face (RFC 0008 §2.2, RFC 0010): names a resolver
/// by opaque `kind` + `locator` rather than carrying recipients
/// directly. `locator` is never interpreted by this crate — it is
/// handed verbatim to whatever invokes the resolver.
pub struct Pointer {
    pub kind: String,
    pub locator: String,
}

impl Pointer {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let h = HyphenceDoc {
            meta: vec![
                MetaLine {
                    prefix: b'-',
                    body: format!("kind=\"{}\"", self.kind),
                },
                MetaLine {
                    prefix: b'-',
                    body: format!("locator=\"{}\"", self.locator),
                },
                MetaLine {
                    prefix: b'!',
                    body: POINTER_TYPE_TAG.to_string(),
                },
            ],
            body: Vec::new(),
        };
        h.marshal()
    }

    pub fn parse(raw: &[u8]) -> Result<Pointer> {
        let h = crate::hyphence::parse(raw)?;
        let is_pointer = h
            .meta
            .iter()
            .any(|l| l.prefix == b'!' && l.body == POINTER_TYPE_TAG);
        if !is_pointer {
            return Err(Error::Malformed(format!(
                "not a {POINTER_TYPE_TAG} document"
            )));
        }
        let mut kind = None;
        let mut locator = None;
        for l in &h.meta {
            if l.prefix != b'-' {
                continue;
            }
            if let Some(v) = parse_quoted_kv(&l.body, "kind") {
                kind = Some(v);
            } else if let Some(v) = parse_quoted_kv(&l.body, "locator") {
                locator = Some(v);
            }
        }
        let kind = kind.ok_or_else(|| Error::Malformed("pointer missing kind tag".into()))?;
        let locator =
            locator.ok_or_else(|| Error::Malformed("pointer missing locator tag".into()))?;
        Ok(Pointer { kind, locator })
    }
}

/// Parse a `key="value"` tag body, e.g. `kind="papi-http"` with
/// `key = "kind"` returns `Some("papi-http")`. Returns `None` if the
/// prefix or quoting doesn't match — callers try each key in turn.
fn parse_quoted_kv(body: &str, key: &str) -> Option<String> {
    let rest = body.strip_prefix(key)?.strip_prefix('=')?;
    let inner = rest.strip_prefix('"')?.strip_suffix('"')?;
    Some(inner.to_string())
}

fn encode_wrap(format: FormatId, blob: &[u8]) -> Result<String> {
    let hrp = match format {
        FormatId::PivyEcdhP256Pub => HRP_WRAP_P256,
        FormatId::AgeX25519Pub => HRP_WRAP_X25519,
        other => return Err(Error::UnsupportedFormat(format!("{other:?}"))),
    };
    let body = blech32::encode(hrp, blob).map_err(|e| Error::Blech32(format!("{e}")))?;
    Ok(format!("{PURPOSE_WRAP}@{body}"))
}

fn decode_wrap(s: &str) -> Result<Vec<u8>> {
    let body = s.split_once('@').map(|(_, b)| b).unwrap_or(s);
    let (hrp, data) = blech32::decode(body).map_err(|e| Error::Blech32(format!("{e}")))?;
    if hrp != HRP_WRAP_P256 && hrp != HRP_WRAP_X25519 {
        return Err(Error::Blech32(format!("unexpected wrap HRP {hrp}")));
    }
    Ok(data)
}

fn encode_mac(mac: &[u8]) -> Result<String> {
    blech32::encode(HRP_HEADER_MAC, mac).map_err(|e| Error::Blech32(format!("{e}")))
}

fn decode_mac(s: &str) -> Result<Vec<u8>> {
    let (hrp, data) = blech32::decode(s).map_err(|e| Error::Blech32(format!("{e}")))?;
    if hrp != HRP_HEADER_MAC {
        return Err(Error::Blech32(format!("unexpected MAC HRP {hrp}")));
    }
    Ok(data)
}

fn parse_type_line(doc: &mut Document, body: &str) -> Result<()> {
    let (tag, mac) = match body.split_once('@') {
        Some((tag, mac_s)) => (tag, Some(decode_mac(mac_s)?)),
        None => (body, None),
    };
    if tag != TYPE_TAG {
        return Err(Error::Malformed(format!(
            "unexpected type {tag:?} (want {TYPE_TAG:?})"
        )));
    }
    doc.mac = mac;
    Ok(())
}

fn parse_recipient_line(body: &str) -> Result<Recipient> {
    let mut comment = None;
    let mut wrap = None;
    // Split the comment on the exact "  # " delimiter (two spaces, hash,
    // space) and take the remainder verbatim, BEFORE looking for the " < "
    // wrap delimiter. A comment is free text that MAY contain " < " or a
    // leading '#'; checking it first (and not trimming its body) keeps those
    // characters intact instead of mistaking a comment for a key wrap or
    // eating a leading '#'. The id and blech32 wrap never contain "  # ".
    let id_str = if let Some((left, right)) = body.split_once("  # ") {
        if !right.is_empty() {
            comment = Some(right.to_string());
        }
        left.trim().to_string()
    } else if let Some((left, right)) = body.split_once(" < ") {
        wrap = Some(decode_wrap(right.trim())?);
        left.trim().to_string()
    } else {
        body.trim().to_string()
    };
    let id = Id::parse(&id_str).map_err(|e| Error::Markl(format!("{e}")))?;
    Ok(Recipient { id, comment, wrap })
}

/// Reject a description/comment carrying a line-breaking control character.
/// Metadata is single-line (RFC 0001 framing), so an embedded newline would
/// silently corrupt the document on re-parse; refuse it at serialization time.
fn reject_control(field: &str, s: &str) -> Result<()> {
    if s.contains(['\n', '\r']) {
        return Err(Error::Malformed(format!(
            "{field} must not contain a newline (metadata is single-line)"
        )));
    }
    Ok(())
}

/// Build a recipient ID from raw key bytes (test/helper convenience).
pub fn recipient_id(format: FormatId, bytes: Vec<u8>) -> Result<Id> {
    Id::new(Some(PurposeId::PiggyRecipientV1), format, bytes)
        .map_err(|e| Error::Markl(format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::OsRng;

    fn new_x25519() -> (Vec<u8>, X25519Identity) {
        let sk = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let pk = x25519_dalek::PublicKey::from(&sk);
        let public = pk.as_bytes().to_vec();
        (
            public.clone(),
            X25519Identity {
                public,
                secret: sk.to_bytes().to_vec(),
            },
        )
    }

    struct SoftP256Oracle {
        sk: p256::SecretKey,
    }
    impl EcdhOracle for SoftP256Oracle {
        fn ecdh(&self, _self: &Id, partner_epk: &[u8]) -> Result<[u8; 32]> {
            let epk = p256::PublicKey::from_sec1_bytes(partner_epk)
                .map_err(|e| Error::Crypto(format!("{e}")))?;
            let shared = p256::ecdh::diffie_hellman(self.sk.to_nonzero_scalar(), epk.as_affine());
            let mut out = [0u8; 32];
            out.copy_from_slice(shared.raw_secret_bytes());
            Ok(out)
        }
    }

    fn new_p256() -> (Vec<u8>, SoftP256Oracle) {
        let sk = p256::SecretKey::random(&mut OsRng);
        let compressed = sk.public_key().to_encoded_point(true).as_bytes().to_vec();
        (compressed, SoftP256Oracle { sk })
    }

    #[test]
    fn recipient_set_round_trip() {
        let (pub_, _) = new_x25519();
        let id = recipient_id(FormatId::AgeX25519Pub, pub_).unwrap();
        let doc = Document::new_recipient_set(vec![Recipient {
            id: id.clone(),
            comment: Some("laptop".into()),
            wrap: None,
        }]);
        let wire = doc.to_bytes().unwrap();
        assert!(!doc.sealed());

        let got = Document::parse(&wire).unwrap();
        assert_eq!(got.recipients.len(), 1);
        assert!(!got.sealed());
        assert_eq!(got.recipients[0].comment.as_deref(), Some("laptop"));
        assert_eq!(got.recipients[0].id.to_wire(), id.to_wire());
    }

    #[test]
    fn seal_open_x25519() {
        let (pub_, ident) = new_x25519();
        let id = recipient_id(FormatId::AgeX25519Pub, pub_).unwrap();
        let plaintext = b"attack at dawn";

        let doc = Document::seal(plaintext, &[id]).unwrap();
        assert!(doc.sealed());
        let wire = doc.to_bytes().unwrap();
        let parsed = Document::parse(&wire).unwrap();

        let got = parsed.open(None, &[ident]).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn seal_open_p256_via_oracle() {
        let (compressed, oracle) = new_p256();
        let id = recipient_id(FormatId::PivyEcdhP256Pub, compressed).unwrap();
        let plaintext = b"piggy rfc0008 pigpen p256";

        let doc = Document::seal(plaintext, &[id]).unwrap();
        let wire = doc.to_bytes().unwrap();
        let parsed = Document::parse(&wire).unwrap();

        let got = parsed.open(Some(&oracle), &[]).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn multi_recipient_any_one_opens() {
        let (xpub, xident) = new_x25519();
        let (ppub, oracle) = new_p256();
        let ids = vec![
            recipient_id(FormatId::AgeX25519Pub, xpub).unwrap(),
            recipient_id(FormatId::PivyEcdhP256Pub, ppub).unwrap(),
        ];
        let plaintext = b"either key suffices";
        let doc = Document::seal(plaintext, &ids).unwrap();

        assert_eq!(doc.open(None, &[xident]).unwrap(), plaintext);
        assert_eq!(doc.open(Some(&oracle), &[]).unwrap(), plaintext);
    }

    #[test]
    fn mac_tamper_rejected() {
        let (pub_, ident) = new_x25519();
        let id = recipient_id(FormatId::AgeX25519Pub, pub_).unwrap();
        let mut doc = Document::seal(b"secret", &[id]).unwrap();
        doc.payload[crypto::PAYLOAD_NONCE_LEN] ^= 0xff;
        assert!(doc.open(None, &[ident]).is_err());
    }

    #[test]
    fn reject_at_ref_with_body() {
        let raw = b"---\n@ blake2b256-abc\n! pigpen-v1\n---\n\ninline\n";
        assert!(Document::parse(raw).is_err());
    }

    #[test]
    fn comment_with_delimiters_round_trips() {
        let (pub_, _) = new_x25519();
        let id = recipient_id(FormatId::AgeX25519Pub, pub_).unwrap();
        // A comment may contain the wrap delimiter " < ", a leading '#', or an
        // inner "  # " — none of these must corrupt the round-trip (#1/#3).
        for c in ["a < b", "#1 backup", "has  # inner", "plain"] {
            let doc = Document::new_recipient_set(vec![Recipient {
                id: id.clone(),
                comment: Some(c.to_string()),
                wrap: None,
            }]);
            let wire = doc.to_bytes().unwrap();
            let got = Document::parse(&wire).unwrap();
            assert_eq!(
                got.recipients[0].comment.as_deref(),
                Some(c),
                "comment {c:?} corrupted through round-trip"
            );
        }
    }

    #[test]
    fn empty_description_absent_from_canonical_header() {
        let (pub_, _) = new_x25519();
        let id = recipient_id(FormatId::AgeX25519Pub, pub_).unwrap();
        let doc = Document {
            description: Some(String::new()),
            recipients: vec![Recipient {
                id,
                comment: None,
                wrap: None,
            }],
            payload: Vec::new(),
            mac: None,
        };
        // An empty description must NOT render a "# " line — otherwise the
        // header MAC desyncs against the Go impl, which drops it (#4).
        let canon = doc.canonical_header().unwrap();
        assert!(
            !canon.windows(2).any(|w| w == b"# "),
            "empty description leaked into canonical header: {}",
            String::from_utf8_lossy(&canon)
        );
    }

    #[test]
    fn newline_in_comment_rejected() {
        let (pub_, _) = new_x25519();
        let id = recipient_id(FormatId::AgeX25519Pub, pub_).unwrap();
        // A newline would break the single-line metadata framing (#2).
        let doc = Document::new_recipient_set(vec![Recipient {
            id,
            comment: Some("line1\nline2".into()),
            wrap: None,
        }]);
        assert!(matches!(doc.to_bytes(), Err(Error::Malformed(_))));
    }

    #[test]
    fn non_utf8_metadata_rejected() {
        // A non-UTF-8 metadata body must be rejected, not lossily decoded, so
        // the Rust and Go parsers agree on the same input (#210).
        let raw = b"---\n# \xff\xfe not utf8\n! pigpen-v1\n---\n";
        assert!(Document::parse(raw).is_err());
    }

    // --- cross-language interop vectors (piggy#210) ----------------------
    //
    // These byte-exact wire vectors are SHARED with the Go impl's
    // pigpen_test.go (identical hex — keep the two copies in lockstep).
    // INTEROP_SECRET is a fixed x25519 recipient; SEALED_BY_RUST and
    // SEALED_BY_GO are the same plaintext sealed to it by each impl (they
    // differ only in their ephemeral keys); RECIPIENT_SET is a payload-less
    // set that both impls serialize byte-identically. Each impl opens BOTH
    // sealed vectors, proving mutual read/decrypt compatibility. Regenerate
    // after a wire-format change with a throwaway test that panics with
    // hex::encode(...) (see this file's git history / #210).
    const INTEROP_SECRET: &str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const INTEROP_PLAINTEXT: &[u8] = b"pigpen cross-language interop vector";
    const SEALED_BY_RUST: &str = "2d2d2d0a2d2070696767792d726563697069656e742d7631406167655f7832353531395f7075622d7137336865307135797a6675336436346d736433703672766b736e72776a6b3364323539386d67746d6c717439777264723337713076646d6565203c2070696770656e2d777261702d76314070696770656e5f777261705f7832353531392d6339776d35336d61706c656b3970717036746e63307a71787333646c636a77336e6c64336436376d7965763573796b616e676332797a6a65353577646b6e36793936656d3763386b36787a3632736368673976797a6b773766617233757566306373366a3637677570656e397a0a212070696770656e2d76314070696770656e5f6865616465725f6d61632d673567656b6a347038653430656c346b6c377a6679746734753767687334736b6468716e333332727a37733578307265633571733771666430720a2d2d2d0a0ac7f53412ca8bc1b9f172e5f324bf00cd58cd1e0abde0f3f63e8645efcdefc224406b9b225588ba8f25ddac4c4b674156f4fb241ca70c8a94282f6c7bdcda5129190b460a";
    const SEALED_BY_GO: &str = "2d2d2d0a2d2070696767792d726563697069656e742d7631406167655f7832353531395f7075622d7137336865307135797a6675336436346d736433703672766b736e72776a6b3364323539386d67746d6c717439777264723337713076646d6565203c2070696770656e2d777261702d76314070696770656e5f777261705f7832353531392d34673772716e67776e30386b6368306c787a7732397074797435636d72757339787968767839756530386573396463656433736d6479713879783061656761677a377a7a767a74323034333779343366707a7a7077633767356a35393267713965366d6e7936676161773735670a212070696770656e2d76314070696770656e5f6865616465725f6d61632d6c687a686b7639757165336a737534366b7764717874346737343974676d6d647272737867666737756835716b38676773657a737268676832750a2d2d2d0a0a53f7272c5a9f2895feb7b1992c5c51b8bfe1b06b422e934a43a6ed153cf1524631a96dbed8493519836e1fe8748afa9e9afe18eef52d869f00be1e0c9ad051f05df3aae4";
    const RECIPIENT_SET: &str = "2d2d2d0a232073686172656420696e7465726f7020766563746f720a2d2070696767792d726563697069656e742d7631406167655f7832353531395f7075622d7137336865307135797a6675336436346d736433703672766b736e72776a6b3364323539386d67746d6c717439777264723337713076646d6565202023206c6170746f70203c206261636b75700a212070696770656e2d76310a2d2d2d0a";

    fn interop_identity() -> X25519Identity {
        let secret = hex::decode(INTEROP_SECRET).unwrap();
        let sec: [u8; 32] = secret.clone().try_into().unwrap();
        let sk = x25519_dalek::StaticSecret::from(sec);
        let public = x25519_dalek::PublicKey::from(&sk).as_bytes().to_vec();
        X25519Identity { public, secret }
    }

    #[test]
    fn interop_opens_both_impls_sealed_vectors() {
        let idents = [interop_identity()];
        for (label, hexv) in [("rust", SEALED_BY_RUST), ("go", SEALED_BY_GO)] {
            let wire = hex::decode(hexv).unwrap();
            let doc = Document::parse(&wire).unwrap();
            let got = doc
                .open(None, &idents)
                .unwrap_or_else(|e| panic!("opening {label}-sealed vector: {e:?}"));
            assert_eq!(
                got, INTEROP_PLAINTEXT,
                "plaintext from {label}-sealed vector"
            );
        }
    }

    #[test]
    fn interop_recipient_set_vector_matches() {
        let wire = hex::decode(RECIPIENT_SET).unwrap();
        let doc = Document::parse(&wire).unwrap();
        assert_eq!(doc.recipients.len(), 1);
        assert_eq!(doc.description.as_deref(), Some("shared interop vector"));
        assert_eq!(
            doc.recipients[0].comment.as_deref(),
            Some("laptop < backup")
        );
        // Re-serialization is byte-identical to the shared vector — the exact
        // bytes the Go impl produces (verified equal when the vector was
        // captured), so the deterministic recipient-set face round-trips
        // identically across implementations.
        assert_eq!(hex::encode(doc.to_bytes().unwrap()), RECIPIENT_SET);
    }

    #[test]
    fn pointer_round_trips_kind_and_locator() {
        let ptr = Pointer {
            kind: "papi-http".into(),
            locator: "https://example.com".into(),
        };
        let bytes = ptr.to_bytes().unwrap();
        let parsed = Pointer::parse(&bytes).unwrap();
        assert_eq!(parsed.kind, "papi-http");
        assert_eq!(parsed.locator, "https://example.com");
    }

    #[test]
    fn pointer_wire_shape_matches_rfc0008() {
        let ptr = Pointer {
            kind: "papi-http".into(),
            locator: "https://example.com".into(),
        };
        let bytes = ptr.to_bytes().unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "---\n- kind=\"papi-http\"\n- locator=\"https://example.com\"\n! pigpen-pointer-v1\n---\n"
        );
    }

    #[test]
    fn pointer_parse_rejects_recipient_set_type() {
        let raw = b"---\n! pigpen-v1\n---\n";
        assert!(Pointer::parse(raw).is_err());
    }

    #[test]
    fn pointer_parse_rejects_missing_locator() {
        let raw = b"---\n- kind=\"papi-http\"\n! pigpen-pointer-v1\n---\n";
        assert!(Pointer::parse(raw).is_err());
    }
}
