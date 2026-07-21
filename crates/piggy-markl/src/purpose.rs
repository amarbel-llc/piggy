//! Purpose ID registry.
//!
//! Mirrors `go/internal/bravo/markl/purposes.go` plus the
//! `validatePurposeAndFormatId` check from `id_blech_coding.go`.
//! Prototype scope: only the purposes piggy uses or expects to see in
//! the wild are enumerated; anything else parses as `Other` and is
//! carried opaquely at decode (madder#255, RFC 0002 §6.6). The
//! enumerated dodder-* purposes keep strict (purpose, format)
//! validation; a `piggy-ids` file carrying a non-piggy purpose is
//! still rejected at the piggy-ids layer regardless.

use thiserror::Error;

use crate::format::FormatId;

/// Purpose ID values that piggy understands. Other purposes parse as
/// `Other(String)` and are carried opaquely through decode/encode
/// (madder#255, RFC 0002 §6.6) — `Id::new` skips the compatibility
/// check for them. `validate_format` itself remains a strict semantic
/// predicate: it still returns `Incompatible` for `Other`, since piggy
/// can't reason about formats for purposes it didn't enumerate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PurposeId {
    /// `piggy-recipient-v1` — piggy 2.x recipient pubkey. **Reserved
    /// by piggy** in RFC 0002 §6.3 (drafted in piggy at madder#150).
    /// Accepts two formats:
    ///   * `pivy_ecdh_p256_pub` — PIV slot 9D (Key Management, ECDH
    ///     over NIST P-256). The piggy 1.x → 2.x cutover format.
    ///   * `age_x25519_pub` — age v1 X25519 recipient pubkey. Same
    ///     purpose, different cryptographic family. Wire-format
    ///     integration is in progress (see piggy RFC 0004); markl-level
    ///     parsing already accepts age recipients so `piggy-ids` files
    ///     declaring them validate cleanly.
    PiggyRecipientV1,
    /// `piggy-piv_auth-v1` — public key from PIV slot 9A (PIV
    /// Authentication). Accepts `ssh_ecdsa_nistp256_pub`,
    /// `ssh_ed25519_pub`, and `ssh_ecdsa_nistp384_pub` (#86); RSA is
    /// not yet enumerated in `piggy list` output and will need a new
    /// compatible (variable-length) format ID.
    PiggyPivAuthV1,
    /// `piggy-piv_sig-v1` — public key from PIV slot 9C (Digital
    /// Signature). Same constraint as `PiggyPivAuthV1`.
    PiggyPivSigV1,
    /// `piggy-piv_card_auth-v1` — public key from PIV slot 9E (Card
    /// Authentication). Same constraint as `PiggyPivAuthV1`.
    PiggyPivCardAuthV1,
    /// `papi-doc-sig-v1` — detached signature over a PAPI document's
    /// canonical (RFC 8785 JCS) signing input, per amarbel-llc/papi
    /// RFC-0001 §10. Produced by `piggy papi sign` from a PIV slot-9A
    /// key. Accepts only `ecdsa_p256_sig` (raw 64-byte r‖s P-256
    /// signature). Registered in madder RFC-0002 §6.1 (commit
    /// `b852d42`) and mirrored here; piggy#183 re-homes the registry
    /// to piggy as the source of truth.
    PapiDocSigV1,
    /// `dodder-blob-digest-sha256-v1` — blob content hash. Piggy does
    /// not produce these, but accepts them for round-trip purposes.
    DodderBlobDigestSha256V1,
    /// `dodder-object-digest-v2` — object metadata hash.
    DodderObjectDigestV2,
    /// `dodder-object-sig-v2` — object signature.
    DodderObjectSigV2,
    /// `dodder-repo-public_key-v1` — repository public key.
    DodderRepoPublicKeyV1,
    /// `dodder-repo-private_key-v1` — repository private key.
    DodderRepoPrivateKeyV1,
    /// Any other syntactically-valid purpose ID. Parses but cannot
    /// validate format compatibility.
    Other(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("format id {format:?} is not compatible with purpose {purpose:?}")]
pub struct Incompatible {
    pub purpose: PurposeId,
    pub format: FormatId,
}

/// Purpose-slot violations of RFC 0011 §2.1 / §2.2.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PurposeError {
    /// A purpose VALUE containing the literal `@`, banned under any
    /// circumstance — quoted or not — because `@` is markl's own
    /// purpose/digest join (§2.2).
    #[error(
        "invalid purpose id {purpose:?}: contains '@', which a purpose must not contain under any circumstance, quoted or not"
    )]
    ContainsAt { purpose: String },
    /// A BARE purpose slot outside §2.1's ASCII inclusion set
    /// `[a-zA-Z0-9_/-]`. Not a dead end: such a purpose is still legal,
    /// it just has to be spelled with the quoted alternative (ruling 2).
    /// `ch` is the first offending character, or `None` for an empty
    /// slot.
    #[error(
        "invalid bare purpose {purpose:?}: contains {ch:?}, which is outside the bare charset [a-zA-Z0-9_/-]; spell it quoted instead"
    )]
    InvalidBarePurpose { purpose: String, ch: Option<char> },
    /// A purpose slot that opens with a quote character but does not
    /// close with the matching one (§2.1's `quoted-string`).
    #[error(
        "unterminated quoted purpose {purpose:?}: opens with a quote but does not close with it"
    )]
    UnterminatedQuoted { purpose: String },
}

// ---------------------------------------------------------------------
// Purpose-slot quoting, RFC 0011 §2.1 / §2.2 (linenisgreat/madder#273
// rulings 1 and 2). Mirrors `go/internal/bravo/markl/purpose_quoting.go`.
//
// The bare purpose production is the ASCII inclusion set [a-zA-Z0-9_/-]
// (`purpose_is_bare_expressible`). Ruling 2 adds a quoted alternative so
// that purposes outside that set remain spellable — a Unicode-named
// object is pinned quoted, `"café/naïve"@blake2b256-...`, rather than
// not at all.
//
// The quoting rules are Doddish, matching 0014-trellis.peg's String
// production verbatim so a markl-id embedded in trellis quotes
// identically: double or single quotes; backslash escapes \n \t \r \a
// \b \f \v, \" and \\ round-trip; an unknown escape passes the
// following character through unchanged.
//
// Only the PURPOSE slot is quoted. The digest slot stays bare and
// structurally intact (§2.2) so tooling that operates on the digest
// independently can locate it without first undoing any quoting.
// ---------------------------------------------------------------------

const PURPOSE_QUOTE_DOUBLE: char = '"';
const PURPOSE_QUOTE_SINGLE: char = '\'';

/// Whether `purpose_id` can be written in RFC 0011 §2.1's BARE
/// `purpose` production — the ASCII inclusion set `[a-zA-Z0-9_/-]`.
///
/// NARROWED (linenisgreat/madder#273 ruling 1) from the former "any
/// Unicode code point except `@` and whitespace". The inclusion list is
/// deliberate and is NOT a transcription of trellis's `Ident`, which is
/// exclusion-style; inclusion keeps a bare markl-id safe to paste into
/// shell, URL, and log contexts where a bare `(`, `;`, or `&` is a
/// hazard. Consequence: Purpose ⊂ trellis Ident (RFC 0011 §7.4).
pub fn purpose_is_bare_expressible(purpose_id: &str) -> bool {
    !purpose_id.is_empty()
        && purpose_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '/' || c == '-')
}

/// Enforce the one constraint RFC 0011 places on a purpose VALUE
/// regardless of how it is spelled: it MUST NOT contain the literal
/// `@` (§2.2). `@` is markl's own purpose/digest join, and admitting it
/// — even inside quotes — would reintroduce the ambiguity the
/// first-`@` decode rule exists to avoid.
///
/// Everything else is permitted at the VALUE level, because ruling 2's
/// quoted alternative can spell it: whitespace, punctuation outside the
/// bare inclusion set, and non-ASCII all round-trip through the quoted
/// form.
pub fn validate_purpose_charset(purpose_id: &str) -> Result<(), PurposeError> {
    if purpose_id.contains('@') {
        return Err(PurposeError::ContainsAt {
            purpose: purpose_id.to_string(),
        });
    }
    Ok(())
}

/// Render a purpose VALUE as its canonical wire spelling: bare when the
/// bare production can express it, quoted otherwise.
pub fn spell_purpose(purpose_id: &str) -> String {
    if purpose_is_bare_expressible(purpose_id) {
        purpose_id.to_string()
    } else {
        quote_purpose(purpose_id)
    }
}

/// Render `purpose_id` in the double-quoted form, escaping per the
/// Doddish rules. Always quotes, even when the bare form would do —
/// `spell_purpose` is the canonical-spelling entry point.
pub fn quote_purpose(purpose_id: &str) -> String {
    let mut out = String::with_capacity(purpose_id.len() * 2 + 2);
    out.push(PURPOSE_QUOTE_DOUBLE);
    for c in purpose_id.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\u{b}' => out.push_str("\\v"),
            other => out.push(other),
        }
    }
    out.push(PURPOSE_QUOTE_DOUBLE);
    out
}

/// Reverse `spell_purpose` for a wire-form purpose slot.
///
/// A slot that opens with a quote character MUST close with the same
/// one; the interior is unescaped per the Doddish rules. A slot that
/// does not open with a quote character is a BARE purpose and MUST
/// satisfy the bare inclusion set — this is where ruling 1's narrowing
/// bites on the decode path, rejecting the Unicode and punctuation
/// shapes the pre-#273 grammar admitted unquoted.
pub fn unquote_purpose(slot: &str) -> Result<String, PurposeError> {
    let Some(first) = slot.chars().next() else {
        return Err(PurposeError::InvalidBarePurpose {
            purpose: String::new(),
            ch: None,
        });
    };

    if first != PURPOSE_QUOTE_DOUBLE && first != PURPOSE_QUOTE_SINGLE {
        if !purpose_is_bare_expressible(slot) {
            return Err(invalid_bare_purpose(slot));
        }
        return Ok(slot.to_string());
    }

    let interior = slot
        .strip_prefix(first)
        .and_then(|rest| rest.strip_suffix(first))
        .ok_or_else(|| PurposeError::UnterminatedQuoted {
            purpose: slot.to_string(),
        })?;

    Ok(unescape_purpose_interior(interior))
}

/// Apply the Doddish escape rules to the text between a quoted
/// purpose's delimiters. A trailing lone backslash is written through
/// literally rather than eating the closing quote; the closing quote was
/// already removed by the caller, so there is nothing left to escape.
fn unescape_purpose_interior(interior: &str) -> String {
    if !interior.contains('\\') {
        return interior.to_string();
    }

    let mut out = String::with_capacity(interior.len());
    let mut chars = interior.chars();

    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }

        let Some(escaped) = chars.next() else {
            out.push('\\');
            break;
        };

        match escaped {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            // Unknown escape: pass the following character through
            // unchanged, per the Doddish rule. This is what makes \"
            // and \\ round-trip without needing their own cases.
            other => out.push(other),
        }
    }

    out
}

/// Report the first character of `slot` that the bare production
/// rejects, so the error names the offending character rather than just
/// the whole slot.
fn invalid_bare_purpose(slot: &str) -> PurposeError {
    let ch = slot
        .chars()
        .find(|c| !purpose_is_bare_expressible(&c.to_string()));
    PurposeError::InvalidBarePurpose {
        purpose: slot.to_string(),
        ch,
    }
}

impl PurposeId {
    /// Wire-format name as it appears before the `@` separator.
    pub fn as_str(&self) -> &str {
        match self {
            PurposeId::PiggyRecipientV1 => "piggy-recipient-v1",
            PurposeId::PiggyPivAuthV1 => "piggy-piv_auth-v1",
            PurposeId::PiggyPivSigV1 => "piggy-piv_sig-v1",
            PurposeId::PiggyPivCardAuthV1 => "piggy-piv_card_auth-v1",
            PurposeId::PapiDocSigV1 => "papi-doc-sig-v1",
            PurposeId::DodderBlobDigestSha256V1 => "dodder-blob-digest-sha256-v1",
            PurposeId::DodderObjectDigestV2 => "dodder-object-digest-v2",
            PurposeId::DodderObjectSigV2 => "dodder-object-sig-v2",
            PurposeId::DodderRepoPublicKeyV1 => "dodder-repo-public_key-v1",
            PurposeId::DodderRepoPrivateKeyV1 => "dodder-repo-private_key-v1",
            PurposeId::Other(s) => s.as_str(),
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "piggy-recipient-v1" => PurposeId::PiggyRecipientV1,
            "piggy-piv_auth-v1" => PurposeId::PiggyPivAuthV1,
            "piggy-piv_sig-v1" => PurposeId::PiggyPivSigV1,
            "piggy-piv_card_auth-v1" => PurposeId::PiggyPivCardAuthV1,
            "papi-doc-sig-v1" => PurposeId::PapiDocSigV1,
            "dodder-blob-digest-sha256-v1" => PurposeId::DodderBlobDigestSha256V1,
            "dodder-object-digest-v2" => PurposeId::DodderObjectDigestV2,
            "dodder-object-sig-v2" => PurposeId::DodderObjectSigV2,
            "dodder-repo-public_key-v1" => PurposeId::DodderRepoPublicKeyV1,
            "dodder-repo-private_key-v1" => PurposeId::DodderRepoPrivateKeyV1,
            other => PurposeId::Other(other.to_string()),
        }
    }

    /// Boolean form of `validate_format` — same predicate, no
    /// `Incompatible` allocation. Use this when set membership is
    /// the question rather than a parser error.
    pub fn accepts(&self, format: FormatId) -> bool {
        self.validate_format(format).is_ok()
    }

    /// Verify that `format` is one of the formats this purpose
    /// constrains itself to. For `Other`, conservatively rejects
    /// every format — piggy doesn't know the registry's rules for
    /// purposes it didn't enumerate. Decode surfaces (`Id::new`,
    /// `Id::parse`) deliberately skip this check for `Other` so
    /// unknown purposes round-trip opaquely (madder#255, RFC 0002
    /// §6.6); this predicate answers the semantic question only.
    pub fn validate_format(&self, format: FormatId) -> Result<(), Incompatible> {
        let ok = match self {
            PurposeId::PiggyRecipientV1 => {
                matches!(format, FormatId::PivyEcdhP256Pub | FormatId::AgeX25519Pub)
            }
            PurposeId::PiggyPivAuthV1
            | PurposeId::PiggyPivSigV1
            | PurposeId::PiggyPivCardAuthV1 => {
                matches!(
                    format,
                    FormatId::SshEcdsaNistp256Pub
                        | FormatId::SshEd25519Pub
                        | FormatId::SshEcdsaNistp384Pub
                )
            }
            PurposeId::PapiDocSigV1 => matches!(format, FormatId::EcdsaP256Sig),
            PurposeId::DodderBlobDigestSha256V1 => {
                matches!(format, FormatId::Sha256 | FormatId::Blake2b256)
            }
            PurposeId::DodderObjectDigestV2 => {
                matches!(format, FormatId::Sha256 | FormatId::Blake2b256)
            }
            PurposeId::DodderObjectSigV2 => {
                matches!(format, FormatId::Ed25519Sig | FormatId::EcdsaP256Sig)
            }
            PurposeId::DodderRepoPublicKeyV1 => {
                matches!(format, FormatId::Ed25519Pub | FormatId::EcdsaP256Pub)
            }
            PurposeId::DodderRepoPrivateKeyV1 => matches!(
                format,
                FormatId::Ed25519Sec | FormatId::Ed25519Ssh | FormatId::EcdsaP256Ssh
            ),
            PurposeId::Other(_) => false,
        };
        if ok {
            Ok(())
        } else {
            Err(Incompatible {
                purpose: self.clone(),
                format,
            })
        }
    }
}

impl core::fmt::Display for PurposeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn piggy_piv_purposes_accept_only_ssh_pub_formats() {
        for p in [
            PurposeId::PiggyPivAuthV1,
            PurposeId::PiggyPivSigV1,
            PurposeId::PiggyPivCardAuthV1,
        ] {
            assert!(
                p.validate_format(FormatId::SshEcdsaNistp256Pub).is_ok(),
                "{p:?} should accept ssh_ecdsa_nistp256_pub"
            );
            assert!(
                p.validate_format(FormatId::SshEd25519Pub).is_ok(),
                "{p:?} should accept ssh_ed25519_pub (#86)"
            );
            assert!(
                p.validate_format(FormatId::SshEcdsaNistp384Pub).is_ok(),
                "{p:?} should accept ssh_ecdsa_nistp384_pub (#86)"
            );
            assert!(
                p.validate_format(FormatId::PivyEcdhP256Pub).is_err(),
                "{p:?} should reject pivy_ecdh_p256_pub — that's a recipient format"
            );
            assert!(
                p.validate_format(FormatId::EcdsaP256Pub).is_err(),
                "{p:?} should reject ecdsa_p256_pub — distinct from ssh form"
            );
            assert!(
                p.validate_format(FormatId::Ed25519Pub).is_err(),
                "{p:?} should reject ed25519_pub — that's the dodder repo-key form"
            );
        }
    }

    #[test]
    fn piggy_recipient_v1_accepts_pivy_and_age_recipient_formats() {
        let p = PurposeId::PiggyRecipientV1;
        assert!(p.validate_format(FormatId::PivyEcdhP256Pub).is_ok());
        assert!(p.validate_format(FormatId::AgeX25519Pub).is_ok());
        // age_x25519_sec is an identity, not a recipient.
        assert!(p.validate_format(FormatId::AgeX25519Sec).is_err());
        assert!(
            p.validate_format(FormatId::SshEcdsaNistp256Pub).is_err(),
            "PiggyRecipientV1 should reject the SSH format — that's for piggy-piv_* purposes"
        );
        assert!(p.validate_format(FormatId::Sha256).is_err());
        assert!(p.validate_format(FormatId::EcdsaP256Pub).is_err());
    }

    #[test]
    fn papi_doc_sig_v1_accepts_only_ecdsa_p256_sig() {
        let p = PurposeId::PapiDocSigV1;
        // Per amarbel-llc/papi RFC-0001 §10 + madder RFC-0002 §6.1:
        // the only compatible format is the raw 64-byte r‖s P-256 sig.
        assert!(p.validate_format(FormatId::EcdsaP256Sig).is_ok());
        assert!(
            p.validate_format(FormatId::Ed25519Sig).is_err(),
            "papi-doc-sig-v1 has no ed25519 document-signing path"
        );
        assert!(
            p.validate_format(FormatId::SshEcdsaNistp256Pub).is_err(),
            "the slot-9A key is the signer, not a doc-sig format"
        );
        assert!(p.validate_format(FormatId::EcdsaP256Pub).is_err());
    }

    #[test]
    fn dodder_blob_digest_sha256_v1_accepts_both_sha256_and_blake2b256() {
        let p = PurposeId::DodderBlobDigestSha256V1;
        assert!(p.validate_format(FormatId::Sha256).is_ok());
        assert!(p.validate_format(FormatId::Blake2b256).is_ok());
        assert!(p.validate_format(FormatId::Ed25519Pub).is_err());
    }

    #[test]
    fn other_purpose_rejects_every_format() {
        let p = PurposeId::parse("future-purpose-v0");
        assert!(matches!(p, PurposeId::Other(_)));
        for f in [
            FormatId::PivyEcdhP256Pub,
            FormatId::Sha256,
            FormatId::Ed25519Sig,
        ] {
            assert!(p.validate_format(f).is_err(), "should reject {f}");
        }
    }

    #[test]
    fn bare_expressible_is_the_ascii_inclusion_set() {
        for ok in [
            "a",
            "A",
            "0",
            "_",
            "/",
            "-",
            "one/uno",
            "piggy-recipient-v1",
        ] {
            assert!(purpose_is_bare_expressible(ok), "{ok:?} should be bare");
        }
        // NARROWED by madder#273 ruling 1: the former rule was "any
        // Unicode code point except '@' and whitespace", which admitted
        // every one of these bare.
        for not_ok in ["", "my thing", "café", "a.b", "a;b", "a(b", "naïve"] {
            assert!(
                !purpose_is_bare_expressible(not_ok),
                "{not_ok:?} should NOT be bare"
            );
        }
    }

    #[test]
    fn validate_purpose_charset_bans_only_at() {
        // Everything but '@' is a legal purpose VALUE — it is simply
        // spelled quoted when the bare production can't express it.
        for ok in ["my thing", "café/naïve", "a.b", "a;b"] {
            assert!(validate_purpose_charset(ok).is_ok(), "{ok:?}");
        }
        assert!(matches!(
            validate_purpose_charset("a@b"),
            Err(PurposeError::ContainsAt { .. })
        ));
    }

    #[test]
    fn spell_purpose_quotes_only_when_needed() {
        assert_eq!(spell_purpose("one/uno"), "one/uno");
        assert_eq!(spell_purpose("my thing"), "\"my thing\"");
        assert_eq!(spell_purpose("café/naïve"), "\"café/naïve\"");
        // An empty value is not bare-expressible, so it spells as "".
        assert_eq!(spell_purpose(""), "\"\"");
    }

    #[test]
    fn quote_unquote_round_trips_every_escape() {
        for value in [
            "my thing",
            "café/naïve",
            "back\\slash",
            "double\"quote",
            "single'quote",
            "nl\ntab\tcr\r",
            "bel\u{7}bs\u{8}ff\u{c}vt\u{b}",
        ] {
            let quoted = quote_purpose(value);
            assert_eq!(
                unquote_purpose(&quoted).unwrap(),
                value,
                "round-trip failed for {value:?} (quoted as {quoted:?})"
            );
        }
    }

    #[test]
    fn unquote_accepts_single_quoted_slots() {
        assert_eq!(unquote_purpose("'my thing'").unwrap(), "my thing");
    }

    /// Doddish rule: an UNKNOWN escape passes the following character
    /// through unchanged. This is what makes `\"` and `\\` round-trip
    /// without needing their own decode cases.
    #[test]
    fn unknown_escape_passes_following_char_through() {
        assert_eq!(unquote_purpose("\"a\\zb\"").unwrap(), "azb");
        assert_eq!(unquote_purpose("\"a\\\"b\"").unwrap(), "a\"b");
        assert_eq!(unquote_purpose("\"a\\\\b\"").unwrap(), "a\\b");
        // A trailing lone backslash is written through literally: the
        // closing quote was already removed, so there is nothing left
        // for it to escape.
        assert_eq!(unquote_purpose("\"ab\\\"").unwrap(), "ab\\");
    }

    #[test]
    fn unquote_rejects_unterminated_and_mismatched_quotes() {
        for slot in ["\"abc", "'abc", "\"", "'", "\"abc'", "'abc\""] {
            assert!(
                matches!(
                    unquote_purpose(slot),
                    Err(PurposeError::UnterminatedQuoted { .. })
                ),
                "{slot:?} should be unterminated"
            );
        }
    }

    #[test]
    fn unquote_rejects_bare_slots_outside_the_inclusion_set() {
        assert!(matches!(
            unquote_purpose("café"),
            Err(PurposeError::InvalidBarePurpose { ch: Some('é'), .. })
        ));
        assert!(matches!(
            unquote_purpose("my thing"),
            Err(PurposeError::InvalidBarePurpose { ch: Some(' '), .. })
        ));
        assert!(matches!(
            unquote_purpose(""),
            Err(PurposeError::InvalidBarePurpose { ch: None, .. })
        ));
        assert_eq!(unquote_purpose("one/uno").unwrap(), "one/uno");
    }

    #[test]
    fn round_trip_purpose_names() {
        for p in [
            PurposeId::PiggyRecipientV1,
            PurposeId::PiggyPivAuthV1,
            PurposeId::PiggyPivSigV1,
            PurposeId::PiggyPivCardAuthV1,
            PurposeId::PapiDocSigV1,
            PurposeId::DodderBlobDigestSha256V1,
            PurposeId::DodderObjectDigestV2,
            PurposeId::DodderObjectSigV2,
            PurposeId::DodderRepoPublicKeyV1,
            PurposeId::DodderRepoPrivateKeyV1,
        ] {
            let s = p.as_str().to_string();
            let parsed = PurposeId::parse(&s);
            assert_eq!(parsed, p);
        }
    }
}
