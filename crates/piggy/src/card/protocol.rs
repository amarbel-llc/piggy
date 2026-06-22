//! The management interaction protocol (RFC 0006 §2–§3): the serde payload
//! types and the [`Frontend`] trait.
//!
//! These are the **single** source of truth for both bindings. The in-process
//! tty frontend ([`super::frontend`]) and the JSON-RPC frontend
//! ([`super::frontend::jsonrpc`]) both speak in terms of these types, so the
//! two paths cannot diverge — the wire shape (RFC 0006 §4) is exactly the serde
//! representation of these structs.
//!
//! An *operation* (e.g. the provisioning engine) drives a card and, whenever it
//! needs human input, issues an interaction request through a `&mut dyn
//! Frontend` and blocks for the response; it MAY also emit non-blocking
//! `progress`/`completed` notifications. The trait is binding-agnostic: the
//! engine never knows whether a tty or a remote TUI is on the other side.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The protocol version string sent in the `initialize` handshake (RFC 0006
/// §4.3). A frontend MUST reject an unknown major.
pub const PROTOCOL_VERSION: &str = "piggy-mgmt/1";

/// Structured card identity (RFC 0006 §2.1). Carried with every card-scoped
/// request so a frontend can render *which* card the input is for — the
/// piggy#195 mis-identification guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardId {
    /// 32 uppercase hex chars; all-zeros means an uninitialized card.
    pub guid: String,
    /// YubiKey factory serial; omitted when unavailable.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub serial: Option<u32>,
    /// The relevant slot cert's Subject CN, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cn: Option<String>,
}

impl CardId {
    /// The shortest human-distinguishing label (RFC 0006 §2.1: serial when
    /// present, else the short GUID), for a one-line prompt.
    pub fn short_label(&self) -> String {
        match self.serial {
            Some(s) => format!("serial {s}"),
            None => {
                let short: String = self.guid.chars().take(8).collect();
                format!("card {short}…")
            }
        }
    }
}

/// Which secret a [`SecretRequest`] is asking for (RFC 0006 §2.2). Serializes to
/// the wire `snake_case` tokens (`current_pin`, `new_pin`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    CurrentPin,
    NewPin,
    ConfirmNewPin,
    CurrentPuk,
    NewPuk,
    ConfirmNewPuk,
    ManagementKey,
    Generic,
}

/// Request a PIN, PUK, or management-key value (RFC 0006 §2.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRequest {
    pub kind: SecretKind,
    /// Human-readable fallback rendering (what a tty/askpass shows).
    pub prompt: String,
    /// Present for card-scoped secrets.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub card: Option<CardId>,
    /// PIV slot id, e.g. `"9a"`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub slot: Option<String>,
    /// Remaining tries before lockout, when known.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attempts_remaining: Option<u32>,
    /// Operation-specific context the frontend renders alongside the card
    /// identity — e.g. `show-batch`'s "decrypt 5 secrets: a, b, c" telling the
    /// operator what they are authorizing. Distinct from `prompt` (the verb)
    /// and `card` (the structured identity): a free-text note appended to a
    /// card-scoped prompt without displacing the #195 card naming.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub detail: Option<String>,
}

/// Choose a management-key source on provision (RFC 0006 §2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MgmtKeyRequest {
    pub prompt: String,
    pub card: CardId,
}

/// The operator's management-key choice (RFC 0006 §2.3). Serializes as
/// `{"source": …}` with `hex` carrying the supplied key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum MgmtKeyChoice {
    /// Keep the factory default management key.
    Default,
    /// Use the operator-supplied hex-encoded key.
    Hex { key: String },
    /// Generate and set a new random key.
    Random,
}

/// A yes/no decision (RFC 0006 §2.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmRequest {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub default: Option<bool>,
}

/// The `confirm` response payload (RFC 0006 §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmResponse {
    pub confirmed: bool,
}

/// Whether a candidate card is already provisioned or still uninitialized
/// (RFC 0006 §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardState {
    Provisioned,
    Uninitialized,
}

/// One candidate in a [`CardSelectRequest`] (RFC 0006 §2.5): a [`CardId`]
/// flattened together with its `state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardCandidate {
    #[serde(flatten)]
    pub card: CardId,
    pub state: CardState,
}

/// Choose among candidate cards (RFC 0006 §2.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardSelectRequest {
    pub reason: String,
    pub candidates: Vec<CardCandidate>,
}

/// The `card_select` response payload (RFC 0006 §2.5). `guid` MUST equal one
/// candidate's guid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardSelectResponse {
    pub guid: String,
}

/// A progress notification (RFC 0006 §2.6) — no response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressEvent {
    /// Machine token, e.g. `"generate-9d"`, `"write-cert"`.
    pub step: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub current: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub total: Option<u32>,
}

/// Terminal status for [`CompletedEvent`] (RFC 0006 §2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletedStatus {
    Ok,
    Error,
}

/// A terminal completion notification (RFC 0006 §2.7) — no response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletedEvent {
    pub status: CompletedStatus,
    /// Operation-specific result, e.g. `{"guid": …}`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub summary: Option<serde_json::Value>,
    /// Present when `status == Error`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

/// An error returned by a [`Frontend`] interaction (RFC 0006 §4.4).
#[derive(Debug, thiserror::Error)]
pub enum FrontendError {
    /// The operator declined or cancelled (JSON-RPC `-32010`). The engine MUST
    /// treat this as an abort and unwind without retrying.
    #[error("interaction declined: {0}")]
    Declined(String),
    /// The channel failed mid-operation (closed, I/O error). Aborts the
    /// operation as an error.
    #[error("transport error: {0}")]
    Transport(String),
    /// A malformed or unexpected message on the channel.
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// The interaction surface an operation needs *from* a frontend (RFC 0006 §3).
///
/// One trait, two bindings: the default in-process tty frontend and the
/// JSON-RPC frontend both implement it, and the request/response types are the
/// same serde types used on the wire so the paths cannot diverge. This
/// generalizes the PIN-only [`crate::card_oracle::PinSupplier`] closure — a
/// `request_secret` of `kind: CurrentPin` is the migration of that seam.
pub trait Frontend {
    /// Request a PIN/PUK/management-key value. The returned secret is
    /// sensitive: the engine MUST NOT log it and MUST zeroize it after use. A
    /// frontend that won't supply it returns [`FrontendError::Declined`].
    fn request_secret(&mut self, req: SecretRequest) -> Result<Zeroizing<String>, FrontendError>;

    /// Ask which management-key source to use on provision.
    fn request_mgmt_key(&mut self, req: MgmtKeyRequest) -> Result<MgmtKeyChoice, FrontendError>;

    /// Ask a yes/no question.
    fn confirm(&mut self, req: ConfirmRequest) -> Result<bool, FrontendError>;

    /// Choose among candidate cards; returns the chosen card's guid (which MUST
    /// equal one candidate's guid).
    fn select_card(&mut self, req: CardSelectRequest) -> Result<String, FrontendError>;

    /// Emit a non-blocking progress notification.
    fn progress(&mut self, ev: ProgressEvent);

    /// Emit the terminal completion notification.
    fn completed(&mut self, ev: CompletedEvent);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T) -> serde_json::Value
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_value(value).unwrap();
        let back: T = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(&back, value, "round-trip must be lossless");
        json
    }

    #[test]
    fn card_id_omits_absent_optional_fields() {
        let id = CardId {
            guid: "2835305C6024B3255557BF6901443404".into(),
            serial: None,
            cn: None,
        };
        let json = roundtrip(&id);
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("guid"));
        assert!(!obj.contains_key("serial"), "absent serial omitted");
        assert!(!obj.contains_key("cn"), "absent cn omitted");
    }

    #[test]
    fn card_id_short_label_prefers_serial_then_guid() {
        let with_serial = CardId {
            guid: "AABBCCDD00000000000000000000FFFF".into(),
            serial: Some(15909078),
            cn: None,
        };
        assert_eq!(with_serial.short_label(), "serial 15909078");
        let without = CardId {
            guid: "AABBCCDD00000000000000000000FFFF".into(),
            serial: None,
            cn: None,
        };
        assert_eq!(without.short_label(), "card AABBCCDD…");
    }

    #[test]
    fn secret_kind_serializes_to_wire_tokens() {
        assert_eq!(
            serde_json::to_value(SecretKind::CurrentPin).unwrap(),
            serde_json::json!("current_pin")
        );
        assert_eq!(
            serde_json::to_value(SecretKind::ConfirmNewPuk).unwrap(),
            serde_json::json!("confirm_new_puk")
        );
        assert_eq!(
            serde_json::to_value(SecretKind::ManagementKey).unwrap(),
            serde_json::json!("management_key")
        );
    }

    #[test]
    fn secret_request_round_trips_with_card() {
        let req = SecretRequest {
            kind: SecretKind::CurrentPin,
            prompt: "Enter PIN".into(),
            card: Some(CardId {
                guid: "2835305C6024B3255557BF6901443404".into(),
                serial: Some(15909078),
                cn: Some("piv-auth@2835305C".into()),
            }),
            slot: Some("9a".into()),
            attempts_remaining: Some(3),
            detail: Some("decrypt 5 secrets: a, b, c".into()),
        };
        roundtrip(&req);
    }

    #[test]
    fn mgmt_key_choice_tags_by_source() {
        assert_eq!(
            serde_json::to_value(MgmtKeyChoice::Default).unwrap(),
            serde_json::json!({"source": "default"})
        );
        assert_eq!(
            serde_json::to_value(MgmtKeyChoice::Random).unwrap(),
            serde_json::json!({"source": "random"})
        );
        assert_eq!(
            serde_json::to_value(MgmtKeyChoice::Hex { key: "0102".into() }).unwrap(),
            serde_json::json!({"source": "hex", "key": "0102"})
        );
        // And the reverse, since the wire MUST parse back.
        let parsed: MgmtKeyChoice =
            serde_json::from_value(serde_json::json!({"source": "hex", "key": "ABCD"})).unwrap();
        assert_eq!(parsed, MgmtKeyChoice::Hex { key: "ABCD".into() });
    }

    #[test]
    fn card_candidate_flattens_card_id_with_state() {
        let cand = CardCandidate {
            card: CardId {
                guid: "0".repeat(32),
                serial: None,
                cn: None,
            },
            state: CardState::Uninitialized,
        };
        let json = roundtrip(&cand);
        let obj = json.as_object().unwrap();
        // The CardId is flattened: guid sits at the top level alongside state.
        assert!(obj.contains_key("guid"));
        assert_eq!(
            obj.get("state").unwrap(),
            &serde_json::json!("uninitialized")
        );
    }

    #[test]
    fn progress_and_completed_round_trip() {
        roundtrip(&ProgressEvent {
            step: "generate-9d".into(),
            message: "Generating key-management key".into(),
            current: Some(2),
            total: Some(6),
        });
        roundtrip(&CompletedEvent {
            status: CompletedStatus::Ok,
            summary: Some(serde_json::json!({"guid": "ABCD"})),
            error: None,
        });
        roundtrip(&CompletedEvent {
            status: CompletedStatus::Error,
            summary: None,
            error: Some("aborted".into()),
        });
    }
}
