//! The v1 `piggy manage` method handlers (RFC 0007 §5): `card.list`,
//! `card.init`, `sign_bytes`.
//!
//! Each returns `Result<Value, (i64, String)>` — the JSON-RPC *result* object
//! on success, or an `(error-code, message)` pair the dispatch loop ([`super`])
//! turns into a JSON-RPC error response. The two interactive methods take a
//! `&mut dyn Frontend` that the caller has bound to the live connection, so
//! their PIN/confirm/progress requests travel back to the client over the same
//! socket (RFC 0007 §1). These handlers reuse the exact CLI cores —
//! [`crate::card::init_cmd::provision_with_frontend`] and
//! [`crate::sign_core::sign_message`] — so a headless workflow behaves
//! identically to the command line.

use std::path::PathBuf;
use std::process::Command;

use base64::Engine as _;
use serde_json::Value;

use crate::card::RequestBinding;
use crate::card::add_key_cmd::{AddKeyArgs, add_key_with_frontend, openssh_line};
use crate::card::engine::ProvisionError;
use crate::card::init_cmd::{CardSelector, provision_with_frontend};
use crate::card::protocol::{Frontend, FrontendError};
use crate::card::seal::{ManagementKeySealer, SealMode, SealRequest};
use crate::card::slot_policy::SlotPolicies;
use crate::manage::{CARD_OP_FAILED, INTERACTION_DECLINED, INVALID_PARAMS};
use crate::sign_core::{self, SigFormat, SignError};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// `card.init`'s `seal_management_key` (piggy#258): absent, null, or `false`
/// never seals (no interactive offer either — the client drives this path);
/// `true` seals to the default store path; a non-empty string seals there.
fn seal_param(params: &Value) -> Result<SealMode, (i64, String)> {
    match params.get("seal_management_key") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => Ok(SealMode::Never),
        Some(Value::Bool(true)) => Ok(SealMode::Always(None)),
        Some(Value::String(s)) if !s.is_empty() => Ok(SealMode::Always(Some(s.clone()))),
        Some(_) => Err((
            INVALID_PARAMS,
            "card.init: 'seal_management_key' must be a boolean or a non-empty store path"
                .to_string(),
        )),
    }
}

/// `card.init`'s `pin_policy` / `touch_policy`: each an object mapping a slot
/// (`9a`, `9c`, `9d`) to a policy name, overriding the fresh-card default for
/// that slot only. Absent or null keeps every default.
fn slot_policies_param(method: &str, params: &Value) -> Result<SlotPolicies, (i64, String)> {
    type Setter = fn(&mut SlotPolicies, &str, &str) -> Result<(), String>;
    let fields: [(&str, Setter); 2] = [
        ("pin_policy", SlotPolicies::set_pin),
        ("touch_policy", SlotPolicies::set_touch),
    ];
    let mut policies = SlotPolicies::default();
    for (key, set) in fields {
        let overrides = match params.get(key) {
            None | Some(Value::Null) => continue,
            Some(Value::Object(map)) => map,
            Some(_) => {
                return Err((
                    INVALID_PARAMS,
                    format!("{method}: '{key}' must be an object mapping a slot to a policy name"),
                ));
            }
        };
        for (slot, policy) in overrides {
            let policy = policy.as_str().ok_or((
                INVALID_PARAMS,
                format!("{method}: '{key}.{slot}' must be a policy name"),
            ))?;
            set(&mut policies, slot, policy)
                .map_err(|e| (INVALID_PARAMS, format!("{method}: '{key}.{slot}': {e}")))?;
        }
    }
    Ok(policies)
}

/// `card.list` (RFC 0007 §5.1) — enumerate attached PIV cards. Read-only,
/// PIN-free, issues no interactions: shells out to the same `piggy-ids
/// list-all` helper behind `piggy list` (forcing ndjson) and wraps the records
/// as `{ "cards": [ … ] }`. `include_uninitialized` (default true) drops the
/// factory-blank card-level records (piggy#193) when false.
pub fn card_list(params: &Value) -> Result<Value, (i64, String)> {
    let include_uninitialized = params
        .get("include_uninitialized")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let cards: Vec<Value> = enumerate_cards()?
        .into_iter()
        .filter(|r| {
            include_uninitialized || r.get("uninitialized").and_then(Value::as_bool) != Some(true)
        })
        .collect();
    Ok(serde_json::json!({ "cards": cards }))
}

/// Resolve the `piggy-ids` helper the same way the CLI's `piggy list` does
/// (the makeWrapper-set `PIGGY_IDS_PATH`, else a bare PATH lookup), run
/// `list-all --format ndjson`, and parse each line into a JSON value.
fn enumerate_cards() -> Result<Vec<Value>, (i64, String)> {
    let binary = std::env::var_os("PIGGY_IDS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("piggy-ids"));
    let output = Command::new(&binary)
        .args(["list-all", "--format", "ndjson"])
        .output()
        .map_err(|e| (CARD_OP_FAILED, format!("launch {}: {e}", binary.display())))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err((
            CARD_OP_FAILED,
            format!("piggy-ids list-all failed: {}", stderr.trim()),
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut cards = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .map_err(|e| (CARD_OP_FAILED, format!("parse piggy-ids ndjson: {e}")))?;
        cards.push(v);
    }
    Ok(cards)
}

/// `card.init` (RFC 0007 §5.2) — provision a factory-blank card. Issues
/// confirm/secret/mgmt_key/progress interactions through `fe`. Returns
/// `{ "guid": …, "generated_management_key"?: …, "sealed_management_key"?: … }`.
/// A generated random mgmt key is the sensitive result (RFC 0007 §Security),
/// present only when the frontend chose `random` and the key was not sealed;
/// with `seal_management_key` (piggy#258) it is sealed into the password store
/// through `sealer` instead, and the result names the store path. An operator
/// decline (the destructive confirm, or a cancelled prompt) surfaces as
/// `-32010`.
pub fn card_init(
    params: &Value,
    fe: &mut dyn Frontend,
    sealer: &dyn ManagementKeySealer,
) -> Result<Value, (i64, String)> {
    let serial = match params.get("serial") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or((
            INVALID_PARAMS,
            "card.init: 'serial' must be a u32".to_string(),
        ))?),
    };
    // `guid` (hex) / `reader` select a serial-less card; mutually exclusive with
    // `serial` and each other (piggy#256). `from_flags` validates the hex + the
    // exclusivity, so a bad selector is an invalid-params error.
    let guid = params
        .get("guid")
        .and_then(Value::as_str)
        .map(str::to_string);
    let reader = params
        .get("reader")
        .and_then(Value::as_str)
        .map(str::to_string);
    let selector = CardSelector::from_flags(serial, guid, reader, RequestBinding::JsonRpc)
        .map_err(|e| (INVALID_PARAMS, format!("card.init: {e}")))?;
    // Also accept an already-initialized card-in-hand and re-provision it
    // (piggy#204) — default false (factory-blank only).
    let allow_reprovision = params
        .get("allow_reprovision")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let policies = slot_policies_param("card.init", params)?;
    let seal = seal_param(params)?;

    let seal = SealRequest { mode: seal, sealer };
    match provision_with_frontend(selector, allow_reprovision, policies, seal, fe) {
        Ok(outcome) => {
            let mut result = serde_json::json!({
                "guid": outcome.guid,
                "serves_operator_acts": outcome.serves_operator_acts,
            });
            if let Some(key) = &outcome.generated_mgmt_key {
                result["generated_management_key"] = Value::String(key.as_str().to_string());
            }
            if let Some(sealed) = &outcome.sealed_mgmt_key {
                result["sealed_management_key"] = Value::String(sealed.pass_name.clone());
            }
            Ok(result)
        }
        // A declined confirm/prompt is the operator aborting — RFC 0007 §6 -32010.
        Err(ProvisionError::Frontend(FrontendError::Declined(m)))
        | Err(ProvisionError::Aborted(m)) => Err((INTERACTION_DECLINED, m)),
        Err(e) => Err((CARD_OP_FAILED, e.to_string())),
    }
}

/// An optional string param: absent or null is `None`, a string is `Some`,
/// anything else is an invalid-params error.
fn optional_str<'a>(
    method: &str,
    params: &'a Value,
    key: &str,
) -> Result<Option<&'a str>, (i64, String)> {
    match params.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err((
            INVALID_PARAMS,
            format!("{method}: '{key}' must be a string"),
        )),
    }
}

/// `card.add_key` (RFC 0007 §5.4) — add one key to an already-provisioned
/// card. Issues confirm, `secret` (the card's current management key unless
/// `management_key_from_store` names where to read it, then the PIN) and
/// progress interactions through `fe`. Returns `{ "guid", "slot",
/// "public_key", "serves_operator_acts" }`. Asking for slot 9d, an unknown
/// slot or an unknown policy is `-32602`; an occupied slot without `replace`
/// is `-32050`; an operator decline is `-32010`.
pub fn card_add_key(
    params: &Value,
    fe: &mut dyn Frontend,
    sealer: &dyn ManagementKeySealer,
) -> Result<Value, (i64, String)> {
    const METHOD: &str = "card.add_key";
    let invalid = |e: String| (INVALID_PARAMS, format!("{METHOD}: {e}"));

    let slot = optional_str(METHOD, params, "slot")?
        .ok_or_else(|| invalid("'slot' is required (9c or 9a)".into()))?;
    let pin_policy = optional_str(METHOD, params, "pin_policy")?;
    let touch_policy = optional_str(METHOD, params, "touch_policy")?;

    let serial = match params.get("serial") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| invalid("'serial' must be a u32".into()))?,
        ),
    };
    let guid = optional_str(METHOD, params, "guid")?.map(str::to_string);
    let reader = optional_str(METHOD, params, "reader")?.map(str::to_string);
    let selector =
        CardSelector::from_flags(serial, guid, reader, RequestBinding::JsonRpc).map_err(invalid)?;
    let replace = params
        .get("replace")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let management_key_from_store = match params.get("management_key_from_store") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => None,
        Some(Value::Bool(true)) => Some(String::new()),
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(_) => {
            return Err(invalid(
                "'management_key_from_store' must be a boolean or a non-empty store path".into(),
            ));
        }
    };

    let args = AddKeyArgs {
        slot,
        pin_policy,
        touch_policy,
        replace,
        management_key_from_store,
        binding: RequestBinding::JsonRpc,
    };
    args.slot_and_policy().map_err(invalid)?;
    match add_key_with_frontend(selector, args, sealer, fe) {
        Ok(outcome) => {
            let public_key = openssh_line(&outcome).map_err(|e| (CARD_OP_FAILED, e))?;
            Ok(serde_json::json!({
                "guid": outcome.guid,
                "slot": format!("{:02x}", outcome.slot),
                "public_key": public_key,
                "serves_operator_acts": outcome.serves_operator_acts,
            }))
        }
        Err(ProvisionError::Frontend(FrontendError::Declined(m)))
        | Err(ProvisionError::Aborted(m)) => Err((INTERACTION_DECLINED, m)),
        Err(e) => Err((CARD_OP_FAILED, e.to_string())),
    }
}

/// `sign_bytes` (RFC 0007 §5.3) — sign a base64 message with a PIV signing slot
/// (9a/9c). Issues a `secret` (PIN) interaction through `fe`. Returns
/// `{ "signature": <base64> }` (raw `r‖s` by default, or DER). piggy applies no
/// canonicalization.
pub fn sign_bytes(params: &Value, fe: &mut dyn Frontend) -> Result<Value, (i64, String)> {
    let slot = params.get("slot").and_then(Value::as_str).ok_or((
        INVALID_PARAMS,
        "sign_bytes: 'slot' (string) is required".to_string(),
    ))?;
    // Validate the slot up front so a bad slot is an invalid-params error
    // rather than a card-op failure.
    sign_core::parse_slot(slot).map_err(|e| (INVALID_PARAMS, e))?;

    let guid = params.get("guid").and_then(Value::as_str);
    let format = match params.get("format").and_then(Value::as_str) {
        None | Some("raw") => SigFormat::Raw,
        Some("der") => SigFormat::Der,
        Some(other) => {
            return Err((
                INVALID_PARAMS,
                format!("sign_bytes: unknown format {other:?}; use \"raw\" or \"der\""),
            ));
        }
    };
    let message_b64 = params.get("message").and_then(Value::as_str).ok_or((
        INVALID_PARAMS,
        "sign_bytes: 'message' (base64 string) is required".to_string(),
    ))?;
    let message = B64.decode(message_b64).map_err(|e| {
        (
            INVALID_PARAMS,
            format!("sign_bytes: 'message' is not valid base64: {e}"),
        )
    })?;

    match sign_core::sign_message(slot, guid, &message, format, None, Some(fe)) {
        Ok(sig) => Ok(serde_json::json!({ "signature": B64.encode(sig) })),
        Err(SignError::Declined(m)) => Err((INTERACTION_DECLINED, m)),
        Err(SignError::Failed(m)) => Err((CARD_OP_FAILED, m)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Card-touching paths (the actual provision/sign/enumerate) are covered by
    // the fibby conformance lane; here we cover the card-free param validation.

    fn no_frontend() -> impl Frontend {
        // A frontend that should never be called for the param-error cases
        // below (they fail before any interaction).
        struct Never;
        impl Frontend for Never {
            fn request_secret(
                &mut self,
                _r: crate::card::protocol::SecretRequest,
            ) -> Result<zeroize::Zeroizing<String>, FrontendError> {
                panic!("frontend must not be reached on a param error")
            }
            fn request_mgmt_key(
                &mut self,
                _r: crate::card::protocol::MgmtKeyRequest,
            ) -> Result<crate::card::protocol::MgmtKeyChoice, FrontendError> {
                panic!("unreached")
            }
            fn confirm(
                &mut self,
                _r: crate::card::protocol::ConfirmRequest,
            ) -> Result<bool, FrontendError> {
                panic!("unreached")
            }
            fn select_card(
                &mut self,
                _r: crate::card::protocol::CardSelectRequest,
            ) -> Result<String, FrontendError> {
                panic!("unreached")
            }
            fn progress(&mut self, _e: crate::card::protocol::ProgressEvent) {}
            fn completed(&mut self, _e: crate::card::protocol::CompletedEvent) {}
        }
        Never
    }

    #[test]
    fn sign_bytes_requires_slot() {
        let mut fe = no_frontend();
        let err = sign_bytes(&serde_json::json!({ "message": "AAAA" }), &mut fe).unwrap_err();
        assert_eq!(err.0, INVALID_PARAMS);
        assert!(err.1.contains("slot"));
    }

    #[test]
    fn sign_bytes_rejects_bad_slot() {
        let mut fe = no_frontend();
        let err = sign_bytes(
            &serde_json::json!({ "slot": "9d", "message": "AAAA" }),
            &mut fe,
        )
        .unwrap_err();
        assert_eq!(err.0, INVALID_PARAMS);
    }

    #[test]
    fn sign_bytes_requires_message() {
        let mut fe = no_frontend();
        let err = sign_bytes(&serde_json::json!({ "slot": "9a" }), &mut fe).unwrap_err();
        assert_eq!(err.0, INVALID_PARAMS);
        assert!(err.1.contains("message"));
    }

    #[test]
    fn sign_bytes_rejects_non_base64_message() {
        let mut fe = no_frontend();
        let err = sign_bytes(
            &serde_json::json!({ "slot": "9a", "message": "not base64!!" }),
            &mut fe,
        )
        .unwrap_err();
        assert_eq!(err.0, INVALID_PARAMS);
        assert!(err.1.contains("base64"));
    }

    #[test]
    fn sign_bytes_rejects_unknown_format() {
        let mut fe = no_frontend();
        let err = sign_bytes(
            &serde_json::json!({ "slot": "9a", "format": "pem", "message": "AAAA" }),
            &mut fe,
        )
        .unwrap_err();
        assert_eq!(err.0, INVALID_PARAMS);
        assert!(err.1.contains("format"));
    }

    #[test]
    fn card_init_rejects_non_integer_serial() {
        let mut fe = no_frontend();
        let err = card_init(
            &serde_json::json!({ "serial": "nope" }),
            &mut fe,
            &crate::card::seal::NoStore,
        )
        .unwrap_err();
        assert_eq!(err.0, INVALID_PARAMS);
    }

    #[test]
    fn card_init_rejects_malformed_seal_param() {
        for bad in [
            serde_json::json!(7),
            serde_json::json!(""),
            serde_json::json!([]),
        ] {
            let mut fe = no_frontend();
            let err = card_init(
                &serde_json::json!({ "seal_management_key": bad }),
                &mut fe,
                &crate::card::seal::NoStore,
            )
            .unwrap_err();
            assert_eq!(err.0, INVALID_PARAMS, "{bad}");
            assert!(err.1.contains("seal_management_key"), "{}", err.1);
        }
    }

    #[test]
    fn slot_policies_param_overrides_only_what_it_names() {
        let p = slot_policies_param(
            "card.init",
            &serde_json::json!({ "pin_policy": { "9a": "always" }, "touch_policy": { "9c": "cached" } }),
        )
        .unwrap();
        let d = SlotPolicies::default();
        assert_eq!(p.piv_auth.pin, piggy_piv::PinPolicy::Always);
        assert_eq!(p.piv_auth.touch, d.piv_auth.touch);
        assert_eq!(p.signature.touch, piggy_piv::TouchPolicy::Cached);
        assert_eq!(p.key_mgmt, d.key_mgmt);
        assert_eq!(
            slot_policies_param("card.init", &serde_json::json!({})),
            Ok(d)
        );
    }

    #[test]
    fn card_init_rejects_malformed_policy_params() {
        for bad in [
            serde_json::json!({ "pin_policy": "always" }),
            serde_json::json!({ "pin_policy": { "9a": 3 } }),
            serde_json::json!({ "pin_policy": { "9e": "once" } }),
            serde_json::json!({ "touch_policy": { "9c": "once" } }),
        ] {
            let mut fe = no_frontend();
            let err = card_init(&bad, &mut fe, &crate::card::seal::NoStore).unwrap_err();
            assert_eq!(err.0, INVALID_PARAMS, "{bad}");
            assert!(err.1.contains("_policy"), "{}", err.1);
        }
    }

    #[test]
    fn card_add_key_rejects_bad_requests_before_any_card() {
        for (bad, needle) in [
            (serde_json::json!({}), "'slot' is required"),
            (serde_json::json!({ "slot": "9d" }), "never regenerated"),
            (serde_json::json!({ "slot": "9e" }), "9c or 9a"),
            (serde_json::json!({ "slot": 9 }), "'slot' must be a string"),
            (
                serde_json::json!({ "slot": "9c", "pin_policy": "sometimes" }),
                "unknown PIN policy",
            ),
            (
                serde_json::json!({ "slot": "9c", "management_key_from_store": 7 }),
                "management_key_from_store",
            ),
            (
                serde_json::json!({ "slot": "9c", "serial": 1, "reader": "r" }),
                "at most one",
            ),
        ] {
            let mut fe = no_frontend();
            let err = card_add_key(&bad, &mut fe, &crate::card::seal::NoStore).unwrap_err();
            assert_eq!(err.0, INVALID_PARAMS, "{bad}");
            assert!(err.1.contains(needle), "{bad}: {}", err.1);
            // A JSON-RPC caller is told about params, never CLI flags.
            assert!(!err.1.contains("--"), "{bad}: {}", err.1);
        }
    }

    #[test]
    fn card_add_key_policy_errors_name_the_param() {
        for (bad, needle) in [
            (
                serde_json::json!({ "slot": "9c", "pin_policy": "sometimes" }),
                "'pin_policy': unknown PIN policy",
            ),
            (
                serde_json::json!({ "slot": "9a", "touch_policy": "once" }),
                "'touch_policy': unknown touch policy",
            ),
            (
                serde_json::json!({ "slot": "9c", "guid": "nothex" }),
                "invalid 'guid'",
            ),
        ] {
            let mut fe = no_frontend();
            let err = card_add_key(&bad, &mut fe, &crate::card::seal::NoStore).unwrap_err();
            assert_eq!(err.0, INVALID_PARAMS, "{bad}");
            assert!(err.1.contains(needle), "{bad}: {}", err.1);
        }
    }

    #[test]
    fn seal_param_maps_to_modes() {
        assert_eq!(seal_param(&serde_json::json!({})), Ok(SealMode::Never));
        assert_eq!(
            seal_param(&serde_json::json!({ "seal_management_key": false })),
            Ok(SealMode::Never)
        );
        assert_eq!(
            seal_param(&serde_json::json!({ "seal_management_key": true })),
            Ok(SealMode::Always(None))
        );
        assert_eq!(
            seal_param(&serde_json::json!({ "seal_management_key": "escrow/yk" })),
            Ok(SealMode::Always(Some("escrow/yk".into())))
        );
    }
}
