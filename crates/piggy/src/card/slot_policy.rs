//! The PIN and touch policy each provisioned slot is generated with (FDR
//! 0006): the fresh-card defaults, and the `SLOT=POLICY` overrides the CLI
//! flags and the JSON-RPC params carry. Also the slot names every card and
//! signing command reads, and the one operator-act verdict.

use std::str::FromStr;

use piggy_piv::{KeyPolicy, PinPolicy, TouchPolicy};

use crate::card::RequestBinding;

pub const SLOT_PIV_AUTH: u8 = 0x9A;
pub const SLOT_SIGNATURE: u8 = 0x9C;
pub const SLOT_KEY_MGMT: u8 = 0x9D;

/// The key slot a slot name (`9a`, `9C`, `9d`, any case) names. Each command
/// narrows this to the slots it takes and words its own refusal.
pub fn named_slot(name: &str) -> Option<u8> {
    match name.to_ascii_lowercase().as_str() {
        "9a" => Some(SLOT_PIV_AUTH),
        "9c" => Some(SLOT_SIGNATURE),
        "9d" => Some(SLOT_KEY_MGMT),
        _ => None,
    }
}

/// A PIN or touch policy name in any case. An unknown name keeps the
/// operator's spelling in the error.
fn parse_policy_name<T: FromStr<Err = String>>(name: &str) -> Result<T, String> {
    name.to_ascii_lowercase().parse().or_else(|_| name.parse())
}

/// Why a slot's key cannot sign operator acts (FDR 0006).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorActBlocker {
    /// The card attests the key with this policy, which is not PIN always,
    /// touch always.
    Policy(KeyPolicy),
    /// The card does not attest the key at all.
    Unattested,
}

/// Whether a key the card attests as `attested` (`None`: the card did not
/// attest it) can sign operator acts. The attestation is the only evidence:
/// what was asked for at generate time does not count. Shared by `card
/// init`/`add-key` and `piggy health` so they cannot disagree.
pub fn operator_act_verdict(attested: Option<KeyPolicy>) -> Result<(), OperatorActBlocker> {
    match attested {
        Some(policy) if policy.serves_operator_acts() => Ok(()),
        Some(policy) => Err(OperatorActBlocker::Policy(policy)),
        None => Err(OperatorActBlocker::Unattested),
    }
}

/// The policies `piggy card init` generates its three keys with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotPolicies {
    /// 9A, the SSH authentication key.
    pub piv_auth: KeyPolicy,
    /// 9C, the operator-act key.
    pub signature: KeyPolicy,
    /// 9D, the store's decrypt key.
    pub key_mgmt: KeyPolicy,
}

impl Default for SlotPolicies {
    /// The fresh-card defaults: 9A asks for the PIN once and a touch that
    /// stays good for a few seconds, so a burst of SSH logins is one touch;
    /// 9C asks for both on every use, which is what makes it an
    /// operator-act key; 9D keeps the card's own default, as before.
    fn default() -> Self {
        Self {
            piv_auth: KeyPolicy {
                pin: PinPolicy::Once,
                touch: TouchPolicy::Cached,
            },
            signature: KeyPolicy::OPERATOR_ACT,
            key_mgmt: KeyPolicy::CARD_DEFAULT,
        }
    }
}

impl SlotPolicies {
    /// No policy tags on any slot: all a card without the YubicoPIV
    /// extension accepts.
    pub const CARD_DEFAULT: Self = Self {
        piv_auth: KeyPolicy::CARD_DEFAULT,
        signature: KeyPolicy::CARD_DEFAULT,
        key_mgmt: KeyPolicy::CARD_DEFAULT,
    };

    pub fn for_slot(&self, slot: u8) -> KeyPolicy {
        match slot {
            SLOT_PIV_AUTH => self.piv_auth,
            SLOT_SIGNATURE => self.signature,
            SLOT_KEY_MGMT => self.key_mgmt,
            _ => KeyPolicy::CARD_DEFAULT,
        }
    }

    fn slot_mut(&mut self, slot: &str) -> Result<&mut KeyPolicy, String> {
        match named_slot(slot) {
            Some(SLOT_PIV_AUTH) => Ok(&mut self.piv_auth),
            Some(SLOT_SIGNATURE) => Ok(&mut self.signature),
            Some(SLOT_KEY_MGMT) => Ok(&mut self.key_mgmt),
            _ => Err(format!(
                "unknown slot {slot:?} (card init provisions 9a, 9c and 9d)"
            )),
        }
    }

    pub fn set_pin(&mut self, slot: &str, policy: &str) -> Result<(), String> {
        self.slot_mut(slot)?.pin = parse_policy_name(policy)?;
        Ok(())
    }

    pub fn set_touch(&mut self, slot: &str, policy: &str) -> Result<(), String> {
        self.slot_mut(slot)?.touch = parse_policy_name(policy)?;
        Ok(())
    }

    /// The defaults with the `--pin-policy` / `--touch-policy` flag values
    /// (`SLOT=POLICY`, e.g. `9a=once`) applied in order.
    pub fn from_flags(pin: &[String], touch: &[String]) -> Result<Self, String> {
        let mut policies = Self::default();
        for flag in pin {
            let (slot, policy) = split_flag("--pin-policy", flag)?;
            policies
                .set_pin(slot, policy)
                .map_err(|e| format!("--pin-policy {flag}: {e}"))?;
        }
        for flag in touch {
            let (slot, policy) = split_flag("--touch-policy", flag)?;
            policies
                .set_touch(slot, policy)
                .map_err(|e| format!("--touch-policy {flag}: {e}"))?;
        }
        Ok(policies)
    }
}

fn split_flag<'a>(name: &str, value: &'a str) -> Result<(&'a str, &'a str), String> {
    value
        .split_once('=')
        .ok_or_else(|| format!("{name} {value}: expected SLOT=POLICY, e.g. 9a=once"))
}

/// The slot `piggy card add-key` may fill, and the policy it gets unless
/// overridden. 9D is refused outright: a new 9D key cannot read anything the
/// store encrypted to the old one.
pub fn add_key_slot(slot: &str) -> Result<(u8, KeyPolicy), String> {
    match named_slot(slot) {
        Some(SLOT_SIGNATURE) => Ok((SLOT_SIGNATURE, SlotPolicies::default().signature)),
        Some(SLOT_PIV_AUTH) => Ok((SLOT_PIV_AUTH, SlotPolicies::default().piv_auth)),
        Some(SLOT_KEY_MGMT) => Err(
            "slot 9D is never regenerated: the password store is encrypted to its key, and a new key could not decrypt it"
                .to_string(),
        ),
        _ => Err(format!("unknown slot {slot:?} (add-key takes 9c or 9a)")),
    }
}

/// A single-key policy from the optional PIN and touch policy names a
/// caller gave, starting from `base`. An error names the option the way
/// `binding` spells it (`--pin-policy`, or the `pin_policy` param).
pub fn key_policy_from_flags(
    base: KeyPolicy,
    pin: Option<&str>,
    touch: Option<&str>,
    binding: RequestBinding,
) -> Result<KeyPolicy, String> {
    let mut policy = base;
    if let Some(p) = pin {
        policy.pin =
            parse_policy_name(p).map_err(|e| format!("{}: {e}", binding.option("pin_policy")))?;
    }
    if let Some(t) = touch {
        policy.touch =
            parse_policy_name(t).map_err(|e| format!("{}: {e}", binding.option("touch_policy")))?;
    }
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flags(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn defaults_make_9c_the_operator_act_key() {
        let d = SlotPolicies::default();
        assert_eq!(d.piv_auth.to_string(), "PIN once, touch cached");
        assert!(d.signature.serves_operator_acts());
        assert!(!d.piv_auth.serves_operator_acts());
        assert_eq!(d.key_mgmt, KeyPolicy::CARD_DEFAULT);
        assert_eq!(d.for_slot(0x9C), d.signature);
    }

    #[test]
    fn flags_override_one_field_of_one_slot() {
        let p =
            SlotPolicies::from_flags(&flags(&["9a=always"]), &flags(&["9C=cached", "9d=never"]))
                .unwrap();
        assert_eq!(p.piv_auth.pin, PinPolicy::Always);
        assert_eq!(p.piv_auth.touch, TouchPolicy::Cached, "untouched default");
        assert_eq!(p.signature.pin, PinPolicy::Always, "untouched default");
        assert_eq!(p.signature.touch, TouchPolicy::Cached);
        assert_eq!(p.key_mgmt.touch, TouchPolicy::Never);
    }

    #[test]
    fn bad_flags_name_what_was_wrong() {
        let e = SlotPolicies::from_flags(&flags(&["9a"]), &[]).unwrap_err();
        assert!(e.contains("SLOT=POLICY"), "{e}");
        let e = SlotPolicies::from_flags(&flags(&["9e=once"]), &[]).unwrap_err();
        assert!(e.contains("unknown slot") && e.contains("9e=once"), "{e}");
        let e = SlotPolicies::from_flags(&[], &flags(&["9a=once"])).unwrap_err();
        assert!(e.contains("unknown touch policy"), "{e}");
    }

    #[test]
    fn add_key_takes_9c_and_9a_and_never_9d() {
        assert_eq!(add_key_slot("9C").unwrap(), (0x9C, KeyPolicy::OPERATOR_ACT));
        assert_eq!(add_key_slot("9a").unwrap().0, 0x9A);
        let e = add_key_slot("9d").unwrap_err();
        assert!(e.contains("never regenerated"), "{e}");
        assert!(add_key_slot("9e").unwrap_err().contains("9c or 9a"));
    }

    #[test]
    fn single_key_flags_start_from_the_base() {
        let p = key_policy_from_flags(
            KeyPolicy::OPERATOR_ACT,
            None,
            Some("cached"),
            RequestBinding::Cli,
        )
        .unwrap();
        assert_eq!(p.pin, PinPolicy::Always);
        assert_eq!(p.touch, TouchPolicy::Cached);
        assert!(
            key_policy_from_flags(
                KeyPolicy::OPERATOR_ACT,
                Some("x"),
                None,
                RequestBinding::Cli
            )
            .is_err()
        );
    }

    #[test]
    fn policy_names_are_case_insensitive() {
        let p = key_policy_from_flags(
            KeyPolicy::CARD_DEFAULT,
            Some("ALWAYS"),
            Some("Cached"),
            RequestBinding::Cli,
        )
        .unwrap();
        assert_eq!(
            p,
            KeyPolicy {
                pin: PinPolicy::Always,
                touch: TouchPolicy::Cached
            }
        );
        let p = SlotPolicies::from_flags(&flags(&["9A=Never"]), &flags(&["9c=CACHED"])).unwrap();
        assert_eq!(p.piv_auth.pin, PinPolicy::Never);
        assert_eq!(p.signature.touch, TouchPolicy::Cached);
        // An unknown name is still refused, in the operator's own spelling.
        let e = SlotPolicies::from_flags(&flags(&["9a=Sometimes"]), &[]).unwrap_err();
        assert!(e.contains("\"Sometimes\""), "{e}");
    }

    #[test]
    fn policy_errors_name_the_option_as_the_binding_spells_it() {
        let cli = key_policy_from_flags(
            KeyPolicy::CARD_DEFAULT,
            Some("sometimes"),
            None,
            RequestBinding::Cli,
        )
        .unwrap_err();
        assert!(cli.starts_with("--pin-policy: "), "{cli}");
        let rpc = key_policy_from_flags(
            KeyPolicy::CARD_DEFAULT,
            None,
            Some("once"),
            RequestBinding::JsonRpc,
        )
        .unwrap_err();
        assert!(rpc.starts_with("'touch_policy': "), "{rpc}");
        assert!(!rpc.contains("--"), "{rpc}");
    }

    #[test]
    fn named_slot_reads_the_three_provisioned_slots_in_any_case() {
        assert_eq!(named_slot("9a"), Some(0x9A));
        assert_eq!(named_slot("9C"), Some(0x9C));
        assert_eq!(named_slot("9D"), Some(0x9D));
        for other in ["9e", "82", "0x9a", "", "9"] {
            assert_eq!(named_slot(other), None, "{other:?}");
        }
    }

    #[test]
    fn only_an_attested_pin_always_touch_always_key_serves_operator_acts() {
        assert_eq!(operator_act_verdict(Some(KeyPolicy::OPERATOR_ACT)), Ok(()));
        let weak = KeyPolicy {
            pin: PinPolicy::Always,
            touch: TouchPolicy::Cached,
        };
        assert_eq!(
            operator_act_verdict(Some(weak)),
            Err(OperatorActBlocker::Policy(weak))
        );
        assert_eq!(
            operator_act_verdict(None),
            Err(OperatorActBlocker::Unattested)
        );
    }
}
