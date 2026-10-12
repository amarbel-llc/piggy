//! The PIN and touch policy each provisioned slot is generated with (FDR
//! 0006): the fresh-card defaults, and the `SLOT=POLICY` overrides the CLI
//! flags and the JSON-RPC params carry.

use piggy_piv::{KeyPolicy, PinPolicy, TouchPolicy};

pub const SLOT_PIV_AUTH: u8 = 0x9A;
pub const SLOT_SIGNATURE: u8 = 0x9C;
pub const SLOT_KEY_MGMT: u8 = 0x9D;

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
        match slot.to_ascii_lowercase().as_str() {
            "9a" => Ok(&mut self.piv_auth),
            "9c" => Ok(&mut self.signature),
            "9d" => Ok(&mut self.key_mgmt),
            _ => Err(format!(
                "unknown slot {slot:?} (card init provisions 9a, 9c and 9d)"
            )),
        }
    }

    pub fn set_pin(&mut self, slot: &str, policy: &str) -> Result<(), String> {
        self.slot_mut(slot)?.pin = policy.parse()?;
        Ok(())
    }

    pub fn set_touch(&mut self, slot: &str, policy: &str) -> Result<(), String> {
        self.slot_mut(slot)?.touch = policy.parse()?;
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
    match slot.to_ascii_lowercase().as_str() {
        "9c" => Ok((SLOT_SIGNATURE, SlotPolicies::default().signature)),
        "9a" => Ok((SLOT_PIV_AUTH, SlotPolicies::default().piv_auth)),
        "9d" => Err(
            "slot 9D is never regenerated: the password store is encrypted to its key, and a new key could not decrypt it"
                .to_string(),
        ),
        _ => Err(format!("unknown slot {slot:?} (add-key takes 9c or 9a)")),
    }
}

/// A single-key policy from optional `--pin-policy` / `--touch-policy`
/// values, starting from `base`.
pub fn key_policy_from_flags(
    base: KeyPolicy,
    pin: Option<&str>,
    touch: Option<&str>,
) -> Result<KeyPolicy, String> {
    let mut policy = base;
    if let Some(p) = pin {
        policy.pin = p.parse().map_err(|e| format!("--pin-policy: {e}"))?;
    }
    if let Some(t) = touch {
        policy.touch = t.parse().map_err(|e| format!("--touch-policy: {e}"))?;
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
        let p = key_policy_from_flags(KeyPolicy::OPERATOR_ACT, None, Some("cached")).unwrap();
        assert_eq!(p.pin, PinPolicy::Always);
        assert_eq!(p.touch, TouchPolicy::Cached);
        assert!(key_policy_from_flags(KeyPolicy::OPERATOR_ACT, Some("x"), None).is_err());
    }
}
