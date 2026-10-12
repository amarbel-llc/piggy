//! YubicoPIV per-slot PIN and touch policies.
//!
//! These are vendor extensions to the NIST 800-73 PIV model. Standard
//! PIV cards have no notion of PIN or touch policy — those are
//! YubicoPIV-specific. Each generated/imported key carries a (pin,
//! touch) policy pair that controls whether the PIN must be re-verified
//! and whether physical touch is required before a private-key
//! operation. Byte values mirror ykpiv.h on Yubico's official client.
//!
//! Two on-card channels carry policy information out:
//!   * INS_GET_METADATA (0xF7) — YubiKey 5.3+ only, returns tag 0x02
//!     = `[pin_byte, touch_byte]`.
//!   * INS_ATTEST (0xF9) — YubiKey 4.3+ with attestation key. The
//!     attestation cert embeds OID `1.3.6.1.4.1.41482.3.8` carrying
//!     the same `[pin_byte, touch_byte]` octet string.
//!
//! Both channels report the *configured* policy, not the *effective*
//! policy: a `Default` value means "whatever the spec default is for
//! this slot". Slot 9D defaults to PIN=once, touch=never; slot 9C
//! defaults to PIN=always, touch=never. Callers that need the
//! effective policy must combine the configured value with the slot
//! default themselves.

use crate::error::PivError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinPolicy {
    /// Use the per-slot spec default (e.g. `Once` for slot 9D).
    Default,
    /// Never require PIN. Useful for unattended automation.
    Never,
    /// Verify PIN once per card session.
    Once,
    /// Verify PIN before every private-key operation.
    Always,
}

impl PinPolicy {
    pub fn from_byte(b: u8) -> Result<Self, PivError> {
        match b {
            0x00 => Ok(Self::Default),
            0x01 => Ok(Self::Never),
            0x02 => Ok(Self::Once),
            0x03 => Ok(Self::Always),
            _ => Err(PivError::Other(format!(
                "unknown YubicoPIV PIN policy byte: 0x{b:02X}"
            ))),
        }
    }

    /// The byte carried in GENERATE/IMPORT tag `AA`. Inverse of
    /// [`Self::from_byte`].
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Default => 0x00,
            Self::Never => 0x01,
            Self::Once => 0x02,
            Self::Always => 0x03,
        }
    }

    /// The tag-`AA` byte to send, or `None` for [`Self::Default`]: leaving
    /// the tag out is what a card without the YubicoPIV extension accepts.
    pub fn generate_tag_byte(self) -> Option<u8> {
        (self != Self::Default).then(|| self.to_byte())
    }

    /// Lowercase canonical name as it appears in `pivy-tool generate -i`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Never => "never",
            Self::Once => "once",
            Self::Always => "always",
        }
    }
}

impl std::str::FromStr for PinPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" => Ok(Self::Default),
            "never" => Ok(Self::Never),
            "once" => Ok(Self::Once),
            "always" => Ok(Self::Always),
            _ => Err(format!(
                "unknown PIN policy {s:?} (expected default, never, once or always)"
            )),
        }
    }
}

impl std::fmt::Display for PinPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TouchPolicy {
    /// Use the per-slot spec default (typically `Never` for every
    /// slot — touch is opt-in even on YubiKey).
    Default,
    /// Never require physical touch.
    Never,
    /// Require touch before every private-key operation.
    Always,
    /// Require touch, then cache the touch for 15 seconds.
    Cached,
}

impl TouchPolicy {
    pub fn from_byte(b: u8) -> Result<Self, PivError> {
        match b {
            0x00 => Ok(Self::Default),
            0x01 => Ok(Self::Never),
            0x02 => Ok(Self::Always),
            0x03 => Ok(Self::Cached),
            _ => Err(PivError::Other(format!(
                "unknown YubicoPIV touch policy byte: 0x{b:02X}"
            ))),
        }
    }

    /// The byte carried in GENERATE/IMPORT tag `AB`. Inverse of
    /// [`Self::from_byte`].
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Default => 0x00,
            Self::Never => 0x01,
            Self::Always => 0x02,
            Self::Cached => 0x03,
        }
    }

    /// The tag-`AB` byte to send, or `None` for [`Self::Default`].
    pub fn generate_tag_byte(self) -> Option<u8> {
        (self != Self::Default).then(|| self.to_byte())
    }

    /// Lowercase canonical name as it appears in `pivy-tool generate -t`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Never => "never",
            Self::Always => "always",
            Self::Cached => "cached",
        }
    }
}

impl std::str::FromStr for TouchPolicy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "default" => Ok(Self::Default),
            "never" => Ok(Self::Never),
            "always" => Ok(Self::Always),
            "cached" => Ok(Self::Cached),
            _ => Err(format!(
                "unknown touch policy {s:?} (expected default, never, always or cached)"
            )),
        }
    }
}

impl std::fmt::Display for TouchPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A key's PIN and touch policy as configured at generate time, or as read
/// back from its attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyPolicy {
    pub pin: PinPolicy,
    pub touch: TouchPolicy,
}

impl KeyPolicy {
    /// No policy tags: whatever the card does for the slot. The only policy
    /// a card without the YubicoPIV extension accepts.
    pub const CARD_DEFAULT: Self = Self {
        pin: PinPolicy::Default,
        touch: TouchPolicy::Default,
    };

    /// The policy an operator-act key must carry (FDR 0006): every use
    /// needs the PIN entered and the card touched.
    pub const OPERATOR_ACT: Self = Self {
        pin: PinPolicy::Always,
        touch: TouchPolicy::Always,
    };

    /// Whether every use of the key is a deliberate human act. Judged on
    /// the configured values: a `default` PIN policy does not qualify even
    /// on slot 9C, whose spec default is `always`, because the claim has to
    /// be readable from the attestation alone.
    pub fn serves_operator_acts(self) -> bool {
        self == Self::OPERATOR_ACT
    }

    /// The PIN policy the card applies to `slot`: the configured one, or
    /// for `default` the PIV spec default (9C always, 9E never, else once).
    pub fn effective_pin(self, slot: u8) -> PinPolicy {
        match (self.pin, slot) {
            (PinPolicy::Default, 0x9C) => PinPolicy::Always,
            (PinPolicy::Default, 0x9E) => PinPolicy::Never,
            (PinPolicy::Default, _) => PinPolicy::Once,
            (configured, _) => configured,
        }
    }

    /// Whether a private-key operation waits for a touch.
    pub fn needs_touch(self) -> bool {
        matches!(self.touch, TouchPolicy::Always | TouchPolicy::Cached)
    }
}

impl std::fmt::Display for KeyPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PIN {}, touch {}", self.pin, self.touch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_pin_always_and_touch_always_serves_operator_acts() {
        assert!(KeyPolicy::OPERATOR_ACT.serves_operator_acts());
        for (pin, touch) in [
            (PinPolicy::Once, TouchPolicy::Always),
            (PinPolicy::Always, TouchPolicy::Cached),
            (PinPolicy::Default, TouchPolicy::Always),
            (PinPolicy::Always, TouchPolicy::Default),
        ] {
            assert!(
                !KeyPolicy { pin, touch }.serves_operator_acts(),
                "{pin} / {touch}"
            );
        }
    }

    #[test]
    fn default_pin_policy_resolves_per_slot() {
        let d = KeyPolicy::CARD_DEFAULT;
        assert_eq!(d.effective_pin(0x9A), PinPolicy::Once);
        assert_eq!(d.effective_pin(0x9C), PinPolicy::Always);
        assert_eq!(d.effective_pin(0x9D), PinPolicy::Once);
        assert_eq!(d.effective_pin(0x9E), PinPolicy::Never);
        let never = KeyPolicy {
            pin: PinPolicy::Never,
            touch: TouchPolicy::Default,
        };
        assert_eq!(never.effective_pin(0x9C), PinPolicy::Never);
        assert!(!d.needs_touch());
        assert!(KeyPolicy::OPERATOR_ACT.needs_touch());
        assert_eq!(
            KeyPolicy::OPERATOR_ACT.to_string(),
            "PIN always, touch always"
        );
    }

    #[test]
    fn pin_policy_round_trips_known_bytes() {
        for (byte, expected) in [
            (0x00, PinPolicy::Default),
            (0x01, PinPolicy::Never),
            (0x02, PinPolicy::Once),
            (0x03, PinPolicy::Always),
        ] {
            assert_eq!(PinPolicy::from_byte(byte).unwrap(), expected);
        }
    }

    #[test]
    fn touch_policy_round_trips_known_bytes() {
        for (byte, expected) in [
            (0x00, TouchPolicy::Default),
            (0x01, TouchPolicy::Never),
            (0x02, TouchPolicy::Always),
            (0x03, TouchPolicy::Cached),
        ] {
            assert_eq!(TouchPolicy::from_byte(byte).unwrap(), expected);
        }
    }

    #[test]
    fn policies_round_trip_through_bytes_and_names() {
        for p in [
            PinPolicy::Default,
            PinPolicy::Never,
            PinPolicy::Once,
            PinPolicy::Always,
        ] {
            assert_eq!(PinPolicy::from_byte(p.to_byte()).unwrap(), p);
            assert_eq!(p.as_str().parse::<PinPolicy>().unwrap(), p);
        }
        for t in [
            TouchPolicy::Default,
            TouchPolicy::Never,
            TouchPolicy::Always,
            TouchPolicy::Cached,
        ] {
            assert_eq!(TouchPolicy::from_byte(t.to_byte()).unwrap(), t);
            assert_eq!(t.as_str().parse::<TouchPolicy>().unwrap(), t);
        }
    }

    #[test]
    fn default_policy_sends_no_generate_tag() {
        assert_eq!(PinPolicy::Default.generate_tag_byte(), None);
        assert_eq!(TouchPolicy::Default.generate_tag_byte(), None);
        assert_eq!(PinPolicy::Always.generate_tag_byte(), Some(0x03));
        assert_eq!(TouchPolicy::Cached.generate_tag_byte(), Some(0x03));
    }

    #[test]
    fn unknown_policy_name_names_the_choices() {
        let e = "sometimes".parse::<PinPolicy>().unwrap_err();
        assert!(e.contains("sometimes") && e.contains("always"), "{e}");
        let e = "once".parse::<TouchPolicy>().unwrap_err();
        assert!(e.contains("cached"), "{e}");
    }

    #[test]
    fn pin_policy_unknown_byte_is_error() {
        let err = PinPolicy::from_byte(0xFF).unwrap_err();
        // We want the byte in the error message so callers can debug
        // surprise firmware behavior.
        assert!(err.to_string().contains("0xFF"), "msg: {err}");
    }

    #[test]
    fn touch_policy_unknown_byte_is_error() {
        let err = TouchPolicy::from_byte(0x7E).unwrap_err();
        assert!(err.to_string().contains("0x7E"), "msg: {err}");
    }

    #[test]
    fn pin_policy_strings_match_pivy_flags() {
        assert_eq!(PinPolicy::Never.as_str(), "never");
        assert_eq!(PinPolicy::Once.as_str(), "once");
        assert_eq!(PinPolicy::Always.as_str(), "always");
        assert_eq!(PinPolicy::Default.as_str(), "default");
    }

    #[test]
    fn touch_policy_strings_match_pivy_flags() {
        assert_eq!(TouchPolicy::Never.as_str(), "never");
        assert_eq!(TouchPolicy::Always.as_str(), "always");
        assert_eq!(TouchPolicy::Cached.as_str(), "cached");
        assert_eq!(TouchPolicy::Default.as_str(), "default");
    }
}
