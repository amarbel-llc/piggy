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

impl std::fmt::Display for TouchPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
