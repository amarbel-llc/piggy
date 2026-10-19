//! Why a card refused a private-key operation with SW 0x6982 ("security
//! status not satisfied"), which [`crate::PivError::PinRequired`] reports.
//!
//! The same status word means two different things to the operator. A
//! YubiKey waiting for a touch gives up after about fifteen seconds and
//! answers 0x6982; the operator's fix is to touch sooner. A card whose PIN
//! state was lost before the operation (a reset, or an APDU between VERIFY
//! and the operation on a PIN-always slot) answers 0x6982 at once; touching
//! sooner cannot help (piggy#325). Only the time the operation took tells
//! them apart, so callers time it and ask [`classify`].

use std::time::Duration;

/// The shortest wait that is read as the card giving up on a touch. An
/// immediate refusal is one APDU round trip, tens of milliseconds over USB;
/// a YubiKey's touch timeout is about fifteen seconds. The floor sits low in
/// that gap, so a virtual card with a shortened touch timeout (fibby's
/// `--touch-timeout-ms`, a few hundred milliseconds in the tests) still
/// reads as a touch timeout.
pub const TOUCH_TIMEOUT_FLOOR: Duration = Duration::from_millis(250);

/// What a 0x6982 from a private-key operation means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityStatusRefusal {
    /// The card waited for a touch and gave up.
    TouchTimedOut,
    /// The card refused at once: the PIN state it needed was not there.
    PinStateNotSatisfied,
}

/// Classify a 0x6982 from an operation that took `elapsed`, on a slot that
/// `needs_touch` or not. A slot that needs no touch never waits for one.
pub fn classify(elapsed: Duration, needs_touch: bool) -> SecurityStatusRefusal {
    if needs_touch && elapsed >= TOUCH_TIMEOUT_FLOOR {
        SecurityStatusRefusal::TouchTimedOut
    } else {
        SecurityStatusRefusal::PinStateNotSatisfied
    }
}

/// The operator-facing reason for a refusal that took `elapsed`.
pub fn describe(refusal: SecurityStatusRefusal, elapsed: Duration) -> String {
    match refusal {
        SecurityStatusRefusal::TouchTimedOut => format!(
            "the card was not touched in time (it gave up waiting after {:.1} s)",
            elapsed.as_secs_f64()
        ),
        SecurityStatusRefusal::PinStateNotSatisfied => format!(
            "the card refused the operation after {} ms with SW=0x6982 (security status not \
             satisfied): too soon to be a missed touch, so the verified PIN was no longer in force",
            elapsed.as_millis()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_wait_on_a_touch_slot_is_a_touch_timeout() {
        for wait in [Duration::from_secs(15), Duration::from_millis(400)] {
            assert_eq!(
                classify(wait, true),
                SecurityStatusRefusal::TouchTimedOut,
                "{wait:?}"
            );
        }
    }

    #[test]
    fn an_immediate_refusal_is_a_lost_pin_state() {
        assert_eq!(
            classify(Duration::from_millis(40), true),
            SecurityStatusRefusal::PinStateNotSatisfied
        );
    }

    #[test]
    fn a_slot_without_touch_never_reads_as_a_touch_timeout() {
        assert_eq!(
            classify(Duration::from_secs(30), false),
            SecurityStatusRefusal::PinStateNotSatisfied
        );
    }

    #[test]
    fn the_descriptions_name_what_to_do_differently() {
        let touch = describe(
            SecurityStatusRefusal::TouchTimedOut,
            Duration::from_secs(15),
        );
        assert!(touch.contains("not touched in time"), "{touch}");
        let pin = describe(
            SecurityStatusRefusal::PinStateNotSatisfied,
            Duration::from_millis(40),
        );
        assert!(pin.contains("0x6982") && pin.contains("40 ms"), "{pin}");
        assert!(!pin.contains("not touched"), "{pin}");
    }
}
