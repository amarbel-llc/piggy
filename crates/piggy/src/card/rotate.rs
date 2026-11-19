//! `piggy card rotate-admin`: a card's management-key rotation as one verb,
//! over the seams `card init` seals with (FDR 0006 card provisioning beside
//! piggy#258's escrow; the design is
//! `docs/plans/2026-11-19-card-rotate-admin-design.md`; circus#448 is the
//! later rotation the shell wrapper could not do).
//!
//! Pure: the card ([`RotateCard`]), the store ([`RotateStore`]), the
//! operator ([`Frontend`]) and the randomness come in as traits and
//! closures, so every row of the state table and every stop is a unit test
//! over mocks; the real card, store and frontend are `rotate_cmd`'s.
//!
//! The sequence, lettered as the operator's checklist is: (a) preflight
//! with nothing written and no PIN, the recipients shown and the word
//! typed; (b) a new key in guarded memory; (c) sealed to the store and read
//! back once; (d) the card rotated from the current key, under one
//! transaction with (e) the proof that the new key authenticates; then the
//! proof that the old one no longer does, the escrow committed and, for a
//! later rotation, the pending entry promoted over the entry. The card is
//! written only with a key that has been read back from the store, so the
//! irreversible window (a card on a key nobody holds) is closed before the
//! write. Where to start is read from the state (the entry, the pending
//! entry, which key authenticates), never from a flag.
//!
//! The key never appears in a message, a TAP line, a progress event or the
//! confirm text: those carry names, counts and digests only.

use std::fmt;

use piggy_guard::GuardedBytes;
use piggy_piv::{DEFAULT_ADMIN_KEY, PivError};
use zeroize::Zeroizing;

use crate::card::protocol::{CardId, ConfirmRequest, Frontend, FrontendError, ProgressEvent};
use crate::card::seal::{KeyEscrow, ManagementKeySealer, check_escrow_recipients};

/// The word the operator types before the store is sealed to and the card
/// written (RFC 0006 §2.4 `word`).
pub const WORD: &str = "seal";

/// A later rotation seals the new key here, `<entry>.pending`, until the
/// card has taken it and the proof is in.
pub const PENDING_SUFFIX: &str = ".pending";

/// A 3-key 3DES management key.
pub const KEY_BYTES: usize = 24;

pub fn pending_name(entry: &str) -> String {
    format!("{entry}{PENDING_SUFFIX}")
}

/// Why the card did not take a rotation.
#[derive(Debug)]
pub enum RotateRefusal {
    /// The current key does not authenticate; the card is unchanged.
    CurrentRefused,
    /// SET MANAGEMENT KEY was refused; the card is still on the current key.
    SetRefused(PivError),
    /// The card accepted the new key and then did not authenticate with it.
    NewNotAccepted,
    /// Any other card failure (the card left, PC/SC).
    Card(PivError),
}

/// The card, as the rotation drives it. Each authentication is its own
/// PC/SC transaction; a rotation and its proof are one.
pub trait RotateCard {
    /// Whether `key` is the card's management key. Nothing is written and no
    /// PIN is asked; a wrong key is `Ok(false)`, never an error.
    fn authenticates(&mut self, key: &[u8]) -> Result<bool, PivError>;
    /// Under one transaction: authenticate with `current`, set `new`, and
    /// authenticate with `new`.
    fn rotate(&mut self, current: &[u8], new: &[u8]) -> Result<(), RotateRefusal>;
    /// Whether the card keeps its management key under the PIN, in the
    /// Printed Information object (YubiKey PIN-protected mode, piggy#198);
    /// `None` when the object cannot be read without a PIN.
    fn pin_protected_management_key(&mut self) -> Option<bool>;
}

/// The store, as the rotation uses it: `card init`'s sealer plus the three
/// questions and moves the state table needs.
pub trait RotateStore: ManagementKeySealer {
    /// Whether the entry `name` exists.
    fn exists(&self, name: &str) -> Result<bool, String>;
    /// Replace `entry` with `pending` in one rename and record it.
    fn promote(&self, pending: &str, entry: &str) -> Result<(), String>;
    /// Remove `name` and record it.
    fn remove(&self, name: &str) -> Result<(), String>;
}

/// The exit table (design note §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Stopped with nothing changed, for a reason the TAP names.
    Stopped = 1,
    Usage = 2,
    /// The store cannot seal, read or move what the rotation needs.
    Store = 3,
    /// The operator declined: the word was not typed, or a PIN prompt was
    /// cancelled.
    Declined = 4,
    /// The card refused, or is not a card this verb manages.
    Card = 5,
    /// The card is on a key piggy does not hold.
    Irreversible = 6,
}

impl Exit {
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// Why the rotation did not reach its end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stop {
    pub exit: Exit,
    pub message: String,
}

impl fmt::Display for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// One TAP-14 point of the rotation's account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    pub name: String,
    pub ok: bool,
    pub diags: Vec<(String, String)>,
}

/// What a finished rotation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Done {
    FirstRotation,
    /// A sealed, proven entry found with the card still on the factory key.
    FirstRotationResumed,
    LaterRotation,
    /// A pending entry found that read back, the card still on the entry's key.
    LaterRotationResumed,
    /// Only the promotion was left.
    Promoted,
}

/// The rotation's account: every point in order, then the outcome.
#[derive(Debug)]
pub struct Report {
    pub points: Vec<Point>,
    pub outcome: Result<Done, Stop>,
}

/// What the verb was asked for.
pub struct RotateConfig {
    pub card: CardId,
    /// The store entry, `piv/<GUID>/management-key` by default.
    pub entry: String,
}

/// A management key on guarded pages (FDR 0006 guarded memory): readable
/// only inside `with`, never a `String` or a `Vec` of its own.
pub struct Key(GuardedBytes);

impl Key {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != KEY_BYTES {
            return Err(format!(
                "a management key is {KEY_BYTES} bytes, not {}",
                bytes.len()
            ));
        }
        GuardedBytes::from_slice(bytes)
            .map(Key)
            .map_err(|e| format!("guarded memory: {e}"))
    }

    /// The store's spelling: 48 hex digits on one line.
    pub fn from_hex(text: &str) -> Result<Self, String> {
        let t = text.trim();
        if t.len() != 2 * KEY_BYTES || !t.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "not a 48-hex-digit management key ({} characters)",
                t.len()
            ));
        }
        let bytes = Zeroizing::new(hex::decode(t).map_err(|e| e.to_string())?);
        Self::from_bytes(&bytes)
    }

    /// A fresh key from `random`, which fills the guarded pages in place.
    pub fn random(random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>) -> Result<Self, String> {
        let mut guarded =
            GuardedBytes::zeroed(KEY_BYTES).map_err(|e| format!("guarded memory: {e}"))?;
        guarded
            .with_mut(|secret| random(secret))
            .map_err(|e| format!("guarded memory: {e}"))??;
        Ok(Key(guarded))
    }

    pub fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R, String> {
        self.0.with(f).map_err(|e| format!("guarded memory: {e}"))
    }

    /// The key as the store spells it, zeroized when dropped.
    pub fn hex(&self) -> Result<Zeroizing<String>, String> {
        self.with(|k| Zeroizing::new(hex::encode(k)))
    }
}

/// The whole rotation. `random` fills a buffer with random bytes.
pub fn rotate_admin(
    card: &mut dyn RotateCard,
    store: &dyn RotateStore,
    fe: &mut dyn Frontend,
    cfg: &RotateConfig,
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>,
) -> Report {
    let mut points = Vec::new();
    let outcome = run(card, store, fe, cfg, random, &mut points);
    Report { points, outcome }
}

fn ok(points: &mut Vec<Point>, name: &str, diags: &[(&str, String)]) {
    points.push(Point {
        name: name.into(),
        ok: true,
        diags: diags
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect(),
    });
}

fn stop(points: &mut Vec<Point>, name: &str, exit: Exit, message: String) -> Stop {
    points.push(Point {
        name: name.into(),
        ok: false,
        diags: vec![
            ("exit".into(), exit.code().to_string()),
            ("why".into(), message.clone()),
        ],
    });
    Stop { exit, message }
}

/// The exit a failed store read gets: the operator's no (a cancelled or
/// refused PIN prompt) is theirs, anything else is the store's. The store
/// reports the prompt's refusal in words, not a type, so the words decide.
fn recover_exit(error: &str) -> Exit {
    let lower = error.to_ascii_lowercase();
    if ["declin", "cancel", "refus", "askpass", "no pin"]
        .iter()
        .any(|w| lower.contains(w))
    {
        Exit::Declined
    } else {
        Exit::Store
    }
}

fn authenticates(
    card: &mut dyn RotateCard,
    key: &Key,
    points: &mut Vec<Point>,
    which: &str,
) -> Result<bool, Stop> {
    let answer = key.with(|k| card.authenticates(k)).map_err(|e| {
        stop(
            points,
            &format!("the card answers for the {which} key"),
            Exit::Stopped,
            e,
        )
    })?;
    answer.map_err(|e| {
        stop(
            points,
            &format!("the card answers for the {which} key"),
            Exit::Card,
            format!("card: {e}"),
        )
    })
}

/// Read a store entry back as a key. A declined prompt is the operator's
/// (exit 4); an entry that is missing or does not decrypt is the store's
/// (3); one that decrypts to something that is not a key is a stop (1), so
/// a caller can tell the three apart.
fn read_key(store: &dyn RotateStore, name: &str, points: &mut Vec<Point>) -> Result<Key, Stop> {
    let point = format!("the entry {name} reads back as a key");
    let text = store
        .recover(name)
        .map_err(|e| stop(points, &point, recover_exit(&e), format!("{name}: {e}")))?;
    let key = Key::from_hex(&text).map_err(|e| {
        stop(
            points,
            &point,
            Exit::Stopped,
            format!("{name} does not hold a management key: {e}"),
        )
    })?;
    ok(points, &point, &[]);
    Ok(key)
}

fn run(
    card: &mut dyn RotateCard,
    store: &dyn RotateStore,
    fe: &mut dyn Frontend,
    cfg: &RotateConfig,
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>,
    points: &mut Vec<Point>,
) -> Result<Done, Stop> {
    let entry = cfg.entry.as_str();
    let pending = pending_name(entry);
    let label = cfg.card.short_label();

    // The store's facts, with nothing read yet.
    let have_entry = store
        .exists(entry)
        .map_err(|e| stop(points, "the store answers for the entry", Exit::Store, e))?;
    let have_pending = store.exists(&pending).map_err(|e| {
        stop(
            points,
            "the store answers for the pending entry",
            Exit::Store,
            e,
        )
    })?;
    ok(
        points,
        "the store answers for the entry and its pending entry",
        &[
            ("entry", yes_no(have_entry)),
            ("pending", yes_no(have_pending)),
        ],
    );

    // A card that keeps its key under the PIN is keyed by a key the store
    // never held: not this verb's card, said before anything is sealed.
    match card.pin_protected_management_key() {
        Some(true) => {
            return Err(stop(
                points,
                "the management key is not PIN-protected",
                Exit::Card,
                format!(
                    "{label} keeps its management key under the PIN (PIN-protected management-key mode, piggy#198); rotate-admin manages a key sealed in the store, so it does not touch this card"
                ),
            ));
        }
        Some(false) => ok(points, "the management key is not PIN-protected", &[]),
        None => ok(
            points,
            "the management key is not PIN-protected",
            &[(
                "printed-information",
                "not readable without the PIN; the mode is not ruled out by the object, only by the keys below".into(),
            )],
        ),
    }

    let factory_key = Key::from_bytes(&DEFAULT_ADMIN_KEY)
        .map_err(|e| stop(points, "guarded memory", Exit::Stopped, e))?;
    let factory = authenticates(card, &factory_key, points, "factory")?;
    ok(
        points,
        "the card answers for the factory key",
        &[("authenticates", yes_no(factory))],
    );

    match (have_entry, have_pending, factory) {
        (false, false, true) => {
            seal_and_rotate(
                card,
                store,
                fe,
                cfg,
                random,
                points,
                entry,
                &factory_key,
                None,
            )?;
            Ok(Done::FirstRotation)
        }
        (true, false, true) => {
            // A first rotation that died between the seal and the card write.
            let sealed = read_key(store, entry, points)?;
            rotate_and_prove(card, points, &factory_key, &sealed, entry)?;
            Ok(Done::FirstRotationResumed)
        }
        (true, true, true) => Err(stop(
            points,
            "the state is one the rotation can finish",
            Exit::Stopped,
            format!(
                "{label} is on its factory key under both {entry} and {pending}: a card reset under a sealed store; inspect by hand, nothing changed"
            ),
        )),
        (true, _, false) => {
            let entry_key = read_key(store, entry, points)?;
            if authenticates(card, &entry_key, points, "entry")? {
                if have_pending {
                    match read_key(store, &pending, points) {
                        Ok(pending_key) => {
                            // A later rotation that died between the seal and
                            // the card write.
                            rotate_and_prove(card, points, &entry_key, &pending_key, &pending)?;
                            store.promote(&pending, entry).map_err(|e| {
                                stop(
                                    points,
                                    "the pending entry is promoted over the entry",
                                    Exit::Store,
                                    promote_failed(&pending, e),
                                )
                            })?;
                            ok(points, "the pending entry is promoted over the entry", &[]);
                            return Ok(Done::LaterRotationResumed);
                        }
                        Err(s) if s.exit == Exit::Declined => return Err(s),
                        Err(_) => {
                            // The entry still authenticates, so the pending key
                            // never reached the card: a pending entry that
                            // will not read back holds nothing and goes.
                            store.remove(&pending).map_err(|e| {
                                stop(
                                    points,
                                    "a pending entry that would not read back is removed",
                                    Exit::Store,
                                    e,
                                )
                            })?;
                            ok(
                                points,
                                "a pending entry that would not read back is removed",
                                &[],
                            );
                        }
                    }
                }
                seal_and_rotate(
                    card,
                    store,
                    fe,
                    cfg,
                    random,
                    points,
                    &pending,
                    &entry_key,
                    Some(entry),
                )?;
                Ok(Done::LaterRotation)
            } else if have_pending {
                let pending_key = read_key(store, &pending, points)?;
                if authenticates(card, &pending_key, points, "pending")? {
                    store.promote(&pending, entry).map_err(|e| {
                        stop(
                            points,
                            "the pending entry is promoted over the entry",
                            Exit::Store,
                            promote_failed(&pending, e),
                        )
                    })?;
                    ok(points, "the pending entry is promoted over the entry", &[]);
                    Ok(Done::Promoted)
                } else {
                    Err(irreversible(points, &label, &[entry, pending.as_str()]))
                }
            } else {
                Err(irreversible(points, &label, &[entry]))
            }
        }
        (false, true, _) => {
            let pending_key = read_key(store, &pending, points)?;
            if authenticates(card, &pending_key, points, "pending")? {
                store.promote(&pending, entry).map_err(|e| {
                    stop(
                        points,
                        "the pending entry is promoted over the entry",
                        Exit::Store,
                        promote_failed(&pending, e),
                    )
                })?;
                ok(points, "the pending entry is promoted over the entry", &[]);
                Ok(Done::Promoted)
            } else {
                Err(stop(
                    points,
                    "the state is one the rotation can finish",
                    Exit::Stopped,
                    format!(
                        "{pending} exists without {entry} and the card does not take its key: not a state this verb makes; inspect by hand, nothing changed (the pending entry is kept: nothing proves it dead)"
                    ),
                ))
            }
        }
        (false, false, false) => Err(irreversible(points, &label, &[])),
    }
}

fn yes_no(b: bool) -> String {
    if b { "yes" } else { "no" }.into()
}

fn promote_failed(pending: &str, e: String) -> String {
    format!(
        "{e}; the card is rotated and {pending} holds its key: run again to finish the promotion"
    )
}

fn irreversible(points: &mut Vec<Point>, label: &str, tried: &[&str]) -> Stop {
    let held = if tried.is_empty() {
        "the factory key".to_string()
    } else {
        format!("the factory key, and the key in {}", tried.join(" and in "))
    };
    stop(
        points,
        "a key piggy holds authenticates",
        Exit::Irreversible,
        format!(
            "{label} takes none of {held}: it is on a key piggy does not hold. Only a factory reset of the PIV applet, which destroys the 9A, 9C and 9D keys, would give it a known management key again; rotate-admin never does that. Do nothing to the card before telling whoever runs the sitting."
        ),
    )
}

/// Steps a to e for a rotation that needs a new key: the recipients, the
/// word, the key, the seal, the read-back, the rotation and its proofs. The
/// new key is sealed at `seal_name`; with `promote_to`, the entry it then
/// replaces.
#[allow(clippy::too_many_arguments)]
fn seal_and_rotate(
    card: &mut dyn RotateCard,
    store: &dyn RotateStore,
    fe: &mut dyn Frontend,
    cfg: &RotateConfig,
    random: &mut dyn FnMut(&mut [u8]) -> Result<(), String>,
    points: &mut Vec<Point>,
    seal_name: &str,
    current: &Key,
    promote_to: Option<&str>,
) -> Result<(), Stop> {
    let label = cfg.card.short_label();

    // a. The recipients, resolved (a pigpen pointer included) and shown.
    let mut escrow: Box<dyn KeyEscrow> = store
        .prepare(seal_name)
        .map_err(|e| stop(points, "the store can seal the new key", Exit::Store, e))?;
    check_escrow_recipients(escrow.recipients(), None)
        .map_err(|e| stop(points, "the store can seal the new key", Exit::Store, e))?;
    let n = escrow.recipients().len();
    ok(
        points,
        "the store can seal the new key",
        &[("entry", seal_name.into()), ("recipients", n.to_string())],
    );
    fe.progress(ProgressEvent {
        step: "recipients".into(),
        message: format!("{seal_name} would be sealed to {n} recipient key(s):"),
        current: None,
        total: None,
    });
    for recipient in escrow.recipients() {
        fe.progress(ProgressEvent {
            step: "recipient".into(),
            message: format!("  {}", recipient.to_wire()),
            current: None,
            total: None,
        });
    }

    // The word. A stray Enter is not a yes where a card write follows.
    let confirmed = fe
        .confirm(ConfirmRequest {
            message: format!(
                "Seal a NEW management key for {label} to {seal_name} (the {n} recipient key(s) above), then rotate the card to it?"
            ),
            default: Some(false),
            word: Some(WORD.into()),
        })
        .map_err(|e| stop(points, "the operator typed the word", Exit::Declined, declined(e)))?;
    if !confirmed {
        return Err(stop(
            points,
            "the operator typed the word",
            Exit::Declined,
            format!("not '{WORD}'; nothing changed"),
        ));
    }
    ok(points, "the operator typed the word", &[]);

    // b. The new key, on guarded pages.
    let new = Key::random(random)
        .map_err(|e| stop(points, "a new key is generated", Exit::Stopped, e))?;
    let new_hex = new
        .hex()
        .map_err(|e| stop(points, "a new key is generated", Exit::Stopped, e))?;
    ok(
        points,
        "a new key is generated",
        &[("bytes", KEY_BYTES.to_string())],
    );

    // c. Sealed, then read back once and compared; the card is untouched
    // until the store has proven it holds the key.
    escrow.seal(&new_hex).map_err(|e| {
        stop(
            points,
            "the new key is sealed",
            Exit::Store,
            format!("{e}; nothing changed on the card"),
        )
    })?;
    ok(
        points,
        "the new key is sealed",
        &[("entry", seal_name.into())],
    );
    match store.recover(seal_name) {
        Ok(back) if back.trim() == new_hex.as_str() => {
            ok(points, "the sealed copy reads back identical", &[]);
        }
        Ok(_) => {
            escrow.rollback();
            return Err(stop(
                points,
                "the sealed copy reads back identical",
                Exit::Stopped,
                format!(
                    "{seal_name} did not read back what was sealed; it is removed and the card is untouched"
                ),
            ));
        }
        Err(e) => {
            escrow.rollback();
            return Err(stop(
                points,
                "the sealed copy reads back identical",
                recover_exit(&e),
                format!("{seal_name}: {e}; it is removed and the card is untouched"),
            ));
        }
    }

    // d, e. The card, under one transaction; then the old key, and the record.
    rotate_and_prove(card, points, current, &new, seal_name)?;
    escrow.commit();
    if let Some(entry) = promote_to {
        store.promote(seal_name, entry).map_err(|e| {
            stop(
                points,
                "the pending entry is promoted over the entry",
                Exit::Store,
                promote_failed(seal_name, e),
            )
        })?;
        ok(
            points,
            "the pending entry is promoted over the entry",
            &[(
                "superseded",
                "gone from the tree; git history keeps it".into(),
            )],
        );
    }
    Ok(())
}

fn declined(e: FrontendError) -> String {
    match e {
        FrontendError::Declined(why) => format!("declined: {why}"),
        other => other.to_string(),
    }
}

/// d and e: rotate from `current` to `new` and prove both ways. `sealed_at`
/// names the entry that holds `new`, for the resume words.
fn rotate_and_prove(
    card: &mut dyn RotateCard,
    points: &mut Vec<Point>,
    current: &Key,
    new: &Key,
    sealed_at: &str,
) -> Result<(), Stop> {
    let rotated = current
        .with(|c| new.with(|n| card.rotate(c, n)))
        .map_err(|e| stop(points, "the card takes the new key", Exit::Stopped, e))?
        .map_err(|e| stop(points, "the card takes the new key", Exit::Stopped, e))?;
    match rotated {
        Ok(()) => ok(points, "the card takes the new key", &[]),
        Err(RotateRefusal::CurrentRefused) => {
            return Err(stop(
                points,
                "the card takes the new key",
                Exit::Card,
                format!(
                    "the current key no longer authenticates; the card is unchanged and {sealed_at} holds the sealed, proven new key: run again, the state table resumes from it"
                ),
            ));
        }
        Err(RotateRefusal::SetRefused(e)) => {
            return Err(stop(
                points,
                "the card takes the new key",
                Exit::Card,
                format!(
                    "the card refused the new key ({e}); it is still on the current key and {sealed_at} holds the sealed, proven new key: run again to resume"
                ),
            ));
        }
        Err(RotateRefusal::NewNotAccepted) => {
            let still_current = authenticates(card, current, points, "current")?;
            return Err(if still_current {
                stop(
                    points,
                    "the card takes the new key",
                    Exit::Card,
                    format!(
                        "the card accepted the new key and then did not authenticate with it, but still takes the current key: unchanged in effect; {sealed_at} holds the new key; run again"
                    ),
                )
            } else {
                stop(
                    points,
                    "the card takes the new key",
                    Exit::Irreversible,
                    format!(
                        "the card accepted the new key and authenticates with neither it nor the current key. {sealed_at} holds what was sent. Do nothing to the card before telling whoever runs the sitting; only a factory reset would recover a known key, and rotate-admin never does that"
                    ),
                )
            });
        }
        Err(RotateRefusal::Card(e)) => {
            return Err(stop(
                points,
                "the card takes the new key",
                Exit::Card,
                format!(
                    "card: {e}; check with `piggy tool -K @store:{sealed_at} auth-test` and `-K default auth-test` which key the card is on before running again"
                ),
            ));
        }
    }
    if authenticates(card, current, points, "old")? {
        return Err(stop(
            points,
            "the old key no longer authenticates",
            Exit::Card,
            "the card still takes the old key after taking the new one: not a card this verb understands; do not run again, inspect by hand".into(),
        ));
    }
    ok(points, "the old key no longer authenticates", &[]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::rc::Rc;

    use piggy_markl::{FormatId, Id, PurposeId};

    use super::*;
    use crate::card::protocol::{
        CardSelectRequest, CompletedEvent, MgmtKeyChoice, MgmtKeyRequest, SecretRequest,
    };

    const FACTORY: [u8; 24] = DEFAULT_ADMIN_KEY;
    const KEY_A: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7";
    const KEY_B: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7";
    const ENTRY: &str = "piv/0123456789ABCDEF0123456789ABCDEF/management-key";

    /// A card whose management key is `current`; the switches stand in for
    /// a card that misbehaves at one step.
    struct MockCard {
        current: Vec<u8>,
        pin_protected: Option<bool>,
        refuse_set: bool,
        drop_new: bool,
        log: Vec<String>,
    }

    impl MockCard {
        fn on(key: &[u8]) -> Self {
            MockCard {
                current: key.to_vec(),
                pin_protected: Some(false),
                refuse_set: false,
                drop_new: false,
                log: Vec::new(),
            }
        }
    }

    impl RotateCard for MockCard {
        fn authenticates(&mut self, key: &[u8]) -> Result<bool, PivError> {
            self.log.push("auth".into());
            Ok(key == self.current.as_slice())
        }
        fn rotate(&mut self, current: &[u8], new: &[u8]) -> Result<(), RotateRefusal> {
            self.log.push("rotate".into());
            if current != self.current.as_slice() {
                return Err(RotateRefusal::CurrentRefused);
            }
            if self.refuse_set {
                return Err(RotateRefusal::SetRefused(PivError::Apdu { sw: 0x6A80 }));
            }
            if self.drop_new {
                // The card took something, but not what was sent.
                self.current = vec![0xEE; 24];
                return Err(RotateRefusal::NewNotAccepted);
            }
            self.current = new.to_vec();
            Ok(())
        }
        fn pin_protected_management_key(&mut self) -> Option<bool> {
            self.pin_protected
        }
    }

    /// Entries by name: `Some(text)` reads back as that text, `None` is an
    /// entry that exists but decrypts to garbage.
    type Entries = Rc<RefCell<HashMap<String, Option<String>>>>;

    struct MockStore {
        entries: Entries,
        decline_reads: bool,
        corrupt_on_seal: bool,
        log: RefCell<Vec<String>>,
    }

    impl MockStore {
        fn new() -> Self {
            MockStore {
                entries: Rc::new(RefCell::new(HashMap::new())),
                decline_reads: false,
                corrupt_on_seal: false,
                log: RefCell::new(Vec::new()),
            }
        }
        fn with(self, name: &str, text: Option<&str>) -> Self {
            self.entries
                .borrow_mut()
                .insert(name.into(), text.map(str::to_owned));
            self
        }
        fn text(&self, name: &str) -> Option<String> {
            self.entries.borrow().get(name).cloned().flatten()
        }
        fn has(&self, name: &str) -> bool {
            self.entries.borrow().contains_key(name)
        }
    }

    struct MockEscrow {
        entries: Entries,
        name: String,
        corrupt: bool,
        recipients: Vec<Id>,
        log: Rc<RefCell<Vec<String>>>,
    }

    impl KeyEscrow for MockEscrow {
        fn pass_name(&self) -> &str {
            &self.name
        }
        fn recipients(&self) -> &[Id] {
            &self.recipients
        }
        fn seal(&mut self, key_hex: &str) -> Result<(), String> {
            let stored = if self.corrupt {
                "deadbeef".repeat(6)
            } else {
                format!("{key_hex}\n")
            };
            self.entries
                .borrow_mut()
                .insert(self.name.clone(), Some(stored));
            self.log.borrow_mut().push(format!("seal {}", self.name));
            Ok(())
        }
        fn rollback(&mut self) {
            self.entries.borrow_mut().remove(&self.name);
            self.log
                .borrow_mut()
                .push(format!("rollback {}", self.name));
        }
        fn commit(&mut self) {
            self.log.borrow_mut().push(format!("commit {}", self.name));
        }
    }

    /// A real P-256 point, as the store's piggy-ids would spell a card's 9D.
    fn recipient() -> Id {
        use openssl::bn::BigNumContext;
        use openssl::ec::{EcGroup, EcKey, PointConversionForm};
        use openssl::nid::Nid;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let point = key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        Id::new(
            Some(PurposeId::PiggyRecipientV1),
            FormatId::PivyEcdhP256Pub,
            point,
        )
        .unwrap()
    }

    impl ManagementKeySealer for MockStore {
        fn prepare(&self, pass_name: &str) -> Result<Box<dyn KeyEscrow>, String> {
            if self.has(pass_name) {
                return Err(format!(
                    "{pass_name} already exists; refusing to overwrite it"
                ));
            }
            Ok(Box::new(MockEscrow {
                entries: Rc::clone(&self.entries),
                name: pass_name.into(),
                corrupt: self.corrupt_on_seal,
                recipients: vec![recipient()],
                log: Rc::new(RefCell::new(Vec::new())),
            }))
        }
        fn recover(&self, pass_name: &str) -> Result<Zeroizing<String>, String> {
            if self.decline_reads {
                return Err("the askpass refused to prompt".into());
            }
            match self.entries.borrow().get(pass_name) {
                Some(Some(text)) => Ok(Zeroizing::new(text.clone())),
                Some(None) => Ok(Zeroizing::new("not a key at all".into())),
                None => Err(format!("{pass_name}: no such entry")),
            }
        }
    }

    impl RotateStore for MockStore {
        fn exists(&self, name: &str) -> Result<bool, String> {
            Ok(self.has(name))
        }
        fn promote(&self, pending: &str, entry: &str) -> Result<(), String> {
            let mut entries = self.entries.borrow_mut();
            let value = entries
                .remove(pending)
                .ok_or_else(|| format!("{pending}: no such entry"))?;
            entries.insert(entry.into(), value);
            self.log
                .borrow_mut()
                .push(format!("promote {pending} -> {entry}"));
            Ok(())
        }
        fn remove(&self, name: &str) -> Result<(), String> {
            self.entries.borrow_mut().remove(name);
            self.log.borrow_mut().push(format!("remove {name}"));
            Ok(())
        }
    }

    struct TestFrontend {
        answers: VecDeque<bool>,
        confirms: Vec<ConfirmRequest>,
        progress: Vec<String>,
    }

    impl TestFrontend {
        fn answering(answers: &[bool]) -> Self {
            TestFrontend {
                answers: answers.iter().copied().collect(),
                confirms: Vec::new(),
                progress: Vec::new(),
            }
        }
    }

    impl Frontend for TestFrontend {
        fn request_secret(&mut self, _: SecretRequest) -> Result<Zeroizing<String>, FrontendError> {
            Err(FrontendError::Declined("no secret is asked here".into()))
        }
        fn request_mgmt_key(&mut self, _: MgmtKeyRequest) -> Result<MgmtKeyChoice, FrontendError> {
            Err(FrontendError::Declined("not used".into()))
        }
        fn confirm(&mut self, req: ConfirmRequest) -> Result<bool, FrontendError> {
            self.confirms.push(req);
            Ok(self.answers.pop_front().unwrap_or(false))
        }
        fn select_card(&mut self, _: CardSelectRequest) -> Result<String, FrontendError> {
            Err(FrontendError::Declined("not used".into()))
        }
        fn progress(&mut self, ev: ProgressEvent) {
            self.progress.push(ev.message);
        }
        fn completed(&mut self, _: CompletedEvent) {}
    }

    fn cfg() -> RotateConfig {
        RotateConfig {
            card: CardId {
                guid: "0123456789ABCDEF0123456789ABCDEF".into(),
                serial: Some(15909078),
                cn: None,
            },
            entry: ENTRY.into(),
        }
    }

    fn fixed_random() -> impl FnMut(&mut [u8]) -> Result<(), String> {
        |buf: &mut [u8]| {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = 0x10 + i as u8;
            }
            Ok(())
        }
    }

    const NEW_HEX: &str = "101112131415161718191a1b1c1d1e1f2021222324252627";

    fn run_with(card: &mut MockCard, store: &MockStore, fe: &mut TestFrontend) -> Report {
        let mut random = fixed_random();
        rotate_admin(card, store, fe, &cfg(), &mut random)
    }

    fn names(report: &Report) -> Vec<&str> {
        report.points.iter().map(|p| p.name.as_str()).collect()
    }

    fn no_key_anywhere(report: &Report, fe: &TestFrontend, store: &MockStore) {
        let everything = format!(
            "{:?} {:?} {:?} {:?}",
            report.points,
            fe.confirms,
            fe.progress,
            store.log.borrow()
        );
        let factory_hex = hex::encode(FACTORY);
        for secret in [NEW_HEX, KEY_A, KEY_B, factory_hex.as_str()] {
            assert!(!everything.contains(secret), "a key leaked: {everything}");
        }
    }

    #[test]
    fn a_first_rotation_seals_reads_back_rotates_and_proves() {
        let mut card = MockCard::on(&FACTORY);
        let store = MockStore::new();
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.as_ref().unwrap(), &Done::FirstRotation);
        assert!(report.points.iter().all(|p| p.ok), "{:?}", report.points);
        assert_eq!(store.text(ENTRY).unwrap().trim(), NEW_HEX);
        assert_eq!(card.current, hex::decode(NEW_HEX).unwrap());
        assert_eq!(
            card.log,
            ["auth", "rotate", "auth"],
            "factory probe, rotate+prove, old key"
        );
        let confirm = &fe.confirms[0];
        assert_eq!(confirm.word.as_deref(), Some(WORD));
        assert_eq!(confirm.default, Some(false));
        assert!(
            fe.progress.iter().any(|m| m.contains("1 recipient")),
            "{:?}",
            fe.progress
        );
        assert!(names(&report).contains(&"the old key no longer authenticates"));
        no_key_anywhere(&report, &fe, &store);
    }

    #[test]
    fn a_word_other_than_seal_stops_before_anything_is_sealed() {
        let mut card = MockCard::on(&FACTORY);
        let store = MockStore::new();
        let mut fe = TestFrontend::answering(&[false]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Declined);
        assert!(!store.has(ENTRY));
        assert_eq!(card.current, FACTORY.to_vec());
        assert_eq!(card.log, ["auth"], "nothing after the probe");
    }

    #[test]
    fn a_later_rotation_seals_at_pending_and_promotes_after_the_proof() {
        let key_a = hex::decode(KEY_A).unwrap();
        let mut card = MockCard::on(&key_a);
        let store = MockStore::new().with(ENTRY, Some(KEY_A));
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.as_ref().unwrap(), &Done::LaterRotation);
        assert_eq!(store.text(ENTRY).unwrap().trim(), NEW_HEX, "promoted");
        assert!(
            !store.has(&pending_name(ENTRY)),
            "the pending entry is gone"
        );
        assert_eq!(card.current, hex::decode(NEW_HEX).unwrap());
        let log = store.log.borrow();
        assert!(log.iter().any(|l| l.starts_with("promote")), "{log:?}");
        assert!(
            fe.confirms[0].message.contains(".pending"),
            "the word is asked for the pending entry: {}",
            fe.confirms[0].message
        );
        no_key_anywhere(&report, &fe, &store);
    }

    #[test]
    fn a_sealed_entry_with_the_card_still_on_the_factory_key_resumes_the_first_rotation() {
        let mut card = MockCard::on(&FACTORY);
        let store = MockStore::new().with(ENTRY, Some(KEY_A));
        let mut fe = TestFrontend::answering(&[]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(
            report.outcome.as_ref().unwrap(),
            &Done::FirstRotationResumed
        );
        assert_eq!(card.current, hex::decode(KEY_A).unwrap());
        assert!(fe.confirms.is_empty(), "no word: nothing new is sealed");
        assert_eq!(store.text(ENTRY).unwrap(), KEY_A);
    }

    #[test]
    fn a_readable_pending_entry_with_the_card_on_the_entry_resumes_the_later_rotation() {
        let key_a = hex::decode(KEY_A).unwrap();
        let mut card = MockCard::on(&key_a);
        let store = MockStore::new()
            .with(ENTRY, Some(KEY_A))
            .with(&pending_name(ENTRY), Some(KEY_B));
        let mut fe = TestFrontend::answering(&[]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(
            report.outcome.as_ref().unwrap(),
            &Done::LaterRotationResumed
        );
        assert_eq!(card.current, hex::decode(KEY_B).unwrap());
        assert_eq!(store.text(ENTRY).unwrap(), KEY_B);
        assert!(!store.has(&pending_name(ENTRY)));
    }

    #[test]
    fn a_corrupt_pending_entry_under_a_live_entry_is_removed_and_the_rotation_restarts() {
        let key_a = hex::decode(KEY_A).unwrap();
        let mut card = MockCard::on(&key_a);
        let store = MockStore::new()
            .with(ENTRY, Some(KEY_A))
            .with(&pending_name(ENTRY), None);
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.as_ref().unwrap(), &Done::LaterRotation);
        let log = store.log.borrow();
        assert!(log.iter().any(|l| l.starts_with("remove")), "{log:?}");
        assert_eq!(store.text(ENTRY).unwrap().trim(), NEW_HEX);
        assert!(names(&report).contains(&"a pending entry that would not read back is removed"));
    }

    #[test]
    fn a_pending_key_the_card_takes_is_promoted_and_nothing_else_happens() {
        let key_b = hex::decode(KEY_B).unwrap();
        let mut card = MockCard::on(&key_b);
        let store = MockStore::new()
            .with(ENTRY, Some(KEY_A))
            .with(&pending_name(ENTRY), Some(KEY_B));
        let mut fe = TestFrontend::answering(&[]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.as_ref().unwrap(), &Done::Promoted);
        assert_eq!(store.text(ENTRY).unwrap(), KEY_B);
        assert!(!card.log.contains(&"rotate".to_string()));

        // The same without an entry: the row the rename cannot produce but
        // the verb can finish.
        let mut card = MockCard::on(&key_b);
        let store = MockStore::new().with(&pending_name(ENTRY), Some(KEY_B));
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.as_ref().unwrap(), &Done::Promoted);
        assert_eq!(store.text(ENTRY).unwrap(), KEY_B);
    }

    #[test]
    fn a_card_on_a_key_nobody_holds_is_the_irreversible_state_named_in_words() {
        let mut card = MockCard::on(&[0x77; 24]);
        for store in [
            MockStore::new(),
            MockStore::new().with(ENTRY, Some(KEY_A)),
            MockStore::new()
                .with(ENTRY, Some(KEY_A))
                .with(&pending_name(ENTRY), Some(KEY_B)),
        ] {
            let mut fe = TestFrontend::answering(&[]);
            let report = run_with(&mut card, &store, &mut fe);
            let stop = report.outcome.unwrap_err();
            assert_eq!(stop.exit, Exit::Irreversible, "{stop}");
            assert!(stop.message.contains("factory reset"), "{stop}");
            assert!(stop.message.contains("never does that"), "{stop}");
            assert!(!card.log.contains(&"rotate".to_string()));
        }
    }

    #[test]
    fn a_pin_protected_card_is_refused_before_any_seal() {
        let mut card = MockCard::on(&[0x77; 24]);
        card.pin_protected = Some(true);
        let store = MockStore::new();
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Card);
        assert!(stop.message.contains("PIN-protected"), "{stop}");
        assert!(stop.message.contains("piggy#198"), "{stop}");
        assert!(
            card.log.is_empty(),
            "the gate speaks before any key is tried"
        );
        assert!(!store.has(ENTRY));

        // An unreadable object does not rule the mode out; the keys decide.
        let mut card = MockCard::on(&FACTORY);
        card.pin_protected = None;
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.as_ref().unwrap(), &Done::FirstRotation);
        assert!(report.points.iter().any(|p| {
            p.name == "the management key is not PIN-protected"
                && p.diags.iter().any(|(k, _)| k == "printed-information")
        }));
    }

    #[test]
    fn a_refused_set_leaves_the_card_unchanged_and_the_entry_sealed_for_the_resume() {
        let mut card = MockCard::on(&FACTORY);
        card.refuse_set = true;
        let store = MockStore::new();
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Card);
        assert!(stop.message.contains("run again"), "{stop}");
        assert_eq!(card.current, FACTORY.to_vec());
        assert_eq!(
            store.text(ENTRY).unwrap().trim(),
            NEW_HEX,
            "the entry stays: the resume row"
        );
    }

    #[test]
    fn a_card_that_drops_the_new_key_is_irreversible_unless_the_old_one_still_works() {
        let mut card = MockCard::on(&FACTORY);
        card.drop_new = true;
        let store = MockStore::new();
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Irreversible, "{stop}");
        assert!(stop.message.contains("neither"), "{stop}");
    }

    #[test]
    fn a_cancelled_pin_at_the_read_back_is_the_operators_no_and_rolls_the_seal_back() {
        let mut card = MockCard::on(&FACTORY);
        let mut store = MockStore::new();
        store.decline_reads = true;
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Declined, "{stop}");
        assert!(!store.has(ENTRY), "rolled back");
        assert_eq!(card.current, FACTORY.to_vec());
        assert!(stop.message.contains("card is untouched"), "{stop}");
    }

    #[test]
    fn a_read_back_that_differs_stops_with_the_entry_removed_and_the_card_untouched() {
        let mut card = MockCard::on(&FACTORY);
        let mut store = MockStore::new();
        store.corrupt_on_seal = true;
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Stopped, "{stop}");
        assert!(!store.has(ENTRY));
        assert_eq!(card.current, FACTORY.to_vec());
        assert!(!card.log.contains(&"rotate".to_string()));
    }

    #[test]
    fn a_card_reset_under_a_sealed_store_stops_for_a_human() {
        let mut card = MockCard::on(&FACTORY);
        let store = MockStore::new()
            .with(ENTRY, Some(KEY_A))
            .with(&pending_name(ENTRY), Some(KEY_B));
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Stopped);
        assert!(stop.message.contains("inspect by hand"), "{stop}");
        assert_eq!(card.log, ["auth"]);
    }

    #[test]
    fn the_exit_table_and_the_key_spellings() {
        assert_eq!(Exit::Stopped.code(), 1);
        assert_eq!(Exit::Usage.code(), 2);
        assert_eq!(Exit::Store.code(), 3);
        assert_eq!(Exit::Declined.code(), 4);
        assert_eq!(Exit::Card.code(), 5);
        assert_eq!(Exit::Irreversible.code(), 6);
        assert_eq!(pending_name(ENTRY), format!("{ENTRY}.pending"));
        assert!(Key::from_hex("0102").is_err());
        assert!(Key::from_hex(&"zz".repeat(24)).is_err());
        let key = Key::from_hex(&format!("  {KEY_A}\n")).unwrap();
        assert_eq!(key.hex().unwrap().as_str(), KEY_A);
        assert_eq!(
            recover_exit("the askpass refused to prompt"),
            Exit::Declined
        );
        assert_eq!(
            recover_exit("interaction declined: cancelled"),
            Exit::Declined
        );
        assert_eq!(recover_exit("no such entry"), Exit::Store);
    }
}
