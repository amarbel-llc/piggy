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
//! with nothing written: the recipients resolved and shown, then the word
//! typed; (b) a new key on guarded pages; (c) sealed to the store and read
//! back once (the 9D PIN asked through the frontend, so the operator's no
//! is typed, never a string to match); (d) the card rotated from the
//! current key, under one transaction with (e) the proof that the new key
//! authenticates; then the proof that the old one no longer does, the
//! entry recorded in git and, for a later rotation, the pending entry
//! promoted over the entry. Every card write is behind the word, a resumed
//! run's too. The card is written only with a key that has been read back
//! from the store, so the irreversible window (a card on a key nobody
//! holds) is closed before the write. Where to start is read from the
//! state (the entry, the pending entry, which key authenticates), never
//! from a flag.
//!
//! The key lives on guarded pages ([`Key`]); the one copy the store takes
//! is its hex spelling in a `Zeroizing<String>`, zeroized when dropped. No
//! key ever appears in a message, a TAP line, a progress event or the
//! confirm text: those carry names, counts and digests only.

use std::fmt;

use piggy_guard::GuardedBytes;
use piggy_markl::Id;
use piggy_piv::{DEFAULT_ADMIN_KEY, PivError};
use zeroize::Zeroizing;

use crate::card::protocol::{
    CardId, ConfirmRequest, Frontend, FrontendError, ProgressEvent, SecretKind, SecretRequest,
};
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

/// Whether a card keeps its management key under the PIN (a YubiKey's
/// PIN-protected mode: the key escrowed in the Printed Information object,
/// piggy#198), as far as the object can be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinProtection {
    /// The object was read and holds no escrowed key, or does not exist.
    No,
    /// The object was read and holds the escrowed key.
    Yes,
    /// The object is behind the PIN; a read after `verify_pin` decides.
    NeedsPin,
    /// The object could not be read for another reason.
    Unreadable(String),
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
    /// The PIN-protected question without a PIN.
    fn pin_protection(&mut self) -> PinProtection;
    /// The same question with the PIN verified first.
    fn pin_protection_with_pin(&mut self, pin: &str) -> Result<PinProtection, PivError>;
}

/// What git made of a change under the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    Committed,
    /// The store is not a git work tree: nothing to commit.
    NoGitStore,
    /// The tree holds the change and git did not commit it.
    CommitFailed(String),
}

/// The store, as the rotation uses it: `card init`'s sealer plus the
/// questions and moves the state table needs. Every read of a key goes
/// through [`RotateStore::recover_with_pin`] with a PIN the rotation asked
/// for itself, so the operator's refusal reaches it typed.
pub trait RotateStore: ManagementKeySealer {
    /// Whether the entry `name` exists.
    fn exists(&self, name: &str) -> Result<bool, String>;
    /// The recipients an entry at `name` would be sealed to, resolved (a
    /// pigpen pointer included), without preparing anything.
    fn recipients_for(&self, name: &str) -> Result<Vec<Id>, String>;
    /// The entry's first line, decrypted on the local card with `pin`.
    fn recover_with_pin(&self, name: &str, pin: &str) -> Result<Zeroizing<String>, String>;
    /// Record an entry the escrow wrote.
    fn record(&self, name: &str, message: &str) -> Recorded;
    /// Replace `entry` with `pending` in one rename and record it.
    fn promote(&self, pending: &str, entry: &str) -> Result<Recorded, String>;
    /// Remove `name` and record it.
    fn remove(&self, name: &str) -> Result<Recorded, String>;
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
    let mut run = Run {
        card,
        store,
        fe,
        cfg,
        random,
        points: Vec::new(),
        pin: None,
        gate: PinProtection::Unreadable("not asked yet".into()),
    };
    let outcome = run.run();
    Report {
        points: run.points,
        outcome,
    }
}

/// One rotation in progress: the seams, the account so far, the PIN once
/// asked (one prompt serves every store read of the run), and the
/// PIN-protected gate's PIN-free answer.
struct Run<'a> {
    card: &'a mut dyn RotateCard,
    store: &'a dyn RotateStore,
    fe: &'a mut dyn Frontend,
    cfg: &'a RotateConfig,
    random: &'a mut dyn FnMut(&mut [u8]) -> Result<(), String>,
    points: Vec<Point>,
    pin: Option<Zeroizing<String>>,
    gate: PinProtection,
}

fn yes_no(b: bool) -> String {
    if b { "yes" } else { "no" }.into()
}

fn recorded_diag(recorded: &Recorded) -> (&'static str, String) {
    match recorded {
        Recorded::Committed => ("git", "committed".into()),
        Recorded::NoGitStore => (
            "git",
            "the store is not a git work tree: nothing to commit".into(),
        ),
        Recorded::CommitFailed(why) => (
            "git",
            format!(
                "COMMIT FAILED ({why}): the tree holds the change; run `piggy pass git status` and commit by hand before anything else uses the store"
            ),
        ),
    }
}

impl Run<'_> {
    fn label(&self) -> String {
        self.cfg.card.short_label()
    }

    fn ok(&mut self, name: &str, diags: &[(&str, String)]) {
        self.points.push(Point {
            name: name.into(),
            ok: true,
            diags: diags
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        });
    }

    /// An ok point that also carries what git made of a store change, said
    /// loudly on the frontend when git did not commit.
    fn ok_recorded(&mut self, name: &str, recorded: &Recorded, more: &[(&str, String)]) {
        let diag = recorded_diag(recorded);
        if matches!(recorded, Recorded::CommitFailed(_)) {
            self.fe.progress(ProgressEvent {
                step: "git-warning".into(),
                message: format!("{name}: {}", diag.1),
                current: None,
                total: None,
            });
        }
        let mut diags: Vec<(&str, String)> = more.to_vec();
        diags.push(diag);
        self.ok(name, &diags);
    }

    fn stop(&mut self, name: &str, exit: Exit, message: String) -> Stop {
        self.points.push(Point {
            name: name.into(),
            ok: false,
            diags: vec![
                ("exit".into(), exit.code().to_string()),
                ("why".into(), message.clone()),
            ],
        });
        Stop { exit, message }
    }

    fn progress(&mut self, step: &str, message: String) {
        self.fe.progress(ProgressEvent {
            step: step.into(),
            message,
            current: None,
            total: None,
        });
    }

    /// The card's PIN, asked once through the frontend (typed: a refusal is
    /// the operator's, exit 4) and kept for the run.
    fn pin(&mut self, why: &str, point: &str) -> Result<Zeroizing<String>, Stop> {
        if let Some(pin) = &self.pin {
            return Ok(pin.clone());
        }
        let request = SecretRequest {
            kind: SecretKind::CurrentPin,
            prompt: format!("PIN for {} to {why}", self.label()),
            card: Some(self.cfg.card.clone()),
            slot: Some("9d".into()),
            attempts_remaining: None,
        };
        let pin = match self.fe.request_secret(request) {
            Ok(pin) => pin,
            Err(FrontendError::Declined(why)) => {
                return Err(self.stop(
                    point,
                    Exit::Declined,
                    format!("the PIN prompt was declined: {why}"),
                ));
            }
            Err(e) => {
                return Err(self.stop(
                    point,
                    Exit::Stopped,
                    format!("the PIN could not be asked for: {e}"),
                ));
            }
        };
        self.pin = Some(pin.clone());
        Ok(pin)
    }

    fn authenticates(&mut self, key: &Key, which: &str) -> Result<bool, Stop> {
        let point = format!("the card answers for the {which} key");
        let card = &mut *self.card;
        let answer = key.with(|k| card.authenticates(k));
        let answer = match answer {
            Ok(a) => a,
            Err(e) => return Err(self.stop(&point, Exit::Stopped, e)),
        };
        answer.map_err(|e| self.stop(&point, Exit::Card, format!("card: {e}")))
    }

    /// Read a store entry back as a key: the PIN through the frontend
    /// (declined: exit 4), the decrypt on the local card (failed: exit 3),
    /// the text a key (not one: exit 1), so the three are told apart.
    fn read_key(&mut self, name: &str) -> Result<Key, Stop> {
        let point = format!("the entry {name} reads back as a key");
        let pin = self.pin(&format!("read {name} back from the store"), &point)?;
        let text = match self.store.recover_with_pin(name, &pin) {
            Ok(text) => text,
            Err(e) => {
                return Err(self.stop(
                    &point,
                    Exit::Store,
                    format!("{name} did not decrypt here: {e}"),
                ));
            }
        };
        let key = match Key::from_hex(&text) {
            Ok(key) => key,
            Err(e) => {
                return Err(self.stop(
                    &point,
                    Exit::Stopped,
                    format!("{name} does not hold a management key: {e}"),
                ));
            }
        };
        self.ok(&point, &[]);
        Ok(key)
    }

    /// The typed word (RFC 0006 §2.4). Every card write is behind one.
    fn word(&mut self, message: String) -> Result<(), Stop> {
        const POINT: &str = "the operator typed the word";
        let confirmed = match self.fe.confirm(ConfirmRequest {
            message,
            default: Some(false),
            word: Some(WORD.into()),
        }) {
            Ok(c) => c,
            Err(FrontendError::Declined(why)) => {
                return Err(self.stop(POINT, Exit::Declined, format!("declined: {why}")));
            }
            Err(e) => return Err(self.stop(POINT, Exit::Stopped, e.to_string())),
        };
        if !confirmed {
            return Err(self.stop(
                POINT,
                Exit::Declined,
                format!("not '{WORD}'; nothing changed"),
            ));
        }
        self.ok(POINT, &[]);
        Ok(())
    }

    fn run(&mut self) -> Result<Done, Stop> {
        let entry = self.cfg.entry.clone();
        let pending = pending_name(&entry);
        let label = self.label();

        // The store's facts, with nothing read yet.
        let have_entry = match self.store.exists(&entry) {
            Ok(b) => b,
            Err(e) => return Err(self.stop("the store answers for the entry", Exit::Store, e)),
        };
        let have_pending = match self.store.exists(&pending) {
            Ok(b) => b,
            Err(e) => {
                return Err(self.stop("the store answers for the pending entry", Exit::Store, e));
            }
        };
        self.ok(
            "the store answers for the entry and its pending entry",
            &[
                ("entry", yes_no(have_entry)),
                ("pending", yes_no(have_pending)),
            ],
        );

        // A card that keeps its key under the PIN is keyed by a key the store
        // never held: not this verb's card. Asked without a PIN first; on a
        // YubiKey the object is behind the PIN, so the answer is often
        // "needs the PIN", and the keys below decide; the question is asked
        // again, with the PIN, only before the irreversible verdict.
        const GATE: &str = "the management key is not PIN-protected";
        self.gate = self.card.pin_protection();
        match self.gate.clone() {
            PinProtection::Yes => return Err(self.pin_protected_stop(GATE)),
            PinProtection::No => self.ok(GATE, &[]),
            PinProtection::NeedsPin => self.ok(
                GATE,
                &[("printed-information", "behind the PIN; read again with it only if no key piggy holds authenticates".into())],
            ),
            PinProtection::Unreadable(why) => self.ok(
                GATE,
                &[("printed-information", format!("not readable ({why}); the mode is ruled out by the keys below, not by the object"))],
            ),
        }

        let factory_key = Key::from_bytes(&DEFAULT_ADMIN_KEY)
            .map_err(|e| self.stop("guarded memory", Exit::Stopped, e))?;
        let factory = self.authenticates(&factory_key, "factory")?;
        self.ok(
            "the card answers for the factory key",
            &[("authenticates", yes_no(factory))],
        );

        match (have_entry, have_pending, factory) {
            (false, false, true) => {
                self.seal_and_rotate(&entry, &factory_key, None, false)?;
                Ok(Done::FirstRotation)
            }
            (true, false, true) => {
                // A first rotation that died between the seal and the card write.
                let sealed = self.read_key(&entry)?;
                self.word(format!(
                    "Rotate {label} from the factory management key to the key sealed at {entry} in an earlier run (it read back as a key), then prove it?"
                ))?;
                self.rotate_and_prove(&factory_key, &sealed, &entry)?;
                Ok(Done::FirstRotationResumed)
            }
            (true, true, true) => Err(self.stop(
                "the state is one the rotation can finish",
                Exit::Stopped,
                format!("{label} is on its factory key under both {entry} and {pending}: a card reset under a sealed store; inspect by hand, nothing changed"),
            )),
            (true, _, false) => {
                let entry_key = self.read_key(&entry)?;
                if self.authenticates(&entry_key, "entry")? {
                    if have_pending {
                        match self.read_key(&pending) {
                            Ok(pending_key) => {
                                // A later rotation that died between the seal and
                                // the card write.
                                self.word(format!(
                                    "Rotate {label} from the key at {entry} to the key sealed at {pending} in an earlier run (it read back as a key), prove it, and promote {pending} over {entry}?"
                                ))?;
                                self.rotate_and_prove(&entry_key, &pending_key, &pending)?;
                                self.promote(&pending, &entry)?;
                                return Ok(Done::LaterRotationResumed);
                            }
                            Err(s) if s.exit == Exit::Declined => return Err(s),
                            Err(_) => {
                                // The entry still authenticates, so the pending
                                // key never reached the card: a pending entry
                                // that will not read back holds nothing. It goes
                                // after the word, with the rest of the writes.
                                self.seal_and_rotate(&pending, &entry_key, Some(entry.as_str()), true)?;
                                return Ok(Done::LaterRotation);
                            }
                        }
                    }
                    self.seal_and_rotate(&pending, &entry_key, Some(entry.as_str()), false)?;
                    Ok(Done::LaterRotation)
                } else if have_pending {
                    let pending_key = self.read_key(&pending)?;
                    if self.authenticates(&pending_key, "pending")? {
                        self.promote(&pending, &entry)?;
                        Ok(Done::Promoted)
                    } else {
                        Err(self.irreversible(&[entry.as_str(), pending.as_str()]))
                    }
                } else {
                    Err(self.irreversible(&[entry.as_str()]))
                }
            }
            (false, true, _) => {
                let pending_key = self.read_key(&pending)?;
                if self.authenticates(&pending_key, "pending")? {
                    self.promote(&pending, &entry)?;
                    Ok(Done::Promoted)
                } else {
                    Err(self.stop(
                        "the state is one the rotation can finish",
                        Exit::Stopped,
                        format!("{pending} exists without {entry} and the card does not take its key: not a state this verb makes; inspect by hand, nothing changed (the pending entry is kept: nothing proves it dead)"),
                    ))
                }
            }
            (false, false, false) => Err(self.irreversible(&[])),
        }
    }

    fn pin_protected_stop(&mut self, point: &str) -> Stop {
        let label = self.label();
        self.stop(
            point,
            Exit::Card,
            format!("{label} keeps its management key under the PIN (PIN-protected management-key mode, piggy#198): that key is recoverable with the PIN through the card's own tooling, and rotate-admin, which manages a key sealed in the store, does not touch this card"),
        )
    }

    /// The verdict when no key piggy holds authenticates: first the
    /// PIN-protected question with the PIN, when the object needed it,
    /// because for that card the key is recoverable and "factory reset" would
    /// be the wrong word.
    fn irreversible(&mut self, tried: &[&str]) -> Stop {
        const POINT: &str = "a key piggy holds authenticates";
        let label = self.label();
        let mut caveat = String::new();
        if self.gate == PinProtection::NeedsPin {
            match self.pin("read the card's Printed Information object (is the management key kept under the PIN?)", POINT) {
                Ok(pin) => match self.card.pin_protection_with_pin(&pin) {
                    Ok(PinProtection::Yes) => return self.pin_protected_stop(POINT),
                    Ok(PinProtection::No) => {}
                    Ok(other) => caveat = unknown_mode_caveat(&format!("{other:?}")),
                    Err(e) => caveat = unknown_mode_caveat(&e.to_string()),
                },
                Err(stop) => return stop,
            }
        } else if !matches!(self.gate, PinProtection::No) {
            caveat = unknown_mode_caveat(&format!("{:?}", self.gate));
        }
        let held = if tried.is_empty() {
            "the factory key".to_string()
        } else {
            format!("the factory key, and the key in {}", tried.join(" and in "))
        };
        self.stop(
            POINT,
            Exit::Irreversible,
            format!(
                "{label} takes none of {held}: it is on a key piggy does not hold.{caveat} Only a factory reset of the PIV applet, which destroys the 9A, 9C and 9D keys, would give it a known management key again; rotate-admin never does that. Do nothing to the card before telling whoever runs the sitting."
            ),
        )
    }

    fn promote(&mut self, pending: &str, entry: &str) -> Result<(), Stop> {
        const POINT: &str = "the pending entry is promoted over the entry";
        match self.store.promote(pending, entry) {
            Ok(recorded) => {
                self.ok_recorded(
                    POINT,
                    &recorded,
                    &[("superseded", "gone from the tree; git history keeps it".into())],
                );
                Ok(())
            }
            Err(e) => Err(self.stop(
                POINT,
                Exit::Store,
                format!("{e}; the card is rotated and {pending} holds its key: run again to finish the promotion"),
            )),
        }
    }

    /// Steps a to e for a rotation that needs a new key: the recipients
    /// shown, the word, then every write: a pending entry that would not
    /// read back removed when `remove_pending_first`, the key sealed at
    /// `seal_name`, read back, the card rotated and proven, the entry
    /// recorded and, with `promote_to`, promoted over that entry.
    fn seal_and_rotate(
        &mut self,
        seal_name: &str,
        current: &Key,
        promote_to: Option<&str>,
        remove_pending_first: bool,
    ) -> Result<(), Stop> {
        let label = self.label();

        // a. The recipients, resolved (a pigpen pointer included) and shown,
        // before anything is written or asked.
        const RECIPIENTS: &str = "the store can seal the new key";
        let recipients = match self.store.recipients_for(seal_name) {
            Ok(r) => r,
            Err(e) => return Err(self.stop(RECIPIENTS, Exit::Store, e)),
        };
        if let Err(e) = check_escrow_recipients(&recipients, None) {
            return Err(self.stop(RECIPIENTS, Exit::Store, e));
        }
        let n = recipients.len();
        self.ok(
            RECIPIENTS,
            &[("entry", seal_name.into()), ("recipients", n.to_string())],
        );
        self.progress(
            "recipients",
            format!("{seal_name} would be sealed to {n} recipient key(s):"),
        );
        for recipient in &recipients {
            self.progress("recipient", format!("  {}", recipient.to_wire()));
        }

        // The word. A stray Enter is not a yes where a card write follows.
        let removal = if remove_pending_first {
            format!(" The unreadable pending entry {seal_name} is removed first.")
        } else {
            String::new()
        };
        self.word(format!(
            "Seal a NEW management key for {label} to {seal_name} (the {n} recipient key(s) above), then rotate the card to it?{removal}"
        ))?;

        if remove_pending_first {
            const REMOVED: &str = "a pending entry that would not read back is removed";
            match self.store.remove(seal_name) {
                Ok(recorded) => self.ok_recorded(REMOVED, &recorded, &[]),
                Err(e) => return Err(self.stop(REMOVED, Exit::Store, e)),
            }
        }

        let mut escrow: Box<dyn KeyEscrow> = match self.store.prepare(seal_name) {
            Ok(e) => e,
            Err(e) => return Err(self.stop("the store takes the new key", Exit::Store, e)),
        };

        // b. The new key, on guarded pages.
        const GENERATED: &str = "a new key is generated";
        let new = match Key::random(&mut *self.random) {
            Ok(k) => k,
            Err(e) => return Err(self.stop(GENERATED, Exit::Stopped, e)),
        };
        let new_hex = match new.hex() {
            Ok(h) => h,
            Err(e) => return Err(self.stop(GENERATED, Exit::Stopped, e)),
        };
        self.ok(GENERATED, &[("bytes", KEY_BYTES.to_string())]);

        // c. Sealed, then read back once and compared; the card is untouched
        // until the store has proven it holds the key.
        const SEALED: &str = "the new key is sealed";
        if let Err(e) = escrow.seal(&new_hex) {
            return Err(self.stop(
                SEALED,
                Exit::Store,
                format!("{e}; nothing changed on the card"),
            ));
        }
        self.ok(SEALED, &[("entry", seal_name.into())]);
        const READ_BACK: &str = "the sealed copy reads back identical";
        let pin = match self.pin(&format!("read {seal_name} back from the store"), READ_BACK) {
            Ok(pin) => pin,
            Err(stop) => {
                escrow.rollback();
                return Err(Stop {
                    message: format!(
                        "{}; {seal_name} is removed and the card is untouched",
                        stop.message
                    ),
                    ..stop
                });
            }
        };
        match self.store.recover_with_pin(seal_name, &pin) {
            Ok(back) if back.trim() == new_hex.as_str() => self.ok(READ_BACK, &[]),
            Ok(_) => {
                escrow.rollback();
                return Err(self.stop(
                    READ_BACK,
                    Exit::Stopped,
                    format!("{seal_name} did not read back what was sealed; it is removed and the card is untouched"),
                ));
            }
            Err(e) => {
                escrow.rollback();
                return Err(self.stop(
                    READ_BACK,
                    Exit::Store,
                    format!("{seal_name} did not decrypt here: {e}; it is removed and the card is untouched"),
                ));
            }
        }

        // d, e. The card, under one transaction; then the old key, the
        // record and, for a later rotation, the promotion.
        self.rotate_and_prove(current, &new, seal_name)?;
        let recorded = self
            .store
            .record(seal_name, &format!("Seal management key to {seal_name}."));
        self.ok_recorded("the new key's entry is recorded", &recorded, &[]);
        if let Some(entry) = promote_to {
            self.promote(seal_name, entry)?;
        }
        Ok(())
    }

    /// d and e: rotate from `current` to `new` and prove both ways.
    /// `sealed_at` names the entry that holds `new`, for the resume words.
    fn rotate_and_prove(&mut self, current: &Key, new: &Key, sealed_at: &str) -> Result<(), Stop> {
        const POINT: &str = "the card takes the new key";
        let card = &mut *self.card;
        let rotated = current.with(|c| new.with(|n| card.rotate(c, n)));
        let rotated = match rotated {
            Ok(Ok(r)) => r,
            Ok(Err(e)) | Err(e) => return Err(self.stop(POINT, Exit::Stopped, e)),
        };
        match rotated {
            Ok(()) => self.ok(POINT, &[]),
            Err(RotateRefusal::CurrentRefused) => {
                return Err(self.stop(
                    POINT,
                    Exit::Card,
                    format!("the current key no longer authenticates; the card is unchanged and {sealed_at} holds the sealed, proven new key: run again, the state table resumes from it"),
                ));
            }
            Err(RotateRefusal::SetRefused(e)) => {
                return Err(self.stop(
                    POINT,
                    Exit::Card,
                    format!("the card refused the new key ({e}); it is still on the current key and {sealed_at} holds the sealed, proven new key: run again to resume"),
                ));
            }
            Err(RotateRefusal::NewNotAccepted) => {
                let still_current = self.authenticates(current, "current")?;
                return Err(if still_current {
                    self.stop(
                        POINT,
                        Exit::Card,
                        format!("the card accepted the new key and then did not authenticate with it, but still takes the current key: unchanged in effect; {sealed_at} holds the new key; run again"),
                    )
                } else {
                    self.stop(
                        POINT,
                        Exit::Irreversible,
                        format!("the card accepted the new key and authenticates with neither it nor the current key. {sealed_at} holds what was sent. Do nothing to the card before telling whoever runs the sitting; only a factory reset would recover a known key, and rotate-admin never does that"),
                    )
                });
            }
            Err(RotateRefusal::Card(e)) => {
                return Err(self.stop(
                    POINT,
                    Exit::Card,
                    format!("card: {e}; check with `piggy tool -K @store:{sealed_at} auth-test` and `-K default auth-test` which key the card is on before running again"),
                ));
            }
        }
        const OLD: &str = "the old key no longer authenticates";
        if self.authenticates(current, "old")? {
            return Err(self.stop(
                OLD,
                Exit::Card,
                "the card still takes the old key after taking the new one: not a card this verb understands; do not run again, inspect by hand".into(),
            ));
        }
        self.ok(OLD, &[]);
        Ok(())
    }
}

fn unknown_mode_caveat(why: &str) -> String {
    format!(
        " Whether it keeps its key under the PIN (PIN-protected management-key mode, piggy#198) could not be told ({why}); if it does, that key is recoverable with the PIN through the card's own tooling, and the rest of this sentence does not apply."
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{HashMap, VecDeque};
    use std::rc::Rc;

    use piggy_markl::{FormatId, PurposeId};

    use super::*;
    use crate::card::protocol::{CardSelectRequest, CompletedEvent, MgmtKeyChoice, MgmtKeyRequest};

    const FACTORY: [u8; 24] = DEFAULT_ADMIN_KEY;
    const KEY_A: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7";
    const KEY_B: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7";
    const ENTRY: &str = "piv/0123456789ABCDEF0123456789ABCDEF/management-key";
    const PIN: &str = "123456";

    /// A card whose management key is `current`; the switches stand in for
    /// a card that misbehaves at one step.
    struct MockCard {
        current: Vec<u8>,
        protection: PinProtection,
        protection_with_pin: PinProtection,
        refuse_set: bool,
        drop_new: bool,
        log: Vec<String>,
    }

    impl MockCard {
        fn on(key: &[u8]) -> Self {
            MockCard {
                current: key.to_vec(),
                protection: PinProtection::No,
                protection_with_pin: PinProtection::No,
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
        fn pin_protection(&mut self) -> PinProtection {
            self.log.push("pinfo".into());
            self.protection.clone()
        }
        fn pin_protection_with_pin(&mut self, pin: &str) -> Result<PinProtection, PivError> {
            self.log.push("pinfo-with-pin".into());
            if pin != PIN {
                return Err(PivError::PinIncorrect { retries: 2 });
            }
            Ok(self.protection_with_pin.clone())
        }
    }

    /// Entries by name: `Some(text)` reads back as that text, `None` is an
    /// entry that exists but decrypts to garbage.
    type Entries = Rc<RefCell<HashMap<String, Option<String>>>>;

    struct MockStore {
        entries: Entries,
        corrupt_on_seal: bool,
        commit_fails: bool,
        log: RefCell<Vec<String>>,
    }

    impl MockStore {
        fn new() -> Self {
            MockStore {
                entries: Rc::new(RefCell::new(HashMap::new())),
                corrupt_on_seal: false,
                commit_fails: false,
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
        fn recorded(&self) -> Recorded {
            if self.commit_fails {
                Recorded::CommitFailed("git exited 128".into())
            } else {
                Recorded::Committed
            }
        }
    }

    struct MockEscrow {
        entries: Entries,
        name: String,
        corrupt: bool,
        recipients: Vec<Id>,
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
            Ok(())
        }
        fn rollback(&mut self) {
            self.entries.borrow_mut().remove(&self.name);
        }
        fn commit(&mut self) {}
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
            self.log.borrow_mut().push(format!("prepare {pass_name}"));
            Ok(Box::new(MockEscrow {
                entries: Rc::clone(&self.entries),
                name: pass_name.into(),
                corrupt: self.corrupt_on_seal,
                recipients: vec![recipient()],
            }))
        }
        fn recover(&self, _: &str) -> Result<Zeroizing<String>, String> {
            Err("the rotation never reads through the askpass route".into())
        }
    }

    impl RotateStore for MockStore {
        fn exists(&self, name: &str) -> Result<bool, String> {
            Ok(self.has(name))
        }
        fn recipients_for(&self, name: &str) -> Result<Vec<Id>, String> {
            self.log.borrow_mut().push(format!("recipients {name}"));
            Ok(vec![recipient()])
        }
        fn recover_with_pin(&self, name: &str, pin: &str) -> Result<Zeroizing<String>, String> {
            if pin != PIN {
                return Err("unlock failed: wrong PIN, 2 retries remaining".into());
            }
            match self.entries.borrow().get(name) {
                Some(Some(text)) => Ok(Zeroizing::new(text.clone())),
                Some(None) => Ok(Zeroizing::new("not a key at all".into())),
                None => Err(format!("{name}: no such entry")),
            }
        }
        fn record(&self, name: &str, _message: &str) -> Recorded {
            self.log.borrow_mut().push(format!("record {name}"));
            self.recorded()
        }
        fn promote(&self, pending: &str, entry: &str) -> Result<Recorded, String> {
            let mut entries = self.entries.borrow_mut();
            let value = entries
                .remove(pending)
                .ok_or_else(|| format!("{pending}: no such entry"))?;
            entries.insert(entry.into(), value);
            self.log
                .borrow_mut()
                .push(format!("promote {pending} -> {entry}"));
            Ok(self.recorded())
        }
        fn remove(&self, name: &str) -> Result<Recorded, String> {
            self.entries.borrow_mut().remove(name);
            self.log.borrow_mut().push(format!("remove {name}"));
            Ok(self.recorded())
        }
    }

    /// The operator: the PIN it gives (or declines), the confirm answers, and
    /// one log of everything shown or asked, in order.
    struct TestFrontend {
        pin: Option<&'static str>,
        answers: VecDeque<bool>,
        confirms: Vec<ConfirmRequest>,
        log: Vec<String>,
    }

    impl TestFrontend {
        fn answering(answers: &[bool]) -> Self {
            TestFrontend {
                pin: Some(PIN),
                answers: answers.iter().copied().collect(),
                confirms: Vec::new(),
                log: Vec::new(),
            }
        }
        fn declining_the_pin(mut self) -> Self {
            self.pin = None;
            self
        }
    }

    impl Frontend for TestFrontend {
        fn request_secret(
            &mut self,
            req: SecretRequest,
        ) -> Result<Zeroizing<String>, FrontendError> {
            self.log.push(format!("secret:{:?}", req.kind));
            match self.pin {
                Some(pin) => Ok(Zeroizing::new(pin.to_owned())),
                None => Err(FrontendError::Declined("askpass refused".into())),
            }
        }
        fn request_mgmt_key(&mut self, _: MgmtKeyRequest) -> Result<MgmtKeyChoice, FrontendError> {
            Err(FrontendError::Declined("not used".into()))
        }
        fn confirm(&mut self, req: ConfirmRequest) -> Result<bool, FrontendError> {
            self.log.push("confirm".into());
            self.confirms.push(req);
            Ok(self.answers.pop_front().unwrap_or(false))
        }
        fn select_card(&mut self, _: CardSelectRequest) -> Result<String, FrontendError> {
            Err(FrontendError::Declined("not used".into()))
        }
        fn progress(&mut self, ev: ProgressEvent) {
            self.log
                .push(format!("progress:{}:{}", ev.step, ev.message));
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
            fe.log,
            store.log.borrow()
        );
        let factory_hex = hex::encode(FACTORY);
        for secret in [NEW_HEX, KEY_A, KEY_B, factory_hex.as_str(), PIN] {
            assert!(
                !everything.contains(secret),
                "a secret leaked: {everything}"
            );
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
            ["pinfo", "auth", "rotate", "auth"],
            "the gate, the factory probe, rotate+prove, the old key"
        );
        let confirm = &fe.confirms[0];
        assert_eq!(confirm.word.as_deref(), Some(WORD));
        assert_eq!(confirm.default, Some(false));
        // Shown, then asked, then written: recipients before the word, the
        // PIN after it (the read-back), nothing prepared before the word.
        let at = |needle: &str| fe.log.iter().position(|l| l.contains(needle)).unwrap();
        assert!(at("1 recipient") < at("confirm"), "{:?}", fe.log);
        assert!(at("confirm") < at("secret:CurrentPin"), "{:?}", fe.log);
        let store_log = store.log.borrow();
        let st = |needle: &str| store_log.iter().position(|l| l.contains(needle)).unwrap();
        assert!(st("recipients") < st("prepare"), "{store_log:?}");
        assert!(
            store_log.iter().any(|l| l.starts_with("record")),
            "{store_log:?}"
        );
        assert!(names(&report).contains(&"the old key no longer authenticates"));
        assert!(names(&report).contains(&"the new key's entry is recorded"));
        drop(store_log);
        no_key_anywhere(&report, &fe, &store);
    }

    #[test]
    fn a_word_other_than_seal_stops_before_anything_is_written() {
        let mut card = MockCard::on(&FACTORY);
        let store = MockStore::new();
        let mut fe = TestFrontend::answering(&[false]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Declined);
        assert!(!store.has(ENTRY));
        assert!(
            store
                .log
                .borrow()
                .iter()
                .all(|l| l.starts_with("recipients")),
            "{:?}",
            store.log.borrow()
        );
        assert_eq!(card.current, FACTORY.to_vec());
        assert_eq!(card.log, ["pinfo", "auth"], "nothing after the probe");
        assert!(
            !fe.log.iter().any(|l| l.starts_with("secret")),
            "no PIN asked"
        );
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
        drop(log);
        assert!(
            fe.confirms[0].message.contains(".pending"),
            "the word is asked for the pending entry: {}",
            fe.confirms[0].message
        );
        // One PIN prompt served both store reads (the entry, the read-back).
        assert_eq!(fe.log.iter().filter(|l| l.starts_with("secret")).count(), 1);
        no_key_anywhere(&report, &fe, &store);
    }

    #[test]
    fn a_resumed_rotation_asks_the_word_before_writing_the_card() {
        // A sealed entry with the card still on the factory key.
        let mut card = MockCard::on(&FACTORY);
        let store = MockStore::new().with(ENTRY, Some(KEY_A));
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(
            report.outcome.as_ref().unwrap(),
            &Done::FirstRotationResumed
        );
        assert_eq!(card.current, hex::decode(KEY_A).unwrap());
        assert_eq!(fe.confirms.len(), 1, "the word, for the resume");
        assert!(fe.confirms[0].message.contains("earlier run"));
        assert_eq!(store.text(ENTRY).unwrap(), KEY_A, "nothing new is sealed");

        // Declining the resume's word writes nothing.
        let mut card = MockCard::on(&FACTORY);
        let mut fe = TestFrontend::answering(&[false]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.unwrap_err().exit, Exit::Declined);
        assert_eq!(card.current, FACTORY.to_vec());

        // A readable pending entry with the card on the entry's key.
        let key_a = hex::decode(KEY_A).unwrap();
        let mut card = MockCard::on(&key_a);
        let store = MockStore::new()
            .with(ENTRY, Some(KEY_A))
            .with(&pending_name(ENTRY), Some(KEY_B));
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(
            report.outcome.as_ref().unwrap(),
            &Done::LaterRotationResumed
        );
        assert_eq!(card.current, hex::decode(KEY_B).unwrap());
        assert_eq!(store.text(ENTRY).unwrap(), KEY_B);
        assert!(!store.has(&pending_name(ENTRY)));
        assert_eq!(fe.confirms.len(), 1);
    }

    #[test]
    fn a_corrupt_pending_entry_under_a_live_entry_is_removed_after_the_word() {
        let key_a = hex::decode(KEY_A).unwrap();
        let mut card = MockCard::on(&key_a);
        let store = MockStore::new()
            .with(ENTRY, Some(KEY_A))
            .with(&pending_name(ENTRY), None);
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.as_ref().unwrap(), &Done::LaterRotation);
        let log = store.log.borrow();
        let at = |needle: &str| log.iter().position(|l| l.starts_with(needle)).unwrap();
        assert!(at("recipients") < at("remove"), "{log:?}");
        assert!(at("remove") < at("prepare"), "{log:?}");
        drop(log);
        assert!(fe.confirms[0].message.contains("removed first"));
        assert_eq!(store.text(ENTRY).unwrap().trim(), NEW_HEX);
        assert!(names(&report).contains(&"a pending entry that would not read back is removed"));

        // Declining the word leaves the corrupt pending entry in place.
        let mut card = MockCard::on(&key_a);
        let store = MockStore::new()
            .with(ENTRY, Some(KEY_A))
            .with(&pending_name(ENTRY), None);
        let mut fe = TestFrontend::answering(&[false]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.unwrap_err().exit, Exit::Declined);
        assert!(store.has(&pending_name(ENTRY)));
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
        assert!(fe.confirms.is_empty(), "no card write, no word");

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
            assert!(
                !stop.message.contains("could not be told"),
                "the gate said No: {stop}"
            );
            assert!(!card.log.contains(&"rotate".to_string()));
        }
    }

    #[test]
    fn a_pin_protected_card_is_refused_before_any_seal_or_named_before_any_factory_reset() {
        // The object readable without a PIN: refused at the gate.
        let mut card = MockCard::on(&[0x77; 24]);
        card.protection = PinProtection::Yes;
        let store = MockStore::new();
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Card);
        assert!(stop.message.contains("PIN-protected"), "{stop}");
        assert!(stop.message.contains("recoverable"), "{stop}");
        assert!(stop.message.contains("piggy#198"), "{stop}");
        assert_eq!(
            card.log,
            ["pinfo"],
            "the gate speaks before any key is tried"
        );
        assert!(!store.has(ENTRY));

        // The object behind the PIN (a YubiKey): the keys decide first; a
        // card on a key nobody holds is asked again, with the PIN, and the
        // PIN-protected one is named as recoverable, never as factory-reset.
        let mut card = MockCard::on(&[0x77; 24]);
        card.protection = PinProtection::NeedsPin;
        card.protection_with_pin = PinProtection::Yes;
        let mut fe = TestFrontend::answering(&[]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Card, "{stop}");
        assert!(stop.message.contains("PIN-protected"), "{stop}");
        assert!(!stop.message.contains("factory reset"), "{stop}");
        assert!(card.log.contains(&"pinfo-with-pin".to_string()));
        assert_eq!(fe.log.iter().filter(|l| l.starts_with("secret")).count(), 1);

        // Behind the PIN and not escrowed: irreversible, said plainly.
        let mut card = MockCard::on(&[0x77; 24]);
        card.protection = PinProtection::NeedsPin;
        card.protection_with_pin = PinProtection::No;
        let mut fe = TestFrontend::answering(&[]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Irreversible, "{stop}");
        assert!(!stop.message.contains("could not be told"), "{stop}");

        // The PIN declined at that question is the operator's no.
        let mut card = MockCard::on(&[0x77; 24]);
        card.protection = PinProtection::NeedsPin;
        let mut fe = TestFrontend::answering(&[]).declining_the_pin();
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.unwrap_err().exit, Exit::Declined);

        // An object that cannot be read at all: the mode stays a caveat in
        // the irreversible words, and a healthy card is not held up by it.
        let mut card = MockCard::on(&[0x77; 24]);
        card.protection = PinProtection::Unreadable("SW 6D00".into());
        let mut fe = TestFrontend::answering(&[]);
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Irreversible, "{stop}");
        assert!(stop.message.contains("could not be told"), "{stop}");
        let mut card = MockCard::on(&FACTORY);
        card.protection = PinProtection::Unreadable("SW 6D00".into());
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(report.outcome.as_ref().unwrap(), &Done::FirstRotation);
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
    fn a_declined_pin_at_the_read_back_is_the_operators_no_and_rolls_the_seal_back() {
        let mut card = MockCard::on(&FACTORY);
        let store = MockStore::new();
        let mut fe = TestFrontend::answering(&[true]).declining_the_pin();
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Declined, "{stop}");
        assert!(!store.has(ENTRY), "rolled back");
        assert_eq!(card.current, FACTORY.to_vec());
        assert!(stop.message.contains("card is untouched"), "{stop}");
        assert_eq!(
            report.points.last().unwrap().name,
            "the sealed copy reads back identical"
        );
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
    fn a_wrong_pin_at_the_read_back_is_the_stores_failure_not_the_operators_no() {
        let mut card = MockCard::on(&FACTORY);
        let store = MockStore::new();
        let mut fe = TestFrontend::answering(&[true]);
        fe.pin = Some("000000");
        let report = run_with(&mut card, &store, &mut fe);
        let stop = report.outcome.unwrap_err();
        assert_eq!(stop.exit, Exit::Store, "{stop}");
        assert!(stop.message.contains("did not decrypt"), "{stop}");
        assert!(!store.has(ENTRY), "rolled back");
        assert_eq!(card.current, FACTORY.to_vec());
    }

    #[test]
    fn a_git_commit_that_fails_is_said_on_the_point_and_the_frontend_not_hidden() {
        let key_a = hex::decode(KEY_A).unwrap();
        let mut card = MockCard::on(&key_a);
        let mut store = MockStore::new().with(ENTRY, Some(KEY_A));
        store.commit_fails = true;
        let mut fe = TestFrontend::answering(&[true]);
        let report = run_with(&mut card, &store, &mut fe);
        assert_eq!(
            report.outcome.as_ref().unwrap(),
            &Done::LaterRotation,
            "the rotation itself is done"
        );
        let promoted = report
            .points
            .iter()
            .find(|p| p.name == "the pending entry is promoted over the entry")
            .unwrap();
        assert!(promoted.ok);
        assert!(
            promoted
                .diags
                .iter()
                .any(|(k, v)| k == "git" && v.contains("COMMIT FAILED")),
            "{:?}",
            promoted.diags
        );
        assert!(
            fe.log.iter().any(|l| l.starts_with("progress:git-warning")),
            "{:?}",
            fe.log
        );
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
        assert_eq!(card.log, ["pinfo", "auth"]);
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
            recorded_diag(&Recorded::NoGitStore).1,
            "the store is not a git work tree: nothing to commit"
        );
    }
}
