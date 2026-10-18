//! `piggy card add-key` (FDR 0006) — the real-card driver that adds one key to
//! an already-provisioned card. Its purpose is giving an existing card the 9C
//! operator-act key without a reprovision; it also regenerates 9A when asked
//! to, and never touches 9D. The flow itself is [`engine::add_key`], reached
//! through the same [`SessionCard`] adapter and frontends as `card init`.

use std::path::Path;

use piggy_piv::PivError;

use piggy_piv::KeyPolicy;

use crate::card::RequestBinding;
use crate::card::engine::{self, AddKeyConfig, AddKeyOutcome, ProvisionError, StoredMgmtKey};
use crate::card::frontend::select::{FrontendKind, build_frontend};
use crate::card::init_cmd::{CardSelector, SessionCard, accepts_policies, select_provisioned_card};
use crate::card::protocol::Frontend;
use crate::card::seal::{ManagementKeySealer, default_pass_name};
use crate::card::slot_policy::{add_key_slot, key_policy_from_flags};

/// What the operator asked `add-key` for.
pub struct AddKeyArgs<'a> {
    /// `9c` or `9a`.
    pub slot: &'a str,
    pub pin_policy: Option<&'a str>,
    pub touch_policy: Option<&'a str>,
    /// Destroy the slot's existing key instead of refusing.
    pub replace: bool,
    /// Read the card's management key from the store instead of asking for
    /// it: `Some("")` is the conventional path for the card
    /// ([`default_pass_name`]), `Some(name)` that store entry.
    pub management_key_from_store: Option<String>,
    /// How the request was made, for wording what went wrong.
    pub binding: RequestBinding,
}

impl AddKeyArgs<'_> {
    /// The slot and the policy its key gets, or why the request is wrong
    /// whatever card is plugged in (asking for 9D, say).
    pub fn slot_and_policy(&self) -> Result<(u8, KeyPolicy), String> {
        let (slot, default_policy) = add_key_slot(self.slot)?;
        let policy = key_policy_from_flags(
            default_policy,
            self.pin_policy,
            self.touch_policy,
            self.binding,
        )?;
        Ok((slot, policy))
    }
}

/// Add a key through an already-built frontend. The binding-agnostic entry
/// the `piggy manage` `card.add_key` method calls; the CLI reaches it via
/// [`run`].
pub fn add_key_with_frontend(
    selector: CardSelector,
    args: AddKeyArgs<'_>,
    sealer: &dyn ManagementKeySealer,
    frontend: &mut dyn Frontend,
) -> Result<AddKeyOutcome, ProvisionError> {
    // The slot and policy are checked before any card is opened: asking for
    // 9D is a usage error whatever is plugged in.
    let (slot, policy) = args.slot_and_policy().map_err(ProvisionError::Setup)?;

    let mut token = select_provisioned_card(&selector).map_err(ProvisionError::Setup)?;
    let guid = token.guid().to_hex();
    let serial = token.yk_serial();
    let accepts_policies = accepts_policies(&token);
    // A slot counts as holding a key when it has a certificate, which is how
    // every piggy command finds a slot's key.
    let occupied = match token.read_slot(slot) {
        Ok(_) => true,
        Err(PivError::SlotEmpty(_)) => false,
        Err(e) => {
            return Err(ProvisionError::Setup(format!(
                "cannot tell whether slot {slot:02X} already holds a key: {e}"
            )));
        }
    };

    let stored_mgmt_key = args
        .management_key_from_store
        .map(|name| -> StoredMgmtKey<'_> {
            let pass_name = if name.is_empty() {
                default_pass_name(&guid)
            } else {
                name
            };
            Box::new(move || {
                sealer.recover(&pass_name).map_err(|e| {
                    format!(
                        "cannot read the management key from {pass_name} in the password store: {e}"
                    )
                })
            })
        });

    let cfg = AddKeyConfig {
        guid,
        slot,
        policy,
        accepts_policies,
        occupied,
        replace: args.replace,
        stored_mgmt_key,
        binding: args.binding,
    };
    // The card session opens only after the plan is made. Reading the
    // management key from the store is a decrypt, which may go to another
    // card over PC/SC; this card must not be held in a transaction while
    // that happens.
    let result = engine::plan_add_key(serial, frontend, cfg).and_then(|plan| {
        let mut session = token
            .begin_pin_session()
            .map_err(|e| ProvisionError::Setup(format!("open card session: {e}")))?;
        let mut card = SessionCard {
            session: &mut session,
            serial,
        };
        engine::apply_add_key(&mut card, frontend, plan)
    });
    engine::report_add_key(frontend, &result);
    result
}

/// The new key as an OpenSSH public-key line, commented the way `piggy tool
/// generate` comments one (`PIV_slot_9C@<GUID>`).
pub fn openssh_line(outcome: &AddKeyOutcome) -> Result<String, String> {
    crate::cmd::tool::generated_key_openssh_line(&outcome.public_point, outcome.slot, &outcome.guid)
}

/// `piggy card add-key` entry point. Returns a process exit code: 2 for a
/// request that is wrong whatever card is present, 1 for everything else.
pub fn run(
    selector: Result<CardSelector, String>,
    args: AddKeyArgs<'_>,
    sealer: &dyn ManagementKeySealer,
    frontend: FrontendKind,
    socket: Option<&Path>,
) -> i32 {
    let fail = |code: i32, e: &dyn std::fmt::Display| {
        eprintln!("piggy card add-key: {e}");
        code
    };
    // A wrong slot or a misspelt policy fails here, before a jsonrpc
    // frontend is connected to or any prompt is shown.
    if let Err(e) = args.slot_and_policy() {
        return fail(2, &e);
    }
    let selector = match selector {
        Ok(s) => s,
        Err(e) => return fail(2, &e),
    };
    // A jsonrpc channel that can't be opened fails before any card is touched.
    let mut frontend = match build_frontend(frontend, socket, "card add-key") {
        Ok(f) => f,
        Err(e) => return fail(1, &e),
    };
    let outcome = match add_key_with_frontend(selector, args, sealer, frontend.as_mut()) {
        Ok(o) => o,
        Err(e) => return fail(1, &e),
    };
    match openssh_line(&outcome) {
        // stdout: the new public key, for an allowed-signers or authorized_keys
        // file. Everything else went to stderr through the frontend.
        Ok(line) => {
            println!("{line}");
            0
        }
        Err(e) => fail(1, &e),
    }
}
