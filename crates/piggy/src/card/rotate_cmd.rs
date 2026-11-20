//! `piggy card rotate-admin`: the real-card driver of [`super::rotate`].
//! Selects the one provisioned card the operator names, puts a `PivToken`
//! behind [`RotateCard`] (one PC/SC transaction per authentication, one for
//! the rotation and its proof), the password store behind [`RotateStore`]
//! (the binary's sealer), the operator behind a `Frontend`, runs the
//! rotation and prints its account as TAP-14 on stdout. Nothing secret ever
//! reaches stdout, stderr or a notification.

use std::io::Write;
use std::path::Path;

use piggy_piv::apdu::alg::TDEA_3KEY;
use piggy_piv::{PivError, PivToken};

use crate::card::frontend::select::{FrontendKind, build_frontend};
use crate::card::init_cmd::{CardSelector, select_provisioned_card};
use crate::card::protocol::{CardId, CompletedEvent, CompletedStatus, Frontend};
use crate::card::rotate::{
    self, Exit, PinProtection, Point, Report, RotateCard, RotateConfig, RotateRefusal, RotateStore,
};
use crate::card::seal::default_pass_name;

/// A live card behind the rotation's seam.
struct TokenCard {
    token: PivToken,
}

/// The Printed Information object's answer as the gate reads it: the
/// YubicoPIV `88 { 89 … }` escrow present means the management key lives
/// under the PIN; `6982` means the object itself is behind the PIN.
fn protection_of(read: Result<piggy_piv::pinfo::Pinfo, PivError>) -> PinProtection {
    match read {
        Ok(pinfo) if pinfo.has_admin_key => PinProtection::Yes,
        Ok(_) => PinProtection::No,
        Err(PivError::Apdu { sw: 0x6982 }) => PinProtection::NeedsPin,
        // No such object: nothing is escrowed there.
        Err(PivError::Apdu { sw: 0x6A82 }) => PinProtection::No,
        Err(e) => PinProtection::Unreadable(e.to_string()),
    }
}

impl RotateCard for TokenCard {
    fn authenticates(&mut self, key: &[u8]) -> Result<bool, PivError> {
        let mut session = self.token.begin_pin_session()?;
        match session.authenticate_admin(key, TDEA_3KEY) {
            Ok(()) => Ok(true),
            Err(PivError::ManagementAuthFailed) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn rotate(&mut self, current: &[u8], new: &[u8]) -> Result<(), RotateRefusal> {
        // One PinSession is one PC/SC transaction: the agent's own use of the
        // card waits until the rotation and its proof are done.
        let mut session = self
            .token
            .begin_pin_session()
            .map_err(RotateRefusal::Card)?;
        match session.authenticate_admin(current, TDEA_3KEY) {
            Ok(()) => {}
            Err(PivError::ManagementAuthFailed) => return Err(RotateRefusal::CurrentRefused),
            Err(e) => return Err(RotateRefusal::Card(e)),
        }
        session
            .set_management_key_3des(new)
            .map_err(RotateRefusal::SetRefused)?;
        match session.authenticate_admin(new, TDEA_3KEY) {
            Ok(()) => Ok(()),
            Err(PivError::ManagementAuthFailed) => Err(RotateRefusal::NewNotAccepted),
            Err(e) => Err(RotateRefusal::Card(e)),
        }
    }

    fn pin_protection(&mut self) -> PinProtection {
        // Yubico's tooling records the mode in the admin data object, which
        // needs no PIN: a set flag answers before any key is tried. A clear or
        // absent flag proves nothing (piggy never writes that object), so the
        // Printed Information object is read next.
        if let Ok(Some(flags)) = self.token.read_admin_flags() {
            if flags & piggy_piv::pinfo::ADMIN_FLAG_PROTECTED_MGM != 0 {
                return PinProtection::Yes;
            }
        }
        protection_of(self.token.read_pinfo())
    }

    fn pin_protection_with_pin(&mut self, pin: &str) -> Result<PinProtection, PivError> {
        let mut session = self.token.begin_pin_session()?;
        session.verify_pin(pin)?;
        Ok(protection_of(session.read_pinfo()))
    }
}

/// `piggy card rotate-admin` entry point; the process exit code is the
/// rotation's exit table (`rotate::Exit`).
pub fn run(
    selector: Result<CardSelector, String>,
    entry: Option<String>,
    store: &dyn RotateStore,
    frontend: FrontendKind,
    socket: Option<&Path>,
) -> i32 {
    let fail = |exit: Exit, e: &dyn std::fmt::Display| {
        eprintln!("piggy card rotate-admin: {e}");
        exit.code()
    };
    let selector = match selector {
        Ok(s) => s,
        Err(e) => return fail(Exit::Usage, &e),
    };
    // A jsonrpc channel that cannot be opened fails before any card is touched.
    let mut frontend = match build_frontend(frontend, socket, "card rotate-admin") {
        Ok(f) => f,
        Err(e) => return fail(Exit::Stopped, &e),
    };
    let token = match select_provisioned_card(&selector) {
        Ok(t) => t,
        Err(e) => return fail(Exit::Card, &e),
    };
    let guid = token.guid().to_hex();
    let cfg = RotateConfig {
        card: CardId {
            guid: guid.clone(),
            serial: token.yk_serial(),
            cn: None,
        },
        entry: entry.unwrap_or_else(|| default_pass_name(&guid)),
    };
    let mut card = TokenCard { token };
    let mut random =
        |buf: &mut [u8]| openssl::rand::rand_bytes(buf).map_err(|e| format!("random key: {e}"));

    let report = rotate::rotate_admin(&mut card, store, frontend.as_mut(), &cfg, &mut random);
    complete(frontend.as_mut(), &report);
    if let Err(e) = print_tap(&report.points) {
        eprintln!("piggy card rotate-admin: write the report: {e}");
    }
    match &report.outcome {
        Ok(_) => 0,
        Err(stop) => stop.exit.code(),
    }
}

fn complete(fe: &mut dyn Frontend, report: &Report) {
    match &report.outcome {
        Ok(done) => fe.completed(CompletedEvent {
            status: CompletedStatus::Ok,
            summary: Some(serde_json::json!({ "done": format!("{done:?}") })),
            error: None,
        }),
        Err(stop) => fe.completed(CompletedEvent {
            status: CompletedStatus::Error,
            summary: Some(serde_json::json!({ "exit": stop.exit.code() })),
            error: Some(stop.message.clone()),
        }),
    }
}

/// The account as TAP-14, plain and deterministic (as `piggy health
/// --format tap`), so a wrapper reads a plan and `ok`/`not ok` lines.
fn print_tap(points: &[Point]) -> std::io::Result<()> {
    let mut out = std::io::stdout().lock();
    {
        let mut rep =
            tap_dancer::Reporter::Tap(tap_dancer::TapWriterBuilder::new(&mut out).build()?);
        rep.plan_ahead(points.len())?;
        for point in points {
            let diags: Vec<(&str, serde_json::Value)> = point
                .diags
                .iter()
                .map(|(k, v)| (k.as_str(), serde_json::Value::String(v.clone())))
                .collect();
            match (point.ok, diags.is_empty()) {
                (true, true) => rep.ok(&point.name)?,
                (true, false) => rep.ok_diag(&point.name, &diags)?,
                (false, _) => rep.not_ok_diag(&point.name, &diags)?,
            };
        }
        rep.finish()?;
    }
    out.flush()
}
