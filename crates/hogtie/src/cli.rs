//! The command line, hogtie(8). Exit codes: 0 success (for `exec`, the
//! action's own status, since hogtie becomes it), 1 refused, 2 usage, 3
//! hogtie's own failure (configuration, audit log, socket).

use crate::audit;
use crate::exec::{Decision, Refusal, decide};
use crate::message::Request;
use crate::nonce::NonceStore;
use crate::paths::Paths;
use crate::response::{Response, parse_nonce_hex};
use crate::serve;
use crate::sshwire::dearmor;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage:
  hogtie nonce [--socket PATH]             ask for a nonce (prints it)
  hogtie message HOST NONCE ACTION [ARGS...]  print the bytes to sign
  hogtie response NONCE SIGFILE            print the response word
  sudo hogtie exec RESPONSE ACTION [ARGS...]
  hogtie serve                             run the nonce socket (root)
  hogtie --version";

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn fail(code: u8, msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("hogtie: {msg}");
    ExitCode::from(code)
}

pub fn main() -> ExitCode {
    // Before any file is opened: the caller's file size limit must not cut
    // hogtie's own writes, nor its SIGXFSZ kill it (review N2).
    crate::child::shield_self();
    let args: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect()
    {
        Ok(a) => a,
        Err(_) => return fail(2, "arguments must be UTF-8"),
    };
    let Some((verb, rest)) = args.split_first() else {
        return usage();
    };
    match verb.as_str() {
        "nonce" => nonce(rest),
        "message" => message(rest),
        "response" => response(rest),
        "exec" => exec(rest),
        "serve" if rest.is_empty() => serve_socket(),
        "--version" if rest.is_empty() => {
            println!("hogtie {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => usage(),
    }
}

fn nonce(rest: &[String]) -> ExitCode {
    let socket = match rest {
        [] => Paths::for_this_binary().socket(),
        [flag, path] if flag == "--socket" => PathBuf::from(path),
        _ => return usage(),
    };
    match serve::ask(&socket) {
        Ok(Ok((hex, _expires))) => {
            println!("{hex}");
            ExitCode::SUCCESS
        }
        Ok(Err(reason)) => fail(1, format!("refused: {reason}")),
        Err(e) => fail(3, format!("{}: {e}", socket.display())),
    }
}

fn message(rest: &[String]) -> ExitCode {
    let [host, nonce, action, args @ ..] = rest else {
        return usage();
    };
    let Some(nonce) = parse_nonce_hex(nonce) else {
        return fail(2, "NONCE is not 64 lowercase hex digits");
    };
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    match (Request {
        host: host.clone(),
        nonce,
        uid,
        action: action.clone(),
        args: args.to_vec(),
    })
    .encode()
    {
        Ok(bytes) => match std::io::stdout().write_all(&bytes) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(3, e),
        },
        Err(e) => fail(2, e),
    }
}

fn response(rest: &[String]) -> ExitCode {
    let [nonce, sigfile] = rest else {
        return usage();
    };
    let Some(nonce) = parse_nonce_hex(nonce) else {
        return fail(2, "NONCE is not 64 lowercase hex digits");
    };
    let text = match std::fs::read_to_string(sigfile) {
        Ok(t) => t,
        Err(e) => return fail(2, format!("{sigfile}: {e}")),
    };
    match dearmor(&text) {
        Some(sshsig) => {
            println!("{}", Response { nonce, sshsig }.format());
            ExitCode::SUCCESS
        }
        None => fail(2, format!("{sigfile}: not an armored SSH signature")),
    }
}

fn exec(rest: &[String]) -> ExitCode {
    use std::os::unix::process::CommandExt as _;
    let [response, action, args @ ..] = rest else {
        return usage();
    };
    let paths = Paths::for_this_binary();
    if let Err(e) = paths.check_running_as_root() {
        return fail(3, e);
    }
    // A clock that cannot be read refuses: a zero boot time would make
    // every nonce look fresh (review N5).
    let clock = match crate::util::Clock::now() {
        Ok(c) => c,
        Err(e) => return fail(3, format!("cannot read the clock: {e}")),
    };
    let now = clock.wall;
    // sudo sets SUDO_UID to the invoking account; without it there is no
    // account to bind the nonce to.
    let caller = std::env::var("SUDO_UID")
        .ok()
        .and_then(|u| u.parse::<u32>().ok());
    let mut decision = match caller {
        Some(caller_uid) => decide(&paths, caller_uid, response, action, args, clock),
        None => Decision {
            run: Err(Refusal {
                reason: "SUDO_UID is not set; run hogtie exec through sudo".into(),
                internal: false,
            }),
            record: audit::Record {
                time: now,
                outcome: "refused",
                reason: Some("SUDO_UID is not set".into()),
                action: Some(action.clone()),
                args: args.to_vec(),
                ..Default::default()
            },
        },
    };
    // Refusals past an account's budget are counted, not logged (finding 2).
    // A budget that cannot be read logs in full.
    let logged = decision.record.outcome != "refused"
        || match Paths::ensure_private_dir(&paths.refusals())
            .and_then(|()| audit::admit_refusal(&paths.refusals(), caller, clock.boot))
        {
            Ok(audit::Admit::Quiet) => false,
            Ok(admit) => {
                decision.record.note = admit.note();
                true
            }
            Err(_) => true,
        };
    let written = if logged {
        Paths::ensure_private_dir(&paths.log)
            .and_then(|()| audit::append(&paths.audit_log(), &decision.record))
    } else {
        Ok(())
    };
    if let Err(e) = written {
        return fail(3, format!("refused: cannot write the audit log: {e}"));
    }
    let run = match decision.run {
        Ok(run) => run,
        Err(r) if r.internal => return fail(3, format!("cannot decide: {}", r.reason)),
        Err(r) => return fail(1, format!("refused: {}", r.reason)),
    };
    let mut cmd = std::process::Command::new(&run.program);
    cmd.arg0(&run.argv[0])
        .args(&run.argv[1..])
        .env_clear()
        .envs(run.env.iter().map(|(k, v)| (k, v)))
        .current_dir("/");
    crate::child::prepare(&mut cmd);
    let err = cmd.exec();
    // exec returned: the `started` line stands corrected by this one.
    let reason = format!("{}: {err}", run.program.display());
    let failed = audit::Record {
        time: crate::util::now(),
        outcome: "exec-failed",
        reason: Some(reason.clone()),
        ..decision.record
    };
    if let Err(e) = audit::append(&paths.audit_log(), &failed) {
        eprintln!("hogtie: cannot write the audit log: {e}");
    }
    fail(3, reason)
}

fn serve_socket() -> ExitCode {
    let paths = Paths::for_this_binary();
    if let Err(e) = paths.check_running_as_root() {
        return fail(3, e);
    }
    // The runtime directory's contents are root-only; the socket in it must
    // still be reachable, so the directory itself has search permission.
    for (dir, mode) in [
        (paths.run.clone(), 0o711),
        (paths.nonces(), 0o700),
        (paths.scratch(), 0o700),
        (paths.refusals(), 0o700),
    ] {
        if let Err(e) = crate::paths::ensure_dir(&dir, mode) {
            return fail(3, format!("{}: {e}", dir.display()));
        }
    }
    // Nonces must not survive a reboot (their life is on the boot clock):
    // the store must be in memory. Not checked under the test harness,
    // whose directories are on whatever the test's temp is.
    if paths.root_uid == 0 {
        if let Err(e) = crate::paths::check_tmpfs(&paths.run) {
            return fail(3, e);
        }
    }
    let listener = match serve::bind(&paths.socket()) {
        Ok(l) => l,
        Err(e) => return fail(3, format!("{}: {e}", paths.socket().display())),
    };
    match serve::serve(
        &listener,
        &NonceStore::new(paths.nonces()),
        &paths.scratch(),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(3, e),
    }
}
