//! The command line, hogtie(8). Exit codes: 0 success (for `exec`, the
//! action's own status, since hogtie becomes it), 1 refused, 2 usage, 3
//! hogtie's own failure (configuration, audit log, socket).

use crate::audit;
use crate::exec::{Decision, decide};
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
  hogtie message NONCE ACTION [ARGS...]    print the bytes to sign
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
    let [nonce, action, args @ ..] = rest else {
        return usage();
    };
    let Some(nonce) = parse_nonce_hex(nonce) else {
        return fail(2, "NONCE is not 64 lowercase hex digits");
    };
    // SAFETY: getuid cannot fail.
    let uid = unsafe { libc::getuid() };
    match (Request {
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
    let now = crate::util::now();
    // sudo sets SUDO_UID to the invoking account; without it there is no
    // account to bind the nonce to.
    let decision = match std::env::var("SUDO_UID")
        .ok()
        .and_then(|u| u.parse::<u32>().ok())
    {
        Some(caller_uid) => decide(&paths, caller_uid, response, action, args, now),
        None => Decision {
            run: Err("SUDO_UID is not set; run hogtie exec through sudo".into()),
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
    if let Err(e) = Paths::ensure_private_dir(&paths.log)
        .and_then(|()| audit::append(&paths.audit_log(), &decision.record))
    {
        return fail(3, format!("refused: cannot write the audit log: {e}"));
    }
    let run = match decision.run {
        Ok(run) => run,
        Err(reason) => return fail(1, format!("refused: {reason}")),
    };
    let err = std::process::Command::new(&run.program)
        .arg0(&run.argv[0])
        .args(&run.argv[1..])
        .env_clear()
        .envs(run.env.iter().map(|(k, v)| (k, v)))
        .current_dir("/")
        .exec();
    fail(3, format!("{}: {err}", run.program.display()))
}

fn serve_socket() -> ExitCode {
    use std::os::unix::fs::PermissionsExt as _;
    let paths = Paths::for_this_binary();
    if let Err(e) = paths.check_running_as_root() {
        return fail(3, e);
    }
    for dir in [&paths.run, &paths.nonces()] {
        if let Err(e) = Paths::ensure_private_dir(dir) {
            return fail(3, format!("{}: {e}", dir.display()));
        }
    }
    // The runtime directory's contents are root-only; the socket in it must
    // still be reachable, so the directory itself gets search permission.
    if let Err(e) = std::fs::set_permissions(&paths.run, std::fs::Permissions::from_mode(0o711)) {
        return fail(3, format!("{}: {e}", paths.run.display()));
    }
    let listener = match serve::bind(&paths.socket()) {
        Ok(l) => l,
        Err(e) => return fail(3, format!("{}: {e}", paths.socket().display())),
    };
    match serve::serve(&listener, &NonceStore::new(paths.nonces())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(3, e),
    }
}
