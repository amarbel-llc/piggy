//! `pigtrough`: the auth decoration proxy pilot (FDR 0009).
//!
//!     pigtrough serve [--dir DIR]
//!     piggy pass show <entry> | pigtrough load github-api [--dir DIR]
//!
//! `serve` listens on `DIR/proxy.sock` (clients) and `DIR/control.sock`
//! (`load`), DIR defaulting to `$XDG_RUNTIME_DIR/pigtrough`, created `0700`.
//! Both sockets admit only this user. It starts with no secret loaded, so
//! every allowed request answers `503 secret-unavailable` until a `load`.
//! Audit lines and control events go to stderr. No credential is ever taken
//! from argv or the environment.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use zeroize::Zeroizing;

use pigtrough::audit::StderrSink;
use pigtrough::control::{MAX_LOAD, send_load, serve_control};
use pigtrough::holder::SecretHolder;
use pigtrough::listener::{admit_peer, bind, effective_uid};
use pigtrough::proxy::{Proxy, Scope};
use pigtrough::route::GITHUB_API;
use pigtrough::server::serve;
use pigtrough::tls::TlsUpstream;

/// The blocking threads that run requests (each holds one for the length of
/// its upstream call), so the cap is the number of concurrent requests. A
/// slow upstream that holds them all makes later requests wait, not fail.
const MAX_IN_FLIGHT: usize = 16;

const USAGE: &str = "usage: pigtrough serve [--dir DIR]\n       pigtrough load ROUTE [--dir DIR]   (the secret on stdin)\n";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("serve") => parse_dir(&args[1..]).and_then(run_serve),
        Some("load") => match args.get(1) {
            Some(route) if !route.starts_with('-') => {
                parse_dir(&args[2..]).and_then(|dir| run_load(route, dir))
            }
            _ => Err(USAGE.to_owned()),
        },
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprint!("pigtrough: {message}");
            if !message.ends_with('\n') {
                eprintln!();
            }
            ExitCode::FAILURE
        }
    }
}

fn parse_dir(args: &[String]) -> Result<PathBuf, String> {
    match args {
        [] => std::env::var_os("XDG_RUNTIME_DIR")
            .map(|d| PathBuf::from(d).join("pigtrough"))
            .ok_or_else(|| "XDG_RUNTIME_DIR is unset; pass --dir DIR".to_owned()),
        [flag, dir] if flag == "--dir" => Ok(PathBuf::from(dir)),
        _ => Err(USAGE.to_owned()),
    }
}

fn run_serve(dir: PathBuf) -> Result<(), String> {
    let hardening = piggy_guard::harden_process();
    if let Some(Err(e)) = &hardening.non_dumpable {
        eprintln!("pigtrough: warning: could not make the process non-dumpable: {e}");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(MAX_IN_FLIGHT)
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let uid = effective_uid();
    let listen = |name: &str| -> Result<tokio::net::UnixListener, String> {
        let path = dir.join(name);
        let listener = bind(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let _entered = runtime.enter();
        tokio::net::UnixListener::from_std(listener).map_err(|e| format!("{}: {e}", path.display()))
    };
    let proxy_listener = listen("proxy.sock")?;
    let control_listener = listen("control.sock")?;

    let holder = Arc::new(SecretHolder::empty());
    let proxy = Arc::new(Proxy::new(
        &GITHUB_API,
        holder.clone(),
        TlsUpstream::with_public_roots(runtime.handle().clone()),
        Arc::new(StderrSink),
        Scope {
            name: "operator".to_owned(),
        },
    ));
    eprintln!(
        "pigtrough: serving route {} on {} (no secret loaded)",
        GITHUB_API.name,
        dir.join("proxy.sock").display()
    );
    runtime.block_on(async move {
        tokio::select! {
            r = serve(proxy_listener, proxy, move |s| admit_peer(s, uid)) => r,
            r = serve_control(control_listener, &GITHUB_API, holder, move |s| admit_peer(s, uid)) => r,
        }
    })
    .map_err(|e| format!("listener: {e}"))
}

fn run_load(route: &str, dir: PathBuf) -> Result<(), String> {
    let mut secret = Zeroizing::new(Vec::new());
    let read = std::io::stdin()
        .take(MAX_LOAD as u64 + 1)
        .read_to_end(&mut secret)
        .map_err(|e| format!("reading the secret from stdin: {e}"))?;
    if read > MAX_LOAD {
        return Err("the secret on stdin is too large".to_owned());
    }
    let path = dir.join("control.sock");
    let answer =
        send_load(&path, route, &secret).map_err(|e| format!("{}: {e}", path.display()))?;
    if answer == "ok" {
        eprintln!("pigtrough: loaded {route}");
        Ok(())
    } else {
        Err(answer)
    }
}
