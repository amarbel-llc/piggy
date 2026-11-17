//! `pigtrough`: the auth decoration proxy pilot (FDR 0009).
//!
//!     pigtrough serve [--dir DIR] [--routes FILE]
//!     piggy pass show <entry> | pigtrough load ROUTE [--dir DIR]
//!
//! `serve` listens on `DIR/proxy.sock` (clients) and `DIR/control.sock`
//! (`load`), DIR defaulting to `$XDG_RUNTIME_DIR/pigtrough`, created `0700`.
//! Both sockets admit only this user. It starts with no secret loaded, so
//! every allowed request answers `503 secret-unavailable` until a `load`.
//! Routes come from the TOML file FILE, read once, or are the compiled-in
//! `github-api` without `--routes`; a route with a `loopback_port` is also
//! served on `127.0.0.1:<port>`, where it is the only route a client can
//! name. Audit lines and control events go to stderr. No credential is ever
//! taken from argv or the environment.

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use zeroize::Zeroizing;

use pigtrough::audit::StderrSink;
use pigtrough::control::{MAX_LOAD, send_load, serve_control};
use pigtrough::holder::Mount;
use pigtrough::listener::{admit_loopback_peer, admit_peer, bind, bind_loopback, effective_uid};
use pigtrough::proxy::{Proxy, Scope};
use pigtrough::route::GITHUB_API;
use pigtrough::server::{serve, serve_tcp};
use pigtrough::table::{self, RouteEntry};
use pigtrough::tls::{HostClients, TlsUpstream, roots_with};

/// The blocking threads that run requests (each holds one for the length of
/// its upstream call), so the cap is the number of concurrent requests. A
/// slow upstream that holds them all makes later requests wait, not fail.
const MAX_IN_FLIGHT: usize = 16;

const USAGE: &str = "usage: pigtrough serve [--dir DIR] [--routes FILE]\n       pigtrough load ROUTE [--dir DIR]   (the secret on stdin)\n";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("serve") => parse_serve(&args[1..]).and_then(|(dir, routes)| run_serve(dir, routes)),
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

fn default_dir() -> Result<PathBuf, String> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| PathBuf::from(d).join("pigtrough"))
        .ok_or_else(|| "XDG_RUNTIME_DIR is unset; pass --dir DIR".to_owned())
}

fn parse_dir(args: &[String]) -> Result<PathBuf, String> {
    match args {
        [] => default_dir(),
        [flag, dir] if flag == "--dir" => Ok(PathBuf::from(dir)),
        _ => Err(USAGE.to_owned()),
    }
}

/// `serve`'s flags, each at most once, in any order.
fn parse_serve(args: &[String]) -> Result<(PathBuf, Option<PathBuf>), String> {
    let (mut dir, mut routes) = (None, None);
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let slot = match flag.as_str() {
            "--dir" => &mut dir,
            "--routes" => &mut routes,
            _ => return Err(USAGE.to_owned()),
        };
        match rest.next() {
            Some(value) if slot.is_none() => *slot = Some(PathBuf::from(value)),
            _ => return Err(USAGE.to_owned()),
        }
    }
    Ok((
        match dir {
            Some(dir) => dir,
            None => default_dir()?,
        },
        routes,
    ))
}

/// The routes to serve: the table file, or the compiled-in route.
fn read_routes(file: Option<PathBuf>) -> Result<Vec<RouteEntry>, String> {
    let Some(file) = file else {
        return Ok(vec![RouteEntry {
            route: &GITHUB_API,
            loopback_port: None,
            extra_roots: Vec::new(),
        }]);
    };
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    table::parse(&text).map_err(|e| format!("{}: {e}", file.display()))
}

/// The upstream client: public roots for every upstream, and a client of
/// its own, with the route's extra roots added, for each upstream that has
/// some. A bad roots file refuses to start.
fn build_client(
    runtime: &tokio::runtime::Runtime,
    entries: &[RouteEntry],
) -> Result<HostClients, String> {
    let mut clients = HostClients::new(TlsUpstream::with_public_roots(runtime.handle().clone()));
    let mut done: Vec<&pigtrough::route::Upstream> = Vec::new();
    for entry in entries.iter().filter(|e| !e.extra_roots.is_empty()) {
        let upstream = &entry.route.upstream;
        // The table guarantees routes sharing an upstream share their roots.
        if done.contains(&upstream) {
            continue;
        }
        let roots = roots_with(&entry.extra_roots)
            .map_err(|e| format!("route {}: extra_roots: {e}", entry.route.name))?;
        clients = clients.with_host(
            upstream,
            TlsUpstream::with_roots(runtime.handle().clone(), roots),
        );
        done.push(upstream);
    }
    Ok(clients)
}

fn run_serve(dir: PathBuf, routes_file: Option<PathBuf>) -> Result<(), String> {
    let entries = read_routes(routes_file)?;
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
    // Built before any socket is bound: a bad roots file refuses to start
    // without leaving a listener behind.
    let client = Arc::new(build_client(&runtime, &entries)?);
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

    let mounts: Vec<Mount> = entries.iter().map(|e| Mount::empty(e.route)).collect();
    let audit = Arc::new(StderrSink);

    // A loopback listener per route that asks for one. Each gets its own
    // proxy over that one route, so a connection on its port can name no
    // other route.
    let mut loopbacks = Vec::new();
    for (entry, mount) in entries.iter().zip(&mounts) {
        let Some(port) = entry.loopback_port else {
            continue;
        };
        let std_listener = bind_loopback(port).map_err(|e| format!("127.0.0.1:{port}: {e}"))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| format!("127.0.0.1:{port}: {e}"))?;
        let listener = {
            let _entered = runtime.enter();
            tokio::net::TcpListener::from_std(std_listener)
                .map_err(|e| format!("127.0.0.1:{port}: {e}"))?
        };
        let proxy = Arc::new(Proxy::with_mounts(
            vec![mount.clone()],
            client.clone(),
            audit.clone(),
            Scope {
                name: format!("loopback-{}", entry.route.name),
            },
        ));
        loopbacks.push((listener, proxy, entry.route.name, port));
    }

    let proxy = Arc::new(Proxy::with_mounts(
        mounts.clone(),
        client.clone(),
        audit.clone(),
        Scope {
            name: "operator".to_owned(),
        },
    ));
    for entry in &entries {
        eprintln!(
            "pigtrough: serving route {} on {} (no secret loaded)",
            entry.route.name,
            dir.join("proxy.sock").display()
        );
    }
    for (_, _, name, port) in &loopbacks {
        eprintln!("pigtrough: route {name} also on 127.0.0.1:{port} (this user only)");
    }
    runtime
        .block_on(async move {
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(serve(proxy_listener, proxy, move |s| admit_peer(s, uid)));
            tasks.spawn(serve_control(control_listener, mounts, move |s| {
                admit_peer(s, uid)
            }));
            for (listener, proxy, _, _) in loopbacks {
                tasks.spawn(serve_tcp(listener, proxy, move |peer, local| {
                    admit_loopback_peer(peer, local, uid)
                }));
            }
            match tasks.join_next().await {
                Some(Ok(result)) => result,
                Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                None => Ok(()),
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
