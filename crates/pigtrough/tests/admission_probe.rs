//! The slice-4 probe: how reliably does `/proc/net/tcp` attribute the owner
//! of a loopback client (docs/plans/2026-11-17-pigtrough-listener-options.md,
//! "Throwaway test"). Not part of the gate: every test here is `#[ignore]`
//! and runs through `just explore-pigtrough-admission`, which prints counts
//! only. No credential, no network beyond loopback, no pigtrough binary.
//!
//! A case that cannot run here says `NOT TESTED` and why; it never passes
//! silently.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use pigtrough::listener::{effective_uid, loopback_client_uid};

const CLIENT_THREADS: usize = 8;
const PER_THREAD: usize = 100;

#[derive(Default, Debug)]
struct Counts {
    connections: usize,
    own_uid: usize,
    other_uid: usize,
    unattributed: usize,
}

fn classify(counts: &mut Counts, peer: SocketAddr, local: SocketAddr, me: u32) {
    counts.connections += 1;
    match loopback_client_uid(peer, local) {
        Some(uid) if uid == me => counts.own_uid += 1,
        Some(_) => counts.other_uid += 1,
        None => counts.unattributed += 1,
    }
}

/// `CLIENT_THREADS * PER_THREAD` connections open at once, each client
/// holding its socket until the server has looked every one up.
#[test]
#[ignore = "explore: run through `just explore-pigtrough-admission`"]
fn same_uid_burst_is_attributed() {
    let me = effective_uid();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let total = CLIENT_THREADS * PER_THREAD;
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let release_rx = std::sync::Arc::new(std::sync::Mutex::new(release_rx));
    let clients: Vec<_> = (0..CLIENT_THREADS)
        .map(|_| {
            let release_rx = release_rx.clone();
            thread::spawn(move || {
                let mut held = Vec::new();
                for _ in 0..PER_THREAD {
                    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
                    // A real client sends its request at once.
                    s.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
                    held.push(s);
                }
                // Hold the sockets open until the server is done.
                let _ = release_rx.lock().unwrap().recv();
                drop(held);
            })
        })
        .collect();

    let mut counts = Counts::default();
    let mut accepted = Vec::new();
    while counts.connections < total {
        let (stream, peer) = listener.accept().unwrap();
        let local = stream.local_addr().unwrap();
        classify(&mut counts, peer, local, me);
        accepted.push(stream);
    }
    for _ in 0..CLIENT_THREADS {
        release_tx.send(()).unwrap();
    }
    for c in clients {
        c.join().unwrap();
    }
    println!("COUNTS same-uid-burst: {counts:?}");
    assert_eq!(
        counts.other_uid, 0,
        "a connection was attributed to another uid"
    );
}

/// A client that has already gone by the time the server looks: the
/// connection is unattributable, so it is refused. Counted, not asserted.
#[test]
#[ignore = "explore: run through `just explore-pigtrough-admission`"]
fn client_gone_before_the_lookup() {
    let me = effective_uid();
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let total = 300;
    for _ in 0..total {
        drop(TcpStream::connect(("127.0.0.1", port)).unwrap());
    }
    let mut counts = Counts::default();
    for _ in 0..total {
        let (stream, peer) = listener.accept().unwrap();
        classify(&mut counts, peer, stream.local_addr().unwrap(), me);
    }
    println!("COUNTS client-gone: {counts:?}");
}

/// The listener binds IPv4 loopback only, so `::1` must not connect.
#[test]
#[ignore = "explore: run through `just explore-pigtrough-admission`"]
fn ipv6_loopback_cannot_reach_the_listener() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    match TcpStream::connect(("::1", port)) {
        Ok(_) => println!("COUNTS ipv6: connected=1 (UNEXPECTED)"),
        Err(e) => println!("COUNTS ipv6: connected=0 ({:?})", e.kind()),
    }
}

/// Another uid needs a process running as a second account (setuid needs
/// root, and no second login is used from a session). Reported, not faked:
/// the unit test on a synthetic table covers the parsing of a foreign uid,
/// not the kernel's attribution.
#[test]
#[ignore = "explore: run through `just explore-pigtrough-admission`"]
fn other_uid_is_not_attributed_to_us() {
    println!(
        "COUNTS other-uid: NOT TESTED (running as uid {}; a client as a second uid needs root or \
         a second account, neither available here)",
        effective_uid()
    );
}

/// A client in its own network namespace cannot reach the host's loopback.
#[test]
#[ignore = "explore: run through `just explore-pigtrough-admission`"]
fn separate_network_namespace() {
    println!(
        "COUNTS netns: NOT TESTED (a client in a new network namespace has its own loopback; \
         reaching ours needs a bridge, which is not part of this probe)"
    );
}
