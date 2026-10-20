//! The pcsc-lite daemon server: listen on a Unix socket, speak the
//! client protocol, and dispatch each command to a [`Backend`].
//!
//! Concurrency model (deliberately simple, easy to debug): one thread
//! per client connection; each backend behind its own `Mutex`.
//! This is sized for the validation use case — one `pivy-tool`/`piggy`
//! at a time against the cards. Multi-client sharing/transactions are
//! left as a clearly-marked extension point rather than half-built.
//! A backend mutex is held only for the length of one backend call. An
//! operation that has to wait for a simulated touch waits with the mutex
//! released ([`transmit_waiting_for_touch`]); holding it there would stop
//! the control socket from reaching the card to deliver the touch.
//!
//! Multi-card (piggy#242): `serve` takes a LIST of backends — one per
//! reader. `CMD_GET_READERS_STATE` reports them all; `SCardConnect`
//! routes by the requested reader name (with a single-backend fallback
//! that ignores the name, preserving the historical one-card behavior
//! for clients that pass a stale/odd name); each minted card handle
//! remembers its backend, and transmit/reconnect/disconnect route by
//! handle.
//!
//! Wire contract reminder (see `frame.rs`): client→server messages
//! carry an 8-byte header; server→client replies are bare structs.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::backend::Backend;
use crate::error::*;
use crate::frame::{read_message, read_payload, write_body};
use crate::proto::*;
use crate::trace;

/// Shared, lockable backend handed to every connection thread.
pub type SharedBackend = Arc<Mutex<dyn Backend>>;

/// The reader table: one backend per reader, in `CMD_GET_READERS_STATE`
/// slot order.
pub type SharedBackends = Arc<Vec<SharedBackend>>;

/// A live client connection's server→client write half plus its
/// reader-state-change registration flag (piggy#248). Every write that can
/// race the async event notification — the `WAIT_READER_STATE_CHANGE` (0x13)
/// array reply, the `STOP_WAITING` (0x14) reply, and the notifier's 8-byte
/// wake — goes through this one mutex, so a reply and a notification can
/// never interleave mid-message. Regular command replies keep using the
/// connection thread's own stream handle: they only run while `armed` is
/// false (the client is not parked in `SCardGetStatusChange`), so they are
/// never concurrent with a notifier write.
struct ConnSink {
    /// A cloned write half of the client socket. The connection thread reads
    /// from the original handle while the control thread may write a wake
    /// here — a Unix socket is full-duplex, so the two never conflict.
    stream: UnixStream,
    /// Set while the client is blocked in `SCardGetStatusChange` (an
    /// old-mode `WAIT_READER_STATE_CHANGE` registered this fd for events).
    /// Exactly one 8-byte notification is delivered per arm cycle — by the
    /// notifier (on a presence change) OR by the stop handler (0x14) — and
    /// whichever fires clears the flag so the other sends nothing.
    armed: bool,
}

/// Registry of live client connections, so the control thread can wake any
/// that are blocked in `SCardGetStatusChange` when a card's presence toggles
/// (piggy#248). A connection registers itself on accept and removes itself on
/// disconnect.
type Waiters = Arc<Mutex<Vec<Arc<Mutex<ConnSink>>>>>;

/// The old-mode (`protocol <= 4005`) async event notification / stop reply:
/// `wait_reader_state_change { u32 timeOut; u32 rv }`, 8 bytes, `timeOut`
/// zero. libpcsclite reads exactly these 8 bytes to end its blocked wait,
/// then re-reads the reader-state array to learn what changed.
fn wait_notification_bytes() -> [u8; 8] {
    let mut out = [0u8; 8];
    out[4..8].copy_from_slice(&SCARD_S_SUCCESS.to_le_bytes());
    out
}

/// Wake every connection currently blocked in `SCardGetStatusChange`
/// (piggy#248): write the 8-byte async notification to each armed sink and
/// clear its flag (one-shot, mirroring pcscd's unregister-on-signal). The
/// woken client re-registers with a fresh 0x13 and re-reads the state array.
/// Best-effort: a write to a since-closed connection errors and is ignored;
/// that connection's own thread removes it from the registry on its next
/// read. Called by the control thread after a presence toggle.
fn notify_waiters(waiters: &Waiters) {
    let bytes = wait_notification_bytes();
    let live = waiters.lock().unwrap();
    let mut woke = 0usize;
    for w in live.iter() {
        let mut sink = w.lock().unwrap();
        if sink.armed {
            trace::hexdump("tx", &bytes);
            let _ = write_body(&mut sink.stream, &bytes);
            sink.armed = false;
            woke += 1;
        }
    }
    if woke > 0 {
        trace::emit(
            trace::DEBUG,
            "ctl",
            &format!("presence change: woke {woke} SCardGetStatusChange waiter(s) (piggy#248)"),
        );
    }
}

/// Bind `socket_path` and serve forever. Removes a stale socket file
/// first and chmods the new one so unprivileged clients can connect
/// (mirrors pcscd's 0777 on `pcscd.comm`). `backends` is one entry per
/// reader; it must be non-empty.
pub fn serve(
    socket_path: &str,
    backends: Vec<SharedBackend>,
    control_socket: Option<&str>,
) -> std::io::Result<()> {
    assert!(!backends.is_empty(), "serve needs at least one backend");
    let backends: SharedBackends = Arc::new(backends);
    // piggy#248: registry of live client connections so the control thread
    // can wake any blocked in SCardGetStatusChange when presence toggles.
    let waiters: Waiters = Arc::new(Mutex::new(Vec::new()));
    // piggy#130: an optional control socket lets a test toggle a card's
    // runtime presence (insert/remove) by reader name. Runs on its own
    // thread over a clone of the shared backends. It also holds the waiters
    // registry (piggy#248) so a toggle wakes event-driven clients.
    if let Some(control_path) = control_socket {
        let control_path = control_path.to_string();
        let control_backends = Arc::clone(&backends);
        let control_waiters = Arc::clone(&waiters);
        thread::spawn(move || {
            if let Err(e) = serve_control(&control_path, control_backends, control_waiters) {
                trace::emit(trace::INFO, "ctl", &format!("control socket ended: {e}"));
            }
        });
    }
    let path = Path::new(socket_path);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))?;
    trace::emit(
        trace::INFO,
        "listen",
        &format!(
            "fibby listening on {socket_path} with {} reader(s) (point PCSCLITE_CSOCK_NAME here)",
            backends.len()
        ),
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let backends = Arc::clone(&backends);
                let waiters = Arc::clone(&waiters);
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, backends, waiters) {
                        trace::emit(trace::INFO, "conn", &format!("connection ended: {e}"));
                    }
                });
            }
            Err(e) => trace::emit(trace::INFO, "listen", &format!("accept error: {e}")),
        }
    }
    Ok(())
}

/// Serve the piggy#130 control socket: one command per connection, each of
/// which toggles a card's runtime presence. Bound + chmod'd like the main
/// socket so an unprivileged test can drive it.
fn serve_control(
    control_path: &str,
    backends: SharedBackends,
    waiters: Waiters,
) -> std::io::Result<()> {
    let path = Path::new(control_path);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))?;
    trace::emit(
        trace::INFO,
        "ctl",
        &format!("fibby control socket on {control_path}"),
    );
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let backends = Arc::clone(&backends);
                let waiters = Arc::clone(&waiters);
                thread::spawn(move || {
                    if let Err(e) = handle_control(stream, backends, waiters) {
                        trace::emit(trace::INFO, "ctl", &format!("control conn ended: {e}"));
                    }
                });
            }
            Err(e) => trace::emit(trace::INFO, "ctl", &format!("control accept error: {e}")),
        }
    }
    Ok(())
}

/// One control command per connection: read a line, apply it, write the
/// reply, drop the connection (the client reads to EOF).
fn handle_control(
    mut stream: UnixStream,
    backends: SharedBackends,
    waiters: Waiters,
) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};
    let mut line = String::new();
    let mut reader = BufReader::new(stream.try_clone()?);
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let reply = control_command(&backends, &waiters, line.trim_end());
    stream.write_all(reply.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(())
}

/// Apply one control command. `insert <reader-name>` / `remove <reader-name>`
/// toggle presence (the reader name may contain spaces — everything after the
/// first space is the name); `list` reports every reader's presence;
/// `fault <INS|*> <SW>[x<count>] <reader-name>` queues an injected fault
/// (piggy#284: the next `count` APDUs with that INS — `*` for any — answer
/// `SW`, e.g. `fault 20 63C2 …` makes one VERIFY report a wrong PIN with 2
/// retries left) and `fault clear <reader-name>` drops them;
/// `touch <reader-name>` grants that card one simulated touch, consumed by
/// its next touch-requiring operation (replies `ok pending=<n>`). Replies
/// `ok[ ...]` or `err <reason>`.
fn control_command(backends: &SharedBackends, waiters: &Waiters, line: &str) -> String {
    let (verb, name) = match line.split_once(' ') {
        Some((v, n)) => (v, n.trim()),
        None => (line, ""),
    };
    match verb {
        "fault" => control_fault(backends, name),
        "touch" => match find_backend(backends, name) {
            // Locking the card here cannot deadlock against a client
            // waiting for this very touch: that client parks on the
            // card's touch pad with the card unlocked (see
            // `transmit_waiting_for_touch`).
            Some(b) => match b.lock().unwrap().grant_touch() {
                Ok(pending) => {
                    trace::emit(
                        trace::INFO,
                        "ctl",
                        &format!("touch queued for '{name}' (pending={pending})"),
                    );
                    format!("ok pending={pending}")
                }
                Err(e) => format!("err {e}"),
            },
            None => format!("err no such reader: {name}"),
        },
        "insert" | "remove" => {
            let present = verb == "insert";
            for b in backends.iter() {
                let mut card = b.lock().unwrap();
                if card.reader_name() == name {
                    card.set_present(present); // bumps event_counter on a real toggle
                    // Release the backend lock BEFORE waking waiters so the
                    // notifier never holds a backend lock across a socket write.
                    drop(card);
                    // piggy#248: wake any event-driven client blocked in
                    // SCardGetStatusChange so it re-reads the changed state.
                    notify_waiters(waiters);
                    return "ok".to_string();
                }
            }
            format!("err no such reader: {name}")
        }
        "list" => {
            let mut out = String::from("ok");
            for b in backends.iter() {
                let card = b.lock().unwrap();
                out.push_str(&format!(
                    "\n{}\t{}",
                    card.reader_name(),
                    if card.card_present() {
                        "present"
                    } else {
                        "absent"
                    }
                ));
            }
            out
        }
        other => format!("err unknown command: {other}"),
    }
}

/// `fault <INS|*> <SW>[x<count>] <reader-name>` / `fault clear <reader-name>`
/// (piggy#284). The reader name is last because it may contain spaces.
fn control_fault(backends: &SharedBackends, args: &str) -> String {
    let Some((first, rest)) = args.split_once(' ') else {
        return "err usage: fault <INS|*> <SW>[x<count>] <reader-name> | fault clear <reader-name>"
            .to_string();
    };
    if first == "clear" {
        let name = rest.trim();
        return match find_backend(backends, name) {
            Some(b) => {
                b.lock().unwrap().clear_faults();
                "ok".to_string()
            }
            None => format!("err no such reader: {name}"),
        };
    }
    let ins = match first {
        "*" => None,
        hex => match u8::from_str_radix(hex, 16) {
            Ok(v) => Some(v),
            Err(_) => return format!("err bad INS {hex:?}: want two hex digits or *"),
        },
    };
    let Some((sw_count, name)) = rest.split_once(' ') else {
        return "err usage: fault <INS|*> <SW>[x<count>] <reader-name>".to_string();
    };
    let (sw_hex, count) = match sw_count.split_once('x') {
        Some((sw, n)) => match n.parse::<u32>() {
            Ok(n) if n > 0 => (sw, n),
            _ => return format!("err bad count {n:?}: want a positive integer"),
        },
        None => (sw_count, 1),
    };
    let sw = match u16::from_str_radix(sw_hex, 16) {
        Ok(v) if sw_hex.len() == 4 => v,
        _ => return format!("err bad SW {sw_hex:?}: want four hex digits, e.g. 63C2"),
    };
    let name = name.trim();
    match find_backend(backends, name) {
        Some(b) => match b.lock().unwrap().inject_fault(crate::virtual_card::Fault {
            ins,
            sw,
            remaining: count,
        }) {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("err {e}"),
        },
        None => format!("err no such reader: {name}"),
    }
}

fn find_backend<'a>(backends: &'a SharedBackends, name: &str) -> Option<&'a SharedBackend> {
    backends
        .iter()
        .find(|b| b.lock().unwrap().reader_name() == name)
}

/// Context and card handle values, minted monotonically for the whole
/// server, not per connection. One client process may hold several
/// connections (libpcsclite opens one per `SCardEstablishContext`) and
/// libpcsclite looks a card handle up across all of that process's
/// contexts: if two connections were both handed `hCard=1`, releasing one
/// would invalidate the other on the client side, and the next call on it
/// fails with "the supplied handle was invalid" before reaching fibby. A
/// real pcscd never repeats a live handle value (piggy#303).
static NEXT_CONTEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
static NEXT_CARD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(1);

/// Per-connection handle bookkeeping. Each card handle records the
/// protocol it negotiated and WHICH backend (reader-table index) it
/// connected to, so transmit/reconnect/disconnect route to the right card
/// (piggy#242).
struct ConnState {
    contexts: HashMap<u32, ()>,
    card_protocols: HashMap<i32, u32>,
    card_backends: HashMap<i32, usize>,
}

impl ConnState {
    fn new() -> Self {
        ConnState {
            contexts: HashMap::new(),
            card_protocols: HashMap::new(),
            card_backends: HashMap::new(),
        }
    }
    fn mint_context(&mut self) -> u32 {
        let h = NEXT_CONTEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.contexts.insert(h, ());
        h
    }
    fn mint_card(&mut self, protocol: u32, backend_idx: usize) -> i32 {
        let h = NEXT_CARD.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.card_protocols.insert(h, protocol);
        self.card_backends.insert(h, backend_idx);
        h
    }
    /// Backend index a card handle is bound to; index 0 for an unknown
    /// handle (the historical single-backend behavior, and visible in
    /// logs via the handle bookkeeping either way).
    fn backend_of(&self, h_card: i32) -> usize {
        self.card_backends.get(&h_card).copied().unwrap_or(0)
    }
}

fn handle_client(
    stream: UnixStream,
    backends: SharedBackends,
    waiters: Waiters,
) -> std::io::Result<()> {
    // piggy#248: register this connection in the waiters registry so a
    // presence toggle on the control socket can wake it if it later blocks
    // in SCardGetStatusChange. The sink holds a cloned write half; the
    // command loop reads from the original handle (a Unix socket is
    // full-duplex, so a concurrent notifier write never conflicts). The
    // registration is torn down on every exit path.
    let sink = Arc::new(Mutex::new(ConnSink {
        stream: stream.try_clone()?,
        armed: false,
    }));
    waiters.lock().unwrap().push(Arc::clone(&sink));
    let result = serve_connection(stream, backends, &sink);
    waiters.lock().unwrap().retain(|w| !Arc::ptr_eq(w, &sink));
    result
}

/// Serve one client connection: the `CMD_VERSION` handshake then the command
/// loop. `sink` is the shared write half used only by the piggy#248 wake path
/// (the 0x13 array reply, the 0x14 stop reply, and the async notification);
/// every other reply writes through the connection thread's own `stream`.
fn serve_connection(
    mut stream: UnixStream,
    backends: SharedBackends,
    sink: &Arc<Mutex<ConnSink>>,
) -> std::io::Result<()> {
    // 1) CMD_VERSION handshake. Must come first; a version-major
    //    mismatch is the sole cause of SCARD_E_SERVICE_STOPPED.
    match read_message(&mut stream)? {
        Some((h, body)) if h.command == Command::Version as u32 => {
            let req = VersionStruct::from_bytes(&body);
            trace::emit(
                trace::INFO,
                "conn",
                &format!("new client; CMD_VERSION {req:?}"),
            );
            trace::hexdump("rx", &body);
            let client_major = req.map(|v| v.major).unwrap_or(0);
            let rv = if client_major == PROTOCOL_VERSION_MAJOR {
                SCARD_S_SUCCESS
            } else {
                trace::emit(
                    trace::INFO,
                    "conn",
                    &format!(
                        "version mismatch: client major {client_major} != {PROTOCOL_VERSION_MAJOR}"
                    ),
                );
                SCARD_E_NO_SERVICE
            };
            let resp = VersionStruct {
                major: PROTOCOL_VERSION_MAJOR,
                minor: PROTOCOL_VERSION_MINOR,
                rv,
            };
            reply(&mut stream, &resp.to_bytes())?;
            if rv != SCARD_S_SUCCESS {
                return Ok(());
            }
        }
        Some((h, _)) => {
            trace::emit(
                trace::INFO,
                "conn",
                &format!("expected CMD_VERSION first, got command {:#04x}", h.command),
            );
            return Ok(());
        }
        None => return Ok(()), // client hung up before handshake
    }

    // 2) Command loop.
    let mut state = ConnState::new();
    loop {
        let (header, body) = match read_message(&mut stream)? {
            Some(m) => m,
            None => {
                trace::emit(trace::DEBUG, "conn", "client disconnected");
                return Ok(());
            }
        };
        let cmd = Command::from_u32(header.command);
        trace::emit(
            trace::DEBUG,
            "rx",
            &format!(
                "command={cmd:?} ({:#04x}) size={}",
                header.command, header.size
            ),
        );
        trace::hexdump("rx", &body);

        match cmd {
            Some(Command::EstablishContext) => establish(&mut stream, &body, &mut state)?,
            Some(Command::ReleaseContext) => simple_ok(&mut stream, &body)?,
            Some(Command::GetReadersState) => readers_state(&mut stream, &backends)?,
            Some(Command::Connect) => connect(&mut stream, &body, &mut state, &backends)?,
            Some(Command::Reconnect) => reconnect(&mut stream, &body, &state, &backends)?,
            Some(Command::Disconnect) => disconnect(&mut stream, &body, &state, &backends)?,
            Some(Command::BeginTransaction) => begin_end_ok(&mut stream, &body)?,
            Some(Command::EndTransaction) => {
                end_transaction(&mut stream, &body, &state, &backends)?
            }
            Some(Command::Transmit) => transmit(&mut stream, &body, &state, &backends)?,
            Some(Command::Status) => status(&mut stream, &body)?,
            Some(Command::Cancel) => cancel(&mut stream, &body)?,
            Some(Command::WaitReaderStateChange) => wait_reader_state(sink, &backends)?,
            Some(Command::StopWaitingReaderStateChange) => stop_waiting(sink)?,
            // Known commands fibby doesn't speak yet. Closing the
            // connection here is intentional: it makes the unimplemented
            // command loudly visible in the log so a wet-env agent knows
            // exactly what to add next, rather than silently mis-replying
            // with a wrong-sized struct.
            Some(other) => {
                trace::emit(
                    trace::INFO,
                    "rx",
                    &format!(
                        "UNIMPLEMENTED command {other:?} — closing. Capture this and extend server::handle_client."
                    ),
                );
                return Ok(());
            }
            None => {
                trace::emit(
                    trace::INFO,
                    "rx",
                    &format!("unknown command {:#04x} — closing", header.command),
                );
                return Ok(());
            }
        }
    }
}

// --- command handlers ----------------------------------------------------

fn establish(stream: &mut UnixStream, body: &[u8], state: &mut ConnState) -> std::io::Result<()> {
    let req = EstablishStruct::from_bytes(body).unwrap_or(EstablishStruct {
        dw_scope: scope::SYSTEM,
        h_context: 0,
        rv: 0,
    });
    let h = state.mint_context();
    trace::emit(
        trace::DEBUG,
        "tx",
        &format!("ESTABLISH_CONTEXT -> hContext={h}"),
    );
    reply(
        stream,
        &EstablishStruct {
            dw_scope: req.dw_scope,
            h_context: h,
            rv: SCARD_S_SUCCESS,
        }
        .to_bytes(),
    )
}

/// Snapshot every reader's current `READER_STATE` from its backend. Shared
/// by `GET_READERS_STATE` (0x12) and the piggy#248 `WAIT_READER_STATE_CHANGE`
/// (0x13) reply, so both report the same presence flags, ATR, and — critical
/// for event-driven clients — the same monotonic `event_counter`.
fn build_reader_states(backends: &SharedBackends) -> Vec<ReaderState> {
    backends
        .iter()
        .map(|backend| {
            let b = backend.lock().unwrap();
            let present = b.card_present();
            ReaderState {
                reader_name: b.reader_name(),
                event_counter: b.event_counter(),
                reader_state: if present {
                    reader_flags::PRESENT | reader_flags::POWERED | reader_flags::NEGOTIABLE
                } else {
                    reader_flags::ABSENT
                },
                reader_sharing: 0,
                card_atr: if present { b.atr() } else { Vec::new() },
                card_protocol: if present {
                    protocol::T1
                } else {
                    protocol::UNDEFINED
                },
            }
        })
        .collect()
}

fn readers_state(stream: &mut UnixStream, backends: &SharedBackends) -> std::io::Result<()> {
    let states = build_reader_states(backends);
    trace::emit(
        trace::DEBUG,
        "tx",
        &format!("GET_READERS_STATE -> {states:?}"),
    );
    reply(stream, &readers_state_array(&states))
}

/// Resolve which backend a `SCardConnect` for `sz_reader` addresses:
/// exact reader-name match wins; with a single backend an unmatched name
/// falls back to it (the historical behavior — the one-card server never
/// looked at the name); with several backends an unmatched name is a
/// routing error surfaced as `SCARD_E_UNKNOWN_READER`.
fn backend_for_reader(backends: &SharedBackends, sz_reader: &str) -> Option<usize> {
    if let Some(idx) = backends
        .iter()
        .position(|b| b.lock().unwrap().reader_name() == sz_reader)
    {
        return Some(idx);
    }
    if backends.len() == 1 { Some(0) } else { None }
}

fn connect(
    stream: &mut UnixStream,
    body: &[u8],
    state: &mut ConnState,
    backends: &SharedBackends,
) -> std::io::Result<()> {
    let req = match ConnectStruct::from_bytes(body) {
        Some(r) => r,
        None => return reply_handle_rv(stream, -1, SCARD_E_INVALID_VALUE),
    };
    let mut resp = req.clone();
    let Some(idx) = backend_for_reader(backends, &req.sz_reader) else {
        trace::emit(
            trace::DEBUG,
            "tx",
            &format!("CONNECT '{}' -> no such reader", req.sz_reader),
        );
        resp.h_card = -1;
        resp.dw_active_protocol = 0;
        resp.rv = SCARD_E_UNKNOWN_READER;
        return reply(stream, &resp.to_bytes());
    };
    // piggy#130: a removed card is a known reader with no card — refuse the
    // connect so the client's enumerate omits it (as pcscd would).
    if !backends[idx].lock().unwrap().card_present() {
        trace::emit(
            trace::DEBUG,
            "tx",
            &format!("CONNECT '{}' -> no card (removed)", req.sz_reader),
        );
        resp.h_card = -1;
        resp.dw_active_protocol = 0;
        resp.rv = SCARD_E_NO_SMARTCARD;
        return reply(stream, &resp.to_bytes());
    }
    match backends[idx]
        .lock()
        .unwrap()
        .connect(req.dw_share_mode, req.dw_preferred_protocols)
    {
        Ok(active) => {
            let h = state.mint_card(active, idx);
            resp.h_card = h;
            resp.dw_active_protocol = active;
            resp.rv = SCARD_S_SUCCESS;
            trace::emit(
                trace::DEBUG,
                "tx",
                &format!(
                    "CONNECT '{}' -> hCard={h} proto={active} reader#{idx}",
                    req.sz_reader
                ),
            );
        }
        Err(code) => {
            resp.h_card = -1;
            resp.dw_active_protocol = 0;
            resp.rv = code;
            trace::emit(
                trace::DEBUG,
                "tx",
                &format!("CONNECT failed rv={code:#010x}"),
            );
        }
    }
    reply(stream, &resp.to_bytes())
}

fn reconnect(
    stream: &mut UnixStream,
    body: &[u8],
    state: &ConnState,
    backends: &SharedBackends,
) -> std::io::Result<()> {
    // reconnect_struct { i32 hCard; u32 dwShareMode; u32 dwPreferredProtocols;
    //                    u32 dwInitialization; u32 dwActiveProtocol; u32 rv }
    let r = |o: usize| u32::from_le_bytes(body[o..o + 4].try_into().unwrap());
    if body.len() < 24 {
        return reply(stream, body); // echo; malformed
    }
    let h_card = i32::from_le_bytes(body[0..4].try_into().unwrap());
    let (share, preferred) = (r(4), r(8));
    let mut out = body.to_vec();
    let backend = &backends[state.backend_of(h_card)];
    match backend.lock().unwrap().connect(share, preferred) {
        Ok(active) => {
            out[16..20].copy_from_slice(&active.to_le_bytes()); // dwActiveProtocol
            out[20..24].copy_from_slice(&SCARD_S_SUCCESS.to_le_bytes());
            trace::emit(
                trace::DEBUG,
                "tx",
                &format!("RECONNECT hCard={h_card} proto={active}"),
            );
        }
        Err(code) => out[20..24].copy_from_slice(&code.to_le_bytes()),
    }
    reply(stream, &out)
}

fn disconnect(
    stream: &mut UnixStream,
    body: &[u8],
    state: &ConnState,
    backends: &SharedBackends,
) -> std::io::Result<()> {
    let req = HandleArgRv::from_bytes(body).unwrap_or(HandleArgRv {
        handle: -1,
        arg: disposition::LEAVE,
        rv: 0,
    });
    let backend = &backends[state.backend_of(req.handle)];
    let rv = match backend.lock().unwrap().disconnect(req.arg) {
        Ok(()) => SCARD_S_SUCCESS,
        Err(code) => code,
    };
    trace::emit(
        trace::DEBUG,
        "tx",
        &format!(
            "DISCONNECT hCard={} disp={} rv={rv:#010x}",
            req.handle, req.arg
        ),
    );
    reply(
        stream,
        &HandleArgRv {
            handle: req.handle,
            arg: req.arg,
            rv,
        }
        .to_bytes(),
    )
}

fn transmit(
    stream: &mut UnixStream,
    body: &[u8],
    state: &ConnState,
    backends: &SharedBackends,
) -> std::io::Result<()> {
    let req = match TransmitStruct::from_bytes(body) {
        Some(r) => r,
        None => return Ok(()),
    };
    // The send APDU streams right after the fixed struct (no header), on
    // the same connection.
    let apdu = read_payload(stream, req.cb_send_length as usize)?;
    trace::emit(
        trace::DEBUG,
        "rx",
        &format!("TRANSMIT hCard={} {} bytes", req.h_card, apdu.len()),
    );
    trace::hexdump("apdu>", &apdu);

    let backend = &backends[state.backend_of(req.h_card)];
    let result = transmit_waiting_for_touch(backend, &apdu, || peer_hung_up(stream));
    let active = state
        .card_protocols
        .get(&req.h_card)
        .copied()
        .unwrap_or(protocol::T1);

    match result {
        Ok(resp) => {
            trace::hexdump("apdu<", &resp);
            let reply_struct = TransmitStruct {
                h_card: req.h_card,
                io_send_pci_protocol: req.io_send_pci_protocol,
                io_send_pci_length: req.io_send_pci_length,
                cb_send_length: req.cb_send_length,
                io_recv_pci_protocol: active,
                io_recv_pci_length: 8, // sizeof(SCARD_IO_REQUEST)
                pcb_recv_length: resp.len() as u32,
                rv: SCARD_S_SUCCESS,
            };
            trace::hexdump("tx", &reply_struct.to_bytes());
            write_body(stream, &reply_struct.to_bytes())?;
            write_body(stream, &resp)
        }
        Err(code) => {
            trace::emit(
                trace::DEBUG,
                "tx",
                &format!("TRANSMIT failed rv={code:#010x}"),
            );
            let mut reply_struct = req;
            reply_struct.pcb_recv_length = 0;
            reply_struct.rv = code;
            write_body(stream, &reply_struct.to_bytes())
        }
    }
}

/// Transmit one APDU, waiting for a simulated touch if the card says the
/// operation needs one (a touch-`always`/`cached` slot with no touch
/// available; see `touch.rs`).
///
/// The backend mutex is held only for each attempt, never across the
/// wait: a blocked attempt changes nothing on the card and hands back the
/// card's [`TouchPad`](crate::touch::TouchPad), this thread parks on the
/// pad's own condition variable, and on a change it re-locks the card and
/// transmits the same APDU again. So while one client waits for a touch
/// the control socket can still lock that card to deliver it
/// (`fibby ctl touch`), and other clients and other cards are served as
/// usual. A touch that never arrives answers the card's timeout status
/// word once the card's touch timeout has passed since the first attempt.
///
/// `client_gone` is asked, without the card locked, before every retry and
/// at least every [`CLIENT_GONE_POLL`] while waiting. Once it says the
/// client that sent the APDU has hung up, the operation is abandoned
/// untried (answering the timeout status word to nobody), so a dead
/// client's waiter never consumes a touch meant for the next live
/// operation (piggy#314).
pub fn transmit_waiting_for_touch(
    backend: &SharedBackend,
    apdu: &[u8],
    client_gone: impl Fn() -> bool,
) -> crate::backend::ScardResult<Vec<u8>> {
    use crate::backend::TransmitOutcome;
    use std::time::Instant;
    let mut deadline: Option<Instant> = None;
    loop {
        // The guard is a temporary of this statement: the card is unlocked
        // again before the wait below.
        let outcome = backend.lock().unwrap().transmit_or_await_touch(apdu)?;
        let wait = match outcome {
            TransmitOutcome::Done(response) => return Ok(response),
            TransmitOutcome::AwaitTouch(wait) => wait,
        };
        let deadline = *deadline.get_or_insert_with(|| {
            crate::touch::log_touch_needed(
                &wait.slot_label,
                &format!("waiting up to {} ms", wait.timeout.as_millis()),
            );
            Instant::now() + wait.timeout
        });
        loop {
            let slice_end = deadline.min(Instant::now() + CLIENT_GONE_POLL);
            let changed = wait.pad.wait_for_change(wait.seen, slice_end);
            if client_gone() {
                crate::touch::log_touch_abandoned(&wait.slot_label);
                return Ok(wait.timeout_response);
            }
            if changed {
                break; // retry the APDU
            }
            if Instant::now() >= deadline {
                crate::touch::log_touch_timeout(&wait.slot_label, &wait.timeout_response);
                return Ok(wait.timeout_response);
            }
        }
    }
}

/// How often a connection waiting for a touch checks that its client is
/// still there (see [`transmit_waiting_for_touch`]).
const CLIENT_GONE_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// True once the peer of `stream` has hung up: a non-blocking peek reads
/// end-of-file or a connection error. A client blocked in SCardTransmit
/// sends nothing, so "would block" means it is still waiting. Nothing is
/// consumed from the socket.
fn peer_hung_up(stream: &UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let mut probe = [0u8; 1];
    // SAFETY: `probe` is a valid one-byte buffer for the whole call and
    // the fd is owned by `stream`, which outlives it.
    let n = unsafe {
        libc::recv(
            stream.as_raw_fd(),
            probe.as_mut_ptr().cast(),
            probe.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    match n {
        0 => true,
        n if n > 0 => false,
        _ => !matches!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ),
    }
}

fn status(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    // SCardStatus fills reader name / state / ATR client-side from the
    // cached reader-state array; the round-trip only needs hCard + rv.
    // Wet-env: if a client expects more here, capture and extend.
    let req = HandleRv::from_bytes(body).unwrap_or(HandleRv { handle: -1, rv: 0 });
    reply_handle_rv(stream, req.handle, SCARD_S_SUCCESS)
}

fn cancel(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    let req = HandleRv::from_bytes(body).unwrap_or(HandleRv { handle: -1, rv: 0 });
    reply_handle_rv(stream, req.handle, SCARD_S_SUCCESS)
}

fn begin_end_ok(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    // BEGIN_TRANSACTION: single-client model grants unconditionally.
    let req = HandleRv::from_bytes(body).unwrap_or(HandleRv { handle: -1, rv: 0 });
    reply_handle_rv(stream, req.handle, SCARD_S_SUCCESS)
}

fn end_transaction(
    stream: &mut UnixStream,
    body: &[u8],
    state: &ConnState,
    backends: &SharedBackends,
) -> std::io::Result<()> {
    let req = HandleArgRv::from_bytes(body).unwrap_or(HandleArgRv {
        handle: -1,
        arg: disposition::LEAVE,
        rv: 0,
    });
    backends[state.backend_of(req.handle)]
        .lock()
        .unwrap()
        .end_transaction(req.arg);
    reply(
        stream,
        &HandleArgRv {
            handle: req.handle,
            arg: req.arg,
            rv: SCARD_S_SUCCESS,
        }
        .to_bytes(),
    )
}

/// `CMD_WAIT_READER_STATE_CHANGE` (0x13), piggy#248. Old-mode
/// (`protocol <= 4005`) semantics, which the pinned libpcsclite speaks: the
/// request body is empty; the server REGISTERS this connection for events and
/// replies the full 16-slot reader-state array (NOT an 8-byte struct — that
/// is the async notification's shape, and replying it here desyncs an
/// old-mode client, the bug the pre-#248 sleep-stub had). The client compares
/// the array to its cached states; if unchanged it blocks reading the 8-byte
/// async notification, which [`notify_waiters`] delivers on the next presence
/// toggle. The array write and the `armed` set happen under one sink-lock so a
/// notification can never interleave between them (a lost or corrupt wake).
fn wait_reader_state(
    sink: &Arc<Mutex<ConnSink>>,
    backends: &SharedBackends,
) -> std::io::Result<()> {
    let array = readers_state_array(&build_reader_states(backends));
    let mut s = sink.lock().unwrap();
    trace::hexdump("tx", &array);
    write_body(&mut s.stream, &array)?;
    s.armed = true;
    trace::emit(
        trace::DEBUG,
        "tx",
        "WAIT_READER_STATE_CHANGE -> array + registered for events (piggy#248)",
    );
    Ok(())
}

/// `CMD_STOP_WAITING_READER_STATE_CHANGE` (0x14), piggy#248. The client sends
/// this to end a wait (its own timeout elapsed, or it already saw the change)
/// and reads one 8-byte reply. Mirroring pcscd: reply the 8 bytes ONLY if this
/// fd is still registered. If [`notify_waiters`] already fired (fd disarmed),
/// those already-queued 8 bytes satisfy the client's read, so sending a second
/// set here would desync it — send nothing. The `armed` test-and-clear under
/// the sink-lock guarantees exactly one 8-byte message per arm cycle.
fn stop_waiting(sink: &Arc<Mutex<ConnSink>>) -> std::io::Result<()> {
    let mut s = sink.lock().unwrap();
    if s.armed {
        let out = wait_notification_bytes();
        trace::hexdump("tx", &out);
        write_body(&mut s.stream, &out)?;
        s.armed = false;
        trace::emit(
            trace::DEBUG,
            "tx",
            "STOP_WAITING -> 8-byte reply (piggy#248)",
        );
    } else {
        trace::emit(
            trace::DEBUG,
            "tx",
            "STOP_WAITING -> already notified; no reply (piggy#248)",
        );
    }
    Ok(())
}

/// ReleaseContext-style: echo the request body with a success rv in its
/// last 4 bytes.
fn simple_ok(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    let mut out = body.to_vec();
    let n = out.len();
    if n >= 4 {
        out[n - 4..].copy_from_slice(&SCARD_S_SUCCESS.to_le_bytes());
    }
    reply(stream, &out)
}

// --- small helpers -------------------------------------------------------

fn reply(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    trace::hexdump("tx", body);
    write_body(stream, body)
}

fn reply_handle_rv(stream: &mut UnixStream, handle: i32, rv: u32) -> std::io::Result<()> {
    reply(stream, &HandleRv { handle, rv }.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn peer_hung_up_tells_a_waiting_client_from_a_closed_one() {
        let (mut ours, mut theirs) = UnixStream::pair().unwrap();
        assert!(!peer_hung_up(&ours), "an idle live peer is still there");

        theirs.write_all(&[0x42]).unwrap();
        assert!(!peer_hung_up(&ours), "a peer with data pending is alive");
        let mut byte = [0u8; 1];
        ours.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [0x42], "the probe consumed nothing");

        drop(theirs);
        assert!(peer_hung_up(&ours), "a closed peer has hung up");
    }
}
