//! The pcsc-lite daemon server: listen on a Unix socket, speak the
//! client protocol, and dispatch each command to a [`Backend`].
//!
//! Concurrency model (deliberately simple, easy to debug): one thread
//! per client connection; each backend behind its own `Mutex`.
//! This is sized for the validation use case — one `pivy-tool`/`piggy`
//! at a time against the cards. Multi-client sharing/transactions are
//! left as a clearly-marked extension point rather than half-built.
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
use std::time::Duration;

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
    // piggy#130: an optional control socket lets a test toggle a card's
    // runtime presence (insert/remove) by reader name. Runs on its own
    // thread over a clone of the shared backends.
    if let Some(control_path) = control_socket {
        let control_path = control_path.to_string();
        let control_backends = Arc::clone(&backends);
        thread::spawn(move || {
            if let Err(e) = serve_control(&control_path, control_backends) {
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
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, backends) {
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
fn serve_control(control_path: &str, backends: SharedBackends) -> std::io::Result<()> {
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
                thread::spawn(move || {
                    if let Err(e) = handle_control(stream, backends) {
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
fn handle_control(mut stream: UnixStream, backends: SharedBackends) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader, Write};
    let mut line = String::new();
    let mut reader = BufReader::new(stream.try_clone()?);
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let reply = control_command(&backends, line.trim_end());
    stream.write_all(reply.as_bytes())?;
    stream.write_all(b"\n")?;
    Ok(())
}

/// Apply one control command. `insert <reader-name>` / `remove <reader-name>`
/// toggle presence (the reader name may contain spaces — everything after the
/// first space is the name); `list` reports every reader's presence. Replies
/// `ok[ ...]` or `err <reason>`.
fn control_command(backends: &SharedBackends, line: &str) -> String {
    let (verb, name) = match line.split_once(' ') {
        Some((v, n)) => (v, n.trim()),
        None => (line, ""),
    };
    match verb {
        "insert" | "remove" => {
            let present = verb == "insert";
            for b in backends.iter() {
                let mut card = b.lock().unwrap();
                if card.reader_name() == name {
                    card.set_present(present);
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

/// Per-connection handle bookkeeping. Handles are minted monotonically;
/// each card handle records the protocol it negotiated and WHICH backend
/// (reader-table index) it connected to, so transmit/reconnect/
/// disconnect route to the right card (piggy#242).
struct ConnState {
    next_context: u32,
    next_card: i32,
    contexts: HashMap<u32, ()>,
    card_protocols: HashMap<i32, u32>,
    card_backends: HashMap<i32, usize>,
}

impl ConnState {
    fn new() -> Self {
        ConnState {
            next_context: 1,
            next_card: 1,
            contexts: HashMap::new(),
            card_protocols: HashMap::new(),
            card_backends: HashMap::new(),
        }
    }
    fn mint_context(&mut self) -> u32 {
        let h = self.next_context;
        self.next_context += 1;
        self.contexts.insert(h, ());
        h
    }
    fn mint_card(&mut self, protocol: u32, backend_idx: usize) -> i32 {
        let h = self.next_card;
        self.next_card += 1;
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

fn handle_client(mut stream: UnixStream, backends: SharedBackends) -> std::io::Result<()> {
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
            Some(Command::EndTransaction) => end_transaction(&mut stream, &body)?,
            Some(Command::Transmit) => transmit(&mut stream, &body, &state, &backends)?,
            Some(Command::Status) => status(&mut stream, &body)?,
            Some(Command::Cancel) => cancel(&mut stream, &body)?,
            Some(Command::WaitReaderStateChange) => wait_reader_state(&mut stream, &body)?,
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

fn readers_state(stream: &mut UnixStream, backends: &SharedBackends) -> std::io::Result<()> {
    let states: Vec<ReaderState> = backends
        .iter()
        .map(|backend| {
            let b = backend.lock().unwrap();
            let present = b.card_present();
            ReaderState {
                reader_name: b.reader_name(),
                event_counter: 0,
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
        .collect();
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
    let result = backend.lock().unwrap().transmit(&apdu);
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

fn end_transaction(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    let req = HandleArgRv::from_bytes(body).unwrap_or(HandleArgRv {
        handle: -1,
        arg: disposition::LEAVE,
        rv: 0,
    });
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

fn wait_reader_state(stream: &mut UnixStream, body: &[u8]) -> std::io::Result<()> {
    // wait_reader_state_change { u32 timeOut; u32 rv }. Our card state
    // is static, so honor the timeout (capped) then report success so
    // the client re-reads states without busy-spinning. Wet-env: real
    // hot-plug needs an event source here.
    let timeout_ms = if body.len() >= 4 {
        u32::from_le_bytes(body[0..4].try_into().unwrap())
    } else {
        0
    };
    let capped = timeout_ms.min(1_000);
    if capped > 0 {
        thread::sleep(Duration::from_millis(capped as u64));
    }
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&timeout_ms.to_le_bytes());
    out[4..8].copy_from_slice(&SCARD_S_SUCCESS.to_le_bytes());
    reply(stream, &out)
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
