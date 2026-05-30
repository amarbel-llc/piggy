//! The pcsc-lite daemon server: listen on a Unix socket, speak the
//! client protocol, and dispatch each command to a [`Backend`].
//!
//! Concurrency model (deliberately simple, easy to debug): one thread
//! per client connection; a single shared backend behind a `Mutex`.
//! This is sized for the validation use case — one `pivy-tool`/`piggy`
//! at a time against one card. Multi-client sharing/transactions are
//! left as a clearly-marked extension point rather than half-built.
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

/// Bind `socket_path` and serve forever. Removes a stale socket file
/// first and chmods the new one so unprivileged clients can connect
/// (mirrors pcscd's 0777 on `pcscd.comm`).
pub fn serve(socket_path: &str, backend: SharedBackend) -> std::io::Result<()> {
    let path = Path::new(socket_path);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))?;
    trace::emit(
        trace::INFO,
        "listen",
        &format!("fibby listening on {socket_path} (point PCSCLITE_CSOCK_NAME here)"),
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let backend = Arc::clone(&backend);
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, backend) {
                        trace::emit(trace::INFO, "conn", &format!("connection ended: {e}"));
                    }
                });
            }
            Err(e) => trace::emit(trace::INFO, "listen", &format!("accept error: {e}")),
        }
    }
    Ok(())
}

/// Per-connection handle bookkeeping. Handles are minted monotonically;
/// we record them so a stray handle is visible in logs, but the
/// single-backend model doesn't multiplex by handle yet.
struct ConnState {
    next_context: u32,
    next_card: i32,
    contexts: HashMap<u32, ()>,
    card_protocols: HashMap<i32, u32>,
}

impl ConnState {
    fn new() -> Self {
        ConnState {
            next_context: 1,
            next_card: 1,
            contexts: HashMap::new(),
            card_protocols: HashMap::new(),
        }
    }
    fn mint_context(&mut self) -> u32 {
        let h = self.next_context;
        self.next_context += 1;
        self.contexts.insert(h, ());
        h
    }
    fn mint_card(&mut self, protocol: u32) -> i32 {
        let h = self.next_card;
        self.next_card += 1;
        self.card_protocols.insert(h, protocol);
        h
    }
}

fn handle_client(mut stream: UnixStream, backend: SharedBackend) -> std::io::Result<()> {
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
            Some(Command::GetReadersState) => readers_state(&mut stream, &backend)?,
            Some(Command::Connect) => connect(&mut stream, &body, &mut state, &backend)?,
            Some(Command::Reconnect) => reconnect(&mut stream, &body, &backend)?,
            Some(Command::Disconnect) => disconnect(&mut stream, &body, &backend)?,
            Some(Command::BeginTransaction) => begin_end_ok(&mut stream, &body)?,
            Some(Command::EndTransaction) => end_transaction(&mut stream, &body)?,
            Some(Command::Transmit) => transmit(&mut stream, &body, &state, &backend)?,
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

fn readers_state(stream: &mut UnixStream, backend: &SharedBackend) -> std::io::Result<()> {
    let b = backend.lock().unwrap();
    let present = b.card_present();
    let st = ReaderState {
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
    };
    drop(b);
    trace::emit(trace::DEBUG, "tx", &format!("GET_READERS_STATE -> {st:?}"));
    reply(stream, &readers_state_array(&[st]))
}

fn connect(
    stream: &mut UnixStream,
    body: &[u8],
    state: &mut ConnState,
    backend: &SharedBackend,
) -> std::io::Result<()> {
    let req = match ConnectStruct::from_bytes(body) {
        Some(r) => r,
        None => return reply_handle_rv(stream, -1, SCARD_E_INVALID_VALUE),
    };
    let mut resp = req.clone();
    match backend
        .lock()
        .unwrap()
        .connect(req.dw_share_mode, req.dw_preferred_protocols)
    {
        Ok(active) => {
            let h = state.mint_card(active);
            resp.h_card = h;
            resp.dw_active_protocol = active;
            resp.rv = SCARD_S_SUCCESS;
            trace::emit(
                trace::DEBUG,
                "tx",
                &format!("CONNECT '{}' -> hCard={h} proto={active}", req.sz_reader),
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

fn reconnect(stream: &mut UnixStream, body: &[u8], backend: &SharedBackend) -> std::io::Result<()> {
    // reconnect_struct { i32 hCard; u32 dwShareMode; u32 dwPreferredProtocols;
    //                    u32 dwInitialization; u32 dwActiveProtocol; u32 rv }
    let r = |o: usize| u32::from_le_bytes(body[o..o + 4].try_into().unwrap());
    if body.len() < 24 {
        return reply(stream, body); // echo; malformed
    }
    let h_card = i32::from_le_bytes(body[0..4].try_into().unwrap());
    let (share, preferred) = (r(4), r(8));
    let mut out = body.to_vec();
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
    backend: &SharedBackend,
) -> std::io::Result<()> {
    let req = HandleArgRv::from_bytes(body).unwrap_or(HandleArgRv {
        handle: -1,
        arg: disposition::LEAVE,
        rv: 0,
    });
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
    backend: &SharedBackend,
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
