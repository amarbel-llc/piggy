//! End-to-end loopback: a real client UnixStream drives fibby's server
//! (with the `VirtualCard` backend) through a full PC/SC session over a
//! real socket — no pcscd, no hardware. This is the hermetic
//! cross-check of the protocol layer and the template the wet-env
//! agents extend (swap in the hardware-proxy backend, replay the same
//! script, diff the bytes).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fibby::proto::*;
use fibby::server;
use fibby::virtual_card::VirtualCard;

/// Minimal client: write `rxHeader + body`, read a bare reply of a known
/// size (server replies carry no header).
struct Client {
    stream: UnixStream,
}

impl Client {
    fn send(&mut self, command: Command, body: &[u8]) {
        let header = Header {
            size: body.len() as u32,
            command: command as u32,
        };
        self.stream.write_all(&header.to_bytes()).unwrap();
        self.stream.write_all(body).unwrap();
        self.stream.flush().unwrap();
    }

    fn recv(&mut self, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        self.stream.read_exact(&mut buf).unwrap();
        buf
    }
}

fn unique_socket_path() -> std::path::PathBuf {
    // AF_UNIX sun_path is 108 bytes on Linux / 104 on macOS. Some test
    // environments (spinclass worktree TMPDIR = `<repo>/.worktrees/<name>/.tmp`)
    // push `std::env::temp_dir()` past ~56 chars on its own, enough that the
    // PID+nanos suffix overflows sun_path and `bind()` fails silently. /tmp
    // is short and writable in every environment this test runs in — host
    // devshell, nix sandbox (private /tmp), GitHub Actions.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::path::PathBuf::from("/tmp").join(format!("fibby-{}-{}.sock", std::process::id(), nanos))
}

fn start_server(path: &std::path::Path, cards: Vec<VirtualCard>) {
    let backends = cards
        .into_iter()
        .map(|c| Arc::new(Mutex::new(c)) as server::SharedBackend)
        .collect();
    let serve_path = path.to_path_buf();
    thread::spawn(move || {
        let _ = server::serve(serve_path.to_str().unwrap(), backends, None);
    });
    // Wait for the socket to appear.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        assert!(Instant::now() < deadline, "server socket never appeared");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn full_piv_select_session_over_socket() {
    let path = unique_socket_path();
    start_server(&path, vec![VirtualCard::new()]);
    let mut c = Client {
        stream: UnixStream::connect(&path).unwrap(),
    };

    // 1) CMD_VERSION handshake.
    c.send(
        Command::Version,
        &VersionStruct {
            major: PROTOCOL_VERSION_MAJOR,
            minor: PROTOCOL_VERSION_MINOR,
            rv: 0,
        }
        .to_bytes(),
    );
    let ver = VersionStruct::from_bytes(&c.recv(VersionStruct::WIRE_LEN)).unwrap();
    assert_eq!(ver.major, PROTOCOL_VERSION_MAJOR);
    assert_eq!(ver.rv, 0, "handshake should succeed");

    // 2) ESTABLISH_CONTEXT.
    c.send(
        Command::EstablishContext,
        &EstablishStruct {
            dw_scope: scope::SYSTEM,
            h_context: 0,
            rv: 0,
        }
        .to_bytes(),
    );
    let est = EstablishStruct::from_bytes(&c.recv(EstablishStruct::WIRE_LEN)).unwrap();
    assert_eq!(est.rv, 0);
    assert!(est.h_context > 0, "minted a context handle");

    // 3) GET_READERS_STATE (no body) — fixed 16-slot array.
    c.send(Command::GetReadersState, &[]);
    let arr = c.recv(MAX_READERS_CONTEXTS * ReaderState::WIRE_LEN);
    let slot0 = ReaderState::from_bytes(&arr[0..ReaderState::WIRE_LEN]).unwrap();
    assert!(slot0.reader_name.contains("fibby"), "reader advertised");
    assert_ne!(
        slot0.reader_state & reader_flags::PRESENT,
        0,
        "card present"
    );
    assert!(!slot0.card_atr.is_empty(), "ATR reported");

    // 4) CONNECT.
    c.send(
        Command::Connect,
        &ConnectStruct {
            h_context: est.h_context,
            sz_reader: slot0.reader_name.clone(),
            dw_share_mode: share::SHARED,
            dw_preferred_protocols: protocol::ANY,
            h_card: 0,
            dw_active_protocol: 0,
            rv: 0,
        }
        .to_bytes(),
    );
    let con = ConnectStruct::from_bytes(&c.recv(ConnectStruct::WIRE_LEN)).unwrap();
    assert_eq!(con.rv, 0);
    assert!(con.h_card > 0, "minted a card handle");
    assert_eq!(con.dw_active_protocol, protocol::T1);

    // 5) TRANSMIT a PIV SELECT and read the response (struct + buffer).
    let piv_aid: &[u8] = &[
        0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    ];
    let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, piv_aid.len() as u8];
    apdu.extend_from_slice(piv_aid);
    let tx = TransmitStruct {
        h_card: con.h_card,
        io_send_pci_protocol: protocol::T1,
        io_send_pci_length: 8,
        cb_send_length: apdu.len() as u32,
        io_recv_pci_protocol: 0,
        io_recv_pci_length: 0,
        pcb_recv_length: 258,
        rv: 0,
    };
    // header(size=32) + struct, then the APDU buffer (no header).
    c.send(Command::Transmit, &tx.to_bytes());
    c.stream.write_all(&apdu).unwrap();
    c.stream.flush().unwrap();

    let reply = TransmitStruct::from_bytes(&c.recv(TransmitStruct::WIRE_LEN)).unwrap();
    assert_eq!(reply.rv, 0, "transmit succeeded");
    let resp = c.recv(reply.pcb_recv_length as usize);
    assert!(resp.len() >= 2);
    assert_eq!(&resp[resp.len() - 2..], &[0x90, 0x00], "SELECT -> 9000");

    // 6) DISCONNECT (LEAVE).
    c.send(
        Command::Disconnect,
        &HandleArgRv {
            handle: con.h_card,
            arg: disposition::LEAVE,
            rv: 0,
        }
        .to_bytes(),
    );
    let dis = HandleArgRv::from_bytes(&c.recv(HandleArgRv::WIRE_LEN)).unwrap();
    assert_eq!(dis.rv, 0);

    let _ = std::fs::remove_file(&path);
}

// --- multi-reader (piggy#242) --------------------------------------------

const GUID_B: [u8; 16] = [0xB2; 16];

/// PIV SELECT APDU (AID from the applet spec).
fn select_piv_apdu() -> Vec<u8> {
    let piv_aid: &[u8] = &[
        0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
    ];
    let mut apdu = vec![0x00, 0xA4, 0x04, 0x00, piv_aid.len() as u8];
    apdu.extend_from_slice(piv_aid);
    apdu
}

/// GET DATA for the CHUID (`5C 03 5F C1 02`).
fn get_chuid_apdu() -> Vec<u8> {
    vec![0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x02]
}

impl Client {
    /// One TRANSMIT round-trip on `h_card`; returns the response bytes
    /// (data ‖ SW1 SW2).
    fn transmit(&mut self, h_card: i32, apdu: &[u8]) -> Vec<u8> {
        let tx = TransmitStruct {
            h_card,
            io_send_pci_protocol: protocol::T1,
            io_send_pci_length: 8,
            cb_send_length: apdu.len() as u32,
            io_recv_pci_protocol: 0,
            io_recv_pci_length: 0,
            pcb_recv_length: 4096,
            rv: 0,
        };
        self.send(Command::Transmit, &tx.to_bytes());
        self.stream.write_all(apdu).unwrap();
        self.stream.flush().unwrap();
        let reply = TransmitStruct::from_bytes(&self.recv(TransmitStruct::WIRE_LEN)).unwrap();
        assert_eq!(reply.rv, 0, "transmit failed");
        self.recv(reply.pcb_recv_length as usize)
    }

    fn connect_reader(&mut self, h_context: u32, reader: &str) -> ConnectStruct {
        self.send(
            Command::Connect,
            &ConnectStruct {
                h_context,
                sz_reader: reader.to_string(),
                dw_share_mode: share::SHARED,
                dw_preferred_protocols: protocol::ANY,
                h_card: 0,
                dw_active_protocol: 0,
                rv: 0,
            }
            .to_bytes(),
        );
        ConnectStruct::from_bytes(&self.recv(ConnectStruct::WIRE_LEN)).unwrap()
    }
}

impl Client {
    /// TRANSMIT expecting the server to refuse it; returns the refusal's rv.
    fn transmit_rv(&mut self, h_card: i32, apdu: &[u8]) -> u32 {
        let tx = TransmitStruct {
            h_card,
            io_send_pci_protocol: protocol::T1,
            io_send_pci_length: 8,
            cb_send_length: apdu.len() as u32,
            io_recv_pci_protocol: 0,
            io_recv_pci_length: 0,
            pcb_recv_length: 4096,
            rv: 0,
        };
        self.send(Command::Transmit, &tx.to_bytes());
        self.stream.write_all(apdu).unwrap();
        self.stream.flush().unwrap();
        let reply = TransmitStruct::from_bytes(&self.recv(TransmitStruct::WIRE_LEN)).unwrap();
        if reply.rv == 0 {
            let _ = self.recv(reply.pcb_recv_length as usize);
        }
        reply.rv
    }

    fn begin_transaction(&mut self, h_card: i32) -> u32 {
        self.send(
            Command::BeginTransaction,
            &HandleRv {
                handle: h_card,
                rv: 0,
            }
            .to_bytes(),
        );
        HandleRv::from_bytes(&self.recv(HandleRv::WIRE_LEN))
            .unwrap()
            .rv
    }

    fn end_transaction(&mut self, h_card: i32, disp: u32) {
        self.send(
            Command::EndTransaction,
            &HandleArgRv {
                handle: h_card,
                arg: disp,
                rv: 0,
            }
            .to_bytes(),
        );
        let _ = self.recv(HandleArgRv::WIRE_LEN);
    }

    fn disconnect(&mut self, h_card: i32, disp: u32) {
        self.send(
            Command::Disconnect,
            &HandleArgRv {
                handle: h_card,
                arg: disp,
                rv: 0,
            }
            .to_bytes(),
        );
        let _ = self.recv(HandleArgRv::WIRE_LEN);
    }
}

/// VERIFY with fibby's factory PIN 123456.
fn verify_default_pin_apdu() -> Vec<u8> {
    vec![
        0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF,
    ]
}

/// VERIFY with no body: the PIN status query (9000 when verified).
fn pin_status_apdu() -> Vec<u8> {
    vec![0x00, 0x20, 0x00, 0x80]
}

/// piggy#320: what pcscd does for a card shared by two clients. While one
/// holds the transaction, the other's TRANSMIT and BEGIN are refused with a
/// sharing violation instead of interleaving, and the second client closing
/// its handle leaves the card powered with the first client's PIN verified.
/// fibby used to power the card down for everyone on any disconnect and
/// grant every transaction, which broke `card init` beside a running agent.
#[test]
fn a_second_client_neither_interleaves_into_a_transaction_nor_powers_the_card_down() {
    const SHARING_VIOLATION: u32 = 0x8010_000B;
    let path = unique_socket_path();
    start_server(&path, vec![VirtualCard::new()]);
    let (mut a, ctx_a) = open_session(&path);
    let (mut b, ctx_b) = open_session(&path);
    let reader = first_reader(&mut a).reader_name;
    let ha = a.connect_reader(ctx_a, &reader).h_card;
    let hb = b.connect_reader(ctx_b, &reader).h_card;

    assert_eq!(a.begin_transaction(ha), 0);
    a.transmit(ha, &select_piv_apdu());
    assert_eq!(a.transmit(ha, &verify_default_pin_apdu()), vec![0x90, 0x00]);

    assert_eq!(b.transmit_rv(hb, &select_piv_apdu()), SHARING_VIOLATION);
    assert_eq!(b.begin_transaction(hb), SHARING_VIOLATION);
    b.disconnect(hb, disposition::LEAVE);

    assert_eq!(
        a.transmit(ha, &pin_status_apdu()),
        vec![0x90, 0x00],
        "another client's disconnect cleared the transaction holder's PIN"
    );

    // Once the holder lets go, the other client gets in.
    a.end_transaction(ha, disposition::LEAVE);
    let (mut c, ctx_c) = open_session(&path);
    let hc = c.connect_reader(ctx_c, &reader).h_card;
    assert_eq!(c.begin_transaction(hc), 0);
    let _ = std::fs::remove_file(&path);
}

/// Extract the 16 GUID bytes from a `53 …` CHUID GET DATA response by
/// scanning for the `34 10` TLV (test-side convenience, not a parser).
fn guid_of(chuid_resp: &[u8]) -> [u8; 16] {
    let pos = chuid_resp
        .windows(2)
        .position(|w| w == [0x34, 0x10])
        .expect("CHUID response carries a GUID TLV");
    chuid_resp[pos + 2..pos + 18].try_into().unwrap()
}

/// piggy#242 end to end over a real socket: two virtual cards on one
/// fibby — both readers advertised, `SCardConnect` routes by name,
/// interleaved TRANSMITs on the two handles each reach their own card
/// (distinct GUIDs prove it), and an unknown reader name is refused.
#[test]
fn two_readers_route_by_name_over_socket() {
    let mut card_a = VirtualCard::new();
    card_a.set_reader_name("Virtual PCD fibby A 00 00");
    card_a.seed_chuid();
    let mut card_b = VirtualCard::new();
    card_b.set_reader_name("Virtual PCD fibby B 00 00");
    card_b.seed_chuid_with_guid(GUID_B);

    let path = unique_socket_path();
    start_server(&path, vec![card_a, card_b]);
    let mut c = Client {
        stream: UnixStream::connect(&path).unwrap(),
    };

    // Handshake + context.
    c.send(
        Command::Version,
        &VersionStruct {
            major: PROTOCOL_VERSION_MAJOR,
            minor: PROTOCOL_VERSION_MINOR,
            rv: 0,
        }
        .to_bytes(),
    );
    assert_eq!(
        VersionStruct::from_bytes(&c.recv(VersionStruct::WIRE_LEN))
            .unwrap()
            .rv,
        0
    );
    c.send(
        Command::EstablishContext,
        &EstablishStruct {
            dw_scope: scope::SYSTEM,
            h_context: 0,
            rv: 0,
        }
        .to_bytes(),
    );
    let est = EstablishStruct::from_bytes(&c.recv(EstablishStruct::WIRE_LEN)).unwrap();

    // Both readers in the state table, in order, with distinct names.
    c.send(Command::GetReadersState, &[]);
    let arr = c.recv(MAX_READERS_CONTEXTS * ReaderState::WIRE_LEN);
    let slot0 = ReaderState::from_bytes(&arr[0..ReaderState::WIRE_LEN]).unwrap();
    let slot1 =
        ReaderState::from_bytes(&arr[ReaderState::WIRE_LEN..2 * ReaderState::WIRE_LEN]).unwrap();
    let slot2 = ReaderState::from_bytes(&arr[2 * ReaderState::WIRE_LEN..3 * ReaderState::WIRE_LEN])
        .unwrap();
    assert_eq!(slot0.reader_name, "Virtual PCD fibby A 00 00");
    assert_eq!(slot1.reader_name, "Virtual PCD fibby B 00 00");
    assert_ne!(slot0.reader_state & reader_flags::PRESENT, 0);
    assert_ne!(slot1.reader_state & reader_flags::PRESENT, 0);
    assert!(slot2.reader_name.is_empty(), "slot 2 is unused");

    // Connect BOTH readers by name, then interleave transmits: each
    // handle must keep reaching its own card.
    let con_a = c.connect_reader(est.h_context, "Virtual PCD fibby A 00 00");
    assert_eq!(con_a.rv, 0);
    let con_b = c.connect_reader(est.h_context, "Virtual PCD fibby B 00 00");
    assert_eq!(con_b.rv, 0);
    assert_ne!(con_a.h_card, con_b.h_card);

    c.transmit(con_a.h_card, &select_piv_apdu());
    c.transmit(con_b.h_card, &select_piv_apdu());

    let chuid_b = c.transmit(con_b.h_card, &get_chuid_apdu());
    let chuid_a = c.transmit(con_a.h_card, &get_chuid_apdu());
    let chuid_a2 = c.transmit(con_a.h_card, &get_chuid_apdu());
    assert_eq!(guid_of(&chuid_b), GUID_B, "handle B reaches card B");
    assert_ne!(
        guid_of(&chuid_a),
        GUID_B,
        "handle A must not see card B's GUID"
    );
    assert_eq!(guid_of(&chuid_a), guid_of(&chuid_a2), "handle A is stable");

    // Unknown reader name: refused, not silently routed anywhere.
    let bad = c.connect_reader(est.h_context, "No Such Reader 00 00");
    assert_eq!(bad.rv, fibby::error::SCARD_E_UNKNOWN_READER);
    assert_eq!(bad.h_card, -1);

    let _ = std::fs::remove_file(&path);
}

// --- runtime hot-plug (piggy#130) ----------------------------------------

fn start_server_with_control(
    path: &std::path::Path,
    control: &std::path::Path,
    cards: Vec<VirtualCard>,
) {
    let backends = cards
        .into_iter()
        .map(|c| Arc::new(Mutex::new(c)) as server::SharedBackend)
        .collect();
    let serve_path = path.to_path_buf();
    let control_path = control.to_path_buf();
    thread::spawn(move || {
        let _ = server::serve(
            serve_path.to_str().unwrap(),
            backends,
            Some(control_path.to_str().unwrap()),
        );
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while !(path.exists() && control.exists()) {
        assert!(Instant::now() < deadline, "server sockets never appeared");
        thread::sleep(Duration::from_millis(10));
    }
}

/// Send one control command to fibby's control socket and return its reply.
fn ctl_command(control: &std::path::Path, command: &str) -> String {
    let mut s = UnixStream::connect(control).unwrap();
    writeln!(s, "{command}").unwrap();
    let mut reply = String::new();
    s.read_to_string(&mut reply).unwrap();
    reply
}

/// Read slot 0 of GET_READERS_STATE.
fn first_reader(c: &mut Client) -> ReaderState {
    c.send(Command::GetReadersState, &[]);
    let arr = c.recv(MAX_READERS_CONTEXTS * ReaderState::WIRE_LEN);
    ReaderState::from_bytes(&arr[0..ReaderState::WIRE_LEN]).unwrap()
}

/// piggy#130 end to end over real sockets: the control socket toggles a
/// card's runtime presence. After `remove`, GET_READERS_STATE reports the
/// reader ABSENT and CONNECT is refused as no-card; `insert` restores a
/// present, connectable card.
#[test]
fn control_socket_toggles_card_presence() {
    let path = unique_socket_path();
    let control = unique_socket_path();
    start_server_with_control(&path, &control, vec![VirtualCard::new()]);
    let mut c = Client {
        stream: UnixStream::connect(&path).unwrap(),
    };

    // Handshake + context.
    c.send(
        Command::Version,
        &VersionStruct {
            major: PROTOCOL_VERSION_MAJOR,
            minor: PROTOCOL_VERSION_MINOR,
            rv: 0,
        }
        .to_bytes(),
    );
    let _ = c.recv(VersionStruct::WIRE_LEN);
    c.send(
        Command::EstablishContext,
        &EstablishStruct {
            dw_scope: scope::SYSTEM,
            h_context: 0,
            rv: 0,
        }
        .to_bytes(),
    );
    let est = EstablishStruct::from_bytes(&c.recv(EstablishStruct::WIRE_LEN)).unwrap();

    // Present at start; capture the reader name.
    let slot0 = first_reader(&mut c);
    assert_ne!(
        slot0.reader_state & reader_flags::PRESENT,
        0,
        "present at start"
    );
    let reader = slot0.reader_name.clone();

    // Remove -> ABSENT, and CONNECT refused as no-card.
    assert!(
        ctl_command(&control, &format!("remove {reader}")).starts_with("ok"),
        "remove should succeed"
    );
    let after = first_reader(&mut c);
    assert_eq!(
        after.reader_state & reader_flags::PRESENT,
        0,
        "absent after remove"
    );
    assert_ne!(
        after.reader_state & reader_flags::ABSENT,
        0,
        "ABSENT flag set"
    );
    let con = c.connect_reader(est.h_context, &reader);
    assert_eq!(
        con.rv,
        fibby::error::SCARD_E_NO_SMARTCARD,
        "connect to a removed card is refused"
    );
    assert_eq!(con.h_card, -1);

    // Re-insert -> present + connectable again.
    assert!(
        ctl_command(&control, &format!("insert {reader}")).starts_with("ok"),
        "insert should succeed"
    );
    let back = first_reader(&mut c);
    assert_ne!(
        back.reader_state & reader_flags::PRESENT,
        0,
        "present after re-insert"
    );
    let con = c.connect_reader(est.h_context, &reader);
    assert_eq!(con.rv, 0, "connect after re-insert succeeds");
    assert!(con.h_card > 0);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&control);
}

// --- simulated touch (FDR 0006) -------------------------------------------

/// The mgmt-key witness the yk4-init capture shows, and the two GENERAL
/// AUTHENTICATE APDUs that authenticate against it with the factory
/// management key (the vectors `virtual_card.rs`'s own tests use).
const MGMT_WITNESS: [u8; 8] = [0xCA, 0xB1, 0x8C, 0x96, 0xB5, 0x49, 0x7D, 0xAE];
const MGMT_AUTH_PHASE_1: &[u8] = &[
    0x00, 0x87, 0x03, 0x9B, 0x00, 0x00, 0x04, 0x7C, 0x02, 0x81, 0x00, 0x00, 0x00,
];
const MGMT_AUTH_PHASE_2: &[u8] = &[
    0x00, 0x87, 0x03, 0x9B, 0x00, 0x00, 0x0C, 0x7C, 0x0A, 0x82, 0x08, 0x73, 0x1E, 0xFC, 0x2B, 0x4B,
    0xD5, 0x86, 0x10, 0x00,
];

/// GENERATE in slot 9A, ECCP256, PIN policy never (`AA 01 01`) and the
/// given touch policy (`AB 01 <touch>`).
fn generate_9a_pin_never_apdu(touch_policy: u8) -> Vec<u8> {
    vec![
        0x00,
        0x47,
        0x00,
        0x9A,
        0x0B,
        0xAC,
        0x09,
        0x80,
        0x01,
        0x11,
        0xAA,
        0x01,
        0x01,
        0xAB,
        0x01,
        touch_policy,
    ]
}

/// GA ECDSA sign of a 32-byte prehash on slot 9A.
fn sign_9a_apdu() -> Vec<u8> {
    let mut apdu = vec![
        0x00, 0x87, 0x11, 0x9A, 0x26, 0x7C, 0x24, 0x82, 0x00, 0x81, 0x20,
    ];
    apdu.extend_from_slice(&[0x5A; 32]);
    apdu
}

const TOUCH_ALWAYS: u8 = 0x02;

/// A virtual card named `reader` holding a 9A key generated on it with
/// PIN never and touch always, waiting `touch_timeout` for a touch.
fn card_with_touch_always_key(reader: &str, touch_timeout: Duration) -> VirtualCard {
    use fibby::backend::Backend;
    let mut card = VirtualCard::new();
    card.set_reader_name(reader);
    card.set_touch_timeout(touch_timeout);
    card.seed_mgmt_key_witness(MGMT_WITNESS);
    card.transmit(MGMT_AUTH_PHASE_1).unwrap();
    assert_eq!(card.transmit(MGMT_AUTH_PHASE_2).unwrap(), [0x90, 0x00]);
    let generated = card
        .transmit(&generate_9a_pin_never_apdu(TOUCH_ALWAYS))
        .unwrap();
    assert!(generated.ends_with(&[0x90, 0x00]), "GENERATE -> 9000");
    card
}

/// Connect, do the version handshake, and establish a context.
fn open_session(path: &std::path::Path) -> (Client, u32) {
    let mut c = Client {
        stream: UnixStream::connect(path).unwrap(),
    };
    c.send(
        Command::Version,
        &VersionStruct {
            major: PROTOCOL_VERSION_MAJOR,
            minor: PROTOCOL_VERSION_MINOR,
            rv: 0,
        }
        .to_bytes(),
    );
    let _ = c.recv(VersionStruct::WIRE_LEN);
    c.send(
        Command::EstablishContext,
        &EstablishStruct {
            dw_scope: scope::SYSTEM,
            h_context: 0,
            rv: 0,
        }
        .to_bytes(),
    );
    let est = EstablishStruct::from_bytes(&c.recv(EstablishStruct::WIRE_LEN)).unwrap();
    (c, est.h_context)
}

/// The touch path end to end over real sockets. A sign on a touch-always
/// slot blocks in TRANSMIT. While it is blocked, a second client reads
/// the reader table (which locks EVERY card, the blocked one included)
/// and talks to another card, and the control socket's `touch` verb
/// reaches the blocked card: none of that could happen if the waiting
/// connection held the card's lock. The sign then completes. On a card
/// with a short timeout and no touch, the sign fails with 6982.
#[test]
fn control_socket_touch_releases_a_blocked_sign_without_stalling_other_clients() {
    const READER_A: &str = "Virtual PCD fibby touch A 00 00";
    const READER_B: &str = "Virtual PCD fibby touch B 00 00";
    let path = unique_socket_path();
    let control = unique_socket_path();
    start_server_with_control(
        &path,
        &control,
        vec![
            card_with_touch_always_key(READER_A, Duration::from_secs(30)),
            card_with_touch_always_key(READER_B, Duration::from_millis(120)),
        ],
    );

    let (mut c, h_context) = open_session(&path);
    let con_a = c.connect_reader(h_context, READER_A);
    assert_eq!(con_a.rv, 0);

    let other_client = {
        let (path, control) = (path.clone(), control.clone());
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            let started = Instant::now();
            let (mut c2, h_context2) = open_session(&path);
            let slot0 = first_reader(&mut c2); // locks every backend in turn
            assert_eq!(slot0.reader_name, READER_A);
            let con_b = c2.connect_reader(h_context2, READER_B);
            assert_eq!(con_b.rv, 0);
            let selected = c2.transmit(con_b.h_card, &select_piv_apdu());
            assert!(selected.ends_with(&[0x90, 0x00]));
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "card B and the reader table were served while card A waited"
            );
            assert_eq!(
                ctl_command(&control, &format!("touch {READER_A}")).trim_end(),
                "ok pending=1"
            );
        })
    };

    let started = Instant::now();
    let signed = c.transmit(con_a.h_card, &sign_9a_apdu());
    let waited = started.elapsed();
    other_client.join().unwrap();
    assert!(
        signed.ends_with(&[0x90, 0x00]),
        "signed once touched: {signed:02X?}"
    );
    assert!(
        waited >= Duration::from_millis(200),
        "the sign waited for the touch ({waited:?})"
    );
    assert!(
        waited < Duration::from_secs(30),
        "ended by the touch, not the timeout ({waited:?})"
    );

    // Card B: nobody touches it, so its 120 ms timeout answers 6982.
    let con_b = c.connect_reader(h_context, READER_B);
    assert_eq!(con_b.rv, 0);
    let started = Instant::now();
    let refused = c.transmit(con_b.h_card, &sign_9a_apdu());
    assert_eq!(refused, [0x69, 0x82], "touch timeout status word");
    assert!(started.elapsed() >= Duration::from_millis(120));

    assert!(
        ctl_command(&control, "touch No Such Reader 00 00").starts_with("err no such reader"),
        "touch names its card by reader name, like insert/remove"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&control);
}

/// A running `fibby` binary, killed when the test ends.
struct FibbyProcess {
    child: std::process::Child,
    socket: std::path::PathBuf,
    control: std::path::PathBuf,
    log: std::path::PathBuf,
}

impl FibbyProcess {
    /// Start `fibby` with a control socket, the mgmt-key witness the auth
    /// vectors need, `FIBBY_LOG=info` captured to a file, and
    /// `extra_args`.
    fn start(extra_args: &[&str]) -> Self {
        let socket = unique_socket_path();
        let control = unique_socket_path();
        let log = unique_socket_path().with_extension("log");
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_fibby"))
            .arg("--socket")
            .arg(&socket)
            .arg("--control-socket")
            .arg(&control)
            .args(["--seed-mgmt-key-witness", "cab18c96b5497dae"])
            .args(extra_args)
            .env("FIBBY_LOG", "info")
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let fibby = FibbyProcess {
            child,
            socket,
            control,
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !(fibby.socket.exists() && fibby.control.exists()) {
            assert!(Instant::now() < deadline, "fibby sockets never appeared");
            thread::sleep(Duration::from_millis(10));
        }
        fibby
    }

    /// Connect to the one card and generate its touch-always 9A key over
    /// the wire. Returns the client, the card handle and the reader name.
    fn session_with_touch_always_key(&self) -> (Client, i32, String) {
        let (mut c, h_context) = open_session(&self.socket);
        let reader = first_reader(&mut c).reader_name;
        let con = c.connect_reader(h_context, &reader);
        assert_eq!(con.rv, 0);
        c.transmit(con.h_card, MGMT_AUTH_PHASE_1);
        assert_eq!(c.transmit(con.h_card, MGMT_AUTH_PHASE_2), [0x90, 0x00]);
        let generated = c.transmit(con.h_card, &generate_9a_pin_never_apdu(TOUCH_ALWAYS));
        assert!(generated.ends_with(&[0x90, 0x00]), "GENERATE -> 9000");
        (c, con.h_card, reader)
    }

    /// Run `fibby ctl --socket <control> <args>`; returns (success, stdout).
    fn ctl(&self, args: &[&str]) -> (bool, String) {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_fibby"))
            .args(["ctl", "--socket"])
            .arg(&self.control)
            .args(args)
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap()
    }
}

impl Drop for FibbyProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for path in [&self.socket, &self.control, &self.log] {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// The command-line surface, against the real binary: `--touch-timeout-ms`
/// bounds the wait, `fibby ctl touch <reader>` grants a touch, and the
/// TOUCH log lines a bats test would grep are emitted.
#[test]
fn fibby_binary_touch_timeout_flag_ctl_touch_and_log_lines() {
    let fibby = FibbyProcess::start(&["--touch-timeout-ms", "150"]);
    let (mut c, h_card, reader) = fibby.session_with_touch_always_key();

    let started = Instant::now();
    assert_eq!(c.transmit(h_card, &sign_9a_apdu()), [0x69, 0x82]);
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(150) && waited < Duration::from_secs(10),
        "--touch-timeout-ms 150 bounded the wait ({waited:?})"
    );

    let (ok, stdout) = fibby.ctl(&["touch", &reader]);
    assert!(ok, "fibby ctl touch exits 0");
    assert_eq!(stdout, "ok pending=1\n");
    assert!(c.transmit(h_card, &sign_9a_apdu()).ends_with(&[0x90, 0x00]));

    let (ok, stdout) = fibby.ctl(&["touch", "No Such Reader 00 00"]);
    assert!(!ok, "an unknown reader is an error exit");
    assert!(stdout.starts_with("err no such reader"), "got: {stdout}");

    let log = fibby.log_text();
    for line in [
        "[fibby:vcard] TOUCH needed 9A (waiting up to 150 ms)",
        "[fibby:vcard] TOUCH timeout 9A -> 6982",
        &format!("[fibby:ctl] touch queued for '{reader}' (pending=1)"),
        "[fibby:vcard] TOUCH granted 9A",
    ] {
        assert!(log.contains(line), "log lacks {line:?}:\n{log}");
    }
}

/// `--auto-touch`: a touch-always sign succeeds at once with no `ctl
/// touch`, and says so in the log.
#[test]
fn fibby_binary_auto_touch_flag_grants_without_ctl() {
    let fibby = FibbyProcess::start(&["--auto-touch", "--touch-timeout-ms=30000"]);
    let (mut c, h_card, _reader) = fibby.session_with_touch_always_key();

    let started = Instant::now();
    assert!(c.transmit(h_card, &sign_9a_apdu()).ends_with(&[0x90, 0x00]));
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "no wait under --auto-touch"
    );

    let log = fibby.log_text();
    assert!(
        log.contains("[fibby:vcard] TOUCH auto-granted 9A (--auto-touch)"),
        "log:\n{log}"
    );
    assert!(!log.contains("TOUCH needed"), "log:\n{log}");
}

#[test]
fn fibby_binary_rejects_a_non_numeric_touch_timeout() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_fibby"))
        .args(["--touch-timeout-ms", "soon"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("--touch-timeout-ms: want a whole number"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
