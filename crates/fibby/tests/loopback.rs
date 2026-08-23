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
        let _ = server::serve(serve_path.to_str().unwrap(), backends);
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
