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
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("fibby-loopback-{}-{}.sock", std::process::id(), nanos))
}

fn start_server(path: &std::path::Path) {
    let backend = Arc::new(Mutex::new(VirtualCard::new()));
    let serve_path = path.to_path_buf();
    thread::spawn(move || {
        let _ = server::serve(serve_path.to_str().unwrap(), backend);
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
    start_server(&path);
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
    assert_ne!(slot0.reader_state & reader_flags::PRESENT, 0, "card present");
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
