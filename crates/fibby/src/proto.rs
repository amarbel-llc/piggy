//! pcsc-lite client/daemon wire protocol (the `pcscd.comm` socket).
//!
//! This is the protocol `libpcsclite.so` speaks to `pcscd`. `fibby`
//! implements the *daemon* side of it so that PC/SC clients (pivy-tool,
//! piggy, opensc-tool) connect straight to fibby with no real pcscd or
//! vsmartcard-vpcd in the loop — the clients only need
//! `PCSCLITE_CSOCK_NAME` pointed at fibby's listening socket.
//!
//! Source of truth: LudovicRousseau/PCSC `src/winscard_msg.h` (protocol
//! 4.6) and `src/winscard_msg.c` (framing). Reproduced field-for-field
//! below; drift against a real `libpcsclite` is what the hardware-proxy
//! backend exists to catch.
//!
//! ## Framing
//!
//! Every exchange is a fixed 8-byte header followed by a command-specific
//! body of `size` bytes:
//!
//! ```text
//! struct rxHeader { uint32_t size; uint32_t command; }   // 8 bytes
//! <body: `size` bytes>
//! ```
//!
//! ## Byte order
//!
//! pcsc-lite is a *local* IPC: structs are written with the host's native
//! byte order and natural alignment, no packing attribute. Every field in
//! the structs we handle is either a 4-byte int or a byte array whose
//! length is a multiple of 4 placed at a 4-aligned offset, so the packed
//! little-endian encoding here is bit-identical to the C layout on the
//! little-endian hosts piggy targets (x86-64, aarch64). A big-endian host
//! would need byteswapping; we assert LE at the codec boundary rather than
//! silently mis-encode. See `assert_le_host`.

/// Protocol version fibby advertises in the `CMD_VERSION` handshake.
/// Must match the client's `libpcsclite` major; a mismatch is the sole
/// cause of `SCARD_E_SERVICE_STOPPED` (see Rousseau's pcsc-lite FAQ).
pub const PROTOCOL_VERSION_MAJOR: i32 = 4;
pub const PROTOCOL_VERSION_MINOR: i32 = 6;

/// `MAX_READERNAME` from pcsclite.h.
pub const MAX_READERNAME: usize = 128;
/// `MAX_ATR_SIZE` from pcsclite.h.
pub const MAX_ATR_SIZE: usize = 33;
/// `MAX_BUFFER_SIZE` from pcsclite.h (short APDU buffer).
pub const MAX_BUFFER_SIZE: usize = 264;

/// Size of `struct rxHeader` on the wire.
pub const HEADER_LEN: usize = 8;

/// `SCARD_S_SUCCESS`. Full status-word vocabulary lives in `error.rs`
/// once the dispatcher needs it; the codec only needs success here.
pub const SCARD_S_SUCCESS: u32 = 0x0000_0000;

/// `enum pcsc_msg_commands` (winscard_msg.h). Numeric values are part of
/// the wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Command {
    EstablishContext = 0x01,
    ReleaseContext = 0x02,
    ListReaders = 0x03,
    Connect = 0x04,
    Reconnect = 0x05,
    Disconnect = 0x06,
    BeginTransaction = 0x07,
    EndTransaction = 0x08,
    Transmit = 0x09,
    Control = 0x0A,
    Status = 0x0B,
    GetStatusChange = 0x0C,
    Cancel = 0x0D,
    CancelTransaction = 0x0E,
    GetAttrib = 0x0F,
    SetAttrib = 0x10,
    Version = 0x11,
    GetReadersState = 0x12,
    WaitReaderStateChange = 0x13,
    StopWaitingReaderStateChange = 0x14,
    GetReaderEvents = 0x15,
    GetReadersStateSize = 0x16,
    GetReadersStateArray = 0x17,
}

impl Command {
    pub fn from_u32(v: u32) -> Option<Self> {
        use Command::*;
        Some(match v {
            0x01 => EstablishContext,
            0x02 => ReleaseContext,
            0x03 => ListReaders,
            0x04 => Connect,
            0x05 => Reconnect,
            0x06 => Disconnect,
            0x07 => BeginTransaction,
            0x08 => EndTransaction,
            0x09 => Transmit,
            0x0A => Control,
            0x0B => Status,
            0x0C => GetStatusChange,
            0x0D => Cancel,
            0x0E => CancelTransaction,
            0x0F => GetAttrib,
            0x10 => SetAttrib,
            0x11 => Version,
            0x12 => GetReadersState,
            0x13 => WaitReaderStateChange,
            0x14 => StopWaitingReaderStateChange,
            0x15 => GetReaderEvents,
            0x16 => GetReadersStateSize,
            0x17 => GetReadersStateArray,
            _ => return None,
        })
    }
}

/// `struct rxHeader { uint32_t size; uint32_t command; }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub size: u32,
    pub command: u32,
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(&self.size.to_le_bytes());
        b[4..8].copy_from_slice(&self.command.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < HEADER_LEN {
            return None;
        }
        Some(Header {
            size: u32::from_le_bytes(b[0..4].try_into().ok()?),
            command: u32::from_le_bytes(b[4..8].try_into().ok()?),
        })
    }
}

/// Marker that the codec's packed-LE layout matches the C struct layout
/// on this host. Panics on a big-endian target so a mis-encode is loud,
/// not silent. Cheap; call once at startup.
pub fn assert_le_host() {
    assert!(
        cfg!(target_endian = "little"),
        "fibby's pcsc-lite codec assumes a little-endian host; big-endian \
         needs per-field byteswapping (winscard_msg uses native order)"
    );
}

/// `struct version_struct { int32_t major; int32_t minor; uint32_t rv; }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionStruct {
    pub major: i32,
    pub minor: i32,
    pub rv: u32,
}

impl VersionStruct {
    pub const WIRE_LEN: usize = 12;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        b[0..4].copy_from_slice(&self.major.to_le_bytes());
        b[4..8].copy_from_slice(&self.minor.to_le_bytes());
        b[8..12].copy_from_slice(&self.rv.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        Some(VersionStruct {
            major: i32::from_le_bytes(b[0..4].try_into().ok()?),
            minor: i32::from_le_bytes(b[4..8].try_into().ok()?),
            rv: u32::from_le_bytes(b[8..12].try_into().ok()?),
        })
    }
}

/// `struct establish_struct { uint32_t dwScope; uint32_t hContext; uint32_t rv; }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EstablishStruct {
    pub dw_scope: u32,
    pub h_context: u32,
    pub rv: u32,
}

impl EstablishStruct {
    pub const WIRE_LEN: usize = 12;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        b[0..4].copy_from_slice(&self.dw_scope.to_le_bytes());
        b[4..8].copy_from_slice(&self.h_context.to_le_bytes());
        b[8..12].copy_from_slice(&self.rv.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        Some(EstablishStruct {
            dw_scope: u32::from_le_bytes(b[0..4].try_into().ok()?),
            h_context: u32::from_le_bytes(b[4..8].try_into().ok()?),
            rv: u32::from_le_bytes(b[8..12].try_into().ok()?),
        })
    }
}

/// `struct transmit_struct` header (the APDU payloads are streamed
/// separately after this fixed block, exactly as winscard_msg does).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransmitStruct {
    pub h_card: i32,
    pub io_send_pci_protocol: u32,
    pub io_send_pci_length: u32,
    pub cb_send_length: u32,
    pub io_recv_pci_protocol: u32,
    pub io_recv_pci_length: u32,
    pub pcb_recv_length: u32,
    pub rv: u32,
}

impl TransmitStruct {
    pub const WIRE_LEN: usize = 32;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        b[0..4].copy_from_slice(&self.h_card.to_le_bytes());
        b[4..8].copy_from_slice(&self.io_send_pci_protocol.to_le_bytes());
        b[8..12].copy_from_slice(&self.io_send_pci_length.to_le_bytes());
        b[12..16].copy_from_slice(&self.cb_send_length.to_le_bytes());
        b[16..20].copy_from_slice(&self.io_recv_pci_protocol.to_le_bytes());
        b[20..24].copy_from_slice(&self.io_recv_pci_length.to_le_bytes());
        b[24..28].copy_from_slice(&self.pcb_recv_length.to_le_bytes());
        b[28..32].copy_from_slice(&self.rv.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        let r = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Some(TransmitStruct {
            h_card: i32::from_le_bytes(b[0..4].try_into().ok()?),
            io_send_pci_protocol: r(4),
            io_send_pci_length: r(8),
            cb_send_length: r(12),
            io_recv_pci_protocol: r(16),
            io_recv_pci_length: r(20),
            pcb_recv_length: r(24),
            rv: r(28),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrips() {
        let h = Header {
            size: VersionStruct::WIRE_LEN as u32,
            command: Command::Version as u32,
        };
        let bytes = h.to_bytes();
        // Little-endian, 8 bytes: size=0x0000000C, command=0x00000011.
        assert_eq!(bytes, [0x0C, 0, 0, 0, 0x11, 0, 0, 0]);
        assert_eq!(Header::from_bytes(&bytes), Some(h));
    }

    #[test]
    fn command_numeric_values_match_winscard_msg() {
        // These are the wire contract; a typo here desyncs every client.
        assert_eq!(Command::EstablishContext as u32, 0x01);
        assert_eq!(Command::Transmit as u32, 0x09);
        assert_eq!(Command::Version as u32, 0x11);
        assert_eq!(Command::GetReadersStateArray as u32, 0x17);
        assert_eq!(Command::from_u32(0x0C), Some(Command::GetStatusChange));
        assert_eq!(Command::from_u32(0xFFFF), None);
    }

    #[test]
    fn version_struct_roundtrips() {
        let v = VersionStruct {
            major: PROTOCOL_VERSION_MAJOR,
            minor: PROTOCOL_VERSION_MINOR,
            rv: SCARD_S_SUCCESS,
        };
        let bytes = v.to_bytes();
        assert_eq!(bytes.len(), 12);
        // major=4, minor=6, rv=0 — all little-endian.
        assert_eq!(bytes, [4, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(VersionStruct::from_bytes(&bytes), Some(v));
    }

    #[test]
    fn establish_struct_roundtrips() {
        let e = EstablishStruct {
            dw_scope: 2, // SCARD_SCOPE_SYSTEM
            h_context: 0xDEAD_BEEF,
            rv: SCARD_S_SUCCESS,
        };
        assert_eq!(EstablishStruct::from_bytes(&e.to_bytes()), Some(e));
    }

    #[test]
    fn transmit_struct_roundtrips_and_is_32_bytes() {
        let t = TransmitStruct {
            h_card: 0x1122_3344,
            io_send_pci_protocol: 2, // T=1
            io_send_pci_length: 8,
            cb_send_length: 5,
            io_recv_pci_protocol: 2,
            io_recv_pci_length: 8,
            pcb_recv_length: 258,
            rv: SCARD_S_SUCCESS,
        };
        let bytes = t.to_bytes();
        assert_eq!(bytes.len(), 32);
        assert_eq!(TransmitStruct::from_bytes(&bytes), Some(t));
    }

    #[test]
    fn from_bytes_rejects_short_input() {
        assert_eq!(Header::from_bytes(&[0u8; 7]), None);
        assert_eq!(VersionStruct::from_bytes(&[0u8; 11]), None);
        assert_eq!(TransmitStruct::from_bytes(&[0u8; 31]), None);
    }
}
