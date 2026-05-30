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
    const {
        assert!(
            cfg!(target_endian = "little"),
            "fibby's pcsc-lite codec assumes a little-endian host; big-endian \
             needs per-field byteswapping (winscard_msg uses native order)"
        );
    }
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

/// `struct connect_struct`. `szReader` is a fixed 128-byte
/// NUL-terminated field on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectStruct {
    pub h_context: u32,
    pub sz_reader: String,
    pub dw_share_mode: u32,
    pub dw_preferred_protocols: u32,
    pub h_card: i32,
    pub dw_active_protocol: u32,
    pub rv: u32,
}

impl ConnectStruct {
    pub const WIRE_LEN: usize = 4 + MAX_READERNAME + 4 + 4 + 4 + 4 + 4; // 152

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; Self::WIRE_LEN];
        b[0..4].copy_from_slice(&self.h_context.to_le_bytes());
        write_cstr(&mut b[4..4 + MAX_READERNAME], &self.sz_reader);
        let o = 4 + MAX_READERNAME;
        b[o..o + 4].copy_from_slice(&self.dw_share_mode.to_le_bytes());
        b[o + 4..o + 8].copy_from_slice(&self.dw_preferred_protocols.to_le_bytes());
        b[o + 8..o + 12].copy_from_slice(&self.h_card.to_le_bytes());
        b[o + 12..o + 16].copy_from_slice(&self.dw_active_protocol.to_le_bytes());
        b[o + 16..o + 20].copy_from_slice(&self.rv.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        let o = 4 + MAX_READERNAME;
        Some(ConnectStruct {
            h_context: u32::from_le_bytes(b[0..4].try_into().ok()?),
            sz_reader: read_cstr(&b[4..4 + MAX_READERNAME]),
            dw_share_mode: u32::from_le_bytes(b[o..o + 4].try_into().ok()?),
            dw_preferred_protocols: u32::from_le_bytes(b[o + 4..o + 8].try_into().ok()?),
            h_card: i32::from_le_bytes(b[o + 8..o + 12].try_into().ok()?),
            dw_active_protocol: u32::from_le_bytes(b[o + 12..o + 16].try_into().ok()?),
            rv: u32::from_le_bytes(b[o + 16..o + 20].try_into().ok()?),
        })
    }
}

/// Tiny two-field structs (`disconnect_struct`, `end_struct` share a
/// shape; `begin_struct`, `status_struct`, `release_struct`,
/// `cancel_struct` are subsets). One codec covers the
/// `{ i32 handle; u32 arg; u32 rv }` and `{ i32 handle; u32 rv }`
/// families; callers pick the field count. Keeping these as explicit
/// little structs (rather than one mega-enum) keeps the dispatcher
/// readable and easy to extend per command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleArgRv {
    pub handle: i32,
    pub arg: u32,
    pub rv: u32,
}

impl HandleArgRv {
    pub const WIRE_LEN: usize = 12;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        b[0..4].copy_from_slice(&self.handle.to_le_bytes());
        b[4..8].copy_from_slice(&self.arg.to_le_bytes());
        b[8..12].copy_from_slice(&self.rv.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        Some(HandleArgRv {
            handle: i32::from_le_bytes(b[0..4].try_into().ok()?),
            arg: u32::from_le_bytes(b[4..8].try_into().ok()?),
            rv: u32::from_le_bytes(b[8..12].try_into().ok()?),
        })
    }
}

/// `{ i32 handle; u32 rv }` — `begin_struct`, `status_struct`,
/// `release_struct` (with hContext), `cancel_struct`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleRv {
    pub handle: i32,
    pub rv: u32,
}

impl HandleRv {
    pub const WIRE_LEN: usize = 8;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        b[0..4].copy_from_slice(&self.handle.to_le_bytes());
        b[4..8].copy_from_slice(&self.rv.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        Some(HandleRv {
            handle: i32::from_le_bytes(b[0..4].try_into().ok()?),
            rv: u32::from_le_bytes(b[4..8].try_into().ok()?),
        })
    }
}

/// `PCSCLITE_MAX_READERS_CONTEXTS` — the fixed slot count in the
/// reader-state array returned by `CMD_GET_READERS_STATE`.
pub const MAX_READERS_CONTEXTS: usize = 16;

/// `READER_STATE` (eventhandler.h). 184 bytes including 3 pad bytes
/// after the 33-byte ATR (so `cardAtrLength` lands on a 4-aligned
/// offset). The padding is load-bearing: get it wrong and every field
/// after the ATR shifts. The hardware-proxy backend is the cheapest
/// way to confirm this against a real `libpcsclite`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderState {
    pub reader_name: String,
    pub event_counter: u32,
    pub reader_state: u32,
    pub reader_sharing: i32,
    pub card_atr: Vec<u8>,
    pub card_protocol: u32,
}

impl ReaderState {
    pub const WIRE_LEN: usize = 184;
    const ATR_OFF: usize = 140;
    const ATR_LEN_OFF: usize = 176; // 140 + 33 = 173, padded up to 176
    const PROTO_OFF: usize = 180;

    /// An empty/unused slot — all zero, matching pcscd's freshly-zeroed
    /// reader-state table.
    pub fn empty() -> Self {
        ReaderState {
            reader_name: String::new(),
            event_counter: 0,
            reader_state: 0,
            reader_sharing: 0,
            card_atr: Vec::new(),
            card_protocol: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut b = [0u8; Self::WIRE_LEN];
        write_cstr(&mut b[0..MAX_READERNAME], &self.reader_name);
        b[128..132].copy_from_slice(&self.event_counter.to_le_bytes());
        b[132..136].copy_from_slice(&self.reader_state.to_le_bytes());
        b[136..140].copy_from_slice(&self.reader_sharing.to_le_bytes());
        let atr = &self.card_atr[..self.card_atr.len().min(MAX_ATR_SIZE)];
        b[Self::ATR_OFF..Self::ATR_OFF + atr.len()].copy_from_slice(atr);
        b[Self::ATR_LEN_OFF..Self::ATR_LEN_OFF + 4]
            .copy_from_slice(&(atr.len() as u32).to_le_bytes());
        b[Self::PROTO_OFF..Self::PROTO_OFF + 4].copy_from_slice(&self.card_protocol.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < Self::WIRE_LEN {
            return None;
        }
        let atr_len = u32::from_le_bytes(
            b[Self::ATR_LEN_OFF..Self::ATR_LEN_OFF + 4]
                .try_into()
                .ok()?,
        ) as usize;
        let atr_len = atr_len.min(MAX_ATR_SIZE);
        Some(ReaderState {
            reader_name: read_cstr(&b[0..MAX_READERNAME]),
            event_counter: u32::from_le_bytes(b[128..132].try_into().ok()?),
            reader_state: u32::from_le_bytes(b[132..136].try_into().ok()?),
            reader_sharing: i32::from_le_bytes(b[136..140].try_into().ok()?),
            card_atr: b[Self::ATR_OFF..Self::ATR_OFF + atr_len].to_vec(),
            card_protocol: u32::from_le_bytes(
                b[Self::PROTO_OFF..Self::PROTO_OFF + 4].try_into().ok()?,
            ),
        })
    }
}

/// Serialize a full `READER_STATE[MAX_READERS_CONTEXTS]` array (the
/// `CMD_GET_READERS_STATE` reply). Slots past `states` are zeroed.
pub fn readers_state_array(states: &[ReaderState]) -> Vec<u8> {
    let mut out = vec![0u8; MAX_READERS_CONTEXTS * ReaderState::WIRE_LEN];
    for (i, st) in states.iter().take(MAX_READERS_CONTEXTS).enumerate() {
        let off = i * ReaderState::WIRE_LEN;
        out[off..off + ReaderState::WIRE_LEN].copy_from_slice(&st.to_bytes());
    }
    out
}

/// Write a NUL-terminated string into a fixed-width field, truncating
/// if needed and always leaving at least the final byte NUL. Zeroes the
/// whole field first so the result never depends on prior buffer
/// contents (no implicit "caller must pre-zero" contract).
fn write_cstr(dst: &mut [u8], s: &str) {
    dst.fill(0);
    let max = dst.len().saturating_sub(1);
    let bytes = s.as_bytes();
    let n = bytes.len().min(max);
    dst[..n].copy_from_slice(&bytes[..n]);
}

/// Read a NUL-terminated string from a fixed-width field.
fn read_cstr(src: &[u8]) -> String {
    let end = src.iter().position(|&c| c == 0).unwrap_or(src.len());
    String::from_utf8_lossy(&src[..end]).into_owned()
}

// --- protocol constants (pcsclite.h) -------------------------------------

/// `SCARD_SCOPE_*`.
pub mod scope {
    pub const USER: u32 = 0;
    pub const TERMINAL: u32 = 1;
    pub const SYSTEM: u32 = 2;
}

/// `SCARD_SHARE_*`.
pub mod share {
    pub const EXCLUSIVE: u32 = 1;
    pub const SHARED: u32 = 2;
    pub const DIRECT: u32 = 3;
}

/// `SCARD_PROTOCOL_*`.
pub mod protocol {
    pub const UNDEFINED: u32 = 0;
    pub const T0: u32 = 1;
    pub const T1: u32 = 2;
    pub const RAW: u32 = 4;
    pub const ANY: u32 = T0 | T1;
}

/// `SCARD_*_CARD` dispositions (disconnect / end-transaction).
pub mod disposition {
    pub const LEAVE: u32 = 0;
    pub const RESET: u32 = 1;
    pub const UNPOWER: u32 = 2;
    pub const EJECT: u32 = 3;
}

/// Internal `readerState` bit flags (pcsclite.h). These are the
/// daemon-side state bits stored in `READER_STATE.readerState`, not the
/// `SCARD_STATE_*` flags the client app sees.
pub mod reader_flags {
    pub const UNKNOWN: u32 = 0x0001;
    pub const ABSENT: u32 = 0x0002;
    pub const PRESENT: u32 = 0x0004;
    pub const SWALLOWED: u32 = 0x0008;
    pub const POWERED: u32 = 0x0010;
    pub const NEGOTIABLE: u32 = 0x0020;
    pub const SPECIFIC: u32 = 0x0040;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Codec tests only need the success code; the full SCARD_* vocabulary
    // lives in error.rs (proto is the lower layer and stays code-free).
    const SCARD_S_SUCCESS: u32 = 0;

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

    #[test]
    fn connect_struct_roundtrips_and_is_152_bytes() {
        let c = ConnectStruct {
            h_context: 0x0101_0101,
            sz_reader: "Yubico YubiKey OTP+FIDO+CCID 00 00".to_string(),
            dw_share_mode: share::SHARED,
            dw_preferred_protocols: protocol::ANY,
            h_card: 0,
            dw_active_protocol: 0,
            rv: SCARD_S_SUCCESS,
        };
        let bytes = c.to_bytes();
        assert_eq!(bytes.len(), ConnectStruct::WIRE_LEN);
        assert_eq!(bytes.len(), 152);
        assert_eq!(ConnectStruct::from_bytes(&bytes), Some(c));
    }

    #[test]
    fn reader_state_layout_is_184_bytes_with_atr_padding() {
        let rs = ReaderState {
            reader_name: "Virtual PCD piggy fibby 00 00".to_string(),
            event_counter: 1,
            reader_state: reader_flags::PRESENT | reader_flags::POWERED | reader_flags::NEGOTIABLE,
            reader_sharing: 0,
            card_atr: vec![0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80],
            card_protocol: protocol::T1,
        };
        let bytes = rs.to_bytes();
        assert_eq!(bytes.len(), 184);
        // ATR length lands at offset 176 (33-byte ATR field at 140 + 3 pad).
        assert_eq!(&bytes[176..180], &10u32.to_le_bytes());
        // cardProtocol at 180.
        assert_eq!(&bytes[180..184], &protocol::T1.to_le_bytes());
        assert_eq!(ReaderState::from_bytes(&bytes), Some(rs));
    }

    #[test]
    fn readers_state_array_is_fixed_16_slots() {
        let arr = readers_state_array(&[ReaderState {
            reader_name: "r".into(),
            event_counter: 0,
            reader_state: reader_flags::PRESENT,
            reader_sharing: 0,
            card_atr: vec![0x3B],
            card_protocol: protocol::T1,
        }]);
        assert_eq!(arr.len(), MAX_READERS_CONTEXTS * ReaderState::WIRE_LEN);
        assert_eq!(arr.len(), 16 * 184);
        // Slot 0 populated, slot 1 zeroed.
        assert_eq!(
            ReaderState::from_bytes(&arr[0..184]).unwrap().reader_name,
            "r"
        );
        assert_eq!(
            ReaderState::from_bytes(&arr[184..368]),
            Some(ReaderState::empty())
        );
    }

    #[test]
    fn handle_codecs_roundtrip() {
        let a = HandleArgRv {
            handle: -1,
            arg: disposition::RESET,
            rv: 0,
        };
        assert_eq!(HandleArgRv::from_bytes(&a.to_bytes()), Some(a));
        let h = HandleRv {
            handle: 7,
            rv: SCARD_S_SUCCESS,
        };
        assert_eq!(HandleRv::from_bytes(&h.to_bytes()), Some(h));
    }

    #[test]
    fn cstr_truncates_and_nul_terminates() {
        let mut buf = [0xFFu8; 8];
        write_cstr(&mut buf, "abcdefghijk");
        assert_eq!(&buf[..7], b"abcdefg"); // 7 chars + reserved NUL slot
        assert_eq!(buf[7], 0);
        assert_eq!(read_cstr(&buf), "abcdefg");
    }
}
