# fibby — pure-Rust virtual PIV smart card

fibby implements the **pcsc-lite daemon protocol** in Rust, so PC/SC
clients (`pivy-tool`, `piggy`, `opensc-tool`) connect straight to it via
`PCSCLITE_CSOCK_NAME` — **no `pcscd`, no `vsmartcard-vpcd`, no Java**.
This is the self-contained replacement for the `fib` stack
(`docs/virtual-piv.md`). Design + rationale:
[`docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md`](../../docs/plans/2026-05-29-fibby-virtual-piv-rust-design.md).

## Module map

Each module is small and independently testable — edit one without
holding the rest in your head.

| Module | Responsibility |
|---|---|
| `proto.rs` | pcsc-lite wire codec (structs ↔ bytes), protocol **4.6**. Source of truth: `LudovicRousseau/PCSC` `winscard_msg.{h,c}`. |
| `frame.rs` | message framing: 8-byte header + body in, bare struct out, streamed payloads (TRANSMIT). |
| `error.rs` | `SCARD_*` return codes. |
| `trace.rs` | `FIBBY_LOG`-gated logging + hex dumps (the debugging firehose). |
| `backend.rs` | the `Backend` trait — the seam between protocol and card. |
| `virtual_card.rs` | in-Rust PIV card. **Stub today**: SELECT→9000, else 6D00. Real applet is phase-5. |
| `hardware_proxy.rs` | forwards to a real pcscd/YubiKey via the `pcsc` crate. Feature `hardware-proxy`. The validation oracle. |
| `server.rs` | listen loop + per-command dispatch + handle table. |

## Build & test (no hardware, any platform)

```sh
cargo test -p fibby --no-default-features
```

This covers the codec unit tests **and** `tests/loopback.rs` — a full
PC/SC session (handshake → establish → readers-state → connect →
transmit SELECT → disconnect) driven over a real Unix socket against the
`VirtualCard`. No pcscd, no card.

## Debugging

```sh
FIBBY_LOG=info    # connection lifecycle, one line per command
FIBBY_LOG=debug   # + decoded struct fields
FIBBY_LOG=wire    # + full hex dump of every rx/tx body + APDU
```

## Hardware validation runbook (wet-env)

The point of the proxy pattern: run the *same* protocol server in front
of a real YubiKey and confirm clients behave, then trust the virtual
path. Needs `libpcsclite-dev` + a running system `pcscd` + a plugged-in
YubiKey.

```sh
# 1. Build with the hardware backend.
cargo build -p fibby --features hardware-proxy

# 2. Run fibby as a proxy to the real card, wire-logging everything.
mkdir -p /tmp/fibby
FIBBY_LOG=wire ./target/debug/fibby \
  --backend hardware --reader Yubico --socket /tmp/fibby/pcscd.comm &

# 3. Point a client at fibby (NOT the system pcscd) and exercise PIV.
export PCSCLITE_CSOCK_NAME=/tmp/fibby/pcscd.comm
pivy-tool list
pivy-tool -P 123456 -K default generate 9d   # real card touched THROUGH fibby
```

If `pivy-tool` works through fibby, the protocol layer is correct. The
`FIBBY_LOG=wire` capture is then the conformance fixture the
`VirtualCard` must reproduce.

### What to extend (and where it screams at you)

`server.rs::handle_client` handles VERSION, ESTABLISH/RELEASE_CONTEXT,
GET_READERS_STATE, CONNECT, RECONNECT, DISCONNECT, BEGIN/END_TRANSACTION,
TRANSMIT, STATUS, CANCEL, WAIT_READER_STATE_CHANGE. Any **other** command
is logged at `info` as `UNIMPLEMENTED command … — closing` and the
connection drops. That is deliberate: when a real client needs a command
fibby doesn't speak yet (likely candidates: `GET_ATTRIB`,
`CMD_GET_READERS_STATE_SIZE`/`ARRAY` on newer libpcsclite), you see
*exactly* what it sent in the log, with its body hex-dumped, and add a
handler. No silent wrong-sized replies.

### Spots flagged for wet-env confirmation

Search the source for these — each is a documented assumption that real
hardware will confirm or correct:

- `proto.rs` `ReaderState` — the 184-byte layout / 3-byte ATR padding.
- `server.rs` `wait_reader_state` — static-card timeout semantics.
- `server.rs` `status` — SCardStatus detail comes from the cached
  reader-state array; the round-trip only carries hCard + rv.
- `virtual_card.rs` `YUBIKEY5_ATR` — replace with the captured ATR.
- `hardware_proxy.rs` `map_err` — pcsc→SCARD code mapping.

## Status

Protocol server + both backends + loopback coverage are landed.
`VirtualCard` is a stub pending the PIV applet (GENERATE / GENERAL
AUTHENTICATE / GET·PUT DATA / VERIFY / YubiKey attestation+serial),
which is validated against RFC 0002 Appendix A and SP 800-73-4 vectors —
see the design doc's phasing.
