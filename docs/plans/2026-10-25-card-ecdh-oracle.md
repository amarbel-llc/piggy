# piggy#341: a card ECDH oracle for pigpen, over any PIV transport

Status: design note (2026-10-25). The PIV-side core is being built
fibby-backed; the crate boundary for the pigpen adapter is an open
decision.

## What pigsty needs

pigsty's Linux unlock asks `piggy_pigpen::agent::AgentEcdhOracle` first.
Its fallback, and its Android path, need the same
`piggy_pigpen::EcdhOracle` over a PIV session: an `ApduTransport` the
caller supplies (PC/SC on Linux, NFC/USB on Android), a PIN from the
app's own dialog, and the slot-9D ECDH of RFC 0008 §4.3. pigsty must not
reimplement PIV crypto. piggy's existing `card_oracle.rs::CardEcdhOracle`
implements piggy-box's trait inside the `piggy` binary crate (OpenSSL,
tokio, askpass), so pigsty cannot link it.

## The core, in piggy-piv (`piggy_piv::card_ecdh`)

Independent of pigpen's types, so it has no crate-boundary question:

```rust
pub struct PinRequest<'a> { pub token_guid: &'a Guid, pub slot: u8,
                            pub retries_remaining: Option<u8> }
pub trait PinSource: Send {
    fn pin(&self, req: &PinRequest<'_>) -> Result<Zeroizing<String>, PinDeclined>;
}
pub struct CardEcdh { /* Mutex<PivToken>, Box<dyn PinSource>, PIN cache */ }
impl CardEcdh {
    pub fn new(token: PivToken, pin: Box<dyn PinSource>) -> Self;
    /// Offline (no PIN): does slot 9D hold this SEC1 P-256 point?
    pub fn holds(&self, recipient: &[u8]) -> Result<bool, CardEcdhError>;
    /// X of (9D private · partner), 32 bytes.
    pub fn ecdh(&self, recipient: &[u8], partner: &[u8])
        -> Result<Zeroizing<[u8; 32]>, CardEcdhError>;
}
pub enum CardEcdhError { NotThisCard, PinDeclined, PinBlocked, Piv(PivError) }
```

Per `ecdh` call:
1. Lock the token and open a PIN session.
2. Read slot 9D inside the session, before the VERIFY (piggy#325).
3. Compare its point with the recipient, both normalized to SEC1
   uncompressed through `p256`. A mismatch is `NotThisCard`, which the
   adapter maps to pigpen's "try the next recipient".
4. Take the PIN from the cache, or ask `PinSource` with
   `retries_remaining: None`, then VERIFY.
   - A wrong PIN clears the cache and asks again with the card's counter.
   - `PinDeclined` ends the call without another VERIFY.
   - A blocked PIN is terminal.
5. GENERAL AUTHENTICATE with the uncompressed partner point.
6. Copy out the 32-byte X and zeroize the card's response.
7. End the session with `ResetCard`, as every PIN session already does.

The PIN is cached for the oracle's lifetime, so a process unseals with one
PIN, matching madder-store's one unseal per process.

`PinSource` is synchronous, so pigsty runs the oracle off its UI thread. An
async variant would be a separate feature, not a change to this trait.
Discovery (which reader holds the recipient) stays with the caller: on
Linux `enumerate_tokens` plus `holds`; on Android the app hands in its own
transport.

Tests: fibby's `VirtualCard` as an in-process transport (no pcscd), seeded
with the RFC 5903 9D key. They cover:
- the derived X matches a software ECDH against the card's public key;
- a wrong PIN re-asks with the counter;
- a declined PIN costs no second VERIFY;
- a recipient the card does not hold is refused before any PIN is asked;
- the PIN is asked once across two calls.

## Open: where the `impl piggy_pigpen::EcdhOracle` adapter lives

It is about ten lines: check the recipient's format, then call
`CardEcdh::ecdh(id.data(), epk)` and map the errors. The question is
which crate depends on which.

| Option | Cost |
|---|---|
| (a) piggy-piv gains an optional `pigpen` feature with a path dependency on piggy-pigpen (#341's text) | piggy-pigpen is excluded from the workspace on purpose (own Cargo.lock, not in nix's `sharedCargoLock`; the root Cargo.toml calls promoting it "a cutover step", RFC 0008 Compatibility). An optional path dependency is still locked, so this starts that cutover. |
| (b) piggy-pigpen gains an optional `card` feature depending on piggy-piv (`default-features = false`) | piggy-pigpen stops being a leaf. piggy-piv and its dependencies enter pigpen's own lock. That stays pure Rust only once #337 removes OpenSSL. |
| (c) The adapter lives in pigsty | No boundary change in piggy. pigsty writes ten lines of glue; the PIV crypto (point check, ECDH, PIN handling) stays in piggy-piv. |

Recommendation (inference): (c) now, and (a) when pigpen is promoted into
the workspace (RFC 0009 cutover). By then the adapter moves into piggy with
no API change to `CardEcdh`. This is a decision for the operator or
coordinator; the core above lands either way.
