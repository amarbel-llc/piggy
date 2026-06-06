---
status: draft (spike validated; hardware gate pending)
date: 2026-06-06
fdr: TBD — file into amarbel-llc/eng FDR series (next number; prior art FDR-0004)
provenance: |
  Authored on branch claude/piggy-wasm-webauthn-access-J3gBD alongside
  the spike at spikes/wasm-piv-decrypt/. Captures the design for a
  browser WASM module that decrypts piggy `.ebox` blobs gated by a PIV
  card, so linenisgreat.com can serve encrypted blob data publicly and
  only authorized YubiKey holders can read it. Related: amarbel-llc/eng
  FDR-0004 (RCM piggy ebox decryption hook), docs/rfcs/0002-piv-ecdh-box.md
  (box wire format — the normative crypto this rides on), linenisgreat
  docs/decisions/0001 (app/api split) and the API blob/formats mechanism
  (linenisgreat docs/plans/2026-06-04-og-image-api-format-*). This file
  lives in piggy because the crypto + new piggy-wasm crate are piggy's;
  relocate/renumber when filed into eng.
---

# FDR — PIV-gated WASM decrypt for linenisgreat blobs

## TL;DR

Encrypt linenisgreat's gated **blob data** as piggy `.ebox` and serve the
ciphertext publicly. A browser WASM module (new `piggy-wasm`, on an
OpenSSL-free `piggy-box` backend) decrypts it client-side; the slot-9D
**ECDH** that unlocks the box is performed on the user's **PIV card reached
over WebUSB**. The page shell stays plaintext — only the blob is ciphertext,
and **the crypto is the gate** (no server-side auth, sessions, or login).

The crypto half is **proven** (RFC 0002 vectors decrypt through pure Rust,
native + `wasm32`). The remaining unknown is the WebUSB→PIV ECDH transport,
which requires a **hardware test session** — gated and scripted below.

## Problem

linenisgreat is fully public today: server-rendered PHP, public JSON API,
static assets, no auth. We want certain blob content readable only by holders
of an authorized PIV card, without standing up server-side auth and without
trusting the server with plaintext.

## Decision

### The crypto is the gate

> Encrypt the gated blob as a `.ebox` (to one or more authorized PIV
> recipient pubkeys via `piggy-ids`) and serve the ciphertext publicly. Only
> a holder of an authorized PIV card can ECDH-decrypt it in the browser.

No sessions, login endpoint, PHP middleware, or JWT. The server serves opaque
bytes. This reuses the exact mechanism linenisgreat already uses for its own
secrets (`secrets/*.ebox`). **Scope refinement (owner):** only the *blob
data* is ciphertext — the app shell, templates, and WASM loader remain
public/plaintext.

### PIV, not WebAuthn

piggy `.ebox` are ECDH boxes (RFC 0002): every box is encrypted to a PIV
**slot 9D (Key Management / ECDH)** public key. Decryption *requires* an ECDH
between the box's ephemeral pubkey and the card's 9D private key.

- **WebAuthn (FIDO2) cannot perform this ECDH** — it is a signing/assertion
  protocol over a *different* credential, and its `prf` extension derives a
  *symmetric* key, not an ECDH-to-9D. It can never decrypt an existing `.ebox`.
- Therefore PIV is the gating mechanism. WebAuthn, if ever added, is only a
  separate login layer — not the thing that unlocks content.

### Architecture — the `EcdhOracle` seam, moved to the JS↔WASM boundary

piggy-box already splits decryption at an `EcdhOracle` trait ("give me a
shared secret for these two pubkeys"; native impls: SSH-agent, direct-PCSC).
The WASM module reuses that seam, but the oracle lives in **JS** because WASM
can't touch USB:

```
BUILD   blob ──piggy-ids encrypt──▶ blob.ebox     (recipients = authorized PIV pubkeys)
SERVE   blob.ebox via API …/blob/formats/ebox     (public, opaque ciphertext)
BROWSER 1. WASM  parse_box(ebox)      → ephemeral pubkey + nonce + iv     (no key needed)
        2. JS    WebUSB → PIV slot 9D → GENERAL AUTHENTICATE (ECDH) → Z    (PIN-gated)
        3. WASM  open_box(ebox, Z)    → SHA-512(Z‖nonce) → ChaCha20-Poly1305 → plaintext
```

The WASM module does the OpenSSL-free symmetric half; JS supplies `Z`. `Z` is
the ECDH X-coordinate (field-size, big-endian) — byte-identical across
OpenSSL `Deriver`, RustCrypto, and the card's `GENERAL AUTHENTICATE`.

### Transport choice: WebUSB → PIV applet (with a fallback)

Chosen by the owner. Fully client-side, no server trust. **Fallback if PC/SC
contention proves a dealbreaker:** a localhost piggy-agent/pivy-agent bridge
exposing the ECDH oracle — same proven WASM half, different `Z` source.

## Components & where code lives

| Component | Status | Location |
|---|---|---|
| Pure-Rust decrypt (`parse_box`/`open_box`) | ✅ spike, proven | `spikes/wasm-piv-decrypt/src/lib.rs` |
| RFC 0002 vector replay (native + wasm32) | ✅ spike, proven | `spikes/wasm-piv-decrypt/tests/` |
| Loop-closing CLI (`box + Z → plaintext`) | ✅ spike | `spikes/wasm-piv-decrypt/examples/open.rs` |
| WebUSB → PIV ECDH harness | ⚠ needs hardware | `spikes/wasm-piv-decrypt/webusb-piv-ecdh-harness.html` |
| `piggy-box` `backend-rustcrypto` cargo feature | future | `crates/piggy-box` |
| `crates/piggy-wasm` (wasm-bindgen + packaged JS glue) | future | new crate |
| linenisgreat: encrypt recipe + `…/blob/formats/ebox` + loader | future | linenisgreat `app/`,`api/`,`justfile` |

## Spike status — what is already proven

Pure Rust, zero `openssl`/`pcsc`: `sha2` + `chacha20poly1305` + `p256`/`p384`.

- All three RFC 0002 §A vectors (A.1/A.2/A.3) decrypt cleanly.
- The vectors were **sealed by OpenSSL**; a passing Poly1305 tag is a
  byte-exact proof that RustCrypto ECDH == OpenSSL `Deriver` == card
  `GENERAL AUTHENTICATE`, and that KDF+AEAD+unpad match piggy-box.
- Wrong-key and tampered-tag cases correctly fail authentication.
- Builds to `wasm32-unknown-unknown` (cdylib → real `.wasm`); native tests pass.

This is exactly the swap the future `piggy-box backend-rustcrypto` feature
makes (openssl → these crates) so `piggy-wasm` can compile.

---

## Hardware test session (the gate)

> **Objective.** Demonstrate that a YubiKey, reached from a browser over
> WebUSB, performs slot-9D ECDH whose result `Z` decrypts a real `.ebox`
> addressed to that card — i.e. validate the only unproven link in the
> architecture.
>
> **Session passes iff:** Gate G6 is reached (Rust `open_box --box <real> --z
> <hardware Z>` prints the original plaintext) on at least one box on at least
> one curve, in Chromium, with no manual key material entered.

### Preconditions (assemble before starting — do not improvise mid-session)

Tick every box; a missing item invalidates the run.

- [ ] **Browser:** Chromium-family (Chrome/Edge/Brave), WebUSB enabled, page
      served from `https://` or `http://localhost` (WebUSB refuses `file://`).
- [ ] **OS PC/SC freed:** the system smartcard service must not hold the CCID
      interface. Linux: `sudo systemctl stop pcscd pcscd.socket` (and confirm
      nothing restarts it). macOS/Windows: expect contention; see Risks.
- [ ] **Toolchain:** `cargo` + the spike crate building
      (`cd spikes/wasm-piv-decrypt && cargo test` is green).
- [ ] **Test YubiKey** (prefer a *non-production* key — see Safety):
  - [ ] PIV applet present; slot **9D** holds an **EC** key on **P-256 or
        P-384** (RSA 9D cannot ECDH — abort if so).
  - [ ] **PIN is known and correct** (confirm out-of-band — a wrong PIN burns
        a retry; see Safety).
  - [ ] Slot-9D **PIN policy** = `once`/`always` is fine; **touch policy** =
        note whether a tap is required (harness does not prompt for touch).
- [ ] **Test box:** a `.ebox` encrypted to that card's 9D pubkey, with its
      plaintext known to you. Produce via piggy (`piggy-ids encrypt`) or
      `pivy-box`. Hold it as **hex** (the CLI takes `--box <hex>`).
- [ ] **No production secrets** used as the test box plaintext.

### Gates (run in order; abort the session at the first hard failure)

| Gate | Action | Pass condition | On fail |
|---|---|---|---|
| **G0** | `cargo test` in the spike | 3 vectors green | fix toolchain before touching hardware |
| **G1** | `cargo run --example open -- --box <hex>` | prints curve + uncompressed `ephemeral_pubkey` + GUID/slot | box malformed / wrong tool — re-export |
| **G2** | Open harness, click *Connect* | device picker lists the YubiKey; `claimInterface` succeeds | "busy" ⇒ PC/SC still holds it (precondition 2); no device ⇒ wrong VID/permissions |
| **G3** | PowerOn + SELECT PIV | ATR logged; SELECT returns `0x9000` | `0x6A82` ⇒ no PIV applet |
| **G4** | VERIFY PIN | `0x9000` | `0x63CX` wrong PIN (X left) — **abort, do not retry blind**; `0x6983` PIN blocked |
| **G5** | GENERAL AUTHENTICATE (ECDH) | `0x9000`; harness prints `Z` of field length (32 B P-256 / 48 B P-384) | see SW triage; curve/alg mismatch ⇒ wrong alg byte for the 9D key |
| **G6** | `cargo run --example open -- --box <hex> --z <Z>` | prints the **original plaintext** | AEAD fail ⇒ `Z` wrong (curve mismatch, point form, or card returned a different secret) |

`Z` must equal what `cargo test -- --nocapture` prints for the matching
vector *only when testing a vector box*; for a real card box there is no
pre-known `Z`, so G6 (authenticated decrypt) is the authority.

### Safety conditions (read before G4)

- **Card lockout is the real risk.** Default PIV PIN retry is typically **3**.
  Each wrong VERIFY decrements it; exhausting it **blocks the PIN** (needs PUK
  to reset, or bricks the slot if PUK is also exhausted). **Confirm the PIN is
  correct before G4. On `0x63CX`, stop the session** and re-confirm the PIN
  out-of-band; do not keep clicking.
- **Use a sacrificial/test YubiKey** if available, not your daily-driver
  production card.
- **PIN handling in the harness:** entered in a plain field, sent only as the
  VERIFY APDU, never logged or persisted. Do not run the harness on a shared
  or screen-shared display. (This mirrors piggy's askpass-leak discipline:
  no prompt should escape to an ambient handler.)
- **No production blob** as the test plaintext until the mechanism is trusted.
- **Restore PC/SC** (`systemctl start pcscd.socket`) after the session.

### Procedure

1. Free PC/SC; serve the harness over localhost/https; open in Chromium.
2. **G0** then **G1** — capture the printed `ephemeral_pubkey` + curve.
3. In the harness: select the curve, paste the uncompressed `ephemeral_pubkey`,
   enter the PIN.
4. Click *Connect & run ECDH* → walk **G2–G5**; copy the printed `Z`.
5. **G6:** `cargo run --example open -- --box <hex> --z <Z>` → expect plaintext.
6. Repeat for a P-384 box if a P-384 9D key is available (covers both alg bytes).
7. Restore pcscd.

### SW-code triage (G3–G5)

| SW | Meaning | Likely cause / action |
|---|---|---|
| `0x9000` | OK | — |
| `0x6A82` | applet/file not found | SELECT AID wrong or PIV absent |
| `0x6982` | security status not satisfied | PIN not verified before GA — order bug |
| `0x6983` | auth method blocked | **PIN blocked** — stop; needs PUK |
| `0x63CX` | wrong PIN, X tries left | **abort**, re-confirm PIN |
| `0x6A80` | wrong data in field | GA template malformed (7C/82/85 framing) |
| `0x6A86` | wrong P1/P2 | wrong alg byte (0x11 P-256 / 0x14 P-384) or slot ref |
| `0x6D00` | INS not supported | applet/firmware quirk — record and report |
| `0x6700` | wrong length | Lc/extended-length handling — record and report |

### Out of scope for this session

- wasm-bindgen packaging / calling the `.wasm` from the page (the spike CLI
  stands in for `open_box`).
- linenisgreat wiring (API `…/blob/formats/ebox`, loader template, CSP).
- Multi-recipient / Shamir boxes (single-recipient 9D box only).
- Firefox/Safari (WebUSB unsupported by design).

## Risks & open questions

- **WebUSB ↔ OS PC/SC contention** — primary risk; the fallback (local agent
  bridge) exists if it can't be reliably resolved on target machines.
- **Chromium-only** — acceptable for a gated-content niche; documented to users.
- **Slot-9D touch policy** — if set, the harness needs a touch step (TODO if hit).
- **Decrypted-HTML injection** — out of this session, but the eventual loader
  must set a CSP and treat blob content as author-trusted.

## Next steps if the gate is green

1. `piggy-box`: add `backend-rustcrypto` feature (openssl → sha2/chacha20poly1305/p256/p384), behind the existing internal crypto API; keep RFC 0002 vectors passing under both backends.
2. `crates/piggy-wasm`: `wasm-bindgen` surface (`parse_box`/`open_box`) + packaged JS CCID glue from the harness.
3. linenisgreat: `just` recipe to encrypt gated blobs via `piggy-ids`; serve `…/blob/formats/ebox`; loader template + PIN UX + DOM injection (CSP).
4. File this FDR into amarbel-llc/eng with its assigned number; cross-link FDR-0004.

## References

- `docs/rfcs/0002-piv-ecdh-box.md` — box wire format (normative crypto).
- `spikes/wasm-piv-decrypt/README.md` — runnable spike + harness.
- amarbel-llc/eng FDR-0004 — RCM piggy ebox decryption hook (prior art).
- linenisgreat `docs/decisions/0001` (app/api split); blob/formats mechanism.
- NIST SP 800-73-4 — PIV GENERAL AUTHENTICATE / slot semantics.
