# Spike: WASM PIV-gated decrypt for linenisgreat (piggy-wasm-webauthn-access)

Goal: a browser WASM module that decrypts piggy `.ebox` blobs **gated by a
PIV card**, so linenisgreat can serve encrypted blob data publicly and only
authorized YubiKey holders can read it. The app stays plaintext; only the
*blob* is ciphertext. The card reaches the browser via **WebUSB → PIV
applet** (the transport chosen for this spike).

This directory de-risks the two unknowns before any real implementation.

## Architecture (the `EcdhOracle` seam, moved to the JS↔WASM boundary)

```
BUILD   page blob ──piggy-ids encrypt──▶ blob.ebox   (recipients = authorized PIV pubkeys)
SERVE   blob.ebox served publicly via API blob/formats (opaque ciphertext)
BROWSER 1. WASM  parse_box(ebox)         → ephemeral pubkey + nonce + iv   (no key needed)
        2. JS    WebUSB → PIV slot 9D    → GENERAL AUTHENTICATE (ECDH) → Z   (PIN-gated)
        3. WASM  open_box(ebox, Z)       → SHA-512(Z‖nonce) → ChaCha20-Poly1305 → plaintext
```

Decryption needs ECDH against slot-9D's private key, which never leaves the
card. The WASM module does the OpenSSL-free symmetric half; JS supplies `Z`.

## Half 1 — crypto path (✅ proven in this environment, native + wasm32)

Pure Rust, zero `openssl`/`pcsc`: `sha2` + `chacha20poly1305` + `p256`/`p384`
(point decompress + the test-only "card simulator" ECDH). See `src/lib.rs`.

```sh
cargo test                                   # replays RFC 0002 §A.1/A.2/A.3
cargo test -- --nocapture                    # also prints each vector's Z
cargo build --lib --release --target wasm32-unknown-unknown   # emits a real .wasm
```

The RFC 0002 vectors were **sealed by OpenSSL**. Deriving `Z` with RustCrypto
and getting a **passing Poly1305 tag** is a byte-exact proof that RustCrypto's
ECDH == OpenSSL's `Deriver` == the card's `GENERAL AUTHENTICATE` X-coordinate,
*and* that the KDF+AEAD+unpad match piggy-box. Wrong-key and tampered-tag
cases correctly fail authentication.

This is exactly the swap a future `piggy-box` `backend-rustcrypto` cargo
feature would make (`openssl` → these crates) so `piggy-wasm` can build.

## Half 2 — WebUSB → PIV ECDH (⚠ run on your hardware)

`webusb-piv-ecdh-harness.html` — open in Chrome/Edge over `localhost` or
`https`. It drives CCID-over-WebUSB: PowerOn → SELECT PIV → VERIFY PIN →
GENERAL AUTHENTICATE (ECDH, slot 9D) → prints `Z`.

End-to-end hardware check:

```sh
# 1. encrypt something to YOUR card, then inspect the box:
cargo run --example open -- --box <your-ebox-hex>
#    → copy the printed `ephemeral_pubkey` (uncompressed) + curve into the harness

# 2. run the harness → it prints Z

# 3. finish the decrypt with the same wasm-capable code:
cargo run --example open -- --box <your-ebox-hex> --z <Z-from-harness>
#    → your plaintext
```

If `Z` from real hardware drives a successful `open_box`, the whole
PIV-gated-WASM architecture is validated.

### Known frictions to confirm during the hardware run
- **WebUSB is Chromium-only** (no Firefox/Safari).
- **OS PC/SC contention**: pcscd / Windows Smart Card service may hold the CCID
  interface; `claimInterface` then fails "busy". Stop pcscd or unbind first.
  (If this is a dealbreaker, the "local agent bridge" oracle is the fallback —
  same WASM half, different `Z` source.)
- **Slot 9D PIN/touch policy**: harness does VERIFY PIN; a touch policy would
  need a tap. Extended-length APDUs are handled via 61xx GET RESPONSE.

## If both halves pass — next steps (not in this spike)
1. `piggy-box`: `backend-rustcrypto` feature (openssl → sha2/chacha20poly1305/p256/p384).
2. `crates/piggy-wasm`: `wasm-bindgen` surface (`parse_box`/`open_box`) + JS CCID glue packaged.
3. linenisgreat: `just` recipe to encrypt gated blobs via `piggy-ids`; serve as a new
   API `…/blob/formats/ebox`; loader template + PIN UX + DOM injection (mind CSP).
```
