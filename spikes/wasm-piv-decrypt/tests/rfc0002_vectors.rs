//! Replays the bit-exact RFC 0002 §A wire vectors (the same ones pinned
//! by `crates/piggy-box/src/piv_box.rs::tests::rfc0002_vectors`) through
//! the **pure-Rust, OpenSSL-free** decrypt path in this spike.
//!
//! Those vectors were sealed by OpenSSL. The decrypt here derives Z with
//! RustCrypto's `p256`/`p384` ECDH, then runs SHA-512 + ChaCha20-Poly1305
//! (RustCrypto) + PKCS#7 unpad. A successful **authenticated** decrypt is
//! therefore a byte-exact proof of two things at once:
//!   1. the symmetric half (KDF + AEAD + unpad) matches piggy-box, and
//!   2. RustCrypto's ECDH derives the *same* Z that OpenSSL did — which
//!      is the same X-coordinate a PIV card returns from GENERAL
//!      AUTHENTICATE. The Poly1305 tag is the cross-check.
//!
//! Run with `--nocapture` to print the derived Z (the value the WebUSB
//! harness must reproduce from real hardware).

use wasm_piv_decrypt_spike::{open_box, parse_box, simulate_card_ecdh, Curve};

struct Vector {
    name: &'static str,
    curve: Curve,
    recipient_scalar: Vec<u8>,
    plaintext: &'static [u8],
    wire_hex: &'static str,
}

const A1_WIRE: &str = "b0c5020000002363686163686132302d706f6c79313330354070696767792e616d617262656c2e6e65740673686135313210a0a1a2a3a4a5a6a7a8a9aaabacadaeaf086e697374703235362102515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f21031f140146bfb1b251f84f4ddbe0d4cdcfd77afd984a9520e35794021f8312bb9e0cd0d1d2d3d4d5d6d7d8d9dadb000000208dd88e114913dc759f69c7590b369008a754ee2d0528e4386c46661631e7fbfd";

const A2_WIRE: &str = "b0c5020110000102030405060708090a0b0c0d0e0f9d2363686163686132302d706f6c79313330354070696767792e616d617262656c2e6e65740673686135313210b0b1b2b3b4b5b6b7b8b9babbbcbdbebf086e6973747032353621038e71ca9d7a62917be7f0db9896b47bf9b91c8b86628eed55d47fe750e65e5bcb21038ed57ec2b8f5e75e9192327b51e5661c87c8e5db0170721309a517fc6e1046b10ce0e1e2e3e4e5e6e7e8e9eaeb00000020f0a8350c88929a3f68dd0d5a74b5d339c5d3624f6b5be4a3b7aa86eac9e0e0db";

const A3_WIRE: &str = "b0c5020000002363686163686132302d706f6c79313330354070696767792e616d617262656c2e6e65740673686135313210c0c1c2c3c4c5c6c7c8c9cacbcccdcecf086e697374703338343103c76f2283dda95cd49b0ed9e733d2904474e37216f124e13d2c9ab4cf01021c49ad9cabb3d0b97499aef2f0ab313fa0283103db89855d1980b2aacdec0752249bea9e0630c16b69c095f6c752b2547b520d8109511d908881491780594f03cfee8a0a0cf0f1f2f3f4f5f6f7f8f9fafb0000003001ed7daba77156dd87a22208274ce93706f3261619acf1f52c8c3d12e71380f30fe5091f18b17ccdfbcefe2a15d0d6df";

fn vectors() -> Vec<Vector> {
    vec![
        Vector {
            name: "A.1 P-256 no-guid empty",
            curve: Curve::NistP256,
            recipient_scalar: (1u8..=32).collect(),
            plaintext: b"",
            wire_hex: A1_WIRE,
        },
        Vector {
            name: "A.2 P-256 guid+slot \"hello\"",
            curve: Curve::NistP256,
            recipient_scalar: (0x10u8..=0x2F).collect(),
            plaintext: b"hello",
            wire_hex: A2_WIRE,
        },
        Vector {
            name: "A.3 P-384 no-guid 24-byte",
            curve: Curve::NistP384,
            recipient_scalar: (0x01u8..=0x30).collect(),
            plaintext: b"piggy rfc0002 vector A.3",
            wire_hex: A3_WIRE,
        },
    ]
}

#[test]
fn pure_rust_decrypt_reproduces_rfc0002_vectors() {
    for v in vectors() {
        let wire = hex::decode(v.wire_hex).expect("vector hex parses");

        // Step 1: parse — no key material needed.
        let parsed = parse_box(&wire).unwrap_or_else(|e| panic!("{}: parse failed: {e}", v.name));
        assert_eq!(parsed.curve, v.curve, "{}: curve", v.name);

        // Step 2: simulate the card's ECDH (in prod: WebUSB GENERAL AUTHENTICATE).
        let z = simulate_card_ecdh(
            v.curve,
            &v.recipient_scalar,
            &parsed.ephemeral_pubkey_uncompressed,
        )
        .unwrap_or_else(|e| panic!("{}: ecdh failed: {e}", v.name));
        assert_eq!(
            z.len(),
            v.curve.field_len(),
            "{}: Z must be field-size",
            v.name
        );

        // Step 3: the OpenSSL-free symmetric decrypt. Authenticated
        // success here IS the cross-impl proof.
        let pt = open_box(&parsed, &z)
            .unwrap_or_else(|e| panic!("{}: open_box failed (AEAD): {e}", v.name));
        assert_eq!(pt, v.plaintext, "{}: plaintext mismatch", v.name);

        println!(
            "[{}] OK\n    Z (card must return this) = {}\n    ephemeral_pub (feed to card) = {}",
            v.name,
            hex::encode(&z),
            hex::encode(&parsed.ephemeral_pubkey_uncompressed),
        );
    }
}

#[test]
fn wrong_scalar_fails_authentication() {
    // A different private scalar yields a different Z, so the Poly1305
    // tag MUST reject — exactly what happens with the wrong card.
    let wire = hex::decode(A1_WIRE).unwrap();
    let parsed = parse_box(&wire).unwrap();
    let wrong_scalar: Vec<u8> = (2u8..=33).collect();
    let z =
        simulate_card_ecdh(Curve::NistP256, &wrong_scalar, &parsed.ephemeral_pubkey_uncompressed)
            .unwrap();
    assert!(
        open_box(&parsed, &z).is_err(),
        "decrypt with wrong key must fail AEAD authentication"
    );
}

#[test]
fn tampered_ciphertext_fails_authentication() {
    let wire = hex::decode(A2_WIRE).unwrap();
    let mut parsed = parse_box(&wire).unwrap();
    *parsed.ciphertext_and_tag.last_mut().unwrap() ^= 0x01; // flip a tag bit
    let z =
        simulate_card_ecdh(Curve::NistP256, &(0x10u8..=0x2F).collect::<Vec<_>>(), &parsed.ephemeral_pubkey_uncompressed)
            .unwrap();
    assert!(
        open_box(&parsed, &z).is_err(),
        "tampered ciphertext must fail AEAD authentication"
    );
}
