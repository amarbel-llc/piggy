//! Closes the spike loop using the *same* wasm-capable code path.
//!
//! Two modes:
//!   * `--box <hex>`            inspect a box: print curve, GUID/slot, and
//!                              the uncompressed ephemeral pubkey you feed
//!                              to the card's GENERAL AUTHENTICATE.
//!   * `--box <hex> --z <hex>`  finish the decrypt with the card-returned
//!                              shared secret Z and print the plaintext.
//!
//! In the full flow the browser runs WebUSB→PIV to produce `Z`
//! (webusb-piv-ecdh-harness.html); this binary stands in for the wasm
//! module's `open_box` so the hardware half can be validated end-to-end
//! without a wasm-bindgen toolchain.

use wasm_piv_decrypt_spike::{open_box, parse_box};

fn arg(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let box_hex = match arg("--box") {
        Some(h) => h,
        None => {
            eprintln!("usage: open --box <hex> [--z <hex>]");
            std::process::exit(2);
        }
    };
    let wire = hex::decode(box_hex.trim()).expect("--box must be hex");
    let parsed = parse_box(&wire).expect("parse box");

    match arg("--z") {
        None => {
            println!("curve            : {:?}", parsed.curve);
            println!("guid             : {:?}", parsed.guid.map(hex::encode));
            println!("slot             : {:?}", parsed.slot.map(|s| format!("{s:#04x}")));
            println!("kdf_nonce        : {}", hex::encode(&parsed.kdf_nonce));
            println!("iv               : {}", hex::encode(&parsed.iv));
            println!("ephemeral_pubkey : {}", hex::encode(&parsed.ephemeral_pubkey_uncompressed));
            println!("  ^ feed this uncompressed point to the card (GENERAL AUTHENTICATE),");
            println!("    then re-run with --z <returned-shared-secret-hex>");
        }
        Some(z_hex) => {
            let z = hex::decode(z_hex.trim()).expect("--z must be hex");
            match open_box(&parsed, &z) {
                Ok(pt) => {
                    eprintln!("[decrypted {} bytes]", pt.len());
                    use std::io::Write;
                    std::io::stdout().write_all(&pt).unwrap();
                }
                Err(e) => {
                    eprintln!("decrypt failed: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
