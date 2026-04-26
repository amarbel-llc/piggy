use piggy_piv::slot::PivAlgorithm;
use piggy_piv::PivContext;

#[test]
fn algorithm_to_byte_matches_apdu_constants() {
    // Mirrors crates/piggy-piv/tests/apdu_tests.rs::alg_constants_match_authoritative_sources.
    // The slot-level enum and the APDU-level constants must agree; #44 was exactly the
    // case where they drifted apart unnoticed because no test pinned either side.
    assert_eq!(
        PivAlgorithm::Rsa1024.to_byte(),
        piggy_piv::apdu::alg::RSA1024
    );
    assert_eq!(
        PivAlgorithm::Rsa2048.to_byte(),
        piggy_piv::apdu::alg::RSA2048
    );
    assert_eq!(
        PivAlgorithm::EcP256.to_byte(),
        piggy_piv::apdu::alg::ECCP256
    );
    assert_eq!(
        PivAlgorithm::EcP384.to_byte(),
        piggy_piv::apdu::alg::ECCP384
    );
    assert_eq!(
        PivAlgorithm::Ed25519.to_byte(),
        piggy_piv::apdu::alg::ED25519
    );
}

#[test]
fn read_slots_from_token() {
    let ctx = match PivContext::new() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("PCSC not available, skipping");
            return;
        }
    };
    let tokens = ctx.enumerate_tokens().unwrap_or_default();
    for token in &tokens {
        let slots = token.read_all_slots().unwrap_or_default();
        for slot in &slots {
            println!(
                "Slot {:#04x}: algo={:?}, pubkey={}",
                slot.id(),
                slot.algorithm(),
                slot.ssh_public_key_string()
            );
        }
    }
}
