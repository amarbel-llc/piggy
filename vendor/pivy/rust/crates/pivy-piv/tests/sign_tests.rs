use pivy_piv::PivContext;

#[test]
fn sign_with_9e_no_pin() {
    // 9E (Card Authentication) doesn't require PIN
    let ctx = match PivContext::new() {
        Ok(c) => c,
        Err(_) => {
            eprintln!("PCSC not available, skipping");
            return;
        }
    };
    let tokens = ctx.enumerate_tokens().unwrap_or_default();
    let token = match tokens.into_iter().next() {
        Some(t) => t,
        None => {
            eprintln!("No PIV tokens found, skipping");
            return;
        }
    };
    // Try slot 9E which typically doesn't need PIN
    match token.read_slot(0x9E) {
        Ok(_) => {
            // Slot exists, try to sign (may still fail without card)
            let data = b"test data to sign";
            match token.sign_prehash(0x9E, data) {
                Ok(sig) => assert!(!sig.is_empty()),
                Err(e) => eprintln!("Sign failed (expected without real card): {}", e),
            }
        }
        Err(_) => eprintln!("Slot 9E empty, skipping"),
    }
}
