use piggy_piv::PivContext;

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
    let mut token = match tokens.into_iter().next() {
        Some(t) => t,
        None => {
            eprintln!("No PIV tokens found, skipping");
            return;
        }
    };
    // Try slot 9E which typically doesn't need PIN
    match token.read_slot(0x9E) {
        Ok(_) => {
            // Slot exists, try to sign (may still fail without card). 9E needs
            // no PIN, but signing is reachable only via a PinSession
            // transaction now (piggy#56), so open one first.
            let data = b"test data to sign";
            let mut session = match token.begin_pin_session() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "begin_pin_session failed (expected without real card): {}",
                        e
                    );
                    return;
                }
            };
            match session.sign_prehash(0x9E, data) {
                Ok(sig) => assert!(!sig.is_empty()),
                Err(e) => eprintln!("Sign failed (expected without real card): {}", e),
            }
        }
        Err(_) => eprintln!("Slot 9E empty, skipping"),
    }
}
