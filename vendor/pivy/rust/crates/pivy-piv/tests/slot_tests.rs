use pivy_piv::PivContext;

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
