use pivy_piv::PivContext;

#[test]
fn connect_and_select() {
    let ctx = match PivContext::new() {
        Ok(ctx) => ctx,
        Err(_) => {
            eprintln!("PCSC not available, skipping");
            return;
        }
    };
    let tokens = ctx.enumerate_tokens().unwrap_or_default();
    for token in &tokens {
        println!(
            "Found PIV token: GUID={} reader={}",
            token.guid().to_hex(),
            token.reader_name()
        );
    }
}
