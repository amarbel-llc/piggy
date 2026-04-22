use pivy_piv::PivContext;

#[test]
fn enumerate_readers() {
    let ctx = match PivContext::new() {
        Ok(ctx) => ctx,
        Err(_) => {
            eprintln!("PCSC not available, skipping");
            return;
        }
    };
    let readers = ctx.list_readers().unwrap_or_default();
    // Just verify it doesn't crash -- may be empty in CI
    println!("Found {} readers", readers.len());
}
