//! pigtrough(1) states limits that are constants in the code. Each value is
//! written once in the page, in a sentence this test builds from the
//! constant, so neither can change alone.

use pigtrough::budget::{BODY_READ_TIMEOUT, TOTAL_BUFFERED_BODIES};
use pigtrough::route::Limits;
use pigtrough::server::MAX_IN_FLIGHT;
use pigtrough::tls::CONNECT_TIMEOUT;

#[test]
fn the_pages_numbers_are_the_codes() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../doc/pigtrough.1.scd");
    let page = std::fs::read_to_string(path).unwrap();
    let page = page.split_whitespace().collect::<Vec<_>>().join(" ");

    let body = Limits::DEFAULT.max_request_body;
    let most = Limits::MAX_REQUEST_BODY_CEILING;
    for sentence in [
        format!(
            "Default {body} ({} MiB); 1 to {most} ({} MiB).",
            body >> 20,
            most >> 20
        ),
        format!(
            "Default {}; 1 to {}.",
            Limits::DEFAULT.response_head_timeout.as_secs(),
            Limits::HEAD_TIMEOUT_CEILING.as_secs()
        ),
        format!(
            "It does not lengthen the {} s allowed for connecting",
            CONNECT_TIMEOUT.as_secs()
        ),
        format!(
            "Default {TOTAL_BUFFERED_BODIES} ({} MiB).",
            TOTAL_BUFFERED_BODIES >> 20
        ),
        format!("Default {}.", BODY_READ_TIMEOUT.as_secs()),
        format!("At most {MAX_IN_FLIGHT} threads run requests"),
    ] {
        assert!(page.contains(&sentence), "the page lacks: {sentence}");
    }
}
