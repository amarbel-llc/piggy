//! Replay APDU fixtures against `VirtualCard`. This is the implementation-
//! progress test bed for the design doc's step 5 work — as `VirtualCard`
//! grows past its current SELECT-only stub, more of the ignored
//! byte-equal assertions below should be un-ignored.
//!
//! The fixtures live at `tests/fixtures/apdu/*.fixture` and are derived
//! from the captures under `tests/fixtures/captures/{yubikey,fib}/` via
//! `cargo run --bin wire-to-apdu-fixtures -- <capture.log>`.
//!
//! Adversarial framing: until `VirtualCard` actually implements PIV,
//! these fixtures encode what it *must eventually do*. The strict
//! `full_byte_replay_*` tests are `#[ignore]`'d on purpose — that's
//! how the implementation milestone is captured (un-ignore the test
//! when the relevant code path lands).

use std::fs;
use std::path::{Path, PathBuf};

use fibby::backend::Backend;
use fibby::virtual_card::{Model, VirtualCard};

const YK4_FIXTURE: &str = "tests/fixtures/apdu/yk4-roundtrip.fixture";
const FIB_YK54_FIXTURE: &str = "tests/fixtures/apdu/fib-yk54-roundtrip.fixture";

/// Fixture-to-model mapping. Each fixture is replayed against the
/// `Model` whose ATR + firmware version matches what the originating
/// card actually advertised on the wire:
///
/// - `yk4-*` fixtures captured against the real YubiKey 4 (fw 4.3.5)
///   pair with [`Model::Yk4`].
/// - `fib-yk54-*` fixtures pair with [`Model::Yk5`] because fib's
///   PivApplet advertises as "YubicoPIV v5.4.0" (same firmware tuple
///   `Model::Yk5` returns from `firmware_version()`).
///
/// Without this per-fixture pairing, fib fixtures would always
/// replay against the default `Yk4` profile and miss matched-count
/// improvements on every per-model dispatch (GET VERSION, ATR-derived
/// behavior, etc.). Three flows (`roundtrip`, `list`, `init`) × two
/// sources = six fixtures total.
const ALL_FIXTURES: &[(&str, Model)] = &[
    (YK4_FIXTURE, Model::Yk4),
    ("tests/fixtures/apdu/yk4-list.fixture", Model::Yk4),
    ("tests/fixtures/apdu/yk4-init.fixture", Model::Yk4),
    (FIB_YK54_FIXTURE, Model::Yk5),
    ("tests/fixtures/apdu/fib-yk54-list.fixture", Model::Yk5),
    ("tests/fixtures/apdu/fib-yk54-init.fixture", Model::Yk5),
];

/// One APDU exchange parsed from a `.fixture` file: the command APDU
/// the client sent, and the response APDU the card returned.
#[derive(Debug, Clone)]
struct Pair {
    request: Vec<u8>,
    response: Vec<u8>,
}

fn workspace_relative(p: &str) -> PathBuf {
    // cargo runs tests with CWD == the crate root, so the fixture
    // paths above resolve directly.
    Path::new(env!("CARGO_MANIFEST_DIR")).join(p)
}

/// Parse the line-based fixture format documented in
/// `src/bin/wire-to-apdu-fixtures.rs`. Strict on shape: each non-comment
/// non-blank block is exactly one `> <hex>` line followed by one `< <hex>`
/// line. Hex parsing is lenient (whitespace within hex is tolerated for
/// editor-friendly fixtures).
fn parse_fixture(path: &Path) -> Vec<Pair> {
    let raw =
        fs::read_to_string(path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    let mut pairs = Vec::new();
    let mut req: Option<Vec<u8>> = None;
    for (lineno, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("> ") {
            assert!(
                req.is_none(),
                "fixture {} line {}: two `>` lines in a row",
                path.display(),
                lineno + 1
            );
            req = Some(parse_hex(rest, path, lineno + 1));
        } else if let Some(rest) = line.strip_prefix("< ") {
            let request = req.take().unwrap_or_else(|| {
                panic!(
                    "fixture {} line {}: `<` line without preceding `>`",
                    path.display(),
                    lineno + 1
                )
            });
            let response = parse_hex(rest, path, lineno + 1);
            pairs.push(Pair { request, response });
        } else {
            panic!(
                "fixture {} line {}: unrecognized line {line:?}",
                path.display(),
                lineno + 1
            );
        }
    }
    assert!(
        req.is_none(),
        "fixture {} ends with a dangling `>` request",
        path.display()
    );
    pairs
}

fn parse_hex(s: &str, path: &Path, lineno: usize) -> Vec<u8> {
    let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(
        stripped.len().is_multiple_of(2),
        "fixture {} line {}: odd hex length",
        path.display(),
        lineno
    );
    (0..stripped.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&stripped[i..i + 2], 16).unwrap_or_else(|e| {
                panic!(
                    "fixture {} line {}: bad hex {:?}: {e}",
                    path.display(),
                    lineno,
                    &stripped[i..i + 2]
                )
            })
        })
        .collect()
}

/// SELECT (CLA=00 INS=A4 P1=04 P2=00) of the PIV AID (whole or by
/// prefix). The wet-env captures show pivy-tool issuing both the
/// extended-length form and the regular form during discovery; both
/// are SELECTs.
fn is_select_piv(apdu: &[u8]) -> bool {
    if apdu.len() < 5 {
        return false;
    }
    if !(apdu[0] == 0x00 && apdu[1] == 0xa4 && apdu[2] == 0x04 && apdu[3] == 0x00) {
        return false;
    }
    // ISO 7816-4 short-form: byte[4] = Lc (1 byte, 1..=255), AID follows.
    // Extended-length: byte[4] = 0x00 (extended-form marker), byte[5..7]
    // = Lc (2 bytes BE), AID follows. YK4's pivy-tool uses extended-form
    // in the wet-env capture; fib accepts both.
    let body = &apdu[4..];
    let aid: &[u8] = if body[0] == 0x00 && body.len() >= 3 {
        let lc = u16::from_be_bytes([body[1], body[2]]) as usize;
        body.get(3..3 + lc).unwrap_or(&[])
    } else {
        let lc = body[0] as usize;
        body.get(1..1 + lc).unwrap_or(&[])
    };
    aid.starts_with(&[0xa0, 0x00, 0x00, 0x03, 0x08])
}

// ============================================================================
// Tests that pass today.
// ============================================================================

/// Sanity: every fixture exists, parses, and contains a useful number
/// of APDU pairs. A regression in either the extractor or any capture
/// pipeline shows up here first. The pair-count floor (5) is set
/// permissively so it accepts the smallest flow (list = ~12 pairs)
/// with margin; the roundtrip fixtures comfortably exceed 30.
#[test]
fn fixtures_parse_with_nontrivial_pair_counts() {
    for &(fixture_path, _model) in ALL_FIXTURES {
        let pairs = parse_fixture(&workspace_relative(fixture_path));
        assert!(
            pairs.len() >= 5,
            "{fixture_path}: expected ≥5 APDU pairs, got {}",
            pairs.len()
        );
        // Every pair should at minimum carry an SW1 SW2 (2 bytes).
        for (i, p) in pairs.iter().enumerate() {
            assert!(
                p.response.len() >= 2,
                "{fixture_path} pair {i}: response too short ({} bytes)",
                p.response.len()
            );
        }
    }
}

/// Every fixture must contain at least one SELECT PIV APDU pair, and
/// the recorded response must be a successful application-property
/// template (starts with FCI tag 0x61, ends with SW 9000). Documents
/// the canonical SELECT shape `VirtualCard` is reproducing today.
/// SELECT is the opening move of every PIV session — list, init,
/// and roundtrip alike — so this holds across all six fixtures.
#[test]
fn fixtures_contain_select_piv_with_fci_response() {
    for &(fixture_path, _model) in ALL_FIXTURES {
        let pairs = parse_fixture(&workspace_relative(fixture_path));
        let selects: Vec<&Pair> = pairs.iter().filter(|p| is_select_piv(&p.request)).collect();
        assert!(
            !selects.is_empty(),
            "{fixture_path}: expected at least one SELECT PIV pair"
        );
        let succeeded = selects
            .iter()
            .filter(|p| {
                p.response.len() >= 3
                    && p.response[0] == 0x61
                    && p.response[p.response.len() - 2..] == [0x90, 0x00]
            })
            .count();
        assert!(
            succeeded >= 1,
            "{fixture_path}: expected at least one SELECT PIV → 0x61...9000, found 0 of {}",
            selects.len()
        );
    }
}

/// `VirtualCard`'s SELECT PIV response today is a stub FCI — different
/// bytes from real silicon (and from fib's PivApplet), but identical
/// *shape*: leading FCI tag 0x61, trailing SW 0x9000. This asserts
/// the shape match, *not* byte equality. When step-5 work produces a
/// byte-faithful FCI, the `full_byte_replay_*` tests below take over
/// for byte-equality and this can be deleted (or kept as a smoke).
#[test]
fn virtual_card_select_piv_returns_fci_shaped_response() {
    let select_apdu: Vec<u8> = {
        let aid = fibby::apdu::PIV_AID;
        let mut a = vec![0x00, 0xa4, 0x04, 0x00, aid.len() as u8];
        a.extend_from_slice(aid);
        a
    };
    let mut card = VirtualCard::new();
    card.connect(2, 3).unwrap();
    let resp = card.transmit(&select_apdu).unwrap();
    assert!(resp.len() >= 3, "VirtualCard SELECT PIV resp too short");
    assert_eq!(
        resp[0], 0x61,
        "VirtualCard SELECT PIV: expected FCI tag 0x61"
    );
    assert_eq!(
        &resp[resp.len() - 2..],
        &[0x90, 0x00],
        "VirtualCard SELECT PIV: expected SW 9000"
    );
}

/// Diagnostic: replay every fixture pair through `VirtualCard` and
/// count how many match byte-for-byte today. Doesn't assert (so it
/// never fails CI), just prints the progress headline. Once the
/// matching count climbs into the high-N range across both fixtures,
/// the `#[ignore]`'d strict tests below become a viable next gate.
#[test]
fn replay_progress_against_real_silicon_is_logged() {
    for &(fixture_path, model) in ALL_FIXTURES {
        let pairs = parse_fixture(&workspace_relative(fixture_path));
        let mut card = VirtualCard::with_model(model);
        card.connect(2, 3).unwrap();
        let mut matched = 0usize;
        let mut select_matched = 0usize;
        let mut selects = 0usize;
        for p in &pairs {
            if is_select_piv(&p.request) {
                selects += 1;
            }
            let got = card.transmit(&p.request).unwrap_or_else(|rv| {
                panic!("VirtualCard transmit errored {rv:#010x} on {:?}", p.request)
            });
            if got == p.response {
                matched += 1;
                if is_select_piv(&p.request) {
                    select_matched += 1;
                }
            }
        }
        // Printed on `cargo test -- --nocapture`; otherwise hidden but
        // the test still runs and exercises VirtualCard against every
        // recorded APDU.
        println!(
            "[replay {fixture_path}] total={} matched={} \
             selects={} select_matched={}",
            pairs.len(),
            matched,
            selects,
            select_matched
        );
    }
}

// ============================================================================
// Implementation-progress test bed.
// ============================================================================
//
// These will fail wholesale today. Each one un-ignores when the
// relevant `VirtualCard` capability lands. The un-ignore commit IS
// the implementation milestone — that's the whole point of #131's
// "becomes the implementation-progress test bed" framing.

/// Strict byte-equal replay against the YK4 capture. Will pass when
/// `VirtualCard` reproduces the YubiKey 4 firmware 4.3.5 responses for
/// every recorded APDU in the round-trip (SELECT PIV, SELECT YK mgmt
/// AID, GET DATA for CHUID/CCC/etc., GENERAL AUTHENTICATE ECDH on slot
/// 9D, plus VERIFY PIN and GET RESPONSE chaining). See #128 for the
/// `--model` profile that this fixture pins to.
#[test]
#[ignore = "VirtualCard PIV applet in progress; see #131 + design-doc step 5"]
fn full_byte_replay_against_yk4_fixture() {
    full_byte_replay(&workspace_relative(YK4_FIXTURE), Model::Yk4);
}

/// Strict byte-equal replay against the fib (PivApplet, advertising as
/// YK 5.4.0) capture. The fib path differs from real silicon in known
/// ways (no Yubico factory-root attestation, different CHUID timing);
/// when this passes byte-equally, `VirtualCard` has reached parity
/// with PivApplet — the precondition for retiring `fib` from the bats
/// lane (design-doc step 6).
#[test]
#[ignore = "VirtualCard PIV applet in progress; see #131 + design-doc step 5"]
fn full_byte_replay_against_fib_yk54_fixture() {
    full_byte_replay(&workspace_relative(FIB_YK54_FIXTURE), Model::Yk5);
}

fn full_byte_replay(fixture: &Path, model: Model) {
    let pairs = parse_fixture(fixture);
    let mut card = VirtualCard::with_model(model);
    card.connect(2, 3).unwrap();
    for (i, p) in pairs.iter().enumerate() {
        let got = card.transmit(&p.request).unwrap_or_else(|rv| {
            panic!(
                "{}: VirtualCard transmit errored {rv:#010x} on pair {i}: {:?}",
                fixture.display(),
                p.request
            )
        });
        assert_eq!(
            got,
            p.response,
            "{}: pair {i}: VirtualCard response mismatch.\n  request: {:?}\n  expected: {:?}\n  got: {:?}",
            fixture.display(),
            p.request,
            p.response,
            got
        );
    }
}
