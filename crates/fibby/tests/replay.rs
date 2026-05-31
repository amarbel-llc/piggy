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
const YK4_TEST_VECTOR_FIXTURE: &str = "tests/fixtures/apdu/yk4-test-vector-roundtrip.fixture";
const YK4_TEST_VECTOR_PIVY_FIXTURE: &str =
    "tests/fixtures/apdu/yk4-test-vector-roundtrip-pivy.fixture";

/// RFC 6979 §A.2.5 P-256 private scalar (big-endian, 32 bytes).
/// Imported into the throwaway YubiKey 4 slot 9D for the two test-
/// vector captures so VirtualCard's ECDH replay is byte-deterministic.
/// See piggy#134 + `crates/fibby/tests/fixtures/test-vectors/README.md`.
const RFC6979_A_2_5_SCALAR: [u8; 32] = [
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
    0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
];

/// Returns the slot 9D scalar to pre-seed VirtualCard with before
/// replaying `fixture_path`, or `None` if the fixture isn't backed by
/// a known test-vector key. Fixtures derived from captures against
/// on-card-generated keys can't be byte-replayed (the scalar never
/// leaves silicon); they remain `None` here.
fn slot_9d_priv_for(fixture_path: &str) -> Option<[u8; 32]> {
    match fixture_path {
        YK4_TEST_VECTOR_FIXTURE | YK4_TEST_VECTOR_PIVY_FIXTURE => Some(RFC6979_A_2_5_SCALAR),
        _ => None,
    }
}

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
    // yk5-list captured 2026-05-31 from a real YubiKey 5 firmware
    // 5.2.7 (the primary card alongside the throwaway YK4). Pinned
    // to `Model::Yk5` with that firmware version and the canonical
    // real-card SELECT FCI both real YK families share.
    ("tests/fixtures/apdu/yk5-list.fixture", Model::Yk5),
    // fib pairs with `Model::Yk5` even though fib's PivApplet
    // advertises firmware 5.4.0 (not 5.2.7) and a 121-byte FCI
    // (not the canonical 19-byte). The mismatch costs ~3 matched
    // pairs per fib fixture; aligning would need a separate
    // `Model::FibPivApplet` variant, deferred.
    (FIB_YK54_FIXTURE, Model::Yk5),
    ("tests/fixtures/apdu/fib-yk54-list.fixture", Model::Yk5),
    ("tests/fixtures/apdu/fib-yk54-init.fixture", Model::Yk5),
    // Test-vector captures (piggy#134) — same RFC 6979 §A.2.5 scalar
    // imported via two independent bootstrap paths so the ECDH
    // determinism check holds across distinct ephemerals. See
    // `slot_9d_priv_for` for the seed-material lookup the diagnostic
    // and strict tests consult.
    (YK4_TEST_VECTOR_FIXTURE, Model::Yk4),
    (YK4_TEST_VECTOR_PIVY_FIXTURE, Model::Yk4),
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
        // Pre-seed VirtualCard's PIV data-object storage with anything
        // the fixture's successful GET DATA pairs show real silicon
        // returned. This models the fact that the captured card was
        // already in a populated state before the captured session
        // began — its CHUID/CCC/cert objects were established by
        // earlier writes we don't have on tape.
        //
        // Self-referential for matched-count purposes (the GET DATA
        // pair that supplied the seed will, of course, then match its
        // own value); the real test value is on the *retrieval*
        // mechanism, which is now exercised against every populated
        // tag in every captured session. If we ever regress the BER-TLV
        // wrap/parse plumbing, those matches drop and the diagnostic
        // headline catches it.
        let seeds = extract_data_object_seed(&pairs);
        for (tag, value) in seeds {
            card.seed_data_object(tag, value);
        }
        // For test-vector fixtures (piggy#134), pre-seed the slot 9D
        // private scalar matching the imported throwaway-card key. The
        // GA ECDH pair then becomes byte-deterministic and shows up in
        // matched-count; without this, the GA exchange falls through
        // VirtualCard's empty-slot branch.
        if let Some(scalar) = slot_9d_priv_for(fixture_path) {
            card.seed_slot_9d_priv(scalar);
        }
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
        // When the env var REPLAY_LOG_MISMATCHES is set, also print the
        // INS bytes + truncated request/response of every mismatched
        // pair. Lets the dev-loop point at the next slice to attack
        // without re-running a custom diagnostic.
        if std::env::var("REPLAY_LOG_MISMATCHES").is_ok() {
            let mut card = VirtualCard::with_model(model);
            card.connect(2, 3).unwrap();
            for (tag, value) in extract_data_object_seed(&pairs) {
                card.seed_data_object(tag, value);
            }
            if let Some(scalar) = slot_9d_priv_for(fixture_path) {
                card.seed_slot_9d_priv(scalar);
            }
            for (i, p) in pairs.iter().enumerate() {
                let got = card.transmit(&p.request).unwrap_or_default();
                if got != p.response {
                    let ins = p.request.get(1).copied().unwrap_or(0);
                    let p1 = p.request.get(2).copied().unwrap_or(0);
                    let p2 = p.request.get(3).copied().unwrap_or(0);
                    println!(
                        "  [{i}] INS={ins:#04x} P1={p1:#04x} P2={p2:#04x}\n    \
                         exp ({} B): {}\n    \
                         got ({} B): {}",
                        p.response.len(),
                        hex_preview(&p.response),
                        got.len(),
                        hex_preview(&got),
                    );
                }
            }
        }
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let cap = bytes.len().min(48);
    let mut s = String::with_capacity(cap * 2 + 8);
    for b in &bytes[..cap] {
        let _ = write!(&mut s, "{b:02x}");
    }
    if bytes.len() > cap {
        let _ = write!(&mut s, "...({} more)", bytes.len() - cap);
    }
    s
}

/// Walk a fixture's APDU pairs once and collect any data-object
/// pre-seed material — tuples of `(tag_bytes, payload_bytes)` from
/// successful GET DATA exchanges. A "successful" GET DATA is anything
/// ending in SW 9000 and not starting with `6A` (the SP 800-73-4 error
/// class for "not present" / "not found"). Both `53`-wrapped object
/// payloads (CHUID, CCC, cert objects, etc.) and the SP 800-73-4
/// §3.3.2 Discovery Object's `7E`-prefixed payload qualify.
fn extract_data_object_seed(pairs: &[Pair]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut seeds = Vec::new();
    for p in pairs {
        // GET DATA request: `00 CB 3F FF <Lc> ... 5C <tag_len> <tag> ...`
        if !(p.request.len() >= 4 && p.request[0] == 0x00 && p.request[1] == 0xCB) {
            continue;
        }
        let Some(tag) = extract_5c_tag_from_get_data_request(&p.request) else {
            continue;
        };
        // Need at least SW1 SW2 + 1 payload byte.
        if p.response.len() < 3 {
            continue;
        }
        let sw_start = p.response.len() - 2;
        if p.response[sw_start..] != [0x90, 0x00] {
            continue;
        }
        // 6A-prefixed payloads aren't really payloads — they're SP
        // 800-73-4 error/diagnostic responses that happened to land
        // inside a 9000-suffixed sequence (none of our fixtures
        // actually have this shape, but the guard makes the intent
        // explicit). Any other leading tag — `53` for object data,
        // `7E` for the Discovery Object — gets seeded verbatim.
        if p.response[0] == 0x6A {
            continue;
        }
        let payload = p.response[..sw_start].to_vec();
        seeds.push((tag.to_vec(), payload));
    }
    seeds
}

/// Find the `5C <tag_len> <tag>` BER-TLV in a GET DATA request and
/// return the `<tag>` slice. Handles both short-form Lc (`00 CB 3F FF
/// <Lc> 5C ...`) and extended-length (`00 CB 3F FF 00 <Lc_hi> <Lc_lo>
/// 5C ...`). Returns None for malformed shapes.
fn extract_5c_tag_from_get_data_request(apdu: &[u8]) -> Option<&[u8]> {
    if apdu.len() < 5 {
        return None;
    }
    // Body start depends on encoding.
    let body_start = if apdu[4] == 0x00 && apdu.len() >= 7 {
        7
    } else {
        5
    };
    let body = apdu.get(body_start..)?;
    if body.first()? != &0x5C {
        return None;
    }
    let tag_len = *body.get(1)? as usize;
    if tag_len == 0 || body.len() < 2 + tag_len {
        return None;
    }
    Some(&body[2..2 + tag_len])
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

/// Replay the GA ECDH (INS 0x87, P1=0x11, P2=0x9D) pair from a test-
/// vector fixture against a VirtualCard seeded with the matching slot
/// 9D scalar, and assert byte-equality of the response. Scopes
/// strictness to the deterministic surface — does not assert on every
/// pair in the fixture, just the GA ECDH pair(s). Closes piggy#134's
/// "byte-deterministic ECDH replay" loop.
fn assert_ga_ecdh_pairs_replay_byte_equal(fixture: &Path, scalar: [u8; 32]) {
    let pairs = parse_fixture(fixture);
    let mut ga_pairs_seen = 0;
    for (i, p) in pairs.iter().enumerate() {
        if !is_ga_ecdh_slot_9d(&p.request) {
            continue;
        }
        ga_pairs_seen += 1;
        let mut card = VirtualCard::new();
        card.seed_slot_9d_priv(scalar);
        // PIN-verify out-of-band via the standard PIV VERIFY (00 20 00
        // 80 + factory PIN 123456+padding) so VirtualCard's PIN-gate
        // doesn't return 6982. Mirrors what the captured session did
        // before reaching this pair.
        let verify_apdu = vec![
            0x00, 0x20, 0x00, 0x80, 0x08, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF,
        ];
        assert_eq!(
            card.transmit(&verify_apdu).unwrap(),
            vec![0x90, 0x00],
            "{}: priming VERIFY failed; PIN gate not satisfied",
            fixture.display()
        );
        let got = card.transmit(&p.request).unwrap();
        assert_eq!(
            got,
            p.response,
            "{}: GA ECDH pair {i} response mismatch.\n  request: {:?}\n  expected: {:?}\n  got: {:?}",
            fixture.display(),
            p.request,
            p.response,
            got
        );
    }
    assert!(
        ga_pairs_seen >= 1,
        "{}: expected at least one GA ECDH pair (INS 0x87 P1=0x11 P2=0x9D) in fixture",
        fixture.display()
    );
}

fn is_ga_ecdh_slot_9d(apdu: &[u8]) -> bool {
    apdu.len() >= 4 && apdu[0] == 0x00 && apdu[1] == 0x87 && apdu[2] == 0x11 && apdu[3] == 0x9D
}

/// GA ECDH byte-replay against `yk4-test-vector-roundtrip.fixture`
/// (yubico-piv-tool import bootstrap). Pair {request, response} is
/// deterministic given the slot scalar; VirtualCard's ECDH must
/// reproduce the captured response exactly.
#[test]
fn ga_ecdh_byte_replay_test_vector_yubico_piv_tool_bootstrap() {
    assert_ga_ecdh_pairs_replay_byte_equal(
        &workspace_relative(YK4_TEST_VECTOR_FIXTURE),
        RFC6979_A_2_5_SCALAR,
    );
}

/// Strict whole-fixture byte-replay against the test-vector capture
/// (yubico-piv-tool import bootstrap). Every pair — SELECT PIV, GET
/// DATA for CHUID/CCC/Discovery/cert, VERIFY PIN, YK ATTEST refusal,
/// GA ECDH — must reproduce byte-for-byte against VirtualCard seeded
/// with the data-object pre-state and the RFC 6979 §A.2.5 scalar.
///
/// This is the closing gate piggy#131 envisioned: not aspirational
/// (un-ignored), not scoped to one INS (whole flow). The companion
/// `full_byte_replay_against_yk4_fixture` stays ignored because its
/// on-card-generated key + factory-signed attestation cert are
/// non-deterministic; the test-vector capture exists precisely to
/// remove those non-determinisms.
#[test]
fn full_byte_replay_against_yk4_test_vector_fixture() {
    full_byte_replay_with_seeding(
        &workspace_relative(YK4_TEST_VECTOR_FIXTURE),
        Model::Yk4,
        Some(RFC6979_A_2_5_SCALAR),
    );
}

/// Companion to `full_byte_replay_against_yk4_test_vector_fixture`:
/// strict whole-fixture replay against the pivy-tool-bootstrap
/// capture (#58). Two distinct bootstrap paths against the same
/// scalar → two distinct deterministic fixtures, both passing.
#[test]
fn full_byte_replay_against_yk4_test_vector_pivy_fixture() {
    full_byte_replay_with_seeding(
        &workspace_relative(YK4_TEST_VECTOR_PIVY_FIXTURE),
        Model::Yk4,
        Some(RFC6979_A_2_5_SCALAR),
    );
}

fn full_byte_replay_with_seeding(fixture: &Path, model: Model, scalar: Option<[u8; 32]>) {
    let pairs = parse_fixture(fixture);
    let mut card = VirtualCard::with_model(model);
    card.connect(2, 3).unwrap();
    for (tag, value) in extract_data_object_seed(&pairs) {
        card.seed_data_object(tag, value);
    }
    if let Some(s) = scalar {
        card.seed_slot_9d_priv(s);
    }
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

/// Companion to the yubico-piv-tool-bootstrap byte-replay: the pivy-
/// tool bootstrap (#58) used a fresh ephemeral, so the X-coord response
/// differs — but the scalar is the same, so VirtualCard's math has to
/// reproduce *this* response byte-equally too. Two distinct fixtures
/// → strong cross-check that the ECDH implementation isn't accidentally
/// fitting one frozen pair.
#[test]
fn ga_ecdh_byte_replay_test_vector_pivy_tool_bootstrap() {
    assert_ga_ecdh_pairs_replay_byte_equal(
        &workspace_relative(YK4_TEST_VECTOR_PIVY_FIXTURE),
        RFC6979_A_2_5_SCALAR,
    );
}
