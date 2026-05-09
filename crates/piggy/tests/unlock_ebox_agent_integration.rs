//! End-to-end integration test for the full `unlock_ebox` flow against a
//! live piggy-agent.
//!
//! Checkpoint 3A of issue #32. Checkpoint 2 proved the agent's
//! `ecdh@joyent.com` extension agrees with a locally-computed scalar;
//! this test pushes one layer higher and proves that seal → serialize
//! → deserialize → `unlock_ebox(..., Some(agent_oracle))` recovers the
//! original key through the abstract [`EcdhOracle`] seam.
//!
//! Gating is identical to `agent_ecdh_integration.rs`: requires
//! `PCSCLITE_CSOCK_NAME` and `PIGGY_BIN`. The `test-rust-agent-unlock`
//! just recipe sets both — plain `cargo test` will skip this file.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use openssl::bn::BigNumContext;
use openssl::ec::{EcGroup, EcPoint, PointConversionForm};
use piggy::agent_client::{unlock_agent_pin, AgentEcdhOracle};
use piggy_box::ebox::{Ebox, EboxType};
use piggy_box::piv_box::EcCurve;
use piggy_box::template::{EboxConfigType, EboxTemplate, EboxTplConfig, EboxTplPart, DEFAULT_SLOT};
use piggy_box::unlock::unlock_ebox;
use piggy_piv::{PivAlgorithm, PivContext};
use ssh_key::public::{EcdsaPublicKey, KeyData};

/// RAII guard that kills the spawned piggy-agent on drop. Mirrors the
/// helper in `agent_ecdh_integration.rs` so the two tests can coexist
/// without either leaking a child on panic.
struct AgentGuard {
    child: Child,
}

impl AgentGuard {
    /// Non-blocking drain of whatever the child has emitted so far —
    /// used in failure paths to surface agent output in the panic
    /// message.
    fn drain_output(&mut self) -> String {
        use std::os::unix::io::{AsRawFd, RawFd};

        fn set_nonblocking(fd: RawFd) {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags >= 0 {
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }
        fn drain(pipe: &mut impl Read, label: &str, out: &mut String) {
            let mut buf = [0u8; 4096];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        out.push_str(&format!("[{label}] "));
                        out.push_str(&String::from_utf8_lossy(&buf[..n]));
                    }
                    Err(_) => break,
                }
            }
        }

        let mut out = String::new();
        if let Some(pipe) = self.child.stdout.as_mut() {
            set_nonblocking(pipe.as_raw_fd());
            drain(pipe, "stdout", &mut out);
        }
        if let Some(pipe) = self.child.stderr.as_mut() {
            set_nonblocking(pipe.as_raw_fd());
            drain(pipe, "stderr", &mut out);
        }
        out
    }
}

impl Drop for AgentGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn unlock_ebox_against_real_agent() {
    // ---- Gating ----
    let pcscd_sock = match std::env::var("PCSCLITE_CSOCK_NAME") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!(
                "PCSCLITE_CSOCK_NAME not set — skipping (run via `just test-rust-agent-unlock`)"
            );
            return;
        }
    };
    let piggy_bin = match std::env::var("PIGGY_BIN") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            eprintln!("PIGGY_BIN not set — skipping");
            return;
        }
    };
    assert!(
        piggy_bin.is_file(),
        "PIGGY_BIN={} does not point to a file",
        piggy_bin.display()
    );
    eprintln!("using pcscd socket: {pcscd_sock}");
    eprintln!("using piggy bin:    {}", piggy_bin.display());

    // ---- Spawn piggy-agent ----
    let tempdir = tempdir();
    let sock = tempdir.join("agent.sock");

    let mut cmd = Command::new(&piggy_bin);
    cmd.arg("agent")
        .arg("-A")
        .arg("-D")
        .arg("-a")
        .arg(&sock)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("spawn piggy-agent: {e}"));
    let mut guard = AgentGuard { child };

    wait_for_socket(&sock, Duration::from_secs(5), &mut guard);

    // ---- Unlock the agent PIN ----
    unlock_agent_pin(&sock, "123456").expect("unlock agent with PIN");

    // ---- Read card's 9D pubkey via piggy-piv ----
    let ctx = PivContext::new().expect("PivContext");
    let tokens = ctx.enumerate_tokens().expect("enumerate_tokens");
    let token = tokens
        .first()
        .expect("at least one PIV token available via PCSCLITE_CSOCK_NAME");
    let slot_9d = token.read_slot(0x9D).expect("read 9D slot");
    assert_eq!(
        slot_9d.algorithm(),
        PivAlgorithm::EcP256,
        "test assumes 9D was generated with eccp256"
    );
    let card_guid = token.guid().clone();

    // The slot's public key is exposed via ssh_key::PublicKey. Extract
    // the raw SEC1 uncompressed bytes for the template (`Ebox::create`
    // uses openssl `EcPoint::from_bytes`, which accepts either form).
    let card_sec1_uncompressed = match slot_9d.public_key().key_data() {
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => p.as_bytes().to_vec(),
        other => panic!("expected NistP256, got {other:?}"),
    };
    assert_eq!(
        card_sec1_uncompressed.len(),
        65,
        "P-256 uncompressed point is 65 bytes"
    );

    // Compress for the template (matches how templates are normally
    // stored by `piggy box tpl create`).
    let card_sec1_compressed = compress_ec_point(EcCurve::NistP256, &card_sec1_uncompressed);

    // ---- Build a minimal single-part Primary template ----
    let tpl = EboxTemplate {
        version: 1,
        configs: vec![EboxTplConfig {
            config_type: EboxConfigType::Primary,
            n: 1,
            parts: vec![EboxTplPart {
                guid: Some(card_guid.clone()),
                slot: DEFAULT_SLOT,
                name: Some("piggy-test:unlock-integration".into()),
                pubkey: card_sec1_compressed,
                pubkey_curve: EcCurve::NistP256,
                cak: None,
            }],
        }],
    };

    // ---- Seal a random key under the card's pubkey ----
    let plaintext_key: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(11).wrapping_add(3))
        .collect();
    let sealed = Ebox::create(&tpl, &plaintext_key, EboxType::Stream).expect("Ebox::create");

    // ---- Wire round-trip (bytes → bytes → Ebox) ----
    let wire = sealed.to_bytes().expect("serialize ebox");
    let mut ebox = Ebox::from_bytes(&wire).expect("deserialize ebox");
    assert!(!ebox.is_unlocked(), "deserialized ebox must start locked");

    // ---- Unlock via the agent ----
    let mut oracle = AgentEcdhOracle::new(&sock).expect("build oracle");
    unlock_ebox(&mut ebox, Some(&mut oracle), None).expect("unlock_ebox via agent");

    assert!(
        ebox.is_unlocked(),
        "ebox must be unlocked after agent round-trip"
    );
    let recovered = ebox.key().expect("key materializes");
    assert_eq!(
        recovered, plaintext_key,
        "recovered key must match the sealed plaintext"
    );

    eprintln!("unlock_ebox round-trip OK: recovered sealed key via agent");
    drop(guard);
}

/// Compress a SEC1 uncompressed EC point (65 bytes for P-256) to the
/// compressed form (33 bytes) using openssl — the same encoding
/// template and piv_box expect for `recipient_pubkey`.
fn compress_ec_point(curve: EcCurve, uncompressed: &[u8]) -> Vec<u8> {
    let group = EcGroup::from_curve_name(curve.nid()).expect("EcGroup");
    let mut ctx = BigNumContext::new().expect("BigNumContext");
    let p = EcPoint::from_bytes(&group, uncompressed, &mut ctx).expect("EcPoint::from_bytes");
    let out = p
        .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
        .expect("point to_bytes");
    // Sanity-check so a silent regression (e.g. openssl changing
    // defaults) surfaces via test failure rather than a bad template.
    assert_eq!(out.len(), 33, "compressed P-256 point is 33 bytes");
    out
}

/// Anchor the socket path at `/tmp` because `sockaddr_un.sun_path` has
/// a 108-byte ceiling and nix-shell's default `TMPDIR` sits several
/// directories deep inside the worktree. See the matching comment in
/// `agent_ecdh_integration.rs::tempdir` for the fuller story.
fn tempdir() -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = PathBuf::from(format!("/tmp/piggy-it-unlock-{pid}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

/// Poll every 100 ms until the agent socket appears, up to `timeout`.
/// On timeout, drain the child's output to surface the failure reason.
fn wait_for_socket(sock: &std::path::Path, timeout: Duration, guard: &mut AgentGuard) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if sock.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let captured = guard.drain_output();
    panic!(
        "agent socket {} never appeared within {:?}\nchild output:\n{}",
        sock.display(),
        timeout,
        captured
    );
}
