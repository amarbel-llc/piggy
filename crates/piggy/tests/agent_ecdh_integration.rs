//! End-to-end integration test for the `ecdh@joyent.com` SSH-agent
//! extension, exercising the real piggy-agent backed by a virtual PIV card.
//!
//! Checkpoint 2 of issue #32. Checkpoint 1 added the pure encode/decode
//! routines; this test proves they are wired to the agent correctly by
//! having both the agent and the test compute ECDH over the same partner
//! point and comparing the scalars bit-for-bit.
//!
//! Gating: requires `PCSCLITE_CSOCK_NAME` (a live pcscd — typically the
//! fibby virtual card socket) and `PIGGY_BIN` (absolute path to the `piggy`
//! binary under test). The `test-rust-integration-fibby` just recipe sets
//! both. Plain `cargo test` / `just test-rust` will skip this file.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use piggy::agent_client::{AgentEcdhOracle, unlock_agent_pin};
use piggy_box::oracle::EcdhOracle;
use piggy_piv::{PivAlgorithm, PivContext};
use ssh_key::PublicKey;
use ssh_key::public::{EcdsaPublicKey, KeyData};

/// RAII guard that kills the spawned piggy-agent on drop. Keeping the
/// child around in a guard (rather than letting `Command::spawn` return)
/// means test panics still tear down the agent instead of leaking it.
struct AgentGuard {
    child: Child,
}

impl AgentGuard {
    /// Drain whatever the child has written so far. Non-blocking via
    /// `O_NONBLOCK` on the pipe fd, so it's safe to call while the agent
    /// is still running.
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
        // Ignore errors: the child may have already exited (e.g. if the
        // socket binding failed). We only care that nothing is left
        // holding the Unix socket when the test ends.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn ecdh_roundtrip_against_real_agent() {
    // ---- Gating ----
    let pcscd_sock = match std::env::var("PCSCLITE_CSOCK_NAME") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!(
                "PCSCLITE_CSOCK_NAME not set — skipping (run via `just test-rust-integration-fibby`)"
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
        .arg("-A") // all-cards
        .arg("-D") // foreground debug
        .arg("-a")
        .arg(&sock)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd
        .spawn()
        .unwrap_or_else(|e| panic!("spawn piggy-agent: {e}"));
    let mut guard = AgentGuard { child };

    // ---- Wait for the socket ----
    wait_for_socket(&sock, Duration::from_secs(5), &mut guard);

    // ---- Unlock the agent PIN ----
    unlock_agent_pin(&sock, "123456").expect("unlock");

    // ---- Read card's 9D pubkey ----
    // Reach into the same pcscd that the agent child is using. The agent
    // and this test contend for the reader, but pcscd serializes access
    // via its transaction lock — both can probe the card successfully.
    let ctx = PivContext::new().expect("PivContext");
    let tokens = ctx.enumerate_tokens().expect("enumerate_tokens");
    let token = tokens
        .first()
        .expect("at least one PIV token available via PCSCLITE_CSOCK_NAME");
    let slot_9d = token.read_slot(0x9D).expect("read 9D slot");

    assert_eq!(
        slot_9d.algorithm(),
        PivAlgorithm::EcP256,
        "test assumes 9D was generated with eccp256 (just load-fib + pivy-tool -a eccp256 generate 9d)"
    );

    // self_pubkey_ssh_blob: the SSH-wire encoding of the card's 9D pubkey.
    // That is: ssh_string("ecdsa-sha2-nistp256") | ssh_string("nistp256") |
    // ssh_string(SEC1 uncompressed point), which is exactly what
    // `ssh_key::PublicKey::to_bytes` produces for an Ecdsa KeyData.
    let self_pubkey: PublicKey = slot_9d.public_key().clone();
    let self_blob = self_pubkey.to_bytes().expect("encode self pubkey");

    // Extract the raw SEC1 bytes for local p256 use.
    let card_sec1_bytes = match self_pubkey.key_data() {
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => p.as_bytes().to_vec(),
        other => panic!("expected NistP256, got {other:?}"),
    };
    let card_p256_pubkey =
        p256::PublicKey::from_sec1_bytes(&card_sec1_bytes).expect("p256 parse card pubkey");

    // ---- Generate partner keypair ----
    let partner_secret = p256::ecdh::EphemeralSecret::random(&mut rand::rngs::OsRng);
    let partner_public = partner_secret.public_key();
    // SEC1 uncompressed bytes (0x04 || x || y). p256 yields a boxed slice.
    let partner_sec1: Vec<u8> = partner_public.to_sec1_bytes().to_vec();
    assert_eq!(
        partner_sec1.len(),
        65,
        "uncompressed P-256 point is 65 bytes"
    );
    assert_eq!(
        partner_sec1[0], 0x04,
        "SEC1 uncompressed point must start with 0x04"
    );

    // Wrap as ssh_key::PublicKey → SSH wire blob.
    let partner_ecdsa =
        EcdsaPublicKey::from_sec1_bytes(&partner_sec1).expect("from_sec1_bytes partner");
    let partner_key_data = KeyData::Ecdsa(partner_ecdsa);
    let partner_ssh_pub = PublicKey::from(partner_key_data);
    let partner_blob = partner_ssh_pub.to_bytes().expect("encode partner pubkey");

    // ---- Compute expected secret locally ----
    let expected_shared = partner_secret.diffie_hellman(&card_p256_pubkey);
    let expected_bytes: Vec<u8> = expected_shared.raw_secret_bytes().as_slice().to_vec();
    assert_eq!(expected_bytes.len(), 32, "P-256 shared secret is 32 bytes");

    // ---- Ask the agent ----
    let mut oracle = AgentEcdhOracle::new(&sock).expect("build oracle");
    let got = oracle
        .ecdh(&self_blob, &partner_blob)
        .expect("agent-computed ECDH");

    // ---- Assert ----
    assert_eq!(got.len(), 32, "agent returned wrong-length secret");
    assert_eq!(
        got, expected_bytes,
        "agent ECDH scalar disagrees with locally-computed scalar"
    );

    eprintln!("ECDH round-trip OK: 32-byte shared secret matches local computation");

    // `guard` drops here, tearing down the child agent.
    drop(guard);
}

/// Allocate a per-test temp directory for the agent socket.
///
/// We ignore `TMPDIR` / `std::env::temp_dir()` and anchor at `/tmp`
/// directly because nix-shell sets `TMPDIR` to a path deep inside the
/// worktree (e.g. `.tmp/nix-shell.XXXXXX/...`). Unix-domain socket
/// paths must fit in `sockaddr_un.sun_path` (108 bytes on Linux); a
/// long tempdir plus `/agent.sock` easily overflows that, and piggy's
/// bind call fails with "path must be shorter than SUN_LEN".
fn tempdir() -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = PathBuf::from(format!("/tmp/piggy-it-{pid}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

/// Poll every 100 ms until the agent socket appears, up to `timeout`. On
/// timeout, drain the child's stdout/stderr and surface them in the panic
/// message so failures tell the operator why the agent didn't come up.
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
