//! End-to-end integration test for the card ECDH SSH-agent extension
//! (`ecdh@code.linenisgreat.com`, legacy alias `ecdh@joyent.com`,
//! piggy#335), exercising the real piggy-agent backed by a virtual PIV card.
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
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use piggy::agent_client::{AgentEcdhOracle, probe_extensions, unlock_agent_pin};
use piggy_box::agent_ext::{decode_ecdh_response, encode_ecdh_request};
use piggy_box::oracle::EcdhOracle;
use piggy_piv::{PivAlgorithm, PivContext};
use ssh_agent_lib::agent::Session;
use ssh_agent_lib::client::Client;
use ssh_agent_lib::proto::Extension;
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

/// Both tests drive the one fibby card through their own agent; run them
/// one at a time so neither sees the other's agent mid-transaction.
static CARD: Mutex<()> = Mutex::new(());

/// The gated environment: the `piggy` binary under test, or `None` (skip)
/// when the fibby recipe did not set `PCSCLITE_CSOCK_NAME` / `PIGGY_BIN`.
fn integration_piggy_bin() -> Option<PathBuf> {
    let pcscd_sock = match std::env::var("PCSCLITE_CSOCK_NAME") {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!(
                "PCSCLITE_CSOCK_NAME not set — skipping (run via `just test-rust-integration-fibby`)"
            );
            return None;
        }
    };
    let piggy_bin = match std::env::var("PIGGY_BIN") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => {
            eprintln!("PIGGY_BIN not set — skipping");
            return None;
        }
    };
    assert!(
        piggy_bin.is_file(),
        "PIGGY_BIN={} does not point to a file",
        piggy_bin.display()
    );
    eprintln!("using pcscd socket: {pcscd_sock}");
    eprintln!("using piggy bin:    {}", piggy_bin.display());
    Some(piggy_bin)
}

/// Spawn `piggy agent` on a fresh socket, wait for it, and unlock its PIN
/// (fibby's 123456). The guard tears the agent down on drop.
fn spawn_unlocked_agent(piggy_bin: &Path) -> (AgentGuard, PathBuf) {
    let tempdir = tempdir();
    let sock = tempdir.join("agent.sock");

    let mut cmd = Command::new(piggy_bin);
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

    wait_for_socket(&sock, Duration::from_secs(5), &mut guard);
    unlock_agent_pin(&sock, "123456").expect("unlock");
    (guard, sock)
}

/// The card's slot-9D public key, read over the same pcscd the agent uses.
/// The agent and this test contend for the reader, but pcscd serializes
/// access via its transaction lock — both can probe the card successfully.
fn read_card_9d() -> PublicKey {
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
    slot_9d.public_key().clone()
}

/// The raw SEC1 bytes of a P-256 SSH public key.
fn p256_sec1_bytes(key: &PublicKey) -> Vec<u8> {
    match key.key_data() {
        KeyData::Ecdsa(EcdsaPublicKey::NistP256(p)) => p.as_bytes().to_vec(),
        other => panic!("expected NistP256, got {other:?}"),
    }
}

#[test]
fn ecdh_roundtrip_against_real_agent() {
    let Some(piggy_bin) = integration_piggy_bin() else {
        return;
    };
    let _card = CARD.lock().unwrap_or_else(|e| e.into_inner());
    let (guard, sock) = spawn_unlocked_agent(&piggy_bin);

    // self_pubkey_ssh_blob: the SSH-wire encoding of the card's 9D pubkey.
    // That is: ssh_string("ecdsa-sha2-nistp256") | ssh_string("nistp256") |
    // ssh_string(SEC1 uncompressed point), which is exactly what
    // `ssh_key::PublicKey::to_bytes` produces for an Ecdsa KeyData.
    let self_pubkey: PublicKey = read_card_9d();
    let self_blob = self_pubkey.to_bytes().expect("encode self pubkey");

    // Extract the raw SEC1 bytes for local p256 use.
    let card_sec1_bytes = p256_sec1_bytes(&self_pubkey);
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

    // ---- piggy#335: both names advertised, served, and echoed ----
    let advertised =
        probe_extensions(&sock, Duration::from_secs(5)).expect("query the agent's extensions");
    assert!(
        advertised.iter().any(|n| n == piggy::ecdh_ext::CANONICAL),
        "{advertised:?}"
    );
    assert!(
        advertised.iter().any(|n| n == piggy::ecdh_ext::LEGACY),
        "{advertised:?}"
    );
    for name in piggy::ecdh_ext::NAMES {
        let reply = raw_ecdh_extension(&sock, name, &self_blob, &partner_blob);
        assert_eq!(reply.name.as_str(), name, "agent must echo the name asked");
        let secret = decode_ecdh_response(reply.details.as_ref()).expect("decode ecdh reply");
        assert_eq!(secret, expected_bytes, "ECDH under {name} disagrees");
    }

    // A second oracle call after the probe: it goes out under the
    // canonical name first and still agrees.
    let again = oracle
        .ecdh(&self_blob, &partner_blob)
        .expect("agent-computed ECDH, second call");
    assert_eq!(again, expected_bytes);

    // `guard` drops here, tearing down the child agent.
    drop(guard);
}

/// The pure-Rust pigpen oracle (no tokio, no OpenSSL) opens a document
/// sealed to the card's 9D key through the real agent — the path madder's
/// Rust CLI and pigsty take.
#[test]
fn pigpen_opens_through_the_pure_rust_oracle_against_real_agent() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use piggy_pigpen::Document;
    use piggy_pigpen::agent::AgentEcdhOracle as PigpenAgentOracle;

    let Some(piggy_bin) = integration_piggy_bin() else {
        return;
    };
    let _card = CARD.lock().unwrap_or_else(|e| e.into_inner());
    let (guard, sock) = spawn_unlocked_agent(&piggy_bin);

    let card_sec1 = p256_sec1_bytes(&read_card_9d());
    let compressed = p256::PublicKey::from_sec1_bytes(&card_sec1)
        .expect("p256 parse card pubkey")
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();
    assert_eq!(compressed.len(), 33);
    let id = piggy_pigpen::recipient_id(piggy_markl::FormatId::PivyEcdhP256Pub, compressed)
        .expect("recipient id");

    let doc = Document::seal(b"pigsty hello", &[id]).expect("seal");
    let oracle = PigpenAgentOracle::new(&sock);
    let plaintext = doc
        .open(Some(&oracle), &[])
        .expect("open through the agent");
    assert_eq!(plaintext, b"pigsty hello");

    drop(guard);
}

/// Send one ECDH extension request under `name` on a fresh connection
/// and return the agent's raw reply, so the test can see the echoed name
/// (the oracle hides it).
fn raw_ecdh_extension(
    sock: &std::path::Path,
    name: &str,
    self_blob: &[u8],
    partner_blob: &[u8],
) -> Extension {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let stream = tokio::net::UnixStream::connect(sock)
            .await
            .expect("connect agent");
        let mut client = Client::new(stream);
        client
            .extension(Extension {
                name: name.to_string(),
                details: encode_ecdh_request(self_blob, partner_blob, 0).into(),
            })
            .await
            .unwrap_or_else(|e| panic!("ecdh under {name}: {e}"))
            .unwrap_or_else(|| panic!("ecdh under {name}: plain SUCCESS"))
    })
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
