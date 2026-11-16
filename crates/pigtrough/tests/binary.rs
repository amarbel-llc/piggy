//! The `pigtrough` binary end to end, Linux only (it reads /proc).
//!
//! Behaviour 2's last clause: the token never appears in the proxy's argv or
//! environment, nor in anything `serve` or `load` print. `serve` runs with
//! public roots, so this test never sends an allowed request after the load
//! (that would reach the real api.github.com); it checks the loaded state
//! through the control answer and the refusals that need no upstream.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TOKEN: &str = "piggy-test-pigtrough-binary-token-0001";

fn short_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pb-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn pigtrough() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pigtrough"))
}

/// A running `serve`, killed when dropped so a failed assertion leaves no
/// process behind.
struct Server {
    child: Option<Child>,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Server {
    fn start(dir: PathBuf) -> Self {
        let child = pigtrough()
            .args(["serve", "--dir"])
            .arg(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !dir.join("control.sock").exists() {
            assert!(
                Instant::now() < deadline,
                "serve did not create its sockets"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            child: Some(child),
            dir,
        }
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().unwrap().id()
    }

    /// Stop the server and return everything it printed.
    fn stop(mut self) -> Vec<u8> {
        let mut child = self.child.take().unwrap();
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        let mut printed = output.stdout;
        printed.extend(output.stderr);
        printed
    }
}

fn load(dir: &Path, route: &str, secret: &[u8]) -> std::process::Output {
    let mut child = pigtrough()
        .args(["load", route, "--dir"])
        .arg(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(secret).unwrap();
    child.wait_with_output().unwrap()
}

fn get(dir: &Path, target: &str) -> Vec<u8> {
    let mut stream = UnixStream::connect(dir.join("proxy.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let raw = format!("GET {target} HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n\r\n");
    stream.write_all(raw.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn the_token_is_never_in_argv_environment_or_output() {
    let server = Server::start(short_dir("serve"));
    let dir = server.dir.clone();

    // Before any load: allowed requests fail closed without an upstream call.
    let before = get(&dir, "/github-api/repos/amarbel-llc/piggy");
    assert!(
        before.starts_with(b"HTTP/1.1 503"),
        "{}",
        String::from_utf8_lossy(&before)
    );
    assert!(contains(&before, "secret-unavailable"));

    let loaded = load(&dir, "github-api", format!("{TOKEN}\n").as_bytes());
    assert!(loaded.status.success(), "{loaded:?}");

    // After it: a refusal still needs no upstream, and carries no token.
    let refused = get(&dir, "/github-api/user");
    assert!(
        refused.starts_with(b"HTTP/1.1 403"),
        "{}",
        String::from_utf8_lossy(&refused)
    );

    let pid = server.pid();
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    assert!(!contains(&cmdline, TOKEN));
    // serve makes itself non-dumpable, which hides its environment even from
    // this user; if it is readable after all, it must not hold the token.
    match std::fs::read(format!("/proc/{pid}/environ")) {
        Ok(environ) => assert!(!contains(&environ, TOKEN)),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}"),
    }

    let printed = server.stop();
    for (what, bytes) in [
        ("serve output", &printed),
        ("load stdout", &loaded.stdout),
        ("load stderr", &loaded.stderr),
        ("refusal", &refused),
    ] {
        assert!(!contains(bytes, TOKEN), "token in {what}");
    }
    let printed = String::from_utf8_lossy(&printed);
    assert!(printed.contains("pigtrough audit"), "{printed}");
    assert!(printed.contains("decision=refuse-unavailable"), "{printed}");
    assert!(printed.contains("load github-api: ok"), "{printed}");
}

#[test]
fn load_refuses_an_unknown_route_and_an_empty_secret() {
    let server = Server::start(short_dir("refuse"));
    let unknown = load(&server.dir, "elsewhere", TOKEN.as_bytes());
    assert!(!unknown.status.success());
    assert!(contains(&unknown.stderr, "unknown route"));
    let empty = load(&server.dir, "github-api", b"");
    assert!(!empty.status.success());
    assert!(contains(&empty.stderr, "empty"));
    let printed = server.stop();
    assert!(!contains(&printed, TOKEN));
}
