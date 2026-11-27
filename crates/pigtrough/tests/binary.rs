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
        Self::start_with(dir, &[])
    }

    fn start_with(dir: PathBuf, extra: &[&std::ffi::OsStr]) -> Self {
        let child = pigtrough()
            .args(["serve", "--dir"])
            .arg(&dir)
            .args(extra)
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

const TWO_ROUTES: &str = r#"
[[route]]
name = "fj-api"
upstream = "forgejo.invalid"
auth = "token"
secret = "piggy-test/fj"
owners = ["some-org"]
loopback_port = PORT
[[route.allow]]
method = "GET"
path = ["api", "v1", "repos", "{owner}", "{name}"]

[[route]]
name = "second"
upstream = "second.invalid"
auth = "bearer"
secret = "piggy-test/second"
owners = ["some-org"]
[[route.allow]]
method = "GET"
path = ["repos", "{owner}", "{name}"]
"#;

fn routes_file(tag: &str, text: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pb-{}-{tag}.toml", std::process::id()));
    std::fs::write(&path, text).unwrap();
    path
}

fn get_tcp(port: u16, target: &str) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
            Err(e) => {
                assert!(Instant::now() < deadline, "no loopback listener: {e}");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let raw = format!("GET {target} HTTP/1.1\r\nHost: proxy\r\nConnection: close\r\n\r\n");
    stream.write_all(raw.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

/// Slices 2 and 3 end to end: two routes from a table, one also on a
/// loopback port. The loopback connection is admitted by the kernel's
/// record of its owner, and can name only its own route.
#[test]
fn a_loopback_route_serves_this_user_and_only_its_own_route() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let file = routes_file("two", &TWO_ROUTES.replace("PORT", &port.to_string()));
    let server = Server::start_with(
        short_dir("loop"),
        &[std::ffi::OsStr::new("--routes"), file.as_os_str()],
    );

    let own = get_tcp(port, "/fj-api/api/v1/repos/some-org/x");
    assert!(
        own.starts_with(b"HTTP/1.1 503"),
        "{}",
        String::from_utf8_lossy(&own)
    );
    let other = get_tcp(port, "/second/repos/some-org/x");
    assert!(
        other.starts_with(b"HTTP/1.1 403"),
        "{}",
        String::from_utf8_lossy(&other)
    );
    // The unix socket serves both routes.
    let on_unix = get(&server.dir, "/second/repos/some-org/x");
    assert!(
        on_unix.starts_with(b"HTTP/1.1 503"),
        "{}",
        String::from_utf8_lossy(&on_unix)
    );

    // Each route is loaded on its own, by name.
    let loaded = load(&server.dir, "fj-api", format!("{TOKEN}\n").as_bytes());
    assert!(loaded.status.success(), "{loaded:?}");
    let still = get(&server.dir, "/second/repos/some-org/x");
    assert!(still.starts_with(b"HTTP/1.1 503"), "second is still empty");
    let refused = get_tcp(port, "/fj-api/api/v1/user");
    assert!(refused.starts_with(b"HTTP/1.1 403"));

    let printed = server.stop();
    assert!(!contains(&printed, TOKEN));
    let printed = String::from_utf8_lossy(&printed);
    assert!(
        printed.contains(&format!("route fj-api also on 127.0.0.1:{port}")),
        "{printed}"
    );
    assert!(printed.contains("load fj-api: ok"), "{printed}");
    let _ = std::fs::remove_file(file);
}

fn os<'a>(args: &[&'a str]) -> Vec<&'a std::ffi::OsStr> {
    args.iter().map(|arg| std::ffi::OsStr::new(*arg)).collect()
}

/// A request head to an allowed path declaring `len` body bytes, followed by
/// `sent` of them.
fn with_body(path: &str, len: usize, sent: usize) -> Vec<u8> {
    let mut raw = format!(
        "{path} HTTP/1.1\r\nHost: proxy\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    raw.resize(raw.len() + sent, b'b');
    raw
}

const POST_REPOS: &str = "POST /github-api/orgs/amarbel-llc/repos";

fn open(dir: &Path, raw: &[u8]) -> UnixStream {
    let mut stream = UnixStream::connect(dir.join("proxy.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(raw).unwrap();
    stream
}

fn reply_on(mut stream: impl Read) -> String {
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// The cap on buffered bodies is `serve`'s to set: a small one turns a body
/// away, and 0 turns the cap off. With no secret loaded, a body that gets
/// through is answered `503` and nothing reaches an upstream.
#[test]
fn serve_sets_or_turns_off_the_body_cap() {
    for (tag, cap, status, needle) in [
        ("capped", "10", "HTTP/1.1 429", "--max-buffered-bytes"),
        ("uncapped", "0", "HTTP/1.1 503", "secret-unavailable"),
    ] {
        let server = Server::start_with(short_dir(tag), &os(&["--max-buffered-bytes", cap]));
        let reply = reply_on(open(&server.dir, &with_body(POST_REPOS, 100, 100)));
        assert!(reply.starts_with(status), "{tag}: {reply}");
        assert!(reply.contains(needle), "{tag}: {reply}");
    }
}

#[test]
fn serve_sets_or_turns_off_the_body_read_timeout() {
    let server = Server::start_with(
        short_dir("deadline"),
        &os(&["--body-read-timeout-seconds", "1"]),
    );
    let reply = reply_on(open(&server.dir, &with_body(POST_REPOS, 10, 4)));
    assert!(reply.starts_with("HTTP/1.1 400"), "{reply}");
    assert!(reply.contains("--body-read-timeout-seconds"), "{reply}");
    drop(server);

    let server = Server::start_with(
        short_dir("nodeadline"),
        &os(&["--body-read-timeout-seconds", "0"]),
    );
    let mut stream = open(&server.dir, &with_body(POST_REPOS, 10, 4));
    std::thread::sleep(Duration::from_secs(2));
    stream.write_all(b"bbbbbb").unwrap();
    let reply = reply_on(stream);
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
}

/// One cap for the process: bytes held for a request on the unix socket
/// leave less for one on a loopback port.
#[test]
fn the_listeners_share_one_body_cap() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let file = routes_file("shared", &TWO_ROUTES.replace("PORT", &port.to_string()));
    let mut args = os(&["--max-buffered-bytes", "10", "--routes"]);
    args.push(file.as_os_str());
    let server = Server::start_with(short_dir("shared"), &args);
    // Waits for the loopback listener too.
    assert!(get_tcp(port, "/fj-api/api/v1/user").starts_with(b"HTTP/1.1 403"));

    let _holding = open(
        &server.dir,
        &with_body("GET /second/repos/some-org/x", 9, 8),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        tcp.write_all(&with_body("GET /fj-api/api/v1/repos/some-org/x", 5, 5))
            .unwrap();
        let reply = reply_on(tcp);
        // Until the first body has arrived there is still room.
        if reply.starts_with("HTTP/1.1 429") {
            break;
        }
        assert!(Instant::now() < deadline, "never refused: {reply}");
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = std::fs::remove_file(file);
}

#[test]
fn serve_refuses_a_limit_that_is_not_a_number_or_is_given_twice() {
    let dir = short_dir("badlimit");
    for args in [
        &["--max-buffered-bytes", "64MiB"][..],
        &["--body-read-timeout-seconds", "-1"],
        &["--max-buffered-bytes"],
        &["--max-buffered-bytes", "1", "--max-buffered-bytes", "2"],
    ] {
        let out = pigtrough()
            .args(["serve", "--dir"])
            .arg(&dir)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!out.status.success(), "{args:?}");
        assert!(contains(&out.stderr, "usage:"), "{args:?}");
        assert!(
            !dir.join("control.sock").exists(),
            "{args:?}: bound a socket"
        );
    }
}

#[test]
fn serve_refuses_a_bad_route_table_before_binding_anything() {
    let dir = short_dir("badtable");
    for (tag, text, needle) in [
        ("bad1", "this is not toml = = =", "route table"),
        ("bad2", "[[route]]\nname = \"r\"\n", "missing field"),
        (
            "bad3",
            "[[route]]\nname = \"r\"\nupstream = \"x.invalid\"\nauth = \"token\"\n\
             secret = \"piggy-test/x\"\nextra_roots = [\"/etc/pigtrough-test-no-such-ca.pem\"]\n\
             [[route.allow]]\nmethod = \"GET\"\npath = [\"a\"]\n",
            "/etc/pigtrough-test-no-such-ca.pem",
        ),
    ] {
        let file = routes_file(tag, text);
        let out = pigtrough()
            .args(["serve", "--dir"])
            .arg(&dir)
            .arg("--routes")
            .arg(&file)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!out.status.success(), "{tag}");
        assert!(
            contains(&out.stderr, needle),
            "{tag}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!dir.join("control.sock").exists(), "{tag}: bound a socket");
        let _ = std::fs::remove_file(file);
    }
}
