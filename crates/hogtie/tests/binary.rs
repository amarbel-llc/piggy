//! The hogtie binary end to end, built with the `test-harness` feature (its
//! paths under HOGTIE_TEST_ROOT, the test's own uid standing in for root):
//! the socket hands out a nonce, the caller signs with stock ssh-keygen and
//! a software CA's grant, `hogtie exec` runs the action with nothing but
//! the declared environment, and every use lands in the audit log.
#![cfg(target_os = "linux")]

use hogtie::testkit::{Kit, trusted_copy, write_trusted};
use hogtie::util::PrivateDir;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::Duration;

const HOGTIE: &str = env!("CARGO_BIN_EXE_hogtie");

/// The `state` action's shell: its umask, its open-file limit, its open
/// descriptors and its ignored and blocked signals (builtins only: the
/// action has no PATH; no braces: the registry refuses them in argv).
const STATE_SCRIPT: &str = "umask; ulimit -n; for f in /proc/self/fd/*; do echo $f; done; \
     while read -r k v; do case $k in SigIgn:|SigBlk:|Cpus_allowed_list:) echo $k $v;; esac; done < /proc/self/status";

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Host {
    kit: Kit,
    root: PrivateDir,
    _server: Server,
}

impl Host {
    fn new() -> Self {
        let kit = Kit::new();
        // A short root: the socket path must fit sun_path (108 bytes).
        let tmp = std::env::temp_dir();
        let parent = if tmp.as_os_str().len() < 64 {
            tmp
        } else {
            PathBuf::from("/tmp")
        };
        let root = PrivateDir::new(&parent, "hgt").unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        // A trusted file that is not executable: exec(2) refuses it.
        let not_exec = root.path().join("etc/not-executable");
        write_trusted(&not_exec, "#!/bin/sh\n");
        let config = format!(
            "host = \"h1\"\nssh_keygen = \"{}\"\nca_keys = [\"{}\"]\nmax_grant_seconds = 86400\n\
             [action.say]\nprogram = \"{}\"\nargv = [\"{{word}}\"]\n\
             param = [{{ name = \"word\", kind = \"choice\", values = [\"hello\"] }}]\n\
             [action.show-env]\nprogram = \"{}\"\nenv = {{ LANG = \"C\" }}\n\
             [action.where]\nprogram = \"{}\"\n\
             [action.broken]\nprogram = \"{}\"\n\
             [action.state]\nprogram = \"{}\"\nargv = [\"-c\", \"{}\"]\n",
            kit.ssh_keygen.display(),
            kit.ca_line(),
            trusted_copy(kit.dir(), "echo").display(),
            trusted_copy(kit.dir(), "env").display(),
            trusted_copy(kit.dir(), "pwd").display(),
            not_exec.display(),
            trusted_copy(kit.dir(), "sh").display(),
            STATE_SCRIPT,
        );
        write_trusted(&root.path().join("etc/hogtie.toml"), &config);
        let server = Server(
            Command::new(HOGTIE)
                .arg("serve")
                .env("HOGTIE_TEST_ROOT", root.path())
                .spawn()
                .unwrap(),
        );
        let sock = root.path().join("run/nonce.sock");
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(sock.exists(), "the socket came up");
        Self {
            kit,
            root,
            _server: server,
        }
    }

    fn hogtie(&self, args: &[&str]) -> Output {
        Command::new(HOGTIE)
            .args(args)
            .env("HOGTIE_TEST_ROOT", self.root.path())
            .output()
            .unwrap()
    }

    fn uid() -> String {
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() }.to_string()
    }

    fn sudo_exec(&self, response: &str, action: &[&str]) -> Output {
        Command::new(HOGTIE)
            .arg("exec")
            .arg(response)
            .args(action)
            .env("HOGTIE_TEST_ROOT", self.root.path())
            .env("SUDO_UID", Self::uid())
            .env("SECRET_FROM_CALLER", "leak")
            .output()
            .unwrap()
    }

    /// Ask for a nonce, build the message, sign it with `cert`, make the
    /// response: the caller's whole side, through the binary.
    fn respond(&self, cert: &Path, action: &[&str]) -> String {
        let out = self.hogtie(&["nonce"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let nonce = String::from_utf8(out.stdout).unwrap().trim().to_string();
        let mut args = vec!["message", hogtie::testkit::HOST, nonce.as_str()];
        args.extend_from_slice(action);
        let msg = self.hogtie(&args);
        assert!(msg.status.success());
        let file: PathBuf = self.kit.dir().join(format!("m-{nonce}"));
        std::fs::write(&file, &msg.stdout).unwrap();
        let signed = Command::new(&self.kit.ssh_keygen)
            .args(["-Y", "sign", "-n", "hogtie-v1", "-f"])
            .arg(cert)
            .arg(&file)
            .output()
            .unwrap();
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
        let sig = format!("{}.sig", file.display());
        let out = self.hogtie(&["response", &nonce, &sig]);
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn audit(&self) -> Vec<String> {
        std::fs::read_to_string(self.root.path().join("log/audit.log"))
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect()
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn a_granted_action_runs_once_and_both_uses_are_audited() {
    let h = Host::new();
    let cert = h.kit.grant("agent-7", &["say"], "+1h", &[]);
    let r = h.respond(&cert, &["say", "hello"]);
    let out = h.sudo_exec(&r, &["say", "hello"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"hello\n");
    let replay = h.sudo_exec(&r, &["say", "hello"]);
    assert_eq!(replay.status.code(), Some(1));
    assert!(
        stderr(&replay).contains("unknown nonce"),
        "{}",
        stderr(&replay)
    );
    let log = h.audit();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(
        log[0].contains("\"outcome\":\"started\"") && log[0].contains("\"key_id\":\"agent-7\""),
        "{}",
        log[0]
    );
    assert!(
        log[1].contains("\"outcome\":\"refused\"") && log[1].contains("unknown nonce"),
        "{}",
        log[1]
    );
}

#[test]
fn the_action_gets_only_the_declared_environment_and_runs_in_root() {
    let h = Host::new();
    let cert = h.kit.grant("a", &["show-env", "where"], "+1h", &[]);
    let out = h.sudo_exec(&h.respond(&cert, &["show-env"]), &["show-env"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "LANG=C\n");
    let out = h.sudo_exec(&h.respond(&cert, &["where"]), &["where"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "/\n");
}

#[test]
fn an_expired_grant_is_refused_and_audited() {
    let h = Host::new();
    let cert = h.kit.grant("old", &["say"], "20200101:20200102", &[]);
    let out = h.sudo_exec(&h.respond(&cert, &["say", "hello"]), &["say", "hello"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("grant has expired"),
        "{}",
        stderr(&out)
    );
    assert!(h.audit()[0].contains("grant has expired"));
}

#[test]
fn exec_without_sudo_uid_is_refused_and_audited() {
    let h = Host::new();
    // Big arguments too: what this refusal records is bounded (finding 2).
    let big = "x".repeat(100_000);
    let mut args = vec!["exec", "v1.x.y", "say"];
    args.extend(std::iter::repeat_n(big.as_str(), 10));
    let out = h.hogtie(&args);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("SUDO_UID"), "{}", stderr(&out));
    let log = h.audit();
    assert!(log[0].contains("SUDO_UID is not set"));
    assert!(
        log[0].len() < 16 * 1024,
        "the line is {} bytes",
        log[0].len()
    );
}

#[test]
fn a_flood_of_refusals_is_counted_not_logged() {
    let h = Host::new();
    for _ in 0..30 {
        let out = h.sudo_exec("garbage", &["say", "hello"]);
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    }
    let log = h.audit();
    assert_eq!(
        log.len(),
        21,
        "20 refusals and the one that says the rest are not logged"
    );
    assert!(log[20].contains("counted, not logged"), "{}", log[20]);
}

/// Start `hogtie serve` over `root` with NOTIFY_SOCKET=`notify`; what the
/// notify socket `rx` received within `wait` (None: nothing), and serve.
fn serve_notifying(
    root: &Path,
    notify: &std::ffi::OsStr,
    rx: &std::os::unix::net::UnixDatagram,
    wait: Duration,
) -> (Option<String>, Server) {
    let server = Server(
        Command::new(HOGTIE)
            .arg("serve")
            .env("HOGTIE_TEST_ROOT", root)
            .env("NOTIFY_SOCKET", notify)
            .spawn()
            .unwrap(),
    );
    rx.set_read_timeout(Some(wait)).unwrap();
    let mut buf = [0u8; 256];
    let got = rx
        .recv(&mut buf)
        .ok()
        .map(|n| String::from_utf8_lossy(&buf[..n]).into_owned());
    (got, server)
}

fn short_root() -> PrivateDir {
    let tmp = std::env::temp_dir();
    let parent = if tmp.as_os_str().len() < 64 {
        tmp
    } else {
        PathBuf::from("/tmp")
    };
    PrivateDir::new(&parent, "hgt").unwrap()
}

#[test]
fn serve_tells_a_path_notify_socket_it_is_ready_once_bound() {
    let root = short_root();
    let path = root.path().join("notify");
    let rx = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
    let (got, _server) =
        serve_notifying(root.path(), path.as_os_str(), &rx, Duration::from_secs(10));
    assert_eq!(got.as_deref(), Some("READY=1"));
    assert!(
        root.path().join("run/nonce.sock").exists(),
        "ready before the socket was bound"
    );
}

#[test]
fn serve_tells_an_abstract_notify_socket_it_is_ready() {
    use std::os::linux::net::SocketAddrExt as _;
    let root = short_root();
    let name = format!(
        "hogtie-test-{}-{:?}",
        std::process::id(),
        std::time::Instant::now()
    );
    let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let rx = std::os::unix::net::UnixDatagram::bind_addr(&addr).unwrap();
    let notify = format!("@{name}");
    let (got, _server) =
        serve_notifying(root.path(), notify.as_ref(), &rx, Duration::from_secs(10));
    assert_eq!(got.as_deref(), Some("READY=1"));
}

#[test]
fn a_refused_serve_start_sends_nothing_and_exits_3() {
    let root = short_root();
    // The runtime directory's place is taken by a file: serve refuses.
    std::fs::write(root.path().join("run"), "").unwrap();
    let path = root.path().join("notify");
    let rx = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
    let (got, mut server) =
        serve_notifying(root.path(), path.as_os_str(), &rx, Duration::from_secs(3));
    assert_eq!(got, None, "a refused start said it was ready");
    assert_eq!(server.0.wait().unwrap().code(), Some(3));
}

#[test]
fn a_niced_caller_can_still_ask_for_a_nonce() {
    // Found under real sudo (circus VM run): at nice 19, resetting the
    // client's own nice to 0 is EACCES, and the client verbs failed.
    use std::os::unix::process::CommandExt as _;
    let h = Host::new();
    let mut cmd = Command::new(HOGTIE);
    cmd.arg("nonce").env("HOGTIE_TEST_ROOT", h.root.path());
    // SAFETY: setpriority in the child before exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpriority(libc::PRIO_PROCESS, 0, 19) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
}

/// `hogtie exec` with `pre` run in the child before exec, killed after 10 s.
fn exec_with(h: &Host, args: &[&str], pre: fn() -> std::io::Result<()>) -> Output {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = Command::new(HOGTIE);
    cmd.arg("exec")
        .args(args)
        .env("HOGTIE_TEST_ROOT", h.root.path())
        .env("SUDO_UID", Host::uid())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // SAFETY: `pre` makes only async-signal-safe calls.
    unsafe { cmd.pre_exec(pre) };
    let mut child = cmd.spawn().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("hogtie exec did not finish in 10 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

#[test]
fn a_small_open_file_limit_cannot_make_hogtie_fail() {
    // R1: the caller lowers RLIMIT_NOFILE (soft) so hogtie would run out
    // of descriptors running ssh-keygen; hogtie resets its own limits first.
    let h = Host::new();
    let cert = h.kit.grant("a", &["say"], "+1h", &[]);
    let r = h.respond(&cert, &["say", "hello"]);
    let out = exec_with(&h, &[&r, "say", "hello"], || {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit/setrlimit on this process.
        unsafe {
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
            lim.rlim_cur = 5;
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
        Ok(())
    });
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(out.stdout, b"hello\n");
}

#[test]
fn a_flood_of_hogtie_errors_is_budgeted_too() {
    // R1: an `error` a caller can cause (here: the nonce store open to
    // everyone) counts against the budget like a refusal.
    use std::os::unix::fs::PermissionsExt as _;
    let h = Host::new();
    let nonces = h.root.path().join("run/nonces");
    std::fs::set_permissions(&nonces, std::fs::Permissions::from_mode(0o777)).unwrap();
    let word = format!("v1.{}.AAAA", "a".repeat(64));
    for i in 0..30 {
        let out = h.sudo_exec(&word, &["say", "hello"]);
        // 21 errors are logged (20, and the one that says so); past that the
        // account gets the fixed over-budget answer.
        let want = if i < 21 { 3 } else { 1 };
        assert_eq!(out.status.code(), Some(want), "{i}: {}", stderr(&out));
    }
    std::fs::set_permissions(&nonces, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(h.audit().len(), 21);
}

#[test]
fn over_the_budget_every_request_gets_one_answer_and_is_not_evaluated() {
    // R3: no oracle past the budget: a well-formed, granted request gets
    // the same refusal as garbage, and its nonce is not spent.
    let h = Host::new();
    for _ in 0..21 {
        h.sudo_exec("garbage", &["say", "hello"]);
    }
    let cert = h.kit.grant("a", &["say"], "+1h", &[]);
    let r = h.respond(&cert, &["say", "hello"]);
    let good = h.sudo_exec(&r, &["say", "hello"]);
    let probe = h.sudo_exec(&r, &["no-such-action"]);
    assert_eq!(good.status.code(), Some(1));
    assert_eq!(stderr(&good), stderr(&probe));
    assert!(
        stderr(&good).contains("over the refusal budget"),
        "{}",
        stderr(&good)
    );
}

#[test]
fn a_held_lock_on_the_audit_log_does_not_stop_exec() {
    // R2: a stopped holder of a lock must not block everyone: exec takes
    // no lock it could wait on forever.
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;
    let h = Host::new();
    std::fs::create_dir_all(h.root.path().join("log")).unwrap();
    std::fs::set_permissions(
        h.root.path().join("log"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(h.root.path().join("log/audit.log"))
        .unwrap();
    // SAFETY: flock on a descriptor this test owns.
    assert_eq!(unsafe { libc::flock(log.as_raw_fd(), libc::LOCK_EX) }, 0);
    let budget = h.root.path().join("run/refusals");
    std::fs::create_dir_all(&budget).unwrap();
    let held = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(budget.join(Host::uid()))
        .unwrap();
    // SAFETY: as above.
    assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX) }, 0);
    let out = exec_with(&h, &["garbage", "say"], || Ok(()));
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    // F1: a budget that cannot be read is over budget (fail closed): the
    // request is not evaluated and nothing is logged in full.
    assert!(
        stderr(&out).contains("over the refusal budget"),
        "{}",
        stderr(&out)
    );
    drop((log, held));
}

#[test]
fn a_symlinked_audit_log_is_not_followed() {
    // R2 leftover: the log is opened O_NOFOLLOW.
    use std::os::unix::fs::PermissionsExt as _;
    let h = Host::new();
    let log_dir = h.root.path().join("log");
    std::fs::create_dir_all(&log_dir).unwrap();
    std::fs::set_permissions(&log_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let elsewhere = h.root.path().join("elsewhere.log");
    std::os::unix::fs::symlink(&elsewhere, log_dir.join("audit.log")).unwrap();
    let out = h.sudo_exec("garbage", &["say"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(!elsewhere.exists(), "the symlink was followed");
}

#[test]
fn an_empty_or_garbled_budget_file_is_over_budget_for_a_window() {
    // F2: a budget file cut to nothing (a kill mid-save) must not read as a
    // fresh window.
    let h = Host::new();
    let budget = h.root.path().join("run/refusals");
    std::fs::write(budget.join(Host::uid()), "").unwrap();
    let out = h.sudo_exec("garbage", &["say"]);
    assert!(
        stderr(&out).contains("over the refusal budget"),
        "{}",
        stderr(&out)
    );
    std::fs::write(budget.join(Host::uid()), "12 x\n").unwrap();
    let out = h.sudo_exec("garbage", &["say"]);
    assert!(
        stderr(&out).contains("over the refusal budget"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_idle_socket_still_writes_summaries() {
    // F4: the sweep is periodic, not only when a connection comes in.
    // (The binary sweeps every 30 s; this test drives serve_every with a
    // short interval, through the library.)
    let h = Host::new();
    let budget = h.root.path().join("run/refusals");
    // A closed window (started at boot second 0) holding 7 unlogged.
    std::fs::write(budget.join("4242"), hogtie::audit::budget_record(0, 21, 7)).unwrap();
    let log = h.root.path().join("log/audit.log");
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while std::time::Instant::now() < deadline {
        if std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("7 refusals")
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("no summary from an idle socket");
}

#[test]
fn a_small_file_size_limit_does_not_cut_the_audit_line() {
    // The caller lowers RLIMIT_FSIZE (soft) below what the line needs:
    // hogtie must not die of SIGXFSZ or write half a line. (sudo's own
    // handling of limits is not reproduced here: this runs hogtie directly.)
    use std::os::unix::process::CommandExt as _;
    let h = Host::new();
    let cert = h.kit.grant("a", &["say"], "+1h", &[]);
    let r = h.respond(&cert, &["say", "hello"]);
    let mut cmd = Command::new(HOGTIE);
    cmd.args(["exec", &r, "say", "hello"])
        .env("HOGTIE_TEST_ROOT", h.root.path())
        .env("SUDO_UID", Host::uid());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::getrlimit(libc::RLIMIT_FSIZE, &mut lim);
            lim.rlim_cur = 64;
            libc::setrlimit(libc::RLIMIT_FSIZE, &lim);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{} {:?}",
        stderr(&out),
        out.status
    );
    let text = std::fs::read_to_string(h.root.path().join("log/audit.log")).unwrap();
    assert!(text.ends_with('\n'), "a partial line: {text:?}");
    assert_eq!(text.lines().count(), 1);
}

#[test]
fn a_hard_file_size_limit_refuses_without_a_partial_line() {
    // The caller lowers the HARD limit too, which hogtie (not root here)
    // cannot raise: the write fails part way, the partial line is cut
    // back off, and nothing runs.
    use std::os::unix::process::CommandExt as _;
    let h = Host::new();
    let cert = h.kit.grant("a", &["say"], "+1h", &[]);
    let r = h.respond(&cert, &["say", "hello"]);
    let mut cmd = Command::new(HOGTIE);
    cmd.args(["exec", &r, "say", "hello"])
        .env("HOGTIE_TEST_ROOT", h.root.path())
        .env("SUDO_UID", Host::uid());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            let lim = libc::rlimit {
                rlim_cur: 64,
                rlim_max: 64,
            };
            libc::setrlimit(libc::RLIMIT_FSIZE, &lim);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "{} {:?}",
        stderr(&out),
        out.status
    );
    assert!(out.stdout.is_empty(), "the action ran");
    let text = std::fs::read_to_string(h.root.path().join("log/audit.log")).unwrap_or_default();
    assert_eq!(text, "", "a partial line was left");
}

#[test]
fn the_nonce_is_issued_and_claimed_on_the_boot_clock() {
    let h = Host::new();
    let cert = h.kit.grant("a", &["say"], "+1h", &[]);
    let out = h.sudo_exec(&h.respond(&cert, &["say", "hello"]), &["say", "hello"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let line = &h.audit()[0];
    let issued: u64 = line
        .split("\"issued\":")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no issued time: {line}"));
    assert!(
        issued <= hogtie::util::boot_now().unwrap(),
        "issued {issued} is not a boot-clock time"
    );
}

#[test]
fn the_action_does_not_inherit_the_callers_process_state() {
    use std::os::unix::process::CommandExt as _;
    let h = Host::new();
    let cert = h.kit.grant("a", &["state"], "+1h", &[]);
    let r = h.respond(&cert, &["state"]);
    let mut cmd = Command::new(HOGTIE);
    cmd.args(["exec", &r, "state"])
        .env("HOGTIE_TEST_ROOT", h.root.path())
        .env("SUDO_UID", Host::uid());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(0o077);
            let mut lim = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
            lim.rlim_cur = 64;
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGUSR1);
            libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
            libc::dup2(2, 9); // a descriptor without close-on-exec
            let mut one: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(0, &mut one);
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &one);
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "0022", "umask: {text}");
    // The declared default (soft 1024), or the test's own hard limit when
    // that is lower and the test cannot raise it.
    let mut own = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit.
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut own) };
    assert_eq!(
        lines[1],
        own.rlim_max.min(1024).to_string(),
        "the open-file limit: {text}"
    );
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if cpus > 1 {
        let allowed = lines
            .iter()
            .find(|l| l.starts_with("Cpus_allowed_list:"))
            .unwrap_or_else(|| panic!("{text}"));
        assert_ne!(
            *allowed, "Cpus_allowed_list: 0",
            "the CPU affinity was inherited: {text}"
        );
    }
    assert!(
        !text.contains("/proc/self/fd/9"),
        "fd 9 was inherited: {text}"
    );
    // The shell may ignore signals of its own (bash ignores SIGQUIT here):
    // check the ones the caller set.
    let mask = |key: &str| {
        let line = lines
            .iter()
            .find(|l| l.starts_with(key))
            .unwrap_or_else(|| panic!("{key}: {text}"));
        u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap()
    };
    let bit = |sig: i32| 1u64 << (sig - 1);
    let ign = mask("SigIgn:");
    assert_eq!(
        ign & (bit(libc::SIGINT) | bit(libc::SIGTERM)),
        0,
        "an ignored signal was inherited: {text}"
    );
    assert_eq!(
        mask("SigBlk:") & bit(libc::SIGUSR1),
        0,
        "a blocked signal was inherited: {text}"
    );
}

#[test]
fn a_failed_exec_is_audited_as_failed_and_exits_3() {
    let h = Host::new();
    let cert = h.kit.grant("a", &["broken"], "+1h", &[]);
    let out = h.sudo_exec(&h.respond(&cert, &["broken"]), &["broken"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    let log = h.audit();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log[0].contains("\"outcome\":\"started\""), "{}", log[0]);
    assert!(log[1].contains("\"outcome\":\"exec-failed\""), "{}", log[1]);
}

#[test]
fn an_audit_log_that_cannot_be_written_refuses_and_runs_nothing() {
    let h = Host::new();
    // The log directory's place is taken by a file: no audit line can land.
    // (The socket's first sweep made the directory: replace it.)
    let _ = std::fs::remove_dir_all(h.root.path().join("log"));
    std::fs::write(h.root.path().join("log"), "").unwrap();
    let cert = h.kit.grant("a", &["say"], "+1h", &[]);
    let out = h.sudo_exec(&h.respond(&cert, &["say", "hello"]), &["say", "hello"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(out.stdout.is_empty(), "the action ran: {:?}", out.stdout);
    assert!(stderr(&out).contains("audit log"), "{}", stderr(&out));
}

#[test]
fn a_missing_configuration_is_hogtie_own_failure_exit_3() {
    let h = Host::new();
    let cert = h.kit.grant("a", &["say"], "+1h", &[]);
    let r = h.respond(&cert, &["say", "hello"]);
    std::fs::remove_file(h.root.path().join("etc/hogtie.toml")).unwrap();
    let out = h.sudo_exec(&r, &["say", "hello"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(h.audit()[0].contains("\"outcome\":\"error\""));
}

#[test]
fn usage_errors_exit_2() {
    let h = Host::new();
    for args in [
        &[][..],
        &["exec"][..],
        &["exec", "r"][..],
        &["bogus"][..],
        &["message", "h1", "zz", "a"][..],
    ] {
        assert_eq!(h.hogtie(args).status.code(), Some(2), "{args:?}");
    }
}
