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
