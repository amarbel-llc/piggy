//! The hogtie binary end to end, built with the `test-harness` feature (its
//! paths under HOGTIE_TEST_ROOT, the test's own uid standing in for root):
//! the socket hands out a nonce, the caller signs with stock ssh-keygen and
//! a software CA's grant, `hogtie exec` runs the action with nothing but
//! the declared environment, and every use lands in the audit log.
#![cfg(target_os = "linux")]

use hogtie::testkit::{Kit, on_path, write_trusted};
use hogtie::util::PrivateDir;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::time::Duration;

const HOGTIE: &str = env!("CARGO_BIN_EXE_hogtie");

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
            "ssh_keygen = \"{}\"\nca_keys = [\"{}\"]\nmax_grant_seconds = 86400\n\
             [action.say]\nprogram = \"{}\"\nargv = [\"{{word}}\"]\n\
             param = [{{ name = \"word\", kind = \"choice\", values = [\"hello\"] }}]\n\
             [action.show-env]\nprogram = \"{}\"\nenv = {{ LANG = \"C\" }}\n\
             [action.where]\nprogram = \"{}\"\n\
             [action.broken]\nprogram = \"{}\"\n",
            kit.ssh_keygen.display(),
            kit.ca_line(),
            on_path("echo"),
            on_path("env"),
            on_path("pwd"),
            not_exec.display(),
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
        let mut args = vec!["message", nonce.as_str()];
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
    let cert = h.kit.cert("agent-7", &["say"], "+1h", &[]);
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
    let cert = h.kit.cert("a", &["show-env", "where"], "+1h", &[]);
    let out = h.sudo_exec(&h.respond(&cert, &["show-env"]), &["show-env"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "LANG=C\n");
    let out = h.sudo_exec(&h.respond(&cert, &["where"]), &["where"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "/\n");
}

#[test]
fn an_expired_grant_is_refused_and_audited() {
    let h = Host::new();
    let cert = h.kit.cert("old", &["say"], "20200101:20200102", &[]);
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
    let out = h.hogtie(&["exec", "v1.x.y", "say", "hello"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("SUDO_UID"), "{}", stderr(&out));
    assert!(h.audit()[0].contains("SUDO_UID is not set"));
}

#[test]
fn a_failed_exec_is_audited_as_failed_and_exits_3() {
    let h = Host::new();
    let cert = h.kit.cert("a", &["broken"], "+1h", &[]);
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
    let cert = h.kit.cert("a", &["say"], "+1h", &[]);
    let out = h.sudo_exec(&h.respond(&cert, &["say", "hello"]), &["say", "hello"]);
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(out.stdout.is_empty(), "the action ran: {:?}", out.stdout);
    assert!(stderr(&out).contains("audit log"), "{}", stderr(&out));
}

#[test]
fn a_missing_configuration_is_hogtie_own_failure_exit_3() {
    let h = Host::new();
    let cert = h.kit.cert("a", &["say"], "+1h", &[]);
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
        &["message", "zz", "a"][..],
    ] {
        assert_eq!(h.hogtie(args).status.code(), Some(2), "{args:?}");
    }
}
