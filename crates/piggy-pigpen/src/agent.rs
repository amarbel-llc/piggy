//! A pure-std [`EcdhOracle`] backed by piggy-agent (feature `agent`).
//!
//! Opens a sealed pigpen document's P-256 recipients through the agent's
//! card ECDH extension ([`crate::ecdh_ext`]) with nothing but `std` and
//! `p256`: no tokio, no OpenSSL, no `piggy-box`. Each request is one
//! `SSH_AGENTC_EXTENSION` on a fresh blocking `UnixStream`; the wire
//! layout is byte-identical to piggy-box's `encode_ecdh_request` and to
//! what `piggy agent`'s `handle_ecdh` decodes:
//!
//! ```text
//! request details = string( string(card_blob) ‖ string(partner_blob) ‖ u32(0) )
//! reply           = byte 29 ‖ string(echoed name) ‖ string(32-byte shared X)
//! ```
//!
//! where each blob is `string("ecdsa-sha2-nistp256") ‖ string("nistp256") ‖
//! string(uncompressed point)`. The canonical name is asked first; an
//! `SSH_AGENT_FAILURE` under it is retried once under the legacy name
//! (piggy#335), and any other failure is reported at once.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use piggy_markl::{FormatId, Id};
use zeroize::Zeroize;

use crate::ecdh_ext::{CANONICAL, LEGACY, NAMES};
use crate::{EcdhOracle, Error, Result};

const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_EXTENSION: u8 = 27;
const SSH_AGENT_EXTENSION_RESPONSE: u8 = 29;

/// The largest agent reply read; anything bigger is not an ECDH answer.
const MAX_REPLY_LEN: usize = 1 << 20;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The agent socket from the environment: the first non-empty of
/// `PIGGY_AUTH_SOCK`, `SSH_AUTH_SOCK`, `PIVY_AUTH_SOCK` (the order Go's
/// `agent.ResolveAuthSock` uses).
pub fn resolve_auth_sock() -> Option<PathBuf> {
    ["PIGGY_AUTH_SOCK", "SSH_AUTH_SOCK", "PIVY_AUTH_SOCK"]
        .iter()
        .find_map(|var| std::env::var_os(var).filter(|v| !v.is_empty()))
        .map(PathBuf::from)
}

/// An [`EcdhOracle`] that asks the piggy-agent at `socket` to run the
/// slot's ECDH on the card.
pub struct AgentEcdhOracle {
    socket: PathBuf,
    timeout: Duration,
}

/// How the agent answered one request.
enum Answer {
    Secret([u8; 32]),
    Refused,
}

impl AgentEcdhOracle {
    /// An oracle for the agent listening on `socket`, with a 30 s read and
    /// write timeout (a PIN prompt or a touch can take a while).
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        AgentEcdhOracle {
            socket: socket.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Replace the per-request read and write timeout.
    pub fn with_timeout(self, timeout: Duration) -> Self {
        AgentEcdhOracle { timeout, ..self }
    }

    fn oracle_error(&self, what: impl std::fmt::Display) -> Error {
        Error::Oracle(format!("the agent at {}: {what}", self.socket.display()))
    }

    /// Send one extension request under `name` on a fresh connection.
    fn ask(&self, name: &str, details: &[u8]) -> Result<Answer> {
        let mut message = vec![SSH_AGENTC_EXTENSION];
        put_string(&mut message, name.as_bytes());
        message.extend_from_slice(details);
        let mut framed = Vec::with_capacity(4 + message.len());
        put_string(&mut framed, &message);

        let mut stream = UnixStream::connect(&self.socket)
            .map_err(|e| self.oracle_error(format!("connect: {e}")))?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|e| self.oracle_error(format!("set timeout: {e}")))?;
        stream
            .write_all(&framed)
            .map_err(|e| self.oracle_error(format!("write {name} request: {e}")))?;

        let mut len = [0u8; 4];
        stream
            .read_exact(&mut len)
            .map_err(|e| self.oracle_error(format!("read {name} reply length: {e}")))?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_REPLY_LEN {
            return Err(self.oracle_error(format!("{name} reply of {len} bytes is too large")));
        }
        let mut reply = vec![0u8; len];
        stream
            .read_exact(&mut reply)
            .map_err(|e| self.oracle_error(format!("read {name} reply: {e}")))?;
        let answer = self.parse_reply(name, &reply);
        reply.zeroize();
        answer
    }

    fn parse_reply(&self, name: &str, reply: &[u8]) -> Result<Answer> {
        let truncated = || self.oracle_error(format!("truncated {name} reply"));
        match reply.first() {
            Some(&SSH_AGENT_FAILURE) => Ok(Answer::Refused),
            Some(&SSH_AGENT_EXTENSION_RESPONSE) => {
                let (echoed, rest) = take_string(&reply[1..]).ok_or_else(truncated)?;
                // A proxy may echo its upstream's name, so either is fine.
                if !NAMES.iter().any(|n| n.as_bytes() == echoed) {
                    return Err(self.oracle_error(format!(
                        "{name} reply names extension {:?}",
                        String::from_utf8_lossy(echoed)
                    )));
                }
                let (secret, rest) = take_string(rest).ok_or_else(truncated)?;
                if !rest.is_empty() {
                    return Err(self.oracle_error(format!(
                        "{} trailing bytes after the {name} shared secret",
                        rest.len()
                    )));
                }
                let secret: [u8; 32] = secret.try_into().map_err(|_| {
                    self.oracle_error(format!(
                        "{name} shared secret is {} bytes, not 32",
                        secret.len()
                    ))
                })?;
                Ok(Answer::Secret(secret))
            }
            Some(other) => {
                Err(self.oracle_error(format!("unexpected reply type {other} to {name}")))
            }
            None => Err(truncated()),
        }
    }
}

impl EcdhOracle for AgentEcdhOracle {
    fn ecdh(&self, self_recipient: &Id, partner_epk: &[u8]) -> Result<[u8; 32]> {
        if self_recipient.format() != FormatId::PivyEcdhP256Pub {
            return Err(Error::UnsupportedFormat(format!(
                "{:?} is not a card ECDH recipient",
                self_recipient.format()
            )));
        }
        let card_blob = p256_ssh_blob(self_recipient.data(), "recipient key")?;
        let partner_blob = p256_ssh_blob(partner_epk, "ephemeral key")?;

        let mut inner = Vec::new();
        put_string(&mut inner, &card_blob);
        put_string(&mut inner, &partner_blob);
        put_u32(&mut inner, 0); // flags
        let mut details = Vec::new();
        put_string(&mut details, &inner);

        for name in NAMES {
            match self.ask(name, &details)? {
                Answer::Secret(secret) => return Ok(secret),
                Answer::Refused => continue,
            }
        }
        Err(Error::Oracle(format!(
            "the agent at {} refused {CANONICAL} and {LEGACY}: it does not hold the key, the card was not unlocked, or it does not serve the extension",
            self.socket.display()
        )))
    }
}

/// The OpenSSH `ecdsa-sha2-nistp256` key blob for a SEC1 P-256 point,
/// carrying the uncompressed encoding the agent matches keys by.
fn p256_ssh_blob(sec1: &[u8], what: &str) -> Result<Vec<u8>> {
    let key = p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|e| Error::Oracle(format!("{what} is not a P-256 point: {e}")))?;
    let mut blob = Vec::new();
    put_string(&mut blob, b"ecdsa-sha2-nistp256");
    put_string(&mut blob, b"nistp256");
    put_string(&mut blob, key.to_encoded_point(false).as_bytes());
    Ok(blob)
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}

/// Split one SSH string off the front of `buf`: `(contents, rest)`.
fn take_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?) as usize;
    let rest = &buf[4..];
    (rest.len() >= len).then(|| rest.split_at(len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdh_ext::{CANONICAL, LEGACY, NAMES};
    use crate::{Document, EcdhOracle, Error, recipient_id};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use piggy_markl::FormatId;
    use rand_core::OsRng;
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    #[derive(Clone, Copy)]
    enum Reply {
        Secret,
        Garbage,
        ShortSecret,
    }

    /// What the stub agent serves.
    struct StubConfig {
        accept: Vec<&'static str>,
        echo: Option<&'static str>,
        reply: Reply,
    }

    impl StubConfig {
        fn serving(accept: &[&'static str]) -> Self {
            StubConfig {
                accept: accept.to_vec(),
                echo: None,
                reply: Reply::Secret,
            }
        }
    }

    /// An ssh-agent stand-in on a Unix socket holding a software P-256 key
    /// and answering the card ECDH extension with the real shared X.
    struct StubAgent {
        path: PathBuf,
        secret: p256::SecretKey,
        asked: Arc<Mutex<Vec<String>>>,
        connections: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl StubAgent {
        fn start(tag: &str, config: StubConfig) -> Self {
            let path = PathBuf::from("/tmp").join(format!("pgpo{}-{tag}.sock", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).expect("bind stub agent");
            let secret = p256::SecretKey::random(&mut OsRng);
            let asked = Arc::new(Mutex::new(Vec::new()));
            let connections = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let thread = {
                let secret = secret.clone();
                let asked = asked.clone();
                let connections = connections.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        let Ok(stream) = stream else { break };
                        connections.fetch_add(1, Ordering::SeqCst);
                        serve_one(stream, &secret, &config, &asked);
                    }
                })
            };
            StubAgent {
                path,
                secret,
                asked,
                connections,
                stop,
                thread: Some(thread),
            }
        }

        fn recipient(&self) -> piggy_markl::Id {
            let point = self.secret.public_key().to_encoded_point(true);
            recipient_id(FormatId::PivyEcdhP256Pub, point.as_bytes().to_vec()).unwrap()
        }

        fn oracle(&self) -> AgentEcdhOracle {
            AgentEcdhOracle::new(&self.path).with_timeout(std::time::Duration::from_secs(5))
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Drop for StubAgent {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = UnixStream::connect(&self.path); // wake the accept loop
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn serve_one(
        mut stream: UnixStream,
        secret: &p256::SecretKey,
        config: &StubConfig,
        asked: &Mutex<Vec<String>>,
    ) {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(body[0], 27, "SSH_AGENTC_EXTENSION");
        let (name, details) = take_string(&body[1..]).unwrap();
        let name = String::from_utf8(name.to_vec()).unwrap();
        asked.lock().unwrap().push(name.clone());

        let reply = if !config.accept.contains(&name.as_str()) {
            vec![5]
        } else {
            match config.reply {
                Reply::Garbage => vec![99],
                Reply::Secret | Reply::ShortSecret => {
                    let (inner, rest) = take_string(details).unwrap();
                    assert!(rest.is_empty());
                    let (card_blob, rest) = take_string(inner).unwrap();
                    let (partner_blob, rest) = take_string(rest).unwrap();
                    assert_eq!(rest, &[0, 0, 0, 0], "flags");
                    assert_eq!(card_blob, ssh_blob(&secret.public_key()).as_slice());
                    let (_, rest) = take_string(partner_blob).unwrap();
                    let (_, rest) = take_string(rest).unwrap();
                    let (point, _) = take_string(rest).unwrap();
                    let partner = p256::PublicKey::from_sec1_bytes(point).unwrap();
                    let shared =
                        p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), partner.as_affine());
                    let mut x = shared.raw_secret_bytes().to_vec();
                    if let Reply::ShortSecret = config.reply {
                        x.pop();
                    }
                    let mut r = vec![29];
                    put_string(&mut r, config.echo.unwrap_or(&name).as_bytes());
                    put_string(&mut r, &x);
                    r
                }
            }
        };
        let mut framed = Vec::new();
        put_string(&mut framed, &reply);
        let _ = stream.write_all(&framed);
    }

    fn ssh_blob(key: &p256::PublicKey) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, b"ecdsa-sha2-nistp256");
        put_string(&mut b, b"nistp256");
        put_string(&mut b, key.to_encoded_point(false).as_bytes());
        b
    }

    /// A fresh partner key: its compressed point and the expected shared X.
    fn partner_for(stub: &StubAgent) -> (Vec<u8>, [u8; 32]) {
        let partner = p256::SecretKey::random(&mut OsRng);
        let shared = p256::ecdh::diffie_hellman(
            partner.to_nonzero_scalar(),
            stub.secret.public_key().as_affine(),
        );
        let mut expected = [0u8; 32];
        expected.copy_from_slice(shared.raw_secret_bytes());
        let epk = partner
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        (epk, expected)
    }

    #[test]
    fn both_names_served_asks_canonical_only() {
        let stub = StubAgent::start("both", StubConfig::serving(&NAMES));
        let (epk, expected) = partner_for(&stub);
        let got = stub.oracle().ecdh(&stub.recipient(), &epk).unwrap();
        assert_eq!(got, expected);
        assert_eq!(stub.asked(), vec![CANONICAL.to_string()]);
    }

    #[test]
    fn canonical_refused_falls_back_to_legacy() {
        let stub = StubAgent::start("legacy", StubConfig::serving(&[LEGACY]));
        let (epk, expected) = partner_for(&stub);
        let got = stub.oracle().ecdh(&stub.recipient(), &epk).unwrap();
        assert_eq!(got, expected);
        assert_eq!(
            stub.asked(),
            vec![CANONICAL.to_string(), LEGACY.to_string()]
        );
    }

    #[test]
    fn proxy_echoing_the_legacy_name_is_accepted() {
        let config = StubConfig {
            echo: Some(LEGACY),
            ..StubConfig::serving(&NAMES)
        };
        let stub = StubAgent::start("echo", config);
        let (epk, expected) = partner_for(&stub);
        let got = stub.oracle().ecdh(&stub.recipient(), &epk).unwrap();
        assert_eq!(got, expected);
        assert_eq!(stub.asked(), vec![CANONICAL.to_string()]);
    }

    #[test]
    fn both_names_refused_is_an_oracle_error_naming_both() {
        let stub = StubAgent::start("none", StubConfig::serving(&[]));
        let (epk, _) = partner_for(&stub);
        let err = stub.oracle().ecdh(&stub.recipient(), &epk).unwrap_err();
        let Error::Oracle(msg) = err else {
            panic!("expected Error::Oracle, got {err:?}")
        };
        assert!(msg.contains(CANONICAL) && msg.contains(LEGACY), "{msg}");
        assert_eq!(stub.asked().len(), 2);
    }

    #[test]
    fn garbage_reply_is_an_oracle_error_without_retry() {
        let config = StubConfig {
            reply: Reply::Garbage,
            ..StubConfig::serving(&NAMES)
        };
        let stub = StubAgent::start("garbage", config);
        let (epk, _) = partner_for(&stub);
        let err = stub.oracle().ecdh(&stub.recipient(), &epk).unwrap_err();
        assert!(matches!(err, Error::Oracle(_)), "{err:?}");
        assert_eq!(stub.asked(), vec![CANONICAL.to_string()]);
    }

    #[test]
    fn short_secret_is_an_error() {
        let config = StubConfig {
            reply: Reply::ShortSecret,
            ..StubConfig::serving(&NAMES)
        };
        let stub = StubAgent::start("short", config);
        let (epk, _) = partner_for(&stub);
        let err = stub.oracle().ecdh(&stub.recipient(), &epk).unwrap_err();
        assert!(matches!(err, Error::Oracle(_)), "{err:?}");
    }

    #[test]
    fn x25519_recipient_is_unsupported_without_connecting() {
        let stub = StubAgent::start("x25519", StubConfig::serving(&NAMES));
        let id = recipient_id(FormatId::AgeX25519Pub, vec![7u8; 32]).unwrap();
        let (epk, _) = partner_for(&stub);
        let err = stub.oracle().ecdh(&id, &epk).unwrap_err();
        assert!(matches!(err, Error::UnsupportedFormat(_)), "{err:?}");
        assert_eq!(stub.connections.load(Ordering::SeqCst), 0);
    }

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolve_auth_sock_precedence() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let vars = ["PIGGY_AUTH_SOCK", "SSH_AUTH_SOCK", "PIVY_AUTH_SOCK"];
        let saved: Vec<_> = vars.iter().map(std::env::var_os).collect();
        let set = |values: [&str; 3]| {
            for (var, value) in vars.iter().zip(values) {
                std::env::set_var(var, value);
            }
        };

        set(["/p", "/s", "/v"]);
        assert_eq!(resolve_auth_sock(), Some(PathBuf::from("/p")));
        set(["", "/s", "/v"]);
        assert_eq!(resolve_auth_sock(), Some(PathBuf::from("/s")));
        set(["", "", "/v"]);
        assert_eq!(resolve_auth_sock(), Some(PathBuf::from("/v")));
        set(["", "", ""]);
        assert_eq!(resolve_auth_sock(), None);
        for var in vars {
            std::env::remove_var(var);
        }
        assert_eq!(resolve_auth_sock(), None);

        for (var, value) in vars.iter().zip(saved) {
            match value {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }
    }

    #[test]
    fn sealed_document_opens_through_the_stub_agent() {
        let stub = StubAgent::start("e2e", StubConfig::serving(&NAMES));
        let doc = Document::seal(b"hello", &[stub.recipient()]).unwrap();
        let oracle = stub.oracle();
        let plaintext = doc.open(Some(&oracle), &[]).unwrap();
        assert_eq!(plaintext, b"hello");
    }
}
