//! The nonce store: a root-only directory in memory (`/run/hogtie/nonces`),
//! one subdirectory per account, one file per outstanding nonce, named by
//! the nonce in hex and holding who asked and when it expires. A nonce is
//! stored, not signed: `hogtie exec` claims it by renaming it away (atomic:
//! of two claims of one nonce, one wins) and deletes it, whatever happens
//! next, so it is used at most once. It looks only in the directory of the
//! account sudo names, so a nonce asked by one account is unknown to every
//! other.

use crate::message::Nonce;
use crate::response::nonce_hex;
use crate::util::{random_bytes, write_new};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

/// How long a nonce lives.
pub const TTL_SECONDS: u64 = 30;
/// Outstanding nonces per account: a flood locks out only the flooder.
pub const CAP_PER_ACCOUNT: usize = 32;

/// Who asked for a nonce, as the socket read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asker {
    pub uid: u32,
    pub pid: i32,
    /// The cgroup v2 path, when it could be read.
    pub cgroup: Option<String>,
}

impl Asker {
    /// The systemd unit: the cgroup's last `.service` or `.scope` component.
    pub fn unit(&self) -> Option<&str> {
        self.cgroup
            .as_deref()?
            .rsplit('/')
            .find(|c| c.ends_with(".service") || c.ends_with(".scope"))
    }
}

/// A claimed nonce's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub asker: Asker,
    pub issued: u64,
    pub expires: u64,
}

impl Entry {
    fn encode(&self) -> String {
        // A delegated cgroup's name is the caller's to choose: no control
        // character from it may reach the record (a newline would add a line).
        let cgroup: String = self
            .asker
            .cgroup
            .as_deref()
            .unwrap_or("")
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
        format!(
            "pid={}\ncgroup={}\nissued={}\nexpires={}\n",
            self.asker.pid, cgroup, self.issued, self.expires
        )
    }

    fn decode(uid: u32, text: &str) -> Option<Self> {
        let mut pid = None;
        let mut cgroup = None;
        let mut issued = None;
        let mut expires = None;
        for line in text.lines() {
            let (k, v) = line.split_once('=')?;
            let slot_was_empty = match k {
                "pid" => pid.replace(v.parse().ok()?).is_none(),
                "cgroup" => cgroup
                    .replace((!v.is_empty()).then(|| v.to_string()))
                    .is_none(),
                "issued" => issued.replace(v.parse().ok()?).is_none(),
                "expires" => expires.replace(v.parse().ok()?).is_none(),
                _ => return None,
            };
            if !slot_was_empty {
                return None;
            }
        }
        Some(Self {
            asker: Asker {
                uid,
                pid: pid?,
                cgroup: cgroup?,
            },
            issued: issued?,
            expires: expires?,
        })
    }
}

#[derive(Debug)]
pub enum IssueError {
    /// The account already holds [`CAP_PER_ACCOUNT`] unexpired nonces.
    Cap,
    Io(io::Error),
}

impl fmt::Display for IssueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IssueError::Cap => write!(
                f,
                "this account holds {CAP_PER_ACCOUNT} unused nonces; wait {TTL_SECONDS} s"
            ),
            IssueError::Io(e) => write!(f, "nonce store: {e}"),
        }
    }
}

#[derive(Debug)]
pub enum ClaimError {
    /// Never issued to this account, already used, or swept.
    Unknown,
    Expired(Entry),
    /// The file was claimed but could not be read back.
    Corrupt,
    Io(io::Error),
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClaimError::Unknown => {
                f.write_str("unknown nonce (never issued to this account, or already used)")
            }
            ClaimError::Expired(_) => f.write_str("nonce has expired"),
            ClaimError::Corrupt => f.write_str("nonce record is unreadable"),
            ClaimError::Io(e) => write!(f, "nonce store: {e}"),
        }
    }
}

pub struct NonceStore {
    dir: PathBuf,
}

fn is_nonce_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

impl NonceStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn account_dir(&self, uid: u32) -> PathBuf {
        self.dir.join(uid.to_string())
    }

    fn ensure_account_dir(&self, uid: u32) -> io::Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt as _;
        let d = self.account_dir(uid);
        match std::fs::DirBuilder::new().mode(0o700).create(&d) {
            Ok(()) => Ok(d),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(d),
            Err(e) => Err(e),
        }
    }

    /// Remove `dir`'s expired nonces, and claim files a crashed `exec` left
    /// (only once their nonce is a further TTL past expiry, so a claim in
    /// flight is never pulled from under its `exec`); return how many
    /// unexpired, unclaimed nonces remain.
    fn sweep_account(dir: &Path, uid: u32, now: u64) -> io::Result<usize> {
        let mut live = 0;
        for e in std::fs::read_dir(dir)? {
            let e = e?;
            let name = e.file_name();
            let name = name.to_string_lossy();
            let expires = || {
                std::fs::read_to_string(e.path())
                    .ok()
                    .and_then(|t| Entry::decode(uid, &t))
                    .map(|en| en.expires)
            };
            let (keep, counts) = match name.strip_prefix(".claim-") {
                Some(hex) if is_nonce_name(hex) => {
                    (expires().is_some_and(|x| now < x + TTL_SECONDS), false)
                }
                _ if is_nonce_name(&name) => {
                    let k = expires().is_some_and(|x| now < x);
                    (k, k)
                }
                _ => (false, false),
            };
            if counts {
                live += 1;
            }
            if !keep {
                let _ = std::fs::remove_file(e.path());
            }
        }
        Ok(live)
    }

    /// Sweep every account's expired nonces (the socket does it now and then).
    pub fn sweep(&self, now: u64) -> io::Result<()> {
        for e in std::fs::read_dir(&self.dir)? {
            let e = e?;
            if let Some(uid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                Self::sweep_account(&e.path(), uid, now)?;
            }
        }
        Ok(())
    }

    /// Issue a nonce to `asker`. Callers must not issue concurrently for one
    /// account (the socket serves one connection at a time).
    pub fn issue(&self, asker: &Asker, now: u64) -> Result<(Nonce, u64), IssueError> {
        let dir = self.ensure_account_dir(asker.uid).map_err(IssueError::Io)?;
        if Self::sweep_account(&dir, asker.uid, now).map_err(IssueError::Io)? >= CAP_PER_ACCOUNT {
            return Err(IssueError::Cap);
        }
        let nonce: Nonce = random_bytes().map_err(IssueError::Io)?;
        let entry = Entry {
            asker: asker.clone(),
            issued: now,
            expires: now + TTL_SECONDS,
        };
        write_new(&dir.join(nonce_hex(&nonce)), entry.encode().as_bytes())
            .map_err(IssueError::Io)?;
        Ok((nonce, entry.expires))
    }

    /// Claim `nonce` for account `uid`: it is gone from the store when this
    /// returns, whatever it returns.
    pub fn claim(&self, uid: u32, nonce: &Nonce, now: u64) -> Result<Entry, ClaimError> {
        let dir = self.account_dir(uid);
        let hex = nonce_hex(nonce);
        let claimed = dir.join(format!(".claim-{hex}"));
        match std::fs::rename(dir.join(&hex), &claimed) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(ClaimError::Unknown),
            Err(e) => return Err(ClaimError::Io(e)),
        }
        let text = std::fs::read_to_string(&claimed);
        std::fs::remove_file(&claimed).map_err(ClaimError::Io)?;
        let entry =
            Entry::decode(uid, &text.map_err(ClaimError::Io)?).ok_or(ClaimError::Corrupt)?;
        if now >= entry.expires {
            return Err(ClaimError::Expired(entry));
        }
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::PrivateDir;

    fn asker(uid: u32) -> Asker {
        Asker {
            uid,
            pid: 4242,
            cgroup: Some(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/agent.scope".into(),
            ),
        }
    }

    fn store() -> (PrivateDir, NonceStore) {
        let d = PrivateDir::new(&std::env::temp_dir(), "hogtie-nonce").unwrap();
        let s = NonceStore::new(d.path());
        (d, s)
    }

    #[test]
    fn a_nonce_is_claimed_once() {
        let (_d, s) = store();
        let (n, expires) = s.issue(&asker(1000), 100).unwrap();
        assert_eq!(expires, 130);
        let e = s.claim(1000, &n, 110).unwrap();
        assert_eq!(e.asker, asker(1000));
        assert_eq!(e.issued, 100);
        assert!(
            matches!(s.claim(1000, &n, 111), Err(ClaimError::Unknown)),
            "a replay is refused"
        );
    }

    #[test]
    fn a_nonce_asked_by_another_account_is_unknown_and_not_burnt() {
        let (_d, s) = store();
        let (n, _) = s.issue(&asker(1000), 100).unwrap();
        assert!(matches!(s.claim(1001, &n, 101), Err(ClaimError::Unknown)));
        assert!(s.claim(1000, &n, 101).is_ok(), "the owner can still use it");
    }

    #[test]
    fn an_expired_nonce_is_refused_and_burnt() {
        let (_d, s) = store();
        let (n, _) = s.issue(&asker(1000), 100).unwrap();
        assert!(matches!(
            s.claim(1000, &n, 130),
            Err(ClaimError::Expired(_))
        ));
        assert!(matches!(s.claim(1000, &n, 100), Err(ClaimError::Unknown)));
    }

    #[test]
    fn a_nonce_never_issued_is_unknown() {
        let (_d, s) = store();
        assert!(matches!(
            s.claim(1000, &[9; 32], 100),
            Err(ClaimError::Unknown)
        ));
    }

    #[test]
    fn the_cap_locks_out_only_the_flooder_and_lifts_on_expiry() {
        let (_d, s) = store();
        for _ in 0..CAP_PER_ACCOUNT {
            s.issue(&asker(1000), 100).unwrap();
        }
        assert!(matches!(s.issue(&asker(1000), 100), Err(IssueError::Cap)));
        assert!(
            s.issue(&asker(1001), 100).is_ok(),
            "another account is not locked out"
        );
        assert!(s.issue(&asker(1000), 130).is_ok(), "the flood expires");
    }

    #[test]
    fn using_a_nonce_frees_its_slot() {
        let (_d, s) = store();
        let mut last = None;
        for _ in 0..CAP_PER_ACCOUNT {
            last = Some(s.issue(&asker(1000), 100).unwrap().0);
        }
        s.claim(1000, &last.unwrap(), 101).unwrap();
        assert!(s.issue(&asker(1000), 101).is_ok());
    }

    #[test]
    fn sweep_removes_only_expired_nonces() {
        let (d, s) = store();
        let (old, _) = s.issue(&asker(1000), 100).unwrap();
        let (new, _) = s.issue(&asker(1000), 120).unwrap();
        s.sweep(135).unwrap();
        assert!(!d.path().join("1000").join(nonce_hex(&old)).exists());
        assert!(d.path().join("1000").join(nonce_hex(&new)).exists());
    }

    #[test]
    fn a_sweep_leaves_a_claim_in_flight_alone() {
        let (d, s) = store();
        let (n, _) = s.issue(&asker(1000), 100).unwrap();
        let dir = d.path().join("1000");
        let claim = dir.join(format!(".claim-{}", nonce_hex(&n)));
        std::fs::rename(dir.join(nonce_hex(&n)), &claim).unwrap();
        s.issue(&asker(1000), 110).unwrap();
        s.sweep(140).unwrap();
        assert!(claim.exists(), "a claim within a TTL of its expiry is kept");
        s.sweep(160).unwrap();
        assert!(!claim.exists(), "a crashed exec's claim is removed later");
    }

    #[test]
    fn the_unit_is_the_last_service_or_scope() {
        assert_eq!(asker(1).unit(), Some("agent.scope"));
        let a = Asker {
            cgroup: Some("/system.slice/hogtie.service".into()),
            ..asker(1)
        };
        assert_eq!(a.unit(), Some("hogtie.service"));
        assert_eq!(
            Asker {
                cgroup: None,
                ..asker(1)
            }
            .unit(),
            None
        );
        assert_eq!(
            Asker {
                cgroup: Some("/".into()),
                ..asker(1)
            }
            .unit(),
            None
        );
    }

    #[test]
    fn a_record_without_a_cgroup_round_trips() {
        let e = Entry {
            asker: Asker {
                cgroup: None,
                ..asker(7)
            },
            issued: 1,
            expires: 31,
        };
        assert_eq!(Entry::decode(7, &e.encode()), Some(e));
        assert_eq!(Entry::decode(7, "pid=1\nbogus=2\n"), None);
    }

    #[test]
    fn a_cgroup_name_cannot_add_a_line_to_the_record() {
        let a = Asker {
            cgroup: Some("/u/x\nexpires=99999999999.scope".into()),
            ..asker(7)
        };
        let e = Entry {
            asker: a,
            issued: 1,
            expires: 31,
        };
        let back = Entry::decode(7, &e.encode()).unwrap();
        assert_eq!(back.expires, 31);
        assert_eq!(
            back.asker.cgroup.as_deref(),
            Some("/u/x?expires=99999999999.scope")
        );
        assert_eq!(
            Entry::decode(7, "pid=1\ncgroup=\nissued=1\nexpires=2\nexpires=9\n"),
            None
        );
    }
}
