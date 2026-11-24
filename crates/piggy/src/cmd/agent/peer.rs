//! Who is on the other end of an agent connection (FDR 0006 phase (d),
//! piggy#383 item 2): the peer's credentials and its cgroup, read once per
//! connection when it is accepted, so the holder can bind a minted key to
//! the scope that asked for it and refuse every other scope.
//!
//! The credentials come from `SO_PEERCRED` (tokio's `UnixStream::peer_cred`;
//! ssh-agent-lib 0.5 hands the accepted stream to `Agent::new_session`, see
//! `listener.rs`). The cgroup is read from `/proc/<pid>/cgroup` through a
//! directory descriptor on `/proc/<pid>` opened at that moment: once the
//! process the descriptor was opened on has exited, reads through it fail
//! rather than following a reused pid, so the read cannot be fooled by a
//! pid recycled after accept. The window between accept and that open is
//! what remains, and is recorded as a limitation in piggy-agent(1).
//!
//! Only cgroup v2 is read (`0::/path`); on a v1-only host the peer is
//! unknown and the holder refuses it.

use std::fmt;

/// An absolute cgroup v2 path, normalized: no trailing slash except for
/// the root `/`, no empty components.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CgroupPath(String);

impl CgroupPath {
    /// Parse an absolute path. `None` for a relative one, an empty one, or
    /// one with an empty component (`/a//b`).
    pub fn parse(path: &str) -> Option<Self> {
        let rest = path.strip_prefix('/')?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        if rest.is_empty() {
            return Some(Self("/".to_string()));
        }
        if rest.split('/').any(str::is_empty) {
            return None;
        }
        Some(Self(format!("/{rest}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this is the root cgroup `/`, which contains every process.
    pub fn is_root(&self) -> bool {
        self.0 == "/"
    }

    /// The path components, none for the root.
    fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/').filter(|c| !c.is_empty())
    }

    /// Whether `other` is this cgroup or one below it. Component-wise:
    /// `/a/b` contains `/a/b/c` and not `/a/bc`; the root contains all.
    pub fn contains(&self, other: &CgroupPath) -> bool {
        let mut mine = self.components();
        let mut theirs = other.components();
        loop {
            match (mine.next(), theirs.next()) {
                (None, _) => return true,
                (Some(a), Some(b)) if a == b => continue,
                _ => return false,
            }
        }
    }

    /// Where this cgroup's directory is under the cgroup2 mount.
    pub fn directory_under(&self, root: &std::path::Path) -> std::path::PathBuf {
        let mut dir = root.to_path_buf();
        for component in self.components() {
            dir.push(component);
        }
        dir
    }
}

impl fmt::Display for CgroupPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The cgroup v2 line of a `/proc/<pid>/cgroup` file: `0::/path`. A file
/// with no such line (cgroup v1 only) yields `None`.
pub fn parse_proc_cgroup(text: &str) -> Option<CgroupPath> {
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .and_then(CgroupPath::parse)
}

/// The process at the other end of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub pid: i32,
    pub cgroup: CgroupPath,
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pid {} uid {} in {}", self.pid, self.uid, self.cgroup)
    }
}

/// Why a peer could not be read; the holder answers `peer-unknown` with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerError {
    /// `SO_PEERCRED` failed, or carried no pid.
    NoCredentials(String),
    /// `/proc/<pid>` or its `cgroup` file could not be read.
    Proc(String),
    /// The cgroup file has no v2 line.
    NoCgroupV2,
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerError::NoCredentials(e) => write!(f, "no peer credentials on the connection: {e}"),
            PeerError::Proc(e) => write!(f, "cannot read the peer's cgroup: {e}"),
            PeerError::NoCgroupV2 => f.write_str("the peer's cgroup file has no cgroup v2 line"),
        }
    }
}

/// Read the peer of an accepted agent connection. Called from
/// `Agent::new_session`, synchronously, before the first request is read.
pub fn peer_of(stream: &tokio::net::UnixStream) -> Result<Peer, PeerError> {
    let cred = stream
        .peer_cred()
        .map_err(|e| PeerError::NoCredentials(e.to_string()))?;
    let pid = cred
        .pid()
        .ok_or_else(|| PeerError::NoCredentials("no pid".into()))?;
    let cgroup = cgroup_of_pid(pid)?;
    Ok(Peer {
        uid: cred.uid(),
        pid,
        cgroup,
    })
}

/// `/proc/<pid>/cgroup`, read through a descriptor on `/proc/<pid>` so the
/// read is of that process instance and no other.
#[cfg(target_os = "linux")]
pub fn cgroup_of_pid(pid: i32) -> Result<CgroupPath, PeerError> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let dir = std::fs::File::open(format!("/proc/{pid}"))
        .map_err(|e| PeerError::Proc(format!("/proc/{pid}: {e}")))?;
    // SAFETY: a plain openat on a valid directory descriptor with a
    // NUL-terminated path; the returned descriptor is owned by the File.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"cgroup".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Err(PeerError::Proc(format!("/proc/{pid}/cgroup: {e}")));
    }
    // SAFETY: `fd` is a freshly opened descriptor this process owns.
    let text = std::io::read_to_string(unsafe { std::fs::File::from_raw_fd(fd) })
        .map_err(|e| PeerError::Proc(format!("/proc/{pid}/cgroup: {e}")))?;
    parse_proc_cgroup(&text).ok_or(PeerError::NoCgroupV2)
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_of_pid(_pid: i32) -> Result<CgroupPath, PeerError> {
    Err(PeerError::Proc("cgroups exist on Linux only".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cg(s: &str) -> CgroupPath {
        CgroupPath::parse(s).unwrap()
    }

    #[test]
    fn paths_are_normalized_and_relative_ones_refused() {
        assert_eq!(cg("/").as_str(), "/");
        assert_eq!(cg("/a/b/").as_str(), "/a/b");
        assert_eq!(cg("/a/b").as_str(), "/a/b");
        assert!(CgroupPath::parse("a/b").is_none());
        assert!(CgroupPath::parse("").is_none());
        assert!(CgroupPath::parse("/a//b").is_none());
    }

    #[test]
    fn containment_is_by_component_not_by_string_prefix() {
        assert!(cg("/a/b").contains(&cg("/a/b")));
        assert!(cg("/a/b").contains(&cg("/a/b/c/d")));
        assert!(!cg("/a/b").contains(&cg("/a/bc")));
        assert!(!cg("/a/b").contains(&cg("/a")));
        assert!(!cg("/a/b/c").contains(&cg("/a/b")));
        assert!(cg("/").contains(&cg("/anything/at/all")));
        assert!(cg("/").contains(&cg("/")));
    }

    #[test]
    fn the_directory_is_the_path_under_the_mount() {
        let root = std::path::Path::new("/sys/fs/cgroup");
        assert_eq!(
            cg("/user.slice/x.scope").directory_under(root),
            std::path::PathBuf::from("/sys/fs/cgroup/user.slice/x.scope")
        );
        assert_eq!(cg("/").directory_under(root), root.to_path_buf());
    }

    #[test]
    fn the_v2_line_is_found_among_v1_lines() {
        let text = "12:memory:/user.slice\n1:name=systemd:/x\n0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(
            parse_proc_cgroup(text),
            Some(cg("/user.slice/user-1000.slice/session-2.scope"))
        );
        assert_eq!(parse_proc_cgroup("0::/\n"), Some(cg("/")));
        assert_eq!(parse_proc_cgroup("1:name=systemd:/x\n"), None);
        assert_eq!(parse_proc_cgroup(""), None);
    }

    /// The real read agrees with `/proc/self/cgroup` for this process.
    #[cfg(target_os = "linux")]
    #[test]
    fn our_own_cgroup_reads_through_the_pinned_descriptor() {
        let direct = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let Some(expected) = parse_proc_cgroup(&direct) else {
            eprintln!("skipped: no cgroup v2 line in /proc/self/cgroup");
            return;
        };
        let pid = std::process::id() as i32;
        assert_eq!(cgroup_of_pid(pid).unwrap(), expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_pid_that_does_not_exist_is_a_proc_error() {
        // pid_max is at most 2^22 on Linux; this one cannot be live.
        let err = cgroup_of_pid(i32::MAX).unwrap_err();
        assert!(matches!(err, PeerError::Proc(_)), "{err:?}");
    }

    /// The peer of a connected pair is this very process.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_peer_of_a_local_pair_is_this_process() {
        let (a, _b) = tokio::net::UnixStream::pair().unwrap();
        let peer = peer_of(&a).unwrap();
        assert_eq!(peer.pid, std::process::id() as i32);
        let direct = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        assert_eq!(Some(peer.cgroup), parse_proc_cgroup(&direct));
    }
}
