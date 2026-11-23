//! The nonce socket (stage 1: it hands out nonces and does nothing else).
//! A client connects and reads one line; it sends nothing. The server takes
//! the client's uid and pid from `SO_PEERCRED`, its cgroup from
//! `/proc/<pid>/cgroup` read through a descriptor on `/proc/<pid>` (so a
//! read after the process exited fails rather than following a reused pid;
//! the window between accept and that open remains), and answers:
//!
//! ```text
//! ok <nonce hex> <seconds it has left>
//! refused <reason>
//! ```
//!
//! Connections are served one at a time, so issuing never races; the only
//! I/O per connection is a short write with a timeout.

use crate::nonce::{Asker, NonceStore};
use crate::response::nonce_hex;
use std::io::{self, BufRead as _, Write as _};
use std::os::fd::AsRawFd as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

/// `SO_PEERCRED`: (uid, pid).
pub fn peer_credentials(stream: &UnixStream) -> io::Result<(u32, i32)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if cred.pid <= 0 {
        return Err(io::Error::other("no peer pid"));
    }
    Ok((cred.uid, cred.pid))
}

/// The cgroup v2 path of `pid`, read through a descriptor on `/proc/<pid>`.
pub fn cgroup_of_pid(pid: i32) -> io::Result<String> {
    use std::os::fd::FromRawFd as _;
    let dir = std::fs::File::open(format!("/proc/{pid}"))?;
    // SAFETY: openat on a valid directory descriptor with a NUL-terminated
    // path; the returned descriptor is owned by the File below.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"cgroup".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly opened descriptor this process owns.
    let text = io::read_to_string(unsafe { std::fs::File::from_raw_fd(fd) })?;
    text.lines()
        .find_map(|l| l.strip_prefix("0::"))
        .map(str::to_string)
        .ok_or_else(|| io::Error::other("no cgroup v2 line"))
}

pub fn asker_of(stream: &UnixStream) -> io::Result<Asker> {
    let (uid, pid) = peer_credentials(stream)?;
    Ok(Asker {
        uid,
        pid,
        cgroup: cgroup_of_pid(pid).ok(),
    })
}

/// Nonces one account may be issued per [`ISSUE_WINDOW`] boot seconds
/// (review R1): the outstanding cap alone lets an account ask for, use and
/// ask again without end, one audit line each.
pub const ISSUE_BUDGET: u64 = 60;
pub const ISSUE_WINDOW: u64 = 60;

/// Each account's issue count in the current window, kept by the socket
/// (one process, one connection at a time, so no lock).
#[derive(Default)]
pub struct IssueBudget(std::collections::HashMap<u32, (u64, u64)>);

impl IssueBudget {
    /// Count one issue to `uid` at `now`; false past the budget.
    pub fn take(&mut self, uid: u32, now: u64) -> bool {
        let (start, count) = self.0.entry(uid).or_insert((now, 0));
        if now >= start.saturating_add(ISSUE_WINDOW) || now < *start {
            (*start, *count) = (now, 0);
        }
        if *count >= ISSUE_BUDGET {
            return false;
        }
        *count += 1;
        true
    }

    /// Forget accounts whose window has closed (one entry per uid ever seen
    /// would otherwise only grow).
    pub fn prune(&mut self, now: u64) {
        self.0
            .retain(|_, (start, _)| now < start.saturating_add(ISSUE_WINDOW) && now >= *start);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Take NOTIFY_SOCKET out of the environment (nothing hogtie starts may
/// inherit it) and return it.
pub fn take_notify_socket() -> Option<std::ffi::OsString> {
    let v = std::env::var_os("NOTIFY_SOCKET");
    std::env::remove_var("NOTIFY_SOCKET");
    v.filter(|v| !v.is_empty())
}

/// Tell systemd `serve` is ready: `READY=1` as one datagram to `addr`, a
/// path or, with a leading `@`, an abstract name (sd_notify(3)'s two
/// forms; no libsystemd).
pub fn notify_ready(addr: &std::ffi::OsStr) -> io::Result<()> {
    use std::os::linux::net::SocketAddrExt as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let bytes = addr.as_bytes();
    let to = match bytes.strip_prefix(b"@") {
        Some(name) => SocketAddr::from_abstract_name(name)?,
        None => SocketAddr::from_pathname(Path::new(addr))?,
    };
    // Non-blocking, so the send can never wait: a would-block (EAGAIN)
    // fails the start rather than leaving the socket bound and unserved.
    // Not shown by a test: on this kernel another sender filling the
    // receiver did not make a fresh socket's send wait.
    let sock = UnixDatagram::unbound()?;
    sock.set_nonblocking(true)?;
    let n = sock.send_to_addr(b"READY=1", &to)?;
    if n != 7 {
        return Err(io::Error::other("a short write to NOTIFY_SOCKET"));
    }
    Ok(())
}

/// Answer one connection.
pub fn answer(
    stream: &mut UnixStream,
    store: &NonceStore,
    budget: &mut IssueBudget,
    now: u64,
) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let line = match asker_of(stream) {
        Err(e) => format!("refused cannot read the caller: {e}\n"),
        Ok(asker) if !budget.take(asker.uid, now) => {
            format!("refused this account was issued {ISSUE_BUDGET} nonces this minute\n")
        }
        Ok(asker) => match store.issue(&asker, now) {
            Ok((nonce, expires)) => {
                format!("ok {} {}\n", nonce_hex(&nonce), expires.saturating_sub(now))
            }
            Err(e) => format!("refused {e}\n"),
        },
    };
    stream.write_all(line.as_bytes())
}

/// Serve forever. The loop waits at most a second for a connection, so
/// the sweep (expired nonces, empty accounts, old scratch, refusal
/// summaries, the issue budget) runs every 30 seconds whether or not anyone
/// connects (F4); the first runs at once.
pub fn serve(
    listener: &UnixListener,
    store: &NonceStore,
    paths: &crate::paths::Paths,
) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    let mut budget = IssueBudget::default();
    let mut last_sweep: Option<u64> = None;
    loop {
        // Nonce life is on the boot clock (util::boot_now): exec reads it.
        let now = match crate::util::boot_now() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("hogtie serve: cannot read the clock: {e}");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        if last_sweep.is_none_or(|l| now >= l + crate::nonce::TTL_SECONDS) {
            sweep(store, paths, &mut budget, now);
            last_sweep = Some(now);
        }
        let mut pfd = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on one descriptor this function holds.
        if unsafe { libc::poll(&mut pfd, 1, 1000) } <= 0 {
            continue;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                if let Err(e) = answer(&mut stream, store, &mut budget, now) {
                    eprintln!("hogtie serve: answer: {e}");
                }
            }
            Err(e) => {
                // Out of descriptors, say: back off rather than spin.
                eprintln!("hogtie serve: accept: {e}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn sweep(store: &NonceStore, paths: &crate::paths::Paths, budget: &mut IssueBudget, now: u64) {
    if let Err(e) = store.sweep(now) {
        eprintln!("hogtie serve: sweep: {e}");
    }
    if let Err(e) = crate::verify::sweep_scratch(&paths.scratch(), crate::verify::SCRATCH_MAX_AGE) {
        eprintln!("hogtie serve: scratch sweep: {e}");
    }
    // The summaries go to the log exec writes, checked as exec checks it.
    let flushed = crate::paths::Paths::ensure_private_dir(&paths.log).and_then(|()| {
        crate::audit::flush_summaries(
            &paths.refusals(),
            &paths.audit_log(),
            now,
            crate::util::now(),
        )
    });
    if let Err(e) = flushed {
        eprintln!("hogtie serve: refusal summaries: {e}");
    }
    budget.prune(now);
}

/// Bind `path` (replacing a stale socket) with mode 0666: any local account
/// may ask; the per-account cap is what bounds a flood.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt as _;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(l)
}

/// The client side: ask the socket at `path` for a nonce.
pub fn ask(path: &Path) -> io::Result<Result<(String, u64), String>> {
    let s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut line = String::new();
    io::BufReader::new(io::Read::take(s, 512)).read_line(&mut line)?;
    let line = line.trim_end();
    if let Some(rest) = line.strip_prefix("ok ") {
        let (hex, exp) = rest
            .split_once(' ')
            .ok_or_else(|| io::Error::other("malformed answer"))?;
        let exp = exp
            .parse()
            .map_err(|_| io::Error::other("malformed expiry"))?;
        return Ok(Ok((hex.to_string(), exp)));
    }
    Ok(Err(line
        .strip_prefix("refused ")
        .unwrap_or(line)
        .to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::PrivateDir;

    #[test]
    fn the_socket_hands_this_process_a_nonce_filed_under_its_uid() {
        let d = PrivateDir::new(&std::env::temp_dir(), "hogtie-sock").unwrap();
        let store_dir = d.path().join("nonces");
        std::fs::create_dir(&store_dir).unwrap();
        let store = NonceStore::new(&store_dir);
        let sock = d.path().join("s");
        let listener = bind(&sock).unwrap();
        let client = std::thread::spawn({
            let sock = sock.clone();
            move || ask(&sock).unwrap()
        });
        let (mut conn, _) = listener.accept().unwrap();
        answer(&mut conn, &store, &mut IssueBudget::default(), 1000).unwrap();
        drop(conn);
        let (hex, expires) = client.join().unwrap().unwrap();
        assert_eq!(expires, 30, "the seconds it has left");
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let nonce = crate::response::parse_nonce_hex(&hex).unwrap();
        let entry = store.claim(uid, &nonce, 1001).unwrap();
        assert_eq!(entry.asker.pid, std::process::id() as i32);
        assert!(entry.asker.cgroup.is_some(), "the cgroup is read on Linux");
    }

    #[test]
    fn nonce_issue_is_rate_limited_per_account() {
        let mut b = IssueBudget::default();
        for _ in 0..ISSUE_BUDGET {
            assert!(b.take(1000, 100));
        }
        assert!(!b.take(1000, 100), "past the budget");
        assert!(b.take(1001, 100), "per account");
        assert!(b.take(1000, 100 + ISSUE_WINDOW), "the next window");
    }

    #[test]
    fn the_issue_budget_forgets_closed_windows() {
        let mut b = IssueBudget::default();
        b.take(1000, 100);
        b.take(1001, 150);
        b.prune(165);
        assert_eq!(b.len(), 1, "1000's window closed at 160");
        b.prune(215);
        assert!(b.is_empty());
    }

    #[test]
    fn the_socket_refuses_an_account_past_its_issue_budget() {
        let d = PrivateDir::new(&std::env::temp_dir(), "hogtie-sock").unwrap();
        let store = NonceStore::new(d.path());
        let sock = d.path().join("s");
        let listener = bind(&sock).unwrap();
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let mut budget = IssueBudget::default();
        for _ in 0..ISSUE_BUDGET {
            assert!(budget.take(uid, 1000));
        }
        let client = std::thread::spawn({
            let sock = sock.clone();
            move || ask(&sock).unwrap()
        });
        let (mut conn, _) = listener.accept().unwrap();
        answer(&mut conn, &store, &mut budget, 1000).unwrap();
        drop(conn);
        let refusal = client.join().unwrap().unwrap_err();
        assert!(refusal.contains("nonces this minute"), "{refusal}");
    }

    #[test]
    fn the_socket_refuses_past_the_cap() {
        let d = PrivateDir::new(&std::env::temp_dir(), "hogtie-sock").unwrap();
        let store = NonceStore::new(d.path());
        let sock = d.path().join("s");
        let listener = bind(&sock).unwrap();
        let mut budget = IssueBudget::default();
        let mut last = None;
        for _ in 0..=crate::nonce::CAP_PER_ACCOUNT {
            let client = std::thread::spawn({
                let sock = sock.clone();
                move || ask(&sock).unwrap()
            });
            let (mut conn, _) = listener.accept().unwrap();
            answer(&mut conn, &store, &mut budget, 1000).unwrap();
            drop(conn);
            last = Some(client.join().unwrap());
        }
        let refusal = last.unwrap().unwrap_err();
        assert!(refusal.contains("unused nonces"), "{refusal}");
    }
}
