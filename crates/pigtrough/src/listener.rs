//! The unix socket the proxy listens on, and who may connect to it.
//!
//! The pilot's binding is single-operator, single-host (FDR 0009, "Process
//! and files"): the socket lives in a directory of mode `0700` owned by the
//! proxy's user, the socket itself is `0600`, and every accepted connection
//! is checked for the peer's UID (behaviour 6). Per-scope sockets and
//! cgroup binding wait for the scope-binding ruling (#386, clown#244).

use std::fs;
use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;

/// The effective UID of this process.
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Create `dir` with mode `0700`, or check that an existing one is owned
/// by this process's user and open to nobody else.
pub fn prepare_socket_dir(dir: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    if meta.uid() != effective_uid() {
        return Err(io::Error::other(format!(
            "{} is not owned by this user",
            dir.display()
        )));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(io::Error::other(format!(
            "{} is open to other users (mode {:o})",
            dir.display(),
            meta.mode() & 0o777
        )));
    }
    Ok(())
}

/// Bind the socket at `path` inside a directory [`prepare_socket_dir`]
/// accepted, and make it `0600`. A stale socket left by an earlier run is
/// removed; any other file at `path` is an error.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        prepare_socket_dir(dir)?;
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if std::os::unix::fs::FileTypeExt::is_socket(&meta.file_type()) => {
            fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(io::Error::other(format!(
                "{} exists and is not a socket",
                path.display()
            )));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// The UID of the process at the other end of `stream`, from the kernel.
#[cfg(target_os = "linux")]
pub fn peer_uid(stream: &impl AsRawFd) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the fd is a live socket owned by `stream`; `cred` and `len`
    // are valid for writes of the size passed.
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
    Ok(cred.uid)
}

/// The UID of the process at the other end of `stream`, from the kernel.
#[cfg(target_os = "macos")]
pub fn peer_uid(stream: &impl AsRawFd) -> io::Result<u32> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: the fd is a live socket owned by `stream`; both out-pointers
    // are valid.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// Whether a connection is admitted: its peer must be `bound_uid`. A peer
/// whose credentials cannot be read is refused. The one admission decision:
/// `server::serve` calls it (through its admission closure) for every
/// accepted connection, std or tokio.
pub fn admit_peer(stream: &impl AsRawFd, bound_uid: u32) -> bool {
    peer_uid(stream).is_ok_and(|uid| uid == bound_uid)
}

/// Bind `127.0.0.1:port`, loopback only.
pub fn bind_loopback(port: u16) -> io::Result<std::net::TcpListener> {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
}

/// The `/proc/net/tcp` spelling of an IPv4 socket address: the address as
/// the kernel prints it (its bytes read in host order), `:`, the port in hex.
fn proc_net_addr(addr: &SocketAddrV4) -> String {
    format!(
        "{:08X}:{:04X}",
        u32::from_ne_bytes(addr.ip().octets()),
        addr.port()
    )
}

/// The owner uid the kernel lists for the *client's* end of a loopback
/// connection: the socket whose local address is `peer` and whose remote
/// address is `local` (the listener's end). `None` when `table` (the text of
/// `/proc/net/tcp`) has no such line, or the addresses are not IPv4.
fn client_uid_in(table: &str, peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let (SocketAddr::V4(peer), SocketAddr::V4(local)) = (peer, local) else {
        return None;
    };
    let (want_local, want_remote) = (proc_net_addr(&peer), proc_net_addr(&local));
    table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let _slot = fields.next()?;
        if fields.next()? != want_local || fields.next()? != want_remote {
            return None;
        }
        // After the addresses: st, tx_queue:rx_queue, tr:tm->when,
        // retrnsmt, then uid.
        fields.nth(4)?.parse().ok()
    })
}

/// Whether a loopback TCP connection is admitted: the kernel must list its
/// client end as owned by `bound_uid`. A connection the table does not show
/// (a lookup that races the connection, a non-IPv4 peer, an unreadable
/// table) is refused. The owner is the uid of the process that created the
/// client socket, not a peer credential: a descriptor handed on to another
/// user keeps its creator's uid (FDR 0009 listener options, path 2).
#[cfg(target_os = "linux")]
pub fn admit_loopback_peer(peer: SocketAddr, local: SocketAddr, bound_uid: u32) -> bool {
    fs::read_to_string("/proc/net/tcp")
        .ok()
        .and_then(|table| client_uid_in(&table, peer, local))
        .is_some_and(|uid| uid == bound_uid)
}

/// Loopback attribution reads Linux's `/proc/net/tcp`; elsewhere every
/// loopback connection is refused.
#[cfg(not(target_os = "linux"))]
pub fn admit_loopback_peer(_peer: SocketAddr, _local: SocketAddr, _bound_uid: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    const TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:1F4B 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 11111 1 0 100\n\
   1: 0100007F:A5E4 0100007F:1F4B 01 00000000:00000000 00:00000000 00000000  1001        0 22222 1 0 20\n\
   2: 0100007F:A5E5 0100007F:1F4B 01 00000000:00000000 00:00000000 00000000  1002        0 33333 1 0 20\n";

    fn v4(port: u16) -> SocketAddr {
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port))
    }

    #[test]
    fn the_clients_uid_is_read_from_its_own_line_of_the_table() {
        // The listener's own line (state 0A) must not be taken for a client.
        assert_eq!(client_uid_in(TABLE, v4(0xA5E4), v4(0x1F4B)), Some(1001));
        assert_eq!(client_uid_in(TABLE, v4(0xA5E5), v4(0x1F4B)), Some(1002));
        assert_eq!(client_uid_in(TABLE, v4(0xA5E6), v4(0x1F4B)), None);
        assert_eq!(client_uid_in(TABLE, v4(0xA5E4), v4(0x1F4C)), None);
        let v6 = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0xA5E4));
        assert_eq!(client_uid_in(TABLE, v6, v4(0x1F4B)), None);
        assert_eq!(client_uid_in("", v4(1), v4(2)), None);
        assert_eq!(client_uid_in("header only\n", v4(1), v4(2)), None);
    }

    #[test]
    fn bind_loopback_listens_on_loopback_only() {
        let listener = bind_loopback(0).unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
    }

    /// A fresh directory with a short name: a socket path must fit in
    /// `sun_path` (108 bytes on Linux) under a worktree's long `TMPDIR`.
    fn tempdir() -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("pd-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn bind_makes_a_private_dir_and_socket() {
        let base = tempdir();
        let sock = base.join("r").join("s");
        let listener = bind(&sock).unwrap();
        let dir_mode = fs::metadata(base.join("r")).unwrap().mode() & 0o777;
        let sock_mode = fs::symlink_metadata(&sock).unwrap().mode() & 0o777;
        assert_eq!((dir_mode, sock_mode), (0o700, 0o600));
        // A second bind replaces the stale socket.
        drop(listener);
        bind(&sock).unwrap();
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn refuses_a_dir_open_to_others_and_a_non_socket() {
        let base = tempdir();
        let open = base.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(bind(&open.join("s")).is_err());

        let private = base.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(private.join("s"), b"not a socket").unwrap();
        assert!(bind(&private.join("s")).is_err());
        fs::remove_dir_all(base).unwrap();
    }

    /// Behaviour 6 against the kernel's own peer credentials: the same
    /// connection is admitted when bound to this UID and refused when
    /// bound to any other.
    #[test]
    fn peer_uid_comes_from_the_kernel_and_gates_admission() {
        let (a, b) = UnixStream::pair().unwrap();
        let me = effective_uid();
        assert_eq!(peer_uid(&a).unwrap(), me);
        assert!(admit_peer(&b, me));
        assert!(!admit_peer(&b, me.wrapping_add(1)));
    }
}
