//! The process state an action starts with, set rather than inherited from
//! whoever ran sudo (review finding 4): umask 022, every signal at its
//! default disposition and none blocked, no descriptor but 0, 1 and 2, and
//! the resource limits of pid 1 (what a service would get), or, where those
//! cannot be read (not root), every soft limit raised to its hard limit, so
//! a caller cannot shrink a root action's limits (a small RLIMIT_FSIZE could
//! truncate a file it writes). The environment and the working directory are
//! set by the caller of [`prepare`].

use std::io;
use std::process::Command;

const RESOURCES: [libc::__rlimit_resource_t; 16] = [
    libc::RLIMIT_CPU,
    libc::RLIMIT_FSIZE,
    libc::RLIMIT_DATA,
    libc::RLIMIT_STACK,
    libc::RLIMIT_CORE,
    libc::RLIMIT_RSS,
    libc::RLIMIT_NPROC,
    libc::RLIMIT_NOFILE,
    libc::RLIMIT_MEMLOCK,
    libc::RLIMIT_AS,
    libc::RLIMIT_LOCKS,
    libc::RLIMIT_SIGPENDING,
    libc::RLIMIT_MSGQUEUE,
    libc::RLIMIT_NICE,
    libc::RLIMIT_RTPRIO,
    libc::RLIMIT_RTTIME,
];

/// The limits the action gets, computed before exec (reading pid 1's is
/// not async-signal-safe work for a pre_exec hook).
fn target_limits() -> Vec<(libc::__rlimit_resource_t, libc::rlimit)> {
    RESOURCES
        .iter()
        .map(|&r| {
            let mut init = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: prlimit with a null new limit only writes `init`.
            let from_init = unsafe { libc::prlimit(1, r, std::ptr::null(), &mut init) } == 0;
            if from_init {
                return (r, init);
            }
            let mut own = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: getrlimit writes one rlimit.
            unsafe { libc::getrlimit(r, &mut own) };
            (
                r,
                libc::rlimit {
                    rlim_cur: own.rlim_max,
                    rlim_max: own.rlim_max,
                },
            )
        })
        .collect()
}

/// Arrange for `cmd`'s exec to start from the state above. Fails closed: if
/// any of it cannot be set, the exec fails and hogtie reports it.
pub fn prepare(cmd: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    let limits = target_limits();
    // SAFETY: the hook makes only async-signal-safe calls (umask,
    // sigaction, sigprocmask, setrlimit, close_range, close) and touches
    // only `limits`, allocated before the hook runs.
    unsafe {
        cmd.pre_exec(move || {
            libc::umask(0o022);
            let mut dfl: libc::sigaction = std::mem::zeroed();
            dfl.sa_sigaction = libc::SIG_DFL;
            for sig in 1..=libc::SIGRTMAX() {
                if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                    // Some numbers are reserved by libc and refuse: harmless.
                    libc::sigaction(sig, &dfl, std::ptr::null_mut());
                }
            }
            let mut none: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut none);
            if libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            for (r, lim) in &limits {
                if libc::setrlimit(*r, lim) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) != 0 {
                // An older kernel: close them one by one.
                for fd in 3..65_536 {
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }
}
