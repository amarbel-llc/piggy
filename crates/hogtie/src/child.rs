//! The process state an action starts with, set rather than inherited from
//! whoever ran sudo (review findings 4, N3, N4, N6): umask 022; every signal
//! at its default disposition and none blocked; no descriptor but 0, 1 and
//! 2; the fixed resource limits of [`LIMITS`]; nice 0, the default
//! scheduler, every CPU, oom_score_adj 0 and the default I/O priority. The
//! environment and the working directory are set by the caller of
//! [`prepare`].
//!
//! As root (production) every one of these must succeed or the exec fails.
//! Not as root (the test harness only), a reset that needs privilege the
//! test lacks (EPERM) is skipped, and a limit the test cannot raise to its
//! value gets the highest the test may give it.
//!
//! Left as inherited, deliberately: the controlling terminal, the session
//! and process group, the cgroup, namespaces, the seccomp filter and the
//! no_new_privs bit (sudo's to give; hogtie runs the action in sudo's place).

use std::io;
use std::process::Command;

const INF: libc::rlim_t = libc::RLIM_INFINITY;
const MIB: libc::rlim_t = 1024 * 1024;

/// The limits an action gets: the kernel's defaults for root, with
/// systemd's open-file soft and hard limits (1024 / 524288).
pub const LIMITS: [(libc::__rlimit_resource_t, libc::rlim_t, libc::rlim_t); 16] = [
    (libc::RLIMIT_CPU, INF, INF),
    (libc::RLIMIT_FSIZE, INF, INF),
    (libc::RLIMIT_DATA, INF, INF),
    (libc::RLIMIT_STACK, 8 * MIB, INF),
    (libc::RLIMIT_CORE, 0, INF),
    (libc::RLIMIT_RSS, INF, INF),
    (libc::RLIMIT_NPROC, INF, INF),
    (libc::RLIMIT_NOFILE, 1024, 524_288),
    (libc::RLIMIT_MEMLOCK, 8 * MIB, 8 * MIB),
    (libc::RLIMIT_AS, INF, INF),
    (libc::RLIMIT_LOCKS, INF, INF),
    (libc::RLIMIT_SIGPENDING, INF, INF),
    (libc::RLIMIT_MSGQUEUE, 819_200, 819_200),
    (libc::RLIMIT_NICE, 0, 0),
    (libc::RLIMIT_RTPRIO, 0, 0),
    (libc::RLIMIT_RTTIME, INF, INF),
];

fn is_root() -> bool {
    // SAFETY: geteuid cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Run `f`; an error fails, except EPERM when not `strict`.
fn required(strict: bool, ok: bool) -> io::Result<()> {
    if ok {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if !strict && e.raw_os_error() == Some(libc::EPERM) {
        return Ok(());
    }
    Err(e)
}

/// Set `r` to (cur, max); not as root, fall back to the most the process
/// may give itself.
///
/// # Safety
/// Calls getrlimit/setrlimit only.
unsafe fn set_limit(
    strict: bool,
    r: libc::__rlimit_resource_t,
    cur: libc::rlim_t,
    max: libc::rlim_t,
) -> io::Result<()> {
    let want = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    if unsafe { libc::setrlimit(r, &want) } == 0 {
        return Ok(());
    }
    if strict {
        return Err(io::Error::last_os_error());
    }
    let mut own = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(r, &mut own) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let fallback = libc::rlimit {
        rlim_cur: cur.min(own.rlim_max),
        rlim_max: own.rlim_max.min(max),
    };
    if unsafe { libc::setrlimit(r, &fallback) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// hogtie's own process, first thing in `main` (review N2, R1, R2): every
/// limit to the [`LIMITS`] table, so the caller cannot make hogtie run out
/// of descriptors, memory or file size and so cause an `error` or cut the
/// audit line; SIGXFSZ ignored (a write past the limit fails with EFBIG
/// instead); and the job-control signals SIGTSTP, SIGTTIN and SIGTTOU
/// ignored, so a caller cannot stop hogtie through sudo's relaying.
/// SIGSTOP cannot be ignored: sudo does not relay it, and the caller (not
/// root) cannot send it to a process sudo runs as root. All of it is reset
/// for the action by [`prepare`].
pub fn shield_self() -> io::Result<()> {
    let strict = is_root();
    for (r, cur, max) in LIMITS {
        // SAFETY: getrlimit/setrlimit on this process.
        unsafe { set_limit(strict, r, cur, max)? };
    }
    // Scheduling too, for hogtie itself and not only for the action: a
    // caller must not be able to starve hogtie (SCHED_IDLE, one CPU, nice
    // 19) while it holds an account's budget lock (F1).
    // SAFETY: plain system calls on this process.
    unsafe { reset_scheduling(strict)? };
    for sig in [libc::SIGXFSZ, libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU] {
        // SAFETY: setting a signal's disposition to ignored.
        if unsafe { libc::signal(sig, libc::SIG_IGN) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// nice 0, SCHED_OTHER, every CPU, oom_score_adj 0, the default I/O
/// priority.
///
/// # Safety
/// Plain system calls on this process.
unsafe fn reset_scheduling(strict: bool) -> io::Result<()> {
    unsafe {
        required(strict, libc::setpriority(libc::PRIO_PROCESS, 0, 0) == 0)?;
        let param = libc::sched_param { sched_priority: 0 };
        required(
            strict,
            libc::sched_setscheduler(0, libc::SCHED_OTHER, &param) == 0,
        )?;
        let mut all: libc::cpu_set_t = std::mem::zeroed();
        for cpu in 0..libc::CPU_SETSIZE as usize {
            libc::CPU_SET(cpu, &mut all);
        }
        required(
            strict,
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &all) == 0,
        )?;
        let fd = libc::open(
            c"/proc/self/oom_score_adj".as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let wrote = libc::write(fd, b"0\n".as_ptr().cast(), 2) == 2;
        let err = io::Error::last_os_error();
        libc::close(fd);
        if !wrote && (strict || err.raw_os_error() != Some(libc::EACCES)) {
            return Err(err);
        }
        // IOPRIO_WHO_PROCESS (1), this process (0), class none: the default.
        required(strict, libc::syscall(libc::SYS_ioprio_set, 1, 0, 0) == 0)?;
    }
    Ok(())
}

/// Block every signal that can be blocked (review R5); [`prepare`]'s hook
/// empties the mask just before execve.
pub fn block_signals() {
    // SAFETY: sigprocmask with a full set on this thread.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::sigprocmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
    }
}

/// Undo [`block_signals`] (an exec that returned).
pub fn unblock_signals() {
    // SAFETY: sigprocmask with an empty set on this thread.
    unsafe {
        let mut none: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut none);
        libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut());
    }
}

/// Arrange for `cmd`'s exec to start from the state above. Fails closed: if
/// any of it cannot be set, the exec fails and hogtie reports it.
pub fn prepare(cmd: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    // SAFETY: `exec` does not fork, so the hook runs in hogtie's own
    // process just before execve; it still makes only plain system calls.
    unsafe {
        cmd.pre_exec(|| {
            libc::umask(0o022);
            let mut dfl: libc::sigaction = std::mem::zeroed();
            dfl.sa_sigaction = libc::SIG_DFL;
            // 32 up to SIGRTMIN are reserved by the C library.
            let reserved = 32..libc::SIGRTMIN();
            for sig in 1..=libc::SIGRTMAX() {
                if sig == libc::SIGKILL || sig == libc::SIGSTOP || reserved.contains(&sig) {
                    continue;
                }
                if libc::sigaction(sig, &dfl, std::ptr::null_mut()) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let mut none: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut none);
            if libc::sigprocmask(libc::SIG_SETMASK, &none, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error());
            }
            // The limits and the scheduling are already reset: shield_self
            // did it for hogtie's own process, and exec keeps them.
            // Last: every descriptor above 2. No fallback (review N4): a
            // kernel without close_range refuses.
            if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
