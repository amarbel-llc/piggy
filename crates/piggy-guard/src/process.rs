//! Process-wide hardening a holder of guarded secrets applies at start
//! (FDR 0006 "Guarded memory": non-dumpable, no core file).

use super::GuardError;

/// What [`harden_process`] did. Each step is independent: a failure in
/// one leaves the other applied, and the caller decides whether to carry
/// on (the agent logs a warning and does).
#[derive(Debug)]
pub struct ProcessHardening {
    /// `prctl(PR_SET_DUMPABLE, 0)`: no core dump, no same-user ptrace
    /// attach, `/proc/<pid>` owned by root. `None` where the call does
    /// not exist (everything but Linux).
    pub non_dumpable: Option<Result<(), GuardError>>,
    /// `setrlimit(RLIMIT_CORE, 0)`, soft and hard, so no core file is
    /// written even where the dumpable flag is not available.
    pub core_limit_zero: Result<(), GuardError>,
}

/// Mark the process non-dumpable (Linux) and set its core size limit to
/// zero (every platform). Children inherit the core limit; an exec'd
/// child gets its dumpable flag back from the kernel's usual rules.
pub fn harden_process() -> ProcessHardening {
    let none = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads one rlimit the call borrows.
    let core_limit_zero = if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &none) } == 0 {
        Ok(())
    } else {
        Err(GuardError::last_os_error("setrlimit(RLIMIT_CORE)"))
    };
    ProcessHardening {
        non_dumpable: set_non_dumpable(),
        core_limit_zero,
    }
}

#[cfg(target_os = "linux")]
fn set_non_dumpable() -> Option<Result<(), GuardError>> {
    // SAFETY: PR_SET_DUMPABLE takes one integer argument and no pointers.
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) };
    Some(if rc == 0 {
        Ok(())
    } else {
        Err(GuardError::last_os_error("prctl(PR_SET_DUMPABLE)"))
    })
}

#[cfg(not(target_os = "linux"))]
fn set_non_dumpable() -> Option<Result<(), GuardError>> {
    None
}

/// The process's dumpable flag, as `prctl(PR_GET_DUMPABLE)` reads it;
/// `None` off Linux or if the call fails.
pub fn is_dumpable() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_GET_DUMPABLE takes no arguments.
        let rc = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        (rc >= 0).then_some(rc != 0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The soft core size limit, in bytes; `None` if it cannot be read.
pub fn core_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit the call borrows.
    (unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } == 0).then_some(limit.rlim_cur)
}
