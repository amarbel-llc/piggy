use std::cell::RefCell;

use super::*;

thread_local! {
    /// The data pages as Drop left them, just before unmapping.
    static WIPED: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

pub(super) fn observe_wiped(pages: &[u8]) {
    WIPED.with(|w| *w.borrow_mut() = Some(pages.to_vec()));
}

/// How a forked child ended.
#[derive(Debug, PartialEq, Eq)]
enum ChildEnd {
    Exited(i32),
    Signalled(i32),
}

/// Fork, run `child` in the child with core dumps off, and report how it
/// ended. The child does nothing but its closure and `_exit`.
fn in_child(child: impl FnOnce() -> i32) -> ChildEnd {
    // SAFETY: the child runs only the closure (page protection changes and
    // reads) and exits with _exit, never returning into the test harness.
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            let none = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &none);
            // A piped core_pattern (systemd-coredump) may not stop at the
            // limit; a non-dumpable process is not dumped at all.
            #[cfg(target_os = "linux")]
            libc::prctl(libc::PR_SET_DUMPABLE, 0);
            let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(child)).unwrap_or(101);
            libc::_exit(code);
        }
        let mut status = 0;
        assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
        if libc::WIFSIGNALED(status) {
            ChildEnd::Signalled(libc::WTERMSIG(status))
        } else {
            ChildEnd::Exited(libc::WEXITSTATUS(status))
        }
    }
}

/// A touch of an inaccessible page: SIGSEGV on Linux, SIGBUS or SIGSEGV
/// on macOS.
fn faulted(end: &ChildEnd) -> bool {
    matches!(end, ChildEnd::Signalled(s) if *s == libc::SIGSEGV || *s == libc::SIGBUS)
}

#[test]
fn a_read_inside_with_sees_the_bytes() {
    let g = GuardedBytes::from_slice(b"123456").unwrap();
    assert_eq!(g.len(), 6);
    assert_eq!(g.with(|b| b.to_vec()).unwrap(), b"123456");
}

#[test]
fn a_write_inside_with_mut_is_seen_by_the_next_read() {
    let mut g = GuardedBytes::zeroed(4).unwrap();
    assert_eq!(g.with(|b| b.to_vec()).unwrap(), [0; 4]);
    g.with_mut(|b| b.copy_from_slice(b"abcd")).unwrap();
    assert_eq!(g.with(|b| b.to_vec()).unwrap(), b"abcd");
}

#[test]
fn an_empty_secret_reads_as_empty() {
    let g = GuardedBytes::from_slice(b"").unwrap();
    assert!(g.is_empty());
    assert_eq!(g.with(|b| b.len()).unwrap(), 0);
}

#[test]
fn a_secret_longer_than_a_page_is_carried_whole() {
    let secret: Vec<u8> = (0..page_size() * 2 + 3).map(|i| i as u8).collect();
    let g = GuardedBytes::from_slice(&secret).unwrap();
    assert_eq!(g.with(|b| b.to_vec()).unwrap(), secret);
}

/// A size the page rounding cannot represent is refused, not wrapped.
#[test]
fn an_unrepresentable_size_is_refused() {
    for len in [
        usize::MAX,
        usize::MAX - page_size() + 2,
        isize::MAX as usize + 1,
    ] {
        let err = GuardedBytes::zeroed(len).unwrap_err();
        assert!(err.to_string().starts_with("size: "), "{len}: {err}");
    }
}

#[test]
fn drop_zeroes_the_data_pages() {
    let g = GuardedBytes::from_slice(b"hunter2").unwrap();
    let pages = page_size();
    drop(g);
    let wiped = WIPED
        .with(|w| w.borrow_mut().take())
        .expect("drop wiped nothing");
    assert_eq!(wiped.len(), pages);
    assert!(wiped.iter().all(|&b| b == 0));
}

#[test]
fn a_touch_at_rest_faults() {
    let g = GuardedBytes::from_slice(b"123456").unwrap();
    let ptr = g.secret_ptr();
    let end = in_child(|| {
        // SAFETY: none; the read is expected to fault.
        let byte = unsafe { std::ptr::read_volatile(ptr) };
        i32::from(byte)
    });
    assert!(faulted(&end), "{end:?}");
}

#[test]
fn the_pages_are_sealed_again_after_with() {
    let g = GuardedBytes::from_slice(b"123456").unwrap();
    let ptr = g.secret_ptr();
    let end = in_child(|| {
        g.with(|_| ()).unwrap();
        // SAFETY: none; the read is expected to fault.
        i32::from(unsafe { std::ptr::read_volatile(ptr) })
    });
    assert!(faulted(&end), "{end:?}");
}

#[test]
fn a_read_past_the_end_hits_the_guard_page() {
    let g = GuardedBytes::from_slice(b"123456").unwrap();
    let end = in_child(|| {
        g.with(|b| {
            // SAFETY: none; one past the secret is the trailing guard
            // page, and the read is expected to fault.
            i32::from(unsafe { std::ptr::read_volatile(b.as_ptr().add(b.len())) })
        })
        .unwrap()
    });
    assert!(faulted(&end), "{end:?}");
}

#[test]
fn a_panic_inside_with_still_seals_the_pages() {
    let g = GuardedBytes::from_slice(b"123456").unwrap();
    let ptr = g.secret_ptr();
    let end = in_child(|| {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            g.with(|_| panic!("inside with")).unwrap()
        }));
        // SAFETY: none; the read is expected to fault.
        i32::from(unsafe { std::ptr::read_volatile(ptr) })
    });
    assert!(faulted(&end), "{end:?}");
}

/// The pages stay readable until the last of several overlapping reads
/// returns, nested on one thread or concurrent on several.
#[test]
fn overlapping_reads_keep_the_pages_open() {
    let g = GuardedBytes::from_slice(b"123456").unwrap();
    let nested = g
        .with(|outer| g.with(|inner| inner == outer).unwrap() && outer == b"123456")
        .unwrap();
    assert!(nested);

    std::thread::scope(|s| {
        let readers: Vec<_> = (0..4)
            .map(|_| s.spawn(|| (0..500).all(|_| g.with(|b| b == b"123456").unwrap())))
            .collect();
        for r in readers {
            assert!(r.join().unwrap());
        }
    });
}

#[test]
fn a_forked_child_sees_zeros() {
    let g = GuardedBytes::from_slice(b"123456").unwrap();
    if !g.protections().wiped_on_fork {
        eprintln!(
            "skipped: MADV_WIPEONFORK is not available here (Linux 4.14 and later only); \
             protections {:?}",
            g.protections()
        );
        return;
    }
    let end = in_child(|| {
        if g.with(|b| b.iter().all(|&x| x == 0)).unwrap() {
            0
        } else {
            1
        }
    });
    assert_eq!(end, ChildEnd::Exited(0));
    assert_eq!(
        g.with(|b| b.to_vec()).unwrap(),
        b"123456",
        "the parent keeps it"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn on_linux_the_mapping_is_left_out_of_core_dumps() {
    let g = GuardedBytes::from_slice(b"123456").unwrap();
    assert!(g.protections().excluded_from_core_dumps);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn off_linux_the_advice_flags_are_reported_absent() {
    let p = GuardedBytes::from_slice(b"123456").unwrap().protections();
    assert!(!p.excluded_from_core_dumps && !p.wiped_on_fork, "{p:?}");
}

/// In a child, so the test process keeps its own flags.
#[test]
fn harden_process_turns_off_core_dumps() {
    let end = in_child(|| {
        // in_child already zeroed the limit; raise it so the call has
        // something to do (the hard limit may refuse, which is fine: zero
        // is all that is checked).
        let some = libc::rlimit {
            rlim_cur: 4096,
            rlim_max: libc::RLIM_INFINITY,
        };
        // SAFETY: setrlimit reads one rlimit the call borrows.
        unsafe { libc::setrlimit(libc::RLIMIT_CORE, &some) };
        // Likewise the flag in_child cleared. Nothing in this child faults.
        #[cfg(target_os = "linux")]
        // SAFETY: PR_SET_DUMPABLE takes one integer argument.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 1 as libc::c_ulong)
        };
        let hardening = harden_process();
        let mut problems = 0;
        if hardening.core_limit_zero.is_err() || core_limit() != Some(0) {
            problems |= 1;
        }
        if cfg!(target_os = "linux") {
            if !matches!(hardening.non_dumpable, Some(Ok(()))) || is_dumpable() != Some(false) {
                problems |= 2;
            }
        } else if hardening.non_dumpable.is_some() || is_dumpable().is_some() {
            problems |= 4;
        }
        problems
    });
    assert_eq!(end, ChildEnd::Exited(0));
}

#[test]
fn debug_does_not_print_the_secret() {
    let g = GuardedBytes::from_slice(b"hunter2").unwrap();
    let shown = format!("{g:?}");
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(shown.contains("len: 7"), "{shown}");
}
