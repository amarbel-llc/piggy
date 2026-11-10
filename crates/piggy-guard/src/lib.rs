//! Guarded memory for secrets (FDR 0006 "Guarded memory", piggy#378).
//!
//! A [`GuardedBytes`] holds one secret on pages of its own, mapped
//! between two inaccessible guard pages, and keeps those pages
//! inaccessible except while a [`GuardedBytes::with`] or
//! [`GuardedBytes::with_mut`] call runs. It is the shape of libsodium's
//! `sodium_malloc` and `sodium_mprotect_*`: a stray read of the secret
//! between operations faults instead of returning it, and an overrun off
//! its end lands on the trailing guard page.
//!
//! Each allocation asks the kernel for more, and records what it got in
//! [`Protections`]:
//!
//! - locked against swap (`mlock`; refused past `RLIMIT_MEMLOCK`);
//! - excluded from core dumps (`MADV_DONTDUMP`, Linux only);
//! - wiped in a forked child (`MADV_WIPEONFORK`, Linux 4.14 and later).
//!
//! On macOS an allocation gets the guard pages, the lock and the seal at
//! rest, and none of the two Linux advice flags. Dropping a
//! [`GuardedBytes`] zeroizes its pages before unmapping them, on every
//! platform.
//!
//! There is no `Deref`: nothing leaves the pages readable past the
//! closure that reads them, so a caller that needs the secret longer
//! copies it into something it zeroizes itself (`zeroize::Zeroizing`).

#![deny(unsafe_op_in_unsafe_fn)]

use std::fmt;
use std::io;
use std::ptr::NonNull;
use std::sync::Mutex;

use zeroize::Zeroize;

/// What the kernel granted one allocation, beyond the guard pages and the
/// seal at rest, which every allocation has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Protections {
    /// The data pages are locked in memory, so never written to swap.
    pub locked: bool,
    /// The whole mapping is left out of a core dump of the process.
    pub excluded_from_core_dumps: bool,
    /// A forked child sees the data pages as zeros.
    pub wiped_on_fork: bool,
}

/// A system call this crate needed failed.
#[derive(Debug)]
pub struct GuardError {
    call: &'static str,
    source: io::Error,
}

impl GuardError {
    fn last_os_error(call: &'static str) -> Self {
        Self {
            call,
            source: io::Error::last_os_error(),
        }
    }
}

impl fmt::Display for GuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.call, self.source)
    }
}

impl std::error::Error for GuardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn page_size() -> usize {
    // SAFETY: sysconf has no preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size)
        .ok()
        .filter(|&s| s > 0)
        .unwrap_or(4096)
}

/// One secret on guarded pages. See the crate documentation.
pub struct GuardedBytes {
    /// The whole mapping: leading guard page, data pages, trailing guard
    /// page.
    mapping: NonNull<u8>,
    mapping_len: usize,
    /// The first data page, one page into the mapping.
    data_pages: NonNull<u8>,
    data_pages_len: usize,
    /// The secret's length. It sits at the very end of the data pages, so
    /// the byte after it is the trailing guard page.
    len: usize,
    protections: Protections,
    /// How many [`GuardedBytes::with`] calls are running. The pages are
    /// readable exactly while this is above zero; the lock orders the
    /// protection changes of concurrent and nested reads.
    readers: Mutex<usize>,
}

// SAFETY: the mapping is owned by this value alone, and every change to its
// protection happens under `readers` (or through `&mut self`), so sharing
// or moving it between threads cannot race on the pages.
unsafe impl Send for GuardedBytes {}
// SAFETY: as for Send.
unsafe impl Sync for GuardedBytes {}

impl GuardedBytes {
    /// A secret of `len` zero bytes, sealed.
    pub fn zeroed(len: usize) -> Result<Self, GuardError> {
        let page = page_size();
        // A slice may span at most isize::MAX bytes; past that, and past
        // what the page rounding can represent, the size is refused rather
        // than wrapped (a wrapped size would break `len <= data_pages_len`,
        // which `secret_ptr` relies on).
        let sizes = (len <= isize::MAX as usize)
            .then(|| len.max(1).div_ceil(page).checked_mul(page))
            .flatten()
            .and_then(|data| Some((data, data.checked_add(2 * page)?)));
        let (data_pages_len, mapping_len) = sizes.ok_or_else(|| GuardError {
            call: "size",
            source: io::ErrorKind::OutOfMemory.into(),
        })?;

        // SAFETY: an anonymous private mapping at an address of the
        // kernel's choosing touches no existing memory.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                mapping_len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(GuardError::last_os_error("mmap"));
        }
        let mapping = NonNull::new(raw.cast::<u8>()).expect("mmap returned null");
        // SAFETY: `page` is inside the mapping just made.
        let data_pages = unsafe { NonNull::new_unchecked(mapping.as_ptr().add(page)) };

        // Built before anything else can fail, so Drop unmaps on every
        // error path below.
        let mut guarded = Self {
            mapping,
            mapping_len,
            data_pages,
            data_pages_len,
            len,
            protections: Protections::default(),
            readers: Mutex::new(0),
        };
        guarded.advise();
        // Open the data pages while locking them, so the lock faults them
        // in (and counts them) rather than locking an inaccessible range.
        guarded.protect(libc::PROT_READ | libc::PROT_WRITE)?;
        // SAFETY: the data pages are inside the mapping.
        guarded.protections.locked =
            unsafe { libc::mlock(data_pages.as_ptr().cast(), data_pages_len) } == 0;
        guarded.protect(libc::PROT_NONE)?;
        Ok(guarded)
    }

    /// A sealed copy of `bytes`. The caller still owns, and should
    /// zeroize, its own copy.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, GuardError> {
        let mut guarded = Self::zeroed(bytes.len())?;
        guarded.with_mut(|secret| secret.copy_from_slice(bytes))?;
        Ok(guarded)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn protections(&self) -> Protections {
        self.protections
    }

    /// Run `f` over the secret with its pages readable, and seal them
    /// again when the last running read returns (or panics). An error
    /// opening the pages means `f` did not run; an error sealing them
    /// again means it ran and its result is dropped, the pages being left
    /// readable.
    pub fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> Result<R, GuardError> {
        self.begin_read()?;
        let mut reading = Reading {
            guarded: self,
            ended: false,
        };
        // SAFETY: the pages are readable until end_read, and nothing
        // writes them while a `&self` exists.
        let result = f(unsafe { std::slice::from_raw_parts(self.secret_ptr(), self.len) });
        reading.ended = true;
        self.end_read()?;
        Ok(result)
    }

    /// Run `f` over the secret with its pages writable, and seal them
    /// again when it returns (or panics). Errors as for [`Self::with`].
    pub fn with_mut<R>(&mut self, f: impl FnOnce(&mut [u8]) -> R) -> Result<R, GuardError> {
        self.protect(libc::PROT_READ | libc::PROT_WRITE)?;
        let mut writing = Writing {
            guarded: self,
            ended: false,
        };
        let (ptr, len) = (writing.guarded.secret_ptr(), writing.guarded.len);
        // SAFETY: the pages are writable until the protect below, and
        // `&mut self` excludes every other access.
        let result = f(unsafe { std::slice::from_raw_parts_mut(ptr, len) });
        writing.ended = true;
        writing.guarded.protect(libc::PROT_NONE)?;
        Ok(result)
    }

    fn secret_ptr(&self) -> *mut u8 {
        // SAFETY: len <= data_pages_len, so the result is inside the data
        // pages or one past their end (for an empty secret).
        unsafe { self.data_pages.as_ptr().add(self.data_pages_len - self.len) }
    }

    fn protect(&self, prot: libc::c_int) -> Result<(), GuardError> {
        // SAFETY: the data pages are inside a mapping this value owns.
        let rc =
            unsafe { libc::mprotect(self.data_pages.as_ptr().cast(), self.data_pages_len, prot) };
        if rc == 0 {
            Ok(())
        } else {
            Err(GuardError::last_os_error("mprotect"))
        }
    }

    fn readers(&self) -> std::sync::MutexGuard<'_, usize> {
        // A panic in a reader's closure cannot leave the count wrong (the
        // count only changes in begin_read and end_read), so a poisoned
        // lock is still a good lock.
        self.readers.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn begin_read(&self) -> Result<(), GuardError> {
        let mut readers = self.readers();
        if *readers == 0 {
            self.protect(libc::PROT_READ)?;
        }
        *readers += 1;
        Ok(())
    }

    fn end_read(&self) -> Result<(), GuardError> {
        let mut readers = self.readers();
        *readers -= 1;
        if *readers == 0 {
            self.protect(libc::PROT_NONE)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn advise(&mut self) {
        // SAFETY: madvise on a mapping this value owns; neither flag
        // changes its contents.
        unsafe {
            self.protections.excluded_from_core_dumps = libc::madvise(
                self.mapping.as_ptr().cast(),
                self.mapping_len,
                libc::MADV_DONTDUMP,
            ) == 0;
            self.protections.wiped_on_fork = libc::madvise(
                self.data_pages.as_ptr().cast(),
                self.data_pages_len,
                libc::MADV_WIPEONFORK,
            ) == 0;
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn advise(&mut self) {}
}

/// Ends a [`GuardedBytes::with`] read that `f` left by panicking.
struct Reading<'a> {
    guarded: &'a GuardedBytes,
    ended: bool,
}

impl Drop for Reading<'_> {
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.guarded.end_read();
        }
    }
}

/// Seals the pages after a [`GuardedBytes::with_mut`] that `f` left by
/// panicking.
struct Writing<'a> {
    guarded: &'a mut GuardedBytes,
    ended: bool,
}

impl Drop for Writing<'_> {
    fn drop(&mut self) {
        if !self.ended {
            let _ = self.guarded.protect(libc::PROT_NONE);
        }
    }
}

impl Drop for GuardedBytes {
    fn drop(&mut self) {
        if self.protect(libc::PROT_READ | libc::PROT_WRITE).is_ok() {
            // SAFETY: the data pages were just made writable, and Drop has
            // the only access.
            let pages = unsafe {
                std::slice::from_raw_parts_mut(self.data_pages.as_ptr(), self.data_pages_len)
            };
            pages.zeroize();
            #[cfg(test)]
            tests::observe_wiped(pages);
            if self.protections.locked {
                // SAFETY: the range locked in zeroed.
                unsafe { libc::munlock(pages.as_ptr().cast(), pages.len()) };
            }
        }
        // If the pages could not be opened to wipe them, unmapping still
        // returns them to the kernel, which zero-fills a page before giving
        // it to anyone else.
        // SAFETY: the whole mapping, owned by this value and no longer used.
        unsafe { libc::munmap(self.mapping.as_ptr().cast(), self.mapping_len) };
    }
}

impl fmt::Debug for GuardedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuardedBytes")
            .field("len", &self.len)
            .field("protections", &self.protections)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
