// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! libcurl's five replaceable allocator hooks.
//!
//! This is the Rust counterpart of `Curl_cmalloc`, `Curl_cfree`,
//! `Curl_crealloc`, `Curl_cstrdup` and `Curl_ccalloc`
//! (`lib/easy.c:106-110`), and it backs `curl_global_init_mem`. Read the
//! crate-level documentation for the scope of what these hooks observe:
//! every buffer this crate hands to C passes through them, and the
//! engine's internal Rust allocations do not, which is a deviation stated
//! there in full along with the two measurements that force it.
//!
//! The hook types below mirror the five typedefs at
//! `include/curl/curl.h:469-473`. They are private and are given names
//! distinct from the C typedefs on purpose: the ABI typedefs belong to the
//! verbatim header text that `cbindgen.toml` and `ffi/handle.rs` own, and
//! nothing here should be mistaken for them or collide with them. The
//! `[export] include` allow-list in `cbindgen.toml` independently keeps
//! them out of the generated header.
//!
//! # Why every entry point here carries its own `dead_code` allowance
//!
//! The five hooks are installed by `curl_global_init_mem` and consumed by every
//! export that hands a buffer to C, so until those modules name them they are
//! legitimately unreferenced -- and the lint gate admits no warning. As in
//! [`super::panic_boundary`], the allowance is written **per item** rather than
//! on the module, so a new unreferenced item still warns and the suppression
//! cannot grow to cover incomplete work. Each allowance is removed by the
//! change that gives its function a caller.

use core::ffi::{c_char, c_void};
use core::ptr;
use std::ffi::CStr;
use std::sync::Mutex;

/// Mirrors `curl_malloc_callback` (`include/curl/curl.h:469`).
type MallocFn = unsafe extern "C" fn(usize) -> *mut c_void;
/// Mirrors `curl_free_callback` (`include/curl/curl.h:470`).
type FreeFn = unsafe extern "C" fn(*mut c_void);
/// Mirrors `curl_realloc_callback` (`include/curl/curl.h:471`).
type ReallocFn = unsafe extern "C" fn(*mut c_void, usize) -> *mut c_void;
/// Mirrors `curl_strdup_callback` (`include/curl/curl.h:472`).
type StrdupFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;
/// Mirrors `curl_calloc_callback` (`include/curl/curl.h:473`).
type CallocFn = unsafe extern "C" fn(usize, usize) -> *mut c_void;

/// All five hooks, stored and replaced as a single value.
///
/// Grouping them is not a convenience. `curl_global_init_mem` takes
/// all five together, and a set that were installed one at a time
/// could be observed half-replaced by another thread, which would
/// pair one allocator's `malloc` with another's `free`. A tuple is
/// used rather than a named struct so that this module declares no
/// type that could be confused with an ABI type.
type Hooks = (MallocFn, FreeFn, ReallocFn, StrdupFn, CallocFn);

/// `None` means the C library defaults are in force.
///
/// A `Mutex` rather than a set of atomics, for two reasons. It makes
/// the five-at-once replacement above trivially correct, and it needs
/// no transmute between a function pointer and an integer, so this
/// module stores no address it has to reconstitute. `Mutex::new` is a
/// `const` constructor, so there is no lazy initialization and no
/// start-up ordering problem. These paths run when a buffer crosses
/// the C boundary, not in any hot loop, so the lock is not on a
/// critical path.
static HOOKS: Mutex<Option<Hooks>> = Mutex::new(None);

/// Copies the installed hooks out, if any are installed.
///
/// The copy is taken so that the lock is released before any hook
/// runs. A callback that re-entered libcurl while the lock was held
/// would deadlock, and function pointers are `Copy`, so avoiding it
/// costs nothing. Poisoning is absorbed rather than propagated: the
/// protected value is five function pointers with no invariant a
/// panic could break, and refusing to release memory because an
/// unrelated thread panicked would be strictly worse than proceeding.
fn snapshot() -> Option<Hooks> {
    *HOOKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Installs a complete hook set, as `curl_global_init_mem` does.
///
/// Returns `false`, and installs nothing, when any hook is null. That
/// is exactly what `lib/easy.c:220-221` tests before returning
/// `CURLE_FAILED_INIT`. Choosing that `CURLcode` is the caller's job,
/// which is what keeps this module free of ABI enumerations.
///
/// The replacement is legal only before any other libcurl call, per
/// `include/curl/curl.h:2743-2745`, because a block must be released
/// by the allocator that produced it. Nothing here can enforce that
/// ordering, and pretending otherwise would be worse than saying so.
#[allow(dead_code)]
pub(crate) fn install(
    malloc: Option<MallocFn>,
    free: Option<FreeFn>,
    realloc: Option<ReallocFn>,
    strdup: Option<StrdupFn>,
    calloc: Option<CallocFn>,
) -> bool {
    let (Some(m), Some(f), Some(r), Some(s), Some(c)) =
        (malloc, free, realloc, strdup, calloc)
    else {
        return false;
    };
    *HOOKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        Some((m, f, r, s, c));
    true
}

/// Restores the C library defaults, as `lib/easy.c:129-133` does.
#[allow(dead_code)]
pub(crate) fn reset() {
    *HOOKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

/// Whether application-supplied hooks are currently in force.
#[allow(dead_code)]
pub(crate) fn is_installed() -> bool {
    snapshot().is_some()
}

/// Allocates `size` bytes for the C caller to own.
///
/// Returns null on failure, as C `malloc` does. A `size` of zero is
/// forwarded unchanged, so the result is whatever the active allocator
/// returns for it, which is the same latitude C libcurl allows.
#[allow(dead_code)]
pub(crate) fn malloc(size: usize) -> *mut c_void {
    match snapshot() {
        Some((hook, ..)) => {
            // SAFETY: `hook` reached `install` as a
            // `curl_malloc_callback`, whose contract at
            // `include/curl/curl.h:2763-2768` is that it behaves as
            // `malloc`; `install` rejected null. No value of `size`
            // can make the call itself unsound.
            unsafe { hook(size) }
        }
        None => {
            // SAFETY: `libc::malloc` has no precondition beyond a
            // valid `size_t`, and every `usize` is one on all four
            // supported targets, which are all 64-bit Unix.
            unsafe { libc::malloc(size) }
        }
    }
}

/// Allocates `nmemb * size` zeroed bytes for the C caller to own.
#[allow(dead_code)]
pub(crate) fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    match snapshot() {
        Some((_, _, _, _, hook)) => {
            // SAFETY: `hook` reached `install` as a
            // `curl_calloc_callback` and is non-null. Overflow of
            // `nmemb * size` is the allocator's to detect and report
            // by returning null, exactly as C `calloc` must.
            unsafe { hook(nmemb, size) }
        }
        None => {
            // SAFETY: `libc::calloc` has no precondition beyond two
            // valid `size_t` arguments and reports overflow by
            // returning null.
            unsafe { libc::calloc(nmemb, size) }
        }
    }
}

/// Resizes a block obtained from this module.
///
/// # Safety
///
/// `ptr` must be null, or a live block previously returned by this
/// module while the *same* hook set was in force. Passing null is
/// well defined and allocates, as C `realloc` requires.
#[allow(dead_code)]
pub(crate) unsafe fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    match snapshot() {
        Some((_, _, hook, _, _)) => {
            // SAFETY: `hook` reached `install` as a
            // `curl_realloc_callback` and is non-null, and this
            // function's own contract has already obliged the caller
            // to pass a pointer that hook set produced.
            unsafe { hook(ptr, size) }
        }
        None => {
            // SAFETY: this function's contract obliges the caller to
            // pass null or a live block from the same default path,
            // which is `libc::realloc`'s only precondition.
            unsafe { libc::realloc(ptr, size) }
        }
    }
}

/// Releases a block obtained from this module.
///
/// Null is forwarded to the hook rather than filtered out, because C
/// `free` defines it as a no-op and libcurl does pass it -- the
/// `Curl_safefree` idiom releases unconditionally -- so filtering
/// would hide calls an accounting hook legitimately expects to see.
///
/// # Safety
///
/// `ptr` must be null, or a live block previously returned by this
/// module while the *same* hook set was in force, and must not have
/// been released already. Releasing across a hook replacement is the
/// mismatch the crate-level documentation describes, which is why
/// `curl_global_init_mem` may only be called before anything else.
#[allow(dead_code)]
pub(crate) unsafe fn free(ptr: *mut c_void) {
    match snapshot() {
        Some((_, hook, _, _, _)) => {
            // SAFETY: `hook` reached `install` as a
            // `curl_free_callback` and is non-null, and this
            // function's contract has already obliged the caller to
            // pass a pointer that hook set produced, or null.
            unsafe { hook(ptr) }
        }
        None => {
            // SAFETY: this function's contract obliges the caller to
            // pass null or a live block from the same default path,
            // which is `libc::free`'s only precondition.
            unsafe { libc::free(ptr) }
        }
    }
}

/// Duplicates a C string into caller-owned memory.
///
/// A null input yields null instead of undefined behaviour. That is a
/// deliberate and stated divergence: the default hook is the C
/// library's `strdup` (`lib/curl_setup.h:1450` defines
/// `CURLX_STRDUP_LOW` as `strdup`), which has no defined behaviour on
/// null, and libcurl simply never passes it one. Guarding costs a
/// branch, is indistinguishable to every conforming caller, and turns
/// a latent undefined behaviour into a null return.
///
/// When no hook is installed the copy is made through this module's own
/// `malloc` rather than by calling the C library's `strdup`. The two
/// are indistinguishable to a caller -- curl's own default reaches
/// `malloc` through `strdup` anyway -- and routing through `malloc`
/// buys two things. The duplicate provably comes from the same
/// allocator as everything else here, so releasing it with `free` is
/// symmetric by construction rather than by coincidence; and it keeps
/// the module executable under Miri, which shims `malloc`, `calloc`,
/// `realloc`, `free` and `strlen` but rejects `strdup` outright as an
/// unsupported operation: it cannot call that foreign function. That
/// was measured, not assumed, and it would otherwise have made the
/// crate's own tests unrunnable under a required gate.
///
/// # Safety
///
/// `s` must be null, or a pointer to a NUL-terminated C string that
/// stays valid and unmodified for the duration of the call.
#[allow(dead_code)]
pub(crate) unsafe fn strdup(s: *const c_char) -> *mut c_char {
    if s.is_null() {
        return ptr::null_mut();
    }
    if let Some((_, _, _, hook, _)) = snapshot() {
        // SAFETY: `hook` reached `install` as a
        // `curl_strdup_callback` and is non-null; `s` is non-null and
        // NUL-terminated by this function's own contract, which is
        // all `strdup` requires.
        return unsafe { hook(s) };
    }
    // SAFETY: `s` is non-null and points to a NUL-terminated string
    // that stays valid for the call, by this function's contract, so
    // the borrow ends before anything can invalidate it. The bytes it
    // yields exclude the terminator, which `copy_to_c_string` adds
    // back.
    let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
    copy_to_c_string(bytes)
}

/// Copies `bytes` into caller-owned C memory and appends a NUL.
///
/// This is the primitive behind every entry point that returns a
/// string the application later releases with `curl_free`, such as
/// `curl_escape`, `curl_easy_escape`, `curl_maprintf` and
/// `curl_getenv`. Going through it rather than through
/// `CString::into_raw` is what makes those buffers the application's
/// own allocator's, so that `curl_free` -- and a plain `free`, which
/// applications do use -- behave exactly as against C libcurl.
///
/// Returns null if the allocation fails or if the length plus its
/// terminator would overflow. `bytes` is copied verbatim, so an
/// interior NUL is preserved in the buffer and simply terminates the
/// string early as far as C is concerned; callers that must reject
/// that case check before calling, which is where the knowledge of
/// whether it matters lives.
#[allow(dead_code)]
pub(crate) fn copy_to_c_string(bytes: &[u8]) -> *mut c_char {
    let Some(total) = bytes.len().checked_add(1) else {
        return ptr::null_mut();
    };
    let block = malloc(total);
    if block.is_null() {
        return ptr::null_mut();
    }
    let out = block.cast::<u8>();
    // SAFETY: `malloc` returned a non-null block of `total` bytes,
    // and `total` is `bytes.len() + 1`, so the copy of `bytes.len()`
    // bytes at offset 0 and the single terminator at offset
    // `bytes.len()` both land inside it. `bytes` is a live borrowed
    // slice, so it cannot overlap a block allocated after it, which
    // is what `copy_nonoverlapping` requires. The destination is a
    // fresh byte allocation, so it has no alignment requirement
    // beyond one.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
        out.add(bytes.len()).write(0);
    }
    out.cast::<c_char>()
}

#[cfg(test)]
mod tests {
    use crate::ffi::memory;

    use core::ffi::{c_char, c_void};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::ffi::CStr;
    use std::sync::{Mutex, MutexGuard};

    /// Serialises the tests that touch the process-wide hook registry.
    ///
    /// `memory`'s state is global by necessity, and the test harness runs
    /// tests on concurrent threads, so anything that installs or resets
    /// hooks has to take this first. Poisoning is absorbed for the same
    /// reason the registry absorbs it: a failure in one test must not turn
    /// every later test into a spurious failure.
    static REGISTRY: Mutex<()> = Mutex::new(());

    fn registry_lock() -> MutexGuard<'static, ()> {
        REGISTRY
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Invocation counters for the test hooks below.
    static MALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static REALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
    static STRDUP_CALLS: AtomicUsize = AtomicUsize::new(0);
    static CALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);

    // The five hooks an application would pass to `curl_global_init_mem`.
    // Each records that it ran and then delegates to the C library, so a
    // block they produce is releasable by the matching hook and the test
    // observes routing without changing allocation behaviour.

    unsafe extern "C" fn test_malloc(size: usize) -> *mut c_void {
        MALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `libc::malloc` requires only a valid `size_t`.
        unsafe { libc::malloc(size) }
    }

    unsafe extern "C" fn test_free(ptr: *mut c_void) {
        FREE_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: this hook is only ever reached through `memory::free`,
        // whose contract obliges the caller to pass null or a live block
        // that `test_malloc`, `test_calloc` or `test_realloc` produced,
        // all of which allocate through `libc`.
        unsafe { libc::free(ptr) }
    }

    unsafe extern "C" fn test_realloc(
        ptr: *mut c_void,
        size: usize,
    ) -> *mut c_void {
        REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: reached only through `memory::realloc`, whose contract
        // obliges the caller to pass null or a live block from this same
        // hook set, which allocates through `libc`.
        unsafe { libc::realloc(ptr, size) }
    }

    /// Duplicates through `memory::copy_to_c_string`, which reaches
    /// `memory::malloc` and therefore `test_malloc`. That is intentional:
    /// it makes this test assert composition -- a hooked `strdup` whose
    /// storage comes from the hooked `malloc` -- rather than merely
    /// assert that one hook fired. It also keeps the test free of
    /// `libc::strdup`, which Miri refuses to call.
    unsafe extern "C" fn test_strdup(s: *const c_char) -> *mut c_char {
        STRDUP_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: reached only through `memory::strdup`, which has already
        // rejected null and whose contract obliges the caller to pass a
        // NUL-terminated string valid for the call, so the borrow ends
        // before anything can invalidate it.
        let bytes = unsafe { CStr::from_ptr(s) }.to_bytes();
        memory::copy_to_c_string(bytes)
    }

    unsafe extern "C" fn test_calloc(nmemb: usize, size: usize) -> *mut c_void {
        CALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: `libc::calloc` requires only two valid `size_t` values.
        unsafe { libc::calloc(nmemb, size) }
    }

    fn install_test_hooks() -> bool {
        memory::install(
            Some(test_malloc),
            Some(test_free),
            Some(test_realloc),
            Some(test_strdup),
            Some(test_calloc),
        )
    }

    #[test]
    fn install_rejects_an_incomplete_hook_set() {
        let _guard = registry_lock();
        // Each of the five positions is exercised as the missing one,
        // because `lib/easy.c:220-221` rejects on any of them.
        assert!(!memory::install(
            None,
            Some(test_free),
            Some(test_realloc),
            Some(test_strdup),
            Some(test_calloc),
        ));
        assert!(!memory::install(
            Some(test_malloc),
            None,
            Some(test_realloc),
            Some(test_strdup),
            Some(test_calloc),
        ));
        assert!(!memory::install(
            Some(test_malloc),
            Some(test_free),
            None,
            Some(test_strdup),
            Some(test_calloc),
        ));
        assert!(!memory::install(
            Some(test_malloc),
            Some(test_free),
            Some(test_realloc),
            None,
            Some(test_calloc),
        ));
        assert!(!memory::install(
            Some(test_malloc),
            Some(test_free),
            Some(test_realloc),
            Some(test_strdup),
            None,
        ));
        // A rejected set must leave the previous state untouched.
        assert!(!memory::is_installed());
    }

    #[test]
    fn the_default_path_round_trips_an_allocation() {
        let _guard = registry_lock();
        memory::reset();
        let block = memory::malloc(32);
        assert!(!block.is_null());
        // SAFETY: `malloc` returned a live 32-byte block, so writing one
        // byte at offset 0 is in bounds, and a fresh byte allocation has
        // no alignment requirement beyond one.
        unsafe { block.cast::<u8>().write(0xAB) };
        // SAFETY: `block` came from `memory::malloc` under the same hook
        // set, which is still the default one, and is released once.
        unsafe { memory::free(block) };

        let zeroed = memory::calloc(4, 8);
        assert!(!zeroed.is_null());
        let start = zeroed.cast::<u8>();
        // SAFETY: `calloc` returned a live 32-byte block, so a 32-byte read
        // from its start is in bounds, and `calloc` guarantees it is zeroed.
        let bytes = unsafe { core::slice::from_raw_parts(start, 32) };
        assert!(bytes.iter().all(|byte| *byte == 0));
        // SAFETY: as above, released exactly once.
        unsafe { memory::free(zeroed) };
    }

    #[test]
    fn installed_hooks_receive_every_boundary_allocation() {
        let _guard = registry_lock();
        let malloc_before = MALLOC_CALLS.load(Ordering::Relaxed);
        let free_before = FREE_CALLS.load(Ordering::Relaxed);
        let calloc_before = CALLOC_CALLS.load(Ordering::Relaxed);
        let realloc_before = REALLOC_CALLS.load(Ordering::Relaxed);
        let strdup_before = STRDUP_CALLS.load(Ordering::Relaxed);

        assert!(install_test_hooks());
        assert!(memory::is_installed());

        let block = memory::malloc(16);
        assert!(!block.is_null());
        // SAFETY: `block` is a live 16-byte block from the hook set that
        // is still installed, and 32 bytes is a valid new size.
        let grown = unsafe { memory::realloc(block, 32) };
        assert!(!grown.is_null());
        // SAFETY: `grown` is the live block that `realloc` returned under
        // the still-installed hook set, released exactly once. `block` is
        // not released: `realloc` already consumed it.
        unsafe { memory::free(grown) };

        let zeroed = memory::calloc(2, 8);
        assert!(!zeroed.is_null());
        // SAFETY: live block from the installed hooks, released once.
        unsafe { memory::free(zeroed) };

        let source = CStr::from_bytes_with_nul(b"curl\0").unwrap();
        let malloc_pre_strdup = MALLOC_CALLS.load(Ordering::Relaxed);
        // SAFETY: `CStr::as_ptr` yields a NUL-terminated string that
        // outlives the call, which is `strdup`'s only precondition.
        let copy = unsafe { memory::strdup(source.as_ptr()) };
        assert!(!copy.is_null());
        // SAFETY: `copy` is NUL-terminated because `strdup` copies through
        // the terminator, and it stays valid until released below.
        assert_eq!(unsafe { CStr::from_ptr(copy) }, source);
        // Composition, not just dispatch: `test_strdup` obtains its
        // storage from `memory::malloc`, so the hooked `malloc` must have
        // fired again while servicing the hooked `strdup`. A hook set that
        // dispatched `strdup` but bypassed `malloc` would pass every other
        // assertion in this test and fail this one.
        assert!(MALLOC_CALLS.load(Ordering::Relaxed) > malloc_pre_strdup);
        // SAFETY: live block from the installed hooks, released once.
        unsafe { memory::free(copy.cast::<c_void>()) };

        assert!(MALLOC_CALLS.load(Ordering::Relaxed) > malloc_before);
        assert!(REALLOC_CALLS.load(Ordering::Relaxed) > realloc_before);
        assert!(CALLOC_CALLS.load(Ordering::Relaxed) > calloc_before);
        assert!(STRDUP_CALLS.load(Ordering::Relaxed) > strdup_before);
        assert!(FREE_CALLS.load(Ordering::Relaxed) > free_before);

        memory::reset();
        assert!(!memory::is_installed());
    }

    #[test]
    fn strdup_maps_null_to_null_rather_than_to_undefined_behaviour() {
        let _guard = registry_lock();
        memory::reset();
        // SAFETY: null is explicitly permitted by `strdup`'s contract and
        // is the case under test.
        let copy = unsafe { memory::strdup(core::ptr::null()) };
        assert!(copy.is_null());
    }

    #[test]
    fn copy_to_c_string_nul_terminates_and_is_caller_freeable() {
        let _guard = registry_lock();
        memory::reset();
        let buffer = memory::copy_to_c_string(b"https://curl.se/");
        assert!(!buffer.is_null());
        // SAFETY: `copy_to_c_string` wrote a NUL after the payload, so the
        // block is a valid C string that stays live until released.
        let seen = unsafe { CStr::from_ptr(buffer) };
        assert_eq!(seen.to_bytes(), b"https://curl.se/");
        // SAFETY: the block came from `copy_to_c_string` under the default
        // hook set, which is still in force, and is released once.
        unsafe { memory::free(buffer.cast::<c_void>()) };

        // The empty case must still produce a one-byte NUL-terminated
        // buffer rather than null, because a caller cannot distinguish
        // "empty" from "failed" otherwise.
        let empty = memory::copy_to_c_string(b"");
        assert!(!empty.is_null());
        // SAFETY: as above; the single byte written is the terminator.
        assert_eq!(unsafe { CStr::from_ptr(empty) }.to_bytes(), b"");
        // SAFETY: as above, released exactly once.
        unsafe { memory::free(empty.cast::<c_void>()) };
    }

    #[test]
    fn the_registry_tolerates_concurrent_readers() {
        let _guard = registry_lock();
        memory::reset();
        // `curl_global_init` and `curl_global_trace` are documented
        // thread-safe at `include/curl/curl.h:2744-2745` and `:2788-2789`,
        // so the state behind them must be too. Several threads allocate
        // and release through the registry at once; the test passes if it
        // neither deadlocks nor observes a torn hook set.
        let threads: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    for _ in 0..64 {
                        let block = memory::malloc(8);
                        assert!(!block.is_null());
                        // SAFETY: a live block from the hook set in force
                        // for this iteration, released exactly once.
                        unsafe { memory::free(block) };
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("registry access must not panic");
        }
    }
}
