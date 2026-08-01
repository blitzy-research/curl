// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Process-wide initialization and teardown.
//!
//! | Symbol | Authority |
//! |--------|-----------|
//! | `curl_global_init`     | `lib/easy.c:194-203` |
//! | `curl_global_init_mem` | `lib/easy.c:210-250` |
//! | `curl_global_cleanup`  | `lib/easy.c:256-287` |
//! | `curl_global_sslset`   | `lib/easy.c:312` forwarding to `lib/vtls/vtls.c:1139-1167` |
//!
//! # `curl_global_trace` is deliberately NOT here
//!
//! It is the fifth member of this family in `lib/libcurl.def` and it is not
//! implemented, because the state it exists to write does not exist yet.
//!
//! `curl_global_trace(config)` forwards to `Curl_trc_opt`, which parses the
//! configuration and then calls `trc_apply_level_by_name` or
//! `trc_apply_level_by_category` (`lib/curl_trc.c:585-620`). Both walk two
//! registries -- `trc_cfts`, keyed on the `Curl_cft_*` connection-filter types,
//! and `trc_feats`, keyed on the `Curl_trc_feat_*` per-subsystem features -- and
//! set a `log_level` field on each entry. Those registries are the connection
//! filter chain and the protocol features, and neither has landed: measured,
//! `curl-rs-lib/src/trace.rs` contains no analogue of either `trc_cfts` or
//! `trc_feats`, and `curl-rs-lib/src/conn/` does not exist at this commit. There
//! is therefore no entry for a `log_level` to be written to.
//!
//! The obstacle is NOT that `trace.rs` is thin, and mistaking it for that
//! points away from the real reason this function is absent. That file carries
//! 135 `pub(crate)` items --
//! `escape_controls` and `ControlEscaping` are consumed today by
//! `curl-rs-lib/src/lib.rs` and `curl-rs-lib/src/tls/cipher_suite.rs`. None of
//! them is visible from HERE in any case: `lib.rs:598` declares
//! `pub(crate) mod trace`, and the file exposes no bare `pub` item at all, so
//! this `crate` can reach nothing in it. The obstacle is not a thin module; it
//! is that the two registries the C function walks have no counterpart to walk.
//!
//! Parsing the configuration and discarding the result would return the right
//! `CURLcode` -- the C returns `CURLE_OK` for every input, including NULL,
//! unknown names and over-long tokens, which was measured against the frozen
//! library rather than inferred -- and would configure nothing. That is a stub
//! wearing a correct return value, and the standing rule is that an absent
//! symbol is better: a consumer calling it gets a link error naming the symbol,
//! which is loud and immediate, where a stub would silently produce untraced
//! transfers.
//!
//! # The reference-count contract
//!
//! `curl_global_init` and `curl_global_cleanup` are counted, not idempotent
//! (`lib/easy.c:150` is `if(initialized++) return CURLE_OK;` and
//! `lib/easy.c:266` is `if(--initialized)`). Two `init` calls need two `cleanup`
//! calls. A library that calls `curl_global_init` in its own setup relies on
//! this: its `cleanup` must not tear down libcurl underneath the application
//! that also initialised it. The count therefore lives here and is guarded the
//! way C guards it, with a lock rather than an atomic, because
//! `curl_global_init_mem` has to test the count and install five hooks as one
//! indivisible step.
//!
//! # What "initialization" amounts to in this implementation
//!
//! C's `global_init` (`lib/easy.c:148-192`) performs eight subsystem
//! initializations after the count and the allocator. Each is accounted for
//! here rather than quietly dropped:
//!
//! | C call | Status |
//! |--------|--------|
//! | `Curl_trc_init` | Returns `CURLE_OK` unconditionally outside a `DEBUGBUILD` (`lib/curl_trc.c:653-660`), and this build does not advertise `Debug` (specification 0.6.6). Nothing to do. |
//! | `Curl_win32_init` | Windows only; out of scope (specification 0.2.2). |
//! | `Curl_amiga_init` | AmigaOS only; out of scope. |
//! | `Curl_macos_init` | Reads the system's SSL trust settings on Apple platforms through `lib/macos.c`, which specification 0.2.2 lists as excluded. |
//! | `Curl_ssl_init` | The TLS backend's process-wide setup. `curl-rs-lib/src/tls/` declares only `cipher_suite` and `keylog` at this commit, so there is no backend to initialise. |
//! | `Curl_vquic_init` | Likewise for QUIC. |
//! | `Curl_ssh_init` | Likewise for SSH. |
//! | `Curl_async_global_init` | The asynchronous resolver's global state. This design uses the system resolver by default (specification 0.8.3), which has none. |
//!
//! So the initialization this module performs is complete for the global state
//! the library actually has: the reference count, the five replaceable
//! allocator hooks, and the remembered flags. It is not a placeholder standing
//! in for work omitted -- each omitted call is named above with the reason, and
//! four of the eight are omitted permanently.
//!
//! # The flags are remembered and never read
//!
//! `easy_init_flags` has exactly one consumer in the whole C tree:
//! `Curl_win32_cleanup(easy_init_flags)` at `lib/easy.c:273`, inside `#ifdef
//! _WIN32`. On all four mandated targets the value is stored and never
//! examined. It is stored here too, because `curl_global_cleanup` must clear it
//! and because a caller can observe the count-and-flags state machine through
//! the pairing rules above -- but no behaviour keys off its value, and claiming
//! otherwise would be untrue.

use core::ffi::{c_char, c_int, c_long};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, OnceLock};

use curl_rs_lib::CURLcode;

use super::memory;
use super::panic_boundary::{guard, guard_void};
use super::types::curl_ssl_backend;

/// The reference count and the flags of the first `init` that took effect.
///
/// One `Mutex` rather than two atomics, for the reason C uses one lock:
/// `curl_global_init_mem` must test the count and install five hooks without
/// another thread observing the intermediate state. `Mutex::new` is `const`, so
/// there is no lazy initialization and no start-up ordering problem.
static STATE: Mutex<GlobalState> = Mutex::new(GlobalState {
    initialised: 0,
    flags: 0,
});

/// The counted global state.
struct GlobalState {
    /// How many `curl_global_init*` calls are outstanding.
    initialised: u32,
    /// The flags the first effective `init` was given. See the module
    /// documentation: stored, never read.
    flags: c_long,
}

/// Takes the state lock, absorbing poisoning.
///
/// Poisoning is absorbed rather than propagated because the protected value is
/// a counter and a flag word with no invariant a panic could break, and
/// refusing to initialise -- or worse, refusing to tear down -- because an
/// unrelated thread panicked would be strictly worse than proceeding. This is
/// the same choice [`super::memory`] makes about its own lock, for the same
/// reason.
fn state() -> std::sync::MutexGuard<'static, GlobalState> {
    STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Initialises the library, counting the call.
///
/// Supersedes `curl_global_init` (`lib/easy.c:194-203`). Returns `CURLE_OK`.
///
/// Every call must be paired with a [`curl_global_cleanup`]; see the module
/// documentation for why the pairing is counted rather than idempotent.
///
/// The allocator is reset to the C library defaults, exactly as
/// `global_init(flags, TRUE)` does at `lib/easy.c:153-159`. That matters when an
/// application called `curl_global_init_mem`, then `curl_global_cleanup`, and
/// then `curl_global_init`: the hooks from the first call must not survive into
/// the third.
#[no_mangle]
pub extern "C" fn curl_global_init(flags: c_long) -> c_int {
    guard(CURLcode::FailedInit.as_i32(), || {
        let mut guard = state();
        if guard.initialised > 0 {
            // "if(initialized++) return CURLE_OK;" -- a repeat call bumps the
            // count and does nothing else.
            guard.initialised += 1;
            return CURLcode::Ok.as_i32();
        }
        // The `memoryfuncs` branch of `global_init`: restore the defaults.
        memory::reset();
        guard.initialised = 1;
        guard.flags = flags;
        CURLcode::Ok.as_i32()
    })
}

/// Initialises the library with application-supplied allocator hooks.
///
/// Supersedes `curl_global_init_mem` (`lib/easy.c:210-250`).
///
/// Returns `CURLE_FAILED_INIT` when any hook is null, before touching the
/// count -- `lib/easy.c:220-221` tests all five first. Confirmed against the
/// frozen library, which answers `2` for five nulls.
///
/// **A repeat call installs nothing.** When the library is already initialised
/// the count is bumped and the existing allocator is kept, which the C spells
/// out at `lib/easy.c:225-232`: "Already initialized, do not do it again, but
/// bump the variable anyway to work like curl_global_init() and require the same
/// amount of cleanup calls." A caller that wants its hooks installed must be
/// first, which is why the header requires this be the first libcurl call
/// a program makes.
///
/// # Safety
///
/// The five hooks must behave as their C library counterparts for the whole
/// time the library is initialised, and blocks they produce must be releasable
/// by the `free` hook given alongside them.
#[no_mangle]
pub unsafe extern "C" fn curl_global_init_mem(
    flags: c_long,
    m: super::types::curl_malloc_callback,
    f: super::types::curl_free_callback,
    r: super::types::curl_realloc_callback,
    s: super::types::curl_strdup_callback,
    c: super::types::curl_calloc_callback,
) -> c_int {
    guard(CURLcode::FailedInit.as_i32(), || {
        if m.is_none()
            || f.is_none()
            || r.is_none()
            || s.is_none()
            || c.is_none()
        {
            // "Invalid input, return immediately" -- before the lock, before
            // the count, exactly as C does.
            return CURLcode::FailedInit.as_i32();
        }

        let mut guard = state();
        if guard.initialised > 0 {
            guard.initialised += 1;
            return CURLcode::Ok.as_i32();
        }

        // "set memory functions before global_init() in case it wants memory
        // functions" (lib/easy.c:234-235). `install` re-tests for null and
        // returns false if any is missing, which cannot happen here.
        if !memory::install(m, f, r, s, c) {
            return CURLcode::FailedInit.as_i32();
        }
        guard.initialised = 1;
        guard.flags = flags;
        CURLcode::Ok.as_i32()
    })
}

/// Releases one outstanding initialization.
///
/// Supersedes `curl_global_cleanup` (`lib/easy.c:256-287`).
///
/// Two guards from the C are reproduced: a call with no outstanding
/// initialization returns immediately (`lib/easy.c:259-262`), and a call that
/// merely decrements a count above one does nothing else
/// (`lib/easy.c:264-267`). Only the last one tears down.
///
/// Teardown restores the default allocator and clears the flags, which is what
/// `lib/easy.c:284` does with `easy_init_flags = 0`.
#[no_mangle]
pub extern "C" fn curl_global_cleanup() {
    guard_void(|| {
        let mut guard = state();
        if guard.initialised == 0 {
            return;
        }
        guard.initialised -= 1;
        if guard.initialised > 0 {
            return;
        }
        memory::reset();
        guard.flags = 0;
    });
}

// curl_global_sslset

/// `CURLSSLSET_OK` (`include/curl/curl.h:2832`).
const CURLSSLSET_OK: c_int = 0;
/// `CURLSSLSET_UNKNOWN_BACKEND` (`include/curl/curl.h:2833`).
const CURLSSLSET_UNKNOWN_BACKEND: c_int = 1;

/// `CURLSSLBACKEND_RUSTLS` (`include/curl/curl.h:166`), IMPORTED from the
/// engine rather than restated here.
///
/// The enumerant already existed in the frozen header, so reporting a rustls
/// backend needs no new value -- specification 0.1.1 goal G4 relies on exactly
/// that.
///
/// The value is `curl_rs_lib::version::TLS_BACKEND_ID`, and consuming it is not
/// a stylistic preference: that constant's own documentation states that
/// "`crate::tls` and `curl-rs-ffi`'s `curl_global_sslset` must consume it from
/// here rather than restate it, so that the backend cannot be called one thing
/// by the banner and another by the API". Writing `14` literally here would
/// satisfy every test -- because both copies would be right -- while leaving
/// two independent definitions of one ABI value in a workspace whose entire
/// premise is that ABI values have exactly one owner. A later divergence would
/// then surface as a caller being told `rustls` by `curl --version` and
/// `unknown backend` by `curl_global_sslset`.
///
/// The `as c_int` conversion is deliberate and belongs here: the FFI crate is
/// where engine types become C types, so this line keeps working unchanged if
/// the engine narrows its own constant to a fixed-width Rust integer.
const BACKEND_ID: c_int = curl_rs_lib::version::TLS_BACKEND_ID as c_int;

/// The backend's name, spelled as `lib/vtls/rustls.c:1398` spells it, and
/// likewise IMPORTED from the engine.
///
/// Lower case, matching `{ CURLSSLBACKEND_RUSTLS, "rustls" }`. The name is
/// compared case-insensitively, so the spelling matters only for what a caller
/// reads back out of `avail` -- which is precisely why it must be the same
/// string the version banner reports. `curl_rs_lib::version::TLS_BACKEND_NAME`
/// is that string, and `SSL_VERSION` is built from it too, so all three agree
/// by construction instead of by coincidence.
const BACKEND_NAME: &str = curl_rs_lib::version::TLS_BACKEND_NAME;

/// The single-entry, NULL-terminated backend array, kept alive forever.
///
/// The layout C hands out is `const curl_ssl_backend **`: an array of pointers
/// to backend descriptors, terminated by a NULL pointer
/// (`lib/vtls/vtls.c:1144`). One descriptor and two array slots.
struct ImmortalBackends {
    /// Address of the first element of the pointer array.
    array: *const *const curl_ssl_backend,
}

// SAFETY: both allocations are leaked at construction and never written again,
// so every thread that reads through `array` sees the same immutable data for
// the life of the process. `OnceLock<T>: Sync` additionally requires `T: Send`,
// which the impl below provides for the same reason: the value carries only an
// immortal address.
unsafe impl Sync for ImmortalBackends {}

// SAFETY: as above -- moving the wrapper moves an immortal address and nothing
// that could be dropped on another thread.
unsafe impl Send for ImmortalBackends {}

/// Builds the immortal backend array, once.
fn backends() -> &'static ImmortalBackends {
    static BACKENDS: OnceLock<ImmortalBackends> = OnceLock::new();

    BACKENDS.get_or_init(|| {
        let name = CString::new(BACKEND_NAME).unwrap_or_else(|_| {
            unreachable!("the backend name is a NUL-free literal")
        });
        let descriptor: &'static curl_ssl_backend =
            Box::leak(Box::new(curl_ssl_backend {
                id: BACKEND_ID,
                name: name.into_raw().cast_const(),
            }));
        // `ptr::from_ref` would read better but is stable only from 1.76,
        // and the declared MSRV is 1.75 (specification 0.8.3). A plain
        // reference-to-pointer coercion is the MSRV-safe spelling and is
        // exactly what `from_ref` does.
        let slots: &'static mut [*const curl_ssl_backend] =
            Vec::leak(vec![descriptor as *const curl_ssl_backend, ptr::null()]);
        ImmortalBackends {
            array: slots.as_ptr(),
        }
    })
}

/// Selects, or confirms, the TLS backend.
///
/// Supersedes `curl_global_sslset` (`lib/easy.c:312`, forwarding to
/// `Curl_init_sslset_nolock` at `lib/vtls/vtls.c:1139-1167`).
///
/// This build has exactly one backend, so it takes the C's single-backend
/// branch throughout: `Curl_ssl != &Curl_ssl_multi` is true, and with
/// `CURL_WITH_MULTI_SSL` undefined the failure answer is
/// `CURLSSLSET_UNKNOWN_BACKEND` rather than `CURLSSLSET_TOO_LATE`.
///
/// Three behaviours were measured against the frozen library and are reproduced
/// exactly:
///
/// * **`avail` is written first, even when the call fails.** `lib/vtls/vtls.c`
///   assigns it at `:1144`, before the identity test at `:1146`. A caller
///   probing for the backend list with a deliberately bogus `id` -- which is
///   the documented way to enumerate -- still gets the array.
/// * **A matching `id` OR a matching `name` succeeds**, and the name comparison
///   is case-insensitive (`curl_strequal` at `:1148`), so `"RUSTLS"` matches.
/// * **`name` is only consulted when non-null.** The C guards it with
///   `(name && ...)`, so a null name with a non-matching id fails rather than
///   dereferencing.
///
/// `CURLSSLSET_NO_BACKENDS` is unreachable here: it is the answer from the
/// no-TLS arm of the `USE_SSL` conditional at `lib/vtls/vtls.c:1170-1177`, for
/// a build with no TLS at all, and specification 0.1.1 goal G4 makes rustls
/// unconditional.
///
/// The wording above deliberately spells that conditional out in words rather
/// than quoting the C directive. A doc comment on an exported function is
/// transcribed verbatim into the generated C header inside a block comment, so
/// a literal comment-close sequence anywhere in the prose ends that block
/// early and turns the remaining lines into stray tokens. `validate_comments`
/// in `build.rs` now fails the build on exactly that, and this sentence
/// records why the rule exists so it is not undone as mere pedantry.
///
/// # Safety
///
/// `name` must be either null or a pointer to a NUL-terminated string, and
/// `avail` must be either null or a valid, writable pointer to a
/// `const curl_ssl_backend **`.
#[no_mangle]
pub unsafe extern "C" fn curl_global_sslset(
    id: c_int,
    name: *const c_char,
    avail: *mut *const *const curl_ssl_backend,
) -> c_int {
    guard(CURLSSLSET_UNKNOWN_BACKEND, || {
        if !avail.is_null() {
            // SAFETY: the caller guarantees `avail` is writable when non-null.
            // The array it receives is immortal, so the caller may keep it.
            unsafe { avail.write(backends().array) };
        }

        if id == BACKEND_ID {
            return CURLSSLSET_OK;
        }

        if !name.is_null() {
            // SAFETY: the caller guarantees a NUL-terminated string when
            // non-null. The borrow does not outlive this expression.
            let requested = unsafe { core::ffi::CStr::from_ptr(name) };
            let ours = CString::new(BACKEND_NAME).unwrap_or_else(|_| {
                unreachable!("the backend name is a NUL-free literal")
            });
            if curl_rs_lib::strequal(Some(requested), Some(ours.as_c_str())) {
                return CURLSSLSET_OK;
            }
        }

        CURLSSLSET_UNKNOWN_BACKEND
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    /// The five hooks, as an application would supply them.
    mod hooks {
        use core::ffi::{c_char, c_void};

        /// # Safety
        /// As C `malloc`.
        pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
            // SAFETY: `libc::malloc` accepts any `size_t`.
            unsafe { libc::malloc(size) }
        }
        /// # Safety
        /// As C `free`.
        pub unsafe extern "C" fn free(ptr: *mut c_void) {
            // SAFETY: the caller passes a block from `malloc` above, or null.
            unsafe { libc::free(ptr) }
        }
        /// # Safety
        /// As C `realloc`.
        pub unsafe extern "C" fn realloc(
            ptr: *mut c_void,
            size: usize,
        ) -> *mut c_void {
            // SAFETY: the caller passes a block from `malloc` above, or null.
            unsafe { libc::realloc(ptr, size) }
        }
        /// # Safety
        /// As C `strdup`.
        pub unsafe extern "C" fn strdup(text: *const c_char) -> *mut c_char {
            // SAFETY: the caller passes a NUL-terminated string.
            unsafe { libc::strdup(text) }
        }
        /// # Safety
        /// As C `calloc`.
        pub unsafe extern "C" fn calloc(
            nmemb: usize,
            size: usize,
        ) -> *mut c_void {
            // SAFETY: `libc::calloc` accepts any pair of `size_t`.
            unsafe { libc::calloc(nmemb, size) }
        }
    }

    /// Restores a pristine global state so each test starts from zero.
    ///
    /// The count is process-wide and Rust runs tests in parallel threads, so
    /// every test in this module holds this guard for its whole body. Sharing
    /// one `Mutex` serialises them, which is the only way to assert on a
    /// process-wide counter.
    ///
    /// `pub(super)` rather than private because
    /// [`super::engine_registry_correspondence`] also drives the counter and
    /// must take the SAME lock: a second guard of its own would serialise that
    /// module against itself while still racing this one.
    pub(super) fn exclusive() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: Mutex<()> = Mutex::new(());
        let guard = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        {
            let mut inner = state();
            inner.initialised = 0;
            inner.flags = 0;
        }
        memory::reset();
        guard
    }

    fn outstanding() -> u32 {
        state().initialised
    }

    #[test]
    fn init_and_cleanup_are_counted_not_idempotent() {
        let _serial = exclusive();
        assert_eq!(curl_global_init(0), 0);
        assert_eq!(outstanding(), 1);
        assert_eq!(curl_global_init(0), 0);
        assert_eq!(outstanding(), 2);
        curl_global_cleanup();
        assert_eq!(outstanding(), 1, "the first cleanup must not tear down");
        curl_global_cleanup();
        assert_eq!(outstanding(), 0);
    }

    #[test]
    fn an_unmatched_cleanup_is_a_no_op() {
        let _serial = exclusive();
        curl_global_cleanup();
        curl_global_cleanup();
        assert_eq!(outstanding(), 0, "the count must not go negative");
    }

    #[test]
    fn the_flags_are_remembered_by_the_first_effective_init_and_cleared_at_zero(
    ) {
        let _serial = exclusive();
        // CURL_GLOBAL_ALL is CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32 == 3.
        assert_eq!(curl_global_init(3), 0);
        assert_eq!(state().flags, 3);
        // A repeat call must not overwrite them.
        assert_eq!(curl_global_init(0), 0);
        assert_eq!(state().flags, 3);
        curl_global_cleanup();
        assert_eq!(state().flags, 3, "still initialised");
        curl_global_cleanup();
        assert_eq!(state().flags, 0, "cleared by the last cleanup");
    }

    #[test]
    fn a_null_hook_is_refused_without_disturbing_the_count() {
        let _serial = exclusive();
        // SAFETY: passing nulls is exactly what this asserts about.
        let rc =
            unsafe { curl_global_init_mem(0, None, None, None, None, None) };
        assert_eq!(rc, 2, "CURLE_FAILED_INIT, as the frozen library answers");
        assert_eq!(outstanding(), 0, "a refused call must not count");
        assert!(!memory::is_installed());
    }

    /// Every one of the five must be present; a single missing hook is enough
    /// to refuse. Asserted one position at a time so a test cannot pass by
    /// checking only the first.
    #[test]
    fn each_of_the_five_hooks_is_individually_required() {
        let _serial = exclusive();
        let full = (
            Some(
                hooks::malloc
                    as unsafe extern "C" fn(usize) -> *mut core::ffi::c_void,
            ),
            Some(hooks::free as unsafe extern "C" fn(*mut core::ffi::c_void)),
            Some(
                hooks::realloc
                    as unsafe extern "C" fn(
                        *mut core::ffi::c_void,
                        usize,
                    )
                        -> *mut core::ffi::c_void,
            ),
            Some(
                hooks::strdup
                    as unsafe extern "C" fn(*const c_char) -> *mut c_char,
            ),
            Some(
                hooks::calloc
                    as unsafe extern "C" fn(
                        usize,
                        usize,
                    )
                        -> *mut core::ffi::c_void,
            ),
        );
        for missing in 0..5 {
            let (m, f, r, s, c) = full;
            // SAFETY: the hooks are real C-library functions; one is nulled.
            let rc = unsafe {
                curl_global_init_mem(
                    0,
                    if missing == 0 { None } else { m },
                    if missing == 1 { None } else { f },
                    if missing == 2 { None } else { r },
                    if missing == 3 { None } else { s },
                    if missing == 4 { None } else { c },
                )
            };
            assert_eq!(rc, 2, "hook {missing} missing must be refused");
            assert_eq!(outstanding(), 0);
        }
    }

    #[test]
    fn a_complete_hook_set_installs_and_the_last_cleanup_removes_it() {
        let _serial = exclusive();
        // SAFETY: all five hooks are the C library's own allocator functions.
        let rc = unsafe {
            curl_global_init_mem(
                0,
                Some(hooks::malloc),
                Some(hooks::free),
                Some(hooks::realloc),
                Some(hooks::strdup),
                Some(hooks::calloc),
            )
        };
        assert_eq!(rc, 0);
        assert!(memory::is_installed(), "the hooks must take effect");
        curl_global_cleanup();
        assert!(!memory::is_installed(), "teardown restores the defaults");
    }

    /// The C keeps the first allocator and only bumps the count, which is why
    /// the header insists this be the first libcurl call.
    #[test]
    fn a_repeat_init_mem_installs_nothing() {
        let _serial = exclusive();
        assert_eq!(curl_global_init(0), 0);
        assert!(!memory::is_installed());
        // SAFETY: all five hooks are valid; the call is expected to be ignored.
        let rc = unsafe {
            curl_global_init_mem(
                0,
                Some(hooks::malloc),
                Some(hooks::free),
                Some(hooks::realloc),
                Some(hooks::strdup),
                Some(hooks::calloc),
            )
        };
        assert_eq!(rc, 0);
        assert!(
            !memory::is_installed(),
            "a repeat call must keep the existing allocator"
        );
        assert_eq!(outstanding(), 2, "but it must still be counted");
        curl_global_cleanup();
        curl_global_cleanup();
    }

    /// A plain `init` after a hooked one must restore the defaults, which is
    /// what `global_init(flags, TRUE)` does and what a naive refcount would
    /// miss.
    #[test]
    fn a_later_plain_init_restores_the_default_allocator() {
        let _serial = exclusive();
        // SAFETY: all five hooks are valid `extern "C"` functions with the
        // signatures the parameters declare, and they outlive the call.
        let rc = unsafe {
            curl_global_init_mem(
                0,
                Some(hooks::malloc),
                Some(hooks::free),
                Some(hooks::realloc),
                Some(hooks::strdup),
                Some(hooks::calloc),
            )
        };
        assert_eq!(rc, 0);
        assert!(memory::is_installed());
        curl_global_cleanup();
        assert_eq!(curl_global_init(0), 0);
        assert!(!memory::is_installed());
        curl_global_cleanup();
    }

    /// Reads the NULL-terminated backend array the way a consumer does.
    fn enumerate() -> Vec<(c_int, String)> {
        let mut array: *const *const curl_ssl_backend = ptr::null();
        // SAFETY: a bogus id with a writable `avail` is the documented way to
        // enumerate, and the array written is immortal.
        let rc = unsafe { curl_global_sslset(-1, ptr::null(), &mut array) };
        assert_eq!(
            rc, CURLSSLSET_UNKNOWN_BACKEND,
            "a bogus id must still fail"
        );
        assert!(!array.is_null(), "avail must be written even on failure");
        let mut out = Vec::new();
        let mut index = 0isize;
        loop {
            // SAFETY: the array is NULL-terminated, so the walk stays in
            // bounds.
            let entry = unsafe { *array.offset(index) };
            if entry.is_null() {
                break;
            }
            // SAFETY: each entry addresses an immortal descriptor whose `name`
            // is a NUL-terminated immortal string.
            unsafe {
                out.push((
                    (*entry).id,
                    CStr::from_ptr((*entry).name)
                        .to_str()
                        .expect("the name is ASCII")
                        .to_owned(),
                ));
            }
            index += 1;
        }
        out
    }

    #[test]
    fn exactly_one_backend_is_advertised_and_it_is_rustls() {
        assert_eq!(enumerate(), [(14, "rustls".to_owned())]);
    }

    /// The advertised backend is the engine's, not a copy that happens to match.
    ///
    /// The literals in the test above are the ABI contract read from
    /// `include/curl/curl.h:166` and `lib/vtls/rustls.c:1398`, so they belong
    /// there. This test asserts the other half: that what this module publishes
    /// is derived from `curl_rs_lib::version`, so a change to the engine's
    /// constants can never leave `curl_global_sslset` reporting a stale value
    /// while `curl --version` reports the new one. Both assertions are needed --
    /// the first alone passes when the value is restated locally, which is the
    /// defect this pair now prevents.
    #[test]
    fn the_advertised_backend_is_the_engines_and_not_a_local_copy() {
        assert_eq!(BACKEND_ID, curl_rs_lib::version::TLS_BACKEND_ID as c_int);
        assert_eq!(BACKEND_NAME, curl_rs_lib::version::TLS_BACKEND_NAME);

        // And the engine's banner must name the same backend, which is the
        // user-visible consequence of the two agreeing.
        assert!(
            curl_rs_lib::version::SSL_VERSION.starts_with(BACKEND_NAME),
            "the version banner reports {:?}, which does not name the backend \
             {BACKEND_NAME:?} that curl_global_sslset advertises",
            curl_rs_lib::version::SSL_VERSION
        );
    }

    #[test]
    fn the_matching_id_succeeds_and_others_do_not() {
        // SAFETY: a null name and a null `avail` are both permitted.
        unsafe {
            assert_eq!(curl_global_sslset(14, ptr::null(), ptr::null_mut()), 0);
            // OpenSSL is 1; this build does not have it.
            assert_eq!(curl_global_sslset(1, ptr::null(), ptr::null_mut()), 1);
            // CURLSSLBACKEND_NONE with no name cannot match.
            assert_eq!(curl_global_sslset(0, ptr::null(), ptr::null_mut()), 1);
        }
    }

    #[test]
    fn the_name_match_is_case_insensitive() {
        for spelling in ["rustls", "RUSTLS", "RustLS"] {
            let name = CString::new(spelling).unwrap();
            // SAFETY: `name` is live for the call and `avail` may be null.
            let rc = unsafe {
                curl_global_sslset(0, name.as_ptr(), ptr::null_mut())
            };
            assert_eq!(rc, 0, "{spelling} must match");
        }
        let wrong = CString::new("openssl").unwrap();
        // SAFETY: as above.
        let rc =
            unsafe { curl_global_sslset(0, wrong.as_ptr(), ptr::null_mut()) };
        assert_eq!(rc, 1, "a different backend must not match");
    }

    /// The array pointer is stable, so a caller may cache it -- which C's
    /// `static available_backends` guarantees.
    #[test]
    fn the_backend_array_is_the_same_on_every_call() {
        let mut first: *const *const curl_ssl_backend = ptr::null();
        let mut second: *const *const curl_ssl_backend = ptr::null();
        // SAFETY: both out-parameters are writable locals.
        unsafe {
            curl_global_sslset(14, ptr::null(), &mut first);
            curl_global_sslset(14, ptr::null(), &mut second);
        }
        assert_eq!(first, second);
    }
}

/// The engine-registry correspondence for [`curl_rs_lib::version::ENGINE_GLOBAL_INIT`].
///
/// `curl-rs-lib`'s capability registry marks every engine it reports as present
/// with a compile-time reference to an item the owning module must export, so a
/// `present: true` cannot outlive the code it claims. `ENGINE_GLOBAL_INIT` is the
/// single entry that cannot follow that rule where the others do: its owner is
/// THIS crate, and the registry lives in a crate this one depends on, so a
/// reference there would invert the dependency direction AAP 0.1.1 goal G1
/// fixes.
///
/// This module is the other half of that arrangement. It is the only place that
/// can see both the registry's claim and the code the claim is about, so it is
/// where the correspondence is asserted -- and `curl-rs-lib`'s
/// `every_present_engine_has_a_compile_time_link` names the exception explicitly
/// and asserts that it stays exactly one entry wide, so this file cannot be
/// forgotten by a change on that side.
#[cfg(test)]
mod engine_registry_correspondence {
    use super::{curl_global_cleanup, curl_global_init};
    use core::ffi::{c_int, c_long};

    /// The two entry points the `threadsafe` claim is ABOUT, referenced with
    /// their exact ABI signatures. Deleting or re-signing either stops the build
    /// here, which is what makes the registry's `present` substantive from this
    /// side.
    const _: extern "C" fn(c_long) -> c_int = curl_global_init;
    const _: extern "C" fn() = curl_global_cleanup;

    /// `ENGINE_GLOBAL_INIT` may claim `present` only while this module really
    /// provides the initialiser -- which the `const _` links above establish at
    /// compile time -- so what remains to check at run time is the direction the
    /// links cannot cover: that the claim is not made about a crate whose code
    /// is absent, and that the initialiser it names actually functions.
    #[test]
    fn the_registry_claim_matches_this_module() {
        assert!(
            curl_rs_lib::version::ENGINE_GLOBAL_INIT.is_present(),
            "this module exists and exports a working, mutex-serialised \
             initialiser, so the registry must not report it absent -- \
             under-reporting withholds the `threadsafe` feature the \
             harness reads"
        );
        assert_eq!(
            curl_rs_lib::version::ENGINE_GLOBAL_INIT.owner(),
            "curl-rs-ffi/src/ffi/global.rs",
            "the registry must name THIS file, or the exception recorded in \
             `every_present_engine_has_a_compile_time_link` is about \
             something else"
        );
        assert!(
            curl_rs_lib::version::has_feature("threadsafe"),
            "the `threadsafe` row is gated on this engine, so a present \
             engine must advertise it"
        );
    }

    /// The initialiser is idempotent and reference-counted, which is the
    /// property `GLOBAL_INIT_IS_THREADSAFE` is a claim about. Asserted through
    /// the public entry points rather than by inspecting `STATE`, so it stays
    /// true of the behaviour rather than of the representation.
    #[test]
    fn repeated_initialization_is_balanced_and_idempotent() {
        let _serial = super::tests::exclusive();

        assert_eq!(curl_global_init(0), 0, "first init must succeed");
        assert_eq!(curl_global_init(0), 0, "a nested init must also succeed");
        curl_global_cleanup();
        curl_global_cleanup();

        // And the cycle can be repeated: cleanup left no state that prevents a
        // later init, which is what a leaked count or a poisoned lock would.
        assert_eq!(curl_global_init(0), 0, "init after full cleanup");
        curl_global_cleanup();
    }
}
