// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Process-wide initialization, teardown, allocator replacement, trace
//! configuration and TLS-backend selection.
//!
//! The five symbols this module owns -- its whole share of the 100 names in
//! `lib/libcurl.def`, each defined exactly once here and nowhere else in the
//! crate, because a duplicate is a link error:
//!
//! | Symbol | Declared | Implemented from |
//! |--------|----------|------------------|
//! | `curl_global_init`     | `curl.h:2748`      | `lib/easy.c:197-208` |
//! | `curl_global_init_mem` | `curl.h:2763-2768` | `lib/easy.c:213-249` |
//! | `curl_global_cleanup`  | `curl.h:2778`      | `lib/easy.c:255-286` |
//! | `curl_global_trace`    | `curl.h:2791`      | `lib/easy.c:292-308` |
//! | `curl_global_sslset`   | `curl.h:2838`      | `lib/easy.c:312-321` |
//!
//! `curl_global_sslset` forwards in C to `Curl_init_sslset_nolock`
//! (`lib/vtls/vtls.c:1139-1166`) and `curl_global_trace` to `Curl_trc_opt`
//! (`lib/curl_trc.c:639-651`); both bodies are reproduced below at those
//! authorities rather than approximated.
//!
//! # `curl_global_cleanup` returns `void`, so it has no error channel
//!
//! The asymmetry with `curl_global_init` is easy to miss and it decides the
//! whole containment strategy for this file. There is no `CURLcode` to hand
//! back, so a panic reaching that boundary can only be **swallowed**: it goes
//! through the crate's single `catch_unwind` -- [`super::panic_boundary`],
//! reached here as `guard_void` -- which discards the payload and returns.
//! Nothing on this path writes to standard error, and that is a hard
//! requirement rather than tidiness: 1,476 of the 1,914 fixtures compare
//! emitted bytes exactly, so a diagnostic printed from a library teardown
//! would corrupt a comparison that has nothing to do with it. `panic_boundary`
//! replaces the default hook for the same reason.
//!
//! Aborting is not the strategy either. The root manifest prohibits
//! `panic = "abort"` and names this crate as the reason -- unwinding across the
//! C ABI must be *contained*, not escalated into killing the host process --
//! and `[profile.*]` is root-only, so a member profile would be ignored and
//! would warn, which the zero-warnings gate turns into a build failure.
//!
//! # Null pointers, and the argument error none of the five returns
//!
//! The crate-wide rule is that every raw pointer from C is null-checked before
//! use and a violation returns the family-correct error. Both halves hold here
//! -- nothing below dereferences an unchecked pointer -- but the
//! family-correct answer in this family is never
//! `CURLE_BAD_FUNCTION_ARGUMENT`, because in C no pointer these five take is
//! required to be non-null:
//!
//! * `curl_global_trace(NULL)` is **success**. `Curl_trc_opt` is
//!   `config ? trc_opt(config) : CURLE_OK` (`lib/curl_trc.c:641`).
//! * `curl_global_sslset` with a null `avail` simply does not write it
//!   (`lib/vtls/vtls.c:1144`), and with a null `name` skips the name
//!   comparison (`:1149`); both are ordinary, documented ways to call it.
//! * `curl_global_init_mem` takes function pointers, and a null one is refused
//!   with `CURLE_FAILED_INIT` rather than an argument error, because that is
//!   the code `lib/easy.c:220-221` returns.
//! * `curl_global_init` and `curl_global_cleanup` take no pointer at all.
//!
//! Inventing a stricter contract than the authority's would be a behaviour
//! change, which is the one thing this work may not do.
//!
//! # The reference-count contract is ABI-visible
//!
//! `curl_global_init` and `curl_global_cleanup` are counted, not idempotent:
//! `lib/easy.c:126` is `if(initialized++) return CURLE_OK;` and `:264` is
//! `if(--initialized)`. Two `init` calls therefore need two `cleanup` calls. A
//! library that initialises libcurl in its own setup depends on this, because
//! its `cleanup` must not tear libcurl down underneath an application that
//! also initialised it. The count lives here and is guarded the way C guards
//! it -- with a lock rather than an atomic -- because `curl_global_init_mem`
//! has to test the count and install five hooks as one indivisible step.
//!
//! Thread safety is a live contract, not a formality: `curl.h:2744-2745` and
//! `:2788-2789` document `curl_global_init` and `curl_global_trace` as
//! thread-safe when `CURL_VERSION_THREADSAFE` is advertised, and the engine's
//! banner does advertise it, so every piece of shared state below is genuinely
//! synchronised. Advertising it and then racing would be over-reporting, which
//! is the one direction that is never safe.
//!
//! # The allocator hooks: this module consumes the mechanism, it does not pick
//! it
//!
//! `#[global_allocator]` is a crate-root attribute, declarable once per
//! artifact and selected at compile time, so a submodule cannot own that
//! decision and nothing can swap an allocator at run time. The decision
//! therefore belongs to `curl-rs-ffi/src/lib.rs`, which documents it in full,
//! and this module consumes what that decision leaves it: [`super::memory`],
//! the Rust counterpart of C's five global function pointers, which
//! `curl_global_init_mem` writes and `curl_global_init` and
//! `curl_global_cleanup` reset.
//!
//! CORRECTION 11, recorded here because this is the file a reader arrives at:
//!
//! * The C hooks are **global function pointers**, one per operation --
//!   `curl_malloc_callback Curl_cmalloc = (curl_malloc_callback)malloc;` at
//!   `lib/easy.c:106`, with four siblings through `:110`. `:236-240` installs
//!   the application's, `:129-135` restores the defaults, and the default
//!   `Curl_cstrdup` is `CURLX_STRDUP_LOW` rather than the platform `strdup`.
//! * **Allocation tracking layers on top rather than competing for the slot.**
//!   `lib/memdebug.c:222` calls `(Curl_cmalloc)(size)`, so the debug wrapper
//!   and the application's hooks compose. The Rust arrangement mirrors that:
//!   the optional `memdebug` counting allocator lives in `curl-rs-lib` behind a
//!   default-off feature and is a `#[global_allocator]`, while these five hooks
//!   route the buffers that cross the C boundary; neither excludes the other.
//! * **The install order inside the C function is `m, f, s, r, c`, which is not
//!   the prototype's `m, f, r, s, c`** (`curl.h:2763-2768`). The signature
//!   below reproduces the *prototype*; the order in which the five are stored
//!   is immaterial because they are stored as one group. The discrepancy is
//!   recorded so that nobody "fixes" the signature to match `lib/easy.c:236`.
//! * **Silently accepting the hooks and ignoring them is prohibited.** A
//!   consumer would believe its allocator was in force when it was not, which
//!   is the class of invisible defect this whole ABI is written to avoid. The
//!   hooks are installed into `memory`, they are genuinely used by every buffer
//!   this crate hands to C, and a test below asserts that installing them is
//!   observable.
//!
//! # What "initialization" amounts to here
//!
//! C's `global_init` (`lib/easy.c:124-192`) performs eight subsystem
//! initializations after the count and the allocator. Each is accounted for
//! rather than quietly dropped:
//!
//! | C call | Status |
//! |--------|--------|
//! | `Curl_trc_init` | Outside a `DEBUGBUILD` its body is exactly `return CURLE_OK` (`lib/curl_trc.c:653-660`), and this build does not advertise `Debug` (specification 0.6.6). It notably does **not** reset the trace levels, which is why the configuration below survives init and cleanup. |
//! | `Curl_win32_init` | Windows only; out of scope (specification 0.2.2). |
//! | `Curl_amiga_init` | AmigaOS only; out of scope. |
//! | `Curl_macos_init` | Reads the system trust settings through `lib/macos.c`, which specification 0.2.2 lists as excluded. |
//! | `Curl_ssl_init` | The TLS backend's process-wide setup. `curl-rs-lib/src/tls/` declares `cipher_suite` and `keylog` at this commit, and no backend, so there is nothing to initialise. |
//! | `Curl_vquic_init` | Likewise for QUIC. |
//! | `Curl_ssh_init` | Likewise for SSH. |
//! | `Curl_async_global_init` | The asynchronous resolver's global state. This design uses the system resolver by default (specification 0.8.3), which has none. |
//!
//! So the initialization performed here is complete for the global state the
//! library actually has: the reference count, the five replaceable allocator
//! hooks, and the remembered flags. Four of the eight are omitted permanently
//! and the other four have nothing to initialise yet; none is a placeholder
//! standing in for work this module owes.
//!
//! # The flags are remembered and never read
//!
//! `easy_init_flags` has exactly one consumer in the whole C tree:
//! `Curl_win32_cleanup(easy_init_flags)` at `lib/easy.c:273`, inside `#ifdef
//! _WIN32`. On all four mandated targets the value is stored and never
//! examined. It is stored here too, because `curl_global_cleanup` must clear it
//! and because the count-and-flags state machine is observable through the
//! pairing rules above -- but no behaviour keys off its value, and claiming
//! otherwise would be untrue.
//!
//! # The trace configuration lives here, and why
//!
//! C keeps the trace levels in file-scope statics that `trc_opt()` writes
//! through (`lib/curl_trc.c:578`, `:584`, `:596`, `:600`). `curl-rs-lib`
//! deliberately holds them in an owned value instead, so that its protocol and
//! transfer modules stay testable by injection; a process-global level would
//! make one test's `WRITE` visible to another. Somebody must nevertheless hold
//! the single instance a C consumer configures through `curl_global_trace`, and
//! a C consumer has no command-line tool to hold one on its behalf. This
//! module is that holder -- it already owns the reference count and the
//! allocator hooks -- and [`trace_config`] lends a snapshot to whichever
//! module creates transfers.
//!
//! **A coordination gap was found here and is reported rather than papered
//! over.** `curl-rs-lib/src/trace.rs` already implements the whole
//! `--trace-config` grammar, byte for byte, as `TraceConfig::apply` and
//! `TraceConfig::apply_code` -- the latter documented in that file as provided
//! "so that the mapping is written once instead of in `curl-rs-ffi`". Both were
//! nevertheless `pub(crate)` inside a `pub(crate) mod trace`, carrying
//! `allow(dead_code)` with the note "consumer module not landed", so the ABI
//! could not reach the code written for it and `curl_global_trace` was absent
//! from this crate altogether. The fix is the crate root's own named
//! re-export idiom -- the one `getdate`, `strequal` and `strnequal` already use
//! and which that file calls load-bearing -- so `curl_rs_lib::TraceConfig` is
//! now reachable while `TraceFeature`, `TraceFilter`, `TraceLevel`,
//! `TraceCategory` and the record layouts stay crate-private. This module can
//! construct, configure and lend a configuration; it can neither read nor forge
//! a level. What was NOT done: no glob re-export, no private path, and no
//! second copy of the grammar in this crate, which would have given one
//! wire-visible parser two owners.
//!
//! # `curl_global_sslset` reports the pre-existing `CURLSSLBACKEND_RUSTLS`
//!
//! `CURLSSLBACKEND_RUSTLS = 14` is already in the frozen header at
//! `curl.h:166`, so this build reports a rustls backend **without inventing an
//! enumerant** -- which is precisely what specification 0.1.1 goal G4 relies
//! on. Nothing in this file can weaken certificate validation: it selects or
//! confirms a backend identity and holds no verification switch. Validation
//! stays on by default, and `--cacert`, `--capath` and `--insecure` remain the
//! only things that speak to it, inside the engine.
//!
//! There is no `tls` Cargo feature in this crate -- the fifteen features are
//! capability forwards to the engine -- so nothing here is conditional:
//! `--no-default-features` still exports all five symbols and still reports
//! rustls.

use core::ffi::{c_char, c_int, c_long, CStr};
use core::ptr;
use std::sync::{Mutex, MutexGuard};

use curl_rs_lib::{strequal, TraceConfig};

use super::codes::{curl_sslbackend, CURLcode, CURLsslset};
use super::memory;
use super::panic_boundary::{guard, guard_void};
use super::types::curl_ssl_backend;

// The flag word shared by curl_global_init and curl_global_init_mem
//
// All six bits from `include/curl/curl.h:3014-3019`, typed `c_long` because
// the parameter is `long`. They are declared here because this module is the
// only one that receives them, and they are declared in full even where they
// cannot do anything: specification 0.8.2 forbids removing public surface, so
// `CURL_GLOBAL_WIN32` stays even though Windows is out of scope, exactly as
// `CURL_GLOBAL_SSL` stays even though the header itself records that it has
// had "no purpose since 7.57.0".
//
// No bit is rejected. C tests none of them outside `Curl_win32_init`, so a
// caller passing an unrecognised bit gets `CURLE_OK` there and must get
// `CURLE_OK` here.
//
// WHY FIVE OF THE SIX CARRY A `dead_code` ALLOWANCE, stated once here rather
// than repeated as a bare attribute five times. Not one of these bits has a
// run-time consumer in a curl 8.19.0 build for these targets, and that is the
// authority's own position rather than an omission on this side:
// `docs/libcurl/curl_global_init.md:107` records that `ACK_EINTR` "has no
// point since 7.69.0 but its behavior is instead the default", `:74` that
// `CURL_GLOBAL_SSL`'s "presence or absence serves no meaning since 7.57.0", and
// `CURL_GLOBAL_WIN32` initialises Winsock on a platform specification 0.2.2
// excludes. They exist because they are public vocabulary a caller writes at
// the call site, they are asserted below against
// `include/curl/curl.h:3014-3019`,
// and specification 0.8.2 forbids removing public surface. The allowance is
// per-item deliberately: a module-level or crate-level `dead_code` level would
// also hide the next genuinely unreferenced item somebody adds.
//
// They are `pub(crate)` and not `pub`, which is also deliberate. The six
// `#define` directives are carried into the generated header verbatim by
// `build.rs`, because cbindgen drops the `L` suffix and cannot render
// `(CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32)`; a `pub` constant here would make
// cbindgen emit a second, subtly different definition of each.

/// `CURL_GLOBAL_SSL` (`include/curl/curl.h:3014`), no purpose since 7.57.0.
#[allow(dead_code)] // public vocabulary with no run-time consumer; see above
pub(crate) const CURL_GLOBAL_SSL: c_long = 1 << 0;

/// `CURL_GLOBAL_WIN32` (`include/curl/curl.h:3015`).
///
/// Declared, accepted, and without effect on the four mandated targets: its
/// only C consumer is `Curl_win32_init` (`lib/easy.c:153`).
#[allow(dead_code)] // public vocabulary with no run-time consumer; see above
pub(crate) const CURL_GLOBAL_WIN32: c_long = 1 << 1;

/// `CURL_GLOBAL_ALL` (`include/curl/curl.h:3016`), the two bits above.
#[allow(dead_code)] // public vocabulary with no run-time consumer; see above
pub(crate) const CURL_GLOBAL_ALL: c_long = CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32;

/// `CURL_GLOBAL_NOTHING` (`include/curl/curl.h:3017`).
///
/// The one bit pattern with a use here: it is the flag word a handle holds
/// before its first `init` and after its last `cleanup`, which is what
/// `lib/easy.c:284` means by `easy_init_flags = 0`.
pub(crate) const CURL_GLOBAL_NOTHING: c_long = 0;

/// `CURL_GLOBAL_DEFAULT` (`include/curl/curl.h:3018`), an alias of
/// [`CURL_GLOBAL_ALL`].
#[allow(dead_code)] // public vocabulary with no run-time consumer; see above
pub(crate) const CURL_GLOBAL_DEFAULT: c_long = CURL_GLOBAL_ALL;

/// `CURL_GLOBAL_ACK_EINTR` (`include/curl/curl.h:3019`).
///
/// Its behaviour has been the default since 7.69.0, so setting it changes
/// nothing -- here or in the authority.
#[allow(dead_code)] // public vocabulary with no run-time consumer; see above
pub(crate) const CURL_GLOBAL_ACK_EINTR: c_long = 1 << 2;

// The two CURLcode values this module hands back, taken from the ABI
// enumeration rather than written as integers. `codes::CURLcode` is the single
// owner of the 103 discriminants, so deriving these keeps one authority.

/// `CURLE_OK` = 0, as an `int` for the two prototypes carried verbatim.
const OK: c_int = CURLcode::CURLE_OK.as_c_int();

/// `CURLE_FAILED_INIT` = 2, the failure `curl_global_init*` reports.
const FAILED_INIT: c_int = CURLcode::CURLE_FAILED_INIT.as_c_int();

// The counted global state

/// The reference count and the flags of the first `init` that took effect.
///
/// One `Mutex` rather than two atomics, for the reason C uses one lock:
/// `curl_global_init_mem` must test the count and install five hooks without
/// another thread observing the intermediate state. `Mutex::new` is `const`, so
/// there is no lazy initialization and no start-up ordering problem.
static STATE: Mutex<GlobalState> = Mutex::new(GlobalState {
    initialised: 0,
    flags: CURL_GLOBAL_NOTHING,
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
fn state() -> MutexGuard<'static, GlobalState> {
    STATE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Initialises the library, counting the call.
///
/// Supersedes `curl_global_init` (`lib/easy.c:197-208`). Returns `CURLE_OK`.
///
/// Every call must be paired with a [`curl_global_cleanup`]; see the module
/// documentation for why the pairing is counted rather than idempotent. Every
/// `flags` value is accepted, including bits this build cannot act on, because
/// C tests none of them outside `Curl_win32_init`.
///
/// The allocator is reset to the C library defaults, exactly as
/// `global_init(flags, TRUE)` does at `lib/easy.c:129-135`. That matters when
/// an application called `curl_global_init_mem`, then `curl_global_cleanup`,
/// and then `curl_global_init`: the hooks from the first call must not survive
/// into the third.
///
/// The trace configuration is deliberately NOT touched. C's `Curl_trc_init` is
/// `return CURLE_OK` outside a debug build (`lib/curl_trc.c:653-660`) and never
/// clears the levels, so a `curl_global_trace` call made before `init` -- which
/// `curl.h:2786-2789` invites, since the function exists to be called "at
/// application start" -- keeps its effect.
#[no_mangle]
pub extern "C" fn curl_global_init(flags: c_long) -> c_int {
    guard(FAILED_INIT, || {
        let mut guard = state();
        if guard.initialised > 0 {
            // "if(initialized++) return CURLE_OK;" -- a repeat call bumps the
            // count and does nothing else.
            guard.initialised += 1;
            return OK;
        }
        // The `memoryfuncs` branch of `global_init`: restore the defaults.
        memory::reset();
        guard.initialised = 1;
        guard.flags = flags;
        OK
    })
}

/// Initialises the library with application-supplied allocator hooks.
///
/// Supersedes `curl_global_init_mem` (`lib/easy.c:213-249`).
///
/// Returns `CURLE_FAILED_INIT` when any hook is null, before touching the
/// count -- `lib/easy.c:220-221` tests all five first. Confirmed against the
/// frozen library, which answers `2` for five nulls.
///
/// **A repeat call installs nothing.** When the library is already initialised
/// the count is bumped and the existing allocator is kept, which the C spells
/// out at `lib/easy.c:225-232`: "Already initialized, do not do it again, but
/// bump the variable anyway to work like curl_global_init() and require the
/// same amount of cleanup calls." A caller that wants its hooks installed
/// must be first, which is why the header requires this be the first libcurl
/// call a program makes.
///
/// The parameter order is the prototype's, `m, f, r, s, c`. The C body stores
/// them in the order `m, f, s, r, c` (`lib/easy.c:236-240`); see CORRECTION 11
/// in the module documentation for why that difference is recorded rather than
/// reconciled.
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
    guard(FAILED_INIT, || {
        if m.is_none()
            || f.is_none()
            || r.is_none()
            || s.is_none()
            || c.is_none()
        {
            // "Invalid input, return immediately" -- before the lock, before
            // the count, exactly as C does.
            return FAILED_INIT;
        }

        let mut guard = state();
        if guard.initialised > 0 {
            guard.initialised += 1;
            return OK;
        }

        // "set memory functions before global_init() in case it wants memory
        // functions" (lib/easy.c:234-235). `install` re-tests for null and
        // returns false if any is missing, which cannot happen here.
        if !memory::install(m, f, r, s, c) {
            return FAILED_INIT;
        }
        guard.initialised = 1;
        guard.flags = flags;
        OK
    })
}

/// Releases one outstanding initialization.
///
/// Supersedes `curl_global_cleanup` (`lib/easy.c:255-286`).
///
/// Two guards from the C are reproduced: a call with no outstanding
/// initialization returns immediately (`lib/easy.c:259-262`), and a call that
/// merely decrements a count above one does nothing else
/// (`lib/easy.c:264-267`). Only the last one tears down.
///
/// Teardown restores the default allocator and clears the flags, which is what
/// `lib/easy.c:284` does with `easy_init_flags = 0`. The trace configuration
/// survives, because C's teardown does not touch the levels either.
///
/// This is the one entry point in the crate with no error channel, so a panic
/// here is swallowed silently; the module documentation gives the consequences
/// in full.
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
        guard.flags = CURL_GLOBAL_NOTHING;
    });
}

// curl_global_trace

/// The process-wide trace configuration, C's file-scope `log_level` statics.
///
/// A separate lock from [`STATE`] on purpose. C takes one global lock for both
/// (`lib/easy.c:296` and `:200` are the same `global_init_lock()`), but the two
/// protect unrelated values and nothing here ever needs both at once, so two
/// locks are simpler to reason about and cannot deadlock against each other.
/// `TraceConfig::new` is a `const fn`, so this is a genuine static with no lazy
/// initialization -- which matters because `curl_global_trace` may be the first
/// libcurl call a program makes.
///
/// The configuration deliberately outlives an init/cleanup cycle. See
/// [`curl_global_init`].
static TRACE: Mutex<TraceConfig> = Mutex::new(TraceConfig::new());

/// The trace configuration in force, copied out.
///
/// The counterpart of C reading `cft->log_level` and `feat->log_level` off its
/// globals from inside a transfer. A snapshot rather than a borrow because the
/// engine takes its configuration by value -- it holds the levels in an owned
/// `TraceConfig` so that its own tests stay independent of each other -- and
/// because handing out a guard would let a transfer hold this lock for as long
/// as it ran.
///
/// This is the seam the transfer layer will use when it lands: whichever module
/// creates an easy handle through the C API lends it this snapshot, which is
/// what makes a `curl_global_trace` call visible to transfers exactly as C's
/// globals are. It is `pub(crate)` and not exported: no symbol in
/// `lib/libcurl.def` reads the trace configuration back.
#[allow(dead_code)] // the transfer layer that lends this has not landed
pub(crate) fn trace_config() -> TraceConfig {
    TRACE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Configures which components participate in tracing.
///
/// Supersedes `curl_global_trace` (`lib/easy.c:292-308`), whose body is
/// `Curl_trc_opt(config)` under the global lock. `Curl_trc_opt`
/// (`lib/curl_trc.c:639-651`) is `config ? trc_opt(config) : CURLE_OK`, so a
/// null configuration is success and not an error -- which is why this is the
/// one pointer-taking entry point here that does not answer
/// `CURLE_BAD_FUNCTION_ARGUMENT` for null. Reproducing the C is the
/// requirement; inventing a stricter contract would be a behaviour change.
///
/// # The return value
///
/// `CURLE_OK`, for every input. That is measured, not assumed:
/// `trc_opt`'s loop ends without an error path (`lib/curl_trc.c:604-637`), and
/// `lib/curl_trc.h:40` states the leniency as contract -- "Unknown names are
/// ignored". An over-long token, an empty token, a name that matches nothing
/// and a null pointer all yield success. The signature is fallible because the
/// C signature is, and the only value this can ever return besides `CURLE_OK`
/// is the `CURLE_FAILED_INIT` a contained panic would produce.
///
/// # The grammar is the engine's, not a second copy
///
/// The parse belongs to `curl_rs_lib::TraceConfig::apply_code`, which owns the
/// comma-separated grammar, the 32-byte token cap, the two sign prefixes, the
/// four category keywords, the `doh` alias and the by-name fallback over both
/// component registries. This function's whole job is the boundary: null test,
/// `*const c_char` to `&[u8]` with no decode step, and the `CURLcode` mapping.
/// Passing bytes rather than `&str` is deliberate and is the engine's stated
/// contract: C never decodes the configuration, so neither may this, or a
/// token containing an invalid byte would be lossily expanded and could push a
/// legal token past the cap.
///
/// # Safety
///
/// `config` must be either null or a pointer to a NUL-terminated string that
/// stays valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_global_trace(config: *const c_char) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        let requested = if config.is_null() {
            None
        } else {
            // SAFETY: the caller guarantees a NUL-terminated string when
            // non-null, and the borrow does not outlive this function. The
            // bytes are copied no further than the parse, which only compares
            // them.
            Some(unsafe { CStr::from_ptr(config) })
        };

        let outcome = TRACE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .apply_code(requested.map(CStr::to_bytes));

        // The engine's `CURLcode` and the ABI's are separate declarations with
        // pinned, asserted-equal discriminants; this conversion is total and
        // infallible in both directions, so no value can be lost here.
        CURLcode::from(outcome)
    })
}

// curl_global_sslset

/// The two `CURLsslset` values this build can answer, as `int`.
///
/// Taken from the ABI enumeration in [`super::codes`] rather than written as
/// integers, so `CURLsslset` keeps exactly one owner. The prototype is one of
/// the twelve carried verbatim into the generated header -- cbindgen renders
/// the `avail` parameter with a `const` in the wrong place -- so the Rust
/// return is a plain `int`, which is also what keeps a caller's arbitrary
/// value from ever being materialised as an enum.
const SSLSET_OK: c_int = CURLsslset::CURLSSLSET_OK.as_c_int();

/// `CURLSSLSET_UNKNOWN_BACKEND` = 1.
const SSLSET_UNKNOWN_BACKEND: c_int =
    CURLsslset::CURLSSLSET_UNKNOWN_BACKEND.as_c_int();

/// `CURLSSLBACKEND_RUSTLS` = 14 (`include/curl/curl.h:166`).
///
/// The enumerant already existed in the frozen header, so reporting a rustls
/// backend needs no new value -- specification 0.1.1 goal G4 relies on exactly
/// that. It is read from [`super::codes`], the crate's single owner of the
/// `curl_sslbackend` discriminants, and a test below ties it to
/// `curl_rs_lib::version::TLS_BACKEND_ID` so that the identity this function
/// reports and the identity the `--version` banner reports cannot diverge.
const BACKEND_ID: c_int = curl_sslbackend::CURLSSLBACKEND_RUSTLS.as_c_int();

/// The backend's name, with its NUL written out in the literal.
///
/// Lower case, as `lib/vtls/rustls.c:1398` spells it in
/// `{ CURLSSLBACKEND_RUSTLS, "rustls" }`. The trailing NUL is explicit because
/// a `c"..."` literal is 1.77 and the declared MSRV is 1.75.
const BACKEND_NAME_BYTES: &[u8] = b"rustls\0";

/// [`BACKEND_NAME_BYTES`] as a `CStr`, checked at compile time.
///
/// `CStr::from_bytes_with_nul` is a `const fn` from 1.72, so the check runs
/// during compilation and the `Err` arm is a build failure rather than a
/// runtime branch that can never be taken. That is why there is no `unsafe`
/// here: the unchecked constructor would need a justification where this needs
/// none.
///
/// One definition serves both uses -- the pointer the descriptor publishes and
/// the string the comparison folds -- so the two cannot disagree.
const fn backend_name() -> &'static CStr {
    match CStr::from_bytes_with_nul(BACKEND_NAME_BYTES) {
        Ok(name) => name,
        Err(_) => panic!("the backend name must end in exactly one NUL"),
    }
}

/// The backend's name as the C caller sees it.
///
/// The name is compared case-insensitively, so the spelling matters only for
/// what a caller reads back out of `avail` -- which is precisely why it must be
/// the string the version banner reports.
const BACKEND_NAME: &CStr = backend_name();

/// A wrapper that makes an immutable static holding raw pointers `Sync`.
///
/// A `static` must be `Sync` and a raw pointer is not, which is the only reason
/// this type exists. C's equivalent is `static const struct Curl_ssl
/// *available_backends[]` (`lib/vtls/vtls.c`), immutable data with static
/// storage duration and no synchronisation of any kind.
struct Immortal<T>(T);

// SAFETY: the wrapped value is written once, in a static initializer, and never
// mutated afterwards -- there is no interior mutability and no `&mut` path to
// it. Concurrent readers therefore observe identical immutable bytes, which is
// what `Sync` requires. The pointers inside address other statics of this same
// crate, so they stay valid for the life of the process.
unsafe impl<T> Sync for Immortal<T> {}

/// The one backend descriptor a caller reads through `avail`.
///
/// `id` is first because the frozen layout says so
/// (`include/curl/curl.h:2825-2829`), and the C tree records why at
/// `lib/vtls/vtls_int.h:141-145`: the descriptor "must be the first entry to
/// allow returning the list of available backends in curl_global_sslset()".
/// `handle.rs` asserts the offsets independently.
static RUSTLS_BACKEND: Immortal<curl_ssl_backend> =
    Immortal(curl_ssl_backend {
        id: BACKEND_ID,
        name: BACKEND_NAME.as_ptr(),
    });

/// The NULL-terminated array of pointers to descriptors.
///
/// The shape C hands out is `const curl_ssl_backend **`
/// (`lib/vtls/vtls.c:1144-1145`): an array of pointers, terminated by NULL. One
/// descriptor and two slots. A genuine `static` rather than a leaked
/// allocation, so the address is fixed at link time and a caller may cache it
/// exactly as it may cache C's.
static AVAILABLE_BACKENDS: Immortal<[*const curl_ssl_backend; 2]> =
    Immortal([&RUSTLS_BACKEND.0 as *const curl_ssl_backend, ptr::null()]);

/// Selects, or confirms, the TLS backend.
///
/// Supersedes `curl_global_sslset` (`lib/easy.c:312-321`, forwarding to
/// `Curl_init_sslset_nolock` at `lib/vtls/vtls.c:1139-1166`).
///
/// This build has exactly one backend, so it takes the C's single-backend
/// branch throughout: `Curl_ssl != &Curl_ssl_multi` is true, and with
/// `CURL_WITH_MULTI_SSL` undefined the failure answer is
/// `CURLSSLSET_UNKNOWN_BACKEND` rather than `CURLSSLSET_TOO_LATE`. Those two
/// answers are the whole return set reachable here, and the reason is worth
/// stating because the header's prose suggests otherwise: `CURLSSLSET_TOO_LATE`
/// exists to distinguish a valid backend requested too late from a misspelled
/// one, and it is reachable only in a build that could have chosen between
/// backends. A single-backend build answers `CURLSSLSET_OK` for its own backend
/// whenever it is asked, before or after initialization, because there is
/// nothing to change.
///
/// Three behaviours were measured against the frozen library and are reproduced
/// exactly:
///
/// * **`avail` is written first, even when the call fails.**
///   `lib/vtls/vtls.c:1144-1145` assigns it before the identity test at
///   `:1147`. A caller probing for the backend list with a deliberately bogus
///   `id` -- which is the documented way to enumerate -- still gets the array,
///   and no error path leaves it unwritten.
/// * **A matching `id` OR a matching `name` succeeds**, and the name comparison
///   is case-insensitive (`curl_strequal` at `:1149`), so `RUSTLS` matches.
/// * **`name` is only consulted when non-null.** The C guards it with
///   `(name && ...)`, so a null name with a non-matching id fails rather than
///   dereferencing.
///
/// `CURLSSLSET_NO_BACKENDS` is unreachable here: it is the answer from the
/// no-TLS arm of the `USE_SSL` conditional at `lib/vtls/vtls.c:1169-1176`, for
/// a build with no TLS at all, and specification 0.1.1 goal G4 makes rustls
/// unconditional. There is no `tls` feature to switch it off.
///
/// The wording above deliberately spells that conditional out in words rather
/// than quoting the C directive. A doc comment on an exported function is
/// transcribed verbatim into the generated C header inside a block comment, so
/// a literal comment-close sequence anywhere in the prose ends that block
/// early and turns the remaining lines into stray tokens. `validate_comments`
/// in `build.rs` fails the build on exactly that, and this sentence records why
/// the rule exists so it is not undone as mere pedantry.
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
    guard(SSLSET_UNKNOWN_BACKEND, || {
        if !avail.is_null() {
            // SAFETY: the caller guarantees `avail` is writable when non-null.
            // The array it receives is a static of this crate, so the caller
            // may keep the pointer for the life of the process.
            unsafe { avail.write(AVAILABLE_BACKENDS.0.as_ptr()) };
        }

        if id == BACKEND_ID {
            return SSLSET_OK;
        }

        if !name.is_null() {
            // SAFETY: the caller guarantees a NUL-terminated string when
            // non-null. The borrow does not outlive this expression.
            let requested = unsafe { CStr::from_ptr(name) };
            // `curl_rs_lib::strequal` is the engine function that backs the
            // exported `curl_strequal`, which is the comparison the C makes
            // here (`lib/vtls/vtls.c:1149`). Reusing it rather than folding the
            // bytes locally keeps one owner for "case-insensitive" -- it folds
            // the 26 ASCII letter pairs and nothing else, whatever the process
            // locale says.
            if strequal(Some(requested), Some(BACKEND_NAME)) {
                return SSLSET_OK;
            }
        }

        SSLSET_UNKNOWN_BACKEND
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

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
    /// Three pieces of process-wide state live in this module -- the count, the
    /// allocator hooks and the trace configuration -- and Rust runs tests in
    /// parallel threads, so every test that touches any of them holds this
    /// guard for its whole body. Sharing one `Mutex` serialises them, which is
    /// the only way to assert on process-wide state.
    ///
    /// `pub(super)` rather than private because
    /// [`super::engine_registry_correspondence`] also drives the counter and
    /// must take the SAME lock: a second guard of its own would serialise that
    /// module against itself while still racing this one.
    pub(super) fn exclusive() -> MutexGuard<'static, ()> {
        static SERIAL: Mutex<()> = Mutex::new(());
        let guard = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        {
            let mut inner = state();
            inner.initialised = 0;
            inner.flags = CURL_GLOBAL_NOTHING;
        }
        memory::reset();
        *TRACE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            TraceConfig::new();
        guard
    }

    fn outstanding() -> u32 {
        state().initialised
    }

    /// `curl_global_trace` over a Rust string, as a C caller would call it.
    fn trace(config: &str) -> c_int {
        let owned = CString::new(config).expect("no interior NUL in the test");
        // SAFETY: `owned` outlives the call and is NUL-terminated.
        unsafe { curl_global_trace(owned.as_ptr()) }.as_c_int()
    }

    // The reference count

    #[test]
    fn init_and_cleanup_are_counted_not_idempotent() {
        let _serial = exclusive();
        assert_eq!(curl_global_init(0), OK);
        assert_eq!(outstanding(), 1);
        assert_eq!(curl_global_init(0), OK);
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
        assert_eq!(curl_global_init(CURL_GLOBAL_ALL), OK);
        assert_eq!(state().flags, CURL_GLOBAL_ALL);
        // A repeat call must not overwrite them.
        assert_eq!(curl_global_init(CURL_GLOBAL_NOTHING), OK);
        assert_eq!(state().flags, CURL_GLOBAL_ALL);
        curl_global_cleanup();
        assert_eq!(state().flags, CURL_GLOBAL_ALL, "still initialised");
        curl_global_cleanup();
        assert_eq!(state().flags, CURL_GLOBAL_NOTHING, "cleared at zero");
    }

    /// Every documented flag word succeeds, and so does an undocumented bit.
    ///
    /// C tests no bit outside `Curl_win32_init`, so rejecting one would be a
    /// behaviour change rather than added rigour.
    #[test]
    fn every_flag_word_including_an_unknown_bit_is_accepted() {
        let _serial = exclusive();
        for flags in [
            CURL_GLOBAL_NOTHING,
            CURL_GLOBAL_SSL,
            CURL_GLOBAL_WIN32,
            CURL_GLOBAL_ALL,
            CURL_GLOBAL_DEFAULT,
            CURL_GLOBAL_ACK_EINTR,
            CURL_GLOBAL_ALL | CURL_GLOBAL_ACK_EINTR,
            1 << 20,
            -1,
        ] {
            assert_eq!(curl_global_init(flags), OK, "flags {flags:#x}");
            curl_global_cleanup();
            assert_eq!(outstanding(), 0);
        }
    }

    // The six flag constants

    /// The values are the header's, not a plausible re-derivation.
    #[test]
    fn the_six_global_flags_match_the_frozen_header() {
        // include/curl/curl.h:3014-3019.
        assert_eq!(CURL_GLOBAL_SSL, 1, "CURL_GLOBAL_SSL is 1 << 0");
        assert_eq!(CURL_GLOBAL_WIN32, 2, "CURL_GLOBAL_WIN32 is 1 << 1");
        assert_eq!(CURL_GLOBAL_ALL, 3, "SSL | WIN32");
        assert_eq!(CURL_GLOBAL_NOTHING, 0);
        assert_eq!(CURL_GLOBAL_ACK_EINTR, 4, "1 << 2");
        // The two relationships the header states rather than the numbers it
        // happens to produce, so a renumbering cannot satisfy only one half.
        assert_eq!(CURL_GLOBAL_ALL, CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32);
        assert_eq!(CURL_GLOBAL_DEFAULT, CURL_GLOBAL_ALL);
        // ACK_EINTR is deliberately outside ALL: "This sets all known bits
        // except CURL_GLOBAL_ACK_EINTR"
        // (docs/libcurl/curl_global_init.md:69-70).
        assert_eq!(CURL_GLOBAL_ALL & CURL_GLOBAL_ACK_EINTR, 0);
    }

    /// The two `CURLcode` values this module returns are the pinned ones.
    #[test]
    fn the_returned_curlcodes_are_the_pinned_discriminants() {
        assert_eq!(OK, 0, "CURLE_OK");
        assert_eq!(FAILED_INIT, 2, "CURLE_FAILED_INIT");
    }

    // The allocator hooks

    #[test]
    fn a_null_hook_is_refused_without_disturbing_the_count() {
        let _serial = exclusive();
        // SAFETY: passing nulls is exactly what this asserts about.
        let rc =
            unsafe { curl_global_init_mem(0, None, None, None, None, None) };
        assert_eq!(
            rc, FAILED_INIT,
            "CURLE_FAILED_INIT, as the frozen library answers"
        );
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
            assert_eq!(
                rc, FAILED_INIT,
                "hook {missing} missing must be refused"
            );
            assert_eq!(outstanding(), 0);
        }
    }

    /// The hooks are genuinely installed. A silently ignoring
    /// `curl_global_init_mem` would let a consumer believe its allocator was in
    /// use when it was not, so this assertion is the one that makes the symbol
    /// more than a signature.
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
        assert_eq!(rc, OK);
        assert!(memory::is_installed(), "the hooks must take effect");
        curl_global_cleanup();
        assert!(!memory::is_installed(), "teardown restores the defaults");
    }

    /// The C keeps the first allocator and only bumps the count, which is why
    /// the header insists this be the first libcurl call.
    #[test]
    fn a_repeat_init_mem_installs_nothing() {
        let _serial = exclusive();
        assert_eq!(curl_global_init(0), OK);
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
        assert_eq!(rc, OK);
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
        assert_eq!(rc, OK);
        assert!(memory::is_installed());
        curl_global_cleanup();
        assert_eq!(curl_global_init(0), OK);
        assert!(!memory::is_installed());
        curl_global_cleanup();
    }

    // curl_global_trace

    /// A null configuration is success, not an argument error. This is the one
    /// pointer-taking entry point in this file where that is the right answer,
    /// and it is C's answer: `config ? trc_opt(config) : CURLE_OK`.
    #[test]
    fn a_null_configuration_succeeds_and_changes_nothing() {
        let _serial = exclusive();
        // SAFETY: a null pointer is exactly what this asserts about.
        let rc = unsafe { curl_global_trace(ptr::null()) };
        assert_eq!(rc, CURLcode::CURLE_OK);
        assert_eq!(
            trace_config(),
            TraceConfig::new(),
            "a null configuration must leave every component silent"
        );
    }

    /// Every configuration succeeds, including the malformed ones. Measured
    /// against the frozen library: `trc_opt` has no error path.
    #[test]
    fn every_configuration_returns_curle_ok() {
        let _serial = exclusive();
        for config in [
            "",
            "all",
            "-all",
            "+all",
            "protocol",
            "network",
            "proxy",
            "doh",
            "dns",
            "multi",
            "RUSTLS-is-not-a-component",
            "all,-multi",
            "multi,,dns",
            ",dns",
            "trailing,",
            "-",
            "+",
            "a-token-that-is-far-longer-than-the-thirty-two-byte-cap",
        ] {
            assert_eq!(trace(config), OK, "config {config:?}");
        }
    }

    /// A configuration that is not valid UTF-8 is accepted and ignored, never
    /// rejected: C compares raw bytes and never decodes, so neither may this.
    #[test]
    fn an_invalid_utf8_configuration_is_accepted_and_ignored() {
        let _serial = exclusive();
        let name = CString::new(vec![0xffu8, 0xfe, 0xfd])
            .expect("no interior NUL in the test");
        // SAFETY: `name` outlives the call and is NUL-terminated.
        let rc = unsafe { curl_global_trace(name.as_ptr()) };
        assert_eq!(rc, CURLcode::CURLE_OK);
        assert_eq!(
            trace_config(),
            TraceConfig::new(),
            "a name matching nothing must leave the levels alone"
        );
    }

    /// The configuration is genuinely applied and genuinely reversible. The
    /// levels themselves are the engine's to interpret -- this module cannot
    /// read one -- so the assertion is on the value as a whole, which is enough
    /// to prove the string reached the parser.
    #[test]
    fn a_configuration_is_applied_and_can_be_switched_back_off() {
        let _serial = exclusive();
        assert_eq!(trace_config(), TraceConfig::new(), "silent to begin with");

        assert_eq!(trace("all"), OK);
        let everything = trace_config();
        assert_ne!(
            everything,
            TraceConfig::new(),
            "`all` must switch components on"
        );

        assert_eq!(trace("-all"), OK);
        assert_eq!(
            trace_config(),
            TraceConfig::new(),
            "`-all` must switch every one of them back off"
        );

        // A single component is a smaller change than `all`, so the two must
        // differ -- otherwise a by-name token could be silently broadcasting.
        assert_eq!(trace("dns"), OK);
        let one = trace_config();
        assert_ne!(one, TraceConfig::new(), "`dns` must switch dns on");
        assert_ne!(one, everything, "`dns` is not `all`");
    }

    /// `doh` is an alias for the `dns` component, not a component of its own
    /// (`lib/curl_trc.c:626-629`).
    #[test]
    fn doh_is_an_alias_for_dns() {
        let _serial = exclusive();
        assert_eq!(trace("doh"), OK);
        let alias = trace_config();
        assert_eq!(trace("-all"), OK);
        assert_eq!(trace("dns"), OK);
        assert_eq!(alias, trace_config());
    }

    /// An unrecognised name is ignored rather than treated as an error, which
    /// `lib/curl_trc.h:40` states as contract: "Unknown names are ignored".
    #[test]
    fn an_unknown_component_name_is_ignored() {
        let _serial = exclusive();
        assert_eq!(trace("no-such-component"), OK);
        assert_eq!(trace_config(), TraceConfig::new());
    }

    /// The configuration outlives an init/cleanup cycle, because C's does: the
    /// levels are file-scope statics and neither `global_init` nor
    /// `curl_global_cleanup` touches them.
    #[test]
    fn the_trace_configuration_survives_init_and_cleanup() {
        let _serial = exclusive();
        assert_eq!(trace("all"), OK);
        let configured = trace_config();
        assert_ne!(configured, TraceConfig::new());

        assert_eq!(curl_global_init(CURL_GLOBAL_DEFAULT), OK);
        assert_eq!(
            trace_config(),
            configured,
            "init must not clear a configuration set before it"
        );
        curl_global_cleanup();
        assert_eq!(
            trace_config(),
            configured,
            "cleanup must not clear it either"
        );
    }

    // curl_global_sslset

    /// Reads the NULL-terminated backend array the way a consumer does.
    fn enumerate() -> Vec<(c_int, String)> {
        let mut array: *const *const curl_ssl_backend = ptr::null();
        // SAFETY: a bogus id with a writable `avail` is the documented way to
        // enumerate, and the array written has static storage duration.
        let rc = unsafe { curl_global_sslset(-1, ptr::null(), &mut array) };
        assert_eq!(rc, SSLSET_UNKNOWN_BACKEND, "a bogus id must still fail");
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
            // SAFETY: each entry addresses a static descriptor whose `name` is
            // a NUL-terminated static string.
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

    /// The advertised backend is the engine's, not a lookalike copy.
    ///
    /// The literals in the test above are the ABI contract read from
    /// `include/curl/curl.h:166` and `lib/vtls/rustls.c:1398`, so they belong
    /// there. This test asserts the other half: that what this module publishes
    /// is derived from the ABI enumeration AND agrees with `curl_rs_lib`, so a
    /// change on either side cannot leave `curl_global_sslset` reporting a
    /// stale value while `curl --version` reports the new one. Both assertions
    /// are needed -- the first alone passes when the value is restated locally,
    /// which is the defect this pair prevents.
    #[test]
    fn the_advertised_backend_is_the_engines_and_not_a_local_copy() {
        assert_eq!(
            BACKEND_ID,
            curl_sslbackend::CURLSSLBACKEND_RUSTLS.as_c_int(),
            "the id must come from the ABI enumeration"
        );
        assert_eq!(
            BACKEND_ID,
            curl_rs_lib::version::TLS_BACKEND_ID,
            "and must agree with the engine"
        );
        assert_eq!(
            BACKEND_NAME.to_bytes(),
            curl_rs_lib::version::TLS_BACKEND_NAME.as_bytes()
        );

        // And the engine's banner must name the same backend, which is the
        // user-visible consequence of the two agreeing.
        let name = curl_rs_lib::version::TLS_BACKEND_NAME;
        assert!(
            curl_rs_lib::version::SSL_VERSION.starts_with(name),
            "the version banner reports {:?}, which does not name the backend \
             {name:?} that curl_global_sslset advertises",
            curl_rs_lib::version::SSL_VERSION
        );
    }

    /// The two answers this build can give are the ABI enumeration's, so a
    /// renumbering there cannot leave this file returning stale integers.
    #[test]
    fn the_two_reachable_verdicts_are_the_abi_enumerations() {
        assert_eq!(SSLSET_OK, CURLsslset::CURLSSLSET_OK.as_c_int());
        assert_eq!(SSLSET_OK, 0);
        assert_eq!(
            SSLSET_UNKNOWN_BACKEND,
            CURLsslset::CURLSSLSET_UNKNOWN_BACKEND.as_c_int()
        );
        assert_eq!(SSLSET_UNKNOWN_BACKEND, 1);
    }

    #[test]
    fn the_matching_id_succeeds_and_others_do_not() {
        // SAFETY: a null name and a null `avail` are both permitted.
        unsafe {
            assert_eq!(
                curl_global_sslset(BACKEND_ID, ptr::null(), ptr::null_mut()),
                SSLSET_OK
            );
            // OpenSSL is 1; this build does not have it.
            assert_eq!(
                curl_global_sslset(
                    curl_sslbackend::CURLSSLBACKEND_OPENSSL.as_c_int(),
                    ptr::null(),
                    ptr::null_mut()
                ),
                SSLSET_UNKNOWN_BACKEND
            );
            // CURLSSLBACKEND_NONE with no name cannot match.
            assert_eq!(
                curl_global_sslset(0, ptr::null(), ptr::null_mut()),
                SSLSET_UNKNOWN_BACKEND
            );
        }
    }

    #[test]
    fn the_name_match_is_case_insensitive() {
        for spelling in ["rustls", "RUSTLS", "RustLS"] {
            let name = CString::new(spelling).expect("no interior NUL");
            // SAFETY: `name` is live for the call and `avail` may be null.
            let rc = unsafe {
                curl_global_sslset(0, name.as_ptr(), ptr::null_mut())
            };
            assert_eq!(rc, SSLSET_OK, "{spelling} must match");
        }
        for spelling in ["openssl", "rustl", "rustlss", ""] {
            let name = CString::new(spelling).expect("no interior NUL");
            // SAFETY: as above.
            let rc = unsafe {
                curl_global_sslset(0, name.as_ptr(), ptr::null_mut())
            };
            assert_eq!(
                rc, SSLSET_UNKNOWN_BACKEND,
                "{spelling:?} must not match"
            );
        }
    }

    /// The array pointer is stable, so a caller may cache it -- which C's
    /// `static available_backends` guarantees.
    #[test]
    fn the_backend_array_is_the_same_on_every_call() {
        let mut first: *const *const curl_ssl_backend = ptr::null();
        let mut second: *const *const curl_ssl_backend = ptr::null();
        // SAFETY: both out-parameters are writable locals.
        unsafe {
            curl_global_sslset(BACKEND_ID, ptr::null(), &mut first);
            curl_global_sslset(BACKEND_ID, ptr::null(), &mut second);
        }
        assert_eq!(first, second);
        assert!(!first.is_null());
    }

    /// `avail` is written on the success path too, not only when enumerating.
    #[test]
    fn avail_is_written_on_every_branch() {
        let mut on_success: *const *const curl_ssl_backend = ptr::null();
        let mut on_failure: *const *const curl_ssl_backend = ptr::null();
        // SAFETY: both out-parameters are writable locals.
        unsafe {
            assert_eq!(
                curl_global_sslset(BACKEND_ID, ptr::null(), &mut on_success),
                SSLSET_OK
            );
            assert_eq!(
                curl_global_sslset(-99, ptr::null(), &mut on_failure),
                SSLSET_UNKNOWN_BACKEND
            );
        }
        assert!(!on_success.is_null(), "written when the call succeeds");
        assert_eq!(on_success, on_failure, "the same array either way");
    }

    /// The descriptor keeps `id` first, which is what lets a consumer walk the
    /// array. `handle.rs` asserts the offsets; this asserts that the entry a
    /// caller actually receives has the identity it should.
    #[test]
    fn the_single_descriptor_is_reachable_and_correct() {
        let first = AVAILABLE_BACKENDS.0[0];
        assert!(!first.is_null());
        // SAFETY: the first slot addresses this module's own static descriptor.
        let descriptor = unsafe { &*first };
        assert_eq!(descriptor.id, BACKEND_ID);
        // SAFETY: `name` is the static, NUL-terminated backend name.
        let name = unsafe { CStr::from_ptr(descriptor.name) };
        assert_eq!(name, BACKEND_NAME);
        assert!(
            AVAILABLE_BACKENDS.0[1].is_null(),
            "the array must be NULL-terminated"
        );
    }

    // Panic containment

    /// A panic on the `void` path is swallowed. There is no return value to
    /// carry a failure, so the only correct behaviour is to absorb it -- and to
    /// print nothing, because the fixture corpus compares emitted bytes.
    #[test]
    fn a_panic_on_the_cleanup_path_is_contained() {
        let before = super::super::panic_boundary::contained();
        guard_void(|| panic!("contained"));
        assert_eq!(
            super::super::panic_boundary::contained(),
            before + 1,
            "the boundary must have counted exactly one containment"
        );
    }

    /// The fallbacks the three fallible entry points would return.
    #[test]
    fn the_panic_fallbacks_are_the_documented_ones() {
        assert_eq!(guard(FAILED_INIT, || panic!("contained")), FAILED_INIT);
        assert_eq!(
            guard(SSLSET_UNKNOWN_BACKEND, || panic!("contained")),
            SSLSET_UNKNOWN_BACKEND
        );
        assert_eq!(
            guard(CURLcode::CURLE_FAILED_INIT, || panic!("contained")),
            CURLcode::CURLE_FAILED_INIT
        );
    }

    /// The five symbols this module owns, referenced with their exact ABI
    /// signatures. A parameter list or return type that drifted from
    /// `include/curl/curl.h` stops the build here rather than at a consumer.
    #[test]
    fn all_five_symbols_have_the_frozen_signatures() {
        let _serial = exclusive();
        // curl.h:2748, :2778.
        const INIT: extern "C" fn(c_long) -> c_int = curl_global_init;
        const CLEANUP: extern "C" fn() = curl_global_cleanup;
        // curl.h:2763-2768, in the prototype's order.
        const INIT_MEM: unsafe extern "C" fn(
            c_long,
            super::super::types::curl_malloc_callback,
            super::super::types::curl_free_callback,
            super::super::types::curl_realloc_callback,
            super::super::types::curl_strdup_callback,
            super::super::types::curl_calloc_callback,
        ) -> c_int = curl_global_init_mem;
        // curl.h:2791.
        const TRACE_FN: unsafe extern "C" fn(*const c_char) -> CURLcode =
            curl_global_trace;
        // curl.h:2838 -- the out-parameter is a TRIPLE pointer.
        const SSLSET: unsafe extern "C" fn(
            c_int,
            *const c_char,
            *mut *const *const curl_ssl_backend,
        ) -> c_int = curl_global_sslset;

        // The five bindings above are checked when this file compiles. Calling
        // through each of them is what makes the test discriminating rather
        // than vacuous, and every call below is a documented no-op or is undone
        // immediately.
        assert_eq!(INIT(CURL_GLOBAL_DEFAULT), OK);
        CLEANUP();
        assert_eq!(outstanding(), 0);
        // SAFETY: five null hooks are refused before anything is touched, a
        // null configuration is success that changes nothing, and a null
        // `avail` with a null `name` reads no memory at all.
        unsafe {
            assert_eq!(INIT_MEM(0, None, None, None, None, None), FAILED_INIT);
            assert_eq!(TRACE_FN(ptr::null()), CURLcode::CURLE_OK);
            assert_eq!(
                SSLSET(BACKEND_ID, ptr::null(), ptr::null_mut()),
                SSLSET_OK
            );
        }
    }
}

/// The engine-registry correspondence for
/// [`curl_rs_lib::version::ENGINE_GLOBAL_INIT`].
///
/// `curl-rs-lib`'s capability registry marks every engine it reports as present
/// with a compile-time reference to an item the owning module must export, so a
/// `present: true` cannot outlive the code it claims. `ENGINE_GLOBAL_INIT` is
/// the single entry that cannot follow that rule where the others do: its owner
/// is THIS crate, and the registry lives in a crate this one depends on, so a
/// reference there would invert the dependency direction specification 0.1.1
/// goal G1 fixes.
///
/// This module is the other half of that arrangement. It is the only place that
/// can see both the registry's claim and the code the claim is about, so it is
/// where the correspondence is asserted -- and `curl-rs-lib`'s
/// `every_present_engine_has_a_compile_time_link` names the exception
/// explicitly and asserts that it stays exactly one entry wide, so this file
/// cannot be forgotten by a change on that side.
#[cfg(test)]
mod engine_registry_correspondence {
    use super::{curl_global_cleanup, curl_global_init};
    use core::ffi::{c_int, c_long};

    /// The two entry points the `threadsafe` claim is ABOUT, referenced with
    /// their exact ABI signatures. Deleting or re-signing either stops the
    /// build here, which is what makes the registry's `present` substantive
    /// from this side.
    const _: extern "C" fn(c_long) -> c_int = curl_global_init;
    const _: extern "C" fn() = curl_global_cleanup;

    /// `ENGINE_GLOBAL_INIT` may claim `present` only while this module really
    /// provides the initialiser -- which the `const _` links above establish at
    /// compile time -- so what remains to check at run time is the direction
    /// the links cannot cover: that the claim is not made about a crate whose
    /// code is absent, and that the initialiser it names actually functions.
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
