// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Containment for panics that would otherwise unwind into C.
//!
//! Every exported entry point routes its body through exactly one of the four
//! functions here. That is the rule for all 100 names in `lib/libcurl.def`;
//! measured today, 59 of the 100 are defined, with the remaining 41 unwritten.
//! Every one of the 53 that is a Rust function obeys the rule directly. The
//! other six obey it one call deeper, and none of them escapes it: they are
//! `global_asm!` labels -- `curl_formadd` and the five plain-variadic
//! `curl_m*printf` forms -- with no Rust body to wrap, and each spills its
//! register arguments and then calls a Rust sibling (`formadd_va`, and the five
//! `curl_mv*printf`) whose body is a `guard` call. So no panic can cross the
//! boundary by that route either; verified by reading the `callee = sym` of
//! each trampoline against the `guard` in its target. The count is not
//! worth trusting from this comment in any case: `build.rs` prints the live
//! figure on every build. The rule is stated as a rule rather than as an
//! accomplished fact because a future export that skipped this module would be
//! a defect, and a comment claiming completeness would hide it. See the crate-level documentation for the fallback each return type
//! takes and for why containment is a safety net rather than an
//! error-handling strategy.
//!
//! # Why every item here carries its own `dead_code` allowance
//!
//! Each function below is reached from an exported entry point and from nowhere
//! else, so until an export module names it, it is legitimately unreferenced --
//! and `cargo clippy --workspace -- -D warnings` admits no warning. The
//! allowance is written **per item**, never on the module and never at the
//! crate root, which is the difference that matters: a *new* unreferenced item
//! added here still warns, so the suppression cannot quietly grow to cover
//! incomplete work. Each allowance is removed by the change that gives its
//! function a caller.

use core::cell::Cell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::panic::{self, AssertUnwindSafe};
use std::sync::Once;

/// Panics absorbed since the library was loaded.
static CONTAINED: AtomicUsize = AtomicUsize::new(0);

/// The one line a redacted boundary panic writes, in full.
///
/// Constant by design: no payload, no source location, no backtrace, and
/// therefore nothing derived from either the caller's data or the machine
/// that compiled the library. The wording is curl's own for this class of
/// fault -- `include/curl/multi.h:66` calls `CURLM_INTERNAL_ERROR` "this is
/// a libcurl bug" -- and a contained panic is precisely that.
pub(crate) const REDACTED_PANIC_LINE: &str =
    "libcurl: internal error contained at the C ABI boundary; \
     this is a libcurl bug\n";

/// The variable that opts back in to the unredacted default output.
pub(crate) const VERBOSE_ENV: &str = "CURL_RS_PANIC_VERBOSE";

/// Installs the hook exactly once, however many threads arrive together.
static HOOK: Once = Once::new();

/// Read once at installation, not per panic.
///
/// A panic hook must not consult the environment: `std::env::var` is not
/// async-signal-safe, and a hook can run while another thread holds the
/// environment lock. Sampling it during `Once::call_once` also makes the
/// behaviour of a process stable for its lifetime, which is what a
/// debugging session wants.
static VERBOSE: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Nesting depth of [`guard`] on **this** thread.
    ///
    /// This is what lets the hook tell a panic raised inside the boundary
    /// from one raised by the application elsewhere, and it is per-thread
    /// because a process-wide flag would redact an unrelated thread's panic
    /// that happened to overlap a libcurl call. The counter is still
    /// non-zero when the hook runs: the hook executes before unwinding
    /// starts, so the guard that decrements it has not been dropped yet.
    static DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Increments [`DEPTH`] and decrements it again on every exit, unwind
/// included.
struct Depth;

impl Depth {
    fn enter() -> Self {
        // `try_with` rather than `with`: a thread-local is unavailable
        // during that thread's own destruction, and a panic there must
        // still be contained rather than turned into a second panic.
        let _ = DEPTH.try_with(|depth| depth.set(depth.get() + 1));
        Self
    }
}

impl Drop for Depth {
    fn drop(&mut self) {
        let _ = DEPTH.try_with(|depth| {
            depth.set(depth.get().saturating_sub(1));
        });
    }
}

/// Whether a panic occurring now would be one of ours, and redactable.
///
/// Split out from the hook so it is testable: a `PanicHookInfo` cannot be
/// constructed by a test, whereas this decision is the whole of what the
/// hook decides.
pub(crate) fn would_redact() -> bool {
    !VERBOSE.load(Ordering::Relaxed)
        && DEPTH.try_with(|depth| depth.get() > 0).unwrap_or(false)
}

/// Chains a redacting hook in front of whatever hook was already set.
///
/// Deliberately never names the hook argument's type. It was `&PanicInfo`
/// up to Rust 1.80 and is `&PanicHookInfo` from 1.82, so spelling it would
/// pin this file to one side of the declared minimum; a closure whose
/// parameter is inferred, plus a captured `previous` that is only ever
/// called, compiles on both.
fn install_hook() {
    HOOK.call_once(|| {
        VERBOSE
            .store(std::env::var_os(VERBOSE_ENV).is_some(), Ordering::Relaxed);

        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            if would_redact() {
                // Written with a single `write_all` so the line cannot be
                // interleaved with another thread's, and unlocked
                // deliberately: `Stderr` is line-buffered and already
                // synchronised internally.
                use std::io::Write as _;
                let mut err = std::io::stderr();
                let _ = err.write_all(REDACTED_PANIC_LINE.as_bytes());
                let _ = err.flush();
            } else {
                previous(info);
            }
        }));
    });
}

/// How many panics this boundary has absorbed.
///
/// A healthy process reports zero, and a non-zero result is a defect
/// report rather than a statistic. It exists so a test can prove the
/// net works without the crate having to write to a stream the test
/// fixtures compare byte for byte.
#[allow(dead_code)]
pub(crate) fn contained() -> usize {
    CONTAINED.load(Ordering::Relaxed)
}

/// Runs `body`, returning `fallback` if it panics.
///
/// `fallback` is evaluated by the caller, so it must be a plain value
/// and not itself able to fail. That is deliberate: the recovery path
/// has to be incapable of the fault it is recovering from.
#[allow(dead_code)]
pub(crate) fn guard<T, F>(fallback: T, body: F) -> T
where
    F: FnOnce() -> T,
{
    // Installed from here rather than from an initialiser, because there is
    // no initialiser that is guaranteed to run: `curl_easy_init` may be the
    // application's first call, `curl_global_init` being optional in
    // practice. After the first call this is one atomic load.
    install_hook();
    let _depth = Depth::enter();

    // `AssertUnwindSafe` is unavoidable and is sound here for a reason
    // worth stating rather than waving through: the closures this
    // wraps capture raw pointers handed over by C, and a raw pointer
    // is never `UnwindSafe`. The lint exists to stop a caller
    // observing a Rust value left half-updated by an unwind, but C
    // owns the memory behind these pointers and inspects it after the
    // call in either outcome. The boundary is itself where the
    // invariant is restored, by returning a documented failure value.
    match panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(payload) => {
            CONTAINED.fetch_add(1, Ordering::Relaxed);
            // Releasing the payload runs the caller's own `Drop` when
            // the panic came from `panic_any` with a type of their
            // choosing, so the release is contained too. A panic
            // raised while already unwinding aborts by Rust's own
            // rules, and that is the single case no library can
            // intercept.
            let _ = panic::catch_unwind(AssertUnwindSafe(move || {
                drop(payload);
            }));
            fallback
        }
    }
}

/// Runs `body`, returning a null pointer if it panics.
///
/// Covers every entry point declared to return `char *`, `CURL *`,
/// `CURLM *`, `CURLSH *`, `CURLU *`, `CURL **`, `struct curl_slist *`,
/// `curl_mime *`, `curl_mimepart *` or `struct curl_header *`.
#[allow(dead_code)]
pub(crate) fn guard_ptr<T, F>(body: F) -> *mut T
where
    F: FnOnce() -> *mut T,
{
    guard(core::ptr::null_mut(), body)
}

/// Runs `body`, returning a null `const` pointer if it panics.
///
/// Covers the entry points declared to return `const char *` or
/// `const struct curl_ws_frame *`.
#[allow(dead_code)]
pub(crate) fn guard_const_ptr<T, F>(body: F) -> *const T
where
    F: FnOnce() -> *const T,
{
    guard(core::ptr::null(), body)
}

/// Runs `body` and returns quietly if it panics.
///
/// Covers the six entry points with no error channel at all:
/// `curl_global_cleanup`, `curl_free`, `curl_slist_free_all`,
/// `curl_mime_free`, `curl_formfree` and `curl_url_cleanup`.
#[allow(dead_code)]
pub(crate) fn guard_void<F>(body: F)
where
    F: FnOnce(),
{
    guard((), body);
}

/// One handle's "a mutation may have been left half-applied" flag.
///
/// Embedded in every handle representation that [`guard_tx`] protects --
/// the easy handle, the multi handle, the share handle, a mime tree and a
/// `CURLU`. It is an `AtomicBool` rather than a `Cell` because libcurl's
/// own contract permits a handle to be moved between threads (never used
/// from two at once), so the flag must be visible to whichever thread
/// arrives next.
///
/// It is one-way on purpose. There is no `unpoison`: nothing can establish
/// that the abandoned mutation was harmless, and an escape hatch would be
/// used exactly when it must not be.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct Poison(AtomicBool);

impl Poison {
    /// A healthy handle.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Whether a panic has already been contained inside this handle.
    #[allow(dead_code)]
    pub(crate) fn is_poisoned(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    /// Marks the handle unusable. Idempotent.
    ///
    /// `Release` pairs with [`Self::is_poisoned`]'s `Acquire` so that a
    /// thread which observes the flag also observes every write the
    /// abandoned mutation had managed to make -- which is what makes
    /// "never read it again" a guarantee rather than a hope.
    #[allow(dead_code)]
    pub(crate) fn poison(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// [`guard`] for an entry point that **mutates** a handle.
///
/// Two things happen that `guard` alone cannot do. A handle already
/// poisoned by an earlier contained panic short-circuits: `body` is not
/// run at all, so no half-mutated state is ever read. Separately, a panic
/// inside `body` poisons the handle before the fallback is returned, because
/// at that point the mutation's progress is unknown and unknowable.
///
/// Poisoning on *any* panic is deliberately conservative -- a panic raised
/// before the first write is treated exactly like one raised after the last
/// -- because `catch_unwind` reports that the body did not finish and
/// nothing more. Distinguishing the two would require the body to describe
/// its own progress, which is the bookkeeping this design exists to avoid.
///
/// The `cleanup` family is the documented exception and must NOT route
/// through here: freeing a poisoned handle has to keep working, or a
/// contained defect becomes a leak. See the crate-level contract.
#[allow(dead_code)]
pub(crate) fn guard_tx<T, F>(poison: &Poison, fallback: T, body: F) -> T
where
    F: FnOnce() -> T,
{
    if poison.is_poisoned() {
        return fallback;
    }

    // `Option` rather than a second closure: the fallback is a plain value
    // by `guard`'s own contract, so it cannot be produced twice.
    match guard(None, || Some(body())) {
        Some(value) => value,
        None => {
            poison.poison();
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_char;

    use crate::ffi::panic_boundary;

    #[test]
    fn guard_returns_the_body_value_when_nothing_panics() {
        assert_eq!(panic_boundary::guard(-1_i32, || 42_i32), 42);
        assert_eq!(panic_boundary::guard(0_usize, || 7_usize), 7);
    }

    #[test]
    fn guard_returns_the_fallback_and_counts_a_contained_panic() {
        let before = panic_boundary::contained();
        // 2 stands in for `CURLE_FAILED_INIT`, the documented fallback for
        // the `CURLcode` family. The enumeration itself belongs to
        // `ffi/codes.rs`, so the assertion is on the integer.
        let observed: i32 =
            panic_boundary::guard(2, || panic!("contained on purpose"));
        assert_eq!(observed, 2);
        assert!(panic_boundary::contained() > before);
    }

    #[test]
    fn guard_ptr_yields_null_on_panic_and_the_pointer_otherwise() {
        let mut value = 5_u8;
        let live: *mut u8 = &mut value;
        assert_eq!(panic_boundary::guard_ptr(|| live), live);
        let fallback: *mut u8 =
            panic_boundary::guard_ptr(|| panic!("contained"));
        assert!(fallback.is_null());
    }

    #[test]
    fn guard_const_ptr_yields_null_on_panic() {
        let fallback: *const c_char =
            panic_boundary::guard_const_ptr(|| panic!("contained"));
        assert!(fallback.is_null());
    }

    #[test]
    fn guard_void_swallows_a_panic_and_returns_normally() {
        let before = panic_boundary::contained();
        panic_boundary::guard_void(|| panic!("no error channel exists"));
        assert!(panic_boundary::contained() > before);
    }

    #[test]
    fn guard_contains_a_panic_whose_payload_drop_also_panics() {
        // The nastiest shape the boundary has to survive: releasing the
        // payload runs the caller's `Drop`, and that `Drop` panics too.
        // Both unwinds must stop inside `guard`.
        struct Hostile;
        impl Drop for Hostile {
            fn drop(&mut self) {
                panic!("the payload's own drop panicked too");
            }
        }
        let observed: i32 =
            panic_boundary::guard(2, || std::panic::panic_any(Hostile));
        assert_eq!(observed, 2);
    }
}
