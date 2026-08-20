// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The three exported share-interface entry points -- the public half of
//! `lib/curl_share.c`.
//!
//! | Symbol | Declared | Returns | Failure answer |
//! |--------|----------|---------|----------------|
//! | `curl_share_init` | `curl.h:3079` | `CURLSH *` | null |
//! | `curl_share_setopt` | `curl.h:3080-3081` | `CURLSHcode` | a `CURLSHcode` |
//! | `curl_share_cleanup` | `curl.h:3082` | `CURLSHcode` | a `CURLSHcode` |
//!
//! # THREE, not four: `curl_share_strerror` is not here
//!
//! `lib/libcurl.def` lists FOUR names under the `curl_share` prefix, on its
//! lines 81 to 84, and `include/curl/curl.h` DECLARES all four -- the fourth
//! being `curl_share_strerror` at `curl.h:3243`, well away from the other
//! three at `:3079-3082`. This module owns three of them, because **definition
//! location is not declaration location**: `lib/strerror.c` defines all four of
//! libcurl's strerror functions in ONE translation unit -- `curl_easy_strerror`
//! at `:34`, `curl_multi_strerror` at `:326`, `curl_share_strerror` at `:385`
//! and `curl_url_strerror` at `:420` -- and the crate's partition follows the
//! definition. So [`super::strerror`] owns the fourth, and this module owns the
//! family LESS its strerror member: 3 rather than 4. That subtraction, applied
//! to four families, is what makes the twelve symbol modules sum to the 100
//! names in `lib/libcurl.def` rather than to 106. A definition is NOT moved to
//! match its declaring header.
//!
//! Each of the three has exactly ONE `#[no_mangle] pub extern "C"` definition.
//! A duplicate anywhere in the crate is a link error rather than a review
//! finding, so the claim is enforced by the linker; that the fourth name
//! appears nowhere in this file is asserted below by a test that reads the
//! file.
//!
//! # `curl_share_cleanup` HAS an error channel, unlike `curl_easy_cleanup`
//!
//! `curl.h:3082` is `CURL_EXTERN CURLSHcode curl_share_cleanup(CURLSH
//! *share);`. The symmetry with the easy interface -- where
//! `curl_easy_cleanup` returns `void` -- does **not** hold, and assuming it
//! does is the single most likely way to get this file wrong. The channel is
//! not decorative: `lib/curl_share.c:231-235` returns `CURLSHE_IN_USE` when
//! any easy handle is still attached, **and tears nothing down**, so the
//! handle survives the call and the caller still owns it. The ownership
//! consequence is exact and is stated where it is implemented: a
//! [`CURLSHcode::CURLSHE_OK`] frees the allocation, and any other answer must
//! not.
//!
//! # The `CURLSHoption` dispatch is a direct ordinal `match`
//!
//! `curl_easy_setopt`'s type safety comes from arithmetic: `CURLOPT(na, t, nu)`
//! is `na = ((t) + (nu))` with the type bases 0, 10000, 20000, 30000 and 40000
//! (`curl.h:1111-1115`), so integer division of the option value by 10,000
//! recovers the argument's type class before the trailing slot is read.
//!
//! **None of that applies here.** `CURLSHoption` (`curl.h:3069-3077`) is a
//! plain ordinal enumeration -- `CURLSHOPT_NONE` = 0 through `CURLSHOPT_LAST`
//! = 6, taking their values from declaration order with no base added. There is
//! consequently **no `/ 10000` base to divide by**, and looking for one would
//! misread every option. The dispatch is a direct `match` over the seven
//! values, each of which names its own trailing-argument type by itself:
//!
//! | Option | Value | Trailing argument, per `lib/curl_share.c` |
//! |--------|-------|-------------------------------------------|
//! | `CURLSHOPT_NONE` | 0 | none -- reaches `default:` at `:211-213` |
//! | `CURLSHOPT_SHARE` | 1 | `va_arg(param, int)` at `:81` |
//! | `CURLSHOPT_UNSHARE` | 2 | `va_arg(param, int)` at `:149` |
//! | `CURLSHOPT_LOCKFUNC` | 3 | `va_arg(param, curl_lock_function)` `:197` |
//! | `CURLSHOPT_UNLOCKFUNC` | 4 | `va_arg(.., curl_unlock_function)` `:202` |
//! | `CURLSHOPT_USERDATA` | 5 | `va_arg(param, void *)` at `:207` |
//! | `CURLSHOPT_LAST` | 6 | none -- reaches the same `default:` |
//!
//! Note that `:81` and `:149` read an `int` and not the `curl_lock_data`
//! enumeration, and perform no validation of it whatever. A value naming no
//! kind must therefore reach `CURLSHE_BAD_OPTION` exactly as the C's inner
//! `default:` does at `:140-141`, which is why the engine's `ShareOption`
//! carries a raw `i32` for those two options rather than a narrowed type.
//!
//! # ESCALATION A4: resolved for this symbol, still open as an ambiguity
//!
//! `curl_share_setopt` is one of the four exports whose C prototype is variadic
//! while its argument count is fixed at three, and it is therefore one of the
//! four A4 names. The short version: a plain non-variadic Rust `extern "C" fn`
//! reached through the variadic prototype is correct on three of the four
//! required targets and **silently wrong on `aarch64-apple-darwin`**, where
//! Apple's arm64 ABI passes variadic arguments on the stack while an aarch64
//! Rust callee reads register x2.
//!
//! **So this module does not define one.** `curl_share_setopt` is emitted by
//! four `core::arch::global_asm!` prologues, one per ABI flavour, each
//! relocating the argument from wherever that target's caller put it and
//! tail-calling [`share_setopt_slot`]. That is stable at the declared minimum
//! of 1.75, needs no C compiler, and removes the hazard rather than mitigating
//! it. `build.rs`'s `check_variadic_strategy` refuses to build a plain
//! non-variadic definition of any of the four names, so the arrangement cannot
//! be undone by accident.
//!
//! What is left of A4 for **this symbol** is a testing gap and not an ABI
//! question: the two Apple prologues are cross-assembled and disassembled
//! rather than executed, no Apple host being available. What is left of A4 as
//! an **ambiguity** is larger and is not this module's to close --
//! `aarch64-apple-darwin` remains unbuildable, because `build.rs` refuses it
//! unconditionally while the other three A4 names are still unwritten. A
//! resolved symbol is not a resolved ambiguity. The full account, the four
//! measured call sites and the options that were and were not taken are
//! recorded at [`share_setopt_slot`].
//!
//! # What this module does NOT contain
//!
//! No protocol logic and no shared store. Pattern P10 (Facade): this crate
//! presents the C surface over the engine without containing the state behind
//! it, which is what keeps the ABI shim auditable in isolation. The shared
//! cookie jar, DNS cache, TLS session cache, HSTS store, Public Suffix List
//! and connection pool all live in [`curl_rs_lib::share`], together with every
//! decision about them; this file marshals arguments and nothing else. A test
//! below asserts that on the import list rather than trusting it.
//!
//! No enumeration and no callback typedef is declared here either, and the
//! three owning modules are named rather than guessed at, because two of the
//! three are not where a reader would first look:
//!
//! * [`CURLSHcode`] and [`CURLSHoption`] -- [`super::codes`]. `codes.rs` also
//!   carries the `From` bridges in both directions to the engine's own
//!   `CURLSHcode`, so no conversion is written here.
//! * [`curl_lock_data`], [`curl_lock_access`], [`curl_lock_function`] and
//!   [`curl_unlock_function`] -- [`super::types`], at `types.rs:261`, `:244`,
//!   `:778` and `:978`. All four are named in `cbindgen.toml`'s `[export]
//!   include` list, so cbindgen generates each of them from that module; a
//!   second declaration here would put a duplicate typedef into
//!   `include/curl/curl.h` and break the 129 example programs that compile
//!   against it. `codes.rs` carries an executable test enumerating the
//!   nineteen types `types.rs` owns for exactly this reason.
//! * The `CURLSH` representation -- [`super::handle`], at `handle.rs:97`.
//!
//! # `CURLSH` is `typedef void`, not an opaque struct
//!
//! `curl.h:110` is `typedef void CURLSH;`, inside the `extern "C" {` block
//! opened at `:106`. cbindgen's natural output for an opaque Rust type is
//! `typedef struct X X;`, which is a DIFFERENT type: a consumer assigning a
//! `CURLSH *` to a `void *` -- a widespread idiom, present in the examples --
//! would begin emitting warnings or errors. `CURLSH` is therefore in
//! `cbindgen.toml`'s `[export] exclude`, its declaration comes from the
//! verbatim prologue, and [`super::handle`] owns the representation decision:
//! `pub type CURLSH = c_void`. Every boundary signature in this file spells the
//! handle `*mut CURLSH`, which is `*mut c_void`, and no opaque struct is
//! declared here.

use core::ffi::{c_int, c_void};
use core::mem;

use curl_rs_lib::share::{
    LockAccess, LockCallback, LockData, LockOwner, Share, ShareOption,
    ShareUserData, UnlockCallback,
};

use super::codes::{CURLSHcode, CURLSHoption};
use super::handle::{borrow, drop_raw, into_raw, CURL, CURLSH};
use super::panic_boundary::{guard, guard_ptr, guard_tx, Poison};
use super::types::{
    curl_lock_access, curl_lock_data, curl_lock_function, curl_unlock_function,
};

// What lives behind a `CURLSH *`

/// The engine's [`Share`] plus the [`Poison`] flag the panic boundary needs.
///
/// The flag cannot live in [`Share`] itself: [`Poison`] is this crate's type
/// and [`Share`] is `curl-rs-lib`'s, and a field of one inside the other would
/// invert the dependency the whole workspace is arranged to keep one-way. So
/// the boundary owns the pairing, which is the right place for it anyway --
/// poisoning describes a fault in the C ABI's use of the handle, not a state
/// the share has.
///
/// # Why both fields are reached through a SHARED borrow
///
/// [`Share::setopt`] and [`Share::cleanup`] both take `&self`, not `&mut
/// self`, and that is the whole reason this file uses
/// [`borrow`](super::handle::borrow) where [`super::url`] uses `borrow_mut`.
/// The share interface exists to be used from several threads at once --
/// `docs/libcurl/opts/CURLSHOPT_SHARE.md` is written for it, and
/// `tests/libtest/lib506.c` and `lib3207.c` drive one share from two threads --
/// so [`Share`] is `Send + Sync` and carries its own interior mutability.
///
/// Taking `&mut ShareHandle` would therefore be unsound on the interface's
/// primary use case rather than merely unnecessary: a `&mut` must be unique,
/// and the second thread to call in through the same `CURLSH *` would create
/// an alias of it. A shared borrow has no such requirement, and it yields
/// `&Poison` and `&Share` at once, so no field-splitting is needed either.
struct ShareHandle {
    /// The share itself. Every store, lock notification and lifecycle
    /// decision belongs to the engine.
    share: Share,

    /// Set once, and only by a panic contained inside a mutating entry point.
    ///
    /// One-way by design: there is no way to establish that an abandoned
    /// mutation was harmless, so a poisoned handle answers its family's
    /// failure code for every call except [`curl_share_cleanup`].
    poison: Poison,
}

impl ShareHandle {
    /// A live share, as `curl_share_init` produces (`lib/curl_share.c:33-55`).
    fn new() -> Self {
        Self {
            share: Share::new(),
            poison: Poison::new(),
        }
    }
}

// Reading the one trailing slot
//
// Every helper below decodes the single `*mut c_void` parameter that
// `curl_share_setopt` receives in place of a `va_list`. Which decoding applies
// is settled by the option identifier before any of them runs, so none of them
// ever guesses; the dispatch that chooses is in `curl_share_setopt` itself.

/// The two function-pointer slots are reconstituted by [`mem::transmute`], so
/// the size premise that makes that sound is checked by the compiler rather
/// than asserted in prose.
///
/// `Option<fn(..)>` is guaranteed to have the same size and alignment as
/// `fn(..)` -- the null-pointer optimisation applies to a function pointer
/// exactly as it does to a reference -- and a function pointer is the same
/// width as a data pointer on all four required targets, all of which are
/// 64-bit. Each of the three assertions below would fail to compile on a target
/// where that stopped holding, which is the only notice worth having.
const _: () = assert!(
    mem::size_of::<curl_lock_function>() == mem::size_of::<*mut c_void>()
);
const _: () = assert!(
    mem::size_of::<curl_unlock_function>() == mem::size_of::<*mut c_void>()
);
const _: () = assert!(
    mem::align_of::<curl_lock_function>() == mem::align_of::<*mut c_void>()
);

/// Reads the `int` that `CURLSHOPT_SHARE` and `CURLSHOPT_UNSHARE` pass.
///
/// `lib/curl_share.c:81` and `:149` are both `va_arg(param, int)`. An `int` is
/// unaffected by the default argument promotions, so a C caller writes one into
/// a single general-purpose slot and **the upper half of that slot is
/// unspecified**: on x86-64 System V a compiler typically emits a 32-bit `mov`
/// that happens to zero it, but nothing in the ABI requires that and AAPCS64
/// makes no such promise either. Reading the slot as a 64-bit value and
/// comparing it against 0..=8 would therefore be a latent, target-dependent
/// bug.
///
/// So the low 32 bits are taken and reinterpreted as a signed `int`, which is
/// exactly the width and signedness the C reads. The truncation is deliberate
/// and total: every bit pattern maps to some `i32`, a value naming no
/// [`LockData`] kind reaches `CURLSHE_BAD_OPTION` through the engine's own
/// `LockData::from_i32`, and a negative `int` survives as itself -- `-1`
/// arrives as `0xFFFF_FFFF` and leaves as `-1`.
///
/// `ptr as usize` rather than `<*mut _>::addr`, which is Rust 1.84 and so
/// exceeds the declared minimum of 1.75. It is the same cast the rest of this
/// crate uses at the boundary (`misc.rs:968`, `:1119`).
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn slot_as_int(param: *mut c_void) -> i32 {
    param as usize as u32 as i32
}

/// Reads the `void *` that `CURLSHOPT_USERDATA` passes
/// (`lib/curl_share.c:207`).
///
/// The engine stores the bit pattern rather than a pointer, because it never
/// dereferences it -- the value's only purpose is to be handed back to the
/// application's own callbacks -- and a [`ShareUserData`] keeps that fact in
/// the type. Nothing here validates it: `:207-208` does not, and a null
/// `clientdata` is the documented state of a freshly initialised share.
fn slot_as_userdata(param: *mut c_void) -> ShareUserData {
    ShareUserData::from_bits(param as usize)
}

/// Reads the `curl_lock_function` that `CURLSHOPT_LOCKFUNC` passes
/// (`lib/curl_share.c:197`).
///
/// # Safety
///
/// `param` must be either null or a pointer to a function with C linkage whose
/// signature is [`curl_lock_function`]'s -- which is what the header's
/// `CURLSHOPT_LOCKFUNC` contract already requires of the caller, and what
/// `docs/libcurl/opts/CURLSHOPT_LOCKFUNC.md` documents. A function of any other
/// signature is undefined behaviour when called, exactly as it is in C.
unsafe fn slot_as_lockfunc(param: *mut c_void) -> curl_lock_function {
    // SAFETY: the source and destination have equal size and alignment,
    // checked by the three `const` assertions above rather than assumed.
    // `Option<unsafe extern "C" fn(..)>` admits every bit pattern a data
    // pointer can hold: the null-pointer optimisation makes an all-zero
    // pattern `None` and any other pattern `Some`, so no value of `param` is
    // an invalid `curl_lock_function`. Whether the address is a function of
    // the right signature is this function's own documented precondition, and
    // it is not checkable here or in C.
    unsafe { mem::transmute::<*mut c_void, curl_lock_function>(param) }
}

/// Reads the `curl_unlock_function` that `CURLSHOPT_UNLOCKFUNC` passes
/// (`lib/curl_share.c:202`).
///
/// # Safety
///
/// The same contract as [`slot_as_lockfunc`], for
/// [`curl_unlock_function`]'s signature. Note that it takes **three**
/// parameters and not four: an unlock notification carries no
/// [`curl_lock_access`], and that asymmetry is the header's
/// (`curl.h:3050-3056`) rather than an omission here.
unsafe fn slot_as_unlockfunc(param: *mut c_void) -> curl_unlock_function {
    // SAFETY: identical to `slot_as_lockfunc`'s, for the other typedef; the
    // size and alignment premise is the same pair of `const` assertions and
    // the signature premise is this function's own precondition.
    unsafe { mem::transmute::<*mut c_void, curl_unlock_function>(param) }
}

// Handing the application's callbacks to the engine
//
// The callbacks are ABI-visible and MUST still be invoked at the same points
// the C invokes them. Rust's interior mutability means the engine does not
// NEED them to be correct for its own safety, and that is precisely the trap:
// an application's callback may count, log, or coordinate with a mutex the
// application itself holds, so quietly stopping calling them would be a silent
// behaviour change in the consumer's process. `lib/curl_share.c` has five call
// sites -- `:228` and `:262` and `:233` in `curl_share_cleanup`, and `:279` and
// `:295` in `Curl_share_lock`/`_unlock` -- and the engine reproduces every one
// of them. What the two adapters below do is make the C function reachable from
// the engine's safe callback type; where it is called from is the engine's,
// and `Share::cleanup` names each site against the C line that has it.

/// The owner argument, back in the shape the application declared.
///
/// `curl_share_cleanup`'s three notifications pass a **null** handle
/// (`lib/curl_share.c:228`, `:233`, `:262`), which the engine spells
/// [`LockOwner::NONE`] and which converts back to a null pointer here with no
/// special case: `LockOwner::NONE` is bit pattern 0.
fn owner_as_ptr(owner: LockOwner) -> *mut CURL {
    owner.bits() as *mut CURL
}

/// The `void *userptr` argument, back in the shape the application declared.
fn userdata_as_ptr(data: ShareUserData) -> *mut c_void {
    data.bits() as *mut c_void
}

/// The data kind, in the enumeration the application's prototype names.
///
/// Total by construction: [`LockData`] has exactly the nine tokens
/// `curl_lock_data` has (`curl.h:3026-3040`), including both out-of-band ones,
/// so there is no arm that could fail and no value that could be invented.
/// `CURL_LOCK_DATA_LAST` is reachable here only if a caller passed it, which
/// the C also forwards rather than filtering.
fn lock_data_as_c(kind: LockData) -> curl_lock_data {
    match kind {
        LockData::None => curl_lock_data::CURL_LOCK_DATA_NONE,
        LockData::Share => curl_lock_data::CURL_LOCK_DATA_SHARE,
        LockData::Cookie => curl_lock_data::CURL_LOCK_DATA_COOKIE,
        LockData::Dns => curl_lock_data::CURL_LOCK_DATA_DNS,
        LockData::SslSession => curl_lock_data::CURL_LOCK_DATA_SSL_SESSION,
        LockData::Connect => curl_lock_data::CURL_LOCK_DATA_CONNECT,
        LockData::Psl => curl_lock_data::CURL_LOCK_DATA_PSL,
        LockData::Hsts => curl_lock_data::CURL_LOCK_DATA_HSTS,
        LockData::Last => curl_lock_data::CURL_LOCK_DATA_LAST,
    }
}

/// The access type, in the enumeration the application's prototype names.
///
/// Total for the same reason as [`lock_data_as_c`]: [`LockAccess`] carries all
/// four of `curl_lock_access`'s tokens (`curl.h:3043-3048`).
fn lock_access_as_c(access: LockAccess) -> curl_lock_access {
    match access {
        LockAccess::None => curl_lock_access::CURL_LOCK_ACCESS_NONE,
        LockAccess::Shared => curl_lock_access::CURL_LOCK_ACCESS_SHARED,
        LockAccess::Single => curl_lock_access::CURL_LOCK_ACCESS_SINGLE,
        LockAccess::Last => curl_lock_access::CURL_LOCK_ACCESS_LAST,
    }
}

/// Wraps the application's `curl_lock_function` as the engine's
/// [`LockCallback`], or [`None`] for a null pointer.
///
/// A null pointer CLEARS the callback rather than being rejected:
/// `lib/curl_share.c:197-198` assigns whatever `va_arg` produced with no
/// validation at all, and `tests/libtest/lib3207.c:154` passes `NULL`
/// deliberately. Reporting an error here would be a behaviour change.
///
/// The closure captures only the function pointer, which is `Copy`, `Send` and
/// `Sync`, so the resulting [`std::sync::Arc`] satisfies the engine's
/// `Fn(..) + Send + Sync` bound and one share's callback can be delivered from
/// whichever thread reaches the notification -- which is the point of the
/// interface.
///
/// # Safety
///
/// `func` must be either [`None`] or a function that remains callable, with
/// the signature its type declares, for as long as the share can deliver a
/// notification to it. That is the application's obligation in C too: libcurl
/// stores the pointer and calls it later, and nothing can defend against a
/// callback that has been unloaded.
unsafe fn wrap_lockfunc(func: curl_lock_function) -> Option<LockCallback> {
    let func = func?;
    Some(std::sync::Arc::new(
        move |owner: LockOwner,
              kind: LockData,
              access: LockAccess,
              data: ShareUserData| {
            // SAFETY: `func` is non-null -- the `?` above returned for the
            // null case -- and by this function's documented precondition it
            // is a live function with `curl_lock_function`'s signature. The
            // four arguments are converted to exactly the types that
            // signature declares, so the call is the one the application's
            // prototype describes. Delivering it here rather than filtering
            // is what keeps the C's five call sites observable.
            unsafe {
                func(
                    owner_as_ptr(owner),
                    lock_data_as_c(kind),
                    lock_access_as_c(access),
                    userdata_as_ptr(data),
                );
            }
        },
    ))
}

/// Wraps the application's `curl_unlock_function` as the engine's
/// [`UnlockCallback`], or [`None`] for a null pointer.
///
/// # Safety
///
/// The same contract as [`wrap_lockfunc`], for the three-argument signature.
unsafe fn wrap_unlockfunc(
    func: curl_unlock_function,
) -> Option<UnlockCallback> {
    let func = func?;
    Some(std::sync::Arc::new(
        move |owner: LockOwner, kind: LockData, data: ShareUserData| {
            // SAFETY: as `wrap_lockfunc`'s, for the other typedef. `func` is
            // non-null by the `?` above and is a live function of the declared
            // signature by precondition; the three arguments are converted to
            // the types that signature names, and no access type is passed
            // because the C prototype has no parameter for one.
            unsafe {
                func(
                    owner_as_ptr(owner),
                    lock_data_as_c(kind),
                    userdata_as_ptr(data),
                );
            }
        },
    ))
}

// The three exported entry points.
//
// Two are ordinary `#[no_mangle]` Rust items. The third,
// `curl_share_setopt`, is not a Rust function at all -- it is four assembled
// prologues -- for the reason set out at length in its own section below.

// 1 of 3: curl_share_init

/// Creates a share object.
///
/// Supersedes `curl_share_init` (`lib/curl_share.c:33-55`), declared at
/// `include/curl/curl.h:3079`. Returns a handle the caller owns and must
/// release with [`curl_share_cleanup`], or null.
///
/// # Null is still the documented failure answer, and still cannot be removed
///
/// The C reaches null from two paths: a refused `curlx_calloc` (`:35-36`, which
/// falls through to `return share` -- the null it just got) and a refused
/// `curl_easy_init` for the internal admin handle (`:41-44`). Neither has an
/// exact Rust counterpart, and the engine's `Share::new` says so: it cannot
/// fail. What can still answer null is the handle allocation itself -- [`into_
/// raw`](super::handle::into_raw) reports a refused allocation rather than
/// aborting, which is strictly better than `Box::new`'s
/// `handle_alloc_error` -- and a contained panic. So the return value must
/// still be tested, exactly as `docs/libcurl/curl_share_init.md` has always
/// required, and a caller cannot tell the paths apart. That is the property
/// that matters.
///
/// Takes no arguments, so unlike its two siblings it is not an `unsafe fn`:
/// there is no caller obligation to state.
#[no_mangle]
pub extern "C" fn curl_share_init() -> *mut CURLSH {
    guard_ptr(|| into_raw::<CURLSH, ShareHandle>(ShareHandle::new()))
}

// 2 of 3: curl_share_setopt
//
// ESCALATION A4 -- the hazard, and the resolution for THIS symbol
//
// `curl_share_setopt` is one of the four exports -- with `curl_easy_setopt`,
// `curl_easy_getinfo` and `curl_multi_setopt` -- whose C prototype is variadic
// (`include/curl/curl.h:3080-3081`) while its argument count is fixed at three.
// The obvious implementation is a plain non-variadic Rust `extern "C" fn`
// reached through that prototype, and it is proven end-to-end on x86-64 System
// V: a C driver compiled against the variadic declaration and linked against
// such a definition round-tripped all five argument classes exactly (`long
// 30L`, `long -1L`, a data pointer, a function pointer and an `off_t` of
// `1 << 40`).
//
// IT IS NOT SAFE ON ALL FOUR REQUIRED TARGETS. Disassembling the call site
// shows where a C caller actually puts the third argument:
//
//   x86_64-unknown-linux-gnu    mov  %rsi,%rdx     -> RDX
//   x86_64-apple-darwin         movq %rsi,%rdx     -> RDX
//   aarch64-unknown-linux-gnu   mov  x2, x1        -> X2
//   aarch64-apple-darwin        str  x1, [sp]      -> THE STACK; x2 unwritten
//
// A non-variadic `extern "C" fn` callee compiles to `mov x0, x2; ret` on
// aarch64 -- it reads x2. On the first three targets caller and callee agree.
// On `aarch64-apple-darwin`, one of the four required targets, the callee
// would read a register the caller never populated, and the failure is
// SILENT: no crash, no diagnostic, just a wrong option value. It would not
// surface in a Linux test environment, and no Apple host is available here to
// observe it.
//
// The remedy that was FIRST considered and rejected is `c_variadic` -- `VaList`
// and `ap.next_arg::<T>()`, whose `VaArgSafe` is a sealed trait implemented for
// the integer and float primitives but NOT for raw pointers, which must be read
// as `usize` and cast. It is marked `#[stable]` only on nightly 1.99, and so
// exceeds the declared minimum of 1.75 that `rust-toolchain.toml` and
// `clippy.toml` both pin. On that reading two of the user's own requirements --
// the MSRV floor and the four-target matrix -- could not both be met by any
// implementation, and the three outcomes were all the user's to choose:
//
//   1. RAISE THE MSRV past `c_variadic`'s stabilisation and write a true
//      variadic, forfeiting the 1.75 floor.
//   2. DROP `aarch64-apple-darwin` from the target matrix, forfeiting one of
//      the four mandated targets.
//   3. ACCEPT that this target's varargs entry points are unsupported,
//      forfeiting ABI correctness for four symbols on one target.
//
// NONE OF THE THREE IS TAKEN HERE, because a fourth option was measured and
// works: a `core::arch::global_asm!` trampoline exported under the public
// symbol name, which relocates the argument from wherever that target's caller
// put it into the register the Rust callee reads, and tail-calls it. It is
// stable at 1.75, needs no C compiler and no nightly feature, and it removes
// the possibility rather than mitigating it -- nothing below treats a register
// as a variadic argument on Apple arm64, because the Apple prologue loads the
// slot the caller actually wrote. The four prologues are at the end of this
// section, one per ABI flavour, and `build.rs`'s `check_variadic_strategy`
// refuses to build a plain non-variadic definition of any of the four names
// precisely so that this cannot be undone by accident.
//
// WHAT REMAINS OF A4, stated rather than buried, in two parts.
//
// FIRST, for this symbol: the two Apple prologues are cross-assembled and
// disassembled rather than executed, no Apple host being available. That is a
// testing gap on a prologue whose whole body is two instructions, not an
// unresolved ABI question.
//
// SECOND, and larger than this file: `aarch64-apple-darwin` REMAINS
// UNBUILDABLE. `build.rs`'s `check_variadic_abi` refuses that target
// **unconditionally** -- measured, not assumed: its condition 1 consults no
// environment variable, and `CURL_RS_A4_VARIADIC_DECISION` is now itself
// refused with a message saying that no value of it does anything, the former
// `accept-unsupported-varargs` bypass having been removed on the ground that a
// build-time variable cannot make an uninitialised register read safe. The
// refusal names all four of `VARIADIC_TRAILING_POINTER`, and three of them --
// `curl_easy_setopt`, `curl_easy_getinfo` and `curl_multi_setopt` -- have no
// definition in this crate yet and so no prologue either. Lifting the refusal
// is therefore not this module's to do and is not attempted here: it needs all
// four trampolined and then a C driver on a real Apple arm64 host
// round-tripping every argument class through the generated header's
// variadic prototype.
// A RESOLVED SYMBOL IS NOT A RESOLVED AMBIGUITY, and specification 0.8.6 A4
// stays open on the two options that are edits to this repository -- raise the
// MSRV, or drop the triple from the matrix.
//
// THIS FILE EMITS NO RUSTC WARNING AND NO `compile_error!`, deliberately. A
// warning would fail the zero-warning build gate and `cargo clippy --
// -D warnings`; a `#[cfg]`-gated `compile_error!` would duplicate a refusal
// `build.rs` already issues, and would issue it from the one place that cannot
// explain itself. Escalation belongs in the build script, whose diagnostics are
// exempt from `-D warnings`. Note also that a build script's `cargo:warning=`
// must use the LEGACY single-colon spelling: `cargo::` requires Cargo 1.77 and
// is silently ignored at the 1.75 floor.
//
// 32-BIT PORTABILITY IS DELIBERATELY FORFEITED AND IS NOT CLAIMED. A single
// register-width slot holds a `curl_off_t` only where `off_t` fits a register.
// All four mandated targets are 64-bit, so the design is sound for the mandated
// matrix and unsound off it. This is a forfeit rather than an oversight, and
// saying so is the difference between the two.

/// The body of `curl_share_setopt`, entered with the trailing slot already in
/// the third argument register.
///
/// Not `#[no_mangle]` and not exported, and both matter. The exported name
/// belongs to the assembled trampolines below, so a second definition of it
/// would be a duplicate symbol; and an exported callee would be a 101st symbol
/// and would fail the `nm` parity gate against the 100 names in
/// `lib/libcurl.def`.
///
/// # Safety
///
/// `share` must be either null -- answered with
/// [`CURLSHcode::CURLSHE_INVALID`] -- or a live pointer that
/// [`curl_share_init`] returned and that has not been passed to
/// [`curl_share_cleanup`]. It may be used concurrently from several threads,
/// which is the interface's purpose and which this function's shared borrow
/// permits.
///
/// `param` must hold the argument type `option` names, per the table in the
/// module documentation: an `int` for `CURLSHOPT_SHARE` and
/// `CURLSHOPT_UNSHARE`, a `curl_lock_function` for `CURLSHOPT_LOCKFUNC`, a
/// `curl_unlock_function` for `CURLSHOPT_UNLOCKFUNC`, and any `void *` for
/// `CURLSHOPT_USERDATA`. The two callback options additionally require that the
/// function stay callable for as long as the share can deliver a notification
/// to it. A mismatch is undefined behaviour here exactly as it is in C, where
/// `va_arg` reading the wrong type is undefined too.
unsafe extern "C" fn share_setopt_slot(
    share: *mut CURLSH,
    option: c_int,
    param: *mut c_void,
) -> CURLSHcode {
    // Deliberately OUTSIDE the guard: the borrow has to exist before
    // `guard_tx` can be given the poison flag to consult. Nothing between here
    // and the guard can panic -- a null check and two field projections -- so
    // there is no window the containment misses.
    //
    // SAFETY: forwarded verbatim from this function's own safety contract,
    // which is what `borrow` requires: `share` is null -- answered with `None`
    // -- or addresses a live `ShareHandle` that `into_raw` allocated and that
    // no mutable borrow aliases, there being no `borrow_mut` of a share
    // anywhere in this crate. The reference does not outlive this body.
    let handle = unsafe { borrow::<CURLSH, ShareHandle>(share) };

    // `if(!GOOD_SHARE_HANDLE(share)) return CURLSHE_INVALID;`
    // (`lib/curl_share.c:68-69`). The C's macro also tests the magic tag,
    // which the engine tests again inside `Share::setopt`; this is the null
    // half, which is the half a Rust reference cannot represent.
    let Some(handle) = handle else {
        return CURLSHcode::CURLSHE_INVALID;
    };

    guard_tx(&handle.poison, CURLSHcode::CURLSHE_INVALID, || {
        // A DIRECT ORDINAL MATCH. `CURLSHoption` is not composed from
        // `CURLOPT(na, t, nu)`, so there is no `/ 10000` type base to recover
        // and none is computed; each of the seven values names its own
        // trailing-argument type outright. The seven arms are written against
        // `codes.rs`'s discriminants rather than bare integers so that a
        // renumbering there is a compile error here.
        let request = match option {
            // `lib/curl_share.c:211-213` -- the outer `default:`, which
            // `CURLSHOPT_NONE` reaches because the switch has no case for it.
            _ if option == CURLSHoption::CURLSHOPT_NONE as c_int => {
                ShareOption::None
            }
            // `:79-145`. `va_arg(param, int)`, unvalidated: a value naming no
            // kind reaches `CURLSHE_BAD_OPTION` in the engine's inner switch.
            _ if option == CURLSHoption::CURLSHOPT_SHARE as c_int => {
                ShareOption::Share(slot_as_int(param))
            }
            // `:147-194`. Note that the C clears the specifier bit at `:150`
            // UNCONDITIONALLY, before its switch and therefore even when the
            // result is `CURLSHE_BAD_OPTION`, and that its switch has no
            // `CURL_LOCK_DATA_PSL` arm where `CURLSHOPT_SHARE`'s does. Both
            // asymmetries are real in curl 8.19.0-DEV and both are reproduced
            // by the engine rather than smoothed over.
            _ if option == CURLSHoption::CURLSHOPT_UNSHARE as c_int => {
                ShareOption::Unshare(slot_as_int(param))
            }
            // `:196-199`. A null pointer clears the callback; it is not an
            // error.
            //
            // SAFETY: by this function's safety contract `param` holds the
            // argument type `option` names, and this arm is reached only for
            // `CURLSHOPT_LOCKFUNC`, whose argument is a `curl_lock_function`.
            // That is exactly `slot_as_lockfunc`'s precondition, and
            // `wrap_lockfunc`'s liveness precondition is the same contract's
            // second clause.
            _ if option == CURLSHoption::CURLSHOPT_LOCKFUNC as c_int => {
                ShareOption::LockFunc(unsafe {
                    wrap_lockfunc(slot_as_lockfunc(param))
                })
            }
            // `:201-204`, and the same null-clears rule.
            //
            // SAFETY: as the arm above, for `CURLSHOPT_UNLOCKFUNC`, whose
            // declared argument is a `curl_unlock_function`.
            _ if option == CURLSHoption::CURLSHOPT_UNLOCKFUNC as c_int => {
                ShareOption::UnlockFunc(unsafe {
                    wrap_unlockfunc(slot_as_unlockfunc(param))
                })
            }
            // `:206-209`. Stored, never dereferenced.
            _ if option == CURLSHoption::CURLSHOPT_USERDATA as c_int => {
                ShareOption::UserData(slot_as_userdata(param))
            }
            // `:211-213` again -- `CURLSHOPT_LAST` is a sentinel the switch
            // does not name either.
            _ if option == CURLSHoption::CURLSHOPT_LAST as c_int => {
                ShareOption::Last
            }
            // Any other integer. Named rather than coerced to a variant that
            // means something else, and it reaches the same `default:` arm,
            // which is what the C does with every value its switch omits. A C
            // caller may legally pass any value of the enumeration's
            // compatible integer type, which is also why `option` is declared
            // `c_int` here rather than as the `#[repr(C)]` enum: receiving an
            // out-of-range value INTO a Rust enum would be undefined behaviour
            // before a line of this function ran. The header still reads
            // `CURLSHoption`, because `cbindgen.toml` excludes this prototype
            // and `build.rs` carries it verbatim.
            other => ShareOption::Unknown(other),
        };

        // Everything else belongs to the engine, and deliberately so
        // (pattern P10). `Share::setopt` performs the C's checks in the C's
        // order: the magic tag at `:68-69`, then `share->dirty` at `:71-74` --
        // which makes `CURLSHE_IN_USE` an answer this function gives too,
        // and not only `curl_share_cleanup` -- and only then the switch.
        CURLSHcode::from(handle.share.setopt(request))
    })
}

// The four assembled prologues for `curl_share_setopt`
//
// One per ABI flavour, with the label written LITERALLY rather than through a
// macro. That is deliberate twice over: `build.rs`'s `check_variadic_strategy`
// looks for the text `_curl_share_setopt:`, which is the assembly label that
// actually emits the global symbol and so cannot be faked by a comment; and
// `assembled_exports` recovers the exported name from `.globl ` and `.globl _`,
// which a macro's `$name` substitution would hide. A single symbol also buys
// nothing from a macro, unlike `super::printf`'s five.
//
// Mach-O decorates symbols with a leading underscore and ELF does not, so a
// prologue emitting only one spelling would export nothing on the targets
// needing the other. `.type` and `.size` are ELF-only and are omitted from the
// Mach-O flavours.
//
// Three of the four are a bare tail call. The third argument is already in the
// register `share_setopt_slot` reads -- RDX on both x86-64 flavours, x2 on
// AAPCS64 -- so there is nothing to relocate, and jumping rather than calling
// keeps the frame and the return address exactly as the caller left them.

// x86-64 System V, ELF flavour -- `x86_64-unknown-linux-gnu`.
//
// The variadic third argument is in RDX, which is where a non-variadic callee
// reads it, so the prologue is a jump. `%al` carries the caller's count of
// vector registers used and is ignored: no argument of any `CURLSHoption` is a
// floating-point type, and the callee never reads a register save area because
// it has no `va_list` to build.
#[cfg(all(target_arch = "x86_64", not(target_vendor = "apple")))]
core::arch::global_asm!(
    concat!(
        ".text\n",
        ".globl curl_share_setopt\n",
        ".p2align 4\n",
        ".type curl_share_setopt,@function\n",
        "curl_share_setopt:\n",
        ".cfi_startproc\n",
        "jmp {callee}\n",
        ".cfi_endproc\n",
        ".size curl_share_setopt, .-curl_share_setopt\n",
    ),
    callee = sym share_setopt_slot,
    options(att_syntax),
);

// x86-64 System V, Mach-O flavour -- `x86_64-apple-darwin`.
#[cfg(all(target_arch = "x86_64", target_vendor = "apple"))]
core::arch::global_asm!(
    concat!(
        ".text\n",
        ".globl _curl_share_setopt\n",
        ".p2align 4\n",
        "_curl_share_setopt:\n",
        ".cfi_startproc\n",
        "jmp {callee}\n",
        ".cfi_endproc\n",
    ),
    callee = sym share_setopt_slot,
    options(att_syntax),
);

// AAPCS64, ELF flavour -- `aarch64-unknown-linux-gnu`.
//
// AAPCS64 passes variadic arguments in the same registers as named ones until
// they run out, so the third argument is in x2 -- measured at the call site as
// `mov x2, x1` -- which is where the callee reads it. A bare branch; the linker
// inserts a range-extension veneer if one is ever needed.
#[cfg(all(target_arch = "aarch64", not(target_vendor = "apple")))]
core::arch::global_asm!(
    concat!(
        ".text\n",
        ".globl curl_share_setopt\n",
        ".p2align 2\n",
        ".type curl_share_setopt,%function\n",
        "curl_share_setopt:\n",
        ".cfi_startproc\n",
        "b {callee}\n",
        ".cfi_endproc\n",
        ".size curl_share_setopt, .-curl_share_setopt\n",
    ),
    callee = sym share_setopt_slot,
);

// Apple arm64, Mach-O flavour -- `aarch64-apple-darwin`.
//
// THIS IS THE TARGET ESCALATION A4 WAS RAISED ABOUT, AND THIS IS THE
// RESOLUTION FOR THIS SYMBOL. Apple's arm64 ABI passes every variadic argument
// on the stack -- measured at the call site as `str x1, [sp]` -- and never
// writes x2. `ldr x2, [sp]` loads the VALUE the caller actually wrote into the
// register the callee reads, so no register is treated as an argument the
// caller did not populate and the possibility is removed rather than mitigated.
//
// The load is of the value and not of the address: `curl_share_setopt`'s
// variadic part is exactly one argument occupying one slot, so `[sp]` holds the
// argument itself. (Contrast `super::form`'s `curl_formadd`, whose prologue is
// `mov x2, sp` because a genuinely open-ended list needs the cursor.)
#[cfg(all(target_arch = "aarch64", target_vendor = "apple"))]
core::arch::global_asm!(
    concat!(
        ".text\n",
        ".globl _curl_share_setopt\n",
        ".p2align 2\n",
        "_curl_share_setopt:\n",
        ".cfi_startproc\n",
        "ldr x2, [sp]\n",
        "b {callee}\n",
        ".cfi_endproc\n",
    ),
    callee = sym share_setopt_slot,
);

// 3 of 3: curl_share_cleanup

/// Frees a share object.
///
/// Supersedes `curl_share_cleanup` (`lib/curl_share.c:221-267`), declared at
/// `include/curl/curl.h:3082`.
///
/// # The return value decides whether the allocation is freed
///
/// `docs/libcurl/curl_share_cleanup.md:59-60` requires that *"If an error
/// occurs, then the share object is not deleted."* So:
///
/// * [`CURLSHcode::CURLSHE_OK`] -- the engine tore everything down and cleared
///   the validity tag, and the allocation is released here, exactly once.
/// * [`CURLSHcode::CURLSHE_IN_USE`] -- easy handles are still attached
///   (`:231-235`). **Nothing was torn down**, the share is exactly as usable as
///   it was, and the caller still owns the pointer and must call again later.
/// * [`CURLSHcode::CURLSHE_INVALID`] -- the pointer was null, or the share was
///   already retired. There is nothing to free.
///
/// Getting that split backwards is a double free or a leak. It is expressed as
/// one `match` on the engine's answer, and the engine's `claim_cleanup` makes
/// the `Ok` arm reachable by exactly one caller per share even when two threads
/// call this function at once -- which the C, whose three steps are
/// unsynchronised, does not.
///
/// # A poisoned handle is still freed
///
/// This is the one entry point that does not consult the [`Poison`] flag, and
/// the exception is the panic boundary's own: *"freeing a poisoned handle has
/// to keep working, or a contained defect becomes a leak."* It therefore uses
/// [`guard`] rather than
/// [`guard_tx`](super::panic_boundary::guard_tx).
///
/// # Safety
///
/// `share` must be either null -- answered with
/// [`CURLSHcode::CURLSHE_INVALID`] -- or a pointer that [`curl_share_init`]
/// returned and that has not already been freed by a successful call to this
/// function. Calling this twice on a pointer the first call answered
/// [`CURLSHcode::CURLSHE_OK`] for is a double free, and the pointer must not be
/// used afterwards. Nothing else may be using the handle at the moment the call
/// succeeds. That contract is the C's unchanged, and no implementation can
/// defend against a violation of it.
#[no_mangle]
pub unsafe extern "C" fn curl_share_cleanup(share: *mut CURLSH) -> CURLSHcode {
    guard(CURLSHcode::CURLSHE_INVALID, || {
        // The borrow is confined to this block so that it has certainly ended
        // before `drop_raw` reclaims the allocation below. A `&` outliving the
        // `Box::from_raw` that frees it would be exactly the aliasing fault
        // this arrangement exists to prevent.
        let outcome = {
            // SAFETY: forwarded verbatim from this function's own safety
            // contract, which is what `borrow` requires: `share` is null --
            // answered with `None` -- or addresses a live `ShareHandle` that
            // `into_raw` allocated and that nothing has reclaimed. The
            // reference dies at the end of this block, before anything frees
            // the allocation.
            let handle = unsafe { borrow::<CURLSH, ShareHandle>(share) };

            // `if(!GOOD_SHARE_HANDLE(share)) return CURLSHE_INVALID;`
            // (`:224-225`) -- with no lock taken and no notification
            // delivered, which is why this precedes everything else.
            let Some(handle) = handle else {
                return CURLSHcode::CURLSHE_INVALID;
            };

            // The engine delivers the lock notification of `:227-229`, reads
            // `share->dirty` at `:231` where the C reads it, delivers the
            // matching unlock on both the refusal path (`:232-233`) and the
            // success path (`:261-262`), tears the six stores down in the C's
            // order (`:237-259`) and clears the validity tag (`:263`).
            CURLSHcode::from(handle.share.cleanup())
        };

        // `:264` -- `curlx_free(share)`, reached only when everything above it
        // succeeded. On any other answer the C returns before the free and so
        // does this.
        if matches!(outcome, CURLSHcode::CURLSHE_OK) {
            // SAFETY: `share` is non-null, since a null pointer took the
            // `CURLSHE_INVALID` return above, and by this function's safety
            // contract it came from `into_raw` with this same `ShareHandle`
            // and has not been reclaimed. The borrow taken above has ended
            // with the enclosing block. `CURLSHE_OK` is reachable for one
            // caller per share -- the engine's `claim_cleanup` is a
            // compare-and-exchange, so two concurrent callers cannot both
            // observe it -- which is what makes this exactly one
            // `Box::from_raw` per allocation.
            unsafe { drop_raw::<CURLSH, ShareHandle>(share) };
        }

        outcome
    })
}

// Tests
//
// `tests-rs/abi/symbol_parity.rs` does not exist yet, so the in-crate
// assertions below ARE the enforcement mechanism for this module's share of the
// ABI rather than a supplement to it. That relocation is sanctioned: the C
// programs that would otherwise carry these assertions --
// `tests/libtest/lib506.c` and `lib3207.c` for the concurrent share, and
// `tests/unit/*` generally -- link a debug static libcurl and call internal
// `Curl_*` symbols, which cannot resolve against a Rust static library at all
// because `pub(crate)` items are genuinely absent from its symbol table rather
// than merely hidden.

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use crate::ffi::panic_boundary;

    // The exported name, declared as `include/curl/curl.h:3080-3081` declares
    // it. It is VARIADIC here, and that is the point: `curl_share_setopt` is
    // not a Rust item, so the assembled label is reachable only through the C
    // ABI -- which is precisely the path a caller takes, and the only path on
    // which the Apple arm64 argument relocation is observable at all.
    extern "C" {
        fn curl_share_setopt(
            share: *mut CURLSH,
            option: c_int,
            ...
        ) -> CURLSHcode;
    }

    // The option and data integers, spelled as a C caller spells them: plain
    // `int`s. `lib/curl_share.c:81` and `:149` read the data kind back with
    // `va_arg(param, int)`, and a caller writing `CURL_LOCK_DATA_COOKIE` passes
    // an `int` by the time it reaches the argument list.
    const SHOPT_NONE: c_int = 0;
    const SHOPT_SHARE: c_int = 1;
    const SHOPT_UNSHARE: c_int = 2;
    const SHOPT_LOCKFUNC: c_int = 3;
    const SHOPT_UNLOCKFUNC: c_int = 4;
    const SHOPT_USERDATA: c_int = 5;
    const SHOPT_LAST: c_int = 6;

    const DATA_NONE: c_int = 0;
    const DATA_SHARE: c_int = 1;
    const DATA_COOKIE: c_int = 2;
    const DATA_DNS: c_int = 3;
    const DATA_SSL_SESSION: c_int = 4;
    const DATA_CONNECT: c_int = 5;
    const DATA_PSL: c_int = 6;
    const DATA_HSTS: c_int = 7;

    /// The answer `CURLSHOPT_SHARE` and `CURLSHOPT_UNSHARE` give for `kind` in
    /// THIS build.
    ///
    /// Three of the five shareable kinds are unconditional and two are not.
    /// The cookie jar sits inside `#ifndef CURL_DISABLE_COOKIES` in the C
    /// (`lib/curl_share.c:94-96` for the share arm, `:161-163` for the
    /// unshare arm) and the HSTS cache inside `#ifndef CURL_DISABLE_HSTS`
    /// (`:106-108` and `:171-173`), so a build without them answers
    /// `CURLSHE_NOT_BUILT_IN` where a full build answers `CURLSHE_OK`. Both
    /// arms agree, which is why one helper serves both directions.
    ///
    /// Asserting the build's OWN answer rather than a fixed `CURLSHE_OK` is
    /// what `curl-rs-lib`'s `share` tests already do -- see
    /// `unshare_with_the_public_suffix_list_is_a_bad_option_and_still_clears`,
    /// which takes the same `cfg!` form. Without it these assertions pass only
    /// under the default feature set and fail under `--no-default-features`
    /// for a reason that is not a defect in the code under test.
    fn expected_for_kind(kind: c_int) -> CURLSHcode {
        match kind {
            DATA_COOKIE if !cfg!(feature = "cookies") => {
                CURLSHcode::CURLSHE_NOT_BUILT_IN
            }
            DATA_HSTS if !cfg!(feature = "hsts") => {
                CURLSHcode::CURLSHE_NOT_BUILT_IN
            }
            _ => CURLSHcode::CURLSHE_OK,
        }
    }
    const DATA_LAST: c_int = 8;

    /// This file up to but not including its test module.
    ///
    /// The truncation is load-bearing rather than tidy. Every assertion below
    /// that is about this file's text searches for a needle, and the assertion
    /// itself contains that needle as a string literal -- so a scanner over the
    /// whole file would match itself and pass no matter what the production
    /// code said. Four of these assertions failed exactly that way before the
    /// truncation was added, which is the reason it is documented here instead
    /// of assumed.
    fn production_source() -> &'static str {
        let source = include_str!("share.rs");
        let at = source
            .find("#[cfg(test)]")
            .expect("this module has a test module");
        &source[..at]
    }

    /// [`production_source`] with its comments removed, so that prose
    /// describing a trap cannot satisfy an assertion looking for the trap.
    ///
    /// Line comments only, which is all this file uses. String literals are
    /// left alone deliberately: the assembly is written as string literals and
    /// several assertions are about it.
    fn production_code() -> String {
        production_source()
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n")
    }

    // -- The file's own shape ------------------------------------------------

    #[test]
    fn this_file_defines_exactly_the_three_names_and_not_the_fourth() {
        let code = production_code();

        // Two are ordinary Rust items.
        for name in ["curl_share_init", "curl_share_cleanup"] {
            let plain = format!("pub extern \"C\" fn {name}(");
            let unsafe_ = format!("pub unsafe extern \"C\" fn {name}(");
            assert_eq!(
                code.matches(&plain).count() + code.matches(&unsafe_).count(),
                1,
                "{name} must be defined exactly once",
            );
        }

        // The exported count, so a third `#[no_mangle]` cannot slip in. The
        // attribute is assembled from two pieces so this line does not count
        // itself.
        let attribute = format!("#[{}]", "no_mangle");
        assert_eq!(
            code.matches(attribute.as_str()).count(),
            2,
            "two Rust exports; the third symbol is assembled",
        );

        // `curl_share_setopt` is not a Rust function at all, on purpose. The
        // needle carries the opening parenthesis so that
        // `share_setopt_slot`'s own signature cannot match it.
        assert!(
            !code.contains("extern \"C\" fn curl_share_setopt("),
            "curl_share_setopt is variadic and must not be a Rust function \
             outside the test module's `extern` block",
        );

        // ...and is exported once per object format per architecture instead.
        assert_eq!(
            code.matches(".globl curl_share_setopt\\n").count(),
            2,
            "one ELF label per x86-64 and aarch64 prologue",
        );
        assert_eq!(
            code.matches(".globl _curl_share_setopt\\n").count(),
            2,
            "one Mach-O label per x86-64 and aarch64 prologue",
        );
        assert_eq!(
            code.matches("core::arch::global_asm!").count(),
            4,
            "four ABI flavours: x86-64 and aarch64, ELF and Mach-O",
        );

        // The label `build.rs`'s `check_variadic_strategy` looks for, written
        // literally rather than through a macro's `$name` substitution.
        assert_eq!(
            code.matches("\"_curl_share_setopt:\\n\"").count(),
            2,
            "the Mach-O label must be literal, or the gate cannot see it",
        );

        // The fourth `curl_share_*` name is `super::strerror`'s. A definition
        // here would be a duplicate export -- a link error, but one whose
        // diagnosis is much clearer stated this way.
        assert!(
            !code.contains("fn curl_share_strerror"),
            "curl_share_strerror is defined in strerror.rs, beside the other \
             three strerror functions that lib/strerror.c houses",
        );
    }

    #[test]
    fn the_apple_arm64_prologue_loads_the_slot_the_caller_wrote() {
        let code = production_code();

        // The one instruction that resolves A4 for this symbol. `ldr` and not
        // `mov`: the value is wanted, not the cursor, because the variadic part
        // is exactly one argument occupying exactly one slot.
        assert!(
            code.contains("\"ldr x2, [sp]\\n\""),
            "the Apple arm64 prologue must load the stack slot into x2",
        );
        assert!(
            !code.contains("\"mov x2, sp\\n\""),
            "`mov x2, sp` would pass the cursor, which is curl_formadd's \
             prologue and not this one's",
        );

        // Every prologue tail-calls the same private implementation, and none
        // of them is `#[no_mangle]`: an exported callee would be a 101st symbol
        // and would fail the nm parity gate against lib/libcurl.def's 100.
        assert_eq!(
            code.matches("callee = sym share_setopt_slot,").count(),
            4,
            "all four prologues reach the one implementation",
        );
        assert_eq!(
            code.matches("unsafe extern \"C\" fn share_setopt_slot(")
                .count(),
            1,
        );
    }

    #[test]
    fn no_engine_state_and_no_type_declaration_lives_here() {
        let code = production_code();

        // Pattern P10: a facade. The shared cookie jar, DNS cache, TLS session
        // cache, HSTS store, Public Suffix List and connection pool are all
        // curl-rs-lib's, and so is every decision about them.
        for line in code.lines() {
            let Some(rest) = line.strip_prefix("use ") else {
                continue;
            };
            let root = rest.split("::").next().unwrap_or_default();
            assert!(
                matches!(root, "core" | "std" | "curl_rs_lib" | "super"),
                "unexpected import root in a marshalling module: {line}",
            );
        }

        // No enumeration and no callback typedef is declared here. Both would
        // be emitted a second time into the generated header, which is a
        // duplicate C declaration and breaks all 129 docs/examples programs.
        for name in [
            "CURLSHcode",
            "CURLSHoption",
            "curl_lock_data",
            "curl_lock_access",
            "curl_lock_function",
            "curl_unlock_function",
        ] {
            for form in [
                format!("pub enum {name}"),
                format!("enum {name} "),
                format!("pub type {name}"),
                format!("type {name} ="),
            ] {
                assert!(
                    !code.contains(&form),
                    "{name} is declared in a sibling module and must only be \
                     imported here; found `{form}`",
                );
            }
        }

        // `CURLSH` is `typedef void`, so no opaque struct may be declared for
        // it either. `super::handle` owns the representation.
        assert!(
            !code.contains("struct CURLSH"),
            "CURLSH is `typedef void` (curl.h:110), never an opaque struct",
        );

        // No `/ 10000` type-base arithmetic. `CURLSHoption` is ordinal, so
        // dividing an option identifier by the `CURLOPT(na, t, nu)` base would
        // misread every one of the seven values.
        assert!(
            !code.contains("10000"),
            "CURLSHoption is ordinal; there is no type base to divide by",
        );

        // No feature gate. There is no `tls` feature in this crate, and all
        // three symbols must be exported under `--no-default-features`; an
        // unsupported share class answers CURLSHE_NOT_BUILT_IN, it does not
        // remove a symbol.
        assert!(
            !code.contains("#[cfg(feature"),
            "no share symbol is feature-gated",
        );

        // The safety invariant is the crate root's, and exactly one
        // `allow(unsafe_code)` exists in the whole crate -- on `mod ffi`.
        // Needles assembled so this test does not match itself.
        let allow = format!("#[{}(unsafe_code)]", "allow");
        let forbid = format!("#![{}(unsafe_code)]", "forbid");
        assert!(!code.contains(&allow), "the one allow is on `mod ffi`");
        assert!(
            !code.contains(&forbid),
            "forbid is curl-rs-lib's and curl-rs's"
        );
    }

    #[test]
    fn every_unsafe_block_carries_a_safety_comment() {
        // Not a substitute for review, but it does catch the one omission that
        // review reliably misses: a block added later without its rationale.
        let lines: Vec<&str> = production_source().lines().collect();
        let mut checked = 0;
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            // An `unsafe { .. }` block, as opposed to an `unsafe fn` item or an
            // `unsafe extern` declaration.
            if !(trimmed.starts_with("unsafe {")
                || trimmed.ends_with("unsafe {")
                || trimmed.contains("= unsafe {"))
            {
                continue;
            }
            let preceding =
                lines[..index].iter().rev().take(24).any(|earlier| {
                    earlier.trim_start().starts_with("// SAFETY:")
                });
            assert!(
                preceding,
                "the unsafe block on line {} has no `// SAFETY:` comment \
                 within twenty-four lines above it",
                index + 1,
            );
            checked += 1;
        }
        // Non-vacuity: a scanner that matched nothing would pass trivially.
        assert!(
            checked >= 5,
            "expected several unsafe blocks, found {checked}"
        );
    }

    // -- The ABI integers ----------------------------------------------------

    #[test]
    fn the_enumeration_integers_match_the_frozen_header() {
        // `CURLSHcode`, curl.h:3058-3066. Seven tokens; only CURLSHE_OK is
        // implicit in the C, the rest taking their values from declaration
        // order, and the comments in the header spell 1 to 5 out.
        assert_eq!(CURLSHcode::CURLSHE_OK as c_int, 0);
        assert_eq!(CURLSHcode::CURLSHE_BAD_OPTION as c_int, 1);
        assert_eq!(CURLSHcode::CURLSHE_IN_USE as c_int, 2);
        assert_eq!(CURLSHcode::CURLSHE_INVALID as c_int, 3);
        assert_eq!(CURLSHcode::CURLSHE_NOMEM as c_int, 4);
        assert_eq!(CURLSHcode::CURLSHE_NOT_BUILT_IN as c_int, 5);
        assert_eq!(CURLSHcode::CURLSHE_LAST as c_int, 6);

        // `CURLSHoption`, curl.h:3068-3077. Ordinal, with no base added -- the
        // fact the dispatch in this file depends on.
        assert_eq!(CURLSHoption::CURLSHOPT_NONE as c_int, SHOPT_NONE);
        assert_eq!(CURLSHoption::CURLSHOPT_SHARE as c_int, SHOPT_SHARE);
        assert_eq!(CURLSHoption::CURLSHOPT_UNSHARE as c_int, SHOPT_UNSHARE);
        assert_eq!(CURLSHoption::CURLSHOPT_LOCKFUNC as c_int, SHOPT_LOCKFUNC);
        assert_eq!(
            CURLSHoption::CURLSHOPT_UNLOCKFUNC as c_int,
            SHOPT_UNLOCKFUNC
        );
        assert_eq!(CURLSHoption::CURLSHOPT_USERDATA as c_int, SHOPT_USERDATA);
        assert_eq!(CURLSHoption::CURLSHOPT_LAST as c_int, SHOPT_LAST);

        // `curl_lock_data`, curl.h:3026-3040. Nine tokens.
        assert_eq!(lock_data_as_c(LockData::None) as c_int, DATA_NONE);
        assert_eq!(lock_data_as_c(LockData::Share) as c_int, DATA_SHARE);
        assert_eq!(lock_data_as_c(LockData::Cookie) as c_int, DATA_COOKIE);
        assert_eq!(lock_data_as_c(LockData::Dns) as c_int, DATA_DNS);
        assert_eq!(
            lock_data_as_c(LockData::SslSession) as c_int,
            DATA_SSL_SESSION
        );
        assert_eq!(lock_data_as_c(LockData::Connect) as c_int, DATA_CONNECT);
        assert_eq!(lock_data_as_c(LockData::Psl) as c_int, DATA_PSL);
        assert_eq!(lock_data_as_c(LockData::Hsts) as c_int, DATA_HSTS);
        assert_eq!(lock_data_as_c(LockData::Last) as c_int, DATA_LAST);

        // `curl_lock_access`, curl.h:3043-3048. Four tokens, three of them
        // explicitly numbered in the header.
        assert_eq!(lock_access_as_c(LockAccess::None) as c_int, 0);
        assert_eq!(lock_access_as_c(LockAccess::Shared) as c_int, 1);
        assert_eq!(lock_access_as_c(LockAccess::Single) as c_int, 2);
        assert_eq!(lock_access_as_c(LockAccess::Last) as c_int, 3);
    }

    #[test]
    fn the_handle_is_a_void_pointer_and_the_callbacks_are_pointer_sized() {
        // `typedef void CURLSH;` (curl.h:110). If this ever became an opaque
        // struct, every handle-passing call would change type.
        assert_eq!(
            core::mem::size_of::<*mut CURLSH>(),
            core::mem::size_of::<*mut c_void>(),
        );

        // The premise behind the two transmutes, restated at runtime for a
        // reader who does not trust a `const` assertion to have been compiled.
        assert_eq!(
            core::mem::size_of::<curl_lock_function>(),
            core::mem::size_of::<*mut c_void>(),
        );
        assert_eq!(
            core::mem::size_of::<curl_unlock_function>(),
            core::mem::size_of::<*mut c_void>(),
        );

        // A null slot really does decode to `None`, which is what makes
        // "a null pointer clears the callback" expressible.
        //
        // SAFETY: a null pointer satisfies both readers' preconditions -- the
        // null case is explicitly permitted -- and neither result is called.
        unsafe {
            assert!(slot_as_lockfunc(ptr::null_mut()).is_none());
            assert!(slot_as_unlockfunc(ptr::null_mut()).is_none());
        }
    }

    #[test]
    fn the_trailing_slot_reads_as_a_signed_thirty_two_bit_int() {
        // A C caller writes an `int` into a register-width slot and the upper
        // half is unspecified, so only the low 32 bits may be read. Each case
        // below is a bit pattern a caller could plausibly leave behind.
        assert_eq!(slot_as_int(ptr::null_mut()), 0);
        assert_eq!(slot_as_int(2_usize as *mut c_void), DATA_COOKIE);
        assert_eq!(slot_as_int(8_usize as *mut c_void), DATA_LAST);
        // Negative survives as itself: -1 arrives as 0xFFFF_FFFF.
        assert_eq!(slot_as_int(0xFFFF_FFFF_usize as *mut c_void), -1);
        // ...and an unspecified upper half is ignored rather than read.
        assert_eq!(slot_as_int(0xDEAD_BEEF_0000_0003_usize as *mut c_void), 3);
        assert_eq!(slot_as_int(0xFFFF_FFFF_0000_0000_usize as *mut c_void), 0);

        // The user pointer keeps every bit, because it is handed back whole.
        assert_eq!(slot_as_userdata(ptr::null_mut()), ShareUserData::NONE);
        let whole = 0xDEAD_BEEF_1234_5678_usize;
        assert_eq!(slot_as_userdata(whole as *mut c_void).bits(), whole);
        assert_eq!(
            userdata_as_ptr(slot_as_userdata(whole as *mut c_void)) as usize,
            whole
        );

        // The owner round-trips too, and `LockOwner::NONE` is the null handle
        // that curl_share_cleanup's three notifications pass.
        assert!(owner_as_ptr(LockOwner::NONE).is_null());
        assert_eq!(owner_as_ptr(LockOwner::from_bits(whole)) as usize, whole);
    }

    // -- Behaviour, through the exported C entry points -----------------------

    /// A live share, or a failure message that says which call refused.
    ///
    /// Every behavioural test starts here rather than with `Share::new`,
    /// because the point is to exercise the boundary and not the engine.
    fn init() -> *mut CURLSH {
        let handle = curl_share_init();
        assert!(!handle.is_null(), "curl_share_init answered null");
        handle
    }

    /// `curl_share_setopt(share, option, param)`, with the `int` payload a C
    /// caller would write.
    ///
    /// # Safety
    ///
    /// `share` must satisfy [`share_setopt_slot`]'s contract.
    unsafe fn setopt_int(
        share: *mut CURLSH,
        option: c_int,
        value: c_int,
    ) -> CURLSHcode {
        // SAFETY: delegated to this helper's own contract. The trailing
        // argument is an `int`, which is what both options that reach this
        // helper declare, and the call goes through the assembled label.
        unsafe { curl_share_setopt(share, option, value) }
    }

    #[test]
    fn init_yields_a_handle_and_cleanup_frees_it() {
        let share = init();
        // SAFETY: `share` came from `curl_share_init` above, is non-null and
        // has not been released.
        assert_eq!(
            unsafe { curl_share_cleanup(share) },
            CURLSHcode::CURLSHE_OK
        );
    }

    #[test]
    fn the_engine_lets_exactly_one_caller_reach_the_free() {
        // WHAT IS NOT TESTED HERE, AND WHY.
        //
        // The obvious test -- call `curl_share_cleanup` twice on one pointer,
        // or from several threads at once, and assert that only the first
        // answers CURLSHE_OK -- IS A USE-AFTER-FREE and cannot be written. The
        // first successful call frees the allocation, so every later `borrow`
        // of that pointer reads memory this process has returned to the
        // allocator. It was written, it segmentation-faulted, and that is the
        // correct outcome rather than a flaw in the test: the C has the same
        // contract, `docs/libcurl/curl_share_cleanup.md` places it on the
        // caller, and no implementation in any language can defend against a
        // violation of it. Both entry points say so in their `# Safety`
        // sections. A test that violated it would fail under Miri and
        // AddressSanitizer exactly as it should, and would teach a reader that
        // the pattern is supported when it is not.
        //
        // The property this file actually DEPENDS on is narrower and is
        // testable without touching a freed allocation: the engine must let at
        // most one caller observe CURLSHE_OK, because that is the answer on
        // which -- and only on which -- `curl_share_cleanup` calls `drop_raw`.
        // So the race is run against a `ShareHandle` this function owns and
        // keeps alive for the whole test, and nothing frees anything.
        let handle = ShareHandle::new();
        let shared = std::sync::Arc::new(handle);
        let winners = std::sync::Arc::new(AtomicUsize::new(0));

        let mut threads = Vec::new();
        for _ in 0..4 {
            let shared = std::sync::Arc::clone(&shared);
            let winners = std::sync::Arc::clone(&winners);
            threads.push(std::thread::spawn(move || {
                let code = CURLSHcode::from(shared.share.cleanup());
                if code == CURLSHcode::CURLSHE_OK {
                    winners.fetch_add(1, Ordering::SeqCst);
                } else {
                    // The loser gets what the C gives the second cleanup of an
                    // already-retired share.
                    assert_eq!(code, CURLSHcode::CURLSHE_INVALID);
                }
            }));
        }
        for thread in threads {
            thread.join().expect("a worker thread panicked");
        }

        assert_eq!(
            winners.load(Ordering::SeqCst),
            1,
            "exactly one caller may reach the free, or `drop_raw` runs twice",
        );

        // And the retired share refuses everything afterwards rather than
        // answering from emptied stores.
        assert!(!shared.share.is_valid());
        assert_eq!(
            CURLSHcode::from(shared.share.setopt(ShareOption::Share(2))),
            CURLSHcode::CURLSHE_INVALID,
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reaches the global_asm! label; see \
                  share_setopt_slot_under_miri"
    )]
    fn a_null_handle_is_refused_by_both_entry_points() {
        // `if(!GOOD_SHARE_HANDLE(share)) return CURLSHE_INVALID;`
        // (`lib/curl_share.c:68-69`, `:224-225`).
        //
        // SAFETY: a null handle is explicitly permitted by both contracts and
        // is answered rather than dereferenced.
        unsafe {
            assert_eq!(
                curl_share_cleanup(ptr::null_mut()),
                CURLSHcode::CURLSHE_INVALID,
            );
            assert_eq!(
                setopt_int(ptr::null_mut(), SHOPT_SHARE, DATA_COOKIE),
                CURLSHcode::CURLSHE_INVALID,
            );
            assert_eq!(
                curl_share_setopt(
                    ptr::null_mut(),
                    SHOPT_USERDATA,
                    ptr::null_mut::<c_void>(),
                ),
                CURLSHcode::CURLSHE_INVALID,
            );
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reaches the global_asm! label; see \
                  share_setopt_slot_under_miri"
    )]
    fn the_five_shareable_kinds_are_accepted() {
        let share = init();
        // SAFETY: `share` is live throughout; each trailing argument is the
        // `int` that CURLSHOPT_SHARE declares.
        unsafe {
            for kind in [
                DATA_DNS,
                DATA_COOKIE,
                DATA_HSTS,
                DATA_SSL_SESSION,
                DATA_CONNECT,
            ] {
                assert_eq!(
                    setopt_int(share, SHOPT_SHARE, kind),
                    expected_for_kind(kind),
                    "CURLSHOPT_SHARE answered wrongly for kind {kind}",
                );
            }

            // `CURL_LOCK_DATA_CONNECT` twice: "It is safe to set this option
            // several times on a share." (`lib/curl_share.c:128`).
            assert_eq!(
                setopt_int(share, SHOPT_SHARE, DATA_CONNECT),
                CURLSHcode::CURLSHE_OK,
            );

            // `CURL_LOCK_DATA_PSL` is either accepted or reported absent, per
            // the `#ifndef USE_LIBPSL` at `:135-137`. Both are correct answers
            // and which one this build gives is the engine's to decide, so the
            // assertion is on the pair rather than on one of them.
            let psl = setopt_int(share, SHOPT_SHARE, DATA_PSL);
            assert!(
                matches!(
                    psl,
                    CURLSHcode::CURLSHE_OK | CURLSHcode::CURLSHE_NOT_BUILT_IN
                ),
                "CURLSHOPT_SHARE/PSL answered {psl:?}",
            );

            assert_eq!(curl_share_cleanup(share), CURLSHcode::CURLSHE_OK);
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reaches the global_asm! label; see \
                  share_setopt_slot_under_miri"
    )]
    fn the_out_of_band_kinds_and_options_are_bad_options() {
        let share = init();
        // SAFETY: `share` is live throughout and every trailing argument
        // matches its option's declared type.
        unsafe {
            // The C's inner `default:` (`lib/curl_share.c:140-141`).
            // `CURL_LOCK_DATA_SHARE` lands there too: the inner switch has no
            // case for it, so asking to share the share's own internal state
            // is a bad option even though its bit is already set.
            for kind in [DATA_NONE, DATA_SHARE, DATA_LAST, 9, -1, 1 << 20] {
                assert_eq!(
                    setopt_int(share, SHOPT_SHARE, kind),
                    CURLSHcode::CURLSHE_BAD_OPTION,
                    "CURLSHOPT_SHARE accepted kind {kind}",
                );
            }

            // The C's outer `default:` (`:211-213`), which CURLSHOPT_NONE and
            // CURLSHOPT_LAST reach because the switch names neither.
            for option in [SHOPT_NONE, SHOPT_LAST, 7, 99, -1] {
                assert_eq!(
                    setopt_int(share, option, DATA_COOKIE),
                    CURLSHcode::CURLSHE_BAD_OPTION,
                    "option {option} was not refused",
                );
            }

            assert_eq!(curl_share_cleanup(share), CURLSHcode::CURLSHE_OK);
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reaches the global_asm! label; see \
                  share_setopt_slot_under_miri"
    )]
    fn unshare_reproduces_the_c_asymmetries_rather_than_smoothing_them() {
        let share = init();
        // SAFETY: `share` is live throughout; every payload is an `int`.
        unsafe {
            for kind in [DATA_DNS, DATA_COOKIE, DATA_HSTS, DATA_SSL_SESSION] {
                assert_eq!(
                    setopt_int(share, SHOPT_SHARE, kind),
                    expected_for_kind(kind),
                );
                assert_eq!(
                    setopt_int(share, SHOPT_UNSHARE, kind),
                    expected_for_kind(kind),
                    "CURLSHOPT_UNSHARE answered wrongly for kind {kind}",
                );
            }

            // `CURL_LOCK_DATA_CONNECT` unshares with a bare `break` and no
            // destroy (`:187-188`).
            assert_eq!(
                setopt_int(share, SHOPT_UNSHARE, DATA_CONNECT),
                CURLSHcode::CURLSHE_OK,
            );

            // THE ASYMMETRY. `CURLSHOPT_SHARE`'s inner switch has a
            // `CURL_LOCK_DATA_PSL` arm (`:134-138`); `CURLSHOPT_UNSHARE`'s has
            // none, so PSL falls to its `default:` at `:190-192` and answers
            // CURLSHE_BAD_OPTION. That is genuinely what curl 8.19.0-DEV does,
            // and reproducing it rather than tidying it is the preservation
            // mandate: where a choice exists between a tidier design and a more
            // behaviourally faithful one, faithfulness wins.
            assert_eq!(
                setopt_int(share, SHOPT_UNSHARE, DATA_PSL),
                CURLSHcode::CURLSHE_BAD_OPTION,
            );

            assert_eq!(curl_share_cleanup(share), CURLSHcode::CURLSHE_OK);
        }
    }

    // The counting callbacks
    //
    // `extern "C" fn` cannot capture, so the observations go into statics, and
    // the statics are shared, so the tests that read them hold one lock. A
    // panic inside an `extern "C" fn` would ABORT the process on this toolchain
    // rather than unwind -- that is rustc's own `C-unwind` rule and not this
    // crate's choice -- so no callback here panics, and panic containment is
    // asserted through `panic_boundary::contained` instead.

    static CALLBACK_LOCK: Mutex<()> = Mutex::new(());
    static LOCK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static UNLOCK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SEEN_OWNER: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SEEN_DATA: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SEEN_ACCESS: AtomicUsize = AtomicUsize::new(usize::MAX);
    static SEEN_USERPTR: AtomicUsize = AtomicUsize::new(usize::MAX);

    /// A `curl_lock_function` that records what it was passed.
    extern "C" fn counting_lock(
        handle: *mut CURL,
        data: curl_lock_data,
        locktype: curl_lock_access,
        userptr: *mut c_void,
    ) {
        LOCK_CALLS.fetch_add(1, Ordering::SeqCst);
        SEEN_OWNER.store(handle as usize, Ordering::SeqCst);
        SEEN_DATA.store(data as usize, Ordering::SeqCst);
        SEEN_ACCESS.store(locktype as usize, Ordering::SeqCst);
        SEEN_USERPTR.store(userptr as usize, Ordering::SeqCst);
    }

    /// A `curl_unlock_function` that records what it was passed.
    extern "C" fn counting_unlock(
        _handle: *mut CURL,
        _data: curl_lock_data,
        _userptr: *mut c_void,
    ) {
        UNLOCK_CALLS.fetch_add(1, Ordering::SeqCst);
    }

    /// Installs both counting callbacks and `userptr`, then zeroes the
    /// counters.
    ///
    /// # Safety
    ///
    /// `share` must be a live handle with nothing attached, since
    /// `curl_share_setopt` refuses every option while any handle is.
    unsafe fn install_counters(share: *mut CURLSH, userptr: usize) {
        // SAFETY: delegated to this helper's contract. Each trailing argument
        // is the type its option declares: a `curl_lock_function`, a
        // `curl_unlock_function` and a `void *`. Both callbacks are `'static`
        // items and so outlive every notification.
        unsafe {
            assert_eq!(
                curl_share_setopt(
                    share,
                    SHOPT_LOCKFUNC,
                    counting_lock as *mut c_void,
                ),
                CURLSHcode::CURLSHE_OK,
            );
            assert_eq!(
                curl_share_setopt(
                    share,
                    SHOPT_UNLOCKFUNC,
                    counting_unlock as *mut c_void,
                ),
                CURLSHcode::CURLSHE_OK,
            );
            assert_eq!(
                curl_share_setopt(
                    share,
                    SHOPT_USERDATA,
                    userptr as *mut c_void,
                ),
                CURLSHcode::CURLSHE_OK,
            );
        }
        LOCK_CALLS.store(0, Ordering::SeqCst);
        UNLOCK_CALLS.store(0, Ordering::SeqCst);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reaches the global_asm! label; see \
                  share_setopt_slot_under_miri"
    )]
    fn cleanup_delivers_the_two_notifications_the_c_delivers() {
        let _serialised =
            CALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let share = init();
        let userptr = 0x5EED_usize;

        // SAFETY: `share` is live, nothing is attached, and both callbacks are
        // `'static` items.
        unsafe {
            install_counters(share, userptr);

            // The callbacks are ABI-visible and must STILL be invoked.
            // `lib/curl_share.c:227-229` delivers a lock notification for
            // CURL_LOCK_DATA_SHARE with CURL_LOCK_ACCESS_SINGLE and a NULL
            // handle, unconditional on the specifier; `:261-262` delivers the
            // matching unlock after the teardown. Exactly one of each.
            assert_eq!(curl_share_cleanup(share), CURLSHcode::CURLSHE_OK);
        }

        assert_eq!(LOCK_CALLS.load(Ordering::SeqCst), 1, "one lock at :228");
        assert_eq!(
            UNLOCK_CALLS.load(Ordering::SeqCst),
            1,
            "one unlock at :262",
        );

        // And the arguments are the C's, not merely present.
        assert_eq!(SEEN_OWNER.load(Ordering::SeqCst), 0, "a NULL CURL *");
        assert_eq!(
            SEEN_DATA.load(Ordering::SeqCst),
            DATA_SHARE as usize,
            "CURL_LOCK_DATA_SHARE",
        );
        assert_eq!(
            SEEN_ACCESS.load(Ordering::SeqCst),
            2,
            "CURL_LOCK_ACCESS_SINGLE",
        );
        assert_eq!(SEEN_USERPTR.load(Ordering::SeqCst), userptr);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reaches the global_asm! label; see \
                  share_setopt_slot_under_miri"
    )]
    fn a_null_callback_pointer_clears_it_rather_than_failing() {
        let _serialised =
            CALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let share = init();

        // SAFETY: `share` is live and nothing is attached. A null trailing
        // argument is explicitly permitted for both callback options --
        // `lib/curl_share.c:197-198` assigns whatever `va_arg` produced with no
        // validation, and `tests/libtest/lib3207.c:154` passes NULL on purpose.
        unsafe {
            install_counters(share, 0);
            assert_eq!(
                curl_share_setopt(
                    share,
                    SHOPT_LOCKFUNC,
                    ptr::null_mut::<c_void>(),
                ),
                CURLSHcode::CURLSHE_OK,
            );
            assert_eq!(
                curl_share_setopt(
                    share,
                    SHOPT_UNLOCKFUNC,
                    ptr::null_mut::<c_void>(),
                ),
                CURLSHcode::CURLSHE_OK,
            );
            assert_eq!(curl_share_cleanup(share), CURLSHcode::CURLSHE_OK);
        }

        // Cleared means cleared: `if(share->lockfunc)` at `:227` and
        // `if(share->unlockfunc)` at `:261` are both false, so neither
        // notification is delivered at all.
        assert_eq!(LOCK_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(UNLOCK_CALLS.load(Ordering::SeqCst), 0);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reaches the global_asm! label; see \
                  share_setopt_slot_under_miri"
    )]
    fn an_attached_handle_makes_both_entry_points_answer_in_use() {
        let _serialised =
            CALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let share = init();

        // SAFETY: `share` is live and nothing is attached yet.
        unsafe {
            install_counters(share, 0);
        }

        // Borrow the handle to reach the engine's `attach`, which is what an
        // easy handle taking `CURLOPT_SHARE` performs (`lib/setopt.c:1520`).
        // There is no exported entry point for it in this crate yet -- the
        // whole `curl_easy_*` family is unwritten -- so the test reaches it
        // through the same shared borrow the entry points use.
        //
        // SAFETY: `share` is a live pointer from `curl_share_init` and nothing
        // holds a mutable borrow of it, there being no `borrow_mut` of a share
        // anywhere in this crate. Every borrow taken in this test is confined
        // to the block that takes it, so none is outstanding when the final
        // `curl_share_cleanup` frees the allocation.
        {
            let handle = unsafe { borrow::<CURLSH, ShareHandle>(share) }
                .expect("the handle is live");
            assert!(
                handle
                    .share
                    .attach(LockOwner::from_bits(1), |_| ())
                    .is_some(),
                "attach was refused",
            );
            assert!(handle.share.is_in_use());
        }

        // attach delivered its own bracketing pair for CURL_LOCK_DATA_SHARE,
        // whose bit is set from birth (`lib/curl_share.c:38`). Count from here.
        LOCK_CALLS.store(0, Ordering::SeqCst);
        UNLOCK_CALLS.store(0, Ordering::SeqCst);

        // SAFETY: `share` is live and the borrow above is a shared one, which
        // is exactly what these entry points also take.
        unsafe {
            // `lib/curl_share.c:71-74` refuses EVERY option while any handle
            // is attached -- the two callback options and the user pointer
            // included -- and it does so BEFORE the switch. So CURLSHE_IN_USE
            // is an answer `curl_share_setopt` gives too, not only
            // `curl_share_cleanup`.
            for (option, value) in [
                (SHOPT_SHARE, DATA_COOKIE),
                (SHOPT_UNSHARE, DATA_COOKIE),
                (SHOPT_NONE, 0),
            ] {
                assert_eq!(
                    setopt_int(share, option, value),
                    CURLSHcode::CURLSHE_IN_USE,
                    "option {option} was not refused while in use",
                );
            }

            // `:231-235`: the lock notification of `:227-229` has already been
            // delivered, the matching unlock is delivered at `:232-233`, and
            // nothing is torn down.
            assert_eq!(curl_share_cleanup(share), CURLSHcode::CURLSHE_IN_USE,);
        }

        assert_eq!(LOCK_CALLS.load(Ordering::SeqCst), 1, "one lock at :228");
        assert_eq!(
            UNLOCK_CALLS.load(Ordering::SeqCst),
            1,
            "the unlock at :232-233 is NOT optional -- skipping it would \
             leave an application mutex held for the rest of the process",
        );

        // The share survived the refusal intact, which is what
        // `docs/libcurl/curl_share_cleanup.md:59-60` requires: "If an error
        // occurs, then the share object is not deleted."
        //
        // SAFETY: as the borrow above -- `share` is live, because the refused
        // cleanup tore nothing down and freed nothing, and this borrow ends
        // with the block.
        {
            let handle = unsafe { borrow::<CURLSH, ShareHandle>(share) }
                .expect("a refused cleanup leaves the share usable");
            assert!(handle.share.is_valid());
            assert!(handle
                .share
                .detach(LockOwner::from_bits(1), |_| ())
                .is_some());
            assert!(!handle.share.is_in_use());
        }

        // SAFETY: `share` is still live, since the refused cleanup freed
        // nothing, and no borrow of it is outstanding.
        assert_eq!(
            unsafe { curl_share_cleanup(share) },
            CURLSHcode::CURLSHE_OK
        );
    }

    // -- Concurrency, which is the whole point of this interface --------------

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reaches the global_asm! label; see \
                  share_setopt_slot_under_miri"
    )]
    fn one_share_serves_several_threads_through_the_c_entry_points() {
        // The property `docs/libcurl/opts/CURLSHOPT_SHARE.md` is written for
        // and `tests/libtest/lib506.c` and `lib3207.c` exercise: ONE share,
        // SEVERAL threads. It is the highest-value path in this file for Miri
        // and for AddressSanitizer, and it is the reason the entry points take
        // a SHARED borrow: a `&mut ShareHandle` would be an aliasing violation
        // the moment the second thread arrived, whereas `Share` is `Send +
        // Sync` and carries its own interior mutability.
        let share = init();

        // SAFETY: `share` is live and nothing is attached.
        unsafe {
            assert_eq!(
                setopt_int(share, SHOPT_SHARE, DATA_COOKIE),
                expected_for_kind(DATA_COOKIE),
            );
            assert_eq!(
                setopt_int(share, SHOPT_SHARE, DATA_DNS),
                expected_for_kind(DATA_DNS),
            );
        }

        // A raw pointer is not `Send`, so it crosses as its bit pattern. That
        // is sound here for the reason the interface exists: the allocation
        // outlives every thread below -- all four are joined before it is
        // freed -- and every operation they perform goes through a shared
        // borrow of a `Send + Sync` value.
        let address = share as usize;
        let mut threads = Vec::new();
        for worker in 0..4_usize {
            threads.push(std::thread::spawn(move || {
                let share = address as *mut CURLSH;
                for round in 0..64_usize {
                    // SAFETY: the allocation is live for the whole of this
                    // closure -- the spawning thread joins every handle before
                    // releasing it -- and concurrent shared borrows are exactly
                    // what a share handle is documented to permit. Every
                    // trailing argument is the type its option declares: an
                    // `int` for SHARE and UNSHARE, and any `void *` for
                    // USERDATA.
                    unsafe {
                        // A real mutation, raced against three other threads'.
                        // Every value is a valid `void *` payload, so the
                        // answer is deterministic however the writes
                        // interleave.
                        assert_eq!(
                            curl_share_setopt(
                                share,
                                SHOPT_USERDATA,
                                (worker * 64 + round + 1) as *mut c_void,
                            ),
                            CURLSHcode::CURLSHE_OK,
                        );
                        // An accepted kind, which reads and writes the
                        // specifier mask. `CURL_LOCK_DATA_CONNECT` is
                        // idempotent by the C's own comment at
                        // `lib/curl_share.c:128`, so racing it is legitimate.
                        assert_eq!(
                            setopt_int(share, SHOPT_SHARE, DATA_CONNECT),
                            CURLSHcode::CURLSHE_OK,
                        );
                        // A refused option is as good a test as an accepted
                        // one: it walks the whole dispatch and reads the same
                        // interior state.
                        assert_eq!(
                            setopt_int(share, SHOPT_NONE, 0),
                            CURLSHcode::CURLSHE_BAD_OPTION,
                        );
                    }
                }
            }));
        }
        for thread in threads {
            thread.join().expect("a worker thread panicked");
        }

        // SAFETY: every worker has been joined, so nothing is using the handle
        // and this call is the sole owner of it.
        assert_eq!(
            unsafe { curl_share_cleanup(share) },
            CURLSHcode::CURLSHE_OK
        );
    }

    // -- The same dispatch, reachable under Miri -----------------------------

    /// Everything `curl_share_setopt` does, minus the two-instruction hop.
    ///
    /// Miri refuses to execute a `global_asm!` symbol -- measured, verbatim:
    /// *"unsupported operation: can't call foreign function
    /// `curl_share_setopt` on OS `linux`"*, with Miri's own note that this
    /// *"does not indicate a bug in the program"*. Every test above that
    /// reaches the assembled label is therefore `#[cfg_attr(miri, ignore)]`,
    /// which would leave the whole option dispatch, both `transmute`s and the
    /// callback wrapping outside Miri's reach if nothing replaced them.
    ///
    /// This test replaces them. It calls [`share_setopt_slot`] directly, which
    /// is exactly what all four prologues tail-call and is byte-for-byte the
    /// same work; what it does not cover is the argument relocation, and that
    /// is two instructions of assembly rather than a code path with an
    /// aliasing story. So Miri still sees the RAII pair, the raw-pointer
    /// borrows, the transmutes, the `Arc` callback adapters and the concurrent
    /// shared access -- which is where undefined behaviour would actually
    /// live.
    #[test]
    fn share_setopt_slot_under_miri() {
        let share = init();

        // SAFETY: `share` is live throughout, nothing is attached, and each
        // trailing argument is the type its option declares. Both callbacks
        // are `'static` items, so they outlive every notification.
        unsafe {
            assert_eq!(
                share_setopt_slot(
                    share,
                    SHOPT_SHARE,
                    DATA_COOKIE as usize as *mut c_void,
                ),
                expected_for_kind(DATA_COOKIE),
            );
            assert_eq!(
                share_setopt_slot(
                    share,
                    SHOPT_UNSHARE,
                    DATA_COOKIE as usize as *mut c_void,
                ),
                expected_for_kind(DATA_COOKIE),
            );
            assert_eq!(
                share_setopt_slot(share, SHOPT_NONE, ptr::null_mut()),
                CURLSHcode::CURLSHE_BAD_OPTION,
            );
            // The two transmuting arms, which are the ones with a soundness
            // question at all.
            assert_eq!(
                share_setopt_slot(
                    share,
                    SHOPT_LOCKFUNC,
                    counting_lock as *mut c_void,
                ),
                CURLSHcode::CURLSHE_OK,
            );
            assert_eq!(
                share_setopt_slot(
                    share,
                    SHOPT_UNLOCKFUNC,
                    counting_unlock as *mut c_void,
                ),
                CURLSHcode::CURLSHE_OK,
            );
            assert_eq!(
                share_setopt_slot(
                    share,
                    SHOPT_USERDATA,
                    0x5EED_usize as *mut c_void,
                ),
                CURLSHcode::CURLSHE_OK,
            );
            // A null handle, so the early return is exercised too.
            assert_eq!(
                share_setopt_slot(ptr::null_mut(), SHOPT_NONE, ptr::null_mut()),
                CURLSHcode::CURLSHE_INVALID,
            );
        }

        // Concurrent shared borrows of one handle, which is the aliasing
        // property the whole design turns on and the reason `borrow` is used in
        // place of `borrow_mut`.
        let address = share as usize;
        let mut threads = Vec::new();
        for _ in 0..3 {
            threads.push(std::thread::spawn(move || {
                let share = address as *mut CURLSH;
                for _ in 0..8 {
                    // SAFETY: the allocation outlives every thread -- all are
                    // joined below before it is freed -- and concurrent shared
                    // borrows are what a share handle permits.
                    unsafe {
                        assert_eq!(
                            share_setopt_slot(
                                share,
                                SHOPT_SHARE,
                                DATA_CONNECT as usize as *mut c_void,
                            ),
                            CURLSHcode::CURLSHE_OK,
                        );
                    }
                }
            }));
        }
        for thread in threads {
            thread.join().expect("a worker thread panicked");
        }

        // SAFETY: every worker is joined, so this call is the sole owner. The
        // callbacks installed above fire here, which puts the `Arc` adapters
        // and the pointer round-trips under Miri as well.
        assert_eq!(
            unsafe { curl_share_cleanup(share) },
            CURLSHcode::CURLSHE_OK,
        );
        assert!(LOCK_CALLS.load(Ordering::SeqCst) > 0, "the lock fired");
        assert!(UNLOCK_CALLS.load(Ordering::SeqCst) > 0, "the unlock fired");
    }

    // -- Panic containment ---------------------------------------------------

    #[test]
    fn the_containment_wiring_is_the_one_the_boundary_prescribes() {
        // Containment itself is `panic_boundary`'s own subject. What belongs
        // here is that this module is wired into it correctly, and the
        // assertion is structural because the alternative is not sound:
        // `panic_boundary::contained()` is a PROCESS-WIDE counter and
        // `panic_boundary`'s own tests raise contained panics deliberately, so
        // a before-and-after comparison of it would fail whenever the two ran
        // at the same moment. A flaky assertion about panics is worse than
        // none, because it teaches a reader to re-run the suite.
        //
        // A deliberate panic is also NOT injected. The only route into this
        // module from a panicking Rust closure is an application callback, and
        // an `extern "C" fn` that unwinds ABORTS the process on this toolchain
        // -- rustc's own rule, not this crate's choice -- so such a test could
        // report nothing.
        let code = production_code();

        // A pointer return falls back to null, which `init`'s own assertion
        // then catches.
        assert!(
            code.contains("guard_ptr(|| into_raw::<CURLSH, ShareHandle>("),
            "curl_share_init must route through guard_ptr",
        );

        // `curl_share_cleanup` uses `guard`, NOT `guard_tx`. That is the
        // panic boundary's own documented exception: "freeing a poisoned handle
        // has to keep working, or a contained defect becomes a leak."
        assert!(
            code.contains("guard(CURLSHcode::CURLSHE_INVALID, || {"),
            "curl_share_cleanup must route through plain guard",
        );

        // ...and `curl_share_setopt`'s body uses `guard_tx`, because it
        // mutates: a handle already poisoned by an earlier contained panic must
        // short-circuit rather than have half-mutated state read.
        assert!(
            code.contains(
                "guard_tx(&handle.poison, CURLSHcode::CURLSHE_INVALID"
            ),
            "share_setopt_slot must route through guard_tx",
        );
        assert_eq!(
            code.matches("guard_tx(").count(),
            1,
            "exactly one mutating entry point, so exactly one guard_tx",
        );

        // No second containment helper, and no abort strategy. A
        // `panic = "abort"` release profile is prohibited, and `[profile.*]`
        // is root-only, so a member profile would be ignored AND warn.
        assert!(
            !code.contains("catch_unwind"),
            "the one catch_unwind is panic_boundary's",
        );
        assert!(
            !code.contains("process::abort"),
            "aborting is not the containment strategy",
        );
        assert!(
            !code.contains("panic!") && !code.contains("unwrap()"),
            "no production path may panic of its own accord",
        );

        // Non-vacuity: the helper the three assertions above name must really
        // be reachable, or they are assertions about a string.
        assert!(!panic_boundary::would_redact(), "not inside a guard");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "reaches the global_asm! label; see \
                  share_setopt_slot_under_miri"
    )]
    fn every_answer_differs_from_its_own_panic_fallback() {
        // The behavioural counterpart of the structural test above, and the
        // reason the process-wide counter is not needed. Each fallback is a
        // value a panicking entry point would return, so an assertion that the
        // answer is something ELSE is itself proof that the body ran to
        // completion: null for the pointer return, CURLSHE_INVALID for both
        // CURLSHcode returns.
        let share = init();
        assert!(!share.is_null(), "guard_ptr's fallback is null");

        // SAFETY: `share` is live throughout and every payload matches its
        // option's declared type.
        unsafe {
            for (option, value, expected) in [
                (SHOPT_SHARE, DATA_COOKIE, expected_for_kind(DATA_COOKIE)),
                (SHOPT_UNSHARE, DATA_COOKIE, expected_for_kind(DATA_COOKIE)),
                (SHOPT_SHARE, 4242, CURLSHcode::CURLSHE_BAD_OPTION),
                (SHOPT_NONE, 0, CURLSHcode::CURLSHE_BAD_OPTION),
            ] {
                let answer = setopt_int(share, option, value);
                assert_ne!(
                    answer,
                    CURLSHcode::CURLSHE_INVALID,
                    "option {option} answered the panic fallback",
                );
                assert_eq!(answer, expected);
            }

            // An all-ones user pointer, which is the widest bit pattern the
            // slot can carry, is stored rather than validated.
            assert_eq!(
                curl_share_setopt(
                    share,
                    SHOPT_USERDATA,
                    usize::MAX as *mut c_void,
                ),
                CURLSHcode::CURLSHE_OK,
            );

            assert_eq!(curl_share_cleanup(share), CURLSHcode::CURLSHE_OK);
        }
    }
}
