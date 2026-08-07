// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The five exported URL-API entry points -- the public half of
//! `lib/urlapi.c`.
//!
//! | Symbol | Declared | Returns | Failure answer |
//! |--------|----------|---------|----------------|
//! | `curl_url` | `urlapi.h:113` | `CURLU *` | null |
//! | `curl_url_cleanup` | `urlapi.h:120` | `void` | none: there is no channel |
//! | `curl_url_dup` | `urlapi.h:126` | `CURLU *` | null |
//! | `curl_url_get` | `urlapi.h:133-134` | `CURLUcode` | a `CURLUcode` member |
//! | `curl_url_set` | `urlapi.h:141-142` | `CURLUcode` | a `CURLUcode` member |
//!
//! # FIVE, not six: `curl_url_strerror` is not here
//!
//! `lib/libcurl.def` lists SIX names under the `curl_url` prefix, on its lines
//! 90 to 95, and `include/curl/urlapi.h` DECLARES all six -- the sixth being
//! `curl_url_strerror` at `urlapi.h:149`, with an unnamed parameter. This
//! module owns five of them, because **definition location is not declaration
//! location**: `lib/strerror.c` defines all four of libcurl's strerror
//! functions in ONE translation unit -- `curl_easy_strerror` at `:34`,
//! `curl_multi_strerror` at `:326`, `curl_share_strerror` at `:385` and
//! `curl_url_strerror` at `:420` -- and the crate's partition follows the
//! definition. So [`super::strerror`] owns the sixth, and this module owns the
//! family LESS its strerror member: 5 rather than 6. That subtraction, applied
//! to four families, is what makes the twelve symbol modules sum to the 100
//! names in `lib/libcurl.def` rather than to 106. A definition is NOT moved to
//! match its declaring header.
//!
//! Each of the five has exactly ONE `#[no_mangle] pub extern "C"` definition. A
//! duplicate anywhere in the crate is a link error rather than a review
//! finding, so the claim is enforced by the linker; that the sixth name appears
//! nowhere in this file is asserted below by a test that reads the file.
//!
//! # `CURLU` is the one genuine opaque struct among the handle typedefs
//!
//! The public handle typedefs are NOT uniform, and treating them uniformly
//! breaks consumers. The measured inventory is SEVEN:
//!
//! | C declaration | Location | Kind |
//! |---|---|---|
//! | `typedef void CURL;` | `curl.h:109` | `void` |
//! | `typedef void CURLSH;` | `curl.h:110` | `void` |
//! | `typedef void CURLM;` | `multi.h:57` | `void` |
//! | `typedef struct Curl_URL CURLU;` | `urlapi.h:107` | opaque struct |
//! | `typedef struct CURLMsg CURLMsg;` | `multi.h:105` | layout-visible |
//! | `typedef struct curl_mime curl_mime;` | `curl.h:2428` | opaque struct |
//! | `typedef struct curl_mimepart curl_mimepart;` | `curl.h:2429` | opaque |
//!
//! `CURLU` is `struct Curl_URL`, not `void`, and that is what separates it from
//! `CURL`, `CURLM` and `CURLSH`. **The struct tag is `Curl_URL` and differs
//! from the typedef name**, which cbindgen cannot express: its natural output
//! for an opaque Rust type is `typedef struct X X;`, so it would emit `typedef
//! struct CURLU CURLU;` -- a DIFFERENT incomplete type from the one libcurl's
//! own translation units define, breaking any consumer that spells `struct
//! Curl_URL *` directly. The typedef is therefore pinned verbatim by
//! `build.rs`'s `URLAPI_H_DECLS` and `CURLU` and `Curl_URL` are both in
//! `cbindgen.toml`'s `[export] exclude`. The Rust side of that -- a genuine
//! opaque struct, not a `*mut c_void` -- belongs to
//! [`super::handle`](super::handle::Curl_URL) and is imported here, never
//! redeclared.
//!
//! # `CURLUPart` has eleven members and NO sentinel
//!
//! `urlapi.h:70-82` ends at `CURLUPART_ZONEID /* added in 7.65.0 */`. **There
//! is no `CURLUPART_LAST` and none may be invented.** Adding one would change
//! no existing integer but would add a public enumerant curl 8.19.0-DEV does
//! not have, which is why `cbindgen.toml` sets `add_sentinel = false` and why
//! this enumeration is one of the cases that proves the setting necessary. The
//! same trap applies to `CURLHcode` (`header.h:47-56`) and `CURLSTScode`
//! (`curl.h:1056-1060`). `CURLUcode`, by contrast, DOES carry a bound --
//! `CURLUE_LAST` = 32 at `urlapi.h:67` -- and it is a bound, not a value.
//!
//! # The `const` asymmetry is deliberate and ABI-visible
//!
//! `curl_url_dup` takes `const CURLU *` and `curl_url_get` takes `const CURLU
//! *`, while `curl_url_set` takes a mutable `CURLU *`. That is `*const CURLU`
//! against `*mut CURLU` here, and the two are NOT unified: the manual-page
//! synopses are compiled against the generated header by
//! `.github/scripts/verify-synopsis.pl`, so a dropped `const` is a gate failure
//! rather than a style question. It also mirrors what each function does --
//! only `curl_url_set` mutates -- which is why the split-borrow below can hand
//! `curl_url_get` a shared reference and `curl_url_set` an exclusive one.
//!
//! # No parsing lives here
//!
//! Not one line of this file inspects the shape of a URL. Percent-encoding,
//! punycode, the dot-segment removal, the port syntax, the scheme syntax, the
//! IPv6 literal and zone identifier, the `%alternatives` of an empty query --
//! all of it belongs to `curl-rs-lib/src/url/{mod,escape,idn}.rs`, which
//! measures itself against oracles taken from the frozen library. This module
//! marshals: it null-checks, converts a `*const c_char` to bytes, calls one
//! engine method, and turns the answer into a `CURLUcode` or a caller-owned
//! `char *`. That is pattern P10, and it is what keeps the ABI shim auditable
//! in isolation.
//!
//! In particular the `url`, `idna` and `percent-encoding` crates are NOT
//! reachable from here and must not become so. They are `curl-rs-lib`'s
//! dependencies, used BENEATH curl's own semantics rather than as a replacement
//! for them, because curl's parsing quirks are the contract: 1,476 of the 1,914
//! fixtures compare full request bytes as one joined string with no per-line
//! matching and no reordering, so a URL that differs by a single percent-escape
//! is a failed fixture.
//!
//! # Two measured corrections worth carrying, though neither function is here
//!
//! Both concern `curl_url_strerror`, which consumes the `CURLUcode` values this
//! module produces, and both are recorded because a reader who meets the
//! contradicting document elsewhere should know which side was checked against
//! the tree. [`super::strerror`] holds the full account.
//!
//! * **The default text is `"CURLUcode unknown"`, not `"Unknown error"`**
//!   (`lib/strerror.c:524`). The per-family defaults are not uniform: easy
//!   (`:317`) and multi (`:376`) are the generic `"Unknown error"`, while share
//!   (`:411`) is `"CURLSHcode unknown"` and url (`:524`) is `"CURLUcode
//!   unknown"`. A sibling specification for `curl-rs-lib/src/error.rs` stated
//!   the generic text for this family; the measurement wins, and the engine's
//!   `CURLUcode::UNKNOWN_MESSAGE` is in fact already correct.
//! * **`curl_url_strerror` has no `default:` arm.** It is exhaustive over all
//!   33 tokens and terminates with `case CURLUE_LAST: break;`, so its Rust
//!   counterpart is an exhaustive `match` with no wildcard.
//!
//! # Panic containment, and why it must be silent
//!
//! Every entry point routes its body through [`super::panic_boundary`], the
//! crate's single `catch_unwind`; unwinding across the C ABI is undefined
//! behaviour and `panic = "abort"` is prohibited in the release profile for
//! exactly this reason. The fallbacks are the documented failure values --
//! [`BAD_URL_HANDLE`] for the two `CURLUcode` functions, null for the two
//! pointer functions, and a quiet return for `curl_url_cleanup`, which has no
//! channel to report anything through. Nothing on the containment path writes
//! to a stream, because the fixture corpus compares output byte for byte.
//!
//! `curl_url_set` additionally routes through
//! [`guard_tx`](super::panic_boundary::guard_tx), because it MUTATES: a panic
//! part-way through a mutation leaves state whose progress is unknowable, so
//! the handle is poisoned and never read again. `curl_url_cleanup` is the
//! documented exception and must NOT route through there -- freeing a poisoned
//! handle has to keep working, or a contained defect becomes a leak.

use core::ffi::{c_char, c_int, c_uint};
use core::ptr;
use std::ffi::CStr;

use curl_rs_lib::scheme_registry;
use curl_rs_lib::url::{Url, UrlFlags};

use super::codes::CURLUcode;
use super::handle::{
    bad_handle_ptr, borrow, borrow_mut, drop_raw, into_raw, BAD_URL_HANDLE,
    CURLU,
};
use super::memory;
use super::panic_boundary::{guard, guard_ptr, guard_tx, guard_void, Poison};

/// What lives behind a `CURLU *`.
///
/// The engine's [`Url`] plus the [`Poison`] flag that
/// [`guard_tx`](super::panic_boundary::guard_tx) needs. The flag cannot live in
/// [`Url`] itself: `Poison` is this crate's type and `Url` is
/// `curl-rs-lib`'s, and a field of one inside the other would invert the
/// dependency the whole workspace is arranged to keep one-way. So the boundary
/// owns the pairing, which is the right place for it anyway -- poisoning
/// describes a fault in the C ABI's use of the handle, not a state the parser
/// has.
///
/// A consumer never sees this type. `CURLU` is an incomplete type in the header
/// (`urlapi.h:107`), so the only thing that crosses the boundary is a pointer,
/// and its width is the only ABI-visible property it has.
struct UrlHandle {
    /// The parsed URL. Every part, flag and quirk belongs to the engine.
    url: Url,

    /// Set once, and only by a panic contained inside a mutating entry point.
    ///
    /// One-way by design: there is no way to establish that an abandoned
    /// mutation was harmless, so a poisoned handle answers its family's failure
    /// code for every call except `curl_url_cleanup`.
    poison: Poison,
}

impl UrlHandle {
    /// An empty handle bound to the process-wide scheme table.
    ///
    /// The counterpart of `curl_url`'s whole body, `curlx_calloc(1,
    /// sizeof(struct Curl_URL))` (`lib/urlapi.c:1290`): every part absent,
    /// a zero port, all three bits clear. The registry is the one thing a
    /// `calloc` cannot supply, and [`scheme_registry`] is where the engine's
    /// documented wiring contract says to get it -- `curl_url()` takes no
    /// arguments, so there is nowhere else it could come from.
    fn new() -> Self {
        Self {
            url: Url::new(scheme_registry()),
            poison: Poison::new(),
        }
    }
}

/// Reads a caller's `CURLUPart` argument, which arrives as a plain integer.
///
/// The header declares `CURLUPart what` and this crate receives a `c_int`, and
/// that pairing is deliberate rather than a slip. A C caller may pass any value
/// of the enumeration's compatible integer type, and curl 8.19.0-DEV answers an
/// out-of-range one with `CURLUE_UNKNOWN_PART` -- measured at
/// `lib/urlapi.c:1626-1628` for `curl_url_get`, `:1873-1874` for `curl_url_set`
/// and `:1773-1774` for `urlset_clear`. Declaring the Rust parameter as the
/// `#[repr(C)]` enum would make that DEFINED C input an invalid Rust value,
/// which is undefined behaviour before a single line of this module runs. So
/// the parameter is a `c_int`, the two prototypes are carried verbatim by
/// `build.rs`'s `URLAPI_H_POST` so that the header still says `CURLUPart`, and
/// the narrowing happens in the engine's `get_by_id` and `set_by_id` -- which
/// exist for precisely this reason and say so.
///
/// This is the crate's established policy rather than a local invention:
/// `curl_version_info(stamp: c_int)` is declared `CURLversion` verbatim at
/// `build.rs:2379`, `curl_url_strerror(error: c_int)` is declared `CURLUcode`
/// verbatim, and `curl_easy_option_by_id(id: c_int)` is declared `CURLoption`
/// verbatim at `build.rs:1208`.
///
/// The function exists to give that reasoning one home and one name; the
/// conversion itself is the identity, because `c_int` and the engine's `i32`
/// are the same type on every target Rust supports.
const fn part_id(what: c_int) -> i32 {
    what
}

/// Reads a caller's `unsigned int flags` argument.
///
/// `urlapi.h:84-105` spells all sixteen bits WITHOUT an `L` suffix, so each is
/// an `int` and the parameter that receives them is an `unsigned int` --
/// `c_uint`, never `c_long`. (Contrast `CURLOPT_WS_OPTIONS`' bits, which use
/// `1L <<`; that literal-suffix distinction is an ABI distinction throughout
/// the headers and not a typo.)
///
/// Unknown bits are preserved rather than rejected, which is the C's behaviour:
/// it tests individual bits and never validates the mask. [`UrlFlags`] is
/// documented to do the same.
fn url_flags(flags: c_uint) -> UrlFlags {
    UrlFlags::from_bits(flags)
}

// ---------------------------------------------------------------------------
// The five exported entry points.
// ---------------------------------------------------------------------------

/// Creates a new, empty URL handle.
///
/// Supersedes `curl_url` (`lib/urlapi.c:1288-1291`), declared at
/// `include/curl/urlapi.h:113`. Returns a handle the caller owns and must
/// release with [`curl_url_cleanup`], or null.
///
/// Null means the same thing it means in C: no handle was produced. The C
/// reaches it through a failed `curlx_calloc`; here the only route is a
/// contained panic, because Rust's allocator aborts rather than reporting. A
/// caller that already tests the return value -- and every correct one does,
/// since `curl_url` has been documented as able to return null since 7.62.0 --
/// cannot tell the two apart, which is the property that matters.
///
/// Takes no arguments, so unlike its four siblings it is not an `unsafe fn`:
/// there is no caller obligation to state.
#[no_mangle]
pub extern "C" fn curl_url() -> *mut CURLU {
    guard_ptr(|| into_raw::<CURLU, UrlHandle>(UrlHandle::new()))
}

/// Frees a URL handle.
///
/// Supersedes `curl_url_cleanup` (`lib/urlapi.c:1293-1299`), declared at
/// `include/curl/urlapi.h:120`. Returns `void`, so it has **no error channel at
/// all**: a null handle is a silent no-op, exactly as the C's `if(u)` guard
/// makes it, and a contained panic is a silent return. Whatever it learns about
/// a fault, it keeps to itself.
///
/// Strings previously handed out by [`curl_url_get`] are NOT freed --
/// `urlapi.h:117-118` says so explicitly -- because they belong to the
/// application and are released with `curl_free`. The handle owns none of them.
///
/// A poisoned handle is still freed. That is the documented exception to
/// [`guard_tx`](super::panic_boundary::guard_tx)'s short-circuit: refusing to
/// release a handle that a contained panic had marked would turn one absorbed
/// defect into a permanent leak.
///
/// # Safety
///
/// `handle` must be either null or a pointer that [`curl_url`] or
/// [`curl_url_dup`] returned and that has not already been passed to this
/// function. Calling this twice on the same non-null pointer is a double free,
/// and the pointer must not be used afterwards. That contract is the C's
/// unchanged: `docs/libcurl/curl_url_cleanup.md` places the same obligation on
/// the caller, and no implementation can defend against a violation of it.
#[no_mangle]
pub unsafe extern "C" fn curl_url_cleanup(handle: *mut CURLU) {
    guard_void(|| {
        // SAFETY: forwarded verbatim from this function's own safety contract,
        // which is exactly what `drop_raw` requires of its caller: `handle` is
        // null -- which it handles by returning -- or a pointer `into_raw`
        // produced with this same `UrlHandle` and that nothing has reclaimed.
        // The `Box` it reconstitutes is dropped here and exactly once.
        unsafe { drop_raw::<CURLU, UrlHandle>(handle) };
    });
}

/// Duplicates a URL handle.
///
/// Supersedes `curl_url_dup` (`lib/urlapi.c:1310-1332`), declared at
/// `include/curl/urlapi.h:126`. The copy is independently owned and is released
/// with [`curl_url_cleanup`] exactly as [`curl_url`]'s result is, so it is
/// allocated through the same path.
///
/// The copy is DEEP: the C duplicates its ten strings through a `DUP` macro and
/// then copies three scalars, and the engine's [`Url::dup`] reproduces that
/// field for field -- including the one omission that is easy to mistake for an
/// oversight. `guessed_scheme` is **not** among the three scalars the C copies,
/// so a duplicate behaves as though its scheme had been given explicitly, and
/// `CURLU_NO_GUESS_SCHEME` therefore answers differently for the original and
/// the copy. That is reproduced deliberately; the engine documents and tests
/// it.
///
/// # A null input is answered rather than dereferenced
///
/// `curl_url_dup(NULL)` is UNDEFINED in C: the `DUP` macro reads `(src)->name`
/// with no null check, so the C segmentation faults. There is therefore no
/// defined output to preserve, and this returns null -- the same answer it
/// gives for any other failure, which is a documented return value every
/// correct caller already handles. That is a deliberate divergence from an
/// UNDEFINED behaviour, not from a defined one, and no fixture can depend on a
/// crash.
///
/// A poisoned input also yields null, because the state a contained panic left
/// behind must not be propagated into a second handle.
///
/// # Safety
///
/// `input` must be either null or a live pointer that [`curl_url`] or this
/// function returned, which has not been passed to [`curl_url_cleanup`], and
/// which nothing else is mutating for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_url_dup(input: *const CURLU) -> *mut CURLU {
    guard_ptr(|| {
        // SAFETY: forwarded verbatim from this function's own safety contract,
        // which is what `borrow` requires: `input` is null -- answered with
        // `None` -- or addresses a live `UrlHandle` that `into_raw` allocated
        // and that no mutable borrow aliases. `cast_mut` only restores the
        // mutability the pointer had when `into_raw` produced it; nothing is
        // written through it, and the borrow ends inside this closure.
        let source = unsafe { borrow::<CURLU, UrlHandle>(input.cast_mut()) };

        let Some(source) = source else {
            return bad_handle_ptr::<CURLU>();
        };
        if source.poison.is_poisoned() {
            return bad_handle_ptr::<CURLU>();
        }

        into_raw::<CURLU, UrlHandle>(UrlHandle {
            url: source.url.dup(),
            poison: Poison::new(),
        })
    })
}

/// Extracts one part of the URL.
///
/// Supersedes `curl_url_get` (`lib/urlapi.c:1541-1634`), declared at
/// `include/curl/urlapi.h:133-134`. On success `*part` receives a
/// NUL-terminated buffer that **the caller releases with `curl_free`**, and the
/// return is `CURLUE_OK`.
///
/// The buffer is allocated through [`super::memory`], libcurl's five
/// replaceable hooks, and not through `CString::into_raw`. That is mandatory
/// rather than tidy: an application may replace the allocator wholesale with
/// `curl_global_init_mem`, and it may release this buffer with a plain `free`,
/// which applications do against libcurl. A mismatch between this allocation
/// and `curl_free`'s release is heap corruption rather than a wrong answer,
/// which is why the pairing is asserted by test.
///
/// # The order of the two argument checks is load-bearing
///
/// The C is `if(!u) return CURLUE_BAD_HANDLE; if(!part) return
/// CURLUE_BAD_PARTPOINTER; *part = NULL;` at `:1548-1552`, and all three lines
/// matter in that order:
///
/// * A null handle wins over a null out-pointer, so `curl_url_get(NULL, w,
///   NULL, f)` is `CURLUE_BAD_HANDLE` (1) and never `CURLUE_BAD_PARTPOINTER`
///   (2).
/// * `*part = NULL` happens only after BOTH checks, so a null handle leaves the
///   caller's variable **untouched** while every later failure leaves it null.
///   A caller that initialises its own variable and tests the return value
///   therefore sees exactly what it sees against C libcurl.
/// * `docs/libcurl/curl_url_get.md:249` -- "If this function returns an error,
///   no URL part is returned" -- is the consequence, and it holds here because
///   the engine returns a `Result` that carries either the part or the code and
///   never both.
///
/// # What `flags` does is the engine's business
///
/// All sixteen `CURLU_*` bits, and every combination of them, are interpreted
/// by [`Url::get_by_id`]: the default-port supply and suppression, the
/// URL-decode, the punycode and IDN conversions, the guessed-scheme
/// suppression, and `CURLU_GET_EMPTY`'s distinction between a query or fragment
/// that is PRESENT AND EMPTY and one that is ABSENT. None of that is
/// second-guessed here, and no validation the C does not perform is added --
/// that would be a behaviour change, and against a byte-exact fixture
/// comparison it would be a visible one.
///
/// # Safety
///
/// `handle` must be either null or a live pointer that [`curl_url`] or
/// [`curl_url_dup`] returned and that has not been released, and nothing else
/// may be mutating it for the duration of the call. `part` must be either null
/// or a writable, aligned `char *` slot.
#[no_mangle]
pub unsafe extern "C" fn curl_url_get(
    handle: *const CURLU,
    what: c_int,
    part: *mut *mut c_char,
    flags: c_uint,
) -> CURLUcode {
    guard(BAD_URL_HANDLE, || {
        // SAFETY: forwarded verbatim from this function's own safety contract,
        // which is what `borrow` requires. `cast_mut` only restores the
        // mutability `into_raw` gave the pointer; nothing is written through
        // it, and the borrow ends inside this closure.
        let owner = unsafe { borrow::<CURLU, UrlHandle>(handle.cast_mut()) };

        // `if(!u) return CURLUE_BAD_HANDLE;` -- FIRST, and note that `*part`
        // is deliberately not written on this path.
        let Some(owner) = owner else {
            return BAD_URL_HANDLE;
        };

        // `if(!part) return CURLUE_BAD_PARTPOINTER;` -- second.
        if part.is_null() {
            return CURLUcode::CURLUE_BAD_PARTPOINTER;
        }

        // `*part = NULL;` -- third, so every failure below leaves it null.
        // SAFETY: `part` is non-null by the check above and, by this
        // function's safety contract, is a writable aligned slot for a `char
        // *`. This is a single scalar store into memory the caller owns.
        unsafe { part.write(ptr::null_mut()) };

        // A handle a contained panic has poisoned is not read. The C cannot
        // reach this state, so there is no behaviour to preserve; answering
        // the family's bad-handle code with `*part` already null is the
        // conservative choice, and it is what stops half-mutated state from
        // reaching an application.
        if owner.poison.is_poisoned() {
            return BAD_URL_HANDLE;
        }

        let extracted = owner.url.get_by_id(part_id(what), url_flags(flags));
        let bytes = match extracted {
            Ok(bytes) => bytes,
            Err(code) => return CURLUcode::from(code),
        };

        // Allocated through the crate-uniform hooks so that `curl_free`
        // releases what this allocated. A failure here is the C's
        // `CURLUE_OUT_OF_MEMORY` (`:1536`), with `*part` left null.
        let buffer = memory::copy_to_c_string(&bytes);
        if buffer.is_null() {
            return CURLUcode::CURLUE_OUT_OF_MEMORY;
        }

        // SAFETY: as for the store above -- `part` is non-null and, by
        // contract, a writable aligned slot the caller owns. Ownership of
        // `buffer` transfers to the caller with this store.
        unsafe { part.write(buffer) };
        CURLUcode::CURLUE_OK
    })
}

/// Sets one part of the URL.
///
/// Supersedes `curl_url_set` (`lib/urlapi.c:1805-1997`), declared at
/// `include/curl/urlapi.h:141-142`. The string is **copied**, so the caller may
/// free or reuse its own buffer the moment this returns.
///
/// # A null `part` CLEARS the component; it is not an error
///
/// `:1819-1821` is `if(!part) /* setting a part to NULL clears it */ return
/// urlset_clear(u, what);`, and `urlapi.h:138-139` documents it -- "Passing a
/// NULL instead of a part string, clears that part." Reporting
/// `CURLUE_BAD_PARTPOINTER` here would be a behaviour change, so a null `part`
/// is forwarded to the engine as [`None`] and clears the component. Clearing an
/// unknown part answers `CURLUE_UNKNOWN_PART`, exactly as `urlset_clear`'s own
/// `default:` arm does at `:1773`.
///
/// Note the asymmetry with [`curl_url_get`], which is real and is preserved: a
/// null `char **part` there IS `CURLUE_BAD_PARTPOINTER`, because it is an
/// out-pointer with nowhere to write rather than a value with a meaning.
///
/// # `CURLUPART_URL` re-parses; every other part mutates in place
///
/// `:1871-1872` delegates `CURLUPART_URL` to `set_url`, which replaces the
/// contents with an absolute URL or applies a RELATIVE one to what is already
/// there -- including the case of an empty string, which is a valid relative
/// URL that changes nothing when the handle already holds a complete one. That
/// relative behaviour is what redirect following is built on, so it is
/// preserved exactly. Everything about it, and about the sixteen flag bits,
/// belongs to [`Url::set_by_id`].
///
/// # Safety
///
/// `handle` must be either null or a live pointer that [`curl_url`] or
/// [`curl_url_dup`] returned and that has not been released, and nothing else
/// may be reading or mutating it for the duration of the call -- this function
/// takes an exclusive borrow, which is what `CURLU *` without a `const`
/// announces. `part` must be either null or a NUL-terminated string that stays
/// valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_url_set(
    handle: *mut CURLU,
    what: c_int,
    part: *const c_char,
    flags: c_uint,
) -> CURLUcode {
    // Deliberately OUTSIDE the guard: the borrow has to exist before
    // `guard_tx` can be given the poison flag to consult. Nothing between here
    // and the guard can panic -- a null check and a field projection -- so
    // there is no window the containment misses.
    //
    // SAFETY: forwarded verbatim from this function's own safety contract,
    // which is what `borrow_mut` requires: `handle` is null -- answered with
    // `None` -- or addresses a live `UrlHandle` that `into_raw` allocated and
    // that nothing else borrows for the duration of this call. The reference
    // does not outlive this function body.
    let owner = unsafe { borrow_mut::<CURLU, UrlHandle>(handle) };

    // `if(!u) return CURLUE_BAD_HANDLE;` (`:1817-1818`).
    let Some(owner) = owner else {
        return BAD_URL_HANDLE;
    };

    // Split the borrow by field so that `guard_tx`'s shared `&Poison` and the
    // closure's exclusive `&mut Url` are disjoint. Borrowing the whole
    // `UrlHandle` twice would not compile, and that is the borrow checker
    // enforcing the very separation this pairing exists to express.
    let UrlHandle { url, poison } = owner;

    guard_tx(poison, BAD_URL_HANDLE, || {
        // `strlen(part)`, which is what the C measures at `:1823`, so an
        // interior NUL truncates here exactly as it does there. A null `part`
        // becomes `None` and clears the component.
        //
        // SAFETY: `part` is non-null inside this branch and, by this
        // function's safety contract, addresses a NUL-terminated string that
        // stays valid and unmodified for the call. The borrow is consumed by
        // `set_by_id` before it ends.
        let value = if part.is_null() {
            None
        } else {
            Some(unsafe { CStr::from_ptr(part) }.to_bytes())
        };

        match url.set_by_id(part_id(what), value, url_flags(flags)) {
            Ok(()) => CURLUcode::CURLUE_OK,
            Err(code) => CURLUcode::from(code),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{
        curl_url, curl_url_cleanup, curl_url_dup, curl_url_get, curl_url_set,
    };

    use crate::ffi::codes::curlu_flags;
    use crate::ffi::codes::CURLUcode;
    use crate::ffi::handle::CURLU;
    use crate::ffi::memory;
    use crate::ffi::types::CURLUPart;

    use core::ffi::{c_char, c_int, c_uint};
    use core::ptr;
    use std::ffi::{CStr, CString};

    /// Every `CURLUPart` member, in declaration order, as the integer a C
    /// caller passes.
    ///
    /// Written out rather than derived so that the ELEVEN-member count and the
    /// absence of a sentinel are both asserted by this list existing. There is
    /// no `CURLUPART_LAST` to include and none may be invented.
    const PARTS: [(&str, CURLUPart); 11] = [
        ("URL", CURLUPart::CURLUPART_URL),
        ("SCHEME", CURLUPart::CURLUPART_SCHEME),
        ("USER", CURLUPart::CURLUPART_USER),
        ("PASSWORD", CURLUPart::CURLUPART_PASSWORD),
        ("OPTIONS", CURLUPart::CURLUPART_OPTIONS),
        ("HOST", CURLUPart::CURLUPART_HOST),
        ("PORT", CURLUPart::CURLUPART_PORT),
        ("PATH", CURLUPart::CURLUPART_PATH),
        ("QUERY", CURLUPart::CURLUPART_QUERY),
        ("FRAGMENT", CURLUPart::CURLUPART_FRAGMENT),
        ("ZONEID", CURLUPart::CURLUPART_ZONEID),
    ];

    /// A part's integer, as C sends it.
    fn id(part: CURLUPart) -> c_int {
        part as c_int
    }

    /// Calls `curl_url_set` with an owned C string, or with NULL for [`None`].
    ///
    /// Goes through the exported entry point rather than the engine, because
    /// the marshalling is what is under test.
    fn set(
        handle: *mut CURLU,
        part: CURLUPart,
        value: Option<&str>,
        flags: c_uint,
    ) -> CURLUcode {
        match value {
            None => {
                // SAFETY: `handle` came from `curl_url` and is live, and a null
                // `part` is the documented clear-this-component form.
                unsafe { curl_url_set(handle, id(part), ptr::null(), flags) }
            }
            Some(text) => {
                let owned =
                    CString::new(text).expect("no interior NUL in a literal");
                // SAFETY: `handle` is live, and `owned` keeps its
                // NUL-terminated buffer alive across the call.
                unsafe { curl_url_set(handle, id(part), owned.as_ptr(), flags) }
            }
        }
    }

    /// Calls `curl_url_get` and releases the buffer, returning its bytes.
    ///
    /// Releases through [`memory::free`] -- the same path `curl_free` takes --
    /// because that pairing with [`memory::copy_to_c_string`] is the single
    /// highest-risk property of this module: a mismatch is heap corruption
    /// rather than a wrong answer.
    fn get(
        handle: *const CURLU,
        part: CURLUPart,
        flags: c_uint,
    ) -> Result<Vec<u8>, CURLUcode> {
        // Pre-set to a recognisable non-null value so that "left untouched"
        // and "set to NULL" are distinguishable outcomes. It points at a real
        // local rather than being cast from an integer: an integer-to-pointer
        // cast carries no provenance and Miri reports one, and a warning in a
        // Miri log is a warning somebody has to triage.
        let mut anchor: c_char = 0;
        let mut out: *mut c_char = &mut anchor;
        // SAFETY: `handle` is null or live for every caller below, and `out` is
        // a live, writable, aligned slot for a `char *`.
        let code = unsafe {
            curl_url_get(handle, id(part), &mut out as *mut *mut c_char, flags)
        };
        if code != CURLUcode::CURLUE_OK {
            return Err(code);
        }
        assert!(!out.is_null(), "CURLUE_OK must deliver a buffer");
        // SAFETY: a successful return hands over a NUL-terminated buffer this
        // caller owns, by the function's documented contract.
        let bytes = unsafe { CStr::from_ptr(out) }.to_bytes().to_vec();
        // SAFETY: `out` came from `memory::copy_to_c_string` and is released
        // exactly once, here.
        unsafe { memory::free(out.cast()) };
        Ok(bytes)
    }

    /// A handle holding `url`, parsed with no flags.
    fn parsed(url: &str) -> *mut CURLU {
        let handle = curl_url();
        assert!(!handle.is_null());
        assert_eq!(
            set(handle, CURLUPart::CURLUPART_URL, Some(url), 0),
            CURLUcode::CURLUE_OK,
            "{url} must parse"
        );
        handle
    }

    /// Releases a handle produced by [`parsed`] or `curl_url`.
    fn cleanup(handle: *mut CURLU) {
        // SAFETY: `handle` came from `curl_url` or `curl_url_dup`, has not been
        // released, and is not used again by the caller.
        unsafe { curl_url_cleanup(handle) };
    }

    // -- Lifecycle -----------------------------------------------------------

    #[test]
    fn a_new_handle_is_non_null_and_empty() {
        let handle = curl_url();
        assert!(!handle.is_null());

        // `curlx_calloc` leaves every part absent, so each accessor answers its
        // own missing-part code rather than an empty string.
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_SCHEME, 0),
            Err(CURLUcode::CURLUE_NO_SCHEME)
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_HOST, 0),
            Err(CURLUcode::CURLUE_NO_HOST)
        );
        cleanup(handle);
    }

    #[test]
    fn cleanup_of_null_is_a_silent_no_op() {
        // `if(u)` at `lib/urlapi.c:1295`. Returns `void`, so the only
        // observable property is that it returns at all.
        // SAFETY: null is the documented no-op input.
        unsafe { curl_url_cleanup(ptr::null_mut()) };
    }

    #[test]
    fn a_handle_is_released_exactly_once() {
        // Miri and AddressSanitizer are what make this assertion mean
        // something: a second `drop_raw` would be a double free and a missing
        // one a leak, and both are detected rather than asserted here.
        for _ in 0..8 {
            let handle = parsed("https://example.com/a?b#c");
            cleanup(handle);
        }
    }

    // -- Duplication ---------------------------------------------------------

    #[test]
    fn dup_deep_copies_and_the_copy_is_independent() {
        let original = parsed("https://example.com/first");
        // SAFETY: `original` is live and nothing is mutating it.
        let copy = unsafe { curl_url_dup(original) };
        assert!(!copy.is_null());

        assert_eq!(
            get(copy, CURLUPart::CURLUPART_PATH, 0).expect("path"),
            b"/first".to_vec()
        );

        // Mutating the copy must leave the original alone, which is what
        // "deep" means: the C duplicates the strings rather than sharing them.
        assert_eq!(
            set(copy, CURLUPart::CURLUPART_PATH, Some("/second"), 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(copy, CURLUPart::CURLUPART_PATH, 0).expect("path"),
            b"/second".to_vec()
        );
        assert_eq!(
            get(original, CURLUPart::CURLUPART_PATH, 0).expect("path"),
            b"/first".to_vec()
        );

        // And the copy is released by `curl_url_cleanup`, exactly as
        // `curl_url`'s result is.
        cleanup(copy);
        cleanup(original);
    }

    #[test]
    fn dup_of_null_answers_null_instead_of_dereferencing() {
        // The C has no null check here -- the `DUP` macro reads through `in` --
        // so `curl_url_dup(NULL)` is UNDEFINED and in practice faults. Null is
        // a defined answer replacing an undefined one.
        // SAFETY: null is explicitly permitted by this function's contract.
        let copy = unsafe { curl_url_dup(ptr::null()) };
        assert!(copy.is_null());
    }

    #[test]
    fn dup_does_not_carry_the_guessed_scheme() {
        // `lib/urlapi.c:1324-1326` copies `portnum`, `fragment_present` and
        // `query_present` -- and NOT `guessed_scheme`. So the original treats
        // its scheme as guessed and the copy does not, which
        // `CURLU_NO_GUESS_SCHEME` makes visible. Reproduced deliberately.
        let handle = curl_url();
        assert_eq!(
            set(
                handle,
                CURLUPart::CURLUPART_URL,
                Some("example.com/a"),
                curlu_flags::CURLU_GUESS_SCHEME,
            ),
            CURLUcode::CURLUE_OK
        );
        let strict = curlu_flags::CURLU_NO_GUESS_SCHEME;
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_SCHEME, strict),
            Err(CURLUcode::CURLUE_NO_SCHEME)
        );

        // SAFETY: `handle` is live and unmutated for the call.
        let copy = unsafe { curl_url_dup(handle) };
        assert!(!copy.is_null());
        assert_eq!(
            get(copy, CURLUPart::CURLUPART_SCHEME, strict).expect("scheme"),
            b"http".to_vec()
        );
        cleanup(copy);
        cleanup(handle);
    }

    // -- Argument checking, and its order ------------------------------------

    #[test]
    fn a_null_handle_is_bad_handle_for_both_code_returning_calls() {
        assert_eq!(
            get(ptr::null(), CURLUPart::CURLUPART_HOST, 0),
            Err(CURLUcode::CURLUE_BAD_HANDLE)
        );
        assert_eq!(CURLUcode::CURLUE_BAD_HANDLE as c_int, 1);

        assert_eq!(
            set(ptr::null_mut(), CURLUPart::CURLUPART_HOST, Some("x"), 0),
            CURLUcode::CURLUE_BAD_HANDLE
        );
    }

    #[test]
    fn a_null_out_pointer_is_bad_partpointer() {
        let handle = parsed("https://example.com/");
        // SAFETY: `handle` is live; a null `part` is exactly the argument
        // shape under test.
        let code = unsafe {
            curl_url_get(
                handle,
                id(CURLUPart::CURLUPART_HOST),
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(code, CURLUcode::CURLUE_BAD_PARTPOINTER);
        assert_eq!(CURLUcode::CURLUE_BAD_PARTPOINTER as c_int, 2);
        cleanup(handle);
    }

    #[test]
    fn the_null_handle_check_wins_over_the_null_out_pointer_check() {
        // `lib/urlapi.c:1548-1551` tests `!u` first. Both arguments are null
        // here, and only one answer is correct.
        // SAFETY: both null arguments are permitted by the contract.
        let code = unsafe {
            curl_url_get(
                ptr::null(),
                id(CURLUPart::CURLUPART_HOST),
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(code, CURLUcode::CURLUE_BAD_HANDLE);
    }

    #[test]
    fn a_null_handle_leaves_the_out_variable_untouched() {
        // `*part = NULL` is at `:1552`, AFTER both checks, so a bad handle
        // never writes. A caller that initialised its own variable sees it
        // unchanged -- which is the one observable difference between the
        // bad-handle path and every later failure.
        // A pointer to a real local, for the provenance reason recorded on
        // `get` above.
        let mut anchor: c_char = 0;
        let sentinel: *mut c_char = &mut anchor;
        let mut out = sentinel;
        // SAFETY: `out` is a live writable slot; the handle is null by design.
        let code = unsafe {
            curl_url_get(
                ptr::null(),
                id(CURLUPart::CURLUPART_HOST),
                &mut out as *mut *mut c_char,
                0,
            )
        };
        assert_eq!(code, CURLUcode::CURLUE_BAD_HANDLE);
        assert_eq!(out, sentinel, "the bad-handle path must not write *part");
    }

    #[test]
    fn every_later_failure_leaves_the_out_variable_null() {
        let handle = curl_url();
        let mut anchor: c_char = 0;
        let mut out: *mut c_char = &mut anchor;
        // SAFETY: `handle` is live and `out` is a live writable slot.
        let code = unsafe {
            curl_url_get(
                handle,
                id(CURLUPart::CURLUPART_HOST),
                &mut out as *mut *mut c_char,
                0,
            )
        };
        assert_eq!(code, CURLUcode::CURLUE_NO_HOST);
        assert!(out.is_null(), "*part is NULL once past both checks");
        cleanup(handle);
    }

    #[test]
    fn an_out_of_range_part_is_unknown_part_rather_than_undefined() {
        // A C caller may pass any value of the enum's compatible integer type,
        // and the C answers `CURLUE_UNKNOWN_PART` by falling through to
        // `default:` -- `lib/urlapi.c:1626-1628` on get, `:1873-1874` on set
        // and `:1773-1774` when clearing. This is the whole reason the Rust
        // parameter is a `c_int` and the prototype is carried verbatim.
        let handle = parsed("https://example.com/");
        for stray in [11, 99, -1, c_int::MAX] {
            let mut out = ptr::null_mut::<c_char>();
            // SAFETY: `handle` is live, `out` is a live writable slot, and a
            // stray `what` is a defined input by the contract above.
            let code = unsafe {
                curl_url_get(handle, stray, &mut out as *mut *mut c_char, 0)
            };
            assert_eq!(code, CURLUcode::CURLUE_UNKNOWN_PART, "get({stray})");
            assert!(out.is_null());

            let owned = CString::new("x").expect("no interior NUL");
            // SAFETY: as above, and `owned` outlives the call.
            let code =
                unsafe { curl_url_set(handle, stray, owned.as_ptr(), 0) };
            assert_eq!(code, CURLUcode::CURLUE_UNKNOWN_PART, "set({stray})");

            // Clearing an unknown part answers the same code, which is
            // `urlset_clear`'s own `default:` arm.
            // SAFETY: as above; null clears.
            let code = unsafe { curl_url_set(handle, stray, ptr::null(), 0) };
            assert_eq!(code, CURLUcode::CURLUE_UNKNOWN_PART, "clear({stray})");
        }
        assert_eq!(CURLUcode::CURLUE_UNKNOWN_PART as c_int, 9);
        cleanup(handle);
    }

    // -- Setting, clearing, and re-parsing ----------------------------------

    #[test]
    fn a_null_part_clears_the_component_and_is_not_an_error() {
        // `:1819-1821`, and `urlapi.h:138-139`: "Passing a NULL instead of a
        // part string, clears that part." Reporting BAD_PARTPOINTER here
        // would be a behaviour change.
        let handle = parsed("https://user:pw@example.com/a?q=1#f");
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_QUERY, 0).expect("query"),
            b"q=1".to_vec()
        );

        assert_eq!(
            set(handle, CURLUPart::CURLUPART_QUERY, None, 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_QUERY, 0),
            Err(CURLUcode::CURLUE_NO_QUERY)
        );

        // The rest of the URL survives, so clearing is per-component.
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_HOST, 0).expect("host"),
            b"example.com".to_vec()
        );
        assert_eq!(
            set(handle, CURLUPart::CURLUPART_FRAGMENT, None, 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_FRAGMENT, 0),
            Err(CURLUcode::CURLUE_NO_FRAGMENT)
        );
        cleanup(handle);
    }

    #[test]
    fn clearing_the_url_empties_the_whole_handle() {
        // `urlset_clear`'s `CURLUPART_URL` arm frees everything and memsets the
        // struct (`:1735-1738`), which is a different operation from clearing a
        // single component.
        let handle = parsed("https://example.com/a?q#f");
        assert_eq!(
            set(handle, CURLUPart::CURLUPART_URL, None, 0),
            CURLUcode::CURLUE_OK
        );
        for (name, part) in PARTS {
            if part == CURLUPart::CURLUPART_PATH {
                // The path is the one part a cleared handle still answers: the
                // C substitutes "/" when none is stored (`:1606-1607`).
                assert_eq!(
                    get(handle, part, 0).expect("path"),
                    b"/".to_vec(),
                    "{name}"
                );
                continue;
            }
            assert!(get(handle, part, 0).is_err(), "{name} must be absent");
        }
        cleanup(handle);
    }

    #[test]
    fn setting_the_url_re_parses_and_accepts_a_relative_reference() {
        // `:1871-1872` delegates to `set_url`, which replaces the contents with
        // an absolute URL and APPLIES a relative one. Redirect following rests
        // on the second behaviour, so both are asserted.
        let handle = parsed("https://example.com/one/two?q=1");

        assert_eq!(
            set(handle, CURLUPart::CURLUPART_URL, Some("three"), 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_URL, 0).expect("url"),
            b"https://example.com/one/three".to_vec()
        );

        assert_eq!(
            set(handle, CURLUPart::CURLUPART_URL, Some("/root"), 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_URL, 0).expect("url"),
            b"https://example.com/root".to_vec()
        );

        assert_eq!(
            set(handle, CURLUPart::CURLUPART_URL, Some("http://other/x"), 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_HOST, 0).expect("host"),
            b"other".to_vec()
        );

        // An empty string is a valid relative URL that changes nothing when the
        // handle already holds a complete one (`:1697-1710`).
        assert_eq!(
            set(handle, CURLUPart::CURLUPART_URL, Some(""), 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_URL, 0).expect("url"),
            b"http://other/x".to_vec()
        );
        cleanup(handle);
    }

    #[test]
    fn the_input_string_is_copied() {
        // `urlapi.h:138` -- "The passed in string will be copied." The buffer
        // is dropped before the value is read back, so a borrow would be a
        // use-after-free that Miri and AddressSanitizer would both report.
        let handle = curl_url();
        {
            let owned = CString::new("example.org").expect("no interior NUL");
            // SAFETY: `handle` is live and `owned` outlives this call.
            let code = unsafe {
                curl_url_set(
                    handle,
                    id(CURLUPart::CURLUPART_HOST),
                    owned.as_ptr(),
                    0,
                )
            };
            assert_eq!(code, CURLUcode::CURLUE_OK);
        }
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_HOST, 0).expect("host"),
            b"example.org".to_vec()
        );
        cleanup(handle);
    }

    #[test]
    fn all_eleven_parts_round_trip() {
        // Every member of `CURLUPart`, set then read back through the C entry
        // points. `CURLUPART_URL` is exercised by `parsed` and by the
        // re-parse test, and `CURLUPART_PORT` and `CURLUPART_ZONEID` have
        // their own syntax rules, so the values differ per part -- but the
        // list is the whole enumeration, which is what makes the count of
        // eleven and the absence of a sentinel assertions rather than claims.
        let handle = parsed("https://example.com/p");
        let values = [
            (CURLUPart::CURLUPART_SCHEME, "http", "http"),
            (CURLUPart::CURLUPART_USER, "u", "u"),
            (CURLUPart::CURLUPART_PASSWORD, "p", "p"),
            (CURLUPart::CURLUPART_HOST, "[fe80::1]", "[fe80::1]"),
            (CURLUPart::CURLUPART_ZONEID, "eth0", "eth0"),
            (CURLUPart::CURLUPART_PORT, "8080", "8080"),
            (CURLUPart::CURLUPART_PATH, "/x/y", "/x/y"),
            (CURLUPart::CURLUPART_QUERY, "a=b", "a=b"),
            (CURLUPart::CURLUPART_FRAGMENT, "frag", "frag"),
        ];
        for (part, written, expected) in values {
            assert_eq!(
                set(handle, part, Some(written), 0),
                CURLUcode::CURLUE_OK,
                "setting {part:?}"
            );
            assert_eq!(
                get(handle, part, 0).expect("a part just set"),
                expected.as_bytes().to_vec(),
                "reading {part:?} back"
            );
        }

        // `CURLUPART_OPTIONS` is the one part no in-scope scheme parses out of
        // a URL -- `PROTOPT_URLOPTIONS` belongs to imap, pop3 and smtp -- but
        // it is still settable and readable, which is what completes the
        // eleven.
        assert_eq!(
            set(handle, CURLUPart::CURLUPART_OPTIONS, Some("opt"), 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_OPTIONS, 0).expect("options"),
            b"opt".to_vec()
        );

        assert_eq!(PARTS.len(), 11);
        cleanup(handle);
    }

    // -- Flags are the engine's, and they reach it intact --------------------

    #[test]
    fn the_default_port_flags_reach_the_scheme_registry() {
        // Proof that `curl_url()` obtained a real 33-entry registry: without
        // one, no scheme would resolve and no default port could be supplied.
        let handle = parsed("https://example.com/");
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_PORT, 0),
            Err(CURLUcode::CURLUE_NO_PORT)
        );
        assert_eq!(
            get(
                handle,
                CURLUPart::CURLUPART_PORT,
                curlu_flags::CURLU_DEFAULT_PORT
            )
            .expect("the scheme's default port"),
            b"443".to_vec()
        );
        cleanup(handle);

        // And the suppression flag is the mirror image: a stored port equal to
        // the scheme's default reads as absent.
        let handle = parsed("http://example.com:80/");
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_PORT, 0).expect("port"),
            b"80".to_vec()
        );
        assert_eq!(
            get(
                handle,
                CURLUPart::CURLUPART_PORT,
                curlu_flags::CURLU_NO_DEFAULT_PORT
            ),
            Err(CURLUcode::CURLUE_NO_PORT)
        );
        cleanup(handle);
    }

    #[test]
    fn get_empty_distinguishes_present_and_empty_from_absent() {
        // The whole reason `CURLU_GET_EMPTY` exists. Zero-length is not
        // missing, and the two must not be collapsed.
        let handle = parsed("https://example.com/?#");
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_QUERY, 0),
            Err(CURLUcode::CURLUE_NO_QUERY)
        );
        assert_eq!(
            get(
                handle,
                CURLUPart::CURLUPART_QUERY,
                curlu_flags::CURLU_GET_EMPTY
            )
            .expect("a present but empty query"),
            Vec::<u8>::new()
        );
        assert_eq!(
            get(
                handle,
                CURLUPart::CURLUPART_FRAGMENT,
                curlu_flags::CURLU_GET_EMPTY
            )
            .expect("a present but empty fragment"),
            Vec::<u8>::new()
        );
        cleanup(handle);

        // A URL that never carried a query answers the missing-part code even
        // with the flag set.
        let handle = parsed("https://example.com/");
        assert_eq!(
            get(
                handle,
                CURLUPart::CURLUPART_QUERY,
                curlu_flags::CURLU_GET_EMPTY
            ),
            Err(CURLUcode::CURLUE_NO_QUERY)
        );
        cleanup(handle);
    }

    #[test]
    fn the_encode_and_decode_flags_reach_the_engine_unaltered() {
        let handle = parsed("https://example.com/");

        // `CURLU_URLENCODE` on set, `CURLU_URLDECODE` on get. The escape
        // tables and the hex casing belong to the engine; what is asserted
        // here is only that the bits arrive.
        assert_eq!(
            set(
                handle,
                CURLUPart::CURLUPART_PATH,
                Some("/a b"),
                curlu_flags::CURLU_URLENCODE
            ),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_PATH, 0).expect("path"),
            b"/a%20b".to_vec()
        );
        assert_eq!(
            get(
                handle,
                CURLUPart::CURLUPART_PATH,
                curlu_flags::CURLU_URLDECODE
            )
            .expect("path"),
            b"/a b".to_vec()
        );
        cleanup(handle);
    }

    #[test]
    fn an_unknown_flag_bit_is_preserved_rather_than_rejected() {
        // The C tests individual bits and never validates the mask, so a bit
        // above `1 << 15` must change nothing. Adding validation here would be
        // a behaviour change.
        let handle = parsed("https://example.com/a");
        let stray = 1u32 << 20;
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_PATH, stray).expect("path"),
            b"/a".to_vec()
        );
        assert_eq!(
            set(handle, CURLUPart::CURLUPART_PATH, Some("/b"), stray),
            CURLUcode::CURLUE_OK
        );
        cleanup(handle);
    }

    #[test]
    fn a_scheme_out_of_core_scope_shows_the_parse_versus_set_asymmetry() {
        // `parse_scheme` accepts any scheme in the registry
        // (`lib/urlapi.c:951`) while `set_url_scheme` additionally requires an
        // implementation (`:1646`). The 24 stubbed schemes are in the table
        // with no implementation, so a full URL parses and a bare scheme does
        // not -- the exact analogue of a C `CURL_DISABLE_SMTP` build.
        let handle = curl_url();
        assert_eq!(
            set(handle, CURLUPart::CURLUPART_URL, Some("smtp://host/"), 0),
            CURLUcode::CURLUE_OK
        );
        assert_eq!(
            get(handle, CURLUPart::CURLUPART_SCHEME, 0).expect("scheme"),
            b"smtp".to_vec()
        );
        assert_eq!(
            set(handle, CURLUPart::CURLUPART_SCHEME, Some("smtp"), 0),
            CURLUcode::CURLUE_UNSUPPORTED_SCHEME
        );
        // And the override makes it settable, which is what the flag is for.
        assert_eq!(
            set(
                handle,
                CURLUPart::CURLUPART_SCHEME,
                Some("smtp"),
                curlu_flags::CURLU_NON_SUPPORT_SCHEME
            ),
            CURLUcode::CURLUE_OK
        );
        cleanup(handle);
    }

    // -- Allocation pairing --------------------------------------------------

    #[test]
    fn the_returned_buffer_is_nul_terminated_and_freed_by_the_hook_path() {
        // The single highest-risk property of this module. `get` above releases
        // through `memory::free`, which is what `curl_free` calls, so running
        // this under AddressSanitizer is what proves the pairing; the
        // assertions here only prove the buffer is a well-formed C string.
        let handle = parsed("https://example.com/path?query#frag");
        for (name, part) in PARTS {
            let Ok(bytes) = get(handle, part, 0) else {
                continue;
            };
            assert!(
                !bytes.contains(&0),
                "{name} must not contain an interior NUL"
            );
        }
        cleanup(handle);
    }

    // -- The file's own shape ------------------------------------------------

    #[test]
    fn this_file_defines_exactly_the_five_names_and_not_the_sixth() {
        // Read from disk so the assertion is about the file rather than about a
        // list kept in the test. `curl_url_strerror` is `strerror.rs`'s, and a
        // definition here would be a duplicate export -- a link error, but one
        // whose diagnosis is much clearer stated this way.
        let source = include_str!("url.rs");
        let defined: Vec<&str> = source
            .lines()
            .filter_map(|line| {
                let rest = line.strip_prefix("pub extern \"C\" fn ").or_else(
                    || line.strip_prefix("pub unsafe extern \"C\" fn "),
                )?;
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                Some(&rest[..end])
            })
            .collect();

        assert_eq!(
            defined,
            vec![
                "curl_url",
                "curl_url_cleanup",
                "curl_url_dup",
                "curl_url_get",
                "curl_url_set",
            ],
            "this module owns five of the six curl_url* names"
        );

        // The `#[no_mangle]` count must match, or a definition would keep its
        // Rust symbol name and resolve nothing.
        assert_eq!(
            source
                .lines()
                .filter(|line| *line == "#[no_mangle]")
                .count(),
            5
        );

        // And no line of CODE invents a sentinel. The needle is assembled from
        // two pieces, and comment lines are skipped, so neither this assertion
        // nor the module documentation that explains the trap matches itself --
        // which is exactly the failure the first version of this test produced.
        let sentinel = concat!("CURLUPART_", "LAST");
        let invented: Vec<&str> = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .filter(|line| line.contains(sentinel))
            .collect();
        assert!(
            invented.is_empty(),
            "the URL part enumeration has no sentinel in curl 8.19.0-DEV and \
             none may be added: {invented:?}"
        );
    }

    #[test]
    fn no_parsing_dependency_is_reachable_from_this_module() {
        // Pattern P10: the `url`, `idna` and `percent-encoding` crates are
        // `curl-rs-lib`'s, used beneath curl's own semantics, and this file
        // contains no parsing at all. Asserted on the import list rather than
        // trusted, because the manifest would happily resolve them.
        let source = include_str!("url.rs");
        for line in source.lines() {
            let Some(rest) = line.strip_prefix("use ") else {
                continue;
            };
            let root = rest.split("::").next().unwrap_or_default();
            assert!(
                matches!(root, "core" | "std" | "curl_rs_lib" | "super"),
                "unexpected import root in a marshalling module: {line}"
            );
        }
    }
}
