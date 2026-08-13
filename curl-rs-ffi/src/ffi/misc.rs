// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The thirteen exported functions that close the 100-symbol partition.
//!
//! Eleven of them belong to no larger family, and two are the header API. That
//! composition -- **11 standalone plus the 2 header-API functions** -- is what
//! makes this the module the partition ends on: tallying the crate's twelve
//! symbol-family modules naively yields 106, and six of those are double
//! counted, two of them here. `curl_easy_header` and `curl_easy_nextheader` sit
//! inside the `curl_easy_*` prefix family as well as here, which is exactly why
//! `ffi/easy.rs` owns 18 rather than 21. With this file's 13 counted once,
//! 18 + 21 + 3 + 5 + 2 + 12 + 3 + 5 + 4 + 10 + 4 + 13 = **100**.
//!
//! | Symbol | Declared | Returns | Authority |
//! |---|---|---|---|
//! | `curl_escape`             | `curl.h:2704`  | `char *`                     | `lib/escape.c:36-39`      |
//! | `curl_unescape`           | `curl.h:2724`  | `char *`                     | `lib/escape.c:42-45`      |
//! | `curl_free`               | `curl.h:2735`  | `void`                       | `lib/escape.c:189-192`    |
//! | `curl_getdate`            | `curl.h:2870`  | `time_t`                     | `lib/parsedate.c:561-575` |
//! | `curl_getenv`             | `curl.h:2679`  | `char *`                     | `lib/getenv.c:26-70`      |
//! | `curl_strequal`           | `curl.h:2424`  | `int`                        | `lib/strequal.c:76-84`    |
//! | `curl_strnequal`          | `curl.h:2425`  | `int`                        | `lib/strequal.c:87-95`    |
//! | `curl_version`            | `curl.h:2688`  | `char *`                     | `lib/version.c:145`       |
//! | `curl_version_info`       | `curl.h:3221`  | `curl_version_info_data *`   | `lib/version.c:596`       |
//! | `curl_pushheader_bynum`   | `multi.h:502`  | `char *`                     | `lib/http2.c:657-668`     |
//! | `curl_pushheader_byname`  | `multi.h:504`  | `char *`                     | `lib/http2.c:673-702`     |
//! | `curl_easy_header`        | `header.h:58`  | `CURLHcode`                  | `lib/headers.c:55-118`    |
//! | `curl_easy_nextheader`    | `header.h:65`  | `struct curl_header *`       | `lib/headers.c:121-179`   |
//!
//! **The return types are not uniform, and that is the easiest thing here to
//! get silently wrong.** One `void`, **six** `char *`, two `int`, one `time_t`,
//! one `curl_version_info_data *`, one `CURLHcode` and one
//! `struct curl_header *` -- which sums to 13, as it must. The count of
//! `char *` is worth stating precisely because it is easy to get one short:
//! the six are `curl_escape`, `curl_unescape`, `curl_getenv`, `curl_version`
//! and BOTH `curl_pushheader_*` accessors, each verified against its
//! declaration in the table above. A mistake in any return type compiles
//! cleanly on the Rust side and breaks the ABI at the call site.
//!
//! # Where a symbol is declared is not where it is defined
//!
//! Four of the thirteen prove it, and none is moved to match its header.
//! `curl_pushheader_bynum` and `curl_pushheader_byname` are declared in
//! `include/curl/multi.h`, which therefore declares 24 of the 100 rather than
//! 22, yet they are defined here and not in `ffi/multi.rs`.
//! `curl_easy_header` and `curl_easy_nextheader` are the only two declarations
//! `include/curl/header.h` carries, and they are defined here and not in
//! `ffi/easy.rs`. The declaration distribution that reconciles to 100 is
//! `easy.h` 10 + `multi.h` 24 + `urlapi.h` 6 + `options.h` 3 + `header.h` 2 +
//! `websockets.h` 4 + `mprintf.h` 10 + `curl.h` 41.
//!
//! **`curl_pushheader_bynum` is declared BEFORE `curl_pushheader_byname`** --
//! `multi.h:502-503` ahead of `:504-505`, the reverse of alphabetical order --
//! and `cbindgen.toml` sets `sort_by = "None"`, so source order is the
//! generated header's order. The two are defined below in that order for that
//! reason. The same class of asymmetry appears at `multi.h:541`/`:544`, where
//! `notify_disable` precedes `notify_enable`.
//!
//! One further piece of header punctuation is deliberate and must survive.
//! `curl_escape` is preceded by `/* the previous version: */` **with** a colon
//! (`curl.h:2703`) and `curl_unescape` by `/* the previous version */`
//! **without** one (`curl.h:2723`). Reproducing that byte for byte is
//! `build.rs`'s verbatim-carrier mechanism to arrange -- `cbindgen.toml` sets
//! `documentation_length = "full"`, so a Rust doc comment renders as itself and
//! cannot stand in for those two literal lines -- and it is recorded here so
//! the asymmetry is not "tidied" on the way through.
//!
//! # Not one of the thirteen decides anything
//!
//! Every behavioural question -- what the banner says, which date formats
//! parse, how case folding works, which bytes percent-encode, which header
//! matches an origin mask -- is answered by `curl-rs-lib`, and this file
//! marshals. That division is what keeps the ABI shim auditable in isolation
//! (the facade pattern) and is why the module has no tables,
//! no parser and no encoding set of its own.
//!
//! # Ownership at the boundary, which is not uniform either
//!
//! Seven of the thirteen hand a pointer to the caller and they do not agree
//! about who owns it. The distinction is part of the contract, and getting it
//! wrong is either a leak or a double free:
//!
//! * **Caller-owned, released with [`curl_free`]**: [`curl_escape`],
//!   [`curl_unescape`] and [`curl_getenv`]. All three allocate through
//!   [`super::memory`], so an application that replaced the allocator through
//!   `curl_global_init_mem` frees with the same one that produced the buffer.
//! * **Immortal, never freed**: [`curl_version`] and [`curl_version_info`].
//!   C uses function-level `static` buffers (`lib/version.c:147` declares
//!   `static char out[300]`); this module leaks one allocation on first use,
//!   which has the same lifetime and the same once-per-process cost. The report
//!   is `struct curl_version_info_data` (`curl.h:3111-3172`), whose 27 fields
//!   begin with `CURLversion age` (`curl.h:3088-3102`, with the
//!   `CURLVERSION_NOW` alias at `:3104-3109`) and whose `features` mask carries
//!   the 31 `CURL_VERSION_*` bits of `curl.h:3175-3211`. The two
//!   `const char * const *` **double-const** members --
//!   `protocols` (`curl.h:3121`) and `feature_names` (`curl.h:3168`) -- are
//!   NULL-terminated arrays of `'static` strings, and both consts must survive
//!   header generation because dropping either is a `-Werror` failure in a
//!   consumer.
//! * **Borrowed from libcurl, never freed**: [`curl_pushheader_bynum`],
//!   [`curl_pushheader_byname`] and [`curl_easy_nextheader`], plus the
//!   `struct curl_header *` (`header.h:31-38`, six fields, the last of them the
//!   libcurl-private `anchor` that must nevertheless occupy its slot because a
//!   consumer's `sizeof` and `offsetof` see it) that [`curl_easy_header`] stores
//!   through `hout`. Each points into state the library owns.
//!   `lib/http2.c:664` returns
//!   `h->stream->push_headers[num]` and `:706` returns
//!   `&stream->push_headers[i][len + 1]`, a pointer into the MIDDLE of that
//!   same string; `lib/headers.c:114-116` and `:176-178` return
//!   `&data->state.headerout[0]` and `[1]`. **No returned pointer here ever
//!   addresses a Rust temporary.**
//!
//! # Why the immortal storage is built lazily, and why only its ADDRESS is kept
//!
//! `curl_version_info_data` holds raw pointers, so it is neither `Send` nor
//! `Sync` and cannot be a plain `static`. Both immortal values here are
//! therefore built on first use and leaked, and the [`OnceLock`] that guards
//! each one stores a `usize` address rather than the value: `usize` is
//! `Send + Sync` on its own, so no wrapper type and no hand-written
//! `unsafe impl` is involved in either.
//!
//! That choice is forced, not stylistic. C returns `curl_version_info_data *`
//! -- a MUTABLE pointer into a mutable `static` -- so a caller has always been
//! able to write through it and race with libcurl. That hazard belongs to the
//! frozen signature and is reproduced rather than fixed:
//! narrowing the return type to `const` would break every consumer that assigns
//! it to a non-const variable. Reproducing it correctly means the returned
//! pointer must carry WRITE provenance, and a pointer obtained by casting a
//! shared reference does not, whatever the C prototype says. Since
//! `OnceLock::get_or_init` can only ever yield a `&T`, the value cannot live
//! inside the cell; `Box::into_raw` provides the write-capable pointer and the
//! cell holds its address. See [`curl_version_info`] for the full account,
//! including the earlier design this replaced.
//!
//! # The two layers this module is waiting on, named rather than implied
//!
//! Four of the thirteen read state off a handle that no other module has built
//! yet, and both gaps are measured rather than assumed. They are recorded here
//! because a reader who does not know them would mistake a faithful answer for
//! a stub:
//!
//! * **No easy handle exists.** `curl-rs-lib/src/easy/` holds only `mod.rs` and
//!   `options.rs`, and `curl_easy_init` is one of the exports `build.rs`'s
//!   `undefined_abi_exports` still reports as missing. So no `CURL *` a caller
//!   can present was issued by this library, and a pointer this library did not
//!   issue cannot be interpreted. See [`header_state`].
//! * **No header collection and no push promise exist.** The engine marks
//!   `HeaderStore::push` and `PushHeaders::push` as awaiting their consumers in
//!   `curl-rs-lib/src/transfer/` and `curl-rs-lib/src/protocols/http2.rs`, and
//!   both are `pub(crate)`, so this crate cannot populate either store even for
//!   a test. See [`promised_fields`].
//!
//! What follows from that is a genuine answer rather than a placeholder, and
//! the difference is that C already wrote the answer down. **Both of these
//! entry points exist TWICE in the C source**: once for a build that has them,
//! and once for a build that does not. `lib/headers.c:365-394` and
//! `lib/http2.c:2993-3011` are the second definitions, reached through
//! `#else`, and they are terse -- `CURLHE_NOT_BUILT_IN`, NULL, NULL, NULL, with
//! every parameter cast to void. This build satisfies the conditions those
//! `#else`s guard, so those are the definitions it reproduces, selected by
//! [`HEADER_API_IS_BUILT_IN`] and [`PUSH_API_IS_BUILT_IN`], each derived from
//! the engine's own capability marker rather than hand-set.
//!
//! That was read late, and it corrected this module. Until it was, the header
//! lookup ran the built-in branch's validation against a freshly created empty
//! store and answered `CURLHE_NOHEADERS` -- a third behaviour matching neither
//! C branch, and a claim that the API works and this transfer merely carried no
//! headers. No transfer happened. Specification 0.6.5's asymmetry decides it:
//! under-reporting a capability is safe, over-reporting is not.
//!
//! The built-in branch is written and tested here in full and is not
//! speculative: the projection into `struct curl_header`, the two output slots
//! that keep its pointers alive, the folded name match, the origin mask, the
//! request comparison and the staleness check all run in the tests through
//! [`HeaderState`] directly, because `HeaderView`'s fields are public and a view
//! can be built without a store. Only the store's filling is missing, and that
//! is the one thing that flips the constant.

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;
use std::ffi::{CStr, CString};
use std::sync::OnceLock;

use curl_rs_lib::headers::{
    HeaderCursor, HeaderStore, HeaderView, PushHeaders,
};

use super::codes::CURLHcode;
use super::escape::{curl_easy_escape, curl_easy_unescape};
use super::handle::{curl_header, BAD_HEADER_ARGUMENT, CURL};
use super::memory;
use super::panic_boundary::{guard, guard_ptr, guard_void};
use super::types::{curl_pushheaders, curl_version_info_data};

/// `time_t` on all four supported targets.
///
/// Every mandated target is 64-bit Unix with a signed 64-bit `time_t`, so the
/// engine's `i64` and the C `time_t` are the same type rather than merely the
/// same width. 32-bit targets are deliberately out of scope, so no narrowing
/// case exists to handle.
type TimeT = i64;

// Immortal storage helpers.

/// Leaks a NUL-terminated copy of `text`, returning a pointer C may keep.
///
/// An interior NUL cannot survive the trip -- a C string has no way to carry
/// one -- so the text is truncated at the first NUL rather than dropped. That
/// is the same thing a C `strcpy` into a `static char[]` would do, and it
/// cannot occur for any string this module actually passes: the banner and the
/// capability names are ASCII literals and generated numbers.
fn immortal_c_string(text: &str) -> *const c_char {
    let truncated = match text.find('\0') {
        Some(at) => &text[..at],
        None => text,
    };
    let owned = CString::new(truncated).unwrap_or_else(|_| {
        unreachable!("the text was truncated at its first NUL, so none remains")
    });
    owned.into_raw().cast_const()
}

/// Leaks a NULL-terminated array of NUL-terminated strings.
fn immortal_c_array(items: &[&'static str]) -> *const *const c_char {
    let mut pointers: Vec<*const c_char> =
        items.iter().map(|item| immortal_c_string(item)).collect();
    pointers.push(ptr::null());
    let leaked: &'static mut [*const c_char] = Vec::leak(pointers);
    leaked.as_ptr()
}

/// An `Option<&str>` as either a C string or NULL.
fn immortal_c_option(text: Option<&'static str>) -> *const c_char {
    match text {
        Some(value) => immortal_c_string(value),
        None => ptr::null(),
    }
}

/// A possibly-null C string as an `Option<&CStr>`.
///
/// # Safety
///
/// `ptr` must be either null or a pointer to a NUL-terminated string that
/// outlives the returned borrow.
unsafe fn borrow<'a>(ptr: *const c_char) -> Option<&'a CStr> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: the caller guarantees a NUL-terminated string that outlives
        // the borrow, which is `CStr::from_ptr`'s precondition.
        Some(unsafe { CStr::from_ptr(ptr) })
    }
}

// curl_escape / curl_unescape

/// Percent-encodes a string. The pre-7.15.4 name for `curl_easy_escape`
/// (`curl.h:2699-2701`, defined in [`super::escape`]).
///
/// Supersedes `curl_escape` (`lib/escape.c:36-39`), whose entire body is a
/// single call into `curl_easy_escape` with a null handle:
///
/// ```c
/// char *curl_escape(const char *string, int inlength)
/// {
///   return curl_easy_escape(NULL, string, inlength);
/// }
/// ```
///
/// A zero `length` means the string is measured with `strlen`
/// (`lib/escape.c:59`); any other value is trusted absolutely, so the encode
/// reads that many bytes whether or not a NUL appears first. The escaped
/// character set, the case of the hex digits and the unreserved set all belong
/// to `curl_rs_lib::url::escape`, which pins them against an oracle measured
/// from the frozen library -- necessarily, because percent-encoding is
/// wire-visible and 1,476 fixtures compare exact bytes.
///
/// # Safety
///
/// `string` must be either null or address at least the number of bytes the
/// length rule above resolves to, unmutated for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_escape(
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    // SAFETY: the contract is identical and is forwarded unchanged; the null
    // handle is what the C passes at `lib/escape.c:38`. `curl_easy_escape`
    // installs its own panic guard, so this forward adds none: a second one
    // would count the same contained panic twice.
    unsafe { curl_easy_escape(ptr::null_mut(), string, length) }
}

/// Percent-decodes a string. The pre-7.15.4 name for `curl_easy_unescape`
/// (`curl.h:2718-2721`, defined in [`super::escape`]).
///
/// # Safety
///
/// As [`curl_escape`].
#[no_mangle]
pub unsafe extern "C" fn curl_unescape(
    string: *const c_char,
    length: c_int,
) -> *mut c_char {
    // SAFETY: the contract is identical and is forwarded unchanged; the null
    // handle and null out-parameter are what the C passes at
    // `lib/escape.c:44`. As above, the guard belongs to the callee.
    unsafe {
        curl_easy_unescape(ptr::null_mut(), string, length, ptr::null_mut())
    }
}

// curl_free

/// Releases a buffer libcurl allocated for the caller.
///
/// # Safety
///
/// `p` must be either null or a pointer previously returned by a libcurl
/// function documented as requiring `curl_free`, and must not be used
/// afterwards. A pointer this crate did not allocate is caller error that
/// cannot be defended against -- there is no header, no offset and no
/// bookkeeping to inspect, which is precisely what makes a plain `free` work
/// too -- but null is defended against and must be.
#[no_mangle]
pub unsafe extern "C" fn curl_free(p: *mut c_void) {
    guard_void(|| {
        // SAFETY: the caller guarantees `p` is null or a live block from this
        // library's allocator, which is `memory::free`'s whole precondition.
        unsafe { memory::free(p) };
    });
}

// curl_getdate

/// Converts a date string to seconds since the Unix epoch.
///
/// Every format curl accepts is accepted, because `curl_getdate` is exported
/// and applications parse arbitrary server dates through it: RFC 1123, RFC 850,
/// asctime and the tolerated variants, with the six-part walk, the timezone
/// table and the two-digit-year pivot all living in `curl-rs-lib`'s parser.
///
/// # Safety
///
/// `p` must be either null or a pointer to a NUL-terminated string. `unused`
/// is never dereferenced and may be anything.
#[no_mangle]
pub unsafe extern "C" fn curl_getdate(
    p: *const c_char,
    unused: *const TimeT,
) -> TimeT {
    let _ = unused;
    guard(-1, || {
        // SAFETY: forwarded from this function's own contract -- `p` is null or
        // a NUL-terminated string, and the borrow ends inside this closure.
        let text = unsafe { borrow(p) };
        // Bound before destructuring because a `let ... else` initialiser may
        // not end in a block expression, and because it keeps the SAFETY
        // comment above directly against the `unsafe` it justifies.
        let Some(text) = text else {
            // C would pass NULL to `parsedate`, which dereferences it. There
            // is no defined result to preserve, and `-1` is the documented
            // failure answer every correct caller already handles.
            return -1;
        };
        match text.to_str() {
            Ok(date) => curl_rs_lib::getdate(date).unwrap_or(-1),
            // A date containing a non-UTF-8 byte cannot match any format the
            // parser accepts -- every one is ASCII -- so failing here gives the
            // same answer as parsing would, without inventing a lossy
            // conversion.
            Err(_) => -1,
        }
    })
}

// curl_getenv

/// Reads an environment variable into a caller-owned buffer.
///
/// Supersedes `curl_getenv` (`lib/getenv.c:26-70`), specifically its
/// non-Windows branch at `:66-69`:
///
/// ```c
/// char *env = getenv(variable);
/// return (env && env[0]) ? curlx_strdup(env) : NULL;
/// ```
///
/// **An empty value reads as absent.** `env[0]` is the test, so a variable set
/// to the empty string returns NULL exactly as an unset one does. That is
/// surprising and it is the contract, so it is reproduced; a caller cannot
/// distinguish the two cases through this function and never could. No
/// filtering curl does not perform is added, and no check it does perform is
/// omitted.
///
/// # The NAME is bytes too
///
/// `getenv` takes a `char *` and compares it against the bytes of `environ`,
/// so a variable whose name is not valid UTF-8 is findable in the C. This
/// function decoded the name with `CStr::to_str` and answered NULL for
/// anything it could not read, which reported such a variable as unset even
/// when it was set -- a filter curl does not perform, on the very surface
/// whose value path is already careful to stay byte-exact.
/// [`OsStr::from_bytes`](std::os::unix::ffi::OsStrExt::from_bytes) is a
/// lossless view rather than a conversion, and `std::env::var_os` accepts an
/// `OsStr`, so the lookup now uses exactly the bytes the caller passed.
///
/// # Safety
///
/// `variable` must be either null or a pointer to a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn curl_getenv(variable: *const c_char) -> *mut c_char {
    guard_ptr(|| {
        // SAFETY: forwarded from this function's own contract; the borrow does
        // not escape this closure.
        let name = unsafe { borrow(variable) };
        let Some(name) = name else {
            return ptr::null_mut();
        };
        // The name reaches `var_os` as the bytes the caller supplied. See the
        // "The NAME is bytes too" section above for what decoding it cost.
        let Some(value) = std::env::var_os(os_str(name.to_bytes())) else {
            return ptr::null_mut();
        };
        let bytes = os_bytes(&value);
        if bytes.is_empty() {
            // The `env[0]` test above: an empty value reads as absent.
            return ptr::null_mut();
        }
        memory::copy_to_c_string(bytes)
    })
}

/// The raw bytes of an `OsStr`, without a lossy conversion.
///
/// Environment values are arbitrary byte strings on every supported target, and
/// all four are Unix, so the platform extension is always available and always
/// exact. Going through `to_string_lossy` would replace an invalid byte with
/// U+FFFD and hand the caller something the environment does not contain.
fn os_bytes(value: &std::ffi::OsStr) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    value.as_bytes()
}

/// The inverse view: bytes as an `OsStr`, without a conversion.
///
/// The mirror of [`os_bytes`] and exact for the same reason. It is what lets an
/// environment variable be looked up by the name the caller actually gave,
/// rather than by a decoded approximation of it.
fn os_str(bytes: &[u8]) -> &std::ffi::OsStr {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::OsStr::from_bytes(bytes)
}

// curl_strequal / curl_strnequal

/// Case-insensitive comparison of two whole strings.
///
/// The folding is **locale-independent ASCII** and deliberately neither Unicode
/// nor locale-aware, which matters beyond this function's size: `lib/easygetopt.c:39`
/// uses `curl_strequal` for the option-name lookup, and that is why
/// `curl_easy_option_by_name` is case-insensitive. The comparison itself,
/// including the null-pointer contract, lives in `curl-rs-lib`; this function
/// converts pointers to `Option<&CStr>` and a `bool` to a `c_int`.
///
/// # Safety
///
/// Each argument must be either null or a pointer to a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn curl_strequal(
    s1: *const c_char,
    s2: *const c_char,
) -> c_int {
    guard(0, || {
        // SAFETY: the caller guarantees each non-null pointer addresses a
        // NUL-terminated string; `borrow` performs the null test itself.
        let (left, right) = unsafe { (borrow(s1), borrow(s2)) };
        c_int::from(curl_rs_lib::strequal(left, right))
    })
}

/// Case-insensitive comparison of at most `n` bytes.
///
/// Supersedes `curl_strnequal` (`lib/strequal.c:87-95`). Two null pointers
/// compare equal only when `n` is non-zero -- an asymmetry with
/// [`curl_strequal`] that the engine documents and reproduces.
///
/// # Safety
///
/// Each argument must be either null or a pointer to a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn curl_strnequal(
    s1: *const c_char,
    s2: *const c_char,
    n: usize,
) -> c_int {
    guard(0, || {
        // SAFETY: as for `curl_strequal` above.
        let (left, right) = unsafe { (borrow(s1), borrow(s2)) };
        c_int::from(curl_rs_lib::strnequal(left, right, n))
    })
}

// curl_version

/// Returns the version banner.
///
/// Supersedes `curl_version` (`lib/version.c:145`), which composes the string
/// into a `static char out[300]`. The composition -- which parts appear, in
/// which order, with which separators -- is `curl-rs-lib`'s, because the test
/// harness parses this string to decide which fixtures to run
/// and so it is a machine-read contract rather than
/// display text. The module documentation records the two banner decisions that
/// follow from that: `Debug` and `TrackMemory` are withheld, and the rustls
/// token is the truthful one rather than `rustls-ffi`.
///
/// The return type is `char *` and not `const char *`, and the pointer
/// addresses immortal storage. The caller must not free it, and C's `static`
/// buffer means the caller never could.
#[no_mangle]
pub extern "C" fn curl_version() -> *mut c_char {
    static BANNER: OnceLock<usize> = OnceLock::new();

    guard_ptr(|| {
        // The address is stored as a `usize` because `*mut c_char` is not
        // `Sync`. Storing the address rather than the pointer keeps the cell
        // itself thread-safe without a wrapper type, and the cast back is
        // sound because nothing else ever writes this cell.
        let address = *BANNER
            .get_or_init(|| immortal_c_string(curl_rs_lib::version()) as usize);
        address as *mut c_char
    })
}

// curl_version_info

/// Returns the version and capability report.
///
/// Supersedes `curl_version_info` (`lib/version.c:596`). The `CURLversion`
/// argument is accepted and ignored, exactly as C ignores it -- `(void)stamp;`
/// at `lib/version.c:619` -- because the struct only ever grew, so an older
/// consumer simply reads fewer fields and `age` tells it how many are valid.
/// `curl.h:3221` leaves the parameter UNNAMED, which `verify-synopsis.pl`
/// depends on when it rewrites `, parameter);` to `, ...);`, and the return is
/// non-const; both are preserved.
///
/// # Why the address is leaked and stored as a `usize`
///
/// C's return type is `curl_version_info_data *` -- a mutable pointer into a
/// mutable `static` -- so a caller has always been able to write through it.
/// Specification 0.8.1 freezes that signature, so the write capability must be
/// reproduced rather than narrowed away.
///
/// That rules out the obvious implementation. Holding the struct in a
/// `OnceLock<ImmortalReport>` behind a hand-written `unsafe impl Send + Sync`,
/// taking `&report.0` from `get_or_init` and casting it with `.cast_mut()`,
/// does not work. **A pointer derived from a shared reference carries
/// read-only provenance, and writing through it is undefined behaviour** no
/// matter what the C prototype says -- `OnceLock::get_or_init` can only ever
/// hand back a `&T`, so no cast performed on its result can produce a pointer a
/// caller may legally write. Such a cast makes the compiler accept a claim the
/// aliasing model does not, and it is exactly the shape Miri reports.
///
/// So the storage is leaked instead: `Box::into_raw` yields a pointer with
/// write provenance and no borrow behind it, and only the ADDRESS is kept, in a
/// `OnceLock<usize>`. That is the pattern [`curl_version`] above already uses
/// for its banner, and adopting it here removes the wrapper struct and both
/// `unsafe impl`s outright -- a `usize` is `Send + Sync` on its own, so there is
/// no unsafe assertion left to get wrong. The leak is deliberate and bounded:
/// one allocation per process, matching C's function-level `static`.
#[no_mangle]
pub extern "C" fn curl_version_info(
    stamp: c_int,
) -> *mut curl_version_info_data {
    let _ = stamp;
    static REPORT: OnceLock<usize> = OnceLock::new();

    guard_ptr(|| {
        let address = *REPORT
            .get_or_init(|| Box::into_raw(Box::new(build_report())) as usize);
        // Sound as a WRITE pointer because the address came from
        // `Box::into_raw` and no reference to the allocation was ever formed:
        // the `Box` was consumed, and a `usize` holds no borrow. Nothing else
        // writes this cell, and `get_or_init` guarantees the initialiser runs
        // exactly once even under concurrent first calls, so every caller
        // receives the same address to the same live allocation.
        address as *mut curl_version_info_data
    })
}

/// Copies the engine's report into the C layout, once.
///
/// # Where the C widths are put on
///
/// The engine reports fixed-width Rust integers -- `u32`, `i32`, `i64` -- and
/// this function is where they become `c_uint`, `c_int` and `c_long`. That
/// split is deliberate: the engine must not carry native-width assumptions, so
/// `core::ffi` types appear only in the crate that owns the C ABI.
fn build_report() -> curl_version_info_data {
    let info = curl_rs_lib::version_info();

    curl_version_info_data {
        age: info.age.as_c_int() as c_int,
        version: immortal_c_string(info.version),
        version_num: info.version_num as c_uint,
        host: immortal_c_string(info.host),
        features: info.features as c_int,
        ssl_version: immortal_c_option(info.ssl_version),
        ssl_version_num: info.ssl_version_num as c_long,
        libz_version: immortal_c_option(info.libz_version),
        protocols: immortal_c_array(info.protocols),
        ares: immortal_c_option(info.ares),
        ares_num: info.ares_num as c_int,
        libidn: immortal_c_option(info.libidn),
        iconv_ver_num: info.iconv_ver_num as c_int,
        libssh_version: immortal_c_option(info.libssh_version),
        brotli_ver_num: info.brotli_ver_num as c_uint,
        brotli_version: immortal_c_option(info.brotli_version),
        nghttp2_ver_num: info.nghttp2_ver_num as c_uint,
        nghttp2_version: immortal_c_option(info.nghttp2_version),
        quic_version: immortal_c_option(info.quic_version),
        cainfo: immortal_c_option(info.cainfo),
        capath: immortal_c_option(info.capath),
        zstd_ver_num: info.zstd_ver_num as c_uint,
        zstd_version: immortal_c_option(info.zstd_version),
        hyper_version: immortal_c_option(info.hyper_version),
        gsasl_version: immortal_c_option(info.gsasl_version),
        feature_names: immortal_c_array(info.feature_names),
        rtmp_version: immortal_c_option(info.rtmp_version),
    }
}

// The HTTP/2 PUSH_PROMISE field set behind `struct curl_pushheaders *`.

/// The promised fields of one `PUSH_PROMISE`, in the form the ABI hands back.
///
/// This is the ABI-side counterpart of `struct h2_stream_ctx`'s `push_headers`
/// trio (`lib/http2.c:132-134`), and it exists for one reason: C's accessors
/// return a **borrowed C string**, and the engine's [`PushHeaders`] holds the
/// same bytes without a terminator. `lib/http2.c:1478` builds each entry with
/// `curl_maprintf("%s:%s", name, value)`, so in C the stored form already is a
/// NUL-terminated `name:value` string and `curl_pushheader_bynum` can return it
/// directly. Here the terminated form has to be owned by something with the
/// lifetime of the push callback, and this is that something.
struct PushSession {
    /// The engine's field set. Adopted whole, and the authority for both
    /// lookups.
    fields: PushHeaders,
    /// The same entries with a NUL appended, index-aligned with `fields`.
    terminated: Vec<Vec<u8>>,
}

impl PushSession {
    /// Adopt an engine field set, building the NUL-terminated form beside it.
    #[allow(dead_code)] // no FFI caller: the promise set is always empty here
    fn adopt(fields: PushHeaders) -> Self {
        let terminated = (0..fields.count())
            .map(|at| {
                let mut owned = match fields.by_num(at) {
                    Some(entry) => entry.to_vec(),
                    // Unreachable: `by_num` is in bounds for every index below
                    // `count`. An empty entry rather than a panic keeps the
                    // index alignment that both accessors rely on.
                    None => Vec::new(),
                };
                if let Some(cut) = owned.iter().position(|byte| *byte == 0) {
                    owned.truncate(cut);
                }
                owned.push(0);
                owned
            })
            .collect();
        Self { fields, terminated }
    }

    /// The `num`-th field as the whole NUL-terminated `name:value` string.
    ///
    /// `lib/http2.c:663-664` returns `h->stream->push_headers[num]` when `num`
    /// is in bounds and NULL otherwise. The bound is the engine's to apply.
    fn bynum(&mut self, num: usize) -> *mut c_char {
        if self.fields.by_num(num).is_none() {
            return ptr::null_mut();
        }
        match self.terminated.get_mut(num) {
            Some(entry) => entry.as_mut_ptr().cast::<c_char>(),
            // Unreachable while `adopt` is the only constructor: it builds one
            // terminated entry per field, so the two are the same length.
            None => ptr::null_mut(),
        }
    }

    /// The value of the first field with this name, as C returns it.
    fn byname(&mut self, name: &[u8]) -> *mut c_char {
        // The engine decides both whether there is an answer and where inside
        // its entry the answer starts. Its result is a borrow of ITS storage,
        // so the shared borrows below end before the mutable one is taken.
        let located = {
            let Some(tail) = self.fields.by_name(name) else {
                return ptr::null_mut();
            };
            let entries: Vec<&[u8]> = (0..self.fields.count())
                .filter_map(|at| self.fields.by_num(at))
                .collect();
            locate(&entries, tail)
        };

        let Some((at, offset)) = located else {
            return ptr::null_mut();
        };
        let Some(entry) = self.terminated.get_mut(at) else {
            // Unreachable: `locate` only ever reports an index it was given.
            return ptr::null_mut();
        };
        // `offset` indexed the engine's entry, and this entry holds the same
        // bytes plus a NUL, so it is in bounds here too. `wrapping_add` cannot
        // overflow for an in-bounds offset and needs no unsafe block, unlike
        // `ptr::add`.
        if offset >= entry.len() {
            return ptr::null_mut();
        }
        entry.as_mut_ptr().wrapping_add(offset).cast::<c_char>()
    }
}

/// Which entry a borrowed sub-slice came from, and at what offset.
///
/// `PushHeaders::by_name` answers with a slice borrowed from the entry it
/// matched, and the ABI needs that entry's INDEX so it can offset into its own
/// terminated copy. Recovering the index by re-running the name grammar would
/// duplicate the engine's rules and create a second place for them to drift, so
/// it is recovered from the borrow itself: the answer lies inside exactly one
/// entry's allocation, and comparing addresses finds which. Casting a pointer
/// to `usize` and comparing integers is defined -- no arithmetic crosses an
/// allocation boundary -- and the entries are walked in the engine's own order,
/// so the first match is the entry the engine chose.
fn locate(entries: &[&[u8]], tail: &[u8]) -> Option<(usize, usize)> {
    let target = tail.as_ptr() as usize;
    entries.iter().enumerate().find_map(|(at, entry)| {
        let start = entry.as_ptr() as usize;
        if target > start && target <= start + entry.len() {
            Some((at, target - start))
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// Which branch of the C source this build IS.
// ---------------------------------------------------------------------------

/// Whether the header API is built in, in the sense `lib/headers.c` means it.
///
/// This is not a question about Cargo features. `lib/headers.c:31` guards the
/// whole file with `#if !defined(CURL_DISABLE_HTTP) &&
/// !defined(CURL_DISABLE_HEADERS_API)`, and the `#else` at `:365-394` supplies
/// a second, complete definition of both entry points for builds where that
/// condition is false: `curl_easy_header` returns `CURLHE_NOT_BUILT_IN` after
/// casting every parameter to void, and `curl_easy_nextheader` returns NULL.
/// **Two C branches exist, and a build is one or the other.**
///
/// This build is the second one, and the reason is the first conjunct rather
/// than the second: no HTTP protocol is implemented, so
/// [`curl_rs_lib::version::protocols`] advertises nothing and the collecting
/// client writer `lib/headers.c:315-346` installs -- which is the only thing
/// that ever puts a header into a store -- has no module to live in yet. The
/// engine records exactly that as
/// [`curl_rs_lib::version::ENGINE_HEADERS`], `Engine::inert`: the store and its
/// lookup are written and tested, and nothing fills them.
///
/// Deriving the branch from that one marker rather than restating it here is
/// the whole point. When `transfer/writeout.rs` installs the writer, the row
/// becomes `Engine::working`, this constant becomes `true`, and both entry
/// points switch to the built-in branch with no edit in this file. A hand-set
/// `false` would have to be remembered.
///
/// Answering `CURLHE_NOHEADERS` instead -- as this module did until the C
/// `#else` branch was read -- states that the API works and this transfer
/// merely carried no headers. That is a claim about a transfer that never
/// happened, and specification 0.6.5's asymmetry applies: under-reporting a
/// capability is safe, over-reporting is not.
const HEADER_API_IS_BUILT_IN: bool =
    curl_rs_lib::version::ENGINE_HEADERS.is_present();

/// Whether the push-header accessors are built in, in `lib/http2.c`'s sense.
///
/// The same two-branch shape, one file over. `lib/http2.c:26` guards with
/// `#if !defined(CURL_DISABLE_HTTP) && defined(USE_NGHTTP2)`, and the `#else`
/// at `:2993-3011` defines both accessors again -- *"Satisfy external
/// references even if http2 is not compiled in"* -- as an unconditional
/// `return NULL`.
///
/// This build is that branch too, and [`curl_rs_lib::version::supports_http2`]
/// is the authority: it conjoins the `http2` feature with `ENGINE_PROTOCOLS`
/// and `ENGINE_TLS`, and `curl-rs-lib/src/protocols/http2.rs` does not exist.
/// So the answer is NULL for every input, which is what the accessors below
/// return -- **the same bytes the built-in branch would return for a pointer it
/// did not recognise**, since `!h || !GOOD_EASY_HANDLE(h->data)`
/// (`lib/http2.c:660`, `:693-694`) also answers NULL. The two branches agree
/// here, which is why this constant changes no behaviour and only records
/// which one is being executed.
const PUSH_API_IS_BUILT_IN: bool = curl_rs_lib::version::supports_http2();

/// The push session an application's `struct curl_pushheaders *` names.
///
/// **This build maintains none, and that is measured rather than assumed.** A
/// `struct curl_pushheaders *` is created by libcurl immediately before it
/// invokes a `curl_push_callback` (`multi.h:507-511`) and is invalid outside
/// that window. Two things have to exist for one to be created, and neither
/// does yet: `CURLMOPT_PUSHFUNCTION` is set through `curl_multi_setopt`, which
/// `ffi/multi.rs` will define and which `build.rs`'s `undefined_abi_exports`
/// still lists as missing; and the promise itself is parsed by
/// `curl-rs-lib/src/protocols/http2.rs`, which the engine marks as the
/// unlanded consumer of `PushHeaders::push`. So no pointer a caller can present
/// was issued here, and a pointer this library did not issue cannot be
/// interpreted -- which is why `h` is not dereferenced below.
///
/// `None` is the faithful answer and not a shortfall, and it is faithful twice
/// over: it is what `lib/http2.c`'s not-built-in branch (`:2993-3011`) returns
/// unconditionally, and it is also what the built-in branch returns for a
/// pointer failing `!h || !GOOD_EASY_HANDLE(h->data)` (`:660`, `:693-694`), a
/// magic-number test whose whole purpose is "detect rubbish input fast(er)".
/// Every pointer this function can be handed today is in that category. See
/// [`PUSH_API_IS_BUILT_IN`] for which branch this build is.
///
/// When the HTTP/2 layer lands, this becomes a borrow of the [`PushSession`]
/// that layer built with [`PushSession::adopt`], and neither accessor changes.
///
/// # Safety
///
/// `h` must be either null or a `struct curl_pushheaders *` libcurl handed to
/// the currently executing `curl_push_callback`, and the returned borrow must
/// not outlive that callback.
unsafe fn promised_fields<'a>(
    h: *mut curl_pushheaders,
) -> Option<&'a mut PushSession> {
    if !PUSH_API_IS_BUILT_IN {
        // `lib/http2.c:2993-3011`. The pointer is not examined, because a
        // build without an HTTP/2 layer issued none.
        return None;
    }
    let _ = h;
    None
}

// curl_pushheader_bynum

/// A promised header field by position, callable only from a push callback.
///
/// **The result is borrowed, not owned.** It points into storage libcurl holds
/// for the duration of the callback, so the caller must NOT release it with
/// [`curl_free`] and must not keep it after the callback returns.
///
/// **It is the whole `name:value` string, colon and value included**, not the
/// value alone -- `lib/http2.c:1478` stores each field that way. Trimming it to
/// a value-only accessor would break every existing push callback.
///
/// # Safety
///
/// `h` must be either null or the `struct curl_pushheaders *` libcurl passed to
/// the `curl_push_callback` now executing. Outside that context the pointer is
/// invalid, and no library can detect every such misuse.
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_bynum(
    h: *mut curl_pushheaders,
    num: usize,
) -> *mut c_char {
    guard_ptr(|| {
        // SAFETY: forwarded verbatim from this function's own contract, which
        // is what `promised_fields` requires of its caller. The borrow does not
        // escape this closure.
        match unsafe { promised_fields(h) } {
            Some(session) => session.bynum(num),
            // `lib/http2.c:660-661`.
            None => ptr::null_mut(),
        }
    })
}

// curl_pushheader_byname

/// A promised header field by name, callable only from a push callback.
///
/// Supersedes `curl_pushheader_byname` (`lib/http2.c:673-702`). Returns the
/// value of the first field with this name -- **borrowed**, as
/// [`curl_pushheader_bynum`] is -- or NULL.
///
/// # Safety
///
/// `h` must satisfy the contract on [`curl_pushheader_bynum`], and `name` must
/// be either null or a pointer to a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn curl_pushheader_byname(
    h: *mut curl_pushheaders,
    name: *const c_char,
) -> *mut c_char {
    guard_ptr(|| {
        // SAFETY: as for `curl_pushheader_bynum`.
        let session = unsafe { promised_fields(h) };
        let Some(session) = session else {
            return ptr::null_mut();
        };
        // SAFETY: `name` is null or a NUL-terminated string by this function's
        // contract; the borrow ends before the pointer is returned.
        let borrowed = unsafe { borrow(name) };
        let Some(name) = borrowed else {
            return ptr::null_mut();
        };
        session.byname(name.to_bytes())
    })
}

// The two output slots -- `data->state.headerout[0]` and `[1]`.

/// One output slot: a `struct curl_header` plus the strings its pointers name.
///
/// The engine's documentation assigns this type and both slots to this module
/// (`curl-rs-lib/src/headers/mod.rs`, on `HeaderView`), which is why they are
/// here and not there: a `#[repr(C)]` mirror of a frozen C struct belongs to the
/// crate that owns the C ABI.
struct HeaderSlot {
    /// The record C reads. Its `name` and `value` address the two buffers
    /// below.
    out: curl_header,
    /// The NUL-terminated name `out.name` points at.
    name: Vec<u8>,
    /// The NUL-terminated value `out.value` points at.
    value: Vec<u8>,
}

impl HeaderSlot {
    /// An empty slot, with both pointers null and every count zero.
    ///
    /// `curl_header` has no `Default`, and giving it one would be a claim about
    /// a frozen ABI struct that nothing needs, so the fields are written out.
    fn new() -> Self {
        Self {
            out: curl_header {
                name: ptr::null_mut(),
                value: ptr::null_mut(),
                amount: 0,
                index: 0,
                origin: 0,
                anchor: ptr::null_mut(),
            },
            name: Vec::new(),
            value: Vec::new(),
        }
    }

    /// Project a view into this slot and return the slot's address.
    fn fill(&mut self, view: HeaderView<'_>) -> *mut curl_header {
        self.name = c_bytes(view.name);
        self.value = c_bytes(view.value);
        // Both buffers are final BEFORE either pointer is taken. Assigning one
        // after taking the other's pointer would be sound but fragile: the
        // ordering is what guarantees neither pointer can be left addressing a
        // reallocated buffer.
        self.out = curl_header {
            name: self.name.as_mut_ptr().cast::<c_char>(),
            value: self.value.as_mut_ptr().cast::<c_char>(),
            amount: view.amount,
            index: view.index,
            origin: view.origin,
            anchor: view.anchor.to_raw() as *mut c_void,
        };
        &mut self.out as *mut curl_header
    }
}

/// A NUL-terminated copy of `bytes`, truncated at any interior NUL.
///
/// `struct curl_header`'s two fields are `char *`, so an interior NUL ends the
/// string as far as every consumer is concerned. C reaches the same place by a
/// different route: it stores the header line as a C string and splits it with
/// NULs, so a value containing one was already truncated before the field was
/// ever handed out. Truncating here reproduces that rather than handing a
/// consumer a length it cannot see.
fn c_bytes(bytes: &[u8]) -> Vec<u8> {
    let visible = match bytes.iter().position(|byte| *byte == 0) {
        Some(at) => &bytes[..at],
        None => bytes,
    };
    let mut owned = Vec::with_capacity(visible.len() + 1);
    owned.extend_from_slice(visible);
    owned.push(0);
    owned
}

/// The header state of one easy handle: `data->state.httphdrs`,
/// `data->state.requests` and both `data->state.headerout` slots.
struct HeaderState {
    /// The headers collected so far.
    store: HeaderStore,
    /// `data->state.requests` -- the number of the request in progress.
    cur_request: c_int,
    /// `headerout[0]`, filled by [`curl_easy_header`].
    lookup: HeaderSlot,
    /// `headerout[1]`, filled by [`curl_easy_nextheader`].
    walk: HeaderSlot,
}

impl HeaderState {
    /// A handle that has collected nothing and issued no request.
    ///
    /// `data->state.requests` starts at 0, so a `request` argument above 0 is
    /// answered with `CURLHE_NOREQUEST` -- after the emptiness test, because
    /// `lib/headers.c` orders them that way.
    #[allow(dead_code)] // no FFI caller: no `CURL *` this library issued exists
    fn new() -> Self {
        Self {
            store: HeaderStore::new(),
            cur_request: 0,
            lookup: HeaderSlot::new(),
            walk: HeaderSlot::new(),
        }
    }

    /// Look one header up, filling `headerout[0]` on success.
    ///
    /// Every decision is the engine's: the ASCII-folded name match, the bitwise
    /// AND against `origin`, the exact request comparison, and the order in
    /// which `CURLHE_BAD_ARGUMENT`, `CURLHE_NOHEADERS`, `CURLHE_NOREQUEST`,
    /// `CURLHE_MISSING` and `CURLHE_BADINDEX` are produced.
    fn header(
        &mut self,
        name: &[u8],
        index: usize,
        origin: c_uint,
        request: c_int,
    ) -> Result<*mut curl_header, CURLHcode> {
        let view = self
            .store
            .header(name, index, origin, request, self.cur_request)
            .map_err(CURLHcode::from)?;
        Ok(self.lookup.fill(view))
    }

    /// Step to the next matching header, filling `headerout[1]`.
    ///
    /// Returns NULL at the end of the walk, which is C's "no more headers
    /// available" (`lib/headers.c:154-156`). There is no error channel and no
    /// validation, because C has neither here.
    fn next_header(
        &mut self,
        origin: c_uint,
        request: c_int,
        prev: Option<HeaderCursor>,
    ) -> *mut curl_header {
        match self
            .store
            .next_header(origin, request, self.cur_request, prev)
        {
            Some(view) => self.walk.fill(view),
            None => ptr::null_mut(),
        }
    }
}

/// The header state of the easy handle `easy` addresses.
///
/// **This build maintains none, and that is measured rather than assumed.**
/// `curl-rs-lib/src/easy/` holds only `mod.rs` and `options.rs`; there is no
/// engine easy-handle object, and `curl_easy_init` is one of the exports
/// `build.rs`'s `undefined_abi_exports` still reports as missing. So no `CURL *`
/// a caller can present was issued by this library, and a pointer this library
/// did not issue cannot be interpreted -- which is why `easy` is not
/// dereferenced below. Doing so on the strength of a type name would be
/// undefined behaviour, not a shortcut.
///
/// Header collection is equally absent: the engine marks `HeaderStore::push` as
/// awaiting its consumer in `curl-rs-lib/src/transfer/`, and it is
/// `pub(crate)`, so no store anywhere in this build has ever held a header.
///
/// `None` therefore means "not a handle this crate issued", which is exactly
/// the `!data` limb of `lib/headers.c:69-72` -- so the built-in branch below
/// answers it with `CURLHE_BAD_ARGUMENT`. It is reached only when the header
/// API is built in at all; [`HEADER_API_IS_BUILT_IN`] is tested first, and
/// today it is false, so the not-built-in branch of `lib/headers.c:365-394`
/// answers every call before this function runs.
///
/// When the easy-handle layer lands, this becomes
/// `handle::borrow_mut::<CURL, _>(easy).map(|handle| &mut handle.headers)` and
/// nothing else in this module changes.
///
/// # Safety
///
/// `easy` must be either null or an easy handle this crate issued and has not
/// released, and the returned borrow must not outlive one entry point's body.
unsafe fn header_state<'a>(easy: *mut CURL) -> Option<&'a mut HeaderState> {
    let _ = easy;
    None
}

/// The cursor a caller's `prev` resumes from.
///
/// `lib/headers.c:138-142` reads `prev->anchor` and treats a null one as
/// *"something is wrong"*, answering NULL. That case needs no test here: the
/// engine's stores start at generation 1 and never reach 0, so a null anchor
/// decodes to a cursor whose generation matches nothing and ends iteration by
/// the same staleness check that protects a cursor from a store that has since
/// been pushed to, reset or cleaned up.
///
/// # Safety
///
/// `prev` must be either null or a `struct curl_header *` a previous call
/// returned, still valid and readable.
unsafe fn resume_from(prev: *mut curl_header) -> Option<HeaderCursor> {
    if prev.is_null() {
        return None;
    }
    // SAFETY: `prev` is non-null and, by this function's contract, addresses a
    // readable `struct curl_header`. Only the `anchor` field is read, as a
    // plain scalar load; no pointer it might hold is followed.
    let anchor = unsafe { (*prev).anchor };
    Some(HeaderCursor::from_raw(anchor as usize))
}

// curl_easy_header

/// Look up one header of a completed or in-flight transfer.
///
/// **The returned record is borrowed and must not be freed.** It addresses
/// `data->state.headerout[0]`, so it stays valid until the next call to this
/// function on the same handle -- and note that `curl_easy_nextheader` uses the
/// OTHER slot, so interleaving the two never clobbers either result.
///
/// # Errors
///
/// `CURLHE_BAD_ARGUMENT` for a null `easy`, `name` or `hout`, for an `origin`
/// of 0 or one carrying a bit outside the five-bit mask of `header.h:41-45`,
/// and for a `request` below -1; then `CURLHE_NOHEADERS`, `CURLHE_NOREQUEST`,
/// `CURLHE_MISSING` and `CURLHE_BADINDEX` in the situations `lib/headers.c`
/// produces them. `CURLHcode` (`header.h:47-56`) has eight members, not one of
/// them explicitly numbered, and **no `_LAST` sentinel** -- none is invented.
///
/// `CURLHE_NOT_BUILT_IN` is what a build whose header API is not compiled in
/// answers, unconditionally and before examining anything
/// (`lib/headers.c:365-381`). **This build is that branch**, because nothing
/// fills a header store -- see [`HEADER_API_IS_BUILT_IN`] -- so it is the only
/// code this function returns today. The symbol itself is exported under
/// `--no-default-features` as all thirteen in this module are; being exported
/// and being built in are different questions, and it was conflating them that
/// previously made this paragraph claim the code was unreachable.
///
/// This function is declared in `include/curl/header.h` (`:58-63`) -- one of
/// only two declarations that header carries -- and defined here rather than in
/// `ffi/easy.rs`; see the module documentation.
///
/// # Safety
///
/// `easy` must be either null or an easy handle this crate issued. `name` must
/// be either null or a pointer to a NUL-terminated string. `hout` must be
/// either null or a writable, aligned `struct curl_header *`.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_header(
    easy: *mut CURL,
    name: *const c_char,
    index: usize,
    origin: c_uint,
    request: c_int,
    hout: *mut *mut curl_header,
) -> CURLHcode {
    guard(BAD_HEADER_ARGUMENT, || {
        if !HEADER_API_IS_BUILT_IN {
            // `lib/headers.c:365-381` verbatim: every parameter is cast to
            // void and `CURLHE_NOT_BUILT_IN` is returned. No argument is
            // examined and `*hout` is not written, so a null `hout` is safe
            // here without a test -- which is why C's branch needs none.
            return CURLHcode::CURLHE_NOT_BUILT_IN;
        }

        // `lib/headers.c:69-72` tests `!name || !hout || !data` as one
        // condition. The origin and request halves of the same condition are
        // the engine's, because they are decisions rather than pointer checks.
        if easy.is_null() || hout.is_null() {
            return BAD_HEADER_ARGUMENT;
        }
        // SAFETY: `name` is null or a NUL-terminated string by this function's
        // contract; the borrow does not escape this closure.
        let borrowed = unsafe { borrow(name) };
        let Some(name) = borrowed else {
            return BAD_HEADER_ARGUMENT;
        };
        let name = name.to_bytes();

        // SAFETY: forwarded verbatim from this function's own contract, which
        // is what `header_state` requires of its caller.
        match unsafe { header_state(easy) } {
            Some(state) => match state.header(name, index, origin, request) {
                Ok(record) => {
                    // SAFETY: `hout` is non-null by the test above and, by
                    // this function's contract, is a writable aligned
                    // `struct curl_header *`. `record` addresses the handle's
                    // own slot, so it outlives this write. `lib/headers.c:117`
                    // performs the same store, and only on success.
                    unsafe { hout.write(record) };
                    CURLHcode::CURLHE_OK
                }
                Err(code) => code,
            },
            // The `!data` limb of `lib/headers.c:69-72`, WIDENED, and the
            // widening is deliberate and measured. That limb tests only for
            // NULL; a non-null pointer that is not a handle is dereferenced,
            // and a driver linked against a stock libcurl 8.14.1 and handed
            // `(CURL *)0x1000` SEGFAULTS here rather than returning a code.
            // `curl_easy_nextheader` below already answers NULL for the same
            // input for the same reason. Reproducing a crash is not
            // reproducing a contract, so an unrecognised pointer gets the code
            // C reserves for an argument that was not okay.
            None => BAD_HEADER_ARGUMENT,
        }
    })
}

// curl_easy_nextheader

/// Iterate the headers matching an origin mask and request number.
///
/// **This function validates almost nothing, deliberately, because C does
/// not.** There is no origin-mask check and no handle check -- `lib/headers.c:133`
/// dereferences the handle immediately, which a driver linked against a stock
/// libcurl 8.14.1 confirms by SEGFAULTING when handed `(CURL *)0x1000` -- and
/// consequently no error channel at all: every way of failing is NULL. An
/// `origin` of 0 matches nothing and simply ends iteration. The one guard this
/// shim adds is a handle it did not issue, answered with NULL, because
/// reproducing a dereference is not reproducing a contract.
///
/// **The returned record is borrowed and must not be freed.** It addresses
/// `data->state.headerout[1]`, a different slot from the one
/// [`curl_easy_header`] fills, and it stays valid until the next call to this
/// function on the same handle.
///
/// A `prev` from a store that has changed since -- pushed to, reset or cleaned
/// up -- ends iteration rather than reading a shifted element.
///
/// A build whose header API is not compiled in returns NULL from here without
/// examining anything (`lib/headers.c:383-393`). **This build is that branch**
/// -- see [`HEADER_API_IS_BUILT_IN`] -- and NULL is also what the built-in
/// branch answers once the walk is over, so the two branches agree on the bytes
/// and differ only in the reason. Unlike [`curl_easy_header`], which has an
/// error channel and therefore had a code to get wrong, nothing observable
/// changed here.
///
/// # Safety
///
/// `easy` must be either null or an easy handle this crate issued. `prev` must
/// be either null or a `struct curl_header *` a previous call returned, still
/// valid and readable.
#[no_mangle]
pub unsafe extern "C" fn curl_easy_nextheader(
    easy: *mut CURL,
    origin: c_uint,
    request: c_int,
    prev: *mut curl_header,
) -> *mut curl_header {
    guard_ptr(|| {
        if !HEADER_API_IS_BUILT_IN {
            // `lib/headers.c:383-393` verbatim.
            return ptr::null_mut();
        }
        if easy.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: `prev` is null or a record a previous call returned, by this
        // function's contract; `resume_from` reads only its `anchor` scalar.
        let resume = unsafe { resume_from(prev) };

        // SAFETY: forwarded verbatim from this function's own contract, which
        // is what `header_state` requires of its caller.
        match unsafe { header_state(easy) } {
            Some(state) => state.next_header(origin, request, resume),
            // A pointer this crate did not issue. `lib/headers.c:133`
            // dereferences the handle immediately and so has no answer for
            // this; NULL ends the caller's walk without a read.
            None => ptr::null_mut(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use curl_rs_lib::headers::{
        CURLH_1XX, CURLH_CONNECT, CURLH_HEADER, CURLH_PSEUDO, CURLH_TRAILER,
    };

    /// The reserved bit `lib/headers.c:50` ORs into every reported `origin`.
    const RESERVED: c_uint = 1 << 27;

    /// Reads a C string a function just returned.
    fn text(ptr: *const c_char) -> String {
        assert!(!ptr.is_null(), "expected a string, got NULL");
        // SAFETY: every caller below passes a pointer one of this module's
        // functions produced, all of which are NUL-terminated.
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }

    /// Walks a NULL-terminated array of C strings, as a consumer does.
    fn walk(array: *const *const c_char) -> Vec<String> {
        assert!(!array.is_null(), "both array fields are always populated");
        let mut out = Vec::new();
        let mut index = 0isize;
        loop {
            // SAFETY: the array was built by `immortal_c_array`, which appends
            // a NULL terminator, so the walk stops in bounds.
            let entry = unsafe { *array.offset(index) };
            if entry.is_null() {
                break;
            }
            out.push(text(entry));
            index += 1;
        }
        out
    }

    fn c_str(text: &str) -> CString {
        CString::new(text).expect("test literals contain no NUL")
    }

    // The partition: exactly thirteen exports, spelled as `lib/libcurl.def`
    // spells them.

    /// This module's own source, so the claim in its documentation is
    /// executable rather than a comment. The needles are matched at column 0,
    /// which is why this test's own indented string literals cannot match
    /// themselves.
    const SOURCE: &str = include_str!("misc.rs");

    #[test]
    fn exactly_thirteen_symbols_are_exported() {
        let attributes = SOURCE
            .lines()
            .filter(|line| *line == "#[no_mangle]")
            .count();
        assert_eq!(
            attributes, 13,
            "this module closes the 100-symbol partition with 13 exports: 11 \
             standalone plus the two header-API functions"
        );

        let mut defined: Vec<&str> = SOURCE
            .lines()
            .filter_map(|line| {
                let rest = line
                    .strip_prefix("pub unsafe extern \"C\" fn ")
                    .or_else(|| line.strip_prefix("pub extern \"C\" fn "))?;
                let end = rest.find('(')?;
                Some(&rest[..end])
            })
            .collect();
        defined.sort_unstable();

        let mut expected = [
            "curl_easy_header",
            "curl_easy_nextheader",
            "curl_escape",
            "curl_free",
            "curl_getdate",
            "curl_getenv",
            "curl_pushheader_byname",
            "curl_pushheader_bynum",
            "curl_strequal",
            "curl_strnequal",
            "curl_unescape",
            "curl_version",
            "curl_version_info",
        ];
        expected.sort_unstable();
        assert_eq!(defined, expected);
    }

    /// `multi.h:502-503` declares `bynum` before `:504-505` declares `byname`,
    /// and `cbindgen.toml` sets `sort_by = "None"`, so source order is the
    /// generated header's order.
    #[test]
    fn bynum_is_defined_before_byname() {
        let bynum = SOURCE
            .find("pub unsafe extern \"C\" fn curl_pushheader_bynum")
            .expect("bynum is defined here");
        let byname = SOURCE
            .find("pub unsafe extern \"C\" fn curl_pushheader_byname")
            .expect("byname is defined here");
        assert!(
            bynum < byname,
            "the declaration order in multi.h is bynum then byname, and \
             sort_by = \"None\" makes source order the header's order"
        );
    }

    // curl_free, and the producers it must round-trip.

    #[test]
    fn freeing_null_is_a_no_op() {
        // SAFETY: null is explicitly permitted.
        unsafe { curl_free(ptr::null_mut()) };
    }

    #[test]
    fn a_getenv_buffer_round_trips_and_is_ours_to_free() {
        // SAFETY: the name is a live NUL-terminated literal.
        let got = unsafe { curl_getenv(c_str("PATH").as_ptr()) };
        assert!(!got.is_null(), "PATH is set in every test environment");
        assert!(!text(got).is_empty());
        // SAFETY: `got` came from `curl_getenv`, which documents `curl_free`.
        unsafe { curl_free(got.cast::<c_void>()) };
    }

    #[test]
    fn an_absent_variable_reads_as_null() {
        let name = c_str("CURL_RS_DEFINITELY_NOT_SET_A7F3");
        // SAFETY: the name is a live NUL-terminated string.
        let got = unsafe { curl_getenv(name.as_ptr()) };
        assert!(got.is_null());
    }

    #[test]
    fn a_null_name_reads_as_null() {
        // SAFETY: null is explicitly permitted.
        let got = unsafe { curl_getenv(ptr::null()) };
        assert!(got.is_null());
    }

    /// `lib/getenv.c:66-69` tests `env[0]`, so an empty value reads as absent.
    #[test]
    fn an_empty_value_reads_as_absent() {
        let name = "CURL_RS_MISC_EMPTY_PROBE";
        std::env::set_var(name, "");
        // SAFETY: the name is a live NUL-terminated string.
        let got = unsafe { curl_getenv(c_str(name).as_ptr()) };
        std::env::remove_var(name);
        assert!(
            got.is_null(),
            "an empty value is indistinguishable from unset"
        );
    }

    /// A variable whose NAME is not valid UTF-8 is found, not reported absent.
    ///
    /// `getenv` compares its `char *` against the bytes of `environ`, so such a
    /// variable is findable in the C. This function decoded the name with
    /// `CStr::to_str` and answered NULL for anything it could not read, which
    /// reported a variable that IS set as unset -- a filter curl does not
    /// perform, on the very surface whose value path was already careful to
    /// stay byte-exact.
    #[test]
    #[cfg(unix)]
    fn an_undecodable_variable_name_is_still_looked_up() {
        use std::os::unix::ffi::OsStrExt;

        // A lone continuation byte in the middle of an otherwise ASCII name.
        const NAME: &[u8] = b"CURL_RS_MISC_\xffPROBE";
        let name = std::ffi::OsStr::from_bytes(NAME);
        std::env::set_var(name, "found");

        // The same bytes, NUL-terminated, as a C caller would pass them.
        let mut terminated = NAME.to_vec();
        terminated.push(0);
        // SAFETY: `terminated` is a live NUL-terminated buffer for the call.
        let got = unsafe { curl_getenv(terminated.as_ptr().cast::<c_char>()) };
        std::env::remove_var(name);

        assert!(
            !got.is_null(),
            "the variable is set, so reporting it absent is wrong"
        );
        assert_eq!(text(got), "found");
        // SAFETY: `got` came from `curl_getenv`, which documents `curl_free`.
        unsafe { curl_free(got.cast::<c_void>()) };
    }

    // curl_escape / curl_unescape -- the two legacy percent-encoding names.

    /// Calls a legacy escape entry point and returns its bytes, freeing the
    /// buffer through `curl_free` so the allocator round-trip is exercised too.
    fn legacy(
        entry: unsafe extern "C" fn(*const c_char, c_int) -> *mut c_char,
        input: &str,
        length: c_int,
    ) -> Option<Vec<u8>> {
        let owned = c_str(input);
        // SAFETY: `owned` is a live NUL-terminated buffer that outlives the
        // call, and no test below passes a length beyond it.
        let raw = unsafe { entry(owned.as_ptr(), length) };
        if raw.is_null() {
            return None;
        }
        // SAFETY: a non-null return is a NUL-terminated caller-owned buffer.
        let bytes = unsafe { CStr::from_ptr(raw) }.to_bytes().to_vec();
        // SAFETY: `raw` came from this crate's allocator through the escape
        // path, and `curl_free` is the documented counterpart.
        unsafe { curl_free(raw.cast::<c_void>()) };
        Some(bytes)
    }

    #[test]
    fn the_legacy_escape_matches_the_modern_one() {
        assert_eq!(
            legacy(curl_escape, "a b/c?d", 0).as_deref(),
            Some(&b"a%20b%2Fc%3Fd"[..]),
            "a zero length measures the string, per lib/escape.c:59"
        );
        assert_eq!(
            legacy(curl_unescape, "a%20b%2Fc", 0).as_deref(),
            Some(&b"a b/c"[..])
        );
    }

    /// A zero length means `strlen`; an explicit length is trusted as given.
    #[test]
    fn the_length_convention_is_the_authoritys() {
        assert_eq!(
            legacy(curl_escape, "abcdef", 3).as_deref(),
            Some(&b"abc"[..])
        );
        // Length 1 over an empty string escapes the terminator itself, which is
        // observable in C and pinned by the engine's oracle.
        assert_eq!(legacy(curl_escape, "", 1).as_deref(), Some(&b"%00"[..]));
    }

    #[test]
    fn an_empty_result_is_an_empty_string_and_not_null() {
        let got = legacy(curl_escape, "", 0);
        assert_eq!(
            got.as_deref(),
            Some(&b""[..]),
            "lib/escape.c:60-61 duplicates the empty string, and the caller \
             must free one but not the other"
        );
    }

    #[test]
    fn a_rejected_argument_is_null_for_both_legacy_names() {
        // SAFETY: null is explicitly permitted for the string argument.
        unsafe {
            assert!(curl_escape(ptr::null(), 0).is_null());
            assert!(curl_unescape(ptr::null(), 0).is_null());
        }
        assert!(legacy(curl_escape, "x", -1).is_none(), "a negative length");
        assert!(legacy(curl_unescape, "x", -1).is_none());
    }

    /// The legacy name discards the decoded length, so a decoded NUL truncates
    /// the answer as far as any caller can tell.
    #[test]
    fn a_decoded_nul_truncates_the_legacy_answer() {
        assert_eq!(
            legacy(curl_unescape, "a%00b", 0).as_deref(),
            Some(&b"a"[..])
        );
    }

    // curl_getdate, curl_strequal, curl_strnequal.

    #[test]
    fn a_parsable_date_matches_the_engine_and_a_bad_one_is_minus_one() {
        let good = c_str("Sun, 06 Nov 1994 08:49:37 GMT");
        // SAFETY: a live NUL-terminated string, and a null `unused` is legal.
        let seconds = unsafe { curl_getdate(good.as_ptr(), ptr::null()) };
        assert_eq!(seconds, 784_111_777, "the RFC 1123 example from the docs");
        assert_eq!(
            seconds,
            curl_rs_lib::getdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap(),
            "the shim must not transform what the engine computed"
        );

        let bad = c_str("not a date at all");
        // SAFETY: a live NUL-terminated string.
        assert_eq!(unsafe { curl_getdate(bad.as_ptr(), ptr::null()) }, -1);
        // SAFETY: null is handled without a dereference.
        assert_eq!(unsafe { curl_getdate(ptr::null(), ptr::null()) }, -1);
    }

    /// Every family `lib/parsedate.c` accepts must still parse through the ABI,
    /// because `curl_getdate` is exported and applications feed it arbitrary
    /// server dates. The engine owns the grammar; this asserts the shim does not
    /// narrow it.
    #[test]
    fn every_accepted_date_family_survives_the_boundary() {
        // Each of these names 1994-11-06 08:49:37 UTC, so a single expected
        // value covers the whole family and a shim that mangled one would be
        // visible immediately. The last three name it in other zones.
        let same_instant = [
            // RFC 1123, RFC 850 and asctime.
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            // No weekday; an explicit numeric zone; lower case throughout; the
            // YYYYMMDD pure-number form; no zone at all, which means UTC.
            "06 Nov 1994 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37 +0000",
            "sun, 06 nov 1994 08:49:37 gmt",
            "19941106 08:49:37 GMT",
            "Sun, 06 Nov 1994 08:49:37",
            // "The order of the items is immaterial", per the manual page.
            "08:49:37 06 Nov 1994 GMT",
        ];
        for entry in same_instant {
            let owned = c_str(entry);
            // SAFETY: a live NUL-terminated string and a null legacy argument.
            let seconds = unsafe { curl_getdate(owned.as_ptr(), ptr::null()) };
            assert_eq!(
                seconds, 784_111_777,
                "{entry} names 1994-11-06 08:49:37 UTC"
            );
            assert_eq!(
                seconds,
                curl_rs_lib::getdate(entry).unwrap_or(-1),
                "{entry} must reach the engine unchanged"
            );
        }

        // A named zone, a numeric offset, dates with no time of day at all, and
        // the two-digit-year forms the manual page documents.
        for (entry, expected) in [
            ("Sun, 06 Nov 1994 08:49:37 MST", 784_136_977),
            ("Sun, 06 Nov 1994 08:49:37 -1200", 784_154_977),
            ("Nov-94 6", 784_080_000),
            ("06-Nov-94", 784_080_000),
            ("20 Jan 2001", 979_948_800),
            ("Thu, 01 Jan 1970 00:00:00 GMT", 0),
        ] {
            let owned = c_str(entry);
            // SAFETY: as above.
            let seconds = unsafe { curl_getdate(owned.as_ptr(), ptr::null()) };
            assert_eq!(seconds, expected, "{entry}");
        }

        // `1994-11-06` is deliberately absent from the accepted set above: the
        // manual page lists `06 Nov 1994`, `06-Nov-94`, `Nov-94 6` and the
        // YYYYMMDD pure-number form, and no ISO dashed form, so rejecting it is
        // parity rather than a shortfall.
        for entry in [
            "",
            "   ",
            "1994-11-06 08:49:37 GMT",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "yesterday",
        ] {
            let owned = c_str(entry);
            // SAFETY: as above.
            let seconds = unsafe { curl_getdate(owned.as_ptr(), ptr::null()) };
            assert_eq!(seconds, -1, "{entry:?} is not a date curl accepts");
        }
    }

    /// The legacy second parameter must be ignored even when it is non-null,
    /// because C names it `unused` and casts it to void.
    #[test]
    fn the_legacy_second_parameter_is_ignored() {
        let good = c_str("Thu, 01 Jan 1970 00:00:00 GMT");
        let sentinel: TimeT = 12345;
        // SAFETY: both pointers address live storage.
        let with = unsafe { curl_getdate(good.as_ptr(), &sentinel) };
        // SAFETY: a live string and a null legacy argument.
        let without = unsafe { curl_getdate(good.as_ptr(), ptr::null()) };
        assert_eq!(with, without);
        assert_eq!(with, 0);
        assert_eq!(sentinel, 12345, "the argument must not be written through");
    }

    #[test]
    fn the_two_comparators_agree_with_the_engine() {
        let upper = c_str("CONTENT-TYPE");
        let lower = c_str("content-type");
        let other = c_str("content-length");
        // SAFETY: all four pointers address live NUL-terminated strings.
        unsafe {
            assert_eq!(curl_strequal(upper.as_ptr(), lower.as_ptr()), 1);
            assert_eq!(curl_strequal(upper.as_ptr(), other.as_ptr()), 0);
            assert_eq!(curl_strequal(ptr::null(), ptr::null()), 1);
            assert_eq!(curl_strequal(upper.as_ptr(), ptr::null()), 0);
            // "content-" is the common eight-byte prefix.
            assert_eq!(curl_strnequal(upper.as_ptr(), other.as_ptr(), 8), 1);
            assert_eq!(curl_strnequal(upper.as_ptr(), other.as_ptr(), 9), 0);
            // The asymmetric null rule.
            assert_eq!(curl_strnequal(ptr::null(), ptr::null(), 0), 0);
            assert_eq!(curl_strnequal(ptr::null(), ptr::null(), 1), 1);
        }
    }

    /// The fold is ASCII and locale-independent, so a byte outside ASCII is
    /// never folded however a locale might spell its case.
    #[test]
    fn the_fold_is_ascii_and_not_locale_aware() {
        let dotless = c_str("\u{0131}"); // LATIN SMALL LETTER DOTLESS I
        let ascii_i = c_str("I");
        // SAFETY: both pointers address live NUL-terminated strings.
        assert_eq!(
            unsafe { curl_strequal(dotless.as_ptr(), ascii_i.as_ptr()) },
            0,
            "a Turkish locale folds these together; ASCII folding must not"
        );
    }

    // curl_version -- the machine-read banner.

    #[test]
    fn the_banner_is_the_engines_and_is_stable_across_calls() {
        let first = curl_version();
        let second = curl_version();
        assert_eq!(first, second, "the buffer must be the same one every time");
        assert_eq!(text(first), curl_rs_lib::version());
    }

    #[test]
    fn the_banner_reports_the_frozen_version() {
        let banner = text(curl_version());
        assert_eq!(curl_rs_lib::LIBCURL_VERSION, "8.19.0-DEV");
        assert_eq!(curl_rs_lib::LIBCURL_VERSION_NUM, 0x0008_1300);
        assert!(
            banner.contains(curl_rs_lib::LIBCURL_VERSION),
            "the harness substitutes %VERSION from this string, so User-Agent \
             bytes depend on it: {banner}"
        );
    }

    /// The whole of ambiguity A5 and A8, asserted rather than described.
    ///
    /// Every token below is one `tests/runtests.pl` keys a feature off, and
    /// every one of them would be FALSE of this build. Over-reporting makes a
    /// fixture run and fail; under-reporting makes it skip.
    #[test]
    fn the_banner_never_over_reports() {
        let banner = text(curl_version());
        let report = curl_version_info(0);
        assert!(!report.is_null());
        // SAFETY: `report` addresses this module's immortal report, which is
        // initialised before the pointer is handed out.
        let names = walk(unsafe { (*report).feature_names });

        for forbidden in [
            // A5: withholding Debug makes tests/runtests.pl:660 leave
            // TrackMemory unset, which makes the whole memory-checking block
            // at :1759 inert. 98 fixtures skip, and torture-test does not
            // apply.
            "Debug",
            "TrackMemory",
            // A8: the harness keys $feature{"rustls"} off a rustls-ffi token
            // at :585-586. This implementation uses rustls natively, so the
            // token would misdescribe it and accuracy wins over the unlocked
            // fixtures.
            "rustls-ffi",
            // No C TLS library is linked at any configuration, so every one of
            // these would be false.
            "OpenSSL",
            "GnuTLS",
            "mbedtls",
            "wolfssl",
            "Schannel",
            "MultiSSL",
            // Windows-only, and the target matrix is Linux and macOS.
            "SSPI",
            "Unicode",
            "WinIDN",
            "win32",
        ] {
            assert!(
                !banner.contains(forbidden),
                "the banner must not claim {forbidden}: {banner}"
            );
            assert!(
                !names.iter().any(|name| name == forbidden),
                "feature_names must not claim {forbidden}: {names:?}"
            );
        }
    }

    #[test]
    fn no_stubbed_protocol_is_advertised() {
        let report = curl_version_info(0);
        // SAFETY: as above.
        let protocols = walk(unsafe { (*report).protocols });
        for stubbed in [
            "smtp", "smtps", "imap", "imaps", "pop3", "pop3s", "telnet",
            "tftp", "smb", "smbs", "ldap", "ldaps", "rtsp", "mqtt", "dict",
            "gopher", "gophers", "rtmp", "rtmpe", "rtmps", "rtmpt", "rtmpte",
            "rtmpts",
        ] {
            assert!(
                !protocols.iter().any(|name| name == stubbed),
                "{stubbed} is not implemented and must not be advertised: \
                 {protocols:?}"
            );
        }
    }

    // curl_version_info -- the 27-field report.

    #[test]
    fn the_report_mirrors_the_engine_field_for_field() {
        let raw = curl_version_info(0);
        assert!(!raw.is_null());
        // SAFETY: `raw` addresses this module's immortal report, which is
        // initialised before the pointer is handed out and never mutated.
        let got = unsafe { &*raw };
        let want = curl_rs_lib::version_info();

        assert_eq!(got.age, want.age.as_c_int());
        assert_eq!(text(got.version), want.version);
        assert_eq!(got.version_num, want.version_num);
        assert_eq!(text(got.host), want.host);
        assert_eq!(got.features, want.features);
        assert_eq!(got.ssl_version_num, 0, "always 0 per curl.h:3117");
        assert_eq!(walk(got.protocols), want.protocols);
        assert_eq!(walk(got.feature_names), want.feature_names);
        assert_eq!(got.ares_num, want.ares_num);
        assert_eq!(got.iconv_ver_num, want.iconv_ver_num);
    }

    /// `age` names the generation whose fields are populated, and
    /// `CURLVERSION_NOW` is `CURLVERSION_TWELFTH`, whose ordinal is 11.
    #[test]
    fn the_reported_age_is_the_current_generation() {
        let raw = curl_version_info(0);
        // SAFETY: as above.
        let got = unsafe { &*raw };
        assert_eq!(got.age, curl_rs_lib::version::CURLversion::NOW.as_c_int());
        assert_eq!(got.age, 11, "CURLVERSION_TWELFTH is ordinal 11");
        assert_eq!(curl_rs_lib::version::CURLversion::LAST, 12);
    }

    /// Only a genuinely true bit is set. These four can never be true of this
    /// implementation, and the first two are the bit-level counterpart of
    /// withholding `Debug`.
    #[test]
    fn no_false_capability_bit_is_set() {
        let raw = curl_version_info(0);
        // SAFETY: as above.
        let features = unsafe { (*raw).features };
        for (name, bit) in [
            (
                "CURL_VERSION_DEBUG",
                curl_rs_lib::version::CURL_VERSION_DEBUG,
            ),
            (
                "CURL_VERSION_CURLDEBUG",
                curl_rs_lib::version::CURL_VERSION_CURLDEBUG,
            ),
            ("CURL_VERSION_SSPI", curl_rs_lib::version::CURL_VERSION_SSPI),
            (
                "CURL_VERSION_MULTI_SSL",
                curl_rs_lib::version::CURL_VERSION_MULTI_SSL,
            ),
            (
                "CURL_VERSION_KERBEROS4",
                curl_rs_lib::version::CURL_VERSION_KERBEROS4,
            ),
            ("CURL_VERSION_CONV", curl_rs_lib::version::CURL_VERSION_CONV),
        ] {
            assert_eq!(features & bit, 0, "{name} would be a false claim");
        }
    }

    /// A field the engine reports as absent must be a NULL pointer, not an
    /// empty string: NULL is how a C consumer detects "not available".
    #[test]
    fn an_absent_field_is_null_and_not_an_empty_string() {
        let raw = curl_version_info(0);
        // SAFETY: as above.
        let got = unsafe { &*raw };
        let want = curl_rs_lib::version_info();

        for (name, pointer, expected) in [
            ("libz_version", got.libz_version, want.libz_version),
            ("ares", got.ares, want.ares),
            ("libidn", got.libidn, want.libidn),
            ("hyper_version", got.hyper_version, want.hyper_version),
            ("gsasl_version", got.gsasl_version, want.gsasl_version),
            ("rtmp_version", got.rtmp_version, want.rtmp_version),
        ] {
            match expected {
                None => assert!(pointer.is_null(), "{name} must be NULL"),
                Some(value) => assert_eq!(text(pointer), value, "{name}"),
            }
        }
    }

    /// The pointer is stable, which is what makes it safe for a consumer to
    /// cache -- and what C's `static` guarantees.
    #[test]
    fn the_report_pointer_is_the_same_on_every_call() {
        assert_eq!(curl_version_info(0), curl_version_info(11));
    }

    /// The returned pointer must be genuinely WRITABLE, because C's is.
    #[test]
    fn the_report_pointer_is_writable_as_the_c_signature_promises() {
        let raw = curl_version_info(0);
        assert!(!raw.is_null());

        // SAFETY: `raw` addresses the single leaked `curl_version_info_data`
        // built by `build_report`. The allocation is immortal, so the reference
        // cannot dangle, and this test is the only writer -- no other test
        // mutates the report, and `age` is restored before this one returns.
        let report = unsafe { &mut *raw };

        let original = report.age;
        // A value no real report uses, so a stale read would be obvious.
        report.age = 0x5A5A;
        assert_eq!(
            report.age, 0x5A5A,
            "a write through the returned pointer must be observable, which is \
             what C's mutable static permits and what a shared-reference cast \
             cannot soundly provide"
        );

        // Restored so the process-wide report stays truthful for every other
        // test in this module, whatever order the harness runs them in.
        report.age = original;
        assert_eq!(report.age, original);
    }

    /// Truncation at an interior NUL is the documented behaviour of the helper,
    /// asserted so the claim is executable. No string this module passes can
    /// contain one, which is why it is tested through the helper directly.
    #[test]
    fn the_string_helper_truncates_at_an_interior_nul() {
        let got = immortal_c_string("visible\0hidden");
        assert_eq!(text(got), "visible");
    }

    // The push-header pair.

    #[test]
    fn a_null_push_handle_answers_null() {
        let name = c_str("content-type");
        // SAFETY: null is explicitly permitted for both parameters.
        unsafe {
            assert!(curl_pushheader_bynum(ptr::null_mut(), 0).is_null());
            assert!(curl_pushheader_byname(ptr::null_mut(), name.as_ptr())
                .is_null());
            assert!(
                curl_pushheader_byname(ptr::null_mut(), ptr::null()).is_null()
            );
        }
    }

    /// A pointer this library never issued answers NULL, which is what C's
    /// `GOOD_EASY_HANDLE` guard does for rubbish input.
    #[test]
    fn an_unrecognised_push_handle_answers_null() {
        // A plainly bogus address, never dereferenced -- `promised_fields`
        // recognises nothing, which is the whole point of the test.
        let bogus = 0x1000_usize as *mut curl_pushheaders;
        let name = c_str("content-type");
        // SAFETY: the pointer is never dereferenced; `promised_fields` performs
        // no read, as its documentation states and as this asserts.
        unsafe {
            assert!(curl_pushheader_bynum(bogus, 0).is_null());
            assert!(curl_pushheader_byname(bogus, name.as_ptr()).is_null());
        }
    }

    /// An adopted but empty promise answers NULL for every query, and the bound
    /// is the engine's.
    #[test]
    fn an_empty_promise_answers_null() {
        let mut session = PushSession::adopt(PushHeaders::new());
        assert!(session.bynum(0).is_null());
        assert!(session.bynum(usize::MAX).is_null());
        assert!(session.byname(b"content-type").is_null());
        assert!(session.byname(b"").is_null());
    }

    /// `locate` recovers the entry and offset a borrowed tail came from, which
    /// is what lets `byname` answer with the same offset into its own
    /// NUL-terminated copy without restating the engine's name grammar.
    #[test]
    fn locate_recovers_the_entry_and_offset_of_a_borrowed_tail() {
        let owned: Vec<Vec<u8>> = vec![
            b":status:200".to_vec(),
            b"content-type:text/html".to_vec(),
            b"x:".to_vec(),
        ];
        let entries: Vec<&[u8]> =
            owned.iter().map(Vec::as_slice).collect::<Vec<_>>();

        // The tail `by_name(b"content-type")` would return: everything past
        // the colon at offset 12.
        let tail = &entries[1][13..];
        assert_eq!(locate(&entries, tail), Some((1, 13)));
        assert_eq!(&entries[1][13..], b"text/html");

        // A pseudo-field, whose leading colon the grammar allows.
        let pseudo = &entries[0][8..];
        assert_eq!(locate(&entries, pseudo), Some((0, 8)));

        // An EMPTY tail, which is what a field with no value produces. It sits
        // one past the end of its entry, and the inclusive upper bound finds it.
        let empty = &entries[2][2..];
        assert!(empty.is_empty());
        assert_eq!(locate(&entries, empty), Some((2, 2)));

        // A slice from somewhere else belongs to no entry.
        let stranger = b"text/html";
        assert_eq!(locate(&entries, &stranger[..]), None);
        assert_eq!(locate(&[], tail), None);
    }

    // The header API pair.

    /// Every mask the five `CURLH_*` bits can form, plus the invalid ones.
    const ORIGIN_MASK: c_uint =
        CURLH_HEADER | CURLH_TRAILER | CURLH_CONNECT | CURLH_1XX | CURLH_PSEUDO;

    /// Calls `curl_easy_header` with a live out-parameter and reports both the
    /// code and whether the out-parameter was touched.
    fn lookup(
        easy: *mut CURL,
        name: Option<&CString>,
        index: usize,
        origin: c_uint,
        request: c_int,
    ) -> (CURLHcode, bool) {
        let mut out: *mut curl_header = 0x1_usize as *mut curl_header;
        let name = name.map_or(ptr::null(), |owned| owned.as_ptr());
        // SAFETY: `easy` is only ever null or a deliberately bogus address that
        // nothing dereferences, `name` is null or a live literal, and `out` is
        // a live writable slot.
        let code = unsafe {
            curl_easy_header(easy, name, index, origin, request, &mut out)
        };
        (code, out != (0x1_usize as *mut curl_header))
    }

    /// Which C branch this build is, asserted rather than assumed, because
    /// every expectation below follows from it.
    #[test]
    fn this_build_is_the_not_built_in_branch_of_both_c_files() {
        // Asserted through the engine's markers rather than on the constants
        // themselves. Two reasons, and the second is the important one:
        // `assert!` on a `const` operand is a constant expression that
        // `clippy::assertions_on_constants` rejects under `-D warnings`, and
        // -- more to the point -- asserting the DERIVATION is what makes these
        // constants flip on their own when the layers land, rather than
        // needing to be remembered.
        assert!(
            !curl_rs_lib::version::ENGINE_HEADERS.is_present(),
            "nothing fills a header store, so `lib/headers.c:365-394` applies"
        );
        assert!(
            !curl_rs_lib::version::supports_http2(),
            "there is no HTTP/2 layer, so `lib/http2.c:2993-3011` applies"
        );
        assert_eq!(
            HEADER_API_IS_BUILT_IN,
            curl_rs_lib::version::ENGINE_HEADERS.is_present()
        );
        assert_eq!(
            PUSH_API_IS_BUILT_IN,
            curl_rs_lib::version::supports_http2()
        );

        // The store itself IS written, and the distinction matters: this is an
        // inert capability, not an unwritten one.
        assert!(curl_rs_lib::version::ENGINE_HEADERS.is_written());
    }

    /// `lib/headers.c:365-381` returns `CURLHE_NOT_BUILT_IN` for every input,
    /// having cast all six parameters to void. Reproduced argument for
    /// argument, including the ones the built-in branch rejects differently.
    #[test]
    fn the_not_built_in_branch_answers_every_input_the_same_way() {
        let name = c_str("content-type");
        let easy = 0x1000_usize as *mut CURL;
        let want = CURLHcode::CURLHE_NOT_BUILT_IN;

        for (label, handle, named, index, origin, request) in [
            ("a well-formed query", easy, true, 0usize, CURLH_HEADER, -1),
            (
                "a null easy handle",
                ptr::null_mut(),
                true,
                0,
                CURLH_HEADER,
                0,
            ),
            ("a null name", easy, false, 0, CURLH_HEADER, 0),
            ("origin of zero", easy, true, 0, 0, 0),
            ("origin above the mask", easy, true, 0, ORIGIN_MASK + 1, 0),
            ("the reserved bit as an origin", easy, true, 0, 1 << 27, 0),
            ("request below -1", easy, true, 0, CURLH_HEADER, -2),
            (
                "a request above the current one",
                easy,
                true,
                0,
                CURLH_HEADER,
                7,
            ),
            ("an index past everything", easy, true, 99, ORIGIN_MASK, -1),
        ] {
            let owned = if named { Some(&name) } else { None };
            let (code, touched) = lookup(handle, owned, index, origin, request);
            assert_eq!(code, want, "{label}");
            assert!(!touched, "{label}: *hout is never written");
        }

        // C's branch does not test `hout` either, and does not need to: it
        // never writes through it.
        // SAFETY: a null `hout` is never dereferenced on this path.
        let code = unsafe {
            curl_easy_header(
                easy,
                name.as_ptr(),
                0,
                CURLH_HEADER,
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(code, want, "a null hout");

        // The value is the header family's own, numbered 7 (`header.h:60`),
        // and is distinct from the null-argument answer the built-in branch
        // uses -- which is the whole reason this correction was worth making.
        assert_eq!(want.as_c_int(), 7);
        assert_ne!(want, BAD_HEADER_ARGUMENT);
        assert_eq!(
            CURLHcode::CURLHE_BAD_ARGUMENT,
            BAD_HEADER_ARGUMENT,
            "the header family's null answer is the shared constant, 6"
        );
    }

    /// The built-in branch's own validation order, exercised where it is
    /// reachable: directly on a [`HeaderState`], which is what
    /// `curl_easy_header` will call once an easy handle can be borrowed.
    ///
    /// This is the coverage the entry point can no longer carry, kept rather
    /// than dropped. `lib/headers.c:69-76` orders the argument tests before the
    /// emptiness test, so a malformed query is never masked by having no
    /// headers, and the emptiness test precedes the request test.
    ///
    /// The `CURLHE_NOHEADERS` expectations below are the measured answer of a
    /// real built-in build, not a reading of the source: a driver linked
    /// against a stock libcurl 8.14.1, given a genuine `curl_easy_init` handle
    /// and no transfer, returns 3 for exactly this query.
    #[test]
    fn the_built_in_branch_validates_before_it_reports_emptiness() {
        let mut state = HeaderState::new();

        for (label, origin, request) in [
            ("origin of zero", 0, 0),
            ("origin above the mask", ORIGIN_MASK + 1, 0),
            ("the reserved bit as an origin", 1 << 27, 0),
            ("request below -1", CURLH_HEADER, -2),
        ] {
            assert_eq!(
                state.header(b"content-type", 0, origin, request),
                Err(CURLHcode::CURLHE_BAD_ARGUMENT),
                "{label}"
            );
        }

        for origin in [
            CURLH_HEADER,
            CURLH_TRAILER,
            CURLH_CONNECT,
            CURLH_1XX,
            CURLH_PSEUDO,
            ORIGIN_MASK,
        ] {
            assert_eq!(
                state.header(b"content-type", 0, origin, -1),
                Err(CURLHcode::CURLHE_NOHEADERS),
                "origin {origin:#x}"
            );
        }

        // A request above the current one still reports NOHEADERS rather than
        // NOREQUEST, because emptiness is tested first.
        assert_eq!(
            state.header(b"content-type", 0, CURLH_HEADER, 7),
            Err(CURLHcode::CURLHE_NOHEADERS)
        );
    }

    /// An empty store cannot match, whatever it is asked -- the property the
    /// built-in branch's `CURLHE_NOHEADERS` rests on.
    #[test]
    fn the_empty_store_never_succeeds() {
        let store = HeaderStore::new();
        assert!(store.is_empty());
        assert_eq!(store.count(), 0);
        for origin in [CURLH_HEADER, ORIGIN_MASK] {
            for request in [-1, 0, 1] {
                for index in [0usize, 1, 99] {
                    assert!(
                        store
                            .header(b"any", index, origin, request, 0)
                            .is_err(),
                        "an empty store cannot match"
                    );
                    assert!(
                        store.next_header(origin, request, 0, None).is_none(),
                        "an empty store has nothing to step to"
                    );
                }
            }
        }
    }

    #[test]
    fn nextheader_answers_null_and_validates_almost_nothing() {
        let easy = 0x1000_usize as *mut CURL;
        let start: *mut curl_header = ptr::null_mut();
        let null_handle: *mut CURL = ptr::null_mut();
        // SAFETY: `easy` is a bogus address nothing dereferences, and `prev` is
        // null throughout.
        unsafe {
            assert!(curl_easy_nextheader(null_handle, CURLH_HEADER, 0, start)
                .is_null());
            // An origin of 0 is accepted here where the built-in
            // `curl_easy_header` rejects it, because `lib/headers.c:121-179`
            // performs no validation at all. It simply matches nothing. The
            // not-built-in branch (`:383-393`) answers NULL for the same input
            // without looking, so both branches agree.
            assert!(curl_easy_nextheader(easy, 0, 0, start).is_null());
            assert!(
                curl_easy_nextheader(easy, ORIGIN_MASK, -1, start).is_null()
            );
        }
    }

    /// A caller-supplied `prev` is read for its anchor and never followed, so
    /// even a deliberately corrupt one only ends iteration.
    #[test]
    fn a_corrupt_anchor_ends_iteration_rather_than_following_a_pointer() {
        let easy = 0x1000_usize as *mut CURL;
        let mut prev = HeaderSlot::new();
        prev.out.anchor = 0xdead_beef_usize as *mut c_void;
        // SAFETY: `prev.out` is a live readable `curl_header`; only its
        // `anchor` scalar is read.
        let stepped = unsafe {
            curl_easy_nextheader(easy, CURLH_HEADER, 0, &mut prev.out)
        };
        assert!(stepped.is_null());

        // The same value decodes to a cursor whose generation no live store
        // shares, which is what makes the walk end instead of misreading.
        // SAFETY: as above.
        let cursor = unsafe { resume_from(&mut prev.out) }
            .expect("a non-null prev always yields a cursor");
        assert_eq!(cursor, HeaderCursor::from_raw(0xdead_beef));

        // A null anchor needs no special case: generation 0 matches no store.
        prev.out.anchor = ptr::null_mut();
        // SAFETY: as above.
        let cursor = unsafe { resume_from(&mut prev.out) }
            .expect("a non-null prev always yields a cursor");
        assert_eq!(
            cursor.generation(),
            0,
            "no store ever reaches generation 0"
        );

        // SAFETY: null is explicitly permitted.
        assert!(unsafe { resume_from(ptr::null_mut()) }.is_none());
    }

    // The projection into `struct curl_header`, and the two slots.

    #[test]
    fn the_projection_assigns_every_field() {
        let cursor = HeaderCursor::from_raw(0x0000_0003_0000_0002);
        let view = HeaderView {
            name: b"Content-Type",
            value: b"text/html; charset=utf-8",
            amount: 3,
            index: 1,
            origin: CURLH_HEADER | RESERVED,
            anchor: cursor,
        };

        let mut slot = HeaderSlot::new();
        let record = slot.fill(view);
        assert!(!record.is_null());

        // SAFETY: `record` addresses `slot.out`, which outlives this borrow,
        // and both string fields address `slot`'s own buffers.
        let got = unsafe { &*record };
        assert_eq!(text(got.name), "Content-Type");
        assert_eq!(text(got.value), "text/html; charset=utf-8");
        assert_eq!(got.amount, 3);
        assert_eq!(got.index, 1);
        assert_eq!(
            got.origin & RESERVED,
            RESERVED,
            "lib/headers.c:46-50 ORs the reserved bit so == cannot be used"
        );
        assert_eq!(got.origin & ORIGIN_MASK, CURLH_HEADER);
        assert_eq!(got.anchor as usize, cursor.to_raw());
        assert_eq!(HeaderCursor::from_raw(got.anchor as usize), cursor);

        // Refilling reuses the same slot, exactly as C's `headerout[n]` does.
        let again = slot.fill(HeaderView {
            name: b"Server",
            value: b"test",
            amount: 1,
            index: 0,
            origin: CURLH_TRAILER | RESERVED,
            anchor: HeaderCursor::from_raw(1),
        });
        assert_eq!(record, again, "the slot address is stable");
        // SAFETY: as above.
        let got = unsafe { &*again };
        assert_eq!(text(got.name), "Server");
        assert_eq!(text(got.value), "test");
        assert_eq!(got.amount, 1);
    }

    /// An interior NUL cannot cross a `char *`, so it truncates -- which is
    /// where C already was, having stored the line as a C string.
    #[test]
    fn the_projection_truncates_at_an_interior_nul() {
        assert_eq!(c_bytes(b"visible\0hidden"), b"visible\0".to_vec());
        assert_eq!(c_bytes(b""), b"\0".to_vec());
        assert_eq!(c_bytes(b"plain"), b"plain\0".to_vec());
    }

    /// `curl_easy_header` fills `headerout[0]` and `curl_easy_nextheader` fills
    /// `headerout[1]`, so interleaving the two never clobbers either result.
    #[test]
    fn the_two_slots_are_distinct() {
        let mut state = HeaderState::new();
        let view = HeaderView {
            name: b"A",
            value: b"1",
            amount: 1,
            index: 0,
            origin: CURLH_HEADER | RESERVED,
            anchor: HeaderCursor::from_raw(1),
        };
        let lookup = state.lookup.fill(view);
        let walk = state.walk.fill(view);
        assert_ne!(
            lookup, walk,
            "lib/headers.c:114-116 and :176-178 write different slots"
        );

        // A fresh state has collected nothing and issued no request, so it
        // answers exactly as the empty-store path does.
        assert_eq!(state.cur_request, 0);
        assert_eq!(
            state.header(b"any", 0, CURLH_HEADER, -1),
            Err(CURLHcode::CURLHE_NOHEADERS)
        );
        assert!(state.next_header(CURLH_HEADER, -1, None).is_null());
    }

    /// The resolution seams report nothing, and that is the measured state of
    /// the tree rather than an omission. Both are asserted so the module
    /// documentation cannot drift away from the code.
    #[test]
    fn the_unlanded_layers_resolve_to_nothing() {
        // SAFETY: neither pointer is dereferenced -- which is precisely the
        // property being asserted.
        unsafe {
            assert!(header_state(ptr::null_mut()).is_none());
            assert!(header_state(0x1000_usize as *mut CURL).is_none());
            assert!(promised_fields(ptr::null_mut()).is_none());
            assert!(promised_fields(0x1000_usize as *mut curl_pushheaders)
                .is_none());
        }
    }
}
