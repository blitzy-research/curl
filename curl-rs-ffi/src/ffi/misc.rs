// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The standalone exported functions that belong to no larger family.
//!
//! | Symbol | Authority | Engine backing |
//! |--------|-----------|----------------|
//! | `curl_free`         | `lib/escape.c:189-192`     | [`super::memory`] |
//! | `curl_getdate`      | `lib/parsedate.c:561-575`  | `curl_rs_lib::getdate` |
//! | `curl_getenv`       | `lib/getenv.c:26-70`       | `std::env` |
//! | `curl_strequal`     | `lib/strequal.c:76-84`     | `curl_rs_lib::strequal` |
//! | `curl_strnequal`    | `lib/strequal.c:87-95`     | `curl_rs_lib::strnequal` |
//! | `curl_version`      | `lib/version.c:145`        | `curl_rs_lib::version` |
//! | `curl_version_info` | `lib/version.c:396`        | `curl_rs_lib::version_info` |
//!
//! Not one of these seven decides anything. Every behavioural question -- what
//! the banner says, which date formats parse, how case folding works, which
//! capabilities are advertised -- is answered by `curl-rs-lib`, and this file
//! marshals. That division is what keeps the ABI shim auditable in isolation
//! (specification 0.3.3, pattern P10) and is why the module has no tables of its
//! own.
//!
//! # Ownership at the boundary
//!
//! Three of the seven hand a pointer to the caller, and they do not agree about
//! who owns it. The distinction is part of the contract and getting it wrong
//! either leaks or double-frees:
//!
//! * `curl_getenv` returns a **caller-owned** buffer that must be released with
//!   `curl_free`. It is allocated through [`super::memory`] so that an
//!   application which replaced the allocator through `curl_global_init_mem`
//!   frees it with the same one that produced it.
//! * `curl_version` and `curl_version_info` return **immortal** storage the
//!   caller must not free. C uses function-level `static` buffers
//!   (`lib/version.c:147` declares `static char out[300]`); this module leaks a
//!   single allocation on first use, which has the same lifetime and the same
//!   once-per-process cost.
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
//! frozen signature (specification 0.8.1) and is reproduced rather than fixed:
//! narrowing the return type to `const` would break every consumer that assigns
//! it to a non-const variable. Reproducing it correctly means the returned
//! pointer must carry WRITE provenance, and a pointer obtained by casting a
//! shared reference does not, whatever the C prototype says. Since
//! `OnceLock::get_or_init` can only ever yield a `&T`, the value cannot live
//! inside the cell; `Box::into_raw` provides the write-capable pointer and the
//! cell holds its address. See [`curl_version_info`] for the full account,
//! including the earlier design this replaced.

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};
use core::ptr;
use std::ffi::{CStr, CString};
use std::sync::OnceLock;

use super::memory;
use super::panic_boundary::{guard, guard_ptr, guard_void};
use super::types::curl_version_info_data;

/// `time_t` on all four supported targets.
///
/// Every mandated target is 64-bit Unix with a signed 64-bit `time_t`
/// (specification 0.8.3 lists them; the reasoning is recorded in
/// `curl-rs-lib/src/util/parsedate.rs`), so the engine's `i64` and the C
/// `time_t` are the same type rather than merely the same width. 32-bit targets
/// are deliberately out of scope, so no narrowing case exists to handle.
type TimeT = i64;

// Immortal storage helpers.

/// Leaks a NUL-terminated copy of `text`, returning a pointer C may keep.
///
/// Called only from the two version accessors and only once per string per
/// process, so the leak is the intended lifetime and not an oversight: the C it
/// supersedes uses `static` buffers for exactly these strings.
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
///
/// Both `protocols` and `feature_names` are declared this way, and the
/// authority's comments say so explicitly: "protocols is terminated by an entry
/// with a NULL protoname" and "feature_names is terminated by an entry with a
/// NULL feature name" (`include/curl/curl.h:3119`, `:3169`). A consumer walks
/// until it sees the NULL, so the terminator is not optional.
fn immortal_c_array(items: &[&'static str]) -> *const *const c_char {
    let mut pointers: Vec<*const c_char> =
        items.iter().map(|item| immortal_c_string(item)).collect();
    pointers.push(ptr::null());
    let leaked: &'static mut [*const c_char] = Vec::leak(pointers);
    leaked.as_ptr()
}

/// An `Option<&str>` as either a C string or NULL.
///
/// Most of `curl_version_info_data`'s string fields are documented as "might be
/// NULL", and in this build several always are, because the library they name is
/// not linked. NULL is the contract's way of saying "not available" and is what
/// a C consumer tests for, so `None` becomes a null pointer rather than an
/// empty string.
fn immortal_c_option(text: Option<&'static str>) -> *const c_char {
    match text {
        Some(value) => immortal_c_string(value),
        None => ptr::null(),
    }
}

// curl_free

/// Releases a buffer libcurl allocated for the caller.
///
/// Supersedes `curl_free` (`lib/escape.c:189-192`), which is a one-line forward
/// to the replaceable `free` hook. A null argument is a no-op, as it is in C.
///
/// This exists because libcurl may have been built against, or configured with,
/// a different allocator than the application's; a buffer from
/// `curl_easy_escape` or `curl_getenv` must go back to the allocator that
/// produced it.
///
/// # Safety
///
/// `p` must be either null or a pointer previously returned by a libcurl
/// function documented as requiring `curl_free`, and must not be used
/// afterwards.
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
/// Supersedes `curl_getdate` (`lib/parsedate.c:561-575`). Returns `-1` when the
/// string cannot be converted.
///
/// The second parameter is, in the authority's own words, a "legacy argument
/// from the past that we ignore" (`lib/parsedate.c:565`). It is still part of
/// the frozen signature, so it is still accepted, and it is still ignored --
/// including when it is non-null.
///
/// # Why `-1` is unambiguous
///
/// `-1` is both the failure sentinel and a representable instant, one second
/// before the epoch. The engine resolves the collision the way C does: a
/// successful parse landing on `-1` is incremented to `0`, so no successful
/// parse ever returns `-1` and the sentinel is unambiguous. That decision lives
/// in `curl-rs-lib` beside the parser, which is why this function can map
/// `None` to `-1` with a bare `unwrap_or`.
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
        if p.is_null() {
            // C would pass NULL to `parsedate`, which dereferences it. There
            // is no defined result to preserve, and `-1` is the documented
            // failure answer every correct caller already handles.
            return -1;
        }
        // SAFETY: the caller guarantees `p` addresses a NUL-terminated string.
        let text = unsafe { CStr::from_ptr(p) };
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
/// distinguish the two cases through this function and never could.
///
/// The result must be released with [`curl_free`].
///
/// # Safety
///
/// `variable` must be either null or a pointer to a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn curl_getenv(variable: *const c_char) -> *mut c_char {
    guard_ptr(|| {
        if variable.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller guarantees `variable` addresses a NUL-terminated
        // string.
        let name = unsafe { CStr::from_ptr(variable) };
        let Ok(name) = name.to_str() else {
            // A non-UTF-8 name cannot be looked up through `std::env`, and no
            // such variable name is portable, so absent is the honest answer.
            return ptr::null_mut();
        };
        let Some(value) = std::env::var_os(name) else {
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

// curl_strequal / curl_strnequal

/// Case-insensitive comparison of two whole strings.
///
/// Supersedes `curl_strequal` (`lib/strequal.c:76-84`). Returns non-zero when
/// the strings match, zero otherwise. Two null pointers compare equal.
///
/// The comparison itself, including the folding rule and the null-pointer
/// contract, lives in `curl-rs-lib`; this function converts pointers to
/// `Option<&CStr>` and a `bool` to a `c_int`.
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

/// A possibly-null C string as an `Option<&CStr>`.
///
/// The one place in this module that turns C's "NULL means absent" convention
/// into Rust's, so the two comparison functions above contain no null tests of
/// their own.
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

// curl_version

/// Returns the version banner.
///
/// Supersedes `curl_version` (`lib/version.c:145`), which composes the string
/// into a `static char out[300]`. The composition -- which parts appear, in
/// which order, with which separators -- is `curl-rs-lib`'s, because the test
/// harness parses this string to decide which fixtures to run
/// (specification 0.6.5) and so it is a machine-read contract rather than
/// display text.
///
/// The returned pointer addresses immortal storage. The caller must not free
/// it, and C's `static` buffer means the caller never could.
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
/// Supersedes `curl_version_info` (`lib/version.c:396`). The `CURLversion`
/// argument is accepted and ignored, exactly as C ignores it -- `(void)stamp;`
/// at `lib/version.c:419` -- because the struct only ever grew, so an older
/// consumer simply reads fewer fields and `age` tells it how many are valid.
///
/// The returned pointer addresses immortal storage the caller must not free.
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
/// Field for field, in the authority's order. Every value comes from
/// `curl_rs_lib::version_info()`; nothing is decided here.
///
/// # Where the C widths are put on
///
/// The engine reports fixed-width Rust integers -- `u32`, `i32`, `i64` -- and
/// this function is where they become `c_uint`, `c_int` and `c_long`. That
/// split is deliberate: the engine must not carry native-width
/// assumptions, so `core::ffi` types appear only in the crate that owns the C
/// ABI. The casts are written out rather than left to inference even though the
/// types coincide on all four targets of specification 0.8.3, because a silent
/// coincidence is not a boundary -- naming the conversion is what makes this
/// the one place a width is asserted, and curl's ABI fixes these widths in the
/// header regardless of what any compiler would have chosen.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn the_banner_is_the_engines_and_is_stable_across_calls() {
        let first = curl_version();
        let second = curl_version();
        assert_eq!(first, second, "the buffer must be the same one every time");
        assert_eq!(text(first), curl_rs_lib::version());
    }

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
    ///
    /// This is the assertion that distinguishes the current implementation from
    /// the one it replaced. A `*mut` produced by casting a shared reference --
    /// which is all `OnceLock::get_or_init` can ever yield -- compiles and even
    /// appears to work, while being undefined behaviour the moment a caller
    /// writes through it. Leaking the allocation with `Box::into_raw` and
    /// keeping only its address gives a pointer with write provenance, and this
    /// test exercises exactly that: it writes a field, reads it back, and
    /// restores it.
    ///
    /// Run under `cargo miri test`, this fails loudly against the old design
    /// and passes against this one, which is what makes it a regression guard
    /// rather than a restatement.
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

    fn c_str(text: &str) -> CString {
        CString::new(text).expect("test literals contain no NUL")
    }
}
