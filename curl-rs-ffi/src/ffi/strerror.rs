// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The four exported result-code-to-text functions -- supersedes the public
//! half of `lib/strerror.c`.
//!
//! | Symbol | Authority | Family |
//! |--------|-----------|--------|
//! | `curl_easy_strerror`  | `lib/strerror.c:34`  | `CURLcode`   |
//! | `curl_multi_strerror` | `lib/strerror.c:326` | `CURLMcode`  |
//! | `curl_share_strerror` | `lib/strerror.c:385` | `CURLSHcode` |
//! | `curl_url_strerror`   | `lib/strerror.c:420` | `CURLUcode`  |
//!
//! # Where the text comes from, and why not from here
//!
//! Not one message literal appears in this file. Each function is three lines:
//! call the engine's `message_for_c` for that family, and return the pointer.
//! The 165 message strings live in `curl-rs-lib/src/error.rs` beside the
//! discriminants they belong to, because a second copy in the ABI shim would
//! be a mirrored source of truth, which is the defect this layout avoids.
//! The engine appends the NUL at
//! compile time with `concat!`, so the pointer this file returns addresses a
//! `&'static CStr` that costs nothing to produce and can never disagree with
//! what a Rust caller sees.
//!
//! # The four fallbacks are not the same string
//!
//! This is the detail a shared "unknown" constant would get wrong, and it was
//! settled by running the frozen `libcurl.so.4.8.0` over every input from -2
//! to past each family's bound:
//!
//! ```text
//! curl_easy_strerror (-2)  -> "Unknown error"
//! curl_multi_strerror(-2)  -> "Unknown error"
//! curl_share_strerror(-2)  -> "CURLSHcode unknown"
//! curl_url_strerror  (-2)  -> "CURLUcode unknown"
//! ```
//!
//! The same sweep established what happens at the three kinds of non-value a
//! consumer can legitimately hold:
//!
//! * The 15 retired `CURLE_OBSOLETE*` placeholders reach the C switch's
//!   `default:` arm and so report the fallback, not a message. Measured at 20,
//!   24, 29, 32, 34, 40, 41, 44, 46, 50, 51, 57, 62, 75 and 76.
//! * `CURL_LAST` (102), `CURLM_LAST` (13), `CURLSHE_LAST` (6) and
//!   `CURLUE_LAST` (32) are bounds rather than values; each is a bare `break`
//!   in the C and reports the fallback.
//! * Anything outside the enumeration reports the fallback.
//!
//! All three cases are one rule in the engine -- `from_i32` returns `None`, so
//! `message_for_c` yields `UNKNOWN_MESSAGE_C` -- and the whole 177-row sweep
//! is asserted against this crate by the differential test at the foot of this
//! file.
//!
//! # Signature shape
//!
//! The frozen prototypes take the enumerated type by value, and the generated
//! header spells them from `codes.rs`:
//!
//! ```c
//! CURL_EXTERN const char *curl_easy_strerror(CURLcode);
//! CURL_EXTERN const char *curl_multi_strerror(CURLMcode);
//! CURL_EXTERN const char *curl_share_strerror(CURLSHcode);
//! CURL_EXTERN const char *curl_url_strerror(CURLUcode);
//! ```
//!
//! Rust takes each parameter as the `#[repr(C)]` enum from
//! [`super::codes`] -- which is what makes the generated prototype name the
//! enumerated type rather than a bare `int` -- and immediately converts it to
//! an `i32` for the lookup. That conversion is not a widening hack: a C caller
//! may legally pass ANY integer of the enum's underlying type, including one
//! with no enumerator, and passing such a value to a Rust `enum` parameter
//! would be an invalid value for that type. The parameter is therefore
//! declared as `c_int` on the Rust side and the enum name is restored in the
//! header by the partition table, which is the same technique the option
//! setters use for `CURLoption`.
//!
//! # Panic containment
//!
//! Every entry point runs inside [`super::panic_boundary::guard_const_ptr`].
//! None of these bodies can panic -- the lookup is a `match` over a const
//! table -- but the guard is applied uniformly rather than case by case,
//! because unwinding across the C ABI is undefined behaviour and "this one
//! cannot panic" is an argument that stops being true the moment the body
//! changes.

use core::ffi::{c_char, c_int};

use curl_rs_lib::{CURLMcode, CURLSHcode, CURLUcode, CURLcode};

use super::panic_boundary::guard_const_ptr;

/// Returns a string describing a `CURLcode`.
///
/// Supersedes `curl_easy_strerror` (`lib/strerror.c:34`).
///
/// The returned pointer addresses immortal static text: the caller must not
/// free it and it stays valid for the life of the process, which is what the
/// C contract promises.
#[no_mangle]
pub extern "C" fn curl_easy_strerror(error: c_int) -> *const c_char {
    guard_const_ptr(|| CURLcode::message_for_c(error).as_ptr())
}

/// Returns a string describing a `CURLMcode`.
///
/// Supersedes `curl_multi_strerror` (`lib/strerror.c:326`).
#[no_mangle]
pub extern "C" fn curl_multi_strerror(error: c_int) -> *const c_char {
    guard_const_ptr(|| CURLMcode::message_for_c(error).as_ptr())
}

/// Returns a string describing a `CURLSHcode`.
///
/// Supersedes `curl_share_strerror` (`lib/strerror.c:385`). Note the fallback
/// text differs from the two above: `"CURLSHcode unknown"`.
#[no_mangle]
pub extern "C" fn curl_share_strerror(error: c_int) -> *const c_char {
    guard_const_ptr(|| CURLSHcode::message_for_c(error).as_ptr())
}

/// Returns a string describing a `CURLUcode`.
///
/// Supersedes `curl_url_strerror` (`lib/strerror.c:420`). Its fallback is
/// `"CURLUcode unknown"`.
#[no_mangle]
pub extern "C" fn curl_url_strerror(error: c_int) -> *const c_char {
    guard_const_ptr(|| CURLUcode::message_for_c(error).as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    /// Reads back what a C caller would see.
    fn text(ptr: *const c_char) -> &'static str {
        assert!(!ptr.is_null(), "these functions never return NULL");
        // SAFETY: every one of the four functions returns the pointer of a
        // `&'static CStr` produced by `concat!` at compile time, so the target
        // is NUL-terminated, immortal, and immutable.
        unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .expect("the message tables are ASCII")
    }

    /// The whole 177-row transcript of the frozen `libcurl.so.4.8.0`, produced
    /// by a C program that called each of the four functions over every input
    /// from -2 up past each family's bound. Rows are `family value message`,
    /// families `E`/`M`/`S`/`U` in the order the table at the top of this file
    /// lists them.
    ///
    /// This is an ORACLE. Nothing in it was written by hand, so a divergence
    /// means this crate disagrees with the shipped C rather than with somebody's
    /// reading of `lib/strerror.c`.
    const C_ORACLE: &str = include_str!("strerror_oracle.txt");

    #[test]
    fn every_row_matches_the_frozen_c_library() {
        let mut rows = 0usize;
        for line in C_ORACLE.lines() {
            if line.is_empty() {
                continue;
            }
            let (family, rest) = line.split_at(1);
            let mut parts = rest.trim_start().splitn(2, '\t');
            let value: c_int = parts
                .next()
                .expect("each row starts with a value")
                .parse()
                .expect("the value column is an integer");
            let expected = parts.next().expect("each row carries a message");
            let got = match family {
                "E" => text(curl_easy_strerror(value)),
                "M" => text(curl_multi_strerror(value)),
                "S" => text(curl_share_strerror(value)),
                "U" => text(curl_url_strerror(value)),
                other => panic!("unknown family column {other:?}"),
            };
            assert_eq!(
                got, expected,
                "{family} {value}: C said {expected:?} and this says {got:?}"
            );
            rows += 1;
        }
        assert_eq!(rows, 177, "the oracle transcript must be complete");
    }

    /// The four fallbacks are two distinct strings, and pairing them wrongly is
    /// the mistake a single shared constant would make. Asserted directly so
    /// the intent survives even if the oracle file is ever regenerated.
    #[test]
    fn the_four_fallbacks_are_not_interchangeable() {
        assert_eq!(text(curl_easy_strerror(-2)), "Unknown error");
        assert_eq!(text(curl_multi_strerror(-2)), "Unknown error");
        assert_eq!(text(curl_share_strerror(-2)), "CURLSHcode unknown");
        assert_eq!(text(curl_url_strerror(-2)), "CURLUcode unknown");
    }

    /// The 15 retired placeholders and the four family bounds report the
    /// fallback, not a message.
    #[test]
    fn the_retired_placeholders_and_the_bounds_report_the_fallback() {
        for obsolete in
            [20, 24, 29, 32, 34, 40, 41, 44, 46, 50, 51, 57, 62, 75, 76]
        {
            assert_eq!(
                text(curl_easy_strerror(obsolete)),
                "Unknown error",
                "CURLE_OBSOLETE{obsolete} must not carry a message"
            );
        }
        assert_eq!(text(curl_easy_strerror(102)), "Unknown error", "CURL_LAST");
        assert_eq!(
            text(curl_multi_strerror(13)),
            "Unknown error",
            "CURLM_LAST"
        );
        assert_eq!(
            text(curl_share_strerror(6)),
            "CURLSHcode unknown",
            "CURLSHE_LAST"
        );
        assert_eq!(
            text(curl_url_strerror(32)),
            "CURLUcode unknown",
            "CURLUE_LAST"
        );
    }

    /// A sanity anchor on the success codes, which are the values a consumer
    /// sees most and the only ones every family agrees about.
    #[test]
    fn zero_is_no_error_in_all_four_families() {
        assert_eq!(text(curl_easy_strerror(0)), "No error");
        assert_eq!(text(curl_multi_strerror(0)), "No error");
        assert_eq!(text(curl_share_strerror(0)), "No error");
        assert_eq!(text(curl_url_strerror(0)), "No error");
    }
}
