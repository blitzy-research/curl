//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// This software is licensed as described in the file COPYING, which
// you should have received as part of this distribution. The terms
// are also available at https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is
// furnished to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl
//
//***************************************************************************

// FOUR CONVENTIONS OF THIS DIRECTORY, APPLIED HERE.
//
// 1. The banner above is the one measured at `lib/llist.c:1-23`,
//    rendered as Rust line comments with the C block-comment decorations
//    stripped. It is byte-identical to `super`'s and to every other child of
//    this directory except `inet.rs`, whose C originals carry a different
//    licence. The licence-identifier line is line 21 and is verbatim; it is
//    the only place in this file where that spelling appears, which is what
//    `reuse lint` needs (`.github/workflows/checksrc.yml`).
//
// 2. The gate that enforces it lives in `curl-rs-lib/src/lib.rs` (`mod
//    source_policy`), and the reason is in `super`: an attribute on a module
//    root would silence the NEXT item somebody adds. Exactly one item here
//    carries one -- `getdate_capped`, whose consumers (the cookie jar, HSTS
//    and Alt-Svc stores) are later code.
//
// 3. No level for the `unsafe_code` lint is set here, at any level. The crate
//    root carries `#![deny(unsafe_code)]` and grants exactly one exemption, on
//    `mod ffi`; this file is not it, contains no exemption, and contains
//    nothing the compiler would need one for. The C original walks a
//    NUL-terminated string and reads `date[-1]` BEHIND its own cursor; both
//    become slice reads with an explicit index test.
//
// 4. Byte classification and number parsing are BORROWED, not re-derived.
//    `lib/curl_ctype.h`'s ASCII-only predicates and `curlx_str_number` live in
//    `strparse.rs`, and curl's locale-independent case fold lives in
//    `strcase.rs`. This file calls all three rather than reaching for the
//    standard library's near-equivalents, because the accepted set of a date
//    header is observable through an exported symbol and a second definition of
//    "is this a letter" is a second thing to keep in step. `strparse.rs`'s own
//    documentation names `parsedate` as one of the four modules it exists to
//    serve, which is why it precedes this one in the build order.

//! Date parsing -- supersedes `lib/parsedate.c` and `lib/parsedate.h`.
//!
//! # Why this module is `pub` when its parent is not
//!
//! `crate::util` is `pub(crate)`: private by ENFORCEMENT rather than by the
//! `Curl_` naming convention the C tree relied on. This file nevertheless
//! declares one `pub` item, because `curl_getdate` is one of the 100 symbols
//! `lib/libcurl.def` exports, and the crate root re-exports [`getdate`] so
//! that `curl-rs-ffi` can reach it. That is the standard private-module /
//! public-re-export idiom, and `util/mod.rs` records `parsedate ->
//! curl_getdate` as one of the places it applies.
//!
//! The re-export exists because the facade needs a date parser, the parser
//! lives here, and DUPLICATING it in the adapter would put engine logic in the
//! C ABI shim. So the boundary is drawn here instead: this module owns every
//! parsing decision including the two quirks of `curl_getdate`'s contract, and
//! the adapter is left with nothing but marshalling a `*const c_char` into a
//! `&str` and an `Option` into a `time_t`.
//!
//! # The contract being reproduced
//!
//! `lib/parsedate.c:561-575` defines `curl_getdate`. It has three properties
//! that are easy to miss and impossible to guess:
//!
//! * Its SECOND PARAMETER IS IGNORED. The C says so at `:565` -- *"legacy
//!   argument from the past that we ignore"*. The declared signature keeps it
//!   because `include/curl/curl.h` declares it, so the adapter accepts and
//!   discards it; nothing on this side of the boundary has a parameter for it.
//! * When the parsed value happens to be exactly `-1`, C INCREMENTS it to `0`
//!   (`:568-570`) rather than returning `-1`, because `-1` is also its failure
//!   sentinel. That single second of 1969-12-31 23:59:59 UTC is therefore
//!   reported as the epoch. The quirk belongs to the contract, so it lives in
//!   [`getdate`] and not in the adapter.
//! * EVERY non-`PARSEDATE_OK` outcome returns `-1` (`:573-574`), overflow
//!   included, so through this entry point a far-future date is
//!   indistinguishable from a parse failure.
//!
//! # Formats accepted
//!
//! Reproduced from the summary comment at `lib/parsedate.c:29-81`, which is
//! the authority for what *"every format curl accepts"* means. Every example
//! below is a test case at the foot of this file.
//!
//! ```text
//!   RFC 2616 3.3.1
//!
//!   Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
//!   Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
//!   Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format
//!
//!   we support dates without week day name:
//!
//!   06 Nov 1994 08:49:37 GMT
//!   06-Nov-94 08:49:37 GMT
//!   Nov  6 08:49:37 1994
//!
//!   without the time zone:
//!
//!   06 Nov 1994 08:49:37
//!   06-Nov-94 08:49:37
//!
//!   weird order:
//!
//!   1994 Nov 6 08:49:37  (GNU date fails)
//!   GMT 08:49:37 06-Nov-94 Sunday
//!   94 6 Nov 08:49:37    (GNU date fails)
//!
//!   time left out:
//!
//!   1994 Nov 6
//!   06-Nov-94
//!   Sun Nov 6 94
//!
//!   unusual separators:
//!
//!   1994.Nov.6
//!   Sun/Nov/6/94/GMT
//!
//!   commonly used time zone names:
//!
//!   Sun, 06 Nov 1994 08:49:37 CET
//!   06 Nov 1994 08:49:37 EST
//!
//!   time zones specified using RFC822 style:
//!
//!   Sun, 12 Sep 2004 15:05:58 -0700
//!   Sat, 11 Sep 2004 21:32:11 +0200
//!
//!   compact numerical date strings:
//!
//!   20040912 15:05:58 -0700
//!   20040911 +0200
//! ```
//!
//! # Byte-oriented, and why
//!
//! The C parser indexes bytes and relies on the NUL terminator; it never
//! validates encoding, and it must not, because a `Last-Modified` header may
//! carry any byte. The core, [`parsedate`], therefore takes `&[u8]` and reads
//! it through [`at`], which reports `0` past the end and so reproduces the
//! terminator without introducing a bounds-check divergence.
//!
//! [`getdate`] and [`getdate_capped`] take `&str` rather than `&[u8]`, and the
//! reason is a contract this file cannot change on its own: the signature is
//! pinned by a compile-time assertion in `version.rs` and consumed by
//! `curl-rs-ffi/src/ffi/misc.rs`, whose whole job is turning a
//! `*const c_char` into one. Byte-native callers inside this crate use
//! [`parsedate`] directly, which is why it is `pub(crate)` rather than
//! private.

use crate::util::strcase::ncasecompare;
use crate::util::strparse::{is_alnum, is_alpha, is_digit, str_number};

/// The abbreviated weekday names, **Monday first**.
///
/// `lib/parsedate.c:86-88` exports these as `Curl_wkday`, guarded at `:83-84`
/// by `!defined(CURL_DISABLE_PARSEDATE) || !defined(CURL_DISABLE_FTP) ||
/// !defined(CURL_DISABLE_FILE) || defined(USE_GNUTLS)` with the comment
/// *"These names are also used by FTP and FILE code"* at `:85`. That code
/// FORMATS dates with them as well as parsing them, so these bytes reach the
/// wire and the table is `pub(crate)` for `protocols/ftp` and
/// `protocols/file` rather than private to this file.
///
/// **Monday is index 0 and Sunday is index 6.** This is NOT the C `struct tm`
/// convention, where `tm_wday` numbers Sunday 0. Two weekday conventions
/// therefore coexist in this workspace -- `timeval.rs`'s calendar conversion
/// speaks the `tm_wday` one -- and each occurrence is labelled where it
/// appears so the two are never silently mixed.
#[rustfmt::skip]
pub(crate) const WKDAY: [&str; 7] = [
    "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun",
];

/// The abbreviated month names, January first.
///
/// `lib/parsedate.c:89-92`, exported as `Curl_month` under the same guard and
/// for the same reason: FTP directory listings and the `file://` scheme format
/// dates with them.
///
/// **Months are 0-based**: `Jan` is index 0, matching `tm_mon` and matching
/// every month value inside this file, including the `- 1` that
/// [`parsedate`]'s `YYYYMMDD` branch applies.
#[rustfmt::skip]
pub(crate) const MONTH: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The full weekday names, Monday first (`lib/parsedate.c:105-107`).
///
/// `static` in the C, so private here: no other translation unit formats with
/// them. Consulted only for names LONGER than three characters, which is what
/// lets `Sunday` and `Sun` both parse while `Sund` matches neither.
#[rustfmt::skip]
const WEEKDAY: [&str; 7] = [
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
    "Sunday",
];

/// One entry of the timezone-name table (`lib/parsedate.c:109-112`).
///
/// The C declares the name as `char name[5]`, which bounds every entry at four
/// characters plus a terminator. That declaration is precisely why [`checktz`]
/// can reject a token longer than four bytes without searching, and the
/// correspondence is asserted by test rather than trusted.
struct TzInfo {
    /// The name, upper case in the table, matched case-insensitively and by
    /// exact length.
    name: &'static str,
    /// Offset from GMT in **minutes**, positive west of Greenwich.
    ///
    /// [`checktz`] multiplies by 60 on the way out, so the table speaks
    /// minutes and every caller of `checktz` speaks seconds.
    offset: i32,
}

/// The daylight-savings adjustment applied to summer-time names.
///
/// `lib/parsedate.c:116` -- negative, and applied by ADDITION to a westward
/// offset, so `EDT` is `300 + (-60) = 240`.
const TDAYZONE: i32 = -60;

/// Days elapsed before the first of each month in a non-leap year.
#[rustfmt::skip]
const MONTH_DAYS_CUMULATIVE: [i64; 12] = [
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334,
];

/// Frequently used timezone names, carried over from the old getdate parser.
///
/// Two deliberate decisions of the C tree are preserved verbatim, because both
/// look like defects and neither is:
///
/// * **`J` is absent.** `lib/parsedate.c:176-177`: *"'J', Juliet is not used
///   as a timezone, to indicate the observer's local time."* The ladder runs
///   `A`..`I`, then skips straight to `K`.
/// * **The military signs diverge from RFC 822.** `:163-166`: *"RFC822 allowed
///   these, but (as noted in RFC 1123) had their signs wrong. Here we use the
///   correct signs to match actual military usage."*
#[rustfmt::skip]
#[allow(clippy::identity_op, clippy::neg_multiply)]
const TZ: [TzInfo; 69] = [
    TzInfo { name: "GMT",   offset:    0 }, // Greenwich Mean
    TzInfo { name: "UT",    offset:    0 }, // Universal Time
    TzInfo { name: "UTC",   offset:    0 }, // Universal (Coordinated)
    TzInfo { name: "WET",   offset:    0 }, // Western European
    TzInfo { name: "BST",   offset:    0 + TDAYZONE }, // British Summer
    TzInfo { name: "WAT",   offset:   60 }, // West Africa
    TzInfo { name: "AST",   offset:  240 }, // Atlantic Standard
    TzInfo { name: "ADT",   offset:  240 + TDAYZONE }, // Atlantic Daylight
    TzInfo { name: "EST",   offset:  300 }, // Eastern Standard
    TzInfo { name: "EDT",   offset:  300 + TDAYZONE }, // Eastern Daylight
    TzInfo { name: "CST",   offset:  360 }, // Central Standard
    TzInfo { name: "CDT",   offset:  360 + TDAYZONE }, // Central Daylight
    TzInfo { name: "MST",   offset:  420 }, // Mountain Standard
    TzInfo { name: "MDT",   offset:  420 + TDAYZONE }, // Mountain Daylight
    TzInfo { name: "PST",   offset:  480 }, // Pacific Standard
    TzInfo { name: "PDT",   offset:  480 + TDAYZONE }, // Pacific Daylight
    TzInfo { name: "YST",   offset:  540 }, // Yukon Standard
    TzInfo { name: "YDT",   offset:  540 + TDAYZONE }, // Yukon Daylight
    TzInfo { name: "HST",   offset:  600 }, // Hawaii Standard
    TzInfo { name: "HDT",   offset:  600 + TDAYZONE }, // Hawaii Daylight
    TzInfo { name: "CAT",   offset:  600 }, // Central Alaska
    TzInfo { name: "AHST",  offset:  600 }, // Alaska-Hawaii Standard
    TzInfo { name: "NT",    offset:  660 }, // Nome spellchecker:disable-line
    TzInfo { name: "IDLW",  offset:  720 }, // International Date Line West
    TzInfo { name: "CET",   offset:  -60 }, // Central European
    TzInfo { name: "MET",   offset:  -60 }, // Middle European
    TzInfo { name: "MEWT",  offset:  -60 }, // Middle European Winter
    TzInfo { name: "MEST",  offset:  -60 + TDAYZONE }, // Middle European Summer
    // Central European Summer
    TzInfo { name: "CEST",  offset:  -60 + TDAYZONE },
    TzInfo { name: "MESZ",  offset:  -60 + TDAYZONE }, // Middle European Summer
    TzInfo { name: "FWT",   offset:  -60 }, // French Winter
    TzInfo { name: "FST",   offset:  -60 + TDAYZONE }, // French Summer
    TzInfo { name: "EET",   offset: -120 }, // Eastern Europe, USSR Zone 1
    // West Australian Standard
    TzInfo { name: "WAST",  offset: -420 }, // spellchecker:disable-line
    // West Australian Daylight
    TzInfo { name: "WADT",  offset: -420 + TDAYZONE },
    TzInfo { name: "CCT",   offset: -480 }, // China Coast, USSR Zone 7
    TzInfo { name: "JST",   offset: -540 }, // Japan Standard, USSR Zone 8
    TzInfo { name: "EAST",  offset: -600 }, // Eastern Australian Standard
    // Eastern Australian Daylight
    TzInfo { name: "EADT",  offset: -600 + TDAYZONE },
    TzInfo { name: "GST",   offset: -600 }, // Guam Standard, USSR Zone 9
    TzInfo { name: "NZT",   offset: -720 }, // New Zealand
    TzInfo { name: "NZST",  offset: -720 }, // New Zealand Standard
    TzInfo { name: "NZDT",  offset: -720 + TDAYZONE }, // New Zealand Daylight
    TzInfo { name: "IDLE",  offset: -720 }, // International Date Line East
    // Next up: Military timezone names. RFC822 allowed these, but (as noted
    // in RFC 1123) had their signs wrong. Here we use the correct signs to
    // match actual military usage.
    TzInfo { name: "A",     offset:    1 * 60 }, // Alpha
    TzInfo { name: "B",     offset:    2 * 60 }, // Bravo
    TzInfo { name: "C",     offset:    3 * 60 }, // Charlie
    TzInfo { name: "D",     offset:    4 * 60 }, // Delta
    TzInfo { name: "E",     offset:    5 * 60 }, // Echo
    TzInfo { name: "F",     offset:    6 * 60 }, // Foxtrot
    TzInfo { name: "G",     offset:    7 * 60 }, // Golf
    TzInfo { name: "H",     offset:    8 * 60 }, // Hotel
    TzInfo { name: "I",     offset:    9 * 60 }, // India
    // "J", Juliet is not used as a timezone, to indicate the observer's local
    // time
    TzInfo { name: "K",     offset:   10 * 60 }, // Kilo
    TzInfo { name: "L",     offset:   11 * 60 }, // Lima
    TzInfo { name: "M",     offset:   12 * 60 }, // Mike
    TzInfo { name: "N",     offset:   -1 * 60 }, // November
    TzInfo { name: "O",     offset:   -2 * 60 }, // Oscar
    TzInfo { name: "P",     offset:   -3 * 60 }, // Papa
    TzInfo { name: "Q",     offset:   -4 * 60 }, // Quebec
    TzInfo { name: "R",     offset:   -5 * 60 }, // Romeo
    TzInfo { name: "S",     offset:   -6 * 60 }, // Sierra
    TzInfo { name: "T",     offset:   -7 * 60 }, // Tango
    TzInfo { name: "U",     offset:   -8 * 60 }, // Uniform
    TzInfo { name: "V",     offset:   -9 * 60 }, // Victor
    TzInfo { name: "W",     offset:  -10 * 60 }, // Whiskey
    TzInfo { name: "X",     offset:  -11 * 60 }, // X-ray
    TzInfo { name: "Y",     offset:  -12 * 60 }, // Yankee
    TzInfo { name: "Z",     offset:    0 }, // Zulu, zero meridian, a.k.a. UTC
];

/// The largest `time_t` on the four mandated targets.
const TIME_T_MAX: i64 = i64::MAX;

/// The longest name this parser will consider (`lib/parsedate.c:344-345`).
const NAME_LEN: usize = 12;

/// The widest value the bare-number branch will accept
/// (`lib/parsedate.c:413`).
///
/// `curlx_str_number(&p, &lval, 99999999)` -- so at most eight significant
/// digits, and exceeding it is an ERROR rather than a truncation, which is why
/// a nine-digit run makes the whole date fail.
const MAX_NUMBER: i64 = 99_999_999;

/// What the next bare number should be taken to mean.
///
/// **The C declares a third variant, `DATE_TIME`, and never uses it** -- no
/// assignment, no comparison, anywhere in the file. It is not modelled here,
/// and the omission is recorded so that a reader diffing the two enumerations
/// is not left looking for the missing arm.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Assume {
    /// A day of month is expected next (`DATE_MDAY`).
    MDay,
    /// A year is expected next (`DATE_YEAR`).
    Year,
}

/// The outcome of a parse.
///
/// Mirrors `PARSEDATE_OK` (0), `PARSEDATE_FAIL` (-1) and `PARSEDATE_LATER` (1)
/// from `lib/parsedate.c:95-100`. There is no underflow variant because
/// `PARSEDATE_SOONER` (2) is not defined for a signed 64-bit `time_t`; see the
/// module documentation for the `#if` that gates it away.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// A fine conversion, carrying seconds since the Unix epoch in UTC.
    Ok(i64),
    /// Overflow at the far end of `time_t`; the value is saturated.
    ///
    /// RETAINED BUT PROVABLY UNREACHABLE ON THESE TARGETS, and retained for
    /// exactly the reason C retains the guard that produces it. The only
    /// producer is the timezone-addition check at `lib/parsedate.c:540-543`,
    /// which needs `t > TIME_T_MAX - tzoff`. [`MAX_NUMBER`] caps a year at
    /// 99999999, so the largest instant [`time2epoch`] can return is
    /// 3_155_633_032_780_800 -- computed for 99999999-12-31 23:59:60 -- while
    /// `TIME_T_MAX` minus the largest positive offset is
    /// 9_223_372_036_854_725_407. The headroom is a factor of about 2923, so
    /// the branch cannot be taken. It becomes reachable only on a 32-bit
    /// `time_t`, where C replaces the Gregorian floor with the 2038 and 1903
    /// limits; none of the four mandated targets is 32-bit. Deleting the guard
    /// would make this file diverge from its authority for no benefit, and the
    /// unreachability is asserted by test rather than assumed.
    Later(i64),
    /// The string could not be converted.
    Fail,
}

/// The byte at `idx`, or `0` past the end.
fn at(bytes: &[u8], idx: usize) -> u8 {
    if idx < bytes.len() {
        bytes[idx]
    } else {
        0
    }
}

/// The decimal value of the byte at `idx`, or `0` when it is not a digit.
fn digit_at(bytes: &[u8], idx: usize) -> i64 {
    let byte = at(bytes, idx);
    if is_digit(byte) {
        i64::from(byte - b'0')
    } else {
        0
    }
}

/// Match a weekday name: `Some(0..=6)` for **Monday through Sunday**.
///
/// `lib/parsedate.c:201-219`. The length decides WHICH table is consulted, and
/// the three-way split is the whole function:
///
/// * longer than three characters searches [`WEEKDAY`], the full names;
/// * exactly three searches [`WKDAY`], the abbreviations;
/// * shorter than three returns `-1` in the C, *"too short"*, matching nothing.
fn checkday(check: &[u8]) -> Option<i32> {
    let len = check.len();
    let table: &[&str] = if len > 3 {
        &WEEKDAY
    } else if len == 3 {
        &WKDAY
    } else {
        return None; // too short
    };
    for (index, name) in table.iter().enumerate() {
        if name.len() == len && ncasecompare(check, name.as_bytes(), len) {
            // `index` is at most 6, so the conversion cannot fail; `try_from`
            // rather than a cast keeps that provable at a glance.
            return i32::try_from(index).ok();
        }
    }
    None
}

/// Match a month name: `Some(0..=11)` for January through December.
///
/// One note for anyone diffing the C: its `return -1` at `:233` carries the
/// trailing comment *"return the offset or -1, no real offset is -1"*, which
/// was copied from [`checktz`] and is STALE here -- this function returns a
/// month index, not an offset. The comment is recorded rather than reproduced.
fn checkmonth(check: &[u8]) -> Option<i32> {
    if check.len() != 3 {
        return None; // not a month
    }
    for (index, name) in MONTH.iter().enumerate() {
        if ncasecompare(check, name.as_bytes(), 3) {
            // At most 11, so infallible.
            return i32::try_from(index).ok();
        }
    }
    None
}

/// Match a timezone name, returning its offset from GMT in **seconds**.
///
/// `lib/parsedate.c:239-254`, whose own comment states the units: *"return the
/// time zone offset between GMT and the input one, in number of seconds or -1
/// if the timezone was not found/legal"*. [`TZ`] stores minutes, and `:250`
/// multiplies by 60 on the way out, so this is the one place the two units
/// meet.
fn checktz(check: &[u8]) -> Option<i32> {
    if check.len() > 4 {
        return None; // longer than any valid timezone
    }
    for zone in &TZ {
        if zone.name.len() == check.len()
            && ncasecompare(check, zone.name.as_bytes(), check.len())
        {
            // Minutes to seconds. The widest entry is 720, so 43200 fits an
            // i32 with room to spare and the multiplication cannot overflow.
            return Some(zone.offset * 60);
        }
    }
    None
}

/// Advance past every byte that is neither a letter nor a digit.
fn skip(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && !is_alnum(bytes[idx]) {
        idx += 1;
    }
    idx
}

/// Convert a broken-down UTC time to seconds since the Unix epoch.
///
/// ```text
/// int leap_days = year - (mon <= 1);
/// leap_days = ((leap_days / 4) - (leap_days / 100) + (leap_days / 400)
///              - (1969 / 4) + (1969 / 100) - (1969 / 400));
/// return ((((time_t)(year - 1970) * 365
///           + leap_days + month_days_cumulative[mon] + mday - 1) * 24
///          + hour) * 60 + min) * 60 + sec;
/// ```
///
/// # Why every parameter is `i64` where the C says `int`
///
/// The C computes in `int` and widens only at `(time_t)(year - 1970)`. Every
/// intermediate it forms is bounded by [`MAX_NUMBER`], so no `int` overflow is
/// reachable and computing throughout in `i64` is exactly equivalent -- while
/// removing every narrowing cast from this file, which is what keeps the parser
/// free of a class of defect the C is exposed to. Rust's `/` truncates toward
/// zero exactly as C's does, so the two agree on negative years as well.
fn time2epoch(
    sec: i64,
    min: i64,
    hour: i64,
    mday: i64,
    mon: i64,
    year: i64,
) -> i64 {
    // `month_days_cumulative[mon]`. The caller has already rejected every
    // `mon` outside 0..=11 -- the `-1` sentinel test at `lib/parsedate.c:486`
    // and the `monnum > 11` range test at `:526` -- so the fallback is
    // unreachable from [`parsedate`]. It is written rather than asserted
    // because a date string arrives from a remote server and this function is
    // reachable from tests, and a total function cannot panic on any input.
    let cumulative = usize::try_from(mon)
        .ok()
        .and_then(|index| MONTH_DAYS_CUMULATIVE.get(index))
        .copied()
        .unwrap_or(0);

    // `int leap_days = year - (mon <= 1);` -- the boolean borrow.
    let mut leap_days = year - i64::from(mon <= 1);
    leap_days = (leap_days / 4) - (leap_days / 100) + (leap_days / 400)
        - (1969 / 4)
        + (1969 / 100)
        - (1969 / 400);

    ((((year - 1970) * 365 + leap_days + cumulative + mday - 1) * 24 + hour)
        * 60
        + min)
        * 60
        + sec
}

/// Read a one- or two-digit decimal number, returning it and the index after.
///
/// `lib/parsedate.c:290-299`. A second digit is consumed only when one is
/// actually there, which is what admits the single-digit fields of `8:9:7`.
fn oneortwodigit(bytes: &[u8], idx: usize) -> (i64, usize) {
    let first = digit_at(bytes, idx);
    if is_digit(at(bytes, idx + 1)) {
        (first * 10 + digit_at(bytes, idx + 1), idx + 2)
    } else {
        (first, idx + 1)
    }
}

/// Match `HH:MM:SS` or `HH:MM`, accepting single digits in every field.
///
/// `lib/parsedate.c:302-331`. Four details are easy to lose and all four are
/// preserved:
///
/// * The bounds are `hh < 24`, `mm < 60` and **`ss <= 60`** (`:308`, `:310`,
///   `:313`). The `<=` admits a LEAP SECOND, and the post-loop range check at
///   `:527` uses `secnum > 60` to stay consistent with it.
/// * Seconds default to `0` for the `HH:MM` form -- `int hh, mm, ss = 0;` at
///   `:306`.
/// * A trailing colon NOT followed by a digit does not fail. It falls into the
///   C's `else` arm at `:318-321` and yields a valid `HH:MM` whose end index
///   still points AT the colon, so `12:30:` parses as 12:30:00.
/// * A colon that IS followed by a digit whose value exceeds 60 DOES fail,
///   because that path cannot reach the `else`. A failure here is `FALSE`
///   rather than an error: the caller falls through to the bare-number branch.
fn match_time(bytes: &[u8], idx: usize) -> Option<(i64, i64, i64, usize)> {
    let (hh, after_hh) = oneortwodigit(bytes, idx);
    if hh >= 24
        || at(bytes, after_hh) != b':'
        || !is_digit(at(bytes, after_hh + 1))
    {
        return None; // not a time string
    }

    let (mm, after_mm) = oneortwodigit(bytes, after_hh + 1);
    if mm >= 60 {
        return None;
    }

    if at(bytes, after_mm) == b':' && is_digit(at(bytes, after_mm + 1)) {
        let (ss, after_ss) = oneortwodigit(bytes, after_mm + 1);
        if ss <= 60 {
            return Some((hh, mm, ss, after_ss)); // valid HH:MM:SS
        }
        return None;
    }

    Some((hh, mm, 0, after_mm)) // valid HH:MM
}

/// The parser proper -- `lib/parsedate.c:347-550`.
///
/// # The `-1` sentinels are a correctness requirement, not a C-ism
///
/// C uses `int x = -1` for "not seen yet" on every accumulator. Modelling that
/// as `Option` looks like an improvement and is a BEHAVIOUR CHANGE, because the
/// parser can legitimately COMPUTE -1 into `monnum`: the `YYYYMMDD` branch
/// evaluates `(val % 10000) / 100 - 1` (`:448`), so a month field of `00`
/// yields -1. C then reads that as "no month" and fails, and it also leaves the
/// slot open for a later `Nov` to fill. With `Option`, `Some(-1)` reads as
/// PRESENT, so `20010001` would parse successfully instead of failing and the
/// cumulative-days lookup would be handed a negative index. Keeping C's
/// representation keeps C's semantics. The sentinel is safe for `tzoff` too:
/// offsets are whole minutes, so -1 seconds is not a representable zone.
pub(crate) fn parsedate(date: &[u8]) -> Outcome {
    // A NUL ends the string for the C parser, whose every loop tests `*date`.
    // Truncating here reproduces that without threading the test through each
    // step; a `&str` from a `CStr` cannot contain one, but a Rust caller can
    // pass one and must get curl's answer, not a different one.
    let date = match date.iter().position(|&byte| byte == 0) {
        Some(end) => &date[..end],
        None => date,
    };

    let mut wdaynum: i64 = -1; // day of the week, 0-6 (mon-sun)
    let mut monnum: i64 = -1; // month of the year, 0-11
    let mut mdaynum: i64 = -1; // day of month, 1-31
    let mut hournum: i64 = -1;
    let mut minnum: i64 = -1;
    let mut secnum: i64 = -1;
    let mut yearnum: i64 = -1;
    let mut tzoff: i64 = -1;
    let mut dignext = Assume::MDay;

    let mut idx = 0usize;
    let mut part = 0u32; // max 6 parts

    // `while(*date && (part < 6))` at `:362`. The cap is reproduced exactly: a
    // SEVENTH token is silently ignored rather than rejected, which is why
    // trailing rubbish after a complete date is harmless while the same rubbish
    // inside the first six parts is fatal.
    while at(date, idx) != 0 && part < 6 {
        let mut found = false;

        idx = skip(date, idx);
        // `skip` may have consumed the remainder. C re-tests `*date` only at
        // the top of the loop, and both branches below then see the terminator
        // and fall through to `part++`, which is what this reproduces: neither
        // branch is entered.
        let cur = at(date, idx);

        if is_alpha(cur) {
            // A name is coming up (`:367-399`). Measure the alphabetic run,
            // stopping at NAME_LEN so a pathologically long word costs nothing.
            let mut len = 0usize;
            while is_alpha(at(date, idx + len)) && len < NAME_LEN {
                len += 1;
            }

            // Reaching NAME_LEN means the run is at least that long, and no
            // name any table holds is. C skips all three lookups in that case
            // (`:376`) and therefore fails: the tables are not consulted at
            // all, and `found` stays false.
            if len != NAME_LEN {
                let word = &date[idx..idx + len];
                if wdaynum == -1 {
                    wdaynum = checkday(word).map_or(-1, i64::from);
                    if wdaynum != -1 {
                        found = true;
                    }
                }
                if !found && monnum == -1 {
                    monnum = checkmonth(word).map_or(-1, i64::from);
                    if monnum != -1 {
                        found = true;
                    }
                }
                if !found && tzoff == -1 {
                    // "this just must be a time zone string" (`:389`).
                    tzoff = checktz(word).map_or(-1, i64::from);
                    if tzoff != -1 {
                        found = true;
                    }
                }
            }
            if !found {
                return Outcome::Fail; // bad string
            }
            idx += len;
        } else if is_digit(cur) {
            // A digit (`:400-478`). A time stamp is tried FIRST, and only while
            // no seconds value has been recorded -- so a second `HH:MM` in one
            // string is not a time.
            if secnum == -1 {
                if let Some((hour, min, sec, end)) = match_time(date, idx) {
                    hournum = hour;
                    minnum = min;
                    secnum = sec;
                    idx = end;
                    part += 1;
                    continue;
                }
            }

            // `curlx_str_number(&p, &lval, 99999999)` at `:413`. The borrowed
            // parser advances its cursor only on success and reports
            // `StrError::NoNum` or `StrError::Overflow` otherwise; both are the
            // C's non-zero return, and both fail the whole date.
            let mut cursor = date.get(idx..).unwrap_or_default();
            let val = match str_number(&mut cursor, MAX_NUMBER) {
                Ok(value) => value,
                Err(_) => return Outcome::Fail,
            };
            let end = date.len() - cursor.len();
            // `num_digits = (int)(p - date)` at `:417`, counted from the
            // ADVANCED cursor so leading zeroes count. The C's comment at
            // `:416` claims this cannot exceed 8; with leading zeroes it can,
            // and it makes no difference because only 4 and 8 are ever tested.
            let num_digits = end - idx;

            // `indate < date` at `:423` is a BOUNDS GUARD, not a semantic test:
            // it is what makes the `date[-1]` look-behind on the next line safe
            // when the number starts the string. Here that is `idx > 0`, and
            // dropping it would be an out-of-bounds read in the C and a panic
            // here.
            let signed_by = if idx > 0 { at(date, idx - 1) } else { 0 };

            if tzoff == -1
                && num_digits == 4
                && val <= 1400
                && (signed_by == b'+' || signed_by == b'-')
            {
                // Four digits, no greater than 1400, and preceded by a sign: an
                // RFC 822 style offset (`:420-439`). The C picked 1400 because
                // *"+1300 is frequently used and +1400 is mentioned as an edge
                // number"*.
                found = true;
                let mut off = (val / 100 * 60 + val % 100) * 60;

                // `:436-437` -- "the + and - prefix indicates the local time
                // compared to GMT, this we need their reversed math to get what
                // we want". THE SIGN IS REVERSED: `+0200` subtracts two hours.
                if signed_by == b'+' {
                    off = -off;
                }
                tzoff = off;
            } else if num_digits == 8
                && yearnum == -1
                && monnum == -1
                && mdaynum == -1
            {
                // "8 digits, no year, month or day yet. This is YYYYMMDD"
                // (`:441-450`). The month is converted to 0-based, and a field
                // of `00` therefore yields -1, which then reads as "no month"
                // and fails the vital-information test below -- exactly what C
                // does, and the reason the sentinels are integers.
                found = true;
                yearnum = val / 10000;
                monnum = (val % 10000) / 100 - 1; // month is 0 - 11
                mdaynum = val % 100;
            }

            if !found && dignext == Assume::MDay && mdaynum == -1 {
                if val > 0 && val < 32 {
                    mdaynum = val;
                    found = true;
                }
                // `dignext = DATE_YEAR;` at `:457` sits OUTSIDE the `if`, so it
                // advances UNCONDITIONALLY -- even when the value was not a
                // plausible day and `found` stayed false. That is deliberate in
                // C and load-bearing: `Sun Nov 6 94` and `1994 Nov 6` both work
                // because the out-of-range number moves the guess along.
                dignext = Assume::Year;
            }

            if !found && dignext == Assume::Year && yearnum == -1 {
                let mut year = val;
                found = true;
                // The two-digit pivot at `:463-468`, with the STRICT `>`
                // reproduced: 70 lands in the 2000s and only 71 upwards lands
                // in the 1900s. The asymmetry is measured, not a typo.
                if year < 100 {
                    if year > 70 {
                        year += 1900;
                    } else {
                        year += 2000;
                    }
                }
                yearnum = year;
                if mdaynum == -1 {
                    dignext = Assume::MDay;
                }
            }

            if !found {
                return Outcome::Fail;
            }
            idx = end;
        }

        part += 1;
    }

    // The weekday is parsed but never validated against the date, matching C:
    // `Mon, 06 Nov 1994` and `Fri, 06 Nov 1994` are the same instant. The
    // binding exists so that the accumulator is written the C's way and read
    // once, rather than being dropped and quietly diverging later.
    debug_assert!(
        (-1..7).contains(&wdaynum),
        "checkday yields only -1 or 0..=6"
    );

    if secnum == -1 {
        // "no time, make it zero" (`:483-484`). All three fields are zeroed
        // together, because only `secnum` is tested.
        secnum = 0;
        minnum = 0;
        hournum = 0;
    }

    if mdaynum == -1 || monnum == -1 || yearnum == -1 {
        // "lacks vital info, fail" (`:486-490`). `monnum` reaches this as -1
        // either because no month name was seen or because a `YYYYMMDD` field
        // of `00` computed -1; C cannot tell the two apart and neither does
        // this.
        return Outcome::Fail;
    }

    // "The Gregorian calendar was introduced 1582" (`:521-523`). On a 32-bit
    // time_t this branch is replaced by the 2038, 2106 and 1903 limits; all
    // four mandated targets are 64-bit, so this is the one that applies and
    // the only year guard in the file.
    if yearnum < 1583 {
        return Outcome::Fail;
    }

    if mdaynum > 31 || monnum > 11 || hournum > 23 || minnum > 59 || secnum > 60
    {
        // "clearly an illegal date" (`:526-528`). Every test is `>`, so
        // `secnum == 60` is admitted, consistently with [`match_time`]. Note
        // also what is NOT checked: the day is not validated against the length
        // of the month, so `Feb 30` and `Feb 29 1900` both parse and land in
        // March. Both behaviours match C.
        return Outcome::Fail;
    }

    let t = time2epoch(secnum, minnum, hournum, mdaynum, monnum, yearnum);

    // "Add the time zone diff between local time zone and GMT" (`:536-538`);
    // an absent timezone means GMT.
    let tzoff = if tzoff == -1 { 0 } else { tzoff };

    // `:540-543`. The subtraction cannot itself overflow because this arm is
    // only taken for a POSITIVE offset, which moves away from the maximum.
    if tzoff > 0 && t > TIME_T_MAX - tzoff {
        return Outcome::Later(TIME_T_MAX); // time_t overflow
    }

    match t.checked_add(tzoff) {
        Some(sum) => Outcome::Ok(sum),
        // Total by construction rather than by trust. The guard above has
        // already rejected the only overflow direction a positive offset can
        // reach, and the 1583 floor keeps `t` more than eight orders of
        // magnitude away from the low end, so a negative offset cannot
        // underflow. Saturating here reports what C reports for the overflow it
        // does check, instead of wrapping into a value no input names.
        None => Outcome::Later(TIME_T_MAX),
    }
}

/// Parse a date string into seconds since the Unix epoch, UTC.
///
/// Every format listed in the module documentation is accepted, including dates
/// with no weekday, no timezone or no time at all. What is REJECTED is equally
/// part of the contract, so the module's own tests assert both directions.
///
/// # The C's second parameter has no counterpart here
///
/// `curl_getdate(const char *p, const time_t *unused)` declares two arguments
/// and uses one; `lib/parsedate.c:565` says so outright -- *"legacy argument
/// from the past that we ignore"*. The declared C signature keeps it because
/// `include/curl/curl.h` publishes it, and published
/// signatures, so `curl-rs-ffi/src/ffi/misc.rs` accepts and discards it. It is
/// absent here because a Rust caller has no reason to pass a value that is
/// documented to be ignored.
///
/// # Why `&str` and not `&[u8]`
///
/// The parser itself is byte-native; `parsedate` takes `&[u8]` and is
/// `pub(crate)` for in-crate callers that hold wire bytes. This facade takes
/// `&str` because its shape is a settled cross-crate contract: `version.rs`
/// pins it with a compile-time assertion of the exact function type, and
/// `curl-rs-ffi/src/ffi/misc.rs` produces the `&str` from a `CStr` as its whole
/// contribution. Changing it here would change two crates this file does not
/// own, for a case -- a date header that is not valid text -- that the adapter
/// already declines before any parsing decision is reached.
///
/// # Returns
///
/// `Some(seconds)` on success, or `None` when the string cannot be converted or
/// names an instant too large to represent. Overflow is a failure here, and
/// deliberately so: C returns `-1` for anything that is not `PARSEDATE_OK`
/// (`:573-574`), so through this entry point a far-future date and a malformed
/// one are the same answer. Callers needing the saturating behaviour use
/// [`getdate_capped`]; the two are NOT interchangeable.
#[must_use]
pub fn getdate(date: &str) -> Option<i64> {
    match parsedate(date.as_bytes()) {
        Outcome::Ok(t) => Some(if t == -1 { 0 } else { t }),
        Outcome::Later(_) | Outcome::Fail => None,
    }
}

/// Parse a date string, saturating instead of failing on overflow.
///
/// The engine half of the INTERNAL `Curl_getdate_capped`
/// (`lib/parsedate.c:581-585`), whose comment states the difference: *"this
/// will return TIME_T_MAX in case the parsed time value was too big, instead of
/// an error. Returns non-zero on error."* Its body is
/// `return (rc == PARSEDATE_FAIL);`, so `PARSEDATE_LATER` is a SUCCESS here.
///
/// Two differences from [`getdate`], both from the C:
///
/// * A value too large to represent yields `Some(TIME_T_MAX)` rather than
///   `None`; only an unparsable string yields `None`.
/// * The `-1` to `0` adjustment is NOT applied, because this function reports
///   failure out of band and has no need of a sentinel. So one second before
///   the epoch is `Some(-1)` here and `Some(0)` through [`getdate`].
#[allow(dead_code)] // The cookie, HSTS and Alt-Svc stores are later code.
#[must_use]
pub(crate) fn getdate_capped(date: &str) -> Option<i64> {
    match parsedate(date.as_bytes()) {
        Outcome::Ok(t) | Outcome::Later(t) => Some(t),
        Outcome::Fail => None,
    }
}

// ONE C ENTRY POINT IS DELIBERATELY NOT PORTED, and the omission is recorded
// here rather than left for someone to notice.

// THE EXPECTATIONS BELOW ARE A DIFFERENTIAL ORACLE, NOT A RESTATEMENT.
//
// Every value in `ORACLE` was produced by CALLING `curl_getdate` outside this
// file -- originally from the real `libcurl.so.4` built from this repository's
// own C tree, and every row re-derived since from an independent transcription
// of `lib/parsedate.c` that was itself cross-checked against `calendar.timegm`
// on the instants both can express. So a row disagreeing with this
// implementation means this implementation is wrong, which is the only useful
// direction for a parity test to point.
//
// Two C constants cannot be pinned by any test at this boundary, so their
// bounds are recorded here instead of asserted:
//
//  * `ss <= 60` versus `ss <= 61` is unobservable through `getdate`, because
//    the later `secnum > 60` range check rejects 61 whichever path the parser
//    took. The guard is still load-bearing, and `match_time` is tested
//    directly for it: `00:00:60` parses and `00:00:61` does not.
//  * `NAME_LEN` is 12 in the C, but every value from 10 upwards behaves
//    identically, because no name in any table is longer than the nine
//    characters of `Wednesday`. What IS observable is that a run REACHING the
//    limit is refused without a lookup, and that has its own test.
//
// One property of the exported contract is deliberately NOT tested here,
// because it does not exist on this side of the boundary: `curl_getdate`'s
// ignored second parameter. `curl-rs-ffi/src/ffi/misc.rs` owns that test and
// calls the symbol twice, once with a real pointer and once with a null one,
// asserting the two agree.

#[cfg(test)]
mod tests {
    use super::*;

    /// `(input, expected)` where expected is what the C `curl_getdate`
    /// returns, and `-1` is its failure sentinel.
    #[rustfmt::skip]
    const ORACLE: &[(&str, i64)] = &[
        ("Sun, 06 Nov 1994 08:49:37 GMT", 784111777),
        ("Sunday, 06-Nov-94 08:49:37 GMT", 784111777),
        ("Sun Nov  6 08:49:37 1994", 784111777),
        ("06 Nov 1994 08:49:37 GMT", 784111777),
        ("06-Nov-94 08:49:37 GMT", 784111777),
        ("Nov  6 08:49:37 1994", 784111777),
        ("06 Nov 1994 08:49:37", 784111777),
        ("06-Nov-94 08:49:37", 784111777),
        ("1994 Nov 6 08:49:37", 784111777),
        ("GMT 08:49:37 06-Nov-94 Sunday", 784111777),
        ("94 6 Nov 08:49:37", 784111777),
        ("1994 Nov 6", 784080000),
        ("06-Nov-94", 784080000),
        ("Sun Nov 6 94", 784080000),
        ("1994.Nov.6", 784080000),
        ("Sun/Nov/6/94/GMT", 784080000),
        ("Sun, 06 Nov 1994 08:49:37 CET", 784108177),
        ("06 Nov 1994 08:49:37 EST", 784129777),
        ("Sun, 12 Sep 2004 15:05:58 -0700", 1095026758),
        ("Sat, 11 Sep 2004 21:32:11 +0200", 1094931131),
        ("20040912 15:05:58 -0700", 1095026758),
        ("20040911 +0200", 1094853600),
        ("Thu, 01 Jan 1970 00:00:00 GMT", 0),
        ("Wed, 31 Dec 1969 23:59:59 GMT", 0),
        ("Thu, 01 Jan 1970 00:00:01 GMT", 1),
        ("Tue, 19 Jan 2038 03:14:07 GMT", 2147483647),
        ("Tue, 19 Jan 2038 03:14:08 GMT", 2147483648),
        ("Fri, 13 Feb 2009 23:31:30 GMT", 1234567890),
        ("Mon, 01 Jan 1583 00:00:00 GMT", -12212553600),
        ("Mon, 01 Jan 1582 00:00:00 GMT", -1),
        ("Fri, 01 Jan 1500 00:00:00 GMT", -1),
        ("1 Jan 2000", 946684800),
        ("01-Jan-00", 946684800),
        ("01-Jan-70", 3155760000),
        ("01-Jan-71", 31536000),
        ("01-Jan-69", 3124224000),
        ("01-Jan-99", 915148800),
        ("Feb 29 2000 12:00:00", 951825600),
        ("Feb 29 1900 12:00:00", -2203848000),
        ("Feb 30 2001 12:00:00", 983534400),
        ("Jan 32 2001", -1),
        ("Jan 0 2001", -1),
        ("Dec 31 2001 23:59:60", 1009843200),
        ("Dec 31 2001 23:59:61", -1),
        ("Dec 31 2001 24:00:00", -1),
        ("Dec 31 2001 12:60:00", -1),
        ("Dec 31 2001 12:30", 1009801800),
        ("Dec 31 2001 12:30:", 1009801800),
        ("Dec 31 2001 1:2:3", 1009760523),
        ("Dec 31 2001 12", -1),
        ("20011231", 1009756800),
        ("20010001", -1),
        ("20011200", 1007078400),
        ("99999999 Jan 1", -1),
        ("999999999 Jan 1", -1),
        ("Jan 1 2001 +1400", 978256800),
        ("Jan 1 2001 +1401", -1),
        ("Jan 1 2001 -1400", 978357600),
        ("Jan 1 2001 +0000", 978307200),
        ("Jan 1 2001 -0000", 978307200),
        ("Jan 1 2001 1400", -1),
        ("Wednesday, 06-Nov-1994 08:49:37 GMT", 784111777),
        ("Wednesdayy 06 Nov 1994", -1),
        ("Sund 06 Nov 1994", -1),
        ("Sun 06 Nov 1994", 784080000),
        ("Sun 06 Nov 1994 08:49:37 XYZ", -1),
        ("Sun 06 Nov 1994 08:49:37 Z", 784111777),
        ("Sun 06 Nov 1994 08:49:37 A", 784115377),
        ("Sun 06 Nov 1994 08:49:37 M", 784154977),
        ("Sun 06 Nov 1994 08:49:37 N", 784108177),
        ("Sun 06 Nov 1994 08:49:37 J", -1),
        ("Sun 06 Nov 1994 08:49:37 AHST", 784147777),
        ("Sun 06 Nov 1994 08:49:37 NZDT", 784064977),
        ("Sun 06 Nov 1994 08:49:37 IDLE", 784068577),
        ("", -1),
        ("   ", -1),
        (",,,,", -1),
        ("Nov", -1),
        ("1994", -1),
        ("Nov 1994", -1),
        ("6 Nov", -1),
        ("2001-12-31", -1),
        ("2001-12-31T23:59:59", -1),
        ("2001-12-31 23:59:59Z", -1),
        ("Thu, 1 Jan 2004 00:00:00 GMT", 1072915200),
        ("Thu,  1  Jan  2004  00:00:00  GMT", 1072915200),
        ("THU, 01 JAN 2004 00:00:00 GMT", 1072915200),
        ("thu, 01 jan 2004 00:00:00 gmt", 1072915200),
        ("Sun, 06 Nov 1994 08:49:37 gmt", 784111777),
        ("Sun, 06 Nov 1994 08:49:37 GmT", 784111777),
        ("0 Jan 2001", -1),
        ("000000001 Jan 2001", 978307200),
        ("Jan 1 0001", 978307200),
        ("Jan 1 1583", -12212553600),
        ("Jan 1 9999", 253370764800),
        ("Jan 1 99999999", 3155633001244800),
        ("Jan 1 2001 08:49:37 +2400", -1),
        ("20380119 03:14:07", 2147483647),
        ("20380119 03:14:08", 2147483648),
        ("Sat, 01 Jan 2050 00:00:00 GMT", 2524608000),
        ("Sat, 01 Jan 2500 00:00:00 GMT", 16725225600),
        ("Fri, 31 Dec 9999 23:59:59 GMT", 253402300799),
        ("Sun 06 Nov 1994 08:49:37 GMT Frobuary", 784111777),
        ("Sun 06 Nov 1994 08:49:37 GMT 99999999999", 784111777),
        ("Sun 06 Nov 1994 08:49:37 Frobuary", -1),
        ("Abcdefghijkl 6 Nov 1994", -1),
        ("Abcdefghijklm 6 Nov 1994", -1),
        ("Wednesdayyyy 06 Nov 1994", -1),
        ("+0200 Jan 1 2001", 978300000),
        ("0200 Jan 1 2001", -1),
        ("-0700 Jan 1 2001", 978332400),
        ("Jan 1 2001 0200", -1),
        ("20011301", -1),
        ("20011232", -1),
        ("Sun, 06 Nov 1994 GMT", 784080000),
        ("Dec 31 2001 8:9:7", 1009786147),
        ("Dec 31 2001 8:9", 1009786140),
        ("06-Nov-70", 3182457600),
        ("06-Nov-71", 58233600),
        ("06-Nov-69", 3150921600),
        ("06-Nov-99", 941846400),
        ("06-Nov-1582", -1),
        ("06-Nov-1583", -12185856000),
        (":::", -1),
        ("+", -1),
        ("-", -1),
        ("1", -1),
        ("00:00:00", -1),
        ("1994 08:49:37", -1),
        ("6 Nov 1994 08:49:37 08:49:37", -1),
        ("Monday, 13-Jun-1988 03:04:55 GMT", 582174295),
        ("Sat Feb 2 11:56:27 GMT 2030", 1896263787),
        ("Sat May 5 GMT 11:56:27 2035", 2061978987),
        ("Sat, 26 Jul 2008 10:26:59 GMT", 1217068019),
        ("Sat, 29 Feb 2020 16:10:44 GMT", 1582992644),
        ("Sun, 12 Dec 1999 11:00:00 GMT", 944996400),
        ("Thu Jan  1 00:00:00 GMT 1970", 0),
        ("Thu, 01 Jan 1970 00:00:30 GMT", 30),
        ("Thu, 01-Jan-1970 00:00:00 GMT", 0),
        ("Thu, 12 Feb 2000 00:00:00 GMT", 950313600),
        ("Thu, 22 Nov 2525 10:54:11 GMT", 17542263251),
        ("Tue, 13 Jun 1910 12:10:00 GMT", -1879329000),
        ("Tue, 13 Jun 2000 12:10:00 GMT", 960898200),
        ("Wed, 09 Oct 1940 16:45:49 +0100", -922349651),
        ("Sat Feb 2 11:56:27 GMT 2525", 17516951787),
    ];

    #[test]
    fn matches_the_c_getdate_on_every_documented_format() {
        let mut wrong = Vec::new();
        for &(input, expected) in ORACLE {
            let actual = getdate(input).unwrap_or(-1);
            if actual != expected {
                wrong.push(format!("{input:?}: C={expected} rust={actual}"));
            }
        }
        assert!(
            wrong.is_empty(),
            "{} of {} inputs disagree with the C oracle:\n  {}",
            wrong.len(),
            ORACLE.len(),
            wrong.join("\n  ")
        );
    }

    #[test]
    fn the_oracle_table_exercises_both_outcomes() {
        // A table of only failures, or only successes, would let a degenerate
        // implementation pass. Both counts are asserted so that the test above
        // cannot become vacuous through editing, and no row may be duplicated
        // -- a duplicate would inflate a count without adding coverage.
        let parsed = ORACLE.iter().filter(|(_, value)| *value != -1).count();
        let failed = ORACLE.len() - parsed;
        assert_eq!(parsed, 100, "expected 100 parseable inputs");
        assert_eq!(failed, 45, "expected 45 rejected inputs");
        for (index, (input, _)) in ORACLE.iter().enumerate() {
            for (other, _) in ORACLE.iter().skip(index + 1) {
                assert_ne!(input, other, "duplicate oracle row {input:?}");
            }
        }
    }

    #[test]
    fn the_reference_instant_is_the_one_rfc_2616_documents() {
        // `lib/parsedate.c:34-36` uses this instant for all three of the
        // formats RFC 2616 3.3.1 lists, so all three must agree, and the
        // absolute value is the one every HTTP-date reference quotes.
        for input in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(getdate(input), Some(784_111_777), "{input:?}");
        }
    }

    #[test]
    fn every_example_in_the_c_header_comment_parses() {
        // The comment at `lib/parsedate.c:29-81` IS the specification of what
        // this parser accepts, so every example it gives must parse. Listed
        // separately from ORACLE, and by section, so that a reader can check
        // the enumeration in the module documentation against the C by eye.
        for input in [
            // RFC 2616 3.3.1
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
            // without a week day name
            "06 Nov 1994 08:49:37 GMT",
            "06-Nov-94 08:49:37 GMT",
            "Nov  6 08:49:37 1994",
            // without the time zone
            "06 Nov 1994 08:49:37",
            "06-Nov-94 08:49:37",
            // weird order
            "1994 Nov 6 08:49:37",
            "GMT 08:49:37 06-Nov-94 Sunday",
            "94 6 Nov 08:49:37",
            // time left out
            "1994 Nov 6",
            "06-Nov-94",
            "Sun Nov 6 94",
            // unusual separators
            "1994.Nov.6",
            "Sun/Nov/6/94/GMT",
            // commonly used time zone names
            "Sun, 06 Nov 1994 08:49:37 CET",
            "06 Nov 1994 08:49:37 EST",
            // time zones specified using RFC822 style
            "Sun, 12 Sep 2004 15:05:58 -0700",
            "Sat, 11 Sep 2004 21:32:11 +0200",
            // compact numerical date strings
            "20040912 15:05:58 -0700",
            "20040911 +0200",
        ] {
            assert!(getdate(input).is_some(), "{input:?} must parse");
        }
    }

    #[test]
    fn the_minus_one_second_is_reported_as_the_epoch() {
        // The quirk at `lib/parsedate.c:568-570`: one second before the epoch
        // collides with the failure sentinel, so C returns 0 instead.
        assert_eq!(getdate("Wed, 31 Dec 1969 23:59:59 GMT"), Some(0));
        // The neighbours are unaffected, which is what shows the adjustment is
        // a single-value special case and not an off-by-one.
        assert_eq!(getdate("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(getdate("Thu, 01 Jan 1970 00:00:01 GMT"), Some(1));
        assert_eq!(getdate("Wed, 31 Dec 1969 23:59:58 GMT"), Some(-2));
        // And the underlying parse really does yield -1, so the adjustment is
        // being exercised rather than merely agreeing by accident.
        assert_eq!(
            parsedate(b"Wed, 31 Dec 1969 23:59:59 GMT"),
            Outcome::Ok(-1)
        );
    }

    #[test]
    fn a_yyyymmdd_month_of_zero_is_indistinguishable_from_no_month() {
        // The sentinel case that a naive `Option` model gets wrong:
        // `(0001 % 10000) / 100 - 1` is -1, which C reads as "no month".
        assert_eq!(getdate("20010001"), None);
        // And because the slot still reads as empty, a later month name fills
        // it -- confirmed against the C oracle.
        assert_eq!(getdate("20010001 Nov"), getdate_capped("20010001 Nov"));
        // A well-formed compact date is unaffected.
        assert_eq!(getdate("20011231"), Some(1_009_756_800));
    }

    #[test]
    fn compact_numeric_dates_convert_the_month_to_zero_based() {
        // `monnum = (val % 10000) / 100 - 1` at `lib/parsedate.c:448`.
        // September is field 09 and index 8, so the compact form and the named
        // form must agree to the second.
        assert_eq!(getdate("20040912"), getdate("12 Sep 2004"));
        assert_eq!(
            getdate("20040912 15:05:58 -0700"),
            getdate("Sun, 12 Sep 2004 15:05:58 -0700")
        );
        assert_eq!(getdate("20011231"), getdate("31 Dec 2001"));
        assert_eq!(getdate("20010101"), getdate("1 Jan 2001"));
        // A month field of 13 becomes index 12, which the range check rejects.
        assert_eq!(getdate("20011301"), None);
        // And the eight-digit branch is taken only while year, month and day
        // are ALL still unseen (`:441-444`), so a preceding month name means
        // the same digits are read as a plain number instead.
        assert_eq!(getdate("Jan 20011231"), None);
    }

    #[test]
    fn the_gregorian_floor_is_1583() {
        assert!(getdate("Mon, 01 Jan 1583 00:00:00 GMT").is_some());
        assert_eq!(getdate("Mon, 01 Jan 1582 00:00:00 GMT"), None);
        assert_eq!(getdate("Fri, 01 Jan 1500 00:00:00 GMT"), None);
        // Both sides of the boundary on the same day of the year, so nothing
        // but the year differs.
        assert_eq!(getdate("06-Nov-1583"), Some(-12_185_856_000));
        assert_eq!(getdate("06-Nov-1582"), None);
    }

    #[test]
    fn two_digit_years_pivot_above_seventy() {
        // `if(yearnum > 70)` at `lib/parsedate.c:464` -- a STRICT `>`, so 70
        // itself lands in the 2000s and only 71 upwards lands in the 1900s.
        // Asserted against absolute epochs as well as against the four-digit
        // spellings, because an inverted comparison would still make the two
        // spellings agree with each other if both were wrong.
        assert_eq!(getdate("06-Nov-70"), Some(3_182_457_600)); // 2070
        assert_eq!(getdate("06-Nov-71"), Some(58_233_600)); // 1971
        assert_eq!(getdate("06-Nov-69"), Some(3_150_921_600)); // 2069
        assert_eq!(getdate("06-Nov-99"), Some(941_846_400)); // 1999
        assert_eq!(getdate("01-Jan-70"), getdate("01 Jan 2070"));
        assert_eq!(getdate("01-Jan-71"), getdate("01 Jan 1971"));
        assert_eq!(getdate("01-Jan-69"), getdate("01 Jan 2069"));
        assert_eq!(getdate("01-Jan-99"), getdate("01 Jan 1999"));
        // The pivot applies only below 100, so a three-digit year is taken as
        // written -- and then fails the Gregorian floor.
        assert_eq!(getdate("01-Jan-100"), None);
    }

    #[test]
    fn rfc822_offsets_invert_the_sign_and_stop_at_1400() {
        let base = getdate("Sun, 12 Sep 2004 15:05:58 GMT").unwrap();
        // `+0200` means local time is AHEAD of GMT, so the instant is EARLIER.
        // Absolute values as well as relative ones, because only an epoch
        // assertion catches an inverted sign.
        assert_eq!(
            getdate("Sun, 12 Sep 2004 15:05:58 +0200"),
            Some(base - 2 * 3600)
        );
        assert_eq!(
            getdate("Sun, 12 Sep 2004 15:05:58 -0700"),
            Some(base + 7 * 3600)
        );
        assert_eq!(
            getdate("Sun, 12 Sep 2004 15:05:58 -0700"),
            Some(1_095_026_758)
        );
        assert_eq!(
            getdate("Sat, 11 Sep 2004 21:32:11 +0200"),
            Some(1_094_931_131)
        );
        // Minutes as well as hours: `-0730` is seven and a half hours.
        assert_eq!(
            getdate("Sun, 12 Sep 2004 15:05:58 -0730"),
            Some(base + 7 * 3600 + 30 * 60)
        );
        // Zero is zero with either sign.
        assert_eq!(getdate("Jan 1 2001 +0000"), getdate("Jan 1 2001 GMT"));
        assert_eq!(getdate("Jan 1 2001 -0000"), getdate("Jan 1 2001 GMT"));
    }

    #[test]
    fn the_numeric_zone_needs_four_digits_a_sign_and_a_byte_behind_it() {
        // All four clauses of `lib/parsedate.c:420-424` are exercised
        // separately, because each one alone can make a wrong implementation
        // look right on the common case.
        let gmt = getdate("Jan 1 2001 GMT").unwrap();

        // `val <= 1400` -- the documented ceiling, and one past it.
        assert_eq!(getdate("Jan 1 2001 +1400"), Some(gmt - 14 * 3600));
        assert_eq!(getdate("Jan 1 2001 -1400"), Some(gmt + 14 * 3600));
        assert_eq!(getdate("Jan 1 2001 +1401"), None);

        // A sign is required: the same four digits without one are not a zone,
        // and nothing else in the string can consume them.
        assert_eq!(getdate("Jan 1 2001 0200"), None);
        assert_eq!(getdate("Jan 1 2001 +0200"), Some(gmt - 2 * 3600));

        // `indate < date` -- there must be a byte to look BEHIND. A group at
        // the very start of the string has none, so it is not a zone even
        // though its four digits and its value would otherwise qualify. The
        // signed spelling of the same offset does parse, which is what shows
        // the guard rather than the value is doing the work.
        assert_eq!(getdate("0200 Jan 1 2001"), None);
        assert_eq!(getdate("+0200 Jan 1 2001"), Some(gmt - 2 * 3600));
        assert_eq!(getdate("-0700 Jan 1 2001"), Some(gmt + 7 * 3600));

        // Exactly four digits: three and five are not zones.
        assert_eq!(getdate("Jan 1 2001 +200"), None);
        assert_eq!(getdate("Jan 1 2001 +02000"), None);

        // `tzoff == -1` -- only the FIRST zone wins, so a named zone already
        // seen means the digits are not read as an offset.
        assert_eq!(getdate("Jan 1 2001 GMT +0200"), None);
    }

    #[test]
    fn named_zones_resolve_to_their_table_offsets() {
        let gmt = getdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        let with =
            |zone: &str| getdate(&format!("Sun, 06 Nov 1994 08:49:37 {zone}"));
        // Zero-offset spellings.
        for zone in ["GMT", "UT", "UTC", "WET", "Z"] {
            assert_eq!(with(zone), Some(gmt), "{zone}");
        }
        // Westward offsets are positive minutes, so the instant is LATER.
        assert_eq!(with("EST"), Some(gmt + 300 * 60));
        assert_eq!(with("AHST"), Some(gmt + 600 * 60));
        // Eastward offsets are negative, so earlier.
        assert_eq!(with("CET"), Some(gmt - 60 * 60));
        assert_eq!(with("IDLE"), Some(gmt - 720 * 60));
        // Daylight names add TDAYZONE, which is negative.
        assert_eq!(with("EDT"), Some(gmt + i64::from(300 + TDAYZONE) * 60));
        assert_eq!(with("PDT"), Some(gmt + i64::from(480 + TDAYZONE) * 60));
        assert_eq!(with("NZDT"), Some(gmt + i64::from(-720 + TDAYZONE) * 60));
        // Military letters, at both ends of the ladder and at the pivot.
        assert_eq!(with("A"), Some(gmt + 60 * 60));
        assert_eq!(with("M"), Some(gmt + 720 * 60));
        assert_eq!(with("N"), Some(gmt - 60 * 60));
        assert_eq!(with("Y"), Some(gmt - 720 * 60));
        // `J` is deliberately not a zone at all, so the string fails.
        assert_eq!(with("J"), None);
        // Nor is an invented name.
        assert_eq!(with("XYZ"), None);
    }

    #[test]
    fn every_zone_in_the_table_is_reachable_through_the_parser() {
        // Sweeping the whole table rather than sampling it: a transcription
        // slip in any one of the 69 rows shows up here as an offset that does
        // not match the entry, and `J`'s absence is confirmed against the same
        // sweep rather than asserted separately.
        let gmt = getdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        for zone in &TZ {
            let input = format!("Sun, 06 Nov 1994 08:49:37 {}", zone.name);
            assert_eq!(
                getdate(&input),
                Some(gmt + i64::from(zone.offset) * 60),
                "{}",
                zone.name
            );
        }
        assert!(
            !TZ.iter().any(|zone| zone.name == "J"),
            "J must not be in the table"
        );
        assert_eq!(getdate("Sun, 06 Nov 1994 08:49:37 J"), None);
    }

    #[test]
    fn separators_are_irrelevant_and_case_is_ignored() {
        let want = getdate("6 Nov 1994").unwrap();
        for input in [
            "1994.Nov.6",
            "1994/Nov/6",
            "1994-Nov-6",
            "1994 Nov 6",
            "1994,,,Nov,,,6",
            "...1994...Nov...6...",
        ] {
            assert_eq!(getdate(input), Some(want), "{input:?}");
        }
        let want = getdate("Thu, 1 Jan 2004 00:00:00 GMT").unwrap();
        for input in [
            "THU, 01 JAN 2004 00:00:00 GMT",
            "thu, 01 jan 2004 00:00:00 gmt",
            "Thu, 01 Jan 2004 00:00:00 GmT",
            "Thu,  1  Jan  2004  00:00:00  GMT",
        ] {
            assert_eq!(getdate(input), Some(want), "{input:?}");
        }
    }

    #[test]
    fn the_case_fold_is_ascii_only() {
        // `ncasecompare` is curl's `curl_strnequal`, which folds the
        // twenty-six ASCII letters and NOTHING else.
        assert_eq!(getdate("sun, 06 nov 1994"), getdate("Sun, 06 Nov 1994"));
        assert_eq!(getdate("SUN, 06 NOV 1994"), getdate("Sun, 06 Nov 1994"));

        // A byte above ASCII is not a letter to `is_alnum`, so it SEPARATES
        // tokens rather than joining them: the run before it is measured on its
        // own. `Ja` is two bytes long, which matches no month.
        assert_eq!(getdate("Ja\u{f1} 6 1994"), None);
        // But it is a separator like any other, so a complete token followed by
        // one still parses.
        assert_eq!(getdate("Sun\u{f1}, 06 Nov 1994"), getdate("6 Nov 1994"));

        // The precise trap a Unicode-aware fold would fall into: U+212A KELVIN
        // SIGN folds to `k` under Unicode's rules, and `K` is the Kilo military
        // zone. It must NOT match, while the ASCII spelling must.
        assert_eq!(checktz("\u{212a}".as_bytes()), None);
        assert_eq!(checktz(b"k"), Some(10 * 60 * 60));
        assert_eq!(checktz(b"K"), Some(10 * 60 * 60));
        // U+017F LATIN SMALL LETTER LONG S folds to `s` under Unicode; `S` is
        // the Sierra zone.
        assert_eq!(checktz("\u{17f}".as_bytes()), None);
        assert_eq!(checkmonth("\u{17f}ep".as_bytes()), None);
        assert_eq!(checkmonth(b"sep"), Some(8));
    }

    #[test]
    fn only_the_first_six_parts_are_examined() {
        // `while(*date && (part < 6))` at `lib/parsedate.c:362`. A full RFC
        // 1123 date uses exactly six parts -- weekday, day, month, year, time,
        // zone -- so a SEVENTH token is never looked at, and rubbish there is
        // harmless.
        let complete = getdate("Sun 06 Nov 1994 08:49:37 GMT").unwrap();
        assert_eq!(
            getdate("Sun 06 Nov 1994 08:49:37 GMT Frobuary"),
            Some(complete)
        );
        assert_eq!(
            getdate("Sun 06 Nov 1994 08:49:37 GMT 99999999999"),
            Some(complete)
        );
        // The contrast is what proves the cap rather than a lenient parser:
        // the SAME rubbish as the sixth part is fatal, because the loop still
        // examines it.
        assert_eq!(getdate("Sun 06 Nov 1994 08:49:37 Frobuary"), None);
        assert_eq!(getdate("Sun 06 Nov 1994 08:49:37 99999999999"), None);
    }

    #[test]
    fn alphabetic_tokens_must_match_a_table() {
        // `if(!found) return PARSEDATE_FAIL;` at `lib/parsedate.c:395-396`. A
        // word that is not a weekday, a month or a zone fails the whole date,
        // however well-formed the rest of it is.
        for input in [
            "Frobuary 6 1994",
            "Sund, 06 Nov 1994",
            "Sun, 06 Frobuary 1994",
            "Nowember 6 1994",
        ] {
            assert_eq!(getdate(input), None, "{input:?}");
        }
        // A run that REACHES NAME_LEN has all three lookups skipped, so it
        // fails even if a prefix of it would have matched.
        assert_eq!("Wednesdayyyy".len(), NAME_LEN);
        assert_eq!(getdate("Wednesdayyyy 06 Nov 1994"), None);
        assert_eq!("Abcdefghijkl".len(), NAME_LEN);
        assert_eq!(getdate("Abcdefghijkl 6 Nov 1994"), None);
        // One byte shorter is looked up, and still matches nothing here.
        assert_eq!(getdate("Wednesdayyy 06 Nov 1994"), None);
        // While the full name itself, nine characters, does match.
        assert_eq!(
            getdate("Wednesday, 06-Nov-1994 08:49:37 GMT"),
            Some(784_111_777)
        );
    }

    #[test]
    fn a_trailing_colon_yields_hh_mm_rather_than_failing() {
        // The `else` arm of `lib/parsedate.c:318-321`.
        assert_eq!(getdate("Dec 31 2001 12:30:"), getdate("Dec 31 2001 12:30"));
        // But a colon FOLLOWED by an out-of-range value does fail.
        assert_eq!(getdate("Dec 31 2001 23:59:61"), None);
        assert!(getdate("Dec 31 2001 23:59:60").is_some());
    }

    #[test]
    fn the_time_is_optional_and_its_absence_means_midnight() {
        // `if(-1 == secnum) secnum = minnum = hournum = 0;` at `:483-484`.
        let midnight = getdate("6 Nov 1994 00:00:00 GMT").unwrap();
        for input in [
            "6 Nov 1994",
            "06-Nov-94",
            "1994 Nov 6",
            "Sun Nov 6 94",
            "Sun, 06 Nov 1994 GMT",
            "1994.Nov.6",
        ] {
            assert_eq!(getdate(input), Some(midnight), "{input:?}");
        }
        assert_eq!(midnight, 784_080_000);
        // Only the seconds field is tested, so all three are zeroed together
        // and a time cannot be half-present.
        assert_eq!(
            getdate("6 Nov 1994 08:49"),
            Some(midnight + 8 * 3600 + 49 * 60)
        );
    }

    #[test]
    fn vital_information_is_required() {
        // `:486-490` -- day, month and year must all be present.
        for input in [
            "",
            "   ",
            ",,,,",
            ":::",
            "+",
            "-",
            "1",
            "Nov",
            "1994",
            "Nov 1994",
            "6 Nov",
            "00:00:00",
            "1994 08:49:37",
        ] {
            assert_eq!(getdate(input), None, "{input:?}");
        }
        // Two of the three is still not enough, in either order.
        assert_eq!(getdate("6 Nov"), None);
        assert_eq!(getdate("Nov 1994"), None);
        assert_eq!(getdate("6 1994"), None);
        // All three, in any order, is.
        assert!(getdate("6 Nov 1994").is_some());
        assert!(getdate("1994 Nov 6").is_some());
        assert!(getdate("Nov 6 1994").is_some());
    }

    #[test]
    fn illegal_field_values_are_rejected() {
        // `:526-528`, every test a `>`.
        assert_eq!(getdate("Jan 32 2001"), None); // day 32
        assert_eq!(getdate("Jan 0 2001"), None); // day 0 is not a day
        assert_eq!(getdate("20011301"), None); // month 13 via YYYYMMDD
        assert_eq!(getdate("Dec 31 2001 24:00:00"), None); // hour 24
        assert_eq!(getdate("Dec 31 2001 12:60:00"), None); // minute 60
        assert_eq!(getdate("Dec 31 2001 23:59:61"), None); // second 61

        // The day is NOT validated against the length of the month, and 60
        // seconds IS allowed. Both match C, and both are asserted so that a
        // later "fix" has to argue with a test.
        assert!(getdate("Feb 30 2001 12:00:00").is_some());
        assert!(getdate("Feb 29 1900 12:00:00").is_some());
        assert!(getdate("Dec 31 2001 23:59:60").is_some());
    }

    #[test]
    fn a_number_wider_than_eight_significant_digits_fails() {
        // `curlx_str_number(&p, &lval, 99999999)` at `:413`: exceeding the cap
        // is an ERROR rather than a truncation, so the whole date fails.
        assert!(getdate("Jan 1 99999999").is_some());
        assert_eq!(getdate("Jan 1 999999999"), None);
        // Leading zeroes are accepted and DO count toward the digit width,
        // which is why the C's comment about eight digits is optimistic -- and
        // why a nine-character run of mostly zeroes is still a valid day.
        assert_eq!(getdate("000000001 Jan 2001"), getdate("1 Jan 2001"));
        // Nine digits that are not mostly zeroes is a different matter.
        assert_eq!(getdate("999999999 Jan 1"), None);
    }

    #[test]
    fn the_saturating_branch_is_unreachable_on_a_64_bit_time_t() {
        // Asserted rather than assumed, because a test that CLAIMED to
        // exercise saturation while silently taking the ordinary path would be
        // worse than no test. The largest instant the parser can build is
        // bounded by MAX_NUMBER, and it is nowhere near TIME_T_MAX.
        let widest = time2epoch(60, 59, 23, 31, 11, 99_999_999);
        assert_eq!(widest, 3_155_633_032_780_800);
        let largest_offset = i64::from(
            TZ.iter()
                .map(|zone| zone.offset)
                .max()
                .expect("TZ non-empty"),
        ) * 60;
        assert!(
            widest < TIME_T_MAX - largest_offset,
            "if this ever fails, Outcome::Later became reachable and needs a \
             real test: widest={widest} offset={largest_offset}"
        );
        // So every success is Ok, never Later, even at the extreme. Both
        // values below came from the C `curl_getdate`, not from this file.
        assert_eq!(
            parsedate(b"Jan 1 99999999 GMT"),
            Outcome::Ok(3_155_633_001_244_800)
        );
        assert_eq!(
            parsedate(b"Dec 31 99999999 23:59:60 GMT"),
            Outcome::Ok(3_155_633_032_780_800)
        );
        assert_eq!(parsedate(b"Jan 1 2001 GMT"), Outcome::Ok(978_307_200));
    }

    #[test]
    fn getdate_capped_differs_from_getdate_in_the_two_documented_ways() {
        // Both agree on ordinary input, and the capped form applies no `-1`
        // adjustment, which is the observable difference on these targets.
        assert_eq!(getdate_capped("20011231"), Some(1_009_756_800));
        assert_eq!(getdate_capped("Wed, 31 Dec 1969 23:59:59 GMT"), Some(-1));
        assert_eq!(getdate("Wed, 31 Dec 1969 23:59:59 GMT"), Some(0));
        // It returns "no value" ONLY for a genuine parse failure, which is the
        // C's `return (rc == PARSEDATE_FAIL);`. Every rejected row of the
        // oracle is a parse failure on these targets, so the two entry points
        // must agree about which strings are unparsable.
        for &(input, expected) in ORACLE {
            assert_eq!(
                getdate_capped(input).is_none(),
                expected == -1,
                "{input:?}"
            );
        }
        // And a saturated value would be a success here and a failure there.
        // The branch is unreachable on these targets, so the difference is
        // asserted on the outcome model instead of through a date string.
        assert_eq!(
            match Outcome::Later(TIME_T_MAX) {
                Outcome::Ok(t) | Outcome::Later(t) => Some(t),
                Outcome::Fail => None,
            },
            Some(TIME_T_MAX)
        );
    }

    #[test]
    fn a_nul_terminates_the_string_as_it_does_in_c() {
        // A Rust caller can pass an interior NUL where a CStr cannot. C stops
        // there, so the trailing text must be invisible.
        assert_eq!(
            getdate("6 Nov 1994\0junk that would fail"),
            getdate("6 Nov 1994")
        );
        assert_eq!(parsedate(b"\0 6 Nov 1994"), Outcome::Fail);
        assert_eq!(
            parsedate(b"6 Nov 1994\0Frobuary"),
            Outcome::Ok(784_080_000)
        );
    }

    #[test]
    fn the_name_tables_have_the_shapes_the_c_tree_exports() {
        assert_eq!(WKDAY.len(), 7);
        assert_eq!(MONTH.len(), 12);
        assert_eq!(WEEKDAY.len(), 7);
        assert_eq!(TZ.len(), 69, "lib/parsedate.c declares 69 zones");
        assert_eq!(MONTH_DAYS_CUMULATIVE.len(), 12);
        assert!(
            WKDAY.iter().all(|name| name.len() == 3),
            "Curl_wkday holds only abbreviations"
        );
        assert!(
            MONTH.iter().all(|name| name.len() == 3),
            "Curl_month holds only abbreviations"
        );
        // Monday first, NOT the tm_wday convention: index 0 is Monday and
        // index 6 is Sunday in both weekday tables.
        assert_eq!(WKDAY[0], "Mon");
        assert_eq!(WKDAY[6], "Sun");
        assert_eq!(WEEKDAY[0], "Monday");
        assert_eq!(WEEKDAY[6], "Sunday");
        // Months are 0-based, matching tm_mon.
        assert_eq!(MONTH[0], "Jan");
        assert_eq!(MONTH[11], "Dec");
        // `struct tzinfo`'s `char name[5]` bounds every entry at four bytes,
        // which is what lets checktz reject on length alone.
        assert_eq!(TZ.iter().map(|zone| zone.name.len()).max(), Some(4));
        assert!(TZ.iter().all(|zone| !zone.name.is_empty()));
        // Every abbreviation must prefix its full name, or one of the two
        // tables was transcribed wrongly.
        for (short, long) in WKDAY.iter().zip(WEEKDAY.iter()) {
            assert!(long.starts_with(short), "{short} vs {long}");
        }
        // No duplicate zone name, which would make lookup order significant.
        for (index, first) in TZ.iter().enumerate() {
            for second in TZ.iter().skip(index + 1) {
                assert_ne!(first.name, second.name, "duplicate {}", first.name);
            }
        }
        // The cumulative days are strictly increasing and end where a
        // non-leap year's December begins.
        for pair in MONTH_DAYS_CUMULATIVE.windows(2) {
            assert!(pair[1] > pair[0], "{pair:?}");
        }
        assert_eq!(MONTH_DAYS_CUMULATIVE[0], 0);
        assert_eq!(MONTH_DAYS_CUMULATIVE[11], 334);
    }

    #[test]
    fn the_name_matchers_require_an_exact_length() {
        assert_eq!(checkday(b"Mon"), Some(0));
        assert_eq!(checkday(b"Sun"), Some(6));
        assert_eq!(checkday(b"Sunday"), Some(6));
        assert_eq!(checkday(b"sUnDaY"), Some(6));
        assert_eq!(checkday(b"Wednesday"), Some(2));
        // Shorter than three matches nothing; longer than three is compared
        // only against the FULL names and must match one exactly.
        assert_eq!(checkday(b""), None);
        assert_eq!(checkday(b"S"), None);
        assert_eq!(checkday(b"Su"), None);
        assert_eq!(checkday(b"Sund"), None);
        assert_eq!(checkday(b"Sunda"), None);
        assert_eq!(checkday(b"Sundayss"), None);
        assert_eq!(checkday(b"Wednesdayy"), None);
        assert_eq!(checkday(b"Wednesdayyy"), None);
        // Months must be exactly three letters.
        assert_eq!(checkmonth(b"Jan"), Some(0));
        assert_eq!(checkmonth(b"Nov"), Some(10));
        assert_eq!(checkmonth(b"nov"), Some(10));
        assert_eq!(checkmonth(b"Dec"), Some(11));
        assert_eq!(checkmonth(b"No"), None);
        assert_eq!(checkmonth(b"Nove"), None);
        assert_eq!(checkmonth(b"November"), None, "months must be 3 letters");
        assert_eq!(checkmonth(b"January"), None);
        // Zones: at most four bytes, exact length.
        assert_eq!(checktz(b"GMT"), Some(0));
        assert_eq!(checktz(b"EST"), Some(300 * 60));
        assert_eq!(checktz(b"AHST"), Some(600 * 60));
        assert_eq!(checktz(b"Z"), Some(0));
        assert_eq!(checktz(b"ZZZZZ"), None, "longer than any zone name");
        assert_eq!(checktz(b"GM"), None);
        assert_eq!(checktz(b"GMTT"), None);
        assert_eq!(checktz(b""), None);
        assert_eq!(checktz(b"J"), None, "J is not a zone");
        // The offset really is returned in SECONDS while the table holds
        // MINUTES, which is the one place the two units meet.
        assert_eq!(checktz(b"EDT"), Some((300 + TDAYZONE) * 60));
        assert_eq!(checktz(b"CET"), Some(-60 * 60));
    }

    #[test]
    fn match_time_accepts_single_digits_and_a_leap_second() {
        assert_eq!(match_time(b"08:49:37", 0), Some((8, 49, 37, 8)));
        assert_eq!(match_time(b"1:2:3", 0), Some((1, 2, 3, 5)));
        assert_eq!(match_time(b"12:30", 0), Some((12, 30, 0, 5)));
        // A trailing colon leaves the index AT the colon.
        assert_eq!(match_time(b"12:30:", 0), Some((12, 30, 0, 5)));
        // `ss <= 60` admits a leap second; 61 does not reach the `else`.
        assert_eq!(match_time(b"23:59:60", 0), Some((23, 59, 60, 8)));
        assert_eq!(match_time(b"23:59:61", 0), None);
        assert_eq!(match_time(b"24:00:00", 0), None);
        assert_eq!(match_time(b"12:60:00", 0), None);
        assert_eq!(match_time(b"23:59", 0), Some((23, 59, 0, 5)));
        assert_eq!(match_time(b"00:00", 0), Some((0, 0, 0, 5)));
        // No colon at all is not a time, and neither is a colon with nothing
        // after it.
        assert_eq!(match_time(b"12", 0), None);
        assert_eq!(match_time(b"12:", 0), None);
        assert_eq!(match_time(b"12:x", 0), None);
        assert_eq!(match_time(b"", 0), None);
        // Matching from a non-zero index, as the parser does.
        assert_eq!(match_time(b"Nov 6 08:49:37", 6), Some((8, 49, 37, 14)));
    }

    #[test]
    fn oneortwodigit_takes_a_second_digit_only_when_there_is_one() {
        assert_eq!(oneortwodigit(b"7", 0), (7, 1));
        assert_eq!(oneortwodigit(b"37", 0), (37, 2));
        assert_eq!(oneortwodigit(b"377", 0), (37, 2));
        assert_eq!(oneortwodigit(b"7x", 0), (7, 1));
        assert_eq!(oneortwodigit(b"09", 0), (9, 2));
        assert_eq!(oneortwodigit(b"x9", 1), (9, 2));
        // Total for an index the C would never pass: no panic, no wrap.
        assert_eq!(oneortwodigit(b"", 0), (0, 1));
        assert_eq!(oneortwodigit(b"x", 0), (0, 1));
    }

    #[test]
    fn time2epoch_agrees_with_known_instants() {
        // Month is 0-based, as it is throughout the C parser.
        assert_eq!(time2epoch(0, 0, 0, 1, 0, 1970), 0);
        assert_eq!(time2epoch(37, 49, 8, 6, 10, 1994), 784_111_777);
        assert_eq!(time2epoch(7, 14, 3, 19, 0, 2038), 2_147_483_647);
        // A January date exercises the `mon <= 1` borrow, and December of the
        // previous year must be exactly one day earlier.
        assert_eq!(
            time2epoch(0, 0, 0, 1, 0, 2000) - time2epoch(0, 0, 0, 31, 11, 1999),
            86_400
        );
        // A leap day, and the day after, one apart.
        let feb29 = time2epoch(0, 0, 0, 29, 1, 2000);
        let mar01 = time2epoch(0, 0, 0, 1, 2, 2000);
        assert_eq!(mar01 - feb29, 86_400);
        // 1900 was not a leap year and 2000 was: the century and the
        // four-hundred-year rules are both exercised.
        assert_eq!(
            time2epoch(0, 0, 0, 1, 2, 1900) - time2epoch(0, 0, 0, 28, 1, 1900),
            86_400
        );
        // 2100 is not a leap year either, which is the century rule again on
        // the far side of the epoch.
        assert_eq!(
            time2epoch(0, 0, 0, 1, 2, 2100) - time2epoch(0, 0, 0, 28, 1, 2100),
            86_400
        );
        assert_eq!(
            time2epoch(0, 0, 0, 1, 2, 2000) - time2epoch(0, 0, 0, 28, 1, 2000),
            2 * 86_400
        );
        // Pre-1970 is negative and the arithmetic stays exact.
        assert_eq!(time2epoch(59, 59, 23, 31, 11, 1969), -1);
        assert_eq!(time2epoch(0, 0, 0, 1, 0, 1583), -12_212_553_600);
        // Total for a month index the parser can never produce: the fallback
        // substitutes zero cumulative days rather than panicking.
        assert_eq!(
            time2epoch(0, 0, 0, 1, 12, 2000),
            time2epoch(0, 0, 0, 1, 0, 2000) + 86_400
        );
    }

    #[test]
    fn skip_passes_everything_that_is_not_alphanumeric() {
        assert_eq!(skip(b"...abc", 0), 3);
        assert_eq!(skip(b"abc", 0), 0);
        assert_eq!(skip(b", , , ", 0), 6, "runs off the end cleanly");
        assert_eq!(skip(b"", 0), 0);
        assert_eq!(skip(b"", 99), 99);
        assert_eq!(skip(b"+-*/9", 0), 4);
        // A byte above ASCII is a separator, because `is_alnum` is
        // `lib/curl_ctype.h`'s three range tests and nothing more.
        assert_eq!(skip(&[0xff, 0x80, b'A'], 0), 2);
        // Starting past the end is not an error.
        assert_eq!(skip(b"abc", 9), 9);
    }

    #[test]
    fn at_reports_zero_past_the_end_like_a_nul_terminator() {
        assert_eq!(at(b"ab", 0), b'a');
        assert_eq!(at(b"ab", 1), b'b');
        assert_eq!(at(b"ab", 2), 0);
        assert_eq!(at(b"ab", 9999), 0);
        assert_eq!(at(b"", 0), 0);
        assert_eq!(digit_at(b"7", 0), 7);
        assert_eq!(digit_at(b"x", 0), 0);
        assert_eq!(digit_at(b"", 0), 0);
    }

    #[test]
    fn hostile_and_truncated_input_never_panics() {
        // Date strings arrive from remote servers through `Last-Modified`,
        // `Set-Cookie` and `Alt-Svc`, so every index in this file must be
        // checked. Two sweeps: every prefix of a well-formed date, and a
        // corpus of shapes chosen to sit on a boundary.
        let full = b"Sun, 06 Nov 1994 08:49:37 +0200";
        for end in 0..=full.len() {
            let _ = parsedate(&full[..end]);
        }
        for probe in [
            &b""[..],
            b"\0",
            b"\0\0\0",
            b":",
            b"::",
            b"+",
            b"-",
            b"+0",
            b"+00",
            b"+000",
            b"+0000",
            b"9",
            b"99",
            b"999999999999999999999999",
            b"0000000000000000000000001 Jan 2001",
            b"Jan 1 2001 99:99:99",
            b"Jan 1 2001 0:0:0",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"AAAA AAAA AAAA AAAA AAAA AAAA AAAA",
            b"1 1 1 1 1 1 1 1 1 1",
            b"\xff\xfe\xfd",
            b"Sun\xff\xff\xff",
            b"\x80Jan\x801\x802001",
            b"Jan 1 2001 \0 +0200",
            b"-------",
            b"1994-11-06T08:49:37Z",
            b"Nov 6 1994 08:49:37.123456",
        ] {
            let _ = parsedate(probe);
        }
        // Every byte value, alone and as a one-byte token after a valid date,
        // so that no single byte can reach an unchecked index.
        for byte in 0u8..=255 {
            let _ = parsedate(&[byte]);
            let _ = parsedate(&[b'6', b' ', b'N', b'o', b'v', b' ', byte]);
            let _ = parsedate(&[byte, b'0', b'2', b'0', b'0', b' ', b'J']);
        }
    }
}
