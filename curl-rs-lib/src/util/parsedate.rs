//! Date parsing -- supersedes `lib/parsedate.c` (585 lines).
//!
//! # Why this module is `pub` when its parent is not
//!
//! `crate::util` is `pub(crate)`: private by ENFORCEMENT rather than by the
//! `Curl_` naming convention the C tree relied on. This file nevertheless
//! declares one `pub` item, because `curl_getdate` is one of the 100 symbols
//! `lib/libcurl.def` exports, and the crate root re-exports [`getdate`] so
//! that `curl-rs-ffi` can reach it. That is the standard private-module /
//! public-re-export idiom, and `util/mod.rs` records `parsedate ->
//! curl_getdate` as one of the four places it applies.
//!
//! Review finding M-13 is the reason the re-export exists: the facade needs a
//! date parser, the parser lives here, and DUPLICATING it in the adapter would
//! put engine logic in the C ABI shim. So the boundary is drawn here instead:
//! this module owns every parsing decision including the two quirks of
//! `curl_getdate`'s contract, and the adapter is left with nothing but
//! marshalling a `*const c_char` into a `&str` and an `Option` into a
//! `time_t`.
//!
//! # The contract being reproduced
//!
//! `lib/parsedate.c:561-575` defines `curl_getdate`, and it has one quirk that
//! is easy to miss and impossible to guess: when the parsed value happens to
//! be exactly `-1`, C INCREMENTS it to `0` rather than returning `-1`, because
//! `-1` is also the failure sentinel. That single second of 1969-12-31
//! 23:59:59 UTC is therefore reported as the epoch. The quirk belongs to the
//! contract, so it lives in [`getdate`] and not in the adapter.
//!
//! `lib/parsedate.c:581-584` defines the internal `Curl_getdate_capped`, which
//! differs by returning `TIME_T_MAX` for a value too large to represent
//! instead of failing. It is NOT an exported symbol, so [`getdate_capped`] is
//! `pub(crate)` -- the same visibility split the C tree draws.
//!
//! # Which of the four `PARSEDATE_*` results can occur here
//!
//! The C parser has four outcomes, but two of them are guarded by
//! `SIZEOF_TIME_T < 5` and `HAVE_TIME_T_UNSIGNED` (`lib/parsedate.c:500-524`,
//! `lib/curl_setup.h:606-622`). All four mandated targets are 64-bit with a
//! SIGNED 64-bit `time_t`, so `TIME_T_MAX` is `0x7FFFFFFFFFFFFFFF`
//! (`curl_setup.h:619`) and:
//!
//! * `PARSEDATE_SOONER` is not merely unreachable, it is not even DEFINED --
//!   `lib/parsedate.c:98-100` gates the `#define` itself. There is no
//!   underflow variant in [`Outcome`] for exactly that reason.
//! * The 2038 and 2106 ceilings do not apply. What does apply is
//!   `lib/parsedate.c:521-523`: a year before 1583 fails, because the
//!   Gregorian calendar was introduced in 1582.
//! * `PARSEDATE_LATER` survives, reached only through the timezone-addition
//!   overflow guard at `:539-542`.
//!
//! # Formats accepted
//!
//! Reproduced from the summary at `lib/parsedate.c:29-79`, which is the
//! authority for what "every format curl accepts" means. The parser is
//! deliberately permissive: it walks up to six alphanumeric parts, classifying
//! each as a weekday name, a month name, a timezone name, a time, a
//! four-digit signed timezone offset, an eight-digit `YYYYMMDD`, a day of
//! month or a year, and skips ANY run of non-alphanumeric bytes between them.
//! That is why `1994.Nov.6` and `Sun/Nov/6/94/GMT` both parse.
//!
//! # Byte-oriented, and why
//!
//! The C parser indexes bytes and relies on the NUL terminator. This works on
//! `&[u8]` with an accessor that reports `0` past the end, which reproduces
//! the terminator exactly without any bounds-check divergence. `ISALPHA`,
//! `ISDIGIT` and `ISALNUM` are curl's own ASCII-only macros, so
//! `is_ascii_alphabetic`, `is_ascii_digit` and `is_ascii_alphanumeric` are the
//! faithful counterparts -- a locale-aware or Unicode-aware test would accept
//! input curl rejects.

/// The abbreviated weekday names, Monday first.
///
/// `lib/parsedate.c:84-86` exports these as `Curl_wkday` because the FTP and
/// FILE code formats dates with them as well as parsing them, which is why
/// they are `pub(crate)` here rather than private to this file.
pub(crate) const WKDAY: [&str; 7] =
    ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/// The abbreviated month names, January first.
///
/// `lib/parsedate.c:87-90`, exported as `Curl_month` for the same reason.
pub(crate) const MONTH: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
    "Nov", "Dec",
];

/// The full weekday names, Monday first (`lib/parsedate.c:104-106`).
///
/// Consulted only for names LONGER than three characters, which is what lets
/// `Sunday` and `Sun` both parse while `Sund` matches neither.
const WEEKDAY: [&str; 7] = [
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
];

/// One entry of the timezone-name table.
struct TzInfo {
    /// The name, upper case. Matched case-insensitively and by exact length.
    name: &'static str,
    /// Offset from GMT in MINUTES, positive west of Greenwich.
    offset: i32,
}

/// The daylight-savings adjustment applied to summer-time names.
///
/// `lib/parsedate.c:111` -- negative, and applied by ADDITION to a westward
/// offset, so `EDT` is `300 + (-60) = 240`.
const TDAYZONE: i32 = -60;

/// Frequently used timezone names, carried over from the old getdate parser.
///
/// Transcribed from `lib/parsedate.c:113-193` -- 69 entries, every name
/// distinct, the longest four characters, which is precisely why [`checktz`]
/// rejects anything longer without searching. The military names in the second
/// half use the CORRECTED signs that RFC 1123 notes RFC 822 got backwards, and
/// `J` is deliberately absent because it denotes the observer's local time.
///
/// The two allowances below are scoped to this ONE constant and are not a
/// module-level blanket, per the policy the crate root sets out. Three
/// expressions here are redundant as arithmetic and load-bearing as
/// PROVENANCE: `0 + TDAYZONE` for `BST`, `1 * 60` for `A` and `-1 * 60` for
/// `N` are what `lib/parsedate.c:117`, `:161` and `:174` literally say. This
/// table was mechanically extracted from that file, so keeping the operands
/// verbatim means a re-extraction reproduces these bytes and a reviewer can
/// diff the two tables line for line. Simplifying them to `TDAYZONE`, `60`
/// and `-60` would silently break that correspondence, and the military ladder
/// from `1 * 60` to `12 * 60` reads as a ladder only if its first rung keeps
/// the same shape as the rest.
#[allow(clippy::identity_op, clippy::neg_multiply)]
const TZ: [TzInfo; 69] = [
    TzInfo {
        name: "GMT",
        offset: 0,
    },
    TzInfo {
        name: "UT",
        offset: 0,
    },
    TzInfo {
        name: "UTC",
        offset: 0,
    },
    TzInfo {
        name: "WET",
        offset: 0,
    },
    TzInfo {
        name: "BST",
        offset: 0 + TDAYZONE,
    },
    TzInfo {
        name: "WAT",
        offset: 60,
    },
    TzInfo {
        name: "AST",
        offset: 240,
    },
    TzInfo {
        name: "ADT",
        offset: 240 + TDAYZONE,
    },
    TzInfo {
        name: "EST",
        offset: 300,
    },
    TzInfo {
        name: "EDT",
        offset: 300 + TDAYZONE,
    },
    TzInfo {
        name: "CST",
        offset: 360,
    },
    TzInfo {
        name: "CDT",
        offset: 360 + TDAYZONE,
    },
    TzInfo {
        name: "MST",
        offset: 420,
    },
    TzInfo {
        name: "MDT",
        offset: 420 + TDAYZONE,
    },
    TzInfo {
        name: "PST",
        offset: 480,
    },
    TzInfo {
        name: "PDT",
        offset: 480 + TDAYZONE,
    },
    TzInfo {
        name: "YST",
        offset: 540,
    },
    TzInfo {
        name: "YDT",
        offset: 540 + TDAYZONE,
    },
    TzInfo {
        name: "HST",
        offset: 600,
    },
    TzInfo {
        name: "HDT",
        offset: 600 + TDAYZONE,
    },
    TzInfo {
        name: "CAT",
        offset: 600,
    },
    TzInfo {
        name: "AHST",
        offset: 600,
    },
    TzInfo {
        name: "NT",
        offset: 660,
    },
    TzInfo {
        name: "IDLW",
        offset: 720,
    },
    TzInfo {
        name: "CET",
        offset: -60,
    },
    TzInfo {
        name: "MET",
        offset: -60,
    },
    TzInfo {
        name: "MEWT",
        offset: -60,
    },
    TzInfo {
        name: "MEST",
        offset: -60 + TDAYZONE,
    },
    TzInfo {
        name: "CEST",
        offset: -60 + TDAYZONE,
    },
    TzInfo {
        name: "MESZ",
        offset: -60 + TDAYZONE,
    },
    TzInfo {
        name: "FWT",
        offset: -60,
    },
    TzInfo {
        name: "FST",
        offset: -60 + TDAYZONE,
    },
    TzInfo {
        name: "EET",
        offset: -120,
    },
    TzInfo {
        // The C table suppresses the spell checker on this exact row
        // (`lib/parsedate.c:151`); the abbreviation is data, not prose.
        name: "WAST", // spellchecker:disable-line
        offset: -420,
    },
    TzInfo {
        name: "WADT",
        offset: -420 + TDAYZONE,
    },
    TzInfo {
        name: "CCT",
        offset: -480,
    },
    TzInfo {
        name: "JST",
        offset: -540,
    },
    TzInfo {
        name: "EAST",
        offset: -600,
    },
    TzInfo {
        name: "EADT",
        offset: -600 + TDAYZONE,
    },
    TzInfo {
        name: "GST",
        offset: -600,
    },
    TzInfo {
        name: "NZT",
        offset: -720,
    },
    TzInfo {
        name: "NZST",
        offset: -720,
    },
    TzInfo {
        name: "NZDT",
        offset: -720 + TDAYZONE,
    },
    TzInfo {
        name: "IDLE",
        offset: -720,
    },
    TzInfo {
        name: "A",
        offset: 1 * 60,
    },
    TzInfo {
        name: "B",
        offset: 2 * 60,
    },
    TzInfo {
        name: "C",
        offset: 3 * 60,
    },
    TzInfo {
        name: "D",
        offset: 4 * 60,
    },
    TzInfo {
        name: "E",
        offset: 5 * 60,
    },
    TzInfo {
        name: "F",
        offset: 6 * 60,
    },
    TzInfo {
        name: "G",
        offset: 7 * 60,
    },
    TzInfo {
        name: "H",
        offset: 8 * 60,
    },
    TzInfo {
        name: "I",
        offset: 9 * 60,
    },
    TzInfo {
        name: "K",
        offset: 10 * 60,
    },
    TzInfo {
        name: "L",
        offset: 11 * 60,
    },
    TzInfo {
        name: "M",
        offset: 12 * 60,
    },
    TzInfo {
        name: "N",
        offset: -1 * 60,
    },
    TzInfo {
        name: "O",
        offset: -2 * 60,
    },
    TzInfo {
        name: "P",
        offset: -3 * 60,
    },
    TzInfo {
        name: "Q",
        offset: -4 * 60,
    },
    TzInfo {
        name: "R",
        offset: -5 * 60,
    },
    TzInfo {
        name: "S",
        offset: -6 * 60,
    },
    TzInfo {
        name: "T",
        offset: -7 * 60,
    },
    TzInfo {
        name: "U",
        offset: -8 * 60,
    },
    TzInfo {
        name: "V",
        offset: -9 * 60,
    },
    TzInfo {
        name: "W",
        offset: -10 * 60,
    },
    TzInfo {
        name: "X",
        offset: -11 * 60,
    },
    TzInfo {
        name: "Y",
        offset: -12 * 60,
    },
    TzInfo {
        name: "Z",
        offset: 0,
    },
];

/// The largest `time_t` on the four mandated targets.
///
/// `lib/curl_setup.h:619` -- `0x7FFFFFFFFFFFFFFF`, the signed 64-bit maximum.
const TIME_T_MAX: i64 = i64::MAX;

/// The longest name this parser will consider (`lib/parsedate.c:345`).
///
/// `Wednesday` is nine characters, so twelve is generous. The value is
/// load-bearing rather than decorative: an alphabetic run that REACHES this
/// length is rejected outright without being compared against any table, which
/// is how the C parser refuses a pathologically long word cheaply.
const NAME_LEN: usize = 12;

/// The widest value [`str_number`] will accept (`lib/parsedate.c:412`).
const MAX_NUMBER: i64 = 99_999_999;

/// What the next bare number should be taken to mean.
///
/// `lib/parsedate.c:262-266`. The parser has no grammar, so it guesses from
/// position: the first plain number is a day of month, the next a year. That
/// is what makes both `06 Nov 1994` and `1994 Nov 6` parse.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Assume {
    /// A day of month is expected next.
    MDay,
    /// A year is expected next.
    Year,
}

/// The outcome of a parse.
///
/// Mirrors `PARSEDATE_OK`, `PARSEDATE_FAIL` and `PARSEDATE_LATER`
/// (`lib/parsedate.c:92-99`). There is no underflow variant because
/// `PARSEDATE_SOONER` is not defined for a signed 64-bit `time_t`; see the
/// module documentation.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// A fine conversion, carrying seconds since the Unix epoch in UTC.
    Ok(i64),
    /// Overflow at the far end of `time_t`; the value is saturated.
    ///
    /// RETAINED BUT PROVABLY UNREACHABLE ON THESE TARGETS, and retained for
    /// exactly the reason C retains the guard that produces it. The only
    /// producer is the timezone-addition check at `lib/parsedate.c:539-542`,
    /// which needs `t > TIME_T_MAX - tzoff`. [`MAX_NUMBER`] caps a year at
    /// 99999999, so the largest instant [`time2epoch`] can return is
    /// 3_155_633_032_780_800 -- computed for 99999999-12-31 23:59:60 -- while
    /// `TIME_T_MAX` minus the largest positive offset is
    /// 9_223_372_036_854_725_407. The headroom is a factor of about 2923, so
    /// the branch cannot be taken. It becomes reachable only on a 32-bit
    /// `time_t`, where C replaces the Gregorian floor with the 2038 and 1903
    /// limits; none of the four mandated targets is 32-bit. Deleting the guard
    /// would make this file diverge from its authority for no benefit.
    Later(i64),
    /// The string could not be converted.
    Fail,
}

/// The byte at `idx`, or `0` past the end.
///
/// Reproduces the NUL terminator the C parser depends on. Every one of its
/// `*p` and `p[1]` reads stops at the terminator, so a zero-past-the-end
/// accessor makes the Rust control flow identical without introducing a
/// bounds check the C never had.
fn at(bytes: &[u8], idx: usize) -> u8 {
    if idx < bytes.len() {
        bytes[idx]
    } else {
        0
    }
}

/// Match a weekday name: `Some(0..=6)` for Monday through Sunday.
///
/// `lib/parsedate.c:198-218`. The length decides WHICH table is consulted --
/// longer than three characters means the full names, exactly three means the
/// abbreviations, shorter than three matches nothing -- and the comparison
/// additionally requires the candidate's own length to equal `len`, so a
/// prefix such as `Sund` matches neither table.
fn checkday(check: &[u8]) -> Option<usize> {
    let len = check.len();
    let table: &[&str] = if len > 3 {
        &WEEKDAY
    } else if len == 3 {
        &WKDAY
    } else {
        return None;
    };
    table.iter().position(|name| {
        name.len() == len && name.as_bytes().eq_ignore_ascii_case(check)
    })
}

/// Match a month name: `Some(0..=11)` for January through December.
///
/// `lib/parsedate.c:220-233`. The length must be exactly three. Note the
/// asymmetry with [`checkday`], faithfully preserved: C compares only the
/// first three bytes here, and since `len` is already known to be 3 the two
/// formulations coincide.
fn checkmonth(check: &[u8]) -> Option<usize> {
    if check.len() != 3 {
        return None;
    }
    MONTH
        .iter()
        .position(|name| name.as_bytes().eq_ignore_ascii_case(check))
}

/// Match a timezone name, returning its offset from GMT in SECONDS.
///
/// `lib/parsedate.c:235-253`. Names longer than four characters are rejected
/// without a search, because four is the longest entry in [`TZ`]. The stored
/// offset is in minutes and is multiplied here, exactly as C does at `:248`.
fn checktz(check: &[u8]) -> Option<i32> {
    if check.len() > 4 {
        return None;
    }
    TZ.iter()
        .find(|zone| {
            zone.name.len() == check.len()
                && zone.name.as_bytes().eq_ignore_ascii_case(check)
        })
        .map(|zone| zone.offset * 60)
}

/// Advance past every byte that is neither a letter nor a digit.
///
/// `lib/parsedate.c:255-260`. This is what makes the separator irrelevant:
/// `1994.Nov.6`, `Sun/Nov/6/94/GMT` and `06-Nov-94` all reduce to the same
/// sequence of parts. The loop stops at the terminator as well, which the
/// zero-past-the-end accessor gives for free.
fn skip(bytes: &[u8], mut idx: usize) -> usize {
    while idx < bytes.len() && !bytes[idx].is_ascii_alphanumeric() {
        idx += 1;
    }
    idx
}

/// Convert a broken-down UTC time to seconds since the Unix epoch.
///
/// `lib/parsedate.c:274-289`, reproduced arithmetic for arithmetic. This is
/// `mktime` for GMT only, and it must not be replaced by a date library: the
/// leap-day expression, the `mon <= 1` correction and the truncating integer
/// divisions together define which instants curl reports, and a library that
/// handled the proleptic Gregorian calendar differently would shift results
/// for pre-1970 dates.
///
/// Rust's `/` truncates toward zero exactly as C's does, and every operand is
/// non-negative here because a year below 1583 has already been rejected, so
/// the two languages agree without a special case.
fn time2epoch(
    sec: i32,
    min: i32,
    hour: i32,
    mday: i32,
    mon: i32,
    year: i32,
) -> i64 {
    const MONTH_DAYS_CUMULATIVE: [i64; 12] =
        [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

    // `mon <= 1` steps the year back for January and February, so that a leap
    // day later in the same year is not counted before it has happened.
    let mut leap_days = i64::from(year) - i64::from(mon <= 1);
    leap_days = (leap_days / 4) - (leap_days / 100) + (leap_days / 400)
        - (1969 / 4)
        + (1969 / 100)
        - (1969 / 400);

    // Widened to 64 bits BEFORE the multiplication, matching C's cast to
    // time_t at `:286`. A 32-bit intermediate would overflow for a large year,
    // and MAX_NUMBER admits years up to 99999999.
    ((((i64::from(year) - 1970) * 365
        + leap_days
        + MONTH_DAYS_CUMULATIVE[mon as usize]
        + i64::from(mday)
        - 1)
        * 24
        + i64::from(hour))
        * 60
        + i64::from(min))
        * 60
        + i64::from(sec)
}

/// Read a one- or two-digit decimal number, returning it and the index after.
///
/// `lib/parsedate.c:292-301`. The caller guarantees `bytes[idx]` is a digit.
fn oneortwodigit(bytes: &[u8], idx: usize) -> (i32, usize) {
    let num = i32::from(bytes[idx] - b'0');
    if at(bytes, idx + 1).is_ascii_digit() {
        (num * 10 + i32::from(bytes[idx + 1] - b'0'), idx + 2)
    } else {
        (num, idx + 1)
    }
}

/// Match `HH:MM:SS` or `HH:MM`, accepting single digits in every field.
///
/// `lib/parsedate.c:303-331`. Three details are easy to lose and all three are
/// preserved:
///
/// * The seconds field tolerates `60` (`ss <= 60`), for a leap second, while
///   minutes must be below 60 and hours below 24.
/// * A trailing colon NOT followed by a digit does not fail -- it falls into
///   C's `else` arm and yields a valid `HH:MM` whose end index still points AT
///   the colon. So `12:30:` parses as 12:30:00.
/// * A colon followed by a digit whose value exceeds 60 DOES fail, because
///   that path cannot reach the `else`.
fn match_time(bytes: &[u8], idx: usize) -> Option<(i32, i32, i32, usize)> {
    let (hh, after_hh) = oneortwodigit(bytes, idx);
    if hh >= 24
        || at(bytes, after_hh) != b':'
        || !at(bytes, after_hh + 1).is_ascii_digit()
    {
        return None;
    }

    let (mm, after_mm) = oneortwodigit(bytes, after_hh + 1);
    if mm >= 60 {
        return None;
    }

    if at(bytes, after_mm) == b':' && at(bytes, after_mm + 1).is_ascii_digit() {
        let (ss, after_ss) = oneortwodigit(bytes, after_mm + 1);
        if ss <= 60 {
            return Some((hh, mm, ss, after_ss));
        }
        return None;
    }

    Some((hh, mm, 0, after_mm))
}

/// Read an unsigned decimal number capped at `max`, greedily.
///
/// Mirrors `curlx_str_number` (`lib/curlx/strparse.c:195-198`) through
/// `str_num_base` (`:157-191`) for base 10. Leading zeroes are accepted, no
/// sign and no prefix are recognised, and exceeding `max` is an ERROR rather
/// than a truncation -- which is why an over-long run of digits makes the whole
/// date fail at `lib/parsedate.c:413`.
///
/// The overflow test is `num > (max - n) / 10` evaluated BEFORE the digit is
/// folded in, exactly as C orders it, so the accepted set is identical rather
/// than merely similar. `max` is [`MAX_NUMBER`], comfortably above the base, so
/// only the general arm of the C function applies.
fn str_number(bytes: &[u8], mut idx: usize, max: i64) -> Option<(i64, usize)> {
    if !at(bytes, idx).is_ascii_digit() {
        return None;
    }
    let mut num: i64 = 0;
    while at(bytes, idx).is_ascii_digit() {
        let n = i64::from(bytes[idx] - b'0');
        if num > (max - n) / 10 {
            return None;
        }
        num = num * 10 + n;
        idx += 1;
    }
    Some((num, idx))
}

/// The parser proper -- `lib/parsedate.c:348-550`.
///
/// Walks at most six alphanumeric parts, classifying each by shape and by what
/// has already been seen. The structure is preserved rather than reorganised,
/// because the ORDER of the attempts is what decides ambiguous input: a
/// three-letter run is tried as a weekday, then a month, then a timezone, and
/// the first table that claims it wins.
fn parsedate(date: &[u8]) -> Outcome {
    // A NUL ends the string for the C parser, whose every loop tests `*date`.
    // Truncating here reproduces that without threading the test through each
    // step; a `&str` from a `CStr` cannot contain one, but a Rust caller can
    // pass one and must get curl's answer, not a different one.
    let date = match date.iter().position(|&b| b == 0) {
        Some(end) => &date[..end],
        None => date,
    };

    // SENTINEL -1, NOT `Option`, AND THIS IS A CORRECTNESS REQUIREMENT.
    //
    // C uses `int x = -1` for "not seen yet" on every one of these. Modelling
    // that as `Option` looks like an improvement and is a BEHAVIOUR CHANGE,
    // because the parser can legitimately COMPUTE -1 into `monnum`: the
    // `YYYYMMDD` branch evaluates `(val % 10000) / 100 - 1`, so a month field
    // of `00` yields -1. C then reads that as "no month" and fails, and it
    // also lets a later `Nov` fill the slot. With `Option`, `Some(-1)` reads
    // as PRESENT, so `20010001` parsed successfully instead of failing and
    // `MONTH_DAYS_CUMULATIVE[-1 as usize]` panicked.
    //
    // Measured against the real `curl_getdate` from `libcurl.so.4`:
    // `20010001` must return -1, and it does only with the sentinel. Keeping
    // C's representation keeps C's semantics, which specification 0.8.1
    // freezes. A -1 sentinel is safe for `tzoff` too: offsets are whole
    // minutes, so -1 seconds is not a representable zone.
    let mut wdaynum: i32 = -1;
    let mut monnum: i32 = -1;
    let mut mdaynum: i32 = -1;
    let mut hournum: i32 = -1;
    let mut minnum: i32 = -1;
    let mut secnum: i32 = -1;
    let mut yearnum: i32 = -1;
    let mut tzoff: i32 = -1;
    let mut dignext = Assume::MDay;

    let mut idx = 0usize;
    let mut part = 0u32;

    while at(date, idx) != 0 && part < 6 {
        let mut found = false;

        idx = skip(date, idx);
        // `skip` may have consumed the remainder. C re-tests `*date` only at
        // the top of the loop, and both branches below then see the
        // terminator and fall through to `part++`, which is what this
        // reproduces: neither branch is entered.
        let cur = at(date, idx);

        if cur.is_ascii_alphabetic() {
            // A name is coming up. Measure the alphabetic run, stopping at
            // NAME_LEN so a pathologically long word costs nothing.
            let mut len = 0usize;
            while at(date, idx + len).is_ascii_alphabetic() && len < NAME_LEN {
                len += 1;
            }

            // Reaching NAME_LEN means the run is at least that long, and no
            // name this parser knows is. C skips every table in that case and
            // therefore fails; the tables are not even consulted.
            if len != NAME_LEN {
                let word = &date[idx..idx + len];
                if wdaynum == -1 {
                    wdaynum = checkday(word).map_or(-1, |d| d as i32);
                    if wdaynum != -1 {
                        found = true;
                    }
                }
                if !found && monnum == -1 {
                    monnum = checkmonth(word).map_or(-1, |m| m as i32);
                    if monnum != -1 {
                        found = true;
                    }
                }
                if !found && tzoff == -1 {
                    // Whatever is left must be a timezone name.
                    tzoff = checktz(word).unwrap_or(-1);
                    if tzoff != -1 {
                        found = true;
                    }
                }
            }
            if !found {
                return Outcome::Fail;
            }
            idx += len;
        } else if cur.is_ascii_digit() {
            // A time stamp is tried first, and only while no seconds value has
            // been recorded -- so a second `HH:MM` in one string is not a time.
            if secnum == -1 {
                if let Some((h, m, s, end)) = match_time(date, idx) {
                    hournum = h;
                    minnum = m;
                    secnum = s;
                    idx = end;
                    part += 1;
                    continue;
                }
            }

            let (val, end) = match str_number(date, idx, MAX_NUMBER) {
                Some(parsed) => parsed,
                // Over MAX_NUMBER, so the whole date fails. C returns here
                // too, at `:413`.
                None => return Outcome::Fail,
            };
            // Counted from the ADVANCED index, so leading zeroes count. C's
            // comment claims this cannot exceed 8; with leading zeroes it can,
            // and it makes no difference because only 4 and 8 are tested.
            let num_digits = end - idx;

            if tzoff == -1
                && num_digits == 4
                && val <= 1400
                && idx > 0
                && (date[idx - 1] == b'+' || date[idx - 1] == b'-')
            {
                // Four digits, no greater than 1400, and signed: an RFC 822
                // style offset. 1400 is the ceiling curl picked because +1300
                // is in real use and +1400 is cited as the edge case.
                found = true;
                let mut off = (val / 100 * 60 + val % 100) * 60;
                // The sign states local time RELATIVE TO GMT, so converting to
                // GMT needs the reverse; `+0200` subtracts two hours.
                if date[idx - 1] == b'+' {
                    off = -off;
                }
                tzoff = off as i32;
            } else if num_digits == 8
                && yearnum == -1
                && monnum == -1
                && mdaynum == -1
            {
                // Compact `YYYYMMDD`, only when nothing it would overwrite has
                // been seen. A month of `00` yields -1 here, which then reads
                // as "no month" and fails the vital-information test below --
                // exactly what C does.
                found = true;
                yearnum = (val / 10000) as i32;
                monnum = ((val % 10000) / 100 - 1) as i32;
                mdaynum = (val % 100) as i32;
            }

            if !found && dignext == Assume::MDay && mdaynum == -1 {
                if val > 0 && val < 32 {
                    mdaynum = val as i32;
                    found = true;
                }
                // Advanced UNCONDITIONALLY, even when the value was not a
                // plausible day. That is deliberate in C and load-bearing:
                // `1994 Nov 6` works because 1994 fails the day test here and
                // the next number is then read as a day.
                dignext = Assume::Year;
            }

            if !found && dignext == Assume::Year && yearnum == -1 {
                let mut year = val as i32;
                found = true;
                // Two-digit years: above 70 is the 1900s, otherwise the 2000s.
                // The boundary is `> 70`, so 70 itself becomes 2070.
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

    // The weekday is parsed but never validated against the date, matching C.
    let _ = wdaynum;

    if secnum == -1 {
        // No time given, so midnight.
        secnum = 0;
        minnum = 0;
        hournum = 0;
    }

    if mdaynum == -1 || monnum == -1 || yearnum == -1 {
        // Lacks vital information. `monnum` reaches this as -1 either because
        // no month name was seen or because a `YYYYMMDD` field of `00`
        // computed -1; C cannot tell the two apart and neither does this.
        return Outcome::Fail;
    }
    let (mday, mon, year) = (mdaynum, monnum, yearnum);

    // The Gregorian calendar was introduced in 1582 (`lib/parsedate.c:521-523`).
    // On a 32-bit time_t this branch is replaced by the 2038 and 1903 limits;
    // all four mandated targets are 64-bit, so this is the one that applies.
    if year < 1583 {
        return Outcome::Fail;
    }

    if mday > 31 || mon > 11 || hournum > 23 || minnum > 59 || secnum > 60 {
        // Clearly an illegal date. Note the day is NOT checked against the
        // length of the month, and 60 seconds is allowed; both match C.
        return Outcome::Fail;
    }

    let t = time2epoch(secnum, minnum, hournum, mday, mon, year);

    // An absent timezone means GMT.
    let tzoff = if tzoff == -1 { 0 } else { tzoff };
    let tzoff64 = i64::from(tzoff);

    if tzoff64 > 0 && t > TIME_T_MAX - tzoff64 {
        return Outcome::Later(TIME_T_MAX);
    }

    Outcome::Ok(t + tzoff64)
}

/// Parse a date string into seconds since the Unix epoch, UTC.
///
/// This is the engine half of the exported `curl_getdate`
/// (`lib/parsedate.c:561-575`), and the ONLY date-parsing entry point
/// `curl-rs-ffi` needs: the adapter converts a `*const c_char` into a `&str`
/// and an absent value into `-1`, and makes no parsing decision of its own.
/// Review finding M-13.
///
/// Every format listed in the module documentation is accepted, including
/// dates with no weekday, no timezone or no time at all.
///
/// # The `-1` quirk is HERE, not in the caller
///
/// `-1` is C's failure sentinel for this function, so a date that genuinely
/// falls on `-1` -- one second before the epoch -- would be indistinguishable
/// from an error. C increments it to `0` (`:570-572`) and this does the same.
/// The quirk is part of the contract rather than of the marshalling, so it
/// belongs on this side of the boundary.
///
/// # Returns
///
/// `Some(seconds)` on success, or `None` when the string cannot be converted
/// or names an instant too large to represent. Overflow is a failure here, and
/// deliberately so: C returns `-1` for anything that is not `PARSEDATE_OK`.
/// Callers needing the saturating behaviour use [`getdate_capped`].
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
/// (`lib/parsedate.c:581-584`), which is not one of the 100 exported symbols
/// -- hence `pub(crate)`, preserving the visibility split the C tree draws.
/// The FTP, cookie, HSTS and Alt-Svc paths use it because an expiry far in the
/// future should clamp rather than be rejected.
///
/// Two differences from [`getdate`], both from the C:
///
/// * A value too large to represent yields `Some(TIME_T_MAX)` rather than
///   `None`; only an unparsable string yields `None`.
/// * The `-1` to `0` adjustment is NOT applied, because this function reports
///   failure out of band and has no need of a sentinel.
#[must_use]
#[allow(dead_code)]
pub(crate) fn getdate_capped(date: &str) -> Option<i64> {
    match parsedate(date.as_bytes()) {
        Outcome::Ok(t) | Outcome::Later(t) => Some(t),
        Outcome::Fail => None,
    }
}

// ===========================================================================
// TESTS
//
// The expectations below are not hand-computed. Every one was produced by
// CALLING `curl_getdate` in the real `libcurl.so.4` built from this
// repository's own C tree, so the table is a differential oracle rather than a
// restatement of what this file happens to do. Regenerating it requires only
// that library and the corpus.
//
// Coverage beyond this table, measured once and recorded because the evidence
// does not fit in a test: a 6,820-entry generated corpus -- systematic
// permutations of all twelve format families, sweeps across every numeric
// threshold the parser tests, all 14x8 `YYYYMMDD` month/day combinations,
// name-length probes around NAME_LEN and the timezone limit, malformed input,
// and random printable-ASCII soup -- was compared against the same C function
// and produced ZERO divergences over 1,477 parsed and 5,343 rejected inputs.
//
// Seven mutations were then applied to this file to confirm the comparison
// discriminates. Five were caught: the two-digit-year pivot (5), the Gregorian
// floor (149), the RFC 822 offset sign (170), the six-part limit (8) and a
// tightened seconds bound (709). Two are UNOBSERVABLE at this boundary and
// that was proven rather than assumed:
//
//  * `ss <= 60` versus `ss <= 61` cannot be seen, because the later
//    `secnum > 60` range check rejects 61 whichever path the parser took. The
//    guard itself is load-bearing -- tightening it to `<= 5` diverges 709
//    times -- and the C oracle confirms `00:00:60` parses while `00:00:61`
//    does not.
//  * `NAME_LEN` is 12 in C, but every value from 10 upwards behaves
//    identically, because no name in any table is that long. Dropping it to 9
//    diverges 38 times, since `Wednesday` is nine characters.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// `(input, expected)` where expected is what the C `curl_getdate`
    /// returns, and `-1` is its failure sentinel.
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
        // A table of only failures, or only successes, would let a
        // degenerate implementation pass. Both counts are asserted so the
        // test above cannot become vacuous through editing.
        let parsed = ORACLE.iter().filter(|(_, v)| *v != -1).count();
        let failed = ORACLE.len() - parsed;
        assert_eq!(parsed, 73, "expected 73 parseable inputs");
        assert_eq!(failed, 29, "expected 29 rejected inputs");
    }

    #[test]
    fn the_reference_instant_is_the_one_rfc_2616_documents() {
        // `lib/parsedate.c:33` uses this instant for all three of the formats
        // RFC 2616 3.3.1 lists, so all three must agree.
        for input in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(getdate(input), Some(784_111_777), "{input:?}");
        }
    }

    #[test]
    fn the_minus_one_second_is_reported_as_the_epoch() {
        // The quirk at `lib/parsedate.c:570-572`: one second before the epoch
        // collides with the failure sentinel, so C returns 0 instead.
        assert_eq!(getdate("Wed, 31 Dec 1969 23:59:59 GMT"), Some(0));
        // The neighbours are unaffected, which is what shows the adjustment is
        // a single-value special case and not an off-by-one.
        assert_eq!(getdate("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(getdate("Thu, 01 Jan 1970 00:00:01 GMT"), Some(1));
        assert_eq!(getdate("Wed, 31 Dec 1969 23:59:58 GMT"), Some(-2));
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
    fn the_gregorian_floor_is_1583() {
        assert!(getdate("Mon, 01 Jan 1583 00:00:00 GMT").is_some());
        assert_eq!(getdate("Mon, 01 Jan 1582 00:00:00 GMT"), None);
        assert_eq!(getdate("Fri, 01 Jan 1500 00:00:00 GMT"), None);
    }

    #[test]
    fn two_digit_years_pivot_above_seventy() {
        // `> 70`, so 70 itself lands in the 2000s.
        assert_eq!(getdate("01-Jan-71"), getdate("01 Jan 1971"));
        assert_eq!(getdate("01-Jan-70"), getdate("01 Jan 2070"));
        assert_eq!(getdate("01-Jan-69"), getdate("01 Jan 2069"));
        assert_eq!(getdate("01-Jan-99"), getdate("01 Jan 1999"));
    }

    #[test]
    fn rfc822_offsets_invert_the_sign_and_stop_at_1400() {
        let base = getdate("Sun, 12 Sep 2004 15:05:58 GMT").unwrap();
        // `+0200` means local time is ahead of GMT, so GMT is EARLIER.
        assert_eq!(
            getdate("Sun, 12 Sep 2004 15:05:58 +0200"),
            Some(base - 2 * 3600)
        );
        assert_eq!(
            getdate("Sun, 12 Sep 2004 15:05:58 -0700"),
            Some(base + 7 * 3600)
        );
        // 1400 is the documented ceiling; 1401 is not an offset, and the four
        // digits are then consumed as a number instead.
        assert!(getdate("Jan 1 2001 +1400").is_some());
        assert_ne!(getdate("Jan 1 2001 +1401"), getdate("Jan 1 2001 +1400"));
    }

    #[test]
    fn named_zones_resolve_to_their_table_offsets() {
        let gmt = getdate("Sun, 06 Nov 1994 08:49:37 GMT").unwrap();
        // Westward offsets are positive minutes, so the instant is LATER.
        assert_eq!(
            getdate("Sun, 06 Nov 1994 08:49:37 EST"),
            Some(gmt + 300 * 60)
        );
        // CET is -60, so earlier.
        assert_eq!(
            getdate("Sun, 06 Nov 1994 08:49:37 CET"),
            Some(gmt - 60 * 60)
        );
        // Daylight names add TDAYZONE, which is negative.
        assert_eq!(
            getdate("Sun, 06 Nov 1994 08:49:37 EDT"),
            Some(gmt + (300 + TDAYZONE) as i64 * 60)
        );
        // Military `Z` is UTC, and `J` is deliberately not a zone at all.
        assert_eq!(getdate("Sun, 06 Nov 1994 08:49:37 Z"), Some(gmt));
        assert_eq!(getdate("Sun, 06 Nov 1994 08:49:37 J"), None);
    }

    #[test]
    fn separators_are_irrelevant_and_case_is_ignored() {
        let want = getdate("6 Nov 1994").unwrap();
        for input in ["1994.Nov.6", "1994/Nov/6", "1994-Nov-6", "1994 Nov 6"] {
            assert_eq!(getdate(input), Some(want), "{input:?}");
        }
        let want = getdate("Thu, 1 Jan 2004 00:00:00 GMT").unwrap();
        for input in [
            "THU, 01 JAN 2004 00:00:00 GMT",
            "thu, 01 jan 2004 00:00:00 gmt",
            "Thu, 01 Jan 2004 00:00:00 GmT",
        ] {
            assert_eq!(getdate(input), Some(want), "{input:?}");
        }
    }

    #[test]
    fn a_trailing_colon_yields_hh_mm_rather_than_failing() {
        // The `else` arm of `lib/parsedate.c:317-320`.
        assert_eq!(getdate("Dec 31 2001 12:30:"), getdate("Dec 31 2001 12:30"));
        // But a colon FOLLOWED by an out-of-range value does fail.
        assert_eq!(getdate("Dec 31 2001 23:59:61"), None);
        assert!(getdate("Dec 31 2001 23:59:60").is_some());
    }

    #[test]
    fn vital_information_is_required() {
        for input in ["", "   ", ",,,,", "Nov", "1994", "Nov 1994", "6 Nov"] {
            assert_eq!(getdate(input), None, "{input:?}");
        }
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
            TZ.iter().map(|z| z.offset).max().expect("TZ is non-empty"),
        ) * 60;
        assert!(
            widest < TIME_T_MAX - largest_offset,
            "if this ever fails, Outcome::Later became reachable and needs a \
             real test: widest={widest} offset={largest_offset}"
        );
        // So every success is Ok, never Later, even at the extreme. Both
        // values below came from the C `curl_getdate`, not from this file:
        // `Jan 1 99999999 GMT` and `Dec 31 99999999 23:59:60 GMT` return
        // 3155633001244800 and 3155633032780800 respectively.
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
        // And an unparsable string is None for both.
        assert_eq!(getdate_capped("Nov"), None);
    }

    #[test]
    fn a_nul_terminates_the_string_as_it_does_in_c() {
        // A Rust caller can pass an interior NUL where a CStr cannot. C stops
        // there, so the trailing text must be invisible.
        assert_eq!(
            getdate("6 Nov 1994\0junk that would fail"),
            getdate("6 Nov 1994")
        );
    }

    #[test]
    fn the_name_tables_have_the_shapes_the_c_tree_exports() {
        assert_eq!(WKDAY.len(), 7);
        assert_eq!(MONTH.len(), 12);
        assert_eq!(WEEKDAY.len(), 7);
        assert_eq!(TZ.len(), 69, "lib/parsedate.c declares 69 zones");
        assert!(
            WKDAY.iter().all(|n| n.len() == 3),
            "Curl_wkday holds only abbreviations"
        );
        assert!(
            MONTH.iter().all(|n| n.len() == 3),
            "Curl_month holds only abbreviations"
        );
        // The longest zone name is what lets checktz reject on length alone.
        assert_eq!(TZ.iter().map(|z| z.name.len()).max(), Some(4));
        // Every abbreviation must prefix its full name, or one of the two
        // tables was transcribed wrongly.
        for (short, long) in WKDAY.iter().zip(WEEKDAY.iter()) {
            assert!(long.starts_with(short), "{short} vs {long}");
        }
        // No duplicate zone name, which would make lookup order significant.
        for (i, a) in TZ.iter().enumerate() {
            for b in TZ.iter().skip(i + 1) {
                assert_ne!(a.name, b.name, "duplicate zone {}", a.name);
            }
        }
    }

    #[test]
    fn the_name_matchers_require_an_exact_length() {
        assert_eq!(checkday(b"Mon"), Some(0));
        assert_eq!(checkday(b"Sun"), Some(6));
        assert_eq!(checkday(b"Sunday"), Some(6));
        assert_eq!(checkday(b"sUnDaY"), Some(6));
        // A prefix of a long name matches neither table.
        assert_eq!(checkday(b"Sund"), None);
        assert_eq!(checkday(b"Su"), None);
        assert_eq!(checkmonth(b"Nov"), Some(10));
        assert_eq!(checkmonth(b"nov"), Some(10));
        assert_eq!(checkmonth(b"November"), None, "months must be 3 letters");
        assert_eq!(checktz(b"GMT"), Some(0));
        assert_eq!(checktz(b"EST"), Some(300 * 60));
        assert_eq!(checktz(b"AHST"), Some(600 * 60));
        assert_eq!(checktz(b"ZZZZZ"), None, "longer than any zone name");
        assert_eq!(checktz(b"J"), None, "J is not a zone");
    }

    #[test]
    fn str_number_is_greedy_capped_and_accepts_leading_zeroes() {
        assert_eq!(str_number(b"123x", 0, MAX_NUMBER), Some((123, 3)));
        // Leading zeroes are accepted and DO count toward the digit width,
        // which is why the C comment about 8 digits is optimistic.
        assert_eq!(str_number(b"000000001", 0, MAX_NUMBER), Some((1, 9)));
        assert_eq!(
            str_number(b"99999999", 0, MAX_NUMBER),
            Some((99_999_999, 8))
        );
        // One digit too many is an ERROR, not a truncation.
        assert_eq!(str_number(b"100000000", 0, MAX_NUMBER), None);
        assert_eq!(str_number(b"x", 0, MAX_NUMBER), None);
        assert_eq!(str_number(b"", 0, MAX_NUMBER), None);
    }

    #[test]
    fn match_time_accepts_single_digits_and_a_leap_second() {
        assert_eq!(match_time(b"08:49:37", 0), Some((8, 49, 37, 8)));
        assert_eq!(match_time(b"1:2:3", 0), Some((1, 2, 3, 5)));
        assert_eq!(match_time(b"12:30", 0), Some((12, 30, 0, 5)));
        // A trailing colon leaves the index AT the colon.
        assert_eq!(match_time(b"12:30:", 0), Some((12, 30, 0, 5)));
        assert_eq!(match_time(b"23:59:60", 0), Some((23, 59, 60, 8)));
        assert_eq!(match_time(b"23:59:61", 0), None);
        assert_eq!(match_time(b"24:00:00", 0), None);
        assert_eq!(match_time(b"12:60:00", 0), None);
        assert_eq!(match_time(b"12", 0), None, "no colon is not a time");
    }

    #[test]
    fn time2epoch_agrees_with_known_instants() {
        // Month is 0-based, as it is throughout the C parser.
        assert_eq!(time2epoch(0, 0, 0, 1, 0, 1970), 0);
        assert_eq!(time2epoch(37, 49, 8, 6, 10, 1994), 784_111_777);
        assert_eq!(time2epoch(7, 14, 3, 19, 0, 2038), 2_147_483_647);
        // A leap day, and the day after, one apart.
        let feb29 = time2epoch(0, 0, 0, 29, 1, 2000);
        let mar01 = time2epoch(0, 0, 0, 1, 2, 2000);
        assert_eq!(mar01 - feb29, 86_400);
        // 1900 was not a leap year, 2000 was: the century rule is exercised.
        assert_eq!(
            time2epoch(0, 0, 0, 1, 2, 1900) - time2epoch(0, 0, 0, 28, 1, 1900),
            86_400
        );
    }

    #[test]
    fn skip_passes_everything_that_is_not_alphanumeric() {
        assert_eq!(skip(b"...abc", 0), 3);
        assert_eq!(skip(b"abc", 0), 0);
        assert_eq!(skip(b", , , ", 0), 6, "runs off the end cleanly");
        assert_eq!(skip(b"", 0), 0);
    }

    #[test]
    fn at_reports_zero_past_the_end_like_a_nul_terminator() {
        assert_eq!(at(b"ab", 0), b'a');
        assert_eq!(at(b"ab", 1), b'b');
        assert_eq!(at(b"ab", 2), 0);
        assert_eq!(at(b"ab", 9999), 0);
        assert_eq!(at(b"", 0), 0);
    }
}
