// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Tool-local helpers: the REALTIME clock reading, broken-down local time,
//! and the NULL-accepting case-insensitive string comparison.
//!
//! # What this supersedes
//!
//! AAP section 0.4.1 maps this module onto two C translation units, and onto
//! only the portable part of each:
//!
//! - `src/tool_util.c:51-61` -- the POSIX arm of `tvrealnow()`, documented at
//!   `src/tool_util.h:28-30` as "Return timeval of the REALTIME clock". That
//!   wording is load-bearing: this is the wall clock, not a monotonic one.
//!   Elapsed-time accounting in the C tool goes through `curlx_now()`
//!   instead, and `docs/internals/TIME-KEEPING.md:101-109` specifies the two
//!   as distinct types so that conflating them fails to compile rather than
//!   misbehaving at run time.
//! - `src/tool_util.c:65-79` -- `struplocompare()` and its indirect `qsort`
//!   wrapper `struplocompare4sort()`, declared together at
//!   `src/tool_util.h:33-35` beneath the heading "Case insensitive
//!   comparison support".
//! - `src/toolx/tool_time.c:36-61` -- `toolx_localtime()`. Its header comment
//!   carries the mandate "Do not use the `localtime_s()`, `localtime_r()` or
//!   `localtime()` functions anywhere else but here", which
//!   `scripts/checksrc.pl:97` enforces by listing `localtime` as a banned
//!   function. This module honours the same mandate: it is the sole home for
//!   local-time conversion in `curl-rs`.
//!
//! Four things in those files are deliberately absent, because AAP section
//! 0.2.2 excludes Windows and the four mandated targets are Linux and macOS
//! on x86_64 and aarch64: the `_WIN32` `FILETIME` arm of `tvrealnow`
//! (`src/tool_util.c:28-47`), the `localtime_s` arm of `toolx_localtime`
//! (`src/toolx/tool_time.c:42-44`), `tool_ftruncate64`
//! (`src/tool_util.c:81-97`, reachable only through the `USE_TOOL_FTRUNCATE`
//! definition at `src/tool_setup.h:88-98`) and `tool_execpath`
//! (`src/tool_util.c:99-127`). No `cfg(windows)` arm stands in for them.
//!
//! # The two consumers
//!
//! Both time helpers exist to serve one field of one flag. `--trace-time`
//! renders it in `src/tool_cb_dbg.c`: `tvrealnow()` is called at `:148` and
//! `toolx_localtime()` at `:42`, through the `hms_for_sec()` helper. The
//! comparison helper serves the two `qsort` call sites at
//! `src/tool_help.c:373` and `src/tool_paramhlp.c:497`. Nothing else in the
//! C tool calls any of them, so this module stays that narrow.
//!
//! # The clock is injected, never reached for
//!
//! `format_trace_timestamp` takes the reading as an argument and never
//! consults the clock itself; `wall_clock_now` is the only function here that
//! touches `SystemTime`. That split is required rather than stylistic. AAP
//! section 0.3.3 pattern P12 injects the clock so that behaviour depending on
//! it can be exercised deterministically, and
//! `docs/internals/TIME-KEEPING.md:135-141` restates it for this tree. Two
//! concrete consequences: the rendered field can be unit-tested against a
//! fixed input, and `curl-rs-lib`'s trace layer cannot end up stamping the
//! same trace stream from a second, differently-read clock.
//! `curl-rs/src/callbacks/debug.rs` therefore reads the clock once per line
//! and passes the value through.
//!
//! Reading the clock needs no `unsafe` and no platform call:
//! `docs/internals/TIME-KEEPING.md:147-148` records that "Reading a clock is
//! a standard-library operation and does not belong in that island", the
//! island being `curl-rs-lib/src/ffi/`.
//!
//! # Local time is unavailable here, and that is reported rather than hidden
//!
//! `toolx_localtime()` reaches `localtime_r()`, which needs libc and the
//! host's timezone database. Neither is reachable from this crate, measured
//! rather than assumed:
//!
//! - `std` has no timezone-aware API at all. `std::time` yields only
//!   epoch-relative durations, so it can name an instant but not a local
//!   wall-clock reading.
//! - No timezone crate is available. `curl-rs/Cargo.toml` declares exactly
//!   `curl-rs-lib`, `clap`, `clap_complete` and `tokio`, and the workspace
//!   manifest that AAP section 0.5.1 fixes contains no `chrono` and no `time`
//!   at any version. Adding one would breach the supply-chain obligation in
//!   AAP section 0.7, which pins the adopted set exactly.
//! - `libc` is not a dependency of this crate, and `unsafe` is forbidden at
//!   the crate root by AAP section 0.1.1 goal G6, so `libc::localtime_r` is
//!   doubly out of reach.
//! - `curl-rs-lib` exposes no local-time accessor. Its enumerated
//!   `src/ffi/` surface covers the hostname query, interface enumeration,
//!   `if_nametoindex`, the allocator hook and the GSS-API wrappers, and
//!   nothing else; its `util` module is crate-private and therefore invisible
//!   from here.
//!
//! The gap is confined to one function, `local_utc_offset_secs`, which
//! reports that the host offset is unknown. `local_time_hms` then fails, and
//! `format_trace_timestamp` renders `00:00:00` -- which is exactly what the C
//! tool renders on the same failure, because `src/tool_cb_dbg.c:43-44`
//! zeroes the `struct tm` and formats it anyway. UTC is never substituted for
//! local time, since a timestamp that silently shifts by the host's offset
//! while still being labelled local time would be a behaviour change dressed
//! up as a success. When `curl-rs-lib` grows a safe local-time accessor
//! backed by `curl-rs-lib/src/ffi/sys.rs`, only `local_utc_offset_secs`
//! changes; every caller and every test here already exercises both outcomes.
//!
//! No test fixture regresses meanwhile. AAP section 0.6.7's byte-exact oracle
//! compares the bytes the client sends, and trace output is not part of that
//! comparison.

use core::cmp::Ordering;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds in a day, the modulus that turns an epoch count into a time of
/// day. Unix time excludes leap seconds, so every day is exactly this long
/// and no table lookup is involved.
const SECS_PER_DAY: i64 = 86_400;

/// Microseconds in a second, the divisor `struct timeval` splits on.
const MICROS_PER_SEC: u32 = 1_000_000;

/// A reading of the REALTIME clock: whole seconds since the Unix epoch plus a
/// microsecond remainder.
///
/// This is the Rust counterpart of the `struct timeval` that
/// `tvrealnow()` returns (`src/tool_util.c:51-61`), narrowed to what the one
/// caller uses. It is deliberately a separate type from any monotonic
/// instant, per `docs/internals/TIME-KEEPING.md:101-109`: a value of this
/// type can be rendered as a time of day but cannot be subtracted to yield a
/// timeout budget, because it offers no such operation.
///
/// Seconds are signed. `time_t` is signed on all four mandated targets, and
/// `gettimeofday` reports a negative `tv_sec` for a clock set before 1970, so
/// an unsigned field could not represent every value the C code can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WallClockTime {
    /// Whole seconds since 1970-01-01T00:00:00Z, negative before it.
    epoch_secs: i64,
    /// Microseconds past `epoch_secs`, always in `0..MICROS_PER_SEC`.
    micros: u32,
}

impl WallClockTime {
    /// Builds a reading from a second count and a microsecond remainder.
    ///
    /// A remainder of a whole second or more is carried into the seconds
    /// field, which is the same normalisation `gettimeofday` guarantees for
    /// `struct timeval`. Keeping the invariant here rather than trusting
    /// callers is what lets `format_trace_timestamp` promise a field of
    /// exactly six microsecond digits: the C tool writes that field into
    /// `char timebuf[20]` (`src/tool_cb_dbg.c:135`), so an over-wide value
    /// would not merely look odd, it would disagree with the frozen layout.
    ///
    /// The carry saturates instead of wrapping. `micros` is a `u32`, so the
    /// largest possible carry is 4,294 seconds and saturation is unreachable
    /// in practice; it is written this way so that no arithmetic here can
    /// overflow in a release build.
    pub(crate) fn new(epoch_secs: i64, micros: u32) -> Self {
        let carry = i64::from(micros / MICROS_PER_SEC);
        Self {
            epoch_secs: epoch_secs.saturating_add(carry),
            micros: micros % MICROS_PER_SEC,
        }
    }
}

/// Reads the REALTIME clock.
///
/// The counterpart of `tvrealnow()` (`src/tool_util.c:51-61`), and the only
/// place in this crate that consults the clock. Everything downstream takes
/// the reading as an argument; see the module documentation on injection.
///
/// `Instant` is deliberately not used: it is monotonic and has no epoch, so
/// it cannot be rendered as a time of day.
///
/// The function is total. `duration_since` fails when the clock is set before
/// the epoch, and rather than aborting -- a panic in the command-line tool
/// would itself be a behaviour change -- that case is normalised into the
/// negative-seconds reading `gettimeofday` would have produced.
pub(crate) fn wall_clock_now() -> WallClockTime {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since_epoch) => after_epoch_reading(since_epoch),
        // The error carries how far the clock is *behind* the epoch.
        Err(before_epoch) => before_epoch_reading(before_epoch.duration()),
    }
}

/// Turns a duration measured forward from the epoch into a reading.
///
/// Split out from `wall_clock_now` so that the conversion can be exercised
/// against fixed inputs; the clock itself cannot be.
fn after_epoch_reading(since_epoch: Duration) -> WallClockTime {
    // as_secs() is a u64 count of whole seconds. A value beyond i64::MAX is
    // some 292 billion years away, but it is converted rather than cast so
    // that even the impossible case has a defined result. `unwrap_or` is a
    // total operation; nothing here can panic.
    let secs = i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX);
    WallClockTime::new(secs, since_epoch.subsec_micros())
}

/// Turns a duration measured backward from the epoch into a reading.
///
/// `gettimeofday` reports a clock set before 1970 as a negative `tv_sec` with
/// `tv_usec` still in `0..=999_999`, so a sub-second remainder borrows a
/// second and is replaced by its complement. Reached only when the host clock
/// is set before the epoch, which is why it is a separate, directly testable
/// function rather than an inline arm.
fn before_epoch_reading(ago: Duration) -> WallClockTime {
    let whole = i64::try_from(ago.as_secs()).unwrap_or(i64::MAX);
    let frac = ago.subsec_micros();
    if frac == 0 {
        WallClockTime::new(whole.saturating_neg(), 0)
    } else {
        WallClockTime::new(
            whole.saturating_neg().saturating_sub(1),
            MICROS_PER_SEC - frac,
        )
    }
}

/// The hour, minute and second of a broken-down time.
///
/// C hands `toolx_localtime()` a whole `struct tm`, but `hms_for_sec()` reads
/// only three of its fields -- `tm_hour`, `tm_min` and `tm_sec`
/// (`src/tool_cb_dbg.c:45-46`). Carrying only those three is not a
/// simplification of the contract, it is the whole of it, and it keeps the
/// type unable to promise a calendar date it has no way to compute.
///
/// Every field is in range: hours `0..=23`, minutes and seconds `0..=59`.
/// Unix time has no leap seconds, so the 60 and 61 that `localtime_r` may put
/// in `tm_sec` cannot arise from an epoch count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hms {
    /// Hour of the day, `0..=23`.
    hour: u32,
    /// Minute of the hour, `0..=59`.
    minute: u32,
    /// Second of the minute, `0..=59`.
    second: u32,
}

impl Hms {
    /// Midnight, the value the C tool formats when the conversion fails.
    ///
    /// `src/tool_cb_dbg.c:43-44` does `if(result) memset(&now, 0,
    /// sizeof(now));` and formats the zeroed structure regardless, so a
    /// failed conversion renders `00:00:00` rather than suppressing the
    /// field. This constant is that behaviour, named.
    const MIDNIGHT: Self = Self {
        hour: 0,
        minute: 0,
        second: 0,
    };
}

/// A broken-down-time conversion that could not be performed.
///
/// The counterpart of the non-`CURLE_OK` return of `toolx_localtime()`. C
/// reports `CURLE_BAD_FUNCTION_ARGUMENT` there
/// (`src/toolx/tool_time.c:45-49`), whose integer value is 43 --
/// `include/curl/curl.h:570` annotates the enumerator `/* 43 */` -- and AAP
/// section 0.6.1 makes those integers part of the frozen contract. The single
/// call site converts to the engine's `CURLcode` at the boundary, which is
/// where the engine-facing types live; C's own caller never inspects which
/// code came back, only whether one did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeError {
    /// The host's offset from UTC could not be determined, so an epoch count
    /// cannot be resolved to a local time of day. See the module
    /// documentation for why this is currently unconditional and what closes
    /// it.
    LocalZoneUnknown,
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::LocalZoneUnknown => f.write_str(
                "cannot determine the local time zone offset from the \
                 command-line crate",
            ),
        }
    }
}

impl std::error::Error for TimeError {}

/// The host's current offset from UTC, in seconds east of Greenwich.
///
/// This is the single point at which local-time support is missing, and it is
/// the single function that changes when it arrives. The module
/// documentation records the four independent measurements behind the `None`:
/// `std` has no timezone API, no timezone crate is in the dependency set,
/// `libc` plus `unsafe` are both unavailable here, and `curl-rs-lib` exposes
/// no accessor. Returning `None` rather than guessing zero is the point --
/// zero would be UTC wearing local time's label.
fn local_utc_offset_secs() -> Option<i32> {
    None
}

/// Splits an epoch second count into a time of day.
///
/// The count must already be expressed in the zone being rendered; this
/// function applies no offset of its own. `rem_euclid` rather than `%` so
/// that a pre-1970 count yields a remainder in `0..SECS_PER_DAY` instead of a
/// negative one, which would render a negative hour.
fn hms_of_epoch_secs(epoch_secs: i64) -> Hms {
    let secs_of_day = epoch_secs.rem_euclid(SECS_PER_DAY);
    // secs_of_day is 0..=86_399, so each quotient below is at most 23 and
    // every narrowing conversion is exact.
    Hms {
        hour: (secs_of_day / 3_600) as u32,
        minute: ((secs_of_day % 3_600) / 60) as u32,
        second: (secs_of_day % 60) as u32,
    }
}

/// Converts a REALTIME second count to the local time of day.
///
/// The counterpart of `toolx_localtime()` (`src/toolx/tool_time.c:40-61`),
/// and, per the mandate quoted in the module documentation, the only place in
/// `curl-rs` that does this. C returns `CURLE_OK` with the broken-down time
/// written through a pointer, or `CURLE_BAD_FUNCTION_ARGUMENT`; the Rust
/// shape is the same outcome expressed as a `Result`.
///
/// # Errors
///
/// Returns `TimeError::LocalZoneUnknown` when the host's UTC offset cannot be
/// determined, which is presently always. The module documentation states why
/// and what closes it; the caller's response is fixed by C's, namely to
/// render midnight.
pub(crate) fn local_time_hms(epoch_secs: i64) -> Result<Hms, TimeError> {
    match local_utc_offset_secs() {
        // Folding the offset into the count before splitting it keeps the
        // arithmetic in one place and keeps this function honest about which
        // zone it produced: the offset is the only thing that distinguishes
        // local time from UTC here.
        Some(offset) => Ok(hms_of_epoch_secs(
            epoch_secs.saturating_add(i64::from(offset)),
        )),
        None => Err(TimeError::LocalZoneUnknown),
    }
}

/// Renders the `--trace-time` field for an already-taken clock reading.
///
/// The format is frozen by AAP section 0.8.1 and reproduced exactly:
/// `src/tool_cb_dbg.c:149-150` writes `"%s.%06ld "` over the
/// `"%02d:%02d:%02d"` that `hms_for_sec()` produces at `:45-46`, so the field
/// is `HH:MM:SS.uuuuuu` followed by one space.
///
/// That trailing space is part of the contract, not padding.
/// `log_line_start` concatenates the three pieces of a line with
/// `"%s%s%s"` -- the time, the transfer and connection identifiers, and the
/// info-type prefix (`src/tool_cb_dbg.c:63`) -- and `dump()` does the same at
/// `:81`. Neither supplies a separator, so dropping the space would run the
/// timestamp into whatever follows it.
///
/// A failed conversion renders `00:00:00`, matching the zeroed `struct tm`
/// that C formats on the same failure (`src/tool_cb_dbg.c:43-44`).
///
/// The clock is not consulted here. The reading arrives as an argument, for
/// the reasons in the module documentation.
///
/// C memoises the hour-minute-second text and recomputes it only when the
/// whole second changes (`src/tool_cb_dbg.c:37-48`). That cache is not
/// reproduced: it is a performance optimisation, and AAP section 0.1.1 makes
/// performance an explicit non-goal while AAP section 0.8.2 forbids changes
/// argued on speed grounds. Its absence is unobservable -- the rendered bytes
/// are identical either way -- whereas reproducing it would need state that
/// outlives the call, which is exactly the global mutable state this design
/// does without.
pub(crate) fn format_trace_timestamp(now: WallClockTime) -> String {
    let hms = local_time_hms(now.epoch_secs).unwrap_or(Hms::MIDNIGHT);
    render_trace_field(hms, now.micros)
}

/// Writes the frozen `--trace-time` field from its two already-resolved
/// parts.
///
/// Separated from `format_trace_timestamp` so that the byte-for-byte layout
/// can be asserted for any time of day, independently of whether the zone
/// resolution above it succeeded. `micros` is always below one second because
/// `WallClockTime::new` normalises it, which is what holds the field to the
/// sixteen characters the C buffer is sized for.
fn render_trace_field(hms: Hms, micros: u32) -> String {
    format!(
        "{:02}:{:02}:{:02}.{:06} ",
        hms.hour, hms.minute, hms.second, micros
    )
}

/// Orders two strings the way `strcasecmp` orders them in the `C` locale.
///
/// `CURL_STRICMP` is what `struplocompare()` calls, and on every mandated
/// target it expands to `strcasecmp`: `src/tool_setup.h:71-75` selects that
/// arm under `HAVE_STRCASECMP`, ahead of the `strcmpi`, `stricmp` and plain
/// `strcmp` fallbacks at `:76-82`, and behind only the `_WIN32` `_stricmp`
/// arm at `:69-70` that these targets never take.
///
/// Case folding is ASCII-only, and that is a decision rather than an
/// approximation. `strcasecmp` is nominally locale-sensitive, but both call
/// sites compare ASCII-only inputs -- option long names on their way into
/// `--help`, and the protocol and parameter name lists of
/// `src/tool_paramhlp.c` -- so ASCII folding gives byte-identical ordering
/// while also being independent of `LC_CTYPE`. Independence is worth having:
/// AAP section 0.7 makes reproducibility an obligation, and an ordering that
/// shifted with the ambient locale would make `--help` output depend on the
/// environment that produced it.
///
/// `str::to_lowercase` would be wrong here, not merely different: it is
/// Unicode-aware and would fold characters `strcasecmp` leaves untouched,
/// reordering any list containing them. Only `u8::to_ascii_lowercase` is
/// used, which leaves every byte above 0x7F exactly as it found it.
///
/// Comparison runs over bytes rather than characters so that the result
/// matches C byte for byte. `Iterator::cmp` supplies the lexicographic rule
/// `strcasecmp` uses, including that a prefix sorts before the string that
/// extends it.
fn ascii_stricmp(p1: &str, p2: &str) -> Ordering {
    p1.bytes()
        .map(|b| b.to_ascii_lowercase())
        .cmp(p2.bytes().map(|b| b.to_ascii_lowercase()))
}

/// Case-insensitive comparison that accepts an absent operand.
///
/// The counterpart of `struplocompare()` (`src/tool_util.c:65-73`), whose
/// comment reads "Case insensitive compare. Accept NULL pointers." The three
/// arms are reproduced exactly:
///
/// - absent against present is `Ordering::Less` (`return p2 ? -1 : 0` with a
///   non-null `p2`);
/// - absent against absent is `Ordering::Equal` (the same expression with a
///   null `p2`);
/// - present against absent is `Ordering::Greater` (`return 1`).
///
/// The absent arms are kept even though the two call sites pass values that
/// are always present, because the C contract admits null and the `qsort`
/// wrapper below dereferences whatever it is handed without checking. Dropping
/// them would narrow a documented contract on the strength of today's callers.
pub(crate) fn struplocompare(p1: Option<&str>, p2: Option<&str>) -> Ordering {
    match (p1, p2) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => ascii_stricmp(left, right),
    }
}

/// Sort comparator over string-like elements.
///
/// The counterpart of `struplocompare4sort()` (`src/tool_util.c:76-79`),
/// which exists only because `qsort` hands its callback pointers to the array
/// elements rather than the elements themselves. Rust needs no such
/// indirection, so what is exposed is the comparator itself, passed straight
/// to `sort_by` or `sort_unstable_by`:
///
/// ```ignore
/// names.sort_by(struplocompare4sort);
/// ```
///
/// It is generic over `AsRef<str>` so that both call sites work whatever they
/// hold -- `src/tool_help.c:373` sorts the help table's long names and
/// `src/tool_paramhlp.c:497` sorts a name list -- without either of them
/// having to convert first.
///
/// The ordering it produces is observable output, not an internal detail.
/// `src/tool_getparam.c`'s `aliases[]` table carries the instruction that the
/// array "MUST be alphasorted based on the 'lname'", the help listing is
/// printed in this order, and AAP section 0.8.1 freezes the command-line
/// surface. It delegates to `struplocompare` so that one definition of the
/// ordering serves both, exactly as the C pair does.
pub(crate) fn struplocompare4sort<S: AsRef<str>>(p1: &S, p2: &S) -> Ordering {
    struplocompare(Some(p1.as_ref()), Some(p2.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::{
        after_epoch_reading, ascii_stricmp, before_epoch_reading, format_trace_timestamp,
        hms_of_epoch_secs, local_time_hms, local_utc_offset_secs, render_trace_field,
        struplocompare, struplocompare4sort, wall_clock_now, Hms, TimeError, WallClockTime,
        MICROS_PER_SEC,
    };
    use core::cmp::Ordering;
    use std::error::Error;
    use std::time::Duration;

    /// The string one byte past `"abc"`, used wherever a test needs a pair
    /// that shares a prefix and differs only in its final letter.
    ///
    /// It is a named constant rather than a repeated literal because the
    /// repository's spell-check gate reads it as a misspelling of "and", and
    /// naming it once means telling that gate once. The marker below is the
    /// project's own mechanism, honoured by `.github/scripts/codespell.sh`
    /// through its `--ignore-regex` and by `.github/scripts/typos.toml`
    /// through its `extend-ignore-re`, and used the same way at
    /// `lib/parsedate.c:151` and `tests/unit/unit1302.c:86`.
    const ABC_NEXT: &str = "abd"; // spellchecker:disable-line

    /// Builds an `Hms` for a test without going through the zone resolution,
    /// which cannot currently succeed.
    fn hms(hour: u32, minute: u32, second: u32) -> Hms {
        Hms {
            hour,
            minute,
            second,
        }
    }

    // -- struplocompare: the three NULL arms of src/tool_util.c:65-73 -------

    #[test]
    fn absent_against_absent_is_equal() {
        // C: `if(!p1) return p2 ? -1 : 0;` with a null p2 yields 0.
        assert_eq!(struplocompare(None, None), Ordering::Equal);
    }

    #[test]
    fn absent_against_present_is_less() {
        // C: the same expression with a non-null p2 yields -1.
        assert_eq!(struplocompare(None, Some("a")), Ordering::Less);
        assert_eq!(struplocompare(None, Some("")), Ordering::Less);
    }

    #[test]
    fn present_against_absent_is_greater() {
        // C: `if(!p2) return 1;`
        assert_eq!(struplocompare(Some("a"), None), Ordering::Greater);
        assert_eq!(struplocompare(Some(""), None), Ordering::Greater);
    }

    #[test]
    fn present_pairs_compare_case_insensitively() {
        assert_eq!(struplocompare(Some("ABC"), Some("abc")), Ordering::Equal);
        assert_eq!(struplocompare(Some("abc"), Some("ABC")), Ordering::Equal);
        assert_eq!(struplocompare(Some("abc"), Some(ABC_NEXT)), Ordering::Less);
        assert_eq!(
            struplocompare(Some(ABC_NEXT), Some("abc")),
            Ordering::Greater
        );
        assert_eq!(struplocompare(Some(""), Some("")), Ordering::Equal);
        assert_eq!(struplocompare(Some(""), Some("a")), Ordering::Less);
        assert_eq!(struplocompare(Some("a"), Some("")), Ordering::Greater);
    }

    #[test]
    fn a_prefix_sorts_before_its_extension() {
        // strcasecmp("ab", "abc") < 0: the shorter string runs out first.
        assert_eq!(struplocompare(Some("ab"), Some("abc")), Ordering::Less);
        assert_eq!(struplocompare(Some("abc"), Some("ab")), Ordering::Greater);
    }

    // -- Case folding is ASCII-only ----------------------------------------

    #[test]
    fn folding_leaves_non_ascii_bytes_alone() {
        // U+00C9 and U+00E9 are one Unicode case pair, so `to_lowercase`
        // would make these equal. `strcasecmp` in the C locale does not fold
        // them, and neither may this comparator: the UTF-8 encodings differ
        // in their second byte, 0x89 against 0xA9.
        let upper = "\u{00c9}";
        let lower = "\u{00e9}";
        assert_eq!(upper.to_lowercase(), lower);
        assert_ne!(ascii_stricmp(upper, lower), Ordering::Equal);
        assert_eq!(ascii_stricmp(upper, lower), Ordering::Less);
        assert_ne!(struplocompare(Some(upper), Some(lower)), Ordering::Equal);
    }

    #[test]
    fn folding_leaves_the_kelvin_sign_alone() {
        // U+212A lowercases to ASCII 'k' under Unicode rules. Its UTF-8 lead
        // byte is 0xE2, so ASCII folding must order it after "k" (0x6B).
        let kelvin = "\u{212a}";
        assert_eq!(kelvin.to_lowercase(), "k");
        assert_eq!(ascii_stricmp(kelvin, "k"), Ordering::Greater);
    }

    #[test]
    fn folding_covers_the_whole_ascii_letter_range() {
        for byte in b'A'..=b'Z' {
            let upper = String::from(char::from(byte));
            let lower = String::from(char::from(byte + 32));
            assert_eq!(ascii_stricmp(&upper, &lower), Ordering::Equal);
        }
    }

    #[test]
    fn folding_does_not_reach_the_bytes_between_the_letter_ranges() {
        // 0x5B..0x60 sit between 'Z' and 'a'. A comparator that lowercased
        // by adding 32 unconditionally would corrupt them; these orderings
        // are what strcasecmp reports.
        assert_eq!(ascii_stricmp("[", "{"), Ordering::Less);
        assert_eq!(ascii_stricmp("_", "?"), Ordering::Greater);
        assert_eq!(ascii_stricmp("@", "`"), Ordering::Less);
    }

    // -- The sort comparator ------------------------------------------------

    #[test]
    fn comparator_sorts_a_mixed_list_as_qsort_would() {
        let mut names = vec!["Verbose", "cert", "Anyauth", "basic", "ABC"];
        names.sort_by(struplocompare4sort);
        assert_eq!(names, vec!["ABC", "Anyauth", "basic", "cert", "Verbose"]);
    }

    #[test]
    fn comparator_accepts_owned_strings_too() {
        // The two C call sites hold different element types; the generic
        // bound is what lets one comparator serve both.
        let mut names = vec![
            String::from("proxy-ntlm"),
            String::from("Proxy-Basic"),
            String::from("proxy-anyauth"),
        ];
        names.sort_unstable_by(struplocompare4sort);
        assert_eq!(names, vec!["proxy-anyauth", "Proxy-Basic", "proxy-ntlm"]);
    }

    #[test]
    fn comparator_is_a_total_order_on_the_sample() {
        let sample = ["ABC", ABC_NEXT, "Ab", "", "zz", "Zz", "a"];
        for left in &sample {
            for right in &sample {
                let forward = struplocompare4sort(left, right);
                let backward = struplocompare4sort(right, left);
                // Antisymmetry.
                assert_eq!(forward, backward.reverse());
                // Transitivity, checked over every third element.
                for mid in &sample {
                    let lm = struplocompare4sort(left, mid);
                    let mr = struplocompare4sort(mid, right);
                    if lm == Ordering::Less && mr == Ordering::Less {
                        assert_eq!(forward, Ordering::Less);
                    }
                    if lm == Ordering::Equal && mr == Ordering::Equal {
                        assert_eq!(forward, Ordering::Equal);
                    }
                }
            }
        }
    }

    #[test]
    fn comparator_is_reflexive() {
        for name in ["", "a", "Retry-All-Errors", "\u{00c9}"] {
            assert_eq!(struplocompare4sort(&name, &name), Ordering::Equal);
        }
    }

    // -- The frozen --trace-time field -------------------------------------

    #[test]
    fn field_renders_with_its_trailing_space() {
        // src/tool_cb_dbg.c:149 formats "%s.%06ld " over "%02d:%02d:%02d".
        // The trailing space is part of the contract: log_line_start
        // concatenates "%s%s%s" at :63 and supplies no separator.
        let field = render_trace_field(hms(13, 45, 2), 123_456);
        assert_eq!(field, "13:45:02.123456 ");
        assert!(field.ends_with(' '));
        assert_eq!(field.len(), 16);
    }

    #[test]
    fn microseconds_are_six_zero_padded_digits() {
        assert_eq!(render_trace_field(hms(0, 0, 0), 7), "00:00:00.000007 ");
        assert_eq!(render_trace_field(hms(0, 0, 0), 0), "00:00:00.000000 ");
        assert_eq!(
            render_trace_field(hms(0, 0, 0), 999_999),
            "00:00:00.999999 "
        );
    }

    #[test]
    fn hours_minutes_and_seconds_are_two_zero_padded_digits() {
        assert_eq!(render_trace_field(hms(9, 4, 5), 0), "09:04:05.000000 ");
        assert_eq!(render_trace_field(hms(23, 59, 59), 1), "23:59:59.000001 ");
    }

    #[test]
    fn field_width_never_exceeds_the_c_buffer() {
        // src/tool_cb_dbg.c:135 sizes the buffer as char timebuf[20], so the
        // rendered field plus a terminator has to fit in twenty bytes.
        for hour in 0..24 {
            let field = render_trace_field(hms(hour, 59, 59), 999_999);
            assert!(field.len() < 20);
        }
    }

    // -- Local time is unavailable, and fails the way C fails --------------

    #[test]
    fn local_zone_is_reported_unknown_rather_than_guessed() {
        // The single gap point. Returning Some(0) here would be UTC wearing
        // local time's label, which is the outcome this design refuses.
        assert_eq!(local_utc_offset_secs(), None);
    }

    #[test]
    fn local_conversion_fails_with_the_documented_error() {
        assert_eq!(local_time_hms(0), Err(TimeError::LocalZoneUnknown));
        assert_eq!(
            local_time_hms(1_700_000_000),
            Err(TimeError::LocalZoneUnknown)
        );
        assert_eq!(local_time_hms(i64::MIN), Err(TimeError::LocalZoneUnknown));
        assert_eq!(local_time_hms(i64::MAX), Err(TimeError::LocalZoneUnknown));
    }

    #[test]
    fn failed_conversion_renders_midnight_without_panicking() {
        // src/tool_cb_dbg.c:43-44 zeroes the struct tm and formats anyway,
        // so the hour-minute-second part is 00:00:00 while the microseconds
        // still come through.
        let field = format_trace_timestamp(WallClockTime::new(0, 250_000));
        assert_eq!(field, "00:00:00.250000 ");

        let other = format_trace_timestamp(WallClockTime::new(1_700_000_000, 7));
        assert_eq!(other, "00:00:00.000007 ");
    }

    #[test]
    fn the_error_is_reportable() {
        let err = TimeError::LocalZoneUnknown;
        assert!(!err.to_string().is_empty());
        let boxed: Box<dyn Error> = Box::new(err);
        assert!(!boxed.to_string().is_empty());
    }

    // -- The time-of-day arithmetic ----------------------------------------

    #[test]
    fn epoch_zero_is_midnight() {
        assert_eq!(hms_of_epoch_secs(0), hms(0, 0, 0));
    }

    #[test]
    fn seconds_split_into_hours_minutes_and_seconds() {
        assert_eq!(hms_of_epoch_secs(1), hms(0, 0, 1));
        assert_eq!(hms_of_epoch_secs(59), hms(0, 0, 59));
        assert_eq!(hms_of_epoch_secs(60), hms(0, 1, 0));
        assert_eq!(hms_of_epoch_secs(3_599), hms(0, 59, 59));
        assert_eq!(hms_of_epoch_secs(3_600), hms(1, 0, 0));
        assert_eq!(hms_of_epoch_secs(86_399), hms(23, 59, 59));
        assert_eq!(hms_of_epoch_secs(86_400), hms(0, 0, 0));
        // 2023-11-14T22:13:20Z, a value with all three parts non-zero.
        assert_eq!(hms_of_epoch_secs(1_700_000_000), hms(22, 13, 20));
    }

    #[test]
    fn pre_epoch_seconds_do_not_render_a_negative_hour() {
        // `%` would give -1 here and a negative hour with it; `rem_euclid`
        // gives 86_399, which is 23:59:59 on the previous day.
        assert_eq!(hms_of_epoch_secs(-1), hms(23, 59, 59));
        assert_eq!(hms_of_epoch_secs(-86_400), hms(0, 0, 0));
        assert_eq!(hms_of_epoch_secs(-86_401), hms(23, 59, 59));
    }

    #[test]
    fn the_arithmetic_is_total_over_the_whole_range() {
        for secs in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX] {
            let value = hms_of_epoch_secs(secs);
            assert!(value.hour < 24);
            assert!(value.minute < 60);
            assert!(value.second < 60);
        }
    }

    // -- Reading construction and normalisation ----------------------------

    #[test]
    fn a_whole_second_of_microseconds_carries() {
        let carried = WallClockTime::new(10, MICROS_PER_SEC + 5);
        assert_eq!(carried, WallClockTime::new(11, 5));

        let two = WallClockTime::new(10, 2 * MICROS_PER_SEC);
        assert_eq!(two, WallClockTime::new(12, 0));
    }

    #[test]
    fn construction_never_overflows() {
        let saturated = WallClockTime::new(i64::MAX, u32::MAX);
        assert_eq!(saturated.epoch_secs, i64::MAX);
        assert!(saturated.micros < MICROS_PER_SEC);
    }

    #[test]
    fn a_forward_duration_becomes_seconds_and_microseconds() {
        let reading = after_epoch_reading(Duration::new(1_700_000_000, 7_000));
        assert_eq!(reading, WallClockTime::new(1_700_000_000, 7));

        // Nanosecond precision beyond a microsecond is truncated, exactly as
        // a struct timeval truncates it.
        let truncated = after_epoch_reading(Duration::new(5, 1_999));
        assert_eq!(truncated, WallClockTime::new(5, 1));
    }

    #[test]
    fn a_backward_duration_becomes_a_negative_reading() {
        // A clock five seconds before the epoch, on the second.
        assert_eq!(
            before_epoch_reading(Duration::new(5, 0)),
            WallClockTime::new(-5, 0)
        );
        // 1.5 seconds before the epoch is -2 seconds plus 500,000 us, which
        // is how gettimeofday normalises it.
        assert_eq!(
            before_epoch_reading(Duration::new(1, 500_000_000)),
            WallClockTime::new(-2, 500_000)
        );
        assert_eq!(
            before_epoch_reading(Duration::new(0, 1_000)),
            WallClockTime::new(-1, 999_999)
        );
    }

    #[test]
    fn a_backward_reading_keeps_the_microsecond_invariant() {
        for nanos in [0, 1, 1_000, 999_999_000, 999_999_999] {
            let reading = before_epoch_reading(Duration::new(3, nanos));
            assert!(reading.micros < MICROS_PER_SEC);
        }
    }

    #[test]
    fn the_clock_reader_is_total() {
        // Cannot assert a value against a live clock, so assert the
        // invariants: it returns, it does not panic, the microsecond field is
        // normalised, and the reading is somewhere after 2001-09-09, the
        // point at which epoch seconds passed one billion.
        let now = wall_clock_now();
        assert!(now.micros < MICROS_PER_SEC);
        assert!(now.epoch_secs > 1_000_000_000);
        // A second reading never precedes the first by construction of the
        // format, and both render at the frozen width.
        assert_eq!(format_trace_timestamp(now).len(), 16);
        assert_eq!(format_trace_timestamp(wall_clock_now()).len(), 16);
    }
}
