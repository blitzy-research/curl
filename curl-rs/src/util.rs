// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Tool-local helpers: the REALTIME clock reading, broken-down local time,
//! and the NULL-accepting case-insensitive string comparison.
//!
//! # What this supersedes
//!
//! This module supersedes two C translation units, and only the portable part
//! of each:
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
//! Four things in those files are deliberately absent, because Windows is out
//! of scope and the four mandated targets are Linux and macOS on x86_64 and
//! aarch64: the `_WIN32` `FILETIME` arm of `tvrealnow`
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
//! touches `SystemTime`. That split is required rather than stylistic: the
//! clock is injected so that behaviour depending on it can be exercised
//! deterministically, and `docs/internals/TIME-KEEPING.md:135-141` restates it
//! for this tree. Two concrete consequences: the rendered field can be
//! unit-tested against a fixed input, and `curl-rs-lib`'s trace layer cannot
//! end up stamping the same trace stream from a second, differently-read
//! clock. `curl-rs/src/callbacks/debug.rs` must therefore read the clock once
//! per line and pass the value through.
//!
//! Reading the clock needs no `unsafe` and no platform call:
//! `docs/internals/TIME-KEEPING.md:147-148` records that "Reading a clock is
//! a standard-library operation and does not belong in that island", the
//! island being `curl-rs-lib/src/ffi/`.
//!
//! # Local time comes from the host through the engine, and a refusal is
//! reported rather than hidden
//!
//! `toolx_localtime()` reaches `localtime_r()`, which needs libc and the
//! host's timezone database. Neither is reachable from *this* crate, measured
//! rather than assumed:
//!
//! - `std` has no timezone-aware API at all. `std::time` yields only
//!   epoch-relative durations, so it can name an instant but not a local
//!   wall-clock reading.
//! - No timezone crate is available. `curl-rs/Cargo.toml` declares four
//!   runtime dependencies -- `curl-rs-lib`, `clap`, `clap_complete` and
//!   `tokio` -- together with two dev-dependencies, `tempfile` and `tokio`,
//!   which are available to `#[cfg(test)]` code only and so cannot serve a
//!   shipped code path in any case. The workspace manifest contains no
//!   `chrono` and no `time` at any version, and adding one would breach the
//!   supply-chain obligation to pin the adopted set exactly.
//! - `libc` is not a dependency of this crate, and this crate grants no
//!   `unsafe` exemption anywhere, so `libc::localtime_r` is doubly out of
//!   reach.
//!
//! So the call is made where it belongs. `curl-rs-lib` owns the platform
//! island that AAP section 0.8.5 conflict C3 designates for exactly this --
//! `curl-rs-lib/src/ffi/sys.rs` wraps `localtime_r` behind the injected
//! `SysCalls` seam, with the `unsafe` block and its `// SAFETY:` justification
//! confined there -- and publishes `curl_rs_lib::local_utc_offset_secs`. This
//! crate consumes that and stays free of both `libc` and `unsafe`, which is
//! what goal G6 asks for: not that the platform call be skipped, but that it
//! live in one audited place.
//!
//! An offset rather than a broken-down time crosses that boundary, and it is
//! asked for **at the instant being rendered** rather than cached at start-up.
//! A zone's offset is not a constant -- daylight-saving time moves it -- and
//! `localtime_r` resolves it against the `time_t` handed to it, so a cached
//! value would render the wrong local time for part of the year. Passing the
//! same second that is about to be formatted is therefore not an
//! implementation detail but the whole of the correctness argument, and it is
//! what C does too: it calls `localtime_r` afresh for every traced line
//! (`src/tool_cb_dbg.c:41-46`).
//!
//! The failure path is retained exactly as C has it. When the platform refuses
//! -- `localtime_r` failing for a `time_t` its calendar arithmetic cannot
//! represent, which is the condition `toolx_localtime()` answers with
//! `CURLE_BAD_FUNCTION_ARGUMENT` -- `local_time_hms` fails and
//! `format_trace_timestamp` renders `00:00:00`, because
//! `src/tool_cb_dbg.c:43-44` zeroes the `struct tm` and formats it anyway. UTC
//! is never substituted for local time: a timestamp that silently shifts by
//! the host's offset while still wearing local time's label would be a
//! behaviour change dressed up as a success.
//!
//! The zone lookup is injected for the same reason the clock is, and through
//! the same shape: `UtcOffsetProvider` is a seam that `local_time_hms_with`
//! and `format_trace_timestamp_with` are written against, so both outcomes are
//! reachable in a test without the build host's `TZ` deciding what the
//! assertions say. That matters more here than for the clock -- a test that
//! asserted a particular local hour would pass in one time zone and fail in
//! the next. Where the host's own answer is itself the thing under test, the
//! tests below re-run themselves in a child process under an injected `TZ`
//! rather than asserting against whatever zone the build host is in.
//!
//! No test fixture regresses meanwhile. The byte-exact oracle compares the
//! bytes the client sends, and trace output is not part of that comparison.

use core::cmp::Ordering;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds in a day, the modulus that turns an epoch count into a time of
/// day. Unix time excludes leap seconds, so every day is exactly this long
/// and no table lookup is involved.
#[allow(dead_code)]
const SECS_PER_DAY: i64 = 86_400;

/// Microseconds in a second, the divisor `struct timeval` splits on.
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    /// field, which is the same normalization `gettimeofday` guarantees for
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
    #[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
    #[allow(dead_code)]
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
/// `include/curl/curl.h:570` annotates the enumerator `/* 43 */` -- and those
/// integers are part of the frozen contract. The single
/// call site converts to the engine's `CURLcode` at the boundary, which is
/// where the engine-facing types live; C's own caller never inspects which
/// code came back, only whether one did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum TimeError {
    /// The host's offset from UTC could not be determined, so an epoch count
    /// cannot be resolved to a local time of day.
    ///
    /// Reached when the platform refuses the conversion -- `localtime_r`
    /// failing, which it does for a `time_t` its calendar arithmetic cannot
    /// represent and which it reports by returning a null pointer, or a
    /// timezone database that yields an offset outside the plausible range.
    /// UTC is not substituted; see the module documentation.
    LocalZoneUnknown,
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::LocalZoneUnknown => f.write_str(
                "cannot determine the local time zone offset for this \
                 timestamp",
            ),
        }
    }
}

impl std::error::Error for TimeError {}

/// How a UTC offset is obtained for a given instant.
///
/// The seam the module documentation calls for. `local_time_hms` is written
/// against this rather than against the engine directly, so both outcomes --
/// an offset and a refusal -- are reachable in a test without depending on
/// the build host's `TZ`, and so the zone lookup sits in exactly one place
/// just as the clock reading does.
type UtcOffsetProvider = fn(i64) -> Option<i32>;

/// The host's offset from UTC at `epoch_secs`, in seconds east of Greenwich.
///
/// The production [`UtcOffsetProvider`], and the only route from this crate to
/// the host's timezone database. `localtime_r` is what answers underneath --
/// the call `src/toolx/tool_time.c:36-61` makes and the one
/// `scripts/checksrc.pl:97` bans everywhere else -- reached through
/// [`curl_rs_lib::local_utc_offset_secs`] because
/// `#![forbid(unsafe_code)]` covers this crate and AAP section 0.8.5 conflict
/// C3 puts such calls in `curl-rs-lib/src/ffi/sys.rs`.
///
/// The offset is asked for **at an instant** rather than in general, which is
/// what makes daylight-saving time correct: a zone's offset is not a constant,
/// and `localtime_r` resolves it against the `time_t` it is given. Passing the
/// same count that is about to be rendered is therefore not an implementation
/// detail but the whole of the correctness argument.
///
/// [`None`] when the platform cannot answer. It is propagated rather than
/// replaced by zero, because zero would be UTC wearing local time's label.
fn local_utc_offset_secs(epoch_secs: i64) -> Option<i32> {
    curl_rs_lib::local_utc_offset_secs(epoch_secs)
}

/// Splits an epoch second count into a time of day.
///
/// The count must already be expressed in the zone being rendered; this
/// function applies no offset of its own. `rem_euclid` rather than `%` so
/// that a pre-1970 count yields a remainder in `0..SECS_PER_DAY` instead of a
/// negative one, which would render a negative hour.
#[allow(dead_code)]
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
/// determined for this timestamp -- the same condition `toolx_localtime()`
/// answers with `CURLE_BAD_FUNCTION_ARGUMENT`. The caller's response is fixed
/// by C's, namely to render midnight (`src/tool_cb_dbg.c:43-44`).
#[allow(dead_code)]
pub(crate) fn local_time_hms(epoch_secs: i64) -> Result<Hms, TimeError> {
    // The offset is asked for at this timestamp, not "now": a traced line
    // carries the reading taken when it was emitted, and across a
    // daylight-saving boundary the two offsets differ.
    local_time_hms_with(local_utc_offset_secs, epoch_secs)
}

/// [`local_time_hms`] over an injected [`UtcOffsetProvider`].
///
/// Named to match the `*_with` pairs the engine's own platform layer uses, so
/// the two halves of a seam read the same way on both sides of the crate
/// boundary.
fn local_time_hms_with(
    offset_at: UtcOffsetProvider,
    epoch_secs: i64,
) -> Result<Hms, TimeError> {
    match offset_at(epoch_secs) {
        // Folding the offset into the count before splitting it keeps the
        // arithmetic in one place and keeps this function honest about which
        // zone it produced: the offset is the only thing that distinguishes
        // local time from UTC here.
        //
        // Saturating rather than wrapping. A count within a day of `i64::MIN`
        // or `i64::MAX` cannot be shifted by an offset without overflowing,
        // and saturating there yields a time of day at the extreme rather than
        // one wrapped to the far end of the range.
        Some(offset) => Ok(hms_of_epoch_secs(
            epoch_secs.saturating_add(i64::from(offset)),
        )),
        None => Err(TimeError::LocalZoneUnknown),
    }
}

/// Renders the `--trace-time` field for an already-taken clock reading.
///
/// The format is frozen and reproduced exactly:
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
/// reproduced: it is a performance optimization, performance is an explicit
/// non-goal here, and a change argued on speed grounds is forbidden. Its
/// absence is unobservable -- the rendered bytes
/// are identical either way -- whereas reproducing it would need state that
/// outlives the call, which is exactly the global mutable state this design
/// does without.
#[allow(dead_code)]
pub(crate) fn format_trace_timestamp(now: WallClockTime) -> String {
    format_trace_timestamp_with(local_utc_offset_secs, now)
}

/// [`format_trace_timestamp`] over an injected [`UtcOffsetProvider`].
///
/// The seam is carried up to this level as well as down to
/// [`local_time_hms_with`] so that the composed behaviour -- a refusal
/// becoming `00:00:00` -- is assertable byte-for-byte without the build host's
/// `TZ` deciding the answer.
fn format_trace_timestamp_with(
    offset_at: UtcOffsetProvider,
    now: WallClockTime,
) -> String {
    let hms =
        local_time_hms_with(offset_at, now.epoch_secs).unwrap_or(Hms::MIDNIGHT);
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
#[allow(dead_code)]
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
/// reproducibility is an obligation, and an ordering that
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
/// printed in this order, and the command-line surface is frozen. It
/// delegates to `struplocompare` so that one definition of the
/// ordering serves both, exactly as the C pair does.
#[allow(dead_code)]
pub(crate) fn struplocompare4sort<S: AsRef<str>>(p1: &S, p2: &S) -> Ordering {
    struplocompare(Some(p1.as_ref()), Some(p2.as_ref()))
}

#[cfg(test)]
mod tests {
    use super::{
        after_epoch_reading, ascii_stricmp, before_epoch_reading,
        format_trace_timestamp, format_trace_timestamp_with, hms_of_epoch_secs,
        local_time_hms, local_time_hms_with, local_utc_offset_secs,
        render_trace_field, struplocompare, struplocompare4sort,
        wall_clock_now, Hms, TimeError, WallClockTime, MICROS_PER_SEC,
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
    /// so an expected time of day is stated outright rather than derived by
    /// the same code the assertion is about. The zone resolution does succeed
    /// now; this helper simply does not depend on it.
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

    // -- Local time comes from the host, and a refusal fails as C fails -----

    /// A provider that refuses, standing in for a platform that cannot answer.
    fn no_zone(_epoch: i64) -> Option<i32> {
        None
    }

    /// A provider fixed at UTC, so a rendered field can be asserted
    /// byte-for-byte whatever the build host's `TZ` happens to be.
    fn utc(_epoch: i64) -> Option<i32> {
        Some(0)
    }

    /// A provider fixed at `+05:30`, chosen because it is not a whole number
    /// of hours: a half-hour zone catches an implementation that folded the
    /// offset in as hours.
    fn kolkata(_epoch: i64) -> Option<i32> {
        Some(5 * 3_600 + 30 * 60)
    }

    /// A provider fixed at `-08:00`, so the westward sign is exercised too.
    fn pacific(_epoch: i64) -> Option<i32> {
        Some(-8 * 3_600)
    }

    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn the_host_offset_is_asked_for_at_the_instant_being_rendered() {
        // The production provider reaches `localtime_r` through the engine.
        // Its value is the build host's and cannot be asserted, but two
        // properties can, and both would fail against the previous body: it
        // must answer, and it must answer for a real instant.
        let now = local_utc_offset_secs(1_700_000_000)
            .expect("the host resolves a present-day instant");

        // Every real zone lies within 14 hours of UTC -- the widest offset in
        // the IANA database is +14:00 for Kiritimati -- and the engine rejects
        // anything that does not fit an i32 for that reason.
        assert!(
            (-14 * 3_600..=14 * 3_600).contains(&now),
            "implausible offset {now}"
        );

        // Asked per instant, so a second call for a different instant is a
        // separate question rather than a cached answer. Both must resolve;
        // whether they agree depends on the host's daylight-saving rules and
        // is deliberately not asserted.
        assert!(local_utc_offset_secs(0).is_some());
    }

    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn the_production_conversion_uses_the_production_provider() {
        // `local_time_hms` must be exactly `local_time_hms_with` over
        // `local_utc_offset_secs` -- asserted by composing the two halves
        // independently and comparing, so a future edit that reached for a
        // different provider inside it would fail here.
        for epoch in [0, 1_700_000_000, -1] {
            let composed = local_time_hms_with(local_utc_offset_secs, epoch);
            assert_eq!(local_time_hms(epoch), composed);
        }
    }

    #[test]
    fn a_refusing_provider_yields_the_documented_error() {
        // The failure path, driven through the seam so it is reachable without
        // a broken timezone database.
        for epoch in [0, 1_700_000_000, i64::MIN, i64::MAX] {
            assert_eq!(
                local_time_hms_with(no_zone, epoch),
                Err(TimeError::LocalZoneUnknown)
            );
        }
    }

    #[test]
    fn the_offset_is_folded_in_before_the_split() {
        // 1_700_000_000 is 22:13:20 UTC (asserted independently below).
        let epoch = 1_700_000_000;

        assert_eq!(local_time_hms_with(utc, epoch), Ok(hms(22, 13, 20)));
        // +05:30 carries it past midnight into the next day: 03:43:20.
        assert_eq!(local_time_hms_with(kolkata, epoch), Ok(hms(3, 43, 20)));
        // -08:00 moves it back to 14:13:20 on the same day.
        assert_eq!(local_time_hms_with(pacific, epoch), Ok(hms(14, 13, 20)));
    }

    #[test]
    fn an_extreme_count_saturates_instead_of_wrapping() {
        // A count at either bound cannot absorb an offset that pushes it
        // further out. Saturating clamps to the bound, so the result is still
        // a time of day; wrapping would land at the opposite end of the range
        // and render an hour that is off by the whole span of `i64`.
        assert_eq!(
            local_time_hms_with(pacific, i64::MIN),
            Ok(hms_of_epoch_secs(i64::MIN)),
            "a westward offset at the lower bound clamps"
        );
        assert_eq!(
            local_time_hms_with(kolkata, i64::MAX),
            Ok(hms_of_epoch_secs(i64::MAX)),
            "an eastward offset at the upper bound clamps"
        );

        // The other two corners do not saturate, and must stay exact rather
        // than being clamped defensively: an offset that moves a bound inward
        // is representable.
        assert_eq!(
            local_time_hms_with(kolkata, i64::MIN),
            Ok(hms_of_epoch_secs(i64::MIN + (5 * 3_600 + 30 * 60))),
        );
        assert_eq!(
            local_time_hms_with(pacific, i64::MAX),
            Ok(hms_of_epoch_secs(i64::MAX - 8 * 3_600)),
        );
    }

    #[test]
    fn a_refused_conversion_renders_midnight_without_panicking() {
        // src/tool_cb_dbg.c:43-44 zeroes the struct tm and formats anyway,
        // so the hour-minute-second part is 00:00:00 while the microseconds
        // still come through.
        let field = format_trace_timestamp_with(
            no_zone,
            WallClockTime::new(0, 250_000),
        );
        assert_eq!(field, "00:00:00.250000 ");

        let other = format_trace_timestamp_with(
            no_zone,
            WallClockTime::new(1_700_000_000, 7),
        );
        assert_eq!(other, "00:00:00.000007 ");
    }

    // -- The same answer taken from the host, and under an injected TZ --

    /// A timestamp whose time of day cannot be midnight in any real zone.
    ///
    /// 1 700 000 000 is 2023-11-14 22:13:20 UTC. Every offset in use anywhere
    /// is a whole number of minutes for a timestamp in this century, and
    /// 22:13:20 is not, so no offset can carry it to 00:00:00. That makes
    /// "renders midnight" a sound proof that the offset lookup failed, on any
    /// host, without the test needing to know the host's zone.
    const NOT_MIDNIGHT_ANYWHERE: i64 = 1_700_000_000;

    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn the_local_offset_is_the_engine_s_answer_and_not_a_hardcoded_one() {
        // The property F16 restores: this crate delegates rather than
        // pretending the offset is unknowable. Comparing against the engine
        // rather than against a literal keeps the test host-independent.
        for probe in [0, NOT_MIDNIGHT_ANYWHERE, -1, 253_402_300_799] {
            assert_eq!(
                local_utc_offset_secs(probe),
                curl_rs_lib::local_utc_offset_secs(probe),
                "the offset for {probe} must come straight from the engine"
            );
        }
        // Guards the four assertions above against being vacuously true: if
        // the engine answered None everywhere, a reverted body that also
        // answered None would satisfy them.
        assert!(
            local_utc_offset_secs(NOT_MIDNIGHT_ANYWHERE).is_some(),
            "this host cannot resolve a 2023 timestamp to local time, so the \
             comparison above proves nothing; localtime_r is broken here"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn local_conversion_applies_the_offset_the_engine_reported() {
        for probe in [0, NOT_MIDNIGHT_ANYWHERE, -1, i64::MIN, i64::MAX] {
            let expected = match curl_rs_lib::local_utc_offset_secs(probe) {
                Some(offset) => Ok(hms_of_epoch_secs(
                    probe.saturating_add(i64::from(offset)),
                )),
                None => Err(TimeError::LocalZoneUnknown),
            };
            assert_eq!(local_time_hms(probe), expected, "at {probe}");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn an_unrepresentable_timestamp_still_fails_the_way_c_fails() {
        // localtime_r rejects a count that overflows a struct tm, which is the
        // condition toolx_localtime reports as CURLE_BAD_FUNCTION_ARGUMENT.
        // The Err arm is therefore reachable on a working host, not dead code.
        assert_eq!(local_time_hms(i64::MAX), Err(TimeError::LocalZoneUnknown));
        assert_eq!(local_time_hms(i64::MIN), Err(TimeError::LocalZoneUnknown));
    }

    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn failed_conversion_renders_midnight_without_panicking() {
        // src/tool_cb_dbg.c:43-44 zeroes the struct tm and formats it anyway,
        // so the hour-minute-second part is 00:00:00 while the microseconds
        // still come through. i64::MAX is the reachable way to reach that path.
        let field =
            format_trace_timestamp(WallClockTime::new(i64::MAX, 250_000));
        assert_eq!(field, "00:00:00.250000 ");
    }

    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn a_resolvable_timestamp_does_not_render_the_midnight_fallback() {
        // The teeth for F16 on any host: before the fix every timestamp took
        // the midnight path, so this assertion failed for all of them.
        let field = format_trace_timestamp(WallClockTime::new(
            NOT_MIDNIGHT_ANYWHERE,
            7,
        ));
        assert!(
            !field.starts_with("00:00:00"),
            "{field} is the midnight fallback, so the offset lookup failed"
        );
        // Whole-minute offsets leave the seconds untouched, and 1 700 000 000
        // is 20 seconds past a minute. True in every zone.
        assert_eq!(
            &field[6..],
            "20.000007 ",
            "the seconds must survive the offset unchanged"
        );
    }

    /// The rendered field a child process must produce, and the zone to set.
    ///
    /// Both are POSIX `TZ` strings, which glibc resolves arithmetically and so
    /// work on a host with no timezone database installed. `XXX-5` is five
    /// hours *east*: 22:13:20 UTC becomes 03:13:20 the next day. `YYY+7` is
    /// seven hours west: the same instant becomes 15:13:20.
    const TZ_CASES: [(&str, &str); 3] = [
        ("UTC0", "22:13:20.000007 "),
        ("XXX-5", "03:13:20.000007 "),
        ("YYY+7", "15:13:20.000007 "),
    ];

    /// Names the child test the way the libtest harness does.
    ///
    /// `module_path!()` is prefixed with the crate name, which `--exact` does
    /// not want. Deriving the rest keeps this working in whichever crate the
    /// file is compiled as part of.
    fn child_test_path(function: &str) -> String {
        let full = module_path!();
        let within_crate = full.split_once("::").map_or(full, |(_, rest)| rest);
        format!("{within_crate}::{function}")
    }

    const TZ_CHILD_VAR: &str = "BLITZY_UTIL_TZ_EXPECTED";

    #[test]
    #[cfg_attr(miri, ignore = "spawning a process is unsupported")]
    fn trace_time_follows_the_host_zone_rather_than_utc() {
        // This container runs in UTC, so a rendering taken here cannot tell
        // local time apart from UTC -- the two coincide. Re-running this test
        // as a child process under an injected TZ separates them, and does so
        // without depending on what zone the host happens to be in.
        //
        // The child half is `tz_child_asserts_the_injected_zone` below. It is
        // an ordinary test that returns immediately unless the variable is
        // set, so a plain `cargo test` run costs nothing.
        if std::env::var_os(TZ_CHILD_VAR).is_some() {
            return;
        }
        let exe = match std::env::current_exe() {
            Ok(path) => path,
            // Nothing to spawn; the assertions would be about the host.
            Err(_) => return,
        };
        let child_name = child_test_path("tz_child_asserts_the_injected_zone");

        for (zone, expected) in TZ_CASES {
            let output = std::process::Command::new(&exe)
                .args(["--exact", &child_name, "--nocapture"])
                .env("TZ", zone)
                .env(TZ_CHILD_VAR, expected)
                .output();
            let output = match output {
                Ok(output) => output,
                Err(_) => return,
            };
            assert!(
                output.status.success(),
                "under TZ={zone} the child expected {expected:?}:\n{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
    fn tz_child_asserts_the_injected_zone() {
        // Inert unless spawned by the test above with both variables set.
        let expected = match std::env::var(TZ_CHILD_VAR) {
            Ok(value) => value,
            Err(_) => return,
        };
        let field = format_trace_timestamp(WallClockTime::new(
            NOT_MIDNIGHT_ANYWHERE,
            7,
        ));
        assert_eq!(
            field,
            expected,
            "TZ={:?} must render {expected:?}",
            std::env::var("TZ")
        );
    }

    #[test]
    fn a_resolved_conversion_renders_the_local_time_of_day() {
        // The outcome the previous body could never produce: a field that is
        // not midnight. Driven at a fixed offset so the bytes are exact.
        let field = format_trace_timestamp_with(
            kolkata,
            WallClockTime::new(1_700_000_000, 7),
        );
        assert_eq!(field, "03:43:20.000007 ");
    }

    #[test]
    fn the_production_entry_point_renders_a_well_formed_field() {
        // `format_trace_timestamp` consults the host, so its digits belong to
        // the build host's zone and are not asserted. The layout is, since
        // that is the frozen part: sixteen bytes, `HH:MM:SS.uuuuuu `.
        let field =
            format_trace_timestamp(WallClockTime::new(1_700_000_000, 7));

        assert_eq!(field.len(), 16);
        assert!(field.ends_with(".000007 "), "{field}");
        let (hms_part, _) = field.split_at(8);
        assert!(
            hms_part
                .bytes()
                .enumerate()
                .all(|(i, b)| if i == 2 || i == 5 {
                    b == b':'
                } else {
                    b.is_ascii_digit()
                }),
            "{field}"
        );
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

    // -- Reading construction and normalization ----------------------------

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
    #[cfg_attr(miri, ignore = "localtime_r(3) is a foreign function")]
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
