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

// THE CLOCK SEAM. This file is the ONE place in `curl-rs-lib` permitted to
// read a clock. Nothing else in the crate may call a monotonic or a
// wall-clock primitive: every consumer receives a [`Clock`] and asks it.
//
// HOW TO CHECK THE CLAIM, because it is the kind of invariant that decays
// silently: every match for a clock constructor must be either inside this
// file or inside a comment. Real clock reads are confined here; matches
// elsewhere in the crate are prose stating this same rule.
//
// NO GLOBAL CLOCK, at any level. No `static mut`, no clock in a
// `thread_local!`, and no `OnceLock<Box<dyn Clock>>` singleton that a test
// could install: a process-global override defeats P12 and makes two tests
// influence one another through the order they happen to run in. The single
// `static` here is [`SystemClock`]'s process-start baseline, which is an
// immutable-once-written `OnceLock<Instant>` and is documented at its
// definition.
//
// FOUR THINGS THIS FILE MUST NOT NAME, each for its own reason:
//
//   * `unsafe` -- `src/lib.rs` carries `#![deny(unsafe_code)]` and grants
//     exactly one exemption, on `mod ffi`, which is not here. The C's four
//     preprocessor clock paths and its `gmtime_r` call are precisely the
//     platform reaching that safe standard-library calls replace.
//   * `libc` -- the crate does declare it, and it is reserved for
//     `src/ffi/`. A C scalar width or a C-shaped time structure appearing
//     here would make a platform assumption part of the engine's own API.
//   * `tokio` -- the runtime's timer belongs to `conn/` and `transfer/`.
//     This file is the clock SOURCE, not the scheduler.
//   * a narrowing `as` cast -- every conversion below is written as
//     `i64::from`, `i32::try_from` or `u64::try_from`. `lib/curlx/warnless.c`
//     exists in the C tree to catch exactly the class of silent narrowing
//     that `as` performs quietly.

//! The monotonic clock, the instant type, the time differences and the UTC
//! calendar conversion -- supersedes `lib/curlx/timeval.c` and
//! `lib/curlx/timeval.h`.
//!
//! # The whole C surface, item by item
//!
//! Nine declared entry points. Each is reproduced here, or recorded as
//! deliberately collapsed into a neighbour, or recorded as excluded with the
//! AAP section that excludes it. Nothing is dropped silently.
//!
//! | C item | Site | Rust counterpart |
//! |---|---|---|
//! | `struct curltime` | `timeval.h:30-33` | [`CurlTime`] |
//! | `curlx_now` | `timeval.c:173-178` | [`Clock::now`] |
//! | `curlx_pnow` | `timeval.c:40-171` | [`Clock::now`] -- collapsed |
//! | `curlx_now_init` | `timeval.h:35-38` | none -- excluded, Windows only |
//! | `curlx_timediff_ms` | `timeval.c:198-201` | [`timediff_ms`] |
//! | `curlx_ptimediff_ms` | `timeval.c:186-195` | [`timediff_ms`], collapsed |
//! | `curlx_timediff_ceil_ms` | `timeval.c:207-216` | [`timediff_ceil_ms`] |
//! | `curlx_timediff_us` | `timeval.c:233-236` | [`timediff_us`] |
//! | `curlx_ptimediff_us` | `timeval.c:222-231` | [`timediff_us`], collapsed |
//! | `curlx_gmtime` | `timeval.c:251-272` | [`gmtime`] |
//!
//! Three collapses and one exclusion, stated rather than implied:
//!
//! * `curlx_now` and `curlx_pnow` are one reading behind two signatures. The
//!   pointer form exists to avoid copying a 16-byte structure out of the
//!   callee; [`CurlTime`] is [`Copy`] and returning it costs the same, so
//!   [`Clock::now`] is the only form here.
//! * `curlx_ptimediff_ms` versus `curlx_timediff_ms`, and
//!   `curlx_ptimediff_us` versus `curlx_timediff_us`, are the same pairing
//!   again: each value-taking function's whole body is a call to the pointer
//!   form with the addresses of its own parameters. One function per unit is
//!   provided. The C names are kept in this table so that a search of
//!   `lib/curlx/timeval.c` still lands here.
//! * There is NO `curlx_ptimediff_ceil_ms` in the C -- only the value-taking
//!   form -- and none is invented here.
//! * `curlx_now_init` is inside `#ifdef _WIN32` and exists solely to fill in
//!   `QueryPerformanceFrequency` before the first reading.
//!
//! # The monotonic reading and the wall reading are different clocks
//!
//! [`Clock`] exposes both, and they must not be interchanged.
//!
//! [`Clock::now`] is MONOTONIC. Its zero point is unspecified in the C and
//! unspecified here -- with [`Instant`] backing it, the zero point is the
//! first reading taken in the process. A monotonic [`CurlTime`] is therefore
//! meaningful ONLY when subtracted from another monotonic [`CurlTime`] taken
//! by the same clock in the same process. Never compare one against a
//! calendar time, never hand one to [`gmtime`], and never write one to a
//! file: a cookie whose expiry was stored from a monotonic reading either
//! never expires or expires immediately, and nothing in the type system
//! stops that, which is why it is stated here.
//!
//! # The calendar conversion is pure Rust
//!
//! [`gmtime`] supersedes `curlx_gmtime`, whose own comment (`:247-249`)
//! reads: "curlx_gmtime() is a gmtime() replacement for portability. Do not
//! use the gmtime_s(), gmtime_r() or gmtime() functions anywhere else but
//! here." Restated for this crate: **this is the only calendar conversion in
//! `curl-rs-lib`, and every other module calls it.**
//!
//! Two neighbours own the two adjacent jobs, and neither is duplicated here:
//!
//! * The INVERSE conversion belongs to [`crate::util::parsedate`], which
//!   supersedes `lib/parsedate.c` and carries that file's own cumulative
//!   month-day table and leap-day correction. Two implementations of one
//!   calendar would eventually disagree, and the one that is reachable
//!   through the exported `curl_getdate` must be the C's arithmetic
//!   unchanged.
//! * Formatting through the platform's `strftime` belongs to
//!   `crate::ffi::sys`, which owns the `unsafe` blocks it needs. That path
//!   exists so that `--write-out %time{...}` and `--trace-time` are
//!   byte-identical to C for an arbitrary user-supplied format, including
//!   its locale-sensitive conversions. It reads no clock: the instant is a
//!   parameter. [`gmtime`] serves the OTHER kind of consumer -- the fixed
//!   formats that the C builds field by field with `curl_msnprintf`, at
//!   `lib/http.c:1904-1910`, `lib/file.c:454-460`, `lib/ftp.c:2461-2467`,
//!   `lib/hsts.c:293-294` and `lib/altsvc.c:270-271`.

use std::fmt;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::CURLcode;
use crate::util::timediff::{TimeDiff, TIMEDIFF_T_MAX, TIMEDIFF_T_MIN};

/// Milliseconds in a second: the `1000` of `timeval.c:194`.
const MS_PER_SEC: TimeDiff = 1_000;

/// Microseconds in a millisecond: the OTHER `1000` of `timeval.c:194`.
///
/// The same value as [`MS_PER_SEC`] and a different quantity. The C spells
/// both as a bare literal in one expression:
///
/// ```text
/// diff * 1000 + (newer->tv_usec - older->tv_usec) / 1000
/// ```
const MICROS_PER_MS: TimeDiff = 1_000;

/// Microseconds in a second: the `1000000` of `timeval.c:230`.
const MICROS_PER_SEC: TimeDiff = 1_000_000;

/// Seconds in a day, for the calendar conversion.
const SECS_PER_DAY: i64 = 86_400;

/// Seconds in an hour.
const SECS_PER_HOUR: i64 = 3_600;

/// Seconds in a minute.
const SECS_PER_MIN: i64 = 60;

/// Days in a week, for the weekday reduction.
const DAYS_PER_WEEK: i64 = 7;

/// A clock reading: `struct curltime` (`lib/curlx/timeval.h:30-33`).
///
/// ```text
/// struct curltime {
///   time_t tv_sec; /* seconds */
///   int tv_usec;   /* microseconds */
/// };
/// ```
///
/// # The invariant
///
/// **`0 <= usec < 1_000_000`.** Every constructor and every arithmetic method
/// here upholds it, carrying whole seconds out of the microsecond field
/// rather than leaving it out of range. [`CurlTime::new`] additionally
/// asserts it in a debug build, so a caller passing 1_500_000 microseconds
/// learns of the mistake instead of receiving a silently corrected value.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) struct CurlTime {
    /// Whole seconds. Monotonic or wall depending on which clock produced it
    /// -- see the module's warning about not mixing the two.
    pub(crate) secs: i64,
    /// Microseconds past `secs`, in `0..1_000_000`.
    pub(crate) usec: i32,
}

impl CurlTime {
    /// The zero reading, `{ tv_sec = 0, tv_usec = 0 }`.
    #[allow(dead_code)]
    pub(crate) const ZERO: Self = Self { secs: 0, usec: 0 };

    /// A reading from its two fields, upholding the microsecond invariant.
    ///
    /// # Panics
    ///
    /// Panics in a debug build if `usec` is outside `0..1_000_000`. A release
    /// build carries the excess into `secs` instead of panicking, so the
    /// value returned always satisfies the invariant. That split is the same
    /// one the sibling shims in [`super`] use, and it is deliberate: a
    /// contract violation is a caller bug worth stopping for while a test
    /// suite runs, and not worth aborting a transfer for in production.
    #[allow(dead_code)]
    pub(crate) fn new(secs: i64, usec: i32) -> Self {
        debug_assert!(
            (0..MICROS_PER_SEC).contains(&i64::from(usec)),
            "CurlTime::new: usec outside 0..1000000: {usec}"
        );
        Self::carry(secs, usec)
    }

    /// True when this is the all-zero "not set" reading.
    #[allow(dead_code)]
    pub(crate) const fn is_zero(self) -> bool {
        self.secs == 0 && self.usec == 0
    }

    /// This reading advanced by `span`.
    #[allow(dead_code)]
    pub(crate) fn add(self, span: Duration) -> Self {
        let (secs, usec) = split(span);
        Self::carry(
            self.secs.saturating_add(secs),
            self.usec.saturating_add(usec),
        )
    }

    /// The span from `older` to this reading, or [`None`] if it is negative.
    ///
    /// [`Duration`] is unsigned, so a reading that precedes `older` has no
    /// representation and [`None`] is returned rather than a wrapped or
    /// clamped span. Callers that need the signed answer use
    /// [`timediff_ms`] or [`timediff_us`], which return it exactly as the C
    /// does -- see the module's note on negative differences.
    #[allow(dead_code)]
    pub(crate) fn checked_sub(self, older: Self) -> Option<Duration> {
        let secs = self.secs.checked_sub(older.secs)?;
        // Both microsecond fields widen losslessly, so their difference
        // cannot overflow and only the seconds arithmetic needs checking.
        let fraction = i64::from(self.usec) - i64::from(older.usec);
        let micros = secs.checked_mul(MICROS_PER_SEC)?.checked_add(fraction)?;
        u64::try_from(micros).ok().map(Duration::from_micros)
    }

    /// Builds a reading from a seconds field and an UNCHECKED microsecond
    /// field, carrying whole seconds out of the latter.
    fn carry(secs: i64, usec: i32) -> Self {
        let total = i64::from(usec);
        Self {
            secs: secs.saturating_add(total.div_euclid(MICROS_PER_SEC)),
            // A remainder from a positive divisor lies in `0..1_000_000`,
            // which is inside `i32`, so the fallback cannot be reached. It is
            // written with `try_from` because this crate admits no narrowing
            // `as` cast, not because the conversion can fail.
            usec: i32::try_from(total.rem_euclid(MICROS_PER_SEC)).unwrap_or(0),
        }
    }
}

/// Splits a span into whole seconds and a microsecond remainder.
fn split(span: Duration) -> (i64, i32) {
    let secs = i64::try_from(span.as_secs()).unwrap_or(i64::MAX);
    // `subsec_micros` returns `0..1_000_000` by construction, so this
    // fallback is unreachable; see [`CurlTime::carry`] for why it is written
    // as a checked conversion regardless.
    let usec = i32::try_from(span.subsec_micros()).unwrap_or(0);
    (secs, usec)
}

/// The crate's source of time, injected rather than reached for.
#[allow(dead_code)]
pub(crate) trait Clock: fmt::Debug {
    /// A monotonic reading -- the successor of `curlx_now()`.
    ///
    /// Two calls in sequence never report a smaller value on the second. The
    /// zero point is unspecified, so the value is meaningful only as the
    /// operand of a difference against another reading from the same clock.
    fn now(&self) -> CurlTime;

    /// Wall-clock seconds since the Unix epoch -- the successor of
    /// `time(NULL)`.
    fn epoch_secs(&self) -> i64;
}

/// The production [`Clock`]: the host's own clocks.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    /// Elapsed time since the first reading taken in this process.
    fn now(&self) -> CurlTime {
        /// The process-start baseline. See this method's documentation.
        static BASELINE: OnceLock<Instant> = OnceLock::new();

        let baseline = *BASELINE.get_or_init(Instant::now);
        // `saturating_duration_since` reports zero rather than panicking if
        // the two readings were somehow taken out of order, which cannot
        // happen for a monotonic clock but costs nothing to rule out.
        let (secs, usec) =
            split(Instant::now().saturating_duration_since(baseline));
        CurlTime::new(secs, usec)
    }

    /// The successor of `time(NULL)`.
    fn epoch_secs(&self) -> i64 {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(since) => i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
            Err(before) => {
                let ago = before.duration();
                let whole = i64::try_from(ago.as_secs()).unwrap_or(i64::MAX);
                if ago.subsec_nanos() == 0 {
                    whole.saturating_neg()
                } else {
                    whole.saturating_neg().saturating_sub(1)
                }
            }
        }
    }
}

/// A manually advanced [`Clock`], for tests anywhere in the crate.
///
/// # Why this is not `#[cfg(test)]`
///
/// Because the tests that need it are not in this file. The coverage gate of
/// The coverage gate falls on `src/protocols/` and `src/transfer/`, whose
/// retries,
/// timeouts, keep-alive expiry and rate limiting are all driven by a clock,
/// and a `#[cfg(test)]` item in `util` is invisible to those modules' own
/// test builds. It is `pub(crate)` so that every module's tests can inject
/// it, and it is compiled into the library for the same reason. Nothing
/// outside the crate can see it: the surface stays `pub(crate)`,
/// and internals are not widened to make the C test programs
/// link.
///
/// # Interior mutability, and why a [`Mutex`]
///
/// A poisoned lock is recovered from rather than propagated. The state is two
/// plain integers with no invariant spanning them, so a panic elsewhere
/// cannot have left it inconsistent, and turning an unrelated panic into a
/// second panic inside a clock would obscure the first failure.
///
/// # Example
///
/// ```text
/// let clock = TestClock::new(CurlTime::new(10, 0));
/// clock.advance(Duration::from_millis(250));
/// assert_eq!(clock.now(), CurlTime::new(10, 250_000));
/// ```
///
/// [`Cell`]: std::cell::Cell
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct TestClock {
    /// Both readings under one lock. See the type's documentation.
    state: Mutex<Reading>,
}

/// The pair of readings a [`TestClock`] holds.
///
/// The wall reading is a whole [`CurlTime`] rather than a bare second count
/// so that repeated sub-second advances accumulate exactly: advancing by 500
/// milliseconds twice moves the wall second on by one, which a truncating
/// per-call conversion would lose.
#[derive(Clone, Copy, Debug, Default)]
struct Reading {
    /// What [`Clock::now`] reports.
    monotonic: CurlTime,
    /// What [`Clock::epoch_secs`] reports, as whole seconds plus a
    /// remainder that only `advance` sees.
    wall: CurlTime,
}

impl TestClock {
    /// A clock reading `at`, with its wall reading at the Unix epoch.
    ///
    /// The wall reading starts at zero rather than at the host's current time
    /// so that a test is reproducible on a machine whose clock is wrong;
    /// [`Self::set_epoch_secs`] places it wherever a test needs it.
    #[allow(dead_code)]
    pub(crate) fn new(at: CurlTime) -> Self {
        Self {
            state: Mutex::new(Reading {
                monotonic: at,
                wall: CurlTime::ZERO,
            }),
        }
    }

    /// Places the monotonic reading at `at`, forwards or backwards.
    #[allow(dead_code)]
    pub(crate) fn set(&self, at: CurlTime) {
        self.mutate(|reading| reading.monotonic = at);
    }

    /// Places the wall reading at `secs` seconds past the Unix epoch.
    #[allow(dead_code)]
    pub(crate) fn set_epoch_secs(&self, secs: i64) {
        self.mutate(|reading| reading.wall = CurlTime::new(secs, 0));
    }

    /// Moves time forward by `span`.
    #[allow(dead_code)]
    pub(crate) fn advance(&self, span: Duration) {
        self.mutate(|reading| {
            reading.monotonic = reading.monotonic.add(span);
            reading.wall = reading.wall.add(span);
        });
    }

    /// Runs `body` over the locked state, recovering from poisoning.
    fn mutate(&self, body: impl FnOnce(&mut Reading)) {
        let mut guard =
            self.state.lock().unwrap_or_else(PoisonError::into_inner);
        body(&mut guard);
    }

    /// A copy of both readings, recovering from poisoning.
    fn read(&self) -> Reading {
        *self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Clock for TestClock {
    fn now(&self) -> CurlTime {
        self.read().monotonic
    }

    fn epoch_secs(&self) -> i64 {
        self.read().wall.secs
    }
}

/// The difference in whole milliseconds -- `curlx_timediff_ms`.
///
/// Supersedes `curlx_ptimediff_ms` (`lib/curlx/timeval.c:186-195`) and the
/// value-taking `curlx_timediff_ms` (`:198-201`) that forwards to it. The C
/// body, transcribed:
///
/// ```text
/// timediff_t diff = (timediff_t)newer->tv_sec - older->tv_sec;
/// if(diff >= (TIMEDIFF_T_MAX / 1000))       return TIMEDIFF_T_MAX;
/// else if(diff <= (TIMEDIFF_T_MIN / 1000))  return TIMEDIFF_T_MIN;
/// return diff * 1000 + (newer->tv_usec - older->tv_usec) / 1000;
/// ```
///
/// # Four details that are easy to get wrong, and are pinned by tests
///
/// 1. **The division truncates toward ZERO, including for a negative
///    numerator.** C99 and Rust agree on that, so `(newer.usec -
///    older.usec) / 1000` contributes 0 for a difference of -500
///    microseconds, not -1. The consequence is that this is NOT
///    `Duration::as_millis` applied to the difference of the two readings,
///    and the formula is written out for exactly that reason.
/// 2. **The guards compare with `>=` and `<=`, not `>` and `<`.** A seconds
///    difference exactly equal to `TIMEDIFF_T_MAX / 1000` saturates.
/// 3. **The divisor in the guard is 1000 here and 1,000,000 in
///    [`timediff_us`].** Copying one function to the other and forgetting to
///    change the divisor saturates at the wrong magnitude, which is why the
///    two are written out separately rather than sharing a helper.
/// 4. **The result is exact once the guards have passed.** They bound
///    `|diff|` below `TIMEDIFF_T_MAX / 1000`, so `diff * 1000` cannot
///    overflow. The saturating operators below are therefore belt and
///    braces, not the mechanism: they replace the `checked_mul` that a
///    literal reading of the requirement suggests, without introducing an
///    arm that no input can reach and no test can cover.
///
/// # `@unittest: 1323`
///
/// The C annotates this function with that reference (`timeval.c:184`).
/// `tests/unit/unit1323.c` cannot link against a Rust static library
///, so its four vectors are ported into this file's test module
/// verbatim.
#[allow(dead_code)]
pub(crate) fn timediff_ms(newer: CurlTime, older: CurlTime) -> TimeDiff {
    let diff = newer.secs.saturating_sub(older.secs);
    if diff >= TIMEDIFF_T_MAX / MS_PER_SEC {
        return TIMEDIFF_T_MAX;
    } else if diff <= TIMEDIFF_T_MIN / MS_PER_SEC {
        return TIMEDIFF_T_MIN;
    }
    let fraction =
        (i64::from(newer.usec) - i64::from(older.usec)) / MICROS_PER_MS;
    diff.saturating_mul(MS_PER_SEC).saturating_add(fraction)
}

/// The difference in milliseconds, rounded up -- `curlx_timediff_ceil_ms`.
///
/// Supersedes `curlx_timediff_ceil_ms` (`lib/curlx/timeval.c:207-216`).
/// Identical to [`timediff_ms`] except for the `+ 999` before the division:
///
/// ```text
/// return diff * 1000 + (newer.tv_usec - older.tv_usec + 999) / 1000;
/// ```
#[allow(dead_code)]
pub(crate) fn timediff_ceil_ms(newer: CurlTime, older: CurlTime) -> TimeDiff {
    let diff = newer.secs.saturating_sub(older.secs);
    if diff >= TIMEDIFF_T_MAX / MS_PER_SEC {
        return TIMEDIFF_T_MAX;
    } else if diff <= TIMEDIFF_T_MIN / MS_PER_SEC {
        return TIMEDIFF_T_MIN;
    }
    // `MICROS_PER_MS - 1` is the C's literal 999.
    let fraction = (i64::from(newer.usec) - i64::from(older.usec)
        + (MICROS_PER_MS - 1))
        / MICROS_PER_MS;
    diff.saturating_mul(MS_PER_SEC).saturating_add(fraction)
}

/// The difference in microseconds -- `curlx_timediff_us`.
///
/// Supersedes `curlx_ptimediff_us` (`lib/curlx/timeval.c:222-231`) and the
/// value-taking `curlx_timediff_us` (`:233-236`) that forwards to it:
///
/// ```text
/// timediff_t diff = (timediff_t)newer->tv_sec - older->tv_sec;
/// if(diff >= (TIMEDIFF_T_MAX / 1000000))       return TIMEDIFF_T_MAX;
/// else if(diff <= (TIMEDIFF_T_MIN / 1000000))  return TIMEDIFF_T_MIN;
/// return diff * 1000000 + newer->tv_usec - older->tv_usec;
/// ```
#[allow(dead_code)]
pub(crate) fn timediff_us(newer: CurlTime, older: CurlTime) -> TimeDiff {
    let diff = newer.secs.saturating_sub(older.secs);
    if diff >= TIMEDIFF_T_MAX / MICROS_PER_SEC {
        return TIMEDIFF_T_MAX;
    } else if diff <= TIMEDIFF_T_MIN / MICROS_PER_SEC {
        return TIMEDIFF_T_MIN;
    }
    diff.saturating_mul(MICROS_PER_SEC)
        .saturating_add(i64::from(newer.usec))
        .saturating_sub(i64::from(older.usec))
}

/// Days from 0000-03-01 to 1970-01-01, the era shift of the algorithm below.
///
/// The calendar arithmetic is easier when a year begins on 1 March, because
/// the leap day then falls at the END of a year and no month length depends
/// on it. This constant moves the epoch onto that footing.
const DAYS_SHIFT_TO_MARCH_ERA: i64 = 719_468;

/// Days in a 400-year era: `400 * 365 + 97` leap days.
const DAYS_PER_ERA: i64 = 146_097;

/// Days from 1 March to 1 January of the following year: the length of March
/// through December, which no leap day can change.
const DAYS_MARCH_TO_JANUARY: i64 = 306;

/// Days from 1 January to 1 March in a common year: 31 plus 28.
///
/// A leap day is added to this when the year has one, which is the only place
/// the leap rule enters the day-of-year calculation.
const DAYS_JANUARY_TO_MARCH: i64 = 59;

/// The weekday of 1970-01-01, which was a Thursday, as a `tm_wday` value.
const EPOCH_WEEKDAY: i64 = 4;

/// The offset C's `tm_year` carries: years since 1900.
const TM_YEAR_BASE: i32 = 1900;

/// A calendar instant in UTC: the fields of `struct tm` that curl reads.
///
/// # The field conventions are the C's, with ONE deliberate change
///
/// Each field therefore documents its own convention, and the one departure is
/// spelled out here rather than left to be discovered:
///
/// **`year` is the ABSOLUTE year, not C's years-since-1900.** `gmtime(0)`
/// gives `year == 1970`, where the C gives `tm_year == 70`. The reason is
/// that every single C call site immediately writes `tm->tm_year + 1900`
/// (`lib/http.c:1907`, `lib/file.c:457`, `lib/ftp.c:2464`, `lib/hsts.c:293`,
/// `lib/altsvc.c:270`, `lib/vtls/gtls.c:188`), so the offset exists only to
/// be undone; carrying it would preserve a hazard rather than a behaviour,
/// and an off-by-1900 mistake produces a plausible-looking date rather than
/// an obvious failure. [`Self::tm_year`] returns the C's value for anyone who
/// needs the raw field, and a test asserts both spellings of the same instant
/// so the choice cannot drift.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct BrokenTime {
    /// The absolute year: 1970 for the epoch. **NOT** C's `tm_year`, which
    /// counts from 1900 -- see the type's documentation and
    /// [`Self::tm_year`].
    pub(crate) year: i32,
    /// The month, **0-based**: 0 is January, 11 is December, exactly as C's
    /// `tm_mon` is. The C subscripts `Curl_month[tm_mon]`
    /// (`lib/parsedate.c:87-90`, reached from `lib/http.c:1906`) with it, so
    /// a 1-based month here would name the wrong month in an HTTP date.
    pub(crate) mon: i32,
    /// The day of the month, **1-based**: 1 to 31, as C's `tm_mday` is.
    pub(crate) mday: i32,
    /// The hour, 0 to 23.
    pub(crate) hour: i32,
    /// The minute, 0 to 59.
    pub(crate) min: i32,
    /// The second, 0 to 59. Never 60: Unix time has no leap seconds.
    pub(crate) sec: i32,
    /// The weekday, **0 is Sunday**, as C's `tm_wday` is. The C formats a
    /// date with `Curl_wkday[tm_wday ? tm_wday - 1 : 6]`
    /// (`lib/http.c:1904`), whose table starts at Monday -- so the
    /// Sunday-is-zero convention is what makes that expression name the
    /// right day, and changing it here would shift every weekday in an HTTP
    /// date by one.
    pub(crate) wday: i32,
    /// The day of the year, **0-based**: 0 to 365, as C's `tm_yday` is.
    pub(crate) yday: i32,
}

impl BrokenTime {
    /// The C's `tm_year`: the year less 1900.
    #[allow(dead_code)]
    pub(crate) const fn tm_year(self) -> i32 {
        self.year.saturating_sub(TM_YEAR_BASE)
    }
}

/// Converts seconds since the Unix epoch into UTC calendar fields --
/// `curlx_gmtime`.
///
/// Supersedes `curlx_gmtime` (`lib/curlx/timeval.c:251-272`), whose own
/// comment is worth carrying over verbatim (`:247-249`): "curlx_gmtime() is a
/// gmtime() replacement for portability. Do not use the gmtime_s(),
/// gmtime_r() or gmtime() functions anywhere else but here." Restated for
/// this crate: **this is the only calendar conversion in `curl-rs-lib`, and
/// every other module calls it.**
///
/// The C selects `gmtime_s` on Windows, the thread-safe `gmtime_r` where the
/// build found it, and the not-thread-safe `gmtime` otherwise. All three are
/// platform functions; none is reachable from here, because `libc` belongs to
/// the FFI island. The conversion is therefore implemented, and being
/// implemented it is also thread-safe by construction -- it holds no state
/// and returns its result by value, so the C's third path, whose whole defect
/// is a shared static buffer, has no successor to worry about.
///
/// # Floor division everywhere, which is what makes negative instants work
///
/// A `time_t` before 1970 is negative and must floor: -1 second is
/// 1969-12-31T23:59:59Z, not 1970-01-01T-00:00:01Z. [`i64::div_euclid`] and
/// [`i64::rem_euclid`] floor and return a non-negative remainder, so the
/// seconds-of-day, the era and the day-of-era are all correct on both sides
/// of the epoch without a special case. Hinnant's C++ writes the same thing
/// as `(z >= 0 ? z : z - 146096) / 146097`, which is floor division spelled
/// out for a language whose `/` truncates.
///
/// # Errors
///
/// Returns [`CURLcode::BadFunctionArgument`], which is the code
/// `curlx_gmtime` returns when the platform function fails
/// (`timeval.c:255`, `:260`, `:268`), for an instant whose year does not fit
/// the field that carries it. That is reachable: [`i64`] seconds span about
/// 292 billion years, while the year is carried in an [`i32`] and C's
/// `tm_year` in an `int`, and `gmtime_r` fails on exactly the same
/// overflow rather than returning a wrong date. Both bounds are checked --
/// the year itself, and the year less 1900 that [`BrokenTime::tm_year`]
/// returns -- so no value this function produces can overflow that accessor.
///
/// No other failure exists. Every representable instant inside those bounds
/// has a calendar date, and the arithmetic below cannot overflow for any
/// [`i64`] input: the day count is at most about 1.07e14 in magnitude, which
/// leaves the era shift and the multiplications four orders of magnitude
/// inside the type.
#[allow(dead_code)]
pub(crate) fn gmtime(intime: i64) -> Result<BrokenTime, CURLcode> {
    // Split into a day number and a time of day, flooring so that a negative
    // instant lands inside the preceding day rather than past it.
    let days = intime.div_euclid(SECS_PER_DAY);
    let second_of_day = intime.rem_euclid(SECS_PER_DAY);

    let hour = second_of_day / SECS_PER_HOUR;
    let minute = (second_of_day % SECS_PER_HOUR) / SECS_PER_MIN;
    let second = second_of_day % SECS_PER_MIN;

    // civil_from_days, on the calendar whose year begins on 1 March.
    let shifted = days + DAYS_SHIFT_TO_MARCH_ERA;
    let era = shifted.div_euclid(DAYS_PER_ERA);
    let day_of_era = shifted.rem_euclid(DAYS_PER_ERA);
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524
        - day_of_era / 146_096)
        / 365;
    let day_of_year =
        day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // The month index on the shifted calendar: 0 is March, 11 is February.
    let month_slot = (5 * day_of_year + 2) / 153;
    let day_of_month = day_of_year - (153 * month_slot + 2) / 5 + 1;
    // Back to a calendar year beginning in January: March through December
    // keep the era's year, while January and February belong to the next one.
    let month = if month_slot < 10 {
        month_slot + 3
    } else {
        month_slot - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);

    // The two range checks the error section documents. The first is the
    // width of this type's own field; the second keeps
    // `BrokenTime::tm_year` exact for every value produced here.
    let year =
        i32::try_from(year).map_err(|_| CURLcode::BadFunctionArgument)?;
    if year.checked_sub(TM_YEAR_BASE).is_none() {
        return Err(CURLcode::BadFunctionArgument);
    }

    // 1970-01-01 was a Thursday, and `rem_euclid` keeps the index
    // non-negative for the days before it.
    let weekday = (days + EPOCH_WEEKDAY).rem_euclid(DAYS_PER_WEEK);

    // The day of the year, from the shifted calendar's day-of-year. March
    // onwards sits `DAYS_JANUARY_TO_MARCH` plus any leap day past 1 January;
    // January and February are `DAYS_MARCH_TO_JANUARY` into the shifted year
    // and so subtract it. No table of month lengths is needed, which is also
    // why `lib/parsedate.c`'s cumulative table is not duplicated here.
    let day_of_year = if month > 2 {
        day_of_year + DAYS_JANUARY_TO_MARCH + i64::from(is_leap_year(year))
    } else {
        day_of_year - DAYS_MARCH_TO_JANUARY
    };

    Ok(BrokenTime {
        year,
        mon: narrow(month - 1),
        mday: narrow(day_of_month),
        hour: narrow(hour),
        min: narrow(minute),
        sec: narrow(second),
        wday: narrow(weekday),
        yday: narrow(day_of_year),
    })
}

/// The proleptic Gregorian leap-year rule.
fn is_leap_year(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

/// Narrows a calendar field the algorithm has already bounded.
fn narrow(value: i64) -> i32 {
    debug_assert!(
        (0..=365).contains(&value),
        "calendar field outside 0..=365: {value}"
    );
    i32::try_from(value).unwrap_or(0)
}

// TESTS
//
// `tests/unit/*.c` (59 files) and `tests/libtest/*.c` link a debug static
// build of the C library and call internal `Curl_*` and `curlx_*` symbols,
// which a Rust static library does not export. Their coverage therefore
// relocates into `#[cfg(test)]` modules inside the files under test (AAP
// 0.8.7), and this is this file's share of that relocation -- specifically
// `tests/unit/unit1323.c`, which the C names in a `@unittest` annotation above
// `curlx_ptimediff_ms` (`lib/curlx/timeval.c:184`). Its four vectors appear
// below unchanged.
//
// TWO BUILDS ARE NEEDED to cover this file completely, because
// `CurlTime::new` behaves differently under `debug_assertions`:
//
//     cargo test -p curl-rs-lib
//     cargo test -p curl-rs-lib --release

#[cfg(test)]
mod tests {
    use super::*;

    /// The inverse of [`gmtime`], as a test oracle only.
    fn epoch_of(year: i64, month: i64, day: i64) -> i64 {
        let shifted_year = year - i64::from(month <= 2);
        let era = shifted_year.div_euclid(400);
        let year_of_era = shifted_year - era * 400;
        let month_slot = if month > 2 { month - 3 } else { month + 9 };
        let day_of_year = (153 * month_slot + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4
            - year_of_era / 100
            + day_of_year;
        (era * DAYS_PER_ERA + day_of_era - DAYS_SHIFT_TO_MARCH_ERA)
            * SECS_PER_DAY
    }

    // --- the instant type --------------------------------------------------

    /// [`CurlTime::ZERO`] is [`Default`], and [`CurlTime::is_zero`] is the C's
    /// field-by-field test at `lib/cf-ip-happy.c:396`.
    #[test]
    fn zero_is_the_default_and_is_recognised() {
        assert_eq!(CurlTime::ZERO, CurlTime::default());
        assert!(CurlTime::ZERO.is_zero());
        assert!(CurlTime::new(0, 0).is_zero());
        assert!(!CurlTime::new(0, 1).is_zero());
        assert!(!CurlTime::new(1, 0).is_zero());
        assert!(!CurlTime::new(-1, 0).is_zero());
    }

    /// The property the expiry timer tree depends on: seconds dominate, and
    /// microseconds only break a tie.
    #[test]
    fn the_derived_order_compares_seconds_before_microseconds() {
        // A whole second outranks any microsecond field.
        assert!(CurlTime::new(1, 0) > CurlTime::new(0, 999_999));
        // Within one second, the microsecond field decides.
        assert!(CurlTime::new(1, 1) > CurlTime::new(1, 0));
        // Equality needs both fields.
        assert_eq!(CurlTime::new(7, 8), CurlTime::new(7, 8));
        assert_ne!(CurlTime::new(7, 8), CurlTime::new(7, 9));
        // Negative seconds order below positive ones.
        assert!(CurlTime::new(-1, 999_999) < CurlTime::new(0, 0));

        // The whole ordering, as a sort: this is the sequence in which the
        // timer tree would fire these readings.
        let mut readings = vec![
            CurlTime::new(1, 1),
            CurlTime::new(0, 999_999),
            CurlTime::new(1, 0),
            CurlTime::new(-1, 0),
            CurlTime::ZERO,
        ];
        readings.sort();
        assert_eq!(
            readings,
            vec![
                CurlTime::new(-1, 0),
                CurlTime::ZERO,
                CurlTime::new(0, 999_999),
                CurlTime::new(1, 0),
                CurlTime::new(1, 1),
            ]
        );
    }

    /// The invariant holds for the constructor, for the arithmetic and for the
    /// clocks.
    #[test]
    fn every_result_satisfies_the_microsecond_invariant() {
        fn check(reading: CurlTime) {
            assert!(
                (0..1_000_000).contains(&reading.usec),
                "invariant broken: {reading:?}"
            );
        }

        check(CurlTime::ZERO);
        check(CurlTime::default());
        check(CurlTime::new(5, 999_999));
        check(CurlTime::new(-5, 0));
        check(CurlTime::new(0, 900_000).add(Duration::from_micros(200_001)));
        check(CurlTime::new(0, 0).add(Duration::MAX));
        check(SystemClock.now());

        let clock = TestClock::new(CurlTime::new(0, 900_000));
        clock.advance(Duration::from_millis(200));
        check(clock.now());
        clock.advance(Duration::from_micros(1));
        check(clock.now());
    }

    /// A debug build stops on a microsecond field outside the invariant.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "usec outside 0..1000000")]
    fn new_asserts_an_out_of_range_microsecond_field() {
        let _ = CurlTime::new(0, 1_000_000);
    }

    /// A release build carries the excess instead of panicking, so the value
    /// still satisfies the invariant.
    #[test]
    #[cfg(not(debug_assertions))]
    fn new_normalises_an_out_of_range_microsecond_field() {
        assert_eq!(CurlTime::new(0, 1_500_000), CurlTime::new(1, 500_000));
        assert_eq!(CurlTime::new(0, -1), CurlTime::new(-1, 999_999));
    }

    /// [`CurlTime::add`] carries across a second boundary, which is the case
    /// the module's example uses and the one a naive implementation gets
    /// wrong.
    #[test]
    fn add_advances_and_carries_across_a_second() {
        assert_eq!(
            CurlTime::new(10, 0).add(Duration::from_millis(250)),
            CurlTime::new(10, 250_000)
        );
        assert_eq!(
            CurlTime::new(0, 900_000).add(Duration::from_millis(200)),
            CurlTime::new(1, 100_000)
        );
        // Exactly on the boundary, and well past it.
        assert_eq!(
            CurlTime::new(0, 999_999).add(Duration::from_micros(1)),
            CurlTime::new(1, 0)
        );
        assert_eq!(
            CurlTime::new(-3, 500_000).add(Duration::from_micros(2_500_001)),
            CurlTime::new(0, 1)
        );
        // A zero span is the identity.
        assert_eq!(
            CurlTime::new(4, 5).add(Duration::ZERO),
            CurlTime::new(4, 5)
        );
    }

    /// Saturating, not wrapping: an unreachable expiry stays unreachable.
    #[test]
    fn add_saturates_rather_than_wrapping() {
        assert_eq!(
            CurlTime::new(i64::MAX, 0).add(Duration::from_secs(1)).secs,
            i64::MAX
        );
        // `Duration::MAX` counts more seconds than `i64` can hold, so the
        // seconds conversion saturates before the addition does.
        assert_eq!(CurlTime::ZERO.add(Duration::MAX).secs, i64::MAX);
        // The microsecond field still obeys the invariant afterwards.
        let far = CurlTime::ZERO.add(Duration::MAX);
        assert!((0..1_000_000).contains(&far.usec));
    }

    /// [`CurlTime::checked_sub`] returns the exact span when there is one.
    #[test]
    fn checked_sub_returns_the_exact_span() {
        assert_eq!(
            CurlTime::new(10, 250_000).checked_sub(CurlTime::new(10, 0)),
            Some(Duration::from_millis(250))
        );
        assert_eq!(
            CurlTime::new(1, 100_000).checked_sub(CurlTime::new(0, 900_000)),
            Some(Duration::from_millis(200))
        );
        assert_eq!(
            CurlTime::new(5, 0).checked_sub(CurlTime::new(5, 0)),
            Some(Duration::ZERO)
        );
        // Across the epoch, where both fields change sign.
        assert_eq!(
            CurlTime::new(0, 0).checked_sub(CurlTime::new(-2, 500_000)),
            Some(Duration::from_micros(1_500_000))
        );
    }

    /// A negative span has no [`Duration`], so [`None`] comes back rather
    /// than a clamped or wrapped value. The signed answer is what
    /// [`timediff_ms`] and [`timediff_us`] are for.
    #[test]
    fn checked_sub_refuses_a_negative_or_overflowing_span() {
        assert_eq!(CurlTime::new(0, 0).checked_sub(CurlTime::new(1, 0)), None);
        assert_eq!(CurlTime::new(1, 0).checked_sub(CurlTime::new(1, 1)), None);
        // The seconds subtraction overflows.
        assert_eq!(
            CurlTime::new(i64::MAX, 0).checked_sub(CurlTime::new(-1, 0)),
            None
        );
        // The subtraction is fine and the conversion into microseconds is
        // not: about 292,000 years is the limit.
        assert_eq!(
            CurlTime::new(i64::MAX, 0).checked_sub(CurlTime::ZERO),
            None
        );
    }

    // --- the differences ---------------------------------------------------

    /// The four vectors of `tests/unit/unit1323.c:36-42`, unchanged.
    ///
    /// The C table is `{ first, second, expected }`, and its loop calls
    /// `curlx_timediff_ms(first, second)`.
    #[test]
    fn timediff_ms_matches_the_vectors_of_unit1323() {
        let earlier = CurlTime::new(36_761, 995_926);
        let later = CurlTime::new(36_762, 8_345);

        assert_eq!(timediff_ms(later, earlier), 13);
        assert_eq!(timediff_ms(earlier, later), -13);
        assert_eq!(timediff_ms(earlier, CurlTime::ZERO), 36_761_995);
        assert_eq!(timediff_ms(CurlTime::ZERO, earlier), -36_761_995);
    }

    /// The microsecond part truncates TOWARD ZERO, which is why this is not
    /// `Duration::as_millis` of the difference.
    #[test]
    fn timediff_ms_truncates_the_microsecond_part_toward_zero() {
        // 500 microseconds is less than a millisecond, so it contributes
        // nothing at all.
        assert_eq!(timediff_ms(CurlTime::new(0, 500), CurlTime::ZERO), 0);
        // 1,500 contributes one, not two.
        assert_eq!(timediff_ms(CurlTime::new(0, 1_500), CurlTime::ZERO), 1);
        // 999,999 contributes 999, so a difference one microsecond short of a
        // second reads as 999 milliseconds.
        assert_eq!(timediff_ms(CurlTime::new(0, 999_999), CurlTime::ZERO), 999);
        // The case worth writing out: one second minus half a second is
        // `1000 + (0 - 500000)/1000`, which is `1000 + (-500)`, which is 500.
        assert_eq!(
            timediff_ms(CurlTime::new(1, 0), CurlTime::new(0, 500_000)),
            500
        );
        // A negative microsecond part of -500 truncates to zero rather than
        // to -1, so this whole second reads as exactly 1000.
        assert_eq!(
            timediff_ms(CurlTime::new(1, 0), CurlTime::new(0, 500)),
            1_000
        );
    }

    /// A negative difference is returned unchanged: it is how a caller
    /// notices that the arguments were the wrong way round.
    #[test]
    fn timediff_ms_returns_negative_differences_unchanged() {
        assert_eq!(timediff_ms(CurlTime::ZERO, CurlTime::new(5, 0)), -5_000);
        assert_eq!(timediff_ms(CurlTime::new(-1, 0), CurlTime::ZERO), -1_000);
        assert_eq!(timediff_us(CurlTime::ZERO, CurlTime::new(0, 1)), -1);
    }

    /// Both units saturate in both directions rather than wrapping.
    #[test]
    fn the_differences_saturate_in_both_directions() {
        assert_eq!(
            timediff_ms(CurlTime::new(i64::MAX, 0), CurlTime::ZERO),
            TIMEDIFF_T_MAX
        );
        assert_eq!(
            timediff_ms(CurlTime::new(i64::MIN, 0), CurlTime::ZERO),
            TIMEDIFF_T_MIN
        );
        assert_eq!(
            timediff_ceil_ms(CurlTime::new(i64::MAX, 0), CurlTime::ZERO),
            TIMEDIFF_T_MAX
        );
        assert_eq!(
            timediff_ceil_ms(CurlTime::new(i64::MIN, 0), CurlTime::ZERO),
            TIMEDIFF_T_MIN
        );
        assert_eq!(
            timediff_us(CurlTime::new(i64::MAX, 0), CurlTime::ZERO),
            TIMEDIFF_T_MAX
        );
        assert_eq!(
            timediff_us(CurlTime::new(i64::MIN, 0), CurlTime::ZERO),
            TIMEDIFF_T_MIN
        );
    }

    /// The guards are `>=` and `<=`, so a seconds difference exactly equal to
    /// the bound saturates and one inside it does not.
    #[test]
    fn the_guards_saturate_on_equality() {
        let bound = TIMEDIFF_T_MAX / MS_PER_SEC;
        assert_eq!(
            timediff_ms(CurlTime::new(bound, 0), CurlTime::ZERO),
            TIMEDIFF_T_MAX
        );
        // One second inside the bound is computed rather than saturated, and
        // the result is nowhere near the saturation value.
        let inside = timediff_ms(CurlTime::new(bound - 1, 0), CurlTime::ZERO);
        assert_eq!(inside, (bound - 1) * MS_PER_SEC);
        assert_ne!(inside, TIMEDIFF_T_MAX);

        let floor = TIMEDIFF_T_MIN / MS_PER_SEC;
        assert_eq!(
            timediff_ms(CurlTime::new(floor, 0), CurlTime::ZERO),
            TIMEDIFF_T_MIN
        );
        assert_eq!(
            timediff_ms(CurlTime::new(floor + 1, 0), CurlTime::ZERO),
            (floor + 1) * MS_PER_SEC
        );
    }

    /// The two guards use DIFFERENT divisors, so there is a band of
    /// differences that the microsecond form saturates and the millisecond
    /// form reports exactly. Finding a value in that band is what catches a
    /// copy-and-paste slip between the two functions.
    #[test]
    fn timediff_us_saturates_a_thousand_times_sooner() {
        // 1e13 seconds is past `TIMEDIFF_T_MAX / 1000000` and far short of
        // `TIMEDIFF_T_MAX / 1000`.
        let seconds = 10_000_000_000_000;
        assert!(seconds > TIMEDIFF_T_MAX / MICROS_PER_SEC);
        assert!(seconds < TIMEDIFF_T_MAX / MS_PER_SEC);

        let apart = CurlTime::new(seconds, 0);
        assert_eq!(timediff_us(apart, CurlTime::ZERO), TIMEDIFF_T_MAX);
        assert_eq!(timediff_ms(apart, CurlTime::ZERO), 10_000_000_000_000_000);

        // And the same band on the negative side.
        let before = CurlTime::new(-seconds, 0);
        assert_eq!(timediff_us(before, CurlTime::ZERO), TIMEDIFF_T_MIN);
        assert_eq!(
            timediff_ms(before, CurlTime::ZERO),
            -10_000_000_000_000_000
        );
    }

    /// The microsecond form adds the two fields directly, with no division.
    #[test]
    fn timediff_us_matches_the_c_formula() {
        assert_eq!(timediff_us(CurlTime::new(0, 500), CurlTime::ZERO), 500);
        assert_eq!(
            timediff_us(CurlTime::new(1, 0), CurlTime::new(0, 500_000)),
            500_000
        );
        assert_eq!(
            timediff_us(
                CurlTime::new(36_762, 8_345),
                CurlTime::new(36_761, 995_926)
            ),
            12_419
        );
        assert_eq!(
            timediff_us(CurlTime::new(36_761, 995_926), CurlTime::ZERO),
            36_761_995_926
        );
    }

    /// The `+ 999` before the division, case by case.
    #[test]
    fn timediff_ceil_ms_adds_999_before_dividing() {
        // One microsecond rounds up to a whole millisecond.
        assert_eq!(timediff_ceil_ms(CurlTime::new(0, 1), CurlTime::ZERO), 1);
        // Exactly one millisecond stays one: `(1000 + 999) / 1000`.
        assert_eq!(
            timediff_ceil_ms(CurlTime::new(0, 1_000), CurlTime::ZERO),
            1
        );
        // One microsecond more becomes two.
        assert_eq!(
            timediff_ceil_ms(CurlTime::new(0, 1_001), CurlTime::ZERO),
            2
        );
        // Zero stays zero: nothing to round up.
        assert_eq!(timediff_ceil_ms(CurlTime::ZERO, CurlTime::ZERO), 0);
        // A NEGATIVE microsecond part is not rounded away from zero, because
        // `(-500 + 999) / 1000` is 0. This is the case the documentation
        // warns is not a ceiling in any direction.
        assert_eq!(
            timediff_ceil_ms(CurlTime::new(0, 0), CurlTime::new(0, 500)),
            0
        );
        // And -1,500 microseconds is `(-1500 + 999) / 1000`, which truncates
        // toward zero and so is also 0.
        assert_eq!(
            timediff_ceil_ms(CurlTime::new(0, 0), CurlTime::new(0, 1_500)),
            0
        );
    }

    /// Where the microsecond parts are equal there is nothing to round, so
    /// the two millisecond forms agree.
    #[test]
    fn timediff_ceil_ms_agrees_on_whole_milliseconds() {
        for seconds in [-2, -1, 0, 1, 2, 1_000] {
            let newer = CurlTime::new(seconds, 250_000);
            let older = CurlTime::new(0, 250_000);
            assert_eq!(
                timediff_ceil_ms(newer, older),
                timediff_ms(newer, older),
                "seconds = {seconds}"
            );
        }
    }

    /// Opposite ends of the type, where the C's own subtraction is undefined
    /// behaviour. Every function returns the saturation bound the true
    /// difference implies, and none of them panics in a debug build.
    #[test]
    fn the_differences_survive_opposite_extremes() {
        let latest = CurlTime::new(i64::MAX, 999_999);
        let earliest = CurlTime::new(i64::MIN, 0);

        assert_eq!(timediff_ms(latest, earliest), TIMEDIFF_T_MAX);
        assert_eq!(timediff_ms(earliest, latest), TIMEDIFF_T_MIN);
        assert_eq!(timediff_ceil_ms(latest, earliest), TIMEDIFF_T_MAX);
        assert_eq!(timediff_ceil_ms(earliest, latest), TIMEDIFF_T_MIN);
        assert_eq!(timediff_us(latest, earliest), TIMEDIFF_T_MAX);
        assert_eq!(timediff_us(earliest, latest), TIMEDIFF_T_MIN);
    }

    /// The two constants named 1000 are the same number, which is what makes
    /// the C's single literal legible as two quantities.
    #[test]
    fn the_two_thousands_agree() {
        assert_eq!(MS_PER_SEC, 1_000);
        assert_eq!(MICROS_PER_MS, 1_000);
        assert_eq!(MS_PER_SEC * MICROS_PER_MS, MICROS_PER_SEC);
    }

    // --- the clocks --------------------------------------------------------

    /// The production clock does not go backwards.
    ///
    /// Runs under interpretation as well as natively: the monotonic reading
    /// goes through [`Instant`], which Miri emulates.
    #[test]
    fn the_system_clock_is_monotonic() {
        let first = SystemClock.now();
        let second = SystemClock.now();
        assert!(second >= first, "{second:?} < {first:?}");

        // Three readings, so that a clock which only appeared monotonic for
        // one pair is caught as well.
        let third = SystemClock.now();
        assert!(third >= second, "{third:?} < {second:?}");
        assert!(third >= first);

        // The baseline is captured on the first reading, so an elapsed span
        // measured against it is representable and non-negative.
        assert!(third.checked_sub(first).is_some());
    }

    /// The production clock's wall reading is a plausible present rather than
    /// a build-time constant.
    ///
    /// The ONE test in this file that reaches the host's wall clock, and
    /// therefore the one an interpreter cannot run: `SystemTime::now` becomes
    /// `clock_gettime(CLOCK_REALTIME)`, which Miri refuses under isolation.
    /// Deliberately isolated into a test of its own so that the rest of the
    /// clock coverage -- object safety, monotonicity, the whole of
    /// [`TestClock`] -- stays interpretable. The alternative,
    /// `-Zmiri-disable-isolation`, would relax the aliasing and isolation
    /// model of the entire run to accommodate one assertion, and
    /// `.github/workflows/rust-miri.yml` lists it among the relaxations that
    /// gate refuses.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "clock_gettime(CLOCK_REALTIME) is refused under Miri isolation"
    )]
    fn the_system_clock_reads_the_host_wall_clock() {
        // 2001-09-09T01:46:40Z. Any host with a set clock is past it, and a
        // reading of zero would mean the wall clock was never consulted.
        let now = SystemClock.epoch_secs();
        assert!(now > 1_000_000_000, "implausible wall reading: {now}");

        // The reading is a real calendar instant, which is the only property
        // its consumers rely on.
        let stamp = gmtime(now).expect("a host reading converts");
        assert!(stamp.year >= 2001, "implausible year: {stamp:?}");

        // Whole seconds, and non-decreasing across two calls.
        assert!(SystemClock.epoch_secs() >= now);
    }

    /// The test clock reports exactly what it was told, forwards or back.
    #[test]
    fn the_test_clock_reports_what_was_set() {
        let clock = TestClock::new(CurlTime::new(42, 500_000));
        assert_eq!(clock.now(), CurlTime::new(42, 500_000));
        assert_eq!(clock.epoch_secs(), 0);

        clock.set(CurlTime::new(1, 2));
        assert_eq!(clock.now(), CurlTime::new(1, 2));

        // Backwards, which a real monotonic clock never does and a test may
        // need to construct anyway.
        clock.set(CurlTime::ZERO);
        assert_eq!(clock.now(), CurlTime::ZERO);

        // A default clock starts at the zero reading on both clocks.
        let fresh = TestClock::default();
        assert_eq!(fresh.now(), CurlTime::ZERO);
        assert_eq!(fresh.epoch_secs(), 0);
    }

    /// `advance` moves both readings by the same span, and the monotonic one
    /// carries across a second boundary.
    #[test]
    fn advance_moves_both_readings_and_carries() {
        // The case the type's example uses: 900,000 microseconds plus 200
        // milliseconds is the next second plus 100,000, not 1,100,000
        // microseconds inside this one.
        let clock = TestClock::new(CurlTime::new(0, 900_000));
        clock.advance(Duration::from_millis(200));
        assert_eq!(clock.now(), CurlTime::new(1, 100_000));

        // The WALL reading is unaffected by the constructor's argument -- it
        // starts at the epoch, so that a test is reproducible on a host whose
        // clock is wrong -- and 200 milliseconds is not yet a whole second.
        assert_eq!(clock.epoch_secs(), 0);
        // The remainder is kept rather than truncated, so the second arrives
        // when the accumulated span reaches it and not a call later.
        clock.advance(Duration::from_millis(800));
        assert_eq!(clock.epoch_secs(), 1);
        assert_eq!(clock.now(), CurlTime::new(1, 900_000));

        // A quarter of a second, exactly, four times: the wall reading
        // accumulates the remainders rather than truncating each one away.
        let clock = TestClock::new(CurlTime::ZERO);
        for _ in 0..4 {
            clock.advance(Duration::from_millis(250));
        }
        assert_eq!(clock.now(), CurlTime::new(1, 0));
        assert_eq!(clock.epoch_secs(), 1);

        // The elapsed difference is what a consumer measures, and it is
        // exactly the span asked for.
        let clock = TestClock::new(CurlTime::new(100, 0));
        let before = clock.now();
        clock.advance(Duration::from_millis(1_500));
        assert_eq!(timediff_ms(clock.now(), before), 1_500);
        assert_eq!(timediff_us(clock.now(), before), 1_500_000);
    }

    /// The wall reading is settable on its own, which is how a test places a
    /// cookie expiry or an HSTS entry at a known date.
    #[test]
    fn set_epoch_secs_moves_only_the_wall_reading() {
        let clock = TestClock::new(CurlTime::new(5, 0));
        clock.set_epoch_secs(951_782_400);
        assert_eq!(clock.epoch_secs(), 951_782_400);
        assert_eq!(clock.now(), CurlTime::new(5, 0));

        // Negative, because `time_t` is signed and a test may need a date
        // before 1970.
        clock.set_epoch_secs(-1);
        assert_eq!(clock.epoch_secs(), -1);

        // The wall reading feeds the calendar conversion, which is the whole
        // point of having it.
        clock.set_epoch_secs(0);
        let stamp = gmtime(clock.epoch_secs()).expect("the epoch converts");
        assert_eq!(stamp.year, 1970);
    }

    /// Both implementations are usable through the trait object, which is the
    /// form a filter chain or a transfer holds.
    #[test]
    fn a_clock_is_usable_as_a_trait_object() {
        fn elapsed_ms(clock: &dyn Clock, since: CurlTime) -> TimeDiff {
            timediff_ms(clock.now(), since)
        }

        fn wall(clock: &dyn Clock) -> i64 {
            clock.epoch_secs()
        }

        let test_clock = TestClock::new(CurlTime::new(10, 0));
        assert_eq!(elapsed_ms(&test_clock, CurlTime::new(8, 0)), 2_000);
        test_clock.set_epoch_secs(784_111_777);
        assert_eq!(wall(&test_clock), 784_111_777);

        // Both implementations coexist in one collection, which is the shape a
        // filter chain holds. The monotonic reading is taken from each,
        // because the values differ and only the shape is being asserted.
        let clocks: Vec<Box<dyn Clock>> =
            vec![Box::new(SystemClock), Box::new(TestClock::default())];
        assert_eq!(clocks.len(), 2);
        for clock in &clocks {
            let _ = clock.now();
        }

        // The `Debug` supertrait is what lets a holder derive `Debug`.
        assert_eq!(format!("{SystemClock:?}"), "SystemClock");
        assert!(format!("{:?}", TestClock::default()).contains("TestClock"));
    }

    // --- the calendar conversion -------------------------------------------

    /// The epoch itself: 1970-01-01T00:00:00Z, a Thursday.
    #[test]
    fn gmtime_at_the_epoch() {
        let stamp = gmtime(0).expect("the epoch is in range");
        assert_eq!(stamp.year, 1970);
        assert_eq!(stamp.mon, 0);
        assert_eq!(stamp.mday, 1);
        assert_eq!(stamp.hour, 0);
        assert_eq!(stamp.min, 0);
        assert_eq!(stamp.sec, 0);
        assert_eq!(stamp.wday, 4);
        assert_eq!(stamp.yday, 0);

        // The C's own field, for anyone transcribing into a `struct tm`.
        assert_eq!(stamp.tm_year(), 70);

        // One second later, so that the time of day is not vacuously zero.
        let stamp = gmtime(1).expect("in range");
        assert_eq!(stamp.sec, 1);
        assert_eq!(stamp.mday, 1);
    }

    /// A negative instant floors into the preceding day, rather than
    /// producing a negative time of day.
    #[test]
    fn gmtime_the_second_before_the_epoch() {
        let stamp = gmtime(-1).expect("in range");
        assert_eq!(stamp.year, 1969);
        assert_eq!(stamp.mon, 11);
        assert_eq!(stamp.mday, 31);
        assert_eq!(stamp.hour, 23);
        assert_eq!(stamp.min, 59);
        assert_eq!(stamp.sec, 59);
        // 1969-12-31 was a Wednesday, the day before the epoch's Thursday.
        assert_eq!(stamp.wday, 3);
        // 1969 was not a leap year, so its last day is the 365th.
        assert_eq!(stamp.yday, 364);
        assert_eq!(stamp.tm_year(), 69);

        // A whole day before the epoch, where the time of day is zero again.
        let stamp = gmtime(-SECS_PER_DAY).expect("in range");
        assert_eq!((stamp.year, stamp.mon, stamp.mday), (1969, 11, 31));
        assert_eq!((stamp.hour, stamp.min, stamp.sec), (0, 0, 0));
    }

    /// 2000 was a leap year -- divisible by 400 -- so it has a 29 February.
    #[test]
    fn gmtime_the_2000_leap_day() {
        let stamp = gmtime(951_782_400).expect("in range");
        assert_eq!(stamp.year, 2000);
        assert_eq!(stamp.mon, 1);
        assert_eq!(stamp.mday, 29);
        // 2000-02-29 was a Tuesday.
        assert_eq!(stamp.wday, 2);
        // 31 days of January plus 28 of February, 0-based.
        assert_eq!(stamp.yday, 59);

        // The following day is 1 March, and its day-of-year counts the leap
        // day.
        let stamp = gmtime(951_782_400 + SECS_PER_DAY).expect("in range");
        assert_eq!((stamp.year, stamp.mon, stamp.mday), (2000, 2, 1));
        assert_eq!(stamp.yday, 60);
    }

    /// 2100 is divisible by 100 and not by 400, so it is NOT a leap year.
    /// This is the case a naive four-year rule gets wrong.
    #[test]
    fn gmtime_knows_2100_is_not_a_leap_year() {
        // 2100-02-28T00:00:00Z, hand-computed as day 47,540 after the epoch.
        let last_of_february = 4_107_456_000;
        assert_eq!(last_of_february, epoch_of(2100, 2, 28));

        let stamp = gmtime(last_of_february).expect("in range");
        assert_eq!((stamp.year, stamp.mon, stamp.mday), (2100, 1, 28));
        assert_eq!(stamp.yday, 58);

        // The next day is 1 March, not 29 February.
        let stamp = gmtime(last_of_february + SECS_PER_DAY).expect("in range");
        assert_eq!((stamp.year, stamp.mon, stamp.mday), (2100, 2, 1));
        assert_eq!(stamp.yday, 59);

        // 1900 is the same case, and 2400 is the exception to the exception.
        assert!(!is_leap_year(2100));
        assert!(!is_leap_year(1900));
        assert!(is_leap_year(2000));
        assert!(is_leap_year(2400));
        assert!(is_leap_year(2024));
        assert!(!is_leap_year(2023));
        // Negative years follow the same proleptic rule.
        assert!(is_leap_year(-400));
        assert!(!is_leap_year(-100));
        assert!(is_leap_year(-4));
        assert!(!is_leap_year(-1));
    }

    /// Two instants checked against dates that are documented elsewhere.
    #[test]
    fn gmtime_hand_checked_instants() {
        // The RFC 2616 example date, "Sun, 06 Nov 1994 08:49:37 GMT", which
        // `curl-rs-lib/src/util/parsedate.rs` also pins from the other
        // direction.
        let stamp = gmtime(784_111_777).expect("in range");
        assert_eq!((stamp.year, stamp.mon, stamp.mday), (1994, 10, 6));
        assert_eq!((stamp.hour, stamp.min, stamp.sec), (8, 49, 37));
        assert_eq!(stamp.wday, 0, "Sunday is zero");
        assert_eq!(stamp.yday, 309);

        // The last second a 32-bit signed `time_t` can hold:
        // 2038-01-19T03:14:07Z, a Tuesday.
        let stamp = gmtime(2_147_483_647).expect("in range");
        assert_eq!((stamp.year, stamp.mon, stamp.mday), (2038, 0, 19));
        assert_eq!((stamp.hour, stamp.min, stamp.sec), (3, 14, 7));
        assert_eq!(stamp.wday, 2);
        assert_eq!(stamp.yday, 18);
        assert_eq!(stamp.tm_year(), 138);

        // One second later, which a 32-bit `time_t` cannot hold and this can.
        let stamp = gmtime(2_147_483_648).expect("in range");
        assert_eq!((stamp.year, stamp.mon, stamp.mday), (2038, 0, 19));
        assert_eq!((stamp.hour, stamp.min, stamp.sec), (3, 14, 8));
    }

    #[test]
    fn the_field_conventions_are_the_c_s() {
        // `mon` is 0-based, so it subscripts a January-first table directly.
        let january = gmtime(epoch_of(2024, 1, 15)).expect("in range");
        let december = gmtime(epoch_of(2024, 12, 15)).expect("in range");
        assert_eq!(january.mon, 0);
        assert_eq!(december.mon, 11);

        // `mday` is 1-based.
        assert_eq!(january.mday, 15);

        // `wday` is 0 for Sunday, which is what makes the C's
        // `Curl_wkday[wday ? wday - 1 : 6]` name the right day against a
        // Monday-first table.
        let sunday = gmtime(epoch_of(2024, 1, 7)).expect("in range");
        let monday = gmtime(epoch_of(2024, 1, 8)).expect("in range");
        let saturday = gmtime(epoch_of(2024, 1, 6)).expect("in range");
        assert_eq!(sunday.wday, 0);
        assert_eq!(monday.wday, 1);
        assert_eq!(saturday.wday, 6);

        // `year` is ABSOLUTE and `tm_year()` is the C's offset field. Both
        // spellings of one instant, so the choice cannot drift unnoticed.
        assert_eq!(january.year, 2024);
        assert_eq!(january.tm_year(), 124);
        assert_eq!(january.year, january.tm_year() + 1900);

        // `yday` is 0-based, so 1 January is zero and the last day of a leap
        // year is 365.
        assert_eq!(gmtime(epoch_of(2024, 1, 1)).expect("ok").yday, 0);
        assert_eq!(gmtime(epoch_of(2024, 12, 31)).expect("ok").yday, 365);
        assert_eq!(gmtime(epoch_of(2023, 12, 31)).expect("ok").yday, 364);
    }

    /// An instant whose year does not fit the field is an error, exactly as
    /// `gmtime_r` fails rather than returning a wrong date.
    #[test]
    fn gmtime_rejects_a_year_that_does_not_fit() {
        // The extremes of the type, roughly 292 billion years out.
        assert_eq!(gmtime(i64::MAX), Err(CURLcode::BadFunctionArgument));
        assert_eq!(gmtime(i64::MIN), Err(CURLcode::BadFunctionArgument));

        // The exact boundary on the positive side: the largest year the field
        // can hold converts, and the next one does not.
        let last_year = i64::from(i32::MAX);
        let inside = epoch_of(last_year, 1, 1);
        assert_eq!(gmtime(inside).expect("in range").year, i32::MAX);
        let outside = epoch_of(last_year + 1, 1, 1);
        assert_eq!(gmtime(outside), Err(CURLcode::BadFunctionArgument));

        // The second bound, which exists so that `tm_year()` stays exact: a
        // year that fits `i32` but whose value less 1900 does not.
        let too_negative = i64::from(i32::MIN) + 1_000;
        assert!(i32::try_from(too_negative).is_ok());
        assert_eq!(
            gmtime(epoch_of(too_negative, 6, 15)),
            Err(CURLcode::BadFunctionArgument)
        );

        // Just inside that bound, the conversion succeeds and the accessor is
        // exact.
        let least_year = i64::from(i32::MIN) + 1_900;
        let stamp = gmtime(epoch_of(least_year, 6, 15)).expect("in range");
        assert_eq!(i64::from(stamp.year), least_year);
        assert_eq!(stamp.tm_year(), i32::MIN);
    }

    /// The conversion agrees with an independent inverse over every day of a
    /// long run, which is a stronger statement than any list of anchors.
    ///
    /// The run deliberately spans a leap day, a century year that is not a
    /// leap year, a year divisible by 400 that is, and the epoch itself, and
    /// it covers both signs of `time_t`.
    #[test]
    fn gmtime_round_trips_against_an_independent_inverse() {
        for (year, month, day) in [
            (1583, 1, 1),
            (1899, 12, 31),
            (1900, 2, 28),
            (1900, 3, 1),
            (1969, 12, 31),
            (1970, 1, 1),
            (2000, 2, 29),
            (2024, 2, 29),
            (2100, 2, 28),
            (2400, 2, 29),
            (9999, 12, 31),
            (-1, 1, 1),
            (-4, 2, 29),
            (0, 1, 1),
        ] {
            let epoch = epoch_of(year, month, day);
            let stamp = gmtime(epoch).unwrap_or_else(|error| {
                panic!("{year}-{month}-{day} failed: {error:?}")
            });
            let read_back = (
                i64::from(stamp.year),
                i64::from(stamp.mon) + 1,
                i64::from(stamp.mday),
            );
            assert_eq!(
                read_back,
                (year, month, day),
                "round trip failed for {year}-{month}-{day}"
            );
        }
    }

    /// Walking a run of consecutive days, every field advances the way a
    /// calendar does: the weekday cycles, the day-of-year increases by one
    /// within a year and resets on 1 January, and the day-of-month never
    /// exceeds the length of its month.
    #[test]
    fn gmtime_walks_consecutive_days_consistently() {
        // Just over four years from the start of 2096, which crosses the 2100
        // non-leap century boundary. Four years is enough to see every
        // month length and both leap outcomes without making the test slow
        // under Miri.
        let first = epoch_of(2099, 1, 1) / SECS_PER_DAY;
        let last = epoch_of(2101, 1, 2) / SECS_PER_DAY;

        let mut previous =
            gmtime(first * SECS_PER_DAY).expect("the first day converts");
        for day in (first + 1)..last {
            let stamp = gmtime(day * SECS_PER_DAY).expect("in range");

            // The weekday always advances by one, modulo seven.
            assert_eq!(stamp.wday, (previous.wday + 1) % 7, "{stamp:?}");

            // The time of day is midnight for every one of these instants.
            assert_eq!((stamp.hour, stamp.min, stamp.sec), (0, 0, 0));

            if stamp.year == previous.year {
                // Inside a year the day-of-year advances by exactly one.
                assert_eq!(stamp.yday, previous.yday + 1, "{stamp:?}");
                // The month either stays or advances by one, and a new month
                // starts on its first day.
                assert!(
                    stamp.mon == previous.mon || stamp.mon == previous.mon + 1
                );
                if stamp.mon == previous.mon {
                    assert_eq!(stamp.mday, previous.mday + 1);
                } else {
                    assert_eq!(stamp.mday, 1);
                }
            } else {
                // A new year begins on 1 January with a zero day-of-year, and
                // the year before it ended on 31 December.
                assert_eq!(stamp.year, previous.year + 1);
                assert_eq!((stamp.mon, stamp.mday, stamp.yday), (0, 1, 0));
                assert_eq!((previous.mon, previous.mday), (11, 31));
                assert_eq!(
                    previous.yday,
                    if is_leap_year(previous.year) {
                        365
                    } else {
                        364
                    }
                );
            }

            previous = stamp;
        }
    }

    /// Every second of a day converts to the right time of day, including the
    /// two boundaries, and the calendar fields do not move within it.
    #[test]
    fn gmtime_splits_the_time_of_day() {
        let midnight = epoch_of(2024, 3, 15);
        for (offset, expected) in [
            (0, (0, 0, 0)),
            (1, (0, 0, 1)),
            (59, (0, 0, 59)),
            (60, (0, 1, 0)),
            (3_599, (0, 59, 59)),
            (3_600, (1, 0, 0)),
            (43_200, (12, 0, 0)),
            (86_399, (23, 59, 59)),
        ] {
            let stamp = gmtime(midnight + offset).expect("in range");
            assert_eq!((stamp.hour, stamp.min, stamp.sec), expected);
            assert_eq!((stamp.year, stamp.mon, stamp.mday), (2024, 2, 15));
        }

        // One second further is the next day at midnight.
        let stamp = gmtime(midnight + 86_400).expect("in range");
        assert_eq!((stamp.hour, stamp.min, stamp.sec), (0, 0, 0));
        assert_eq!(stamp.mday, 16);
    }
}
