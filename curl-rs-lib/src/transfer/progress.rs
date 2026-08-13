//**************************************************************************
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
//**************************************************************************/
//! Transfer accounting and timing -- supersedes `lib/progress.c` and
//! `lib/progress.h`.
//!
//! Four consumers read this state, and every one of them is a frozen
//! contract:
//!
//! * `easy/getinfo.rs`, for the `CURLINFO_*_T` values enumerated under
//!   [`Progress::size_download`] and its neighbours -- the mapping is
//!   `lib/getinfo.c:417-462`;
//! * the progress callbacks, `CURLOPT_XFERINFOFUNCTION` and the deprecated
//!   `CURLOPT_PROGRESSFUNCTION`, through [`ProgressSnapshot`];
//! * rate limiting, which each direction owns one [`RateLimit`] for;
//! * `--write-out`, whose `%{time_*}`, `%{size_*}` and `%{speed_*}` variables
//!   are these fields under different names.
//!
//! # What this module is NOT
//!
//! It performs no rendering and writes no byte anywhere. The built-in meter
//! -- `time2str` (`lib/progress.c:39-80`), `max6out` (`:89-121`),
//! `pgrs_est_percent` (`:494-501`), `pgrs_estimates` (`:503-513`) and
//! `progress_meter` (`:515-600`) -- belongs to
//! `curl-rs/src/output/progress.rs` and `curl-rs/src/callbacks/progress.rs`,
//! where its layout is frozen byte for byte. Two consequences follow, and
//! both are deliberate:
//!
//! 1. **No literal of the meter appears here.** No heading, no field width,
//!    no unit suffix, and no `\n`. `Curl_pgrsDone` (`:191-205`) writes a
//!    trailing newline to `data->set.err`; [`Progress::done`] instead reports
//!    [`Done::write_newline`], leaving the write to the adapter that owns the
//!    stream.
//! 2. **Every value the renderer needs is preserved and reachable.**
//!    [`Progress::meter_snapshot`] hands over exactly the eleven fields
//!    `progress_meter` reads, so relocating the presentation layer cannot
//!    change what it prints.
//!
//! # Timing is transcribed, not re-derived
//!
//! For this module that has five concrete consequences, each pinned by a test:
//!
//! 1. **Microseconds are the unit of every accumulator**, because the
//!    `CURLINFO_*_TIME_T` values are microseconds. Nothing here converts to
//!    or from a floating-point second.
//! 2. **The integer boundaries are the C's**, including
//!    [`trspeed`]'s four-way split at `CURL_OFF_T_MAX / 1000000` and the
//!    floating-point branch of [`Progress::calculate`]. Where C would have
//!    undefined behaviour on overflow this module saturates, which agrees
//!    with C on every input a transfer can actually produce and is defined
//!    on the rest.
//! 3. **The speed history stays six records over about five seconds.** No
//!    smoothing is added and no window is widened.
//! 4. **The record counter stays eight bits wide.** `speeder_c` is a
//!    `uint8_t` in C, and its wrap after 256 records is reproduced rather
//!    than repaired -- see [`Progress::calculate`].
//! 5. **The callback return codes keep their exact meanings**, including the
//!    distinction between `CURL_PROGRESSFUNC_CONTINUE`, zero and everything
//!    else.

use crate::error::{CURLcode, Error};
use crate::transfer::ratelimit::RateLimit;
use crate::util::timediff::TimeDiff;
use crate::util::timeval::{timediff_ms, timediff_us, Clock, CurlTime};

/// Slots in the speed history -- `CURL_SPEED_RECORDS` of
/// `lib/urldata.h:820`, spelled `(5 + 1)` there and commented "6 entries for
/// 5 seconds".
#[allow(dead_code)]
pub(crate) const CURL_SPEED_RECORDS: usize = 5 + 1;

/// `CURL_PROGRESSFUNC_CONTINUE` -- `include/curl/curl.h:234`.
///
/// A progress callback returns this to say "I did nothing, carry on with the
/// built-in behaviour". It is deliberately not zero, because zero already
/// means "handled, do not abort"; the three-way distinction is preserved in
/// [`Progress::report`].
#[allow(dead_code)]
pub(crate) const CURL_PROGRESSFUNC_CONTINUE: i32 = 0x1000_0001;

/// The delay `pgrs_speedcheck` asks `EXPIRE_SPEEDCHECK` for, in
/// milliseconds -- `lib/progress.c:166`.
///
/// The C comment says it plainly: "since low speed limit is enabled, set the
/// expire timer to make this connection's speed get checked again in a
/// second".
#[allow(dead_code)]
pub(crate) const SPEEDCHECK_EXPIRE_MS: TimeDiff = 1_000;

/// Microseconds in a second.
///
/// The factor in [`trspeed`] and in the current-speed calculation. It is the
/// C's literal `1000000`, written with separators.
#[allow(dead_code)]
const US_PER_SEC: i64 = 1_000_000;

/// The largest byte count that can be multiplied by [`US_PER_SEC`] without
/// leaving [`i64`] -- the C's `CURL_OFF_T_MAX / 1000000`.
#[allow(dead_code)]
const SPEED_OVERFLOW_LIMIT: i64 = i64::MAX / US_PER_SEC;

/// The interval that must pass before a new speed record is made, in
/// milliseconds -- `lib/progress.c:439`.
///
/// The C comment is the rationale: "Make a new record only when some time has
/// passed. Too frequent calls otherwise ruin the history."
#[allow(dead_code)]
const SPEED_SAMPLE_MS: TimeDiff = 1_000;

/// The floor a timer accumulator contributes -- `lib/progress.c:311-312`,
/// "make sure at least one microsecond passed".
///
/// Without it a sub-microsecond phase would accumulate zero, and a
/// `CURLINFO_*_TIME_T` of zero reads as "this phase never happened" rather
/// than "this phase was fast".
#[allow(dead_code)]
const MIN_ELAPSED_US: TimeDiff = 1;

/// Milliseconds in a second, for the low-speed threshold.
///
/// `lib/progress.c:150` compares against `data->set.low_speed_time * 1000`.
#[allow(dead_code)]
const MS_PER_SEC: TimeDiff = 1_000;

/// The message `pgrs_speedcheck` fails with -- `lib/progress.c:152-154`.
///
/// Held as a formatting shape rather than a finished string because both
/// operands come from the caller's options. The C:
///
/// ```text
/// failf(data, "Operation too slow. Less than %" FMT_OFF_T
///       " bytes/sec transferred the last %u seconds",
///       data->set.low_speed_limit, data->set.low_speed_time);
/// ```
///
/// This text reaches `CURLOPT_ERRORBUFFER`, so it is observable and frozen.
/// [`LowSpeedLimit::too_slow`] is the one place it is produced.
#[allow(dead_code)]
const TOO_SLOW_PREFIX: &str = "Operation too slow. Less than ";

/// The message `pgrsupdate` fails with when a progress callback returns a
/// non-zero value that is not [`CURL_PROGRESSFUNC_CONTINUE`] --
/// `lib/progress.c:624` and `:642`.
///
/// Both call sites use the identical string, so it is written once.
#[allow(dead_code)]
const CALLBACK_ABORTED: &str = "Callback aborted";

/// The labels `Curl_pgrsTimeWas` accepts -- the `timerid` enumeration of
/// `lib/progress.h:30-44`.
///
/// # Two differences from the C, both deliberate
///
/// 1. Nothing converts a `timerid` across a boundary, and no public header
///    names one, so no ordinal meaning has to be preserved and a variant that
///    may never be passed would be a variant every `match` here had to reject.
///    [`Self::VARIANTS`] serves the one real need the sentinel would have met,
///    which is enumerating the labels in a test.
/// 2. **`TIMER_POSTRANSFER` is spelled [`Self::PostTransfer`].** The C
///    identifier is missing a letter (`lib/progress.h:40`) while the field it
///    writes is spelled correctly (`lib/urldata.h:810`,
///    `progress.t_posttransfer`). The corrected spelling is used here because
///    the misspelling crosses no boundary; `CURLINFO_POSTTRANSFER_TIME_T`
///    itself is spelled with both `t`s.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum TimerId {
    /// `TIMER_NONE`. The C calls it a "mistake filter"
    /// (`lib/progress.c:250-252`): it mutates nothing, so a caller that has
    /// not decided which timer it means cannot corrupt one.
    None,
    /// `TIMER_STARTOP`. The start of the whole operation, redirects
    /// included.
    StartOp,
    /// `TIMER_STARTSINGLE`. The start of one request, which the C header
    /// notes "might get queued".
    StartSingle,
    /// `TIMER_POSTQUEUE`. Immediately after leaving the queue. Accumulative
    /// across redirects.
    PostQueue,
    /// `TIMER_NAMELOOKUP`. Name resolution complete.
    NameLookup,
    /// `TIMER_CONNECT`. The transport connection is up.
    Connect,
    /// `TIMER_APPCONNECT`. The TLS handshake is complete.
    AppConnect,
    /// `TIMER_PRETRANSFER`. Everything is ready and the transfer is about to
    /// begin.
    PreTransfer,
    /// `TIMER_STARTTRANSFER`. The first byte of the response body has
    /// arrived. Recorded once per single transfer -- see
    /// [`Progress::time_was`].
    StartTransfer,
    /// `TIMER_POSTRANSFER`, spelled correctly. The transfer is over.
    PostTransfer,
    /// `TIMER_STARTACCEPT`. An active-mode FTP data connection has been
    /// accepted.
    StartAccept,
    /// `TIMER_REDIRECT`. A redirect has been followed. Measured from the
    /// overall start, not from the current request.
    Redirect,
}

impl TimerId {
    /// Every label, in the C's declaration order.
    ///
    /// Exhaustive by construction is not something a slice can promise, so
    /// the test module asserts the length and walks each entry. The order is
    /// the C's so that a reader comparing the two files reads them in the
    /// same sequence.
    #[allow(dead_code)]
    pub(crate) const VARIANTS: [Self; 12] = [
        Self::None,
        Self::StartOp,
        Self::StartSingle,
        Self::PostQueue,
        Self::NameLookup,
        Self::Connect,
        Self::AppConnect,
        Self::PreTransfer,
        Self::StartTransfer,
        Self::PostTransfer,
        Self::StartAccept,
        Self::Redirect,
    ];

    /// The C identifier for this label, spelled exactly as
    /// `lib/progress.h:30-44` spells it -- misspelling included.
    ///
    /// Present so that a diagnostic or a test can name a timer the way the C
    /// tree does without a second table to keep in step.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::None => "TIMER_NONE",
            Self::StartOp => "TIMER_STARTOP",
            Self::StartSingle => "TIMER_STARTSINGLE",
            Self::PostQueue => "TIMER_POSTQUEUE",
            Self::NameLookup => "TIMER_NAMELOOKUP",
            Self::Connect => "TIMER_CONNECT",
            Self::AppConnect => "TIMER_APPCONNECT",
            Self::PreTransfer => "TIMER_PRETRANSFER",
            Self::StartTransfer => "TIMER_STARTTRANSFER",
            // The C really does spell this one with a single R.
            Self::PostTransfer => "TIMER_POSTRANSFER",
            Self::StartAccept => "TIMER_STARTACCEPT",
            Self::Redirect => "TIMER_REDIRECT",
        }
    }
}

/// One entry of the speed history.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
struct SpeedRecord {
    /// `speed_amount[i]`: the combined download and upload byte count at the
    /// moment this record was taken.
    amount: i64,
    /// `speed_time[i]`: when it was taken.
    at: CurlTime,
}

/// One direction of a transfer -- `struct pgrs_dir` of
/// `lib/urldata.h:786-791`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ProgressDirection {
    /// `total_size`: total expected bytes. Meaningful only when the owning
    /// [`Progress`] reports the size as known.
    total_size: i64,
    /// `cur_size`: bytes transferred so far.
    cur_size: i64,
    /// `speed`: the average over the whole transfer so far, in bytes per
    /// second, as [`trspeed`] computes it.
    speed: i64,
    /// `rlimit`: this direction's token bucket, serving
    /// `CURLOPT_MAX_RECV_SPEED_LARGE` or `CURLOPT_MAX_SEND_SPEED_LARGE`.
    rlimit: RateLimit,
}

impl ProgressDirection {
    /// Total expected bytes, as stored.
    ///
    /// A caller deciding what `CURLINFO_CONTENT_LENGTH_*_T` should report
    /// wants [`Progress::content_length_download`] instead, which applies the
    /// "known" flag; this accessor is the raw field.
    #[allow(dead_code)]
    pub(crate) const fn total_size(&self) -> i64 {
        self.total_size
    }

    /// Bytes transferred so far -- `CURLINFO_SIZE_DOWNLOAD_T` and
    /// `CURLINFO_SIZE_UPLOAD_T`.
    #[allow(dead_code)]
    pub(crate) const fn cur_size(&self) -> i64 {
        self.cur_size
    }

    /// The average speed in bytes per second --
    /// `CURLINFO_SPEED_DOWNLOAD_T` and `CURLINFO_SPEED_UPLOAD_T`.
    #[allow(dead_code)]
    pub(crate) const fn speed(&self) -> i64 {
        self.speed
    }

    /// This direction's rate limiter, for the transfer loop that arms the
    /// pacing timer.
    #[allow(dead_code)]
    pub(crate) const fn rlimit(&self) -> &RateLimit {
        &self.rlimit
    }

    /// This direction's rate limiter, mutably.
    ///
    /// Needed because three of [`RateLimit`]'s query methods mutate -- they
    /// bring the bucket up to date before answering -- and because
    /// `lib/setopt.c:2793-2813` re-initialises a live limiter when the
    /// corresponding option is set.
    #[allow(dead_code)]
    pub(crate) fn rlimit_mut(&mut self) -> &mut RateLimit {
        &mut self.rlimit
    }
}

/// The two options that arm the low-speed abort -- `data->set` members
/// `low_speed_limit` (`lib/urldata.h:1336`) and `low_speed_time`
/// (`lib/urldata.h:1452`).
///
/// # The widths are the C's
///
/// `limit_bps` is a `curl_off_t`, so [`i64`]. `time_secs` is a `uint16_t`,
/// and `lib/setopt.c:870-874` clamps `CURLOPT_LOW_SPEED_TIME` to
/// `0..=USHRT_MAX` before narrowing to it, so [`u16`] is the exact domain and
/// not a guess. The product `time_secs * 1000` therefore reaches at most
/// 65,535,000 and cannot overflow the [`TimeDiff`] it is compared against.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) struct LowSpeedLimit {
    /// `CURLOPT_LOW_SPEED_LIMIT`, in bytes per second. Zero disables the
    /// check.
    pub(crate) limit_bps: i64,
    /// `CURLOPT_LOW_SPEED_TIME`, in seconds. Zero disables the check.
    pub(crate) time_secs: u16,
}

impl LowSpeedLimit {
    /// A limit of `limit_bps` bytes per second sustained over `time_secs`.
    #[allow(dead_code)]
    pub(crate) const fn new(limit_bps: i64, time_secs: u16) -> Self {
        Self {
            limit_bps,
            time_secs,
        }
    }

    /// Whether the low-speed abort is armed at all.
    ///
    /// `lib/progress.c:135`: `if(!data->set.low_speed_time ||
    /// !data->set.low_speed_limit)`. Either being zero disables the check, so
    /// this is the negation of that guard.
    #[allow(dead_code)]
    pub(crate) const fn is_armed(self) -> bool {
        self.time_secs != 0 && self.limit_bps != 0
    }

    /// How long a transfer may stay under the limit, in milliseconds.
    ///
    /// `lib/progress.c:150`: `howlong >= data->set.low_speed_time * 1000`.
    #[allow(dead_code)]
    const fn window_ms(self) -> TimeDiff {
        // `u16` widens losslessly and the product is bounded by 65,535,000,
        // so neither conversion nor multiplication can overflow.
        (self.time_secs as TimeDiff) * MS_PER_SEC
    }

    /// The exact text `failf` writes when the window expires --
    /// `lib/progress.c:152-154`.
    #[allow(dead_code)]
    fn too_slow(self) -> Error {
        Error::with_context(
            CURLcode::OperationTimedout,
            format!(
                "{TOO_SLOW_PREFIX}{} bytes/sec transferred the last {} seconds",
                self.limit_bps, self.time_secs
            ),
        )
    }
}

/// Whether either direction of the transfer is paused -- the results of
/// `Curl_xfer_recv_is_paused` and `Curl_xfer_send_is_paused` at
/// `lib/progress.c:136`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) struct Paused {
    /// `Curl_xfer_recv_is_paused(data)`.
    pub(crate) recv: bool,
    /// `Curl_xfer_send_is_paused(data)`.
    pub(crate) send: bool,
}

impl Paused {
    /// Neither direction paused -- the ordinary case.
    #[allow(dead_code)]
    pub(crate) const NEITHER: Self = Self {
        recv: false,
        send: false,
    };

    /// Whether either direction is paused.
    #[allow(dead_code)]
    pub(crate) const fn either(self) -> bool {
        self.recv || self.send
    }
}

/// The four byte counts a progress callback receives.
///
/// One value serves both callbacks, because `lib/progress.c:616-620` and
/// `:634-638` pass the same four fields in the same order and differ only in
/// the parameter type. The modern `CURLOPT_XFERINFOFUNCTION` takes them as
/// `curl_off_t`, which is what the fields already are; the deprecated
/// `CURLOPT_PROGRESSFUNCTION` takes them as `double`, which the four
/// `*_f64` accessors below produce.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ProgressSnapshot {
    /// `dltotal`: total expected download bytes, as stored -- the C passes
    /// `data->progress.dl.total_size` WITHOUT consulting `dl_size_known`, so
    /// an unknown size reaches the callback as 0 rather than as -1.
    pub(crate) dl_total: i64,
    /// `dlnow`: download bytes so far.
    pub(crate) dl_now: i64,
    /// `ultotal`: total expected upload bytes, with the same caveat as
    /// [`Self::dl_total`].
    pub(crate) ul_total: i64,
    /// `ulnow`: upload bytes so far.
    pub(crate) ul_now: i64,
}

impl ProgressSnapshot {
    /// [`Self::dl_total`] as the `double` the legacy callback expects.
    ///
    /// The C cast is `(double)data->progress.dl.total_size`
    /// (`lib/progress.c:635`). It loses precision above 2^53 bytes -- eight
    /// petabytes -- exactly as the C cast does, which is why
    /// `CURLOPT_XFERINFOFUNCTION` exists and why this one is deprecated.
    #[allow(dead_code)]
    pub(crate) fn dl_total_f64(self) -> f64 {
        self.dl_total as f64
    }

    /// [`Self::dl_now`] as a `double` -- `lib/progress.c:636`.
    #[allow(dead_code)]
    pub(crate) fn dl_now_f64(self) -> f64 {
        self.dl_now as f64
    }

    /// [`Self::ul_total`] as a `double` -- `lib/progress.c:637`.
    #[allow(dead_code)]
    pub(crate) fn ul_total_f64(self) -> f64 {
        self.ul_total as f64
    }

    /// [`Self::ul_now`] as a `double` -- `lib/progress.c:638`.
    #[allow(dead_code)]
    pub(crate) fn ul_now_f64(self) -> f64 {
        self.ul_now as f64
    }
}

/// Everything the built-in meter reads, handed over in one value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct MeterSnapshot {
    /// `p->timespent`, in microseconds.
    pub(crate) timespent: TimeDiff,
    /// `p->dl.total_size`.
    pub(crate) dl_total: i64,
    /// `p->dl.cur_size`.
    pub(crate) dl_cur: i64,
    /// `p->dl.speed`.
    pub(crate) dl_speed: i64,
    /// `p->dl_size_known`.
    pub(crate) dl_size_known: bool,
    /// `p->ul.total_size`.
    pub(crate) ul_total: i64,
    /// `p->ul.cur_size`.
    pub(crate) ul_cur: i64,
    /// `p->ul.speed`.
    pub(crate) ul_speed: i64,
    /// `p->ul_size_known`.
    pub(crate) ul_size_known: bool,
    /// `p->current_speed`.
    pub(crate) current_speed: i64,
    /// `p->headers_out`, so the renderer knows whether it still owes the
    /// two-line heading.
    pub(crate) headers_out: bool,
}

/// Which of the two progress callbacks a handle has installed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum CallbackFlavour {
    /// `CURLOPT_XFERINFOFUNCTION`, taking `curl_off_t` counts.
    XferInfo,
    /// `CURLOPT_PROGRESSFUNCTION`, deprecated, taking `double` counts.
    Progress,
}

/// The progress-callback surface, injected.
#[allow(dead_code)]
pub(crate) trait ProgressCallback {
    /// Which callback is installed, or [`None`] when neither is.
    ///
    /// [`None`] skips the callback path entirely, which is the C's
    /// fall-through when both pointers are null.
    fn flavour(&self) -> Option<CallbackFlavour>;

    /// Sets or clears the handle's `in_callback` flag --
    /// `Curl_set_in_callback(data, TRUE)` and `(data, FALSE)`.
    fn set_in_callback(&mut self, active: bool);

    /// Invokes `CURLOPT_XFERINFOFUNCTION` and returns its `int`.
    ///
    /// Called only when [`Self::flavour`] reported
    /// [`CallbackFlavour::XferInfo`].
    fn xferinfo(&mut self, snapshot: &ProgressSnapshot) -> i32;

    /// Invokes `CURLOPT_PROGRESSFUNCTION` and returns its `int`.
    ///
    /// Called only when [`Self::flavour`] reported
    /// [`CallbackFlavour::Progress`]. The implementor converts through the
    /// snapshot's `*_f64` accessors, which is where the C's four `(double)`
    /// casts live.
    fn progress(&mut self, snapshot: &ProgressSnapshot) -> i32;
}

/// A handle with no progress callback installed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct NoProgressCallback;

impl ProgressCallback for NoProgressCallback {
    fn flavour(&self) -> Option<CallbackFlavour> {
        None
    }

    fn set_in_callback(&mut self, _active: bool) {}

    fn xferinfo(&mut self, _snapshot: &ProgressSnapshot) -> i32 {
        CURL_PROGRESSFUNC_CONTINUE
    }

    fn progress(&mut self, _snapshot: &ProgressSnapshot) -> i32 {
        CURL_PROGRESSFUNC_CONTINUE
    }
}

/// Brackets one callback invocation with the handle's `in_callback` flag.
///
/// # Why a guard rather than two calls
///
/// Two bare calls around the invocation are correct only while nothing
/// between them diverges. A callback is arbitrary code -- in the shipped
/// artifact it is a C function pointer reached through the ABI shim, and in a
/// test it is a closure -- and an unwind between the two calls would leave
/// the handle permanently marked as being inside a callback, which
/// `curl_easy_*` would then reject on every subsequent call. [`Drop`] clears
/// the flag on the normal path and on the unwinding path alike.
#[allow(dead_code)]
struct CallbackGuard<'host, C: ProgressCallback + ?Sized> {
    /// The handle whose flag is set, borrowed for the guard's lifetime so
    /// that the callback is reached THROUGH the guard and cannot be invoked
    /// outside the bracket.
    host: &'host mut C,
}

impl<'host, C: ProgressCallback + ?Sized> CallbackGuard<'host, C> {
    /// Marks `host` as being inside a callback.
    #[allow(dead_code)]
    fn enter(host: &'host mut C) -> Self {
        host.set_in_callback(true);
        Self { host }
    }

    /// Invokes the installed callback and returns its `int`.
    #[allow(dead_code)]
    fn call(&mut self, flavour: CallbackFlavour, at: &ProgressSnapshot) -> i32 {
        match flavour {
            CallbackFlavour::XferInfo => self.host.xferinfo(at),
            CallbackFlavour::Progress => self.host.progress(at),
        }
    }
}

impl<C: ProgressCallback + ?Sized> Drop for CallbackGuard<'_, C> {
    fn drop(&mut self) {
        self.host.set_in_callback(false);
    }
}

/// Whether the caller should draw the built-in meter now.
///
/// The C draws it inside `pgrsupdate` (`lib/progress.c:649-650`), guarded by
/// three conditions at once: the progress must not be hidden, the throttle in
/// `progress_calc` must have said it is time, and any installed callback must
/// have returned [`CURL_PROGRESSFUNC_CONTINUE`] rather than taking the update
/// over. All three are evaluated here, so a caller that draws on
/// [`Self::Draw`] and only then draws exactly when the C does.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)]
pub(crate) enum Meter {
    /// Draw it.
    Draw,
    /// Do not: hidden, throttled, or a callback handled this update.
    Skip,
}

impl Meter {
    /// Whether this is [`Self::Draw`].
    #[allow(dead_code)]
    pub(crate) const fn should_draw(self) -> bool {
        matches!(self, Self::Draw)
    }
}

/// What the low-speed check asks of its caller.
///
/// The C ends `pgrs_speedcheck` with `Curl_expire(data, 1000,
/// EXPIRE_SPEEDCHECK)` (`lib/progress.c:166`) on every path that does not
/// fail. That call is the caller's to make here, because arming a timer needs
/// the multi handle's expiry tree and this module holds no handle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)]
pub(crate) enum SpeedCheck {
    /// Nothing to arm. Either the check is not armed at all, or the transfer
    /// is paused, or the request has already finished -- the C skips the call
    /// entirely in the last case (`lib/progress.c:673`).
    Skipped,
    /// The transfer is keeping up. Arm `EXPIRE_SPEEDCHECK` in `in_ms`
    /// milliseconds so that the speed is checked again.
    Expire {
        /// Always [`SPEEDCHECK_EXPIRE_MS`]. Carried as a field rather than
        /// left implicit so that the caller passes a value it was given
        /// instead of one it remembered.
        in_ms: TimeDiff,
    },
}

impl SpeedCheck {
    /// The delay to arm `EXPIRE_SPEEDCHECK` for, or [`None`].
    #[allow(dead_code)]
    pub(crate) const fn arm_ms(self) -> Option<TimeDiff> {
        match self {
            Self::Skipped => None,
            Self::Expire { in_ms } => Some(in_ms),
        }
    }
}

/// The outcome of [`Progress::check`] -- `Curl_pgrsCheck`
/// (`lib/progress.c:668-676`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)]
pub(crate) struct Check {
    /// Whether to draw the built-in meter.
    pub(crate) meter: Meter,
    /// Whether to arm `EXPIRE_SPEEDCHECK`.
    pub(crate) speedcheck: SpeedCheck,
}

/// The outcome of [`Progress::done`] -- `Curl_pgrsDone`
/// (`lib/progress.c:191-205`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
#[allow(dead_code)]
pub(crate) struct Done {
    /// Whether to draw the built-in meter one last time.
    pub(crate) meter: Meter,
    /// Whether the built-in meter still owes a trailing newline.
    pub(crate) write_newline: bool,
}

/// The average speed of `size` bytes over `us` microseconds, in bytes per
/// second -- `trspeed` of `lib/progress.c:396-407`.
///
/// The C, transcribed:
///
/// ```text
/// if(us < 1)                            return size * 1000000;
/// else if(size < CURL_OFF_T_MAX / 1000000) return (size * 1000000) / us;
/// else if(us >= 1000000)                return size / (us / 1000000);
/// else                                  return CURL_OFF_T_MAX;
/// ```
///
/// # The two places this saturates and C does not
///
/// Both are undefined behaviour in C and cannot be reproduced literally:
///
/// * `size * 1000000` in the first branch, for a `size` whose magnitude
///   exceeds [`SPEED_OVERFLOW_LIMIT`]. Reachable only with a negative or
///   absurd byte count, and [`i64::saturating_mul`] yields the bound the true
///   value implies.
/// * `size * 1000000` in the second branch for a NEGATIVE size below
///   `-SPEED_OVERFLOW_LIMIT`. The branch condition is `size <
///   SPEED_OVERFLOW_LIMIT`, which every negative size satisfies, so the C's
///   guard protects only the positive side.
#[allow(dead_code)]
fn trspeed(size: i64, us: TimeDiff) -> i64 {
    if us < 1 {
        return size.saturating_mul(US_PER_SEC);
    }
    if size < SPEED_OVERFLOW_LIMIT {
        return size.saturating_mul(US_PER_SEC) / us;
    }
    if us >= US_PER_SEC {
        return size / (us / US_PER_SEC);
    }
    i64::MAX
}

/// Everything one transfer reports about itself -- `struct Progress` of
/// `lib/urldata.h:793-831`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct Progress {
    /// `now`: the most recently sampled instant.
    now: CurlTime,
    /// `lastshow`: the whole second in which the meter was last shown, or 0
    /// to force a redraw. A `time_t` in C, compared against
    /// `pnow->tv_sec`.
    lastshow: i64,
    /// `ul`: the upload direction.
    ul: ProgressDirection,
    /// `dl`: the download direction.
    dl: ProgressDirection,
    /// `current_speed`: the rate over the span the speed history covers,
    /// which is about five seconds. Distinct from either direction's `speed`,
    /// which is the average over the whole transfer.
    current_speed: i64,
    /// `earlydata_sent`: bytes sent as TLS early data.
    earlydata_sent: i64,
    /// `timespent`: microseconds from [`Self::start`] to the last
    /// calculation -- `CURLINFO_TOTAL_TIME_T`.
    timespent: TimeDiff,
    /// `t_postqueue`: microseconds spent queued, accumulated across
    /// redirects -- `CURLINFO_QUEUE_TIME_T`.
    t_postqueue: TimeDiff,
    /// `t_nslookup`: `CURLINFO_NAMELOOKUP_TIME_T`.
    t_nslookup: TimeDiff,
    /// `t_connect`: `CURLINFO_CONNECT_TIME_T`.
    t_connect: TimeDiff,
    /// `t_appconnect`: `CURLINFO_APPCONNECT_TIME_T`.
    t_appconnect: TimeDiff,
    /// `t_pretransfer`: `CURLINFO_PRETRANSFER_TIME_T`.
    t_pretransfer: TimeDiff,
    /// `t_posttransfer`: `CURLINFO_POSTTRANSFER_TIME_T`. Written by
    /// [`TimerId::PostTransfer`], whose C identifier is misspelled.
    t_posttransfer: TimeDiff,
    /// `t_starttransfer`: `CURLINFO_STARTTRANSFER_TIME_T`. Guarded by
    /// [`Self::is_t_starttransfer_set`].
    t_starttransfer: TimeDiff,
    /// `t_redirect`: `CURLINFO_REDIRECT_TIME_T`. Measured from
    /// [`Self::start`] rather than accumulated.
    t_redirect: TimeDiff,
    /// `start`: when the whole transfer began, set by [`Self::start_now`].
    start: CurlTime,
    /// `t_startsingle`: when the current single request began. The origin
    /// every plain accumulator measures from.
    t_startsingle: CurlTime,
    /// `t_startop`: when the operation began, redirects included.
    t_startop: CurlTime,
    /// `t_startqueue`: when the current queue wait began. Restarted by a
    /// redirect.
    t_startqueue: CurlTime,
    /// `t_acceptdata`: when an active-mode FTP data connection was accepted.
    t_acceptdata: CurlTime,
    /// `speed_amount` and `speed_time`, merged -- see [`SpeedRecord`].
    speeder: [SpeedRecord; CURL_SPEED_RECORDS],
    /// `speeder_c`: how many records have been taken, modulo 256.
    ///
    /// A `uint8_t` in C, and the width is load-bearing rather than
    /// incidental. See [`Self::calculate`] for what happens on the wrap.
    speeder_c: u8,
    /// `data->state.keeps_speed` (`lib/urldata.h:941`), relocated.
    ///
    /// When the current speed first fell below the low-speed limit, or the
    /// zero reading for "not currently under the limit". `pgrs_speedinit`
    /// (`lib/progress.c:124-127`) zeroes it, and this module is its only
    /// reader and writer in the whole C tree, which is why it moves here.
    keeps_speed: CurlTime,
    /// `hide`: `CURLOPT_NOPROGRESS`. Suppresses both the callback and the
    /// meter.
    hide: bool,
    /// `ul_size_known`: whether [`ProgressDirection::total_size`] of the
    /// upload direction means anything.
    ul_size_known: bool,
    /// `dl_size_known`: the same for the download direction.
    dl_size_known: bool,
    /// `headers_out`: whether the meter's two-line heading has been written.
    headers_out: bool,
    /// `callback`: whether a progress callback is in use, which
    /// `lib/setopt.c:2576-2589` sets when either callback option receives a
    /// non-null pointer. Read only to decide the trailing newline, so it is
    /// kept distinct from [`ProgressCallback::flavour`]: this flag is a
    /// record of what was set, that method is the live surface.
    callback: bool,
    /// `is_t_startransfer_set`, spelled correctly. Whether
    /// [`Self::t_starttransfer`] has been recorded for the current single
    /// transfer.
    is_t_starttransfer_set: bool,
}

impl Progress {
    // ---- the clock seam -------------------------------------------------

    /// Samples `clock`, stores the reading and returns it -- `Curl_pgrs_now`
    /// (`lib/progress.c:171-177`).
    #[allow(dead_code)]
    pub(crate) fn sample(&mut self, clock: &dyn Clock) -> CurlTime {
        let now = clock.now();
        self.now = now;
        now
    }

    /// The most recently sampled instant, without sampling again.
    #[allow(dead_code)]
    pub(crate) const fn now(&self) -> CurlTime {
        self.now
    }

    // ---- resetting and starting -----------------------------------------

    /// Clears the counters and forgets both sizes -- `Curl_pgrsReset`
    /// (`lib/progress.c:207-215`).
    #[allow(dead_code)]
    pub(crate) fn reset(&mut self) {
        self.set_upload_counter(0);
        self.dl.cur_size = 0;
        self.set_upload_size(-1);
        self.set_download_size(-1);
        self.speeder_c = 0;
        self.speed_init();
    }

    /// Forgets both expected sizes and nothing else --
    /// `Curl_pgrsResetTransferSizes` (`lib/progress.c:218-222`).
    #[allow(dead_code)]
    pub(crate) fn reset_transfer_sizes(&mut self) {
        self.set_download_size(-1);
        self.set_upload_size(-1);
    }

    /// Starts the transfer at `now` -- `Curl_pgrsStartNow`
    /// (`lib/progress.c:328-340`).
    #[allow(dead_code)]
    pub(crate) fn start_now(&mut self, now: CurlTime) {
        self.speeder_c = 0;
        self.start = now;
        self.is_t_starttransfer_set = false;
        self.dl.cur_size = 0;
        self.ul.cur_size = 0;
        self.dl_size_known = false;
        self.ul_size_known = false;
    }

    /// Clears the low-speed measurement -- `pgrs_speedinit`
    /// (`lib/progress.c:124-127`), which memsets `data->state.keeps_speed`.
    #[allow(dead_code)]
    fn speed_init(&mut self) {
        self.keeps_speed = CurlTime::ZERO;
    }

    // ---- sizes and counters ---------------------------------------------

    /// Records the expected download size -- `Curl_pgrsSetDownloadSize`
    /// (`lib/progress.c:366-376`).
    #[allow(dead_code)]
    pub(crate) fn set_download_size(&mut self, size: i64) {
        if size >= 0 {
            self.dl.total_size = size;
            self.dl_size_known = true;
        } else {
            self.dl.total_size = 0;
            self.dl_size_known = false;
        }
    }

    /// Records the expected upload size -- `Curl_pgrsSetUploadSize`
    /// (`lib/progress.c:378-388`). The download form's reasoning applies
    /// unchanged.
    #[allow(dead_code)]
    pub(crate) fn set_upload_size(&mut self, size: i64) {
        if size >= 0 {
            self.ul.total_size = size;
            self.ul_size_known = true;
        } else {
            self.ul.total_size = 0;
            self.ul_size_known = false;
        }
    }

    /// Sets the uploaded byte count outright --
    /// `Curl_pgrsSetUploadCounter` (`lib/progress.c:361-364`).
    #[allow(dead_code)]
    pub(crate) fn set_upload_counter(&mut self, size: i64) {
        self.ul.cur_size = size;
    }

    /// Adds `delta` downloaded bytes at `now` --
    /// `Curl_pgrs_download_inc` (`lib/progress.c:342-348`).
    #[allow(dead_code)]
    pub(crate) fn download_inc(&mut self, delta: usize, now: CurlTime) {
        if delta == 0 {
            return;
        }
        self.dl.cur_size = self.dl.cur_size.saturating_add(as_i64(delta));
        self.dl.rlimit.drain(delta, now);
    }

    /// Adds `delta` uploaded bytes at `now` -- `Curl_pgrs_upload_inc`
    /// (`lib/progress.c:350-356`). The download form's reasoning applies
    /// unchanged.
    #[allow(dead_code)]
    pub(crate) fn upload_inc(&mut self, delta: usize, now: CurlTime) {
        if delta == 0 {
            return;
        }
        self.ul.cur_size = self.ul.cur_size.saturating_add(as_i64(delta));
        self.ul.rlimit.drain(delta, now);
    }

    /// Records how many bytes were sent as TLS early data --
    /// `Curl_pgrsEarlyData` (`lib/progress.c:390-393`).
    ///
    /// Stored exactly as given, with no validation: the C assigns straight
    /// through, and the value reaches `--write-out %{tls_earlydata}`.
    #[allow(dead_code)]
    pub(crate) fn set_early_data(&mut self, sent: i64) {
        self.earlydata_sent = sent;
    }

    // ---- pausing ---------------------------------------------------------

    /// Informs the accounting that receiving has been paused or resumed --
    /// `Curl_pgrsRecvPause` (`lib/progress.c:224-230`).
    #[allow(dead_code)]
    pub(crate) fn recv_pause(&mut self, enable: bool) {
        if !enable {
            self.speeder_c = 0;
            self.speed_init();
        }
    }

    /// Informs the accounting that sending has been paused or resumed --
    /// `Curl_pgrsSendPause` (`lib/progress.c:232-238`). The receive form's
    /// reasoning applies unchanged, and the C bodies are identical.
    #[allow(dead_code)]
    pub(crate) fn send_pause(&mut self, enable: bool) {
        if !enable {
            self.speeder_c = 0;
            self.speed_init();
        }
    }

    // ---- timers ----------------------------------------------------------

    /// Samples `clock` and records it at `timer` -- `Curl_pgrsTime`
    /// (`lib/progress.c:323-326`), annotated `@unittest: 1399`.
    ///
    /// The convenience form, for the overwhelming majority of call sites that
    /// mean "now". [`Self::time_was`] is the form to use when the instant is
    /// already known.
    #[allow(dead_code)]
    pub(crate) fn time(&mut self, timer: TimerId, clock: &dyn Clock) {
        let now = self.sample(clock);
        self.time_was(timer, now);
    }

    /// Records `timestamp` at `timer` -- `Curl_pgrsTimeWas`
    /// (`lib/progress.c:243-315`).
    ///
    /// # The five kinds of label
    ///
    /// 1. **Origins.** [`TimerId::StartOp`] sets the operation and queue
    ///    origins and zeroes the accumulated queue time.
    ///    [`TimerId::StartSingle`] sets the request origin and clears the
    ///    start-transfer guard. [`TimerId::StartAccept`] stores the accept
    ///    origin. None of them accumulates.
    /// 2. **The queue total.** [`TimerId::PostQueue`] adds the microseconds
    ///    from the queue origin, and the C comment at `:265` states the
    ///    intent: "Queue time is accumulative from all involved redirects."
    /// 3. **Plain accumulators.** [`TimerId::NameLookup`],
    ///    [`TimerId::Connect`], [`TimerId::AppConnect`],
    ///    [`TimerId::PreTransfer`] and [`TimerId::PostTransfer`] each add the
    ///    microseconds elapsed since the REQUEST origin, with a floor of
    ///    [`MIN_ELAPSED_US`].
    /// 4. **The guarded accumulator.** [`TimerId::StartTransfer`] behaves
    ///    like a plain one on its first call per single transfer and does
    ///    nothing thereafter. The C's own comment at `:286-291` is the
    ///    specification: update it only "the first time we are setting
    ///    t_starttransfer" or when "a redirect has occurred since the last
    ///    time t_starttransfer was set". The guard is cleared by
    ///    [`TimerId::StartSingle`], which a redirect issues, so the two
    ///    conditions are one mechanism.
    /// 5. **The absolute measurement.** [`TimerId::Redirect`] ASSIGNS the
    ///    microseconds from the overall start -- it does not accumulate --
    ///    and restarts the queue origin at `timestamp`.
    #[allow(dead_code)]
    pub(crate) fn time_was(&mut self, timer: TimerId, timestamp: CurlTime) {
        // The C hoists a `timediff_t *delta` and lets the switch either
        // handle the label completely or point `delta` at an accumulator,
        // then applies the elapsed time once at the end. A pointer into
        // `self` cannot be held across the borrow, so the switch yields the
        // ACCUMULATOR'S IDENTITY instead and one match applies it. The two
        // shapes are equivalent, and this one keeps the elapsed-time
        // arithmetic in a single place exactly as the C does.
        let accumulator = match timer {
            // "mistake filter", and the C's `default:` arm as well.
            TimerId::None => None,
            TimerId::StartOp => {
                self.t_startop = timestamp;
                self.t_startqueue = timestamp;
                self.t_postqueue = 0;
                None
            }
            TimerId::StartSingle => {
                self.t_startsingle = timestamp;
                self.is_t_starttransfer_set = false;
                None
            }
            TimerId::PostQueue => {
                let queued = timediff_us(timestamp, self.t_startqueue);
                self.t_postqueue = self.t_postqueue.saturating_add(queued);
                None
            }
            TimerId::StartAccept => {
                self.t_acceptdata = timestamp;
                None
            }
            TimerId::NameLookup => Some(Accumulator::NameLookup),
            TimerId::Connect => Some(Accumulator::Connect),
            TimerId::AppConnect => Some(Accumulator::AppConnect),
            TimerId::PreTransfer => Some(Accumulator::PreTransfer),
            TimerId::StartTransfer => {
                if self.is_t_starttransfer_set {
                    // The C returns outright here, so not even the elapsed
                    // time is computed.
                    return;
                }
                self.is_t_starttransfer_set = true;
                Some(Accumulator::StartTransfer)
            }
            TimerId::PostTransfer => Some(Accumulator::PostTransfer),
            TimerId::Redirect => {
                self.t_redirect = timediff_us(timestamp, self.start);
                self.t_startqueue = timestamp;
                None
            }
        };

        let Some(accumulator) = accumulator else {
            return;
        };

        // `if(us < 1) us = 1;` -- one microsecond is the floor, so a phase
        // that completed faster than the clock's resolution still registers
        // as having happened. A negative difference, which a timestamp before
        // the request origin produces, is floored the same way.
        let mut elapsed = timediff_us(timestamp, self.t_startsingle);
        if elapsed < MIN_ELAPSED_US {
            elapsed = MIN_ELAPSED_US;
        }
        let field = match accumulator {
            Accumulator::NameLookup => &mut self.t_nslookup,
            Accumulator::Connect => &mut self.t_connect,
            Accumulator::AppConnect => &mut self.t_appconnect,
            Accumulator::PreTransfer => &mut self.t_pretransfer,
            Accumulator::StartTransfer => &mut self.t_starttransfer,
            Accumulator::PostTransfer => &mut self.t_posttransfer,
        };
        *field = field.saturating_add(elapsed);
    }
}

/// Which accumulator [`Progress::time_was`] is about to add to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
enum Accumulator {
    /// `&data->progress.t_nslookup`.
    NameLookup,
    /// `&data->progress.t_connect`.
    Connect,
    /// `&data->progress.t_appconnect`.
    AppConnect,
    /// `&data->progress.t_pretransfer`.
    PreTransfer,
    /// `&data->progress.t_starttransfer`.
    StartTransfer,
    /// `&data->progress.t_posttransfer`.
    PostTransfer,
}

/// A byte count as the signed integer every counter here is.
#[allow(dead_code)]
fn as_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl Progress {
    // ---- the speed calculation ------------------------------------------

    /// Recomputes every derived figure and reports whether the meter is due
    /// -- `progress_calc` (`lib/progress.c:410-485`).
    ///
    /// # The history, and the four ways a call can end
    ///
    /// With no record yet, one is taken, the current speed becomes the sum of
    /// the two averages, and the call reports "show". Otherwise the C
    /// computes where the next record would go and where the latest one is,
    /// and then:
    ///
    /// * **a second or more has passed** since the latest record: a new
    ///   record is taken and the ring advances;
    /// * **less than a second has passed and the request is done**: the
    ///   latest record is OVERWRITTEN, but only when the current speed is
    ///   still zero. The C's comment at `:446-449` gives the reason, and it is
    ///   a rate-limiting detail worth keeping in view -- "The last chunk of
    ///   data, when rate limiting, would increase reported speed since it no
    ///   longer measures a full second";
    /// * **less than a second has passed and the request is not done**: the
    ///   call returns "do not show" without touching the history, because
    ///   "too frequent calls otherwise ruin the history" (`:438`);
    /// * otherwise the current speed is recomputed from the oldest and latest
    ///   records, and the once-per-second throttle decides the answer.
    ///
    /// # The eight-bit counter wraps, and that is reproduced
    ///
    /// `speeder_c` is a `uint8_t` (`lib/urldata.h:824`). Its 256th increment
    /// wraps it to zero, and the next call then finds `!p->speeder_c` true and
    /// takes the first-record branch -- discarding the history and reporting
    /// the whole-transfer average as the current speed for one call. That is
    /// what curl 8.x does, roughly every 256 seconds of a long transfer, and it
    /// is frozen. [`u8::wrapping_add`] is the wrap written explicitly, because
    /// a plain `+= 1` would panic in a debug build at exactly the moment the C
    /// wraps.
    ///
    /// # The once-per-second throttle
    ///
    /// `if((p->lastshow == pnow->tv_sec) && !data->req.done) return FALSE;`
    /// (`:481-482`). The comparison is on whole seconds, so the meter is
    /// redrawn at most once per second of wall movement -- and a finished
    /// request overrides it, which is how the final row always appears.
    /// [`Self::done`] additionally zeroes [`Self::lastshow`], which makes the
    /// comparison fail for any non-zero second and forces the redraw.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn calculate(&mut self, now: CurlTime, req_done: bool) -> bool {
        self.timespent = timediff_us(now, self.start);
        self.dl.speed = trspeed(self.dl.cur_size, self.timespent);
        self.ul.speed = trspeed(self.ul.cur_size, self.timespent);

        if self.speeder_c == 0 {
            // No previous record exists.
            self.speeder[0] = SpeedRecord {
                amount: self.transferred(),
                at: now,
            };
            self.speeder_c = self.speeder_c.wrapping_add(1);
            // The overall average is the best estimate available at the
            // start, and it is what the C uses until two records exist.
            self.current_speed = self.ul.speed.saturating_add(self.dl.speed);
            self.lastshow = now.secs;
            return true;
        }

        // Where the next record goes, and where the latest one is.
        let i_next = usize::from(self.speeder_c) % CURL_SPEED_RECORDS;
        let mut i_latest = if i_next > 0 {
            i_next - 1
        } else {
            CURL_SPEED_RECORDS - 1
        };

        if timediff_ms(now, self.speeder[i_latest].at) >= SPEED_SAMPLE_MS {
            self.speeder_c = self.speeder_c.wrapping_add(1);
            i_latest = i_next;
            self.speeder[i_latest] = SpeedRecord {
                amount: self.transferred(),
                at: now,
            };
        } else if req_done {
            if self.current_speed == 0 {
                self.speeder[i_latest] = SpeedRecord {
                    amount: self.transferred(),
                    at: now,
                };
            }
        } else {
            // Transfer ongoing, wait for more time to pass.
            return false;
        }

        // Until the ring has been filled the oldest record is slot 0; after
        // that it is the one the next write will replace.
        let i_oldest = if usize::from(self.speeder_c) < CURL_SPEED_RECORDS {
            0
        } else {
            (i_latest + 1) % CURL_SPEED_RECORDS
        };

        let amount = self.speeder[i_latest]
            .amount
            .saturating_sub(self.speeder[i_oldest].amount);
        let mut duration_us =
            timediff_us(self.speeder[i_latest].at, self.speeder[i_oldest].at);
        if duration_us <= 0 {
            duration_us = MIN_ELAPSED_US;
        }

        self.current_speed = if amount > SPEED_OVERFLOW_LIMIT {
            // The C at `:471-475`: "the 'amount' value is bigger than would
            // fit in 64 bits if multiplied with 1000000, so we use the double
            // math for this". The two casts and the operator order are the
            // C's, and the narrowing cast back to an integer TRUNCATES toward
            // zero and SATURATES at the bounds -- which is exactly what the
            // schema asks for and, since Rust 1.45, what `as` does. In C the
            // same cast would be undefined for an out-of-range value.
            let scaled = (amount as f64) * 1_000_000.0 / (duration_us as f64);
            scaled as i64
        } else {
            // `amount * 1000000 / duration_us`. The guard above bounds
            // `amount` at `SPEED_OVERFLOW_LIMIT`, so the product is in range
            // for a non-negative amount; a negative amount below the mirror
            // bound is what the saturation covers, and it arises when a
            // counter was reset between two records.
            amount.saturating_mul(US_PER_SEC) / duration_us
        };

        if self.lastshow == now.secs && !req_done {
            return false;
        }
        self.lastshow = now.secs;
        true
    }

    /// The combined byte count both directions have transferred.
    #[allow(dead_code)]
    const fn transferred(&self) -> i64 {
        self.dl.cur_size.saturating_add(self.ul.cur_size)
    }

    // ---- the callback and the meter decision -----------------------------

    /// Runs the progress callback and decides the meter -- `pgrsupdate`
    /// (`lib/progress.c:609-654`).
    ///
    /// The C structure is preserved exactly, and its shape is easy to get
    /// wrong in three ways:
    ///
    /// 1. **Hidden means hidden.** With `CURLOPT_NOPROGRESS` set, neither the
    ///    callback nor the meter happens. The callback is inside the
    ///    `if(!data->progress.hide)` block, not outside it.
    /// 2. **Exactly one callback runs.** `else if` at `:630`, so a handle with
    ///    both options set calls only the modern one.
    /// 3. **`CURL_PROGRESSFUNC_CONTINUE` falls THROUGH to the meter; zero
    ///    does not.** A callback returning zero has handled the update, so
    ///    the C returns `CURLE_OK` before reaching `progress_meter`. Only
    ///    `CONTINUE` leaves the built-in behaviour in play. Anything else is
    ///    an abort.
    #[allow(dead_code)]
    fn report<C: ProgressCallback + ?Sized>(
        &mut self,
        show: bool,
        callback: &mut C,
    ) -> Result<Meter, Error> {
        if self.hide {
            return Ok(Meter::Skip);
        }

        if let Some(flavour) = callback.flavour() {
            let snapshot = self.snapshot();
            let result = {
                let mut guard = CallbackGuard::enter(callback);
                guard.call(flavour, &snapshot)
            };
            if result != CURL_PROGRESSFUNC_CONTINUE {
                if result != 0 {
                    return Err(Error::with_context(
                        CURLcode::AbortedByCallback,
                        CALLBACK_ABORTED,
                    ));
                }
                return Ok(Meter::Skip);
            }
        }

        Ok(if show { Meter::Draw } else { Meter::Skip })
    }

    /// Recalculates and reports -- `Curl_pgrsUpdate` (`lib/progress.c:663-666`)
    /// by way of `pgrs_update` (`:656-661`).
    ///
    /// `now` is pinned by the caller rather than sampled here, so that the
    /// byte counts this update reports and the instant it attributes them to
    /// are the same pair the transfer loop measured.
    #[allow(dead_code)]
    pub(crate) fn update<C: ProgressCallback + ?Sized>(
        &mut self,
        now: CurlTime,
        req_done: bool,
        callback: &mut C,
    ) -> Result<Meter, Error> {
        let show = self.calculate(now, req_done);
        self.report(show, callback)
    }

    /// Recalculates without reporting -- `Curl_pgrsUpdate_nometer`
    /// (`lib/progress.c:681-684`).
    #[allow(dead_code)]
    pub(crate) fn update_nometer(&mut self, now: CurlTime, req_done: bool) {
        let _ = self.calculate(now, req_done);
    }

    /// Updates, then checks the low speed -- `Curl_pgrsCheck`
    /// (`lib/progress.c:668-676`).
    ///
    /// # One pinned instant, where the C samples twice
    ///
    /// `Curl_pgrsCheck` calls `Curl_pgrs_now(data)` at `:672` and again at
    /// `:674`, so the two halves see readings microseconds apart. Here both
    /// halves use `now`. Nothing observable changes -- the second reading is
    /// never compared with the first, and both are compared only against
    /// timestamps taken far earlier -- while a single instant is what makes the
    /// pair reproducible from a pinned clock.
    #[allow(dead_code)]
    pub(crate) fn check<C: ProgressCallback + ?Sized>(
        &mut self,
        now: CurlTime,
        req_done: bool,
        limits: LowSpeedLimit,
        paused: Paused,
        callback: &mut C,
    ) -> Result<Check, Error> {
        let meter = self.update(now, req_done, callback)?;
        let speedcheck = if req_done {
            SpeedCheck::Skipped
        } else {
            self.speedcheck(limits, paused, now)?
        };
        Ok(Check { meter, speedcheck })
    }

    /// Forces a final update -- `Curl_pgrsDone` (`lib/progress.c:191-205`).
    #[allow(dead_code)]
    pub(crate) fn done<C: ProgressCallback + ?Sized>(
        &mut self,
        now: CurlTime,
        req_done: bool,
        callback: &mut C,
    ) -> Result<Done, Error> {
        self.lastshow = 0;
        let meter = self.update(now, req_done, callback)?;
        Ok(Done {
            meter,
            write_newline: !self.hide && !self.callback,
        })
    }

    // ---- the low-speed abort ---------------------------------------------

    /// Aborts a transfer that has been too slow for too long --
    /// `pgrs_speedcheck` (`lib/progress.c:132-169`), annotated
    /// `@unittest: 1606`.
    #[allow(dead_code)]
    pub(crate) fn speedcheck(
        &mut self,
        limits: LowSpeedLimit,
        paused: Paused,
        now: CurlTime,
    ) -> Result<SpeedCheck, Error> {
        if !limits.is_armed() || paused.either() {
            // A paused transfer is not qualified for speed checks.
            return Ok(SpeedCheck::Skipped);
        }

        if self.current_speed >= 0 {
            if self.current_speed < limits.limit_bps {
                if self.keeps_speed.secs == 0 {
                    // Under the limit at this moment.
                    self.keeps_speed = now;
                } else {
                    let howlong = timediff_ms(now, self.keeps_speed);
                    if howlong >= limits.window_ms() {
                        return Err(limits.too_slow());
                    }
                }
            } else {
                // Faster right now.
                self.keeps_speed.secs = 0;
            }
        }

        Ok(SpeedCheck::Expire {
            in_ms: SPEEDCHECK_EXPIRE_MS,
        })
    }

    // ---- snapshots -------------------------------------------------------

    /// The four counts a progress callback receives.
    ///
    /// Built from the fields in the order `lib/progress.c:617-620` passes
    /// them, and WITHOUT consulting either `*_size_known` flag, because the C
    /// does not: an unknown total reaches the callback as 0. That is
    /// deliberate in curl and documented in `CURLOPT_XFERINFOFUNCTION`, whose
    /// manual tells the application to expect 0 for an unknown size.
    #[allow(dead_code)]
    pub(crate) const fn snapshot(&self) -> ProgressSnapshot {
        ProgressSnapshot {
            dl_total: self.dl.total_size,
            dl_now: self.dl.cur_size,
            ul_total: self.ul.total_size,
            ul_now: self.ul.cur_size,
        }
    }

    /// Everything the built-in meter reads -- see [`MeterSnapshot`].
    #[allow(dead_code)]
    pub(crate) const fn meter_snapshot(&self) -> MeterSnapshot {
        MeterSnapshot {
            timespent: self.timespent,
            dl_total: self.dl.total_size,
            dl_cur: self.dl.cur_size,
            dl_speed: self.dl.speed,
            dl_size_known: self.dl_size_known,
            ul_total: self.ul.total_size,
            ul_cur: self.ul.cur_size,
            ul_speed: self.ul.speed,
            ul_size_known: self.ul_size_known,
            current_speed: self.current_speed,
            headers_out: self.headers_out,
        }
    }

    // ---- flags -----------------------------------------------------------

    /// Whether progress reporting is suppressed -- `CURLOPT_NOPROGRESS`.
    #[allow(dead_code)]
    pub(crate) const fn hide(&self) -> bool {
        self.hide
    }

    /// Suppresses or resumes progress reporting -- `lib/setopt.c:462`,
    /// `lib/url.c:495` and `lib/easy.c:1109`.
    #[allow(dead_code)]
    pub(crate) fn set_hide(&mut self, hide: bool) {
        self.hide = hide;
    }

    /// Whether a progress callback has been installed --
    /// `lib/setopt.c:2576-2589`.
    #[allow(dead_code)]
    pub(crate) const fn uses_callback(&self) -> bool {
        self.callback
    }

    /// Records whether a progress callback is in use.
    ///
    /// `lib/setopt.c:2576-2589` sets it TRUE for a non-null pointer and FALSE
    /// for null, with the comments "no longer internal" and "NULL enforces
    /// internal".
    #[allow(dead_code)]
    pub(crate) fn set_uses_callback(&mut self, uses_callback: bool) {
        self.callback = uses_callback;
    }

    /// Whether the meter's two-line heading has been written --
    /// `p->headers_out`.
    #[allow(dead_code)]
    pub(crate) const fn headers_shown(&self) -> bool {
        self.headers_out
    }

    /// Records that the meter's heading has been written --
    /// `lib/progress.c:541`, `p->headers_out = TRUE`.
    ///
    /// Set by the renderer rather than here, which is why the setter takes no
    /// argument and cannot unset it: the C never clears the flag within a
    /// transfer, and the only reset is a whole new [`Progress`].
    #[allow(dead_code)]
    pub(crate) fn mark_headers_shown(&mut self) {
        self.headers_out = true;
    }

    /// The upload direction.
    #[allow(dead_code)]
    pub(crate) const fn upload(&self) -> &ProgressDirection {
        &self.ul
    }

    /// The download direction.
    #[allow(dead_code)]
    pub(crate) const fn download(&self) -> &ProgressDirection {
        &self.dl
    }

    /// The upload direction, mutably -- for its rate limiter.
    #[allow(dead_code)]
    pub(crate) fn upload_mut(&mut self) -> &mut ProgressDirection {
        &mut self.ul
    }

    /// The download direction, mutably -- for its rate limiter.
    #[allow(dead_code)]
    pub(crate) fn download_mut(&mut self) -> &mut ProgressDirection {
        &mut self.dl
    }

    // ---- the CURLINFO surface -------------------------------------------
    //
    // One accessor per value `lib/getinfo.c:417-462` produces, named after
    // the `CURLINFO` it answers so that `easy/getinfo.rs` reads as a table.
    // Every one is a pure read: `curl_easy_getinfo` must not perturb the
    // transfer it is asked about.

    /// `CURLINFO_SIZE_DOWNLOAD_T` -- `lib/getinfo.c:420-422`.
    #[allow(dead_code)]
    pub(crate) const fn size_download(&self) -> i64 {
        self.dl.cur_size
    }

    /// `CURLINFO_SIZE_UPLOAD_T` -- `lib/getinfo.c:417-419`.
    #[allow(dead_code)]
    pub(crate) const fn size_upload(&self) -> i64 {
        self.ul.cur_size
    }

    /// `CURLINFO_SPEED_DOWNLOAD_T` -- `lib/getinfo.c:423-425`.
    #[allow(dead_code)]
    pub(crate) const fn speed_download(&self) -> i64 {
        self.dl.speed
    }

    /// `CURLINFO_SPEED_UPLOAD_T` -- `lib/getinfo.c:426-428`.
    #[allow(dead_code)]
    pub(crate) const fn speed_upload(&self) -> i64 {
        self.ul.speed
    }

    /// `CURLINFO_TOTAL_TIME_T`, in microseconds -- `lib/getinfo.c:437-439`.
    #[allow(dead_code)]
    pub(crate) const fn total_time_us(&self) -> TimeDiff {
        self.timespent
    }

    /// `CURLINFO_NAMELOOKUP_TIME_T`, in microseconds --
    /// `lib/getinfo.c:440-442`.
    #[allow(dead_code)]
    pub(crate) const fn namelookup_time_us(&self) -> TimeDiff {
        self.t_nslookup
    }

    /// `CURLINFO_CONNECT_TIME_T`, in microseconds -- `lib/getinfo.c:443-445`.
    #[allow(dead_code)]
    pub(crate) const fn connect_time_us(&self) -> TimeDiff {
        self.t_connect
    }

    /// `CURLINFO_APPCONNECT_TIME_T`, in microseconds --
    /// `lib/getinfo.c:446-448`.
    #[allow(dead_code)]
    pub(crate) const fn appconnect_time_us(&self) -> TimeDiff {
        self.t_appconnect
    }

    /// `CURLINFO_PRETRANSFER_TIME_T`, in microseconds --
    /// `lib/getinfo.c:449-451`.
    #[allow(dead_code)]
    pub(crate) const fn pretransfer_time_us(&self) -> TimeDiff {
        self.t_pretransfer
    }

    /// `CURLINFO_POSTTRANSFER_TIME_T`, in microseconds --
    /// `lib/getinfo.c:452-454`.
    #[allow(dead_code)]
    pub(crate) const fn posttransfer_time_us(&self) -> TimeDiff {
        self.t_posttransfer
    }

    /// `CURLINFO_STARTTRANSFER_TIME_T`, in microseconds --
    /// `lib/getinfo.c:455-457`.
    #[allow(dead_code)]
    pub(crate) const fn starttransfer_time_us(&self) -> TimeDiff {
        self.t_starttransfer
    }

    /// `CURLINFO_QUEUE_TIME_T`, in microseconds -- `lib/getinfo.c:458-460`.
    ///
    /// Present because `lib/getinfo.c` reads `t_postqueue` for it, and the
    /// forward contract of `easy/getinfo.rs` covers the complete `CURLINFO`
    /// mapping rather than a subset. Omitting the accessor would leave the
    /// field unreachable and the value unreportable.
    #[allow(dead_code)]
    pub(crate) const fn queue_time_us(&self) -> TimeDiff {
        self.t_postqueue
    }

    /// `CURLINFO_REDIRECT_TIME_T`, in microseconds --
    /// `lib/getinfo.c:461-463`.
    #[allow(dead_code)]
    pub(crate) const fn redirect_time_us(&self) -> TimeDiff {
        self.t_redirect
    }

    /// `CURLINFO_CONTENT_LENGTH_DOWNLOAD_T` -- `lib/getinfo.c:429-432`.
    #[allow(dead_code)]
    pub(crate) const fn content_length_download(&self) -> i64 {
        if self.dl_size_known {
            self.dl.total_size
        } else {
            -1
        }
    }

    /// `CURLINFO_CONTENT_LENGTH_UPLOAD_T` -- `lib/getinfo.c:433-436`. The
    /// download form's reasoning applies unchanged.
    #[allow(dead_code)]
    pub(crate) const fn content_length_upload(&self) -> i64 {
        if self.ul_size_known {
            self.ul.total_size
        } else {
            -1
        }
    }

    /// The rate over the span the speed history covers, in bytes per second.
    ///
    /// Reaches the meter's rightmost column and, through
    /// [`Self::speedcheck`], the low-speed abort. It is not a `CURLINFO`
    /// value: `CURLINFO_SPEED_DOWNLOAD_T` reports the whole-transfer average
    /// instead.
    #[allow(dead_code)]
    pub(crate) const fn current_speed(&self) -> i64 {
        self.current_speed
    }

    /// Bytes sent as TLS early data -- `--write-out %{tls_earlydata}`.
    #[allow(dead_code)]
    pub(crate) const fn early_data_sent(&self) -> i64 {
        self.earlydata_sent
    }

    /// When the transfer began, as [`Self::start_now`] recorded it.
    ///
    /// Read by the transfer loop to compute an overall timeout, which is the
    /// same origin `CURLINFO_TOTAL_TIME_T` is measured from.
    #[allow(dead_code)]
    pub(crate) const fn start(&self) -> CurlTime {
        self.start
    }

    /// When the current single request began.
    #[allow(dead_code)]
    pub(crate) const fn start_single(&self) -> CurlTime {
        self.t_startsingle
    }

    /// When the operation began, redirects included.
    #[allow(dead_code)]
    pub(crate) const fn start_op(&self) -> CurlTime {
        self.t_startop
    }

    /// When an active-mode FTP data connection was accepted.
    ///
    /// `lib/ftp.c` compares this against the current instant to enforce
    /// `CURLOPT_ACCEPTTIMEOUT_MS`, which is the only reader in the C tree.
    #[allow(dead_code)]
    pub(crate) const fn accept_data(&self) -> CurlTime {
        self.t_acceptdata
    }
}

// A `#[cfg(test)]` module is a CHILD of the module it tests, so these tests
// reach private fields directly. That is used sparingly and only where the
// public path cannot construct the state under test -- setting
// [`Progress::current_speed`] before a speed check, for instance, which
// otherwise needs a whole calculation to arrange and would then be testing
// two things at once.
#[cfg(test)]
mod tests {
    use super::{
        trspeed, CallbackFlavour, CallbackGuard, Check, Done, LowSpeedLimit,
        Meter, MeterSnapshot, NoProgressCallback, Paused, Progress,
        ProgressCallback, ProgressSnapshot, SpeedCheck, TimerId,
        CALLBACK_ABORTED, CURL_PROGRESSFUNC_CONTINUE, CURL_SPEED_RECORDS,
        MIN_ELAPSED_US, MS_PER_SEC, SPEEDCHECK_EXPIRE_MS, SPEED_OVERFLOW_LIMIT,
        SPEED_SAMPLE_MS, TOO_SLOW_PREFIX, US_PER_SEC,
    };
    use crate::error::CURLcode;
    use crate::util::timeval::{Clock, CurlTime, TestClock};
    use std::time::Duration;

    /// The whole second the test origin sits at.
    ///
    /// Non-zero so that a reading BEFORE the origin is representable, which
    /// the negative-elapsed tests need, and so that `tv_sec` is never 0 --
    /// a zero second would collide with [`Progress::lastshow`]'s "force a
    /// redraw" sentinel and make a throttle assertion say nothing.
    const ORIGIN_SECS: i64 = 1_000;

    /// The reading `offset_us` microseconds after the test origin.
    fn at_us(offset_us: i64) -> CurlTime {
        CurlTime::new(
            ORIGIN_SECS + offset_us / US_PER_SEC,
            i32::try_from(offset_us % US_PER_SEC)
                .expect("a microsecond remainder is under a second"),
        )
    }

    /// The reading `offset_ms` milliseconds after the test origin.
    fn at_ms(offset_ms: i64) -> CurlTime {
        at_us(offset_ms * 1_000)
    }

    /// A defaulted [`Progress`] whose current speed is pinned.
    fn at_speed(current_speed: i64) -> Progress {
        Progress {
            current_speed,
            ..Progress::default()
        }
    }

    /// A [`Progress`] partway through a measurement: four records taken and
    /// the low-speed marker running.
    ///
    /// The state the two pause tests start from, so that "the history and the
    /// marker were discarded" and "they were left alone" are assertions about
    /// the same starting point.
    fn mid_measurement() -> Progress {
        Progress {
            speeder_c: 4,
            keeps_speed: at_ms(10),
            ..Progress::default()
        }
    }

    /// A recording [`ProgressCallback`].
    #[derive(Debug, Default)]
    struct Recorder {
        /// What [`ProgressCallback::flavour`] reports.
        flavour: Option<CallbackFlavour>,
        /// What the callback returns.
        result: i32,
        /// The snapshots the modern callback received.
        modern: Vec<ProgressSnapshot>,
        /// The four doubles the legacy callback received, in ABI order.
        legacy: Vec<[f64; 4]>,
        /// The live `in_callback` flag.
        in_callback: bool,
        /// Every value the flag was set to, in order.
        transitions: Vec<bool>,
        /// What the flag read at the top of each invocation.
        flag_inside: Vec<bool>,
    }

    impl Recorder {
        /// A handle with no callback installed.
        fn silent() -> Self {
            Self::default()
        }

        /// A handle whose `CURLOPT_XFERINFOFUNCTION` returns `result`.
        fn modern(result: i32) -> Self {
            Self {
                flavour: Some(CallbackFlavour::XferInfo),
                result,
                ..Self::default()
            }
        }

        /// A handle whose `CURLOPT_PROGRESSFUNCTION` returns `result`.
        fn legacy(result: i32) -> Self {
            Self {
                flavour: Some(CallbackFlavour::Progress),
                result,
                ..Self::default()
            }
        }

        /// How many times either callback was invoked.
        fn calls(&self) -> usize {
            self.modern.len() + self.legacy.len()
        }
    }

    impl ProgressCallback for Recorder {
        fn flavour(&self) -> Option<CallbackFlavour> {
            self.flavour
        }

        fn set_in_callback(&mut self, active: bool) {
            self.in_callback = active;
            self.transitions.push(active);
        }

        fn xferinfo(&mut self, snapshot: &ProgressSnapshot) -> i32 {
            self.flag_inside.push(self.in_callback);
            self.modern.push(*snapshot);
            self.result
        }

        fn progress(&mut self, snapshot: &ProgressSnapshot) -> i32 {
            self.flag_inside.push(self.in_callback);
            self.legacy.push([
                snapshot.dl_total_f64(),
                snapshot.dl_now_f64(),
                snapshot.ul_total_f64(),
                snapshot.ul_now_f64(),
            ]);
            self.result
        }
    }

    /// A [`ProgressCallback`] whose callback panics.
    ///
    /// Exists for one test: that the bracketing survives an unwind. The
    /// workspace pins `panic = "unwind"` in every profile, for the unrelated
    /// but load-bearing reason that unwinding across the C ABI is undefined
    /// behaviour and every exported entry point has to contain it, so
    /// [`std::panic::catch_unwind`] is available here.
    #[derive(Debug, Default)]
    struct Exploding {
        /// The live `in_callback` flag.
        in_callback: bool,
    }

    impl ProgressCallback for Exploding {
        fn flavour(&self) -> Option<CallbackFlavour> {
            Some(CallbackFlavour::XferInfo)
        }

        fn set_in_callback(&mut self, active: bool) {
            self.in_callback = active;
        }

        fn xferinfo(&mut self, _snapshot: &ProgressSnapshot) -> i32 {
            panic!("a progress callback may do anything, including this");
        }

        fn progress(&mut self, _snapshot: &ProgressSnapshot) -> i32 {
            unreachable!("this recorder installs the modern callback");
        }
    }

    /// A transfer whose accounting was driven entirely from a pinned clock.
    ///
    /// Every number the table-driven `CURLINFO` assertion expects is produced
    /// by this function through the module's own public operations -- no field
    /// is written directly -- so the table checks the accessors AND the
    /// arithmetic that fed them. The schedule, in milliseconds from the
    /// origin:
    ///
    /// ```text
    ///    0  StartOp        operation and queue origins
    ///   10  StartSingle    request origin; the transfer starts here
    ///   15  PostQueue      +15_000us queued
    ///   35  NameLookup     +25_000us
    ///   65  Connect        +55_000us
    ///  105  AppConnect     +95_000us
    ///  115  PreTransfer    +105_000us
    ///  200  StartTransfer  +190_000us
    /// 1000  4096 down and 512 up delivered; PostTransfer +990_000us;
    ///       Redirect = 990_000us; one calculation
    /// ```
    fn pinned_transfer() -> Progress {
        let clock = TestClock::new(at_us(0));
        let mut progress = Progress::default();

        progress.time(TimerId::StartOp, &clock);
        clock.advance(Duration::from_millis(10));
        progress.time(TimerId::StartSingle, &clock);
        progress.start_now(progress.now());

        clock.advance(Duration::from_millis(5));
        progress.time(TimerId::PostQueue, &clock);
        clock.advance(Duration::from_millis(20));
        progress.time(TimerId::NameLookup, &clock);
        clock.advance(Duration::from_millis(30));
        progress.time(TimerId::Connect, &clock);
        clock.advance(Duration::from_millis(40));
        progress.time(TimerId::AppConnect, &clock);
        clock.advance(Duration::from_millis(10));
        progress.time(TimerId::PreTransfer, &clock);
        clock.advance(Duration::from_millis(85));
        progress.time(TimerId::StartTransfer, &clock);

        progress.set_download_size(4096);
        progress.set_upload_size(512);

        clock.advance(Duration::from_millis(800));
        let now = progress.sample(&clock);
        progress.download_inc(4096, now);
        progress.upload_inc(512, now);
        progress.time(TimerId::PostTransfer, &clock);
        progress.time(TimerId::Redirect, &clock);
        assert!(
            progress.calculate(now, true),
            "the first calculation always reports a show"
        );
        progress
    }

    // ---- the constants ---------------------------------------------------

    #[test]
    fn the_constants_are_the_c_s_literals() {
        assert_eq!(CURL_SPEED_RECORDS, 6, "lib/urldata.h:820, `(5 + 1)`");
        assert_eq!(
            CURL_PROGRESSFUNC_CONTINUE, 0x1000_0001,
            "include/curl/curl.h:234"
        );
        assert_eq!(SPEEDCHECK_EXPIRE_MS, 1_000, "lib/progress.c:166");
        assert_eq!(US_PER_SEC, 1_000_000);
        assert_eq!(MS_PER_SEC, 1_000);
        assert_eq!(SPEED_SAMPLE_MS, 1_000, "lib/progress.c:439");
        assert_eq!(MIN_ELAPSED_US, 1, "lib/progress.c:311-312");
        assert_eq!(SPEED_OVERFLOW_LIMIT, i64::MAX / 1_000_000);
        assert_eq!(SPEED_OVERFLOW_LIMIT, 9_223_372_036_854);
        assert_eq!(CALLBACK_ABORTED, "Callback aborted");
        assert_eq!(TOO_SLOW_PREFIX, "Operation too slow. Less than ");
    }

    #[test]
    fn the_timer_vocabulary_is_the_c_enumeration() {
        // Twelve labels, because the C's thirteenth is the `TIMER_LAST`
        // sentinel and the type's documentation records why it has no
        // counterpart.
        assert_eq!(TimerId::VARIANTS.len(), 12);
        let names: Vec<&str> =
            TimerId::VARIANTS.iter().map(|id| id.c_name()).collect();
        assert_eq!(
            names,
            vec![
                "TIMER_NONE",
                "TIMER_STARTOP",
                "TIMER_STARTSINGLE",
                "TIMER_POSTQUEUE",
                "TIMER_NAMELOOKUP",
                "TIMER_CONNECT",
                "TIMER_APPCONNECT",
                "TIMER_PRETRANSFER",
                "TIMER_STARTTRANSFER",
                // The C really does drop a letter here.
                "TIMER_POSTRANSFER",
                "TIMER_STARTACCEPT",
                "TIMER_REDIRECT",
            ]
        );
        // Distinct, so that no two labels are the same value under a
        // different name.
        for (index, first) in TimerId::VARIANTS.iter().enumerate() {
            for second in &TimerId::VARIANTS[index + 1..] {
                assert_ne!(first, second);
            }
        }
    }

    // ---- resetting, starting, sizes and counters -------------------------

    #[test]
    fn reset_clears_the_counters_and_forgets_both_sizes() {
        let mut progress = Progress::default();
        progress.set_download_size(4096);
        progress.set_upload_size(512);
        progress.download_inc(100, at_us(0));
        progress.upload_inc(50, at_us(0));
        progress.speeder_c = 4;
        progress.keeps_speed = at_us(0);

        progress.reset();

        assert_eq!(progress.size_download(), 0);
        assert_eq!(progress.size_upload(), 0);
        assert_eq!(progress.download().total_size(), 0);
        assert_eq!(progress.upload().total_size(), 0);
        assert_eq!(progress.content_length_download(), -1);
        assert_eq!(progress.content_length_upload(), -1);
        assert_eq!(progress.speeder_c, 0, "the speed records are forgotten");
        assert!(
            progress.keeps_speed.is_zero(),
            "pgrs_speedinit clears the low-speed marker"
        );
    }

    #[test]
    fn reset_leaves_the_timers_and_the_history_contents_alone() {
        let mut progress = pinned_transfer();
        let before = progress.speeder;
        let namelookup = progress.namelookup_time_us();

        progress.reset();

        assert_eq!(progress.namelookup_time_us(), namelookup);
        assert_eq!(progress.redirect_time_us(), 990_000);
        assert_eq!(
            progress.speeder, before,
            "the ring's CONTENTS survive; only the counter is cleared, \
             which is what makes them unreachable"
        );
    }

    #[test]
    fn reset_transfer_sizes_leaves_the_counters_alone() {
        let mut progress = Progress::default();
        progress.set_download_size(4096);
        progress.set_upload_size(512);
        progress.download_inc(100, at_us(0));
        progress.upload_inc(50, at_us(0));
        progress.speeder_c = 3;

        progress.reset_transfer_sizes();

        assert_eq!(progress.content_length_download(), -1);
        assert_eq!(progress.content_length_upload(), -1);
        assert_eq!(progress.size_download(), 100, "the counter survives");
        assert_eq!(progress.size_upload(), 50, "and so does this one");
        assert_eq!(progress.speeder_c, 3, "and so does the record counter");
    }

    #[test]
    fn start_now_pins_the_origin_and_forgets_the_sizes() {
        let mut progress = Progress::default();
        progress.set_download_size(4096);
        progress.set_upload_size(512);
        progress.download_inc(700, at_us(0));
        progress.upload_inc(300, at_us(0));
        progress.speeder_c = 5;
        progress.is_t_starttransfer_set = true;

        progress.start_now(at_ms(250));

        assert_eq!(progress.start(), at_ms(250));
        assert_eq!(progress.speeder_c, 0);
        assert!(!progress.is_t_starttransfer_set);
        assert_eq!(progress.size_download(), 0);
        assert_eq!(progress.size_upload(), 0);
        assert_eq!(progress.content_length_download(), -1);
        assert_eq!(progress.content_length_upload(), -1);
        // The faithful subtlety: the flags are cleared but the stored totals
        // are NOT, which is why the callback can still see them.
        assert_eq!(progress.download().total_size(), 4096);
        assert_eq!(progress.upload().total_size(), 512);
        assert_eq!(progress.snapshot().dl_total, 4096);
    }

    #[test]
    fn a_non_negative_size_is_known_and_a_negative_one_is_not() {
        let mut progress = Progress::default();

        progress.set_download_size(4096);
        assert_eq!(progress.download().total_size(), 4096);
        assert_eq!(progress.content_length_download(), 4096);

        progress.set_download_size(-1);
        assert_eq!(
            progress.download().total_size(),
            0,
            "an unknown size STORES zero rather than keeping the old value"
        );
        assert_eq!(progress.content_length_download(), -1);

        progress.set_upload_size(512);
        assert_eq!(progress.content_length_upload(), 512);
        progress.set_upload_size(-1024);
        assert_eq!(progress.upload().total_size(), 0);
        assert_eq!(progress.content_length_upload(), -1);
    }

    #[test]
    fn a_known_length_of_zero_is_not_an_unknown_length() {
        let mut progress = Progress::default();
        progress.set_download_size(0);
        progress.set_upload_size(0);

        assert_eq!(
            progress.content_length_download(),
            0,
            "a zero-length body is a KNOWN length"
        );
        assert_eq!(progress.content_length_upload(), 0);

        progress.reset_transfer_sizes();
        assert_eq!(progress.content_length_download(), -1);
        assert_eq!(progress.content_length_upload(), -1);
    }

    #[test]
    fn the_upload_counter_can_be_set_outright() {
        let mut progress = Progress::default();
        progress.set_upload_counter(9_999);
        assert_eq!(progress.size_upload(), 9_999);
        progress.set_upload_counter(0);
        assert_eq!(progress.size_upload(), 0);
    }

    #[test]
    fn an_increment_drains_its_own_limiter_at_the_pinned_instant() {
        use crate::transfer::ratelimit::RateLimit;

        let start = at_us(0);
        let mut progress = Progress::default();
        // A limited bucket in each direction, so that a drain is observable.
        *progress.download_mut().rlimit_mut() =
            RateLimit::new(1_000, 1_000, start);
        *progress.upload_mut().rlimit_mut() =
            RateLimit::new(1_000, 1_000, start);

        // No time passes, so no tokens are generated and the balance moves by
        // exactly the delta.
        progress.download_inc(400, start);
        assert_eq!(progress.size_download(), 400);
        assert_eq!(progress.download_mut().rlimit_mut().available(start), 600);
        assert_eq!(
            progress.upload_mut().rlimit_mut().available(start),
            1_000,
            "the upload limiter is untouched by a download"
        );

        progress.upload_inc(250, start);
        assert_eq!(progress.size_upload(), 250);
        assert_eq!(progress.upload_mut().rlimit_mut().available(start), 750);
        assert_eq!(
            progress.download_mut().rlimit_mut().available(start),
            600,
            "and the download limiter is untouched by an upload"
        );
    }

    #[test]
    fn a_zero_delta_touches_neither_the_counter_nor_the_limiter() {
        use crate::transfer::ratelimit::RateLimit;

        let start = at_us(0);
        let mut progress = Progress::default();
        *progress.download_mut().rlimit_mut() =
            RateLimit::new(1_000, 1_000, start);
        *progress.upload_mut().rlimit_mut() =
            RateLimit::new(1_000, 1_000, start);
        let untouched = progress.clone();

        progress.download_inc(0, at_ms(500));
        progress.upload_inc(0, at_ms(500));

        assert_eq!(
            progress, untouched,
            "`if(delta)` guards the whole body, limiter included -- and the \
             limiter's own timestamp must not move either"
        );
    }

    #[test]
    fn early_data_is_stored_exactly() {
        let mut progress = Progress::default();
        assert_eq!(progress.early_data_sent(), 0);
        progress.set_early_data(1_337);
        assert_eq!(progress.early_data_sent(), 1_337);
        progress.set_early_data(0);
        assert_eq!(progress.early_data_sent(), 0);
    }

    // ---- pausing ---------------------------------------------------------

    #[test]
    fn resuming_either_direction_resets_the_history_and_the_marker() {
        for resume_receive in [true, false] {
            let mut progress = mid_measurement();

            if resume_receive {
                progress.recv_pause(false);
            } else {
                progress.send_pause(false);
            }

            assert_eq!(progress.speeder_c, 0);
            assert!(progress.keeps_speed.is_zero());
        }
    }

    #[test]
    fn pausing_alone_resets_nothing() {
        for pause_receive in [true, false] {
            let mut progress = mid_measurement();

            if pause_receive {
                progress.recv_pause(true);
            } else {
                progress.send_pause(true);
            }

            assert_eq!(
                progress.speeder_c, 4,
                "no measurement happens while paused, so discarding the \
                 history now would achieve nothing"
            );
            assert_eq!(progress.keeps_speed, at_ms(10));
        }
    }

    // ---- the timers ------------------------------------------------------

    #[test]
    fn the_none_label_mutates_nothing() {
        let mut progress = pinned_transfer();
        let untouched = progress.clone();
        progress.time_was(TimerId::None, at_ms(5_000));
        assert_eq!(progress, untouched, "the C calls it a mistake filter");
    }

    #[test]
    fn start_op_sets_both_origins_and_zeroes_the_queue_total() {
        let mut progress = Progress {
            t_postqueue: 12_345,
            ..Progress::default()
        };

        progress.time_was(TimerId::StartOp, at_ms(40));

        assert_eq!(progress.start_op(), at_ms(40));
        assert_eq!(progress.t_startqueue, at_ms(40));
        assert_eq!(progress.queue_time_us(), 0);
    }

    #[test]
    fn start_single_pins_the_request_origin_and_clears_the_guard() {
        let mut progress = Progress {
            is_t_starttransfer_set: true,
            ..Progress::default()
        };

        progress.time_was(TimerId::StartSingle, at_ms(70));

        assert_eq!(progress.start_single(), at_ms(70));
        assert!(!progress.is_t_starttransfer_set);
    }

    #[test]
    fn the_queue_total_accumulates_across_redirects() {
        let mut progress = Progress::default();
        progress.time_was(TimerId::StartOp, at_ms(0));

        // First request: queued for 30 ms.
        progress.time_was(TimerId::PostQueue, at_ms(30));
        assert_eq!(progress.queue_time_us(), 30_000);

        // A redirect restarts the queue clock at the redirect's instant.
        progress.time_was(TimerId::Redirect, at_ms(100));
        assert_eq!(progress.t_startqueue, at_ms(100));

        // Second request: queued for another 45 ms, which ADDS.
        progress.time_was(TimerId::PostQueue, at_ms(145));
        assert_eq!(
            progress.queue_time_us(),
            75_000,
            "queue time is accumulative from all involved redirects"
        );

        // And a third, to prove the accumulation is not a two-term special
        // case.
        progress.time_was(TimerId::Redirect, at_ms(200));
        progress.time_was(TimerId::PostQueue, at_ms(225));
        assert_eq!(progress.queue_time_us(), 100_000);
    }

    #[test]
    fn start_accept_stores_the_accept_origin() {
        let mut progress = Progress::default();
        progress.time_was(TimerId::StartAccept, at_ms(900));
        assert_eq!(progress.accept_data(), at_ms(900));
    }

    #[test]
    fn every_plain_accumulator_adds_elapsed_microseconds() {
        // (label, the accessor it feeds)
        let cases: [(TimerId, fn(&Progress) -> i64); 5] = [
            (TimerId::NameLookup, Progress::namelookup_time_us),
            (TimerId::Connect, Progress::connect_time_us),
            (TimerId::AppConnect, Progress::appconnect_time_us),
            (TimerId::PreTransfer, Progress::pretransfer_time_us),
            (TimerId::PostTransfer, Progress::posttransfer_time_us),
        ];

        for (label, read) in cases {
            let mut progress = Progress::default();
            progress.time_was(TimerId::StartSingle, at_ms(100));

            progress.time_was(label, at_ms(160));
            assert_eq!(read(&progress), 60_000, "{}", label.c_name());

            // Accumulative, not assignment: a second call on a later request
            // adds to what is already there. This is what makes the reported
            // times cover every attempt rather than only the last.
            progress.time_was(TimerId::StartSingle, at_ms(200));
            progress.time_was(label, at_ms(215));
            assert_eq!(read(&progress), 75_000, "{}", label.c_name());
        }
    }

    #[test]
    fn an_accumulator_contributes_at_least_one_microsecond() {
        let mut progress = Progress::default();
        progress.time_was(TimerId::StartSingle, at_us(500));

        // Zero elapsed: the same instant as the request origin.
        progress.time_was(TimerId::NameLookup, at_us(500));
        assert_eq!(progress.namelookup_time_us(), MIN_ELAPSED_US);

        // NEGATIVE elapsed, which happy eyeballing can produce when a
        // winner's timestamp predates the origin the loser established. The
        // floor applies there too rather than subtracting.
        progress.time_was(TimerId::Connect, at_us(400));
        assert_eq!(progress.connect_time_us(), MIN_ELAPSED_US);

        // And a sub-microsecond phase, which is the case the C's comment
        // names.
        progress.time_was(TimerId::AppConnect, at_us(501));
        assert_eq!(progress.appconnect_time_us(), 1);
    }

    #[test]
    fn repeated_start_transfer_calls_are_suppressed() {
        let mut progress = Progress::default();
        progress.time_was(TimerId::StartSingle, at_ms(100));

        progress.time_was(TimerId::StartTransfer, at_ms(180));
        assert_eq!(progress.starttransfer_time_us(), 80_000);
        assert!(progress.is_t_starttransfer_set);

        // Repeated invocations must not change it.
        progress.time_was(TimerId::StartTransfer, at_ms(400));
        progress.time_was(TimerId::StartTransfer, at_ms(900));
        assert_eq!(progress.starttransfer_time_us(), 80_000);

        // A new single transfer -- which is what a redirect issues -- clears
        // the guard, and the next first-byte moment accumulates again.
        progress.time_was(TimerId::StartSingle, at_ms(1_000));
        progress.time_was(TimerId::StartTransfer, at_ms(1_050));
        assert_eq!(progress.starttransfer_time_us(), 130_000);
        // Still guarded afterwards.
        progress.time_was(TimerId::StartTransfer, at_ms(1_500));
        assert_eq!(progress.starttransfer_time_us(), 130_000);
    }

    #[test]
    fn redirect_measures_from_the_overall_origin_and_assigns() {
        let mut progress = Progress::default();
        progress.start_now(at_ms(10));
        progress.time_was(TimerId::StartSingle, at_ms(500));

        progress.time_was(TimerId::Redirect, at_ms(600));
        assert_eq!(
            progress.redirect_time_us(),
            590_000,
            "measured from `start`, NOT from the current request"
        );

        // The second redirect ASSIGNS rather than accumulating, so the value
        // is always "time from the start until the last redirect".
        progress.time_was(TimerId::Redirect, at_ms(900));
        assert_eq!(progress.redirect_time_us(), 890_000);
    }

    #[test]
    fn time_samples_the_injected_clock_and_delegates() {
        let clock = TestClock::new(at_ms(300));
        let mut progress = Progress::default();
        progress.time(TimerId::StartSingle, &clock);
        assert_eq!(progress.now(), at_ms(300));
        assert_eq!(progress.start_single(), at_ms(300));

        clock.advance(Duration::from_millis(45));
        progress.time(TimerId::Connect, &clock);
        assert_eq!(progress.now(), at_ms(345));
        assert_eq!(progress.connect_time_us(), 45_000);
    }

    #[test]
    fn sample_stores_and_returns_the_same_reading() {
        let clock = TestClock::new(at_ms(7));
        let mut progress = Progress::default();
        assert!(progress.now().is_zero());
        assert_eq!(progress.sample(&clock), at_ms(7));
        assert_eq!(progress.now(), at_ms(7));
        assert_eq!(progress.now(), clock.now(), "no second reading was taken");
    }

    // ---- trspeed ---------------------------------------------------------

    #[test]
    fn trspeed_scales_the_size_below_one_microsecond() {
        assert_eq!(trspeed(0, 0), 0);
        assert_eq!(trspeed(5, 0), 5_000_000);
        // A negative duration takes the same branch, `us < 1`.
        assert_eq!(trspeed(5, -1), 5_000_000);
        assert_eq!(trspeed(5, -1_000_000), 5_000_000);
    }

    #[test]
    fn trspeed_multiplies_before_dividing_when_it_can() {
        assert_eq!(trspeed(1_000, 1_000_000), 1_000, "1000 bytes in a second");
        assert_eq!(trspeed(1_000, 500_000), 2_000, "in half a second");
        assert_eq!(trspeed(1, 3), 333_333, "and the division truncates");
        // The boundary of the second branch is `<`, so one below it still
        // multiplies first and stays exact.
        let just_inside = SPEED_OVERFLOW_LIMIT - 1;
        assert_eq!(
            trspeed(just_inside, 1_000_000),
            just_inside,
            "exact for the largest size the multiply-first branch admits"
        );
    }

    #[test]
    fn trspeed_divides_the_duration_when_the_product_would_overflow() {
        // At the boundary the second branch's `<` is false, so the third
        // branch runs: it divides the DURATION down to whole seconds first.
        assert_eq!(
            trspeed(SPEED_OVERFLOW_LIMIT, 2_000_000),
            SPEED_OVERFLOW_LIMIT / 2
        );
        assert_eq!(trspeed(i64::MAX, 1_000_000), i64::MAX);
        // The duration's fractional second is DISCARDED here, which is the
        // precision the C trades away rather than overflowing.
        assert_eq!(
            trspeed(SPEED_OVERFLOW_LIMIT, 1_999_999),
            SPEED_OVERFLOW_LIMIT,
            "1_999_999 / 1_000_000 truncates to 1"
        );
    }

    #[test]
    fn trspeed_saturates_when_neither_branch_applies() {
        // A size at or above the boundary with a sub-second duration: the C
        // gives up and returns the largest representable rate.
        assert_eq!(trspeed(SPEED_OVERFLOW_LIMIT, 1), i64::MAX);
        assert_eq!(trspeed(i64::MAX, 999_999), i64::MAX);
    }

    #[test]
    fn trspeed_never_panics_on_an_extreme() {
        // The two places the C would have undefined behaviour, and the whole
        // extreme grid besides. The assertion is that this returns at all.
        for size in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX] {
            for us in [i64::MIN, -1, 0, 1, 999_999, 1_000_000, i64::MAX] {
                let _ = trspeed(size, us);
            }
        }
        assert_eq!(trspeed(i64::MIN, 0), i64::MIN, "saturated, not wrapped");
        assert_eq!(trspeed(i64::MIN, 1), i64::MIN);
    }

    // ---- the speed calculation ------------------------------------------

    #[test]
    fn the_first_calculation_creates_one_record_and_shows() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        progress.download_inc(1_000, at_us(0));

        assert!(progress.calculate(at_ms(500), false));

        assert_eq!(progress.total_time_us(), 500_000);
        assert_eq!(progress.speed_download(), 2_000, "1000 bytes in 0.5 s");
        assert_eq!(progress.speed_upload(), 0);
        assert_eq!(progress.speeder_c, 1);
        assert_eq!(progress.speeder[0].amount, 1_000);
        assert_eq!(progress.speeder[0].at, at_ms(500));
        assert_eq!(
            progress.current_speed(),
            2_000,
            "the overall average is used until two records exist"
        );
        assert_eq!(progress.lastshow, at_ms(500).secs);
    }

    #[test]
    fn an_ongoing_subsecond_calculation_does_not_show() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        progress.download_inc(1_000, at_us(0));
        assert!(progress.calculate(at_ms(500), false));
        let history = progress.speeder;

        progress.download_inc(500, at_ms(900));
        assert!(
            !progress.calculate(at_ms(900), false),
            "less than a second since the latest record"
        );

        // The derived figures ARE refreshed even though nothing is shown --
        // `progress_calc` updates them before it consults the history.
        assert_eq!(progress.total_time_us(), 900_000);
        assert_eq!(progress.speed_download(), 1_666);
        assert_eq!(
            progress.speeder, history,
            "the history is untouched: too frequent calls would ruin it"
        );
        assert_eq!(progress.speeder_c, 1);
    }

    #[test]
    fn a_calculation_a_second_later_records_and_shows() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        progress.download_inc(1_000, at_us(0));
        assert!(progress.calculate(at_ms(500), false));

        progress.download_inc(3_000, at_ms(1_500));
        assert!(progress.calculate(at_ms(1_500), false));

        assert_eq!(progress.speeder_c, 2);
        assert_eq!(progress.speeder[1].amount, 4_000);
        assert_eq!(progress.speeder[1].at, at_ms(1_500));
        assert_eq!(progress.total_time_us(), 1_500_000);
        assert_eq!(progress.speed_download(), 2_666, "4000 bytes in 1.5 s");
        assert_eq!(
            progress.current_speed(),
            3_000,
            "3000 bytes between the two records, one second apart"
        );
        assert_eq!(progress.lastshow, at_ms(1_500).secs);
    }

    #[test]
    fn a_finished_request_updates_the_latest_record_only_at_zero_speed() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        assert!(progress.calculate(at_us(0), false));
        assert_eq!(progress.current_speed(), 0, "nothing transferred yet");

        // Sub-second AND done AND the current speed is still zero: the latest
        // record is overwritten so that the final figure reflects the last
        // chunk.
        progress.download_inc(700, at_ms(400));
        assert!(progress.calculate(at_ms(400), true));
        assert_eq!(progress.speeder_c, 1, "no NEW record was made");
        assert_eq!(progress.speeder[0].amount, 700);
        assert_eq!(progress.speeder[0].at, at_ms(400));

        // Now the current speed is non-zero, so a second sub-second finish
        // leaves the record alone: "stay at the speed we have", because the
        // last chunk under rate limiting no longer measures a full second.
        progress.current_speed = 4_242;
        progress.download_inc(300, at_ms(600));
        assert!(progress.calculate(at_ms(600), true));
        assert_eq!(
            progress.speeder[0].amount, 700,
            "the record is preserved when a current speed already exists"
        );
        assert_eq!(progress.speeder[0].at, at_ms(400));
    }

    #[test]
    fn the_ring_wraps_and_measures_the_five_second_window() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));

        // Seven records, one a second, 1000 bytes each second.
        for second in 0..7_i64 {
            progress.download_inc(1_000, at_ms(second * 1_000));
            assert!(
                progress.calculate(at_ms(second * 1_000), false),
                "second {second} makes a record and shows"
            );
        }

        assert_eq!(progress.speeder_c, 7);
        // The seventh record wrapped into slot 0, so the oldest reachable one
        // is slot 1 -- the record from second one.
        assert_eq!(progress.speeder[0].at, at_ms(6_000));
        assert_eq!(progress.speeder[0].amount, 7_000);
        assert_eq!(progress.speeder[1].at, at_ms(1_000));
        assert_eq!(progress.speeder[1].amount, 2_000);
        assert_eq!(
            progress.current_speed(),
            1_000,
            "5000 bytes over the five seconds the ring spans"
        );
    }

    #[test]
    fn the_oldest_record_is_slot_zero_until_the_ring_fills() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));

        // Six records fill the ring exactly. Until the counter reaches six the
        // oldest is slot 0, so the window widens by a second each time.
        for second in 0..6_i64 {
            progress.download_inc(2_000, at_ms(second * 1_000));
            assert!(progress.calculate(at_ms(second * 1_000), false));
        }
        assert_eq!(progress.speeder_c, CURL_SPEED_RECORDS as u8);
        assert_eq!(progress.speeder[5].at, at_ms(5_000));
        assert_eq!(
            progress.current_speed(),
            2_000,
            "10000 bytes over five seconds"
        );
    }

    #[test]
    fn a_zero_duration_between_records_becomes_one_microsecond() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        assert!(progress.calculate(at_us(0), false));

        // Force two records at the SAME instant: the first is at the origin,
        // and the done-with-zero-speed path rewrites the latest one there too.
        progress.download_inc(3, at_us(0));
        assert!(progress.calculate(at_us(0), true));

        // With one record taken, the oldest and the latest are the SAME slot,
        // so the duration between them is zero and the floor turns it into one
        // microsecond. The guard exists to avoid a division by zero rather
        // than to be meaningful: the amount between a record and itself is
        // also zero, so the rate is 0 / 1us. What is being asserted is that
        // this returns a number at all.
        assert_eq!(progress.current_speed(), 0, "amount is zero: 0 / 1us");
        assert_eq!(progress.speeder[0].at, at_us(0));
        assert_eq!(progress.speeder[0].amount, 3, "the record was rewritten");
    }

    #[test]
    fn a_huge_amount_uses_the_floating_point_branch() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));

        // Two records a second apart whose difference exceeds
        // SPEED_OVERFLOW_LIMIT, which is the C's `amount > CURL_OFF_T_MAX /
        // 1000000` guard.
        progress.speeder[0] = super::SpeedRecord {
            amount: 0,
            at: at_us(0),
        };
        progress.speeder_c = 1;
        progress.dl.cur_size = SPEED_OVERFLOW_LIMIT + 1_000;

        assert!(progress.calculate(at_ms(1_000), false));

        // (amount * 1e6) / 1e6 in double arithmetic. The double has 53 bits of
        // mantissa and the amount needs 44, so the round trip is exact here.
        assert_eq!(progress.current_speed(), SPEED_OVERFLOW_LIMIT + 1_000);
    }

    #[test]
    fn the_floating_point_branch_saturates_rather_than_wrapping() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        progress.speeder[0] = super::SpeedRecord {
            amount: 0,
            at: at_us(0),
        };
        progress.speeder_c = 1;
        progress.dl.cur_size = i64::MAX;

        // i64::MAX bytes between the two records. In double arithmetic
        // `(double)i64::MAX` already rounds UP, to 2^63, so the quotient is
        // above the range of the integer it is cast back to. C's cast would be
        // undefined there; the `as` cast here truncates toward zero and
        // saturates at the bound.
        assert!(progress.calculate(at_ms(1_000), false));
        assert_eq!(progress.current_speed(), i64::MAX);
    }

    #[test]
    fn a_negative_amount_between_records_is_carried_through() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        progress.download_inc(5_000, at_us(0));
        assert!(progress.calculate(at_us(0), false));

        // A counter reset between two records makes the difference negative,
        // which is how `current_speed` can go below zero -- and why
        // `speedcheck` declines to judge one that has.
        progress.reset_transfer_sizes();
        progress.dl.cur_size = 1_000;
        assert!(progress.calculate(at_ms(1_000), false));
        assert_eq!(progress.current_speed(), -4_000);
    }

    #[test]
    fn the_record_counter_wraps_after_two_hundred_and_fifty_six() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));

        // 256 records, one a second. The 256th increment wraps the eight-bit
        // counter back to zero.
        for second in 0..256_i64 {
            progress.download_inc(1_000, at_ms(second * 1_000));
            assert!(progress.calculate(at_ms(second * 1_000), false));
        }
        assert_eq!(
            progress.speeder_c, 0,
            "wrapped, exactly as the uint8_t does"
        );

        // The next call therefore finds no record and takes the first-record
        // branch, reporting the whole-transfer average as the current speed
        // for one call. This is curl 8.x's behaviour and it is frozen.
        progress.download_inc(1_000, at_ms(256_000));
        assert!(progress.calculate(at_ms(256_000), false));
        assert_eq!(progress.speeder_c, 1);
        assert_eq!(progress.speeder[0].amount, 257_000);
        assert_eq!(
            progress.current_speed(),
            progress.speed_download() + progress.speed_upload()
        );
    }

    #[test]
    fn the_throttle_shows_at_most_once_per_record() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        assert!(progress.calculate(at_us(0), false), "the first call shows");

        // Four calls inside the same second, none of which shows.
        for offset_ms in [1, 250, 500, 999] {
            assert!(
                !progress.calculate(at_ms(offset_ms), false),
                "{offset_ms} ms is still inside the first second"
            );
        }
        // And the next second shows again.
        assert!(progress.calculate(at_ms(1_000), false));
        assert_eq!(progress.lastshow, at_ms(1_000).secs);

        // A finished request always shows, whatever the throttle says.
        assert!(progress.calculate(at_ms(1_100), true));
        assert!(progress.calculate(at_ms(1_100), true));
    }

    #[test]
    fn a_record_inside_an_already_shown_second_does_not_show_again() {
        // The throttle's second guard -- `lastshow == pnow->tv_sec` with a
        // record freshly made -- looks unreachable, because a record needs a
        // full second to pass and `lastshow` normally holds the second of the
        // latest record. It IS reachable, through the one path that advances
        // `lastshow` WITHOUT making a record: a finished request whose current
        // speed is already non-zero.
        let mut progress = Progress::default();
        progress.start_now(at_us(0));

        // One record at 900 ms, so its second is the origin's.
        assert!(progress.calculate(at_ms(900), false));
        assert_eq!(progress.speeder[0].at, at_ms(900));
        assert_eq!(progress.lastshow, ORIGIN_SECS);
        // A current speed, so the done path declines to rewrite the record.
        progress.current_speed = 5;

        // 1100 ms is 200 ms after the record, so no record is made -- yet the
        // request is done, so this shows and moves `lastshow` on a second.
        assert!(progress.calculate(at_ms(1_100), true));
        assert_eq!(progress.speeder_c, 1, "still one record");
        assert_eq!(progress.speeder[0].at, at_ms(900), "and it is unchanged");
        assert_eq!(progress.lastshow, ORIGIN_SECS + 1);

        // 1950 ms is 1050 ms after the record, so a record IS made -- but it
        // lands in the second that has already been shown, and the request is
        // no longer done, so the guard suppresses the redraw.
        assert!(!progress.calculate(at_ms(1_950), false));
        assert_eq!(progress.speeder_c, 2, "the record was still made");
        assert_eq!(progress.speeder[1].at, at_ms(1_950));
        assert_eq!(
            progress.lastshow,
            ORIGIN_SECS + 1,
            "and lastshow was left alone, so the next second still shows"
        );
    }

    #[test]
    fn update_nometer_calculates_and_invokes_nothing() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        progress.download_inc(2_048, at_us(0));

        progress.update_nometer(at_ms(1_000), false);

        assert_eq!(progress.total_time_us(), 1_000_000);
        assert_eq!(progress.speed_download(), 2_048);
        assert_eq!(progress.speeder_c, 1, "the history was still advanced");
    }

    // ---- the low-speed abort --------------------------------------------

    #[test]
    fn the_check_is_skipped_when_it_is_not_armed() {
        for limits in [
            LowSpeedLimit::default(),
            LowSpeedLimit::new(0, 5),
            LowSpeedLimit::new(100, 0),
        ] {
            let mut progress = Progress::default();
            let untouched = progress.clone();
            let outcome = progress
                .speedcheck(limits, Paused::NEITHER, at_ms(10))
                .expect("an unarmed check cannot fail");
            assert_eq!(outcome, SpeedCheck::Skipped, "{limits:?}");
            assert_eq!(outcome.arm_ms(), None, "and no timer is armed");
            assert_eq!(progress, untouched, "and nothing is written");
            assert!(!limits.is_armed());
        }
    }

    #[test]
    fn a_paused_transfer_is_not_qualified_for_a_speed_check() {
        let limits = LowSpeedLimit::new(1_000, 3);
        for paused in [
            Paused {
                recv: true,
                send: false,
            },
            Paused {
                recv: false,
                send: true,
            },
            Paused {
                recv: true,
                send: true,
            },
        ] {
            let mut progress = at_speed(1);
            let outcome = progress
                .speedcheck(limits, paused, at_ms(10))
                .expect("a paused check cannot fail");
            assert_eq!(outcome, SpeedCheck::Skipped, "{paused:?}");
            assert!(
                progress.keeps_speed.is_zero(),
                "the marker must not start while paused"
            );
            assert!(paused.either());
        }
        assert!(!Paused::NEITHER.either());
    }

    #[test]
    fn going_under_the_limit_starts_the_marker_and_arms_the_timer() {
        let limits = LowSpeedLimit::new(1_000, 3);
        let mut progress = at_speed(999);

        let outcome = progress
            .speedcheck(limits, Paused::NEITHER, at_ms(500))
            .expect("the window has not expired");

        assert_eq!(
            outcome,
            SpeedCheck::Expire {
                in_ms: SPEEDCHECK_EXPIRE_MS
            }
        );
        assert_eq!(outcome.arm_ms(), Some(1_000));
        assert_eq!(progress.keeps_speed, at_ms(500));
    }

    #[test]
    fn one_millisecond_below_the_window_still_passes() {
        let limits = LowSpeedLimit::new(1_000, 3);
        let mut progress = at_speed(0);
        let _ = progress
            .speedcheck(limits, Paused::NEITHER, at_ms(0))
            .expect("the marker is only started here");

        // 2_999 ms under the limit, one millisecond short of the window.
        let outcome = progress
            .speedcheck(limits, Paused::NEITHER, at_ms(2_999))
            .expect("2999 ms is less than 3 * 1000");
        assert_eq!(
            outcome,
            SpeedCheck::Expire {
                in_ms: SPEEDCHECK_EXPIRE_MS
            }
        );
        assert_eq!(
            progress.keeps_speed,
            at_ms(0),
            "the marker is NOT restarted while it is still running"
        );
    }

    #[test]
    fn exactly_the_window_times_out_with_the_frozen_message() {
        let limits = LowSpeedLimit::new(1_000, 3);
        let mut progress = at_speed(0);
        let _ = progress
            .speedcheck(limits, Paused::NEITHER, at_ms(0))
            .expect("the marker is started here");

        let error = progress
            .speedcheck(limits, Paused::NEITHER, at_ms(3_000))
            .expect_err("the comparison is `>=`, so the boundary fails");

        assert_eq!(error.code(), CURLcode::OperationTimedout);
        assert_eq!(
            error.message(),
            "Operation too slow. Less than 1000 bytes/sec transferred the \
             last 3 seconds"
        );
    }

    #[test]
    fn recovering_clears_the_marker() {
        let limits = LowSpeedLimit::new(1_000, 3);
        let mut progress = at_speed(10);
        let _ = progress
            .speedcheck(limits, Paused::NEITHER, at_ms(0))
            .expect("under the limit, so the marker starts");
        assert_eq!(progress.keeps_speed, at_ms(0));

        // At or above the limit is "faster right now".
        progress.current_speed = 1_000;
        let outcome = progress
            .speedcheck(limits, Paused::NEITHER, at_ms(1_000))
            .expect("a recovered transfer does not fail");
        assert_eq!(
            outcome,
            SpeedCheck::Expire {
                in_ms: SPEEDCHECK_EXPIRE_MS
            }
        );
        assert_eq!(
            progress.keeps_speed.secs, 0,
            "only the SECONDS field is cleared, exactly as the C does"
        );

        // And the window starts again from scratch, so a long slow stretch
        // followed by a recovery cannot fail on the old marker.
        progress.current_speed = 0;
        let _ = progress
            .speedcheck(limits, Paused::NEITHER, at_ms(9_000))
            .expect("the marker restarts here");
        assert_eq!(progress.keeps_speed, at_ms(9_000));
    }

    #[test]
    fn a_negative_current_speed_is_not_judged_but_still_arms_the_timer() {
        let limits = LowSpeedLimit::new(1_000, 3);
        let mut progress = at_speed(-1);

        let outcome = progress
            .speedcheck(limits, Paused::NEITHER, at_ms(10))
            .expect("an unjudged check cannot fail");

        assert_eq!(
            outcome,
            SpeedCheck::Expire {
                in_ms: SPEEDCHECK_EXPIRE_MS
            }
        );
        assert!(
            progress.keeps_speed.is_zero(),
            "a bookkeeping artefact must not start the abort window"
        );
    }

    // ---- the callback contract ------------------------------------------

    #[test]
    fn the_modern_callback_receives_the_byte_counts() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        progress.set_download_size(4_096);
        progress.set_upload_size(512);
        progress.download_inc(1_024, at_us(0));
        progress.upload_inc(256, at_us(0));
        let mut host = Recorder::modern(CURL_PROGRESSFUNC_CONTINUE);

        let meter = progress
            .update(at_ms(100), false, &mut host)
            .expect("CONTINUE is not an abort");

        assert_eq!(meter, Meter::Draw, "CONTINUE falls through to the meter");
        assert!(meter.should_draw());
        assert_eq!(host.calls(), 1);
        assert_eq!(
            host.modern[0],
            ProgressSnapshot {
                dl_total: 4_096,
                dl_now: 1_024,
                ul_total: 512,
                ul_now: 256,
            }
        );
        assert!(
            host.legacy.is_empty(),
            "the legacy callback was not reached"
        );
    }

    #[test]
    fn the_legacy_callback_receives_the_same_counts_as_doubles() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        progress.set_download_size(4_096);
        progress.set_upload_size(512);
        progress.download_inc(1_024, at_us(0));
        progress.upload_inc(256, at_us(0));
        let mut host = Recorder::legacy(CURL_PROGRESSFUNC_CONTINUE);

        let meter = progress
            .update(at_ms(100), false, &mut host)
            .expect("CONTINUE is not an abort");

        assert_eq!(meter, Meter::Draw);
        assert_eq!(host.calls(), 1);
        assert!(host.modern.is_empty());
        // The ABI order: dltotal, dlnow, ultotal, ulnow.
        assert_eq!(host.legacy[0], [4_096.0, 1_024.0, 512.0, 256.0]);
    }

    #[test]
    fn zero_suppresses_the_meter_without_aborting() {
        for mut host in [Recorder::modern(0), Recorder::legacy(0)] {
            let mut progress = Progress::default();
            progress.start_now(at_us(0));

            let meter = progress
                .update(at_ms(100), false, &mut host)
                .expect("zero means handled, not aborted");

            assert_eq!(
                meter,
                Meter::Skip,
                "a callback that handled the update takes the meter's place"
            );
            assert!(!meter.should_draw());
            assert_eq!(host.calls(), 1);
        }
    }

    #[test]
    fn any_other_return_aborts_the_transfer() {
        for result in [1, -1, 42, i32::MIN, i32::MAX] {
            for mut host in [Recorder::modern(result), Recorder::legacy(result)]
            {
                let mut progress = Progress::default();
                progress.start_now(at_us(0));

                let error = progress
                    .update(at_ms(100), false, &mut host)
                    .expect_err("a non-zero, non-CONTINUE return aborts");

                assert_eq!(error.code(), CURLcode::AbortedByCallback);
                assert_eq!(error.message(), CALLBACK_ABORTED);
                assert_eq!(error.message(), "Callback aborted");
            }
        }
    }

    #[test]
    fn the_in_callback_flag_is_set_during_and_cleared_after() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        let mut host = Recorder::modern(CURL_PROGRESSFUNC_CONTINUE);

        let _ = progress
            .update(at_ms(100), false, &mut host)
            .expect("CONTINUE is not an abort");

        assert_eq!(host.flag_inside, vec![true], "set DURING the call");
        assert_eq!(host.transitions, vec![true, false], "and cleared after");
        assert!(!host.in_callback);
    }

    #[test]
    fn the_flag_is_cleared_after_an_abort_too() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        let mut host = Recorder::modern(7);

        let _ = progress
            .update(at_ms(100), false, &mut host)
            .expect_err("7 aborts");

        assert!(
            !host.in_callback,
            "the guard runs before the error is built, not after"
        );
        assert_eq!(host.transitions, vec![true, false]);
    }

    #[test]
    fn the_guard_clears_the_flag_when_it_is_dropped() {
        let mut host = Recorder::silent();
        {
            let mut guard = CallbackGuard::enter(&mut host);
            assert_eq!(
                guard.call(
                    CallbackFlavour::XferInfo,
                    &ProgressSnapshot::default()
                ),
                0,
                "a silent recorder returns its programmed zero"
            );
        }
        assert!(!host.in_callback);
        assert_eq!(host.transitions, vec![true, false]);
    }

    #[test]
    fn the_flag_is_cleared_even_when_the_callback_unwinds() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        let mut host = Exploding::default();

        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                progress.update(at_ms(100), false, &mut host)
            }));

        assert!(outcome.is_err(), "the callback panicked");
        assert!(
            !host.in_callback,
            "Drop is what makes the bracket hold across an unwind"
        );
    }

    #[test]
    fn hidden_progress_calls_no_callback_and_draws_nothing() {
        let mut progress = Progress::default();
        progress.set_hide(true);
        assert!(progress.hide());
        progress.start_now(at_us(0));
        let mut host = Recorder::modern(1);

        let meter = progress
            .update(at_ms(100), false, &mut host)
            .expect("a hidden update cannot abort, because nothing is called");

        assert_eq!(meter, Meter::Skip);
        assert_eq!(host.calls(), 0);
        assert!(host.transitions.is_empty(), "the flag was never touched");
        // The accounting still happened: hiding suppresses reporting, not
        // measurement.
        assert_eq!(progress.total_time_us(), 100_000);
        assert_eq!(progress.speeder_c, 1);
    }

    #[test]
    fn a_handle_with_no_callback_reaches_the_meter_directly() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        let mut host = NoProgressCallback;

        assert_eq!(
            progress
                .update(at_ms(100), false, &mut host)
                .expect("nothing can abort"),
            Meter::Draw
        );
        assert_eq!(host.flavour(), None);
        // Throttled now, and still no callback to change the answer.
        assert_eq!(
            progress
                .update(at_ms(200), false, &mut host)
                .expect("nothing can abort"),
            Meter::Skip
        );
    }

    #[test]
    fn the_absent_callback_is_a_defined_no_op_rather_than_a_panic() {
        let mut host = NoProgressCallback;
        let snapshot = ProgressSnapshot::default();
        host.set_in_callback(true);
        host.set_in_callback(false);
        assert_eq!(host.xferinfo(&snapshot), CURL_PROGRESSFUNC_CONTINUE);
        assert_eq!(host.progress(&snapshot), CURL_PROGRESSFUNC_CONTINUE);
        assert_eq!(host, NoProgressCallback, "a unit struct has one value");
        assert_eq!(host.flavour(), None, "and it installs no callback");
    }

    #[test]
    fn the_direction_accessors_agree_with_the_curlinfo_ones() {
        let progress = pinned_transfer();

        // Two views of the same four fields: `easy/getinfo.rs` reads the
        // `CURLINFO`-named accessors, while the transfer loop and the meter
        // reach a whole direction. They must not be able to disagree.
        assert_eq!(progress.download().cur_size(), progress.size_download());
        assert_eq!(progress.upload().cur_size(), progress.size_upload());
        assert_eq!(progress.download().speed(), progress.speed_download());
        assert_eq!(progress.upload().speed(), progress.speed_upload());
        assert_eq!(
            progress.download().total_size(),
            progress.content_length_download(),
            "equal only because this transfer's length is KNOWN"
        );
        assert_eq!(
            progress.upload().total_size(),
            progress.content_length_upload()
        );
        // And the limiters are reachable but unengaged: nothing set a rate.
        assert!(!progress.download().rlimit().is_active());
        assert!(!progress.upload().rlimit().is_active());
    }

    #[test]
    fn the_callback_is_reachable_through_a_trait_object() {
        // The `?Sized` bound is what makes this compile, and a boxed callback
        // is what the transfer loop will actually hold.
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        let mut host = Recorder::modern(CURL_PROGRESSFUNC_CONTINUE);
        let erased: &mut dyn ProgressCallback = &mut host;

        assert_eq!(
            progress
                .update(at_ms(100), false, erased)
                .expect("CONTINUE is not an abort"),
            Meter::Draw
        );
        assert_eq!(host.calls(), 1);
    }

    // ---- check and done --------------------------------------------------

    #[test]
    fn check_runs_the_speed_check_only_while_the_request_is_unfinished() {
        let limits = LowSpeedLimit::new(1_000, 3);
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        let mut host = NoProgressCallback;

        let outcome = progress
            .check(at_ms(100), false, limits, Paused::NEITHER, &mut host)
            .expect("neither half fails");
        assert_eq!(
            outcome,
            Check {
                meter: Meter::Draw,
                speedcheck: SpeedCheck::Expire {
                    in_ms: SPEEDCHECK_EXPIRE_MS
                },
            }
        );
        assert_eq!(progress.keeps_speed, at_ms(100), "the marker started");

        // A finished request is not checked at all: a transfer that has just
        // delivered its last byte must not be aborted for going quiet.
        let mut finished = Progress::default();
        finished.start_now(at_us(0));
        let outcome = finished
            .check(at_ms(100), true, limits, Paused::NEITHER, &mut host)
            .expect("neither half fails");
        assert_eq!(outcome.speedcheck, SpeedCheck::Skipped);
        assert!(finished.keeps_speed.is_zero());
    }

    #[test]
    fn a_failed_update_short_circuits_the_speed_check() {
        let limits = LowSpeedLimit::new(1_000, 3);
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        let mut host = Recorder::modern(3);

        let error = progress
            .check(at_ms(100), false, limits, Paused::NEITHER, &mut host)
            .expect_err("the callback aborted");

        assert_eq!(error.code(), CURLcode::AbortedByCallback);
        assert!(
            progress.keeps_speed.is_zero(),
            "`if(!result && !data->req.done)` never reached the check"
        );
    }

    #[test]
    fn check_propagates_the_low_speed_timeout() {
        let limits = LowSpeedLimit::new(1_000, 1);
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        progress.keeps_speed = at_ms(0);
        let mut host = NoProgressCallback;

        let error = progress
            .check(at_ms(1_000), false, limits, Paused::NEITHER, &mut host)
            .expect_err("a full second under the limit");
        assert_eq!(error.code(), CURLcode::OperationTimedout);
    }

    #[test]
    fn done_forces_a_final_update_and_asks_for_the_newline() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        let mut host = NoProgressCallback;

        // A shown update inside the current second, so that the throttle would
        // suppress an ordinary second call.
        assert_eq!(
            progress
                .update(at_ms(100), false, &mut host)
                .expect("nothing aborts"),
            Meter::Draw
        );
        assert_eq!(
            progress
                .update(at_ms(200), false, &mut host)
                .expect("nothing aborts"),
            Meter::Skip,
            "throttled, as expected"
        );

        let outcome = progress
            .done(at_ms(300), true, &mut host)
            .expect("nothing aborts");

        assert_eq!(
            outcome,
            Done {
                meter: Meter::Draw,
                write_newline: true,
            },
            "zeroing lastshow is what forces the final row through"
        );
    }

    #[test]
    fn done_withholds_the_newline_when_hidden_or_delegated() {
        // Hidden: the meter never wrote a line, so there is nothing to
        // terminate.
        let mut hidden = Progress::default();
        hidden.set_hide(true);
        hidden.start_now(at_us(0));
        let mut host = NoProgressCallback;
        assert_eq!(
            hidden
                .done(at_ms(10), true, &mut host)
                .expect("nothing aborts"),
            Done {
                meter: Meter::Skip,
                write_newline: false,
            }
        );

        // Delegated: a callback drew whatever it liked, and libcurl must not
        // append to it.
        let mut delegated = Progress::default();
        delegated.start_now(at_us(0));
        delegated.set_uses_callback(true);
        assert!(delegated.uses_callback());
        let mut recorder = Recorder::modern(CURL_PROGRESSFUNC_CONTINUE);
        assert_eq!(
            delegated
                .done(at_ms(10), true, &mut recorder)
                .expect("CONTINUE is not an abort"),
            Done {
                meter: Meter::Draw,
                write_newline: false,
            }
        );
    }

    #[test]
    fn a_failed_final_update_reports_no_newline_at_all() {
        let mut progress = Progress::default();
        progress.start_now(at_us(0));
        let mut host = Recorder::modern(9);

        let error = progress
            .done(at_ms(10), true, &mut host)
            .expect_err("9 aborts");

        assert_eq!(error.code(), CURLcode::AbortedByCallback);
        // The C returns at `:196-197`, BEFORE the newline write at `:199-202`.
        // Returning `Result<Done, _>` makes that structural rather than a flag
        // the caller has to remember to check: there is no `Done` to read a
        // newline decision out of.
        assert!(!host.in_callback, "the bracket still closed");
        assert_eq!(
            progress.total_time_us(),
            10_000,
            "the accounting ran before the callback did"
        );
    }

    // ---- the CURLINFO surface -------------------------------------------

    #[test]
    fn every_required_curlinfo_accessor_reports_its_field() {
        let progress = pinned_transfer();

        // Every `CURLINFO_*_T` value `lib/getinfo.c:417-462` reads out of
        // `struct Progress`, with the number the pinned schedule produces.
        let table: [(&str, fn(&Progress) -> i64, i64); 15] = [
            ("CURLINFO_SIZE_DOWNLOAD_T", Progress::size_download, 4_096),
            ("CURLINFO_SIZE_UPLOAD_T", Progress::size_upload, 512),
            ("CURLINFO_SPEED_DOWNLOAD_T", Progress::speed_download, 4_137),
            ("CURLINFO_SPEED_UPLOAD_T", Progress::speed_upload, 517),
            ("CURLINFO_TOTAL_TIME_T", Progress::total_time_us, 990_000),
            (
                "CURLINFO_NAMELOOKUP_TIME_T",
                Progress::namelookup_time_us,
                25_000,
            ),
            ("CURLINFO_CONNECT_TIME_T", Progress::connect_time_us, 55_000),
            (
                "CURLINFO_APPCONNECT_TIME_T",
                Progress::appconnect_time_us,
                95_000,
            ),
            (
                "CURLINFO_PRETRANSFER_TIME_T",
                Progress::pretransfer_time_us,
                105_000,
            ),
            (
                "CURLINFO_STARTTRANSFER_TIME_T",
                Progress::starttransfer_time_us,
                190_000,
            ),
            (
                "CURLINFO_POSTTRANSFER_TIME_T",
                Progress::posttransfer_time_us,
                990_000,
            ),
            ("CURLINFO_QUEUE_TIME_T", Progress::queue_time_us, 15_000),
            (
                "CURLINFO_REDIRECT_TIME_T",
                Progress::redirect_time_us,
                990_000,
            ),
            (
                "CURLINFO_CONTENT_LENGTH_DOWNLOAD_T",
                Progress::content_length_download,
                4_096,
            ),
            (
                "CURLINFO_CONTENT_LENGTH_UPLOAD_T",
                Progress::content_length_upload,
                512,
            ),
        ];

        for (info, read, expected) in table {
            assert_eq!(read(&progress), expected, "{info}");
        }

        // Not a `CURLINFO` value, and asserted here so that the distinction is
        // recorded: the current speed is the five-second figure while
        // `CURLINFO_SPEED_*_T` is the whole-transfer average.
        assert_eq!(progress.current_speed(), 4_137 + 517);
    }

    #[test]
    fn a_getinfo_read_does_not_perturb_the_transfer() {
        let progress = pinned_transfer();
        let before = progress.clone();

        let _ = progress.size_download();
        let _ = progress.size_upload();
        let _ = progress.speed_download();
        let _ = progress.speed_upload();
        let _ = progress.total_time_us();
        let _ = progress.namelookup_time_us();
        let _ = progress.connect_time_us();
        let _ = progress.appconnect_time_us();
        let _ = progress.pretransfer_time_us();
        let _ = progress.posttransfer_time_us();
        let _ = progress.starttransfer_time_us();
        let _ = progress.queue_time_us();
        let _ = progress.redirect_time_us();
        let _ = progress.content_length_download();
        let _ = progress.content_length_upload();
        let _ = progress.current_speed();
        let _ = progress.early_data_sent();
        let _ = progress.start();
        let _ = progress.start_single();
        let _ = progress.start_op();
        let _ = progress.accept_data();
        let _ = progress.snapshot();
        let _ = progress.meter_snapshot();
        let _ = progress.headers_shown();
        let _ = progress.hide();
        let _ = progress.uses_callback();
        let _ = progress.download().rlimit();
        let _ = progress.upload().rlimit();

        assert_eq!(progress, before, "curl_easy_getinfo is a pure read");
    }

    // ---- the snapshots ---------------------------------------------------

    #[test]
    fn the_meter_snapshot_carries_every_value_the_renderer_reads() {
        let progress = pinned_transfer();

        assert_eq!(
            progress.meter_snapshot(),
            MeterSnapshot {
                timespent: 990_000,
                dl_total: 4_096,
                dl_cur: 4_096,
                dl_speed: 4_137,
                dl_size_known: true,
                ul_total: 512,
                ul_cur: 512,
                ul_speed: 517,
                ul_size_known: true,
                current_speed: 4_654,
                headers_out: false,
            }
        );
    }

    #[test]
    fn the_heading_flag_is_recorded_for_the_renderer() {
        let mut progress = Progress::default();
        assert!(!progress.headers_shown());
        assert!(!progress.meter_snapshot().headers_out);
        progress.mark_headers_shown();
        assert!(progress.headers_shown());
        assert!(progress.meter_snapshot().headers_out);
        // Idempotent: the C never clears it within a transfer.
        progress.mark_headers_shown();
        assert!(progress.headers_shown());
    }

    #[test]
    fn an_unknown_total_reaches_the_callback_as_zero() {
        let mut progress = Progress::default();
        progress.download_inc(64, at_us(0));
        progress.upload_inc(32, at_us(0));

        // No size was ever set, so both flags are false.
        assert_eq!(progress.content_length_download(), -1);
        assert_eq!(progress.content_length_upload(), -1);
        // The callback, however, sees the raw field, which is zero. The two
        // answers differ on purpose and both are frozen.
        let snapshot = progress.snapshot();
        assert_eq!(
            snapshot,
            ProgressSnapshot {
                dl_total: 0,
                dl_now: 64,
                ul_total: 0,
                ul_now: 32,
            }
        );
        assert_eq!(snapshot.dl_total_f64(), 0.0);
        assert_eq!(snapshot.dl_now_f64(), 64.0);
        assert_eq!(snapshot.ul_total_f64(), 0.0);
        assert_eq!(snapshot.ul_now_f64(), 32.0);
    }

    // ---- extremes --------------------------------------------------------

    #[test]
    fn a_long_transfer_of_a_huge_amount_never_panics() {
        let mut progress = Progress::default();
        progress.start_now(CurlTime::new(i64::MIN / 2, 0));

        // A span that saturates `timediff_us`, byte counters at their ceiling,
        // and a finished request, all at once. The assertion is that every
        // operation returns.
        progress.dl.cur_size = i64::MAX;
        progress.ul.cur_size = i64::MAX;
        progress.set_download_size(i64::MAX);
        progress.set_upload_size(i64::MAX);
        let _ = progress.calculate(CurlTime::new(i64::MAX / 2, 999_999), true);
        let _ = progress.calculate(CurlTime::new(i64::MAX / 2, 999_999), true);

        // And the counters cannot be pushed past their ceiling either.
        progress.download_inc(usize::MAX, CurlTime::new(0, 0));
        progress.upload_inc(usize::MAX, CurlTime::new(0, 0));
        assert_eq!(progress.size_download(), i64::MAX);
        assert_eq!(progress.size_upload(), i64::MAX);

        // Every timer label, against a timestamp far in the past.
        for label in TimerId::VARIANTS {
            progress.time_was(label, CurlTime::new(i64::MIN / 2, 0));
        }
        // The accumulators saturate rather than wrapping into a negative time.
        progress.t_nslookup = i64::MAX;
        progress.time_was(TimerId::StartSingle, CurlTime::new(0, 0));
        progress.time_was(TimerId::NameLookup, CurlTime::new(1_000, 0));
        assert_eq!(progress.namelookup_time_us(), i64::MAX);
    }

    #[test]
    fn a_saturating_span_is_reported_rather_than_wrapped() {
        let mut progress = Progress::default();
        progress.start_now(CurlTime::new(i64::MIN, 0));
        let _ = progress.calculate(CurlTime::new(i64::MAX, 0), false);
        assert_eq!(
            progress.total_time_us(),
            i64::MAX,
            "timediff_us saturates, and the value is carried through"
        );
    }
}
