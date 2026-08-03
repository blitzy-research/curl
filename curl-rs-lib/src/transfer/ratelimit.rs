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
//! The token bucket behind `--limit-rate` -- supersedes `lib/ratelimit.c`
//! (289 lines) and `lib/ratelimit.h` (107).
//!
//! Three public options are served by this one primitive, and by nothing
//! else in the crate:
//!
//! * `CURLOPT_MAX_RECV_SPEED_LARGE`, applied to the download direction;
//! * `CURLOPT_MAX_SEND_SPEED_LARGE`, applied to the upload direction;
//! * `--limit-rate`, which the command-line tool implements by setting both
//!   of the above to the same value.
//!
//! `lib/setopt.c:2793-2813` is where the two options land, and it calls
//! `Curl_rlimit_init(&data->progress.{ul,dl}.rlimit, offt, offt, ...)` --
//! burst equal to rate, which per `lib/ratelimit.h:45-47` makes a transfer
//! "always try to stay *at/below* the rate" so that idle periods do not
//! bank tokens for a later burst.
//!
//! # What a token bucket is, in curl's words
//!
//! `lib/ratelimit.h:30-55` states the contract, and the worked example is
//! worth keeping because it fixes the semantics of every method below. For a
//! rate limit of one megabyte per second:
//!
//! * initially one million tokens are available;
//! * they are drained in the first second;
//! * asking for available tokens before the second second returns 0;
//! * at or after the second second, one million tokens are available again;
//! * after a second of inactivity the million would grow to two million,
//!   except that a burst limit of 1.5 million caps them there.
//!
//! Two consequences of the burst cap, both from the same passage: a burst of
//! `CURL_OFF_T_MAX` averages the rate over the whole transfer, so that the
//! average from start to finish is the rate limit; a burst equal to the rate
//! keeps the transfer at or below the rate at all times.
//!
//! A limiter may also be BLOCKED, which makes available tokens always 0
//! until it is unblocked, and unblocking restarts the limiting with no
//! history of the past. A limiter whose rate is 0 always has
//! [`i64::MAX`] tokens available, unless it is blocked.
//!
//! # Timing is preserved deliberately, not approximated
//!
//! This is a faithful transcription and not a re-derivation.
//! Specification 0.1.1 makes performance an explicit non-goal and states
//! that where a choice exists between a faster design and a more
//! behaviourally faithful one, faithfulness wins; specification 0.8.1 freezes
//! observable behaviour outright. For this module that has three concrete
//! consequences:
//!
//! 1. **No floating point.** Every quotient below truncates toward zero and
//!    every millisecond conversion is the `(x + 999) / 1000` ceiling the C
//!    writes. A floating-point reformulation would move a wait by a
//!    millisecond here and there, and a millisecond is observable: it is the
//!    argument to the expiry timer that decides when a transfer next runs.
//! 2. **No general-purpose rate-limiting crate.** The step-tuning algorithm
//!    of [`RateLimit::start`] deliberately makes the LAST step of a transfer
//!    small, which changes completion timing for small transfers. A smoother
//!    or fairer algorithm is a different algorithm, and different timing is
//!    a defect here rather than an improvement.
//! 3. **The integer boundaries are transcribed, including the odd ones.**
//!    Where the C compares with `>` rather than `>=`, so does this module;
//!    where the C saturates in a direction that looks counterintuitive --
//!    [`RateLimit::drain`] has one such branch -- the shipped behaviour is
//!    reproduced and the oddity is documented at the site.
//!
//! # What this module does NOT do
//!
//! It computes durations. It does not wait, and it does not know what a
//! transfer state is:
//!
//! * **No timer is scheduled here.** There is no `tokio::time` import and no
//!   sleep. [`RateLimit::wait_ms`] and [`RateLimit::next_step_ms`] return
//!   exact millisecond counts, and the caller arms the expiry timer.
//! * **No transfer state is touched here.** The `PERFORMING` and
//!   `RATELIMITING` transitions and the `TOOFAST` expiry identifier belong to
//!   the transfer loop; this module never names them. [`RateLimit`] is a
//!   plain owned value with no reference to a handle, which is what keeps it
//!   testable without a network, a runtime or a clock.
//! * **No clock is read here.** Every method that needs the current instant
//!   takes it as a [`CurlTime`] parameter, exactly as the C takes a
//!   `const struct curltime *`. `Instant::now` and `SystemTime::now` appear
//!   nowhere in this file; `crate::util::timeval` is the crate's only clock
//!   seam.
//!
//! The orchestration those three bullets refer to is spelled out under
//! [`RateLimit::wait_ms`] and [`RateLimit::next_step_ms`], transcribed from
//! `lib/multi.c:1880-1921`, so that whoever writes the transfer loop has the
//! contract in front of them rather than having to rediscover it.
//!
//! # Where this sits in the dependency order
//!
//! Downwards only. This module imports [`CurlTime`] and [`timediff_us`] from
//! `crate::util::timeval` and [`TimeDiff`] from `crate::util::timediff`, and
//! nothing else -- no sibling in `transfer/`, no protocol, no connection, no
//! TLS.
//!
//! The direction of the coupling with progress accounting is fixed by the C
//! and is worth stating because it is easy to invert: `lib/urldata.h:788-793`
//! declares `struct pgrs_dir { curl_off_t total_size; curl_off_t cur_size;
//! curl_off_t speed; struct Curl_rlimit rlimit; }`, so the progress
//! structure EMBEDS the limiter. Progress accounting will therefore hold a
//! [`RateLimit`]; this module will never hold a progress structure.
//! [`RateLimit`] implements [`Default`] for exactly that reason, as the
//! successor of the calloc-zeroed state a fresh easy handle starts in.

use crate::util::timediff::TimeDiff;
use crate::util::timeval::{timediff_us, CurlTime};

/// Microseconds in a second -- `CURL_US_PER_SEC` of `lib/ratelimit.c:29`.
///
/// The initial step duration, and the base that [`RateLimit::start`]'s
/// tuning adjusts. `lib/ratelimit.c:118` asserts that a limiter about to be
/// tuned still has exactly this step, which is why the value appears both as
/// the initial step in [`RateLimit::new`] and as the assertion in
/// [`RateLimit::tune_steps`].
const CURL_US_PER_SEC: TimeDiff = 1_000_000;

/// The largest number of tokens the final step may be given --
/// `CURL_RLIMIT_MIN_RATE` of `lib/ratelimit.c:30`, whose comment reads
/// "minimum step rate".
///
/// Written `4 * 1024` rather than `4096` because that is how the C spells
/// it. The name says "minimum rate" while the only use, at
/// `lib/ratelimit.c:110-111`, is an upper bound on the last step's token
/// count; the two readings agree, because capping the last step's tokens is
/// what stops the tuned main rate from falling below this floor.
const CURL_RLIMIT_MIN_RATE: i64 = 4 * 1024;

/// The shortest step duration tuning will produce, in milliseconds --
/// `CURL_RLIMIT_STEP_MIN_MS` of `lib/ratelimit.c:31`.
///
/// A transfer that would need fewer than two millisteps is left untuned:
/// `lib/ratelimit.c:121-124` says "Steps this small will not work."
const CURL_RLIMIT_STEP_MIN_MS: i64 = 2;

/// Milliseconds in a second, and microseconds in a millisecond.
///
/// One value, two quantities, and the C spells both as a bare `1000` -- at
/// `lib/ratelimit.c:120` it scales tokens into millisteps, at `:128` and
/// `:141` it converts millisteps into microseconds, and at `:253` and `:265`
/// it reduces microseconds to milliseconds. A single named constant is used
/// for all of them because they are numerically the same and separating them
/// would suggest they could diverge.
const MILLI: i64 = 1_000;

/// Millisteps in one step: the `1000` that `lib/ratelimit.c:125-137` compares
/// and divides `msteps` against.
///
/// Distinct from [`MILLI`] in meaning even though the two are equal. This one
/// is "how many millisteps make a whole step", so it is the threshold below
/// which a whole transfer fits inside a single shortened step.
const MSTEPS_PER_STEP: i64 = 1_000;

/// One hundred, as a percentage denominator.
///
/// Used twice, and for two different purposes that must not be conflated:
/// `lib/ratelimit.c:107` takes one percent of the total token count as the
/// last step's budget, and `:244-246` converts a negative token balance into
/// a percentage of a step's worth of debt.
const PERCENT: i64 = 100;

/// The rounding addend of the microsecond-to-millisecond ceiling: the `999`
/// of `lib/ratelimit.c:253` and `:265`.
///
/// `(x + 999) / 1000` is the ceiling of a NON-NEGATIVE quotient, which is the
/// only case either site can reach: both divide a strictly positive duration.
/// One microsecond therefore becomes one millisecond rather than zero, which
/// matters because a zero return from [`RateLimit::wait_ms`] means "do not
/// wait at all" and would spin the transfer loop.
const CEIL_ADDEND: i64 = MILLI - 1;

/// A token bucket for one direction of one transfer -- the successor of
/// `struct Curl_rlimit` (`lib/ratelimit.h:57-65`).
///
/// # Field mapping
///
/// | C field | Here | Meaning |
/// |---|---|---|
/// | `int64_t rate_per_step` | `rate_per_step` | tokens generated per step |
/// | `int64_t burst_per_step` | `burst_per_step` | cap on tokens, 0 for none |
/// | `timediff_t step_us` | `step_us` | microseconds between token increases |
/// | `int64_t tokens` | `tokens` | tokens available, MAY BE NEGATIVE |
/// | `timediff_t spare_us` | `spare_us` | microseconds not yet a whole step |
/// | `struct curltime ts` | `ts` | the last update's timestamp |
/// | `BIT(blocked)` | `blocked` | blocking pins available tokens to 0 |
///
/// The two integer widths are the C's, kept apart on purpose: token counts
/// are `int64_t` in C and [`i64`] here, while durations are `timediff_t` in C
/// and [`TimeDiff`] here. They are the same 64-bit signed integer on all four
/// mandated targets -- so is `curl_off_t`, which is what `lib/ratelimit.c`
/// uses for the intermediates at `:136-139` and `:244` -- and the distinction
/// is documentation rather than type safety. It is kept because a token count
/// and a microsecond count appear on opposite sides of the same
/// multiplication in [`Self::wait_ms`], and mixing them up there produces a
/// plausible-looking wait that is wrong by a factor of a thousand.
///
/// # The fields are private, unlike the C's
///
/// In C every field of `struct Curl_rlimit` is reachable from anywhere that
/// includes `ratelimit.h`, and only `ratelimit.c` touches them by
/// convention. Here that convention is enforced: the invariants below are
/// upheld by the methods, and a caller that could write `tokens` directly
/// could break all of them.
///
/// # Invariants
///
/// * `0 <= spare_us < step_us` whenever `step_us > 0`. Established by
///   [`Self::update`], which stores the remainder of a division by
///   `step_us`, and reset to 0 by [`Self::new`] and [`Self::start`].
/// * `step_us > 0` whenever `rate_per_step != 0`. [`Self::new`] sets
///   `step_us` to [`CURL_US_PER_SEC`] and tuning only ever lengthens or
///   shortens it within `[2000, 1_999_000]`. The one state with a zero step
///   is [`Default`], where the rate is zero as well and no method divides by
///   it -- see [`Self::update`], which guards the division anyway rather
///   than resting on that argument.
/// * `tokens` is unbounded below. A drain may take a limiter into debt, and
///   the debt is what [`Self::wait_ms`] converts into a wait. Clamping it to
///   zero would let a transfer that overshot its budget escape the
///   corresponding wait, which is precisely the averaging the option
///   promises.
///
/// # Neither [`Copy`] nor a shared reference
///
/// [`Copy`] is deliberately not derived even though every field is a scalar
/// and the whole structure is about 60 bytes. This is mutable state: three of
/// the query methods mutate through `&mut self` because the C's do, and an
/// accidental copy -- `let mut r = dir.rlimit;` -- would drain the copy and
/// silently leave the original unthrottled. [`Clone`] is derived, because an
/// explicit clone is exactly what a test needs in order to assert that a call
/// left the limiter untouched.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct RateLimit {
    /// Tokens generated per step. Zero means unlimited, and it is the value
    /// every other method tests to decide whether limiting applies at all.
    rate_per_step: i64,
    /// The cap on banked tokens, or zero for no cap. Applied only by
    /// [`Self::update`], and only when tokens exceed it.
    burst_per_step: i64,
    /// Microseconds between token increases. One second until
    /// [`Self::start`] tunes it.
    step_us: TimeDiff,
    /// Tokens available to spend. Negative means the transfer has spent more
    /// than its budget and owes the difference.
    tokens: i64,
    /// Microseconds already elapsed that have not yet become a whole step.
    /// Carried across updates so that repeated sub-step calls accumulate
    /// exactly rather than being rounded away one at a time.
    spare_us: TimeDiff,
    /// The timestamp of the last update, moved only by a COMPLETE update.
    ts: CurlTime,
    /// Blocking pins available tokens to 0 until it is lifted. This is how a
    /// paused transfer is represented, and it is kept distinct from token
    /// debt: a pause is a caller's decision, while debt is arithmetic.
    blocked: bool,
}

/// `value` narrowed back to [`i64`], saturating at either bound.
///
/// Three products in `lib/ratelimit.c` can leave the range of a signed 64-bit
/// integer for inputs a caller can actually supply -- `(-r->tokens) * 100` at
/// `:244`, `r->step_us * debt_pct` at `:246`, and
/// `r->rate_per_step * mstep_inc` at `:139`. In C that is undefined
/// behaviour; in a debug Rust build it is a panic, and this module must
/// never panic on a value the ABI accepts.
///
/// Each of those products is therefore computed in [`i128`], where it is
/// EXACT for every 64-bit input, and brought back through this function.
/// Widening rather than pre-clamping is what preserves the C's arithmetic:
/// the two expressions above multiply before they divide, and clamping the
/// product first would change the quotient rather than merely bounding it.
///
/// Saturation is the right narrowing here because every one of the three
/// products feeds a duration or a rate that the C already saturates
/// elsewhere: a wait longer than [`i64::MAX`] microseconds and a wait of
/// exactly [`i64::MAX`] microseconds are the same instruction to a caller
/// that is arming a timer.
fn saturating_i64(value: i128) -> i64 {
    if value > i128::from(i64::MAX) {
        return i64::MAX;
    }
    if value < i128::from(i64::MIN) {
        return i64::MIN;
    }
    // Both bounds are excluded above, so this conversion cannot fail. It is
    // written as a checked conversion because this crate admits no narrowing
    // `as` cast, and the fallback is unreachable rather than a default.
    i64::try_from(value).unwrap_or_default()
}

impl RateLimit {
    /// A limiter of `rate_per_sec` tokens a second, banking at most
    /// `burst_per_sec` -- `Curl_rlimit_init` (`lib/ratelimit.c:152-167`).
    ///
    /// The C initialises a structure the caller already owns, because
    /// `struct Curl_rlimit` is embedded in `struct pgrs_dir`. The in-place
    /// form has an exact counterpart here that needs no second entry point:
    /// `dir.rlimit = RateLimit::new(rate, burst, now)`, which is what
    /// `lib/setopt.c:2801` and `:2812` mean when they re-initialise a live
    /// limiter as `CURLOPT_MAX_SEND_SPEED_LARGE` or
    /// `CURLOPT_MAX_RECV_SPEED_LARGE` is set.
    ///
    /// `burst_per_sec` of 0 means "no cap", not "bank nothing". The two
    /// interesting settings are recorded at `lib/ratelimit.h:42-47`: a burst
    /// of [`i64::MAX`] averages the rate across the whole transfer, while a
    /// burst equal to the rate keeps the transfer at or below the rate
    /// throughout. curl itself always passes the second form.
    ///
    /// # Panics
    ///
    /// Panics in a debug build when a contract the C also asserts is
    /// violated: a negative rate, or a burst that is neither zero nor at
    /// least the rate (`lib/ratelimit.c:157-158`). A release build proceeds,
    /// as the C does, and the arithmetic below saturates rather than
    /// overflowing. C's third assertion, `DEBUGASSERT(pts)`, has no
    /// counterpart because [`CurlTime`] is a value and cannot be null.
    #[allow(dead_code)]
    pub(crate) fn new(
        rate_per_sec: i64,
        burst_per_sec: i64,
        now: CurlTime,
    ) -> Self {
        debug_assert!(
            rate_per_sec >= 0,
            "Curl_rlimit_init: a negative rate is a caller bug: \
             {rate_per_sec}"
        );
        debug_assert!(
            burst_per_sec >= rate_per_sec || burst_per_sec == 0,
            "Curl_rlimit_init: a burst of {burst_per_sec} below the rate of \
             {rate_per_sec} would cap every step"
        );
        Self {
            // The C names both fields "per_step" while its arguments are
            // "per_sec", and assigns one to the other unchanged. That is
            // consistent because the initial step IS one second; tuning later
            // changes the step and the rate together.
            rate_per_step: rate_per_sec,
            burst_per_step: burst_per_sec,
            step_us: CURL_US_PER_SEC,
            // Full at the start, so that the first step of a transfer is not
            // spent waiting for tokens that the rate promises immediately.
            tokens: rate_per_sec,
            spare_us: 0,
            ts: now,
            blocked: false,
        }
    }

    /// Restarts limiting at `now`, tuning the step for `total_tokens` --
    /// `Curl_rlimit_start` (`lib/ratelimit.c:169-176`).
    ///
    /// `total_tokens` is either -1 for "unknown" or the number of tokens the
    /// transfer expects to consume in total. `lib/sendf.c:202` passes
    /// `data->req.size` for a download whose length is known and
    /// `lib/sendf.c:1198` passes -1 for an upload; [`Self::block`] passes -1
    /// when it lifts a block, so that time spent blocked generates no tokens.
    ///
    /// Available tokens are reset to one step's worth and the spare
    /// microseconds are discarded, which is what "with no history of the
    /// past" means at `lib/ratelimit.h:50-51`.
    ///
    /// # Panics
    ///
    /// Panics in a debug build if called with a `total_tokens` above 1 on a
    /// limiter whose step is no longer one second, because tuning asserts
    /// that precondition at `lib/ratelimit.c:118`. This is not a restriction
    /// this module invents: the C has it, and the C's own call sites respect
    /// it -- `lib/sendf.c:200-204` guards the sized call with
    /// `!ctx->started_body` so that it happens once per request, and every
    /// other call site passes -1, which returns before the assertion. Tuning
    /// twice would compound two step adjustments and pace the transfer at a
    /// rate neither setting asked for, so the assertion is load-bearing.
    #[allow(dead_code)]
    pub(crate) fn start(&mut self, now: CurlTime, total_tokens: i64) {
        self.tokens = self.rate_per_step;
        self.spare_us = 0;
        self.ts = now;
        self.tune_steps(total_tokens);
    }

    /// Generates the tokens that have accrued since the last update --
    /// `rlimit_update` (`lib/ratelimit.c:33-75`).
    ///
    /// Called by [`Self::available`], [`Self::drain`] and [`Self::wait_ms`],
    /// which are the three places the C calls it, and by nothing else. It is
    /// private because it is the one operation that may only run on a limiter
    /// that is actually limiting: its first line asserts
    /// `r->rate_per_step`, and each of its three callers has already returned
    /// for an unlimited or blocked limiter by the time it is reached.
    ///
    /// # The four ways it declines to do anything
    ///
    /// 1. **The timestamp has not moved.** `lib/ratelimit.c:40-41` compares
    ///    both fields of `struct curltime`; here [`CurlTime`] derives
    ///    [`PartialEq`] over the same two fields, so `self.ts == now` is the
    ///    same test. This is the common case on a busy transfer, where
    ///    several drains share one reading of the clock.
    /// 2. **Time went backwards.** `:44-47` returns rather than minting
    ///    tokens for a negative interval, with a bare `DEBUGASSERT(0)` to
    ///    stop a debug build at the caller's bug. The monotonic clock of
    ///    `crate::util::timeval` does not go backwards, so reaching this is a
    ///    caller passing a stale reading -- for instance the reading taken at
    ///    the start of a `multi` cycle after a later one has already been
    ///    applied.
    /// 3. **Less than one step has passed.** `:50-51` returns WITHOUT
    ///    touching `ts`, which is what makes the sub-step case accumulate:
    ///    the interval stays pending in the difference against the unchanged
    ///    `ts` and is measured again on the next call, so a hundred calls a
    ///    microsecond apart eventually produce one step rather than a hundred
    ///    rounding errors.
    /// 4. **The step is zero.** Not a case the C has, and not one this module
    ///    can reach either: `step_us` is zero only in the [`Default`] state,
    ///    where `rate_per_step` is zero as well and all three callers have
    ///    already returned. The guard exists because the alternative to
    ///    reasoning about it is a division by zero -- undefined behaviour in
    ///    C, a panic here -- and a guard that costs one comparison is
    ///    preferable to an argument that a later change could invalidate.
    ///
    /// # Why `spare_us` is added before the comparison and not after
    ///
    /// `:49-56` adds the pending microseconds to the measured interval,
    /// compares the SUM against one step, and on a complete update splits the
    /// sum into whole steps and a new remainder. Comparing the interval alone
    /// would drop the pending time whenever the interval on its own reached a
    /// step, and the transfer would then run slightly under its rate
    /// permanently.
    fn update(&mut self, now: CurlTime) {
        // C: `DEBUGASSERT(r->rate_per_step);`
        debug_assert!(
            self.rate_per_step != 0,
            "rlimit_update on a limiter with no rate: its three callers \
             return first"
        );
        debug_assert!(
            self.step_us > 0,
            "rlimit_update with a step of {} on a rate of {}",
            self.step_us,
            self.rate_per_step
        );
        if self.step_us <= 0 {
            return;
        }

        // C: `if((r->ts.tv_sec == pts->tv_sec) && (r->ts.tv_usec == ...))`
        if self.ts == now {
            return;
        }

        let elapsed_us = timediff_us(now, self.ts);
        // C: `if(elapsed_us < 0) { DEBUGASSERT(0); return; }`. Written as an
        // assertion on the condition rather than as `debug_assert!(false)`
        // inside the branch: the two fire on exactly the same inputs, and
        // this form says which input was wrong.
        debug_assert!(
            elapsed_us >= 0,
            "rlimit_update: not going back in time, but the caller's \
             timestamp is {elapsed_us}us behind the last update"
        );
        if elapsed_us < 0 {
            return;
        }

        // C: `elapsed_us += r->spare_us;` -- the same shadowing the C's
        // reuse of the variable performs. `saturating_add` because
        // `timediff_us` may already have saturated at `i64::MAX`, where the
        // C's `+=` would overflow.
        let elapsed_us = elapsed_us.saturating_add(self.spare_us);
        if elapsed_us < self.step_us {
            return;
        }

        // C: "we do the update".
        self.ts = now;
        // `elapsed_us >= step_us > 0` at this point, so the quotient is at
        // least 1 and the divisor is not zero. Both facts are relied on
        // below, where `i64::MAX / elapsed_steps` must not divide by zero.
        let elapsed_steps = elapsed_us / self.step_us;
        self.spare_us = elapsed_us % self.step_us;

        // C: the token gain, saturating instead of overflowing:
        //   if(r->rate_per_step > (INT64_MAX / elapsed_steps))
        //     token_gain = INT64_MAX;
        //   else token_gain = r->rate_per_step * elapsed_steps;
        let token_gain = if self.rate_per_step > i64::MAX / elapsed_steps {
            i64::MAX
        } else {
            self.rate_per_step.saturating_mul(elapsed_steps)
        };

        // C: `if((INT64_MAX - token_gain) > r->tokens) r->tokens += ...`
        // The comparison is STRICT, and it is transcribed rather than
        // replaced by a bare `saturating_add`: the two agree on every input,
        // and keeping the C's shape is what makes that agreement checkable
        // against the original.
        self.tokens = if i64::MAX.saturating_sub(token_gain) > self.tokens {
            self.tokens.saturating_add(token_gain)
        } else {
            i64::MAX
        };

        // C: "Limit the token again by the burst rate (if set), so we do not
        // suddenly have a huge number of tokens after inactivity."
        if self.burst_per_step != 0 && self.tokens > self.burst_per_step {
            self.tokens = self.burst_per_step;
        }
    }

    /// Shortens the step so that the LAST step of a transfer is small --
    /// `rlimit_tune_steps` (`lib/ratelimit.c:77-150`).
    ///
    /// # The problem being solved, in the C's own words
    ///
    /// `lib/ratelimit.c:82-100` explains it, and the explanation is the
    /// specification. Tokens arrive per step, and they may be spent in full
    /// at the very start of a step; the rest of that step then has none,
    /// which blocks consumption and holds the average at the rate. That works
    /// up to the LAST step: when no more tokens are needed there is no wait,
    /// so the last step finishes too fast, and the effect is most visible
    /// when only a few steps are needed.
    ///
    /// The C's example: downloading 1.5kB at a rate limit of 1k could finish
    /// in roughly one second -- 1k in the first second and the remaining 0.5k
    /// at the start of the second one -- rather than in the two seconds the
    /// rate implies.
    ///
    /// The remedy is to give the last step only about one percent of the
    /// total and to spread the rest over slightly longer, slightly richer
    /// steps before it.
    ///
    /// # Why this is transcribed and not improved
    ///
    /// It changes observable completion timing for small transfers, so a
    /// different distribution is a behaviour change even when it is
    /// defensible in isolation. Every quotient below truncates toward zero,
    /// every comparison keeps the C's strictness, and the two `if`s that
    /// guard against a zero increment are kept even though a zero increment
    /// would be harmless to apply -- because applying it would still move
    /// `tokens`, which the C leaves alone.
    ///
    /// # The three guards that make the arithmetic safe
    ///
    /// `:101-104` returns early for an unlimited limiter, for a total of 1 or
    /// less (which is how -1, "unknown", is handled), and for a total above
    /// `INT64_MAX / 1000`. The third is what bounds `tokens_main * 1000`
    /// below the range of the type, so the C's plain multiplication cannot
    /// overflow; the saturating form used here is belt and braces rather than
    /// the mechanism.
    fn tune_steps(&mut self, tokens_total: i64) {
        if self.rate_per_step == 0
            || tokens_total <= 1
            || tokens_total > i64::MAX / MSTEPS_PER_STEP
        {
            return;
        }

        // C: the last step's budget -- one percent, at least 1, at most
        // `CURL_RLIMIT_MIN_RATE`.
        let mut tokens_last = tokens_total / PERCENT;
        if tokens_last == 0 {
            // C: "less than 100 total, just use 1".
            tokens_last = 1;
        } else if tokens_last > CURL_RLIMIT_MIN_RATE {
            tokens_last = CURL_RLIMIT_MIN_RATE;
        }
        // C: `DEBUGASSERT(tokens_last);` -- upheld by the branch above.
        debug_assert!(tokens_last != 0, "the last step needs a token budget");

        // The subtraction cannot overflow: `tokens_total` is above 1 and
        // `tokens_last` is at most one percent of it, so the difference is at
        // least 1 and at most `tokens_total`.
        let tokens_main = tokens_total - tokens_last;
        // C: `DEBUGASSERT(tokens_main);` -- upheld because `tokens_total > 1`
        // implies `tokens_last < tokens_total`.
        debug_assert!(
            tokens_main != 0,
            "the steps before the last need a token budget"
        );
        // C: `DEBUGASSERT(r->step_us == CURL_US_PER_SEC);` -- tuning is
        // relative to the untuned one-second step, so it may run only once.
        debug_assert_eq!(
            self.step_us, CURL_US_PER_SEC,
            "rlimit_tune_steps: tuning an already tuned limiter would \
             compound two step adjustments"
        );

        // C: `msteps = (tokens_main * 1000 / r->rate_per_step);` -- how many
        // thousandths of the original one-second step it takes to provide the
        // main tokens at the original rate. Truncation toward zero is
        // deliberate and observable.
        let msteps = tokens_main.saturating_mul(MILLI) / self.rate_per_step;

        if msteps < CURL_RLIMIT_STEP_MIN_MS {
            // C: "Steps this small will not work. Do not tune."
            return;
        }

        // The C writes this as `else if` / `else` after the return above.
        if msteps < MSTEPS_PER_STEP {
            // C: "It needs less than one step to provide the needed tokens.
            // Make it exactly that long and with exactly those tokens."
            self.step_us = msteps.saturating_mul(MILLI);
            self.rate_per_step = tokens_main;
            self.tokens = self.rate_per_step;
        } else {
            // C: "More than 1 step. Spread the remainder milli steps and the
            // tokens they need to provide across all steps. If integer
            // arithmetic can do it."
            let ms_unaccounted = msteps % MSTEPS_PER_STEP;
            // `msteps / MSTEPS_PER_STEP` is at least 1 in this branch, so the
            // division is safe.
            let mstep_inc = ms_unaccounted / (msteps / MSTEPS_PER_STEP);
            if mstep_inc != 0 {
                // C: `rate_inc = ((r->rate_per_step * mstep_inc) / 1000);`
                // Multiply first, then divide: reversing them would truncate
                // the rate increase to zero for every rate below 1000.
                let rate_inc = saturating_i64(
                    i128::from(self.rate_per_step) * i128::from(mstep_inc)
                        / i128::from(MILLI),
                );
                if rate_inc != 0 {
                    self.step_us = CURL_US_PER_SEC
                        .saturating_add(mstep_inc.saturating_mul(MILLI));
                    self.rate_per_step =
                        self.rate_per_step.saturating_add(rate_inc);
                    self.tokens = self.rate_per_step;
                }
            }
        }

        // C: `if(r->burst_per_step) r->burst_per_step = r->rate_per_step;`
        // A limiter that had a cap keeps one, moved to the tuned rate. A
        // limiter that had none is not given one.
        if self.burst_per_step != 0 {
            self.burst_per_step = self.rate_per_step;
        }
    }

    /// The tokens generated per step -- `Curl_rlimit_per_step`
    /// (`lib/ratelimit.c:178-181`).
    ///
    /// This is the TUNED rate once [`Self::start`] has run with a known
    /// total, not the per-second rate the limiter was built with, and the
    /// step it applies to is not necessarily a second. `lib/http2.c:215` uses
    /// it to size a stream window, which is why it is exposed at all: a
    /// window smaller than one step's tokens would throttle below the rate
    /// limit, and one much larger would defeat it.
    #[allow(dead_code)]
    pub(crate) const fn per_step(&self) -> i64 {
        self.rate_per_step
    }

    /// Whether this limiter has anything to say -- `Curl_rlimit_active`
    /// (`lib/ratelimit.c:183-186`).
    ///
    /// True when the rate is positive OR the limiter is blocked. The second
    /// disjunct is easy to miss and load-bearing: a blocked limiter has no
    /// rate to enforce but must still report 0 available tokens, so a
    /// transfer loop that consulted only the rate would run a paused transfer
    /// at full speed.
    ///
    /// Note the asymmetry with the other methods, transcribed rather than
    /// tidied: this one tests `rate_per_step > 0` while [`Self::available`],
    /// [`Self::drain`], [`Self::wait_ms`] and [`Self::next_step_ms`] test
    /// `rate_per_step != 0`. The two agree for every value the constructor's
    /// assertion admits, and differ only for a negative rate, which is a
    /// contract violation in the first place.
    #[allow(dead_code)]
    pub(crate) const fn is_active(&self) -> bool {
        self.rate_per_step > 0 || self.blocked
    }

    /// Whether limiting is blocked -- `Curl_rlimit_is_blocked`
    /// (`lib/ratelimit.c:188-191`).
    ///
    /// `lib/transfer.c:885-891` exposes exactly this as the "is the upload or
    /// download paused" question, so blocking is how a pause is represented
    /// rather than a state kept beside it.
    #[allow(dead_code)]
    pub(crate) const fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// The tokens available to spend, which may be negative --
    /// `Curl_rlimit_avail` (`lib/ratelimit.c:193-204`).
    ///
    /// Three answers, in the C's order of testing:
    ///
    /// * blocked -- 0, whatever the rate and whatever the balance;
    /// * limited -- the balance after generating whatever has accrued since
    ///   the last update, so this call moves the limiter forward in time;
    /// * unlimited -- [`i64::MAX`], the successor of the C's
    ///   `CURL_OFF_T_MAX`. This is a sentinel meaning "as much as you like",
    ///   and callers treat it as such: `lib/transfer.c:251-256` and
    ///   `lib/sendf.c:1202-1206` use the value to size the next read or write
    ///   and are content to be told a number larger than any buffer.
    ///
    /// A NEGATIVE answer is meaningful and is not clamped. `lib/multi.c:953`
    /// and `:954` read "blocked" as `avail <= 0` rather than `== 0` for
    /// exactly that reason.
    #[allow(dead_code)]
    pub(crate) fn available(&mut self, now: CurlTime) -> i64 {
        if self.blocked {
            0
        } else if self.rate_per_step != 0 {
            self.update(now);
            self.tokens
        } else {
            i64::MAX
        }
    }

    /// Spends `tokens` -- `Curl_rlimit_drain` (`lib/ratelimit.c:206-227`).
    ///
    /// Called once per delivered chunk from progress accounting
    /// (`lib/progress.c:342-356`), which is why the count is a [`usize`]: it
    /// is a byte count that came from a buffer length.
    ///
    /// A blocked or unlimited limiter ignores the call entirely, exactly as
    /// the C does -- so a paused transfer that somehow delivers bytes does
    /// not accumulate a debt it would have to pay off after unpausing.
    ///
    /// Otherwise the limiter is brought up to date first and the balance is
    /// then reduced, saturating at [`i64::MIN`] instead of wrapping. The
    /// balance is ALLOWED to go negative: that debt is what
    /// [`Self::wait_ms`] converts into a wait, and it is how a chunk larger
    /// than one step's tokens is paid for over the following steps.
    ///
    /// # One branch that looks wrong and is reproduced anyway
    ///
    /// `lib/ratelimit.c:214-219` reads:
    ///
    /// ```text
    /// #if 8 <= SIZEOF_SIZE_T
    ///   if(tokens > INT64_MAX) {
    ///     r->tokens = INT64_MAX;
    ///   }
    ///   else
    /// #endif
    /// ```
    ///
    /// A drain too large to express as a signed 64-bit integer sets the
    /// balance to `INT64_MAX` -- the most credit possible -- where the
    /// arithmetic direction of the function would suggest `INT64_MIN`. It is
    /// reproduced rather than corrected, because specification 0.8.1 freezes
    /// observable behaviour and this is the shipped behaviour. It is also
    /// unreachable in practice: the argument is a buffer length, and a single
    /// buffer of more than eight exabytes cannot exist.
    ///
    /// `i64::try_from` reproduces both the branch AND its conditional
    /// compilation, which is the reason it is written that way here. On a
    /// 64-bit target the conversion fails on exactly the values for which
    /// `tokens > INT64_MAX` holds; on a 32-bit target every [`usize`] fits
    /// and the branch is unreachable, which is what the `#if` arranges in C.
    /// All four mandated targets are 64-bit, so the live path is the first.
    #[allow(dead_code)]
    pub(crate) fn drain(&mut self, tokens: usize, now: CurlTime) {
        if self.blocked || self.rate_per_step == 0 {
            return;
        }

        self.update(now);

        match i64::try_from(tokens) {
            Ok(val) => {
                // C: `if((INT64_MIN + val) < r->tokens) r->tokens -= val;`
                // `else r->tokens = INT64_MIN;` -- a strict comparison, and
                // the addition cannot overflow because `val` is
                // non-negative.
                self.tokens = if i64::MIN.saturating_add(val) < self.tokens {
                    self.tokens.saturating_sub(val)
                } else {
                    i64::MIN
                };
            }
            Err(_) => self.tokens = i64::MAX,
        }
    }

    /// How many milliseconds until tokens are available again --
    /// `Curl_rlimit_wait_ms` (`lib/ratelimit.c:229-254`).
    ///
    /// Zero means "do not wait". A blocked limiter returns zero because a
    /// block is not a wait -- it is lifted by a caller, never by the passage
    /// of time -- and an unlimited limiter returns zero because it never
    /// runs out. A limiter with a positive balance returns zero too.
    ///
    /// # The wait is one step, plus the debt, minus what has already elapsed
    ///
    /// Three terms, in the C's order:
    ///
    /// 1. `step_us - spare_us`, the remainder of the current step. The spare
    ///    microseconds are deducted because they have already been served.
    /// 2. The debt, when the balance is negative, as a whole percentage of a
    ///    step: `debt_pct = (-tokens) * 100 / rate_per_step`, then
    ///    `step_us * debt_pct / 100`. The order matters -- multiply, then
    ///    divide -- and so does the truncation: a debt below one percent of a
    ///    step's tokens rounds to zero and adds nothing, which is the C's
    ///    `if(debt_pct)`.
    /// 3. Minus the interval since the last update. After a complete update
    ///    that interval is zero, because the update moved `ts` to `now`; when
    ///    the update declined for being sub-step, it is the pending time,
    ///    and deducting it is what stops a caller polling every millisecond
    ///    from being told to wait a full step every time.
    ///
    /// The result is rounded UP to milliseconds, so a wait of one microsecond
    /// is reported as one millisecond rather than as zero. Reporting zero
    /// would tell the caller not to wait at all and spin the transfer loop.
    ///
    /// # How the transfer loop uses this
    ///
    /// From `lib/multi.c:1880-1921`, and recorded here rather than in the
    /// loop's own module because this is the method whose contract it
    /// depends on. When either direction is [`Self::is_active`], the loop
    /// takes ONE reading of the clock, asks both directions for their wait,
    /// and if either is non-zero:
    ///
    /// * moves the transfer to the rate-limiting state if it is not there
    ///   already;
    /// * arms the expiry timer with the MAXIMUM of the two waits, under the
    ///   `TOOFAST` identifier -- the maximum, because waiting the shorter of
    ///   the two would return with the other direction still throttled;
    ///   and traces `[RLIMIT] waiting <n>ms`;
    /// * reports "try again later" for this cycle.
    ///
    /// When both waits are zero it consults [`Self::next_step_ms`] instead.
    /// Neither the state transition nor the timer is this module's business:
    /// see the module documentation.
    #[allow(dead_code)]
    pub(crate) fn wait_ms(&mut self, now: CurlTime) -> TimeDiff {
        if self.blocked || self.rate_per_step == 0 {
            return 0;
        }

        self.update(now);
        if self.tokens > 0 {
            return 0;
        }

        // C: `wait_us = r->step_us - r->spare_us;`
        let mut wait_us = self.step_us.saturating_sub(self.spare_us);

        if self.tokens < 0 {
            // C: `debt_pct = ((-r->tokens) * 100 / r->rate_per_step);`
            //
            // Computed in `i128` for two reasons. The negation is exact even
            // at `i64::MIN`, where C's `-r->tokens` is undefined behaviour
            // and Rust's would panic; and the product survives a debt near
            // `i64::MAX`, where multiplying by 100 leaves the range. The
            // divisor is non-zero because the guard at the top of this
            // function has already returned for a rate of zero.
            let debt_pct = saturating_i64(
                -i128::from(self.tokens) * i128::from(PERCENT)
                    / i128::from(self.rate_per_step),
            );
            if debt_pct != 0 {
                // C: `wait_us += (r->step_us * debt_pct / 100);`
                let debt_us = saturating_i64(
                    i128::from(self.step_us) * i128::from(debt_pct)
                        / i128::from(PERCENT),
                );
                wait_us = wait_us.saturating_add(debt_us);
            }
        }

        // C: `elapsed_us = curlx_ptimediff_us(pts, &r->ts);`
        //
        // This comparison is defensive in the C and defensive here, and the
        // reason is worth recording so that a reader does not mistake the
        // gap in the coverage report for an untested branch. While the step
        // is positive it cannot fire: a COMPLETE update moved `ts` to `now`,
        // so the interval is zero, and an update that declined for being
        // sub-step did so because `elapsed_us + spare_us < step_us`, which is
        // exactly `elapsed_us < wait_us`. Debt only widens the gap. The one
        // state that reaches it is the zero-step state, which no sequence of
        // calls can produce -- see [`Self::update`]'s fourth case.
        let elapsed_us = timediff_us(now, self.ts);
        if elapsed_us >= wait_us {
            return 0;
        }
        wait_us = wait_us.saturating_sub(elapsed_us);

        // C: `return (wait_us + 999) / 1000;` -- the ceiling of a strictly
        // positive quotient, since `wait_us > elapsed_us >= ...` here.
        wait_us.saturating_add(CEIL_ADDEND) / MILLI
    }

    /// How many milliseconds until this limiter next generates tokens --
    /// `Curl_rlimit_next_step_ms` (`lib/ratelimit.c:256-269`).
    ///
    /// Zero when the limiter is blocked, when it is unlimited, or when a
    /// step's worth of time has already passed -- in the last case there is
    /// nothing to wait for, because the tokens arrive on the next update.
    ///
    /// # This one does NOT update
    ///
    /// It reads `ts` and `spare_us` and mutates nothing, so it is the only
    /// query here that takes `&self`. The C takes a mutable pointer, as all
    /// of its accessors do, and never writes through it. That is not a
    /// detail: the transfer loop calls this method for BOTH directions after
    /// having called [`Self::wait_ms`] on both, and a hidden update here
    /// would generate tokens between the two questions.
    ///
    /// # Why the loop needs it at all
    ///
    /// `lib/multi.c:1902-1915`: when neither direction needs to wait, the
    /// transfer still has to be woken when tokens next arrive, "or it may
    /// stall". The loop takes the MINIMUM of the two directions' answers,
    /// falling back to the maximum when the minimum is zero -- so that a
    /// direction which is not limited, and answers zero, does not cancel the
    /// wake-up the other direction needs -- and arms the same `TOOFAST`
    /// timer, tracing `[RLIMIT] next token update in <n>ms`.
    ///
    /// A negative interval is not guarded here, unlike in [`Self::update`],
    /// and that is the C's behaviour rather than an oversight: a stale
    /// timestamp makes the reported delay LONGER, which is safe, where
    /// minting tokens for it would not be.
    #[allow(dead_code)]
    pub(crate) fn next_step_ms(&self, now: CurlTime) -> TimeDiff {
        if !self.blocked && self.rate_per_step != 0 {
            // C: `elapsed_us = curlx_ptimediff_us(pts, &r->ts) + spare_us;`
            let elapsed_us =
                timediff_us(now, self.ts).saturating_add(self.spare_us);
            if self.step_us > elapsed_us {
                let next_us = self.step_us.saturating_sub(elapsed_us);
                // C: `return (next_us + 999) / 1000;`
                return next_us.saturating_add(CEIL_ADDEND) / MILLI;
            }
        }
        0
    }

    /// Blocks or unblocks limiting -- `Curl_rlimit_block`
    /// (`lib/ratelimit.c:271-288`).
    ///
    /// This is how a pause is applied: `lib/transfer.c:896` and `:906` call
    /// it with the pause state for the upload and download directions, and
    /// `lib/request.c:162-163` unblocks both as a request begins.
    ///
    /// Setting the state it already has does nothing at all -- not even
    /// moving the timestamp -- which is what makes it safe to call on every
    /// cycle with the current pause state.
    ///
    /// # The two directions are not symmetrical
    ///
    /// Blocking sets the balance to zero. Unblocking calls
    /// [`Self::start`] with an unknown total, so that the balance is reset
    /// to one step's worth, the pending microseconds are discarded and the
    /// step is left as it is. `lib/ratelimit.c:281-283` gives the reason:
    /// "Start rate limiting fresh. The amount of time this was blocked does
    /// not generate extra tokens."
    ///
    /// That asymmetry is the whole point. A blocked limiter whose timestamp
    /// stayed put would, on unblocking, be asked for the tokens accrued
    /// across the entire pause -- and a transfer paused for an hour would
    /// then run unthrottled for as long as that credit lasted. Because
    /// [`Self::start`] is called with -1, the tuning inside it returns
    /// immediately, so unblocking never re-tunes a step: see
    /// [`Self::start`]'s note on why tuning may run only once.
    #[allow(dead_code)]
    pub(crate) fn block(&mut self, activate: bool, now: CurlTime) {
        // C: `if(!activate == !r->blocked) return;` -- for two booleans that
        // is equality.
        if activate == self.blocked {
            return;
        }

        self.ts = now;
        self.blocked = activate;
        if self.blocked {
            self.tokens = 0;
        } else {
            self.start(now, -1);
        }
    }
}

// The tests below move time by hand. Not one of them sleeps, reads the host
// clock or touches the network: every instant is a [`CurlTime`] built by
// [`at_us`], and the scenarios that need a clock use [`TestClock`], which is
// `pub(crate)` in `crate::util::timeval` precisely so that a consumer's tests
// can inject it. That is what makes the line-coverage gate of
// specification 0.8.4 reachable over this directory.
//
// `cargo test` builds with `debug_assertions` on, so the contract assertions
// this module transcribes from the C's `DEBUGASSERT`s do fire during a test
// run. The tests are split accordingly, following the convention already
// established in `crate::util`: `#[cfg(debug_assertions)]` proves an
// assertion FIRES, and `#[cfg(not(debug_assertions))]` proves the release
// behaviour the C ships -- return without touching a field -- is what happens
// when it does not. Neither half is redundant, because the two halves are
// different builds of different code.
#[cfg(test)]
mod tests {
    use super::{
        RateLimit, CEIL_ADDEND, CURL_RLIMIT_MIN_RATE, CURL_RLIMIT_STEP_MIN_MS,
        CURL_US_PER_SEC, MILLI, MSTEPS_PER_STEP, PERCENT,
    };
    use crate::util::timediff::TimeDiff;
    use crate::util::timeval::{timediff_us, Clock, CurlTime, TestClock};
    use std::time::Duration;

    /// The whole second the test origin sits at.
    ///
    /// Non-zero so that a reading BEFORE the origin is representable, which
    /// the backwards-clock tests need. Its actual value is irrelevant: every
    /// method here works on differences.
    const ORIGIN_SECS: i64 = 1_000;

    /// The reading `offset_us` microseconds after the test origin.
    fn at_us(offset_us: i64) -> CurlTime {
        CurlTime::new(
            ORIGIN_SECS + offset_us / CURL_US_PER_SEC,
            i32::try_from(offset_us % CURL_US_PER_SEC)
                .expect("a microsecond remainder is under a second"),
        )
    }

    /// [`i64::MAX`] as a [`usize`], for the drain-saturation tests.
    ///
    /// All four mandated targets are 64-bit (specification 0.8.3), so the
    /// conversion succeeds; on a hypothetical 32-bit target it would fail and
    /// say so rather than silently truncating.
    fn i64_max_tokens() -> usize {
        usize::try_from(i64::MAX).expect("a 64-bit target")
    }

    // ---- the constants, and the arithmetic identities that depend on them

    #[test]
    fn the_constants_are_the_c_s_literals() {
        assert_eq!(CURL_US_PER_SEC, 1_000_000, "lib/ratelimit.c:29");
        assert_eq!(CURL_RLIMIT_MIN_RATE, 4 * 1024, "lib/ratelimit.c:30");
        assert_eq!(CURL_RLIMIT_MIN_RATE, 4096, "the same value, spelled out");
        assert_eq!(CURL_RLIMIT_STEP_MIN_MS, 2, "lib/ratelimit.c:31");
        assert_eq!(MILLI, 1_000);
        assert_eq!(MSTEPS_PER_STEP, MILLI, "equal, and different quantities");
        assert_eq!(PERCENT, 100);
        assert_eq!(CEIL_ADDEND, 999, "the addend of `(x + 999) / 1000`");
        assert_eq!(
            CURL_US_PER_SEC / MILLI,
            MSTEPS_PER_STEP,
            "one step is a thousand millisteps of a thousand microseconds"
        );
    }

    // ---- initialisation, and the two predicates

    #[test]
    fn a_limited_limiter_starts_full_and_reports_itself_active() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));

        assert_eq!(limiter.per_step(), 1000);
        assert!(limiter.is_active());
        assert!(!limiter.is_blocked());
        // `Curl_rlimit_init` sets `tokens = rate_per_step`, so the first step
        // of a transfer does not begin by waiting for tokens the rate has
        // already promised.
        assert_eq!(limiter.available(at_us(0)), 1000);
        // The untuned step is one second, reported as a ceiling in
        // milliseconds.
        assert_eq!(limiter.next_step_ms(at_us(0)), 1000);
    }

    #[test]
    fn an_unlimited_limiter_offers_everything_and_is_not_active() {
        let mut limiter = RateLimit::new(0, 0, at_us(0));

        assert_eq!(limiter.per_step(), 0);
        assert!(!limiter.is_active());
        assert!(!limiter.is_blocked());
        // `lib/ratelimit.h:53-54`: "a rate limiter with rate 0 will always
        // have CURL_OFF_T_MAX tokens available, unless blocked."
        assert_eq!(limiter.available(at_us(0)), i64::MAX);
        assert_eq!(limiter.available(at_us(9_000_000)), i64::MAX);
        assert_eq!(limiter.wait_ms(at_us(9_000_000)), 0);
        assert_eq!(limiter.next_step_ms(at_us(9_000_000)), 0);
    }

    #[test]
    fn the_default_is_the_calloc_zeroed_state_of_a_fresh_handle() {
        // `struct Curl_rlimit` is embedded in `struct pgrs_dir`
        // (`lib/urldata.h:788-793`) and a fresh easy handle is allocated with
        // calloc, so every field starts at zero -- including `step_us`, which
        // no method may divide by. This is the state progress accounting will
        // hold before any speed option is set.
        let mut limiter = RateLimit::default();

        assert_eq!(limiter.per_step(), 0);
        assert!(!limiter.is_active());
        assert!(!limiter.is_blocked());
        assert_eq!(limiter.available(at_us(0)), i64::MAX);
        assert_eq!(limiter.wait_ms(at_us(5_000_000)), 0);
        assert_eq!(limiter.next_step_ms(at_us(5_000_000)), 0);

        let before = limiter.clone();
        limiter.drain(4096, at_us(5_000_000));
        assert_eq!(limiter, before, "an unlimited limiter ignores a drain");
    }

    #[test]
    fn a_burst_above_the_rate_is_accepted_and_a_zero_burst_means_no_cap() {
        // The two settings `lib/ratelimit.h:42-47` singles out.
        let averaging = RateLimit::new(1000, i64::MAX, at_us(0));
        assert_eq!(averaging.per_step(), 1000);

        let uncapped = RateLimit::new(1000, 0, at_us(0));
        assert_eq!(uncapped.per_step(), 1000);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "a negative rate is a caller bug")]
    fn a_negative_rate_is_rejected_in_a_debug_build() {
        // C: `DEBUGASSERT(rate_per_sec >= 0);` at `lib/ratelimit.c:157`.
        let _ = RateLimit::new(-1, 0, at_us(0));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "would cap every step")]
    fn a_burst_below_the_rate_is_rejected_in_a_debug_build() {
        // C: `DEBUGASSERT(burst_per_sec >= rate_per_sec || !burst_per_sec);`
        let _ = RateLimit::new(1000, 999, at_us(0));
    }

    // ---- token generation

    #[test]
    fn one_step_of_idleness_generates_one_step_of_tokens() {
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.drain(1000, at_us(0));
        assert_eq!(limiter.available(at_us(0)), 0);

        assert_eq!(limiter.available(at_us(CURL_US_PER_SEC)), 1000);
    }

    #[test]
    fn two_steps_of_idleness_generate_two_steps_of_tokens() {
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.drain(1000, at_us(0));

        // Two whole steps and a half: the half stays behind as spare.
        assert_eq!(limiter.available(at_us(2_500_000)), 2000);
        // Half a step has been served, so half a step remains of it.
        assert_eq!(limiter.next_step_ms(at_us(2_500_000)), 500);
    }

    #[test]
    fn an_identical_timestamp_changes_nothing_at_all() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1000, at_us(0));

        let before = limiter.clone();
        assert_eq!(limiter.available(at_us(0)), 0);
        assert_eq!(
            limiter, before,
            "`lib/ratelimit.c:40-41` returns before touching a field"
        );
    }

    #[test]
    fn sub_step_intervals_accumulate_through_the_unchanged_timestamp() {
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.drain(1000, at_us(0));

        // Three sub-step queries. None of them generates a token, and --
        // crucially -- none of them moves `ts`, so the interval is still
        // pending and is measured again on the next call.
        assert_eq!(limiter.available(at_us(400_000)), 0);
        assert_eq!(limiter.available(at_us(800_000)), 0);
        // 1.2 steps have now passed since the LAST update, not 0.4.
        assert_eq!(limiter.available(at_us(1_200_000)), 1000);
        // The 0.2 that did not make a whole step is the new spare, so only
        // 0.8 of a step remains before the next token arrives.
        assert_eq!(limiter.next_step_ms(at_us(1_200_000)), 800);
    }

    #[test]
    fn spare_microseconds_carry_into_the_next_step() {
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.drain(1000, at_us(0));
        // Leaves 200ms of spare.
        assert_eq!(limiter.available(at_us(1_200_000)), 1000);
        limiter.drain(1000, at_us(1_200_000));

        // 900ms alone is NOT a step, but 900ms plus the 200ms carried is.
        // Without `elapsed_us += r->spare_us` at `lib/ratelimit.c:49` this
        // would answer 0 and the transfer would run permanently under its
        // rate.
        assert_eq!(limiter.available(at_us(2_100_000)), 1000);
        // 1100ms consumed one step and left 100ms.
        assert_eq!(limiter.next_step_ms(at_us(2_100_000)), 900);
    }

    #[test]
    fn the_burst_cap_stops_idleness_banking_tokens() {
        // `lib/ratelimit.h:36-40`: after a second of inactivity the million
        // would grow to two million, "however the burst limit caps those at
        // 1.5 million".
        let mut limiter = RateLimit::new(1000, 1500, at_us(0));
        limiter.drain(1000, at_us(0));

        assert_eq!(limiter.available(at_us(5_000_000)), 1500);
    }

    #[test]
    fn a_burst_equal_to_the_rate_never_banks_anything() {
        // What curl itself sets: `lib/setopt.c:2801` and `:2812` pass the
        // option value as both the rate and the burst, which
        // `lib/ratelimit.h:45-47` describes as making a transfer "always try
        // to stay *at/below* the rate".
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1000, at_us(0));

        assert_eq!(limiter.available(at_us(5_000_000)), 1000);
        assert_eq!(limiter.available(at_us(60_000_000)), 1000);
    }

    #[test]
    fn a_zero_burst_banks_without_limit() {
        // Zero means "no cap", not "cap at zero" -- the difference decides
        // whether an idle transfer may catch up afterwards.
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.drain(1000, at_us(0));

        assert_eq!(limiter.available(at_us(5_000_000)), 5000);
    }

    // ---- the backwards clock

    #[test]
    fn a_backwards_reading_lengthens_the_next_step_rather_than_panicking() {
        // `Curl_rlimit_next_step_ms` has no guard for a negative interval and
        // needs none: a stale timestamp makes the reported delay LONGER,
        // which is safe, where minting tokens for it would not be.
        let limiter = RateLimit::new(1000, 1000, at_us(CURL_US_PER_SEC));

        assert_eq!(limiter.next_step_ms(at_us(0)), 2000);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "not going back in time")]
    fn a_backwards_reading_stops_a_debug_build_inside_update() {
        // C: `if(elapsed_us < 0) { DEBUGASSERT(0); return; }` at
        // `lib/ratelimit.c:44-47`.
        let mut limiter = RateLimit::new(1000, 1000, at_us(CURL_US_PER_SEC));
        let _ = limiter.available(at_us(0));
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn a_backwards_reading_neither_moves_the_limiter_nor_mints_tokens() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(CURL_US_PER_SEC));
        limiter.drain(1000, at_us(CURL_US_PER_SEC));

        let before = limiter.clone();
        assert_eq!(limiter.available(at_us(0)), 0);
        assert_eq!(limiter, before, "no field moved, and no token appeared");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "rlimit_update with a step of 0")]
    fn a_zero_step_stops_a_debug_build_instead_of_dividing_by_zero() {
        // Unreachable through the API -- `step_us` is zero only where
        // `rate_per_step` is zero as well -- so the state has to be built
        // field by field, which this module can do because it is a child of
        // the one that declares them.
        let mut pathological = RateLimit {
            rate_per_step: 1000,
            burst_per_step: 0,
            step_us: 0,
            tokens: 0,
            spare_us: 0,
            ts: at_us(0),
            blocked: false,
        };
        let _ = pathological.available(at_us(CURL_US_PER_SEC));
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn a_zero_step_returns_rather_than_dividing_by_zero() {
        let mut pathological = RateLimit {
            rate_per_step: 1000,
            burst_per_step: 0,
            step_us: 0,
            tokens: 0,
            spare_us: 0,
            ts: at_us(0),
            blocked: false,
        };

        let before = pathological.clone();
        assert_eq!(pathological.available(at_us(CURL_US_PER_SEC)), 0);
        assert_eq!(pathological, before);
    }

    // ---- draining

    #[test]
    fn draining_walks_the_balance_positive_then_zero_then_negative() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));

        limiter.drain(400, at_us(0));
        assert_eq!(limiter.available(at_us(0)), 600);

        limiter.drain(600, at_us(0));
        assert_eq!(limiter.available(at_us(0)), 0);

        // Debt is legal and is NOT clamped: it is what the following steps
        // pay off, and `lib/multi.c:953` reads "blocked" as `avail <= 0`
        // rather than `== 0` for that reason.
        limiter.drain(100, at_us(0));
        assert_eq!(limiter.available(at_us(0)), -100);
    }

    #[test]
    fn a_drain_larger_than_a_step_is_paid_off_over_the_following_steps() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));

        // A 3500-byte chunk against a 1000-a-second rate: 1000 in credit,
        // 2500 in debt.
        limiter.drain(3500, at_us(0));
        assert_eq!(limiter.available(at_us(0)), -2500);

        assert_eq!(limiter.available(at_us(CURL_US_PER_SEC)), -1500);
        assert_eq!(limiter.available(at_us(2 * CURL_US_PER_SEC)), -500);
        // The burst cap applies to a positive balance, so the step that
        // clears the debt lands at +500 rather than being capped to 1000.
        assert_eq!(limiter.available(at_us(3 * CURL_US_PER_SEC)), 500);
    }

    #[test]
    fn a_blocked_limiter_ignores_a_drain_entirely() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.block(true, at_us(0));

        let before = limiter.clone();
        limiter.drain(500, at_us(CURL_US_PER_SEC));
        assert_eq!(
            limiter, before,
            "a paused transfer must not accumulate a debt to pay off later"
        );
        assert_eq!(limiter.wait_ms(at_us(CURL_US_PER_SEC)), 0);
        assert_eq!(limiter, before, "and a block is not a wait");
    }

    #[test]
    fn an_unlimited_limiter_ignores_a_drain_entirely() {
        let mut limiter = RateLimit::new(0, 0, at_us(0));

        let before = limiter.clone();
        limiter.drain(1_000_000, at_us(CURL_US_PER_SEC));
        assert_eq!(limiter, before);
        assert_eq!(limiter.available(at_us(CURL_US_PER_SEC)), i64::MAX);
    }

    #[test]
    fn a_drain_too_large_for_the_type_credits_rather_than_debits() {
        // The branch of `lib/ratelimit.c:214-219` that looks wrong and is
        // reproduced anyway: a count above `INT64_MAX` sets the balance to
        // `INT64_MAX`. Unreachable in practice -- the argument is a buffer
        // length -- and asserted here so that the oddity is recorded as
        // deliberate rather than rediscovered as a defect.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(usize::MAX, at_us(0));

        assert_eq!(limiter.available(at_us(0)), i64::MAX);
        // The next COMPLETE update re-applies the burst cap, so the credit
        // does not survive the step. That too is the C's behaviour: the cap
        // lives in `rlimit_update`, which the query above did not reach
        // because the timestamp had not moved.
        assert_eq!(limiter.available(at_us(CURL_US_PER_SEC)), 1000);
    }

    #[test]
    fn draining_saturates_at_the_lower_bound_without_panicking() {
        let big = i64_max_tokens();
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));

        // C: `if((INT64_MIN + val) < r->tokens) r->tokens -= val;` -- the
        // first drain fits, because 1000 - INT64_MAX is still representable.
        limiter.drain(big, at_us(0));
        assert_eq!(limiter.available(at_us(0)), 1000 - i64::MAX);

        // The second cannot, so the balance saturates instead of wrapping.
        limiter.drain(big, at_us(0));
        assert_eq!(limiter.available(at_us(0)), i64::MIN);
    }

    // ---- the wait

    #[test]
    fn the_wait_rounds_microseconds_up_to_whole_milliseconds() {
        // Three limiters rather than three calls: `wait_ms` mutates, and the
        // point of these vectors is the exact boundary of the C's
        // `(wait_us + 999) / 1000` at `lib/ratelimit.c:253`.
        //
        // Each is drained dry at the origin, so the wait is one whole step
        // minus the interval already elapsed.
        for (queried_at, expected_ms, remaining_us) in
            [(999_999, 1, 1), (999_000, 1, 1000), (998_999, 2, 1001)]
        {
            let mut limiter = RateLimit::new(1000, 1000, at_us(0));
            limiter.drain(1000, at_us(0));

            assert_eq!(
                limiter.wait_ms(at_us(queried_at)),
                expected_ms,
                "{remaining_us}us of a step remained"
            );
        }
    }

    #[test]
    fn a_wait_of_one_microsecond_is_never_reported_as_no_wait() {
        // The reason the ceiling matters rather than being cosmetic: zero
        // means "do not wait" to `lib/multi.c:1891`, so truncating would spin
        // the transfer loop instead of idling it.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1000, at_us(0));

        assert!(limiter.wait_ms(at_us(999_999)) > 0);
    }

    #[test]
    fn a_full_step_of_waiting_is_reported_when_nothing_has_elapsed() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1000, at_us(0));

        assert_eq!(limiter.wait_ms(at_us(0)), 1000);
    }

    #[test]
    fn no_wait_is_reported_once_the_step_has_produced_its_tokens() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1000, at_us(0));

        // At exactly one step the update fires, the balance turns positive
        // and the early return at `lib/ratelimit.c:237-238` applies.
        assert_eq!(limiter.wait_ms(at_us(CURL_US_PER_SEC)), 0);
        assert_eq!(limiter.available(at_us(CURL_US_PER_SEC)), 1000);
    }

    #[test]
    fn a_blocked_or_unlimited_limiter_never_asks_for_a_wait() {
        let mut blocked = RateLimit::new(1000, 1000, at_us(0));
        blocked.drain(5000, at_us(0));
        blocked.block(true, at_us(0));
        assert_eq!(blocked.wait_ms(at_us(0)), 0);
        assert_eq!(blocked.next_step_ms(at_us(0)), 0);

        let mut unlimited = RateLimit::new(0, 0, at_us(0));
        assert_eq!(unlimited.wait_ms(at_us(0)), 0);
        assert_eq!(unlimited.next_step_ms(at_us(0)), 0);
    }

    #[test]
    fn debt_adds_whole_percentages_of_a_step_to_the_wait() {
        // C: `debt_pct = ((-r->tokens) * 100 / r->rate_per_step);` then
        // `wait_us += (r->step_us * debt_pct / 100);`
        //
        // A debt of 500 against a rate of 1000 is 50 percent of a step, so
        // half a step is added to the whole step already owed.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1500, at_us(0));

        assert_eq!(limiter.available(at_us(0)), -500);
        assert_eq!(limiter.wait_ms(at_us(0)), 1500);
    }

    #[test]
    fn a_debt_below_one_percent_of_a_step_adds_nothing() {
        // The truncation is deliberate and is the C's `if(debt_pct)` guard:
        // 9 against 1000 is 0.9 percent, which truncates to zero.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1009, at_us(0));

        assert_eq!(limiter.available(at_us(0)), -9);
        assert_eq!(limiter.wait_ms(at_us(0)), 1000);
    }

    #[test]
    fn a_debt_of_exactly_one_percent_adds_one_percent_of_a_step() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1010, at_us(0));

        assert_eq!(limiter.available(at_us(0)), -10);
        // One step plus one percent of a step: 1_010_000us.
        assert_eq!(limiter.wait_ms(at_us(0)), 1010);
    }

    #[test]
    fn the_wait_deducts_the_time_that_has_already_elapsed() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1500, at_us(0));

        // 1_500_000us were owed at the origin; 400_000 of them have passed.
        assert_eq!(limiter.wait_ms(at_us(400_000)), 1100);
    }

    #[test]
    fn the_wait_survives_a_balance_at_the_lower_bound() {
        let big = i64_max_tokens();
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(big, at_us(0));
        limiter.drain(big, at_us(0));
        assert_eq!(limiter.available(at_us(0)), i64::MIN);

        // C's `-r->tokens` is undefined behaviour at `INT64_MIN` and a plain
        // Rust negation would panic. The debt is negated in `i128`, where it
        // is exact, and the resulting wait saturates at the widest value the
        // return type can carry.
        assert_eq!(limiter.wait_ms(at_us(0)), i64::MAX / MILLI);
    }

    #[test]
    fn the_widest_possible_rate_neither_panics_nor_wraps() {
        let mut limiter = RateLimit::new(i64::MAX, i64::MAX, at_us(0));

        assert_eq!(limiter.available(at_us(0)), i64::MAX);
        limiter.drain(1000, at_us(0));
        assert_eq!(limiter.available(at_us(0)), i64::MAX - 1000);

        // Ten steps at a rate of `i64::MAX` is where the C's
        // `rate_per_step > (INT64_MAX / elapsed_steps)` guard earns its keep:
        // the product would overflow, so the gain saturates instead.
        assert_eq!(limiter.available(at_us(10 * CURL_US_PER_SEC)), i64::MAX);
        assert_eq!(limiter.wait_ms(at_us(10 * CURL_US_PER_SEC)), 0);
    }

    // ---- the next step

    #[test]
    fn the_next_step_is_reported_to_the_microsecond_rounded_up() {
        let limiter = RateLimit::new(1000, 1000, at_us(0));

        assert_eq!(limiter.next_step_ms(at_us(0)), 1000);
        assert_eq!(limiter.next_step_ms(at_us(1)), 1000);
        assert_eq!(limiter.next_step_ms(at_us(1000)), 999);
        assert_eq!(limiter.next_step_ms(at_us(999_000)), 1);
        assert_eq!(limiter.next_step_ms(at_us(999_999)), 1);
    }

    #[test]
    fn no_next_step_is_reported_once_a_step_has_passed() {
        let limiter = RateLimit::new(1000, 1000, at_us(0));

        // `if(r->step_us > elapsed_us)` is strict, so the boundary itself
        // reports nothing: the tokens arrive on the next update.
        assert_eq!(limiter.next_step_ms(at_us(CURL_US_PER_SEC)), 0);
        assert_eq!(limiter.next_step_ms(at_us(3 * CURL_US_PER_SEC)), 0);
    }

    #[test]
    fn the_next_step_never_updates_the_limiter() {
        // The transfer loop asks both directions in turn
        // (`lib/multi.c:1904-1905`), so a hidden update here would generate
        // tokens between the two questions.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1000, at_us(0));

        let before = limiter.clone();
        assert_eq!(limiter.next_step_ms(at_us(5_000_000)), 0);
        assert_eq!(limiter, before);
        assert_eq!(
            limiter.available(at_us(5_000_000)),
            1000,
            "the tokens arrive on the update, not on the question"
        );
    }

    // ---- blocking

    #[test]
    fn blocking_zeroes_the_balance_and_unblocking_starts_fresh() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(1000, at_us(0));

        limiter.block(true, at_us(0));
        assert!(limiter.is_blocked());
        assert!(limiter.is_active());
        assert_eq!(limiter.available(at_us(0)), 0);

        // Ten seconds of being blocked. `lib/ratelimit.c:281-283`: "The
        // amount of time this was blocked does not generate extra tokens."
        assert_eq!(limiter.available(at_us(10 * CURL_US_PER_SEC)), 0);

        limiter.block(false, at_us(10 * CURL_US_PER_SEC));
        assert!(!limiter.is_blocked());
        assert_eq!(
            limiter.available(at_us(10 * CURL_US_PER_SEC)),
            1000,
            "one step's worth, not ten"
        );
        assert_eq!(limiter.next_step_ms(at_us(10 * CURL_US_PER_SEC)), 1000);
    }

    #[test]
    fn blocking_an_already_blocked_limiter_does_nothing() {
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.block(true, at_us(0));

        let before = limiter.clone();
        limiter.block(true, at_us(5_000_000));
        assert_eq!(limiter, before, "not even the timestamp moved");
    }

    #[test]
    fn unblocking_a_limiter_that_is_not_blocked_does_nothing() {
        // The early return at `lib/ratelimit.c:275-276` is what makes it safe
        // for `lib/request.c:162-163` to unblock both directions at the start
        // of every request: without it, an unblock would reset the balance
        // and the timestamp of a limiter that was already running.
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.drain(400, at_us(0));

        let before = limiter.clone();
        limiter.block(false, at_us(5_000_000));
        assert_eq!(limiter, before);
        assert_eq!(limiter.available(at_us(0)), 600, "the debt is still owed");
    }

    #[test]
    fn a_blocked_unlimited_limiter_reports_itself_active_and_offers_nothing() {
        // The disjunct of `Curl_rlimit_active` that is easy to miss: a
        // limiter with no rate still has something to say once it is
        // blocked, and a transfer loop that consulted only the rate would run
        // a paused transfer at full speed.
        let mut limiter = RateLimit::new(0, 0, at_us(0));
        assert!(!limiter.is_active());

        limiter.block(true, at_us(0));
        assert!(limiter.is_active());
        assert_eq!(limiter.available(at_us(5_000_000)), 0);

        limiter.block(false, at_us(5_000_000));
        assert!(!limiter.is_active());
        assert_eq!(limiter.available(at_us(5_000_000)), i64::MAX);
    }

    #[test]
    fn a_pause_is_distinct_from_a_debt() {
        // `lib/transfer.c:896` and `:906` express a pause as a block, and
        // `lib/progress.c:342-356` expresses consumption as a drain. The two
        // must not be conflated: unblocking clears the balance rather than
        // restoring the debt that was owed when the pause began.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.drain(2000, at_us(0));
        assert_eq!(limiter.available(at_us(0)), -1000);

        limiter.block(true, at_us(0));
        limiter.block(false, at_us(0));
        assert_eq!(limiter.available(at_us(0)), 1000);
    }

    // ---- starting, and the step tuning that happens there

    #[test]
    fn starting_resets_the_balance_and_the_spare_microseconds() {
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.drain(1500, at_us(0));
        assert_eq!(limiter.available(at_us(0)), -500, "500 in debt");
        // One step later the debt is paid off and 200_000us of the interval
        // are left over as spare.
        assert_eq!(limiter.available(at_us(1_200_000)), 500);
        assert_eq!(limiter.next_step_ms(at_us(1_200_000)), 800);

        limiter.start(at_us(1_200_000), -1);
        assert_eq!(limiter.available(at_us(1_200_000)), 1000);
        assert_eq!(
            limiter.next_step_ms(at_us(1_200_000)),
            1000,
            "the spare microseconds are discarded, not carried"
        );
    }

    #[test]
    fn an_unknown_or_trivial_total_leaves_the_step_untuned() {
        // -1 is how every call site but `lib/sendf.c:202` spells "unknown",
        // and the guard at `lib/ratelimit.c:102` catches 0 and 1 with it.
        for total in [-1, 0, 1] {
            let mut limiter = RateLimit::new(1000, 1000, at_us(0));
            limiter.start(at_us(0), total);

            assert_eq!(limiter.per_step(), 1000, "total {total}");
            assert_eq!(limiter.next_step_ms(at_us(0)), 1000, "total {total}");
            assert_eq!(limiter.available(at_us(0)), 1000, "total {total}");
        }
    }

    #[test]
    fn a_total_too_large_to_scale_leaves_the_step_untuned() {
        // `lib/ratelimit.c:103`: a total above `INT64_MAX / 1000` is refused,
        // because `tokens_main * 1000` is what the tuning divides.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.start(at_us(0), i64::MAX / MSTEPS_PER_STEP + 1);

        assert_eq!(limiter.per_step(), 1000);
        assert_eq!(limiter.next_step_ms(at_us(0)), 1000);
    }

    #[test]
    fn the_widest_accepted_total_is_handled_without_overflow() {
        // The boundary the guard admits, `INT64_MAX / 1000` exactly, which is
        // where `tokens_main * 1000` comes within 4e18 of leaving the type.
        // It is accepted, and then declines to tune because the remainder is
        // far too small to spread -- so the observable outcome is "no
        // change", and the value of the test is that it neither panics nor
        // wraps on the way there.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.start(at_us(0), i64::MAX / MSTEPS_PER_STEP);

        assert_eq!(limiter.per_step(), 1000);
        assert_eq!(limiter.next_step_ms(at_us(0)), 1000);
    }

    #[test]
    fn an_unlimited_limiter_is_never_tuned() {
        let mut limiter = RateLimit::new(0, 0, at_us(0));
        limiter.start(at_us(0), 100_000);

        assert_eq!(limiter.per_step(), 0);
        assert_eq!(limiter.available(at_us(0)), i64::MAX);
    }

    #[test]
    fn a_transfer_needing_under_two_millisteps_is_left_untuned() {
        // `lib/ratelimit.c:121-124`: "Steps this small will not work."
        // 2000 tokens at a megabyte a second is 1980 main tokens, which is
        // one milli-step after truncation -- below
        // `CURL_RLIMIT_STEP_MIN_MS`.
        let mut limiter = RateLimit::new(1_000_000, 1_000_000, at_us(0));
        limiter.start(at_us(0), 2000);

        assert_eq!(limiter.per_step(), 1_000_000);
        assert_eq!(limiter.next_step_ms(at_us(0)), 1000);
        assert_eq!(CURL_RLIMIT_STEP_MIN_MS, 2, "the threshold being tested");
    }

    #[test]
    fn a_transfer_that_fits_in_one_shortened_step_gets_exactly_that_step() {
        // 100 tokens at 1000 a second: the last step takes 1, the other 99
        // are delivered in a single step of 99 milliseconds at a rate of 99.
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.start(at_us(0), 100);

        assert_eq!(limiter.per_step(), 99);
        assert_eq!(limiter.next_step_ms(at_us(0)), 99);
        assert_eq!(limiter.available(at_us(0)), 99);
    }

    #[test]
    fn the_c_s_own_example_of_1500_tokens_at_1000_a_second() {
        // `lib/ratelimit.c:93-95`: without tuning, "downloading 1.5kb with a
        // ratelimit of 1k could be done in roughly 1 second". Tuning gives
        // the main 1485 tokens a step of 1.485 seconds, so the transfer takes
        // the time the rate limit implies instead.
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.start(at_us(0), 1500);

        assert_eq!(limiter.per_step(), 1485);
        assert_eq!(limiter.next_step_ms(at_us(0)), 1485);
        assert_eq!(limiter.available(at_us(0)), 1485);
    }

    #[test]
    fn a_multi_step_transfer_spreads_the_remainder_across_its_steps() {
        // 2500 tokens at 1000 a second: 25 for the last step, 2475 to spread.
        // That is 2475 millisteps, or two steps and 475 millisteps left over;
        // dividing the leftover across the two steps lengthens each by 237
        // millisteps and enriches each by 237 tokens.
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.start(at_us(0), 2500);

        assert_eq!(limiter.per_step(), 1237);
        assert_eq!(limiter.next_step_ms(at_us(0)), 1237);
    }

    #[test]
    fn a_remainder_too_small_to_spread_leaves_the_step_untuned() {
        // `mstep_inc` is zero here: 10005 millisteps is ten steps with five
        // millisteps left over, and five spread across ten steps is nothing.
        // The C's `if(mstep_inc)` then leaves every field alone -- which is
        // not the same as adding zero, because adding zero would still have
        // reset the balance.
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.start(at_us(0), 10_106);

        assert_eq!(limiter.per_step(), 1000);
        assert_eq!(limiter.next_step_ms(at_us(0)), 1000);
    }

    #[test]
    fn a_rate_increase_that_truncates_to_zero_leaves_the_step_untuned() {
        // `rate_inc` is zero here even though `mstep_inc` is not: 5 tokens at
        // 3 a second gives 1333 millisteps, a leftover of 333 to spread over
        // one step, and a rate increase of 3 * 333 / 1000, which truncates to
        // nothing. The C's `if(rate_inc)` declines to lengthen a step it
        // cannot enrich, because doing so would pace the transfer BELOW its
        // rate limit.
        let mut limiter = RateLimit::new(3, 0, at_us(0));
        limiter.start(at_us(0), 5);

        assert_eq!(limiter.per_step(), 3);
        assert_eq!(limiter.next_step_ms(at_us(0)), 1000);
    }

    #[test]
    fn the_last_step_gets_at_least_one_token() {
        // `lib/ratelimit.c:107-109`: one percent of 50 is zero, and "less
        // than 100 total, just use 1". The main budget is therefore 49 rather
        // than 50, which is what `per_step` reports back.
        let mut limiter = RateLimit::new(1000, 0, at_us(0));
        limiter.start(at_us(0), 50);

        assert_eq!(limiter.per_step(), 49);
        assert_eq!(limiter.next_step_ms(at_us(0)), 49);
    }

    #[test]
    fn the_last_step_gets_at_most_four_kilobytes_of_tokens() {
        // One percent of a million is 10,000, which `lib/ratelimit.c:110-111`
        // caps at `CURL_RLIMIT_MIN_RATE`. The cap is observable: with it the
        // main budget is 995,904 and the tuned rate 110,600, while an
        // uncapped last step of 10,000 would have produced 110,000.
        let mut limiter = RateLimit::new(100_000, 0, at_us(0));
        limiter.start(at_us(0), 1_000_000);

        assert_eq!(CURL_RLIMIT_MIN_RATE, 4096, "the cap being tested");
        assert_eq!(limiter.per_step(), 110_600);
        assert_ne!(limiter.per_step(), 110_000, "the uncapped counterfactual");
        assert_eq!(limiter.next_step_ms(at_us(0)), 1106);
    }

    #[test]
    fn tuning_moves_an_existing_burst_cap_to_the_tuned_rate() {
        // `lib/ratelimit.c:148-149`: a limiter that had a cap keeps one, at
        // the tuned rate. Without the move, the old cap of 1000 would sit
        // above the tuned rate of 99 and let ten steps' worth of tokens bank.
        let mut capped = RateLimit::new(1000, 1000, at_us(0));
        capped.start(at_us(0), 100);
        assert_eq!(capped.per_step(), 99);
        // Five tuned steps of idleness, capped back to one step's worth.
        assert_eq!(capped.available(at_us(495_000)), 99);
    }

    #[test]
    fn tuning_does_not_invent_a_burst_cap() {
        // The same `if(r->burst_per_step)` guard, read the other way: a
        // limiter without a cap is not given one, so five tuned steps of
        // idleness really do bank five steps' worth.
        let mut uncapped = RateLimit::new(1000, 0, at_us(0));
        uncapped.start(at_us(0), 100);
        assert_eq!(uncapped.per_step(), 99);

        assert_eq!(uncapped.available(at_us(495_000)), 99 + 5 * 99);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "already tuned")]
    fn tuning_a_second_time_stops_a_debug_build() {
        // `lib/ratelimit.c:118` asserts that the step is still one second,
        // which is what confines a sized start to once per request --
        // `lib/sendf.c:200-204` guards it with `!ctx->started_body`.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        limiter.start(at_us(0), 100);
        limiter.start(at_us(0), 100);
    }

    #[test]
    fn an_unsized_start_may_be_repeated_because_it_never_tunes() {
        // The counterpart of the test above, and the reason unblocking is
        // allowed to call `start` on every pause cycle: a total of -1 returns
        // before the assertion, so the step is never touched.
        let mut limiter = RateLimit::new(1000, 1000, at_us(0));
        for _ in 0..4 {
            limiter.start(at_us(0), -1);
        }

        assert_eq!(limiter.per_step(), 1000);
        assert_eq!(limiter.next_step_ms(at_us(0)), 1000);
    }

    // ---- the two end-to-end pacing scenarios

    /// Runs `total` tokens through `limiter` on a virtual clock, waiting
    /// whenever it asks to, and returns the microseconds the transfer took.
    ///
    /// This is the C's transfer loop reduced to its pacing:
    /// `lib/multi.c:1880-1899` asks for a wait and idles for it,
    /// `lib/transfer.c:251-256` sizes the next read by the available tokens,
    /// and `lib/progress.c:342-347` drains what was delivered.
    fn deliver(limiter: &mut RateLimit, total: usize) -> TimeDiff {
        let clock = TestClock::new(at_us(0));
        let mut remaining = total;

        while remaining > 0 {
            let wait_ms = limiter.wait_ms(clock.now());
            if wait_ms > 0 {
                clock.advance(Duration::from_millis(
                    u64::try_from(wait_ms).expect("a positive wait"),
                ));
                continue;
            }

            let offered = limiter.available(clock.now());
            assert!(offered > 0, "no wait was asked for, so tokens are due");
            let chunk = usize::try_from(offered)
                .unwrap_or(usize::MAX)
                .min(remaining);
            limiter.drain(chunk, clock.now());
            remaining -= chunk;
        }

        timediff_us(clock.now(), at_us(0))
    }

    #[test]
    fn tuning_makes_a_small_transfer_take_its_rate_limited_time() {
        // The C's example of `lib/ratelimit.c:93-95`, measured both ways.
        //
        // Untuned, 1500 tokens at 1000 a second finish in one second: the
        // bucket starts full, so 1000 go immediately and the remaining 500
        // go at the start of the second step. That is 1500 a second --
        // 50 percent above the limit.
        let mut untuned = RateLimit::new(1000, 1000, at_us(0));
        assert_eq!(deliver(&mut untuned, 1500), 1_000_000);

        // Tuned, the same transfer takes 1.485 seconds, which is 1010 tokens
        // a second. The residual overshoot is the one percent the last step
        // is deliberately given.
        let mut tuned = RateLimit::new(1000, 1000, at_us(0));
        tuned.start(at_us(0), 1500);
        assert_eq!(deliver(&mut tuned, 1500), 1_485_000);
    }

    #[test]
    fn limit_rate_paces_the_two_directions_independently() {
        // `--limit-rate 1000` sets both `CURLOPT_MAX_RECV_SPEED_LARGE` and
        // `CURLOPT_MAX_SEND_SPEED_LARGE`, and `lib/setopt.c:2801` and `:2812`
        // pass the value as the rate AND the burst -- so the two directions
        // are two limiters with identical settings and no shared state.
        let mut download = RateLimit::new(1000, 1000, at_us(0));
        let mut upload = RateLimit::new(1000, 1000, at_us(0));

        download.drain(1000, at_us(0));
        assert_eq!(download.available(at_us(0)), 0);
        assert_eq!(
            upload.available(at_us(0)),
            1000,
            "draining one direction must not throttle the other"
        );

        // The transfer loop waits the MAXIMUM of the two waits
        // (`lib/multi.c:1895`), because waiting the shorter one would return
        // with the other direction still throttled.
        let recv_ms = download.wait_ms(at_us(0));
        let send_ms = upload.wait_ms(at_us(0));
        assert_eq!(recv_ms, 1000);
        assert_eq!(send_ms, 0);
        assert_eq!(recv_ms.max(send_ms), 1000);

        // Four kilo-tokens at 1000 a second takes three seconds in either
        // direction: the full bucket pays for the first thousand.
        let mut fresh_download = RateLimit::new(1000, 1000, at_us(0));
        let mut fresh_upload = RateLimit::new(1000, 1000, at_us(0));
        let down_us = deliver(&mut fresh_download, 4000);
        let up_us = deliver(&mut fresh_upload, 4000);
        assert_eq!(down_us, 3_000_000);
        assert_eq!(up_us, down_us, "one primitive, so one pacing");
    }

    #[test]
    fn the_next_step_wake_up_takes_the_minimum_with_a_maximum_fallback() {
        // `lib/multi.c:1902-1913`: when neither direction needs to wait, the
        // loop still has to be woken when tokens next arrive "or it may
        // stall". It takes the minimum of the two answers and falls back to
        // the maximum when the minimum is zero -- so that an unlimited
        // direction, which answers zero, cannot cancel the wake-up the
        // limited direction needs. The rule lives in the loop; this test
        // pins the values this module feeds it.
        let limited = RateLimit::new(1000, 1000, at_us(0));
        let unlimited = RateLimit::new(0, 0, at_us(0));

        let recv_ms = limited.next_step_ms(at_us(0));
        let send_ms = unlimited.next_step_ms(at_us(0));
        assert_eq!(recv_ms, 1000);
        assert_eq!(send_ms, 0);

        let mut next_ms = recv_ms.min(send_ms);
        if next_ms == 0 {
            next_ms = recv_ms.max(send_ms);
        }
        assert_eq!(next_ms, 1000);
    }
}
