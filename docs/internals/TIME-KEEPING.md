<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Keeping Time

Transfers need the current time to handle timeouts and keep a record of
events. The current time function is `curlx_now()` and it uses a **monotonic**
clock on most platforms. This ensures that time only ever increases (the
timestamps it gives are however not the "real" world clock).

## Initial Approach (now historic)

The loop processing functions called `curlx_now()` at the beginning and then
passed a pointer to the `struct curltime now` to functions to save them the
calls. Passing this pointer down to all functions possibly involved was not
done as this pollutes the internal APIs.

So, some functions continued to call `curlx_now()` on their own while others
used the passed pointer *to a timestamp in the past*. This led to a transfer
experiencing *jumps* in time, reversing cause and effect. On fast systems,
this was mostly not noticeable. On slow machines or in CI, this led to rare
and annoying test failures.

(Especially when we added assertions that the reported "timeline" of a
transfer was in the correct order: *queue -> nameloopup -> connect ->
appconnect ->...*.)

## Revised Approach

The strategy of handling transfer's time is now:

* Keep a "now" timestamp in the multi handle. Keep a fallback "now" timestamp
  in the easy handle.
* Always use `Curl_pgrs_now(data)` to get the current time of a transfer.
* Do not use `curlx_now()` directly for transfer handling (exceptions apply
  for loops).

This has the following advantages:

* No need to pass a `struct curltime` around or pass a pointer to an outdated
  timestamp to other functions.
* No need to calculate the exact `now` until it is really used.
* Passing a `const` pointer is better than struct passing. Updating and
  passing a pointer to the same memory location for all transfers is even
  better.

Caveats:

* do not store the pointer returned by `Curl_pgrs_now(data)` anywhere that
  outlives the current code invocation.

## The C Mechanism as Reference Oracle

The C implementation described above stays in the tree as the reference
oracle for this behavior. `lib/curlx/timeval.c` reads the clock and computes
differences from it, `lib/curlx/timediff.c` converts those differences to and
from the shapes the wait calls take, and `lib/progress.c` holds the
per-handle accessor that the revised approach describes: `Curl_pgrs_now(data)`
refreshes the "now" in the multi handle when the transfer has one, or the easy
handle copy when it does not, and hands back a pointer to it.

Four properties of that mechanism are behavior rather than implementation
detail, and any replacement has to keep all four:

* **Monotonic against wall clock.** Timeouts, transfer timing and the retry
  logic are computed on a clock that does not move backwards. The timestamps
  reported to a user, and the date values that go on the wire, come from the
  wall clock instead. Conflating the two changes observable behavior in both
  directions: a timeout that a clock adjustment can shorten or stretch, or a
  reported date that no calendar recognizes.
* **One "now" per iteration.** The revised approach exists because a single
  operation has to observe one consistent instant. That property, and not the
  name of the accessor, is the contract.
* **Resolution.** Time differences are computed in the units the timeout
  options are expressed in, and the arithmetic guards against negative and
  overflowing differences rather than letting them wrap.
* **Lifetime.** The returned pointer is valid only for the current
  invocation. That is a hazard of the C interface, and it is the kind of
  hazard the specified migration removes.

## The `Rust` Successors

Both successors are **delivered**. The paths below name code that exists and is
tested, and the C files remain the reference oracle. The mapping is recorded so
that the contract above is checkable against the implementation rather than
merely intended.

* `curl-rs-lib/src/util/timeval.rs` succeeds `lib/curlx/timeval.c`. It covers
  the clock reading and, following the C, the difference helpers that
  `timeval.c` keeps beside it: the millisecond and microsecond differences and
  the ceiling variant.
* `curl-rs-lib/src/util/timediff.rs` succeeds `lib/curlx/timediff.c`. It covers
  the difference type itself, its bounds and the two conversions between
  milliseconds and a duration -- the mapping that tells a reactor whether to
  block indefinitely, poll without blocking or wait a bounded time.

Both are among the six `lib/curlx/` sources specified to receive a dedicated
module rather than being absorbed into a shared utility module; see
[`curlx`](CURLX.md).

### Two clocks, one reading type

The two clocks are distinct and injected, but the reading they hand back is one
type, and this is where the delivered code differs from a design that separated
them. A monotonic reading and a wall-clock reading are both a pair of seconds
and microseconds, and which of the two a value holds depends on the clock that
produced it rather than on its type, exactly as in the C. Mixing them is
therefore still a rule to observe rather than something the compiler refuses.

The reason is the coverage requirement rather than preference. The standard
library's opaque instant cannot be constructed at a chosen value, so a test
could not place a transfer at a known point in time, and the line-coverage gate
over the time-driven modules would be out of reach. A constructible reading type
is what makes a controllable clock possible; that clock is what makes the gate
reachable. The safety the migration does gain here is narrower and real: reading
a clock happens in exactly one module, so nothing else in the engine can consult
the wall clock by accident.

### One "now" per iteration, owned rather than pointed to

The per-iteration instant is specified to be owned by the multi handle in
`curl-rs-lib/src/multi/mod.rs` and read from there, with the same fallback
for a handle driven on its own. Because the instant is owned rather than
reached through a pointer, the lifetime caveat above becomes a borrow the
compiler checks: retaining the value past the point where it is valid draws
an objection from the borrow checker. That removes the documented hazard by
construction rather than by convention.

### Expiry and the timeout budget

The C timeout for name resolution arms `alarm()` and leaves the signal
handler through `sigsetjmp` and `siglongjmp`, a non-local jump across
allocation boundaries. That is the single most hazardous construct the
specified migration removes, and `tokio::time::timeout` replaces it. The wait
point itself belongs to [Multi Event Based](MULTI-EV.md), which owns the
runtime story.

The budget arithmetic stays here. Which deadline applies, and how much of it
remains, is specified to be computed by `util/timediff.rs` against the expiry
ledger in `curl-rs-lib/src/util/splay.rs`; see [splay](SPLAY.md). The runtime
supplies the waiting, not the policy.

### Injecting the clock

The clock is specified as an injected dependency rather than something a
module reaches for globally. A test can therefore hand a protocol or transfer
module a clock it drives itself and exercise a timeout or a retry decision
without waiting for real time to elapse. That is a testability consequence,
claimed as nothing else.

### Where `unsafe` is allowed

The safety invariant at the root of `curl-rs-lib` is `#![deny(unsafe_code)]`
plus exactly one `#[allow(unsafe_code)]`, on `mod ffi` -- the one narrowly
allowed island under `curl-rs-lib/src/ffi/`, where every `unsafe` block carries
a mandatory `// SAFETY:` comment. It is `deny` and not `forbid` because
`forbid` cannot be locally overridden (`error[E0453]: allow(unsafe_code)
incompatible with previous forbid`) and Agent Action Plan goal G1 permits only
three crates, so the island cannot move into a fourth; `deny` is no weaker,
since a stray `unsafe` block outside the island is a hard error rather than a
warning.
Reading a clock is a standard-library operation and does not belong in that
island. The residual
platform calls that do belong there are named in [`curlx`](CURLX.md).
