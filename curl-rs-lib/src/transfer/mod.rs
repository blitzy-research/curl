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
//! The transfer core: the loop, its buffers and its accounting.
//!
//! Supersedes `lib/transfer.c` (the transfer loop, which becomes async),
//! `lib/request.c` (per-request state), `lib/sendf.c` (manual buffers become
//! `BytesMut`), `lib/cw-out.c` with `lib/cw-pause.c` (the client-writer chain
//! and pause handling), `lib/progress.c` (accounting, with the output format
//! frozen), `lib/ratelimit.c` (`--limit-rate` pacing),
//! `lib/content_encoding.c` (zlib, brotli and zstd calls become `flate2`,
//! `brotli` and `zstd`) and `lib/http_chunks.c` (chunked framing, byte-exact
//! in both directions).
//!
//! `pub(crate)`: a transfer is driven through an easy or a multi handle, and
//! no exported symbol names a transfer directly.
//!
//! This is one of the two directories the line-coverage gate of
//! specification 0.8.4 measures, at 80 percent of lines or better. Almost
//! everything here is time-driven, so the clock reaches this directory by
//! injection -- as a [`CurlTime`] parameter or a [`Clock`] reference from
//! `crate::util::timeval` -- and never by reading the host clock. A module
//! that read the clock itself could not be tested deterministically, and the
//! gate would be out of reach.
//!
//! [`CurlTime`]: crate::util::timeval::CurlTime
//! [`Clock`]: crate::util::timeval::Clock
//!
//! # Partially delivered
//!
//! Of this module's planned children, [`ratelimit`], [`progress`], [`sendf`],
//! [`request`], [`writeout`], [`chunked`] and [`content_encoding`] exist. The
//! transfer loop itself arrives with its own file, and each declaration lands
//! WITH its file -- a `mod` line without a file is `error[E0583]`, which no
//! attribute can reach, because module resolution never gets far enough to
//! produce a lint.
//!
//! The order in which they compose is dependency order rather than
//! preference. [`ratelimit`] came first because it depends on nothing but the
//! utility layer: it is a self-contained arithmetic primitive that progress
//! accounting EMBEDS, following `lib/urldata.h:786-791`, where
//! `struct pgrs_dir` carries a `struct Curl_rlimit` as a member. [`progress`]
//! is second, and it is the only module in this directory that may name
//! [`ratelimit`]; nothing may invert that direction.

/// Transfer accounting and timing: supersedes `lib/progress.c` and
/// `lib/progress.h`.
///
/// Owns the state `CURLINFO_*_T`, the progress callbacks, the low-speed abort
/// and `--write-out`'s `%{time_*}`, `%{size_*}` and `%{speed_*}` variables all
/// read -- the measured `struct Progress` and `struct pgrs_dir` of
/// `lib/urldata.h:786-831`.
///
/// It renders nothing. The built-in meter's layout, `time2str` and `max6out`
/// belong to `curl-rs/src/output/progress.rs` and
/// `curl-rs/src/callbacks/progress.rs`, where the emitted bytes are frozen;
/// this module preserves every value they read and hands it over in one
/// snapshot. It reads no clock and arms no timer either: an instant arrives as
/// a parameter or a `Clock` to sample, and the low-speed check RETURNS the
/// `EXPIRE_SPEEDCHECK` request rather than making it.
pub(crate) mod progress;

/// The client reader and writer chains: supersedes `lib/sendf.c` and
/// `lib/sendf.h`.
///
/// The shared substrate of this directory. Every response byte in the crate
/// reaches the application through `ClientIo::client_write` and every request
/// byte leaves it through `ClientIo::client_read`, so `writeout`, `chunked`,
/// `content_encoding` and `request` all compose out of the two traits declared
/// here -- `ClientWriter` and `ClientReader` -- rather than out of a
/// per-protocol arrangement of their own.
///
/// It names neither this module root nor `writeout`: `lib/sendf.c` includes
/// `transfer.h`, `cw-out.h` and `cw-pause.h`, and all three include `sendf.h`
/// straight back, so the C's include cycle would become a module cycle. What
/// the C reaches through those includes for arrives instead as three narrow
/// seams the dependency-last engine implements -- `TransferControl` for the
/// three operations that belong to the transfer loop, `ClientIoFactory` for the
/// two writer stages `lib/cw-out.c` and `lib/cw-pause.c` own, and `TraceSink`
/// for the five diagnostic emitters. The base writer stack is still assembled
/// HERE, in the exact order of `lib/sendf.c:325-368`, because that order is the
/// contract: the pause stage is installed FIRST and therefore ends up BEHIND
/// the download stage, so a length check happens before any byte is buffered
/// for a paused transfer.
///
/// It reads no clock either. The one instant it needs arrives as an injected
/// [`Clock`], which is what lets the upload rate-limit clamp and the
/// `TIMER_STARTTRANSFER` record be asserted deterministically.
///
/// [`Clock`]: crate::util::timeval::Clock
pub(crate) mod sendf;

/// Per-request state: supersedes `lib/request.c` and `lib/request.h`.
///
/// One `SingleRequest` covers one request attempt -- its counters, its upload
/// send queue, its send and flush path, its pause and blocking predicates, its
/// completion, and the redirect and retry bookkeeping that carries an
/// operation from one attempt to the next.
///
/// It names neither this module root nor a protocol module, and both omissions
/// are structural. `lib/request.c` includes `transfer.h` and `url.h`, which
/// include `request.h` straight back, so the C's include cycle would become a
/// module cycle; and `Curl_http_follow` lives in `lib/http.c`, so a literal
/// transcription would put HTTP inside the request layer. What the C reaches
/// through those includes for arrives instead as two narrow seams the
/// dependency-last engine and the protocol modules implement -- `RequestIo` for
/// the transport, client-chain, resolver, progress and diagnostic operations,
/// and `ProtocolFollow` for the URL, scheme, port and request-method work a
/// redirect needs. The bookkeeping around that work -- the counters, the
/// ceiling, the fake-follow storage, the soft reset and the frozen log lines --
/// stays here, so no protocol module reimplements it.
///
/// It reads no clock. Every instant arrives through `RequestIo::pgrs_now`,
/// which is `Curl_pgrs_now` (`lib/progress.c:171-177`), so the request start
/// time and the `TIMER_POSTRANSFER` record are both assertable against a
/// pinned [`TestClock`].
///
/// [`TestClock`]: crate::util::timeval::TestClock
pub(crate) mod request;

/// The token bucket behind `--limit-rate`: supersedes `lib/ratelimit.c` and
/// `lib/ratelimit.h`.
///
/// Serves `CURLOPT_MAX_RECV_SPEED_LARGE` and `CURLOPT_MAX_SEND_SPEED_LARGE`,
/// which is what the command-line tool sets for `--limit-rate`, and the
/// pause mechanism, which is expressed as a blocked limiter rather than as a
/// separate flag.
///
/// It computes durations and nothing else: no timer is armed here, and no
/// transfer state is touched, so the `PERFORMING` and `RATELIMITING`
/// transitions and the `TOOFAST` expiry identifier belong to the transfer
/// loop that consumes it. The contract between the two is transcribed from
/// `lib/multi.c:1880-1921` into the documentation of the module's `wait_ms`
/// and `next_step_ms`.
pub(crate) mod ratelimit;

/// The client-output and pause-handling writer stages: supersedes
/// `lib/cw-out.c` with `lib/cw-out.h` and `lib/cw-pause.c` with
/// `lib/cw-pause.h`.
///
/// The bottom of the writer chain, and the only module in the crate that
/// invokes `CURLOPT_WRITEFUNCTION` and `CURLOPT_HEADERFUNCTION`. It owns the
/// two stages [`sendf`] deliberately does not name -- `cw-out` at
/// `CURL_CW_CLIENT` and `cw-pause` at `CURL_CW_PROTOCOL`, both reached there
/// through `ClientIoFactory` -- together with the ordered buffering that makes
/// `curl_easy_pause` replay a paused transfer's bytes in their original order,
/// and the `hds-collect` stage that fills the store `curl_easy_header` reads.
///
/// It depends on [`sendf`] and never the other way round, which is what keeps
/// the C's `sendf.h` / `cw-out.h` / `cw-pause.h` include cycle from becoming a
/// module cycle. It does not name this module root either: the one operation it
/// needs from the transfer loop, `Curl_xfer_pause_recv`, arrives through
/// `sendf`'s `TransferControl` seam.
pub(crate) mod writeout;

/// HTTP/1.1 chunked transfer coding, in both directions: supersedes
/// `lib/http_chunks.c` and `lib/http_chunks.h`.
///
/// The receive state machine that de-frames a chunked response body and its
/// trailers, and the encoder that frames a chunked request body -- both
/// byte-exact, because 1,476 of the fixtures under `tests/data/` compare the
/// bytes on the wire as one string and would fail on a size line spelled with
/// a different case or a leading zero. Chunk framing is therefore NOT
/// delegated to hyper, which manages the connection and nothing about these
/// bytes.
///
/// It depends on [`sendf`] for the two chain contracts and on nothing else in
/// this directory, and it names neither [`writeout`] nor a protocol module.
/// The C reaches through `struct Curl_easy` for a downstream writer, a source
/// reader and `CURLOPT_TRAILERFUNCTION`; all three arrive here as narrow seams
/// the consumer implements, which is also what lets the parser be driven from
/// memory, one byte at a time, without a network.
pub(crate) mod chunked;

/// Content and transfer decoding: supersedes `lib/content_encoding.c` and
/// `lib/content_encoding.h`.
///
/// The registry of decoders this build compiled, the `Accept-Encoding` token
/// list that registry produces, and the construction of the unencoding writer
/// stack from a `Content-Encoding` or `Transfer-Encoding` header value. The
/// C's zlib, brotli and zstd calls become `flate2` on its pure-Rust backend,
/// `brotli` and `zstd`; every registry order, separator byte, state machine
/// and refusal point is transcribed rather than reinterpreted.
///
/// It depends on [`sendf`] for the writer contract and on [`chunked`] for the
/// one transfer coding it installs without owning -- `"chunked"`, whose stage
/// arrives through `chunked::transfer_unencoder` -- and it names no protocol
/// module: HTTP/1 assembly CONSUMES this module, both to install the stack
/// from a response header and to emit `Accept-Encoding` with the exact bytes
/// and order `content_encodings` produces.
///
/// Decoding is streamed. Each stage decompresses into a fixed 16 KiB window
/// and forwards what it produced immediately, so a highly compressible body
/// costs a bounded amount of resident memory rather than its expanded size,
/// and a downstream refusal returns that stage's own code unchanged.
pub(crate) mod content_encoding;
