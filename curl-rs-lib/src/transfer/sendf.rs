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
// THE LICENCE BANNER ABOVE -- 23 lines, byte-identical to the banner that
// heads `lib/sendf.c:1-23` with the C block comment converted to line
// comments, and byte-identical to the banners of `transfer/progress.rs` and
// `transfer/ratelimit.rs` beside it. The licence tag appears exactly once, on
// line 21, and nowhere else in this file -- not even in prose -- because
// `reuse` reads every line carrying the tag's colon form as a licence
// expression, so a second mention becomes a parse error rather than a
// comment.
//
// `dead_code` IS NOT ALLOWED for this file as a whole, and no attribute below
// grants it at module scope. Items whose consumers have yet to land carry
// their own `#[allow(dead_code)]`, so the suppressions read as an inventory:
// each one is load-bearing, deleting any one restores a warning, and an item
// added later with no consumer is still reported. That is enforced rather
// than agreed -- `mod source_policy` in `curl-rs-lib/src/lib.rs` walks the
// workspace at test time and fails on a `dead_code` level set on any crate
// root or module root.
//
// The allowances here are expected to be short-lived, and their pattern is
// structural: this module is the COMPOSITION MECHANISM for the reader and
// writer chains, so most of its consumers are the stages themselves --
// `transfer/writeout.rs`, `transfer/content_encoding.rs`,
// `transfer/chunked.rs`, `transfer/request.rs`, `protocols/ftp/mod.rs` and
// `protocols/ws.rs` -- together with the transfer loop that drives a chain.
// None of them exists yet. Each allowance is deleted when its consumer
// lands.
//
// No level for the `unsafe_code` lint is set here, at any level, and the
// keyword itself does not appear in any expression in this file. `src/lib.rs`
// carries `#![deny(unsafe_code)]` and grants exactly ONE exemption, on
// `mod ffi`. That matters more here than in most of the crate: the C
// original is built out of two raw context pointers that every stage casts to
// its own type, out of intrusive `next` pointers, and out of an allocation
// size carried in a vtable, and reproducing the same composition with typed
// owned values is this module's entire reason to exist.
//
// No `libc`, no raw pointer, no `extern` function, no `#[repr(C)]` and no
// `Any` downcast appears below either. Nor is any host clock read: the one
// instant this module needs arrives through the injected `Clock` of
// `crate::util::timeval`, which is what lets every rate-limit and
// start-transfer assertion in the test module below be pinned.

//! The client reader and writer chains -- supersedes `lib/sendf.c` (1,475
//! lines) and `lib/sendf.h` (423).
//!
//! Measured against `lib/sendf.h:42-421` and `lib/sendf.c:47-1475`, with
//! buffer policy from `lib/bufq.c` and `lib/curlx/dynbuf.c`, contract context
//! from `lib/cw-out.c`, `lib/cw-pause.c`, `lib/progress.c` and
//! `lib/request.h:56-134`, and the callback vocabulary from
//! `include/curl/curl.h:258-456`.
//!
//! libcurl sits between an application and a server. Response bytes travel
//! from the server, through this module's WRITER chain, to the callbacks the
//! application registered; request bytes travel from the application, through
//! this module's READER chain, to the server. Everything in the crate that
//! handles response data ultimately forwards it through
//! [`ClientIo::client_write`], and everything that needs request data
//! ultimately pulls it through [`ClientIo::client_read`]. That is why this
//! file is the shared substrate for `transfer/writeout.rs`,
//! `transfer/chunked.rs`, `transfer/content_encoding.rs`,
//! `transfer/request.rs` and the transfer loop.
//!
//! # What the C expresses, and how
//!
//! Four structures, and each one becomes a different Rust construct:
//!
//! * `struct Curl_cwtype` (`lib/sendf.h:110-121`) -- a name, an optional
//!   alias, three function pointers and `size_t cwriter_size`. It is the
//!   strategy pattern written without language support for it, so it becomes
//!   [`ClientWriter`], a trait. The allocation size disappears: a Rust value
//!   knows its own size.
//! * `struct Curl_cwriter` (`lib/sendf.h:129-134`) -- a vtable pointer, a
//!   `next` pointer, a `void *ctx` and a phase. The `ctx` is documented there
//!   as *"the pointer from the allocation of the `struct Curl_cwriter` itself
//!   ... suitable for 'downcasting' by the writers implementation"*, a device
//!   introduced to dodge the alignment problems of curl PR 13054. There is
//!   nothing to downcast here: a stage's state lives in its own type, in its
//!   own fields.
//! * `struct Curl_crtype` and `struct Curl_creader` (`lib/sendf.h:214-253`)
//!   -- the same shape for the read direction, with ten function pointers
//!   instead of three. They become [`ClientReader`].
//! * The `next` chains become owned collections, [`ClientWriterStack`] and
//!   [`ClientReaderStack`]. A stage no longer owns its successor, so no stage
//!   can free a successor another stage still holds; instead the STACK owns
//!   every stage and hands each one a [`WriterTail`] or [`ReaderTail`] over
//!   the remainder of the chain. Forwarding down the chain is then a slice
//!   split rather than a pointer dereference, and the C's
//!   `if(!writer) return CURLE_WRITE_ERROR` (`lib/sendf.c:132-133`) becomes
//!   an empty tail returning exactly the same code.
//!
//! # Ordering is behaviour, not a detail
//!
//! Both chains are ordered by PHASE, and a stage is inserted FIRST WITHIN ITS
//! PHASE (`lib/sendf.c:464-469` and `:1156-1161`). Two consequences the C
//! header spells out (`lib/sendf.h:90-92`) and this module preserves exactly:
//!
//! * the order in which stages of the SAME phase are added is observable, and
//!   reverses their execution order;
//! * stages of DIFFERENT phases may be added in any order.
//!
//! The phase boundary between [`ClientWriterPhase::Protocol`] and
//! [`ClientWriterPhase::ContentDecode`] is itself behavioural: a response's
//! `Content-Length` describes the COMPRESSED body, so the length check has to
//! run before any decoder. Moving [`DownloadWriter`] behind a decoder would
//! compare the decoded length and produce a different error on the same
//! input.
//!
//! # Layering: how the include cycle was removed
//!
//! `lib/sendf.c` includes `transfer.h`, `cfilters.h`, `connect.h`,
//! `cw-out.h`, `cw-pause.h`, `multiif.h` and `progress.h`, and several of
//! those include `sendf.h` straight back. That cycle is a property of the
//! preprocessor, not of the design, and it does not survive the migration:
//!
//! * Nothing here names `transfer/mod.rs` or `transfer/writeout.rs`. The
//!   three things `lib/sendf.c` reaches into the transfer loop for --
//!   `streamclose`, `connclose` and `Curl_xfer_pause_send` -- arrive as the
//!   three methods of [`TransferControl`], which the dependency-last engine
//!   implements.
//! * The two writers that `lib/cw-out.c` and `lib/cw-pause.c` own arrive
//!   through [`ClientIoFactory`], so the base stack is assembled HERE, in the
//!   exact C order, out of stages this module never has to name a type for.
//! * No TLS type is named. TLS is interposed transparently by
//!   `conn/filters.rs` beneath the transport, so both chains here are
//!   transport-agnostic.
//! * `Curl_debug`, `CURL_TRC_WRITE`, `CURL_TRC_READ`, `failf` and `infof`
//!   arrive as [`TraceSink`], a five-method seam rather than an import of
//!   `crate::trace`.
//!
//! Imports therefore reach only [`crate::error`],
//! [`crate::transfer::progress`], [`crate::transfer::ratelimit`],
//! [`crate::util::bufq`], [`crate::util::dynbuf`] and
//! [`crate::util::timeval`]. Every one of those is strictly below this module
//! in the graph, so the graph stays acyclic.
//!
//! # Buffers
//!
//! Specification 0.6.9 requires the manual pointer, length and capacity
//! arithmetic of `lib/sendf.c`, `lib/bufq.c` and `lib/curlx/dynbuf.c` to
//! become owned Rust buffers, and that is what happens: the line-ending
//! converter buffers through [`crate::util::bufq::BufQ`] exactly as
//! `cr_lc_init` does (`lib/sendf.c:969`), and the resume scratch area is a
//! [`bytes::BytesMut`] of exactly the C's `char scratch[4 * 1024]`
//! (`lib/sendf.c:782`). No size policy is invented here: the ceilings live in
//! [`crate::util::dynbuf`], where `DYN_HTTP_REQUEST` (one mebibyte) serves the
//! request builders and `DYN_PAUSE_BUFFER` (64 mebibytes) serves the pause
//! buffering that `transfer/writeout.rs` owns. The test module asserts both
//! values so that a drift in either is caught here as well as there.
//!
//! Payloads are bytes throughout. Nothing below converts a payload to `str`,
//! lossily or otherwise: specification 0.6.7 measures 1,476 of the 1,914
//! fixtures by comparing emitted bytes as one string, so a normalisation
//! anywhere on either chain is a wire-parity failure.

use core::fmt;
use std::io::{Read, Seek, SeekFrom};

use bytes::BytesMut;

use crate::error::{CURLcode, CurlResult, Error};
use crate::transfer::progress::{Progress, TimerId};
use crate::util::bufq::{BufQ, BufqOpts};
use crate::util::timeval::{Clock, CurlTime};

// =========================================================================
// Saturating width conversion -- `curlx_sotouz_range`
// =========================================================================

/// Clamps a `curl_off_t` into a `size_t` range without wrapping.
///
/// Supersedes `curlx_sotouz_range` (`lib/curlx/warnless.c:286-295`) for the
/// three call sites inside `lib/sendf.c` that use it: the writable-body
/// calculation at `:163`, the read-length clamp at `:664` and the resume
/// offset at `:1361`.
///
/// Transcribed rather than imported. `crate::util` publishes the same
/// conversion, but this module's dependency whitelist is exactly the six
/// files named in the module documentation, and a six-line arithmetic
/// clamp is not worth widening it for. The C is reproduced branch for
/// branch, including the detail that a `uzmin` above `uzmax` yields `uzmax`,
/// because `CURLMIN(CURLMAX(v, min), max)` applies the maximum first:
///
/// * negative input yields `uzmin`;
/// * input above [`usize::MAX`] yields `uzmax`, which on a 64-bit target is
///   unreachable and on a narrower one is the C's
///   `#if SIZEOF_CURL_OFF_T > SIZEOF_SIZE_T` arm;
/// * otherwise the value, raised to `uzmin` and then lowered to `uzmax`.
#[allow(dead_code)]
fn so_to_usize_range(sonum: i64, uzmin: usize, uzmax: usize) -> usize {
    // `warnless.c:288-289`.
    if sonum < 0 {
        return uzmin;
    }
    // `warnless.c:290-293`. `try_from` fails only where `usize` is narrower
    // than `i64`, and saturating to `usize::MAX` there makes the `min` below
    // yield `uzmax`, which is what the C's guarded arm returns.
    let widened = usize::try_from(sonum).unwrap_or(usize::MAX);
    // `warnless.c:294`, in the C's order: maximum first, then minimum.
    widened.max(uzmin).min(uzmax)
}

// =========================================================================
// The client-write flag vocabulary -- `lib/sendf.h:42-50`
// =========================================================================

/// What a client write CONTAINS, as a set of bits.
///
/// Supersedes the nine `CLIENTWRITE_*` macros of `lib/sendf.h:42-50`. The
/// numeric shape is preserved bit for bit because it is what
/// [`crate::headers`] classifies an incoming header by, and because the
/// chains route on it; the type exists so that the mutual exclusivity the C
/// asserts at run time in a debug build becomes something a reader can see in
/// one place.
///
/// # The three classes, and the qualifiers
///
/// The header's own comment (`lib/sendf.h:28-41`) is the specification:
///
/// > - data written can be either BODY or META data
/// > - META data is either INFO or HEADER
/// > - INFO is meta information, e.g. not BODY, that cannot be interpreted
/// >   as headers of a response. Example FTP/IMAP pingpong answers.
/// > - HEADER can have additional bits set (more than one)
/// > - BODY, INFO and HEADER should not be mixed, as this would lead to
/// >   confusion on how to interpret/format/convert the data.
///
/// So [`Self::BODY`], [`Self::INFO`] and [`Self::HEADER`] are three mutually
/// exclusive CLASSES and at least one is always present;
/// [`Self::STATUS`], [`Self::CONNECT`], [`Self::ONE_XX`] and
/// [`Self::TRAILER`] QUALIFY [`Self::HEADER`] alone; and [`Self::EOS`] and
/// [`Self::ZERO_LEN`] are orthogonal to both groups.
///
/// # None of these bits crosses the public ABI
///
/// `CLIENTWRITE` appears zero times anywhere under `include/`. An application
/// sees only the callback it registered, never a type bit, which is why this
/// type is `pub(crate)` and carries no `#[repr(C)]`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) struct ClientWriteFlags(u32);

impl ClientWriteFlags {
    /// No bits at all.
    ///
    /// Not a value the C ever passes to `Curl_client_write` -- its first
    /// assertion (`lib/sendf.c:381-382`) rejects it -- but the identity for
    /// [`Self::union`] and the starting point for building a set up.
    #[allow(dead_code)]
    pub(crate) const NONE: Self = Self(0);

    /// `CLIENTWRITE_BODY` = `1 << 0`: non-meta information, the body
    /// (`lib/sendf.h:42`).
    #[allow(dead_code)]
    pub(crate) const BODY: Self = Self(1 << 0);

    /// `CLIENTWRITE_INFO` = `1 << 1`: meta information that is not a header
    /// (`lib/sendf.h:43`). FTP and IMAP pingpong replies arrive this way.
    #[allow(dead_code)]
    pub(crate) const INFO: Self = Self(1 << 1);

    /// `CLIENTWRITE_HEADER` = `1 << 2`: meta information that IS a header
    /// (`lib/sendf.h:44`).
    #[allow(dead_code)]
    pub(crate) const HEADER: Self = Self(1 << 2);

    /// `CLIENTWRITE_STATUS` = `1 << 3`: a special status header
    /// (`lib/sendf.h:45`), such as HTTP's response status line.
    #[allow(dead_code)]
    pub(crate) const STATUS: Self = Self(1 << 3);

    /// `CLIENTWRITE_CONNECT` = `1 << 4`: a header received while proxying the
    /// connection (`lib/sendf.h:46`).
    #[allow(dead_code)]
    pub(crate) const CONNECT: Self = Self(1 << 4);

    /// `CLIENTWRITE_1XX` = `1 << 5`: a header belonging to an intermediate
    /// response (`lib/sendf.h:47`).
    ///
    /// Named `ONE_XX` because `1XX` is not an identifier. The bit, the C
    /// spelling in the documentation above and the numeric value are all
    /// unchanged.
    #[allow(dead_code)]
    pub(crate) const ONE_XX: Self = Self(1 << 5);

    /// `CLIENTWRITE_TRAILER` = `1 << 6`: trailing response data
    /// (`lib/sendf.h:48`), such as HTTP trailers.
    #[allow(dead_code)]
    pub(crate) const TRAILER: Self = Self(1 << 6);

    /// `CLIENTWRITE_EOS` = `1 << 7`: the end of the download stream
    /// (`lib/sendf.h:49`).
    ///
    /// The one bit permitted alongside [`Self::BODY`] or [`Self::INFO`].
    #[allow(dead_code)]
    pub(crate) const EOS: Self = Self(1 << 7);

    /// `CLIENTWRITE_0LEN` = `1 << 8`: write even a zero-length buffer
    /// (`lib/sendf.h:50`).
    ///
    /// Named `ZERO_LEN` for the same reason [`Self::ONE_XX`] is renamed. Only
    /// `lib/cw-out.c:428` reads it, and only `lib/ws.c:704` sets it -- see
    /// [`Self::is_valid`], where that call site matters.
    #[allow(dead_code)]
    pub(crate) const ZERO_LEN: Self = Self(1 << 8);

    /// The three mutually exclusive classes, as one mask.
    #[allow(dead_code)]
    pub(crate) const CLASS_MASK: Self =
        Self(Self::BODY.0 | Self::INFO.0 | Self::HEADER.0);

    /// The four bits that qualify [`Self::HEADER`], as one mask.
    #[allow(dead_code)]
    pub(crate) const HEADER_QUALIFIERS: Self = Self(
        Self::STATUS.0 | Self::CONNECT.0 | Self::ONE_XX.0 | Self::TRAILER.0,
    );

    /// Every bit the C defines, as one mask.
    ///
    /// `1 << 9` and above are unassigned. A caller that sets one is not
    /// speaking this vocabulary, which [`Self::is_valid`] reports.
    #[allow(dead_code)]
    pub(crate) const ALL: Self = Self(
        Self::CLASS_MASK.0
            | Self::HEADER_QUALIFIERS.0
            | Self::EOS.0
            | Self::ZERO_LEN.0,
    );

    /// The raw bit pattern, for the one consumer that needs it.
    ///
    /// [`crate::headers::classify_origin`] takes the mask as a `u32` because
    /// it reproduces a C function that reads `int type`. Handing it
    /// `flags.bits()` keeps ONE definition of the numbers -- these -- rather
    /// than two that could drift.
    #[allow(dead_code)]
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// A set from a raw bit pattern.
    ///
    /// The inbound direction of [`Self::bits`], for the stages that receive a
    /// mask from a C-shaped caller. Unassigned bits are preserved rather than
    /// masked away, so that [`Self::is_valid`] can report them; masking here
    /// would hide the caller's mistake.
    #[allow(dead_code)]
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Whether EVERY bit of `other` is present.
    ///
    /// The C idiom is `(type & CLIENTWRITE_BODY)`, which for a single bit is
    /// the same test. For a multi-bit `other` this is the CONJUNCTION, which
    /// is what "contains" has to mean; [`Self::intersects`] is the
    /// disjunction, and the two are not interchangeable.
    #[allow(dead_code)]
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Whether ANY bit of `other` is present.
    ///
    /// The successor of the C's `(type & (CLIENTWRITE_INFO |
    /// CLIENTWRITE_CONNECT))` at `lib/sendf.c:186` and `:201`, where a match
    /// on either bit suppresses a one-shot action.
    #[allow(dead_code)]
    pub(crate) const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Both sets of bits together -- the C's `|`.
    #[allow(dead_code)]
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// The bits of `self` that are not in `other` -- the C's `& ~`.
    #[allow(dead_code)]
    pub(crate) const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether no bit at all is set.
    #[allow(dead_code)]
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether this set satisfies the three invariants `Curl_client_write`
    /// asserts.
    ///
    /// Transcribed from `lib/sendf.c:380-388`, in the C's order:
    ///
    /// 1. `DEBUGASSERT(type & (BODY | HEADER | INFO))` -- at least one class.
    /// 2. `DEBUGASSERT(!(type & BODY) || ((type & ~(BODY | EOS)) == 0))` --
    ///    `BODY` may be accompanied only by `EOS`.
    /// 3. `DEBUGASSERT(!(type & INFO) || ((type & ~(INFO | EOS)) == 0))` --
    ///    `INFO` may be accompanied only by `EOS`.
    ///
    /// Invariants 2 and 3 are what make the three classes mutually exclusive:
    /// `BODY | HEADER` fails 2, and `INFO | HEADER` fails 3.
    ///
    /// # Why this is asserted at the entry point and NOWHERE else
    ///
    /// The C asserts these three ONLY in `Curl_client_write`, and that is not
    /// an oversight to be corrected. `lib/ws.c:703-705` calls
    /// `Curl_cwriter_write` DIRECTLY with `ctx->cw_type | CLIENTWRITE_0LEN`,
    /// and `cw_type` is `CLIENTWRITE_BODY` for a WebSocket data frame -- so
    /// `BODY | ZERO_LEN` really does travel down a writer chain, and it fails
    /// invariant 2. Asserting inside [`ClientWriterStack::write`] would
    /// therefore abort a debug build on a legitimate WebSocket transfer.
    /// [`ClientIo::client_write`] is the one place this is checked, exactly as
    /// in the C.
    ///
    /// A `1 << 9` or higher bit also fails, which the C cannot notice: its
    /// assertions test only the bits they name. Reporting it is strictly more
    /// information and costs a caller that speaks the vocabulary nothing.
    #[allow(dead_code)]
    pub(crate) const fn is_valid(self) -> bool {
        // `lib/sendf.c:381-382`: it is one of those, at least.
        if !self.intersects(Self::CLASS_MASK) {
            return false;
        }
        // `lib/sendf.c:384-385`: BODY is only BODY (with optional EOS).
        if self.contains(Self::BODY)
            && !self.difference(Self::BODY.union(Self::EOS)).is_empty()
        {
            return false;
        }
        // `lib/sendf.c:387-388`: INFO is only INFO (with optional EOS).
        if self.contains(Self::INFO)
            && !self.difference(Self::INFO.union(Self::EOS)).is_empty()
        {
            return false;
        }
        // Beyond the C: a bit outside the vocabulary means nothing to any
        // stage, so a caller that sets one has made a mistake worth naming.
        self.difference(Self::ALL).is_empty()
    }

    /// The class bits alone, with every qualifier and orthogonal bit removed.
    ///
    /// Used by the trace lines below so that a diagnostic can name the class
    /// without restating the mask.
    #[allow(dead_code)]
    pub(crate) const fn class(self) -> Self {
        Self(self.0 & Self::CLASS_MASK.0)
    }
}

impl fmt::Display for ClientWriteFlags {
    /// The hexadecimal mask, spelled as `CURL_TRC_WRITE`'s `type=%x` spells
    /// it (`lib/sendf.c:195`, `:260`, `:398`).
    ///
    /// A trace line is compared by eye against the C's, so the rendering has
    /// to match the C's: bare lowercase hexadecimal with no `0x` prefix,
    /// because that is what `%x` produces.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl core::ops::BitOr for ClientWriteFlags {
    type Output = Self;

    /// [`Self::union`] as an operator, so that a call site reads like the C's
    /// `CLIENTWRITE_BODY | CLIENTWRITE_EOS`.
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::ops::BitOrAssign for ClientWriteFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = self.union(rhs);
    }
}

// =========================================================================
// The two phase orderings -- `lib/sendf.h:101-107` and `:234-240`
// =========================================================================

/// Where in the writer chain a stage operates.
///
/// Supersedes `Curl_cwriter_phase` (`lib/sendf.h:101-107`). The declaration
/// order IS the chain order, and the derived [`Ord`] is what
/// [`ClientWriterStack::add`] compares -- so the variants below must never be
/// reordered.
///
/// A stage's phase is a property of the INSTANCE, not of its type.
/// `lib/content_encoding.c` creates the very same `gzip_encoding` writer at
/// [`Self::TransferDecode`] when the coding arrived in a `Transfer-Encoding`
/// header and at [`Self::ContentDecode`] when it arrived in a
/// `Content-Encoding` header, which is why [`ClientWriter::phase`] is a
/// method a stage answers rather than a parameter this module records.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum ClientWriterPhase {
    /// `CURL_CW_RAW`: raw data written, before any decoding
    /// (`lib/sendf.h:102`). [`RawWriter`] is the only stage here.
    Raw,
    /// `CURL_CW_TRANSFER_DECODE`: removes transfer encodings
    /// (`lib/sendf.h:103`). Chunked de-framing and any `Transfer-Encoding`
    /// decoder installs here, so that a protocol length check downstream sees
    /// the de-framed bytes.
    TransferDecode,
    /// `CURL_CW_PROTOCOL`: after transfer decoding, before content decoding
    /// (`lib/sendf.h:104`). [`DownloadWriter`] and the pause stage live here.
    Protocol,
    /// `CURL_CW_CONTENT_DECODE`: removes content encodings
    /// (`lib/sendf.h:105`).
    ContentDecode,
    /// `CURL_CW_CLIENT`: data written to the client (`lib/sendf.h:106`). The
    /// stage `transfer/writeout.rs` owns is the only one here, and it is
    /// always last.
    Client,
}

impl ClientWriterPhase {
    /// Every phase, in the C's declaration order.
    ///
    /// Exhaustiveness is not something a slice can promise, so the test module
    /// asserts the length and walks each entry against [`Self::c_name`].
    #[allow(dead_code)]
    pub(crate) const VARIANTS: [Self; 5] = [
        Self::Raw,
        Self::TransferDecode,
        Self::Protocol,
        Self::ContentDecode,
        Self::Client,
    ];

    /// The C identifier for this phase, spelled as `lib/sendf.h` spells it.
    ///
    /// Present so that a diagnostic can name a phase the way the header does
    /// without a second table to keep in step.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::Raw => "CURL_CW_RAW",
            Self::TransferDecode => "CURL_CW_TRANSFER_DECODE",
            Self::Protocol => "CURL_CW_PROTOCOL",
            Self::ContentDecode => "CURL_CW_CONTENT_DECODE",
            Self::Client => "CURL_CW_CLIENT",
        }
    }
}

/// Where in the reader chain a stage operates.
///
/// Supersedes `Curl_creader_phase` (`lib/sendf.h:234-240`). As with
/// [`ClientWriterPhase`], declaration order is chain order and the derived
/// [`Ord`] is what [`ClientReaderStack::add`] compares.
///
/// Note that the read chain runs the other way round conceptually: bytes enter
/// at [`Self::Client`], the DEEPEST phase, and are pulled up towards
/// [`Self::Net`]. The stack is still ordered lowest phase first, so the
/// numerically first phase is the one a caller reaches first -- which is why
/// [`Self::Net`] is 0 and [`Self::Client`] is 4, mirroring the writer chain's
/// numbering rather than its direction of travel.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)]
pub(crate) enum ClientReaderPhase {
    /// `CURL_CR_NET`: data sent to the network, i.e. to the connection
    /// filters (`lib/sendf.h:235`).
    Net,
    /// `CURL_CR_TRANSFER_ENCODE`: adds transfer encodings
    /// (`lib/sendf.h:236`). Chunked framing for an upload installs here.
    TransferEncode,
    /// `CURL_CR_PROTOCOL`: before transfer, after content encoding
    /// (`lib/sendf.h:237`).
    Protocol,
    /// `CURL_CR_CONTENT_ENCODE`: adds content encodings
    /// (`lib/sendf.h:238`). [`CrLineConv`] installs here.
    ContentEncode,
    /// `CURL_CR_CLIENT`: data read from the client (`lib/sendf.h:239`).
    /// Exactly one stage occupies this phase -- [`CrIn`], [`CrNull`] or
    /// [`CrBuf`] -- and it is the bottom of the chain.
    Client,
}

impl ClientReaderPhase {
    /// Every phase, in the C's declaration order.
    #[allow(dead_code)]
    pub(crate) const VARIANTS: [Self; 5] = [
        Self::Net,
        Self::TransferEncode,
        Self::Protocol,
        Self::ContentEncode,
        Self::Client,
    ];

    /// The C identifier for this phase, spelled as `lib/sendf.h` spells it.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::Net => "CURL_CR_NET",
            Self::TransferEncode => "CURL_CR_TRANSFER_ENCODE",
            Self::Protocol => "CURL_CR_PROTOCOL",
            Self::ContentEncode => "CURL_CR_CONTENT_ENCODE",
            Self::Client => "CURL_CR_CLIENT",
        }
    }
}

// =========================================================================
// Stage identity -- the safe successor of `get_by_type`
// =========================================================================

/// Which writer a stage IS.
///
/// The safe successor of the pointer comparison in `Curl_cwriter_get_by_type`
/// (`lib/sendf.c:484-493`), which asks whether `writer->cwt == cwt` -- an
/// identity test over a static vtable address. There is no vtable address to
/// compare here and no `Any` downcast is permitted, so identity is stated
/// EXPLICITLY as a value.
///
/// The inventory is the complete set of `struct Curl_cwtype` definitions in
/// the C tree, found by enumerating them rather than by sampling:
/// `lib/sendf.c:295` and `:316`, `lib/cw-out.c:444`, `lib/cw-pause.c:206`,
/// `lib/http_chunks.c:453`, `lib/content_encoding.c:279`, `:340`, `:462`,
/// `:565`, `:576` and `:660`, `lib/headers.c:315`, `lib/ws.c:770` and
/// `lib/ftp.c:442`. Fourteen types, thirteen of which are in scope; the
/// fourteenth belongs to a protocol that is not.
///
/// # Why the name lives here
///
/// [`Self::name`] returns the exact string the C's `cwt->name` holds, so
/// [`ClientWriterStack::get_by_name`] and [`Self::name`] cannot disagree, and
/// a stage implementing [`ClientWriter`] states its identity ONCE by answering
/// [`ClientWriter::kind`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum ClientWriterKind {
    /// `cw_raw`, name `"raw"` (`lib/sendf.c:316-317`). [`RawWriter`].
    Raw,
    /// `cw_download`, name `"protocol"` (`lib/sendf.c:295-296`).
    /// [`DownloadWriter`].
    ///
    /// The name is `"protocol"` and not `"download"`, which is easy to get
    /// wrong: the phase is `CURL_CW_PROTOCOL` and the C named the type after
    /// the phase rather than after the job.
    Download,
    /// `Curl_cwt_out`, name `"cw-out"` (`lib/cw-out.c:444-445`). Owned by
    /// `transfer/writeout.rs` and reached here only through
    /// [`ClientIoFactory::client_out_writer`].
    ClientOut,
    /// `Curl_cwt_pause`, name `"cw-pause"` (`lib/cw-pause.c:206-207`). Owned
    /// by `transfer/writeout.rs` and reached here only through
    /// [`ClientIoFactory::pause_writer`].
    Pause,
    /// `Curl_httpchunk_unencoder`, name `"chunked"`
    /// (`lib/http_chunks.c:453-454`). Owned by `transfer/chunked.rs`.
    ChunkedDecode,
    /// `deflate_encoding`, name `"deflate"`
    /// (`lib/content_encoding.c:279-280`).
    Deflate,
    /// `gzip_encoding`, name `"gzip"`, alias `"x-gzip"`
    /// (`lib/content_encoding.c:340-342`).
    Gzip,
    /// `brotli_encoding`, name `"br"` (`lib/content_encoding.c:462-463`).
    Brotli,
    /// `zstd_encoding`, name `"zstd"` (`lib/content_encoding.c:565-566`).
    Zstd,
    /// `identity_encoding`, name `"identity"`, alias `"none"`
    /// (`lib/content_encoding.c:576-578`).
    Identity,
    /// `error_writer`, name `"ce-error"` (`lib/content_encoding.c:660-661`).
    /// The stage installed for an unrecognised coding, which fails the
    /// transfer when body bytes reach it.
    ContentEncodingError,
    /// `hds_cw_collect`, name `"hds-collect"` (`lib/headers.c:315-316`). The
    /// stage behind `curl_easy_header`.
    HeaderCollect,
    /// `ws_cw_decode`, name `"ws-decode"` (`lib/ws.c:770-771`). Owned by
    /// `protocols/ws.rs`.
    WebSocketDecode,
    /// `ftp_cw_lc`, name `"ftp-lineconv"` (`lib/ftp.c:442-443`). Owned by
    /// `protocols/ftp/mod.rs`.
    FtpLineConv,
    /// A stage with no counterpart in the C tree.
    ///
    /// Two uses, and no others: the test doubles in this file's test module,
    /// and any stage a later module adds that the enumeration above does not
    /// yet name. The string is the stage's name, so [`Self::name`] stays
    /// total and [`ClientWriterStack::get_by_name`] keeps working for it.
    Custom(&'static str),
}

/// The Brotli stage's name: the two bytes `b` and `r`.
///
/// `lib/content_encoding.c:1194` registers exactly that string, and it is what
/// an `Accept-Encoding` header carries, so the value is not negotiable. The
/// SPELLING is: written out, the two characters before a closing quote read to
/// `lib.rs`'s `no_raw_string_literal_defeats_the_stripper` gate as the opening
/// of a raw byte string, and that gate protects two other gates that would
/// silently lose coverage if a real raw string were ever introduced. Escaping
/// the first byte keeps this crate's one legitimate occurrence of the sequence
/// from having to weaken it. The test module asserts the bytes.
const BROTLI_STAGE_NAME: &str = "\x62r";

impl ClientWriterKind {
    /// The `name` member of the corresponding `struct Curl_cwtype`.
    #[allow(dead_code)]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Download => "protocol",
            Self::ClientOut => "cw-out",
            Self::Pause => "cw-pause",
            Self::ChunkedDecode => "chunked",
            Self::Deflate => "deflate",
            Self::Gzip => "gzip",
            Self::Brotli => BROTLI_STAGE_NAME,
            Self::Zstd => "zstd",
            Self::Identity => "identity",
            Self::ContentEncodingError => "ce-error",
            Self::HeaderCollect => "hds-collect",
            Self::WebSocketDecode => "ws-decode",
            Self::FtpLineConv => "ftp-lineconv",
            Self::Custom(name) => name,
        }
    }

    /// The `alias` member of the corresponding `struct Curl_cwtype`, which is
    /// `NULL` for all but two of them.
    ///
    /// `"x-gzip"` for [`Self::Gzip`] and `"none"` for [`Self::Identity`]. The
    /// alias is NOT consulted by `Curl_cwriter_get_by_name`, which compares
    /// `cwt->name` alone (`lib/sendf.c:478`); it exists so that
    /// `lib/content_encoding.c` can match a coding token spelled either way.
    /// [`ClientWriterStack::get_by_name`] reproduces that asymmetry exactly.
    #[allow(dead_code)]
    pub(crate) const fn alias(self) -> Option<&'static str> {
        match self {
            Self::Gzip => Some("x-gzip"),
            Self::Identity => Some("none"),
            _ => None,
        }
    }
}

impl fmt::Display for ClientWriterKind {
    /// [`Self::name`], so a trace line names a stage exactly as the C's
    /// `writer->cwt->name` does.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Which reader a stage IS.
///
/// The safe successor of the pointer comparison in `Curl_creader_get_by_type`
/// (`lib/sendf.c:1466-1475`), and the read-side counterpart of
/// [`ClientWriterKind`] in every respect.
///
/// The inventory is the complete set of `struct Curl_crtype` definitions:
/// `lib/sendf.c:908`, `:1068`, `:1258` and `:1372`, `lib/mime.c:2089`,
/// `lib/http_chunks.c:640`, `lib/ws.c:1226` and `lib/smtp.c:448`. Eight
/// types, seven in scope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum ClientReaderKind {
    /// `cr_in`, name `"cr-in"` (`lib/sendf.c:908-909`). [`CrIn`].
    Input,
    /// `cr_lc`, name `"cr-lineconv"` (`lib/sendf.c:1068-1069`).
    /// [`CrLineConv`].
    LineConv,
    /// `cr_null`, name `"cr-null"` (`lib/sendf.c:1258-1259`). [`CrNull`].
    Null,
    /// `cr_buf`, name `"cr-buf"` (`lib/sendf.c:1372-1373`). [`CrBuf`].
    Buf,
    /// `cr_mime`, name `"cr-mime"` (`lib/mime.c:2089-2090`). Owned by
    /// `mime/mod.rs`.
    Mime,
    /// `Curl_httpchunk_encoder`, name `"chunked"`
    /// (`lib/http_chunks.c:640-641`). Owned by `transfer/chunked.rs`.
    ChunkedEncode,
    /// `ws_cr_encode`, name `"ws-encode"` (`lib/ws.c:1226-1227`). Owned by
    /// `protocols/ws.rs`.
    WebSocketEncode,
    /// A stage with no counterpart in the C tree; see
    /// [`ClientWriterKind::Custom`], whose reasoning applies unchanged.
    Custom(&'static str),
}

impl ClientReaderKind {
    /// The `name` member of the corresponding `struct Curl_crtype`.
    #[allow(dead_code)]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Input => "cr-in",
            Self::LineConv => "cr-lineconv",
            Self::Null => "cr-null",
            Self::Buf => "cr-buf",
            Self::Mime => "cr-mime",
            Self::ChunkedEncode => "chunked",
            Self::WebSocketEncode => "ws-encode",
            Self::Custom(name) => name,
        }
    }
}

impl fmt::Display for ClientReaderKind {
    /// [`Self::name`], so a trace line names a stage exactly as the C's
    /// `reader->crt->name` does -- which `lib/sendf.c:106`, `:1437` and
    /// `:1227` all interpolate.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The three things a reader can be TOLD, as opposed to asked.
///
/// Supersedes `Curl_creader_cntrl` (`lib/sendf.h:207-211`). The C's `cntrl`
/// member takes this as an opcode and a `default:` arm absorbs anything else;
/// an exhaustive `match` here means a stage that forgets one is a compile
/// error rather than a silent no-op.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum ReaderControl {
    /// `CURL_CRCNTRL_REWIND` (`lib/sendf.h:208`): a retry is starting, so put
    /// the source back to where it began.
    ///
    /// The one control that can FAIL, and the only reason
    /// [`ClientReader::control`] returns a result at all. [`CrIn`] answers it
    /// by seeking; see [`CrIn::rewind`].
    Rewind,
    /// `CURL_CRCNTRL_UNPAUSE` (`lib/sendf.h:209`): the transfer is no longer
    /// paused, so clear any paused state.
    Unpause,
    /// `CURL_CRCNTRL_CLEAR_EOS` (`lib/sendf.h:210`): forget that the end of
    /// the stream was seen, so that the next read consults the source again.
    ClearEos,
}

impl ReaderControl {
    /// Every control, in the C's declaration order.
    #[allow(dead_code)]
    pub(crate) const VARIANTS: [Self; 3] =
        [Self::Rewind, Self::Unpause, Self::ClearEos];

    /// The C identifier for this control, spelled as `lib/sendf.h` spells it.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::Rewind => "CURL_CRCNTRL_REWIND",
            Self::Unpause => "CURL_CRCNTRL_UNPAUSE",
            Self::ClearEos => "CURL_CRCNTRL_CLEAR_EOS",
        }
    }
}

// =========================================================================
// The injected seams -- what `lib/sendf.c` reaches out of its file for
// =========================================================================

/// The three things `lib/sendf.c` asks the transfer engine to DO.
///
/// `lib/sendf.c` includes `transfer.h`, `connect.h` and `multiif.h` for
/// exactly three operations, and `sendf.h` is included straight back by all
/// three -- the include cycle the module documentation describes. Naming them
/// as a trait the dependency-last engine implements breaks the cycle without
/// losing a single call.
///
/// The two close requests are kept DISTINCT because the C distinguishes them
/// and the distinction is observable on a multiplexed connection: `streamclose`
/// retires one stream, `connclose` retires the whole connection. Collapsing
/// them would close an HTTP/2 connection where curl 8.x closes one stream.
#[allow(dead_code)]
pub(crate) trait TransferControl: fmt::Debug {
    /// `streamclose(data->conn, reason)`, as called at `lib/sendf.c:215` with
    /// the reason `"ignoring body"`.
    ///
    /// The reason is `&'static str` because every call site in the C tree
    /// passes a string literal, and because the reason is echoed into a trace
    /// line rather than parsed.
    fn stream_close(&mut self, reason: &'static str);

    /// `connclose(data->conn, reason)`, as called at `lib/sendf.c:282` with
    /// the reason `"excess found in a read"`.
    fn conn_close(&mut self, reason: &'static str);

    /// `Curl_xfer_pause_send(data, pause)`, as called at `lib/sendf.c:711`
    /// when the input callback returns the pause sentinel.
    ///
    /// One of the two seam methods that can fail, and its result is returned
    /// to the caller of [`ClientIo::client_read`] unchanged -- the C assigns it
    /// straight to `result` and lets it propagate.
    fn pause_send(&mut self, pause: bool) -> CurlResult<()>;

    /// `Curl_xfer_pause_recv(data, pause)`, as called at `lib/cw-out.c:205`
    /// when the application's WRITE callback returns the pause sentinel.
    ///
    /// The receive-direction twin of [`Self::pause_send`], and the reason this
    /// trait carries four methods rather than the three `lib/sendf.c` alone
    /// needs. `lib/cw-out.c` is the client-output stage that
    /// `transfer/writeout.rs` supersedes, and it is installed into the chain
    /// through [`ClientIoFactory::client_out_writer`], so the only channel it
    /// has to the transfer engine is the [`ClientCtx`] it is handed. Adding the
    /// operation here rather than inventing a second seam keeps every
    /// engine-owned operation in one trait.
    ///
    /// The C's result handling is specific and is preserved by its caller: a
    /// failure is returned as-is, and SUCCESS becomes
    /// [`CURLcode::Again`] -- `result ? result : CURLE_AGAIN`
    /// (`lib/cw-out.c:206`) -- so that the pause is reported as backpressure
    /// rather than as completion.
    fn pause_recv(&mut self, pause: bool) -> CurlResult<()>;
}

/// The flag that says an application callback is currently running.
///
/// Supersedes `Curl_set_in_callback(data, bool)`, which `lib/sendf.c` brackets
/// every user callback with -- at `:668-670`, `:768-770`, `:789-792`,
/// `:830-832` and `:842-845`. libcurl uses it to refuse a reentrant API call
/// from inside a callback, which is why it must be restored on EVERY path out.
///
/// It is a one-method trait rather than a `bool` field so that the engine can
/// keep the flag wherever it keeps the rest of the handle's state, and so that
/// a test can observe the bracketing directly.
#[allow(dead_code)]
pub(crate) trait ClientCallbackGuard: fmt::Debug {
    /// `Curl_set_in_callback(data, inside)`.
    fn set_in_callback(&mut self, inside: bool);
}

/// A scope that holds the in-callback flag raised, and lowers it on drop.
///
/// This is the mechanism behind the agent contract's *"always restoring it on
/// every path"*. The C achieves it by writing the `FALSE` call after every
/// callback invocation, which is correct only as long as nobody adds an early
/// return between the two lines; here the compiler inserts the restore, and it
/// runs on an early return and on an unwind alike.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct InCallback<'guard> {
    guard: &'guard mut dyn ClientCallbackGuard,
}

impl<'guard> InCallback<'guard> {
    /// Raises the flag and returns the scope that will lower it.
    ///
    /// `#[must_use]` is deliberate and load-bearing: binding the result to `_`
    /// would drop it immediately and lower the flag before the callback ran,
    /// which is exactly the mistake this type exists to prevent. Bind it to a
    /// named `_entered` instead.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn enter(guard: &'guard mut dyn ClientCallbackGuard) -> Self {
        guard.set_in_callback(true);
        Self { guard }
    }
}

impl Drop for InCallback<'_> {
    fn drop(&mut self) {
        self.guard.set_in_callback(false);
    }
}

/// Which of `curl_infotype`'s streams a traced payload belongs to.
///
/// Only one variant is produced by this module -- [`Self::DataIn`], from
/// `Curl_debug(data, CURLINFO_DATA_IN, buf, nbytes)` at `lib/sendf.c:311` --
/// but the whole enumeration is transcribed because it is the vocabulary the
/// seam speaks, and a partial vocabulary would have to be widened by every
/// later stage that traces.
///
/// The values are `curl_infotype`'s, in the header's declaration order
/// (`include/curl/curl.h:479-488`). They are not `#[repr]`-pinned here: the
/// integer belongs to the ABI shim, which is where a C consumer reads it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum TraceDataKind {
    /// `CURLINFO_TEXT`: informational text.
    Text,
    /// `CURLINFO_HEADER_IN`: a header received.
    HeaderIn,
    /// `CURLINFO_HEADER_OUT`: a header sent.
    HeaderOut,
    /// `CURLINFO_DATA_IN`: body data received. The one kind [`RawWriter`]
    /// emits.
    DataIn,
    /// `CURLINFO_DATA_OUT`: body data sent.
    DataOut,
    /// `CURLINFO_SSL_DATA_IN`: TLS record data received.
    SslDataIn,
    /// `CURLINFO_SSL_DATA_OUT`: TLS record data sent.
    SslDataOut,
}

/// Where diagnostics go.
///
/// Supersedes the five emitters `lib/sendf.c` uses, and nothing more:
///
/// | C emitter | method | call sites in `lib/sendf.c` |
/// |---|---|---|
/// | `Curl_debug` | [`Self::debug`] | `:311` |
/// | `CURL_TRC_WRITE` | [`Self::trace_write`] | four sites, `:195` to `:398` |
/// | `CURL_TRC_READ` | [`Self::trace_read`] | ten sites, `:83` to `:1437` |
/// | `failf` | [`Self::failf`] | eleven sites, `:105` to `:873` |
/// | `infof` | [`Self::infof`] | `:274` |
///
/// Every method takes [`fmt::Arguments`], which is what `format_args!`
/// produces: the line is formatted only if the sink actually renders it, so a
/// transfer that is not tracing pays for no formatting at all. That is the
/// same economy the C gets from `CURL_TRC_WRITE` being a macro that tests the
/// level before evaluating its arguments.
///
/// A transfer that is not tracing has no sink at all -- [`ClientCtx`] holds
/// `Option<&mut dyn TraceSink>` -- so a stage never has to pretend it can
/// trace.
#[allow(dead_code)]
pub(crate) trait TraceSink: fmt::Debug {
    /// `Curl_debug(data, kind, bytes, len)`: hands a raw PAYLOAD to the
    /// application's debug callback.
    ///
    /// The bytes are passed through untouched. `--trace` and `--trace-ascii`
    /// render them, and the rendering is frozen, but the rendering belongs to
    /// `curl-rs/src/callbacks/debug.rs` and not here.
    fn debug(&mut self, kind: TraceDataKind, bytes: &[u8]);

    /// `CURL_TRC_WRITE(data, ...)`: a trace line about the writer chain.
    fn trace_write(&mut self, line: fmt::Arguments<'_>);

    /// `CURL_TRC_READ(data, ...)`: a trace line about the reader chain.
    fn trace_read(&mut self, line: fmt::Arguments<'_>);

    /// `failf(data, ...)`: the specific line that reaches
    /// `CURLOPT_ERRORBUFFER`.
    ///
    /// Called IN ADDITION to returning an error, never instead of one. Every
    /// site below that calls this also attaches the same text to the returned
    /// [`Error`], so the diagnostic survives even when no sink is installed.
    fn failf(&mut self, line: fmt::Arguments<'_>);

    /// `infof(data, ...)`: a verbose-mode informational line, which is not an
    /// error.
    fn infof(&mut self, line: fmt::Arguments<'_>);
}

// =========================================================================
// The application callbacks, as typed seams
// =========================================================================

/// What `CURLOPT_READFUNCTION` answered.
///
/// The C reads a single `size_t` and overloads two magic values onto it:
/// `CURL_READFUNC_ABORT` = `0x10000000` (`include/curl/curl.h:390`) and
/// `CURL_READFUNC_PAUSE` = `0x10000001` (`:393`). Those integers are part of
/// the public ABI and are kept there, in `curl-rs-ffi`; internally the three
/// outcomes are three variants, so no stage below can mistake a byte count for
/// a sentinel or vice versa.
///
/// # `Bytes` may exceed the buffer, deliberately
///
/// `lib/sendf.c:714-724` exists precisely because a callback can claim to have
/// written more than it was given, and the C's answer is to fail the transfer
/// with `"read function returned funny value"`. Clamping the count HERE would
/// delete that check. An adapter therefore reports whatever the callback said
/// and lets [`CrIn::read`] judge it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum SourceRead {
    /// The callback reports this many bytes written into the buffer.
    ///
    /// `Bytes(0)` is the C's `case 0:` -- the end of the upload, or a
    /// premature end if a known length has not been reached.
    Bytes(usize),
    /// `CURL_READFUNC_ABORT`: fail the transfer now.
    Abort,
    /// `CURL_READFUNC_PAUSE`: no data available, pause the upload.
    Pause,
}

/// Where request bytes come from.
///
/// Supersedes the pair `data->state.fread_func` and `data->state.in`, which
/// `cr_in_init` copies into its own context (`lib/sendf.c:632-633`). Fusing
/// the function pointer and its client data into one object is what removes
/// the `void *` from the internal contract; the ABI shim keeps the two apart,
/// because `CURLOPT_READFUNCTION` and `CURLOPT_READDATA` are separate options.
#[allow(dead_code)]
pub(crate) trait ClientReadSource: fmt::Debug {
    /// `read_cb(buf, 1, blen, cb_user_data)` (`lib/sendf.c:669`).
    ///
    /// The element size the C passes is always 1 and the count is always the
    /// buffer length, so the two collapse into one slice.
    fn read(&mut self, buf: &mut [u8]) -> SourceRead;

    /// Seeks this source back to its start, if it is the DEFAULT `fread`
    /// source over a seekable stream.
    ///
    /// The safe successor of `lib/sendf.c:852-870`, which asks
    /// `data->state.fread_func == (curl_read_callback)fread` -- a comparison
    /// of function pointers, wrapped in a `#pragma` that silences
    /// `-Wcast-function-type-strict` because the cast is not strictly legal --
    /// and then calls `fseek(data->state.in, 0, SEEK_SET)`.
    ///
    /// Neither the comparison nor the cast survives. A source ANSWERS whether
    /// it can rewind itself, and the three answers map exactly onto the C's
    /// three outcomes:
    ///
    /// | this method | the C |
    /// |---|---|
    /// | [`None`] (the default) | `fread_func != fread`, so no attempt |
    /// | `Some(Ok(()))` | `fseek` returned other than -1: success |
    /// | `Some(Err(_))` | `fseek` returned -1: fall through and fail |
    ///
    /// The error is [`std::io::Error`] rather than an `errno` integer. The C
    /// only ever prints that integer into a trace line, and
    /// [`std::io::Error`]'s own rendering carries strictly more than the
    /// number.
    fn seek_to_start(&mut self) -> Option<std::io::Result<()>> {
        None
    }
}

/// The `origin` argument of `CURLOPT_SEEKFUNCTION`.
///
/// The C passes the C library's `SEEK_SET`, `SEEK_CUR` and `SEEK_END` through
/// unchanged; `lib/sendf.c` only ever passes `SEEK_SET`, at `:769` and `:831`.
/// All three are transcribed because the option's contract admits all three and
/// an adapter has to be able to express what it received.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum SeekOrigin {
    /// `SEEK_SET`: from the start of the stream. The only origin this module
    /// ever asks for.
    Start,
    /// `SEEK_CUR`: from the current position.
    Current,
    /// `SEEK_END`: from the end of the stream.
    End,
}

/// What `CURLOPT_SEEKFUNCTION` answered.
///
/// The three documented returns are `CURL_SEEKFUNC_OK` = 0,
/// `CURL_SEEKFUNC_FAIL` = 1 and `CURL_SEEKFUNC_CANTSEEK` = 2
/// (`include/curl/curl.h:380-382`). The C tests them as
/// `!= CURL_SEEKFUNC_OK` and then `!= CURL_SEEKFUNC_CANTSEEK`
/// (`lib/sendf.c:773-779`), so anything that is neither behaves as a failure --
/// which is why [`Self::Failed`] CARRIES the raw integer instead of discarding
/// it. `lib/sendf.c:835` prints exactly that integer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum SeekOutcome {
    /// `CURL_SEEKFUNC_OK`: the stream is positioned as asked.
    Ok,
    /// `CURL_SEEKFUNC_CANTSEEK`: the stream cannot seek, so the caller should
    /// read and discard instead. Only [`CrIn::resume_from`] acts on this;
    /// [`CrIn::rewind`] treats it as a failure, because the C's `if(err)` at
    /// `:834` tests any non-zero value.
    CantSeek,
    /// Any other value, including `CURL_SEEKFUNC_FAIL`. The integer is carried
    /// for the diagnostic.
    Failed(i32),
}

impl SeekOutcome {
    /// The raw integer a C callback would have returned.
    ///
    /// `CURL_SEEKFUNC_OK` = 0 and `CURL_SEEKFUNC_CANTSEEK` = 2 come from
    /// `include/curl/curl.h:380-382`; [`Self::Failed`] returns what it was
    /// given.
    #[allow(dead_code)]
    pub(crate) const fn as_i32(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::CantSeek => 2,
            Self::Failed(raw) => raw,
        }
    }

    /// Whether this is a failure by the test `lib/sendf.c:834` applies --
    /// `if(err)`, i.e. any non-zero value.
    #[allow(dead_code)]
    pub(crate) const fn is_nonzero(self) -> bool {
        self.as_i32() != 0
    }
}

/// `CURLOPT_SEEKFUNCTION` together with `CURLOPT_SEEKDATA`.
///
/// Fused into one object for the same reason [`ClientReadSource`] is; the
/// options stay separate at the ABI boundary.
#[allow(dead_code)]
pub(crate) trait SeekCallback: fmt::Debug {
    /// `seek_func(seek_client, offset, origin)` (`lib/sendf.c:769`, `:831`).
    fn seek(&mut self, offset: i64, origin: SeekOrigin) -> SeekOutcome;
}

/// The `cmd` argument of `CURLOPT_IOCTLFUNCTION`.
///
/// `curliocmd` (`include/curl/curl.h:452-456`). `lib/sendf.c:843` passes
/// [`Self::RestartRead`] and nothing else.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum IoCmd {
    /// `CURLIOCMD_NOP`: no operation.
    Nop,
    /// `CURLIOCMD_RESTARTREAD`: restart the read stream from its start.
    RestartRead,
}

/// What `CURLOPT_IOCTLFUNCTION` answered.
///
/// `curlioerr` (`include/curl/curl.h:446-449`). The C tests `if(err)`
/// (`lib/sendf.c:847`), so anything but [`Self::Ok`] is a failure, and
/// `:848` prints the integer -- which is why [`Self::as_i32`] exists.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum IoOutcome {
    /// `CURLIOE_OK` = 0: the operation succeeded.
    Ok,
    /// `CURLIOE_UNKNOWNCMD` = 1: the callback did not recognise the command.
    UnknownCmd,
    /// `CURLIOE_FAILRESTART` = 2: the callback could not restart the read.
    FailRestart,
}

impl IoOutcome {
    /// The raw integer a C callback would have returned, in the declaration
    /// order of `curlioerr` (`include/curl/curl.h:446-449`).
    #[allow(dead_code)]
    pub(crate) const fn as_i32(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::UnknownCmd => 1,
            Self::FailRestart => 2,
        }
    }
}

/// `CURLOPT_IOCTLFUNCTION` together with `CURLOPT_IOCTLDATA`.
#[allow(dead_code)]
pub(crate) trait IoctlCallback: fmt::Debug {
    /// `ioctl_func(data, cmd, ioctl_client)` (`lib/sendf.c:843-844`).
    ///
    /// The C hands the easy handle to the callback as its first argument. That
    /// argument does not appear here: an internal caller has no handle to pass,
    /// and the ABI shim -- which does -- supplies it when it adapts a C
    /// callback into this trait.
    fn ioctl(&mut self, cmd: IoCmd) -> IoOutcome;
}

/// The two writer stages and the one read source that live OUTSIDE this
/// module.
///
/// `do_init_writer_stack` (`lib/sendf.c:325-368`) names `Curl_cwt_out` from
/// `lib/cw-out.c` and `Curl_cwt_pause` from `lib/cw-pause.c`, and
/// `Curl_creader_set_fread` reads `data->state.fread_func`
/// (`lib/sendf.c:632`). All three would be imports of
/// `transfer/writeout.rs` and of the transfer engine, which the module
/// documentation rules out, so all three arrive here instead.
///
/// The base stack is still assembled HERE, in the exact C order, which is what
/// keeps the ordering guarantee in one auditable place; only the construction
/// of two stages is delegated.
///
/// # The read source must be the SAME stream every time
///
/// `cr_in_init` copies a function pointer and a client-data pointer, so two
/// `cr_in` instances built from one handle read the SAME underlying stream, and
/// a rewind performed through one is visible to the other. An implementation of
/// [`Self::input_source`] must preserve that: successive calls have to yield
/// handles onto one stream, not independent copies of it. Sharing the state
/// behind an [`std::rc::Rc`] is the usual way; the C's shared `FILE *` is
/// exactly the same arrangement.
#[allow(dead_code)]
pub(crate) trait ClientIoFactory<'data>: fmt::Debug {
    /// `Curl_cwt_out` at [`ClientWriterPhase::Client`]
    /// (`lib/sendf.c:331-332`).
    ///
    /// The returned stage must report [`ClientWriterKind::ClientOut`] and
    /// [`ClientWriterPhase::Client`]; [`ClientWriterStack::init_base`] asserts
    /// both in a debug build, because a stage at the wrong phase would be
    /// inserted in the wrong place and the whole ordering guarantee would go
    /// with it.
    fn client_out_writer(&self) -> Box<dyn ClientWriter + 'data>;

    /// `Curl_cwt_pause` at [`ClientWriterPhase::Protocol`]
    /// (`lib/sendf.c:339-340`).
    ///
    /// Must report [`ClientWriterKind::Pause`] and
    /// [`ClientWriterPhase::Protocol`].
    fn pause_writer(&self) -> Box<dyn ClientWriter + 'data>;

    /// `data->state.fread_func` bound to `data->state.in`
    /// (`lib/sendf.c:632-633`).
    ///
    /// [`None`] stands for a null `fread_func`, which the C tolerates: its
    /// guard at `:667` is `if(ctx->read_cb && blen)`, so a missing callback
    /// yields zero bytes and is then judged by the same `case 0:` arm as a
    /// genuine end of file.
    fn input_source(&self) -> Option<Box<dyn ClientReadSource + 'data>>;
}

// =========================================================================
// The request state this module owns -- migrated out of the god-struct
// =========================================================================

/// The write-side fields of `struct SingleRequest` that the writer chain reads
/// and writes.
///
/// Specification 0.1.2 requires the fields of `lib/urldata.h`'s god-struct to
/// migrate to the module that owns their lifecycle, and these eight are the
/// ones `lib/sendf.c` touches. `transfer/request.rs` EMBEDS this struct rather
/// than restating its fields, exactly as `struct pgrs_dir` embeds a
/// `struct Curl_rlimit`.
///
/// Every field is transcribed from `lib/request.h:57-134` except
/// [`Self::header_size`], which is `data->info.header_size`
/// (`lib/urldata.h:764`) and is read here but never written.
///
/// # Fields, not accessors
///
/// The C reads and writes these as plain struct members from several
/// translation units, and eight pairs of accessors would add nothing a reader
/// could not already see. What accessors WOULD hide is the initial state, so
/// that is stated explicitly in [`Default`]: three of the fields start at -1,
/// and a derived `Default` -- which would start them at zero -- would be
/// wrong in a way no test of this module could catch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct RequestWriteState {
    /// `req.size`: the expected response body length, or -1 when it is not
    /// known at this point (`lib/request.h:57`).
    ///
    /// Read twice: to size the download rate limiter (`lib/sendf.c:203`) and
    /// to detect a truncated response (`lib/sendf.c:242`).
    pub(crate) size: i64,

    /// `req.maxdownload`: the most body data to fetch, or -1 for unlimited
    /// (`lib/request.h:58-59`).
    ///
    /// Distinct from [`ClientConfig::max_filesize`]: this is what the PROTOCOL
    /// says the response contains, and exceeding it is an excess to be reported
    /// and then dropped; the other is what the USER permitted, and exceeding it
    /// fails the transfer.
    pub(crate) maxdownload: i64,

    /// `req.bytecount`: the total number of body bytes accepted so far
    /// (`lib/request.h:60`).
    ///
    /// Advanced ONLY by bytes actually written downstream, never by bytes
    /// clamped away -- `lib/sendf.c:267-270` increments by `nwrite`, not by
    /// `nbytes`.
    pub(crate) bytecount: i64,

    /// `req.headerline`: counts header lines so that the first one can be
    /// recognised (`lib/request.h:74-75`).
    ///
    /// Not read by `lib/sendf.c`; it is RESET by it, at `:76` and `:92`,
    /// which is why it lives with the rest of the state the reset touches.
    pub(crate) headerline: i32,

    /// `data->info.header_size`: the size of the received headers, in bytes
    /// (`lib/urldata.h:764`, a `uint32_t`).
    ///
    /// Read once, at `lib/sendf.c:219`, to decide whether a body arriving on a
    /// bodyless response is tolerable: headers already received means the
    /// server answered, so the transfer succeeds; nothing received means the
    /// reply was weird.
    pub(crate) header_size: u32,

    /// `req.no_body`: the response has no body (`lib/request.h:124`).
    ///
    /// Set for a `HEAD` request and for a status the protocol defines as
    /// bodyless. Body bytes arriving anyway are an error, not something to
    /// discard -- which is what makes this DIFFERENT from
    /// [`Self::ignorebody`].
    pub(crate) no_body: bool,

    /// `req.ignorebody`: a response body is being read and thrown away
    /// (`lib/request.h:116`).
    ///
    /// Set while a body is being drained -- an authentication round that will
    /// be retried, for instance. The bytes are counted and their progress is
    /// reported, but they are not written to the client and neither the
    /// user's size limit nor the excess report applies to them.
    pub(crate) ignorebody: bool,

    /// `req.download_done`: the download is complete (`lib/request.h:105`).
    ///
    /// Written by [`DownloadWriter`] in three situations: a body arrived on a
    /// bodyless response, the protocol's maximum was exactly reached, and the
    /// protocol's maximum was exceeded.
    pub(crate) download_done: bool,
}

impl Default for RequestWriteState {
    /// The state `Curl_req_init` leaves behind, with the three sentinels the C
    /// sets explicitly.
    ///
    /// `size` and `maxdownload` are -1 -- "unknown" and "unlimited"
    /// respectively -- because zero means something entirely different for
    /// both: a zero `size` is an empty response, and a zero `maxdownload`
    /// would forbid every byte.
    fn default() -> Self {
        Self {
            size: -1,
            maxdownload: -1,
            bytecount: 0,
            headerline: 0,
            header_size: 0,
            no_body: false,
            ignorebody: false,
            download_done: false,
        }
    }
}

/// The read-side fields of `struct SingleRequest` that the reader chain reads
/// and writes.
///
/// Two flags, both transcribed from `lib/request.h:110` and `:133`, and both
/// owned here for the same reason the write-side fields are.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct RequestReadState {
    /// `req.rewind_read`: the reader needs a rewind at the next start
    /// (`lib/request.h:110`).
    ///
    /// Set by the retry logic through [`ClientIo::set_rewind`], read by
    /// [`ClientIo::client_reset`] to decide whether the reader chain survives
    /// the reset, and cleared by [`ClientIo::client_start`] once the rewind has
    /// been performed.
    pub(crate) rewind_read: bool,

    /// `req.reader_started`: client reads have begun
    /// (`lib/request.h:133`).
    ///
    /// The guard that makes the upload rate limiter start exactly once per
    /// reader chain (`lib/sendf.c:1197-1200`), and cleared whenever the chain
    /// is torn down (`lib/sendf.c:61`).
    pub(crate) reader_started: bool,
}

/// The settings both chains consult, gathered from `data->set` and
/// `data->state`.
///
/// Seven values, each cited to the field the C reads. They are gathered into
/// one borrowed struct rather than reached for individually so that a stage
/// receives one shared reference instead of a handle it could write through:
/// nothing in `lib/sendf.c` modifies a setting, and this type makes that
/// structural.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ClientConfig {
    /// `data->set.suppress_connect_headers`, read at `lib/sendf.c:192`.
    ///
    /// When set, a header received while proxying is dropped instead of being
    /// forwarded -- `--suppress-connect-headers`.
    pub(crate) suppress_connect_headers: bool,

    /// `data->set.max_filesize`, read at `lib/sendf.c:251-252`.
    ///
    /// Zero means no limit, which is why the C tests
    /// `if(data->set.max_filesize)` rather than comparing against -1. That is
    /// the opposite convention from [`RequestWriteState::maxdownload`], and
    /// both are preserved.
    pub(crate) max_filesize: i64,

    /// `data->set.verbose`, read at `lib/sendf.c:310`.
    ///
    /// Gates the raw body trace, together with
    /// [`RequestWriteState::ignorebody`].
    pub(crate) verbose: bool,

    /// `data->set.crlf`, read at `lib/sendf.c:1111`.
    ///
    /// `--crlf`: convert bare line feeds in uploaded data into carriage
    /// return / line feed pairs.
    pub(crate) crlf: bool,

    /// `data->state.prefer_ascii`, read at `lib/sendf.c:1113` under
    /// `CURL_PREFER_LF_LINEENDS`.
    ///
    /// The C compiles this disjunct in only on platforms whose native line
    /// ending is a bare line feed. There is no such conditional here: the
    /// field is always present and defaults to false, so a build for a target
    /// that does not want it behaves exactly as the C's disabled branch does,
    /// and no Cargo feature is invented for a platform distinction that the
    /// four mandated targets do not draw.
    pub(crate) prefer_ascii: bool,

    /// Whether the scheme in play carries `PROTOPT_NONETWORK`
    /// (`lib/urldata.h:535`), read at `lib/sendf.c:698`.
    ///
    /// True only for `file://` among the nine schemes that carry transfers.
    /// Such a transfer cannot be paused, because it does not run through the
    /// normal procedure, so a pause request from the input callback is an
    /// error rather than a pause.
    pub(crate) nonetwork: bool,

    /// `data->state.infilesize`, read at `lib/sendf.c:1151` and `:1192`.
    ///
    /// The length the application declared for the upload, or -1 when it did
    /// not. This is the value the lazily created input reader is given as its
    /// total length.
    pub(crate) infilesize: i64,
}

impl Default for ClientConfig {
    /// Every setting off, and `infilesize` at the C's -1 for "not declared".
    ///
    /// A derived `Default` would put a zero there, which means "an upload of
    /// no bytes" and is a different transfer.
    fn default() -> Self {
        Self {
            suppress_connect_headers: false,
            max_filesize: 0,
            verbose: false,
            crlf: false,
            prefer_ascii: false,
            nonetwork: false,
            infilesize: -1,
        }
    }
}

// =========================================================================
// The call context -- the safe successor of `struct Curl_easy *data`
// =========================================================================

/// Everything a stage needs that is not its own state.
///
/// Every function in `lib/sendf.c` takes `struct Curl_easy *data` and reaches
/// through it for whatever it wants: the request state, the settings, the
/// progress counters, the connection, the callbacks, the trace level. This is
/// the same argument with the reach made explicit -- ten borrows, each of which
/// a reader can enumerate, instead of one pointer into 200 fields.
///
/// # Why ONE context and not one per direction
///
/// A write context and a read context would each have to hold
/// `&mut Progress`, `&mut dyn TransferControl` and the trace sink, and two
/// simultaneous mutable borrows of the same three things do not exist. The C
/// has one `data` for both directions and so does this. A writer can therefore
/// reach the seek callback, which it has no business with -- exactly as in the
/// C, and the alternative costs more than the discipline does.
///
/// # The clock
///
/// The only instant this module uses arrives through [`Self::clock`], and it is
/// sampled through [`Progress::sample`] so that the reading is stored where
/// `Curl_pgrs_now` stores it (`lib/progress.c:171-177`). Nothing here calls a
/// host clock, which is what lets [`crate::util::timeval::TestClock`] pin every
/// rate-limit and start-transfer assertion in the test module.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ClientCtx<'ctx> {
    /// The write-side request state.
    write: &'ctx mut RequestWriteState,
    /// The read-side request state.
    read: &'ctx mut RequestReadState,
    /// The settings, borrowed shared because nothing here writes one.
    config: &'ctx ClientConfig,
    /// The transfer's accounting: timers, byte counters and both rate
    /// limiters.
    progress: &'ctx mut Progress,
    /// The injected clock.
    clock: &'ctx dyn Clock,
    /// The three operations that belong to the transfer engine.
    control: &'ctx mut dyn TransferControl,
    /// The in-callback flag every application callback is bracketed with.
    guard: &'ctx mut dyn ClientCallbackGuard,
    /// `data->set.seek_func` bound to `data->set.seek_client`. [`None`] is the
    /// ordinary case: the option is unset by default.
    seek: Option<&'ctx mut dyn SeekCallback>,
    /// `data->set.ioctl_func` bound to `data->set.ioctl_client`. [`None`] is
    /// the ordinary case.
    ioctl: Option<&'ctx mut dyn IoctlCallback>,
    /// Where trace lines go, when the transfer is tracing at all. [`None`] is
    /// the ordinary case, because `CURLOPT_VERBOSE` is off by default.
    trace: Option<&'ctx mut dyn TraceSink>,
}

impl<'ctx> ClientCtx<'ctx> {
    /// A context over the six things every transfer has, tracing nothing and
    /// with neither optional callback installed.
    ///
    /// The three optional seams are attached with [`Self::with_seek`],
    /// [`Self::with_ioctl`] and [`Self::with_trace`], following the
    /// `CallCtx::new(clock).with_tracer(...)` shape that `conn/filters.rs`
    /// already uses for the same reason: a constructor with ten parameters is
    /// unreadable at the call site and three of them are almost always absent.
    #[allow(dead_code)]
    pub(crate) fn new(
        write: &'ctx mut RequestWriteState,
        read: &'ctx mut RequestReadState,
        config: &'ctx ClientConfig,
        progress: &'ctx mut Progress,
        clock: &'ctx dyn Clock,
        control: &'ctx mut dyn TransferControl,
        guard: &'ctx mut dyn ClientCallbackGuard,
    ) -> Self {
        Self {
            write,
            read,
            config,
            progress,
            clock,
            control,
            guard,
            seek: None,
            ioctl: None,
            trace: None,
        }
    }

    /// Attaches `CURLOPT_SEEKFUNCTION`.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn with_seek(
        mut self,
        seek: &'ctx mut dyn SeekCallback,
    ) -> Self {
        self.seek = Some(seek);
        self
    }

    /// Attaches `CURLOPT_IOCTLFUNCTION`.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn with_ioctl(
        mut self,
        ioctl: &'ctx mut dyn IoctlCallback,
    ) -> Self {
        self.ioctl = Some(ioctl);
        self
    }

    /// Attaches the transfer's trace sink.
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn with_trace(mut self, trace: &'ctx mut dyn TraceSink) -> Self {
        self.trace = Some(trace);
        self
    }

    // ---- the state and the settings -------------------------------------

    /// The write-side request state, shared.
    #[allow(dead_code)]
    pub(crate) fn write_state(&self) -> &RequestWriteState {
        self.write
    }

    /// The write-side request state, mutable.
    #[allow(dead_code)]
    pub(crate) fn write_state_mut(&mut self) -> &mut RequestWriteState {
        self.write
    }

    /// The read-side request state, shared.
    #[allow(dead_code)]
    pub(crate) fn read_state(&self) -> &RequestReadState {
        self.read
    }

    /// The read-side request state, mutable.
    #[allow(dead_code)]
    pub(crate) fn read_state_mut(&mut self) -> &mut RequestReadState {
        self.read
    }

    /// The settings.
    #[allow(dead_code)]
    pub(crate) fn config(&self) -> &ClientConfig {
        self.config
    }

    /// The transfer's accounting, mutable.
    #[allow(dead_code)]
    pub(crate) fn progress_mut(&mut self) -> &mut Progress {
        self.progress
    }

    /// The transfer engine's three operations.
    #[allow(dead_code)]
    pub(crate) fn control(&mut self) -> &mut dyn TransferControl {
        self.control
    }

    // ---- the clock ------------------------------------------------------

    /// Samples the injected clock and stores the reading -- `Curl_pgrs_now`
    /// (`lib/progress.c:171-177`).
    ///
    /// Takes `&mut self` because the reading is STORED, which is what the C
    /// does: `curlx_pnow(pnow)` writes through a pointer into either the multi
    /// handle or the progress struct, so a later reader of `progress.now` sees
    /// this instant.
    #[allow(dead_code)]
    pub(crate) fn pgrs_now(&mut self) -> CurlTime {
        // The clock is a shared reference and therefore `Copy`, so lifting it
        // out first is what lets the progress borrow be mutable. Reading
        // `self.progress.sample(self.clock)` directly would borrow `self`
        // twice.
        let clock = self.clock;
        self.progress.sample(clock)
    }

    /// Records the current instant against `timer` -- `Curl_pgrsTime`
    /// (`lib/progress.c:323-326`).
    ///
    /// Exists for the same borrow reason [`Self::pgrs_now`] lifts the clock
    /// out.
    #[allow(dead_code)]
    pub(crate) fn pgrs_time(&mut self, timer: TimerId) {
        let clock = self.clock;
        self.progress.time(timer, clock);
    }

    // ---- the application callbacks --------------------------------------

    /// Raises the in-callback flag for the duration of the returned scope.
    ///
    /// For a callback the CALLER owns -- the input source, which a reader holds
    /// in its own field. The two optional callbacks live in this context
    /// instead, and are bracketed by [`Self::call_seek`] and
    /// [`Self::call_ioctl`], which cannot be expressed this way: handing out a
    /// scope that borrows `self` mutably would leave no way to reach the
    /// callback beside it.
    #[allow(dead_code)]
    pub(crate) fn enter_callback(&mut self) -> InCallback<'_> {
        InCallback::enter(self.guard)
    }

    /// Whether `CURLOPT_SEEKFUNCTION` is installed.
    ///
    /// [`CrIn::rewind`] branches on this BEFORE calling, because the C's
    /// `if(data->set.seek_func) ... else if(data->set.ioctl_func) ... else ...`
    /// (`lib/sendf.c:827-852`) chooses a strategy by which option is set and
    /// not by what the call returned.
    #[allow(dead_code)]
    pub(crate) fn has_seek(&self) -> bool {
        self.seek.is_some()
    }

    /// Whether `CURLOPT_IOCTLFUNCTION` is installed.
    #[allow(dead_code)]
    pub(crate) fn has_ioctl(&self) -> bool {
        self.ioctl.is_some()
    }

    /// Calls `CURLOPT_SEEKFUNCTION` with the flag raised, or reports that
    /// there is none.
    ///
    /// [`None`] means the option is unset. `lib/sendf.c:760` initialises
    /// `seekerr` to `CURL_SEEKFUNC_CANTSEEK` before testing the option, so
    /// [`CrIn::resume_from`] reads a missing callback as
    /// [`SeekOutcome::CantSeek`] -- which is why this returns an [`Option`]
    /// rather than substituting a value here.
    #[allow(dead_code)]
    pub(crate) fn call_seek(
        &mut self,
        offset: i64,
        origin: SeekOrigin,
    ) -> Option<SeekOutcome> {
        // Destructured so that the guard and the callback are two disjoint
        // borrows of one context. `self.guard` and `self.seek` reached through
        // `self` would be two mutable borrows of the whole struct.
        let Self { guard, seek, .. } = self;
        let seek = seek.as_deref_mut()?;
        let _entered = InCallback::enter(&mut **guard);
        Some(seek.seek(offset, origin))
    }

    /// Calls `CURLOPT_IOCTLFUNCTION` with the flag raised, or reports that
    /// there is none.
    #[allow(dead_code)]
    pub(crate) fn call_ioctl(&mut self, cmd: IoCmd) -> Option<IoOutcome> {
        let Self { guard, ioctl, .. } = self;
        let ioctl = ioctl.as_deref_mut()?;
        let _entered = InCallback::enter(&mut **guard);
        Some(ioctl.ioctl(cmd))
    }

    // ---- diagnostics ----------------------------------------------------

    /// `Curl_debug(data, kind, bytes, len)`, when a sink is installed.
    #[allow(dead_code)]
    pub(crate) fn debug(&mut self, kind: TraceDataKind, bytes: &[u8]) {
        if let Some(trace) = self.trace.as_deref_mut() {
            trace.debug(kind, bytes);
        }
    }

    /// `CURL_TRC_WRITE(data, ...)`, when a sink is installed.
    #[allow(dead_code)]
    pub(crate) fn trc_write(&mut self, line: fmt::Arguments<'_>) {
        if let Some(trace) = self.trace.as_deref_mut() {
            trace.trace_write(line);
        }
    }

    /// `CURL_TRC_READ(data, ...)`, when a sink is installed.
    #[allow(dead_code)]
    pub(crate) fn trc_read(&mut self, line: fmt::Arguments<'_>) {
        if let Some(trace) = self.trace.as_deref_mut() {
            trace.trace_read(line);
        }
    }

    /// `infof(data, ...)`, when a sink is installed.
    #[allow(dead_code)]
    pub(crate) fn infof(&mut self, line: fmt::Arguments<'_>) {
        if let Some(trace) = self.trace.as_deref_mut() {
            trace.infof(line);
        }
    }

    /// `failf(data, ...)` AND the [`Error`] that accompanies it.
    ///
    /// Every `failf` in `lib/sendf.c` is immediately followed by a return of a
    /// specific code, and the text is what reaches `CURLOPT_ERRORBUFFER`. This
    /// does both halves in one call so the two cannot drift apart, and it
    /// attaches the text to the error as well as to the sink -- so the
    /// diagnostic survives even on a transfer that is not tracing, where the C
    /// would still have written the error buffer.
    ///
    /// The line is formatted exactly once, into a `String`, because it is
    /// needed twice: [`fmt::Arguments`] renders through [`fmt::Display`], and
    /// the resulting owned string then serves both the sink and the error.
    #[allow(dead_code)]
    pub(crate) fn failf(
        &mut self,
        code: CURLcode,
        line: fmt::Arguments<'_>,
    ) -> Error {
        let text = line.to_string();
        if let Some(trace) = self.trace.as_deref_mut() {
            trace.failf(format_args!("{text}"));
        }
        Error::with_context(code, text)
    }
}

// =========================================================================
// The writer contract -- `struct Curl_cwtype` and `struct Curl_cwriter`
// =========================================================================

/// One stage of the writer chain.
///
/// Supersedes `struct Curl_cwtype` (`lib/sendf.h:110-121`) together with
/// `struct Curl_cwriter` (`:129-134`). Four of the six C members disappear
/// outright:
///
/// * `size_t cwriter_size` -- a Rust value knows its own size, so there is
///   nothing to record and nothing to assert against.
/// * `void *ctx` -- a stage's state lives in the stage's own fields. There is
///   no self-referential allocation pointer and no downcast, which is what
///   makes the alignment hazard of curl PR 13054 structurally impossible.
/// * `struct Curl_cwriter *next` -- the STACK owns the chain and passes each
///   stage a [`WriterTail`] over the remainder. A stage cannot free, replace or
///   outlive its successor.
/// * `const char *name` and `const char *alias` -- answered from
///   [`Self::kind`], so a stage states its identity once.
///
/// # The default implementations
///
/// `Curl_cwriter_def_init`, `Curl_cwriter_def_write` and
/// `Curl_cwriter_def_close` (`lib/sendf.c:137-157`) are the C's way of letting
/// a stage opt out of a member, and eight of the fourteen registered types use
/// at least one of them. They are the DEFAULT METHOD BODIES here, so a
/// monitoring stage that neither initialises nor closes nor transforms writes
/// exactly one method: [`Self::kind`], [`Self::phase`] and nothing else.
#[allow(dead_code)]
pub(crate) trait ClientWriter: fmt::Debug {
    /// Which writer this is, and therefore what it is called.
    ///
    /// The successor of both `cwt->name` and the `writer->cwt == cwt` identity
    /// test; see [`ClientWriterKind`].
    fn kind(&self) -> ClientWriterKind;

    /// The phase this INSTANCE operates at.
    ///
    /// A method rather than a field this module records, because the phase is
    /// per-instance: `lib/content_encoding.c` installs one decoder type at
    /// either [`ClientWriterPhase::TransferDecode`] or
    /// [`ClientWriterPhase::ContentDecode`] depending on which header carried
    /// the coding.
    fn phase(&self) -> ClientWriterPhase;

    /// The `name` member of `struct Curl_cwtype` (`lib/sendf.h:111`).
    ///
    /// Answered from [`Self::kind`]. Overriding it would let a stage's name and
    /// its identity disagree, and [`ClientWriterStack::get_by_name`] looks it
    /// up by this method, so the two must be one thing.
    fn name(&self) -> &'static str {
        self.kind().name()
    }

    /// The `alias` member of `struct Curl_cwtype` (`lib/sendf.h:112`), which is
    /// `NULL` for all but `gzip` and `identity`.
    fn alias(&self) -> Option<&'static str> {
        self.kind().alias()
    }

    /// `do_init` (`lib/sendf.h:113`), invoked by
    /// [`ClientWriterStack::create`].
    ///
    /// Defaults to `Curl_cwriter_def_init` (`lib/sendf.c:137-143`): nothing at
    /// all.
    fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        let _ = ctx;
        Ok(())
    }

    /// `do_write` (`lib/sendf.h:115-117`).
    ///
    /// Defaults to `Curl_cwriter_def_write` (`lib/sendf.c:145-150`): forward
    /// the bytes and the flags downstream, entirely unchanged. A stage that
    /// only observes therefore needs no body here at all, and a stage that
    /// TRANSFORMS must be at [`ClientWriterPhase::TransferDecode`] or
    /// [`ClientWriterPhase::ContentDecode`] -- the other three phases are for
    /// monitoring, as `lib/sendf.h:94-97` states.
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        tail.write(ctx, flags, buf)
    }

    /// `do_close` (`lib/sendf.h:118-119`), invoked when the stage leaves the
    /// chain.
    ///
    /// Defaults to `Curl_cwriter_def_close` (`lib/sendf.c:152-157`): nothing.
    fn close(&mut self, ctx: &mut ClientCtx<'_>) {
        let _ = ctx;
    }

    /// Whether this stage is holding bytes back because the transfer is paused.
    ///
    /// `Curl_cwriter_is_paused` (`lib/sendf.c:505-508`) delegates straight to
    /// `Curl_cw_out_is_paused`, reaching into `lib/cw-out.c` for one stage's
    /// private state. Asking every stage instead is equivalent -- no other
    /// stage can be paused -- and it removes the import that made the question
    /// a cycle. Defaults to false.
    fn is_paused(&self) -> bool {
        false
    }

    /// Releases anything this stage held back, now that the transfer is no
    /// longer paused.
    ///
    /// `Curl_cwriter_unpause` (`lib/sendf.c:510-513`) delegates to
    /// `Curl_cw_out_unpause`, and the same reasoning as [`Self::is_paused`]
    /// applies. The stage receives its own tail, so a flush travels downstream
    /// exactly as an ordinary write does. Defaults to nothing.
    fn unpause(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
    ) -> CurlResult<()> {
        let _ = (ctx, tail);
        Ok(())
    }

    /// Clears this stage's paused state without flushing anything.
    ///
    /// `ctx->paused = FALSE` (`lib/cw-out.c:496`) alone, separated from the two
    /// flushes that follow it there so that an upstream stage can perform the
    /// C's first step at the C's moment. [`WriterTail::clear_pause`] documents
    /// why the separation is needed and which order it restores.
    ///
    /// Defaults to nothing, which is right for every stage that cannot be
    /// paused -- and only the client-output stage can be.
    fn clear_pause(&mut self) {}

    /// Flushes everything this stage still holds, because the download has
    /// ended.
    ///
    /// `Curl_cw_out_done` (`lib/cw-out.c:504-517`) is the entry point, and it
    /// differs from [`Self::unpause`] in exactly one respect that is
    /// observable: it flushes with `flush_all` TRUE, so a stage that would
    /// otherwise hold a short write back for collation must emit it. Nothing is
    /// unpaused -- a paused transfer that is finished stays paused and the C's
    /// two flushes both decline, which is why this is a separate operation
    /// rather than an argument to the one above.
    ///
    /// The stage receives its own tail, so a flush travels downstream exactly
    /// as an ordinary write does. Defaults to nothing.
    fn done(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
    ) -> CurlResult<()> {
        let _ = (ctx, tail);
        Ok(())
    }
}

/// The remainder of a writer chain, below the stage currently running.
///
/// The successor of `struct Curl_cwriter`'s `next` member. Where the C
/// dereferences a pointer that may be `NULL`, this splits a slice that may be
/// empty -- and an empty split is where `CURLE_WRITE_ERROR` comes from, exactly
/// as `Curl_cwriter_write`'s `if(!writer)` does (`lib/sendf.c:132-133`).
///
/// A stage cannot reach PAST its tail to a stage above it, cannot reorder the
/// chain and cannot hold the tail beyond its own call, because the borrow
/// checker will not let it. Those are three classes of defect the C's raw
/// pointers admit and this does not.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct WriterTail<'stack, 'data> {
    stages: &'stack mut [Box<dyn ClientWriter + 'data>],
}

impl<'stack, 'data> WriterTail<'stack, 'data> {
    /// A tail over `stages`.
    #[allow(dead_code)]
    fn new(stages: &'stack mut [Box<dyn ClientWriter + 'data>]) -> Self {
        Self { stages }
    }

    /// An empty tail -- the successor of a `NULL` `next` pointer.
    ///
    /// Writing through it is [`CURLcode::WriteError`], which is what makes the
    /// bottom of the chain behave as the C's does.
    #[allow(dead_code)]
    fn empty() -> Self {
        Self { stages: &mut [] }
    }

    /// How many stages remain below the caller.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.stages.len()
    }

    /// Whether the caller is the last stage in the chain.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// `Curl_cwriter_is_paused(data)` (`lib/sendf.c:505-508`), asked of the
    /// stages BELOW the caller.
    ///
    /// The C walks the whole chain from `data`; a stage asking through its tail
    /// reaches strictly less. That is not a narrowing in practice, and the
    /// phase ordering is what guarantees it: the only stage that can be paused
    /// is the client-output stage at [`ClientWriterPhase::Client`], which is
    /// last in the chain, so it is in the tail of every stage that could ask.
    ///
    /// `lib/cw-pause.c:107` and `:151` are the two call sites this exists for,
    /// and both are inside a stage at [`ClientWriterPhase::Protocol`].
    #[allow(dead_code)]
    pub(crate) fn is_paused(&self) -> bool {
        self.stages.iter().any(|stage| stage.is_paused())
    }

    /// `Curl_cwriter_is_content_decoding(data)` (`lib/sendf.c:495-503`), asked
    /// of the stages BELOW the caller.
    ///
    /// The same reasoning as [`Self::is_paused`], and the same guarantee from
    /// the same source: [`ClientWriterPhase::ContentDecode`] sorts after
    /// [`ClientWriterPhase::Protocol`], so every decoder is in the tail of the
    /// pause stage that asks. A PHASE test and not a kind test, exactly as the
    /// C's is.
    ///
    /// `lib/cw-pause.c:103` and `:149` are the call sites.
    #[allow(dead_code)]
    pub(crate) fn is_content_decoding(&self) -> bool {
        self.stages
            .iter()
            .any(|stage| stage.phase() == ClientWriterPhase::ContentDecode)
    }

    /// `ctx->paused = FALSE` (`lib/cw-out.c:496`), applied to the stages BELOW
    /// the caller.
    ///
    /// This exists so that `Curl_cw_out_unpause`'s ORDER survives the
    /// decomposition. The C is one function that clears the client stage's flag
    /// and then flushes two stages in a fixed sequence (`lib/cw-out.c:487-502`):
    ///
    /// 1. clear the client stage's `paused` flag;
    /// 2. `Curl_cw_pause_flush(data)` -- drain the bytes that were in flight;
    /// 3. `cw_out_flush(data, cw_out, FALSE)` -- drain the client stage.
    ///
    /// [`ClientWriterStack::unpause`] walks the chain from the top, so it
    /// reaches the pause stage (at [`ClientWriterPhase::Protocol`]) BEFORE the
    /// client stage (at [`ClientWriterPhase::Client`]). Step 2 therefore runs
    /// first -- and its loop condition is `!Curl_cwriter_is_paused(data)`, so
    /// without step 1 having happened it would find the transfer still paused
    /// and drain nothing. Calling this at the top of the pause stage's
    /// [`ClientWriter::unpause`] performs step 1 at exactly the point the C
    /// performs it, and the walk then delivers step 3 on its own.
    ///
    /// Clearing rather than toggling: there is no counterpart that SETS the
    /// flag, because a pause originates inside the client stage itself, from a
    /// callback's return value.
    #[allow(dead_code)]
    pub(crate) fn clear_pause(&mut self) {
        for stage in self.stages.iter_mut() {
            stage.clear_pause();
        }
    }

    /// `Curl_cwriter_write(data, writer->next, type, buf, nbytes)`
    /// (`lib/sendf.c:128-135`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::WriteError`] when the tail is empty, which is the C's
    /// `if(!writer) return CURLE_WRITE_ERROR` verbatim. Otherwise whatever the
    /// next stage returns, unchanged -- no code is remapped on the way back
    /// up, because a stage's caller distinguishes them.
    #[allow(dead_code)]
    pub(crate) fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        match self.stages.split_first_mut() {
            // `lib/sendf.c:132-133`.
            None => Err(Error::new(CURLcode::WriteError)),
            Some((head, rest)) => {
                let mut tail = WriterTail::new(rest);
                head.write(ctx, &mut tail, flags, buf)
            }
        }
    }
}

/// The writer chain, owned.
///
/// Supersedes `data->req.writer_stack` (`lib/request.h:87`) and the eight
/// functions that walk it. The chain is a [`Vec`] ordered by phase, lowest
/// first, so index 0 is the stage a write reaches first.
///
/// A [`Vec`] and not a [`std::collections::VecDeque`], even though every
/// insertion is at or near the front: [`Self::write`] needs one contiguous
/// slice to split, `split_first_mut` over a ring buffer's two halves does not
/// exist, and the chains are at most a handful of stages long. Specification
/// 0.1.1 settles the trade in any case -- performance is a non-goal, and
/// faithfulness to the ordering is what matters.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ClientWriterStack<'data> {
    stages: Vec<Box<dyn ClientWriter + 'data>>,
}

impl<'data> Default for ClientWriterStack<'data> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'data> ClientWriterStack<'data> {
    /// An empty chain.
    ///
    /// The state a fresh `struct SingleRequest` is in: `writer_stack` is
    /// `NULL` until the first write, or until the first
    /// [`Self::add`], builds the base stack.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// How many stages the chain holds, over every phase.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.stages.len()
    }

    /// Whether the chain is empty -- the C's `if(!data->req.writer_stack)`.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// `Curl_cwriter_count(data, phase)` (`lib/sendf.c:440-450`): how many
    /// stages of `phase` are installed.
    ///
    /// `lib/content_encoding.c` uses it to cap how many decoders may be
    /// stacked, which is why it counts a phase rather than the whole chain.
    #[allow(dead_code)]
    pub(crate) fn count(&self, phase: ClientWriterPhase) -> usize {
        self.stages.iter().filter(|w| w.phase() == phase).count()
    }

    /// Every stage's name, from the top of the chain down.
    ///
    /// Not a C function. It exists because the ORDER is the contract this
    /// module has to keep, and a test that asserts a list of names is a direct
    /// assertion about it; reading the order out of the C requires walking
    /// `next` pointers in a debugger.
    #[allow(dead_code)]
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.stages.iter().map(|w| w.name()).collect()
    }

    /// `Curl_cwriter_create` (`lib/sendf.c:404-429`): initialise a stage,
    /// before it joins any chain.
    ///
    /// Three of the C's four concerns are gone. There is no allocation to fail,
    /// so `CURLE_OUT_OF_MEMORY` cannot arise here; there is no `writer->ctx`
    /// self-pointer to set; and there is no phase to record, because the stage
    /// answers [`ClientWriter::phase`] itself. What remains is the one thing
    /// that matters: `do_init` runs, and a stage whose initialisation fails is
    /// destroyed rather than returned.
    ///
    /// # Errors
    ///
    /// Whatever [`ClientWriter::init`] returns. The stage is dropped on the way
    /// out, which is the C's `curlx_free(writer)` at `:427` -- and unlike the C
    /// there is no `*pwriter = NULL` for a caller to forget to check.
    #[allow(dead_code)]
    pub(crate) fn create(
        mut writer: Box<dyn ClientWriter + 'data>,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<Box<dyn ClientWriter + 'data>> {
        writer.init(ctx)?;
        Ok(writer)
    }

    /// `Curl_cwriter_free` (`lib/sendf.c:431-438`): close a stage that is not
    /// in a chain.
    ///
    /// Takes the stage BY VALUE, so a closed stage cannot be used again and
    /// cannot be closed twice -- two mistakes the C's pointer signature
    /// permits. The deallocation the C performs is the drop at the end of this
    /// function.
    #[allow(dead_code)]
    pub(crate) fn free(
        mut writer: Box<dyn ClientWriter + 'data>,
        ctx: &mut ClientCtx<'_>,
    ) {
        writer.close(ctx);
    }

    /// `Curl_cwriter_add` (`lib/sendf.c:452-471`): insert a stage FIRST WITHIN
    /// ITS PHASE.
    ///
    /// Two behaviours, and both are observable:
    ///
    /// 1. **A lazy base stack.** Adding to an EMPTY chain builds the base
    ///    stack first (`:458-462`), so a decoder installed before any write has
    ///    the same four stages beneath it as one installed after. The recursion
    ///    this implies in the C terminates because
    ///    `do_init_writer_stack` assigns the client stage DIRECTLY rather than
    ///    through `add`; [`Self::init_base`] does the same, for the same
    ///    reason.
    /// 2. **First within the phase.** Stages of a LOWER phase are skipped and
    ///    the new stage goes before every stage of its own phase
    ///    (`:466-469`). So adding two decoders at one phase reverses their
    ///    execution order relative to their installation order, which is
    ///    precisely how `lib/content_encoding.c` unwinds
    ///    `Content-Encoding: gzip, br` -- brotli comes off first because it was
    ///    added last.
    ///
    /// # Errors
    ///
    /// Only from building the base stack, and only when a factory-supplied
    /// stage fails to initialise. The insertion itself cannot fail.
    #[allow(dead_code)]
    pub(crate) fn add(
        &mut self,
        writer: Box<dyn ClientWriter + 'data>,
        ctx: &mut ClientCtx<'_>,
        factory: &dyn ClientIoFactory<'data>,
    ) -> CurlResult<()> {
        // `lib/sendf.c:458-462`.
        if self.stages.is_empty() {
            self.init_base(ctx, factory)?;
        }
        self.insert(writer);
        Ok(())
    }

    /// The insertion rule alone, without the lazy base stack.
    ///
    /// `lib/sendf.c:464-469`. Separated out because [`Self::init_base`] needs
    /// the rule while the chain is still being built, and calling
    /// [`Self::add`] there would re-enter the builder.
    #[allow(dead_code)]
    fn insert(&mut self, writer: Box<dyn ClientWriter + 'data>) {
        let phase = writer.phase();
        // `while(*anchor && (*anchor)->phase < writer->phase)`: the index of
        // the first stage that is NOT of a lower phase.
        let at = self
            .stages
            .iter()
            .position(|installed| installed.phase() >= phase)
            .unwrap_or(self.stages.len());
        self.stages.insert(at, writer);
    }

    /// `do_init_writer_stack` (`lib/sendf.c:325-368`): the four stages every
    /// transfer starts with.
    ///
    /// THE ORDER BELOW IS THE CONTRACT, and it is not the order the stages run
    /// in. Construction order, then the chain each step produces:
    ///
    /// | step | stage created | phase | chain afterwards |
    /// |---|---|---|---|
    /// | 1 | `cw-out` | `Client` | `cw-out` |
    /// | 2 | `cw-pause` | `Protocol` | `cw-pause`, `cw-out` |
    /// | 3 | `protocol` | `Protocol` | `protocol`, `cw-pause`, `cw-out` |
    /// | 4 | `raw` | `Raw` | `raw`, `protocol`, `cw-pause`, `cw-out` |
    ///
    /// So the execution order is `raw`, `protocol`, `cw-pause`, `cw-out`, and
    /// the pause stage ends up BEHIND the download stage even though it was
    /// installed FIRST. That inversion is the whole point of the C's comment at
    /// `:336-338`: *"This places the 'pause' writer behind the 'download'
    /// writer that is added below. Meaning the 'download' can do checks on
    /// content length and other things \*before\* write outs are buffered for
    /// paused transfers."* Install them the other way round and a paused
    /// transfer buffers bytes that the length check would have rejected.
    ///
    /// Step 1 assigns the client stage DIRECTLY, as the C does at `:331`, and
    /// not through [`Self::add`] -- which is what stops the lazy-init test in
    /// `add` from recursing.
    ///
    /// # Errors
    ///
    /// Whatever [`ClientWriter::init`] returns for a factory-supplied stage.
    /// The chain is left EMPTY on failure rather than half-built, so a caller
    /// that retries starts from a clean state; the C leaves a partial chain
    /// behind, which its caller then tears down through `Curl_client_reset`.
    ///
    /// # Panics
    ///
    /// In a debug build only, when a factory returns a stage of the wrong kind
    /// or phase. A `cw-out` at any phase but [`ClientWriterPhase::Client`]
    /// would not be last in the chain and every downstream write would land in
    /// the wrong place, so the mistake is worth naming loudly where it can be
    /// seen. A release build proceeds, exactly as the C's `DEBUGASSERT` does.
    #[allow(dead_code)]
    pub(crate) fn init_base(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        factory: &dyn ClientIoFactory<'data>,
    ) -> CurlResult<()> {
        // `lib/sendf.c:330`: `DEBUGASSERT(!data->req.writer_stack)`.
        debug_assert!(
            self.stages.is_empty(),
            "the base writer stack is built once, into an empty chain"
        );

        // Step 1 -- `lib/sendf.c:331-334`. Assigned directly.
        let out = factory.client_out_writer();
        debug_assert_eq!(
            out.kind(),
            ClientWriterKind::ClientOut,
            "the factory's client stage must report ClientOut"
        );
        debug_assert_eq!(
            out.phase(),
            ClientWriterPhase::Client,
            "the factory's client stage must be at CURL_CW_CLIENT"
        );
        // Assigned DIRECTLY rather than through `Self::insert`, which is what
        // makes the C's recursion terminate: `Curl_cwriter_add` calls this
        // builder when the chain is empty, so a builder that added its first
        // stage through `add` would re-enter itself for ever.
        self.stages.push(Self::create(out, ctx)?);

        // Step 2 -- `lib/sendf.c:339-347`. The pause stage, added FIRST so
        // that step 3 displaces it.
        let pause = factory.pause_writer();
        debug_assert_eq!(
            pause.kind(),
            ClientWriterKind::Pause,
            "the factory's pause stage must report Pause"
        );
        debug_assert_eq!(
            pause.phase(),
            ClientWriterPhase::Protocol,
            "the factory's pause stage must be at CURL_CW_PROTOCOL"
        );
        // A FAILURE HERE LEAVES THE PARTIAL CHAIN STANDING, and that is the
        // C's behaviour rather than an oversight in this transcription. Each of
        // the C's three steps reads `if(result) return result` (`:346-347`,
        // `:355-356`, `:364-365`) with nothing between it and the return: the
        // stage that failed is freed by `Curl_cwriter_create` itself
        // (`:426-427`), the stages already installed are NOT touched, and
        // `data->req.writer_stack` keeps pointing at them. `Curl_client_write`
        // then finds a non-null stack on its next call (`:390`) and writes
        // through the partial chain instead of rebuilding it. Clearing here
        // would be a different observable behaviour on the one path that can
        // reach it -- an allocation failure inside a stage's own `init` -- so
        // the plain `?` is the faithful form.
        self.insert(Self::create(pause, ctx)?);

        // Step 3 -- `lib/sendf.c:349-356`. The download stage, which lands
        // AHEAD of the pause stage because both are at the same phase.
        self.insert(Self::create(Box::new(DownloadWriter::new()), ctx)?);

        // Step 4 -- `lib/sendf.c:358-365`. The raw stage, at the top.
        self.insert(Self::create(Box::new(RawWriter::new()), ctx)?);

        // `lib/sendf.c:394`: `DEBUGASSERT(data->req.writer_stack)`.
        debug_assert_eq!(
            self.names(),
            vec!["raw", "protocol", "cw-pause", "cw-out"],
            "the base writer stack's order is the contract of \
             lib/sendf.c:325-368"
        );
        Ok(())
    }

    /// `Curl_cwriter_get_by_name` (`lib/sendf.c:473-482`): the first stage
    /// whose NAME matches.
    ///
    /// The alias is NOT consulted, and that asymmetry is the C's: `:478`
    /// compares `writer->cwt->name` alone, so looking up `"x-gzip"` finds
    /// nothing even though a `gzip` stage answers to that alias elsewhere.
    /// Reproduced rather than tidied.
    #[allow(dead_code)]
    pub(crate) fn get_by_name(
        &self,
        name: &str,
    ) -> Option<&(dyn ClientWriter + 'data)> {
        self.stages
            .iter()
            .find(|w| w.name() == name)
            .map(std::convert::AsRef::as_ref)
    }

    /// `Curl_cwriter_get_by_type` (`lib/sendf.c:484-493`): the first stage of
    /// the given kind.
    ///
    /// The C compares vtable ADDRESSES. Comparing a [`ClientWriterKind`] value
    /// is the same question asked safely, and it is the reason that enumeration
    /// exists.
    #[allow(dead_code)]
    pub(crate) fn get_by_kind(
        &self,
        kind: ClientWriterKind,
    ) -> Option<&(dyn ClientWriter + 'data)> {
        self.stages
            .iter()
            .find(|w| w.kind() == kind)
            .map(std::convert::AsRef::as_ref)
    }

    /// `Curl_cwriter_is_content_decoding` (`lib/sendf.c:495-503`): whether any
    /// stage removes a content encoding.
    ///
    /// A PHASE test and not a kind test, exactly as the C's is. That matters:
    /// the same decoder type installed at
    /// [`ClientWriterPhase::TransferDecode`] is NOT content decoding, and a
    /// kind test would report it as such.
    #[allow(dead_code)]
    pub(crate) fn is_content_decoding(&self) -> bool {
        self.stages
            .iter()
            .any(|w| w.phase() == ClientWriterPhase::ContentDecode)
    }

    /// `Curl_cwriter_is_paused` (`lib/sendf.c:505-508`): whether the chain is
    /// holding bytes back.
    #[allow(dead_code)]
    pub(crate) fn is_paused(&self) -> bool {
        self.stages.iter().any(|w| w.is_paused())
    }

    /// `Curl_cwriter_unpause` (`lib/sendf.c:510-513`): release whatever the
    /// chain held back.
    ///
    /// Each stage receives its own tail, so a stage that flushes writes
    /// downstream exactly as it would during an ordinary write. The walk stops
    /// at the first failure and returns it, which is what a delegation to one
    /// stage does when that stage is the only one that can fail.
    ///
    /// # Errors
    ///
    /// Whatever the first failing [`ClientWriter::unpause`] returns.
    #[allow(dead_code)]
    pub(crate) fn unpause(
        &mut self,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<()> {
        for index in 0..self.stages.len() {
            let (head, rest) = self.stages[index..]
                .split_first_mut()
                .expect("the index is below the length just measured");
            let mut tail = WriterTail::new(rest);
            head.unpause(ctx, &mut tail)?;
        }
        Ok(())
    }

    /// `Curl_cw_out_done` (`lib/cw-out.c:504-517`): the download has ended, so
    /// flush everything every stage still holds.
    ///
    /// Walks from the TOP of the chain, and that direction is the C's sequence
    /// rather than an arbitrary choice. `Curl_cw_out_done` calls
    /// `Curl_cw_pause_flush(data)` first and `cw_out_flush(data, cw_out, TRUE)`
    /// second; the pause stage is at [`ClientWriterPhase::Protocol`] and the
    /// client stage at [`ClientWriterPhase::Client`], so a top-down walk
    /// delivers them in exactly that order. Draining the in-flight buffer first
    /// is what puts those bytes AHEAD of nothing and BEHIND whatever the client
    /// stage already holds, because the pause stage writes downstream through
    /// the client stage, which appends and replays in arrival order.
    ///
    /// # Errors
    ///
    /// Whatever the first failing [`ClientWriter::done`] returns. The walk
    /// stops there, as the C's `if(!result)` between its two flushes does.
    #[allow(dead_code)]
    pub(crate) fn done(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        for index in 0..self.stages.len() {
            let (head, rest) = self.stages[index..]
                .split_first_mut()
                .expect("the index is below the length just measured");
            let mut tail = WriterTail::new(rest);
            head.done(ctx, &mut tail)?;
        }
        Ok(())
    }

    /// `Curl_cwriter_write(data, data->req.writer_stack, ...)`: drive the whole
    /// chain from the top.
    ///
    /// # Errors
    ///
    /// [`CURLcode::WriteError`] when the chain is EMPTY -- the C reaches the
    /// same code by the same route, passing a `NULL` `writer_stack` into
    /// `Curl_cwriter_write` -- and otherwise whatever a stage returns.
    ///
    /// The write-flag invariants are NOT asserted here; see
    /// [`ClientWriteFlags::is_valid`] for why `lib/ws.c:703` makes that the
    /// entry point's job alone.
    #[allow(dead_code)]
    pub(crate) fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        WriterTail::new(&mut self.stages).write(ctx, flags, buf)
    }

    /// `cl_reset_writer` (`lib/sendf.c:47-56`): close and discard every stage.
    ///
    /// The C pops from the HEAD, so stages close from the top of the chain
    /// down, and the order is preserved here because a stage that flushes on
    /// close writes to stages BELOW it -- closing the bottom first would
    /// discard those bytes.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self, ctx: &mut ClientCtx<'_>) {
        // Drained front-first rather than iterated, so that a stage's `close`
        // cannot observe a chain that still holds it -- the C detaches each
        // writer from `writer_stack` before calling `do_close` (`:51-52`).
        while !self.stages.is_empty() {
            let mut stage = self.stages.remove(0);
            stage.close(ctx);
        }
    }
}

// =========================================================================
// `cw_download` -- the protocol stage, `lib/sendf.c:168-302`
// =========================================================================

/// The stage that sees the REAL body, and everything that follows from that.
///
/// Supersedes `cw_download` and `struct cw_download_ctx`
/// (`lib/sendf.c:168-302`), whose own comment states the position exactly:
/// *"Here, we deal with REAL BODY bytes. All filtering and transfer encodings
/// have been applied and only the true content, e.g. BODY, bytes are passed
/// here. This allows us to check sizes, update stats, etc. independent from the
/// protocol in play."*
///
/// It is at [`ClientWriterPhase::Protocol`] and its name is `"protocol"`, not
/// `"download"`: the C named the type after the phase.
///
/// # The four things it does, in the order it does them
///
/// 1. **Records when the response began.** [`TimerId::StartTransfer`], on the
///    first write that is neither informational nor a proxy header.
/// 2. **Passes metadata through**, dropping a proxy header when the user asked
///    for that.
/// 3. **Enforces two independent size limits**, the protocol's and the user's,
///    and reports them differently because they mean different things.
/// 4. **Accounts for the bytes it accepted**, and only those.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct DownloadWriter {
    /// `BIT(started_response)` (`lib/sendf.c:170`): the start-transfer timer
    /// has been recorded.
    started_response: bool,
    /// `BIT(started_body)` (`lib/sendf.c:171`): the download rate limiter has
    /// been started.
    started_body: bool,
}

impl DownloadWriter {
    /// A stage that has seen neither a response nor a body yet.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Whether the start-transfer timer has been recorded, for the tests.
    #[allow(dead_code)]
    pub(crate) fn started_response(&self) -> bool {
        self.started_response
    }

    /// Whether the download rate limiter has been started, for the tests.
    #[allow(dead_code)]
    pub(crate) fn started_body(&self) -> bool {
        self.started_body
    }

    /// `get_max_body_write_len(data, limit)` (`lib/sendf.c:159-166`): how many
    /// more body bytes `limit` permits.
    ///
    /// [`usize::MAX`] means "no limit", which is what the C's `SIZE_MAX` means,
    /// and -1 as the limit is the sentinel for that. A limit already reached or
    /// passed yields zero rather than wrapping, because the subtraction goes
    /// through [`so_to_usize_range`] with a floor of zero -- and that is why a
    /// `bytecount` above the limit clamps the write to nothing instead of
    /// permitting an enormous one.
    #[allow(dead_code)]
    fn max_body_write_len(state: &RequestWriteState, limit: i64) -> usize {
        // `lib/sendf.c:161-164`.
        if limit != -1 {
            return so_to_usize_range(
                limit.saturating_sub(state.bytecount),
                0,
                usize::MAX,
            );
        }
        // `lib/sendf.c:165`.
        usize::MAX
    }

    /// The metadata path: everything that is not body bytes.
    ///
    /// `lib/sendf.c:191-198`. Split out so that the body path below reads as
    /// one sequence.
    #[allow(dead_code)]
    fn write_meta(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
        is_connect: bool,
    ) -> CurlResult<()> {
        // `lib/sendf.c:192-193`. A header received while proxying, when the
        // user asked not to see those, is dropped SUCCESSFULLY -- the chain
        // below never sees it, and that is not an error.
        if is_connect && ctx.config().suppress_connect_headers {
            return Ok(());
        }
        // `lib/sendf.c:194`.
        let result = tail.write(ctx, flags, buf);
        // `lib/sendf.c:195-196`. Traced on both outcomes, with the C's own
        // wording and its `%d` rendering of the code.
        let code = match &result {
            Ok(()) => CURLcode::Ok,
            Err(error) => error.code(),
        };
        ctx.trc_write(format_args!(
            "download_write header(type={flags}, blen={}) -> {}",
            buf.len(),
            code.as_i32()
        ));
        result
    }
}

impl ClientWriter for DownloadWriter {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::Download
    }

    fn phase(&self) -> ClientWriterPhase {
        ClientWriterPhase::Protocol
    }

    /// `cw_download_write` (`lib/sendf.c:176-293`), transcribed step for step.
    ///
    /// # Errors
    ///
    /// Four codes, each meaning something the others do not:
    ///
    /// * [`CURLcode::WeirdServerReply`] -- body bytes arrived on a response
    ///   declared bodyless AND no headers were received. Had headers arrived,
    ///   the same situation succeeds.
    /// * [`CURLcode::PartialFile`] -- the stream ended with the declared length
    ///   unmet.
    /// * [`CURLcode::FilesizeExceeded`] -- the USER's `--max-filesize` was
    ///   exceeded. Never returned for the PROTOCOL's `maxdownload`, which is
    ///   reported and dropped instead.
    /// * whatever a downstream stage returns.
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        let nbytes = buf.len();
        // `lib/sendf.c:183`.
        let is_connect = flags.contains(ClientWriteFlags::CONNECT);
        // `lib/sendf.c:186` and `:201`, hoisted because both one-shot guards
        // test the same pair of bits.
        let meta_or_connect = flags.intersects(
            ClientWriteFlags::INFO.union(ClientWriteFlags::CONNECT),
        );

        // `lib/sendf.c:185-189`. The response has begun the moment something
        // arrives that is neither informational nor a proxy header -- so a
        // status line counts and an FTP pingpong reply does not.
        if !self.started_response && !meta_or_connect {
            ctx.pgrs_time(TimerId::StartTransfer);
            self.started_response = true;
        }

        // `lib/sendf.c:191-198`.
        if !flags.contains(ClientWriteFlags::BODY) {
            return self.write_meta(ctx, tail, flags, buf, is_connect);
        }

        // `lib/sendf.c:200-205`. The download limiter is tuned for the
        // EXPECTED response length, which is why it starts here -- on the
        // first real body write -- rather than when the transfer did.
        if !self.started_body && !meta_or_connect {
            let now = ctx.pgrs_now();
            let size = ctx.write_state().size;
            ctx.progress_mut()
                .download_mut()
                .rlimit_mut()
                .start(now, size);
            self.started_body = true;
        }

        // `lib/sendf.c:213-223`. A body on a response that has none.
        if ctx.write_state().no_body && nbytes > 0 {
            ctx.control().stream_close("ignoring body");
            ctx.trc_write(format_args!(
                "download_write body(type={flags}, blen={nbytes}), \
                 did not want a BODY"
            ));
            ctx.write_state_mut().download_done = true;
            // `lib/sendf.c:219-221`: headers received means the server
            // answered, so this is fine; nothing received means it was not.
            if ctx.write_state().header_size != 0 {
                return Ok(());
            }
            return Err(Error::new(CURLcode::WeirdServerReply));
        }

        // `lib/sendf.c:225-247`. THE PROTOCOL'S LIMIT. The excess is computed
        // and the permitted prefix written, which is what gives deterministic
        // body writes whatever length the receive buffer happened to be.
        let mut nwrite = nbytes;
        let mut excess_len = 0_usize;
        let maxdownload = ctx.write_state().maxdownload;
        if maxdownload != -1 {
            let wmax = Self::max_body_write_len(ctx.write_state(), maxdownload);
            // `lib/sendf.c:232-235`.
            if nwrite > wmax {
                excess_len = nbytes - wmax;
                nwrite = wmax;
            }
            // `lib/sendf.c:237-239`. Note the test is on the CLAMPED length,
            // so a write that exactly reaches the maximum completes the
            // download just as one that overshoots does. Note too that a
            // `wmax` of zero makes this true for an empty write, which is how
            // an already-complete download stays complete.
            if nwrite == wmax {
                ctx.write_state_mut().download_done = true;
            }
            // `lib/sendf.c:241-246`. The stream ended and the declared length
            // was not met. Returned BEFORE anything is written, so the
            // truncated tail never reaches the client.
            let state = *ctx.write_state();
            if flags.contains(ClientWriteFlags::EOS)
                && !state.no_body
                && state.size > state.bytecount
            {
                return Err(ctx.failf(
                    CURLcode::PartialFile,
                    format_args!(
                        "end of response with {} bytes missing",
                        state.size - state.bytecount
                    ),
                ));
            }
        }

        // `lib/sendf.c:249-256`. THE USER'S LIMIT, applied AFTER the
        // protocol's, and its own comment says why the order matters: *"Error
        // on too large filesize is handled below, after writing the permitted
        // bytes"*. A zero `max_filesize` means no limit, which is the opposite
        // convention from `maxdownload`'s -1 and is preserved as such.
        //
        // This clamp does NOT set `excess_len`, and that distinction is what
        // step 10 below reads to tell the two limits apart.
        if ctx.config().max_filesize != 0 && !ctx.write_state().ignorebody {
            let wmax = Self::max_body_write_len(
                ctx.write_state(),
                ctx.config().max_filesize,
            );
            if nwrite > wmax {
                nwrite = wmax;
            }
        }

        // `lib/sendf.c:258-264`. The `|| EOS` disjunct is what forwards a
        // ZERO-LENGTH body write when the stream ends, so that the stage below
        // learns the stream is over even with no bytes to carry it.
        if !ctx.write_state().ignorebody
            && (nwrite != 0 || flags.contains(ClientWriteFlags::EOS))
        {
            let permitted = buf.get(..nwrite).unwrap_or(buf);
            let result = tail.write(ctx, flags, permitted);
            // `lib/sendf.c:260-261`. The traced length is `nbytes`, the length
            // that ARRIVED, not the clamped `nwrite` -- transcribed as it
            // stands, because a trace that reported the clamped length would
            // hide the clamp.
            let code = match &result {
                Ok(()) => CURLcode::Ok,
                Err(error) => error.code(),
            };
            ctx.trc_write(format_args!(
                "download_write body(type={flags}, blen={nbytes}) -> {}",
                code.as_i32()
            ));
            result?;
        }

        // `lib/sendf.c:266-270`. Accounted for the bytes ACCEPTED, never the
        // bytes that arrived: a clamped tail is not downloaded.
        if nwrite != 0 {
            let now = ctx.pgrs_now();
            let accepted = i64::try_from(nwrite).unwrap_or(i64::MAX);
            ctx.write_state_mut().bytecount += accepted;
            ctx.progress_mut().download_inc(nwrite, now);
        }

        // `lib/sendf.c:272-290`. The two limits are reported differently, and
        // the `else` is what keeps them apart: an excess from the PROTOCOL's
        // limit is reported and the connection retired, and the write still
        // SUCCEEDS; a shortfall with no excess can only have come from the
        // USER's limit, and that FAILS the transfer.
        if excess_len != 0 {
            if !ctx.write_state().ignorebody {
                let state = *ctx.write_state();
                ctx.infof(format_args!(
                    "Excess found writing body: excess = {excess_len}, \
                     size = {}, maxdownload = {}, bytecount = {}",
                    state.size, state.maxdownload, state.bytecount
                ));
                ctx.control().conn_close("excess found in a read");
            }
        } else if nwrite < nbytes && !ctx.write_state().ignorebody {
            let max_filesize = ctx.config().max_filesize;
            let bytecount = ctx.write_state().bytecount;
            return Err(ctx.failf(
                CURLcode::FilesizeExceeded,
                format_args!(
                    "Exceeded the maximum allowed file size ({max_filesize}) \
                     with {bytecount} bytes"
                ),
            ));
        }

        // `lib/sendf.c:292`.
        Ok(())
    }
}

// =========================================================================
// `cw_raw` -- the raw stage, `lib/sendf.c:304-323`
// =========================================================================

/// The stage that traces body bytes before anything has touched them.
///
/// Supersedes `cw_raw` (`lib/sendf.c:304-323`), whose comment is *"RAW client
/// writer in phase CURL_CW_RAW that enabled tracing of raw data"*. It is at
/// [`ClientWriterPhase::Raw`], the top of the chain, so what it traces is what
/// arrived: before de-framing, before decoding, before any length check.
///
/// It NEVER modifies a byte. `lib/sendf.h:94-97` reserves modification for the
/// two decode phases, and specification 0.6.7 makes any normalisation here a
/// wire-parity failure in any case.
///
/// # It carries no state
///
/// The C declares it with `sizeof(struct Curl_cwriter)` rather than a context
/// struct of its own (`lib/sendf.c:322`) -- it is the one registered writer
/// with nothing to remember.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct RawWriter;

impl RawWriter {
    /// The stage. There is nothing to configure.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self
    }
}

impl ClientWriter for RawWriter {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::Raw
    }

    fn phase(&self) -> ClientWriterPhase {
        ClientWriterPhase::Raw
    }

    /// `cw_raw_write` (`lib/sendf.c:306-314`).
    ///
    /// Three conditions must all hold before anything is traced, and the C
    /// spells them in this order at `:310`: the write carries BODY bytes, the
    /// transfer is verbose, and the body is not being discarded. Tracing a
    /// discarded body would show the application data it will never receive.
    ///
    /// The trace happens BEFORE the forward, so a stage below that fails does
    /// not suppress the record of what arrived.
    ///
    /// # Errors
    ///
    /// Whatever the stage below returns, unchanged, including
    /// [`CURLcode::WriteError`] when there is none.
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `lib/sendf.c:310-312`.
        if flags.contains(ClientWriteFlags::BODY)
            && ctx.config().verbose
            && !ctx.write_state().ignorebody
        {
            ctx.debug(TraceDataKind::DataIn, buf);
        }
        // `lib/sendf.c:313`.
        tail.write(ctx, flags, buf)
    }
}

// =========================================================================
// The reader contract -- `struct Curl_crtype` and `struct Curl_creader`
// =========================================================================

/// What one read produced.
///
/// The successor of the C's `size_t *nread` and `bool *eos` out-parameters.
/// `Curl_creader_read` zeroes both BEFORE it dispatches (`lib/sendf.c:519-520`)
/// so that a stage which returns an error without writing them cannot leave a
/// stale count behind; returning the pair BY VALUE subsumes that entirely --
/// there is no out-parameter to leave stale, and an error carries no outcome at
/// all.
///
/// [`Self::EMPTY`] is the zero-initialised state the C starts from, and every
/// construction site below either uses it or names both fields, so the
/// invariant is in the code rather than in a comment.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ReadOutcome {
    /// How many bytes were written into the destination.
    pub(crate) bytes_read: usize,
    /// Whether those bytes are the last the client will provide.
    ///
    /// True WITH a non-zero `bytes_read` is normal and means "these bytes, and
    /// no more after them" -- `cr_in` reports exactly that when a known length
    /// is reached (`lib/sendf.c:726-729`). A caller that treated end-of-stream
    /// as implying zero bytes would silently drop the final chunk of every
    /// sized upload.
    pub(crate) eos: bool,
}

impl ReadOutcome {
    /// Zero bytes and not the end of the stream.
    ///
    /// `*nread = 0; *eos = FALSE;` (`lib/sendf.c:519-520`).
    #[allow(dead_code)]
    pub(crate) const EMPTY: Self = Self {
        bytes_read: 0,
        eos: false,
    };

    /// Zero bytes AND the end of the stream.
    ///
    /// `*pnread = 0; *peos = TRUE;`, which `cr_in` returns for an exhausted
    /// source (`:658-659`), `cr_lc` for a drained buffer (`:1000-1001`),
    /// `cr_null` always (`:1244-1245`) and `cr_buf` for an empty one
    /// (`:1301-1302`).
    #[allow(dead_code)]
    pub(crate) const EOS: Self = Self {
        bytes_read: 0,
        eos: true,
    };

    /// `count` bytes, and whether they are the last.
    #[allow(dead_code)]
    pub(crate) const fn new(bytes_read: usize, eos: bool) -> Self {
        Self { bytes_read, eos }
    }
}

/// One stage of the reader chain.
///
/// Supersedes `struct Curl_crtype` (`lib/sendf.h:214-231`) together with
/// `struct Curl_creader` (`:248-253`). The same four C members disappear as on
/// the writer side -- the allocation size, the `void *ctx`, the `next` pointer
/// and the name -- for the same reasons, which [`ClientWriter`] records.
///
/// Ten members become nine methods plus [`Self::kind`]. Eight of them have
/// default bodies transcribed from the C's `Curl_creader_def_*` family
/// (`lib/sendf.c:535-614`), so a stage that only transforms bytes writes
/// [`Self::kind`], [`Self::phase`] and [`Self::read`].
#[allow(dead_code)]
pub(crate) trait ClientReader: fmt::Debug {
    /// Which reader this is, and therefore what it is called.
    fn kind(&self) -> ClientReaderKind;

    /// The phase this INSTANCE operates at.
    fn phase(&self) -> ClientReaderPhase;

    /// The `name` member of `struct Curl_crtype` (`lib/sendf.h:215`).
    ///
    /// Answered from [`Self::kind`]; the C interpolates this string into three
    /// diagnostics, at `lib/sendf.c:106`, `:1437` and by way of `:1227`.
    fn name(&self) -> &'static str {
        self.kind().name()
    }

    /// `do_init` (`lib/sendf.h:216`), invoked by
    /// [`ClientReaderStack::create`].
    ///
    /// Defaults to `Curl_creader_def_init` (`lib/sendf.c:535-541`): nothing.
    fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        let _ = ctx;
        Ok(())
    }

    /// `do_read` (`lib/sendf.h:217-218`).
    ///
    /// Defaults to `Curl_creader_def_read` (`lib/sendf.c:550-563`): pull from
    /// the stage below, or fail with [`CURLcode::ReadError`] when there is
    /// none.
    ///
    /// # Errors
    ///
    /// Whatever the stage below returns, or [`CURLcode::ReadError`] at the
    /// bottom of the chain.
    fn read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut ReaderTail<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        tail.read(ctx, buf)
    }

    /// `do_close` (`lib/sendf.h:219`), invoked when the stage leaves the
    /// chain.
    ///
    /// Defaults to `Curl_creader_def_close` (`lib/sendf.c:543-548`): nothing.
    fn close(&mut self, ctx: &mut ClientCtx<'_>) {
        let _ = ctx;
    }

    /// `needs_rewind` (`lib/sendf.h:220`): whether a retry would need this
    /// stage put back to its start.
    ///
    /// Defaults to `Curl_creader_def_needs_rewind` (`lib/sendf.c:565-571`):
    /// false. Note that the default does NOT consult the stage below, unlike
    /// [`Self::total_length`] -- transcribed as it stands, because the two C
    /// defaults really do differ, and [`ClientReaderStack::needs_rewind`] walks
    /// the whole chain itself.
    fn needs_rewind(&self) -> bool {
        false
    }

    /// `total_length` (`lib/sendf.h:221-222`): how many bytes this stage will
    /// ultimately provide, or -1 when that is indeterminate.
    ///
    /// Defaults to `Curl_creader_def_total_length` (`lib/sendf.c:573-578`): the
    /// stage below's answer, or -1 at the bottom. A stage that CHANGES the
    /// length -- [`CrLineConv`], chunked framing -- must override this with -1,
    /// because forwarding a length it is about to alter would be a lie.
    ///
    /// The view of the chain below is a [`ReaderQuery`] and not a
    /// [`ReaderTail`], because this is the one member of `struct Curl_crtype`
    /// that asks rather than acts. The C cannot draw that distinction -- every
    /// member of the vtable takes a non-const `struct Curl_easy *` and a
    /// non-const `struct Curl_creader *`, so the signature says nothing about
    /// what the body does -- and here a query provably cannot mutate the chain
    /// it walks.
    fn total_length(&self, below: &ReaderQuery<'_, '_>) -> i64 {
        below.total_length()
    }

    /// `resume_from` (`lib/sendf.h:223-224`): start reading at `offset`
    /// instead of at the beginning.
    ///
    /// Defaults to `Curl_creader_def_resume_from` (`lib/sendf.c:580-588`):
    /// [`CURLcode::ReadError`], meaning "not supported by this stage". Only a
    /// stage at [`ClientReaderPhase::Client`] is ever asked, because
    /// [`ClientReaderStack::resume_from`] walks to that phase first.
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] by default, and see [`CrIn::resume_from`] and
    /// [`CrBuf`] for the two stages that implement it.
    fn resume_from(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        offset: i64,
    ) -> CurlResult<()> {
        let _ = (ctx, offset);
        Err(Error::new(CURLcode::ReadError))
    }

    /// `cntrl` (`lib/sendf.h:225-226`): tell this stage something.
    ///
    /// Defaults to `Curl_creader_def_cntrl` (`lib/sendf.c:590-598`):
    /// success, having done nothing. The C's `switch` has a `default:` arm that
    /// absorbs an unknown opcode; here the argument is a
    /// [`ReaderControl`], so there is no unknown opcode to absorb.
    ///
    /// # Errors
    ///
    /// Only [`ReaderControl::Rewind`] can fail, and only for a stage that
    /// implements it; see [`CrIn::rewind`].
    fn control(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        control: ReaderControl,
    ) -> CurlResult<()> {
        let _ = (ctx, control);
        Ok(())
    }

    /// `is_paused` (`lib/sendf.h:227`): whether this stage is waiting to be
    /// unpaused.
    ///
    /// Defaults to `Curl_creader_def_is_paused` (`lib/sendf.c:600-606`):
    /// false.
    fn is_paused(&self) -> bool {
        false
    }

    /// `done` (`lib/sendf.h:228-229`): the request is over.
    ///
    /// Defaults to `Curl_creader_def_done` (`lib/sendf.c:608-614`): nothing.
    /// `premature` is the C's `int`, non-zero when the request ended before the
    /// stage had provided everything it had; it is a `bool` here because every
    /// C call site passes a truth value.
    fn done(&mut self, ctx: &mut ClientCtx<'_>, premature: bool) {
        let _ = (ctx, premature);
    }
}

/// The remainder of a reader chain, below the stage currently running.
///
/// The read-side counterpart of [`WriterTail`], and the successor of
/// `struct Curl_creader`'s `next` member. An empty tail is the successor of a
/// `NULL` `next`, and reading through one is [`CURLcode::ReadError`] --
/// `Curl_creader_read`'s `if(!reader)` (`lib/sendf.c:521-522`) and
/// `Curl_creader_def_read`'s `else` branch (`:558-562`) both produce exactly
/// that.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ReaderTail<'stack, 'data> {
    stages: &'stack mut [Box<dyn ClientReader + 'data>],
}

impl<'stack, 'data> ReaderTail<'stack, 'data> {
    /// A tail over `stages`.
    #[allow(dead_code)]
    fn new(stages: &'stack mut [Box<dyn ClientReader + 'data>]) -> Self {
        Self { stages }
    }

    /// How many stages remain below the caller.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.stages.len()
    }

    /// Whether the caller is the bottom of the chain.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// `Curl_creader_read(data, reader, buf, blen, nread, eos)`
    /// (`lib/sendf.c:515-524`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] when the tail is empty, otherwise whatever the
    /// next stage returns.
    #[allow(dead_code)]
    pub(crate) fn read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        match self.stages.split_first_mut() {
            // `lib/sendf.c:521-522`, and `:558-562` for the default read.
            None => Err(Error::new(CURLcode::ReadError)),
            Some((head, rest)) => {
                let mut tail = ReaderTail::new(rest);
                head.read(ctx, &mut tail, buf)
            }
        }
    }
}

/// A read-only view of a reader chain, for the one query that walks it.
///
/// [`ClientReader::total_length`] asks the chain below it a question and must
/// not be able to change it, so it receives this rather than a
/// [`ReaderTail`]. The recursion is the C's own, from
/// `Curl_creader_def_total_length` (`lib/sendf.c:573-578`), with the pointer
/// walk replaced by a slice split.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
pub(crate) struct ReaderQuery<'stack, 'data> {
    stages: &'stack [Box<dyn ClientReader + 'data>],
}

impl<'stack, 'data> ReaderQuery<'stack, 'data> {
    /// A view over `stages`.
    #[allow(dead_code)]
    fn new(stages: &'stack [Box<dyn ClientReader + 'data>]) -> Self {
        Self { stages }
    }

    /// How many stages the view covers.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.stages.len()
    }

    /// Whether the view is empty -- the bottom of the chain.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// The length the topmost stage of this view reports, or -1 when the view
    /// is empty.
    ///
    /// `reader->next ? reader->next->crt->total_length(...) : -1`
    /// (`lib/sendf.c:576-577`).
    #[allow(dead_code)]
    pub(crate) fn total_length(&self) -> i64 {
        match self.stages.split_first() {
            None => -1,
            Some((head, rest)) => head.total_length(&Self::new(rest)),
        }
    }
}

/// The reader chain, owned.
///
/// Supersedes `data->req.reader_stack` (`lib/request.h:90`) and the sixteen
/// functions that walk it. Ordered by phase, lowest first, so index 0 is the
/// stage a read reaches first and the last index is the
/// [`ClientReaderPhase::Client`] stage that actually produces bytes.
///
/// # The lifetime is what makes `cr_buf` safe
///
/// `Curl_creader_set_buf`'s own header comment is *"Set the client reader the
/// reads from the supplied buf (NOT COPIED)"* (`lib/sendf.h:418`). The C states
/// that contract in prose and relies on the caller to honour it. Here it is
/// `'data`: a chain built over a borrowed buffer cannot outlive the buffer, and
/// the compiler says so rather than the documentation.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ClientReaderStack<'data> {
    stages: Vec<Box<dyn ClientReader + 'data>>,
}

impl<'data> Default for ClientReaderStack<'data> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'data> ClientReaderStack<'data> {
    /// An empty chain.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// How many stages the chain holds.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.stages.len()
    }

    /// Whether the chain is empty -- the C's `if(!data->req.reader_stack)`.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    /// Every stage's name, from the top of the chain down.
    ///
    /// The read-side counterpart of [`ClientWriterStack::names`], and it exists
    /// for the same reason: the order is the contract.
    #[allow(dead_code)]
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.stages.iter().map(|r| r.name()).collect()
    }

    /// `Curl_creader_create` (`lib/sendf.c:922-947`): initialise a stage,
    /// before it joins any chain.
    ///
    /// The writer side's reasoning applies unchanged; see
    /// [`ClientWriterStack::create`].
    ///
    /// # Errors
    ///
    /// Whatever [`ClientReader::init`] returns. The stage is dropped on the way
    /// out.
    #[allow(dead_code)]
    pub(crate) fn create(
        mut reader: Box<dyn ClientReader + 'data>,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<Box<dyn ClientReader + 'data>> {
        reader.init(ctx)?;
        Ok(reader)
    }

    /// `Curl_creader_free` (`lib/sendf.c:949-955`): close a stage that is not
    /// in a chain.
    #[allow(dead_code)]
    pub(crate) fn free(
        mut reader: Box<dyn ClientReader + 'data>,
        ctx: &mut ClientCtx<'_>,
    ) {
        reader.close(ctx);
    }

    /// The insertion rule: FIRST WITHIN THE PHASE.
    ///
    /// `lib/sendf.c:1156-1161`, character for character the writer side's rule
    /// at `:464-469` -- the C even repeats the comment, `"Insert the writer as
    /// first in its phase"`, in the reader function.
    #[allow(dead_code)]
    fn insert(&mut self, reader: Box<dyn ClientReader + 'data>) {
        let phase = reader.phase();
        let at = self
            .stages
            .iter()
            .position(|installed| installed.phase() >= phase)
            .unwrap_or(self.stages.len());
        self.stages.insert(at, reader);
    }

    /// `cl_reset_reader` (`lib/sendf.c:58-68`): close and discard every stage.
    ///
    /// Does NOT clear `reader_started`, although the C's function does at
    /// `:61`. That assignment belongs to the state the caller holds, and every
    /// caller here -- [`ClientIo::client_cleanup`], [`ClientIo::client_reset`],
    /// [`ClientIo::client_start`] and the three `set_*` installers -- performs
    /// it through the context, so the flag and the chain still move together.
    /// Keeping it out of this function is what lets the function take no
    /// context beyond the one it needs to close stages with.
    #[allow(dead_code)]
    pub(crate) fn clear(&mut self, ctx: &mut ClientCtx<'_>) {
        while !self.stages.is_empty() {
            let mut stage = self.stages.remove(0);
            stage.close(ctx);
        }
    }

    /// Drive the whole chain from the top.
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] when the chain is empty, otherwise whatever a
    /// stage returns.
    #[allow(dead_code)]
    pub(crate) fn read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        ReaderTail::new(&mut self.stages).read(ctx, buf)
    }

    /// A read-only view of the whole chain.
    #[allow(dead_code)]
    pub(crate) fn query(&self) -> ReaderQuery<'_, 'data> {
        ReaderQuery::new(&self.stages)
    }

    /// `Curl_creader_total_length` (`lib/sendf.c:1408-1412`): what the whole
    /// chain will provide.
    ///
    /// -1 when indeterminate, which is what the header promises for a chain
    /// carrying a chunked or line-converting stage (`lib/sendf.h:353-359`), and
    /// also what an EMPTY chain answers -- the C's `r ? ... : -1`.
    #[allow(dead_code)]
    pub(crate) fn total_length(&self) -> i64 {
        self.query().total_length()
    }

    /// The index of the [`ClientReaderPhase::Client`] stage.
    ///
    /// `while(r && r->phase != CURL_CR_CLIENT) r = r->next;`, which
    /// `lib/sendf.c:1417-1418`, `:1425-1426` all perform before asking the
    /// stage they found.
    #[allow(dead_code)]
    fn client_index(&self) -> Option<usize> {
        self.stages
            .iter()
            .position(|r| r.phase() == ClientReaderPhase::Client)
    }

    /// `Curl_creader_client_length` (`lib/sendf.c:1414-1420`): what the
    /// CLIENT-phase stage will provide, ignoring every encoding above it.
    ///
    /// The header explains what it is for (`lib/sendf.h:362-368`): it *"may not
    /// match the amount of bytes read for a request"* but *"allows for rough
    /// estimation of the overall length"*. -1 when there is no client stage at
    /// all.
    #[allow(dead_code)]
    pub(crate) fn client_length(&self) -> i64 {
        match self.client_index() {
            None => -1,
            Some(index) => {
                ReaderQuery::new(&self.stages[index..]).total_length()
            }
        }
    }

    /// `Curl_creader_resume_from` (`lib/sendf.c:1422-1428`): ask the
    /// CLIENT-phase stage to start at `offset`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] when there is no client stage -- the C's
    /// `: CURLE_READ_ERROR` at `:1427` -- and otherwise whatever
    /// [`ClientReader::resume_from`] returns, which the header enumerates as
    /// [`CURLcode::ReadError`] for an unsupported or failed seek and
    /// [`CURLcode::PartialFile`] when the offset consumed the whole upload
    /// (`lib/sendf.h:378-381`).
    #[allow(dead_code)]
    pub(crate) fn resume_from(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        offset: i64,
    ) -> CurlResult<()> {
        match self.client_index() {
            None => Err(Error::new(CURLcode::ReadError)),
            Some(index) => self.stages[index].resume_from(ctx, offset),
        }
    }

    /// `Curl_creader_needs_rewind` (`lib/sendf.c:1222-1233`): whether ANY stage
    /// needs a rewind before the next request.
    ///
    /// Traced on a positive answer, with the C's own wording.
    #[allow(dead_code)]
    pub(crate) fn needs_rewind(&self, ctx: &mut ClientCtx<'_>) -> bool {
        if self.stages.iter().any(|r| r.needs_rewind()) {
            ctx.trc_read(format_args!(
                "client reader needs rewind before next request"
            ));
            return true;
        }
        false
    }

    /// `Curl_creader_is_paused` (`lib/sendf.c:1445-1455`): whether ANY stage is
    /// paused.
    #[allow(dead_code)]
    pub(crate) fn is_paused(&self) -> bool {
        self.stages.iter().any(|r| r.is_paused())
    }

    /// Sends `control` to every stage, from the top down, stopping at the first
    /// failure.
    ///
    /// The shape shared by `Curl_client_start`'s rewind walk
    /// (`lib/sendf.c:102-110`) and `Curl_creader_unpause`
    /// (`:1430-1443`). Both walk in chain order and both abandon the walk on
    /// the first error, so the stages below a failing one are NOT told -- which
    /// is deliberate in the C and is preserved.
    ///
    /// # Errors
    ///
    /// The first failing [`ClientReader::control`] result, paired with the name
    /// of the stage that produced it so a caller can name it in a diagnostic.
    #[allow(dead_code)]
    fn control_all(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        control: ReaderControl,
    ) -> Result<(), (&'static str, Error)> {
        for index in 0..self.stages.len() {
            let name = self.stages[index].name();
            match self.stages[index].control(ctx, control) {
                Ok(()) => {}
                Err(error) => return Err((name, error)),
            }
        }
        Ok(())
    }

    /// `Curl_creader_unpause` (`lib/sendf.c:1430-1443`): clear the paused state
    /// of every stage.
    ///
    /// Each step is traced with the C's wording, `"unpausing %s -> %d"`, which
    /// names the stage and its result.
    ///
    /// # Errors
    ///
    /// The first failing [`ClientReader::control`] result.
    #[allow(dead_code)]
    pub(crate) fn unpause(
        &mut self,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<()> {
        for index in 0..self.stages.len() {
            let name = self.stages[index].name();
            let result =
                self.stages[index].control(ctx, ReaderControl::Unpause);
            let code = match &result {
                Ok(()) => CURLcode::Ok,
                Err(error) => error.code(),
            };
            ctx.trc_read(format_args!("unpausing {name} -> {}", code.as_i32()));
            result?;
        }
        Ok(())
    }

    /// `Curl_creader_clear_eos` (`lib/sendf.c:526-533`): tell every stage to
    /// forget that it saw the end of the stream.
    ///
    /// The result is DISCARDED at every stage, as the C's `(void)` cast at
    /// `:530` discards it, and the walk continues past a failure. That is not
    /// an oversight to be corrected: no stage's [`ReaderControl::ClearEos`] can
    /// fail, and stopping early would leave part of the chain believing the
    /// stream had ended.
    #[allow(dead_code)]
    pub(crate) fn clear_eos(&mut self, ctx: &mut ClientCtx<'_>) {
        for index in 0..self.stages.len() {
            let _ = self.stages[index].control(ctx, ReaderControl::ClearEos);
        }
    }

    /// `Curl_creader_done` (`lib/sendf.c:1457-1464`): tell every stage the
    /// request is over.
    #[allow(dead_code)]
    pub(crate) fn done(&mut self, ctx: &mut ClientCtx<'_>, premature: bool) {
        for index in 0..self.stages.len() {
            self.stages[index].done(ctx, premature);
        }
    }

    /// `Curl_creader_get_by_type` (`lib/sendf.c:1466-1475`): the first stage of
    /// the given kind.
    #[allow(dead_code)]
    pub(crate) fn get_by_kind(
        &self,
        kind: ClientReaderKind,
    ) -> Option<&(dyn ClientReader + 'data)> {
        self.stages
            .iter()
            .find(|r| r.kind() == kind)
            .map(std::convert::AsRef::as_ref)
    }

    /// The first stage of the given kind, mutable.
    ///
    /// Not a C function -- the C hands out a `struct Curl_creader *` from
    /// `get_by_type` and the caller does as it likes with it. Splitting the
    /// shared and mutable forms is what makes a read-only query provably
    /// read-only.
    #[allow(dead_code)]
    pub(crate) fn get_by_kind_mut(
        &mut self,
        kind: ClientReaderKind,
    ) -> Option<&mut (dyn ClientReader + 'data)> {
        self.stages
            .iter_mut()
            .find(|r| r.kind() == kind)
            .map(std::convert::AsMut::as_mut)
    }
}

// =========================================================================
// `cr_in` -- the input callback reader, `lib/sendf.c:616-920`
// =========================================================================

/// The scratch area `cr_in_resume_from` reads and discards through.
///
/// `char scratch[4 * 1024]` (`lib/sendf.c:782`), reproduced at exactly that
/// size. The size is observable: it decides how many times the input callback
/// is invoked to skip a given offset, and a callback that counts its own
/// invocations -- which several of the fixture-driven test programs do -- would
/// see a different sequence at any other size.
#[allow(dead_code)]
const RESUME_SCRATCH_LEN: usize = 4 * 1024;

/// The reader that pulls bytes from the application.
///
/// Supersedes `cr_in` and `struct cr_in_ctx` (`lib/sendf.c:616-920`), the stage
/// at [`ClientReaderPhase::Client`] that every upload not backed by a memory
/// buffer or by MIME bottoms out in.
///
/// # Errors are STICKY, and that is a contract
///
/// `lib/sendf.c:651-656` opens the read with *"Once we have errored, we will
/// return the same error forever"*, and the C keeps both a flag and the code so
/// that the SAME code comes back. Two of the four error paths set it and two do
/// not, which is easy to lose:
///
/// | outcome | sticky? | `lib/sendf.c` |
/// |---|---|---|
/// | premature end of a sized upload | NO | `:676-682` |
/// | the callback aborted | YES | `:688-695` |
/// | the callback asked to pause on a networkless scheme | NO | `:697-705` |
/// | the callback returned more than it was given | YES | `:714-724` |
///
/// So a premature end can be retried and an abort cannot. That asymmetry is
/// reproduced exactly; [`Self::error`] is `Some` only for the two sticky
/// cases.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct CrIn<'src> {
    /// `ctx->read_cb` fused with `ctx->cb_user_data` (`lib/sendf.c:618-619`).
    ///
    /// [`None`] is a null `fread_func`, which the C tolerates through its
    /// `if(ctx->read_cb && blen)` guard at `:667`.
    source: Option<Box<dyn ClientReadSource + 'src>>,
    /// `ctx->total_len` (`lib/sendf.c:620`): the declared upload length, or -1
    /// when it is unknown.
    total_len: i64,
    /// `ctx->read_len` (`lib/sendf.c:621`): how much has been read so far.
    read_len: i64,
    /// `ctx->error_result` together with `BIT(errored)` (`lib/sendf.c:622` and
    /// `:624`).
    ///
    /// One [`Option`] rather than a flag and a code, because the C's pair can
    /// disagree -- `errored` set with a stale `error_result`, or a code stored
    /// without the flag -- and this cannot.
    error: Option<CURLcode>,
    /// `BIT(seen_eos)` (`lib/sendf.c:623`).
    seen_eos: bool,
    /// `BIT(has_used_cb)` (`lib/sendf.c:625`): the callback has been invoked at
    /// least once, so there may be something to rewind.
    has_used_cb: bool,
    /// `BIT(is_paused)` (`lib/sendf.c:626`).
    is_paused: bool,
}

impl<'src> CrIn<'src> {
    /// A reader over `source`, declaring `total_len` bytes.
    ///
    /// `cr_in_init` (`lib/sendf.c:629-637`) copies the callback out of
    /// `data->state` and sets `total_len` to -1; `Curl_creader_set_fread` then
    /// overwrites it at `:1134`. The two steps collapse into one constructor
    /// here, because a reader that briefly claimed an unknown length before
    /// being told the real one would be a state no caller can observe.
    ///
    /// `total_len` is -1 for an unknown length; any other negative value is
    /// treated the same way by every test below, all of which are
    /// `total_len >= 0`.
    #[allow(dead_code)]
    pub(crate) fn new(
        source: Option<Box<dyn ClientReadSource + 'src>>,
        total_len: i64,
    ) -> Self {
        Self {
            source,
            total_len,
            read_len: 0,
            error: None,
            seen_eos: false,
            has_used_cb: false,
            is_paused: false,
        }
    }

    /// How much has been read so far, for the tests and for diagnostics.
    #[allow(dead_code)]
    pub(crate) fn read_len(&self) -> i64 {
        self.read_len
    }

    /// The sticky error, if one has been recorded.
    #[allow(dead_code)]
    pub(crate) fn sticky_error(&self) -> Option<CURLcode> {
        self.error
    }

    /// `cr_in_rewind` (`lib/sendf.c:818-877`): put the source back to its
    /// start.
    ///
    /// Four strategies, tried in the C's order, and the order is chosen by
    /// WHICH OPTION IS SET rather than by what a call returned:
    ///
    /// 1. **Nothing was read.** `if(!ctx->has_used_cb) return CURLE_OK`
    ///    (`:823-825`). No callback has run, so there is nothing to undo, and
    ///    nothing is invoked -- not even an installed seek callback.
    /// 2. **`CURLOPT_SEEKFUNCTION`.** Seek to zero; any non-zero return fails
    ///    (`:827-838`). Note that [`SeekOutcome::CantSeek`] fails HERE even
    ///    though [`Self::resume_from`] treats it as a fallback, because the C's
    ///    test at `:834` is `if(err)` and `CURL_SEEKFUNC_CANTSEEK` is 2.
    /// 3. **`CURLOPT_IOCTLFUNCTION`.** Only when no seek callback is installed
    ///    (`:839-851`). Any non-`CURLIOE_OK` return fails.
    /// 4. **The default source's own seek.** Only when neither callback is
    ///    installed (`:852-874`). The C asks whether `fread_func == fread` and
    ///    then calls `fseek`; here the source answers
    ///    [`ClientReadSource::seek_to_start`], which removes both the function
    ///    pointer comparison and the cast the C needs a `#pragma` to silence.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SendFailRewind`] from strategies 2, 3 and 4, with the C's
    /// three distinct messages preserved so that a reader of
    /// `CURLOPT_ERRORBUFFER` can tell which strategy failed.
    #[allow(dead_code)]
    fn rewind(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        // 1 -- `lib/sendf.c:823-825`.
        if !self.has_used_cb {
            return Ok(());
        }

        // 2 -- `lib/sendf.c:827-838`.
        if ctx.has_seek() {
            let outcome = ctx
                .call_seek(0, SeekOrigin::Start)
                .expect("has_seek reported a callback a moment ago");
            ctx.trc_read(format_args!(
                "cr_in, rewind via set.seek_func -> {}",
                outcome.as_i32()
            ));
            if outcome.is_nonzero() {
                return Err(ctx.failf(
                    CURLcode::SendFailRewind,
                    format_args!(
                        "seek callback returned error {}",
                        outcome.as_i32()
                    ),
                ));
            }
            return Ok(());
        }

        // 3 -- `lib/sendf.c:839-851`.
        if ctx.has_ioctl() {
            let outcome = ctx
                .call_ioctl(IoCmd::RestartRead)
                .expect("has_ioctl reported a callback a moment ago");
            ctx.trc_read(format_args!(
                "cr_in, rewind via set.ioctl_func -> {}",
                outcome.as_i32()
            ));
            if outcome != IoOutcome::Ok {
                return Err(ctx.failf(
                    CURLcode::SendFailRewind,
                    format_args!(
                        "ioctl callback returned error {}",
                        outcome.as_i32()
                    ),
                ));
            }
            return Ok(());
        }

        // 4 -- `lib/sendf.c:852-874`. A source that cannot rewind itself
        // answers `None`, which is the C's `fread_func != fread`, and falls
        // through to the failure below exactly as the C does.
        if let Some(source) = self.source.as_deref_mut() {
            if let Some(attempt) = source.seek_to_start() {
                match attempt {
                    Ok(()) => {
                        ctx.trc_read(format_args!(
                            "cr_in, rewind via source seek -> 0"
                        ));
                        // `lib/sendf.c:867-869`: successful rewind.
                        return Ok(());
                    }
                    Err(error) => {
                        // `lib/sendf.c:865-866` traces the return and the
                        // errno; the io error's own rendering carries both.
                        ctx.trc_read(format_args!(
                            "cr_in, rewind via source seek -> {error}"
                        ));
                    }
                }
            }
        }

        // `lib/sendf.c:872-874`: no callback set or failure above, makes us
        // fail at once.
        Err(ctx.failf(
            CURLcode::SendFailRewind,
            format_args!("necessary data rewind was not possible"),
        ))
    }

    /// The read-and-discard fallback of `cr_in_resume_from`
    /// (`lib/sendf.c:781-802`).
    ///
    /// Reached only when the seek callback reported
    /// [`SeekOutcome::CantSeek`], or when there is none at all -- `seekerr` is
    /// initialised to that value at `:760`.
    ///
    /// The loop is a `do ... while(passed < offset)`, so it runs AT LEAST ONCE
    /// even for a zero offset. Transcribed as it stands: a zero offset with a
    /// callback that returns nothing is therefore an error in the C, and
    /// [`ClientReaderStack::resume_from`]'s callers never pass one, because
    /// `Curl_creader_resume_from`'s own contract calls a negative offset
    /// something to ignore, and zero something no caller asks for.
    ///
    /// # The request length is CLAMPED to the scratch area, which the C does
    /// not do
    ///
    /// `:783-786` sizes each request as
    /// `(offset - passed > (curl_off_t)sizeof(scratch)) ? sizeof(scratch) :
    /// curlx_sotouz(offset - passed)`, and `curlx_sotouz`
    /// (`lib/curlx/warnless.c:209-222`) is a MASK rather than a clamp: it
    /// carries a `DEBUGASSERT(sonum >= 0)` that compiles away in a release
    /// build and then returns `sonum & CURL_MASK_USIZE_T`. For a NEGATIVE
    /// remainder -- which a negative offset produces on the very first turn --
    /// the comparison against the scratch size is false and the mask yields an
    /// enormous count, so the C asks the application to write approximately
    /// 2^64 bytes into a 4 KiB stack array. That is a latent buffer overflow,
    /// not a behaviour to reproduce.
    ///
    /// [`so_to_usize_range`] with a ceiling of [`RESUME_SCRATCH_LEN`] is used
    /// instead. For every offset the C's own contract admits the two agree
    /// exactly, so no observable behaviour of any correct caller moves; for a
    /// negative offset the outcome becomes a request for zero bytes, which the
    /// error below then reports honestly. Specification 0.8.1 freezes
    /// behaviour, and a memory-safety defect is not behaviour.
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] when the callback yields nothing or claims more
    /// than it was given -- one test for both, and the C's comment at
    /// `:796-797` explains why: *"this checks for greater-than only to make
    /// sure that the `CURL_READFUNC_ABORT` return code still aborts"*. The
    /// message carries the byte count reached, as `:798-799` does.
    #[allow(dead_code)]
    fn discard_to_offset(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        offset: i64,
    ) -> CurlResult<()> {
        // `lib/sendf.c:782`. Owned rather than a stack array, so the length is
        // the buffer's own property; `zeroed` because a scratch area handed to
        // a callback must not expose whatever the allocator last held.
        let mut scratch = BytesMut::zeroed(RESUME_SCRATCH_LEN);
        let mut passed: i64 = 0;
        loop {
            // `lib/sendf.c:783-786`.
            let remaining = offset.saturating_sub(passed);
            let want = if remaining > RESUME_SCRATCH_LEN as i64 {
                RESUME_SCRATCH_LEN
            } else {
                so_to_usize_range(remaining, 0, RESUME_SCRATCH_LEN)
            };

            // `lib/sendf.c:789-792`. The C dereferences `ctx->read_cb`
            // unconditionally here, which would fault on a null callback; a
            // missing source is treated as a callback that produced nothing,
            // which lands on the same error two lines below.
            let outcome = match self.source.as_deref_mut() {
                None => SourceRead::Bytes(0),
                Some(source) => {
                    let dest = &mut scratch[..want];
                    let _entered = ctx.enter_callback();
                    source.read(dest)
                }
            };

            // `lib/sendf.c:794-801`. `CURL_READFUNC_ABORT` and
            // `CURL_READFUNC_PAUSE` are both enormous byte counts to the C, so
            // both trip the `actuallyread > readthisamountnow` test; here they
            // are variants, and they take the same branch by name.
            let actually_read = match outcome {
                SourceRead::Bytes(count) => count,
                SourceRead::Abort | SourceRead::Pause => want + 1,
            };
            let advanced = i64::try_from(actually_read).unwrap_or(i64::MAX);
            passed = passed.saturating_add(advanced);
            if actually_read == 0 || actually_read > want {
                return Err(ctx.failf(
                    CURLcode::ReadError,
                    format_args!(
                        "Could only read {passed} bytes from the input"
                    ),
                ));
            }

            // `lib/sendf.c:802`: the `while` of the `do ... while`.
            if passed >= offset {
                return Ok(());
            }
        }
    }
}

impl ClientReader for CrIn<'_> {
    fn kind(&self) -> ClientReaderKind {
        ClientReaderKind::Input
    }

    fn phase(&self) -> ClientReaderPhase {
        ClientReaderPhase::Client
    }

    /// `cr_in_read` (`lib/sendf.c:640-737`), transcribed branch for branch.
    ///
    /// # Errors
    ///
    /// * the sticky code, forever, once one has been recorded (`:652-656`);
    /// * [`CURLcode::ReadError`] for a premature end of a sized upload
    ///   (`:676-682`), for a pause requested on a networkless scheme
    ///   (`:698-704`) and for a callback that returned more than it was given
    ///   (`:715-723`);
    /// * [`CURLcode::AbortedByCallback`] when the callback aborted
    ///   (`:688-695`);
    /// * whatever [`TransferControl::pause_send`] returns, which the C assigns
    ///   straight to `result` at `:711`.
    fn read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        _tail: &mut ReaderTail<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        // `lib/sendf.c:649`. Cleared FIRST, before the sticky and end-of-stream
        // tests, so that a reader that errored while paused does not stay
        // paused.
        self.is_paused = false;

        // `lib/sendf.c:651-656`. The same error forever, with zero bytes and
        // NOT end-of-stream. Returned before the trace line at `:732`, because
        // the C returns rather than breaking out of the switch.
        if let Some(code) = self.error {
            return Err(Error::new(code));
        }
        // `lib/sendf.c:657-661`, likewise an early return.
        if self.seen_eos {
            return Ok(ReadOutcome::EOS);
        }

        // `lib/sendf.c:662-665`. Respect length limitations: never ask the
        // callback for more than the declared length still permits. A declared
        // length already reached clamps to zero, which skips the callback
        // entirely and lands on the end-of-stream arm below.
        let mut blen = buf.len();
        if self.total_len >= 0 {
            blen = so_to_usize_range(
                self.total_len.saturating_sub(self.read_len),
                0,
                blen,
            );
        }

        // `lib/sendf.c:666-672`. The guard is `if(ctx->read_cb && blen)`, so
        // neither a missing callback nor a zero-length request invokes
        // anything, and `has_used_cb` is set only when the callback really ran.
        let mut outcome = SourceRead::Bytes(0);
        if blen != 0 {
            if let Some(source) = self.source.as_deref_mut() {
                let dest = buf
                    .get_mut(..blen)
                    .expect("blen was clamped to the buffer's length");
                {
                    let _entered = ctx.enter_callback();
                    outcome = source.read(dest);
                }
                self.has_used_cb = true;
            }
        }

        // `lib/sendf.c:674-731`, the `switch(nread)`.
        let result = match outcome {
            // `case 0:` -- `lib/sendf.c:675-686`.
            SourceRead::Bytes(0) => {
                if self.total_len >= 0 && self.read_len < self.total_len {
                    // `:676-682`. NOT sticky: the C sets neither `errored` nor
                    // `error_result` here.
                    Err(ctx.failf(
                        CURLcode::ReadError,
                        format_args!(
                            "client read function EOF fail, only {}/{} of \
                             needed bytes read",
                            self.read_len, self.total_len
                        ),
                    ))
                } else {
                    // `:683-685`.
                    self.seen_eos = true;
                    Ok(ReadOutcome::EOS)
                }
            }

            // `case CURL_READFUNC_ABORT:` -- `lib/sendf.c:688-695`. Sticky.
            SourceRead::Abort => {
                let error = ctx.failf(
                    CURLcode::AbortedByCallback,
                    format_args!("operation aborted by callback"),
                );
                self.error = Some(CURLcode::AbortedByCallback);
                Err(error)
            }

            // `case CURL_READFUNC_PAUSE:` -- `lib/sendf.c:697-712`.
            SourceRead::Pause => {
                if ctx.config().nonetwork {
                    // `:698-705`. The C's comment: *"protocols that work
                    // without network cannot be paused. This is actually only
                    // FILE:// just now, and it cannot pause since the transfer
                    // is not done using the 'normal' procedure."* NOT sticky,
                    // and `is_paused` is left false.
                    Err(ctx.failf(
                        CURLcode::ReadError,
                        format_args!(
                            "Read callback asked for PAUSE when not supported"
                        ),
                    ))
                } else {
                    // `:706-712`.
                    ctx.trc_read(format_args!(
                        "cr_in_read, callback returned CURL_READFUNC_PAUSE"
                    ));
                    self.is_paused = true;
                    // The pause is requested of the transfer engine, and its
                    // result becomes this read's result -- so a pause that
                    // cannot be arranged fails the read rather than being
                    // silently forgotten.
                    ctx.control().pause_send(true).map(|()| ReadOutcome::EMPTY)
                }
            }

            // `default:` -- `lib/sendf.c:714-730`.
            SourceRead::Bytes(count) => {
                if count > blen {
                    // `:715-723`. Sticky. Judged against the CLAMPED length,
                    // not the destination's full length, which is what the C
                    // compares: `blen` has already been reduced by the
                    // declared-length clamp above.
                    let error = ctx.failf(
                        CURLcode::ReadError,
                        format_args!("read function returned funny value"),
                    );
                    self.error = Some(CURLcode::ReadError);
                    Err(error)
                } else {
                    // `:725-729`.
                    self.read_len = self
                        .read_len
                        .saturating_add(i64::try_from(count).unwrap_or(0));
                    if self.total_len >= 0 {
                        self.seen_eos = self.read_len >= self.total_len;
                    }
                    Ok(ReadOutcome::new(count, self.seen_eos))
                }
            }
        };

        // `lib/sendf.c:732-735`. Reached by every path that BROKE out of the
        // switch, which is all four of them, and by none of the two early
        // returns above.
        let (code, bytes_read, eos) = match &result {
            Ok(outcome) => (CURLcode::Ok, outcome.bytes_read, outcome.eos),
            Err(error) => (error.code(), 0, false),
        };
        ctx.trc_read(format_args!(
            "cr_in_read(len={blen}, total={}, read={}) -> {}, nread={}, \
             eos={}",
            self.total_len,
            self.read_len,
            code.as_i32(),
            bytes_read,
            i32::from(eos)
        ));
        result
    }

    /// `cr_in_needs_rewind` (`lib/sendf.c:739-745`): true once the callback has
    /// been invoked.
    ///
    /// Not "true once bytes were read": a callback that returned nothing has
    /// still been given the chance to advance its own stream, and the C keeps
    /// `has_used_cb` rather than testing `read_len` for exactly that reason.
    fn needs_rewind(&self) -> bool {
        self.has_used_cb
    }

    /// `cr_in_total_length` (`lib/sendf.c:747-753`): the declared length,
    /// unchanged.
    ///
    /// Does NOT consult the chain below, which is why the default body is
    /// overridden: this stage is at [`ClientReaderPhase::Client`] and is the
    /// bottom of the chain, so there is nothing below to ask.
    fn total_length(&self, _below: &ReaderQuery<'_, '_>) -> i64 {
        self.total_len
    }

    /// `cr_in_resume_from` (`lib/sendf.c:755-816`): start at `offset` instead
    /// of at the beginning.
    ///
    /// Four steps, in the C's order:
    ///
    /// 1. **Refuse if reading has begun** (`:763-765`). A source already part
    ///    way through cannot be repositioned by this route.
    /// 2. **Try the seek callback** (`:767-771`), with `seekerr` initialised to
    ///    `CURL_SEEKFUNC_CANTSEEK` so that a missing callback takes the same
    ///    path as one that cannot seek.
    /// 3. **Read and discard** when the answer was "cannot seek"
    ///    (`:773-803`), through the 4 KiB scratch area. Any OTHER non-OK answer
    ///    fails immediately, without discarding anything.
    /// 4. **Reduce the declared length** (`:805-813`), and fail when the offset
    ///    consumed all of it.
    ///
    /// # A negative offset
    ///
    /// `lib/sendf.h:376-377` says *"negative values will be ignored"*, and this
    /// is where they are: a negative offset makes step 3's `passed < offset`
    /// true at once, so nothing is discarded, and step 4's subtraction then
    /// INCREASES the length, which cannot reach the `<= 0` failure. The
    /// arithmetic saturates rather than wrapping, so no offset -- however
    /// extreme -- can panic or underflow here.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::ReadError`] when reading has already begun, when the seek
    ///   callback failed for any reason other than "cannot seek", or when the
    ///   discard loop could not reach the offset;
    /// * [`CURLcode::PartialFile`] when the offset consumed the whole declared
    ///   length, with the C's message *"File already completely uploaded"*.
    fn resume_from(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        offset: i64,
    ) -> CurlResult<()> {
        // 1 -- `lib/sendf.c:763-765`.
        if self.read_len != 0 {
            return Err(Error::new(CURLcode::ReadError));
        }

        // 2 -- `lib/sendf.c:760` and `:767-771`.
        let outcome = ctx
            .call_seek(offset, SeekOrigin::Start)
            .unwrap_or(SeekOutcome::CantSeek);

        // 3 -- `lib/sendf.c:773-803`.
        if outcome != SeekOutcome::Ok {
            if outcome != SeekOutcome::CantSeek {
                // `:776-779`.
                return Err(ctx.failf(
                    CURLcode::ReadError,
                    format_args!("Could not seek stream"),
                ));
            }
            self.discard_to_offset(ctx, offset)?;
        }

        // 4 -- `lib/sendf.c:805-813`. Guarded on `> 0`, so an unknown length
        // is left alone: -1 minus an offset would be a nonsense length.
        if self.total_len > 0 {
            self.total_len = self.total_len.saturating_sub(offset);
            if self.total_len <= 0 {
                return Err(ctx.failf(
                    CURLcode::PartialFile,
                    format_args!("File already completely uploaded"),
                ));
            }
        }
        // `lib/sendf.c:814-815`: we have passed, proceed as normal.
        Ok(())
    }

    /// `cr_in_cntrl` (`lib/sendf.c:879-898`).
    ///
    /// # Errors
    ///
    /// Only from [`ReaderControl::Rewind`]; see [`Self::rewind`].
    fn control(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        control: ReaderControl,
    ) -> CurlResult<()> {
        match control {
            // `:886-887`.
            ReaderControl::Rewind => self.rewind(ctx),
            // `:888-890`.
            ReaderControl::Unpause => {
                self.is_paused = false;
                Ok(())
            }
            // `:891-893`.
            ReaderControl::ClearEos => {
                self.seen_eos = false;
                Ok(())
            }
        }
    }

    /// `cr_in_is_paused` (`lib/sendf.c:900-906`).
    fn is_paused(&self) -> bool {
        self.is_paused
    }
}

// =========================================================================
// `cr_lc` -- the line-ending converter, `lib/sendf.c:957-1094`
// =========================================================================

/// The chunk size `cr_lc_init` gives its queue.
///
/// `Curl_bufq_init2(&ctx->buf, (16 * 1024), 1, BUFQ_OPT_SOFT_LIMIT)`
/// (`lib/sendf.c:969`). Sixteen kibibytes, ONE nominal chunk, and a SOFT limit
/// -- which together are what the C's comment at `:1028` relies on: *"on a soft
/// limit bufq, we do not need to check length"*. A soft limit lets the queue
/// exceed its nominal chunk count rather than refusing a write, so conversion
/// can never fail for want of room, whatever the input.
#[allow(dead_code)]
const LINECONV_CHUNK_LEN: usize = 16 * 1024;

/// The nominal chunk count `cr_lc_init` gives its queue.
#[allow(dead_code)]
const LINECONV_CHUNKS: usize = 1;

/// Appends every byte of `bytes` to `queue`.
///
/// The successor of the C's `Curl_bufq_cwrite(&ctx->buf, p, len, &n)` calls at
/// `lib/sendf.c:1029`, `:1031` and `:1038`, all three of which IGNORE the
/// written count `n` for the reason the comment at `:1028` gives. This loops
/// anyway, so the guarantee is structural rather than inherited: if a queue
/// without a soft limit were ever passed here, a short write would be completed
/// instead of silently dropping bytes.
///
/// An empty slice writes nothing and succeeds. That case is real --
/// `buf[start..i]` is empty whenever a bare line feed is the first byte of a
/// run -- and [`BufQ::write`] answers `Ok(0)` for it, so the guard below exists
/// to keep the loop's progress argument simple rather than to correct the
/// queue.
///
/// # Errors
///
/// Whatever [`BufQ::write`] returns, which for a soft-limit queue is only the
/// [`CURLcode::OutOfMemory`] its contract retains.
///
/// # Termination
///
/// Every turn either appends at least one byte, which shortens `remaining`, or
/// returns. There is no path that repeats without progress.
#[allow(dead_code)]
fn queue_write_all(queue: &mut BufQ, bytes: &[u8]) -> CurlResult<()> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let written = queue.write(remaining)?;
        if written == 0 {
            // A soft-limit queue cannot reach this, and a hard-limit one
            // reports a full queue as `Err(Again)` from `write` rather than as
            // a zero-length success. Treating it as "no room" keeps the loop
            // finite for any queue this function is ever handed.
            return Err(Error::new(CURLcode::Again));
        }
        remaining = remaining.get(written..).unwrap_or(&[]);
    }
    Ok(())
}

/// The reader that turns a bare line feed into a carriage return / line feed
/// pair.
///
/// Supersedes `cr_lc` and `struct cr_lc_ctx` (`lib/sendf.c:957-1094`).
/// Installed at [`ClientReaderPhase::ContentEncode`] and only when
/// [`ClientConfig::crlf`] or [`ClientConfig::prefer_ascii`] asks for it AND the
/// client stage reports a non-zero length -- see
/// [`ClientReaderStack::init_from_client`].
///
/// # What it converts, and what it leaves alone
///
/// A line feed is converted only when it is BARE. An existing pair is left
/// exactly as it is, which requires remembering whether the previous byte was a
/// carriage return -- and that memory has to survive a buffer boundary, because
/// the pair can be split across two reads. [`Self::prev_cr`] is that memory,
/// and it is why the converter cannot be written as a pure function over one
/// buffer.
///
/// Nothing else is touched. Not a lone carriage return, not a line feed
/// followed by a carriage return, not any other byte: specification 0.6.7
/// compares uploaded bytes literally, so the transformation is exactly the one
/// the C performs and nothing more.
///
/// # Why the length becomes indeterminate
///
/// Conversion GROWS the data by one byte per converted line feed, and by an
/// amount nobody can know before reading it. [`Self::total_length`] therefore
/// answers -1, which is what `cr_lc_total_length` does (`:1059-1066`) and what
/// `lib/sendf.h:353-357` promises a caller.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct CrLineConv {
    /// `struct bufq buf` (`lib/sendf.c:959`): the converted bytes waiting to be
    /// handed up.
    buf: BufQ,
    /// `BIT(read_eos)` (`lib/sendf.c:960`): the stage below has reported the
    /// end of its stream.
    read_eos: bool,
    /// `BIT(eos)` (`lib/sendf.c:961`): the end of the stream has been REPORTED
    /// upwards, which happens only once the queue has drained.
    eos: bool,
    /// `BIT(prev_cr)` (`lib/sendf.c:962`): the last byte examined was a
    /// carriage return.
    prev_cr: bool,
}

impl Default for CrLineConv {
    fn default() -> Self {
        Self::new()
    }
}

impl CrLineConv {
    /// A converter with an empty queue.
    ///
    /// `cr_lc_init` (`lib/sendf.c:965-971`). The queue is built here rather
    /// than in [`ClientReader::init`] because a Rust value is fully formed
    /// before anything can use it, so there is no window in which the queue
    /// does not exist -- and `cr_lc_close`'s `Curl_bufq_free` (`:973-978`) is
    /// the drop of that field.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            buf: BufQ::with_opts(
                LINECONV_CHUNK_LEN,
                LINECONV_CHUNKS,
                BufqOpts::SOFT_LIMIT,
            ),
            read_eos: false,
            eos: false,
            prev_cr: false,
        }
    }

    /// How many converted bytes are waiting, for the tests.
    #[allow(dead_code)]
    pub(crate) fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Whether the last byte examined was a carriage return, for the tests.
    ///
    /// The one piece of state that must survive a buffer boundary, which is
    /// exactly what makes it worth asserting on directly.
    #[allow(dead_code)]
    pub(crate) fn prev_cr(&self) -> bool {
        self.prev_cr
    }

    /// The conversion itself: `lib/sendf.c:1019-1041`.
    ///
    /// Reads `bytes` and appends the converted form to the queue. Split out of
    /// [`Self::read`] so that the read reads as one sequence, and because this
    /// loop is the part worth checking against the C line by line. Made
    /// `pub(crate)` so the test module can drive it directly with a pinned
    /// [`Self::prev_cr`] rather than having to arrange a whole chain to reach
    /// it.
    ///
    /// # Errors
    ///
    /// Whatever [`queue_write_all`] returns.
    #[allow(dead_code)]
    pub(crate) fn convert_into_queue(
        &mut self,
        bytes: &[u8],
    ) -> CurlResult<()> {
        let mut start = 0_usize;
        // `for(i = start = 0; i < nread; ++i)` -- `lib/sendf.c:1020`.
        for (index, &byte) in bytes.iter().enumerate() {
            // `:1023-1026`: if this byte is not a line feed, or if the
            // preceding character was a carriage return -- meaning this already
            // is a pair -- go to the next.
            if byte != b'\n' || self.prev_cr {
                self.prev_cr = byte == b'\r';
                continue;
            }
            // `:1027`.
            self.prev_cr = false;
            // `:1029-1033`. The run before the bare line feed, then the pair
            // that replaces it. The two literal bytes are written as a byte
            // string so that no formatting machinery can be interposed on them:
            // a `write!` with an escape would be a rendering of the pair, and
            // this is the pair.
            queue_write_all(&mut self.buf, &bytes[start..index])?;
            queue_write_all(&mut self.buf, b"\r\n")?;
            // `:1034`.
            start = index + 1;
        }

        // `:1037-1041`. The C's `if(start < i)` compares against the loop
        // variable, which after the loop equals the input length; the leftover
        // is whatever followed the last converted line feed.
        if start < bytes.len() {
            queue_write_all(&mut self.buf, &bytes[start..])?;
        }
        Ok(())
    }
}

impl ClientReader for CrLineConv {
    fn kind(&self) -> ClientReaderKind {
        ClientReaderKind::LineConv
    }

    fn phase(&self) -> ClientReaderPhase {
        ClientReaderPhase::ContentEncode
    }

    /// `cr_lc_read` (`lib/sendf.c:981-1057`), transcribed branch for branch.
    ///
    /// The destination buffer is used TWICE and the order matters: first as the
    /// scratch the stage below reads into, then as the destination the queue
    /// drains into. That is the C's own arrangement -- `Curl_creader_read(data,
    /// reader->next, buf, blen, ...)` at `:1005` followed by
    /// `Curl_bufq_cread(&ctx->buf, buf, blen, pnread)` at `:1046` -- and it is
    /// what lets conversion happen with one buffer rather than two.
    ///
    /// # The end of the stream is DEFERRED
    ///
    /// When the stage below reports the end of its stream, this stage does NOT
    /// pass that on until its queue has drained (`:1047-1051`). Reporting it
    /// early would tell the caller there is nothing more while converted bytes
    /// were still held, and those bytes would never be sent.
    ///
    /// # The no-line-feed shortcut does NOT update `prev_cr`, and that is
    /// transcribed rather than corrected
    ///
    /// `:1010-1017` returns before the conversion loop when the buffer holds
    /// no line feed, so [`Self::prev_cr`] is left exactly as it was. The
    /// consequence is observable and is measured in this file's test module: a
    /// carriage return that arrives in a buffer with no line feed in it is
    /// forgotten, so a pair split so that its carriage return lands in such a
    /// buffer becomes `\r\r\n`. A pair split after a buffer that DID hold a
    /// line feed is preserved, because the loop ran and recorded the carriage
    /// return.
    ///
    /// This is curl 8.19.0-DEV's behaviour, and specification 0.8.1 freezes it:
    /// tracking the carriage return through the shortcut as well would produce
    /// different uploaded bytes from the C on the same input, which is a
    /// wire-parity failure however much more sensible it looks.
    ///
    /// # Errors
    ///
    /// * whatever the stage below returns, which is returned WITHOUT tracing --
    ///   the C returns at `:1007` rather than reaching its `out:` label;
    /// * whatever [`queue_write_all`] returns, likewise untraced (`:1033`,
    ///   `:1040`);
    /// * [`CURLcode::Again`] from draining an empty destination, which is what
    ///   [`BufQ::read`] answers for a zero-length request and IS traced,
    ///   because the C falls through to `out:` for it.
    fn read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut ReaderTail<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        let blen = buf.len();
        // `lib/sendf.c:991-995`.
        if self.eos {
            return Ok(ReadOutcome::EOS);
        }

        if self.buf.is_empty() {
            // `:997-1003`. Nothing buffered and nothing more coming.
            if self.read_eos {
                self.eos = true;
                return Ok(ReadOutcome::EOS);
            }

            // `:1005-1008`. Still getting data from the next reader.
            let below = tail.read(ctx, buf)?;
            let nread = below.bytes_read;
            self.read_eos = below.eos;

            // `:1010-1017`. Nothing to convert: hand the bytes straight back,
            // untouched and uncopied. This is the common case for binary data,
            // and it is why an upload of a file with no line feeds costs
            // nothing at all.
            let holds_lf = memchr::memchr(b'\n', &buf[..nread]).is_some();
            if nread == 0 || !holds_lf {
                if self.read_eos {
                    self.eos = true;
                }
                let outcome = ReadOutcome::new(nread, self.eos);
                // `:1054-1055`, reached through the C's `goto out`.
                ctx.trc_read(format_args!(
                    "cr_lc_read(len={blen}) -> 0, nread={}, eos={}",
                    outcome.bytes_read,
                    i32::from(outcome.eos)
                ));
                return Ok(outcome);
            }

            // `:1019-1041`. At least one line feed might need converting.
            // `buf` is a parameter and `self` is the receiver, so the shared
            // borrow of the source and the mutable borrow of the queue are
            // disjoint and no copy is needed to separate them.
            self.convert_into_queue(&buf[..nread])?;
        }

        // `:1044`: `DEBUGASSERT(!Curl_bufq_is_empty(&ctx->buf))`.
        debug_assert!(
            !self.buf.is_empty(),
            "cr_lc drains a queue it has just filled"
        );
        // `:1045-1051`. The end of the stream is reported only once the queue
        // has drained.
        let result = self.buf.read(buf).map(|nread| {
            let mut eos = false;
            if self.read_eos && self.buf.is_empty() {
                self.eos = true;
                eos = true;
            }
            ReadOutcome::new(nread, eos)
        });

        // `:1053-1055`, the `out:` label, reached on success AND on a drain
        // failure.
        let (code, bytes_read, eos) = match &result {
            Ok(outcome) => (CURLcode::Ok, outcome.bytes_read, outcome.eos),
            Err(code) => (*code, 0, false),
        };
        ctx.trc_read(format_args!(
            "cr_lc_read(len={blen}) -> {}, nread={bytes_read}, eos={}",
            code.as_i32(),
            i32::from(eos)
        ));
        result.map_err(Error::new)
    }

    /// `cr_lc_total_length` (`lib/sendf.c:1059-1066`): always -1.
    ///
    /// *"this reader changes length depending on input"*. The chain below is
    /// deliberately not consulted: forwarding a length this stage is about to
    /// alter would be worse than admitting the length is unknown.
    fn total_length(&self, _below: &ReaderQuery<'_, '_>) -> i64 {
        -1
    }
}

// =========================================================================
// `cr_null` -- the empty source, `lib/sendf.c:1235-1283`
// =========================================================================

/// The reader that provides nothing at all.
///
/// Supersedes `cr_null` (`lib/sendf.c:1235-1270`). Installed by
/// [`ClientIo::set_null`] for a request whose body is known to be empty -- a
/// `POST` with no data, for instance -- so that the chain has a
/// [`ClientReaderPhase::Client`] stage without an application callback being
/// consulted for bytes that do not exist.
///
/// It has no state, so `sizeof(struct Curl_creader)` is what the C registers
/// for it (`:1269`).
///
/// Its length is ZERO and not -1, which is the detail that matters:
/// [`ClientReaderStack::init_from_client`] tests the client stage's length
/// before installing the line converter, so a zero-length source never gets one
/// (`:1111`).
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct CrNull;

impl CrNull {
    /// The reader. There is nothing to configure.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self
    }
}

impl ClientReader for CrNull {
    fn kind(&self) -> ClientReaderKind {
        ClientReaderKind::Null
    }

    fn phase(&self) -> ClientReaderPhase {
        ClientReaderPhase::Client
    }

    /// `cr_null_read` (`lib/sendf.c:1235-1247`): zero bytes and the end of the
    /// stream, on the first call and on every call after it.
    ///
    /// The destination is not touched, and there is no state to advance, so the
    /// answer never changes.
    fn read(
        &mut self,
        _ctx: &mut ClientCtx<'_>,
        _tail: &mut ReaderTail<'_, '_>,
        _buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        Ok(ReadOutcome::EOS)
    }

    /// `cr_null_total_length` (`lib/sendf.c:1249-1256`): zero.
    fn total_length(&self, _below: &ReaderQuery<'_, '_>) -> i64 {
        0
    }
}

// =========================================================================
// `cr_buf` -- the borrowed-buffer source, `lib/sendf.c:1285-1406`
// =========================================================================

/// The reader that hands up bytes from a buffer it does NOT own.
///
/// Supersedes `cr_buf` and `struct cr_buf_ctx` (`lib/sendf.c:1285-1384`).
/// Installed by [`ClientIo::set_buf`] for a request body the caller already
/// holds in memory -- `CURLOPT_POSTFIELDS`, chiefly.
///
/// # The buffer is BORROWED, and the compiler knows it
///
/// `lib/sendf.h:418` states the contract in prose: *"Set the client reader the
/// reads from the supplied buf (NOT COPIED)"*. Here `'data` states it in the
/// type. A reader over a borrowed buffer cannot outlive the buffer, so the
/// dangling read the C's contract only warns about is not expressible.
///
/// Nothing is copied on installation, and nothing is copied on a read beyond
/// the bytes the caller asked for -- which is the one copy the C performs too,
/// with `memcpy` at `:1307`.
///
/// # `blen` and `buf` are one field
///
/// The C keeps a pointer and a length and advances the pointer while
/// decrementing the length (`:1367-1368`). A slice carries both, so
/// `Self::remaining` is the C's pair and cannot go out of step with itself --
/// which is a real hazard in the C, where a `resume_from` that advanced the
/// pointer without shortening the length would read past the buffer.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct CrBuf<'data> {
    /// `ctx->buf` together with `ctx->blen` (`lib/sendf.c:1287-1288`).
    remaining: &'data [u8],
    /// `ctx->index` (`lib/sendf.c:1289`): how far into `remaining` reading has
    /// reached.
    index: usize,
}

impl<'data> CrBuf<'data> {
    /// A reader over `buf`, positioned at its start.
    ///
    /// `Curl_creader_set_buf`'s assignment of the three context fields
    /// (`lib/sendf.c:1397-1399`).
    #[allow(dead_code)]
    pub(crate) fn new(buf: &'data [u8]) -> Self {
        Self {
            remaining: buf,
            index: 0,
        }
    }

    /// How far into the buffer reading has reached, for the tests.
    #[allow(dead_code)]
    pub(crate) fn index(&self) -> usize {
        self.index
    }
}

impl ClientReader for CrBuf<'_> {
    fn kind(&self) -> ClientReaderKind {
        ClientReaderKind::Buf
    }

    fn phase(&self) -> ClientReaderPhase {
        ClientReaderPhase::Client
    }

    /// `cr_buf_read` (`lib/sendf.c:1292-1315`).
    ///
    /// Hands up as much as the destination will take, and reports the end of
    /// the stream on the read that reaches the last byte -- WITH those bytes,
    /// not after them. An exhausted or empty buffer answers zero bytes and the
    /// end of the stream, which is the C's `if(!nread || !ctx->buf)` at
    /// `:1300`: a null pointer and a zero remaining length take the same
    /// branch, and an empty slice is the successor of both.
    fn read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        _tail: &mut ReaderTail<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        // `lib/sendf.c:1298`.
        let available = self.remaining.len() - self.index;
        let outcome = if available == 0 {
            // `:1300-1303`.
            ReadOutcome::EOS
        } else {
            // `:1304-1311`.
            let nread = available.min(buf.len());
            let source = &self.remaining[self.index..self.index + nread];
            buf[..nread].copy_from_slice(source);
            self.index += nread;
            ReadOutcome::new(nread, self.index == self.remaining.len())
        };
        // `:1312-1313`. The C hard-codes the result as 0 in this trace, because
        // this reader cannot fail.
        ctx.trc_read(format_args!(
            "cr_buf_read(len={}) -> 0, nread={}, eos={}",
            buf.len(),
            outcome.bytes_read,
            i32::from(outcome.eos)
        ));
        Ok(outcome)
    }

    /// `cr_buf_needs_rewind` (`lib/sendf.c:1317-1323`): true once anything has
    /// been read.
    fn needs_rewind(&self) -> bool {
        self.index > 0
    }

    /// `cr_buf_total_length` (`lib/sendf.c:1341-1347`): the length of the
    /// buffer the reader was given, or of what remains of it after a resume.
    ///
    /// NOT the length still unread. The C returns `ctx->blen`, which
    /// `resume_from` shortens but a read does not, so this answer is stable
    /// across reads -- and it has to be, because a caller uses it to declare a
    /// `Content-Length` before any reading happens.
    fn total_length(&self, _below: &ReaderQuery<'_, '_>) -> i64 {
        i64::try_from(self.remaining.len()).unwrap_or(i64::MAX)
    }

    /// `cr_buf_resume_from` (`lib/sendf.c:1349-1370`): drop the first `offset`
    /// bytes.
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] when reading has already begun (`:1359-1360`) or
    /// when the offset is past the end of the buffer (`:1364-1365`). A negative
    /// offset clamps to zero through [`so_to_usize_range`] and then succeeds
    /// having done nothing, which is the C's `if(!boffset) return CURLE_OK` at
    /// `:1362` and matches `lib/sendf.h:376-377`'s promise that negative values
    /// are ignored.
    fn resume_from(
        &mut self,
        _ctx: &mut ClientCtx<'_>,
        offset: i64,
    ) -> CurlResult<()> {
        // `:1359-1360`.
        if self.index != 0 {
            return Err(Error::new(CURLcode::ReadError));
        }
        // `:1361`.
        let boffset = so_to_usize_range(offset, 0, usize::MAX);
        // `:1362-1363`.
        if boffset == 0 {
            return Ok(());
        }
        // `:1364-1365`. Strictly greater: an offset EQUAL to the length is
        // accepted and leaves an empty buffer, which then reads as the end of
        // the stream.
        if boffset > self.remaining.len() {
            return Err(Error::new(CURLcode::ReadError));
        }
        // `:1367-1368`.
        self.remaining = &self.remaining[boffset..];
        Ok(())
    }

    /// `cr_buf_cntrl` (`lib/sendf.c:1325-1339`): only
    /// [`ReaderControl::Rewind`] does anything.
    ///
    /// The C's `switch` handles `CURL_CRCNTRL_REWIND` and falls to `default:`
    /// for the other two, so neither an unpause nor a clear-EOS touches this
    /// reader -- and neither needs to: it is never paused, and its
    /// end-of-stream answer is derived from `index` rather than remembered, so
    /// a rewind clears it as a side effect.
    fn control(
        &mut self,
        _ctx: &mut ClientCtx<'_>,
        control: ReaderControl,
    ) -> CurlResult<()> {
        if control == ReaderControl::Rewind {
            // `:1332-1334`.
            self.index = 0;
        }
        Ok(())
    }
}

// =========================================================================
// The default input source -- the safe successor of `fread` plus `fseek`
// =========================================================================

/// An input source over anything that can be read and seeked.
///
/// The safe successor of curl's default upload path, which is
/// `data->state.fread_func == fread` reading from the `FILE *` in
/// `data->state.in`. Two things the C needs disappear:
///
/// * the function-pointer comparison at `lib/sendf.c:860`, whose cast needs a
///   `#pragma` to silence `-Wcast-function-type-strict`, becomes
///   [`ClientReadSource::seek_to_start`] answering [`Some`];
/// * `fseek`'s -1-and-consult-`errno` protocol becomes a
///   [`std::io::Result`].
///
/// Any `Read + Seek` will do, which is what makes the rewind path of
/// [`CrIn::rewind`] testable over a [`std::io::Cursor`] with no file system
/// involved -- and a real upload is a [`std::fs::File`], which satisfies both
/// bounds.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct StreamReadSource<S> {
    /// The stream. Owned, because the C's `FILE *` outlives every individual
    /// read and the reader is the natural owner of it.
    stream: S,
}

impl<S: Read + Seek> StreamReadSource<S> {
    /// A source over `stream`, reading from wherever it currently is.
    ///
    /// The position is NOT reset on construction, exactly as curl does not
    /// rewind the `FILE *` an application handed it: an application that opened
    /// a file and read its header before passing it in expects the upload to
    /// begin where it left off.
    #[allow(dead_code)]
    pub(crate) fn new(stream: S) -> Self {
        Self { stream }
    }

    /// The stream back, for a caller that needs to inspect it after a transfer.
    #[allow(dead_code)]
    pub(crate) fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Seek + fmt::Debug> ClientReadSource for StreamReadSource<S> {
    /// One `fread`.
    ///
    /// # Why an error becomes zero bytes
    ///
    /// `fread` reports a read error and the end of the file identically -- a
    /// short item count -- and leaves the caller to distinguish them with
    /// `ferror`, which curl's default path does NOT do. So a failing read
    /// presents to `cr_in` as the end of the upload, and `cr_in` then judges it
    /// against the declared length: a sized upload fails with
    /// [`CURLcode::ReadError`] and *"client read function EOF fail"*, and an
    /// unsized one ends cleanly. Reproducing that means answering
    /// [`SourceRead::Bytes`] with zero rather than inventing an error variant
    /// the C's default path cannot produce.
    ///
    /// [`std::io::ErrorKind::Interrupted`] is retried instead, because it means
    /// "nothing happened, ask again" -- the C library's `fread` retries a
    /// signal-interrupted read internally, so surfacing it would be a
    /// difference rather than a faithful reproduction.
    fn read(&mut self, buf: &mut [u8]) -> SourceRead {
        loop {
            match self.stream.read(buf) {
                Ok(count) => return SourceRead::Bytes(count),
                Err(error)
                    if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return SourceRead::Bytes(0),
            }
        }
    }

    /// `fseek(data->state.in, 0, SEEK_SET)` (`lib/sendf.c:864`).
    ///
    /// [`Some`] rather than [`None`], because this IS the default source the
    /// C's function-pointer comparison is looking for.
    fn seek_to_start(&mut self) -> Option<std::io::Result<()>> {
        Some(self.stream.seek(SeekFrom::Start(0)).map(|_| ()))
    }
}

// =========================================================================
// The reader chain's installers -- `lib/sendf.c:1096-1178`
// =========================================================================

impl<'data> ClientReaderStack<'data> {
    /// `do_init_reader_stack` (`lib/sendf.c:1096-1122`): make `client` the
    /// whole chain, and add the line converter when it is wanted.
    ///
    /// The ORDER of the two tests is what matters, and the C's own comment says
    /// so: *"if we do not have 0 length init, and crlf conversion is wanted,
    /// add the reader for it"* (`:1109-1110`). The length is asked of the
    /// client stage FIRST, so a source that provides nothing -- [`CrNull`],
    /// whose length is 0 -- never gets a converter, whatever the settings
    /// say. A length of -1, "unknown", is NOT zero and does get one.
    ///
    /// # Errors
    ///
    /// Whatever [`ClientReader::init`] returns for the converter. The client
    /// stage is already installed at that point, exactly as in the C, so a
    /// caller that retries sees a chain with the source but no converter.
    ///
    /// # Panics
    ///
    /// In a debug build only, when `client` is not at
    /// [`ClientReaderPhase::Client`] or the chain is not empty -- the C's two
    /// `DEBUGASSERT`s at `:1104-1105`. A source installed at any other phase
    /// would not be the bottom of the chain, and every length, resume and
    /// rewind query walks to the client phase to find it.
    #[allow(dead_code)]
    pub(crate) fn init_from_client(
        &mut self,
        client: Box<dyn ClientReader + 'data>,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<()> {
        // `lib/sendf.c:1104-1105`.
        debug_assert_eq!(
            client.phase(),
            ClientReaderPhase::Client,
            "a reader chain is founded on a CURL_CR_CLIENT stage"
        );
        debug_assert!(
            self.stages.is_empty(),
            "a reader chain is founded on an empty chain"
        );

        // `:1107-1108`.
        self.stages.push(client);
        let clen = self.total_length();

        // `:1111-1119`.
        let wants_conversion = ctx.config().crlf || ctx.config().prefer_ascii;
        if clen != 0 && wants_conversion {
            // `cr_lc_add` (`:1082-1094`): created, then added, and freed again
            // if the add fails. The add cannot fail here -- the chain is not
            // empty, so no lazy base stack is built -- so the C's cleanup arm
            // has no counterpart beyond the drop `create` already performs.
            let converter = Self::create(Box::new(CrLineConv::new()), ctx)?;
            self.insert(converter);
        }
        Ok(())
    }
}

// =========================================================================
// `ClientIo` -- the two chains and their lifecycle
// =========================================================================

/// The two chains of one transfer, and the five operations that manage them.
///
/// Supersedes the pair of fields `struct SingleRequest` holds for them --
/// `writer_stack` and `reader_stack` (`lib/request.h:87` and `:90`) -- together
/// with `Curl_client_write`, `Curl_client_read`, `Curl_client_cleanup`,
/// `Curl_client_reset` and `Curl_client_start`.
///
/// `transfer/request.rs` embeds this; nothing else needs to.
///
/// # The factory
///
/// The base writer stack needs two stages that `transfer/writeout.rs` owns, and
/// the lazily created input reader needs the application's callback. All three
/// arrive through [`ClientIoFactory`], which the transfer engine supplies once
/// and this type then holds for the life of the request -- so a chain rebuilt
/// after a reset is rebuilt from the same source as the first one, which is
/// what the C achieves by reading `data->state` again.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ClientIo<'data> {
    /// Where the two stages of the base writer stack and the default input
    /// source come from.
    factory: &'data dyn ClientIoFactory<'data>,
    /// The writer chain.
    writers: ClientWriterStack<'data>,
    /// The reader chain.
    readers: ClientReaderStack<'data>,
}

impl<'data> ClientIo<'data> {
    /// Two empty chains over `factory`.
    ///
    /// The state `Curl_req_init` leaves behind: both `writer_stack` and
    /// `reader_stack` are `NULL` until something is written or read.
    #[allow(dead_code)]
    pub(crate) fn new(factory: &'data dyn ClientIoFactory<'data>) -> Self {
        Self {
            factory,
            writers: ClientWriterStack::new(),
            readers: ClientReaderStack::new(),
        }
    }

    /// The writer chain, shared.
    #[allow(dead_code)]
    pub(crate) fn writers(&self) -> &ClientWriterStack<'data> {
        &self.writers
    }

    /// The reader chain, shared.
    #[allow(dead_code)]
    pub(crate) fn readers(&self) -> &ClientReaderStack<'data> {
        &self.readers
    }

    /// The reader chain, mutable.
    ///
    /// Handed out so that a stage installed by another module -- the chunked
    /// encoder, the MIME reader -- can be reached without this type having to
    /// name it.
    #[allow(dead_code)]
    pub(crate) fn readers_mut(&mut self) -> &mut ClientReaderStack<'data> {
        &mut self.readers
    }

    /// The writer chain, mutable.
    ///
    /// [`Self::add_writer`] exists ON TOP of this rather than instead of it,
    /// because inserting a stage has to run the lazy base-stack build first and
    /// that needs the factory this type holds -- which the chain itself does
    /// not have.
    #[allow(dead_code)]
    pub(crate) fn writers_mut(&mut self) -> &mut ClientWriterStack<'data> {
        &mut self.writers
    }

    // ---- the writer chain ------------------------------------------------

    /// `Curl_client_write` (`lib/sendf.c:375-401`): send bytes to the
    /// application.
    ///
    /// THE ENTRY POINT for every response byte in the crate. Three things
    /// happen, in this order:
    ///
    /// 1. **The flag invariants are checked** (`:380-388`), in a debug build.
    ///    This is the ONE place that check belongs; see
    ///    [`ClientWriteFlags::is_valid`] for the `lib/ws.c` call site that
    ///    makes that so.
    /// 2. **The base stack is built if the chain is empty** (`:390-395`), so a
    ///    protocol that writes before installing anything still gets the four
    ///    standard stages.
    /// 3. **The chain runs** (`:397-399`), and the outcome is traced.
    ///
    /// # Errors
    ///
    /// Whatever a stage returns, and [`CURLcode::WriteError`] if the chain is
    /// somehow still empty -- which the C guards with a `DEBUGASSERT` at `:394`
    /// and this reproduces as an assertion plus the same code.
    ///
    /// # Panics
    ///
    /// In a debug build only, on flags that violate the three invariants, or if
    /// the base stack build left an empty chain. A release build proceeds and
    /// the empty chain becomes [`CURLcode::WriteError`], which is what the C's
    /// compiled-out assertion leaves behind.
    #[allow(dead_code)]
    pub(crate) fn client_write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // 1 -- `lib/sendf.c:380-388`. One assertion rather than the C's three,
        // and it names which of the three failed; see the method's own
        // documentation for each.
        debug_assert!(
            flags.is_valid(),
            "client_write flags {flags} violate lib/sendf.c:380-388: exactly \
             one of BODY/INFO/HEADER, BODY and INFO only with EOS"
        );

        // 2 -- `:390-395`.
        if self.writers.is_empty() {
            self.writers.init_base(ctx, self.factory)?;
            debug_assert!(
                !self.writers.is_empty(),
                "init_base leaves four stages behind"
            );
        }

        // 3 -- `:397-399`.
        let result = self.writers.write(ctx, flags, buf);
        let code = match &result {
            Ok(()) => CURLcode::Ok,
            Err(error) => error.code(),
        };
        ctx.trc_write(format_args!(
            "client_write(type={flags}, len={}) -> {}",
            buf.len(),
            code.as_i32()
        ));
        result
    }

    /// `Curl_cwriter_add` (`lib/sendf.c:452-471`): install a writer stage.
    ///
    /// # Errors
    ///
    /// Whatever building the base stack returns; the insertion cannot fail.
    #[allow(dead_code)]
    pub(crate) fn add_writer(
        &mut self,
        writer: Box<dyn ClientWriter + 'data>,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<()> {
        self.writers.add(writer, ctx, self.factory)
    }

    /// `do_init_writer_stack` (`lib/sendf.c:325-368`) on demand.
    ///
    /// Exposed so that a caller which needs the four standard stages present
    /// before it writes -- or a test that wants to assert their order -- can
    /// ask for them without writing a byte.
    ///
    /// # Errors
    ///
    /// Whatever [`ClientWriterStack::init_base`] returns.
    #[allow(dead_code)]
    pub(crate) fn init_writers(
        &mut self,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<()> {
        if self.writers.is_empty() {
            self.writers.init_base(ctx, self.factory)?;
        }
        Ok(())
    }

    // ---- the reader chain ------------------------------------------------

    /// `Curl_client_read` (`lib/sendf.c:1180-1220`): pull bytes from the
    /// application.
    ///
    /// THE ENTRY POINT for every request byte in the crate. Four things happen,
    /// in this order:
    ///
    /// 1. **The chain is built if it is empty** (`:1191-1196`), from the
    ///    factory's input source and [`ClientConfig::infilesize`].
    /// 2. **The upload rate limiter is started, once** (`:1197-1200`), with an
    ///    UNKNOWN total. -1 rather than the declared length, deliberately: the
    ///    C passes -1 here where `cw_download` passes `req.size`, because an
    ///    upload's pacing is not tuned to its length.
    /// 3. **The request is clamped to the tokens available** (`:1202-1212`). No
    ///    tokens is a SUCCESSFUL read of nothing -- backpressure, not an error
    ///    -- and the caller retries when the limiter says to.
    /// 4. **The chain runs** (`:1213-1214`), and the outcome is traced.
    ///
    /// # The tokens are not spent here
    ///
    /// Step 3 CONSULTS the limiter; it does not charge it. The charge happens
    /// when the bytes are actually accounted for, through
    /// [`Progress::upload_inc`], because bytes that were read but not yet sent
    /// have not consumed any bandwidth. Draining on the read instead would pace
    /// the transfer by what the application produced rather than by what went
    /// out.
    ///
    /// # Errors
    ///
    /// Whatever building the chain or a stage returns, and
    /// [`CURLcode::ReadError`] when the chain is empty.
    ///
    /// # Panics
    ///
    /// In a debug build only, on an empty destination -- the C's
    /// `DEBUGASSERT(blen)` at `:1186`. A zero-length request would reach
    /// [`BufQ::read`] through a line converter and be answered
    /// [`CURLcode::Again`], which is a strange thing for a read of nothing to
    /// say and is worth catching where it is caused.
    #[allow(dead_code)]
    pub(crate) fn client_read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        // `lib/sendf.c:1185-1188`.
        debug_assert!(
            !buf.is_empty(),
            "client_read is never asked for zero bytes"
        );

        // 1 -- `:1191-1196`.
        if self.readers.is_empty() {
            self.set_fread(ctx, ctx.config().infilesize)?;
            debug_assert!(
                !self.readers.is_empty(),
                "set_fread leaves at least the client stage behind"
            );
        }

        // 2 -- `:1197-1200`.
        if !ctx.read_state().reader_started {
            let now = ctx.pgrs_now();
            ctx.progress_mut().upload_mut().rlimit_mut().start(now, -1);
            ctx.read_state_mut().reader_started = true;
        }

        // 3 -- `:1202-1212`.
        let mut blen = buf.len();
        if ctx.progress_mut().upload().rlimit().is_active() {
            let now = ctx.pgrs_now();
            let available =
                ctx.progress_mut().upload_mut().rlimit_mut().available(now);
            if available <= 0 {
                // `:1205-1209`. A successful read of nothing, and NOT the end
                // of the stream: the data is still coming, just not yet.
                let outcome = ReadOutcome::EMPTY;
                ctx.trc_read(format_args!(
                    "client_read(len={blen}) -> 0, nread=0, eos=0"
                ));
                return Ok(outcome);
            }
            // `:1210-1211`.
            if available < i64::try_from(blen).unwrap_or(i64::MAX) {
                blen = so_to_usize_range(available, 0, blen);
            }
        }

        // 4 -- `:1213-1218`.
        let dest = buf
            .get_mut(..blen)
            .expect("blen was clamped to the buffer's length");
        let result = self.readers.read(ctx, dest);
        let (code, bytes_read, eos) = match &result {
            Ok(outcome) => (CURLcode::Ok, outcome.bytes_read, outcome.eos),
            Err(error) => (error.code(), 0, false),
        };
        ctx.trc_read(format_args!(
            "client_read(len={blen}) -> {}, nread={bytes_read}, eos={}",
            code.as_i32(),
            i32::from(eos)
        ));
        result
    }

    /// `Curl_creader_set_fread` (`lib/sendf.c:1124-1142`): make the
    /// application's callback the source, declaring `len` bytes.
    ///
    /// Replaces whatever chain was installed, so a caller that had a converter
    /// gets a fresh one built by [`ClientReaderStack::init_from_client`].
    ///
    /// # Errors
    ///
    /// Whatever [`ClientReaderStack::init_from_client`] returns.
    #[allow(dead_code)]
    pub(crate) fn set_fread(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        len: i64,
    ) -> CurlResult<()> {
        // `:1130-1134`. Built with its length rather than initialised and then
        // adjusted; see `CrIn::new`.
        let source = self.factory.input_source();
        let reader =
            ClientReaderStack::create(Box::new(CrIn::new(source, len)), ctx);
        let result = match reader {
            Err(error) => Err(error),
            Ok(reader) => {
                // `:1136-1137`.
                self.reset_readers(ctx);
                self.readers.init_from_client(reader, ctx)
            }
        };
        // `:1139-1140`.
        let code = match &result {
            Ok(()) => CURLcode::Ok,
            Err(error) => error.code(),
        };
        ctx.trc_read(format_args!(
            "add fread reader, len={len} -> {}",
            code.as_i32()
        ));
        result
    }

    /// `Curl_creader_set_null` (`lib/sendf.c:1272-1283`): make the source an
    /// empty one.
    ///
    /// # Errors
    ///
    /// Whatever [`ClientReaderStack::init_from_client`] returns, which for a
    /// [`CrNull`] source is nothing: its length is zero, so no converter is
    /// installed and there is nothing left that can fail.
    #[allow(dead_code)]
    pub(crate) fn set_null(
        &mut self,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<()> {
        let reader = ClientReaderStack::create(Box::new(CrNull::new()), ctx)?;
        self.reset_readers(ctx);
        self.readers.init_from_client(reader, ctx)
    }

    /// `Curl_creader_set_buf` (`lib/sendf.c:1386-1406`): make the source a
    /// buffer the caller still owns.
    ///
    /// The buffer is NOT copied, and `'data` is what makes that safe; see
    /// [`CrBuf`].
    ///
    /// # Errors
    ///
    /// Whatever [`ClientReaderStack::init_from_client`] returns.
    #[allow(dead_code)]
    pub(crate) fn set_buf(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        buf: &'data [u8],
    ) -> CurlResult<()> {
        let blen = buf.len();
        let reader = ClientReaderStack::create(Box::new(CrBuf::new(buf)), ctx);
        let result = match reader {
            Err(error) => Err(error),
            Ok(reader) => {
                self.reset_readers(ctx);
                self.readers.init_from_client(reader, ctx)
            }
        };
        // `:1404`.
        let code = match &result {
            Ok(()) => CURLcode::Ok,
            Err(error) => error.code(),
        };
        ctx.trc_read(format_args!(
            "add buf reader, len={blen} -> {}",
            code.as_i32()
        ));
        result
    }

    /// `Curl_creader_set` (`lib/sendf.c:1165-1178`): make `reader` the whole
    /// chain.
    ///
    /// The general form of the three `set_*` installers above, for a source
    /// another module owns -- the MIME reader, chiefly. Takes ownership of
    /// `reader`, as the C's header promises at `lib/sendf.h:321`, so a failed
    /// installation destroys it rather than leaving the caller a stage it can
    /// no longer install.
    ///
    /// # Errors
    ///
    /// Whatever [`ClientReaderStack::init_from_client`] returns.
    #[allow(dead_code)]
    pub(crate) fn set_reader(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        reader: Box<dyn ClientReader + 'data>,
    ) -> CurlResult<()> {
        // `:1169-1171`.
        debug_assert_eq!(
            reader.phase(),
            ClientReaderPhase::Client,
            "Curl_creader_set takes a CURL_CR_CLIENT stage"
        );
        self.reset_readers(ctx);
        self.readers.init_from_client(reader, ctx)
    }

    /// `Curl_creader_add` (`lib/sendf.c:1144-1163`): install a reader stage
    /// above the source.
    ///
    /// Builds the default source first when the chain is empty (`:1150-1154`),
    /// so a chunked encoder installed before anything else still has something
    /// beneath it to pull from -- the read-side counterpart of the writer
    /// chain's lazy base stack.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::set_fread`] returns; the insertion cannot fail.
    #[allow(dead_code)]
    pub(crate) fn add_reader(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        reader: Box<dyn ClientReader + 'data>,
    ) -> CurlResult<()> {
        // `:1150-1154`.
        if self.readers.is_empty() {
            self.set_fread(ctx, ctx.config().infilesize)?;
        }
        // `:1156-1161`.
        self.readers.insert(reader);
        Ok(())
    }

    // ---- the lifecycle ---------------------------------------------------

    /// `cl_reset_reader` (`lib/sendf.c:58-68`) in full, including the flag.
    ///
    /// Clears the chain AND `reader_started`, which the C's function does at
    /// `:61` -- before closing anything, so a stage's `do_close` observes the
    /// flag already cleared. Every caller of the C's function goes through
    /// this one.
    #[allow(dead_code)]
    fn reset_readers(&mut self, ctx: &mut ClientCtx<'_>) {
        // `:61`, and before the walk exactly as the C has it.
        ctx.read_state_mut().reader_started = false;
        self.readers.clear(ctx);
    }

    /// `Curl_client_cleanup` (`lib/sendf.c:70-77`): tear both chains down.
    ///
    /// The readers go FIRST and the writers second, which is the C's order at
    /// `:72-73`. Then the two counters are reset (`:75-76`).
    ///
    /// Unlike [`Self::client_reset`] this ignores `rewind_read` entirely: a
    /// cleanup is the end of the transfer, so there is no next request to
    /// rewind for.
    #[allow(dead_code)]
    pub(crate) fn client_cleanup(&mut self, ctx: &mut ClientCtx<'_>) {
        self.reset_readers(ctx);
        self.writers.clear(ctx);
        // `:75-76`.
        ctx.write_state_mut().bytecount = 0;
        ctx.write_state_mut().headerline = 0;
    }

    /// `Curl_client_reset` (`lib/sendf.c:79-93`): tear the chains down between
    /// requests, KEEPING the readers when a rewind is pending.
    ///
    /// The one asymmetry between the two chains, and it is the whole point of
    /// the function: the writers always go, and the readers survive when
    /// `rewind_read` is set -- because rewinding them is what
    /// [`Self::client_start`] is going to do, and a chain that had been
    /// destroyed could not be rewound. The C traces which of the two happened,
    /// and both wordings are preserved.
    #[allow(dead_code)]
    pub(crate) fn client_reset(&mut self, ctx: &mut ClientCtx<'_>) {
        if ctx.read_state().rewind_read {
            // `:81-84`: already requested.
            ctx.trc_read(format_args!("client_reset, will rewind reader"));
        } else {
            // `:85-88`.
            ctx.trc_read(format_args!("client_reset, clear readers"));
            self.reset_readers(ctx);
        }
        // `:89`.
        self.writers.clear(ctx);
        // `:91-92`.
        ctx.write_state_mut().bytecount = 0;
        ctx.write_state_mut().headerline = 0;
    }

    /// `Curl_client_start` (`lib/sendf.c:95-115`): a new request is beginning.
    ///
    /// Does nothing at all unless a rewind is pending. When one is, every
    /// reader is told to rewind, in chain order, and the chain is DISCARDED --
    /// which looks contradictory and is not: the rewind puts the underlying
    /// source back to its start, and the chain is then rebuilt on the next read
    /// so that any encoding stage starts fresh. Rewinding without discarding
    /// would leave a line converter holding bytes from the previous attempt.
    ///
    /// # Errors
    ///
    /// The FIRST failure, unchanged, with the C's diagnostic at `:105-106`
    /// naming the stage that produced it. The walk stops there, so the stages
    /// below an unrewindable one are not asked -- and the chain is NOT
    /// discarded, because a rewind that failed leaves the transfer unable to
    /// retry and the caller is about to fail it.
    #[allow(dead_code)]
    pub(crate) fn client_start(
        &mut self,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<()> {
        // `:97`.
        if !ctx.read_state().rewind_read {
            return Ok(());
        }

        // `:101`.
        ctx.trc_read(format_args!("client start, rewind readers"));
        // `:102-110`.
        if let Err((name, error)) =
            self.readers.control_all(ctx, ReaderControl::Rewind)
        {
            let code = error.code();
            // `:105-106`. The message names the stage and the code, and it
            // REPLACES nothing: the returned error keeps the code the stage
            // chose, and the specific line the stage may already have attached
            // is superseded by this one, which is what `failf` does in the C.
            return Err(ctx.failf(
                code,
                format_args!(
                    "rewind of client reader '{name}' failed: {}",
                    code.as_i32()
                ),
            ));
        }

        // `:111-112`.
        ctx.read_state_mut().rewind_read = false;
        self.reset_readers(ctx);
        Ok(())
    }

    /// `Curl_creader_will_rewind` (`lib/sendf.c:117-120`): whether a rewind is
    /// pending.
    #[allow(dead_code)]
    pub(crate) fn will_rewind(&self, ctx: &ClientCtx<'_>) -> bool {
        ctx.read_state().rewind_read
    }

    /// `Curl_creader_set_rewind` (`lib/sendf.c:122-125`): request or cancel a
    /// rewind at the next start.
    #[allow(dead_code)]
    pub(crate) fn set_rewind(&self, ctx: &mut ClientCtx<'_>, enable: bool) {
        ctx.read_state_mut().rewind_read = enable;
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::rc::Rc;
    use std::time::Duration;

    use super::*;
    use crate::transfer::ratelimit::RateLimit;
    use crate::util::dynbuf::{DYN_HTTP_REQUEST, DYN_PAUSE_BUFFER};
    use crate::util::timeval::TestClock;

    // -- the doubles ------------------------------------------------------

    /// One write that reached a recording stage.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct WriteRecord {
        stage: &'static str,
        flags: ClientWriteFlags,
        bytes: Vec<u8>,
    }

    /// One read that a recording stage answered.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ReadRecord {
        stage: &'static str,
        asked: usize,
    }

    /// Everything the recording stages of one chain saw, in order.
    ///
    /// Shared rather than owned per stage, so that a single assertion can check
    /// the ORDER across the whole chain -- which is the property this module
    /// exists to keep.
    #[derive(Debug, Default)]
    struct ChainLog {
        writes: Vec<WriteRecord>,
        inits: Vec<&'static str>,
        closes: Vec<&'static str>,
        unpauses: Vec<&'static str>,
        reads: Vec<ReadRecord>,
        controls: Vec<(&'static str, ReaderControl)>,
        dones: Vec<(&'static str, bool)>,
    }

    type SharedLog = Rc<RefCell<ChainLog>>;

    fn log() -> SharedLog {
        Rc::new(RefCell::new(ChainLog::default()))
    }

    /// A writer stage that records what it saw.
    #[derive(Debug)]
    struct RecordingWriter {
        kind: ClientWriterKind,
        phase: ClientWriterPhase,
        log: SharedLog,
        /// Whether to hand the bytes on. A sink -- the `cw-out` double -- does
        /// not.
        forward: bool,
        /// What [`ClientWriter::is_paused`] answers.
        paused: Rc<Cell<bool>>,
        /// A code to fail every write with.
        fail: Option<CURLcode>,
        /// A code to fail initialisation with.
        init_fail: Option<CURLcode>,
    }

    impl RecordingWriter {
        fn new(
            kind: ClientWriterKind,
            phase: ClientWriterPhase,
            log: &SharedLog,
        ) -> Self {
            Self {
                kind,
                phase,
                log: Rc::clone(log),
                forward: true,
                paused: Rc::new(Cell::new(false)),
                fail: None,
                init_fail: None,
            }
        }

        fn sink(kind: ClientWriterKind, log: &SharedLog) -> Self {
            let mut writer = Self::new(kind, ClientWriterPhase::Client, log);
            writer.forward = false;
            writer
        }

        fn boxed(self) -> Box<dyn ClientWriter> {
            Box::new(self)
        }

        fn with_paused(mut self, paused: &Rc<Cell<bool>>) -> Self {
            self.paused = Rc::clone(paused);
            self
        }

        fn failing(mut self, code: CURLcode) -> Self {
            self.fail = Some(code);
            self
        }

        fn init_failing(mut self, code: CURLcode) -> Self {
            self.init_fail = Some(code);
            self
        }
    }

    impl ClientWriter for RecordingWriter {
        fn kind(&self) -> ClientWriterKind {
            self.kind
        }

        fn phase(&self) -> ClientWriterPhase {
            self.phase
        }

        fn init(&mut self, _ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
            self.log.borrow_mut().inits.push(self.name());
            match self.init_fail {
                None => Ok(()),
                Some(code) => Err(Error::new(code)),
            }
        }

        fn write(
            &mut self,
            ctx: &mut ClientCtx<'_>,
            tail: &mut WriterTail<'_, '_>,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CurlResult<()> {
            self.log.borrow_mut().writes.push(WriteRecord {
                stage: self.name(),
                flags,
                bytes: buf.to_vec(),
            });
            if let Some(code) = self.fail {
                return Err(Error::new(code));
            }
            if self.forward {
                tail.write(ctx, flags, buf)
            } else {
                Ok(())
            }
        }

        fn close(&mut self, _ctx: &mut ClientCtx<'_>) {
            self.log.borrow_mut().closes.push(self.name());
        }

        fn is_paused(&self) -> bool {
            self.paused.get()
        }

        fn unpause(
            &mut self,
            _ctx: &mut ClientCtx<'_>,
            _tail: &mut WriterTail<'_, '_>,
        ) -> CurlResult<()> {
            self.log.borrow_mut().unpauses.push(self.name());
            self.paused.set(false);
            Ok(())
        }
    }

    /// What a recording reader answers with.
    #[derive(Clone, Debug)]
    enum ReaderBehaviour {
        /// Pull from the stage below -- the default body.
        Forward,
        /// Hand up these bytes, then report the end of the stream.
        Yield(Vec<u8>),
        /// Report the end of the stream at once.
        Eos,
        /// Fail with this code.
        Fail(CURLcode),
    }

    /// A reader stage that records what it was asked.
    #[derive(Debug)]
    struct RecordingReader {
        kind: ClientReaderKind,
        phase: ClientReaderPhase,
        log: SharedLog,
        behaviour: ReaderBehaviour,
        offset: usize,
        needs_rewind: bool,
        paused: bool,
        length: Option<i64>,
        control_fail: Option<CURLcode>,
    }

    impl RecordingReader {
        fn new(
            kind: ClientReaderKind,
            phase: ClientReaderPhase,
            log: &SharedLog,
        ) -> Self {
            Self {
                kind,
                phase,
                log: Rc::clone(log),
                behaviour: ReaderBehaviour::Forward,
                offset: 0,
                needs_rewind: false,
                paused: false,
                length: None,
                control_fail: None,
            }
        }

        fn boxed(self) -> Box<dyn ClientReader> {
            Box::new(self)
        }

        fn yielding(mut self, bytes: &[u8]) -> Self {
            self.behaviour = ReaderBehaviour::Yield(bytes.to_vec());
            self
        }

        fn at_eos(mut self) -> Self {
            self.behaviour = ReaderBehaviour::Eos;
            self
        }

        fn failing(mut self, code: CURLcode) -> Self {
            self.behaviour = ReaderBehaviour::Fail(code);
            self
        }

        fn with_length(mut self, length: i64) -> Self {
            self.length = Some(length);
            self
        }

        fn needing_rewind(mut self) -> Self {
            self.needs_rewind = true;
            self
        }

        fn paused(mut self) -> Self {
            self.paused = true;
            self
        }

        fn control_failing(mut self, code: CURLcode) -> Self {
            self.control_fail = Some(code);
            self
        }
    }

    impl ClientReader for RecordingReader {
        fn kind(&self) -> ClientReaderKind {
            self.kind
        }

        fn phase(&self) -> ClientReaderPhase {
            self.phase
        }

        fn read(
            &mut self,
            ctx: &mut ClientCtx<'_>,
            tail: &mut ReaderTail<'_, '_>,
            buf: &mut [u8],
        ) -> CurlResult<ReadOutcome> {
            self.log.borrow_mut().reads.push(ReadRecord {
                stage: self.name(),
                asked: buf.len(),
            });
            match &self.behaviour {
                ReaderBehaviour::Forward => tail.read(ctx, buf),
                ReaderBehaviour::Eos => Ok(ReadOutcome::EOS),
                ReaderBehaviour::Fail(code) => Err(Error::new(*code)),
                ReaderBehaviour::Yield(bytes) => {
                    let available = bytes.len() - self.offset;
                    if available == 0 {
                        return Ok(ReadOutcome::EOS);
                    }
                    let count = available.min(buf.len());
                    buf[..count].copy_from_slice(
                        &bytes[self.offset..self.offset + count],
                    );
                    self.offset += count;
                    Ok(ReadOutcome::new(count, self.offset == bytes.len()))
                }
            }
        }

        fn close(&mut self, _ctx: &mut ClientCtx<'_>) {
            self.log.borrow_mut().closes.push(self.name());
        }

        fn needs_rewind(&self) -> bool {
            self.needs_rewind
        }

        fn total_length(&self, below: &ReaderQuery<'_, '_>) -> i64 {
            match self.length {
                Some(length) => length,
                None => below.total_length(),
            }
        }

        fn control(
            &mut self,
            _ctx: &mut ClientCtx<'_>,
            control: ReaderControl,
        ) -> CurlResult<()> {
            self.log.borrow_mut().controls.push((self.name(), control));
            match self.control_fail {
                None => {
                    if control == ReaderControl::Unpause {
                        self.paused = false;
                    }
                    Ok(())
                }
                Some(code) => Err(Error::new(code)),
            }
        }

        fn is_paused(&self) -> bool {
            self.paused
        }

        fn done(&mut self, _ctx: &mut ClientCtx<'_>, premature: bool) {
            self.log.borrow_mut().dones.push((self.name(), premature));
        }
    }

    /// One scripted answer from an input source.
    #[derive(Clone, Debug)]
    enum Step {
        /// Write these bytes and report their count.
        Data(&'static [u8]),
        /// Report this count WITHOUT writing anything -- the shape the C's
        /// *"read function returned funny value"* check exists for.
        Claim(usize),
        /// `CURL_READFUNC_ABORT`.
        Abort,
        /// `CURL_READFUNC_PAUSE`.
        Pause,
    }

    /// The mutable half of a [`ScriptSource`], shared between every handle onto
    /// it.
    ///
    /// [`ClientIoFactory::input_source`] must hand out handles onto ONE stream,
    /// because the C copies a function pointer and a client-data pointer that
    /// both denote one `FILE *`. Keeping the state behind an [`Rc`] is how this
    /// double honours that.
    #[derive(Debug, Default)]
    struct SourceState {
        script: VecDeque<Step>,
        /// The destination lengths the source was handed, in order.
        asked: Vec<usize>,
        /// How [`ClientReadSource::seek_to_start`] answers: [`None`] for "not
        /// the default source", `Some(true)` for success, `Some(false)` for a
        /// failure.
        seek_to_start: Option<bool>,
        /// How many times [`ClientReadSource::seek_to_start`] was called.
        seeks: usize,
    }

    #[derive(Clone, Debug, Default)]
    struct ScriptSource {
        state: Rc<RefCell<SourceState>>,
    }

    impl ScriptSource {
        fn new(steps: &[Step]) -> Self {
            Self {
                state: Rc::new(RefCell::new(SourceState {
                    script: steps.iter().cloned().collect(),
                    ..SourceState::default()
                })),
            }
        }

        fn seekable(self, ok: bool) -> Self {
            self.state.borrow_mut().seek_to_start = Some(ok);
            self
        }

        fn asked(&self) -> Vec<usize> {
            self.state.borrow().asked.clone()
        }

        fn seeks(&self) -> usize {
            self.state.borrow().seeks
        }

        fn boxed(&self) -> Box<dyn ClientReadSource> {
            Box::new(self.clone())
        }
    }

    impl ClientReadSource for ScriptSource {
        fn read(&mut self, buf: &mut [u8]) -> SourceRead {
            let mut state = self.state.borrow_mut();
            state.asked.push(buf.len());
            match state.script.pop_front() {
                // An exhausted script is the end of the file, which is what
                // `fread` reports once it has nothing left.
                None => SourceRead::Bytes(0),
                Some(Step::Data(bytes)) => {
                    assert!(
                        bytes.len() <= buf.len(),
                        "a scripted Data step must fit the destination it is \
                         handed: {} bytes into {}",
                        bytes.len(),
                        buf.len()
                    );
                    buf[..bytes.len()].copy_from_slice(bytes);
                    SourceRead::Bytes(bytes.len())
                }
                Some(Step::Claim(count)) => SourceRead::Bytes(count),
                Some(Step::Abort) => SourceRead::Abort,
                Some(Step::Pause) => SourceRead::Pause,
            }
        }

        fn seek_to_start(&mut self) -> Option<std::io::Result<()>> {
            let mut state = self.state.borrow_mut();
            state.seeks += 1;
            match state.seek_to_start {
                None => None,
                Some(true) => Some(Ok(())),
                Some(false) => Some(Err(std::io::Error::other("no rewind"))),
            }
        }
    }

    /// A scripted `CURLOPT_SEEKFUNCTION`.
    #[derive(Debug)]
    struct ScriptSeek {
        answers: VecDeque<SeekOutcome>,
        fallback: SeekOutcome,
        calls: Vec<(i64, SeekOrigin)>,
    }

    impl ScriptSeek {
        fn always(outcome: SeekOutcome) -> Self {
            Self {
                answers: VecDeque::new(),
                fallback: outcome,
                calls: Vec::new(),
            }
        }
    }

    impl SeekCallback for ScriptSeek {
        fn seek(&mut self, offset: i64, origin: SeekOrigin) -> SeekOutcome {
            self.calls.push((offset, origin));
            self.answers.pop_front().unwrap_or(self.fallback)
        }
    }

    /// A scripted `CURLOPT_IOCTLFUNCTION`.
    #[derive(Debug)]
    struct ScriptIoctl {
        outcome: IoOutcome,
        calls: Vec<IoCmd>,
    }

    impl ScriptIoctl {
        fn always(outcome: IoOutcome) -> Self {
            Self {
                outcome,
                calls: Vec::new(),
            }
        }
    }

    impl IoctlCallback for ScriptIoctl {
        fn ioctl(&mut self, cmd: IoCmd) -> IoOutcome {
            self.calls.push(cmd);
            self.outcome
        }
    }

    /// The transfer engine's three operations, recorded.
    #[derive(Debug, Default)]
    struct TestControl {
        stream_closes: Vec<&'static str>,
        conn_closes: Vec<&'static str>,
        pauses: Vec<bool>,
        /// Every `Curl_xfer_pause_recv`, kept apart from the send direction
        /// because the two are different operations on different chains.
        recv_pauses: Vec<bool>,
        pause_fail: Option<CURLcode>,
    }

    impl TransferControl for TestControl {
        fn stream_close(&mut self, reason: &'static str) {
            self.stream_closes.push(reason);
        }

        fn conn_close(&mut self, reason: &'static str) {
            self.conn_closes.push(reason);
        }

        fn pause_send(&mut self, pause: bool) -> CurlResult<()> {
            self.pauses.push(pause);
            match self.pause_fail {
                None => Ok(()),
                Some(code) => Err(Error::new(code)),
            }
        }

        fn pause_recv(&mut self, pause: bool) -> CurlResult<()> {
            self.recv_pauses.push(pause);
            match self.pause_fail {
                None => Ok(()),
                Some(code) => Err(Error::new(code)),
            }
        }
    }

    /// The in-callback flag, with every transition recorded.
    ///
    /// [`Self::depth`] must be back at zero after every operation, and must
    /// never go negative or above one: the flag is a boolean in the C, and a
    /// nested raise would mean a callback was entered twice without leaving.
    #[derive(Debug, Default)]
    struct TestGuard {
        transitions: Vec<bool>,
        depth: i32,
        peak: i32,
    }

    impl TestGuard {
        fn balanced(&self) -> bool {
            self.depth == 0
        }

        fn entries(&self) -> usize {
            self.transitions.iter().filter(|raised| **raised).count()
        }
    }

    impl ClientCallbackGuard for TestGuard {
        fn set_in_callback(&mut self, inside: bool) {
            self.transitions.push(inside);
            self.depth += if inside { 1 } else { -1 };
            assert!(
                self.depth >= 0,
                "the in-callback flag was lowered without being raised"
            );
            self.peak = self.peak.max(self.depth);
        }
    }

    /// Every diagnostic, kept as rendered text.
    #[derive(Debug, Default)]
    struct TestTrace {
        debug: Vec<(TraceDataKind, Vec<u8>)>,
        writes: Vec<String>,
        reads: Vec<String>,
        fails: Vec<String>,
        infos: Vec<String>,
    }

    impl TestTrace {
        fn saw_read(&self, needle: &str) -> bool {
            self.reads.iter().any(|line| line.contains(needle))
        }

        fn saw_write(&self, needle: &str) -> bool {
            self.writes.iter().any(|line| line.contains(needle))
        }
    }

    impl TraceSink for TestTrace {
        fn debug(&mut self, kind: TraceDataKind, bytes: &[u8]) {
            self.debug.push((kind, bytes.to_vec()));
        }

        fn trace_write(&mut self, line: fmt::Arguments<'_>) {
            self.writes.push(line.to_string());
        }

        fn trace_read(&mut self, line: fmt::Arguments<'_>) {
            self.reads.push(line.to_string());
        }

        fn failf(&mut self, line: fmt::Arguments<'_>) {
            self.fails.push(line.to_string());
        }

        fn infof(&mut self, line: fmt::Arguments<'_>) {
            self.infos.push(line.to_string());
        }
    }

    /// The two writer stages `transfer/writeout.rs` owns, plus the default
    /// input source.
    #[derive(Debug)]
    struct TestFactory {
        log: SharedLog,
        source: Option<ScriptSource>,
        paused: Rc<Cell<bool>>,
        out_init_fail: Option<CURLcode>,
        pause_init_fail: Option<CURLcode>,
    }

    impl TestFactory {
        fn new(log: &SharedLog) -> Self {
            Self {
                log: Rc::clone(log),
                source: None,
                paused: Rc::new(Cell::new(false)),
                out_init_fail: None,
                pause_init_fail: None,
            }
        }

        fn with_source(mut self, source: &ScriptSource) -> Self {
            self.source = Some(source.clone());
            self
        }

        fn pause_init_failing(mut self, code: CURLcode) -> Self {
            self.pause_init_fail = Some(code);
            self
        }

        fn out_init_failing(mut self, code: CURLcode) -> Self {
            self.out_init_fail = Some(code);
            self
        }
    }

    impl<'data> ClientIoFactory<'data> for TestFactory {
        fn client_out_writer(&self) -> Box<dyn ClientWriter + 'data> {
            let mut writer =
                RecordingWriter::sink(ClientWriterKind::ClientOut, &self.log)
                    .with_paused(&self.paused);
            writer.init_fail = self.out_init_fail;
            Box::new(writer)
        }

        fn pause_writer(&self) -> Box<dyn ClientWriter + 'data> {
            let mut writer = RecordingWriter::new(
                ClientWriterKind::Pause,
                ClientWriterPhase::Protocol,
                &self.log,
            );
            writer.init_fail = self.pause_init_fail;
            Box::new(writer)
        }

        fn input_source(&self) -> Option<Box<dyn ClientReadSource + 'data>> {
            self.source.as_ref().map(|source| {
                Box::new(source.clone()) as Box<dyn ClientReadSource + 'data>
            })
        }
    }

    /// Everything a [`ClientCtx`] borrows, owned in one place.
    #[derive(Debug)]
    struct Env {
        write: RequestWriteState,
        read: RequestReadState,
        config: ClientConfig,
        progress: Progress,
        clock: TestClock,
        control: TestControl,
        guard: TestGuard,
        trace: TestTrace,
    }

    impl Env {
        /// An environment at a pinned instant, with every setting at its
        /// default.
        fn new() -> Self {
            Self {
                write: RequestWriteState::default(),
                read: RequestReadState::default(),
                config: ClientConfig::default(),
                progress: Progress::default(),
                clock: TestClock::new(CurlTime::new(1_000, 0)),
                control: TestControl::default(),
                guard: TestGuard::default(),
                trace: TestTrace::default(),
            }
        }

        /// A context over this environment.
        ///
        /// Destructured rather than reached through `self`, so that the shared
        /// borrow of the settings and the mutable borrows of the state are
        /// disjoint field borrows rather than two borrows of the whole
        /// environment.
        fn ctx(&mut self) -> ClientCtx<'_> {
            let Self {
                write,
                read,
                config,
                progress,
                clock,
                control,
                guard,
                trace,
            } = self;
            ClientCtx::new(
                write, read, &*config, progress, &*clock, control, guard,
            )
            .with_trace(trace)
        }

        /// A context with NO trace sink installed.
        ///
        /// The configuration a transfer that is not tracing runs in, and the
        /// one in which every `CURL_TRC_*` macro in `lib/sendf.c` expands to
        /// nothing. Worth driving on its own because the emitters are the only
        /// members of [`ClientCtx`] with a branch in them.
        fn untraced_ctx(&mut self) -> ClientCtx<'_> {
            let Self {
                write,
                read,
                config,
                progress,
                clock,
                control,
                guard,
                ..
            } = self;
            ClientCtx::new(
                write, read, &*config, progress, &*clock, control, guard,
            )
        }
    }

    /// An empty writer tail, for driving a stage in isolation.
    fn no_writers() -> [Box<dyn ClientWriter>; 0] {
        []
    }

    /// An empty reader tail, for driving a stage in isolation.
    fn no_readers() -> [Box<dyn ClientReader>; 0] {
        []
    }

    // -- the write-flag vocabulary ----------------------------------------

    /// Every bit is the integer `lib/sendf.h:42-50` defines, and the masks are
    /// their unions.
    #[test]
    fn write_flag_bits_are_the_c_macros() {
        assert_eq!(ClientWriteFlags::NONE.bits(), 0);
        assert_eq!(ClientWriteFlags::BODY.bits(), 1 << 0);
        assert_eq!(ClientWriteFlags::INFO.bits(), 1 << 1);
        assert_eq!(ClientWriteFlags::HEADER.bits(), 1 << 2);
        assert_eq!(ClientWriteFlags::STATUS.bits(), 1 << 3);
        assert_eq!(ClientWriteFlags::CONNECT.bits(), 1 << 4);
        assert_eq!(ClientWriteFlags::ONE_XX.bits(), 1 << 5);
        assert_eq!(ClientWriteFlags::TRAILER.bits(), 1 << 6);
        assert_eq!(ClientWriteFlags::EOS.bits(), 1 << 7);
        assert_eq!(ClientWriteFlags::ZERO_LEN.bits(), 1 << 8);

        assert_eq!(ClientWriteFlags::CLASS_MASK.bits(), 0b0000_0111);
        assert_eq!(ClientWriteFlags::HEADER_QUALIFIERS.bits(), 0b0111_1000);
        assert_eq!(ClientWriteFlags::ALL.bits(), 0b1_1111_1111);

        // The two directions of the boundary conversion agree.
        for bit in 0..12_u32 {
            let flags = ClientWriteFlags::from_bits(1 << bit);
            assert_eq!(flags.bits(), 1 << bit);
        }
    }

    /// The three invariants of `lib/sendf.c:380-388`, each exercised in both
    /// directions.
    #[test]
    fn write_flag_invariants_match_curl_client_write() {
        // At least one class.
        assert!(!ClientWriteFlags::NONE.is_valid());
        assert!(!ClientWriteFlags::EOS.is_valid());
        assert!(!ClientWriteFlags::STATUS.is_valid());

        // BODY alone, and BODY with EOS.
        assert!(ClientWriteFlags::BODY.is_valid());
        assert!((ClientWriteFlags::BODY | ClientWriteFlags::EOS).is_valid());
        // BODY with anything else.
        assert!(!(ClientWriteFlags::BODY | ClientWriteFlags::HEADER).is_valid());
        assert!(!(ClientWriteFlags::BODY | ClientWriteFlags::INFO).is_valid());
        assert!(
            !(ClientWriteFlags::BODY | ClientWriteFlags::ZERO_LEN).is_valid(),
            "BODY | 0LEN fails invariant 2, which is why lib/ws.c:703 calls \
             the chain directly rather than through client_write"
        );

        // INFO alone, and INFO with EOS.
        assert!(ClientWriteFlags::INFO.is_valid());
        assert!((ClientWriteFlags::INFO | ClientWriteFlags::EOS).is_valid());
        assert!(!(ClientWriteFlags::INFO | ClientWriteFlags::HEADER).is_valid());

        // HEADER may carry every qualifier, and EOS besides.
        assert!(ClientWriteFlags::HEADER.is_valid());
        for qualifier in [
            ClientWriteFlags::STATUS,
            ClientWriteFlags::CONNECT,
            ClientWriteFlags::ONE_XX,
            ClientWriteFlags::TRAILER,
            ClientWriteFlags::EOS,
            ClientWriteFlags::ZERO_LEN,
        ] {
            assert!((ClientWriteFlags::HEADER | qualifier).is_valid());
        }
        assert!(ClientWriteFlags::HEADER
            .union(ClientWriteFlags::HEADER_QUALIFIERS)
            .is_valid());

        // A bit outside the vocabulary, which the C's assertions cannot see.
        assert!(!ClientWriteFlags::from_bits((1 << 9) | 1).is_valid());
    }

    /// The set operations, and the class projection the trace lines use.
    #[test]
    fn write_flag_set_operations() {
        let both = ClientWriteFlags::HEADER | ClientWriteFlags::STATUS;
        assert!(both.contains(ClientWriteFlags::HEADER));
        assert!(both.contains(ClientWriteFlags::STATUS));
        assert!(both.contains(both));
        assert!(!both.contains(ClientWriteFlags::BODY));

        // `contains` is the conjunction, `intersects` the disjunction, and the
        // difference between them is load-bearing at `lib/sendf.c:186`.
        let pair = ClientWriteFlags::INFO | ClientWriteFlags::CONNECT;
        assert!(!ClientWriteFlags::CONNECT.contains(pair));
        assert!(ClientWriteFlags::CONNECT.intersects(pair));

        assert_eq!(
            both.difference(ClientWriteFlags::STATUS),
            ClientWriteFlags::HEADER
        );
        assert!(ClientWriteFlags::NONE.is_empty());
        assert!(!both.is_empty());
        assert_eq!(both.class(), ClientWriteFlags::HEADER);
        assert_eq!(
            (ClientWriteFlags::BODY | ClientWriteFlags::EOS).class(),
            ClientWriteFlags::BODY
        );

        let mut accumulating = ClientWriteFlags::BODY;
        accumulating |= ClientWriteFlags::EOS;
        assert_eq!(
            accumulating,
            ClientWriteFlags::BODY | ClientWriteFlags::EOS
        );
    }

    /// The rendering is `%x`: bare lowercase hexadecimal, as the C's trace
    /// lines print it.
    #[test]
    fn write_flags_render_as_hex() {
        assert_eq!(ClientWriteFlags::BODY.to_string(), "1");
        assert_eq!(ClientWriteFlags::ZERO_LEN.to_string(), "100");
        assert_eq!(
            (ClientWriteFlags::HEADER | ClientWriteFlags::CONNECT).to_string(),
            "14"
        );
    }

    // -- the phase and identity tables ------------------------------------

    /// Both phase enumerations are ordered as the C declares them, and the
    /// derived ordering is what the insertion rule compares.
    #[test]
    fn phases_are_ordered_as_the_c_declares_them() {
        assert_eq!(ClientWriterPhase::VARIANTS.len(), 5);
        assert!(
            ClientWriterPhase::Raw < ClientWriterPhase::TransferDecode
                && ClientWriterPhase::TransferDecode
                    < ClientWriterPhase::Protocol
                && ClientWriterPhase::Protocol
                    < ClientWriterPhase::ContentDecode
                && ClientWriterPhase::ContentDecode < ClientWriterPhase::Client
        );
        assert_eq!(
            ClientWriterPhase::VARIANTS.map(ClientWriterPhase::c_name),
            [
                "CURL_CW_RAW",
                "CURL_CW_TRANSFER_DECODE",
                "CURL_CW_PROTOCOL",
                "CURL_CW_CONTENT_DECODE",
                "CURL_CW_CLIENT",
            ]
        );

        assert_eq!(ClientReaderPhase::VARIANTS.len(), 5);
        assert!(
            ClientReaderPhase::Net < ClientReaderPhase::TransferEncode
                && ClientReaderPhase::TransferEncode
                    < ClientReaderPhase::Protocol
                && ClientReaderPhase::Protocol
                    < ClientReaderPhase::ContentEncode
                && ClientReaderPhase::ContentEncode < ClientReaderPhase::Client
        );
        assert_eq!(
            ClientReaderPhase::VARIANTS.map(ClientReaderPhase::c_name),
            [
                "CURL_CR_NET",
                "CURL_CR_TRANSFER_ENCODE",
                "CURL_CR_PROTOCOL",
                "CURL_CR_CONTENT_ENCODE",
                "CURL_CR_CLIENT",
            ]
        );
    }

    /// Every stage name is the string the corresponding `struct Curl_cwtype` or
    /// `struct Curl_crtype` holds, and the two aliases are the only two.
    #[test]
    fn stage_names_are_the_c_names() {
        let writers = [
            (ClientWriterKind::Raw, "raw", None),
            (ClientWriterKind::Download, "protocol", None),
            (ClientWriterKind::ClientOut, "cw-out", None),
            (ClientWriterKind::Pause, "cw-pause", None),
            (ClientWriterKind::ChunkedDecode, "chunked", None),
            (ClientWriterKind::Deflate, "deflate", None),
            (ClientWriterKind::Gzip, "gzip", Some("x-gzip")),
            (ClientWriterKind::Brotli, BROTLI_STAGE_NAME, None),
            (ClientWriterKind::Zstd, "zstd", None),
            (ClientWriterKind::Identity, "identity", Some("none")),
            (ClientWriterKind::ContentEncodingError, "ce-error", None),
            (ClientWriterKind::HeaderCollect, "hds-collect", None),
            (ClientWriterKind::WebSocketDecode, "ws-decode", None),
            (ClientWriterKind::FtpLineConv, "ftp-lineconv", None),
            (ClientWriterKind::Custom("double"), "double", None),
        ];
        assert_eq!(
            BROTLI_STAGE_NAME.as_bytes(),
            [b'b', b'r'],
            "the escaped spelling must be the two bytes curl registers"
        );
        for (kind, name, alias) in writers {
            assert_eq!(kind.name(), name);
            assert_eq!(kind.alias(), alias);
            assert_eq!(kind.to_string(), name);
        }

        let readers = [
            (ClientReaderKind::Input, "cr-in"),
            (ClientReaderKind::LineConv, "cr-lineconv"),
            (ClientReaderKind::Null, "cr-null"),
            (ClientReaderKind::Buf, "cr-buf"),
            (ClientReaderKind::Mime, "cr-mime"),
            (ClientReaderKind::ChunkedEncode, "chunked"),
            (ClientReaderKind::WebSocketEncode, "ws-encode"),
            (ClientReaderKind::Custom("double"), "double"),
        ];
        for (kind, name) in readers {
            assert_eq!(kind.name(), name);
            assert_eq!(kind.to_string(), name);
        }
    }

    /// The reader-control vocabulary is the C's three opcodes.
    #[test]
    fn reader_control_names_are_the_c_names() {
        assert_eq!(ReaderControl::VARIANTS.len(), 3);
        assert_eq!(
            ReaderControl::VARIANTS.map(ReaderControl::c_name),
            [
                "CURL_CRCNTRL_REWIND",
                "CURL_CRCNTRL_UNPAUSE",
                "CURL_CRCNTRL_CLEAR_EOS",
            ]
        );
    }

    /// The two callback outcome enumerations carry the integers the public
    /// header assigns.
    #[test]
    fn callback_outcomes_carry_the_header_integers() {
        assert_eq!(SeekOutcome::Ok.as_i32(), 0);
        assert_eq!(SeekOutcome::CantSeek.as_i32(), 2);
        assert_eq!(SeekOutcome::Failed(1).as_i32(), 1);
        assert_eq!(SeekOutcome::Failed(-7).as_i32(), -7);
        assert!(!SeekOutcome::Ok.is_nonzero());
        assert!(SeekOutcome::CantSeek.is_nonzero());
        assert!(SeekOutcome::Failed(1).is_nonzero());
        assert!(!SeekOutcome::Failed(0).is_nonzero());

        assert_eq!(IoOutcome::Ok.as_i32(), 0);
        assert_eq!(IoOutcome::UnknownCmd.as_i32(), 1);
        assert_eq!(IoOutcome::FailRestart.as_i32(), 2);
    }

    /// The shared buffer ceilings are unchanged, and they are consumed from
    /// [`crate::util::dynbuf`] rather than restated here.
    #[test]
    fn the_shared_buffer_ceilings_are_unchanged() {
        assert_eq!(DYN_HTTP_REQUEST, 1024 * 1024);
        assert_eq!(DYN_PAUSE_BUFFER, 64 * 1024 * 1024);
        // And the two sizes this module DOES own.
        assert_eq!(RESUME_SCRATCH_LEN, 4 * 1024);
        assert_eq!(LINECONV_CHUNK_LEN, 16 * 1024);
        assert_eq!(LINECONV_CHUNKS, 1);
    }

    /// `curlx_sotouz_range` (`lib/curlx/warnless.c:286-295`), branch for
    /// branch.
    #[test]
    fn saturating_range_conversion_matches_warnless() {
        assert_eq!(so_to_usize_range(50, 10, 100), 50);
        assert_eq!(so_to_usize_range(10, 10, 100), 10);
        assert_eq!(so_to_usize_range(100, 10, 100), 100);
        // Below the floor and above the ceiling.
        assert_eq!(so_to_usize_range(9, 10, 100), 10);
        assert_eq!(so_to_usize_range(101, 10, 100), 100);
        assert_eq!(so_to_usize_range(i64::MAX, 10, 100), 100);
        // Negative yields the floor, whatever its magnitude.
        assert_eq!(so_to_usize_range(-1, 10, 100), 10);
        assert_eq!(so_to_usize_range(i64::MIN, 10, 100), 10);
        // The C applies the maximum first, so an inverted range yields the
        // ceiling.
        assert_eq!(so_to_usize_range(50, 100, 10), 10);
        assert_eq!(so_to_usize_range(0, 0, usize::MAX), 0);
    }

    // -- the writer chain -------------------------------------------------

    /// Stages sort by phase, whatever order they are added in.
    #[test]
    fn writer_insertion_orders_by_phase() {
        let recorder = log();
        let mut stack = ClientWriterStack::new();
        // Added in reverse phase order, deliberately.
        for (kind, phase) in [
            (ClientWriterKind::ClientOut, ClientWriterPhase::Client),
            (ClientWriterKind::Gzip, ClientWriterPhase::ContentDecode),
            (ClientWriterKind::Download, ClientWriterPhase::Protocol),
            (
                ClientWriterKind::ChunkedDecode,
                ClientWriterPhase::TransferDecode,
            ),
            (ClientWriterKind::Raw, ClientWriterPhase::Raw),
        ] {
            stack.insert(RecordingWriter::new(kind, phase, &recorder).boxed());
        }
        assert_eq!(
            stack.names(),
            vec!["raw", "chunked", "protocol", "gzip", "cw-out"]
        );
        assert_eq!(stack.len(), 5);
        assert!(!stack.is_empty());
    }

    /// Within one phase, the LAST added runs FIRST -- which is how
    /// `lib/content_encoding.c` unwinds a coding list in reverse.
    #[test]
    fn writer_insertion_is_first_within_its_phase() {
        let recorder = log();
        let mut stack = ClientWriterStack::new();
        for kind in [
            ClientWriterKind::Gzip,
            ClientWriterKind::Brotli,
            ClientWriterKind::Zstd,
        ] {
            stack.insert(
                RecordingWriter::new(
                    kind,
                    ClientWriterPhase::ContentDecode,
                    &recorder,
                )
                .boxed(),
            );
        }
        assert_eq!(stack.names(), vec!["zstd", BROTLI_STAGE_NAME, "gzip"]);
        assert_eq!(stack.count(ClientWriterPhase::ContentDecode), 3);
        assert_eq!(stack.count(ClientWriterPhase::Protocol), 0);
    }

    /// A write into an empty chain is exactly
    /// [`CURLcode::WriteError`] -- the C's `if(!writer)`.
    #[test]
    fn writing_into_an_empty_chain_is_a_write_error() {
        let mut env = Env::new();
        let mut ctx = env.ctx();
        let mut stack = ClientWriterStack::new();
        let error = stack
            .write(&mut ctx, ClientWriteFlags::BODY, b"x")
            .expect_err("an empty chain cannot accept a write");
        assert_eq!(error.code(), CURLcode::WriteError);

        // And the tail's own empty form answers the same.
        let mut tail = WriterTail::empty();
        assert!(tail.is_empty());
        assert_eq!(tail.len(), 0);
        assert_eq!(
            tail.write(&mut ctx, ClientWriteFlags::BODY, b"x")
                .expect_err("an empty tail is a write error")
                .code(),
            CURLcode::WriteError
        );
    }

    /// The default `write` body forwards the bytes and the flags unchanged.
    #[test]
    fn the_default_writer_forwards_unchanged() {
        /// A stage with no `write` at all, so the default body runs.
        #[derive(Debug)]
        struct Passive;
        impl ClientWriter for Passive {
            fn kind(&self) -> ClientWriterKind {
                ClientWriterKind::Custom("passive")
            }
            fn phase(&self) -> ClientWriterPhase {
                ClientWriterPhase::Raw
            }
        }

        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientWriterStack::new();
        stack.insert(
            RecordingWriter::sink(ClientWriterKind::ClientOut, &recorder)
                .boxed(),
        );
        stack.insert(Box::new(Passive));
        assert_eq!(stack.names(), vec!["passive", "cw-out"]);

        let flags = ClientWriteFlags::HEADER | ClientWriteFlags::STATUS;
        stack
            .write(&mut env.ctx(), flags, b"HTTP/1.1 200 OK\r\n")
            .expect("the sink accepts everything");
        assert_eq!(
            recorder.borrow().writes,
            vec![WriteRecord {
                stage: "cw-out",
                flags,
                bytes: b"HTTP/1.1 200 OK\r\n".to_vec(),
            }]
        );
    }

    /// The base stack is `raw`, `protocol`, `cw-pause`, `cw-out`, and the pause
    /// stage is BEHIND the download stage although it was installed first.
    #[test]
    fn the_base_writer_stack_is_raw_protocol_pause_out() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        io.init_writers(&mut env.ctx())
            .expect("the base stack builds");

        assert_eq!(
            io.writers().names(),
            vec!["raw", "protocol", "cw-pause", "cw-out"],
            "lib/sendf.c:325-368 installs cw-out, then cw-pause, then the \
             download stage, then raw -- and insert-first-in-phase puts the \
             download stage AHEAD of the pause stage"
        );
        // Construction order, which is the reverse question and is what the
        // stages' own initialisation records.
        assert_eq!(recorder.borrow().inits, vec!["cw-out", "cw-pause"]);
        assert_eq!(io.writers().count(ClientWriterPhase::Protocol), 2);
        assert_eq!(io.writers().count(ClientWriterPhase::Client), 1);
        assert_eq!(io.writers().count(ClientWriterPhase::Raw), 1);

        // A second call is a no-op rather than a second base stack.
        io.init_writers(&mut env.ctx()).expect("idempotent");
        assert_eq!(io.writers().len(), 4);
    }

    /// Adding to an empty chain builds the base stack FIRST, so a decoder
    /// installed before any write still has the four standard stages beneath
    /// it.
    #[test]
    fn adding_to_an_empty_chain_builds_the_base_stack_first() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        io.add_writer(
            RecordingWriter::new(
                ClientWriterKind::Gzip,
                ClientWriterPhase::ContentDecode,
                &recorder,
            )
            .boxed(),
            &mut env.ctx(),
        )
        .expect("the base stack builds and the decoder is inserted");
        assert_eq!(
            io.writers().names(),
            vec!["raw", "protocol", "cw-pause", "gzip", "cw-out"]
        );
        assert!(io.writers().is_content_decoding());
    }

    /// A factory stage whose initialisation fails leaves the stages installed
    /// BEFORE it standing, and a later write goes through that partial chain.
    ///
    /// This is `lib/sendf.c`'s behaviour, not a simplification of it: each of
    /// the builder's three later steps reads `if(result) return result` with
    /// nothing between it and the return (`:346-347`, `:355-356`, `:364-365`),
    /// so `data->req.writer_stack` keeps pointing at the stages already
    /// installed and `Curl_client_write`'s `if(!data->req.writer_stack)`
    /// (`:390`) is then false. The stage that failed is freed by
    /// `Curl_cwriter_create` itself (`:426-427`) -- and freed WITHOUT its
    /// `do_close`, which is why nothing is recorded for it here.
    #[test]
    fn a_failed_base_stage_leaves_the_partial_chain() {
        let recorder = log();
        let factory =
            TestFactory::new(&recorder).pause_init_failing(CURLcode::TooLarge);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        let error = io
            .init_writers(&mut env.ctx())
            .expect_err("the pause stage refused to initialise");
        assert_eq!(error.code(), CURLcode::TooLarge);
        assert_eq!(
            io.writers().names(),
            vec!["cw-out"],
            "the client stage installed by step 1 is still there"
        );
        assert_eq!(
            recorder.borrow().inits,
            vec!["cw-out", "cw-pause"],
            "both were initialised; only the second one failed"
        );
        assert!(
            recorder.borrow().closes.is_empty(),
            "a stage that fails to initialise is freed without do_close"
        );

        // And the partial chain is USED rather than rebuilt, which is what the
        // C's non-null test at `:390` arranges.
        io.client_write(&mut env.ctx(), ClientWriteFlags::BODY, b"body")
            .expect("the partial chain writes");
        assert_eq!(io.writers().names(), vec!["cw-out"]);
        assert_eq!(
            recorder.borrow().writes.len(),
            1,
            "the one installed stage saw the body"
        );

        // The very first stage failing leaves nothing, because nothing had been
        // installed yet -- the C's `return result` at `:333-334`.
        let other =
            TestFactory::new(&recorder).out_init_failing(CURLcode::OutOfMemory);
        let mut io = ClientIo::new(&other);
        let mut env = Env::new();
        assert_eq!(
            io.init_writers(&mut env.ctx())
                .expect_err("the client stage refused to initialise")
                .code(),
            CURLcode::OutOfMemory
        );
        assert!(io.writers().is_empty());
    }

    /// `get_by_name` compares the NAME and never the alias;
    /// `get_by_kind` compares identity.
    #[test]
    fn writer_lookup_by_name_ignores_the_alias() {
        let recorder = log();
        let mut stack = ClientWriterStack::new();
        stack.insert(
            RecordingWriter::new(
                ClientWriterKind::Gzip,
                ClientWriterPhase::ContentDecode,
                &recorder,
            )
            .boxed(),
        );
        assert!(stack.get_by_name("gzip").is_some());
        assert!(
            stack.get_by_name("x-gzip").is_none(),
            "lib/sendf.c:478 compares cwt->name alone"
        );
        assert_eq!(
            stack
                .get_by_kind(ClientWriterKind::Gzip)
                .map(ClientWriter::alias),
            Some(Some("x-gzip"))
        );
        assert!(stack.get_by_kind(ClientWriterKind::Brotli).is_none());
    }

    /// `is_content_decoding` tests the PHASE, so the same decoder type at
    /// `TRANSFER_DECODE` does not count.
    #[test]
    fn is_content_decoding_tests_the_phase_not_the_kind() {
        let recorder = log();
        let mut stack = ClientWriterStack::new();
        assert!(!stack.is_content_decoding());
        stack.insert(
            RecordingWriter::new(
                ClientWriterKind::Gzip,
                ClientWriterPhase::TransferDecode,
                &recorder,
            )
            .boxed(),
        );
        assert!(!stack.is_content_decoding());
        stack.insert(
            RecordingWriter::new(
                ClientWriterKind::Gzip,
                ClientWriterPhase::ContentDecode,
                &recorder,
            )
            .boxed(),
        );
        assert!(stack.is_content_decoding());
    }

    /// The pause question and the flush are asked of every stage, which is what
    /// removes the C's reach into `lib/cw-out.c`.
    #[test]
    fn writer_is_paused_and_unpause() {
        let recorder = log();
        let paused = Rc::new(Cell::new(true));
        let mut env = Env::new();
        let mut stack = ClientWriterStack::new();
        stack.insert(
            RecordingWriter::sink(ClientWriterKind::ClientOut, &recorder)
                .with_paused(&paused)
                .boxed(),
        );
        stack.insert(
            RecordingWriter::new(
                ClientWriterKind::Raw,
                ClientWriterPhase::Raw,
                &recorder,
            )
            .boxed(),
        );

        assert!(stack.is_paused());
        stack.unpause(&mut env.ctx()).expect("nothing refuses");
        assert!(!stack.is_paused());
        assert_eq!(recorder.borrow().unpauses, vec!["raw", "cw-out"]);
    }

    /// `create` runs initialisation and destroys a stage that refuses; `free`
    /// closes one that is not in a chain.
    #[test]
    fn writer_create_and_free_run_the_lifecycle() {
        let recorder = log();
        let mut env = Env::new();

        let good = ClientWriterStack::create(
            RecordingWriter::new(
                ClientWriterKind::Raw,
                ClientWriterPhase::Raw,
                &recorder,
            )
            .boxed(),
            &mut env.ctx(),
        )
        .expect("initialisation succeeds");
        assert_eq!(good.name(), "raw");
        assert_eq!(recorder.borrow().inits, vec!["raw"]);

        ClientWriterStack::free(good, &mut env.ctx());
        assert_eq!(recorder.borrow().closes, vec!["raw"]);

        let refused = ClientWriterStack::create(
            RecordingWriter::new(
                ClientWriterKind::Brotli,
                ClientWriterPhase::ContentDecode,
                &recorder,
            )
            .init_failing(CURLcode::OutOfMemory)
            .boxed(),
            &mut env.ctx(),
        );
        assert_eq!(
            refused.expect_err("initialisation refused").code(),
            CURLcode::OutOfMemory
        );
        // Dropped rather than returned, so `close` never ran for it.
        assert_eq!(recorder.borrow().closes, vec!["raw"]);
    }

    /// The chain closes from the TOP down, so a stage that flushes on close
    /// still has the stages below it.
    ///
    /// Built from four recording doubles rather than from the base stack,
    /// because [`RawWriter`] and [`DownloadWriter`] use the default `close` --
    /// which does nothing and therefore records nothing.
    #[test]
    fn writer_clear_closes_from_the_top_down() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientWriterStack::new();
        for (kind, phase) in [
            (ClientWriterKind::ClientOut, ClientWriterPhase::Client),
            (ClientWriterKind::Pause, ClientWriterPhase::Protocol),
            (ClientWriterKind::Download, ClientWriterPhase::Protocol),
            (ClientWriterKind::Raw, ClientWriterPhase::Raw),
        ] {
            stack.insert(RecordingWriter::new(kind, phase, &recorder).boxed());
        }
        assert_eq!(
            stack.names(),
            vec!["raw", "protocol", "cw-pause", "cw-out"]
        );
        stack.clear(&mut env.ctx());
        assert_eq!(
            recorder.borrow().closes,
            vec!["raw", "protocol", "cw-pause", "cw-out"]
        );
        assert!(stack.is_empty());
    }

    /// The base stack's own teardown closes the two factory stages, which are
    /// the only two of the four that record anything.
    #[test]
    fn the_base_stack_tears_down_through_the_chain() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        io.init_writers(&mut env.ctx())
            .expect("the base stack builds");
        io.writers_mut().clear(&mut env.ctx());
        assert_eq!(recorder.borrow().closes, vec!["cw-pause", "cw-out"]);
        assert!(io.writers().is_empty());
    }

    /// A stage that fails stops the chain, and the stages below it are not
    /// reached.
    #[test]
    fn a_failing_writer_stops_the_chain() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientWriterStack::new();
        stack.insert(
            RecordingWriter::sink(ClientWriterKind::ClientOut, &recorder)
                .boxed(),
        );
        stack.insert(
            RecordingWriter::new(
                ClientWriterKind::Gzip,
                ClientWriterPhase::ContentDecode,
                &recorder,
            )
            .failing(CURLcode::WriteError)
            .boxed(),
        );
        let error = stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"body")
            .expect_err("the decoder refuses");
        assert_eq!(error.code(), CURLcode::WriteError);
        assert_eq!(
            recorder
                .borrow()
                .writes
                .iter()
                .map(|record| record.stage)
                .collect::<Vec<_>>(),
            vec!["gzip"]
        );
    }

    // -- the download stage -----------------------------------------------

    /// A chain of just the download stage over a recording sink.
    fn download_chain(
        recorder: &SharedLog,
    ) -> (ClientWriterStack<'static>, Rc<Cell<bool>>) {
        let paused = Rc::new(Cell::new(false));
        let mut stack = ClientWriterStack::new();
        stack.insert(
            RecordingWriter::sink(ClientWriterKind::ClientOut, recorder)
                .with_paused(&paused)
                .boxed(),
        );
        stack.insert(Box::new(DownloadWriter::new()));
        (stack, paused)
    }

    /// The bytes the sink received, concatenated.
    fn delivered(recorder: &SharedLog) -> Vec<u8> {
        recorder
            .borrow()
            .writes
            .iter()
            .filter(|record| record.stage == "cw-out")
            .flat_map(|record| record.bytes.clone())
            .collect()
    }

    /// The start-transfer timer is recorded on the first write that is neither
    /// informational nor a proxy header, and only once.
    #[test]
    fn download_writer_records_start_transfer_once() {
        let recorder = log();
        let (mut stack, _) = download_chain(&recorder);
        let mut env = Env::new();
        // The request origin, so that the accumulator has something to measure
        // from; then one second passes before the response arrives.
        env.progress
            .time_was(TimerId::StartSingle, CurlTime::new(1_000, 0));
        env.clock.advance(Duration::from_secs(1));

        // Informational and proxy writes do NOT start the clock.
        stack
            .write(&mut env.ctx(), ClientWriteFlags::INFO, b"220 ready\r\n")
            .expect("info is forwarded");
        stack
            .write(
                &mut env.ctx(),
                ClientWriteFlags::HEADER | ClientWriteFlags::CONNECT,
                b"HTTP/1.1 200\r\n",
            )
            .expect("a proxy header is forwarded");
        assert_eq!(env.progress.starttransfer_time_us(), 0);

        // A status line does.
        stack
            .write(
                &mut env.ctx(),
                ClientWriteFlags::HEADER | ClientWriteFlags::STATUS,
                b"HTTP/1.1 200 OK\r\n",
            )
            .expect("a status line is forwarded");
        assert_eq!(env.progress.starttransfer_time_us(), 1_000_000);

        // A second write does not move it, even a second later.
        env.clock.advance(Duration::from_secs(1));
        stack
            .write(&mut env.ctx(), ClientWriteFlags::HEADER, b"a: b\r\n")
            .expect("a header is forwarded");
        assert_eq!(env.progress.starttransfer_time_us(), 1_000_000);
    }

    /// Metadata is forwarded unchanged, and a proxy header is DROPPED when
    /// `--suppress-connect-headers` asked for that -- successfully, not as an
    /// error.
    #[test]
    fn download_writer_drops_suppressed_connect_headers() {
        let recorder = log();
        let mut env = Env::new();
        env.config.suppress_connect_headers = true;
        let (mut stack, _) = download_chain(&recorder);

        let connect = ClientWriteFlags::HEADER | ClientWriteFlags::CONNECT;
        stack
            .write(&mut env.ctx(), connect, b"Proxy-Agent: x\r\n")
            .expect("dropping is a success");
        stack
            .write(&mut env.ctx(), ClientWriteFlags::HEADER, b"a: b\r\n")
            .expect("an ordinary header is forwarded");

        assert_eq!(
            recorder
                .borrow()
                .writes
                .iter()
                .map(|record| record.bytes.clone())
                .collect::<Vec<_>>(),
            vec![b"a: b\r\n".to_vec()]
        );
        assert!(env.trace.saw_write("download_write header(type=4, blen=6)"));
    }

    /// The download rate limiter is started once, with the EXPECTED response
    /// length, on the first real body write.
    #[test]
    fn download_writer_starts_the_download_limiter_once() {
        let recorder = log();
        let mut env = Env::new();
        env.write.size = 4_096;
        let mut stage = DownloadWriter::new();
        let mut empty = no_writers();

        // A body write with no chain below it fails, which is beside the point
        // here: what matters is that the limiter was started first.
        let mut tail = WriterTail::new(&mut empty);
        let _ = stage.write(
            &mut env.ctx(),
            &mut tail,
            ClientWriteFlags::BODY,
            b"data",
        );
        assert!(stage.started_response());
        assert!(stage.started_body());
        drop(recorder);

        // `Curl_rlimit_start` on an unlimited limiter leaves it unlimited, so
        // the observable effect is the flag; a limited one is exercised by
        // `client_read_clamps_to_the_available_tokens` below.
        assert!(!env.progress.download().rlimit().is_active());
    }

    /// A body on a bodyless response fails when no headers arrived, and
    /// succeeds when they did -- and both mark the download done and retire the
    /// stream.
    #[test]
    fn download_writer_rejects_a_body_on_a_bodyless_response() {
        let recorder = log();
        let mut env = Env::new();
        env.write.no_body = true;
        let (mut stack, _) = download_chain(&recorder);

        let error = stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"surprise")
            .expect_err("no headers arrived, so the reply was weird");
        assert_eq!(error.code(), CURLcode::WeirdServerReply);
        assert!(env.write.download_done);
        assert_eq!(env.control.stream_closes, vec!["ignoring body"]);
        assert!(delivered(&recorder).is_empty());
        assert!(env.trace.saw_write("did not want a BODY"));

        // With headers received, the same situation is fine.
        let mut env = Env::new();
        env.write.no_body = true;
        env.write.header_size = 42;
        let (mut stack, _) = download_chain(&recorder);
        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"surprise")
            .expect("headers arrived, so the server answered");
        assert!(env.write.download_done);
        assert_eq!(env.control.stream_closes, vec!["ignoring body"]);

        // An EMPTY body write on a bodyless response is not a body at all and
        // takes neither branch.
        let mut env = Env::new();
        env.write.no_body = true;
        let (mut stack, _) = download_chain(&recorder);
        stack
            .write(
                &mut env.ctx(),
                ClientWriteFlags::BODY | ClientWriteFlags::EOS,
                b"",
            )
            .expect("an empty body is not a body");
        assert!(env.control.stream_closes.is_empty());
    }

    /// The protocol's maximum clamps the write, reports the excess and retires
    /// the connection -- and still SUCCEEDS.
    #[test]
    fn download_writer_clamps_to_maxdownload_and_reports_the_excess() {
        let recorder = log();
        let mut env = Env::new();
        env.write.size = 4;
        env.write.maxdownload = 4;
        let (mut stack, _) = download_chain(&recorder);

        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"0123456789")
            .expect("an excess is reported, not returned");
        assert_eq!(delivered(&recorder), b"0123".to_vec());
        assert_eq!(env.write.bytecount, 4);
        assert!(env.write.download_done);
        assert_eq!(env.control.conn_closes, vec!["excess found in a read"]);
        assert!(env.trace.infos.iter().any(|line| {
            line.contains("Excess found writing body: excess = 6")
        }));
        // The user's limit was never involved, so no error came back.
        assert!(env.trace.fails.is_empty());
    }

    /// Reaching the maximum EXACTLY marks the download done without reporting
    /// an excess.
    #[test]
    fn download_writer_marks_done_when_maxdownload_is_exactly_reached() {
        let recorder = log();
        let mut env = Env::new();
        env.write.size = 4;
        env.write.maxdownload = 4;
        let (mut stack, _) = download_chain(&recorder);
        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"0123")
            .expect("exactly the permitted amount");
        assert_eq!(delivered(&recorder), b"0123".to_vec());
        assert!(env.write.download_done);
        assert!(env.control.conn_closes.is_empty());
    }

    /// The end of the stream with the declared length unmet is
    /// [`CURLcode::PartialFile`], and nothing is written.
    #[test]
    fn download_writer_reports_a_truncated_response() {
        let recorder = log();
        let mut env = Env::new();
        env.write.size = 10;
        env.write.maxdownload = 10;
        let (mut stack, _) = download_chain(&recorder);

        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"012")
            .expect("the first three bytes are fine");
        assert_eq!(env.write.bytecount, 3);

        let error = stack
            .write(
                &mut env.ctx(),
                ClientWriteFlags::BODY | ClientWriteFlags::EOS,
                b"345",
            )
            .expect_err("the stream ended four bytes short");
        assert_eq!(error.code(), CURLcode::PartialFile);
        assert_eq!(
            error.message(),
            "end of response with 7 bytes missing",
            "the count is the shortfall at the moment of the failure, before \
             this write's bytes are counted"
        );
        // The truncated tail never reached the client.
        assert_eq!(delivered(&recorder), b"012".to_vec());
        assert_eq!(env.write.bytecount, 3);

        // A bodyless response is exempt from the check.
        let mut env = Env::new();
        env.write.size = 10;
        env.write.maxdownload = 10;
        env.write.no_body = true;
        env.write.header_size = 1;
        let (mut stack, _) = download_chain(&recorder);
        stack
            .write(
                &mut env.ctx(),
                ClientWriteFlags::BODY | ClientWriteFlags::EOS,
                b"",
            )
            .expect("a bodyless response cannot be truncated");
    }

    /// The user's maximum writes the permitted PREFIX and THEN fails, which is
    /// the opposite of the protocol's maximum.
    #[test]
    fn download_writer_writes_the_prefix_then_fails_on_max_filesize() {
        let recorder = log();
        let mut env = Env::new();
        env.config.max_filesize = 4;
        let (mut stack, _) = download_chain(&recorder);

        let error = stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"0123456789")
            .expect_err("the user's limit fails the transfer");
        assert_eq!(error.code(), CURLcode::FilesizeExceeded);
        assert_eq!(
            delivered(&recorder),
            b"0123".to_vec(),
            "lib/sendf.c:249-250: the permitted bytes are written first"
        );
        assert_eq!(env.write.bytecount, 4);
        assert_eq!(
            error.message(),
            "Exceeded the maximum allowed file size (4) with 4 bytes"
        );
        // The protocol's limit was not in play, so no excess was reported.
        assert!(env.control.conn_closes.is_empty());
    }

    /// A discarded body is exempt from the user's limit AND from the excess
    /// report, but is still counted.
    #[test]
    fn download_writer_ignores_the_body_when_asked() {
        let recorder = log();
        let mut env = Env::new();
        env.write.ignorebody = true;
        env.config.max_filesize = 2;
        env.write.size = 2;
        env.write.maxdownload = 2;
        let (mut stack, _) = download_chain(&recorder);

        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"0123456789")
            .expect("a discarded body never fails on a size limit");
        assert!(
            delivered(&recorder).is_empty(),
            "nothing is written to the client"
        );
        assert_eq!(
            env.write.bytecount, 2,
            "the permitted bytes are still counted"
        );
        assert!(env.control.conn_closes.is_empty());
        assert!(env.trace.infos.is_empty());
    }

    /// A zero-length body write is forwarded when the stream ends, so that the
    /// stage below learns the stream is over.
    #[test]
    fn download_writer_forwards_a_zero_length_body_at_end_of_stream() {
        let recorder = log();
        let mut env = Env::new();
        let (mut stack, _) = download_chain(&recorder);

        // Without the end-of-stream bit, an empty write reaches nobody.
        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"")
            .expect("an empty write succeeds");
        assert!(recorder.borrow().writes.is_empty());

        // With it, the empty write is forwarded.
        let eos = ClientWriteFlags::BODY | ClientWriteFlags::EOS;
        stack.write(&mut env.ctx(), eos, b"").expect("forwarded");
        assert_eq!(
            recorder.borrow().writes,
            vec![WriteRecord {
                stage: "cw-out",
                flags: eos,
                bytes: Vec::new(),
            }]
        );
    }

    /// Progress accounting advances by the bytes ACCEPTED, never by the bytes
    /// that arrived.
    #[test]
    fn download_writer_accounts_only_for_accepted_bytes() {
        let recorder = log();
        let mut env = Env::new();
        env.write.maxdownload = 6;
        let (mut stack, _) = download_chain(&recorder);
        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"0123456789")
            .expect("the excess is dropped");
        assert_eq!(env.write.bytecount, 6);
        assert_eq!(env.progress.download().cur_size(), 6);
    }

    /// A `maxdownload` already exceeded clamps the write to nothing rather than
    /// permitting an enormous one.
    #[test]
    fn download_writer_clamps_to_nothing_once_the_limit_is_passed() {
        let recorder = log();
        let mut env = Env::new();
        env.write.maxdownload = 4;
        env.write.bytecount = 9;
        let (mut stack, _) = download_chain(&recorder);
        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"more")
            .expect("the excess is reported, not returned");
        assert!(delivered(&recorder).is_empty());
        assert_eq!(env.write.bytecount, 9);
        assert!(env.write.download_done);
        assert_eq!(env.control.conn_closes, vec!["excess found in a read"]);
    }

    /// The download stage's own identity.
    #[test]
    fn download_writer_is_the_protocol_stage() {
        let stage = DownloadWriter::new();
        assert_eq!(stage.kind(), ClientWriterKind::Download);
        assert_eq!(stage.name(), "protocol");
        assert_eq!(stage.alias(), None);
        assert_eq!(stage.phase(), ClientWriterPhase::Protocol);
        assert!(!stage.is_paused());
    }

    // -- the raw stage ----------------------------------------------------

    /// The raw stage traces a body only when the transfer is verbose and the
    /// body is not being discarded, and it never changes a byte.
    #[test]
    fn raw_writer_traces_only_a_verbose_undiscarded_body() {
        let recorder = log();
        let mut stack = ClientWriterStack::new();
        stack.insert(
            RecordingWriter::sink(ClientWriterKind::ClientOut, &recorder)
                .boxed(),
        );
        stack.insert(Box::new(RawWriter::new()));

        // Not verbose: nothing traced, everything forwarded.
        let mut env = Env::new();
        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"\x00\xffbytes")
            .expect("forwarded");
        assert!(env.trace.debug.is_empty());
        assert_eq!(delivered(&recorder), b"\x00\xffbytes".to_vec());

        // Verbose: traced as CURLINFO_DATA_IN, byte for byte.
        let mut env = Env::new();
        env.config.verbose = true;
        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"\x00\xffbytes")
            .expect("forwarded");
        assert_eq!(
            env.trace.debug,
            vec![(TraceDataKind::DataIn, b"\x00\xffbytes".to_vec())]
        );

        // Verbose but discarded: not traced.
        let mut env = Env::new();
        env.config.verbose = true;
        env.write.ignorebody = true;
        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"bytes")
            .expect("forwarded");
        assert!(env.trace.debug.is_empty());

        // Verbose headers: not traced either, because they are not a body.
        let mut env = Env::new();
        env.config.verbose = true;
        stack
            .write(&mut env.ctx(), ClientWriteFlags::HEADER, b"a: b\r\n")
            .expect("forwarded");
        assert!(env.trace.debug.is_empty());
    }

    /// The raw stage's own identity, and that it is at the top of the chain.
    #[test]
    fn raw_writer_is_the_raw_stage() {
        let stage = RawWriter::new();
        assert_eq!(stage.kind(), ClientWriterKind::Raw);
        assert_eq!(stage.name(), "raw");
        assert_eq!(stage.phase(), ClientWriterPhase::Raw);
    }

    // -- `client_write` ---------------------------------------------------

    /// The entry point builds the base stack on demand, traces the outcome and
    /// carries the bytes to the sink through all four stages.
    #[test]
    fn client_write_builds_the_chain_and_traces_the_outcome() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();

        assert!(io.writers().is_empty());
        io.client_write(&mut env.ctx(), ClientWriteFlags::BODY, b"hello")
            .expect("the chain is built and the bytes delivered");
        assert_eq!(io.writers().len(), 4);
        assert_eq!(delivered(&recorder), b"hello".to_vec());
        assert!(env.trace.saw_write("client_write(type=1, len=5) -> 0"));
    }

    /// An error from a stage reaches the caller with its code intact and is
    /// traced.
    #[test]
    fn client_write_reports_a_stage_failure() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        env.write.no_body = true;

        let error = io
            .client_write(&mut env.ctx(), ClientWriteFlags::BODY, b"body")
            .expect_err("a body on a bodyless response");
        assert_eq!(error.code(), CURLcode::WeirdServerReply);
        assert!(env.trace.saw_write("client_write(type=1, len=4) -> 8"));
    }

    // -- the reader chain --------------------------------------------------

    /// A read from an empty chain is exactly [`CURLcode::ReadError`].
    #[test]
    fn reading_from_an_empty_chain_is_a_read_error() {
        let mut env = Env::new();
        let mut stack = ClientReaderStack::new();
        let mut buf = [0_u8; 8];
        assert_eq!(
            stack
                .read(&mut env.ctx(), &mut buf)
                .expect_err("an empty chain cannot be read")
                .code(),
            CURLcode::ReadError
        );
        assert_eq!(stack.total_length(), -1);
        assert_eq!(stack.client_length(), -1);
        assert!(!stack.is_paused());
        assert!(!stack.needs_rewind(&mut env.ctx()));
    }

    /// The default `read` body forwards, and the bottom of the chain is a read
    /// error.
    #[test]
    fn the_default_reader_forwards() {
        /// A stage with no `read` at all, so the default body runs.
        #[derive(Debug)]
        struct Passive;
        impl ClientReader for Passive {
            fn kind(&self) -> ClientReaderKind {
                ClientReaderKind::Custom("passive")
            }
            fn phase(&self) -> ClientReaderPhase {
                ClientReaderPhase::Protocol
            }
        }

        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientReaderStack::new();
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::Buf,
                ClientReaderPhase::Client,
                &recorder,
            )
            .yielding(b"payload")
            .boxed(),
        );
        stack.insert(Box::new(Passive));
        assert_eq!(stack.names(), vec!["passive", "cr-buf"]);

        let mut buf = [0_u8; 16];
        let outcome = stack
            .read(&mut env.ctx(), &mut buf)
            .expect("the default body forwarded to the source");
        assert_eq!(outcome, ReadOutcome::new(7, true));
        assert_eq!(&buf[..7], b"payload");

        // With nothing below it, the same stage is a read error.
        let mut alone = ClientReaderStack::new();
        alone.insert(Box::new(Passive));
        assert_eq!(
            alone
                .read(&mut env.ctx(), &mut buf)
                .expect_err("nothing below")
                .code(),
            CURLcode::ReadError
        );
    }

    /// Reader stages sort by phase and insert first within their phase, exactly
    /// as writers do.
    #[test]
    fn reader_insertion_orders_by_phase_then_first_within_it() {
        let recorder = log();
        let mut stack = ClientReaderStack::new();
        for (kind, phase) in [
            (ClientReaderKind::Input, ClientReaderPhase::Client),
            (ClientReaderKind::LineConv, ClientReaderPhase::ContentEncode),
            (
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
            ),
            (ClientReaderKind::Mime, ClientReaderPhase::Protocol),
            (
                ClientReaderKind::WebSocketEncode,
                ClientReaderPhase::TransferEncode,
            ),
        ] {
            stack.insert(RecordingReader::new(kind, phase, &recorder).boxed());
        }
        assert_eq!(
            stack.names(),
            vec!["ws-encode", "chunked", "cr-mime", "cr-lineconv", "cr-in",],
            "the two TRANSFER_ENCODE stages are in reverse installation order"
        );
        assert_eq!(stack.len(), 5);
    }

    /// The two length queries: the whole chain, and the client stage alone.
    #[test]
    fn reader_lengths_walk_the_chain() {
        let recorder = log();
        let mut stack = ClientReaderStack::new();
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::Input,
                ClientReaderPhase::Client,
                &recorder,
            )
            .with_length(1_234)
            .boxed(),
        );
        // A forwarding stage above it does not change either answer.
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::Mime,
                ClientReaderPhase::Protocol,
                &recorder,
            )
            .boxed(),
        );
        assert_eq!(stack.total_length(), 1_234);
        assert_eq!(stack.client_length(), 1_234);

        // A stage that changes the length reports -1 for the whole chain while
        // the client stage's own answer stands.
        stack.insert(Box::new(CrLineConv::new()));
        assert_eq!(stack.names(), vec!["cr-mime", "cr-lineconv", "cr-in"]);
        assert_eq!(stack.total_length(), -1);
        assert_eq!(stack.client_length(), 1_234);

        // With no client stage at all, the client length is -1.
        let mut headless = ClientReaderStack::new();
        headless.insert(
            RecordingReader::new(
                ClientReaderKind::Mime,
                ClientReaderPhase::Protocol,
                &recorder,
            )
            .with_length(9)
            .boxed(),
        );
        assert_eq!(headless.total_length(), 9);
        assert_eq!(headless.client_length(), -1);
    }

    /// The read-only query view walks the chain and answers -1 at its bottom.
    #[test]
    fn the_reader_query_view_walks_the_chain() {
        let recorder = log();
        let mut stack = ClientReaderStack::new();
        assert!(stack.query().is_empty());
        assert_eq!(stack.query().len(), 0);
        assert_eq!(stack.query().total_length(), -1);
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::Input,
                ClientReaderPhase::Client,
                &recorder,
            )
            .boxed(),
        );
        assert_eq!(stack.query().len(), 1);
        assert!(!stack.query().is_empty());
        // A forwarding stage over nothing is -1.
        assert_eq!(stack.query().total_length(), -1);
    }

    /// The four chain-wide reader operations reach every stage, and only the
    /// rewind walk stops early.
    #[test]
    fn reader_chain_operations_reach_every_stage() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientReaderStack::new();
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::Input,
                ClientReaderPhase::Client,
                &recorder,
            )
            .paused()
            .boxed(),
        );
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                &recorder,
            )
            .needing_rewind()
            .boxed(),
        );

        assert!(stack.is_paused());
        assert!(stack.needs_rewind(&mut env.ctx()));
        assert!(env.trace.saw_read("needs rewind before next request"));

        stack.unpause(&mut env.ctx()).expect("nothing refuses");
        assert!(!stack.is_paused());
        assert!(env.trace.saw_read("unpausing chunked -> 0"));
        assert!(env.trace.saw_read("unpausing cr-in -> 0"));

        stack.clear_eos(&mut env.ctx());
        stack.done(&mut env.ctx(), true);
        assert_eq!(
            recorder.borrow().controls,
            vec![
                ("chunked", ReaderControl::Unpause),
                ("cr-in", ReaderControl::Unpause),
                ("chunked", ReaderControl::ClearEos),
                ("cr-in", ReaderControl::ClearEos),
            ]
        );
        assert_eq!(
            recorder.borrow().dones,
            vec![("chunked", true), ("cr-in", true)]
        );

        assert_eq!(
            stack
                .get_by_kind(ClientReaderKind::Input)
                .map(ClientReader::name),
            Some("cr-in")
        );
        assert_eq!(
            stack
                .get_by_kind_mut(ClientReaderKind::ChunkedEncode)
                .map(|stage| stage.name()),
            Some("chunked")
        );
        assert!(stack.get_by_kind(ClientReaderKind::Mime).is_none());
    }

    /// The clear-EOS walk carries on past a failure, because no stage's answer
    /// can fail and stopping would leave the chain divided.
    #[test]
    fn clear_eos_carries_on_past_a_failure() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientReaderStack::new();
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::Input,
                ClientReaderPhase::Client,
                &recorder,
            )
            .boxed(),
        );
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                &recorder,
            )
            .control_failing(CURLcode::ReadError)
            .boxed(),
        );
        stack.clear_eos(&mut env.ctx());
        assert_eq!(
            recorder.borrow().controls,
            vec![
                ("chunked", ReaderControl::ClearEos),
                ("cr-in", ReaderControl::ClearEos),
            ]
        );
    }

    /// The unpause walk STOPS at the first failure, which is what the C's
    /// `if(result) break;` does.
    #[test]
    fn unpause_stops_at_the_first_failure() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientReaderStack::new();
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::Input,
                ClientReaderPhase::Client,
                &recorder,
            )
            .boxed(),
        );
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                &recorder,
            )
            .control_failing(CURLcode::AbortedByCallback)
            .boxed(),
        );
        assert_eq!(
            stack
                .unpause(&mut env.ctx())
                .expect_err("the first stage refuses")
                .code(),
            CURLcode::AbortedByCallback
        );
        assert_eq!(
            recorder.borrow().controls,
            vec![("chunked", ReaderControl::Unpause)]
        );
    }

    /// `resume_from` walks to the client stage, and answers
    /// [`CURLcode::ReadError`] when there is none.
    #[test]
    fn reader_resume_walks_to_the_client_phase() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientReaderStack::new();
        assert_eq!(
            stack
                .resume_from(&mut env.ctx(), 4)
                .expect_err("no client stage")
                .code(),
            CURLcode::ReadError
        );

        stack.insert(Box::new(CrBuf::new(b"0123456789")));
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                &recorder,
            )
            .boxed(),
        );
        stack
            .resume_from(&mut env.ctx(), 4)
            .expect("the client stage handled it");
        let mut buf = [0_u8; 16];
        let outcome = stack
            .read(&mut env.ctx(), &mut buf)
            .expect("the resumed source reads");
        assert_eq!(&buf[..outcome.bytes_read], b"456789");
    }

    // -- `cr_in`, the input callback reader ---------------------------------

    /// Drives one read of a stage that has nothing below it.
    fn read_alone(
        stage: &mut dyn ClientReader,
        env: &mut Env,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        let mut empty = no_readers();
        let mut tail = ReaderTail::new(&mut empty);
        let mut ctx = env.ctx();
        stage.read(&mut ctx, &mut tail, buf)
    }

    /// A callback that provides bytes reads them through, and the guard is
    /// raised and lowered exactly once per invocation.
    #[test]
    fn cr_in_reads_what_the_callback_provides() {
        let source =
            ScriptSource::new(&[Step::Data(b"abc"), Step::Data(b"de")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 8];

        let outcome = read_alone(&mut stage, &mut env, &mut buf)
            .expect("the callback provided three bytes");
        assert_eq!(outcome, ReadOutcome::new(3, false));
        assert_eq!(&buf[..3], b"abc");
        assert_eq!(stage.read_len(), 3);
        assert!(stage.needs_rewind());

        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("and two more");
        assert_eq!(outcome, ReadOutcome::new(2, false));
        assert_eq!(&buf[..2], b"de");
        assert_eq!(stage.read_len(), 5);

        // The exhausted script is the end of the upload.
        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("end of file");
        assert_eq!(outcome, ReadOutcome::EOS);

        assert_eq!(source.asked(), vec![8, 8, 8]);
        assert!(env.guard.balanced());
        assert_eq!(env.guard.entries(), 3);
        assert_eq!(env.guard.peak, 1);
        assert_eq!(stage.kind(), ClientReaderKind::Input);
        assert_eq!(stage.name(), "cr-in");
        assert_eq!(stage.phase(), ClientReaderPhase::Client);
        assert!(env.trace.saw_read("cr_in_read(len=8, total=-1, read=3)"));
    }

    /// The end of the stream, once reported, is reported for ever -- without
    /// the callback being consulted again.
    #[test]
    fn cr_in_repeats_end_of_stream() {
        let source = ScriptSource::new(&[]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 4];

        for _ in 0..3 {
            assert_eq!(
                read_alone(&mut stage, &mut env, &mut buf)
                    .expect("the end of the stream"),
                ReadOutcome::EOS
            );
        }
        assert_eq!(
            source.asked().len(),
            1,
            "the callback is consulted once and then never again"
        );
        assert!(stage.sticky_error().is_none());
    }

    /// A premature end of a SIZED upload is [`CURLcode::ReadError`], and it is
    /// NOT sticky -- the C sets neither `errored` nor `error_result` there.
    #[test]
    fn cr_in_fails_on_a_premature_end_and_the_failure_is_not_sticky() {
        let source = ScriptSource::new(&[Step::Data(b"ab")]);
        let mut stage = CrIn::new(Some(source.boxed()), 10);
        let mut env = Env::new();
        let mut buf = [0_u8; 8];

        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        let error = read_alone(&mut stage, &mut env, &mut buf)
            .expect_err("the upload ended eight bytes short");
        assert_eq!(error.code(), CURLcode::ReadError);
        assert_eq!(
            error.message(),
            "client read function EOF fail, only 2/10 of needed bytes read"
        );
        assert!(
            stage.sticky_error().is_none(),
            "lib/sendf.c:676-682 records no sticky error"
        );
        assert!(env.trace.fails.iter().any(|line| line.contains("EOF fail")));
    }

    /// An abort is [`CURLcode::AbortedByCallback`], and it IS sticky: every
    /// later read answers the same code with no bytes and no end-of-stream.
    #[test]
    fn cr_in_aborts_and_the_abort_is_sticky() {
        let source = ScriptSource::new(&[Step::Abort, Step::Data(b"never")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 8];

        let error = read_alone(&mut stage, &mut env, &mut buf)
            .expect_err("the callback aborted");
        assert_eq!(error.code(), CURLcode::AbortedByCallback);
        assert_eq!(error.message(), "operation aborted by callback");
        assert_eq!(stage.sticky_error(), Some(CURLcode::AbortedByCallback));

        for _ in 0..2 {
            let again = read_alone(&mut stage, &mut env, &mut buf)
                .expect_err("the same error for ever");
            assert_eq!(again.code(), CURLcode::AbortedByCallback);
        }
        assert_eq!(
            source.asked().len(),
            1,
            "a sticky error short-circuits before the callback"
        );
        assert!(env.guard.balanced());
    }

    /// A pause marks the stage paused and asks the engine to pause the upload;
    /// its result becomes the read's result.
    #[test]
    fn cr_in_pauses_and_asks_the_engine_to_pause() {
        let source = ScriptSource::new(&[Step::Pause]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 8];

        let outcome = read_alone(&mut stage, &mut env, &mut buf)
            .expect("a pause is a successful read of nothing");
        assert_eq!(outcome, ReadOutcome::EMPTY);
        assert!(stage.is_paused());
        assert!(stage.sticky_error().is_none());
        assert_eq!(env.control.pauses, vec![true]);
        assert!(env.trace.saw_read("CURL_READFUNC_PAUSE"));

        // The unpause control clears it.
        {
            let mut ctx = env.ctx();
            stage
                .control(&mut ctx, ReaderControl::Unpause)
                .expect("unpausing cannot fail");
        }
        assert!(!stage.is_paused());

        // A pause the engine refuses fails the read with the engine's code.
        let source = ScriptSource::new(&[Step::Pause]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        env.control.pause_fail = Some(CURLcode::OutOfMemory);
        assert_eq!(
            read_alone(&mut stage, &mut env, &mut buf)
                .expect_err("the engine refused")
                .code(),
            CURLcode::OutOfMemory
        );
        assert!(stage.is_paused());
    }

    /// A networkless scheme cannot be paused, so a pause request is
    /// [`CURLcode::ReadError`] and the stage stays unpaused.
    #[test]
    fn cr_in_refuses_to_pause_a_networkless_scheme() {
        let source = ScriptSource::new(&[Step::Pause]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        env.config.nonetwork = true;
        let mut buf = [0_u8; 8];

        let error = read_alone(&mut stage, &mut env, &mut buf)
            .expect_err("file:// cannot pause");
        assert_eq!(error.code(), CURLcode::ReadError);
        assert_eq!(
            error.message(),
            "Read callback asked for PAUSE when not supported"
        );
        assert!(!stage.is_paused());
        assert!(env.control.pauses.is_empty());
        assert!(
            stage.sticky_error().is_none(),
            "lib/sendf.c:698-705 records no sticky error"
        );
    }

    /// A callback that claims more than it was given is
    /// [`CURLcode::ReadError`], and it IS sticky.
    #[test]
    fn cr_in_rejects_a_funny_value_and_the_rejection_is_sticky() {
        let source = ScriptSource::new(&[Step::Claim(99)]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 8];

        let error = read_alone(&mut stage, &mut env, &mut buf)
            .expect_err("99 bytes into an 8-byte buffer");
        assert_eq!(error.code(), CURLcode::ReadError);
        assert_eq!(error.message(), "read function returned funny value");
        assert_eq!(stage.sticky_error(), Some(CURLcode::ReadError));
        assert_eq!(
            read_alone(&mut stage, &mut env, &mut buf)
                .expect_err("sticky")
                .code(),
            CURLcode::ReadError
        );
    }

    /// The request is clamped to what the declared length still permits, and
    /// the last bytes carry the end of the stream WITH them.
    #[test]
    fn cr_in_clamps_to_the_declared_length() {
        let source =
            ScriptSource::new(&[Step::Data(b"abc"), Step::Data(b"de")]);
        let mut stage = CrIn::new(Some(source.boxed()), 5);
        let mut env = Env::new();
        let mut buf = [0_u8; 16];

        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 5);
        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("three bytes");
        assert_eq!(outcome, ReadOutcome::new(3, false));
        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("two more");
        assert_eq!(
            outcome,
            ReadOutcome::new(2, true),
            "the declared length was reached, so these bytes ARE the last"
        );
        assert_eq!(
            source.asked(),
            vec![5, 2],
            "the destination was 16 bytes both times; the clamp is the \
             declared length's"
        );

        // The declared length is now exhausted, so the callback is not
        // consulted again at all.
        let outcome = read_alone(&mut stage, &mut env, &mut buf)
            .expect("the end of the stream");
        assert_eq!(outcome, ReadOutcome::EOS);
        assert_eq!(source.asked().len(), 2);
    }

    /// A declared length already met skips the callback and lands on the
    /// end-of-stream arm.
    #[test]
    fn cr_in_with_a_met_length_never_consults_the_callback() {
        let source = ScriptSource::new(&[Step::Data(b"x")]);
        let mut stage = CrIn::new(Some(source.boxed()), 0);
        let mut env = Env::new();
        let mut buf = [0_u8; 4];
        assert_eq!(
            read_alone(&mut stage, &mut env, &mut buf)
                .expect("nothing was wanted"),
            ReadOutcome::EOS
        );
        assert!(source.asked().is_empty());
    }

    /// No source at all behaves as a callback that produced nothing, which the
    /// C's `if(ctx->read_cb && blen)` guard arranges.
    #[test]
    fn cr_in_with_no_source_is_immediately_at_end_of_stream() {
        let mut stage = CrIn::new(None, -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 4];
        let outcome = read_alone(&mut stage, &mut env, &mut buf)
            .expect("nothing to read");
        assert_eq!(outcome, ReadOutcome::EOS);
        assert!(!stage.needs_rewind());
        assert_eq!(env.guard.entries(), 0);

        // And with a declared length it is a premature end.
        let mut stage = CrIn::new(None, 4);
        assert_eq!(
            read_alone(&mut stage, &mut env, &mut buf)
                .expect_err("four bytes were promised")
                .code(),
            CURLcode::ReadError
        );
    }

    /// The clear-EOS control makes the stage consult its source again.
    #[test]
    fn cr_in_clear_eos_reopens_the_stream() {
        let source = ScriptSource::new(&[]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 4];
        read_alone(&mut stage, &mut env, &mut buf).expect("end of stream");
        {
            let mut ctx = env.ctx();
            stage
                .control(&mut ctx, ReaderControl::ClearEos)
                .expect("clearing cannot fail");
        }
        read_alone(&mut stage, &mut env, &mut buf).expect("asked again");
        assert_eq!(source.asked().len(), 2);
    }

    // -- `cr_in` resume ----------------------------------------------------

    /// Resuming prefers the seek callback, and asks for the start of the
    /// stream.
    #[test]
    fn cr_in_resume_prefers_the_seek_callback() {
        let source = ScriptSource::new(&[Step::Data(b"tail")]);
        let mut stage = CrIn::new(Some(source.boxed()), 100);
        let mut env = Env::new();
        let mut seek = ScriptSeek::always(SeekOutcome::Ok);
        {
            let mut ctx = env.ctx().with_seek(&mut seek);
            assert!(ctx.has_seek());
            assert!(!ctx.has_ioctl());
            stage.resume_from(&mut ctx, 40).expect("the seek succeeded");
        }
        assert_eq!(seek.calls, vec![(40, SeekOrigin::Start)]);
        assert!(source.asked().is_empty(), "nothing was discarded");
        assert_eq!(
            stage.total_length(&ReaderQuery::new(&[])),
            60,
            "the declared length is reduced by the offset"
        );
        assert!(env.guard.balanced());
        assert_eq!(env.guard.entries(), 1);
    }

    /// A seek failure that is not "cannot seek" fails at once, discarding
    /// nothing.
    #[test]
    fn cr_in_resume_fails_when_the_seek_callback_fails() {
        let source = ScriptSource::new(&[Step::Data(b"x")]);
        let mut stage = CrIn::new(Some(source.boxed()), 100);
        let mut env = Env::new();
        let mut seek = ScriptSeek::always(SeekOutcome::Failed(1));
        let error = {
            let mut ctx = env.ctx().with_seek(&mut seek);
            stage
                .resume_from(&mut ctx, 40)
                .expect_err("the seek callback failed")
        };
        assert_eq!(error.code(), CURLcode::ReadError);
        assert_eq!(error.message(), "Could not seek stream");
        assert!(source.asked().is_empty());
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 100);
    }

    /// When the stream cannot seek, the offset is passed by reading and
    /// discarding in four-kibibyte requests.
    #[test]
    fn cr_in_resume_discards_in_four_kibibyte_reads() {
        // 4096 + 4096 + 8 = 8200 bytes to pass.
        const FULL: &[u8] = &[b'z'; RESUME_SCRATCH_LEN];
        let source = ScriptSource::new(&[
            Step::Data(FULL),
            Step::Data(FULL),
            Step::Data(b"12345678"),
        ]);
        let mut stage = CrIn::new(Some(source.boxed()), 10_000);
        let mut env = Env::new();

        // No seek callback at all, which the C reads as "cannot seek".
        {
            let mut ctx = env.ctx();
            stage
                .resume_from(&mut ctx, 8_200)
                .expect("the offset was passed");
        }
        assert_eq!(
            source.asked(),
            vec![RESUME_SCRATCH_LEN, RESUME_SCRATCH_LEN, 8],
            "the scratch area is exactly 4 * 1024 bytes, and the last request \
             asks only for what remains"
        );
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 1_800);
        assert!(env.guard.balanced());
        assert_eq!(env.guard.entries(), 3);

        // An explicit "cannot seek" answer takes the same path.
        let source = ScriptSource::new(&[Step::Data(b"0123")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut seek = ScriptSeek::always(SeekOutcome::CantSeek);
        {
            let mut ctx = env.ctx().with_seek(&mut seek);
            stage
                .resume_from(&mut ctx, 4)
                .expect("discarded four bytes");
        }
        assert_eq!(seek.calls, vec![(4, SeekOrigin::Start)]);
        assert_eq!(source.asked(), vec![4]);
        assert_eq!(
            stage.total_length(&ReaderQuery::new(&[])),
            -1,
            "an unknown length is left alone rather than made nonsense of"
        );
    }

    /// A discard that cannot reach the offset fails, and names how far it got.
    #[test]
    fn cr_in_resume_fails_when_the_discard_falls_short() {
        let source = ScriptSource::new(&[Step::Data(b"012")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let error = {
            let mut ctx = env.ctx();
            stage
                .resume_from(&mut ctx, 10)
                .expect_err("the source ran out after three bytes")
        };
        assert_eq!(error.code(), CURLcode::ReadError);
        assert_eq!(error.message(), "Could only read 3 bytes from the input");

        // A callback that claims more than it was given fails the same way,
        // which is what the C's greater-than test is for.
        let source = ScriptSource::new(&[Step::Claim(99)]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let error = {
            let mut ctx = env.ctx();
            stage.resume_from(&mut ctx, 10).expect_err("a funny value")
        };
        assert_eq!(error.code(), CURLcode::ReadError);

        // And so does an abort, which is an enormous count to the C.
        let source = ScriptSource::new(&[Step::Abort]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let error = {
            let mut ctx = env.ctx();
            stage.resume_from(&mut ctx, 10).expect_err("an abort")
        };
        assert_eq!(error.code(), CURLcode::ReadError);
    }

    /// An offset that consumes the whole declared length is
    /// [`CURLcode::PartialFile`].
    #[test]
    fn cr_in_resume_reports_a_fully_uploaded_file() {
        let source = ScriptSource::new(&[]);
        let mut stage = CrIn::new(Some(source.boxed()), 40);
        let mut env = Env::new();
        let mut seek = ScriptSeek::always(SeekOutcome::Ok);
        let error = {
            let mut ctx = env.ctx().with_seek(&mut seek);
            stage
                .resume_from(&mut ctx, 40)
                .expect_err("the whole file was already uploaded")
        };
        assert_eq!(error.code(), CURLcode::PartialFile);
        assert_eq!(error.message(), "File already completely uploaded");
    }

    /// Resuming is refused once reading has begun, and a negative offset is
    /// ignored.
    #[test]
    fn cr_in_resume_boundaries() {
        let source = ScriptSource::new(&[Step::Data(b"ab")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 4];
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        {
            let mut ctx = env.ctx();
            assert_eq!(
                stage
                    .resume_from(&mut ctx, 1)
                    .expect_err("reading has begun")
                    .code(),
                CURLcode::ReadError
            );
        }

        // A negative offset reaches the seek callback unchanged -- `cr_in`
        // does not screen it, unlike `cr_buf` -- and cannot make the declared
        // length nonsense: subtracting it INCREASES the length, so the
        // "already uploaded" test is unreachable and nothing underflows.
        let source = ScriptSource::new(&[]);
        let mut stage = CrIn::new(Some(source.boxed()), 10);
        let mut seek = ScriptSeek::always(SeekOutcome::Ok);
        {
            let mut ctx = env.ctx().with_seek(&mut seek);
            stage
                .resume_from(&mut ctx, -5)
                .expect("the callback accepted it");
        }
        assert_eq!(seek.calls, vec![(-5, SeekOrigin::Start)]);
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 15);
        assert!(source.asked().is_empty());

        // Down the DISCARD path a negative offset asks for zero bytes, which
        // the callback cannot satisfy, so the read fails honestly. The C
        // computes an enormous request here instead; see the note on
        // `CrIn::discard_to_offset` for the measurement and for why clamping
        // is not a behaviour change.
        let source = ScriptSource::new(&[]);
        let mut stage = CrIn::new(Some(source.boxed()), 10);
        let mut seek = ScriptSeek::always(SeekOutcome::CantSeek);
        let error = {
            let mut ctx = env.ctx().with_seek(&mut seek);
            stage
                .resume_from(&mut ctx, -5)
                .expect_err("nothing can be discarded")
        };
        assert_eq!(error.code(), CURLcode::ReadError);
        assert_eq!(
            source.asked(),
            vec![0],
            "the do-while runs once even for an unreachable offset, and the \
             request is clamped to the scratch area rather than masked"
        );
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 10);
    }

    // -- `cr_in` rewind ----------------------------------------------------

    /// Sends a rewind to a stage.
    fn rewind(stage: &mut dyn ClientReader, env: &mut Env) -> CurlResult<()> {
        let mut ctx = env.ctx();
        stage.control(&mut ctx, ReaderControl::Rewind)
    }

    /// A rewind before the callback ever ran does nothing at all -- not even
    /// consulting an installed seek callback.
    #[test]
    fn cr_in_rewind_does_nothing_before_the_callback_ran() {
        let source = ScriptSource::new(&[Step::Data(b"x")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut seek = ScriptSeek::always(SeekOutcome::Failed(1));
        {
            let mut ctx = env.ctx().with_seek(&mut seek);
            stage
                .control(&mut ctx, ReaderControl::Rewind)
                .expect("there is nothing to rewind");
        }
        assert!(seek.calls.is_empty());
        assert_eq!(source.seeks(), 0);
    }

    /// The seek callback is preferred, and any non-zero answer -- including
    /// "cannot seek" -- is [`CURLcode::SendFailRewind`].
    #[test]
    fn cr_in_rewind_prefers_the_seek_callback() {
        let mut buf = [0_u8; 4];

        // Success.
        let source = ScriptSource::new(&[Step::Data(b"ab")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        let mut seek = ScriptSeek::always(SeekOutcome::Ok);
        {
            let mut ctx = env.ctx().with_seek(&mut seek);
            stage
                .control(&mut ctx, ReaderControl::Rewind)
                .expect("the seek succeeded");
        }
        assert_eq!(seek.calls, vec![(0, SeekOrigin::Start)]);
        assert!(env.trace.saw_read("rewind via set.seek_func -> 0"));

        // Failure.
        let source = ScriptSource::new(&[Step::Data(b"ab")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        let mut seek = ScriptSeek::always(SeekOutcome::Failed(7));
        let error = {
            let mut ctx = env.ctx().with_seek(&mut seek);
            stage
                .control(&mut ctx, ReaderControl::Rewind)
                .expect_err("the seek failed")
        };
        assert_eq!(error.code(), CURLcode::SendFailRewind);
        assert_eq!(error.message(), "seek callback returned error 7");

        // "Cannot seek" is a FAILURE here, unlike in `resume_from`.
        let source = ScriptSource::new(&[Step::Data(b"ab")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        let mut seek = ScriptSeek::always(SeekOutcome::CantSeek);
        let error = {
            let mut ctx = env.ctx().with_seek(&mut seek);
            stage
                .control(&mut ctx, ReaderControl::Rewind)
                .expect_err("lib/sendf.c:834 tests any non-zero value")
        };
        assert_eq!(error.code(), CURLcode::SendFailRewind);
        assert_eq!(error.message(), "seek callback returned error 2");
    }

    /// With no seek callback, the ioctl callback is asked to restart the read.
    #[test]
    fn cr_in_rewind_uses_the_ioctl_callback() {
        let mut buf = [0_u8; 4];

        let source = ScriptSource::new(&[Step::Data(b"ab")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        let mut ioctl = ScriptIoctl::always(IoOutcome::Ok);
        {
            let mut ctx = env.ctx().with_ioctl(&mut ioctl);
            assert!(ctx.has_ioctl());
            stage
                .control(&mut ctx, ReaderControl::Rewind)
                .expect("the ioctl succeeded");
        }
        assert_eq!(ioctl.calls, vec![IoCmd::RestartRead]);
        assert_eq!(source.seeks(), 0, "the source's own seek was not needed");
        assert!(env.trace.saw_read("rewind via set.ioctl_func -> 0"));

        // A failure names the code the C prints.
        let source = ScriptSource::new(&[Step::Data(b"ab")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        let mut ioctl = ScriptIoctl::always(IoOutcome::FailRestart);
        let error = {
            let mut ctx = env.ctx().with_ioctl(&mut ioctl);
            stage
                .control(&mut ctx, ReaderControl::Rewind)
                .expect_err("the ioctl refused")
        };
        assert_eq!(error.code(), CURLcode::SendFailRewind);
        assert_eq!(error.message(), "ioctl callback returned error 2");

        // The seek callback wins when both are installed.
        let source = ScriptSource::new(&[Step::Data(b"ab")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        let mut seek = ScriptSeek::always(SeekOutcome::Ok);
        let mut ioctl = ScriptIoctl::always(IoOutcome::Ok);
        {
            let mut ctx = env.ctx().with_seek(&mut seek).with_ioctl(&mut ioctl);
            stage
                .control(&mut ctx, ReaderControl::Rewind)
                .expect("the seek callback was preferred");
        }
        assert_eq!(seek.calls.len(), 1);
        assert!(ioctl.calls.is_empty());
    }

    /// With neither callback installed, the source's own seek is used -- and a
    /// source that cannot seek itself makes the rewind impossible.
    #[test]
    fn cr_in_rewind_falls_back_to_the_sources_own_seek() {
        let mut buf = [0_u8; 4];

        // A seekable source.
        let source = ScriptSource::new(&[Step::Data(b"ab")]).seekable(true);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        rewind(&mut stage, &mut env).expect("the source rewound itself");
        assert_eq!(source.seeks(), 1);
        assert!(env.trace.saw_read("rewind via source seek -> 0"));

        // A source whose seek fails falls through to the impossible-rewind
        // failure, exactly as the C's `if(err != -1)` does.
        let source = ScriptSource::new(&[Step::Data(b"ab")]).seekable(false);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        let error = rewind(&mut stage, &mut env).expect_err("the seek failed");
        assert_eq!(error.code(), CURLcode::SendFailRewind);
        assert_eq!(error.message(), "necessary data rewind was not possible");
        assert_eq!(source.seeks(), 1);

        // A source that is not the default one is never even asked.
        let source = ScriptSource::new(&[Step::Data(b"ab")]);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        read_alone(&mut stage, &mut env, &mut buf).expect("two bytes");
        assert_eq!(
            rewind(&mut stage, &mut env)
                .expect_err("nothing can rewind this")
                .code(),
            CURLcode::SendFailRewind
        );
        assert_eq!(source.seeks(), 1, "asked, and answered `None`");
    }

    /// The stream source is a real `Read + Seek` adapter, and it is the
    /// DEFAULT source -- so it answers the rewind question itself.
    #[test]
    fn the_stream_source_reads_and_rewinds() {
        let mut source = StreamReadSource::new(Cursor::new(b"0123456789"));
        let mut buf = [0_u8; 4];
        assert_eq!(source.read(&mut buf), SourceRead::Bytes(4));
        assert_eq!(&buf, b"0123");
        assert_eq!(source.read(&mut buf), SourceRead::Bytes(4));
        assert_eq!(&buf, b"4567");

        source
            .seek_to_start()
            .expect("this IS the default source")
            .expect("a cursor always seeks");
        assert_eq!(source.read(&mut buf), SourceRead::Bytes(4));
        assert_eq!(&buf, b"0123");

        // Exhausted is zero bytes, which `cr_in` reads as the end of the
        // upload.
        let mut empty = StreamReadSource::new(Cursor::new(Vec::new()));
        assert_eq!(empty.read(&mut buf), SourceRead::Bytes(0));
        assert!(empty.into_inner().into_inner().is_empty());

        // And a whole rewind cycle through `cr_in`.
        let mut stage = CrIn::new(
            Some(Box::new(StreamReadSource::new(Cursor::new(b"abcdef")))),
            -1,
        );
        let mut env = Env::new();
        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("four bytes");
        assert_eq!(&buf[..outcome.bytes_read], b"abcd");
        rewind(&mut stage, &mut env).expect("the cursor rewound");
        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("from the start");
        assert_eq!(&buf[..outcome.bytes_read], b"abcd");
    }

    // -- `cr_lc`, the line-ending converter --------------------------------

    /// Reads a whole chain to exhaustion, gathering every byte.
    fn drain(
        stack: &mut ClientReaderStack<'_>,
        env: &mut Env,
        chunk: usize,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0_u8; chunk];
        for _ in 0..64 {
            let outcome = {
                let mut ctx = env.ctx();
                stack.read(&mut ctx, &mut buf).expect("the chain reads")
            };
            out.extend_from_slice(&buf[..outcome.bytes_read]);
            if outcome.eos {
                return out;
            }
        }
        panic!("the chain never reported the end of its stream");
    }

    /// A chain of the converter over a source that yields `bytes`.
    fn lineconv_chain(
        recorder: &SharedLog,
        bytes: &'static [u8],
    ) -> ClientReaderStack<'static> {
        let mut stack = ClientReaderStack::new();
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::Buf,
                ClientReaderPhase::Client,
                recorder,
            )
            .yielding(bytes)
            .boxed(),
        );
        stack.insert(Box::new(CrLineConv::new()));
        stack
    }

    /// Data with no line feed is handed straight back, uncopied and unbuffered.
    #[test]
    fn lineconv_passes_data_with_no_line_feed_straight_through() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = lineconv_chain(&recorder, b"no newlines here\r");
        assert_eq!(drain(&mut stack, &mut env, 64), b"no newlines here\r");
        assert!(env
            .trace
            .saw_read("cr_lc_read(len=64) -> 0, nread=17, eos=1"));
    }

    /// A bare line feed becomes a pair; an existing pair is left alone.
    #[test]
    fn lineconv_converts_only_bare_line_feeds() {
        let recorder = log();
        let mut env = Env::new();

        let mut stack = lineconv_chain(&recorder, b"a\nb\nc");
        assert_eq!(drain(&mut stack, &mut env, 64), b"a\r\nb\r\nc");

        let mut stack = lineconv_chain(&recorder, b"a\r\nb\r\n");
        assert_eq!(
            drain(&mut stack, &mut env, 64),
            b"a\r\nb\r\n",
            "an existing pair is preserved, not doubled"
        );

        // Mixed, including a lone carriage return and a REVERSED pair. The
        // line feed after `b` is bare -- `b` is not a carriage return -- so it
        // is converted; the `\n\r` at index 3 is not a pair in either
        // direction, so the `\r` merely arms `prev_cr` for a line feed that
        // never comes.
        let mut stack = lineconv_chain(&recorder, b"a\rb\n\rc\n\nd");
        assert_eq!(drain(&mut stack, &mut env, 64), b"a\rb\r\n\rc\r\n\r\nd");

        // An empty run before a bare line feed is a zero-length write into the
        // queue, which is why `queue_write_all` must tolerate one.
        let mut stack = lineconv_chain(&recorder, b"\n\n");
        assert_eq!(drain(&mut stack, &mut env, 64), b"\r\n\r\n");
    }

    /// A pair SPLIT across two reads is preserved, which is what
    /// [`CrLineConv::prev_cr`] exists for.
    #[test]
    fn lineconv_preserves_a_pair_split_across_two_reads() {
        let mut env = Env::new();
        let mut stage = CrLineConv::new();

        // First run ends on a carriage return.
        stage
            .convert_into_queue(b"line\r")
            .expect("the run is buffered");
        assert!(stage.prev_cr(), "the boundary state was remembered");

        // The next run opens with the line feed that completes the pair.
        stage
            .convert_into_queue(b"\nnext")
            .expect("the run is buffered");
        assert!(!stage.prev_cr());

        let mut buf = [0_u8; 32];
        let outcome = read_alone(&mut stage, &mut env, &mut buf)
            .expect("the queue drains");
        assert_eq!(
            &buf[..outcome.bytes_read],
            b"line\r\nnext",
            "the pair was preserved rather than becoming \\r\\r\\n"
        );
        assert_eq!(stage.buffered(), 0);

        // Through a CHAIN, the shortcut at `lib/sendf.c:1010-1017` changes the
        // answer, and this is the measured behaviour of curl 8.19.0-DEV rather
        // than a defect of this translation. Reading one byte at a time, the
        // buffer holding the carriage return contains no line feed, so the
        // conversion loop never runs for it and `prev_cr` is never armed; the
        // line feed that follows therefore looks bare and is converted.
        let recorder = log();
        let mut stack = lineconv_chain(&recorder, b"one\r\ntwo\nthree");
        assert_eq!(
            drain(&mut stack, &mut env, 1),
            b"one\r\r\ntwo\r\nthree",
            "the no-line-feed shortcut forgets a carriage return, so a \
             pair split across it becomes CR CR LF -- see CrLineConv::read"
        );

        // And the case where the shortcut is NOT taken, so the memory IS armed
        // and the pair IS preserved across the boundary: the first buffer holds
        // a line feed of its own AND ends on a carriage return.
        let mut stage = CrLineConv::new();
        stage.convert_into_queue(b"a\n\r").expect("buffered");
        assert!(stage.prev_cr());
        stage.convert_into_queue(b"\nb").expect("buffered");
        let mut buf = [0_u8; 32];
        let outcome = read_alone(&mut stage, &mut env, &mut buf)
            .expect("the queue drains");
        assert_eq!(&buf[..outcome.bytes_read], b"a\r\n\r\nb");
    }

    /// The end of the stream is DEFERRED until the queue has drained.
    #[test]
    fn lineconv_defers_end_of_stream_until_the_queue_drains() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = lineconv_chain(&recorder, b"a\nb\nc\nd\n");

        // A destination too small to take the converted form: the first read
        // must NOT report the end of the stream even though the source has.
        let mut buf = [0_u8; 4];
        let first = {
            let mut ctx = env.ctx();
            stack.read(&mut ctx, &mut buf).expect("the chain reads")
        };
        assert_eq!(first.bytes_read, 4);
        assert!(
            !first.eos,
            "converted bytes are still held, so the stream has not ended"
        );
        assert_eq!(&buf[..4], b"a\r\nb");

        let mut rest = buf[..4].to_vec();
        rest.extend(drain(&mut stack, &mut env, 4));
        assert_eq!(rest, b"a\r\nb\r\nc\r\nd\r\n");
    }

    /// The converter's length is indeterminate, and it is at the content-encode
    /// phase.
    #[test]
    fn lineconv_length_is_indeterminate() {
        let stage = CrLineConv::new();
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), -1);
        assert_eq!(stage.kind(), ClientReaderKind::LineConv);
        assert_eq!(stage.name(), "cr-lineconv");
        assert_eq!(stage.phase(), ClientReaderPhase::ContentEncode);
        assert_eq!(stage.buffered(), 0);
        assert!(!stage.prev_cr());
        assert!(!stage.is_paused());
        assert!(!stage.needs_rewind());
    }

    /// The two bytes written are exactly `0x0d 0x0a`, and nothing renders them.
    #[test]
    fn lineconv_writes_the_literal_two_bytes() {
        let mut stage = CrLineConv::new();
        stage.convert_into_queue(b"\n").expect("buffered");
        let mut env = Env::new();
        let mut buf = [0_u8; 8];
        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("drained");
        assert_eq!(&buf[..outcome.bytes_read], &[0x0d, 0x0a]);
    }

    /// A failure below the converter is returned WITHOUT a trace line, which is
    /// the C returning at `:1007` rather than reaching its `out:` label.
    #[test]
    fn lineconv_propagates_a_failure_from_below_untraced() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientReaderStack::new();
        stack.insert(
            RecordingReader::new(
                ClientReaderKind::Buf,
                ClientReaderPhase::Client,
                &recorder,
            )
            .failing(CURLcode::ReadError)
            .boxed(),
        );
        stack.insert(Box::new(CrLineConv::new()));
        let mut buf = [0_u8; 8];
        assert_eq!(
            stack
                .read(&mut env.ctx(), &mut buf)
                .expect_err("the source refused")
                .code(),
            CURLcode::ReadError
        );
        assert!(env.trace.reads.is_empty());
    }

    /// The queue helper completes a short write and treats an empty slice as a
    /// no-op.
    #[test]
    fn the_queue_helper_writes_everything() {
        let mut queue = BufQ::with_opts(
            LINECONV_CHUNK_LEN,
            LINECONV_CHUNKS,
            BufqOpts::SOFT_LIMIT,
        );
        queue_write_all(&mut queue, b"").expect("an empty write is a no-op");
        assert_eq!(queue.len(), 0);

        // More than one nominal chunk, which a soft limit accepts.
        let big = vec![b'q'; LINECONV_CHUNK_LEN * 3 + 7];
        queue_write_all(&mut queue, &big).expect("a soft limit grows");
        assert_eq!(queue.len(), big.len());
    }

    // -- `cr_null` and `cr_buf` --------------------------------------------

    /// The null reader provides nothing, for ever, and its length is ZERO --
    /// which is what keeps a converter off an empty upload.
    #[test]
    fn null_reader_is_immediately_at_end_of_stream() {
        let mut stage = CrNull::new();
        let mut env = Env::new();
        let mut buf = [0_u8; 4];
        for _ in 0..3 {
            assert_eq!(
                read_alone(&mut stage, &mut env, &mut buf).expect("nothing"),
                ReadOutcome::EOS
            );
        }
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 0);
        assert_eq!(stage.kind(), ClientReaderKind::Null);
        assert_eq!(stage.name(), "cr-null");
        assert_eq!(stage.phase(), ClientReaderPhase::Client);
        assert!(!stage.needs_rewind());
        assert_eq!(buf, [0_u8; 4], "the destination is untouched");
    }

    /// The buffer reader hands up its bytes sequentially, clamped to the
    /// destination, and reports the end of the stream WITH the last of them.
    #[test]
    fn buf_reader_reads_sequentially() {
        let mut stage = CrBuf::new(b"0123456789");
        let mut env = Env::new();
        let mut buf = [0_u8; 4];

        assert_eq!(stage.index(), 0);
        assert!(!stage.needs_rewind());
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 10);

        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("four bytes");
        assert_eq!(outcome, ReadOutcome::new(4, false));
        assert_eq!(&buf, b"0123");
        assert!(stage.needs_rewind());

        read_alone(&mut stage, &mut env, &mut buf).expect("four more");
        assert_eq!(&buf, b"4567");

        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("the last two");
        assert_eq!(
            outcome,
            ReadOutcome::new(2, true),
            "the end of the stream arrives WITH the last bytes"
        );
        assert_eq!(&buf[..2], b"89");
        assert_eq!(stage.index(), 10);

        // Exhausted, and then for ever.
        assert_eq!(
            read_alone(&mut stage, &mut env, &mut buf).expect("nothing left"),
            ReadOutcome::EOS
        );
        assert!(env
            .trace
            .saw_read("cr_buf_read(len=4) -> 0, nread=0, eos=1"));

        // An empty buffer is the end of the stream at once.
        let mut empty = CrBuf::new(b"");
        assert_eq!(
            read_alone(&mut empty, &mut env, &mut buf).expect("nothing"),
            ReadOutcome::EOS
        );
        assert_eq!(empty.total_length(&ReaderQuery::new(&[])), 0);
        assert_eq!(empty.kind(), ClientReaderKind::Buf);
        assert_eq!(empty.name(), "cr-buf");
    }

    /// A rewind puts the buffer reader back to its start.
    #[test]
    fn buf_reader_rewinds() {
        let mut stage = CrBuf::new(b"abcdef");
        let mut env = Env::new();
        let mut buf = [0_u8; 3];
        read_alone(&mut stage, &mut env, &mut buf).expect("three bytes");
        assert_eq!(stage.index(), 3);
        rewind(&mut stage, &mut env).expect("a rewind cannot fail here");
        assert_eq!(stage.index(), 0);
        assert!(!stage.needs_rewind());
        let outcome = read_alone(&mut stage, &mut env, &mut buf)
            .expect("from the start again");
        assert_eq!(&buf[..outcome.bytes_read], b"abc");

        // The other two controls do nothing at all to it.
        {
            let mut ctx = env.ctx();
            stage
                .control(&mut ctx, ReaderControl::Unpause)
                .expect("a no-op");
            stage
                .control(&mut ctx, ReaderControl::ClearEos)
                .expect("a no-op");
        }
        assert_eq!(stage.index(), 3);
    }

    /// Resuming drops the leading bytes and shortens the reported length.
    #[test]
    fn buf_reader_resume_advances_the_slice() {
        let mut env = Env::new();

        let mut stage = CrBuf::new(b"0123456789");
        {
            let mut ctx = env.ctx();
            stage.resume_from(&mut ctx, 4).expect("four bytes dropped");
        }
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 6);
        let mut buf = [0_u8; 16];
        let outcome =
            read_alone(&mut stage, &mut env, &mut buf).expect("the remainder");
        assert_eq!(&buf[..outcome.bytes_read], b"456789");

        // A zero and a negative offset both do nothing.
        let mut stage = CrBuf::new(b"abc");
        {
            let mut ctx = env.ctx();
            stage.resume_from(&mut ctx, 0).expect("nothing to do");
            stage.resume_from(&mut ctx, -9).expect("ignored");
        }
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 3);

        // An offset EQUAL to the length is accepted and leaves nothing.
        let mut stage = CrBuf::new(b"abc");
        {
            let mut ctx = env.ctx();
            stage.resume_from(&mut ctx, 3).expect("the whole buffer");
        }
        assert_eq!(stage.total_length(&ReaderQuery::new(&[])), 0);
        assert_eq!(
            read_alone(&mut stage, &mut env, &mut buf).expect("nothing left"),
            ReadOutcome::EOS
        );

        // One past it is a read error.
        let mut stage = CrBuf::new(b"abc");
        {
            let mut ctx = env.ctx();
            assert_eq!(
                stage
                    .resume_from(&mut ctx, 4)
                    .expect_err("past the end")
                    .code(),
                CURLcode::ReadError
            );
        }

        // And resuming after reading has begun is refused.
        let mut stage = CrBuf::new(b"abc");
        let mut small = [0_u8; 1];
        read_alone(&mut stage, &mut env, &mut small).expect("one byte");
        {
            let mut ctx = env.ctx();
            assert_eq!(
                stage
                    .resume_from(&mut ctx, 1)
                    .expect_err("reading has begun")
                    .code(),
                CURLcode::ReadError
            );
        }
    }

    // -- the reader chain's installers -------------------------------------

    /// The null source installs NO converter, because its length is zero --
    /// which is the whole point of `lib/sendf.c:1111` testing the length first.
    #[test]
    fn set_null_installs_no_converter() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        env.config.crlf = true;

        io.set_null(&mut env.ctx())
            .expect("the null source installs");
        assert_eq!(io.readers().names(), vec!["cr-null"]);
        assert_eq!(io.readers().total_length(), 0);
        assert_eq!(io.readers().client_length(), 0);
    }

    /// A source with a non-zero length DOES get a converter when either setting
    /// asks for one, and it lands at the content-encode phase above the source.
    #[test]
    fn a_converter_is_installed_when_either_setting_asks() {
        let recorder = log();
        let source = ScriptSource::new(&[Step::Data(b"a\nb")]);

        // `--crlf`.
        let factory = TestFactory::new(&recorder).with_source(&source);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        env.config.crlf = true;
        io.set_fread(&mut env.ctx(), 3)
            .expect("the source installs");
        assert_eq!(io.readers().names(), vec!["cr-lineconv", "cr-in"]);
        assert_eq!(
            io.readers().total_length(),
            -1,
            "the converter makes the whole chain's length indeterminate"
        );
        assert_eq!(io.readers().client_length(), 3);
        assert!(env.trace.saw_read("add fread reader, len=3 -> 0"));

        // The prefer-ASCII disjunct, over a borrowed buffer this time.
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        env.config.prefer_ascii = true;
        io.set_buf(&mut env.ctx(), b"x\ny")
            .expect("the buffer installs");
        assert_eq!(io.readers().names(), vec!["cr-lineconv", "cr-buf"]);
        assert!(env.trace.saw_read("add buf reader, len=3 -> 0"));

        // Neither setting: no converter.
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        io.set_buf(&mut env.ctx(), b"x\ny")
            .expect("the buffer installs");
        assert_eq!(io.readers().names(), vec!["cr-buf"]);
    }

    /// The borrowed buffer is read through the whole chain, converted on the
    /// way, and NOT copied on installation.
    #[test]
    fn a_borrowed_buffer_reads_through_the_converter() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        env.config.crlf = true;
        // A `'static` literal, because the chain holds the slice rather than a
        // copy of it and so must not outlive it.
        io.set_buf(&mut env.ctx(), b"one\ntwo\n").expect("installs");

        let mut collected = Vec::new();
        let mut buf = [0_u8; 4];
        loop {
            let outcome = io
                .client_read(&mut env.ctx(), &mut buf)
                .expect("the chain reads");
            collected.extend_from_slice(&buf[..outcome.bytes_read]);
            if outcome.eos {
                break;
            }
        }
        assert_eq!(collected, b"one\r\ntwo\r\n");
    }

    /// Each installer REPLACES the whole chain, closing what was there.
    #[test]
    fn an_installer_replaces_the_whole_chain() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();

        io.set_buf(&mut env.ctx(), b"first").expect("installs");
        io.readers_mut().insert(
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                &recorder,
            )
            .boxed(),
        );
        assert_eq!(io.readers().names(), vec!["chunked", "cr-buf"]);
        env.read.reader_started = true;

        io.set_null(&mut env.ctx()).expect("installs");
        assert_eq!(io.readers().names(), vec!["cr-null"]);
        assert_eq!(
            recorder.borrow().closes,
            vec!["chunked"],
            "the recording stage was closed; cr-buf's close is the default"
        );
        assert!(
            !env.read.reader_started,
            "tearing the chain down clears the started flag"
        );

        // The general form takes ownership of a stage another module built.
        io.set_reader(&mut env.ctx(), Box::new(CrBuf::new(b"third")))
            .expect("installs");
        assert_eq!(io.readers().names(), vec!["cr-buf"]);
        assert_eq!(io.readers().client_length(), 5);
    }

    /// Adding a reader to an EMPTY chain installs the default source beneath it
    /// first, from the factory and `infilesize`.
    #[test]
    fn adding_a_reader_to_an_empty_chain_installs_the_default_source() {
        let recorder = log();
        let source = ScriptSource::new(&[Step::Data(b"payload")]);
        let factory = TestFactory::new(&recorder).with_source(&source);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        env.config.infilesize = 7;

        io.add_reader(
            &mut env.ctx(),
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                &recorder,
            )
            .boxed(),
        )
        .expect("the default source is installed first");
        assert_eq!(io.readers().names(), vec!["chunked", "cr-in"]);
        assert_eq!(io.readers().client_length(), 7);
    }

    // -- `client_read` ------------------------------------------------------

    /// The entry point installs the chain on demand, from the factory's source
    /// and the declared upload length.
    #[test]
    fn client_read_installs_the_chain_on_demand() {
        let recorder = log();
        let source = ScriptSource::new(&[Step::Data(b"upload")]);
        let factory = TestFactory::new(&recorder).with_source(&source);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        env.config.infilesize = 6;

        assert!(io.readers().is_empty());
        let mut buf = [0_u8; 16];
        let outcome = io
            .client_read(&mut env.ctx(), &mut buf)
            .expect("the chain is installed and read");
        assert_eq!(outcome, ReadOutcome::new(6, true));
        assert_eq!(&buf[..6], b"upload");
        assert_eq!(io.readers().names(), vec!["cr-in"]);
        assert!(env.read.reader_started);
        assert!(env
            .trace
            .saw_read("client_read(len=16) -> 0, nread=6, eos=1"));
    }

    /// The instant every [`Env`] is pinned to.
    ///
    /// A function rather than a constant because [`CurlTime::new`] is not
    /// `const`, and making it so belongs to that module rather than this one.
    fn pinned() -> CurlTime {
        CurlTime::new(1_000, 0)
    }

    /// Installs an upload limit of `rate` bytes a second, as
    /// `CURLOPT_MAX_SEND_SPEED_LARGE` does.
    fn limit_upload(env: &mut Env, rate: i64) {
        *env.progress.upload_mut().rlimit_mut() =
            RateLimit::new(rate, 0, pinned());
    }

    /// The upload tokens available at `at`.
    fn upload_avail(env: &mut Env, at: CurlTime) -> i64 {
        env.progress.upload_mut().rlimit_mut().available(at)
    }

    /// Spends upload tokens, as progress accounting does once bytes are away.
    fn upload_drain(env: &mut Env, tokens: usize, at: CurlTime) {
        env.progress.upload_mut().rlimit_mut().drain(tokens, at);
    }

    /// The upload limiter is started exactly once, with an UNKNOWN total.
    #[test]
    fn client_read_starts_the_upload_limiter_once() {
        let recorder = log();
        let source = ScriptSource::new(&[Step::Data(b"a"), Step::Data(b"b")]);
        let factory = TestFactory::new(&recorder).with_source(&source);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();

        // A limiter of 100 bytes a second, started at the pinned instant.
        limit_upload(&mut env, 100);
        let mut buf = [0_u8; 4];
        io.client_read(&mut env.ctx(), &mut buf).expect("one byte");
        assert!(env.read.reader_started);
        // `Curl_rlimit_start` refills to one step's worth.
        assert_eq!(upload_avail(&mut env, pinned()), 100);

        // A second read does not restart it, which is what the flag is for.
        upload_drain(&mut env, 60, pinned());
        io.client_read(&mut env.ctx(), &mut buf).expect("one more");
        assert_eq!(
            upload_avail(&mut env, pinned()),
            40,
            "a restart would have refilled the bucket to 100"
        );
    }

    /// The request is clamped to the tokens available, and no tokens is a
    /// SUCCESSFUL read of nothing rather than an error.
    #[test]
    fn client_read_clamps_to_the_available_tokens() {
        const TEN: &[u8] = b"0123456789";
        let recorder = log();
        let source = ScriptSource::new(&[Step::Data(TEN), Step::Data(TEN)]);
        let factory = TestFactory::new(&recorder).with_source(&source);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        limit_upload(&mut env, 10);

        // Ten tokens, so a 64-byte request is clamped to ten -- which the
        // source records, because it is handed the clamped destination.
        let mut buf = [0_u8; 64];
        let outcome =
            io.client_read(&mut env.ctx(), &mut buf).expect("clamped");
        assert_eq!(outcome.bytes_read, 10);
        assert_eq!(source.asked(), vec![10]);
        assert!(env.trace.saw_read("client_read(len=10)"));

        // Spend them all, and the next read is zero bytes and NOT the end of
        // the stream: backpressure, not an error and not exhaustion.
        upload_drain(&mut env, 10, pinned());
        let outcome = io
            .client_read(&mut env.ctx(), &mut buf)
            .expect("no tokens is a success");
        assert_eq!(outcome, ReadOutcome::EMPTY);
        assert_eq!(
            source.asked().len(),
            1,
            "the source was not consulted at all"
        );

        // Time passing generates tokens, and the read resumes.
        env.clock.advance(Duration::from_secs(1));
        let outcome = io
            .client_read(&mut env.ctx(), &mut buf)
            .expect("tokens again");
        assert_eq!(outcome.bytes_read, 10);
        assert_eq!(source.asked(), vec![10, 10]);
    }

    /// A stage that reports the end of the stream ENDS the read, whatever the
    /// stage below it still holds.
    ///
    /// The shape a chunked encoder has once it has written its terminating
    /// chunk: the source may be exhausted or not, and the answer is the top
    /// stage's, because `Curl_creader_read` returns what the FIRST stage says.
    #[test]
    fn client_read_ends_when_the_top_stage_reports_the_end() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        io.set_buf(&mut env.ctx(), b"never read").expect("installs");
        io.readers_mut().insert(
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                &recorder,
            )
            .at_eos()
            .boxed(),
        );

        let mut buf = [0_u8; 16];
        let outcome = io
            .client_read(&mut env.ctx(), &mut buf)
            .expect("the encoder answers");
        assert_eq!(outcome, ReadOutcome::EOS);
        assert_eq!(
            recorder
                .borrow()
                .reads
                .iter()
                .map(|record| record.stage)
                .collect::<Vec<_>>(),
            vec!["chunked"],
            "the source below was never consulted"
        );
        assert!(env
            .trace
            .saw_read("client_read(len=16) -> 0, nread=0, eos=1"));
    }

    /// An unlimited limiter clamps nothing, because `Curl_rlimit_avail` answers
    /// the maximum offset for one.
    #[test]
    fn client_read_is_unclamped_without_a_limit() {
        let recorder = log();
        let source = ScriptSource::new(&[Step::Data(b"abcd")]);
        let factory = TestFactory::new(&recorder).with_source(&source);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        let mut buf = [0_u8; 16];
        io.client_read(&mut env.ctx(), &mut buf).expect("unclamped");
        assert_eq!(source.asked(), vec![16]);
    }

    // -- the lifecycle ------------------------------------------------------

    /// A chain of both kinds, plus the two counters set to something.
    fn populated_io<'a>(
        factory: &'a TestFactory,
        env: &mut Env,
        recorder: &SharedLog,
    ) -> ClientIo<'a> {
        let mut io = ClientIo::new(factory);
        io.init_writers(&mut env.ctx())
            .expect("the base stack builds");
        io.set_buf(&mut env.ctx(), b"body")
            .expect("a source installs");
        io.readers_mut().insert(
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                recorder,
            )
            .boxed(),
        );
        env.write.bytecount = 99;
        env.write.headerline = 7;
        env.read.reader_started = true;
        io
    }

    /// Cleanup tears BOTH chains down -- readers first -- and resets the two
    /// counters.
    #[test]
    fn client_cleanup_clears_both_chains_and_the_counters() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut env = Env::new();
        let mut io = populated_io(&factory, &mut env, &recorder);

        io.client_cleanup(&mut env.ctx());
        assert!(io.readers().is_empty());
        assert!(io.writers().is_empty());
        assert_eq!(env.write.bytecount, 0);
        assert_eq!(env.write.headerline, 0);
        assert!(!env.read.reader_started);
        assert_eq!(
            recorder.borrow().closes,
            vec!["chunked", "cw-pause", "cw-out"],
            "the readers close before the writers"
        );

        // Cleanup ignores a pending rewind: there is no next request.
        let mut env = Env::new();
        let mut io = populated_io(&factory, &mut env, &recorder);
        env.read.rewind_read = true;
        io.client_cleanup(&mut env.ctx());
        assert!(io.readers().is_empty());
    }

    /// A reset always clears the writers, and clears the readers only when NO
    /// rewind is pending.
    #[test]
    fn client_reset_keeps_the_readers_for_a_pending_rewind() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);

        // No rewind pending: both chains go.
        let mut env = Env::new();
        let mut io = populated_io(&factory, &mut env, &recorder);
        io.client_reset(&mut env.ctx());
        assert!(io.readers().is_empty());
        assert!(io.writers().is_empty());
        assert_eq!(env.write.bytecount, 0);
        assert_eq!(env.write.headerline, 0);
        assert!(env.trace.saw_read("client_reset, clear readers"));

        // A rewind pending: the readers survive so that they CAN be rewound.
        let mut env = Env::new();
        let mut io = populated_io(&factory, &mut env, &recorder);
        io.set_rewind(&mut env.ctx(), true);
        assert!(io.will_rewind(&env.ctx()));
        io.client_reset(&mut env.ctx());
        assert_eq!(io.readers().names(), vec!["chunked", "cr-buf"]);
        assert!(io.writers().is_empty());
        assert!(
            env.read.reader_started,
            "the chain survived, so the flag does too"
        );
        assert!(env.trace.saw_read("client_reset, will rewind reader"));

        io.set_rewind(&mut env.ctx(), false);
        assert!(!io.will_rewind(&env.ctx()));
    }

    /// A start with no rewind pending does nothing at all.
    #[test]
    fn client_start_does_nothing_without_a_pending_rewind() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut env = Env::new();
        let mut io = populated_io(&factory, &mut env, &recorder);
        io.client_start(&mut env.ctx()).expect("nothing to do");
        assert_eq!(io.readers().names(), vec!["chunked", "cr-buf"]);
        assert!(recorder.borrow().controls.is_empty());
        assert!(env.trace.reads.iter().all(|line| !line.contains("rewind")));
    }

    /// A start with a rewind pending rewinds every reader IN ORDER and then
    /// DISCARDS the chain, so an encoding stage starts fresh.
    #[test]
    fn client_start_rewinds_every_reader_and_discards_the_chain() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut env = Env::new();
        let mut io = populated_io(&factory, &mut env, &recorder);
        io.set_rewind(&mut env.ctx(), true);

        io.client_start(&mut env.ctx()).expect("everything rewound");
        assert_eq!(
            recorder.borrow().controls,
            vec![("chunked", ReaderControl::Rewind)],
            "cr-buf's rewind is its own and records nothing"
        );
        assert!(io.readers().is_empty());
        assert!(!env.read.rewind_read);
        assert!(!env.read.reader_started);
        assert!(env.trace.saw_read("client start, rewind readers"));
    }

    /// The FIRST reader that cannot rewind stops the walk, is named in the
    /// diagnostic, and leaves the chain in place.
    #[test]
    fn client_start_reports_the_reader_that_failed_to_rewind() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut env = Env::new();
        let mut io = ClientIo::new(&factory);
        io.set_buf(&mut env.ctx(), b"body")
            .expect("a source installs");
        io.readers_mut().insert(
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                &recorder,
            )
            .control_failing(CURLcode::SendFailRewind)
            .boxed(),
        );
        io.set_rewind(&mut env.ctx(), true);

        let error = io
            .client_start(&mut env.ctx())
            .expect_err("the encoder cannot rewind");
        assert_eq!(error.code(), CURLcode::SendFailRewind);
        assert_eq!(
            error.message(),
            "rewind of client reader 'chunked' failed: 65"
        );
        assert_eq!(
            recorder.borrow().controls,
            vec![("chunked", ReaderControl::Rewind)],
            "the walk stopped, so cr-buf was never asked"
        );
        assert!(
            !io.readers().is_empty(),
            "a failed rewind leaves the chain for the caller to inspect"
        );
        assert!(env.read.rewind_read, "and leaves the request standing");
    }

    /// A whole retry cycle: read, request a rewind, reset, start, and read the
    /// same bytes again.
    #[test]
    fn a_rewind_cycle_reads_the_same_bytes_twice() {
        let recorder = log();
        let source =
            ScriptSource::new(&[Step::Data(b"first"), Step::Data(b"first")])
                .seekable(true);
        let factory = TestFactory::new(&recorder).with_source(&source);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();

        let mut buf = [0_u8; 8];
        let outcome = io
            .client_read(&mut env.ctx(), &mut buf)
            .expect("five bytes");
        assert_eq!(&buf[..outcome.bytes_read], b"first");
        assert!(io.readers().needs_rewind(&mut env.ctx()));

        io.set_rewind(&mut env.ctx(), true);
        io.client_reset(&mut env.ctx());
        assert!(!io.readers().is_empty(), "kept for the rewind");
        io.client_start(&mut env.ctx()).expect("the source rewound");
        assert_eq!(source.seeks(), 1);
        assert!(io.readers().is_empty(), "and then discarded");

        let outcome = io
            .client_read(&mut env.ctx(), &mut buf)
            .expect("the chain is rebuilt and reads again");
        assert_eq!(&buf[..outcome.bytes_read], b"first");
    }

    // -- fuzz-style ---------------------------------------------------------

    /// A deterministic byte generator, so a failure is reproducible.
    fn pseudo_random(seed: &mut u64) -> u8 {
        // xorshift64, chosen because it is four lines and needs no dependency.
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        u8::try_from(*seed & 0xff).unwrap_or(0)
    }

    /// Arbitrary bytes and arbitrary flags through the whole writer chain never
    /// panic, and the sink receives exactly what the limits permit.
    #[test]
    fn arbitrary_writes_do_not_panic_or_reorder() {
        let mut seed = 0x1234_5678_9abc_def0_u64;
        for round in 0..64_u32 {
            let recorder = log();
            let factory = TestFactory::new(&recorder);
            let mut io = ClientIo::new(&factory);
            let mut env = Env::new();
            env.write.size = i64::from(round % 7).wrapping_sub(1);
            env.write.maxdownload = i64::from(round % 5).wrapping_sub(1);
            env.config.max_filesize = i64::from(round % 3);
            env.config.verbose = round % 2 == 0;
            env.write.ignorebody = round % 11 == 0;
            env.write.no_body = round % 13 == 0;
            env.write.header_size = round % 17;

            let len = usize::try_from(round % 32).unwrap_or(0);
            let payload: Vec<u8> =
                (0..len).map(|_| pseudo_random(&mut seed)).collect();

            // Every class, with and without the end-of-stream bit.
            for class in [
                ClientWriteFlags::BODY,
                ClientWriteFlags::INFO,
                ClientWriteFlags::HEADER,
            ] {
                for extra in [ClientWriteFlags::NONE, ClientWriteFlags::EOS] {
                    let flags = class | extra;
                    assert!(flags.is_valid());
                    // Any outcome is acceptable; not panicking is the property.
                    let _ = io.client_write(&mut env.ctx(), flags, &payload);
                }
            }

            // Whatever reached the sink is a PREFIX of what was offered, never
            // a rearrangement of it.
            for record in &recorder.borrow().writes {
                if record.stage != "cw-out" {
                    continue;
                }
                assert!(
                    payload.starts_with(&record.bytes),
                    "round {round}: the sink received bytes that were not a \
                     prefix of the payload"
                );
            }
        }
    }

    /// Arbitrary bytes through the line converter never panic, and the
    /// conversion is exactly "every bare line feed becomes a pair".
    #[test]
    fn arbitrary_bytes_convert_exactly() {
        let mut seed = 0x0fed_cba9_8765_4321_u64;
        for round in 0..64_usize {
            // A payload biased towards carriage returns and line feeds, so that
            // boundaries are actually exercised.
            let len = round * 3 % 97;
            let payload: Vec<u8> = (0..len)
                .map(|_| match pseudo_random(&mut seed) % 4 {
                    0 => b'\n',
                    1 => b'\r',
                    other => b'a' + other,
                })
                .collect();

            // The expected form, computed independently of the implementation:
            // a line feed whose predecessor is not a carriage return grows a
            // carriage return in front of it.
            let mut expected = Vec::with_capacity(payload.len() * 2);
            let mut prev_cr = false;
            for &byte in &payload {
                if byte == b'\n' && !prev_cr {
                    expected.push(b'\r');
                }
                expected.push(byte);
                prev_cr = byte == b'\r';
            }

            let mut stage = CrLineConv::new();
            stage
                .convert_into_queue(&payload)
                .expect("the conversion cannot fail on a soft-limit queue");

            let mut env = Env::new();
            let mut produced = Vec::new();
            let mut buf = [0_u8; 8];
            while stage.buffered() > 0 {
                let outcome = read_alone(&mut stage, &mut env, &mut buf)
                    .expect("the queue drains");
                assert!(
                    outcome.bytes_read > 0,
                    "round {round}: a non-empty queue must yield something"
                );
                produced.extend_from_slice(&buf[..outcome.bytes_read]);
            }
            assert_eq!(
                produced, expected,
                "round {round}: payload {payload:?}"
            );
        }
    }

    /// Arbitrary reads through a converter over a callback source never panic,
    /// always terminate, and deliver exactly the converted stream however the
    /// destination is sliced.
    ///
    /// The script is one byte a step, because a source hands back whatever the
    /// destination can hold and the destination here is as small as one byte.
    /// That is also the interesting shape: a bare line feed alone in a one-byte
    /// buffer converts to TWO bytes, so the queue and the deferred end of
    /// stream are exercised on every round.
    #[test]
    fn arbitrary_reads_terminate() {
        // No carriage return anywhere, so the shortcut documented on
        // `CrLineConv::read` -- a buffer with no line feed leaves `prev_cr`
        // untouched -- cannot make the expectation depend on the slicing.
        const SCRIPT: &[Step] = &[
            Step::Data(b"a"),
            Step::Data(b"\n"),
            Step::Data(b"b"),
            Step::Data(b"b"),
            Step::Data(b"\n"),
            Step::Pause,
            Step::Data(b"c"),
            Step::Data(b"\n"),
        ];
        let mut seed = 0xdead_beef_cafe_babe_u64;
        for chunk in 1..24_usize {
            let recorder = log();
            let source = ScriptSource::new(SCRIPT);
            let factory = TestFactory::new(&recorder).with_source(&source);
            let mut io = ClientIo::new(&factory);
            let mut env = Env::new();
            env.config.crlf = pseudo_random(&mut seed) % 2 == 0;

            let mut buf = vec![0_u8; chunk];
            let mut produced = Vec::new();
            let mut guard = 0;
            loop {
                guard += 1;
                assert!(guard < 256, "chunk {chunk}: the chain never settled");
                let outcome =
                    io.client_read(&mut env.ctx(), &mut buf).unwrap_or_else(
                        |error| panic!("chunk {chunk}: unexpected {error:?}"),
                    );
                produced.extend_from_slice(&buf[..outcome.bytes_read]);
                if outcome.eos {
                    break;
                }
                if outcome.bytes_read == 0 {
                    // A pause is a successful read of nothing. Lift it and
                    // carry on, which is what the transfer loop does once the
                    // application unpauses the handle.
                    io.readers_mut()
                        .unpause(&mut env.ctx())
                        .expect("unpausing cannot fail here");
                }
            }
            let expected: &[u8] = if env.config.crlf {
                b"a\r\nbb\r\nc\r\n"
            } else {
                b"a\nbb\nc\n"
            };
            assert_eq!(produced, expected, "chunk {chunk}");
            assert!(
                env.guard.balanced(),
                "chunk {chunk}: the in-callback flag was left raised"
            );
        }
    }

    // -- the untraced configuration, and every defaulted member -------------

    /// A transfer that is not tracing reaches every emitter and produces
    /// nothing, and a `failf` still carries its text on the error.
    #[test]
    fn a_context_without_a_trace_sink_is_silent() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        // Verbose, so the raw stage reaches `debug`; a body, so the download
        // stage reaches `trc_write`.
        env.config.verbose = true;

        io.client_write(
            &mut env.untraced_ctx(),
            ClientWriteFlags::BODY,
            b"body",
        )
        .expect("an untraced write works");
        io.client_write(
            &mut env.untraced_ctx(),
            ClientWriteFlags::HEADER,
            b"X: 1\r\n",
        )
        .expect("an untraced header write works");

        let mut buf = [0_u8; 8];
        io.set_buf(&mut env.untraced_ctx(), b"up")
            .expect("installs");
        let outcome = io
            .client_read(&mut env.untraced_ctx(), &mut buf)
            .expect("an untraced read works");
        assert_eq!(outcome, ReadOutcome::new(2, true));

        // `failf` without a sink: the text lives on the error, which is what
        // reaches `CURLOPT_ERRORBUFFER` in the C whether tracing is on or not.
        env.write.no_body = true;
        env.write.header_size = 0;
        let error = io
            .client_write(&mut env.untraced_ctx(), ClientWriteFlags::BODY, b"x")
            .expect_err("a body arrived for a no-body request");
        assert_eq!(error.code(), CURLcode::WeirdServerReply);

        // `infof` without a sink, through the excess report.
        let mut env = Env::new();
        env.write.maxdownload = 1;
        io.client_write(&mut env.untraced_ctx(), ClientWriteFlags::BODY, b"ab")
            .expect("the permitted prefix is written");
        assert_eq!(
            env.control.conn_closes,
            vec!["excess found in a read"],
            "the report reached the engine even with no sink to describe it"
        );

        assert!(
            env.trace.reads.is_empty() && env.trace.writes.is_empty(),
            "nothing can reach a sink that was never installed"
        );
    }

    /// Every defaulted member of [`ClientWriter`] behaves as the C's
    /// `Curl_cwriter_def_*` do.
    #[test]
    fn the_default_writer_members_are_the_c_defaults() {
        /// A stage that overrides NOTHING but its identity.
        #[derive(Debug)]
        struct Bare;

        impl ClientWriter for Bare {
            fn kind(&self) -> ClientWriterKind {
                ClientWriterKind::Custom("bare")
            }

            fn phase(&self) -> ClientWriterPhase {
                ClientWriterPhase::TransferDecode
            }
        }

        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientWriterStack::new();
        stack.insert(
            RecordingWriter::sink(ClientWriterKind::ClientOut, &recorder)
                .boxed(),
        );
        stack.insert(Box::new(Bare));
        assert_eq!(stack.names(), vec!["bare", "cw-out"]);

        // `Curl_cwriter_def_write` (`lib/sendf.c:143-150`) forwards unchanged.
        stack
            .write(&mut env.ctx(), ClientWriteFlags::BODY, b"through")
            .expect("the default write forwards");
        assert_eq!(recorder.borrow().writes[0].bytes, b"through");

        // The C has no `is_paused` or `unpause` member on `Curl_cwtype` at all:
        // `Curl_cwriter_is_paused` and `_unpause` (`:505-513`) ask the CLIENT
        // stage alone, so every other stage answers "not paused" and does
        // nothing when unpaused. The default members here are that answer.
        assert!(!Bare.is_paused());
        stack
            .unpause(&mut env.ctx())
            .expect("the default unpause is a no-op that succeeds");
        assert_eq!(
            recorder.borrow().unpauses,
            vec!["cw-out"],
            "the recording client stage recorded its own; `bare` had nothing \
             to record"
        );

        // `Curl_cwriter_def_init` and `_def_close` (`:137-141`, `:152-157`).
        let mut bare =
            ClientWriterStack::create(Box::new(Bare), &mut env.ctx())
                .expect("the default init succeeds");
        bare.close(&mut env.ctx());
    }

    /// Every defaulted member of [`ClientReader`] behaves as the C's
    /// `Curl_creader_def_*` do.
    #[test]
    fn the_default_reader_members_are_the_c_defaults() {
        /// A stage that overrides NOTHING but its identity.
        #[derive(Debug)]
        struct Bare;

        impl ClientReader for Bare {
            fn kind(&self) -> ClientReaderKind {
                ClientReaderKind::Custom("bare")
            }

            fn phase(&self) -> ClientReaderPhase {
                ClientReaderPhase::TransferEncode
            }
        }

        let mut env = Env::new();
        let mut stack = ClientReaderStack::new();
        stack.insert(Box::new(CrBuf::new(b"below")));
        stack.insert(Box::new(Bare));
        assert_eq!(stack.names(), vec!["bare", "cr-buf"]);

        // `Curl_creader_def_read` (`:558-566`) forwards.
        let mut buf = [0_u8; 8];
        assert_eq!(
            stack.read(&mut env.ctx(), &mut buf).expect("forwarded"),
            ReadOutcome::new(5, true)
        );
        assert_eq!(&buf[..5], b"below");

        // `Curl_creader_def_total_length` (`:573-578`): the answer from below.
        assert_eq!(stack.total_length(), 5);
        // `Curl_creader_def_needs_rewind` (`:568-571`): false, even though the
        // stage below now DOES need one -- the walk asks every stage, so this
        // proves the default answers for itself rather than delegating.
        assert!(!Bare.needs_rewind());
        assert!(stack.needs_rewind(&mut env.ctx()));
        // `Curl_creader_def_is_paused` (`:606-610`): false.
        assert!(!Bare.is_paused());
        assert!(!stack.is_paused());
        // `Curl_creader_def_cntrl` (`:598-604`): succeeds and does nothing.
        // Reached twice, because the two walks treat a control differently:
        // `Curl_creader_clear_eos` discards every answer while
        // `Curl_creader_unpause` stops at the first failure -- so the default
        // succeeding is what keeps the second walk going.
        stack.clear_eos(&mut env.ctx());
        stack
            .unpause(&mut env.ctx())
            .expect("the default control succeeds");
        // `Curl_creader_def_done` (`:612-614`): no-op.
        stack.done(&mut env.ctx(), true);

        // `Curl_creader_def_resume_from` (`:580-587`): CURLE_READ_ERROR. Asked
        // of the stage directly, because the chain walk goes to the CLIENT
        // phase and `cr-buf` implements its own.
        let mut empty = no_readers();
        let tail = ReaderTail::new(&mut empty);
        assert!(tail.is_empty());
        assert_eq!(tail.len(), 0);
        let mut bare = Bare;
        assert_eq!(
            bare.resume_from(&mut env.ctx(), 4)
                .expect_err("the default cannot resume")
                .code(),
            CURLcode::ReadError
        );

        // `Curl_creader_def_init` and `_def_close` (`:537-541`, `:552-556`),
        // and `Curl_creader_free` (`:949-955`) for a stage in no chain at all.
        let bare = ClientReaderStack::create(Box::new(Bare), &mut env.ctx())
            .expect("the default init succeeds");
        ClientReaderStack::free(bare, &mut env.ctx());
    }

    /// A tail knows how many stages are still beneath it.
    #[test]
    fn a_reader_tail_reports_what_is_beneath_it() {
        /// A stage that answers with the shape of the chain below it.
        #[derive(Debug)]
        struct Counting(Rc<Cell<(usize, bool)>>);

        impl ClientReader for Counting {
            fn kind(&self) -> ClientReaderKind {
                ClientReaderKind::Custom("counting")
            }

            fn phase(&self) -> ClientReaderPhase {
                ClientReaderPhase::TransferEncode
            }

            fn read(
                &mut self,
                ctx: &mut ClientCtx<'_>,
                tail: &mut ReaderTail<'_, '_>,
                buf: &mut [u8],
            ) -> CurlResult<ReadOutcome> {
                self.0.set((tail.len(), tail.is_empty()));
                tail.read(ctx, buf)
            }
        }

        let seen = Rc::new(Cell::new((usize::MAX, false)));
        let mut env = Env::new();
        let mut stack = ClientReaderStack::new();
        stack.insert(Box::new(CrNull::new()));
        stack.insert(Box::new(CrLineConv::new()));
        stack.insert(Box::new(Counting(Rc::clone(&seen))));
        assert_eq!(stack.names(), vec!["counting", "cr-lineconv", "cr-null"]);

        let mut buf = [0_u8; 4];
        stack
            .read(&mut env.ctx(), &mut buf)
            .expect("the chain reads");
        assert_eq!(
            seen.get(),
            (2, false),
            "the converter and the null source were beneath it"
        );
    }

    // -- the remaining branches of the ported logic -------------------------

    /// `get_max_body_write_len(data, -1)` is unbounded --
    /// `lib/sendf.c:159-166`.
    #[test]
    fn the_body_write_limit_is_unbounded_for_minus_one() {
        let state = RequestWriteState {
            bytecount: 40,
            ..RequestWriteState::default()
        };
        assert_eq!(
            DownloadWriter::max_body_write_len(&state, -1),
            usize::MAX,
            "-1 means no limit, and the count already written is irrelevant"
        );
        // And the limited form, for contrast: what is left of the allowance.
        assert_eq!(DownloadWriter::max_body_write_len(&state, 100), 60);
        assert_eq!(
            DownloadWriter::max_body_write_len(&state, 10),
            0,
            "an allowance already exceeded permits nothing, never a wrap"
        );
    }

    /// A header write that the stage below refuses is reported with ITS code,
    /// through the download stage's own trace line.
    #[test]
    fn download_writer_reports_a_failed_header_forward() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = ClientWriterStack::new();
        stack.insert(
            RecordingWriter::new(
                ClientWriterKind::ClientOut,
                ClientWriterPhase::Client,
                &recorder,
            )
            .failing(CURLcode::WriteError)
            .boxed(),
        );
        stack.insert(Box::new(DownloadWriter::new()));

        let error = stack
            .write(&mut env.ctx(), ClientWriteFlags::HEADER, b"X: 1\r\n")
            .expect_err("the stage below refused the header");
        assert_eq!(error.code(), CURLcode::WriteError);
        assert!(env
            .trace
            .saw_write("download_write header(type=4, blen=6) -> 23"));
    }

    /// A resume that has to discard, with no source to discard from, reports
    /// the short read rather than looping.
    #[test]
    fn cr_in_resume_without_a_source_cannot_discard() {
        let mut stage = CrIn::new(None, -1);
        let mut env = Env::new();
        let error = stage
            .resume_from(&mut env.ctx(), 100)
            .expect_err("nothing can be discarded");
        assert_eq!(error.code(), CURLcode::ReadError);
        assert_eq!(
            error.message(),
            "Could only read 0 bytes from the input",
            "the count is what was passed, which is nothing"
        );
    }

    /// A source that reports a failed rewind is traced and then falls through
    /// to the same impossibility as one that cannot rewind at all.
    #[test]
    fn cr_in_rewind_reports_a_source_whose_seek_failed() {
        let source = ScriptSource::new(&[Step::Data(b"x")]).seekable(false);
        let mut stage = CrIn::new(Some(source.boxed()), -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 4];
        read_alone(&mut stage, &mut env, &mut buf).expect("one byte");

        let error = rewind(&mut stage, &mut env)
            .expect_err("the source refused to seek");
        assert_eq!(error.code(), CURLcode::SendFailRewind);
        assert_eq!(error.message(), "necessary data rewind was not possible");
        assert_eq!(source.seeks(), 1);
        assert!(env
            .trace
            .reads
            .iter()
            .any(|line| line.starts_with("cr_in, rewind via source seek -> ")
                && !line.ends_with("-> 0")));
    }

    /// A source that does not implement `seek_to_start` at all answers [`None`]
    /// through the trait's default -- the C's `fread_func != fread`.
    #[test]
    fn a_source_that_is_not_the_default_one_cannot_seek() {
        /// A source with only the one required member.
        #[derive(Debug)]
        struct Minimal(usize);

        impl ClientReadSource for Minimal {
            fn read(&mut self, buf: &mut [u8]) -> SourceRead {
                if self.0 == 0 || buf.is_empty() {
                    return SourceRead::Bytes(0);
                }
                self.0 -= 1;
                buf[0] = b'z';
                SourceRead::Bytes(1)
            }
        }

        let mut minimal = Minimal(1);
        assert!(
            minimal.seek_to_start().is_none(),
            "the default answer is `no seek of my own`"
        );
        let mut one = [0_u8; 1];
        assert_eq!(minimal.read(&mut one), SourceRead::Bytes(1));
        assert_eq!(
            minimal.read(&mut one),
            SourceRead::Bytes(0),
            "and then it is exhausted"
        );

        let mut stage = CrIn::new(Some(Box::new(Minimal(1))), -1);
        let mut env = Env::new();
        let mut buf = [0_u8; 4];
        read_alone(&mut stage, &mut env, &mut buf).expect("one byte");
        assert_eq!(
            rewind(&mut stage, &mut env)
                .expect_err("no strategy is available")
                .code(),
            CURLcode::SendFailRewind
        );
    }

    /// Once the converter has reported the end of its stream it repeats that
    /// answer -- `lib/sendf.c:991-995`.
    #[test]
    fn lineconv_repeats_the_end_of_stream() {
        let recorder = log();
        let mut env = Env::new();
        let mut stack = lineconv_chain(&recorder, b"no line feeds");

        let mut buf = [0_u8; 32];
        assert!(
            stack.read(&mut env.ctx(), &mut buf).expect("the bytes").eos,
            "the source reported the end with its bytes"
        );
        for _ in 0..3 {
            assert_eq!(
                stack.read(&mut env.ctx(), &mut buf).expect("repeated"),
                ReadOutcome::EOS
            );
        }
        assert_eq!(
            recorder.borrow().reads.len(),
            1,
            "the stage below was never consulted again"
        );
    }

    /// A drain into a destination with no room reports [`CURLcode::Again`] and
    /// traces it, which is the C falling through to its `out:` label.
    #[test]
    fn lineconv_traces_a_failed_drain() {
        let mut stage = CrLineConv::default();
        stage
            .convert_into_queue(b"a\nb")
            .expect("the conversion fills the queue");
        assert_eq!(stage.buffered(), 4);

        let mut env = Env::new();
        let mut empty = no_readers();
        let mut tail = ReaderTail::new(&mut empty);
        // Scoped, so the context's borrow of the environment ends before the
        // sink it wrote to is inspected.
        let error = {
            let mut ctx = env.ctx();
            stage
                .read(&mut ctx, &mut tail, &mut [])
                .expect_err("there is nowhere to put the bytes")
        };
        assert_eq!(error.code(), CURLcode::Again);
        assert!(env
            .trace
            .saw_read("cr_lc_read(len=0) -> 81, nread=0, eos=0"));
        assert_eq!(stage.buffered(), 4, "and nothing was consumed");
    }

    /// The queue helper reports a queue that cannot take the bytes rather than
    /// dropping them.
    #[test]
    fn the_queue_helper_reports_a_queue_that_cannot_grow() {
        // A HARD limit: one chunk of four bytes and no soft-limit flag, which
        // is the one shape `queue_write_all`'s own note says it must survive.
        let mut queue = BufQ::with_opts(4, 1, BufqOpts::NONE);
        queue_write_all(&mut queue, b"abcd").expect("exactly one chunk");
        assert_eq!(queue.len(), 4);
        let error = queue_write_all(&mut queue, b"e")
            .expect_err("the queue is full and cannot grow");
        assert_eq!(error.code(), CURLcode::Again);
        assert_eq!(queue.len(), 4, "and nothing was lost or duplicated");
    }

    /// The stream source retries an interrupted read and reports any other
    /// failure as the end of the file, which is what `fread` does.
    #[test]
    fn the_stream_source_retries_an_interruption() {
        /// A reader that fails in a scripted way.
        #[derive(Debug)]
        struct Fussy {
            script: VecDeque<std::io::ErrorKind>,
            tail: Cursor<Vec<u8>>,
        }

        impl Read for Fussy {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                match self.script.pop_front() {
                    Some(kind) => Err(std::io::Error::from(kind)),
                    None => self.tail.read(buf),
                }
            }
        }

        impl Seek for Fussy {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                self.tail.seek(pos)
            }
        }

        // Two interruptions in a row, then real bytes.
        let mut source = StreamReadSource::new(Fussy {
            script: VecDeque::from(vec![
                std::io::ErrorKind::Interrupted,
                std::io::ErrorKind::Interrupted,
            ]),
            tail: Cursor::new(b"payload".to_vec()),
        });
        let mut buf = [0_u8; 8];
        assert_eq!(source.read(&mut buf), SourceRead::Bytes(7));
        assert_eq!(&buf[..7], b"payload");

        // Any other failure is indistinguishable from the end of the file.
        let mut source = StreamReadSource::new(Fussy {
            script: VecDeque::from(vec![std::io::ErrorKind::PermissionDenied]),
            tail: Cursor::new(b"never reached".to_vec()),
        });
        assert_eq!(source.read(&mut buf), SourceRead::Bytes(0));

        // And it answers `Some` for a rewind, because it IS the default source
        // the C's `fread_func == fread` test is looking for.
        assert!(matches!(source.seek_to_start(), Some(Ok(()))));
    }

    /// A reader stage that fails is reported with its own code, through
    /// `client_read`'s trace line.
    #[test]
    fn client_read_reports_a_stage_failure() {
        let recorder = log();
        let factory = TestFactory::new(&recorder);
        let mut io = ClientIo::new(&factory);
        let mut env = Env::new();
        io.set_buf(&mut env.ctx(), b"never reached")
            .expect("installs");
        io.readers_mut().insert(
            RecordingReader::new(
                ClientReaderKind::ChunkedEncode,
                ClientReaderPhase::TransferEncode,
                &recorder,
            )
            .failing(CURLcode::AbortedByCallback)
            .boxed(),
        );

        let mut buf = [0_u8; 8];
        let error = io
            .client_read(&mut env.ctx(), &mut buf)
            .expect_err("the encoder failed");
        assert_eq!(error.code(), CURLcode::AbortedByCallback);
        assert!(env
            .trace
            .saw_read("client_read(len=8) -> 42, nread=0, eos=0"));
    }

    /// The two chains and the converter each have a [`Default`] that is the
    /// empty state, so a struct that holds one need not name a constructor.
    #[test]
    fn the_chains_and_the_converter_default_to_empty() {
        let writers = ClientWriterStack::default();
        assert!(writers.is_empty());
        assert_eq!(writers.len(), 0);
        let readers = ClientReaderStack::default();
        assert!(readers.is_empty());
        assert_eq!(readers.len(), 0);
        let converter = CrLineConv::default();
        assert_eq!(converter.buffered(), 0);
        assert!(!converter.prev_cr());
    }
}
