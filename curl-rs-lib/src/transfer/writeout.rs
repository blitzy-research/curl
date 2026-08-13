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
// THE LICENCE BANNER ABOVE, byte-identical to the banner that
// heads `lib/cw-out.c:1-23` with the C block comment converted to line
// comments, and byte-identical to the banners of `transfer/sendf.rs`,
// `transfer/progress.rs` and `transfer/ratelimit.rs` beside it. The licence
// tag appears exactly once, on line 21, and nowhere else in this file -- not
// even in prose -- because `reuse` reads every line carrying the tag's colon
// form as a licence expression, so a second mention becomes a parse error
// rather than a comment.
//
// `dead_code` IS NOT ALLOWED for this file as a whole, and no attribute below
// grants it at module scope. Each unreferenced item carries its own
// `#[allow(dead_code)]` naming the consumer it belongs to, so the suppressions
// read as an inventory: every one is load-bearing, deleting any one restores a
// warning, and an item added later with no consumer is still reported. That is
// enforced rather than agreed -- `mod source_policy` in
// `curl-rs-lib/src/lib.rs` walks the workspace at test time and fails on a
// `dead_code` level set on any crate root or module root.

//! The client-output and pause-handling writer stages -- supersedes
//! `lib/cw-out.c` with `lib/cw-out.h` and `lib/cw-pause.c` with
//! `lib/cw-pause.h`.
//!
//! Measured against `lib/cw-out.c:36-517` and `lib/cw-pause.c:34-225`, with
//! the writer contract from `lib/sendf.h:42-140` and `lib/sendf.c:128-513`,
//! the header collector from `lib/headers.c:292-346`, the buffer policies from
//! `lib/curlx/dynbuf.c` and `lib/bufq.c`, and the callback vocabulary from
//! `include/curl/curl.h:258-282` and `:3256-3263`.
//!
//! # Why two C files become one Rust module
//!
//! `lib/cw-out.c` and `lib/cw-pause.c` are one mechanism split across two
//! translation units, and the split is an artefact of C rather than a
//! boundary in the design. Three facts make that concrete:
//!
//! * `lib/cw-out.c` includes `cw-pause.h` and calls `Curl_cw_pause_flush`
//!   from BOTH of its two entry points (`:497` and `:512`). The dependency is
//!   one-way and unconditional: unpausing or finishing a transfer means
//!   draining the in-flight buffer and then the output buffer, in that order.
//! * Neither file's state is reachable from the other's without going through
//!   the chain, and neither is reachable from anywhere else: `cw-out.h`
//!   exports three functions and one writer type, `cw-pause.h` exports one
//!   function and one writer type, and that is the whole of their surface.
//! * They divide ONE requirement -- "a paused transfer replays its bytes
//!   exactly as they arrived" -- into the half that buffers what the client
//!   refused ([`ClientOutWriter`]) and the half that buffers what the server
//!   had already sent ([`PauseWriter`]). Reading either alone leaves the
//!   ordering guarantee unexplained.
//!
//! # HEADER and BODY interleave, and the interleaving is observable
//!
//! `lib/cw-out.c:58-61` states the model: *"HEADER and BODY data may arrive
//! in any order. For paused transfers, a list of `struct cw_out_buf` is kept
//! for `cw_out_type` types. The list may be:
//! \[BODY\]->\[HEADER\]->\[BODY\]->\[HEADER\]....  When unpausing, this list
//! is 'played back' to the client callbacks."*
//!
//! The C expresses that queue as a singly linked list that grows at the HEAD
//! and is flushed from the TAIL by a recursive walk (`:302-338`). Here it is a
//! [`VecDeque`] that grows at the back and is flushed from the front, which is
//! the same order stated directly.
//!
//! # What this module does NOT do
//!
//! It does not name `transfer/mod.rs`, and it does not name a connection, a
//! socket or a TLS type. The one operation it needs from the transfer loop --
//! `Curl_xfer_pause_recv`, called at `lib/cw-out.c:205` -- arrives through
//! [`TransferControl::pause_recv`], and the application's callbacks arrive
//! through [`ClientOutput`]. Both are seams that the dependency-last engine
//! implements, which is what keeps the C's `sendf.h` / `cw-out.h` /
//! `cw-pause.h` include cycle from becoming a module cycle.
//!
//! Payloads are bytes throughout.

use core::fmt;
use std::collections::VecDeque;

use crate::error::{CURLcode, CurlResult, Error};
use crate::headers::{classify_origin, HeaderStore};
use crate::transfer::sendf::{
    ClientCtx, ClientIoFactory, ClientWriteFlags, ClientWriter,
    ClientWriterKind, ClientWriterPhase, ClientWriterStack, TransferControl,
    WriterTail,
};
use crate::util::bufq::{BufQ, BufqOpts};
use crate::util::dynbuf::{DynBuf, DYN_PAUSE_BUFFER};

// The ABI vocabulary -- `include/curl/curl.h:258-282` and `:3256-3263`

/// The largest chunk a body write callback is ever handed.
pub(crate) const CURL_MAX_WRITE_SIZE: usize = 16384;

/// The count a write callback returns to pause the transfer.
pub(crate) const CURL_WRITEFUNC_PAUSE: usize = 0x1000_0001;

/// The count a write callback returns to fail the transfer.
///
/// Note what this is NOT: it is 0xFFFFFFFF, and on a 64-bit target that is
/// 4,294,967,295 rather than [`usize::MAX`]. A callback that returns
/// `(size_t)-1` therefore does not match, and is reported as a short write
/// instead. That asymmetry is the C's, at `lib/cw-out.c:208`, and it is
/// preserved because the value is fixed by the header.
pub(crate) const CURL_WRITEFUNC_ERROR: usize = 0xFFFF_FFFF;

/// `CURLPAUSE_RECV` (`include/curl/curl.h:3256`): pause the receive
/// direction.
pub(crate) const CURLPAUSE_RECV: i32 = 1 << 0;

/// `CURLPAUSE_RECV_CONT` (`include/curl/curl.h:3257`): resume the receive
/// direction.
///
/// Zero, because `curl_easy_pause` takes a bitmask of what should REMAIN
/// paused: an absent bit is a resumed direction, so the "continue" spelling is
/// the absence of the pause bit rather than a bit of its own.
pub(crate) const CURLPAUSE_RECV_CONT: i32 = 0;

/// `CURLPAUSE_SEND` (`include/curl/curl.h:3259`): pause the send direction.
///
/// `1 << 2` and not `1 << 1`. The bit between them is unused, and the gap is
/// historical: it is part of the ABI and cannot be closed.
pub(crate) const CURLPAUSE_SEND: i32 = 1 << 2;

/// `CURLPAUSE_SEND_CONT` (`include/curl/curl.h:3260`): resume the send
/// direction.
pub(crate) const CURLPAUSE_SEND_CONT: i32 = 0;

/// `CURLPAUSE_ALL` (`include/curl/curl.h:3262`): pause both directions.
pub(crate) const CURLPAUSE_ALL: i32 = CURLPAUSE_RECV | CURLPAUSE_SEND;

/// `CURLPAUSE_CONT` (`include/curl/curl.h:3263`): resume both directions.
pub(crate) const CURLPAUSE_CONT: i32 =
    CURLPAUSE_RECV_CONT | CURLPAUSE_SEND_CONT;

/// `curl_easy_pause`'s bitmask, read rather than guessed at.
///
/// # Why the "continue" spellings are both zero, and why that is not a bug
///
/// `CURLPAUSE_RECV_CONT` and `CURLPAUSE_SEND_CONT` are both `0`, so they carry
/// no information on their own: a mask of `CURLPAUSE_RECV_CONT` is
/// indistinguishable from `CURLPAUSE_CONT`. That is deliberate in the C -- the
/// mask names what should remain paused, and everything unnamed resumes -- and
/// it means [`Self::pauses_recv`] and [`Self::pauses_send`] are the only
/// questions the mask can answer. There is no "leave this direction alone"
/// state to ask about.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PauseBits(i32);

impl PauseBits {
    /// `CURLPAUSE_RECV`: the receive direction stays paused.
    #[allow(dead_code)] // consumer: easy/setopt.rs, curl_easy_pause
    pub(crate) const RECV: Self = Self(CURLPAUSE_RECV);

    /// `CURLPAUSE_SEND`: the send direction stays paused.
    #[allow(dead_code)] // consumer: easy/setopt.rs, curl_easy_pause
    pub(crate) const SEND: Self = Self(CURLPAUSE_SEND);

    /// `CURLPAUSE_ALL`: both directions stay paused.
    #[allow(dead_code)] // consumer: easy/setopt.rs, curl_easy_pause
    pub(crate) const ALL: Self = Self(CURLPAUSE_ALL);

    /// `CURLPAUSE_CONT`: both directions resume.
    #[allow(dead_code)] // consumer: easy/setopt.rs, curl_easy_pause
    pub(crate) const CONT: Self = Self(CURLPAUSE_CONT);

    /// The mask an application passed to `curl_easy_pause`.
    ///
    /// Unrecognised bits are PRESERVED rather than masked away. The C does not
    /// validate the mask either -- `lib/easy.c` tests the two bits it knows and
    /// ignores the rest -- and discarding them here would hide a caller's
    /// mistake from [`Self::bits`].
    #[allow(dead_code)] // consumer: easy/setopt.rs, curl_easy_pause
    pub(crate) const fn from_bits(bits: i32) -> Self {
        Self(bits)
    }

    /// The raw mask, for the ABI shim that received it.
    #[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/easy.rs
    pub(crate) const fn bits(self) -> i32 {
        self.0
    }

    /// Whether the receive direction is to remain paused.
    ///
    /// This is the bit [`ClientOutWriter`] answers to: a mask without it means
    /// [`unpause`] should run.
    #[allow(dead_code)] // consumer: easy/setopt.rs, curl_easy_pause
    pub(crate) const fn pauses_recv(self) -> bool {
        (self.0 & CURLPAUSE_RECV) != 0
    }

    /// Whether the send direction is to remain paused.
    ///
    /// Answered by the READER chain rather than by anything here; the method
    /// lives beside its twin so that the vocabulary is not split across two
    /// modules.
    #[allow(dead_code)] // consumer: easy/setopt.rs, curl_easy_pause
    pub(crate) const fn pauses_send(self) -> bool {
        (self.0 & CURLPAUSE_SEND) != 0
    }
}

/// What a write callback answered.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
// Every variant is MATCHED below, so the allowance covers construction only.
#[allow(dead_code)]
pub(crate) enum ClientWriteOutcome {
    /// The callback claims to have consumed this many bytes.
    ///
    /// A count that is not exactly the length offered is an ERROR in libcurl,
    /// not a short write to be retried, and [`ClientOutWriter`] enforces that.
    /// The count is therefore carried through unclamped so the diagnostic can
    /// report what the application actually said.
    Written(usize),
    /// `CURL_WRITEFUNC_PAUSE`: stop delivering data until the application
    /// unpauses the transfer.
    Pause,
    /// `CURL_WRITEFUNC_ERROR`: fail the transfer now.
    Error,
}

impl ClientWriteOutcome {
    /// Classifies the count a callback returned.
    ///
    /// The two sentinels are tested in the C's order (`lib/cw-out.c:195` then
    /// `:208`). The order cannot matter -- the values differ -- and it is
    /// preserved so a reader diffing the two files finds the branches where
    /// they were.
    #[must_use]
    #[allow(dead_code)] // consumer: curl-rs-ffi/src/ffi/easy.rs
    pub(crate) const fn from_callback_count(count: usize) -> Self {
        if count == CURL_WRITEFUNC_PAUSE {
            Self::Pause
        } else if count == CURL_WRITEFUNC_ERROR {
            Self::Error
        } else {
            Self::Written(count)
        }
    }

    /// The count a C callback would have returned for this outcome.
    ///
    /// The inverse of [`Self::from_callback_count`] on every value it can
    /// produce, and what the trace line at `lib/cw-out.c:192-194` prints: the C
    /// traces `nwritten` BEFORE classifying it, so a paused transfer's trace
    /// carries the sentinel and not a byte count.
    #[must_use]
    pub(crate) const fn to_callback_count(self) -> usize {
        match self {
            Self::Written(count) => count,
            Self::Pause => CURL_WRITEFUNC_PAUSE,
            Self::Error => CURL_WRITEFUNC_ERROR,
        }
    }
}

/// The application's output configuration: two callbacks, two destinations and
/// one flag.
///
/// Supersedes the five `data->set` members that `cw_get_writefunc` and
/// `cw_out_write` read (`lib/cw-out.c:144-172` and `:426-427`):
///
/// | C member | method here |
/// |---|---|
/// | `fwrite_func` | [`Self::has_body_write`], [`Self::write_body`] |
/// | `out` | the destination [`Self::write_body`] writes to |
/// | `fwrite_header` | [`Self::has_header_write`], [`Self::write_header`] |
/// | `writeheader` | [`Self::has_header_target`] |
/// | `include_header` | [`Self::include_header`] |
pub(crate) trait ClientOutput: fmt::Debug {
    /// Whether `CURLOPT_WRITEFUNCTION` is installed.
    ///
    /// False makes a body write succeed while consuming everything, which is
    /// the C's `if(!wcb) { *pconsumed = blen; return CURLE_OK; }`
    /// (`lib/cw-out.c:240-243`). It is not an error and never has been.
    fn has_body_write(&self) -> bool;

    /// Whether `CURLOPT_HEADERFUNCTION` is installed.
    fn has_header_write(&self) -> bool;

    /// Whether `CURLOPT_HEADERDATA` -- the C's `writeheader`, reached through
    /// the `CURLOPT_WRITEHEADER` alias as well -- is set.
    fn has_header_target(&self) -> bool;

    /// `CURLOPT_HEADER`: whether headers are ALSO written to the body stream.
    ///
    /// Read at `lib/cw-out.c:427`. It is what makes `curl -i` include the
    /// response headers in the saved body, and it is the one setting in this
    /// trait that routes rather than delivers.
    fn include_header(&self) -> bool;

    /// `fwrite_func(buffer, 1, len, out)`.
    ///
    /// The C's four arguments become one slice: `size` is always 1 and
    /// `nitems` is always the length (`lib/cw-out.c:190`), so the product the
    /// callback is expected to multiply is the slice's length, and the
    /// destination is the implementation's own.
    fn write_body(&mut self, bytes: &[u8]) -> ClientWriteOutcome;

    /// `fwrite_header(buffer, 1, len, writeheader)`.
    fn write_header(&mut self, bytes: &[u8]) -> ClientWriteOutcome;

    /// `fwrite_func(buffer, 1, len, writeheader)` -- the crossed pairing.
    ///
    /// The body callback with the HEADER destination, reached when
    /// `CURLOPT_HEADERDATA` is set and `CURLOPT_HEADERFUNCTION` is not.
    fn write_body_to_header_target(
        &mut self,
        bytes: &[u8],
    ) -> ClientWriteOutcome;
}

/// The transfer's header store, and the request it is currently on.
///
/// A seam and not an owned field, because the store outlives the writer chain:
/// `curl_easy_header` is answerable after a transfer has finished and its
/// writers have been torn down, so [`HeaderCollectWriter`] must write THROUGH
/// to state the engine owns rather than accumulate its own copy.
pub(crate) trait HeaderStoreHandle: fmt::Debug {
    /// `data->state.httphdrs`, mutably.
    fn store(&mut self) -> &mut HeaderStore;

    /// `data->state.requests`: 0 for the first request, then 1, 2 and so on.
    fn request(&self) -> i32;
}

// `cw-out` -- the client-output stage, `lib/cw-out.c:66-517`

/// Which of the client's two streams a buffered run of bytes belongs to.
///
/// Supersedes `cw_out_type` (`lib/cw-out.c:66-71`). All four values are kept,
/// including the sentinel, because the sentinel is load-bearing: see
/// [`Self::None`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum OutBufKind {
    /// `CW_OUT_NONE` (`lib/cw-out.c:67`): no stream.
    None,
    /// `CW_OUT_BODY` (`lib/cw-out.c:68`): the body stream.
    Body,
    /// `CW_OUT_BODY_0LEN` (`lib/cw-out.c:69`): a body write of no bytes that
    /// must still reach the callback.
    BodyZeroLen,
    /// `CW_OUT_HDS` (`lib/cw-out.c:70`): the header stream, which is metadata
    /// rather than content -- headers, and the informational writes FTP and
    /// IMAP pingpong replies produce.
    Header,
}

impl OutBufKind {
    /// The C identifier for this kind, spelled as `lib/cw-out.c` spells it.
    ///
    /// Present so a diagnostic can name a kind the way the C does without a
    /// second table to keep in step.
    #[must_use]
    #[allow(dead_code)] // consumer: trace/mod.rs pause diagnostics
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::None => "CW_OUT_NONE",
            Self::Body => "CW_OUT_BODY",
            Self::BodyZeroLen => "CW_OUT_BODY_0LEN",
            Self::Header => "CW_OUT_HDS",
        }
    }

    /// The word the trace line at `lib/cw-out.c:192-194` uses for this kind.
    ///
    /// The C's expression is `(otype == CW_OUT_HDS) ? "header" : "body"`, so
    /// the two body kinds and the sentinel all render as `body`. Reproduced
    /// exactly, because a trace line is compared by eye against the C's.
    const fn trace_word(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::None | Self::Body | Self::BodyZeroLen => "body",
        }
    }
}

/// One run of buffered bytes, together with the stream it is destined for.
///
/// Supersedes `struct cw_out_buf` (`lib/cw-out.c:73-77`) minus its `next`
/// pointer, which the owning [`VecDeque`] replaces. The C's
/// `cw_out_buf_create` / `cw_out_buf_free` pair (`:79-95`) becomes
/// [`Self::new`] and the drop glue.
#[derive(Debug)]
struct OutBuf {
    /// `cwbuf->type`.
    kind: OutBufKind,
    /// `cwbuf->b`, initialised with the C's ceiling (`lib/cw-out.c:84`).
    data: DynBuf,
}

impl OutBuf {
    /// `cw_out_buf_create(otype)` (`lib/cw-out.c:79-87`).
    fn new(kind: OutBufKind) -> Self {
        Self {
            kind,
            data: DynBuf::new(DYN_PAUSE_BUFFER),
        }
    }
}

/// Which callback pairing a flush resolved to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum CallbackSlot {
    /// `data->set.fwrite_func` with `data->set.out`.
    Body,
    /// `data->set.fwrite_header` with `data->set.writeheader`.
    Header,
    /// `data->set.fwrite_func` with `data->set.writeheader`.
    BodyToHeaderTarget,
}

/// A resolved callback and the two chunking sizes that go with it.
///
/// Supersedes the four out-parameters of `cw_get_writefunc`
/// (`lib/cw-out.c:144-172`), minus the callback-is-absent case, which is
/// [`Option::None`] at the one call site that asks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Resolved {
    /// Which pairing to invoke.
    slot: CallbackSlot,
    /// The largest slice to hand over in one call, or zero for "no limit".
    max_write: usize,
    /// The smallest slice worth handing over, unless the caller is flushing
    /// everything.
    min_write: usize,
}

/// What one attempt at handing bytes to a callback achieved.
#[derive(Debug)]
struct DirectFlush {
    /// The C's `*pconsumed`: how many bytes the callback took.
    consumed: usize,
    /// The C's return value, with [`CURLcode::Again`] preserved as the
    /// backpressure signal it is rather than collapsed into an error.
    result: CurlResult<()>,
}

/// The stage that hands bytes to the application, and holds them back when it
/// will not take them.
#[derive(Debug)]
pub(crate) struct ClientOutWriter<'data> {
    /// The application's callbacks, re-asked on every flush.
    output: Box<dyn ClientOutput + 'data>,
    /// `ctx->buf`, as a queue with the OLDEST run at the front.
    bufs: VecDeque<OutBuf>,
    /// `BIT(paused)`: the application asked for delivery to stop.
    paused: bool,
    /// `BIT(errored)`: a callback failed, so the application is never called
    /// again.
    errored: bool,
}

impl<'data> ClientOutWriter<'data> {
    /// A stage over the application's callbacks, with nothing buffered.
    #[allow(dead_code)] // consumer: the engine's ClientIoFactory
    pub(crate) fn new(output: Box<dyn ClientOutput + 'data>) -> Self {
        Self {
            output,
            bufs: VecDeque::new(),
            paused: false,
            errored: false,
        }
    }

    /// `cw_out_bufs_len(ctx)` (`lib/cw-out.c:122-131`): how many bytes are
    /// buffered across every run.
    #[allow(dead_code)] // consumer: multi/mod.rs pause accounting
    pub(crate) fn buffered(&self) -> usize {
        self.bufs.iter().map(|buf| buf.data.len()).sum()
    }

    /// The kind of the NEWEST buffered run, or [`OutBufKind::None`] when
    /// nothing is buffered.
    fn newest_kind(&self) -> OutBufKind {
        self.bufs
            .back()
            .map_or(OutBufKind::None, |newest| newest.kind)
    }

    /// `cw_get_writefunc` (`lib/cw-out.c:144-172`), asked afresh on every
    /// flush.
    ///
    /// # The header precedence, which is a chain and not a choice
    ///
    /// `lib/cw-out.c:160-162` is one conditional expression:
    ///
    /// 1. `fwrite_header` if it is installed;
    /// 2. otherwise `fwrite_func`, but ONLY if `writeheader` is set;
    /// 3. otherwise no callback at all.
    fn resolve(&self, kind: OutBufKind) -> Option<Resolved> {
        match kind {
            // `lib/cw-out.c:149-158`.
            OutBufKind::Body | OutBufKind::BodyZeroLen => {
                if self.output.has_body_write() {
                    Some(Resolved {
                        slot: CallbackSlot::Body,
                        max_write: CURL_MAX_WRITE_SIZE,
                        min_write: 0,
                    })
                } else {
                    None
                }
            }
            // `lib/cw-out.c:159-165`.
            OutBufKind::Header => {
                let slot = if self.output.has_header_write() {
                    Some(CallbackSlot::Header)
                } else if self.output.has_header_target()
                    && self.output.has_body_write()
                {
                    Some(CallbackSlot::BodyToHeaderTarget)
                } else {
                    None
                };
                slot.map(|slot| Resolved {
                    slot,
                    // `:163`: headers are written as they are.
                    max_write: 0,
                    min_write: 0,
                })
            }
            // `lib/cw-out.c:166-171`: the `default:` arm, which assigns a
            // null callback. Nothing can be delivered for the sentinel.
            OutBufKind::None => None,
        }
    }

    /// `cw_out_cb_write` (`lib/cw-out.c:174-219`): one call into the
    /// application, and the four ways it can end.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::WriteError`] when the callback asked to pause a transfer
    ///   that cannot be paused, when it returned the error sentinel, or when it
    ///   returned any count other than the exact length offered. Three
    ///   different diagnostics, all the same code, exactly as the C.
    /// * [`CURLcode::Again`] when the callback paused a transfer that CAN be
    ///   paused and [`TransferControl::pause_recv`] accepted it. This is
    ///   backpressure rather than failure, and every caller in this file treats
    ///   it as such.
    /// * whatever [`TransferControl::pause_recv`] returned, when it refused.
    fn cb_write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        slot: CallbackSlot,
        kind: OutBufKind,
        buf: &[u8],
    ) -> CurlResult<usize> {
        let blen = buf.len();

        // `lib/cw-out.c:189-191`. The in-callback flag is raised for the
        // duration of the call and lowered on EVERY path out, including an
        // unwind: the scope's drop glue does what the C's second
        // `Curl_set_in_callback` call does, and cannot be skipped by an early
        // return added later.
        let outcome = {
            let _entered = ctx.enter_callback();
            match slot {
                CallbackSlot::Body => self.output.write_body(buf),
                CallbackSlot::Header => self.output.write_header(buf),
                CallbackSlot::BodyToHeaderTarget => {
                    self.output.write_body_to_header_target(buf)
                }
            }
        };

        // `lib/cw-out.c:192-194`. Traced BEFORE classification, so a pause
        // shows the sentinel rather than a count -- which is what the C's
        // `%zu` of `nwritten` prints.
        let reported = outcome.to_callback_count();
        let word = kind.trace_word();
        ctx.trc_write(format_args!(
            "[OUT] wrote {blen} {word} bytes -> {reported}"
        ));

        match outcome {
            // `lib/cw-out.c:195-207`.
            ClientWriteOutcome::Pause => {
                // `:196-202`. The C tests `PROTOPT_NONETWORK` and its comment
                // names the one scheme that carries it: *"Protocols that work
                // without network cannot be paused. This is actually only
                // FILE:// just now, and it cannot pause since the transfer is
                // not done using the 'normal' procedure."*
                if ctx.config().nonetwork {
                    return Err(ctx.failf(
                        CURLcode::WriteError,
                        format_args!(
                            "Write callback asked for PAUSE when not supported"
                        ),
                    ));
                }
                // `:203-204`.
                self.paused = true;
                ctx.trc_write(format_args!("[OUT] PAUSE requested by client"));
                // `:205-206`: `result ? result : CURLE_AGAIN`. A refusal
                // propagates unchanged; an acceptance becomes backpressure.
                TransferControl::pause_recv(ctx.control(), true)?;
                Err(Error::new(CURLcode::Again))
            }
            // `lib/cw-out.c:208-211`.
            ClientWriteOutcome::Error => Err(ctx.failf(
                CURLcode::WriteError,
                format_args!("client returned ERROR on write of {blen} bytes"),
            )),
            // `lib/cw-out.c:212-216`. Note the C's format: `passed %zu
            // returned %zd`, so the count the application returned is printed
            // SIGNED while the length offered is printed unsigned. A callback
            // that answered `(size_t)-1` therefore reports -1, and the cast
            // below reproduces that rather than tidying it.
            ClientWriteOutcome::Written(count) if count != blen => {
                let signed = count as isize;
                Err(ctx.failf(
                    CURLcode::WriteError,
                    format_args!(
                        "Failure writing output to destination, \
                         passed {blen} returned {signed}"
                    ),
                ))
            }
            // `lib/cw-out.c:217-218`.
            ClientWriteOutcome::Written(count) => Ok(count),
        }
    }
}

impl ClientOutWriter<'_> {
    /// `cw_out_ptr_flush` (`lib/cw-out.c:221-266`): hand a slice straight to
    /// the application, chunked as the stream requires.
    ///
    /// # The three shapes of the body of this function
    ///
    /// 1. **Already failed** -- returns [`CURLcode::WriteError`] having called
    ///    nothing (`:234-236`). This is the sticky state, and it is tested
    ///    FIRST so that no later branch can reach the application.
    /// 2. **No callback** -- consumes everything and succeeds (`:240-243`).
    /// 3. **A zero-length body write** -- one call with an empty slice, whose
    ///    pause and error answers are honoured exactly as a real write's are
    ///    (`:246-250`). `consumed` stays ZERO, which is not an oversight: the C
    ///    leaves `*pconsumed` at the zero it set at `:245`, and
    ///    [`Self::buf_flush`] relies on that to leave the buffer empty and
    ///    therefore droppable.
    /// 4. **Anything else** -- the chunking loop (`:252-263`).
    fn ptr_flush(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        kind: OutBufKind,
        flush_all: bool,
        buf: &[u8],
    ) -> DirectFlush {
        // `lib/cw-out.c:234-236`: *"If we errored once, we do not invoke the
        // client callback again"*.
        if self.errored {
            return DirectFlush {
                consumed: 0,
                result: Err(Error::new(CURLcode::WriteError)),
            };
        }

        // `lib/cw-out.c:238-243`. Resolved here and not cached anywhere,
        // because the application may have changed it since the last flush.
        let Some(resolved) = self.resolve(kind) else {
            return DirectFlush {
                consumed: buf.len(),
                result: Ok(()),
            };
        };

        // `lib/cw-out.c:245`.
        let mut consumed = 0_usize;

        // `lib/cw-out.c:246-250`.
        if matches!(kind, OutBufKind::BodyZeroLen) {
            debug_assert!(
                buf.is_empty(),
                "CW_OUT_BODY_0LEN carries no bytes (lib/cw-out.c:247)"
            );
            let result = self
                .cb_write(ctx, resolved.slot, kind, buf)
                .map(|_written| ());
            return DirectFlush { consumed, result };
        }

        // `lib/cw-out.c:252-263`.
        let mut rest = buf;
        while !rest.is_empty() && !self.paused {
            // `:253-254`. Unreachable while `min_write` is zero, and kept
            // because the C keeps it; see [`Resolved::min_write`].
            if !flush_all && rest.len() < resolved.min_write {
                break;
            }
            // `:255`. A `max_write` of zero means "no limit", which is how the
            // header stream avoids being chunked at all.
            let wlen = if resolved.max_write == 0 {
                rest.len()
            } else {
                rest.len().min(resolved.max_write)
            };
            match self.cb_write(ctx, resolved.slot, kind, &rest[..wlen]) {
                // `:258-259`. Note that an error leaves `consumed` holding
                // whatever the EARLIER chunks took, which is the whole reason
                // this function reports a pair.
                Err(error) => {
                    return DirectFlush {
                        consumed,
                        result: Err(error),
                    }
                }
                // `:260-262`. `nwritten` is known to equal `wlen` here --
                // `cb_write` rejects every other count -- and the C still
                // advances by `nwritten` rather than by `wlen`. Reproduced, so
                // that the two files read alike.
                Ok(nwritten) => {
                    consumed += nwritten;
                    rest = &rest[nwritten..];
                }
            }
        }

        DirectFlush {
            consumed,
            result: Ok(()),
        }
    }

    /// `cw_out_buf_flush` (`lib/cw-out.c:268-300`): flush one buffered run and
    /// keep whatever the application would not take.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::ptr_flush`] returned, EXCEPT [`CURLcode::Again`]:
    /// `:282-284` swallows that one, because a pause is not a failure of this
    /// flush -- the bytes that were not taken stay in the run and the caller
    /// stops walking.
    fn buf_flush(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        node: &mut OutBuf,
        flush_all: bool,
    ) -> CurlResult<()> {
        // `lib/cw-out.c:275`. An empty run is skipped unless it is the
        // zero-length body write, which exists precisely to be delivered
        // empty.
        if node.data.is_empty() && !matches!(node.kind, OutBufKind::BodyZeroLen)
        {
            return Ok(());
        }

        // `lib/cw-out.c:278-281`.
        let flush =
            self.ptr_flush(ctx, node.kind, flush_all, node.data.as_slice());

        // `lib/cw-out.c:282-284`.
        match flush.result {
            Err(error) if error.code() != CURLcode::Again => return Err(error),
            _ => {}
        }

        // `lib/cw-out.c:286-297`.
        if flush.consumed > 0 {
            let len = node.data.len();
            if flush.consumed == len {
                // `:287-289`.
                node.data.free();
            } else {
                // `:290-296`. Keeping the TAIL is what preserves order: the
                // bytes the application took are the leading ones, so the
                // remainder must stay in front of everything that follows it.
                debug_assert!(
                    flush.consumed < len,
                    "a callback cannot consume more than it was offered \
                     (lib/cw-out.c:291)"
                );
                node.data.tail(len - flush.consumed).map_err(Error::new)?;
            }
        }
        Ok(())
    }

    /// `cw_out_flush_chain` (`lib/cw-out.c:302-338`): drain the queue from the
    /// OLDEST run forward, stopping at the first that will not empty.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::buf_flush`] returned. The run that failed stays in the
    /// queue, as it does in the C, where nothing frees it before the error
    /// propagates; every caller then releases the whole queue.
    fn flush_chain(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        flush_all: bool,
    ) -> CurlResult<()> {
        // `lib/cw-out.c:310-311`.
        if self.bufs.is_empty() {
            return Ok(());
        }
        // `lib/cw-out.c:312-313`. A paused stage flushes nothing and says so
        // with success, so an unpause is the only thing that can restart it.
        if self.paused {
            return Ok(());
        }

        // Each run is lifted out of the queue so that `buf_flush` can borrow
        // the callbacks and the bytes at once, and put back below unless it is
        // spent. `pop_front` is the C's `plast`, which walks to the last node
        // of a head-inserted list -- the oldest.
        while let Some(mut node) = self.bufs.pop_front() {
            if let Err(error) = self.buf_flush(ctx, &mut node, flush_all) {
                self.bufs.push_front(node);
                return Err(error);
            }
            if !node.data.is_empty() {
                // `lib/cw-out.c:323-327`: the run did not empty, so the walk
                // stops. The C asserts that this means the stage paused.
                self.bufs.push_front(node);
                debug_assert!(
                    self.paused,
                    "a run survives its flush only on a pause \
                     (lib/cw-out.c:325)"
                );
                break;
            }
            // `lib/cw-out.c:333-336`: spent, so it is released. The drop here
            // is `cw_out_buf_free`.
        }
        Ok(())
    }

    /// `cw_out_append` (`lib/cw-out.c:340-364`): buffer bytes the application
    /// has not taken.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::TooLarge`] when the total across every run would exceed
    ///   [`DYN_PAUSE_BUFFER`] (`:347-350`). Checked BEFORE anything is stored,
    ///   so a refusal leaves the queue exactly as it was and nothing is
    ///   silently truncated.
    /// * whatever [`DynBuf::addn`] returned, which is the per-buffer ceiling
    ///   the aggregate check above already makes unreachable.
    fn append(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        kind: OutBufKind,
        buf: &[u8],
    ) -> CurlResult<()> {
        let blen = buf.len();
        let buffered = self.buffered();

        // `lib/cw-out.c:345-346`.
        ctx.trc_write(format_args!(
            "[OUT] paused, buffering {blen} more bytes \
             ({buffered}/{DYN_PAUSE_BUFFER})"
        ));

        // `lib/cw-out.c:347-350`. Saturating rather than wrapping: the C's
        // `cw_out_bufs_len(ctx) + blen` can in principle overflow, and a
        // wrapped sum would pass a check it should fail.
        if buffered.saturating_add(blen) > DYN_PAUSE_BUFFER {
            return Err(ctx.failf(
                CURLcode::TooLarge,
                format_args!(
                    "pause buffer not large enough -> CURLE_TOO_LARGE"
                ),
            ));
        }

        // `lib/cw-out.c:352-361`, whose comment gives both halves of the
        // condition: *"if we do not have a buffer, or it is of another type,
        // make a new one. And for CW_OUT_HDS always make a new one, so we
        // 'replay' headers exactly as they came in"*.
        if self.newest_kind() != kind || matches!(kind, OutBufKind::Header) {
            self.bufs.push_back(OutBuf::new(kind));
        }

        // `lib/cw-out.c:362-363`.
        let newest = self
            .bufs
            .back_mut()
            .expect("the branch above guarantees a newest run");
        debug_assert_eq!(
            newest.kind, kind,
            "the newest run carries the kind being appended \
             (lib/cw-out.c:362)"
        );
        newest.data.addn(buf).map_err(Error::new)
    }

    /// `cw_out_do_write` (`lib/cw-out.c:366-416`): one stream's worth of one
    /// client write.
    ///
    /// Three paths, and the order between them is the behaviour:
    ///
    /// 1. **A kind change flushes everything first** (`:374-380`), with
    ///    `flush_all` forced TRUE regardless of what the caller asked for. That
    ///    is what keeps the two streams from interleaving inside one run, and
    ///    it is why a `--include`d header does not end up spliced into the
    ///    middle of a buffered body.
    /// 2. **Something is still buffered** (`:382-390`): append, then flush.
    ///    Never write directly, because doing so would deliver these bytes
    ///    ahead of the ones already waiting.
    /// 3. **Nothing is buffered** (`:391-406`): write directly and buffer only
    ///    the suffix the application would not take.
    ///
    /// # Errors
    ///
    /// Whatever the path taken returned. A failure latches
    /// [`Self::errored`] and releases every buffered run -- with ONE
    /// exception, which is the C's and is documented at the return itself.
    fn do_write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        kind: OutBufKind,
        flush_all: bool,
        buf: &[u8],
    ) -> CurlResult<()> {
        let mut result: CurlResult<()> = Ok(());

        // `lib/cw-out.c:374-380`.
        if !self.bufs.is_empty() && self.newest_kind() != kind {
            result = self.flush_chain(ctx, true);
        }

        if result.is_ok() {
            if self.bufs.is_empty() {
                // `lib/cw-out.c:391-406`.
                let flush = self.ptr_flush(ctx, kind, flush_all, buf);
                // `:396-397`. THIS RETURN BYPASSES THE ERROR LATCH BELOW, and
                // that is the C's control flow rather than a transcription
                // slip: the C writes `return result` here where every other
                // failing path writes `goto out`. Nothing observable follows
                // from the difference -- this path is reached only with an
                // EMPTY queue, so there are no runs for the latch to release,
                // and the code returned aborts the transfer before another
                // write can arrive. Reproducing it keeps the two files
                // line-for-line comparable.
                match flush.result {
                    Err(error) if error.code() != CURLcode::Again => {
                        return Err(error)
                    }
                    _ => {}
                }
                // `:398-405`.
                if flush.consumed < buf.len() {
                    result = self.append(ctx, kind, &buf[flush.consumed..]);
                }
            } else {
                // `lib/cw-out.c:382-390`.
                result = self.append(ctx, kind, buf);
                if result.is_ok() {
                    result = self.flush_chain(ctx, flush_all);
                }
            }
        }

        // `lib/cw-out.c:408-415`.
        if result.is_err() {
            self.errored = true;
            self.bufs.clear();
        }
        result
    }

    /// `cw_out_flush` (`lib/cw-out.c:466-485`): drain the queue on behalf of an
    /// unpause or an end of stream.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::WriteError`] when the stage has already failed
    ///   (`:473-474`),
    ///   without touching the application.
    /// * whatever [`Self::flush_chain`] returned, having first latched the
    ///   failure and released every run (`:479-483`).
    ///
    /// A PAUSED stage returns success and flushes nothing (`:475-476`), so
    /// finishing a transfer that the application has paused is not an error.
    fn flush(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        flush_all: bool,
    ) -> CurlResult<()> {
        // `lib/cw-out.c:473-474`.
        if self.errored {
            return Err(Error::new(CURLcode::WriteError));
        }
        // `lib/cw-out.c:475-476`: *"not doing it"*.
        if self.paused {
            return Ok(());
        }

        // `lib/cw-out.c:478-484`.
        match self.flush_chain(ctx, flush_all) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.errored = true;
                self.bufs.clear();
                Err(error)
            }
        }
    }
}

impl ClientWriter for ClientOutWriter<'_> {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::ClientOut
    }

    fn phase(&self) -> ClientWriterPhase {
        ClientWriterPhase::Client
    }

    /// `cw_out_init` (`lib/cw-out.c:104-111`): `ctx->buf = NULL`.
    ///
    /// Clearing rather than asserting emptiness, because the C assigns
    /// unconditionally. A stage that is initialised twice therefore discards
    /// whatever it held, exactly as the C's would.
    fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        let _ = ctx;
        self.bufs.clear();
        Ok(())
    }

    /// `cw_out_write` (`lib/cw-out.c:418-442`): route one client write to one
    /// or both streams.
    ///
    /// # The routing matrix, which is a pair of independent tests
    ///
    /// | flags | body stream | header stream |
    /// |---|---|---|
    /// | `BODY` | yes | no |
    /// | `BODY \| ZERO_LEN`, empty | yes, as zero-length | no |
    /// | `HEADER`, `CURLOPT_HEADER` off | no | yes |
    /// | `HEADER`, `CURLOPT_HEADER` on | yes | yes |
    /// | `INFO` | no | yes |
    ///
    /// # Errors
    ///
    /// Whatever [`Self::do_write`] returned, from the FIRST stream that fails.
    /// The header stream is not attempted when the body stream failed
    /// (`:431-432`).
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // Nothing is forwarded: this stage is the last in the chain, and the
        // C's `writer->next` is null here. `cw_out_write` has no
        // `Curl_cwriter_write` call at all.
        let _ = tail;

        // `lib/cw-out.c:424`.
        let flush_all = flags.contains(ClientWriteFlags::EOS);

        // `lib/cw-out.c:426-433`.
        if flags.contains(ClientWriteFlags::BODY)
            || (flags.contains(ClientWriteFlags::HEADER)
                && self.output.include_header())
        {
            // `:428-429`. The zero-length kind is chosen only when there really
            // are no bytes AND the caller asked for an empty write to be
            // delivered; an empty BODY write without the flag is an ordinary
            // body write that happens to consume nothing.
            let kind = if buf.is_empty()
                && flags.contains(ClientWriteFlags::ZERO_LEN)
            {
                OutBufKind::BodyZeroLen
            } else {
                OutBufKind::Body
            };
            self.do_write(ctx, kind, flush_all, buf)?;
        }

        // `lib/cw-out.c:435-439`.
        if flags
            .intersects(ClientWriteFlags::HEADER.union(ClientWriteFlags::INFO))
        {
            self.do_write(ctx, OutBufKind::Header, flush_all, buf)?;
        }

        // `lib/cw-out.c:441`.
        Ok(())
    }

    /// `cw_out_close` (`lib/cw-out.c:133-139`): release every buffered run.
    ///
    /// Nothing is flushed. A transfer torn down while paused discards what it
    /// was holding, which is what `cw_out_bufs_free` does and the only thing it
    /// can do -- the application is no longer expecting calls.
    fn close(&mut self, ctx: &mut ClientCtx<'_>) {
        let _ = ctx;
        self.bufs.clear();
    }

    /// `Curl_cw_out_is_paused` (`lib/cw-out.c:453-464`).
    fn is_paused(&self) -> bool {
        self.paused
    }

    /// `ctx->paused = FALSE` (`lib/cw-out.c:496`), and nothing else.
    ///
    /// Separated from the flushes that follow it in the C so that
    /// [`PauseWriter`] can perform the C's first step at the C's moment; see
    /// [`WriterTail::clear_pause`].
    fn clear_pause(&mut self) {
        self.paused = false;
    }

    /// `Curl_cw_out_unpause` (`lib/cw-out.c:487-502`), steps one and three.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::flush`] returned.
    fn unpause(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
    ) -> CurlResult<()> {
        let _ = tail;
        // `lib/cw-out.c:495-496`. The trace line lands after the pause stage's
        // own lines rather than before them, because the C's single function
        // has become two stages walked in chain order. No byte moves as a
        // result; only the order of two diagnostics.
        ctx.trc_write(format_args!("[OUT] unpause"));
        self.paused = false;
        // `:499`, with `flush_all` FALSE: collation still applies, so an
        // unpause delivers what it can and no more.
        self.flush(ctx, false)
    }

    /// `Curl_cw_out_done` (`lib/cw-out.c:504-517`), its second half.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::flush`] returned, including [`CURLcode::WriteError`]
    /// when the stage had already failed.
    fn done(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
    ) -> CurlResult<()> {
        let _ = tail;
        // `lib/cw-out.c:511`.
        ctx.trc_write(format_args!("[OUT] done"));
        // `:514`, with `flush_all` TRUE: everything held back for collation is
        // forced out, because no more bytes are coming.
        self.flush(ctx, true)
    }
}

// `cw-pause` -- the in-flight stage, `lib/cw-pause.c:34-225`

/// The chunk size of a buffered BODY run in the in-flight stage.
pub(crate) const CW_PAUSE_BUF_CHUNK: usize = 16 * 1024;

/// The largest BODY slice handed downstream while a content decoder is
/// installed.
pub(crate) const CW_PAUSE_DEC_WRITE_CHUNK: usize = 4096;

/// One run of bytes that arrived while the application was not taking any.
///
/// # Two buffer policies, chosen by what the run holds
///
/// `cw_pause_buf_create` (`:45-57`) branches on the write flags:
///
/// * a BODY run gets a [`BufQ`] of [`CW_PAUSE_BUF_CHUNK`] chunks with
///   [`BufqOpts::SOFT_LIMIT`] and [`BufqOpts::NO_SPARES`], so it grows as
///   far as
///   it must and returns no chunk to a spare list on the way;
/// * anything else gets a HARD queue of exactly one chunk sized to the write.
#[derive(Debug)]
struct PauseBuf {
    /// `cwbuf->type`: the write flags the run arrived with, replayed unchanged.
    flags: ClientWriteFlags,
    /// `cwbuf->b`.
    data: BufQ,
}

impl PauseBuf {
    /// `cw_pause_buf_create(type, buflen)` (`lib/cw-pause.c:45-57`).
    ///
    /// `buflen` is read only on the metadata path, where it becomes the chunk
    /// size. On the body path the C ignores it entirely.
    fn new(flags: ClientWriteFlags, buflen: usize) -> Self {
        let data = if flags.contains(ClientWriteFlags::BODY) {
            // `lib/cw-pause.c:51-52`.
            BufQ::with_opts(
                CW_PAUSE_BUF_CHUNK,
                1,
                BufqOpts::SOFT_LIMIT | BufqOpts::NO_SPARES,
            )
        } else {
            // `lib/cw-pause.c:54`.
            BufQ::new(buflen, 1)
        };
        Self { flags, data }
    }
}

/// The stage that holds bytes already in flight when the application pauses.
#[derive(Debug, Default)]
pub(crate) struct PauseWriter {
    /// `ctx->buf`, as a queue with the OLDEST run at the front.
    ///
    /// The C's list grows at the head (`lib/cw-pause.c:189-190`) and is drained
    /// from the tail (`:112-113`); both ends are reversed here.
    bufs: VecDeque<PauseBuf>,
    /// `ctx->buf_total`: how many bytes are held across every run.
    total: usize,
}

impl PauseWriter {
    /// A stage holding nothing.
    ///
    /// `cw_pause_init` (`lib/cw-pause.c:73-80`) sets `ctx->buf = NULL` over a
    /// zeroed structure, so the total starts at zero too.
    #[allow(dead_code)] // consumer: the engine's ClientIoFactory
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `ctx->buf_total`: how many bytes are held back.
    #[allow(dead_code)] // consumer: multi/mod.rs pause accounting
    pub(crate) fn buffered(&self) -> usize {
        self.total
    }

    /// `cw_pause_flush` (`lib/cw-pause.c:99-140`): hand the held runs
    /// downstream, oldest first, for as long as the client stage will take
    /// them.
    ///
    /// # Errors
    ///
    /// Whatever a downstream write returned. The C's two branches differ in how
    /// they report it, and the difference is transcribed rather than tidied:
    /// the ordinary branch returns immediately (`:124-125`), while the
    /// zero-length end-of-stream branch merely RECORDS the code and lets the
    /// loop continue (`:127-132`), so a later successful turn can overwrite it.
    /// Both are the C's, and both are reachable.
    fn flush(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
    ) -> CurlResult<()> {
        // `lib/cw-pause.c:103`. Asked once, before the loop, exactly as the C
        // asks it: a decoder cannot be installed while a flush is running.
        let decoding = tail.is_content_decoding();
        let mut result: CurlResult<()> = Ok(());

        // `lib/cw-pause.c:107`. The client stage is downstream of this one, so
        // its paused flag is reachable through the tail; see
        // `WriterTail::is_paused`.
        while !self.bufs.is_empty() && !tail.is_paused() {
            // `:108-113`: `plast` walks to the last node of a head-inserted
            // list, which is the oldest. Lifted out so that the peeked span and
            // the later `skip` do not overlap as borrows.
            let Some(mut node) = self.bufs.pop_front() else {
                break;
            };
            let flags = node.flags;

            // `lib/cw-pause.c:114-126`.
            let mut wrote: Option<(usize, CurlResult<()>)> = None;
            if let Some(span) = node.data.peek() {
                // `:115-116`. The span stops at the head chunk's end, so a run
                // spanning several chunks takes several turns of this loop --
                // which is exactly what the C's `Curl_bufq_peek` gives it.
                let wlen = if decoding && flags.contains(ClientWriteFlags::BODY)
                {
                    span.len().min(CW_PAUSE_DEC_WRITE_CHUNK)
                } else {
                    span.len()
                };
                // `:117-118`.
                wrote = Some((wlen, tail.write(ctx, flags, &span[..wlen])));
            }

            if let Some((wlen, outcome)) = wrote {
                // `:119-120`.
                let total = self.total;
                let code = code_of(&outcome);
                ctx.trc_write(format_args!(
                    "[PAUSE] flushed {wlen}/{total} bytes, type={flags} -> \
                     {code}"
                ));
                // `:121-123`. Skipped and accounted for even when the write
                // failed, because the bytes left this stage either way.
                node.data.skip(wlen);
                debug_assert!(
                    self.total >= wlen,
                    "the running total covers every buffered byte \
                     (lib/cw-pause.c:122)"
                );
                self.total = self.total.saturating_sub(wlen);
                // `:124-125`. Returned BEFORE the emptiness test below, so the
                // run stays in the queue with whatever it still holds.
                if let Err(error) = outcome {
                    self.bufs.push_front(node);
                    return Err(error);
                }
            } else if flags.contains(ClientWriteFlags::EOS) {
                // `lib/cw-pause.c:127-132`. An EMPTY run that carries the end
                // of stream still has something to say, and this is where it
                // says it: a zero-length write downstream, so the client stage
                // sees the stream end. The C passes its still-null `buf`
                // pointer with a length of zero; an empty slice is that.
                result = tail.write(ctx, flags, &[]);
                let total = self.total;
                let code = code_of(&result);
                ctx.trc_write(format_args!(
                    "[PAUSE] flushed 0/{total} bytes, type={flags} -> {code}"
                ));
            }

            // `lib/cw-pause.c:134-137`.
            if node.data.is_empty() {
                // Spent, so it is released. The drop here is
                // `cw_pause_buf_free`.
            } else {
                self.bufs.push_front(node);
            }
        }
        result
    }

    /// `cw_pause_write` (`lib/cw-pause.c:142-204`): forward what the client
    /// stage will take and hold the rest.
    ///
    /// # Errors
    ///
    /// * whatever a downstream write returned, from [`Self::flush`] or from the
    ///   forwarding loop.
    /// * [`CURLcode::TooLarge`] when holding the remainder would take the total
    ///   past [`DYN_PAUSE_BUFFER`]. This bound is NOT in the C, which lets a
    ///   soft-limited queue grow until the allocator refuses; the
    ///   64-mebibyte pause-buffer policy require the whole pause path to be
    ///   bounded, and an explicit refusal is what
    ///   [`ClientOutWriter::append`] already gives for the other half of it.
    /// * [`CURLcode::OutOfMemory`] when a queue accepted no bytes at all from a
    ///   non-empty slice. The C loops on that condition for ever; the same
    ///   trade [`BufQ::with_opts`] documents applies, and a defined refusal
    ///   replaces a hang.
    fn write_or_hold(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `lib/cw-pause.c:149`.
        let decoding = tail.is_content_decoding();

        // `lib/cw-pause.c:151-155`. Held bytes go first, always: forwarding the
        // new ones ahead of them would reorder the stream.
        if !self.bufs.is_empty() && !tail.is_paused() {
            self.flush(ctx, tail)?;
        }

        let mut rest = buf;

        // `lib/cw-pause.c:157-175`. A `while` and not an `if`, because a write
        // split into decoder-sized chunks may pause partway: the loop re-tests
        // both conditions on every turn and leaves the remainder to the
        // buffering below.
        while self.bufs.is_empty() && !tail.is_paused() {
            let blen = rest.len();
            // `:162-163`.
            let wlen = if decoding && flags.contains(ClientWriteFlags::BODY) {
                blen.min(CW_PAUSE_DEC_WRITE_CHUNK)
            } else {
                blen
            };
            // `:164-165`. The end of stream belongs to the LAST segment only.
            let wtype = if wlen < blen {
                flags.difference(ClientWriteFlags::EOS)
            } else {
                flags
            };
            // `:166`.
            let outcome = tail.write(ctx, wtype, &rest[..wlen]);
            // `:167-168`.
            let code = code_of(&outcome);
            ctx.trc_write(format_args!(
                "[PAUSE] writing {wlen}/{blen} bytes of type {wtype} -> {code}"
            ));
            // `:169-170`.
            outcome?;
            // `:171-174`.
            rest = &rest[wlen..];
            if rest.is_empty() {
                return Ok(());
            }
        }

        // `lib/cw-pause.c:177-201`. A `do`/`while` in the C, so it runs at
        // least once even for an empty slice -- which is how a zero-length
        // end-of-stream write reaches a run of its own and is replayed later.
        loop {
            // Beyond the C; see this function's error documentation.
            if self.total.saturating_add(rest.len()) > DYN_PAUSE_BUFFER {
                let total = self.total;
                return Err(ctx.failf(
                    CURLcode::TooLarge,
                    format_args!(
                        "pause buffer not large enough, {total} buffered \
                         -> CURLE_TOO_LARGE"
                    ),
                ));
            }

            // `lib/cw-pause.c:179-192`. The append case requires BOTH that the
            // newest run carries the same flags AND that this is body data:
            // metadata always starts a new run, which is what keeps one header
            // to one callback.
            let same_body_run =
                self.bufs.back().is_some_and(|newest| newest.flags == flags)
                    && flags.contains(ClientWriteFlags::BODY);
            if !same_body_run {
                // `:185-190`.
                self.bufs.push_back(PauseBuf::new(flags, rest.len()));
            }
            let newest = self
                .bufs
                .back_mut()
                .expect("the branch above guarantees a newest run");
            // `:182` and `:191`.
            let nwritten = newest.data.write(rest).map_err(Error::new)?;

            // `:193-195`.
            let total = self.total;
            ctx.trc_write(format_args!(
                "[PAUSE] buffer {nwritten} more bytes of type {flags}, \
                 total={total} -> 0"
            ));

            // `:198-200`.
            rest = &rest[nwritten..];
            self.total = self.total.saturating_add(nwritten);

            // `:201`.
            if rest.is_empty() {
                return Ok(());
            }
            // Beyond the C: a queue that took nothing from a non-empty slice
            // would make the C's `while(blen)` spin for ever.
            if nwritten == 0 {
                return Err(Error::with_context(
                    CURLcode::OutOfMemory,
                    "pause buffer accepted no bytes",
                ));
            }
        }
    }
}

impl ClientWriter for PauseWriter {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::Pause
    }

    fn phase(&self) -> ClientWriterPhase {
        ClientWriterPhase::Protocol
    }

    /// `cw_pause_init` (`lib/cw-pause.c:73-80`): `ctx->buf = NULL`.
    fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        let _ = ctx;
        self.bufs.clear();
        self.total = 0;
        Ok(())
    }

    /// `cw_pause_write` (`lib/cw-pause.c:142-204`).
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        self.write_or_hold(ctx, tail, flags, buf)
    }

    /// `cw_pause_close` (`lib/cw-pause.c:91-97`): release every held run.
    fn close(&mut self, ctx: &mut ClientCtx<'_>) {
        let _ = ctx;
        self.bufs.clear();
        self.total = 0;
    }

    /// `Curl_cw_out_unpause`'s first two steps (`lib/cw-out.c:496-497`).
    ///
    /// # Errors
    ///
    /// Whatever [`Self::flush`] returned.
    fn unpause(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
    ) -> CurlResult<()> {
        // `lib/cw-out.c:496`.
        tail.clear_pause();
        // `lib/cw-out.c:497`: `Curl_cw_pause_flush(data)`.
        self.flush(ctx, tail)
    }

    /// `Curl_cw_out_done`'s first step (`lib/cw-out.c:512`).
    ///
    /// # Errors
    ///
    /// Whatever [`Self::flush`] returned.
    fn done(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
    ) -> CurlResult<()> {
        self.flush(ctx, tail)
    }
}

/// The integer a `CURL_TRC_WRITE` line's `%d` of a `CURLcode` prints.
///
/// The C traces the result of a downstream write as a bare integer, and zero is
/// `CURLE_OK`. Rendering it from a [`CurlResult`] keeps those trace lines
/// comparable with the C's by eye, which is the only reason they are reproduced
/// at all.
fn code_of(result: &CurlResult<()>) -> i32 {
    match result {
        Ok(()) => CURLcode::Ok as i32,
        Err(error) => error.code() as i32,
    }
}

// `hds-collect` -- the header collector, `lib/headers.c:292-346`

/// The stage that fills the store `curl_easy_header` reads.
///
/// # A monitoring stage, which is why it is at `Protocol`
///
/// Being at `Protocol` also puts it AHEAD of the client stage, which is the
/// ordering the store's contract needs: a header is recorded before the
/// application's header callback can be invoked for it, so a callback
/// that turns
/// round and calls `curl_easy_header` finds the header it was just handed.
#[derive(Debug)]
pub(crate) struct HeaderCollectWriter<'data> {
    /// The store to push into, and the request number to stamp.
    handle: Box<dyn HeaderStoreHandle + 'data>,
}

impl<'data> HeaderCollectWriter<'data> {
    /// A collector over the transfer's store.
    ///
    /// `Curl_cwriter_create` allocates and zeroes a `struct
    /// hds_cw_collect_ctx` that carries nothing but its base
    /// (`lib/headers.c:290-292`); the state this stage needs is the handle,
    /// which the C reaches through `data` instead.
    #[allow(dead_code)] // consumer: the engine's header init
    pub(crate) fn new(handle: Box<dyn HeaderStoreHandle + 'data>) -> Self {
        Self { handle }
    }
}

impl ClientWriter for HeaderCollectWriter<'_> {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::HeaderCollect
    }

    fn phase(&self) -> ClientWriterPhase {
        ClientWriterPhase::Protocol
    }

    /// `hds_cw_collect_write` (`lib/headers.c:296-313`): store a header, then
    /// forward it unchanged.
    ///
    /// # Errors
    ///
    /// Whatever [`HeaderStore::push`] returned, and the C's currencies are
    /// preserved because they are not remapped:
    ///
    /// * [`CURLcode::TooLarge`] once the store holds
    ///   `MAX_HTTP_RESP_HEADER_COUNT` headers;
    /// * [`CURLcode::WeirdServerReply`] for a line with no terminator, or a
    ///   continuation line of nothing but blanks;
    /// * [`CURLcode::BadFunctionArgument`] for a line with no separating colon;
    /// * [`CURLcode::OutOfMemory`] from the entry and byte ceilings the store's
    ///   own policy applies.
    ///
    /// A push failure ABORTS the write (`:307-308`), so the header never
    /// reaches the stages below it. Anything else is forwarded, including every
    /// write the classification declined to store.
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `lib/headers.c:300-305`, in one call.
        if let Some(origin) = classify_origin(flags.bits()) {
            let request = self.handle.request();
            // `:306`.
            let outcome = self.handle.store().push(buf, origin, request);
            // `:307-308`. The C's `%x` of `htype` and `%d` of the code.
            let blen = buf.len();
            let code = match outcome {
                Ok(()) => CURLcode::Ok as i32,
                Err(code) => code as i32,
            };
            ctx.trc_write(format_args!(
                "header_collect pushed(type={origin:x}, len={blen}) -> {code}"
            ));
            // `:309-310`.
            outcome.map_err(Error::new)?;
        }
        // `lib/headers.c:312`.
        tail.write(ctx, flags, buf)
    }
}

/// `Curl_headers_init` (`lib/headers.c:324-347`): install the collector, once
/// and only for an HTTP-family transfer.
///
/// The two guards are the C's and both matter:
///
/// * `http_family` is `data->conn->scheme->protocol & PROTO_FAMILY_HTTP`
///   (`:329`). The header store is an HTTP concept, so an FTP or SFTP transfer
///   gets no collector and `curl_easy_header` answers nothing for it.
/// * the double-install check is by NAME (`:331-332`), whose comment reads
///   *"avoid installing it twice"*. It matters because the C calls this
///   once per
///   request and a redirection is a further request on the same chain; a second
///   collector would store every header twice.
///
/// # Errors
///
/// Whatever [`ClientWriterStack::create`] or [`ClientWriterStack::add`]
/// returned. The C frees the stage when `add` fails (`:340-343`); `add` takes
/// ownership here, so a failure drops it -- which runs the same `do_close` the
/// C's `Curl_cwriter_free` would, this stage having none.
#[allow(dead_code)] // consumer: the engine's per-request init
pub(crate) fn install_header_collector<'data>(
    stack: &mut ClientWriterStack<'data>,
    ctx: &mut ClientCtx<'_>,
    factory: &dyn ClientIoFactory<'data>,
    handle: Box<dyn HeaderStoreHandle + 'data>,
    http_family: bool,
) -> CurlResult<()> {
    // `lib/headers.c:329`.
    if !http_family {
        return Ok(());
    }
    // `lib/headers.c:331-332`.
    if stack
        .get_by_name(ClientWriterKind::HeaderCollect.name())
        .is_some()
    {
        return Ok(());
    }
    // `lib/headers.c:335-337`, which runs `do_init` before the stage is
    // inserted, then `:339`.
    let writer = ClientWriterStack::create(
        Box::new(HeaderCollectWriter::new(handle)),
        ctx,
    )?;
    stack.add(writer, ctx, factory)
}

// The three entry points -- `lib/cw-out.h:40-50`

/// `Curl_cw_out_is_paused` (`lib/cw-out.c:453-464`): whether the client stage
/// is holding bytes back.
#[allow(dead_code)] // consumer: easy/mod.rs, curl_easy_pause
pub(crate) fn is_paused(stack: &ClientWriterStack<'_>) -> bool {
    stack
        .get_by_kind(ClientWriterKind::ClientOut)
        .is_some_and(ClientWriter::is_paused)
}

/// `Curl_cw_out_unpause` (`lib/cw-out.c:487-502`): the application unpaused the
/// transfer, so replay what was held back.
///
/// # The order, which is the whole contract
///
/// 1. the client stage's paused flag is cleared;
/// 2. the in-flight stage is drained, its writes travelling DOWN the chain and
///    through the client stage, which appends them behind whatever it already
///    holds and replays the queue in arrival order;
/// 3. the client stage is drained, with collation still applying.
///
/// # Errors
///
/// Whatever the first failing stage returned -- a client callback's
/// [`CURLcode::WriteError`], a downstream failure during the replay, or
/// [`CURLcode::WriteError`] outright when the client stage had already failed.
#[allow(dead_code)] // consumer: easy/mod.rs, curl_easy_pause
pub(crate) fn unpause(
    stack: &mut ClientWriterStack<'_>,
    ctx: &mut ClientCtx<'_>,
) -> CurlResult<()> {
    // `lib/cw-out.c:492-493`.
    if stack.get_by_kind(ClientWriterKind::ClientOut).is_none() {
        return Ok(());
    }
    stack.unpause(ctx)
}

/// `Curl_cw_out_done` (`lib/cw-out.c:504-517`): the download has ended, so
/// deliver everything still held.
///
/// The same two stages in the same order as [`unpause`], with two differences,
/// both of which are observable:
///
/// * nothing is unpaused, so a transfer the application has paused delivers
///   NOTHING here and keeps both buffers -- the C's two flushes each decline
///   while the client stage is paused, and neither reports an error for it;
/// * the client stage flushes with `flush_all` TRUE, so a run that collation
///   would have held back is forced out. That is the only difference the flag
///   makes today, the preferred minimum being zero, and it is the reason the
///   flag exists.
///
/// # Errors
///
/// Whatever the first failing stage returned, including
/// [`CURLcode::WriteError`]
/// when the client stage had already failed -- so finishing a transfer whose
/// callback failed reports the failure again rather than succeeding quietly.
#[allow(dead_code)] // consumer: transfer/mod.rs, end of stream
pub(crate) fn done(
    stack: &mut ClientWriterStack<'_>,
    ctx: &mut ClientCtx<'_>,
) -> CurlResult<()> {
    // `lib/cw-out.c:509-510`.
    if stack.get_by_kind(ClientWriterKind::ClientOut).is_none() {
        return Ok(());
    }
    stack.done(ctx)
}

// The test module's imports are the module's own five, reached through
// `use super::*`, plus `crate::transfer::progress` and
// `crate::util::timeval`. The second of those is the only name in this file
// outside the dependency set the module itself uses, it is confined to
// `#[cfg(test)]`, and it is not a choice: `ClientCtx::new` takes a
// `&dyn Clock`, the trait and its test double both live in
// `crate::util::timeval`, and there is no way to build a context -- and
// therefore no way to drive a writer stage at all -- without them. Nothing
// below reads a host clock; `TestClock` pins the instant so that every
// assertion is deterministic.
#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    use crate::headers::{
        CURLH_1XX, CURLH_CONNECT, CURLH_HEADER, CURLH_TRAILER,
        MAX_HTTP_RESP_HEADER_COUNT,
    };
    use crate::transfer::progress::Progress;
    use crate::transfer::sendf::{
        ClientCallbackGuard, ClientConfig, ClientReadSource, RequestReadState,
        RequestWriteState, TraceDataKind, TraceSink,
    };
    use crate::util::timeval::{CurlTime, TestClock};

    // -- the doubles ------------------------------------------------------

    /// Which of the three pairings a recorded callback used.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Stream {
        /// `fwrite_func` with `out`.
        Body,
        /// `fwrite_header` with `writeheader`.
        Header,
        /// `fwrite_func` with `writeheader`.
        BodyToHeaderTarget,
    }

    /// One thing that happened, in the order it happened.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        /// A call into the application.
        Callback(Stream, Vec<u8>),
        /// A write that reached the relay stage installed below the pause
        /// stage.
        Relay(ClientWriteFlags, Vec<u8>),
    }

    /// What a scripted callback answers.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Answer {
        /// The exact length offered: the ordinary success.
        Exact,
        /// A count that is not the length offered.
        Count(usize),
        /// `CURL_WRITEFUNC_PAUSE`.
        Pause,
        /// `CURL_WRITEFUNC_ERROR`.
        Error,
    }

    /// Everything the doubles saw, and everything they were told to answer.
    #[derive(Debug)]
    struct Recorder {
        events: Vec<Event>,
        /// Consumed one per callback invocation; [`Answer::Exact`] once spent.
        script: Vec<Answer>,
        has_body: bool,
        has_header: bool,
        has_header_target: bool,
        include_header: bool,
    }

    impl Default for Recorder {
        /// A body callback installed and nothing else, which is libcurl's own
        /// default: `data->set.fwrite_func` starts at `fwrite` and the three
        /// header settings start unset.
        fn default() -> Self {
            Self {
                events: Vec::new(),
                script: Vec::new(),
                has_body: true,
                has_header: false,
                has_header_target: false,
                include_header: false,
            }
        }
    }

    type Shared = Rc<RefCell<Recorder>>;

    fn recorder() -> Shared {
        Rc::new(RefCell::new(Recorder::default()))
    }

    /// The bytes of every callback invocation on one stream, concatenated.
    fn callback_bytes(shared: &Shared, stream: Stream) -> Vec<u8> {
        shared
            .borrow()
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Callback(seen, bytes) if *seen == stream => Some(bytes),
                _ => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    /// One entry per callback invocation on one stream, with its length.
    fn callback_lengths(shared: &Shared, stream: Stream) -> Vec<usize> {
        shared
            .borrow()
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Callback(seen, bytes) if *seen == stream => {
                    Some(bytes.len())
                }
                _ => None,
            })
            .collect()
    }

    /// Every event, cloned for assertion.
    fn events(shared: &Shared) -> Vec<Event> {
        shared.borrow().events.clone()
    }

    /// The application's callbacks, scripted and recorded.
    #[derive(Debug)]
    struct TestOutput {
        shared: Shared,
    }

    impl TestOutput {
        fn record(
            &mut self,
            stream: Stream,
            bytes: &[u8],
        ) -> ClientWriteOutcome {
            let mut state = self.shared.borrow_mut();
            state.events.push(Event::Callback(stream, bytes.to_vec()));
            let answer = if state.script.is_empty() {
                Answer::Exact
            } else {
                state.script.remove(0)
            };
            match answer {
                Answer::Exact => ClientWriteOutcome::Written(bytes.len()),
                Answer::Count(count) => ClientWriteOutcome::Written(count),
                Answer::Pause => ClientWriteOutcome::Pause,
                Answer::Error => ClientWriteOutcome::Error,
            }
        }
    }

    impl ClientOutput for TestOutput {
        fn has_body_write(&self) -> bool {
            self.shared.borrow().has_body
        }

        fn has_header_write(&self) -> bool {
            self.shared.borrow().has_header
        }

        fn has_header_target(&self) -> bool {
            self.shared.borrow().has_header_target
        }

        fn include_header(&self) -> bool {
            self.shared.borrow().include_header
        }

        fn write_body(&mut self, bytes: &[u8]) -> ClientWriteOutcome {
            self.record(Stream::Body, bytes)
        }

        fn write_header(&mut self, bytes: &[u8]) -> ClientWriteOutcome {
            self.record(Stream::Header, bytes)
        }

        fn write_body_to_header_target(
            &mut self,
            bytes: &[u8],
        ) -> ClientWriteOutcome {
            self.record(Stream::BodyToHeaderTarget, bytes)
        }
    }

    /// A monitoring stage that records what passed and forwards it unchanged.
    #[derive(Debug)]
    struct Relay {
        shared: Shared,
    }

    impl ClientWriter for Relay {
        fn kind(&self) -> ClientWriterKind {
            ClientWriterKind::Custom("relay")
        }

        fn phase(&self) -> ClientWriterPhase {
            ClientWriterPhase::ContentDecode
        }

        fn write(
            &mut self,
            ctx: &mut ClientCtx<'_>,
            tail: &mut WriterTail<'_, '_>,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CurlResult<()> {
            self.shared
                .borrow_mut()
                .events
                .push(Event::Relay(flags, buf.to_vec()));
            tail.write(ctx, flags, buf)
        }
    }

    /// A stage that stands where the pause stage would and does nothing.
    #[derive(Debug)]
    struct BypassPause;

    impl ClientWriter for BypassPause {
        fn kind(&self) -> ClientWriterKind {
            ClientWriterKind::Pause
        }

        fn phase(&self) -> ClientWriterPhase {
            ClientWriterPhase::Protocol
        }
    }

    /// The transfer engine's four operations, recorded.
    #[derive(Debug, Default)]
    struct TestControl {
        recv_pauses: Vec<bool>,
        send_pauses: Vec<bool>,
        pause_fail: Option<CURLcode>,
    }

    impl TransferControl for TestControl {
        fn stream_close(&mut self, _reason: &'static str) {}

        fn conn_close(&mut self, _reason: &'static str) {}

        fn pause_send(&mut self, pause: bool) -> CurlResult<()> {
            self.send_pauses.push(pause);
            Ok(())
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
    #[derive(Debug, Default)]
    struct TestGuard {
        transitions: Vec<bool>,
        depth: i32,
        peak: i32,
    }

    impl TestGuard {
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
        writes: Vec<String>,
        fails: Vec<String>,
    }

    impl TestTrace {
        fn saw_write(&self, needle: &str) -> bool {
            self.writes.iter().any(|line| line.contains(needle))
        }

        fn saw_fail(&self, needle: &str) -> bool {
            self.fails.iter().any(|line| line.contains(needle))
        }
    }

    impl TraceSink for TestTrace {
        fn debug(&mut self, _kind: TraceDataKind, _bytes: &[u8]) {}

        fn trace_write(&mut self, line: fmt::Arguments<'_>) {
            self.writes.push(line.to_string());
        }

        fn trace_read(&mut self, _line: fmt::Arguments<'_>) {}

        fn failf(&mut self, line: fmt::Arguments<'_>) {
            self.fails.push(line.to_string());
        }

        fn infof(&mut self, _line: fmt::Arguments<'_>) {}
    }

    /// Builds the base chain out of the two stages this module owns.
    #[derive(Debug)]
    struct TestFactory {
        shared: Shared,
        /// When set, the pause stage is replaced by [`BypassPause`].
        bypass_pause: bool,
    }

    impl TestFactory {
        fn new(shared: &Shared) -> Self {
            Self {
                shared: Rc::clone(shared),
                bypass_pause: false,
            }
        }

        fn bypassing_pause(shared: &Shared) -> Self {
            Self {
                shared: Rc::clone(shared),
                bypass_pause: true,
            }
        }
    }

    impl<'data> ClientIoFactory<'data> for TestFactory {
        fn client_out_writer(&self) -> Box<dyn ClientWriter + 'data> {
            Box::new(ClientOutWriter::new(Box::new(TestOutput {
                shared: Rc::clone(&self.shared),
            })))
        }

        fn pause_writer(&self) -> Box<dyn ClientWriter + 'data> {
            if self.bypass_pause {
                Box::new(BypassPause)
            } else {
                Box::new(PauseWriter::new())
            }
        }

        fn input_source(&self) -> Option<Box<dyn ClientReadSource + 'data>> {
            None
        }
    }

    /// A handle onto a store the TEST owns.
    #[derive(Debug)]
    struct BorrowedStore<'store> {
        store: &'store mut HeaderStore,
        request: i32,
    }

    impl HeaderStoreHandle for BorrowedStore<'_> {
        fn store(&mut self) -> &mut HeaderStore {
            self.store
        }

        fn request(&self) -> i32 {
            self.request
        }
    }

    /// Everything one test needs, at a pinned instant.
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
    }

    /// The base chain, out of the two stages this module owns.
    fn base_chain<'data>(
        env: &mut Env,
        factory: &dyn ClientIoFactory<'data>,
    ) -> ClientWriterStack<'data> {
        let mut stack = ClientWriterStack::new();
        stack
            .init_base(&mut env.ctx(), factory)
            .expect("the base chain builds");
        assert_eq!(
            stack.names(),
            vec!["raw", "protocol", "cw-pause", "cw-out"],
            "the base chain is the one lib/sendf.c:325-368 builds"
        );
        stack
    }

    /// `CLIENTWRITE_BODY`.
    const BODY: ClientWriteFlags = ClientWriteFlags::BODY;
    /// `CLIENTWRITE_HEADER`.
    const HEADER: ClientWriteFlags = ClientWriteFlags::HEADER;
    /// `CLIENTWRITE_INFO`.
    const INFO: ClientWriteFlags = ClientWriteFlags::INFO;

    // -- the ABI vocabulary ------------------------------------------------

    /// Every constant is the integer `include/curl/curl.h` defines.
    ///
    /// The two write sentinels and the six pause macros cross the public ABI,
    /// so a drift in any of them changes what an application's callback means.
    #[test]
    fn abi_constants_are_the_public_header_values() {
        // `include/curl/curl.h:265`.
        assert_eq!(CURL_MAX_WRITE_SIZE, 16384);
        // `:277` and `:281`.
        assert_eq!(CURL_WRITEFUNC_PAUSE, 0x1000_0001);
        assert_eq!(CURL_WRITEFUNC_ERROR, 0xFFFF_FFFF);
        // Not `usize::MAX`, which is the asymmetry documented on the constant.
        assert_ne!(CURL_WRITEFUNC_ERROR, usize::MAX);

        // `:3256-3263`.
        assert_eq!(CURLPAUSE_RECV, 1);
        assert_eq!(CURLPAUSE_RECV_CONT, 0);
        assert_eq!(CURLPAUSE_SEND, 4);
        assert_eq!(CURLPAUSE_SEND_CONT, 0);
        assert_eq!(CURLPAUSE_ALL, 5);
        assert_eq!(CURLPAUSE_CONT, 0);
        // The gap between the two pause bits is part of the ABI.
        assert_eq!(CURLPAUSE_SEND, 1 << 2);

        // `lib/cw-pause.c:35` and `:37`.
        assert_eq!(CW_PAUSE_BUF_CHUNK, 16 * 1024);
        assert_eq!(CW_PAUSE_DEC_WRITE_CHUNK, 4096);

        // The one ceiling, imported and not restated -- `lib/curlx/dynbuf.h`.
        assert_eq!(DYN_PAUSE_BUFFER, 64 * 1024 * 1024);
    }

    /// The pause mask interprets exactly the two bits the C tests.
    #[test]
    fn pause_bits_read_the_mask_the_c_reads() {
        assert!(PauseBits::RECV.pauses_recv());
        assert!(!PauseBits::RECV.pauses_send());
        assert!(PauseBits::SEND.pauses_send());
        assert!(!PauseBits::SEND.pauses_recv());
        assert!(PauseBits::ALL.pauses_recv());
        assert!(PauseBits::ALL.pauses_send());
        assert!(!PauseBits::CONT.pauses_recv());
        assert!(!PauseBits::CONT.pauses_send());

        assert_eq!(PauseBits::ALL.bits(), CURLPAUSE_ALL);
        assert_eq!(PauseBits::CONT.bits(), CURLPAUSE_CONT);
        // The two "continue" spellings carry no information of their own.
        assert_eq!(PauseBits::from_bits(CURLPAUSE_RECV_CONT), PauseBits::CONT);

        // An unrecognised bit survives the round trip rather than being
        // masked away.
        let odd = PauseBits::from_bits(0x40 | CURLPAUSE_RECV);
        assert_eq!(odd.bits(), 0x41);
        assert!(odd.pauses_recv());
        assert!(!odd.pauses_send());
    }

    /// The typed outcome and the magic integers convert both ways, exactly.
    #[test]
    fn callback_outcomes_round_trip_the_sentinels() {
        assert_eq!(
            ClientWriteOutcome::from_callback_count(CURL_WRITEFUNC_PAUSE),
            ClientWriteOutcome::Pause
        );
        assert_eq!(
            ClientWriteOutcome::from_callback_count(CURL_WRITEFUNC_ERROR),
            ClientWriteOutcome::Error
        );
        assert_eq!(
            ClientWriteOutcome::from_callback_count(0),
            ClientWriteOutcome::Written(0)
        );
        assert_eq!(
            ClientWriteOutcome::from_callback_count(16384),
            ClientWriteOutcome::Written(16384)
        );
        // `(size_t)-1` is NOT the error sentinel on a 64-bit target.
        assert_eq!(
            ClientWriteOutcome::from_callback_count(usize::MAX),
            ClientWriteOutcome::Written(usize::MAX)
        );

        assert_eq!(
            ClientWriteOutcome::Pause.to_callback_count(),
            CURL_WRITEFUNC_PAUSE
        );
        assert_eq!(
            ClientWriteOutcome::Error.to_callback_count(),
            CURL_WRITEFUNC_ERROR
        );
        assert_eq!(ClientWriteOutcome::Written(7).to_callback_count(), 7);
    }

    /// The four buffer kinds keep the C's names and the C's trace wording.
    #[test]
    fn buffer_kinds_name_themselves_as_the_c_does() {
        assert_eq!(OutBufKind::None.c_name(), "CW_OUT_NONE");
        assert_eq!(OutBufKind::Body.c_name(), "CW_OUT_BODY");
        assert_eq!(OutBufKind::BodyZeroLen.c_name(), "CW_OUT_BODY_0LEN");
        assert_eq!(OutBufKind::Header.c_name(), "CW_OUT_HDS");

        // `lib/cw-out.c:193`: only CW_OUT_HDS renders as "header".
        assert_eq!(OutBufKind::Header.trace_word(), "header");
        assert_eq!(OutBufKind::Body.trace_word(), "body");
        assert_eq!(OutBufKind::BodyZeroLen.trace_word(), "body");
        assert_eq!(OutBufKind::None.trace_word(), "body");
    }

    /// The two stages report the names and phases the C registers them under.
    #[test]
    fn stage_identities_match_the_c_registrations() {
        let shared = recorder();
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let stack = base_chain(&mut env, &factory);

        let out = stack
            .get_by_kind(ClientWriterKind::ClientOut)
            .expect("the client stage is in the base chain");
        assert_eq!(out.name(), "cw-out");
        assert_eq!(out.phase(), ClientWriterPhase::Client);
        assert_eq!(out.alias(), None);

        let pause = stack
            .get_by_kind(ClientWriterKind::Pause)
            .expect("the pause stage is in the base chain");
        assert_eq!(pause.name(), "cw-pause");
        assert_eq!(pause.phase(), ClientWriterPhase::Protocol);

        // The client stage is LAST, which `lib/cw-out.c:39-40` requires.
        assert_eq!(stack.names().last().copied(), Some("cw-out"));
    }

    // -- the callback contract --------------------------------------------

    /// The ordinary case: the exact bytes reach the body callback, once.
    #[test]
    fn a_body_write_reaches_the_body_callback_exactly() {
        let shared = recorder();
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), BODY, b"hello")
            .expect("an exact count is a success");

        assert_eq!(
            events(&shared),
            vec![Event::Callback(Stream::Body, b"hello".to_vec())]
        );
        // The in-callback flag was raised once and lowered again.
        assert_eq!(env.guard.entries(), 1);
        assert_eq!(env.guard.depth, 0);
        assert_eq!(env.guard.peak, 1);
        // `lib/cw-out.c:192-194`.
        assert!(env.trace.saw_write("[OUT] wrote 5 body bytes -> 5"));
    }

    /// A count that is not the length offered fails the transfer, and the
    /// diagnostic reports BOTH numbers -- the returned one signed.
    #[test]
    fn a_short_count_is_a_write_error() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Count(2)];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        let error = stack
            .write(&mut env.ctx(), BODY, b"hello")
            .expect_err("a partial count is an error, not a retry");
        assert_eq!(error.code(), CURLcode::WriteError);
        // `lib/cw-out.c:213-214`.
        assert_eq!(
            error.message(),
            "Failure writing output to destination, passed 5 returned 2"
        );
        assert!(env.trace.saw_fail("passed 5 returned 2"));
        assert_eq!(env.guard.depth, 0);
    }

    /// A count the C would print as -1, because its format is `%zd`.
    #[test]
    fn a_wrapped_count_is_reported_signed() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Count(usize::MAX)];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        let error = stack
            .write(&mut env.ctx(), BODY, b"hi")
            .expect_err("SIZE_MAX is not a valid count");
        assert_eq!(error.code(), CURLcode::WriteError);
        assert_eq!(
            error.message(),
            "Failure writing output to destination, passed 2 returned -1"
        );
    }

    /// The error sentinel fails the transfer with its own diagnostic.
    #[test]
    fn the_error_sentinel_is_a_write_error() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Error];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        let error = stack
            .write(&mut env.ctx(), BODY, b"hello")
            .expect_err("CURL_WRITEFUNC_ERROR fails the transfer");
        assert_eq!(error.code(), CURLcode::WriteError);
        // `lib/cw-out.c:209`.
        assert_eq!(
            error.message(),
            "client returned ERROR on write of 5 bytes"
        );
        // Traced with the sentinel, not with a byte count.
        assert!(env.trace.saw_write(&format!("-> {CURL_WRITEFUNC_ERROR}")));
    }

    /// The pause sentinel buffers what was refused, reports the pause to the
    /// transfer loop, and leaves the chain paused.
    #[test]
    fn the_pause_sentinel_pauses_and_buffers() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        // A pause is NOT an error at this level: `cw_out_do_write` swallows
        // `CURLE_AGAIN` and buffers the remainder.
        stack
            .write(&mut env.ctx(), BODY, b"hello")
            .expect("a pause is backpressure, not a failure");

        assert!(is_paused(&stack), "the client stage is holding bytes back");
        assert!(stack.is_paused(), "and the chain agrees");
        // `Curl_xfer_pause_recv(data, TRUE)` reached the transfer loop once.
        assert_eq!(env.control.recv_pauses, vec![true]);
        assert!(env.control.send_pauses.is_empty());
        // The callback saw the bytes once and was not called again.
        assert_eq!(
            events(&shared),
            vec![Event::Callback(Stream::Body, b"hello".to_vec())]
        );
        assert!(env.trace.saw_write("[OUT] PAUSE requested by client"));
        assert!(env.trace.saw_write("[OUT] paused, buffering 5 more bytes"));
        assert_eq!(env.guard.depth, 0);
    }

    /// A refusal from the transfer loop propagates unchanged, rather than
    /// becoming the pause's `CURLE_AGAIN`.
    #[test]
    fn a_refused_pause_propagates_its_own_code() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        env.control.pause_fail = Some(CURLcode::RecvError);
        let mut stack = base_chain(&mut env, &factory);

        let error = stack
            .write(&mut env.ctx(), BODY, b"hello")
            .expect_err("the refusal is not swallowed");
        // `lib/cw-out.c:206`: `result ? result : CURLE_AGAIN`.
        assert_eq!(error.code(), CURLcode::RecvError);
    }

    /// A transfer that cannot be paused rejects the request outright.
    ///
    /// `PROTOPT_NONETWORK` is carried by `file://` alone among the nine schemes
    /// in scope, and `lib/cw-out.c:197-199` explains why it cannot pause: *"it
    /// cannot pause since the transfer is not done using the 'normal'
    /// procedure."*
    #[test]
    fn a_nonnetwork_transfer_cannot_be_paused() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        env.config.nonetwork = true;
        let mut stack = base_chain(&mut env, &factory);

        let error = stack
            .write(&mut env.ctx(), BODY, b"hello")
            .expect_err("file:// cannot pause");
        assert_eq!(error.code(), CURLcode::WriteError);
        // `lib/cw-out.c:200`, verbatim.
        assert_eq!(
            error.message(),
            "Write callback asked for PAUSE when not supported"
        );
        // Nothing was reported to the transfer loop and nothing is paused.
        assert!(env.control.recv_pauses.is_empty());
        assert!(!is_paused(&stack));
    }

    /// A permanent failure is sticky: the application is never called again,
    /// and everything buffered is released.
    ///
    /// The C's comment at `lib/cw-out.c:410-411` names the defect this fixes:
    /// *"We do not want to invoked client callbacks a second time after
    /// encountering an error. See issue #13337."*
    #[test]
    fn a_permanent_error_is_sticky_and_clears_the_buffers() {
        let shared = recorder();
        // Pause first so that bytes are buffered, THEN fail on the replay.
        shared.borrow_mut().script = vec![Answer::Pause, Answer::Error];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), BODY, b"buffered")
            .expect("the pause buffers");
        assert!(is_paused(&stack));

        // The replay reaches the callback a second time and it fails.
        let error = unpause(&mut stack, &mut env.ctx())
            .expect_err("the replay fails the transfer");
        assert_eq!(error.code(), CURLcode::WriteError);
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![8, 8],
            "exactly two invocations: the original and the replay"
        );

        // A third attempt reaches nothing, and reports the sticky state.
        let again = stack
            .write(&mut env.ctx(), BODY, b"more")
            .expect_err("the stage refuses everything now");
        assert_eq!(again.code(), CURLcode::WriteError);
        let flush = done(&mut stack, &mut env.ctx())
            .expect_err("and so does the end of stream");
        assert_eq!(flush.code(), CURLcode::WriteError);
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![8, 8],
            "no further invocation of any kind"
        );
    }

    /// The callback is resolved on every flush, so removing or replacing it
    /// between writes takes effect.
    ///
    /// `lib/cw-out.c:238` states the requirement: *"write callbacks may get
    /// NULLed by the client between calls."*
    #[test]
    fn the_callback_is_resolved_on_every_write() {
        let shared = recorder();
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), BODY, b"one")
            .expect("delivered");

        // The application removes its callback.
        shared.borrow_mut().has_body = false;
        stack
            .write(&mut env.ctx(), BODY, b"two")
            .expect("a missing callback consumes everything and succeeds");

        // And installs it again.
        shared.borrow_mut().has_body = true;
        stack
            .write(&mut env.ctx(), BODY, b"three")
            .expect("delivered");

        assert_eq!(
            events(&shared),
            vec![
                Event::Callback(Stream::Body, b"one".to_vec()),
                Event::Callback(Stream::Body, b"three".to_vec()),
            ],
            "the middle write was dropped, not buffered"
        );
    }

    /// Body writes are chunked at `CURL_MAX_WRITE_SIZE`; headers never are.
    #[test]
    fn bodies_chunk_at_the_abi_maximum_and_headers_do_not() {
        let shared = recorder();
        shared.borrow_mut().has_header = true;
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        // Two full chunks and a remainder.
        let body = vec![b'x'; CURL_MAX_WRITE_SIZE * 2 + 7];
        stack.write(&mut env.ctx(), BODY, &body).expect("delivered");
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![CURL_MAX_WRITE_SIZE, CURL_MAX_WRITE_SIZE, 7]
        );
        assert_eq!(callback_bytes(&shared, Stream::Body), body);

        // A header of the same length arrives in ONE call: `max_write` is zero
        // for that stream (`lib/cw-out.c:163`).
        let header = vec![b'h'; CURL_MAX_WRITE_SIZE * 2 + 7];
        stack
            .write(&mut env.ctx(), HEADER, &header)
            .expect("delivered");
        assert_eq!(
            callback_lengths(&shared, Stream::Header),
            vec![CURL_MAX_WRITE_SIZE * 2 + 7]
        );
    }

    /// A zero-length body write still reaches the callback.
    ///
    /// `CLIENTWRITE_0LEN` is what asks for it, and `lib/sendf.c:258` means the
    /// download stage forwards an empty write only when the stream is also
    /// ending -- so the two flags travel together in practice.
    #[test]
    fn a_zero_length_body_write_still_calls_back() {
        let shared = recorder();
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        let flags = BODY
            .union(ClientWriteFlags::ZERO_LEN)
            .union(ClientWriteFlags::EOS);
        stack.write(&mut env.ctx(), flags, b"").expect("delivered");

        assert_eq!(
            events(&shared),
            vec![Event::Callback(Stream::Body, Vec::new())]
        );
        assert_eq!(env.guard.entries(), 1);
    }

    /// A zero-length write WITHOUT the flag reaches no callback at all.
    #[test]
    fn a_zero_length_body_write_without_the_flag_calls_nothing() {
        let shared = recorder();
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), BODY.union(ClientWriteFlags::EOS), b"")
            .expect("an empty body write is not an error");

        assert!(events(&shared).is_empty());
    }

    // -- the routing matrix ------------------------------------------------

    /// A header with `CURLOPT_HEADER` off reaches the header stream only.
    #[test]
    fn a_header_without_include_header_reaches_one_stream() {
        let shared = recorder();
        shared.borrow_mut().has_header = true;
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), HEADER, b"Server: x\r\n")
            .expect("delivered");

        assert_eq!(
            events(&shared),
            vec![Event::Callback(Stream::Header, b"Server: x\r\n".to_vec())]
        );
    }

    /// A header with `CURLOPT_HEADER` on reaches BOTH streams, the body one
    /// first.
    ///
    /// This is `curl -i`, and the order is `lib/cw-out.c:426-439`: the body
    /// test comes before the header test, so an application with two callbacks
    /// sees the header twice in that order.
    #[test]
    fn a_header_with_include_header_reaches_body_then_header() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            state.include_header = true;
        }
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), HEADER, b"Server: x\r\n")
            .expect("delivered");

        assert_eq!(
            events(&shared),
            vec![
                Event::Callback(Stream::Body, b"Server: x\r\n".to_vec()),
                Event::Callback(Stream::Header, b"Server: x\r\n".to_vec()),
            ]
        );
    }

    /// An informational write reaches the header stream and never the body.
    ///
    /// `CLIENTWRITE_INFO` is an FTP or IMAP pingpong reply: metadata that
    /// cannot be read as a response header, and which `CURLOPT_HEADER` does not
    /// route to the body -- the C's include test is on `CLIENTWRITE_HEADER`
    /// alone (`lib/cw-out.c:427`).
    #[test]
    fn an_informational_write_reaches_the_header_stream_only() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            state.include_header = true;
        }
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), INFO, b"220 ready\r\n")
            .expect("delivered");

        assert_eq!(
            events(&shared),
            vec![Event::Callback(Stream::Header, b"220 ready\r\n".to_vec())],
            "include_header routes HEADER, not INFO"
        );
    }

    /// With `CURLOPT_HEADERDATA` set and no header callback, headers go to the
    /// BODY callback with the HEADER destination.
    ///
    /// `lib/cw-out.c:160-162`, the crossed pairing.
    #[test]
    fn a_header_falls_back_to_the_body_callback_with_the_header_target() {
        let shared = recorder();
        shared.borrow_mut().has_header_target = true;
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), HEADER, b"Date: now\r\n")
            .expect("delivered");

        assert_eq!(
            events(&shared),
            vec![Event::Callback(
                Stream::BodyToHeaderTarget,
                b"Date: now\r\n".to_vec()
            )]
        );
    }

    /// `CURLOPT_HEADERDATA` without a body callback yields NO callback.
    ///
    /// The C's inner conditional still evaluates to `data->set.fwrite_func`,
    /// which is null, so the whole expression is null.
    #[test]
    fn a_header_target_without_a_body_callback_delivers_nothing() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_body = false;
            state.has_header_target = true;
        }
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), HEADER, b"Date: now\r\n")
            .expect("a missing callback consumes and succeeds");

        assert!(events(&shared).is_empty());
    }

    /// A body callback alone, with no `CURLOPT_HEADERDATA`, gets no headers.
    #[test]
    fn a_body_callback_alone_receives_no_headers() {
        let shared = recorder();
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), HEADER, b"Date: now\r\n")
            .expect("consumed and succeeded");
        stack
            .write(&mut env.ctx(), BODY, b"body")
            .expect("delivered");

        assert_eq!(
            events(&shared),
            vec![Event::Callback(Stream::Body, b"body".to_vec())],
            "the header was dropped; only the body reached the callback"
        );
    }

    /// The header qualifiers are not separate streams.
    ///
    /// `STATUS`, `CONNECT`, `1XX` and `TRAILER` qualify `HEADER` for the
    /// collector's benefit; the client stage routes on `HEADER` alone.
    #[test]
    fn header_qualifiers_do_not_change_the_routing() {
        let shared = recorder();
        shared.borrow_mut().has_header = true;
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        for qualifier in [
            ClientWriteFlags::STATUS,
            ClientWriteFlags::CONNECT,
            ClientWriteFlags::ONE_XX,
            ClientWriteFlags::TRAILER,
        ] {
            stack
                .write(&mut env.ctx(), HEADER.union(qualifier), b"h\r\n")
                .expect("delivered");
        }

        assert_eq!(
            callback_lengths(&shared, Stream::Header),
            vec![3, 3, 3, 3],
            "every qualifier reached the header stream, unchanged"
        );
    }

    // -- ordered buffering and replay --------------------------------------

    /// Alternating streams replay in arrival order, and header boundaries
    /// survive.
    #[test]
    fn alternating_streams_replay_in_arrival_order() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            // Pause on the very first invocation, then accept everything.
            state.script = vec![Answer::Pause];
        }
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack.write(&mut env.ctx(), BODY, b"one").expect("buffered");
        assert!(is_paused(&stack));
        stack
            .write(&mut env.ctx(), HEADER, b"A\r\n")
            .expect("buffered");
        stack
            .write(&mut env.ctx(), HEADER, b"B\r\n")
            .expect("buffered");
        stack.write(&mut env.ctx(), BODY, b"two").expect("buffered");

        // Only the paused invocation has happened so far.
        assert_eq!(
            events(&shared),
            vec![Event::Callback(Stream::Body, b"one".to_vec())]
        );

        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        assert_eq!(
            events(&shared),
            vec![
                Event::Callback(Stream::Body, b"one".to_vec()),
                Event::Callback(Stream::Body, b"one".to_vec()),
                Event::Callback(Stream::Header, b"A\r\n".to_vec()),
                Event::Callback(Stream::Header, b"B\r\n".to_vec()),
                Event::Callback(Stream::Body, b"two".to_vec()),
            ],
            "arrival order, with the two headers still two invocations"
        );
        assert!(!is_paused(&stack));
    }

    /// Two consecutive body writes buffered behind a pause COALESCE into one
    /// invocation.
    ///
    /// The counterpart of the header rule above, and the reason the C singles
    /// headers out: body bytes are a stream with no boundaries to preserve.
    #[test]
    fn consecutive_body_runs_coalesce_on_replay() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack.write(&mut env.ctx(), BODY, b"aa").expect("buffered");
        stack.write(&mut env.ctx(), BODY, b"bb").expect("buffered");
        stack.write(&mut env.ctx(), BODY, b"cc").expect("buffered");
        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![2, 6],
            "the paused call, then one replay of all six bytes"
        );
        assert_eq!(callback_bytes(&shared, Stream::Body), b"aaaabbcc".to_vec());
    }

    /// A pause DURING the replay stops it, and nothing is delivered twice.
    #[test]
    fn a_pause_during_the_replay_stops_it_without_duplication() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            // Pause on the first invocation, and again on the replay's first.
            state.script = vec![Answer::Pause, Answer::Pause];
        }
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), BODY, b"body")
            .expect("buffered");
        stack
            .write(&mut env.ctx(), HEADER, b"H\r\n")
            .expect("buffered");

        unpause(&mut stack, &mut env.ctx())
            .expect("a re-pause is not an error");
        assert!(is_paused(&stack), "the stage paused again");
        assert_eq!(
            events(&shared),
            vec![
                Event::Callback(Stream::Body, b"body".to_vec()),
                Event::Callback(Stream::Body, b"body".to_vec()),
            ],
            "the header run was not reached"
        );

        // The second unpause finishes the job. The body run is OFFERED a third
        // time -- it was refused twice, so it was never consumed and the queue
        // still holds it -- and the header run follows it. What must not happen
        // is a byte reaching the application twice having been ACCEPTED once,
        // and it does not: every acceptance below is a first acceptance.
        unpause(&mut stack, &mut env.ctx()).expect("the replay finishes");
        assert_eq!(
            events(&shared),
            vec![
                Event::Callback(Stream::Body, b"body".to_vec()),
                Event::Callback(Stream::Body, b"body".to_vec()),
                Event::Callback(Stream::Body, b"body".to_vec()),
                Event::Callback(Stream::Header, b"H\r\n".to_vec()),
            ]
        );
        assert!(!is_paused(&stack));

        // A third unpause has nothing left to offer.
        unpause(&mut stack, &mut env.ctx()).expect("the queue is empty");
        assert_eq!(events(&shared).len(), 4);
    }

    /// A partial consumption keeps only the unconsumed tail.
    ///
    /// The path `lib/cw-out.c:290-296` takes: a chunked body write whose second
    /// chunk pauses leaves the second chunk buffered and the first delivered,
    /// and the replay must not repeat the first.
    #[test]
    fn a_partial_flush_keeps_only_the_tail() {
        let shared = recorder();
        // Accept the first chunk, pause on the second.
        shared.borrow_mut().script = vec![Answer::Exact, Answer::Pause];
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        // Three chunks: accepted, paused, and never offered before the pause.
        let body: Vec<u8> = (0..CURL_MAX_WRITE_SIZE * 2 + 10)
            .map(|index| u8::try_from(index % 251).expect("below 251"))
            .collect();
        stack.write(&mut env.ctx(), BODY, &body).expect("buffered");

        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![CURL_MAX_WRITE_SIZE, CURL_MAX_WRITE_SIZE],
            "the first chunk was accepted and the second paused"
        );
        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        // The buffered remainder is the paused chunk plus everything after it,
        // and the replay chunks it afresh.
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![
                CURL_MAX_WRITE_SIZE,
                CURL_MAX_WRITE_SIZE,
                CURL_MAX_WRITE_SIZE,
                10
            ]
        );
        // The ACCEPTED bytes are the whole body exactly once. The refused chunk
        // was offered twice, which is why it appears twice in the log: the
        // buffer kept only the tail the application had not taken, so nothing
        // it accepted was offered again.
        let mut expected = body[..CURL_MAX_WRITE_SIZE * 2].to_vec();
        expected.extend_from_slice(&body[CURL_MAX_WRITE_SIZE..]);
        assert_eq!(callback_bytes(&shared, Stream::Body), expected);
    }

    /// Arbitrary bytes -- NUL, every high byte, an embedded CRLF -- replay
    /// unchanged.
    #[test]
    fn arbitrary_bytes_replay_unchanged() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        let payload: Vec<u8> = (0..=255_u8).chain([0, 13, 10, 0]).collect();
        stack
            .write(&mut env.ctx(), BODY, &payload)
            .expect("buffered");
        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![payload.len(), payload.len()]
        );
        let mut expected = payload.clone();
        expected.extend_from_slice(&payload);
        assert_eq!(callback_bytes(&shared, Stream::Body), expected);
    }

    /// The end of stream forces out what collation would hold back.
    #[test]
    fn the_end_of_stream_flushes_everything() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            state.script = vec![Answer::Pause];
        }
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack.write(&mut env.ctx(), BODY, b"b").expect("buffered");
        stack.write(&mut env.ctx(), HEADER, b"h").expect("buffered");

        // `done` alone delivers nothing while the stage is paused, and reports
        // no error for it -- both C flushes decline.
        done(&mut stack, &mut env.ctx())
            .expect("a paused done is not an error");
        assert_eq!(callback_lengths(&shared, Stream::Body), vec![1]);

        // Once unpaused, `done` forces the rest out.
        stack
            .get_by_kind(ClientWriterKind::ClientOut)
            .expect("the client stage is installed");
        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");
        done(&mut stack, &mut env.ctx()).expect("nothing is left to fail");

        assert_eq!(
            events(&shared),
            vec![
                Event::Callback(Stream::Body, b"b".to_vec()),
                Event::Callback(Stream::Body, b"b".to_vec()),
                Event::Callback(Stream::Header, b"h".to_vec()),
            ]
        );
        assert!(env.trace.saw_write("[OUT] done"));
        assert!(env.trace.saw_write("[OUT] unpause"));
    }

    /// Neither entry point does anything without a client stage.
    ///
    /// `lib/cw-out.c:459-460`, `:493` and `:510` all guard on finding it.
    #[test]
    fn the_entry_points_are_inert_without_a_client_stage() {
        let mut env = Env::new();
        let mut stack: ClientWriterStack<'_> = ClientWriterStack::new();

        assert!(!is_paused(&stack));
        unpause(&mut stack, &mut env.ctx()).expect("nothing to unpause");
        done(&mut stack, &mut env.ctx()).expect("nothing to finish");
        assert!(stack.is_empty());
    }

    // -- the aggregate ceiling ---------------------------------------------

    /// The 64-mebibyte ceiling is exact, and it is a SUM across every run.
    #[test]
    #[cfg_attr(miri, ignore = "buffers 64 MiB; the arithmetic is the point")]
    fn the_aggregate_ceiling_is_exact() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            state.script = vec![Answer::Pause];
        }
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        let half = vec![b'h'; DYN_PAUSE_BUFFER / 2];
        stack
            .write(&mut env.ctx(), HEADER, &half)
            .expect("the first half buffers");
        assert!(is_paused(&stack));
        stack
            .write(&mut env.ctx(), HEADER, &half)
            .expect("the second half reaches the ceiling exactly");

        // One more byte crosses it.
        let error = stack
            .write(&mut env.ctx(), HEADER, b"!")
            .expect_err("one byte past the ceiling is refused");
        assert_eq!(error.code(), CURLcode::TooLarge);
        // `lib/cw-out.c:348`, verbatim.
        assert_eq!(
            error.message(),
            "pause buffer not large enough -> CURLE_TOO_LARGE"
        );

        // The refusal latched the failure, so nothing is replayed.
        let after = unpause(&mut stack, &mut env.ctx())
            .expect_err("the stage is in its sticky state");
        assert_eq!(after.code(), CURLcode::WriteError);
        assert_eq!(
            callback_lengths(&shared, Stream::Header),
            vec![DYN_PAUSE_BUFFER / 2],
            "only the paused invocation ever happened"
        );
    }

    /// A single run is bounded by the per-buffer ceiling as well.
    #[test]
    #[cfg_attr(miri, ignore = "buffers 64 MiB; the arithmetic is the point")]
    fn a_single_run_is_bounded_by_the_buffer_ceiling_too() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        let whole = vec![b'b'; DYN_PAUSE_BUFFER];
        let error = stack
            .write(&mut env.ctx(), BODY, &whole)
            .expect_err("one run cannot hold the whole ceiling");
        assert_eq!(error.code(), CURLcode::TooLarge);
    }

    // -- the in-flight stage -----------------------------------------------

    /// Installs a relay at [`ClientWriterPhase::ContentDecode`], which is BELOW
    /// the pause stage and ABOVE the client stage.
    ///
    /// Its presence makes [`WriterTail::is_content_decoding`] answer true from
    /// the pause stage, because that question is a phase test.
    fn with_relay<'data>(
        stack: &mut ClientWriterStack<'data>,
        env: &mut Env,
        factory: &dyn ClientIoFactory<'data>,
        shared: &Shared,
    ) {
        stack
            .add(
                Box::new(Relay {
                    shared: Rc::clone(shared),
                }),
                &mut env.ctx(),
                factory,
            )
            .expect("the relay installs");
        assert_eq!(
            stack.names(),
            vec!["raw", "protocol", "cw-pause", "relay", "cw-out"],
            "the relay sits between the pause stage and the client stage"
        );
    }

    /// Every downstream write the relay recorded, as (flags, length).
    fn relay_writes(shared: &Shared) -> Vec<(ClientWriteFlags, usize)> {
        shared
            .borrow()
            .events
            .iter()
            .filter_map(|event| match event {
                Event::Relay(flags, bytes) => Some((*flags, bytes.len())),
                Event::Callback(..) => None,
            })
            .collect()
    }

    /// With no content decoder installed, a body write is forwarded whole.
    ///
    /// The `decoding` test at `lib/cw-pause.c:162` is false, so `wlen` is the
    /// whole length and the end-of-stream flag stays on the one segment there
    /// is.
    #[test]
    fn without_decoding_a_body_write_is_forwarded_whole() {
        let shared = recorder();
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        // Well past the decode chunk, and past the client stage's chunk too, so
        // that neither could be mistaken for the other.
        let body = vec![b'z'; CW_PAUSE_DEC_WRITE_CHUNK * 3];
        let flags = BODY.union(ClientWriteFlags::EOS);
        stack
            .write(&mut env.ctx(), flags, &body)
            .expect("delivered");

        // The client stage still chunks at its own maximum, and 12288 is below
        // it, so exactly one callback invocation proves the pause stage did not
        // split the write.
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![CW_PAUSE_DEC_WRITE_CHUNK * 3]
        );
    }

    /// With a content decoder installed, a body write is split at 4096 bytes
    /// and only the LAST segment carries the end of stream.
    #[test]
    fn with_decoding_a_body_write_splits_and_keeps_the_eos_last() {
        let shared = recorder();
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);
        with_relay(&mut stack, &mut env, &factory, &shared);

        let body = vec![b'z'; CW_PAUSE_DEC_WRITE_CHUNK * 2 + 100];
        let flags = BODY.union(ClientWriteFlags::EOS);
        stack
            .write(&mut env.ctx(), flags, &body)
            .expect("delivered");

        assert_eq!(
            relay_writes(&shared),
            vec![
                (BODY, CW_PAUSE_DEC_WRITE_CHUNK),
                (BODY, CW_PAUSE_DEC_WRITE_CHUNK),
                (flags, 100),
            ],
            "three segments, and only the last carries EOS"
        );
        // Every byte still reached the application, in order.
        assert_eq!(callback_bytes(&shared, Stream::Body), body);
    }

    /// A metadata write is never split, decoder or no decoder.
    ///
    /// The `decoding` test is conjoined with `CLIENTWRITE_BODY`
    /// (`lib/cw-pause.c:162`), so a header of any size crosses in one piece --
    /// which is what keeps one header to one callback.
    #[test]
    fn a_metadata_write_is_never_split() {
        let shared = recorder();
        shared.borrow_mut().has_header = true;
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);
        with_relay(&mut stack, &mut env, &factory, &shared);

        let header = vec![b'h'; CW_PAUSE_DEC_WRITE_CHUNK * 2];
        stack
            .write(&mut env.ctx(), HEADER, &header)
            .expect("delivered");

        assert_eq!(
            relay_writes(&shared),
            vec![(HEADER, CW_PAUSE_DEC_WRITE_CHUNK * 2)]
        );
    }

    /// While the client stage is paused, the in-flight stage holds what
    /// arrives -- and an unpause drains it BEFORE the client stage's own queue.
    #[test]
    fn an_unpause_drains_the_in_flight_stage_first() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);
        with_relay(&mut stack, &mut env, &factory, &shared);

        // The first write reaches the client stage, which pauses and buffers.
        stack
            .write(&mut env.ctx(), BODY, b"first")
            .expect("buffered");
        assert!(is_paused(&stack));
        // The second never reaches it: the in-flight stage holds it.
        stack.write(&mut env.ctx(), BODY, b"second").expect("held");

        assert_eq!(
            events(&shared),
            vec![
                Event::Relay(BODY, b"first".to_vec()),
                Event::Callback(Stream::Body, b"first".to_vec()),
            ],
            "the second write stopped at the pause stage"
        );

        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        assert_eq!(
            events(&shared),
            vec![
                Event::Relay(BODY, b"first".to_vec()),
                Event::Callback(Stream::Body, b"first".to_vec()),
                // The in-flight stage replays FIRST, through the relay.
                Event::Relay(BODY, b"second".to_vec()),
                // Reaching the client stage, which appends it behind the run it
                // was already holding and delivers both in arrival order.
                Event::Callback(Stream::Body, b"firstsecond".to_vec()),
            ]
        );
        assert!(!is_paused(&stack));
        assert!(env.trace.saw_write("[PAUSE] flushed 6/6 bytes"));
    }

    /// The end of stream drains the in-flight stage first as well.
    #[test]
    fn the_end_of_stream_drains_the_in_flight_stage_first() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);
        with_relay(&mut stack, &mut env, &factory, &shared);

        stack.write(&mut env.ctx(), BODY, b"a").expect("buffered");
        stack.write(&mut env.ctx(), BODY, b"b").expect("held");

        // Paused, so `done` delivers nothing and reports no error.
        done(&mut stack, &mut env.ctx()).expect("a paused done is inert");
        assert_eq!(callback_lengths(&shared, Stream::Body), vec![1]);

        // Unpaused, `done` drains both stages in the same order.
        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");
        done(&mut stack, &mut env.ctx()).expect("nothing is left");

        assert_eq!(callback_bytes(&shared, Stream::Body), b"aab".to_vec());
    }

    /// An empty run that carries the end of stream still forwards a zero-length
    /// write.
    #[test]
    fn an_empty_end_of_stream_run_is_still_forwarded() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);
        with_relay(&mut stack, &mut env, &factory, &shared);

        // Pause the client stage.
        stack.write(&mut env.ctx(), BODY, b"x").expect("buffered");
        assert!(is_paused(&stack));

        // A zero-length end-of-stream write now reaches the paused in-flight
        // stage, which has to hold it: there is no byte to hold, only the flag.
        let eos = BODY
            .union(ClientWriteFlags::EOS)
            .union(ClientWriteFlags::ZERO_LEN);
        stack.write(&mut env.ctx(), eos, b"").expect("held");
        assert_eq!(
            relay_writes(&shared),
            vec![(BODY, 1)],
            "nothing has crossed the relay since the pause"
        );

        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        assert_eq!(
            relay_writes(&shared),
            vec![(BODY, 1), (eos, 0)],
            "the empty run replayed as a zero-length write with its flags"
        );
        assert!(env.trace.saw_write("[PAUSE] flushed 0/0 bytes"));
        // And the client stage turned it into a zero-length body callback.
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![1, 1, 0],
            "the run, its replay, and the zero-length end of stream"
        );
    }

    /// A metadata run and a body run held together replay in arrival order,
    /// each with its own boundaries.
    ///
    /// `lib/cw-pause.c:179-192`: only a BODY run of the SAME flags is appended
    /// to, so a header held while paused keeps a run of its own.
    #[test]
    fn held_runs_of_different_kinds_replay_in_order() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            state.script = vec![Answer::Pause];
        }
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);
        with_relay(&mut stack, &mut env, &factory, &shared);

        stack.write(&mut env.ctx(), BODY, b"p").expect("buffered");
        stack.write(&mut env.ctx(), BODY, b"11").expect("held");
        stack.write(&mut env.ctx(), HEADER, b"H\r\n").expect("held");
        stack.write(&mut env.ctx(), BODY, b"22").expect("held");

        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        assert_eq!(
            relay_writes(&shared),
            vec![(BODY, 1), (BODY, 2), (HEADER, 3), (BODY, 2),],
            "arrival order, with the header a run of its own"
        );
    }

    /// The 64-mebibyte bound applies to the in-flight stage too.
    #[test]
    #[cfg_attr(miri, ignore = "buffers 64 MiB; the arithmetic is the point")]
    fn the_in_flight_stage_is_bounded_as_well() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), BODY, b"pause me")
            .expect("buffered");
        assert!(is_paused(&stack));

        // Exactly the ceiling is accepted.
        let half = vec![b'q'; DYN_PAUSE_BUFFER / 2];
        stack.write(&mut env.ctx(), BODY, &half).expect("held");
        stack
            .write(&mut env.ctx(), BODY, &half)
            .expect("held to the ceiling");

        // One byte past it is refused.
        let error = stack
            .write(&mut env.ctx(), BODY, b"!")
            .expect_err("the in-flight stage is bounded");
        assert_eq!(error.code(), CURLcode::TooLarge);
        assert!(env.trace.saw_fail("pause buffer not large enough"));
    }

    // -- the header collector ----------------------------------------------

    /// The origin precedence is `classify_origin`'s, and every write is
    /// forwarded whether it was stored or not.
    ///
    /// `lib/headers.c:300-312`. The five cases below are the whole of the
    /// mapping: a `STATUS` line is stored under no origin at all, and the other
    /// four resolve by first match rather than by union.
    #[test]
    fn the_collector_stores_by_origin_and_forwards_everything() {
        let shared = recorder();
        shared.borrow_mut().has_header = true;
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut store = HeaderStore::new();

        {
            let mut stack = base_chain(&mut env, &factory);
            install_header_collector(
                &mut stack,
                &mut env.ctx(),
                &factory,
                Box::new(BorrowedStore {
                    store: &mut store,
                    request: 2,
                }),
                true,
            )
            .expect("the collector installs");
            assert_eq!(
                stack.names(),
                vec!["raw", "hds-collect", "protocol", "cw-pause", "cw-out"],
                "inserted FIRST within CURL_CW_PROTOCOL, so it lands ahead of \
                 the download stage and sees a header before it does"
            );

            // A status line: forwarded, never stored.
            stack
                .write(
                    &mut env.ctx(),
                    HEADER.union(ClientWriteFlags::STATUS),
                    b"HTTP/1.1 200 OK\r\n",
                )
                .expect("forwarded");
            // The four origins, in the C's precedence order.
            stack
                .write(
                    &mut env.ctx(),
                    HEADER.union(ClientWriteFlags::CONNECT),
                    b"Proxy: yes\r\n",
                )
                .expect("stored");
            stack
                .write(
                    &mut env.ctx(),
                    HEADER
                        .union(ClientWriteFlags::ONE_XX)
                        .union(ClientWriteFlags::TRAILER),
                    b"Early: hint\r\n",
                )
                .expect("stored");
            stack
                .write(
                    &mut env.ctx(),
                    HEADER.union(ClientWriteFlags::TRAILER),
                    b"Trailer: last\r\n",
                )
                .expect("stored");
            stack
                .write(&mut env.ctx(), HEADER, b"Server: x\r\n")
                .expect("stored");
            // A body: forwarded, never stored.
            stack
                .write(&mut env.ctx(), BODY, b"payload")
                .expect("forwarded");
        }

        let stored: Vec<(Vec<u8>, u32, i32)> = store
            .as_slice()
            .iter()
            .map(|entry| {
                (entry.name().to_vec(), entry.origin(), entry.request())
            })
            .collect();
        assert_eq!(
            stored,
            vec![
                (b"Proxy".to_vec(), CURLH_CONNECT, 2),
                (b"Early".to_vec(), CURLH_1XX, 2),
                (b"Trailer".to_vec(), CURLH_TRAILER, 2),
                (b"Server".to_vec(), CURLH_HEADER, 2),
            ],
            "CONNECT before 1XX before TRAILER before HEADER, and no status \
             line"
        );

        // Everything was forwarded, stored or not.
        assert_eq!(
            callback_lengths(&shared, Stream::Header),
            vec![17, 12, 13, 15, 11]
        );
        assert_eq!(callback_bytes(&shared, Stream::Body), b"payload".to_vec());
        assert!(env.trace.saw_write("header_collect pushed(type=4, len=12)"));
    }

    /// A store failure aborts the write, so the header never reaches the
    /// stages below.
    ///
    /// The currency is the store's and is not remapped: a store already holding
    /// `MAX_HTTP_RESP_HEADER_COUNT` headers reports
    /// [`CURLcode::TooLarge`] (`lib/headers.c:253-257`).
    #[test]
    fn a_store_failure_aborts_the_write() {
        let shared = recorder();
        shared.borrow_mut().has_header = true;
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut store = HeaderStore::new();
        for index in 0..MAX_HTTP_RESP_HEADER_COUNT {
            store
                .push(format!("H{index}: v\r\n").as_bytes(), CURLH_HEADER, 0)
                .expect("the store admits this many");
        }
        assert_eq!(store.count(), MAX_HTTP_RESP_HEADER_COUNT);

        {
            let mut stack = base_chain(&mut env, &factory);
            install_header_collector(
                &mut stack,
                &mut env.ctx(),
                &factory,
                Box::new(BorrowedStore {
                    store: &mut store,
                    request: 0,
                }),
                true,
            )
            .expect("the collector installs");

            let error = stack
                .write(&mut env.ctx(), HEADER, b"One: too many\r\n")
                .expect_err("the store is full");
            assert_eq!(error.code(), CURLcode::TooLarge);
        }

        // The write was aborted, so no callback saw it.
        assert!(events(&shared).is_empty());
        assert_eq!(store.count(), MAX_HTTP_RESP_HEADER_COUNT);
    }

    /// A malformed header reports the store's own code, not a remapped one.
    #[test]
    fn a_malformed_header_reports_the_stores_code() {
        let shared = recorder();
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut store = HeaderStore::new();

        {
            let mut stack = base_chain(&mut env, &factory);
            install_header_collector(
                &mut stack,
                &mut env.ctx(),
                &factory,
                Box::new(BorrowedStore {
                    store: &mut store,
                    request: 0,
                }),
                true,
            )
            .expect("the collector installs");

            // No terminator at all: `lib/headers.c:240-242`.
            let error = stack
                .write(&mut env.ctx(), HEADER, b"Server: x")
                .expect_err("an unterminated line is rejected");
            assert_eq!(error.code(), CURLcode::WeirdServerReply);

            // No separating colon: `lib/headers.c:265` through `namevalue`.
            let error = stack
                .write(&mut env.ctx(), HEADER, b"nonsense\r\n")
                .expect_err("a line with no colon is rejected");
            assert_eq!(error.code(), CURLcode::BadFunctionArgument);
        }

        assert!(store.is_empty());
    }

    /// The collector is installed once, and not at all for a non-HTTP
    /// transfer.
    ///
    /// `lib/headers.c:329-332`. The double-install guard matters because a
    /// redirection is a further request on the same chain, and two collectors
    /// would store every header twice.
    #[test]
    fn the_collector_installs_once_and_only_for_http() {
        let shared = recorder();
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut store = HeaderStore::new();
        // Two further stores rather than one reused: a handle's borrow lasts as
        // long as the chain does, whether or not the chain kept the handle.
        let mut unused_non_http = HeaderStore::new();
        let mut unused_second = HeaderStore::new();

        {
            let mut stack = base_chain(&mut env, &factory);

            // Not HTTP: nothing is installed.
            install_header_collector(
                &mut stack,
                &mut env.ctx(),
                &factory,
                Box::new(BorrowedStore {
                    store: &mut unused_non_http,
                    request: 0,
                }),
                false,
            )
            .expect("a non-HTTP transfer needs no collector");
            assert_eq!(
                stack.names(),
                vec!["raw", "protocol", "cw-pause", "cw-out"]
            );

            // HTTP: installed.
            install_header_collector(
                &mut stack,
                &mut env.ctx(),
                &factory,
                Box::new(BorrowedStore {
                    store: &mut store,
                    request: 0,
                }),
                true,
            )
            .expect("the collector installs");
            assert_eq!(
                stack.names(),
                vec!["raw", "hds-collect", "protocol", "cw-pause", "cw-out"]
            );

            // Again: refused, silently and successfully.
            install_header_collector(
                &mut stack,
                &mut env.ctx(),
                &factory,
                Box::new(BorrowedStore {
                    store: &mut unused_second,
                    request: 0,
                }),
                true,
            )
            .expect("a second install is a no-op");
            assert_eq!(
                stack.names(),
                vec!["raw", "hds-collect", "protocol", "cw-pause", "cw-out"]
            );

            stack
                .write(&mut env.ctx(), HEADER, b"Server: x\r\n")
                .expect("stored once");
        }

        assert_eq!(store.count(), 1, "one collector, one entry");
        assert!(
            unused_non_http.is_empty(),
            "a non-HTTP transfer collects nothing"
        );
        assert!(
            unused_second.is_empty(),
            "the second handle was never installed"
        );
    }

    // -- the remaining invariants ------------------------------------------

    /// Two IDENTICAL headers buffered behind a pause stay two invocations.
    #[test]
    fn identical_headers_keep_their_own_runs() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            state.script = vec![Answer::Pause];
        }
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        // Pause the stage on a header, then buffer the same header twice more.
        stack
            .write(&mut env.ctx(), HEADER, b"X: 1\r\n")
            .expect("buffered");
        stack
            .write(&mut env.ctx(), HEADER, b"X: 1\r\n")
            .expect("buffered");
        stack
            .write(&mut env.ctx(), HEADER, b"X: 1\r\n")
            .expect("buffered");

        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        assert_eq!(
            callback_lengths(&shared, Stream::Header),
            vec![6, 6, 6, 6],
            "the paused invocation and three distinct replays"
        );
    }

    /// The in-callback flag is raised exactly once per invocation and lowered
    /// again, never nesting.
    ///
    /// `Curl_set_in_callback` is what makes libcurl refuse a reentrant API call
    /// from inside a callback, so a missed restore would leave a handle
    /// permanently unusable. Every path out of `cw_out_cb_write` is exercised
    /// here -- success, a short count, the error sentinel and a pause --
    /// and the
    /// flag balances on all four.
    #[test]
    fn the_in_callback_flag_balances_on_every_path() {
        for script in [
            vec![Answer::Exact],
            vec![Answer::Count(1)],
            vec![Answer::Error],
            vec![Answer::Pause],
        ] {
            let shared = recorder();
            shared.borrow_mut().script = script;
            let factory = TestFactory::new(&shared);
            let mut env = Env::new();
            let mut stack = base_chain(&mut env, &factory);

            // The result varies with the script; the flag must not.
            let _ = stack.write(&mut env.ctx(), BODY, b"abc");

            assert_eq!(env.guard.entries(), 1, "one invocation, one raise");
            assert_eq!(env.guard.depth, 0, "the flag was lowered again");
            assert_eq!(env.guard.peak, 1, "the flag never nested");
            assert_eq!(env.guard.transitions, vec![true, false]);
        }
    }

    /// Tearing the chain down releases everything buffered without delivering
    /// it.
    ///
    /// `cw_out_close` and `cw_pause_close` free their runs and flush nothing:
    /// the application is no longer expecting calls, so there is nothing else
    /// they could do.
    #[test]
    fn closing_the_chain_discards_what_was_held() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), BODY, b"held")
            .expect("buffered");
        stack.write(&mut env.ctx(), BODY, b"more").expect("held");
        assert_eq!(callback_lengths(&shared, Stream::Body), vec![4]);

        stack.clear(&mut env.ctx());
        assert!(stack.is_empty());
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![4],
            "closing delivered nothing"
        );
    }

    /// Both stages report what they are holding, and both start empty.
    ///
    /// The two accountings differ in kind -- one is summed on demand, the other
    /// tracked incrementally -- and both must agree with what was actually
    /// buffered. Driven on the stages directly, because the totals are the one
    /// thing the chain does not expose.
    #[test]
    fn both_stages_account_for_what_they_hold() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let mut env = Env::new();

        // The client stage, driven through a chain of its own so that the pause
        // stage cannot intercept.
        let factory = TestFactory::bypassing_pause(&shared);
        let mut stack = base_chain(&mut env, &factory);
        stack
            .write(&mut env.ctx(), BODY, b"12345")
            .expect("buffered");
        stack.write(&mut env.ctx(), BODY, b"678").expect("buffered");

        // A freshly built stage holds nothing, which is what `cw_out_init` and
        // `cw_pause_init` establish.
        let idle_out = ClientOutWriter::new(Box::new(TestOutput {
            shared: Rc::clone(&shared),
        }));
        assert_eq!(idle_out.buffered(), 0);
        assert!(!idle_out.is_paused());
        let idle_pause = PauseWriter::new();
        assert_eq!(idle_pause.buffered(), 0);
        assert!(!idle_pause.is_paused());

        // The in-flight stage's total, driven through the real chain. A second
        // recorder rather than the first: the script above has been spent,
        // and a
        // spent script answers every call with the exact count.
        let held = recorder();
        held.borrow_mut().script = vec![Answer::Pause];
        let real = TestFactory::new(&held);
        let mut env = Env::new();
        let mut chain = base_chain(&mut env, &real);
        chain
            .write(&mut env.ctx(), BODY, b"abcd")
            .expect("buffered");
        assert!(is_paused(&chain));
        chain.write(&mut env.ctx(), BODY, b"efghij").expect("held");
        // Six bytes are in flight, which the flush trace reports as it drains
        // them.
        unpause(&mut chain, &mut env.ctx()).expect("the replay succeeds");
        assert!(env.trace.saw_write("[PAUSE] flushed 6/6 bytes"));
    }

    /// A body write that a decoder has split is accounted for per segment.
    ///
    /// The pause stage's running total is the one piece of state in this module
    /// that is tracked incrementally rather than derived, so the arithmetic is
    /// checked against a payload that crosses the decode chunk twice.
    #[test]
    fn the_in_flight_total_survives_a_split_replay() {
        let shared = recorder();
        shared.borrow_mut().script = vec![Answer::Pause];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);
        with_relay(&mut stack, &mut env, &factory, &shared);

        // Pause the client stage on a small write.
        stack.write(&mut env.ctx(), BODY, b"p").expect("buffered");
        // Then hold a payload longer than two decode chunks.
        let held = vec![b'h'; CW_PAUSE_DEC_WRITE_CHUNK * 2 + 5];
        stack.write(&mut env.ctx(), BODY, &held).expect("held");

        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        // Replayed in decode-sized segments, because the relay makes the tail
        // report content decoding.
        assert_eq!(
            relay_writes(&shared),
            vec![
                (BODY, 1),
                (BODY, CW_PAUSE_DEC_WRITE_CHUNK),
                (BODY, CW_PAUSE_DEC_WRITE_CHUNK),
                (BODY, 5),
            ]
        );
        // And every byte reached the application, in order, exactly once after
        // the paused offer.
        let mut expected = b"p".to_vec();
        expected.push(b'p');
        expected.extend_from_slice(&held);
        assert_eq!(callback_bytes(&shared, Stream::Body), expected);
    }

    /// The sentinel kind resolves to no callback, which is the C's `default:`
    /// arm.
    #[test]
    fn the_sentinel_kind_resolves_to_no_callback() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            state.has_header_target = true;
        }
        let stage = ClientOutWriter::new(Box::new(TestOutput {
            shared: Rc::clone(&shared),
        }));

        assert!(stage.resolve(OutBufKind::None).is_none());

        // The three real kinds all resolve, and to the sizes the C assigns.
        let body = stage
            .resolve(OutBufKind::Body)
            .expect("a body callback is installed");
        assert_eq!(body.slot, CallbackSlot::Body);
        assert_eq!(body.max_write, CURL_MAX_WRITE_SIZE);
        assert_eq!(body.min_write, 0);

        let zero = stage
            .resolve(OutBufKind::BodyZeroLen)
            .expect("the zero-length kind uses the body callback");
        assert_eq!(zero.slot, CallbackSlot::Body);
        assert_eq!(zero.max_write, CURL_MAX_WRITE_SIZE);

        let header = stage
            .resolve(OutBufKind::Header)
            .expect("a header callback is installed");
        assert_eq!(header.slot, CallbackSlot::Header);
        assert_eq!(header.max_write, 0, "headers are not chunked");

        // With the explicit header callback gone, the crossed pairing wins.
        shared.borrow_mut().has_header = false;
        let fallback = stage
            .resolve(OutBufKind::Header)
            .expect("the header target selects the body callback");
        assert_eq!(fallback.slot, CallbackSlot::BodyToHeaderTarget);

        // With neither, nothing.
        shared.borrow_mut().has_header_target = false;
        assert!(stage.resolve(OutBufKind::Header).is_none());
    }

    /// An EMPTY buffered run that is not the zero-length body kind is skipped
    /// and dropped.
    #[test]
    fn an_empty_run_of_the_wrong_kind_is_dropped_silently() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            state.script = vec![Answer::Pause];
        }
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        // A header run is buffered by the pause.
        stack
            .write(&mut env.ctx(), HEADER, b"H\r\n")
            .expect("buffered");
        assert!(is_paused(&stack));

        // An empty BODY write now starts a run of its own -- the kind
        // changed --
        // holding no bytes. It carries neither `ZERO_LEN` nor therefore the
        // zero-length kind, so it must never reach the callback.
        let empty_body = BODY.union(ClientWriteFlags::EOS);
        stack
            .write(&mut env.ctx(), empty_body, b"")
            .expect("buffered");

        unpause(&mut stack, &mut env.ctx()).expect("the replay succeeds");

        assert_eq!(
            events(&shared),
            vec![
                Event::Callback(Stream::Header, b"H\r\n".to_vec()),
                Event::Callback(Stream::Header, b"H\r\n".to_vec()),
            ],
            "the empty body run was dropped without an invocation"
        );
        assert!(!is_paused(&stack));
    }

    /// A BUFFERED run that is only partly taken keeps exactly its unconsumed
    /// tail.
    #[test]
    fn a_partly_taken_run_keeps_exactly_its_tail() {
        let shared = recorder();
        // Pause immediately, then on the replay accept the first chunk and
        // pause on the second.
        shared.borrow_mut().script =
            vec![Answer::Pause, Answer::Exact, Answer::Pause];
        let factory = TestFactory::bypassing_pause(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        // Three chunks' worth, buffered whole by the first pause.
        let body: Vec<u8> = (0..CURL_MAX_WRITE_SIZE * 2 + 9)
            .map(|index| u8::try_from(index % 241).expect("below 241"))
            .collect();
        stack.write(&mut env.ctx(), BODY, &body).expect("buffered");
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![CURL_MAX_WRITE_SIZE]
        );

        // The first replay takes one chunk and pauses on the next, so the run
        // must now hold everything from the second chunk onward.
        unpause(&mut stack, &mut env.ctx())
            .expect("a re-pause is not an error");
        assert!(is_paused(&stack));
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![
                CURL_MAX_WRITE_SIZE,
                CURL_MAX_WRITE_SIZE,
                CURL_MAX_WRITE_SIZE
            ]
        );

        // The second replay delivers the tail and nothing else.
        unpause(&mut stack, &mut env.ctx()).expect("the replay finishes");
        assert_eq!(
            callback_lengths(&shared, Stream::Body),
            vec![
                CURL_MAX_WRITE_SIZE,
                CURL_MAX_WRITE_SIZE,
                CURL_MAX_WRITE_SIZE,
                CURL_MAX_WRITE_SIZE,
                9
            ]
        );

        // The bytes the application ACCEPTED are the body exactly once, in
        // order: the first chunk from the first replay, then the second and
        // third from the last one.
        let accepted: Vec<u8> = {
            let mut bytes = body[..CURL_MAX_WRITE_SIZE].to_vec();
            bytes.extend_from_slice(&body[CURL_MAX_WRITE_SIZE..]);
            bytes
        };
        assert_eq!(accepted, body, "the tail arithmetic lost nothing");
        assert!(!is_paused(&stack));
    }

    /// A downstream failure during the in-flight replay propagates, and the
    /// run stays where it was.
    ///
    /// `lib/cw-pause.c:124-125` returns BEFORE the emptiness test, so a run
    /// whose write failed keeps whatever it still holds rather than being
    /// dropped.
    #[test]
    fn a_failing_replay_propagates_from_the_in_flight_stage() {
        let shared = recorder();
        // Pause on the first write, then fail on the replay.
        shared.borrow_mut().script = vec![Answer::Pause, Answer::Error];
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack
            .write(&mut env.ctx(), BODY, b"first")
            .expect("buffered");
        stack.write(&mut env.ctx(), BODY, b"held").expect("held");

        let error = unpause(&mut stack, &mut env.ctx())
            .expect_err("the client callback failed during the replay");
        assert_eq!(error.code(), CURLcode::WriteError);
        assert_eq!(
        callback_lengths(&shared, Stream::Body),
        vec![5, 9],
        "the replay offered the held bytes appended behind the buffered run"
    );
    }

    /// A held run is drained on the NEXT write once the client stage is no
    /// longer paused.
    #[test]
    fn a_held_run_is_drained_before_the_next_write() {
        let shared = recorder();
        {
            let mut state = shared.borrow_mut();
            state.has_header = true;
            // Pause on the first write, and again on the first replay.
            state.script = vec![Answer::Pause, Answer::Pause];
        }
        let factory = TestFactory::new(&shared);
        let mut env = Env::new();
        let mut stack = base_chain(&mut env, &factory);

        stack.write(&mut env.ctx(), BODY, b"a").expect("buffered");
        assert!(is_paused(&stack));
        stack.write(&mut env.ctx(), BODY, b"b").expect("held");
        stack.write(&mut env.ctx(), HEADER, b"H\r\n").expect("held");

        // The replay: the in-flight stage hands "b" down, the client stage
        // re-pauses on it, and the walk then reaches the client stage's own
        // unpause -- which clears the flag and drains its queue. The header run
        // is still held.
        unpause(&mut stack, &mut env.ctx())
            .expect("a re-pause is not an error");
        assert!(!is_paused(&stack), "the client stage was cleared last");

        // The next write therefore finds held bytes and no pause, and must
        // deliver the header BEFORE the new body byte.
        stack.write(&mut env.ctx(), BODY, b"c").expect("delivered");

        assert_eq!(
            events(&shared),
            vec![
                Event::Callback(Stream::Body, b"a".to_vec()),
                Event::Callback(Stream::Body, b"ab".to_vec()),
                Event::Callback(Stream::Body, b"ab".to_vec()),
                Event::Callback(Stream::Header, b"H\r\n".to_vec()),
                Event::Callback(Stream::Body, b"c".to_vec()),
            ],
            "the held header was drained before the new body byte"
        );
    }
}
