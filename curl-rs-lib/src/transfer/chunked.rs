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
//! HTTP/1.1 chunked transfer coding, in both directions.
//!
//! Supersedes `lib/http_chunks.c` and `lib/http_chunks.h`. This module owns
//! curl-compatible chunk framing rather than delegating it to hyper: hyper
//! manages connections, keep-alive and the socket, and curl owns these exact
//! bytes and their order.
//!
//! # Why the framing is not delegated
//!
//! 1,476 of the 1,914 fixtures under `tests/data/` carry a `<protocol>`
//! block, and `compareparts` (`tests/getpart.pm:351+`) joins both sides into
//! ONE string and compares them as one string. There is no per-line matching,
//! no normalisation and no reordering, so the size line's case, the absence of
//! leading zeros, every CRLF and the trailing `0\r\n\r\n` are all part of the
//! contract rather than presentation. A serializer that emitted `0A\r\n`
//! where curl emits `a\r\n` would be equally correct HTTP and would fail the
//! comparison, which is why every wire literal in this file is a deliberate
//! source literal.
//!
//! # What is here
//!
//! * [`Chunker`] -- the receive state machine, `struct Curl_chunker` plus
//!   `httpchunk_readwrite` (`lib/http_chunks.c:106-358`). Reusable across
//!   feeds, safe at any buffer boundary, and it reports how many bytes it
//!   consumed so the caller keeps whatever followed the response.
//! * [`ChunkedDecoder`] -- the `"chunked"` transfer-unencoder writer stage,
//!   `Curl_httpchunk_unencoder` (`:453-460`), which
//!   `transfer/content_encoding.rs` installs at
//!   [`ClientWriterPhase::TransferDecode`].
//! * [`ChunkedEncoder`] -- the `"chunked"` transfer-encoder reader stage,
//!   `Curl_httpchunk_encoder` (`:640-652`), which `protocols/http1.rs`
//!   installs through [`add_chunked_encoder`] for a request body that needs
//!   chunked framing.
//!
//! # Module boundaries
//!
//! Nothing here names a TLS type: the connection filters make TLS
//! transparent, so a codec sees plaintext either way. Nothing here names
//! `protocols/http1.rs` either -- HTTP/1 assembly CONSUMES this module, and
//! the reverse would be a cycle. What the C reaches for through
//! `struct Curl_easy *data` arrives instead as [`ClientCtx`] plus three
//! narrow seams this module declares: [`ChunkSink`] for the writes a decode
//! produces, [`ChunkSource`] for the reads an encode consumes, and
//! [`TrailerCallback`] for `CURLOPT_TRAILERFUNCTION`.
//!
//! Two pieces of `struct Curl_easy` have no field in
//! [`RequestWriteState`](crate::transfer::sendf::RequestWriteState) and are
//! therefore expressed differently here, with no behaviour lost:
//!
//! * `data->set.http_te_skip` is a per-handle setting fixed before a transfer
//!   starts, so it arrives as a constructor argument to [`ChunkedDecoder`] and
//!   as an explicit parameter to [`Chunker::read`] rather than being reached
//!   for through the context.
//! * `data->req.chunk = TRUE` (`lib/http_chunks.c:398`) is read only by
//!   `lib/http.c:3620`, `:3807` and `:3993`, and it means exactly "a chunked
//!   decoder is installed". [`receiving_chunks`] answers that question from
//!   the writer chain itself, so there is no second copy of the fact to keep
//!   in step.
//!
//! # Where these stages sit in the two chains
//!
//! Both chains are ordered by phase and both orders are contracts.
//!
//! On the way IN, `ClientWriterStack` inserts a stage first within its phase
//! (`lib/sendf.c:464-469`) and the base stack is `raw`, `protocol`,
//! `cw-pause`, `cw-out` (`:325-368`). [`ChunkedDecoder`] is at
//! [`ClientWriterPhase::TransferDecode`], which is BELOW `Raw` and ABOVE
//! `Protocol`, so a response body reaches:
//!
//! ```text
//!   raw -> chunked -> protocol -> cw-pause -> cw-out
//!          ^^^^^^^    ^^^^^^^^
//!          framing    the length check and the client, which therefore
//!          removed    only ever see de-framed bytes
//! ```
//!
//! That ordering is what makes the response length check, any
//! `Content-Encoding` decoder at [`ClientWriterPhase::ContentDecode`] and the
//! application's write callback agree on what the body is. A trailer keeps its
//! `CLIENTWRITE_HEADER|CLIENTWRITE_TRAILER` flags all the way down, so
//! `transfer/writeout.rs`'s `hds-collect` stage stores it under
//! `CURLH_TRAILER` and its bytes reach the header callback in arrival order,
//! unchanged.
//!
//! On the way OUT, [`ChunkedEncoder`] is at
//! [`ClientReaderPhase::TransferEncode`], above the client source and any
//! content encoder, so it frames what the application actually supplied.
//!
//! # Bounded buffers
//!
//! No pointer, length or capacity is tracked by hand. An incoming trailer
//! line accumulates in a [`DynBuf`] whose ceiling is `DYN_H1_TRAILER`, which
//! is the ceiling `Curl_httpchunk_init` gives it (`:79`); an outgoing trailer
//! block is staged in a [`DynBuf`] whose ceiling is `DYN_TRAILERS`; and the
//! encoder's output queue is a [`BytesMut`] sized to the C's bufq preference.
//! Crossing either ceiling is [`CURLcode::TooLarge`], deterministically,
//! rather than an unbounded allocation.

use core::fmt;

use bytes::{Buf, BytesMut};

use crate::error::{CURLcode, CurlResult, Error};
use crate::transfer::sendf::{
    ClientCtx, ClientIo, ClientReader, ClientReaderKind, ClientReaderPhase,
    ClientReaderStack, ClientWriteFlags, ClientWriter, ClientWriterKind,
    ClientWriterPhase, ClientWriterStack, ReadOutcome, ReaderQuery, ReaderTail,
    WriterTail,
};
use crate::util::dynbuf::{DynBuf, DYN_H1_TRAILER, DYN_TRAILERS};

// The wire vocabulary. Every one of these is compared byte for byte by the
// fixture corpus, so each is written once, here, and referenced everywhere.

/// Carriage return -- `0x0d`, spelled as the C spells it.
///
/// `lib/http_chunks.h:124-125` states the rule this file follows: *"This
/// function always uses ASCII hex values to accommodate non-ASCII hosts. For
/// example, 0x0d and 0x0a are used instead of `\r` and `\n`."*
const CR: u8 = 0x0d;

/// Line feed -- `0x0a`.
const LF: u8 = 0x0a;

/// The two bytes that terminate every chunk size line, every chunk's data and
/// every trailer line.
const CRLF: &[u8] = b"\x0d\x0a";

/// The complete terminal block a request body ends with when no trailer
/// callback is installed -- `lib/http_chunks.c:501`.
const LAST_CHUNK: &[u8] = b"0\x0d\x0a\x0d\x0a";

/// The size line of the last chunk, without the blank line that follows it.
///
/// Enqueued first when a trailer callback IS installed (`:504`), so that the
/// trailers land between it and the final CRLF.
const LAST_CHUNK_HEAD: &[u8] = b"0\x0d\x0a";

/// The width of `curl_off_t`, which this engine models as signed 64-bit.
///
/// `SIZEOF_CURL_OFF_T` is a configure-time probe in the C tree; all four
/// supported targets are 64-bit (specification 0.8.3), so the probe has one
/// answer and it is written as the width of the type that carries it.
const SIZEOF_CURL_OFF_T: usize = core::mem::size_of::<i64>();

/// The longest hexadecimal chunk size this decoder accepts, in digits.
///
/// `CHUNK_MAXNUM_LEN` (`lib/http_chunks.h:39`), whose comment reads: *"The
/// longest possible hexadecimal number we support in a chunked transfer.
/// Neither RFC2616 nor the later HTTP specs define a maximum chunk size. For
/// 64-bit curl_off_t we support 16 digits. For 32-bit, 8 digits."*
///
/// Sixteen digits admit values a signed 64-bit count cannot hold, so the
/// digit ceiling is necessary and not sufficient: a parsed value above
/// [`i64::MAX`] is rejected as well, exactly as
/// `curlx_str_hex(..., CURL_OFF_T_MAX)` rejects it at `:164`.
#[allow(dead_code)] // consumer: protocols/http1.rs, and the tests below
pub(crate) const CHUNK_MAXNUM_LEN: usize = SIZEOF_CURL_OFF_T * 2;

/// The chunk payload the encoder stages when the destination is small --
/// `CURL_CHUNKED_MINLEN` (`lib/http_chunks.c:463`).
///
/// A destination shorter than this makes the encoder read into scratch of
/// exactly this size instead, so that a caller offering 40 bytes does not
/// produce a stream of 40-byte chunks. `add_chunk`'s own comment is *"small
/// read, make a chunk of decent size"* (`:555`).
#[allow(dead_code)] // consumer: protocols/http1.rs, and the tests below
pub(crate) const CURL_CHUNKED_MINLEN: usize = 1024;

/// The largest chunk payload the encoder will produce, and the size of one
/// output-queue chunk -- `CURL_CHUNKED_MAXLEN` (`lib/http_chunks.c:464`).
#[allow(dead_code)] // consumer: protocols/http1.rs, and the tests below
pub(crate) const CURL_CHUNKED_MAXLEN: usize = 64 * 1024;

/// How many output-queue chunks the encoder prefers -- the `2` of
/// `Curl_bufq_init2(&ctx->chunkbuf, CURL_CHUNKED_MAXLEN, 2, ...)` (`:478`).
const CHUNK_QUEUE_CHUNKS: usize = 2;

/// The encoder's output-queue capacity: the C's chunk size times its chunk
/// count.
///
/// `BUFQ_OPT_SOFT_LIMIT` is what the C passes with it, and its documented
/// meaning is that the limit governs when the queue reports itself FULL and
/// not whether a write is accepted: *"a bufq will allow writing beyond this
/// limit and use more than `max_chunks` [...] This is provided for situation
/// where writes preferably never fail"* (`lib/bufq.h:80-83`). Nothing in
/// `lib/http_chunks.c` ever asks whether the queue is full -- only whether it
/// is empty (`:608` and `:615`) -- so the soft limit is the whole of the
/// policy, and a growable buffer with this much capacity reserved up front
/// reproduces it exactly.
const CHUNK_QUEUE_CAPACITY: usize = CURL_CHUNKED_MAXLEN * CHUNK_QUEUE_CHUNKS;

/// The digits a chunk size line is spelled with: lowercase, and nothing else.
///
/// `add_chunk` formats with `"%zx\r\n"` (`lib/http_chunks.c:576`), so the size
/// is lowercase hexadecimal with no leading zero and no width. Spelled out
/// here rather than reached for through a formatter, because the case is part
/// of the wire contract and a formatter's choice of case is a formatter's to
/// change.
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// The framing bytes one chunk can cost, deducted before a payload read.
///
/// `blen -= (8 + 2 + 2)` with the comment *"deduct max overhead, 8 hex +
/// 2*crlf"* (`lib/http_chunks.c:561`). Eight hexadecimal digits is the width
/// `hd[11]` in `add_chunk` leaves room for, and it is generous: a payload
/// capped at [`CURL_CHUNKED_MAXLEN`] needs five. The allowance is preserved at
/// the C's value even so, because it decides the payload length and therefore
/// the size line of every chunk on the wire.
const CHUNK_FRAMING_ALLOWANCE: usize = 8 + 2 + 2;

/// `CURL_TRAILERFUNC_OK` -- `include/curl/curl.h:397`.
#[allow(dead_code)] // consumer: curl-rs-ffi's CURLOPT_TRAILERFUNCTION shim
pub(crate) const CURL_TRAILERFUNC_OK: i32 = 0;

/// `CURL_TRAILERFUNC_ABORT` -- `include/curl/curl.h:400`.
#[allow(dead_code)] // consumer: curl-rs-ffi's CURLOPT_TRAILERFUNCTION shim
pub(crate) const CURL_TRAILERFUNC_ABORT: i32 = 1;

/// The transfer coding token this module implements: `chunked`.
///
/// The `name` member of both `Curl_httpchunk_unencoder` (`:454`) and
/// `Curl_httpchunk_encoder` (`:641`), and the token
/// `transfer/content_encoding.rs` matches a `Transfer-Encoding` header field
/// against.
///
/// DERIVED from the decode stage's identity rather than spelled a fourth time.
/// `ClientWriterStack::get_by_name` looks a stage up by
/// [`ClientWriterKind::name`], so a literal here that disagreed with that
/// method would make the lookup miss a stage that is installed -- and the
/// symptom would be a duplicate `"chunked"` decoder, which RFC 9112 section 6.1
/// forbids. The test module asserts that the encoder's name is the same string
/// and that the string is `chunked`.
#[allow(dead_code)] // consumer: transfer/content_encoding.rs
pub(crate) const CHUNKED_CODING_NAME: &str =
    ClientWriterKind::ChunkedDecode.name();

/// The flags every decoded trailer line is written with.
///
/// `CLIENTWRITE_HEADER|CLIENTWRITE_TRAILER` (`lib/http_chunks.c:261-262` and
/// `:266-267`). Both bits matter downstream: `hds_cw_collect_write`
/// (`lib/headers.c:296-313`) stores a write only when `HEADER` is set, and the
/// first-match chain there maps `HEADER | TRAILER` to `CURLH_TRAILER`, the
/// origin `curl_easy_header` reports as 2. Relabelling a trailer as an
/// ordinary response header would move it into `CURLH_HEADER` and change what
/// an application's origin mask matches; the test module asserts the
/// classification through [`classify_origin`](crate::headers::classify_origin)
/// itself rather than restating the bit here.
const TRAILER_FLAGS: ClientWriteFlags =
    ClientWriteFlags::HEADER.union(ClientWriteFlags::TRAILER);

// The receive state machine's vocabulary -- `lib/http_chunks.h:41-92`.

/// Where the receive state machine is.
///
/// Supersedes `ChunkyState` (`lib/http_chunks.h:41-82`), variant for variant
/// and in the C's declaration order. The C's doc comments are preserved on
/// each variant because they record intent that the transitions alone do not:
/// `CHUNK_LF`'s *"wait for LF, ignore all else"* is what makes curl accept
/// chunk extensions, and `CHUNK_POSTLF`'s *"A missing CR is no big deal"* is
/// what makes it tolerate a bare line feed after a chunk's data.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum ChunkyState {
    /// `CHUNK_HEX`: *"await and buffer all hexadecimal digits until we get one
    /// that is not a hexadecimal digit. When done, we go CHUNK_LF"*.
    Hex,

    /// `CHUNK_LF`: *"wait for LF, ignore all else"*.
    Lf,

    /// `CHUNK_DATA`: *"We eat the amount of data specified. When done, we move
    /// on to the POST_CR state."*
    Data,

    /// `CHUNK_POSTLF`: *"POSTLF should get a CR and then an LF and nothing
    /// else, then move back to HEX as the CRLF combination marks the end of a
    /// chunk. A missing CR is no big deal."*
    PostLf,

    /// `CHUNK_STOP`: *"Used to mark that we are out of the game. NOTE: that
    /// there is a 'datasize' field in the struct that will tell how many bytes
    /// that were not passed to the client in the end of the last buffer!"*
    Stop,

    /// `CHUNK_TRAILER`: *"At this point optional trailer headers can be found,
    /// unless the next line is CRLF"*.
    Trailer,

    /// `CHUNK_TRAILER_CR`: *"A trailer CR has been found - next state is
    /// CHUNK_TRAILER_POSTCR. Next char must be an LF"*.
    TrailerCr,

    /// `CHUNK_TRAILER_POSTCR`: *"A trailer LF must be found now, otherwise
    /// CHUNKE_BAD_CHUNK will be signalled If this is an empty trailer
    /// CHUNKE_STOP will be signalled. Otherwise the trailer will be
    /// broadcasted via Curl_client_write() and the next state will be
    /// CHUNK_TRAILER"*.
    TrailerPostCr,

    /// `CHUNK_DONE`: *"Successfully de-chunked everything"*.
    Done,

    /// `CHUNK_FAILED`: *"Failed on seeing a bad or not correctly terminated
    /// chunk"*.
    Failed,
}

impl ChunkyState {
    /// The C identifier for this state, spelled as `lib/http_chunks.h` spells
    /// it.
    ///
    /// Present so that a diagnostic or an assertion message can name a state
    /// the way the header does, without a second table to keep in step.
    #[allow(dead_code)] // consumer: the assertions in the tests below
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::Hex => "CHUNK_HEX",
            Self::Lf => "CHUNK_LF",
            Self::Data => "CHUNK_DATA",
            Self::PostLf => "CHUNK_POSTLF",
            Self::Stop => "CHUNK_STOP",
            Self::Trailer => "CHUNK_TRAILER",
            Self::TrailerCr => "CHUNK_TRAILER_CR",
            Self::TrailerPostCr => "CHUNK_TRAILER_POSTCR",
            Self::Done => "CHUNK_DONE",
            Self::Failed => "CHUNK_FAILED",
        }
    }
}

impl fmt::Display for ChunkyState {
    /// [`Self::c_name`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.c_name())
    }
}

/// Why the receive state machine stopped.
///
/// Supersedes `CHUNKcode` (`lib/http_chunks.h:84-92`). The C's integers are
/// explicit for the first two and positional for the rest; all seven are
/// pinned here by [`Self::as_i32`] because `cw_chunked_write` selects a
/// diagnostic by comparing against [`Self::PassthruError`] (`:426`) and the
/// remaining codes reach the user as the text of
/// [`Self::message`](ChunkCode::message).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum ChunkCode {
    /// `CHUNKE_OK = 0`.
    Ok,
    /// `CHUNKE_TOO_LONG_HEX = 1`: more than [`CHUNK_MAXNUM_LEN`] digits.
    TooLongHex,
    /// `CHUNKE_ILLEGAL_HEX`: no digit where one was required, or a size a
    /// `curl_off_t` cannot hold.
    IllegalHex,
    /// `CHUNKE_BAD_CHUNK`: a chunk or trailer was not terminated as the
    /// grammar requires.
    BadChunk,
    /// `CHUNKE_BAD_ENCODING`.
    ///
    /// Never set by `lib/http_chunks.c` itself -- it exists in the
    /// enumeration, `Curl_chunked_strerror` renders it (`:373-374`), and it is
    /// kept so the vocabulary is the C's rather than a subset of it. A
    /// truncated enumeration would be a silently different `CHUNKcode`, and
    /// the integers of the two after it would shift.
    #[allow(dead_code)] // never constructed in the C either; see above
    BadEncoding,
    /// `CHUNKE_OUT_OF_MEMORY`: a trailer buffer refused an append. Reported
    /// with the append's own [`CURLcode`], which distinguishes a ceiling
    /// ([`CURLcode::TooLarge`]) from an exhausted allocator
    /// ([`CURLcode::OutOfMemory`]).
    OutOfMemory,
    /// `CHUNKE_PASSTHRU_ERROR`: the stage below refused a write. The comment
    /// in the C reads *"Curl_httpchunk_read() returns a CURLcode to use"*, and
    /// that is exactly what happens: the downstream code is returned
    /// unchanged.
    PassthruError,
}

impl ChunkCode {
    /// The C's integer for this code.
    #[allow(dead_code)] // consumer: the assertions in the tests below
    pub(crate) const fn as_i32(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::TooLongHex => 1,
            Self::IllegalHex => 2,
            Self::BadChunk => 3,
            Self::BadEncoding => 4,
            Self::OutOfMemory => 5,
            Self::PassthruError => 6,
        }
    }

    /// The C identifier for this code.
    // consumer: `chunk_codes_carry_their_c_identifiers` below. The allowance is
    // needed even so, because a `pub(crate)` item reached only from a
    // `#[cfg(test)]` module is dead code in an ordinary `cargo build`.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::Ok => "CHUNKE_OK",
            Self::TooLongHex => "CHUNKE_TOO_LONG_HEX",
            Self::IllegalHex => "CHUNKE_ILLEGAL_HEX",
            Self::BadChunk => "CHUNKE_BAD_CHUNK",
            Self::BadEncoding => "CHUNKE_BAD_ENCODING",
            Self::OutOfMemory => "CHUNKE_OUT_OF_MEMORY",
            Self::PassthruError => "CHUNKE_PASSTHRU_ERROR",
        }
    }

    /// The description `Curl_chunked_strerror` returns (`:360-378`).
    ///
    /// These strings reach the user: `cw_chunked_write` interpolates one into
    /// `"%s in chunked-encoding"` (`:430-431`), which becomes the error buffer
    /// a `curl_easy_perform` failure carries. They are reproduced exactly,
    /// including the C's `default:` arm answering `"OK"`.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::TooLongHex => "Too long hexadecimal number",
            Self::IllegalHex => "Illegal or missing hexadecimal sequence",
            Self::BadChunk => "Malformed encoding found",
            Self::PassthruError => "Error writing data to client",
            Self::BadEncoding => "Bad content-encoding found",
            Self::OutOfMemory => "Out of memory",
            // `lib/http_chunks.c:363-364`: the `default:` arm, which
            // `CHUNKE_OK` reaches.
            Self::Ok => "OK",
        }
    }
}

impl fmt::Display for ChunkCode {
    /// [`Self::message`], so that a format string reading `"{code} in
    /// chunked-encoding"` produces the C's sentence.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

// The three seams -- what `httpchunk_readwrite` and `add_chunk` reach for
// through `struct Curl_easy *data`, made explicit.

/// Where a decode's output goes.
///
/// `httpchunk_readwrite` takes a `struct Curl_cwriter *cw_next` and branches on
/// it at every write site (`lib/http_chunks.c:125-128`, `:203-207`,
/// `:259-268`): non-null means `Curl_cwriter_write` down the chain, null means
/// `Curl_client_write` from the top of it. That is a choice the CALLER makes,
/// so it is a trait here and the caller picks the implementation:
///
/// * The writer stage passes the [`WriterTail`] it was handed, which is the
///   `cw_next` case and the ordinary one.
/// * A caller with no chain -- `lib/cf-h1-proxy.c` decoding a chunked CONNECT
///   response body -- passes its own client-write seam, which is the null
///   case.
///
/// It exists as a trait for a second reason that matters just as much:
/// [`WriterTail`] cannot be constructed outside `transfer/sendf.rs`, so
/// without this seam the state machine could only ever be exercised through a
/// fully assembled writer chain. With it, the parser is driven by an
/// in-memory recorder in the tests below and the coverage gate of
/// specification 0.8.4 is reachable without a network.
pub(crate) trait ChunkSink: fmt::Debug {
    /// `Curl_cwriter_write(data, cw_next, type, buf, blen)`.
    ///
    /// # Errors
    ///
    /// Whatever the stage below returns. The decoder does not remap it: the
    /// code the application sees is the code the failing stage produced.
    fn chunk_write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()>;
}

impl ChunkSink for WriterTail<'_, '_> {
    /// The `cw_next` case, forwarded to the remainder of the chain.
    ///
    /// [`WriterTail::write`] is `Curl_cwriter_write` including its
    /// `if(!writer) return CURLE_WRITE_ERROR` at the bottom, so a stage
    /// installed with nothing beneath it behaves as the C's would.
    fn chunk_write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        self.write(ctx, flags, buf)
    }
}

/// Where an encode's payload comes from.
///
/// `add_chunk` calls `Curl_creader_read(data, reader->next, ...)` (`:564`), and
/// this is that call. The reader stage passes the [`ReaderTail`] it was handed;
/// the tests pass a scripted source, which is what makes the pause path -- no
/// bytes, no end of stream -- assertable without a paused application.
pub(crate) trait ChunkSource: fmt::Debug {
    /// `Curl_creader_read(data, reader->next, buf, blen, &nread, &eos)`.
    ///
    /// # Errors
    ///
    /// Whatever the stage below returns, unchanged.
    fn chunk_read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome>;
}

impl ChunkSource for ReaderTail<'_, '_> {
    /// The ordinary case, forwarded to the remainder of the chain.
    fn chunk_read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        self.read(ctx, buf)
    }
}

/// What a trailer callback produced.
///
/// The C's callback is
/// `int (*curl_trailer_callback)(struct curl_slist **list, void *userdata)`
/// (`include/curl/curl.h:402-403`): it returns a code AND fills a list through
/// an out-parameter. Both halves are carried here, together, because
/// `add_last_chunk` uses both on every path -- it frees the list at its `out:`
/// label whatever the code was (`:536`), so a callback that built a list and
/// then aborted still has that list released.
///
/// Modelling the list as owned [`Vec<Vec<u8>>`] is what makes that release
/// automatic: the value is dropped when this struct is, on the success path and
/// on every error path alike, with no label to reach and nothing for a future
/// edit to forget. Each entry is bytes rather than a string because
/// `curl_slist` carries a C string, and a trailer is emitted byte for byte
/// (`:526`) without being validated as UTF-8.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct TrailerResult {
    /// The callback's return value. Anything other than
    /// [`CURL_TRAILERFUNC_OK`] aborts the transfer.
    pub(crate) code: i32,
    /// The list the callback built, in the order it built it.
    pub(crate) trailers: Vec<Vec<u8>>,
}

impl TrailerResult {
    /// A successful result carrying `trailers`.
    #[allow(dead_code)] // consumer: curl-rs-ffi's CURLOPT_TRAILERFUNCTION shim
    pub(crate) fn ok(trailers: Vec<Vec<u8>>) -> Self {
        Self {
            code: CURL_TRAILERFUNC_OK,
            trailers,
        }
    }

    /// `CURL_TRAILERFUNC_ABORT`, with whatever the callback had built.
    #[allow(dead_code)] // consumer: curl-rs-ffi's CURLOPT_TRAILERFUNCTION shim
    pub(crate) fn abort(trailers: Vec<Vec<u8>>) -> Self {
        Self {
            code: CURL_TRAILERFUNC_ABORT,
            trailers,
        }
    }

    /// Whether the callback said to carry on -- `rc != CURL_TRAILERFUNC_OK`
    /// inverted (`:512`).
    ///
    /// The C tests against `CURL_TRAILERFUNC_OK` and not against
    /// `CURL_TRAILERFUNC_ABORT`, so EVERY value other than zero aborts, not
    /// just 1. That asymmetry is preserved.
    const fn accepted(&self) -> bool {
        self.code == CURL_TRAILERFUNC_OK
    }
}

/// `CURLOPT_TRAILERFUNCTION` together with `CURLOPT_TRAILERDATA`.
///
/// The user data the C passes as the callback's second argument is the
/// implementor's own state here, which is why it does not appear in the
/// signature.
pub(crate) trait TrailerCallback: fmt::Debug {
    /// `data->set.trailer_callback(&trailers, data->set.trailer_data)`.
    ///
    /// Invoked exactly once per request, after the source has reported the end
    /// of its stream, and always inside the crate's in-callback guard.
    fn trailers(&mut self) -> TrailerResult;
}

// The receive state machine -- `struct Curl_chunker` and
// `httpchunk_readwrite`.

/// What one turn of the state machine did with the byte in front of it.
///
/// The C expresses these three outcomes by mutating `buf`, `blen` and
/// `*pconsumed` in place and then either `break`ing out of the switch or
/// `return`ing from the function. Naming them makes the one property that
/// matters checkable: every turn either consumes a byte or changes state, so
/// the loop cannot spin. The `debug_assert!` in [`Chunker::read`] holds a
/// future edit to that.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    /// Consume this many bytes and take another turn.
    Take(usize),
    /// Consume nothing and take another turn: the state changed and the same
    /// byte is examined again. The C's `break` with the pointer unmoved.
    Retry,
    /// The response is complete. Consume this many bytes and return at once,
    /// leaving whatever follows for the caller.
    Complete(usize),
}

/// The chunked decoder's state, carried across feeds.
///
/// Supersedes `struct Curl_chunker` (`lib/http_chunks.h:94-102`), field for
/// field:
///
/// | C field | here |
/// |---|---|
/// | `curl_off_t datasize` | [`Self::datasize`] |
/// | `ChunkyState state` | [`Self::state`] |
/// | `CHUNKcode last_code` | [`Self::last_code`] |
/// | `struct dynbuf trailer` | [`Self::trailer`] |
/// | `unsigned char hexindex` | [`Self::hexindex`] |
/// | `char hexbuffer[CHUNK_MAXNUM_LEN + 1]` | [`Self::hexbuffer`] |
/// | `BIT(ignore_body)` | [`Self::ignore_body`] |
///
/// The C's `+ 1` on `hexbuffer` is *"+1 for null-terminator"*, which a slice
/// does not need: the digits are read as `&self.hexbuffer[..hexindex]`, so the
/// array is exactly the digits it can hold.
///
/// # Reusable, and safe at any boundary
///
/// One instance decodes one response, however that response arrives. The C is
/// fed a byte at a time by `lib/cf-h1-proxy.c:486` and in whole receive
/// buffers by `cw_chunked_write`, and both must produce the same output, so
/// every partial token -- a half-written size, a trailer line split across two
/// packets -- lives in this struct rather than on the stack. The test module
/// drives the same message through every split point and asserts the results
/// are identical.
#[derive(Debug)]
pub(crate) struct Chunker {
    /// `datasize`: how much of the current chunk is still to come.
    ///
    /// Reused at the end for a second purpose the C's header calls out: once
    /// the response is complete this holds *"how many bytes that were not
    /// passed to the client in the end of the last buffer"*
    /// (`lib/http_chunks.h:58-60`).
    datasize: i64,

    /// `state`: where the machine is.
    state: ChunkyState,

    /// `last_code`: why it stopped, for the diagnostic the decode stage picks.
    last_code: ChunkCode,

    /// `trailer`: the trailer line being accumulated, capped at
    /// `DYN_H1_TRAILER` exactly as `Curl_httpchunk_init` caps it (`:79`).
    trailer: DynBuf,

    /// `hexbuffer`: the size digits seen so far.
    hexbuffer: [u8; CHUNK_MAXNUM_LEN],

    /// `hexindex`: how many of them there are.
    ///
    /// A `u8` because the C's is `unsigned char`, and the ceiling it is tested
    /// against is 16.
    hexindex: u8,

    /// `ignore_body`: *"never write response body data"*.
    ///
    /// Framing and completion are still tracked; only the body writes stop.
    /// `lib/cf-h1-proxy.c:120` sets it for a chunked CONNECT response, whose
    /// body is not the user's data.
    ignore_body: bool,
}

impl Chunker {
    /// `Curl_httpchunk_init` (`lib/http_chunks.c:72-81`).
    ///
    /// Hex index at zero, state at [`ChunkyState::Hex`] -- *"we get hex
    /// first!"* -- last code at [`ChunkCode::Ok`], an empty trailer buffer with
    /// the `DYN_H1_TRAILER` ceiling, and `ignore_body` as asked.
    #[must_use]
    pub(crate) fn new(ignore_body: bool) -> Self {
        Self {
            datasize: 0,
            state: ChunkyState::Hex,
            last_code: ChunkCode::Ok,
            trailer: DynBuf::new(DYN_H1_TRAILER),
            hexbuffer: [0; CHUNK_MAXNUM_LEN],
            hexindex: 0,
            ignore_body,
        }
    }

    /// `Curl_httpchunk_reset` (`lib/http_chunks.c:83-92`): ready for the next
    /// chunk.
    ///
    /// Called after every non-final chunk, from [`ChunkyState::PostLf`], with
    /// the CURRENT `ignore_body` passed straight back in (`:231`) -- so a reset
    /// mid-response cannot silently change what the rest of the response does
    /// with its body. It keeps the trailer buffer's allocation and its
    /// ceiling, as `curlx_dyn_reset` does.
    pub(crate) fn reset(&mut self, ignore_body: bool) {
        self.hexindex = 0;
        self.state = ChunkyState::Hex;
        self.last_code = ChunkCode::Ok;
        self.trailer.reset();
        self.ignore_body = ignore_body;
    }

    /// `Curl_httpchunk_free` (`lib/http_chunks.c:94-98`): release the trailer
    /// buffer.
    ///
    /// Dropping a [`Chunker`] releases it too, so this exists for the call
    /// site that has one and is not finished with it -- `do_close` on the
    /// decode stage, and `lib/cf-h1-proxy.c:189`.
    #[allow(dead_code)] // consumer: proxy/http_connect.rs
    pub(crate) fn free(&mut self) {
        self.trailer.free();
    }

    /// `Curl_httpchunk_is_done` (`lib/http_chunks.c:100-104`): TRUE only in
    /// [`ChunkyState::Done`].
    ///
    /// Deliberately not "finished one way or the other":
    /// [`ChunkyState::Failed`] is not done, and a caller that treated it as
    /// done would report a truncated body as a complete one.
    #[must_use]
    pub(crate) fn is_done(&self) -> bool {
        self.state == ChunkyState::Done
    }

    /// Where the machine is.
    #[must_use]
    #[allow(dead_code)] // consumer: proxy/http_connect.rs, protocols/http1.rs
    pub(crate) const fn state(&self) -> ChunkyState {
        self.state
    }

    /// Why it stopped -- the value `cw_chunked_write` selects a diagnostic
    /// from.
    #[must_use]
    #[allow(dead_code)] // consumer: proxy/http_connect.rs
    pub(crate) const fn last_code(&self) -> ChunkCode {
        self.last_code
    }

    /// The current chunk's outstanding byte count, and after
    /// [`ChunkyState::Done`] the number of bytes that followed the response in
    /// the last buffer.
    #[must_use]
    #[allow(dead_code)] // consumer: proxy/http_connect.rs
    pub(crate) const fn datasize(&self) -> i64 {
        self.datasize
    }

    /// Whether body writes are suppressed.
    #[must_use]
    #[allow(dead_code)] // consumer: proxy/http_connect.rs
    pub(crate) const fn ignore_body(&self) -> bool {
        self.ignore_body
    }

    /// The size digits collected so far.
    fn hex_digits(&self) -> &[u8] {
        &self.hexbuffer[..usize::from(self.hexindex)]
    }

    /// Decode `buf`, writing what comes out through `sink`, and report how
    /// many of its bytes were consumed.
    ///
    /// Supersedes `httpchunk_readwrite` (`lib/http_chunks.c:106-358`) and
    /// therefore `Curl_httpchunk_read` (`:380-386`), which is that function
    /// with no downstream writer -- a caller reproduces it by passing a sink
    /// that writes from the top of the chain.
    ///
    /// `te_skip` is `data->set.http_te_skip`
    /// (`CURLOPT_HTTP_TRANSFER_DECODING` turned off). When it is set, and the
    /// body is not being ignored, the ORIGINAL encoded bytes are written once,
    /// as body, before parsing begins -- the C's comment reads *"the original
    /// data is written to the client, but we go on with the chunk read
    /// process, to properly calculate the content length"* (`:122-123`). The
    /// decoded bytes are then NOT written, so the client sees the framing
    /// exactly once and never both forms. Decoded trailers are withheld too
    /// (`:257`), since they are part of the framing the client already has.
    ///
    /// # The consumed count is the whole interface to leftovers
    ///
    /// A response's last chunk can arrive in the same buffer as the first
    /// bytes of the next response on a kept-alive connection. The count
    /// returned here stops at the final line feed, so those bytes stay with
    /// the caller; nothing is copied into this struct and there is no second
    /// place for them to be found. `cw_chunked_write` uses the same count to
    /// report `"Leftovers after chunking"`.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::RecvError`] for every framing fault -- a size too long, a
    ///   size that is not hexadecimal or does not fit a `curl_off_t`, a chunk
    ///   or trailer that is not terminated as the grammar requires, and any
    ///   feed to a decoder that has already failed. [`Self::last_code`] then
    ///   says which, and its [`ChunkCode::message`] is the sentence the user
    ///   sees.
    /// * Whatever `sink` returned, unchanged, when a write downstream fails.
    ///   [`Self::last_code`] is [`ChunkCode::PassthruError`] and the decoder is
    ///   left failed, so a later feed cannot resume a broken stream.
    /// * Whatever the trailer buffer returned when an append crossed its
    ///   ceiling -- [`CURLcode::TooLarge`] -- or exhausted the allocator --
    ///   [`CURLcode::OutOfMemory`]. Neither is reported as a framing fault,
    ///   because the bytes on the wire were not at fault.
    pub(crate) fn read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        sink: &mut dyn ChunkSink,
        te_skip: bool,
        buf: &[u8],
    ) -> CurlResult<usize> {
        // `:115`: nothing is written yet.
        let mut consumed = 0_usize;

        // `:116-120`: the two states that will not progress anywhere. Both
        // consume nothing, so a caller that keeps feeding a finished or broken
        // decoder gets a stable answer rather than a moving one.
        match self.state {
            ChunkyState::Done => return Ok(consumed),
            ChunkyState::Failed => return Err(Error::new(CURLcode::RecvError)),
            _ => {}
        }

        // `:122-134`.
        if te_skip && !self.ignore_body {
            self.passthru(ctx, sink, ClientWriteFlags::BODY, buf)?;
        }

        // `:136`.
        while consumed < buf.len() {
            let rest = &buf[consumed..];
            let byte = rest[0];
            let before = self.state;
            let step = match self.state {
                ChunkyState::Hex => self.step_hex(ctx, byte)?,
                ChunkyState::Lf => self.step_lf(ctx, byte),
                ChunkyState::Data => {
                    self.step_data(ctx, sink, te_skip, rest)?
                }
                ChunkyState::PostLf => self.step_post_lf(byte)?,
                ChunkyState::Trailer => {
                    self.step_trailer(ctx, sink, te_skip, byte)?
                }
                ChunkyState::TrailerCr => self.step_trailer_cr(byte)?,
                ChunkyState::TrailerPostCr => self.step_trailer_post_cr(byte),
                ChunkyState::Stop => self.step_stop(ctx, rest)?,
                // `:350-354`. Neither is reachable from inside the loop --
                // the only transition into [`ChunkyState::Done`] returns at
                // once and every transition into [`ChunkyState::Failed`]
                // returns an error -- and both are kept because the C keeps
                // them, so this `match` is the C's `switch` arm for arm.
                ChunkyState::Done => return Ok(consumed),
                ChunkyState::Failed => {
                    return Err(Error::new(CURLcode::RecvError))
                }
            };

            match step {
                Step::Take(taken) => consumed += taken,
                Step::Retry => debug_assert_ne!(
                    self.state, before,
                    "a turn that consumed nothing must have changed state, \
                     or the loop cannot make progress"
                ),
                Step::Complete(taken) => return Ok(consumed + taken),
            }
        }

        // `:357`.
        Ok(consumed)
    }

    /// Write through the sink, and remember a downstream failure.
    ///
    /// `:129-133`, `:208-212` and `:269-273` are the same three lines three
    /// times: mark the decoder failed, record
    /// [`ChunkCode::PassthruError`], return the code the stage below produced.
    /// Sticky by design -- a stream whose consumer refused a write cannot be
    /// resumed, and the C's terminal-state check at the top of the next call
    /// is what enforces that.
    fn passthru(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        sink: &mut dyn ChunkSink,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        match sink.chunk_write(ctx, flags, buf) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.mark_failed(ChunkCode::PassthruError);
                Err(error)
            }
        }
    }

    /// Mark the decoder failed and remember why.
    ///
    /// Every failure path in the C sets these two fields together, and they go
    /// through one method so that a future arm cannot set the state and forget
    /// the code -- which would leave `cw_chunked_write` choosing its diagnostic
    /// from a stale value.
    fn mark_failed(&mut self, code: ChunkCode) {
        self.state = ChunkyState::Failed;
        self.last_code = code;
    }

    /// A framing fault that carries no diagnostic of its own.
    ///
    /// [`CURLcode::RecvError`] is the code every framing fault in
    /// `httpchunk_readwrite` returns. The sentence the user sees is composed
    /// downstream, by `cw_chunked_write`, out of [`ChunkCode::message`].
    fn fail(&mut self, code: ChunkCode) -> Error {
        self.mark_failed(code);
        Error::new(CURLcode::RecvError)
    }

    /// Mark the decoder failed because a trailer buffer refused an append.
    ///
    /// `:251-255` and `:289-293`. [`ChunkCode::OutOfMemory`] is recorded for
    /// the diagnostic, and the buffer's OWN code is returned: a crossed
    /// ceiling is [`CURLcode::TooLarge`] and an exhausted allocator is
    /// [`CURLcode::OutOfMemory`], and reporting either as
    /// [`CURLcode::RecvError`] would blame the server for something the wire
    /// did not do.
    fn fail_buffer(&mut self, code: CURLcode) -> Error {
        self.mark_failed(ChunkCode::OutOfMemory);
        Error::new(code)
    }
}

// One method per state. The C is a single `switch` inside a `while`; splitting
// it keeps each arm short enough to read against its source lines and keeps
// `read` itself well inside the 300-line ceiling clippy.toml sets.
impl Chunker {
    /// [`ChunkyState::Hex`] -- `lib/http_chunks.c:138-172`.
    ///
    /// Collects hexadecimal digits and nothing else. Three ways out:
    ///
    /// * A digit, with room for it: stored, consumed.
    /// * A digit too many: [`ChunkCode::TooLongHex`]. The C's test is
    ///   `hexindex >= CHUNK_MAXNUM_LEN`, checked BEFORE the store, so 16
    ///   digits are accepted and the 17th fails.
    /// * Anything else: with no digit yet this is junk
    ///   ([`ChunkCode::IllegalHex`]); with at least one digit it ends the size,
    ///   which is parsed here and the byte is left UNCONSUMED for
    ///   [`ChunkyState::Lf`] to look at. That is the C's *"blen and buf are
    ///   unmodified"* comment at `:161`, and it is what lets a chunk extension
    ///   -- or the CR of a CRLF -- be swallowed by the next state instead of
    ///   this one.
    fn step_hex(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        byte: u8,
    ) -> CurlResult<Step> {
        // `:139`: ISXDIGIT is `[0-9a-fA-F]` (`lib/curl_ctype.h:39`), which is
        // exactly what `u8::is_ascii_hexdigit` answers.
        if byte.is_ascii_hexdigit() {
            let at = usize::from(self.hexindex);
            // `:140-145`.
            if at >= CHUNK_MAXNUM_LEN {
                self.mark_failed(ChunkCode::TooLongHex);
                return Err(ctx.failf(
                    CURLcode::RecvError,
                    format_args!(
                        "chunk hex-length longer than {CHUNK_MAXNUM_LEN}"
                    ),
                ));
            }
            // `:146-149`.
            self.hexbuffer[at] = byte;
            self.hexindex += 1;
            return Ok(Step::Take(1));
        }

        // `:152-160`.
        if self.hexindex == 0 {
            self.mark_failed(ChunkCode::IllegalHex);
            // The C renders the offending byte with `%x` of a `char`, which
            // sign-extends a byte above 0x7f into `0xffffffXX` on a platform
            // where `char` is signed -- every platform in scope. The value is
            // rendered as the unsigned byte it is, because a diagnostic that
            // named 0xff as 0xffffffff would be reproducing a C promotion
            // artefact rather than curl's intent, and no fixture compares this
            // text (`tests/data/test207` mentions the wording only in a
            // comment and asserts `<errorcode>` instead).
            return Err(ctx.failf(
                CURLcode::RecvError,
                format_args!(
                    "chunk hex-length char not a hex digit: 0x{byte:x}"
                ),
            ));
        }

        // `:162-169`. The digits are ASCII hexadecimal by construction, so the
        // lossy conversion for the diagnostic is exact.
        let digits = String::from_utf8_lossy(self.hex_digits()).into_owned();
        match parse_chunk_size(self.hex_digits()) {
            Some(size) => {
                self.datasize = size;
                // `:170`: now wait for the CRLF.
                self.state = ChunkyState::Lf;
                Ok(Step::Retry)
            }
            None => {
                self.mark_failed(ChunkCode::IllegalHex);
                Err(ctx.failf(
                    CURLcode::RecvError,
                    format_args!("invalid chunk size: '{digits}'"),
                ))
            }
        }
    }

    /// [`ChunkyState::Lf`] -- `lib/http_chunks.c:174-191`.
    ///
    /// # This is the leniency, and it is deliberate
    ///
    /// Every byte is consumed, and only a line feed does anything. A stricter
    /// parser here would reject input curl accepts, and the grammar it accepts
    /// is not an accident: `chunk-extension` is part of RFC 2616 section 3.6
    /// -- `*( ";" chunk-ext-name [ "=" chunk-ext-val ] )` with a token or a
    /// quoted string as the value -- and this state is how curl skips one
    /// without parsing it. The same swallowing absorbs the CR of the CRLF, and
    /// therefore also accepts a bare line feed. None of that is corrected
    /// here.
    fn step_lf(&mut self, ctx: &mut ClientCtx<'_>, byte: u8) -> Step {
        // `:176`.
        if byte == LF {
            if self.datasize == 0 {
                // `:178-180`: a zero-sized chunk is the last chunk, so what
                // follows is the trailer section.
                self.state = ChunkyState::Trailer;
            } else {
                // `:181-185`.
                self.state = ChunkyState::Data;
                ctx.trc_write(format_args!(
                    "http_chunked, chunk start of {} bytes",
                    self.datasize
                ));
            }
        }
        // `:188-190`: outside the `if`, so it runs whatever the byte was.
        Step::Take(1)
    }

    /// [`ChunkyState::Data`] -- `lib/http_chunks.c:193-226`.
    ///
    /// Forwards at most the smaller of what is in hand and what the chunk still
    /// owes, so a chunk that spans buffers is delivered in as many pieces as it
    /// arrives in and one that shares a buffer with the next chunk's header
    /// does not swallow it.
    fn step_data(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        sink: &mut dyn ChunkSink,
        te_skip: bool,
        rest: &[u8],
    ) -> CurlResult<Step> {
        // `:197-199`. In this state the outstanding count is positive -- the
        // only way in requires a non-zero size and the only way out is it
        // reaching zero -- so the narrowing below cannot lose anything, and
        // the piece is at least one byte, which is what guarantees the loop
        // advances.
        let available = i64::try_from(rest.len()).unwrap_or(i64::MAX);
        let piece = if self.datasize < available {
            usize::try_from(self.datasize).unwrap_or(rest.len())
        } else {
            rest.len()
        };

        // `:202-213`. Under `te_skip` the client already has these bytes in
        // their encoded form, and under `ignore_body` it wants none of them.
        if !te_skip && !self.ignore_body {
            self.passthru(ctx, sink, ClientWriteFlags::BODY, &rest[..piece])?;
        }

        // `:215-218`.
        self.datasize -= i64::try_from(piece).unwrap_or(0);
        // `:219-221`, traced with the piece just written and the count that is
        // left, in that order.
        ctx.trc_write(format_args!(
            "http_chunked, write {piece} body bytes, {} bytes in chunk remain",
            self.datasize
        ));

        // `:223-225`.
        if self.datasize == 0 {
            self.state = ChunkyState::PostLf;
        }
        Ok(Step::Take(piece))
    }

    /// [`ChunkyState::PostLf`] -- `lib/http_chunks.c:228-241`.
    ///
    /// A line feed ends the chunk and readies the machine for the next one; a
    /// carriage return is skipped; anything else is malformed. The C emits no
    /// `failf` here, so the sentence the user sees is the one
    /// `cw_chunked_write` composes from [`ChunkCode::BadChunk`] --
    /// *"Malformed encoding found in chunked-encoding"*.
    fn step_post_lf(&mut self, byte: u8) -> CurlResult<Step> {
        // `:229-232`. The reset passes the CURRENT `ignore_body` back in, so
        // it survives every chunk boundary.
        if byte == LF {
            let ignore_body = self.ignore_body;
            self.reset(ignore_body);
        } else if byte != CR {
            // `:233-237`.
            return Err(self.fail(ChunkCode::BadChunk));
        }
        // `:238-240`.
        Ok(Step::Take(1))
    }

    /// [`ChunkyState::Trailer`] -- `lib/http_chunks.c:243-298`.
    ///
    /// Accumulates one trailer line, then emits it with exactly CRLF appended
    /// -- so a trailer that arrived with a bare line feed is normalised to the
    /// header form the rest of the crate expects, and a trailer that arrived
    /// with CRLF is unchanged.
    ///
    /// # Emptiness is what distinguishes a trailer from the end of the section
    ///
    /// The C tests `curlx_dyn_ptr(&ch->trailer)` for null, and that pointer is
    /// the buffer's ALLOCATION (`lib/curlx/dynbuf.c:237-243` returns `s->bufr`
    /// unconditionally), which `curlx_dyn_reset` deliberately keeps. So the C's
    /// test asks *"has anything ever been appended"* rather than *"is the line
    /// non-empty"*. The two answers agree in every state this machine can
    /// reach, and the reasoning is worth recording because it is not obvious:
    ///
    /// * Appends happen only in this state.
    /// * This state's family -- [`ChunkyState::TrailerCr`],
    ///   [`ChunkyState::TrailerPostCr`], [`ChunkyState::Stop`] -- never returns
    ///   to [`ChunkyState::Hex`], [`ChunkyState::Data`] or
    ///   [`ChunkyState::PostLf`], so the reset that ends a data chunk can never
    ///   follow a trailer append.
    /// * Re-entry from [`ChunkyState::TrailerPostCr`] requires a byte that is
    ///   neither CR nor LF and does NOT consume it, so this state always
    ///   appends at least one byte before its next CR-or-LF test.
    ///
    /// They differ only if [`Chunker::reset`] is called from OUTSIDE after a
    /// trailer line was emitted, where the C would emit a bare CRLF as a
    /// trailer of its own. The empty-line test is used here, so no such
    /// spurious trailer is ever produced.
    fn step_trailer(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        sink: &mut dyn ChunkSink,
        te_skip: bool,
        byte: u8,
    ) -> CurlResult<Step> {
        // `:244`, inverted: the ordinary case is an ordinary byte.
        if byte != CR && byte != LF {
            // `:288-297`.
            if let Err(code) = self.trailer.addn(&[byte]) {
                return Err(self.fail_buffer(code));
            }
            return Ok(Step::Take(1));
        }

        // `:245-249` and `:281-285`: nothing accumulated means there was no
        // trailer at all and this is the final CRLF pair. The byte is NOT
        // consumed -- *"do not advance the pointer"* -- so
        // [`ChunkyState::TrailerPostCr`] gets to see it.
        if self.trailer.is_empty() {
            self.state = ChunkyState::TrailerPostCr;
            return Ok(Step::Retry);
        }

        // `:250-255`: the line is complete, terminated the way a header is.
        if let Err(code) = self.trailer.addn(CRLF) {
            return Err(self.fail_buffer(code));
        }

        // `:256-274`. Withheld under `te_skip`, where the client is being given
        // the encoded stream and already has these bytes.
        if !te_skip {
            // The write borrows the buffer and the failure bookkeeping borrows
            // the rest of the struct, so the two are kept in sequence rather
            // than nested: `passthru` would need both at once.
            let line = self.trailer.as_slice();
            let outcome = sink.chunk_write(ctx, TRAILER_FLAGS, line);
            if let Err(error) = outcome {
                self.mark_failed(ChunkCode::PassthruError);
                return Err(error);
            }
        }

        // `:275-276`.
        self.trailer.reset();
        self.state = ChunkyState::TrailerCr;

        // `:277-279`: already on the line feed, so leave it for
        // [`ChunkyState::TrailerCr`]; a carriage return is consumed here and
        // that state waits for the feed that follows it.
        if byte == LF {
            return Ok(Step::Retry);
        }
        Ok(Step::Take(1))
    }

    /// [`ChunkyState::TrailerCr`] -- `lib/http_chunks.c:300-312`.
    ///
    /// A trailer line's carriage return has been seen and only its line feed
    /// will do.
    fn step_trailer_cr(&mut self, byte: u8) -> CurlResult<Step> {
        // `:301-306`.
        if byte == LF {
            self.state = ChunkyState::TrailerPostCr;
            return Ok(Step::Take(1));
        }
        // `:307-311`.
        Err(self.fail(ChunkCode::BadChunk))
    }

    /// [`ChunkyState::TrailerPostCr`] -- `lib/http_chunks.c:314-330`.
    ///
    /// One trailer line has ended, and what comes next decides whether the
    /// section has: an ordinary byte starts another trailer, and a CR or an LF
    /// closes the section.
    fn step_trailer_post_cr(&mut self, byte: u8) -> Step {
        // `:317-321`: *"not a CR then it must be another header in the
        // trailer"*. Unconsumed, so [`ChunkyState::Trailer`] accumulates it.
        if byte != CR && byte != LF {
            self.state = ChunkyState::Trailer;
            return Step::Retry;
        }
        // `:322-329`: the carriage return of the final pair is skipped if it is
        // there, and either way the final line feed is awaited in
        // [`ChunkyState::Stop`]. A bare line feed therefore ends the response
        // just as CRLF does.
        let step = if byte == CR {
            Step::Take(1)
        } else {
            Step::Retry
        };
        self.state = ChunkyState::Stop;
        step
    }

    /// [`ChunkyState::Stop`] -- `lib/http_chunks.c:332-349`.
    ///
    /// The final line feed, and nothing else, completes the response. Only that
    /// one byte is consumed: the rest of the buffer belongs to whatever follows
    /// on the connection, and the count returned by [`Chunker::read`] is what
    /// hands it back.
    fn step_stop(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        rest: &[u8],
    ) -> CurlResult<Step> {
        let byte = rest[0];
        // `:333-341`.
        if byte == LF {
            // `:336-338`: *"Record the length of any data left in the end of
            // the buffer even if there is no more chunks to read"*. The count
            // is what remains AFTER this line feed.
            let leftover = rest.len() - 1;
            self.datasize = i64::try_from(leftover).unwrap_or(i64::MAX);
            self.state = ChunkyState::Done;
            ctx.trc_write(format_args!("http_chunk, response complete"));
            return Ok(Step::Complete(1));
        }

        // `:343-348`. The trace's `0x%ux` is the C's own spelling: `%u`
        // renders the byte in DECIMAL and the `x` that follows it is a literal
        // character, so curl prints `0x13x` for a carriage return. Reproduced
        // as it stands -- specification 0.8.1 freezes observable behaviour, and
        // silently correcting a diagnostic would make this trace line differ
        // from the C's for every byte above 9.
        let error = self.fail(ChunkCode::BadChunk);
        ctx.trc_write(format_args!(
            "http_chunk error, expected 0x0a, seeing 0x{}x",
            u32::from(byte)
        ));
        Err(error)
    }
}

/// Parse a chunk size from its hexadecimal digits, rejecting anything a
/// `curl_off_t` cannot hold.
///
/// Supersedes the call `curlx_str_hex(&p, &ch->datasize, CURL_OFF_T_MAX)` makes
/// into `str_num_base` (`lib/curlx/strparse.c:157-191`) for base 16. The
/// overflow test is transcribed rather than reinvented: the C guards with
/// `if(num > ((max - n) / base))` BEFORE multiplying, so no intermediate value
/// ever exceeds the maximum, and the maximum is `CURL_OFF_T_MAX`, which this
/// engine models as [`i64::MAX`].
///
/// Returns [`None`] for an overflow, and for a non-hexadecimal byte -- which
/// the caller has already excluded, and which is answered rather than panicked
/// on because a decoder must not abort a process over malformed input.
fn parse_chunk_size(digits: &[u8]) -> Option<i64> {
    // `:169-170`: `STRE_NO_NUM` for an empty run. The caller checks
    // `hexindex != 0` first, exactly as the C does.
    debug_assert!(
        !digits.is_empty(),
        "a chunk size is parsed only after at least one digit"
    );
    let mut num: i64 = 0;
    for &digit in digits {
        let value = i64::from(char::from(digit).to_digit(16)?);
        // `:183-184`.
        if num > (i64::MAX - value) / 16 {
            return None;
        }
        // `:185`.
        num = num * 16 + value;
    }
    Some(num)
}

// The transfer-decoder writer stage -- `Curl_httpchunk_unencoder`.

/// The `"chunked"` transfer-unencoder.
///
/// Supersedes `struct chunked_writer` together with `cw_chunked_init`,
/// `cw_chunked_write`, `cw_chunked_close` and the descriptor
/// `Curl_httpchunk_unencoder` (`lib/http_chunks.c:388-460`). The C's
/// descriptor is a table of function pointers plus a `sizeof`; here the stage
/// IS the state, so `cwriter_size` has nothing to describe and `void *ctx` has
/// nothing to cast.
///
/// # Installed only at the transfer-decoding phase
///
/// `transfer/content_encoding.rs` owns installation, and the rules it must
/// enforce belong to it rather than here -- this stage performs framing and
/// makes no policy decision about its own presence. Those rules, from
/// `Curl_build_unencoding_stack` and `find_unencode_writer`
/// (`lib/content_encoding.c:667-790`), are:
///
/// * `"chunked"` is looked up ONLY when the phase is
///   [`ClientWriterPhase::TransferDecode`]: `transfer_unencoders[]`
///   (`:601-604`) holds this stage alone, and the general content decoders are
///   consulted afterwards. A `Content-Encoding: chunked` therefore does not
///   find this stage.
/// * The match is on exactly seven bytes, case-insensitively (`:726-727`).
/// * A second `"chunked"` is IGNORED, not stacked -- RFC 9112 section 6.1,
///   *"A sender MUST NOT apply the chunked transfer coding more than once to a
///   message body"*, and curl issue 13451 (`:646-656`).
/// * Any other transfer coding listed AFTER `"chunked"` is rejected with
///   [`CURLcode::BadContentEncoding`] (`:658-671`), because a stage added later
///   would land first within the phase and de-frame in the wrong order.
/// * `"chunked"` is installed even when transfer decoding is otherwise turned
///   off (`:719-720`), since a caller cannot opt out of framing and still read
///   the body.
#[derive(Debug)]
pub(crate) struct ChunkedDecoder {
    /// The state machine, one per response.
    chunker: Chunker,

    /// `data->set.http_te_skip`: write the ENCODED bytes to the client and
    /// decode only to find the end of the response.
    ///
    /// `CURLOPT_HTTP_TRANSFER_DECODING` set to 0. A per-handle setting fixed
    /// before the transfer begins, which is why it is a field here rather than
    /// something reached for on each write.
    http_te_skip: bool,
}

impl ChunkedDecoder {
    /// A decoder for one response.
    ///
    /// `Curl_httpchunk_init(data, &ctx->ch, FALSE)` (`:399`): `ignore_body` is
    /// FALSE for this stage, always. A writer chain exists to deliver a body,
    /// so a stage in one never suppresses it; the suppressing caller is
    /// `lib/cf-h1-proxy.c`, which drives a [`Chunker`] directly.
    #[must_use]
    pub(crate) fn new(http_te_skip: bool) -> Self {
        Self {
            chunker: Chunker::new(false),
            http_te_skip,
        }
    }

    /// The decoder's state, for a caller that wants it without a downcast.
    #[must_use]
    #[allow(dead_code)] // consumer: protocols/http1.rs
    pub(crate) const fn state(&self) -> ChunkyState {
        self.chunker.state()
    }
}

impl ClientWriter for ChunkedDecoder {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::ChunkedDecode
    }

    /// `CURL_CW_TRANSFER_DECODE`.
    ///
    /// The phase is what puts this stage ABOVE the protocol stage, so the
    /// length check, the content decoders and the client all see de-framed
    /// bytes. `Curl_build_unencoding_stack` passes the phase in
    /// (`lib/content_encoding.c:700-701`); it is fixed here because this stage
    /// has exactly one place it can work.
    fn phase(&self) -> ClientWriterPhase {
        ClientWriterPhase::TransferDecode
    }

    /// `cw_chunked_init` (`lib/http_chunks.c:393-401`).
    ///
    /// The C's first line is `data->req.chunk = TRUE`. That flag has one
    /// meaning -- *"chunks coming our way"* -- and three readers, all in
    /// `lib/http.c` (`:3620`, `:3807`, `:3993`), where it says the response
    /// length is not to be trusted and the connection need not be closed to
    /// delimit the body. [`receiving_chunks`] answers exactly that question
    /// from the chain, so nothing is written here and there is no second copy
    /// of the fact to fall out of step.
    ///
    /// Its second line is `Curl_httpchunk_init(data, &ctx->ch, FALSE)`, which
    /// is this method's whole body. The C runs it at create time and so does
    /// this, because `ClientWriterStack::create` calls `do_init` before the
    /// stage joins the chain. Nothing is traced: the C traces nothing here, and
    /// a trace line this module invented would appear in a `--trace` capture
    /// that the C's would not.
    fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        let _ = ctx;
        self.chunker = Chunker::new(false);
        Ok(())
    }

    /// `cw_chunked_write` (`lib/http_chunks.c:410-450`).
    ///
    /// # Errors
    ///
    /// * Whatever [`Chunker::read`] returned -- [`CURLcode::RecvError`] for a
    ///   framing fault, a downstream stage's own code for a refused write, or
    ///   [`CURLcode::TooLarge`] for a trailer line past its ceiling. The code
    ///   is returned UNCHANGED; only the sentence that accompanies it is chosen
    ///   here.
    /// * [`CURLcode::PartialFile`] when the stream ends before the last chunk
    ///   arrives.
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `:418-419`. Headers, informational writes and the trailers this
        // stage itself produced on an earlier turn are none of its business.
        if !flags.contains(ClientWriteFlags::BODY) {
            return tail.write(ctx, flags, buf);
        }

        // `:421-423`.
        let outcome = self.chunker.read(ctx, tail, self.http_te_skip, buf);

        let consumed = match outcome {
            Ok(consumed) => consumed,
            // `:425-434`. Two sentences, and which one appears depends on
            // whether the fault was ours or the next stage's. The code is not
            // remapped either way.
            Err(error) => {
                let code = error.code();
                let last = self.chunker.last_code();
                return Err(if last == ChunkCode::PassthruError {
                    ctx.failf(
                        code,
                        format_args!(
                            "Failed reading the chunked-encoded stream"
                        ),
                    )
                } else {
                    ctx.failf(
                        code,
                        format_args!("{} in chunked-encoding", last.message()),
                    )
                });
            }
        };

        // `:436`.
        let leftover = buf.len() - consumed;

        // `:437-443`.
        if self.chunker.is_done() {
            ctx.write_state_mut().download_done = true;
            if leftover != 0 {
                // The bytes after the last chunk belong to whatever comes next
                // on this connection -- another response on a kept-alive
                // connection, most often -- and were never part of the body.
                ctx.infof(format_args!(
                    "Leftovers after chunking: {leftover} bytes"
                ));
            }
            return Ok(());
        }

        // `:444-447`. The stream ended with a chunk still outstanding, which is
        // a truncated response and not a complete one. A bodyless response is
        // exempt: there was nothing to truncate.
        if flags.contains(ClientWriteFlags::EOS) && !ctx.write_state().no_body {
            return Err(ctx.failf(
                CURLcode::PartialFile,
                format_args!(
                    "transfer closed with outstanding read data remaining"
                ),
            ));
        }

        // `:449`.
        Ok(())
    }

    /// `cw_chunked_close` (`lib/http_chunks.c:403-408`).
    ///
    /// Releases the trailer buffer and writes nothing: a stage leaving the
    /// chain must not emit anything, or a torn-down transfer would deliver
    /// bytes after its last write.
    fn close(&mut self, ctx: &mut ClientCtx<'_>) {
        let _ = ctx;
        self.chunker.free();
    }
}

/// The stage `transfer/content_encoding.rs` installs for the `"chunked"`
/// transfer coding -- the `transfer_unencoders[]` entry
/// (`lib/content_encoding.c:601-604`).
///
/// A function rather than a static table because the stage carries
/// `data->set.http_te_skip`, which the C reads from the handle on every write.
#[must_use]
#[allow(dead_code)] // consumer: transfer/content_encoding.rs
pub(crate) fn transfer_unencoder(
    http_te_skip: bool,
) -> Box<dyn ClientWriter + 'static> {
    Box::new(ChunkedDecoder::new(http_te_skip))
}

/// `data->req.chunk`: whether the response being read is chunked.
///
/// The C sets a flag in `cw_chunked_init` (`lib/http_chunks.c:398`), clears it
/// in `Curl_req_init` (`lib/request.c:155`) and in `multi.c:116`, and reads it
/// in three places in `lib/http.c`. All four writes exist to keep one boolean
/// in step with one fact -- *is a chunked decoder installed* -- so the fact is
/// answered from the chain instead, by name, the way
/// `Curl_cwriter_get_by_name(data, "chunked")` already answers it at
/// `lib/content_encoding.c:668`.
///
/// The three readers this serves, with what each does when it is true:
///
/// * `lib/http.c:3620` -- do not offer a `Transfer-Encoding` request header
///   for a response already being de-framed.
/// * `:3807` -- ignore the response's `Content-Length`, since the framing
///   carries the length.
/// * `:3993` -- do not require the connection to close in order to delimit the
///   body.
#[must_use]
#[allow(dead_code)] // consumer: protocols/http1.rs
pub(crate) fn receiving_chunks(stack: &ClientWriterStack<'_>) -> bool {
    stack.get_by_kind(ClientWriterKind::ChunkedDecode).is_some()
}

// The transfer-encoder reader stage -- `Curl_httpchunk_encoder`.

/// Append one chunk's size line: lowercase hexadecimal, no leading zeros, CRLF.
///
/// `curl_msnprintf(hd, sizeof(hd), "%zx\r\n", nread)`
/// (`lib/http_chunks.c:576`), written out rather than delegated. Every
/// property here is observable and therefore deliberate:
///
/// * **Lowercase.** `%zx`, not `%zX`.
/// * **No leading zeros and no minimum width.** No flags and no field width in
///   the C's format string, so 16 bytes are `10` and never `0010`.
/// * **CRLF, always.** Never a bare line feed.
///
/// Sixteen digits hold any [`usize`] on a 64-bit target, which every supported
/// target is (specification 0.8.3), and a payload is capped at
/// [`CURL_CHUNKED_MAXLEN`] anyway, so five digits are the practical maximum.
fn append_chunk_size(out: &mut BytesMut, len: usize) {
    debug_assert!(
        len != 0,
        "the C writes a size line only for a non-empty payload (`:570`)"
    );
    let mut digits = [0_u8; CHUNK_MAXNUM_LEN];
    let mut at = digits.len();
    let mut left = len;
    // Least significant digit first, filling the array from its end, so the
    // most significant digit ends up first and no leading zero is ever
    // produced. A zero length would emit nothing at all, which is why the
    // caller's guard is asserted above.
    while left != 0 {
        at -= 1;
        digits[at] = HEX_LOWER[left % 16];
        left /= 16;
    }
    out.extend_from_slice(&digits[at..]);
    out.extend_from_slice(CRLF);
}

/// Whether a trailer from the callback is well formed enough to emit.
///
/// `const char *ptr = strchr(tr->data, ':'); if(!ptr || *(ptr + 1) != ' ')`
/// (`lib/http_chunks.c:520-521`). Two conditions, and both are exactly as
/// narrow as the C's:
///
/// * There is a colon somewhere.
/// * The byte immediately after it is a single ASCII space -- not a tab, not
///   two spaces, not the end of the entry.
///
/// Nothing else is checked: the name is not validated, the value is not
/// trimmed, and a trailer whose colon is its first byte passes. Widening this
/// would reject trailers curl emits, and narrowing it would emit trailers curl
/// skips.
///
/// The C's `strchr` stops at the string's terminator, which cannot be reached
/// here: an entry is the bytes of a C string WITHOUT its terminator, so no
/// interior zero byte can exist in one that arrived through the ABI.
fn well_formed_trailer(trailer: &[u8]) -> bool {
    match trailer.iter().position(|byte| *byte == b':') {
        None => false,
        Some(at) => trailer.get(at + 1) == Some(&b' '),
    }
}

/// The `"chunked"` transfer encoder.
///
/// Supersedes `struct chunked_reader` together with `cr_chunked_init`,
/// `add_last_chunk`, `add_chunk`, `cr_chunked_read`,
/// `cr_chunked_total_length`, `cr_chunked_close` and the descriptor
/// `Curl_httpchunk_encoder` (`lib/http_chunks.c:466-652`).
///
/// # What the two flags mean, and why there are two
///
/// `read_eos` is *"we read an EOS from the next reader"* and `eos` is *"we have
/// returned an EOS"*, and they are days apart in a slow upload: the source can
/// be exhausted long before the terminal block has been drained through a
/// caller that reads 16 bytes at a time. Collapsing them would either report
/// the end of the stream while framing was still queued, or ask an exhausted
/// source for more.
#[derive(Debug)]
pub(crate) struct ChunkedEncoder<'data> {
    /// `struct bufq chunkbuf`: framed bytes waiting to be read out.
    ///
    /// A first-in, first-out byte queue. Reading takes from the front with
    /// [`Buf::advance`], which is a pointer bump rather than a copy, and
    /// [`BytesMut`] reclaims the space at the front when it next grows.
    queue: BytesMut,

    /// `BIT(read_eos)`: the source has reported the end of its stream.
    read_eos: bool,

    /// `BIT(eos)`: the end of the stream has been reported onwards.
    eos: bool,

    /// `data->set.trailer_callback` bound to `data->set.trailer_data`.
    ///
    /// [`None`] is the ordinary case and the one that produces the plain
    /// `0\r\n\r\n` terminal block.
    trailers: Option<Box<dyn TrailerCallback + 'data>>,
}

impl<'data> ChunkedEncoder<'data> {
    /// An encoder, with `CURLOPT_TRAILERFUNCTION` if one is installed.
    #[must_use]
    pub(crate) fn new(
        trailers: Option<Box<dyn TrailerCallback + 'data>>,
    ) -> Self {
        Self {
            queue: BytesMut::new(),
            read_eos: false,
            eos: false,
            trailers,
        }
    }

    /// How many framed bytes are waiting.
    #[must_use]
    #[allow(dead_code)] // consumer: protocols/http1.rs
    pub(crate) fn queued(&self) -> usize {
        self.queue.len()
    }

    /// Take up to `buf.len()` bytes off the front of the queue.
    ///
    /// `Curl_bufq_cread` (`lib/http_chunks.c:616`). A caller that offers less
    /// than the queue holds gets a prefix and the rest stays queued, which is
    /// what lets a 5-byte destination drain a 64 KiB chunk without changing a
    /// single byte of it.
    fn take_queued(&mut self, buf: &mut [u8]) -> usize {
        let taken = self.queue.len().min(buf.len());
        buf[..taken].copy_from_slice(&self.queue[..taken]);
        self.queue.advance(taken);
        taken
    }

    /// `add_last_chunk` (`lib/http_chunks.c:490-540`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::AbortedByCallback`] when the callback returns anything other
    /// than [`CURL_TRAILERFUNC_OK`], and [`CURLcode::TooLarge`] when a trailer
    /// crosses `DYN_H1_TRAILER` or the block crosses `DYN_TRAILERS`.
    fn add_last_chunk(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        // `:499-502`.
        if self.trailers.is_none() {
            ctx.trc_read(format_args!("http_chunk, added last, empty chunk"));
            self.queue.extend_from_slice(LAST_CHUNK);
            return Ok(());
        }

        let result = self.append_trailer_block(ctx);
        // `:537-538`, traced on both outcomes with the C's `%d` of the code.
        let code = match &result {
            Ok(()) => CURLcode::Ok.as_i32(),
            Err(error) => error.code().as_i32(),
        };
        ctx.trc_read(format_args!(
            "http_chunk, added last chunk with trailers from client -> {code}"
        ));
        result
    }

    /// The terminal block when a trailer callback is installed.
    ///
    /// `lib/http_chunks.c:504-533`, with one structural difference that is
    /// deliberate and observable only on the failure path.
    ///
    /// # Staged, then committed in one piece
    ///
    /// The C writes `"0\r\n"`, each trailer and the final `"\r\n"` straight
    /// into its output queue as it goes, which it can do because that queue is
    /// soft-limited and has no ceiling to cross. This module applies
    /// `DYN_H1_TRAILER` to each line and `DYN_TRAILERS` to the block, so a
    /// crossing IS possible -- and a block written incrementally would then
    /// leave a truncated terminal block queued for the peer, which cannot be
    /// taken back once the bytes are framed. The block is therefore staged in a
    /// bounded buffer and appended to the queue only when it is complete. The
    /// byte ORDER is the C's exactly: the last chunk's size line first, so the
    /// trailers land between it and the final CRLF.
    ///
    /// # The callback's list is released on every path
    ///
    /// The C reaches `curl_slist_free_all(trailers)` through a `goto out`
    /// (`:536`), which runs after an abort as well as after a success. Here the
    /// list is an owned field of [`TrailerResult`], so it is dropped when this
    /// function returns however it returns -- including through the `?` on a
    /// crossed ceiling.
    fn append_trailer_block(
        &mut self,
        ctx: &mut ClientCtx<'_>,
    ) -> CurlResult<()> {
        let mut block = DynBuf::new(DYN_TRAILERS);
        // `:504-506`.
        block.addn(LAST_CHUNK_HEAD).map_err(Error::new)?;

        // `:508-510`. The guard is raised for the call and lowered as the
        // borrow ends, so a callback that panics or returns early cannot leave
        // the transfer looking as though it were still inside one.
        let outcome = match self.trailers.as_mut() {
            // Unreachable: the caller checked. Answering rather than panicking
            // keeps a future caller's mistake from aborting a transfer.
            None => return Ok(()),
            Some(callback) => {
                let _entered = ctx.enter_callback();
                callback.trailers()
            }
        };

        // `:512-516`. The C compares against `CURL_TRAILERFUNC_OK`, so every
        // other value aborts -- not only `CURL_TRAILERFUNC_ABORT`.
        if !outcome.accepted() {
            return Err(ctx.failf(
                CURLcode::AbortedByCallback,
                format_args!("operation aborted by trailing headers callback"),
            ));
        }

        // `:518-531`.
        for trailer in &outcome.trailers {
            // `:519-524`: *"only add correctly formatted trailers"*. A
            // malformed entry is skipped and the rest are still emitted.
            if !well_formed_trailer(trailer) {
                ctx.infof(format_args!(
                    "Malformatted trailing header, skipping trailer"
                ));
                continue;
            }
            // `DYN_H1_TRAILER` per line. The line is built in its own bounded
            // buffer so that the ceiling applies to the trailer AND its CRLF,
            // and so that a crossing is reported before anything reaches the
            // block.
            let mut line = DynBuf::new(DYN_H1_TRAILER);
            line.addn(trailer).map_err(Error::new)?;
            line.addn(CRLF).map_err(Error::new)?;
            // `:526-528`: the trailer exactly as the callback returned it, then
            // CRLF. Not lowercased, not trimmed, not reordered, not
            // deduplicated -- a trailer is the application's bytes.
            block.addn(line.as_slice()).map_err(Error::new)?;
        }

        // `:533`: the blank line that ends the trailer section.
        block.addn(CRLF).map_err(Error::new)?;

        self.queue.extend_from_slice(block.as_slice());
        Ok(())
    }

    /// `add_chunk` (`lib/http_chunks.c:542-594`): frame one read from the
    /// source.
    ///
    /// # The payload length is chosen, not taken
    ///
    /// Three rules, in the C's order, and each is observable in the size line
    /// it produces:
    ///
    /// 1. The destination is capped at [`CURL_CHUNKED_MAXLEN`] -- *"respect our
    ///    buffer pref"* (`:553`).
    /// 2. A destination shorter than [`CURL_CHUNKED_MINLEN`] is not used at
    ///    all: the payload is read into scratch of exactly that size instead,
    ///    so a caller offering 40 bytes still produces a 1024-byte chunk
    ///    (`:554-558`).
    /// 3. Otherwise the destination IS the scratch, less
    ///    [`CHUNK_FRAMING_ALLOWANCE`], so that the framed chunk fits the
    ///    destination it will be read back into (`:559-562`).
    ///
    /// # Errors
    ///
    /// Whatever the source returned, and whatever [`Self::add_last_chunk`]
    /// returned when this read was the last.
    fn add_chunk(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        source: &mut dyn ChunkSource,
        buf: &mut [u8],
    ) -> CurlResult<()> {
        // `:552`.
        debug_assert!(
            !self.read_eos,
            "the source is not consulted again once it has reported the end \
             of its stream"
        );

        // `:553`.
        let blen = buf.len().min(CURL_CHUNKED_MAXLEN);
        let mut scratch = [0_u8; CURL_CHUNKED_MINLEN];
        let (outcome, from_scratch) = if blen < CURL_CHUNKED_MINLEN {
            // `:554-558`.
            (source.chunk_read(ctx, &mut scratch)?, true)
        } else {
            // `:559-562`.
            let room = blen - CHUNK_FRAMING_ALLOWANCE;
            (source.chunk_read(ctx, &mut buf[..room])?, false)
        };

        // `:567-568`.
        if outcome.eos {
            self.read_eos = true;
        }

        // `:570-589`.
        if outcome.bytes_read != 0 {
            let payload = if from_scratch {
                &scratch[..outcome.bytes_read]
            } else {
                &buf[..outcome.bytes_read]
            };
            append_chunk_size(&mut self.queue, payload.len());
            self.queue.extend_from_slice(payload);
            self.queue.extend_from_slice(CRLF);
            // `:585-586`. The C traces the queue write's result; a growable
            // buffer's append cannot fail, so the code is always
            // `CURLE_OK`, and the line is kept for comparability with the C's
            // by eye.
            ctx.trc_read(format_args!(
                "http_chunk, made chunk of {} bytes -> {}",
                payload.len(),
                CURLcode::Ok.as_i32()
            ));
        }

        // `:591-593`.
        if self.read_eos {
            return self.add_last_chunk(ctx);
        }
        Ok(())
    }

    /// `cr_chunked_read` (`lib/http_chunks.c:596-628`).
    ///
    /// Separated from [`ClientReader::read`] so that the source is a
    /// [`ChunkSource`] rather than a [`ReaderTail`], which is what lets the
    /// encoder be driven from memory in the tests below.
    ///
    /// # Pause semantics
    ///
    /// A source that returns no bytes and does NOT report the end of its stream
    /// is paused or momentarily out of data. The queue is then still empty, the
    /// `if` at `:615` is not taken, and the answer is no bytes and NOT the end
    /// of the stream. Crucially the terminal block is not manufactured: doing
    /// so would frame a complete body around an upload that has more to come.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::add_chunk`] returned.
    fn read_framed(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        source: &mut dyn ChunkSource,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        // `:604-607`: once the end of the stream has been reported, it is
        // reported for ever and nothing else happens.
        if self.eos {
            return Ok(ReadOutcome::EOS);
        }

        // `:608-613`.
        if !self.read_eos && self.queue.is_empty() {
            self.add_chunk(ctx, source, buf)?;
        }

        // `:615-623`.
        if !self.queue.is_empty() {
            let taken = self.take_queued(buf);
            // `:617-621`: the end of the stream is reported with the LAST
            // bytes, and only once the terminal block has been drained.
            if self.read_eos && self.queue.is_empty() {
                self.eos = true;
                return Ok(ReadOutcome::new(taken, true));
            }
            return Ok(ReadOutcome::new(taken, false));
        }

        // `:625-627`: *"We may get here, because we are done or because
        // callbacks paused"*. The C's `DEBUGASSERT(ctx->eos || !ctx->read_eos)`
        // holds because a source that reported the end of its stream also
        // caused a terminal block to be queued, which is at least five bytes.
        debug_assert!(
            self.eos || !self.read_eos,
            "an exhausted source leaves a terminal block to drain"
        );
        Ok(ReadOutcome::EMPTY)
    }
}

/// The descriptor `Curl_httpchunk_encoder` (`lib/http_chunks.c:640-652`)
/// overrides four members and takes the default for five, and this
/// implementation matches it member for member:
///
/// | C member | here |
/// |---|---|
/// | `cr_chunked_init` | [`ClientReader::init`] |
/// | `cr_chunked_read` | [`ClientReader::read`] |
/// | `cr_chunked_close` | [`ClientReader::close`] |
/// | `cr_chunked_total_length` | [`ClientReader::total_length`] |
/// | `Curl_creader_def_needs_rewind` | not overridden |
/// | `Curl_creader_def_resume_from` | not overridden |
/// | `Curl_creader_def_cntrl` | not overridden |
/// | `Curl_creader_def_is_paused` | not overridden |
/// | `Curl_creader_def_done` | not overridden |
///
/// The five omissions are deliberate. A rewind, a resumption, an unpause and
/// the end of a request are the SOURCE's business: this stage holds no position
/// in the upload, only bytes it has already framed, and a chain-wide control
/// reaches every stage in turn (`Curl_creader_cntrl` walks the whole chain), so
/// the source below hears each one directly. Answering
/// [`ClientReader::needs_rewind`] with anything but false, or accepting a
/// [`ClientReader::resume_from`] this stage cannot honour, would claim a
/// capability the C's descriptor declines.
impl ClientReader for ChunkedEncoder<'_> {
    fn kind(&self) -> ClientReaderKind {
        ClientReaderKind::ChunkedEncode
    }

    /// `CURL_CR_TRANSFER_ENCODE`, the phase
    /// `Curl_httpchunk_add_reader` creates this stage at (`:660`).
    fn phase(&self) -> ClientReaderPhase {
        ClientReaderPhase::TransferEncode
    }

    /// `cr_chunked_init` (`lib/http_chunks.c:473-480`): give the output queue
    /// the C's preferred room.
    ///
    /// `Curl_bufq_init2(&ctx->chunkbuf, CURL_CHUNKED_MAXLEN, 2,
    /// BUFQ_OPT_SOFT_LIMIT)` and nothing else. Untraced for the same reason
    /// [`ChunkedDecoder::init`] is.
    fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        let _ = ctx;
        self.queue.reserve(CHUNK_QUEUE_CAPACITY);
        Ok(())
    }

    fn read(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut ReaderTail<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<ReadOutcome> {
        self.read_framed(ctx, tail, buf)
    }

    /// `cr_chunked_close` (`lib/http_chunks.c:482-488`): release the queue.
    ///
    /// Nothing is emitted: a stage leaving the chain must not add bytes to a
    /// body it will no longer be asked about.
    fn close(&mut self, ctx: &mut ClientCtx<'_>) {
        let _ = ctx;
        self.queue.clear();
        // The C's `Curl_bufq_free` returns the chunks; shrinking to nothing is
        // the same statement about the allocation.
        self.queue = BytesMut::new();
    }

    /// `cr_chunked_total_length` (`lib/http_chunks.c:630-637`): unknown.
    ///
    /// The C's comment is *"this reader changes length depending on input"*,
    /// and it ignores the chain below rather than adding framing to whatever
    /// that reports -- the framing depends on how the reads happen to divide,
    /// which is not knowable in advance. -1 is what
    /// `Curl_creader_total_length` then reports for the whole chain
    /// (`lib/sendf.h:353-359`), which is what makes a chunked upload a chunked
    /// upload rather than one with a `Content-Length`.
    fn total_length(&self, below: &ReaderQuery<'_, '_>) -> i64 {
        let _ = below;
        -1
    }
}

/// `Curl_httpchunk_add_reader` (`lib/http_chunks.c:654-667`): install the
/// encoder.
///
/// The C creates the stage at `CURL_CR_TRANSFER_ENCODE`, adds it, and frees it
/// if the add failed. Here `create` drops a stage whose `do_init` failed and
/// `add_reader` takes ownership, so both halves of that clean-up are the type
/// system's and there is no pointer left for a caller to free twice.
///
/// # `protocols/http1.rs` calls this and does not serialize chunks itself
///
/// `lib/http.c:2454` is the only caller, on the path where a request body needs
/// chunked transfer coding. The framing belongs to this stage so that ONE
/// implementation produces it: hyper's own body encoder would produce
/// well-formed but differently spelled chunks, and the fixture corpus compares
/// the bytes.
///
/// # Errors
///
/// Whatever [`ClientReaderStack::create`] or
/// [`ClientIo::add_reader`] returned.
#[must_use = "the installation can fail and the error must be handled"]
#[allow(dead_code)] // consumer: protocols/http1.rs
pub(crate) fn add_chunked_encoder<'data>(
    io: &mut ClientIo<'data>,
    ctx: &mut ClientCtx<'_>,
    trailers: Option<Box<dyn TrailerCallback + 'data>>,
) -> CurlResult<()> {
    // `:659-660`.
    let reader = ClientReaderStack::create(
        Box::new(ChunkedEncoder::new(trailers)),
        ctx,
    )?;
    // `:661-662`.
    io.add_reader(ctx, reader)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use super::*;
    use crate::headers::{
        classify_origin, HeaderStore, CURLH_HEADER, CURLH_TRAILER,
    };
    // `Progress`, `Clock` and `CurlTime` are named here because
    // `ClientCtx::new` -- which IS in this module's dependency set -- takes
    // them; they arrive transitively through that signature rather than as
    // dependencies of their own, and only in this test module.
    use crate::transfer::progress::Progress;
    use crate::transfer::sendf::{
        ClientCallbackGuard, ClientConfig, ClientIoFactory, ClientReadSource,
        RequestReadState, RequestWriteState, TraceDataKind, TraceSink,
        TransferControl,
    };
    use crate::transfer::writeout::{
        install_header_collector, HeaderStoreHandle, CURL_MAX_WRITE_SIZE,
    };
    use crate::util::timeval::{CurlTime, TestClock};

    // -- the doubles ------------------------------------------------------

    /// One write that reached a recorder.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Written {
        flags: ClientWriteFlags,
        bytes: Vec<u8>,
    }

    /// A [`ChunkSink`] that records every write and can refuse one.
    #[derive(Debug)]
    struct Sink {
        writes: Vec<Written>,
        /// Which write to refuse, counted from zero.
        refuse_at: Option<usize>,
        /// The code to refuse it with.
        refuse_with: CURLcode,
    }

    impl Sink {
        fn new() -> Self {
            Self {
                writes: Vec::new(),
                refuse_at: None,
                refuse_with: CURLcode::WriteError,
            }
        }

        fn refusing(at: usize, code: CURLcode) -> Self {
            Self {
                writes: Vec::new(),
                refuse_at: Some(at),
                refuse_with: code,
            }
        }

        /// Every body byte, in the order it was written.
        fn body(&self) -> Vec<u8> {
            self.writes
                .iter()
                .filter(|write| write.flags.contains(ClientWriteFlags::BODY))
                .flat_map(|write| write.bytes.clone())
                .collect()
        }

        /// Every write that carried the trailer flags.
        fn trailers(&self) -> Vec<Written> {
            self.writes
                .iter()
                .filter(|write| write.flags.contains(ClientWriteFlags::TRAILER))
                .cloned()
                .collect()
        }
    }

    impl ChunkSink for Sink {
        fn chunk_write(
            &mut self,
            ctx: &mut ClientCtx<'_>,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CurlResult<()> {
            let _ = ctx;
            let index = self.writes.len();
            self.writes.push(Written {
                flags,
                bytes: buf.to_vec(),
            });
            if self.refuse_at == Some(index) {
                return Err(Error::new(self.refuse_with));
            }
            Ok(())
        }
    }

    /// One scripted answer from a [`ChunkSource`].
    #[derive(Clone, Debug)]
    enum SourceStep {
        /// These bytes, and more to come.
        Data(Vec<u8>),
        /// These bytes, and that is all.
        Last(Vec<u8>),
        /// Nothing, and NOT the end of the stream -- a paused source.
        Paused,
        /// Nothing, and the end of the stream.
        Eos,
        /// Refuse the read.
        Fail(CURLcode),
    }

    /// A [`ChunkSource`] that answers from a script and records what it was
    /// asked for.
    #[derive(Debug)]
    struct Source {
        script: VecDeque<SourceStep>,
        asked: Vec<usize>,
    }

    impl Source {
        fn new(steps: Vec<SourceStep>) -> Self {
            Self {
                script: steps.into(),
                asked: Vec::new(),
            }
        }
    }

    impl ChunkSource for Source {
        fn chunk_read(
            &mut self,
            ctx: &mut ClientCtx<'_>,
            buf: &mut [u8],
        ) -> CurlResult<ReadOutcome> {
            let _ = ctx;
            self.asked.push(buf.len());
            let hand_over = |bytes: &[u8], buf: &mut [u8], eos: bool| {
                assert!(
                    bytes.len() <= buf.len(),
                    "a scripted step must fit the destination: {} into {}",
                    bytes.len(),
                    buf.len()
                );
                buf[..bytes.len()].copy_from_slice(bytes);
                Ok(ReadOutcome::new(bytes.len(), eos))
            };
            match self.script.pop_front() {
                // An exhausted script is an exhausted source.
                None => Ok(ReadOutcome::EOS),
                Some(SourceStep::Data(bytes)) => hand_over(&bytes, buf, false),
                Some(SourceStep::Last(bytes)) => hand_over(&bytes, buf, true),
                Some(SourceStep::Paused) => Ok(ReadOutcome::EMPTY),
                Some(SourceStep::Eos) => Ok(ReadOutcome::EOS),
                Some(SourceStep::Fail(code)) => Err(Error::new(code)),
            }
        }
    }

    /// A scripted `CURLOPT_TRAILERFUNCTION`.
    #[derive(Clone, Debug)]
    struct Trailers {
        answer: TrailerResult,
        calls: Rc<Cell<usize>>,
    }

    impl Trailers {
        fn new(answer: TrailerResult) -> Self {
            Self {
                answer,
                calls: Rc::new(Cell::new(0)),
            }
        }

        /// A callback answering `CURL_TRAILERFUNC_OK` with these entries.
        fn ok(entries: &[&[u8]]) -> Self {
            Self::new(TrailerResult::ok(
                entries.iter().map(|entry| entry.to_vec()).collect(),
            ))
        }

        fn boxed(&self) -> Box<dyn TrailerCallback> {
            Box::new(self.clone())
        }
    }

    impl TrailerCallback for Trailers {
        fn trailers(&mut self) -> TrailerResult {
            self.calls.set(self.calls.get() + 1);
            self.answer.clone()
        }
    }

    /// The transfer engine's three operations, recorded.
    #[derive(Debug, Default)]
    struct Control {
        stream_closes: Vec<&'static str>,
        conn_closes: Vec<&'static str>,
    }

    impl TransferControl for Control {
        fn stream_close(&mut self, reason: &'static str) {
            self.stream_closes.push(reason);
        }

        fn conn_close(&mut self, reason: &'static str) {
            self.conn_closes.push(reason);
        }

        fn pause_send(&mut self, pause: bool) -> CurlResult<()> {
            let _ = pause;
            Ok(())
        }

        fn pause_recv(&mut self, pause: bool) -> CurlResult<()> {
            let _ = pause;
            Ok(())
        }
    }

    /// The in-callback flag, with every transition recorded.
    #[derive(Debug, Default)]
    struct Guard {
        transitions: Vec<bool>,
        depth: i32,
    }

    impl Guard {
        fn entries(&self) -> usize {
            self.transitions.iter().filter(|raised| **raised).count()
        }
    }

    impl ClientCallbackGuard for Guard {
        fn set_in_callback(&mut self, inside: bool) {
            self.transitions.push(inside);
            self.depth += if inside { 1 } else { -1 };
            assert!(
                (0..=1).contains(&self.depth),
                "the in-callback flag is a boolean: depth {} is impossible",
                self.depth
            );
        }
    }

    /// Every diagnostic, as rendered text.
    #[derive(Debug, Default)]
    struct Trace {
        writes: Vec<String>,
        reads: Vec<String>,
        fails: Vec<String>,
        infos: Vec<String>,
    }

    impl Trace {
        fn saw(lines: &[String], needle: &str) -> bool {
            lines.iter().any(|line| line.contains(needle))
        }
    }

    impl TraceSink for Trace {
        fn debug(&mut self, kind: TraceDataKind, bytes: &[u8]) {
            let _ = (kind, bytes);
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

    /// Everything a [`ClientCtx`] borrows, owned in one place.
    #[derive(Debug)]
    struct Env {
        write: RequestWriteState,
        read: RequestReadState,
        config: ClientConfig,
        progress: Progress,
        clock: TestClock,
        control: Control,
        guard: Guard,
        trace: Trace,
    }

    impl Env {
        fn new() -> Self {
            Self {
                write: RequestWriteState::default(),
                read: RequestReadState::default(),
                config: ClientConfig::default(),
                progress: Progress::default(),
                clock: TestClock::new(CurlTime::new(1_000, 0)),
                control: Control::default(),
                guard: Guard::default(),
                trace: Trace::default(),
            }
        }

        /// A context over this environment, tracing into it.
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

    /// A decoder, its environment and its recorder, driven feed by feed.
    #[derive(Debug)]
    struct Decoder {
        env: Env,
        sink: Sink,
        chunker: Chunker,
        te_skip: bool,
    }

    impl Decoder {
        fn new() -> Self {
            Self {
                env: Env::new(),
                sink: Sink::new(),
                chunker: Chunker::new(false),
                te_skip: false,
            }
        }

        /// `Curl_httpchunk_init(data, ch, TRUE)` -- the proxy's configuration.
        fn ignoring_body() -> Self {
            let mut decoder = Self::new();
            decoder.chunker = Chunker::new(true);
            decoder
        }

        /// `data->set.http_te_skip` set.
        fn skipping() -> Self {
            let mut decoder = Self::new();
            decoder.te_skip = true;
            decoder
        }

        fn with_sink(sink: Sink) -> Self {
            let mut decoder = Self::new();
            decoder.sink = sink;
            decoder
        }

        /// One call to `Curl_httpchunk_read`.
        fn feed(&mut self, input: &[u8]) -> CurlResult<usize> {
            let Self {
                env,
                sink,
                chunker,
                te_skip,
            } = self;
            let mut ctx = env.ctx();
            chunker.read(&mut ctx, sink, *te_skip, input)
        }

        /// Feed `input` one byte at a time, summing what was consumed.
        ///
        /// Stops at the first error or at completion, exactly as a caller
        /// would.
        fn feed_by_byte(&mut self, input: &[u8]) -> CurlResult<usize> {
            let mut total = 0;
            for at in 0..input.len() {
                total += self.feed(&input[at..=at])?;
                if self.chunker.is_done() {
                    break;
                }
            }
            Ok(total)
        }

        fn state(&self) -> ChunkyState {
            self.chunker.state()
        }

        fn body(&self) -> Vec<u8> {
            self.sink.body()
        }
    }

    /// An encoder, its environment and its source.
    #[derive(Debug)]
    struct Encoder<'data> {
        env: Env,
        source: Source,
        encoder: ChunkedEncoder<'data>,
    }

    impl<'data> Encoder<'data> {
        fn new(steps: Vec<SourceStep>) -> Self {
            Self {
                env: Env::new(),
                source: Source::new(steps),
                encoder: ChunkedEncoder::new(None),
            }
        }

        fn with_trailers(
            steps: Vec<SourceStep>,
            trailers: Box<dyn TrailerCallback + 'data>,
        ) -> Self {
            Self {
                env: Env::new(),
                source: Source::new(steps),
                encoder: ChunkedEncoder::new(Some(trailers)),
            }
        }

        /// `Curl_creader_read` into a destination of `buf.len()` bytes.
        fn read(&mut self, buf: &mut [u8]) -> CurlResult<ReadOutcome> {
            let Self {
                env,
                source,
                encoder,
            } = self;
            let mut ctx = env.ctx();
            encoder.read_framed(&mut ctx, source, buf)
        }

        /// Read until the end of the stream, `at_a_time` bytes per call.
        ///
        /// Returns everything that came out, in order. Bounded so that a
        /// stage that never reports the end of its stream fails the test
        /// rather than hanging it.
        fn drain(&mut self, at_a_time: usize) -> CurlResult<Vec<u8>> {
            let mut out = Vec::new();
            let mut buf = vec![0_u8; at_a_time];
            for _ in 0..10_000 {
                let outcome = self.read(&mut buf)?;
                out.extend_from_slice(&buf[..outcome.bytes_read]);
                if outcome.eos {
                    return Ok(out);
                }
            }
            panic!("the encoder never reported the end of its stream");
        }
    }

    /// A writer stage that records, for the base stack the factory builds.
    #[derive(Debug)]
    struct StageWriter {
        kind: ClientWriterKind,
        phase: ClientWriterPhase,
        log: Rc<RefCell<Vec<Written>>>,
        forward: bool,
        /// A code to refuse every write with -- the shape a
        /// `CURL_WRITEFUNC_ERROR` from the application takes by the time it
        /// reaches a decoder.
        refuse: Option<CURLcode>,
    }

    impl ClientWriter for StageWriter {
        fn kind(&self) -> ClientWriterKind {
            self.kind
        }

        fn phase(&self) -> ClientWriterPhase {
            self.phase
        }

        fn write(
            &mut self,
            ctx: &mut ClientCtx<'_>,
            tail: &mut WriterTail<'_, '_>,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CurlResult<()> {
            if self.kind == ClientWriterKind::ClientOut {
                self.log.borrow_mut().push(Written {
                    flags,
                    bytes: buf.to_vec(),
                });
            }
            if let Some(code) = self.refuse {
                return Err(Error::new(code));
            }
            if self.forward {
                tail.write(ctx, flags, buf)
            } else {
                Ok(())
            }
        }
    }

    /// A borrowed header store, for the `hds-collect` stage to fill.
    ///
    /// The same shape `transfer/writeout.rs`'s own tests use: the stage needs
    /// `&mut HeaderStore`, which cannot come out of a shared cell, so the
    /// store is borrowed and read back once the chain holding it is dropped.
    #[derive(Debug)]
    struct StoreHandle<'a> {
        store: &'a mut HeaderStore,
        request: i32,
    }

    impl HeaderStoreHandle for StoreHandle<'_> {
        fn store(&mut self) -> &mut HeaderStore {
            self.store
        }

        fn request(&self) -> i32 {
            self.request
        }
    }

    /// The two stages `transfer/writeout.rs` owns, as recorders.
    #[derive(Debug, Default)]
    struct Factory {
        log: Rc<RefCell<Vec<Written>>>,
        /// A code the CLIENT stage refuses every write with.
        refuse: Option<CURLcode>,
    }

    impl Factory {
        fn refusing(code: CURLcode) -> Self {
            Self {
                log: Rc::new(RefCell::new(Vec::new())),
                refuse: Some(code),
            }
        }
    }

    impl<'data> ClientIoFactory<'data> for Factory {
        fn client_out_writer(&self) -> Box<dyn ClientWriter + 'data> {
            Box::new(StageWriter {
                kind: ClientWriterKind::ClientOut,
                phase: ClientWriterPhase::Client,
                log: Rc::clone(&self.log),
                forward: false,
                refuse: self.refuse,
            })
        }

        fn pause_writer(&self) -> Box<dyn ClientWriter + 'data> {
            Box::new(StageWriter {
                kind: ClientWriterKind::Pause,
                phase: ClientWriterPhase::Protocol,
                log: Rc::clone(&self.log),
                forward: true,
                refuse: None,
            })
        }

        fn input_source(&self) -> Option<Box<dyn ClientReadSource + 'data>> {
            None
        }
    }

    /// The chunked decoder installed in a chain with the four base stages
    /// beneath it, which is the arrangement a real transfer produces.
    fn decode_stack<'a>(
        factory: &'a Factory,
        ctx: &mut ClientCtx<'_>,
        te_skip: bool,
    ) -> ClientWriterStack<'a> {
        let mut stack = ClientWriterStack::new();
        let stage = ClientWriterStack::create(transfer_unencoder(te_skip), ctx)
            .expect("the chunked decoder initialises");
        stack
            .add(stage, ctx, factory)
            .expect("the base stack builds");
        assert_eq!(
            stack.names(),
            vec!["raw", "chunked", "protocol", "cw-pause", "cw-out"],
            "the decoder belongs between the raw stage and the protocol stage"
        );
        stack
    }

    /// The canonical message from the chunked-encoding article, and the one
    /// the mission statement names: two chunks, no trailer.
    const WIKI: &[u8] =
        b"4\x0d\x0aWiki\x0d\x0a5\x0d\x0apedia\x0d\x0a0\x0d\x0a\x0d\x0a";

    // -- the vocabulary and the constants --------------------------------

    /// Every `CHUNKcode` integer, as `lib/http_chunks.h:84-92` numbers them.
    #[test]
    fn chunk_codes_have_their_c_integers() {
        assert_eq!(ChunkCode::Ok.as_i32(), 0);
        assert_eq!(ChunkCode::TooLongHex.as_i32(), 1);
        assert_eq!(ChunkCode::IllegalHex.as_i32(), 2);
        assert_eq!(ChunkCode::BadChunk.as_i32(), 3);
        assert_eq!(ChunkCode::BadEncoding.as_i32(), 4);
        assert_eq!(ChunkCode::OutOfMemory.as_i32(), 5);
        assert_eq!(ChunkCode::PassthruError.as_i32(), 6);
    }

    /// Every description `Curl_chunked_strerror` returns (`:360-378`),
    /// character for character -- these reach the user through
    /// `"%s in chunked-encoding"`.
    #[test]
    fn chunk_codes_carry_the_c_descriptions() {
        assert_eq!(ChunkCode::Ok.message(), "OK");
        assert_eq!(
            ChunkCode::TooLongHex.message(),
            "Too long hexadecimal number"
        );
        assert_eq!(
            ChunkCode::IllegalHex.message(),
            "Illegal or missing hexadecimal sequence"
        );
        assert_eq!(ChunkCode::BadChunk.message(), "Malformed encoding found");
        assert_eq!(
            ChunkCode::PassthruError.message(),
            "Error writing data to client"
        );
        assert_eq!(
            ChunkCode::BadEncoding.message(),
            "Bad content-encoding found"
        );
        assert_eq!(ChunkCode::OutOfMemory.message(), "Out of memory");
        // Display is the description, so the C's sentence composes.
        assert_eq!(
            format!("{} in chunked-encoding", ChunkCode::BadChunk),
            "Malformed encoding found in chunked-encoding"
        );
    }

    /// Every `CHUNKcode` spelling, as `lib/http_chunks.h:84-92` writes it.
    ///
    /// The tokens are part of the vocabulary this module is required to
    /// preserve, and a rename would be invisible without an assertion: nothing
    /// in the engine dispatches on the string, so only a reader comparing the
    /// two trees would notice. Display is the description rather than the
    /// identifier, which is what makes `"%s in chunked-encoding"` compose, so
    /// the identifier needs a test of its own.
    #[test]
    fn chunk_codes_carry_their_c_identifiers() {
        let pairs = [
            (ChunkCode::Ok, "CHUNKE_OK"),
            (ChunkCode::TooLongHex, "CHUNKE_TOO_LONG_HEX"),
            (ChunkCode::IllegalHex, "CHUNKE_ILLEGAL_HEX"),
            (ChunkCode::BadChunk, "CHUNKE_BAD_CHUNK"),
            (ChunkCode::BadEncoding, "CHUNKE_BAD_ENCODING"),
            (ChunkCode::OutOfMemory, "CHUNKE_OUT_OF_MEMORY"),
            (ChunkCode::PassthruError, "CHUNKE_PASSTHRU_ERROR"),
        ];
        assert_eq!(pairs.len(), 7, "the C declares seven codes");
        for (code, name) in pairs {
            assert_eq!(code.c_name(), name);
            // Every identifier is the enumerator, so the prefix is uniform and
            // no member of the C enumeration is missing from this module.
            assert!(
                name.starts_with("CHUNKE_"),
                "{name} is not a CHUNKE_ enumerator"
            );
        }
    }

    /// Every `ChunkyState` names its C identifier, and Display agrees.
    #[test]
    fn chunky_states_name_their_c_identifiers() {
        let pairs = [
            (ChunkyState::Hex, "CHUNK_HEX"),
            (ChunkyState::Lf, "CHUNK_LF"),
            (ChunkyState::Data, "CHUNK_DATA"),
            (ChunkyState::PostLf, "CHUNK_POSTLF"),
            (ChunkyState::Stop, "CHUNK_STOP"),
            (ChunkyState::Trailer, "CHUNK_TRAILER"),
            (ChunkyState::TrailerCr, "CHUNK_TRAILER_CR"),
            (ChunkyState::TrailerPostCr, "CHUNK_TRAILER_POSTCR"),
            (ChunkyState::Done, "CHUNK_DONE"),
            (ChunkyState::Failed, "CHUNK_FAILED"),
        ];
        assert_eq!(pairs.len(), 10, "the C declares ten states");
        for (state, name) in pairs {
            assert_eq!(state.c_name(), name);
            assert_eq!(state.to_string(), name);
        }
    }

    /// The measured constants, and the token both stages answer to.
    #[test]
    fn the_constants_are_the_measured_ones() {
        // `CHUNK_MAXNUM_LEN (SIZEOF_CURL_OFF_T * 2)` with a 64-bit
        // `curl_off_t`.
        assert_eq!(CHUNK_MAXNUM_LEN, 16);
        assert_eq!(CURL_CHUNKED_MINLEN, 1024);
        assert_eq!(CURL_CHUNKED_MAXLEN, 64 * 1024);
        assert_eq!(CHUNK_FRAMING_ALLOWANCE, 12);
        assert_eq!(CHUNK_QUEUE_CAPACITY, 128 * 1024);
        assert_eq!(CURL_TRAILERFUNC_OK, 0);
        assert_eq!(CURL_TRAILERFUNC_ABORT, 1);
        assert_eq!(DYN_H1_TRAILER, 4096);
        assert_eq!(DYN_TRAILERS, 64 * 1024);
        // The wire literals.
        assert_eq!(CR, 0x0d);
        assert_eq!(LF, 0x0a);
        assert_eq!(CRLF, b"\x0d\x0a");
        assert_eq!(LAST_CHUNK, b"0\x0d\x0a\x0d\x0a");
        assert_eq!(LAST_CHUNK_HEAD, b"0\x0d\x0a");
    }

    /// One token for the coding, and both stages answer to it.
    ///
    /// The constant is derived from the writer kind, so this test's job is the
    /// half that cannot be a compile-time derivation: that the READER's name is
    /// the same string, and that the string is the one on the wire.
    #[test]
    fn both_stages_answer_to_the_same_coding_token() {
        assert_eq!(CHUNKED_CODING_NAME, "chunked");
        assert_eq!(ClientWriterKind::ChunkedDecode.name(), "chunked");
        assert_eq!(ClientReaderKind::ChunkedEncode.name(), "chunked");
        // Neither stage carries an alias: only `gzip` and `identity` do.
        assert_eq!(ClientWriterKind::ChunkedDecode.alias(), None);
    }

    /// The decode stage's identity and placement.
    #[test]
    fn the_decoder_is_a_transfer_decode_stage_named_chunked() {
        let stage = ChunkedDecoder::new(false);
        assert_eq!(stage.kind(), ClientWriterKind::ChunkedDecode);
        assert_eq!(stage.phase(), ClientWriterPhase::TransferDecode);
        assert_eq!(stage.name(), CHUNKED_CODING_NAME);
        assert_eq!(stage.state(), ChunkyState::Hex);
    }

    /// The encode stage's identity, placement and unknowable length.
    #[test]
    fn the_encoder_is_a_transfer_encode_stage_of_unknown_length() {
        let stage = ChunkedEncoder::new(None);
        assert_eq!(stage.kind(), ClientReaderKind::ChunkedEncode);
        assert_eq!(stage.phase(), ClientReaderPhase::TransferEncode);
        assert_eq!(stage.name(), CHUNKED_CODING_NAME);
        // `cr_chunked_total_length` returns -1 whatever is below it, and a
        // stage with nothing below it is the strongest form of that claim.
        let empty: [Box<dyn ClientReader>; 0] = [];
        let mut stack = ClientReaderStack::new();
        assert!(stack.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(stage.total_length(&stack.query()), -1);
        let mut env = Env::new();
        stack.clear(&mut env.ctx());
    }

    /// A trailer write classifies as `CURLH_TRAILER`, which is 2.
    #[test]
    fn the_trailer_flags_classify_as_curlh_trailer() {
        assert_eq!(CURLH_TRAILER, 2);
        assert!(TRAILER_FLAGS.contains(ClientWriteFlags::HEADER));
        assert!(TRAILER_FLAGS.contains(ClientWriteFlags::TRAILER));
        // The function `hds_cw_collect_write` classifies with.
        assert_eq!(classify_origin(TRAILER_FLAGS.bits()), Some(CURLH_TRAILER));
        // And an ordinary header is a different origin, so the distinction is
        // not vacuous.
        assert_eq!(
            classify_origin(ClientWriteFlags::HEADER.bits()),
            Some(CURLH_HEADER)
        );
        assert_ne!(CURLH_TRAILER, CURLH_HEADER);
    }

    // -- decoding, the ordinary case --------------------------------------

    /// The canonical two-chunk message: every byte consumed, the body
    /// reassembled, the trailer section recognised as empty.
    #[test]
    fn a_two_chunk_message_decodes_to_its_body_and_consumes_all_of_itself() {
        let mut decoder = Decoder::new();
        let consumed = decoder.feed(WIKI).expect("a well formed message");
        assert_eq!(WIKI.len(), 24, "the fixture is 24 bytes");
        assert_eq!(consumed, 24, "the last line feed ends the response");
        assert_eq!(decoder.body(), b"Wikipedia");
        assert_eq!(decoder.state(), ChunkyState::Done);
        assert!(decoder.chunker.is_done());
        assert_eq!(decoder.chunker.last_code(), ChunkCode::Ok);
        // Two body writes, one per chunk, and no trailer write at all.
        assert_eq!(decoder.sink.writes.len(), 2);
        assert_eq!(decoder.sink.writes[0].bytes, b"Wiki");
        assert_eq!(decoder.sink.writes[1].bytes, b"pedia");
        assert_eq!(decoder.sink.writes[0].flags, ClientWriteFlags::BODY);
        assert!(decoder.sink.trailers().is_empty());
    }

    /// The same message split at every single point produces the same result.
    ///
    /// This is the property that makes the decoder safe on a real connection,
    /// where a chunk header, a chunk's data and the trailer section arrive in
    /// whatever pieces the network chose.
    #[test]
    fn every_split_point_produces_the_same_decode() {
        for at in 0..=WIKI.len() {
            let mut decoder = Decoder::new();
            let first = decoder
                .feed(&WIKI[..at])
                .unwrap_or_else(|error| panic!("split at {at}: {error:?}"));
            let second = decoder
                .feed(&WIKI[at..])
                .unwrap_or_else(|error| panic!("split at {at}: {error:?}"));
            assert_eq!(
                first + second,
                24,
                "split at {at} consumed the whole message"
            );
            assert_eq!(decoder.body(), b"Wikipedia", "split at {at}");
            assert_eq!(decoder.state(), ChunkyState::Done, "split at {at}");
        }
    }

    /// And one byte at a time -- the way `lib/cf-h1-proxy.c:486` feeds it.
    #[test]
    fn one_byte_at_a_time_produces_the_same_decode() {
        let mut decoder = Decoder::new();
        let consumed =
            decoder.feed_by_byte(WIKI).expect("a well formed message");
        assert_eq!(consumed, 24);
        assert_eq!(decoder.body(), b"Wikipedia");
        assert_eq!(decoder.state(), ChunkyState::Done);
        // Each chunk still arrives as ONE write per feed that carried data, so
        // a byte-at-a-time feed produces one write per byte of body.
        assert_eq!(decoder.sink.body(), b"Wikipedia");
        assert_eq!(decoder.sink.writes.len(), 9);
    }

    /// A three-way split across the header, the data and the terminator.
    #[test]
    fn a_partial_hex_token_survives_a_feed_boundary() {
        let mut decoder = Decoder::new();
        // The size is split down the middle: "1" then "0" makes 16, not 1.
        assert_eq!(decoder.feed(b"1").expect("a partial size"), 1);
        assert_eq!(decoder.state(), ChunkyState::Hex);
        assert_eq!(decoder.feed(b"0\x0d\x0a").expect("the rest"), 3);
        assert_eq!(decoder.state(), ChunkyState::Data);
        assert_eq!(decoder.chunker.datasize(), 16);
        let sixteen = b"0123456789abcdef";
        assert_eq!(decoder.feed(sixteen).expect("the data"), 16);
        assert_eq!(decoder.body(), sixteen);
        assert_eq!(
            decoder.feed(b"\x0d\x0a0\x0d\x0a\x0d\x0a").expect("the end"),
            7
        );
        assert_eq!(decoder.state(), ChunkyState::Done);
    }

    // -- decoding, the leniency ------------------------------------------

    /// Upper-case size digits are accepted, because `ISXDIGIT` accepts them.
    #[test]
    fn an_upper_case_size_is_accepted() {
        let mut decoder = Decoder::new();
        let message = b"A\x0d\x0a0123456789\x0d\x0a0\x0d\x0a\x0d\x0a";
        decoder.feed(message).expect("upper case hexadecimal");
        assert_eq!(decoder.body(), b"0123456789");
        assert_eq!(decoder.state(), ChunkyState::Done);
    }

    /// And mixed case, and leading zeros, all in one size.
    #[test]
    fn a_mixed_case_size_with_leading_zeros_is_accepted() {
        let mut decoder = Decoder::new();
        let message = b"00000000000000aB\x0d\x0a";
        decoder.feed(message).expect("sixteen digits");
        assert_eq!(decoder.chunker.datasize(), 0xab);
        assert_eq!(decoder.state(), ChunkyState::Data);
    }

    /// A chunk extension is skipped, token form.
    ///
    /// `CHUNK_LF`'s *"wait for LF, ignore all else"* is the whole mechanism.
    #[test]
    fn a_token_chunk_extension_is_skipped() {
        let mut decoder = Decoder::new();
        let message = b"4;name=value\x0d\x0aWiki\x0d\x0a0\x0d\x0a\x0d\x0a";
        let consumed = decoder.feed(message).expect("an extension");
        assert_eq!(consumed, message.len());
        assert_eq!(decoder.body(), b"Wiki");
        assert_eq!(decoder.state(), ChunkyState::Done);
    }

    /// A chunk extension is skipped, quoted-string form.
    #[test]
    fn a_quoted_chunk_extension_is_skipped() {
        let mut decoder = Decoder::new();
        // 4;name="va;lue\"quoted" -- semicolons, an escaped quote and blanks
        // are all just bytes to skip.
        let message =
            b"4;name=\"va;lue\\\"quoted\" \x0d\x0aWiki\x0d\x0a0\x0d\x0a\x0d\x0a";
        let consumed = decoder.feed(message).expect("a quoted extension");
        assert_eq!(consumed, message.len());
        assert_eq!(decoder.body(), b"Wiki");
        assert_eq!(decoder.state(), ChunkyState::Done);
    }

    /// A size line ending in a bare line feed is accepted.
    #[test]
    fn a_bare_line_feed_after_the_size_is_accepted() {
        let mut decoder = Decoder::new();
        let message = b"4\x0aWiki\x0a0\x0a\x0a";
        let consumed = decoder.feed(message).expect("bare line feeds");
        assert_eq!(consumed, message.len());
        assert_eq!(decoder.body(), b"Wiki");
        assert_eq!(decoder.state(), ChunkyState::Done);
    }

    /// The carriage return after a chunk's data is optional -- the C's *"A
    /// missing CR is no big deal"*.
    #[test]
    fn the_carriage_return_after_data_is_optional() {
        let mut decoder = Decoder::new();
        let message = b"4\x0d\x0aWiki\x0a0\x0d\x0a\x0d\x0a";
        let consumed = decoder.feed(message).expect("no CR after the data");
        assert_eq!(consumed, message.len());
        assert_eq!(decoder.body(), b"Wiki");
        assert_eq!(decoder.state(), ChunkyState::Done);
    }

    /// Anything but CR or LF after a chunk's data is malformed.
    #[test]
    fn a_stray_byte_after_data_is_a_malformed_chunk() {
        let mut decoder = Decoder::new();
        let error = decoder
            .feed(b"4\x0d\x0aWikiXY")
            .expect_err("X is not a chunk terminator");
        assert_eq!(error.code(), CURLcode::RecvError);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::BadChunk);
        assert_eq!(decoder.state(), ChunkyState::Failed);
        // The body written before the fault is not taken back.
        assert_eq!(decoder.body(), b"Wiki");
    }

    /// A trailer line that ends with a carriage return needs its line feed.
    #[test]
    fn a_trailer_carriage_return_without_a_line_feed_is_malformed() {
        let mut decoder = Decoder::new();
        let error = decoder
            .feed(b"0\x0d\x0aFoo: bar\x0dX")
            .expect_err("the CR must be followed by an LF");
        assert_eq!(error.code(), CURLcode::RecvError);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::BadChunk);
        assert_eq!(decoder.state(), ChunkyState::Failed);
    }

    /// The final line feed is required, and a byte in its place is malformed.
    #[test]
    fn a_byte_in_place_of_the_final_line_feed_is_malformed() {
        let mut decoder = Decoder::new();
        let error = decoder
            .feed(b"0\x0d\x0a\x0dX")
            .expect_err("the response must end with a line feed");
        assert_eq!(error.code(), CURLcode::RecvError);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::BadChunk);
        // The C's trace, with its own `0x%ux` spelling: `%u` renders the byte
        // in decimal and the `x` is a literal.
        assert!(
            Trace::saw(
                &decoder.env.trace.writes,
                "http_chunk error, expected 0x0a, seeing 0x88x"
            ),
            "traces: {:?}",
            decoder.env.trace.writes
        );
    }

    // -- decoding, the trailer section -----------------------------------

    /// One trailer: emitted once, with exactly CRLF appended, as a trailer.
    #[test]
    fn one_trailer_is_emitted_once_with_the_trailer_flags() {
        let mut decoder = Decoder::new();
        let message = b"0\x0d\x0aFoo: bar\x0d\x0a\x0d\x0a";
        let consumed = decoder.feed(message).expect("one trailer");
        assert_eq!(consumed, message.len());
        assert_eq!(decoder.state(), ChunkyState::Done);
        let trailers = decoder.sink.trailers();
        assert_eq!(trailers.len(), 1, "emitted exactly once");
        assert_eq!(trailers[0].bytes, b"Foo: bar\x0d\x0a");
        assert_eq!(trailers[0].flags, TRAILER_FLAGS);
        // The header store would file it under CURLH_TRAILER, not
        // CURLH_HEADER.
        assert_eq!(
            classify_origin(trailers[0].flags.bits()),
            Some(CURLH_TRAILER)
        );
        // And no body was produced by a message with no chunk data.
        assert!(decoder.body().is_empty());
    }

    /// Several trailers, in arrival order, each terminated once.
    #[test]
    fn several_trailers_keep_their_order_and_their_bytes() {
        let mut decoder = Decoder::new();
        let message =
            b"0\x0d\x0aFoo: bar\x0d\x0aBaz: QUX\x0d\x0aEmpty:\x0d\x0a\x0d\x0a";
        let consumed = decoder.feed(message).expect("three trailers");
        assert_eq!(consumed, message.len());
        assert_eq!(decoder.state(), ChunkyState::Done);
        let trailers = decoder.sink.trailers();
        assert_eq!(trailers.len(), 3);
        assert_eq!(trailers[0].bytes, b"Foo: bar\x0d\x0a");
        // Case is preserved: a trailer is the server's bytes.
        assert_eq!(trailers[1].bytes, b"Baz: QUX\x0d\x0a");
        // A value-less trailer is still a trailer -- nothing here validates
        // the field, and the decoder is not the place that would.
        assert_eq!(trailers[2].bytes, b"Empty:\x0d\x0a");
    }

    /// A trailer that ends with a bare line feed is normalised to CRLF.
    #[test]
    fn a_bare_line_feed_trailer_is_emitted_with_crlf() {
        let mut decoder = Decoder::new();
        let message = b"0\x0aFoo: bar\x0aBaz: qux\x0a\x0a";
        let consumed = decoder.feed(message).expect("bare line feeds");
        assert_eq!(consumed, message.len());
        assert_eq!(decoder.state(), ChunkyState::Done);
        let trailers = decoder.sink.trailers();
        assert_eq!(trailers.len(), 2);
        assert_eq!(trailers[0].bytes, b"Foo: bar\x0d\x0a");
        assert_eq!(trailers[1].bytes, b"Baz: qux\x0d\x0a");
    }

    /// No trailer at all: the final CRLF pair is recognised and nothing is
    /// emitted.
    #[test]
    fn an_absent_trailer_section_emits_nothing() {
        let mut decoder = Decoder::new();
        let consumed = decoder.feed(b"0\x0d\x0a\x0d\x0a").expect("no trailer");
        assert_eq!(consumed, 5);
        assert_eq!(decoder.state(), ChunkyState::Done);
        assert!(
            decoder.sink.writes.is_empty(),
            "a message with no data and no trailer writes nothing: {:?}",
            decoder.sink.writes
        );
    }

    /// A trailer split across feeds arrives whole and once.
    #[test]
    fn a_trailer_split_across_feeds_is_emitted_once() {
        let message = b"0\x0d\x0aFoo: bar\x0d\x0aBaz: qux\x0d\x0a\x0d\x0a";
        for at in 0..=message.len() {
            let mut decoder = Decoder::new();
            decoder.feed(&message[..at]).expect("the first half");
            decoder.feed(&message[at..]).expect("the second half");
            assert_eq!(decoder.state(), ChunkyState::Done, "split at {at}");
            let trailers = decoder.sink.trailers();
            assert_eq!(trailers.len(), 2, "split at {at}");
            assert_eq!(trailers[0].bytes, b"Foo: bar\x0d\x0a", "split at {at}");
            assert_eq!(trailers[1].bytes, b"Baz: qux\x0d\x0a", "split at {at}");
        }
    }

    /// And one byte at a time, which exercises every partial trailer line.
    #[test]
    fn a_trailer_survives_a_byte_at_a_time() {
        let mut decoder = Decoder::new();
        let message = b"4\x0d\x0aWiki\x0d\x0a0\x0d\x0aFoo: bar\x0d\x0a\x0d\x0a";
        let consumed = decoder.feed_by_byte(message).expect("a trailer");
        assert_eq!(consumed, message.len());
        assert_eq!(decoder.state(), ChunkyState::Done);
        assert_eq!(decoder.body(), b"Wiki");
        let trailers = decoder.sink.trailers();
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers[0].bytes, b"Foo: bar\x0d\x0a");
    }

    // -- decoding, leftovers and the terminal states ----------------------

    /// Bytes after the last chunk are left for the caller and reported.
    #[test]
    fn bytes_after_the_response_are_left_for_the_caller() {
        let mut decoder = Decoder::new();
        let mut message = WIKI.to_vec();
        message.extend_from_slice(b"HTTP/1.1 200 OK\x0d\x0a");
        let consumed = decoder.feed(&message).expect("a complete response");
        assert_eq!(consumed, WIKI.len(), "the next response is not consumed");
        assert_eq!(decoder.body(), b"Wikipedia");
        // `ch->datasize` carries the count of what was left, per the header's
        // note at `lib/http_chunks.h:58-60`.
        assert_eq!(decoder.chunker.datasize(), 17);
        assert_eq!(message.len() - consumed, 17);
    }

    /// A finished decoder consumes nothing and succeeds, however often it is
    /// fed.
    #[test]
    fn a_finished_decoder_consumes_nothing_and_succeeds() {
        let mut decoder = Decoder::new();
        decoder.feed(WIKI).expect("a complete response");
        assert!(decoder.chunker.is_done());
        let writes = decoder.sink.writes.len();
        for _ in 0..3 {
            assert_eq!(decoder.feed(b"more bytes").expect("done is done"), 0);
        }
        assert_eq!(decoder.state(), ChunkyState::Done);
        assert_eq!(
            decoder.sink.writes.len(),
            writes,
            "a finished decoder writes nothing"
        );
    }

    /// A failed decoder consumes nothing and keeps failing.
    #[test]
    fn a_failed_decoder_consumes_nothing_and_keeps_failing() {
        let mut decoder = Decoder::new();
        decoder
            .feed(b"Z")
            .expect_err("Z is not a hexadecimal digit");
        assert_eq!(decoder.state(), ChunkyState::Failed);
        assert!(!decoder.chunker.is_done(), "failed is not done");
        for _ in 0..3 {
            let error = decoder
                .feed(b"0\x0d\x0a\x0d\x0a")
                .expect_err("a broken stream cannot be resumed");
            assert_eq!(error.code(), CURLcode::RecvError);
        }
        // The last code from the ORIGINAL fault is still the one reported.
        assert_eq!(decoder.chunker.last_code(), ChunkCode::IllegalHex);
    }

    // -- decoding, the size boundaries ------------------------------------

    /// Sixteen digits are accepted; the seventeenth is not.
    #[test]
    fn sixteen_size_digits_fit_and_the_seventeenth_does_not() {
        // Sixteen digits, value 4.
        let mut decoder = Decoder::new();
        let sixteen = b"0000000000000004\x0d\x0aWiki\x0d\x0a0\x0d\x0a\x0d\x0a";
        decoder
            .feed(sixteen)
            .expect("sixteen digits are the maximum");
        assert_eq!(decoder.body(), b"Wiki");
        assert_eq!(decoder.state(), ChunkyState::Done);

        // Seventeen.
        let mut decoder = Decoder::new();
        let error = decoder
            .feed(b"00000000000000004\x0d\x0a")
            .expect_err("seventeen digits are too many");
        assert_eq!(error.code(), CURLcode::RecvError);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::TooLongHex);
        assert_eq!(decoder.state(), ChunkyState::Failed);
        assert!(
            Trace::saw(
                &decoder.env.trace.fails,
                "chunk hex-length longer than 16"
            ),
            "diagnostics: {:?}",
            decoder.env.trace.fails
        );
    }

    /// A size with no digit at all is illegal, and the byte is named.
    #[test]
    fn a_size_with_no_digit_is_illegal() {
        let mut decoder = Decoder::new();
        let error = decoder.feed(b"\x0d\x0a").expect_err("a CR is not a size");
        assert_eq!(error.code(), CURLcode::RecvError);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::IllegalHex);
        assert!(
            Trace::saw(
                &decoder.env.trace.fails,
                "chunk hex-length char not a hex digit: 0xd"
            ),
            "diagnostics: {:?}",
            decoder.env.trace.fails
        );
    }

    /// The largest size a `curl_off_t` holds is accepted; one more is not.
    #[test]
    fn a_size_above_the_curl_off_t_maximum_is_illegal() {
        // 0x7fffffffffffffff is i64::MAX exactly.
        let mut decoder = Decoder::new();
        decoder
            .feed(b"7fffffffffffffff\x0d\x0a")
            .expect("the maximum is representable");
        assert_eq!(decoder.chunker.datasize(), i64::MAX);
        assert_eq!(decoder.state(), ChunkyState::Data);

        // 0x8000000000000000 is one more, and does not fit.
        let mut decoder = Decoder::new();
        let error = decoder
            .feed(b"8000000000000000\x0d\x0a")
            .expect_err("one past the maximum");
        assert_eq!(error.code(), CURLcode::RecvError);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::IllegalHex);
        assert!(
            Trace::saw(
                &decoder.env.trace.fails,
                "invalid chunk size: '8000000000000000'"
            ),
            "diagnostics: {:?}",
            decoder.env.trace.fails
        );

        // And the all-ones size, which overflows on its first digit pair.
        let mut decoder = Decoder::new();
        decoder
            .feed(b"ffffffffffffffff\x0d\x0a")
            .expect_err("sixteen f digits do not fit either");
        assert_eq!(decoder.chunker.last_code(), ChunkCode::IllegalHex);
    }

    /// The size parser itself, at its edges.
    #[test]
    fn the_size_parser_matches_the_c_overflow_rule() {
        assert_eq!(parse_chunk_size(b"0"), Some(0));
        assert_eq!(parse_chunk_size(b"a"), Some(10));
        assert_eq!(parse_chunk_size(b"A"), Some(10));
        assert_eq!(parse_chunk_size(b"ff"), Some(255));
        assert_eq!(parse_chunk_size(b"0000000000000000"), Some(0));
        assert_eq!(parse_chunk_size(b"7fffffffffffffff"), Some(i64::MAX));
        assert_eq!(parse_chunk_size(b"8000000000000000"), None);
        assert_eq!(parse_chunk_size(b"ffffffffffffffff"), None);
        // A byte that is not a digit is refused rather than panicked on.
        assert_eq!(parse_chunk_size(b"1g"), None);
    }

    // -- decoding, the write paths ----------------------------------------

    /// A refused body write leaves the decoder failed with the downstream code.
    #[test]
    fn a_refused_body_write_is_a_passthrough_failure() {
        let mut decoder =
            Decoder::with_sink(Sink::refusing(0, CURLcode::WriteError));
        let error = decoder.feed(WIKI).expect_err("the sink refused");
        // The downstream code is returned UNCHANGED -- not remapped to
        // CURLE_RECV_ERROR.
        assert_eq!(error.code(), CURLcode::WriteError);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::PassthruError);
        assert_eq!(decoder.state(), ChunkyState::Failed);
    }

    /// A refused trailer write is a passthrough failure too.
    #[test]
    fn a_refused_trailer_write_is_a_passthrough_failure() {
        let mut decoder =
            Decoder::with_sink(Sink::refusing(0, CURLcode::AbortedByCallback));
        let error = decoder
            .feed(b"0\x0d\x0aFoo: bar\x0d\x0a\x0d\x0a")
            .expect_err("the sink refused the trailer");
        assert_eq!(error.code(), CURLcode::AbortedByCallback);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::PassthruError);
        assert_eq!(decoder.state(), ChunkyState::Failed);
    }

    /// `ignore_body`: framing and completion still happen, the body does not.
    #[test]
    fn an_ignored_body_is_parsed_but_never_written() {
        let mut decoder = Decoder::ignoring_body();
        let consumed = decoder.feed(WIKI).expect("framing is still parsed");
        assert_eq!(consumed, WIKI.len());
        assert_eq!(decoder.state(), ChunkyState::Done);
        assert!(decoder.chunker.ignore_body());
        assert!(
            decoder.sink.writes.is_empty(),
            "an ignored body writes nothing: {:?}",
            decoder.sink.writes
        );
    }

    /// `ignore_body` survives every chunk boundary, because the reset carries
    /// it.
    #[test]
    fn an_ignored_body_survives_the_chunk_reset() {
        let mut decoder = Decoder::ignoring_body();
        decoder
            .feed(b"4\x0d\x0aWiki\x0d\x0a")
            .expect("the first chunk");
        // The reset at the end of a chunk put the machine back at HEX with
        // `ignore_body` intact.
        assert_eq!(decoder.state(), ChunkyState::Hex);
        assert!(decoder.chunker.ignore_body());
        decoder.feed(b"5\x0d\x0apedia\x0d\x0a").expect("the second");
        assert!(decoder.sink.writes.is_empty());
    }

    /// `ignore_body` does NOT suppress trailers: only `http_te_skip` does.
    #[test]
    fn an_ignored_body_still_emits_trailers() {
        let mut decoder = Decoder::ignoring_body();
        decoder
            .feed(b"0\x0d\x0aFoo: bar\x0d\x0a\x0d\x0a")
            .expect("a trailer with the body ignored");
        let trailers = decoder.sink.trailers();
        assert_eq!(
            trailers.len(),
            1,
            "the C writes trailers whenever http_te_skip is unset"
        );
        assert_eq!(trailers[0].bytes, b"Foo: bar\x0d\x0a");
    }

    /// `http_te_skip`: the ENCODED bytes go to the client, once, and nothing
    /// else does.
    #[test]
    fn te_skip_forwards_the_encoded_bytes_and_nothing_else() {
        let mut decoder = Decoder::skipping();
        let consumed = decoder.feed(WIKI).expect("the framing is still parsed");
        assert_eq!(consumed, WIKI.len(), "completion is still detected");
        assert_eq!(decoder.state(), ChunkyState::Done);
        assert_eq!(decoder.sink.writes.len(), 1, "written once, not twice");
        assert_eq!(decoder.sink.writes[0].flags, ClientWriteFlags::BODY);
        assert_eq!(
            decoder.sink.writes[0].bytes, WIKI,
            "the client gets the encoded stream verbatim"
        );
        // And NOT the decoded body: the framing was delivered, so delivering
        // the payload as well would double the transfer.
        assert_ne!(decoder.sink.writes[0].bytes, b"Wikipedia");
    }

    /// `http_te_skip` withholds decoded trailers, per `:257`.
    #[test]
    fn te_skip_withholds_decoded_trailers() {
        let mut decoder = Decoder::skipping();
        let message = b"0\x0d\x0aFoo: bar\x0d\x0a\x0d\x0a";
        decoder.feed(message).expect("a trailer under te_skip");
        assert!(
            decoder.sink.trailers().is_empty(),
            "the encoded stream already carries the trailer"
        );
        assert_eq!(decoder.sink.writes.len(), 1);
        assert_eq!(decoder.sink.writes[0].bytes, message);
    }

    /// `http_te_skip` with the body ignored writes nothing at all.
    #[test]
    fn te_skip_with_an_ignored_body_writes_nothing() {
        let mut decoder = Decoder::skipping();
        decoder.chunker = Chunker::new(true);
        decoder.feed(WIKI).expect("framing only");
        assert_eq!(decoder.state(), ChunkyState::Done);
        assert!(decoder.sink.writes.is_empty());
    }

    /// Each feed forwards its own bytes once under `http_te_skip`.
    #[test]
    fn te_skip_forwards_each_feed_exactly_once() {
        let mut decoder = Decoder::skipping();
        decoder.feed(&WIKI[..9]).expect("the first feed");
        decoder.feed(&WIKI[9..]).expect("the second feed");
        assert_eq!(decoder.sink.writes.len(), 2);
        assert_eq!(decoder.sink.writes[0].bytes, &WIKI[..9]);
        assert_eq!(decoder.sink.writes[1].bytes, &WIKI[9..]);
    }

    // -- decoding, the trailer ceiling ------------------------------------

    /// A trailer line and its CRLF may reach the dynbuf's ceiling, and no
    /// further.
    ///
    /// `DynBuf`'s ceiling admits `toobig - 1` bytes, because the C counts the
    /// terminator it stores, so a 4096-byte ceiling holds 4095 bytes: a
    /// 4093-byte trailer plus CRLF exactly fills it.
    #[test]
    fn a_trailer_line_may_fill_the_ceiling_exactly() {
        let mut decoder = Decoder::new();
        let mut message = b"0\x0d\x0a".to_vec();
        message.extend(std::iter::repeat(b'a').take(DYN_H1_TRAILER - 3));
        message.extend_from_slice(b"\x0d\x0a\x0d\x0a");
        let consumed = decoder.feed(&message).expect("4093 bytes plus CRLF");
        assert_eq!(consumed, message.len());
        assert_eq!(decoder.state(), ChunkyState::Done);
        let trailers = decoder.sink.trailers();
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers[0].bytes.len(), DYN_H1_TRAILER - 1);
    }

    /// One byte more and the CRLF crosses the ceiling: `CURLE_TOO_LARGE`, and
    /// nothing is delivered.
    #[test]
    fn a_trailer_line_past_the_ceiling_is_too_large() {
        let mut decoder = Decoder::new();
        let mut message = b"0\x0d\x0a".to_vec();
        message.extend(std::iter::repeat(b'a').take(DYN_H1_TRAILER - 2));
        message.extend_from_slice(b"\x0d\x0a\x0d\x0a");
        let error = decoder.feed(&message).expect_err("4094 bytes plus CRLF");
        // The buffer's own code, not a framing fault: the wire was not at
        // fault.
        assert_eq!(error.code(), CURLcode::TooLarge);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::OutOfMemory);
        assert_eq!(decoder.state(), ChunkyState::Failed);
        assert!(
            decoder.sink.trailers().is_empty(),
            "no partial trailer is delivered"
        );
    }

    /// A trailer line longer than the ceiling fails while it accumulates.
    #[test]
    fn a_trailer_line_far_past_the_ceiling_is_too_large() {
        let mut decoder = Decoder::new();
        let mut message = b"0\x0d\x0a".to_vec();
        message.extend(std::iter::repeat(b'b').take(DYN_H1_TRAILER + 64));
        message.extend_from_slice(b"\x0d\x0a\x0d\x0a");
        let error = decoder.feed(&message).expect_err("past the ceiling");
        assert_eq!(error.code(), CURLcode::TooLarge);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::OutOfMemory);
        assert!(decoder.sink.trailers().is_empty());
    }

    /// Two trailers, each within the ceiling, both arrive: the ceiling is per
    /// LINE, and the buffer is reset between them.
    #[test]
    fn the_trailer_ceiling_is_per_line() {
        let mut decoder = Decoder::new();
        let long = std::iter::repeat(b'c')
            .take(DYN_H1_TRAILER - 3)
            .collect::<Vec<u8>>();
        let mut message = b"0\x0d\x0a".to_vec();
        message.extend_from_slice(&long);
        message.extend_from_slice(b"\x0d\x0a");
        message.extend_from_slice(&long);
        message.extend_from_slice(b"\x0d\x0a\x0d\x0a");
        decoder.feed(&message).expect("two full-length trailers");
        assert_eq!(decoder.state(), ChunkyState::Done);
        let trailers = decoder.sink.trailers();
        assert_eq!(trailers.len(), 2);
        assert_eq!(trailers[0].bytes.len(), DYN_H1_TRAILER - 1);
        assert_eq!(trailers[1].bytes.len(), DYN_H1_TRAILER - 1);
    }

    // -- the decode stage, in a real writer chain -------------------------

    /// The stage de-frames a body and the client sees the payload alone.
    #[test]
    fn the_stage_removes_the_framing_before_the_client_sees_the_body() {
        let factory = Factory::default();
        let mut env = Env::new();
        {
            let mut ctx = env.ctx();
            let mut stack = decode_stack(&factory, &mut ctx, false);
            assert!(
                receiving_chunks(&stack),
                "req.chunk is the presence of this stage"
            );
            stack
                .write(&mut ctx, ClientWriteFlags::BODY, WIKI)
                .expect("a complete chunked response");
            stack.clear(&mut ctx);
        }
        let log = factory.log.borrow();
        let body: Vec<u8> = log
            .iter()
            .filter(|write| write.flags.contains(ClientWriteFlags::BODY))
            .flat_map(|write| write.bytes.clone())
            .collect();
        assert_eq!(body, b"Wikipedia");
        // The download is complete, and `req.download_done` says so.
        assert!(env.write.download_done);
    }

    /// An empty chain has no chunked stage, so `req.chunk` is false.
    #[test]
    fn a_chain_without_the_stage_is_not_receiving_chunks() {
        let factory = Factory::default();
        let mut env = Env::new();
        let mut ctx = env.ctx();
        let mut stack = ClientWriterStack::new();
        stack.init_base(&mut ctx, &factory).expect("the base stack");
        assert!(!receiving_chunks(&stack));
        stack.clear(&mut ctx);
    }

    /// Trailers reach the client with their flags intact, through the whole
    /// chain.
    #[test]
    fn the_stage_forwards_trailers_with_their_flags_through_the_chain() {
        let factory = Factory::default();
        let mut env = Env::new();
        {
            let mut ctx = env.ctx();
            let mut stack = decode_stack(&factory, &mut ctx, false);
            stack
                .write(
                    &mut ctx,
                    ClientWriteFlags::BODY,
                    b"0\x0d\x0aFoo: bar\x0d\x0a\x0d\x0a",
                )
                .expect("a trailer");
            stack.clear(&mut ctx);
        }
        let log = factory.log.borrow();
        let trailers: Vec<&Written> = log
            .iter()
            .filter(|write| write.flags.contains(ClientWriteFlags::TRAILER))
            .collect();
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers[0].bytes, b"Foo: bar\x0d\x0a");
        assert_eq!(
            classify_origin(trailers[0].flags.bits()),
            Some(CURLH_TRAILER),
            "the header store files it as a trailer"
        );
    }

    /// A non-body write passes straight through, untouched.
    #[test]
    fn the_stage_passes_a_header_write_through() {
        let factory = Factory::default();
        let mut env = Env::new();
        {
            let mut ctx = env.ctx();
            let mut stack = decode_stack(&factory, &mut ctx, false);
            stack
                .write(
                    &mut ctx,
                    ClientWriteFlags::HEADER,
                    b"Server: test\x0d\x0a",
                )
                .expect("a header");
            stack.clear(&mut ctx);
        }
        let log = factory.log.borrow();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].bytes, b"Server: test\x0d\x0a");
        assert_eq!(log[0].flags, ClientWriteFlags::HEADER);
    }

    /// Leftovers are reported and are not part of the body.
    #[test]
    fn the_stage_reports_leftovers_after_the_last_chunk() {
        let factory = Factory::default();
        let mut env = Env::new();
        let mut message = WIKI.to_vec();
        message.extend_from_slice(b"HTTP/1.1 200 OK\x0d\x0a");
        {
            let mut ctx = env.ctx();
            let mut stack = decode_stack(&factory, &mut ctx, false);
            stack
                .write(&mut ctx, ClientWriteFlags::BODY, &message)
                .expect("a response with a second one behind it");
            stack.clear(&mut ctx);
        }
        assert!(env.write.download_done);
        assert!(
            Trace::saw(&env.trace.infos, "Leftovers after chunking: 17 bytes"),
            "informational messages: {:?}",
            env.trace.infos
        );
        let log = factory.log.borrow();
        let body: Vec<u8> = log
            .iter()
            .filter(|write| write.flags.contains(ClientWriteFlags::BODY))
            .flat_map(|write| write.bytes.clone())
            .collect();
        assert_eq!(body, b"Wikipedia", "the leftovers are not body bytes");
    }

    /// A stream that ends mid-response is a partial file.
    #[test]
    fn an_end_of_stream_before_the_last_chunk_is_a_partial_file() {
        let factory = Factory::default();
        let mut env = Env::new();
        let error = {
            let mut ctx = env.ctx();
            let mut stack = decode_stack(&factory, &mut ctx, false);
            let outcome = stack.write(
                &mut ctx,
                ClientWriteFlags::BODY.union(ClientWriteFlags::EOS),
                b"4\x0d\x0aWiki\x0d\x0a",
            );
            stack.clear(&mut ctx);
            outcome.expect_err("the response was truncated")
        };
        assert_eq!(error.code(), CURLcode::PartialFile);
        assert!(
            Trace::saw(
                &env.trace.fails,
                "transfer closed with outstanding read data remaining"
            ),
            "diagnostics: {:?}",
            env.trace.fails
        );
    }

    /// A bodyless response is exempt from that check.
    #[test]
    fn an_end_of_stream_on_a_bodyless_response_is_not_a_partial_file() {
        let factory = Factory::default();
        let mut env = Env::new();
        env.write.no_body = true;
        let mut ctx = env.ctx();
        let mut stack = decode_stack(&factory, &mut ctx, false);
        stack
            .write(
                &mut ctx,
                ClientWriteFlags::BODY.union(ClientWriteFlags::EOS),
                b"",
            )
            .expect("nothing was truncated because nothing was expected");
        stack.clear(&mut ctx);
    }

    /// A framing fault reaches the caller as the C's sentence.
    #[test]
    fn the_stage_names_a_framing_fault_in_the_c_s_words() {
        let factory = Factory::default();
        let mut env = Env::new();
        let error = {
            let mut ctx = env.ctx();
            let mut stack = decode_stack(&factory, &mut ctx, false);
            let outcome = stack.write(
                &mut ctx,
                ClientWriteFlags::BODY,
                b"4\x0d\x0aWikiXY",
            );
            stack.clear(&mut ctx);
            outcome.expect_err("X is not a chunk terminator")
        };
        assert_eq!(error.code(), CURLcode::RecvError);
        assert!(
            Trace::saw(
                &env.trace.fails,
                "Malformed encoding found in chunked-encoding"
            ),
            "diagnostics: {:?}",
            env.trace.fails
        );
    }

    /// A refused write downstream reaches the caller as the OTHER sentence.
    ///
    /// The client stage refuses, which is what a `CURL_WRITEFUNC_ERROR` from
    /// the application looks like from here.
    #[test]
    fn the_stage_names_a_passthrough_fault_in_the_c_s_words() {
        let factory = Factory::refusing(CURLcode::WriteError);
        let mut env = Env::new();
        let error = {
            let mut ctx = env.ctx();
            let mut stack = decode_stack(&factory, &mut ctx, false);
            let outcome = stack.write(&mut ctx, ClientWriteFlags::BODY, WIKI);
            stack.clear(&mut ctx);
            outcome.expect_err("the client refused the body")
        };
        // The client's own code, unchanged.
        assert_eq!(error.code(), CURLcode::WriteError);
        assert!(
            Trace::saw(
                &env.trace.fails,
                "Failed reading the chunked-encoded stream"
            ),
            "diagnostics: {:?}",
            env.trace.fails
        );
        // And NOT the framing sentence, which would blame the server.
        assert!(
            !Trace::saw(&env.trace.fails, "in chunked-encoding"),
            "diagnostics: {:?}",
            env.trace.fails
        );
    }

    /// The stage releases its buffer on close and emits nothing.
    #[test]
    fn closing_the_stage_emits_nothing() {
        let factory = Factory::default();
        let mut env = Env::new();
        {
            let mut ctx = env.ctx();
            let mut stack = decode_stack(&factory, &mut ctx, false);
            stack
                .write(
                    &mut ctx,
                    ClientWriteFlags::BODY,
                    b"4\x0d\x0aWiki\x0d\x0a",
                )
                .expect("one chunk");
            let before = factory.log.borrow().len();
            stack.clear(&mut ctx);
            assert_eq!(
                factory.log.borrow().len(),
                before,
                "a stage leaving the chain writes nothing"
            );
        }
        drop(env);
    }

    /// A decoded trailer is STORED as a trailer, through the real collector.
    ///
    /// Every other trailer test asserts the flags this module emits and then
    /// runs them through [`classify_origin`] directly. That proves the flags
    /// are right; it does not prove the composition is. This one closes the
    /// gap by installing `transfer/writeout.rs`'s own `hds-collect` stage --
    /// the successor of `lib/headers.c`'s `hds_cw_collect_write` -- beneath the
    /// decoder, feeding a chunked message with a trailer through the assembled
    /// chain, and reading the store afterwards. The stage sits in the protocol
    /// phase and the decoder in the transfer-decode phase, which is exactly
    /// why the collector sees a trailer the decoder produced.
    ///
    /// `CURLH_TRAILER` is 2 and `CURLH_HEADER` is 1, so the two assertions are
    /// not the same assertion twice: a trailer relabelled as an ordinary
    /// response header would still be stored, still be readable through
    /// `curl_easy_header`, and be wrong.
    #[test]
    fn a_decoded_trailer_reaches_the_header_store_as_a_trailer() {
        let factory = Factory::default();
        let mut store = HeaderStore::new();
        let mut env = Env::new();

        {
            let mut ctx = env.ctx();
            let mut stack = decode_stack(&factory, &mut ctx, false);
            install_header_collector(
                &mut stack,
                &mut ctx,
                &factory,
                Box::new(StoreHandle {
                    store: &mut store,
                    request: 0,
                }),
                true,
            )
            .expect("the header collector installs");
            assert!(
                stack.names().contains(&"hds-collect"),
                "the collector joined the chain"
            );

            stack
                .write(
                    &mut ctx,
                    ClientWriteFlags::BODY,
                    b"1\x0d\x0ax\x0d\x0a0\x0d\x0aChecksum: 1234\x0d\x0a\x0d\x0a",
                )
                .expect("the message decodes");
        }
        drop(env);

        let stored = store.as_slice();
        assert_eq!(stored.len(), 1, "one trailer in, one header stored");
        assert_eq!(stored[0].name(), b"Checksum");
        assert_eq!(stored[0].value(), b"1234");
        assert_eq!(
            stored[0].origin(),
            CURLH_TRAILER,
            "a trailer is stored with origin CURLH_TRAILER"
        );
        assert_ne!(
            stored[0].origin(),
            CURLH_HEADER,
            "and never as an ordinary response header"
        );
        assert_eq!(stored[0].request(), 0);
    }

    // -- encoding, the size line ------------------------------------------

    /// Every size the mission statement names, spelled as `%zx` spells it.
    ///
    /// Lower case, no leading zero, no field width, CRLF. Each of those is a
    /// separate way to get the bytes wrong, and the fixture corpus compares
    /// them as one string.
    #[test]
    fn a_size_line_is_lower_case_hexadecimal_with_no_leading_zeros() {
        let cases: [(usize, &[u8]); 8] = [
            (1, b"1\x0d\x0a"),
            (15, b"f\x0d\x0a"),
            (16, b"10\x0d\x0a"),
            (255, b"ff\x0d\x0a"),
            (256, b"100\x0d\x0a"),
            (1023, b"3ff\x0d\x0a"),
            (1024, b"400\x0d\x0a"),
            (65536, b"10000\x0d\x0a"),
        ];
        for (len, expected) in cases {
            let mut out = BytesMut::new();
            append_chunk_size(&mut out, len);
            assert_eq!(out.as_ref(), expected, "the size line for {len} bytes");
            // Belt and braces on the property that matters most: no
            // upper-case digit ever appears.
            assert!(
                out.iter().all(|byte| !byte.is_ascii_uppercase()),
                "the size line for {len} bytes is lower case"
            );
        }
    }

    /// The digits themselves, all sixteen of them, in one size.
    #[test]
    fn a_size_line_uses_every_lower_case_digit() {
        let mut out = BytesMut::new();
        append_chunk_size(&mut out, 0x1234_5678_9abc_def0);
        assert_eq!(out.as_ref(), b"123456789abcdef0\x0d\x0a");
    }

    // -- encoding, the framing --------------------------------------------

    /// One payload: size line, payload, CRLF, then the terminal block.
    #[test]
    fn a_single_payload_is_framed_and_terminated() {
        let mut encoder = Encoder::new(vec![SourceStep::Last(b"x".to_vec())]);
        let out = encoder.drain(2048).expect("one payload");
        assert_eq!(out, b"1\x0d\x0ax\x0d\x0a0\x0d\x0a\x0d\x0a");
    }

    /// A payload of exactly the minimum, and one a byte under it.
    #[test]
    fn payloads_around_the_minimum_are_framed_exactly() {
        for len in [CURL_CHUNKED_MINLEN - 1, CURL_CHUNKED_MINLEN] {
            let payload = vec![b'a'; len];
            let mut encoder =
                Encoder::new(vec![SourceStep::Last(payload.clone())]);
            let out = encoder.drain(2048).expect("a payload");
            let mut expected = BytesMut::new();
            append_chunk_size(&mut expected, len);
            expected.extend_from_slice(&payload);
            expected.extend_from_slice(CRLF);
            expected.extend_from_slice(LAST_CHUNK);
            assert_eq!(out, expected.as_ref(), "a payload of {len} bytes");
        }
    }

    /// Several payloads become several chunks, in order.
    #[test]
    fn several_payloads_become_several_chunks_in_order() {
        let mut encoder = Encoder::new(vec![
            SourceStep::Data(b"Wiki".to_vec()),
            SourceStep::Data(b"pedia".to_vec()),
            SourceStep::Last(b"!".to_vec()),
        ]);
        let out = encoder.drain(2048).expect("three payloads");
        assert_eq!(
            out,
            b"4\x0d\x0aWiki\x0d\x0a5\x0d\x0apedia\x0d\x0a1\x0d\x0a!\x0d\x0a0\x0d\x0a\x0d\x0a"
        );
    }

    /// An empty body is exactly the terminal block, and nothing else.
    #[test]
    fn an_empty_body_is_exactly_the_terminal_block() {
        let mut encoder = Encoder::new(vec![SourceStep::Eos]);
        let out = encoder.drain(2048).expect("an empty body");
        assert_eq!(out, b"0\x0d\x0a\x0d\x0a");
        assert_eq!(out.len(), 5);
        assert!(
            Trace::saw(
                &encoder.env.trace.reads,
                "http_chunk, added last, empty chunk"
            ),
            "traces: {:?}",
            encoder.env.trace.reads
        );
    }

    /// A source that hands over bytes AND ends the stream in one answer emits
    /// both the chunk and the terminal block.
    #[test]
    fn a_last_payload_and_the_terminal_block_arrive_together() {
        let mut encoder = Encoder::new(vec![SourceStep::Last(b"ab".to_vec())]);
        let mut buf = [0_u8; 64];
        let outcome = encoder.read(&mut buf).expect("one read");
        assert!(outcome.eos, "the queue drained in one read");
        assert_eq!(
            &buf[..outcome.bytes_read],
            b"2\x0d\x0aab\x0d\x0a0\x0d\x0a\x0d\x0a"
        );
    }

    /// The framed bytes are identical however small the destination is.
    #[test]
    fn a_partial_read_does_not_change_the_encoded_bytes() {
        let whole = {
            let mut encoder =
                Encoder::new(vec![SourceStep::Last(b"Wikipedia".to_vec())]);
            encoder.drain(2048).expect("in one piece")
        };
        assert_eq!(whole, b"9\x0d\x0aWikipedia\x0d\x0a0\x0d\x0a\x0d\x0a");
        for at_a_time in [1, 2, 3, 5, 7, 13] {
            let mut encoder =
                Encoder::new(vec![SourceStep::Last(b"Wikipedia".to_vec())]);
            let piecemeal = encoder
                .drain(at_a_time)
                .unwrap_or_else(|error| panic!("{at_a_time}: {error:?}"));
            assert_eq!(
                piecemeal, whole,
                "reading {at_a_time} bytes at a time changed the framing"
            );
        }
    }

    // -- encoding, the payload sizing rules -------------------------------

    /// A destination under the minimum makes the encoder read exactly the
    /// minimum.
    #[test]
    fn a_small_destination_still_asks_for_a_decent_payload() {
        let mut encoder = Encoder::new(vec![SourceStep::Last(b"x".to_vec())]);
        let mut buf = [0_u8; 40];
        encoder.read(&mut buf).expect("a small destination");
        assert_eq!(
            encoder.source.asked,
            vec![CURL_CHUNKED_MINLEN],
            "a 40-byte destination reads 1024 bytes into scratch"
        );
    }

    /// A destination at or above the minimum is used, less the framing
    /// allowance.
    #[test]
    fn a_large_destination_is_used_less_the_framing_allowance() {
        let mut encoder = Encoder::new(vec![SourceStep::Last(b"x".to_vec())]);
        let mut buf = [0_u8; CURL_CHUNKED_MINLEN];
        encoder
            .read(&mut buf)
            .expect("a destination at the minimum");
        assert_eq!(
            encoder.source.asked,
            vec![CURL_CHUNKED_MINLEN - CHUNK_FRAMING_ALLOWANCE],
            "1024 bytes of room leaves 1012 for the payload"
        );
    }

    /// The destination a real transfer offers -- `CURL_MAX_WRITE_SIZE`.
    #[test]
    fn the_transfer_s_own_buffer_size_deducts_the_allowance() {
        let mut encoder = Encoder::new(vec![SourceStep::Last(b"x".to_vec())]);
        let mut buf = vec![0_u8; CURL_MAX_WRITE_SIZE];
        encoder.read(&mut buf).expect("the transfer's buffer");
        assert_eq!(
            encoder.source.asked,
            vec![CURL_MAX_WRITE_SIZE - CHUNK_FRAMING_ALLOWANCE]
        );
    }

    /// A destination above the maximum is capped at the maximum first.
    #[test]
    fn an_oversized_destination_is_capped_at_the_maximum() {
        let mut encoder = Encoder::new(vec![SourceStep::Last(b"x".to_vec())]);
        let mut buf = vec![0_u8; 4 * CURL_CHUNKED_MAXLEN];
        encoder.read(&mut buf).expect("an oversized destination");
        assert_eq!(
            encoder.source.asked,
            vec![CURL_CHUNKED_MAXLEN - CHUNK_FRAMING_ALLOWANCE],
            "the cap is applied before the allowance is deducted"
        );
    }

    /// Sixty-four kibibytes of body, framed across the chunks it takes.
    #[test]
    fn sixty_four_kibibytes_of_body_are_framed_and_recoverable() {
        let first = CURL_CHUNKED_MAXLEN - CHUNK_FRAMING_ALLOWANCE;
        let rest = CURL_CHUNKED_MAXLEN - first;
        let mut body = vec![b'a'; first];
        body.extend(std::iter::repeat(b'b').take(rest));
        assert_eq!(body.len(), 64 * 1024);
        let mut encoder = Encoder::new(vec![
            SourceStep::Data(body[..first].to_vec()),
            SourceStep::Last(body[first..].to_vec()),
        ]);
        let out = encoder.drain(CURL_CHUNKED_MAXLEN).expect("64 KiB");
        // The first size line is 65524 = 0xfff4: lower case, no leading zero.
        assert!(out.starts_with(b"fff4\x0d\x0a"), "the first size line");
        assert!(out.ends_with(LAST_CHUNK), "the terminal block");
        // And it decodes back to exactly the body that went in.
        let mut decoder = Decoder::new();
        let consumed = decoder.feed(&out).expect("the framing round-trips");
        assert_eq!(consumed, out.len());
        assert_eq!(decoder.body(), body);
        assert_eq!(decoder.state(), ChunkyState::Done);
    }

    // -- encoding, pausing and the end of the stream ----------------------

    /// A paused source yields nothing, and NOT the end of the stream.
    #[test]
    fn a_paused_source_yields_nothing_and_no_end_of_stream() {
        let mut encoder = Encoder::new(vec![
            SourceStep::Paused,
            SourceStep::Last(b"x".to_vec()),
        ]);
        let mut buf = [0_u8; 64];
        let outcome = encoder.read(&mut buf).expect("a paused source");
        assert_eq!(outcome.bytes_read, 0);
        assert!(!outcome.eos, "a pause is not the end of the stream");
        assert_eq!(
            encoder.encoder.queued(),
            0,
            "no terminal block was manufactured for a paused source"
        );
        // And when the source comes back, the framing continues normally.
        let outcome = encoder.read(&mut buf).expect("the source resumed");
        assert!(outcome.eos);
        assert_eq!(
            &buf[..outcome.bytes_read],
            b"1\x0d\x0ax\x0d\x0a0\x0d\x0a\x0d\x0a"
        );
    }

    /// A source that pauses several times still produces one clean body.
    #[test]
    fn repeated_pauses_do_not_change_the_framing() {
        let mut encoder = Encoder::new(vec![
            SourceStep::Paused,
            SourceStep::Data(b"Wiki".to_vec()),
            SourceStep::Paused,
            SourceStep::Paused,
            SourceStep::Last(b"pedia".to_vec()),
        ]);
        let mut out = Vec::new();
        let mut buf = [0_u8; 2048];
        for _ in 0..16 {
            let outcome = encoder.read(&mut buf).expect("a read");
            out.extend_from_slice(&buf[..outcome.bytes_read]);
            if outcome.eos {
                break;
            }
        }
        assert_eq!(
            out,
            b"4\x0d\x0aWiki\x0d\x0a5\x0d\x0apedia\x0d\x0a0\x0d\x0a\x0d\x0a"
        );
    }

    /// The end of the stream is reported once, and the source is not consulted
    /// again.
    #[test]
    fn the_end_of_the_stream_is_reported_exactly_once() {
        let mut encoder = Encoder::new(vec![SourceStep::Last(b"x".to_vec())]);
        let mut buf = [0_u8; 64];
        let outcome = encoder.read(&mut buf).expect("the only payload");
        assert!(outcome.eos);
        let asked = encoder.source.asked.len();
        for _ in 0..3 {
            let again = encoder.read(&mut buf).expect("after the end");
            assert_eq!(again.bytes_read, 0);
            assert!(again.eos, "the end of the stream is sticky");
        }
        assert_eq!(
            encoder.source.asked.len(),
            asked,
            "an exhausted source is not consulted again"
        );
    }

    /// The end of the stream waits for the terminal block to drain.
    #[test]
    fn the_end_of_the_stream_waits_for_the_last_byte() {
        let mut encoder = Encoder::new(vec![SourceStep::Last(b"x".to_vec())]);
        // "1\r\nx\r\n0\r\n\r\n" is 11 bytes; read ten of them.
        let mut buf = [0_u8; 10];
        let outcome = encoder.read(&mut buf).expect("ten bytes");
        assert_eq!(outcome.bytes_read, 10);
        assert!(!outcome.eos, "one byte of the terminal block is still owed");
        let mut last = [0_u8; 10];
        let outcome = encoder.read(&mut last).expect("the last byte");
        assert_eq!(&last[..outcome.bytes_read], b"\x0a");
        assert!(outcome.eos);
    }

    /// A source failure is returned unchanged and nothing is queued.
    #[test]
    fn a_source_failure_is_returned_unchanged() {
        let mut encoder =
            Encoder::new(vec![SourceStep::Fail(CURLcode::ReadError)]);
        let mut buf = [0_u8; 64];
        let error = encoder.read(&mut buf).expect_err("the source refused");
        assert_eq!(error.code(), CURLcode::ReadError);
        assert_eq!(encoder.encoder.queued(), 0);
    }

    /// The C's per-chunk trace line, with its `-> %d` of the code.
    #[test]
    fn a_framed_chunk_is_traced_with_its_length() {
        let mut encoder =
            Encoder::new(vec![SourceStep::Last(b"Wikipedia".to_vec())]);
        encoder.drain(2048).expect("one payload");
        assert!(
            Trace::saw(
                &encoder.env.trace.reads,
                "http_chunk, made chunk of 9 bytes -> 0"
            ),
            "traces: {:?}",
            encoder.env.trace.reads
        );
    }

    // -- encoding, the trailer callback -----------------------------------

    /// Trailers from the callback, in order, between the last size line and
    /// the final blank line.
    #[test]
    fn trailers_from_the_callback_are_emitted_in_order() {
        let callback = Trailers::ok(&[b"Foo: bar", b"Baz: qux"]);
        let mut encoder = Encoder::with_trailers(
            vec![SourceStep::Last(b"x".to_vec())],
            callback.boxed(),
        );
        let out = encoder.drain(2048).expect("two trailers");
        assert_eq!(
            out,
            b"1\x0d\x0ax\x0d\x0a0\x0d\x0aFoo: bar\x0d\x0aBaz: qux\x0d\x0a\x0d\x0a"
        );
        assert_eq!(callback.calls.get(), 1, "invoked exactly once");
        // The guard was raised for the call and lowered again.
        assert_eq!(encoder.env.guard.entries(), 1);
        assert_eq!(encoder.env.guard.depth, 0, "the flag is balanced");
        assert!(Trace::saw(
            &encoder.env.trace.reads,
            "http_chunk, added last chunk with trailers from client -> 0"
        ));
    }

    /// The callback is not consulted until the source is exhausted.
    #[test]
    fn the_trailer_callback_is_not_consulted_before_the_end_of_the_source() {
        let callback = Trailers::ok(&[b"Foo: bar"]);
        let mut encoder = Encoder::with_trailers(
            vec![
                SourceStep::Data(b"one".to_vec()),
                SourceStep::Last(b"two".to_vec()),
            ],
            callback.boxed(),
        );
        let mut buf = [0_u8; 2048];
        encoder.read(&mut buf).expect("the first payload");
        assert_eq!(callback.calls.get(), 0, "the source has more to give");
        encoder.read(&mut buf).expect("the last payload");
        assert_eq!(callback.calls.get(), 1);
    }

    /// Every byte of an accepted trailer is emitted as the callback wrote it.
    #[test]
    fn an_accepted_trailer_is_emitted_verbatim() {
        // Mixed case, an inner colon, and two spaces after the separating one
        // -- all preserved, because a trailer is the application's bytes.
        let callback = Trailers::ok(&[b"X-Odd-NAME:  a:b  ", b"z: 1"]);
        let mut encoder =
            Encoder::with_trailers(vec![SourceStep::Eos], callback.boxed());
        let out = encoder.drain(2048).expect("odd but well formed trailers");
        assert_eq!(
            out,
            b"0\x0d\x0aX-Odd-NAME:  a:b  \x0d\x0az: 1\x0d\x0a\x0d\x0a"
        );
    }

    /// A malformed trailer is skipped and the rest are still emitted.
    #[test]
    fn a_malformed_trailer_is_skipped() {
        let callback = Trailers::ok(&[
            // No colon at all.
            b"no colon here",
            // A colon, but the next byte is not a space.
            b"Tight:value",
            // A colon, but a tab follows it.
            b"Tabbed:\tvalue",
            // A colon at the very end, with nothing after it.
            b"Trailing:",
            // Well formed, and therefore emitted.
            b"Good: yes",
        ]);
        let mut encoder =
            Encoder::with_trailers(vec![SourceStep::Eos], callback.boxed());
        let out = encoder.drain(2048).expect("four skipped, one emitted");
        assert_eq!(out, b"0\x0d\x0aGood: yes\x0d\x0a\x0d\x0a");
        let skipped = encoder
            .env
            .trace
            .infos
            .iter()
            .filter(|line| {
                line.contains("Malformatted trailing header, skipping trailer")
            })
            .count();
        assert_eq!(skipped, 4, "one message per skipped trailer");
    }

    /// A trailer whose only content is the separator is accepted when a space
    /// follows.
    #[test]
    fn the_acceptance_test_is_exactly_the_c_s() {
        assert!(well_formed_trailer(b": value"));
        assert!(well_formed_trailer(b"A: "));
        assert!(well_formed_trailer(b"A:  two spaces"));
        assert!(!well_formed_trailer(b""));
        assert!(!well_formed_trailer(b"A:"));
        assert!(!well_formed_trailer(b"A:x"));
        assert!(!well_formed_trailer(b"A:\tx"));
        assert!(!well_formed_trailer(b"no colon"));
        // The FIRST colon decides, as `strchr` does.
        assert!(!well_formed_trailer(b"A:x B: y"));
    }

    /// An aborting callback fails the transfer with the C's diagnostic.
    #[test]
    fn an_aborting_trailer_callback_fails_the_transfer() {
        let callback =
            Trailers::new(TrailerResult::abort(vec![b"Foo: bar".to_vec()]));
        let mut encoder = Encoder::with_trailers(
            vec![SourceStep::Last(b"x".to_vec())],
            callback.boxed(),
        );
        let mut buf = [0_u8; 2048];
        let error = encoder.read(&mut buf).expect_err("the callback aborted");
        assert_eq!(error.code(), CURLcode::AbortedByCallback);
        assert!(
            Trace::saw(
                &encoder.env.trace.fails,
                "operation aborted by trailing headers callback"
            ),
            "diagnostics: {:?}",
            encoder.env.trace.fails
        );
        // The guard was still balanced across the aborting call.
        assert_eq!(encoder.env.guard.entries(), 1);
        assert_eq!(encoder.env.guard.depth, 0);
    }

    /// Any code other than `CURL_TRAILERFUNC_OK` aborts, not only
    /// `CURL_TRAILERFUNC_ABORT`.
    #[test]
    fn every_non_ok_callback_code_aborts() {
        for code in [CURL_TRAILERFUNC_ABORT, -1, 2, 99] {
            let callback = Trailers::new(TrailerResult {
                code,
                trailers: Vec::new(),
            });
            let mut encoder =
                Encoder::with_trailers(vec![SourceStep::Eos], callback.boxed());
            let mut buf = [0_u8; 64];
            let error = encoder
                .read(&mut buf)
                .expect_err("every code but zero aborts");
            assert_eq!(
                error.code(),
                CURLcode::AbortedByCallback,
                "callback code {code}"
            );
            assert_eq!(
                encoder.encoder.queued(),
                0,
                "callback code {code} queued a partial block"
            );
        }
    }

    /// A trailer line past `DYN_H1_TRAILER` is too large, and nothing is
    /// emitted.
    #[test]
    fn a_callback_trailer_past_the_line_ceiling_is_too_large() {
        let mut entry = b"X: ".to_vec();
        entry.extend(std::iter::repeat(b'a').take(DYN_H1_TRAILER));
        let callback = Trailers::new(TrailerResult::ok(vec![entry]));
        let mut encoder =
            Encoder::with_trailers(vec![SourceStep::Eos], callback.boxed());
        let mut buf = [0_u8; 64];
        let error = encoder.read(&mut buf).expect_err("past the line ceiling");
        assert_eq!(error.code(), CURLcode::TooLarge);
        assert_eq!(
            encoder.encoder.queued(),
            0,
            "no part of a truncated terminal block is ever queued"
        );
    }

    /// A trailer line that exactly fills the line ceiling is emitted.
    #[test]
    fn a_callback_trailer_at_the_line_ceiling_is_emitted() {
        // The ceiling admits `DYN_H1_TRAILER - 1` bytes, and the line carries
        // its CRLF, so the entry may be three bytes short of the ceiling.
        let mut entry = b"X: ".to_vec();
        entry.extend(
            std::iter::repeat(b'a').take(DYN_H1_TRAILER - 3 - entry.len()),
        );
        assert_eq!(entry.len(), DYN_H1_TRAILER - 3);
        let callback = Trailers::new(TrailerResult::ok(vec![entry.clone()]));
        let mut encoder =
            Encoder::with_trailers(vec![SourceStep::Eos], callback.boxed());
        let out = encoder.drain(DYN_H1_TRAILER * 2).expect("at the ceiling");
        let mut expected = Vec::from(LAST_CHUNK_HEAD);
        expected.extend_from_slice(&entry);
        expected.extend_from_slice(CRLF);
        expected.extend_from_slice(CRLF);
        assert_eq!(out, expected);
    }

    /// A trailer block past `DYN_TRAILERS` is too large, and nothing is
    /// emitted.
    #[test]
    fn a_callback_trailer_block_past_the_aggregate_ceiling_is_too_large() {
        // Seventeen lines of 4002 bytes cross 65536; fifteen do not.
        let entry = {
            let mut entry = b"X: ".to_vec();
            entry.extend(std::iter::repeat(b'a').take(3997));
            entry
        };
        assert_eq!(entry.len(), 4000);

        let fits = Trailers::new(TrailerResult::ok(vec![entry.clone(); 15]));
        let mut encoder =
            Encoder::with_trailers(vec![SourceStep::Eos], fits.boxed());
        let out = encoder.drain(DYN_TRAILERS * 2).expect("fifteen fit");
        assert_eq!(out.len(), 3 + 15 * 4002 + 2);

        let over = Trailers::new(TrailerResult::ok(vec![entry; 17]));
        let mut encoder =
            Encoder::with_trailers(vec![SourceStep::Eos], over.boxed());
        let mut buf = vec![0_u8; DYN_TRAILERS * 2];
        let error = encoder
            .read(&mut buf)
            .expect_err("seventeen cross the aggregate ceiling");
        assert_eq!(error.code(), CURLcode::TooLarge);
        assert_eq!(
            encoder.encoder.queued(),
            0,
            "a partial trailer block is never queued"
        );
    }

    /// An encoder with no callback answers rather than aborting.
    ///
    /// `append_trailer_block` is only ever called behind a check that the
    /// callback exists, so its [`None`] arm is defensive. It is asserted
    /// because the arm makes a promise -- *"a future caller's mistake does not
    /// abort a transfer"* -- and a promise no test exercises is a promise that
    /// silently becomes a `panic!` when someone tidies the arm away. Nothing is
    /// queued either: an absent callback must not leave a stray `0\r\n` behind,
    /// which is the failure this would otherwise hide.
    #[test]
    fn an_absent_callback_leaves_the_trailer_block_untouched() {
        let mut env = Env::new();
        let mut ctx = env.ctx();
        let mut encoder = ChunkedEncoder::new(None);

        encoder
            .append_trailer_block(&mut ctx)
            .expect("the absent callback is answered, not aborted");

        assert_eq!(
            encoder.queued(),
            0,
            "no callback means no trailer block, not a truncated one"
        );
    }

    // -- the encode stage, in a real reader chain -------------------------

    /// `Curl_httpchunk_add_reader` in the arrangement a real upload produces.
    ///
    /// Every other encoder test drives [`ChunkedEncoder::read_framed`] through
    /// an in-memory [`ChunkSource`], because `ReaderTail::new` is private to
    /// `transfer/sendf.rs` and a test cannot fabricate a tail. That leaves the
    /// production wiring itself unasserted, so this test builds the real thing
    /// instead: `set_buf` installs the client-phase source the C's
    /// `Curl_creader_set_buf` installs, [`add_chunked_encoder`] adds this
    /// module's stage above it, and `client_read` -- the C's
    /// `Curl_client_read` -- drives the chain. It therefore covers the
    /// [`ClientReader`] implementation, the installer, and the [`ChunkSource`]
    /// implementation over a genuine `ReaderTail`, none of which the doubles
    /// reach.
    #[test]
    fn the_installer_frames_through_a_real_reader_chain() {
        const PAYLOAD: &[u8] = b"Wikipedia";

        let factory = Factory::default();
        let mut env = Env::new();
        let mut ctx = env.ctx();
        let mut io = ClientIo::new(&factory);

        io.set_buf(&mut ctx, PAYLOAD)
            .expect("the borrowed-buffer source installs");
        add_chunked_encoder(&mut io, &mut ctx, None)
            .expect("the chunked encoder installs");

        // The transfer-encoding stage sits ABOVE the client source, which is
        // what puts framing between the payload and the connection.
        assert_eq!(
            io.readers().names(),
            vec![CHUNKED_CODING_NAME, "cr-buf"],
            "the encoder belongs above the client source"
        );
        // `cr_chunked_total_length` returns -1, so the whole chain is
        // indeterminate however much the source below it knows.
        assert_eq!(
            io.readers().total_length(),
            -1,
            "a chain carrying the chunked stage has no known length"
        );

        // Two reads: the framed payload, then the terminal block. The source
        // reports its end only after a read that returns fewer bytes than
        // asked for, exactly as `cr_buf` does.
        let mut out = Vec::new();
        let mut buf = vec![0_u8; CURL_MAX_WRITE_SIZE];
        for _ in 0..8 {
            let outcome =
                io.client_read(&mut ctx, &mut buf).expect("the chain reads");
            out.extend_from_slice(&buf[..outcome.bytes_read]);
            if outcome.eos {
                break;
            }
        }

        assert_eq!(
            out,
            b"9\x0d\x0aWikipedia\x0d\x0a0\x0d\x0a\x0d\x0a".to_vec(),
            "the real chain frames the same bytes the doubles produce"
        );

        // `close` runs on the way out, and releases the queue.
        io.readers_mut().clear(&mut ctx);
        assert!(io.readers().is_empty(), "clearing closes every stage");
    }

    // -- round trips ------------------------------------------------------

    /// What the encoder frames, the decoder recovers -- at every read size and
    /// every feed size.
    #[test]
    fn the_encoder_and_the_decoder_agree_at_every_boundary() {
        let body: Vec<u8> = (0..=255_u8).cycle().take(3000).collect();
        for at_a_time in [1, 7, 64, 1024, 4096] {
            let mut encoder = Encoder::new(vec![
                SourceStep::Data(body[..1000].to_vec()),
                SourceStep::Data(body[1000..2000].to_vec()),
                SourceStep::Last(body[2000..].to_vec()),
            ]);
            let framed = encoder
                .drain(at_a_time)
                .unwrap_or_else(|error| panic!("{at_a_time}: {error:?}"));
            // Whole, and then a byte at a time.
            let mut decoder = Decoder::new();
            let consumed = decoder.feed(&framed).expect("the whole stream");
            assert_eq!(consumed, framed.len(), "read size {at_a_time}");
            assert_eq!(decoder.body(), body, "read size {at_a_time}");

            let mut decoder = Decoder::new();
            decoder.feed_by_byte(&framed).expect("a byte at a time");
            assert_eq!(decoder.body(), body, "read size {at_a_time}");
            assert_eq!(decoder.state(), ChunkyState::Done);
        }
    }

    /// A round trip with trailers, and with an extension added on the way in.
    #[test]
    fn a_round_trip_survives_trailers_and_an_extension() {
        let callback = Trailers::ok(&[b"Checksum: 1234", b"Note: done"]);
        let mut encoder = Encoder::with_trailers(
            vec![SourceStep::Last(b"Wikipedia".to_vec())],
            callback.boxed(),
        );
        let framed = encoder.drain(2048).expect("a body with trailers");
        assert_eq!(
            framed,
            b"9\x0d\x0aWikipedia\x0d\x0a0\x0d\x0aChecksum: 1234\x0d\x0aNote: done\x0d\x0a\x0d\x0a"
        );

        // A proxy or an intermediary may add an extension to the size line;
        // the decoder must skip it and recover the same body and trailers.
        let tail = b"0\x0d\x0aChecksum: 1234\x0d\x0aNote: done\x0d\x0a\x0d\x0a";
        assert!(framed.ends_with(tail), "the tail is the encoder's own");
        let mut altered = Vec::new();
        altered.extend_from_slice(b"9;fresh=\"yes\"\x0d\x0a");
        altered.extend_from_slice(b"Wikipedia\x0d\x0a");
        altered.extend_from_slice(tail);
        let mut decoder = Decoder::new();
        decoder
            .feed(&altered)
            .expect("an extension on the way back");
        assert_eq!(decoder.body(), b"Wikipedia");
        assert_eq!(decoder.state(), ChunkyState::Done);
        let trailers = decoder.sink.trailers();
        assert_eq!(trailers.len(), 2);
        assert_eq!(trailers[0].bytes, b"Checksum: 1234\x0d\x0a");
        assert_eq!(trailers[1].bytes, b"Note: done\x0d\x0a");
    }

    /// An empty body round-trips to an empty body.
    #[test]
    fn an_empty_body_round_trips() {
        let mut encoder = Encoder::new(vec![SourceStep::Eos]);
        let framed = encoder.drain(64).expect("an empty body");
        let mut decoder = Decoder::new();
        let consumed = decoder.feed(&framed).expect("the terminal block");
        assert_eq!(consumed, framed.len());
        assert!(decoder.body().is_empty());
        assert_eq!(decoder.state(), ChunkyState::Done);
    }

    /// A reset decoder starts again on the next response, keeping its
    /// configuration.
    #[test]
    fn a_reset_decoder_decodes_the_next_response() {
        let mut decoder = Decoder::new();
        decoder.feed(WIKI).expect("the first response");
        assert_eq!(decoder.state(), ChunkyState::Done);
        decoder.chunker.reset(false);
        assert_eq!(decoder.state(), ChunkyState::Hex);
        assert_eq!(decoder.chunker.last_code(), ChunkCode::Ok);
        let consumed = decoder.feed(WIKI).expect("the second response");
        assert_eq!(consumed, WIKI.len());
        assert_eq!(decoder.body(), b"WikipediaWikipedia");
    }

    /// Freeing the decoder's buffer leaves it usable, as `curlx_dyn_free`
    /// does.
    #[test]
    fn freeing_the_trailer_buffer_leaves_the_decoder_usable() {
        let mut decoder = Decoder::new();
        decoder
            .feed(b"0\x0d\x0aFoo: bar\x0d\x0a\x0d\x0a")
            .expect("a trailer");
        decoder.chunker.free();
        decoder.chunker.reset(false);
        decoder
            .feed(b"0\x0d\x0aBaz: qux\x0d\x0a\x0d\x0a")
            .expect("another trailer after the free");
        let trailers = decoder.sink.trailers();
        assert_eq!(trailers.len(), 2);
        assert_eq!(trailers[1].bytes, b"Baz: qux\x0d\x0a");
    }
}
