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
//! Content and transfer decoding, streamed through the writer chain.
//!
//! Supersedes `lib/content_encoding.c` and `lib/content_encoding.h`. Three
//! things live here and nothing else does: the registry of decoders this
//! build actually compiled, the `Accept-Encoding` token list that registry
//! produces, and the construction of the unencoding writer stack from a
//! `Content-Encoding` or `Transfer-Encoding` header value.
//!
//! The C's zlib, brotli and zstd calls become `flate2`, `brotli` and `zstd`
//! -- the versions the specification pins, with `flate2` on its pure-Rust
//! `rust_backend` so that no `libz-sys` enters the graph. Everything else is
//! transcribed: the registry ORDER, the token separator, the state machine of
//! the deflate decoder including its broken-server fallback, the deferred
//! failure for an unrecognised coding, and the exact point at which each of
//! the eight refusals in `Curl_build_unencoding_stack` happens.
//!
//! # Decoding is streamed, never accumulated
//!
//! Every decoder here decompresses into a fixed
//! [`DECOMPRESS_BUFFER_SIZE`]-byte window and forwards what it produced
//! IMMEDIATELY to the next stage of the chain, then reuses the window. No
//! stage holds a whole decompressed entity, so a highly compressible body
//! costs 16 KiB of resident buffer per stage rather than its expanded size,
//! and the expansion is bounded by the number of stages the
//! [`MAX_ENCODE_STACK`] check admits. That is the C's arrangement exactly, and
//! it is why none of the convenience helpers these crates offer -- the ones
//! that return a `Vec<u8>` or a `String` for a whole stream -- appears in this
//! file.
//!
//! Backpressure is therefore the downstream stage's to apply, and its answer
//! is passed back UNCHANGED: a refused or paused write stops the decode where
//! it stands and returns the code the next stage returned, never a codec
//! error of this module's own.
//!
//! # Where these stages sit, and why the order looks reversed
//!
//! [`ClientWriterStack::add`] inserts a stage FIRST WITHIN ITS PHASE
//! (`lib/sendf.c:464-469`), so of two decoders added at one phase the one
//! added LAST runs FIRST. That is not an accident to be corrected: a
//! `Content-Encoding: gzip, deflate` header names the codings in the order
//! they were APPLIED, so decoding has to undo them in reverse, and adding
//! them in list order produces exactly that.
//!
//! ```text
//!   Content-Encoding: gzip, deflate     added:    gzip, then deflate
//!   raw -> protocol -> cw-pause -> deflate -> gzip -> cw-out
//!                                  ^^^^^^^    ^^^^
//!                                  runs first, as it must
//! ```
//!
//! One coding is not at [`ClientWriterPhase::ContentDecode`]:
//! `"chunked"` is a TRANSFER coding, it belongs to
//! [`ClientWriterPhase::TransferDecode`], and its stage is supplied by
//! `transfer/chunked.rs` through [`transfer_unencoder`] rather than built
//! here. This module owns which codings exist and when they are installed;
//! that module owns chunk framing.
//!
//! # The `Accept-Encoding` contract this module hands forward
//!
//! [`content_encodings`] is the successor of `Curl_get_content_encodings`
//! (`lib/content_encoding.c:607-628`) and answers with the comma-and-space
//! joined names of the compiled decoders, `identity` excluded. With every
//! optional feature on that is exactly
//!
//! ```text
//! deflate, gzip, br, zstd
//! ```
//!
//! and a build with fewer features keeps the surviving names in that relative
//! order. `CURLOPT_ACCEPT_ENCODING` semantics are unchanged
//! (`lib/setopt.c:1954-1974`): a non-null EMPTY string means "everything this
//! build supports" and resolves to that list, a null pointer means send no
//! `Accept-Encoding` header at all and ignore any `Content-Encoding` that
//! comes back, and a caller-supplied non-empty value is stored verbatim by
//! the option layer.
//!
//! No request header is emitted here. `protocols/http1.rs` writes
//! `Accept-Encoding` with this exact value, in this exact order, as wire
//! bytes: it must not sort it, re-case it or normalise the separator, because
//! `tests/getpart.pm:351+` joins a fixture's expected request into ONE string
//! and compares it as one string.
//!
//! # Truthful advertisement
//!
//! [`DECODER_CAPABILITIES`] pairs each optional decoder with the
//! `curl --version` feature name and the `CURL_VERSION_*` bit it contributes,
//! and with whether this build genuinely compiled it. `crate::version` reads
//! those facts rather than keeping a second opinion, so a feature that is off
//! loses its name, its bit, its registry entry, its aliases and its
//! `Accept-Encoding` token together. That direction matters: the harness
//! decides which fixtures to run from the banner, so under-reporting costs a
//! skipped fixture while over-reporting turns a clean skip into a failure.
//!
//! # What this module may not name
//!
//! Not `protocols/http1.rs`: HTTP/1 assembly CONSUMES this module, and the
//! reverse would be a cycle. Not a TLS type either -- the connection filters
//! make TLS transparent, so a decoder sees plaintext either way. No clock is
//! read, no allocation is performed by hand, no C decompressor is bound, and
//! there is no `unsafe` block: the crate root's `#![deny(unsafe_code)]`
//! covers this file, and the two things the C did with raw memory here --
//! `zalloc_cb`/`zfree_cb` and a fixed `char buffer[]` inside the writer
//! allocation -- are a `Vec<u8>` owned by the stage and the codec crates' own
//! safe allocation.

// Named only by the three hand-written `Debug` implementations, whose types are
// feature-gated, and by the test module's `TraceSink`. The condition is
// therefore the union of those four, so that a build with no codec at all has
// no unused import.
#[cfg(any(feature = "gzip", feature = "brotli", feature = "zstd", test))]
use core::fmt;

#[cfg(feature = "brotli")]
use brotli::{
    BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc, HuffmanCode,
};
#[cfg(feature = "gzip")]
use flate2::{Crc, Decompress, FlushDecompress, Status};
#[cfg(feature = "zstd")]
use zstd::stream::raw::{
    Decoder as ZstdStream, InBuffer, Operation, OutBuffer,
};

use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::transfer::chunked::{transfer_unencoder, CHUNKED_CODING_NAME};
use crate::transfer::sendf::{
    ClientCtx, ClientIoFactory, ClientWriteFlags, ClientWriter,
    ClientWriterKind, ClientWriterPhase, ClientWriterStack, WriterTail,
};
use crate::util::dynbuf::DynBuf;
use crate::version::{
    CURL_VERSION_BROTLI, CURL_VERSION_LIBZ, CURL_VERSION_ZSTD,
};

// The constants, each spelled as `lib/content_encoding.c` spells it.

/// The one coding an `Accept-Encoding` list never advertises.
///
/// `CONTENT_ENCODING_DEFAULT` (`lib/content_encoding.c:53`). It is a real
/// decoder -- a pass-through one -- and it is excluded from the token list
/// because a server needs no permission to send a body unencoded.
pub(crate) const CONTENT_ENCODING_DEFAULT: &str = "identity";

/// The ceiling on chained decoding steps -- *"allow no more than 5 'chained'
/// compression steps"* (`lib/content_encoding.c:57-58`).
///
/// The check that reads it is `count + 1 >= MAX_ENCODE_STACK`
/// (`:750`), which admits FOUR decoders at one phase and refuses the fifth.
/// The off-by-one is the C's and is preserved deliberately; see
/// [`build_unencoding_stack`].
pub(crate) const MAX_ENCODE_STACK: usize = 5;

/// The output window each decoder decompresses into, in bytes.
///
/// `DECOMPRESS_BUFFER_SIZE` (`lib/content_encoding.c:61`). Fixed, per stage,
/// and reused for every iteration of every write -- which is what makes a
/// decompression bomb cost a bounded amount of memory instead of its expanded
/// size.
///
/// Declared under the same condition as the C's, which is
/// `#if defined(HAVE_LIBZ) || defined(HAVE_BROTLI) || defined(HAVE_ZSTD)`
/// (`:60-62`): the window belongs to the codec stages, and a build with none of
/// them has nothing to size.
#[cfg(any(feature = "gzip", feature = "brotli", feature = "zstd"))]
pub(crate) const DECOMPRESS_BUFFER_SIZE: usize = 16_384;

/// The ceiling `Curl_get_content_encodings` gives its dynbuf
/// (`lib/content_encoding.c:614`).
///
/// Far above the 22 bytes the full list occupies, so it never fires in
/// practice; it is preserved because the policy is the C's and because a
/// registry that grew past it should fail loudly rather than allocate without
/// bound.
const CONTENT_ENCODINGS_CEILING: usize = 255;

/// The separator between two names in an `Accept-Encoding` value: comma, then
/// one space (`lib/content_encoding.c:620`).
const ENCODING_SEPARATOR: &[u8] = b", ";

// The registry -- `general_unencoders[]` and `transfer_unencoders[]`

/// One row of a decoder registry.
///
/// The C's registries are arrays of `const struct Curl_cwtype *` whose
/// membership is decided by the preprocessor: `&deflate_encoding` and
/// `&gzip_encoding` appear only `#ifdef HAVE_LIBZ`, and so on
/// (`lib/content_encoding.c:586-599`). A Rust array cannot have its ELEMENTS
/// conditionally compiled -- an attribute on an array element is not stable
/// -- so the rows are all present and each carries the answer to *did this
/// build compile it*, which `cfg!` resolves at compile time exactly as the
/// `#ifdef` did.
///
/// Nothing reads a row whose [`Self::compiled`] is false:
/// [`general_unencoders`] and [`transfer_unencoders`] filter them out, and
/// those two are the only readers. So a disabled feature is as invisible to a
/// lookup, to the token list and to the version banner as a missing
/// `#ifdef` arm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Unencoder {
    /// Which decoder this row names. Its `name` and `alias` come from
    /// [`ClientWriterKind`], so the spellings the C keeps in
    /// `struct Curl_cwtype` have ONE definition in this tree.
    coding: ClientWriterKind,

    /// Whether this build compiled it -- the C's `#ifdef`.
    compiled: bool,
}

/// The general content decoders, in the C's registry order.
///
/// `general_unencoders[]` (`lib/content_encoding.c:585-599`). The order is
/// observable twice over: [`content_encodings`] walks it to build the
/// `Accept-Encoding` value, and [`find_unencoder`] walks it to resolve a
/// coding name, so it is transcribed rather than sorted.
const GENERAL_UNENCODERS: &[Unencoder] = &[
    Unencoder {
        coding: ClientWriterKind::Identity,
        compiled: true,
    },
    Unencoder {
        coding: ClientWriterKind::Deflate,
        compiled: cfg!(feature = "gzip"),
    },
    Unencoder {
        coding: ClientWriterKind::Gzip,
        compiled: cfg!(feature = "gzip"),
    },
    Unencoder {
        coding: ClientWriterKind::Brotli,
        compiled: cfg!(feature = "brotli"),
    },
    Unencoder {
        coding: ClientWriterKind::Zstd,
        compiled: cfg!(feature = "zstd"),
    },
];

/// The decoders that exist ONLY as transfer codings.
///
/// `transfer_unencoders[]` (`lib/content_encoding.c:601-605`), whose single
/// entry is `Curl_httpchunk_unencoder`. `"chunked"` is unconditional: a
/// caller cannot opt out of framing and still find the end of the response.
const TRANSFER_UNENCODERS: &[Unencoder] = &[Unencoder {
    coding: ClientWriterKind::ChunkedDecode,
    compiled: true,
}];

/// The general decoders this build compiled, in registry order.
#[allow(dead_code)] // consumer: protocols/http1.rs, version.rs
pub(crate) fn general_unencoders() -> impl Iterator<Item = ClientWriterKind> {
    GENERAL_UNENCODERS
        .iter()
        .filter_map(|row| row.compiled.then_some(row.coding))
}

/// The transfer-only decoders this build compiled, in registry order.
#[allow(dead_code)] // consumer: protocols/http1.rs
pub(crate) fn transfer_unencoders() -> impl Iterator<Item = ClientWriterKind> {
    TRANSFER_UNENCODERS
        .iter()
        .filter_map(|row| row.compiled.then_some(row.coding))
}

// The capability facts `crate::version` reads

/// One optional decoder, paired with what advertising it means.
///
/// The C decides all three of these with one `#ifdef` per codec: `libz`
/// appears in the `Features:` line and contributes `CURL_VERSION_LIBZ` only
/// `#ifdef HAVE_LIBZ` (`lib/version.c`), and the same macro admits
/// `&deflate_encoding` and `&gzip_encoding` to the registry
/// (`lib/content_encoding.c:588-591`). Keeping the two decisions in two places
/// is how a build comes to advertise a codec it cannot run, so both read the
/// SAME `cfg!` here.
///
/// # Why the direction matters
///
/// `tests/runtests.pl:640-730` parses the `Features:` line and gates 874 of
/// the 1,914 fixtures on what it finds. Under-reporting a capability makes a
/// fixture SKIP; over-reporting makes it RUN and FAIL. So the safe error is
/// always to claim less, and the only claim this table permits is one this
/// build genuinely compiled.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DecoderCapability {
    /// The name as it appears in the `Features:` line of `curl --version`.
    ///
    /// Casing is contractual: the harness matches `/libz/i` (`:673-674`), and
    /// `libz` stays `libz` even though the implementation is `flate2` -- the
    /// name is a protocol between the binary and the harness, not a statement
    /// about which library is linked.
    name: &'static str,

    /// The `CURL_VERSION_*` bit this capability contributes to
    /// `curl_version_info`.
    bitmask: i32,

    /// Whether this build compiled the decoder in -- the C's `#ifdef`.
    compiled: bool,

    /// The registry entry this capability speaks for.
    ///
    /// `libz` covers two codings, `deflate` and `gzip`; the row names `gzip`
    /// because that is the one with an alias and the one the feature name is
    /// historically attached to. The coupling test walks both.
    coding: ClientWriterKind,
}

impl DecoderCapability {
    /// The `Features:` line name.
    #[allow(dead_code)] // consumer: version.rs
    pub(crate) const fn name(&self) -> &'static str {
        self.name
    }

    /// The `CURL_VERSION_*` bit.
    #[allow(dead_code)] // consumer: version.rs, ffi/misc.rs
    pub(crate) const fn bitmask(&self) -> i32 {
        self.bitmask
    }

    /// Whether this build compiled the decoder in.
    #[allow(dead_code)] // consumer: version.rs
    pub(crate) const fn is_compiled(&self) -> bool {
        self.compiled
    }

    /// The coding this capability speaks for.
    #[allow(dead_code)] // consumer: version.rs
    pub(crate) const fn coding(&self) -> ClientWriterKind {
        self.coding
    }
}

/// Every optional decoder, with the name and bit advertising it implies.
///
/// The bits are IMPORTED from [`crate::version`] rather than restated, so the
/// integers a C program compares against have exactly one definition in this
/// tree. Their values are pinned by test: `1 << 3`, `1 << 23` and `1 << 26`.
///
/// `identity` has no row. It is not optional, it has no feature name and it
/// contributes no bit -- a build that could not deliver an unencoded body
/// would not be a build.
#[allow(dead_code)] // consumer: version.rs
pub(crate) const DECODER_CAPABILITIES: &[DecoderCapability] = &[
    DecoderCapability {
        name: "libz",
        bitmask: CURL_VERSION_LIBZ,
        compiled: cfg!(feature = "gzip"),
        coding: ClientWriterKind::Gzip,
    },
    DecoderCapability {
        name: "brotli",
        bitmask: CURL_VERSION_BROTLI,
        compiled: cfg!(feature = "brotli"),
        coding: ClientWriterKind::Brotli,
    },
    DecoderCapability {
        name: "zstd",
        bitmask: CURL_VERSION_ZSTD,
        compiled: cfg!(feature = "zstd"),
        coding: ClientWriterKind::Zstd,
    },
];

/// Whether this build can decode `Content-Encoding: deflate` and `gzip`.
///
/// The narrow, `const` capability question [`crate::version`] asks. It is a
/// compile-time answer and reads nothing from that module, so the coupling has
/// no run-time direction to be circular in: this module states what it
/// compiled, and `version.rs` conjoins that with whether a transfer can reach
/// it at all.
#[allow(dead_code)] // consumer: version.rs
pub(crate) const fn gzip_compiled() -> bool {
    cfg!(feature = "gzip")
}

/// Whether this build can decode `Content-Encoding: br`.
#[allow(dead_code)] // consumer: version.rs
pub(crate) const fn brotli_compiled() -> bool {
    cfg!(feature = "brotli")
}

/// Whether this build can decode `Content-Encoding: zstd`.
#[allow(dead_code)] // consumer: version.rs
pub(crate) const fn zstd_compiled() -> bool {
    cfg!(feature = "zstd")
}

/// The value `CURLOPT_ACCEPT_ENCODING` resolves an empty string to.
///
/// `Curl_get_content_encodings` (`lib/content_encoding.c:607-628`): the
/// comma-and-space joined canonical names of the compiled general decoders,
/// with `identity` excluded. With every optional feature on it is exactly
///
/// ```text
/// deflate, gzip, br, zstd
/// ```
///
/// and a reduced build keeps the surviving names in that same relative order,
/// because the walk follows [`GENERAL_UNENCODERS`] and that order is the C's.
///
/// # The bytes are the contract
///
/// `protocols/http1.rs` writes this value into the `Accept-Encoding` request
/// header verbatim. It must not sort the names, change their case, drop the
/// space after a comma or add one before it: `tests/getpart.pm:351+` joins a
/// fixture's expected request into ONE string and compares it as one string,
/// so a re-spelled separator fails a test that has nothing to do with
/// compression. Everything about the value is decided here, once.
///
/// # `CURLOPT_ACCEPT_ENCODING`, unchanged
///
/// The option layer's three cases (`lib/setopt.c:1954-1974`):
///
/// * a non-null EMPTY string means *everything this build supports* and is
///   replaced by this value;
/// * a null pointer means send no `Accept-Encoding` at all AND ignore any
///   `Content-Encoding` that comes back;
/// * any other value is stored exactly as the caller supplied it.
///
/// Only the first of the three reaches this function.
///
/// # Errors
///
/// The C answers `NULL` when its dynbuf refuses an append, and its caller maps
/// that to `CURLE_OUT_OF_MEMORY`. This answers the [`DynBuf`] code itself --
/// [`CURLcode::OutOfMemory`] for a refused allocation, or
/// [`CURLcode::TooLarge`] if the registry ever outgrew the C's 255-byte
/// ceiling -- which is strictly more information at the same call site, and
/// the option layer maps either to `CURLE_OUT_OF_MEMORY` exactly as the C
/// does. Neither is reachable today: the full list is 22 bytes.
#[allow(dead_code)] // consumer: easy/setopt.rs, protocols/http1.rs, version.rs
pub(crate) fn content_encodings() -> CodeResult<String> {
    // `:611-614`: the ceiling is the C's, and it is a real ceiling rather than
    // a hint -- crossing it empties the buffer and reports TooLarge instead of
    // growing without bound.
    let mut enc = DynBuf::new(CONTENT_ENCODINGS_CEILING);

    // `:616-624`. The C's loop stops at the first failure (`&& !result`),
    // which is what `?` does here.
    for coding in general_unencoders() {
        // `:618`: `if(!curl_strequal(ce->name, CONTENT_ENCODING_DEFAULT))`.
        // Case-insensitive in the C, so it is case-insensitive here, even
        // though both sides are compile-time literals.
        if coding.name().eq_ignore_ascii_case(CONTENT_ENCODING_DEFAULT) {
            continue;
        }
        // `:619-620`: the separator goes BEFORE a name and only when
        // something is already there, which is what leaves no leading and no
        // trailing separator.
        if !enc.is_empty() {
            enc.addn(ENCODING_SEPARATOR)?;
        }
        enc.add(coding.name())?;
    }

    // Every name in the registry is an ASCII literal in this tree, so the bytes
    // are valid UTF-8 by construction and this conversion is EXACT; the test
    // module asserts the ASCII property per token rather than trusting the
    // claim. Lossy rather than `expect`, because the eventual caller is
    // `curl_easy_setopt` across the C boundary: a panic there aborts the
    // application, and no condition in this function is worth that.
    Ok(String::from_utf8_lossy(&enc.take()).into_owned())
}

/// Whether `name` names this coding, by its canonical name or by its alias.
///
/// The C's test, twice over (`lib/content_encoding.c:679-681`):
///
/// ```text
/// (curl_strnequal(name, ce->name, len) && !ce->name[len]) ||
/// (ce->alias && curl_strnequal(name, ce->alias, len) && !ce->alias[len])
/// ```
///
/// `curl_strnequal` compares case-insensitively over at most `len` bytes and
/// the `!ce->name[len]` that follows it demands the registry name be EXACTLY
/// that long -- so a token is not a prefix match: `"gz"` does not select
/// `gzip`, and `"gzipp"` does not either. [`slice::eq_ignore_ascii_case`]
/// is that conjunction in one call, since it compares length before content.
///
/// Case folding is ASCII-only in both, which matters for a header value that
/// need not be UTF-8: a byte outside ASCII compares literally rather than
/// through any locale's notion of case.
fn coding_matches(coding: ClientWriterKind, name: &[u8]) -> bool {
    if name.eq_ignore_ascii_case(coding.name().as_bytes()) {
        return true;
    }
    // `ce->alias &&` -- only two codings have one: `gzip`'s `x-gzip` and
    // `identity`'s `none`.
    coding
        .alias()
        .is_some_and(|alias| name.eq_ignore_ascii_case(alias.as_bytes()))
}

/// The decoder a coding name selects, or [`None`] for a name this build does
/// not know.
///
/// `find_unencode_writer` (`lib/content_encoding.c:669-693`). The transfer-only
/// registry is consulted FIRST and only in the transfer phase, so `"chunked"`
/// resolves as a transfer coding and is unknown as a content coding -- which
/// is what makes `Content-Encoding: chunked` a deferred failure rather than a
/// framing instruction.
///
/// A decoder whose feature is off is not in either registry, so a build
/// without `gzip` answers [`None`] for `"gzip"`, `"x-gzip"` and `"deflate"`
/// and the caller installs the deferred error stage -- the same outcome the C
/// reaches when `HAVE_LIBZ` is undefined.
#[allow(dead_code)] // consumer: protocols/http1.rs, and build_unencoding_stack
pub(crate) fn find_unencoder(
    name: &[u8],
    phase: ClientWriterPhase,
) -> Option<ClientWriterKind> {
    // `:676-684`.
    if phase == ClientWriterPhase::TransferDecode {
        if let Some(coding) =
            transfer_unencoders().find(|coding| coding_matches(*coding, name))
        {
            return Some(coding);
        }
    }
    // `:686-691`: "look among the general decoders".
    general_unencoders().find(|coding| coding_matches(*coding, name))
}

// The rule every decoder shares

/// Whether a write passes STRAIGHT through, untouched by any decoder.
///
/// `if(!(type & CLIENTWRITE_BODY) || !nbytes)` -- the first statement of every
/// `do_write` in the C file (`lib/content_encoding.c:256`, `:316`, `:416`,
/// `:524` and `:647`), and the reason a decoder never has to think about
/// metadata.
///
/// Two distinct cases, both of which must forward rather than decode:
///
/// * **Not body.** A header, an informational line or a trailer is not part of
///   the compressed entity and reaches the client unchanged. A decoder that
///   fed a header to its codec would corrupt both.
/// * **Empty body.** There is nothing to decode, but the write still carries
///   flags that stages downstream act on -- `CLIENTWRITE_EOS` above all, which
///   is how the end of the download is announced.
fn passes_through(flags: ClientWriteFlags, buf: &[u8]) -> bool {
    !flags.contains(ClientWriteFlags::BODY) || buf.is_empty()
}

// The decoder stages
//
// EVERY stage below CARRIES the phase it was created at rather than fixing
// one, because `Curl_cwriter_create(&writer, data, cwt, phase)`
// (`lib/content_encoding.c:786`) is called with the phase the header being
// parsed implies -- `CURL_CW_TRANSFER_DECODE` for a `Transfer-Encoding` value
// and `CURL_CW_CONTENT_DECODE` for a `Content-Encoding` one -- and the same
// `struct Curl_cwtype` serves both. `Transfer-Encoding: gzip, chunked` is a
// real header that `CURLOPT_TRANSFER_ENCODING` asks for, and its `gzip` stage
// belongs to the transfer phase.
//
// The phase is observable in two ways, which is why it is not simplified
// away: it decides where [`ClientWriterStack::add`] inserts the stage, and it
// decides which stages `Curl_cwriter_count(data, phase)` counts for the
// [`MAX_ENCODE_STACK`] refusal. A stage that hard-coded
// [`ClientWriterPhase::ContentDecode`] would slip past that refusal when four
// codings arrived in a `Transfer-Encoding` header.
//
// `transfer/chunked.rs`'s stage is the one exception, and legitimately so:
// [`find_unencoder`] answers `"chunked"` only for the transfer phase, so that
// stage has exactly one phase it can be created at and fixes it.

// `identity_encoding` -- `lib/content_encoding.c:575-583`

/// The pass-through decoder, named `identity` with the alias `none`.
///
/// The C builds it out of `Curl_cwriter_def_init`,
/// `Curl_cwriter_def_write` and `Curl_cwriter_def_close`
/// (`lib/content_encoding.c:576-583`) -- three functions that do nothing but
/// forward. [`ClientWriter`]'s defaults ARE those three
/// (`lib/sendf.c:137-157`), so this stage overrides only its identity: no
/// `write` is declared here, which is the point rather than an omission.
///
/// It is always compiled. A response with no `Content-Encoding`, or one that
/// says `identity` or `none`, must be delivered whatever optional features a
/// build has, so this decoder has no `#[cfg]` and its row in
/// [`GENERAL_UNENCODERS`] is unconditionally `compiled`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct IdentityDecoder {
    /// The phase this INSTANCE was created at; see the section comment above.
    phase: ClientWriterPhase,
}

impl ClientWriter for IdentityDecoder {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::Identity
    }

    fn phase(&self) -> ClientWriterPhase {
        self.phase
    }
}

// `error_writer` -- the deferred failure (`lib/content_encoding.c:630-667`)

/// The sentence an unrecognised coding fails with (`:649`).
const UNRECOGNIZED_ENCODING: &str = "Unrecognized content encoding type";

/// The stage installed for a coding this build does not know: `"ce-error"`.
///
/// # Why the failure is deferred, and why that must not be "fixed"
///
/// [`build_unencoding_stack`] could refuse an unknown coding while it is
/// parsing the header. The C deliberately does not
/// (`lib/content_encoding.c:783-784`, *"Defer error at use"*): it installs this
/// stage instead and returns success, so the failure happens only if body bytes
/// actually arrive.
///
/// That difference is observable and it is the useful behaviour. A response
/// that names a coding curl cannot decode but carries NO body -- a `204`, a
/// `304`, a `HEAD` reply, a redirect with an empty entity -- completes
/// normally, headers and all, exactly as it would have without the header. Only
/// a body that would have to be decoded fails, and it fails with the code that
/// says why.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DeferredErrorDecoder {
    /// The phase this instance was created at.
    phase: ClientWriterPhase,
}

impl ClientWriter for DeferredErrorDecoder {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::ContentEncodingError
    }

    fn phase(&self) -> ClientWriterPhase {
        self.phase
    }

    /// `error_do_write` (`lib/content_encoding.c:639-651`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadContentEncoding`], on the first NONEMPTY body write and
    /// on no other write. Everything else -- headers, informational lines,
    /// trailers, and a zero-length body write with its `CLIENTWRITE_EOS` --
    /// passes downstream untouched.
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `:647-648`.
        if passes_through(flags, buf) {
            return tail.write(ctx, flags, buf);
        }
        // `:649-650`.
        Err(ctx.failf(
            CURLcode::BadContentEncoding,
            format_args!("{UNRECOGNIZED_ENCODING}"),
        ))
    }
}

// `zlib_writer` -- the deflate and gzip stages
// (`lib/content_encoding.c:64-349`)

/// The prefix both zlib diagnostics share (`:103` and `:106`).
#[cfg(feature = "gzip")]
const UNENCODING_PREFIX: &str = "Error while processing content unencoding: ";

/// What stands in for an absent `z->msg` (`:106-107`).
#[cfg(feature = "gzip")]
const UNENCODING_UNKNOWN: &str =
    "Unknown failure within decompression software.";

/// The two bytes a gzip member begins with -- RFC 1952 section 2.3.1.
#[cfg(feature = "gzip")]
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// The only compression method a gzip member may name: `CM = 8`, deflate.
#[cfg(feature = "gzip")]
const GZIP_DEFLATE_METHOD: u8 = 8;

/// `FHCRC`: a 16-bit CRC of the header follows the optional fields.
#[cfg(feature = "gzip")]
const GZIP_FHCRC: u8 = 1 << 1;

/// `FEXTRA`: a length-prefixed extra field follows the fixed header.
#[cfg(feature = "gzip")]
const GZIP_FEXTRA: u8 = 1 << 2;

/// `FNAME`: a zero-terminated original file name follows.
#[cfg(feature = "gzip")]
const GZIP_FNAME: u8 = 1 << 3;

/// `FCOMMENT`: a zero-terminated comment follows.
#[cfg(feature = "gzip")]
const GZIP_FCOMMENT: u8 = 1 << 4;

/// The three flag bits RFC 1952 reserves. Any of them set is an error, which
/// is the `if (state->flags & 0xe000)` of zlib's own header reader.
///
/// `FTEXT`, bit zero, is NOT here: it is advisory, and zlib ignores it exactly
/// as this does.
#[cfg(feature = "gzip")]
const GZIP_RESERVED_FLAGS: u8 = 0xE0;

/// The bytes of the fixed header after `CM` and `FLG`: `MTIME`, `XFL`, `OS`.
#[cfg(feature = "gzip")]
const GZIP_FIXED_TAIL: usize = 6;

/// The gzip trailer: a CRC-32 then an `ISIZE`, both little-endian.
#[cfg(feature = "gzip")]
const GZIP_TRAILER_LEN: usize = 8;

/// How many unknown trailer bytes the raw-deflate fallback tolerates.
///
/// `zp->trailerlen = 4; /* Tolerate up to 4 unknown trailer bytes. */`
/// (`lib/content_encoding.c:209`). A server that omitted the zlib header
/// usually appended the four-byte Adler-32 anyway, and curl accepts that
/// rather than failing a transfer over bytes it does not need.
#[cfg(feature = "gzip")]
const ZLIB_RAW_TRAILER_TOLERANCE: usize = 4;

/// `process_zlib_error`'s message (`lib/content_encoding.c:100-110`).
///
/// Two shapes, chosen by whether the codec supplied a reason:
///
/// ```text
/// Error while processing content unencoding: <reason>
/// Error while processing content unencoding: Unknown failure within \
///     decompression software.
/// ```
///
/// # Which one appears, in this build
///
/// `flate2`'s `rust_backend` supplies NO message: its `ErrorMessage::get()`
/// answers `None` unconditionally, so a corrupt deflate stream takes the
/// second shape. The first is reached by the transparent gzip wrapper, whose
/// faults this module detects itself and names with the same sentences zlib's
/// `inflate.c` uses -- see [`GzFault`] -- and it would also be reached by a
/// backend that did supply one. Both shapes are therefore live, and both are
/// asserted by test.
#[cfg(feature = "gzip")]
fn unencoding_message(msg: Option<&str>) -> String {
    match msg {
        Some(detail) => format!("{UNENCODING_PREFIX}{detail}"),
        None => format!("{UNENCODING_PREFIX}{UNENCODING_UNKNOWN}"),
    }
}

/// `process_zlib_error` (`lib/content_encoding.c:100-110`): report, and answer
/// [`CURLcode::BadContentEncoding`].
#[cfg(feature = "gzip")]
fn process_zlib_error(ctx: &mut ClientCtx<'_>, msg: Option<&str>) -> Error {
    ctx.failf(
        CURLcode::BadContentEncoding,
        format_args!("{}", unencoding_message(msg)),
    )
}

/// The zlib stage's initialisation state -- `zlibInitState` (`:70-76`).
#[cfg(feature = "gzip")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ZlibInit {
    /// `ZLIB_UNINIT`: no codec state. Reached again once a stream ends, which
    /// is what turns a later body write into [`CURLcode::WriteError`].
    Uninit,
    /// `ZLIB_INIT`: initialised, nothing decoded yet. The ONLY state the
    /// raw-deflate retry may fire from.
    Init,
    /// `ZLIB_INFLATING`: inflating has started, so the stream is committed.
    Inflating,
    /// `ZLIB_EXTERNAL_TRAILER`: consuming a trailer this stage counts itself,
    /// which happens only after the raw-deflate fallback.
    ExternalTrailer,
    /// `ZLIB_INIT_GZIP`: initialised in transparent gzip mode.
    InitGzip,
}

/// Which wrapper the transparent gzip stage settled on.
///
/// The C hands this decision to zlib by asking for `MAX_WBITS + 32`
/// (`lib/content_encoding.c:302`), documented as *"add 32 to windowBits to
/// enable zlib and gzip decoding with automatic header detection"*.
/// `flate2`'s pure-Rust backend has no such mode -- `Decompress::new_gzip` and
/// `new_with_window_bits` are `#[cfg(feature = "any_zlib")]`, and
/// `miniz_oxide` knows only `DataFormat::Zlib` and `DataFormat::Raw` and
/// ignores the window-bits argument entirely -- so the detection, the gzip
/// member header, its CRC-32 and its `ISIZE` are performed here, over a raw
/// inflate.
///
/// Reproducing the mode rather than approximating it is what keeps the stage's
/// observable behaviour the C's: a `Content-Encoding: gzip` body that is
/// actually zlib-wrapped still decodes, a bad CRC is still a data error, and
/// bytes after the member are still refused.
#[cfg(feature = "gzip")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Wrapper {
    /// Not applicable: this stage is the `deflate` decoder, which asks for a
    /// zlib header outright (`inflateInit`, `:243`).
    NotGzip,
    /// Fewer than two bytes have arrived, so the question is still open. zlib
    /// waits in exactly this way, with its 16-bit header word half filled.
    Undecided,
    /// A zlib-wrapped stream: `Decompress` validates the header and the
    /// Adler-32 and this module adds nothing.
    Zlib,
    /// A gzip member: the framing below is this module's to parse and check.
    Gzip,
    /// A gzip member whose trailer has been consumed and verified. Any further
    /// body byte is [`CURLcode::WriteError`], which is what
    /// `process_trailer`'s *"Issue an error if unexpected bytes follow"*
    /// (`:130-131`) answers.
    Ended,
}

/// How far a gzip member's framing has got.
#[cfg(feature = "gzip")]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
enum GzPhase {
    /// Inside the member header.
    #[default]
    Header,
    /// Inside the member's raw deflate stream.
    Deflate,
    /// Inside the eight-byte trailer.
    Trailer,
}

/// Which field of a gzip member header the next byte belongs to.
///
/// RFC 1952 section 2.3 fixes both the fixed head and the order of the
/// optional fields: `FEXTRA`, then `FNAME`, then `FCOMMENT`, then `FHCRC`.
#[cfg(feature = "gzip")]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
enum GzField {
    /// `ID1`, which must be `0x1f`.
    #[default]
    Magic1,
    /// `ID2`, which must be `0x8b`.
    Magic2,
    /// `CM`, which must be 8.
    Method,
    /// `FLG`, whose reserved bits must be clear.
    Flags,
    /// `MTIME`, `XFL` and `OS`: six bytes with no constraint.
    Fixed,
    /// `XLEN`: two little-endian bytes counting the extra field.
    ExtraLen,
    /// The extra field itself.
    Extra,
    /// `FNAME`, up to and including its terminating zero.
    Name,
    /// `FCOMMENT`, up to and including its terminating zero.
    Comment,
    /// `CRC16`: the low sixteen bits of a CRC-32 over every preceding header
    /// byte.
    Hcrc,
    /// The header is complete.
    Done,
}

/// A fault in the framing this module parses itself.
///
/// Every variant's message is the sentence zlib's `inflate.c` puts in
/// `strm->msg` for the same condition, so a `--trace` capture of a
/// broken gzip body reads as it did before the migration -- the C would have
/// printed zlib's string through `process_zlib_error`, and this prints the
/// same string through the same formatting.
#[cfg(feature = "gzip")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum GzFault {
    /// The magic did not match, or a zlib header failed its own check.
    Header,
    /// `CM` was not 8.
    Method,
    /// A reserved `FLG` bit was set.
    Flags,
    /// `FHCRC` was set and the stored CRC-16 disagreed.
    HeaderCrc,
    /// The trailer's CRC-32 disagreed with the decompressed bytes.
    DataCheck,
    /// The trailer's `ISIZE` disagreed with the decompressed length.
    LengthCheck,
}

#[cfg(feature = "gzip")]
impl GzFault {
    /// The sentence zlib would have left in `strm->msg`.
    const fn message(self) -> &'static str {
        match self {
            Self::Header => "incorrect header check",
            Self::Method => "unknown compression method",
            Self::Flags => "unknown header flags set",
            Self::HeaderCrc => "header crc mismatch",
            Self::DataCheck => "incorrect data check",
            Self::LengthCheck => "incorrect length check",
        }
    }
}

/// The framing state of one gzip member.
///
/// Bounded by construction: the header is parsed byte by byte and nothing but
/// the two-byte counters and the eight-byte trailer is retained, so a member
/// carrying a megabyte of `FEXTRA` or a long `FNAME` costs no memory at all.
#[cfg(feature = "gzip")]
#[derive(Debug, Default)]
struct GzipFraming {
    /// Header, deflate stream, or trailer.
    phase: GzPhase,

    /// Which header field the next byte belongs to.
    field: GzField,

    /// `FLG`, once read: it decides which optional fields follow.
    flags: u8,

    /// How many bytes of the current fixed-size run are still to come.
    pending: usize,

    /// `XLEN`, accumulated little-endian.
    extra: usize,

    /// A CRC-32 over the header bytes that precede `CRC16`, for `FHCRC`.
    header_crc: Crc,

    /// The stored `CRC16`, accumulated little-endian.
    header_crc_seen: u32,

    /// A CRC-32 over the decompressed bytes, and -- through
    /// [`Crc::amount`] -- their count modulo 2^32, which is exactly what
    /// `ISIZE` states.
    body_crc: Crc,

    /// The trailer, as far as it has arrived.
    trailer: [u8; GZIP_TRAILER_LEN],

    /// How much of [`Self::trailer`] is filled.
    trailer_len: usize,
}

/// One `inflate_stream` call's outcome.
///
/// The C needs neither field: `z->next_in` carries the cursor and zlib itself
/// consumes the gzip trailer, so its `inflate_stream` returns only a
/// `CURLcode`. Both are needed here because the gzip framing is this module's,
/// and it has to know where the deflate stream stopped and whether it ended.
#[cfg(feature = "gzip")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct InflateStop {
    /// How many input bytes the codec consumed.
    consumed: usize,

    /// Whether the deflate stream reached its end.
    ended: bool,
}

/// The `deflate` and `gzip` stages -- `struct zlib_writer` (`:78-85`) with
/// `deflate_encoding` (`:279-286`) and `gzip_encoding` (`:340-347`).
///
/// One type for both codings, exactly as in the C, because the loop that does
/// the work is shared and only the initial wrapper differs:
///
/// | coding | C initialisation | here |
/// |---|---|---|
/// | `deflate` | `inflateInit(z)` (`:243`) | `Decompress::new(true)`, with the fallback below |
/// | `gzip` | `inflateInit2(z, MAX_WBITS + 32)` (`:302`) | detection, then `Decompress::new(true)` or a raw stream plus [`GzipFraming`] |
///
/// # The broken-server fallback, preserved
///
/// *"some servers seem to not generate zlib headers, so this is an attempt to
/// fix and continue anyway"* (`:202-203`). If the FIRST inflate of a
/// `deflate` body reports a data error and nothing has been decoded yet --
/// state still [`ZlibInit::Init`] -- the stream is reset to RAW deflate, the
/// same unconsumed input is replayed from its start, and decoding continues,
/// tolerating up to [`ZLIB_RAW_TRAILER_TOLERANCE`] unknown trailer bytes
/// afterwards.
///
/// The retry can fire only once, and only before any byte has been decoded or
/// any input has been seen: `:226-227` moves the state on at the end of every
/// call that had input, *"If we are in a state that would wrongly allow restart
/// in raw mode at the next call, assume output has already started"*. So a
/// stream that fails halfway through is a failure, not a second guess.
#[cfg(feature = "gzip")]
struct ZlibDecoder {
    /// Which of the two codings this stage is.
    coding: ZlibCoding,

    /// The phase this instance was created at.
    phase: ClientWriterPhase,

    /// `zp->zlib_init`.
    zlib_init: ZlibInit,

    /// `z_stream z`. [`None`] means there is no codec state: either it has
    /// been released, or -- for `gzip` alone -- the wrapper is still
    /// undecided, so which stream to create is not yet known.
    stream: Option<Decompress>,

    /// `zp->trailerlen`.
    trailerlen: usize,

    /// `char buffer[DECOMPRESS_BUFFER_SIZE]`: the output window, owned by the
    /// stage, allocated once and reused for every iteration of every write.
    buffer: Vec<u8>,

    /// Which wrapper this stage is decoding, for `gzip`.
    wrapper: Wrapper,

    /// The first byte of the stream, held back while the wrapper is undecided.
    held: Option<u8>,

    /// The gzip member's framing, for `gzip` in [`Wrapper::Gzip`] mode.
    gz: GzipFraming,
}

/// Which of the two zlib-backed codings a stage is.
///
/// Two variants rather than a [`ClientWriterKind`] field, so that every match
/// over it is exhaustive: a third coding would be a compile error here instead
/// of a silent fall into the wildcard arm that a fifteen-variant enumeration
/// would need.
#[cfg(feature = "gzip")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum ZlibCoding {
    /// `deflate_encoding` (`lib/content_encoding.c:279-286`).
    Deflate,
    /// `gzip_encoding` (`:340-347`).
    Gzip,
}

#[cfg(feature = "gzip")]
impl ZlibCoding {
    /// The registry identity, and therefore the name and alias.
    const fn kind(self) -> ClientWriterKind {
        match self {
            Self::Deflate => ClientWriterKind::Deflate,
            Self::Gzip => ClientWriterKind::Gzip,
        }
    }
}

#[cfg(feature = "gzip")]
impl fmt::Debug for ZlibDecoder {
    /// Written out rather than derived, and the reason is the window: a derived
    /// `Debug` renders `buffer` element by element, which is 16,384 zeroes and
    /// close to 50 KB of text for ONE stage. `ClientWriterStack` derives its
    /// own `Debug` and holds every stage, so a single `{:?}` of a chain would
    /// carry that four times over. The state that matters is small and is what
    /// appears here; the two other codec stages summarise for the same reason.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZlibDecoder")
            .field("coding", &self.coding)
            .field("phase", &self.phase)
            .field("state", &self.zlib_init)
            .field("open", &self.stream.is_some())
            .field("wrapper", &self.wrapper)
            .field("trailerlen", &self.trailerlen)
            .field("held", &self.held.is_some())
            .field("gz", &self.gz)
            .field("window", &self.buffer.len())
            .finish()
    }
}

#[cfg(feature = "gzip")]
impl ZlibDecoder {
    /// The `deflate` stage: a zlib-wrapped stream, with the raw fallback.
    fn deflate(phase: ClientWriterPhase) -> Self {
        Self::new(ZlibCoding::Deflate, phase, Wrapper::NotGzip)
    }

    /// The `gzip` stage: transparent gzip or zlib, decided from the first two
    /// bytes.
    fn gzip(phase: ClientWriterPhase) -> Self {
        Self::new(ZlibCoding::Gzip, phase, Wrapper::Undecided)
    }

    fn new(
        coding: ZlibCoding,
        phase: ClientWriterPhase,
        wrapper: Wrapper,
    ) -> Self {
        Self {
            coding,
            phase,
            zlib_init: ZlibInit::Uninit,
            stream: None,
            trailerlen: 0,
            // The C's buffer is a member of the writer allocation, so it
            // exists from creation and is never resized. This is the same
            // arrangement: one allocation of exactly the window, owned by the
            // stage, reused until the stage is dropped.
            buffer: vec![0; DECOMPRESS_BUFFER_SIZE],
            wrapper,
            held: None,
            gz: GzipFraming::default(),
        }
    }

    /// `exit_zlib` (`:112-122`).
    ///
    /// The C calls `inflateEnd` and, if THAT fails while the result was still
    /// `CURLE_OK`, replaces the result with a zlib error. Dropping a
    /// [`Decompress`] cannot fail, so the second half has no reachable
    /// counterpart and the caller's result always survives -- which is why this
    /// returns nothing and every caller keeps the code it already had.
    fn exit_zlib(&mut self) {
        if self.zlib_init != ZlibInit::Uninit {
            self.stream = None;
            self.zlib_init = ZlibInit::Uninit;
        }
    }

    /// `process_trailer` (`:124-145`), over the bytes still unconsumed.
    ///
    /// *"Consume expected trailer bytes. Terminate stream if exhausted. Issue
    /// an error if unexpected bytes follow."*
    ///
    /// # Errors
    ///
    /// [`CURLcode::WriteError`] when bytes remain after the tolerated trailer
    /// -- the code the C returns at `:137`, and deliberately NOT
    /// [`CURLcode::BadContentEncoding`]: the stream itself was well formed and
    /// what followed it was not part of it. No diagnostic accompanies it,
    /// because the C emits none.
    fn process_trailer(&mut self, available: usize) -> CurlResult<()> {
        // `:128`.
        let len = available.min(self.trailerlen);

        // `:133-135`.
        self.trailerlen -= len;
        let leftover = available - len;

        // `:136-137`.
        let result: CurlResult<()> = if leftover == 0 {
            Ok(())
        } else {
            Err(Error::new(CURLcode::WriteError))
        };

        // `:138-143`.
        if result.is_err() || self.trailerlen == 0 {
            self.exit_zlib();
        } else {
            // "Only occurs for gzip with zlib < 1.2.0.4 or raw deflate."
            self.zlib_init = ZlibInit::ExternalTrailer;
        }
        result
    }

    /// `inflateReset2(z, -MAX_WBITS)` (`:205`).
    ///
    /// `flate2` takes the same decision as a boolean and cannot fail, so the
    /// C's `else` arm -- where the reset itself errors, `inflateEnd` has
    /// already run, and the state is forced to `ZLIB_UNINIT` (`:213`) -- has no
    /// reachable counterpart here.
    fn reset_raw(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            stream.reset(false);
        }
    }
}

#[cfg(feature = "gzip")]
impl ZlibDecoder {
    /// `inflate_stream` (`lib/content_encoding.c:147-230`): decompress what is
    /// there, forwarding each windowful as it is produced.
    ///
    /// # The loop, and why it iterates
    ///
    /// *"because the buffer size is fixed, iteratively decompress and transfer
    /// to the client via next_write function"* (`:164-165`). Every iteration
    /// resets the window, inflates once, forwards whatever came out, and then
    /// decides from the codec's answer whether to go round again:
    ///
    /// | answer | C | here |
    /// |---|---|---|
    /// | `Z_OK` | *"Always loop: there may be unflushed latched data"* (`:191-194`) | [`Status::Ok`], loop |
    /// | `Z_BUF_ERROR` | *"No more data to flush: just exit loop"* (`:195-197`) | [`Status::BufError`], stop |
    /// | `Z_STREAM_END` | `process_trailer` (`:198-200`) | [`Status::StreamEnd`] |
    /// | `Z_DATA_ERROR` | retry raw, once (`:201-216`) | `Err`, see below |
    ///
    /// The C passes `Z_BLOCK` and this passes [`FlushDecompress::None`],
    /// because `miniz_oxide` has no `Z_BLOCK`. `Z_BLOCK` asks inflate to stop
    /// at the next deflate block boundary, which changes only how often it
    /// returns -- not a single decompressed byte, and not the terminating
    /// condition, since both modes answer `Z_BUF_ERROR` once no progress is
    /// possible. The loop's exit is therefore reached by the same route.
    ///
    /// # Errors
    ///
    /// * A downstream refusal, UNCHANGED. The stage releases its codec state
    ///   and returns the code the next stage returned (`:180-185`), so a paused
    ///   client or a `CURL_WRITEFUNC_ERROR` is not reported as a codec fault.
    /// * [`CURLcode::BadContentEncoding`] for a malformed stream, through
    ///   [`process_zlib_error`].
    /// * [`CURLcode::WriteError`] when called in a state that has no stream
    ///   (`:158-162`), or when bytes follow a completed one
    ///   ([`Self::process_trailer`]).
    fn inflate_stream(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        input: &[u8],
        started: ZlibInit,
    ) -> CurlResult<InflateStop> {
        // `:158-162`. The three states that have a stream to inflate with.
        if !matches!(
            self.zlib_init,
            ZlibInit::Init | ZlibInit::Inflating | ZlibInit::InitGzip
        ) {
            self.exit_zlib();
            return Err(Error::new(CURLcode::WriteError));
        }

        // `:153-154`: `nread` and `orig_in`, the input as it stood on entry.
        // The raw-deflate retry replays from here, so the cursor -- not the
        // slice -- is what moves.
        let nread = input.len();
        let mut cursor = 0;

        // Whether this stage owns the framing around the deflate stream. In
        // gzip-member mode a stream end hands back to the caller for the
        // trailer this module checks itself; otherwise it is zlib's own
        // wrapper that just ended, and `process_trailer` applies.
        let framed = self.wrapper == Wrapper::Gzip;
        let mut ended = false;

        let mut done = false;
        let mut result: CurlResult<()> = Ok(());

        // `:166`.
        while !done {
            // `:168`: assume this is the last iteration, and let the codec's
            // answer say otherwise.
            done = true;

            let (status, consumed, produced) = {
                let Self { stream, buffer, .. } = self;
                let Some(stream) = stream.as_mut() else {
                    // Unreachable: the guard above admits only states that
                    // have a stream, and nothing clears it without leaving
                    // them. Answered rather than panicked, because a wrong
                    // answer here would abort a transfer that could still be
                    // failed cleanly.
                    return Err(Error::new(CURLcode::WriteError));
                };
                // `:170-174`: the window is reset for every iteration, which
                // is what bounds the memory this stage holds.
                let before_in = stream.total_in();
                let before_out = stream.total_out();
                let status = stream.decompress(
                    &input[cursor..],
                    buffer.as_mut_slice(),
                    FlushDecompress::None,
                );
                // `flate2` reports progress through its running totals rather
                // than through `avail_in`/`avail_out`, and `reset` zeroes them
                // -- so both are read immediately either side of the one call
                // and never carried across an iteration.
                let consumed =
                    narrow(stream.total_in().wrapping_sub(before_in));
                let produced =
                    narrow(stream.total_out().wrapping_sub(before_out));
                (status, consumed, produced)
            };
            cursor += consumed;

            // `:176-187`: flush output, but only for the two answers that mean
            // the bytes are real. A `Z_BUF_ERROR` produces none, and an error's
            // partial output is discarded rather than delivered.
            if produced != 0
                && matches!(status, Ok(Status::Ok | Status::StreamEnd))
            {
                // `:179`: "Data started." -- and from here the raw retry is no
                // longer permitted.
                self.zlib_init = started;
                if framed {
                    // The member's CRC-32 and its length, which the trailer
                    // will be checked against. `Crc::amount` is the byte count
                    // modulo 2^32, which is exactly what `ISIZE` states.
                    self.gz.body_crc.update(&self.buffer[..produced]);
                }
                // Bound to a `let` rather than tested inline: an `if let` would
                // hold the borrow of `self.buffer` for the whole block, and the
                // block releases the codec state.
                let written = tail.write(ctx, flags, &self.buffer[..produced]);
                if let Err(err) = written {
                    // `:182-185`: release the codec state and hand the NEXT
                    // stage's code back untouched.
                    self.exit_zlib();
                    result = Err(err);
                    break;
                }
            }

            // `:189-220`.
            match status {
                // `:191-194`.
                Ok(Status::Ok) => done = false,
                // `:195-197`.
                Ok(Status::BufError) => {}
                // `:198-200`.
                Ok(Status::StreamEnd) => {
                    if framed {
                        ended = true;
                    } else {
                        result = self.process_trailer(nread - cursor);
                    }
                }
                Err(err) => {
                    // `:201-216`: the broken-server fallback. Permitted only
                    // while nothing has been decoded, which `ZLIB_INIT` is
                    // exactly the record of.
                    if self.zlib_init == ZlibInit::Init {
                        self.reset_raw();
                        // `:206-207`: replay the same input from its start.
                        cursor = 0;
                        self.zlib_init = ZlibInit::Inflating;
                        self.trailerlen = ZLIB_RAW_TRAILER_TOLERANCE;
                        done = false;
                    } else {
                        // `:215` and `:218`.
                        let failure = process_zlib_error(ctx, err.message());
                        self.exit_zlib();
                        result = Err(failure);
                    }
                }
            }
        }

        // `:223-227`: *"We are about to leave this call so the `nread' data
        // bytes will not be seen again. If we are in a state that would wrongly
        // allow restart in raw mode at the next call, assume output has already
        // started."*
        if nread != 0 && self.zlib_init == ZlibInit::Init {
            self.zlib_init = started;
        }

        result.map(|()| InflateStop {
            consumed: cursor,
            ended,
        })
    }

    /// `deflate_do_write` (`lib/content_encoding.c:249-268`), for a body write.
    fn deflate_write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `:263-264`: a trailer left over from the raw fallback is consumed
        // without touching the codec, which no longer exists.
        if self.zlib_init == ZlibInit::ExternalTrailer {
            return self.process_trailer(buf.len());
        }
        // `:266-267`.
        self.inflate_stream(ctx, tail, flags, buf, ZlibInit::Inflating)
            .map(|_| ())
    }

    /// `gzip_do_write` (`lib/content_encoding.c:309-329`), for a body write.
    ///
    /// The C hands the whole job to zlib's transparent mode. This drives the
    /// same three parts explicitly -- detection, the member framing, the
    /// deflate stream -- because `flate2`'s pure-Rust backend has no
    /// transparent mode; see [`Wrapper`].
    fn gzip_write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `:319` and `:327-328`: any state but `ZLIB_INIT_GZIP` means the
        // stream is over -- or, in the C, that zlib was too old to have a
        // transparent mode at all -- and the answer is `CURLE_WRITE_ERROR`.
        if self.zlib_init != ZlibInit::InitGzip {
            self.exit_zlib();
            return Err(Error::new(CURLcode::WriteError));
        }

        let mut rest = buf;
        loop {
            match self.wrapper {
                Wrapper::NotGzip => {
                    // Unreachable: `Self::gzip` starts at `Undecided` and
                    // nothing moves a stage back to `NotGzip`.
                    debug_assert!(
                        false,
                        "the gzip stage never carries Wrapper::NotGzip"
                    );
                    return Err(Error::new(CURLcode::WriteError));
                }
                Wrapper::Undecided => {
                    rest = self.decide_wrapper(ctx, tail, flags, rest)?;
                    if self.wrapper == Wrapper::Undecided {
                        // One byte was held back; the answer needs two.
                        return Ok(());
                    }
                }
                Wrapper::Zlib => {
                    // zlib's own wrapper: the codec validates the header and
                    // the Adler-32, and `process_trailer` refuses anything
                    // after the stream, exactly as for `deflate`.
                    self.inflate_stream(
                        ctx,
                        tail,
                        flags,
                        rest,
                        ZlibInit::InitGzip,
                    )?;
                    return Ok(());
                }
                Wrapper::Gzip => match self.gz.phase {
                    GzPhase::Header => {
                        let used = match self.feed_header(rest) {
                            Ok(used) => used,
                            Err(fault) => return self.fail_gz(ctx, fault),
                        };
                        rest = &rest[used..];
                        if self.gz.phase == GzPhase::Header {
                            // The header is not complete yet, and the input is
                            // exhausted.
                            return Ok(());
                        }
                    }
                    GzPhase::Deflate => {
                        let stop = self.inflate_stream(
                            ctx,
                            tail,
                            flags,
                            rest,
                            ZlibInit::InitGzip,
                        )?;
                        rest = &rest[stop.consumed..];
                        if !stop.ended {
                            return Ok(());
                        }
                        self.gz.phase = GzPhase::Trailer;
                    }
                    GzPhase::Trailer => {
                        let used = self.feed_trailer(rest);
                        rest = &rest[used..];
                        if self.gz.trailer_len < GZIP_TRAILER_LEN {
                            return Ok(());
                        }
                        if let Err(fault) = self.verify_trailer() {
                            return self.fail_gz(ctx, fault);
                        }
                        // zlib answers `Z_STREAM_END` at this point and the C's
                        // `process_trailer` releases the codec state; with
                        // `trailerlen` at zero that is all it has left to do.
                        self.exit_zlib();
                        self.wrapper = Wrapper::Ended;
                    }
                },
                Wrapper::Ended => {
                    // `:130-131`: *"Issue an error if unexpected bytes
                    // follow."* A second gzip member is NOT decoded: zlib's
                    // transparent mode does not concatenate members either, and
                    // silently accepting one would deliver a body the server
                    // never described.
                    return if rest.is_empty() {
                        Ok(())
                    } else {
                        Err(Error::new(CURLcode::WriteError))
                    };
                }
            }
        }
    }

    /// Release the codec state and report a framing fault the way the C
    /// reports a zlib one.
    fn fail_gz<T>(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        fault: GzFault,
    ) -> CurlResult<T> {
        let failure = process_zlib_error(ctx, Some(fault.message()));
        self.exit_zlib();
        Err(failure)
    }

    /// Decide, from the first two bytes, whether this is a gzip member or a
    /// zlib stream -- zlib's `HEAD` state, which needs both bytes before it can
    /// answer.
    ///
    /// The first byte is REPLAYED into whichever consumer takes over, because
    /// it belongs to the stream either way. Returns what is left of `input`
    /// after the second byte's position; the caller loops on the new wrapper.
    fn decide_wrapper<'buf>(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        input: &'buf [u8],
    ) -> CurlResult<&'buf [u8]> {
        let mut rest = input;
        let first = match self.held.take() {
            Some(byte) => byte,
            None => match rest.split_first() {
                // Nothing held and nothing to read. Not reachable through
                // `write`, which forwards an empty body before it gets here
                // (see [`passes_through`]); answered rather than asserted,
                // since there is a correct answer -- wait for more input.
                None => return Ok(rest),
                Some((byte, remainder)) => {
                    rest = remainder;
                    *byte
                }
            },
        };

        if rest.is_empty() {
            // Hold it and wait, as zlib waits with a half-filled header word.
            self.held = Some(first);
            return Ok(rest);
        }

        if [first, rest[0]] == GZIP_MAGIC {
            self.wrapper = Wrapper::Gzip;
            self.gz = GzipFraming::default();
            // A gzip member's payload is RAW deflate: the framing around it is
            // this module's to parse.
            self.stream = Some(Decompress::new(false));
            if let Err(fault) = self.feed_header(&[first]) {
                return self.fail_gz(ctx, fault);
            }
        } else {
            self.wrapper = Wrapper::Zlib;
            self.stream = Some(Decompress::new(true));
            self.inflate_stream(
                ctx,
                tail,
                flags,
                &[first],
                ZlibInit::InitGzip,
            )?;
        }
        Ok(rest)
    }

    /// Consume header bytes, one at a time, and report how many were taken.
    ///
    /// RFC 1952 section 2.3: ten fixed bytes, then `FEXTRA`, `FNAME`,
    /// `FCOMMENT` and `FHCRC` in that order, each present only if its flag bit
    /// is set. Nothing is retained but the counters, so a member with a huge
    /// extra field or a long name costs no memory.
    ///
    /// # Errors
    ///
    /// The [`GzFault`] zlib's own header reader would have reported: bad magic,
    /// a compression method other than deflate, a reserved flag bit, or a
    /// stored header CRC that disagrees.
    fn feed_header(&mut self, input: &[u8]) -> Result<usize, GzFault> {
        let mut at = 0;
        while self.gz.phase == GzPhase::Header && at < input.len() {
            let byte = input[at];
            at += 1;

            // The stored CRC-16 covers every header byte BEFORE itself
            // (RFC 1952 section 2.3.1.2), so the two bytes that carry it are
            // the only ones excluded.
            if self.gz.field != GzField::Hcrc {
                self.gz.header_crc.update(&[byte]);
            }

            match self.gz.field {
                // The two magic arms are kept complete but are not reachable
                // from this module: `decide_wrapper` enters gzip mode only
                // after it has already seen both bytes, so the machine is
                // never handed a member whose magic is wrong. They stay
                // because the machine is the RFC's and a reader checking it
                // against RFC 1952 section 2.3 should find every field, and
                // because a future caller that starts the machine without the
                // lookahead would otherwise mis-parse silently rather than
                // report `incorrect header check`.
                GzField::Magic1 => {
                    if byte != GZIP_MAGIC[0] {
                        return Err(GzFault::Header);
                    }
                    self.gz.field = GzField::Magic2;
                }
                GzField::Magic2 => {
                    if byte != GZIP_MAGIC[1] {
                        return Err(GzFault::Header);
                    }
                    self.gz.field = GzField::Method;
                }
                GzField::Method => {
                    if byte != GZIP_DEFLATE_METHOD {
                        return Err(GzFault::Method);
                    }
                    self.gz.field = GzField::Flags;
                }
                GzField::Flags => {
                    if byte & GZIP_RESERVED_FLAGS != 0 {
                        return Err(GzFault::Flags);
                    }
                    self.gz.flags = byte;
                    self.gz.pending = GZIP_FIXED_TAIL;
                    self.gz.field = GzField::Fixed;
                }
                GzField::Fixed => {
                    self.gz.pending -= 1;
                    if self.gz.pending == 0 {
                        self.advance_past(0);
                    }
                }
                GzField::ExtraLen => {
                    // `XLEN`, little-endian: `pending` counts down from two, so
                    // the first byte is the low half.
                    self.gz.extra |=
                        usize::from(byte) << (8 * (2 - self.gz.pending));
                    self.gz.pending -= 1;
                    if self.gz.pending == 0 {
                        if self.gz.extra == 0 {
                            self.advance_past(1);
                        } else {
                            self.gz.pending = self.gz.extra;
                            self.gz.field = GzField::Extra;
                        }
                    }
                }
                GzField::Extra => {
                    self.gz.pending -= 1;
                    if self.gz.pending == 0 {
                        self.advance_past(1);
                    }
                }
                GzField::Name => {
                    if byte == 0 {
                        self.advance_past(2);
                    }
                }
                GzField::Comment => {
                    if byte == 0 {
                        self.advance_past(3);
                    }
                }
                GzField::Hcrc => {
                    self.gz.header_crc_seen |=
                        u32::from(byte) << (8 * (2 - self.gz.pending));
                    self.gz.pending -= 1;
                    if self.gz.pending == 0 {
                        if self.gz.header_crc_seen
                            != (self.gz.header_crc.sum() & 0xffff)
                        {
                            return Err(GzFault::HeaderCrc);
                        }
                        self.gz.field = GzField::Done;
                        self.gz.phase = GzPhase::Deflate;
                    }
                }
                // Likewise unreachable: `Done` is set in the same step that
                // leaves `GzPhase::Header`, and the loop above tests the phase.
                GzField::Done => break,
            }
        }
        Ok(at)
    }

    /// Move to the next optional header field that `FLG` asks for, or to the
    /// deflate stream if none is left.
    ///
    /// `done` is how many of the four optional fields have been passed: 0 after
    /// the fixed head, 1 after `FEXTRA`, 2 after `FNAME`, 3 after `FCOMMENT`.
    fn advance_past(&mut self, done: usize) {
        // RFC 1952 section 2.3 fixes this order, and a reader that took them in
        // any other would mis-parse a member carrying two of them.
        const ORDER: [(u8, GzField); 4] = [
            (GZIP_FEXTRA, GzField::ExtraLen),
            (GZIP_FNAME, GzField::Name),
            (GZIP_FCOMMENT, GzField::Comment),
            (GZIP_FHCRC, GzField::Hcrc),
        ];

        for &(bit, field) in ORDER.iter().skip(done) {
            if self.gz.flags & bit != 0 {
                self.gz.field = field;
                // The two length-prefixed fields accumulate a 16-bit value.
                self.gz.pending = match field {
                    GzField::ExtraLen | GzField::Hcrc => 2,
                    _ => 0,
                };
                return;
            }
        }
        self.gz.field = GzField::Done;
        self.gz.phase = GzPhase::Deflate;
    }

    /// Collect trailer bytes, and report how many were taken.
    ///
    /// The eight bytes may arrive in any number of pieces, so they accumulate
    /// in a fixed array until all eight are there.
    fn feed_trailer(&mut self, input: &[u8]) -> usize {
        let at = self.gz.trailer_len;
        let take = (GZIP_TRAILER_LEN - at).min(input.len());
        self.gz.trailer[at..at + take].copy_from_slice(&input[..take]);
        self.gz.trailer_len += take;
        take
    }

    /// Check the member's CRC-32 and `ISIZE` -- the two checks zlib performs
    /// itself in transparent mode, with the same two messages.
    fn verify_trailer(&self) -> Result<(), GzFault> {
        let tail = &self.gz.trailer;
        let stored_crc =
            u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]);
        let stored_len =
            u32::from_le_bytes([tail[4], tail[5], tail[6], tail[7]]);

        if stored_crc != self.gz.body_crc.sum() {
            return Err(GzFault::DataCheck);
        }
        // `ISIZE` is the uncompressed length modulo 2^32, and `Crc::amount` is
        // the count of bytes hashed, wrapping at the same modulus.
        if stored_len != self.gz.body_crc.amount() {
            return Err(GzFault::LengthCheck);
        }
        Ok(())
    }
}

#[cfg(feature = "gzip")]
impl ClientWriter for ZlibDecoder {
    fn kind(&self) -> ClientWriterKind {
        self.coding.kind()
    }

    fn phase(&self) -> ClientWriterPhase {
        self.phase
    }

    /// `deflate_do_init` (`:233-247`) and `gzip_do_init` (`:292-307`).
    ///
    /// The C's `zalloc`/`zfree` hooks (`:87-98`), which exist only to route
    /// zlib's allocation through curl's, have no counterpart: `flate2`
    /// allocates through Rust's allocator, which IS the one the crate uses
    /// everywhere else. Neither constructor can fail -- the C's
    /// `if(inflateInit(z) != Z_OK)` covers an allocation failure, which Rust
    /// reports by aborting -- so `Ok(())` is the only answer, and the C's
    /// `process_zlib_error` arm has no reachable counterpart.
    fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        let _ = ctx;
        match self.coding {
            ZlibCoding::Deflate => {
                // `inflateInit(z)`: a zlib header is expected, and a body that
                // does not have one is retried raw.
                self.stream = Some(Decompress::new(true));
                self.zlib_init = ZlibInit::Init;
                self.wrapper = Wrapper::NotGzip;
            }
            ZlibCoding::Gzip => {
                // `inflateInit2(z, MAX_WBITS + 32)`: which wrapper to expect is
                // not known until the first two bytes, so the stream is created
                // then.
                self.stream = None;
                self.zlib_init = ZlibInit::InitGzip;
                self.wrapper = Wrapper::Undecided;
            }
        }
        self.trailerlen = 0;
        self.held = None;
        self.gz = GzipFraming::default();
        Ok(())
    }

    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `:256-257` and `:316-317`.
        if passes_through(flags, buf) {
            return tail.write(ctx, flags, buf);
        }
        match self.coding {
            ZlibCoding::Deflate => self.deflate_write(ctx, tail, flags, buf),
            ZlibCoding::Gzip => self.gzip_write(ctx, tail, flags, buf),
        }
    }

    /// `deflate_do_close` (`:270-277`) and `gzip_do_close` (`:331-338`), which
    /// are the same function twice: `exit_zlib(data, z, &zp->zlib_init,
    /// CURLE_OK)`.
    fn close(&mut self, ctx: &mut ClientCtx<'_>) {
        let _ = ctx;
        self.exit_zlib();
    }
}

// `brotli_writer` -- the `br` stage (`lib/content_encoding.c:351-470`)

/// The allocator triple a [`BrotliState`] is built over.
///
/// The C passes three null pointers to `BrotliDecoderCreateInstance`
/// (`:401`), which tells the C library to use `malloc` and `free`. `HeapAlloc`
/// is the same choice expressed safely: it allocates through Rust's allocator,
/// which is the one this crate uses everywhere else -- and, under the
/// `memdebug` feature, the one that counts.
#[cfg(feature = "brotli")]
type BrotliAlloc =
    BrotliState<HeapAlloc<u8>, HeapAlloc<u32>, HeapAlloc<HuffmanCode>>;

/// Which of the C's three error classes a brotli failure belongs to.
///
/// `brotli_map_error` (`lib/content_encoding.c:359-393`) sorts twenty-two
/// `BrotliDecoderErrorCode` values into three answers, and that taxonomy is
/// preserved here rather than flattened, because the three codes mean
/// different things to a caller.
///
/// # Why the classification is made from the RESULT and not from a code
///
/// `BrotliDecoderErrorCode` is not reachable through the `brotli` crate's
/// public API: it is re-exported only behind the `ffi-api` feature, which this
/// workspace must keep OFF because it would add `#[no_mangle]` C symbols to
/// `libcurl.so.4` and break the export parity gate. So the class is decided by
/// what the decoder DID rather than by which of its codes it recorded:
///
/// * [`Self::Format`] -- the decoder reported failure while decoding. Every
///   reachable failure of the pure-Rust decoder is one of the sixteen format
///   or invalid-argument codes the C maps to
///   [`CURLcode::BadContentEncoding`].
/// * [`Self::Allocation`] -- the six `BROTLI_DECODER_ERROR_ALLOC_*` codes,
///   which the C maps to [`CURLcode::OutOfMemory`]. NOT REACHABLE here, and
///   the honest reason is recorded rather than the arm quietly dropped: the
///   pure-Rust decoder allocates through `HeapAlloc`, and Rust's allocator
///   reports exhaustion by aborting the process instead of returning. The arm
///   is kept, and asserted by test, so that the mapping stays complete if a
///   later `brotli` release exposes a fallible allocator.
/// * [`Self::State`] -- the C's `default` arm, [`CURLcode::WriteError`], which
///   it reaches for a decoder that is in no position to decode. Both of the C's
///   own paths to it are reproduced: a write after the stream ended (`:419-420`)
///   and input left over once it has (`:439-440`).
#[cfg(feature = "brotli")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum BrotliFailure {
    /// A malformed stream or an invalid argument.
    Format,
    /// An allocation the decoder could not satisfy.
    ///
    /// Never constructed, and the type's documentation records why: Rust's
    /// allocator aborts rather than reporting, so the six
    /// `BROTLI_DECODER_ERROR_ALLOC_*` codes have no reachable counterpart. The
    /// arm is kept so the C's mapping stays complete, and
    /// `the_brotli_error_taxonomy_is_the_sources` asserts it.
    #[allow(dead_code)]
    Allocation,
    /// A decoder that cannot decode, for a reason that is not the stream's.
    State,
}

#[cfg(feature = "brotli")]
impl BrotliFailure {
    /// `brotli_map_error` (`lib/content_encoding.c:359-393`).
    const fn code(self) -> CURLcode {
        match self {
            Self::Format => CURLcode::BadContentEncoding,
            Self::Allocation => CURLcode::OutOfMemory,
            Self::State => CURLcode::WriteError,
        }
    }
}

/// The `br` stage -- `struct brotli_writer` (`:352-357`) with
/// `brotli_encoding` (`:462-469`).
///
/// # The loop is the C's, including the write it always performs
///
/// ```text
/// while((nbytes || r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) &&
///       result == CURLE_OK) {
///   dst = bp->buffer; dstleft = DECOMPRESS_BUFFER_SIZE;
///   r = BrotliDecoderDecompressStream(...);
///   result = Curl_cwriter_write(data, writer->next, type,
///                               bp->buffer, DECOMPRESS_BUFFER_SIZE - dstleft);
/// ```
///
/// That write is UNCONDITIONAL (`:428-429`): the C forwards the window's
/// contents on every iteration, even when the decoder produced nothing. The
/// zero-length write is harmless -- a stage downstream ignores an empty body
/// write unless `CLIENTWRITE_0LEN` is set -- but it is also observable, and its
/// result is what the loop's `result == CURLE_OK` condition then tests. It is
/// reproduced exactly, so that a downstream refusal is seen at the same
/// iteration the C would see it.
#[cfg(feature = "brotli")]
struct BrotliDecoder {
    /// The phase this instance was created at.
    phase: ClientWriterPhase,

    /// `BrotliDecoderState *br`. [`None`] is the C's `NULL`: the stream has
    /// ended, and a further body write is [`CURLcode::WriteError`].
    state: Option<Box<BrotliAlloc>>,

    /// `char buffer[DECOMPRESS_BUFFER_SIZE]`.
    buffer: Vec<u8>,
}

#[cfg(feature = "brotli")]
impl fmt::Debug for BrotliDecoder {
    /// Written out rather than derived, because [`BrotliState`] implements no
    /// `Debug` -- and a decoder's internal Huffman tables would be noise in a
    /// diagnostic anyway. The shape is what matters: which phase, and whether
    /// the stream is still open.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrotliDecoder")
            .field("phase", &self.phase)
            .field("open", &self.state.is_some())
            .field("window", &self.buffer.len())
            .finish()
    }
}

#[cfg(feature = "brotli")]
impl BrotliDecoder {
    fn new(phase: ClientWriterPhase) -> Self {
        Self {
            phase,
            state: None,
            buffer: vec![0; DECOMPRESS_BUFFER_SIZE],
        }
    }

    /// `BrotliDecoderCreateInstance(NULL, NULL, NULL)` (`:401`).
    ///
    /// Boxed because a `BrotliState` is large -- its Huffman tables are inline
    /// -- and a stage in a `Box<dyn ClientWriter>` should not carry that on the
    /// stack while it is moved into the chain.
    fn fresh_state() -> Box<BrotliAlloc> {
        Box::new(BrotliState::new(
            HeapAlloc::new(0),
            HeapAlloc::new(0),
            HeapAlloc::new(HuffmanCode { value: 0, bits: 0 }),
        ))
    }
}

#[cfg(feature = "brotli")]
impl ClientWriter for BrotliDecoder {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::Brotli
    }

    fn phase(&self) -> ClientWriterPhase {
        self.phase
    }

    /// `brotli_do_init` (`:395-403`).
    ///
    /// The C answers `CURLE_OUT_OF_MEMORY` when the create returns `NULL`.
    /// `BrotliState::new` cannot return a failure -- it allocates through
    /// `HeapAlloc`, which aborts rather than reporting -- so this cannot fail.
    fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        let _ = ctx;
        self.state = Some(Self::fresh_state());
        Ok(())
    }

    /// `brotli_do_write` (`:405-448`).
    ///
    /// # Errors
    ///
    /// * [`CURLcode::WriteError`] for a body write after the stream ended
    ///   (`:419-420`), and for input left over once it has (`:439-440`).
    /// * [`CURLcode::BadContentEncoding`] for a malformed stream -- see
    ///   [`BrotliFailure`] for why the class is decided from the result.
    /// * Whatever the next stage returned, unchanged.
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `:416-417`.
        if passes_through(flags, buf) {
            return tail.write(ctx, flags, buf);
        }

        // `:419-420`: "Stream already ended."
        if self.state.is_none() {
            return Err(Error::new(BrotliFailure::State.code()));
        }

        // `:410-414`. `available_in` counts down and `input_offset` counts up,
        // which together are the C's `&nbytes` and `&src`.
        let mut available_in = buf.len();
        let mut input_offset = 0;
        // `:414`: the loop is entered as though more output were wanted, so a
        // stream that needs no input at all still gets one iteration.
        let mut answer = BrotliResult::NeedsMoreOutput;

        // `:422-423`. `BrotliResult` implements no `PartialEq`, so the C's
        // `r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT` is spelled as a match.
        while available_in != 0
            || matches!(answer, BrotliResult::NeedsMoreOutput)
        {
            // `:424-425`: the window is reset every iteration.
            let mut available_out = DECOMPRESS_BUFFER_SIZE;
            let mut output_offset = 0;
            let mut total_out = 0;

            let produced = {
                let Self { state, buffer, .. } = self;
                let Some(state) = state.as_mut() else {
                    // Unreachable: the only path that clears the state returns
                    // from this function in the same iteration.
                    return Err(Error::new(BrotliFailure::State.code()));
                };
                // `:426-427`.
                answer = BrotliDecompressStream(
                    &mut available_in,
                    &mut input_offset,
                    buf,
                    &mut available_out,
                    &mut output_offset,
                    buffer.as_mut_slice(),
                    &mut total_out,
                    state,
                );
                DECOMPRESS_BUFFER_SIZE - available_out
            };

            // `:428-431`: UNCONDITIONAL, and its result decides whether the
            // loop goes round again. A downstream code is returned unchanged.
            let written = tail.write(ctx, flags, &self.buffer[..produced]);
            written?;

            // `:432-445`.
            match answer {
                // `:433-435`: more of either is wanted, so the loop condition
                // decides.
                BrotliResult::NeedsMoreOutput
                | BrotliResult::NeedsMoreInput => {}
                BrotliResult::ResultSuccess => {
                    // `:436-441`: destroy the state, then refuse any input that
                    // outlived the stream. Dropping the box IS
                    // `BrotliDecoderDestroyInstance`.
                    self.state = None;
                    if available_in != 0 {
                        return Err(Error::new(BrotliFailure::State.code()));
                    }
                }
                // `:442-444`: `brotli_map_error(BrotliDecoderGetErrorCode(...))`.
                //
                // A CODE and no diagnostic. The C file calls `failf` in
                // exactly seven places -- twice in `process_zlib_error`, once
                // in the deferred stage and four times in the builder -- and
                // NONE of them is here: a brotli fault reports nothing and
                // leaves the error buffer as it was. A sentence invented for
                // this path would be observable in `CURLOPT_ERRORBUFFER` and
                // on stderr under `--show-error`, so there is none.
                BrotliResult::ResultFailure => {
                    return Err(Error::new(BrotliFailure::Format.code()));
                }
            }
        }
        Ok(())
    }

    /// `brotli_do_close` (`:450-460`).
    ///
    /// Dropping the box is `BrotliDecoderDestroyInstance`, so an unfinished
    /// stream releases its tables here and a finished one has already released
    /// them.
    fn close(&mut self, ctx: &mut ClientCtx<'_>) {
        let _ = ctx;
        self.state = None;
    }
}

// `zstd_writer` -- the `zstd` stage (`lib/content_encoding.c:472-573`)

/// The `zstd` stage -- `struct zstd_writer` (`:473-478`) with
/// `zstd_encoding` (`:565-572`).
///
/// # The loop is the C's, and its exit condition is the interesting part
///
/// ```text
/// for(;;) {
///   out.pos = 0; out.dst = zp->buffer; out.size = DECOMPRESS_BUFFER_SIZE;
///   errorCode = ZSTD_decompressStream(zp->zds, &out, &in);
///   if(ZSTD_isError(errorCode)) return CURLE_BAD_CONTENT_ENCODING;
///   if(out.pos > 0) { result = Curl_cwriter_write(...); if(result) break; }
///   if((in.pos == nbytes) && (out.pos < out.size)) break;
/// }
/// ```
///
/// The exit needs BOTH halves. Input being consumed is not enough: a decoder
/// that filled the window may still be holding decompressed bytes it had
/// nowhere to put, so the loop goes round again with an empty input to collect
/// them. And a partly filled window is not enough either, since input may
/// remain. Unlike the brotli stage, the forward here is CONDITIONAL on the
/// window having something in it (`:540`), which is also reproduced.
///
/// A `zstd` body may be several frames, and the decoder reads them one after
/// another exactly as `ZSTD_decompressStream` does; the C refuses nothing here,
/// so neither does this.
#[cfg(feature = "zstd")]
struct ZstdDecoder {
    /// The phase this instance was created at.
    phase: ClientWriterPhase,

    /// `ZSTD_DStream *zds`. [`None`] means there is no decoder: it has been
    /// released, and a body write in that state is refused rather than passed
    /// to a null pointer, which is what the C would do.
    stream: Option<ZstdStream<'static>>,

    /// `char buffer[DECOMPRESS_BUFFER_SIZE]`.
    buffer: Vec<u8>,
}

#[cfg(feature = "zstd")]
impl fmt::Debug for ZstdDecoder {
    /// Written out because `zstd`'s raw decoder implements no `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZstdDecoder")
            .field("phase", &self.phase)
            .field("open", &self.stream.is_some())
            .field("window", &self.buffer.len())
            .finish()
    }
}

#[cfg(feature = "zstd")]
impl ZstdDecoder {
    fn new(phase: ClientWriterPhase) -> Self {
        Self {
            phase,
            stream: None,
            buffer: vec![0; DECOMPRESS_BUFFER_SIZE],
        }
    }
}

#[cfg(feature = "zstd")]
impl ClientWriter for ZstdDecoder {
    fn kind(&self) -> ClientWriterKind {
        ClientWriterKind::Zstd
    }

    fn phase(&self) -> ClientWriterPhase {
        self.phase
    }

    /// `zstd_do_init` (`:494-512`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`], which is the C's answer to
    /// `ZSTD_createDStream()` returning `NULL` (`:511`). The C's
    /// `ZSTD_STATIC_LINKING_ONLY` arm, which routes the decoder's allocation
    /// through curl's own `malloc` (`:480-492`), has no counterpart: the crate
    /// allocates through the allocator this crate already uses.
    fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
        let _ = ctx;
        self.stream = Some(
            ZstdStream::new().map_err(|_| Error::new(CURLcode::OutOfMemory))?,
        );
        Ok(())
    }

    /// `zstd_do_write` (`:514-551`).
    ///
    /// # Errors
    ///
    /// * [`CURLcode::BadContentEncoding`] for any error the codec reports
    ///   (`:537-539`) -- there is no second class here, unlike brotli's.
    /// * [`CURLcode::WriteError`] for a body write with no decoder, which is
    ///   the state the C would have passed a `NULL` `ZSTD_DStream` in.
    /// * Whatever the next stage returned, unchanged.
    fn write(
        &mut self,
        ctx: &mut ClientCtx<'_>,
        tail: &mut WriterTail<'_, '_>,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CurlResult<()> {
        // `:524-525`.
        if passes_through(flags, buf) {
            return tail.write(ctx, flags, buf);
        }

        if self.stream.is_none() {
            // The C reaches `ZSTD_decompressStream` with a null decoder here,
            // which is undefined; refusing deterministically is the same
            // outcome a caller can act on.
            return Err(Error::new(CURLcode::WriteError));
        }

        // `:527-529`: one input cursor for the whole call, which `run` advances.
        let mut input = InBuffer::around(buf);

        // `:531`.
        loop {
            let produced = {
                let Self { stream, buffer, .. } = self;
                let Some(stream) = stream.as_mut() else {
                    // Unreachable: nothing inside this loop clears the decoder.
                    return Err(Error::new(CURLcode::WriteError));
                };
                // `:532-534`: a fresh output view every iteration, which is
                // what keeps the window bounded.
                let mut output = OutBuffer::around(buffer.as_mut_slice());
                // `:536-539`: `ZSTD_decompressStream`, and any error it reports
                // is a malformed stream.
                stream
                    .run(&mut input, &mut output)
                    .map_err(|_| Error::new(CURLcode::BadContentEncoding))?;
                output.pos()
            };

            // `:540-545`: forward only what there is, and stop at a refusal
            // with the refusal's own code.
            if produced > 0 {
                // The refusal's own `CURLcode`, untranslated: a client that
                // pauses or errors is not a malformed stream.
                tail.write(ctx, flags, &self.buffer[..produced])?;
            }

            // `:546-547`: input consumed AND the window not filled.
            if input.pos() == buf.len() && produced < DECOMPRESS_BUFFER_SIZE {
                return Ok(());
            }
        }
    }

    /// `zstd_do_close` (`:553-563`).
    ///
    /// `ZSTD_freeDStream` is the drop of the decoder, so this releases it and
    /// leaves the stage in the state a further write refuses.
    fn close(&mut self, ctx: &mut ClientCtx<'_>) {
        let _ = ctx;
        self.stream = None;
    }
}

// Building a stage for a coding

/// Create the stage that decodes `coding`, at `phase`.
///
/// The successor of the `Curl_cwtype` pointer `find_unencode_writer` returns
/// (`lib/content_encoding.c:669-693`) together with the allocation
/// `Curl_cwriter_create` performs from its `cwriter_size` (`lib/sendf.c:411`).
/// A Rust value knows its own size, so there is no size member and nothing to
/// get wrong.
///
/// # Every arm is gated exactly as its registry row is
///
/// A coding whose Cargo feature is off has no arm here, so it cannot be
/// constructed even by a caller that bypassed [`find_unencoder`] -- and
/// [`None`] is that caller's answer. The two facts come from the same `cfg!`
/// pair by construction: the row and the arm.
///
/// `chunked` is NOT built here. It comes from `transfer/chunked.rs` through
/// [`transfer_unencoder`], because that stage owns chunk framing and carries
/// `data->set.http_te_skip`, which the C reads from the handle on every write.
#[allow(dead_code)] // consumer: protocols/http1.rs, and build_unencoding_stack
pub(crate) fn new_decoder(
    coding: ClientWriterKind,
    phase: ClientWriterPhase,
    http_te_skip: bool,
) -> Option<Box<dyn ClientWriter + 'static>> {
    match coding {
        // `identity_encoding` (`:576-583`).
        ClientWriterKind::Identity => Some(Box::new(IdentityDecoder { phase })),
        // `error_writer` (`:660-667`), which is not in either registry: it is
        // reached only by an unknown coding.
        ClientWriterKind::ContentEncodingError => {
            Some(Box::new(DeferredErrorDecoder { phase }))
        }
        // `Curl_httpchunk_unencoder` (`lib/http_chunks.c:453-460`).
        ClientWriterKind::ChunkedDecode => {
            Some(transfer_unencoder(http_te_skip))
        }
        #[cfg(feature = "gzip")]
        ClientWriterKind::Deflate => {
            Some(Box::new(ZlibDecoder::deflate(phase)))
        }
        #[cfg(feature = "gzip")]
        ClientWriterKind::Gzip => Some(Box::new(ZlibDecoder::gzip(phase))),
        #[cfg(feature = "brotli")]
        ClientWriterKind::Brotli => Some(Box::new(BrotliDecoder::new(phase))),
        #[cfg(feature = "zstd")]
        ClientWriterKind::Zstd => Some(Box::new(ZstdDecoder::new(phase))),
        // Every other `ClientWriterKind` names a stage some other module owns
        // -- `cw-out`, `hds-collect`, `ws-decode` -- and none of them is a
        // content or transfer coding. So is any decoder whose feature is off.
        _ => None,
    }
}

/// A `total_in` or `total_out` delta, as a count of bytes.
///
/// The delta cannot exceed the slice it was measured over -- one write's input,
/// or the [`DECOMPRESS_BUFFER_SIZE`] window -- so the conversion is exact on
/// every supported target. `try_from` rather than `as`, so that a 32-bit host
/// outside the mandated matrix would clamp rather than wrap.
#[cfg(feature = "gzip")]
fn narrow(delta: u64) -> usize {
    usize::try_from(delta).unwrap_or(usize::MAX)
}

// `Curl_build_unencoding_stack` -- the parser and the builder
// (`lib/content_encoding.c:695-803`)

/// `is_transfer ? "transfer" : "content"`, as the three trace lines spell it
/// (`:725`, `:735` and `:788`).
const fn phase_word(is_transfer: bool) -> &'static str {
    if is_transfer {
        "transfer"
    } else {
        "content"
    }
}

/// The three handle settings the builder reads.
///
/// The C reaches into `data->set` for each of them (`lib/urldata.h:1537`,
/// `:1550` and `:1552`). None has a field in
/// [`ClientConfig`](crate::transfer::sendf::ClientConfig), which carries the
/// settings the writer CHAIN consults rather than the ones this builder does,
/// so they arrive together here. All three are fixed before a transfer starts,
/// which is why they are passed by value.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumer: protocols/http1.rs
pub(crate) struct UnencodingSettings {
    /// `data->set.http_transfer_encoding` -- *"request compressed HTTP
    /// transfer-encoding"* (`lib/urldata.h:1537`), which
    /// `CURLOPT_TRANSFER_ENCODING` sets (`lib/setopt.c:531-533`).
    ///
    /// Default FALSE. A `Transfer-Encoding` that names anything but `chunked`
    /// was therefore not asked for, and the builder refuses it rather than
    /// decoding it.
    pub(crate) http_transfer_encoding: bool,

    /// `data->set.http_ce_skip` -- *"pass the raw body data to the user, even
    /// when content-encoded"* (`lib/urldata.h:1552`).
    ///
    /// The REVERSE of `CURLOPT_HTTP_CONTENT_DECODING`
    /// (`lib/setopt.c:546-552`, `s->http_ce_skip = !enabled`), so the default
    /// -- decoding enabled -- is FALSE here.
    pub(crate) http_ce_skip: bool,

    /// `data->set.http_te_skip` -- the same reversal of
    /// `CURLOPT_HTTP_TRANSFER_DECODING` (`lib/setopt.c:540-545`), default
    /// FALSE.
    ///
    /// Read twice, for two different purposes: it decides whether an
    /// unsolicited transfer coding is REFUSED or merely ignored (`:736`), and
    /// it is handed to the chunked stage, which writes the framed bytes to the
    /// client when it is set (`lib/http_chunks.c:124`).
    pub(crate) http_te_skip: bool,
}

/// Build the unencoding stack from a `Content-Encoding` or `Transfer-Encoding`
/// header value.
///
/// `Curl_build_unencoding_stack` (`lib/content_encoding.c:695-803`), whose own
/// reference is *"See RFC 7231 section 3.1.2.2"*. `enclist` is the header
/// value as bytes, `is_transfer` says which header it came from, and `factory`
/// supplies the two stages the base chain needs, since adding to an empty chain
/// builds that base first (`lib/sendf.c:458-462`).
///
/// # The parse, byte for byte
///
/// ```text
/// while(ISBLANK(*enclist) || *enclist == ',') enclist++;
/// name = enclist;
/// for(namelen = 0; *enclist && *enclist != ','; enclist++)
///   if(*enclist > ' ') namelen = enclist - name + 1;
/// ```
///
/// Leading spaces, tabs and commas are skipped, so `", , gzip"` yields one
/// token. The token then runs to the last byte ABOVE a space, which trims
/// trailing spaces, tabs and control bytes without touching anything inside it:
/// `"gzip\t"` is `gzip`, and `"gz ip"` stays `gz ip` and matches nothing.
///
/// One divergence, and it is the C that is ambiguous rather than this. The C's
/// `*enclist > ' '` compares a `char`, whose signedness is
/// implementation-defined: on x86-64 Linux it is signed, so a trailing byte at
/// or above `0x80` compares as negative and is TRIMMED; on ARM Linux it is
/// unsigned and the same byte is KEPT. Two of the four supported targets read
/// it each way. This compares bytes, which is the ARM reading and the one the
/// specification's own wording states -- *"retain characters through the last
/// byte greater than ASCII space"*. It is observable only for a token whose
/// LAST byte is non-ASCII, which matches no coding either way; the sole
/// difference is whether such a token becomes a deferred failure or is skipped
/// outright, and no fixture contains one.
///
/// # Errors
///
/// Five refusals, all [`CURLcode::BadContentEncoding`], each at the exact point
/// the C reaches it:
///
/// | condition | message |
/// |---|---|
/// | a coding after `chunked`, unsolicited | `A Transfer-Encoding (%.*s) was listed after chunked` |
/// | any other unsolicited transfer coding | `Unsolicited Transfer-Encoding (%.*s) found` |
/// | a fifth decoder at one phase | `Reject response due to more than %u content encodings` |
/// | a transfer coding after `chunked` was installed | `Reject response due to 'chunked' not being the last Transfer-Encoding` |
/// | a stage that fails to initialise or add | whatever it returned |
///
/// An UNKNOWN coding is not among them: it installs the deferred stage and
/// answers `Ok`, so the failure happens only if a body arrives. See
/// [`DeferredErrorDecoder`].
#[allow(dead_code)] // consumer: protocols/http1.rs
pub(crate) fn build_unencoding_stack<'data>(
    ctx: &mut ClientCtx<'_>,
    stack: &mut ClientWriterStack<'data>,
    factory: &dyn ClientIoFactory<'data>,
    enclist: &[u8],
    is_transfer: bool,
    settings: UnencodingSettings,
) -> CurlResult<()> {
    // `:700-701`.
    let phase = if is_transfer {
        ClientWriterPhase::TransferDecode
    } else {
        ClientWriterPhase::ContentDecode
    };
    let word = phase_word(is_transfer);

    // `:703`: whether a `chunked` coding has been seen in THIS header.
    let mut has_chunked = false;

    let mut at = 0;

    // `:705` with `:800`: a do-while, so an empty value performs one pass that
    // finds no token and stops.
    loop {
        // `:711-712`. `ISBLANK` is space or tab (`lib/curl_ctype.h:45`).
        while at < enclist.len()
            && (enclist[at] == b' '
                || enclist[at] == b'\t'
                || enclist[at] == b',')
        {
            at += 1;
        }

        // `:714-718`.
        let start = at;
        let mut namelen = 0;
        while at < enclist.len() && enclist[at] != b',' {
            if enclist[at] > b' ' {
                namelen = at - start + 1;
            }
            at += 1;
        }

        // `:720`.
        if namelen != 0 {
            let token = &enclist[start..start + namelen];

            // `:724-725`. A header value need not be UTF-8 and the C's `%.*s`
            // writes the bytes as they are; rendering them lossily keeps every
            // ASCII coding name identical and turns anything else into U+FFFD
            // rather than corrupting the diagnostic.
            ctx.trc_write(format_args!(
                "looking for {word} decoder: {}",
                String::from_utf8_lossy(token)
            ));

            // `:726-727`. Seven bytes exactly, and only in the transfer phase.
            let is_chunked = is_transfer
                && namelen == 7
                && token.eq_ignore_ascii_case(b"chunked");

            // `:728-748`: *"if we skip the decoding in this phase, do not look
            // further. Exception is "chunked" transfer-encoding which always
            // must happen"*.
            if (is_transfer && !settings.http_transfer_encoding && !is_chunked)
                || (!is_transfer && settings.http_ce_skip)
            {
                // `:732`: `curl_strnequal(name, "identity", 8)`, which compares
                // EIGHT bytes from the token's start rather than the token --
                // so `identityfoo` counts as identity here, and a token shorter
                // than eight bytes cannot, because the C's comparison runs into
                // the terminating zero. Both are reproduced.
                let is_identity = enclist.len() - start >= 8
                    && enclist[start..start + 8]
                        .eq_ignore_ascii_case(b"identity");

                // `:734-735`.
                ctx.trc_write(format_args!(
                    "decoder not requested, ignored: {}",
                    String::from_utf8_lossy(token)
                ));

                // `:736-746`.
                if is_transfer && !settings.http_te_skip {
                    if has_chunked {
                        return Err(ctx.failf(
                            CURLcode::BadContentEncoding,
                            format_args!(
                                "A Transfer-Encoding ({}) was listed after \
                                 chunked",
                                String::from_utf8_lossy(token)
                            ),
                        ));
                    }
                    if is_identity {
                        // `:740-741`: ignored, and the rest of the list is
                        // still examined.
                        continue;
                    }
                    return Err(ctx.failf(
                        CURLcode::BadContentEncoding,
                        format_args!(
                            "Unsolicited Transfer-Encoding ({}) found",
                            String::from_utf8_lossy(token)
                        ),
                    ));
                }
                // `:747`: success, and the REST OF THE LIST IS ABANDONED. Not a
                // `continue`: once decoding is not wanted at this phase, no
                // later coding in the same header is examined either.
                return Ok(());
            }

            // `:750-754`. `count + 1 >= 5` admits four decoders at one phase
            // and refuses the fifth; the off-by-one is the C's and is preserved
            // rather than tidied, because the refusal is observable.
            if stack.count(phase) + 1 >= MAX_ENCODE_STACK {
                return Err(ctx.failf(
                    CURLcode::BadContentEncoding,
                    format_args!(
                        "Reject response due to more than \
                         {MAX_ENCODE_STACK} content encodings"
                    ),
                ));
            }

            // `:756`.
            let found = find_unencoder(token, phase);

            // `:757-766`: a duplicate `chunked` is IGNORED, not stacked -- RFC
            // 9112 section 6.1, *"A sender MUST NOT apply the chunked transfer
            // coding more than once to a message body"*, and curl issue 13451.
            if is_chunked
                && found
                    .is_some_and(|coding| stack.get_by_kind(coding).is_some())
            {
                ctx.trc_write(format_args!(
                    "ignoring duplicate 'chunked' decoder"
                ));
                return Ok(());
            }

            // `:768-781`: RFC 9112 section 6.1 again -- chunked must be the
            // LAST transfer coding applied, so it must be the last one added to
            // be the first in its phase. Anything after it is refused.
            if is_transfer
                && !is_chunked
                && stack.get_by_name(CHUNKED_CODING_NAME).is_some()
            {
                return Err(ctx.failf(
                    CURLcode::BadContentEncoding,
                    format_args!(
                        "Reject response due to 'chunked' not being the last \
                         Transfer-Encoding"
                    ),
                ));
            }

            // `:783-784`: *"Defer error at use."*
            let coding =
                found.unwrap_or(ClientWriterKind::ContentEncodingError);

            let Some(writer) =
                new_decoder(coding, phase, settings.http_te_skip)
            else {
                // Unreachable: `find_unencoder` answers only codings this build
                // compiled, and the deferred stage is always compiled. Answered
                // rather than panicked, since a wrong answer here would abort a
                // transfer that can still be failed cleanly.
                return Err(Error::new(CURLcode::BadContentEncoding));
            };

            // `:786`.
            let created = ClientWriterStack::create(writer, ctx);

            // `:787-788`: the trace carries the `CURLcode` as an integer, so it
            // is emitted for a failure as well as a success -- which is why the
            // result is inspected here and propagated afterwards.
            let code = match &created {
                Ok(_) => CURLcode::Ok,
                Err(err) => err.code(),
            };
            ctx.trc_write(format_args!(
                "added {word} decoder {} -> {}",
                coding.name(),
                code.as_i32()
            ));

            // `:789-790`.
            let stage = created?;

            // `:792-796`. The C frees the not-added writer explicitly; here
            // `add` has taken ownership, so a failure drops it -- and dropping
            // one of this module's stages releases exactly what its `close`
            // would, since every one of them holds only codec state.
            stack.add(stage, ctx, factory)?;

            // `:797-798`.
            if is_chunked {
                has_chunked = true;
            }
        }

        // `:800`: `while(*enclist)`.
        if at >= enclist.len() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    // `Progress`, `Clock` and `CurlTime` are named here because
    // `ClientCtx::new` -- which IS in this module's dependency set -- takes
    // them; they arrive transitively through that signature rather than as
    // dependencies of their own, and only in this test module.
    use crate::transfer::progress::Progress;
    use crate::transfer::sendf::{
        ClientCallbackGuard, ClientConfig, ClientReadSource, RequestReadState,
        RequestWriteState, TraceDataKind, TraceSink, TransferControl,
    };
    use crate::util::timeval::{CurlTime, TestClock};

    // -- the doubles ------------------------------------------------------

    /// One write that reached the recorder at the bottom of the chain.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Written {
        flags: ClientWriteFlags,
        bytes: Vec<u8>,
    }

    /// The transfer engine's operations. Nothing here calls one, and a
    /// recorder proves it.
    #[derive(Debug, Default)]
    struct Control {
        calls: usize,
    }

    impl TransferControl for Control {
        fn stream_close(&mut self, reason: &'static str) {
            let _ = reason;
            self.calls += 1;
        }

        fn conn_close(&mut self, reason: &'static str) {
            let _ = reason;
            self.calls += 1;
        }

        fn pause_send(&mut self, pause: bool) -> CurlResult<()> {
            let _ = pause;
            self.calls += 1;
            Ok(())
        }

        fn pause_recv(&mut self, pause: bool) -> CurlResult<()> {
            let _ = pause;
            self.calls += 1;
            Ok(())
        }
    }

    /// The in-callback flag. No decoder invokes an application callback, so
    /// this must never be raised.
    #[derive(Debug, Default)]
    struct Guard {
        entries: usize,
    }

    impl ClientCallbackGuard for Guard {
        fn set_in_callback(&mut self, inside: bool) {
            if inside {
                self.entries += 1;
            }
        }
    }

    /// Every diagnostic, as rendered text.
    #[derive(Debug, Default)]
    struct Trace {
        writes: Vec<String>,
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
            let _ = line;
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
                // Pinned, and never advanced: nothing in this module reads a
                // clock, and a test that failed only when the clock moved
                // would be a test of something else.
                clock: TestClock::new(CurlTime::new(1_000, 0)),
                control: Control::default(),
                guard: Guard::default(),
                trace: Trace::default(),
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

    /// One of the two stages the writer chain's base is built from, as a
    /// recorder.
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
        /// A code to fail `init` with, which is how a BASE stage refuses to be
        /// built and therefore how `ClientWriterStack::add` fails.
        refuse_init: Option<CURLcode>,
    }

    impl ClientWriter for StageWriter {
        fn kind(&self) -> ClientWriterKind {
            self.kind
        }

        fn phase(&self) -> ClientWriterPhase {
            self.phase
        }

        fn init(&mut self, ctx: &mut ClientCtx<'_>) -> CurlResult<()> {
            let _ = ctx;
            match self.refuse_init {
                Some(code) => Err(Error::new(code)),
                None => Ok(()),
            }
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

    /// The two stages `transfer/writeout.rs` owns, as recorders.
    #[derive(Debug, Default)]
    struct Factory {
        log: Rc<RefCell<Vec<Written>>>,
        /// A code the CLIENT stage refuses every write with.
        refuse: Option<CURLcode>,
        /// A code the CLIENT stage fails its `init` with, which makes the lazy
        /// base stack fail to build and therefore makes `add` fail.
        refuse_init: Option<CURLcode>,
    }

    impl Factory {
        fn refusing(code: CURLcode) -> Self {
            Self {
                log: Rc::new(RefCell::new(Vec::new())),
                refuse: Some(code),
                refuse_init: None,
            }
        }

        /// A factory whose base stage cannot be initialised.
        fn refusing_to_build(code: CURLcode) -> Self {
            Self {
                log: Rc::new(RefCell::new(Vec::new())),
                refuse: None,
                refuse_init: Some(code),
            }
        }

        /// Every body byte that reached the client, in order.
        fn body(&self) -> Vec<u8> {
            self.log
                .borrow()
                .iter()
                .filter(|write| write.flags.contains(ClientWriteFlags::BODY))
                .flat_map(|write| write.bytes.clone())
                .collect()
        }

        /// Every write that reached the client, body or not.
        fn writes(&self) -> Vec<Written> {
            self.log.borrow().clone()
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
                refuse_init: self.refuse_init,
            })
        }

        fn pause_writer(&self) -> Box<dyn ClientWriter + 'data> {
            Box::new(StageWriter {
                kind: ClientWriterKind::Pause,
                phase: ClientWriterPhase::Protocol,
                log: Rc::clone(&self.log),
                forward: true,
                refuse: None,
                refuse_init: None,
            })
        }

        fn input_source(&self) -> Option<Box<dyn ClientReadSource + 'data>> {
            None
        }
    }

    /// A chain with one decoder installed over the four base stages, driven
    /// feed by feed.
    ///
    /// The arrangement a real transfer produces: `ClientWriterStack::add`
    /// builds the base stack when the chain is empty, so a decoder installed
    /// before any write has the same stages beneath it as one installed after.
    #[derive(Debug)]
    struct Chain<'data> {
        env: Env,
        stack: ClientWriterStack<'data>,
    }

    impl<'data> Chain<'data> {
        /// Install `decoder` over the base stack that `factory` supplies.
        fn install(
            factory: &'data Factory,
            decoder: Box<dyn ClientWriter + 'data>,
        ) -> Self {
            let mut env = Env::new();
            let mut stack = ClientWriterStack::new();
            {
                let mut ctx = env.ctx();
                let stage = ClientWriterStack::create(decoder, &mut ctx)
                    .expect("a decoder initialises");
                stack
                    .add(stage, &mut ctx, factory)
                    .expect("the base stack builds");
            }
            Self { env, stack }
        }

        /// Install `decoder` WITHOUT the `create` step, so its `init` never
        /// runs.
        ///
        /// `Curl_cwriter_add` does not initialise -- only `Curl_cwriter_create`
        /// does (`lib/sendf.c:404-429` and `:452-471`) -- so this is a real
        /// arrangement of the C's own two functions, and it is the only way to
        /// observe a stage whose codec state is absent.
        ///
        /// Only a codec stage HAS state to be absent: `identity`, the deferred
        /// stage and `chunked` hold none, so this is compiled with the codecs.
        #[cfg(any(feature = "gzip", feature = "brotli", feature = "zstd"))]
        fn install_uninitialised(
            factory: &'data Factory,
            decoder: Box<dyn ClientWriter + 'data>,
        ) -> Self {
            let mut env = Env::new();
            let mut stack = ClientWriterStack::new();
            {
                let mut ctx = env.ctx();
                stack
                    .add(decoder, &mut ctx, factory)
                    .expect("the base stack builds");
            }
            Self { env, stack }
        }

        /// One `Curl_client_write` of body bytes.
        fn feed(&mut self, bytes: &[u8]) -> CurlResult<()> {
            self.write(ClientWriteFlags::BODY, bytes)
        }

        /// One write with the flags spelled out.
        fn write(
            &mut self,
            flags: ClientWriteFlags,
            bytes: &[u8],
        ) -> CurlResult<()> {
            let mut ctx = self.env.ctx();
            self.stack.write(&mut ctx, flags, bytes)
        }

        /// Feed `bytes` in pieces of `at_a_time`, stopping at the first
        /// refusal.
        ///
        /// Only a codec stage carries state across writes, so only the codec
        /// tests split a stream this way.
        #[cfg(any(feature = "gzip", feature = "brotli", feature = "zstd"))]
        fn feed_in_pieces(
            &mut self,
            bytes: &[u8],
            at_a_time: usize,
        ) -> CurlResult<()> {
            for piece in bytes.chunks(at_a_time) {
                self.feed(piece)?;
            }
            Ok(())
        }

        fn names(&self) -> Vec<&'static str> {
            self.stack.names()
        }

        fn fails(&self) -> &[String] {
            &self.env.trace.fails
        }

        /// `cl_reset_writer` (`lib/sendf.c:47-56`) through the stack, which is
        /// the only route by which a stage's `close` runs in a real transfer.
        fn close_all(&mut self) {
            let mut ctx = self.env.ctx();
            self.stack.clear(&mut ctx);
        }
    }

    /// A writer chain assembled the way a transfer assembles it: by handing a
    /// header value to [`build_unencoding_stack`], one call per header line.
    ///
    /// `lib/http.c` calls `Curl_build_unencoding_stack` once for every
    /// `Content-Encoding` or `Transfer-Encoding` line it reads, against the
    /// same stack, so [`Builder::add`] may be called more than once and the
    /// refusals that depend on what is already installed are reachable.
    #[derive(Debug)]
    struct Builder<'data> {
        env: Env,
        stack: ClientWriterStack<'data>,
    }

    impl<'data> Builder<'data> {
        fn new() -> Self {
            Self {
                env: Env::new(),
                stack: ClientWriterStack::new(),
            }
        }

        /// One `Curl_build_unencoding_stack` call, with the header value as
        /// bytes -- a header value need not be UTF-8.
        fn add_bytes(
            &mut self,
            factory: &'data Factory,
            enclist: &[u8],
            is_transfer: bool,
            settings: UnencodingSettings,
        ) -> CurlResult<()> {
            let mut ctx = self.env.ctx();
            build_unencoding_stack(
                &mut ctx,
                &mut self.stack,
                factory,
                enclist,
                is_transfer,
                settings,
            )
        }

        /// One `Curl_build_unencoding_stack` call.
        fn add(
            &mut self,
            factory: &'data Factory,
            enclist: &str,
            is_transfer: bool,
            settings: UnencodingSettings,
        ) -> CurlResult<()> {
            self.add_bytes(factory, enclist.as_bytes(), is_transfer, settings)
        }

        /// One `Curl_client_write` of body bytes.
        fn feed(&mut self, bytes: &[u8]) -> CurlResult<()> {
            let mut ctx = self.env.ctx();
            self.stack.write(&mut ctx, ClientWriteFlags::BODY, bytes)
        }

        fn names(&self) -> Vec<&'static str> {
            self.stack.names()
        }

        /// How many stages the phase's `MAX_ENCODE_STACK` count covers.
        fn count(&self, phase: ClientWriterPhase) -> usize {
            self.stack.count(phase)
        }

        fn traces(&self) -> &[String] {
            &self.env.trace.writes
        }

        fn fails(&self) -> &[String] {
            &self.env.trace.fails
        }
    }

    /// Decoding enabled at both phases and raw transfer bytes not wanted --
    /// what a handle carries with nothing set, since all three settings are
    /// `FALSE` by default (`lib/setopt.c:531-552`).
    const DEFAULT_SETTINGS: UnencodingSettings = UnencodingSettings {
        http_transfer_encoding: false,
        http_ce_skip: false,
        http_te_skip: false,
    };

    /// The plaintext every codec round-trip uses: long enough to compress,
    /// short enough to read in a failure message.
    const PLAIN: &[u8] = b"curl 8.19.0-DEV content encoding fidelity check; \
        the quick brown fox jumps over the lazy dog, repeatedly. \
        the quick brown fox jumps over the lazy dog, repeatedly.";

    // -- the registry, the token list and the capability table ------------

    #[test]
    fn the_token_list_is_exact() {
        let list = content_encodings().expect("the list fits its ceiling");

        #[cfg(all(feature = "gzip", feature = "brotli", feature = "zstd"))]
        assert_eq!(
            list, "deflate, gzip, br, zstd",
            "the default value is frozen: protocols/http1.rs writes it as \
             wire bytes"
        );

        // True in EVERY feature combination: identity is never advertised,
        // there is no leading or trailing separator, and the separator is
        // exactly a comma and a space.
        assert!(!list.contains("identity"), "{list}");
        assert!(!list.starts_with(','), "{list}");
        assert!(!list.ends_with(", "), "{list}");
        assert!(!list.contains(",,"), "{list}");
        assert!(!list.contains(" ,"), "{list}");

        // A build with no optional decoder advertises nothing at all, which
        // is the C's answer too: `identity` is the only registry row and
        // `Curl_get_content_encodings` skips it, so it returns an empty
        // (but allocated, hence non-NULL) string. `split` on an empty string
        // yields one empty field, so the per-token checks below are only
        // meaningful when at least one decoder is compiled.
        if list.is_empty() {
            assert!(
                !gzip_compiled() && !brotli_compiled() && !zstd_compiled(),
                "an empty list is only correct with no compiled decoder"
            );
            return;
        }

        for token in list.split(", ") {
            assert!(
                token.is_ascii() && !token.is_empty(),
                "every token is a non-empty ASCII name: {token:?}"
            );
        }
    }

    // -- the codec helpers -------------------------------------------------

    /// `Content-Encoding: deflate` as the standard describes it: a zlib
    /// wrapper around the deflate stream (RFC 1950), which is what
    /// `inflateInit` expects.
    #[cfg(feature = "gzip")]
    fn zlib_wrapped(plain: &[u8]) -> Vec<u8> {
        use std::io::Write;

        use flate2::write::ZlibEncoder;
        use flate2::Compression;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).expect("a Vec sink never refuses");
        encoder.finish().expect("the encoder finishes")
    }

    /// `Content-Encoding: deflate` as some servers actually send it: a bare
    /// deflate stream with no wrapper at all, which is the case the C's
    /// fallback exists for.
    #[cfg(feature = "gzip")]
    fn raw_deflate(plain: &[u8]) -> Vec<u8> {
        use std::io::Write;

        use flate2::write::DeflateEncoder;
        use flate2::Compression;

        let mut encoder =
            DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).expect("a Vec sink never refuses");
        encoder.finish().expect("the encoder finishes")
    }

    /// One gzip member: the RFC 1952 header, the deflate stream, the CRC-32 and
    /// the length.
    #[cfg(feature = "gzip")]
    fn gzip_member(plain: &[u8]) -> Vec<u8> {
        use std::io::Write;

        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plain).expect("a Vec sink never refuses");
        encoder.finish().expect("the encoder finishes")
    }

    /// A gzip member built by hand, so that the optional header fields and a
    /// deliberately wrong trailer are both reachable.
    ///
    /// `flags` is `FLG`; the optional fields are emitted in the order RFC 1952
    /// fixes, with a two-byte extra field, the name `"n"` and the comment
    /// `"c"`. When `FHCRC` is set the header CRC is computed rather than
    /// invented, so a test that wants it wrong corrupts it explicitly.
    #[cfg(feature = "gzip")]
    fn gzip_member_with(flags: u8, plain: &[u8]) -> Vec<u8> {
        let mut out = vec![
            GZIP_MAGIC[0],
            GZIP_MAGIC[1],
            GZIP_DEFLATE_METHOD,
            flags,
            0,
            0,
            0,
            0, // MTIME
            0, // XFL
            3, // OS: Unix
        ];
        if flags & GZIP_FEXTRA != 0 {
            out.extend_from_slice(&[2, 0, 0xaa, 0xbb]);
        }
        if flags & GZIP_FNAME != 0 {
            out.extend_from_slice(b"n\0");
        }
        if flags & GZIP_FCOMMENT != 0 {
            out.extend_from_slice(b"c\0");
        }
        if flags & GZIP_FHCRC != 0 {
            let mut crc = Crc::new();
            crc.update(&out);
            let sum = crc.sum() & 0xffff;
            out.push((sum & 0xff) as u8);
            out.push((sum >> 8) as u8);
        }
        out.extend_from_slice(&raw_deflate(plain));
        let mut crc = Crc::new();
        crc.update(plain);
        out.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&crc.amount().to_le_bytes());
        out
    }

    /// The `deflate` stage, at the content phase.
    #[cfg(feature = "gzip")]
    fn deflate_stage() -> Box<dyn ClientWriter + 'static> {
        Box::new(ZlibDecoder::deflate(ClientWriterPhase::ContentDecode))
    }

    /// The `gzip` stage, at the content phase.
    #[cfg(feature = "gzip")]
    fn gzip_stage() -> Box<dyn ClientWriter + 'static> {
        Box::new(ZlibDecoder::gzip(ClientWriterPhase::ContentDecode))
    }

    // -- identity ----------------------------------------------------------

    #[test]
    fn identity_forwards_every_byte_unchanged() {
        let factory = Factory::default();
        let mut chain = Chain::install(
            &factory,
            Box::new(IdentityDecoder {
                phase: ClientWriterPhase::ContentDecode,
            }),
        );
        assert_eq!(
            chain.names(),
            vec!["raw", "protocol", "cw-pause", "identity", "cw-out"],
            "a content decoder sits between the pause stage and the client"
        );
        chain.feed(PLAIN).expect("identity never fails");
        assert_eq!(factory.body(), PLAIN);
    }

    #[test]
    fn identity_forwards_metadata_and_empty_writes_with_their_flags() {
        // Every decoder in this module leaves a non-body write alone, and
        // `identity` is the one whose body writes are untouched too, so it is
        // where the flags are asserted rather than inferred.
        let factory = Factory::default();
        let mut chain = Chain::install(
            &factory,
            Box::new(IdentityDecoder {
                phase: ClientWriterPhase::ContentDecode,
            }),
        );

        let sent: [(ClientWriteFlags, &[u8]); 4] = [
            (
                ClientWriteFlags::HEADER | ClientWriteFlags::STATUS,
                b"HTTP/1.1 200 OK\x0d\x0a",
            ),
            (ClientWriteFlags::INFO, b"a pingpong reply"),
            // A zero-length body write, which must reach the client rather
            // than be swallowed: it is how end-of-stream arrives.
            (ClientWriteFlags::BODY | ClientWriteFlags::EOS, b""),
            (ClientWriteFlags::BODY, b"payload"),
        ];
        for (flags, bytes) in sent {
            chain.write(flags, bytes).expect("identity never fails");
        }

        let seen = factory.writes();
        assert_eq!(seen.len(), sent.len(), "{seen:?}");
        for (write, (flags, bytes)) in seen.iter().zip(sent) {
            assert_eq!(write.flags, flags, "{seen:?}");
            assert_eq!(write.bytes, bytes, "{seen:?}");
        }
    }

    #[test]
    fn a_downstream_refusal_comes_back_unchanged() {
        // `Curl_cwriter_write` returns the next writer's `CURLcode` as it is
        // (`lib/content_encoding.c:186-189` for the codecs, and every stage in
        // this module does the same), so a client callback's refusal must not
        // be reported as a decoding fault. `CURLE_WRITE_ERROR` is what a
        // `CURL_WRITEFUNC_ERROR` becomes by the time a decoder sees it, and
        // `CURLE_AGAIN` is what a pause becomes.
        for code in [CURLcode::WriteError, CURLcode::Again] {
            let factory = Factory::refusing(code);
            let mut chain = Chain::install(
                &factory,
                Box::new(IdentityDecoder {
                    phase: ClientWriterPhase::ContentDecode,
                }),
            );
            let failure = chain
                .feed(PLAIN)
                .expect_err("the client refused this write");
            assert_eq!(failure.code(), code);
            assert!(chain.fails().is_empty(), "{:?}", chain.fails());
        }
    }

    // -- deflate -----------------------------------------------------------

    #[cfg(feature = "gzip")]
    #[test]
    fn deflate_decodes_a_zlib_wrapped_stream() {
        let body = zlib_wrapped(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        chain.feed(&body).expect("a well formed stream decodes");
        assert_eq!(factory.body(), PLAIN);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn deflate_decodes_a_raw_stream_through_the_fallback() {
        // The broken-server case: no zlib header at all. The C resets to raw
        // and replays the same input, and so does this.
        let body = raw_deflate(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        chain.feed(&body).expect("the raw fallback decodes");
        assert_eq!(factory.body(), PLAIN);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn deflate_survives_every_split() {
        let body = zlib_wrapped(PLAIN);
        let one_shot = {
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, deflate_stage());
            chain.feed(&body).expect("one shot decodes");
            factory.body()
        };
        assert_eq!(one_shot, PLAIN);

        // EVERY piece size, so no boundary inside the stream is untested.
        for at_a_time in 1..=body.len() {
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, deflate_stage());
            chain
                .feed_in_pieces(&body, at_a_time)
                .unwrap_or_else(|err| {
                    panic!("{at_a_time}-byte pieces decode: {err}")
                });
            assert_eq!(
                factory.body(),
                one_shot,
                "{at_a_time}-byte pieces must produce the same bytes"
            );
        }
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn raw_deflate_survives_every_split_that_can_reach_the_fallback() {
        // Two bytes are enough for the codec to reject a zlib header, and the
        // retry then replays them, so every split from two upwards decodes.
        let body = raw_deflate(PLAIN);
        // Every piece size from two upwards: one-byte pieces cannot reach
        // the fallback, which the test above this one establishes.
        for at_a_time in 2..=body.len() {
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, deflate_stage());
            chain
                .feed_in_pieces(&body, at_a_time)
                .unwrap_or_else(|err| {
                    panic!("{at_a_time}-byte pieces decode: {err}")
                });
            assert_eq!(factory.body(), PLAIN, "{at_a_time}-byte pieces");
        }
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn the_raw_fallback_is_unavailable_once_input_has_been_seen() {
        // A DELIBERATE limit of the C, asserted so that it cannot be
        // "improved" into a difference. `lib/content_encoding.c:223-227`:
        //
        //   We are about to leave this call so the `nread' data bytes will not
        //   be seen again. If we are in a state that would wrongly allow
        //   restart in raw mode at the next call, assume output has already
        //   started.
        //
        // With one byte per write the codec cannot judge the zlib header on the
        // first call -- two bytes are needed -- and by the second call the state
        // has moved past `ZLIB_INIT`, so the retry is no longer permitted and
        // the transfer fails. Buffering the first byte to widen the window
        // would decode a body the C refuses.
        let body = raw_deflate(PLAIN);
        assert_ne!(
            body[0] & 0x0f,
            GZIP_DEFLATE_METHOD,
            "the fixture must not accidentally look like a zlib header"
        );

        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        let failure = chain
            .feed_in_pieces(&body, 1)
            .expect_err("one byte at a time cannot reach the fallback");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert!(
            Trace::saw(chain.fails(), UNENCODING_PREFIX),
            "the zlib diagnostic is reported: {:?}",
            chain.fails()
        );
    }

    // -- gzip --------------------------------------------------------------

    #[cfg(feature = "gzip")]
    #[test]
    fn gzip_decodes_a_member() {
        let body = gzip_member(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, gzip_stage());
        chain.feed(&body).expect("a well formed member decodes");
        assert_eq!(factory.body(), PLAIN);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn gzip_decodes_a_zlib_stream_transparently() {
        // `inflateInit2(z, MAX_WBITS + 32)` accepts either wrapper, and a
        // server that labels a zlib stream `gzip` is served rather than
        // refused.
        let body = zlib_wrapped(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, gzip_stage());
        chain.feed(&body).expect("a zlib stream decodes too");
        assert_eq!(factory.body(), PLAIN);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn gzip_survives_every_split() {
        let body = gzip_member(PLAIN);
        // Every piece size, which walks the 10-byte header, the deflate
        // stream and the 8-byte trailer past every boundary they have.
        for at_a_time in 1..=body.len() {
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, gzip_stage());
            chain
                .feed_in_pieces(&body, at_a_time)
                .unwrap_or_else(|err| {
                    panic!("{at_a_time}-byte pieces decode: {err}")
                });
            assert_eq!(
                factory.body(),
                PLAIN,
                "{at_a_time}-byte pieces must produce the same bytes"
            );
        }
    }

    // -- identity, its alias, and the deferred failure ---------------------

    #[test]
    fn identity_and_none_are_the_same_decoder() {
        for spelling in [
            &b"identity"[..],
            b"IDENTITY",
            b"Identity",
            b"none",
            b"NONE",
            b"None",
        ] {
            assert_eq!(
                find_unencoder(spelling, ClientWriterPhase::ContentDecode),
                Some(ClientWriterKind::Identity),
                "{}",
                String::from_utf8_lossy(spelling)
            );
        }
        assert_eq!(ClientWriterKind::Identity.name(), "identity");
        assert_eq!(ClientWriterKind::Identity.alias(), Some("none"));
    }

    #[test]
    fn the_deferred_stage_fails_only_on_a_nonempty_body() {
        let factory = Factory::default();
        let mut chain = Chain::install(
            &factory,
            Box::new(DeferredErrorDecoder {
                phase: ClientWriterPhase::ContentDecode,
            }),
        );
        assert_eq!(
            chain.names(),
            vec!["raw", "protocol", "cw-pause", "ce-error", "cw-out"],
            "the stage is named exactly ce-error"
        );

        // Metadata passes: a status line, a header, a trailer, an
        // informational line.
        chain
            .write(
                ClientWriteFlags::HEADER | ClientWriteFlags::STATUS,
                b"HTTP/1.1 200 OK\x0d\x0a",
            )
            .expect("a status header passes");
        chain
            .write(
                ClientWriteFlags::HEADER,
                b"Content-Encoding: nonesuch\x0d\x0a",
            )
            .expect("a header passes");
        chain
            .write(ClientWriteFlags::INFO, b"a pingpong reply")
            .expect("an informational line passes");
        chain
            .write(
                ClientWriteFlags::HEADER | ClientWriteFlags::TRAILER,
                b"Trailer: x\x0d\x0a",
            )
            .expect("a trailer passes");

        // A zero-length body write passes too, which is what lets a bodyless
        // response with an unknown coding complete normally.
        chain
            .write(ClientWriteFlags::BODY | ClientWriteFlags::EOS, b"")
            .expect("an empty body passes");
        assert!(chain.fails().is_empty(), "{:?}", chain.fails());

        // The first nonempty body write is the failure.
        let failure = chain
            .feed(b"x")
            .expect_err("a body cannot be decoded by an unknown coding");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert_eq!(failure.message(), UNRECOGNIZED_ENCODING);
        assert!(
            Trace::saw(chain.fails(), UNRECOGNIZED_ENCODING),
            "{:?}",
            chain.fails()
        );
    }

    #[test]
    fn every_compiled_coding_can_be_constructed_and_names_itself() {
        for coding in general_unencoders().chain(transfer_unencoders()) {
            let stage =
                new_decoder(coding, ClientWriterPhase::ContentDecode, false)
                    .unwrap_or_else(|| {
                        panic!(
                            "{} is advertised, so it must build",
                            coding.name()
                        )
                    });
            assert_eq!(stage.kind(), coding);
            assert_eq!(stage.name(), coding.name());
            assert_eq!(stage.alias(), coding.alias());
        }

        // The deferred stage is not in a registry and is still constructible,
        // because an unknown coding needs it.
        let deferred = new_decoder(
            ClientWriterKind::ContentEncodingError,
            ClientWriterPhase::ContentDecode,
            false,
        )
        .expect("the deferred stage always exists");
        assert_eq!(deferred.name(), "ce-error");

        // A stage another module owns is not a coding.
        assert!(new_decoder(
            ClientWriterKind::ClientOut,
            ClientWriterPhase::Client,
            false
        )
        .is_none());
    }

    #[test]
    fn a_stage_carries_the_phase_it_was_created_at() {
        // The phase decides both the insertion point and which stages the
        // MAX_ENCODE_STACK count covers, so it must not be hard-coded.
        for phase in [
            ClientWriterPhase::ContentDecode,
            ClientWriterPhase::TransferDecode,
        ] {
            for coding in general_unencoders() {
                let stage = new_decoder(coding, phase, false)
                    .expect("an advertised coding builds");
                assert_eq!(stage.phase(), phase, "{}", coding.name());
            }
        }
        // `chunked` is the one exception, and it fixes its own phase because
        // find_unencoder answers it only for the transfer phase.
        let chunked = new_decoder(
            ClientWriterKind::ChunkedDecode,
            ClientWriterPhase::ContentDecode,
            false,
        )
        .expect("chunked always exists");
        assert_eq!(chunked.phase(), ClientWriterPhase::TransferDecode);
    }

    // -- zstd --------------------------------------------------------------
    //
    // Every test below carries `#[cfg_attr(miri, ignore = ...)]`, and the
    // reason is a property of the pinned dependency rather than of this code:
    // `zstd 0.13.3` is a binding to the reference C implementation through
    // `zstd-sys`, and Miri does not execute foreign functions -- it stops with
    // *"unsupported operation: can't call foreign function `ZSTD_createDCtx`"*,
    // which is NOT a report of undefined behaviour. `.github/workflows/
    // rust-miri.yml` classifies exactly this case and names the remedy as
    // `#[cfg_attr(miri, ignore = "...")]` applied by the owner of the file,
    // which is what these are. The other two codecs need no such marking:
    // `flate2`'s `rust_backend` and `brotli` are pure Rust, so the zlib, gzip
    // and brotli stages ARE interpreted, and so is every stage-independent
    // test in this module.

    /// A zstd frame of `plain`.
    #[cfg(feature = "zstd")]
    fn zstd_frame(plain: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(plain, 3).expect("encoding in memory succeeds")
    }

    /// The `zstd` stage, at the content phase.
    #[cfg(feature = "zstd")]
    fn zstd_stage() -> Box<dyn ClientWriter + 'static> {
        Box::new(ZstdDecoder::new(ClientWriterPhase::ContentDecode))
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(miri, ignore = "zstd 0.13.3 binds C: ZSTD_createDCtx")]
    fn zstd_decodes_a_frame() {
        let body = zstd_frame(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, zstd_stage());
        assert_eq!(
            chain.names(),
            vec!["raw", "protocol", "cw-pause", "zstd", "cw-out"]
        );
        chain.feed(&body).expect("a well formed frame decodes");
        assert_eq!(factory.body(), PLAIN);
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(miri, ignore = "zstd 0.13.3 binds C: ZSTD_createDCtx")]
    fn zstd_survives_every_split() {
        let body = zstd_frame(PLAIN);
        // Every piece size.
        for at_a_time in 1..=body.len() {
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, zstd_stage());
            chain
                .feed_in_pieces(&body, at_a_time)
                .unwrap_or_else(|err| {
                    panic!("{at_a_time}-byte pieces decode: {err}")
                });
            assert_eq!(factory.body(), PLAIN, "{at_a_time}-byte pieces");
        }
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(miri, ignore = "zstd 0.13.3 binds C: ZSTD_createDCtx")]
    fn a_malformed_zstd_frame_is_a_bad_content_encoding() {
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, zstd_stage());
        // Not a zstd magic number, and not a skippable frame either, so the
        // decoder rejects it outright rather than waiting for more input.
        let failure = chain
            .feed(&[0xff; 64])
            .expect_err("a corrupt frame cannot decode");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(miri, ignore = "zstd 0.13.3 binds C: ZSTD_createDCtx")]
    fn a_truncated_zstd_frame_delivers_only_a_prefix() {
        // Truncation is not itself a codec error: the decoder simply waits for
        // the rest, and the transfer layer is what notices the response ended.
        let body = zstd_frame(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, zstd_stage());
        chain
            .feed(&body[..body.len() / 2])
            .expect("a partial frame is not a failure");
        let delivered = factory.body();
        assert!(
            PLAIN.starts_with(&delivered),
            "only a prefix of the plaintext may be delivered"
        );
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(miri, ignore = "zstd 0.13.3 binds C: ZSTD_createDCtx")]
    fn two_zstd_frames_decode_as_the_source_reads_them() {
        // `ZSTD_decompressStream` reads frame after frame, and the C refuses
        // nothing -- so a concatenation decodes rather than failing. Asserted so
        // that the difference from brotli and gzip, which DO refuse trailing
        // bytes, is deliberate rather than accidental.
        let mut body = zstd_frame(PLAIN);
        body.extend_from_slice(&zstd_frame(b"second frame"));

        let factory = Factory::default();
        let mut chain = Chain::install(&factory, zstd_stage());
        chain.feed(&body).expect("both frames decode");
        let mut expected = PLAIN.to_vec();
        expected.extend_from_slice(b"second frame");
        assert_eq!(factory.body(), expected);
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(miri, ignore = "zstd 0.13.3 binds C: ZSTD_createDCtx")]
    fn a_zstd_write_with_no_decoder_is_refused_deterministically() {
        // The state a closed -- or never initialised -- stage is in. Reached
        // here by installing WITHOUT the `create` step, because that is what
        // calls `init`; through a live chain the state is unreachable, since
        // `close` runs only as the chain is torn down. The C would hand a null
        // `ZSTD_DStream` to `ZSTD_decompressStream`, which is undefined; this
        // answers a code the caller can act on instead.
        let factory = Factory::default();
        let mut chain = Chain::install_uninitialised(
            &factory,
            Box::new(ZstdDecoder::new(ClientWriterPhase::ContentDecode)),
        );
        let failure = chain
            .feed(&zstd_frame(PLAIN))
            .expect_err("a stage with no decoder refuses");
        assert_eq!(failure.code(), CURLcode::WriteError);
    }

    // -- brotli ------------------------------------------------------------

    /// A brotli stream of `plain`.
    #[cfg(feature = "brotli")]
    fn brotli_stream(plain: &[u8]) -> Vec<u8> {
        use std::io::Write;

        use brotli::CompressorWriter;

        let mut out = Vec::new();
        {
            // Quality 5 and a 22-bit window: any legal encoder settings will
            // do, since the decoder reads the parameters from the stream.
            let mut encoder = CompressorWriter::new(&mut out, 4096, 5, 22);
            encoder.write_all(plain).expect("a Vec sink never refuses");
        }
        out
    }

    /// The `br` stage, at the content phase.
    #[cfg(feature = "brotli")]
    fn brotli_stage() -> Box<dyn ClientWriter + 'static> {
        Box::new(BrotliDecoder::new(ClientWriterPhase::ContentDecode))
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn brotli_decodes_a_stream() {
        let body = brotli_stream(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, brotli_stage());
        // `"\x62r"` IS `br`, and the escape is `sendf.rs`'s own convention for
        // this one name (`BROTLI_STAGE_NAME`): `lib.rs`'s source-policy gate
        // reads a `b`, an `r` and a quote as a raw-byte-string opener, and it
        // is deliberately conservative because the `unsafe`-keyword scan next
        // to it does not lex raw strings.
        assert_eq!(
            chain.names(),
            vec!["raw", "protocol", "cw-pause", "\x62r", "cw-out"]
        );
        chain.feed(&body).expect("a well formed stream decodes");
        assert_eq!(factory.body(), PLAIN);
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn brotli_survives_every_split() {
        let body = brotli_stream(PLAIN);
        for at_a_time in 1..=body.len() {
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, brotli_stage());
            chain
                .feed_in_pieces(&body, at_a_time)
                .unwrap_or_else(|err| {
                    panic!("{at_a_time}-byte pieces decode: {err}")
                });
            assert_eq!(factory.body(), PLAIN, "{at_a_time}-byte pieces");
        }
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn a_malformed_brotli_stream_is_a_bad_content_encoding() {
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, brotli_stage());
        // Not a brotli stream at any reading.
        let failure = chain
            .feed(&[0xff; 64])
            .expect_err("a malformed stream cannot decode");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        // `brotli_map_error` (`:359-393`) answers a CODE and says nothing.
        // The zlib stage is the only codec in the C file that reports a
        // sentence, so a brotli fault must leave the error buffer alone.
        assert!(
            chain.fails().is_empty(),
            "the C's brotli path emits no diagnostic: {:?}",
            chain.fails()
        );
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn a_brotli_write_with_no_decoder_is_refused_deterministically() {
        // `:419-420`: `if(!bp->br) return CURLE_WRITE_ERROR;` -- the C's own
        // guard, reached here by installing WITHOUT the `create` step, since
        // that is what calls `init`.
        let factory = Factory::default();
        let mut chain = Chain::install_uninitialised(
            &factory,
            Box::new(BrotliDecoder::new(ClientWriterPhase::ContentDecode)),
        );
        let failure = chain
            .feed(&brotli_stream(PLAIN))
            .expect_err("a stage with no decoder refuses");
        assert_eq!(failure.code(), CURLcode::WriteError);
        assert!(chain.fails().is_empty(), "{:?}", chain.fails());
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn bytes_after_a_completed_brotli_stream_are_a_write_error() {
        // `:439-440`: input that outlives the stream is refused rather than
        // read as a second one.
        let mut body = brotli_stream(PLAIN);
        body.extend_from_slice(b"trailing bytes");

        let factory = Factory::default();
        let mut chain = Chain::install(&factory, brotli_stage());
        let failure =
            chain.feed(&body).expect_err("trailing bytes are refused");
        assert_eq!(failure.code(), CURLcode::WriteError);
        assert_eq!(factory.body(), PLAIN);
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn a_brotli_write_after_the_stream_ended_is_a_write_error() {
        // `:419-420`: "Stream already ended."
        let body = brotli_stream(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, brotli_stage());
        chain.feed(&body).expect("the stream decodes");
        let failure =
            chain.feed(b"afterwards").expect_err("the stream has ended");
        assert_eq!(failure.code(), CURLcode::WriteError);
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn the_brotli_error_taxonomy_is_the_sources() {
        // The three classes `brotli_map_error` sorts twenty-two codes into. The
        // allocation arm is not reachable through this crate's API -- Rust's
        // allocator aborts rather than reporting -- so it is asserted here
        // rather than left to rot.
        assert_eq!(BrotliFailure::Format.code(), CURLcode::BadContentEncoding);
        assert_eq!(BrotliFailure::Allocation.code(), CURLcode::OutOfMemory);
        assert_eq!(BrotliFailure::State.code(), CURLcode::WriteError);
    }

    // -- deflate and gzip: the error paths --------------------------------

    #[cfg(feature = "gzip")]
    #[test]
    fn a_corrupt_deflate_stream_is_a_bad_content_encoding() {
        // Corrupted PAST the header, so the raw retry has already been ruled
        // out by output having started.
        let mut body = zlib_wrapped(PLAIN);
        let at = body.len() / 2;
        body[at] ^= 0xff;
        body[at + 1] ^= 0xff;

        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        let failure = chain
            .feed(&body)
            .expect_err("a corrupt stream cannot decode");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert!(
            Trace::saw(chain.fails(), UNENCODING_UNKNOWN),
            "flate2's rust backend supplies no message, so the second \
             diagnostic shape appears: {:?}",
            chain.fails()
        );
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_bad_adler32_is_a_bad_content_encoding() {
        // The zlib wrapper's own checksum, which the codec verifies. Only the
        // last four bytes are touched, so every decompressed byte is fine and
        // the stream fails at its end.
        let mut body = zlib_wrapped(PLAIN);
        let last = body.len() - 1;
        body[last] ^= 0xff;

        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        let failure = chain.feed(&body).expect_err("a bad Adler-32 is refused");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_truncated_deflate_stream_delivers_what_it_had_and_no_more() {
        // Truncation is not an error at this stage: the codec simply never
        // reports an end, and it is the transfer layer's business that the
        // response stopped early. What must NOT happen is a spurious codec
        // failure or an invented byte.
        let body = zlib_wrapped(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        chain
            .feed(&body[..body.len() - 6])
            .expect("a partial stream is not itself a failure");
        let delivered = factory.body();
        assert!(
            PLAIN.starts_with(&delivered),
            "only a prefix of the plaintext may be delivered"
        );
        assert!(chain.fails().is_empty(), "{:?}", chain.fails());
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn bytes_after_a_completed_zlib_stream_are_a_write_error() {
        // `process_trailer` (`:130-137`): *"Issue an error if unexpected bytes
        // follow."* The code is CURLE_WRITE_ERROR and NOT
        // CURLE_BAD_CONTENT_ENCODING -- the stream was well formed and what
        // followed was not part of it -- and no diagnostic accompanies it.
        let mut body = zlib_wrapped(PLAIN);
        body.extend_from_slice(b"trailing");

        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        let failure =
            chain.feed(&body).expect_err("trailing bytes are refused");
        assert_eq!(failure.code(), CURLcode::WriteError);
        assert!(chain.fails().is_empty(), "{:?}", chain.fails());
        assert_eq!(
            factory.body(),
            PLAIN,
            "every byte of the real stream is still delivered"
        );
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn the_raw_fallback_tolerates_four_trailer_bytes_and_no_more() {
        // `:209`: *"Tolerate up to 4 unknown trailer bytes."* A server that
        // omitted the zlib header often appends the Adler-32 anyway.
        let raw = raw_deflate(PLAIN);

        for extra in 0..=ZLIB_RAW_TRAILER_TOLERANCE {
            let mut body = raw.clone();
            body.extend(std::iter::repeat(0x5a).take(extra));
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, deflate_stage());
            chain
                .feed(&body)
                .unwrap_or_else(|err| panic!("{extra} trailer bytes: {err}"));
            assert_eq!(factory.body(), PLAIN, "{extra} trailer bytes");
        }

        let mut body = raw.clone();
        body.extend(
            std::iter::repeat(0x5a).take(ZLIB_RAW_TRAILER_TOLERANCE + 1),
        );
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        let failure = chain
            .feed(&body)
            .expect_err("a fifth trailer byte is one too many");
        assert_eq!(failure.code(), CURLcode::WriteError);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_trailer_split_across_writes_continues_in_the_external_state() {
        // The `ZLIB_EXTERNAL_TRAILER` path (`:140-143` and `:263-264`): the
        // tolerated trailer arrives in a later write, and the stage consumes it
        // without touching a codec it no longer has.
        let mut body = raw_deflate(PLAIN);
        body.extend_from_slice(&[1, 2, 3, 4]);
        let split = body.len() - 2;

        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        chain
            .feed(&body[..split])
            .expect("the stream and two of four");
        chain
            .feed(&body[split..])
            .expect("the last two trailer bytes");
        assert_eq!(factory.body(), PLAIN);

        // And once the stream is over, a further body write is refused.
        let failure = chain.feed(b"more").expect_err("the stream has ended");
        assert_eq!(failure.code(), CURLcode::WriteError);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_write_after_a_completed_stream_is_a_write_error() {
        for (label, body, stage) in [
            ("deflate", zlib_wrapped(PLAIN), deflate_stage()),
            ("gzip", gzip_member(PLAIN), gzip_stage()),
        ] {
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, stage);
            chain.feed(&body).expect("the stream decodes");
            assert_eq!(factory.body(), PLAIN, "{label}");
            let failure = chain
                .feed(b"afterwards")
                .expect_err("a body write after the end is refused");
            assert_eq!(failure.code(), CURLcode::WriteError, "{label}");
        }
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_second_gzip_member_is_refused_rather_than_concatenated() {
        // zlib's transparent mode does not concatenate members, and neither
        // does this: silently decoding a second one would deliver a body the
        // server never described.
        let mut body = gzip_member(PLAIN);
        body.extend_from_slice(&gzip_member(b"second"));

        let factory = Factory::default();
        let mut chain = Chain::install(&factory, gzip_stage());
        let failure =
            chain.feed(&body).expect_err("a second member is refused");
        assert_eq!(failure.code(), CURLcode::WriteError);
        assert_eq!(factory.body(), PLAIN, "the first member still arrives");
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn every_gzip_framing_fault_reports_zlibs_own_sentence() {
        let good = gzip_member(PLAIN);

        // A header whose magic is right but whose method is not.
        let mut bad_method = good.clone();
        bad_method[2] = 7;

        // A reserved FLG bit.
        let mut bad_flags = good.clone();
        bad_flags[3] = 0x80;

        // FHCRC set, with a CRC-16 that disagrees.
        let mut bad_hcrc = gzip_member_with(GZIP_FHCRC, PLAIN);
        bad_hcrc[10] ^= 0xff;

        // A CRC-32 that disagrees with the decompressed bytes.
        let mut bad_crc = good.clone();
        let crc_at = good.len() - 8;
        bad_crc[crc_at] ^= 0xff;

        // An ISIZE that disagrees with the decompressed length.
        let mut bad_len = good.clone();
        let len_at = good.len() - 4;
        bad_len[len_at] ^= 0xff;

        for (body, fault) in [
            (bad_method, GzFault::Method),
            (bad_flags, GzFault::Flags),
            (bad_hcrc, GzFault::HeaderCrc),
            (bad_crc, GzFault::DataCheck),
            (bad_len, GzFault::LengthCheck),
        ] {
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, gzip_stage());
            let failure = chain.feed(&body).unwrap_err();
            assert_eq!(
                failure.code(),
                CURLcode::BadContentEncoding,
                "{fault:?} is a malformed stream"
            );
            // The FIRST diagnostic shape, carrying the same sentence zlib
            // would have left in `strm->msg`.
            let expected = unencoding_message(Some(fault.message()));
            assert!(
                Trace::saw(chain.fails(), &expected),
                "{fault:?} must report {expected:?}, got {:?}",
                chain.fails()
            );
        }
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_bad_gzip_magic_falls_back_to_the_zlib_reading_and_fails() {
        // Neither wrapper: the first two bytes are not the gzip magic, so the
        // codec is asked for a zlib header and refuses it. zlib reaches the
        // same answer by the same route.
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, gzip_stage());
        let failure = chain
            .feed(b"\x1f\x00 not a member at all")
            .expect_err("neither wrapper matches");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_zlib_write_with_no_decoder_is_refused_deterministically() {
        // `:158-162`: the state guard admits `ZLIB_INIT`, `ZLIB_INFLATING` and
        // `ZLIB_INIT_GZIP` and answers `CURLE_WRITE_ERROR` for anything else --
        // and `gzip_do_write` reaches the same code by its own route at
        // `:330-331`. Both stages are checked, because both have the state.
        for (coding, stage) in
            [("deflate", deflate_stage()), ("gzip", gzip_stage())]
        {
            let factory = Factory::default();
            let mut chain = Chain::install_uninitialised(&factory, stage);
            let failure = chain
                .feed(&gzip_member(PLAIN))
                .expect_err("a stage with no codec refuses");
            assert_eq!(failure.code(), CURLcode::WriteError, "{coding}");
            // `exit_zlib` reports only when `inflateEnd` fails on a stream
            // that HAD been initialised, which this never was.
            assert!(chain.fails().is_empty(), "{coding}: {:?}", chain.fails());
        }
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn gzip_reads_every_optional_header_field() {
        for flags in [
            0,
            GZIP_FEXTRA,
            GZIP_FNAME,
            GZIP_FCOMMENT,
            GZIP_FHCRC,
            GZIP_FEXTRA | GZIP_FNAME,
            GZIP_FEXTRA | GZIP_FNAME | GZIP_FCOMMENT | GZIP_FHCRC,
            // FTEXT is advisory and must be ignored rather than refused.
            1,
        ] {
            let body = gzip_member_with(flags, PLAIN);
            for at_a_time in [1, 4, body.len()] {
                let factory = Factory::default();
                let mut chain = Chain::install(&factory, gzip_stage());
                chain.feed_in_pieces(&body, at_a_time).unwrap_or_else(|err| {
                    panic!("flags {flags:#04x} in {at_a_time}-byte pieces: {err}")
                });
                assert_eq!(factory.body(), PLAIN, "flags {flags:#04x}");
            }
        }
    }

    // -- the parser and the builder ----------------------------------------

    #[test]
    fn the_lookup_reads_the_transfer_registry_only_at_the_transfer_phase() {
        // `find_unencode_writer` (`:669-693`): the transfer-only registry
        // first and only in the transfer phase, then the general one.
        for spelling in [&b"chunked"[..], b"CHUNKED", b"Chunked"] {
            assert_eq!(
                find_unencoder(spelling, ClientWriterPhase::TransferDecode),
                Some(ClientWriterKind::ChunkedDecode),
                "{}",
                String::from_utf8_lossy(spelling)
            );
            assert_eq!(
                find_unencoder(spelling, ClientWriterPhase::ContentDecode),
                None,
                "Content-Encoding: chunked is not a framing instruction"
            );
        }

        // The general registry is reachable from BOTH phases.
        assert_eq!(
            find_unencoder(b"identity", ClientWriterPhase::TransferDecode),
            Some(ClientWriterKind::Identity)
        );

        // Exact length, on both registries.
        for near_miss in [&b"chunke"[..], b"chunkedx", b"chunked "] {
            assert_eq!(
                find_unencoder(near_miss, ClientWriterPhase::TransferDecode),
                None,
                "{}",
                String::from_utf8_lossy(near_miss)
            );
        }
        for near_miss in [&b"identit"[..], b"identityx", b"non", b"nonex"] {
            assert_eq!(
                find_unencoder(near_miss, ClientWriterPhase::ContentDecode),
                None,
                "{}",
                String::from_utf8_lossy(near_miss)
            );
        }
    }

    #[test]
    fn the_builder_puts_a_stage_at_the_phase_of_its_header() {
        // Content-Encoding.
        let content = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&content, "identity", false, DEFAULT_SETTINGS)
            .expect("identity is always compiled");
        assert_eq!(
            builder.names(),
            vec!["raw", "protocol", "cw-pause", "identity", "cw-out"],
            "a content decoder sits between the pause stage and the client"
        );
        assert_eq!(builder.count(ClientWriterPhase::ContentDecode), 1);
        assert_eq!(builder.count(ClientWriterPhase::TransferDecode), 0);
        drop(builder);

        // Transfer-Encoding. `chunked` is the exception that is decoded even
        // though `http_transfer_encoding` is false (`:728-730`).
        let transfer = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&transfer, "chunked", true, DEFAULT_SETTINGS)
            .expect("chunked is always compiled and always handled");
        assert_eq!(
            builder.names(),
            vec!["raw", "chunked", "protocol", "cw-pause", "cw-out"],
            "a transfer decoder sits above the protocol stage"
        );
        assert_eq!(builder.count(ClientWriterPhase::TransferDecode), 1);
        assert_eq!(builder.count(ClientWriterPhase::ContentDecode), 0);
    }

    #[test]
    fn the_tokeniser_skips_blanks_and_commas_and_trims_the_tail() {
        // `:711-718`. Leading spaces, tabs and commas are skipped; the token
        // runs to the last byte ABOVE a space, so trailing blanks and control
        // bytes fall away. Two tokens here, both `identity`.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add_bytes(
                &factory,
                b",\t , identity\t,,  none \x0d",
                false,
                DEFAULT_SETTINGS,
            )
            .expect("both tokens are identity");
        assert_eq!(
            builder.names(),
            vec![
                "raw", "protocol", "cw-pause", "identity", "identity", "cw-out"
            ]
        );
        assert!(
            Trace::saw(builder.traces(), "looking for content decoder: none"),
            "the trailing CR is trimmed off the token: {:?}",
            builder.traces()
        );
    }

    #[test]
    fn an_interior_blank_is_kept_so_the_token_matches_nothing() {
        // `"gz ip"` stays `gz ip`: the trim looks only at the tail, and the C
        // normalises nothing inside a token.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "gz ip", false, DEFAULT_SETTINGS)
            .expect("an unknown coding defers rather than refusing");
        assert_eq!(
            builder.names(),
            vec!["raw", "protocol", "cw-pause", "ce-error", "cw-out"]
        );
        assert!(
            Trace::saw(builder.traces(), "looking for content decoder: gz ip"),
            "{:?}",
            builder.traces()
        );
    }

    #[test]
    fn a_token_whose_last_byte_is_non_ascii_is_kept_and_matches_nothing() {
        // The one place the C is ambiguous: `*enclist > ' '` on a signed
        // `char` trims a byte at or above 0x80, on an unsigned one keeps it.
        // Bytes are compared here, which is the ARM reading. Either way the
        // token matches no coding; only the diagnostic differs, and it is
        // rendered lossily rather than corrupting the trace.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add_bytes(&factory, b"gzip\xff", false, DEFAULT_SETTINGS)
            .expect("an unknown coding defers rather than refusing");
        assert_eq!(
            builder.names(),
            vec!["raw", "protocol", "cw-pause", "ce-error", "cw-out"]
        );
        assert!(
            Trace::saw(
                builder.traces(),
                "looking for content decoder: gzip\u{FFFD}"
            ),
            "{:?}",
            builder.traces()
        );
    }

    #[test]
    fn a_coding_matches_case_insensitively_at_its_exact_length() {
        for spelling in ["IDENTITY", "Identity", "NoNe", "none"] {
            let factory = Factory::default();
            let mut builder = Builder::new();
            builder
                .add(&factory, spelling, false, DEFAULT_SETTINGS)
                .expect("a spelling of identity");
            assert_eq!(
                builder.names(),
                vec!["raw", "protocol", "cw-pause", "identity", "cw-out"],
                "{spelling}"
            );
        }
        // One byte too many or too few is a different coding, which is
        // unknown, which defers.
        for spelling in ["identityx", "identit", "non", "nonesuch"] {
            let factory = Factory::default();
            let mut builder = Builder::new();
            builder
                .add(&factory, spelling, false, DEFAULT_SETTINGS)
                .expect("an unknown coding defers");
            assert_eq!(
                builder.names(),
                vec!["raw", "protocol", "cw-pause", "ce-error", "cw-out"],
                "{spelling}"
            );
        }
    }

    #[test]
    fn an_unknown_coding_is_answered_ok_and_fails_only_on_a_body() {
        // `:783-784` -- *"Defer error at use."* The header is accepted, so a
        // bodyless response with an unknown coding completes normally.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "made-up-coding", false, DEFAULT_SETTINGS)
            .expect("parsing an unknown coding is not a failure");
        assert!(builder.fails().is_empty(), "{:?}", builder.fails());
        assert!(
            Trace::saw(builder.traces(), "added content decoder ce-error -> 0"),
            "{:?}",
            builder.traces()
        );

        let failure = builder
            .feed(b"x")
            .expect_err("a body cannot be decoded by an unknown coding");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert_eq!(failure.message(), UNRECOGNIZED_ENCODING);
    }

    #[test]
    fn the_last_named_coding_decodes_first() {
        // A stage joins its phase AHEAD of the stages already there
        // (`lib/sendf.c:464-469`), so the codings run in reverse of the order
        // they are written -- which is right, because `Content-Encoding: a, b`
        // means `a` was applied first and `b` second, so `b` must be undone
        // first. Two DIFFERENT stage names are needed to see the order, and
        // `identity` plus an unknown coding are the two that exist in every
        // feature combination.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(
                &factory,
                "made-up-coding, identity",
                false,
                DEFAULT_SETTINGS,
            )
            .expect("an unknown coding defers");
        assert_eq!(
            builder.names(),
            vec![
                "raw", "protocol", "cw-pause", "identity", "ce-error", "cw-out"
            ],
            "the second token's stage runs FIRST"
        );
    }

    #[test]
    fn the_fifth_decoder_at_one_phase_is_refused() {
        // `:750-754`: `count + 1 >= MAX_ENCODE_STACK` admits FOUR and refuses
        // the fifth. The off-by-one is the C's and the refusal is observable,
        // so it is reproduced rather than tidied.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(
                &factory,
                "identity, identity, identity, identity",
                false,
                DEFAULT_SETTINGS,
            )
            .expect("four decoders at one phase are admitted");
        assert_eq!(builder.count(ClientWriterPhase::ContentDecode), 4);

        let failure = builder
            .add(&factory, "identity", false, DEFAULT_SETTINGS)
            .expect_err("the fifth is refused");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert_eq!(
            failure.message(),
            "Reject response due to more than 5 content encodings"
        );
        assert_eq!(
            builder.count(ClientWriterPhase::ContentDecode),
            4,
            "the refused stage is not installed"
        );
    }

    #[test]
    fn the_fifth_decoder_in_one_header_is_refused_with_four_installed() {
        // The same guard reached inside a single header value: the first four
        // tokens are installed and the fifth ends the parse.
        let factory = Factory::default();
        let mut builder = Builder::new();
        let failure = builder
            .add(
                &factory,
                "identity, identity, identity, identity, identity",
                false,
                DEFAULT_SETTINGS,
            )
            .expect_err("five codings at one phase are refused");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert_eq!(builder.count(ClientWriterPhase::ContentDecode), 4);
    }

    #[test]
    fn the_two_phases_are_counted_separately() {
        // `Curl_cwriter_count` counts ONE phase (`lib/sendf.c:440-450`), so a
        // full content stack does not crowd out the transfer stack.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(
                &factory,
                "identity, identity, identity, identity",
                false,
                DEFAULT_SETTINGS,
            )
            .expect("four content decoders");
        builder
            .add(&factory, "chunked", true, DEFAULT_SETTINGS)
            .expect("the transfer phase has its own count");
        assert_eq!(builder.count(ClientWriterPhase::ContentDecode), 4);
        assert_eq!(builder.count(ClientWriterPhase::TransferDecode), 1);
    }

    #[test]
    fn chunked_as_a_content_coding_is_unknown_and_defers() {
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "chunked", false, DEFAULT_SETTINGS)
            .expect("an unknown content coding defers");
        assert_eq!(
            builder.names(),
            vec!["raw", "protocol", "cw-pause", "ce-error", "cw-out"],
            "chunked is not a content coding"
        );
    }

    #[test]
    fn a_duplicate_chunked_is_ignored() {
        // `:757-766`, curl issue 13451 and RFC 9112 section 6.1: *"A sender
        // MUST NOT apply the chunked transfer coding more than once to a
        // message body."* Within one header value, and across two.
        for value in ["chunked, chunked", "chunked,chunked"] {
            let factory = Factory::default();
            let mut builder = Builder::new();
            builder
                .add(&factory, value, true, DEFAULT_SETTINGS)
                .expect("a duplicate is ignored, not refused");
            assert_eq!(
                builder.count(ClientWriterPhase::TransferDecode),
                1,
                "{value}"
            );
            assert!(
                Trace::saw(
                    builder.traces(),
                    "ignoring duplicate 'chunked' decoder"
                ),
                "{:?}",
                builder.traces()
            );
        }

        let factory = Factory::default();
        let mut builder = Builder::new();
        for _ in 0..3 {
            builder
                .add(&factory, "chunked", true, DEFAULT_SETTINGS)
                .expect("a second header line is ignored too");
        }
        assert_eq!(builder.count(ClientWriterPhase::TransferDecode), 1);
    }

    #[test]
    fn a_transfer_coding_after_an_installed_chunked_is_refused() {
        // `:768-781`: `chunked` must be the last coding APPLIED, so it must be
        // the first in its phase; a coding that would land ahead of it is
        // refused. `http_transfer_encoding` is set so the coding reaches this
        // check rather than the not-requested branch.
        let asked = UnencodingSettings {
            http_transfer_encoding: true,
            ..DEFAULT_SETTINGS
        };
        let factory = Factory::default();
        let mut builder = Builder::new();
        let failure = builder
            .add(&factory, "chunked, made-up-coding", true, asked)
            .expect_err("a coding after chunked cannot be stacked");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert_eq!(
            failure.message(),
            "Reject response due to 'chunked' not being the last \
             Transfer-Encoding"
        );
        assert_eq!(
            builder.count(ClientWriterPhase::TransferDecode),
            1,
            "chunked stays, the refused coding is not installed"
        );
    }

    #[test]
    fn an_unsolicited_transfer_coding_is_refused() {
        // `:743-745`. Nothing but `chunked` was asked for, so a transfer
        // coding that arrives anyway is a failure rather than a decode.
        let factory = Factory::default();
        let mut builder = Builder::new();
        let failure = builder
            .add(&factory, "made-up-coding", true, DEFAULT_SETTINGS)
            .expect_err("an unsolicited transfer coding is refused");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert_eq!(
            failure.message(),
            "Unsolicited Transfer-Encoding (made-up-coding) found"
        );
        assert!(
            Trace::saw(
                builder.traces(),
                "decoder not requested, ignored: made-up-coding"
            ),
            "{:?}",
            builder.traces()
        );
    }

    #[test]
    fn an_unsolicited_coding_after_chunked_names_chunked_in_the_refusal() {
        // `:737-739`: the same branch, but `chunked` came first in THIS
        // header, so the message is the more specific one.
        let factory = Factory::default();
        let mut builder = Builder::new();
        let failure = builder
            .add(&factory, "chunked, made-up-coding", true, DEFAULT_SETTINGS)
            .expect_err("a coding listed after chunked is refused");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert_eq!(
            failure.message(),
            "A Transfer-Encoding (made-up-coding) was listed after chunked"
        );
    }

    #[test]
    fn identity_is_ignored_in_the_skip_branch_and_the_list_continues() {
        // `:740-741`: `identity` transforms nothing, so an unsolicited
        // `identity` is ignored and the REST of the list is still examined --
        // the one `continue` in the branch.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "identity, chunked", true, DEFAULT_SETTINGS)
            .expect("identity is ignored and chunked is still installed");
        assert_eq!(builder.count(ClientWriterPhase::TransferDecode), 1);
        assert_eq!(
            builder.names(),
            vec!["raw", "chunked", "protocol", "cw-pause", "cw-out"]
        );
        assert!(
            Trace::saw(
                builder.traces(),
                "decoder not requested, ignored: identity"
            ),
            "{:?}",
            builder.traces()
        );
    }

    #[test]
    fn the_identity_test_in_the_skip_branch_reads_eight_bytes_from_the_token() {
        // `:732`: `curl_strnequal(name, "identity", 8)` compares eight bytes
        // from the token's START rather than the token, so `identityfoo`
        // counts as identity here even though it matches no coding. The quirk
        // is observable -- it decides refusal against `continue` -- so it is
        // reproduced.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "identityfoo, chunked", true, DEFAULT_SETTINGS)
            .expect("identityfoo passes the eight-byte test");
        assert_eq!(builder.count(ClientWriterPhase::TransferDecode), 1);

        // A token too short for the comparison to succeed is refused. The C
        // reads past the token into the rest of the header, and so does this.
        let factory = Factory::default();
        let mut builder = Builder::new();
        let failure = builder
            .add(&factory, "ident, chunked", true, DEFAULT_SETTINGS)
            .expect_err("ident is not identity");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert_eq!(
            failure.message(),
            "Unsolicited Transfer-Encoding (ident) found"
        );
    }

    #[test]
    fn http_te_skip_abandons_the_rest_of_the_transfer_list() {
        // `:747`: once decoding is not wanted at this phase the whole value is
        // abandoned -- a `return`, not a `continue` -- so a `chunked` behind an
        // ignored coding is never installed.
        let raw_wanted = UnencodingSettings {
            http_te_skip: true,
            ..DEFAULT_SETTINGS
        };
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "made-up-coding, chunked", true, raw_wanted)
            .expect("raw transfer bytes were asked for, so nothing is refused");
        assert_eq!(builder.count(ClientWriterPhase::TransferDecode), 0);
        assert!(builder.names().is_empty(), "{:?}", builder.names());
        assert!(builder.fails().is_empty(), "{:?}", builder.fails());
    }

    #[test]
    fn http_ce_skip_abandons_the_content_list() {
        // The same `return` on the content side, which is what
        // `CURLOPT_HTTP_CONTENT_DECODING: 0` produces
        // (`lib/setopt.c:546-552`).
        let raw_wanted = UnencodingSettings {
            http_ce_skip: true,
            ..DEFAULT_SETTINGS
        };
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "made-up-coding, identity", false, raw_wanted)
            .expect("the content list is abandoned, not refused");
        assert!(builder.names().is_empty(), "{:?}", builder.names());
        assert!(builder.fails().is_empty(), "{:?}", builder.fails());
        assert!(
            Trace::saw(
                builder.traces(),
                "decoder not requested, ignored: made-up-coding"
            ),
            "{:?}",
            builder.traces()
        );
    }

    #[test]
    fn a_transfer_coding_is_decoded_when_it_was_asked_for() {
        // `CURLOPT_TRANSFER_ENCODING: 1` (`lib/setopt.c:531-533`) is the
        // setting that turns the not-requested branch off, so an unknown
        // coding then reaches the deferred stage instead of being refused.
        let asked = UnencodingSettings {
            http_transfer_encoding: true,
            ..DEFAULT_SETTINGS
        };
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "made-up-coding", true, asked)
            .expect("an asked-for coding defers rather than refusing");
        assert_eq!(
            builder.names(),
            vec!["raw", "ce-error", "protocol", "cw-pause", "cw-out"],
            "the deferred stage joins the TRANSFER phase"
        );
        assert_eq!(builder.count(ClientWriterPhase::TransferDecode), 1);
    }

    #[test]
    fn an_empty_or_separator_only_value_installs_nothing() {
        // `:705` with `:800` is a do-while, so an empty value performs one
        // pass, finds no token, and stops.
        for value in ["", " ", ",", "  , ,\t,  ", "\x0d\x0a"] {
            let factory = Factory::default();
            let mut builder = Builder::new();
            builder
                .add(&factory, value, false, DEFAULT_SETTINGS)
                .unwrap_or_else(|err| {
                    panic!("{value:?} is not a failure: {err}")
                });
            assert!(builder.names().is_empty(), "{value:?}");
            assert!(builder.traces().is_empty(), "{value:?}");
        }
    }

    #[test]
    fn the_builder_traces_the_sources_three_shapes() {
        // `:724-725`, `:734-735` and `:787-788`. The third carries the
        // `CURLcode` as an integer, and zero is success.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "identity", false, DEFAULT_SETTINGS)
            .expect("identity installs");
        assert!(
            Trace::saw(
                builder.traces(),
                "looking for content decoder: identity"
            ) && Trace::saw(
                builder.traces(),
                "added content decoder identity -> 0"
            ),
            "{:?}",
            builder.traces()
        );

        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "chunked", true, DEFAULT_SETTINGS)
            .expect("chunked installs");
        assert!(
            Trace::saw(
                builder.traces(),
                "looking for transfer decoder: chunked"
            ) && Trace::saw(
                builder.traces(),
                "added transfer decoder chunked -> 0"
            ),
            "{:?}",
            builder.traces()
        );
    }

    // -- bounded buffering, at the source's own limits ----------------------

    #[test]
    fn the_deepest_admitted_stack_passes_a_body_through() {
        // Four stages at one phase is what `count + 1 >= MAX_ENCODE_STACK`
        // admits, and every build has four `identity` stages available. Proves
        // the depth is reachable and that a chain that deep still delivers.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(
                &factory,
                "identity, identity, identity, identity",
                false,
                DEFAULT_SETTINGS,
            )
            .expect("four stages are admitted");
        assert_eq!(builder.count(ClientWriterPhase::ContentDecode), 4);
        builder.feed(PLAIN).expect("a four-deep chain delivers");
        assert_eq!(factory.body(), PLAIN);
    }

    /// A body that expands enormously: 512 KiB from a few compressed bytes.
    ///
    /// Named rather than inlined because two tests need the same shape, and
    /// because the POINT of the fixture is the expansion ratio.
    #[cfg(feature = "gzip")]
    fn highly_compressible() -> Vec<u8> {
        // A repeating pattern rather than a run of zeros, so the deflate
        // stream exercises back-references rather than a single stored block.
        b"curl-rs "
            .iter()
            .copied()
            .cycle()
            .take(512 * 1024)
            .collect()
    }

    #[cfg(feature = "gzip")]
    #[test]
    #[cfg_attr(miri, ignore = "decodes 512 KiB, minutes under interpretation")]
    fn a_hugely_expanding_body_is_forwarded_in_bounded_pieces() {
        // The one memory limit the C has is the fixed output window
        // (`:170-174`), and this is what it buys: 512 KiB of plaintext reaches
        // the client in pieces no larger than the window, from an input of a
        // few hundred bytes, with nothing accumulated in between.
        let plain = highly_compressible();
        let body = gzip_member(&plain);
        assert!(
            body.len() * 100 < plain.len(),
            "the fixture must expand by more than a hundredfold: {} -> {}",
            body.len(),
            plain.len()
        );

        let factory = Factory::default();
        let mut chain = Chain::install(&factory, gzip_stage());
        chain.feed(&body).expect("the member decodes");
        assert_eq!(factory.body(), plain);

        let writes = factory.writes();
        assert!(
            writes
                .iter()
                .all(|write| write.bytes.len() <= DECOMPRESS_BUFFER_SIZE),
            "every forwarded piece fits the window: {:?}",
            writes.iter().map(|w| w.bytes.len()).max()
        );
        assert!(
            writes.len() >= plain.len() / DECOMPRESS_BUFFER_SIZE,
            "a body {} bytes long cannot arrive in {} writes of at most {} \
             bytes, so it was NOT buffered whole",
            plain.len(),
            writes.len(),
            DECOMPRESS_BUFFER_SIZE
        );
    }

    #[cfg(feature = "gzip")]
    #[test]
    #[cfg_attr(miri, ignore = "decodes 512 KiB, minutes under interpretation")]
    fn the_deepest_admitted_codec_stack_stays_bounded() {
        // Four gzip stages -- the deepest the guard admits -- over a body that
        // was gzipped four times. Each stage holds one window, so the whole
        // chain holds four, whatever the expansion is; and each forwards in
        // window-sized pieces, so no stage accumulates its successor's input.
        let plain = highly_compressible();
        let mut body = plain.clone();
        for _ in 0..4 {
            body = gzip_member(&body);
        }

        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "gzip, gzip, gzip, gzip", false, DEFAULT_SETTINGS)
            .expect("four stages are admitted");
        assert_eq!(builder.count(ClientWriterPhase::ContentDecode), 4);
        assert_eq!(
            builder.names(),
            vec![
                "raw", "protocol", "cw-pause", "gzip", "gzip", "gzip", "gzip",
                "cw-out"
            ]
        );

        // Fed in window-sized pieces, which is how a transfer delivers it.
        for piece in body.chunks(DECOMPRESS_BUFFER_SIZE) {
            builder.feed(piece).expect("a four-deep gzip chain decodes");
        }
        assert_eq!(factory.body(), plain);

        let writes = factory.writes();
        assert!(
            writes
                .iter()
                .all(|write| write.bytes.len() <= DECOMPRESS_BUFFER_SIZE),
            "every forwarded piece fits the window: {:?}",
            writes.iter().map(|w| w.bytes.len()).max()
        );
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_fifth_stage_is_still_refused_at_the_codec_depth() {
        // The guard is the only stack limit, so it is asserted with real
        // codecs as well as with `identity`: nothing about a codec stage
        // changes the count.
        let factory = Factory::default();
        let mut builder = Builder::new();
        let failure = builder
            .add(
                &factory,
                "gzip, gzip, gzip, gzip, gzip",
                false,
                DEFAULT_SETTINGS,
            )
            .expect_err("the fifth stage is refused");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert_eq!(builder.count(ClientWriterPhase::ContentDecode), 4);
    }

    // -- the mandated inventory: order, truthfulness, aliases, stacking -----

    #[test]
    fn the_token_list_keeps_its_relative_order_in_every_feature_build() {
        // `Curl_get_content_encodings` walks the registry in order and skips
        // `identity` (`:616-624`), so the value is determined by which
        // decoders are compiled -- and the RELATIVE order never changes.
        // Building the expectation from the same `cfg!` flags the registry
        // uses makes this one test assert all eight feature builds.
        let mut expected: Vec<&str> = Vec::new();
        if gzip_compiled() {
            expected.push("deflate");
            expected.push("gzip");
        }
        if brotli_compiled() {
            // `"\x62r"` is `br`; see the note in `brotli_decodes_a_stream`.
            expected.push("\x62r");
        }
        if zstd_compiled() {
            expected.push("zstd");
        }

        assert_eq!(
            content_encodings().expect("the list fits its ceiling"),
            expected.join(", "),
            "the order is deflate, gzip, br, zstd with the absent ones removed"
        );
    }

    #[test]
    fn the_capability_table_and_the_registry_agree() {
        // The truthfulness coupling `version.rs` depends on: a decoder that is
        // not compiled must vanish from the registry, the token list, the
        // feature NAME and the feature BIT together. Over-reporting turns a
        // clean fixture skip into a fixture failure, so the four must never
        // drift apart.
        let list = content_encodings().expect("the list fits its ceiling");
        assert_eq!(DECODER_CAPABILITIES.len(), 3, "libz, brotli, zstd");

        for capability in DECODER_CAPABILITIES {
            let coding = capability.coding();
            let in_registry =
                general_unencoders().any(|advertised| advertised == coding);
            let named = list.split(", ").any(|token| token == coding.name());

            assert_eq!(
                capability.is_compiled(),
                in_registry,
                "{}: the capability table and the registry disagree",
                capability.name()
            );
            assert_eq!(
                capability.is_compiled(),
                named,
                "{}: the capability table and the token list disagree",
                capability.name()
            );

            if capability.is_compiled() {
                // An advertised decoder must actually build.
                let stage = new_decoder(
                    coding,
                    ClientWriterPhase::ContentDecode,
                    false,
                )
                .unwrap_or_else(|| panic!("{} must build", capability.name()));
                assert_eq!(stage.kind(), coding);
                // And be reachable by name, which is what a header carries.
                assert_eq!(
                    find_unencoder(
                        coding.name().as_bytes(),
                        ClientWriterPhase::ContentDecode
                    ),
                    Some(coding)
                );
            } else {
                assert!(
                    new_decoder(
                        coding,
                        ClientWriterPhase::ContentDecode,
                        false
                    )
                    .is_none(),
                    "{} is not compiled, so it must not build",
                    capability.name()
                );
                assert_eq!(
                    find_unencoder(
                        coding.name().as_bytes(),
                        ClientWriterPhase::ContentDecode
                    ),
                    None,
                    "{} is not compiled, so its name must not resolve",
                    capability.name()
                );
            }
        }

        // The three names and the three bits, exactly as `lib/version.c` and
        // `include/curl/curl.h` spell them. Written out rather than derived,
        // because a derived assertion cannot catch a wrong constant.
        let rows: Vec<(&str, i32, bool)> = DECODER_CAPABILITIES
            .iter()
            .map(|c| (c.name(), c.bitmask(), c.is_compiled()))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("libz", 1 << 3, gzip_compiled()),
                ("brotli", 1 << 23, brotli_compiled()),
                ("zstd", 1 << 26, zstd_compiled()),
            ]
        );
        assert_eq!(
            rows.iter().map(|(_, bit, _)| *bit).collect::<Vec<_>>(),
            vec![
                crate::version::CURL_VERSION_LIBZ,
                crate::version::CURL_VERSION_BROTLI,
                crate::version::CURL_VERSION_ZSTD,
            ],
            "the bits must be the ones version.rs publishes"
        );
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn x_gzip_selects_the_gzip_stage_and_decodes() {
        // `gzip_encoding`'s alias (`:341-348`), matched case-insensitively at
        // its exact length like every other name.
        for spelling in [&b"x-gzip"[..], b"X-GZIP", b"X-Gzip"] {
            assert_eq!(
                find_unencoder(spelling, ClientWriterPhase::ContentDecode),
                Some(ClientWriterKind::Gzip),
                "{}",
                String::from_utf8_lossy(spelling)
            );
        }
        for near_miss in [&b"x-gzi"[..], b"x-gzipp", b"xgzip"] {
            assert_eq!(
                find_unencoder(near_miss, ClientWriterPhase::ContentDecode),
                None,
                "{}",
                String::from_utf8_lossy(near_miss)
            );
        }

        // End to end through the builder, with the casing a server might send.
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, " X-Gzip ", false, DEFAULT_SETTINGS)
            .expect("x-gzip is gzip");
        assert_eq!(
            builder.names(),
            vec!["raw", "protocol", "cw-pause", "gzip", "cw-out"],
            "the stage is named by its CANONICAL name, not by the alias"
        );
        builder
            .feed(&gzip_member(PLAIN))
            .expect("the member decodes");
        assert_eq!(factory.body(), PLAIN);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn stacked_gzip_and_deflate_decode_in_reverse_order() {
        // The mission's named case. `Content-Encoding: gzip, deflate` means
        // gzip was applied FIRST and deflate SECOND, so the body is a zlib
        // stream wrapping a gzip member, and it must be undone deflate first.
        let body = zlib_wrapped(&gzip_member(PLAIN));

        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "gzip, deflate", false, DEFAULT_SETTINGS)
            .expect("both codings are compiled");
        assert_eq!(
            builder.names(),
            vec!["raw", "protocol", "cw-pause", "deflate", "gzip", "cw-out"],
            "deflate runs FIRST even though gzip is written first"
        );
        assert_eq!(builder.count(ClientWriterPhase::ContentDecode), 2);

        for piece in body.chunks(7) {
            builder.feed(piece).expect("a stacked chain decodes");
        }
        assert_eq!(factory.body(), PLAIN);

        // And the reverse header is the reverse arrangement, which decodes the
        // reverse body -- so the order is genuinely load-bearing.
        let swapped = gzip_member(&zlib_wrapped(PLAIN));
        let factory = Factory::default();
        let mut builder = Builder::new();
        builder
            .add(&factory, "deflate, gzip", false, DEFAULT_SETTINGS)
            .expect("both codings are compiled");
        assert_eq!(
            builder.names(),
            vec!["raw", "protocol", "cw-pause", "gzip", "deflate", "cw-out"]
        );
        builder.feed(&swapped).expect("a stacked chain decodes");
        assert_eq!(factory.body(), PLAIN);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_stream_split_around_its_checksum_decodes() {
        // The bytes most likely to be mishandled are the ones after the last
        // compressed byte, so every split point inside the trailer is checked:
        // gzip's CRC-32 and ISIZE (eight bytes) and zlib's Adler-32 (four).
        for body in [gzip_member(PLAIN), zlib_wrapped(PLAIN)] {
            // A zlib header names deflate in its low nibble; a gzip member
            // starts with 0x1f, whose low nibble is 0x0f.
            let is_zlib = body[0] & 0x0f == GZIP_DEFLATE_METHOD;
            for split in (body.len().saturating_sub(12))..=body.len() {
                let factory = Factory::default();
                let mut chain = Chain::install(
                    &factory,
                    if is_zlib {
                        deflate_stage()
                    } else {
                        gzip_stage()
                    },
                );
                chain.feed(&body[..split]).unwrap_or_else(|err| {
                    panic!("split at {split} of {}: {err}", body.len())
                });
                if split < body.len() {
                    chain.feed(&body[split..]).unwrap_or_else(|err| {
                        panic!("split at {split} of {}: {err}", body.len())
                    });
                }
                assert_eq!(
                    factory.body(),
                    PLAIN,
                    "split at {split} of {}",
                    body.len()
                );
            }
        }
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn an_invalid_raw_deflate_stream_is_a_bad_content_encoding() {
        // Neither reading works: `0x06` is not a zlib CM of 8 and the two-byte
        // header fails the modulo-31 check, so the raw retry fires -- and the
        // same first byte carries BTYPE 3, which is the reserved block type,
        // so raw inflate refuses it too.
        let body = [0x06_u8, 0x00, 0x00, 0x00];
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, deflate_stage());
        let failure = chain
            .feed(&body)
            .expect_err("neither the zlib nor the raw reading works");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
        assert!(factory.body().is_empty(), "nothing may be delivered");
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_downstream_refusal_through_the_zlib_stage_is_unchanged() {
        // `:186-189`: the decoder returns the next writer's code as it is.
        // Asserted through a CODEC, not only through `identity`, because the
        // zlib stage has an error path of its own that must not swallow it.
        for code in [CURLcode::WriteError, CURLcode::Again] {
            let factory = Factory::refusing(code);
            let mut chain = Chain::install(&factory, gzip_stage());
            let failure = chain
                .feed(&gzip_member(PLAIN))
                .expect_err("the client refused this write");
            assert_eq!(failure.code(), code);
            assert!(
                chain.fails().is_empty(),
                "a refusal is not a decoding fault: {:?}",
                chain.fails()
            );
        }
    }

    #[cfg(feature = "brotli")]
    #[test]
    fn a_downstream_refusal_through_the_brotli_stage_is_unchanged() {
        for code in [CURLcode::WriteError, CURLcode::Again] {
            let factory = Factory::refusing(code);
            let mut chain = Chain::install(&factory, brotli_stage());
            let failure = chain
                .feed(&brotli_stream(PLAIN))
                .expect_err("the client refused this write");
            assert_eq!(failure.code(), code);
        }
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(miri, ignore = "zstd 0.13.3 binds C: ZSTD_createDCtx")]
    fn a_downstream_refusal_through_the_zstd_stage_is_unchanged() {
        for code in [CURLcode::WriteError, CURLcode::Again] {
            let factory = Factory::refusing(code);
            let mut chain = Chain::install(&factory, zstd_stage());
            let failure = chain
                .feed(&zstd_frame(PLAIN))
                .expect_err("the client refused this write");
            assert_eq!(failure.code(), code);
        }
    }

    #[test]
    fn a_downstream_refusal_through_the_deferred_stage_is_its_own() {
        // The one stage that must NOT forward a body: it fails before the tail
        // is reached, so the refusal downstream is never consulted.
        let factory = Factory::refusing(CURLcode::WriteError);
        let mut chain = Chain::install(
            &factory,
            Box::new(DeferredErrorDecoder {
                phase: ClientWriterPhase::ContentDecode,
            }),
        );
        let failure = chain.feed(b"x").expect_err("an unknown coding fails");
        assert_eq!(failure.code(), CURLcode::BadContentEncoding);
    }

    // -- the remaining branches: pass-through, close, and the builder's
    //    propagation of a stage that cannot be built ------------------------

    #[test]
    fn every_stage_passes_metadata_and_empty_writes_straight_through() {
        // `if(!(type & CLIENTWRITE_BODY) || !nbytes)` is the FIRST statement of
        // every `do_write` in the C file (`:256`, `:316`, `:416`, `:524` and
        // `:647`), so it is asserted for every compiled stage rather than for
        // `identity` alone: a decoder that fed a header to its codec would
        // corrupt both, and one that swallowed the empty end-of-stream write
        // would strand the client.
        //
        // Each stage is checked by a call rather than collected into a list,
        // so that a build with no codec feature compiles the same code.
        fn passes(stage: Box<dyn ClientWriter + 'static>) {
            let name = stage.name();
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, stage);

            let sent: [(ClientWriteFlags, &[u8]); 4] = [
                (
                    ClientWriteFlags::HEADER | ClientWriteFlags::STATUS,
                    b"HTTP/1.1 200 OK\x0d\x0a",
                ),
                (
                    ClientWriteFlags::HEADER | ClientWriteFlags::TRAILER,
                    b"Trailer: x\x0d\x0a",
                ),
                (ClientWriteFlags::INFO, b"a pingpong reply"),
                (ClientWriteFlags::BODY | ClientWriteFlags::EOS, b""),
            ];
            for (flags, bytes) in sent {
                chain
                    .write(flags, bytes)
                    .unwrap_or_else(|err| panic!("{name}: {err}"));
            }

            let seen = factory.writes();
            assert_eq!(seen.len(), sent.len(), "{name}: {seen:?}");
            for (write, (flags, bytes)) in seen.iter().zip(sent) {
                assert_eq!(write.flags, flags, "{name}");
                assert_eq!(write.bytes, bytes, "{name}");
            }
            assert!(chain.fails().is_empty(), "{name}: {:?}", chain.fails());
        }

        passes(Box::new(IdentityDecoder {
            phase: ClientWriterPhase::ContentDecode,
        }));
        passes(Box::new(DeferredErrorDecoder {
            phase: ClientWriterPhase::ContentDecode,
        }));
        #[cfg(feature = "gzip")]
        {
            passes(deflate_stage());
            passes(gzip_stage());
        }
        #[cfg(feature = "brotli")]
        passes(brotli_stage());
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(miri, ignore = "zstd 0.13.3 binds C: ZSTD_createDCtx")]
    fn the_zstd_stage_passes_metadata_and_empty_writes_through() {
        // `:524-525`, separately from the test above because a zstd stage
        // cannot be constructed under interpretation.
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, zstd_stage());
        chain
            .write(ClientWriteFlags::HEADER, b"Content-Encoding: zstd\x0d\x0a")
            .expect("a header passes");
        chain
            .write(ClientWriteFlags::BODY | ClientWriteFlags::EOS, b"")
            .expect("an empty body passes");
        let seen = factory.writes();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert_eq!(seen[0].bytes, b"Content-Encoding: zstd\x0d\x0a");
        assert!(seen[1].bytes.is_empty());
    }

    #[test]
    fn closing_a_chain_mid_stream_releases_every_codec() {
        // `deflate_do_close`, `gzip_do_close`, `brotli_do_close` and
        // `zstd_do_close` (`:270-277`, `:322-328`, `:450-460`, `:553-563`) all
        // release codec state, and `exit_zlib` additionally reports an
        // `inflateEnd` that fails. Rust ownership does the releasing, so what
        // is asserted is that closing a HALF-FED chain is clean, says nothing,
        // and is idempotent -- `cl_reset_writer` may run twice on a handle that
        // is reset and then torn down.
        fn closes(stage: Box<dyn ClientWriter + 'static>, prefix: &[u8]) {
            let name = stage.name();
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, stage);
            if !prefix.is_empty() {
                chain
                    .feed(prefix)
                    .unwrap_or_else(|err| panic!("{name}: {err}"));
            }
            chain.close_all();
            assert!(chain.names().is_empty(), "{name}: {:?}", chain.names());
            // Idempotent: a second reset has nothing to close and must not
            // panic.
            chain.close_all();
            assert!(chain.fails().is_empty(), "{name}: {:?}", chain.fails());
        }

        closes(
            Box::new(IdentityDecoder {
                phase: ClientWriterPhase::ContentDecode,
            }),
            PLAIN,
        );
        closes(
            Box::new(DeferredErrorDecoder {
                phase: ClientWriterPhase::ContentDecode,
            }),
            b"",
        );
        #[cfg(feature = "gzip")]
        {
            // Half of a stream each: the codec is mid-inflate when it is
            // dropped, which is the state a cancelled transfer leaves.
            let zlib = zlib_wrapped(PLAIN);
            closes(deflate_stage(), &zlib[..zlib.len() / 2]);
            let member = gzip_member(PLAIN);
            closes(gzip_stage(), &member[..member.len() / 2]);
        }
        #[cfg(feature = "brotli")]
        {
            let stream = brotli_stream(PLAIN);
            closes(brotli_stage(), &stream[..stream.len() / 2]);
        }
    }

    #[cfg(feature = "zstd")]
    #[test]
    #[cfg_attr(miri, ignore = "zstd 0.13.3 binds C: ZSTD_createDCtx")]
    fn closing_a_zstd_chain_mid_stream_releases_the_decoder() {
        let frame = zstd_frame(PLAIN);
        let factory = Factory::default();
        let mut chain = Chain::install(&factory, zstd_stage());
        chain
            .feed(&frame[..frame.len() / 2])
            .expect("a partial frame is not a failure");
        chain.close_all();
        assert!(chain.names().is_empty(), "{:?}", chain.names());
        chain.close_all();
    }

    #[test]
    fn every_stage_renders_its_own_debug() {
        // Each codec stage holds state that implements no `Debug` and a 16 KiB
        // window, so all three write the impl by hand. A `{:?}` that panicked,
        // or that rendered the window element by element, would be found only
        // by somebody trying to debug something else -- and
        // `ClientWriterStack` derives its own `Debug` over every stage, so one
        // chain would carry it several times over.
        fn summarises(label: &str, text: &str) {
            assert!(!text.is_empty(), "{label}");
            assert!(
                text.len() < 512,
                "{label} must summarise its state rather than dump the \
                 window: {} bytes",
                text.len()
            );
            assert!(
                text.contains("Decoder"),
                "{label} must name its type: {text}"
            );
        }

        summarises(
            "identity",
            &format!(
                "{:?}",
                IdentityDecoder {
                    phase: ClientWriterPhase::ContentDecode
                }
            ),
        );
        summarises(
            "ce-error",
            &format!(
                "{:?}",
                DeferredErrorDecoder {
                    phase: ClientWriterPhase::ContentDecode
                }
            ),
        );
        #[cfg(feature = "gzip")]
        {
            summarises(
                "deflate",
                &format!(
                    "{:?}",
                    ZlibDecoder::deflate(ClientWriterPhase::ContentDecode)
                ),
            );
            summarises(
                "gzip",
                &format!(
                    "{:?}",
                    ZlibDecoder::gzip(ClientWriterPhase::ContentDecode)
                ),
            );
        }
        #[cfg(feature = "brotli")]
        summarises(
            "brotli",
            &format!(
                "{:?}",
                BrotliDecoder::new(ClientWriterPhase::ContentDecode)
            ),
        );
        #[cfg(feature = "zstd")]
        summarises(
            "zstd",
            &format!(
                "{:?}",
                ZstdDecoder::new(ClientWriterPhase::ContentDecode)
            ),
        );
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn every_zlib_sentence_is_the_one_zlib_would_have_left() {
        // `GzFault::message` supplies what `strm->msg` would have held, which
        // `process_zlib_error` (`:100-110`) then prefixes. The six sentences
        // are zlib's own, from `inflate.c`, and they are frozen: a fixture that
        // matches on stderr would see any rewording.
        assert_eq!(GzFault::Header.message(), "incorrect header check");
        assert_eq!(GzFault::Method.message(), "unknown compression method");
        assert_eq!(GzFault::Flags.message(), "unknown header flags set");
        assert_eq!(GzFault::HeaderCrc.message(), "header crc mismatch");
        assert_eq!(GzFault::DataCheck.message(), "incorrect data check");
        assert_eq!(GzFault::LengthCheck.message(), "incorrect length check");

        // And the two shapes the prefix produces, since the message function
        // is what decides between them (`:103` against `:106-107`).
        assert_eq!(
            unencoding_message(Some(GzFault::DataCheck.message())),
            "Error while processing content unencoding: incorrect data check"
        );
        assert_eq!(
            unencoding_message(None),
            "Error while processing content unencoding: Unknown failure \
             within decompression software."
        );
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn a_gzip_member_with_an_empty_extra_field_decodes() {
        // `XLEN == 0` with `FEXTRA` set: RFC 1952 permits it, and the header
        // machine must move straight to the next field rather than wait for a
        // byte that never comes.
        let mut body = vec![
            GZIP_MAGIC[0],
            GZIP_MAGIC[1],
            GZIP_DEFLATE_METHOD,
            GZIP_FEXTRA | GZIP_FNAME,
            0,
            0,
            0,
            0, // MTIME
            0, // XFL
            3, // OS
            0,
            0, // XLEN = 0
        ];
        body.extend_from_slice(b"name\0");
        body.extend_from_slice(&raw_deflate(PLAIN));
        let mut crc = Crc::new();
        crc.update(PLAIN);
        body.extend_from_slice(&crc.sum().to_le_bytes());
        body.extend_from_slice(&crc.amount().to_le_bytes());

        for at_a_time in [1, 3, body.len()] {
            let factory = Factory::default();
            let mut chain = Chain::install(&factory, gzip_stage());
            chain
                .feed_in_pieces(&body, at_a_time)
                .unwrap_or_else(|err| panic!("{at_a_time}-byte pieces: {err}"));
            assert_eq!(factory.body(), PLAIN, "{at_a_time}-byte pieces");
        }
    }

    #[test]
    fn a_stage_that_cannot_join_the_chain_returns_its_own_error() {
        // `:789-796`: `Curl_cwriter_create` then `Curl_cwriter_add`, and a
        // failure of either is returned AS IT IS after the not-added writer is
        // released. `add` builds the base chain when the chain is empty
        // (`lib/sendf.c:458-462`), so a base stage that cannot initialise is
        // what makes `add` fail -- and the trace line has already been written
        // by then, which is why it carries a zero even on this path.
        let factory = Factory::refusing_to_build(CURLcode::OutOfMemory);
        let mut builder = Builder::new();
        let failure = builder
            .add(&factory, "identity", false, DEFAULT_SETTINGS)
            .expect_err("the base stack cannot be built");
        assert_eq!(failure.code(), CURLcode::OutOfMemory);
        assert!(
            Trace::saw(builder.traces(), "added content decoder identity -> 0"),
            "the trace precedes the add, so it reports the CREATE result: \
             {:?}",
            builder.traces()
        );
        assert!(
            builder.names().is_empty(),
            "a chain that failed to build holds nothing: {:?}",
            builder.names()
        );
    }
}
