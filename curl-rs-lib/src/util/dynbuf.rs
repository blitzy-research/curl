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

// THE BANNER ABOVE -- 23 lines, and why the licence tag appears exactly once.
//
// The block is the banner measured at `lib/llist.c:1-23`, rendered as Rust
// line comments in the stripped form the rest of this crate already uses:
// `src/lib.rs:1-23`, `src/error.rs:1-23` and `src/util/mod.rs:1-23` are
// byte-identical to it. `reuse lint` runs in continuous integration and
// requires the licence-identifier tag naming `curl`, which is on line 21.
//
// That tag spelling is never repeated anywhere else in this file, and the
// omission is deliberate rather than stylistic. `reuse` scans every line for
// the tag's colon form and parses whatever follows it as a licence
// expression, so a second, prose mention becomes a parse error instead of
// prose. `src/util/mod.rs:33-42` records the two verbatim diagnostics that
// established this. Line 21 is therefore the only place in this file where
// that spelling occurs, which is exactly what the tool needs.

// NO `unsafe` HERE, AND NO EXEMPTION FOR IT.
//
// `src/lib.rs` carries `#![deny(unsafe_code)]` and grants exactly one
// exemption, on `pub(crate) mod ffi;`. This file is not under that module, so
// it has no exemption, contains no block of the kind the keyword introduces
// and contains no attribute allowing one. The specification names this module
// as the flagship of that invariant: the C original tracks a pointer, a
// length and an allocation size by hand across `malloc` and `realloc`
// boundaries, and every one of those operations becomes a checked, safe
// container operation below. There is no `memcpy`, no `memmove`, no
// `realloc` and no pointer arithmetic left to get wrong.
//
// Four executable gates in `src/lib.rs` (`mod source_policy`) enforce that
// mechanically across this crate rather than by review, and this file is
// written to pass all four: the keyword appears only under `src/ffi/`, at
// most one exemption exists per crate, no raw string literal defeats the
// scanner's comment stripper, and no C scalar width is named outside the
// island. A fifth forbids a `dead_code` lint level on a module or crate root,
// which is why every unreferenced item below carries its own allowance.

// `dead_code` allowances, item by item, and why there are so many.
//
// `util` is the base of this crate's module graph: everything depends on it
// and it depends on nothing, so its consumers are the last code to exist.
// Until they land, every item here is legitimately unreferenced and the
// zero-warnings gate would otherwise fail on code that is correct. Measured
// on the pinned toolchain (rustc 1.97.1) rather than assumed: an unreferenced
// `pub(crate) const` is reported individually, one allowance on the struct
// covers the struct and its fields, and one on the `impl` block covers all of
// its associated items. A `#[cfg(test)]` use does not count, because the lint
// is evaluated for the non-test build -- which is also why these are `allow`
// and not `expect`. Each one is removed when its consumer lands, and
// `MAX_DYNBUF_SIZE` carries none because `DynBuf::new` really does read it.

//! The growable, size-capped byte buffer.
//!
//! Supersedes `lib/curlx/dynbuf.c` (292 lines) and its interface
//! `lib/curlx/dynbuf.h` (83 lines). `docs/internals/DYNBUF.md` documents the
//! C original and names this file as its specified successor.
//!
//! A `dynbuf` accumulates bytes behind a hard ceiling. The C tree uses it for
//! HTTP request assembly, header accumulation, cookie, alt-svc and HSTS file
//! lines, FTP command construction, DNS-over-HTTPS responses, certificate and
//! CRL file loading, trailers, proxy CONNECT headers, qlog file names and
//! `aprintf`.
//!
//! # The ceiling is behaviour, not tuning
//!
//! Exceeding a buffer's limit produces `CURLE_TOO_LARGE`, which is a return
//! code a caller observes and branches on. The nineteen limits below are
//! therefore frozen under the preservation mandate exactly as a header name or
//! a wire byte is, and `docs/internals/DYNBUF.md` states the corollary
//! plainly: reporting `CURLE_OUT_OF_MEMORY` at the ceiling instead "would be
//! a behavior change", because that code means the allocator refused rather
//! than that the cap was reached. The two conditions stay distinguishable
//! here for the same reason.
//!
//! # What the transformation removed
//!
//! The C struct (`lib/curlx/dynbuf.h:27-35`) carries four fields plus a
//! debug-only fifth:
//!
//! ```text
//! struct dynbuf {
//!   char *bufr;    /* point to a null-terminated allocated buffer */
//!   size_t leng;   /* number of bytes *EXCLUDING* the null-terminator */
//!   size_t allc;   /* size of the current allocation */
//!   size_t toobig; /* size limit for the buffer */
//! #ifdef DEBUGBUILD
//!   int init;      /* detect API usage mistakes */
//! #endif
//! };
//! ```
//!
//! [`DynBuf`] keeps two. Three fields go away, and each disappearance is the
//! point of the migration rather than a side effect of it:
//!
//! - `bufr`, `leng` and `allc` collapse into one owned container. They are
//!   `Vec::len` and `Vec::capacity`, so the invariant relating them is the
//!   container's responsibility and no longer a rule this file must restate
//!   at every append. This is the transformation the specification asks for
//!   in as many words.
//! - `init` was a debug-only misuse detector: `#define DYNINIT 0xbee51da`
//!   (`lib/curlx/dynbuf.c:31-33`), stamped by `curlx_dyn_init` and re-checked
//!   by every single other entry point with `DEBUGASSERT(s->init ==
//!   DYNINIT)`, to catch a caller that passed a stack-garbage struct or one it
//!   had never initialised. **It has no successor, and that is a win rather
//!   than an omission.** A `DynBuf` is reachable only through
//!   [`DynBuf::new`], so the state the sentinel detected is not
//!   constructible. The value is named here so that a reader diffing against
//!   the C can find the correspondence.
//!
//! Three of the C's other `DEBUGASSERT`s go the same way and are listed so
//! their absence reads as deliberate: `DEBUGASSERT(s)` (a reference cannot be
//! null), `DEBUGASSERT(!s->leng || s->bufr)` (the container upholds it) and
//! `DEBUGASSERT(!len || mem)` (a `&[u8]` cannot be null). A fourth,
//! `DEBUGASSERT(a <= s->toobig)` at `lib/curlx/dynbuf.c:79`, is dropped for a
//! different and more interesting reason recorded at [`DynBuf::nappend`]. The
//! asserts that *do* still say something are reproduced as `debug_assert!`.
//!
//! # No trailing zero is stored
//!
//! **The Rust buffer holds exactly the bytes appended to it and no
//! terminator.** State so plainly because the C's invariant is the opposite:
//! it keeps the allocation NUL-terminated at all times, `leng` excludes that
//! byte, and `curlx_dyn_ptr` hands the result out as a C string.
//!
//! Not storing it makes [`DynBuf::len`] equal the C's `leng` exactly, so
//! every limit comparison, every `tail` and every `setlen` reads the same as
//! its C counterpart with no off-by-one correction anywhere. Storing it
//! instead would mean subtracting one in `len` and accounting for it in each
//! of those comparisons, which is precisely the hand-maintained arithmetic
//! this module exists to delete. Where a terminator is genuinely needed --
//! at a boundary that hands a `const char *` to C -- it is appended there, by
//! the code that crosses the boundary; `docs/internals/DYNBUF.md` specifies
//! that placement.
//!
//! **The one place the terminator survives is the limit test**, and it
//! survives there because the ceiling is behaviour. See
//! [`DynBuf::nappend`]: the comparison is against `len + current + 1`, the
//! `+ 1` being the C's zero byte, and dropping it would shift every
//! `CURLE_TOO_LARGE` boundary in libcurl by one byte.
//!
//! # Why `Vec<u8>` and not `BytesMut`
//!
//! The specification names `bytes::BytesMut` and `Vec<u8>` together as the
//! replacement for the C tree's hand-managed buffers, leaving the choice per
//! module. `Vec<u8>` is chosen here, on four measured grounds:
//!
//! 1. **Nothing in this API splits, freezes or shares.** All fourteen entry
//!    points of `lib/curlx/dynbuf.h:37-60` were read; not one has a split,
//!    freeze or reference-count analogue. `BytesMut`'s distinguishing
//!    capabilities would be dead weight.
//! 2. **`take` is a whole-allocation ownership transfer.**
//!    `curlx_dyn_take` hands the caller the pointer and resets the struct;
//!    `core::mem::take` on a `Vec` is that operation exactly.
//!    The `BytesMut` spelling would be `freeze()`, which yields a
//!    shared immutable `Bytes` -- a different contract from the C's
//!    "caller has ownership".
//! 3. **Only `Vec` offers `reserve_exact`.** The C computes an allocation
//!    size and passes it to `realloc`; `reserve_exact` is the request for
//!    that size, which is what lets the growth policy below be read against
//!    the C line for line. `BytesMut::reserve` has no exact form and applies
//!    its own amortisation.
//! 4. **`free` must release the allocation.** Replacing the field with an
//!    empty `Vec` does that; `BytesMut` has no shrink-to-fit.
//!
//! # The size-policy table
//!
//! Transcribed verbatim from `lib/curlx/dynbuf.h:63-82` so that a reader can
//! diff this block against the header directly. Each row is declared
//! individually below with its measured consumer.
//!
//! ```text
//! #define MAX_DYNBUF_SIZE (SIZE_MAX / 2)
//!
//! #define DYN_DOH_RESPONSE    3000
//! #define DYN_DOH_CNAME       256
//! #define DYN_PAUSE_BUFFER    (64 * 1024 * 1024)
//! #define DYN_HAXPROXY        2048
//! #define DYN_HTTP_REQUEST    (1024 * 1024)
//! #define DYN_APRINTF         8000000
//! #define DYN_RTSP_REQ_HEADER (64 * 1024)
//! #define DYN_TRAILERS        (64 * 1024)
//! #define DYN_PROXY_CONNECT_HEADERS 16384
//! #define DYN_QLOG_NAME       1024
//! #define DYN_H1_TRAILER      4096
//! #define DYN_PINGPPONG_CMD   (64 * 1024)
//! #define DYN_IMAP_CMD        (64 * 1024)
//! #define DYN_MQTT_RECV       (64 * 1024)
//! #define DYN_MQTT_SEND       0xFFFFFFF
//! #define DYN_CRLFILE_SIZE    (400 * 1024 * 1024) /* 400MiB */
//! #define DYN_CERTFILE_SIZE   (100 * 1024) /* 100KiB */
//! #define DYN_KEYFILE_SIZE    (100 * 1024) /* 100KiB */
//! ```
//!
//! Nineteen rows, counted rather than eyeballed. This expression
//!
//! ```text
//! grep -cE '^#define (DYN_|MAX_DYNBUF_SIZE)' lib/curlx/dynbuf.h
//! ```
//!
//! returns 19, and nineteen constants are declared below.
//!
//! The names keep their `DYN_` prefix and their upper-snake spelling, against
//! the usual Rust preference for dropping a redundant prefix, so that
//! `grep DYN_HTTP_REQUEST` still lands in both trees. The arithmetic form is
//! kept too -- `64 * 1024 * 1024` rather than `67108864` -- because it is
//! self-documenting and because a pre-multiplied literal cannot be diffed
//! against the header by eye.
//!
//! Most of these are consumed by modules well outside `util`, which is why
//! they live beside the type that enforces them rather than at each call
//! site: DNS-over-HTTPS, HTTP/1.1, HTTP/2, HTTP/3, the chunked decoder, FTP
//! and IMAP command construction, MQTT, RTSP, the HAProxy filter, the proxy
//! CONNECT tunnel, the paused-transfer writer, `aprintf` and the TLS file
//! loaders.
//!
//! # Not implemented here: `curlx_dyn_vprintf`
//!
//! `lib/curlx/dynbuf.h:54-56` declares it and says so in a comment: "The
//! implementation of this function exists in mprintf.c". `lib/mprintf.c` maps
//! to `curl-rs-ffi/src/ffi/printf.rs`, in a **different crate**, and the
//! crate dependency direction is fixed one way -- the ABI shim depends on
//! this engine and never the reverse. Implementing a formatting engine here
//! would duplicate that work; importing it from there would create the cycle
//! the architecture forbids. Rust's own formatting machinery covers every
//! internal need, and [`DynBuf::addf`] is the whole of the interface to it.

use core::fmt;

use crate::error::{CURLcode, CodeResult};

// --- The size-policy table -- `lib/curlx/dynbuf.h:63-82`, all 19 rows -------

/// The largest limit any buffer may be given -- `MAX_DYNBUF_SIZE`,
/// `lib/curlx/dynbuf.h:63`.
///
/// The C spelling is `(SIZE_MAX / 2)`. `size_t` is [`usize`], so this is
/// `usize::MAX / 2`, and on the four 64-bit targets that is
/// `0x7fff_ffff_ffff_ffff`. Thirty-two-bit support is a deliberate forfeit
/// recorded in the specification, so no narrower reading of `SIZE_MAX` is
/// reproduced.
///
/// It is not a limit any buffer actually uses. Its sole consumer in the C is
/// the sanity check in `curlx_dyn_init` (`lib/curlx/dynbuf.c:42`), annotated
/// there "catch crazy mistakes", which [`DynBuf::new`] reproduces.
pub(crate) const MAX_DYNBUF_SIZE: usize = usize::MAX / 2;

/// A DNS-over-HTTPS response -- `DYN_DOH_RESPONSE`,
/// `lib/curlx/dynbuf.h:65`. Consumed by `lib/doh.c`.
#[allow(dead_code)]
pub(crate) const DYN_DOH_RESPONSE: usize = 3000;

/// A canonical name inside a DNS-over-HTTPS response -- `DYN_DOH_CNAME`,
/// `lib/curlx/dynbuf.h:66`. Consumed by `lib/doh.c`.
#[allow(dead_code)]
pub(crate) const DYN_DOH_CNAME: usize = 256;

/// Data buffered while a transfer is paused -- `DYN_PAUSE_BUFFER`,
/// `lib/curlx/dynbuf.h:67`. Consumed by `lib/cw-out.c`.
///
/// The largest limit in the table after the CRL file: a paused transfer must
/// hold whatever arrives until the application unpauses it.
#[allow(dead_code)]
pub(crate) const DYN_PAUSE_BUFFER: usize = 64 * 1024 * 1024;

/// A PROXY-protocol header -- `DYN_HAXPROXY`,
/// `lib/curlx/dynbuf.h:68`. Consumed by `lib/cf-haproxy.c`.
#[allow(dead_code)]
pub(crate) const DYN_HAXPROXY: usize = 2048;

/// An outgoing HTTP request -- `DYN_HTTP_REQUEST`,
/// `lib/curlx/dynbuf.h:69`.
///
/// The most widely used row in the table, and the one whose ceiling is most
/// visible to a caller. Consumed by `lib/http.c`, `lib/http1.h`,
/// `lib/http2.c`, `lib/cf-h1-proxy.c`, `lib/cf-h2-proxy.c`,
/// `lib/vquic/curl_ngtcp2.c` and `lib/vquic/curl_quiche.c`.
#[allow(dead_code)]
pub(crate) const DYN_HTTP_REQUEST: usize = 1024 * 1024;

/// A string built by `aprintf` -- `DYN_APRINTF`,
/// `lib/curlx/dynbuf.h:70`. Consumed by `lib/mprintf.c`.
///
/// Eight million exactly, not eight mebibytes: the C literal is `8000000`, a
/// decimal round number rather than a power of two, and it is transcribed
/// unchanged.
#[allow(dead_code)]
pub(crate) const DYN_APRINTF: usize = 8000000;

/// An RTSP request header block -- `DYN_RTSP_REQ_HEADER`,
/// `lib/curlx/dynbuf.h:71`. Consumed by `lib/rtsp.c`.
///
/// RTSP is one of the schemes registered for ABI completeness rather than
/// implemented, so this row exists for parity of the table.
#[allow(dead_code)]
pub(crate) const DYN_RTSP_REQ_HEADER: usize = 64 * 1024;

/// HTTP trailers -- `DYN_TRAILERS`,
/// `lib/curlx/dynbuf.h:72`. Consumed by `lib/http2.c`.
#[allow(dead_code)]
pub(crate) const DYN_TRAILERS: usize = 64 * 1024;

/// The headers of a proxy CONNECT request -- `DYN_PROXY_CONNECT_HEADERS`,
/// `lib/curlx/dynbuf.h:73`. Consumed by `lib/cf-h1-proxy.c`.
#[allow(dead_code)]
pub(crate) const DYN_PROXY_CONNECT_HEADERS: usize = 16384;

/// A qlog file name -- `DYN_QLOG_NAME`,
/// `lib/curlx/dynbuf.h:74`. Consumed by `lib/vquic/vquic.c`.
#[allow(dead_code)]
pub(crate) const DYN_QLOG_NAME: usize = 1024;

/// A trailer in a chunked HTTP/1.1 body -- `DYN_H1_TRAILER`,
/// `lib/curlx/dynbuf.h:75`. Consumed by `lib/http_chunks.c`.
#[allow(dead_code)]
pub(crate) const DYN_H1_TRAILER: usize = 4096;

/// A command on a request/response ("ping-pong") control connection --
/// `DYN_PINGPPONG_CMD`, `lib/curlx/dynbuf.h:76`. Consumed by
/// `lib/pingpong.c`, which serves FTP among others.
///
/// **The doubled `P` is upstream's spelling, not a typo introduced here.**
/// The C header really does read `DYN_PINGPPONG_CMD`. The name is reproduced
/// character for character so that `grep DYN_PINGPPONG_CMD lib/` correlates
/// the two trees; silently correcting it would break exactly the
/// cross-reference these names exist to support. Neither of the repository's
/// two spell-checking gates flags the token today, because the header that
/// contains it is tracked and unexcluded, so reproducing it introduces no new
/// finding either.
#[allow(dead_code)]
pub(crate) const DYN_PINGPPONG_CMD: usize = 64 * 1024;

/// An IMAP command -- `DYN_IMAP_CMD`,
/// `lib/curlx/dynbuf.h:77`. Consumed by `lib/imap.c`.
///
/// IMAP is registered for ABI completeness rather than implemented; the row
/// is kept so the table matches the header.
#[allow(dead_code)]
pub(crate) const DYN_IMAP_CMD: usize = 64 * 1024;

/// An inbound MQTT message -- `DYN_MQTT_RECV`,
/// `lib/curlx/dynbuf.h:78`. Consumed by `lib/mqtt.c`.
#[allow(dead_code)]
pub(crate) const DYN_MQTT_RECV: usize = 64 * 1024;

/// An outbound MQTT message -- `DYN_MQTT_SEND`,
/// `lib/curlx/dynbuf.h:79`. Consumed by `lib/mqtt.c`.
///
/// **Seven hexadecimal digits, not eight.** The C literal is `0xFFFFFFF`,
/// which is 268,435,455 and one less than 2^28 -- not the 4,294,967,295 that
/// an eight-digit `0xFFFFFFFF` would give. The digits were counted in the
/// header rather than assumed, and the unit test asserts the decimal value so
/// that a miscount cannot survive a test run.
#[allow(dead_code)]
pub(crate) const DYN_MQTT_SEND: usize = 0xFFFFFFF;

/// A certificate revocation list file -- `DYN_CRLFILE_SIZE`,
/// `lib/curlx/dynbuf.h:80`, annotated there `/* 400MiB */`. Consumed by
/// `lib/vtls/rustls.c`.
///
/// The largest limit in the table. Its consumer is curl's existing rustls
/// backend, which is the closest reference the C tree offers for this
/// workspace's TLS layer.
#[allow(dead_code)]
pub(crate) const DYN_CRLFILE_SIZE: usize = 400 * 1024 * 1024;

/// A client certificate file -- `DYN_CERTFILE_SIZE`,
/// `lib/curlx/dynbuf.h:81`, annotated there `/* 100KiB */`. Consumed by
/// `lib/vtls/rustls.c`.
#[allow(dead_code)]
pub(crate) const DYN_CERTFILE_SIZE: usize = 100 * 1024;

/// A private key file -- `DYN_KEYFILE_SIZE`,
/// `lib/curlx/dynbuf.h:82`, annotated there `/* 100KiB */`. Consumed by
/// `lib/vtls/rustls.c`.
#[allow(dead_code)]
pub(crate) const DYN_KEYFILE_SIZE: usize = 100 * 1024;

/// The floor on a buffer's first allocation -- `MIN_FIRST_ALLOC`,
/// `lib/curlx/dynbuf.c:29`.
///
/// Private, exactly as in the C, where it is defined in the implementation
/// file and not in the header. It is a growth-policy detail rather than a
/// limit a caller may pass, and [`DynBuf::nappend`] is its only reader.
const MIN_FIRST_ALLOC: usize = 32;

/// A growable byte buffer with a hard, caller-supplied ceiling.
///
/// Supersedes `struct dynbuf` (`lib/curlx/dynbuf.h:27-35`). Two fields where
/// the C had four plus a debug-only fifth; the module documentation records
/// what each disappearance bought.
///
/// # Lifecycle, and why there are three ways to empty it
///
/// Rust would naturally offer one. All three are kept because the C call
/// sites use them differently, and collapsing them would change behaviour at
/// some of those sites:
///
/// | Operation             | Content | Allocation | Reusable |
/// |-----------------------|---------|------------|----------|
/// | [`reset`](Self::reset) | dropped | **kept**   | yes      |
/// | [`free`](Self::free)   | dropped | released   | yes      |
/// | `drop`                 | dropped | released   | gone     |
///
/// [`reset`](Self::reset) is the hot path -- a line reader calls it once per
/// line and wants the allocation back for the next one. [`free`](Self::free)
/// is what a failed append performs internally, and what a caller performs
/// when it is done with the contents but intends to keep appending later; the
/// C comment at `lib/curlx/dynbuf.c:53-54` is explicit that the struct "can
/// be reused to add data to again" afterwards. `Drop` is end-of-life and
/// needs no code at all: the container releases its own allocation, which is
/// the whole of what `curlx_dyn_free` had to be called by hand for.
///
/// The ceiling survives all three. Nothing short of dropping the value
/// changes it, so a buffer that has been emptied still refuses the same
/// oversized append it refused before.
///
/// # Errors
///
/// Every fallible method returns one of exactly three codes, and no other:
///
/// - `CURLcode::TooLarge` -- the append would have carried the buffer past
///   its ceiling. The buffer is emptied.
/// - `CURLcode::OutOfMemory` -- an allocation was refused. Near-unreachable
///   in Rust; see [`Self::nappend`].
/// - `CURLcode::BadFunctionArgument` -- [`tail`](Self::tail) or
///   [`setlen`](Self::setlen) was asked for more bytes than the buffer holds.
#[allow(dead_code)]
pub(crate) struct DynBuf {
    /// The bytes appended so far, and nothing else.
    ///
    /// Subsumes the C's `bufr`, `leng` and `allc`: the pointer is the
    /// container, `leng` is `Vec::len` and `allc` is `Vec::capacity`. No
    /// trailing zero is stored -- see the module documentation.
    buf: Vec<u8>,

    /// The ceiling, in bytes, as `curlx_dyn_init` was given it.
    ///
    /// The one C field that survives unchanged, because it is the one that is
    /// observable: crossing it produces `CURLcode::TooLarge`.
    toobig: usize,
}

/// Reports the buffer's shape without dumping its contents.
///
/// Deliberately hand-written rather than derived. `#[derive(Debug)]` would
/// render the `Vec<u8>` element by element, so a failed assertion on a
/// `DYN_CRLFILE_SIZE` buffer could emit four hundred mebibytes of decimal
/// integers into a panic message. The three numbers below are what a reader
/// debugging a limit or a growth question actually needs, and `capacity` is
/// included precisely because it is *not* part of the API contract and is
/// therefore otherwise unobservable.
impl fmt::Debug for DynBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynBuf")
            .field("len", &self.buf.len())
            .field("capacity", &self.buf.capacity())
            .field("toobig", &self.toobig)
            .finish()
    }
}

#[allow(dead_code)]
impl DynBuf {
    /// Creates an empty buffer with `toobig` as its ceiling.
    ///
    /// Supersedes `curlx_dyn_init` (`lib/curlx/dynbuf.c:38-50`), which
    /// "cannot fail" and allocates nothing. Neither does this: the first
    /// allocation happens on the first append, exactly as in the C, where
    /// `bufr` starts as `NULL` and `allc` as zero.
    ///
    /// # Panics
    ///
    /// In a debug build only, and for the same two mistakes the C catches
    /// with `DEBUGASSERT` at `lib/curlx/dynbuf.c:41-42`:
    ///
    /// - `toobig` is zero. A ceiling of zero admits no append at all, since
    ///   even an empty one needs room for the C's terminator, so a zero here
    ///   is a caller bug rather than a very small buffer.
    /// - `toobig` exceeds [`MAX_DYNBUF_SIZE`]. The C annotates this one
    ///   "catch crazy mistakes"; it is the shape a sign-flipped or
    ///   uninitialised size arrives in.
    ///
    /// Neither is promoted to a release-build check, because neither is a
    /// limit that must hold for memory safety -- the ceiling test in
    /// [`Self::nappend`] holds unconditionally in every build, and it is the
    /// one that governs behaviour. Reproducing the C's debug-only severity is
    /// also the faithful choice.
    #[must_use]
    pub(crate) fn new(toobig: usize) -> Self {
        debug_assert!(toobig != 0, "a dynbuf ceiling of zero admits nothing");
        debug_assert!(
            toobig <= MAX_DYNBUF_SIZE,
            "a dynbuf ceiling above MAX_DYNBUF_SIZE is a caller mistake"
        );
        Self {
            buf: Vec::new(),
            toobig,
        }
    }

    /// Appends `mem`, growing the buffer if it fits and emptying it if it
    /// does not.
    ///
    /// Supersedes `dyn_nappend` (`lib/curlx/dynbuf.c:67-119`), the heart of
    /// the module and the only place where growth and the ceiling interact.
    /// The C reads:
    ///
    /// ```text
    /// size_t idx = s->leng;
    /// size_t a = s->allc;
    /// size_t fit = len + idx + 1; /* new string + old string + zero byte */
    ///
    /// if(fit > s->toobig) {
    ///   curlx_dyn_free(s);
    ///   return CURLE_TOO_LARGE;
    /// }
    /// else if(!a) {                            /* first invoke */
    ///   if(MIN_FIRST_ALLOC > s->toobig)      a = s->toobig;
    ///   else if(fit < MIN_FIRST_ALLOC)       a = MIN_FIRST_ALLOC;
    ///   else                                 a = fit;
    /// }
    /// else {
    ///   while(a < fit)
    ///     a *= 2;
    ///   if(a > s->toobig)
    ///     a = s->toobig;
    /// }
    /// ```
    ///
    /// # The `+ 1` is the whole ceiling contract
    ///
    /// `fit` counts the incoming bytes, the bytes already held, **and the
    /// zero byte** (`lib/curlx/dynbuf.c:72`). This module stores no zero
    /// byte, and the `+ 1` survives anyway, because the ceiling is behaviour
    /// rather than an allocation detail: a buffer whose ceiling is `n` accepts
    /// at most `n - 1` bytes in curl 8.x, so dropping the `+ 1` here would
    /// let through a payload of exactly `n` bytes that curl rejects, shifting
    /// every `CURLE_TOO_LARGE` boundary in libcurl by one byte. The unit test
    /// named for this boundary pins it from both sides.
    ///
    /// # Both failure paths empty the buffer
    ///
    /// The C calls `curlx_dyn_free` before returning either error
    /// (`lib/curlx/dynbuf.c:83` and `:107`), and
    /// `docs/internals/DYNBUF.md` states it as a guarantee of the interface
    /// rather than an implementation accident. This is *not* a mere refusal
    /// to append: whatever the buffer had accumulated is destroyed and the
    /// allocation released. Callers depend on it, so it is reproduced exactly.
    ///
    /// # The out-of-memory path is near-dead, and kept anyway
    ///
    /// The C's second failure is `realloc` returning null. Rust's global
    /// allocator aborts the process instead of reporting failure, so
    /// `CURLcode::OutOfMemory` is not reachable from the growth performed
    /// here. It stays in the documented error set of this module because
    /// callers match on it and because [`Self::addf`] does reach it, by a
    /// different route: a `Display` implementation that fails without
    /// recording a code of its own. `try_reserve` was considered as a way to
    /// make the growth path reachable too and rejected: it cannot be adopted
    /// without changing what the success path does, and the specification
    /// makes faithfulness the tie-breaker.
    ///
    /// # Growth
    ///
    /// The three-branch first allocation and the doubling loop are
    /// reproduced in the C's own shape rather than replaced by the
    /// container's amortised growth. Capacity is not observable through this
    /// interface, so a different policy would be undetectable and the code
    /// would be faster to write; it is written this way so that it can be
    /// read against the C line for line, and because performance is an
    /// explicit non-goal. The three branches matter individually -- the first
    /// of them, `MIN_FIRST_ALLOC > toobig`, is the only thing that keeps a
    /// buffer whose ceiling is under 32 bytes from over-allocating past it.
    ///
    /// Two differences from the C are deliberate and neither is observable:
    ///
    /// - The doubling uses `checked_mul` and falls back to the ceiling. In C,
    ///   `a *= 2` can wrap to zero and spin, or wrap past `fit` and allocate
    ///   a fraction of what was asked for. The fallback is sound as a loop
    ///   exit as well as an allocation size, because `fit <= toobig` has
    ///   already been established, so assigning the ceiling always satisfies
    ///   `a >= fit`.
    /// - `DEBUGASSERT(a <= s->toobig)` (`lib/curlx/dynbuf.c:79`) is **not**
    ///   reproduced. It asserts that the current allocation never exceeds the
    ///   ceiling, which holds in C because every allocation size is clamped
    ///   to it. Here the allocator, not this code, has the last word on
    ///   capacity: `reserve_exact` is documented to be free to give more than
    ///   it was asked for, so `capacity() > toobig` is permitted and the
    ///   assertion would be a false alarm. Everything downstream of it copes,
    ///   because the ceiling test reads `fit` and the clamp reads `a`; neither
    ///   reads capacity.
    fn nappend(&mut self, mem: &[u8]) -> CodeResult<()> {
        // `idx` and `a` are the C's locals, kept under their C names so the
        // algorithm below reads against `lib/curlx/dynbuf.c:70-71`.
        let idx = self.buf.len();
        let mut a = self.buf.capacity();

        // The two `DEBUGASSERT`s at `lib/curlx/dynbuf.c:76-77` that still say
        // something. The remaining four have no Rust content; the module
        // documentation lists them and why.
        debug_assert!(self.toobig != 0, "a dynbuf ceiling is never zero");
        debug_assert!(
            idx < self.toobig,
            "a dynbuf never holds as many bytes as its ceiling"
        );

        // `lib/curlx/dynbuf.c:72`. The `+ 1` is the C's zero byte and is part
        // of the ceiling contract; see this method's documentation.
        //
        // The C computes this with wrapping arithmetic, which is a latent hole
        // there: a sufficiently large `len` wraps `fit` to a small value, the
        // ceiling test then passes, and the append overruns the allocation.
        // Rust cannot reach that state with a slice on these targets, but the
        // window is closed explicitly rather than argued away. An overflow
        // means the request cannot fit under any ceiling, which is what
        // `CURLE_TOO_LARGE` says.
        let fit = match mem
            .len()
            .checked_add(idx)
            .and_then(|sum| sum.checked_add(1))
        {
            Some(fit) => fit,
            None => {
                self.free();
                return Err(CURLcode::TooLarge);
            }
        };

        // `lib/curlx/dynbuf.c:82-85`.
        if fit > self.toobig {
            self.free();
            return Err(CURLcode::TooLarge);
        }

        if a == 0 {
            // `lib/curlx/dynbuf.c:86-95` -- first invoke. `a == 0` is the C's
            // `!a` exactly: a new buffer and a freed one both have no
            // allocation, and `reset` keeps whatever it had.
            debug_assert!(idx == 0, "no allocation implies no content");
            if MIN_FIRST_ALLOC > self.toobig {
                a = self.toobig;
            } else if fit < MIN_FIRST_ALLOC {
                a = MIN_FIRST_ALLOC;
            } else {
                a = fit;
            }
        } else {
            // `lib/curlx/dynbuf.c:96-102` -- double until it fits, then clamp
            // because there is no point allocating past what is allowed.
            while a < fit {
                a = match a.checked_mul(2) {
                    Some(doubled) => doubled,
                    None => self.toobig,
                };
            }
            if a > self.toobig {
                a = self.toobig;
            }
        }

        // `lib/curlx/dynbuf.c:104-112`. The C reallocates when the computed
        // size differs from the current one; `a` can never come out smaller
        // than `allc` there, so that test is a grow test, and `reserve_exact`
        // is its counterpart -- it asks for a total capacity of `a` and never
        // shrinks.
        //
        // The argument is an increment over the current length, not a total.
        // The guard establishes `a > capacity() >= len() == idx`, so the
        // subtraction cannot underflow; `saturating_sub` states that in code
        // rather than in a comment, and a zero would merely reserve nothing.
        if a > self.buf.capacity() {
            self.buf.reserve_exact(a.saturating_sub(idx));
        }

        // `lib/curlx/dynbuf.c:114-117`, in one line. This is the C's `memcpy`
        // and its by-hand `s->leng = idx + len`, and the terminator write it
        // ends with has no counterpart here.
        //
        // An empty `mem` is not special-cased and must not be. The C runs the
        // whole of the above for a zero-length append -- ceiling test,
        // allocation and all -- and returns success, and a caller uses that to
        // force a buffer into existence. Everything before this point has
        // already happened by the time an empty slice arrives, and appending
        // it is the no-op the C's skipped `memcpy` is.
        self.buf.extend_from_slice(mem);
        Ok(())
    }

    /// Appends a byte slice.
    ///
    /// Supersedes `curlx_dyn_addn` (`lib/curlx/dynbuf.c:162-168`), which is
    /// the same thin wrapper over the core append. The C's separate `len`
    /// parameter is the slice's own length here.
    ///
    /// # Errors
    ///
    /// `CURLcode::TooLarge` if the append would cross the ceiling, in which
    /// case the buffer is emptied. See [`Self::nappend`].
    pub(crate) fn addn(&mut self, mem: &[u8]) -> CodeResult<()> {
        self.nappend(mem)
    }

    /// Appends a string's bytes.
    ///
    /// Supersedes `curlx_dyn_add` (`lib/curlx/dynbuf.c:173-182`), which takes
    /// a `const char *` and calls `strlen` on it. A `&str` carries its length,
    /// so there is no scan and no way to pass a string that is not
    /// terminated -- the two failure modes of the C signature both disappear.
    ///
    /// A C string arriving from outside is converted at the boundary that
    /// receives it, not here: this module never sees a `const char *`.
    ///
    /// # Errors
    ///
    /// `CURLcode::TooLarge` if the append would cross the ceiling, in which
    /// case the buffer is emptied.
    pub(crate) fn add(&mut self, s: &str) -> CodeResult<()> {
        self.nappend(s.as_bytes())
    }

    /// Appends formatted output.
    ///
    /// Supersedes **both** `curlx_dyn_addf` (`lib/curlx/dynbuf.c:220-232`)
    /// and `curlx_dyn_vaddf` (`:187-215`). The C needs two functions because
    /// one takes `...` and the other the `va_list` it was packed into;
    /// `format_args!` is Rust's `va_list`, already packed by the caller, so
    /// one function covers both. Call it as
    ///
    /// ```text
    /// buf.addf(format_args!("{scheme}://{host}:{port}"))?;
    /// ```
    ///
    /// Prefer [`add`](Self::add) for a bare string. The C carries
    /// `DEBUGASSERT(strcmp(fmt, "%s"))` at `lib/curlx/dynbuf.c:227` with the
    /// comment "use curlx_dyn_add instead", guarding against a formatting
    /// pass that does nothing but copy. There is no runtime counterpart --
    /// `fmt::Arguments` does not expose its template -- and no attempt is made
    /// to inspect the literal at compile time either; the guidance lives in
    /// this sentence instead.
    ///
    /// # Errors
    ///
    /// Reproduces the C's mapping at `lib/curlx/dynbuf.c:197-201` exactly:
    ///
    /// - `CURLcode::TooLarge` where the C sees `MERR_TOO_LARGE`, which is to
    ///   say the formatted output crossed the ceiling. The check happens
    ///   inside the sink, one fragment at a time, so a format whose *output*
    ///   is oversized fails even though its arguments individually were not.
    /// - `CURLcode::OutOfMemory` for anything else -- here, a `Display`
    ///   implementation among the arguments that returned an error of its own.
    ///
    /// The buffer is emptied on both, matching the C: the ceiling path
    /// inherits the emptying from [`Self::addn`], and the other performs it
    /// explicitly, as the C does at `lib/curlx/dynbuf.c:211-213` ("If we
    /// failed, we cleanup the whole buffer and return error").
    pub(crate) fn addf(&mut self, args: fmt::Arguments<'_>) -> CodeResult<()> {
        // The sink borrows the buffer, so it must be gone before the buffer
        // can be emptied below. Both values it produces are `Copy`, so the
        // block yields them and drops the borrow with them.
        let (outcome, failure) = {
            let mut sink = FmtSink {
                buf: self,
                failure: None,
            };
            let outcome = fmt::write(&mut sink, args);
            (outcome, sink.failure)
        };

        if outcome.is_ok() {
            // Nothing can have failed silently: the sink records a code for
            // every error it originates, so an `Ok` here means every fragment
            // landed.
            debug_assert!(failure.is_none(), "a silent formatting failure");
            return Ok(());
        }

        match failure {
            // An append refused the fragment and has already emptied the
            // buffer, so the code travels out unchanged.
            Some(code) => Err(code),
            // The formatting machinery failed without this module's
            // involvement, which leaves the buffer holding a partial
            // rendering. The C's `#else` branch empties it and reports
            // out-of-memory; so does this.
            None => {
                self.free();
                Err(CURLcode::OutOfMemory)
            }
        }
    }

    /// Drops the content and keeps the allocation.
    ///
    /// Supersedes `curlx_dyn_reset` (`lib/curlx/dynbuf.c:125-133`), whose
    /// comment reads "Clears the string, keeps the allocation. This can also
    /// be called on a buffer that already was freed."
    ///
    /// Both halves of that comment are reproduced. `Vec::clear` truncates to
    /// zero and is documented to have no effect on capacity, which is the
    /// "keeps the allocation" half and is what makes this the right call in a
    /// loop -- a line reader calls it once per line and the next line reuses
    /// the same buffer. And it is total: clearing an already-empty buffer,
    /// including one that [`free`](Self::free) has just emptied, does nothing
    /// and cannot panic, so the C's second sentence needs no special case
    /// here either.
    ///
    /// Contrast [`free`](Self::free), which releases the allocation as well.
    /// The lifecycle table on [`DynBuf`] sets the three operations side by
    /// side.
    pub(crate) fn reset(&mut self) {
        self.buf.clear();
    }

    /// Drops the content and releases the allocation, leaving the buffer
    /// reusable.
    ///
    /// Supersedes `curlx_dyn_free` (`lib/curlx/dynbuf.c:56-62`), which
    /// releases `bufr` and zeroes `leng` and `allc` while leaving `toobig` --
    /// and the debug sentinel -- alone, so that, in the C's words, "this
    /// buffer can be reused to add data to again".
    ///
    /// **This is deliberately not `Drop`.** Call sites invoke it mid-life and
    /// then keep appending, and the internal failure paths invoke it on a
    /// buffer whose owner still holds it, so the operation has to be nameable.
    /// `Drop` is a separate concern and needs no implementation at all: the
    /// container releases its own allocation when the value goes out of
    /// scope, which is the entire reason `curlx_dyn_free` had to be called by
    /// hand in the first place.
    ///
    /// Replacing the field is what releases the memory: the outgoing `Vec` is
    /// dropped here, and the incoming one holds no allocation, so `capacity`
    /// returns to zero. That matters beyond tidiness -- it restores the
    /// `allc == 0` state that [`Self::nappend`] tests for, so the next append
    /// takes the C's first-invoke branch, exactly as it would after
    /// `curlx_dyn_free`.
    pub(crate) fn free(&mut self) {
        self.buf = Vec::new();
    }

    /// Keeps the last `trail` bytes and drops everything before them.
    ///
    /// Supersedes `curlx_dyn_tail` (`lib/curlx/dynbuf.c:139-157`). To keep the
    /// *leading* bytes instead, use [`setlen`](Self::setlen); the two are each
    /// other's complement and the C's own documentation cross-references them.
    ///
    /// All four of the C's cases are reproduced in its order:
    ///
    /// | `trail`            | Result |
    /// |--------------------|--------|
    /// | greater than `len` | `CURLcode::BadFunctionArgument`, no change |
    /// | equal to `len`     | success, no change |
    /// | zero               | success, empty -- the C calls `reset` here |
    /// | otherwise          | the tail moves to the front |
    ///
    /// The `trail == 0` case routing through [`reset`](Self::reset) rather
    /// than `free` is not incidental: the allocation is kept, which is what
    /// the C does.
    ///
    /// # Errors
    ///
    /// `CURLcode::BadFunctionArgument` if `trail` exceeds the current length.
    /// The buffer is left untouched -- this is the one error in the module
    /// that does *not* empty it, matching the C, which returns before
    /// touching anything.
    pub(crate) fn tail(&mut self, trail: usize) -> CodeResult<()> {
        let len = self.buf.len();

        // `lib/curlx/dynbuf.c:144-145`.
        if trail > len {
            return Err(CURLcode::BadFunctionArgument);
        }
        // `:146-147` -- already exactly the requested tail.
        if trail == len {
            return Ok(());
        }
        // `:148-150`.
        if trail == 0 {
            self.reset();
            return Ok(());
        }

        // `:152-154`. `copy_within` is the C's `memmove` -- it is defined for
        // overlapping ranges, which this one is whenever `trail` exceeds half
        // the length -- and `truncate` is the by-hand `s->leng = trail` that
        // follows it. The terminator write the C ends with has no counterpart.
        //
        // `len - trail` cannot underflow: the two guards above have
        // established `trail < len`.
        self.buf.copy_within(len - trail.., 0);
        self.buf.truncate(trail);
        Ok(())
    }

    /// Keeps the first `set` bytes and drops everything after them.
    ///
    /// Supersedes `curlx_dyn_setlen` (`lib/curlx/dynbuf.c:282-292`). It can
    /// only ever shrink: the C rejects any `set` above the current length
    /// rather than growing to meet it, because the bytes between the old
    /// length and the new one would have no defined content. To keep the
    /// *trailing* bytes instead, use [`tail`](Self::tail).
    ///
    /// A note for anyone diffing against the C: `curlx_dyn_setlen(s, 0)` on a
    /// buffer that has never been appended to writes `s->bufr[0]` with `bufr`
    /// still null (`lib/curlx/dynbuf.c:290`). `Vec::truncate(0)` on an empty
    /// container is well defined and does nothing, so the successor is
    /// strictly better behaved on an input the C cannot survive. No valid C
    /// caller reaches that state, so nothing observable changes.
    ///
    /// # Errors
    ///
    /// `CURLcode::BadFunctionArgument` if `set` exceeds the current length.
    /// The buffer is left untouched.
    pub(crate) fn setlen(&mut self, set: usize) -> CodeResult<()> {
        // `lib/curlx/dynbuf.c:287-288`.
        if set > self.buf.len() {
            return Err(CURLcode::BadFunctionArgument);
        }
        self.buf.truncate(set);
        Ok(())
    }

    /// Borrows the accumulated bytes.
    ///
    /// Supersedes **both** `curlx_dyn_ptr` (`lib/curlx/dynbuf.c:237-243`) and
    /// `curlx_dyn_uptr` (`:260-266`). The C needs two accessors only because
    /// its buffer is a `char *` that half its callers want as
    /// `unsigned char *`; the second is a cast and nothing else. Rust has one
    /// byte type, so one accessor.
    ///
    /// # Two C behaviours that change here, both safely
    ///
    /// **A never-appended buffer yields an empty slice, where the C yields
    /// `NULL`.** Several C callers test the pointer for null, and the
    /// distinction they are drawing is "never allocated" against "allocated
    /// but empty" -- a distinction with no consequence, because both mean
    /// there are no bytes to read, and every such caller goes on to treat the
    /// two identically. An empty slice answers the only question they are
    /// really asking, and it removes the null check rather than converting it
    /// into an `Option` that every call site would have to unwrap. Callers
    /// ported into this crate are written against the empty slice; there is no
    /// route by which C code reaches this method, since it is crate-private.
    ///
    /// **The returned bytes are not NUL-terminated.** The C's are, and its
    /// callers pass them to string functions. See the module documentation:
    /// the terminator belongs at the boundary that produces a C string.
    ///
    /// # Pointer invalidation stops being a rule to remember
    ///
    /// `docs/internals/DYNBUF.md` warns that a pointer from `curlx_dyn_ptr`
    /// "should not be trusted or used anymore after the next buffer
    /// manipulation call", because an append may reallocate. That warning has
    /// no counterpart here and needs none: the returned slice borrows the
    /// buffer, so any later mutation is rejected at compile time while the
    /// borrow is live. A runtime hazard becomes an error the compiler reports.
    #[must_use]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Borrows the accumulated bytes mutably, for in-place editing.
    ///
    /// The mutable counterpart of [`as_slice`](Self::as_slice), for the C
    /// callers that write through `curlx_dyn_ptr`'s result rather than only
    /// reading it. In-place editing only: the slice cannot change the length,
    /// so it cannot reach past the ceiling, which is why this needs no limit
    /// check and cannot fail.
    ///
    /// Everything said about [`as_slice`](Self::as_slice) applies -- empty
    /// rather than null, no terminator, and the borrow checker enforcing the
    /// invalidation rule the C could only document.
    #[must_use]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// The number of bytes held.
    ///
    /// Supersedes `curlx_dyn_len` (`lib/curlx/dynbuf.c:271-277`). Equal to the
    /// C's `leng` on the nose, which is the payoff of not storing a
    /// terminator: the C's "does not include the terminating zero byte"
    /// caveat has nothing left to caveat.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the buffer holds no bytes.
    ///
    /// The C has no counterpart -- its callers compare `curlx_dyn_len` against
    /// zero, or test the pointer for null. Provided because
    /// `self.len() == 0` is the clearer thing to say as `self.is_empty()`,
    /// and because a length accessor without one reads as an oversight to
    /// every Rust reader and to the linter.
    ///
    /// True both for a buffer that has never been appended to and for one that
    /// [`reset`](Self::reset) or [`free`](Self::free) has emptied; those
    /// states differ only in capacity, which is not part of this interface.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Hands the accumulated bytes to the caller and returns the buffer to its
    /// initial state.
    ///
    /// Supersedes `curlx_dyn_take` (`lib/curlx/dynbuf.c:245-255`), which
    /// returns `bufr` and the length through an out-parameter, then sets
    /// `bufr` to null and `leng` and `allc` to zero -- transferring ownership
    /// of the allocation and leaving `toobig` in place.
    ///
    /// All of that is one operation on an owned container. The out-parameter
    /// disappears because the returned `Vec` carries its own length, and the
    /// three-field reset is what `core::mem::take` leaves behind: an empty
    /// container with no allocation. The ceiling is untouched, so the buffer
    /// keeps enforcing the same limit on everything appended afterwards.
    ///
    /// The state left behind is [`free`](Self::free)'s, not
    /// [`reset`](Self::reset)'s -- capacity goes with the bytes, because the
    /// caller now owns the allocation they were in.
    ///
    /// A note for anyone diffing against the C: `curlx_dyn_take` is the one
    /// entry point that omits `DEBUGASSERT(!s->leng || s->bufr)`. Nothing
    /// follows from that here, since the invariant it was checking is the
    /// container's.
    #[must_use]
    pub(crate) fn take(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.buf)
    }
}

/// The formatting sink behind [`DynBuf::addf`].
///
/// `fmt::Write` is implemented here rather than on [`DynBuf`] itself, and that
/// is the point of the type existing. `fmt::Write::write_str` can report only
/// `fmt::Error`, which carries nothing, so a `DynBuf` implementing the trait
/// directly would let `write!` collapse `CURLcode::TooLarge` and
/// `CURLcode::OutOfMemory` into one indistinguishable failure -- and
/// `docs/internals/DYNBUF.md` is explicit that confusing those two is a
/// behaviour change, because one means the caller asked for more than the
/// buffer may hold and the other means the allocator refused.
///
/// The sink keeps the real code in a field and hands `fmt::Error` to the
/// formatting machinery purely as a stop signal, so [`DynBuf::addf`] can
/// recover the code afterwards and no caller is offered the lossy route.
struct FmtSink<'a> {
    /// The buffer being appended to.
    buf: &'a mut DynBuf,

    /// The code from the first fragment that failed, if any.
    ///
    /// Only ever written once in practice: `fmt::write` abandons the whole
    /// operation on the first error, so there is no second failure to record.
    failure: Option<CURLcode>,
}

impl fmt::Write for FmtSink<'_> {
    /// Appends one rendered fragment, remembering why if it does not fit.
    ///
    /// The ceiling is therefore enforced fragment by fragment as the output is
    /// produced, rather than on a fully rendered string. That is what the C
    /// does too -- its `curlx_dyn_vprintf` appends as it formats -- and it
    /// means an oversized result is refused without first assembling it.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        match self.buf.addn(s.as_bytes()) {
            Ok(()) => Ok(()),
            Err(code) => {
                self.failure = Some(code);
                // `fmt::Error` is a stop signal, not the diagnosis. The
                // diagnosis is in `failure`, which the caller reads.
                Err(fmt::Error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nineteen size limits, each paired with the value the C header
    /// spells, transcribed a second time and independently.
    ///
    /// Two things are asserted here that no single `assert_eq!` could be.
    ///
    /// The **count** is asserted by the type: `[_; 19]` makes a missing row or
    /// a twentieth one a compile error rather than a test failure, which is
    /// the check `grep -cE '^#define (DYN_|MAX_DYNBUF_SIZE)'
    /// lib/curlx/dynbuf.h` performs against the header.
    ///
    /// The **values** are asserted against a second transcription. The
    /// constants above keep the C's arithmetic form so that they can be diffed
    /// against the header by eye; the third column here is the same number
    /// written out, so a slip in either spelling disagrees with the other. The
    /// `MAX_DYNBUF_SIZE` row is the one exception -- its C spelling is
    /// `(SIZE_MAX / 2)` rather than a literal, so the second transcription is
    /// necessarily the same expression, and
    /// [`max_dynbuf_size_is_half_the_address_space`] supplies the independent
    /// literal for the targets where one exists.
    const LIMITS: [(&str, usize, usize); 19] = [
        ("MAX_DYNBUF_SIZE", MAX_DYNBUF_SIZE, usize::MAX / 2),
        ("DYN_DOH_RESPONSE", DYN_DOH_RESPONSE, 3000),
        ("DYN_DOH_CNAME", DYN_DOH_CNAME, 256),
        ("DYN_PAUSE_BUFFER", DYN_PAUSE_BUFFER, 67_108_864),
        ("DYN_HAXPROXY", DYN_HAXPROXY, 2048),
        ("DYN_HTTP_REQUEST", DYN_HTTP_REQUEST, 1_048_576),
        ("DYN_APRINTF", DYN_APRINTF, 8_000_000),
        ("DYN_RTSP_REQ_HEADER", DYN_RTSP_REQ_HEADER, 65_536),
        ("DYN_TRAILERS", DYN_TRAILERS, 65_536),
        (
            "DYN_PROXY_CONNECT_HEADERS",
            DYN_PROXY_CONNECT_HEADERS,
            16_384,
        ),
        ("DYN_QLOG_NAME", DYN_QLOG_NAME, 1024),
        ("DYN_H1_TRAILER", DYN_H1_TRAILER, 4096),
        ("DYN_PINGPPONG_CMD", DYN_PINGPPONG_CMD, 65_536),
        ("DYN_IMAP_CMD", DYN_IMAP_CMD, 65_536),
        ("DYN_MQTT_RECV", DYN_MQTT_RECV, 65_536),
        ("DYN_MQTT_SEND", DYN_MQTT_SEND, 268_435_455),
        ("DYN_CRLFILE_SIZE", DYN_CRLFILE_SIZE, 419_430_400),
        ("DYN_CERTFILE_SIZE", DYN_CERTFILE_SIZE, 102_400),
        ("DYN_KEYFILE_SIZE", DYN_KEYFILE_SIZE, 102_400),
    ];

    /// A `Display` implementation that fails.
    ///
    /// Exists so that [`DynBuf::addf`]'s out-of-memory branch is reachable
    /// from a test. It is the only route to that branch: the growth path
    /// cannot report an allocation failure, because Rust's global allocator
    /// aborts instead of returning.
    struct FailingDisplay;

    impl fmt::Display for FailingDisplay {
        fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            Err(fmt::Error)
        }
    }

    // ---- The size-policy table ---------------------------------------------

    #[test]
    fn every_size_limit_matches_the_c_header() {
        for (name, declared, expected) in LIMITS {
            assert_eq!(
                declared, expected,
                "{name} disagrees with lib/curlx/dynbuf.h"
            );
        }
    }

    /// `MAX_DYNBUF_SIZE` against a literal, where the target admits one.
    ///
    /// The C spells it `(SIZE_MAX / 2)`, so the definition and the check would
    /// otherwise be the same expression. On a 64-bit target the value has a
    /// literal form, and all four mandated targets are 64-bit -- 32-bit
    /// support being a deliberate forfeit -- so the literal is asserted there
    /// and the relationship everywhere.
    #[test]
    fn max_dynbuf_size_is_half_the_address_space() {
        assert_eq!(MAX_DYNBUF_SIZE, usize::MAX / 2);

        #[cfg(target_pointer_width = "64")]
        assert_eq!(MAX_DYNBUF_SIZE, 0x7fff_ffff_ffff_ffff);
    }

    /// `DYN_MQTT_SEND` has seven hexadecimal digits, not eight.
    ///
    /// Called out on its own because the trap is silent: `0xFFFFFFFF` is a
    /// far more familiar shape than the header's `0xFFFFFFF`, and mistaking
    /// one for the other multiplies the limit sixteenfold.
    #[test]
    fn dyn_mqtt_send_is_seven_hex_digits() {
        assert_eq!(DYN_MQTT_SEND, 0x0fff_ffff);
        assert_eq!(DYN_MQTT_SEND, 268_435_455);
        assert_ne!(DYN_MQTT_SEND, 0xffff_ffff);
    }

    /// The two limits the C header annotates in binary units mean what the
    /// annotations say.
    #[test]
    fn the_annotated_limits_are_the_annotated_sizes() {
        assert_eq!(DYN_CRLFILE_SIZE, 400 * 1024 * 1024, "the /* 400MiB */ row");
        assert_eq!(DYN_CERTFILE_SIZE, 100 * 1024, "a /* 100KiB */ row");
        assert_eq!(DYN_KEYFILE_SIZE, 100 * 1024, "the other /* 100KiB */ row");
    }

    #[test]
    fn min_first_alloc_is_the_c_floor() {
        assert_eq!(MIN_FIRST_ALLOC, 32, "lib/curlx/dynbuf.c:29");
    }

    // ---- The ceiling, and the `+ 1` that defines it ------------------------

    /// The single most important behaviour in the module.
    ///
    /// The C's `fit` counts the incoming bytes, the bytes held **and** a zero
    /// byte, so a ceiling of `n` admits at most `n - 1` bytes. Both sides of
    /// the boundary are pinned, and the second half of the test moves the
    /// ceiling up by one to show the boundary moves with it -- which is what
    /// distinguishes a correct `+ 1` from a coincidence.
    #[test]
    fn the_ceiling_reserves_one_byte_for_the_c_terminator() {
        // 7 + 0 + 1 == 8, which is not greater than 8.
        let mut buf = DynBuf::new(8);
        assert_eq!(buf.addn(b"1234567"), Ok(()));
        assert_eq!(buf.as_slice(), b"1234567");

        // 8 + 0 + 1 == 9, which is.
        let mut buf = DynBuf::new(8);
        assert_eq!(buf.addn(b"12345678"), Err(CURLcode::TooLarge));

        // One more byte of ceiling admits one more byte of payload.
        let mut buf = DynBuf::new(9);
        assert_eq!(buf.addn(b"12345678"), Ok(()));
        assert_eq!(buf.as_slice(), b"12345678");
        assert_eq!(buf.addn(b"9"), Err(CURLcode::TooLarge));
    }

    /// Crossing the ceiling destroys the accumulated content.
    ///
    /// Not a refusal to append: the C calls `curlx_dyn_free` before returning,
    /// and callers depend on the buffer coming back empty.
    #[test]
    fn crossing_the_ceiling_empties_the_buffer() {
        let mut buf = DynBuf::new(16);
        assert_eq!(buf.addn(b"kept for now"), Ok(()));
        assert_eq!(buf.len(), 12);

        assert_eq!(buf.addn(b"far too much"), Err(CURLcode::TooLarge));
        assert_eq!(buf.len(), 0, "the failing append must free the buffer");
        assert!(buf.is_empty());
        assert_eq!(buf.as_slice(), b"");
    }

    /// The ceiling is cumulative, not per-append.
    #[test]
    fn two_appends_that_individually_fit_can_jointly_overflow() {
        let mut buf = DynBuf::new(10);

        // 5 + 0 + 1 == 6.
        assert_eq!(buf.addn(b"12345"), Ok(()));
        // 5 + 5 + 1 == 11, one past the ceiling.
        assert_eq!(buf.addn(b"67890"), Err(CURLcode::TooLarge));
        assert!(
            buf.is_empty(),
            "the second append frees what the first left"
        );
    }

    /// A buffer left usable after an overflow still enforces the same ceiling.
    #[test]
    fn an_emptied_buffer_keeps_its_ceiling() {
        let mut buf = DynBuf::new(8);
        assert_eq!(buf.addn(b"12345678"), Err(CURLcode::TooLarge));

        // Same ceiling, same boundary, both sides.
        assert_eq!(buf.addn(b"1234567"), Ok(()));
        buf.free();
        assert_eq!(buf.addn(b"12345678"), Err(CURLcode::TooLarge));
    }

    /// A ceiling deliberately smaller than [`MIN_FIRST_ALLOC`].
    ///
    /// Named rather than written inline so that the assertion below can pin
    /// the relationship the test depends on.
    const SUB_FLOOR_CEILING: usize = 4;

    /// The premise of [`a_ceiling_below_the_first_allocation_floor_still_works`]
    /// holds at compile time.
    ///
    /// Written as an anonymous constant rather than a runtime assertion so
    /// that raising `MIN_FIRST_ALLOC` to 4 or below breaks the build instead
    /// of leaving a test that no longer exercises the branch it is named for.
    const _: () = assert!(SUB_FLOOR_CEILING < MIN_FIRST_ALLOC);

    /// The first of the C's three first-allocation branches.
    ///
    /// `MIN_FIRST_ALLOC > toobig` exists for exactly this case: a ceiling
    /// below 32 bytes. Without it the first allocation would round up to the
    /// floor and overshoot the ceiling.
    #[test]
    fn a_ceiling_below_the_first_allocation_floor_still_works() {
        // 3 + 0 + 1 == 4.
        let mut buf = DynBuf::new(SUB_FLOOR_CEILING);
        assert_eq!(buf.addn(b"abc"), Ok(()));
        assert_eq!(buf.as_slice(), b"abc");

        // 4 + 0 + 1 == 5.
        let mut buf = DynBuf::new(SUB_FLOOR_CEILING);
        assert_eq!(buf.addn(b"abcd"), Err(CURLcode::TooLarge));
    }

    /// The doubling branch and the clamp that follows it.
    ///
    /// Chosen so that every arm of the growth policy runs: the first append
    /// takes the `fit < MIN_FIRST_ALLOC` branch, the second doubles 32 to 64
    /// and is then clamped down to the ceiling, and the third crosses it.
    /// Capacity is not observable through this interface, so what is asserted
    /// is the content and the boundary -- which is the whole of the contract.
    #[test]
    fn growth_doubles_and_then_clamps_to_the_ceiling() {
        let mut buf = DynBuf::new(40);

        assert_eq!(buf.addn(b"0123456789"), Ok(()));
        assert_eq!(buf.len(), 10);

        assert_eq!(buf.addn(b"abcdefghijklmnopqrstuvwxy"), Ok(()));
        assert_eq!(buf.len(), 35);
        assert_eq!(buf.as_slice(), b"0123456789abcdefghijklmnopqrstuvwxy");

        // 5 + 35 + 1 == 41.
        assert_eq!(buf.addn(b"z!?*+"), Err(CURLcode::TooLarge));
        assert!(buf.is_empty());
    }

    /// Many small appends across several doublings accumulate exactly.
    #[test]
    fn repeated_appends_accumulate_in_order() {
        let mut buf = DynBuf::new(DYN_QLOG_NAME);
        let mut expected = Vec::new();

        for index in 0..64_u8 {
            let chunk = [index, index.wrapping_add(1), index.wrapping_add(2)];
            assert_eq!(buf.addn(&chunk), Ok(()));
            expected.extend_from_slice(&chunk);
        }

        assert_eq!(buf.len(), 192);
        assert_eq!(buf.as_slice(), expected.as_slice());
    }

    // ---- Appending ---------------------------------------------------------

    /// A zero-length append succeeds, and must not be short-circuited away.
    #[test]
    fn a_zero_length_append_succeeds_and_preserves_content() {
        let mut buf = DynBuf::new(DYN_HAXPROXY);

        // On a buffer that has never been touched: the C runs the whole
        // algorithm and allocates, and returns success.
        assert_eq!(buf.addn(b""), Ok(()));
        assert!(buf.is_empty());

        // And it leaves existing content alone.
        assert_eq!(buf.addn(b"already here"), Ok(()));
        assert_eq!(buf.addn(b""), Ok(()));
        assert_eq!(buf.as_slice(), b"already here");
    }

    /// A zero-length append still runs the ceiling test.
    ///
    /// With the buffer one byte short of its ceiling, `0 + (n - 1) + 1 == n`,
    /// which is not greater than `n`, so it succeeds -- but it succeeds by
    /// passing the test, not by skipping it.
    #[test]
    fn a_zero_length_append_at_the_ceiling_still_succeeds() {
        let mut buf = DynBuf::new(4);
        assert_eq!(buf.addn(b"abc"), Ok(()));
        assert_eq!(buf.addn(b""), Ok(()));
        assert_eq!(buf.as_slice(), b"abc");
    }

    #[test]
    fn add_appends_a_string_slice() {
        let mut buf = DynBuf::new(DYN_HTTP_REQUEST);

        assert_eq!(buf.add("GET / HTTP/1.1"), Ok(()));
        assert_eq!(buf.add("\r\n"), Ok(()));
        assert_eq!(buf.as_slice(), b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn add_respects_the_ceiling_and_empties_on_refusal() {
        let mut buf = DynBuf::new(4);
        assert_eq!(buf.add("abc"), Ok(()));
        assert_eq!(buf.add("d"), Err(CURLcode::TooLarge));
        assert!(buf.is_empty());
    }

    /// A multi-byte character is appended as its bytes, not its scalar.
    #[test]
    fn add_appends_utf8_bytes_and_counts_them_as_bytes() {
        let mut buf = DynBuf::new(DYN_QLOG_NAME);

        // Two scalars, three bytes: one ASCII plus a two-byte sequence.
        assert_eq!(buf.add("a\u{00f6}"), Ok(()));
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.as_slice(), &[b'a', 0xc3, 0xb6]);
    }

    // ---- Formatted appending ----------------------------------------------

    #[test]
    fn addf_appends_formatted_output() {
        let mut buf = DynBuf::new(DYN_HTTP_REQUEST);

        assert_eq!(buf.addf(format_args!("Host: {}", "example.com")), Ok(()));
        assert_eq!(buf.addf(format_args!("\r\nPort: {}", 443_u16)), Ok(()));
        assert_eq!(buf.as_slice(), b"Host: example.com\r\nPort: 443");
    }

    /// Formatted output that crosses the ceiling reports `TooLarge` and
    /// empties the buffer, exactly as a plain append does.
    #[test]
    fn addf_reports_too_large_and_empties_the_buffer() {
        let mut buf = DynBuf::new(8);

        assert_eq!(
            buf.addf(format_args!("{}", 123_456_789_u32)),
            Err(CURLcode::TooLarge)
        );
        assert!(buf.is_empty());
    }

    /// The ceiling is applied as the output is produced, so a format whose
    /// pieces each fit but whose result does not is still refused -- and what
    /// had already been rendered is destroyed with the rest.
    #[test]
    fn addf_enforces_the_ceiling_fragment_by_fragment() {
        let mut buf = DynBuf::new(16);
        assert_eq!(buf.add("start:"), Ok(()));

        assert_eq!(
            buf.addf(format_args!("{}-{}-{}", "aaaa", "bbbb", "cccc")),
            Err(CURLcode::TooLarge)
        );
        assert!(buf.is_empty(), "a partial rendering must not survive");
    }

    /// A failing `Display` maps to out-of-memory and empties the buffer.
    ///
    /// This is the C's "anything else" arm at `lib/curlx/dynbuf.c:201`, and
    /// the only route by which this module returns `CURLE_OUT_OF_MEMORY`.
    #[test]
    fn addf_maps_a_formatting_failure_to_out_of_memory() {
        let mut buf = DynBuf::new(DYN_HTTP_REQUEST);
        assert_eq!(buf.add("kept until the failure"), Ok(()));

        assert_eq!(
            buf.addf(format_args!("{}", FailingDisplay)),
            Err(CURLcode::OutOfMemory)
        );
        assert!(buf.is_empty(), "the failure must free the whole buffer");
    }

    // ---- The three ways to empty a buffer ---------------------------------

    /// `reset` clears the content, keeps the allocation and permits reuse.
    #[test]
    fn reset_clears_the_content_and_permits_further_appends() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.add("first line"), Ok(()));

        buf.reset();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());

        assert_eq!(buf.add("second line"), Ok(()));
        assert_eq!(buf.as_slice(), b"second line");
    }

    /// `free` releases the allocation and also permits reuse -- the C comment
    /// at `lib/curlx/dynbuf.c:53-54` guarantees it in as many words.
    #[test]
    fn free_releases_the_allocation_and_permits_further_appends() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.add("first"), Ok(()));

        buf.free();
        assert!(buf.is_empty());

        assert_eq!(buf.add("second"), Ok(()));
        assert_eq!(buf.as_slice(), b"second");
    }

    /// `reset` on an already-freed buffer is a no-op, not a fault.
    ///
    /// The C's comment says it "can also be called on a buffer that already
    /// was freed", and its implementation guards the write with `if(s->leng)`
    /// to make that true. `Vec::clear` needs no guard.
    #[test]
    fn reset_after_free_is_harmless() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.add("content"), Ok(()));

        buf.free();
        buf.reset();
        buf.reset();
        assert!(buf.is_empty());

        assert_eq!(buf.add("still usable"), Ok(()));
        assert_eq!(buf.as_slice(), b"still usable");
    }

    /// Both operations are total on a buffer that was never appended to.
    #[test]
    fn reset_and_free_are_total_on_an_untouched_buffer() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        buf.reset();
        buf.free();
        buf.reset();
        assert!(buf.is_empty());
        assert_eq!(buf.as_slice(), b"");
    }

    // ---- Truncation -------------------------------------------------------

    #[test]
    fn tail_keeps_the_last_bytes() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.addn(b"abcdef"), Ok(()));

        assert_eq!(buf.tail(3), Ok(()));
        assert_eq!(buf.as_slice(), b"def");
        assert_eq!(buf.len(), 3);
    }

    /// An overlapping move: the kept tail is more than half the buffer, so
    /// source and destination ranges overlap and the C needs `memmove` rather
    /// than `memcpy`. `copy_within` is defined for exactly this.
    #[test]
    fn tail_handles_an_overlapping_move() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.addn(b"abcdef"), Ok(()));

        assert_eq!(buf.tail(5), Ok(()));
        assert_eq!(buf.as_slice(), b"bcdef");
    }

    #[test]
    fn tail_rejects_more_than_the_buffer_holds() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.addn(b"abcdef"), Ok(()));

        assert_eq!(buf.tail(7), Err(CURLcode::BadFunctionArgument));
        assert_eq!(
            buf.as_slice(),
            b"abcdef",
            "a rejected tail must not disturb the buffer"
        );
    }

    #[test]
    fn tail_of_the_whole_buffer_changes_nothing() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.addn(b"abcdef"), Ok(()));

        assert_eq!(buf.tail(6), Ok(()));
        assert_eq!(buf.as_slice(), b"abcdef");
    }

    #[test]
    fn tail_of_zero_empties_the_buffer_and_keeps_it_usable() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.addn(b"abcdef"), Ok(()));

        assert_eq!(buf.tail(0), Ok(()));
        assert!(buf.is_empty());

        assert_eq!(buf.addn(b"again"), Ok(()));
        assert_eq!(buf.as_slice(), b"again");
    }

    /// `tail` on an empty buffer: zero is the only admissible argument, and it
    /// is a no-op.
    #[test]
    fn tail_on_an_empty_buffer() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);

        assert_eq!(buf.tail(0), Ok(()));
        assert_eq!(buf.tail(1), Err(CURLcode::BadFunctionArgument));
        assert!(buf.is_empty());
    }

    #[test]
    fn setlen_keeps_the_first_bytes() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.addn(b"abcdef"), Ok(()));

        assert_eq!(buf.setlen(2), Ok(()));
        assert_eq!(buf.as_slice(), b"ab");
        assert_eq!(buf.len(), 2);
    }

    #[test]
    fn setlen_rejects_a_larger_length() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.addn(b"abcdef"), Ok(()));

        assert_eq!(buf.setlen(7), Err(CURLcode::BadFunctionArgument));
        assert_eq!(
            buf.as_slice(),
            b"abcdef",
            "a rejected setlen must not disturb the buffer"
        );
    }

    #[test]
    fn setlen_of_zero_empties_the_buffer() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(buf.addn(b"abcdef"), Ok(()));

        assert_eq!(buf.setlen(0), Ok(()));
        assert!(buf.is_empty());

        assert_eq!(buf.addn(b"again"), Ok(()));
        assert_eq!(buf.as_slice(), b"again");
    }

    /// `setlen(0)` on a buffer that was never appended to.
    ///
    /// The input on which the C dereferences a null `bufr`
    /// (`lib/curlx/dynbuf.c:290`). Here it is simply a no-op.
    #[test]
    fn setlen_of_zero_on_an_untouched_buffer_is_a_no_op() {
        let mut buf = DynBuf::new(DYN_H1_TRAILER);

        assert_eq!(buf.setlen(0), Ok(()));
        assert!(buf.is_empty());
        assert_eq!(buf.setlen(1), Err(CURLcode::BadFunctionArgument));
    }

    /// `setlen` and `tail` are complements, and neither is the other.
    #[test]
    fn setlen_and_tail_keep_opposite_ends() {
        let mut left = DynBuf::new(DYN_H1_TRAILER);
        let mut right = DynBuf::new(DYN_H1_TRAILER);
        assert_eq!(left.addn(b"abcdef"), Ok(()));
        assert_eq!(right.addn(b"abcdef"), Ok(()));

        assert_eq!(left.setlen(2), Ok(()));
        assert_eq!(right.tail(2), Ok(()));

        assert_eq!(left.as_slice(), b"ab");
        assert_eq!(right.as_slice(), b"ef");
    }

    // ---- Accessors --------------------------------------------------------

    /// A never-appended buffer yields an empty slice, where the C yields
    /// `NULL`. The documented behaviour change, pinned.
    #[test]
    fn as_slice_on_an_untouched_buffer_is_empty_not_null() {
        let buf = DynBuf::new(DYN_DOH_CNAME);

        assert!(buf.as_slice().is_empty());
        assert_eq!(buf.as_slice(), b"");
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    /// The same holds after `free`, which is the state the C represents as a
    /// null pointer.
    #[test]
    fn as_slice_after_free_is_empty() {
        let mut buf = DynBuf::new(DYN_DOH_CNAME);
        assert_eq!(buf.addn(b"something"), Ok(()));

        buf.free();
        assert!(buf.as_slice().is_empty());
    }

    /// Nothing appends a terminator.
    #[test]
    fn no_trailing_zero_is_stored() {
        let mut buf = DynBuf::new(DYN_DOH_CNAME);
        assert_eq!(buf.add("abc"), Ok(()));

        assert_eq!(buf.len(), 3, "the length is the C's leng exactly");
        assert_eq!(buf.as_slice(), b"abc");
        assert!(!buf.as_slice().contains(&0), "no terminator is stored");
    }

    #[test]
    fn as_mut_slice_edits_in_place_without_changing_the_length() {
        let mut buf = DynBuf::new(DYN_DOH_CNAME);
        assert_eq!(buf.addn(b"abc"), Ok(()));

        buf.as_mut_slice()[0] = b'A';
        buf.as_mut_slice().reverse();

        assert_eq!(buf.as_slice(), b"cbA");
        assert_eq!(buf.len(), 3);
    }

    #[test]
    fn is_empty_agrees_with_the_length() {
        let mut buf = DynBuf::new(DYN_DOH_CNAME);
        assert!(buf.is_empty());

        assert_eq!(buf.addn(b"x"), Ok(()));
        assert!(!buf.is_empty());
        assert_eq!(buf.len(), 1);

        buf.reset();
        assert!(buf.is_empty());
    }

    // ---- Ownership transfer ----------------------------------------------

    #[test]
    fn take_transfers_the_bytes_and_resets_the_buffer() {
        let mut buf = DynBuf::new(DYN_DOH_RESPONSE);
        assert_eq!(buf.addn(b"payload"), Ok(()));

        let taken = buf.take();
        assert_eq!(taken, b"payload".to_vec());
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(buf.as_slice().is_empty());
    }

    /// `take` keeps the ceiling, exactly as `curlx_dyn_take` leaves `toobig`
    /// alone.
    #[test]
    fn take_keeps_the_ceiling_and_the_buffer_stays_usable() {
        let mut buf = DynBuf::new(8);
        assert_eq!(buf.addn(b"1234567"), Ok(()));

        let taken = buf.take();
        assert_eq!(taken.len(), 7);

        // The same boundary as before, from both sides.
        assert_eq!(buf.addn(b"12345678"), Err(CURLcode::TooLarge));
        assert_eq!(buf.addn(b"1234567"), Ok(()));
        assert_eq!(buf.as_slice(), b"1234567");
    }

    #[test]
    fn take_on_an_untouched_buffer_yields_nothing() {
        let mut buf = DynBuf::new(DYN_DOH_RESPONSE);

        assert!(buf.take().is_empty());
        assert!(buf.is_empty());
    }

    // ---- Diagnostics ------------------------------------------------------

    /// The hand-written `Debug` reports the shape, never the contents.
    #[test]
    fn debug_reports_the_shape_and_not_the_bytes() {
        let mut buf = DynBuf::new(DYN_QLOG_NAME);
        assert_eq!(buf.addn(b"abc"), Ok(()));

        let rendered = format!("{buf:?}");
        assert!(rendered.starts_with("DynBuf {"), "{rendered}");
        assert!(rendered.contains("len: 3"), "{rendered}");
        assert!(rendered.contains("capacity: "), "{rendered}");
        assert!(rendered.contains("toobig: 1024"), "{rendered}");
        assert!(
            !rendered.contains("97"),
            "the bytes themselves must not appear: {rendered}"
        );
    }

    // ---- The debug-only construction checks -------------------------------
    //
    // Both reproduce a `DEBUGASSERT` and are therefore debug-only, exactly as
    // in the C. The `cfg` is what keeps them honest rather than merely green:
    // without it, a release-profile test run would report a failure to panic
    // as a defect, when the absence of the panic is the specified behaviour.

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "ceiling of zero")]
    fn a_zero_ceiling_is_a_caller_mistake() {
        let _ = DynBuf::new(0);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "above MAX_DYNBUF_SIZE")]
    fn a_ceiling_above_the_maximum_is_a_caller_mistake() {
        let _ = DynBuf::new(MAX_DYNBUF_SIZE + 1);
    }

    /// The largest admissible ceiling is accepted.
    #[test]
    fn the_maximum_ceiling_is_admissible() {
        let mut buf = DynBuf::new(MAX_DYNBUF_SIZE);

        assert_eq!(buf.addn(b"small append, enormous ceiling"), Ok(()));
        assert_eq!(buf.len(), 30);
    }

    /// A ceiling of one admits nothing but an empty append.
    ///
    /// `0 + 0 + 1 == 1` passes; one byte would need two.
    #[test]
    fn a_ceiling_of_one_admits_only_the_empty_append() {
        let mut buf = DynBuf::new(1);

        assert_eq!(buf.addn(b""), Ok(()));
        assert_eq!(buf.addn(b"x"), Err(CURLcode::TooLarge));
        assert!(buf.is_empty());
    }

    /// Every code this module can return is one of the three documented ones,
    /// with the pinned integer the C ABI froze.
    #[test]
    fn the_returned_codes_carry_their_c_values() {
        assert_eq!(CURLcode::TooLarge.as_i32(), 100);
        assert_eq!(CURLcode::OutOfMemory.as_i32(), 27);
        assert_eq!(CURLcode::BadFunctionArgument.as_i32(), 43);
    }
}
