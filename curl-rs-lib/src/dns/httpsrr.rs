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

//! HTTPS resource records: the RFC 9460 SVCB/HTTPS record and its SvcParams.
//!
//! Supersedes the portable half of `lib/httpsrr.c` (`:26-150`) and all of
//! `lib/httpsrr.h`. The type is [`HttpsRrInfo`], superseding
//! `struct Curl_https_rrinfo` (`lib/httpsrr.h:39-57`); the per-parameter
//! setter is [`HttpsRrInfo::set_param`], superseding `Curl_httpsrr_set`
//! (`lib/httpsrr.c:71-132`); and the ALPN list decoder is [`decode_alpn`],
//! superseding the file-local `httpsrr_decode_alpn` (`:34-69`).
//!
//! Every claim below is cited, per AAP 0.7 (*"Claims are evidenced, not
//! asserted"*). The C lines this module was measured against are
//! `lib/httpsrr.c:34-150`, `lib/httpsrr.h:34-35`, `:39-57` and `:71-77`,
//! `lib/connect.c:71-88`, `lib/hostip.h:49-54`, `lib/doh.c:1104-1156` and
//! `:1167`, `lib/urlapi.c:223-239`, `lib/version.c:454-455` and `:492-493`,
//! `CMakeLists.txt:2008` and `:2034`, and `configure.ac:4990-4997`.
//!
//! # Where this module ends and `doh.rs` begins
//!
//! `Curl_httpsrr_set` is a **per-SvcParam** setter. Nothing in
//! `lib/httpsrr.c` walks a *record*: the code that reads the priority,
//! decodes the target name and loops over the SvcParams is
//! `doh_resp_decode_httpsrr` (`lib/doh.c:1104-1156`). The division is
//! therefore inherited rather than invented:
//!
//! * **This module owns** the record's decoded shape ([`HttpsRrInfo`]), the
//!   seven SvcParam code points, [`MAX_HTTPSRR_ALPNS`],
//!   [`CURL_MAXLEN_HOST_NAME`], [`decode_alpn`] and
//!   [`set_param`](HttpsRrInfo::set_param) with its eight trace strings.
//! * **`dns/doh.rs` owns** the record walk, because that walk needs
//!   `doh.rs`'s own DNS-wire helpers (`doh_get16bit`,
//!   `doh_decode_rdata_name`), and calls
//!   [`set_param`](HttpsRrInfo::set_param) inside its loop.
//!
//! **This module must never `use crate::dns::doh`.** Two reasons, and the
//! second is the binding one. It would make the import graph
//! `httpsrr -> doh -> httpsrr`, and `doh` is a Cargo feature: a
//! `--no-default-features` build has no `doh` module at all, and this module
//! is compiled unconditionally, so an import of it would not even resolve.
//! The dependency runs one way, from the record walk down to the setter.
//!
//! ## The record-level invariants, documented where the setter lives
//!
//! [`set_param`](HttpsRrInfo::set_param) is `pub(crate)` and therefore
//! directly callable, so the conditions its only production caller
//! establishes are recorded here rather than left implicit in another file.
//! From `doh_resp_decode_httpsrr` (`lib/doh.c:1104-1156`):
//!
//! * `len <= 2` is rejected with `CURLE_BAD_FUNCTION_ARGUMENT` before
//!   anything is allocated (`:1116-1117`).
//! * [`priority`](HttpsRrInfo::priority) is the big-endian `u16` in the
//!   first two bytes (`:1121`), after which those two bytes are consumed.
//! * [`target`](HttpsRrInfo::target) comes from `doh_decode_rdata_name` and
//!   is then screened by `Curl_junkscan(dnsname, &olen, FALSE)`; rejection
//!   is `CURLE_WEIRD_SERVER_REPLY` (`:1127-1131`). `Curl_junkscan`
//!   (`lib/urlapi.c:223-239`, commented *"scan for byte values <= 31, 127
//!   and sometimes space"*) sets `control = 0x20` when `allowspace` is
//!   false, so **every byte `<= 0x20` -- the space included -- and every
//!   byte `== 127` is rejected**, as is a name longer than
//!   `CURL_MAX_INPUT_LENGTH`. ⚠️ That function lives in `lib/urlapi.c`,
//!   whose successor `crate::url` does not carry it, so **`doh.rs` must
//!   implement the check locally** rather than reach for a module that does
//!   not provide it.
//! * [`port`](HttpsRrInfo::port) is set to "not yet set" before the loop
//!   (`lhrr->port = -1; /* until set */`, `:1132`).
//! * The loop is `while(len >= 4)`, reading `pcode` and `plen` as two
//!   big-endian `u16`s and consuming four bytes (`:1133-1137`).
//! * ⚠️ `if(pcode < expected_min_pcode || plen > len)` is
//!   `CURLE_WEIRD_SERVER_REPLY`, with `expected_min_pcode = pcode + 1` after
//!   each parameter (`:1138-1147`). That enforces **strictly ascending
//!   SvcParam keys**, which RFC 9460 requires and which means a duplicate
//!   key can never reach this module from the DoH path. The
//!   replace-not-append semantics documented on
//!   [`set_param`](HttpsRrInfo::set_param) is therefore unreachable through
//!   that caller -- and is still implemented faithfully, because the setter
//!   is callable without it.
//! * `DEBUGASSERT(!len)` follows the loop (`:1149`): a trailing one-to-three
//!   byte remainder is *tolerated* in a release build. The faithful analogue
//!   is `debug_assert!`, not a hard error.
//!
//! # Compiled unconditionally, advertised conditionally
//!
//! C wraps the whole file in `#ifdef USE_HTTPSRR` (`lib/httpsrr.c:26`,
//! `lib/httpsrr.h:32`), which `configure.ac:4990-4997` defines **by
//! default** -- `--disable-httpsrr` is the opt-out -- and which enabling ECH
//! forces on (`lib/version.c:469-470` makes the inconsistent combination a
//! `#error`).
//!
//! There is no `httpsrr` Cargo feature: the fifteen are `http2`, `http3`,
//! `ftp`, `ssh`, `websockets`, `cookies`, `hsts`, `altsvc`, `doh`, `brotli`,
//! `zstd`, `gzip`, `negotiate`, `hickory-dns` and `memdebug`. **This module
//! therefore carries no `cfg` at all.** Inventing one would be worse than
//! useless: `#[cfg(feature = "httpsrr")]` on a feature that does not exist
//! silently deletes the code it guards, with no diagnostic anywhere.
//!
//! ## The reciprocal contract with `crate::version`
//!
//! Whether the `Features:` banner says `HTTPSRR` is
//! `curl-rs-lib/src/version.rs`'s decision, not this module's, and the two
//! must not drift -- so the condition is written down in both places.
//!
//! AAP 0.6.5 measures the asymmetry that settles it: the test harness parses
//! that line and uses it to choose which fixtures to run, so
//! **over-reporting turns a clean skip into a hard failure while
//! under-reporting merely skips**. The determinant is that, with c-ares
//! dropped (AAP 0.5.2), `Curl_httpsrr_from_ares` is gone and the **only**
//! surviving producer of an [`HttpsRrInfo`] is the DoH path
//! (`lib/doh.c:1104-1156`, reaching `dns->hinfo` at `:1274`). HTTPS RR is
//! consequently functional only when a record walk exists behind the `doh`
//! feature. It does not yet, and `version.rs` withholds the name for exactly
//! that reason; the name becomes truthful when that producer lands, and not
//! before. The measured cost of withholding is nil: `HTTPSRR` appears in one
//! fixture only, `tests/data/test2100:72`, and there as an in-fixture
//! `%if HTTPSRR` conditional rather than a `<features>` gate.
//!
//! Two C precedents differ from each other, so which one is followed is
//! stated rather than assumed. `lib/version.c:492-493` emits
//! `FEATURE("HTTPSRR", NULL, 0)` under a plain `#ifdef USE_HTTPSRR`, while
//! `CMakeLists.txt:2034` is `curl_add_if("HTTPSRR" _ssl_enabled AND
//! USE_HTTPSRR)` and so *additionally* requires TLS. **The CMake condition
//! is the one this workspace follows**, because it is the stricter of the
//! two and stricter is the safe direction here; TLS is unconditional in this
//! crate, so the clause that decides the row is the presence of a producer.
//!
//! ## `asyn-rr` can never be emitted
//!
//! `lib/version.c:454-455` gates that name on
//! `USE_ARES && CURLRES_THREADED && USE_HTTPSRR`, and `CMakeLists.txt:2008`
//! agrees. c-ares is dropped, so the conjunction can never hold -- which
//! independently confirms the resolver's decision to withhold it. ⚠️ More
//! sharply: `tests/runtests.pl:611-613` matches `/ares/i` **anywhere** in
//! the libcurl banner and switches the whole harness into c-ares mode, so
//! nothing this module contributes may ever put that substring into
//! `curl --version` output. The word appears in this file only in prose
//! explaining the removal.
//!
//! # Two C functions that vanish rather than move
//!
//! `Curl_httpsrr_dup_move` (`lib/httpsrr.c:134-141`) is
//! `curlx_memdup(rrinfo, sizeof(*rrinfo))` followed by `memset(rrinfo, 0,
//! sizeof(*rrinfo))` -- a hand-written move, needed because C cannot express
//! one. `Curl_httpsrr_cleanup` (`:143-150`) is five `Curl_safefree` calls,
//! over `target`, `echconfiglist`, `ipv4hints`, `ipv6hints` and `rrname`.
//!
//! **Rust ownership and `Drop` subsume both entirely.** Moving an
//! [`HttpsRrInfo`] is a move; dropping one releases every heap field. There
//! is deliberately **no `cleanup` method and no hand-written `Drop`
//! implementation** here: either would be a second, weaker spelling of what
//! the language already guarantees, and a `cleanup` that left a
//! partially-emptied value behind would reintroduce precisely the state the
//! C `memset` exists to erase. The absence is a decision, not an omission.
//!
//! `Curl_httpsrr_from_ares` (`:167-205`) and its helper `httpsrr_opt`
//! (`:154-165`) are dropped with c-ares, along with the only two trace
//! strings that mention a target or a priority. Those strings are
//! consequently **absent from this module by design** -- the DoH path has
//! its own, differently spelled, and they belong to `doh.rs`.
//!
//! # Attacker-controlled input
//!
//! Every byte reaching [`decode_alpn`] or
//! [`set_param`](HttpsRrInfo::set_param) came off the network in a DNS
//! response. A panic here unwinds toward a C caller through `curl-rs-ffi`,
//! so this module contains **no `unwrap`, no `expect`, no `panic!`, no
//! indexing that could be out of bounds, and no unchecked arithmetic**
//! outside `#[cfg(test)]`. Slice patterns, `split_first`, `split_at` behind
//! a proven bound, `get` and `get_mut` do the work that C does with a
//! pointer and a decrementing length. The release profile sets
//! `overflow-checks = true`, so a wrapping subtraction would panic there
//! too, not merely in a debug build.

use super::AlpnId;
use crate::error::{CURLcode, CodeResult};
use crate::trace::{trc_feat, TraceFeature, Tracer};

/// The longest host name curl will accept, `253` bytes.
///
/// `#define CURL_MAXLEN_host_name 253` (`lib/httpsrr.h:34`). Spelled in
/// Rust's constant case; C's mixed-case identifier is quoted here so the
/// grep from one tree to the other still lands.
///
/// The number is the DNS presentation-format limit: 255 octets of wire
/// format less the leading length byte and the root label's terminating
/// zero. Nothing in `lib/httpsrr.c` reads it -- the header defines it beside
/// the record because the record's `target` is a host name -- so it is
/// carried here for the same reason, as the bound a consumer of
/// [`HttpsRrInfo::target`] measures against.
// No consumer yet; doh.rs bounds the decoded target name with it.
#[allow(dead_code)]
pub(crate) const CURL_MAXLEN_HOST_NAME: usize = 253;

/// How many ALPN identifiers one HTTPS RR may contribute, `4`.
///
/// `#define MAX_HTTPSRR_ALPNS 4` (`lib/httpsrr.h:35`), sizing
/// `unsigned char alpns[MAX_HTTPSRR_ALPNS]` (`:52`).
///
/// # Why four, when only three identifiers exist
///
/// [`AlpnId`] has exactly three storable values -- `H1`, `H2` and `H3`;
/// `None` is the absence of one -- and [`decode_alpn`] deduplicates, so at
/// most three can ever be stored. The fourth slot is what guarantees room
/// for the `ALPN_none` terminator described on [`decode_alpn`]. That is not
/// a spare: it is the reason the terminator is always written today, and it
/// is why the array is four bytes rather than three.
pub(crate) const MAX_HTTPSRR_ALPNS: usize = 4;

// THE SEVEN SvcParam CODE POINTS
//
// `lib/httpsrr.h:71-77`, under the comment "Code points for DNS wire format
// SvcParams as per RFC 9460" (`:68-70`).
//
// Plain `u16` constants rather than an enumeration, and the choice is
// forced rather than stylistic: `Curl_httpsrr_set`'s `default:` arm accepts
// ANY unrecognised key and reports it (`lib/httpsrr.c:127-129`), so the
// parameter type has to be the wire type. An enumeration would demand a
// fallible conversion at the call site to buy nothing, and would put the
// failure in the wrong place -- an unknown code point is a normal event
// that the sender is entitled to send, not a decoding error.
//
// Each value is written explicitly and each carries `#[rustfmt::skip]` so
// that no formatter can renormalise a frozen wire constant out of the
// hexadecimal spelling the RFC and the C header both use. The values are
// never inferred from declaration order.

/// `HTTPS_RR_CODE_MANDATORY 0x00` (`lib/httpsrr.h:71`), RFC 9460 `mandatory`.
#[rustfmt::skip]
pub(crate) const HTTPS_RR_CODE_MANDATORY: u16 = 0x00;

/// `HTTPS_RR_CODE_ALPN 0x01` (`lib/httpsrr.h:72`), RFC 9460 `alpn`.
///
/// The keytag the `alpns` field records (`lib/httpsrr.h:52`).
#[rustfmt::skip]
pub(crate) const HTTPS_RR_CODE_ALPN: u16 = 0x01;

/// `HTTPS_RR_CODE_NO_DEF_ALPN 0x02` (`lib/httpsrr.h:73`), RFC 9460
/// `no-default-alpn`.
///
/// The keytag the `no_def_alpn` field records (`lib/httpsrr.h:56`).
#[rustfmt::skip]
pub(crate) const HTTPS_RR_CODE_NO_DEF_ALPN: u16 = 0x02;

/// `HTTPS_RR_CODE_PORT 0x03` (`lib/httpsrr.h:74`), RFC 9460 `port`.
#[rustfmt::skip]
pub(crate) const HTTPS_RR_CODE_PORT: u16 = 0x03;

/// `HTTPS_RR_CODE_IPV4 0x04` (`lib/httpsrr.h:75`), RFC 9460 `ipv4hint`.
///
/// The keytag the `ipv4hints` field records (`lib/httpsrr.h:46`).
#[rustfmt::skip]
pub(crate) const HTTPS_RR_CODE_IPV4: u16 = 0x04;

/// `HTTPS_RR_CODE_ECH 0x05` (`lib/httpsrr.h:76`), RFC 9460 `ech`.
///
/// The keytag the `echconfiglist` field records (`lib/httpsrr.h:48`).
#[rustfmt::skip]
pub(crate) const HTTPS_RR_CODE_ECH: u16 = 0x05;

/// `HTTPS_RR_CODE_IPV6 0x06` (`lib/httpsrr.h:77`), RFC 9460 `ipv6hint`.
///
/// The keytag the `ipv6hints` field records (`lib/httpsrr.h:50`).
#[rustfmt::skip]
pub(crate) const HTTPS_RR_CODE_IPV6: u16 = 0x06;

/// One decoded HTTPS resource record.
///
/// Supersedes `struct Curl_https_rrinfo` (`lib/httpsrr.h:39-57`):
///
/// ```c
/// struct Curl_https_rrinfo {
///   char *rrname; /* if NULL, the same as the URL hostname */
///   /*
///    * Fields from HTTPS RR. The only mandatory fields are priority and
///    * target.
///    * See https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2
///    */
///   char *target;
///   unsigned char *ipv4hints; /* keytag = 4 */
///   size_t ipv4hints_len;
///   unsigned char *echconfiglist; /* keytag = 5 */
///   size_t echconfiglist_len;
///   unsigned char *ipv6hints; /* keytag = 6 */
///   size_t ipv6hints_len;
///   unsigned char alpns[MAX_HTTPSRR_ALPNS]; /* keytag = 1 */
///   /* store parsed alpnid entries in the array, end with ALPN_none */
///   int port; /* -1 means not set */
///   uint16_t priority;
///   BIT(no_def_alpn); /* keytag = 2 */
/// };
/// ```
///
/// Field order is C's declaration order, so the two can be read side by
/// side. Three shapes change, each for a stated reason.
///
/// # The three `*_len` companions disappear
///
/// C pairs every byte buffer with an explicit length, and the pair can
/// disagree: `Curl_httpsrr_set` assigns the pointer and the length in
/// separate statements (`lib/httpsrr.c:95` and `:98`, and likewise for ECH
/// and IPv6). A `Vec<u8>` carries its own length, so the two cannot
/// disagree, and the three `size_t` fields have no counterpart.
///
/// # `Default` is C's `calloc`, and `None` is C's `-1`
///
/// `doh_resp_decode_httpsrr` obtains its record from
/// `curlx_calloc(1, sizeof(struct Curl_https_rrinfo))` (`lib/doh.c:1118`),
/// so every field starts zeroed -- which [`Default`] reproduces exactly,
/// including `alpns` starting as four `ALPN_none` bytes.
///
/// The one field where zero is *not* the right start is `port`: C
/// immediately overwrites it with `lhrr->port = -1; /* until set */`
/// (`lib/doh.c:1132`), because port zero is a value a record could legally
/// carry and so cannot double as "absent". [`Option<u16>`] expresses that
/// distinction in the type instead, and `None` -- which is what
/// [`Default`] yields -- **is** C's `-1`. The sentinel is gone; the meaning
/// is not.
///
/// # No `cleanup`, and no `Drop`
///
/// See the module documentation: `Curl_httpsrr_cleanup`
/// (`lib/httpsrr.c:143-150`) and `Curl_httpsrr_dup_move` (`:134-141`) are
/// both subsumed by ownership, and neither is reproduced.
///
/// [`Option<u16>`]: Option
#[derive(Clone, Debug, Default, Eq, PartialEq)]
// No consumer yet; doh.rs produces it and conn/ reads it, as the C pair
// `lib/doh.c:1274` and `lib/cf-https-connect.c:670` do.
#[allow(dead_code)]
pub(crate) struct HttpsRrInfo {
    /// C's `rrname`, whose comment reads *"if NULL, the same as the URL
    /// hostname"* (`lib/httpsrr.h:40`).
    ///
    /// [`None`] is that `NULL`: the record was queried for the host the URL
    /// already names, so there is nothing extra to record. Only the c-ares
    /// path ever set it (`lib/asyn-ares.c:809`,
    /// `lib/asyn-thrdd.c:376`) and it was cleared again on the way out
    /// (`lib/httpsrr.c:203`), so with c-ares dropped no producer in this
    /// crate populates it today. It is carried because it is part of the
    /// superseded struct and because a future producer that queries a
    /// different name has nowhere else to say so.
    pub(crate) rrname: Option<String>,
    /// C's `target`: the host name the record points at.
    ///
    /// Mandatory per RFC 9460 section 14.3.2, as C's own comment says
    /// (`lib/httpsrr.h:41-44`) -- yet the C field is a nullable pointer, so
    /// [`Option`] is the faithful shape. The record-level decoder does
    /// always set it before returning success (`lib/doh.c:1126`), which is
    /// how the mandatory field and the nullable pointer coexist.
    pub(crate) target: Option<String>,
    /// C's `ipv4hints` plus `ipv4hints_len`, keytag `4`
    /// ([`HTTPS_RR_CODE_IPV4`]).
    ///
    /// Stored verbatim, four bytes per address; the length is a multiple of
    /// four because [`set_param`](Self::set_param) rejects anything else.
    pub(crate) ipv4hints: Option<Vec<u8>>,
    /// C's `echconfiglist` plus `echconfiglist_len`, keytag `5`
    /// ([`HTTPS_RR_CODE_ECH`]).
    ///
    /// Stored verbatim and **not interpreted**. Encrypted Client Hello is
    /// not among this crate's features, so there is deliberately no consumer
    /// -- the bytes are preserved so that adding one later needs no change
    /// here. `CURLE_ECH_REQUIRED` exists in [`CURLcode`] and is never raised
    /// from this module.
    pub(crate) echconfiglist: Option<Vec<u8>>,
    /// C's `ipv6hints` plus `ipv6hints_len`, keytag `6`
    /// ([`HTTPS_RR_CODE_IPV6`]).
    ///
    /// Stored verbatim, sixteen bytes per address; the length is a multiple
    /// of sixteen because [`set_param`](Self::set_param) rejects anything
    /// else.
    pub(crate) ipv6hints: Option<Vec<u8>>,
    /// C's `alpns`, keytag `1` ([`HTTPS_RR_CODE_ALPN`]), whose comment reads
    /// *"store parsed alpnid entries in the array, end with ALPN_none"*
    /// (`lib/httpsrr.h:52-53`).
    ///
    /// **The fixed array is kept, and so is the byte representation.** Each
    /// entry is an [`AlpnId`] discriminant as a single byte, which is what
    /// makes the deduplication in [`decode_alpn`] a byte search and what
    /// makes the terminator convention expressible at all. A `Vec` would
    /// look tidier and would quietly change the boundary semantics
    /// [`decode_alpn`] documents, and `lib/doh.c:1167` reads `alpns[0]`
    /// directly to decide whether to print anything.
    ///
    /// Read it through [`alpns`](Self::alpns), which applies that
    /// convention.
    pub(crate) alpns: [u8; MAX_HTTPSRR_ALPNS],
    /// C's `port`, keytag `3` ([`HTTPS_RR_CODE_PORT`]), whose comment reads
    /// *"-1 means not set"* (`lib/httpsrr.h:54`).
    ///
    /// C declares an `int` purely to have a value outside the port range to
    /// use as a sentinel, then stores `(unsigned short)` into it
    /// (`lib/httpsrr.c:124`). [`None`] is that sentinel and `u16` is the
    /// range actually stored.
    pub(crate) port: Option<u16>,
    /// C's `priority`: the record's `SvcPriority`.
    ///
    /// Mandatory per RFC 9460, and not a SvcParam -- it is the first two
    /// bytes of the record's RDATA, so the record walk sets it
    /// (`lib/doh.c:1121`) and [`set_param`](Self::set_param) never touches
    /// it. **Zero is meaningful**: RFC 9460 gives priority zero to AliasMode,
    /// where the record redirects rather than describes, which is why this is
    /// a plain `u16` with no sentinel.
    pub(crate) priority: u16,
    /// C's `BIT(no_def_alpn)`, keytag `2`
    /// ([`HTTPS_RR_CODE_NO_DEF_ALPN`]).
    ///
    /// A one-bit bitfield in C, a `bool` here. Set by the presence of the
    /// parameter, never by its contents: RFC 9460 gives `no-default-alpn` an
    /// empty value, and [`set_param`](Self::set_param) rejects a non-empty
    /// one.
    pub(crate) no_def_alpn: bool,
}

/// The byte that ends the ALPN list.
///
/// `ALPN_none`, which `lib/hostip.h:50` fixes at zero. Named rather than
/// written as `0`, because the zero is the enumerator's value and not a
/// coincidence: `lib/httpsrr.c:67` writes `ALPN_none` and `lib/doh.c:1167`
/// compares against it.
const ALPN_TERMINATOR: u8 = AlpnId::None.as_u8();

impl HttpsRrInfo {
    /// The ALPN identifiers this record advertises, in the order it listed
    /// them.
    ///
    /// Applies the terminator convention [`decode_alpn`] establishes: the
    /// walk stops at the first [`ALPN_TERMINATOR`], or after
    /// [`MAX_HTTPSRR_ALPNS`] entries if there is no terminator to find. A
    /// full list and a terminated list are therefore both valid ends, and a
    /// caller does not have to know which it has.
    ///
    /// A byte that is not an [`AlpnId`] discriminant is skipped rather than
    /// reported. [`decode_alpn`] cannot produce one -- it only ever stores
    /// [`AlpnId::as_u8`] results -- but the field is reachable, and silently
    /// ignoring an uninterpretable entry is what
    /// `Curl_alpn2alpnid`'s own contract does with an unrecognised protocol
    /// name (`lib/connect.c:87`, commented *"unknown, probably rubbish
    /// input"*).
    // No consumer yet; conn/ reads it where `lib/cf-https-connect.c:670`
    // reads the C array.
    #[allow(dead_code)]
    pub(crate) fn alpns(&self) -> impl Iterator<Item = AlpnId> + '_ {
        self.alpns
            .iter()
            .copied()
            .take_while(|&byte| byte != ALPN_TERMINATOR)
            .filter_map(AlpnId::from_u8)
    }

    /// Applies one SvcParam to this record.
    ///
    /// Supersedes `Curl_httpsrr_set` (`lib/httpsrr.c:71-132`):
    ///
    /// ```c
    /// CURLcode Curl_httpsrr_set(struct Curl_easy *data,
    ///                           struct Curl_https_rrinfo *hi,
    ///                           uint16_t rrkey, const uint8_t *val,
    ///                           size_t vlen);
    /// ```
    ///
    /// The `data` handle becomes the `tracer` this crate threads for the
    /// same purpose, `hi` becomes the receiver, and the `val`/`vlen` pointer
    /// pair becomes one slice -- which is also what removes every
    /// opportunity for the two to disagree.
    ///
    /// # The validation rules are deliberately asymmetric
    ///
    /// Each was measured from the C, and none may be regularised into its
    /// neighbours:
    ///
    /// | Code point | Rule | C |
    /// |---|---|---|
    /// | [`HTTPS_RR_CODE_MANDATORY`] | none; not implemented | `:77-79` |
    /// | [`HTTPS_RR_CODE_ALPN`] | whatever [`decode_alpn`] says | `:80-84` |
    /// | [`HTTPS_RR_CODE_NO_DEF_ALPN`] | must be **empty** | `:86-87` |
    /// | [`HTTPS_RR_CODE_PORT`] | **exactly two** bytes | `:122` |
    /// | [`HTTPS_RR_CODE_IPV4`] | non-empty **and** a multiple of 4 | `:92` |
    /// | [`HTTPS_RR_CODE_ECH`] | non-empty, **no** alignment rule | `:102` |
    /// | [`HTTPS_RR_CODE_IPV6`] | non-empty **and** a multiple of 16 | `:112` |
    /// | anything else | none; reported and accepted | `:127-129` |
    ///
    /// Every rejection is `CURLE_BAD_FUNCTION_ARGUMENT`. ECH taking only the
    /// non-emptiness half is the asymmetry most likely to be "tidied" by
    /// mistake: an `ECHConfigList` is a variable-length structure, so there
    /// is nothing for it to be a multiple of.
    ///
    /// # Repeating a parameter replaces, it does not append
    ///
    /// The three buffer arms each `curlx_free` the previous value before
    /// storing the new one (`:94`, `:104`, `:114`). Assigning over an
    /// [`Option<Vec<u8>>`] drops the old buffer and stores the new one,
    /// which is the same observable behaviour -- the second occurrence wins
    /// and the first is gone. The equivalence is stated because the
    /// *behaviour* is the observable part, not the free.
    ///
    /// A duplicate key cannot arrive from the DoH path at all, which
    /// enforces strictly ascending keys; see the module documentation. The
    /// semantics is implemented anyway, because this function is `pub(crate)`
    /// and a future producer may not have that guarantee.
    ///
    /// # Tracing fires on the ALPN failure and on no other
    ///
    /// The ALPN arm stores `decode_alpn`'s result, then emits its trace line,
    /// then `break`s (`:81-84`) -- so the line is emitted **even when the
    /// decode failed**, printing whatever partial state was written. Every
    /// other failing arm `return`s before reaching its trace call, so it
    /// emits nothing. That asymmetry is real, is observable in a `--trace`
    /// log, and is reproduced here rather than smoothed over.
    ///
    /// # The three `CURLE_OUT_OF_MEMORY` arms have no counterpart
    ///
    /// C's `:97`, `:107` and `:117` each report a failed `curlx_memdup`. Rust
    /// aborts on allocation failure rather than returning it, so there is
    /// nothing to report and **no such path is fabricated here**. The
    /// enumerator itself still exists in [`CURLcode`], reachable from the
    /// places that genuinely can run out.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] when a parameter's value fails the
    /// rule tabulated above, or [`CURLcode::BadContentEncoding`] when an
    /// `alpn` value is malformed -- see [`decode_alpn`] for why that
    /// particular code.
    ///
    /// [`Option<Vec<u8>>`]: Option
    // No consumer yet; doh.rs calls it once per SvcParam, exactly where
    // `lib/doh.c:1142` calls the C function.
    #[allow(dead_code)]
    pub(crate) fn set_param(
        &mut self,
        rrkey: u16,
        val: &[u8],
        tracer: &mut Tracer<'_>,
    ) -> CodeResult<()> {
        // `CURLcode result = CURLE_OK;` (`:75`). Only the ALPN arm ever
        // writes it; every other arm either succeeds or returns early, so
        // this carries exactly one arm's outcome past its trace line.
        let mut result: CodeResult<()> = Ok(());

        // C's `switch` runs MANDATORY, ALPN, NO_DEF_ALPN, IPV4, ECH, IPV6,
        // PORT, default -- note PORT (0x03) last, after IPV6 (0x06). A
        // `switch` over distinct constants is order-irrelevant and so is
        // this `match`, so the arms are in numeric order for readability.
        // Eight arms transcribed, eight arms below.
        match rrkey {
            HTTPS_RR_CODE_MANDATORY => {
                // `:77-79`. C implements nothing and says so; reproducing
                // the absence means reproducing the message, because the
                // message is what a `--trace` log shows.
                trc_feat!(
                    tracer,
                    TraceFeature::Dns,
                    "HTTPS RR MANDATORY left to implement"
                );
            }
            HTTPS_RR_CODE_ALPN => {
                // `:80-84`, C's comment on the arm being `/* str_list */`.
                result = decode_alpn(val, &mut self.alpns);
                // `hi->alpns[0], hi->alpns[1], hi->alpns[2], hi->alpns[3]`
                // -- ALL FOUR SLOTS, unconditionally, so trailing
                // `ALPN_none` zeros are printed. That is C's output and it
                // is not to be cleaned up. Destructured rather than indexed
                // so the four-slot shape is checked by the compiler: were
                // `MAX_HTTPSRR_ALPNS` ever to change, this stops building
                // instead of quietly printing the wrong number of columns.
                let [first, second, third, fourth] = self.alpns;
                trc_feat!(
                    tracer,
                    TraceFeature::Dns,
                    "HTTPS RR ALPN: {first} {second} {third} {fourth}"
                );
            }
            HTTPS_RR_CODE_NO_DEF_ALPN => {
                // `if(vlen) /* no data */ return
                //  CURLE_BAD_FUNCTION_ARGUMENT;` (`:86-87`)
                if !val.is_empty() {
                    return Err(CURLcode::BadFunctionArgument);
                }
                // `hi->no_def_alpn = TRUE;` -- the presence of the
                // parameter is the whole payload.
                self.no_def_alpn = true;
                trc_feat!(tracer, TraceFeature::Dns, "HTTPS RR no-def-alpn");
            }
            HTTPS_RR_CODE_PORT => {
                // `if(vlen != 2) return CURLE_BAD_FUNCTION_ARGUMENT;`
                // (`:122-123`) then
                // `hi->port = (unsigned short)((val[0] << 8) | val[1]);`
                // (`:124`).
                //
                // The two-element slice pattern IS the length test, and it
                // hands over both bytes without an index that could be out
                // of bounds. The shift-and-or is BIG-ENDIAN, as DNS wire
                // format requires; every target in the matrix is
                // little-endian, so a host-order read would compile
                // silently and report 47873 for 443.
                let &[high, low] = val else {
                    return Err(CURLcode::BadFunctionArgument);
                };
                let port = u16::from_be_bytes([high, low]);
                self.port = Some(port);
                trc_feat!(tracer, TraceFeature::Dns, "HTTPS RR port {port}");
            }
            HTTPS_RR_CODE_IPV4 => {
                // `if(!vlen || (vlen & 3)) /* the size must be 4-byte
                //  aligned */ return CURLE_BAD_FUNCTION_ARGUMENT;` (`:92`)
                if val.is_empty() || (val.len() & 3) != 0 {
                    return Err(CURLcode::BadFunctionArgument);
                }
                // `curlx_free(hi->ipv4hints);` then `curlx_memdup` then
                // `hi->ipv4hints_len = vlen;` (`:94-98`) -- one assignment
                // here, which drops the previous buffer and cannot leave
                // the pointer and the length disagreeing.
                self.ipv4hints = Some(val.to_vec());
                trc_feat!(tracer, TraceFeature::Dns, "HTTPS RR IPv4");
            }
            HTTPS_RR_CODE_ECH => {
                // `if(!vlen) return CURLE_BAD_FUNCTION_ARGUMENT;` (`:102`)
                // -- non-emptiness ONLY. An `ECHConfigList` has no fixed
                // element size, so there is no alignment rule to add.
                if val.is_empty() {
                    return Err(CURLcode::BadFunctionArgument);
                }
                self.echconfiglist = Some(val.to_vec());
                trc_feat!(tracer, TraceFeature::Dns, "HTTPS RR ECH");
            }
            HTTPS_RR_CODE_IPV6 => {
                // `if(!vlen || (vlen & 15)) /* the size must be 16-byte
                //  aligned */ return CURLE_BAD_FUNCTION_ARGUMENT;` (`:112`)
                if val.is_empty() || (val.len() & 15) != 0 {
                    return Err(CURLcode::BadFunctionArgument);
                }
                self.ipv6hints = Some(val.to_vec());
                trc_feat!(tracer, TraceFeature::Dns, "HTTPS RR IPv6");
            }
            _ => {
                // `default:` (`:127-129`). An unrecognised code point is
                // NOT an error: RFC 9460 lets a sender include SvcParams a
                // receiver has never heard of, and the receiver's job is to
                // ignore them. Reporting and continuing is exactly that.
                trc_feat!(tracer, TraceFeature::Dns, "HTTPS RR unknown code");
            }
        }

        // `return result;` (`:131`) -- Ok unless the ALPN arm said otherwise.
        result
    }
}

/// Decodes an RFC 9460 `alpn` SvcParamValue into `alpns`.
///
/// Supersedes the file-local `httpsrr_decode_alpn` (`lib/httpsrr.c:34-69`),
/// and is private for the same reason C's is `static`: only
/// [`HttpsRrInfo::set_param`] has any business calling it.
///
/// C's own description of the wire format, which is the specification this
/// implements (`:37-42`):
///
/// > The wire-format value for `alpn` consists of at least one alpn-id
/// > prefixed by its length as a single octet, and these length-value pairs
/// > are concatenated to form the SvcParamValue. These pairs MUST exactly
/// > fill the SvcParamValue; otherwise, the SvcParamValue is malformed.
///
/// # Five behaviours that look like defects and are not
///
/// Each was measured, and each is preserved.
///
/// 1. **A truncated length octet is
///    [`CURLE_BAD_CONTENT_ENCODING`](CURLcode::BadContentEncoding)**
///    (`:49-50`) -- an unexpected code for a DNS parse failure, and
///    therefore exactly the kind of thing a rewrite "corrects". It is what a
///    caller of curl 8.19.0-DEV sees today, so it stays.
/// 2. **An unrecognised alpn-id is skipped, not rejected** -- C's comment is
///    *"we only store ALPN ids we know about"* (`:52`). Critically the cursor
///    still advances past it (`:63-64`), so a protocol this client has never
///    heard of cannot desynchronise the walk and lose the identifiers that
///    follow it.
/// 3. **A full list truncates silently** (`:55-56`): the guard is a `break`
///    returning success, not an error. A record advertising more identifiers
///    than there is room for is not malformed.
/// 4. **Identifiers are deduplicated, keeping the first occurrence**
///    (`:57-61`). C searches the stored prefix with `memchr` -- a **byte**
///    search, which is why [`AlpnId`]'s discriminants must each fit one byte.
/// 5. **Storing nothing is success.** An empty value, or one naming only
///    protocols this client does not know, returns
///    [`CURLE_OK`](CodeResult) with the list left empty (`:68`).
///
/// # The terminator is written only when there is room
///
/// `if(idnum < MAX_HTTPSRR_ALPNS) alpns[idnum] = ALPN_none;` (`:66-67`). A
/// **full list therefore carries no terminator**, and any reader has to treat
/// "[`MAX_HTTPSRR_ALPNS`] entries" and "terminated" as equally valid ends --
/// which [`HttpsRrInfo::alpns`] does. A `Vec`-based rewrite would look
/// tidier and would silently change that boundary, and `lib/doh.c:1167`
/// tests `hrr->alpns[0] != ALPN_none` directly.
///
/// ## Both of those branches are unreachable today, and both are kept
///
/// A measured consequence of `Curl_alpn2alpnid` (`lib/connect.c:73-88`)
/// having only **three** non-`None` results: with deduplication, `idnum`
/// cannot exceed three, so
///
/// * the `break` at (3) above never fires, and
/// * the terminator is *always* written, at index three at the very worst.
///
/// That is not an argument for deleting either. It is the reason
/// [`MAX_HTTPSRR_ALPNS`] is four rather than three -- the fourth slot is the
/// terminator's -- and both branches become live the moment a fourth
/// identifier joins the enumeration, which is a change to
/// `lib/hostip.h:49-54`'s successor and not to this file. Removing them
/// would put a latent overflow one enumerator away.
///
/// # Errors
///
/// [`CURLcode::BadContentEncoding`] when a length octet claims more bytes
/// than the value has left.
fn decode_alpn(
    val: &[u8],
    alpns: &mut [u8; MAX_HTTPSRR_ALPNS],
) -> CodeResult<()> {
    // `int idnum = 0;` (`:43`)
    let mut idnum: usize = 0;
    // C walks with `const uint8_t *cp` and a decrementing `size_t len`; one
    // shrinking slice carries both, and carries the relationship between
    // them that C has to maintain by hand.
    let mut rest = val;

    // `while(len > 0) { size_t tlen = *cp++; len--;` (`:45-48`). Taking the
    // length octet off the front IS the post-increment and the decrement,
    // together, so the two can never fall out of step.
    while let Some((&tlen_octet, tail)) = rest.split_first() {
        let tlen = usize::from(tlen_octet);

        // `if(tlen > len) return CURLE_BAD_CONTENT_ENCODING;` (`:49-50`),
        // where C's `len` has already been decremented -- so the comparison
        // is against what remains AFTER the length octet, which is exactly
        // `tail`. Testing before splitting is also what makes the split
        // below infallible: C's safety here is by construction, and so is
        // this.
        if tlen > tail.len() {
            return Err(CURLcode::BadContentEncoding);
        }

        // The alpn-id, and what `cp += tlen; len -= tlen;` (`:63-64`) would
        // leave behind. `split_at` cannot panic: the guard above proved
        // `tlen <= tail.len()`. No subtraction is performed at all, so
        // neither a debug-build underflow panic nor a release-build wrap is
        // reachable -- and the release profile has `overflow-checks = true`,
        // so both would be the same panic anyway.
        let (name, remainder) = tail.split_at(tlen);

        // `id = Curl_alpn2alpnid(cp, tlen);` (`:53`). The mapping belongs to
        // the module that owns the type; reimplementing it here would give
        // the crate two tables to keep in agreement.
        let id = AlpnId::from_wire(name);

        // `if(id != ALPN_none) { ... }` (`:54`)
        if id != AlpnId::None {
            // `if(idnum == MAX_HTTPSRR_ALPNS) break;` (`:55-56`)
            if idnum == MAX_HTTPSRR_ALPNS {
                break;
            }

            let stored = id.as_u8();

            // `if(idnum && memchr(alpns, id, idnum))` (`:57`) -- a byte
            // search over the entries stored so far. `contains` over the
            // same prefix is the same test. C's leading `idnum &&` is
            // redundant, since `memchr` with a zero count finds nothing,
            // and an empty prefix likewise contains nothing.
            let already = alpns
                .get(..idnum)
                .is_some_and(|kept| kept.contains(&stored));

            // `else alpns[idnum++] = (unsigned char)id;` (`:60-61`), so the
            // first occurrence is the one kept and its position is its
            // arrival order.
            if !already {
                // The `break` above already proves `idnum` is in range; the
                // bounds-checked write keeps that true if the guard is ever
                // edited, which is cheaper than trusting a proof at a
                // distance in a function fed by the network.
                if let Some(slot) = alpns.get_mut(idnum) {
                    *slot = stored;
                    idnum += 1;
                }
            }
        }

        // `cp += tlen; len -= tlen;` (`:63-64`) -- reached whether or not
        // the identifier was stored, which is what behaviour (2) above
        // depends on.
        rest = remainder;
    }

    // `if(idnum < MAX_HTTPSRR_ALPNS) alpns[idnum] = ALPN_none;` (`:66-67`).
    // The failure of the bounds-checked lookup IS that condition: `get_mut`
    // yields nothing exactly when `idnum == MAX_HTTPSRR_ALPNS`, so the "no
    // room, no terminator" case needs no separate test and cannot be got
    // wrong.
    if let Some(slot) = alpns.get_mut(idnum) {
        *slot = ALPN_TERMINATOR;
    }

    // `return CURLE_OK;` (`:68`)
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{TraceConfig, TraceLevel, TraceState, WriterSink};

    // The stored bytes, written as literals so the tests pin the integers
    // rather than restating whatever the enumeration happens to say. The
    // binding between the two is itself asserted, by
    // `alpn_id_integers_are_the_alt_svc_bits`.
    const NONE: u8 = 0;
    const H1: u8 = 8;
    const H2: u8 = 16;
    const H3: u8 = 32;

    /// A byte no [`AlpnId`] claims, for proving which slots were written.
    const UNWRITTEN: u8 = 0xFF;

    /// The record a `[DNS]`-labelled trace line produces.
    ///
    /// `InfoType::Text`'s two-byte `"* "` prefix, the feature's bracketed
    /// name, the message, and the newline the emitter appends.
    fn dns_line(message: &str) -> String {
        format!("* [DNS] {message}\n")
    }

    /// Runs `body` against a tracer capturing DNS records, returning them.
    ///
    /// The DNS feature has to be raised to [`TraceLevel::Info`] explicitly:
    /// `TraceConfig::new()` starts every feature silent, exactly as C's
    /// static `curl_trc_feat` initialisers do, so `--trace-config dns` is
    /// what turns these lines on in production too.
    fn traced<F>(body: F) -> String
    where
        F: FnOnce(&mut Tracer<'_>),
    {
        let mut config = TraceConfig::new();
        config.set_feature_level(TraceFeature::Dns, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            body(&mut tracer);
        }
        String::from_utf8(sink.into_inner())
            .expect("every trace string in this module is ASCII")
    }

    /// Runs `body` against a tracer that captures nothing.
    fn silent<F, T>(body: F) -> T
    where
        F: FnOnce(&mut Tracer<'_>) -> T,
    {
        let config = TraceConfig::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let mut tracer = Tracer::new(&config, &mut sink);
        body(&mut tracer)
    }

    /// One `set_param` call on a fresh record, with tracing discarded.
    fn set(rrkey: u16, val: &[u8]) -> (HttpsRrInfo, CodeResult<()>) {
        let mut info = HttpsRrInfo::default();
        let outcome = silent(|tracer| info.set_param(rrkey, val, tracer));
        (info, outcome)
    }

    /// `decode_alpn` over an array starting in C's `calloc` state.
    fn alpn(value: &[u8]) -> (CodeResult<()>, [u8; MAX_HTTPSRR_ALPNS]) {
        alpn_from([NONE; MAX_HTTPSRR_ALPNS], value)
    }

    /// `decode_alpn` over an array pre-filled with `seed`.
    ///
    /// Seeding with [`UNWRITTEN`] is what distinguishes "the terminator was
    /// written here" from "this slot was already zero", which the terminator
    /// tests depend on.
    fn alpn_from(
        seed: [u8; MAX_HTTPSRR_ALPNS],
        value: &[u8],
    ) -> (CodeResult<()>, [u8; MAX_HTTPSRR_ALPNS]) {
        let mut alpns = seed;
        let outcome = decode_alpn(value, &mut alpns);
        (outcome, alpns)
    }

    // ---- the pinned integers -------------------------------------------

    #[test]
    fn alpn_id_integers_are_the_alt_svc_bits() {
        // `include/curl/curl.h:1033-1035` via `lib/hostip.h:49-54`. These
        // are the bytes `lib/httpsrr.c:61` stores and `:82-83` prints, and
        // they are the `CURLOPT_ALTSVC_CTRL` mask bits, so they are not free
        // to be renumbered into ordinals.
        assert_eq!(AlpnId::None.as_u8(), NONE);
        assert_eq!(AlpnId::H1.as_u8(), H1);
        assert_eq!(AlpnId::H2.as_u8(), H2);
        assert_eq!(AlpnId::H3.as_u8(), H3);
        assert_eq!(1_u8 << 3, H1);
        assert_eq!(1_u8 << 4, H2);
        assert_eq!(1_u8 << 5, H3);
    }

    #[test]
    fn every_stored_byte_fits_one_octet() {
        // The array is `unsigned char alpns[4]` and the deduplication is a
        // BYTE search, so a value that did not fit an octet would break
        // both. Asserted through the accessor that produces the stored byte.
        for id in [AlpnId::None, AlpnId::H1, AlpnId::H2, AlpnId::H3] {
            assert_eq!(AlpnId::from_u8(id.as_u8()), Some(id));
        }
    }

    #[test]
    fn the_terminator_is_alpn_none() {
        // `lib/httpsrr.c:67` writes `ALPN_none`, and `lib/doh.c:1167`
        // compares `alpns[0]` against it.
        assert_eq!(ALPN_TERMINATOR, NONE);
        assert_eq!(ALPN_TERMINATOR, AlpnId::None.as_u8());
    }

    #[test]
    fn the_header_constants_are_reproduced() {
        // `lib/httpsrr.h:34-35`.
        assert_eq!(CURL_MAXLEN_HOST_NAME, 253);
        assert_eq!(MAX_HTTPSRR_ALPNS, 4);
    }

    #[test]
    fn the_code_points_are_the_rfc_9460_values() {
        // `lib/httpsrr.h:71-77`, all seven, written out so a transcription
        // slip in either direction fails here.
        assert_eq!(HTTPS_RR_CODE_MANDATORY, 0x00);
        assert_eq!(HTTPS_RR_CODE_ALPN, 0x01);
        assert_eq!(HTTPS_RR_CODE_NO_DEF_ALPN, 0x02);
        assert_eq!(HTTPS_RR_CODE_PORT, 0x03);
        assert_eq!(HTTPS_RR_CODE_IPV4, 0x04);
        assert_eq!(HTTPS_RR_CODE_ECH, 0x05);
        assert_eq!(HTTPS_RR_CODE_IPV6, 0x06);
    }

    // ---- the ALPN name table this module consumes ----------------------

    #[test]
    fn alpn_names_map_as_curl_alpn2alpnid_does() {
        // `lib/connect.c:73-88`: length two for the short forms, length
        // eight for the long one, and nothing else examined at all.
        assert_eq!(AlpnId::from_wire(b"h1"), AlpnId::H1);
        assert_eq!(AlpnId::from_wire(b"h2"), AlpnId::H2);
        assert_eq!(AlpnId::from_wire(b"h3"), AlpnId::H3);
        assert_eq!(AlpnId::from_wire(b"http/1.1"), AlpnId::H1);
    }

    #[test]
    fn alpn_names_are_compared_case_sensitively() {
        // The comparison is `memcmp`, so no case folding may be added.
        assert_eq!(AlpnId::from_wire(b"H2"), AlpnId::None);
        assert_eq!(AlpnId::from_wire(b"HTTP/1.1"), AlpnId::None);
        assert_eq!(AlpnId::from_wire(b"Http/1.1"), AlpnId::None);
    }

    #[test]
    fn unknown_alpn_names_are_none_rather_than_an_error() {
        // The absence of `h2c` and `http/1.0` is deliberate: C maps neither.
        for name in [
            &b""[..],
            &b"h"[..],
            &b"h4"[..],
            &b"h2c"[..],
            &b"http/1.0"[..],
            &b"http/1.1 "[..],
            &b"spdy/3"[..],
        ] {
            assert_eq!(
                AlpnId::from_wire(name),
                AlpnId::None,
                "{name:?} should not map"
            );
        }
    }

    // ---- decode_alpn ---------------------------------------------------

    #[test]
    fn decode_alpn_keeps_first_occurrence_order() {
        // Two length-prefixed identifiers, `h2` then `h3`.
        let (outcome, alpns) = alpn(b"\x02h2\x02h3");
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [H2, H3, NONE, NONE]);
    }

    #[test]
    fn decode_alpn_rejects_a_truncated_length_octet() {
        // `if(tlen > len) return CURLE_BAD_CONTENT_ENCODING;` -- the exact
        // code, which is what this asserts rather than merely "an error".
        let (outcome, _) = alpn(b"\x04h2");
        assert_eq!(outcome, Err(CURLcode::BadContentEncoding));

        // A length octet with nothing at all behind it.
        let (outcome, _) = alpn(b"\x01");
        assert_eq!(outcome, Err(CURLcode::BadContentEncoding));

        // And the extreme: 255 claimed, two supplied.
        let (outcome, _) = alpn(b"\xffh2");
        assert_eq!(outcome, Err(CURLcode::BadContentEncoding));
    }

    #[test]
    fn decode_alpn_partially_populates_before_rejecting() {
        // C writes into the caller's array as it goes and does not undo that
        // on failure. `set_param`'s trace line prints the partial state, so
        // this is observable and has to be preserved.
        let (outcome, alpns) =
            alpn_from([UNWRITTEN; MAX_HTTPSRR_ALPNS], b"\x02h2\x09short");
        assert_eq!(outcome, Err(CURLcode::BadContentEncoding));
        assert_eq!(alpns[0], H2);
        // No terminator either: the early return skips `:66-67` entirely.
        assert_eq!(alpns[1], UNWRITTEN);
    }

    #[test]
    fn decode_alpn_skips_an_unknown_id_without_desynchronising() {
        // A three-byte name this client does not know, then `h2`. If the
        // cursor did not advance past the unknown name, `h2` would be lost.
        let (outcome, alpns) = alpn(b"\x03xyz\x02h2");
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [H2, NONE, NONE, NONE]);
    }

    #[test]
    fn decode_alpn_skips_a_zero_length_id() {
        // A length octet of zero names the empty string, which maps to
        // `ALPN_none`, so nothing is stored and the walk continues.
        let (outcome, alpns) = alpn(b"\x00\x02h3");
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [H3, NONE, NONE, NONE]);
    }

    #[test]
    fn decode_alpn_deduplicates_keeping_the_first() {
        let (outcome, alpns) = alpn(b"\x02h2\x02h2\x02h3");
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [H2, H3, NONE, NONE]);
    }

    #[test]
    fn decode_alpn_deduplicates_across_the_two_spellings_of_h1() {
        // `h1` and `http/1.1` are the same identifier, so the deduplication
        // is on the decoded value and not on the name.
        let (outcome, alpns) = alpn(b"\x08http/1.1\x02h1");
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [H1, NONE, NONE, NONE]);
    }

    #[test]
    fn decode_alpn_terminates_a_partial_list_at_the_next_slot() {
        // Seeded with a byte no enumerator claims, so the terminator is
        // visible as a write rather than as a leftover zero.
        let seed = [UNWRITTEN; MAX_HTTPSRR_ALPNS];

        let (outcome, alpns) = alpn_from(seed, b"\x02h2");
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [H2, NONE, UNWRITTEN, UNWRITTEN]);

        // Nothing stored at all still terminates, at index zero -- which is
        // what makes `lib/doh.c:1167`'s `alpns[0] != ALPN_none` test valid.
        let (outcome, alpns) = alpn_from(seed, b"");
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [NONE, UNWRITTEN, UNWRITTEN, UNWRITTEN]);
    }

    #[test]
    fn decode_alpn_fills_three_slots_and_terminates_the_fourth() {
        // Every identifier the name table can produce, in one value. THREE
        // is the maximum -- `Curl_alpn2alpnid` has only three non-`None`
        // results and the list is deduplicated -- which is exactly why
        // `MAX_HTTPSRR_ALPNS` is four: the fourth slot is the terminator's.
        let (outcome, alpns) = alpn_from(
            [UNWRITTEN; MAX_HTTPSRR_ALPNS],
            b"\x02h3\x02h2\x08http/1.1",
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [H3, H2, H1, NONE]);
    }

    #[test]
    fn decode_alpn_never_stores_more_than_the_three_known_ids() {
        // A long, repetitive, out-of-order value. The `break` at
        // `lib/httpsrr.c:55-56` cannot fire while only three identifiers
        // exist, so the observable contract is "at most three stored, always
        // terminated, always Ok" -- and the guard stays in the code because
        // a fourth enumerator would make it live.
        let mut value = Vec::new();
        for name in [&b"h1"[..], &b"h2"[..], &b"h3"[..], &b"h4"[..], &b"h2"[..]]
            .iter()
            .cycle()
            .take(40)
        {
            let len = u8::try_from(name.len()).expect("names are short");
            value.push(len);
            value.extend_from_slice(name);
        }

        let (outcome, alpns) = alpn(&value);
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [H1, H2, H3, NONE]);
    }

    #[test]
    fn decode_alpn_accepts_an_empty_value() {
        let (outcome, alpns) = alpn(b"");
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns[0], NONE);
    }

    #[test]
    fn decode_alpn_accepts_an_all_unknown_value() {
        // Storing nothing is success, not a malformed value.
        let (outcome, alpns) = alpn(b"\x03h2c\x08http/1.0\x02h9");
        assert_eq!(outcome, Ok(()));
        assert_eq!(alpns, [NONE, NONE, NONE, NONE]);
    }

    // ---- the accessor and its terminator-or-full contract --------------

    #[test]
    fn the_accessor_stops_at_the_terminator() {
        let info = HttpsRrInfo {
            alpns: [H2, H3, NONE, H1],
            ..HttpsRrInfo::default()
        };
        // The `H1` past the terminator is unreachable, which is what makes
        // a stale fourth byte harmless.
        assert_eq!(
            info.alpns().collect::<Vec<_>>(),
            vec![AlpnId::H2, AlpnId::H3]
        );
    }

    #[test]
    fn the_accessor_yields_all_four_when_there_is_no_terminator() {
        // ⚠️ The Phase 3 subtlety: `lib/httpsrr.c:66-67` writes the
        // terminator ONLY if there is room, so a full array has none and
        // "four entries" is a valid end. Constructed by hand because
        // `decode_alpn` cannot produce it while only three identifiers
        // exist -- and the accessor must still read it correctly, since the
        // field is reachable and a fourth identifier would make it real.
        let info = HttpsRrInfo {
            alpns: [H1, H2, H3, H1],
            ..HttpsRrInfo::default()
        };
        assert_eq!(
            info.alpns().collect::<Vec<_>>(),
            vec![AlpnId::H1, AlpnId::H2, AlpnId::H3, AlpnId::H1]
        );
    }

    #[test]
    fn the_accessor_is_empty_for_a_record_with_no_alpn_param() {
        let info = HttpsRrInfo::default();
        assert_eq!(info.alpns().count(), 0);
    }

    #[test]
    fn the_accessor_skips_a_byte_no_enumerator_claims() {
        // Unreachable from `decode_alpn`, which only ever stores
        // `AlpnId::as_u8` results, and handled rather than panicked on
        // because the field is `pub(crate)`.
        let info = HttpsRrInfo {
            alpns: [H2, UNWRITTEN, H3, NONE],
            ..HttpsRrInfo::default()
        };
        assert_eq!(
            info.alpns().collect::<Vec<_>>(),
            vec![AlpnId::H2, AlpnId::H3]
        );
    }

    // ---- the default state ---------------------------------------------

    #[test]
    fn default_is_the_calloc_state_with_port_absent() {
        // `curlx_calloc` at `lib/doh.c:1118` zeroes everything, and `:1132`
        // then overwrites `port` with -1. `None` IS that -1.
        let info = HttpsRrInfo::default();
        assert_eq!(info.rrname, None);
        assert_eq!(info.target, None);
        assert_eq!(info.ipv4hints, None);
        assert_eq!(info.echconfiglist, None);
        assert_eq!(info.ipv6hints, None);
        assert_eq!(info.alpns, [NONE; MAX_HTTPSRR_ALPNS]);
        assert_eq!(info.port, None);
        assert_eq!(info.priority, 0);
        assert!(!info.no_def_alpn);
    }

    // ---- set_param, one arm at a time ----------------------------------

    #[test]
    fn set_param_mandatory_stores_nothing() {
        // C implements the parameter not at all, so a record carrying it is
        // unchanged and the call still succeeds.
        let (info, outcome) = set(HTTPS_RR_CODE_MANDATORY, b"\x00\x01");
        assert_eq!(outcome, Ok(()));
        assert_eq!(info, HttpsRrInfo::default());
    }

    #[test]
    fn set_param_no_def_alpn_requires_an_empty_value() {
        let (info, outcome) = set(HTTPS_RR_CODE_NO_DEF_ALPN, b"");
        assert_eq!(outcome, Ok(()));
        assert!(info.no_def_alpn);

        // ANY payload is a rejection, one byte included.
        for value in [&b"\x00"[..], &b"x"[..], &b"\x00\x00"[..]] {
            let (info, outcome) = set(HTTPS_RR_CODE_NO_DEF_ALPN, value);
            assert_eq!(outcome, Err(CURLcode::BadFunctionArgument));
            assert!(!info.no_def_alpn);
        }
    }

    #[test]
    fn set_param_ipv4_requires_a_non_empty_multiple_of_four() {
        for length in [0, 1, 2, 3, 5, 6, 7, 9] {
            let (info, outcome) = set(HTTPS_RR_CODE_IPV4, &vec![0x0a; length]);
            assert_eq!(
                outcome,
                Err(CURLcode::BadFunctionArgument),
                "{length} bytes should be rejected"
            );
            assert_eq!(info.ipv4hints, None);
        }

        for length in [4, 8, 12, 40] {
            let value = vec![0x0a; length];
            let (info, outcome) = set(HTTPS_RR_CODE_IPV4, &value);
            assert_eq!(outcome, Ok(()), "{length} bytes should be accepted");
            assert_eq!(info.ipv4hints.as_deref(), Some(&value[..]));
        }
    }

    #[test]
    fn set_param_ipv6_requires_a_non_empty_multiple_of_sixteen() {
        for length in [0, 1, 4, 8, 15, 17, 31, 33] {
            let (info, outcome) = set(HTTPS_RR_CODE_IPV6, &vec![0x0b; length]);
            assert_eq!(
                outcome,
                Err(CURLcode::BadFunctionArgument),
                "{length} bytes should be rejected"
            );
            assert_eq!(info.ipv6hints, None);
        }

        for length in [16, 32, 48] {
            let value = vec![0x0b; length];
            let (info, outcome) = set(HTTPS_RR_CODE_IPV6, &value);
            assert_eq!(outcome, Ok(()), "{length} bytes should be accepted");
            assert_eq!(info.ipv6hints.as_deref(), Some(&value[..]));
        }
    }

    #[test]
    fn set_param_ech_requires_only_non_emptiness() {
        // The deliberate asymmetry against IPv4 and IPv6: an ECHConfigList
        // has no fixed element size, so there is nothing to align to and a
        // single byte is acceptable.
        let (info, outcome) = set(HTTPS_RR_CODE_ECH, b"");
        assert_eq!(outcome, Err(CURLcode::BadFunctionArgument));
        assert_eq!(info.echconfiglist, None);

        for length in [1, 2, 3, 5, 7, 13, 17] {
            let value = vec![0x0c; length];
            let (info, outcome) = set(HTTPS_RR_CODE_ECH, &value);
            assert_eq!(outcome, Ok(()), "{length} bytes should be accepted");
            assert_eq!(info.echconfiglist.as_deref(), Some(&value[..]));
        }
    }

    #[test]
    fn set_param_port_is_big_endian() {
        // `(val[0] << 8) | val[1]`. Host order would give 47873 here, which
        // would compile cleanly on every target in the matrix.
        let (info, outcome) = set(HTTPS_RR_CODE_PORT, &[0x01, 0xBB]);
        assert_eq!(outcome, Ok(()));
        assert_eq!(info.port, Some(443));

        let (info, outcome) = set(HTTPS_RR_CODE_PORT, &[0x00, 0x50]);
        assert_eq!(outcome, Ok(()));
        assert_eq!(info.port, Some(80));

        // Both extremes of the range, so a sign or width slip shows up.
        let (info, outcome) = set(HTTPS_RR_CODE_PORT, &[0xFF, 0xFF]);
        assert_eq!(outcome, Ok(()));
        assert_eq!(info.port, Some(65535));

        // Port zero is a stored value, distinct from "not set" -- which is
        // the whole reason C needed a -1 sentinel and this an `Option`.
        let (info, outcome) = set(HTTPS_RR_CODE_PORT, &[0x00, 0x00]);
        assert_eq!(outcome, Ok(()));
        assert_eq!(info.port, Some(0));
    }

    #[test]
    fn set_param_port_requires_exactly_two_bytes() {
        for length in [0, 1, 3, 4, 8] {
            let (info, outcome) = set(HTTPS_RR_CODE_PORT, &vec![0x01; length]);
            assert_eq!(
                outcome,
                Err(CURLcode::BadFunctionArgument),
                "{length} bytes should be rejected"
            );
            assert_eq!(info.port, None);
        }
    }

    #[test]
    fn set_param_alpn_delegates_and_reports() {
        let (info, outcome) = set(HTTPS_RR_CODE_ALPN, b"\x02h2\x02h3");
        assert_eq!(outcome, Ok(()));
        assert_eq!(info.alpns, [H2, H3, NONE, NONE]);

        // And the decoder's failure is the caller's failure.
        let (_, outcome) = set(HTTPS_RR_CODE_ALPN, b"\x09short");
        assert_eq!(outcome, Err(CURLcode::BadContentEncoding));
    }

    #[test]
    fn set_param_accepts_and_ignores_an_unrecognised_code() {
        // RFC 9460 lets a sender include SvcParams the receiver has never
        // heard of; ignoring them is the specified behaviour, so this is a
        // success and the record is untouched.
        for code in [0x07_u16, 0x08, 0x40, 0x1234, 0xFFFF] {
            let (info, outcome) = set(code, b"whatever");
            assert_eq!(outcome, Ok(()), "code {code:#x} should be accepted");
            assert_eq!(info, HttpsRrInfo::default());
        }
    }

    #[test]
    fn set_param_replaces_rather_than_appends() {
        // C frees the previous buffer before storing (`:94`, `:104`, `:114`),
        // so the second occurrence wins outright. Unreachable from the DoH
        // path, which enforces ascending keys, and asserted because this
        // function is directly callable.
        let mut info = HttpsRrInfo::default();
        silent(|tracer| {
            let first =
                info.set_param(HTTPS_RR_CODE_IPV4, &[1, 2, 3, 4], tracer);
            assert_eq!(first, Ok(()));
            let second =
                info.set_param(HTTPS_RR_CODE_IPV4, &[9, 9, 9, 9], tracer);
            assert_eq!(second, Ok(()));
        });
        assert_eq!(info.ipv4hints.as_deref(), Some(&[9, 9, 9, 9][..]));

        let mut info = HttpsRrInfo::default();
        silent(|tracer| {
            assert_eq!(
                info.set_param(HTTPS_RR_CODE_ECH, b"first", tracer),
                Ok(())
            );
            assert_eq!(
                info.set_param(HTTPS_RR_CODE_ECH, b"second", tracer),
                Ok(())
            );
        });
        assert_eq!(info.echconfiglist.as_deref(), Some(&b"second"[..]));

        let mut info = HttpsRrInfo::default();
        silent(|tracer| {
            assert_eq!(
                info.set_param(HTTPS_RR_CODE_IPV6, &[0; 16], tracer),
                Ok(())
            );
            assert_eq!(
                info.set_param(HTTPS_RR_CODE_IPV6, &[7; 32], tracer),
                Ok(())
            );
        });
        assert_eq!(info.ipv6hints.as_deref(), Some(&[7_u8; 32][..]));
    }

    // ---- the eight surviving trace strings -----------------------------

    #[test]
    fn every_surviving_trace_string_is_reproduced_verbatim() {
        // The eight of `lib/httpsrr.c:26-150`. The two that mention a
        // target or a priority belong to `Curl_httpsrr_from_ares`, are
        // inside `#ifdef USE_ARES`, and are absent here by design.
        let cases: [(u16, &[u8], &str); 8] = [
            (
                HTTPS_RR_CODE_MANDATORY,
                b"",
                "HTTPS RR MANDATORY left to implement",
            ),
            (HTTPS_RR_CODE_ALPN, b"\x02h2", "HTTPS RR ALPN: 16 0 0 0"),
            (HTTPS_RR_CODE_NO_DEF_ALPN, b"", "HTTPS RR no-def-alpn"),
            (HTTPS_RR_CODE_PORT, &[0x01, 0xBB], "HTTPS RR port 443"),
            (HTTPS_RR_CODE_IPV4, &[1, 2, 3, 4], "HTTPS RR IPv4"),
            (HTTPS_RR_CODE_ECH, b"cfg", "HTTPS RR ECH"),
            (HTTPS_RR_CODE_IPV6, &[0; 16], "HTTPS RR IPv6"),
            (0xFFFF, b"", "HTTPS RR unknown code"),
        ];

        for (code, value, expected) in cases {
            let mut info = HttpsRrInfo::default();
            let log = traced(|tracer| {
                let outcome = info.set_param(code, value, tracer);
                assert_eq!(outcome, Ok(()), "code {code:#x} should succeed");
            });
            assert_eq!(log, dns_line(expected));
        }
    }

    #[test]
    fn the_alpn_line_prints_all_four_slots_including_the_zeros() {
        // `hi->alpns[0] .. [3]`, unconditionally, so trailing `ALPN_none`
        // bytes appear as zeros. That is C's output and it is frozen.
        let mut info = HttpsRrInfo::default();
        let log = traced(|tracer| {
            let outcome =
                info.set_param(HTTPS_RR_CODE_ALPN, b"\x02h3\x02h1", tracer);
            assert_eq!(outcome, Ok(()));
        });
        assert_eq!(log, dns_line("HTTPS RR ALPN: 32 8 0 0"));

        // And with every identifier stored, no zero remains but the
        // terminator's.
        let mut info = HttpsRrInfo::default();
        let log = traced(|tracer| {
            let outcome = info.set_param(
                HTTPS_RR_CODE_ALPN,
                b"\x02h1\x02h2\x02h3",
                tracer,
            );
            assert_eq!(outcome, Ok(()));
        });
        assert_eq!(log, dns_line("HTTPS RR ALPN: 8 16 32 0"));
    }

    #[test]
    fn the_alpn_line_is_emitted_even_when_the_decode_fails() {
        // `:81-84` assigns the result, THEN traces, THEN breaks -- so the
        // partial state reaches the log. `h2` was stored before the
        // truncated pair was found.
        let mut info = HttpsRrInfo::default();
        let log = traced(|tracer| {
            let outcome =
                info.set_param(HTTPS_RR_CODE_ALPN, b"\x02h2\x09short", tracer);
            assert_eq!(outcome, Err(CURLcode::BadContentEncoding));
        });
        assert_eq!(log, dns_line("HTTPS RR ALPN: 16 0 0 0"));
    }

    #[test]
    fn a_rejected_parameter_emits_no_trace_line_at_all() {
        // Every arm other than ALPN `return`s before its trace call, which
        // is the other half of the asymmetry above.
        let rejections: [(u16, &[u8]); 5] = [
            (HTTPS_RR_CODE_NO_DEF_ALPN, b"x"),
            (HTTPS_RR_CODE_PORT, b"\x01"),
            (HTTPS_RR_CODE_IPV4, b"\x01\x02\x03"),
            (HTTPS_RR_CODE_ECH, b""),
            (HTTPS_RR_CODE_IPV6, b"\x00"),
        ];

        for (code, value) in rejections {
            let mut info = HttpsRrInfo::default();
            let log = traced(|tracer| {
                let outcome = info.set_param(code, value, tracer);
                assert_eq!(
                    outcome,
                    Err(CURLcode::BadFunctionArgument),
                    "code {code:#x} should reject"
                );
            });
            assert!(log.is_empty(), "code {code:#x} traced {log:?}");
        }
    }

    #[test]
    fn nothing_is_traced_while_the_dns_feature_is_silent() {
        // `TraceConfig::new()` leaves every feature at `CURL_LOG_LVL_NONE`,
        // so these lines need `--trace-config dns` even with
        // `CURLOPT_VERBOSE` set. Confirms the gate is real and that the
        // assertions above are not passing by accident.
        let config = TraceConfig::new();
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            let mut info = HttpsRrInfo::default();
            let outcome =
                info.set_param(HTTPS_RR_CODE_IPV4, &[1, 2, 3, 4], &mut tracer);
            assert_eq!(outcome, Ok(()));
        }
        assert!(sink.into_inner().is_empty());
    }

    // ---- hostile input -------------------------------------------------

    /// A deterministic spread of values: every length up to 40 bytes of a
    /// repeating pattern, plus the shapes that historically break a
    /// length-prefixed walk.
    fn hostile_values() -> Vec<Vec<u8>> {
        let mut values = vec![
            Vec::new(),
            vec![0x00],
            vec![0xFF],
            vec![0xFF, 0xFF],
            vec![0x01],
            vec![0x02, b'h'],
            vec![0x00; 40],
            vec![0xFF; 40],
            b"\x02h2\x02h3\x02h1\x08http/1.1".to_vec(),
        ];

        // Every single byte on its own: each is a length octet claiming
        // more than the zero bytes behind it, except 0x00.
        values.extend((0..=u8::MAX).map(|byte| vec![byte]));

        // Truncations of a well-formed value, so every boundary inside it
        // is exercised as the end of input.
        let whole = b"\x02h2\x08http/1.1\x02h3\x00\x02h1";
        for take in 0..=whole.len() {
            values.push(whole[..take].to_vec());
        }

        // A repeating pattern at every length, which sweeps length octets
        // that overrun by every amount up to the buffer size.
        for length in 0..=40_usize {
            values.push(
                (0..length)
                    .map(|index| u8::try_from(index % 7).unwrap_or(0))
                    .collect(),
            );
        }

        values
    }

    #[test]
    fn decode_alpn_never_panics_on_hostile_input() {
        // Every path returns a `CURLcode`; completing this test IS the
        // proof, since a panic would fail it. The array is inspected
        // afterwards so an out-of-range write would also be caught.
        for value in hostile_values() {
            let (outcome, alpns) =
                alpn_from([UNWRITTEN; MAX_HTTPSRR_ALPNS], &value);
            assert!(
                matches!(outcome, Ok(()) | Err(CURLcode::BadContentEncoding)),
                "{value:?} gave {outcome:?}"
            );
            for byte in alpns {
                assert!(
                    matches!(byte, NONE | H1 | H2 | H3 | UNWRITTEN),
                    "{value:?} left {byte} in the array"
                );
            }
        }
    }

    #[test]
    fn set_param_never_panics_on_hostile_input() {
        // The same corpus through every code point, recognised and not, so
        // each arm's validation meets every shape.
        let codes = [
            HTTPS_RR_CODE_MANDATORY,
            HTTPS_RR_CODE_ALPN,
            HTTPS_RR_CODE_NO_DEF_ALPN,
            HTTPS_RR_CODE_PORT,
            HTTPS_RR_CODE_IPV4,
            HTTPS_RR_CODE_ECH,
            HTTPS_RR_CODE_IPV6,
            0x07,
            0xFFFF,
        ];

        for value in hostile_values() {
            for code in codes {
                let (_, outcome) = set(code, &value);
                assert!(
                    matches!(
                        outcome,
                        Ok(())
                            | Err(CURLcode::BadFunctionArgument)
                            | Err(CURLcode::BadContentEncoding)
                    ),
                    "code {code:#x} on {value:?} gave {outcome:?}"
                );
            }
        }
    }

    #[test]
    fn a_record_is_cloneable_and_comparable() {
        // `Curl_httpsrr_dup_move` is gone; a move is a move and a copy is a
        // `clone`. Equality is what lets `DnsEntry` derive its own.
        let mut info = HttpsRrInfo::default();
        silent(|tracer| {
            assert_eq!(
                info.set_param(HTTPS_RR_CODE_ALPN, b"\x02h2", tracer),
                Ok(())
            );
            assert_eq!(
                info.set_param(HTTPS_RR_CODE_PORT, &[0x01, 0xBB], tracer),
                Ok(())
            );
            assert_eq!(
                info.set_param(HTTPS_RR_CODE_ECH, b"cfg", tracer),
                Ok(())
            );
        });
        info.target = Some(String::from("example.net"));
        info.priority = 1;

        let copy = info.clone();
        assert_eq!(copy, info);
        assert_ne!(copy, HttpsRrInfo::default());

        // And the move leaves nothing behind to clean up, which is what
        // deletes `Curl_httpsrr_cleanup`.
        let moved = info;
        assert_eq!(moved, copy);
    }
}
