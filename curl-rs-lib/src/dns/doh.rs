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

//! DNS-over-HTTPS: RFC 8484 name resolution through an HTTPS transfer.
//!
//! # What is frozen
//!
//! * **The query bytes.** [`req_encode`] emits a DNS message whose every byte
//!   is fixed by `lib/doh.c:104-166`.
//! * **The request shape.** POST, a raw binary body, and exactly one header
//!   reading `Content-Type: application/dns-message` (`:313-314`).
//!   [`DohProbeRequest`] carries that shape whole rather than letting a
//!   transport re-derive any part of it.
//! * **The trace and error text.** Every string this module emits is
//!   transcribed from the C with its locator, and the transcriptions include
//!   two genuine source asymmetries that would look like typos to a reader who
//!   had not checked -- see [`print_buf`] and [`print_httpsrr`].
//!
//! # The transport is injected, never imported
//!
//! The import that would express it directly, `use crate::protocols`, would
//! close a `dns -> protocols -> dns` cycle, so the dependency is inverted into
//! a seam. **This file names neither `crate::protocols` nor `crate::conn`, and
//! must never come to.**
//!
//! The seam already exists: [`crate::dns::DohTransport`] is declared by this
//! directory's module root (`dns/mod.rs`), whose own documentation says
//! *"doh.rs consumes it"* and *"The seam is deliberately narrow ... carries
//! bytes and nothing else"*. It is consumed rather than re-declared, because a
//! second trait of the same name at a second path would leave the first
//! unused and its documented contract broken.
//!
//! Narrowness has one consequence worth spelling out. `post` takes a URL and
//! a query and returns a body, so it cannot by itself carry the header, the
//! method, the timeout, the protocol restriction or the TLS verification
//! triple that `doh_probe_run` sets -- all of which are frozen and all of
//! which belong to this file's contract. They are therefore represented here,
//! in [`DohProbeRequest`], and reachable by a transport through the richer
//! [`DohProbeTransport`].
//!
//! A blanket implementation used to adapt every [`DohTransport`] into a
//! [`DohProbeTransport`] by forwarding those two fields and dropping the other
//! eleven. **It is gone.** Dropping them was not a simplification: it meant a
//! request built to verify a private resolver against a pinned CA, or built with
//! `--doh-insecure`, would go out under the transport's own policy with nothing
//! reporting the substitution -- and it applied itself by coherence, so no call
//! site had to admit to it. The narrowing is now spelled
//! [`NarrowDohTransport`], which forwards the two fields only when the other
//! eleven carry nothing, and otherwise **refuses the request**.
//!
//! **No PRODUCTION transport is registered, and that is what withholds the
//! `DoH` label.** Every implementor of either trait in this tree -- here and in
//! `dns/mod.rs` alike -- is a `#[cfg(test)]` double, because a real one has to
//! perform an HTTPS transfer and `curl-rs-lib/src/protocols/http1.rs` does not
//! exist. The module root holds the registry, `dns::DOH_TRANSPORTS`, and
//! [`crate::version::supports_doh`] conjoins it: the capability turns itself on
//! when the slice gains an entry and cannot be turned on before. So the codec,
//! the probe pairing and the record walk below are complete and exercised while
//! the banner stays silent -- which is the direction AAP 0.6.5 requires, since a
//! `DoH`-gated fixture that skips reports the gap and one that runs against a
//! seam nothing fills reports a defect that does not exist.
//!
//! # Everything decoded here is attacker-controlled
//!
//! `lib/doh.c:163-164` carries its own warning: *"verify that our estimation
//! of length is valid, since **this has led to buffer overflows in this
//! function**"*. Every read of a response in this module is bounds-checked
//! through [`slice::get`] or a slice pattern, every offset arithmetic is
//! [`usize::checked_add`], and there is no `unwrap`, no `expect`, no `panic!`
//! and no indexing expression that can fail outside `#[cfg(test)]`. A panic
//! here would unwind toward a C caller through `curl-rs-ffi`, and a bounds
//! check that wrapped would be a vulnerability rather than a bug.
//!
//! # Feature gating
//!
//! `lib/doh.c:26` wraps the whole file in `#ifndef CURL_DISABLE_DOH`. The
//! successor gate is the default-on `doh` Cargo feature, applied **once**, on
//! this module's declaration in `dns/mod.rs`:
//!
//! ```text
//! #[cfg(feature = "doh")]
//! pub(crate) mod doh;
//! ```
//!
//! No item in this file carries a second `doh` gate; a `cfg` on a feature that
//! does not exist deletes code silently, so the fifteen-name vocabulary is
//! treated as closed. Two consequences of that closure are recorded on the
//! items they affect: there is no `httpsrr` feature, so the HTTPS-RR slot
//! compiles unconditionally where C has `#ifdef USE_HTTPSRR`
//! (`lib/doh.h:64-66`), and there is no `CURLVERBOSE`, so [`strerror`] and
//! [`show`] compile unconditionally where C has `#ifdef CURLVERBOSE`
//! (`lib/doh.c:43-68`, `:854-900`). The one feature that *is* consulted is
//! `http2`, for the two version hints of `:335-338`.
//!
//! # Ownership boundary with [`httpsrr`](crate::dns::httpsrr)
//!
//! The HTTPS resource record is split between two files, and the split follows
//! the C rather than the obvious reading of the names:
//!
//! * `httpsrr.rs` owns the record *type* and the per-SvcParam setter --
//!   `Curl_https_rrinfo` and `Curl_httpsrr_set`, both in `lib/httpsrr.c`.
//! * **This file** owns the record *walk* and the debug dump --
//!   `doh_resp_decode_httpsrr` (`lib/doh.c:1099-1156`) and
//!   `doh_print_httpsrr` (`:1158-1196`), which live in `lib/doh.c` and not in
//!   `lib/httpsrr.c` because both need the DNS-wire helpers that are here.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::dns::httpsrr::{HttpsRrInfo, CURL_MAXLEN_HOST_NAME};
use crate::dns::{
    DnsCache, DnsEntryRef, DohTransport, IpVersion, ResolveFuture, ResolvedAddr,
};
use crate::error::{CURLcode, CodeResult};
use crate::trace::{failf, infof, trc_feat, TraceFeature, Tracer};
use crate::util::dynbuf::{DynBuf, DYN_DOH_CNAME, DYN_DOH_RESPONSE};
use crate::util::fallible;
use crate::util::redact::Redacted;
use crate::util::timediff::{mstotv, TimeDiff};
use crate::util::timeval::Clock;

// Constants -- `lib/doh.h` and `lib/doh.c:41`.

/// The DNS `CLASS` this module queries and accepts: `IN`, the Internet.
///
/// `#define DNS_CLASS_IN 0x01` (`lib/doh.c:41`). A wire constant from RFC
/// 1035; frozen. [`req_encode`] writes it and [`resp_decode`] rejects anything
/// else with [`DohCode::DnsUnexpectedClass`].
pub(crate) const DNS_CLASS_IN: u16 = 0x01;

/// The largest DNS query this module will build: 272 bytes.
pub(crate) const DOH_MAX_DNSREQ_SIZE: usize = 256 + 16;

/// The most addresses one [`DohEntry`] retains: 24.
///
/// `#define DOH_MAX_ADDR 24` (`lib/doh.h:119`). Addresses past the limit are
/// **silently ignored**, not reported -- see [`DohEntry::store_a`].
pub(crate) const DOH_MAX_ADDR: usize = 24;

/// The most CNAMEs one [`DohEntry`] retains: 4.
///
/// `#define DOH_MAX_CNAME 4` (`lib/doh.h:120`). Records past the limit are
/// skipped and reported as success -- see [`DohEntry::store_cname`].
pub(crate) const DOH_MAX_CNAME: usize = 4;

/// The most HTTPS resource records one [`DohEntry`] retains: 4.
pub(crate) const DOH_MAX_HTTPS: usize = 4;

/// A character that may need escaping inside an ALPN string value.
#[allow(dead_code)] // Carried from `lib/doh.h:137`; the C has no user either.
pub(crate) const COMMA_CHAR: u8 = b',';

/// A character that may need escaping inside an ALPN string value.
///
/// `#define BACKSLASH_CHAR '\\'` (`lib/doh.h:138`). See [`COMMA_CHAR`] for why
/// both are carried without a consumer.
#[allow(dead_code)] // Carried from `lib/doh.h:138`; the C has no user either.
pub(crate) const BACKSLASH_CHAR: u8 = b'\\';

/// The port at which the HTTPS-RR query name loses its `_port._https` prefix.
///
/// `PORT_HTTPS`, which `lib/urldata.h` fixes at 443 and `lib/doh.c:499` tests.
/// The comparison is wire-observable: see [`https_rr_qname`].
pub(crate) const PORT_HTTPS: u16 = 443;

/// `CURL_MAX_INPUT_LENGTH` -- 8,000,000.
const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// The longest label a QNAME may carry: 63 bytes.
const MAX_LABEL_LEN: usize = 63;

/// The two high bits that classify a QNAME length byte: `0xc0`.
///
/// RFC 1035 section 4.1.4. `0xc0` is a compression pointer, `0x00` a literal
/// label, and `0x40` and `0x80` are reserved and rejected. C writes `0xc0`
/// inline in three places (`lib/doh.c:529`, `:536`, `:620`); one name serves
/// all three.
const LABEL_TYPE_MASK: u8 = 0xc0;

/// The bit pattern of a compression pointer: `0xc0`.
///
/// Equal to [`LABEL_TYPE_MASK`] by construction -- the mask and the pointer
/// pattern coincide, which is why C's test reads
/// `if((length & 0xc0) == 0xc0)`. Both names exist so that the two *roles*
/// remain legible.
const LABEL_TYPE_POINTER: u8 = 0xc0;

/// The fourteen low bits of a compression pointer's offset: `0x3f` over the
/// high byte.
///
/// `newpos = (length & 0x3f) << 8 | doh[index + 1]` (`lib/doh.c:627`).
const LABEL_POINTER_OFFSET_MASK: u8 = 0x3f;

/// The iteration budget [`DohEntry::store_cname`] gives a compressed name.
const CNAME_LOOP_BUDGET: u32 = 128;

/// The fixed size of a DNS message header: 12 bytes.
///
/// RFC 1035 section 4.1.1. C writes twelve individual bytes at
/// `lib/doh.c:116-127` and tests `dohlen < 12` at `:726`, then starts its walk
/// at `index = 12` (`:723`).
const DNS_HEADER_LEN: usize = 12;

/// The byte offset of `QDCOUNT` within the header.
///
/// `doh_get16bit(doh, 4)` (`lib/doh.c:734`).
const OFFSET_QDCOUNT: usize = 4;

/// The byte offset of `ANCOUNT` within the header.
///
/// `doh_get16bit(doh, 6)` (`lib/doh.c:745`).
const OFFSET_ANCOUNT: usize = 6;

/// The byte offset of `NSCOUNT` within the header.
///
/// `doh_get16bit(doh, 8)` (`lib/doh.c:795`).
const OFFSET_NSCOUNT: usize = 8;

/// The byte offset of `ARCOUNT` within the header.
///
/// `doh_get16bit(doh, 10)` (`lib/doh.c:817`).
const OFFSET_ARCOUNT: usize = 10;

/// The hex-string budget of [`print_buf`]: 400 bytes.
///
/// `#define LOCAL_PB_HEXMAX 400` (`lib/doh.c:187`), with C's own comment
/// *"doh_print_buf truncates if the hex string will be more than this"*.
const LOCAL_PB_HEXMAX: usize = 400;

// `DOHcode` -- `lib/doh.h:30-45`.

/// Why a DoH message could not be built or parsed.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(i32)]
pub(crate) enum DohCode {
    /// `DOH_OK` -- no error. Not a variant [`resp_decode`] ever returns in an
    /// `Err`; it is the zero of the C enumeration and is retained so that
    /// [`strerror`]'s fourteen-entry mapping is complete.
    Ok = 0,
    /// `DOH_DNS_BAD_LABEL` -- `/* 1 */`. A label longer than
    /// [`MAX_LABEL_LEN`], a zero-length label before the end of the name, or a
    /// length byte whose type bits are one of the two reserved patterns.
    DnsBadLabel = 1,
    /// `DOH_DNS_OUT_OF_RANGE` -- `/* 2 */`. A read that would pass the end of
    /// the message.
    DnsOutOfRange = 2,
    /// `DOH_DNS_LABEL_LOOP` -- `/* 3 */`. A chain of compression pointers that
    /// outlasted [`CNAME_LOOP_BUDGET`].
    DnsLabelLoop = 3,
    /// `DOH_TOO_SMALL_BUFFER` -- `/* 4 */`. The output buffer cannot hold the
    /// query, or the response is shorter than a DNS header.
    TooSmallBuffer = 4,
    /// `DOH_OUT_OF_MEM` -- `/* 5 */`.
    ///
    /// In C this reports a failed `curlx_memdup` or a `dynbuf` append that hit
    /// its ceiling. **Both halves are live here.** The ceiling half always was:
    /// appending past [`DYN_DOH_CNAME`] fails and arrives here (see
    /// [`DohEntry::store_cname`]). The allocation half arrived with
    /// `crate::util::dynbuf`'s growth becoming fallible: a refused
    /// `try_reserve_exact` is `CURLE_OUT_OF_MEMORY` from the buffer, exactly as
    /// a null `realloc` is in the C, and it reaches this code by the same
    /// route. The one route with no counterpart is the fixed-size `memdup` of a
    /// name already in memory.
    OutOfMem = 5,
    /// `DOH_DNS_RDATA_LEN` -- `/* 6 */`. An `A` record whose RDATA is not four
    /// bytes, or an `AAAA` record whose RDATA is not sixteen.
    DnsRdataLen = 6,
    /// `DOH_DNS_MALFORMAT` -- `/* 7 */`. The message was not consumed exactly:
    /// bytes remain after the last section.
    DnsMalformat = 7,
    /// `DOH_DNS_BAD_RCODE` -- `/* 8 - no such name */`. A non-zero `RCODE`. C's
    /// annotation names the common case rather than the only one; the test does
    /// not distinguish between `RCODE` values.
    DnsBadRcode = 8,
    /// `DOH_DNS_UNEXPECTED_TYPE` -- `/* 9 */`. An answer whose `TYPE` is
    /// neither the one queried nor `CNAME` nor `DNAME`.
    DnsUnexpectedType = 9,
    /// `DOH_DNS_UNEXPECTED_CLASS` -- `/* 10 */`. An answer whose `CLASS` is not
    /// [`DNS_CLASS_IN`].
    DnsUnexpectedClass = 10,
    /// `DOH_NO_CONTENT` -- `/* 11 */`. A well-formed message that stored
    /// nothing. See [`resp_decode`] for the `USE_HTTTPS` typo that decides
    /// exactly what "nothing" means.
    NoContent = 11,
    /// `DOH_DNS_BAD_ID` -- `/* 12 */`. A non-zero message ID. [`req_encode`]
    /// always writes zero, so a reply that carries anything else is not a reply
    /// to a query this module sent.
    DnsBadId = 12,
    /// `DOH_DNS_NAME_TOO_LONG` -- `/* 13 */`. The QNAME encoding of the host
    /// would push the query past [`DOH_MAX_DNSREQ_SIZE`].
    DnsNameTooLong = 13,
}

/// The text C prints for a [`DohCode`].
///
/// Supersedes `errors[]` and `doh_strerror` (`lib/doh.c:44-66`) **as one
/// item**. C keeps a fourteen-entry array and indexes it by the code, guarded
/// by a range test; a `match` is used here instead, and the substitution is
/// deliberate rather than stylistic:
///
/// * The array and the enumeration can drift apart in C -- inserting a variant
///   without inserting a string silently shifts every later message. An
///   exhaustive `match` cannot compile with a variant unmapped.
/// * C's out-of-range fall-through returns `"bad error code"` (`:65`). Rust has
///   no out-of-range [`DohCode`] to fall through with, so that string would be
///   unreachable from this function. It is preserved on [`strerror_raw`], the
///   integer-taking form, which is where a value that is not a variant can
///   still arrive.
///
/// C compiles this under `#ifdef CURLVERBOSE`. There is no such feature here
/// and none is invented: gating fourteen short literals would only create a
/// configuration in which a trace line silently lost its text.
#[rustfmt::skip]
pub(crate) const fn strerror(code: DohCode) -> &'static str {
    match code {
        DohCode::Ok                 => "",                  // `:45`
        DohCode::DnsBadLabel        => "Bad label",          // `:46`
        DohCode::DnsOutOfRange      => "Out of range",       // `:47`
        DohCode::DnsLabelLoop       => "Label loop",         // `:48`
        DohCode::TooSmallBuffer     => "Too small",          // `:49`
        DohCode::OutOfMem           => "Out of memory",      // `:50`
        DohCode::DnsRdataLen        => "RDATA length",       // `:51`
        DohCode::DnsMalformat       => "Malformat",          // `:52`
        DohCode::DnsBadRcode        => "Bad RCODE",          // `:53`
        DohCode::DnsUnexpectedType  => "Unexpected TYPE",    // `:54`
        DohCode::DnsUnexpectedClass => "Unexpected CLASS",   // `:55`
        DohCode::NoContent          => "No content",         // `:56`
        DohCode::DnsBadId           => "Bad ID",             // `:57`
        DohCode::DnsNameTooLong     => "Name too long",      // `:58`
    }
}

/// The text C prints for a raw `DOHcode` integer, including its fall-through.
#[allow(dead_code)] // The FFI boundary is later code; the tests exercise it.
pub(crate) fn strerror_raw(code: i32) -> &'static str {
    // `if((code >= DOH_OK) && (code <= DOH_DNS_NAME_TOO_LONG))`, with the two
    // bounds named rather than written as 0 and 13 so that adding a variant
    // moves the window automatically.
    match code {
        0 => strerror(DohCode::Ok),
        1 => strerror(DohCode::DnsBadLabel),
        2 => strerror(DohCode::DnsOutOfRange),
        3 => strerror(DohCode::DnsLabelLoop),
        4 => strerror(DohCode::TooSmallBuffer),
        5 => strerror(DohCode::OutOfMem),
        6 => strerror(DohCode::DnsRdataLen),
        7 => strerror(DohCode::DnsMalformat),
        8 => strerror(DohCode::DnsBadRcode),
        9 => strerror(DohCode::DnsUnexpectedType),
        10 => strerror(DohCode::DnsUnexpectedClass),
        11 => strerror(DohCode::NoContent),
        12 => strerror(DohCode::DnsBadId),
        13 => strerror(DohCode::DnsNameTooLong),
        // `return "bad error code";` (`:65`).
        _ => "bad error code",
    }
}

impl fmt::Display for DohCode {
    /// Writes [`strerror`]'s text, so that a code interpolates into a trace
    /// line without the call site naming the function.
    ///
    /// `CURL_TRC_DNS(data, "DoH: %s type %s for %s", doh_strerror(rc[slot]),
    /// ...)` (`lib/doh.c:1235-1236`) is the one call site, and it wants the
    /// text and nothing else -- no code number, no wrapper punctuation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(strerror(*self))
    }
}

// `DNStype` -- `lib/doh.h:47-54`.

/// A DNS record type this module can query or recognise.
///
/// Supersedes `DNStype` (`lib/doh.h:47-54`). Every value is an IANA-assigned
/// wire code, so all six are frozen and none may be renumbered:
///
/// * **[`Self::A`]** -- 1 -- queried unconditionally (`lib/doh.c:474`)
/// * **[`Self::Ns`]** -- 2 -- never queried; exempted from the no-content test
///   (`:846`)
/// * **[`Self::Cname`]** -- 5 -- never queried; accepted in any answer (`:758`)
/// * **[`Self::Aaaa`]** -- 28 -- queried when IPv6 is usable (`:485`)
/// * **[`Self::Dname`]** -- 39 -- never queried; accepted and ignored (`:759`)
/// * **[`Self::Https`]** -- 65 -- queried for HTTP-family transfers (`:504`)
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub(crate) enum DnsType {
    /// `CURL_DNS_TYPE_A = 1`: a 32-bit IPv4 address.
    A = 1,
    /// `CURL_DNS_TYPE_NS = 2`: an authoritative name server.
    ///
    /// Never queried. It exists because the no-content test exempts it
    /// (`lib/doh.c:846`), an exemption that is unreachable through this
    /// module's own probes and is reproduced anyway; see [`resp_decode`].
    Ns = 2,
    /// `CURL_DNS_TYPE_CNAME = 5`: a canonical name.
    Cname = 5,
    /// `CURL_DNS_TYPE_AAAA = 28`: a 128-bit IPv6 address.
    Aaaa = 28,
    /// `CURL_DNS_TYPE_DNAME = 39`: a delegation name, `/* RFC6672 */`.
    Dname = 39,
    /// `CURL_DNS_TYPE_HTTPS = 65`: an RFC 9460 HTTPS resource record.
    ///
    /// Two-byte encoding matters here more than anywhere else: 65 is
    /// `0x00 0x41` on the wire, and a host-order write would emit
    /// `0x41 0x00` and query type 16,640. C's comment at `lib/doh.c:154` is
    /// *"There are assigned TYPE codes beyond 255: use range [1..65535]"*.
    Https = 65,
}

impl DnsType {
    /// The wire code, for the big-endian pair [`req_encode`] emits.
    pub(crate) const fn as_u16(self) -> u16 {
        self as u16
    }

    /// The display name of this type, or `"unknown"`.
    #[rustfmt::skip]
    pub(crate) const fn type2name(self) -> &'static str {
        match self {
            Self::A     => "A",        // `:1014-1015`
            Self::Aaaa  => "AAAA",     // `:1016-1017`
            Self::Https => "HTTPS",    // `:1019-1020`
            // `default: return "unknown";` (`:1022-1023`)
            Self::Ns | Self::Cname | Self::Dname => "unknown",
        }
    }
}

impl fmt::Display for DnsType {
    /// Writes [`Self::type2name`], for the `%s` of `lib/doh.c:1235-1236`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.type2name())
    }
}

// `enum doh_slot_num` -- `lib/doh.h:56-75`.

/// Which probe a response belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(usize)]
pub(crate) enum DohSlot {
    /// `DOH_SLOT_IPV4 = 0`, with C's comment *"make 'V4' stand out for
    /// readability"*.
    Ipv4 = 0,
    /// `DOH_SLOT_IPV6 = 1`, *"'V6' likewise"*.
    Ipv6 = 1,
    /// `DOH_SLOT_HTTPS_RR = 2`, *"for HTTPS RR"*.
    HttpsRr = 2,
}

/// How many probe slots exist: 3.
pub(crate) const SLOT_COUNT: usize = 3;

impl DohSlot {
    /// Every slot, in declaration order.
    pub(crate) const ALL: [Self; SLOT_COUNT] =
        [Self::Ipv4, Self::Ipv6, Self::HttpsRr];

    /// This slot's array index.
    pub(crate) const fn index(self) -> usize {
        self as usize
    }
}

// Observable text, frozen.

/// Every string this module emits, transcribed with its locator.
///
/// # Two asymmetries that are not typos
///
/// * [`print_buf_truncated`] is **missing the space** before `val=` that
///   [`print_buf_line`] has (`lib/doh.c:201` versus `:203`).
/// * [`HTTPS_RR_IPV6HINT`] is **singular** while [`HTTPS_RR_NO_IPV6HINTS`] is
///   **plural** (`:1189` versus `:1193`), where the IPv4 pair at `:1177` and
///   `:1181` is plural on both sides.
///
/// # What is deliberately NOT here
///
/// `"HTTPS RR target: %s"` and `"HTTPS RR priority: %u"` -- note the absent
/// colon after `RR` -- belong to `lib/httpsrr.c:191` and `:193`, inside
/// `#ifdef USE_ARES`, and go with c-ares, which is dropped. The DoH forms this
/// module does emit have the colon in a different place; see
/// [`https_rr_priority_target`].
#[rustfmt::skip]
pub(crate) mod msg {
    /// `"Failed to encode DoH packet [%d]"` -- `lib/doh.c:302`.
    ///
    /// The `%d` is the raw `DOHcode`, so the number a reader sees is the
    /// integer and not the text; that is C's choice and it is kept.
    pub(crate) fn failed_to_encode(code: i32) -> String {
        format!("Failed to encode DoH packet [{code}]")
    }

    /// `"DoH request %s"` -- `lib/doh.c:248`.
    ///
    /// The argument is `curl_easy_strerror(result)`, so the interpolation is
    /// the [`CURLcode`](crate::error::CURLcode)'s message and not its number.
    /// The one message from `doh_probe_done` whose situation survives the
    /// collapse described in the module preamble: a probe can still fail.
    pub(crate) fn doh_request(reason: &str) -> String {
        format!("DoH request {reason}")
    }

    /// `"Could not DoH-resolve: %s"` -- `lib/doh.c:1211`.
    ///
    /// Emitted when neither address probe was started at all, which is the one
    /// branch of `Curl_doh_is_resolved` that reports before decoding anything.
    pub(crate) fn could_not_resolve(host: &str) -> String {
        format!("Could not DoH-resolve: {host}")
    }

    /// `"Failed to decode HTTPS RR"` -- `lib/doh.c:1266`.
    pub(crate) const FAILED_TO_DECODE_HTTPS_RR: &str =
        "Failed to decode HTTPS RR";

    /// `"Some HTTPS RR to process"` -- `lib/doh.c:1270`.
    ///
    /// Emitted on success, before the record is attached to the cache entry.
    pub(crate) const SOME_HTTPS_RR_TO_PROCESS: &str =
        "Some HTTPS RR to process";

    /// `"%s: len=%d, val=%s"` -- `lib/doh.c:201`. **Has the space.**
    pub(crate) fn print_buf_line(prefix: &str, len: i32, hex: &str) -> String {
        format!("{prefix}: len={len}, val={hex}")
    }

    /// `"%s: len=%d (truncated)val=%s"` -- `lib/doh.c:203`.
    ///
    /// **No space before `val=`, and no comma either.** Compare
    /// [`print_buf_line`]. Reproduced character for character.
    pub(crate) fn print_buf_truncated(
        prefix: &str, len: i32, hex: &str,
    ) -> String {
        format!("{prefix}: len={len} (truncated)val={hex}")
    }

    /// `"DoH: %s type %s for %s"` -- `lib/doh.c:1235-1236`.
    ///
    /// The three arguments are `doh_strerror(rc[slot])`,
    /// `doh_type2name(p->dnstype)` and the host, in that order.
    pub(crate) fn decode_failed(
        reason: &str, dnstype: &str, host: &str,
    ) -> String {
        format!("DoH: {reason} type {dnstype} for {host}")
    }

    /// `"hostname: %s"` -- `lib/doh.c:1247`.
    ///
    /// Lower case, no prefix of its own; the `[DNS]` label comes from the
    /// emitter.
    pub(crate) fn hostname(host: &str) -> String {
        format!("hostname: {host}")
    }

    /// `"[DoH] TTL: %u seconds"` -- `lib/doh.c:859`.
    ///
    /// The bracketed `[DoH]` is part of the message, not the trace emitter's
    /// feature label -- so a verbose line carries both, reading
    /// `* [DNS] [DoH] TTL: ...`. That doubling is C's and is preserved.
    pub(crate) fn doh_ttl(ttl: u32) -> String {
        format!("[DoH] TTL: {ttl} seconds")
    }

    /// `"[DoH] A: %u.%u.%u.%u"` -- `lib/doh.c:863`.
    ///
    /// Built from the four stored octets rather than from a formatted address,
    /// because C's four `%u` conversions are what fix the rendering: no
    /// zero-padding, no compression, exactly three dots.
    pub(crate) fn doh_a(octets: [u8; 4]) -> String {
        let [a, b, c, d] = octets;
        format!("[DoH] A: {a}.{b}.{c}.{d}")
    }

    /// `"[DoH] AAAA: "` -- the literal initialiser of `lib/doh.c:869`.
    ///
    /// C declares `char buffer[128] = "[DoH] AAAA: ";` and appends to it, then
    /// emits the whole thing through a bare `"%s"` (`:882`). The prefix is
    /// therefore a separate literal from the eight hexadecimal groups, and is
    /// named separately here for the same reason.
    pub(crate) const DOH_AAAA_PREFIX: &str = "[DoH] AAAA: ";

    /// `"DoH HTTPS RR: length %d"` -- `lib/doh.c:890`.
    ///
    /// The release-build form. A debug build with verbose tracing prints the
    /// record's bytes instead, through [`print_buf_line`] with the prefix
    /// `"DoH HTTPS"` (`:888`); see [`show`](super::show).
    pub(crate) fn doh_https_rr_length(len: i32) -> String {
        format!("DoH HTTPS RR: length {len}")
    }

    /// `"DoH HTTPS"` -- the `prefix` argument of `lib/doh.c:888`.
    pub(crate) const DOH_HTTPS_PREFIX: &str = "DoH HTTPS";

    /// `"CNAME: %s"` -- `lib/doh.c:895`.
    ///
    /// No `[DoH]` prefix, unlike its three neighbours in the same function.
    /// Another real inconsistency, and another one left alone.
    pub(crate) fn cname(name: &str) -> String {
        format!("CNAME: {name}")
    }

    /// `"HTTPS RR: priority %d, target: %s"` -- `lib/doh.c:1166`.
    pub(crate) fn https_rr_priority_target(
        priority: u16, target: &str,
    ) -> String {
        format!("HTTPS RR: priority {priority}, target: {target}")
    }

    /// `"HTTPS RR: alpns %u %u %u %u"` -- `lib/doh.c:1168`.
    ///
    /// **All four slots, unconditionally**, so trailing `ALPN_none` zeros are
    /// printed. Distinct from `httpsrr.rs`'s own
    /// `"HTTPS RR ALPN: {} {} {} {}"`, which is emitted by the SvcParam setter
    /// at a different moment; neither duplicates the other.
    pub(crate) fn https_rr_alpns(alpns: [u8; 4]) -> String {
        let [a, b, c, d] = alpns;
        format!("HTTPS RR: alpns {a} {b} {c} {d}")
    }

    /// `"HTTPS RR: no alpns"` -- `lib/doh.c:1171`.
    pub(crate) const HTTPS_RR_NO_ALPNS: &str = "HTTPS RR: no alpns";

    /// `"HTTPS RR: no_def_alpn set"` -- `lib/doh.c:1173`.
    pub(crate) const HTTPS_RR_NO_DEF_ALPN_SET: &str =
        "HTTPS RR: no_def_alpn set";

    /// `"HTTPS RR: no_def_alpn not set"` -- `lib/doh.c:1175`.
    pub(crate) const HTTPS_RR_NO_DEF_ALPN_NOT_SET: &str =
        "HTTPS RR: no_def_alpn not set";

    /// `"HTTPS RR: ipv4hints"` -- `lib/doh.c:1177`, the `prefix` of a
    /// [`print_buf_line`] call rather than a message in its own right.
    pub(crate) const HTTPS_RR_IPV4HINTS: &str = "HTTPS RR: ipv4hints";

    /// `"HTTPS RR: no ipv4hints"` -- `lib/doh.c:1181`. Plural, as is its
    /// positive counterpart.
    pub(crate) const HTTPS_RR_NO_IPV4HINTS: &str = "HTTPS RR: no ipv4hints";

    /// `"HTTPS RR: ECHConfigList"` -- `lib/doh.c:1183`. Note the casing:
    /// `ECHConfigList` exactly, as RFC 9180 spells the structure.
    pub(crate) const HTTPS_RR_ECHCONFIGLIST: &str =
        "HTTPS RR: ECHConfigList";

    /// `"HTTPS RR: no ECHConfigList"` -- `lib/doh.c:1187`.
    pub(crate) const HTTPS_RR_NO_ECHCONFIGLIST: &str =
        "HTTPS RR: no ECHConfigList";

    /// `"HTTPS RR: ipv6hint"` -- `lib/doh.c:1189`. **SINGULAR.**
    ///
    /// Its negative counterpart [`HTTPS_RR_NO_IPV6HINTS`] is plural. The
    /// asymmetry is in the C source, is visible in a `--trace` log, and is
    /// preserved rather than regularised.
    pub(crate) const HTTPS_RR_IPV6HINT: &str = "HTTPS RR: ipv6hint";

    /// `"HTTPS RR: no ipv6hints"` -- `lib/doh.c:1193`. **PLURAL.** See
    /// [`HTTPS_RR_IPV6HINT`].
    pub(crate) const HTTPS_RR_NO_IPV6HINTS: &str = "HTTPS RR: no ipv6hints";

    /// `"Content-Type: application/dns-message"` -- `lib/doh.c:314`.
    ///
    /// The single header a DoH probe sends, as one `curl_slist` entry, and
    /// therefore one complete header line with its name, colon, single space
    /// and value. RFC 8484 section 4.1 fixes the media type; the casing and
    /// the spacing are curl's and are wire-observable.
    pub(crate) const CONTENT_TYPE_DNS_MESSAGE: &str =
        "Content-Type: application/dns-message";

    /// `"https"` -- the `CURLOPT_DEFAULT_PROTOCOL` value of `lib/doh.c:329`.
    pub(crate) const DEFAULT_PROTOCOL: &str = "https";
}

// Bounds-checked wire primitives -- `lib/doh.c:545-562`.

/// Reads a big-endian `u16` at `index`, or [`None`] if it does not fit.
fn get16bit(doh: &[u8], index: usize) -> Option<u16> {
    let end = index.checked_add(2)?;
    let bytes = doh.get(index..end)?;
    let &[high, low] = bytes else { return None };
    Some(u16::from_be_bytes([high, low]))
}

/// Reads a big-endian `u32` at `index`, or [`None`] if it does not fit.
///
/// Supersedes `doh_get32bit` (`lib/doh.c:551-562`), whose body carries two
/// comments about hazards that **both disappear** in this form, which is why it
/// is worth one sentence each:
///
/// * *"make clang and gcc optimize this to bswap by incrementing the pointer
///   first"* -- a codegen hint with no meaning for `u32::from_be_bytes`, which
///   is the byte swap.
/// * *"avoid undefined behavior by casting to unsigned before shifting 24
///   bits, possibly into the sign bit ... ub sanitizer will not be upset"* --
///   there is no shift and no signed intermediate, so the undefined behaviour
///   C had to write around cannot be expressed.
fn get32bit(doh: &[u8], index: usize) -> Option<u32> {
    let end = index.checked_add(4)?;
    let bytes = doh.get(index..end)?;
    let &[a, b, c, d] = bytes else { return None };
    Some(u32::from_be_bytes([a, b, c, d]))
}

/// Steps `index` past one QNAME **without following compression pointers**.
///
/// Supersedes `doh_skipqname` (`lib/doh.c:521-543`). Five behaviours are
/// transcribed and none may be merged with its neighbour:
///
/// * **`dohlen < (*indexp + 1)` (`:526`)** -- [`DohCode::DnsOutOfRange`]
/// * **`(length & 0xc0) == 0xc0` (`:529`)** -- require two bytes, advance
///   **2**, `break`
/// * **`length & 0xc0` (`:536`)** -- [`DohCode::DnsBadLabel`] -- the `0x40` and
///   `0x80` patterns
/// * **`dohlen < (*indexp + 1 + length)` (`:538`)** --
///   [`DohCode::DnsOutOfRange`]
/// * **`while(length)` (`:541`)** -- a zero length byte ends the name
///
/// **This parser does not follow a pointer; [`DohEntry::store_cname`] does.**
/// The asymmetry is deliberate on both sides: skipping a name needs only its
/// length, and a pointer is exactly two bytes long wherever it points, so
/// following it would be work with no result. The two functions also return
/// *different* codes for their bounds failures -- `DnsOutOfRange` here, and
/// `DnsBadLabel` for one of the two in `store_cname` -- and both spellings are
/// preserved.
///
/// # Errors
///
/// [`DohCode::DnsOutOfRange`] for a read past the end of `doh`, or
/// [`DohCode::DnsBadLabel`] for a reserved label type.
fn skipqname(doh: &[u8], index: &mut usize) -> Result<(), DohCode> {
    loop {
        // `if(dohlen < (*indexp + 1)) return DOH_DNS_OUT_OF_RANGE;`
        let length = *doh.get(*index).ok_or(DohCode::DnsOutOfRange)?;

        if (length & LABEL_TYPE_MASK) == LABEL_TYPE_POINTER {
            // `if(dohlen < (*indexp + 2)) return DOH_DNS_OUT_OF_RANGE;`
            let after = index.checked_add(2).ok_or(DohCode::DnsOutOfRange)?;
            if doh.len() < after {
                return Err(DohCode::DnsOutOfRange);
            }
            // `*indexp += 2; break;` -- the pointer is not followed.
            *index = after;
            return Ok(());
        }
        if (length & LABEL_TYPE_MASK) != 0 {
            // `if(length & 0xc0) return DOH_DNS_BAD_LABEL;`
            return Err(DohCode::DnsBadLabel);
        }

        // `if(dohlen < (*indexp + 1 + length)) return DOH_DNS_OUT_OF_RANGE;`
        let after = index
            .checked_add(1)
            .and_then(|next| next.checked_add(usize::from(length)))
            .ok_or(DohCode::DnsOutOfRange)?;
        if doh.len() < after {
            return Err(DohCode::DnsOutOfRange);
        }
        *index = after;

        // `} while(length);` -- the root label ends the name. Tested last so
        // that the zero byte itself is consumed, exactly as the do-while does.
        if length == 0 {
            return Ok(());
        }
    }
}

// `struct dohaddr` -- `lib/doh.h:123-129`.

/// One address a DoH answer carried.
///
/// Supersedes `struct dohaddr` (`lib/doh.h:123-129`):
///
/// ```c
/// struct dohaddr {
///   int type;
///   union {
///     unsigned char v4[4]; /* network byte order */
///     unsigned char v6[16];
///   } ip;
/// };
/// ```
///
/// The discriminated union becomes an [`IpAddr`], which is the same shape with
/// the tag and the payload welded together. Three things follow, and all three
/// are improvements C could not have:
///
/// * `type` cannot disagree with the arm of `ip` that is populated. In C it
///   could, and reading the wrong arm was undefined behaviour.
/// * *"network byte order"* stops being a comment and becomes the contract of
///   [`Ipv4Addr::from`] and [`Ipv6Addr::from`] over a byte array, which is what
///   [`DohEntry::store_a`] and [`DohEntry::store_aaaa`] feed them.
/// * The `4`-versus-`16` length rule is checked by the type rather than by the
///   caller. [`DohEntry::rdata`] still performs C's explicit RDATA-length test,
///   because that test produces an observable [`DohCode::DnsRdataLen`] and is
///   not merely a memory-safety measure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct DohAddr(pub(crate) IpAddr);

impl DohAddr {
    /// The record type this address came from.
    ///
    /// C stores it in the `type` member and reads it back in `doh_show`
    /// (`lib/doh.c:862`, `:867`) and `doh2ai` (`:937`). Derived here, so the
    /// two can never disagree.
    #[allow(dead_code)]
    pub(crate) const fn dnstype(self) -> DnsType {
        match self.0 {
            IpAddr::V4(_) => DnsType::A,
            IpAddr::V6(_) => DnsType::Aaaa,
        }
    }
}

// `struct dohhttps_rr` -- `lib/doh.h:140-143`.

/// One HTTPS resource record's RDATA, stored verbatim.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DohHttpsRr {
    /// C's `val` and `len` as one owned buffer.
    pub(crate) val: Vec<u8>,
}

impl DohHttpsRr {
    /// C's `len`, narrowed as C declares it.
    ///
    /// The C field is `uint16_t` because an RDATA length is a 16-bit field on
    /// the wire, and [`DohEntry::rdata`] only ever stores a slice whose length
    /// came from such a field, so the cast cannot lose information. It is
    /// written as a saturating conversion rather than an `as` cast so that the
    /// invariant is enforced instead of assumed.
    pub(crate) fn len(&self) -> u16 {
        u16::try_from(self.val.len()).unwrap_or(u16::MAX)
    }
}

// `struct dohentry` -- `lib/doh.h:146-156`, plus the `store_*` family and
// `de_init` / `de_cleanup` -- `lib/doh.c:564-710`, `:1028-1038`.

/// Everything one or more DoH answers contributed.
///
/// ```c
/// struct dohentry {
///   struct dynbuf cname[DOH_MAX_CNAME];
///   struct dohaddr addr[DOH_MAX_ADDR];
///   int numaddr;
///   unsigned int ttl;
///   int numcname;
///   struct dohhttps_rr https_rrs[DOH_MAX_HTTPS];
///   int numhttps_rrs;
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DohEntry {
    /// C's `cname[DOH_MAX_CNAME]` and `numcname`, capped at
    /// [`DOH_MAX_CNAME`].
    pub(crate) cname: Vec<Vec<u8>>,
    /// C's `addr[DOH_MAX_ADDR]` and `numaddr`, capped at [`DOH_MAX_ADDR`].
    ///
    /// **The order is behaviour.** [`doh2ai`] walks it front to back and
    /// `conn/happy_eyeballs.rs` races what that produces, so a sort here would
    /// change which address a transfer connects to.
    pub(crate) addr: Vec<DohAddr>,
    /// C's `ttl`, seeded to `INT_MAX`.
    pub(crate) ttl: u32,
    /// C's `https_rrs[DOH_MAX_HTTPS]` and `numhttps_rrs`, capped at
    /// [`DOH_MAX_HTTPS`].
    ///
    /// Unconditional, where C wraps both in `#ifdef USE_HTTPSRR`
    /// (`lib/doh.h:152-155`); see the module preamble.
    pub(crate) https_rrs: Vec<DohHttpsRr>,
}

impl Default for DohEntry {
    /// Supersedes `de_init` (`lib/doh.c:702-709`).
    ///
    /// The `memset` is the empty vectors, and the `curlx_dyn_init` loop has no
    /// counterpart because a buffer is created with its cap at the moment
    /// [`Self::store_cname`] needs one -- C has to pre-initialise all four
    /// because the array exists whether or not it is used.
    fn default() -> Self {
        Self {
            cname: Vec::new(),
            addr: Vec::new(),
            // `de->ttl = INT_MAX;`
            ttl: i32::MAX as u32,
            https_rrs: Vec::new(),
        }
    }
}

impl DohEntry {
    /// Stores an `A` record's four octets, or silently drops it.
    fn store_a(&mut self, rdata: &[u8]) {
        // `if(d->numaddr < DOH_MAX_ADDR)`
        if self.addr.len() >= DOH_MAX_ADDR {
            return;
        }
        // `memcpy(&a->ip.v4, &doh[index], 4);` -- network byte order, which is
        // what `Ipv4Addr::from([u8; 4])` reads.
        let &[a, b, c, d] = rdata else { return };
        self.addr
            .push(DohAddr(IpAddr::V4(Ipv4Addr::new(a, b, c, d))));
    }

    /// Stores an `AAAA` record's sixteen octets, or silently drops it.
    ///
    /// Supersedes `doh_store_aaaa` (`lib/doh.c:576-586`). Identical in every
    /// respect to [`Self::store_a`] but the width, exactly as the C pair is.
    fn store_aaaa(&mut self, rdata: &[u8]) {
        if self.addr.len() >= DOH_MAX_ADDR {
            return;
        }
        let Ok(octets) = <[u8; 16]>::try_from(rdata) else {
            return;
        };
        self.addr.push(DohAddr(IpAddr::V6(Ipv6Addr::from(octets))));
    }

    /// Stores an HTTPS record's RDATA verbatim, or silently drops it.
    ///
    /// Supersedes `doh_store_https` (`lib/doh.c:589-602`), whose comment is
    /// *"silently ignore RRs over the limit"* and which returns `DOH_OK` in
    /// that case -- an over-limit record is success, not an error.
    ///
    /// # Errors
    ///
    /// [`DohCode::OutOfMem`], which is C's `if(!h->val) return DOH_OUT_OF_MEM;`
    /// after its `curlx_memdup` (`lib/doh.c:596-598`).
    ///
    /// The duplicated extent is an RDATA field from a **DNS response**, so its
    /// length is chosen by whatever answered the query -- up to 65,535 bytes per
    /// record, and up to [`DOH_MAX_HTTPS`] records. That is an externally sized
    /// allocation by any reading, which is why it is routed through
    /// [`crate::util::fallible`] rather than allowed to abort: a resolver
    /// answering a hostile or merely large HTTPS record must not be able to kill
    /// an embedding process that is prepared to handle an out-of-memory return.
    ///
    /// The over-limit case is still success, and still silent, exactly as the
    /// C's comment says: *"silently ignore RRs over the limit"*.
    fn store_https(&mut self, rdata: &[u8]) -> Result<(), DohCode> {
        // `if(d->numhttps_rrs < DOH_MAX_HTTPS)`
        if self.https_rrs.len() >= DOH_MAX_HTTPS {
            return Ok(());
        }
        // The copy first, then the push: nothing is stored unless both
        // allocations succeeded, which is the shape the C gets from checking
        // `h->val` before incrementing `numhttps_rrs`.
        let val =
            fallible::vec_from_slice(rdata).map_err(|_| DohCode::OutOfMem)?;
        fallible::push(&mut self.https_rrs, DohHttpsRr { val })
            .map_err(|_| DohCode::OutOfMem)
    }

    /// Decodes a `CNAME` record's name, **following compression pointers**.
    ///
    /// Supersedes `doh_store_cname` (`lib/doh.c:605-653`), the one parser in
    /// this module that chases a pointer, and therefore the one that needs a
    /// loop guard. Every clause is transcribed:
    ///
    /// * **`if(d->numcname == DOH_MAX_CNAME) return DOH_OK;` (`:612-613`)** --
    ///   over the cap is **success**, and nothing is stored
    /// * **`if(index >= dohlen)` (`:617`)** -- [`DohCode::DnsOutOfRange`]
    /// * **`(length & 0xc0) == 0xc0` (`:620`)** -- needs `index + 1 < dohlen`
    ///   (`:623`), else `DnsOutOfRange`; then jumps and `continue`s
    /// * **`else if(length & 0xc0)` (`:631`)** -- [`DohCode::DnsBadLabel`]
    /// * **`if(curlx_dyn_len(c))` (`:637`)** -- a `"."` separator, only when
    ///   something is already stored
    /// * **`if((index + length) > dohlen)` (`:641`)** --
    ///   **[`DohCode::DnsBadLabel`]**, not `DnsOutOfRange`
    /// * **`while(length && --loop)` (`:648`)** -- [`CNAME_LOOP_BUDGET`]
    ///   iterations
    /// * **`if(!loop) return DOH_DNS_LABEL_LOOP;` (`:650-651`)** -- budget
    ///   exhausted
    ///
    /// Two details are easy to lose and are called out:
    ///
    /// * **The two bounds tests return different codes.** `:617` gives
    ///   `DnsOutOfRange` and `:641` gives `DnsBadLabel`, for what is arguably
    ///   the same kind of overrun. Both are preserved.
    /// * **The separator is written before the bound is checked** (`:637-642`),
    ///   so a name that overruns can still have left a trailing `"."` in the
    ///   buffer. The buffer is discarded on error by the caller, so the
    ///   ordering is unobservable -- but it is reproduced rather than tidied,
    ///   because "unobservable" is a claim about today's callers.
    ///
    /// # Errors
    ///
    /// [`DohCode::DnsOutOfRange`], [`DohCode::DnsBadLabel`],
    /// [`DohCode::DnsLabelLoop`], or [`DohCode::OutOfMem`] when the decoded
    /// name would pass [`DYN_DOH_CNAME`].
    fn store_cname(&mut self, doh: &[u8], index: usize) -> Result<(), DohCode> {
        // `if(d->numcname == DOH_MAX_CNAME) return DOH_OK; /* skip! */`
        if self.cname.len() >= DOH_MAX_CNAME {
            return Ok(());
        }

        // `c = &d->cname[d->numcname++];` -- C takes the next pre-initialised
        // buffer and increments the count BEFORE walking, so whatever the walk
        // managed to write is retained even when it then fails. Pushing after
        // the walk with the outcome held aside is the same observable result
        // and needs no borrow of `self` across the walk.
        let mut buffer = DynBuf::new(DYN_DOH_CNAME);
        let outcome = decode_cname_into(doh, index, &mut buffer);
        self.cname.push(buffer.take());
        outcome
    }

    /// Dispatches one answer's RDATA by record type.
    ///
    /// Supersedes `doh_rdata` (`lib/doh.c:655-699`), carrying C's own summary
    /// of the widths it accepts:
    ///
    /// ```text
    /// RDATA
    ///  - A (TYPE 1): 4 bytes
    ///  - AAAA (TYPE 28): 16 bytes
    ///  - NS (TYPE 2): N bytes
    ///  - HTTPS (TYPE 65): N bytes
    /// ```
    ///
    /// Six arms, and every one of C's is present:
    ///
    /// * `A` -- `if(rdlength != 4) return DOH_DNS_RDATA_LEN;` (`:671-672`).
    /// * `AAAA` -- `if(rdlength != 16)` likewise (`:676-677`).
    /// * `HTTPS` -- stored verbatim at any length, unconditional here where C
    ///   has `#ifdef USE_HTTPSRR` (`:680-686`).
    /// * `CNAME` -- decoded, and the only arm that can fail for a reason other
    ///   than length (`:687-691`).
    /// * `DNAME` -- C's comment is *"explicit for clarity; just skip; rely on
    ///   synthesized CNAME"* (`:692-694`). The empty arm is the behaviour.
    /// * `default` -- *"unsupported type, just skip it"* (`:695-697`). Reached
    ///   only through [`DnsType::Ns`], the one variant this module recognises
    ///   without handling.
    ///
    /// # Errors
    ///
    /// [`DohCode::DnsRdataLen`] for a mis-sized address, or whatever
    /// [`Self::store_https`] or [`Self::store_cname`] reports.
    fn rdata(
        &mut self,
        doh: &[u8],
        rdata_at: usize,
        rdata: &[u8],
        dnstype: DnsType,
    ) -> Result<(), DohCode> {
        match dnstype {
            DnsType::A => {
                if rdata.len() != 4 {
                    return Err(DohCode::DnsRdataLen);
                }
                self.store_a(rdata);
            }
            DnsType::Aaaa => {
                if rdata.len() != 16 {
                    return Err(DohCode::DnsRdataLen);
                }
                self.store_aaaa(rdata);
            }
            DnsType::Https => self.store_https(rdata)?,
            DnsType::Cname => self.store_cname(doh, rdata_at)?,
            // `case CURL_DNS_TYPE_DNAME: /* just skip */ break;` and
            // `default: /* unsupported type, just skip it */ break;`
            DnsType::Dname | DnsType::Ns => {}
        }
        Ok(())
    }

    /// True when nothing at all was stored, by C's *effective* test.
    ///
    /// The predicate behind [`DohCode::NoContent`], separated out because the
    /// reason it reads the way it does needs more room than a condition allows.
    /// See [`resp_decode`], which is its only caller and which documents the
    /// `USE_HTTTPS` typo in full.
    fn stored_nothing(&self) -> bool {
        self.cname.is_empty() && self.addr.is_empty()
    }
}

/// The compression-following name walk of `doh_store_cname`'s loop body.
///
/// # Errors
///
/// [`DohCode::DnsOutOfRange`], [`DohCode::DnsBadLabel`],
/// [`DohCode::DnsLabelLoop`] or [`DohCode::OutOfMem`].
fn decode_cname_into(
    doh: &[u8],
    mut index: usize,
    buffer: &mut DynBuf,
) -> Result<(), DohCode> {
    // `unsigned int loop = 128;`. C's decrement lives in the `while
    // (length && --loop)` condition, which every path except a zero-length
    // label reaches -- including the `continue` a compression pointer takes,
    // because `continue` in a do-while jumps to the condition. The body
    // therefore runs at most 128 times however it is left, and the two
    // `spend` calls below are the two paths that reach that condition.
    let mut budget = CNAME_LOOP_BUDGET;

    // `--loop` then `if(!loop) return DOH_DNS_LABEL_LOOP;`.
    let spend = |budget: &mut u32| -> Result<(), DohCode> {
        *budget = budget.saturating_sub(1);
        if *budget == 0 {
            return Err(DohCode::DnsLabelLoop);
        }
        Ok(())
    };

    loop {
        // `if(index >= dohlen) return DOH_DNS_OUT_OF_RANGE;`
        let length = *doh.get(index).ok_or(DohCode::DnsOutOfRange)?;

        if (length & LABEL_TYPE_MASK) == LABEL_TYPE_POINTER {
            // `if((index + 1) >= dohlen) return DOH_DNS_OUT_OF_RANGE;`
            let low_at = index.checked_add(1).ok_or(DohCode::DnsOutOfRange)?;
            let low = *doh.get(low_at).ok_or(DohCode::DnsOutOfRange)?;
            // `newpos = (length & 0x3f) << 8 | doh[index + 1];` -- a 14-bit
            // offset from the START of the message, which is why this parser
            // needs the whole of `doh` and not just the RDATA.
            index = usize::from(u16::from_be_bytes([
                length & LABEL_POINTER_OFFSET_MASK,
                low,
            ]));
            // `continue;`
            spend(&mut budget)?;
            continue;
        } else if (length & LABEL_TYPE_MASK) != 0 {
            // `else if(length & 0xc0) return DOH_DNS_BAD_LABEL;`
            return Err(DohCode::DnsBadLabel);
        }
        // `else index++;`
        index = index.checked_add(1).ok_or(DohCode::DnsOutOfRange)?;

        if length != 0 {
            // `if(curlx_dyn_len(c)) dyn_addn(c, ".")` -- a separator BETWEEN
            // labels, so only once something is already stored. Written before
            // the bound below is checked, exactly as C orders it.
            if !buffer.is_empty() {
                buffer.add(".").map_err(|_| DohCode::OutOfMem)?;
            }
            // `if((index + length) > dohlen) return DOH_DNS_BAD_LABEL;` --
            // note the code: BAD_LABEL here where `:617` gives OUT_OF_RANGE.
            let end = index
                .checked_add(usize::from(length))
                .ok_or(DohCode::DnsBadLabel)?;
            let label = doh.get(index..end).ok_or(DohCode::DnsBadLabel)?;
            // `curlx_dyn_addn(c, &doh[index], length)` -- a failure here is
            // the DYN_DOH_CNAME ceiling, which C reports as OUT_OF_MEM.
            buffer.addn(label).map_err(|_| DohCode::OutOfMem)?;
            index = end;
        }

        // `} while(length && --loop);` -- a zero length byte is the root
        // label and ends the name WITHOUT spending budget, because `&&`
        // short-circuits before the decrement.
        if length == 0 {
            return Ok(());
        }
        spend(&mut budget)?;
    }
}

// `doh_resp_decode` -- `lib/doh.c:711-852`.

/// Decodes one DNS response into `entry`.
///
/// # The walk, section by section
///
/// * **header size** -- `:726-727` -- `dohlen < 12` is
///   [`DohCode::TooSmallBuffer`]
/// * **message ID** -- `:728-729` -- `doh[0]` or `doh[1]` non-zero is
///   [`DohCode::DnsBadId`]
/// * **`RCODE`** -- `:730-732` -- `doh[3] & 0x0f` non-zero is
///   [`DohCode::DnsBadRcode`], annotated *"no such name"*
/// * **`QDCOUNT`** -- `:734-743` -- skip each question's name, then four bytes
///   of `TYPE` and `CLASS`
/// * **`ANCOUNT`** -- `:745-793` -- the only section parsed; see below
/// * **`NSCOUNT`** -- `:795-815` -- **skipped, never parsed**
/// * **`ARCOUNT`** -- `:817-837` -- skipped likewise
/// * **consumption** -- `:839-840` -- `index != dohlen` is
///   [`DohCode::DnsMalformat`]
/// * **emptiness** -- `:842-849` -- see the typo section
///
/// Each answer is read in this exact order, with a bound tested before every
/// read: name, `TYPE`, `CLASS`, `TTL`, `RDLENGTH`, RDATA. Three of those carry
/// rules that are behaviour rather than parsing:
///
/// * **The accepted `TYPE` set is three-valued** (`:758-762`): the type
///   queried, or [`DnsType::Cname`] because it *"may be synthesized from
///   DNAME"*, or [`DnsType::Dname`] because *"if present, accept and ignore"*.
///   Anything else, **including a type this module knows about**, is
///   [`DohCode::DnsUnexpectedType`].
/// * **An unrecognised `TYPE` integer is also `DnsUnexpectedType`.** C compares
///   integers, so a `TYPE` of, say, 16 fails the three-way test and is
///   rejected; it never reaches `doh_rdata`'s `default` arm from this path.
///   Parsing the integer into a [`DnsType`] first and rejecting the failure
///   gives the identical outcome.
/// * **The minimum TTL wins** (`:776-777`): `if(ttl < d->ttl) d->ttl = ttl;`,
///   with the seed documented on [`DohEntry::ttl`].
///
/// # The `USE_HTTTPS` typo at `lib/doh.c:842` -- THREE T's
///
/// The emptiness test is guarded by a macro spelled `USE_HTTTPS`:
///
/// ```c
/// #ifdef USE_HTTTPS
///   if((type != CURL_DNS_TYPE_NS) && !d->numcname && !d->numaddr &&
///      !d->numhttps_rrs)
/// #else
///   if((type != CURL_DNS_TYPE_NS) && !d->numcname && !d->numaddr)
/// #endif
///     return DOH_NO_CONTENT;
/// ```
///
/// # Errors
///
/// Any [`DohCode`] but [`DohCode::Ok`].
pub(crate) fn resp_decode(
    doh: &[u8],
    dnstype: DnsType,
    entry: &mut DohEntry,
) -> Result<(), DohCode> {
    // `if(dohlen < 12) return DOH_TOO_SMALL_BUFFER;`
    if doh.len() < DNS_HEADER_LEN {
        return Err(DohCode::TooSmallBuffer);
    }
    // `if(!doh || doh[0] || doh[1]) return DOH_DNS_BAD_ID;` -- the NULL test
    // has no counterpart, since a slice cannot be null. Both ID bytes must be
    // zero because `req_encode` always writes zero; see there.
    let header = doh.get(..DNS_HEADER_LEN).ok_or(DohCode::TooSmallBuffer)?;
    let &[id_high, id_low, _flags_high, flags_low, ..] = header else {
        return Err(DohCode::TooSmallBuffer);
    };
    if id_high != 0 || id_low != 0 {
        return Err(DohCode::DnsBadId);
    }
    // `rcode = doh[3] & 0x0f; if(rcode) return DOH_DNS_BAD_RCODE;`
    if (flags_low & 0x0f) != 0 {
        return Err(DohCode::DnsBadRcode);
    }

    // `unsigned int index = 12;`
    let mut index = DNS_HEADER_LEN;

    // The four counts. Reading them cannot fail: the header is present and
    // every offset is inside it, which the `ok_or` states without asserting.
    let qdcount =
        get16bit(doh, OFFSET_QDCOUNT).ok_or(DohCode::TooSmallBuffer)?;
    let ancount =
        get16bit(doh, OFFSET_ANCOUNT).ok_or(DohCode::TooSmallBuffer)?;
    let nscount =
        get16bit(doh, OFFSET_NSCOUNT).ok_or(DohCode::TooSmallBuffer)?;
    let arcount =
        get16bit(doh, OFFSET_ARCOUNT).ok_or(DohCode::TooSmallBuffer)?;

    // `while(qdcount) { ... qdcount--; }` (`:735-743`).
    for _ in 0..qdcount {
        skipqname(doh, &mut index)?;
        // `if(dohlen < (index + 4)) return DOH_DNS_OUT_OF_RANGE;`
        // `index += 4; /* skip question's type and class */`
        index = advance(doh, index, 4)?;
    }

    // `while(ancount) { ... ancount--; }` (`:746-793`). The last `type` read
    // survives the loop in C and is what the emptiness test below inspects, so
    // it is carried out of the loop here too -- including the case of zero
    // answers, where C's `unsigned short type = 0` initialiser leaves it at a
    // value no `DNStype` claims and the `type != CURL_DNS_TYPE_NS` clause is
    // therefore true.
    let mut last_type: Option<DnsType> = None;
    for _ in 0..ancount {
        skipqname(doh, &mut index)?;

        // `if(dohlen < (index + 2)) return DOH_DNS_OUT_OF_RANGE;`
        // `type = doh_get16bit(doh, index);`
        let raw_type = get16bit(doh, index).ok_or(DohCode::DnsOutOfRange)?;
        // The three-way acceptance test of `:758-762`, with an unrecognised
        // integer falling into the same rejection: C's comparison against
        // three integers cannot match a fourth, whatever it is.
        let answer_type = match dns_type_from_u16(raw_type) {
            Some(DnsType::Cname) => DnsType::Cname,
            Some(DnsType::Dname) => DnsType::Dname,
            Some(other) if other == dnstype => other,
            // "Not the same type as was asked for nor CNAME nor DNAME"
            _ => return Err(DohCode::DnsUnexpectedType),
        };
        last_type = Some(answer_type);
        index = advance(doh, index, 2)?;

        // `dnsclass = doh_get16bit(doh, index);`
        // `if(DNS_CLASS_IN != dnsclass) return DOH_DNS_UNEXPECTED_CLASS;`
        let dnsclass = get16bit(doh, index).ok_or(DohCode::DnsOutOfRange)?;
        if dnsclass != DNS_CLASS_IN {
            return Err(DohCode::DnsUnexpectedClass);
        }
        index = advance(doh, index, 2)?;

        // `ttl = doh_get32bit(doh, index); if(ttl < d->ttl) d->ttl = ttl;`
        let ttl = get32bit(doh, index).ok_or(DohCode::DnsOutOfRange)?;
        if ttl < entry.ttl {
            entry.ttl = ttl;
        }
        index = advance(doh, index, 4)?;

        // `rdlength = doh_get16bit(doh, index); index += 2;`
        // `if(dohlen < (index + rdlength)) return DOH_DNS_OUT_OF_RANGE;`
        let rdlength = get16bit(doh, index).ok_or(DohCode::DnsOutOfRange)?;
        index = advance(doh, index, 2)?;
        let rdata_end = index
            .checked_add(usize::from(rdlength))
            .ok_or(DohCode::DnsOutOfRange)?;
        let rdata = doh.get(index..rdata_end).ok_or(DohCode::DnsOutOfRange)?;

        // `rc = doh_rdata(doh, dohlen, rdlength, type, (int)index, d);`
        entry.rdata(doh, index, rdata, answer_type)?;
        index = rdata_end;
    }

    // `while(nscount)` (`:796-815`) and `while(arcount)` (`:818-837`) are
    // byte-for-byte identical in C, so one helper serves both. Records in
    // these two sections are SKIPPED and never parsed -- no type test, no
    // class test, no TTL contribution.
    for _ in 0..nscount {
        skip_unparsed_record(doh, &mut index)?;
    }
    for _ in 0..arcount {
        skip_unparsed_record(doh, &mut index)?;
    }

    // `if(index != dohlen) return DOH_DNS_MALFORMAT;` -- EXACT consumption.
    // Trailing bytes are an error, not padding to be tolerated.
    if index != doh.len() {
        return Err(DohCode::DnsMalformat);
    }

    // `if((type != CURL_DNS_TYPE_NS) && !d->numcname && !d->numaddr)` -- the
    // `#else` branch, which is the one that compiles. See this function's
    // documentation for the `USE_HTTTPS` typo at `lib/doh.c:842` that makes it
    // so, and note that `numhttps_rrs` is deliberately NOT consulted.
    if last_type != Some(DnsType::Ns) && entry.stored_nothing() {
        // `/* nothing stored! */ return DOH_NO_CONTENT;`
        return Err(DohCode::NoContent);
    }

    Ok(())
}

/// Advances `index` by `step`, requiring the bytes to be present.
///
/// # Errors
///
/// [`DohCode::DnsOutOfRange`].
fn advance(doh: &[u8], index: usize, step: usize) -> Result<usize, DohCode> {
    let next = index.checked_add(step).ok_or(DohCode::DnsOutOfRange)?;
    if doh.len() < next {
        return Err(DohCode::DnsOutOfRange);
    }
    Ok(next)
}

/// Skips one record of the authority or additional section.
///
/// # Errors
///
/// Whatever [`skipqname`] reports, or [`DohCode::DnsOutOfRange`].
fn skip_unparsed_record(doh: &[u8], index: &mut usize) -> Result<(), DohCode> {
    skipqname(doh, index)?;

    // `if(dohlen < (index + 8)) return DOH_DNS_OUT_OF_RANGE;` then
    // `index += 2 + 2 + 4; /* type, dnsclass and ttl */` -- the check and the
    // skip are the same eight bytes, so one `advance` is both.
    *index = advance(doh, *index, 2 + 2 + 4)?;

    // `if(dohlen < (index + 2))`, then
    // `rdlength = doh_get16bit(doh, index); index += 2;`
    let rdlength = get16bit(doh, *index).ok_or(DohCode::DnsOutOfRange)?;
    *index = advance(doh, *index, 2)?;

    // `if(dohlen < (index + rdlength)) return DOH_DNS_OUT_OF_RANGE;`
    // `index += rdlength;`
    *index = advance(doh, *index, usize::from(rdlength))?;
    Ok(())
}

/// The [`DnsType`] a wire code names, or [`None`].
#[rustfmt::skip]
const fn dns_type_from_u16(raw: u16) -> Option<DnsType> {
    match raw {
        1  => Some(DnsType::A),
        2  => Some(DnsType::Ns),
        5  => Some(DnsType::Cname),
        28 => Some(DnsType::Aaaa),
        39 => Some(DnsType::Dname),
        65 => Some(DnsType::Https),
        _  => None,
    }
}

// `doh_req_encode` -- `lib/doh.c:70-167`. BYTE-EXACT.

/// Builds the DNS query for `host` and `dnstype` into `out`, returning its
/// length.
///
/// # The length pre-computation, and why the `+ 1` is there
///
/// C's own twenty-line comment at `:82-102` is the specification, and it is
/// worth having in full because it is the only place the arithmetic is
/// justified:
///
/// > The expected output length is 16 bytes more than the length of the
/// > QNAME-encoding of the hostname.
/// >
/// > A valid DNS name may not contain a zero-length label, except at the end.
/// > For this reason, a name beginning with a dot, or containing a sequence of
/// > two or more consecutive dots, is invalid and cannot be encoded as a QNAME.
/// >
/// > If the hostname ends with a trailing dot, the corresponding QNAME-encoding
/// > is one byte longer than the hostname. If (as is also valid) the hostname is
/// > shortened by the omission of the trailing dot, then its QNAME-encoding will
/// > be two bytes longer than the hostname.
/// >
/// > Each [ label, dot ] pair is encoded as [ length, label ], preserving
/// > overall length. A final [ label ] without a dot is also encoded as
/// > [ length, label ], increasing overall length by one. The encoding is
/// > completed by appending a zero byte, representing the zero-length root
/// > label, again increasing the overall length by one.
///
/// # The twelve-byte header
///
/// ```text
/// 00 00   ID -- always zero
/// 01      |QR| Opcode |AA|TC|RD|   "Set the RD bit"
/// 00      |RA|   Z    |  RCODE  |
/// 00 01   QDCOUNT = 1
/// 00 00   ANCOUNT = 0
/// 00 00   NSCOUNT = 0
/// 00 00   ARCOUNT = 0
/// ```
///
/// # Divergences, both stated
///
/// * `DEBUGASSERT(hostlen)` (`:105`) becomes a **returned error**. An empty
///   host is a caller bug either way, but a debug-only assertion means a
///   release build indexes `host[hostlen - 1]` at `host[-1]`; returning
///   [`DohCode::DnsBadLabel`] makes the bug visible in every build and cannot
///   underflow. The code is `DnsBadLabel` because an empty host is a
///   zero-length first label, which is what `:137` rejects for every other
///   spelling of the same mistake.
/// * `DEBUGASSERT(*olen == expected_len)` (`:165`), whose comment is *"verify
///   that our estimation of length is valid, since this has led to buffer
///   overflows in this function"*, becomes a [`debug_assert_eq!`]. The overflow
///   it guards against cannot occur here -- writes go through a bounds-checked
///   cursor -- but the *equality* is a real invariant of the arithmetic above
///   and is worth keeping as one.
///
/// # Errors
///
/// * [`DohCode::DnsNameTooLong`] when the encoding would exceed
///   [`DOH_MAX_DNSREQ_SIZE`].
/// * [`DohCode::TooSmallBuffer`] when `out` is shorter than the encoding.
/// * [`DohCode::DnsBadLabel`] for an empty host, a leading dot, two consecutive
///   dots, or a label longer than [`MAX_LABEL_LEN`]. **The reported length is
///   zero in this case**, matching C's `*olen = 0;` at `:139` -- which is set
///   *before* the return and is the one place C writes the out-parameter on a
///   failure path.
pub(crate) fn req_encode(
    host: &str,
    dnstype: DnsType,
    out: &mut [u8],
) -> Result<usize, DohCode> {
    let hostlen = host.len();

    // `DEBUGASSERT(hostlen);` -- see the divergence note above.
    if hostlen == 0 {
        return Err(DohCode::DnsBadLabel);
    }

    // `expected_len = 12 + 1 + hostlen + 4;`
    // `if(host[hostlen - 1] != '.') expected_len++;`
    let mut expected_len = DNS_HEADER_LEN
        .checked_add(1)
        .and_then(|acc| acc.checked_add(hostlen))
        .and_then(|acc| acc.checked_add(4))
        .ok_or(DohCode::DnsNameTooLong)?;
    if !host.ends_with('.') {
        expected_len =
            expected_len.checked_add(1).ok_or(DohCode::DnsNameTooLong)?;
    }

    // `if(expected_len > DOH_MAX_DNSREQ_SIZE) return DOH_DNS_NAME_TOO_LONG;`
    if expected_len > DOH_MAX_DNSREQ_SIZE {
        return Err(DohCode::DnsNameTooLong);
    }
    // `if(len < expected_len) return DOH_TOO_SMALL_BUFFER;`
    if out.len() < expected_len {
        return Err(DohCode::TooSmallBuffer);
    }

    // A write cursor rather than C's advancing `unsigned char *dnsp`. Every
    // push is bounds-checked, so the class of defect C's comment at `:163-164`
    // records is not merely unlikely here but inexpressible.
    let mut at = 0usize;
    let mut put = |byte: u8| -> Result<(), DohCode> {
        let slot = out.get_mut(at).ok_or(DohCode::TooSmallBuffer)?;
        *slot = byte;
        at = at.checked_add(1).ok_or(DohCode::TooSmallBuffer)?;
        Ok(())
    };

    // The twelve-byte header of `:116-127`, in C's order.
    put(0)?; // 16-bit id, high
    put(0)?; // 16-bit id, low
    put(0x01)?; // |QR| Opcode |AA|TC|RD| -- "Set the RD bit"
    put(0)?; // |RA| Z | RCODE |
    put(0)?; // QDCOUNT, high
    put(1)?; // QDCOUNT, low -- one entry in the question section
    put(0)?; // ANCOUNT, high
    put(0)?; // ANCOUNT, low
    put(0)?; // NSCOUNT, high
    put(0)?; // NSCOUNT, low
    put(0)?; // ARCOUNT, high
    put(0)?; // ARCOUNT, low

    // `while(*hostp) { ... }` (`:130-150`). The bytes are emitted verbatim:
    // **no case folding and no IDN conversion**. The caller supplies a name
    // that is already in its wire form -- `lib/doh.c` is reached from
    // `Curl_resolv`, which has already applied `Curl_idnconvert_hostname`.
    let mut rest = host;
    while !rest.is_empty() {
        // `const char *dot = strchr(hostp, '.');`
        let (label, after) = match rest.find('.') {
            // `labellen = dot - hostp;` then `if(dot) hostp++;` (`:148-149`).
            Some(dot) => (
                rest.get(..dot).ok_or(DohCode::DnsBadLabel)?,
                rest.get(dot.saturating_add(1)..)
                    .ok_or(DohCode::DnsBadLabel)?,
            ),
            // `labellen = strlen(hostp);` and no dot to advance past.
            None => (rest, ""),
        };

        // `if((labellen > 63) || (!labellen)) { *olen = 0; return
        //  DOH_DNS_BAD_LABEL; }` -- a leading dot, two consecutive dots and an
        // over-long label all arrive here. C assigns the zero to the
        // out-parameter BEFORE returning; the `Err` carries no length at all,
        // which is the same information and cannot be misread as a real one.
        if label.len() > MAX_LABEL_LEN || label.is_empty() {
            return Err(DohCode::DnsBadLabel);
        }

        // `*dnsp++ = (unsigned char)labellen;` then
        // `memcpy(dnsp, hostp, labellen);`
        let label_len =
            u8::try_from(label.len()).map_err(|_| DohCode::DnsBadLabel)?;
        put(label_len)?;
        for byte in label.bytes() {
            put(byte)?;
        }

        rest = after;
    }

    // `*dnsp++ = 0; /* append zero-length label for root */` (`:152`).
    put(0)?;

    // `*dnsp++ = (unsigned char)(255 & (dnstype >> 8));` then
    // `*dnsp++ = (unsigned char)(255 & dnstype);` (`:155-156`), under C's
    // comment "There are assigned TYPE codes beyond 255: use range [1..65535]".
    // `to_be_bytes` is that pair, and it is what makes `DnsType::Https` emit
    // `00 41` rather than `41 00`.
    let [type_high, type_low] = dnstype.as_u16().to_be_bytes();
    put(type_high)?;
    put(type_low)?;

    // `*dnsp++ = '\0';` upper CLASS, then `*dnsp++ = DNS_CLASS_IN;` (`:158-159`).
    let [class_high, class_low] = DNS_CLASS_IN.to_be_bytes();
    put(class_high)?;
    put(class_low)?;

    // `*olen = dnsp - orig;` then the assertion of `:165`.
    let olen = at;
    debug_assert_eq!(
        olen, expected_len,
        "the encoder's length pre-computation must match what it wrote"
    );
    Ok(olen)
}

/// The QNAME query name for an HTTPS resource record, which is port-dependent.
///
/// Supersedes `lib/doh.c:498-505`:
///
/// ```c
/// char *qname = NULL;
/// if(port != PORT_HTTPS) {
///   qname = curl_maprintf("_%d._https.%s", port, hostname);
///   if(!qname)
///     goto error;
/// }
/// result = doh_probe_run(data, CURL_DNS_TYPE_HTTPS,
///                        qname ? qname : hostname, ...);
/// ```
pub(crate) fn https_rr_qname(host: &str, port: u16) -> String {
    if port == PORT_HTTPS {
        host.to_owned()
    } else {
        format!("_{port}._https.{host}")
    }
}

// The HTTPS resource record: `doh_decode_rdata_name` (`lib/doh.c:1056-1097`),
// `doh_resp_decode_httpsrr` (`:1099-1156`) and the local `Curl_junkscan`.

/// Decodes the DNS name at the head of `rdata`, returning it and what follows.
///
/// Supersedes `doh_decode_rdata_name` (`lib/doh.c:1056-1097`), whose Doxygen
/// block explains the pointer-pointer signature:
///
/// > The input buffer pointer will be modified so it points to just after the
/// > end of the DNS name encoding on output. (And that is why it is an
/// > "unsigned char \*\*" :-)
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`] for an empty input or a label that runs past the
/// end, [`CURLcode::TooLarge`] for a name past [`CURL_MAXLEN_HOST_NAME`].
fn decode_rdata_name(rdata: &[u8]) -> CodeResult<(String, &[u8])> {
    // `if(!buf || !remaining || !dnsname || !*remaining) return
    //  CURLE_OUT_OF_MEMORY;` -- of the four tests only the last can fail here,
    // the other three being null checks on references.
    if rdata.is_empty() {
        return Err(CURLcode::OutOfMemory);
    }

    // `curlx_dyn_init(&thename, CURL_MAXLEN_host_name);`
    let mut name = DynBuf::new(CURL_MAXLEN_HOST_NAME);
    // `rem = *remaining; cp = *buf; clen = *cp++;`
    let mut rem = rdata.len();
    let mut at = 0usize;
    let mut clen = usize::from(*rdata.get(at).ok_or(CURLcode::OutOfMemory)?);
    at = at.checked_add(1).ok_or(CURLcode::OutOfMemory)?;

    // `if(clen == 0) { /* special case - return "." as name */ }` (`:1071-1074`)
    if clen == 0 {
        name.add(".")?;
    }

    // `while(clen) { ... }` (`:1076-1092`)
    while clen != 0 {
        // `if(clen >= rem) { curlx_dyn_free(&thename); return
        //  CURLE_OUT_OF_MEMORY; }` -- note `>=`, not `>`: the terminating or
        // next length byte has to fit as well.
        if clen >= rem {
            return Err(CURLcode::OutOfMemory);
        }
        let end = at.checked_add(clen).ok_or(CURLcode::OutOfMemory)?;
        let label = rdata.get(at..end).ok_or(CURLcode::OutOfMemory)?;
        // `if(curlx_dyn_addn(&thename, cp, clen) || curlx_dyn_addn(&thename,
        //  ".", 1)) return CURLE_TOO_LARGE;`
        name.addn(label).map_err(|_| CURLcode::TooLarge)?;
        name.add(".").map_err(|_| CURLcode::TooLarge)?;

        // `cp += clen; rem -= (clen + 1);`
        at = end;
        rem = rem
            .checked_sub(clen.checked_add(1).ok_or(CURLcode::OutOfMemory)?)
            .ok_or(CURLcode::OutOfMemory)?;
        // `if(rem <= 0) { ... return CURLE_OUT_OF_MEMORY; }` -- `rem` is a
        // `size_t` in C, so `rem <= 0` is `rem == 0`; the signed-looking
        // comparison is a red herring and behaves as an equality test.
        if rem == 0 {
            return Err(CURLcode::OutOfMemory);
        }
        // `clen = *cp++;`
        clen = usize::from(*rdata.get(at).ok_or(CURLcode::OutOfMemory)?);
        at = at.checked_add(1).ok_or(CURLcode::OutOfMemory)?;
    }

    // `*buf = cp; *remaining = rem - 1;` -- the minus one is the length byte
    // just consumed, which for the zero-length case is the root label itself.
    let consumed = at;
    let rest = rdata.get(consumed..).ok_or(CURLcode::OutOfMemory)?;
    debug_assert_eq!(
        rest.len(),
        rem.saturating_sub(1),
        "the remainder C computes as `rem - 1` is what is left of the slice"
    );

    // `*dnsname = curlx_dyn_ptr(&thename);` -- C hands back a `char *` and the
    // caller prints it with `%s`, so the bytes are already being treated as
    // text. Lossy conversion is that treatment made explicit; `junkscan` then
    // rejects the control bytes that would make it meaningful.
    let text = String::from_utf8_lossy(name.as_slice()).into_owned();
    Ok((text, rest))
}

/// Rejects a name carrying control bytes, a space, or `DEL`.
///
/// ```c
/// /* scan for byte values <= 31, 127 and sometimes space */
/// CURLUcode Curl_junkscan(const char *url, size_t *urllen, bool allowspace)
/// {
///   size_t n = strlen(url);
///   ...
///   if(n > CURL_MAX_INPUT_LENGTH)
///     return CURLUE_MALFORMED_INPUT;
///   control = allowspace ? 0x1f : 0x20;
///   for(i = 0; i < n; i++) {
///     if(p[i] <= control || p[i] == 127)
///       return CURLUE_MALFORMED_INPUT;
///   }
///   *urllen = n;
///   return CURLUE_OK;
/// }
/// ```
fn junkscan(name: &str) -> bool {
    // `if(n > CURL_MAX_INPUT_LENGTH) return CURLUE_MALFORMED_INPUT;`
    if name.len() > CURL_MAX_INPUT_LENGTH {
        return false;
    }
    // `control = allowspace ? 0x1f : 0x20;` with `allowspace == FALSE`.
    const CONTROL: u8 = 0x20;
    const DEL: u8 = 127;
    !name.bytes().any(|byte| byte <= CONTROL || byte == DEL)
}

/// Decodes one HTTPS resource record's RDATA into an [`HttpsRrInfo`].
///
/// # The record layout
///
/// * **minimum size** -- `:1116-1117` -- `len <= 2` is
///   [`CURLcode::BadFunctionArgument`]
/// * **`SvcPriority`** -- `:1121-1123` -- big-endian [`u16`], then advance two
/// * **`TargetName`** -- `:1124-1126` -- [`decode_rdata_name`]
/// * **name sanity** -- `:1127-1131` -- [`junkscan`], else
///   [`CURLcode::WeirdServerReply`]
/// * **port sentinel** -- `:1132` -- `lhrr->port = -1; /* until set */`, which
///   is [`None`]
/// * **SvcParams** -- `:1133-1148` -- see below
/// * **remainder** -- `:1149` -- `DEBUGASSERT(!len)` -- a debug assertion only
///
/// # SvcParam keys must strictly ascend
///
/// ```c
/// while(len >= 4) {
///   pcode = doh_get16bit(cp, 0);
///   plen = doh_get16bit(cp, 2);
///   cp += 4; len -= 4;
///   if(pcode < expected_min_pcode || plen > len) {
///     result = CURLE_WEIRD_SERVER_REPLY; goto err;
///   }
///   result = Curl_httpsrr_set(data, lhrr, pcode, cp, plen);
///   if(result) goto err;
///   cp += plen; len -= plen;
///   expected_min_pcode = pcode + 1;
/// }
/// ```
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for a record of two bytes or fewer,
/// [`CURLcode::WeirdServerReply`] for a descending or repeated key, a
/// SvcParam that overruns, or a target that fails [`junkscan`], and whatever
/// [`HttpsRrInfo::set_param`] reports for a malformed value.
pub(crate) fn resp_decode_httpsrr(
    rdata: &[u8],
    tracer: &mut Tracer<'_>,
) -> CodeResult<HttpsRrInfo> {
    // `if(len <= 2) return CURLE_BAD_FUNCTION_ARGUMENT;`
    if rdata.len() <= 2 {
        return Err(CURLcode::BadFunctionArgument);
    }

    // `lhrr->priority = doh_get16bit(cp, 0); cp += 2; len -= 2;`
    let priority = get16bit(rdata, 0).ok_or(CURLcode::WeirdServerReply)?;
    let after_priority = rdata.get(2..).ok_or(CURLcode::WeirdServerReply)?;

    // `if(doh_decode_rdata_name(&cp, &len, &dnsname) != CURLE_OK) goto err;`
    // then `lhrr->target = dnsname;`.
    let (target, mut rest) = decode_rdata_name(after_priority)
        .map_err(|_| CURLcode::WeirdServerReply)?;

    // `if(Curl_junkscan(dnsname, &olen, FALSE)) { result =
    //  CURLE_WEIRD_SERVER_REPLY; goto err; }` -- C's non-zero return is a
    // rejection, so the sense is inverted here where `junkscan` reports
    // acceptance.
    if !junkscan(&target) {
        return Err(CURLcode::WeirdServerReply);
    }

    // `lhrr = curlx_calloc(1, sizeof(struct Curl_https_rrinfo));` and the
    // `if(!lhrr) return CURLE_OUT_OF_MEMORY;` that guards it. The guard has no
    // counterpart because the ALLOCATION has none: the record is built as a
    // value on the stack and returned by move, so there is nothing for an
    // allocator to refuse. This is a genuinely absent failure mode, not an
    // unhandled one -- contrast `Self::store_https`, whose copy IS externally
    // sized and does report a refusal.
    let mut record = HttpsRrInfo {
        priority,
        target: Some(target),
        ..HttpsRrInfo::default()
    };

    // `lhrr->port = -1; /* until set */` -- `HttpsRrInfo::default()` already
    // leaves `port` as `None`, which is that sentinel; stated so that the C
    // line has a visible successor rather than appearing to have been dropped.
    debug_assert!(record.port.is_none(), "the port sentinel is `None`");

    // `uint32_t expected_min_pcode = 0;`
    let mut expected_min_pcode: u32 = 0;

    // `while(len >= 4)`
    while rest.len() >= 4 {
        let pcode = get16bit(rest, 0).ok_or(CURLcode::WeirdServerReply)?;
        let plen =
            usize::from(get16bit(rest, 2).ok_or(CURLcode::WeirdServerReply)?);
        // `cp += 4; len -= 4;`
        rest = rest.get(4..).ok_or(CURLcode::WeirdServerReply)?;

        // `if(pcode < expected_min_pcode || plen > len) { result =
        //  CURLE_WEIRD_SERVER_REPLY; goto err; }`
        if u32::from(pcode) < expected_min_pcode || plen > rest.len() {
            return Err(CURLcode::WeirdServerReply);
        }

        // `result = Curl_httpsrr_set(data, lhrr, pcode, cp, plen);` -- the one
        // call, and the reason none of its eight arms is repeated here.
        let value = rest.get(..plen).ok_or(CURLcode::WeirdServerReply)?;
        record.set_param(pcode, value, tracer)?;

        // `cp += plen; len -= plen;`
        rest = rest.get(plen..).ok_or(CURLcode::WeirdServerReply)?;
        // `expected_min_pcode = pcode + 1;`
        expected_min_pcode = u32::from(pcode).saturating_add(1);
    }

    // `DEBUGASSERT(!len);` -- debug only, and a one-to-three byte remainder is
    // tolerated in a release build. Not hardened; see this function's docs.
    debug_assert!(
        rest.is_empty(),
        "a well-formed HTTPS RR consumes its RDATA exactly, but a remainder \
         of one to three bytes is tolerated in release as C tolerates it"
    );

    Ok(record)
}

// Diagnostic output: `doh_print_buf` (`lib/doh.c:189-205`), `doh_show`
// (`:855-897`) and `doh_print_httpsrr` (`:1162-1195`).

/// Traces a labelled hexadecimal dump of `buf`, truncating a long one.
///
/// Supersedes `doh_print_buf` (`lib/doh.c:189-205`):
///
/// ```c
/// unsigned char hexstr[LOCAL_PB_HEXMAX];
/// size_t hlen = LOCAL_PB_HEXMAX;
/// bool truncated = FALSE;
/// if(len > (LOCAL_PB_HEXMAX / 2))
///   truncated = TRUE;
/// Curl_hexencode(buf, len, hexstr, hlen);
/// if(!truncated)
///   infof(data, "%s: len=%d, val=%s", prefix, (int)len, hexstr);
/// else
///   infof(data, "%s: len=%d (truncated)val=%s", prefix, (int)len, hexstr);
/// ```
///
/// # Three details of the C, all preserved
///
/// * **The truncated form has no space before `val=`, and no comma.** Compare
///   `:201` with `:203`. It looks like a typo and it is in the shipped source,
///   so it is reproduced; [`msg::print_buf_truncated`] carries it.
/// * **The reported length is the whole buffer, not the encoded part.** `(int)
///   len` is the input length even when the hex string was cut short, so a
///   truncated line reports more bytes than it shows. That is the point of the
///   marker.
/// * **The truncation threshold and the encoding limit are off by one byte.**
///   `truncated` is set when `len > 200`, but `Curl_hexencode` with
///   `olen == 400` stops while `olen >= 3` and so encodes at most **199**
///   bytes: its loop writes two characters and subtracts two from a budget of
///   400, halting at 2. A 200-byte buffer therefore prints 199 bytes' worth of
///   hex and claims not to be truncated. Reproduced exactly, with
///   [`HEXENCODE_MAX_INPUT`] naming the real limit.
pub(crate) fn print_buf(prefix: &str, buf: &[u8], tracer: &mut Tracer<'_>) {
    // `if(len > (LOCAL_PB_HEXMAX / 2)) truncated = TRUE;`
    let truncated = buf.len() > LOCAL_PB_HEXMAX / 2;

    // `Curl_hexencode(buf, len, hexstr, hlen)` -- lowercase hex, capped by the
    // output budget rather than by the input length. `hex::encode` is the same
    // lowercase alphabet as `Curl_ldigits`.
    let shown = buf.get(..buf.len().min(HEXENCODE_MAX_INPUT)).unwrap_or(buf);
    let hexstr = hex::encode(shown);

    // `(int)len` -- the input length, saturating rather than wrapping, since a
    // buffer of more than two billion bytes cannot reach here from a DNS
    // message and a wrap would print a negative number.
    let reported = i32::try_from(buf.len()).unwrap_or(i32::MAX);

    let line = if truncated {
        msg::print_buf_truncated(prefix, reported, &hexstr)
    } else {
        msg::print_buf_line(prefix, reported, &hexstr)
    };
    infof!(tracer, "{}", line);
}

/// The most bytes `Curl_hexencode` will encode into a [`LOCAL_PB_HEXMAX`]
/// buffer: 199.
const HEXENCODE_MAX_INPUT: usize = (LOCAL_PB_HEXMAX - 2) / 2;

/// Traces everything a [`DohEntry`] holds.
///
/// Supersedes `doh_show` (`lib/doh.c:855-897`), which C compiles under
/// `#ifdef CURLVERBOSE` and otherwise `#define`s away to nothing (`:898-900`).
/// There is no such feature here; the tracer's own level gate is what silences
/// it, which is both finer-grained and testable.
///
/// # The four line shapes, and the two inconsistencies among them
///
/// * `"[DoH] TTL: %u seconds"` (`:859`) -- always first.
/// * `"[DoH] A: %u.%u.%u.%u"` (`:863`) -- four unsigned conversions over the
///   stored octets.
/// * The IPv6 line is **assembled and then emitted through a bare `"%s"`**
///   (`:869-882`). C starts a 128-byte buffer at the literal `"[DoH] AAAA: "`
///   and appends eight `"%s%02x%02x"` groups, the leading `%s` being `":"` for
///   every group but the first. So the rendering is eight fixed four-digit
///   lowercase groups with no zero-compression -- **not** `Ipv6Addr`'s
///   [`fmt::Display`], which compresses runs of zeroes and would print
///   `::1` where this prints `0000:0000:...:0001`.
/// * `"CNAME: %s"` (`:895`) -- and note that it carries **no `[DoH]`
///   prefix**, unlike its three neighbours. That is in the C source and is
///   left alone.
pub(crate) fn show(entry: &DohEntry, tracer: &mut Tracer<'_>) {
    // `infof(data, "[DoH] TTL: %u seconds", d->ttl);`
    infof!(tracer, "{}", msg::doh_ttl(entry.ttl));

    // `for(i = 0; i < d->numaddr; i++)`
    for address in &entry.addr {
        match address.0 {
            IpAddr::V4(v4) => {
                infof!(tracer, "{}", msg::doh_a(v4.octets()));
            }
            IpAddr::V6(v6) => {
                infof!(tracer, "{}", aaaa_line(v6));
            }
        }
    }

    // `for(i = 0; i < d->numhttps_rrs; i++)`
    for record in &entry.https_rrs {
        if cfg!(debug_assertions) {
            // `doh_print_buf(data, "DoH HTTPS", val, len);` (`:888`)
            print_buf(msg::DOH_HTTPS_PREFIX, &record.val, tracer);
        } else {
            // `infof(data, "DoH HTTPS RR: length %d", len);` (`:890`)
            infof!(
                tracer,
                "{}",
                msg::doh_https_rr_length(i32::from(record.len()))
            );
        }
    }

    // `for(i = 0; i < d->numcname; i++) infof(data, "CNAME: %s", ptr);`
    for name in &entry.cname {
        infof!(tracer, "{}", msg::cname(&cstr_text(name)));
    }
}

/// The assembled IPv6 line of `lib/doh.c:869-882`.
fn aaaa_line(addr: Ipv6Addr) -> String {
    let mut line = String::from(msg::DOH_AAAA_PREFIX);
    // `for(j = 0; j < 16; j += 2)` with `"%s%02x%02x"` and `j ? ":" : ""`.
    for (group, pair) in addr.octets().chunks_exact(2).enumerate() {
        if group != 0 {
            line.push(':');
        }
        // `%02x%02x` over the two octets, which is `hex::encode` of the pair.
        line.push_str(&hex::encode(pair));
    }
    line
}

/// The text C's `%s` would print for a byte buffer it holds as a `char *`.
fn cstr_text(bytes: &[u8]) -> String {
    let end = memchr::memchr(0, bytes).unwrap_or(bytes.len());
    let upto = bytes.get(..end).unwrap_or(bytes);
    String::from_utf8_lossy(upto).into_owned()
}

/// Traces every field of a decoded HTTPS resource record.
///
/// # Eleven strings, and the singular/plural asymmetry
///
/// The pairs are positive-then-negative for four of the five fields, and the
/// fifth -- ALPN -- has a parameterised positive form:
///
/// * **priority and target** -- present: [`msg::https_rr_priority_target`] --
///   never absent
/// * **ALPN** -- present: [`msg::https_rr_alpns`] -- absent:
///   [`msg::HTTPS_RR_NO_ALPNS`]
/// * **`no-default-alpn`** -- present: [`msg::HTTPS_RR_NO_DEF_ALPN_SET`] --
///   absent: [`msg::HTTPS_RR_NO_DEF_ALPN_NOT_SET`]
/// * **`ipv4hint`** -- present: [`msg::HTTPS_RR_IPV4HINTS`] via [`print_buf`]
///   -- absent: [`msg::HTTPS_RR_NO_IPV4HINTS`]
/// * **`ech`** -- present: [`msg::HTTPS_RR_ECHCONFIGLIST`] via [`print_buf`] --
///   absent: [`msg::HTTPS_RR_NO_ECHCONFIGLIST`]
/// * **`ipv6hint`** -- present: [`msg::HTTPS_RR_IPV6HINT`] via [`print_buf`] --
///   absent: [`msg::HTTPS_RR_NO_IPV6HINTS`]
pub(crate) fn print_httpsrr(record: &HttpsRrInfo, tracer: &mut Tracer<'_>) {
    // `infof(data, "HTTPS RR: priority %d, target: %s", priority, target);`
    let target = record.target.as_deref().unwrap_or_default();
    infof!(
        tracer,
        "{}",
        msg::https_rr_priority_target(record.priority, target)
    );

    // `if(hrr->alpns[0] != ALPN_none)` -- slot zero only.
    if record.alpns.first().copied().unwrap_or(0) != 0 {
        infof!(tracer, "{}", msg::https_rr_alpns(record.alpns));
    } else {
        infof!(tracer, "{}", msg::HTTPS_RR_NO_ALPNS);
    }

    // `if(hrr->no_def_alpn)`
    if record.no_def_alpn {
        infof!(tracer, "{}", msg::HTTPS_RR_NO_DEF_ALPN_SET);
    } else {
        infof!(tracer, "{}", msg::HTTPS_RR_NO_DEF_ALPN_NOT_SET);
    }

    // `if(hrr->ipv4hints) doh_print_buf(...) else infof(...)`
    if let Some(hints) = record.ipv4hints.as_deref() {
        print_buf(msg::HTTPS_RR_IPV4HINTS, hints, tracer);
    } else {
        infof!(tracer, "{}", msg::HTTPS_RR_NO_IPV4HINTS);
    }

    // `if(hrr->echconfiglist) doh_print_buf(...) else infof(...)`
    if let Some(ech) = record.echconfiglist.as_deref() {
        print_buf(msg::HTTPS_RR_ECHCONFIGLIST, ech, tracer);
    } else {
        infof!(tracer, "{}", msg::HTTPS_RR_NO_ECHCONFIGLIST);
    }

    // `if(hrr->ipv6hints) doh_print_buf(...) else infof(...)` -- SINGULAR
    // prefix, PLURAL negative. See this function's documentation.
    if let Some(hints) = record.ipv6hints.as_deref() {
        print_buf(msg::HTTPS_RR_IPV6HINT, hints, tracer);
    } else {
        infof!(tracer, "{}", msg::HTTPS_RR_NO_IPV6HINTS);
    }
}

// The request shape -- `doh_probe_run`'s option block, `lib/doh.c:328-401`.

/// Which URL schemes a DoH probe may use.
///
/// Supersedes the `CURLOPT_PROTOCOLS` pair at `lib/doh.c:339-345`:
///
/// ```c
/// #ifndef DEBUGBUILD
///   /* enforce HTTPS if not debug */
///   ERROR_CHECK_SETOPT(CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
/// #else
///   /* in debug mode, also allow http */
///   ERROR_CHECK_SETOPT(CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
/// #endif
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DohProtocols {
    /// `CURLPROTO_HTTPS` alone -- the release-build value.
    HttpsOnly,
    /// `CURLPROTO_HTTP | CURLPROTO_HTTPS` -- the `DEBUGBUILD` value.
    HttpAndHttps,
}

impl DohProtocols {
    /// The value this build uses.
    pub(crate) fn for_this_build() -> Self {
        if cfg!(debug_assertions) {
            Self::HttpAndHttps
        } else {
            Self::HttpsOnly
        }
    }

    /// True when a `http://` DoH URL is permitted.
    #[allow(dead_code)]
    pub(crate) fn allows_plain_http(self) -> bool {
        matches!(self, Self::HttpAndHttps)
    }
}

/// The `CURLOPT_HTTP_VERSION` hint a DoH probe carries.
///
/// Supersedes `lib/doh.c:335-338`, which is `#ifdef USE_HTTP2`:
///
/// ```c
/// ERROR_CHECK_SETOPT(CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
/// ERROR_CHECK_SETOPT(CURLOPT_PIPEWAIT, 1L);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DohHttpVersion {
    /// `CURL_HTTP_VERSION_2TLS` (the integer 4 in `include/curl/curl.h`).
    Http2Tls,
}

/// The three TLS verification switches a DoH probe applies to *itself*.
///
/// Supersedes `lib/doh.c:355-360`:
///
/// ```c
/// ERROR_CHECK_SETOPT(CURLOPT_SSL_VERIFYHOST, data->set.doh_verifyhost ? 2L : 0L);
/// ERROR_CHECK_SETOPT(CURLOPT_SSL_VERIFYPEER, data->set.doh_verifypeer ? 1L : 0L);
/// ERROR_CHECK_SETOPT(CURLOPT_SSL_VERIFYSTATUS, data->set.doh_verifystatus ? 1L : 0L);
/// ```
///
/// # This is security-relevant, and the distinction is the security
///
/// The three inputs are `CURLOPT_DOH_SSL_VERIFYHOST`,
/// `CURLOPT_DOH_SSL_VERIFYPEER` and `CURLOPT_DOH_SSL_VERIFYSTATUS`, set by
/// `--doh-insecure` -- **not** the transfer's own `CURLOPT_SSL_VERIFY*`, and
/// **not** `--insecure`. So a transfer run with `--insecure` still validates
/// the DoH server's certificate: weakening the transfer does not weaken the
/// name resolution that precedes it, and there is no option that weakens both
/// at once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DohVerify {
    /// `data->set.doh_verifyhost`, from `CURLOPT_DOH_SSL_VERIFYHOST`.
    pub(crate) host: bool,
    /// `data->set.doh_verifypeer`, from `CURLOPT_DOH_SSL_VERIFYPEER`.
    pub(crate) peer: bool,
    /// `data->set.doh_verifystatus`, from `CURLOPT_DOH_SSL_VERIFYSTATUS`.
    pub(crate) status: bool,
}

impl Default for DohVerify {
    fn default() -> Self {
        Self {
            host: true,
            peer: true,
            status: true,
        }
    }
}

impl DohVerify {
    /// The `CURLOPT_SSL_VERIFYHOST` value: `2` or `0`. **Never `1`.**
    #[allow(dead_code)]
    pub(crate) const fn verify_host_value(self) -> i64 {
        if self.host {
            2
        } else {
            0
        }
    }

    /// The `CURLOPT_SSL_VERIFYPEER` value: `1` or `0`.
    #[allow(dead_code)]
    pub(crate) const fn verify_peer_value(self) -> i64 {
        if self.peer {
            1
        } else {
            0
        }
    }

    /// The `CURLOPT_SSL_VERIFYSTATUS` value: `1` or `0`.
    #[allow(dead_code)]
    pub(crate) const fn verify_status_value(self) -> i64 {
        if self.status {
            1
        } else {
            0
        }
    }
}

/// TLS material a DoH probe inherits from the user's transfer.
///
/// Supersedes `lib/doh.c:362-401`, whose own comment is the specification and
/// is reproduced because it is also the caveat:
///
/// > Inherit *some* SSL options from the user's transfer. This is a best-guess
/// > as to which options are needed for compatibility. #3661
/// >
/// > Note DoH does not inherit the user's proxy server so proxy SSL settings
/// > have no effect and are not inherited. If that changes then two new options
/// > should be added to check doh proxy insecure separately,
/// > CURLOPT_DOH_PROXY_SSL_VERIFYHOST and CURLOPT_DOH_PROXY_SSL_VERIFYPEER.
///
/// **Every field is applied only when set**, exactly as each C line is guarded
/// by its own `if(...)`. That conditionality is the behaviour: setting
/// `CURLOPT_CAINFO` to an unset value is not the same as not setting it,
/// because the option's own default differs from the empty string. [`Option`]
/// carries the distinction; a `String` would lose it.
///
/// Two of C's pairs are **callbacks** and cannot be represented here:
/// `CURLOPT_SSL_CTX_FUNCTION`/`_DATA` (`:387-390`) and
/// `CURLOPT_DEBUGFUNCTION`/`_DATA` (`:391-394`) are function pointers whose
/// types live at the C boundary that `curl-rs-ffi` owns. What this file must
/// record about them is not their value but the *decision* -- "inherit, and
/// only when set" -- so each is a presence flag, and the transport that holds
/// the real callback consults it.
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct DohTlsSettings {
    /// `data->set.ssl.custom_cafile`, copied directly at `:370` rather than
    /// through `curl_easy_setopt`.
    pub(crate) custom_cafile: bool,
    /// `data->set.ssl.custom_capath`, copied at `:371`.
    pub(crate) custom_capath: bool,
    /// `data->set.ssl.custom_cablob`, copied at `:372`.
    pub(crate) custom_cablob: bool,
    /// `CURLOPT_CAINFO` from `data->set.str[STRING_SSL_CAFILE]` (`:373-375`).
    pub(crate) cainfo: Option<String>,
    /// `CURLOPT_CAINFO_BLOB` from `data->set.blobs[BLOB_CAINFO]` (`:376-378`).
    pub(crate) cainfo_blob: Option<Vec<u8>>,
    /// `CURLOPT_CAPATH` from `data->set.str[STRING_SSL_CAPATH]` (`:379-381`).
    pub(crate) capath: Option<String>,
    /// `CURLOPT_CRLFILE` from `data->set.str[STRING_SSL_CRLFILE]` (`:382-384`).
    pub(crate) crlfile: Option<String>,
    /// `CURLOPT_CERTINFO` from `data->set.ssl.certinfo` (`:385-386`).
    pub(crate) certinfo: bool,
    /// Whether `CURLOPT_SSL_CTX_FUNCTION` is inherited (`:387-388`). The
    /// callback itself belongs to the C boundary; see this struct's docs.
    pub(crate) ssl_ctx_callback: bool,
    /// Whether `CURLOPT_SSL_CTX_DATA` is inherited (`:389-390`).
    pub(crate) ssl_ctx_data: bool,
    /// Whether `CURLOPT_DEBUGFUNCTION` is inherited (`:391-392`).
    pub(crate) debug_callback: bool,
    /// Whether `CURLOPT_DEBUGDATA` is inherited (`:393-394`).
    pub(crate) debug_data: bool,
    /// `CURLOPT_SSL_EC_CURVES` from `data->set.str[STRING_SSL_EC_CURVES]`
    /// (`:395-398`).
    pub(crate) ec_curves: Option<String>,
    /// `CURLOPT_SSL_OPTIONS` from `data->set.ssl.primary.ssl_options`
    /// (`:400-401`).
    ///
    /// **Applied unconditionally**, and through a bare `curl_easy_setopt` whose
    /// result C explicitly discards with `(void)`. The other fourteen go
    /// through `ERROR_CHECK_SETOPT`, which aborts the probe on failure; this
    /// one cannot fail the probe. The asymmetry is C's and is preserved by the
    /// field not being an [`Option`].
    pub(crate) ssl_options: i64,
}

/// Presence and lengths, never a trust-material path or blob.
///
/// The three `Option<String>` paths -- `cainfo`, `capath`, `crlfile` -- and the
/// `cainfo_blob` bytes describe where this process's trust anchors live and
/// what they are. A path discloses a filesystem layout and, for a
/// per-tenant deployment, often a tenant identity; a CA blob is the anchor
/// itself. Neither belongs in a log, and neither is needed there: what a reader
/// debugging a DoH trust failure needs is whether a custom anchor was supplied
/// at all, which is what a presence flag and a length say.
///
/// The booleans and `ssl_options` render in full: they are the policy, they are
/// what `doh_probe_run` (`lib/doh.c:362-401`) copies, and none of them is a
/// secret.
impl fmt::Debug for DohTlsSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DohTlsSettings")
            .field("custom_cafile", &self.custom_cafile)
            .field("custom_capath", &self.custom_capath)
            .field("custom_cablob", &self.custom_cablob)
            .field("cainfo", &self.cainfo.as_deref().map(str::len))
            .field("cainfo_blob", &self.cainfo_blob.as_deref().map(Redacted))
            .field("capath", &self.capath.as_deref().map(str::len))
            .field("crlfile", &self.crlfile.as_deref().map(str::len))
            .field("certinfo", &self.certinfo)
            .field("ssl_ctx_callback", &self.ssl_ctx_callback)
            .field("ssl_ctx_data", &self.ssl_ctx_data)
            .field("debug_callback", &self.debug_callback)
            .field("debug_data", &self.debug_data)
            .field("ec_curves", &self.ec_curves.as_deref().map(str::len))
            .field("ssl_options", &self.ssl_options)
            .finish()
    }
}

/// Everything a DoH probe needs from the user's transfer.
///
/// The inputs of `doh_probe_run` that come from `data`, gathered so that the
/// probe builder has one argument instead of a dozen. Nothing here is computed;
/// [`DohProbeRequest::build`] is what turns these into a request.
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct DohSettings {
    /// `data->set.str[STRING_DOH]` -- `CURLOPT_DOH_URL`, from `--doh-url`.
    pub(crate) url: String,
    /// The three DoH-specific verification switches.
    pub(crate) verify: DohVerify,
    /// The inherited TLS material.
    pub(crate) tls: DohTlsSettings,
    /// `CURLOPT_VERBOSE`, set only when
    /// `Curl_trc_ft_is_verbose(data, &Curl_trc_feat_dns)` (`:350-351`) -- so
    /// a probe is verbose exactly when the DNS trace feature is, not whenever
    /// the parent transfer is.
    pub(crate) verbose: bool,
    /// `CURLOPT_NOSIGNAL`, set only when `data->set.no_signal` (`:352-353`).
    ///
    /// Carried for fidelity. There is no signal to suppress in this
    /// implementation -- `crate::dns::resolver` records the same deletion for
    /// the same reason -- but the option is part of the request shape and a
    /// transport may still forward it.
    pub(crate) no_signal: bool,
    /// Whether `CURLOPT_STDERR` is inherited, which C does only when
    /// `data->set.err && data->set.err != stderr` (`:348-349`): a handle
    /// already writing to the real stderr needs no redirection.
    pub(crate) redirect_stderr: bool,
}

/// The endpoint is redacted; the policy is not.
///
/// `CURLOPT_DOH_URL` is a full URL and may carry userinfo -- a private DoH
/// resolver commonly authenticates by embedding a token in the authority or
/// the path, which is why `docs/cmdline-opts/doh-url.md` describes it as an
/// ordinary URL. `crate::url::Url` redacts userinfo for the same reason, so
/// rendering this as a plain string would have reinstated the disclosure. It
/// renders as a byte count.
///
/// Everything else -- the verification triple, the inherited TLS settings
/// (themselves redacted), and the three inherited flags -- renders in full,
/// because those are the policy a reader is checking and none is a secret.
impl fmt::Debug for DohSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DohSettings")
            .field("url", &Redacted(self.url.as_bytes()))
            .field("verify", &self.verify)
            .field("tls", &self.tls)
            .field("verbose", &self.verbose)
            .field("no_signal", &self.no_signal)
            .field("redirect_stderr", &self.redirect_stderr)
            .finish()
    }
}

/// One fully-specified DoH request, ready for a transport.
///
/// The successor of everything `doh_probe_run` (`lib/doh.c:278-428`)
/// configures, as data rather than as twenty-five side effects on a handle. Two
/// things follow from that change of shape, and both are the point:
///
/// * **The shape is assertable.** A test can compare the whole request against
///   a literal, which is what pins the frozen parts -- the method, the single
///   header, the raw body, the `2`-not-`1` verification value.
/// * **The shape is complete.** [`DohTransport`]'s `post` carries only a URL
///   and a query, so a transport reached through it sees the two fields that
///   decide the bytes on the wire; one that wants the rest implements
///   [`DohProbeTransport`] and receives this. Neither has to re-derive
///   anything.
///
/// # What has no field here
///
/// `CURLOPT_WRITEFUNCTION` and `CURLOPT_WRITEDATA` (`:330-331`) are the
/// response accumulator, and a transport that returns bytes needs no callback
/// to be pushed them. `doh->master_mid` (`:404`) correlates a completion with
/// its parent and has nothing to correlate. Both are in the module preamble's
/// deletion table.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DohProbeRequest {
    /// `CURLOPT_URL` (`:328`) -- the DoH endpoint, not the name being resolved.
    pub(crate) url: String,
    /// `CURLOPT_POSTFIELDS` (`:332`) -- the DNS wire query, **raw binary**.
    ///
    /// This is the POST form of RFC 8484 section 4.1 and never the
    /// GET-plus-`?dns=` form: there is no base64url encoding anywhere in
    /// `lib/doh.c`, and adding one would change every byte on the wire.
    pub(crate) body: Vec<u8>,
    /// `CURLOPT_HTTPHEADER` (`:313-314`, `:334`) -- exactly one entry.
    ///
    /// A [`Vec`] rather than a single [`String`] because C's `curl_slist` is a
    /// list and a transport applies it as one. That it holds exactly one
    /// element is asserted by
    /// [`tests::the_probe_request_carries_exactly_the_one_frozen_header`].
    pub(crate) headers: Vec<String>,
    /// `CURLOPT_PROTOCOLS` (`:339-345`).
    pub(crate) protocols: DohProtocols,
    /// `CURLOPT_HTTP_VERSION` (`:336`), present only with the `http2` feature.
    pub(crate) http_version: Option<DohHttpVersion>,
    /// `CURLOPT_PIPEWAIT` (`:337`), set only alongside
    /// [`Self::http_version`].
    pub(crate) pipewait: bool,
    /// `CURLOPT_TIMEOUT_MS` (`:346`) -- the parent transfer's remaining time.
    ///
    /// Always non-negative: a negative reading means the deadline has already
    /// passed and [`Self::build`] refuses before reaching this field.
    pub(crate) timeout_ms: TimeDiff,
    /// Which record this probe asks for. C keeps it in the sub-handle's
    /// `struct doh_request` so that `doh_probe_done` can label the response
    /// (`lib/doh.h:89`); here it labels the response directly.
    pub(crate) dnstype: DnsType,
    /// The DoH-specific verification switches (`:355-360`).
    pub(crate) verify: DohVerify,
    /// The inherited TLS material (`:362-401`).
    pub(crate) tls: DohTlsSettings,
    /// `CURLOPT_VERBOSE` (`:350-351`).
    pub(crate) verbose: bool,
    /// `CURLOPT_NOSIGNAL` (`:352-353`).
    pub(crate) no_signal: bool,
    /// Whether `CURLOPT_STDERR` is inherited (`:348-349`).
    pub(crate) redirect_stderr: bool,
}

/// The endpoint and the query are redacted; the request shape is not.
///
/// # Why the raw query is a privacy matter and not merely a secret
///
/// [`Self::body`] is a DNS wire query, and its QNAME is **the hostname the
/// user is resolving**. The entire purpose of DNS-over-HTTPS is to stop that
/// name being observable (RFC 8484 section 1), so writing it into a log defeats
/// the feature the caller opted into. It renders as a byte count.
///
/// [`Self::url`] and [`Self::headers`] are redacted for the reason
/// [`DohSettings`] records: a private endpoint's credential lives in the URL,
/// and the single header is the `Content-Type` the C freezes, whose value is
/// uninteresting but whose slot is a place a future change could put a token.
///
/// Everything that decides the request's SHAPE renders in full -- the protocol
/// restriction, the HTTP version, `pipewait`, the timeout, the record type, the
/// verification triple and the inherited flags -- because that is what a test
/// or a reader is comparing against `lib/doh.c:290-401`, and none of it is
/// sensitive.
impl fmt::Debug for DohProbeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DohProbeRequest")
            .field("url", &Redacted(self.url.as_bytes()))
            .field("body", &Redacted(&self.body))
            .field("headers", &self.headers.len())
            .field("protocols", &self.protocols)
            .field("http_version", &self.http_version)
            .field("pipewait", &self.pipewait)
            .field("timeout_ms", &self.timeout_ms)
            .field("dnstype", &self.dnstype)
            .field("verify", &self.verify)
            .field("tls", &self.tls)
            .field("verbose", &self.verbose)
            .field("no_signal", &self.no_signal)
            .field("redirect_stderr", &self.redirect_stderr)
            .finish()
    }
}

impl DohProbeRequest {
    /// The HTTP method, which is always `POST`.
    ///
    /// C expresses it by setting `CURLOPT_POSTFIELDS` (`:332`), which makes the
    /// request a POST as a side effect. Named here so that a test can assert it
    /// and a transport need not infer it from the presence of a body.
    #[allow(dead_code)]
    pub(crate) const METHOD: &'static str = "POST";

    /// `CURLOPT_DEFAULT_PROTOCOL` (`:329`) -- the scheme assumed for a DoH URL
    /// written without one.
    #[allow(dead_code)]
    pub(crate) const DEFAULT_PROTOCOL: &'static str = msg::DEFAULT_PROTOCOL;

    /// True for every DoH probe: C's `doh->state.internal = TRUE` (`:403`).
    ///
    /// The flag keeps the sub-handle out of user-facing accounting. C's related
    /// invariant is at `:411-415`:
    ///
    /// > DoH handles must not inherit private_data. The handles may be passed to
    /// > the user via callbacks and the user will be able to identify them as
    /// > internal handles because private data is not set.
    #[allow(dead_code)]
    pub(crate) const INTERNAL: bool = true;

    /// `CURLOPT_POSTFIELDSIZE` (`:333`) -- the body length C passes separately.
    #[allow(dead_code)]
    pub(crate) fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Builds the request for one probe.
    ///
    /// Supersedes the option block of `doh_probe_run` (`lib/doh.c:290-401`), in
    /// C's own order, which matters for the two early returns:
    ///
    /// 1. Encode the query (`:298-305`). On failure, `failf` the message and
    ///    return **[`CURLcode::OutOfMemory`]**.
    /// 2. Read the remaining time (`:307-311`). If negative, return
    ///    [`CURLcode::OperationTimedout`] -- **before** the header list is
    ///    built and before any handle exists, so no request is issued.
    /// 3. Everything else, none of which can fail here.
    ///
    /// # The `CURLE_OUT_OF_MEMORY` mapping is preserved, not corrected
    ///
    /// ```c
    /// d = doh_req_encode(host, dnstype, doh_req->req_body, ...);
    /// if(d) {
    ///   failf(data, "Failed to encode DoH packet [%d]", d);
    ///   result = CURLE_OUT_OF_MEMORY;
    ///   goto error;
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`] for a query that cannot be encoded, or
    /// [`CURLcode::OperationTimedout`] for a deadline that has already passed.
    pub(crate) fn build(
        query_name: &str,
        dnstype: DnsType,
        timeout_ms: TimeDiff,
        settings: &DohSettings,
        tracer: &mut Tracer<'_>,
    ) -> CodeResult<Self> {
        // Step 1. C's buffer is `unsigned char req_body[DOH_MAX_DNSREQ_SIZE]`
        // inside the heap-allocated `struct doh_request`; here it is a local
        // array of the same size, trimmed to the encoded length afterwards.
        let mut buffer = [0u8; DOH_MAX_DNSREQ_SIZE];
        let body = match req_encode(query_name, dnstype, &mut buffer) {
            Ok(len) => buffer.get(..len).unwrap_or_default().to_vec(),
            Err(code) => {
                // `failf(data, "Failed to encode DoH packet [%d]", d);`
                failf!(tracer, "{}", msg::failed_to_encode(code as i32));
                // `result = CURLE_OUT_OF_MEMORY;` -- see the note above.
                return Err(CURLcode::OutOfMemory);
            }
        };

        // Step 2. `timeout_ms = Curl_timeleft_ms(data); if(timeout_ms < 0)
        // { result = CURLE_OPERATION_TIMEDOUT; goto error; }`.
        if timeout_ms < 0 {
            return Err(CURLcode::OperationTimedout);
        }

        // Step 3. `#ifdef USE_HTTP2` -- the one feature consulted here.
        let http_version = if cfg!(feature = "http2") {
            Some(DohHttpVersion::Http2Tls)
        } else {
            None
        };

        Ok(Self {
            url: settings.url.clone(),
            body,
            // `curl_slist_append(NULL, "Content-Type: application/dns-message")`
            headers: vec![msg::CONTENT_TYPE_DNS_MESSAGE.to_owned()],
            protocols: DohProtocols::for_this_build(),
            // `CURLOPT_PIPEWAIT, 1L` sits inside the same `#ifdef` as the
            // version hint, so the two are set together or not at all.
            pipewait: http_version.is_some(),
            http_version,
            timeout_ms,
            dnstype,
            verify: settings.verify,
            tls: settings.tls.clone(),
            verbose: settings.verbose,
            no_signal: settings.no_signal,
            redirect_stderr: settings.redirect_stderr,
        })
    }

    /// The deadline as a [`Duration`](core::time::Duration), or [`None`] for no
    /// deadline.
    #[allow(dead_code)]
    pub(crate) fn timeout(&self) -> Option<core::time::Duration> {
        mstotv(self.timeout_ms)
    }
}

/// The DoH transport seam, carrying the whole request rather than two fields.
///
/// A production transport in `crate::protocols` therefore has a choice:
///
/// * implement this trait directly and receive everything, including the
///   verification triple, the trust material and the protocol restriction; or
/// * implement [`DohTransport`] and be wrapped in [`NarrowDohTransport`], which
///   forwards the URL and the query and **refuses, rather than silently
///   dropping, a request carrying policy those two fields cannot express.**
///
/// # There is no blanket implementation, deliberately
///
/// There was: `impl<T: DohTransport + ?Sized> DohProbeTransport for T` forwarded
/// `url` and `body` and discarded the other eleven fields, on the argument that
/// a narrow transport "is being trusted to apply curl's own defaults". The
/// argument does not survive contact with the fields it was dropping.
/// [`DohProbeRequest::verify`] and [`DohProbeRequest::tls`] are not defaults to
/// be re-derived -- they are the caller's `CURLOPT_DOH_SSL_VERIFYPEER`,
/// `CURLOPT_DOH_SSL_VERIFYHOST`, `CURLOPT_DOH_SSL_VERIFYSTATUS` and the CA
/// file, path, blob and client certificate that go with them. A request built
/// to verify a private DoH resolver against a pinned CA would have executed
/// against the transport's own trust store instead, with nothing anywhere
/// reporting the substitution.
///
/// Being implicit was the whole defect: a coherent-looking `impl DohTransport`
/// silently became the strictest-looking `DohProbeTransport`. Requiring the
/// wrapper to be named makes the narrowing a decision somebody wrote down, and
/// makes it checkable -- see [`NarrowDohTransport::unconveyable`].
pub(crate) trait DohProbeTransport: fmt::Debug + Send + Sync {
    /// Issues one DoH request and returns the response body.
    ///
    /// # Errors
    ///
    /// Whatever the transfer produced. [`is_resolved`] is what turns a failed
    /// transfer into the [`CURLcode::CouldntResolveHost`] a caller asked for,
    /// so an implementation reports the real code and does not pre-empt that
    /// decision.
    fn probe<'a>(
        &'a self,
        request: &'a DohProbeRequest,
    ) -> ResolveFuture<'a, Vec<u8>>;
}

/// Adapts a narrow [`DohTransport`] to the full seam, **fail-closed**.
///
/// Named rather than blanket, and that is the point: wrapping a transport that
/// only carries bytes is a decision to forgo everything else the request says,
/// so it has to be written at the call site instead of applying itself by
/// coherence.
///
/// The wrapper does not merely document the loss, it refuses it.
/// [`Self::unconveyable`] enumerates every field the two forwarded arguments
/// cannot express, and [`Self::probe`] returns
/// [`CURLcode::SslConnectError`] rather than issuing a request under a weaker
/// policy than the caller asked for. A transport that needs the whole request
/// implements [`DohProbeTransport`] directly; a transport that genuinely only
/// carries bytes may be wrapped, and will then be told when the request has
/// outgrown it.
#[derive(Debug)]
#[allow(dead_code)] // The production transport lands with crate::protocols.
pub(crate) struct NarrowDohTransport<T: ?Sized>(
    /// The byte-carrying transport being adapted.
    pub(crate) T,
);

#[allow(dead_code)]
impl<T: DohTransport + ?Sized> NarrowDohTransport<T> {
    /// The first field this request carries that the narrow seam cannot convey,
    /// or [`None`] when the request is fully expressible as a URL and a body.
    ///
    /// Split out as a pure function over the request so the policy is testable
    /// without a transport, a runtime or a network -- the same reason
    /// `crate::tls::keylog` splits its own verdict out.
    ///
    /// The order is severity, not declaration: the trust material and the
    /// verification triple come first, because those are the two whose loss
    /// changes who the resolver is allowed to be. It has no effect on whether a
    /// request is accepted.
    ///
    /// `headers` is compared against the single header
    /// [`DohProbeRequest::build`] always sets, `Content-Type:
    /// application/dns-message`. That one IS conveyable, because
    /// [`DohTransport::post`]'s contract is to send it -- its own documentation
    /// says the seam "POSTs it with `Content-Type: application/dns-message`".
    /// Any other header is not.
    ///
    /// `dnstype` is absent from the list on purpose: it is already encoded in
    /// the query bytes, so forwarding the body forwards it.
    fn unconveyable(request: &DohProbeRequest) -> Option<&'static str> {
        if request.tls != DohTlsSettings::default() {
            // A CA file, path or blob, a client certificate, a CRL, a curve
            // list, an SSL_CTX callback or a debug callback. All of these decide
            // which resolver is trusted, and none reaches a `post(url, body)`.
            return Some("CURLOPT_DOH_SSL trust material");
        }
        if request.verify != DohVerify::default() {
            // `--doh-insecure` and its two siblings. Note the direction: this
            // refuses a request that has RELAXED verification just as firmly as
            // one that has tightened it, because a narrow transport applying its
            // own defaults would silently re-tighten it, and a caller who asked
            // for `--doh-insecure` and got a hard failure is better served than
            // one who asked and was quietly overruled.
            return Some("CURLOPT_DOH_SSL_VERIFY* policy");
        }
        if request.protocols != DohProtocols::for_this_build() {
            return Some("a CURLOPT_PROTOCOLS_STR restriction");
        }
        if request.timeout_ms != 0 {
            return Some("a resolve timeout");
        }
        if request.headers.as_slice()
            != [msg::CONTENT_TYPE_DNS_MESSAGE.to_owned()]
        {
            return Some("request headers beyond the DNS content type");
        }
        // `http_version` and `pipewait` are deliberately NOT checked. Neither is
        // caller policy: `Self::build` derives `http_version` from
        // `cfg!(feature = "http2")` and sets `pipewait` from whether that
        // produced a value, mirroring the single `#ifdef USE_HTTP2` block in
        // `lib/doh.c` that sets `CURLOPT_HTTP_VERSION` and `CURLOPT_PIPEWAIT`
        // together. They describe the build, and a narrow transport applying
        // curl's own defaults arrives at the same pair. Refusing them would
        // reject every request on an HTTP/2 build, which is the whole corpus.
        None
    }
}

impl<T: DohTransport + ?Sized> DohProbeTransport for NarrowDohTransport<T> {
    /// Forwards the URL and the query, or refuses the request.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SslConnectError`] when [`Self::unconveyable`] names a field.
    /// That code rather than `CURLcode::NotBuiltIn` or
    /// `CURLcode::BadFunctionArgument` because the condition is a TLS policy
    /// that could not be honoured, and `lib/doh.c`'s caller turns a failed probe
    /// into `CURLE_COULDNT_RESOLVE_HOST` through [`is_resolved`] anyway -- so
    /// the resolve fails, as it must, and the specific code survives in a trace
    /// for whoever has to work out why.
    fn probe<'a>(
        &'a self,
        request: &'a DohProbeRequest,
    ) -> ResolveFuture<'a, Vec<u8>> {
        if Self::unconveyable(request).is_some() {
            // Fail closed. The alternative -- issuing the request with the
            // transport's own policy -- is the defect this type exists to
            // prevent, and it is silent, which is what made it dangerous.
            return Box::pin(async { Err(CURLcode::SslConnectError) });
        }
        self.0.post(&request.url, &request.body)
    }
}

// `struct doh_response` and `struct doh_probes` -- `lib/doh.h:92-106`.

/// One probe's outcome.
///
/// Supersedes `struct doh_response` (`lib/doh.h:92-97`):
///
/// ```c
/// struct doh_response {
///   uint32_t probe_mid;
///   struct dynbuf body;
///   DNStype dnstype;
///   CURLcode result;
/// };
/// ```
///
/// `probe_mid` becomes [`Self::started`], and the substitution is exact rather
/// than approximate. C uses the field as a tri-state: `UINT32_MAX` means "not
/// started" both before `doh_probe_run` succeeds (`lib/doh.c:462`) and after
/// `Curl_doh_close` tears the handle down (`:1308`), and any other value is a
/// live multi-handle identifier. The identifier itself is only ever used to
/// *find* the handle, which nothing here needs to do, so what survives is the
/// one bit the reader actually consults -- and it is consulted, at
/// `:1209-1210`, to decide whether to report failure at all.
///
/// # `dnstype` is `Option`, and the `None` is load-bearing
///
/// C's `dnstype` starts at zero from `calloc` and is written **only when the
/// probe completes with no error** (`:237-238`). So a zero means "this slot has
/// no usable body", whether because it never ran or because its transfer
/// failed, and `:1229`'s `if(!p->dnstype) continue;` skips both. [`None`] is
/// that zero, and [`DnsType`] deliberately has no zero variant so the state
/// cannot be confused with a record type.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct DohResponse {
    /// Whether this probe was issued at all -- C's `probe_mid != UINT32_MAX`.
    pub(crate) started: bool,
    /// The record type whose answer [`Self::body`] holds, or [`None`] when
    /// there is no usable answer. See this struct's documentation.
    pub(crate) dnstype: Option<DnsType>,
    /// C's `body`, the accumulated response.
    ///
    /// A [`Vec`] rather than a [`DynBuf`] because the ceiling that made it a
    /// `dynbuf` is applied while filling it -- see [`accumulate_body`] -- and
    /// keeping the buffer afterwards would carry a cap that no longer has
    /// anything to cap.
    pub(crate) body: Vec<u8>,
    /// C's `result`, the transfer's own code.
    pub(crate) result: CodeResult<()>,
}

/// The answer body is redacted; the outcome is not.
///
/// A DoH response body carries the resolved addresses for the name that
/// [`DohProbeRequest::body`] asked about, so it discloses the same private
/// resolution the query does and is redacted for the same reason (RFC 8484
/// section 1). `started`, `dnstype` and `result` are the outcome, which is what
/// a reader of a resolution failure needs and what `lib/doh.c:1209-1214`
/// branches on.
impl fmt::Debug for DohResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DohResponse")
            .field("started", &self.started)
            .field("dnstype", &self.dnstype)
            .field("body", &Redacted(&self.body))
            .field("result", &self.result)
            .finish()
    }
}

impl Default for DohResponse {
    /// The `calloc` state of `struct doh_response`, plus C's explicit
    /// `probe_mid = UINT32_MAX` and `curlx_dyn_init(&body, DYN_DOH_RESPONSE)`
    /// (`lib/doh.c:461-464`).
    fn default() -> Self {
        Self {
            started: false,
            dnstype: None,
            body: Vec::new(),
            result: Ok(()),
        }
    }
}

/// Every probe of one DoH resolution.
///
/// Supersedes `struct doh_probes` (`lib/doh.h:101-106`):
///
/// ```c
/// struct doh_probes {
///   struct doh_response probe_resp[DOH_SLOT_COUNT];
///   unsigned int pending; /* still outstanding probes */
///   int port;
///   const char *host;
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DohProbes {
    /// C's `host`.
    pub(crate) host: String,
    /// C's `port`, narrowed from `int` to the range a port occupies.
    pub(crate) port: u16,
    /// C's `probe_resp[DOH_SLOT_COUNT]`, indexed by [`DohSlot::index`].
    pub(crate) responses: [DohResponse; SLOT_COUNT],
}

impl DohProbes {
    /// A fresh set for `host` and `port`, with no probe started.
    fn new(host: &str, port: u16) -> Self {
        Self {
            host: host.to_owned(),
            port,
            responses: [
                DohResponse::default(),
                DohResponse::default(),
                DohResponse::default(),
            ],
        }
    }

    /// One slot's outcome.
    pub(crate) fn response(&self, slot: DohSlot) -> &DohResponse {
        let [ipv4, ipv6, https_rr] = &self.responses;
        match slot {
            DohSlot::Ipv4 => ipv4,
            DohSlot::Ipv6 => ipv6,
            DohSlot::HttpsRr => https_rr,
        }
    }

    /// One slot's outcome, mutably. Total, as [`Self::response`] explains.
    fn response_mut(&mut self, slot: DohSlot) -> &mut DohResponse {
        let [ipv4, ipv6, https_rr] = &mut self.responses;
        match slot {
            DohSlot::Ipv4 => ipv4,
            DohSlot::Ipv6 => ipv6,
            DohSlot::HttpsRr => https_rr,
        }
    }
}

// `Curl_doh` -- `lib/doh.c:435-519`.

/// What one DoH resolution is being asked for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DohQuery<'a> {
    /// C's `hostname`. Already in wire form: `Curl_resolv` has applied
    /// `Curl_idnconvert_hostname` before reaching DoH, which is why
    /// [`req_encode`] performs no conversion of its own.
    pub(crate) host: &'a str,
    /// C's `port`, narrowed from `int`. Decides the HTTPS-RR query name; see
    /// [`https_rr_qname`].
    pub(crate) port: u16,
    /// C's `ip_version`, from `CURLOPT_IPRESOLVE`.
    pub(crate) ip_version: IpVersion,
    /// `Curl_ipv6works(data)` (`:483`), evaluated by the caller.
    ///
    /// Passed in rather than probed here because probing opens a socket, and
    /// `crate::dns` already owns that seam as
    /// [`Ipv6Probe`](crate::dns::Ipv6Probe) -- reproducing it would put a
    /// syscall in a module that must run under Miri.
    pub(crate) ipv6_works: bool,
    /// `conn->scheme->protocol & PROTO_FAMILY_HTTP` (`:496`), evaluated by the
    /// caller because `conn` belongs to `crate::conn`, which this file must not
    /// name.
    pub(crate) http_family: bool,
    /// `Curl_timeleft_ms(data)` (`:307`) -- the parent transfer's remaining
    /// time, in milliseconds, where **negative means already expired**.
    pub(crate) timeout_ms: TimeDiff,
}

/// Runs every applicable DoH probe and collects their responses.
///
/// # Which probes fire
///
/// | Probe | C | Condition |
/// |---|---|---|
/// | [`DnsType::A`] | `:473-480` | **unconditional** |
/// | [`DnsType::Aaaa`] | `:482-493` | `ip_version != V4 && ipv6_works` |
/// | [`DnsType::Https`] | `:495-513` | `http_family` |
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`] for a query that cannot be encoded, or
/// [`CURLcode::OperationTimedout`] for a deadline that has already passed.
/// Both come from [`DohProbeRequest::build`], and both are reported before any
/// request is issued.
pub(crate) async fn doh<T>(
    transport: &T,
    query: &DohQuery<'_>,
    settings: &DohSettings,
    tracer: &mut Tracer<'_>,
) -> CodeResult<DohProbes>
where
    T: DohProbeTransport + ?Sized,
{
    // `data->state.async.hostname = curlx_strdup(hostname);` (`:452`) and
    // `dohp->host = ...; dohp->port = ...;` (`:467-468`).
    let mut probes = DohProbes::new(query.host, query.port);

    // The three `doh_probe_run` calls, built first so that a build failure is
    // reported before any of them is issued -- C's ordering, where each `goto
    // error` precedes the next `doh_probe_run`.
    let mut planned: Vec<(DohSlot, DohProbeRequest)> = Vec::new();

    // `/* create IPv4 DoH request */` -- unconditional.
    planned.push((
        DohSlot::Ipv4,
        DohProbeRequest::build(
            query.host,
            DnsType::A,
            query.timeout_ms,
            settings,
            tracer,
        )?,
    ));

    // `#ifdef USE_IPV6` plus
    // `if((ip_version != CURL_IPRESOLVE_V4) && Curl_ipv6works(data))`.
    if query.ip_version != IpVersion::V4 && query.ipv6_works {
        planned.push((
            DohSlot::Ipv6,
            DohProbeRequest::build(
                query.host,
                DnsType::Aaaa,
                query.timeout_ms,
                settings,
                tracer,
            )?,
        ));
    }

    // `if(conn->scheme->protocol & PROTO_FAMILY_HTTP)` --
    // "Only use HTTPS RR for HTTP(S) transfers".
    if query.http_family {
        let qname = https_rr_qname(query.host, query.port);
        planned.push((
            DohSlot::HttpsRr,
            DohProbeRequest::build(
                &qname,
                DnsType::Https,
                query.timeout_ms,
                settings,
                tracer,
            )?,
        ));
    }

    // Every planned probe was accepted, so every one is started. C sets
    // `probe_mid` on success and increments `pending`; the flag is the former
    // and there is nothing to count.
    for (slot, _) in &planned {
        probes.response_mut(*slot).started = true;
    }

    // The probes run CONCURRENTLY, as C's several handles on one multi handle
    // do. `join_all` is the direct expression of that and preserves the order
    // of its inputs in its output, which is what keeps a response with its
    // slot.
    let issued = futures::future::join_all(
        planned.iter().map(|(_, request)| transport.probe(request)),
    )
    .await;

    // `doh_probe_done` (`:212-255`), minus the slot search and the countdown:
    // the outcome already knows which slot it belongs to.
    //
    // The statement order below is C's, and which side of it the response
    // ceiling falls on is load-bearing. C runs:
    //
    // ```c
    // dohp->probe_resp[i].result = result;                     /* :232 */
    // if(doh_req) {
    //   if(!result) {                                          /* :237 */
    //     dohp->probe_resp[i].dnstype = doh_req->dnstype;      /* :238 */
    //     result = curlx_dyn_addn(&dohp->probe_resp[i].body,   /* :239 */
    //                             curlx_dyn_ptr(&doh_req->resp_body), ...);
    //   }
    // }
    // if(result)                                               /* :247 */
    //   infof(doh, "DoH request %s", curl_easy_strerror(result));
    // ```
    //
    // # There are two `DYN_DOH_RESPONSE` buffers, and only one ceiling bites
    //
    // C initialises the sub-request's accumulator with `DYN_DOH_RESPONSE`
    // (`:296`) *and* each slot's body with the same limit (`:463`). They behave
    // very differently:
    //
    // * The accumulator is filled by `doh_probe_write_cb`, which returns `0`
    //   the moment the append fails (`:178-179`). A short return from a write
    //   callback fails the transfer with `CURLE_WRITE_ERROR`, so **an
    //   over-long response is a transport failure**, discovered before
    //   `doh_probe_done` ever runs. It is therefore part of the `result`
    //   stored at `:232`, which is why [`accumulate_body`] is folded into the
    //   outcome below rather than applied after `dnstype` is set.
    // * The `:239` copy moves that accumulator into the slot. Both buffers
    //   share the 3,000-byte limit and the destination starts empty, so if the
    //   source fit, the copy fits: `dyn_addn` there can only fail on
    //   allocation failure. Rust has no such path -- a `Vec` that cannot grow
    //   aborts rather than returning -- so the `:239` reassignment of `result`
    //   has **no reachable counterpart here**, and the local `result` the
    //   `infof` at `:248` names is always the transport's.
    for ((slot, request), outcome) in planned.iter().zip(issued) {
        let response = probes.response_mut(*slot);

        // The transport's outcome with the write callback's ceiling folded in,
        // because in C the ceiling *is* a transport failure; see above.
        let outcome = outcome.and_then(|body| accumulate_body(&body));

        // `dohp->probe_resp[i].result = result;` (`:232`), unconditional.
        response.result = outcome.as_ref().map(|_| ()).map_err(|code| *code);

        match outcome {
            Ok(stored) => {
                // `if(!result) { dohp->probe_resp[i].dnstype = ...; }`
                // (`:237-238`) -- set ONLY on success, which is what makes a
                // failed probe's slot read as "no usable answer".
                response.dnstype = Some(request.dnstype);
                response.body = stored;
            }
            Err(code) => {
                // `if(result) infof(doh, "DoH request %s",
                //  curl_easy_strerror(result));` (`:247-248`).
                //
                // This is an `infof` on the SUB-handle, and `doh_probe_run`
                // sets `doh->state.feat = &Curl_trc_feat_dns` on it (`:327`),
                // so the line carries the `[DNS]` label. `Tracer::feature` is
                // byte-identical to `Tracer::infof` under that state -- both
                // assemble `Some(Dns)`, and `is_feature_verbose(Dns)` and
                // `is_verbose()` reduce to the same test when the label in
                // force *is* DNS -- which is why the feature emitter is the
                // faithful spelling here.
                trc_feat!(
                    tracer,
                    TraceFeature::Dns,
                    "{}",
                    msg::doh_request(code.message())
                );
            }
        }
    }

    Ok(probes)
}

/// Accepts a response body, applying the ceiling C's write callback applies.
///
/// # Errors
///
/// [`CURLcode::WriteError`], which is what a `0` return from a write callback
/// becomes.
fn accumulate_body(body: &[u8]) -> CodeResult<Vec<u8>> {
    // `curlx_dyn_init(&doh_req->resp_body, DYN_DOH_RESPONSE);` then
    // `if(curlx_dyn_addn(&doh_req->resp_body, contents, realsize)) return 0;`
    let mut accumulator = DynBuf::new(DYN_DOH_RESPONSE);
    accumulator.addn(body).map_err(|_| CURLcode::WriteError)?;
    Ok(accumulator.take())
}

// `doh2ai` -- `lib/doh.c:915-1008`.

/// Turns the stored addresses into the crate's resolved-address list.
///
/// Supersedes `doh2ai` (`lib/doh.c:915-1008`), whose header comment describes
/// what has been removed as much as what remains:
///
/// > This function returns a pointer to the first element of a newly allocated
/// > Curl_addrinfo struct linked list ... The memory allocated by this function
/// > \*MUST\* be free'd later on calling Curl_freeaddrinfo().
///
/// The list, the manual linking through `ai_next`, the single `calloc` holding
/// a `struct Curl_addrinfo` plus a `sockaddr` plus the canonical name, and the
/// paired free are all gone: [`ResolvedAddr`] owns its address and its name,
/// and a [`Vec`] owns the sequence.
///
/// # Three behaviours that are not bookkeeping
///
/// * **`ai_socktype = SOCK_STREAM` for every entry**, with C's own comment
///   *"we return all names as STREAM, so when using this address for TFTP the
///   type must be ignored and conn->socktype be used instead!"*
///   [`ResolvedAddr::tcp`] is exactly that shape.
/// * **`ai_canonname` is the requested hostname**, copied into every entry
///   (`:958`) -- not a name learned from the answer, and not the CNAME target
///   even when one was decoded.
/// * **The order is preserved.** C walks `de->addr[0..numaddr]` and links each
///   to the previous, so the output order is the storage order, which is the
///   order the answers arrived in. `conn/happy_eyeballs.rs` races what this
///   produces, so sorting it would change which address is connected to first.
///
/// # Errors
///
/// [`CURLcode::CouldntResolveHost`] when no address was stored.
pub(crate) fn doh2ai(
    entry: &DohEntry,
    hostname: &str,
    port: u16,
) -> CodeResult<Vec<ResolvedAddr>> {
    // `if(!de->numaddr) return CURLE_COULDNT_RESOLVE_HOST;`
    if entry.addr.is_empty() {
        return Err(CURLcode::CouldntResolveHost);
    }

    // `for(i = 0; i < de->numaddr; i++)`, in order.
    Ok(entry
        .addr
        .iter()
        .map(|address| {
            // `addr->sin_port = htons((unsigned short)port);` -- the byte order
            // is `SocketAddr`'s business, not this function's.
            let socket = SocketAddr::new(address.0, port);
            // `memcpy(ai->ai_canonname, hostname, hostlen);`
            ResolvedAddr::tcp(socket, Some(hostname.to_owned()))
        })
        .collect())
}

// `Curl_doh_is_resolved` -- `lib/doh.c:1199-1295`.

/// What [`is_resolved`] needs beyond the probe results.
#[derive(Debug)]
pub(crate) struct DohResolveContext<'a> {
    /// The cache `Curl_dnscache_add` inserts into (`lib/doh.c:1279`).
    pub(crate) cache: &'a mut DnsCache,
    /// The clock `Curl_dnscache_mk_entry` stamps the entry with, C's
    /// `*Curl_pgrs_now(data)`.
    pub(crate) clock: &'a dyn Clock,
    /// `CONN_IS_PROXIED(data->conn)` (`lib/doh.c:1212`), which selects
    /// [`CURLcode::CouldntResolveProxy`] over
    /// [`CURLcode::CouldntResolveHost`].
    pub(crate) proxied: bool,
}

impl DohResolveContext<'_> {
    /// The code a failed resolution reports.
    ///
    /// `CONN_IS_PROXIED(data->conn) ? CURLE_COULDNT_RESOLVE_PROXY :
    /// CURLE_COULDNT_RESOLVE_HOST` (`lib/doh.c:1212-1213`). Named because the
    /// choice is made at three points in `Curl_doh_is_resolved`'s successor and
    /// must be the same choice at all three.
    const fn failure_code(&self) -> CURLcode {
        if self.proxied {
            CURLcode::CouldntResolveProxy
        } else {
            CURLcode::CouldntResolveHost
        }
    }
}

/// Decodes the probe responses, builds a cache entry and inserts it.
///
/// Supersedes `Curl_doh_is_resolved` (`lib/doh.c:1199-1295`), minus the
/// re-entrancy: C is called repeatedly by the multi state machine and returns
/// `CURLE_OK` with `*dnsp == NULL` while `pending` is non-zero (`:1287-1289`).
///
/// # The order of operations is C's
///
/// 1. **Neither address probe started** (`:1209-1214`) --
///    [`msg::could_not_resolve`] and [`DohResolveContext::failure_code`].
///    Reached before anything is decoded, so a resolution that never got off
///    the ground reports the host rather than a parse error.
/// 2. Decode every slot that has a usable answer, accumulating into one
///    [`DohEntry`] so that the TTL minimum spans all of them (`:1227-1238`). A
///    slot with no answer is skipped by `if(!p->dnstype) continue;`.
/// 3. Trace [`msg::decode_failed`] for each slot that failed to decode.
/// 4. Apply the success test, then [`doh2ai`], then the entry, then the HTTPS
///    record, then the insertion.
///
/// # The success test succeeds when EITHER slot is error-free -- including
/// when neither ran
///
/// ```c
/// DOHcode rc[DOH_SLOT_COUNT];
/// memset(rc, 0, sizeof(rc));
/// ...
/// result = CURLE_COULDNT_RESOLVE_HOST; /* until we know better */
/// if(!rc[DOH_SLOT_IPV4] || !rc[DOH_SLOT_IPV6]) {
/// ```
///
/// Three facts combine into behaviour that is easy to misread:
///
/// * `rc[]` is zeroed, and zero is `DOH_OK`.
/// * A slot is only written when it had an answer to decode.
/// * The test is `||`, not `&&`.
///
/// # Only the FIRST HTTPS record is ever decoded
///
/// ```c
/// if(de.numhttps_rrs > 0 && result == CURLE_OK) {
///   result = doh_resp_decode_httpsrr(data, de.https_rrs->val,
///                                    de.https_rrs->len, &hrr);
/// ```
///
/// # Errors
///
/// [`CURLcode::CouldntResolveHost`] or [`CURLcode::CouldntResolveProxy`] for a
/// resolution that produced no address, or whatever
/// [`resp_decode_httpsrr`] reports for a malformed HTTPS record.
pub(crate) fn is_resolved(
    probes: &DohProbes,
    ctx: &mut DohResolveContext<'_>,
    tracer: &mut Tracer<'_>,
) -> CodeResult<DnsEntryRef> {
    // Step 1. `if(probe_resp[IPV4].probe_mid == UINT32_MAX &&
    //          probe_resp[IPV6].probe_mid == UINT32_MAX)`.
    if !probes.response(DohSlot::Ipv4).started
        && !probes.response(DohSlot::Ipv6).started
    {
        // `failf(data, "Could not DoH-resolve: %s", dohp->host);`
        failf!(tracer, "{}", msg::could_not_resolve(&probes.host));
        return Err(ctx.failure_code());
    }

    // `de_init(&de);` -- one entry for every slot, which is what makes the TTL
    // a minimum across all of them.
    let mut entry = DohEntry::default();
    // `memset(rc, 0, sizeof(rc));` -- zero is `DOH_OK`, and the zero is
    // load-bearing; see this function's documentation.
    let mut rc: [Result<(), DohCode>; SLOT_COUNT] = [Ok(()), Ok(()), Ok(())];

    // `for(slot = 0; slot < DOH_SLOT_COUNT; slot++)`, in slot order.
    for slot in DohSlot::ALL {
        let response = probes.response(slot);
        // `if(!p->dnstype) continue;`
        let Some(dnstype) = response.dnstype else {
            continue;
        };
        let outcome = resp_decode(&response.body, dnstype, &mut entry);
        if let Err(code) = outcome {
            // `CURL_TRC_DNS(data, "DoH: %s type %s for %s", ...)`
            trc_feat!(
                tracer,
                TraceFeature::Dns,
                "{}",
                msg::decode_failed(
                    strerror(code),
                    dnstype.type2name(),
                    &probes.host
                )
            );
        }
        // `rc[slot] = doh_resp_decode(...);`
        if let Some(cell) = rc.get_mut(slot.index()) {
            *cell = outcome;
        }
    }

    // `result = CURLE_COULDNT_RESOLVE_HOST; /* until we know better */` plus
    // `if(!rc[DOH_SLOT_IPV4] || !rc[DOH_SLOT_IPV6])`.
    let ipv4_ok = rc.get(DohSlot::Ipv4.index()).is_some_and(Result::is_ok);
    let ipv6_ok = rc.get(DohSlot::Ipv6.index()).is_some_and(Result::is_ok);
    if !(ipv4_ok || ipv6_ok) {
        return Err(CURLcode::CouldntResolveHost);
    }

    // `if(Curl_trc_ft_is_verbose(data, &Curl_trc_feat_dns)) {
    //    CURL_TRC_DNS(data, "hostname: %s", dohp->host);
    //    doh_show(data, &de); }`
    if tracer.is_feature_verbose(TraceFeature::Dns) {
        trc_feat!(tracer, TraceFeature::Dns, "{}", msg::hostname(&probes.host));
        show(&entry, tracer);
    }

    // `result = doh2ai(&de, dohp->host, dohp->port, &ai);`
    let addrs = doh2ai(&entry, &probes.host, probes.port)?;

    // `dns = Curl_dnscache_mk_entry(data, &ai, dohp->host, 0, dohp->port,
    //                               FALSE);` -- note the FALSE for permanent.
    // Delegated; nothing about entry construction is duplicated here.
    let mut dns = DnsCache::mk_entry(
        &probes.host,
        probes.port,
        addrs,
        false,
        ctx.clock,
        None,
        tracer,
    )?;

    // `if(de.numhttps_rrs > 0 && result == CURLE_OK)` -- and `de.https_rrs->val`
    // is the FIRST record only. See this function's documentation.
    if let Some(first) = entry.https_rrs.first() {
        match resp_decode_httpsrr(&first.val, tracer) {
            Ok(record) => {
                // `infof(data, "Some HTTPS RR to process");`
                infof!(tracer, "{}", msg::SOME_HTTPS_RR_TO_PROCESS);
                // `#if defined(DEBUGBUILD) && defined(CURLVERBOSE)
                //    doh_print_httpsrr(data, hrr); #endif`
                if cfg!(debug_assertions) {
                    print_httpsrr(&record, tracer);
                }
                // `dns->hinfo = hrr;`
                dns.hinfo = Some(Box::new(record));
            }
            Err(code) => {
                // `infof(data, "Failed to decode HTTPS RR");` then
                // `Curl_resolv_unlink(data, &dns); goto error;` -- the entry is
                // dropped rather than unlinked, since it was never inserted.
                infof!(tracer, "{}", msg::FAILED_TO_DECODE_HTTPS_RR);
                return Err(code);
            }
        }
    }

    // `data->state.async.dns = dns; result = Curl_dnscache_add(data, dns);`
    // and `data->state.async.done = TRUE;`. Insertion is the cache's; the
    // "done" flag is the return of a value rather than a field to set.
    Ok(ctx.cache.add(dns))
}

/// Resolves `query` over DoH from end to end.
///
/// # Errors
///
/// Whatever [`doh`] or [`is_resolved`] reports.
// Annotated as the ONE live root of this module, which is what keeps its whole
// call graph -- the encoder, the decoders, the printers and the probe
// orchestration -- out of the dead-code report.
#[allow(dead_code)]
pub(crate) async fn resolve<T>(
    transport: &T,
    query: &DohQuery<'_>,
    settings: &DohSettings,
    ctx: &mut DohResolveContext<'_>,
    tracer: &mut Tracer<'_>,
) -> CodeResult<DnsEntryRef>
where
    T: DohProbeTransport + ?Sized,
{
    let probes = doh(transport, query, settings, tracer).await?;
    is_resolved(&probes, ctx, tracer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::httpsrr::{
        HTTPS_RR_CODE_ALPN, HTTPS_RR_CODE_ECH, HTTPS_RR_CODE_IPV4,
        HTTPS_RR_CODE_IPV6, HTTPS_RR_CODE_MANDATORY, HTTPS_RR_CODE_NO_DEF_ALPN,
        HTTPS_RR_CODE_PORT,
    };
    use crate::trace::{
        ErrorBuffer, TraceConfig, TraceIds, TraceLevel, TraceState, WriterSink,
    };
    use crate::util::timeval::{CurlTime, TestClock};
    use std::sync::Mutex;

    // ---- tracer plumbing, matching `httpsrr.rs`'s own test harness --------

    /// The record a `[DNS]`-labelled trace line produces.
    ///
    /// **Which lines get this bracket is a property of the C source, not of
    /// this harness**, and the two helpers exist to keep the distinction
    /// visible at every assertion. `lib/doh.c` emits on two different handles:
    ///
    /// * `CURL_TRC_DNS(data, ...)` (`:1235`, `:1247`) names the DNS feature
    ///   explicitly, so `"DoH: ..."` and `"hostname: ..."` are bracketed.
    /// * `infof(doh, ...)` (`:231`, `:248`) runs on the DoH **sub**-handle,
    ///   which `doh_probe_run` labels with
    ///   `doh->state.feat = &Curl_trc_feat_dns` (`:327`) -- so `"DoH request
    ///   ..."` is bracketed too.
    fn dns_line(message: &str) -> String {
        format!("* [DNS] {message}\n")
    }

    /// The record an unlabelled trace line produces.
    fn info_line(message: &str) -> String {
        format!("* {message}\n")
    }

    /// Runs `body` against a tracer capturing DNS records, returning them.
    ///
    /// The DNS feature is raised to [`TraceLevel::Info`] explicitly, because
    /// `TraceConfig::new()` starts every feature silent -- which is also what
    /// `--trace-config dns` (or its `doh` alias) does in production.
    fn traced<F, T>(body: F) -> (T, String)
    where
        F: FnOnce(&mut Tracer<'_>) -> T,
    {
        let mut config = TraceConfig::new();
        config.set_feature_level(TraceFeature::Dns, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let value = {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            body(&mut tracer)
        };
        let text = String::from_utf8(sink.into_inner())
            .expect("every trace string in this module is ASCII");
        (value, text)
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

    /// Drives a future to completion on a current-thread runtime.
    fn block_on<F: core::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map(|runtime| runtime.block_on(future))
            .unwrap_or_else(|error| {
                panic!("a current-thread runtime must build: {error}")
            })
    }

    // ---- the injected transport ------------------------------------------

    /// A [`DohProbeTransport`] that answers from a script and records what it
    /// was asked.
    #[derive(Debug)]
    struct MockDohTransport {
        /// One answer per call, in order. An exhausted script is a test bug and
        /// is reported as a transfer failure rather than a panic.
        answers: Mutex<Vec<CodeResult<Vec<u8>>>>,
        /// Every request received, in order.
        seen: Mutex<Vec<DohProbeRequest>>,
    }

    impl MockDohTransport {
        fn new(answers: Vec<CodeResult<Vec<u8>>>) -> Self {
            Self {
                answers: Mutex::new(answers),
                seen: Mutex::new(Vec::new()),
            }
        }

        /// One answer used for every call, however many there are.
        fn always(answer: CodeResult<Vec<u8>>) -> Self {
            Self::new(vec![answer; SLOT_COUNT])
        }

        fn requests(&self) -> Vec<DohProbeRequest> {
            self.seen
                .lock()
                .map(|seen| seen.clone())
                .unwrap_or_default()
        }
    }

    impl DohProbeTransport for MockDohTransport {
        fn probe<'a>(
            &'a self,
            request: &'a DohProbeRequest,
        ) -> ResolveFuture<'a, Vec<u8>> {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push(request.clone());
            }
            let answer = self
                .answers
                .lock()
                .ok()
                .and_then(|mut answers| {
                    if answers.is_empty() {
                        None
                    } else {
                        Some(answers.remove(0))
                    }
                })
                .unwrap_or(Err(CURLcode::CouldntResolveHost));
            Box::pin(async move { answer })
        }
    }

    /// A narrow [`DohTransport`], for exercising the blanket adapter.
    #[derive(Debug)]
    struct BytesTransport {
        answer: Vec<u8>,
        seen: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl DohTransport for BytesTransport {
        fn post<'a>(
            &'a self,
            url: &'a str,
            query: &'a [u8],
        ) -> ResolveFuture<'a, Vec<u8>> {
            if let Ok(mut seen) = self.seen.lock() {
                seen.push((url.to_owned(), query.to_vec()));
            }
            let answer = self.answer.clone();
            Box::pin(async move { Ok(answer) })
        }
    }

    // ---- fixture builders -------------------------------------------------

    /// The DoH settings a test uses unless it needs different ones.
    fn settings() -> DohSettings {
        DohSettings {
            url: "https://doh.example/dns-query".to_owned(),
            ..DohSettings::default()
        }
    }

    /// A query for `example.com` on the default HTTPS port over HTTP.
    fn spec<'a>(host: &'a str, port: u16) -> DohQuery<'a> {
        DohQuery {
            host,
            port,
            ip_version: IpVersion::Whatever,
            ipv6_works: true,
            http_family: true,
            timeout_ms: 5_000,
        }
    }

    /// A resolution context over a fresh cache and a fixed clock.
    ///
    /// The clock is a [`TestClock`] rather than the system one so that nothing
    /// in these tests reads the wall clock -- `util/timeval.rs` owns that seam
    /// and there is a repository-wide gate on reaching past it.
    fn context<'a>(
        cache: &'a mut DnsCache,
        clock: &'a TestClock,
        proxied: bool,
    ) -> DohResolveContext<'a> {
        DohResolveContext {
            cache,
            clock,
            proxied,
        }
    }

    /// A twelve-byte DNS response header with the four counts.
    fn header(qd: u16, an: u16, ns: u16, ar: u16) -> Vec<u8> {
        let mut out = vec![0x00, 0x00, 0x81, 0x80];
        out.extend_from_slice(&qd.to_be_bytes());
        out.extend_from_slice(&an.to_be_bytes());
        out.extend_from_slice(&ns.to_be_bytes());
        out.extend_from_slice(&ar.to_be_bytes());
        out
    }

    /// A QNAME encoding of a dotted name, root label included.
    fn qname(host: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in host.split('.').filter(|label| !label.is_empty()) {
            out.push(u8::try_from(label.len()).unwrap_or(0));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// One question section entry for `host` and `dnstype`.
    fn question(host: &str, dnstype: DnsType) -> Vec<u8> {
        let mut out = qname(host);
        out.extend_from_slice(&dnstype.as_u16().to_be_bytes());
        out.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        out
    }

    /// One answer record with an explicit class, for the class-rejection test.
    fn answer_with_class(
        host: &str,
        dnstype: DnsType,
        class: u16,
        ttl: u32,
        rdata: &[u8],
    ) -> Vec<u8> {
        let mut out = qname(host);
        out.extend_from_slice(&dnstype.as_u16().to_be_bytes());
        out.extend_from_slice(&class.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        let rdlength = u16::try_from(rdata.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&rdlength.to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    /// One answer record in class `IN`.
    fn answer(host: &str, dnstype: DnsType, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        answer_with_class(host, dnstype, DNS_CLASS_IN, ttl, rdata)
    }

    /// A complete response: header, one question, then the given answers.
    fn response(host: &str, queried: DnsType, answers: &[Vec<u8>]) -> Vec<u8> {
        let count = u16::try_from(answers.len()).unwrap_or(u16::MAX);
        let mut out = header(1, count, 0, 0);
        out.extend_from_slice(&question(host, queried));
        for record in answers {
            out.extend_from_slice(record);
        }
        out
    }

    /// A response carrying one `A` record for `1.2.3.4`.
    fn a_response(host: &str) -> Vec<u8> {
        response(
            host,
            DnsType::A,
            &[answer(host, DnsType::A, 300, &[1, 2, 3, 4])],
        )
    }

    /// A response carrying one `AAAA` record for `2001:db8::1`.
    fn aaaa_response(host: &str) -> Vec<u8> {
        let octets = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).octets();
        response(
            host,
            DnsType::Aaaa,
            &[answer(host, DnsType::Aaaa, 300, &octets)],
        )
    }

    /// A minimal HTTPS resource record's RDATA: priority, target, one ALPN.
    fn https_rdata(priority: u16, target_labels: &[&str]) -> Vec<u8> {
        let mut out = priority.to_be_bytes().to_vec();
        for label in target_labels {
            out.push(u8::try_from(label.len()).unwrap_or(0));
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&HTTPS_RR_CODE_ALPN.to_be_bytes());
        out.extend_from_slice(&3u16.to_be_bytes());
        out.extend_from_slice(b"\x02h2");
        out
    }

    // ---- the pinned vocabulary --------------------------------------------

    /// `lib/doh.h:30-45`. The integers, because `doh_strerror` indexes by them.
    #[test]
    fn doh_code_discriminants_are_the_c_declaration_order() {
        assert_eq!(DohCode::Ok as i32, 0);
        assert_eq!(DohCode::DnsBadLabel as i32, 1);
        assert_eq!(DohCode::DnsOutOfRange as i32, 2);
        assert_eq!(DohCode::DnsLabelLoop as i32, 3);
        assert_eq!(DohCode::TooSmallBuffer as i32, 4);
        assert_eq!(DohCode::OutOfMem as i32, 5);
        assert_eq!(DohCode::DnsRdataLen as i32, 6);
        assert_eq!(DohCode::DnsMalformat as i32, 7);
        assert_eq!(DohCode::DnsBadRcode as i32, 8);
        assert_eq!(DohCode::DnsUnexpectedType as i32, 9);
        assert_eq!(DohCode::DnsUnexpectedClass as i32, 10);
        assert_eq!(DohCode::NoContent as i32, 11);
        assert_eq!(DohCode::DnsBadId as i32, 12);
        assert_eq!(DohCode::DnsNameTooLong as i32, 13);
    }

    /// `lib/doh.c:44-66`, character for character, including both shortenings
    /// and the out-of-range fall-through.
    #[test]
    fn strerror_maps_all_fourteen_codes_to_the_c_strings() {
        assert_eq!(strerror(DohCode::Ok), "");
        assert_eq!(strerror(DohCode::DnsBadLabel), "Bad label");
        // NOT "Dns out of range": the string is shorter than the identifier.
        assert_eq!(strerror(DohCode::DnsOutOfRange), "Out of range");
        assert_eq!(strerror(DohCode::DnsLabelLoop), "Label loop");
        // NOT "Too small buffer".
        assert_eq!(strerror(DohCode::TooSmallBuffer), "Too small");
        assert_eq!(strerror(DohCode::OutOfMem), "Out of memory");
        assert_eq!(strerror(DohCode::DnsRdataLen), "RDATA length");
        assert_eq!(strerror(DohCode::DnsMalformat), "Malformat");
        assert_eq!(strerror(DohCode::DnsBadRcode), "Bad RCODE");
        assert_eq!(strerror(DohCode::DnsUnexpectedType), "Unexpected TYPE");
        assert_eq!(strerror(DohCode::DnsUnexpectedClass), "Unexpected CLASS");
        assert_eq!(strerror(DohCode::NoContent), "No content");
        assert_eq!(strerror(DohCode::DnsBadId), "Bad ID");
        assert_eq!(strerror(DohCode::DnsNameTooLong), "Name too long");
    }

    /// `lib/doh.c:61-65`: the range test and the string it guards.
    #[test]
    fn strerror_raw_agrees_with_strerror_and_reports_bad_error_code() {
        for code in [
            DohCode::Ok,
            DohCode::DnsBadLabel,
            DohCode::DnsOutOfRange,
            DohCode::DnsLabelLoop,
            DohCode::TooSmallBuffer,
            DohCode::OutOfMem,
            DohCode::DnsRdataLen,
            DohCode::DnsMalformat,
            DohCode::DnsBadRcode,
            DohCode::DnsUnexpectedType,
            DohCode::DnsUnexpectedClass,
            DohCode::NoContent,
            DohCode::DnsBadId,
            DohCode::DnsNameTooLong,
        ] {
            assert_eq!(strerror_raw(code as i32), strerror(code));
        }
        // Outside `[DOH_OK, DOH_DNS_NAME_TOO_LONG]` on both sides.
        assert_eq!(strerror_raw(14), "bad error code");
        assert_eq!(strerror_raw(-1), "bad error code");
        assert_eq!(strerror_raw(i32::MAX), "bad error code");
    }

    /// `Display` is what `lib/doh.c:1235`'s `%s` interpolates.
    #[test]
    fn doh_code_displays_its_message() {
        assert_eq!(DohCode::NoContent.to_string(), "No content");
        assert_eq!(DohCode::Ok.to_string(), "");
    }

    /// `lib/doh.h:47-54`. IANA wire codes; not free to be renumbered.
    #[test]
    fn dns_type_integers_are_the_iana_wire_codes() {
        assert_eq!(DnsType::A.as_u16(), 1);
        assert_eq!(DnsType::Ns.as_u16(), 2);
        assert_eq!(DnsType::Cname.as_u16(), 5);
        assert_eq!(DnsType::Aaaa.as_u16(), 28);
        assert_eq!(DnsType::Dname.as_u16(), 39);
        assert_eq!(DnsType::Https.as_u16(), 65);
    }

    /// `lib/doh.c:1011-1025`, including the three that print `"unknown"`.
    #[test]
    fn type2name_reproduces_the_c_spellings() {
        assert_eq!(DnsType::A.type2name(), "A");
        assert_eq!(DnsType::Aaaa.type2name(), "AAAA");
        assert_eq!(DnsType::Https.type2name(), "HTTPS");
        assert_eq!(DnsType::Ns.type2name(), "unknown");
        assert_eq!(DnsType::Cname.type2name(), "unknown");
        assert_eq!(DnsType::Dname.type2name(), "unknown");
        assert_eq!(DnsType::Aaaa.to_string(), "AAAA");
    }

    /// `dns_type_from_u16` accepts exactly the six and rejects everything else.
    #[test]
    fn only_the_six_known_wire_codes_parse() {
        for dnstype in [
            DnsType::A,
            DnsType::Ns,
            DnsType::Cname,
            DnsType::Aaaa,
            DnsType::Dname,
            DnsType::Https,
        ] {
            assert_eq!(dns_type_from_u16(dnstype.as_u16()), Some(dnstype));
        }
        for raw in [0u16, 3, 4, 6, 16, 27, 29, 38, 40, 64, 66, 0xffff] {
            assert_eq!(dns_type_from_u16(raw), None, "wire code {raw}");
        }
    }

    /// `lib/doh.h:56-75`, and that [`SLOT_COUNT`] agrees with the enumeration.
    #[test]
    fn the_slot_vocabulary_is_exactly_three_in_wire_order() {
        assert_eq!(SLOT_COUNT, 3);
        assert_eq!(DohSlot::ALL.len(), SLOT_COUNT);
        assert_eq!(DohSlot::Ipv4.index(), 0);
        assert_eq!(DohSlot::Ipv6.index(), 1);
        assert_eq!(DohSlot::HttpsRr.index(), 2);
        assert_eq!(
            DohSlot::ALL,
            [DohSlot::Ipv4, DohSlot::Ipv6, DohSlot::HttpsRr]
        );
    }

    /// The constants of `lib/doh.h` and `lib/doh.c:41`.
    #[test]
    fn the_frozen_constants_hold_their_c_values() {
        assert_eq!(DNS_CLASS_IN, 0x01);
        assert_eq!(DOH_MAX_DNSREQ_SIZE, 272);
        assert_eq!(DOH_MAX_ADDR, 24);
        assert_eq!(DOH_MAX_CNAME, 4);
        assert_eq!(DOH_MAX_HTTPS, 4);
        assert_eq!(COMMA_CHAR, b',');
        assert_eq!(BACKSLASH_CHAR, b'\\');
        assert_eq!(PORT_HTTPS, 443);
        assert_eq!(CNAME_LOOP_BUDGET, 128);
        assert_eq!(MAX_LABEL_LEN, 63);
        assert_eq!(DNS_HEADER_LEN, 12);
        assert_eq!(LOCAL_PB_HEXMAX, 400);
        // `Curl_hexencode`'s real ceiling, which is 199 and not 200.
        assert_eq!(HEXENCODE_MAX_INPUT, 199);
    }

    /// The two buffer ceilings come from `crate::util::dynbuf` and are not
    /// redeclared here (`lib/curlx/dynbuf.h:65-66`).
    #[test]
    fn the_dynbuf_ceilings_are_the_imported_ones() {
        assert_eq!(DYN_DOH_RESPONSE, 3000);
        assert_eq!(DYN_DOH_CNAME, 256);
    }

    /// `lib/urldata.h:131`, the one bound [`junkscan`] applies before scanning.
    #[test]
    fn junkscan_rejects_a_name_longer_than_the_input_limit() {
        assert_eq!(CURL_MAX_INPUT_LENGTH, 8_000_000);

        // Over the limit. The length test precedes the byte scan, so this
        // half returns without reading a single byte and is cheap at any size.
        let huge = "a".repeat(CURL_MAX_INPUT_LENGTH + 1);
        assert!(!junkscan(&huge));

        // Exactly at the limit is ACCEPTED, which is what makes the comparison
        // `>` and not `>=`. Because the name is accepted, the scan cannot
        // short-circuit: `bytes().any()` visits all eight million bytes.
        #[cfg(not(miri))]
        {
            let at_limit = "a".repeat(CURL_MAX_INPUT_LENGTH);
            assert!(junkscan(&at_limit));
        }
    }

    // ---- the encoder: `tests/unit/unit1655.c` relocated -------------------

    /// The single most valuable assertion in this file.
    ///
    /// `lib/doh.c:116-159` byte by byte, for `example.com` as type `A`.
    #[test]
    fn the_golden_query_for_example_com_is_byte_exact() {
        let mut out = [0u8; DOH_MAX_DNSREQ_SIZE];
        let len = req_encode("example.com", DnsType::A, &mut out)
            .expect("a plain hostname encodes");

        #[rustfmt::skip]
        let expected: &[u8] = &[
            0x00, 0x00,             // ID -- always zero
            0x01,                   // RD set
            0x00,                   // RA, Z, RCODE
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT = 0
            0x00, 0x00,             // NSCOUNT = 0
            0x00, 0x00,             // ARCOUNT = 0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,                   // root label
            0x00, 0x01,             // TYPE = A, big-endian
            0x00, 0x01,             // CLASS = IN, big-endian
        ];
        assert_eq!(out.get(..len), Some(expected));
        // 12 + 1 + 11 + 4 + 1 (no trailing dot) = 29.
        assert_eq!(len, 29);
    }

    /// `lib/doh.c:107-108`: a trailing dot produces the same QNAME.
    #[test]
    fn a_trailing_dot_produces_the_same_encoding() {
        let mut plain = [0u8; DOH_MAX_DNSREQ_SIZE];
        let mut dotted = [0u8; DOH_MAX_DNSREQ_SIZE];
        let plain_len = req_encode("example.com", DnsType::A, &mut plain)
            .expect("plain encodes");
        let dotted_len = req_encode("example.com.", DnsType::A, &mut dotted)
            .expect("dotted encodes");
        assert_eq!(plain_len, dotted_len, "olen must not grow for a dot");
        assert_eq!(plain.get(..plain_len), dotted.get(..dotted_len));
    }

    /// `tests/unit/unit1655.c`'s "sunshine" block, relocated.
    #[test]
    fn the_length_relations_of_unit1655_hold() {
        let mut buffer = [0u8; 128];

        // `ret = doh_req_encode(sunshine1, ...)` with `sunshine1 = "a.com"`.
        let olen1 = req_encode("a.com", DnsType::A, &mut buffer)
            .expect("sunshine case 1 should pass fine");
        assert!(olen1 > "a.com".len(), "bad out length");

        // "with a trailing dot, the response should have the same length"
        let olen2 = req_encode("a.com.", DnsType::A, &mut buffer)
            .expect("dotshine case should pass fine");
        assert_eq!(olen1, olen2, "olen should not grow for a trailing dot");

        // "add one letter, the response should be one longer"
        let olen3 = req_encode("aa.com", DnsType::A, &mut buffer)
            .expect("sunshine case 2 should pass fine");
        assert_eq!(olen1 + 1, olen3, "olen should grow with the hostname");

        // "pass a short buffer, should fail"
        let short = buffer.get_mut(..olen1 - 1).expect("in range");
        assert_eq!(
            req_encode("a.com", DnsType::A, short),
            Err(DohCode::TooSmallBuffer),
            "short buffer should have been noticed"
        );

        // "pass a minimum buffer, should succeed"
        let exact = buffer.get_mut(..olen1).expect("in range");
        assert_eq!(
            req_encode("a.com", DnsType::A, exact),
            Ok(olen1),
            "minimal length buffer should be long enough"
        );
    }

    /// `tests/unit/unit1655.c`'s four-case playlist, relocated verbatim.
    ///
    /// The C wrote past a deliberately short buffer to prove the length
    /// arithmetic; here the arithmetic is proven directly, because writing past
    /// the buffer is not expressible.
    #[test]
    fn the_playlist_of_unit1655_reports_the_same_four_outcomes() {
        // 255 characters, ending in a dot: expected_len == 272 == the maximum.
        const MAX: &str = concat!(
            "this.is.a.maximum-length.hostname.",
            "with-no-label-of-greater-length-than-the-sixty-three-characters.",
            "specified.in.the.RFCs.",
            "and.with.a.QNAME.encoding.whose.length.is.exactly.",
            "the.maximum.length.allowed.",
            "that.is.two-hundred.and.fifty-six.",
            "including.the.last.null.",
        );
        // 256 characters: expected_len == 273, one past the maximum.
        const TOOLONG: &str = concat!(
            "here.is.a.hostname.which.is.just.barely.too.long.",
            "to.be.encoded.as.a.QNAME.of.the.maximum.allowed.length.",
            "which.is.256.including.a.final.zero-length.label.",
            "representing.the.root.node.so.that.a.name.with.",
            "a.trailing.dot.may.have.up.to.",
            "255.characters.never.more.",
        );
        const EMPTYLABEL: &str = concat!(
            "this.is.an.otherwise-valid.hostname.",
            ".with.an.empty.label.",
        );
        const OUTSIZELABEL: &str = concat!(
            "this.is.an.otherwise-valid.hostname.",
            "with-a-label-of-greater-length-than-the-sixty-three-characters-",
            "specified.in.the.RFCs.",
        );

        assert_eq!(MAX.len(), 255, "the C fixture is 255 characters");
        assert_eq!(TOOLONG.len(), 256, "the C fixture is 256 characters");

        // C's buffer is `unsigned char dohbuffer[255 + 16]` -- one byte short
        // of what `MAX` needs, which is what its canary detected.
        let mut victim = [0u8; 255 + 16];
        assert_eq!(
            req_encode(TOOLONG, DnsType::A, &mut victim),
            Err(DohCode::DnsNameTooLong),
            "expect early failure"
        );
        assert_eq!(
            req_encode(EMPTYLABEL, DnsType::A, &mut victim),
            Err(DohCode::DnsBadLabel)
        );
        assert_eq!(
            req_encode(OUTSIZELABEL, DnsType::A, &mut victim),
            Err(DohCode::DnsBadLabel)
        );
        // The case whose one-byte overrun the C proved by canary: 272 bytes are
        // needed and 271 are offered, so this is a clean refusal here.
        assert_eq!(
            req_encode(MAX, DnsType::A, &mut victim),
            Err(DohCode::TooSmallBuffer),
            "the C's canary fired here; a checked write refuses instead"
        );
        // Given the byte C's buffer lacked, it encodes -- proving the refusal
        // above was the buffer and not the name.
        let mut roomy = [0u8; DOH_MAX_DNSREQ_SIZE];
        assert_eq!(
            req_encode(MAX, DnsType::A, &mut roomy),
            Ok(DOH_MAX_DNSREQ_SIZE),
            "255 characters plus a trailing dot is exactly the maximum"
        );
    }

    /// `lib/doh.c:137`: 63 is the longest label and 64 is one too many.
    #[test]
    fn a_sixty_three_byte_label_encodes_and_sixty_four_does_not() {
        let mut out = [0u8; DOH_MAX_DNSREQ_SIZE];

        let ok = format!("{}.com", "a".repeat(MAX_LABEL_LEN));
        assert!(req_encode(&ok, DnsType::A, &mut out).is_ok());

        let bad = format!("{}.com", "a".repeat(MAX_LABEL_LEN + 1));
        assert_eq!(
            req_encode(&bad, DnsType::A, &mut out),
            Err(DohCode::DnsBadLabel)
        );
    }

    /// `lib/doh.c:137-141`: a zero-length label anywhere but the end.
    #[test]
    fn a_leading_or_doubled_dot_is_a_bad_label() {
        let mut out = [0u8; DOH_MAX_DNSREQ_SIZE];
        for host in [".example.com", "a..b", "..", "a.b..c"] {
            assert_eq!(
                req_encode(host, DnsType::A, &mut out),
                Err(DohCode::DnsBadLabel),
                "host {host:?}"
            );
        }
    }

    /// The `DEBUGASSERT(hostlen)` divergence of `lib/doh.c:105`.
    #[test]
    fn an_empty_host_is_rejected_rather_than_asserted() {
        let mut out = [0u8; DOH_MAX_DNSREQ_SIZE];
        assert_eq!(
            req_encode("", DnsType::A, &mut out),
            Err(DohCode::DnsBadLabel)
        );
        // A lone dot is one character, so the length arithmetic is fine and the
        // label loop is what rejects it -- a different route to the same code.
        assert_eq!(
            req_encode(".", DnsType::A, &mut out),
            Err(DohCode::DnsBadLabel)
        );
    }

    /// `lib/doh.c:154-156`: TYPE is big-endian, so 65 is `00 41`.
    #[test]
    fn the_type_field_is_big_endian_for_every_queried_type() {
        for (dnstype, expected) in [
            (DnsType::A, [0x00, 0x01]),
            (DnsType::Aaaa, [0x00, 0x1c]),
            (DnsType::Https, [0x00, 0x41]),
        ] {
            let mut out = [0u8; DOH_MAX_DNSREQ_SIZE];
            let len = req_encode("a.com", dnstype, &mut out)
                .expect("a.com encodes for every type");
            // The TYPE pair is the two bytes before the two CLASS bytes.
            let pair = out.get(len - 4..len - 2).expect("in range");
            assert_eq!(pair, expected, "{dnstype:?} must be big-endian");
            // And CLASS is `00 01`, never `01 00`.
            assert_eq!(out.get(len - 2..len), Some(&[0x00, 0x01][..]));
        }
    }

    /// `lib/doh.c:498-505`: the HTTPS-RR query name is port-dependent.
    #[test]
    fn the_https_rr_query_name_prefixes_a_non_default_port() {
        assert_eq!(https_rr_qname("example.com", 443), "example.com");
        assert_eq!(
            https_rr_qname("example.com", 8443),
            "_8443._https.example.com"
        );
        assert_eq!(https_rr_qname("example.com", 80), "_80._https.example.com");
        assert_eq!(https_rr_qname("h.example", 1), "_1._https.h.example");
    }

    // ---- the decoder ------------------------------------------------------

    /// A round trip: a well-formed `A` answer reaches the address list.
    #[test]
    fn a_well_formed_a_response_decodes() {
        let mut entry = DohEntry::default();
        let wire = a_response("example.com");
        assert_eq!(resp_decode(&wire, DnsType::A, &mut entry), Ok(()));
        assert_eq!(
            entry.addr,
            vec![DohAddr(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))]
        );
        assert_eq!(entry.ttl, 300);
        assert!(entry.cname.is_empty());
        assert_eq!(entry.addr.first().map(|a| a.dnstype()), Some(DnsType::A));
    }

    /// The same for `AAAA`, including the sixteen-byte width.
    #[test]
    fn a_well_formed_aaaa_response_decodes() {
        let mut entry = DohEntry::default();
        let wire = aaaa_response("example.com");
        assert_eq!(resp_decode(&wire, DnsType::Aaaa, &mut entry), Ok(()));
        let expected = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        assert_eq!(entry.addr, vec![DohAddr(IpAddr::V6(expected))]);
        assert_eq!(
            entry.addr.first().map(|a| a.dnstype()),
            Some(DnsType::Aaaa)
        );
    }

    /// `lib/doh.c:726-727`.
    #[test]
    fn a_response_shorter_than_a_header_is_too_small() {
        let mut entry = DohEntry::default();
        for len in 0..DNS_HEADER_LEN {
            let wire = vec![0u8; len];
            assert_eq!(
                resp_decode(&wire, DnsType::A, &mut entry),
                Err(DohCode::TooSmallBuffer),
                "length {len}"
            );
        }
    }

    /// `lib/doh.c:728-729`: the ID must be zero in BOTH bytes.
    #[test]
    fn a_non_zero_message_id_is_rejected() {
        let mut entry = DohEntry::default();
        for byte in [0usize, 1] {
            let mut wire = a_response("example.com");
            if let Some(slot) = wire.get_mut(byte) {
                *slot = 0x42;
            }
            assert_eq!(
                resp_decode(&wire, DnsType::A, &mut entry),
                Err(DohCode::DnsBadId),
                "byte {byte}"
            );
        }
    }

    /// `lib/doh.c:730-732`: every non-zero `RCODE`, not merely `NXDOMAIN`.
    #[test]
    fn every_non_zero_rcode_is_rejected() {
        for rcode in 1u8..=15 {
            let mut entry = DohEntry::default();
            let mut wire = a_response("example.com");
            if let Some(slot) = wire.get_mut(3) {
                *slot = (*slot & 0xf0) | rcode;
            }
            assert_eq!(
                resp_decode(&wire, DnsType::A, &mut entry),
                Err(DohCode::DnsBadRcode),
                "rcode {rcode}"
            );
        }
    }

    /// `lib/doh.c:758-762`: the three-valued acceptance test.
    #[test]
    fn an_unexpected_answer_type_is_rejected() {
        // A `TYPE` this module knows about but did not ask for.
        let mut entry = DohEntry::default();
        let wire = response(
            "example.com",
            DnsType::A,
            &[answer("example.com", DnsType::Aaaa, 60, &[0u8; 16])],
        );
        assert_eq!(
            resp_decode(&wire, DnsType::A, &mut entry),
            Err(DohCode::DnsUnexpectedType)
        );

        // A `TYPE` integer that is not one of the six at all -- 16 is `TXT`.
        let mut entry = DohEntry::default();
        let mut record = qname("example.com");
        record.extend_from_slice(&16u16.to_be_bytes());
        record.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        record.extend_from_slice(&60u32.to_be_bytes());
        record.extend_from_slice(&1u16.to_be_bytes());
        record.push(b'x');
        let mut wire = header(1, 1, 0, 0);
        wire.extend_from_slice(&question("example.com", DnsType::A));
        wire.extend_from_slice(&record);
        assert_eq!(
            resp_decode(&wire, DnsType::A, &mut entry),
            Err(DohCode::DnsUnexpectedType)
        );
    }

    /// `lib/doh.c:758-759`: `CNAME` and `DNAME` are accepted whatever was
    /// asked.
    #[test]
    fn cname_and_dname_are_accepted_for_any_query_type() {
        // A `CNAME` answer to an `A` query, followed by the address.
        let mut entry = DohEntry::default();
        let wire = response(
            "example.com",
            DnsType::A,
            &[
                answer(
                    "example.com",
                    DnsType::Cname,
                    120,
                    &qname("target.example"),
                ),
                answer("target.example", DnsType::A, 300, &[9, 8, 7, 6]),
            ],
        );
        assert_eq!(resp_decode(&wire, DnsType::A, &mut entry), Ok(()));
        assert_eq!(entry.cname, vec![b"target.example".to_vec()]);
        assert_eq!(
            entry.addr,
            vec![DohAddr(IpAddr::V4(Ipv4Addr::new(9, 8, 7, 6)))]
        );
        // The minimum TTL wins: 120 and not 300.
        assert_eq!(entry.ttl, 120);

        // A `DNAME` answer is accepted and contributes nothing, so the address
        // that follows it is what keeps the response from being NO_CONTENT.
        let mut entry = DohEntry::default();
        let wire = response(
            "example.com",
            DnsType::A,
            &[
                answer("example.com", DnsType::Dname, 90, &qname("d.example")),
                answer("example.com", DnsType::A, 300, &[1, 1, 1, 1]),
            ],
        );
        assert_eq!(resp_decode(&wire, DnsType::A, &mut entry), Ok(()));
        assert!(entry.cname.is_empty(), "DNAME is skipped, not stored");
        assert_eq!(entry.ttl, 90);
    }

    /// `lib/doh.c:767-769`.
    #[test]
    fn a_class_other_than_in_is_rejected() {
        for class in [0u16, 2, 3, 4, 255] {
            let mut entry = DohEntry::default();
            let wire = response(
                "example.com",
                DnsType::A,
                &[answer_with_class(
                    "example.com",
                    DnsType::A,
                    class,
                    60,
                    &[1, 2, 3, 4],
                )],
            );
            assert_eq!(
                resp_decode(&wire, DnsType::A, &mut entry),
                Err(DohCode::DnsUnexpectedClass),
                "class {class}"
            );
        }
    }

    /// `lib/doh.c:706` and `:776-777`: the seed and the minimum.
    #[test]
    fn the_minimum_ttl_across_all_records_wins() {
        assert_eq!(DohEntry::default().ttl, i32::MAX as u32);

        let mut entry = DohEntry::default();
        let wire = response(
            "example.com",
            DnsType::A,
            &[
                answer("example.com", DnsType::A, 300, &[1, 2, 3, 4]),
                answer("example.com", DnsType::A, 60, &[1, 2, 3, 5]),
                answer("example.com", DnsType::A, 900, &[1, 2, 3, 6]),
            ],
        );
        assert_eq!(resp_decode(&wire, DnsType::A, &mut entry), Ok(()));
        assert_eq!(entry.ttl, 60);
        assert_eq!(entry.addr.len(), 3, "and the order is the wire order");

        // The seed is `INT_MAX`, not `UINT_MAX`: a TTL above 2,147,483,647 does
        // NOT lower it, because the comparison is unsigned.
        let mut entry = DohEntry::default();
        let wire = response(
            "example.com",
            DnsType::A,
            &[answer("example.com", DnsType::A, u32::MAX, &[1, 2, 3, 4])],
        );
        assert_eq!(resp_decode(&wire, DnsType::A, &mut entry), Ok(()));
        assert_eq!(entry.ttl, i32::MAX as u32);
    }

    /// `lib/doh.c:671-677`: an address record's RDATA width is exact.
    #[test]
    fn a_mis_sized_address_record_is_an_rdata_length_error() {
        for (dnstype, rdata) in [
            (DnsType::A, vec![1u8, 2, 3]),
            (DnsType::A, vec![1u8, 2, 3, 4, 5]),
            (DnsType::Aaaa, vec![0u8; 15]),
            (DnsType::Aaaa, vec![0u8; 17]),
        ] {
            let mut entry = DohEntry::default();
            let wire = response(
                "example.com",
                dnstype,
                &[answer("example.com", dnstype, 60, &rdata)],
            );
            assert_eq!(
                resp_decode(&wire, dnstype, &mut entry),
                Err(DohCode::DnsRdataLen),
                "{dnstype:?} with {} bytes",
                rdata.len()
            );
        }
    }

    /// `lib/doh.c:839-840`: exact consumption.
    #[test]
    fn trailing_bytes_after_the_last_section_are_malformed() {
        let mut entry = DohEntry::default();
        let mut wire = a_response("example.com");
        wire.push(0xff);
        assert_eq!(
            resp_decode(&wire, DnsType::A, &mut entry),
            Err(DohCode::DnsMalformat)
        );
    }

    /// `lib/doh.c:846-849`: a well-formed message that stored nothing.
    #[test]
    fn an_answerless_response_has_no_content() {
        let mut entry = DohEntry::default();
        let mut wire = header(1, 0, 0, 0);
        wire.extend_from_slice(&question("example.com", DnsType::A));
        assert_eq!(
            resp_decode(&wire, DnsType::A, &mut entry),
            Err(DohCode::NoContent)
        );
    }

    /// **Pins the `USE_HTTTPS` typo at `lib/doh.c:842` -- THREE T's.**
    #[test]
    fn an_https_rr_only_answer_is_no_content_per_the_use_htttps_typo() {
        let mut entry = DohEntry::default();
        let rdata = https_rdata(1, &["target", "example"]);
        let wire = response(
            "example.com",
            DnsType::Https,
            &[answer("example.com", DnsType::Https, 60, &rdata)],
        );
        assert_eq!(
            resp_decode(&wire, DnsType::Https, &mut entry),
            Err(DohCode::NoContent),
            "lib/doh.c:842's USE_HTTTPS typo makes this NO_CONTENT"
        );
        // The record WAS stored -- the emptiness test simply does not look at
        // it, which is the whole of the typo's effect. The expected length is
        // taken from the fixture rather than written as a literal, so that
        // adjusting the fixture cannot silently turn this into a weaker
        // assertion than "every RDATA byte was kept verbatim".
        assert_eq!(entry.https_rrs.len(), 1);
        assert_eq!(
            entry.https_rrs.first().map(DohHttpsRr::len),
            Some(u16::try_from(rdata.len()).unwrap_or(u16::MAX))
        );
        assert_eq!(
            entry.https_rrs.first().map(|rr| rr.val.as_slice()),
            Some(rdata.as_slice())
        );
    }

    /// `lib/doh.c:846`: the `type != CURL_DNS_TYPE_NS` exemption.
    #[test]
    fn an_ns_answer_is_exempt_from_the_no_content_test() {
        let mut entry = DohEntry::default();
        let wire = response(
            "example.com",
            DnsType::Ns,
            &[answer("example.com", DnsType::Ns, 60, &qname("ns.example"))],
        );
        // Nothing is stored -- `doh_rdata`'s `default` arm skips `NS` -- and
        // yet the result is success, because the emptiness test exempts it.
        assert_eq!(resp_decode(&wire, DnsType::Ns, &mut entry), Ok(()));
        assert!(entry.addr.is_empty() && entry.cname.is_empty());
    }

    /// `lib/doh.c:795-837`: the authority and additional sections are skipped.
    #[test]
    fn authority_and_additional_records_are_skipped_not_parsed() {
        let mut entry = DohEntry::default();
        // An authority record of a type that would be REJECTED in the answer
        // section, and an additional record with a TTL lower than the answer's.
        // Neither may be parsed, so neither may affect the outcome.
        let mut wire = header(1, 1, 1, 1);
        wire.extend_from_slice(&question("example.com", DnsType::A));
        wire.extend_from_slice(&answer(
            "example.com",
            DnsType::A,
            300,
            &[1, 2, 3, 4],
        ));
        wire.extend_from_slice(&answer_with_class(
            "example.com",
            DnsType::Aaaa,
            9,
            1,
            &[0u8; 16],
        ));
        wire.extend_from_slice(&answer_with_class(
            "example.com",
            DnsType::Cname,
            9,
            2,
            &qname("nope.example"),
        ));
        assert_eq!(resp_decode(&wire, DnsType::A, &mut entry), Ok(()));
        // The answer's TTL survives: the skipped records contributed nothing.
        assert_eq!(entry.ttl, 300);
        assert!(entry.cname.is_empty());
        assert_eq!(entry.addr.len(), 1);
    }

    /// `lib/doh.c:568`, `:593`, `:612`: three silent caps.
    #[test]
    fn records_over_their_caps_are_silently_ignored() {
        // More than `DOH_MAX_ADDR` addresses.
        let mut entry = DohEntry::default();
        let records: Vec<Vec<u8>> = (0..DOH_MAX_ADDR + 6)
            .map(|i| {
                let last = u8::try_from(i).unwrap_or(0);
                answer("example.com", DnsType::A, 60, &[10, 0, 0, last])
            })
            .collect();
        let wire = response("example.com", DnsType::A, &records);
        assert_eq!(
            resp_decode(&wire, DnsType::A, &mut entry),
            Ok(()),
            "over the limit is success, not an error"
        );
        assert_eq!(entry.addr.len(), DOH_MAX_ADDR);
        // The first 24 are kept, in order -- the excess is dropped from the
        // tail rather than displacing an earlier entry.
        assert_eq!(
            entry.addr.first(),
            Some(&DohAddr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))))
        );

        // More than `DOH_MAX_CNAME` CNAMEs, with one address so the response is
        // not NO_CONTENT.
        let mut entry = DohEntry::default();
        let mut records: Vec<Vec<u8>> = (0..DOH_MAX_CNAME + 3)
            .map(|i| {
                answer(
                    "example.com",
                    DnsType::Cname,
                    60,
                    &qname(&format!("c{i}.example")),
                )
            })
            .collect();
        records.push(answer("example.com", DnsType::A, 60, &[1, 2, 3, 4]));
        let wire = response("example.com", DnsType::A, &records);
        assert_eq!(resp_decode(&wire, DnsType::A, &mut entry), Ok(()));
        assert_eq!(entry.cname.len(), DOH_MAX_CNAME);

        // More than `DOH_MAX_HTTPS` HTTPS records.
        let mut entry = DohEntry::default();
        let records: Vec<Vec<u8>> = (0..DOH_MAX_HTTPS + 2)
            .map(|i| {
                let priority = u16::try_from(i + 1).unwrap_or(1);
                answer(
                    "example.com",
                    DnsType::Https,
                    60,
                    &https_rdata(priority, &["t", "example"]),
                )
            })
            .collect();
        let wire = response("example.com", DnsType::Https, &records);
        // Still NO_CONTENT per the typo above, but the cap is what is measured.
        assert_eq!(
            resp_decode(&wire, DnsType::Https, &mut entry),
            Err(DohCode::NoContent)
        );
        assert_eq!(entry.https_rrs.len(), DOH_MAX_HTTPS);
    }

    // ---- the two name parsers, and their deliberate asymmetries -----------

    /// `lib/doh.c:529-534`: a compression pointer advances two and stops.
    #[test]
    fn skipqname_steps_over_a_pointer_without_following_it() {
        // `0xc0 0x0c` is a pointer to offset 12 -- which, if followed, would
        // walk a name. It must not be.
        let wire = [0xc0u8, 0x0c, 0xde, 0xad];
        let mut index = 0usize;
        assert_eq!(skipqname(&wire, &mut index), Ok(()));
        assert_eq!(index, 2, "exactly two bytes, and no further");

        // A pointer needs both of its bytes present.
        let truncated = [0xc0u8];
        let mut index = 0usize;
        assert_eq!(
            skipqname(&truncated, &mut index),
            Err(DohCode::DnsOutOfRange)
        );
    }

    /// `lib/doh.c:536-537`: the two reserved label types.
    #[test]
    fn skipqname_rejects_the_reserved_label_types() {
        for bits in [0x40u8, 0x80] {
            let wire = [bits, 0x00, 0x00, 0x00];
            let mut index = 0usize;
            assert_eq!(
                skipqname(&wire, &mut index),
                Err(DohCode::DnsBadLabel),
                "label type {bits:#04x}"
            );
        }
    }

    /// `lib/doh.c:538-541`: a literal label must fit, and a zero byte ends it.
    #[test]
    fn skipqname_walks_literal_labels_to_the_root() {
        let wire = qname("a.bc");
        let mut index = 0usize;
        assert_eq!(skipqname(&wire, &mut index), Ok(()));
        assert_eq!(index, wire.len(), "the root label is consumed too");

        // One byte short of the last label.
        let short = wire.get(..wire.len() - 2).unwrap_or_default().to_vec();
        let mut index = 0usize;
        assert_eq!(skipqname(&short, &mut index), Err(DohCode::DnsOutOfRange));
    }

    /// `lib/doh.c:620-629`: `store_cname` DOES follow pointers, unlike
    /// `skipqname`.
    #[test]
    fn store_cname_follows_a_compression_pointer() {
        // The message is `[0..4] = "\x02hi\x00"` and the RDATA at offset 4 is a
        // pointer back to offset 0.
        let mut wire = b"\x02hi\x00".to_vec();
        wire.extend_from_slice(&[0xc0, 0x00]);

        let mut entry = DohEntry::default();
        assert_eq!(entry.store_cname(&wire, 4), Ok(()));
        assert_eq!(entry.cname, vec![b"hi".to_vec()]);
    }

    /// `lib/doh.c:609`, `:648-651`: the 128-iteration guard, which must neither
    /// hang nor overflow the stack.
    #[test]
    fn a_self_referential_pointer_is_a_label_loop() {
        // A pointer at offset 0 pointing at offset 0.
        let wire = [0xc0u8, 0x00];
        let mut entry = DohEntry::default();
        assert_eq!(
            entry.store_cname(&wire, 0),
            Err(DohCode::DnsLabelLoop),
            "the budget must run out rather than the process"
        );
        // A two-pointer cycle, which the same budget catches.
        let cycle = [0xc0u8, 0x02, 0xc0, 0x00];
        let mut entry = DohEntry::default();
        assert_eq!(entry.store_cname(&cycle, 0), Err(DohCode::DnsLabelLoop));
    }

    /// `lib/doh.c:617` versus `:641`: the two bounds tests return DIFFERENT
    /// codes, and neither may be unified with the other.
    #[test]
    fn the_two_cname_bounds_tests_report_different_codes() {
        // `index >= dohlen` at the top of the loop -- OUT_OF_RANGE.
        let mut entry = DohEntry::default();
        assert_eq!(
            entry.store_cname(b"\x02hi", 3),
            Err(DohCode::DnsOutOfRange)
        );

        // `(index + length) > dohlen` inside the loop -- BAD_LABEL. A length
        // byte of 9 with only three bytes following.
        let mut entry = DohEntry::default();
        assert_eq!(entry.store_cname(b"\x09abc", 0), Err(DohCode::DnsBadLabel));
    }

    /// `lib/doh.c:631-632`: a reserved label type inside a CNAME.
    #[test]
    fn store_cname_rejects_the_reserved_label_types() {
        for bits in [0x40u8, 0x80] {
            let wire = [bits, b'x', b'y', 0x00];
            let mut entry = DohEntry::default();
            assert_eq!(
                entry.store_cname(&wire, 0),
                Err(DohCode::DnsBadLabel),
                "label type {bits:#04x}"
            );
        }
    }

    /// `lib/doh.c:637-640`: the separator goes BETWEEN labels only.
    #[test]
    fn cname_labels_are_joined_with_single_dots_and_no_trailing_dot() {
        let mut entry = DohEntry::default();
        assert_eq!(entry.store_cname(&qname("a.bb.ccc"), 0), Ok(()));
        assert_eq!(entry.cname, vec![b"a.bb.ccc".to_vec()]);

        // A single label has no separator at all.
        let mut entry = DohEntry::default();
        assert_eq!(entry.store_cname(&qname("only"), 0), Ok(()));
        assert_eq!(entry.cname, vec![b"only".to_vec()]);

        // The root label alone stores nothing, and is success.
        let mut entry = DohEntry::default();
        assert_eq!(entry.store_cname(&[0u8], 0), Ok(()));
        assert_eq!(entry.cname, vec![Vec::<u8>::new()]);
    }

    /// The [`DYN_DOH_CNAME`] ceiling, which C reports as `DOH_OUT_OF_MEM`.
    #[test]
    fn a_cname_past_the_dynbuf_ceiling_is_out_of_memory() {
        // Five 63-byte labels plus separators is 319 bytes, past the 256 cap.
        let long = (0..5).map(|_| "a".repeat(63)).collect::<Vec<_>>().join(".");
        let mut entry = DohEntry::default();
        assert_eq!(entry.store_cname(&qname(&long), 0), Err(DohCode::OutOfMem));
        // The slot was still taken, as C's pre-incremented `numcname` takes it,
        // and the buffer is empty because the ceiling emptied it.
        assert_eq!(entry.cname, vec![Vec::<u8>::new()]);
    }

    /// The executable form of the attacker-controlled-input convention.
    ///
    /// For a valid response of length `N`, every prefix `0..N` is fed to the
    /// decoder. Each must return *some* [`DohCode`] and **none may panic**,
    /// which is what proves that no index, no slice range and no arithmetic in
    /// the walk can fail on truncated input.
    #[test]
    fn every_truncation_of_a_valid_response_is_rejected_without_panicking() {
        let full = response(
            "example.com",
            DnsType::A,
            &[
                answer(
                    "example.com",
                    DnsType::Cname,
                    120,
                    &qname("target.example"),
                ),
                answer("target.example", DnsType::A, 300, &[9, 8, 7, 6]),
            ],
        );
        for len in 0..full.len() {
            let prefix = full.get(..len).unwrap_or_default();
            let mut entry = DohEntry::default();
            let outcome = resp_decode(prefix, DnsType::A, &mut entry);
            assert!(
                outcome.is_err(),
                "a truncated response must be rejected, not accepted \
                 (length {len})"
            );
        }
        // And the untruncated one still succeeds, so the sweep is not vacuous.
        let mut entry = DohEntry::default();
        assert_eq!(resp_decode(&full, DnsType::A, &mut entry), Ok(()));
    }

    /// The same sweep over an `AAAA` response with authority and additional
    /// sections, so that the skipping paths are covered too.
    #[test]
    fn every_truncation_of_a_sectioned_response_is_safe() {
        let mut full = header(1, 1, 1, 1);
        full.extend_from_slice(&question("example.com", DnsType::Aaaa));
        full.extend_from_slice(&answer(
            "example.com",
            DnsType::Aaaa,
            300,
            &[0u8; 16],
        ));
        full.extend_from_slice(&answer(
            "example.com",
            DnsType::Ns,
            300,
            &qname("ns.example"),
        ));
        full.extend_from_slice(&answer(
            "example.com",
            DnsType::A,
            300,
            &[1, 2, 3, 4],
        ));
        for len in 0..full.len() {
            let prefix = full.get(..len).unwrap_or_default();
            let mut entry = DohEntry::default();
            assert!(resp_decode(prefix, DnsType::Aaaa, &mut entry).is_err());
        }
        let mut entry = DohEntry::default();
        assert_eq!(resp_decode(&full, DnsType::Aaaa, &mut entry), Ok(()));
    }

    /// A byte-level fuzz over short inputs: nothing may panic, whatever
    /// arrives.
    #[test]
    fn arbitrary_short_inputs_never_panic() {
        // A deterministic walk rather than a random one, so a failure is
        // reproducible. Every one-byte value in each of the first sixteen
        // positions of an otherwise-valid response.
        let base = a_response("example.com");
        for position in 0..base.len().min(24) {
            for byte in [0u8, 1, 0x3f, 0x40, 0x7f, 0x80, 0xc0, 0xff] {
                let mut wire = base.clone();
                if let Some(slot) = wire.get_mut(position) {
                    *slot = byte;
                }
                let mut entry = DohEntry::default();
                // The outcome is not asserted -- only that reaching one is
                // possible. A panic here would fail the test by unwinding.
                let _ = resp_decode(&wire, DnsType::A, &mut entry);
            }
        }
    }

    // ---- the HTTPS resource record: `tests/unit/unit1658.c` relocated -----

    /// `unit1658`'s output format, so that its expectations can be compared
    /// as it compared them.
    fn rrresults(outcome: &CodeResult<HttpsRrInfo>) -> String {
        let code = match outcome {
            Ok(_) => 0,
            Err(code) => *code as i32,
        };
        let mut out = format!("r:{code}|");
        let Ok(record) = outcome else {
            return out;
        };
        out.push_str(&format!("p:{}|", record.priority));
        out.push_str(&format!("{}|", record.target.as_deref().unwrap_or("-")));
        for alpn in record.alpns.iter().copied().take_while(|&id| id != 0) {
            out.push_str(&format!("alpn:{alpn:x}|"));
        }
        if record.no_def_alpn {
            out.push_str("no-def-alpn|");
        }
        if let Some(port) = record.port {
            out.push_str(&format!("port:{port}|"));
        }
        if let Some(hints) = record.ipv4hints.as_deref() {
            for quad in hints.chunks_exact(4) {
                if let [a, b, c, d] = quad {
                    out.push_str(&format!("ipv4:{a}.{b}.{c}.{d}|"));
                }
            }
        }
        if let Some(ech) = record.echconfiglist.as_deref() {
            out.push_str(&format!("ech:{}|", hex::encode(ech)));
        }
        if let Some(hints) = record.ipv6hints.as_deref() {
            for block in hints.chunks_exact(16) {
                let groups: Vec<String> =
                    block.chunks_exact(2).map(hex::encode).collect();
                out.push_str(&format!("ipv6:{}|", groups.join(":")));
            }
        }
        out
    }

    /// All nineteen vectors of `tests/unit/unit1658.c`, verbatim.
    ///
    /// The C drives `doh_resp_decode_httpsrr` with each packet and compares the
    /// rendered result against a literal. The packets and the literals are
    /// transcribed unchanged; only the harness is Rust.
    #[test]
    fn the_nineteen_vectors_of_unit1658_produce_the_c_strings() {
        #[rustfmt::skip]
        let cases: &[(&str, &[u8], &str)] = &[
            ("single h2 alpn",
             b"\x00\x00\x04name\x00\x00\x01\x00\x03\x02h2",
             "r:0|p:0|name.|alpn:10|"),
            ("single h2 alpn missing last byte",
             b"\x00\x00\x04name\x00\x00\x01\x00\x03\x02h",
             "r:8|"),
            ("two alpns",
             b"\x00\x00\x04name\x04some\x00\x00\x01\x00\x06\x02h2\x02h1",
             "r:0|p:0|name.some.|alpn:10|alpn:8|"),
            ("alnt + no-default-alpn",
             b"\x00\x00\x04name\x04some\x00\x00\x01\x00\x03\x02h2\
               \x00\x02\x00\x00",
             "r:0|p:0|name.some.|alpn:10|no-def-alpn|"),
            ("alnt + no-default-alpn with size",
             b"\x00\x00\x04name\x04some\x00\x00\x01\x00\x03\x02h2\
               \x00\x02\x00\x01\xff",
             "r:43|"),
            ("alnt + no-default-alpn with size too short package",
             b"\x00\x00\x04name\x04some\x00\x00\x01\x00\x03\x02h2\
               \x00\x02\x00\x01",
             "r:8|"),
            ("rname + blank alpn field",
             b"\x11\x11\x04name\x04some\x00\x00\x01\x00\x00",
             "r:0|p:4369|name.some.|"),
            ("no rname + blank alpn",
             b"\x00\x11\x00\x00\x01\x00\x00",
             "r:0|p:17|.|"),
            ("unsupported field",
             b"\xff\xff\x00\x00\x07\x00\x02FF",
             "r:0|p:65535|.|"),
            ("unsupported field (wrong size)",
             b"\xff\xff\x00\x00\x07\x00\x02F",
             "r:8|"),
            ("port number",
             b"\x00\x10\x00\x00\x01\x00\x03\x02h2\x00\x03\x00\x02\x12\x34",
             "r:0|p:16|.|alpn:10|port:4660|"),
            ("port number with wrong size (3 bytes)",
             b"\x00\x10\x00\x00\x01\x00\x03\x02h2\
               \x00\x03\x00\x03\x12\x34\x00",
             "r:43|"),
            ("port number with wrong size (1 byte)",
             b"\x00\x10\x00\x00\x01\x00\x03\x02h2\x00\x03\x00\x01\x12",
             "r:43|"),
            ("alpn + two ipv4 addresses",
             b"\x00\x10\x00\x00\x01\x00\x03\x02h2\
               \x00\x04\x00\x08\xc0\xa8\x00\x01\xc0\xa8\x00\x02",
             "r:0|p:16|.|alpn:10|ipv4:192.168.0.1|ipv4:192.168.0.2|"),
            ("alpn + two ipv4 addresses in wrong order",
             b"\x00\x10\x00\
               \x00\x04\x00\x08\xc0\xa8\x00\x01\xc0\xa8\x00\x02\
               \x00\x01\x00\x03\x02h2",
             "r:8|"),
            ("alpn + ipv4 address with wrong size",
             b"\x00\x10\x00\x00\x01\x00\x03\x02h2\
               \x00\x04\x00\x05\xc0\xa8\x00\x01\xff",
             "r:43|"),
            ("alpn + one ipv6 address",
             b"\x00\x10\x00\x00\x01\x00\x03\x02h2\x00\x06\x00\x10\
               \xfe\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x23",
             "r:0|p:16|.|alpn:10|\
              ipv6:fe80:dabb:c1ff:fea3:8a22:1234:5678:9123|"),
            ("alpn + one ipv6 address with wrong size",
             b"\x00\x10\x00\x00\x01\x00\x03\x02h2\x00\x06\x00\x11\
               \xfe\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x23\x45",
             "r:43|"),
            ("alpn + ech",
             b"\x00\x10\x00\x00\x01\x00\x03\x02h2\x00\x05\x00\x10\
               \xfe\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x23",
             "r:0|p:16|.|alpn:10|ech:fe80dabbc1fffea38a22123456789123|"),
        ];

        for (name, packet, expected) in cases {
            let outcome = silent(|tracer| resp_decode_httpsrr(packet, tracer));
            assert_eq!(
                rrresults(&outcome).as_str(),
                *expected,
                "unit1658 case {name:?}"
            );
        }
    }

    /// `unit1658`'s "fully packed" vector, which exercises every code point at
    /// once including an unsupported one at 263.
    #[test]
    fn the_fully_packed_vector_of_unit1658_decodes() {
        #[rustfmt::skip]
        let packet: &[u8] =
            b"\xa0\x0b\x00\
              \x00\x00\x00\x00\
              \x00\x01\x00\x06\x02h2\x02h1\
              \x00\x02\x00\x00\
              \x00\x03\x00\x02\xbc\x71\
              \x00\x04\x00\x08\xc0\xa8\x00\x01\xc0\xa8\x00\x02\
              \x00\x05\x00\x10\
              \xfe\x80\xda\xbb\xc1\xff\x7e\xb3\x8a\x22\x12\x34\x56\x78\x91\x23\
              \x00\x06\x00\x20\
              \xfe\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x23\
              \xee\x80\xda\xbb\xc1\xff\xfe\xa3\x8a\x22\x12\x34\x56\x78\x91\x25\
              \x01\x07\x00\x04FFAA";
        let expected = concat!(
            "r:0|p:40971|.|alpn:10|alpn:8|no-def-alpn|port:48241|",
            "ipv4:192.168.0.1|ipv4:192.168.0.2|",
            "ech:fe80dabbc1ff7eb38a22123456789123|",
            "ipv6:fe80:dabb:c1ff:fea3:8a22:1234:5678:9123|",
            "ipv6:ee80:dabb:c1ff:fea3:8a22:1234:5678:9125|",
        );
        let outcome = silent(|tracer| resp_decode_httpsrr(packet, tracer));
        assert_eq!(rrresults(&outcome).as_str(), expected);
    }

    /// `lib/doh.c:1116-1117`.
    #[test]
    fn a_record_of_two_bytes_or_fewer_is_a_bad_argument() {
        for len in 0..=2usize {
            let packet = vec![0u8; len];
            let outcome = silent(|tracer| resp_decode_httpsrr(&packet, tracer));
            assert_eq!(
                outcome.err(),
                Some(CURLcode::BadFunctionArgument),
                "length {len}"
            );
        }
    }

    /// `lib/doh.c:1121`: the priority is big-endian.
    #[test]
    fn the_https_rr_priority_is_big_endian() {
        // `0x1234` must read as 4,660 and not as 13,330.
        let packet = b"\x12\x34\x00";
        let record = silent(|tracer| resp_decode_httpsrr(packet, tracer))
            .expect("priority plus a root target is a valid record");
        assert_eq!(record.priority, 0x1234);
        assert_eq!(record.priority, 4660);
        assert_eq!(record.target.as_deref(), Some("."));
        assert_eq!(record.port, None, "the port sentinel stays unset");
    }

    /// `lib/doh.c:1127-1131`, through the locally-implemented `Curl_junkscan`.
    #[test]
    fn a_target_carrying_a_control_byte_a_space_or_del_is_rejected() {
        for byte in [0x00u8, 0x09, 0x0a, 0x1f, 0x20, 0x7f] {
            let mut packet = vec![0x00, 0x00, 0x02, b'a', byte, 0x00];
            let outcome = silent(|tracer| resp_decode_httpsrr(&packet, tracer));
            assert_eq!(
                outcome.err(),
                Some(CURLcode::WeirdServerReply),
                "byte {byte:#04x} must be rejected"
            );
            // The same label with a printable byte is accepted, so the
            // rejection is the byte and not the shape.
            if let Some(slot) = packet.get_mut(4) {
                *slot = b'b';
            }
            assert!(
                silent(|tracer| resp_decode_httpsrr(&packet, tracer)).is_ok(),
                "byte {byte:#04x}: the control-free form must be accepted"
            );
        }
    }

    /// `junkscan`'s rule in isolation: `<= 0x20` or `== 127`.
    #[test]
    fn junkscan_accepts_printable_names_and_rejects_the_rest() {
        assert!(junkscan("example.com."));
        assert!(junkscan("~!@#$%^&*()"));
        assert!(junkscan(""), "an empty name has no offending byte");
        assert!(!junkscan("has space"));
        assert!(!junkscan("has\ttab"));
        assert!(!junkscan("has\nnewline"));
        assert!(!junkscan("has\u{7f}del"));
        assert!(!junkscan("has\u{0}nul"));
        // `0x21` is the first accepted byte, so the boundary is exact.
        assert!(junkscan("!"));
    }

    /// `lib/doh.c:1138`, `:1147`: SvcParam keys must STRICTLY ascend.
    #[test]
    fn svcparam_keys_must_strictly_ascend() {
        // Ascending: accepted.
        let mut packet = vec![0x00, 0x00, 0x00];
        packet.extend_from_slice(&HTTPS_RR_CODE_ALPN.to_be_bytes());
        packet.extend_from_slice(&3u16.to_be_bytes());
        packet.extend_from_slice(b"\x02h2");
        packet.extend_from_slice(&HTTPS_RR_CODE_PORT.to_be_bytes());
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&443u16.to_be_bytes());
        let record = silent(|tracer| resp_decode_httpsrr(&packet, tracer))
            .expect("ascending keys are accepted");
        assert_eq!(record.port, Some(443));

        // Descending: rejected.
        let mut packet = vec![0x00, 0x00, 0x00];
        packet.extend_from_slice(&HTTPS_RR_CODE_PORT.to_be_bytes());
        packet.extend_from_slice(&2u16.to_be_bytes());
        packet.extend_from_slice(&443u16.to_be_bytes());
        packet.extend_from_slice(&HTTPS_RR_CODE_ALPN.to_be_bytes());
        packet.extend_from_slice(&3u16.to_be_bytes());
        packet.extend_from_slice(b"\x02h2");
        assert_eq!(
            silent(|tracer| resp_decode_httpsrr(&packet, tracer)).err(),
            Some(CURLcode::WeirdServerReply)
        );

        // A REPEATED key is rejected too, because `expected_min_pcode` is
        // `pcode + 1` rather than `pcode`. This is what makes
        // `HttpsRrInfo::set_param`'s replace-on-repeat unreachable from here.
        let mut packet = vec![0x00, 0x00, 0x00];
        for _ in 0..2 {
            packet.extend_from_slice(&HTTPS_RR_CODE_ALPN.to_be_bytes());
            packet.extend_from_slice(&3u16.to_be_bytes());
            packet.extend_from_slice(b"\x02h2");
        }
        assert_eq!(
            silent(|tracer| resp_decode_httpsrr(&packet, tracer)).err(),
            Some(CURLcode::WeirdServerReply),
            "a duplicate key is as bad as a descending one"
        );

        // Key zero first is fine: `expected_min_pcode` starts at zero.
        let mut packet = vec![0x00, 0x00, 0x00];
        packet.extend_from_slice(&HTTPS_RR_CODE_MANDATORY.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        assert!(silent(|tracer| resp_decode_httpsrr(&packet, tracer)).is_ok());
    }

    /// `lib/doh.c:1138`: a SvcParam that claims more than remains.
    #[test]
    fn a_svcparam_longer_than_the_remainder_is_rejected() {
        let mut packet = vec![0x00, 0x00, 0x00];
        packet.extend_from_slice(&HTTPS_RR_CODE_ECH.to_be_bytes());
        packet.extend_from_slice(&9u16.to_be_bytes());
        packet.extend_from_slice(b"12345");
        assert_eq!(
            silent(|tracer| resp_decode_httpsrr(&packet, tracer)).err(),
            Some(CURLcode::WeirdServerReply)
        );
    }

    /// `lib/doh.c:1133`, `:1149`: a one-to-three byte remainder is tolerated in
    /// release and only debug-asserted, so it must NOT be hardened into an
    /// error.
    #[test]
    fn a_short_trailing_remainder_ends_the_svcparam_loop() {
        let base: &[u8] = b"\x00\x00\x00";
        // Zero remainder always succeeds, in either build.
        assert!(silent(|tracer| resp_decode_httpsrr(base, tracer)).is_ok());

        // Appended only where `DEBUGASSERT` is compiled out, because where it
        // is present the panic *is* the behaviour under test and belongs in the
        // `should_panic` companion rather than here.
        #[cfg(not(debug_assertions))]
        for extra in 1..=3usize {
            let mut packet = base.to_vec();
            packet.extend(std::iter::repeat(0xffu8).take(extra));
            assert!(
                silent(|tracer| resp_decode_httpsrr(&packet, tracer)).is_ok(),
                "a {extra}-byte remainder is tolerated in release"
            );
        }
    }

    /// The other half of [`a_short_trailing_remainder_ends_the_svcparam_loop`].
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "consumes its RDATA exactly")]
    fn a_short_trailing_remainder_debug_asserts() {
        let packet: &[u8] = b"\x00\x00\x00\xff";
        let _ = silent(|tracer| resp_decode_httpsrr(packet, tracer));
    }

    /// `lib/doh.c:1071-1092`: the target always ends in a dot, and a
    /// zero-length name is `"."`.
    #[test]
    fn the_target_name_is_dot_terminated() {
        for (labels, expected) in [
            (vec![], "."),
            (vec!["name"], "name."),
            (vec!["name", "some"], "name.some."),
            (vec!["a", "b", "c"], "a.b.c."),
        ] {
            let mut packet = vec![0x00, 0x01];
            for label in &labels {
                packet.push(u8::try_from(label.len()).unwrap_or(0));
                packet.extend_from_slice(label.as_bytes());
            }
            packet.push(0);
            let record = silent(|tracer| resp_decode_httpsrr(&packet, tracer))
                .expect("a priority plus a target is a valid record");
            assert_eq!(record.target.as_deref(), Some(expected));
        }
    }

    /// `lib/doh.c:1056-1092` cannot follow a compression pointer, because it is
    /// given no message base -- RFC 9460 forbids compression in a `TargetName`.
    #[test]
    fn the_target_name_parser_treats_a_pointer_byte_as_a_length() {
        // `0xc0` asks for 192 octets, which four bytes cannot satisfy.
        let packet = b"\x00\x00\xc0\x00\x00\x00";
        assert_eq!(
            silent(|tracer| resp_decode_httpsrr(packet, tracer)).err(),
            Some(CURLcode::WeirdServerReply)
        );
    }

    /// `resp_decode_httpsrr` DELEGATES to `httpsrr.rs` and duplicates none of
    /// its eight arms -- which is observable through the trace sink, because
    /// each arm emits its own line.
    #[test]
    fn the_svcparam_loop_emits_only_httpsrr_dot_rs_own_trace_lines() {
        let mut packet = vec![0x00, 0x00, 0x00];
        packet.extend_from_slice(&HTTPS_RR_CODE_ALPN.to_be_bytes());
        packet.extend_from_slice(&3u16.to_be_bytes());
        packet.extend_from_slice(b"\x02h2");
        packet.extend_from_slice(&HTTPS_RR_CODE_NO_DEF_ALPN.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&HTTPS_RR_CODE_IPV4.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet.extend_from_slice(&[192, 168, 0, 1]);
        packet.extend_from_slice(&HTTPS_RR_CODE_IPV6.to_be_bytes());
        packet.extend_from_slice(&16u16.to_be_bytes());
        packet.extend_from_slice(&[0u8; 16]);

        let (outcome, log) =
            traced(|tracer| resp_decode_httpsrr(&packet, tracer));
        assert!(outcome.is_ok());

        // `httpsrr.rs`'s strings, which this file must not restate.
        assert!(log.contains(&dns_line("HTTPS RR ALPN: 16 0 0 0")), "{log}");
        assert!(log.contains(&dns_line("HTTPS RR no-def-alpn")), "{log}");
        assert!(log.contains(&dns_line("HTTPS RR IPv4")), "{log}");
        assert!(log.contains(&dns_line("HTTPS RR IPv6")), "{log}");

        // And NONE of this file's own HTTPS-RR lines, which belong to
        // `print_httpsrr` and are emitted only from `is_resolved`.
        assert!(!log.contains("HTTPS RR: alpns"), "{log}");
        assert!(!log.contains("HTTPS RR: no_def_alpn"), "{log}");
        assert!(!log.contains("HTTPS RR: ipv4hints"), "{log}");
        assert!(!log.contains("HTTPS RR: ipv6hint"), "{log}");

        // Each delegated line appears exactly ONCE: a duplicated arm here
        // would show up as two.
        assert_eq!(log.matches("HTTPS RR IPv4").count(), 1, "{log}");
    }

    // ---- the observable strings, byte for byte ----------------------------

    /// `lib/doh.c:201` versus `:203`: **the truncated form is missing the space
    /// (and the comma) before `val=`.**
    #[test]
    fn print_buf_reproduces_the_truncated_form_asymmetry() {
        // 200 bytes or fewer: the untruncated form, with `, val=`.
        let (_, log) = traced(|tracer| print_buf("P", &[0xde, 0xad], tracer));
        assert_eq!(log, info_line("P: len=2, val=dead"));

        // More than 200 bytes: the truncated form, with NO space and NO comma.
        let big = vec![0xabu8; 201];
        let (_, log) = traced(|tracer| print_buf("Q", &big, tracer));
        let hex = "ab".repeat(HEXENCODE_MAX_INPUT);
        assert_eq!(log, info_line(&format!("Q: len=201 (truncated)val={hex}")));
        assert!(
            !log.contains("(truncated), val="),
            "the truncated form has no comma"
        );
        assert!(
            !log.contains("(truncated) val="),
            "the truncated form has no space"
        );
    }

    /// The `truncated`-versus-encoded off-by-one of `lib/doh.c:197` against
    /// `lib/escape.c:205`.
    ///
    /// A 200-byte buffer reports itself untruncated and yet only 199 bytes are
    /// encoded. Preserved rather than corrected.
    #[test]
    fn the_hexencode_ceiling_is_one_byte_below_the_truncation_threshold() {
        let exactly_two_hundred = vec![0x5au8; LOCAL_PB_HEXMAX / 2];
        let (_, log) =
            traced(|tracer| print_buf("R", &exactly_two_hundred, tracer));
        // Claims not to be truncated ...
        assert!(log.contains("len=200, val="), "{log}");
        assert!(!log.contains("(truncated)"), "{log}");
        // ... and yet shows 199 bytes, which is 398 hex characters.
        let hex = "5a".repeat(HEXENCODE_MAX_INPUT);
        assert!(log.contains(&hex), "{log}");
        assert_eq!(hex.len(), 398);
    }

    /// `Curl_hexencode`'s empty-input case (`lib/escape.c:214-215`).
    #[test]
    fn print_buf_of_an_empty_buffer_shows_an_empty_value() {
        let (_, log) = traced(|tracer| print_buf("S", &[], tracer));
        assert_eq!(log, info_line("S: len=0, val="));
    }

    /// `lib/doh.c:859-896`, all four line shapes.
    #[test]
    fn show_reproduces_every_line_of_doh_show() {
        let mut entry = DohEntry {
            ttl: 300,
            ..DohEntry::default()
        };
        entry
            .addr
            .push(DohAddr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))));
        entry.addr.push(DohAddr(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0xdabb, 0xc1ff, 0xfea3, 0x8a22, 0x1234, 0x5678, 0x9123,
        ))));
        entry.cname.push(b"target.example".to_vec());

        let (_, log) = traced(|tracer| show(&entry, tracer));
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(
            lines,
            vec![
                "* [DoH] TTL: 300 seconds",
                "* [DoH] A: 192.0.2.7",
                "* [DoH] AAAA: fe80:dabb:c1ff:fea3:8a22:1234:5678:9123",
                // `"CNAME: %s"` carries NO `[DoH]` prefix -- `lib/doh.c:895`.
                "* CNAME: target.example",
            ]
        );
    }

    /// `lib/doh.c:869-882`: eight fixed groups, no zero-compression.
    ///
    /// This is where `Ipv6Addr`'s own `Display` would diverge: it prints `::1`
    /// where C prints every group.
    #[test]
    fn the_aaaa_line_never_compresses_a_run_of_zeroes() {
        let loopback = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        assert_eq!(
            aaaa_line(loopback),
            "[DoH] AAAA: 0000:0000:0000:0000:0000:0000:0000:0001"
        );
        // The standard library would have said `::1`, so the two really do
        // differ and the choice is load-bearing.
        assert_ne!(aaaa_line(loopback), format!("[DoH] AAAA: {loopback}"));

        let unspecified = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(
            aaaa_line(unspecified),
            "[DoH] AAAA: 0000:0000:0000:0000:0000:0000:0000:0000"
        );
    }

    /// `lib/doh.c:890`: the release-build HTTPS-RR line of `doh_show`.
    #[test]
    fn show_reports_an_https_record_by_bytes_or_by_length() {
        let mut entry = DohEntry::default();
        entry
            .addr
            .push(DohAddr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        entry.https_rrs.push(DohHttpsRr {
            val: vec![0xaa, 0xbb, 0xcc],
        });
        let (_, log) = traced(|tracer| show(&entry, tracer));
        if cfg!(debug_assertions) {
            // `doh_print_buf(data, "DoH HTTPS", ...)` (`:888`).
            assert!(log.contains(&info_line("DoH HTTPS: len=3, val=aabbcc")));
        } else {
            // `infof(data, "DoH HTTPS RR: length %d", ...)` (`:890`).
            assert!(log.contains(&info_line("DoH HTTPS RR: length 3")));
        }
        assert_eq!(
            entry.https_rrs.first().map(DohHttpsRr::len),
            Some(3),
            "the C `uint16_t len` narrows without losing anything"
        );
    }

    /// `lib/doh.c:895`, and the `%s` semantics C applies to a CNAME buffer.
    #[test]
    fn a_cname_with_an_interior_nul_prints_only_up_to_it() {
        let mut entry = DohEntry::default();
        entry
            .addr
            .push(DohAddr(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        entry.cname.push(b"visible\0hidden".to_vec());
        let (_, log) = traced(|tracer| show(&entry, tracer));
        assert!(log.contains(&info_line("CNAME: visible")), "{log}");
        assert!(!log.contains("hidden"), "{log}");
        assert_eq!(cstr_text(b"abc"), "abc");
        assert_eq!(cstr_text(b""), "");
    }

    /// `lib/doh.c:1166-1193`: eleven strings, including the singular/plural
    /// asymmetry of the IPv6 pair.
    #[test]
    fn print_httpsrr_reproduces_all_eleven_strings() {
        // The all-absent record, which selects every negative form.
        let bare = HttpsRrInfo {
            priority: 7,
            target: Some("t.example.".to_owned()),
            ..HttpsRrInfo::default()
        };
        let (_, log) = traced(|tracer| print_httpsrr(&bare, tracer));
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(
            lines,
            vec![
                "* HTTPS RR: priority 7, target: t.example.",
                "* HTTPS RR: no alpns",
                "* HTTPS RR: no_def_alpn not set",
                "* HTTPS RR: no ipv4hints",
                "* HTTPS RR: no ECHConfigList",
                // PLURAL on the negative side.
                "* HTTPS RR: no ipv6hints",
            ]
        );

        // The all-present record, which selects every positive form.
        let full = HttpsRrInfo {
            priority: 1,
            target: Some("t.".to_owned()),
            alpns: [16, 8, 0, 0],
            no_def_alpn: true,
            ipv4hints: Some(vec![192, 0, 2, 1]),
            echconfiglist: Some(vec![0xde, 0xad]),
            ipv6hints: Some(vec![0u8; 16]),
            ..HttpsRrInfo::default()
        };
        let (_, log) = traced(|tracer| print_httpsrr(&full, tracer));
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(
            lines,
            vec![
                "* HTTPS RR: priority 1, target: t.",
                // All four slots, trailing zeros included -- `lib/doh.c:1168`.
                "* HTTPS RR: alpns 16 8 0 0",
                "* HTTPS RR: no_def_alpn set",
                "* HTTPS RR: ipv4hints: len=4, val=c0000201",
                "* HTTPS RR: ECHConfigList: len=2, val=dead",
                // SINGULAR on the positive side -- `lib/doh.c:1189`.
                "* HTTPS RR: ipv6hint: len=16, \
                 val=00000000000000000000000000000000",
            ]
        );
    }

    /// The two `lib/httpsrr.c` strings that go with c-ares must NOT appear.
    ///
    /// `"HTTPS RR target: %s"` and `"HTTPS RR priority: %u"` (`:191`, `:193`)
    /// have no colon after `RR` and live inside `#ifdef USE_ARES`, which AAP
    /// 0.5.2 drops. This file's forms put the colon after `RR` instead, so the
    /// two are distinguishable by exactly that character.
    #[test]
    fn the_dropped_c_ares_strings_are_not_emitted() {
        let record = HttpsRrInfo {
            priority: 3,
            target: Some("x.".to_owned()),
            ..HttpsRrInfo::default()
        };
        let (_, log) = traced(|tracer| print_httpsrr(&record, tracer));
        assert!(!log.contains("HTTPS RR target:"), "{log}");
        assert!(!log.contains("HTTPS RR priority:"), "{log}");
        // And the form that IS emitted, for contrast.
        assert!(log.contains("HTTPS RR: priority 3, target: x."), "{log}");
    }

    /// `lib/doh.c:1167`: the ALPN test reads slot ZERO only.
    #[test]
    fn the_alpn_line_is_selected_by_the_first_slot_alone() {
        // A record whose first slot is the terminator but whose later slots are
        // not: C prints `"no alpns"` regardless, because it tests `alpns[0]`.
        let odd = HttpsRrInfo {
            target: Some(".".to_owned()),
            alpns: [0, 16, 0, 0],
            ..HttpsRrInfo::default()
        };
        let (_, log) = traced(|tracer| print_httpsrr(&odd, tracer));
        assert!(log.contains(&info_line("HTTPS RR: no alpns")), "{log}");
        assert!(!log.contains("HTTPS RR: alpns"), "{log}");
    }

    /// Every message of `mod msg`, asserted against its C literal.
    #[test]
    fn the_message_table_matches_the_c_literals() {
        assert_eq!(
            msg::failed_to_encode(13),
            "Failed to encode DoH packet [13]"
        );
        assert_eq!(
            msg::doh_request("Timeout was reached"),
            "DoH request Timeout was reached"
        );
        assert_eq!(
            msg::could_not_resolve("h.example"),
            "Could not DoH-resolve: h.example"
        );
        assert_eq!(msg::FAILED_TO_DECODE_HTTPS_RR, "Failed to decode HTTPS RR");
        assert_eq!(msg::SOME_HTTPS_RR_TO_PROCESS, "Some HTTPS RR to process");
        assert_eq!(msg::print_buf_line("P", 2, "ab"), "P: len=2, val=ab");
        assert_eq!(
            msg::print_buf_truncated("P", 2, "ab"),
            "P: len=2 (truncated)val=ab"
        );
        assert_eq!(
            msg::decode_failed("No content", "AAAA", "h.example"),
            "DoH: No content type AAAA for h.example"
        );
        assert_eq!(msg::hostname("h.example"), "hostname: h.example");
        assert_eq!(msg::doh_ttl(60), "[DoH] TTL: 60 seconds");
        assert_eq!(msg::doh_a([10, 0, 0, 1]), "[DoH] A: 10.0.0.1");
        assert_eq!(msg::DOH_AAAA_PREFIX, "[DoH] AAAA: ");
        assert_eq!(msg::doh_https_rr_length(9), "DoH HTTPS RR: length 9");
        assert_eq!(msg::DOH_HTTPS_PREFIX, "DoH HTTPS");
        assert_eq!(msg::cname("a.b"), "CNAME: a.b");
        assert_eq!(
            msg::https_rr_priority_target(2, "t."),
            "HTTPS RR: priority 2, target: t."
        );
        assert_eq!(
            msg::https_rr_alpns([16, 8, 0, 0]),
            "HTTPS RR: alpns 16 8 0 0"
        );
        assert_eq!(msg::HTTPS_RR_NO_ALPNS, "HTTPS RR: no alpns");
        assert_eq!(msg::HTTPS_RR_NO_DEF_ALPN_SET, "HTTPS RR: no_def_alpn set");
        assert_eq!(
            msg::HTTPS_RR_NO_DEF_ALPN_NOT_SET,
            "HTTPS RR: no_def_alpn not set"
        );
        assert_eq!(msg::HTTPS_RR_IPV4HINTS, "HTTPS RR: ipv4hints");
        assert_eq!(msg::HTTPS_RR_NO_IPV4HINTS, "HTTPS RR: no ipv4hints");
        assert_eq!(msg::HTTPS_RR_ECHCONFIGLIST, "HTTPS RR: ECHConfigList");
        assert_eq!(
            msg::HTTPS_RR_NO_ECHCONFIGLIST,
            "HTTPS RR: no ECHConfigList"
        );
        // The asymmetry, asserted as two separate literals so that neither can
        // be "corrected" into the other without failing here.
        assert_eq!(msg::HTTPS_RR_IPV6HINT, "HTTPS RR: ipv6hint");
        assert_eq!(msg::HTTPS_RR_NO_IPV6HINTS, "HTTPS RR: no ipv6hints");
        assert!(!msg::HTTPS_RR_IPV6HINT.ends_with('s'));
        assert!(msg::HTTPS_RR_NO_IPV6HINTS.ends_with('s'));
        assert_eq!(
            msg::CONTENT_TYPE_DNS_MESSAGE,
            "Content-Type: application/dns-message"
        );
        assert_eq!(msg::DEFAULT_PROTOCOL, "https");
    }

    // ---- the request shape ------------------------------------------------

    /// `lib/doh.c:313-314`, `:328-346`: everything the request freezes.
    #[test]
    fn the_probe_request_carries_exactly_the_one_frozen_header() {
        let request = silent(|tracer| {
            DohProbeRequest::build(
                "example.com",
                DnsType::A,
                5_000,
                &settings(),
                tracer,
            )
        })
        .expect("a plain hostname builds");

        assert_eq!(DohProbeRequest::METHOD, "POST");
        assert_eq!(DohProbeRequest::DEFAULT_PROTOCOL, "https");
        // A compile-time assertion, because the value is a `const`: a
        // regression cannot even build, let alone reach a test run.
        const _: () = assert!(DohProbeRequest::INTERNAL);
        assert_eq!(request.url, "https://doh.example/dns-query");
        assert_eq!(
            request.headers,
            vec!["Content-Type: application/dns-message".to_owned()],
            "exactly one header, and exactly that spelling"
        );
        assert_eq!(request.headers.len(), 1);
        assert_eq!(request.timeout_ms, 5_000);
        assert_eq!(request.dnstype, DnsType::A);
        assert_eq!(request.body_len(), request.body.len());
        assert_eq!(request.body_len(), 29);

        // The body is the RAW DNS query -- never base64url, so no `?dns=`
        // form and no printable-ASCII encoding.
        let mut expected = [0u8; DOH_MAX_DNSREQ_SIZE];
        let len = req_encode("example.com", DnsType::A, &mut expected)
            .expect("the golden query encodes");
        assert_eq!(request.body.as_slice(), expected.get(..len).unwrap_or(&[]));
        assert!(
            request.body.contains(&0u8),
            "a base64url body could not contain a zero byte"
        );

        // `mstotv`'s reading of a positive count.
        assert_eq!(
            request.timeout(),
            Some(core::time::Duration::from_millis(5_000))
        );
    }

    /// `lib/doh.c:339-345`: HTTPS only in a release build.
    #[test]
    fn the_protocol_restriction_never_allows_plain_http_in_release() {
        let chosen = DohProtocols::for_this_build();
        if cfg!(debug_assertions) {
            assert_eq!(chosen, DohProtocols::HttpAndHttps);
            assert!(chosen.allows_plain_http());
        } else {
            assert_eq!(
                chosen,
                DohProtocols::HttpsOnly,
                "a shipped artifact must never send DoH over plain HTTP"
            );
            assert!(!chosen.allows_plain_http());
        }
        assert!(!DohProtocols::HttpsOnly.allows_plain_http());
        assert!(DohProtocols::HttpAndHttps.allows_plain_http());
    }

    /// `lib/doh.c:335-338`: the HTTP/2 hints, and their `#ifdef`.
    #[test]
    fn the_http2_hints_follow_the_http2_feature() {
        let request = silent(|tracer| {
            DohProbeRequest::build(
                "example.com",
                DnsType::A,
                1,
                &settings(),
                tracer,
            )
        })
        .expect("builds");
        if cfg!(feature = "http2") {
            assert_eq!(request.http_version, Some(DohHttpVersion::Http2Tls));
            assert!(
                request.pipewait,
                "CURLOPT_PIPEWAIT is set alongside the version hint"
            );
        } else {
            assert_eq!(request.http_version, None);
            assert!(!request.pipewait);
        }
        // The two are always set together or not at all, which is what the
        // single `#ifdef` around both guarantees.
        assert_eq!(request.pipewait, request.http_version.is_some());
    }

    /// `lib/doh.c:355-360`: **`2`, not `1`**, and default-on.
    #[test]
    fn the_doh_verification_triple_defaults_on_and_uses_two_for_verifyhost() {
        let on = DohVerify::default();
        assert!(on.host && on.peer && on.status, "all three default ON");
        assert_eq!(on.verify_host_value(), 2, "VERIFYHOST is 2, never 1");
        assert_ne!(on.verify_host_value(), 1);
        assert_eq!(on.verify_peer_value(), 1);
        assert_eq!(on.verify_status_value(), 1);

        let off = DohVerify {
            host: false,
            peer: false,
            status: false,
        };
        assert_eq!(off.verify_host_value(), 0);
        assert_eq!(off.verify_peer_value(), 0);
        assert_eq!(off.verify_status_value(), 0);
    }

    /// The security property: `--insecure` must NOT weaken the DoH connection.
    ///
    /// The transfer's own verification switches are not inputs to
    /// [`DohProbeRequest`] at all -- only `CURLOPT_DOH_SSL_VERIFY*` is -- so
    /// there is no expression by which one could weaken the other. That
    /// absence is what this asserts.
    #[test]
    fn the_transfers_insecure_flag_cannot_weaken_the_doh_connection() {
        // A settings value built as `--insecure` would leave it: untouched,
        // because `--insecure` writes a DIFFERENT option.
        let request = silent(|tracer| {
            DohProbeRequest::build(
                "example.com",
                DnsType::A,
                1,
                &settings(),
                tracer,
            )
        })
        .expect("builds");
        assert_eq!(request.verify, DohVerify::default());
        assert_eq!(request.verify.verify_host_value(), 2);

        // And `--doh-insecure`, which is the option that DOES weaken it.
        let insecure = DohSettings {
            verify: DohVerify {
                host: false,
                peer: false,
                status: false,
            },
            ..settings()
        };
        let request = silent(|tracer| {
            DohProbeRequest::build(
                "example.com",
                DnsType::A,
                1,
                &insecure,
                tracer,
            )
        })
        .expect("builds");
        assert_eq!(request.verify.verify_host_value(), 0);
    }

    /// `lib/doh.c:362-401`: the inherited TLS material, conditional throughout.
    #[test]
    fn the_inherited_tls_material_travels_only_when_set() {
        // Nothing set: every option is absent rather than empty.
        let request = silent(|tracer| {
            DohProbeRequest::build(
                "example.com",
                DnsType::A,
                1,
                &settings(),
                tracer,
            )
        })
        .expect("builds");
        assert_eq!(request.tls, DohTlsSettings::default());
        assert_eq!(request.tls.cainfo, None);
        assert_eq!(request.tls.capath, None);
        assert_eq!(request.tls.crlfile, None);
        assert_eq!(request.tls.ec_curves, None);
        assert_eq!(request.tls.cainfo_blob, None);
        assert!(!request.tls.certinfo);
        assert_eq!(
            request.tls.ssl_options, 0,
            "the one option applied unconditionally"
        );

        // Everything set: every option travels.
        let rich = DohSettings {
            tls: DohTlsSettings {
                custom_cafile: true,
                custom_capath: true,
                custom_cablob: true,
                cainfo: Some("/ca.pem".to_owned()),
                cainfo_blob: Some(vec![1, 2, 3]),
                capath: Some("/certs".to_owned()),
                crlfile: Some("/crl.pem".to_owned()),
                certinfo: true,
                ssl_ctx_callback: true,
                ssl_ctx_data: true,
                debug_callback: true,
                debug_data: true,
                ec_curves: Some("X25519".to_owned()),
                ssl_options: 0x11,
            },
            verbose: true,
            no_signal: true,
            redirect_stderr: true,
            ..settings()
        };
        let request = silent(|tracer| {
            DohProbeRequest::build("example.com", DnsType::A, 1, &rich, tracer)
        })
        .expect("builds");
        assert_eq!(request.tls, rich.tls);
        assert!(request.verbose && request.no_signal);
        assert!(request.redirect_stderr);
    }

    /// `lib/doh.c:298-305`: an encode failure reports the message and returns
    /// **`CURLE_OUT_OF_MEMORY`**, which is preserved rather than corrected.
    #[test]
    fn an_unencodable_name_fails_as_out_of_memory_with_the_c_message() {
        let too_long = format!("{}.example.", "a".repeat(300));
        let (outcome, log) = traced(|tracer| {
            DohProbeRequest::build(
                &too_long,
                DnsType::A,
                1_000,
                &settings(),
                tracer,
            )
        });
        assert_eq!(
            outcome.err(),
            Some(CURLcode::OutOfMemory),
            "a name too long is reported as out of memory -- lib/doh.c:303"
        );
        // The DOHcode is what the message carries: 13 is DOH_DNS_NAME_TOO_LONG.
        assert!(log.contains("Failed to encode DoH packet [13]"), "{log}");

        // A bad label reports code 1 through the same path.
        let (outcome, log) = traced(|tracer| {
            DohProbeRequest::build(
                ".leading.dot",
                DnsType::A,
                1_000,
                &settings(),
                tracer,
            )
        });
        assert_eq!(outcome.err(), Some(CURLcode::OutOfMemory));
        assert!(log.contains("Failed to encode DoH packet [1]"), "{log}");
    }

    /// `lib/doh.c:307-311`: a negative time-left is refused BEFORE anything is
    /// issued, and it is never routed through `mstotv`.
    #[test]
    fn a_negative_time_left_is_operation_timedout() {
        for timeout_ms in [-1i64, -1_000, TimeDiff::MIN] {
            let outcome = silent(|tracer| {
                DohProbeRequest::build(
                    "example.com",
                    DnsType::A,
                    timeout_ms,
                    &settings(),
                    tracer,
                )
            });
            assert_eq!(
                outcome.err(),
                Some(CURLcode::OperationTimedout),
                "timeout_ms {timeout_ms}"
            );
        }
        // Zero is NOT negative and is accepted, reaching `mstotv` as "poll".
        let request = silent(|tracer| {
            DohProbeRequest::build(
                "example.com",
                DnsType::A,
                0,
                &settings(),
                tracer,
            )
        })
        .expect("a zero deadline is not an expired one");
        assert_eq!(request.timeout(), Some(core::time::Duration::ZERO));
    }

    // ---- the whole path, driven through the injected transport -------------

    /// `lib/doh.c:473-513`: which probes fire, and what they ask for.
    #[test]
    fn the_a_probe_is_unconditional_and_the_others_are_not() {
        /// The record types one query asks the transport for, in order.
        fn asked_for(query: DohQuery<'_>) -> Vec<DnsType> {
            let transport = MockDohTransport::always(Ok(Vec::new()));
            let _ = silent(|tracer| {
                block_on(doh(&transport, &query, &settings(), tracer))
            });
            transport
                .requests()
                .iter()
                .map(|request| request.dnstype)
                .collect()
        }

        // `CURL_IPRESOLVE_V6`: the `A` probe STILL fires. Measured quirk.
        let asked = asked_for(DohQuery {
            ip_version: IpVersion::V6,
            ..spec("example.com", 443)
        });
        assert!(
            asked.contains(&DnsType::A),
            "the A probe fires even for CURL_IPRESOLVE_V6 -- lib/doh.c:473"
        );
        assert_eq!(asked, vec![DnsType::A, DnsType::Aaaa, DnsType::Https]);

        // `CURL_IPRESOLVE_V4`: no `AAAA`.
        assert_eq!(
            asked_for(DohQuery {
                ip_version: IpVersion::V4,
                ..spec("example.com", 443)
            }),
            vec![DnsType::A, DnsType::Https]
        );

        // No IPv6 on the host: no `AAAA` either, whatever the option says.
        assert_eq!(
            asked_for(DohQuery {
                ipv6_works: false,
                ..spec("example.com", 443)
            }),
            vec![DnsType::A, DnsType::Https]
        );

        // Not an HTTP-family transfer: no `HTTPS` probe.
        assert_eq!(
            asked_for(DohQuery {
                http_family: false,
                ..spec("example.com", 443)
            }),
            vec![DnsType::A, DnsType::Aaaa]
        );

        // Nothing but the `A` probe, the narrowest set reachable at all.
        assert_eq!(
            asked_for(DohQuery {
                ip_version: IpVersion::V4,
                http_family: false,
                ..spec("example.com", 443)
            }),
            vec![DnsType::A]
        );
    }

    /// `lib/doh.c:499-505`: the HTTPS probe's query name on a non-443 port.
    #[test]
    fn the_https_probe_asks_for_the_attrleaf_name_on_a_non_default_port() {
        let transport = MockDohTransport::always(Ok(Vec::new()));
        let query = spec("example.com", 8443);
        let _ = silent(|tracer| {
            block_on(doh(&transport, &query, &settings(), tracer))
        });

        let requests = transport.requests();
        let https = requests
            .iter()
            .find(|request| request.dnstype == DnsType::Https)
            .expect("the HTTPS probe fired");

        // The body must be the query for `_8443._https.example.com`, which is
        // wire-observable and is what the fixture corpus would see.
        let mut expected = [0u8; DOH_MAX_DNSREQ_SIZE];
        let len = req_encode(
            "_8443._https.example.com",
            DnsType::Https,
            &mut expected,
        )
        .expect("the attrleaf name encodes");
        assert_eq!(https.body.as_slice(), expected.get(..len).unwrap_or(&[]));

        // And the `A` probe asks for the plain host, not the prefixed one.
        let a = requests
            .iter()
            .find(|request| request.dnstype == DnsType::A)
            .expect("the A probe fired");
        let mut plain = [0u8; DOH_MAX_DNSREQ_SIZE];
        let plain_len = req_encode("example.com", DnsType::A, &mut plain)
            .expect("the plain name encodes");
        assert_eq!(a.body.as_slice(), plain.get(..plain_len).unwrap_or(&[]));
    }

    /// The happy path, end to end, with no resolver and no socket.
    #[test]
    fn a_successful_resolution_reaches_the_cache() {
        let transport = MockDohTransport::new(vec![
            Ok(a_response("example.com")),
            Ok(aaaa_response("example.com")),
            Err(CURLcode::CouldntConnect),
        ]);
        let query = spec("example.com", 443);
        let mut cache = DnsCache::new();
        let clock = TestClock::new(CurlTime::new(1_700_000_000, 0));

        let (entry, log) = traced(|tracer| {
            let probes = block_on(doh(&transport, &query, &settings(), tracer))
                .expect("the probes complete");
            assert!(probes.response(DohSlot::Ipv4).started);
            assert!(probes.response(DohSlot::Ipv6).started);
            assert_eq!(
                probes.response(DohSlot::HttpsRr).result,
                Err(CURLcode::CouldntConnect),
                "a probe that failed keeps its own code"
            );
            assert_eq!(
                probes.response(DohSlot::HttpsRr).dnstype,
                None,
                "and reports no usable answer"
            );
            let mut ctx = context(&mut cache, &clock, false);
            is_resolved(&probes, &mut ctx, tracer)
        });

        let entry = entry.expect("both address probes answered");
        assert_eq!(entry.hostname, "example.com");
        assert_eq!(entry.hostport, 443);
        assert_eq!(entry.addrs.len(), 2, "one A and one AAAA");
        // `Curl_dnscache_mk_entry(..., FALSE)` -- not permanent.
        assert!(!entry.is_permanent());
        assert_eq!(entry.timestamp, clock.now());
        // The failed probe's line, from `doh_probe_done`'s survivor.
        assert!(log.contains("DoH request"), "{log}");
        // And the entry really is in the cache.
        assert_eq!(cache.len(), 1);
    }

    /// The narrow seam reaches the rich one only through the named adapter.
    ///
    /// It used to reach it through a blanket implementation, which is what
    /// discarded the caller's policy. Wrapping in [`NarrowDohTransport`] is now
    /// the only route, and the `.0` in the assertions below is the visible
    /// evidence of that: the narrowing is a thing somebody wrote.
    #[test]
    fn a_narrow_doh_transport_satisfies_the_rich_seam() {
        let transport = NarrowDohTransport(BytesTransport {
            answer: a_response("example.com"),
            seen: Mutex::new(Vec::new()),
        });
        // `timeout_ms: 0` -- unbounded. A byte-only `post(url, body)` has
        // nowhere to put a deadline, so a bounded query is refused rather than
        // issued without one; `the_narrow_adapter_refuses_a_request_it_cannot_convey`
        // asserts that, and this test is the conveyable case.
        let query = DohQuery {
            ip_version: IpVersion::V4,
            http_family: false,
            timeout_ms: 0,
            ..spec("example.com", 443)
        };
        let probes = silent(|tracer| {
            block_on(doh(&transport, &query, &settings(), tracer))
        })
        .expect("one probe completes");
        assert_eq!(probes.response(DohSlot::Ipv4).dnstype, Some(DnsType::A));

        // The adapter handed over exactly the URL and the body.
        let seen = transport
            .0
            .seen
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();
        assert_eq!(seen.len(), 1);
        let (url, body) = seen.first().expect("one call");
        assert_eq!(url, "https://doh.example/dns-query");
        let mut expected = [0u8; DOH_MAX_DNSREQ_SIZE];
        let len = req_encode("example.com", DnsType::A, &mut expected)
            .expect("encodes");
        assert_eq!(body.as_slice(), expected.get(..len).unwrap_or(&[]));

        // And the wrapper erases, which is what its `T: ?Sized` bound is for:
        // `&NarrowDohTransport<BytesTransport>` unsizes to
        // `&NarrowDohTransport<dyn DohTransport>`, so a caller holding a
        // transport of unknown type can wrap it once and pass it everywhere.
        // This is the coercion the old blanket implementation provided by
        // accident and this one provides deliberately.
        let erased: &NarrowDohTransport<dyn DohTransport> = &transport;
        let probes =
            silent(|tracer| block_on(doh(erased, &query, &settings(), tracer)))
                .expect("the erased transport works identically");
        assert!(probes.response(DohSlot::Ipv4).started);
    }

    /// A request carrying policy the narrow seam cannot express is REFUSED.
    ///
    /// The heart of the fix. Each case is a real option a caller can set, and
    /// each one used to be dropped in silence while the request went out under
    /// the transport's own policy. The first two are the ones that decide which
    /// resolver is trusted.
    #[test]
    fn the_narrow_adapter_refuses_a_request_it_cannot_convey() {
        type Narrow = NarrowDohTransport<BytesTransport>;

        // A conveyable request: exactly what `build` produces by default.
        let base = silent(|tracer| {
            DohProbeRequest::build(
                "example.com",
                DnsType::A,
                0,
                &settings(),
                tracer,
            )
        })
        .expect("the default request builds");
        assert_eq!(
            Narrow::unconveyable(&base),
            None,
            "a default request loses nothing and must be accepted"
        );

        // Trust material: a pinned CA for a private resolver.
        let mut pinned = base.clone();
        pinned.tls.cainfo = Some(String::from("/etc/pki/private-doh.pem"));
        assert_eq!(
            Narrow::unconveyable(&pinned),
            Some("CURLOPT_DOH_SSL trust material"),
            "a pinned CA cannot be silently replaced by the transport's store"
        );

        // Verification: all three of `CURLOPT_DOH_SSL_VERIFY*` default to ON
        // (`DohVerify::default`), so every departure a caller can express is a
        // RELAXATION -- `--doh-insecure` and its siblings. Each is refused,
        // because a narrow transport would apply its own defaults and quietly
        // re-tighten what the caller deliberately loosened. Being overruled in
        // silence is worse than being told no: all three are asserted so that
        // none can be forgotten.
        for relax in [
            DohVerify {
                peer: false,
                ..DohVerify::default()
            },
            DohVerify {
                host: false,
                ..DohVerify::default()
            },
            DohVerify {
                status: false,
                ..DohVerify::default()
            },
        ] {
            let mut relaxed = base.clone();
            relaxed.verify = relax;
            assert_eq!(
                Narrow::unconveyable(&relaxed),
                Some("CURLOPT_DOH_SSL_VERIFY* policy"),
                "a relaxed {relax:?} must not be silently re-tightened"
            );
        }

        // A resolve timeout. `post(url, body)` has nowhere to put a deadline, so
        // forwarding a bounded request would produce an unbounded probe -- a
        // DoH resolver that never answers would hang the transfer instead of
        // failing it at the deadline the caller set.
        let mut bounded = base.clone();
        bounded.timeout_ms = 5_000;
        assert_eq!(Narrow::unconveyable(&bounded), Some("a resolve timeout"));

        // An extra header.
        let mut headed = base.clone();
        headed.headers.push(String::from("X-Trace: 1"));
        assert_eq!(
            Narrow::unconveyable(&headed),
            Some("request headers beyond the DNS content type"),
        );

        // The HTTP version hint is NOT policy and must not be refused: it comes
        // from `cfg!(feature = "http2")` rather than from any caller option, so
        // refusing it would reject every request on an HTTP/2 build. Asserted
        // explicitly because it is the one field where "differs from a bare
        // default" and "is caller policy" come apart.
        assert_eq!(
            base.http_version.is_some(),
            cfg!(feature = "http2"),
            "the hint tracks the build, so it is the build's business"
        );
        assert_eq!(
            base.pipewait,
            base.http_version.is_some(),
            "and pipewait is set with it, as lib/doh.c sets the pair together"
        );

        // And the refusal really reaches `probe`, not just the predicate.
        let transport = NarrowDohTransport(BytesTransport {
            answer: a_response("example.com"),
            seen: Mutex::new(Vec::new()),
        });
        let outcome = block_on(transport.probe(&pinned));
        assert_eq!(
            outcome.err(),
            Some(CURLcode::SslConnectError),
            "the request must fail closed rather than go out unprotected"
        );
        let seen = transport
            .0
            .seen
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default();
        assert!(
            seen.is_empty(),
            "and nothing must have been sent: {} call(s) reached the transport",
            seen.len()
        );
    }

    /// `lib/doh.c:1209-1214`: neither address probe started.
    #[test]
    fn a_resolution_with_no_address_probe_reports_the_host_or_the_proxy() {
        // Only the HTTPS probe fires, which happens when IPv6 is unavailable
        // and the caller restricted to it -- a combination the C reaches the
        // same way. `A` is unconditional, so this is constructed directly.
        let mut probes = DohProbes::new("h.example", 443);
        probes.response_mut(DohSlot::HttpsRr).started = true;
        let mut cache = DnsCache::new();
        let clock = TestClock::new(CurlTime::new(1, 0));

        let (outcome, log) = traced(|tracer| {
            let mut ctx = context(&mut cache, &clock, false);
            is_resolved(&probes, &mut ctx, tracer)
        });
        assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveHost));
        assert!(
            log.contains(&info_line("Could not DoH-resolve: h.example")),
            "{log}"
        );

        // `CONN_IS_PROXIED(data->conn)` selects the proxy code -- and this is
        // the ONLY place in the function that consults it.
        let mut cache = DnsCache::new();
        let outcome = silent(|tracer| {
            let mut ctx = context(&mut cache, &clock, true);
            is_resolved(&probes, &mut ctx, tracer)
        });
        assert_eq!(outcome.err(), Some(CURLcode::CouldntResolveProxy));
    }

    /// **`lib/doh.c:1222` and `:1241`: the `||` over a zero-seeded `rc[]`.**
    #[test]
    fn a_single_failed_probe_still_enters_the_success_branch_and_then_fails() {
        let transport = MockDohTransport::always(Err(CURLcode::CouldntConnect));
        let query = DohQuery {
            ip_version: IpVersion::V4,
            http_family: false,
            ..spec("h.example", 443)
        };
        let mut cache = DnsCache::new();
        let clock = TestClock::new(CurlTime::new(1, 0));

        let (outcome, log) = traced(|tracer| {
            let probes = block_on(doh(&transport, &query, &settings(), tracer))
                .expect("the probe was issued and then failed");
            // It DID start, so step 1 does not fire ...
            assert!(probes.response(DohSlot::Ipv4).started);
            // ... and it has no usable answer, so the decode loop skips it and
            // `rc[IPV4]` stays at its zero -- which is `DOH_OK`.
            assert_eq!(probes.response(DohSlot::Ipv4).dnstype, None);
            let mut ctx = context(&mut cache, &clock, false);
            is_resolved(&probes, &mut ctx, tracer)
        });

        assert_eq!(
            outcome.err(),
            Some(CURLcode::CouldntResolveHost),
            "doh2ai supplies the failure the zeroed rc[] let through"
        );
        // The step-1 message did NOT fire, which is how the indirect route is
        // distinguishable from the direct one.
        assert!(!log.contains("Could not DoH-resolve"), "{log}");
        assert_eq!(cache.len(), 0, "nothing reached the cache");
    }

    /// `lib/doh.c:1240`: two answers that both fail to decode report the PLAIN
    /// host code even when proxied.
    #[test]
    fn two_undecodable_answers_report_the_host_even_when_proxied() {
        let transport = MockDohTransport::new(vec![
            Ok(vec![0xff; 20]),
            Ok(vec![0xff; 20]),
            Err(CURLcode::CouldntConnect),
        ]);
        let query = spec("h.example", 443);
        let mut cache = DnsCache::new();
        let clock = TestClock::new(CurlTime::new(1, 0));

        let (outcome, log) = traced(|tracer| {
            let probes = block_on(doh(&transport, &query, &settings(), tracer))
                .expect("both probes answered, with rubbish");
            let mut ctx = context(&mut cache, &clock, true);
            is_resolved(&probes, &mut ctx, tracer)
        });
        assert_eq!(
            outcome.err(),
            Some(CURLcode::CouldntResolveHost),
            "the seeded code is the host one, NOT the proxy one"
        );
        // `CURL_TRC_DNS(data, "DoH: %s type %s for %s", ...)` fired for each.
        assert!(log.contains("DoH: Bad ID type A for h.example"), "{log}");
        assert!(log.contains("DoH: Bad ID type AAAA for h.example"), "{log}");
    }

    /// `lib/doh.c:1261-1264`: **only the FIRST HTTPS record is decoded.**
    #[test]
    fn only_the_first_https_record_is_decoded() {
        // Two HTTPS records: the first valid, the second deliberately absurd.
        // If the second were read, the resolution would fail.
        let mut https = header(1, 2, 0, 0);
        https.extend_from_slice(&question("example.com", DnsType::Https));
        https.extend_from_slice(&answer(
            "example.com",
            DnsType::Https,
            60,
            &https_rdata(1, &["first", "example"]),
        ));
        https.extend_from_slice(&answer(
            "example.com",
            DnsType::Https,
            60,
            // A descending SvcParam pair, which `resp_decode_httpsrr` rejects.
            b"\x00\x02\x00\x00\x03\x00\x02\x01\xbb\x00\x01\x00\x03\x02h2",
        ));

        let transport = MockDohTransport::new(vec![
            Ok(a_response("example.com")),
            Ok(aaaa_response("example.com")),
            Ok(https),
        ]);
        let query = spec("example.com", 443);
        let mut cache = DnsCache::new();
        let clock = TestClock::new(CurlTime::new(1, 0));

        let (entry, log) = traced(|tracer| {
            let probes = block_on(doh(&transport, &query, &settings(), tracer))
                .expect("all three probes answered");
            let mut ctx = context(&mut cache, &clock, false);
            is_resolved(&probes, &mut ctx, tracer)
        });

        let entry = entry.expect("the FIRST record decodes, so this succeeds");
        let record = entry.hinfo.as_deref().expect("the record is attached");
        assert_eq!(record.priority, 1);
        assert_eq!(record.target.as_deref(), Some("first.example."));
        assert!(
            log.contains(&info_line("Some HTTPS RR to process")),
            "{log}"
        );
    }

    /// `lib/doh.c:1265-1269`: a malformed first record loses the addresses too.
    #[test]
    fn a_malformed_https_record_fails_the_whole_resolution() {
        let mut https = header(1, 1, 0, 0);
        https.extend_from_slice(&question("example.com", DnsType::Https));
        https.extend_from_slice(&answer(
            "example.com",
            DnsType::Https,
            60,
            // Descending SvcParam keys: PORT (3) then ALPN (1).
            b"\x00\x02\x00\x00\x03\x00\x02\x01\xbb\x00\x01\x00\x03\x02h2",
        ));

        let transport = MockDohTransport::new(vec![
            Ok(a_response("example.com")),
            Ok(aaaa_response("example.com")),
            Ok(https),
        ]);
        let query = spec("example.com", 443);
        let mut cache = DnsCache::new();
        let clock = TestClock::new(CurlTime::new(1, 0));

        let (outcome, log) = traced(|tracer| {
            let probes = block_on(doh(&transport, &query, &settings(), tracer))
                .expect("all three probes answered");
            let mut ctx = context(&mut cache, &clock, false);
            is_resolved(&probes, &mut ctx, tracer)
        });
        assert_eq!(
            outcome.err(),
            Some(CURLcode::WeirdServerReply),
            "the addresses are lost with the record -- C's own severity"
        );
        assert!(
            log.contains(&info_line("Failed to decode HTTPS RR")),
            "{log}"
        );
        assert_eq!(cache.len(), 0);
    }

    /// `lib/doh.c:1246-1249`: the verbose block, gated and in order.
    #[test]
    fn the_verbose_block_emits_the_hostname_line_before_the_dump() {
        let transport = MockDohTransport::new(vec![
            Ok(a_response("example.com")),
            Err(CURLcode::CouldntConnect),
            Err(CURLcode::CouldntConnect),
        ]);
        let query = spec("example.com", 443);
        let mut cache = DnsCache::new();
        let clock = TestClock::new(CurlTime::new(1, 0));

        let (outcome, log) = traced(|tracer| {
            let probes = block_on(doh(&transport, &query, &settings(), tracer))
                .expect("probes complete");
            let mut ctx = context(&mut cache, &clock, false);
            is_resolved(&probes, &mut ctx, tracer)
        });
        assert!(outcome.is_ok());
        let hostname_at = log
            .find("hostname: example.com")
            .expect("the hostname line is emitted");
        let ttl_at = log.find("[DoH] TTL:").expect("doh_show follows it");
        assert!(hostname_at < ttl_at, "the hostname line comes first: {log}");

        // With the DNS feature silent, neither appears.
        let mut cache = DnsCache::new();
        let probes = silent(|tracer| {
            block_on(doh(&transport, &query, &settings(), tracer))
        });
        let _ = probes;
        let quiet = {
            let config = TraceConfig::new();
            let mut sink = WriterSink::new(Vec::<u8>::new());
            {
                let mut tracer = Tracer::new(&config, &mut sink);
                let mut probes = DohProbes::new("example.com", 443);
                probes.response_mut(DohSlot::Ipv4).started = true;
                probes.response_mut(DohSlot::Ipv4).dnstype = Some(DnsType::A);
                probes.response_mut(DohSlot::Ipv4).body =
                    a_response("example.com");
                let mut ctx = context(&mut cache, &clock, false);
                let _ = is_resolved(&probes, &mut ctx, &mut tracer);
            }
            String::from_utf8(sink.into_inner()).unwrap_or_default()
        };
        assert!(quiet.is_empty(), "a silent tracer emits nothing: {quiet}");
    }

    /// `lib/doh.c:169-182`, `:296`: the response ceiling of `DYN_DOH_RESPONSE`.
    #[test]
    fn a_response_past_the_dynbuf_ceiling_is_a_write_error() {
        assert!(accumulate_body(&vec![0u8; DYN_DOH_RESPONSE - 1]).is_ok());
        assert_eq!(
            accumulate_body(&vec![0u8; DYN_DOH_RESPONSE]),
            Err(CURLcode::WriteError),
            "the ceiling test is `len + current + 1 > toobig`"
        );

        // And it reaches the probe's own slot as that code.
        let transport =
            MockDohTransport::always(Ok(vec![0u8; DYN_DOH_RESPONSE + 100]));
        let query = DohQuery {
            ip_version: IpVersion::V4,
            http_family: false,
            ..spec("h.example", 443)
        };
        let probes = silent(|tracer| {
            block_on(doh(&transport, &query, &settings(), tracer))
        })
        .expect("the probe was issued");
        assert_eq!(
            probes.response(DohSlot::Ipv4).result,
            Err(CURLcode::WriteError)
        );
        assert_eq!(probes.response(DohSlot::Ipv4).dnstype, None);
    }

    /// `lib/doh.c:248` is `infof(doh, ...)` -- **on the sub-handle**, and
    /// `lib/doh.c:327` labels that handle with `Curl_trc_feat_dns`.
    ///
    /// Two properties follow, and both are easy to lose by reaching for
    /// `failf!` because the situation being reported is a failure:
    ///
    /// * the line is `[DNS]`-bracketed, because the emitting handle's label is
    ///   DNS -- unlike every other line this file emits, which runs on the
    ///   master handle;
    /// * it does **not** reach `CURLOPT_ERRORBUFFER`. `Curl_failf` stores its
    ///   message there and fires whenever an error buffer exists even with
    ///   tracing off; `Curl_infof` does neither. A probe failure is not the
    ///   transfer's failure -- the *other* probe may still carry an address --
    ///   so putting this text in the application's buffer would report an
    ///   error for a resolution that went on to succeed.
    #[test]
    fn a_failed_probe_traces_a_dns_labelled_line_and_spares_the_error_buffer() {
        let transport = MockDohTransport::always(Err(CURLcode::CouldntConnect));
        let query = DohQuery {
            ip_version: IpVersion::V4,
            http_family: false,
            ..spec("h.example", 443)
        };

        let mut config = TraceConfig::new();
        config.set_feature_level(TraceFeature::Dns, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::<u8>::new());
        let mut errors = ErrorBuffer::new();
        {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_error_buffer(&mut errors)
                .with_state(TraceState::verbose());
            block_on(doh(&transport, &query, &settings(), &mut tracer))
                .expect("the probe was issued");
        }
        let log = String::from_utf8(sink.into_inner())
            .expect("every trace string in this module is ASCII");

        // Bracketed, because `:327` put the DNS label on the emitting handle.
        assert_eq!(
            log,
            dns_line(&msg::doh_request(CURLcode::CouldntConnect.message())),
            "lib/doh.c:248 is infof() on the DNS-labelled sub-handle"
        );
        // And nothing was stored for the application to read.
        assert!(
            !errors.is_set(),
            "lib/doh.c:248 is infof(), not failf(): {:?}",
            errors.message_lossy()
        );
    }

    /// Every emitter in this file other than the two `CURL_TRC_DNS` calls and
    /// `:248` runs on the master handle -- `infof(data, ...)` and
    /// `failf(data, ...)` -- whose label is whatever the user's own transfer
    /// has in force. A bare handle has none, which is why the assertions above
    /// expect no bracket. Give the transfer a label and the same lines carry
    /// it, which is what `Curl_infof`'s use of `data->state.feat`
    /// (`lib/curl_trc.c:256-265`) means. Asserting this keeps the earlier
    /// expectations honest: they pin an absent label, not a broken one.
    #[test]
    fn a_master_handle_line_carries_whatever_label_the_transfer_holds() {
        let mut entry = DohEntry {
            ttl: 300,
            ..DohEntry::default()
        };
        entry
            .addr
            .push(DohAddr(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))));

        let mut config = TraceConfig::new();
        config.set_feature_level(TraceFeature::Dns, TraceLevel::Info);
        let mut sink = WriterSink::new(Vec::<u8>::new());
        {
            let mut tracer =
                Tracer::new(&config, &mut sink).with_state(TraceState {
                    verbose: true,
                    feat: Some(TraceFeature::Dns),
                    ids: TraceIds::UNASSIGNED,
                });
            show(&entry, &mut tracer);
        }
        let log = String::from_utf8(sink.into_inner())
            .expect("every trace string in this module is ASCII");

        assert_eq!(
            log.lines().collect::<Vec<&str>>(),
            vec![
                "* [DNS] [DoH] TTL: 300 seconds",
                "* [DNS] [DoH] A: 192.0.2.7"
            ],
            "the same show() output, now labelled by the transfer"
        );
    }

    /// `lib/doh.c:307-311` again, but from the orchestrator: no request is
    /// issued at all.
    #[test]
    fn an_expired_deadline_issues_no_request() {
        let transport = MockDohTransport::always(Ok(Vec::new()));
        let query = DohQuery {
            timeout_ms: -1,
            ..spec("example.com", 443)
        };
        let outcome = silent(|tracer| {
            block_on(doh(&transport, &query, &settings(), tracer))
        });
        assert_eq!(outcome.err(), Some(CURLcode::OperationTimedout));
        assert!(
            transport.requests().is_empty(),
            "the refusal precedes every request"
        );
    }

    /// `resolve` is `doh` then `is_resolved`, and reports either's failure.
    #[test]
    fn resolve_composes_the_two_halves() {
        let transport = MockDohTransport::new(vec![
            Ok(a_response("example.com")),
            Ok(aaaa_response("example.com")),
            Err(CURLcode::CouldntConnect),
        ]);
        let query = spec("example.com", 443);
        let mut cache = DnsCache::new();
        let clock = TestClock::new(CurlTime::new(42, 0));

        let entry = silent(|tracer| {
            let mut ctx = context(&mut cache, &clock, false);
            block_on(resolve(&transport, &query, &settings(), &mut ctx, tracer))
        })
        .expect("the composition succeeds");
        assert_eq!(entry.addrs.len(), 2);
        assert_eq!(cache.len(), 1);

        // And the first half's failure propagates unchanged.
        let transport = MockDohTransport::always(Ok(Vec::new()));
        let expired = DohQuery {
            timeout_ms: -5,
            ..spec("example.com", 443)
        };
        let mut cache = DnsCache::new();
        let outcome = silent(|tracer| {
            let mut ctx = context(&mut cache, &clock, false);
            block_on(resolve(
                &transport,
                &expired,
                &settings(),
                &mut ctx,
                tracer,
            ))
        });
        assert_eq!(outcome.err(), Some(CURLcode::OperationTimedout));
    }

    /// `lib/doh.c:915-1008`: the order, the socket type and the canonical name.
    #[test]
    fn doh2ai_preserves_order_and_stamps_the_requested_hostname() {
        let mut entry = DohEntry::default();
        entry.addr.push(DohAddr(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0, 0, 0, 0, 0, 0, 1,
        ))));
        entry
            .addr
            .push(DohAddr(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))));

        let addrs =
            doh2ai(&entry, "example.com", 8080).expect("two addresses convert");
        assert_eq!(addrs.len(), 2);
        // The order is the storage order -- IPv6 first here, because that is
        // how it was stored. Sorting would change which is connected to first.
        assert_eq!(
            addrs.first().and_then(ResolvedAddr::socket_addr),
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1)),
                8080
            ))
        );
        assert_eq!(
            addrs.get(1).and_then(ResolvedAddr::socket_addr),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                8080
            ))
        );
        // "we return all names as STREAM" and the canonical name is the
        // REQUESTED host, not a name learned from the answer.
        for addr in &addrs {
            assert_eq!(addr.canonname.as_deref(), Some("example.com"));
        }

        // `if(!de->numaddr) return CURLE_COULDNT_RESOLVE_HOST;`
        let empty = DohEntry::default();
        assert_eq!(
            doh2ai(&empty, "example.com", 80).err(),
            Some(CURLcode::CouldntResolveHost)
        );
    }

    /// `DohProbes::response` is total over all three slots, and `Default`
    /// reports the `calloc` state.
    #[test]
    fn a_fresh_probe_set_reports_nothing_started() {
        let probes = DohProbes::new("h.example", 80);
        assert_eq!(probes.host, "h.example");
        assert_eq!(probes.port, 80);
        for slot in DohSlot::ALL {
            let response = probes.response(slot);
            assert!(!response.started);
            assert_eq!(response.dnstype, None);
            assert!(response.body.is_empty());
            assert_eq!(response.result, Ok(()));
        }
    }

    /// The queried name cannot appear in a formatted DoH request or response.
    ///
    /// The whole purpose of DoH is that the queried name is not observable
    /// (RFC 8484 section 1), so a formatter that printed the wire query would
    /// defeat the feature the caller opted into. The endpoint is redacted for
    /// the ordinary reason: a private resolver authenticates through its URL.
    #[test]
    fn a_doh_query_and_endpoint_cannot_reach_a_formatted_request() {
        let settings = DohSettings {
            url: String::from("https://token:s3cret@doh.example/dns-query"),
            ..DohSettings::default()
        };
        let request = silent(|tracer| {
            DohProbeRequest::build(
                "private.internal.example",
                DnsType::A,
                5_000,
                &settings,
                tracer,
            )
        })
        .expect("the request builds");

        let text = format!("{request:?}");
        assert!(
            !text.contains("s3cret"),
            "the endpoint token leaked: {text}"
        );
        assert!(!text.contains("doh.example"), "the endpoint leaked: {text}");
        // The QNAME is inside the binary body; assert the body is not rendered
        // at all rather than searching for an encoded form of the name.
        assert!(text.contains("body: <redacted,"), "{text}");
        // The request SHAPE still renders, which is what a test or a reader
        // compares against `lib/doh.c:290-401`.
        assert!(text.contains("dnstype: A"), "{text}");
        assert!(text.contains("timeout_ms: 5000"), "{text}");

        let settings_text = format!("{settings:?}");
        assert!(!settings_text.contains("s3cret"), "{settings_text}");
        assert!(!settings_text.contains("doh.example"), "{settings_text}");

        // And the request still carries the bytes a transport needs.
        assert_eq!(request.url, settings.url);
        assert!(!request.body.is_empty());
    }
}
