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

//! The Alt-Svc cache -- supersedes `lib/altsvc.c` and `lib/altsvc.h`.
//!
//! Alt-Svc is RFC 7838. A server answers a request with an `Alt-Svc:`
//! response header naming an alternative service -- a different protocol
//! version, host or port that serves the same origin -- and curl remembers
//! it, optionally across invocations in the file `--alt-svc <file>` names.
//! The option surface is `CURLOPT_ALTSVC` (10287) for the file and
//! `CURLOPT_ALTSVC_CTRL` (286) for the [`CURLALTSVC_READONLYFILE`],
//! [`CURLALTSVC_H1`], [`CURLALTSVC_H2`] and [`CURLALTSVC_H3`] bitmask.
//!
//! # `share/` owns locking; this module owns none
//!
//! What that module needs to know is which operations mutate, so it is
//! recorded here:
//!
//! | Operation | Access |
//! |---|---|
//! | [`AltSvcInfo::load`], [`AltSvcInfo::load_reader`] | WRITE |
//! | [`AltSvcInfo::parse`] | WRITE |
//! | [`AltSvcInfo::flush`] | WRITE |
//! | [`AltSvcInfo::lookup`] | **WRITE** -- it prunes expired entries |
//! | [`AltSvcInfo::ctrl`], [`AltSvcInfo::cleanup`] | WRITE |
//! | [`AltSvcInfo::write_to`], [`AltSvcInfo::save`] | read |
//!
//! **No operation is read-only except the two writers**, and `lookup` is the
//! trap: it looks like a query and takes `&mut self` because
//! `lib/altsvc.c:641-647` deletes expired entries as it scans. A shared
//! cache must therefore take the WRITE lock for a lookup.
//!
//! # The clock is injected
//!
//! Every instant this module reads is the WALL clock: `lib/altsvc.c` calls
//! `time(NULL)` in `Curl_altsvc_parse` (`:582`) and `Curl_altsvc_lookup`
//! (`:632`), and the stamp written into the cache file is a `gmtime` of an
//! expiry derived from it. So the parameter is
//! [`Clock::epoch_secs`](crate::util::timeval::Clock::epoch_secs), never
//! [`Clock::now`](crate::util::timeval::Clock::now), which is the monotonic
//! reading and is what `crate::cookies::psl` uses instead because
//! `lib/psl.c:52` goes through `Curl_pgrs_now`.
//!
//! Injection is faithful rather than invented. `lib/altsvc.c:431-447`
//! already replaces `time()` under `DEBUGBUILD || UNITTESTS` with
//! `altsvc_debugtime`, which reads the `CURL_TIME` environment variable --
//! `tests/data/test1654` sets `CURL_TIME=1548369261` and every expiry in its
//! expected output is derived from it. The environment-variable mechanism is
//! deliberately NOT reproduced: a `&dyn Clock` says the same thing without a
//! process-global, and C reached for `getenv` only because it had no better
//! seam.
//!
//! # Visibility
//!
//! `pub(crate)` throughout.

use core::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::error::{CURLcode, CodeResult};
// The two open flags for the hardened save, from the one directory in this
// crate allowed to name `libc`; `crate::util::fopen` cannot import them itself.
use crate::ffi::{O_CLOEXEC, O_NOFOLLOW};
use crate::util::dynbuf::DynBuf;
use crate::util::fopen::{open_for_write, NoFollow, StoreClass};
use crate::util::get_line::get_line;
use crate::util::inet::pton6;
use crate::util::parsedate::{parsedate, Outcome};
use crate::util::sltous;
use crate::util::strcase::ncasecompare;
use crate::util::strparse::{
    hexval, is_blank, str_casecompare, str_cspn, str_newline, str_number,
    str_passblanks, str_quotedword, str_single, str_singlespace,
    str_trimblanks, str_until, str_word, StrError,
};
use crate::util::timeval::{gmtime, Clock};

// Constants -- `lib/altsvc.c:41-46` and `include/curl/curl.h:1031-1035`.

/// The ceiling on one line of the cache file -- `lib/altsvc.c:41`.
#[allow(dead_code)]
const MAX_ALTSVC_LINE: usize = 4095;

/// The ceiling on the quoted date field -- `lib/altsvc.c:42`.
///
/// Exactly the length of `YYYYMMDD HH:MM:SS`, which is why it is a
/// REJECTION rather than a truncation: a longer quoted date makes
/// `str_quotedword` report [`StrError::Big`] and the line is dropped.
/// `tests/data/test355` is that case, with a stamp of `20290222 22:19:028`.
#[allow(dead_code)]
const MAX_ALTSVC_DATELEN: usize = 17;

/// The ceiling on a host field -- `lib/altsvc.c:43`.
#[allow(dead_code)]
const MAX_ALTSVC_HOSTLEN: usize = 2048;

/// The ceiling on an ALPN name field -- `lib/altsvc.c:44`.
///
/// Ten bytes, which is more than any name [`alpn2alpnid`] recognises. A
/// longer field is a dropped line; a shorter unrecognised one parses and is
/// then refused by [`AltSvc::create`].
#[allow(dead_code)]
const MAX_ALTSVC_ALPNLEN: usize = 10;

/// The ALPN name for HTTP/3 -- `H3VERSION`, `lib/altsvc.c:46`.
///
/// Spelled as a constant because the C does, and because it is the one name
/// [`alpnid2str`] takes from a macro rather than a literal.
#[allow(dead_code)]
const H3VERSION: &str = "h3";

/// The widest numeric address text `str_until` will take for an IPv6
/// destination -- `MAX_IPADR_LEN`, `lib/urldata.h:124`.
#[allow(dead_code)]
const MAX_IPADR_LEN: usize = 46;

/// The ceiling on an optional parameter's NAME -- `lib/altsvc.c:539`.
///
/// Twenty bytes. The C writes the number inline with no macro, and a longer
/// name ends the parameter loop rather than the alternative.
#[allow(dead_code)]
const MAX_ALTSVC_PARAMLEN: usize = 20;

/// The default `max-age` of an alternative: 24 hours -- `lib/altsvc.c:492`.
#[allow(dead_code)]
const DEFAULT_MAXAGE: i64 = 24 * 3600;

/// The largest representable instant, C's `TIME_T_MAX`.
///
/// A signed 64-bit `time_t` on all four mandated targets, so
/// [`i64::MAX`]. It is the clamp for an expiry that would overflow
/// (`lib/altsvc.c:584-587`) and the bound the C gives `str_number` when
/// reading a `ma=` value (`:556`).
#[allow(dead_code)]
const TIME_T_MAX: i64 = i64::MAX;

/// `CURLALTSVC_READONLYFILE` -- `include/curl/curl.h:1032`.
///
/// The cache is loaded from the file but never written back to it.
#[allow(dead_code)]
pub(crate) const CURLALTSVC_READONLYFILE: i64 = 1 << 2;

/// `CURLALTSVC_H1` -- `include/curl/curl.h:1033`. Also [`AlpnId::H1`].
#[allow(dead_code)]
pub(crate) const CURLALTSVC_H1: i64 = 1 << 3;

/// `CURLALTSVC_H2` -- `include/curl/curl.h:1034`. Also [`AlpnId::H2`].
#[allow(dead_code)]
pub(crate) const CURLALTSVC_H2: i64 = 1 << 4;

/// `CURLALTSVC_H3` -- `include/curl/curl.h:1035`. Also [`AlpnId::H3`].
#[allow(dead_code)]
pub(crate) const CURLALTSVC_H3: i64 = 1 << 5;

/// The two comment lines that open the cache file -- `lib/altsvc.c:375`.
#[rustfmt::skip]
#[allow(dead_code)]
const HEADER_LINE_1: &[u8] =
    b"# Your alt-svc cache. https://curl.se/docs/alt-svc.html\n";

/// The second of the two comment lines -- see [`HEADER_LINE_1`].
#[rustfmt::skip]
#[allow(dead_code)]
const HEADER_LINE_2: &[u8] =
    b"# This file was generated by libcurl! Edit at your own risk.\n";

// The ALPN identifier -- `enum alpnid`, `lib/hostip.h:49-54`.

/// An application-layer protocol identifier.
///
/// # The discriminants ARE the `CURLALTSVC_*` bits
///
/// The C writes them that way:
///
/// ```text
/// enum alpnid {
///   ALPN_none = 0,
///   ALPN_h1 = CURLALTSVC_H1,
///   ALPN_h2 = CURLALTSVC_H2,
///   ALPN_h3 = CURLALTSVC_H3
/// };
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(i32)]
#[allow(dead_code)]
pub(crate) enum AlpnId {
    /// `ALPN_none` -- no protocol, and the answer for every name
    /// [`alpn2alpnid`] does not recognise.
    ///
    /// Zero, so it is falsy in C and every `if(alpnid)` in `lib/altsvc.c` is
    /// a test for "recognised". [`Default`] is derived onto this variant for
    /// the same reason `calloc` gives it to the C.
    #[default]
    None = 0,

    /// `ALPN_h1` -- HTTP/1.1, over TLS or not. Equals [`CURLALTSVC_H1`].
    H1 = CURLALTSVC_H1 as i32,

    /// `ALPN_h2` -- HTTP/2. Equals [`CURLALTSVC_H2`].
    H2 = CURLALTSVC_H2 as i32,

    /// `ALPN_h3` -- HTTP/3 over QUIC. Equals [`CURLALTSVC_H3`].
    H3 = CURLALTSVC_H3 as i32,
}

#[allow(dead_code)]
impl AlpnId {
    /// The discriminant, for masking against a `CURLALTSVC_*` bitmask.
    #[must_use]
    pub(crate) const fn bits(self) -> i64 {
        self as i64
    }

    /// True when this is a recognised protocol -- the C's `if(alpnid)`.
    #[must_use]
    pub(crate) const fn is_some(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// The name of an ALPN identifier -- supersedes `Curl_alpnid2str`
/// (`lib/altsvc.c:49-61`).
#[must_use]
#[allow(dead_code)]
pub(crate) const fn alpnid2str(id: AlpnId) -> &'static str {
    match id {
        AlpnId::H1 => "h1",
        AlpnId::H2 => "h2",
        AlpnId::H3 => H3VERSION,
        AlpnId::None => "", // `/* bad */`
    }
}

/// The ALPN identifier of a name -- supersedes `Curl_alpn2alpnid`
/// (`lib/connect.c:73-88`) and, since a span carries its own length,
/// `Curl_str2alpnid` (`:90-94`) as well.
///
/// The C is a length test followed by `memcmp`:
///
/// ```text
/// if(len == 2) { "h1" -> ALPN_h1; "h2" -> ALPN_h2; "h3" -> ALPN_h3; }
/// else if(len == 8) { "http/1.1" -> ALPN_h1; }
/// return ALPN_none; /* unknown, probably rubbish input */
/// ```
#[must_use]
#[allow(dead_code)]
pub(crate) fn alpn2alpnid(name: &[u8]) -> AlpnId {
    match name {
        // `if(len == 2)`
        b"h1" => AlpnId::H1,
        b"h2" => AlpnId::H2,
        b"h3" => AlpnId::H3,
        // `else if(len == 8)`
        b"http/1.1" => AlpnId::H1,
        // "unknown, probably rubbish input"
        _ => AlpnId::None,
    }
}

// The diagnostic sink -- the successor of `infof`.

/// Where this module's four diagnostics go.
#[allow(dead_code)]
pub(crate) trait AltSvcLog {
    /// Emits one diagnostic line, or discards it.
    fn infof(&self, message: fmt::Arguments<'_>);
}

/// The sink that discards -- `lib/curl_trc.h:212-215`, the arm C compiles
/// when tracing is disabled entirely.
///
/// Zero-sized, so passing it costs nothing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct NoLog;

impl AltSvcLog for NoLog {
    fn infof(&self, _message: fmt::Arguments<'_>) {}
}

/// A host span as text, for a diagnostic only.
#[allow(dead_code)]
struct HostText<'a>(&'a [u8]);

impl fmt::Display for HostText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(self.0))
    }
}

// The stored shapes -- `struct althost`, `struct altsvc`, `struct altsvcinfo`
// (`lib/altsvc.h:31-51`).

/// One end of an alternative: a host, a port and a protocol.
///
/// Supersedes `struct althost` (`lib/altsvc.h:31-35`):
///
/// ```text
/// struct althost { char *host; unsigned short port; enum alpnid alpnid; };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct AltHost {
    /// The host, unbracketed, never empty.
    pub(crate) host: Vec<u8>,
    /// The port. `unsigned short` in the C, and every producer bounds its
    /// input at 65535 before narrowing.
    pub(crate) port: u16,
    /// The protocol spoken at this end.
    pub(crate) alpn: AlpnId,
}

/// One cached alternative service.
///
/// Supersedes `struct altsvc` (`lib/altsvc.h:37-44`):
///
/// ```text
/// struct altsvc {
///   struct althost src; struct althost dst;
///   time_t expires; struct Curl_llist_node node;
///   unsigned int prio; BIT(persist);
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct AltSvc {
    /// The origin this alternative belongs to.
    pub(crate) src: AltHost,
    /// The alternative to use instead.
    pub(crate) dst: AltHost,
    /// When this entry stops being usable, in seconds since the Unix epoch.
    ///
    /// `time_t`, so `i64` on all four mandated targets. Zero is a perfectly
    /// ordinary value and means "expired at the epoch": it is what a line
    /// with an unparsable date produces (`lib/altsvc.c:169-172`).
    pub(crate) expires: i64,
    /// The priority field of the file format.
    ///
    /// Always zero. `lib/altsvc.c:178` sets it so with the comment *"not
    /// supported to just set zero"*, discarding whatever the file said, and
    /// `Curl_altsvc_parse` never assigns it at all. It is carried because it
    /// is the ninth field of a frozen file format and has to be written back.
    pub(crate) prio: u32,
    /// Whether the alternative survives a network change -- RFC 7838's
    /// `persist`. `BIT(persist)` is a one-bit field in the C.
    pub(crate) persist: bool,
}

#[allow(dead_code)]
impl AltSvc {
    /// Builds an entry from already-resolved protocol identifiers.
    fn createid(
        srchost: &[u8],
        dsthost: &[u8],
        srcalpn: AlpnId,
        dstalpn: AlpnId,
        srcport: u16,
        dstport: u16,
    ) -> Option<Self> {
        // `:72-80`. NOTE the shape: the trailing-dot strip is an `else if`,
        // so a bracketed source host NEVER has a trailing dot removed.
        let src = if let Some(inner) = strip_brackets(srchost) {
            inner
        } else if let Some((&b'.', rest)) = srchost.split_last() {
            // `:77-80` -- "strip off trailing dot".
            rest
        } else {
            srchost
        };

        // `:81-85`. The destination gets the bracket strip and NOTHING else:
        // there is no trailing-dot arm here. The asymmetry with the source is
        // real and is preserved.
        let dst = strip_brackets(dsthost).unwrap_or(dsthost);

        // `:86-88` -- "bad input".
        if src.is_empty() || dst.is_empty() {
            return None;
        }

        // `:89-104`. The C's single allocation carries the struct and both
        // strings; two owned vectors say the same thing without the pointer
        // arithmetic. The ports are the C's `(unsigned short)` narrowing at
        // `:102-103`, already applied by every caller.
        Some(Self {
            src: AltHost {
                host: src.to_vec(),
                port: srcport,
                alpn: srcalpn,
            },
            dst: AltHost {
                host: dst.to_vec(),
                port: dstport,
                alpn: dstalpn,
            },
            // `calloc` at `:89` zeroes the rest.
            expires: 0,
            prio: 0,
            persist: false,
        })
    }

    /// Builds an entry from ALPN names that still have to be resolved.
    ///
    /// Supersedes `altsvc_create` (`lib/altsvc.c:112-127`). Both names are
    /// resolved FIRST and [`None`] comes back if EITHER is unrecognised,
    /// which is the only reason a well-formed cache line is refused --
    /// `tests/data/test1654` relies on it for its `bad example.com ...` row.
    fn create(
        srchost: &[u8],
        dsthost: &[u8],
        srcalpn: &[u8],
        dstalpn: &[u8],
        srcport: u16,
        dstport: u16,
    ) -> Option<Self> {
        // `:118-119` -- destination first, exactly as the C evaluates them.
        let dstalpnid = alpn2alpnid(dstalpn);
        let srcalpnid = alpn2alpnid(srcalpn);

        // `:120-121` -- `if(!srcalpnid || !dstalpnid) return NULL;`
        if !srcalpnid.is_some() || !dstalpnid.is_some() {
            return None;
        }

        Self::createid(srchost, dsthost, srcalpnid, dstalpnid, srcport, dstport)
    }

    /// True when this entry answers a lookup for the given origin.
    ///
    /// The four conjuncts of `lib/altsvc.c:648-651`, in the C's order:
    ///
    /// ```text
    /// (as->src.alpnid == srcalpnid) &&
    /// hostcompare(srchost, as->src.host) &&
    /// (as->src.port == srcport) &&
    /// (versions & (int)as->dst.alpnid)
    /// ```
    fn matches_origin(
        &self,
        srcalpn: AlpnId,
        srchost: &[u8],
        srcport: u16,
        versions: i64,
    ) -> bool {
        self.src.alpn == srcalpn
            && hostcompare(srchost, &self.src.host)
            && self.src.port == srcport
            && (versions & self.dst.alpn.bits()) != 0
    }

    /// Writes this entry as one line of the cache file.
    ///
    /// ```text
    /// "%s %s%s%s %u %s %s%s%s %u \"%d%02d%02d %02d:%02d:%02d\" %u %u\n"
    /// ```
    ///
    /// with the source's ALPN name, its optional `[`, its host, its optional
    /// `]` and its port; the same five for the destination; the expiry in
    /// double quotes; then `persist` and `prio`. Four details are easy to lose
    /// and each is a byte of a frozen format:
    ///
    /// * The stamp is GMT, from `curlx_gmtime`, and the C's `tm_year + 1900`
    ///   and `tm_mon + 1` are already applied by
    ///   `crate::util::timeval::gmtime` and by the `+ 1` below respectively.
    /// * The YEAR is `%d` -- NOT zero-padded -- while every other field is
    ///   `%02d`.
    /// * There is **no `unlimited` special case**, unlike the HSTS cache:
    ///   `curlx_gmtime` is called unconditionally at `:240` and its failure
    ///   aborts the entry.
    /// * The brackets are decided per SIDE, by [`push_host`].
    ///
    /// # Errors
    ///
    /// Whatever `crate::util::timeval::gmtime` returns -- the C's only failure
    /// here, and it aborts the whole save. A failed WRITE is not reported; see
    /// [`AltSvcInfo::write_to`].
    fn write_line<W: Write>(&self, out: &mut W) -> CodeResult<()> {
        // `:240-242` -- computed first, and the only way out.
        let stamp = gmtime(self.expires)?;

        let mut line: Vec<u8> = Vec::new();

        // `"%s %s%s%s %u "` -- the source origin.
        line.extend_from_slice(alpnid2str(self.src.alpn).as_bytes());
        line.push(b' ');
        push_host(&mut line, &self.src.host);
        line.push(b' ');
        push_int(&mut line, i64::from(self.src.port), 1);
        line.push(b' ');

        // `"%s %s%s%s %u "` -- the destination.
        line.extend_from_slice(alpnid2str(self.dst.alpn).as_bytes());
        line.push(b' ');
        push_host(&mut line, &self.dst.host);
        line.push(b' ');
        push_int(&mut line, i64::from(self.dst.port), 1);
        line.push(b' ');

        // `"\"%d%02d%02d %02d:%02d:%02d\" "` -- the expiry, in GMT.
        line.push(b'"');
        push_int(&mut line, i64::from(stamp.year), 1);
        push_int(&mut line, i64::from(stamp.mon).saturating_add(1), 2);
        push_int(&mut line, i64::from(stamp.mday), 2);
        line.push(b' ');
        push_int(&mut line, i64::from(stamp.hour), 2);
        line.push(b':');
        push_int(&mut line, i64::from(stamp.min), 2);
        line.push(b':');
        push_int(&mut line, i64::from(stamp.sec), 2);
        line.push(b'"');
        line.push(b' ');

        // `"%u %u\n"` -- `persist` and the always-zero priority.
        push_int(&mut line, i64::from(self.persist), 1);
        line.push(b' ');
        push_int(&mut line, i64::from(self.prio), 1);
        line.push(b'\n');

        // WART, PRESERVED: `curl_mfprintf`'s result is not examined at `:256`,
        // so neither is this one. See [`AltSvcInfo::write_to`].
        let _ = out.write_all(&line);

        Ok(())
    }
}

/// What a successful [`AltSvcInfo::lookup`] hands back.
///
/// The C writes the matching entry through `struct altsvc **dstentry` and
/// reports sameness through `bool *psame_destination`
/// (`lib/altsvc.h:63-70`). Its caller then uses exactly three fields of that
/// entry and copies the host out of it -- `curlx_strdup(as->dst.host)` at
/// `lib/url.c:3022` -- so this carries those three by value plus the flag,
/// and the caller is left holding nothing that borrows the cache.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct AltSvcHit {
    /// The protocol to speak to the alternative -- `as->dst.alpnid`, the
    /// value `lib/url.c:3005-3053` switches on to choose the HTTP version and
    /// therefore the ALPN offered.
    pub(crate) alpn: AlpnId,
    /// The alternative's host, unbracketed -- `as->dst.host`.
    pub(crate) host: Vec<u8>,
    /// The alternative's port -- `as->dst.port`.
    pub(crate) port: u16,
    /// True when the alternative names the SAME host and port as the origin.
    pub(crate) same_destination: bool,
}

// Shared helpers.

/// The bracket strip of `altsvc_createid`, with its wart intact.
///
/// `lib/altsvc.c:73-76` and `:82-85`, which are the same three lines twice:
///
/// ```text
/// if((hlen > 2) && srchost[0] == '[') {
///   /* IPv6 address, strip off brackets */
///   srchost++;
///   hlen -= 2;
/// }
/// ```
#[allow(dead_code)]
fn strip_brackets(host: &[u8]) -> Option<&[u8]> {
    if host.len() > 2 && host.first() == Some(&b'[') {
        // `srchost++; hlen -= 2;` -- in range because the length exceeds two,
        // so the end index is at least two and the range is non-empty.
        host.get(1..host.len() - 1)
    } else {
        None
    }
}

/// True when `host` matches `check` -- supersedes `hostcompare`
/// (`lib/altsvc.c:399-410`).
///
/// Three properties, and getting any of them wrong changes which
/// alternatives are found:
///
/// * A trailing dot is ignored on the FIRST argument only. `tests/data/test412`
///   passes `whohoo.` from the URL against a stored `whohoo`, and
///   `tests/data/test413` stores `whohoo.` -- which
///   [`AltSvc::createid`] has already stripped -- and looks it up as `whohoo`.
/// * The lengths must then be EQUAL. The C says so in a comment: *"they
///   cannot match if they have different lengths"*, which is what keeps
///   `example.com` from matching `example.com.au`.
/// * The comparison is case-INSENSITIVE, through `curl_strnequal`.
#[allow(dead_code)]
fn hostcompare(host: &[u8], check: &[u8]) -> bool {
    // `if(hlen && (host[hlen - 1] == '.')) hlen--;`
    let hlen = match host.split_last() {
        Some((&b'.', rest)) => rest.len(),
        _ => host.len(),
    };

    // `if(hlen != clen) return FALSE;`
    if hlen != check.len() {
        return false;
    }

    // `return curl_strnequal(host, check, hlen);`
    ncasecompare(host, check, hlen)
}

/// `Curl_getdate_capped` over a byte span.
///
/// ```text
/// int rc = parsedate(p, tp);
/// return (rc == PARSEDATE_FAIL);
/// ```
#[allow(dead_code)]
fn getdate_capped_bytes(date: &[u8]) -> Option<i64> {
    match parsedate(date) {
        // `PARSEDATE_OK` and `PARSEDATE_LATER`, both of which have written
        // through the C's out-parameter.
        Outcome::Ok(seconds) | Outcome::Later(seconds) => Some(seconds),
        // `PARSEDATE_FAIL`, which leaves the caller's `expires` at zero.
        Outcome::Fail => None,
    }
}

/// Appends `value` in decimal, zero-padded to at least `width` digits.
#[allow(dead_code)]
fn push_int(out: &mut Vec<u8>, value: i64, width: usize) {
    // Twenty digits is `u64::MAX`, so the buffer cannot be outrun. The bound
    // check is written anyway to keep the loop total without an index panic.
    let mut digits = [0_u8; 20];
    let mut len = 0_usize;
    let mut rest = value.unsigned_abs();

    loop {
        let digit = (rest % 10) as u8;
        if let Some(slot) = digits.get_mut(len) {
            *slot = b'0' + digit;
            len += 1;
        }
        rest /= 10;
        if rest == 0 {
            break;
        }
    }

    if value < 0 {
        out.push(b'-');
    }
    for _ in len..width {
        out.push(b'0');
    }
    for index in (0..len).rev() {
        if let Some(&digit) = digits.get(index) {
            out.push(digit);
        }
    }
}

/// Appends a host, bracketed when it is a numeric IPv6 address.
#[allow(dead_code)]
fn push_host(out: &mut Vec<u8>, host: &[u8]) {
    let numeric_v6 = is_numeric_v6(host);
    if numeric_v6 {
        out.push(b'[');
    }
    out.extend_from_slice(host);
    if numeric_v6 {
        out.push(b']');
    }
}

/// `curlx_inet_pton(AF_INET6, host, buf) == 1`, as the platform answers it.
fn is_numeric_v6(host: &[u8]) -> bool {
    // The divergent shape: a final `:` whose predecessor is a hexadecimal
    // digit. `hexval` is the crate's own `ISXDIGIT` -- `strparse`'s tests
    // check that its accept set is that macro's for all 256 byte values --
    // so this classifies the byte exactly as the C would.
    let len = host.len();
    if host.last() == Some(&b':') && len >= 2 {
        if let Some(&before) = host.get(len - 2) {
            if hexval(before).is_some() {
                return false;
            }
        }
    }

    pton6(host).is_some()
}

// The file-line grammar -- the `||` chain of `altsvc_add`
// (`lib/altsvc.c:145-163`).

/// The nine fields of one cache-file line, as spans of that line.
///
/// ```text
/// h2 quic.tech 8443 h3-22 quic.tech 8443 "20190808 06:18:37" 0 0
/// ```
#[allow(dead_code)]
struct FileLine<'a> {
    /// Field 1: the source origin's ALPN name, at most
    /// [`MAX_ALTSVC_ALPNLEN`] bytes.
    srcalpn: &'a [u8],
    /// Field 2: the source origin's host, at most [`MAX_ALTSVC_HOSTLEN`].
    srchost: &'a [u8],
    /// Field 3: the source origin's port, at most 65535.
    srcport: i64,
    /// Field 4: the destination's ALPN name.
    dstalpn: &'a [u8],
    /// Field 5: the destination's host, bracketed if numeric IPv6.
    dsthost: &'a [u8],
    /// Field 6: the destination's port, at most 65535.
    dstport: i64,
    /// Field 7: the quoted expiry, at most [`MAX_ALTSVC_DATELEN`] bytes
    /// BETWEEN the quotes, and not unescaped.
    date: &'a [u8],
    /// Field 8: `persist`, at most 1 -- so only `0` and `1` parse.
    persist: i64,
}

#[allow(dead_code)]
impl<'a> FileLine<'a> {
    /// Parses one line, or refuses it.
    ///
    /// The eighteen steps of `lib/altsvc.c:145-163`, in order and one for
    /// one. The C writes them as a chain of `||` whose SUCCESS branch is the
    /// `else`, with an empty statement on the failure branch:
    ///
    /// ```text
    /// if(curlx_str_word(&line, &srcalpn, MAX_ALTSVC_ALPNLEN) || ... )
    ///   ;
    /// else { ...build the entry... }
    /// ```
    ///
    /// Three of the bounds are worth reading twice, because each rejects
    /// lines a reader might expect to be accepted:
    ///
    /// * every separator is [`str_singlespace`] -- EXACTLY one space, so two
    ///   spaces anywhere drop the line;
    /// * `persist` is bounded at 1, so `2` drops the line;
    /// * `prio` is bounded at ZERO, so anything but a literal `0` drops the
    ///   line -- and the value is discarded regardless.
    ///
    /// # Errors
    ///
    /// The [`StrError`] of the first step that failed. The caller discards it:
    /// `altsvc_add` returns `CURLE_OK` for a dropped line and its own comment
    /// says it *"only returns SERIOUS errors"*.
    fn parse(line: &'a [u8]) -> Result<Self, StrError> {
        let mut cursor = line;

        // 1, 2
        let srcalpn = str_word(&mut cursor, MAX_ALTSVC_ALPNLEN)?;
        str_singlespace(&mut cursor)?;
        // 3, 4
        let srchost = str_word(&mut cursor, MAX_ALTSVC_HOSTLEN)?;
        str_singlespace(&mut cursor)?;
        // 5, 6
        let srcport = str_number(&mut cursor, 65535)?;
        str_singlespace(&mut cursor)?;
        // 7, 8
        let dstalpn = str_word(&mut cursor, MAX_ALTSVC_ALPNLEN)?;
        str_singlespace(&mut cursor)?;
        // 9, 10
        let dsthost = str_word(&mut cursor, MAX_ALTSVC_HOSTLEN)?;
        str_singlespace(&mut cursor)?;
        // 11, 12
        let dstport = str_number(&mut cursor, 65535)?;
        str_singlespace(&mut cursor)?;
        // 13, 14 -- the quoted date. The bound is the RAW length between the
        // quotes, and nothing is unescaped.
        let date = str_quotedword(&mut cursor, MAX_ALTSVC_DATELEN)?;
        str_singlespace(&mut cursor)?;
        // 15, 16 -- `persist`, bounded at 1.
        let persist = str_number(&mut cursor, 1)?;
        str_singlespace(&mut cursor)?;
        // 17 -- WART, PRESERVED (`lib/altsvc.c:161`): the priority field is
        // bounded at ZERO, so `0` is the only value that parses, and
        // `:178` then discards whatever was read. The call is kept because
        // removing it would accept a line curl rejects.
        let _prio = str_number(&mut cursor, 0)?;
        // 18 -- the line must end here.
        str_newline(&mut cursor)?;

        Ok(Self {
            srcalpn,
            srchost,
            srcport,
            dstalpn,
            dsthost,
            dstport,
            date,
            persist,
        })
    }
}

// The cache -- `struct altsvcinfo` (`lib/altsvc.h:46-50`) and the
// library-wide functions of `lib/altsvc.c:280-660`.

/// The default flag set of a fresh cache -- `lib/altsvc.c:293-298`.
///
/// ```text
/// asi->flags = CURLALTSVC_H1
/// #ifdef USE_HTTP2
///   | CURLALTSVC_H2
/// #endif
/// #ifdef USE_HTTP3
///   | CURLALTSVC_H3
/// #endif
///   ;
/// ```
#[allow(dead_code)]
const DEFAULT_FLAGS: i64 = CURLALTSVC_H1 | DEFAULT_H2 | DEFAULT_H3;

/// The HTTP/2 bit of [`DEFAULT_FLAGS`] -- the C's `#ifdef USE_HTTP2` arm.
#[cfg(feature = "http2")]
#[allow(dead_code)]
const DEFAULT_H2: i64 = CURLALTSVC_H2;

/// No HTTP/2 bit -- the configuration in which the C's `#ifdef` contributes
/// nothing.
#[cfg(not(feature = "http2"))]
#[allow(dead_code)]
const DEFAULT_H2: i64 = 0;

/// The HTTP/3 bit of [`DEFAULT_FLAGS`] -- the C's `#ifdef USE_HTTP3` arm.
#[cfg(feature = "http3")]
#[allow(dead_code)]
const DEFAULT_H3: i64 = CURLALTSVC_H3;

/// No HTTP/3 bit -- the configuration in which the C's `#ifdef` contributes
/// nothing.
#[cfg(not(feature = "http3"))]
#[allow(dead_code)]
const DEFAULT_H3: i64 = 0;

/// The Alt-Svc cache: a file name, the entries, and the public bitmask.
///
/// Supersedes `struct altsvcinfo` (`lib/altsvc.h:46-50`):
///
/// ```text
/// struct altsvcinfo {
///   char *filename;
///   struct Curl_llist list; /* list of entries */
///   long flags;             /* the publicly set bitmask */
/// };
/// ```
///
/// # The order of the entries is part of the file format
///
/// A [`Vec`], and never a map. `Curl_altsvc_save` walks the list from
/// `Curl_llist_head` through `Curl_node_next` (`lib/altsvc.c:378-384`) and
/// every producer appends at the TAIL, so the file is written in insertion
/// order. A hash map would reorder it -- and with a randomised hash, it would
/// reorder it differently on every run -- which would change the bytes of a
/// file whose bytes are frozen. Lookup is a linear scan for the same reason it
/// is in the C: the order is the contract, and performance is a non-goal.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct AltSvcInfo {
    /// The file this cache was loaded from, kept so that a save with no name
    /// of its own can find it again.
    ///
    /// `lib/altsvc.c:201-207` copies the name before opening anything,
    /// with the comment *"we need a private copy of the filename so that the
    /// altsvc cache file name survives an easy handle reset"*.
    filename: Option<PathBuf>,

    /// The entries, in insertion order. See the type's documentation.
    list: Vec<AltSvc>,

    /// The `CURLOPT_ALTSVC_CTRL` bitmask, `long` in the C.
    flags: i64,
}

impl Default for AltSvcInfo {
    /// The same cache [`Self::new`] builds, flags included.
    ///
    /// Not derived: a derived [`Default`] would zero the flags, and a cache
    /// with no version bits set matches no alternative at all.
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl AltSvcInfo {
    /// Creates an empty cache with the default flags.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            filename: None,
            list: Vec::new(),
            flags: DEFAULT_FLAGS,
        }
    }

    /// The `CURLOPT_ALTSVC_CTRL` bitmask -- `asi->flags`.
    ///
    /// Read by `lib/url.c:2973` to limit which alternatives may be used, and
    /// by [`Self::save`] to honour [`CURLALTSVC_READONLYFILE`].
    #[must_use]
    pub(crate) fn flags(&self) -> i64 {
        self.flags
    }

    /// Replaces the bitmask -- supersedes `Curl_altsvc_ctrl`
    /// (`lib/altsvc.c:312-325`).
    ///
    /// # Errors
    ///
    /// `CURLcode::BadFunctionArgument` when `ctrl` is zero. The C refuses it
    /// outright -- `if(!ctrl) return CURLE_BAD_FUNCTION_ARGUMENT;` -- rather
    /// than treating it as "no versions allowed", and the bitmask is left
    /// untouched.
    pub(crate) fn ctrl(&mut self, ctrl: i64) -> CodeResult<()> {
        if ctrl == 0 {
            return Err(CURLcode::BadFunctionArgument);
        }
        self.flags = ctrl;
        Ok(())
    }

    /// Empties the cache -- supersedes `Curl_altsvc_cleanup`
    /// (`lib/altsvc.c:331-346`).
    ///
    /// The flags are deliberately NOT reset. They came from
    /// `CURLOPT_ALTSVC_CTRL` and outlive the entries, exactly as they do in
    /// the C where the whole structure is replaced rather than cleared.
    pub(crate) fn cleanup(&mut self) {
        self.list.clear();
        self.filename = None;
    }

    /// The file this cache was loaded from, if any -- `asi->filename`.
    #[must_use]
    pub(crate) fn filename(&self) -> Option<&Path> {
        self.filename.as_deref()
    }

    /// The entries, in the order they will be written.
    ///
    /// Shared and not mutable: the order is part of the file format, so
    /// nothing outside this module may reorder or insert.
    #[must_use]
    pub(crate) fn entries(&self) -> &[AltSvc] {
        &self.list
    }

    /// How many entries the cache holds -- the C's `Curl_llist_count`, which
    /// is what `tests/unit/unit1654.c` asserts against after every step.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.list.len()
    }

    /// True when the cache holds no entries.
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Loads entries from a file -- supersedes `Curl_altsvc_load`
    /// (`lib/altsvc.c:303-307`) and the `altsvc_load` it forwards to
    /// (`:197-227`).
    ///
    /// Two behaviours here surprise people, and both are the C's:
    ///
    /// * **A missing or unopenable file is NOT an error.** `:209` simply does
    ///   nothing when `fopen` returns null, and `CURLE_OK` comes back. Only a
    ///   file that opens and then misbehaves can fail.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::load_reader`] returns -- which for a real cache file
    /// means `CURLcode::TooLarge` for a line over [`MAX_ALTSVC_LINE`] bytes,
    /// or `CURLcode::ReadError`. `lib/setopt.c:2524` returns that straight out
    /// of `curl_easy_setopt`, so a malformed cache file can fail an
    /// application's option call; a malformed cache LINE cannot.
    pub(crate) fn load(&mut self, file: &Path) -> CodeResult<()> {
        // `:201-207` -- the private copy, before anything is opened.
        self.filename = Some(file.to_path_buf());

        // `:209-210` -- `fp = curlx_fopen(file, FOPEN_READTEXT); if(fp) {`.
        // No arm for the failure: the C has none either.
        let Ok(handle) = File::open(file) else {
            return Ok(());
        };

        let mut input = BufReader::new(handle);
        self.load_reader(&mut input)
    }

    /// Loads entries from an already-open reader.
    ///
    /// The loop is `:211-222`:
    ///
    /// ```text
    /// do {
    ///   result = Curl_get_line(&buf, fp, &eof);
    ///   if(!result) {
    ///     const char *lineptr = curlx_dyn_ptr(&buf);
    ///     curlx_str_passblanks(&lineptr);
    ///     if(curlx_str_single(&lineptr, '#'))
    ///       altsvc_add(asi, lineptr);
    ///   }
    /// } while(!result && !eof);
    /// ```
    ///
    /// Three details are load-bearing:
    ///
    /// * `curlx_str_single` reports FAILURE when the byte does not match, so
    ///   the test reads "add this line UNLESS it starts with `#`". Leading
    ///   blanks are skipped first, so an indented comment is still a comment
    ///   -- `tests/data/test1654` has one indented by four spaces.
    /// * There is **no empty-line short-circuit**, unlike `lib/hsts.c:521`. A
    ///   blank line goes to the grammar and is dropped there by the first
    ///   [`str_word`] failing. The path is reproduced rather than shortened,
    ///   because a shortcut here would be a different function with the same
    ///   output and nothing would prove it stayed that way.
    /// * `altsvc_add`'s return value is **discarded** at `:220`. A line that
    ///   names an unknown protocol reports `CURLE_OUT_OF_MEMORY` and the load
    ///   still succeeds; see [`Self::add`].
    ///
    /// # Errors
    ///
    /// Whatever [`get_line`] returns: `CURLcode::TooLarge` when a line exceeds
    /// [`MAX_ALTSVC_LINE`] bytes, or `CURLcode::ReadError`. The loop stops at
    /// the first such failure and the entries already read are KEPT, which is
    /// what the C's `while(!result && !eof)` does.
    pub(crate) fn load_reader<R: BufRead>(
        &mut self,
        input: &mut R,
    ) -> CodeResult<()> {
        // `:208` -- `curlx_dyn_init(&buf, MAX_ALTSVC_LINE)`.
        let mut buf = DynBuf::new(MAX_ALTSVC_LINE);

        loop {
            // `:213` -- the failure leaves the loop with the error, exactly as
            // the `while(!result ...)` condition does.
            let last = get_line(&mut buf, input)?;

            {
                let mut line: &[u8] = buf.as_slice();
                // `:216` -- `curlx_str_passblanks(&lineptr)`.
                str_passblanks(&mut line);
                // `:217-218` -- "add the line unless it starts with '#'".
                if str_single(&mut line, b'#').is_err() {
                    // `:219` -- the return value is DISCARDED.
                    let _ = self.add(line);
                }
            }

            if last {
                break;
            }
        }

        Ok(())
    }

    /// Adds one cache-file line -- supersedes `altsvc_add`
    /// (`lib/altsvc.c:130-187`), whose own comment is *"only returns SERIOUS
    /// errors"*.
    ///
    /// The grammar lives in [`FileLine::parse`]; what remains is the four
    /// steps after it, and three of the four are warts:
    ///
    /// * `:165-172` -- **`Curl_getdate_capped`'s result is IGNORED** and
    ///   `expires` starts at zero, so a date that will not parse produces an
    ///   entry that expired at the Unix epoch rather than a rejected line.
    ///   [`Self::lookup`] then deletes it the first time it is scanned, and
    ///   until then it is written back to the cache file verbatim.
    /// * `:178` -- **the priority is set to zero**, discarding whatever the
    ///   file said. The C's comment: *"not supported to just set zero"*.
    /// * `:182-183` -- **an unknown ALPN name reports
    ///   `CURLE_OUT_OF_MEMORY`**, which is not what happened. Nothing ran out
    ///   of anything: [`AltSvc::create`] refused the name. The code is
    ///   harmless because `:219` discards it, and it is reproduced because
    ///   this function is not the only possible caller.
    ///
    /// # Errors
    ///
    /// `CURLcode::OutOfMemory` for the third wart above, and nothing else. A
    /// line that fails the grammar returns `Ok(())` having changed nothing.
    fn add(&mut self, line: &[u8]) -> CodeResult<()> {
        // `:145-164` -- the chain, whose failure branch is an empty statement.
        let Ok(fields) = FileLine::parse(line) else {
            return Ok(());
        };

        // `:167-172`. The C copies the span into a terminated buffer because
        // its parser needs one; a span carries its own length here, so the
        // copy is gone and the bound that made it safe is [`str_quotedword`]'s.
        let mut expires: i64 = 0;
        if let Some(parsed) = getdate_capped_bytes(fields.date) {
            expires = parsed;
        }

        // `:173-174`. The ports are within range by construction: the grammar
        // bounded both at 65535.
        let created = AltSvc::create(
            fields.srchost,
            fields.dsthost,
            fields.srcalpn,
            fields.dstalpn,
            sltous(fields.srcport),
            sltous(fields.dstport),
        );

        match created {
            // `:176-181`
            Some(mut entry) => {
                entry.expires = expires;
                // WART, PRESERVED: `:178`.
                entry.prio = 0;
                entry.persist = fields.persist != 0;
                self.list.push(entry);
                Ok(())
            }
            // WART, PRESERVED: `:182-183`.
            None => Err(CURLcode::OutOfMemory),
        }
    }

    /// Writes the cache to a file, through a temporary when it is safe to.
    ///
    /// # Errors
    ///
    /// * Whatever `crate::util::fopen::open_for_write` returns, including
    ///   whatever `rand_suffix` returned.
    /// * `CURLcode::WriteError` if the rename of the temporary file over the
    ///   target fails, in which case the temporary is removed. That is the
    ///   C's `if(!result && tempstore && curlx_rename(tempstore, file))` at
    ///   `:385-390`, written once in the shared `commit`.
    /// * Whatever [`Self::write_to`] returns, in which case the temporary file
    ///   is removed and the target is left truncated -- the C's
    ///   `if(result && tempstore) unlink(tempstore);`.
    pub(crate) fn save<F>(
        &self,
        file: Option<&Path>,
        rand_suffix: F,
    ) -> CodeResult<()>
    where
        F: FnOnce() -> CodeResult<String>,
    {
        // `:363-364` -- "if not new name is given, use the one we stored from
        // the load".
        let Some(target) = file.or(self.filename.as_deref()) else {
            return Ok(());
        };

        // `:366-368` -- "marked as read-only, no file or zero length
        // filename". The `!file` arm of the C's condition is the `else` above.
        if (self.flags & CURLALTSVC_READONLYFILE) != 0
            || target.as_os_str().is_empty()
        {
            return Ok(());
        }

        // `:370` -- `result = Curl_fopen(data, file, &out, &tempstore);`
        //
        // `StoreClass::Public`: an Alt-Svc entry is a hostname and port the
        // server advertised in the clear, so there is nothing here to keep from
        // a local reader and the C's mode cloning is kept exactly. Only the
        // cookie jar is classified `Credential`.
        //
        // `NoFollow` carries the platform's `O_NOFOLLOW` from `crate::ffi`,
        // injected because `crate::util` may not name that module; see the
        // hardening section of `crate::util::fopen`.
        let mut opened = open_for_write(
            target,
            StoreClass::Public,
            NoFollow::new(O_NOFOLLOW | O_CLOEXEC),
            rand_suffix,
        )?;

        // `:371-384` -- the contents, then `:383-390`, the finish sequence.
        match self.write_to(opened.file_mut()) {
            Ok(()) => opened.commit(target),
            Err(code) => {
                opened.discard();
                Err(code)
            }
        }
    }

    /// Writes the whole cache to `out` -- the body of [`Self::save`], over any
    /// sink.
    ///
    /// # Errors
    ///
    /// Whatever `crate::util::timeval::gmtime` returns for an entry whose
    /// expiry has no representable calendar date. The C breaks out of its loop
    /// at the same point, so the file is left holding the entries written so
    /// far.
    pub(crate) fn write_to<W: Write>(&self, out: &mut W) -> CodeResult<()> {
        // `:373-377` -- one `fputs` of both lines, and nothing after them.
        let _ = out.write_all(HEADER_LINE_1);
        let _ = out.write_all(HEADER_LINE_2);

        // `:378-384` -- `Curl_llist_head` then `Curl_node_next`: insertion
        // order, which is the format.
        for entry in &self.list {
            entry.write_line(out)?;
        }

        Ok(())
    }

    /// Stores the alternatives of an incoming `Alt-Svc:` response header.
    ///
    /// # The grammar, and the two places it surprises
    ///
    /// The two surprises:
    ///
    /// * **An unrecognised protocol skips the alternative ENTIRELY** --
    ///   `if(dstalpnid)` at `:568`. No entry is created AND no flush happens.
    /// * **The flush fires on the first ACCEPTED alternative**, not at the
    ///   start -- `if(!entries++)` at `:569`. So a header whose every
    ///   alternative is skipped leaves the cache exactly as it was, and
    ///   `tests/data/test356` depends on that.
    ///
    /// # Errors
    ///
    /// `CURLcode::OutOfMemory` when an accepted alternative cannot be built,
    /// which happens for an empty host -- `:599-600`. `lib/http.c:3222`
    /// returns it into the header handler, so it fails the transfer. Every
    /// other rejection is silent, by design.
    pub(crate) fn parse(
        &mut self,
        value: &[u8],
        srcalpn: AlpnId,
        srchost: &[u8],
        srcport: u16,
        clock: &dyn Clock,
        log: &dyn AltSvcLog,
    ) -> CodeResult<()> {
        let mut p: &[u8] = value;

        // `:472-482` -- "initial check for 'clear'". The token runs to the
        // first `;`, CR or LF; a header of only blanks fails the extractor and
        // falls through, which is why the whole thing is guarded rather than
        // unwrapped.
        if let Ok(token) = str_cspn(&mut p, b";\n\r") {
            let token = str_trimblanks(token);
            // "'clear' is a magic keyword"
            if str_casecompare(token, b"clear") {
                // "Flush cached alternatives for this source origin"
                self.flush(srcalpn, srchost, srcport);
                return Ok(());
            }
        }

        // `:484` -- start over from the beginning of the value.
        p = value;

        // `:486-489`
        let Ok(span) = str_until(&mut p, MAX_ALTSVC_LINE, b'=') else {
            // "strange line"
            return Ok(());
        };
        let mut alpn = str_trimblanks(span);

        // `:469` -- the count of alternatives ACCEPTED so far, which is what
        // decides whether the flush has already happened.
        let mut entries = 0_usize;

        // `:491-617` -- `do { ... } while(1)`.
        loop {
            // `:492`, whose `else break` is at `:615-616`.
            if str_single(&mut p, b'=').is_err() {
                break;
            }

            // `:493-495`. "default is 24 hours".
            let mut maxage = DEFAULT_MAXAGE;
            let mut persist = false;
            let dstalpnid = alpn2alpnid(alpn);

            // `:497`, whose `else break` is at `:604-605`.
            if str_single(&mut p, b'"').is_err() {
                break;
            }

            // `:500-523` -- the destination host, in three cases. The C's
            // outer test is `if(curlx_str_single(&p, ':'))`, which is TRUE
            // when the next byte is NOT a colon and leaves the cursor
            // untouched.
            let dsthost: &[u8] = if str_single(&mut p, b':').is_err() {
                // "hostname starts here"
                let host = if str_single(&mut p, b'[').is_err() {
                    // Not bracketed: a name, up to the colon before the port.
                    // NOTE that the C's comments on these two arms are
                    // transposed -- the `[`-less arm is the plain host and the
                    // arm labelled "IPv6 hostname" is the one reached AFTER
                    // the bracket was consumed. The code is what is
                    // reproduced.
                    let Ok(host) = str_until(&mut p, MAX_ALTSVC_HOSTLEN, b':')
                    else {
                        log.infof(format_args!(
                            "Bad alt-svc hostname, ignoring."
                        ));
                        break;
                    };
                    host
                } else {
                    // The `[` has been consumed: a numeric IPv6 address, whose
                    // bound is MAX_IPADR_LEN and not MAX_ALTSVC_HOSTLEN.
                    let Ok(host) = str_until(&mut p, MAX_IPADR_LEN, b']')
                    else {
                        log.infof(format_args!(
                            "Bad alt-svc IPv6 hostname, ignoring."
                        ));
                        break;
                    };
                    // The second half of the C's `||`: the closing bracket,
                    // reported with the same message.
                    if str_single(&mut p, b']').is_err() {
                        log.infof(format_args!(
                            "Bad alt-svc IPv6 hostname, ignoring."
                        ));
                        break;
                    }
                    host
                };

                // `:518-519` -- the colon before the port. No message.
                if str_single(&mut p, b':').is_err() {
                    break;
                }
                host
            } else {
                // `:521-523` -- "no destination name, use source host".
                srchost
            };

            // `:525-529`
            let Ok(port) = str_number(&mut p, 0xffff) else {
                log.infof(format_args!(
                    "Unknown alt-svc port number, ignoring."
                ));
                break;
            };
            // `:531`. The C's `dstport` is declared outside the loop and is
            // always assigned here before it is read, so its initialiser at
            // `:466` is dead and a per-alternative binding is the same thing.
            let dstport = sltous(port);

            // `:533-534` -- the closing quote.
            if str_single(&mut p, b'"').is_err() {
                break;
            }

            // `:536-576` -- "Handle the optional 'ma' and 'persist' flags.
            // Unknown flags are skipped."
            str_passblanks(&mut p);
            if str_single(&mut p, b';').is_ok() {
                self.parse_params(&mut p, &mut maxage, &mut persist);
            }

            // `:568-601`
            if dstalpnid.is_some() {
                // `:569-573` -- "Flush cached alternatives for this source
                // origin, if any - when this is the first entry of the line."
                if entries == 0 {
                    self.flush(srcalpn, srchost, srcport);
                }
                entries += 1;

                // `:575-579`
                let created = AltSvc::createid(
                    srchost, dsthost, srcalpn, dstalpnid, srcport, dstport,
                );

                match created {
                    Some(mut entry) => {
                        // `:581-587` -- "The expires time also needs to take
                        // the Age: value (if any) into account. [See RFC 7838
                        // section 3.1]". The C clamps with
                        // `if(maxage > (TIME_T_MAX - secs))`, which for the
                        // non-negative operands this can produce is exactly a
                        // saturating addition.
                        entry.expires =
                            maxage.saturating_add(clock.epoch_secs());
                        entry.persist = persist;
                        // `:589` -- tail append, which is the file's order.
                        self.list.push(entry);
                        // `:590-593`
                        log.infof(format_args!(
                            "Added alt-svc: {}:{} over {}",
                            HostText(dsthost),
                            dstport,
                            alpnid2str(dstalpnid)
                        ));
                    }
                    // `:595-596`
                    None => return Err(CURLcode::OutOfMemory),
                }
            }

            // `:606-608` -- "after the double quote there can be a comma if
            // there is another string or a semicolon if no more".
            if str_single(&mut p, b',').is_err() {
                break;
            }

            // `:610-613` -- "comma means another alternative is present".
            let Ok(span) = str_until(&mut p, MAX_ALTSVC_LINE, b'=') else {
                break;
            };
            alpn = str_trimblanks(span);
        }

        Ok(())
    }

    /// Reads the `;`-separated parameters of one alternative.
    fn parse_params(
        &self,
        p: &mut &[u8],
        maxage: &mut i64,
        persist: &mut bool,
    ) {
        // `:538` -- `for(;;)`. The C's first exit is a chain of three
        // extractors (`:539-543`); the first of them is this loop's condition
        // and the other two stay explicit breaks, which is the same
        // short-circuit in the same order. "Allow some extra whitespaces around
        // name and value" is the C's comment on it, and the name's bound of
        // twenty bytes is written inline there.
        while let Ok(name) = str_until(p, MAX_ALTSVC_PARAMLEN, b'=') {
            if str_single(p, b'=').is_err() {
                break;
            }

            // The cursor at the value's first byte, kept so that the C's
            // pointer arithmetic can be reproduced below.
            let before: &[u8] = p;
            let Ok(val) = str_cspn(p, b",;") else {
                break;
            };

            // `:544-545`
            let name = str_trimblanks(name);

            // `:547-550` -- the trim, then `vp = curlx_str(&val)`, then
            // `if(quoted) vp++`. The trim's effect on the START is exactly the
            // count of leading blanks, and the index is in range because it
            // cannot exceed the span's own length.
            let lead = val.iter().take_while(|&&byte| is_blank(byte)).count();
            let Some(mut vp) = before.get(lead..) else {
                break;
            };
            let quoted = vp.first() == Some(&b'"');
            if quoted {
                let Some(rest) = vp.get(1..) else {
                    break;
                };
                vp = rest;
            }

            // `:551-558`
            let Ok(num) = str_number(&mut vp, TIME_T_MAX) else {
                // The C's `else break`: a value that is not a number ends the
                // parameter list rather than the alternative.
                break;
            };
            if str_casecompare(name, b"ma") {
                *maxage = num;
            } else if str_casecompare(name, b"persist") && num == 1 {
                // Any value other than 1 leaves the flag alone.
                *persist = true;
            }

            // `:560-561` -- "point to the byte ending the value".
            *p = vp;
            str_passblanks(p);

            // `:562-563` -- the closing quote, only if there was an opening
            // one.
            if quoted && str_single(p, b'"').is_err() {
                break;
            }
            str_passblanks(p);

            // `:565-566` -- another `;` continues the list.
            if str_single(p, b';').is_err() {
                break;
            }
        }
    }

    /// Finds a usable alternative for an origin, pruning expired entries.
    ///
    /// # This is the wire-parity path
    ///
    /// The answer decides which HTTP version the transfer negotiates and
    /// therefore which ALPN identifiers appear in the TLS ClientHello, and it
    /// decides whether an `Alt-Used:` request header is emitted. Each side of a
    /// fixture's `<protocol>` block is compared as ONE joined string, so a wrong
    /// answer here is a wrong byte on the wire.
    pub(crate) fn lookup(
        &mut self,
        srcalpn: AlpnId,
        srchost: &[u8],
        srcport: u16,
        versions: i64,
        clock: &dyn Clock,
    ) -> Option<AltSvcHit> {
        // `:632` -- the WALL clock.
        let now = clock.epoch_secs();

        // `:635-658`. An index rather than an iterator, because the walk
        // deletes as it goes -- the C's `n = Curl_node_next(e)` before the
        // removal is the same manoeuvre.
        let mut index = 0_usize;
        while index < self.list.len() {
            let Some(entry) = self.list.get(index) else {
                break;
            };

            // `:640-645` -- "an expired entry, remove". Note `<` and not
            // `<=`: an entry expiring exactly now is still usable.
            if entry.expires < now {
                self.list.remove(index);
                continue;
            }

            // `:648-657`
            if entry.matches_origin(srcalpn, srchost, srcport, versions) {
                return Some(AltSvcHit {
                    alpn: entry.dst.alpn,
                    host: entry.dst.host.clone(),
                    port: entry.dst.port,
                    // `:654-656`
                    same_destination: srcport == entry.dst.port
                        && hostcompare(srchost, &entry.dst.host),
                });
            }

            index += 1;
        }

        None
    }

    /// Removes every alternative cached for one source origin.
    pub(crate) fn flush(
        &mut self,
        srcalpn: AlpnId,
        srchost: &[u8],
        srcport: u16,
    ) {
        self.list.retain(|entry| {
            // `:422-424`, negated: keep what does NOT match.
            !(entry.src.alpn == srcalpn
                && entry.src.port == srcport
                && hostcompare(srchost, &entry.src.host))
        });
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::util::fopen::{RAND_ALPHABET, RAND_SUFFIX_LEN};
    use crate::util::parsedate::getdate_capped;
    use crate::util::timeval::TestClock;

    // The oracle: `tests/data/test1654`, transcribed.

    /// The instant `tests/data/test1654` pins, in seconds since the epoch.
    ///
    /// The fixture sets `CURL_TIME=1548369261` and its own comment states what
    /// that is: *"This date is exactly `20190124 22:34:21` UTC"*. The C reads
    /// it through the `altsvc_debugtime` shim at `lib/altsvc.c:431-447`; here
    /// it is the wall reading of an injected clock, which is the same input
    /// arriving by a better route.
    const UNIT1654_NOW: i64 = 1_548_369_261;

    /// The `<file>` block of `tests/data/test1654`, byte for byte.
    #[rustfmt::skip]
    const TEST1654_INPUT: &[u8] = concat!(
        "h2 example.com 443 h3 shiny.example.com 8443",
        " \"20191231 00:00:00\" 0 0\n",
        "# a comment\n",
        "h2 foo.example.com 443 h3 shiny.example.com 8443",
        " \"20291231 23:30:00\" 0 0\n",
        "  h1 example.com 443 h3 shiny.example.com 8443",
        " \"20121231 00:00:01\" 0 0\n",
        "\th3 example.com 443 h3 shiny.example.com 8443",
        " \"20131231 00:00:00\" 0 0\n",
        "    # also a comment\n",
        "bad example.com 443 h3 shiny.example.com 8443",
        " \"20191231 00:00:00\" 0 0\n",
        "rubbish\n",
    )
    .as_bytes();

    /// The four entry lines the input above is expected to produce, in order.
    ///
    /// The first four data lines of the fixture's expected output file, which
    /// is to say: the two plain lines and the two indented ones, with their
    /// indentation gone and everything else identical.
    #[rustfmt::skip]
    const TEST1654_LOADED: &[u8] = concat!(
        "h2 example.com 443 h3 shiny.example.com 8443",
        " \"20191231 00:00:00\" 0 0\n",
        "h2 foo.example.com 443 h3 shiny.example.com 8443",
        " \"20291231 23:30:00\" 0 0\n",
        "h1 example.com 443 h3 shiny.example.com 8443",
        " \"20121231 00:00:01\" 0 0\n",
        "h3 example.com 443 h3 shiny.example.com 8443",
        " \"20131231 00:00:00\" 0 0\n",
    )
    .as_bytes();

    /// The eight entry lines the parsed headers of `unit1654` add, in order.
    ///
    /// The remaining data lines of the fixture's expected output. Their stamps
    /// are what pin the max-age arithmetic: `20190125 22:34:21` is the default
    /// twenty-four hours after [`UNIT1654_NOW`], `22:36:21` is `ma=120` and
    /// `22:37:21` is `ma=180`.
    #[rustfmt::skip]
    const TEST1654_PARSED: &[u8] = concat!(
        "h1 example.org 8080 h2 example.com 8080",
        " \"20190125 22:34:21\" 0 0\n",
        "h1 2.example.org 8080 h3 2.example.org 8080",
        " \"20190125 22:34:21\" 0 0\n",
        "h1 3.example.org 8080 h2 example.com 8080",
        " \"20190125 22:34:21\" 0 0\n",
        "h1 3.example.org 8080 h3 yesyes.com 8080",
        " \"20190125 22:34:21\" 0 0\n",
        "h2 example.org 80 h2 example.com 443",
        " \"20190124 22:36:21\" 0 0\n",
        "h2 example.net 80 h2 example.net 443",
        " \"20190124 22:37:21\" 0 0\n",
        "h2 test.se 443 h2 test2.se 443",
        " \"20190124 22:37:21\" 0 0\n",
        "h2 test.se 443 h2 test3.se 443",
        " \"20190124 22:36:21\" 0 0\n",
    )
    .as_bytes();

    // Helpers. Every one of them works in memory, so the whole suite below
    // runs under Miri except where a test says otherwise.

    /// A clock whose wall reading is `secs`.
    ///
    /// [`TestClock`] starts its wall reading at the epoch deliberately, so a
    /// test is reproducible on a host whose clock is wrong; this places it.
    fn clock_at(secs: i64) -> TestClock {
        let clock = TestClock::default();
        clock.set_epoch_secs(secs);
        clock
    }

    /// Loads `text` as a cache file, returning the cache and the outcome.
    ///
    /// The outcome is returned rather than asserted because several tests are
    /// about it: a load can report `TooLarge` while still holding the entries
    /// it read.
    fn load(text: &[u8]) -> (AltSvcInfo, CodeResult<()>) {
        let mut cache = AltSvcInfo::new();
        let mut input = Cursor::new(text.to_vec());
        let outcome = cache.load_reader(&mut input);
        (cache, outcome)
    }

    /// Loads one line and returns how many entries it produced.
    ///
    /// The line is written exactly as given, so a test can omit the newline to
    /// check that the grammar's last step really is required.
    fn accepted(line: &[u8]) -> usize {
        load(line).0.len()
    }

    /// The bytes [`AltSvcInfo::write_to`] produces for a cache.
    fn dump(cache: &AltSvcInfo) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let outcome = cache.write_to(&mut out);
        assert!(outcome.is_ok(), "the writer failed: {outcome:?}");
        out
    }

    /// The two header lines followed by `entries`.
    fn expected_file(entries: &[&[u8]]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(HEADER_LINE_1);
        out.extend_from_slice(HEADER_LINE_2);
        for entry in entries {
            out.extend_from_slice(entry);
        }
        out
    }

    /// A cache holding exactly the entries of `text`, loaded with no clock.
    fn loaded(text: &[u8]) -> AltSvcInfo {
        let (cache, outcome) = load(text);
        assert_eq!(outcome, Ok(()), "this fixture must load cleanly");
        cache
    }

    /// The two stored hosts of a created entry, or [`None`] if it was refused.
    fn hosts(entry: &Option<AltSvc>) -> Option<(&[u8], &[u8])> {
        entry
            .as_ref()
            .map(|entry| (entry.src.host.as_slice(), entry.dst.host.as_slice()))
    }

    /// A byte slice as text, for an assertion message.
    ///
    /// Every fixture in this module is ASCII, so this never has to substitute
    /// anything; it exists so that a failure prints the line rather than a
    /// list of byte values.
    fn shown(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    // The public integers. Nothing here may drift.

    /// The four flag bits are the literals of `include/curl/curl.h:1032-1035`.
    ///
    /// Written as the shifted forms the header uses rather than as 4, 8, 16
    /// and 32, so that a reader comparing the two files sees the same
    /// expression.
    #[test]
    fn the_flag_bits_are_the_public_header_values() {
        assert_eq!(CURLALTSVC_READONLYFILE, 1 << 2);
        assert_eq!(CURLALTSVC_H1, 1 << 3);
        assert_eq!(CURLALTSVC_H2, 1 << 4);
        assert_eq!(CURLALTSVC_H3, 1 << 5);
    }

    /// The ALPN discriminants ARE those bits -- `lib/hostip.h:49-54`.
    ///
    /// The reason this matters is [`AltSvcInfo::lookup`], which ANDs a
    /// `CURLALTSVC_*` mask straight against a stored identifier. The absolute
    /// values are asserted as well as the equalities, so that a change to both
    /// sides at once still fails.
    #[test]
    fn the_alpn_discriminants_are_the_flag_bits() {
        assert_eq!(AlpnId::None.bits(), 0);
        assert_eq!(AlpnId::H1.bits(), CURLALTSVC_H1);
        assert_eq!(AlpnId::H2.bits(), CURLALTSVC_H2);
        assert_eq!(AlpnId::H3.bits(), CURLALTSVC_H3);

        assert_eq!(AlpnId::H1.bits(), 8);
        assert_eq!(AlpnId::H2.bits(), 16);
        assert_eq!(AlpnId::H3.bits(), 32);
    }

    /// [`AlpnId::None`] is the zero the C's `if(alpnid)` tests, and the
    /// default.
    #[test]
    fn none_is_zero_and_is_the_default() {
        assert_eq!(AlpnId::default(), AlpnId::None);
        assert!(!AlpnId::None.is_some());
        assert!(AlpnId::H1.is_some());
        assert!(AlpnId::H2.is_some());
        assert!(AlpnId::H3.is_some());
    }

    /// The name mapping is case-sensitive and length-exact --
    /// `lib/connect.c:73-88`.
    ///
    /// The rejected column is the point of the test: `H2` differs only in case
    /// and `h3-22` is the name `docs/ALTSVC.md` still shows in its example, and
    /// both answer [`AlpnId::None`].
    #[test]
    fn alpn_names_map_case_sensitively() {
        assert_eq!(alpn2alpnid(b"h1"), AlpnId::H1);
        assert_eq!(alpn2alpnid(b"h2"), AlpnId::H2);
        assert_eq!(alpn2alpnid(b"h3"), AlpnId::H3);
        assert_eq!(alpn2alpnid(b"http/1.1"), AlpnId::H1);

        for rejected in [
            &b"H1"[..],
            b"H2",
            b"H3",
            b"HTTP/1.1",
            b"h3-22",
            b"h3-29",
            b"h1 ",
            b" h1",
            b"h",
            b"h4",
            b"",
            b"http/1.0",
            b"http/2",
            // Exactly MAX_ALTSVC_ALPNLEN bytes: the grammar accepts the field
            // and this refuses the name.
            b"aaaaaaaaaa",
        ] {
            assert_eq!(
                alpn2alpnid(rejected),
                AlpnId::None,
                "{} must not be a recognised ALPN name",
                shown(rejected)
            );
        }
    }

    /// The name of each identifier, and the empty string the C marks
    /// `/* bad */`.
    #[test]
    fn alpnid2str_names_three_protocols_and_nothing_else() {
        assert_eq!(alpnid2str(AlpnId::H1), "h1");
        assert_eq!(alpnid2str(AlpnId::H2), "h2");
        assert_eq!(alpnid2str(AlpnId::H3), "h3");
        assert_eq!(alpnid2str(AlpnId::H3), H3VERSION);
        assert_eq!(alpnid2str(AlpnId::None), "");
    }

    /// Every recognised name survives a round trip through both conversions.
    #[test]
    fn the_two_conversions_are_inverses_for_recognised_names() {
        for id in [AlpnId::H1, AlpnId::H2, AlpnId::H3] {
            assert_eq!(alpn2alpnid(alpnid2str(id).as_bytes()), id);
        }
    }

    /// A fresh cache offers HTTP/1.1 always, and the versions that are built.
    ///
    /// `lib/altsvc.c:293-298`. The expectation is computed the same way the
    /// constant is, from [`cfg!`], because the answer legitimately differs
    /// between configurations -- what must hold in ALL of them is that H1 is
    /// present and that a version is offered exactly when it is compiled in.
    #[test]
    fn the_default_flags_follow_the_built_http_versions() {
        let cache = AltSvcInfo::new();
        assert_eq!(cache.flags() & CURLALTSVC_H1, CURLALTSVC_H1);
        assert_eq!(cache.flags() & CURLALTSVC_H2 != 0, cfg!(feature = "http2"));
        assert_eq!(cache.flags() & CURLALTSVC_H3 != 0, cfg!(feature = "http3"));
        // Never read-only by default: that bit only ever arrives through
        // `CURLOPT_ALTSVC_CTRL`.
        assert_eq!(cache.flags() & CURLALTSVC_READONLYFILE, 0);
        assert_eq!(AltSvcInfo::default().flags(), cache.flags());
    }

    // Host normalisation -- the three asymmetries of `altsvc_createid`.

    /// A trailing dot is stripped from the SOURCE host -- `:77-80`.
    ///
    /// `tests/data/test413` is this case: the cache file names `whohoo.` and
    /// the transfer asks for `whohoo`.
    #[test]
    fn a_trailing_dot_is_stripped_from_the_source_host() {
        let entry = AltSvc::createid(
            b"whohoo.",
            b"alt.ex",
            AlpnId::H1,
            AlpnId::H1,
            80,
            443,
        );
        assert_eq!(hosts(&entry), Some((&b"whohoo"[..], &b"alt.ex"[..])));
    }

    /// A trailing dot is NOT stripped from the DESTINATION host -- `:81-85`
    /// has no such arm.
    #[test]
    fn a_trailing_dot_survives_on_the_destination_host() {
        let entry = AltSvc::createid(
            b"origin.ex",
            b"alt.ex.",
            AlpnId::H1,
            AlpnId::H1,
            80,
            443,
        );
        assert_eq!(hosts(&entry), Some((&b"origin.ex"[..], &b"alt.ex."[..])));
    }

    /// A trailing dot survives a bracket strip, because the C's second arm is
    /// an `else if` -- `:72-80`.
    #[test]
    fn a_trailing_dot_survives_a_bracket_strip() {
        // The brackets go, and the dot inside them stays.
        let entry = AltSvc::createid(
            b"[fe80::1.]",
            b"alt.ex",
            AlpnId::H1,
            AlpnId::H1,
            80,
            443,
        );
        assert_eq!(hosts(&entry), Some((&b"fe80::1."[..], &b"alt.ex"[..])));
    }

    /// The bracket strip does not verify the closing bracket -- `:72-76`.
    ///
    /// WART. `[abc` loses its last byte, because the length is reduced by two
    /// on the strength of the opening bracket alone.
    #[test]
    fn the_bracket_strip_does_not_verify_the_closing_bracket() {
        let entry =
            AltSvc::createid(b"[abc", b"[def", AlpnId::H1, AlpnId::H1, 80, 443);
        assert_eq!(hosts(&entry), Some((&b"ab"[..], &b"de"[..])));
    }

    /// Brackets are stripped independently on each side.
    #[test]
    fn brackets_are_stripped_from_either_side() {
        let cases: [(&[u8], &[u8], &[u8], &[u8]); 4] = [
            (b"[::1]", b"alt.ex", b"::1", b"alt.ex"),
            (b"origin.ex", b"[::1]", b"origin.ex", b"::1"),
            (b"[::1]", b"[ffff::2]", b"::1", b"ffff::2"),
            (b"a.ex", b"b.ex", b"a.ex", b"b.ex"),
        ];
        for (srchost, dsthost, src, dst) in cases {
            let entry = AltSvc::createid(
                srchost,
                dsthost,
                AlpnId::H1,
                AlpnId::H2,
                80,
                443,
            );
            assert_eq!(
                hosts(&entry),
                Some((src, dst)),
                "{} / {} normalised wrongly",
                shown(srchost),
                shown(dsthost)
            );
        }
    }

    /// A host that is empty, or becomes empty, is refused -- `:86-88`.
    ///
    /// `[]` is the interesting one: it is three bytes, so the strip applies and
    /// leaves nothing.
    #[test]
    fn an_empty_host_is_refused() {
        let bad: [(&[u8], &[u8]); 5] = [
            (b"", b"alt.ex"),
            (b"origin.ex", b""),
            (b"", b""),
            (b"[.]", b"alt.ex"),
            (b"origin.ex", b"[.]"),
        ];
        for (srchost, dsthost) in bad {
            // `[.]` strips to `.`, which is NOT empty -- so only the genuinely
            // empty pairs are refused, and the bracketed dot is accepted.
            let entry = AltSvc::createid(
                srchost,
                dsthost,
                AlpnId::H1,
                AlpnId::H1,
                80,
                443,
            );
            if srchost.is_empty() || dsthost.is_empty() {
                assert!(
                    entry.is_none(),
                    "an empty host must be refused: {} / {}",
                    shown(srchost),
                    shown(dsthost)
                );
            } else {
                assert!(entry.is_some(), "a bracketed dot is not empty");
            }
        }
    }

    /// [`AltSvc::create`] refuses an unrecognised name on EITHER side --
    /// `:120-121`.
    #[test]
    fn an_unrecognised_alpn_name_refuses_the_entry() {
        let good = AltSvc::create(b"a.ex", b"b.ex", b"h1", b"h2", 1, 2);
        assert!(good.is_some());

        for (srcalpn, dstalpn) in
            [(&b"bad"[..], &b"h2"[..]), (b"h1", b"bad"), (b"bad", b"bad")]
        {
            assert!(
                AltSvc::create(b"a.ex", b"b.ex", srcalpn, dstalpn, 1, 2)
                    .is_none(),
                "{} / {} must be refused",
                shown(srcalpn),
                shown(dstalpn)
            );
        }
    }

    /// The port narrowing of `:102-103`, at both ends of the range.
    #[test]
    fn ports_are_carried_through_unchanged() {
        let entry = AltSvc::createid(
            b"a.ex",
            b"b.ex",
            AlpnId::H1,
            AlpnId::H3,
            0,
            65535,
        );
        // The whole structure, so that the fields `calloc` zeroes at `:89` are
        // asserted too rather than assumed.
        assert_eq!(
            entry,
            Some(AltSvc {
                src: AltHost {
                    host: b"a.ex".to_vec(),
                    port: 0,
                    alpn: AlpnId::H1,
                },
                dst: AltHost {
                    host: b"b.ex".to_vec(),
                    port: 65535,
                    alpn: AlpnId::H3,
                },
                expires: 0,
                prio: 0,
                persist: false,
            })
        );
    }

    // The on-disk format. THE headline contract of this module.

    /// A cache file written by curl 8.19.0-DEV reads back and writes out
    /// IDENTICALLY.
    #[test]
    fn a_c_produced_cache_file_round_trips_byte_for_byte() {
        let cache = loaded(TEST1654_INPUT);
        assert_eq!(cache.len(), 4, "four of the eight lines are entries");
        assert_eq!(
            shown(&dump(&cache)),
            shown(&expected_file(&[TEST1654_LOADED]))
        );
    }

    /// An empty cache is exactly the two comment lines -- `:373-377`.
    ///
    /// No trailing blank line, unlike the Netscape cookie jar, and no version
    /// marker, unlike the HSTS cache.
    #[test]
    fn an_empty_cache_writes_only_the_two_comment_lines() {
        let text = dump(&AltSvcInfo::new());
        assert_eq!(
            shown(&text),
            "# Your alt-svc cache. https://curl.se/docs/alt-svc.html\n\
             # This file was generated by libcurl! Edit at your own risk.\n"
        );
        // Nothing after the second newline, and no blank line between them.
        assert!(text.ends_with(b"risk.\n"));
        assert_eq!(text.iter().filter(|&&byte| byte == b'\n').count(), 2);
    }

    /// A numeric IPv6 host loses its brackets on the way in and regains them on
    /// the way out -- independently on each side.
    ///
    /// `tests/data/test437` is the destination case: an `Alt-Svc:` header of
    /// `h1="[ffff::1]:8181"` is saved as
    /// `h1 <origin> <port> h1 [ffff::1] 8181`.
    #[test]
    fn numeric_ipv6_hosts_are_rebracketed_on_each_side() {
        let cases: [(&[u8], &[u8]); 4] = [
            // Destination only.
            (
                b"h1 ex.com 443 h1 [ffff::1] 8181 \"20291231 00:00:00\" 0 0\n",
                b"h1 ex.com 443 h1 [ffff::1] 8181 \"20291231 00:00:00\" 0 0\n",
            ),
            // Source only.
            (
                b"h1 [::1] 443 h1 ex.com 8181 \"20291231 00:00:00\" 0 0\n",
                b"h1 [::1] 443 h1 ex.com 8181 \"20291231 00:00:00\" 0 0\n",
            ),
            // Both.
            (
                b"h2 [::1] 443 h3 [ffff::2] 8181 \"20291231 00:00:00\" 1 0\n",
                b"h2 [::1] 443 h3 [ffff::2] 8181 \"20291231 00:00:00\" 1 0\n",
            ),
            // Neither -- a name that merely contains colons is not an address.
            (
                b"h1 a.ex 443 h1 b.ex 8181 \"20291231 00:00:00\" 0 0\n",
                b"h1 a.ex 443 h1 b.ex 8181 \"20291231 00:00:00\" 0 0\n",
            ),
        ];

        for (input, expected) in cases {
            let cache = loaded(input);
            assert_eq!(cache.len(), 1, "{} must load", shown(input));
            assert_eq!(
                shown(&dump(&cache)),
                shown(&expected_file(&[expected])),
                "{} did not round trip",
                shown(input)
            );
        }
    }

    /// The stored host has NO brackets, which is what the round trip rests on.
    #[test]
    fn brackets_are_not_part_of_the_stored_host() {
        let cache = loaded(
            b"h1 [::1] 443 h1 [ffff::2] 8181 \"20291231 00:00:00\" 0 0\n",
        );
        let Some(entry) = cache.entries().first() else {
            assert_eq!(cache.len(), 1, "the line must load");
            return;
        };
        assert_eq!(entry.src.host, b"::1");
        assert_eq!(entry.dst.host, b"ffff::2");
    }

    /// A host that curl's own address parser rejects gets NO brackets.
    ///
    /// A zone identifier is the case that separates `crate::util::inet::pton6`
    /// from Rust's own parser, and the answer decides a byte of the file.
    #[test]
    fn a_zone_identifier_is_not_a_numeric_address() {
        let mut out: Vec<u8> = Vec::new();
        push_host(&mut out, b"fe80::1%eth0");
        assert_eq!(shown(&out), "fe80::1%eth0");

        out.clear();
        push_host(&mut out, b"fe80::1");
        assert_eq!(shown(&out), "[fe80::1]");
    }

    /// The whole bracketing decision, differentially verified against C.
    #[test]
    fn the_bracketing_decision_matches_the_c_address_parser() {
        let cases: [(&[u8], bool); 37] = [
            // Accepted by both.
            (b"::1", true),
            (b"ffff::1", true),
            (b"ffff::2", true),
            (b"::", true),
            (b"1:2:3:4:5:6:7:8", true),
            (b"1::8", true),
            (b"1::", true),
            (b"0::0", true),
            (b"0:0:0:0:0:0:0:1", true),
            (b"::2:3:4:5:6:7:8", true),
            (b"FFFF::1", true),
            (b"::ffff:0:1", true),
            // The embedded dotted quad, which both accept.
            (b"::ffff:1.2.3.4", true),
            (b"::1.2.3.4", true),
            (b"1:2:3:4:5:6:1.2.3.4", true),
            // Refused by both: not addresses at all.
            (b"", false),
            (b":", false),
            (b":::", false),
            (b"1.2.3.4", false),
            (b"example.com", false),
            (b"whohoo", false),
            (b"nowhere.foo", false),
            (b"3dbb.example", false),
            (b"h3", false),
            // Refused by both: an address with something wrong with it.
            (b"::1%eth0", false),
            (b"fe80::1%1", false),
            (b"1:2:3:4:5:6:7:8:9", false),
            (b"1:2:3:4:5:6:7", false),
            (b"1::2::3", false),
            (b"12345::", false),
            (b"::00001", false),
            // Refused by both: brackets and blanks are not part of a host.
            (b"[::1]", false),
            (b"ffff::1]", false),
            (b"::1 ", false),
            (b" ::1", false),
            // A trailing colon: numeric only when it closes a `::`.
            (b"::1:", false),
            (b"1:2:3:4:5:6:7:8:", false),
        ];

        for (host, bracketed) in cases {
            let mut out: Vec<u8> = Vec::new();
            push_host(&mut out, host);
            // Bracketing adds exactly two bytes, so the length is an
            // unambiguous witness even when the host itself starts with `[`.
            assert_eq!(
                out.len() == host.len() + 2,
                bracketed,
                "wrong bracketing for {}",
                shown(host)
            );
            if bracketed {
                assert_eq!(out.first(), Some(&b'['), "{}", shown(host));
                assert_eq!(out.last(), Some(&b']'), "{}", shown(host));
            } else {
                assert_eq!(shown(&out), shown(host));
            }
        }
    }

    /// Padding, sign and width -- the `%d` and `%02d` of the stamp.
    #[test]
    fn the_number_formatter_matches_the_c_conversions() {
        let cases: [(i64, usize, &str); 9] = [
            (0, 1, "0"),
            (0, 2, "00"),
            (7, 2, "07"),
            (12, 2, "12"),
            (2019, 1, "2019"),
            (999, 1, "999"),
            (65535, 1, "65535"),
            (-44, 1, "-44"),
            (i64::MIN, 1, "-9223372036854775808"),
        ];
        for (value, width, expected) in cases {
            let mut out: Vec<u8> = Vec::new();
            push_int(&mut out, value, width);
            assert_eq!(shown(&out), expected);
        }
    }

    /// The year is NOT zero-padded, while the other five fields are -- `:258`.
    ///
    /// Reached through the writer rather than through the formatter, with an
    /// expiry in the first century so that the year is three digits.
    #[test]
    fn the_year_is_not_zero_padded() {
        // 0099-01-02 03:04:05 UTC, which `crate::util::timeval::gmtime`
        // resolves and which no four-digit year can demonstrate.
        let expires = -59_042_897_755_i64;
        let entry = AltSvc {
            src: AltHost {
                host: b"a.ex".to_vec(),
                port: 80,
                alpn: AlpnId::H1,
            },
            dst: AltHost {
                host: b"b.ex".to_vec(),
                port: 443,
                alpn: AlpnId::H2,
            },
            expires,
            prio: 0,
            persist: false,
        };
        let mut out: Vec<u8> = Vec::new();
        let outcome = entry.write_line(&mut out);
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            shown(&out),
            "h1 a.ex 80 h2 b.ex 443 \"990102 03:04:05\" 0 0\n"
        );
    }

    /// `persist` and the always-zero priority are the last two fields.
    #[test]
    fn persist_is_written_as_one_or_zero() {
        let text = concat!(
            "h1 a.ex 80 h2 b.ex 443 \"20291231 00:00:00\" 1 0\n",
            "h1 c.ex 80 h2 d.ex 443 \"20291231 00:00:00\" 0 0\n",
        )
        .as_bytes();
        let cache = loaded(text);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.entries().first().map(|e| e.persist), Some(true));
        assert_eq!(cache.entries().get(1).map(|e| e.persist), Some(false));
        assert_eq!(shown(&dump(&cache)), shown(&expected_file(&[text])));
    }

    /// A failed write is NOT reported -- `:256`, `:375`.
    ///
    /// WART. The C examines neither `curl_mfprintf` nor `fputs`, so a full disk
    /// produces a truncated file and `CURLE_OK`. Propagating instead would
    /// change what [`AltSvcInfo::save`] leaves on disk.
    #[test]
    fn a_failed_write_is_not_reported() {
        /// A sink that refuses everything.
        struct FullDisk;

        impl Write for FullDisk {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("no space left on device"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let cache = loaded(TEST1654_INPUT);
        assert_eq!(cache.write_to(&mut FullDisk), Ok(()));
    }

    /// An expiry with no calendar date aborts the save -- `:240-242`.
    ///
    /// The C's `curlx_gmtime` failure is the ONLY error `altsvc_out` can
    /// report, and `Curl_altsvc_save` breaks its loop on it, leaving the file
    /// holding whatever was written first. Both halves are asserted.
    #[test]
    fn an_unrepresentable_expiry_aborts_the_save() {
        let mut cache = AltSvcInfo::new();
        let good = AltSvc {
            src: AltHost {
                host: b"a.ex".to_vec(),
                port: 80,
                alpn: AlpnId::H1,
            },
            dst: AltHost {
                host: b"b.ex".to_vec(),
                port: 443,
                alpn: AlpnId::H2,
            },
            expires: 0,
            prio: 0,
            persist: false,
        };
        let mut bad = good.clone();
        bad.expires = i64::MAX;
        cache.list.push(good);
        cache.list.push(bad);

        let mut out: Vec<u8> = Vec::new();
        assert!(cache.write_to(&mut out).is_err());
        // The header and the first entry are there; the second is not.
        assert_eq!(
            shown(&out),
            shown(&expected_file(&[
                b"h1 a.ex 80 h2 b.ex 443 \"19700101 00:00:00\" 0 0\n"
            ]))
        );
    }

    // The file reader -- what it accepts and, mostly, what it drops.

    /// The one line every rejection case below is a mutation of.
    const GOOD_LINE: &[u8] =
        b"h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n";

    /// The reference line loads, so the rejections below are about their
    /// mutation and not about the line's shape.
    #[test]
    fn the_reference_line_loads() {
        assert_eq!(accepted(GOOD_LINE), 1);
    }

    /// Blanks before a line are skipped, and a comment is still a comment after
    /// them -- `:216-218`.
    #[test]
    fn leading_blanks_are_skipped_and_comments_are_dropped() {
        let cases: [(&[u8], usize); 6] = [
            (b"  h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n", 1),
            (
                b"\t\th2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n",
                1,
            ),
            (b"# a comment\n", 0),
            (b"    # an indented comment\n", 0),
            (b"#\n", 0),
            (b"#h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n", 0),
        ];

        for (line, expected) in cases {
            assert_eq!(accepted(line), expected, "{}", shown(line));
        }
    }

    /// Every one of these is dropped in silence -- the C's empty statement at
    /// `:164`.
    #[test]
    fn a_malformed_line_is_dropped_without_a_word() {
        let cases: [(&[u8], usize, &str); 19] = [
            (b"\n", 0, "a blank line, dropped by the grammar not a shortcut"),
            (b"rubbish\n", 0, "not a cache line at all"),
            (b"   \n", 0, "blanks only"),
            (
                b"h2  a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n",
                0,
                "two spaces where the grammar takes exactly one",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 20291231 00:00:00 0 0\n",
                0,
                "an unquoted date",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 \"20290222 22:19:028\" 0 0\n",
                0,
                "a date of 18 bytes, one over the ceiling -- see test355",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 2 0\n",
                0,
                "persist of 2, over its bound of 1",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 1\n",
                0,
                "prio of 1, over its bound of ZERO",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 01\n",
                0,
                "prio of 01 -- the second digit takes the value past zero",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 00\n",
                1,
                "prio of 00 IS accepted: the C's number parser accepts leading \
                 zeroes, and a bound of zero refuses the VALUE, not the digits",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0\n",
                0,
                "the priority field missing entirely",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0 x\n",
                0,
                "trailing junk after the priority",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0",
                1,
                "no line ending -- the READER supplies one, so this loads",
            ),
            (
                b"h2 a.ex 65536 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n",
                0,
                "a source port over 65535",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 65536 \"20291231 00:00:00\" 0 0\n",
                0,
                "a destination port over 65535",
            ),
            (
                b"h2 a.ex -1 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n",
                0,
                "a negative port -- the number parser is unsigned",
            ),
            (
                b"aaaaaaaaaaa a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0",
                0,
                "an ALPN field of 11 bytes, one over MAX_ALTSVC_ALPNLEN",
            ),
            (
                b"h2 a.ex 443 h3 b.ex 8443 \"\" 0 0\n",
                1,
                "an empty date IS accepted: str_quotedword has no minimum, and \
                 the unparsable date then expires at the epoch",
            ),
            (
                b"h2 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n",
                0,
                "a field missing from the middle",
            ),
        ];

        for (line, expected, why) in cases {
            assert_eq!(accepted(line), expected, "{why}: {}", shown(line));
        }
    }

    /// A host of exactly [`MAX_ALTSVC_HOSTLEN`] loads and one byte more does
    /// not.
    ///
    /// The bound is inclusive, because the C tests `if(++len > max)` after the
    /// increment.
    #[test]
    fn the_host_ceiling_is_inclusive() {
        for (len, expected) in
            [(MAX_ALTSVC_HOSTLEN, 1), (MAX_ALTSVC_HOSTLEN + 1, 0)]
        {
            let mut line: Vec<u8> = Vec::new();
            line.extend_from_slice(b"h2 ");
            line.extend(std::iter::repeat(b'a').take(len));
            line.extend_from_slice(
                b" 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n",
            );
            assert_eq!(accepted(&line), expected, "host of {len} bytes");
        }
    }

    /// An ALPN field of exactly [`MAX_ALTSVC_ALPNLEN`] passes the grammar and
    /// is then refused as a name.
    #[test]
    fn the_alpn_ceiling_is_inclusive_and_the_name_is_still_checked() {
        let (cache, outcome) = load(
            b"aaaaaaaaaa a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n",
        );
        // The grammar accepted the field, so `altsvc_add` reached
        // `altsvc_create` -- which refused the name and reported the wart.
        assert_eq!(outcome, Ok(()), "the LOAD still succeeds");
        assert_eq!(cache.len(), 0);
    }

    /// A date that will not parse yields an entry expiring at the epoch --
    /// `:169-172`.
    ///
    /// WART. The C ignores `Curl_getdate_capped`'s result, so the line is
    /// ACCEPTED with `expires` left at its initial zero rather than rejected.
    #[test]
    fn an_unparsable_date_expires_at_the_epoch() {
        let cache = loaded(b"h2 a.ex 443 h3 b.ex 8443 \"nonsense\" 0 0\n");
        assert_eq!(cache.len(), 1, "the line is accepted, not rejected");
        assert_eq!(cache.entries().first().map(|e| e.expires), Some(0));

        // And it is written back with the epoch as its stamp.
        assert_eq!(
            shown(&dump(&cache)),
            shown(&expected_file(&[
                b"h2 a.ex 443 h3 b.ex 8443 \"19700101 00:00:00\" 0 0\n"
            ]))
        );
    }

    /// An unknown ALPN name reports out of memory, and the load still succeeds
    /// -- `:182-183` and `:219`.
    ///
    /// WART. Both halves are asserted, because it is the discarded return value
    /// at `:219` that makes the misleading code harmless.
    #[test]
    fn an_unknown_alpn_reports_out_of_memory_yet_the_load_succeeds() {
        let mut cache = AltSvcInfo::new();
        assert_eq!(
            cache.add(b"bad a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n"),
            Err(CURLcode::OutOfMemory)
        );
        assert!(cache.is_empty());

        // Through the loader, the same line is simply absent and the load is
        // clean -- which is what `tests/data/test1654` relies on.
        let (cache, outcome) =
            load(b"bad a.ex 443 h3 b.ex 8443 \"20291231 00:00:00\" 0 0\n");
        assert_eq!(outcome, Ok(()));
        assert!(cache.is_empty());
    }

    /// A line over the ceiling fails the WHOLE load -- `:210` and `:213`.
    ///
    /// The entries read before it are kept, which is what the C's
    /// `while(!result && !eof)` does, and `lib/setopt.c:2524` hands the code
    /// back out of `curl_easy_setopt`.
    #[test]
    fn a_line_over_the_ceiling_fails_the_load_and_keeps_what_was_read() {
        let mut text: Vec<u8> = Vec::new();
        text.extend_from_slice(GOOD_LINE);
        text.extend(std::iter::repeat(b'x').take(MAX_ALTSVC_LINE + 1));
        text.push(b'\n');
        text.extend_from_slice(GOOD_LINE);

        let (cache, outcome) = load(&text);
        assert_eq!(outcome, Err(CURLcode::TooLarge));
        assert_eq!(
            cache.len(),
            1,
            "the entry read before the failure survives"
        );
    }

    /// An empty file is not an error and produces nothing.
    #[test]
    fn an_empty_file_loads_to_an_empty_cache() {
        let (cache, outcome) = load(b"");
        assert_eq!(outcome, Ok(()));
        assert!(cache.is_empty());
    }

    /// A final line without a newline still parses, because [`get_line`]
    /// synthesises one.
    #[test]
    fn a_missing_final_newline_is_supplied_by_the_reader() {
        let mut line = GOOD_LINE.to_vec();
        assert_eq!(line.pop(), Some(b'\n'));
        assert_eq!(accepted(&line), 1);
    }

    /// [`getdate_capped_bytes`] agrees with the designated `getdate_capped` for
    /// every span that is text.
    ///
    /// The equivalence this module relies on, pinned so the two cannot drift.
    /// The last row is why the byte form exists at all: it is not UTF-8, so the
    /// designated function cannot be offered it.
    #[test]
    fn the_byte_date_parser_agrees_with_the_text_one() {
        for text in [
            "20191231 00:00:00",
            "20291231 23:30:00",
            "20121231 00:00:01",
            "19700101 00:00:00",
            "20190124 22:34:21",
            "nonsense",
            "",
            "99999999 00:00:00",
        ] {
            assert_eq!(
                getdate_capped_bytes(text.as_bytes()),
                getdate_capped(text),
                "the two parsers disagree about {text:?}"
            );
        }

        // Not text, so only the byte form can be asked -- and it refuses.
        assert_eq!(getdate_capped_bytes(&[0xff, 0xfe]), None);
    }

    // The `Alt-Svc:` header grammar.

    /// Parses one header into `cache` at the instant `now`.
    fn parse_at(
        cache: &mut AltSvcInfo,
        value: &[u8],
        srcalpn: AlpnId,
        srchost: &[u8],
        srcport: u16,
        now: i64,
    ) -> CodeResult<()> {
        let clock = clock_at(now);
        cache.parse(value, srcalpn, srchost, srcport, &clock, &NoLog)
    }

    /// A cache holding whatever one header produced, parsed at
    /// [`UNIT1654_NOW`].
    fn from_header(
        value: &[u8],
        srcalpn: AlpnId,
        srchost: &[u8],
        srcport: u16,
    ) -> AltSvcInfo {
        let mut cache = AltSvcInfo::new();
        let outcome = parse_at(
            &mut cache,
            value,
            srcalpn,
            srchost,
            srcport,
            UNIT1654_NOW,
        );
        assert_eq!(outcome, Ok(()), "{} must parse", shown(value));
        cache
    }

    /// The destination of the single entry a header produced.
    fn only_destination(cache: &AltSvcInfo) -> Option<(&[u8], u16, AlpnId)> {
        cache.entries().first().map(|entry| {
            (entry.dst.host.as_slice(), entry.dst.port, entry.dst.alpn)
        })
    }

    /// A sink that records what it was told, so the C's four diagnostics can be
    /// asserted.
    #[derive(Debug, Default)]
    struct Recorder {
        lines: std::cell::RefCell<Vec<String>>,
    }

    impl AltSvcLog for Recorder {
        fn infof(&self, message: fmt::Arguments<'_>) {
            self.lines.borrow_mut().push(message.to_string());
        }
    }

    /// One well-formed alternative, with an explicit host and port.
    #[test]
    fn an_alternative_names_a_host_and_a_port() {
        let cache =
            from_header(b"h2=\"alt.ex:443\"\r\n", AlpnId::H1, b"a.ex", 80);
        assert_eq!(cache.len(), 1);
        assert_eq!(
            only_destination(&cache),
            Some((&b"alt.ex"[..], 443, AlpnId::H2))
        );
        // The origin is what was passed in, not what the header said.
        assert_eq!(
            cache.entries().first().map(|e| (
                e.src.host.clone(),
                e.src.port,
                e.src.alpn
            )),
            Some((b"a.ex".to_vec(), 80, AlpnId::H1))
        );
    }

    /// An omitted host means the origin's own -- `:521-523`.
    ///
    /// `h3=":8080"` is `tests/unit/unit1654.c`'s second case and the reason the
    /// expected output has `h1 2.example.org 8080 h3 2.example.org 8080`.
    #[test]
    fn an_omitted_host_reuses_the_origin() {
        let cache = from_header(
            b"h3=\":8443\"\r\n",
            AlpnId::H1,
            b"2.example.org",
            8080,
        );
        assert_eq!(
            only_destination(&cache),
            Some((&b"2.example.org"[..], 8443, AlpnId::H3))
        );
    }

    /// A bracketed numeric address is stored unbracketed -- `:509-516`.
    #[test]
    fn a_bracketed_ipv6_alternative_is_stored_unbracketed() {
        let cache =
            from_header(b"h3=\"[::1]:443\"\r\n", AlpnId::H1, b"a.ex", 80);
        assert_eq!(
            only_destination(&cache),
            Some((&b"::1"[..], 443, AlpnId::H3))
        );
        // And regains its brackets in the file.
        assert!(shown(&dump(&cache)).contains("h3 [::1] 443 "));
    }

    /// Every malformed alternative is rejected, and nothing is stored.
    ///
    /// The `Ok(())` is as much the assertion as the count: the C's own comment
    /// promises that invalid data is refused *"without returning an error"*.
    #[test]
    fn a_malformed_alternative_is_rejected_without_an_error() {
        let cases: [(&[u8], &str); 14] = [
            (
                b"h2=\"alt.ex\"\r\n",
                "no port at all -- tests/data/test1654",
            ),
            (b"h2=\"alt.ex:\"\r\n", "a colon and no digits"),
            (b"h2=\"alt.ex:70000\"\r\n", "a port over 65535"),
            (b"h2=\"alt.ex:-1\"\r\n", "a negative port"),
            (
                b"h2=\"alt.ex:-18446744073709551614\"\r\n",
                "the huge negative port of tests/data/test356",
            ),
            (b"h2=\"alt.ex:443\r\n", "no closing quote"),
            (
                b"h2=\"example.net:443,; ma=\"180\";\r\n",
                "the missing quote of tests/unit/unit1654.c",
            ),
            (b"h2=alt.ex:443\r\n", "no opening quote"),
            (
                b"h2=\"[::1:443\"\r\n",
                "an IPv6 host with no closing bracket",
            ),
            (b"h2=\"[]:443\"\r\n", "an empty bracketed host"),
            (b"h2=\"[\"\r\n", "a bracket and nothing else"),
            (b"h2\r\n", "no equals sign"),
            (b"\r\n", "an empty value"),
            (b"h2=\"\"\r\n", "an empty quoted destination"),
        ];

        for (value, why) in cases {
            let cache = from_header(value, AlpnId::H1, b"a.ex", 80);
            assert_eq!(
                cache.len(),
                0,
                "{why} must store nothing: {}",
                shown(value)
            );
        }
    }

    /// `ma` sets the expiry, quoted or not, and a blank inside the quotes is
    /// trimmed.
    ///
    /// The third row is `tests/unit/unit1654.c`'s `ma="180 "`, which is also
    /// what proves the value is read through a pointer rather than a bounded
    /// span.
    #[test]
    fn the_max_age_parameter_sets_the_expiry() {
        let cases: [(&[u8], i64); 6] = [
            (b"h2=\"alt.ex:443\"\r\n", DEFAULT_MAXAGE),
            (b"h2=\"alt.ex:443\"; ma=120\r\n", 120),
            (b"h2=\"alt.ex:443\"; ma = 120;\r\n", 120),
            (b"h2=\"alt.ex:443\"; ma=\"180\";\r\n", 180),
            (b"h2=\"alt.ex:443\"; ma=\"180 \" ;\r\n", 180),
            (b"h2=\"alt.ex:443\"; MA=3600;\r\n", 3600),
        ];

        for (value, maxage) in cases {
            let cache = from_header(value, AlpnId::H1, b"a.ex", 80);
            assert_eq!(
                cache.entries().first().map(|entry| entry.expires),
                Some(UNIT1654_NOW + maxage),
                "{} must expire {maxage} seconds from now",
                shown(value)
            );
        }
    }

    /// `persist` is set by the value `1` and by nothing else -- `:555-556`.
    #[test]
    fn persist_is_set_only_by_exactly_one() {
        let cases: [(&[u8], bool); 7] = [
            (b"h2=\"alt.ex:443\"\r\n", false),
            (b"h2=\"alt.ex:443\"; persist=1\r\n", true),
            (b"h2=\"alt.ex:443\"; persist = \"1\";\r\n", true),
            (b"h2=\"alt.ex:443\"; PERSIST=1\r\n", true),
            (b"h2=\"alt.ex:443\"; persist=0\r\n", false),
            (b"h2=\"alt.ex:443\"; persist=2\r\n", false),
            (b"h2=\"alt.ex:443\"; persist=11\r\n", false),
        ];

        for (value, persist) in cases {
            let cache = from_header(value, AlpnId::H1, b"a.ex", 80);
            assert_eq!(
                cache.entries().first().map(|entry| entry.persist),
                Some(persist),
                "{}",
                shown(value)
            );
        }
    }

    /// An unknown parameter is parsed and ignored, and does not stop the list.
    #[test]
    fn an_unknown_parameter_is_ignored() {
        let cache = from_header(
            b"h2=\"alt.ex:443\"; unknown=2; ma=99\r\n",
            AlpnId::H1,
            b"a.ex",
            80,
        );
        assert_eq!(
            cache.entries().first().map(|entry| entry.expires),
            Some(UNIT1654_NOW + 99)
        );
    }

    /// A parameter whose value is not a number ends the list -- the C's
    /// `else break` at `:557-558`.
    ///
    /// The alternative itself is still stored: the break leaves the parameter
    /// loop, not the alternative.
    #[test]
    fn a_non_numeric_parameter_value_ends_the_list() {
        let cache = from_header(
            b"h2=\"alt.ex:443\"; ma=soon; persist=1\r\n",
            AlpnId::H1,
            b"a.ex",
            80,
        );
        assert_eq!(cache.len(), 1, "the alternative survives");
        assert_eq!(
            cache.entries().first().map(|entry| entry.expires),
            Some(UNIT1654_NOW + DEFAULT_MAXAGE),
            "ma was never applied"
        );
        assert_eq!(
            cache.entries().first().map(|entry| entry.persist),
            Some(false),
            "and the list ended before persist was read"
        );
    }

    /// A parameter NAME over twenty bytes ends the list -- `:539`.
    #[test]
    fn a_parameter_name_over_twenty_bytes_ends_the_list() {
        // Twenty bytes exactly: read, unrecognised, ignored, and `ma` after it
        // still applies.
        let cache = from_header(
            b"h2=\"alt.ex:443\";aaaaaaaaaaaaaaaaaaaa=2; ma=55\r\n",
            AlpnId::H1,
            b"a.ex",
            80,
        );
        assert_eq!(
            cache.entries().first().map(|entry| entry.expires),
            Some(UNIT1654_NOW + 55)
        );

        // Twenty-one: the extractor refuses, the list ends, `ma` never runs.
        let cache = from_header(
            b"h2=\"alt.ex:443\";aaaaaaaaaaaaaaaaaaaaa=2; ma=55\r\n",
            AlpnId::H1,
            b"a.ex",
            80,
        );
        assert_eq!(
            cache.entries().first().map(|entry| entry.expires),
            Some(UNIT1654_NOW + DEFAULT_MAXAGE)
        );

        // Twenty bytes WITH a leading blank is a twenty-one byte span, so it is
        // refused too: the blank is inside the span the bound applies to.
        let cache = from_header(
            b"h2=\"alt.ex:443\"; aaaaaaaaaaaaaaaaaaaa=2; ma=55\r\n",
            AlpnId::H1,
            b"a.ex",
            80,
        );
        assert_eq!(
            cache.entries().first().map(|entry| entry.expires),
            Some(UNIT1654_NOW + DEFAULT_MAXAGE)
        );
    }

    /// A comma introduces another alternative, and both are stored --
    /// `:606-613`.
    ///
    /// This is the case that fails if the parameter value is read as a bounded
    /// span instead of a pointer: the first `ma=180` would swallow the rest of
    /// the header and `h3` would be lost.
    #[test]
    fn comma_separated_alternatives_are_all_stored() {
        let cache = from_header(
            b"h2=\":443\"; ma=180, h3=\":443\"; persist = \"1\"; ma = 120;\r\n",
            AlpnId::H1,
            b"curl.se",
            80,
        );
        assert_eq!(cache.len(), 2, "both alternatives must survive");

        let seen: Vec<(AlpnId, u16, i64, bool)> = cache
            .entries()
            .iter()
            .map(|entry| {
                (entry.dst.alpn, entry.dst.port, entry.expires, entry.persist)
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                (AlpnId::H2, 443, UNIT1654_NOW + 180, false),
                (AlpnId::H3, 443, UNIT1654_NOW + 120, true),
            ]
        );
    }

    /// A comma-separated alternative whose protocol is unknown is skipped and
    /// the rest is unaffected -- `tests/data/test356`.
    #[test]
    fn an_unknown_protocol_among_several_is_skipped() {
        let cache = from_header(
            b"h1=\"nowhere.foo:81\", un-kno22!wn=\":82\"\r\n",
            AlpnId::H1,
            b"a.ex",
            80,
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(
            only_destination(&cache),
            Some((&b"nowhere.foo"[..], 81, AlpnId::H1))
        );
    }

    /// `clear` flushes this origin and parses nothing else -- `:472-482`.
    ///
    /// With and without the trailing semicolon, in either case, and with blanks
    /// around it. `tests/unit/unit1654.c` uses the first two spellings.
    #[test]
    fn clear_flushes_the_origin_and_stops() {
        for value in [
            &b"clear;\r\n"[..],
            b"clear\r\n",
            b"CLEAR;\r\n",
            b" clear ;\r\n",
            b"Clear",
            // Anything after the keyword is not parsed, so this stores nothing.
            b"clear; h2=\"alt.ex:443\"\r\n",
        ] {
            let mut cache =
                loaded(b"h1 a.ex 80 h2 b.ex 443 \"20291231 00:00:00\" 0 0\n");
            assert_eq!(cache.len(), 1);
            let outcome = parse_at(
                &mut cache,
                value,
                AlpnId::H1,
                b"a.ex",
                80,
                UNIT1654_NOW,
            );
            assert_eq!(outcome, Ok(()));
            assert!(cache.is_empty(), "{} must clear the origin", shown(value));
        }
    }

    /// `clear` flushes only the origin it was received from.
    #[test]
    fn clear_leaves_other_origins_alone() {
        let mut cache = loaded(
            concat!(
                "h1 a.ex 80 h2 b.ex 443 \"20291231 00:00:00\" 0 0\n",
                "h1 a.ex 81 h2 b.ex 443 \"20291231 00:00:00\" 0 0\n",
                "h2 a.ex 80 h2 b.ex 443 \"20291231 00:00:00\" 0 0\n",
                "h1 z.ex 80 h2 b.ex 443 \"20291231 00:00:00\" 0 0\n",
            )
            .as_bytes(),
        );
        assert_eq!(cache.len(), 4);
        let outcome = parse_at(
            &mut cache,
            b"clear\r\n",
            AlpnId::H1,
            b"a.ex",
            80,
            UNIT1654_NOW,
        );
        assert_eq!(outcome, Ok(()));
        // Only the first row matched all three of protocol, port and host.
        assert_eq!(cache.len(), 3);
    }

    /// A fresh header REPLACES what the origin said before -- `:569-573`.
    #[test]
    fn the_first_accepted_alternative_flushes_the_origin() {
        let mut cache =
            loaded(b"h1 a.ex 80 h2 old.ex 443 \"20291231 00:00:00\" 0 0\n");
        let outcome = parse_at(
            &mut cache,
            b"h2=\"new.ex:443\"\r\n",
            AlpnId::H1,
            b"a.ex",
            80,
            UNIT1654_NOW,
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(cache.len(), 1);
        assert_eq!(
            only_destination(&cache),
            Some((&b"new.ex"[..], 443, AlpnId::H2))
        );
    }

    /// A header whose EVERY alternative is skipped leaves the cache untouched.
    ///
    /// WART, and the reason `if(!entries++)` is where it is: the flush fires on
    /// the first ACCEPTED alternative, so an entirely unrecognised header
    /// cannot silently discard what the origin said last time.
    /// `tests/data/test356` and `tests/unit/unit1654.c` both depend on it.
    #[test]
    fn a_header_of_only_unknown_protocols_leaves_the_cache_untouched() {
        for value in [
            &b"h6=\"example.net:443\"; ma=\"180\";\r\n"[..],
            b"h3-22=\"example.net:443\"\r\n",
            b"H2=\"example.net:443\"\r\n",
            b"h6=\":443\", h7=\":444\"\r\n",
        ] {
            let mut cache =
                loaded(b"h1 a.ex 80 h2 old.ex 443 \"20291231 00:00:00\" 0 0\n");
            let outcome = parse_at(
                &mut cache,
                value,
                AlpnId::H1,
                b"a.ex",
                80,
                UNIT1654_NOW,
            );
            assert_eq!(outcome, Ok(()));
            assert_eq!(cache.len(), 1, "{} must change nothing", shown(value));
            assert_eq!(
                only_destination(&cache),
                Some((&b"old.ex"[..], 443, AlpnId::H2))
            );
        }
    }

    /// The flush fires ONCE, so two alternatives from one header coexist.
    #[test]
    fn the_second_alternative_does_not_flush_the_first() {
        let cache = from_header(
            b"h2=\"one.ex:443\", h3=\"two.ex:443\"\r\n",
            AlpnId::H1,
            b"a.ex",
            80,
        );
        assert_eq!(cache.len(), 2);
        let hosts: Vec<Vec<u8>> = cache
            .entries()
            .iter()
            .map(|entry| entry.dst.host.clone())
            .collect();
        assert_eq!(hosts, vec![b"one.ex".to_vec(), b"two.ex".to_vec()]);
    }

    /// An expiry that would overflow is clamped -- `:584-585`.
    #[test]
    fn an_overflowing_expiry_is_clamped() {
        let mut cache = AltSvcInfo::new();
        let value = b"h2=\"alt.ex:443\"; ma=9223372036854775807\r\n";
        let outcome =
            parse_at(&mut cache, value, AlpnId::H1, b"a.ex", 80, 1_000);
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            cache.entries().first().map(|entry| entry.expires),
            Some(TIME_T_MAX)
        );
    }

    /// An empty origin host reports out of memory -- `:595-596`.
    ///
    /// The one error [`AltSvcInfo::parse`] can return, and it reaches the
    /// transfer through `lib/http.c:3222`.
    #[test]
    fn an_empty_origin_host_reports_out_of_memory() {
        let mut cache = AltSvcInfo::new();
        let outcome = parse_at(
            &mut cache,
            b"h2=\"alt.ex:443\"\r\n",
            AlpnId::H1,
            b"",
            80,
            UNIT1654_NOW,
        );
        assert_eq!(outcome, Err(CURLcode::OutOfMemory));
        assert!(cache.is_empty());
    }

    /// The four diagnostics, verbatim -- `:503`, `:511`, `:519`, `:597`.
    #[test]
    fn the_diagnostics_are_reproduced_verbatim() {
        let cases: [(&[u8], &str); 5] = [
            (
                // A value that ends at the opening quote. This is the ONLY way
                // to reach the hostname message short of a host over 2048
                // bytes: `str_until` does not require its delimiter, so a
                // MISSING COLON yields a span rather than a failure and the
                // alternative is refused later, in silence.
                b"h2=\"",
                "Bad alt-svc hostname, ignoring.",
            ),
            (
                b"h2=\"[::1:443\"\r\n",
                "Bad alt-svc IPv6 hostname, ignoring.",
            ),
            (b"h2=\"[]:443\"\r\n", "Bad alt-svc IPv6 hostname, ignoring."),
            (
                b"h2=\"alt.ex:70000\"\r\n",
                "Unknown alt-svc port number, ignoring.",
            ),
            (
                b"h3=\"alt.ex:443\"\r\n",
                "Added alt-svc: alt.ex:443 over h3",
            ),
        ];

        for (value, expected) in cases {
            let mut cache = AltSvcInfo::new();
            let clock = clock_at(UNIT1654_NOW);
            let log = Recorder::default();
            let outcome =
                cache.parse(value, AlpnId::H1, b"a.ex", 80, &clock, &log);
            assert_eq!(outcome, Ok(()));
            assert_eq!(log.lines.borrow().as_slice(), &[expected.to_string()]);
        }
    }

    /// A rejected alternative that produces no message produces no message.
    ///
    /// The C logs nothing for a missing colon before the port, a missing
    /// closing quote or an unknown protocol, and neither does this.
    #[test]
    fn the_silent_rejections_stay_silent() {
        for value in [
            &b"h2=\"alt.ex:443\r\n"[..],
            b"h6=\"alt.ex:443\"\r\n",
            b"h2=alt.ex\r\n",
            b"clear\r\n",
        ] {
            let mut cache = AltSvcInfo::new();
            let clock = clock_at(UNIT1654_NOW);
            let log = Recorder::default();
            let outcome =
                cache.parse(value, AlpnId::H1, b"a.ex", 80, &clock, &log);
            assert_eq!(outcome, Ok(()));
            assert!(
                log.lines.borrow().is_empty(),
                "{} must say nothing",
                shown(value)
            );
        }
    }

    /// The four stamps of `tests/data/test1654` parse to the instants its
    /// expected output implies.
    #[test]
    fn the_fixtures_stamps_parse_to_the_expected_instants() {
        let cache = loaded(TEST1654_INPUT);
        let expires: Vec<i64> =
            cache.entries().iter().map(|entry| entry.expires).collect();
        assert_eq!(
            expires,
            vec![
                1_577_750_400, // 20191231 00:00:00
                1_893_454_200, // 20291231 23:30:00
                1_356_912_001, // 20121231 00:00:01
                1_388_448_000, // 20131231 00:00:00
            ]
        );
    }

    /// Every assertion of `tests/unit/unit1654.c`, in order, plus the file
    /// comparison the fixture makes afterwards.
    ///
    /// The clock stands in for the `CURL_TIME=1548369261` the fixture exports
    /// and the `altsvc_debugtime` shim that reads it (`lib/altsvc.c:431-447`).
    #[test]
    fn the_unit1654_sequence_reproduces_the_fixtures_output() {
        let clock = clock_at(UNIT1654_NOW);
        let mut cache = AltSvcInfo::new();

        // `Curl_altsvc_load(asi, arg)` then
        // `fail_unless(Curl_llist_count(&asi->list) == 4)`.
        let mut input = Cursor::new(TEST1654_INPUT.to_vec());
        assert_eq!(cache.load_reader(&mut input), Ok(()));
        assert_eq!(cache.len(), 4, "wrong number of entries");

        // Each row is one `Curl_altsvc_parse` call and the count the C asserts
        // immediately after it. The header values are transcribed VERBATIM
        // from the C, so the two rows that run past this file's eightieth
        // column stay on one line: re-wrapping a byte-exact fixture is how a
        // fixture stops being one.
        let steps: [(&[u8], AlpnId, &[u8], u16, usize); 14] = [
            (b"h2=\"example.com:8080\"\r\n", AlpnId::H1, b"example.org", 8080, 5),
            (b"h3=\":8080\"\r\n", AlpnId::H1, b"2.example.org", 8080, 6),
            (
                b"h2=\"example.com:8080\", h3=\"yesyes.com:8080\"\r\n",
                AlpnId::H1,
                b"3.example.org",
                8080,
                // "that one should make two entries"
                8,
            ),
            (
                b"h2=\"example.com:443\"; ma = 120;\r\n",
                AlpnId::H2,
                b"example.org",
                80,
                9,
            ),
            // "quoted 'ma' value"
            (
                b"h2=\"example.net:443\"; ma=\"180\";\r\n",
                AlpnId::H2,
                b"example.net",
                80,
                10,
            ),
            (
                b"h2=\":443\"; ma=180, h3=\":443\"; persist = \"1\"; ma = 120;\r\n",
                AlpnId::H1,
                b"curl.se",
                80,
                12,
            ),
            // "clear that one again and decrease the counter"
            (b"clear;\r\n", AlpnId::H1, b"curl.se", 80, 10),
            (
                b"h2=\":443\", h3=\":443\"; persist = \"1\"; ma = 120;\r\n",
                AlpnId::H1,
                b"curl.se",
                80,
                12,
            ),
            // "clear - without semicolon"
            (b"clear\r\n", AlpnId::H1, b"curl.se", 80, 10),
            // "only a non-existing alpn"
            (
                b"h6=\"example.net:443\"; ma=\"180\";\r\n",
                AlpnId::H2,
                b"5.example.net",
                80,
                10,
            ),
            // "missing quote in alpn host"
            (
                b"h2=\"example.net:443,; ma=\"180\";\r\n",
                AlpnId::H2,
                b"6.example.net",
                80,
                10,
            ),
            // "missing port in hostname"
            (
                b"h2=\"example.net\"; ma=\"180\";\r\n",
                AlpnId::H2,
                b"7.example.net",
                80,
                10,
            ),
            // "illegal port in hostname"
            (
                b"h2=\"example.net:70000\"; ma=\"180\";\r\n",
                AlpnId::H2,
                b"8.example.net",
                80,
                10,
            ),
            (
                b"h2=\"test2.se:443\"; ma=\"180 \" ; unknown=2, \
                  h2=\"test3.se:443\"; ma = 120;\r\n",
                AlpnId::H2,
                b"test.se",
                443,
                12,
            ),
        ];

        for (index, (value, srcalpn, srchost, srcport, expected)) in
            steps.into_iter().enumerate()
        {
            let outcome =
                cache.parse(value, srcalpn, srchost, srcport, &clock, &NoLog);
            assert_eq!(
                outcome,
                Ok(()),
                "step {index} must not fail: {}",
                shown(value)
            );
            assert_eq!(
                cache.len(),
                expected,
                "step {index} left the wrong number of entries: {}",
                shown(value)
            );
        }

        // `Curl_altsvc_save(curl, asi, outname)`, and then the fixture's
        // byte-for-byte comparison of the twelve lines it wrote.
        assert_eq!(
            shown(&dump(&cache)),
            shown(&expected_file(&[TEST1654_LOADED, TEST1654_PARSED]))
        );
    }

    // The bitmask, the accessors and emptying.

    /// A zero bitmask is refused -- `:314-315`.
    #[test]
    fn a_zero_bitmask_is_a_bad_function_argument() {
        let mut cache = AltSvcInfo::new();
        let before = cache.flags();
        assert_eq!(cache.ctrl(0), Err(CURLcode::BadFunctionArgument));
        assert_eq!(cache.flags(), before, "the bitmask must be untouched");
    }

    /// A non-zero bitmask REPLACES the default, rather than adding to it.
    #[test]
    fn a_bitmask_replaces_the_default() {
        let mut cache = AltSvcInfo::new();
        assert_eq!(cache.ctrl(CURLALTSVC_H1), Ok(()));
        assert_eq!(cache.flags(), CURLALTSVC_H1);
        assert_eq!(cache.flags() & CURLALTSVC_H2, 0);
        assert_eq!(cache.flags() & CURLALTSVC_H3, 0);

        assert_eq!(cache.ctrl(CURLALTSVC_READONLYFILE), Ok(()));
        assert_eq!(cache.flags(), CURLALTSVC_READONLYFILE);
    }

    /// Emptying drops the entries and the remembered name, and keeps the flags.
    #[test]
    fn emptying_keeps_the_bitmask() {
        let mut cache = loaded(TEST1654_INPUT);
        assert_eq!(cache.ctrl(CURLALTSVC_H2), Ok(()));
        assert_eq!(cache.len(), 4);

        cache.cleanup();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.filename(), None);
        assert_eq!(
            cache.flags(),
            CURLALTSVC_H2,
            "the bitmask outlives the entries"
        );
    }

    // Lookup -- the wire-parity path.

    /// Every version bit, for the tests that do not care which.
    const ALL_VERSIONS: i64 = CURLALTSVC_H1 | CURLALTSVC_H2 | CURLALTSVC_H3;

    /// One entry expiring in the year 2029, for a lookup test.
    fn one_alternative() -> AltSvcInfo {
        loaded(b"h1 example.com 443 h2 alt.ex 8443 \"20291231 00:00:00\" 0 0\n")
    }

    /// A match reports the destination the caller then connects to.
    #[test]
    fn a_matching_alternative_is_found() {
        let mut cache = one_alternative();
        let clock = clock_at(UNIT1654_NOW);
        assert_eq!(
            cache.lookup(AlpnId::H1, b"example.com", 443, ALL_VERSIONS, &clock),
            Some(AltSvcHit {
                alpn: AlpnId::H2,
                host: b"alt.ex".to_vec(),
                port: 8443,
                same_destination: false,
            })
        );
    }

    /// Each of the four conjuncts of the match is necessary -- `:648-651`.
    #[test]
    fn every_part_of_the_match_is_required() {
        let clock = clock_at(UNIT1654_NOW);
        let cases: [(AlpnId, &[u8], u16, i64, &str); 5] = [
            (AlpnId::H1, b"example.com", 443, ALL_VERSIONS, "the match"),
            (
                AlpnId::H2,
                b"example.com",
                443,
                ALL_VERSIONS,
                "wrong protocol",
            ),
            (AlpnId::H1, b"other.ex", 443, ALL_VERSIONS, "wrong host"),
            (AlpnId::H1, b"example.com", 444, ALL_VERSIONS, "wrong port"),
            (
                AlpnId::H1,
                b"example.com",
                443,
                CURLALTSVC_H1 | CURLALTSVC_H3,
                "the destination's protocol is not in the mask",
            ),
        ];

        for (index, (srcalpn, srchost, srcport, versions, why)) in
            cases.into_iter().enumerate()
        {
            let mut cache = one_alternative();
            let hit = cache.lookup(srcalpn, srchost, srcport, versions, &clock);
            assert_eq!(hit.is_some(), index == 0, "{why}");
        }
    }

    /// The mask filters by the DESTINATION's protocol, which is what makes the
    /// ALPN offer follow the cache.
    #[test]
    fn the_versions_mask_selects_by_destination_protocol() {
        let clock = clock_at(UNIT1654_NOW);
        let text = concat!(
            "h1 example.com 443 h2 two.ex 8443 \"20291231 00:00:00\" 0 0\n",
            "h1 example.com 443 h3 three.ex 8443 \"20291231 00:00:00\" 0 0\n",
        )
        .as_bytes();

        for (versions, expected) in [
            (CURLALTSVC_H2, Some(&b"two.ex"[..])),
            (CURLALTSVC_H3, Some(&b"three.ex"[..])),
            (CURLALTSVC_H1, None),
            // With both allowed, the FIRST in list order wins.
            (CURLALTSVC_H2 | CURLALTSVC_H3, Some(&b"two.ex"[..])),
        ] {
            let mut cache = loaded(text);
            let hit =
                cache.lookup(AlpnId::H1, b"example.com", 443, versions, &clock);
            assert_eq!(
                hit.as_ref().map(|hit| hit.host.as_slice()),
                expected,
                "mask {versions}"
            );
        }
    }

    /// An expired entry is deleted during the scan -- `:640-645`.
    ///
    /// The boundary is `<`, so an entry expiring exactly now still matches.
    #[test]
    fn expired_entries_are_deleted_during_the_scan() {
        let cache_text =
            b"h1 example.com 443 h2 alt.ex 8443 \"20291231 00:00:00\" 0 0\n";
        // One second past the stamp: gone, and the cache is left empty.
        // 1893369600 is `20291231 00:00:00` UTC, the stamp of the line above.
        let mut cache = loaded(cache_text);
        let clock = clock_at(1_893_369_601);
        assert_eq!(
            cache.lookup(AlpnId::H1, b"example.com", 443, ALL_VERSIONS, &clock),
            None
        );
        assert!(cache.is_empty(), "the expired entry must be gone");

        // Exactly at the stamp: still usable, because the C's test is `<`.
        let mut cache = loaded(cache_text);
        let clock = clock_at(1_893_369_600);
        assert!(cache
            .lookup(AlpnId::H1, b"example.com", 443, ALL_VERSIONS, &clock)
            .is_some());
        assert_eq!(cache.len(), 1);
    }

    /// Pruning stops at the first match -- `:641-647` returns from the loop.
    ///
    /// WART, and it is observable: the expired entry AFTER the match survives
    /// into the next save.
    #[test]
    fn pruning_stops_at_the_first_match() {
        let mut cache = loaded(
            concat!(
                // Expired, and before the match: deleted.
                "h1 example.com 443 h2 first.ex 1 \"19700101 00:00:01\" 0 0\n",
                // The match.
                "h1 example.com 443 h2 alt.ex 8443 \"20291231 00:00:00\" 0 0\n",
                // Expired, but after the match: survives.
                "h1 example.com 443 h2 last.ex 3 \"19700101 00:00:01\" 0 0\n",
            )
            .as_bytes(),
        );
        assert_eq!(cache.len(), 3);

        let clock = clock_at(UNIT1654_NOW);
        let hit =
            cache.lookup(AlpnId::H1, b"example.com", 443, ALL_VERSIONS, &clock);
        assert_eq!(hit.map(|hit| hit.host), Some(b"alt.ex".to_vec()));

        let survivors: Vec<Vec<u8>> = cache
            .entries()
            .iter()
            .map(|entry| entry.dst.host.clone())
            .collect();
        assert_eq!(survivors, vec![b"alt.ex".to_vec(), b"last.ex".to_vec()]);
    }

    /// `same_destination` is set only when the host AND the port both match --
    /// `:654-656`.
    #[test]
    fn same_destination_needs_the_same_host_and_port() {
        let clock = clock_at(UNIT1654_NOW);
        let cases: [(&[u8], bool, &str); 4] = [
            (
                b"h1 ex.com 443 h2 ex.com 443 \"20291231 00:00:00\" 0 0\n",
                true,
                "same host, same port",
            ),
            (
                b"h1 ex.com 443 h2 ex.com 8443 \"20291231 00:00:00\" 0 0\n",
                false,
                "same host, different port",
            ),
            (
                b"h1 ex.com 443 h2 alt.ex 443 \"20291231 00:00:00\" 0 0\n",
                false,
                "different host, same port",
            ),
            (
                b"h1 ex.com 443 h2 EX.COM 443 \"20291231 00:00:00\" 0 0\n",
                true,
                "the host comparison is case-insensitive",
            ),
        ];

        for (text, expected, why) in cases {
            let mut cache = loaded(text);
            let hit =
                cache.lookup(AlpnId::H1, b"ex.com", 443, ALL_VERSIONS, &clock);
            assert_eq!(
                hit.map(|hit| hit.same_destination),
                Some(expected),
                "{why}"
            );
        }
    }

    /// The host comparison needs EQUAL lengths, and ignores one trailing dot on
    /// the argument -- `hostcompare`, `:399-410`.
    ///
    /// The first two rows are `tests/data/test412` and `tests/data/test413`;
    /// the third is what the C's *"they cannot match if they have different
    /// lengths"* comment prevents.
    #[test]
    fn the_host_comparison_ignores_one_trailing_dot_and_needs_equal_lengths() {
        assert!(hostcompare(b"whohoo.", b"whohoo"));
        assert!(hostcompare(b"whohoo", b"whohoo"));
        assert!(hostcompare(b"WhoHoo.", b"whohoo"));
        assert!(!hostcompare(b"example.com", b"example.com.au"));
        assert!(!hostcompare(b"example.com.au", b"example.com"));
        // Only ONE dot is ignored, and only on the first argument.
        assert!(!hostcompare(b"whohoo..", b"whohoo"));
        assert!(!hostcompare(b"whohoo", b"whohoo."));
        // A lone dot is a length of zero against an empty comparand.
        assert!(hostcompare(b".", b""));
        assert!(hostcompare(b"", b""));

        // And through a lookup, which is how test412 reaches it.
        let mut cache = loaded(
            b"h1 whohoo 12345 h1 alt.ex 8080 \"20291231 00:00:00\" 0 0\n",
        );
        let clock = clock_at(UNIT1654_NOW);
        assert!(
            cache
                .lookup(AlpnId::H1, b"whohoo.", 12345, ALL_VERSIONS, &clock)
                .is_some(),
            "a URL host with a trailing dot must match the stored host"
        );
    }

    /// A lookup against an empty cache finds nothing and changes nothing.
    #[test]
    fn a_lookup_on_an_empty_cache_finds_nothing() {
        let mut cache = AltSvcInfo::new();
        let clock = clock_at(UNIT1654_NOW);
        assert_eq!(
            cache.lookup(AlpnId::H1, b"example.com", 443, ALL_VERSIONS, &clock),
            None
        );
        assert!(cache.is_empty());
    }

    /// A mask of zero matches nothing, whatever the cache holds.
    #[test]
    fn a_zero_mask_matches_nothing() {
        let mut cache = one_alternative();
        let clock = clock_at(UNIT1654_NOW);
        assert_eq!(
            cache.lookup(AlpnId::H1, b"example.com", 443, 0, &clock),
            None
        );
        assert_eq!(cache.len(), 1, "and nothing was pruned");
    }

    // Saving. The three skip conditions need no filesystem; the rest do, and
    // say so.

    /// A temporary-name generator that satisfies the injected contract.
    fn fixed_suffix() -> CodeResult<String> {
        Ok(RAND_ALPHABET
            .iter()
            .take(RAND_SUFFIX_LEN)
            .map(|&byte| char::from(byte))
            .collect())
    }

    /// A generator that fails, to prove its error is passed through unchanged.
    fn failing_suffix() -> CodeResult<String> {
        Err(CURLcode::OutOfMemory)
    }

    /// `CURLALTSVC_READONLYFILE` skips the write entirely -- `:366-368`.
    ///
    /// Asserted without touching the filesystem: the path names a directory
    /// that cannot exist, so if the write were attempted at all it would fail
    /// rather than return `Ok`.
    #[test]
    fn a_read_only_cache_is_never_written() {
        let mut cache = loaded(TEST1654_INPUT);
        assert_eq!(cache.ctrl(CURLALTSVC_READONLYFILE), Ok(()));
        assert_eq!(
            cache
                .save(Some(Path::new("/nonexistent-dir/altsvc")), fixed_suffix),
            Ok(())
        );
    }

    /// No file name at all skips the write -- the `!file` arm of `:366`.
    #[test]
    fn a_cache_with_no_name_is_never_written() {
        let cache = loaded(TEST1654_INPUT);
        assert_eq!(cache.filename(), None, "load_reader remembers no name");
        assert_eq!(cache.save(None, failing_suffix), Ok(()));
    }

    /// An EMPTY file name skips the write -- the `!file[0]` arm of `:366`.
    #[test]
    fn an_empty_name_is_never_written() {
        let cache = loaded(TEST1654_INPUT);
        assert_eq!(cache.save(Some(Path::new("")), failing_suffix), Ok(()));
    }

    /// The remembered name is used when none is given -- `:363-364`.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_save_with_no_name_uses_the_remembered_one() {
        let scratch = tempfile::tempdir();
        assert!(scratch.is_ok(), "this test needs a scratch directory");
        let Ok(scratch) = scratch else { return };
        let path = scratch.path().join("altsvc-remembered");

        // Write the fixture out, then load it BY PATH so the name is stored.
        assert!(std::fs::write(&path, TEST1654_INPUT).is_ok());
        let mut cache = AltSvcInfo::new();
        assert_eq!(cache.load(&path), Ok(()));
        assert_eq!(cache.filename(), Some(path.as_path()));
        assert_eq!(cache.len(), 4);

        // Saving with no name of its own overwrites that same file.
        assert_eq!(cache.save(None, fixed_suffix), Ok(()));
        let written = std::fs::read(&path);
        assert_eq!(
            written.map(|bytes| shown(&bytes)).ok(),
            Some(shown(&expected_file(&[TEST1654_LOADED])))
        );
    }

    /// A save through a temporary file leaves the target correct and the
    /// temporary gone -- `:370-390`.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_save_renames_a_temporary_over_the_target() {
        let scratch = tempfile::tempdir();
        assert!(scratch.is_ok(), "this test needs a scratch directory");
        let Ok(scratch) = scratch else { return };
        let path = scratch.path().join("altsvc-cache");

        // A pre-existing file, so the target is a regular file and the
        // temporary-file path is the one taken.
        assert!(std::fs::write(&path, b"replace me\n").is_ok());

        let cache = loaded(TEST1654_INPUT);
        assert_eq!(cache.save(Some(&path), fixed_suffix), Ok(()));

        let written = std::fs::read(&path);
        assert_eq!(
            written.map(|bytes| shown(&bytes)).ok(),
            Some(shown(&expected_file(&[TEST1654_LOADED])))
        );

        // Nothing else is left in the directory.
        let entries = std::fs::read_dir(scratch.path());
        assert!(entries.is_ok());
        let Ok(entries) = entries else { return };
        let names: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["altsvc-cache".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_save_creates_a_file_that_did_not_exist() {
        let scratch = tempfile::tempdir();
        assert!(scratch.is_ok(), "this test needs a scratch directory");
        let Ok(scratch) = scratch else { return };
        let path = scratch.path().join("brand-new");

        let mut cache = AltSvcInfo::new();
        // Loading a file that is not there is not an error, and the name is
        // remembered anyway -- `:201-209`.
        assert_eq!(cache.load(&path), Ok(()));
        assert!(cache.is_empty());
        assert_eq!(cache.filename(), Some(path.as_path()));

        assert_eq!(cache.save(None, fixed_suffix), Ok(()));
        let written = std::fs::read(&path);
        assert_eq!(
            written.map(|bytes| shown(&bytes)).ok(),
            Some(shown(&expected_file(&[])))
        );
    }

    /// A save to a target that is not a regular file writes straight to it and
    /// performs no rename -- `lib/curl_fopen.c:102-104`.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not model /dev/null")]
    fn a_save_to_a_device_writes_directly() {
        let cache = loaded(TEST1654_INPUT);
        // `/dev/null` is a character device, so the direct path is taken. The
        // assertion is that this succeeds: the temporary-file path would try to
        // create `/dev/<suffix>.tmp` and fail.
        assert_eq!(
            cache.save(Some(Path::new("/dev/null")), fixed_suffix),
            Ok(())
        );
    }

    /// The generator's own error is passed through unchanged.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_failing_name_generator_fails_the_save() {
        let scratch = tempfile::tempdir();
        assert!(scratch.is_ok(), "this test needs a scratch directory");
        let Ok(scratch) = scratch else { return };
        let path = scratch.path().join("altsvc-cache");
        assert!(std::fs::write(&path, b"replace me\n").is_ok());

        let cache = loaded(TEST1654_INPUT);
        assert_eq!(
            cache.save(Some(&path), failing_suffix),
            Err(CURLcode::OutOfMemory)
        );

        // The C TRUNCATES the target before the temporary file is ever named
        // (`lib/curl_fopen.c:99`), so its original contents are gone even
        // though the save failed. This assertion used to check for that data
        // loss; `crate::util::fopen` no longer passes `O_TRUNC`, because
        // truncating the final target is the destructive half of CWE-22, so the
        // previous cache now survives a failed save.
        let written = std::fs::read(&path);
        assert_eq!(
            written.ok().as_deref(),
            Some(&b"replace me\n"[..]),
            "a failed save leaves the previous cache file untouched"
        );
    }

    /// A save whose CONTENTS fail removes the temporary and reports the code.
    ///
    /// The other arm of the finish sequence: `if(result && tempstore)
    /// unlink(tempstore);` at `:389-390`. An entry with an unrepresentable
    /// expiry is the only way to reach it.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_failed_serialisation_removes_the_temporary() {
        let scratch = tempfile::tempdir();
        assert!(scratch.is_ok(), "this test needs a scratch directory");
        let Ok(scratch) = scratch else { return };
        let path = scratch.path().join("altsvc-cache");
        assert!(std::fs::write(&path, b"replace me\n").is_ok());

        let mut cache = AltSvcInfo::new();
        cache.list.push(AltSvc {
            src: AltHost {
                host: b"a.ex".to_vec(),
                port: 80,
                alpn: AlpnId::H1,
            },
            dst: AltHost {
                host: b"b.ex".to_vec(),
                port: 443,
                alpn: AlpnId::H2,
            },
            expires: i64::MAX,
            prio: 0,
            persist: false,
        });

        assert!(cache.save(Some(&path), fixed_suffix).is_err());

        // The target survives -- truncated -- and no temporary is left behind.
        let entries = std::fs::read_dir(scratch.path());
        assert!(entries.is_ok());
        let Ok(entries) = entries else { return };
        let names: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["altsvc-cache".to_string()]);
    }

    /// A cache file survives a full cycle: read it, save it, read it again.
    ///
    /// The property a user depends on and the one `curl_easy_reset` exercises,
    /// asserted end to end through the filesystem rather than in memory.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_cache_file_survives_a_full_cycle() {
        let scratch = tempfile::tempdir();
        assert!(scratch.is_ok(), "this test needs a scratch directory");
        let Ok(scratch) = scratch else { return };
        let path = scratch.path().join("altsvc-cycle");
        assert!(std::fs::write(&path, TEST1654_INPUT).is_ok());

        let mut first = AltSvcInfo::new();
        assert_eq!(first.load(&path), Ok(()));
        assert_eq!(first.save(None, fixed_suffix), Ok(()));

        let mut second = AltSvcInfo::new();
        assert_eq!(second.load(&path), Ok(()));
        assert_eq!(second.entries(), first.entries());
        assert_eq!(shown(&dump(&second)), shown(&dump(&first)));
    }

    /// A directory cannot be written to, and the code says so.
    ///
    /// This is the OPEN failing rather than the rename. The rename arm --
    /// `CURLcode::WriteError` with the temporary removed, `:385-390` -- lives
    /// in `crate::util::fopen`'s `commit`, which owns that sequence for all
    /// three state-file savers and asserts it directly in
    /// `a_failed_commit_reports_a_write_error_and_removes_the_temporary`. It is
    /// not reproduced here because engineering a rename failure whose open
    /// succeeded needs a filesystem this test cannot arrange, and because a
    /// second transcription of the sequence is exactly what routing it through
    /// one shared implementation avoids.
    #[cfg(unix)]
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_save_onto_a_directory_is_a_write_error() {
        let scratch = tempfile::tempdir();
        assert!(scratch.is_ok(), "this test needs a scratch directory");
        let Ok(scratch) = scratch else { return };

        let cache = loaded(TEST1654_INPUT);
        assert_eq!(
            cache.save(Some(scratch.path()), fixed_suffix),
            Err(CURLcode::WriteError)
        );
    }

    // The `tests/data` corpus, replayed.

    /// The harness substitutions these fixtures use.
    const HOSTIP: &[u8] = b"127.0.0.1";
    const HOST6IP: &[u8] = b"[::1]";
    const HTTPPORT: u16 = 8990;
    const HTTPSPORT: u16 = 8991;
    const HTTP2PORT: u16 = 9015;
    const HTTP6PORT: u16 = 8992;

    /// Applies a fixture's `<stripfile>` expiry substitution.
    fn strip_timestamp(bytes: &[u8], year_starts_with_two: bool) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for line in bytes.split_inclusive(|&byte| byte == b'\n') {
            let open = line.iter().position(|&byte| byte == b'"');
            let close = line.iter().rposition(|&byte| byte == b'"');
            match (open, close) {
                (Some(open), Some(close)) if close > open => {
                    if year_starts_with_two {
                        assert_eq!(
                            line.get(open + 1),
                            Some(&b'2'),
                            "the fixture's regex needs a 2: {}",
                            shown(line)
                        );
                    }
                    out.extend(line.iter().take(open).copied());
                    out.extend_from_slice(b"TIMESTAMP");
                    out.extend(line.iter().skip(close + 1).copied());
                }
                _ => out.extend_from_slice(line),
            }
        }
        out
    }

    /// A hit reduced to a comparable tuple.
    ///
    /// Follows the [`hosts`] precedent: Some-ness and the four values are one
    /// comparison, so no test below has to unwrap anything.
    fn hit_of(hit: &Option<AltSvcHit>) -> Option<(AlpnId, &[u8], u16, bool)> {
        hit.as_ref().map(|hit| {
            (
                hit.alpn,
                hit.host.as_slice(),
                hit.port,
                hit.same_destination,
            )
        })
    }

    /// `tests/data/test355` -- *"Alt-Svc from file with too long date"*.
    ///
    /// The cache file holds a stamp of `20290222 22:19:028`, which is 18 bytes
    /// against a [`MAX_ALTSVC_DATELEN`] of 17. The line must be dropped and
    /// the load must still succeed, because the fixture's only expectation is
    /// an ordinary unaffected request.
    #[test]
    fn fixture_355_drops_a_date_that_is_one_byte_too_long() {
        let line = format!(
            "h1 {} {HTTPPORT} h1 example.com 80 \"20290222 22:19:028\" 0 0\n",
            shown(HOSTIP)
        );
        let (cache, outcome) = load(line.as_bytes());
        assert_eq!(outcome, Ok(()), "the load itself must not fail");
        assert_eq!(cache.len(), 0, "the over-long stamp drops the line");
        assert_eq!(shown(&dump(&cache)), shown(&expected_file(&[])));
    }

    /// `tests/data/test356` -- *"parse incoming Alt-Svc and save to file"*.
    ///
    /// Four headers arrive in order. Three are refused -- two impossible ports
    /// and one out of range -- and the third contributes a single entry whose
    /// second alternative names an unknown protocol. The fixture's expected
    /// file has exactly one line, which pins three separate behaviours at
    /// once: the port bound, that an unknown protocol is skipped without
    /// flushing, and that the fourth header's failure leaves the accepted
    /// entry alone because the flush fires only on an ACCEPTED alternative.
    #[test]
    fn fixture_356_keeps_only_the_one_accepted_alternative() {
        let clock = clock_at(UNIT1654_NOW);
        let mut cache = AltSvcInfo::new();
        let headers: [&[u8]; 4] = [
            b"h1=\"nowhere.foo:-1\"",
            b"h1=\"nowhere.foo:-18446744073709551614\"",
            b"h1=\"nowhere.foo:81\", un-kno22!wn=\":82\"",
            b"h1=\"nowhere.foo:70000\"",
        ];
        for (index, value) in headers.into_iter().enumerate() {
            assert_eq!(
                cache.parse(
                    value,
                    AlpnId::H1,
                    HOSTIP,
                    HTTPPORT,
                    &clock,
                    &NoLog
                ),
                Ok(()),
                "header {index} must not report an error: {}",
                shown(value)
            );
        }

        let want = format!(
            "h1 {} {HTTPPORT} h1 nowhere.foo 81 TIMESTAMP 0 0\n",
            shown(HOSTIP)
        );
        assert_eq!(
            shown(&strip_timestamp(&dump(&cache), false)),
            shown(&expected_file(&[want.as_bytes()]))
        );
    }

    /// `tests/data/test358` -- *"HTTPS GET translated by alt-svc lookup to
    /// HTTP/2 GET"*.
    ///
    /// This is the wire-parity fixture. A preloaded entry must be FOUND, which
    /// is what moves the transfer onto HTTP/2 and therefore changes the ALPN
    /// offered; then the response's own header replaces it, and the saved file
    /// must again hold exactly one line.
    #[test]
    fn fixture_358_finds_the_alternative_and_then_replaces_it() {
        a_preloaded_http2_alternative_is_found_and_replaced(HTTPPORT);
    }

    /// `tests/data/test359` -- the same over the HTTPS port.
    ///
    /// Kept separate rather than folded into the previous test because the
    /// fixtures are separate and a divergence should name the one that broke.
    #[test]
    fn fixture_359_finds_the_alternative_over_the_https_port() {
        a_preloaded_http2_alternative_is_found_and_replaced(HTTPSPORT);
    }

    fn a_preloaded_http2_alternative_is_found_and_replaced(srcport: u16) {
        let clock = clock_at(UNIT1654_NOW);
        let line = format!(
            "h2 {} {srcport} h2 {} {HTTP2PORT} \"20290222 22:19:28\" 0 0\n",
            shown(HOSTIP),
            shown(HOSTIP)
        );
        let mut cache = loaded(line.as_bytes());

        // The lookup `lib/url.c:3005-3053` acts on.
        let hit =
            cache.lookup(AlpnId::H2, HOSTIP, srcport, ALL_VERSIONS, &clock);
        assert_eq!(
            hit_of(&hit),
            Some((AlpnId::H2, HOSTIP, HTTP2PORT, false)),
            "a different port is not the same destination"
        );

        // `alt-svc: h2=":<port>", ma=315360000; persist=0` -- no host, so the
        // origin's own is reused.
        let header = format!("h2=\":{HTTP2PORT}\", ma=315360000; persist=0");
        assert_eq!(
            cache.parse(
                header.as_bytes(),
                AlpnId::H2,
                HOSTIP,
                srcport,
                &clock,
                &NoLog
            ),
            Ok(())
        );

        let want = format!(
            "h2 {} {srcport} h2 {} {HTTP2PORT} TIMESTAMP 0 0\n",
            shown(HOSTIP),
            shown(HOSTIP)
        );
        assert_eq!(
            shown(&strip_timestamp(&dump(&cache), true)),
            shown(&expected_file(&[want.as_bytes()])),
            "the flush must have replaced the loaded entry"
        );
    }

    /// `tests/data/test412` -- *"alt-svc using hostname with trailing dot in
    /// URL"*.
    #[test]
    fn fixture_412_matches_a_trailing_dot_in_the_url() {
        let clock = clock_at(UNIT1654_NOW);
        let line = format!(
            "h1 whohoo 12345 h1 {} {HTTPPORT} \"20290222 22:19:28\" 0 0\n",
            shown(HOSTIP)
        );
        let mut cache = loaded(line.as_bytes());
        let hit =
            cache.lookup(AlpnId::H1, b"whohoo.", 12345, ALL_VERSIONS, &clock);
        assert_eq!(hit_of(&hit), Some((AlpnId::H1, HOSTIP, HTTPPORT, false)));
    }

    /// `tests/data/test413` -- *"trailing dot on host from file"*.
    ///
    /// The dot is on the other side here, and `hostcompare` would refuse it:
    /// it strips only its first argument and then demands equal lengths. The
    /// fixture passes because the LOAD already removed it -- the `else if` at
    /// `lib/altsvc.c:77-80` applies to the source host -- so the stored key is
    /// `whohoo` before any lookup happens. That is why the asymmetry is
    /// load-bearing rather than cosmetic.
    #[test]
    fn fixture_413_matches_a_trailing_dot_stored_in_the_file() {
        let clock = clock_at(UNIT1654_NOW);
        let line = format!(
            "h1 whohoo. 12345 h1 {} {HTTPPORT} \"20290222 22:19:28\" 0 0\n",
            shown(HOSTIP)
        );
        let mut cache = loaded(line.as_bytes());
        assert_eq!(
            cache
                .entries()
                .first()
                .map(|entry| entry.src.host.as_slice()),
            Some(&b"whohoo"[..]),
            "the load must have stripped the dot"
        );
        let hit =
            cache.lookup(AlpnId::H1, b"whohoo", 12345, ALL_VERSIONS, &clock);
        assert_eq!(hit_of(&hit), Some((AlpnId::H1, HOSTIP, HTTPPORT, false)));
    }

    /// `tests/data/test437` -- *"Alt-Svc to numerical IPv6 address"*.
    ///
    /// `h1="[ffff::1]:8181"` is stored unbracketed and re-bracketed on the way
    /// out, which is the whole reason the format round trips.
    #[test]
    fn fixture_437_stores_an_ipv6_alternative_unbracketed() {
        let clock = clock_at(UNIT1654_NOW);
        let mut cache = AltSvcInfo::new();
        assert_eq!(
            cache.parse(
                b"h1=\"[ffff::1]:8181\"",
                AlpnId::H1,
                HOSTIP,
                HTTPPORT,
                &clock,
                &NoLog
            ),
            Ok(())
        );
        assert_eq!(
            cache
                .entries()
                .first()
                .map(|entry| entry.dst.host.as_slice()),
            Some(&b"ffff::1"[..]),
            "the brackets belong to the file, not to the entry"
        );

        let want = format!(
            "h1 {} {HTTPPORT} h1 [ffff::1] 8181 TIMESTAMP 0 0\n",
            shown(HOSTIP)
        );
        assert_eq!(
            shown(&strip_timestamp(&dump(&cache), false)),
            shown(&expected_file(&[want.as_bytes()]))
        );
    }

    /// `tests/data/test438` -- *"HTTPS IPv4 GET translated by alt-svc to IPv6
    /// address"*.
    #[test]
    fn fixture_438_round_trips_an_ipv6_alternative_through_all_three_paths() {
        let clock = clock_at(UNIT1654_NOW);
        let line = format!(
            "h1 {} {HTTPPORT} h1 {} {HTTP6PORT} \"20290222 22:19:28\" 0 0\n",
            shown(HOSTIP),
            shown(HOST6IP)
        );
        let mut cache = loaded(line.as_bytes());
        assert_eq!(
            cache
                .entries()
                .first()
                .map(|entry| entry.dst.host.as_slice()),
            Some(&b"::1"[..]),
            "the file read must unbracket"
        );

        let hit =
            cache.lookup(AlpnId::H1, HOSTIP, HTTPPORT, ALL_VERSIONS, &clock);
        assert_eq!(
            hit_of(&hit),
            Some((AlpnId::H1, &b"::1"[..], HTTP6PORT, false))
        );

        let header = format!(
            "h1=\"{}:{HTTP6PORT}\", ma=315360000; persist=0",
            shown(HOST6IP)
        );
        assert_eq!(
            cache.parse(
                header.as_bytes(),
                AlpnId::H1,
                HOSTIP,
                HTTPPORT,
                &clock,
                &NoLog
            ),
            Ok(())
        );
        assert_eq!(
            cache
                .entries()
                .first()
                .map(|entry| entry.dst.host.as_slice()),
            Some(&b"::1"[..]),
            "the header parse must unbracket too"
        );

        let want = format!(
            "h1 {} {HTTPPORT} h1 {} {HTTP6PORT} TIMESTAMP 0 0\n",
            shown(HOSTIP),
            shown(HOST6IP)
        );
        assert_eq!(
            shown(&strip_timestamp(&dump(&cache), true)),
            shown(&expected_file(&[want.as_bytes()])),
            "the writer must re-add the brackets"
        );
    }

    /// `tests/data/test1908` -- *"alt-svc cache save after resetting the
    /// handle"*.
    ///
    /// The fixture's real subject -- that the file name survives
    /// `curl_easy_reset` -- is the reason [`AltSvcInfo::filename`] is stored
    /// by the load rather than kept by the caller; see
    /// `a_load_remembers_the_file_name_for_a_later_save`.
    #[test]
    fn fixture_1908_saves_a_persistent_h2_alternative() {
        let clock = clock_at(UNIT1654_NOW);
        let mut cache = AltSvcInfo::new();
        let header: &[u8] = b"h2=\"3dbbdetxoyw4nsp6c3cc456oj2ays6s43ezxzsf\
                              xxri3h5xqd.example:443\"; ma=315360000; \
                              persist=1";
        assert_eq!(
            cache.parse(header, AlpnId::H1, HOSTIP, HTTPPORT, &clock, &NoLog),
            Ok(())
        );

        let want = format!(
            "h1 {} {HTTPPORT} h2 \
             3dbbdetxoyw4nsp6c3cc456oj2ays6s43ezxzsfxxri3h5xqd.example 443 \
             TIMESTAMP 1 0\n",
            shown(HOSTIP)
        );
        assert_eq!(
            shown(&strip_timestamp(&dump(&cache), false)),
            shown(&expected_file(&[want.as_bytes()]))
        );
    }
}
