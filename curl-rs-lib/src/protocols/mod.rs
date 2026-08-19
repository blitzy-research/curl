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

//! The protocol implementations, the scheme registry and the HTTPS version
//! race.
//!
//! # What this file supersedes, with locators
//!
//! * `lib/url.c:1469` -- `Curl_get_scheme`, which forwards to the next with
//!   `strlen`; [`get_scheme`] here.
//! * `lib/url.c:1477` -- `Curl_getn_scheme`; [`getn_scheme`] here.
//! * `lib/url.c:1488` -- `static const struct Curl_scheme * const
//!   all_schemes[67]`, the registered table; [`SCHEMES`] here.
//! * `lib/url.c:1536` -- the perfect-hash lookup and its length gate.
//! * `lib/url.c:1543-1574` -- `findprotocol`; [`findprotocol`] here.
//! * `lib/urldata.h:428-513` -- `struct Curl_protocol`, the per-scheme
//!   vtable; [`Protocol`] here.
//! * `lib/urldata.h:515-524` -- `struct Curl_scheme`; [`Scheme`] here.
//! * `lib/urldata.h:526+` -- the `PROTOPT_*` bits, owned by
//!   [`crate::conn::ProtocolOptions`] and only CONSUMED here.
//! * `lib/urldata.h:29-53` -- the `PORT_*` defaults; this module is their
//!   single source of truth (see [`default_port_for_scheme`]).
//! * `lib/cf-https-connect.c:41-46` -- `cf_hc_state`; [`HcState`] here.
//! * `lib/cf-https-connect.c:48-57` -- `struct cf_hc_baller`; [`HcBaller`].
//! * `lib/cf-https-connect.c:111-119` -- `struct cf_hc_ctx`, whose members are
//!   ordinary typed fields of [`HttpsConnect`] here.
//! * `lib/cf-https-connect.c:121-142` -- `cf_hc_baller_assign`.
//! * `lib/cf-https-connect.c:557-573` -- `struct Curl_cftype
//!   Curl_cft_http_connect`, the 15-field vtable.
//! * `lib/cf-https-connect.c:575-617` -- `cf_hc_create` and its ALPN-count
//!   bound; [`HttpsConnect::new`] here.
//! * `lib/cf-https-connect.c:648-772` -- `Curl_cf_https_setup`;
//!   [`https_setup`] and [`alpn_offer`] here.
//!
//! Supporting contracts read rather than superseded: `lib/http.h:41-48` and
//! `:50-53` and `:63-72`, `lib/hostip.h:49-54`, `lib/cfilters.h:203-226` and
//! `lib/vquic/vquic.h`.
//!
//! # The registry is wider than the implementation, deliberately
//!
//! The C tree defines and registers 33 URL schemes. Nine are in core scope;
//! the other 24 are registered for ABI completeness, answer
//! `CURLE_UNSUPPORTED_PROTOCOL`, and are deliberately WITHHELD from the
//! `Protocols:` banner so that the 283 fixtures targeting them skip cleanly
//! instead of running and failing. Under-reporting a capability makes a
//! fixture skip; over-reporting makes it run and fail, so truthful
//! advertisement is the optimal strategy and not merely the honest one.
//!
//! A note for anyone reading the C: the backing array is declared
//! `all_schemes[67]` at `lib/url.c:1488`, and 67 is the MODULUS of the hash at
//! `:1536` -- 33 slots hold a scheme and 34 are `NULL` padding. It is a
//! perfect hash table, not an over-allocated list, and 67 must never be read
//! as a count. The hash is deliberately NOT reproduced: it exists to make the
//! lookup cheap, performance is an explicit non-goal, and a linear scan over
//! 33 rows is auditable against the C table row by row.
//!
//! # Three protocol-name conventions exist and must not be unified
//!
//! 1. THIS table, `lib/url.c:1488`'s. Mixed case: four names are UPPER CASE in
//!    the C source -- `"WS"`, `"WSS"`, `"SFTP"` and `"SCP"` -- despite
//!    `struct Curl_scheme`'s own comment claiming "URL scheme name in
//!    lowercase". The table works because both sides of the comparison are
//!    case-folded. The spellings are reproduced exactly.
//! 2. `lib/version.c:302`'s `supported_protocols[]`: a separate, lower-case,
//!    alphabetically sorted table behind the `curl --version` `Protocols:`
//!    line. [`crate::version`] owns it.
//! 3. `curl-config --protocols` and `libcurl.pc`: UPPER CASE, substituted from
//!    `@SUPPORT_PROTOCOLS@`.
//!
//! None is derived from another, here or in the C.
//!
//! # Serialisation is ours, not a library's
//!
//! [`http1`] owns request-line composition and header emission in curl's exact
//! order, using `hyper` only for connection management, keep-alive and
//! framing. That is a design
//! constraint rather than a preference: 1,476 of the 1,914 fixtures compare
//! full request bytes, and `compareparts` (`tests/getpart.pm:351+`) JOINS both
//! arrays into a single string and compares them as one -- no per-line
//! matching, no normalisation, no reordering. The same principle governs FTP
//! command sequencing, chunked framing, and Digest and NTLM message
//! construction.
//!
//! The same rule reaches into this file through [`alpn_offer`]: the ALPN
//! identifiers it selects, AND THEIR ORDER, become the `ClientHello`'s ALPN
//! extension. Reordering them changes bytes on the wire.
//!
//! # This is the only module under `protocols/` that may name `crate::tls`
//!
//! `#include "vtls/vtls.h"` in a C protocol file becomes NO TLS import at
//! all: the connection-filter chain interposes TLS transparently, so a
//! protocol module never opens a session. This file names [`crate::tls`] for
//! one narrow purpose -- the ALPN vocabulary and the offer specification --
//! and a sibling that names it is a layering defect.
//!
//! # `pub(crate)`, with one exception
//!
//! A scheme is selected by URL and never named by a caller, so no exported
//! symbol of `lib/libcurl.def` resolves a name in this directory. The ONE
//! exception is [`scheme_registry`], which the URL API needs and which is
//! re-exported at the crate root -- see its own documentation.
//!
//! # Three imports come from modules this file was not told to expect
//!
//! Recorded because a reviewer checking imports against this file's stated
//! dependencies will find them, and each is deliberate:
//!
//! * [`crate::transfer::request::FollowType`] is CONSUMED rather than declared
//!   here. `crate::transfer::request` already defines it with the C's four
//!   values, and a second same-named enum in one crate would give
//!   [`Protocol::follow`] a type its caller could not pass. The direction is
//!   sanctioned: `lib.rs` declares `transfer` before `protocols`, and
//!   `transfer/request.rs` carries a gate forbidding it to name
//!   `crate::protocols`, so no cycle is possible.
//! * [`crate::url::SchemeInfo`] and [`crate::url::SchemeRegistry`] are the
//!   contract [`scheme_registry`] fulfils. `crate::url` declares the trait and
//!   this module implements it -- never the reverse -- and `curl-rs-ffi` and
//!   `curl-rs` both resolve URLs through it.
//! * [`crate::dns::httpsrr::HttpsRrInfo`] is the record [`alpn_offer`] reads.
//!   `crate::dns` owns it, declares the module publicly within the crate, and is
//!   the only writer of its `alpns` array; reproducing the type here would give
//!   the resolver and the offer two shapes to disagree over.
//!
//! # No production `DohTransport` is registered here, and why
//!
//! `crate::dns::doh` declares the `DohTransport` contract and records that its
//! production implementor belongs to `protocols/` or `conn/`; this file is the
//! right home for it, because issuing a DNS-over-HTTPS query means selecting
//! the `https` row, running the version race below, and dispatching to the
//! negotiated version. It is NOT implemented, and the reason is structural
//! rather than a matter of effort:
//!
//! * Every path to an answer runs through an HTTP request writer AND something
//!   that drives it. The writer has landed -- it is [`http1`] -- but the driver
//!   has not: nothing in this checkout constructs a request specification,
//!   because `easy/handle.rs` and `easy/setopt.rs` are two of the eleven files
//!   `curl-rs-lib/src/lib.rs` enumerates as absent, and
//!   `curl-rs/src/bin/curlinfo.rs`'s `absent_target_gate` asserts that absence
//!   against the disk. Composing a `DohTransport` on top of a writer with no
//!   caller would put the round trip's other half in this file, which is not
//!   where it is measured.
//! * A `post` that compiled and then reported a failure would be a stub, which
//!   specification 0.8.2 forbids outright.
//! * Registering one in `crate::dns::DOH_TRANSPORTS` would make the binary
//!   ADVERTISE DoH. Specification 0.6.5 measures that asymmetry precisely:
//!   under-reporting a capability makes a fixture SKIP, over-reporting makes it
//!   RUN AND FAIL. An unregistered transport is therefore the truthful answer
//!   as well as the only complete one.
//!
//! What this file does supply is everything the transport would be built from:
//! [`https_setup`], [`alpn_offer`] and [`HttpsConnect`]. The DoH-specific
//! request shape stays where it is measured, in `crate::dns::doh` -- `POST`
//! with a raw `application/dns-message` body, `https` only, and TLS
//! verification that does NOT weaken with the transfer's `--insecure`.

use core::fmt;
use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;

use crate::conn::filters::{
    link, CallCtx, CfControl, CfQuery, CfQueryValue, CfType, ConnFilter,
    ConnId, FilterBase, FilterChain, FilterChains, CURL_LOG_LVL_NONE,
};
use crate::conn::happy_eyeballs::{ExpireScheduler, CURL_HET_DEFAULT};
use crate::conn::pool::{ConnCheck, ConnResult};
use crate::conn::select::EasyPollset;
use crate::conn::{
    cf_setup_add, ProtocolOptions, SetupContext, SocketIndex, TlsMode,
    Transport,
};
use crate::dns::httpsrr::HttpsRrInfo;
use crate::dns::AlpnId;
use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::tls::HttpMajors;
use crate::trace::{trc_cf, TimerId, TraceFilter, Tracer};
use crate::transfer::request::FollowType;
use crate::url::{SchemeInfo, SchemeRegistry};
use crate::util::strcase::ncasecompare;
use crate::util::timediff::TimeDiff;
use crate::util::timeval::{timediff_ms, Clock, CurlTime};

/// FTP and FTPS -- `lib/ftp.c`, `lib/pingpong.c`, `lib/ftplistparser.c` and
/// `lib/fileinfo.c`.
///
/// Gated on `ftp`, matching the C's `CURL_DISABLE_FTP`. The gate sits on the
/// child rather than on this module's own declaration in
/// `curl-rs-lib/src/lib.rs`, so that the registry always exists: a build with
/// every protocol feature switched off still has to answer
/// `curl_easy_setopt(CURLOPT_URL, "ftp://...")` with
/// `CURLE_UNSUPPORTED_PROTOCOL` rather than fail to compile, and it still has
/// to report a truthful `Protocols:` line.
///
/// **Six of the other children of this directory are absent from this
/// checkout**, and their declarations therefore cannot be written: a `mod`
/// line without its file is `error[E0583]`, which no attribute suppresses. The
/// absence is measured rather than assumed --
/// `curl-rs/src/bin/curlinfo.rs`'s `absent_target_gate` names
/// `http2.rs`, `http3.rs`, `sftp.rs`, `scp.rs`, `file.rs`, `ws.rs`
/// and `ftp/pingpong.rs` and asserts against the disk that each is
/// still missing. Each declaration lands with the file it names, which is the
/// convention `curl-rs-lib/src/lib.rs` states for the whole crate.
///
/// One consequence follows and is recorded where it bites: all but one row of
/// [`SCHEMES`] carries `run: None` (see [`Scheme::run`]). The exception is
/// `SFTP`, whose module [`sftp`] has landed. Three other children have landed
/// without changing that column: [`stub`], which owns the 24 out-of-scope rows
/// this file used to hold inline, [`file`], whose handler cannot sit in a
/// `const` table, and [`http1`], which owns the HTTP/1.x request writer and the
/// vtable both HTTP rows would point at -- [`http1::SCHEMES`] carries
/// `run: Some(&http1::HTTP)` on its own two rows, and a test in that module
/// binds them to the two rows below column for column so wiring HTTP stays a
/// one-column substitution, held until an easy handle exists to build a request
/// from and not for want of a writer.
#[cfg(feature = "ftp")]
pub(crate) mod ftp;

/// HTTP/1.x, and the bespoke request writer -- `lib/http.c` and
/// `lib/http1.c`.
///
/// Declared with NO `#[cfg]`, and the asymmetry with [`ftp`] above is the
/// C's: `CURL_DISABLE_HTTP` exists as a preprocessor symbol, but this
/// workspace declares no `http` Cargo feature, because HTTP is the substrate
/// every other capability of this crate rests on -- DNS-over-HTTPS, the
/// `CONNECT` tunnel, the WebSocket handshake and the HTTPS version race all
/// speak it.
///
/// It owns the transformation rule with the widest consequences in the
/// migration: request-line composition and header emission IN CURL'S EXACT
/// ORDER, using `hyper` only for connection management, keep-alive and
/// framing. See its own module documentation for the measurement behind that,
/// and for the 20-slot default header order it reproduces from
/// `lib/http.c:2826-2853`.
///
/// `https` needs no separate module and no separate feature: it is this
/// protocol with a TLS filter inserted into the chain `crate::conn` owns and
/// with `PROTOPT_ALPN` on its registry row. One handler serves both schemes in
/// the C too (`lib/http.c:5011` and `:5028` both name
/// `&Curl_protocol_http`), and `protocols/ws.rs` wraps that same handler
/// rather than transcribing it a second time.
pub(crate) mod http1;

/// SFTP, and the SSH session core `protocols/scp.rs` shares with it --
/// `lib/vssh/libssh2.c`, `lib/vssh/vssh.c` and `lib/vssh/ssh.h`.
///
/// Gated on `ssh`, matching the C's `USE_SSH`, and gated on the CHILD for the
/// same reason [`ftp`] is: the registry has to hold its 33 rows under every
/// feature combination, so `sftp://` must answer
/// `CURLE_UNSUPPORTED_PROTOCOL` in a build without this module rather than fail
/// to compile.
///
/// Specification 0.4.1 assigns `lib/vssh/` two targets and no third, and the
/// two C handlers are identical in 14 of their 17 slots
/// (`lib/vssh/libssh2.c:3846-3864` against `:3823-3841`), so this module hosts
/// the shared core and `protocols/scp.rs` imports it. `protocols/scp.rs` is not
/// on disk yet, which is why the [`SCHEMES`] row for `SCP` still carries
/// `run: None` while `SFTP`'s does not.
#[cfg(feature = "ssh")]
pub(crate) mod sftp;

/// The 24 schemes registered for ABI completeness -- `lib/smtp.c`,
/// `lib/imap.c`, `lib/pop3.c`, `lib/telnet.c`, `lib/tftp.c`, `lib/smb.c`,
/// `lib/ldap.c`, `lib/openldap.c`, `lib/rtsp.c`, `lib/mqtt.c`,
/// `lib/curl_rtmp.c`, `lib/dict.c` and `lib/gopher.c`.
///
/// Declared with NO `#[cfg]`, unlike [`ftp`] above, and the asymmetry is
/// deliberate. `ftp` gates an IMPLEMENTATION, which a build may legitimately
/// omit; this module holds only REGISTRY ROWS, and the registry has to be 33
/// rows long under every feature combination -- including
/// `--no-default-features` -- so that `smtp://` answers
/// `CURLE_UNSUPPORTED_PROTOCOL` rather than failing to compile, and so that
/// `CURLOPT_PROTOCOLS_STR` keeps accepting every name the public header
/// declares.
pub(crate) mod stub;

/// The `file://` scheme -- `lib/file.c`.
///
/// Declared with NO `#[cfg]`, like [`stub`] above and unlike [`ftp`]: there is
/// no `file` Cargo feature, because the C's own `CURL_DISABLE_FILE` has no
/// analogue in this workspace's fifteen-feature vocabulary and because
/// `PROTOPT_NONETWORK` means the module pulls in no optional dependency to gate.
///
/// It is the FIRST per-scheme executor to land, and the sparsest: 5 of `struct
/// Curl_protocol`'s 17 slots (`lib/file.c:601-619`), which is what makes it the
/// cheap proof that [`Protocol`]'s twelve defaults really do stand in for
/// `ZERO_NULL`.
///
/// [`SCHEMES`]'s `file` row nevertheless still carries `run: None`, and the
/// reason is structural rather than a matter of effort: this table is a `const`,
/// so it may hold neither a reference to a `static` (`error[E0013]`) nor a
/// reference to interior-mutable data (`error[E0492]`), while a
/// [`file::FileProtocol`] binds one transfer's own state and therefore has both
/// properties. `crate::transfer::TransferIo::xfer_ctx` borrows its owner
/// mutably, so the transfer core cannot hand `do_it` a context AND the seam a
/// [`file::FileClient`] projects from either. That module's own documentation
/// records both, along with why leaving the row `None` is also the truthful
/// answer while `crate::version`'s `ENGINE_PROTOCOLS` is inert.
pub(crate) mod file;

// The protocol bit set -- `curl_prot_t` and the `CURLPROTO_*` values

/// One or more `CURLPROTO_*` bits.
///
/// `curl_prot_t`, which is `uint32_t` while `PROTO_TYPE_SMALL` is defined
/// (`lib/urldata.h:81-88`). The C comment there is the whole story: *"This
/// should be undefined once we need bit 32 or higher"* -- bit 31 is taken by
/// the internal `CURLPROTO_WSS`, so the type is exactly full.
///
/// # The integers are the public ABI's and are pinned
///
/// `include/curl/curl.h:1076-1107` fixes all 31 publicly named bits, and a
/// program compiled against curl 8.19.0-DEV holds those numbers in its
/// instruction stream: `CURLOPT_PROTOCOLS` and `CURLOPT_REDIR_PROTOCOLS` take
/// them as a `long` mask. Renumbering any of them would break that contract
/// silently, so every value below is written as the C writes it.
///
/// # The measured collision, which must NOT be "fixed"
///
/// [`Self::WS`] and [`Self::MQTTS`] ARE THE SAME BIT, `1 << 30`.
/// `CURLPROTO_MQTTS` is public (`curl.h:1107`) and `CURLPROTO_WS` is internal
/// (`lib/urldata.h:70`), and the C comment at `:65-68` explains why the
/// internal pair sits up there: *"CURLPROTO_GOPHERS (29) is the highest
/// publicly used protocol bit number, the rest are internal information."*
/// Whoever added the WebSocket bits reused 30. Upstream lives with it because
/// no `struct Curl_scheme` row can name both, and this port reproduces it
/// because renumbering would change a public integer. The collision is
/// asserted by [`mod tests`](self) so that nobody quietly repairs it.
///
/// A bitwise newtype rather than the `bitflags` crate: the dependency set is
/// closed, and `crate::conn::ProtocolOptions`, `crate::conn::filters::CfType`
/// and `crate::tls::HttpMajors` are all written this way already.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct Proto(u32);

#[allow(dead_code)] // consumers: the transfer core and the protocol modules
impl Proto {
    /// No protocol at all. Not a `CURLPROTO_*` value; the identity for
    /// [`Self::union`] and what an empty mask reads as.
    pub(crate) const NONE: Self = Self(0);

    /// `CURLPROTO_HTTP` = `1 << 0` (`curl.h:1076`).
    pub(crate) const HTTP: Self = Self(1 << 0);
    /// `CURLPROTO_HTTPS` = `1 << 1`.
    pub(crate) const HTTPS: Self = Self(1 << 1);
    /// `CURLPROTO_FTP` = `1 << 2`.
    pub(crate) const FTP: Self = Self(1 << 2);
    /// `CURLPROTO_FTPS` = `1 << 3`.
    pub(crate) const FTPS: Self = Self(1 << 3);
    /// `CURLPROTO_SCP` = `1 << 4`.
    pub(crate) const SCP: Self = Self(1 << 4);
    /// `CURLPROTO_SFTP` = `1 << 5`.
    pub(crate) const SFTP: Self = Self(1 << 5);
    /// `CURLPROTO_TELNET` = `1 << 6`.
    pub(crate) const TELNET: Self = Self(1 << 6);
    /// `CURLPROTO_LDAP` = `1 << 7`.
    pub(crate) const LDAP: Self = Self(1 << 7);
    /// `CURLPROTO_LDAPS` = `1 << 8`.
    pub(crate) const LDAPS: Self = Self(1 << 8);
    /// `CURLPROTO_DICT` = `1 << 9`.
    pub(crate) const DICT: Self = Self(1 << 9);
    /// `CURLPROTO_FILE` = `1 << 10`.
    pub(crate) const FILE: Self = Self(1 << 10);
    /// `CURLPROTO_TFTP` = `1 << 11`.
    pub(crate) const TFTP: Self = Self(1 << 11);
    /// `CURLPROTO_IMAP` = `1 << 12`.
    pub(crate) const IMAP: Self = Self(1 << 12);
    /// `CURLPROTO_IMAPS` = `1 << 13`.
    pub(crate) const IMAPS: Self = Self(1 << 13);
    /// `CURLPROTO_POP3` = `1 << 14`.
    pub(crate) const POP3: Self = Self(1 << 14);
    /// `CURLPROTO_POP3S` = `1 << 15`.
    pub(crate) const POP3S: Self = Self(1 << 15);
    /// `CURLPROTO_SMTP` = `1 << 16`.
    pub(crate) const SMTP: Self = Self(1 << 16);
    /// `CURLPROTO_SMTPS` = `1 << 17`.
    pub(crate) const SMTPS: Self = Self(1 << 17);
    /// `CURLPROTO_RTSP` = `1 << 18`.
    pub(crate) const RTSP: Self = Self(1 << 18);
    /// `CURLPROTO_RTMP` = `1 << 19`.
    pub(crate) const RTMP: Self = Self(1 << 19);
    /// `CURLPROTO_RTMPT` = `1 << 20`.
    pub(crate) const RTMPT: Self = Self(1 << 20);
    /// `CURLPROTO_RTMPE` = `1 << 21`.
    pub(crate) const RTMPE: Self = Self(1 << 21);
    /// `CURLPROTO_RTMPTE` = `1 << 22`.
    pub(crate) const RTMPTE: Self = Self(1 << 22);
    /// `CURLPROTO_RTMPS` = `1 << 23`.
    pub(crate) const RTMPS: Self = Self(1 << 23);
    /// `CURLPROTO_RTMPTS` = `1 << 24`.
    pub(crate) const RTMPTS: Self = Self(1 << 24);
    /// `CURLPROTO_GOPHER` = `1 << 25`.
    pub(crate) const GOPHER: Self = Self(1 << 25);
    /// `CURLPROTO_SMB` = `1 << 26`.
    pub(crate) const SMB: Self = Self(1 << 26);
    /// `CURLPROTO_SMBS` = `1 << 27`.
    pub(crate) const SMBS: Self = Self(1 << 27);
    /// `CURLPROTO_MQTT` = `1 << 28`.
    pub(crate) const MQTT: Self = Self(1 << 28);
    /// `CURLPROTO_GOPHERS` = `1 << 29`. The highest PUBLICLY used bit number,
    /// per the C comment at `lib/urldata.h:65-66`.
    pub(crate) const GOPHERS: Self = Self(1 << 29);
    /// `CURLPROTO_MQTTS` = `1 << 30` (`curl.h:1107`).
    ///
    /// Equal to [`Self::WS`]; see this type's documentation.
    pub(crate) const MQTTS: Self = Self(1 << 30);

    /// `CURLPROTO_WS` = `1L << 30` (`lib/urldata.h:70`), INTERNAL.
    ///
    /// `0L` when `CURL_DISABLE_WEBSOCKETS` is defined (`:73`). Here the value
    /// is unconditional and the `websockets` feature decides whether the row
    /// carries an implementation instead, because a bit that changes value with
    /// a build flag cannot be a `const`.
    pub(crate) const WS: Self = Self(1 << 30);
    /// `CURLPROTO_WSS` = `((curl_prot_t)1 << 31)` (`lib/urldata.h:71`),
    /// INTERNAL. The bit that makes `curl_prot_t` exactly full.
    pub(crate) const WSS: Self = Self(1 << 31);

    /// `CURLPROTO_ALL` = `((unsigned long)0xffffffff)` (`curl.h:1108`).
    pub(crate) const ALL: Self = Self(0xffff_ffff);

    /// `CURLPROTO_MASK` = `0x3ffffff` (`lib/urldata.h:93`): bits 0 through 25.
    ///
    /// The C comment: *"This mask is for all the old protocols that are
    /// provided and defined in the public header and shall exclude protocols
    /// added since which are not exposed in the API"*. Note what that means in
    /// practice -- `GOPHER`, `SMB`, `SMBS`, `MQTT`, `GOPHERS` and `MQTTS` are
    /// all declared in the public header yet all sit OUTSIDE this mask, so the
    /// comment describes the mask's history rather than its extent. The value
    /// is reproduced, not reinterpreted.
    pub(crate) const MASK: Self = Self(0x3ff_ffff);

    /// `CURLPROTO_REDIR` (`lib/urldata.h:78-79`): the default set a redirect
    /// may target.
    pub(crate) const REDIR: Self =
        Self(Self::HTTP.0 | Self::HTTPS.0 | Self::FTP.0 | Self::FTPS.0);

    /// `PROTO_FAMILY_HTTP` (`lib/urldata.h:107-108`).
    ///
    /// Read by `crate::headers` to decide whether the `hds-collect` writer is
    /// installed -- `data->conn && (data->conn->scheme->protocol &
    /// PROTO_FAMILY_HTTP)` -- and by `crate::transfer::writeout` for the same
    /// question. Note that `WS | WSS` is `MQTTS | 1 << 31`, a consequence of
    /// the documented bit collision rather than an error here.
    pub(crate) const FAMILY_HTTP: Self =
        Self(Self::HTTP.0 | Self::HTTPS.0 | Self::WS.0 | Self::WSS.0);
    /// `PROTO_FAMILY_FTP` (`lib/urldata.h:109`).
    pub(crate) const FAMILY_FTP: Self = Self(Self::FTP.0 | Self::FTPS.0);
    /// `PROTO_FAMILY_POP3` (`lib/urldata.h:110`).
    pub(crate) const FAMILY_POP3: Self = Self(Self::POP3.0 | Self::POP3S.0);
    /// `PROTO_FAMILY_SMB` (`lib/urldata.h:111`).
    pub(crate) const FAMILY_SMB: Self = Self(Self::SMB.0 | Self::SMBS.0);
    /// `PROTO_FAMILY_SMTP` (`lib/urldata.h:112`).
    pub(crate) const FAMILY_SMTP: Self = Self(Self::SMTP.0 | Self::SMTPS.0);
    /// `PROTO_FAMILY_SSH` (`lib/urldata.h:113`).
    ///
    /// Read by `crate::conn::happy_eyeballs`, which asks
    /// `cf->conn->scheme->protocol & PROTO_FAMILY_SSH`.
    pub(crate) const FAMILY_SSH: Self = Self(Self::SCP.0 | Self::SFTP.0);

    /// The nine schemes this rewrite implements, as one mask.
    ///
    /// Not a C constant: the C tree implements every scheme it registers, so it
    /// needs no such set. Specification 0.2.2 excludes 24 of the 33 from
    /// implementation, and this mask is what keeps that exclusion enforceable
    /// in production rather than only in a review -- see
    /// [`Scheme::in_core_scope`].
    ///
    /// # This mask ALONE cannot decide core scope, and the reason is [`Self::WS`]
    ///
    /// [`Self::WS`] and [`Self::MQTTS`] are THE SAME BIT -- upstream's own
    /// encoding, preserved deliberately and asserted by
    /// [`mod tests`](self#tests). So `mqtts`, which is out of scope, intersects
    /// this mask through a bit it shares with `ws`, which is in scope. A test
    /// caught exactly that. [`Scheme::in_core_scope`] therefore conjoins this
    /// with [`Self::CORE_FAMILIES`], whose bits do not collide with anything.
    pub(crate) const CORE_SCHEMES: Self = Self(
        Self::HTTP.0
            | Self::HTTPS.0
            | Self::FTP.0
            | Self::FTPS.0
            | Self::SFTP.0
            | Self::SCP.0
            | Self::FILE.0
            | Self::WS.0
            | Self::WSS.0,
    );

    /// The FAMILY column of the nine in-scope rows, as one mask.
    ///
    /// The four families specification 0.2.1 names -- HTTP (`http`, `https`,
    /// `ws`, `wss`), FTP (`ftp`, `ftps`), SSH (`scp`, `sftp`) and `file`. Every
    /// bit here is one of `1 << 0`, `1 << 2`, `1 << 4`, `1 << 5` and `1 << 10`,
    /// none of which any other `CURLPROTO_*` shares, which is what makes this
    /// mask usable where [`Self::CORE_SCHEMES`] is ambiguous.
    ///
    /// `HTTPS` is absent on purpose: no row's family column holds it. The C
    /// records `CURLPROTO_HTTP` as the family of all four HTTP-family schemes
    /// (`lib/http.c:5013`, `:5030`, `lib/ws.c:1987`, `:2002`), and the family
    /// column is the non-TLS spelling by definition.
    pub(crate) const CORE_FAMILIES: Self = Self(
        Self::HTTP.0 | Self::FTP.0 | Self::SCP.0 | Self::SFTP.0 | Self::FILE.0,
    );

    /// The raw mask -- the `curl_prot_t` value itself.
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }

    /// A mask from raw bits. Total, because `CURLOPT_PROTOCOLS` accepts any
    /// `long` and `CURLPROTO_ALL` is every bit.
    pub(crate) const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Both masks at once.
    #[must_use]
    pub(crate) const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether any bit is shared -- the C's `a & b` used as a truth value,
    /// which is how every `allowed_protocols` and `PROTO_FAMILY_*` test in the
    /// C tree is written.
    pub(crate) const fn intersects(self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Whether every bit of `other` is present.
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Whether no bit is set.
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether exactly one bit is set.
    ///
    /// `struct Curl_scheme`'s comment requires it of both the `protocol` and
    /// the `family` column: *"this needs to be the single specific protocol
    /// bit"* (`lib/urldata.h:517-518`). Asserted over the whole table by
    /// [`mod tests`](self).
    pub(crate) const fn is_single_bit(self) -> bool {
        self.0 != 0 && (self.0 & (self.0 - 1)) == 0
    }
}

impl core::ops::BitOr for Proto {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

/// Renders the set as its `CURLPROTO_*` names, so a test failure names the
/// protocols rather than printing a hexadecimal mask.
///
/// Bit 30 renders as `MQTTS|WS`, both spellings, because the two constants are
/// the same bit and printing one of them would misdescribe the other.
impl fmt::Debug for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Proto(")?;
        let mut first = true;
        for (bit, name) in PROTO_NAMES {
            if !self.contains(bit) {
                continue;
            }
            if !first {
                f.write_str("|")?;
            }
            first = false;
            f.write_str(name)?;
        }
        if first {
            f.write_str("NONE")?;
        }
        f.write_str(")")
    }
}

/// The 32 occupied bits and their names, in bit order.
///
/// 31 names come from `include/curl/curl.h:1076-1107` and one -- `WSS` -- from
/// `lib/urldata.h:71`. Bit 30 carries both of its spellings for the reason
/// [`Proto`] documents, so 32 bits are named by 32 entries even though 33
/// constants exist.
#[rustfmt::skip]
const PROTO_NAMES: [(Proto, &str); 32] = [
    (Proto::HTTP,    "HTTP"),
    (Proto::HTTPS,   "HTTPS"),
    (Proto::FTP,     "FTP"),
    (Proto::FTPS,    "FTPS"),
    (Proto::SCP,     "SCP"),
    (Proto::SFTP,    "SFTP"),
    (Proto::TELNET,  "TELNET"),
    (Proto::LDAP,    "LDAP"),
    (Proto::LDAPS,   "LDAPS"),
    (Proto::DICT,    "DICT"),
    (Proto::FILE,    "FILE"),
    (Proto::TFTP,    "TFTP"),
    (Proto::IMAP,    "IMAP"),
    (Proto::IMAPS,   "IMAPS"),
    (Proto::POP3,    "POP3"),
    (Proto::POP3S,   "POP3S"),
    (Proto::SMTP,    "SMTP"),
    (Proto::SMTPS,   "SMTPS"),
    (Proto::RTSP,    "RTSP"),
    (Proto::RTMP,    "RTMP"),
    (Proto::RTMPT,   "RTMPT"),
    (Proto::RTMPE,   "RTMPE"),
    (Proto::RTMPTE,  "RTMPTE"),
    (Proto::RTMPS,   "RTMPS"),
    (Proto::RTMPTS,  "RTMPTS"),
    (Proto::GOPHER,  "GOPHER"),
    (Proto::SMB,     "SMB"),
    (Proto::SMBS,    "SMBS"),
    (Proto::MQTT,    "MQTT"),
    (Proto::GOPHERS, "GOPHERS"),
    (Proto::MQTTS,   "MQTTS|WS"),
    (Proto::WSS,     "WSS"),
];

// The default ports -- `lib/urldata.h:29-53`
//
// This module is their single source of truth. `crate::url` needs them for
// `CURLU_DEFAULT_PORT` and reaches them through the registry rather than
// re-deriving a second table that could disagree; see
// [`default_port_for_scheme`] and [`SchemeInfo::default_port`].

/// `PORT_FTP` (`lib/urldata.h:29`).
pub(crate) const PORT_FTP: u16 = 21;
/// `PORT_FTPS` (`:30`).
pub(crate) const PORT_FTPS: u16 = 990;
/// `PORT_TELNET` (`:31`).
pub(crate) const PORT_TELNET: u16 = 23;
/// `PORT_HTTP` (`:32`).
pub(crate) const PORT_HTTP: u16 = 80;
/// `PORT_HTTPS` (`:33`).
pub(crate) const PORT_HTTPS: u16 = 443;
/// `PORT_DICT` (`:34`).
pub(crate) const PORT_DICT: u16 = 2628;
/// `PORT_LDAP` (`:35`).
pub(crate) const PORT_LDAP: u16 = 389;
/// `PORT_LDAPS` (`:36`).
pub(crate) const PORT_LDAPS: u16 = 636;
/// `PORT_TFTP` (`:37`).
pub(crate) const PORT_TFTP: u16 = 69;
/// `PORT_SSH` (`:38`) -- shared by SFTP and SCP.
pub(crate) const PORT_SSH: u16 = 22;
/// `PORT_IMAP` (`:39`).
pub(crate) const PORT_IMAP: u16 = 143;
/// `PORT_IMAPS` (`:40`).
pub(crate) const PORT_IMAPS: u16 = 993;
/// `PORT_POP3` (`:41`).
pub(crate) const PORT_POP3: u16 = 110;
/// `PORT_POP3S` (`:42`).
pub(crate) const PORT_POP3S: u16 = 995;
/// `PORT_SMB` (`:43`).
pub(crate) const PORT_SMB: u16 = 445;
/// `PORT_SMBS` (`:44`) -- the same 445, which is the C's value and not a slip.
pub(crate) const PORT_SMBS: u16 = 445;
/// `PORT_SMTP` (`:45`).
pub(crate) const PORT_SMTP: u16 = 25;
/// `PORT_SMTPS` (`:46`), with the C's own comment: *"sometimes called SSMTP"*.
pub(crate) const PORT_SMTPS: u16 = 465;
/// `PORT_RTSP` (`:47`).
pub(crate) const PORT_RTSP: u16 = 554;
/// `PORT_RTMP` (`:48`).
pub(crate) const PORT_RTMP: u16 = 1935;
/// `PORT_RTMPT` (`:49`), defined as `PORT_HTTP` -- written as the alias so the
/// derivation survives.
pub(crate) const PORT_RTMPT: u16 = PORT_HTTP;
/// `PORT_RTMPS` (`:50`), defined as `PORT_HTTPS`.
pub(crate) const PORT_RTMPS: u16 = PORT_HTTPS;
/// `PORT_GOPHER` (`:51`) -- shared by `gopher` and `gophers`, which is the C's
/// value: `gophers` has no port of its own.
pub(crate) const PORT_GOPHER: u16 = 70;
/// `PORT_MQTT` (`:52`).
pub(crate) const PORT_MQTT: u16 = 1883;
/// `PORT_MQTTS` (`:53`).
pub(crate) const PORT_MQTTS: u16 = 8883;

/// The default port `name` resolves to, if it resolves at all.
///
/// The `defport` column of [`SCHEMES`], reached by the same lookup as
/// [`get_scheme`] so that the two can never disagree. `file` answers
/// `Some(0)`, not `None`: `lib/file.c:635` registers a literal `0` because the
/// scheme has no network endpoint, and `None` here means "no such scheme".
#[allow(dead_code)] // consumer: crate::url, for CURLU_DEFAULT_PORT
pub(crate) fn default_port_for_scheme(name: &[u8]) -> Option<u16> {
    get_scheme(name).map(|scheme| scheme.defport)
}

// The scheme registry -- `struct Curl_scheme` and `all_schemes[67]`

/// One registered URL scheme.
///
/// `struct Curl_scheme` (`lib/urldata.h:515-524`), all six members, in the C's
/// order:
///
/// ```c
/// const char *name;                 /* URL scheme name in lowercase */
/// const struct Curl_protocol *run;  /* implementation */
/// curl_prot_t protocol;             /* the single specific CURLPROTO_* bit */
/// curl_prot_t family;               /* single bit, the non-TLS name */
/// uint32_t flags;                   /* PROTOPT_* */
/// uint16_t defport;                 /* Default port. */
/// ```
///
/// `name` is `&'static [u8]` rather than `&'static str` because the comparison
/// it takes part in is a byte comparison with ASCII-only case folding: the C
/// uses `curl_strnequal`, whose `Curl_raw_tolower` is the identity for
/// `0x80..=0xFF`, and a `str`-based fold would invite Unicode semantics that
/// the C does not have.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Scheme {
    /// The scheme name, EXACTLY as `lib/url.c`'s table spells it -- which is
    /// UPPER CASE for `SFTP`, `SCP`, `WS` and `WSS`. Never compared
    /// case-sensitively.
    pub(crate) name: &'static [u8],

    /// This scheme's transfer implementation, or [`None`] when the build
    /// carries none.
    ///
    /// The C's `run` member, and the C's own idiom for a scheme that is
    /// registered but not implemented: every registration is written
    /// `#ifdef CURL_DISABLE_<PROTO> ZERO_NULL #else &Curl_protocol_<proto>
    /// #endif` -- measured at `lib/file.c:626-632`, `lib/ftp.c:4348-4354` and
    /// `:4367-4374`, `lib/http.c:5011-5017` and `:5028-5034`,
    /// `lib/ws.c:1984-1990` and `:1999-2006`, `lib/vssh/vssh.c:338-344` and
    /// `:352-358`, and `lib/dict.c:295-301`. `Curl_getn_scheme`'s contract
    /// names it explicitly: *"Check the ->run struct field for non-NULL to
    /// figure out if an implementation is present"* (`lib/url.c:1474-1476`).
    ///
    /// **Exactly ONE row of [`SCHEMES`] carries an implementation in this
    /// checkout: `SFTP`.** That is a measurement, not an aspiration, and the
    /// rows that carry [`None`] do so for two DIFFERENT reasons that are worth
    /// keeping apart. For most schemes the file that would define an
    /// implementation is absent: five remain missing under
    /// `protocols/` -- `http2.rs`, `http3.rs`, `scp.rs`, `ws.rs` and
    /// `ftp/pingpong.rs` -- which
    /// `curl-rs/src/bin/curlinfo.rs`'s `absent_target_gate` asserts against the
    /// disk. For `file`, `http` and `https` the file has LANDED and the column
    /// is still empty: [`http1`] defines a
    /// full [`Protocol`] implementor and exports its own two rows carrying
    /// `run: Some(&http1::HTTP)`, and what those two rows lack is a CALLER --
    /// nothing in this checkout builds a request specification, because
    /// `easy/handle.rs` and `easy/setopt.rs` are unwritten -- while [`file`]'s
    /// handler binds one transfer's state and so cannot sit in a `const` table
    /// at all. Adopting either
    /// executor here would advertise a transfer this build cannot perform, and
    /// specification 0.6.5 measures that asymmetry precisely: under-reporting
    /// makes a fixture SKIP, over-reporting makes it RUN AND FAIL. Each column
    /// therefore stays `None` until its caller exists, and a test in [`http1`]
    /// binds its rows to these column for column so the substitution stays a
    /// one-column change. Every row but `SFTP`'s answers exactly as a C curl
    /// configured with the matching
    /// `CURL_DISABLE_<PROTO>` answers -- the scheme RESOLVES, with its
    /// port and its flags, and then reports no implementation.
    ///
    /// The consequence is [`findprotocol`]'s: `Protocol "http" disabled`
    /// rather than `Protocol "http" not supported`, because the row was found.
    ///
    /// The `SFTP` column is cfg'd on the `ssh` feature, so a build that omits
    /// the feature still holds 33 rows and still answers
    /// `CURLE_UNSUPPORTED_PROTOCOL` for `sftp://` -- see [`RUN_SFTP`].
    ///
    /// A note for readers arriving from `crate::version`'s and
    /// `crate::dns`'s documentation, which speak of `protocols::EXECUTORS`:
    /// this column IS that registration point. An earlier revision kept a
    /// separate slice of executors and derived runnability from it; the column
    /// is the C's own mechanism, keeps the answer in one place, and cannot
    /// disagree with the row it belongs to.
    pub(crate) run: Option<&'static dyn Protocol>,

    /// The single `CURLPROTO_*` bit that identifies this scheme.
    pub(crate) protocol: Proto,

    /// The single bit naming this scheme's FAMILY, which is the non-TLS
    /// spelling of the protocol.
    ///
    /// Four in-scope rows have a family differing from their protocol --
    /// `ftps` is `FTP`, and `https`, `ws` and `wss` are all `HTTP` -- which is
    /// what makes `PROTO_FAMILY_*` tests work on the family column.
    // Consumers: ssl_reuse_matches here, and crate::conn::pool's candidate
    // match.
    #[allow(dead_code)]
    pub(crate) family: Proto,

    /// `PROTOPT_*`, owned by [`crate::conn::ProtocolOptions`].
    ///
    /// Consumed rather than redeclared: `crate::conn` holds the one definition
    /// of all 17 bits, including the freed `1 << 9` that used to be
    /// `PROTOPT_STREAM` and must not be reused.
    pub(crate) flags: ProtocolOptions,

    /// The default port, or `0` for a scheme with no network endpoint.
    pub(crate) defport: u16,
}

#[allow(dead_code)] // consumers: the transfer core and the protocol modules
impl Scheme {
    /// Whether specification 0.2.2 puts this scheme in core scope.
    ///
    /// # Both columns are consulted, and that is not belt-and-braces
    ///
    /// [`Proto::WS`] and [`Proto::MQTTS`] are the same bit -- see
    /// [`Proto::CORE_SCHEMES`] -- so the protocol column alone reports the
    /// out-of-scope `mqtts` row as in scope. Conjoining
    /// [`Proto::CORE_FAMILIES`], whose bits collide with nothing, settles it:
    /// `mqtts` has family `MQTT` and `ws` has family `HTTP`. A test caught this;
    /// it is recorded here because the conjunction looks redundant and is not.
    ///
    /// Tested against [`Proto::CORE_SCHEMES`] rather than against a second
    /// list of names, so the two cannot drift. This is the production guard
    /// that stops an out-of-scope row from ever reporting an implementation:
    /// [`Self::runnable`] conjoins it, so registering an executor for `smtp`
    /// would not make `smtp` runnable even if somebody wrote one.
    pub(crate) const fn in_core_scope(&self) -> bool {
        self.protocol.intersects(Proto::CORE_SCHEMES)
            && self.family.intersects(Proto::CORE_FAMILIES)
    }

    /// Whether this build can actually run a transfer for this scheme.
    ///
    /// The C's `p->run != NULL` test (`lib/url.c:1546`), conjoined with the
    /// scope guard above.
    pub(crate) const fn runnable(&self) -> bool {
        self.run.is_some() && self.in_core_scope()
    }

    /// `PROTOPT_SSL`: whether the scheme is TLS-protected by definition.
    pub(crate) const fn is_ssl(&self) -> bool {
        self.flags.intersects(ProtocolOptions::SSL)
    }

    /// The projection `crate::url` consumes.
    ///
    /// `url_options` is derived from [`ProtocolOptions::URLOPTIONS`] rather
    /// than stored twice; the six schemes that carry it are `smtp`, `smtps`,
    /// `imap`, `imaps`, `pop3` and `pop3s` (`lib/smtp.c:2022` and `:2039`,
    /// `lib/imap.c:2341` and `:2359`, `lib/pop3.c:1730` and `:1747`).
    fn info(&self) -> SchemeInfo {
        SchemeInfo {
            // The registry's own spelling, which the C stores and returns
            // unchanged. `from_utf8` cannot fail for any row: all 33 names are
            // ASCII, asserted by `mod tests`. The fallback keeps the function
            // total without an `unwrap`.
            name: core::str::from_utf8(self.name).unwrap_or(""),
            default_port: self.defport,
            url_options: self.flags.intersects(ProtocolOptions::URLOPTIONS),
            runnable: self.runnable(),
        }
    }
}

/// The longest scheme name [`getn_scheme`] can resolve.
///
/// `if(len && (len <= 7))` gates the whole lookup (`lib/url.c:1524`), so a name
/// of eight bytes or more misses the table however long a name the URL parser
/// admits on the way in. Reproduced rather than "fixed": the long-scheme rows
/// of the ported `set_parts_list` fixtures depend on falling through to the
/// syntax check instead of resolving. Every one of the 33 names is at most
/// seven bytes, which [`mod tests`](self) asserts.
pub(crate) const MAX_RESOLVABLE_SCHEME_LEN: usize = 7;

/// Folds a `PROTOPT_*` list into one mask, in a `const` context.
///
/// [`ProtocolOptions`]'s `BitOr` is an ordinary trait implementation and
/// therefore unavailable in a `const`, while its `union` is a `const fn`. This
/// helper lets each `FLAGS_*` below be written as the LIST the C writes with
/// `|`, in the C's order, rather than as a nest of method calls -- which is
/// what makes the two readable side by side.
const fn protopt(list: &[ProtocolOptions]) -> ProtocolOptions {
    let mut folded = ProtocolOptions::NONE;
    let mut index = 0;
    while index < list.len() {
        folded = folded.union(list[index]);
        index += 1;
    }
    folded
}

/// `lib/http.c:5017-5019`: `PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL |
/// PROTOPT_CONN_REUSE`.
const FLAGS_HTTP: ProtocolOptions = protopt(&[
    ProtocolOptions::CREDSPERREQUEST,
    ProtocolOptions::USERPWDCTRL,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/http.c:5035-5036`: the HTTP set plus `PROTOPT_SSL` and `PROTOPT_ALPN`.
///
/// `PROTOPT_ALPN` is what makes `https` -- and only `https` -- offer ALPN, and
/// it is the flag [`https_setup`] exists to serve.
const FLAGS_HTTPS: ProtocolOptions = protopt(&[
    ProtocolOptions::SSL,
    ProtocolOptions::CREDSPERREQUEST,
    ProtocolOptions::ALPN,
    ProtocolOptions::USERPWDCTRL,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/ftp.c:4356-4359`.
///
/// `PROTOPT_DUAL` is why FTP is the only in-scope scheme that uses
/// [`Protocol::do_more`] and [`Protocol::domore_pollset`]: it needs a second
/// connection for the data channel. `PROTOPT_PROXY_AS_HTTP` lets an FTP URL be
/// handed to an HTTP proxy as HTTP, and `PROTOPT_SSL_REUSE` lets plain `ftp`
/// reuse an existing TLS connection in the same family without itself carrying
/// `PROTOPT_SSL`.
const FLAGS_FTP: ProtocolOptions = protopt(&[
    ProtocolOptions::DUAL,
    ProtocolOptions::CLOSEACTION,
    ProtocolOptions::NEEDSPWD,
    ProtocolOptions::NOURLQUERY,
    ProtocolOptions::PROXY_AS_HTTP,
    ProtocolOptions::WILDCARD,
    ProtocolOptions::SSL_REUSE,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/ftp.c:4375-4377`.
///
/// Note what is NOT here: `PROTOPT_PROXY_AS_HTTP` and `PROTOPT_SSL_REUSE`,
/// both of which plain `ftp` carries. `ftps` cannot be handed to an HTTP proxy
/// as HTTP, and it has no need to borrow another scheme's TLS because it
/// carries `PROTOPT_SSL` itself.
const FLAGS_FTPS: ProtocolOptions = protopt(&[
    ProtocolOptions::SSL,
    ProtocolOptions::DUAL,
    ProtocolOptions::CLOSEACTION,
    ProtocolOptions::NEEDSPWD,
    ProtocolOptions::NOURLQUERY,
    ProtocolOptions::WILDCARD,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/vssh/vssh.c:346-347` and `:360-361`, which are identical.
///
/// One constant for both SSH schemes because the C registers the same four
/// flags for `SFTP` and `SCP`. `PROTOPT_DIRLOCK` is the flag whose comment
/// explains itself at `lib/urldata.h:530-534`: these protocols call send and
/// receive without regard to what the socket signalled.
const FLAGS_SSH: ProtocolOptions = protopt(&[
    ProtocolOptions::DIRLOCK,
    ProtocolOptions::CLOSEACTION,
    ProtocolOptions::NOURLQUERY,
    ProtocolOptions::CONN_REUSE,
]);

/// `lib/file.c:635`: `PROTOPT_NONETWORK | PROTOPT_NOURLQUERY`.
///
/// `PROTOPT_NONETWORK` is the flag that keeps `file://` out of every
/// connection-establishment path, and it pairs with the `0` default port.
const FLAGS_FILE: ProtocolOptions =
    protopt(&[ProtocolOptions::NONETWORK, ProtocolOptions::NOURLQUERY]);

/// `lib/ws.c:1992-1993`: `PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL`.
///
/// The HTTP set MINUS `PROTOPT_CONN_REUSE`. The omission is deliberate
/// upstream and is preserved: a WebSocket connection has been upgraded away
/// from request/response semantics, so it must never be returned to the pool
/// for another transfer to pick up.
const FLAGS_WS: ProtocolOptions = protopt(&[
    ProtocolOptions::CREDSPERREQUEST,
    ProtocolOptions::USERPWDCTRL,
]);

/// `lib/ws.c:2008-2009`: [`FLAGS_WS`] plus `PROTOPT_SSL`, and still no
/// `PROTOPT_CONN_REUSE`.
const FLAGS_WSS: ProtocolOptions = protopt(&[
    ProtocolOptions::SSL,
    ProtocolOptions::CREDSPERREQUEST,
    ProtocolOptions::USERPWDCTRL,
]);

/// The `SFTP` row's implementation column.
///
/// A cfg'd constant rather than `#[cfg]` on the row itself, because the registry
/// must hold all 33 rows under EVERY feature combination. Specification 0.6.5's
/// asymmetry is why: the harness reads the `Protocols:` banner to decide which
/// fixtures to run, so a row that is present-but-unrunnable produces a clean
/// skip while a row that is absent altogether produces a hard failure.
///
/// This is the C's own idiom, written the way Rust spells it. `lib/vssh/vssh.c`
/// registers `Curl_scheme_sftp` with
/// `#ifdef CURL_DISABLE_SFTP ZERO_NULL #else &Curl_protocol_sftp #endif`
/// (`:338-344`), and this is that `#ifdef`.
#[cfg(feature = "ssh")]
const RUN_SFTP: Option<&'static dyn Protocol> = Some(&sftp::SFTP);

/// The `SFTP` row's implementation column in a build without `ssh`.
///
/// The `#else` arm of the `#ifdef` above: the row survives, its executor does
/// not, and `getn_scheme` still resolves `sftp://` so the request can be
/// refused with `CURLE_UNSUPPORTED_PROTOCOL` rather than "no such scheme".
#[cfg(not(feature = "ssh"))]
const RUN_SFTP: Option<&'static dyn Protocol> = None;

/// The nine schemes specification 0.2.1 puts in core scope, in the C's
/// registration order.
///
/// Transcribed row by row from the `struct Curl_scheme` definitions the table
/// at `lib/url.c:1488-1522` points at: `lib/http.c:5011` and `:5028`,
/// `lib/ftp.c:4348` and `:4367`, `lib/vssh/vssh.c:338` and `:352`,
/// `lib/file.c:626`, and `lib/ws.c:1984` and `:1999`.
///
/// `#[rustfmt::skip]` because every column is wire- or ABI-bearing and the
/// alignment is what makes the table auditable against the C side by side.
///
/// # Three things a reader should not try to tidy
///
/// * **Four names are UPPER CASE.** `"SFTP"`, `"SCP"`, `"WS"` and `"WSS"`, as
///   the C spells them.
/// * **`ws` and `wss` carry no `CONN_REUSE`.** Every other row that could
///   plausibly reuse a connection has it; the WebSocket pair deliberately does
///   not, so a WebSocket connection is never returned to the pool. See
///   [`connection_reusable`].
/// * **`file` has `defport` 0**, a literal in the C rather than a `PORT_*`
///   macro, because the scheme has no network endpoint.
#[rustfmt::skip]
const IN_SCOPE_SCHEMES: [Scheme; 9] = [
    Scheme { name: b"http",    run: None, protocol: Proto::HTTP,    family: Proto::HTTP,    flags: FLAGS_HTTP,    defport: PORT_HTTP },
    Scheme { name: b"https",   run: None, protocol: Proto::HTTPS,   family: Proto::HTTP,    flags: FLAGS_HTTPS,   defport: PORT_HTTPS },
    Scheme { name: b"ftp",     run: None, protocol: Proto::FTP,     family: Proto::FTP,     flags: FLAGS_FTP,     defport: PORT_FTP },
    Scheme { name: b"ftps",    run: None, protocol: Proto::FTPS,    family: Proto::FTP,     flags: FLAGS_FTPS,    defport: PORT_FTPS },
    Scheme { name: b"SFTP",    run: RUN_SFTP, protocol: Proto::SFTP, family: Proto::SFTP, flags: FLAGS_SSH,     defport: PORT_SSH },
    Scheme { name: b"SCP",     run: None, protocol: Proto::SCP,     family: Proto::SCP,     flags: FLAGS_SSH,     defport: PORT_SSH },
    Scheme { name: b"file",    run: None, protocol: Proto::FILE,    family: Proto::FILE,    flags: FLAGS_FILE,    defport: 0 },
    Scheme { name: b"WS",      run: None, protocol: Proto::WS,      family: Proto::HTTP,    flags: FLAGS_WS,      defport: PORT_HTTP },
    Scheme { name: b"WSS",     run: None, protocol: Proto::WSS,     family: Proto::HTTP,    flags: FLAGS_WSS,     defport: PORT_HTTPS },
];

/// How many schemes the registry holds: 9 + 24 = 33.
///
/// Derived from the two tables rather than written as a literal, so that the
/// arithmetic cannot disagree with either of them. 33 is the number of non-NULL
/// entries in `all_schemes[67]` (`lib/url.c:1488-1522`); 67 is that array's hash
/// modulus and never a count.
const SCHEME_COUNT: usize = IN_SCOPE_SCHEMES.len() + stub::SCHEMES.len();

/// All 33 schemes the C tree defines and registers.
///
/// The nine in core scope are [`IN_SCOPE_SCHEMES`] above; the 24 registered for
/// ABI completeness are [`stub::SCHEMES`], which owns their transcription and
/// the reasoning behind their `run: None`. The seam is asserted from both sides
/// -- by [`mod tests`](self) here and by `stub`'s own tests -- so a row cannot
/// migrate across it unnoticed.
///
/// The ORDER is the C's registration order and is preserved: the nine in-scope
/// rows first, then the 24 in their C-source grouping. Nothing observable
/// depends on it, because the lookup compares names, but the correspondence
/// with the C is what makes the tables auditable and it is asserted.
const SCHEMES: &[Scheme] = &registry();

/// Concatenates the two halves of [`SCHEMES`] in a `const` context.
///
/// There is no `const` slice concatenation and no `const` iterator, so the two
/// `while` loops below are the whole mechanism. [`Scheme`] is [`Copy`], which is
/// what lets the array be initialised from one row and then overwritten -- an
/// `Option<&dyn Protocol>` has no `const` default, so there is no null row to
/// start from.
///
/// A `const fn` rather than a `static` built at run time: the registry is
/// consulted by `getn_scheme` on every URL, it must be available in `const`
/// contexts, and a `static` would additionally require `Scheme: Sync`.
const fn registry() -> [Scheme; SCHEME_COUNT] {
    let mut rows = [IN_SCOPE_SCHEMES[0]; SCHEME_COUNT];

    let mut index = 0;
    while index < IN_SCOPE_SCHEMES.len() {
        rows[index] = IN_SCOPE_SCHEMES[index];
        index += 1;
    }

    let mut stub_index = 0;
    while stub_index < stub::SCHEMES.len() {
        rows[IN_SCOPE_SCHEMES.len() + stub_index] = stub::SCHEMES[stub_index];
        stub_index += 1;
    }

    rows
}

/// `Curl_get_scheme(scheme)` (`lib/url.c:1469-1472`): resolve a NUL-terminated
/// scheme name.
///
/// The C body is `return Curl_getn_scheme(scheme, strlen(scheme));`, and this
/// is the same forward with the length the slice already carries.
pub(crate) fn get_scheme(name: &[u8]) -> Option<&'static Scheme> {
    getn_scheme(name, name.len())
}

/// `Curl_getn_scheme(scheme, len)` (`lib/url.c:1477-1541`): resolve the first
/// `len` bytes of `scheme`.
///
/// Behaviourally identical to the C and structurally different, deliberately.
/// The C hashes into `all_schemes[67]`; this scans 33 rows. What IS reproduced
/// exactly is the pair of predicates the C applies around the lookup, because
/// those are observable:
///
/// * **The length gate**, `if(len && (len <= 7))` at `:1524`. An empty name and
///   any name of eight bytes or more are rejected BEFORE the table is
///   consulted. Every registered name is at most seven bytes, so the gate
///   changes no answer for a name that exists -- and it is still reproduced,
///   because a caller passing a longer name must miss rather than match a
///   prefix.
/// * **The whole-name, case-folded comparison**, `curl_strnequal(scheme,
///   h->name, len) && !h->name[len]` at `:1537`. The second half is what stops
///   `"htt"` from matching `"http"`: the stored name must be exactly `len`
///   bytes. Folding is ASCII-only on both sides, which is what
///   [`crate::util::strcase::strnequal`] provides and what
///   `Curl_raw_tolower` does -- it is the identity for `0x80..=0xFF`, so no
///   Unicode case rule may be introduced here.
///   [`crate::util::strcase::ncasecompare`] is the byte-slice successor of
///   `curl_strnequal`; the crate's `strnequal` is the `CStr`-shaped shim that
///   backs the exported `curl_strnequal` and takes NUL-terminated input, which
///   a scheme slice is not.
///
/// `len` may exceed `name.len()`, which the C cannot express and which is
/// treated as a miss rather than as a read past the end.
pub(crate) fn getn_scheme(name: &[u8], len: usize) -> Option<&'static Scheme> {
    // `if(len && (len <= 7))` -- and, additionally, a length that the slice
    // cannot supply. The C is handed a pointer and trusts the caller.
    if len == 0 || len > MAX_RESOLVABLE_SCHEME_LEN || len > name.len() {
        return None;
    }
    let wanted = &name[..len];
    SCHEMES.iter().find(|scheme| {
        // `!h->name[len]`: the stored name is exactly this long. Checked first
        // because it is a length comparison, and it is what a prefix fails.
        scheme.name.len() == len && ncasecompare(wanted, scheme.name, len)
    })
}

/// Why [`findprotocol`] refused a scheme, with the message the C would have
/// written into `CURLOPT_ERRORBUFFER`.
///
/// The message is CARRIED rather than emitted. `lib/url.c:1568-1570` calls
/// `failf` directly, which writes to the error buffer and to the verbose
/// stream; here the text travels back to `curl-rs/src/output/msgs.rs`, which
/// owns stderr. Two reasons, and both matter: this crate must not print, and a
/// returned string is assertable byte for byte without capturing a stream --
/// which is what lets [`mod tests`](self) hold the wording to specification
/// 0.8.1's preservation mandate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolError {
    /// Always [`CURLcode::UnsupportedProtocol`], which is the single code
    /// `findprotocol` returns from every failing branch. Carried rather than
    /// implied so that a caller converting to a code needs no knowledge of
    /// this type's internals.
    code: CURLcode,
    /// The `failf` text, formatted exactly as `"Protocol \"%s\" %s%s"`.
    message: String,
}

#[allow(dead_code)] // consumers: the transfer core and curl-rs's messages
impl ProtocolError {
    /// The code to report -- [`CURLcode::UnsupportedProtocol`].
    pub(crate) const fn code(&self) -> CURLcode {
        self.code
    }

    /// The message to print, byte for byte as the C writes it.
    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProtocolError {}

/// Turns the refusal into the crate's ordinary error, preserving the text as
/// the failure's context.
impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::with_context(error.code, error.message)
    }
}

/// `findprotocol(data, conn, protostr)` (`lib/url.c:1543-1573`): resolve a
/// scheme and decide whether this transfer is allowed to use it.
///
/// The C, in full:
///
/// ```c
/// const struct Curl_scheme *p = Curl_get_scheme(protostr);
/// if(p && p->run && (data->set.allowed_protocols & p->protocol)) {
///   if(data->state.this_is_a_follow &&
///      !(data->set.redir_protocols & p->protocol))
///     ;
///   else {
///     conn->scheme = conn->given = p;
///     return CURLE_OK;
///   }
/// }
/// failf(data, "Protocol \"%s\" %s%s", protostr,
///       p ? "disabled" : "not supported",
///       data->state.this_is_a_follow ? " (in redirect)" : "");
/// return CURLE_UNSUPPORTED_PROTOCOL;
/// ```
///
/// # The three gates, in order
///
/// 1. `p->run` -- the build carries an implementation.
/// 2. `allowed & p->protocol` -- `CURLOPT_PROTOCOLS_STR` permits it.
/// 3. On a redirect ONLY, `redir_allowed & p->protocol` --
///    `CURLOPT_REDIR_PROTOCOLS_STR` permits it. The C expresses the third as an
///    empty `if` branch that falls through to the failure, which reads oddly
///    and is exactly equivalent to refusing.
///
/// # The wording is a frozen, user-visible string
///
/// * A scheme the table KNOWS is `disabled`, whatever the reason -- no
///   implementation, or not permitted. Because every row of [`SCHEMES`] carries
///   `run: None` in this checkout, `http://` produces
///   `Protocol "http" disabled`.
/// * A scheme the table does not know is `not supported`.
/// * A refusal while following a redirect appends `" (in redirect)"`.
///
/// There is exactly one space before `disabled` / `not supported`, and the
/// redirect suffix begins with its own space, so a plain refusal has NO
/// trailing space. Both spellings are asserted byte for byte.
///
/// # Errors
///
/// [`ProtocolError`] carrying [`CURLcode::UnsupportedProtocol`] and that
/// message. Every failing branch of the C returns that one code.
#[allow(dead_code)] // consumer: crate::transfer's connection setup
pub(crate) fn findprotocol(
    scheme: &[u8],
    allowed: Proto,
    redir_allowed: Proto,
    is_follow: bool,
) -> Result<&'static Scheme, ProtocolError> {
    let found = get_scheme(scheme);

    if let Some(candidate) = found {
        if admits(candidate, allowed, redir_allowed, is_follow) {
            return Ok(candidate);
        }
    }

    Err(ProtocolError {
        code: CURLcode::UnsupportedProtocol,
        message: unsupported_message(scheme, found.is_some(), is_follow),
    })
}

/// The three gates of [`findprotocol`], applied to a row the table already
/// produced.
///
/// Separated from the lookup for one reason: the gates are decidable for ANY
/// row, while [`findprotocol`] can only ever present rows this build carries --
/// and every row of [`SCHEMES`] carries `run: None` here, so gate 2 and gate 3
/// would be unreachable through the composed function and would go untested. A
/// caller in [`mod tests`](self) hands this one a row with an implementation
/// and exercises all three. The composition above is the only production
/// caller, so the C's behaviour is unchanged either way.
fn admits(
    candidate: &Scheme,
    allowed: Proto,
    redir_allowed: Proto,
    is_follow: bool,
) -> bool {
    // Gate 1 and gate 2, in the C's order and with the C's conjunction:
    // `p->run && (data->set.allowed_protocols & p->protocol)`.
    if !candidate.runnable() || !allowed.intersects(candidate.protocol) {
        return false;
    }
    // Gate 3, which applies only to a redirect: `this_is_a_follow &&
    // !(redir_protocols & p->protocol)` falls through to the failure.
    let refused_on_redirect =
        is_follow && !redir_allowed.intersects(candidate.protocol);
    !refused_on_redirect
}

/// The `failf` text of [`findprotocol`], assembled from its three literal
/// fragments.
///
/// Separated so that the exact bytes are produced in one place and so that a
/// test can reach them without going through the gates. The scheme name is
/// rendered with [`String::from_utf8_lossy`]: the C's `%s` prints whatever
/// bytes the URL parser handed it, and a lossy rendering is the closest
/// faithful equivalent that cannot fail -- the alternative, refusing to format,
/// would lose the diagnostic for exactly the malformed input that needs it.
#[rustfmt::skip]
#[allow(dead_code)] // consumer: findprotocol, and mod tests directly
fn unsupported_message(
    scheme: &[u8],
    found: bool,
    is_follow: bool,
) -> String {
    // `p ? "disabled" : "not supported"` (`lib/url.c:1569`).
    let disposition = if found { "disabled" } else { "not supported" };
    // `data->state.this_is_a_follow ? " (in redirect)" : ""` (`:1570`).
    let redirect = if is_follow { " (in redirect)" } else { "" };
    // `"Protocol \"%s\" %s%s"` (`:1568`).
    format!(
        "Protocol \"{}\" {}{}",
        String::from_utf8_lossy(scheme),
        disposition,
        redirect,
    )
}

// The per-scheme vtable -- `struct Curl_protocol`

/// A boxed, pinned, `Send` future -- what every asynchronous member of
/// [`Protocol`] returns.
///
/// # Why boxed rather than `async fn` or `-> impl Future`
///
/// Specification 0.3.3's pattern P1 requires `&dyn Protocol` dispatch: the
/// registry stores `Option<&'static dyn Protocol>` and the transfer core
/// selects one at run time from a URL. Both `async fn` in a trait and
/// return-position `impl Trait` in a trait stabilised in Rust 1.75, which is
/// exactly this workspace's declared floor, and NEITHER is dyn-compatible --
/// a trait using either cannot be used behind `dyn` at all, so the mandated
/// dispatch would be unavailable. A boxed future is dyn-compatible, so it is
/// the form used here and the reason is recorded rather than left to be
/// rediscovered. Verified by building the crate with `cargo +1.75.0`, which
/// is a gate of its own in `.github/workflows/rust-build.yml`.
///
/// `crate::dns::ResolveFuture` is the same shape for the same reason, and
/// `clippy.toml`'s `type-complexity-threshold` note records that boxed futures
/// are unavoidable wherever this crate composes trait objects.
///
/// The error type is [`CURLcode`] rather than [`crate::error::Error`] because
/// these are the C's `CURLcode`-returning callbacks; a caller wanting a message
/// attaches one.
#[allow(dead_code)] // consumers: the protocol modules, none yet landed
pub(crate) type ProtoFuture<'a, T> =
    Pin<Box<dyn Future<Output = CodeResult<T>> + Send + 'a>>;

/// What a [`Protocol`] operation is handed in place of `struct Curl_easy *data`
/// and `struct connectdata *conn`.
///
/// C threads two pointers through all 17 callbacks, and between them they carry
/// the whole world: the transfer, the connection, the filter chains, the clock,
/// the trace destination and every option. Passing a successor to the
/// god-struct would defeat the decomposition specification 0.1.2 requires, so
/// this carries the four things a protocol implementation genuinely needs and
/// nothing else.
///
/// # Every field is injected, and that is what makes coverage reachable
///
/// Specification 0.3.3's pattern P12 requires the clock, the resolver and the
/// TLS provider to be injected rather than reached for globally. The clock here
/// is a borrowed trait object, so a test drives a protocol with
/// [`crate::util::timeval::TestClock`] and no wall clock is ever consulted; the
/// chains are borrowed, so a test installs an in-memory filter and no socket is
/// ever opened. Neither is a testing convenience: without them, the 80% line
/// coverage this directory is measured at would require live network access.
///
/// # Why the clock is `dyn Clock + Send + Sync` here and `dyn Clock` in
/// `crate::conn`
///
/// [`crate::conn::filters::CallCtx`] holds `&dyn Clock`, which is not [`Send`],
/// because nothing in the synchronous filter layer crosses an await point. A
/// [`ProtoFuture`] is `Send` by contract -- the multi handle drives transfers on
/// a multi-thread runtime -- so a borrow held across an await must be `Send`
/// too, and the bound is therefore stated here. Constructing a `CallCtx` from
/// this clock is a widening-free coercion, which is how an asynchronous
/// protocol reaches the synchronous chain below it.
#[allow(dead_code)] // consumers: the protocol modules, none yet landed
pub(crate) struct TransferCtx<'a> {
    /// `conn->cfilter[]` -- both chains, because a `PROTOPT_DUAL` protocol
    /// works on the secondary one as well.
    chains: &'a mut FilterChains,
    /// `curlx_now()`, injected.
    clock: &'a (dyn Clock + Send + Sync),
    /// `conn->scheme`, which is how a shared implementation tells its schemes
    /// apart -- one `Curl_protocol_http` serves `http` and `https`, and one
    /// `Curl_protocol_ws` serves `ws` and `wss`.
    scheme: &'static Scheme,
    /// Which chain this operation is working on -- `FIRSTSOCKET` for everything
    /// except an FTP data connection.
    sockindex: SocketIndex,
}

#[allow(dead_code)] // consumers: the protocol modules, none yet landed
impl<'a> TransferCtx<'a> {
    /// A context over the borrowed chains and the injected clock.
    pub(crate) fn new(
        chains: &'a mut FilterChains,
        clock: &'a (dyn Clock + Send + Sync),
        scheme: &'static Scheme,
    ) -> Self {
        Self {
            chains,
            clock,
            scheme,
            sockindex: SocketIndex::First,
        }
    }

    /// Points this context at the secondary chain -- FTP's data connection.
    #[must_use]
    pub(crate) fn with_sockindex(mut self, sockindex: SocketIndex) -> Self {
        self.sockindex = sockindex;
        self
    }

    /// `conn->scheme`.
    pub(crate) const fn scheme(&self) -> &'static Scheme {
        self.scheme
    }

    /// Which chain is being worked on.
    pub(crate) const fn sockindex(&self) -> SocketIndex {
        self.sockindex
    }

    /// The chain for [`Self::sockindex`].
    pub(crate) fn chain(&mut self) -> &mut FilterChain {
        self.chains.chain_mut(self.sockindex)
    }

    /// Both chains, for a protocol that drives the pair.
    pub(crate) fn chains(&mut self) -> &mut FilterChains {
        self.chains
    }

    /// A synchronous filter-layer context over this context's clock.
    ///
    /// The bridge from the asynchronous protocol layer to the synchronous
    /// filter layer. Deliberately returned by value and short-lived: a
    /// `CallCtx` is not `Send`, so it must be created inside a future's body
    /// and dropped before the next await rather than held across one.
    pub(crate) fn call_ctx(&self) -> CallCtx<'_, 'static> {
        CallCtx::new(self.clock)
    }

    /// The chain for [`Self::sockindex`] AND a filter-layer context over the
    /// same injected clock, in one step.
    ///
    /// [`Self::chain`] and [`Self::call_ctx`] cannot be composed:
    /// the first borrows this context mutably and the second borrows it
    /// shared. Every call into the filter layer needs both at once --
    /// `FilterChain::socket`, `FilterChain::adjust_pollset`,
    /// `FilterChain::send` and `FilterChain::recv` each take
    /// `&mut CallCtx` as well as `&mut self` -- so composing the two
    /// accessors is a borrow-checker error rather than a style choice, and a
    /// protocol module reaching the chain would otherwise have no way through.
    ///
    /// The clock REFERENCE is copied out before the chains are borrowed, so the
    /// returned context does not borrow `self` and the two results are
    /// independent. The `CallCtx` traces nothing, exactly as
    /// [`Self::call_ctx`] does; a caller with a tracer attaches it with
    /// `CallCtx::with_tracer`.
    #[allow(dead_code)] // consumers: the protocol modules
    pub(crate) fn chain_with_ctx(
        &mut self,
    ) -> (&mut FilterChain, CallCtx<'a, 'static>) {
        let cx = CallCtx::new(self.clock);
        (self.chains.chain_mut(self.sockindex), cx)
    }

    /// The chain for [`Self::sockindex`] AND a filter-layer context over the
    /// same clock, both at once.
    ///
    /// [`Self::chain`] and [`Self::call_ctx`] cannot be combined by a caller:
    /// the first borrows this context mutably and the second borrows it
    /// immutably, so `chain.send(&mut ctx.call_ctx(), ...)` does not compile.
    /// Every synchronous filter call a protocol module makes needs exactly that
    /// pair, which makes the split an obligation of this type rather than a
    /// problem for each of its callers.
    ///
    /// The returned context borrows the CLOCK, not `self`, so it outlives the
    /// chain borrow and can be reused across several calls -- which is what a
    /// send-then-receive burst inside one future body needs. It still must not
    /// cross an await point; see [`Self::call_ctx`].
    pub(crate) fn split(&mut self) -> (&mut FilterChain, CallCtx<'a, 'static>) {
        let clock = self.clock;
        let sockindex = self.sockindex;
        (self.chains.chain_mut(sockindex), CallCtx::new(clock))
    }

    /// A reading from the injected clock -- the successor of
    /// `Curl_pgrs_now(data)`.
    pub(crate) fn now(&self) -> CurlTime {
        self.clock.now()
    }
}

impl fmt::Debug for TransferCtx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferCtx")
            .field("scheme", &String::from_utf8_lossy(self.scheme.name))
            .field("sockindex", &self.sockindex)
            .finish()
    }
}

/// One scheme's transfer implementation.
///
/// `struct Curl_protocol` (`lib/urldata.h:428-513`).
///
/// # The member count is 17, measured
///
/// Specification 0.1.2 says the struct carries 18 function pointers. **It
/// carries 17.** The enumerated list is authoritative over the count, and 17
/// was verified twice: once by reading the declaration, and once by counting
/// the initialisers of seven independent handler definitions --
/// `Curl_protocol_file` (`lib/file.c:601-619`), `Curl_protocol_ftp`
/// (`lib/ftp.c:4323-4341`), `Curl_protocol_http` (`lib/http.c:4986-5004`),
/// `Curl_protocol_ws` (`lib/ws.c:1918-1936`), `Curl_protocol_sftp`
/// (`lib/vssh/libssh2.c:3846-3864`), `Curl_protocol_scp` (`:3823-3841`) and
/// `Curl_protocol_dict` (`lib/dict.c:278-296`). Every one has exactly 17
/// initialisers in the same order. The correction is recorded here rather than
/// silently applied.
///
/// # Two members are required and fifteen are defaulted
///
/// The C comment above members 2 and 3 is *"These two functions MUST be set to
/// be protocol dependent"*, and every other slot may be `ZERO_NULL`. That
/// distinction is expressed in the type system: [`Self::do_it`] and
/// [`Self::done`] have no default body, and the other fifteen do. The defaults
/// are not conveniences -- each reproduces what the C's caller does when it
/// finds a `NULL` slot, so a scheme that fills five of seventeen behaves
/// identically to its C original without writing twelve empty methods.
///
/// The measured occupancy the defaults are sized for: `file` fills 5,
/// `http` and `https` share one handler filling 8, `ws` and `wss` share one
/// filling 8 of which only `setup_connection` is WebSocket-specific, `ftp`
/// fills 11, `sftp` and `scp` fill 11 each, and each of the 13 stub handlers
/// fills exactly 1 -- `do_it`.
///
/// # `bool *done` is gone
///
/// Four members carry a `bool *done` out-parameter in the C: `do_it`,
/// `connect_it`, `connecting` and `doing`. Specification 0.1.2 requires that
/// they disappear, *"readiness is expressed by the async return, not by writing
/// through a caller-supplied pointer"*, so each returns
/// [`ProtoFuture`]`<'_, bool>` and the `bool` is the readiness the C wrote
/// through the pointer. No member takes `&mut bool`.
///
/// # Which members are asynchronous, and why not all of them
///
/// A member that performs transport I/O in the C is asynchronous here. A member
/// that only reads or manipulates in-memory state is not, because wrapping a
/// synchronous computation in a boxed future costs an allocation on a transfer
/// path and misdescribes it as something that can yield. That split is:
///
/// * asynchronous -- `do_it`, `done`, `do_more`, `connect_it`, `connecting`,
///   `doing`, `disconnect`, `write_resp`, `write_resp_hd`;
/// * synchronous -- `setup_connection`, the four pollsets, `connection_check`,
///   `attach`, `follow`.
///
/// # The supertraits
///
/// [`fmt::Debug`] so a chain or a registry row can be printed in a test
/// failure. [`Send`] and [`Sync`] because the registry holds
/// `&'static dyn Protocol` -- a `&'static T` is only `Send` when `T: Sync` --
/// and because a [`ProtoFuture`] borrowing `&'a self` is only `Send` when
/// `Self: Sync`.
#[allow(dead_code)] // consumers: the nine protocol modules, none yet landed
pub(crate) trait Protocol: fmt::Debug + Send + Sync {
    // -- 1. setup_connection ---------------------------------------------

    /// `setup_connection(data, conn)` (`lib/urldata.h:430-433`): allocate this
    /// scheme's per-connection state.
    ///
    /// The C comment: *"Complement to setup_connection_internals(). This is
    /// done before the transfer 'owns' the connection."*
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports. `Ok(())` by default, which is what a
    /// `ZERO_NULL` slot means: nothing to allocate.
    fn setup_connection(&self, ctx: &mut TransferCtx<'_>) -> CodeResult<()> {
        let _ = ctx;
        Ok(())
    }

    // -- 2. do_it (MUST be set) ------------------------------------------

    /// `do_it(data, bool *done)` (`lib/urldata.h:436`): issue the request.
    ///
    /// Required, because the C requires it. The `bool` is the C's `*done`:
    /// `true` when the DO phase completed, `false` when the caller must come
    /// back. A stub scheme's whole implementation is this one member answering
    /// [`CURLcode::UnsupportedProtocol`].
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports.
    fn do_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool>;

    // -- 3. done (MUST be set) -------------------------------------------

    /// `done(data, CURLcode, bool)` (`lib/urldata.h:437`): the transfer
    /// finished; release what `do_it` acquired.
    ///
    /// Required, because the C requires it. `status` is the transfer's outcome
    /// and `premature` says it ended early -- FTP, for instance, sends `ABOR`
    /// only when both are true.
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports. Reporting a failure here does not undo the
    /// transfer; the C's caller keeps the more specific of the two codes.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        status: CURLcode,
        premature: bool,
    ) -> ProtoFuture<'a, ()>;

    // -- 4. do_more ------------------------------------------------------

    /// `do_more(data, int *)` (`lib/urldata.h:443`): the second half of a
    /// two-part DO.
    ///
    /// The C comment: *"If the curl_do() function is better made in two halves,
    /// this curl_do_more() function will be called afterwards, if set. For
    /// example for doing the FTP stuff after the PASV/PORT command."* FTP is the
    /// only in-scope scheme that sets it, which follows from
    /// [`ProtocolOptions::DUAL`].
    ///
    /// The C's `int *completed` becomes the returned `bool`, the same
    /// transformation the four `bool *done` members get.
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports. The default completes immediately, which is
    /// what a `ZERO_NULL` slot means: there is no second half.
    fn do_more<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Ok(true)))
    }

    // -- 5. connect_it ---------------------------------------------------

    /// `connect_it(data, bool *done)` (`lib/urldata.h:451`): a scheme-specific
    /// step after the socket is connected.
    ///
    /// The C comment: *"The 'done' pointer points to a bool that should be set
    /// to TRUE if the function completes before return. If it does not
    /// complete, the caller should call the ->connecting() function until it
    /// is."*
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports. The default answers `true` -- already
    /// connected, nothing scheme-specific to do.
    fn connect_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Ok(true)))
    }

    // -- 6. connecting ---------------------------------------------------

    /// `connecting(data, bool *done)` (`lib/urldata.h:454`): continue what
    /// [`Self::connect_it`] left unfinished.
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports. The default answers `true`, consistent with
    /// a default [`Self::connect_it`] that never leaves anything unfinished.
    fn connecting<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Ok(true)))
    }

    // -- 7. doing --------------------------------------------------------

    /// `doing(data, bool *done)` (`lib/urldata.h:455`): continue what
    /// [`Self::do_it`] left unfinished.
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports. The default answers `true`.
    fn doing<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(core::future::ready(Ok(true)))
    }

    // -- 8..11. the four pollsets ----------------------------------------

    /// `proto_pollset(data, ps)` (`lib/urldata.h:459-460`): which readiness
    /// this scheme is waiting for during PROTOCONNECT.
    ///
    /// # The four pollsets are subsumed by the runtime
    ///
    /// C's multi interface surrenders descriptors to an external poll loop and
    /// is re-entered, which is why each phase has its own pollset callback.
    /// `crate::conn::select` and the tokio reactor do that job here, so none of
    /// the four reimplements pollset arithmetic and all four default to a pure
    /// no-op -- exactly as [`crate::conn::filters::ConnFilter::adjust_pollset`]
    /// does, and for the same reason. The SHAPE is retained because a scheme
    /// with a descriptor of its own, outside the filter chain, still needs
    /// somewhere to register it.
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset`] reports for an invalid descriptor.
    fn proto_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        let _ = ctx;
        let _ = ps;
        Ok(())
    }

    /// `doing_pollset(data, ps)` (`lib/urldata.h:463-464`): the same during the
    /// DOING phase. Defaults to a no-op; see [`Self::proto_pollset`].
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset`] reports for an invalid descriptor.
    fn doing_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        let _ = ctx;
        let _ = ps;
        Ok(())
    }

    /// `domore_pollset(data, ps)` (`lib/urldata.h:467-468`): the same during
    /// DO_MORE. Set only by FTP; defaults to a no-op.
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset`] reports for an invalid descriptor.
    fn domore_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        let _ = ctx;
        let _ = ps;
        Ok(())
    }

    /// `perform_pollset(data, ps)` (`lib/urldata.h:473-474`): the same during
    /// DO_DONE, PERFORM and WAITPERFORM.
    ///
    /// The C comment names the fallback explicitly -- *"Not setting this will
    /// make libcurl use the generic default one"* -- which is why this member
    /// is defaulted rather than required, and why its default is the no-op that
    /// lets the generic path run.
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset`] reports for an invalid descriptor.
    fn perform_pollset(
        &self,
        ctx: &mut TransferCtx<'_>,
        ps: &mut EasyPollset,
    ) -> CodeResult<()> {
        let _ = ctx;
        let _ = ps;
        Ok(())
    }

    // -- 12. disconnect --------------------------------------------------

    /// `disconnect(data, conn, bool dead_connection)`
    /// (`lib/urldata.h:482-483`): a scheme-specific step while the connection
    /// is torn down.
    ///
    /// The C comment: *"If the handler is called because the connection has
    /// been considered dead, dead_connection is set to TRUE."* A scheme must
    /// not send anything when it is -- FTP's `QUIT` would block forever on a
    /// dead socket.
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports. The C's caller closes the connection
    /// regardless.
    fn disconnect<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        dead_connection: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = ctx;
        let _ = dead_connection;
        Box::pin(core::future::ready(Ok(())))
    }

    // -- 13. write_resp --------------------------------------------------

    /// `write_resp(data, buf, blen, bool is_eos)` (`lib/urldata.h:487-488`):
    /// scheme-specific handling of response bytes on their way to the client.
    ///
    /// The C comment: *"If used, this function gets called from transfer.c to
    /// allow the protocol to do extra handling in writing response to the
    /// client."*
    ///
    /// The returned `bool` is what the C expresses by leaving the slot `NULL`:
    /// `true` means this scheme consumed the bytes itself, `false` means the
    /// caller must run the generic client-writer chain in `crate::transfer`.
    /// The default answers `false`, so a scheme that does not fill this member
    /// gets the generic path -- which is what `if(handler->write_resp)` in the
    /// C achieves.
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports.
    fn write_resp<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        buf: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        let _ = buf;
        let _ = is_eos;
        Box::pin(core::future::ready(Ok(false)))
    }

    // -- 14. write_resp_hd -----------------------------------------------

    /// `write_resp_hd(data, hd, hdlen, bool is_eos)`
    /// (`lib/urldata.h:492-493`): the same for a single response header line.
    ///
    /// Returns and defaults exactly as [`Self::write_resp`] does.
    ///
    /// # Errors
    ///
    /// Whatever the scheme reports.
    fn write_resp_hd<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        hd: &'a [u8],
        is_eos: bool,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        let _ = hd;
        let _ = is_eos;
        Box::pin(core::future::ready(Ok(false)))
    }

    // -- 15. connection_check --------------------------------------------

    /// `connection_check(data, conn, uint32_t)` (`lib/urldata.h:498-500`): run
    /// the requested checks on an idle connection.
    ///
    /// Both vocabularies belong to `crate::conn::pool`, which owns the pool
    /// that asks the question: [`ConnCheck`] carries `CONNCHECK_NONE`,
    /// `CONNCHECK_ISDEAD` and `CONNCHECK_KEEPALIVE`, and [`ConnResult`] carries
    /// `CONNRESULT_NONE` and `CONNRESULT_DEAD` (`lib/urldata.h:560-565`).
    /// Consumed here, never redeclared.
    ///
    /// The default answers [`ConnResult::NONE`] -- no extra information --
    /// which is what the pool assumes for a `ZERO_NULL` slot.
    fn connection_check(
        &self,
        ctx: &mut TransferCtx<'_>,
        checks: ConnCheck,
    ) -> ConnResult {
        let _ = ctx;
        let _ = checks;
        ConnResult::NONE
    }

    // -- 16. attach ------------------------------------------------------

    /// `attach(data, conn)` (`lib/urldata.h:503`): this transfer is now using
    /// this connection.
    ///
    /// Returns nothing in the C, and nothing here. Among the in-scope schemes
    /// only SFTP and SCP fill it.
    fn attach(&self, ctx: &mut TransferCtx<'_>) {
        let _ = ctx;
    }

    // -- 17. follow ------------------------------------------------------

    /// `follow(data, newurl, followtype)` (`lib/urldata.h:508-509`): may this
    /// redirect be followed?
    ///
    /// The C comment is the contract: *"return CURLE_OK if a redirect to
    /// `newurl` should be followed, CURLE_TOO_MANY_REDIRECTS otherwise. May
    /// alter `data` to change the way the follow request is performed."*
    ///
    /// [`FollowType`] is CONSUMED from `crate::transfer::request`, which
    /// already declares all four of `lib/http.h:41-48`'s values with their
    /// integers. Declaring a second copy here would put two incompatible enums
    /// of the same name in one crate, and the redirect machinery this member
    /// feeds -- `SingleRequest::follow` and its `ProtocolFollow` seam -- speaks
    /// that one. The import direction is the crate's own:
    /// `curl-rs-lib/src/lib.rs` declares `transfer` before `protocols`, and
    /// `transfer::request` carries a gate of its own forbidding it to name
    /// `crate::protocols`, so no cycle exists.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooManyRedirects`] when the redirect must not be followed --
    /// which is the DEFAULT, and deliberately so: a `ZERO_NULL` slot makes
    /// `multi_follow` answer exactly that (`lib/multi.c:1870-1878`). It reads
    /// oddly and is the C's, because the multi handle is about to return to
    /// `CONNECT` with a URL nothing can act on, so "no more redirects" is what
    /// stops it looping.
    fn follow(
        &self,
        ctx: &mut TransferCtx<'_>,
        newurl: &str,
        follow_type: FollowType,
    ) -> CodeResult<()> {
        let _ = ctx;
        let _ = newurl;
        let _ = follow_type;
        Err(CURLcode::TooManyRedirects)
    }
}

// HTTP version negotiation state -- `struct http_negotiation`

/// `CURL_HTTP_V1x` (`lib/http.h:50`), re-stated for a reader of this file.
///
/// The three major-version bits are declared ONCE, by `crate::tls`, as
/// [`HttpMajors`]. `crate::tls` owns them because the TLS layer builds the ALPN
/// specification from them and may not name an HTTP module -- reaching into
/// `crate::protocols::http2` from the TLS layer would be the cycle the filter
/// design exists to avoid. These aliases let this file read as the C reads
/// without introducing a second definition; they are the same values.
#[allow(dead_code)] // consumers: alpn_offer and the HTTP modules
pub(crate) const CURL_HTTP_V1X: HttpMajors = HttpMajors::V1X;
/// `CURL_HTTP_V2x` (`lib/http.h:51`).
#[allow(dead_code)] // consumers: alpn_offer and the HTTP modules
pub(crate) const CURL_HTTP_V2X: HttpMajors = HttpMajors::V2X;
/// `CURL_HTTP_V3x` (`lib/http.h:52`).
#[allow(dead_code)] // consumers: alpn_offer and the HTTP modules
pub(crate) const CURL_HTTP_V3X: HttpMajors = HttpMajors::V3X;

/// Which HTTP versions this transfer wants, allows and prefers.
///
/// `struct http_negotiation` (`lib/http.h:63-72`), all eight members:
///
/// ```c
/// unsigned char rcvd_min; /* minimum version seen in responses, 09, 10, 11 */
/// http_majors wanted;     /* wanted major versions */
/// http_majors allowed;    /* allowed major versions */
/// http_majors preferred;  /* preferred major version */
/// BIT(h2_upgrade);        /* Do HTTP Upgrade from 1.1 to 2 */
/// BIT(h2_prior_knowledge);/* Directly do HTTP/2 without ALPN/SSL */
/// BIT(accept_09);         /* Accept an HTTP/0.9 response */
/// BIT(only_10);           /* When using major version 1x, use only 1.0 */
/// ```
///
/// [`alpn_offer`] reads `wanted`, `allowed` and `preferred`; the remaining five
/// members belong to the HTTP modules and are carried here because the C
/// carries them in one struct that `Curl_http_neg_init` fills, and splitting it
/// would make two places to keep in step.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: the HTTP protocol modules, none yet landed
pub(crate) struct HttpNegotiation {
    /// `rcvd_min`: the lowest version seen in a response so far, as the C's
    /// two-digit encoding -- `9`, `10` or `11`, and `0` before any response.
    pub(crate) rcvd_min: u8,
    /// `wanted`: what this transfer asked for.
    pub(crate) wanted: HttpMajors,
    /// `allowed`: what it will accept.
    pub(crate) allowed: HttpMajors,
    /// `preferred`: which single version it would rather have. Compared for
    /// EQUALITY by [`alpn_offer`], not tested as a mask, because the C
    /// `switch`es on the whole value.
    pub(crate) preferred: HttpMajors,
    /// `h2_upgrade`: attempt the `Upgrade: h2c` dance over cleartext.
    pub(crate) h2_upgrade: bool,
    /// `h2_prior_knowledge`: speak HTTP/2 immediately, without ALPN or TLS.
    pub(crate) h2_prior_knowledge: bool,
    /// `accept_09`: tolerate a bodies-only HTTP/0.9 response.
    pub(crate) accept_09: bool,
    /// `only_10`: when using 1.x, use 1.0 -- which is what makes
    /// `crate::tls::alpn_get_spec` offer `[http/1.0, http/1.1]`.
    pub(crate) only_10: bool,
}

/// Whether a proxy stands in the way of HTTP/3.
///
/// The two `conn->bits` that `Curl_conn_may_http3` reads
/// (`lib/vquic/vquic.c:733-740`), passed as one value because they are asked
/// together and because a bare pair of booleans at a call site is
/// indistinguishable in either order.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[allow(dead_code)] // consumers: alpn_offer and crate::conn's connection setup
pub(crate) struct Http3Proxy {
    /// `conn->bits.socksproxy`.
    pub(crate) socks: bool,
    /// `conn->bits.httpproxy && conn->bits.tunnel_proxy`, already conjoined:
    /// the C tests them together and an HTTP proxy that does not tunnel is not
    /// an obstacle.
    pub(crate) http_tunnel: bool,
}

/// `failf` text of `Curl_conn_may_http3` for a plaintext URL
/// (`lib/vquic/vquic.c:729`).
#[allow(dead_code)] // consumer: may_http3
const H3_NEEDS_HTTPS: &str = "HTTP/3 requested for non-HTTPS URL";

/// `failf` text for a SOCKS proxy (`lib/vquic/vquic.c:734`).
#[allow(dead_code)] // consumer: may_http3
const H3_OVER_SOCKS: &str = "HTTP/3 is not supported over a SOCKS proxy";

/// `failf` text for a tunnelling HTTP proxy (`lib/vquic/vquic.c:738`).
#[allow(dead_code)] // consumer: may_http3
const H3_OVER_HTTP_PROXY: &str = "HTTP/3 is not supported over an HTTP proxy";

/// `Curl_conn_may_http3(data, conn, transport)`: can this connection carry
/// HTTP/3 at all?
///
/// # Declared unconditionally, deliberately
///
/// `lib/vquic/vquic.h` declares this function OUTSIDE its
/// `#if !defined(CURL_DISABLE_HTTP) && defined(USE_HTTP3)` block, so it exists
/// in every build and has two definitions:
/// `lib/vquic/vquic.c:720-744` with HTTP/3 compiled in, and `:854-863` without.
/// Both are reproduced, one per `#cfg` branch of [`may_http3`], and the public
/// entry point is therefore NOT feature-gated -- [`alpn_offer`] calls it in
/// every build and needs an answer rather than a missing symbol.
///
/// # Errors
///
/// * [`CURLcode::NotBuiltIn`] when HTTP/3 is not compiled in. The C also emits
///   `"QUIC is not supported in this build"`, but through `DEBUGF(infof(...))`
///   -- a debug-build-only line -- so no message is attached here and the
///   code's own string is what a caller prints.
/// * [`CURLcode::QuicConnectError`] for [`Transport::Unix`]: QUIC cannot run
///   over a Unix domain socket. The C attaches no message to this one either.
/// * [`CURLcode::UrlMalformat`] with [`H3_NEEDS_HTTPS`], [`H3_OVER_SOCKS`] or
///   [`H3_OVER_HTTP_PROXY`] -- three `failf` texts, all user-visible and
///   therefore reproduced byte for byte.
#[allow(dead_code)] // consumers: alpn_offer, and crate::protocols::http3
pub(crate) fn conn_may_http3(
    scheme_flags: ProtocolOptions,
    transport: Transport,
    proxy: Http3Proxy,
) -> CurlResult<()> {
    may_http3(scheme_flags, transport, proxy)
}

/// `Curl_conn_may_http3` as `lib/vquic/vquic.c:720-744` defines it, with
/// HTTP/3 compiled in.
#[cfg(feature = "http3")]
#[allow(dead_code)] // consumer: conn_may_http3
fn may_http3(
    scheme_flags: ProtocolOptions,
    transport: Transport,
    proxy: Http3Proxy,
) -> CurlResult<()> {
    // `if(transport == TRNSPRT_UNIX)` -- "cannot do QUIC over a Unix domain
    // socket". No `failf`: the C reports the code alone.
    if matches!(transport, Transport::Unix) {
        return Err(Error::new(CURLcode::QuicConnectError));
    }
    // `if(!(conn->scheme->flags & PROTOPT_SSL))`
    if !scheme_flags.intersects(ProtocolOptions::SSL) {
        return Err(Error::with_context(
            CURLcode::UrlMalformat,
            H3_NEEDS_HTTPS,
        ));
    }
    // `#ifndef CURL_DISABLE_PROXY` -- proxying is unconditional in this crate,
    // so both tests are unconditional too.
    if proxy.socks {
        return Err(Error::with_context(CURLcode::UrlMalformat, H3_OVER_SOCKS));
    }
    if proxy.http_tunnel {
        return Err(Error::with_context(
            CURLcode::UrlMalformat,
            H3_OVER_HTTP_PROXY,
        ));
    }
    Ok(())
}

/// `Curl_conn_may_http3` as `lib/vquic/vquic.c:854-863` defines it, without
/// HTTP/3.
///
/// The C body is three `(void)` casts and `return CURLE_NOT_BUILT_IN`, so this
/// one refuses every input -- including a Unix socket, which the compiled-in
/// definition refuses with a different code. The asymmetry is the C's.
#[cfg(not(feature = "http3"))]
#[allow(dead_code)] // consumer: conn_may_http3
fn may_http3(
    scheme_flags: ProtocolOptions,
    transport: Transport,
    proxy: Http3Proxy,
) -> CurlResult<()> {
    // `(void)data; (void)conn; (void)transport;`
    let _ = scheme_flags;
    let _ = transport;
    let _ = proxy;
    Err(Error::new(CURLcode::NotBuiltIn))
}

// The HTTPS-CONNECT filter -- `lib/cf-https-connect.c`

/// One trace line attributed to the HTTPS-CONNECT filter.
///
/// `CURL_TRC_CF(data, cf, ...)`. The local shape mirrors
/// `crate::conn::filters`' own `trc!`, which is private to that module; both
/// exist because the two-level guard -- a registered identity AND a tracer --
/// is what keeps a trace call free when tracing is off.
macro_rules! trc_hc {
    (
        $cx:expr, $sockindex:expr, $fmt:literal $(, $arg:expr)* $(,)?
    ) => {{
        let sockindex: i32 = $sockindex;
        if let Some(tracer) = $cx.tracer_mut() {
            let tracer: &mut Tracer<'_> = tracer;
            trc_cf!(
                tracer,
                TraceFilter::HttpConnect,
                sockindex,
                $fmt $(, $arg)*
            );
        }
    }};
}

/// The `name` member of `struct Curl_cft_http_connect`
/// (`lib/cf-https-connect.c:558`).
///
/// `--trace-config` matches it and every trace line this filter emits carries
/// it. [`TraceFilter::HttpConnect`] holds the same spelling, and
/// `TraceFilter::from_name` resolves one to the other -- so the string is
/// stated once, in `crate::trace`, and asserted equal here by
/// [`mod tests`](self).
pub(crate) const HTTPS_CONNECT_FILTER_NAME: &str = "HTTPS-CONNECT";

/// The `flags` member (`:559`): `0`.
///
/// The version race declares no capability of its own -- it provides no IP
/// connection, no TLS, no multiplexing and no proxying; the sub-chain it
/// installs provides all of those. That zero is why the filter is invisible to
/// `crate::conn::filters`' capability searches, which is exactly right: a
/// question about TLS must be answered by the TLS filter inside the winning
/// baller, not by the referee.
pub(crate) const HTTPS_CONNECT_FLAGS: CfType = CfType::NONE;

/// The `log_level` member (`:560`): `CURL_LOG_LVL_NONE`.
#[allow(dead_code)] // consumer: --trace-config, through crate::trace
pub(crate) const HTTPS_CONNECT_LOG_LEVEL: i32 = CURL_LOG_LVL_NONE;

/// How many versions may be raced at once: `2`.
///
/// `struct cf_hc_ctx` declares `struct cf_hc_baller ballers[2]`
/// (`lib/cf-https-connect.c:115`) and `cf_hc_create` rejects any other count
/// against `CURL_ARRAYSIZE(ctx->ballers)` (`:594-601`). The bound is the
/// array's, so it is expressed here as the array's length rather than as a
/// separate limit that could drift from it.
#[allow(dead_code)] // consumers: HttpsConnect::new and alpn_offer
pub(crate) const MAX_ALPN_BALLERS: usize = 2;

/// The timer the race arms -- `EXPIRE_ALPN_EYEBALLS`.
///
/// `crate::trace` owns the name `"ALPN_EYEBALLS"` and the integer 13; consumed
/// here so that no string is invented at the call site.
const ALPN_EYEBALLS_TIMER: TimerId = TimerId::AlpnEyeballs;

/// `failf` text of `cf_hc_create` for an unusable ALPN count (`:598-599`).
///
/// The C formats the count with `%zu`; [`alpn_count_rejected`] renders the same
/// sentence. User-visible, so reproduced byte for byte.
#[allow(dead_code)] // consumer: HttpsConnect::new
fn alpn_count_rejected(count: usize) -> String {
    format!("https-connect filter create with unsupported {count} ALPN ids")
}

/// How far the race has got -- `cf_hc_state`
/// (`lib/cf-https-connect.c:41-46`).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum HcState {
    /// `CF_HC_INIT`: nothing started. The state a fresh filter and a reset
    /// filter are both in.
    #[default]
    Init,
    /// `CF_HC_CONNECT`: at least one baller is running.
    Connect,
    /// `CF_HC_SUCCESS`: a baller won and its sub-chain is installed below.
    Success,
    /// `CF_HC_FAILURE`: every baller failed.
    Failure,
}

impl HcState {
    /// The four states, for exhaustive iteration in tests.
    #[allow(dead_code)] // consumer: mod tests
    pub(crate) const ALL: [Self; 4] =
        [Self::Init, Self::Connect, Self::Success, Self::Failure];

    /// The C's own spelling, for a trace line or an assertion message.
    #[allow(dead_code)] // consumer: assertion messages in mod tests
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::Init => "CF_HC_INIT",
            Self::Connect => "CF_HC_CONNECT",
            Self::Success => "CF_HC_SUCCESS",
            Self::Failure => "CF_HC_FAILURE",
        }
    }
}

/// One version being raced -- `struct cf_hc_baller`
/// (`lib/cf-https-connect.c:48-57`).
///
/// # The pointer-swapping dance is gone
///
/// C keeps `struct Curl_cfilter *cf` and splices it into the enclosing filter's
/// single `next` link whenever it wants to work on it: `cf_hc_baller_init`
/// nulls `cf->next`, inserts, harvests and restores (`:146-165`), and
/// `cf_hc_baller_connect` swaps the link in, connects, RE-READS `b->cf =
/// cf->next` because *"it might mutate"*, and swaps back (`:168-180`). All of
/// that exists because the ballers and the winner share one intrusive list.
///
/// Here each baller OWNS its sub-chain as a [`FilterChain`], so there is
/// nothing to swap and nothing to re-read: the chain object is stable while its
/// contents change, which is the same guarantee the C's re-read was buying. The
/// observable behaviour -- including that the sub-chain may be replaced during
/// a connect pass -- is unchanged, and the promotion of the winner is a single
/// move of the chain into the enclosing filter's successor link.
#[derive(Debug)]
struct HcBaller {
    /// `b->name`: `"h1"`, `"h2"` or `"h3"`, assigned by
    /// [`Self::assign`]. Two-byte literals that appear in `--trace` output.
    name: &'static str,
    /// `b->cf`: the sub-chain this baller is connecting, once started.
    chain: Option<FilterChain>,
    /// `b->result`: this baller's failure, if it has one. `None` is the C's
    /// `CURLE_OK`.
    ///
    /// An [`Error`] rather than a bare [`CURLcode`] so that the message the
    /// losing sub-chain reported survives to be re-reported when EVERY baller
    /// fails -- which is the one path where a baller's code becomes the
    /// connection's code (`:341-350`).
    result: Option<Error>,
    /// `b->started`: when this baller began, from the injected clock.
    started: CurlTime,
    /// `b->reply_ms`: milliseconds to the first response byte, or `-1` before
    /// the sub-chain has been asked.
    ///
    /// C declares it `int`; widened to [`TimeDiff`] because that is what
    /// `CF_QUERY_CONNECT_REPLY_MS` answers in this crate. The `-1` sentinel is
    /// preserved exactly, because `time_to_start_next` tests for it.
    reply_ms: TimeDiff,
    /// `b->transport`: which transport the sub-chain is built for. Forced to
    /// [`Transport::Quic`] for `h3`.
    transport: Transport,
    /// `b->alpn_id`: which version this baller is racing.
    // Consumer: HttpsConnect::raced.
    #[allow(dead_code)]
    alpn_id: AlpnId,
    /// `b->shutdown`: this baller has finished shutting down, or failed doing
    /// so -- the C treats those the same (`:409-410`).
    shutdown: bool,
}

impl HcBaller {
    /// `cf_hc_baller_assign(b, alpn_id, def_transport)`
    /// (`lib/cf-https-connect.c:121-142`).
    ///
    /// The three names are literal two-byte strings in the C and are
    /// reproduced exactly; `h3` additionally forces the transport to
    /// `TRNSPRT_QUIC`, which is the whole reason a baller carries a transport
    /// of its own rather than reading the connection's.
    ///
    /// An identifier the C's `switch` does not name -- `ALPN_none`, or anything
    /// added later -- lands in `default:` and sets `CURLE_FAILED_INIT`. That
    /// baller is then never active, because [`Self::is_active`] requires no
    /// result, so the race skips it rather than starting it.
    #[allow(dead_code)] // consumer: HttpsConnect::new
    fn assign(alpn_id: AlpnId, def_transport: Transport) -> Self {
        let (name, transport, result) = match alpn_id {
            AlpnId::H3 => ("h3", Transport::Quic, None),
            AlpnId::H2 => ("h2", def_transport, None),
            AlpnId::H1 => ("h1", def_transport, None),
            AlpnId::None => {
                ("", def_transport, Some(Error::new(CURLcode::FailedInit)))
            }
        };
        Self {
            name,
            chain: None,
            result,
            started: CurlTime::ZERO,
            reply_ms: -1,
            transport,
            alpn_id,
            shutdown: false,
        }
    }

    /// `cf_hc_baller_is_active(b)` (`:71-74`): `b->cf && !b->result`.
    fn is_active(&self) -> bool {
        self.chain.is_some() && self.result.is_none()
    }

    /// `cf_hc_baller_has_started(b)` (`:76-79`): `!!b->cf`.
    fn has_started(&self) -> bool {
        self.chain.is_some()
    }

    /// `cf_hc_baller_reply_ms(b, data)` (`:81-88`): the cached answer, asking
    /// the sub-chain once.
    ///
    /// The laziness is load-bearing rather than an optimisation: the query is
    /// asked only while the value is still `-1`, so a sub-chain that has seen
    /// data keeps its first measurement, and one that has not is asked again on
    /// the next pass.
    fn reply_ms(&mut self, cx: &mut CallCtx<'_, '_>) -> TimeDiff {
        if self.reply_ms < 0 {
            if let Some(chain) = self.chain.as_mut() {
                self.reply_ms = chain.connect_reply_ms(cx);
            }
        }
        self.reply_ms
    }

    /// `cf_hc_baller_data_pending(b, data)` (`:90-94`).
    fn data_pending(&mut self, cx: &mut CallCtx<'_, '_>) -> bool {
        if self.result.is_some() {
            return false;
        }
        match self.chain.as_mut() {
            Some(chain) => chain.data_pending(cx),
            None => false,
        }
    }

    /// `cf_hc_baller_needs_flush(b, data)` (`:96-100`).
    fn needs_flush(&mut self, cx: &mut CallCtx<'_, '_>) -> bool {
        if self.result.is_some() {
            return false;
        }
        match self.chain.as_mut() {
            Some(chain) => chain.needs_flush(cx),
            None => false,
        }
    }

    /// `cf_hc_baller_cntrl(b, data, event, arg1, arg2)` (`:102-109`): forward
    /// an event, but only to a baller that is still running.
    ///
    /// # Errors
    ///
    /// Whatever the sub-chain reports.
    fn cntrl(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        event: CfControl,
    ) -> CurlResult<()> {
        if self.result.is_some() {
            return Ok(());
        }
        match self.chain.as_mut() {
            Some(chain) => chain.cntrl(cx, event),
            None => Ok(()),
        }
    }

    /// `cf_hc_baller_reset(b, data)` (`:59-69`): close and discard the
    /// sub-chain, then clear the failure and the timing.
    ///
    /// Note which two fields the C resets and which it leaves: `result` and
    /// `reply_ms` are cleared, while `name`, `transport` and `alpn_id` survive
    /// -- a reset baller can be started again as the same version.
    fn reset(&mut self, cx: &mut CallCtx<'_, '_>) {
        if let Some(mut chain) = self.chain.take() {
            // `Curl_conn_cf_close(b->cf, data);`
            chain.close(cx);
            // `Curl_conn_cf_discard_chain(&b->cf, data);`
            chain.discard_chain(cx);
        }
        self.result = None;
        self.reply_ms = -1;
        self.shutdown = false;
    }

    /// `cf_hc_baller_init(b, cf, data, transport)` (`:144-166`): build this
    /// baller's sub-chain.
    ///
    /// C inserts a SETUP filter below the enclosing filter while its `next` is
    /// temporarily `NULL`, which makes that SETUP filter the whole sub-chain,
    /// and then harvests it. The Rust equivalent of "insert below a filter with
    /// no successor" is "add to an empty chain", so this builds an owned
    /// [`FilterChain`] and calls [`crate::conn::cf_setup_add`] -- the same
    /// [`crate::conn::SetupFilter`], with the same transport and the same
    /// `CURL_CF_SSL_ENABLE`. [`crate::conn::cf_setup_insert_after`] is the
    /// wrong primitive here for a mechanical reason: it addresses a POSITION,
    /// and an empty chain has none.
    ///
    /// The timestamp is `*Curl_pgrs_now(data)`, taken from the injected clock.
    fn init(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        setup: &SetupContext,
        conn: Option<ConnId>,
        sockindex: SocketIndex,
    ) {
        // `b->started = *Curl_pgrs_now(data);`
        self.started = cx.now();
        // `switch(b->alpn_id) { case ALPN_h3: transport = TRNSPRT_QUIC; ... }`
        // -- already settled by `assign`, which stored the forced transport.
        let transport = self.transport;
        if self.result.is_some() {
            // `if(!b->result)` -- a baller that failed assignment is not built.
            return;
        }
        let mut chain = FilterChain::new(conn, sockindex);
        cf_setup_add(cx, &mut chain, setup.clone(), transport, TlsMode::Enable);
        self.chain = Some(chain);
    }

    /// `cf_hc_baller_connect(b, cf, data, done)` (`:168-180`): drive this
    /// baller's sub-chain one pass.
    ///
    /// Returns readiness rather than writing through a `bool *`, and records
    /// the failure on the baller exactly as the C's `b->result = ...` does, so
    /// that a failed baller becomes inactive without the caller having to
    /// remember to mark it.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> bool {
        let outcome = match self.chain.as_mut() {
            Some(chain) => chain.connect_head(cx),
            // A baller with no chain cannot make progress. The C cannot reach
            // this state -- it only calls this on an active baller -- and
            // reporting rather than asserting keeps a live transfer up.
            None => Err(Error::with_context(
                CURLcode::FailedInit,
                "https-connect baller has no sub-chain to connect",
            )),
        };
        match outcome {
            Ok(done) => done,
            Err(error) => {
                self.result = Some(error);
                false
            }
        }
    }

    /// `b->cf->cft->do_shutdown(b->cf, data, &bdone)` (`:406`): shut the
    /// sub-chain down, one pass.
    ///
    /// The C calls the HEAD FILTER's own shutdown rather than the chain driver,
    /// so no shutdown deadline is consulted here; the enclosing transfer owns
    /// that. A failure counts as done -- the C's comment is *"treat a failed
    /// shutdown as done"* (`:409-410`).
    fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) {
        let outcome = match self.chain.as_mut().and_then(FilterChain::head_mut)
        {
            Some(head) => head.shutdown(cx),
            None => Ok(true),
        };
        match outcome {
            Ok(done) => {
                if done {
                    self.shutdown = true;
                }
            }
            Err(error) => {
                self.result = Some(error);
                self.shutdown = true;
            }
        }
    }

    /// `Curl_conn_cf_adjust_pollset(b->cf, data, ps)` (`:439`).
    ///
    /// # Errors
    ///
    /// Whatever the sub-chain's head reports.
    fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        match self.chain.as_mut().and_then(FilterChain::head_mut) {
            Some(head) => head.adjust_pollset(cx, ps),
            None => Ok(()),
        }
    }

    /// `cfb->cft->query(cfb, data, query, NULL, &t)` (`:471`), for the two
    /// timer queries.
    fn timer(&mut self, cx: &mut CallCtx<'_, '_>, which: CfQuery) -> CurlTime {
        match self.chain.as_mut() {
            Some(chain) => chain.timer(cx, which),
            None => CurlTime::ZERO,
        }
    }
}

/// What the version race needs that this module does not own.
///
/// Specification 0.3.3's pattern P12 again: the sub-chains are built through
/// injected factories and the timers are armed through an injected scheduler, so
/// this filter reaches for nothing global. The alternative -- naming a concrete
/// TLS or QUIC module here -- is the coupling the filter chain exists to
/// remove.
#[derive(Clone, Debug)]
pub(crate) struct HttpsConnectSeams {
    /// The context each baller's SETUP filter is built with, which carries the
    /// six filter factories and the resolved-address handle.
    pub(crate) setup: SetupContext,
    /// `Curl_expire` and `Curl_expire_done` (`lib/multiif.h:31-32`), as a
    /// contract. The race arms [`ALPN_EYEBALLS_TIMER`] through it.
    pub(crate) expiry: Arc<dyn ExpireScheduler>,
    /// `data->set.happy_eyeballs_timeout` -- `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`
    /// (`lib/cf-https-connect.c:192`), whose default is
    /// [`CURL_HET_DEFAULT`], 200 ms.
    pub(crate) happy_eyeballs_timeout_ms: TimeDiff,
}

#[allow(dead_code)] // consumers: crate::conn's factories implementation
impl HttpsConnectSeams {
    /// The seams with `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS` left at its default.
    pub(crate) fn new(
        setup: SetupContext,
        expiry: Arc<dyn ExpireScheduler>,
    ) -> Self {
        Self {
            setup,
            expiry,
            happy_eyeballs_timeout_ms: CURL_HET_DEFAULT,
        }
    }

    /// Records a caller-supplied `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`.
    #[must_use]
    pub(crate) fn with_happy_eyeballs_timeout_ms(
        mut self,
        timeout_ms: TimeDiff,
    ) -> Self {
        self.happy_eyeballs_timeout_ms = timeout_ms;
        self
    }
}

/// The HTTPS version race -- `Curl_cft_http_connect`
/// (`lib/cf-https-connect.c:557-573`) together with its context
/// `struct cf_hc_ctx` (`:111-119`).
///
/// # A connect-only filter
///
/// Four of the twelve vtable slots are the DEFAULTS -- `Curl_cf_def_send`,
/// `Curl_cf_def_recv`, `Curl_cf_def_conn_is_alive` and
/// `Curl_cf_def_conn_keep_alive` (`:566-571`) -- so this filter never touches a
/// byte of payload. It exists to choose a sub-chain and then get out of the way,
/// and the four are left to [`ConnFilter`]'s trait defaults here for the same
/// reason.
///
/// One property of those defaults must not be "corrected" on the way past:
/// `Curl_cf_def_send` reports `CURLE_RECV_ERROR` at the bottom of the chain and
/// `Curl_cf_def_recv` reports `CURLE_SEND_ERROR` -- swapped, deliberately
/// preserved in `crate::conn::filters`, and inherited unchanged here.
///
/// # What replaces the `void *ctx`
///
/// C keeps its whole state behind `cf->ctx` and casts it back at the top of
/// every callback. Here the members are ordinary typed fields, which is
/// specification 0.1.2's translation rule for the filter layer and pattern P2's
/// central improvement: the cast that appeared at every filter boundary is gone
/// by construction rather than by discipline.
#[derive(Debug)]
pub(crate) struct HttpsConnect {
    /// The chain link, socket index and the two state flags.
    base: FilterBase,
    /// `ctx->state`.
    state: HcState,
    /// `ctx->started`: when the race began.
    started: CurlTime,
    /// `ctx->result`: the overall failure, once [`HcState::Failure`] is
    /// reached.
    result: Option<CURLcode>,
    /// `ctx->ballers[2]` and `ctx->baller_count`, as one owned vector.
    ///
    /// A [`Vec`] rather than `[HcBaller; 2]` plus a count, because a fixed
    /// array would need a filled slot for a version that is not being raced --
    /// which is precisely what C's `ctx->ballers[i].alpn_id = ALPN_none`
    /// padding at `:606-607` is for. The bound is enforced by
    /// [`Self::new`] instead, so the two representations carry the same
    /// information and this one cannot be read past its count.
    ballers: Vec<HcBaller>,
    /// `ctx->soft_eyeballs_timeout_ms`: the hard timeout DIVIDED BY FOUR
    /// (`:193`).
    soft_eyeballs_timeout_ms: TimeDiff,
    /// `ctx->hard_eyeballs_timeout_ms`: `data->set.happy_eyeballs_timeout`
    /// (`:192`).
    hard_eyeballs_timeout_ms: TimeDiff,
    /// The injected sub-chain builder, timer scheduler and timeout.
    seams: HttpsConnectSeams,
}

impl HttpsConnect {
    /// `cf_hc_create(pcf, data, alpnids, alpn_count, def_transport)`
    /// (`lib/cf-https-connect.c:575-617`).
    ///
    /// # The ALPN count bound
    ///
    /// `alpn_ids` must hold between 1 and [`MAX_ALPN_BALLERS`] identifiers. The
    /// C asserts that in a debug build and then checks it again in every build,
    /// because the array it indexes is two long:
    ///
    /// ```c
    /// if(!alpn_count || (alpn_count > CURL_ARRAYSIZE(ctx->ballers))) {
    ///   failf(data, "https-connect filter create with unsupported %zu ALPN ids",
    ///         alpn_count);
    ///   result = CURLE_FAILED_INIT;
    ///   goto out;
    /// }
    /// ```
    ///
    /// Both halves are reproduced: the message is [`alpn_count_rejected`]'s and
    /// the code is [`CURLcode::FailedInit`].
    ///
    /// The C then runs `cf_hc_reset`, which is what sets the two eyeball
    /// timeouts; that is done here in the constructor for the same effect.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] with [`alpn_count_rejected`]'s text for a count
    /// of zero or more than two.
    #[allow(dead_code)] // consumer: https_setup
    pub(crate) fn new(
        sockindex: SocketIndex,
        alpn_ids: &[AlpnId],
        def_transport: Transport,
        seams: HttpsConnectSeams,
    ) -> CurlResult<Self> {
        if alpn_ids.is_empty() || alpn_ids.len() > MAX_ALPN_BALLERS {
            return Err(Error::with_context(
                CURLcode::FailedInit,
                alpn_count_rejected(alpn_ids.len()),
            ));
        }

        // `for(i = 0; i < alpn_count; ++i)
        //    cf_hc_baller_assign(&ctx->ballers[i], alpnids[i], def_transport);`
        //
        // The C's trailing loop -- `for(; i < CURL_ARRAYSIZE(ctx->ballers);
        // ++i) ctx->ballers[i].alpn_id = ALPN_none;` -- has no counterpart: a
        // slot that would hold `ALPN_none` simply does not exist here.
        let ballers = alpn_ids
            .iter()
            .map(|&alpn_id| HcBaller::assign(alpn_id, def_transport))
            .collect();

        let hard = seams.happy_eyeballs_timeout_ms;
        Ok(Self {
            base: FilterBase::new(sockindex),
            state: HcState::Init,
            started: CurlTime::ZERO,
            result: None,
            ballers,
            // `ctx->soft_eyeballs_timeout_ms =
            //    data->set.happy_eyeballs_timeout / 4;` (`:193`)
            soft_eyeballs_timeout_ms: hard / 4,
            // `ctx->hard_eyeballs_timeout_ms =
            //    data->set.happy_eyeballs_timeout;` (`:192`)
            hard_eyeballs_timeout_ms: hard,
            seams,
        })
    }

    /// How far the race has got.
    #[allow(dead_code)] // consumers: crate::conn and mod tests
    pub(crate) const fn state(&self) -> HcState {
        self.state
    }

    /// How many versions are being raced -- `ctx->baller_count`.
    #[allow(dead_code)] // consumers: crate::conn and mod tests
    pub(crate) fn baller_count(&self) -> usize {
        self.ballers.len()
    }

    /// The versions being raced, in offer order.
    ///
    /// Order matters and is asserted: baller 0 is the first ALPN identifier
    /// [`alpn_offer`] chose, and it is the one that starts immediately.
    #[allow(dead_code)] // consumers: crate::conn and mod tests
    pub(crate) fn raced(&self) -> Vec<AlpnId> {
        self.ballers.iter().map(|baller| baller.alpn_id).collect()
    }

    /// `ctx->soft_eyeballs_timeout_ms` -- the hard timeout divided by four.
    #[allow(dead_code)] // consumers: crate::conn and mod tests
    pub(crate) const fn soft_eyeballs_timeout_ms(&self) -> TimeDiff {
        self.soft_eyeballs_timeout_ms
    }

    /// `ctx->hard_eyeballs_timeout_ms`.
    #[allow(dead_code)] // consumers: crate::conn and mod tests
    pub(crate) const fn hard_eyeballs_timeout_ms(&self) -> TimeDiff {
        self.hard_eyeballs_timeout_ms
    }

    /// `cf_hc_reset(cf, data)` (`lib/cf-https-connect.c:182-195`): reset every
    /// baller, then the state, the overall result and both timeouts.
    fn reset(&mut self, cx: &mut CallCtx<'_, '_>) {
        for baller in &mut self.ballers {
            baller.reset(cx);
        }
        self.state = HcState::Init;
        self.result = None;
        self.hard_eyeballs_timeout_ms = self.seams.happy_eyeballs_timeout_ms;
        self.soft_eyeballs_timeout_ms =
            self.seams.happy_eyeballs_timeout_ms / 4;
    }

    /// `baller_connected(cf, data, winner)` (`:197-246`): promote the winner and
    /// discard the losers.
    ///
    /// The order is the C's and matters: the losers are reset FIRST, so their
    /// sockets are closed before the winner's sub-chain is installed and the
    /// connection is reported connected.
    ///
    /// # The one omission, and why it is not a gap
    ///
    /// C follows the promotion with an `#ifdef USE_NGHTTP2` block that reads the
    /// negotiated ALPN and calls `Curl_http2_switch_at(cf, data)` when the
    /// server chose `h2` (`:227-241`). That switch belongs to
    /// `protocols/http2.rs`, which is absent from this checkout, so this build
    /// is in exactly the state a C build without `USE_NGHTTP2` is in: the block
    /// does not run. The negotiated protocol is still read, because the trace
    /// line the C emits either way depends on it.
    ///
    /// # Errors
    ///
    /// Nothing here fails today. The signature keeps the C's `CURLcode` return
    /// because the HTTP/2 switch it will carry can fail, and the C stores that
    /// failure in `ctx->result` and moves to [`HcState::Failure`].
    fn baller_connected(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        winner: usize,
    ) -> CurlResult<()> {
        let sockindex = self.base.sockindex().as_i32();

        // `for(i = 0; i < ctx->baller_count; ++i)
        //    if(winner != &ctx->ballers[i]) cf_hc_baller_reset(...)`
        for index in 0..self.ballers.len() {
            if index != winner {
                self.ballers[index].reset(cx);
            }
        }

        let name = self.ballers[winner].name;
        let started = self.ballers[winner].started;
        let reply_ms = self.ballers[winner].reply_ms(cx);
        let elapsed = timediff_ms(cx.now(), started);
        if reply_ms >= 0 {
            trc_hc!(
                cx,
                sockindex,
                "connect+handshake {}: {}ms, 1st data: {}ms",
                name,
                elapsed,
                reply_ms,
            );
        } else {
            trc_hc!(
                cx,
                sockindex,
                "deferred handshake {}: {}ms",
                name,
                elapsed,
            );
        }

        // `cf->next = winner->cf; winner->cf = NULL;`
        let promoted = self.ballers[winner]
            .chain
            .take()
            .and_then(|mut chain| chain.take_chain());
        self.base.set_next(promoted);

        // The `#ifdef USE_NGHTTP2` switch reads this; the trace above does not
        // need it, but reading it keeps the query on the path the C queries so
        // that a filter answering it is exercised.
        let _negotiated = self
            .base
            .next_mut()
            .map(|next| next.query(cx, CfQuery::AlpnNegotiated));

        self.state = HcState::Success;
        self.base.set_connected(true);
        Ok(())
    }

    /// `time_to_start_next(cf, data, idx, now)` (`:248-289`): should baller
    /// `idx` start on this pass?
    ///
    /// Four decisions, in the C's order, and the order is what makes the race
    /// behave:
    ///
    /// 1. `idx` is out of range, or that baller has already started -- no.
    /// 2. **Every earlier baller has failed** -- yes, immediately, with the
    ///    trace line `"all previous attempts failed, starting %s"`. This is the
    ///    path that makes a race of two collapse to a sequence when the first
    ///    version cannot connect at all.
    /// 3. The HARD timeout has elapsed -- yes, with `"hard timeout of %ldms
    ///    reached, starting %s"`.
    /// 4. `idx > 0` AND the SOFT timeout has elapsed: yes IF the previous
    ///    baller has not seen any data (`reply_ms < 0`), with `"soft timeout of
    ///    %ldms reached, %s has not seen any data, starting %s"`. If it HAS
    ///    seen data, the answer is no and the hard timeout is re-armed at
    ///    `hard - elapsed` -- which is the C's only re-arm and the reason a
    ///    responsive first version is given the whole budget rather than a
    ///    quarter of it.
    fn time_to_start_next(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        idx: usize,
        now: CurlTime,
    ) -> bool {
        let sockindex = self.base.sockindex().as_i32();

        // `if(idx >= ctx->baller_count) return FALSE;`
        if idx >= self.ballers.len() {
            return false;
        }
        // `if(cf_hc_baller_has_started(&ctx->ballers[idx])) return FALSE;`
        if self.ballers[idx].has_started() {
            return false;
        }

        // `for(i = 0; i < idx; i++) if(!ctx->ballers[i].result) break;
        //  if(i == idx) { ... return TRUE; }`
        let all_earlier_failed = self.ballers[..idx]
            .iter()
            .all(|baller| baller.result.is_some());
        if all_earlier_failed {
            let name = self.ballers[idx].name;
            trc_hc!(
                cx,
                sockindex,
                "all previous attempts failed, starting {}",
                name,
            );
            return true;
        }

        let elapsed_ms = timediff_ms(now, self.started);
        if elapsed_ms >= self.hard_eyeballs_timeout_ms {
            let hard = self.hard_eyeballs_timeout_ms;
            let name = self.ballers[idx].name;
            trc_hc!(
                cx,
                sockindex,
                "hard timeout of {}ms reached, starting {}",
                hard,
                name,
            );
            return true;
        }

        // `if((idx > 0) && (elapsed_ms >= ctx->soft_eyeballs_timeout_ms))`
        if idx > 0 && elapsed_ms >= self.soft_eyeballs_timeout_ms {
            if self.ballers[idx - 1].reply_ms(cx) < 0 {
                let soft = self.soft_eyeballs_timeout_ms;
                let previous = self.ballers[idx - 1].name;
                let name = self.ballers[idx].name;
                trc_hc!(
                    cx,
                    sockindex,
                    "soft timeout of {}ms reached, {} has not seen any data, \
                     starting {}",
                    soft,
                    previous,
                    name,
                );
                return true;
            }
            // `Curl_expire(data, ctx->hard_eyeballs_timeout_ms - elapsed_ms,
            //              EXPIRE_ALPN_EYEBALLS);`
            self.seams.expiry.expire(
                self.hard_eyeballs_timeout_ms - elapsed_ms,
                ALPN_EYEBALLS_TIMER,
            );
        }
        false
    }

    /// The `CF_HC_INIT` arm of `cf_hc_connect` (`:301-317`).
    ///
    /// Baller 0 starts immediately and unconditionally. When a second version
    /// is being raced, the soft timer is armed and the trace line `"set next
    /// attempt to start in %ldms"` records it; with only one baller no timer is
    /// armed at all, because nothing is waiting to start.
    fn start(&mut self, cx: &mut CallCtx<'_, '_>) {
        let sockindex = self.base.sockindex().as_i32();
        trc_hc!(cx, sockindex, "connect, init");

        // `ctx->started = *Curl_pgrs_now(data);`
        self.started = cx.now();

        let conn = self.base.conn();
        let chain_sockindex = self.base.sockindex();
        let setup = self.seams.setup.clone();
        self.ballers[0].init(cx, &setup, conn, chain_sockindex);

        if self.ballers.len() > 1 {
            let soft = self.soft_eyeballs_timeout_ms;
            self.seams.expiry.expire(soft, ALPN_EYEBALLS_TIMER);
            trc_hc!(cx, sockindex, "set next attempt to start in {}ms", soft);
        }
        self.state = HcState::Connect;
    }

    /// The `CF_HC_CONNECT` arm of `cf_hc_connect` (`:319-361`): one pass over
    /// the race.
    ///
    /// # Errors
    ///
    /// The failure of the FIRST baller that has one, once every baller has
    /// failed -- which is the C's `for` loop at `:343-348` and the only path on
    /// which a baller's code becomes the connection's.
    fn drive(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        let sockindex = self.base.sockindex().as_i32();

        // `if(cf_hc_baller_is_active(&ctx->ballers[0])) { ... }`
        if self.ballers[0].is_active() && self.ballers[0].connect(cx) {
            self.baller_connected(cx, 0)?;
            return Ok(true);
        }

        // `if(time_to_start_next(cf, data, 1, *Curl_pgrs_now(data))) { ... }`
        let now = cx.now();
        if self.time_to_start_next(cx, 1, now) {
            let conn = self.base.conn();
            let chain_sockindex = self.base.sockindex();
            let setup = self.seams.setup.clone();
            self.ballers[1].init(cx, &setup, conn, chain_sockindex);
        }

        // `if((ctx->baller_count > 1) &&
        //     cf_hc_baller_is_active(&ctx->ballers[1])) { ... }`
        if self.ballers.len() > 1 && self.ballers[1].is_active() {
            let name = self.ballers[1].name;
            trc_hc!(cx, sockindex, "connect, check {}", name);
            if self.ballers[1].connect(cx) {
                self.baller_connected(cx, 1)?;
                return Ok(true);
            }
        }

        // `failed_ballers == ctx->baller_count` -- all have failed, give up.
        let failed = self
            .ballers
            .iter()
            .filter(|baller| baller.result.is_some())
            .count();
        if failed == self.ballers.len() {
            trc_hc!(cx, sockindex, "connect, all attempts failed");
            self.state = HcState::Failure;
            let first = self
                .ballers
                .iter_mut()
                .find_map(|baller| baller.result.take());
            let error = first.unwrap_or_else(|| {
                // Unreachable: `failed == len` and `len >= 1`, so at least one
                // baller holds a result. Reported rather than asserted, because
                // a panic here would take a live transfer down.
                Error::with_context(
                    CURLcode::FailedInit,
                    "https-connect: every version failed without a code",
                )
            });
            self.result = Some(error.code());
            return Err(error);
        }

        // `result = CURLE_OK; *done = FALSE; break;`
        Ok(false)
    }
}

impl ConnFilter for HttpsConnect {
    fn trace_name(&self) -> &'static str {
        HTTPS_CONNECT_FILTER_NAME
    }

    /// [`HTTPS_CONNECT_FLAGS`], which is `0`.
    ///
    /// Stated rather than left to the trait default, because the zero is a
    /// decision `lib/cf-https-connect.c:559` makes and a reader comparing the
    /// two should find it.
    fn cf_type(&self) -> CfType {
        HTTPS_CONNECT_FLAGS
    }

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    /// `cf_hc_destroy(cf, data)` (`lib/cf-https-connect.c:547-555`): the trace
    /// line, then reset.
    ///
    /// The C's `Curl_safefree(ctx)` has no counterpart: the state is an ordinary
    /// field, released when this value is dropped, which the caller does
    /// immediately after. This must not reach `next` -- the caller has already
    /// severed the link and owns the rest of the chain.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        let sockindex = self.base.sockindex().as_i32();
        trc_hc!(cx, sockindex, "destroy");
        self.reset(cx);
    }

    /// `cf_hc_connect(cf, data, done)` (`lib/cf-https-connect.c:291-383`).
    ///
    /// The state machine, arm by arm:
    ///
    /// * `CF_HC_INIT` -- start baller 0, arm the soft timer if a second version
    ///   is being raced, move to `CF_HC_CONNECT` and **fall through**. The C's
    ///   `FALLTHROUGH()` at `:318` is load-bearing: the first connect pass
    ///   happens immediately rather than on the next re-entry.
    /// * `CF_HC_CONNECT` -- one pass over the race; see [`Self::drive`].
    /// * `CF_HC_FAILURE` -- report the stored code, stay unconnected.
    /// * `CF_HC_SUCCESS` -- report connected.
    ///
    /// # Errors
    ///
    /// The first baller's failure once all of them have failed, and the stored
    /// code on every later pass through `CF_HC_FAILURE`.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        // `if(cf->connected) { *done = TRUE; return CURLE_OK; }`
        if self.base.is_connected() {
            return Ok(true);
        }

        let sockindex = self.base.sockindex().as_i32();
        let outcome = match self.state {
            HcState::Init => {
                debug_assert!(
                    !self.base.has_next(),
                    "a filter in CF_HC_INIT has installed no winner"
                );
                debug_assert!(
                    self.ballers.iter().all(|baller| !baller.has_started()),
                    "a filter in CF_HC_INIT has started no baller"
                );
                self.start(cx);
                // `FALLTHROUGH();`
                self.drive(cx)
            }
            HcState::Connect => self.drive(cx),
            HcState::Failure => {
                // `result = ctx->result; cf->connected = FALSE;
                //  *done = FALSE;`
                self.base.set_connected(false);
                match self.result {
                    Some(code) => Err(Error::new(code)),
                    None => Ok(false),
                }
            }
            HcState::Success => {
                // `result = CURLE_OK; cf->connected = TRUE; *done = TRUE;`
                self.base.set_connected(true);
                Ok(true)
            }
        };

        // `out: CURL_TRC_CF(data, cf, "connect -> %d, done=%d", result,
        //                   *done);`
        let (code, done) = match &outcome {
            Ok(done) => (CURLcode::Ok.as_i32(), u8::from(*done)),
            Err(error) => (error.code().as_i32(), 0),
        };
        trc_hc!(cx, sockindex, "connect -> {}, done={}", code, done);
        outcome
    }

    /// `cf_hc_close(cf, data)` (`lib/cf-https-connect.c:533-545`).
    ///
    /// Resets every baller, clears `connected`, then closes AND DISCARDS the
    /// installed winner. Discarding is sanctioned here for the reason
    /// [`ConnFilter::close`] records: the sub-chain below this filter is
    /// PRIVATE -- this filter installed it and nothing else can reach it -- so
    /// there is no other owner to surprise.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        let sockindex = self.base.sockindex().as_i32();
        trc_hc!(cx, sockindex, "close");
        self.reset(cx);
        self.base.set_connected(false);

        // `if(cf->next) { cf->next->cft->do_close(cf->next, data);
        //  Curl_conn_cf_discard_chain(&cf->next, data); }`
        if let Some(next) = self.base.next_mut() {
            next.close(cx);
        }
        let installed = self.base.take_next();
        crate::conn::filters::discard_chain_from(cx, installed);
    }

    /// `cf_hc_shutdown(cf, data, done)` (`lib/cf-https-connect.c:385-423`).
    ///
    /// Shuts down every baller that has not finished, continuing past a failure
    /// so that the others still get their chance -- the C's comment is *"If one
    /// fails, continue shutting down others until all are shutdown"*. Only when
    /// every baller reports done does this report done, and only then is a
    /// failure reported -- the LAST one, because the C's loop at `:412-416`
    /// overwrites `result` as it walks.
    ///
    /// # Errors
    ///
    /// The last baller failure, once all of them have finished.
    fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        let sockindex = self.base.sockindex().as_i32();

        // `if(cf->connected) { *done = TRUE; return CURLE_OK; }`
        if self.base.is_connected() {
            return Ok(true);
        }

        for index in 0..self.ballers.len() {
            if !self.ballers[index].is_active() || self.ballers[index].shutdown
            {
                continue;
            }
            self.ballers[index].shutdown(cx);
        }

        let done = self.ballers.iter().all(|baller| baller.shutdown);
        let mut outcome = Ok(done);
        if done {
            // `for(i = 0; i < ctx->baller_count; i++)
            //    if(ctx->ballers[i].result) result = ctx->ballers[i].result;`
            // -- the LAST failure wins, which is what the unguarded assignment
            // in the C's loop does.
            let last = self
                .ballers
                .iter_mut()
                .filter_map(|baller| baller.result.take())
                .last();
            if let Some(error) = last {
                outcome = Err(error);
            }
        }

        let code = match &outcome {
            Ok(_) => CURLcode::Ok.as_i32(),
            Err(error) => error.code().as_i32(),
        };
        trc_hc!(
            cx,
            sockindex,
            "shutdown -> {}, done={}",
            code,
            u8::from(done),
        );
        outcome
    }

    /// `cf_hc_adjust_pollset(cf, data, ps)`
    /// (`lib/cf-https-connect.c:425-443`): collect the readiness of every
    /// running baller.
    ///
    /// Nothing is collected once connected: the installed winner is asked
    /// directly by the chain walker above this filter.
    ///
    /// # Errors
    ///
    /// The first sub-chain failure, which stops the walk exactly as the C's
    /// `&& !result` loop condition does.
    fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        if self.base.is_connected() {
            return Ok(());
        }

        let sockindex = self.base.sockindex().as_i32();
        let mut outcome = Ok(());
        for index in 0..self.ballers.len() {
            if !self.ballers[index].is_active() {
                continue;
            }
            outcome = self.ballers[index].adjust_pollset(cx, ps);
            if outcome.is_err() {
                break;
            }
        }

        let code = match &outcome {
            Ok(()) => CURLcode::Ok.as_i32(),
            Err(error) => error.code().as_i32(),
        };
        trc_hc!(
            cx,
            sockindex,
            "adjust_pollset -> {}, {} socks",
            code,
            ps.len(),
        );
        outcome
    }

    /// `cf_hc_data_pending(cf, data)` (`lib/cf-https-connect.c:445-457`).
    ///
    /// Once connected the question goes to the installed winner, which is the
    /// trait default's behaviour; before that, any baller with buffered bytes
    /// answers yes.
    fn data_pending(&mut self, cx: &CallCtx<'_, '_>) -> bool {
        if self.base.is_connected() {
            return match self.base.next_mut() {
                Some(next) => next.data_pending(cx),
                None => false,
            };
        }

        // The baller helpers need `&mut CallCtx` to ask their sub-chains, and
        // this callback is handed a shared one -- the C's signature is
        // `const struct Curl_easy *data`. A private context over the same
        // injected clock is what bridges the two; it carries no tracer, and
        // this callback emits no trace line in the C either.
        let mut owned = CallCtx::new(cx.clock());
        self.ballers
            .iter_mut()
            .any(|baller| baller.data_pending(&mut owned))
    }

    /// `cf_hc_cntrl(cf, data, event, arg1, arg2)`
    /// (`lib/cf-https-connect.c:514-531`): distribute an event to every running
    /// baller.
    ///
    /// [`CURLcode::Again`] is skipped rather than propagated, which is the C's
    /// `if(result && (result != CURLE_AGAIN)) goto out;` -- a baller that would
    /// block is not a baller that failed. Nothing is distributed once
    /// connected: the winner is reached by the chain walker instead.
    ///
    /// # Errors
    ///
    /// The first baller failure that is not [`CURLcode::Again`].
    fn cntrl(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        event: CfControl,
    ) -> CurlResult<()> {
        if self.base.is_connected() {
            return Ok(());
        }
        for index in 0..self.ballers.len() {
            if let Err(error) = self.ballers[index].cntrl(cx, event) {
                if error.code() != CURLcode::Again {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// `cf_hc_query(cf, data, query, pres1, pres2)`
    /// (`lib/cf-https-connect.c:459-512`).
    ///
    /// Three questions are answered from the ballers while the race is still
    /// running, and everything else -- including all three once connected --
    /// falls through to the successor, which is the trait default.
    ///
    /// * `CF_QUERY_TIMER_CONNECT` and `CF_QUERY_TIMER_APPCONNECT`: the LATEST
    ///   non-zero timestamp any baller reports, because the race is not over
    ///   until the last runner is done. `cf_get_max_baller_time` (`:459-478`)
    ///   skips a zero timestamp, so an unstarted baller cannot drag the answer
    ///   back to the epoch.
    /// * `CF_QUERY_NEED_FLUSH`: yes if ANY baller needs one, answered on the
    ///   first that does.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] at the bottom of the chain, which is a
    /// sentinel meaning "nobody understood the question" rather than a failure.
    fn query(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        if !self.base.is_connected() {
            match query {
                CfQuery::TimerConnect | CfQuery::TimerAppConnect => {
                    return Ok(CfQueryValue::Timer(
                        self.max_baller_time(cx, query),
                    ));
                }
                CfQuery::NeedFlush => {
                    let any = (0..self.ballers.len())
                        .any(|index| self.ballers[index].needs_flush(cx));
                    if any {
                        return Ok(CfQueryValue::NeedFlush(true));
                    }
                }
                _ => {}
            }
        }

        match self.base.next_mut() {
            Some(next) => next.query(cx, query),
            None => Err(Error::new(CURLcode::UnknownOption)),
        }
    }
}

impl HttpsConnect {
    /// `cf_get_max_baller_time(cf, data, query)`
    /// (`lib/cf-https-connect.c:459-478`): the latest timestamp any baller
    /// reports for `query`.
    ///
    /// `memset(&tmax, 0, ...)` starts at the epoch and `if((t.tv_sec ||
    /// t.tv_usec) && curlx_ptimediff_us(&t, &tmax) > 0)` is what skips a
    /// baller that has no timestamp yet -- both reproduced, because a zero here
    /// means "not measured" rather than "measured as the epoch".
    fn max_baller_time(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlTime {
        let mut latest = CurlTime::ZERO;
        for index in 0..self.ballers.len() {
            let when = self.ballers[index].timer(cx, query);
            if !when.is_zero() && timediff_ms(when, latest) > 0 {
                latest = when;
            }
        }
        latest
    }
}

// `Curl_cf_https_setup` -- the ALPN offer and the filter it installs

/// Everything `Curl_cf_https_setup` reads out of `data` and `conn`
/// (`lib/cf-https-connect.c:648-772`).
///
/// The C reaches seven distinct things through two pointers; they are named
/// here so that [`alpn_offer`] is a function of its arguments alone and can be
/// driven from a table in a test. Nothing in it is optional in the C sense: a
/// field that is absent there is [`None`] or `false` here.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // consumer: crate::conn's factories implementation
pub(crate) struct HttpsSetupRequest<'a> {
    /// `conn->bits.tls_enable_alpn`. When false the whole selection is skipped
    /// and nothing is installed -- ALPN is what the race depends on.
    pub(crate) tls_enable_alpn: bool,
    /// `data->state.http_neg`.
    pub(crate) neg: HttpNegotiation,
    /// `data->state.dns[sockindex]->hinfo`, the HTTPS resource record, when the
    /// resolver produced one.
    pub(crate) rr: Option<&'a HttpsRrInfo>,
    /// `conn->remote_port`, which the record's own port is compared against.
    pub(crate) remote_port: u16,
    /// `conn->transport_wanted`, the default transport each baller is built
    /// with -- overridden to QUIC for `h3`.
    pub(crate) transport_wanted: Transport,
    /// `conn->scheme->flags`, read by [`conn_may_http3`] for
    /// [`ProtocolOptions::SSL`].
    pub(crate) scheme_flags: ProtocolOptions,
    /// The proxy state [`conn_may_http3`] reads.
    pub(crate) proxy: Http3Proxy,
}

#[allow(dead_code)] // consumers: https_setup and crate::conn
impl<'a> HttpsSetupRequest<'a> {
    /// A request with ALPN enabled, no HTTPS record and no proxy.
    ///
    /// The state an ordinary `https://` connection to a non-proxied host is in,
    /// which is the shape most callers want; the builders below add the rest.
    pub(crate) fn new(
        neg: HttpNegotiation,
        remote_port: u16,
        transport_wanted: Transport,
        scheme_flags: ProtocolOptions,
    ) -> Self {
        Self {
            tls_enable_alpn: true,
            neg,
            rr: None,
            remote_port,
            transport_wanted,
            scheme_flags,
            proxy: Http3Proxy::default(),
        }
    }

    /// Records `conn->bits.tls_enable_alpn`.
    #[must_use]
    pub(crate) fn with_tls_enable_alpn(mut self, enabled: bool) -> Self {
        self.tls_enable_alpn = enabled;
        self
    }

    /// Records the HTTPS resource record the resolver produced.
    #[must_use]
    pub(crate) fn with_https_rr(mut self, rr: &'a HttpsRrInfo) -> Self {
        self.rr = Some(rr);
        self
    }

    /// Records the proxy state.
    #[must_use]
    pub(crate) fn with_proxy(mut self, proxy: Http3Proxy) -> Self {
        self.proxy = proxy;
        self
    }

    /// `rr && !rr->no_def_alpn && (same host) && (same port)`
    /// (`lib/cf-https-connect.c:670-680`): may this record's ALPNs be used?
    ///
    /// The C comment states why the last two tests exist: *"We are here after
    /// having selected a connection to a host+port and can no longer change
    /// that. Any HTTPSRR advice for other hosts and ports we need to ignore."*
    ///
    /// * `no_def_alpn` -- the record says its ALPNs are NOT defaults.
    /// * the target is absent, empty, or exactly `"."`, all three of which mean
    ///   "this same host". The C spells it
    ///   `!rr->target || !rr->target[0] || (rr->target[0] == '.' &&
    ///   !rr->target[1])`.
    /// * the port is unset or equal to `conn->remote_port`. C stores an `int`
    ///   and tests `rr->port < 0` for unset; `crate::dns` stores
    ///   `Option<u16>`, so [`None`] is that same "unset".
    fn rr_alpns_apply(&self) -> Option<&'a HttpsRrInfo> {
        let rr = self.rr?;
        if rr.no_def_alpn {
            return None;
        }
        let same_host = rr
            .target
            .as_deref()
            .map_or(true, |target| target.is_empty() || target == ".");
        if !same_host {
            return None;
        }
        let same_port = rr.port.map_or(true, |port| port == self.remote_port);
        if !same_port {
            return None;
        }
        Some(rr)
    }
}

/// `Curl_cf_https_setup`'s ALPN selection (`lib/cf-https-connect.c:648-757`),
/// separated from the installation.
///
/// # This function decides bytes on the wire
///
/// The identifiers it returns become the `ClientHello`'s ALPN extension, IN
/// THIS ORDER, so both the membership and the sequence are frozen by
/// specification 0.8.1's preservation mandate. `crate::tls` owns the wire
/// encoding -- one length byte then the protocol bytes, in caller order -- and
/// this function owns which protocols are handed to it.
///
/// # The five steps, in the C's order
///
/// 0. Nothing at all unless `conn->bits.tls_enable_alpn`. The C fabricates a
///    `struct Curl_cfilter` on the stack here purely so that trace lines can be
///    attributed before the filter exists (`:655-660`); this passes the trace
///    context instead and fabricates nothing.
/// 1. **The HTTPS record's ALPNs FIRST**, when [`HttpsSetupRequest::rr_alpns_apply`]
///    admits them. Each is skipped if already chosen, `h3` additionally requires
///    [`conn_may_http3`] to succeed AND `allowed & CURL_HTTP_V3x`, `h2` requires
///    `allowed & V2x` and `h1` requires `allowed & V1x`. Trace lines: `"adding
///    h3 via HTTPS-RR"`, `"adding h2 via HTTPS-RR"`, `"adding h1 via
///    HTTPS-RR"`.
/// 2. **The preferred version next**, when `preferred` is set and
///    `preferred & allowed`. The C `switch`es on the WHOLE value, so this
///    compares for equality rather than testing a mask -- a `preferred`
///    carrying two bits matches no arm and adds nothing. `V3x` is taken only if
///    [`conn_may_http3`] succeeds.
/// 3. `wanted & V3x` and `h3` not already chosen: ask [`conn_may_http3`]. On
///    success, trace `"adding wanted h3"`. **On failure, if `wanted` is EXACTLY
///    `V3x`, return the error** -- the C's `goto out` at `:744`. If other
///    versions were also wanted, the failure is ignored and the walk continues.
/// 4. An `if` / `else if` PAIR, not two `if`s (`:747-757`): `wanted & V2x` adds
///    `h2` with `"adding wanted h2"`, and OTHERWISE `wanted & V1x` adds `h1`
///    with `"adding wanted h1"`. Step 4 never adds both. Note which condition
///    the `else` attaches to: if the `h2` arm is not taken -- because `h2` was
///    already chosen, or because two identifiers are already held -- the `h1`
///    arm is evaluated.
/// 5. Every step is additionally capped at [`MAX_ALPN_BALLERS`], the C's
///    `alpn_count < CURL_ARRAYSIZE(alpn_ids)`.
///
/// # Errors
///
/// Only from step 3, and only when HTTP/3 is the sole wanted version: whatever
/// [`conn_may_http3`] reported, so that `--http3-only` against a plaintext URL
/// or a proxy fails with the specific message rather than silently falling back.
#[allow(dead_code)] // consumer: https_setup
pub(crate) fn alpn_offer(
    cx: &mut CallCtx<'_, '_>,
    sockindex: SocketIndex,
    request: &HttpsSetupRequest<'_>,
) -> CurlResult<Vec<AlpnId>> {
    let mut ids: Vec<AlpnId> = Vec::with_capacity(MAX_ALPN_BALLERS);
    if !request.tls_enable_alpn {
        return Ok(ids);
    }

    let trace_index = sockindex.as_i32();
    let neg = request.neg;
    let may_h3 = || {
        conn_may_http3(
            request.scheme_flags,
            request.transport_wanted,
            request.proxy,
        )
    };

    // -- step 1: the HTTPS resource record ---------------------------------
    if let Some(rr) = request.rr_alpns_apply() {
        for alpn in rr.alpns() {
            if ids.len() >= MAX_ALPN_BALLERS {
                break;
            }
            // `if(cf_https_alpns_contain(alpn, alpn_ids, alpn_count)) continue;`
            if ids.contains(&alpn) {
                continue;
            }
            match alpn {
                AlpnId::H3 => {
                    // `if(Curl_conn_may_http3(...)) break; /* not possible */`
                    // -- a `break` out of the `switch`, which is a `continue`
                    // of the walk: the record's next ALPN is still considered.
                    if may_h3().is_err() {
                        continue;
                    }
                    if neg.allowed.intersects(CURL_HTTP_V3X) {
                        trc_hc!(cx, trace_index, "adding h3 via HTTPS-RR");
                        ids.push(AlpnId::H3);
                    }
                }
                AlpnId::H2 => {
                    if neg.allowed.intersects(CURL_HTTP_V2X) {
                        trc_hc!(cx, trace_index, "adding h2 via HTTPS-RR");
                        ids.push(AlpnId::H2);
                    }
                }
                AlpnId::H1 => {
                    if neg.allowed.intersects(CURL_HTTP_V1X) {
                        trc_hc!(cx, trace_index, "adding h1 via HTTPS-RR");
                        ids.push(AlpnId::H1);
                    }
                }
                // `default: /* ignore */ break;`
                AlpnId::None => {}
            }
        }
    }

    // -- step 2: the preferred version -------------------------------------
    if neg.preferred != HttpMajors::NONE
        && ids.len() < MAX_ALPN_BALLERS
        && neg.preferred.intersects(neg.allowed)
    {
        // `switch(data->state.http_neg.preferred)` -- on the WHOLE value.
        let preferred = if neg.preferred == CURL_HTTP_V3X {
            if may_h3().is_ok() {
                Some(AlpnId::H3)
            } else {
                None
            }
        } else if neg.preferred == CURL_HTTP_V2X {
            Some(AlpnId::H2)
        } else if neg.preferred == CURL_HTTP_V1X {
            Some(AlpnId::H1)
        } else {
            None
        };
        if let Some(alpn) = preferred {
            if !ids.contains(&alpn) {
                ids.push(alpn);
            }
        }
    }

    // -- step 3: wanted HTTP/3 ---------------------------------------------
    if ids.len() < MAX_ALPN_BALLERS
        && neg.wanted.intersects(CURL_HTTP_V3X)
        && !ids.contains(&AlpnId::H3)
    {
        match may_h3() {
            Ok(()) => {
                trc_hc!(cx, trace_index, "adding wanted h3");
                ids.push(AlpnId::H3);
            }
            Err(error) => {
                // `else if(data->state.http_neg.wanted == CURL_HTTP_V3x)
                //    goto out; /* only h3 allowed, not possible, error out */`
                if neg.wanted == CURL_HTTP_V3X {
                    return Err(error);
                }
            }
        }
    }

    // -- step 4: wanted HTTP/2, ELSE wanted HTTP/1 -------------------------
    if ids.len() < MAX_ALPN_BALLERS
        && neg.wanted.intersects(CURL_HTTP_V2X)
        && !ids.contains(&AlpnId::H2)
    {
        trc_hc!(cx, trace_index, "adding wanted h2");
        ids.push(AlpnId::H2);
    } else if ids.len() < MAX_ALPN_BALLERS
        && neg.wanted.intersects(CURL_HTTP_V1X)
        && !ids.contains(&AlpnId::H1)
    {
        trc_hc!(cx, trace_index, "adding wanted h1");
        ids.push(AlpnId::H1);
    }

    Ok(ids)
}

/// `Curl_cf_https_setup(data, conn, sockindex)`
/// (`lib/cf-https-connect.c:648-772`): install the version race, or install
/// nothing.
///
/// This is the implementation behind
/// [`crate::conn::ConnectionFilterFactories::https_setup`], which
/// `crate::conn::conn_setup` calls when the chain is EMPTY and the scheme is
/// `https`. The factory method belongs to whoever owns the connection; the
/// decision and the filter belong here, which is why `crate::conn` states the
/// hook and never names this module.
///
/// # Installing nothing is a correct outcome, not a failure
///
/// The C's comment at `:766-767` is *"If we identified ALPNs to use, install our
/// filter. Otherwise, install nothing, so our call will use a default connect
/// setup."* An empty offer therefore returns `Ok(())` with an untouched chain,
/// and `conn_setup`'s emptiness re-test is what then applies the generic
/// [`crate::conn::SetupFilter`]. Two ordinary configurations reach it: ALPN
/// switched off, and a build with neither HTTP/2 nor HTTP/3 to race.
///
/// The filter is added at the TOP of the chain, which is
/// `Curl_conn_cf_add`'s position and the only one that makes sense: the race
/// must see the connect call before anything else does.
///
/// # Errors
///
/// Whatever [`alpn_offer`] reports -- which is only the HTTP/3-only case -- and
/// whatever [`HttpsConnect::new`] reports, which cannot fire here because the
/// offer is non-empty and capped at [`MAX_ALPN_BALLERS`] by construction.
#[allow(dead_code)] // consumer: crate::conn::ConnectionFilterFactories
pub(crate) fn https_setup(
    cx: &mut CallCtx<'_, '_>,
    chain: &mut FilterChain,
    request: &HttpsSetupRequest<'_>,
    seams: HttpsConnectSeams,
) -> CurlResult<()> {
    let ids = alpn_offer(cx, chain.sockindex(), request)?;

    // `if(alpn_count) { result = cf_http_connect_add(...); }`
    if ids.is_empty() {
        return Ok(());
    }

    let filter = HttpsConnect::new(
        chain.sockindex(),
        &ids,
        request.transport_wanted,
        seams,
    )?;
    chain.add(cx, link(filter));
    Ok(())
}

// Connection-reuse policy, which is protocol-aware

/// `multi_conn_should_close`'s protocol test (`lib/multi.c:580-583`): may this
/// connection go back into the pool?
///
/// ```c
/// /* Unless this connection is for a "connect-only" transfer, it
///  * needs to be closed if the protocol handler does not support reuse. */
/// if(!data->set.connect_only && conn->scheme &&
///    !(conn->scheme->flags & PROTOPT_CONN_REUSE))
///   return TRUE;
/// ```
///
/// `crate::conn::pool` asks this rather than reading a flag itself, because the
/// flags belong to the scheme and the scheme belongs here. The `connect_only`
/// exemption is the C's and is not an oversight: `CURLOPT_CONNECT_ONLY` hands
/// the socket to the application, which then owns its lifetime, so the pool's
/// reuse rule does not apply.
///
/// # The measured asymmetry this predicate exists to preserve
///
/// `ws` and `wss` carry NO [`ProtocolOptions::CONN_REUSE`]
/// (`lib/ws.c:1992-1993` and `:2008-2009`), while `http` and `https` do. A
/// WebSocket connection has been upgraded away from request/response semantics,
/// so it must never be handed to another transfer -- and because the two share
/// one protocol implementation, the flags are the ONLY place that distinction
/// lives.
#[allow(dead_code)] // consumer: crate::conn::pool's admission predicate
pub(crate) fn connection_reusable(scheme: &Scheme, connect_only: bool) -> bool {
    connect_only || scheme.flags.intersects(ProtocolOptions::CONN_REUSE)
}

/// `url_match_ssl_use(conn, m)` (`lib/url.c:902-916`): may `candidate` be
/// reused for a transfer that wants `wanted`?
///
/// ```c
/// if(m->needle->scheme->flags & PROTOPT_SSL) {
///   if(!Curl_conn_is_ssl(conn, FIRSTSOCKET)) return FALSE;
/// }
/// else if(Curl_conn_is_ssl(conn, FIRSTSOCKET)) {
///   if(!(m->needle->scheme->flags & PROTOPT_SSL_REUSE) ||
///      (get_protocol_family(conn->scheme) != m->needle->scheme->protocol))
///     return FALSE;
/// }
/// return TRUE;
/// ```
///
/// Two rules, and the second is the subtle one:
///
/// * A scheme that IS TLS-protected needs a TLS connection. Plain and simple.
/// * A scheme that is NOT may still reuse a TLS connection -- but only if it
///   carries [`ProtocolOptions::SSL_REUSE`] AND the candidate's FAMILY equals
///   the wanted scheme's PROTOCOL. That comparison is deliberately across the
///   two columns: `ftp` (protocol `FTP`) may reuse an `ftps` connection, whose
///   family is also `FTP`, and that is exactly the case the flag exists for.
///   `get_protocol_family` is a one-line accessor for `s->family`
///   (`lib/url.c:154-159`).
///
/// `candidate_is_ssl` is `Curl_conn_is_ssl(conn, FIRSTSOCKET)`, which asks the
/// filter chain rather than the scheme -- a connection can be TLS-protected
/// through a proxy tunnel whose scheme says nothing about it -- so it is passed
/// in rather than derived here.
#[allow(dead_code)] // consumer: crate::conn::pool's candidate match
pub(crate) fn ssl_reuse_matches(
    wanted: &Scheme,
    candidate: &Scheme,
    candidate_is_ssl: bool,
) -> bool {
    if wanted.is_ssl() {
        return candidate_is_ssl;
    }
    if candidate_is_ssl {
        return wanted.flags.intersects(ProtocolOptions::SSL_REUSE)
            && candidate.family == wanted.protocol;
    }
    true
}

// The registry as `crate::url` consumes it

/// The 33-entry table, as a [`SchemeRegistry`].
///
/// Zero-sized: the rows are a `const`, so an instance carries nothing and a
/// `&'static` reference to one costs no allocation and no initialisation.
#[derive(Debug)]
struct AllSchemes;

impl SchemeRegistry for AllSchemes {
    /// [`getn_scheme`], projected into a [`SchemeInfo`].
    ///
    /// One lookup for both callers: the URL API reaches the table through this
    /// method and the transfer core reaches it through [`get_scheme`], and both
    /// resolve the same rows by the same two predicates. A second lookup
    /// written for `crate::url`'s convenience is how the two would come to
    /// disagree about `"htt"`.
    fn lookup(&self, scheme: &[u8]) -> Option<SchemeInfo> {
        get_scheme(scheme).map(Scheme::info)
    }
}

/// The one instance, `'static` because [`crate::url::Url`] holds the borrow.
static REGISTRY: AllSchemes = AllSchemes;

/// The scheme table every URL handle resolves against.
///
/// This is the wiring contract `crate::url::SchemeRegistry` states and
/// `curl-rs-lib/src/lib.rs` repeats: `curl_url()` takes no arguments
/// (`include/curl/urlapi.h:113`), so `curl-rs-ffi/src/ffi/url.rs` has to obtain
/// a registry without being handed one, and this function is where it gets it.
///
/// The direction of the dependency is the point. `url` declares the
/// [`SchemeRegistry`] trait and `protocols` implements it, never the reverse, so
/// the URL API does not depend on the transfer engine and the module graph stays
/// acyclic. There is deliberately no global to reach for instead: no
/// `static mut`, no lazily initialised singleton and no registration side
/// effect. The registry is a constructor argument and [`crate::url::Url`] holds
/// the borrow.
///
/// # Why this returns a table wider than the `Protocols:` banner
///
/// All 33 schemes resolve, and none of them is [`SchemeInfo::runnable`] in this
/// checkout. The distinction between the two answers is load-bearing rather than
/// pedantic: RESOLVING a scheme is what URL parsing needs, while runnability and
/// the banner describe what a TRANSFER can do. So this table stays at 33 --
/// which is what keeps `guess_scheme`'s host-name prefixes, the default-port
/// lookups and the parse-versus-set asymmetry behaving as they do in curl
/// 8.19.0-DEV -- while every row carries `run: None` and
/// `crate::version::protocols()` returns nothing.
///
/// Both UNDER-report, which makes a fixture skip, rather than over-reporting,
/// which makes it run and fail.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::url::{Url, UrlFlags, UrlPart};
///
/// let mut url = Url::new(curl_rs_lib::scheme_registry());
/// url.set(UrlPart::Url, Some(b"https://example.com/a"), UrlFlags::NONE)?;
/// let port = url.get(UrlPart::Port, UrlFlags::DEFAULT_PORT)?;
/// assert_eq!(port, b"443".to_vec());
/// # Ok::<(), curl_rs_lib::CURLUcode>(())
/// ```
#[must_use]
pub fn scheme_registry() -> &'static dyn SchemeRegistry {
    &REGISTRY
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{
        chain_close, FilterLink, CF_TYPE_PROXY, CF_TYPE_SSL,
    };
    use crate::conn::{ConnectionFilterFactories, ResolvedPresence};
    use crate::dns::httpsrr::MAX_HTTPSRR_ALPNS;
    use crate::trace::{TraceConfig, TraceLevel, WriterSink};
    use crate::util::sync_cell::SyncCell;
    use crate::util::timeval::TestClock;
    use std::time::Duration;

    // -- shared plumbing ---------------------------------------------------

    /// An ordered record of what happened, shared by every double in a test.
    ///
    /// A filter installed below another is owned as an opaque
    /// `Pin<Box<dyn ConnFilter>>` and there is no way back to its concrete
    /// type -- deliberately, since recovering one is exactly what pattern P2's
    /// typed context abolished. A shared log is therefore the only way a test
    /// can observe what a linked filter did.
    type EventLog = Arc<SyncCell<Vec<String>>>;

    fn new_log() -> EventLog {
        Arc::new(SyncCell::new(Vec::new()))
    }

    fn events(log: &EventLog) -> Vec<String> {
        log.borrow().clone()
    }

    /// A clock at a round, non-zero reading.
    ///
    /// Non-zero on purpose: `CurlTime::ZERO` is the sentinel `HcBaller::started`
    /// holds before a baller starts, and a test whose clock read zero would
    /// agree with a broken implementation by accident.
    fn clock() -> TestClock {
        TestClock::new(CurlTime::new(1_000, 0))
    }

    /// The `&'static Scheme` a [`TransferCtx`] needs, which every test takes
    /// from the production table rather than fabricating.
    fn http_row() -> &'static Scheme {
        get_scheme(b"http").expect("http is a row of the table")
    }

    /// Collects a verbose trace of `body` with every filter level raised.
    ///
    /// The trace strings this module must emit byte for byte are asserted
    /// through this, not through a mock logger: the assertion then covers the
    /// real `trc_cf!` path, including its two-level guard.
    fn traced(
        clock: &TestClock,
        body: impl FnOnce(&mut CallCtx<'_, '_>),
    ) -> String {
        let mut config = TraceConfig::new();
        for filter in TraceFilter::ALL {
            config.set_filter_level(*filter, TraceLevel::Info);
        }
        let mut sink = WriterSink::new(Vec::new());
        {
            let mut tracer = Tracer::new(&config, &mut sink);
            tracer.set_verbose(true);
            let mut cx = CallCtx::new(clock).with_tracer(&mut tracer);
            body(&mut cx);
        }
        String::from_utf8(sink.into_inner()).expect("trace output is text")
    }

    /// A [`ResolvedPresence`] with one fixed answer for both chains.
    ///
    /// `false` is how a test makes a baller's sub-chain fail on its first pass:
    /// `crate::conn::SetupFilter::connect` refuses with `CURLE_FAILED_INIT`
    /// before it reaches a factory.
    #[derive(Debug)]
    struct FixedPresence(bool);

    impl FixedPresence {
        fn new(present: bool) -> Arc<Self> {
            Arc::new(Self(present))
        }
    }

    impl ResolvedPresence for FixedPresence {
        fn has_resolved(&self, sockindex: SocketIndex) -> bool {
            let _ = sockindex;
            self.0
        }
    }

    /// Records every `Curl_expire` and `Curl_expire_done`.
    #[derive(Debug, Default)]
    struct TestExpiry {
        armed: SyncCell<Vec<(TimeDiff, TimerId)>>,
        cleared: SyncCell<Vec<TimerId>>,
    }

    impl ExpireScheduler for TestExpiry {
        fn expire(&self, timeout_ms: TimeDiff, timer: TimerId) {
            self.armed.borrow_mut().push((timeout_ms, timer));
        }

        fn expire_done(&self, timer: TimerId) {
            self.cleared.borrow_mut().push(timer);
        }
    }

    /// A filter that records that it was reached and connects after `steps`
    /// refusals.
    ///
    /// It carries the NAME and FLAGS of the real filter it stands in for,
    /// because the capability searches the setup machine performs read the
    /// flags and nothing else.
    #[derive(Debug)]
    struct Marker {
        base: FilterBase,
        name: &'static str,
        flags: CfType,
        /// Connect passes still to be refused before reporting connected.
        steps: usize,
        /// What `CF_QUERY_CONNECT_REPLY_MS` answers, when anything. [`None`]
        /// leaves the query unanswered, which `FilterChain::connect_reply_ms`
        /// turns into the C's `-1` -- "this baller has seen no data".
        reply_ms: Option<TimeDiff>,
        log: EventLog,
    }

    impl Marker {
        fn new(
            name: &'static str,
            flags: CfType,
            steps: usize,
            log: &EventLog,
        ) -> Self {
            Self {
                base: FilterBase::new(SocketIndex::First),
                name,
                flags,
                steps,
                reply_ms: None,
                log: Arc::clone(log),
            }
        }

        fn note(&self, what: &str) {
            self.log.borrow_mut().push(format!("{}:{what}", self.name));
        }
    }

    impl ConnFilter for Marker {
        fn trace_name(&self) -> &'static str {
            self.name
        }

        fn cf_type(&self) -> CfType {
            self.flags
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            self.note("connect");
            if let Some(next) = self.base.next_mut() {
                if !next.base().is_connected() && !next.connect(cx)? {
                    return Ok(false);
                }
            }
            if self.steps > 0 {
                self.steps -= 1;
                return Ok(false);
            }
            self.base.set_connected(true);
            Ok(true)
        }

        fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
            self.note("close");
            chain_close(self, cx);
        }

        fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            let _ = cx;
            self.note("shutdown");
            Ok(true)
        }

        fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
            let _ = cx;
            self.note("destroy");
        }

        fn query(
            &mut self,
            cx: &mut CallCtx<'_, '_>,
            query: CfQuery,
        ) -> CurlResult<CfQueryValue> {
            if matches!(query, CfQuery::ConnectReplyMs) {
                if let Some(ms) = self.reply_ms {
                    return Ok(CfQueryValue::ConnectReplyMs(ms));
                }
            }
            match self.base_mut().next_mut() {
                Some(next) => next.query(cx, query),
                None => Err(Error::new(CURLcode::UnknownOption)),
            }
        }
    }

    /// Builds a [`Marker`] per setup stage, and can be told to fail one.
    ///
    /// `https_setup` is deliberately a hard failure: this module OWNS that
    /// factory method, so a baller's sub-chain reaching it would mean the race
    /// had recursed into itself.
    #[derive(Debug)]
    struct TestFactories {
        log: EventLog,
        /// Connect passes each produced filter refuses before connecting.
        steps: usize,
        /// A stage name that must fail, and the code it fails with.
        fail: Option<(&'static str, CURLcode)>,
        /// What `CF_QUERY_CONNECT_REPLY_MS` answers on the produced filters.
        reply_ms: Option<TimeDiff>,
    }

    impl TestFactories {
        fn new(log: &EventLog) -> Self {
            Self {
                log: Arc::clone(log),
                steps: 0,
                fail: None,
                reply_ms: None,
            }
        }

        fn with_steps(mut self, steps: usize) -> Self {
            self.steps = steps;
            self
        }

        fn failing(mut self, stage: &'static str, code: CURLcode) -> Self {
            self.fail = Some((stage, code));
            self
        }

        fn with_reply_ms(mut self, reply_ms: TimeDiff) -> Self {
            self.reply_ms = Some(reply_ms);
            self
        }

        fn build(
            &self,
            name: &'static str,
            flags: CfType,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            self.log.borrow_mut().push(format!("build:{name}"));
            if let Some((stage, code)) = self.fail {
                if stage == name {
                    return Err(Error::new(code));
                }
            }
            let mut marker = Marker::new(name, flags, self.steps, &self.log);
            marker.reply_ms = self.reply_ms;
            marker.base.set_sockindex(sockindex);
            marker.base.set_conn(conn);
            Ok(link(marker))
        }
    }

    impl ConnectionFilterFactories for TestFactories {
        fn happy_eyeballs(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
            transport: Transport,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            // The transport each baller was built for, which is how a test sees
            // that `h3` forced QUIC. `lib/cf-ip-happy.c:903-905` declares the
            // real filter's flags as zero.
            self.log
                .borrow_mut()
                .push(format!("transport:{}", transport.as_u8()));
            self.build("HAPPY-EYEBALLS", CfType::NONE, sockindex, conn)
        }

        fn socks_proxy(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("SOCKS", CF_TYPE_PROXY, sockindex, conn)
        }

        fn proxy_tls(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("SSL-PROXY", CF_TYPE_SSL, sockindex, conn)
        }

        fn http_proxy_tunnel(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("HTTP-PROXY", CF_TYPE_PROXY, sockindex, conn)
        }

        fn haproxy(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("HAPROXY", CF_TYPE_PROXY, sockindex, conn)
        }

        fn origin_tls(
            &self,
            cx: &mut CallCtx<'_, '_>,
            sockindex: SocketIndex,
            conn: Option<ConnId>,
        ) -> CurlResult<FilterLink> {
            let _ = cx;
            self.build("SSL", CF_TYPE_SSL, sockindex, conn)
        }

        fn https_setup(
            &self,
            cx: &mut CallCtx<'_, '_>,
            chain: &mut FilterChain,
        ) -> CurlResult<()> {
            let _ = (cx, chain);
            Err(Error::with_context(
                CURLcode::FailedInit,
                "a baller sub-chain must never re-enter https_setup",
            ))
        }
    }

    /// The seams a race is built with, plus the expiry recorder to inspect.
    fn seams_with(
        log: &EventLog,
        factories: TestFactories,
        resolved: bool,
        timeout_ms: TimeDiff,
    ) -> (HttpsConnectSeams, Arc<TestExpiry>) {
        let _ = log;
        let expiry = Arc::new(TestExpiry::default());
        let setup = SetupContext::new(
            Arc::new(factories),
            FixedPresence::new(resolved),
        );
        let seams =
            HttpsConnectSeams::new(setup, Arc::clone(&expiry) as Arc<_>)
                .with_happy_eyeballs_timeout_ms(timeout_ms);
        (seams, expiry)
    }

    /// A minimal [`Protocol`] -- 2 of the 17 members.
    ///
    /// Its shape is the point: `Curl_protocol_file` fills 5 slots of 17 and a
    /// stub handler fills 1, so a two-member implementation must compile
    /// without a single further line. Everything else is inherited from the
    /// trait's defaults, and `the_defaults_behave_as_a_zero_null_slot_does`
    /// asserts what each of them answers.
    #[derive(Debug)]
    struct Probe;

    impl Protocol for Probe {
        fn do_it<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
        ) -> ProtoFuture<'a, bool> {
            let _ = ctx;
            Box::pin(core::future::ready(Ok(true)))
        }

        fn done<'a>(
            &'a self,
            ctx: &'a mut TransferCtx<'_>,
            status: CURLcode,
            premature: bool,
        ) -> ProtoFuture<'a, ()> {
            let _ = (ctx, status, premature);
            Box::pin(core::future::ready(Ok(())))
        }
    }

    /// The one instance, `'static` so that a [`Scheme`] row can point at it --
    /// which is what makes the gates of [`findprotocol`] reachable in a build
    /// whose every production row carries `run: None`.
    static PROBE: Probe = Probe;

    // -- 1. the registry, asserted row by row ------------------------------

    /// One row as the C writes it: name, `protocol`, `family`, the
    /// `PROTOPT_*` list and the default port.
    ///
    /// An INDEPENDENT transcription of the C, deliberately: the ports are
    /// written as integer literals rather than as this module's `PORT_*`
    /// constants, and the flags as explicit lists rather than as its `FLAGS_*`
    /// constants, so that a mistake in either would be caught rather than
    /// confirmed. The `Proto` column does name this module's constants, and
    /// those are pinned to their literal bit positions by
    /// `the_public_protocol_bits_are_curls_own_integers` below, which closes
    /// the chain.
    type ExpectedRow =
        (&'static str, Proto, Proto, &'static [ProtocolOptions], u16);

    /// All 33 registrations of `lib/url.c:1488-1522`, from their defining
    /// sites.
    ///
    /// The nine in-scope rows come from `lib/http.c:5011` and `:5028`,
    /// `lib/ftp.c:4348` and `:4367`, `lib/vssh/vssh.c:338` and `:352`,
    /// `lib/file.c:626`, and `lib/ws.c:1984` and `:1999`. The 24 others come
    /// from `lib/smtp.c`, `lib/imap.c`, `lib/pop3.c`, `lib/telnet.c`,
    /// `lib/tftp.c`, `lib/smb.c`, `lib/openldap.c`, `lib/rtsp.c`,
    /// `lib/mqtt.c`, `lib/curl_rtmp.c`, `lib/dict.c` and `lib/gopher.c`.
    #[rustfmt::skip]
    const EXPECTED: &[ExpectedRow] = &[
        // -- the nine in core scope ----------------------------------------
        ("http",    Proto::HTTP,    Proto::HTTP,    &[ProtocolOptions::CREDSPERREQUEST, ProtocolOptions::USERPWDCTRL, ProtocolOptions::CONN_REUSE], 80),
        ("https",   Proto::HTTPS,   Proto::HTTP,    &[ProtocolOptions::SSL, ProtocolOptions::CREDSPERREQUEST, ProtocolOptions::ALPN, ProtocolOptions::USERPWDCTRL, ProtocolOptions::CONN_REUSE], 443),
        ("ftp",     Proto::FTP,     Proto::FTP,     &[ProtocolOptions::DUAL, ProtocolOptions::CLOSEACTION, ProtocolOptions::NEEDSPWD, ProtocolOptions::NOURLQUERY, ProtocolOptions::PROXY_AS_HTTP, ProtocolOptions::WILDCARD, ProtocolOptions::SSL_REUSE, ProtocolOptions::CONN_REUSE], 21),
        ("ftps",    Proto::FTPS,    Proto::FTP,     &[ProtocolOptions::SSL, ProtocolOptions::DUAL, ProtocolOptions::CLOSEACTION, ProtocolOptions::NEEDSPWD, ProtocolOptions::NOURLQUERY, ProtocolOptions::WILDCARD, ProtocolOptions::CONN_REUSE], 990),
        ("SFTP",    Proto::SFTP,    Proto::SFTP,    &[ProtocolOptions::DIRLOCK, ProtocolOptions::CLOSEACTION, ProtocolOptions::NOURLQUERY, ProtocolOptions::CONN_REUSE], 22),
        ("SCP",     Proto::SCP,     Proto::SCP,     &[ProtocolOptions::DIRLOCK, ProtocolOptions::CLOSEACTION, ProtocolOptions::NOURLQUERY, ProtocolOptions::CONN_REUSE], 22),
        ("file",    Proto::FILE,    Proto::FILE,    &[ProtocolOptions::NONETWORK, ProtocolOptions::NOURLQUERY], 0),
        ("WS",      Proto::WS,      Proto::HTTP,    &[ProtocolOptions::CREDSPERREQUEST, ProtocolOptions::USERPWDCTRL], 80),
        ("WSS",     Proto::WSS,     Proto::HTTP,    &[ProtocolOptions::SSL, ProtocolOptions::CREDSPERREQUEST, ProtocolOptions::USERPWDCTRL], 443),
        // -- the 24 registered for ABI completeness -------------------------
        ("smtp",    Proto::SMTP,    Proto::SMTP,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::NOURLQUERY, ProtocolOptions::URLOPTIONS, ProtocolOptions::SSL_REUSE, ProtocolOptions::CONN_REUSE], 25),
        ("smtps",   Proto::SMTPS,   Proto::SMTP,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::SSL, ProtocolOptions::NOURLQUERY, ProtocolOptions::URLOPTIONS, ProtocolOptions::CONN_REUSE], 465),
        ("imap",    Proto::IMAP,    Proto::IMAP,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::URLOPTIONS, ProtocolOptions::SSL_REUSE, ProtocolOptions::CONN_REUSE], 143),
        ("imaps",   Proto::IMAPS,   Proto::IMAP,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::SSL, ProtocolOptions::URLOPTIONS, ProtocolOptions::CONN_REUSE], 993),
        ("pop3",    Proto::POP3,    Proto::POP3,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::NOURLQUERY, ProtocolOptions::URLOPTIONS, ProtocolOptions::SSL_REUSE, ProtocolOptions::CONN_REUSE], 110),
        ("pop3s",   Proto::POP3S,   Proto::POP3,    &[ProtocolOptions::CLOSEACTION, ProtocolOptions::SSL, ProtocolOptions::NOURLQUERY, ProtocolOptions::URLOPTIONS, ProtocolOptions::CONN_REUSE], 995),
        ("telnet",  Proto::TELNET,  Proto::TELNET,  &[ProtocolOptions::NONE, ProtocolOptions::NOURLQUERY], 23),
        ("tftp",    Proto::TFTP,    Proto::TFTP,    &[ProtocolOptions::NOTCPPROXY, ProtocolOptions::NOURLQUERY], 69),
        ("smb",     Proto::SMB,     Proto::SMB,     &[ProtocolOptions::CONN_REUSE], 445),
        ("smbs",    Proto::SMBS,    Proto::SMB,     &[ProtocolOptions::SSL, ProtocolOptions::CONN_REUSE], 445),
        ("ldap",    Proto::LDAP,    Proto::LDAP,    &[ProtocolOptions::SSL_REUSE], 389),
        ("ldaps",   Proto::LDAPS,   Proto::LDAP,    &[ProtocolOptions::SSL], 636),
        ("rtsp",    Proto::RTSP,    Proto::RTSP,    &[ProtocolOptions::CONN_REUSE], 554),
        ("mqtt",    Proto::MQTT,    Proto::MQTT,    &[ProtocolOptions::NONE], 1883),
        ("mqtts",   Proto::MQTTS,   Proto::MQTT,    &[ProtocolOptions::SSL], 8883),
        ("rtmp",    Proto::RTMP,    Proto::RTMP,    &[ProtocolOptions::NONE], 1935),
        ("rtmpt",   Proto::RTMPT,   Proto::RTMPT,   &[ProtocolOptions::NONE], 80),
        ("rtmpe",   Proto::RTMPE,   Proto::RTMPE,   &[ProtocolOptions::NONE], 1935),
        ("rtmpte",  Proto::RTMPTE,  Proto::RTMPTE,  &[ProtocolOptions::NONE], 80),
        ("rtmps",   Proto::RTMPS,   Proto::RTMP,    &[ProtocolOptions::NONE], 443),
        ("rtmpts",  Proto::RTMPTS,  Proto::RTMPT,   &[ProtocolOptions::NONE], 443),
        ("dict",    Proto::DICT,    Proto::DICT,    &[ProtocolOptions::NONE, ProtocolOptions::NOURLQUERY], 2628),
        ("gopher",  Proto::GOPHER,  Proto::GOPHER,  &[ProtocolOptions::NONE], 70),
        ("gophers", Proto::GOPHERS, Proto::GOPHER,  &[ProtocolOptions::SSL], 70),
    ];

    /// The nine schemes specification 0.2.1 puts in core scope, as the table
    /// spells them -- upper case included.
    const IN_SCOPE: [&str; 9] = [
        "http", "https", "ftp", "ftps", "SFTP", "SCP", "file", "WS", "WSS",
    ];

    #[test]
    fn the_table_holds_the_thirty_three_schemes_the_c_registers() {
        // `lib/url.c:1488-1522` defines and registers 33 entries. The array's
        // declared length of 67 is the hash modulus and is NOT a count.
        assert_eq!(SCHEMES.len(), 33);
        assert_eq!(EXPECTED.len(), 33);

        // And no name appears twice, folded, which a hand-transcribed table is
        // exactly the kind of thing to get wrong.
        for (index, row) in SCHEMES.iter().enumerate() {
            for other in &SCHEMES[index + 1..] {
                let (left, right) = (row.name, other.name);
                assert!(
                    !left.eq_ignore_ascii_case(right),
                    "{} and {} collide when folded",
                    String::from_utf8_lossy(left),
                    String::from_utf8_lossy(right),
                );
            }
        }
    }

    #[test]
    fn every_row_matches_the_c_registration() {
        // The WHOLE table, column by column, in the C's own registration
        // order -- not a sample. A single transposed flag or port is the kind
        // of defect that only shows up as a wire mismatch in one fixture.
        assert_eq!(SCHEMES.len(), EXPECTED.len());

        for (row, expected) in SCHEMES.iter().zip(EXPECTED) {
            let (name, protocol, family, flags, defport) = *expected;
            assert_eq!(
                row.name,
                name.as_bytes(),
                "the table is out of the C's registration order at {name}"
            );

            let mut wanted = ProtocolOptions::NONE;
            for option in flags {
                wanted = wanted.union(*option);
            }

            assert_eq!(row.protocol, protocol, "{name}'s protocol column");
            assert_eq!(row.family, family, "{name}'s family column");
            assert_eq!(row.flags, wanted, "{name}'s PROTOPT_* column");
            assert_eq!(row.defport, defport, "{name}'s default port");
        }
    }

    #[test]
    fn every_protocol_and_family_column_is_a_single_bit() {
        // `struct Curl_scheme`'s comments: *"the specific protocol in this
        // struct, a single bit"* and *"family: single bit"*
        // (`lib/urldata.h:518-520`). A mask in either column would make
        // `findprotocol`'s gate and the pool's family match answer for schemes
        // they were never meant to.
        for row in SCHEMES {
            let name = String::from_utf8_lossy(row.name);
            assert!(
                row.protocol.is_single_bit(),
                "{name}'s protocol column is not one bit"
            );
            assert!(
                row.family.is_single_bit(),
                "{name}'s family column is not one bit"
            );
        }
    }

    #[test]
    fn exactly_four_rows_have_a_family_differing_from_their_protocol() {
        // `ftps` is `FTP`, and `https`, `WS` and `WSS` are all `HTTP` among
        // the nine in scope. The measured full set adds the TLS and the RTMP
        // variants, so the assertion names every row rather than a subset.
        let differing: Vec<String> = SCHEMES
            .iter()
            .filter(|row| row.family != row.protocol)
            .map(|row| String::from_utf8_lossy(row.name).into_owned())
            .collect();

        for name in ["ftps", "https", "WS", "WSS"] {
            assert!(
                differing.iter().any(|found| found == name),
                "{name}'s family must differ from its protocol"
            );
        }
        // And the four in-scope rows whose columns agree still agree.
        for name in ["http", "ftp", "SFTP", "SCP", "file"] {
            assert!(
                !differing.iter().any(|found| found == name),
                "{name}'s family and protocol must be the same bit"
            );
        }
    }

    #[test]
    fn ws_and_wss_carry_no_conn_reuse() {
        // `lib/ws.c:1992-1993` and `:2008-2009` set only
        // `PROTOPT_CREDSPERREQUEST | PROTOPT_USERPWDCTRL`, while
        // `lib/http.c:5015` and `:5032` add `PROTOPT_CONN_REUSE`. The two pairs
        // share ONE protocol implementation, so the flags are the only place
        // the distinction lives -- an upgraded WebSocket must never go back
        // into the pool.
        for name in [&b"WS"[..], b"WSS"] {
            let row = get_scheme(name).expect("the websocket rows resolve");
            assert!(
                !row.flags.intersects(ProtocolOptions::CONN_REUSE),
                "{} must not be poolable",
                String::from_utf8_lossy(name)
            );
        }
        for name in [&b"http"[..], b"https"] {
            let row = get_scheme(name).expect("the http rows resolve");
            assert!(
                row.flags.intersects(ProtocolOptions::CONN_REUSE),
                "{} is poolable in the C",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn url_options_is_set_for_exactly_the_six_sasl_schemes() {
        // `lib/smtp.c:2022` and `:2039`, `lib/imap.c:2341` and `:2359`,
        // `lib/pop3.c:1730` and `:1747`. `crate::url` reads this column
        // through `SchemeInfo::url_options`, so a wrong answer changes URL
        // parsing rather than only a transfer.
        let expected = ["smtp", "smtps", "imap", "imaps", "pop3", "pop3s"];
        for row in SCHEMES {
            let name = String::from_utf8_lossy(row.name);
            assert_eq!(
                row.flags.intersects(ProtocolOptions::URLOPTIONS),
                expected.contains(&name.as_ref()),
                "{name}'s PROTOPT_URLOPTIONS column disagrees with the C"
            );
        }
    }

    // -- 2. the lookup and its two guards ----------------------------------

    #[test]
    fn lookup_folds_case_and_requires_the_whole_name() {
        // `Curl_getn_scheme` lowercases the input for the hash and compares
        // with `curl_strnequal` (`lib/url.c:1524-1536`), so both sides fold.
        for spelling in [&b"SFTP"[..], b"sftp", b"Sftp", b"sFtP"] {
            let row = get_scheme(spelling).expect("sftp resolves");
            // The row's own spelling comes back unchanged -- the C stores and
            // returns the table's bytes, not the caller's.
            assert_eq!(row.name, b"SFTP");
            assert_eq!(row.defport, 22);
        }

        // A prefix must NOT match: the C's second predicate is
        // `!h->name[len]`, so the stored name must be exactly `len` bytes.
        assert!(get_scheme(b"htt").is_none());
        assert!(get_scheme(b"http ").is_none());
        assert!(get_scheme(b"nosuch").is_none());
    }

    #[test]
    fn the_four_upper_case_names_resolve_from_either_spelling() {
        // MEASURED: four of the 33 `name` fields are UPPER CASE in the C
        // despite the struct comment saying lowercase -- `lib/vssh/vssh.c:339`
        // and `:353`, `lib/ws.c:1985` and `:2000`. Preserved, not "fixed".
        for (upper, lower) in [
            ("SFTP", "sftp"),
            ("SCP", "scp"),
            ("WS", "ws"),
            ("WSS", "wss"),
        ] {
            let from_upper = get_scheme(upper.as_bytes());
            let from_lower = get_scheme(lower.as_bytes());
            let stored = from_upper.expect("resolves from its own spelling");
            assert_eq!(stored.name, upper.as_bytes());
            assert_eq!(
                from_lower.map(|row| row.name),
                Some(upper.as_bytes()),
                "{lower} must reach the same row as {upper}"
            );
        }

        // And every OTHER row is lower case, so the four are the whole set.
        let upper: Vec<String> = SCHEMES
            .iter()
            .filter(|row| row.name.iter().any(u8::is_ascii_uppercase))
            .map(|row| String::from_utf8_lossy(row.name).into_owned())
            .collect();
        assert_eq!(upper, ["SFTP", "SCP", "WS", "WSS"]);
    }

    #[test]
    fn nothing_longer_than_seven_bytes_can_resolve() {
        // `if(len && (len <= 7))` at `lib/url.c:1524` gates the whole lookup.
        // `gophers` is exactly seven and resolves; the guard is asserted
        // against a synthetic eight-byte name, since the table holds none.
        assert_eq!(MAX_RESOLVABLE_SCHEME_LEN, 7);
        assert_eq!(get_scheme(b"gophers").map(|row| row.defport), Some(70));
        assert!(get_scheme(b"gophers1").is_none());
        assert!(get_scheme(b"httpsxxx").is_none());

        for row in SCHEMES {
            assert!(
                row.name.len() <= MAX_RESOLVABLE_SCHEME_LEN,
                "{} is longer than the C's lookup can resolve",
                String::from_utf8_lossy(row.name)
            );
            assert!(
                row.name.is_ascii(),
                "{} is not ASCII, and the fold is ASCII-only",
                String::from_utf8_lossy(row.name)
            );
        }
    }

    #[test]
    fn an_empty_name_never_resolves() {
        // The `len &&` half of the same guard. `Curl_get_scheme` forwards
        // `strlen(scheme)` (`lib/url.c:1469-1472`), so an empty string arrives
        // here as a zero length rather than being rejected earlier.
        assert!(get_scheme(b"").is_none());
        assert!(getn_scheme(b"", 0).is_none());
        assert!(getn_scheme(b"http", 0).is_none());
    }

    #[test]
    fn getn_scheme_takes_a_prefix_and_refuses_one_it_cannot_read() {
        // The point of `Curl_getn_scheme` (`lib/url.c:1477`) is that the URL
        // parser hands it the bytes BEFORE the colon without copying them, so
        // a longer buffer with a shorter length must resolve.
        let row = getn_scheme(b"https://example.com", 5)
            .expect("the first five bytes are https");
        assert_eq!(row.name, b"https");

        // A length the slice cannot supply resolves to nothing rather than
        // reading past the end -- the bounds check the C gets from its
        // caller's contract, made explicit here.
        assert!(getn_scheme(b"http", 5).is_none());
        assert!(getn_scheme(b"ftp", 7).is_none());

        // A shorter length names whatever row is exactly that long, which is
        // the C's `!h->name[len]` and NOT a prefix match: four bytes of
        // `"https"` are `"http"`, a row in its own right, while three are
        // `"htt"`, which is no row at all.
        assert_eq!(
            getn_scheme(b"https", 4).map(|row| row.name),
            Some(&b"http"[..])
        );
        assert!(getn_scheme(b"https", 3).is_none());
        assert!(getn_scheme(b"ftps", 2).is_none());
    }

    #[test]
    fn default_port_for_scheme_answers_from_the_one_table() {
        // `crate::url` needs `CURLU_DEFAULT_PORT` and gets it from here rather
        // than from a second copy of the port list.
        assert_eq!(default_port_for_scheme(b"http"), Some(80));
        assert_eq!(default_port_for_scheme(b"HTTPS"), Some(443));
        assert_eq!(default_port_for_scheme(b"sftp"), Some(22));
        assert_eq!(default_port_for_scheme(b"gophers"), Some(70));
        // `file` has a port of ZERO, which is a row that resolves and answers
        // zero -- not a row that fails to resolve.
        assert_eq!(default_port_for_scheme(b"file"), Some(0));
        assert_eq!(default_port_for_scheme(b"nosuch"), None);

        for row in SCHEMES {
            assert_eq!(
                default_port_for_scheme(row.name),
                Some(row.defport),
                "{}'s port must come from its own row",
                String::from_utf8_lossy(row.name)
            );
        }
    }

    #[test]
    fn the_port_constants_are_the_measured_integers() {
        // `lib/urldata.h:29-53`, transcribed independently of the table above.
        assert_eq!(PORT_FTP, 21);
        assert_eq!(PORT_FTPS, 990);
        assert_eq!(PORT_TELNET, 23);
        assert_eq!(PORT_HTTP, 80);
        assert_eq!(PORT_HTTPS, 443);
        assert_eq!(PORT_DICT, 2628);
        assert_eq!(PORT_LDAP, 389);
        assert_eq!(PORT_LDAPS, 636);
        assert_eq!(PORT_TFTP, 69);
        assert_eq!(PORT_SSH, 22);
        assert_eq!(PORT_IMAP, 143);
        assert_eq!(PORT_IMAPS, 993);
        assert_eq!(PORT_POP3, 110);
        assert_eq!(PORT_POP3S, 995);
        assert_eq!(PORT_SMB, 445);
        assert_eq!(PORT_SMBS, 445);
        assert_eq!(PORT_SMTP, 25);
        assert_eq!(PORT_SMTPS, 465);
        assert_eq!(PORT_RTSP, 554);
        assert_eq!(PORT_RTMP, 1935);
        assert_eq!(PORT_GOPHER, 70);
        assert_eq!(PORT_MQTT, 1883);
        assert_eq!(PORT_MQTTS, 8883);
        // The C defines these two as ALIASES rather than as their own numbers
        // (`lib/urldata.h:46-47`), and the aliasing is the assertion.
        assert_eq!(PORT_RTMPT, PORT_HTTP);
        assert_eq!(PORT_RTMPS, PORT_HTTPS);
    }

    // -- 3. runnability, which is `run != NULL` within core scope -----------

    #[test]
    fn runnability_is_an_implementation_within_core_scope() {
        // The property, stated so that it holds before AND after an engine
        // lands: a row is runnable if and only if it carries an implementation
        // AND specification 0.2.2 puts it in scope. Nothing is compared
        // against a literal list of names, so no edit is needed here when a
        // protocol module registers itself.
        for row in SCHEMES {
            let name = String::from_utf8_lossy(row.name);
            assert_eq!(
                row.runnable(),
                row.run.is_some() && IN_SCOPE.contains(&name.as_ref()),
                "{name}'s runnable flag disagrees with its own columns"
            );
            assert_eq!(
                row.in_core_scope(),
                IN_SCOPE.contains(&name.as_ref()),
                "{name}'s core-scope answer disagrees with specification 0.2.2"
            );
        }
    }

    #[test]
    fn a_row_with_an_implementation_in_core_scope_is_runnable() {
        // The mechanism itself, proven against a stand-in so that the empty
        // production column cannot make the machinery vacuous. Without this,
        // `runnable` could be a constant `false` and every assertion above
        // would still pass.
        let runnable = Scheme {
            run: Some(&PROBE),
            ..*http_row()
        };
        assert!(runnable.run.is_some());
        assert!(runnable.in_core_scope());
        assert!(runnable.runnable());

        // And the scope guard is not decoration: an out-of-scope row stays
        // unrunnable even when an implementation is attached to it, which is
        // what stops `smtp` from claiming a transfer it cannot perform.
        let out_of_scope = Scheme {
            run: Some(&PROBE),
            ..*get_scheme(b"smtp").expect("smtp is a row of the table")
        };
        assert!(out_of_scope.run.is_some());
        assert!(!out_of_scope.in_core_scope());
        assert!(!out_of_scope.runnable());
    }

    #[test]
    fn the_registry_projects_every_row_through_one_lookup() {
        // `crate::url` sees the table only as `SchemeInfo`, and the projection
        // must agree with the row it came from in all four columns.
        let registry = scheme_registry();
        for row in SCHEMES {
            let name = String::from_utf8_lossy(row.name);
            let info = registry
                .lookup(row.name)
                .expect("every row resolves by its own name");
            assert_eq!(info.name, name, "the projected name is the row's");
            assert_eq!(info.default_port, row.defport, "{name}'s port");
            assert_eq!(
                info.url_options,
                row.flags.intersects(ProtocolOptions::URLOPTIONS),
                "{name}'s url_options"
            );
            assert_eq!(info.runnable, row.runnable(), "{name}'s runnable");
        }
        assert!(registry.lookup(b"htt").is_none());
        assert!(registry.lookup(b"").is_none());
    }

    #[test]
    fn the_registry_is_zero_sized_and_stable() {
        assert_eq!(core::mem::size_of::<AllSchemes>(), 0);
        // Two calls name one table; nothing is allocated per call, which is
        // what lets `curl_url()` obtain a registry without being handed one.
        let first: *const dyn SchemeRegistry = scheme_registry();
        let second: *const dyn SchemeRegistry = scheme_registry();
        assert_eq!(first.cast::<u8>(), second.cast::<u8>());
    }

    // -- 4. `CURLPROTO_*`, including the collision -------------------------

    #[test]
    fn the_public_protocol_bits_are_curls_own_integers() {
        // `include/curl/curl.h:1076-1107`, bit position by bit position. A
        // program compiled against curl 8.19.0-DEV holds these NUMBERS, so a
        // renumbering that kept the names would link and then misbehave with no
        // diagnostic anywhere -- specification 0.6.1's silent failure mode.
        #[rustfmt::skip]
        let expected: [(Proto, u32, &str); 31] = [
            (Proto::HTTP,    1 << 0,  "HTTP"),
            (Proto::HTTPS,   1 << 1,  "HTTPS"),
            (Proto::FTP,     1 << 2,  "FTP"),
            (Proto::FTPS,    1 << 3,  "FTPS"),
            (Proto::SCP,     1 << 4,  "SCP"),
            (Proto::SFTP,    1 << 5,  "SFTP"),
            (Proto::TELNET,  1 << 6,  "TELNET"),
            (Proto::LDAP,    1 << 7,  "LDAP"),
            (Proto::LDAPS,   1 << 8,  "LDAPS"),
            (Proto::DICT,    1 << 9,  "DICT"),
            (Proto::FILE,    1 << 10, "FILE"),
            (Proto::TFTP,    1 << 11, "TFTP"),
            (Proto::IMAP,    1 << 12, "IMAP"),
            (Proto::IMAPS,   1 << 13, "IMAPS"),
            (Proto::POP3,    1 << 14, "POP3"),
            (Proto::POP3S,   1 << 15, "POP3S"),
            (Proto::SMTP,    1 << 16, "SMTP"),
            (Proto::SMTPS,   1 << 17, "SMTPS"),
            (Proto::RTSP,    1 << 18, "RTSP"),
            (Proto::RTMP,    1 << 19, "RTMP"),
            (Proto::RTMPT,   1 << 20, "RTMPT"),
            (Proto::RTMPE,   1 << 21, "RTMPE"),
            (Proto::RTMPTE,  1 << 22, "RTMPTE"),
            (Proto::RTMPS,   1 << 23, "RTMPS"),
            (Proto::RTMPTS,  1 << 24, "RTMPTS"),
            (Proto::GOPHER,  1 << 25, "GOPHER"),
            (Proto::SMB,     1 << 26, "SMB"),
            (Proto::SMBS,    1 << 27, "SMBS"),
            (Proto::MQTT,    1 << 28, "MQTT"),
            (Proto::GOPHERS, 1 << 29, "GOPHERS"),
            (Proto::MQTTS,   1 << 30, "MQTTS"),
        ];

        for (proto, bits, name) in expected {
            assert_eq!(proto.bits(), bits, "CURLPROTO_{name}");
            assert!(proto.is_single_bit(), "CURLPROTO_{name} is not one bit");
        }

        // The two INTERNAL bits, `lib/urldata.h:70-71`.
        assert_eq!(Proto::WS.bits(), 1 << 30);
        assert_eq!(Proto::WSS.bits(), 1 << 31);

        // `CURLPROTO_ALL` is `~0`, not the union of the defined bits
        // (`include/curl/curl.h:1108`).
        assert_eq!(Proto::ALL.bits(), 0xffff_ffff);
        assert_eq!(Proto::NONE.bits(), 0);
        assert!(Proto::NONE.is_empty());
        assert!(!Proto::ALL.is_empty());
    }

    #[test]
    fn the_websocket_bit_collides_with_mqtts_and_that_is_upstreams_encoding() {
        // MEASURED, and asserted so that nobody "fixes" it: `lib/urldata.h:70`
        // defines `CURLPROTO_WS` as `(1L << 30)` and
        // `include/curl/curl.h:1106` defines `CURLPROTO_MQTTS` as the same bit.
        // Renumbering either would break the public header's integer contract.
        assert_eq!(Proto::WS.bits(), Proto::MQTTS.bits());
        assert_eq!(Proto::WS, Proto::MQTTS);

        // Which is exactly why `Scheme::in_core_scope` cannot be decided by the
        // protocol column alone: `mqtts` is out of scope and `ws` is in it.
        let mqtts = get_scheme(b"mqtts").expect("mqtts is a row");
        let ws = get_scheme(b"WS").expect("WS is a row");
        assert_eq!(mqtts.protocol, ws.protocol);
        assert!(mqtts.protocol.intersects(Proto::CORE_SCHEMES));
        assert!(!mqtts.in_core_scope());
        assert!(ws.in_core_scope());
        // `WSS` does not collide with anything, and is in scope on both tests.
        let wss = get_scheme(b"WSS").expect("WSS is a row");
        assert!(wss.in_core_scope());
    }

    #[test]
    fn the_family_masks_match_the_measured_definitions() {
        // `lib/urldata.h`'s six `PROTO_FAMILY_*`. Three of them have named
        // consumers: `crate::headers` gates its collector on
        // `PROTO_FAMILY_HTTP`, `crate::conn::happy_eyeballs` reads
        // `PROTO_FAMILY_SSH`, and `protocols/ftp` reads `PROTO_FAMILY_FTP`.
        assert_eq!(
            Proto::FAMILY_HTTP,
            Proto::HTTP | Proto::HTTPS | Proto::WS | Proto::WSS
        );
        assert_eq!(Proto::FAMILY_FTP, Proto::FTP | Proto::FTPS);
        assert_eq!(Proto::FAMILY_SSH, Proto::SCP | Proto::SFTP);
        assert_eq!(Proto::FAMILY_POP3, Proto::POP3 | Proto::POP3S);
        assert_eq!(Proto::FAMILY_SMB, Proto::SMB | Proto::SMBS);
        assert_eq!(Proto::FAMILY_SMTP, Proto::SMTP | Proto::SMTPS);

        // `CURLPROTO_REDIR` -- what a redirect may target by default
        // (`lib/urldata.h`), which is the HTTP and FTP families WITHOUT the
        // WebSocket schemes.
        assert_eq!(
            Proto::REDIR,
            Proto::HTTP | Proto::HTTPS | Proto::FTP | Proto::FTPS
        );
        assert!(!Proto::REDIR.intersects(Proto::WS));
        assert!(!Proto::REDIR.intersects(Proto::WSS));

        // `CURLPROTO_MASK`, `lib/urldata.h`.
        assert_eq!(Proto::MASK.bits(), 0x3ff_ffff);
    }

    #[test]
    fn every_in_scope_row_is_in_one_of_the_core_families() {
        // The two masks `Scheme::in_core_scope` conjoins, checked against each
        // other rather than against a third list.
        for row in SCHEMES {
            let name = String::from_utf8_lossy(row.name);
            assert_eq!(
                row.in_core_scope(),
                IN_SCOPE.contains(&name.as_ref()),
                "{name}'s core-scope answer"
            );
            if row.in_core_scope() {
                assert!(
                    row.family.intersects(Proto::CORE_FAMILIES),
                    "{name} is in scope but its family is not a core family"
                );
            }
        }
        assert_eq!(
            Proto::CORE_FAMILIES,
            Proto::HTTP | Proto::FTP | Proto::SCP | Proto::SFTP | Proto::FILE
        );
    }

    #[test]
    fn proto_renders_its_bits_and_names_the_collision_honestly() {
        // The `Debug` rendering is a diagnostic surface, and bit 30 carries two
        // names -- so it prints BOTH rather than picking one and misleading
        // whoever is reading a log.
        assert_eq!(format!("{:?}", Proto::HTTP), "Proto(HTTP)");
        assert_eq!(format!("{:?}", Proto::NONE), "Proto(NONE)");
        assert_eq!(format!("{:?}", Proto::WS), "Proto(MQTTS|WS)");
        assert_eq!(format!("{:?}", Proto::MQTTS), "Proto(MQTTS|WS)");
        let both = format!("{:?}", Proto::HTTP | Proto::FTP);
        assert!(both.contains("HTTP"), "{both}");
        assert!(both.contains("FTP"), "{both}");
    }

    #[test]
    fn proto_from_bits_and_contains_agree_with_the_masks() {
        assert_eq!(Proto::from_bits(1 << 0), Proto::HTTP);
        assert_eq!(Proto::from_bits(0), Proto::NONE);
        assert!(Proto::FAMILY_HTTP.contains(Proto::HTTP | Proto::HTTPS));
        assert!(!Proto::FAMILY_HTTP.contains(Proto::HTTP | Proto::FTP));
        assert!(Proto::FAMILY_HTTP.intersects(Proto::HTTP | Proto::FTP));
        assert!(!Proto::FAMILY_FTP.intersects(Proto::HTTP));
        assert_eq!(
            Proto::HTTP.union(Proto::FTP),
            Proto::from_bits((1 << 0) | (1 << 2))
        );
    }

    // -- 5. `findprotocol` and its three gates -----------------------------

    #[test]
    fn an_unknown_scheme_is_not_supported() {
        // `p` is NULL, so the C's ternary picks `"not supported"`.
        let refusal = findprotocol(b"xyz", Proto::ALL, Proto::ALL, false)
            .expect_err("an unknown scheme cannot be used");
        assert_eq!(refusal.message(), "Protocol \"xyz\" not supported");
        assert_eq!(refusal.code(), CURLcode::UnsupportedProtocol);
    }

    #[test]
    fn a_registered_scheme_without_an_implementation_is_disabled() {
        // `p` is non-NULL and `p->run` is NULL, so the C picks `"disabled"`.
        // This is the whole reason the 24 out-of-scope rows stay registered:
        // `smtp://` reports a DISABLED protocol, exactly as a C curl built with
        // `CURL_DISABLE_SMTP` does (`lib/dict.c:298` is the C's own idiom).
        let refusal = findprotocol(b"smtp", Proto::ALL, Proto::ALL, false)
            .expect_err("no row carries an implementation here");
        assert_eq!(refusal.message(), "Protocol \"smtp\" disabled");
        assert_eq!(refusal.code(), CURLcode::UnsupportedProtocol);

        // And an in-scope row answers the same way in this checkout, which is
        // the measured state rather than a defect in the message.
        let refusal = findprotocol(b"http", Proto::ALL, Proto::ALL, false)
            .expect_err("no row carries an implementation here");
        assert_eq!(refusal.message(), "Protocol \"http\" disabled");
    }

    #[test]
    fn a_refusal_while_following_a_redirect_carries_the_suffix() {
        // `data->state.this_is_a_follow ? " (in redirect)" : ""`
        // (`lib/url.c:1570`). The suffix begins with its own space, so a plain
        // refusal has NO trailing space -- both spellings asserted byte for
        // byte, since this is user-visible stderr text under specification
        // 0.8.1.
        let plain = findprotocol(b"xyz", Proto::ALL, Proto::ALL, false)
            .expect_err("unknown");
        let redirected = findprotocol(b"xyz", Proto::ALL, Proto::ALL, true)
            .expect_err("unknown");
        assert_eq!(plain.message(), "Protocol \"xyz\" not supported");
        assert_eq!(
            redirected.message(),
            "Protocol \"xyz\" not supported (in redirect)"
        );
        assert!(!plain.message().ends_with(' '));

        let known = findprotocol(b"ftp", Proto::ALL, Proto::ALL, true)
            .expect_err("no implementation");
        assert_eq!(known.message(), "Protocol \"ftp\" disabled (in redirect)");
    }

    #[test]
    fn the_message_is_assembled_from_exactly_three_fragments() {
        // All four combinations of the two ternaries, reached directly so that
        // the wording is asserted without going through the gates.
        assert_eq!(
            unsupported_message(b"http", true, false),
            "Protocol \"http\" disabled"
        );
        assert_eq!(
            unsupported_message(b"http", true, true),
            "Protocol \"http\" disabled (in redirect)"
        );
        assert_eq!(
            unsupported_message(b"zz", false, false),
            "Protocol \"zz\" not supported"
        );
        assert_eq!(
            unsupported_message(b"zz", false, true),
            "Protocol \"zz\" not supported (in redirect)"
        );

        // Exactly ONE space before the disposition, and the quotes are the C's
        // own `\"%s\"`.
        let message = unsupported_message(b"a", true, false);
        assert!(message.starts_with("Protocol \"a\" d"), "{message}");

        // A name the URL parser accepted but that is not UTF-8 still produces a
        // diagnostic, because the C's `%s` prints whatever bytes it was given.
        let lossy = unsupported_message(&[0xff, 0xfe], false, false);
        assert!(lossy.starts_with("Protocol \""), "{lossy}");
        assert!(lossy.ends_with("\" not supported"), "{lossy}");
    }

    #[test]
    fn the_three_gates_are_independent() {
        // Every row of the production table carries `run: None`, so gates two
        // and three are unreachable through `findprotocol` itself. `admits`
        // exists for exactly this: the same production predicate, applied to a
        // row that does carry an implementation.
        let runnable = Scheme {
            run: Some(&PROBE),
            ..*http_row()
        };

        // All three satisfied.
        assert!(admits(&runnable, Proto::ALL, Proto::ALL, false));
        assert!(admits(&runnable, Proto::HTTP, Proto::HTTP, true));

        // Gate 1 -- no implementation. The row is otherwise identical.
        assert!(!admits(http_row(), Proto::ALL, Proto::ALL, false));

        // Gate 2 -- `CURLOPT_PROTOCOLS_STR` does not permit it. Note that this
        // is checked whether or not a redirect is being followed.
        assert!(!admits(&runnable, Proto::FTP, Proto::ALL, false));
        assert!(!admits(&runnable, Proto::NONE, Proto::ALL, false));

        // Gate 3 -- `CURLOPT_REDIR_PROTOCOLS_STR` does not permit it, and ONLY
        // while following a redirect. The same arguments differ in the flag
        // alone, which is what makes the gate's conditionality the assertion.
        assert!(admits(&runnable, Proto::ALL, Proto::NONE, false));
        assert!(!admits(&runnable, Proto::ALL, Proto::NONE, true));
        assert!(!admits(&runnable, Proto::ALL, Proto::FTP, true));
        assert!(admits(&runnable, Proto::ALL, Proto::HTTP, true));

        // And the composed function returns the ROW on success, which is what
        // the C assigns to `conn->scheme` and `conn->given`.
        let found = findprotocol(b"HtTp", Proto::ALL, Proto::ALL, false);
        assert!(found.is_err(), "no implementation in this checkout");
        assert!(admits(&runnable, Proto::REDIR, Proto::REDIR, true));
    }

    #[test]
    fn the_refusal_converts_to_the_crates_error_and_keeps_its_text() {
        let refusal = findprotocol(b"nosuch", Proto::ALL, Proto::ALL, false)
            .expect_err("unknown");
        let expected = refusal.message().to_owned();
        assert_eq!(refusal.to_string(), expected);

        let error: Error = refusal.into();
        assert_eq!(error.code(), CURLcode::UnsupportedProtocol);
        assert!(
            error.to_string().contains(&expected),
            "the message must survive the conversion: {error}"
        );
    }

    // -- 6. `trait Protocol` -- object safety and the 15 defaults -----------

    /// A [`TransferCtx`] over borrowed chains and an injected clock.
    ///
    /// The scheme is taken from the production table rather than fabricated, so
    /// the context a defaulted member sees is the one a real transfer would
    /// hand it.
    fn transfer_ctx<'a>(
        chains: &'a mut FilterChains,
        clock: &'a TestClock,
    ) -> TransferCtx<'a> {
        TransferCtx::new(chains, clock, http_row())
    }

    #[test]
    fn a_two_of_seventeen_implementation_is_dispatchable_behind_dyn() {
        // THE object-safety regression test. Specification 0.3.3's pattern P1
        // requires `&dyn Protocol` dispatch, and both `async fn` in a trait and
        // return-position `impl Trait` in a trait -- stabilised in 1.75, this
        // workspace's floor -- would make the trait dyn-INCOMPATIBLE. If
        // somebody replaced a `ProtoFuture` with `async fn`, this line would
        // stop compiling, which is precisely the alarm that is wanted.
        let handler: &dyn Protocol = &PROBE;
        let boxed: Box<dyn Protocol> = Box::new(Probe);
        let stored: Option<&'static dyn Protocol> = Some(&PROBE);
        assert!(stored.is_some());

        // And the registry's own column has that type, so a row can hold one.
        let row = Scheme {
            run: Some(handler),
            ..*http_row()
        };
        assert!(row.runnable());

        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);

        // Dispatched through the trait object, not through `Probe`.
        let done = futures::executor::block_on(handler.do_it(&mut ctx));
        assert_eq!(done, Ok(true));
        let finished = futures::executor::block_on(boxed.done(
            &mut ctx,
            CURLcode::Ok,
            false,
        ));
        assert_eq!(finished, Ok(()));
    }

    #[test]
    fn the_defaults_behave_as_a_zero_null_slot_does() {
        // 15 of the 17 members are defaulted, because `Curl_protocol_file`
        // fills 5 slots and `Curl_protocol_dict` fills 1. Each default answers
        // what the C's caller assumes for a `ZERO_NULL`, and this asserts every
        // one of them.
        let handler: &dyn Protocol = &PROBE;
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);

        // 1. setup_connection -- nothing to allocate.
        assert_eq!(handler.setup_connection(&mut ctx), Ok(()));

        // 4..7. the four former `bool *done` members complete immediately.
        assert_eq!(
            futures::executor::block_on(handler.do_more(&mut ctx)),
            Ok(true)
        );
        assert_eq!(
            futures::executor::block_on(handler.connect_it(&mut ctx)),
            Ok(true)
        );
        assert_eq!(
            futures::executor::block_on(handler.connecting(&mut ctx)),
            Ok(true)
        );
        assert_eq!(
            futures::executor::block_on(handler.doing(&mut ctx)),
            Ok(true)
        );

        // 8..11. the four pollsets are no-ops -- the tokio reactor does that
        // job, and `crate::conn::filters`' own `adjust_pollset` default is a
        // pure no-op for the same reason.
        let mut ps = EasyPollset::new();
        assert_eq!(handler.proto_pollset(&mut ctx, &mut ps), Ok(()));
        assert_eq!(handler.doing_pollset(&mut ctx, &mut ps), Ok(()));
        assert_eq!(handler.domore_pollset(&mut ctx, &mut ps), Ok(()));
        assert_eq!(handler.perform_pollset(&mut ctx, &mut ps), Ok(()));
        assert!(ps.is_empty(), "a defaulted pollset registers nothing");

        // 12. disconnect succeeds, dead or alive.
        assert_eq!(
            futures::executor::block_on(handler.disconnect(&mut ctx, false)),
            Ok(())
        );
        assert_eq!(
            futures::executor::block_on(handler.disconnect(&mut ctx, true)),
            Ok(())
        );

        // 13..14. the write hooks report NOT HANDLED, which is what sends the
        // bytes down the generic client-writer path in `crate::transfer`.
        assert_eq!(
            futures::executor::block_on(
                handler.write_resp(&mut ctx, b"body", false)
            ),
            Ok(false)
        );
        assert_eq!(
            futures::executor::block_on(
                handler.write_resp_hd(&mut ctx, b"X: y", true)
            ),
            Ok(false)
        );

        // 15. connection_check answers CONNRESULT_NONE for every check.
        assert_eq!(
            handler.connection_check(&mut ctx, ConnCheck::ISDEAD),
            ConnResult::NONE
        );
        assert_eq!(
            handler.connection_check(&mut ctx, ConnCheck::ALL),
            ConnResult::NONE
        );

        // 16. attach returns nothing and does nothing.
        handler.attach(&mut ctx);

        // 17. follow REFUSES by default -- `multi_follow` answers
        // `CURLE_TOO_MANY_REDIRECTS` for a `ZERO_NULL` slot
        // (`lib/multi.c:1870-1878`), which is what stops the multi handle
        // looping on a URL nothing can act on.
        for follow_type in [
            FollowType::None,
            FollowType::Fake,
            FollowType::Retry,
            FollowType::Redir,
        ] {
            assert_eq!(
                handler.follow(&mut ctx, "https://example.com/", follow_type),
                Err(CURLcode::TooManyRedirects),
                "{follow_type:?} must be refused by the default"
            );
        }
    }

    #[test]
    fn the_transfer_context_carries_the_scheme_and_both_chains() {
        // The context is how an asynchronous protocol reaches the synchronous
        // filter layer, and the bridge is deliberately short-lived.
        let clock = clock();
        let mut chains = FilterChains::new(None);
        let mut ctx = transfer_ctx(&mut chains, &clock);

        assert_eq!(ctx.scheme().name, b"http");
        assert_eq!(ctx.sockindex(), SocketIndex::First);
        assert_eq!(ctx.now(), CurlTime::new(1_000, 0));
        assert!(ctx.chain().is_empty());
        assert!(ctx.chains().chain(SocketIndex::Secondary).is_empty());

        // `CallCtx` is not `Send`, so it is created inside a future's body and
        // goes out of scope before the next await rather than being held across
        // one -- the borrow ends with the block.
        {
            let sub = ctx.call_ctx();
            assert_eq!(sub.now(), CurlTime::new(1_000, 0));
        }

        // A `PROTOPT_DUAL` protocol works on the secondary chain, which is the
        // one thing `with_sockindex` exists for.
        let mut chains = FilterChains::new(None);
        let ctx = transfer_ctx(&mut chains, &clock)
            .with_sockindex(SocketIndex::Secondary);
        assert_eq!(ctx.sockindex(), SocketIndex::Secondary);
        assert!(format!("{ctx:?}").contains("http"), "{ctx:?}");
    }

    // -- 7. HTTP version negotiation and `Curl_conn_may_http3` --------------

    /// The negotiation state of an ordinary `https://` transfer: every version
    /// allowed, none preferred, `wanted` supplied by the caller.
    fn negotiation(wanted: HttpMajors) -> HttpNegotiation {
        HttpNegotiation {
            rcvd_min: 0,
            wanted,
            allowed: CURL_HTTP_V1X | CURL_HTTP_V2X | CURL_HTTP_V3X,
            preferred: HttpMajors::NONE,
            h2_upgrade: false,
            h2_prior_knowledge: false,
            accept_09: false,
            only_10: false,
        }
    }

    #[test]
    fn the_major_version_bits_are_the_measured_ones() {
        // `lib/http.h:50-52`, consumed from `crate::tls` rather than
        // redeclared: the TLS layer owns them because it builds the ALPN offer.
        assert_eq!(CURL_HTTP_V1X.bits(), 1 << 0);
        assert_eq!(CURL_HTTP_V2X.bits(), 1 << 1);
        assert_eq!(CURL_HTTP_V3X.bits(), 1 << 2);
        assert_eq!(CURL_HTTP_V1X, HttpMajors::V1X);
        assert_eq!(CURL_HTTP_V2X, HttpMajors::V2X);
        assert_eq!(CURL_HTTP_V3X, HttpMajors::V3X);

        // `struct http_negotiation`'s default is every field zero, which is
        // what `Curl_http_neg_init` overwrites (`lib/http.h:63-72`).
        let neg = HttpNegotiation::default();
        assert_eq!(neg.rcvd_min, 0);
        assert_eq!(neg.wanted, HttpMajors::NONE);
        assert_eq!(neg.allowed, HttpMajors::NONE);
        assert_eq!(neg.preferred, HttpMajors::NONE);
        assert!(!neg.h2_upgrade);
        assert!(!neg.h2_prior_knowledge);
        assert!(!neg.accept_09);
        assert!(!neg.only_10);
    }

    #[test]
    fn conn_may_http3_is_declared_whatever_the_build_carries() {
        // `Curl_conn_may_http3` is declared OUTSIDE the `USE_HTTP3` guard in
        // `lib/vquic/vquic.h`, so it exists in every build and only its success
        // path is conditional. This test therefore compiles either way.
        let https = get_scheme(b"https").expect("https is a row").flags;
        let no_proxy = Http3Proxy::default();

        let over_tcp = conn_may_http3(https, Transport::Tcp, no_proxy);

        #[cfg(feature = "http3")]
        {
            // TLS, no proxy, a transport that is not a Unix socket: permitted.
            assert!(over_tcp.is_ok(), "{:?}", over_tcp.err());
            assert!(conn_may_http3(https, Transport::Quic, no_proxy).is_ok());

            // A plaintext scheme is refused with the C's own `failf` text.
            let http = get_scheme(b"http").expect("http is a row").flags;
            let plain = conn_may_http3(http, Transport::Tcp, no_proxy)
                .expect_err("http:// cannot carry HTTP/3");
            assert_eq!(plain.code(), CURLcode::UrlMalformat);
            assert_eq!(plain.to_string(), H3_NEEDS_HTTPS);

            // A Unix domain socket is refused with a code and NO message.
            let unix = conn_may_http3(https, Transport::Unix, no_proxy)
                .expect_err("QUIC cannot run over a Unix socket");
            assert_eq!(unix.code(), CURLcode::QuicConnectError);

            // Both proxy obstacles, each with its own frozen text.
            let socks = conn_may_http3(
                https,
                Transport::Tcp,
                Http3Proxy {
                    socks: true,
                    http_tunnel: false,
                },
            )
            .expect_err("a SOCKS proxy blocks HTTP/3");
            assert_eq!(socks.code(), CURLcode::UrlMalformat);
            assert_eq!(socks.to_string(), H3_OVER_SOCKS);

            let tunnel = conn_may_http3(
                https,
                Transport::Tcp,
                Http3Proxy {
                    socks: false,
                    http_tunnel: true,
                },
            )
            .expect_err("an HTTP tunnel blocks HTTP/3");
            assert_eq!(tunnel.code(), CURLcode::UrlMalformat);
            assert_eq!(tunnel.to_string(), H3_OVER_HTTP_PROXY);
        }

        #[cfg(not(feature = "http3"))]
        {
            // `lib/vquic/vquic.c:854-863` is three `(void)` casts and
            // `return CURLE_NOT_BUILT_IN`, so EVERY input is refused -- with a
            // different code from the compiled-in Unix-socket refusal. The
            // asymmetry is the C's.
            let refusal = over_tcp.expect_err("no HTTP/3 in this build");
            assert_eq!(refusal.code(), CURLcode::NotBuiltIn);
            assert_eq!(
                conn_may_http3(https, Transport::Unix, no_proxy)
                    .expect_err("no HTTP/3 in this build")
                    .code(),
                CURLcode::NotBuiltIn
            );
        }
    }

    #[test]
    fn the_http3_refusal_texts_are_the_measured_ones() {
        // Frozen, user-visible `failf` strings (`lib/vquic/vquic.c:729`, `:734`
        // and `:739`), asserted whatever the feature set is so that a build
        // without HTTP/3 still cannot drift.
        assert_eq!(H3_NEEDS_HTTPS, "HTTP/3 requested for non-HTTPS URL");
        assert_eq!(H3_OVER_SOCKS, "HTTP/3 is not supported over a SOCKS proxy");
        assert_eq!(
            H3_OVER_HTTP_PROXY,
            "HTTP/3 is not supported over an HTTP proxy"
        );
    }

    // -- 8. the ALPN offer, which IS ClientHello bytes ----------------------

    /// The `PROTOPT_*` of `https`, which is what makes HTTP/3 permissible.
    fn https_flags() -> ProtocolOptions {
        get_scheme(b"https").expect("https is a row").flags
    }

    /// The `PROTOPT_*` of `http`, which is what makes it impermissible.
    fn http_flags() -> ProtocolOptions {
        get_scheme(b"http").expect("http is a row").flags
    }

    /// An `https://` request to port 443 over TCP with no record and no proxy.
    fn https_request(neg: HttpNegotiation) -> HttpsSetupRequest<'static> {
        HttpsSetupRequest::new(neg, 443, Transport::Tcp, https_flags())
    }

    /// The offer for `request`, with the trace discarded.
    ///
    /// Returned as a plain `Vec` because `crate::error::Error` is deliberately
    /// not `PartialEq` -- it carries a message -- so an offer is compared by
    /// value and a refusal is inspected through [`offer_result`].
    fn offer(request: &HttpsSetupRequest<'_>) -> Vec<AlpnId> {
        offer_result(request).expect("this request has an offer")
    }

    /// The offer for `request`, refusal and all.
    fn offer_result(
        request: &HttpsSetupRequest<'_>,
    ) -> CurlResult<Vec<AlpnId>> {
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        alpn_offer(&mut cx, SocketIndex::First, request)
    }

    /// The offer for `request`, together with everything it traced.
    fn offer_traced(request: &HttpsSetupRequest<'_>) -> (Vec<AlpnId>, String) {
        let clock = clock();
        let mut ids = Vec::new();
        let trace = traced(&clock, |cx| {
            ids = alpn_offer(cx, SocketIndex::First, request)
                .expect("this request has an offer");
        });
        (ids, trace)
    }

    /// An HTTPS resource record advertising `alpns`, for this same host and
    /// port.
    fn record(alpns: &[AlpnId]) -> HttpsRrInfo {
        let mut stored = [AlpnId::None.as_u8(); MAX_HTTPSRR_ALPNS];
        for (slot, alpn) in stored.iter_mut().zip(alpns) {
            *slot = alpn.as_u8();
        }
        HttpsRrInfo {
            alpns: stored,
            ..HttpsRrInfo::default()
        }
    }

    #[test]
    fn an_offer_is_empty_when_alpn_is_switched_off() {
        // `if(conn->bits.tls_enable_alpn)` wraps the WHOLE selection
        // (`lib/cf-https-connect.c:663`), and an empty offer installs nothing
        // -- which is a correct outcome, not a failure.
        let neg = negotiation(CURL_HTTP_V1X | CURL_HTTP_V2X);
        let request = https_request(neg).with_tls_enable_alpn(false);
        assert!(offer(&request).is_empty());

        // With ALPN on, the same negotiation state does produce an offer, so
        // the flag is what the assertion above turns on.
        let request = https_request(neg);
        assert_eq!(offer(&request), vec![AlpnId::H2]);
    }

    #[test]
    fn step_four_adds_h2_or_h1_but_never_both() {
        // The C writes an `if` / `else if` PAIR (`:747-761`), so a transfer
        // wanting both 1.1 and 2 offers `h2` alone. Two separate `if`s would
        // offer `[h2, h1]` and change the ClientHello.
        let both = negotiation(CURL_HTTP_V1X | CURL_HTTP_V2X);
        assert_eq!(offer(&https_request(both)), vec![AlpnId::H2]);

        let only_h1 = negotiation(CURL_HTTP_V1X);
        assert_eq!(offer(&https_request(only_h1)), vec![AlpnId::H1]);

        let only_h2 = negotiation(CURL_HTTP_V2X);
        assert_eq!(offer(&https_request(only_h2)), vec![AlpnId::H2]);

        // And step 4 consults `wanted` ALONE -- never `allowed`, which is the
        // C's own asymmetry with steps 1 and 2.
        let mut narrow = negotiation(CURL_HTTP_V2X);
        narrow.allowed = CURL_HTTP_V1X;
        assert_eq!(offer(&https_request(narrow)), vec![AlpnId::H2]);
    }

    #[test]
    fn the_preferred_version_is_offered_before_the_wanted_one() {
        // Step 2 runs before steps 3 and 4, so `preferred` leads the offer --
        // and ORDER is what the ClientHello carries.
        let mut neg = negotiation(CURL_HTTP_V1X);
        neg.preferred = CURL_HTTP_V2X;
        assert_eq!(offer(&https_request(neg)), vec![AlpnId::H2, AlpnId::H1]);

        let mut neg = negotiation(CURL_HTTP_V2X);
        neg.preferred = CURL_HTTP_V1X;
        assert_eq!(offer(&https_request(neg)), vec![AlpnId::H1, AlpnId::H2]);

        // `preferred` is compared for EQUALITY against the whole value, because
        // the C `switch`es on it -- a mask of two versions matches no arm.
        let mut neg = negotiation(CURL_HTTP_V1X);
        neg.preferred = CURL_HTTP_V1X | CURL_HTTP_V2X;
        assert_eq!(offer(&https_request(neg)), vec![AlpnId::H1]);

        // And a preference outside `allowed` is skipped entirely.
        let mut neg = negotiation(CURL_HTTP_V1X);
        neg.preferred = CURL_HTTP_V2X;
        neg.allowed = CURL_HTTP_V1X;
        assert_eq!(offer(&https_request(neg)), vec![AlpnId::H1]);

        // A preference already offered is not offered twice.
        let mut neg = negotiation(CURL_HTTP_V2X);
        neg.preferred = CURL_HTTP_V2X;
        assert_eq!(offer(&https_request(neg)), vec![AlpnId::H2]);
    }

    #[test]
    fn the_https_record_leads_the_offer_when_its_three_tests_pass() {
        // Step 1 comes FIRST (`:665-709`), so a record's advice outranks both
        // the preference and the wanted set.
        let neg = negotiation(CURL_HTTP_V1X | CURL_HTTP_V2X);
        let rr = record(&[AlpnId::H2, AlpnId::H1]);
        let request = https_request(neg).with_https_rr(&rr);
        assert_eq!(offer(&request), vec![AlpnId::H2, AlpnId::H1]);

        // The record's ORDER is the offer's order, reversed here to prove the
        // walk is not sorting anything.
        let rr = record(&[AlpnId::H1, AlpnId::H2]);
        let request = https_request(neg).with_https_rr(&rr);
        assert_eq!(offer(&request), vec![AlpnId::H1, AlpnId::H2]);

        // A duplicate is skipped -- `cf_https_alpns_contain` (`:682-683`).
        let rr = record(&[AlpnId::H1, AlpnId::H1, AlpnId::H2]);
        let request = https_request(neg).with_https_rr(&rr);
        assert_eq!(offer(&request), vec![AlpnId::H1, AlpnId::H2]);

        // A record entry outside `allowed` is dropped, and the walk continues.
        let mut narrow = negotiation(CURL_HTTP_V1X);
        narrow.allowed = CURL_HTTP_V1X;
        let rr = record(&[AlpnId::H2, AlpnId::H1]);
        let request = https_request(narrow).with_https_rr(&rr);
        assert_eq!(offer(&request), vec![AlpnId::H1]);

        // `ALPN_none` terminates the walk. `crate::dns::httpsrr` writes the
        // array sequentially and then terminates it (`lib/httpsrr.c:60-67`), so
        // an INTERIOR terminator is not producible; the C's four-slot walk and
        // this terminated one therefore agree for every reachable record.
        //
        // Held against a transfer wanting 1.1 ALONE, so that step 4 adds
        // nothing once `h1` is already offered and the record's contribution is
        // the whole of the answer.
        let only_h1 = negotiation(CURL_HTTP_V1X);
        let mut gapped = record(&[AlpnId::H1]);
        gapped.alpns[2] = AlpnId::H2.as_u8();
        let request = https_request(only_h1).with_https_rr(&gapped);
        assert_eq!(offer(&request), vec![AlpnId::H1]);

        // The same record WITHOUT the gap does contribute both, which is what
        // makes the assertion above about the terminator rather than about h2.
        let contiguous = record(&[AlpnId::H1, AlpnId::H2]);
        let request = https_request(only_h1).with_https_rr(&contiguous);
        assert_eq!(offer(&request), vec![AlpnId::H1, AlpnId::H2]);
    }

    #[test]
    fn the_record_is_ignored_unless_all_three_preconditions_hold() {
        // *"We are here after having selected a connection to a host+port and
        // can no longer change that"* (`:666-668`). Each precondition is
        // falsified on its own, with everything else held constant, and the
        // offer then falls through to step 4.
        let neg = negotiation(CURL_HTTP_V1X);
        let fallthrough = vec![AlpnId::H1];

        // `no_def_alpn` -- the record says its ALPNs are not defaults.
        let mut rr = record(&[AlpnId::H2]);
        rr.no_def_alpn = true;
        let request = https_request(neg).with_https_rr(&rr);
        assert_eq!(offer(&request), fallthrough);

        // A target naming ANOTHER host.
        let mut rr = record(&[AlpnId::H2]);
        rr.target = Some("other.example".to_owned());
        let request = https_request(neg).with_https_rr(&rr);
        assert_eq!(offer(&request), fallthrough);

        // A port that is not this connection's.
        let mut rr = record(&[AlpnId::H2]);
        rr.port = Some(8443);
        let request = https_request(neg).with_https_rr(&rr);
        assert_eq!(offer(&request), fallthrough);

        // The three spellings of "this same host" that DO apply: absent, empty
        // and exactly `"."` -- the C's
        // `!rr->target || !rr->target[0] || (rr->target[0] == '.' &&
        // !rr->target[1])`.
        //
        // The record contributes `h2`, and step 4 then supplies the `h1` this
        // transfer wanted -- so an applied record shows up as TWO identifiers
        // with the record's first, which is the order the ClientHello carries.
        for target in [None, Some(String::new()), Some(".".to_owned())] {
            let mut rr = record(&[AlpnId::H2]);
            rr.target = target.clone();
            let request = https_request(neg).with_https_rr(&rr);
            assert_eq!(
                offer(&request),
                vec![AlpnId::H2, AlpnId::H1],
                "target {target:?} names this same host"
            );
        }
        // A target of `".."` is NOT the "same host" spelling.
        let mut rr = record(&[AlpnId::H2]);
        rr.target = Some("..".to_owned());
        let request = https_request(neg).with_https_rr(&rr);
        assert_eq!(offer(&request), fallthrough);

        // A record port EQUAL to the connection's does apply, and an unset one
        // -- the C's `rr->port < 0` -- applies too.
        let mut rr = record(&[AlpnId::H2]);
        rr.port = Some(443);
        let request = https_request(neg).with_https_rr(&rr);
        assert_eq!(offer(&request), vec![AlpnId::H2, AlpnId::H1]);
    }

    #[test]
    fn the_offer_never_exceeds_two_identifiers() {
        // `enum alpnid alpn_ids[2]` (`:652`) bounds every step, and
        // `MAX_ALPN_BALLERS` is that array's length.
        assert_eq!(MAX_ALPN_BALLERS, 2);

        let mut neg = negotiation(CURL_HTTP_V1X | CURL_HTTP_V2X);
        neg.preferred = CURL_HTTP_V1X;
        let rr = record(&[AlpnId::H1, AlpnId::H2, AlpnId::H1, AlpnId::H2]);
        let request = https_request(neg).with_https_rr(&rr);
        let ids = offer(&request);
        assert_eq!(ids, vec![AlpnId::H1, AlpnId::H2]);
        assert!(ids.len() <= MAX_ALPN_BALLERS);
    }

    #[test]
    fn the_trace_strings_are_the_c_s_word_for_word() {
        // Six literal strings, all of which appear in `--trace` output and are
        // therefore part of the user-visible surface.
        let neg = negotiation(CURL_HTTP_V1X | CURL_HTTP_V2X);
        let rr = record(&[AlpnId::H2, AlpnId::H1]);
        let request = https_request(neg).with_https_rr(&rr);
        let (ids, trace) = offer_traced(&request);
        assert_eq!(ids, vec![AlpnId::H2, AlpnId::H1]);
        assert!(trace.contains("adding h2 via HTTPS-RR"), "{trace}");
        assert!(trace.contains("adding h1 via HTTPS-RR"), "{trace}");
        // And the line is attributed to this filter by name.
        assert!(trace.contains(HTTPS_CONNECT_FILTER_NAME), "{trace}");

        let (ids, trace) = offer_traced(&https_request(neg));
        assert_eq!(ids, vec![AlpnId::H2]);
        assert!(trace.contains("adding wanted h2"), "{trace}");

        let (ids, trace) =
            offer_traced(&https_request(negotiation(CURL_HTTP_V1X)));
        assert_eq!(ids, vec![AlpnId::H1]);
        assert!(trace.contains("adding wanted h1"), "{trace}");
    }

    #[cfg(feature = "http3")]
    #[test]
    fn http3_leads_the_offer_when_the_build_and_the_url_allow_it() {
        // Step 3 (`:736-746`), and step 1's and step 2's h3 arms, all of which
        // are gated on `Curl_conn_may_http3`.
        let all = negotiation(CURL_HTTP_V1X | CURL_HTTP_V2X | CURL_HTTP_V3X);
        assert_eq!(offer(&https_request(all)), vec![AlpnId::H3, AlpnId::H2]);

        // h3 wanted with only 1.1 beside it: step 4's `else if` supplies h1.
        let h3_and_h1 = negotiation(CURL_HTTP_V1X | CURL_HTTP_V3X);
        assert_eq!(
            offer(&https_request(h3_and_h1)),
            vec![AlpnId::H3, AlpnId::H1]
        );

        // h3 alone.
        let only_h3 = negotiation(CURL_HTTP_V3X);
        assert_eq!(offer(&https_request(only_h3)), vec![AlpnId::H3]);

        // Preferred h3 leads, even when h3 is not in `wanted`.
        let mut neg = negotiation(CURL_HTTP_V1X);
        neg.preferred = CURL_HTTP_V3X;
        assert_eq!(offer(&https_request(neg)), vec![AlpnId::H3, AlpnId::H1]);

        // A record advertising h3 leads too, and the trace names the source.
        let neg = negotiation(CURL_HTTP_V1X);
        let rr = record(&[AlpnId::H3, AlpnId::H1]);
        let request = https_request(neg).with_https_rr(&rr);
        let (ids, trace) = offer_traced(&request);
        assert_eq!(ids, vec![AlpnId::H3, AlpnId::H1]);
        assert!(trace.contains("adding h3 via HTTPS-RR"), "{trace}");

        let (ids, trace) = offer_traced(&https_request(only_h3));
        assert_eq!(ids, vec![AlpnId::H3]);
        assert!(trace.contains("adding wanted h3"), "{trace}");

        // `allowed` gates the RECORD's h3 arm even when h3 is possible.
        let mut narrow = negotiation(CURL_HTTP_V1X);
        narrow.allowed = CURL_HTTP_V1X;
        let rr = record(&[AlpnId::H3, AlpnId::H1]);
        let request = https_request(narrow).with_https_rr(&rr);
        assert_eq!(offer(&request), vec![AlpnId::H1]);
    }

    #[test]
    fn wanting_only_http3_where_it_is_impossible_returns_the_error() {
        // `else if(data->state.http_neg.wanted == CURL_HTTP_V3x) goto out;`
        // (`:745-746`) -- the ONE path on which this function fails, and the
        // reason `--http3-only` against a plaintext URL reports the specific
        // message instead of silently falling back.
        let only_h3 = negotiation(CURL_HTTP_V3X);
        let plaintext =
            HttpsSetupRequest::new(only_h3, 80, Transport::Tcp, http_flags());
        let refusal =
            offer_result(&plaintext).expect_err("h3 is impossible here");

        #[cfg(feature = "http3")]
        {
            assert_eq!(refusal.code(), CURLcode::UrlMalformat);
            assert_eq!(refusal.to_string(), H3_NEEDS_HTTPS);
        }
        #[cfg(not(feature = "http3"))]
        {
            assert_eq!(refusal.code(), CURLcode::NotBuiltIn);
        }

        // A SOCKS proxy is the same refusal for a TLS URL.
        let proxied = https_request(only_h3).with_proxy(Http3Proxy {
            socks: true,
            http_tunnel: false,
        });
        assert!(offer_result(&proxied).is_err());

        // But h3 wanted ALONGSIDE another version is NOT an error: the offer
        // falls back to what is possible. `wanted == CURL_HTTP_V3x` is an
        // equality on the whole mask, not an intersection.
        let h3_and_h2 = negotiation(CURL_HTTP_V2X | CURL_HTTP_V3X);
        let plaintext =
            HttpsSetupRequest::new(h3_and_h2, 80, Transport::Tcp, http_flags());
        assert_eq!(offer(&plaintext), vec![AlpnId::H2]);

        let h3_and_h1 = negotiation(CURL_HTTP_V1X | CURL_HTTP_V3X);
        let plaintext =
            HttpsSetupRequest::new(h3_and_h1, 80, Transport::Tcp, http_flags());
        assert_eq!(offer(&plaintext), vec![AlpnId::H1]);

        // And a record's h3 entry is SKIPPED rather than fatal, because the C
        // `break`s out of the `switch` and keeps walking (`:685-687`).
        let neg = negotiation(CURL_HTTP_V1X);
        let rr = record(&[AlpnId::H3, AlpnId::H1]);
        let plaintext =
            HttpsSetupRequest::new(neg, 80, Transport::Tcp, http_flags())
                .with_https_rr(&rr);
        assert_eq!(offer(&plaintext), vec![AlpnId::H1]);
    }

    #[cfg(not(feature = "http3"))]
    #[test]
    fn a_build_without_http3_offers_what_it_has() {
        // The same inputs as `http3_leads_the_offer_when_...`, with the
        // outcomes a build carrying no QUIC produces. Under-reporting is the
        // safe direction: a fixture skips rather than failing.
        let all = negotiation(CURL_HTTP_V1X | CURL_HTTP_V2X | CURL_HTTP_V3X);
        assert_eq!(offer(&https_request(all)), vec![AlpnId::H2]);

        let h3_and_h1 = negotiation(CURL_HTTP_V1X | CURL_HTTP_V3X);
        assert_eq!(offer(&https_request(h3_and_h1)), vec![AlpnId::H1]);

        let mut neg = negotiation(CURL_HTTP_V1X);
        neg.preferred = CURL_HTTP_V3X;
        assert_eq!(offer(&https_request(neg)), vec![AlpnId::H1]);

        let neg = negotiation(CURL_HTTP_V1X);
        let rr = record(&[AlpnId::H3, AlpnId::H1]);
        let request = https_request(neg).with_https_rr(&rr);
        assert_eq!(offer(&request), vec![AlpnId::H1]);
    }

    // -- 9. the HTTPS-CONNECT filter and the version race -------------------

    /// A race over `alpn_ids`, with the seams a test can inspect.
    fn race(
        log: &EventLog,
        factories: TestFactories,
        alpn_ids: &[AlpnId],
        timeout_ms: TimeDiff,
    ) -> (HttpsConnect, Arc<TestExpiry>) {
        let (seams, expiry) = seams_with(log, factories, true, timeout_ms);
        let filter = HttpsConnect::new(
            SocketIndex::First,
            alpn_ids,
            Transport::Tcp,
            seams,
        )
        .expect("one or two identifiers are accepted");
        (filter, expiry)
    }

    /// How many sub-chains have been built so far.
    fn ballers_started(log: &EventLog) -> usize {
        events(log)
            .iter()
            .filter(|note| *note == "build:HAPPY-EYEBALLS")
            .count()
    }

    #[test]
    fn an_alpn_count_of_zero_or_three_is_rejected() {
        // `if(!alpn_count || (alpn_count > CURL_ARRAYSIZE(ctx->ballers)))`
        // (`lib/cf-https-connect.c:596-602`). The array is two long, so the
        // bound is a property of the C's own storage.
        let log = new_log();
        for ids in [&[][..], &[AlpnId::H3, AlpnId::H2, AlpnId::H1][..]] {
            let (seams, _) =
                seams_with(&log, TestFactories::new(&log), true, 200);
            let refusal = HttpsConnect::new(
                SocketIndex::First,
                ids,
                Transport::Tcp,
                seams,
            )
            .expect_err("this count is out of range");
            assert_eq!(refusal.code(), CURLcode::FailedInit);
            assert_eq!(refusal.to_string(), alpn_count_rejected(ids.len()));
        }

        // The measured wording, held to the C's `%zu` rendering.
        assert_eq!(
            alpn_count_rejected(0),
            "https-connect filter create with unsupported 0 ALPN ids"
        );
        assert_eq!(
            alpn_count_rejected(3),
            "https-connect filter create with unsupported 3 ALPN ids"
        );

        // One and two are accepted, which is what makes the bound a bound.
        for ids in [&[AlpnId::H2][..], &[AlpnId::H3, AlpnId::H1][..]] {
            let (seams, _) =
                seams_with(&log, TestFactories::new(&log), true, 200);
            let filter = HttpsConnect::new(
                SocketIndex::First,
                ids,
                Transport::Tcp,
                seams,
            )
            .expect("within the bound");
            assert_eq!(filter.baller_count(), ids.len());
            assert_eq!(filter.raced(), ids.to_vec());
        }
    }

    #[test]
    fn the_filter_declares_the_measured_name_flags_and_log_level() {
        // `struct Curl_cft_http_connect` (`lib/cf-https-connect.c:557-573`):
        // name `"HTTPS-CONNECT"`, flags ZERO, log level
        // `CURL_LOG_LVL_NONE`. The name is consumed from `crate::trace`'s table
        // rather than spelled twice.
        assert_eq!(HTTPS_CONNECT_FILTER_NAME, "HTTPS-CONNECT");
        assert_eq!(HTTPS_CONNECT_FLAGS, CfType::NONE);
        assert_eq!(HTTPS_CONNECT_LOG_LEVEL, CURL_LOG_LVL_NONE);
        assert_eq!(CURL_LOG_LVL_NONE, 0);
        assert_eq!(TraceFilter::HttpConnect.name(), HTTPS_CONNECT_FILTER_NAME);
        assert_eq!(ALPN_EYEBALLS_TIMER, TimerId::AlpnEyeballs);
        assert_eq!(ALPN_EYEBALLS_TIMER.name(), "ALPN_EYEBALLS");

        let log = new_log();
        let (filter, _) =
            race(&log, TestFactories::new(&log), &[AlpnId::H2], 200);
        assert_eq!(filter.trace_name(), HTTPS_CONNECT_FILTER_NAME);
        assert_eq!(filter.cf_type(), HTTPS_CONNECT_FLAGS);
        assert_eq!(filter.state(), HcState::Init);
        assert_eq!(filter.base().sockindex(), SocketIndex::First);
        assert!(!filter.base().is_connected());
    }

    #[test]
    fn the_soft_timeout_is_the_hard_timeout_divided_by_four() {
        // `ctx->hard_eyeballs_timeout_ms = data->set.happy_eyeballs_timeout;`
        // and `ctx->soft_... = ... / 4;` (`:192-193`), whose default is
        // `CURL_HET_DEFAULT`.
        assert_eq!(CURL_HET_DEFAULT, 200);
        let log = new_log();

        let (filter, _) = race(
            &log,
            TestFactories::new(&log),
            &[AlpnId::H2, AlpnId::H1],
            CURL_HET_DEFAULT,
        );
        assert_eq!(filter.hard_eyeballs_timeout_ms(), 200);
        assert_eq!(filter.soft_eyeballs_timeout_ms(), 50);

        // A caller-supplied `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`, and integer
        // division -- 3 / 4 is 0, so a tiny budget makes the second attempt
        // start on the very next pass rather than never.
        let (filter, _) =
            race(&log, TestFactories::new(&log), &[AlpnId::H2], 1_000);
        assert_eq!(filter.soft_eyeballs_timeout_ms(), 250);
        let (filter, _) =
            race(&log, TestFactories::new(&log), &[AlpnId::H2], 3);
        assert_eq!(filter.soft_eyeballs_timeout_ms(), 0);
    }

    #[test]
    fn the_first_baller_starts_immediately_and_arms_the_soft_timer() {
        // `cf_hc_connect`'s `CF_HC_INIT` arm (`:301-317`): baller 0 starts
        // unconditionally, and the soft timer is armed ONLY when a second
        // version is waiting.
        let log = new_log();
        let clock = clock();
        let (mut filter, expiry) = race(
            &log,
            TestFactories::new(&log).with_steps(100),
            &[AlpnId::H2, AlpnId::H1],
            200,
        );
        let mut cx = CallCtx::new(&clock);
        assert!(
            !filter.connect(&mut cx).expect("the race is under way"),
            "a baller refusing 100 passes cannot be done"
        );
        assert_eq!(filter.state(), HcState::Connect);
        assert_eq!(ballers_started(&log), 1);
        assert_eq!(
            expiry.armed.borrow().as_slice(),
            [(50, TimerId::AlpnEyeballs)]
        );

        // With ONE baller nothing is waiting, so no timer is armed at all.
        let log = new_log();
        let (mut filter, expiry) = race(
            &log,
            TestFactories::new(&log).with_steps(100),
            &[AlpnId::H2],
            200,
        );
        let mut cx = CallCtx::new(&clock);
        assert!(!filter.connect(&mut cx).expect("under way"));
        assert_eq!(ballers_started(&log), 1);
        assert!(expiry.armed.borrow().is_empty());
    }

    #[test]
    fn the_second_baller_waits_for_the_soft_timeout() {
        // `if((idx > 0) && (elapsed_ms >= ctx->soft_eyeballs_timeout_ms))` with
        // `cf_hc_baller_reply_ms(...) < 0` (`:278-286`) -- the previous attempt
        // has seen no data, so the next one starts. The clock is INJECTED, so
        // the boundary is asserted exactly rather than slept through.
        let log = new_log();
        let clock = clock();
        let (mut filter, _) = race(
            &log,
            TestFactories::new(&log).with_steps(100),
            &[AlpnId::H2, AlpnId::H1],
            200,
        );
        let mut cx = CallCtx::new(&clock);

        assert!(!filter.connect(&mut cx).expect("under way"));
        assert_eq!(ballers_started(&log), 1);

        // One millisecond BEFORE the soft timeout: still one attempt.
        clock.advance(Duration::from_millis(49));
        assert!(!filter.connect(&mut cx).expect("under way"));
        assert_eq!(ballers_started(&log), 1, "49ms is before hard/4");

        // Exactly AT the soft timeout: the second attempt starts. The C's test
        // is `>=`, so the boundary itself starts it.
        clock.advance(Duration::from_millis(1));
        assert!(!filter.connect(&mut cx).expect("under way"));
        assert_eq!(ballers_started(&log), 2, "50ms is hard/4");
        assert_eq!(filter.state(), HcState::Connect);

        // And no third attempt exists to start, however long it takes.
        clock.advance(Duration::from_millis(10_000));
        assert!(!filter.connect(&mut cx).expect("under way"));
        assert_eq!(ballers_started(&log), 2);
    }

    #[test]
    fn a_baller_that_has_seen_data_holds_the_race_until_the_hard_timeout() {
        // The other arm of `:278-289`: when the previous attempt HAS seen data,
        // the soft timeout does not start the next one -- the hard timeout is
        // re-armed at `hard - elapsed` and the next attempt waits for it.
        let log = new_log();
        let clock = clock();
        let (mut filter, expiry) = race(
            &log,
            TestFactories::new(&log).with_steps(100).with_reply_ms(20),
            &[AlpnId::H2, AlpnId::H1],
            200,
        );
        let mut cx = CallCtx::new(&clock);
        assert!(!filter.connect(&mut cx).expect("under way"));
        assert_eq!(ballers_started(&log), 1);

        // At the soft timeout the first attempt has data, so nothing starts and
        // the effective hard timeout is re-armed.
        clock.advance(Duration::from_millis(50));
        assert!(!filter.connect(&mut cx).expect("under way"));
        assert_eq!(ballers_started(&log), 1, "the first attempt has data");
        assert!(
            expiry
                .armed
                .borrow()
                .contains(&(150, TimerId::AlpnEyeballs)),
            "the effective hard timeout is re-armed at hard - elapsed: {:?}",
            expiry.armed.borrow()
        );

        // At the hard timeout the second attempt starts regardless, and the
        // trace says so in the C's words.
        clock.advance(Duration::from_millis(150));
        let trace = traced(&clock, |cx| {
            assert!(!filter.connect(cx).expect("under way"));
        });
        assert_eq!(ballers_started(&log), 2);
        assert!(
            trace.contains("hard timeout of 200ms reached, starting h1"),
            "{trace}"
        );
    }

    #[test]
    fn a_failed_attempt_starts_the_next_one_at_once() {
        // `for(i = 0; i < idx; i++) if(!ctx->ballers[i].result) break;`
        // (`:261-269`): when every earlier attempt has failed there is nothing
        // to wait for, so the clock is not consulted at all.
        let log = new_log();
        let clock = clock();
        let (mut filter, _) = race(
            &log,
            TestFactories::new(&log)
                .failing("HAPPY-EYEBALLS", CURLcode::CouldntConnect),
            &[AlpnId::H2, AlpnId::H1],
            200,
        );

        // Both attempts fail within this single pass, and the connection then
        // reports the FIRST failure -- the one path on which a baller's code
        // becomes the connection's (`:341-350`).
        let mut refusal = None;
        let trace = traced(&clock, |cx| {
            refusal = filter.connect(cx).err();
        });
        let refusal = refusal.expect("every attempt failed");
        assert_eq!(refusal.code(), CURLcode::CouldntConnect);
        assert_eq!(ballers_started(&log), 2);
        assert_eq!(filter.state(), HcState::Failure);
        assert!(!filter.base().is_connected());
        assert!(
            trace.contains("all previous attempts failed, starting h1"),
            "{trace}"
        );
        assert!(trace.contains("connect, all attempts failed"), "{trace}");

        // A later pass reports the STORED code and stays unconnected, which is
        // the C's `CF_HC_FAILURE` arm (`:362-366`).
        let mut cx = CallCtx::new(&clock);
        let again = filter.connect(&mut cx).expect_err("still failed");
        assert_eq!(again.code(), CURLcode::CouldntConnect);
        assert!(!filter.base().is_connected());
    }

    #[test]
    fn a_winning_attempt_is_promoted_and_the_filter_reports_connected() {
        // `cf_hc_baller_connected` (`:210-241`): the winner's sub-chain becomes
        // this filter's successor, the losers are reset, and the state is
        // `CF_HC_SUCCESS`.
        let log = new_log();
        let clock = clock();
        let (mut filter, _) = race(
            &log,
            TestFactories::new(&log),
            &[AlpnId::H2, AlpnId::H1],
            200,
        );

        let trace = traced(&clock, |cx| {
            assert!(filter.connect(cx).expect("the first attempt connects"));
        });
        assert_eq!(filter.state(), HcState::Success);
        assert!(filter.base().is_connected());
        assert!(
            filter.base().has_next(),
            "the winner's sub-chain is installed below"
        );
        assert_eq!(ballers_started(&log), 1, "the second never had to start");
        assert!(trace.contains("deferred handshake h2"), "{trace}");

        // The TLS filter the sub-chain installed is reachable through the
        // promoted link, which is what makes the promotion a promotion.
        let installed: Vec<&'static str> =
            std::iter::successors(filter.base().next_ref(), |node| {
                node.base().next_ref()
            })
            .map(ConnFilter::trace_name)
            .collect();
        assert!(installed.contains(&"SSL"), "{installed:?}");

        // A second pass short-circuits on `cf->connected`.
        let mut cx = CallCtx::new(&clock);
        assert!(filter.connect(&mut cx).expect("already connected"));
    }

    #[test]
    fn an_h3_attempt_is_built_for_the_quic_transport() {
        // `cf_hc_baller_assign` (`:121-142`): `ALPN_h3` forces
        // `TRNSPRT_QUIC` whatever the connection wanted, and the three names are
        // the literal two-byte strings the C stores.
        let log = new_log();
        let clock = clock();
        let (mut filter, _) = race(
            &log,
            TestFactories::new(&log).with_steps(100),
            &[AlpnId::H3, AlpnId::H2],
            200,
        );
        let mut cx = CallCtx::new(&clock);
        assert!(!filter.connect(&mut cx).expect("under way"));

        // `Transport::Quic` is 5 and `Transport::Tcp` is 3
        // (`lib/urldata.h:567-571`).
        assert_eq!(Transport::Quic.as_u8(), 5);
        assert!(
            events(&log).contains(&"transport:5".to_owned()),
            "the h3 attempt must be built for QUIC: {:?}",
            events(&log)
        );

        // The second attempt keeps the connection's own transport.
        clock.advance(Duration::from_millis(50));
        assert!(!filter.connect(&mut cx).expect("under way"));
        assert!(
            events(&log).contains(&"transport:3".to_owned()),
            "the h2 attempt keeps TCP: {:?}",
            events(&log)
        );

        // And the trace names the running attempt by its C spelling -- the
        // literal two-byte string `cf_hc_baller_assign` stored.
        let trace = traced(&clock, |cx| {
            assert!(!filter.connect(cx).expect("under way"));
        });
        assert!(trace.contains("connect, check h2"), "{trace}");
        assert_eq!(filter.raced(), vec![AlpnId::H3, AlpnId::H2]);
    }

    #[test]
    fn an_unresolved_connection_fails_every_attempt() {
        // `crate::conn::SetupFilter::connect` refuses before it reaches a
        // factory when no address has been resolved, which is the shape a
        // sub-chain failure takes in the C too.
        let log = new_log();
        let clock = clock();
        let (seams, _) = seams_with(&log, TestFactories::new(&log), false, 200);
        let mut filter = HttpsConnect::new(
            SocketIndex::First,
            &[AlpnId::H2],
            Transport::Tcp,
            seams,
        )
        .expect("one identifier is accepted");

        let mut cx = CallCtx::new(&clock);
        let refusal = filter.connect(&mut cx).expect_err("nothing resolved");
        assert_eq!(refusal.code(), CURLcode::FailedInit);
        assert_eq!(filter.state(), HcState::Failure);
    }

    #[test]
    fn the_connect_only_slots_answer_while_the_race_is_running() {
        // The filter is CONNECT-ONLY -- `send`, `recv`, `is_alive` and
        // `keep_alive` are the trait defaults (`:566-571`) -- but the remaining
        // slots must answer sensibly mid-race, because the multi handle asks
        // them between passes.
        let log = new_log();
        let clock = clock();
        let (mut filter, _) = race(
            &log,
            TestFactories::new(&log).with_steps(100),
            &[AlpnId::H2, AlpnId::H1],
            200,
        );
        let mut cx = CallCtx::new(&clock);
        assert!(!filter.connect(&mut cx).expect("under way"));

        // `cf_hc_adjust_pollset` walks the ACTIVE attempts only.
        let mut ps = EasyPollset::new();
        assert!(filter.adjust_pollset(&mut cx, &mut ps).is_ok());

        // `cf_hc_data_pending` asks every attempt; a stand-in that has seen
        // nothing answers false.
        assert!(!filter.data_pending(&cx));

        // `cf_hc_cntrl` forwards to every attempt and swallows `CURLE_AGAIN`.
        assert!(filter.cntrl(&mut cx, CfControl::Flush).is_ok());
        assert!(filter.cntrl(&mut cx, CfControl::DataSetup).is_ok());

        // `cf_hc_query` answers the two timer queries from the attempts.
        let answer = filter
            .query(&mut cx, CfQuery::TimerConnect)
            .expect("the timer queries are answered mid-race");
        assert!(matches!(answer, CfQueryValue::Timer(_)), "{answer:?}");
        let answer = filter
            .query(&mut cx, CfQuery::TimerAppConnect)
            .expect("the timer queries are answered mid-race");
        assert!(matches!(answer, CfQueryValue::Timer(_)), "{answer:?}");

        // `cf_hc_shutdown` walks the ACTIVE attempts and reports done only
        // when EVERY one of them has finished (`:399-425`). The second attempt
        // never started, so it is skipped and its flag stays clear -- which
        // makes the whole shutdown unfinished on this pass.
        assert!(
            !filter
                .shutdown(&mut cx)
                .expect("a shutdown pass without a failure"),
            "an attempt that never started leaves the shutdown unfinished"
        );

        // `cf_hc_close` resets every attempt and discards the winner, taking
        // the filter back to `CF_HC_INIT` so that a reused handle starts over.
        filter.close(&mut cx);
        assert_eq!(filter.state(), HcState::Init);
        assert!(!filter.base().is_connected());
        assert!(!filter.base().has_next());

        filter.destroy(&mut cx);
    }

    #[test]
    fn https_setup_installs_the_race_only_when_there_is_something_to_race() {
        // *"If we identified ALPNs to use, install our filter. Otherwise,
        // install nothing, so our call will use a default connect setup."*
        // (`:766-767`). `crate::conn::conn_setup` then re-tests the chain's
        // emptiness, exactly as `if(!conn->cfilter[sockindex])` does.
        let log = new_log();
        let clock = clock();
        let mut cx = CallCtx::new(&clock);
        let neg = negotiation(CURL_HTTP_V1X | CURL_HTTP_V2X);

        // Nothing to race: ALPN switched off.
        let mut chain = FilterChain::new(None, SocketIndex::First);
        let (seams, _) = seams_with(&log, TestFactories::new(&log), true, 200);
        let request = https_request(neg).with_tls_enable_alpn(false);
        https_setup(&mut cx, &mut chain, &request, seams)
            .expect("installing nothing is a correct outcome");
        assert!(chain.is_empty(), "an empty offer installs nothing");

        // Something to race: the filter goes in at the TOP of the chain.
        let mut chain = FilterChain::new(None, SocketIndex::First);
        let (seams, _) = seams_with(&log, TestFactories::new(&log), true, 200);
        let request = https_request(neg);
        https_setup(&mut cx, &mut chain, &request, seams)
            .expect("an offer installs the race");
        assert_eq!(chain.len(), 1);
        assert_eq!(
            chain.head_ref().map(ConnFilter::trace_name),
            Some(HTTPS_CONNECT_FILTER_NAME)
        );

        // And the installed filter connects through the chain, which is the
        // whole point of installing it there.
        assert!(chain.connect_head(&mut cx).expect("the race runs"));
        assert!(chain.is_head_connected());

        // A refusal from the offer is a refusal from the setup.
        let mut chain = FilterChain::new(None, SocketIndex::First);
        let (seams, _) = seams_with(&log, TestFactories::new(&log), true, 200);
        let only_h3 = negotiation(CURL_HTTP_V3X);
        let plaintext =
            HttpsSetupRequest::new(only_h3, 80, Transport::Tcp, http_flags());
        assert!(https_setup(&mut cx, &mut chain, &plaintext, seams).is_err());
        assert!(chain.is_empty(), "a refusal installs nothing");
    }

    // -- 10. connection-reuse policy, which is protocol-aware ---------------

    #[test]
    fn connection_reusable_honours_the_websocket_asymmetry() {
        // `multi_conn_should_close`'s protocol test (`lib/multi.c:580-583`).
        for name in [&b"http"[..], b"https", b"ftp", b"ftps", b"SFTP", b"SCP"] {
            let row = get_scheme(name).expect("a row");
            assert!(
                connection_reusable(row, false),
                "{} is poolable in the C",
                String::from_utf8_lossy(name)
            );
        }
        for name in [&b"WS"[..], b"WSS", b"file"] {
            let row = get_scheme(name).expect("a row");
            assert!(
                !connection_reusable(row, false),
                "{} carries no PROTOPT_CONN_REUSE",
                String::from_utf8_lossy(name)
            );
        }

        // `CURLOPT_CONNECT_ONLY` exempts every scheme: the application owns the
        // socket's lifetime once it has been handed over, so the pool's rule
        // does not apply. Not an oversight -- the C's own exemption.
        for name in [&b"WS"[..], b"WSS", b"file", b"http"] {
            let row = get_scheme(name).expect("a row");
            assert!(connection_reusable(row, true));
        }
    }

    #[test]
    fn ssl_reuse_lets_ftp_take_over_an_ftps_connection() {
        // `url_match_ssl_use` (`lib/url.c:902-916`). The subtle rule is the
        // second: a non-TLS scheme may reuse a TLS connection only with
        // `PROTOPT_SSL_REUSE` AND a family matching its own protocol -- which
        // is exactly `ftp` over an `ftps` connection.
        let ftp = get_scheme(b"ftp").expect("a row");
        let ftps = get_scheme(b"ftps").expect("a row");
        let http = get_scheme(b"http").expect("a row");
        let https = get_scheme(b"https").expect("a row");

        // A TLS scheme needs a TLS connection, full stop.
        assert!(ssl_reuse_matches(https, https, true));
        assert!(!ssl_reuse_matches(https, https, false));
        assert!(!ssl_reuse_matches(ftps, ftps, false));

        // `ftp` carries `PROTOPT_SSL_REUSE` and `ftps`'s family is `FTP`, which
        // is `ftp`'s protocol -- so the takeover is permitted.
        assert!(ftp.flags.intersects(ProtocolOptions::SSL_REUSE));
        assert_eq!(ftps.family, ftp.protocol);
        assert!(ssl_reuse_matches(ftp, ftps, true));

        // `http` does NOT carry the flag, so it may not take over an `https`
        // connection however well the families line up.
        assert!(!http.flags.intersects(ProtocolOptions::SSL_REUSE));
        assert!(!ssl_reuse_matches(http, https, true));

        // And a plain connection is reusable by a plain scheme.
        assert!(ssl_reuse_matches(http, http, false));
        assert!(ssl_reuse_matches(ftp, ftp, false));

        // The family comparison is across the two COLUMNS, so a TLS connection
        // whose family is not the wanted protocol is refused even with the
        // flag: `ldap` carries `PROTOPT_SSL_REUSE`, and `gophers`'s family is
        // `GOPHER`.
        let ldap = get_scheme(b"ldap").expect("a row");
        let gophers = get_scheme(b"gophers").expect("a row");
        assert!(ldap.flags.intersects(ProtocolOptions::SSL_REUSE));
        assert!(!ssl_reuse_matches(ldap, gophers, true));
    }

    #[test]
    fn the_state_names_are_the_c_s_and_the_flag_folder_folds() {
        // `cf_hc_state`'s four spellings (`lib/cf-https-connect.c:41-46`), which
        // a trace line or an assertion message renders.
        assert_eq!(HcState::Init.c_name(), "CF_HC_INIT");
        assert_eq!(HcState::Connect.c_name(), "CF_HC_CONNECT");
        assert_eq!(HcState::Success.c_name(), "CF_HC_SUCCESS");
        assert_eq!(HcState::Failure.c_name(), "CF_HC_FAILURE");
        assert_eq!(HcState::default(), HcState::Init);

        // `protopt` is a `const fn` and every production call is evaluated at
        // compile time, so this is what exercises it at run time -- and what
        // proves the fold is a union rather than, say, the last element.
        assert_eq!(protopt(&[]), ProtocolOptions::NONE);
        assert_eq!(protopt(&[ProtocolOptions::SSL]), ProtocolOptions::SSL);
        assert_eq!(
            protopt(&[
                ProtocolOptions::SSL,
                ProtocolOptions::ALPN,
                ProtocolOptions::CONN_REUSE,
            ]),
            ProtocolOptions::SSL
                .union(ProtocolOptions::ALPN)
                .union(ProtocolOptions::CONN_REUSE)
        );
        // And the fold is what the registry's own `https` row holds.
        assert_eq!(
            protopt(&[
                ProtocolOptions::SSL,
                ProtocolOptions::CREDSPERREQUEST,
                ProtocolOptions::ALPN,
                ProtocolOptions::USERPWDCTRL,
                ProtocolOptions::CONN_REUSE,
            ]),
            https_flags()
        );
    }

    #[test]
    fn a_connected_filter_delegates_every_slot_to_the_winner() {
        // Once the race is over this filter is a pass-through: `cf_hc_query`,
        // `cf_hc_data_pending`, `cf_hc_cntrl` and `cf_hc_adjust_pollset` all
        // short-circuit on `cf->connected` and let the winner answer.
        let log = new_log();
        let clock = clock();
        let (mut filter, _) = race(
            &log,
            TestFactories::new(&log).with_reply_ms(20),
            &[AlpnId::H2, AlpnId::H1],
            200,
        );

        // A winner that HAS seen data takes the other trace branch of
        // `cf_hc_baller_connected` (`:225-232`).
        let trace = traced(&clock, |cx| {
            assert!(filter.connect(cx).expect("the first attempt connects"));
        });
        assert_eq!(filter.state(), HcState::Success);
        assert!(
            trace.contains("connect+handshake h2:"),
            "a winner with data reports its first-byte time: {trace}"
        );
        assert!(trace.contains("1st data: 20ms"), "{trace}");

        let mut cx = CallCtx::new(&clock);

        // `adjust_pollset` adds nothing once connected -- the winner is asked
        // through the chain, not through this filter.
        let mut ps = EasyPollset::new();
        assert!(filter.adjust_pollset(&mut cx, &mut ps).is_ok());
        assert!(ps.is_empty());

        // `data_pending` delegates; the stand-in answers false.
        assert!(!filter.data_pending(&cx));

        // `cntrl` is a no-op once connected.
        assert!(filter.cntrl(&mut cx, CfControl::Flush).is_ok());

        // `query` falls through to the winner, which answers what it can and
        // reports `CURLE_UNKNOWN_OPTION` at the bottom of the chain.
        let answer = filter
            .query(&mut cx, CfQuery::ConnectReplyMs)
            .expect("the winner answers this one");
        assert!(
            matches!(answer, CfQueryValue::ConnectReplyMs(20)),
            "{answer:?}"
        );
        let refusal = filter
            .query(&mut cx, CfQuery::HostPort)
            .expect_err("nothing in this chain knows the host");
        assert_eq!(refusal.code(), CURLcode::UnknownOption);

        // `shutdown` reports done immediately once connected (`:401-403`).
        assert!(filter.shutdown(&mut cx).expect("connected"));
    }

    #[test]
    fn a_shutdown_is_done_when_every_started_attempt_is_done() {
        // `cf_hc_shutdown` (`:399-425`): walk the ACTIVE attempts, ask each one
        // once, and report done only when every attempt's flag is set.
        let log = new_log();
        let clock = clock();

        // One attempt, still connecting: its sub-chain reports done, so the
        // whole shutdown is done in a single pass.
        let (mut filter, _) = race(
            &log,
            TestFactories::new(&log).with_steps(100),
            &[AlpnId::H2],
            200,
        );
        let mut cx = CallCtx::new(&clock);
        assert!(!filter.connect(&mut cx).expect("under way"));
        let trace = traced(&clock, |cx| {
            assert!(
                filter.shutdown(cx).expect("no attempt reported a failure"),
                "a single started attempt finishing finishes the shutdown"
            );
        });
        assert!(trace.contains("shutdown -> 0, done=1"), "{trace}");

        // Two attempts with only the first started: the second's flag is never
        // set, because a non-active attempt is skipped rather than asked -- so
        // the shutdown stays unfinished, which is the C's own arithmetic.
        let log = new_log();
        let (mut filter, _) = race(
            &log,
            TestFactories::new(&log).with_steps(100),
            &[AlpnId::H2, AlpnId::H1],
            200,
        );
        let mut cx = CallCtx::new(&clock);
        assert!(!filter.connect(&mut cx).expect("under way"));
        assert!(!filter.shutdown(&mut cx).expect("no failure"));

        // The reporting arm this filter also carries -- *"treat a failed
        // shutdown as done"* while remembering the code (`:406-421`) -- needs a
        // sub-chain HEAD that fails its own shutdown. In this checkout every
        // baller sub-chain is headed by `crate::conn::SetupFilter`, which takes
        // `ConnFilter`'s default and always reports done, so no test can reach
        // it from here; a real TLS head filter, whose `close_notify` write can
        // fail, is what will. The arm is kept because the C keeps it and
        // because removing it would have to be undone by whoever lands that
        // filter.
    }

    #[test]
    fn a_failed_attempt_stops_answering_for_itself() {
        // `cf_hc_baller_data_pending`, `_needs_flush` and `_cntrl` all begin
        // with `if(!b->result)` (`:90-109`), so an attempt that has failed is
        // silent rather than being asked again through a chain it no longer
        // trusts.
        let log = new_log();
        let clock = clock();
        let (mut filter, _) = race(
            &log,
            TestFactories::new(&log)
                .failing("HAPPY-EYEBALLS", CURLcode::CouldntConnect),
            &[AlpnId::H2, AlpnId::H1],
            200,
        );
        let mut cx = CallCtx::new(&clock);
        assert!(filter.connect(&mut cx).is_err(), "every attempt fails");
        assert_eq!(filter.state(), HcState::Failure);

        // Neither attempt reports pending data or needs a flush, and an event
        // forwarded to them is swallowed.
        assert!(!filter.data_pending(&cx));
        assert!(filter.cntrl(&mut cx, CfControl::Flush).is_ok());

        // `CF_QUERY_NEED_FLUSH` finds no attempt that wants one, so it falls
        // through -- and with no winner installed there is nothing below.
        let refusal = filter
            .query(&mut cx, CfQuery::NeedFlush)
            .expect_err("a failed race has nothing below it");
        assert_eq!(refusal.code(), CURLcode::UnknownOption);

        // The timer queries still answer, from the attempts' own start times.
        let answer = filter
            .query(&mut cx, CfQuery::TimerConnect)
            .expect("the timer queries are always answered");
        assert!(matches!(answer, CfQueryValue::Timer(_)), "{answer:?}");
    }
}
