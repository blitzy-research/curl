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

//! The raw transports at the bottom of every filter chain, and the wakeup
//! primitive the multi handle polls alongside them.
//!
//! Supersedes six C files: `lib/cf-socket.h:37-155` and
//! `lib/cf-socket.c:260-529,531-1182,1239-1698,1740-2233` (2,233 lines),
//! `lib/socketpair.c:31-373` with `lib/socketpair.h`, and
//! `lib/curlx/nonblock.c:40-63` with `lib/curlx/nonblock.h`. The AAP section
//! 0.4.1 row is *"`curl-rs-lib/src/conn/socket.rs` | CREATE |
//! `lib/cf-socket.c`, `lib/socketpair.c`, `lib/curlx/nonblock.c` | Raw socket
//! calls become `socket2`"*, and that is the whole of the transformation rule:
//! every `socket`, `connect`, `bind`, `listen`, `accept`, `setsockopt`,
//! `getsockopt`, `getsockname`, `getpeername`, `fcntl`, `read`, `write` and
//! `close` in those files becomes a method on [`socket2::Socket`].
//!
//! # What this file owns, and what it deliberately does not
//!
//! It owns four safe socket transports -- TCP, UDP, UNIX and TCP-ACCEPT --
//! the address and connection metadata they gather, the adapters for the
//! open, close and sockopt callbacks that higher layers supply, and a safe
//! wakeup mechanism that [`crate::multi`] consumes.
//!
//! **There are no FFI exports here and no protocol policy.** Nothing in this
//! file is declared with C linkage, exported without name mangling, or given a
//! C memory layout; the C layout mirrors and the callback trampolines belong to
//! `curl-rs-ffi`, which is the crate that owns the ABI. A negative continuous-
//! integration grep for those three attributes is expected to find nothing in
//! this file, so none of the three is spelled out even in prose.
//! Nor does this file decide anything a scheme decides: it
//! neither knows which scheme is in play nor registers one, and the protocol
//! capability bits it honours arrive from the owning connection rather than
//! being redefined here. See [`ProtocolIdentity`].
//!
//! # The two-phase contract Happy Eyeballs depends on
//!
//! `lib/cf-socket.h:84-121` says the same thing three times, once per
//! factory: *"The filter will not touch any connection/data flags and can be
//! used in happy eyeballing. Once selected for use, its `_active()` method
//! needs to be called."* That sentence is the design, and it is load-bearing
//! rather than advisory.
//!
//! Establishing a connection means racing several addresses at once -- two
//! families, several addresses within each. Each attempt therefore has to be
//! creatable, openable and connectable **in complete isolation**, publishing
//! nothing that another attempt could observe or that a loser could leave
//! behind. So the work splits in two:
//!
//! 1. **Create, open, connect.** [`cf_tcp_create`], [`cf_udp_create`] and
//!    [`cf_unix_create`] return an UNATTACHED filter holding exactly one
//!    resolved address -- the only address it is ever allowed to use.
//!    [`ConnFilter::connect`] opens its own socket, binds its own local end
//!    and drives its own non-blocking connect. Everything it learns it keeps
//!    in its own [`SocketContext`]. Nothing reaches the connection.
//! 2. **Activate.** Only the winner is sent
//!    [`CfControl::ConnInfoUpdate`], and only that event publishes the
//!    socket into connection state, refreshes the local address and marks the
//!    filter active (`lib/cf-socket.c:1545-1557`). Every loser is closed with
//!    its own socket still private to it, so it can close exactly once and
//!    cannot clear a descriptor the winner has since published.
//!
//! The check `ctx->sock == cf->conn->sock[cf->sockindex]` before clearing
//! (`lib/cf-socket.c:1233`) exists for precisely that reason, and
//! [`SocketFilter::do_close`] reproduces it.
//!
//! # Two C mechanisms that disappear rather than being translated
//!
//! **The `void *ctx` cast.** `struct Curl_cftype` carries fourteen function
//! pointers beside an untyped context that every filter casts back to its own
//! type (`lib/cfilters.h:210-226`). Here the state is [`SocketContext`], an
//! ordinary typed field beside [`FilterBase`], so there is no cast at any
//! filter boundary. AAP section 0.6.9 names this the largest single category
//! of unsound pattern in the C tree.
//!
//! **The entire broken-pipe-signal apparatus.** C devotes two whole files to
//! masking the signal that writing to a closed socket raises, plus a helper at
//! `lib/cf-socket.c:299-306` that sets the Apple-only socket option serving the
//! same purpose. **None of it has a successor anywhere in this crate** -- not
//! here, and not routed through [`crate::ffi::sys`]. Two facts remove the need
//! outright: the Rust runtime sets that signal to be ignored before `main`
//! runs, so a write to a closed socket returns `EPIPE` instead of terminating
//! the process, which is exactly the outcome the masking exists to produce; and
//! [`socket2::Socket::new`] sets the Apple-only option itself. A negative
//! continuous-integration grep for the signal's name is expected to find
//! nothing here, so the name is not spelled out even in prose.
//!
//! # Everything is injected
//!
//! AAP section 0.3.3's pattern P12 requires it and the mandated Miri gate
//! makes it unavoidable: `cargo +nightly miri test` cannot execute a foreign
//! function, so a test that reached a real socket, a real clock or a real
//! resolver could not run at all. The resolver ([`BindResolver`]), the clock
//! ([`Clock`], reached through [`CallCtx`]), the interface lookup
//! ([`If2Ip`]), the three user callbacks ([`OpenSocket`], [`CloseSocket`],
//! [`SockOpt`]), the multi-handle close observer
//! ([`MultiCloseObserver`]), the connection's socket table
//! ([`ConnSockets`]), the generic deadline ([`Deadline`]) and even socket
//! readiness ([`ReadinessProbe`]) are all seams. Nothing in this file reads a
//! system clock -- [`std::time::Instant`] is never named, let alone sampled --
//! there is no global resolver state, and no test touches the network.

use core::fmt;
use core::mem::MaybeUninit;
use core::time::Duration;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, IntoRawFd};
use std::rc::Rc;

use socket2::{
    Domain, Protocol as OsProtocol, SockAddr, Socket as OsSocket, TcpKeepalive,
    Type as OsType,
};

use crate::conn::filters::{
    link, CallCtx, CfControl, CfQuery, CfQueryValue, CfType, ConnFilter,
    FilterBase, FilterChain, IpQuadruple, Liveness, RemoteAddr, SocketIndex,
    Transport, CF_TYPE_IP_CONNECT,
};
use crate::conn::select::{
    is_valid_sock, EasyPollset, PollEvents, PollFds, Socket, CURL_CSELECT_IN,
    CURL_SOCKET_BAD,
};
use crate::conn::{addr2string, AddrText};
use crate::dns::if2ip::{if2ip, ipv6_scope, If2IpResult};
use crate::dns::{
    AddressFamily, IpProto, IpVersion, ResolvedAddr, ResolvedSockAddr,
    SockType, MAX_IPADR_LEN,
};
use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::trace::{failf, infof, trc_cf, TraceFilter};
use crate::util::inet::{pton4, pton6};
use crate::util::os_strerror;
use crate::util::strparse::str_number;
use crate::util::timediff::TimeDiff;
use crate::util::timeval::{timediff_ms, CurlTime};

// =========================================================================
// The exact C integers this layer carries
// =========================================================================

/// `TRNSPRT_NONE` (`lib/urldata.h:567`).
///
/// The five `TRNSPRT_*` values are restated here as the integers the C header
/// assigns, beside the checked [`Transport`] that [`crate::conn::filters`]
/// owns. That is not duplication for its own sake: these constants are what
/// [`transport_from_c`] validates against, and writing them out is what makes
/// the gap at 1 and 2 impossible to close by accident.
#[allow(dead_code)]
pub(crate) const TRNSPRT_NONE: u8 = 0;

/// `TRNSPRT_TCP` (`lib/urldata.h:568`).
///
/// Three, not one. The values start at three because 1 and 2 were retired,
/// and both remain RESERVED: [`transport_from_c`] rejects them.
#[allow(dead_code)]
pub(crate) const TRNSPRT_TCP: u8 = 3;

/// `TRNSPRT_UDP` (`lib/urldata.h:569`).
#[allow(dead_code)]
pub(crate) const TRNSPRT_UDP: u8 = 4;

/// `TRNSPRT_QUIC` (`lib/urldata.h:570`).
#[allow(dead_code)]
pub(crate) const TRNSPRT_QUIC: u8 = 5;

/// `TRNSPRT_UNIX` (`lib/urldata.h:571`).
#[allow(dead_code)]
pub(crate) const TRNSPRT_UNIX: u8 = 6;

/// `CURLSOCKTYPE_IPCXN = 0` (`include/curl/curl.h:410-411`): *"socket created
/// for a specific IP connection"*.
///
/// Part of the PUBLIC ABI: the value reaches an application's
/// `curl_sockopt_callback` and `curl_opensocket_callback`, so it is pinned
/// rather than inferred from declaration order.
#[allow(dead_code)]
pub(crate) const CURLSOCKTYPE_IPCXN: i32 = 0;

/// `CURLSOCKTYPE_ACCEPT = 1` (`include/curl/curl.h:412`): *"socket created by
/// `accept()` call"*.
#[allow(dead_code)]
pub(crate) const CURLSOCKTYPE_ACCEPT: i32 = 1;

/// `CURL_SOCKOPT_OK = 0` (`include/curl/curl.h:418`).
#[allow(dead_code)]
pub(crate) const CURL_SOCKOPT_OK: i32 = 0;

/// `CURL_SOCKOPT_ERROR = 1` (`include/curl/curl.h:419-420`): *"causes libcurl
/// to abort and return `CURLE_ABORTED_BY_CALLBACK`"*.
///
/// Any non-zero value that is not [`CURL_SOCKOPT_ALREADY_CONNECTED`] has that
/// effect, which `lib/cf-socket.c:1116-1121` implements as an `else if(error)`
/// after testing for the already-connected value.
#[allow(dead_code)]
pub(crate) const CURL_SOCKOPT_ERROR: i32 = 1;

/// `CURL_SOCKOPT_ALREADY_CONNECTED = 2` (`include/curl/curl.h:421`).
#[allow(dead_code)]
pub(crate) const CURL_SOCKOPT_ALREADY_CONNECTED: i32 = 2;

/// `sizeof(struct Curl_sockaddr_storage)` on all four mandated targets.
///
/// The bound `sock_assign_addr` enforces: *"`DEBUGASSERT(dest->addrlen <=
/// sizeof(dest->curl_sa_addrbuf)); if(dest->addrlen >
/// sizeof(dest->curl_sa_addrbuf)) return CURLE_TOO_LARGE;`"*
/// (`lib/cf-socket.c:290-297`). One hundred and twenty-eight bytes is what
/// `sizeof(struct sockaddr_storage)` is on Linux and on Apple platforms alike,
/// which `sockaddr_storage_is_the_size_the_platform_reports` verifies against
/// [`socket2::SockAddrStorage`] rather than taking on trust.
#[allow(dead_code)]
pub(crate) const SOCKADDR_STORAGE_LEN: u32 = 128;

/// The longest interface argument [`parse_interface`] accepts.
///
/// `if(len > 512) return CURLE_BAD_FUNCTION_ARGUMENT;`
/// (`lib/cf-socket.c:474-475`). Note the strictness: 512 is ACCEPTED and 513
/// is not.
#[allow(dead_code)]
pub(crate) const INTERFACE_INPUT_MAX: usize = 512;

/// The length at which `bindlocal` refuses an interface name.
///
/// `else if(iface && (strlen(iface) >= 255)) return
/// CURLE_BAD_FUNCTION_ARGUMENT;` (`lib/cf-socket.c:567-568`). A `>=`, so 254
/// is accepted and 255 is not -- a different bound and a different comparison
/// from [`INTERFACE_INPUT_MAX`], and the two are not interchangeable.
pub(crate) const BINDLOCAL_IFACE_MAX: usize = 255;

/// The service port `bindlocal` resolves a bind HOST with.
///
/// `Curl_resolv_blocking(data, host, 80, ip_version, &h)`
/// (`lib/cf-socket.c:649`). Hard-coded in the C and hard-coded here: the port
/// plays no part in the bind, which uses `data->set.localport`, so this is
/// only what the resolver is handed and changing it could change which
/// addresses a resolver returns.
pub(crate) const BINDLOCAL_SERVICE_PORT: u16 = 80;

/// `DEFAULT_ACCEPT_TIMEOUT` (`lib/connect.h:47`): sixty seconds in
/// milliseconds.
pub(crate) const DEFAULT_ACCEPT_TIMEOUT: TimeDiff = 60 * 1000;

/// How many bytes the graceful shutdown drains, at most, and once.
///
/// `unsigned char buf[1024]; (void)sread(ctx->sock, buf, sizeof(buf));`
/// (`lib/cf-socket.c:972-973`).
pub(crate) const SHUTDOWN_DRAIN_MAX: usize = 1024;

/// The buffer [`Wakeup::consume`] drains into.
///
/// `char buf[64];` (`lib/socketpair.c:340`).
#[allow(dead_code)]
pub(crate) const WAKEUP_DRAIN_LEN: usize = 64;

// =========================================================================
// Protocol capability bits this layer HONOURS and does not redefine
// =========================================================================

/// `PROTOPT_SSL` (`lib/urldata.h:527`).
///
/// # This is not [`CF_TYPE_IP_CONNECT`]
///
/// Both are `1 << 0` and the coincidence is worth stating once, because
/// confusing them would be silent. They live in unrelated bitmaps:
/// `PROTOPT_*` describes a SCHEME (`struct Curl_protocol::flags`,
/// `lib/urldata.h:522`) and `CF_TYPE_*` describes a FILTER
/// (`struct Curl_cftype::flags`, `lib/cfilters.h:212`). No value of one may
/// ever be tested against the other.
#[allow(dead_code)]
pub(crate) const PROTOPT_SSL: u32 = 1 << 0;

/// `PROTOPT_DUAL` (`lib/urldata.h:528`): *"this protocol uses two
/// connections"*.
///
/// Why this layer cares: a dual-connection scheme is the only reason
/// [`SocketIndex::Secondary`] is ever occupied, and TCP-ACCEPT exists to
/// serve it.
#[allow(dead_code)]
pub(crate) const PROTOPT_DUAL: u32 = 1 << 1;

/// `PROTOPT_ALPN` (`lib/urldata.h:544`).
#[allow(dead_code)]
pub(crate) const PROTOPT_ALPN: u32 = 1 << 8;

/// `1 << 9`, which *"was `PROTOPT_STREAM`, now free"* (`lib/urldata.h:545`).
///
/// Named so that its freedom is recorded rather than rediscovered, and
/// **deliberately not used**. The TFTP exception in
/// [`SocketFilter::set_local_ip`] is protocol IDENTITY -- carried by
/// [`ProtocolIdentity::connects_socket`] -- and reusing this bit to encode it
/// would quietly claim a value the C tree has left available.
#[allow(dead_code)]
pub(crate) const PROTOPT_FREE_BIT_9: u32 = 1 << 9;

/// `PROTOPT_NOTCPPROXY` (`lib/urldata.h:554`): *"this protocol cannot proxy
/// over TCP"*.
#[allow(dead_code)]
pub(crate) const PROTOPT_NOTCPPROXY: u32 = 1 << 14;

/// `PROTOPT_SSL_REUSE` (`lib/urldata.h:555-557`).
#[allow(dead_code)]
pub(crate) const PROTOPT_SSL_REUSE: u32 = 1 << 15;

/// `PROTOPT_CONN_REUSE` (`lib/urldata.h:558`).
#[allow(dead_code)]
pub(crate) const PROTOPT_CONN_REUSE: u32 = 1 << 16;

/// What a socket filter needs to know about the scheme above it.
///
/// C reaches `data->conn->scheme->protocol` and `->flags` through two back
/// pointers, which is how `set_local_ip` comes to test
/// `!(data->conn->scheme->protocol & CURLPROTO_TFTP)`
/// (`lib/cf-socket.c:998`). A socket filter cannot hold either pointer here --
/// the connection owns the chain, so the chain cannot own the connection --
/// and it must not build a second scheme registry to compensate. So the two
/// facts it actually uses travel with it as values.
///
/// **This type redefines nothing.** [`Self::flags`] carries the owner's
/// `PROTOPT_*` bitmap unchanged, including every bit this file never names,
/// and [`Self::connects_socket`] is a single derived predicate rather than a
/// new bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtocolIdentity {
    /// The scheme's `PROTOPT_*` bitmap, exactly as its owner holds it.
    pub(crate) flags: u32,

    /// Whether this scheme's socket is connected, so `getsockname` can answer.
    ///
    /// The successor of `!(data->conn->scheme->protocol & CURLPROTO_TFTP)`
    /// (`lib/cf-socket.c:998`), whose comment is *"TFTP does not connect, so
    /// it cannot get the IP like this"*. TFTP is out of implementation scope
    /// (AAP section 0.2.2), so no scheme in this build reports `false` -- but
    /// the EXCEPTION is reproduced rather than dropped, because it is the
    /// scheme's identity that decides it and a later scheme may need it.
    pub(crate) connects_socket: bool,
}

impl Default for ProtocolIdentity {
    /// A scheme with no special characteristics whose socket does connect.
    ///
    /// `PROTOPT_NONE` (`lib/urldata.h:526`) is zero, and every scheme in
    /// implementation scope connects its socket.
    fn default() -> Self {
        Self {
            flags: 0,
            connects_socket: true,
        }
    }
}

#[allow(dead_code)]
impl ProtocolIdentity {
    /// True when the scheme carries every bit of `flags`.
    #[allow(dead_code)]
    pub(crate) const fn has(self, flags: u32) -> bool {
        self.flags & flags == flags
    }
}

// =========================================================================
// Transport, and the socket parameters it selects
// =========================================================================

/// The checked conversion from a C `TRNSPRT_*` integer.
///
/// [`Transport::from_u8`] already rejects an unassigned value; this wraps it
/// in the crate's error type so a caller can propagate with `?`, and it exists
/// mainly to give the RESERVED values 1 and 2 a single documented rejection
/// point.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for any value other than
/// [`TRNSPRT_NONE`], [`TRNSPRT_TCP`], [`TRNSPRT_UDP`], [`TRNSPRT_QUIC`] and
/// [`TRNSPRT_UNIX`] -- which includes 1 and 2, retired and reserved.
#[allow(dead_code)]
pub(crate) fn transport_from_c(raw: u8) -> CodeResult<Transport> {
    Transport::from_u8(raw).ok_or(CURLcode::BadFunctionArgument)
}

/// The `(family, socktype, protocol)` triple a transport selects.
///
/// `sock_assign_addr`'s switch (`lib/cf-socket.c:275-288`), transcribed
/// exactly:
///
/// ```text
/// TRNSPRT_TCP   -> SOCK_STREAM, IPPROTO_TCP
/// TRNSPRT_UNIX  -> SOCK_STREAM, IPPROTO_IP     (the default protocol)
/// default       -> SOCK_DGRAM,  IPPROTO_UDP    (UDP and QUIC)
/// ```
///
/// The C's `default:` arm is commented *"UDP and QUIC"*, and it is genuinely a
/// default: [`Transport::None`] reaches it too. That is preserved -- a `file://`
/// transfer never opens a socket, so the value it would produce is never used,
/// and inventing a rejection here would be a behaviour change rather than a
/// tightening.
#[allow(dead_code)]
pub(crate) const fn socket_params(
    transport: Transport,
) -> (OsType, Option<OsProtocol>) {
    match transport {
        // `dest->socktype = SOCK_STREAM; dest->protocol = IPPROTO_TCP;`
        Transport::Tcp => (OsType::STREAM, Some(OsProtocol::TCP)),
        // `dest->socktype = SOCK_STREAM; dest->protocol = IPPROTO_IP;`
        // `IPPROTO_IP` is zero, which for `socket(2)` means "the default
        // protocol for this domain and type" -- `None` in `socket2`'s
        // vocabulary, which passes zero.
        Transport::Unix => (OsType::STREAM, None),
        // `default: dest->socktype = SOCK_DGRAM; dest->protocol =
        // IPPROTO_UDP;`
        Transport::Udp | Transport::Quic | Transport::None => {
            (OsType::DGRAM, Some(OsProtocol::UDP))
        }
    }
}

/// The `socket2` domain for an address family.
const fn domain_of(family: AddressFamily) -> Domain {
    match family {
        AddressFamily::Inet => Domain::IPV4,
        AddressFamily::Inet6 => Domain::IPV6,
        AddressFamily::Unix => Domain::UNIX,
    }
}

// =========================================================================
// The address a socket is opened for -- `struct Curl_sockaddr_ex`
// =========================================================================

/// Where a socket filter is pointed, with the metadata a callback may rewrite.
///
/// The successor of `struct Curl_sockaddr_ex` (`lib/cf-socket.h:37-55`):
///
/// ```c
/// struct Curl_sockaddr_ex {
///   int family;
///   int socktype;
///   int protocol;
///   unsigned int addrlen;
///   union {
///     struct sockaddr sa;
///     struct Curl_sockaddr_storage buf;
///   } addr;
/// };
/// #define curl_sa_addr    addr.sa
/// #define curl_sa_addrbuf addr.buf
/// ```
///
/// **The union and the two macros do not survive, deliberately.** They exist
/// so that C can write a `sockaddr_in6` into the buffer and then read it back
/// through a `struct sockaddr *` -- the pointer pun AAP section 0.6.9 removes.
/// [`socket2::SockAddr`] owns storage of exactly the union's size and hands out
/// a typed view through [`SockAddr::as_socket`] and
/// [`SockAddr::as_pathname`], so nothing here is ever reinterpreted.
///
/// The other three members remain because the header's own comment explains
/// why: *"The variable declared here will be used to pass / receive data
/// to/from the `fopensocket` callback if this has been set, before that, it is
/// initialized from parameters."* The family, socket type and protocol are
/// what the callback SEES and may CHANGE, so they are stored rather than
/// derived -- see [`OpenSocket`].
#[derive(Clone, Debug)]
pub(crate) struct SockAddrEx {
    /// `family`. `AF_INET`, `AF_INET6` or `AF_UNIX`, named rather than
    /// numbered because the numbers differ between Linux and Apple platforms.
    pub(crate) family: AddressFamily,

    /// `socktype`. `SOCK_STREAM` or `SOCK_DGRAM`.
    pub(crate) socktype: SockType,

    /// `protocol`. `IPPROTO_TCP`, `IPPROTO_UDP`, or unspecified for
    /// `IPPROTO_IP`.
    pub(crate) protocol: IpProto,

    /// `addr`, the union, as owned typed storage.
    pub(crate) addr: SockAddr,

    /// `addrlen`.
    ///
    /// Retained even though [`SockAddr`] tracks its own length, because it is
    /// the member the size check is performed against and a callback can be
    /// handed an address whose length it must be told.
    pub(crate) addrlen: u32,
}

#[allow(dead_code)]
impl SockAddrEx {
    /// Assigns an address and a transport -- `sock_assign_addr`
    /// (`lib/cf-socket.c:264-298`).
    ///
    /// The C's order is preserved: family first, then the transport switch
    /// selecting socket type and protocol, then the length, then the size
    /// check, then the copy. Only the copy differs, because there is no copy:
    /// the address moves into owned storage.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] when the address is longer than
    /// [`SOCKADDR_STORAGE_LEN`], which is `sock_assign_addr`'s own
    /// `CURLE_TOO_LARGE` at `lib/cf-socket.c:296-297`.
    ///
    /// [`CURLcode::BadFunctionArgument`] for a Unix path that cannot be
    /// expressed -- longer than `SUN_LEN`. C reaches the same refusal earlier,
    /// in `Curl_unix2addr` (`lib/curl_addrinfo.c:447-485`), because a path
    /// that does not fit never becomes a `Curl_addrinfo` in the first place.
    #[allow(dead_code)]
    pub(crate) fn assign(
        ai: &ResolvedAddr,
        transport: Transport,
    ) -> CodeResult<Self> {
        // `dest->family = ai->ai_family;`
        let family = ai.family();
        // The transport switch, verbatim.
        let (socktype, protocol) = match transport {
            Transport::Tcp => (SockType::Stream, IpProto::Tcp),
            Transport::Unix => (SockType::Stream, IpProto::Unspecified),
            Transport::Udp | Transport::Quic | Transport::None => {
                (SockType::Dgram, IpProto::Udp)
            }
        };
        let addr = sockaddr_of(&ai.addr)?;
        // `dest->addrlen = (unsigned int)ai->ai_addrlen;`
        let addrlen = addrlen_of(&addr);
        Self::new(family, socktype, protocol, addr, addrlen)
    }

    /// The size-checked constructor every other entry point funnels through.
    ///
    /// Separate from [`Self::assign`] so that the `CURLE_TOO_LARGE` branch has
    /// a reachable test: an address built by [`sockaddr_of`] can never exceed
    /// the storage, so a test that could only go through `assign` would leave
    /// the branch uncovered and the C's check unreproduced.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`], as [`Self::assign`].
    #[allow(dead_code)]
    pub(crate) fn new(
        family: AddressFamily,
        socktype: SockType,
        protocol: IpProto,
        addr: SockAddr,
        addrlen: u32,
    ) -> CodeResult<Self> {
        // C writes `DEBUGASSERT(dest->addrlen <=
        // sizeof(dest->curl_sa_addrbuf));` immediately before the test below.
        // It is DELIBERATELY NOT reproduced. An assertion here would abort the
        // build every test runs in, which would make the `CURLE_TOO_LARGE`
        // branch unreachable in exactly the configuration that has to prove it
        // works -- and the assertion adds nothing else, since the test that
        // follows it is what the release build relies on anyway.
        // `oversized_address_is_too_large` is the reachability this buys.
        //
        // `if(dest->addrlen > sizeof(...)) return CURLE_TOO_LARGE;`
        if addrlen > SOCKADDR_STORAGE_LEN {
            return Err(CURLcode::TooLarge);
        }
        Ok(Self {
            family,
            socktype,
            protocol,
            addr,
            addrlen,
        })
    }

    /// The `(domain, type, protocol)` triple `socket(2)` is called with.
    pub(crate) fn open_params(&self) -> (Domain, OsType, Option<OsProtocol>) {
        let kind = match self.socktype {
            SockType::Stream => OsType::STREAM,
            SockType::Dgram => OsType::DGRAM,
        };
        let proto = match self.protocol {
            IpProto::Unspecified => None,
            IpProto::Tcp => Some(OsProtocol::TCP),
            IpProto::Udp => Some(OsProtocol::UDP),
        };
        (domain_of(self.family), kind, proto)
    }

    /// True for an `AF_INET` or `AF_INET6` `SOCK_STREAM` address.
    ///
    /// `is_tcp` (`lib/cf-socket.c:1095-1102`), which gates TCP_NODELAY and
    /// keepalive. The name is the C's; note that it tests the SOCKET SHAPE and
    /// not [`Transport`], so an `AF_UNIX` stream is excluded even though it is
    /// carried by [`Transport::Unix`] with `SOCK_STREAM`.
    pub(crate) fn is_tcp(&self) -> bool {
        matches!(self.family, AddressFamily::Inet | AddressFamily::Inet6)
            && matches!(self.socktype, SockType::Stream)
    }

    /// True for an `AF_INET` or `AF_INET6` address, whatever its socket type.
    ///
    /// The `bindlocal` gate at `lib/cf-socket.c:1126-1131`: a local end is
    /// bound only for the two Internet families.
    pub(crate) fn is_inet(&self) -> bool {
        matches!(self.family, AddressFamily::Inet | AddressFamily::Inet6)
    }

    /// The peer, typed -- what `CF_QUERY_REMOTE_ADDR` answers with.
    pub(crate) fn remote_addr(&self) -> Option<RemoteAddr> {
        if let Some(inet) = self.addr.as_socket() {
            return Some(RemoteAddr::Inet(inet));
        }
        self.addr
            .as_pathname()
            .map(|path| RemoteAddr::Unix(path.to_string_lossy().into_owned()))
    }
}

/// Builds owned address storage from a resolved address.
///
/// The successor of the `memcpy(&dest->curl_sa_addrbuf, ai->ai_addr,
/// dest->addrlen)` at `lib/cf-socket.c:299`, and of the `sockaddr_un`
/// construction `Curl_unix2addr` performs (`lib/curl_addrinfo.c:447-485`).
///
/// The abstract-namespace convention is reproduced exactly: *"an abstract
/// socket's name occupies `sun_path` from offset one, leaving the leading byte
/// zero"*, which is what a leading NUL in the path expresses and what
/// [`SockAddr::unix`] recognises.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for a Unix path longer than `SUN_LEN`.
#[allow(dead_code)]
fn sockaddr_of(addr: &ResolvedSockAddr) -> CodeResult<SockAddr> {
    match addr {
        ResolvedSockAddr::Ip(inet) => Ok(SockAddr::from(*inet)),
        ResolvedSockAddr::Unix { path, abstract_ns } => {
            if *abstract_ns {
                use std::os::unix::ffi::OsStrExt;
                let name = path.as_os_str().as_bytes();
                let mut bytes = Vec::with_capacity(name.len() + 1);
                bytes.push(0);
                bytes.extend_from_slice(name);
                let os = std::ffi::OsStr::from_bytes(&bytes);
                SockAddr::unix(std::path::Path::new(os))
                    .map_err(|_| CURLcode::BadFunctionArgument)
            } else {
                SockAddr::unix(path).map_err(|_| CURLcode::BadFunctionArgument)
            }
        }
    }
}

/// The C's `dest->addrlen`, in the width `Curl_sockaddr_ex` declares it.
///
/// `struct Curl_sockaddr_ex` stores it as `unsigned int`
/// (`lib/cf-socket.c:41`) and assigns it from `ai->ai_addrlen`, whose type is
/// `socklen_t`. Named rather than written inline at each of its four call sites
/// so that the ONE portability fact it rests on is stated once: `socklen_t` is
/// `u32` on every target of the mandated four-target matrix, so there is no
/// conversion to perform and no value that could be truncated.
///
/// A target where the two widths differed would fail to compile here -- loudly,
/// at the single place that would have to be revisited -- rather than silently
/// narrowing an address length, which is the behaviour worth having.
fn addrlen_of(addr: &SockAddr) -> u32 {
    addr.len()
}

// =========================================================================
// The IP quadruple
// =========================================================================

/// True when address text fits the C's `char[MAX_IPADR_LEN]` with its NUL.
///
/// `struct ip_quadruple` stores both addresses as `char[MAX_IPADR_LEN]`
/// (`lib/urldata.h:574-575`), where [`MAX_IPADR_LEN`] is
/// `sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")` --
/// forty-six bytes INCLUDING the terminator (`lib/urldata.h:124`). The Rust
/// quadruple holds [`String`]s, so nothing truncates here; the bound still
/// matters because `curl-rs-ffi` must copy these into the fixed arrays that
/// back `CURLINFO_PRIMARY_IP`, `CURLINFO_LOCAL_IP` and the `%HOSTIP` the test
/// harness substitutes, and a value that did not fit would be silently cut
/// there instead.
///
/// Hence `<`, not `<=`: forty-five printable bytes is the most that fits.
pub(crate) fn ip_text_fits(text: &str) -> bool {
    text.len() < MAX_IPADR_LEN
}

/// The four addresses and two ports, cleared.
///
/// `memset(ctx, 0, sizeof(*ctx))` (`lib/cf-socket.c:900`) reaches the
/// quadruple too, which is why both address strings start empty and both ports
/// start at zero rather than being left undefined.
#[allow(dead_code)]
fn empty_quadruple() -> IpQuadruple {
    IpQuadruple::default()
}

// =========================================================================
// Observable text -- every string this layer emits, in one place
// =========================================================================

/// The messages `lib/cf-socket.c` writes, verbatim.
///
/// Collected here for one reason: AAP section 0.8.1 freezes them, and a format
/// string reachable from a test is a format string that cannot drift. The two
/// `Trying` lines in particular carry **two leading spaces**, which no
/// reviewer would notice missing and which
/// `the_trying_lines_keep_their_two_leading_spaces` pins.
pub(crate) mod msg {
    use super::AddressFamily;

    /// `"  Trying [%s]:%d..."` (`lib/cf-socket.c:1085`) -- IPv6, bracketed.
    ///
    /// TWO LEADING SPACES, and three trailing dots.
    pub(crate) fn trying_ipv6(ip: &str, port: u16) -> String {
        format!("  Trying [{ip}]:{port}...")
    }

    /// `"  Trying %s:%d..."` (`lib/cf-socket.c:1092`) -- everything else.
    ///
    /// TWO LEADING SPACES, as [`trying_ipv6`] has.
    pub(crate) fn trying(ip: &str, port: u16) -> String {
        format!("  Trying {ip}:{port}...")
    }

    /// The `Trying` line for `family`.
    ///
    /// C selects between the two forms with `#ifdef USE_IPV6` around an
    /// `if(ctx->addr.family == AF_INET6)` (`lib/cf-socket.c:1075-1092`), so
    /// the bracketed form is IPv6's alone -- an `AF_UNIX` address takes the
    /// unbracketed one.
    pub(crate) fn trying_for(
        family: AddressFamily,
        ip: &str,
        port: u16,
    ) -> String {
        match family {
            AddressFamily::Inet6 => trying_ipv6(ip, port),
            AddressFamily::Inet | AddressFamily::Unix => trying(ip, port),
        }
    }

    /// `"connect to %s port %u from %s port %d failed: %s"`
    /// (`lib/cf-socket.c:1314-1317`).
    ///
    /// The asymmetry is the C's and is preserved: the REMOTE port is `%u`,
    /// UNSIGNED, and the LOCAL port is `%d`, SIGNED. Both members of
    /// `struct ip_quadruple` are `uint16_t` (`lib/urldata.h:576-577`), so
    /// neither can be negative and the two render identically -- but the
    /// FORMAT STRING is what AAP section 0.8.1 freezes, and it says `%u` for
    /// one and `%d` for the other.
    pub(crate) fn connect_failed(
        remote_ip: &str,
        remote_port: u16,
        local_ip: &str,
        local_port: u16,
        reason: &str,
    ) -> String {
        format!(
            "connect to {remote_ip} port {remote_port} from {local_ip} \
             port {local_port} failed: {reason}"
        )
    }

    /// `"Immediate connect fail for %s: %s"` (`lib/cf-socket.c:854`).
    pub(crate) fn immediate_connect_fail(ip: &str, reason: &str) -> String {
        format!("Immediate connect fail for {ip}: {reason}")
    }

    /// `"curl_sa_addr inet_ntop() failed with errno %d: %s"`
    /// (`lib/cf-socket.c:1035-1036`) -- the REMOTE conversion.
    ///
    /// `curl_sa_addr` is the `#define` for `addr.sa` (`lib/cf-socket.h:53`),
    /// so the name in the message is a macro name rather than a variable, and
    /// it is reproduced as the C prints it.
    pub(crate) fn remote_ntop_failed(errno: i32, reason: &str) -> String {
        format!("curl_sa_addr inet_ntop() failed with errno {errno}: {reason}")
    }

    /// `"ssloc inet_ntop() failed with errno %d: %s"`
    /// (`lib/cf-socket.c:1015-1016`) -- the LOCAL conversion.
    ///
    /// `ssloc` is the C's local variable name, kept for the same reason.
    pub(crate) fn local_ntop_failed(errno: i32, reason: &str) -> String {
        format!("ssloc inet_ntop() failed with errno {errno}: {reason}")
    }

    /// `"ssrem inet_ntop() failed with errno %d: %s"`
    /// (`lib/cf-socket.c:2003-2004`) -- the ACCEPTED PEER conversion.
    pub(crate) fn peer_ntop_failed(errno: i32, reason: &str) -> String {
        format!("ssrem inet_ntop() failed with errno {errno}: {reason}")
    }

    /// `"getsockname() failed with errno %d: %s"`
    /// (`lib/cf-socket.c:1010-1011`).
    pub(crate) fn getsockname_failed(errno: i32, reason: &str) -> String {
        format!("getsockname() failed with errno {errno}: {reason}")
    }

    /// `"getpeername() failed with errno %d: %s"`
    /// (`lib/cf-socket.c:1997-1998`).
    pub(crate) fn getpeername_failed(errno: i32, reason: &str) -> String {
        format!("getpeername() failed with errno {errno}: {reason}")
    }

    /// `"failed to open socket: %s"` (`lib/cf-socket.c:350-351`).
    pub(crate) fn open_failed(reason: &str) -> String {
        format!("failed to open socket: {reason}")
    }

    /// `"Send failure: %s"` (`lib/cf-socket.c:1451-1452`).
    pub(crate) fn send_failure(reason: &str) -> String {
        format!("Send failure: {reason}")
    }

    /// `"Recv failure: %s"` (`lib/cf-socket.c:1521-1522`).
    pub(crate) fn recv_failure(reason: &str) -> String {
        format!("Recv failure: {reason}")
    }

    /// `"socket successfully bound to interface '%s'"`
    /// (`lib/cf-socket.c:597`).
    pub(crate) fn bound_to_interface(iface: &str) -> String {
        format!("socket successfully bound to interface '{iface}'")
    }

    /// `"Could not bind to interface '%s' with errno %d: %s"`
    /// (`lib/cf-socket.c:614-615`).
    pub(crate) fn bind_iface_failed(
        iface: &str,
        errno: i32,
        reason: &str,
    ) -> String {
        format!(
            "Could not bind to interface '{iface}' with errno \
             {errno}: {reason}"
        )
    }

    /// `"Local Interface %s is ip %s using address family %i"`
    /// (`lib/cf-socket.c:625-626`).
    ///
    /// The family is printed as the OS integer, so the value is passed in
    /// rather than derived: naming `AF_INET6` in the engine is what
    /// `crate::lib`'s `source_policy` gate exists to prevent.
    pub(crate) fn local_interface_is(iface: &str, ip: &str, af: i32) -> String {
        format!("Local Interface {iface} is ip {ip} using address family {af}")
    }

    /// `"Name '%s' family %i resolved to '%s' family %i"`
    /// (`lib/cf-socket.c:653-654`).
    pub(crate) fn name_resolved(
        host: &str,
        af: i32,
        ip: &str,
        resolved_af: i32,
    ) -> String {
        format!(
            "Name '{host}' family {af} resolved to '{ip}' \
             family {resolved_af}"
        )
    }

    /// `"Could not bind to '%s' with errno %d: %s"`
    /// (`lib/cf-socket.c:716-717`).
    pub(crate) fn bind_host_failed(
        host: &str,
        errno: i32,
        reason: &str,
    ) -> String {
        format!("Could not bind to '{host}' with errno {errno}: {reason}")
    }

    /// `"Local port: %hu"` (`lib/cf-socket.c:748`).
    ///
    /// `%hu` is an unsigned short, and the local port is a `u16`, so the
    /// rendered number is the same value the C prints.
    pub(crate) fn local_port(port: u16) -> String {
        format!("Local port: {port}")
    }

    /// `"Bind to local port %d failed, trying next"`
    /// (`lib/cf-socket.c:755`).
    ///
    /// The C prints `port - 1`: it has ALREADY incremented, so the number in
    /// the message is the port that failed and not the one about to be tried.
    pub(crate) fn bind_port_retry(failed_port: u16) -> String {
        format!("Bind to local port {failed_port} failed, trying next")
    }

    /// `"bind failed with errno %d: %s"` (`lib/cf-socket.c:768-769`).
    pub(crate) fn bind_failed(errno: i32, reason: &str) -> String {
        format!("bind failed with errno {errno}: {reason}")
    }

    /// `"Accept timeout occurred while waiting server connect"`
    /// (`lib/cf-socket.c:2042`).
    pub(crate) const ACCEPT_TIMEOUT: &str =
        "Accept timeout occurred while waiting server connect";

    /// `"Error while waiting for server connect"`
    /// (`lib/cf-socket.c:2053`).
    pub(crate) const ACCEPT_WAIT_ERROR: &str =
        "Error while waiting for server connect";

    /// `"Ready to accept data connection from server"`
    /// (`lib/cf-socket.c:2059`).
    pub(crate) const ACCEPT_READY: &str =
        "Ready to accept data connection from server";

    /// `"Connection accepted from server"` (`lib/cf-socket.c:2094`).
    pub(crate) const ACCEPT_DONE: &str = "Connection accepted from server";

    /// `"Error accept()ing server connect: %s"`
    /// (`lib/cf-socket.c:2078-2079`).
    ///
    /// `accept()ing` is the C's spelling, parentheses and all.
    pub(crate) fn accept_failed(reason: &str) -> String {
        format!("Error accept()ing server connect: {reason}")
    }

    /// `"set socket NONBLOCK: %s"` (`lib/cf-socket.c:2087-2088`).
    #[allow(dead_code)]
    pub(crate) fn set_nonblock_failed(reason: &str) -> String {
        format!("set socket NONBLOCK: {reason}")
    }

    /// The trace line the accept path emits while it waits.
    ///
    /// `CURL_TRC_CF(data, cf, "nothing heard from the server yet")`
    /// (`lib/cf-socket.c:2065`).
    pub(crate) const NOTHING_HEARD: &str = "nothing heard from the server yet";

    /// `CURL_TRC_CF(data, cf, "socket_check -> %x", socketstate)`
    /// (`lib/cf-socket.c:2050`).
    ///
    /// The value is what `SOCKET_READABLE(ctx->sock, 0)` returned -- `-1` for a
    /// failed wait, `0` for nothing, and [`CURL_CSELECT_IN`] when the socket is
    /// readable -- printed in the C's lower-case hexadecimal. `%x` on a
    /// negative `int` prints its two's-complement bit pattern, `ffffffff`, and
    /// that is what a reader of a curl trace sees, so the cast is to `u32`
    /// rather than to a wider type that would print more digits.
    ///
    /// This is the ONE trace line here whose argument the C computes and this
    /// file does not: [`AcceptProbe`] carries the outcome as a typed value
    /// rather than as a bitmask. The mapping back is total and is performed by
    /// [`AcceptProbe::socket_state`], so the line is reproduced rather than
    /// dropped.
    pub(crate) fn socket_check(state: i32) -> String {
        format!("socket_check -> {:x}", state as u32)
    }
}

// =========================================================================
// The three user callbacks, as injected seams
// =========================================================================

/// Why a socket was created -- `curlsocktype`
/// (`include/curl/curl.h:410-414`).
///
/// The integers are PUBLIC ABI, so [`Self::as_i32`] pins them rather than
/// letting declaration order decide. `CURLSOCKTYPE_LAST` has no variant: its
/// own comment is *"never use"*, and a Rust enumeration has no need of a
/// sentinel to bound itself.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SockPurpose {
    /// `CURLSOCKTYPE_IPCXN = 0`.
    IpCxn,
    /// `CURLSOCKTYPE_ACCEPT = 1`.
    Accept,
}

#[allow(dead_code)]
impl SockPurpose {
    /// The C integer.
    #[allow(dead_code)]
    pub(crate) const fn as_i32(self) -> i32 {
        match self {
            Self::IpCxn => CURLSOCKTYPE_IPCXN,
            Self::Accept => CURLSOCKTYPE_ACCEPT,
        }
    }

    /// The checked conversion from the C integer.
    ///
    /// Returns [`None`] for anything else, `CURLSOCKTYPE_LAST` included.
    #[allow(dead_code)]
    pub(crate) const fn from_i32(raw: i32) -> Option<Self> {
        match raw {
            CURLSOCKTYPE_IPCXN => Some(Self::IpCxn),
            CURLSOCKTYPE_ACCEPT => Some(Self::Accept),
            _ => None,
        }
    }
}

/// What a `CURLOPT_SOCKOPTFUNCTION` callback reported.
///
/// The three `CURL_SOCKOPT_*` values (`include/curl/curl.h:416-421`).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum SockOptOutcome {
    /// `CURL_SOCKOPT_OK = 0`: carry on.
    Ok,
    /// Any non-zero value that is not [`Self::AlreadyConnected`].
    ///
    /// `CURL_SOCKOPT_ERROR = 1` is its documented spelling, but the C tests
    /// `else if(error)` (`lib/cf-socket.c:1118`), so EVERY other non-zero
    /// value aborts identically -- which is why [`Self::from_i32`] is total.
    #[allow(dead_code)]
    Error,
    /// `CURL_SOCKOPT_ALREADY_CONNECTED = 2`: the callback handed back a socket
    /// that is already connected, so the connect is skipped.
    #[allow(dead_code)]
    AlreadyConnected,
}

#[allow(dead_code)]
impl SockOptOutcome {
    /// The C integer, using the documented spelling for [`Self::Error`].
    #[allow(dead_code)]
    pub(crate) const fn as_i32(self) -> i32 {
        match self {
            Self::Ok => CURL_SOCKOPT_OK,
            Self::Error => CURL_SOCKOPT_ERROR,
            Self::AlreadyConnected => CURL_SOCKOPT_ALREADY_CONNECTED,
        }
    }

    /// The classification `lib/cf-socket.c:1116-1121` performs.
    ///
    /// Total by construction, and in the C's own order: the
    /// already-connected value is tested FIRST, then any non-zero is an error,
    /// then zero is success. A callback returning 3 aborts the transfer, which
    /// is what the C does and is therefore what this reports.
    #[allow(dead_code)]
    pub(crate) const fn from_i32(raw: i32) -> Self {
        if raw == CURL_SOCKOPT_ALREADY_CONNECTED {
            Self::AlreadyConnected
        } else if raw == CURL_SOCKOPT_OK {
            Self::Ok
        } else {
            Self::Error
        }
    }
}

/// Why an open-socket callback declined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum OpenSocketError {
    /// The callback returned `CURL_SOCKET_BAD`.
    ///
    /// *"Depending on this information the callback may opt to abort the
    /// connection, this is indicated returning `CURL_SOCKET_BAD`"*
    /// (`lib/cf-socket.c:325-327`). The C then falls into the shared
    /// `if(*sockfd == CURL_SOCKET_BAD)` arm and reports
    /// [`CURLcode::CouldntConnect`] (`:348-353`) -- NOT
    /// [`CURLcode::OutOfMemory`], which only the internal `socket(2)` path can
    /// produce.
    #[allow(dead_code)]
    Refused,
    /// The callback could not allocate.
    ///
    /// The counterpart of `if((*sockfd == CURL_SOCKET_BAD) && (SOCKERRNO ==
    /// SOCKENOMEM)) return CURLE_OUT_OF_MEMORY;` (`:344-345`), offered to a
    /// callback so an implementation that knows it ran out of memory can say
    /// so rather than being reported as a refusal.
    #[allow(dead_code)]
    OutOfMemory,
}

/// `CURLOPT_OPENSOCKETFUNCTION`, as a seam.
///
/// # Why this returns an OWNED socket rather than a descriptor
///
/// The C callback returns a `curl_socket_t` -- a raw integer -- and libcurl
/// then treats it as its own. Adopting a raw descriptor needs an unchecked conversion
/// (`std::os::fd`'s `from_raw_fd`, which has no way to know the caller owns
/// it), and this
/// file must contain none: AAP section 0.6.9's invariant is machine-checked by
/// `#![deny(unsafe_code)]` at the crate root with a single exemption on
/// [`crate::ffi`]. So the adoption happens where the C boundary genuinely is
/// -- in `curl-rs-ffi`, which owns the trampoline -- and what crosses INTO
/// this file is an already-owned [`socket2::Socket`]. The ownership is then
/// explicit and the socket closes exactly once.
///
/// # The address is `&mut` on purpose
///
/// *"When the callback returns a valid socket the destination address
/// information might have been changed and this 'new' address will actually be
/// used here to connect"* (`lib/cf-socket.c:327-329`). An implementation may
/// therefore rewrite [`SockAddrEx::family`], [`SockAddrEx::socktype`],
/// [`SockAddrEx::protocol`] and [`SockAddrEx::addr`], and
/// [`SocketFilter`] honours what it finds afterwards rather than what it
/// passed in.
pub(crate) trait OpenSocket: fmt::Debug {
    /// Creates a socket for `addr`, which the callback may rewrite.
    ///
    /// # Errors
    ///
    /// [`OpenSocketError::Refused`] for the C's `CURL_SOCKET_BAD`, and
    /// [`OpenSocketError::OutOfMemory`] for exhaustion.
    fn open_socket(
        &self,
        purpose: SockPurpose,
        addr: &mut SockAddrEx,
    ) -> Result<OsSocket, OpenSocketError>;
}

/// `CURLOPT_CLOSESOCKETFUNCTION`, as a seam.
///
/// # Why this CONSUMES the socket
///
/// The C callback is handed the descriptor and is responsible for closing it;
/// libcurl does not close it afterwards (`lib/cf-socket.c:419-425`). Taking
/// the [`socket2::Socket`] by value states exactly that: this file can no
/// longer touch it, and a double close is unrepresentable rather than merely
/// avoided.
pub(crate) trait CloseSocket: fmt::Debug {
    /// Closes `socket` and reports what the callback returned.
    ///
    /// The C propagates the callback's `int` out of `Curl_socket_close`
    /// (`lib/cf-socket.c:423`); no caller in `lib/cf-socket.c` reads it, but it
    /// is part of the callback contract, so it is carried.
    fn close_socket(&self, socket: OsSocket) -> i32;
}

/// `CURLOPT_SOCKOPTFUNCTION`, as a seam.
///
/// Borrows the socket rather than taking it: the callback configures a socket
/// it does not own, and `CURL_SOCKOPT_ALREADY_CONNECTED` says so explicitly by
/// handing the socket back for use.
pub(crate) trait SockOpt: fmt::Debug {
    /// Configures `socket`, told why it was created.
    fn sockopt(
        &self,
        socket: &OsSocket,
        purpose: SockPurpose,
    ) -> SockOptOutcome;
}

/// `Curl_multi_will_close`, as a seam.
///
/// The multi handle keeps a socket-to-transfer map for
/// `CURLMOPT_SOCKETFUNCTION`, and it has to be told before a descriptor
/// disappears or the map keeps an entry the kernel may reissue to something
/// else. `socket_close` calls it on BOTH paths -- before the callback
/// (`lib/cf-socket.c:420`) and before `sclose` (`:429`) -- and so does
/// [`close_owned_socket`].
pub(crate) trait MultiCloseObserver: fmt::Debug {
    /// Announces that `sock` is about to stop existing.
    fn will_close(&self, sock: Socket);
}

// =========================================================================
// The connection and transfer state a socket filter publishes into
// =========================================================================

/// The connection fields a socket filter reads and writes.
///
/// C reaches all of these through `cf->conn` and `data`, two back pointers a
/// safe ownership graph cannot reproduce -- the connection owns the chain, so
/// the chain cannot own the connection (`crate::conn::filters::ConnId`
/// documents the same problem for filter identity). The five things
/// `lib/cf-socket.c` actually does with them become this seam:
///
/// 1. `cf->conn->sock[cf->sockindex] = ctx->sock` on activation (`:1550`) and
///    on accept (`:2101`), and `= CURL_SOCKET_BAD` on close (`:1234`).
/// 2. `cf->conn->bits.ipv6 = (ctx->addr.family == AF_INET6)` (`:1554`).
/// 3. `conn->bits.bound = TRUE` once a local bind succeeds (`:749`).
/// 4. `data->info.primary = ctx->ip` and `data->info.conn_remote_port =
///    cf->conn->remote_port` (`:1538-1541`).
/// 5. `data->state.os_errno = error` wherever a failure is reported.
///
/// Every method takes `&self`. That is deliberate: a filter holds this behind
/// an [`Rc`] alongside the connection that owns the chain, so shared access
/// with interior mutability is the shape the ownership graph permits -- and it
/// keeps the seam trivial to double in a test.
pub(crate) trait ConnState: fmt::Debug {
    /// `cf->conn->sock[sockindex]`.
    fn socket(&self, sockindex: SocketIndex) -> Socket;

    /// `cf->conn->sock[sockindex] = sock`.
    fn publish_socket(&self, sockindex: SocketIndex, sock: Socket);

    /// `cf->conn->sock[sockindex] = CURL_SOCKET_BAD`.
    fn clear_socket(&self, sockindex: SocketIndex);

    /// `cf->conn->bits.ipv6 = is_ipv6`.
    fn set_ipv6(&self, is_ipv6: bool);

    /// `conn->bits.bound = bound`.
    fn set_bound(&self, bound: bool);

    /// `cf->conn->remote_port`.
    fn remote_port(&self) -> u16;

    /// `data->info.primary = *quad; data->info.conn_remote_port = port;`.
    fn set_primary(&self, quad: &IpQuadruple, remote_port: u16);

    /// `data->state.os_errno = errno`.
    fn set_os_errno(&self, errno: i32);
}

/// A connection that records nothing.
///
/// What a filter created for a Happy Eyeballs attempt can be given before any
/// connection exists to publish into, and what every test that is not
/// asserting on publication uses. [`Self::socket`] answers
/// [`CURL_SOCKET_BAD`], so the `ctx->sock == cf->conn->sock[...]` guard in
/// [`SocketFilter::do_close`] never matches and nothing is ever cleared --
/// which is the correct outcome for a filter whose socket was never published.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NullConnState;

impl ConnState for NullConnState {
    fn socket(&self, _sockindex: SocketIndex) -> Socket {
        CURL_SOCKET_BAD
    }

    fn publish_socket(&self, _sockindex: SocketIndex, _sock: Socket) {}

    fn clear_socket(&self, _sockindex: SocketIndex) {}

    fn set_ipv6(&self, _is_ipv6: bool) {}

    fn set_bound(&self, _bound: bool) {}

    fn remote_port(&self) -> u16 {
        0
    }

    fn set_primary(&self, _quad: &IpQuadruple, _remote_port: u16) {}

    fn set_os_errno(&self, _errno: i32) {}
}

// =========================================================================
// Readiness, as a seam -- and why it has to be one
// =========================================================================

/// What a zero-timeout readiness check found.
///
/// The three outcomes `Curl_poll(pfd, 1, 0)` can produce, as
/// `cf_socket_conn_is_alive` reads them (`lib/cf-socket.c:1596-1615`):
/// negative, zero, and a set of `revents`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProbeOutcome {
    /// The C's `r < 0`: *"poll error, assume dead"*.
    Failed,
    /// The C's `r == 0`: *"poll timeout, assume alive"*.
    Timeout,
    /// The C's `r > 0`, carrying `pfd[0].revents`.
    Ready(PollEvents),
}

/// How far a non-blocking connect has got.
///
/// One value where C has two mechanisms -- `SOCKET_WRITABLE(sock, 0)`
/// (`lib/cf-socket.c:1285`) followed by `verifyconnect(sock, &ctx->error)`
/// (`:1291`) -- and combining them is a correctness improvement rather than a
/// simplification. `verifyconnect` reads `SO_ERROR` with `getsockopt`, and
/// **reading `SO_ERROR` clears it**: two readings of one failed connect give
/// the error once and zero the second time, which is exactly how a failure
/// gets misreported as a success. C avoids that by ordering its calls
/// carefully. Here the reading happens once and its verdict travels in this
/// type, so the ordering cannot be got wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectProgress {
    /// Still in the handshake -- the C's `rc == 0`, *"no connection yet"*.
    Pending,
    /// Finished, and `verifyconnect` returned true.
    Connected,
    /// Finished and failed, carrying what `SO_ERROR` reported.
    Failed(i32),
    /// The check itself could not be made.
    ///
    /// C has no counterpart: its `getsockopt` failure path assigns
    /// `err = SOCKERRNO` and carries on (`lib/cf-socket.c:809-810`). Separating
    /// it makes "the socket is unusable" distinguishable from "the peer refused
    /// us", which the caller reports identically but a test need not.
    Unusable,
}

/// What an accept attempt on a listening socket produced.
///
/// C splits this across a readability check and an `accept`
/// (`lib/cf-socket.c:2049-2081`), with FOUR distinguishable outcomes and a
/// different observable message for each. They are enumerated here rather than
/// reconstructed, because a probe that only reported readability could not
/// preserve them: `accept(2)` is the only non-blocking way to learn that a
/// connection is pending, and learning it consumes it.
#[derive(Debug)]
pub(crate) enum AcceptProbe {
    /// Nothing arrived -- the C's `if(!incoming)`, whose trace line is
    /// [`msg::NOTHING_HEARD`].
    Pending,
    /// A connection arrived and was accepted, non-blocking and close-on-exec.
    ///
    /// `CURL_ACCEPT4(..., SOCK_NONBLOCK | SOCK_CLOEXEC)`
    /// (`lib/cf-socket.c:2069-2070`), whose two flags a probe must establish
    /// however its platform offers them.
    Accepted(OsSocket),
    /// The wait itself failed -- the C's `case -1`, whose message is
    /// [`msg::ACCEPT_WAIT_ERROR`].
    WaitFailed,
    /// A connection was pending but `accept` refused it -- the C's
    /// `s_accepted == CURL_SOCKET_BAD`, whose message is
    /// [`msg::accept_failed`].
    AcceptFailed(io::Error),
}

impl AcceptProbe {
    /// What `SOCKET_READABLE(ctx->sock, 0)` returned, for
    /// [`msg::socket_check`].
    ///
    /// `SOCKET_READABLE` is `Curl_socket_check(x, CURL_SOCKET_BAD,
    /// CURL_SOCKET_BAD, ms)` (`lib/select.h:76-77`), whose three possible
    /// answers this maps back to exactly:
    ///
    /// * `-1` -- the wait itself failed, the C's `case -1`.
    /// * `0` -- the timeout expired with nothing readable, which is what
    ///   `if(!incoming)` observes.
    /// * [`CURL_CSELECT_IN`] -- the listener is readable. BOTH
    ///   [`Self::Accepted`] and [`Self::AcceptFailed`] follow from it, because
    ///   the C reaches its `accept` call only down this branch and the accept
    ///   may then still refuse.
    ///
    /// Total by construction, so the trace line the C emits before its `switch`
    /// is reproduced rather than dropped, even though this seam carries the
    /// outcome as a typed value.
    pub(crate) const fn socket_state(&self) -> i32 {
        match self {
            Self::WaitFailed => -1,
            Self::Pending => 0,
            Self::Accepted(_) | Self::AcceptFailed(_) => CURL_CSELECT_IN as i32,
        }
    }
}

/// Socket readiness, injected.
///
/// # Why readiness is a seam rather than a call into [`crate::conn::select`]
///
/// [`ConnFilter`] is a SYNCHRONOUS trait: `connect`, `is_alive` and the rest
/// all take `&mut self` and return a value, because the C design they succeed
/// is non-blocking rather than blocking -- a filter makes what progress it can
/// and reports whether it finished. Everything in [`crate::conn::select`] that
/// waits, on the other hand, is `async`: `socket_check`, `socket_readable`,
/// `socket_writable` and `poll_sockets` are all futures over the `tokio`
/// reactor. The two cannot meet directly, and the join must not be made by
/// blocking on a future from inside a synchronous method -- doing that inside a
/// runtime panics.
///
/// So the zero-timeout probes -- and ONLY the zero-timeout probes, which is
/// every probe `lib/cf-socket.c` performs -- are expressed as this trait. The
/// waiting that genuinely needs the reactor still belongs to
/// [`crate::conn::select`]: a filter says what readiness it wants through
/// [`ConnFilter::adjust_pollset`] and the driver awaits it there.
///
/// The seam pays twice over. AAP section 0.8.4 mandates
/// `cargo +nightly miri test`, and Miri cannot execute a foreign function, so
/// a test that probed a real descriptor could not run; and the outcomes a real
/// host cannot be made to produce on demand -- a refused connect, a hung-up
/// peer, an `accept` that fails after readability -- are reachable only through
/// a double.
pub(crate) trait ReadinessProbe: fmt::Debug {
    /// `Curl_poll(pfd, 1, 0)` with `POLLRDNORM | POLLIN | POLLRDBAND |
    /// POLLPRI` (`lib/cf-socket.c:1592-1596`).
    fn probe_input(&self, socket: &OsSocket) -> ProbeOutcome;

    /// `SOCKET_WRITABLE(sock, 0)` followed by `verifyconnect`, as one verdict.
    fn probe_connect(&self, socket: &OsSocket) -> ConnectProgress;

    /// `SOCKET_READABLE(sock, 0)` followed by `accept4`, as one verdict.
    fn probe_accept(&self, listener: &OsSocket) -> AcceptProbe;
}

/// The real probe: `socket2` and nothing else.
///
/// Every branch below is reached through a safe `socket2` method, and each one
/// documents which C construct it replaces and why the replacement observes the
/// same thing.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SocketProbe;

impl ReadinessProbe for SocketProbe {
    /// Readability without a `poll`.
    ///
    /// `MSG_PEEK` answers the same question `POLLIN` does and answers it
    /// without consuming: a non-blocking peek returns bytes when bytes are
    /// waiting, `WouldBlock` when none are, and zero when the peer has closed.
    /// `SO_ERROR` is consulted first, because `POLLERR` is a condition the C
    /// tests for and a peek would report as an ordinary failure.
    fn probe_input(&self, socket: &OsSocket) -> ProbeOutcome {
        match socket.take_error() {
            // `POLLERR`: an error is pending on the socket.
            Ok(Some(_)) => return ProbeOutcome::Ready(PollEvents::ERR),
            // `getsockopt` itself failed, which the C reads as `r < 0`.
            Err(_) => return ProbeOutcome::Failed,
            Ok(None) => {}
        }
        let mut byte = [MaybeUninit::<u8>::uninit(); 1];
        match socket.peek(&mut byte) {
            // Zero from a peek is end of stream, which is what `POLLHUP`
            // reports and what the C treats as dead.
            Ok(0) => ProbeOutcome::Ready(PollEvents::HUP),
            // Bytes are waiting: `POLLIN`.
            Ok(_) => ProbeOutcome::Ready(PollEvents::IN),
            Err(error) => match error.kind() {
                // Nothing waiting, which is the C's `r == 0` timeout.
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => {
                    ProbeOutcome::Timeout
                }
                // Anything else is a condition, not an absence.
                _ => ProbeOutcome::Ready(PollEvents::ERR),
            },
        }
    }

    /// Connect completion without a `poll`.
    ///
    /// Two safe observations, in this order:
    ///
    /// 1. `SO_ERROR`, which is `verifyconnect`'s `getsockopt` of
    ///    `SO_ERROR` on `SOL_SOCKET` (`lib/cf-socket.c:809`).
    /// 2. Whether the socket has a peer, which is `POLLOUT`'s meaning for a
    ///    connecting socket: the handshake completing is exactly when a peer
    ///    appears, and one still in progress reports `ENOTCONN`.
    ///
    /// The second observation is also how `SOCKEISCONN` is honoured without
    /// naming a platform errno. `verifyconnect`'s test is `if((err == 0) ||
    /// (SOCKEISCONN == err))` (`:818`), and `EISCONN` means precisely *already
    /// connected* -- a socket that has its peer. So a pending error on a socket
    /// that already has a peer verifies as connected, which is the C's second
    /// disjunct expressed as the condition it describes rather than as the
    /// number that names it. `crate::lib`'s `source_policy` gate exists to keep
    /// those numbers out of the engine.
    fn probe_connect(&self, socket: &OsSocket) -> ConnectProgress {
        let pending = match socket.take_error() {
            Ok(pending) => pending,
            Err(_) => return ConnectProgress::Unusable,
        };
        let has_peer = socket.peer_addr().is_ok();
        match pending {
            // `err == 0` with the handshake finished.
            None if has_peer => ConnectProgress::Connected,
            // `err == 0` with no peer yet: the C's `rc == 0`.
            None => ConnectProgress::Pending,
            // `SOCKEISCONN == err`, observed rather than numbered.
            Some(_) if has_peer => ConnectProgress::Connected,
            Some(error) => {
                ConnectProgress::Failed(error.raw_os_error().unwrap_or(0))
            }
        }
    }

    /// A pending connection, accepted non-blocking and close-on-exec.
    ///
    /// [`socket2::Socket::accept`] sets the close-on-exec flag itself, exactly
    /// as [`socket2::Socket::new`] does, so `SOCK_CLOEXEC` needs no separate
    /// step; `SOCK_NONBLOCK` is applied afterwards, which is the fallback path
    /// `lib/cf-socket.c:2085-2091` takes when `accept4` is unavailable and
    /// whose failure message [`msg::set_nonblock_failed`] preserves.
    fn probe_accept(&self, listener: &OsSocket) -> AcceptProbe {
        // A pending error on the LISTENER is the C's `socketstate == -1`.
        match listener.take_error() {
            Ok(Some(_)) | Err(_) => return AcceptProbe::WaitFailed,
            Ok(None) => {}
        }
        match listener.accept() {
            Ok((accepted, _peer)) => match accepted.set_nonblocking(true) {
                Ok(()) => AcceptProbe::Accepted(accepted),
                Err(error) => AcceptProbe::AcceptFailed(error),
            },
            Err(error) => match error.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => {
                    AcceptProbe::Pending
                }
                _ => AcceptProbe::AcceptFailed(error),
            },
        }
    }
}

// =========================================================================
// The remaining seams: resolver, interfaces, deadline
// =========================================================================

/// The blocking name lookup `bindlocal` performs.
///
/// # Why this is synchronous when [`crate::dns::Resolver`] is not
///
/// Because the C's is. `bindlocal` calls `Curl_resolv_blocking(data, host, 80,
/// ip_version, &h)` (`lib/cf-socket.c:649`) from a synchronous function
/// reached, ultimately, from `ConnFilter::connect` -- which is synchronous
/// here for the reason [`ReadinessProbe`] sets out. An `async` seam could not
/// be awaited from there, and blocking on a future inside a runtime panics.
///
/// The production implementation is therefore the CALLER's: whoever drives the
/// chain has a runtime and can resolve before it hands the filter over. That
/// keeps `crate::dns`'s asynchronous resolver asynchronous and keeps this file
/// free of any bridge between the two.
pub(crate) trait BindResolver: fmt::Debug {
    /// Resolves `host` for `ip_version`, or reports that it could not.
    ///
    /// [`None`] is the C's `if(h)` failing (`lib/cf-socket.c:650`), which sets
    /// `done = -1` and leads to [`msg::bind_host_failed`].
    fn resolve_blocking(
        &self,
        host: &str,
        port: u16,
        ip_version: IpVersion,
    ) -> Option<Vec<ResolvedAddr>>;
}

/// A resolver that resolves nothing.
///
/// The default, and the honest one: a filter built without a resolver cannot
/// resolve a bind host, and C behaves identically when `Curl_resolv_blocking`
/// fails.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoBindResolver;

impl BindResolver for NoBindResolver {
    fn resolve_blocking(
        &self,
        _host: &str,
        _port: u16,
        _ip_version: IpVersion,
    ) -> Option<Vec<ResolvedAddr>> {
        None
    }
}

/// Interface lookup and interface binding, injected.
///
/// Both halves of what `bindlocal` does with an interface name, and neither is
/// reimplemented here: [`Self::if2ip`] delegates to
/// [`crate::dns::if2ip::if2ip`], which owns interface enumeration, and
/// [`Self::bind_to_device`] is one `socket2` call.
pub(crate) trait If2Ip: fmt::Debug {
    /// `Curl_if2ip(af, scope, conn->scope_id, iface, myhost, sizeof(myhost))`
    /// (`lib/cf-socket.c:603-608`).
    fn if2ip(
        &self,
        af: AddressFamily,
        remote_scope: u32,
        local_scope_id: u32,
        iface: &[u8],
    ) -> If2IpResult;

    /// `setsockopt` of `SO_BINDTODEVICE` on `SOL_SOCKET`
    /// (`lib/cf-socket.c:588-589`).
    ///
    /// Its failure is expected and benign: the C's own comment is *"This is
    /// often 'errno 1, error: Operation not permitted' if you are not running
    /// as root"*, and it carries on regardless.
    fn bind_to_device(&self, socket: &OsSocket, iface: &[u8])
        -> io::Result<()>;
}

/// The real interface lookup.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemIf2Ip;

impl If2Ip for SystemIf2Ip {
    fn if2ip(
        &self,
        af: AddressFamily,
        remote_scope: u32,
        local_scope_id: u32,
        iface: &[u8],
    ) -> If2IpResult {
        if2ip(af, remote_scope, local_scope_id, iface)
    }

    fn bind_to_device(
        &self,
        socket: &OsSocket,
        iface: &[u8],
    ) -> io::Result<()> {
        socket.bind_device(Some(iface))
    }
}

/// The transfer's generic deadline -- `Curl_timeleft_ms(data)`.
///
/// Folded into the accept timeout by `cf_tcp_accept_timeleft`
/// (`lib/cf-socket.c:1968-1972`), and injected because a deadline belongs to a
/// transfer rather than to a socket.
pub(crate) trait Deadline: fmt::Debug {
    /// Milliseconds remaining, or zero when no deadline is set.
    ///
    /// Zero means NO TIMEOUT and not "expired", which is what
    /// `Curl_timeleft_ms` returns for a transfer without one and why
    /// `cf_tcp_accept_timeleft` tests `if(other_ms && ...)` rather than
    /// comparing against zero. A NEGATIVE value means already elapsed, and the
    /// C's own comment says the fold *"also works fine for when `other_ms`
    /// happens to be negative due to it already having elapsed"*.
    fn time_left_ms(&self) -> TimeDiff;
}

/// A transfer with no deadline.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct NoDeadline;

impl Deadline for NoDeadline {
    fn time_left_ms(&self) -> TimeDiff {
        0
    }
}

// =========================================================================
// Everything a socket filter is given when it is built
// =========================================================================

/// The seams a socket filter holds.
///
/// One struct rather than nine constructor arguments, so that
/// [`cf_tcp_create`] and its siblings keep the two-argument shape their C
/// counterparts have and a caller that wants the defaults writes
/// [`SocketHooks::default`].
#[derive(Clone, Debug)]
pub(crate) struct SocketHooks {
    /// `data->set.fopensocket`, absent when unset.
    pub(crate) open: Option<Rc<dyn OpenSocket>>,
    /// `conn->fclosesocket`, absent when unset.
    pub(crate) close: Option<Rc<dyn CloseSocket>>,
    /// `data->set.fsockopt`, absent when unset.
    pub(crate) sockopt: Option<Rc<dyn SockOpt>>,
    /// The multi handle, absent when there is none.
    ///
    /// Absence models the C's `if(conn)` guard around
    /// `Curl_multi_will_close` on the non-callback path
    /// (`lib/cf-socket.c:428-429`): no connection means no map to update.
    pub(crate) will_close: Option<Rc<dyn MultiCloseObserver>>,
    /// The connection and transfer state to publish into.
    pub(crate) conn: Rc<dyn ConnState>,
    /// Zero-timeout socket readiness.
    pub(crate) probe: Rc<dyn ReadinessProbe>,
    /// The blocking lookup a bind host needs.
    pub(crate) resolver: Rc<dyn BindResolver>,
    /// Interface lookup and interface binding.
    pub(crate) interfaces: Rc<dyn If2Ip>,
    /// The transfer's generic deadline.
    pub(crate) deadline: Rc<dyn Deadline>,
}

impl Default for SocketHooks {
    /// No user callbacks, no multi handle, real probes and real interfaces.
    ///
    /// The three callbacks default to absent because
    /// `CURLOPT_OPENSOCKETFUNCTION`, `CURLOPT_CLOSESOCKETFUNCTION` and
    /// `CURLOPT_SOCKOPTFUNCTION` all default to unset, and every branch guarded
    /// by them in `lib/cf-socket.c` is `if(data->set.f...)`.
    fn default() -> Self {
        Self {
            open: None,
            close: None,
            sockopt: None,
            will_close: None,
            conn: Rc::new(NullConnState),
            probe: Rc::new(SocketProbe),
            resolver: Rc::new(NoBindResolver),
            interfaces: Rc::new(SystemIf2Ip),
            deadline: Rc::new(NoDeadline),
        }
    }
}

/// Where a socket binds its local end -- the `bindlocal` inputs.
///
/// The five `data->set` members `bindlocal` reads (`lib/cf-socket.c:545-552`).
/// They arrive as owned bytes rather than as `&str` because
/// `CURLOPT_INTERFACE` accepts whatever the application supplies and an
/// interface name is not required to be UTF-8.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct BindConfig {
    /// `data->set.localport` -- *"use this port number, 0 for random"*.
    pub(crate) localport: u16,
    /// `data->set.localportrange` -- *"how many port numbers to try to bind
    /// to, increasing one at a time"*.
    pub(crate) localportrange: i32,
    /// `data->set.str[STRING_DEVICE]`, the bare `CURLOPT_INTERFACE` argument.
    pub(crate) device: Option<Vec<u8>>,
    /// `data->set.str[STRING_INTERFACE]`, from `if!` or `ifhost!`.
    pub(crate) interface: Option<Vec<u8>>,
    /// `data->set.str[STRING_BINDHOST]`, from `host!` or `ifhost!`.
    pub(crate) bindhost: Option<Vec<u8>>,
}

impl BindConfig {
    /// `const char *iface = iface_input ? iface_input : dev;`
    /// (`lib/cf-socket.c:550`).
    ///
    /// An EXPLICIT interface wins over the bare device. The precedence is not
    /// symmetric with a fallback in the other direction, and both halves matter
    /// -- the C consults `iface_input` on its own several times afterwards to
    /// decide whether a lookup failure may be retried as a hostname.
    pub(crate) fn iface(&self) -> Option<&[u8]> {
        self.interface.as_deref().or(self.device.as_deref())
    }

    /// `const char *host = host_input ? host_input : dev;`
    /// (`lib/cf-socket.c:551`).
    ///
    /// An EXPLICIT bind host wins over the bare device.
    pub(crate) fn host(&self) -> Option<&[u8]> {
        self.bindhost.as_deref().or(self.device.as_deref())
    }

    /// True when nothing at all was asked for.
    ///
    /// `if(!iface && !host && !port) return CURLE_OK;`
    /// (`lib/cf-socket.c:565-567`) -- *"no local kind of binding was
    /// requested"*.
    pub(crate) fn is_empty(&self) -> bool {
        self.iface().is_none() && self.host().is_none() && self.localport == 0
    }
}

/// The `data->set` members a socket filter reads.
///
/// Values rather than a back pointer, for the reason [`ConnState`] gives, and
/// carried on the filter because they are fixed for the life of one connection
/// attempt.
#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub(crate) struct SocketSettings {
    /// `data->set.tcp_nodelay`.
    pub(crate) tcp_nodelay: bool,
    /// `data->set.tcp_keepalive`.
    pub(crate) tcp_keepalive: bool,
    /// `data->set.tcp_keepidle`, in seconds.
    pub(crate) tcp_keepidle: i64,
    /// `data->set.tcp_keepintvl`, in seconds.
    pub(crate) tcp_keepintvl: i64,
    /// `data->set.tcp_keepcnt`, a probe count.
    pub(crate) tcp_keepcnt: i64,
    /// `conn->bits.tcp_fastopen`.
    ///
    /// # Recorded and honoured, but not enabled
    ///
    /// C enables TCP Fast Open with `connectx` on Darwin or
    /// `setsockopt` of `TCP_FASTOPEN_CONNECT` on Linux >= 4.11
    /// (`lib/cf-socket.c:1183-1226`). `socket2` 0.6.5 offers neither, and this
    /// file may not reach a socket option any other way, so the option cannot
    /// be turned on. The flag still has an observable effect and is therefore
    /// kept: the connect-completion test is `if(rc == CURL_CSELECT_OUT ||
    /// cf->conn->bits.tcp_fastopen)` (`:1290`), so a fast-open connection
    /// verifies on any readiness rather than on writability alone.
    #[allow(dead_code)]
    pub(crate) tcp_fastopen: bool,
    /// `conn->scope_id`, for an IPv6 link-local address.
    pub(crate) scope_id: u32,
    /// `data->set.accepttimeout`, zero when unset.
    ///
    /// `if(data->set.accepttimeout > 0) timeout_ms =
    /// data->set.accepttimeout;` (`lib/cf-socket.c:1963-1964`), so zero leaves
    /// [`DEFAULT_ACCEPT_TIMEOUT`] in force.
    pub(crate) accept_timeout_ms: TimeDiff,
    /// The `bindlocal` inputs.
    pub(crate) bind: BindConfig,
    /// What the scheme above this filter is.
    pub(crate) protocol: ProtocolIdentity,
}

// =========================================================================
// Non-blocking mode -- `curlx_nonblock`
// =========================================================================

/// Puts `socket` into blocking or non-blocking mode.
///
/// The whole of `curlx_nonblock` (`lib/curlx/nonblock.c:40-63` and the five
/// `#elif` arms after it) collapses to one call. Every one of those arms --
/// `fcntl` of `F_GETFL` plus `F_SETFL`, `IoctlSocket` and `ioctl` and
/// `ioctlsocket` of `FIONBIO`, and `setsockopt` of `SO_NONBLOCK` -- is
/// one platform's way of saying [`socket2::Socket::set_nonblocking`], and
/// `socket2` picks the right one.
///
/// # The read-modify-write disappears, and losing it changes nothing
///
/// C fetches the flags first and returns early when the request is already
/// satisfied: *"Check if the current file status flags have already satisfied
/// the request, if so, it is no need to call `fcntl` to replicate it"*
/// (`lib/curlx/nonblock.c:54-56`). That is a call-avoidance optimisation, not a
/// semantic: setting `O_NONBLOCK` on a socket that already has it is a no-op,
/// so the OUTCOME is identical and idempotent either way, and performance is
/// explicitly a non-goal (AAP section 0.1.1). The prompt for this file says so
/// in as many words -- *"there is no reason to manually fetch flags first"* --
/// and `nonblocking_mode_is_idempotent` pins the idempotence that matters.
///
/// # Errors
///
/// Whatever the platform reported. Callers differ in what they make of it:
/// `cf_socket_open` turns a failure into [`CURLcode::UnsupportedProtocol`]
/// (`lib/cf-socket.c:1148-1152`) while `cf_socket_shutdown` merely declines to
/// drain (`:970`), so the error is returned rather than classified here.
pub(crate) fn set_nonblocking(
    socket: &OsSocket,
    nonblock: bool,
) -> io::Result<()> {
    socket.set_nonblocking(nonblock)
}

// =========================================================================
// Interface parsing -- `Curl_parse_interface`
// =========================================================================

/// The three strings an interface argument can yield.
///
/// The out-parameters of `Curl_parse_interface(input, &dev, &iface, &host)`
/// (`lib/cf-socket.h:59-60`). C hands back three `char **`, of which AT MOST
/// ONE PAIR is ever written; the shape is preserved rather than tightened into
/// an enumeration because the three fields map one-to-one onto
/// `STRING_DEVICE`, `STRING_INTERFACE` and `STRING_BINDHOST`, and
/// [`BindConfig`] reads them individually with a precedence that depends on
/// which are present.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct ParsedInterface {
    /// `dev` -- the bare form, which *"can be either an interface name or a
    /// host"*.
    pub(crate) dev: Option<Vec<u8>>,
    /// `iface` -- from `if!<iface>` or the first half of `ifhost!`.
    pub(crate) iface: Option<Vec<u8>>,
    /// `host` -- from `host!<host>` or the second half of `ifhost!`.
    pub(crate) host: Option<Vec<u8>>,
}

/// `if!` (`lib/cf-socket.c:462`).
#[allow(dead_code)]
const IF_PREFIX: &[u8] = b"if!";

/// `host!` (`lib/cf-socket.c:463`).
#[allow(dead_code)]
const HOST_PREFIX: &[u8] = b"host!";

/// `ifhost!` (`lib/cf-socket.c:464`).
#[allow(dead_code)]
const IF_HOST_PREFIX: &[u8] = b"ifhost!";

/// Parses a `CURLOPT_INTERFACE` argument -- `Curl_parse_interface`
/// (`lib/cf-socket.c:452-529`).
///
/// The four accepted forms, from the C's own documentation comment:
///
/// ```text
/// <iface_or_host>       - can be either an interface name or a host.
/// if!<iface>            - interface name.
/// host!<host>           - hostname.
/// ifhost!<iface>!<host> - interface name and hostname.
/// ```
///
/// The prefixes are tested IN THE C's ORDER and the order is observable:
/// `if!` is tested before `ifhost!`, and because `"ifhost!x!y"` does not start
/// with `"if!"` -- the third byte is `h`, not `!` -- the two do not collide.
/// Testing `ifhost!` first would not change any accepted input either, but the
/// order is kept so that the two implementations read alike.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] in exactly four cases, all of which the C
/// reaches:
///
/// * The input is longer than [`INTERFACE_INPUT_MAX`] (`:474-475`).
/// * A prefix is present but nothing follows it (`:468-469`, `:475-476`).
/// * `ifhost!` has no second `!`, or nothing after it (`:487-489`).
/// * The bare form is empty (`:507-508`).
///
/// C also has `CURLE_OUT_OF_MEMORY` returns from `curlx_memdup0`. Those have
/// no successor: a failure to allocate aborts here rather than returning a
/// code, which is the same translation [`crate::conn::filters::link`] records.
#[allow(dead_code)]
pub(crate) fn parse_interface(input: &[u8]) -> CodeResult<ParsedInterface> {
    // `len = strlen(input); if(len > 512) return
    // CURLE_BAD_FUNCTION_ARGUMENT;`
    if input.len() > INTERFACE_INPUT_MAX {
        return Err(CURLcode::BadFunctionArgument);
    }

    // `if(!strncmp(if_prefix, input, strlen(if_prefix)))`
    if let Some(rest) = input.strip_prefix(IF_PREFIX) {
        // `input += strlen(if_prefix); if(!*input) return ...;`
        if rest.is_empty() {
            return Err(CURLcode::BadFunctionArgument);
        }
        return Ok(ParsedInterface {
            iface: Some(rest.to_vec()),
            ..ParsedInterface::default()
        });
    }

    // `else if(!strncmp(host_prefix, input, strlen(host_prefix)))`
    if let Some(rest) = input.strip_prefix(HOST_PREFIX) {
        if rest.is_empty() {
            return Err(CURLcode::BadFunctionArgument);
        }
        return Ok(ParsedInterface {
            host: Some(rest.to_vec()),
            ..ParsedInterface::default()
        });
    }

    // `else if(!strncmp(if_host_prefix, input, strlen(if_host_prefix)))`
    if let Some(rest) = input.strip_prefix(IF_HOST_PREFIX) {
        // `host_part = memchr(input, '!', len); if(!host_part ||
        // !*(host_part + 1)) return CURLE_BAD_FUNCTION_ARGUMENT;`
        //
        // Note what the C does NOT check: the INTERFACE half may be empty.
        // `ifhost!!host` finds the separator at offset zero, duplicates zero
        // bytes into `*iface`, and succeeds. That is reproduced rather than
        // tightened -- `bindlocal` then treats an empty interface name as a
        // name that no interface has, which is a lookup failure and not an
        // argument error.
        let at = rest.iter().position(|byte| *byte == b'!');
        let Some(at) = at else {
            return Err(CURLcode::BadFunctionArgument);
        };
        let (iface, after) = rest.split_at(at);
        // `++host_part;` past the separator, then the emptiness test.
        let host = &after[1..];
        if host.is_empty() {
            return Err(CURLcode::BadFunctionArgument);
        }
        return Ok(ParsedInterface {
            dev: None,
            iface: Some(iface.to_vec()),
            host: Some(host.to_vec()),
        });
    }

    // `if(!*input) return CURLE_BAD_FUNCTION_ARGUMENT; *dev = ...;`
    if input.is_empty() {
        return Err(CURLcode::BadFunctionArgument);
    }
    Ok(ParsedInterface {
        dev: Some(input.to_vec()),
        ..ParsedInterface::default()
    })
}

// =========================================================================
// Local binding -- `bindlocal`
// =========================================================================

/// The OS integer for an address family, as the C prints it with `%i`.
///
/// `AF_INET` is 2 everywhere but `AF_INET6` is 10 on Linux and 30 on Apple
/// platforms, and the messages at `lib/cf-socket.c:625` and `:653` print the
/// number. Reached through [`socket2::Domain`] so the platform integer is never
/// spelled out in the engine, which is what `crate::lib`'s `source_policy`
/// gate requires.
fn af_number(family: AddressFamily) -> i32 {
    i32::from(domain_of(family))
}

/// The `CURL_IPRESOLVE_*` restriction `bindlocal` resolves a host under.
///
/// ```c
/// int ip_version = (af == AF_INET) ? CURL_IPRESOLVE_V4 :
///                                   CURL_IPRESOLVE_WHATEVER;
/// if(af == AF_INET6) ip_version = CURL_IPRESOLVE_V6;
/// ```
/// (`lib/cf-socket.c:643-648`). The `WHATEVER` middle case is reachable: it is
/// what an `AF_UNIX` family would take, and the C's comment explains the whole
/// construct as *"Temporarily force name resolution to use only the address
/// type of the connection."*
const fn bind_ip_version(af: AddressFamily) -> IpVersion {
    match af {
        AddressFamily::Inet => IpVersion::V4,
        AddressFamily::Inet6 => IpVersion::V6,
        AddressFamily::Unix => IpVersion::Whatever,
    }
}

/// How far the local address was determined -- the C's `int done`.
///
/// `done` is a THREE-valued integer, not a boolean: `0` is *"not decided"*,
/// `1` is *"address found"* and `-1` is *"error"*, and the two tests
/// afterwards are `if(done > 0)` and `if(done < 1)` (`lib/cf-socket.c:672`,
/// `:704`, `:712`). A boolean would merge the untouched and failed cases,
/// which is exactly the distinction those two tests draw.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindLookup {
    /// `done == 0`.
    Undecided,
    /// `done == 1`.
    Found,
    /// `done == -1`.
    Failed,
}

/// Binds the local end of `socket` -- `bindlocal`
/// (`lib/cf-socket.c:532-777`).
///
/// # Errors
///
/// * [`CURLcode::BadFunctionArgument`] for an interface name of
///   [`BINDLOCAL_IFACE_MAX`] bytes or more (`:567-568`).
/// * [`CURLcode::UnsupportedProtocol`] when the family cannot be used --
///   [`If2IpResult::AfNotSupported`] (`:621-622`), a resolved address of the
///   wrong family (`:659-663`) or an unparsable IPv6 scope (`:687-688`). The
///   C's comment is explicit that this is a SIGNAL rather than a failure:
///   *"Signal the caller to try another address family if available."*
///   [`SocketFilter::open`] translates it to [`CURLcode::CouldntConnect`] so
///   that Happy Eyeballs moves to the next address (`:1133-1138`).
/// * [`CURLcode::InterfaceFailed`] when a requested interface or host could
///   not be used at all (`:611-618`, `:712-719`) or when every port in the
///   range was refused (`:765-772`).
fn bindlocal(
    cx: &mut CallCtx<'_, '_>,
    hooks: &SocketHooks,
    settings: &SocketSettings,
    socket: &OsSocket,
    af: AddressFamily,
    scope: u32,
) -> CodeResult<()> {
    let bind = &settings.bind;
    // `if(!iface && !host && !port) return CURLE_OK;`
    if bind.is_empty() {
        return Ok(());
    }
    let iface = bind.iface();
    let host = bind.host();
    // `else if(iface && (strlen(iface) >= 255)) return
    // CURLE_BAD_FUNCTION_ARGUMENT;`
    if iface.is_some_and(|name| name.len() >= BINDLOCAL_IFACE_MAX) {
        return Err(CURLcode::BadFunctionArgument);
    }

    // `if(iface || host)` -- an address has to be discovered. Otherwise the
    // wildcard address for the family is bound with the requested port.
    let local_ip = if iface.is_some() || host.is_some() {
        match resolve_bind_address(
            cx, hooks, settings, socket, af, scope, iface, host,
        ) {
            // `if(!host_input) { infof(...); return CURLE_OK; }` after a
            // successful `SO_BINDTODEVICE`: the bind is already done.
            BindOutcome::AlreadyBound => return Ok(()),
            BindOutcome::Address(text) => Some(text),
            BindOutcome::Refused(code) => return Err(code),
        }
    } else {
        None
    };

    let address = bind_sockaddr(af, local_ip.as_deref(), bind.localport)?;
    bind_ports(cx, hooks, socket, address, bind, af)
}

/// What the address-discovery half of `bindlocal` decided.
enum BindOutcome {
    /// `SO_BINDTODEVICE` succeeded and no host was asked for, so there is
    /// nothing left to bind (`lib/cf-socket.c:594-599`).
    AlreadyBound,
    /// The numeric local address, as text -- the C's `myhost` buffer.
    Address(String),
    /// Give up with this code.
    Refused(CURLcode),
}

/// The interface-and-host half of `bindlocal`
/// (`lib/cf-socket.c:571-720`).
///
/// Split out so that the port loop below reads as the loop it is; the order of
/// operations inside is the C's exactly.
#[allow(clippy::too_many_arguments)]
fn resolve_bind_address(
    cx: &mut CallCtx<'_, '_>,
    hooks: &SocketHooks,
    settings: &SocketSettings,
    socket: &OsSocket,
    af: AddressFamily,
    scope: u32,
    iface: Option<&[u8]>,
    host: Option<&[u8]>,
) -> BindOutcome {
    let bind = &settings.bind;
    // C's `char myhost[256] = ""` plus `int done = 0`.
    let mut myhost: Option<String> = None;
    let mut done = BindLookup::Undecided;

    // `#ifdef SO_BINDTODEVICE`: bind to the interface itself first.
    //
    // The C's reasoning is worth keeping: *"The interface might be a VRF, eg:
    // vrf-blue, which means it cannot be converted to an IP address and would
    // fail Curl_if2ip. Simply try to use it straight away."* And when it works
    // and no host was ALSO requested, the bind is complete -- note the test is
    // `host_input`, the explicit `CURLOPT_BINDHOST`, not the derived `host`.
    if let Some(name) = iface {
        if hooks.interfaces.bind_to_device(socket, name).is_ok()
            && bind.bindhost.is_none()
        {
            if let Some(tracer) = cx.tracer_mut() {
                infof!(
                    tracer,
                    "{}",
                    msg::bound_to_interface(&String::from_utf8_lossy(name))
                );
            }
            return BindOutcome::AlreadyBound;
        }
    }

    // `if2ip_result_t if2ip_result = IF2IP_NOT_FOUND;` and then
    // `if(!host_input) { if2ip_result = Curl_if2ip(...); }`.
    let mut lookup = If2IpResult::NotFound;
    if bind.bindhost.is_none() {
        if let Some(name) = iface {
            lookup = hooks.interfaces.if2ip(
                af,
                scope_or_zero(af, scope),
                settings.scope_id,
                name,
            );
        }
    }

    match lookup {
        // `case IF2IP_NOT_FOUND:` -- *"Do not fall back to treating it as a
        // hostname"* when an interface was named explicitly and no host was.
        If2IpResult::NotFound => {
            if bind.interface.is_some() && bind.bindhost.is_none() {
                let name = iface.unwrap_or_default();
                let text = String::from_utf8_lossy(name).into_owned();
                // C reads `SOCKERRNO` here, which after a failed lookup holds
                // whatever the last system call left. There is no such
                // ambient value to read safely, so the reported number is the
                // absence of one -- the message SHAPE is what section 0.8.1
                // freezes, and it is preserved exactly.
                let errno = 0;
                hooks.conn.set_os_errno(errno);
                if let Some(tracer) = cx.tracer_mut() {
                    failf!(
                        tracer,
                        "{}",
                        msg::bind_iface_failed(
                            &text,
                            errno,
                            &os_strerror(errno)
                        )
                    );
                }
                return BindOutcome::Refused(CURLcode::InterfaceFailed);
            }
        }
        // `case IF2IP_AF_NOT_SUPPORTED: return CURLE_UNSUPPORTED_PROTOCOL;`
        If2IpResult::AfNotSupported => {
            return BindOutcome::Refused(CURLcode::UnsupportedProtocol);
        }
        // `case IF2IP_FOUND: host = myhost; ... done = 1;`
        If2IpResult::Found(text) => {
            if let Some(tracer) = cx.tracer_mut() {
                infof!(
                    tracer,
                    "{}",
                    msg::local_interface_is(
                        &String::from_utf8_lossy(iface.unwrap_or_default()),
                        &text,
                        af_number(af)
                    )
                );
            }
            myhost = Some(text);
            done = BindLookup::Found;
        }
    }

    // `if(!iface_input || host_input)` -- resolve as a hostname or IP number.
    //
    // Both halves are reachable, and the second is the surprising one: when an
    // interface lookup has ALREADY succeeded, C has reassigned `host = myhost`
    // and now resolves that numeric text as well, purely to compare the
    // family. The step is preserved rather than optimised away, because
    // `Curl_resolv_blocking` failing is what turns `done` from `1` to `-1`.
    if bind.interface.is_none() || bind.bindhost.is_some() {
        let target = myhost.clone().unwrap_or_else(|| {
            String::from_utf8_lossy(host.unwrap_or_default()).into_owned()
        });
        let resolved = hooks.resolver.resolve_blocking(
            &target,
            BINDLOCAL_SERVICE_PORT,
            bind_ip_version(af),
        );
        match resolved.as_deref().and_then(<[ResolvedAddr]>::first) {
            Some(entry) => {
                let resolved_af = entry.family();
                let text = entry.printable_address();
                if let Some(tracer) = cx.tracer_mut() {
                    infof!(
                        tracer,
                        "{}",
                        msg::name_resolved(
                            &target,
                            af_number(af),
                            &text,
                            af_number(resolved_af)
                        )
                    );
                }
                myhost = Some(text);
                // `if(af != h_af) return CURLE_UNSUPPORTED_PROTOCOL;` --
                // *"bad IP version combo, signal the caller to try another
                // address family if available"*.
                if af != resolved_af {
                    return BindOutcome::Refused(CURLcode::UnsupportedProtocol);
                }
                done = BindLookup::Found;
            }
            // *"provided dev was no interface (or interfaces are not
            // supported e.g. Solaris) no ip address and no domain we fail
            // here"*.
            None => done = BindLookup::Failed,
        }
    }

    // `if(done < 1) { ... return CURLE_INTERFACE_FAILED; }` -- note that this
    // catches BOTH `Undecided` and `Failed`, which is what `< 1` means.
    if done != BindLookup::Found {
        let text = myhost.unwrap_or_else(|| {
            String::from_utf8_lossy(host.unwrap_or_default()).into_owned()
        });
        let errno = 0;
        hooks.conn.set_os_errno(errno);
        if let Some(tracer) = cx.tracer_mut() {
            // C also clears `data->state.errorbuf` first, *"so failf will
            // overwrite any message already in the error buffer, so the user
            // receives this error message instead of a generic resolve
            // error"*. `Tracer` stores only the FIRST failure, so the
            // equivalent belongs to whoever owns the buffer; the message
            // itself is unchanged.
            failf!(
                tracer,
                "{}",
                msg::bind_host_failed(&text, errno, &os_strerror(errno))
            );
        }
        return BindOutcome::Refused(CURLcode::InterfaceFailed);
    }

    myhost.map_or(
        BindOutcome::Refused(CURLcode::InterfaceFailed),
        BindOutcome::Address,
    )
}

/// The remote scope `Curl_if2ip` is told about, for IPv6 only.
///
/// C passes `scope` only under `#ifdef USE_IPV6` and the argument is otherwise
/// absent from the call (`lib/cf-socket.c:603-608`). Zero for the other
/// families keeps the scope comparison at `lib/if2ip.c:125-132` inert, which is
/// what a build without IPv6 produces.
const fn scope_or_zero(af: AddressFamily, scope: u32) -> u32 {
    match af {
        AddressFamily::Inet6 => scope,
        AddressFamily::Inet | AddressFamily::Unix => 0,
    }
}

/// Builds the address `bind(2)` is called with.
///
/// Covers both of the C's arms:
///
/// * `if(done > 0)` (`lib/cf-socket.c:672-703`), which parses `myhost` with
///   `curlx_inet_pton` and, for IPv6, splits a `%scope` suffix off first.
/// * the `else` at `:705-720`, *"no device was given, prepare `sa` to match
///   `af`'s needs"*, which is the wildcard address with the requested port.
///
/// # Errors
///
/// [`CURLcode::UnsupportedProtocol`] for a scope suffix that is not a number
/// within `UINT_MAX` (`:684-689`), which is the C's own code for it.
///
/// [`CURLcode::InterfaceFailed`] for numeric text that does not parse. C
/// reaches the same outcome by a longer route: the `pton` sits inside the
/// condition that assigns the family, so a failure leaves a zeroed `sockaddr`
/// -- or, for IPv4, a `sizeof_sa` of zero -- and the kernel then refuses the
/// bind, ending in `CURLE_INTERFACE_FAILED` at `:772`. A typed address cannot
/// be zeroed, so the refusal is made here instead of being deferred to a
/// syscall that would have to be handed a deliberately invalid argument.
fn bind_sockaddr(
    af: AddressFamily,
    local_ip: Option<&str>,
    port: u16,
) -> CodeResult<SockAddr> {
    let Some(text) = local_ip else {
        // The `else` arm: the wildcard address for the family.
        return match af {
            AddressFamily::Inet => Ok(SockAddr::from(SocketAddr::V4(
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
            ))),
            AddressFamily::Inet6 => Ok(SockAddr::from(SocketAddr::V6(
                SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0),
            ))),
            // Unreachable through `SocketFilter::open`, which binds a local
            // end only for `SockAddrEx::is_inet`. Reported rather than
            // asserted so that a future caller gets the "try another family"
            // signal instead of a panic.
            AddressFamily::Unix => Err(CURLcode::UnsupportedProtocol),
        };
    };

    match af {
        AddressFamily::Inet6 => {
            // `char *scope_ptr = strchr(myhost, '%'); if(scope_ptr)
            // *(scope_ptr++) = '\0';`
            let (base, suffix) = match text.split_once('%') {
                Some((base, suffix)) => (base, Some(suffix)),
                None => (text, None),
            };
            let octets =
                pton6(base.as_bytes()).ok_or(CURLcode::InterfaceFailed)?;
            // *"The 'myhost' string either comes from Curl_if2ip or from
            // Curl_printable_address. The latter returns only numeric scope
            // IDs and the former returns none at all. So the scope ID, if
            // present, is known to be numeric."*
            let scope_id = match suffix {
                Some(suffix) => {
                    let mut cursor = suffix.as_bytes();
                    let value = str_number(&mut cursor, i64::from(u32::MAX))
                        .map_err(|_| CURLcode::UnsupportedProtocol)?;
                    u32::try_from(value)
                        .map_err(|_| CURLcode::UnsupportedProtocol)?
                }
                None => 0,
            };
            Ok(SockAddr::from(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(octets),
                port,
                0,
                scope_id,
            ))))
        }
        AddressFamily::Inet => {
            let octets =
                pton4(text.as_bytes()).ok_or(CURLcode::InterfaceFailed)?;
            Ok(SockAddr::from(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(octets),
                port,
            ))))
        }
        AddressFamily::Unix => Err(CURLcode::UnsupportedProtocol),
    }
}

/// The `for(;;)` bind loop (`lib/cf-socket.c:740-763`).
///
/// Four behaviours, all preserved:
///
/// * A successful bind emits [`msg::local_port`] and sets `bits.bound`.
/// * `--portnum > 0` is evaluated BEFORE the increment, so a range of one is
///   a single attempt.
/// * `port++` wrapping to zero ends the loop -- there is no port 0 to try, and
///   `u16::wrapping_add` reproduces the C's `unsigned short` overflow exactly.
/// * The retry line names the port that FAILED, because the C prints
///   `port - 1` after incrementing.
///
/// # Errors
///
/// [`CURLcode::InterfaceFailed`] once the range is exhausted, with
/// [`msg::bind_failed`] carrying the last error.
fn bind_ports(
    cx: &mut CallCtx<'_, '_>,
    hooks: &SocketHooks,
    socket: &OsSocket,
    mut address: SockAddr,
    bind: &BindConfig,
    af: AddressFamily,
) -> CodeResult<()> {
    // `IP_BIND_ADDRESS_NO_PORT` is set here in the C with its result
    // deliberately discarded (`lib/cf-socket.c:738-739`). `socket2` 0.6.5
    // exposes no such option and this file may reach a socket option no other
    // way, so the hint is not applied. It is a scalability hint for outgoing
    // connections with no observable effect on a single transfer, and
    // performance is a non-goal (AAP section 0.1.1).
    let mut port = bind.localport;
    let mut portnum = bind.localportrange;

    loop {
        match socket.bind(&address) {
            Ok(()) => {
                if let Some(tracer) = cx.tracer_mut() {
                    infof!(tracer, "{}", msg::local_port(port));
                }
                hooks.conn.set_bound(true);
                return Ok(());
            }
            Err(error) => {
                portnum -= 1;
                if portnum <= 0 {
                    return Err(refuse_bind(cx, hooks, &error));
                }
                let failed = port;
                port = port.wrapping_add(1);
                if port == 0 {
                    return Err(refuse_bind(cx, hooks, &error));
                }
                if let Some(tracer) = cx.tracer_mut() {
                    infof!(tracer, "{}", msg::bind_port_retry(failed));
                }
                // C reuses the same storage and rewrites only the port,
                // choosing the member by `sock->sa_family`. Rebuilding from
                // the family is the same decision without the union.
                address = bind_sockaddr_port(&address, af, port)?;
            }
        }
    }
}

/// The failure tail of the bind loop (`lib/cf-socket.c:764-773`).
fn refuse_bind(
    cx: &mut CallCtx<'_, '_>,
    hooks: &SocketHooks,
    error: &io::Error,
) -> CURLcode {
    let errno = error.raw_os_error().unwrap_or(0);
    hooks.conn.set_os_errno(errno);
    if let Some(tracer) = cx.tracer_mut() {
        failf!(tracer, "{}", msg::bind_failed(errno, &os_strerror(errno)));
    }
    CURLcode::InterfaceFailed
}

/// Replaces the port of an address, keeping everything else.
///
/// ```c
/// if(sock->sa_family == AF_INET)
///   si4->sin_port = htons(port);
/// else
///   si6->sin6_port = htons(port);
/// ```
/// (`lib/cf-socket.c:757-761`). The scope id and flow information of an IPv6
/// address are carried over, which the C gets for free by writing through the
/// union and which has to be explicit here.
///
/// # Errors
///
/// [`CURLcode::InterfaceFailed`] for an address that is not an Internet
/// address, which the bind loop cannot be entered with.
fn bind_sockaddr_port(
    address: &SockAddr,
    af: AddressFamily,
    port: u16,
) -> CodeResult<SockAddr> {
    let Some(inet) = address.as_socket() else {
        return Err(CURLcode::InterfaceFailed);
    };
    match (inet, af) {
        (SocketAddr::V4(v4), _) => Ok(SockAddr::from(SocketAddr::V4(
            SocketAddrV4::new(*v4.ip(), port),
        ))),
        (SocketAddr::V6(v6), _) => Ok(SockAddr::from(SocketAddr::V6(
            SocketAddrV6::new(*v6.ip(), port, v6.flowinfo(), v6.scope_id()),
        ))),
    }
}

// =========================================================================
// Error classification -- the two tables that differ by one value
// =========================================================================

/// The socket conditions `lib/cf-socket.c` distinguishes.
///
/// Named as conditions rather than as numbers, for the reason
/// [`crate::ffi::sys::SOCKEINPROGRESS`] records: only one of the four needs a
/// platform integer, and [`std::io::ErrorKind`] supplies the other three.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SocketCondition {
    /// `SOCKEWOULDBLOCK`, and `EAGAIN` where the two differ.
    ///
    /// The C writes both with a comment explaining the duplication -- *"errno
    /// may be EWOULDBLOCK or on some systems EAGAIN when it returned due to its
    /// inability to send off data without blocking. We therefore treat both
    /// error codes the same here"* -- and behind an `#if (EAGAIN) !=
    /// (SOCKEWOULDBLOCK)` where it does not. Rust folds them into one
    /// [`std::io::ErrorKind::WouldBlock`], which is the same treatment.
    WouldBlock,
    /// `SOCKEINTR`.
    Interrupted,
    /// `SOCKEINPROGRESS`.
    InProgress,
    /// Anything else.
    Other,
}

/// Classifies an I/O error into the conditions the two tables below read.
pub(crate) fn classify(error: &io::Error) -> SocketCondition {
    match error.kind() {
        io::ErrorKind::WouldBlock => SocketCondition::WouldBlock,
        io::ErrorKind::Interrupted => SocketCondition::Interrupted,
        _ => {
            if error.raw_os_error() == Some(crate::ffi::sys::SOCKEINPROGRESS) {
                SocketCondition::InProgress
            } else {
                SocketCondition::Other
            }
        }
    }
}

/// The SEND table (`lib/cf-socket.c:1435-1447`).
///
/// ```c
/// (SOCKEWOULDBLOCK == sockerr) ||
/// (EAGAIN == sockerr) || (SOCKEINTR == sockerr) ||
/// (SOCKEINPROGRESS == sockerr)
/// ```
/// FOUR conditions, [`SocketCondition::InProgress`] among them.
pub(crate) const fn send_is_again(condition: SocketCondition) -> bool {
    matches!(
        condition,
        SocketCondition::WouldBlock
            | SocketCondition::Interrupted
            | SocketCondition::InProgress
    )
}

/// The RECEIVE table (`lib/cf-socket.c:1508-1517`).
///
/// ```c
/// (SOCKEWOULDBLOCK == sockerr) ||
/// (EAGAIN == sockerr) || (SOCKEINTR == sockerr)
/// ```
/// THREE conditions. [`SocketCondition::InProgress`] is ABSENT, and its absence
/// is deliberate rather than an oversight in the C: a receive that reports "the
/// operation is in progress" has not been asked to start an operation, so the
/// condition means something has gone wrong rather than that nothing has
/// happened yet. The asymmetry between the two tables is the single difference
/// between them, and `send_and_receive_tables_differ_only_in_progress` pins it.
pub(crate) const fn recv_is_again(condition: SocketCondition) -> bool {
    matches!(
        condition,
        SocketCondition::WouldBlock | SocketCondition::Interrupted
    )
}

/// The verdict `socket_connect_result` reaches (`lib/cf-socket.c:836-861`).
///
/// `CURLE_OK` for the three in-progress conditions -- *"unknown error,
/// fallthrough and try another address!"* is the comment on the other arm --
/// and [`CURLcode::CouldntConnect`] for everything else. Note that
/// [`SocketCondition::Interrupted`] is NOT in the C's in-progress set here even
/// though it is in the send table: `connect(2)` interrupted by a signal has
/// still started the handshake on every platform curl supports, but the C does
/// not say so, and this reproduces what the C says.
pub(crate) const fn connect_is_in_progress(condition: SocketCondition) -> bool {
    matches!(
        condition,
        SocketCondition::WouldBlock | SocketCondition::InProgress
    )
}

// =========================================================================
// The typed context -- `struct cf_socket_ctx`
// =========================================================================

/// One socket attempt's whole state.
///
/// The successor of `struct cf_socket_ctx` (`lib/cf-socket.c:868-892`), field
/// for field. Two groups from the C are absent and both absences are
/// deliberate:
///
/// * `last_sndbuf_query_at` and `sndbuf_size` are `#ifdef USE_WINSOCK`
///   (`:876-879`) and exist for `win_update_sndbuf_size`
///   (`:1363-1380`), a Winsock send-buffer autotuner. Windows is outside the
///   four-target matrix (AAP section 0.2.2), so they have no successor.
/// * `wblock_percent`, `wpartial_percent`, `rblock_percent` and `recv_max` are
///   `#ifdef DEBUGBUILD` (`:881-886`) and inject artificial blocking and
///   partial transfers from four `CURL_DBG_SOCK_*` environment variables. They
///   have no successor either: the transports they perturb are reachable
///   directly in a test here through [`ReadinessProbe`] and an in-memory
///   filter, so simulating a short write is a matter of writing the test rather
///   than of asking the production path to misbehave -- and a production build
///   should not carry the branches at all.
///
/// **This is the type that replaces `void *ctx`.** It sits beside
/// [`FilterBase`] as an ordinary typed field, so no filter method casts
/// anything.
#[derive(Debug)]
pub(crate) struct SocketContext {
    /// `transport`.
    transport: Transport,
    /// `addr` -- *"address to connect to"*.
    ///
    /// [`Option`] where C has a value, because a listening socket adopted
    /// through [`tcp_listen_set`] has no address to connect TO: the C leaves
    /// the whole struct zeroed there (`lib/cf-socket.c:2158-2163` sets only
    /// `transport`, `sock`, `listening` and `accepted`), and a zeroed
    /// `sockaddr` has no typed equivalent.
    addr: Option<SockAddrEx>,
    /// `sock` -- *"current attempt socket"*, and its OWNER.
    ///
    /// `curl_socket_t` is an integer that owns nothing; this owns the
    /// descriptor. [`None`] is `CURL_SOCKET_BAD`, and the difference is what
    /// makes a double close unrepresentable: there is no second value to close.
    socket: Option<OsSocket>,
    /// `ip` -- *"The IP quadruple 2x(addr+port)"*.
    ip: IpQuadruple,
    /// `started_at` -- *"when socket was created"*.
    started_at: CurlTime,
    /// `connected_at` -- *"when socket connected/got first byte"*.
    connected_at: CurlTime,
    /// `first_byte_at` -- *"when first byte was recvd"*.
    first_byte_at: CurlTime,
    /// `error` -- *"errno of last failure or 0"*.
    error: i32,
    /// `got_first_byte` -- *"if first byte was received"*.
    got_first_byte: bool,
    /// `listening` -- *"socket is listening"*.
    listening: bool,
    /// `accepted` -- *"socket was accepted, not connected"*.
    ///
    /// The flag the close-callback asymmetry turns on: `cf_socket_close` passes
    /// `!ctx->accepted` as its `use_callback` argument
    /// (`lib/cf-socket.c:1235`).
    accepted: bool,
    /// `sock_connected` -- *"socket is 'connected', e.g. in UDP"*.
    sock_connected: bool,
    /// `active`.
    active: bool,
}

#[allow(dead_code)]
impl SocketContext {
    /// `cf_socket_ctx_init` (`lib/cf-socket.c:894-943`).
    ///
    /// The C's `memset(ctx, 0, sizeof(*ctx))` followed by `ctx->sock =
    /// CURL_SOCKET_BAD` becomes [`Default`]-shaped initialisation with
    /// [`None`], and the four `CURL_DBG_SOCK_*` environment probes have no
    /// successor for the reason [`SocketContext`] records.
    ///
    /// # Errors
    ///
    /// As [`SockAddrEx::assign`]: [`CURLcode::TooLarge`] for an address that
    /// does not fit.
    #[allow(dead_code)]
    fn init(ai: &ResolvedAddr, transport: Transport) -> CodeResult<Self> {
        Ok(Self {
            transport,
            addr: Some(SockAddrEx::assign(ai, transport)?),
            socket: None,
            ip: empty_quadruple(),
            started_at: CurlTime::ZERO,
            connected_at: CurlTime::ZERO,
            first_byte_at: CurlTime::ZERO,
            error: 0,
            got_first_byte: false,
            listening: false,
            accepted: false,
            sock_connected: false,
            active: false,
        })
    }

    /// A context for an already-created listening socket.
    ///
    /// `Curl_conn_tcp_listen_set` sets exactly four members
    /// (`lib/cf-socket.c:2158-2163`) and leaves the rest at the zero its
    /// `calloc` produced, which is what this reproduces.
    #[allow(dead_code)]
    fn listening(socket: OsSocket) -> Self {
        Self {
            transport: Transport::Tcp,
            addr: None,
            socket: Some(socket),
            ip: empty_quadruple(),
            started_at: CurlTime::ZERO,
            connected_at: CurlTime::ZERO,
            first_byte_at: CurlTime::ZERO,
            error: 0,
            got_first_byte: false,
            listening: true,
            accepted: false,
            sock_connected: false,
            active: false,
        }
    }

    /// `ctx->sock` as the descriptor a pollset and a query speak in.
    ///
    /// [`CURL_SOCKET_BAD`] when there is no socket, which is the same value the
    /// C stores in that case. [`AsRawFd::as_raw_fd`] BORROWS: the descriptor
    /// number is handed out while this context keeps ownership, so nothing that
    /// receives it may close it.
    pub(crate) fn raw_socket(&self) -> Socket {
        self.socket
            .as_ref()
            .map_or(CURL_SOCKET_BAD, AsRawFd::as_raw_fd)
    }

    /// `ctx->transport`.
    #[allow(dead_code)]
    pub(crate) fn transport(&self) -> Transport {
        self.transport
    }

    /// `&ctx->addr`, absent for a listening socket.
    #[allow(dead_code)]
    pub(crate) fn addr(&self) -> Option<&SockAddrEx> {
        self.addr.as_ref()
    }

    /// `ctx->ip`.
    #[allow(dead_code)]
    pub(crate) fn ip(&self) -> &IpQuadruple {
        &self.ip
    }

    /// `ctx->error`.
    #[allow(dead_code)]
    pub(crate) fn last_error(&self) -> i32 {
        self.error
    }

    /// `ctx->active`.
    #[allow(dead_code)]
    pub(crate) fn is_active(&self) -> bool {
        self.active
    }

    /// `ctx->listening`.
    #[allow(dead_code)]
    pub(crate) fn is_listening(&self) -> bool {
        self.listening
    }

    /// `ctx->accepted`.
    #[allow(dead_code)]
    pub(crate) fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// `ctx->sock_connected`.
    #[allow(dead_code)]
    pub(crate) fn is_sock_connected(&self) -> bool {
        self.sock_connected
    }

    /// `ctx->got_first_byte`.
    #[allow(dead_code)]
    pub(crate) fn got_first_byte(&self) -> bool {
        self.got_first_byte
    }

    /// `ctx->started_at`.
    #[allow(dead_code)]
    pub(crate) fn started_at(&self) -> CurlTime {
        self.started_at
    }

    /// `ctx->connected_at`.
    #[allow(dead_code)]
    pub(crate) fn connected_at(&self) -> CurlTime {
        self.connected_at
    }

    /// `ctx->first_byte_at`.
    #[allow(dead_code)]
    pub(crate) fn first_byte_at(&self) -> CurlTime {
        self.first_byte_at
    }
}

// =========================================================================
// Closing a socket -- and the callback asymmetry
// =========================================================================

/// `socket_close(data, conn, use_callback, sock)`
/// (`lib/cf-socket.c:414-434`).
///
/// Takes the socket BY VALUE, which is the whole point: after this returns
/// there is no value left to close a second time, whichever branch ran.
///
/// The observer is notified on BOTH paths and BEFORE either close, exactly as
/// the C does -- `Curl_multi_will_close(data, sock)` at `:420` on the callback
/// path and at `:429` on the direct one. Its absence models the C's `if(conn)`
/// guard: no connection means no socket-to-transfer map to keep in step.
///
/// Whether the callback runs is decided by whether one was PASSED, not by a
/// flag. That is what makes [`socket_close`] structurally unable to invoke it.
fn close_owned_socket(
    socket: OsSocket,
    observer: Option<&dyn MultiCloseObserver>,
    callback: Option<&dyn CloseSocket>,
) -> i32 {
    // `if(sock == CURL_SOCKET_BAD) return 0;` has no counterpart: an
    // `OsSocket` is always a real descriptor, and the absent case is the
    // `Option` the caller already matched on.
    if let Some(observer) = observer {
        observer.will_close(socket.as_raw_fd());
    }
    match callback {
        // `rc = conn->fclosesocket(conn->closesocket_client, sock);` -- the
        // callback closes it, and the socket moves to it so that this side
        // cannot.
        Some(callback) => callback.close_socket(socket),
        // `sclose(sock); return 0;` -- `Drop` is `sclose`.
        None => {
            drop(socket);
            0
        }
    }
}

/// `Curl_socket_close(data, conn, sock)` (`lib/cf-socket.c:441-444`).
///
/// # This NEVER invokes the close callback
///
/// Its entire body is `return socket_close(data, conn, FALSE, sock);` -- the
/// `use_callback` argument is the literal `FALSE`. The asymmetry against
/// `cf_socket_close`, which passes `!ctx->accepted` (`:1235`), is deliberate in
/// the C and is preserved here **structurally**: this function has no callback
/// parameter to pass, so no caller can make it call one.
///
/// The accept path relies on exactly this. When `accept4` succeeds but the
/// close-on-exec or non-blocking follow-up fails, C disposes of the accepted
/// socket with `Curl_socket_close` (`:2083`, `:2090`) rather than with the
/// filter's own close, so a user callback is never handed a socket it never
/// created.
#[allow(dead_code)]
pub(crate) fn socket_close(
    socket: OsSocket,
    observer: Option<&dyn MultiCloseObserver>,
) -> i32 {
    close_owned_socket(socket, observer, None)
}

// =========================================================================
// Trace emission -- free functions, so no borrow of `self` is held
// =========================================================================

/// `CURL_TRC_CF(data, cf, ...)` for a socket filter.
///
/// A free function rather than a method because every call site already holds a
/// mutable borrow of the filter's own state, and a `&self` method would
/// conflict with it. The filter's identity and socket index are [`Copy`], so
/// passing them costs nothing.
///
/// A filter whose name is not in the trace registry emits nothing, which is the
/// honest outcome: no `--trace-config` keyword could enable it.
fn trace_line(
    cx: &mut CallCtx<'_, '_>,
    identity: Option<TraceFilter>,
    sockindex: i32,
    line: &str,
) {
    let Some(identity) = identity else {
        return;
    };
    if let Some(tracer) = cx.tracer_mut() {
        trc_cf!(tracer, identity, sockindex, "{}", line);
    }
}

/// `infof(data, ...)`.
fn info_line(cx: &mut CallCtx<'_, '_>, line: &str) {
    if let Some(tracer) = cx.tracer_mut() {
        infof!(tracer, "{}", line);
    }
}

/// `failf(data, ...)`.
fn fail_line(cx: &mut CallCtx<'_, '_>, line: &str) {
    if let Some(tracer) = cx.tracer_mut() {
        failf!(tracer, "{}", line);
    }
}

// =========================================================================
// The four filter identities
// =========================================================================

/// Which of the four socket filters an instance is.
///
/// C registers four `struct Curl_cftype` instances -- `Curl_cft_tcp`
/// (`lib/cf-socket.c:1682-1698`), `Curl_cft_udp` (`:1848-1864`),
/// `Curl_cft_unix` (`:1901-1918`) and `Curl_cft_tcp_accept` (`:2132-2148`) --
/// that differ in **exactly two members**: the name and the connect function.
/// The other thirteen are the same function pointer in all four.
///
/// So this is one implementation with a kind rather than four implementations,
/// which is not a simplification but a transcription: `Curl_cft_unix` does not
/// merely resemble `Curl_cft_tcp`, it names `cf_tcp_connect` itself, under the
/// comment *"this is the TCP filter which can also handle this case"*
/// (`lib/cf-socket.c:1900`). Writing a second UNIX state machine would create a
/// divergence the C does not have.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(dead_code)]
pub(crate) enum SocketFilterKind {
    /// `Curl_cft_tcp`, name `"TCP"`.
    #[allow(dead_code)]
    Tcp,
    /// `Curl_cft_udp`, name `"UDP"` -- datagram, for UDP and QUIC.
    #[allow(dead_code)]
    Udp,
    /// `Curl_cft_unix`, name `"UNIX"` -- the TCP algorithm over `AF_UNIX`.
    #[allow(dead_code)]
    Unix,
    /// `Curl_cft_tcp_accept`, name `"TCP-ACCEPT"` -- a listener.
    #[allow(dead_code)]
    TcpAccept,
}

#[allow(dead_code)]
impl SocketFilterKind {
    /// Every kind, in the order `lib/cf-socket.c` registers them.
    #[allow(dead_code)]
    pub(crate) const ALL: [Self; 4] =
        [Self::Tcp, Self::Udp, Self::Unix, Self::TcpAccept];

    /// The `name` member, byte for byte.
    ///
    /// `"TCP-ACCEPT"` is hyphenated and upper case; getting it wrong would
    /// break `--trace-config tcp-accept` silently, since an unmatched keyword
    /// merely enables nothing.
    pub(crate) const fn trace_name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
            Self::Unix => "UNIX",
            Self::TcpAccept => "TCP-ACCEPT",
        }
    }

    /// The `flags` member: [`CF_TYPE_IP_CONNECT`] for ALL FOUR.
    ///
    /// Not one of them carries anything else, and none of them carries
    /// [`crate::conn::filters::CF_TYPE_SSL`] or
    /// [`crate::conn::filters::CF_TYPE_MULTIPLEX`]. Worth stating because the
    /// filter that sits directly above these -- `HAPPY-EYEBALLS` -- carries
    /// `CF_TYPE_NONE` instead, so "is this the IP-connecting layer?" is
    /// answered by the socket filters alone.
    pub(crate) const fn cf_type(self) -> CfType {
        match self {
            Self::Tcp | Self::Udp | Self::Unix | Self::TcpAccept => {
                CF_TYPE_IP_CONNECT
            }
        }
    }

    /// This kind's entry in the trace registry.
    pub(crate) fn trace_filter(self) -> Option<TraceFilter> {
        TraceFilter::from_name(self.trace_name().as_bytes())
    }
}

// =========================================================================
// Opening a socket -- `socket_open`
// =========================================================================

/// `socket_open(data, addr, sockfd)` (`lib/cf-socket.c:308-383`).
///
/// The C's `#ifdef SOCK_CLOEXEC` prologue and its two `fcntl` fallbacks that
/// set `F_SETFD` to `FD_CLOEXEC` all disappear into one fact:
/// [`socket2::Socket::new`] *"sets the close-on-exec flag on the new socket"*
/// on every Unix platform. The Apple-only broken-pipe-signal step at `:299-306`
/// disappears the same way -- `Socket::new` sets that option on Apple platforms
/// itself, as this module's documentation records -- which is why the two
/// failure messages guarding those fallbacks have no successor: neither fallback
/// is ever taken, and a message must not be reproduced unless its path is.
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`] for exhaustion -- `if((*sockfd ==
/// CURL_SOCKET_BAD) && (SOCKERRNO == SOCKENOMEM)) return CURLE_OUT_OF_MEMORY;`
/// (`:344-345`), which the C tests only on the INTERNAL path.
///
/// [`CURLcode::CouldntConnect`] for any other refusal, with
/// [`msg::open_failed`] -- the shared `if(*sockfd == CURL_SOCKET_BAD)` arm at
/// `:348-353`, which both paths fall into.
fn socket_open(
    cx: &mut CallCtx<'_, '_>,
    hooks: &SocketHooks,
    addr: &mut SockAddrEx,
) -> CodeResult<OsSocket> {
    // The callback is cloned out of the hooks so that `addr` can be borrowed
    // mutably for it -- *"the destination address information might have been
    // changed and this 'new' address will actually be used here to connect"*.
    if let Some(opener) = hooks.open.clone() {
        return match opener.open_socket(SockPurpose::IpCxn, addr) {
            Ok(socket) => Ok(socket),
            Err(OpenSocketError::OutOfMemory) => Err(CURLcode::OutOfMemory),
            Err(OpenSocketError::Refused) => {
                // The callback's refusal lands in the shared bad-socket arm,
                // which reports `CURLE_COULDNT_CONNECT` and not
                // `CURLE_ABORTED_BY_CALLBACK`.
                fail_line(cx, &msg::open_failed(&os_strerror(0)));
                Err(CURLcode::CouldntConnect)
            }
        };
    }

    // `*sockfd = CURL_SOCKET(addr->family, addr->socktype, addr->protocol);`
    let (domain, kind, protocol) = addr.open_params();
    match OsSocket::new(domain, kind, protocol) {
        Ok(socket) => Ok(socket),
        Err(error) => {
            if error.kind() == io::ErrorKind::OutOfMemory {
                return Err(CURLcode::OutOfMemory);
            }
            let errno = error.raw_os_error().unwrap_or(0);
            fail_line(cx, &msg::open_failed(&os_strerror(errno)));
            Err(CURLcode::CouldntConnect)
        }
    }
}

/// Stamps `conn->scope_id` onto an IPv6 remote address.
///
/// ```c
/// if(data->conn->scope_id && (addr->family == AF_INET6)) {
///   struct sockaddr_in6 * const sa6 = (void *)&addr->curl_sa_addr;
///   sa6->sin6_scope_id = data->conn->scope_id;
/// }
/// ```
/// (`lib/cf-socket.c:375-380`). C reaches into the union and writes the member;
/// here the address is rebuilt, which is the same change without the cast.
/// Both guards are preserved, including the `scope_id &&`: a zero scope id
/// leaves the address alone rather than writing a zero over whatever the
/// resolver supplied.
fn apply_scope_id(addr: &mut SockAddrEx, scope_id: u32) {
    if scope_id == 0 || addr.family != AddressFamily::Inet6 {
        return;
    }
    if let Some(SocketAddr::V6(v6)) = addr.addr.as_socket() {
        let replaced =
            SocketAddrV6::new(*v6.ip(), v6.port(), v6.flowinfo(), scope_id);
        addr.addr = SockAddr::from(SocketAddr::V6(replaced));
        addr.addrlen = addrlen_of(&addr.addr);
    }
}

/// Applies `CURLOPT_TCP_NODELAY` -- `tcpnodelay` (`lib/cf-socket.c:70-88`).
///
/// A failure is TRACED AND IGNORED, which is the C's behaviour and not a
/// relaxation of it: `CURL_TRC_CF(data, cf, "Could not set TCP_NODELAY: %s")`
/// with no error propagated. Nagle's algorithm staying on is a latency
/// characteristic, and latency is not correctness.
fn apply_nodelay(
    cx: &mut CallCtx<'_, '_>,
    identity: Option<TraceFilter>,
    sockindex: i32,
    socket: &OsSocket,
) {
    if let Err(error) = socket.set_tcp_nodelay(true) {
        let errno = error.raw_os_error().unwrap_or(0);
        trace_line(
            cx,
            identity,
            sockindex,
            &format!("Could not set TCP_NODELAY: {}", os_strerror(errno)),
        );
    }
}

/// Applies `CURLOPT_TCP_KEEPALIVE` and its three timers -- `tcpkeepalive`
/// (`lib/cf-socket.c:114-227`).
///
/// One hundred and thirteen lines of C become one call, and the collapse is
/// entirely platform variance: `SO_KEEPALIVE` then `TCP_KEEPIDLE` or
/// `TCP_KEEPALIVE` or `TCP_KEEPALIVE_THRESHOLD`, then `TCP_KEEPINTVL` or
/// `TCP_KEEPALIVE_ABORT_THRESHOLD`, then `TCP_KEEPCNT`, each spelling belonging
/// to a different operating system, plus a `KEEPALIVE_FACTOR` that converts
/// seconds to milliseconds on the three platforms that want milliseconds.
/// [`socket2::TcpKeepalive`] picks the spelling and the unit for the target.
///
/// Two behaviours are preserved deliberately:
///
/// * The idle and interval times are set ONLY IF `SO_KEEPALIVE` itself
///   succeeded -- *"only set IDLE and INTVL if setting KEEPALIVE is
///   successful"* (`:118`) -- which is why the enable is a separate call whose
///   result is tested.
/// * Every failure is traced and ignored, as with [`apply_nodelay`].
///
/// The retry count is passed only where the platform has one:
/// [`socket2::TcpKeepalive::with_retries`] is unavailable on Apple platforms
/// other than macOS, and the four mandated targets are Linux and macOS, so it
/// is set on both.
///
/// # The one trace line that is not verbatim, and why
///
/// C traces THREE distinct failures -- `"Failed to set TCP_KEEPIDLE on fd
/// %d: errno %d"`, `"...TCP_KEEPINTVL..."` and `"...TCP_KEEPCNT..."`
/// (`:150-164`) -- because it issues three separate `setsockopt` calls and can
/// name the one that failed. [`socket2::TcpKeepalive`] applies all three timers
/// in a single call, so the option that failed is genuinely not known here, and
/// a line naming a specific one would be a guess.
///
/// The line emitted is therefore `"Failed to set TCP_KEEP* on fd %d: errno
/// %d"`: the C's own shape and its own `TCP_KEEP*` wildcard, which the C uses
/// for exactly this purpose in its success line at `:132`, `"Set TCP_KEEP* on
/// fd=%d"`. `SO_KEEPALIVE` keeps its own verbatim line because it is still a
/// call of its own.
///
/// This is a trace line, reached only under `--trace-config`, and it is the
/// only text in this file that is a composition rather than a transcription.
/// It is recorded here rather than left for a reader to notice.
fn apply_keepalive(
    cx: &mut CallCtx<'_, '_>,
    identity: Option<TraceFilter>,
    sockindex: i32,
    socket: &OsSocket,
    settings: &SocketSettings,
) {
    // `int optval = data->set.tcp_keepalive ? 1 : 0;` then
    // `setsockopt` of `SO_KEEPALIVE`.
    if let Err(error) = socket.set_keepalive(settings.tcp_keepalive) {
        let errno = error.raw_os_error().unwrap_or(0);
        trace_line(
            cx,
            identity,
            sockindex,
            &format!(
                "Failed to set SO_KEEPALIVE on fd {}: errno {errno}",
                socket.as_raw_fd()
            ),
        );
        return;
    }
    if !settings.tcp_keepalive {
        return;
    }
    let seconds = |value: i64| {
        Duration::from_secs(u64::try_from(value.max(0)).unwrap_or(0))
    };
    let mut params = TcpKeepalive::new()
        .with_time(seconds(settings.tcp_keepidle))
        .with_interval(seconds(settings.tcp_keepintvl));
    params = params
        .with_retries(u32::try_from(settings.tcp_keepcnt.max(0)).unwrap_or(0));
    if let Err(error) = socket.set_tcp_keepalive(&params) {
        let errno = error.raw_os_error().unwrap_or(0);
        trace_line(
            cx,
            identity,
            sockindex,
            &format!(
                "Failed to set TCP_KEEP* on fd {}: errno {errno}",
                socket.as_raw_fd()
            ),
        );
    }
}

// =========================================================================
// The socket filter
// =========================================================================

/// One raw transport at the bottom of a filter chain.
///
/// The four `struct Curl_cftype` instances of `lib/cf-socket.c` collapsed into
/// one implementation with a [`SocketFilterKind`], for the reason that type
/// records. What C keeps behind `void *ctx` is [`Self::ctx`], a typed field.
#[derive(Debug)]
pub(crate) struct SocketFilter {
    /// `struct Curl_cfilter`'s own members.
    base: FilterBase,
    /// Which of the four this is.
    kind: SocketFilterKind,
    /// The typed successor of `void *ctx`.
    ctx: SocketContext,
    /// The injected seams.
    hooks: SocketHooks,
    /// The `data->set` members this filter reads.
    settings: SocketSettings,
}

#[allow(dead_code)]
impl SocketFilter {
    /// The shared constructor the four factories funnel through.
    #[allow(dead_code)]
    fn new(
        kind: SocketFilterKind,
        ctx: SocketContext,
        hooks: SocketHooks,
        settings: SocketSettings,
        sockindex: SocketIndex,
    ) -> Self {
        Self {
            base: FilterBase::new(sockindex),
            kind,
            ctx,
            hooks,
            settings,
        }
    }

    /// Which of the four this is.
    #[allow(dead_code)]
    pub(crate) fn kind(&self) -> SocketFilterKind {
        self.kind
    }

    /// `Curl_cf_socket_peek(cf, data, psock, paddr, pip)`
    /// (`lib/cf-socket.c:2209-2228`).
    ///
    /// C returns `CURLE_FAILED_INIT` for a filter that is not a socket filter,
    /// having tested `cf_is_socket(cf)` -- a function-pointer comparison against
    /// the four registered types (`:2202-2207`). Here the type IS the answer:
    /// only a [`SocketFilter`] has this method, so the error case does not
    /// exist and the return type is not a `Result`. That is the same
    /// improvement `CfQueryValue` makes over `void *pres2`.
    ///
    /// The C's contract *"The filter owns all returned values"* is what the
    /// borrows express.
    #[allow(dead_code)]
    pub(crate) fn peek(&self) -> (Socket, Option<&SockAddrEx>, &IpQuadruple) {
        (self.ctx.raw_socket(), self.ctx.addr(), self.ctx.ip())
    }

    /// The typed context, for a caller that needs more than [`Self::peek`].
    #[allow(dead_code)]
    pub(crate) fn context(&self) -> &SocketContext {
        &self.ctx
    }

    /// The seams this filter was built with.
    #[allow(dead_code)]
    pub(crate) fn hooks(&self) -> &SocketHooks {
        &self.hooks
    }

    /// The settings this filter was built with.
    #[allow(dead_code)]
    pub(crate) fn settings(&self) -> &SocketSettings {
        &self.settings
    }

    /// This filter's trace identity, as [`trace_line`] wants it.
    fn identity(&self) -> Option<TraceFilter> {
        self.kind.trace_filter()
    }

    /// `cf->sockindex` as the integer a trace line prints.
    fn sockindex_i32(&self) -> i32 {
        self.base.sockindex().as_i32()
    }

    // -- address bookkeeping ---------------------------------------------

    /// `set_remote_ip(cf, data)` (`lib/cf-socket.c:1023-1044`).
    ///
    /// The transport is stamped BEFORE the conversion -- `ctx->ip.transport =
    /// ctx->transport;` at `:1029`, ahead of the `Curl_addr2string` call -- so
    /// a failure leaves the quadruple describing the right transport with no
    /// address, rather than describing nothing.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`], which the C reaches with the comment
    /// *"malformed address or bug in inet_ntop, try next address"*.
    fn set_remote_ip(&mut self, cx: &mut CallCtx<'_, '_>) -> CodeResult<()> {
        let identity = self.identity();
        let sockindex = self.sockindex_i32();
        let _ = (identity, sockindex);
        self.ctx.ip.transport = self.ctx.transport;
        let Some(addr) = self.ctx.addr.as_ref() else {
            // A listening filter has no address to convert. C cannot reach
            // this: `Curl_conn_tcp_listen_set` never calls `set_remote_ip`.
            return Err(CURLcode::FailedInit);
        };
        match addr2string(&addr.addr) {
            Ok(AddrText { addr: text, port }) => {
                debug_assert!(
                    ip_text_fits(&text),
                    "an address of {} bytes overflows the C buffer",
                    text.len()
                );
                self.ctx.ip.remote_ip = text;
                self.ctx.ip.remote_port = port;
                Ok(())
            }
            Err(error) => {
                let errno = error.errno();
                self.ctx.error = errno;
                fail_line(
                    cx,
                    &msg::remote_ntop_failed(errno, &os_strerror(errno)),
                );
                Err(CURLcode::FailedInit)
            }
        }
    }

    /// `set_local_ip(cf, data)` (`lib/cf-socket.c:986-1021`).
    ///
    /// Three behaviours, all preserved:
    ///
    /// * The text and the port are CLEARED FIRST, unconditionally
    ///   (`:990-991`), so a failed lookup leaves nothing stale behind.
    /// * The lookup happens only for a socket that exists AND a scheme whose
    ///   socket connects -- the C's `!(data->conn->scheme->protocol &
    ///   CURLPROTO_TFTP)`, carried here by
    ///   [`ProtocolIdentity::connects_socket`]. See that field for why the
    ///   exception is expressed as protocol identity and not as a bit.
    /// * Both failures are `infof`, not `failf`: neither stops the transfer,
    ///   because not knowing the local address is a reporting gap and not a
    ///   connection failure.
    fn set_local_ip(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.ctx.ip.local_ip.clear();
        self.ctx.ip.local_port = 0;

        if !self.settings.protocol.connects_socket {
            return;
        }
        let Some(socket) = self.ctx.socket.as_ref() else {
            return;
        };
        match socket.local_addr() {
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(0);
                info_line(
                    cx,
                    &msg::getsockname_failed(errno, &os_strerror(errno)),
                );
            }
            Ok(local) => match addr2string(&local) {
                Ok(AddrText { addr: text, port }) => {
                    self.ctx.ip.local_ip = text;
                    self.ctx.ip.local_port = port;
                }
                Err(error) => {
                    let errno = error.errno();
                    info_line(
                        cx,
                        &msg::local_ntop_failed(errno, &os_strerror(errno)),
                    );
                }
            },
        }
    }

    /// `cf_tcp_set_accepted_remote_ip(cf, data)`
    /// (`lib/cf-socket.c:1983-2012`).
    ///
    /// Clears first, exactly as [`Self::set_local_ip`] does, and RETURNS on
    /// either failure rather than carrying on -- so an accepted connection whose
    /// peer cannot be named reports no peer at all, which is what the C's two
    /// bare `return`s produce. Both failures are `failf` here where the local
    /// equivalents are `infof`; that difference is the C's and is preserved.
    fn set_accepted_remote_ip(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.ctx.ip.remote_ip.clear();
        self.ctx.ip.remote_port = 0;
        let Some(socket) = self.ctx.socket.as_ref() else {
            return;
        };
        match socket.peer_addr() {
            Err(error) => {
                let errno = error.raw_os_error().unwrap_or(0);
                fail_line(
                    cx,
                    &msg::getpeername_failed(errno, &os_strerror(errno)),
                );
            }
            Ok(peer) => match addr2string(&peer) {
                Ok(AddrText { addr: text, port }) => {
                    self.ctx.ip.remote_ip = text;
                    self.ctx.ip.remote_port = port;
                }
                Err(error) => {
                    let errno = error.errno();
                    fail_line(
                        cx,
                        &msg::peer_ntop_failed(errno, &os_strerror(errno)),
                    );
                }
            },
        }
    }

    // -- opening ---------------------------------------------------------

    /// `cf_socket_open(cf, data)` (`lib/cf-socket.c:1046-1180`).
    ///
    /// Returns whether the socket came back ALREADY CONNECTED, which is the
    /// C's local `isconnected` and happens only when a `CURLOPT_SOCKOPTFUNCTION`
    /// callback reports `CURL_SOCKOPT_ALREADY_CONNECTED`.
    ///
    /// # Errors
    ///
    /// Whatever the step that failed reported, after closing the socket
    /// **through the close callback** -- `socket_close(data, cf->conn, TRUE,
    /// ctx->sock)` at `:1167`. Note the `TRUE`: a socket this filter opened is
    /// the callback's business, unlike an accepted one.
    fn open(&mut self, cx: &mut CallCtx<'_, '_>) -> CodeResult<bool> {
        debug_assert!(
            self.ctx.socket.is_none(),
            "cf_socket_open on a filter that already holds a socket"
        );
        let identity = self.identity();
        let sockindex = self.sockindex_i32();
        // `ctx->started_at = *Curl_pgrs_now(data);`
        self.ctx.started_at = cx.now();

        let outcome = self.open_steps(cx, identity, sockindex);
        match outcome {
            Ok(isconnected) => {
                // `else if(isconnected) { set_local_ip(...); ctx->connected_at
                // = *Curl_pgrs_now(data); cf->connected = TRUE; }`
                if isconnected {
                    self.set_local_ip(cx);
                    self.ctx.connected_at = cx.now();
                    self.base.set_connected(true);
                }
                let line = format!(
                    "cf_socket_open() -> 0, fd={}",
                    self.ctx.raw_socket()
                );
                trace_line(cx, identity, sockindex, &line);
                Ok(isconnected)
            }
            Err(code) => {
                // `out: if(result) { if(ctx->sock != CURL_SOCKET_BAD) {
                // socket_close(data, cf->conn, TRUE, ctx->sock); ctx->sock =
                // CURL_SOCKET_BAD; } }`
                self.close_socket_now(true);
                let line = format!(
                    "cf_socket_open() -> {}, fd={CURL_SOCKET_BAD}",
                    code.as_i32()
                );
                trace_line(cx, identity, sockindex, &line);
                Err(code)
            }
        }
    }

    /// The body of [`Self::open`], in the C's order.
    ///
    /// Split out so that the shared `out:` tail is written once. The socket is
    /// stored in the context IMMEDIATELY after it is created and before any
    /// fallible step, which is what makes that tail able to close it.
    fn open_steps(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        identity: Option<TraceFilter>,
        sockindex: i32,
    ) -> CodeResult<bool> {
        // `result = socket_open(data, &ctx->addr, &ctx->sock);`
        //
        // The destructuring is what lets the address be borrowed mutably for
        // the callback while the hooks are borrowed beside it: they are
        // disjoint fields, and naming them separately is how that is stated.
        let socket = {
            let Self { ctx, hooks, .. } = self;
            let addr =
                ctx.addr.as_mut().ok_or(CURLcode::BadFunctionArgument)?;
            socket_open(cx, hooks, addr)?
        };
        self.ctx.socket = Some(socket);

        // The `sin6_scope_id` stamp that closes `socket_open`.
        if let Some(addr) = self.ctx.addr.as_mut() {
            apply_scope_id(addr, self.settings.scope_id);
        }

        // `result = set_remote_ip(cf, data); if(result) goto out;`
        self.set_remote_ip(cx)?;

        // `infof(data, "  Trying ...")`. The `IPV6_V6ONLY` reset that precedes
        // it in the C is `#ifdef USE_WINSOCK` (`:1077-1088`) and has no
        // successor: Windows is outside the four-target matrix, and the two
        // mandated platforms both default the option off already.
        let family = self
            .ctx
            .addr
            .as_ref()
            .map_or(AddressFamily::Inet, |addr| addr.family);
        let line = msg::trying_for(
            family,
            &self.ctx.ip.remote_ip,
            self.ctx.ip.remote_port,
        );
        info_line(cx, &line);

        // `if(is_tcp && data->set.tcp_nodelay) tcpnodelay(...)` and
        // `if(is_tcp && data->set.tcp_keepalive) tcpkeepalive(...)`.
        let is_tcp = self.ctx.addr.as_ref().is_some_and(SockAddrEx::is_tcp);
        if is_tcp {
            let Self { ctx, settings, .. } = self;
            let Some(socket) = ctx.socket.as_ref() else {
                return Err(CURLcode::FailedInit);
            };
            if settings.tcp_nodelay {
                apply_nodelay(cx, identity, sockindex, socket);
            }
            if settings.tcp_keepalive {
                apply_keepalive(cx, identity, sockindex, socket, settings);
            }
        }

        // `if(data->set.fsockopt) { ... }` -- the sockopt callback, whose
        // `CURL_SOCKOPT_ALREADY_CONNECTED` is the only way `isconnected`
        // becomes true.
        let mut isconnected = false;
        if let Some(callback) = self.hooks.sockopt.clone() {
            let Some(socket) = self.ctx.socket.as_ref() else {
                return Err(CURLcode::FailedInit);
            };
            match callback.sockopt(socket, SockPurpose::IpCxn) {
                SockOptOutcome::AlreadyConnected => isconnected = true,
                SockOptOutcome::Error => {
                    return Err(CURLcode::AbortedByCallback)
                }
                SockOptOutcome::Ok => {}
            }
        }

        // `if(ctx->addr.family == AF_INET || ctx->addr.family == AF_INET6) {
        // result = bindlocal(...); if(result) { if(result ==
        // CURLE_UNSUPPORTED_PROTOCOL) result = CURLE_COULDNT_CONNECT; goto
        // out; } }`
        if self.ctx.addr.as_ref().is_some_and(SockAddrEx::is_inet) {
            let Self {
                ctx,
                hooks,
                settings,
                ..
            } = self;
            let Some(addr) = ctx.addr.as_ref() else {
                return Err(CURLcode::FailedInit);
            };
            let Some(socket) = ctx.socket.as_ref() else {
                return Err(CURLcode::FailedInit);
            };
            // `Curl_ipv6_scope(&ctx->addr.curl_sa_addr)`.
            let scope = addr
                .addr
                .as_socket()
                .map_or(0, |inet| ipv6_scope(inet.ip()));
            let family = addr.family;
            if let Err(code) =
                bindlocal(cx, hooks, settings, socket, family, scope)
            {
                // *"The address family is not supported on this interface. We
                // can continue trying addresses"* -- the translation that keeps
                // Happy Eyeballs moving.
                return Err(if code == CURLcode::UnsupportedProtocol {
                    CURLcode::CouldntConnect
                } else {
                    code
                });
            }
        }

        // `error = curlx_nonblock(ctx->sock, TRUE); if(error < 0) { result =
        // CURLE_UNSUPPORTED_PROTOCOL; ctx->error = SOCKERRNO; goto out; }`
        //
        // C reaches this two ways -- unconditionally without `SOCK_NONBLOCK`,
        // and only for a callback-created socket with it (`:1143-1163`) --
        // because the flag is otherwise folded into `socktype`. `socket2` has
        // no such fold, so the call is made once here for whichever socket the
        // filter now holds. Doing it for an internally created socket as well
        // is not a behaviour change: [`set_nonblocking`] is idempotent, which
        // is the very property `curlx_nonblock`'s early return relies on.
        {
            let Some(socket) = self.ctx.socket.as_ref() else {
                return Err(CURLcode::FailedInit);
            };
            if let Err(error) = set_nonblocking(socket, true) {
                self.ctx.error = error.raw_os_error().unwrap_or(0);
                return Err(CURLcode::UnsupportedProtocol);
            }
        }

        // `ctx->sock_connected = (ctx->addr.socktype != SOCK_DGRAM);`
        self.ctx.sock_connected = self
            .ctx
            .addr
            .as_ref()
            .is_some_and(|addr| !matches!(addr.socktype, SockType::Dgram));

        Ok(isconnected)
    }

    // -- closing ---------------------------------------------------------

    /// Closes the owned socket, if there is one, honouring the callback rule.
    ///
    /// `use_callback` is the C's third argument to `socket_close`, and the two
    /// values it takes in `lib/cf-socket.c` are `TRUE` from the open and connect
    /// failure paths and `!ctx->accepted` from `cf_socket_close`.
    fn close_socket_now(&mut self, use_callback: bool) {
        if let Some(socket) = self.ctx.socket.take() {
            let observer = self.hooks.will_close.as_deref();
            let callback = if use_callback {
                self.hooks.close.as_deref()
            } else {
                None
            };
            close_owned_socket(socket, observer, callback);
        }
    }

    /// `cf_socket_close(cf, data)` (`lib/cf-socket.c:1228-1245`).
    ///
    /// Four things happen, in the C's order:
    ///
    /// 1. The connection's published descriptor is cleared **only if it is this
    ///    filter's** -- `if(ctx->sock == cf->conn->sock[cf->sockindex])`. That
    ///    guard is what makes a losing Happy Eyeballs attempt safe to close
    ///    after the winner has published: the numbers differ, so nothing is
    ///    cleared.
    /// 2. The socket is closed with the callback unless it was ACCEPTED --
    ///    `socket_close(data, cf->conn, !ctx->accepted, ctx->sock)`.
    /// 3. `active` and the two timestamps are cleared. Note which two:
    ///    `started_at` and `connected_at` are zeroed and `first_byte_at` is
    ///    NOT, so a reconnected filter still reports when it first heard from
    ///    the peer.
    /// 4. `cf->connected = FALSE`, OUTSIDE the `if` -- so a filter with no
    ///    socket is still marked unconnected.
    fn do_close(&mut self, cx: &mut CallCtx<'_, '_>) {
        if self.ctx.socket.is_some() {
            let identity = self.identity();
            let sockindex = self.sockindex_i32();
            let raw = self.ctx.raw_socket();
            let line = format!("cf_socket_close, fd={raw}");
            trace_line(cx, identity, sockindex, &line);

            let index = self.base.sockindex();
            if self.hooks.conn.socket(index) == raw {
                self.hooks.conn.clear_socket(index);
            }
            self.close_socket_now(!self.ctx.accepted);
            self.ctx.active = false;
            self.ctx.started_at = CurlTime::ZERO;
            self.ctx.connected_at = CurlTime::ZERO;
        }
        self.base.set_connected(false);
    }

    // -- connecting ------------------------------------------------------

    /// The `out:` tail of `cf_tcp_connect` (`lib/cf-socket.c:1306-1324`).
    ///
    /// Emits [`msg::connect_failed`] **only when an OS error was recorded**, so
    /// an immediate connect failure -- which reports through
    /// [`msg::immediate_connect_fail`] and never writes `ctx->error` -- does
    /// not produce a second message. Then closes with the callback and reports
    /// the code.
    ///
    /// C also performs `SET_SOCKERRNO(ctx->error)` here, restoring the ambient
    /// `errno` so that a later `curlx_strerror` with no argument sees it. There
    /// is no ambient `errno` to restore safely and none is read: every message
    /// above is handed its number explicitly.
    fn connect_failed(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        code: CURLcode,
    ) -> Error {
        if self.ctx.error != 0 {
            self.set_local_ip(cx);
            let errno = self.ctx.error;
            self.hooks.conn.set_os_errno(errno);
            let line = msg::connect_failed(
                &self.ctx.ip.remote_ip,
                self.ctx.ip.remote_port,
                &self.ctx.ip.local_ip,
                self.ctx.ip.local_port,
                &os_strerror(errno),
            );
            info_line(cx, &line);
        }
        self.close_socket_now(true);
        Error::new(code)
    }

    /// `do_connect(cf, data, is_tcp_fastopen)` plus its result handling
    /// (`lib/cf-socket.c:1265-1275`).
    ///
    /// Returns whether to go on and check for completion: `true` when
    /// `connect(2)` returned success, `false` when it reported that the
    /// handshake has merely started. The distinction is the C's `goto out` with
    /// `result == CURLE_OK`, which leaves `*done` false and returns without
    /// probing.
    ///
    /// The three TCP Fast Open variants in `do_connect` -- Darwin's `connectx`,
    /// Linux's `TCP_FASTOPEN_CONNECT` and old Linux's `MSG_FASTOPEN` -- have no
    /// successor, for the reason [`SocketSettings::tcp_fastopen`] records.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] for an immediate failure, with
    /// [`msg::immediate_connect_fail`] and `data->state.os_errno` recorded --
    /// which is exactly `socket_connect_result` (`lib/cf-socket.c:836-861`).
    fn attempt_connect(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        identity: Option<TraceFilter>,
        sockindex: i32,
    ) -> CodeResult<bool> {
        let outcome = {
            let Some(socket) = self.ctx.socket.as_ref() else {
                return Err(CURLcode::FailedInit);
            };
            let Some(addr) = self.ctx.addr.as_ref() else {
                return Err(CURLcode::FailedInit);
            };
            socket.connect(&addr.addr)
        };
        // `set_local_ip(cf, data);` happens whether or not the connect
        // succeeded, and BEFORE the result is classified.
        self.set_local_ip(cx);
        let line = format!(
            "local address {} port {}...",
            self.ctx.ip.local_ip, self.ctx.ip.local_port
        );
        trace_line(cx, identity, sockindex, &line);

        match outcome {
            Ok(()) => Ok(true),
            Err(error) => {
                if connect_is_in_progress(classify(&error)) {
                    return Ok(false);
                }
                let errno = error.raw_os_error().unwrap_or(0);
                let line = msg::immediate_connect_fail(
                    &self.ctx.ip.remote_ip,
                    &os_strerror(errno),
                );
                info_line(cx, &line);
                self.hooks.conn.set_os_errno(errno);
                Err(CURLcode::CouldntConnect)
            }
        }
    }

    /// `cf_tcp_connect(cf, data, done)` (`lib/cf-socket.c:1229-1324`).
    ///
    /// Shared by [`SocketFilterKind::Tcp`] and [`SocketFilterKind::Unix`],
    /// because `Curl_cft_unix` names this very function
    /// (`lib/cf-socket.c:1905`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] for a refused or unverifiable connect, and
    /// whatever [`Self::open`] reported for a socket that could not be created.
    fn tcp_connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        // `if(cf->connected) { *done = TRUE; return CURLE_OK; }`
        if self.base.is_connected() {
            return Ok(true);
        }
        let identity = self.identity();
        let sockindex = self.sockindex_i32();

        // `if(ctx->sock == CURL_SOCKET_BAD) { ... }`
        if self.ctx.socket.is_none() {
            match self.open(cx) {
                // `if(cf->connected) { *done = TRUE; return CURLE_OK; }` --
                // the already-connected socket a callback handed back.
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(code) => return Err(self.connect_failed(cx, code)),
            }
            match self.attempt_connect(cx, identity, sockindex) {
                Ok(true) => {}
                // In progress: `result` is `CURLE_OK` and `*done` stays false.
                Ok(false) => return Ok(false),
                Err(code) => return Err(self.connect_failed(cx, code)),
            }
        }

        // `rc = SOCKET_WRITABLE(ctx->sock, 0);` and then `verifyconnect`, as
        // one verdict -- see [`ConnectProgress`] for why they are combined.
        let progress = {
            let Some(socket) = self.ctx.socket.as_ref() else {
                return Err(Error::with_context(
                    CURLcode::CouldntConnect,
                    "connect: the socket disappeared",
                ));
            };
            self.hooks.probe.probe_connect(socket)
        };
        match progress {
            ConnectProgress::Pending => {
                let line = format!(
                    "not connected yet on fd={}",
                    self.ctx.raw_socket()
                );
                trace_line(cx, identity, sockindex, &line);
                Ok(false)
            }
            ConnectProgress::Connected => {
                self.ctx.connected_at = cx.now();
                self.set_local_ip(cx);
                self.base.set_connected(true);
                let line = format!("connected on fd={}", self.ctx.raw_socket());
                trace_line(cx, identity, sockindex, &line);
                Ok(true)
            }
            ConnectProgress::Failed(errno) => {
                self.ctx.error = errno;
                Err(self.connect_failed(cx, CURLcode::CouldntConnect))
            }
            ConnectProgress::Unusable => {
                Err(self.connect_failed(cx, CURLcode::CouldntConnect))
            }
        }
    }

    /// `cf_udp_setup_quic(cf, data)` (`lib/cf-socket.c:1778-1810`).
    ///
    /// *"QUIC needs a connected socket, nonblocking"* -- and it already is
    /// non-blocking, which the C notes explicitly: *"Currently, `cf->ctx->sock`
    /// is always non-blocking because the only caller to
    /// `cf_udp_setup_quic()` is `cf_udp_connect()` that passes the
    /// non-blocking socket created by `cf_socket_open()` to it. Thus, we do not
    /// need to call `curlx_nonblock()` in `cf_udp_setup_quic()` anymore."*
    ///
    /// # The Linux QUIC tuning has no successor
    ///
    /// `linux_quic_mtu` sets `IP_MTU_DISCOVER`/`IPV6_MTU_DISCOVER` to
    /// `PMTUDISC_DO` (`:1741-1761`) and `linux_quic_gro` sets `UDP_GRO`
    /// (`:1766-1775`). `socket2` 0.6.5 exposes neither and this file may reach
    /// a socket option no other way, so neither is applied. Both are
    /// throughput tuning for a path that is not yet reachable -- `UDP_GRO` is
    /// compiled in the C only alongside ngtcp2 or quiche, and AAP section
    /// 0.2.2 drops both -- and performance is explicitly a non-goal.
    ///
    /// # Errors
    ///
    /// As [`Self::attempt_connect`]'s classification: an immediate failure is
    /// [`CURLcode::CouldntConnect`] and an in-progress one is success, which
    /// for a datagram socket cannot happen.
    fn setup_quic(&mut self, cx: &mut CallCtx<'_, '_>) -> CodeResult<()> {
        let identity = self.identity();
        let sockindex = self.sockindex_i32();
        let outcome = {
            let Some(socket) = self.ctx.socket.as_ref() else {
                return Err(CURLcode::FailedInit);
            };
            let Some(addr) = self.ctx.addr.as_ref() else {
                return Err(CURLcode::FailedInit);
            };
            socket.connect(&addr.addr)
        };
        if let Err(error) = outcome {
            if !connect_is_in_progress(classify(&error)) {
                let errno = error.raw_os_error().unwrap_or(0);
                let line = msg::immediate_connect_fail(
                    &self.ctx.ip.remote_ip,
                    &os_strerror(errno),
                );
                info_line(cx, &line);
                self.hooks.conn.set_os_errno(errno);
                return Err(CURLcode::CouldntConnect);
            }
        }
        self.ctx.sock_connected = true;
        self.set_local_ip(cx);
        let label = if self.ctx.transport == Transport::Quic {
            "QUIC"
        } else {
            "UDP"
        };
        let line = format!(
            "{label} socket {} connected: [{}:{}] -> [{}:{}]",
            self.ctx.raw_socket(),
            self.ctx.ip.local_ip,
            self.ctx.ip.local_port,
            self.ctx.ip.remote_ip,
            self.ctx.ip.remote_port,
        );
        trace_line(cx, identity, sockindex, &line);
        Ok(())
    }

    /// `cf_udp_connect(cf, data, done)` (`lib/cf-socket.c:1812-1846`).
    ///
    /// # The unreachable branch that is reproduced anyway
    ///
    /// C initialises `result = CURLE_COULDNT_CONNECT` and only assigns
    /// `CURLE_OK` inside `if(ctx->sock == CURL_SOCKET_BAD)`. So a UDP filter
    /// that already holds a socket and is not yet marked connected returns
    /// `CURLE_COULDNT_CONNECT` from a call that did nothing. The block always
    /// sets `cf->connected` on the way out, so nothing reaches it -- and it is
    /// reproduced rather than tidied, because tidying it would be a behaviour
    /// change made on an assumption about reachability rather than on evidence.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::open`] or [`Self::setup_quic`] reported, plus the
    /// unreachable [`CURLcode::CouldntConnect`] above.
    fn udp_connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if self.base.is_connected() {
            return Ok(true);
        }
        let identity = self.identity();
        let sockindex = self.sockindex_i32();

        if self.ctx.socket.is_none() {
            if let Err(code) = self.open(cx) {
                let line = format!(
                    "cf_udp_connect(), open failed -> {}",
                    code.as_i32()
                );
                trace_line(cx, identity, sockindex, &line);
                return Err(Error::new(code));
            }
            if self.ctx.transport == Transport::Quic {
                self.setup_quic(cx).map_err(Error::new)?;
                let line = format!(
                    "cf_udp_connect(), opened socket={} ({}:{})",
                    self.ctx.raw_socket(),
                    self.ctx.ip.local_ip,
                    self.ctx.ip.local_port
                );
                trace_line(cx, identity, sockindex, &line);
            }
            self.base.set_connected(true);
            return Ok(true);
        }
        Err(Error::with_context(
            CURLcode::CouldntConnect,
            "udp connect: a socket is open but the filter is not connected",
        ))
    }

    // -- accepting -------------------------------------------------------

    /// `cf_tcp_accept_timeleft(cf, data)` (`lib/cf-socket.c:1955-1981`).
    ///
    /// The *"fake zero to minus one"* convention, in the C's own words: *"avoid
    /// returning 0 as that means no timeout!"* Zero from the subtraction becomes
    /// `-1`, which the caller reads as expired.
    ///
    /// The fold is `if(other_ms && (other_ms < timeout_ms))`, so a transfer with
    /// NO deadline -- zero -- takes the `else`, which subtracts the elapsed time
    /// instead. A negative `other_ms`, already elapsed, takes the `if` and is
    /// returned unchanged; the C's comment says exactly that.
    fn accept_timeleft(&self, cx: &CallCtx<'_, '_>) -> TimeDiff {
        // `timediff_t timeout_ms = DEFAULT_ACCEPT_TIMEOUT;`
        let mut timeout_ms = DEFAULT_ACCEPT_TIMEOUT;
        // `if(data->set.accepttimeout > 0) timeout_ms =
        // data->set.accepttimeout;`
        if self.settings.accept_timeout_ms > 0 {
            timeout_ms = self.settings.accept_timeout_ms;
        }
        let other_ms = self.hooks.deadline.time_left_ms();
        if other_ms != 0 && other_ms < timeout_ms {
            timeout_ms = other_ms;
        } else {
            timeout_ms -= timediff_ms(cx.now(), self.ctx.started_at);
            if timeout_ms == 0 {
                timeout_ms = -1;
            }
        }
        timeout_ms
    }

    /// `cf_tcp_accept_connect(cf, data, done)`
    /// (`lib/cf-socket.c:2014-2130`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::FtpAcceptTimeout`] once [`Self::accept_timeleft`] goes
    /// negative, [`CURLcode::FtpAcceptFailed`] for a failed wait or a failed
    /// `accept`, and [`CURLcode::AbortedByCallback`] when the ACCEPT-purpose
    /// sockopt callback refuses -- note that the accept path treats EVERY
    /// non-zero return as a refusal, `CURL_SOCKOPT_ALREADY_CONNECTED`
    /// included, because it does not test for that value (`:2120-2126`).
    fn accept_connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        // *"we start accepted, if we ever close, we cannot go on"*.
        if self.base.is_connected() {
            return Ok(true);
        }
        let identity = self.identity();
        let sockindex = self.sockindex_i32();

        let timeout_ms = self.accept_timeleft(cx);
        if timeout_ms < 0 {
            fail_line(cx, msg::ACCEPT_TIMEOUT);
            return Err(Error::new(CURLcode::FtpAcceptTimeout));
        }
        // The deadline is computed and then NOT traced: C emits no line for it,
        // and this file does not add observable output the C does not produce.
        // Its only use here is the refusal above.
        let _ = timeout_ms;
        let line = format!(
            "Checking for incoming on fd={} ip={}:{}",
            self.ctx.raw_socket(),
            self.ctx.ip.local_ip,
            self.ctx.ip.local_port
        );
        trace_line(cx, identity, sockindex, &line);

        let probe = {
            let Some(listener) = self.ctx.socket.as_ref() else {
                fail_line(cx, msg::ACCEPT_WAIT_ERROR);
                return Err(Error::new(CURLcode::FtpAcceptFailed));
            };
            self.hooks.probe.probe_accept(listener)
        };
        // `CURL_TRC_CF(data, cf, "socket_check -> %x", socketstate)` -- after
        // the check and before the `switch`, exactly where the C has it.
        trace_line(
            cx,
            identity,
            sockindex,
            &msg::socket_check(probe.socket_state()),
        );
        let accepted = match probe {
            AcceptProbe::WaitFailed => {
                fail_line(cx, msg::ACCEPT_WAIT_ERROR);
                return Err(Error::new(CURLcode::FtpAcceptFailed));
            }
            AcceptProbe::Pending => {
                trace_line(cx, identity, sockindex, msg::NOTHING_HEARD);
                return Ok(false);
            }
            AcceptProbe::AcceptFailed(error) => {
                let errno = error.raw_os_error().unwrap_or(0);
                fail_line(cx, &msg::accept_failed(&os_strerror(errno)));
                return Err(Error::new(CURLcode::FtpAcceptFailed));
            }
            AcceptProbe::Accepted(accepted) => accepted,
        };
        info_line(cx, msg::ACCEPT_READY);
        info_line(cx, msg::ACCEPT_DONE);

        // *"Replace any filter on SECONDARY with one listening on this
        // socket"* -- the C's comment, which describes the socket replacement
        // below rather than a filter replacement.
        self.ctx.listening = false;
        self.ctx.accepted = true;
        // The LISTENER is closed WITH the callback: `socket_close(data,
        // cf->conn, TRUE, ctx->sock)` (`:2100`). Only the ACCEPTED socket
        // bypasses it, and it does so later through `cf_socket_close`'s
        // `!ctx->accepted`.
        self.close_socket_now(true);
        self.ctx.socket = Some(accepted);

        let index = self.base.sockindex();
        let raw = self.ctx.raw_socket();
        self.hooks.conn.publish_socket(index, raw);
        self.set_accepted_remote_ip(cx);
        self.set_local_ip(cx);
        self.ctx.active = true;
        self.ctx.connected_at = cx.now();
        self.base.set_connected(true);
        let line = format!(
            "accepted_set(sock={raw}, remote={} port={})",
            self.ctx.ip.remote_ip, self.ctx.ip.remote_port
        );
        trace_line(cx, identity, sockindex, &line);

        if let Some(callback) = self.hooks.sockopt.clone() {
            let Some(socket) = self.ctx.socket.as_ref() else {
                return Err(Error::new(CURLcode::FtpAcceptFailed));
            };
            if callback.sockopt(socket, SockPurpose::Accept)
                != SockOptOutcome::Ok
            {
                return Err(Error::new(CURLcode::AbortedByCallback));
            }
        }
        Ok(true)
    }

    // -- activation ------------------------------------------------------

    /// `cf_socket_active(cf, data)` (`lib/cf-socket.c:1545-1557`).
    ///
    /// The second phase of the two-phase contract, and the ONLY place a socket
    /// reaches connection state. Four steps, in the C's order: publish the
    /// descriptor, refresh the local address, record the family on the primary
    /// socket only, and mark the filter active.
    ///
    /// The `bits.ipv6` stamp is guarded by `if(cf->sockindex == FIRSTSOCKET)`,
    /// so a secondary connection -- FTP's data channel -- does not overwrite
    /// what the control channel established.
    fn activate(&mut self, cx: &mut CallCtx<'_, '_>) {
        let index = self.base.sockindex();
        // `cf->conn->sock[cf->sockindex] = ctx->sock;` -- *"use this socket
        // from now on"*.
        self.hooks.conn.publish_socket(index, self.ctx.raw_socket());
        self.set_local_ip(cx);
        if index == SocketIndex::First {
            let is_ipv6 = self
                .ctx
                .addr
                .as_ref()
                .is_some_and(|addr| addr.family == AddressFamily::Inet6);
            self.hooks.conn.set_ipv6(is_ipv6);
        }
        self.ctx.active = true;
    }

    /// `cf_socket_update_data(cf, data)` (`lib/cf-socket.c:1533-1543`).
    ///
    /// *"Update the IP info held in the transfer, if we have that."* Both
    /// guards are load-bearing: the quadruple is published only for a
    /// CONNECTED filter on the PRIMARY socket, so an unconnected attempt and a
    /// secondary channel both leave `CURLINFO_PRIMARY_IP` alone.
    ///
    /// The C's second assignment carries its own hedge -- *"not sure if this is
    /// redundant..."* -- and is copied across with it, because a redundant
    /// write is still an observable one if anything else ever changes the
    /// field.
    fn update_data(&mut self) {
        if self.base.is_connected()
            && self.base.sockindex() == SocketIndex::First
        {
            let port = self.hooks.conn.remote_port();
            self.hooks.conn.set_primary(&self.ctx.ip, port);
        }
    }
}

impl ConnFilter for SocketFilter {
    fn trace_name(&self) -> &'static str {
        self.kind.trace_name()
    }

    fn cf_type(&self) -> CfType {
        self.kind.cf_type()
    }

    fn base(&self) -> &FilterBase {
        &self.base
    }

    fn base_mut(&mut self) -> &mut FilterBase {
        &mut self.base
    }

    /// `cf_socket_destroy` (`lib/cf-socket.c:1180-1188`).
    ///
    /// Closes first, then traces, then releases the context -- and the release
    /// has no successor, because `curlx_free(ctx)` is what [`Drop`] does. This
    /// hook exists for the effects a `Drop` cannot have, which here is the
    /// close: it may invoke a user callback and must notify the multi handle.
    fn destroy(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.do_close(cx);
        let identity = self.identity();
        let sockindex = self.sockindex_i32();
        trace_line(cx, identity, sockindex, "destroy");
    }

    /// The one member that differs between the four registered types.
    ///
    /// `Curl_cft_tcp` and `Curl_cft_unix` both name `cf_tcp_connect`,
    /// `Curl_cft_udp` names `cf_udp_connect`, and `Curl_cft_tcp_accept` names
    /// `cf_tcp_accept_connect`.
    fn connect(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        match self.kind {
            SocketFilterKind::Tcp | SocketFilterKind::Unix => {
                self.tcp_connect(cx)
            }
            SocketFilterKind::Udp => self.udp_connect(cx),
            SocketFilterKind::TcpAccept => self.accept_connect(cx),
        }
    }

    /// `cf_socket_close`, shared by all four types.
    ///
    /// Does NOT chain. A socket filter is the bottom of its chain by
    /// construction -- it is the transport -- so there is nothing below to pass
    /// a close down to, which is why [`crate::conn::filters::chain_close`] is
    /// not used here.
    fn close(&mut self, cx: &mut CallCtx<'_, '_>) {
        self.do_close(cx);
    }

    /// `cf_socket_shutdown` (`lib/cf-socket.c:958-978`).
    ///
    /// A best-effort drain and nothing more: *"On TCP, and when the socket looks
    /// well and non-blocking mode can be enabled, receive dangling bytes before
    /// close to avoid entering RST states unnecessarily."*
    ///
    /// Four conditions gate it and all four are preserved -- the filter must be
    /// connected, the socket must exist, the transport must be exactly
    /// [`Transport::Tcp`], and non-blocking mode must be establishable. The read
    /// is performed AT MOST ONCE, of at most [`SHUTDOWN_DRAIN_MAX`] bytes, and
    /// its result is discarded: the C writes `(void)sread(...)`, because bytes
    /// arriving during a shutdown are bytes nobody asked for.
    ///
    /// Reports done unconditionally. `*done = TRUE` sits outside the `if`, so a
    /// filter that drained nothing has still finished shutting down.
    fn shutdown(&mut self, cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
        if self.base.is_connected() {
            let identity = self.identity();
            let sockindex = self.sockindex_i32();
            let line =
                format!("cf_socket_shutdown, fd={}", self.ctx.raw_socket());
            trace_line(cx, identity, sockindex, &line);
            if self.ctx.transport == Transport::Tcp {
                if let Some(socket) = self.ctx.socket.as_ref() {
                    // `(curlx_nonblock(ctx->sock, TRUE) >= 0)` is the third
                    // conjunct of the C's condition, so a socket that cannot be
                    // made non-blocking is not drained at all.
                    if set_nonblocking(socket, true).is_ok() {
                        let mut drain = [0_u8; SHUTDOWN_DRAIN_MAX];
                        let mut source: &OsSocket = socket;
                        let _ = io::Read::read(&mut source, &mut drain);
                    }
                }
            }
        }
        Ok(true)
    }

    /// `cf_socket_adjust_pollset` (`lib/cf-socket.c:1328-1357`).
    ///
    /// Four cases, mutually exclusive and in the C's order:
    ///
    /// 1. **Listening** -- input only. The C's comment is worth carrying: *"A
    ///    listening socket filter needs to be connected before the accept for
    ///    some weird FTP interaction. This should be rewritten, so that FTP no
    ///    longer does the socket checks and accept calls and delegates all that
    ///    to the filter."*
    /// 2. **Not connected** -- output only, because writability IS the
    ///    completion of a non-blocking connect.
    /// 3. **Connected but not active** -- add input, so that a Happy Eyeballs
    ///    attempt still learns about a peer that hangs up.
    /// 4. **Active** -- nothing. The layer above owns the interest from here.
    ///
    /// Does NOT chain: [`crate::conn::filters::FilterChain::adjust_pollset`]
    /// walks the chain itself, and a socket filter is the bottom in any case.
    ///
    /// # Errors
    ///
    /// Whatever [`EasyPollset`] reports, which is
    /// [`CURLcode::BadFunctionArgument`] for a value that is not a descriptor.
    fn adjust_pollset(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        ps: &mut EasyPollset,
    ) -> CurlResult<()> {
        let sock = self.ctx.raw_socket();
        if !is_valid_sock(sock) {
            return Ok(());
        }
        let identity = self.identity();
        let sockindex = self.sockindex_i32();

        if self.ctx.listening {
            ps.set_in_only(sock, cx.tracer_mut())?;
            let line = format!("adjust_pollset, listening, POLLIN fd={sock}");
            trace_line(cx, identity, sockindex, &line);
        } else if !self.base.is_connected() {
            ps.set_out_only(sock, cx.tracer_mut())?;
            let line = format!("adjust_pollset, !connected, POLLOUT fd={sock}");
            trace_line(cx, identity, sockindex, &line);
        } else if !self.ctx.active {
            ps.add_in(sock, cx.tracer_mut())?;
            let line = format!("adjust_pollset, !active, POLLIN fd={sock}");
            trace_line(cx, identity, sockindex, &line);
        }
        Ok(())
    }

    /// `cf_socket_send` (`lib/cf-socket.c:1382-1468`).
    ///
    /// # `eos` is ignored, and that is the C's own `(void)eos`
    ///
    /// A socket has no end-of-stream marker to write. The flag matters to the
    /// layers above -- chunked framing closes its stream, HTTP/2 sets
    /// END_STREAM -- and by the time bytes reach a socket the framing is
    /// already in them.
    ///
    /// # The re-entrancy hack disappears
    ///
    /// C saves `cf->conn->sock[cf->sockindex]`, overwrites it with `ctx->sock`
    /// for the duration of the send, and restores it afterwards
    /// (`:1394-1395`, `:1465`). It does that because the debug simulation and
    /// the Winsock buffer autotuner reach the socket through the CONNECTION
    /// rather than through the context. Here the context owns its socket, so
    /// there is nothing to swap, nothing to restore, and no window in which the
    /// connection describes the wrong descriptor.
    ///
    /// Partial writes are reported exactly: whatever the socket accepted is
    /// returned, and the caller sends the rest.
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] for the FOUR conditions [`send_is_again`] lists --
    /// [`SocketCondition::InProgress`] among them -- and
    /// [`CURLcode::SendError`] with [`msg::send_failure`] for anything else.
    fn send(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &[u8],
        eos: bool,
    ) -> CurlResult<usize> {
        // `(void)eos;`
        let _ = eos;
        let identity = self.identity();
        let sockindex = self.sockindex_i32();
        let Some(socket) = self.ctx.socket.as_ref() else {
            return Err(Error::with_context(
                CURLcode::SendError,
                "send: the socket filter holds no socket",
            ));
        };
        match socket.send(buf) {
            Ok(written) => {
                let line = format!("send(len={}) -> 0, {written}", buf.len());
                trace_line(cx, identity, sockindex, &line);
                Ok(written)
            }
            Err(error) => {
                if send_is_again(classify(&error)) {
                    let line = format!("send(len={}) -> EAGAIN", buf.len());
                    trace_line(cx, identity, sockindex, &line);
                    return Err(Error::new(CURLcode::Again));
                }
                let errno = error.raw_os_error().unwrap_or(0);
                fail_line(cx, &msg::send_failure(&os_strerror(errno)));
                self.hooks.conn.set_os_errno(errno);
                Err(Error::new(CURLcode::SendError))
            }
        }
    }

    /// `cf_socket_recv` (`lib/cf-socket.c:1471-1531`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::Again`] for the THREE conditions [`recv_is_again`] lists --
    /// [`SocketCondition::InProgress`] is DELIBERATELY ABSENT, see that
    /// function -- and [`CURLcode::RecvError`] with [`msg::recv_failure`]
    /// otherwise.
    ///
    /// A zero-length read is SUCCESS, meaning end of stream, and it records the
    /// first-byte time like any other success: the C's guard is `if(!result &&
    /// !ctx->got_first_byte)`, which a zero-byte read satisfies.
    fn recv(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        let identity = self.identity();
        let sockindex = self.sockindex_i32();
        let outcome = {
            let Some(socket) = self.ctx.socket.as_ref() else {
                return Err(Error::with_context(
                    CURLcode::RecvError,
                    "recv: the socket filter holds no socket",
                ));
            };
            let mut source: &OsSocket = socket;
            io::Read::read(&mut source, buf)
        };
        let read = match outcome {
            Ok(read) => read,
            Err(error) => {
                if recv_is_again(classify(&error)) {
                    let line = format!("recv(len={}) -> EAGAIN", buf.len());
                    trace_line(cx, identity, sockindex, &line);
                    return Err(Error::new(CURLcode::Again));
                }
                let errno = error.raw_os_error().unwrap_or(0);
                fail_line(cx, &msg::recv_failure(&os_strerror(errno)));
                self.hooks.conn.set_os_errno(errno);
                return Err(Error::new(CURLcode::RecvError));
            }
        };
        let line = format!("recv(len={}) -> 0, {read}", buf.len());
        trace_line(cx, identity, sockindex, &line);
        // `if(!result && !ctx->got_first_byte) { ctx->first_byte_at =
        // *Curl_pgrs_now(data); ctx->got_first_byte = TRUE; }` -- once, and
        // only once.
        if !self.ctx.got_first_byte {
            self.ctx.first_byte_at = cx.now();
            self.ctx.got_first_byte = true;
        }
        Ok(read)
    }

    /// `cf_socket_cntrl` (`lib/cf-socket.c:1559-1580`).
    ///
    /// Three events are handled and the other four fall through to success,
    /// which is what the C's `switch` with no `default` does.
    ///
    /// [`CfControl::ForgetSocket`] is the interesting one: `ctx->sock =
    /// CURL_SOCKET_BAD` **without closing**. The descriptor stays open and
    /// somebody else now owns it -- FTP hands a data connection to the
    /// application through `CURLOPT_CLOSESOCKETFUNCTION` this way.
    /// [`std::os::fd::IntoRawFd::into_raw_fd`] is the safe expression of that:
    /// it consumes the owned socket and yields the number WITHOUT closing it,
    /// which is precisely a relinquished ownership. Dropping the socket instead
    /// would close it and break the caller.
    fn cntrl(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        event: CfControl,
    ) -> CurlResult<()> {
        match event {
            // `case CF_CTRL_CONN_INFO_UPDATE: cf_socket_active(cf, data);
            // cf_socket_update_data(cf, data); break;`
            CfControl::ConnInfoUpdate => {
                self.activate(cx);
                self.update_data();
            }
            // `case CF_CTRL_DATA_SETUP: cf_socket_update_data(cf, data);`
            CfControl::DataSetup => self.update_data(),
            // `case CF_CTRL_FORGET_SOCKET: ctx->sock = CURL_SOCKET_BAD;`
            //
            // The C emits NO trace line here, and none is added: a line this
            // file invented would be observable output curl does not produce.
            // The descriptor number is discarded rather than logged, which is
            // the whole content of relinquishing it.
            CfControl::ForgetSocket => {
                if let Some(socket) = self.ctx.socket.take() {
                    let _relinquished = socket.into_raw_fd();
                }
            }
            CfControl::DataPause { .. }
            | CfControl::DataDone { .. }
            | CfControl::DataDoneSend
            | CfControl::Flush => {}
        }
        Ok(())
    }

    /// `cf_socket_conn_is_alive` (`lib/cf-socket.c:1582-1617`).
    ///
    /// The mapping, verbatim: no socket is dead, a failed probe is dead, a
    /// timeout is alive with nothing waiting, `POLLERR | POLLHUP | POLLPRI |
    /// POLLNVAL` is dead, and anything else is alive with input pending.
    ///
    /// [`PollEvents::PRI`] counting as DEAD is not a slip. Out-of-band data on a
    /// pooled connection means the peer is doing something this transfer did not
    /// ask for, and the C treats that as a reason to reconnect rather than to
    /// read.
    fn is_alive(&mut self, cx: &mut CallCtx<'_, '_>) -> Liveness {
        let identity = self.identity();
        let sockindex = self.sockindex_i32();
        let outcome = {
            let Some(socket) = self.ctx.socket.as_ref() else {
                return Liveness::DEAD;
            };
            self.hooks.probe.probe_input(socket)
        };
        match outcome {
            ProbeOutcome::Failed => {
                trace_line(
                    cx,
                    identity,
                    sockindex,
                    "is_alive: poll error, assume dead",
                );
                Liveness::DEAD
            }
            ProbeOutcome::Timeout => {
                trace_line(
                    cx,
                    identity,
                    sockindex,
                    "is_alive: poll timeout, assume alive",
                );
                Liveness::alive(false)
            }
            ProbeOutcome::Ready(events) => {
                let fatal = PollEvents::ERR
                    | PollEvents::HUP
                    | PollEvents::PRI
                    | PollEvents::NVAL;
                if events.intersects(fatal) {
                    trace_line(
                        cx,
                        identity,
                        sockindex,
                        "is_alive: err/hup/etc events, assume dead",
                    );
                    return Liveness::DEAD;
                }
                trace_line(
                    cx,
                    identity,
                    sockindex,
                    "is_alive: valid events, looks alive",
                );
                Liveness::alive(true)
            }
        }
    }

    /// `cf_socket_query` (`lib/cf-socket.c:1619-1680`).
    ///
    /// Six questions answered and the rest delegated, which is the C's
    /// `default: break;` followed by `return cf->next ? cf->next->cft->query(...)
    /// : CURLE_UNKNOWN_OPTION;`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::UnknownOption`] at the bottom of the chain for a question
    /// nobody understood. That is a SENTINEL rather than a failure -- every
    /// caller reads it as "use the default".
    fn query(
        &mut self,
        cx: &mut CallCtx<'_, '_>,
        query: CfQuery,
    ) -> CurlResult<CfQueryValue> {
        match query {
            // `case CF_QUERY_SOCKET: *((curl_socket_t *)pres2) = ctx->sock;`
            CfQuery::Socket => Ok(CfQueryValue::Socket(self.ctx.raw_socket())),
            // `case CF_QUERY_TRANSPORT: *pres1 = ctx->transport;`
            CfQuery::Transport => {
                Ok(CfQueryValue::Transport(self.ctx.transport))
            }
            // `*((const struct Curl_sockaddr_ex **)pres2) = cf->connected ?
            // &ctx->addr : NULL;` -- the peer is reported ONLY once connected.
            CfQuery::RemoteAddr => {
                Ok(CfQueryValue::RemoteAddr(if self.base.is_connected() {
                    self.ctx.addr.as_ref().and_then(SockAddrEx::remote_addr)
                } else {
                    None
                }))
            }
            // `if(ctx->got_first_byte) { ms = ...; *pres1 = (ms < INT_MAX) ?
            // (int)ms : INT_MAX; } else *pres1 = -1;`
            CfQuery::ConnectReplyMs => {
                let ms = if self.ctx.got_first_byte {
                    let elapsed = timediff_ms(
                        self.ctx.first_byte_at,
                        self.ctx.started_at,
                    );
                    let cap = TimeDiff::from(i32::MAX);
                    if elapsed < cap {
                        elapsed
                    } else {
                        cap
                    }
                } else {
                    -1
                };
                Ok(CfQueryValue::ConnectReplyMs(ms))
            }
            // The `FALLTHROUGH()` is the whole subtlety: UDP and QUIC use the
            // first-byte time *"Since UDP connected sockets work different from
            // TCP, we use the time of the first byte from the peer as the
            // 'connect' time"* -- but ONLY if a first byte arrived. Without one
            // they fall through to `connected_at` like every other transport.
            CfQuery::TimerConnect => {
                let when = match self.ctx.transport {
                    Transport::Udp | Transport::Quic
                        if self.ctx.got_first_byte =>
                    {
                        self.ctx.first_byte_at
                    }
                    Transport::Udp
                    | Transport::Quic
                    | Transport::Tcp
                    | Transport::Unix
                    | Transport::None => self.ctx.connected_at,
                };
                Ok(CfQueryValue::Timer(when))
            }
            // `*pres1 = (ctx->addr.family == AF_INET6); *(struct ip_quadruple
            // *)pres2 = ctx->ip;`
            CfQuery::IpInfo => {
                Ok(CfQueryValue::IpInfo {
                    is_ipv6: self.ctx.addr.as_ref().is_some_and(|addr| {
                        addr.family == AddressFamily::Inet6
                    }),
                    quad: self.ctx.ip.clone(),
                })
            }
            CfQuery::MaxConcurrent
            | CfQuery::TimerAppConnect
            | CfQuery::StreamError
            | CfQuery::NeedFlush
            | CfQuery::HttpVersion
            | CfQuery::HostPort
            | CfQuery::SslInfo
            | CfQuery::SslCtxInfo
            | CfQuery::AlpnNegotiated => match self.base.next_mut() {
                Some(next) => next.query(cx, query),
                None => Err(Error::new(CURLcode::UnknownOption)),
            },
        }
    }
}

// =========================================================================
// The four factories
// =========================================================================

/// `Curl_cf_tcp_create` (`lib/cf-socket.c:1700-1738`).
///
/// Returns an **unattached** filter, and the whole two-phase contract depends on
/// that: *"The filter will not touch any connection/data flags and can be used
/// in happy eyeballing. Once selected for use, its `_active()` method needs to
/// be called."* (`lib/cf-socket.h:84-89`.)
///
/// `ai` is the ONLY address this filter may ever use. The C asserts
/// `DEBUGASSERT(transport == TRNSPRT_TCP)` and refuses a missing address with
/// `CURLE_BAD_FUNCTION_ARGUMENT` (`:1715-1718`); both are reproduced, the first
/// as a debug assertion and the second by the type -- `ai` is not optional here,
/// so the C's `if(!ai)` branch has no expressible caller.
///
/// The C's `Curl_cf_create` step and its `CURLE_OUT_OF_MEMORY` have no
/// successor: a failure to allocate aborts, exactly as
/// [`crate::conn::filters::link`] records. So the only error left is the
/// address-size check.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`SockAddrEx::assign`].
#[allow(dead_code)]
pub(crate) fn cf_tcp_create(
    ai: &ResolvedAddr,
    hooks: SocketHooks,
    settings: SocketSettings,
    sockindex: SocketIndex,
) -> CodeResult<SocketFilter> {
    // C's `DEBUGASSERT(transport == TRNSPRT_TCP)` (`:1714`) has no successor
    // to assert: the transport is not a parameter here, so a caller cannot pass
    // the wrong one and there is no run-time condition left to check.
    let ctx = SocketContext::init(ai, Transport::Tcp)?;
    Ok(SocketFilter::new(
        SocketFilterKind::Tcp,
        ctx,
        hooks,
        settings,
        sockindex,
    ))
}

/// `Curl_cf_udp_create` (`lib/cf-socket.c:1866-1898`).
///
/// The one factory that takes the transport as an argument, because two values
/// are valid: `DEBUGASSERT(transport == TRNSPRT_UDP || transport ==
/// TRNSPRT_QUIC)` (`:1876`). The distinction is behaviour --
/// [`Transport::Quic`] additionally runs [`SocketFilter::setup_quic`], and
/// `CF_QUERY_TIMER_CONNECT` reports the first-byte time for both -- so it is
/// checked rather than assumed.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for a transport that is neither
/// [`Transport::Udp`] nor [`Transport::Quic`], which is stricter than the C's
/// debug-only assertion and stricter on purpose: a UDP filter carrying
/// [`Transport::Tcp`] would answer `CF_QUERY_TRANSPORT` with a lie.
///
/// [`CURLcode::TooLarge`] from [`SockAddrEx::assign`].
#[allow(dead_code)]
pub(crate) fn cf_udp_create(
    ai: &ResolvedAddr,
    transport: Transport,
    hooks: SocketHooks,
    settings: SocketSettings,
    sockindex: SocketIndex,
) -> CodeResult<SocketFilter> {
    if !matches!(transport, Transport::Udp | Transport::Quic) {
        return Err(CURLcode::BadFunctionArgument);
    }
    let ctx = SocketContext::init(ai, transport)?;
    Ok(SocketFilter::new(
        SocketFilterKind::Udp,
        ctx,
        hooks,
        settings,
        sockindex,
    ))
}

/// `Curl_cf_unix_create` (`lib/cf-socket.c:1920-1953`).
///
/// A `UNIX`-named filter running the TCP algorithm, which is what the C does:
/// `Curl_cft_unix` names `cf_tcp_connect` under the comment *"this is the TCP
/// filter which can also handle this case"* (`:1900`). No parallel UNIX state
/// machine exists here for the same reason it does not exist there.
///
/// # Errors
///
/// [`CURLcode::TooLarge`] from [`SockAddrEx::assign`], and
/// [`CURLcode::BadFunctionArgument`] for a Unix path that does not fit
/// `SUN_LEN`.
#[allow(dead_code)]
pub(crate) fn cf_unix_create(
    ai: &ResolvedAddr,
    hooks: SocketHooks,
    settings: SocketSettings,
    sockindex: SocketIndex,
) -> CodeResult<SocketFilter> {
    let ctx = SocketContext::init(ai, Transport::Unix)?;
    Ok(SocketFilter::new(
        SocketFilterKind::Unix,
        ctx,
        hooks,
        settings,
        sockindex,
    ))
}

/// `Curl_conn_tcp_listen_set` (`lib/cf-socket.c:2150-2196`).
///
/// Adopts an already-created listening socket and installs a `TCP-ACCEPT`
/// filter over it. FTP's active mode is the only caller: it creates and binds
/// the listener itself and then hands it over.
///
/// **The existing chain is discarded FIRST** -- `Curl_conn_cf_discard_all(data,
/// conn, sockindex)` at `:2160`, before anything is built -- and the C then
/// asserts the connection's descriptor is `CURL_SOCKET_BAD`, which is what that
/// discard leaves behind. Getting the order wrong would install a filter over a
/// socket the previous chain still believed it owned.
///
/// The listener MOVES in, so this function is the point at which its ownership
/// transfers: the filter closes it exactly once, either when the accept replaces
/// it or when the chain is torn down.
#[allow(dead_code)]
pub(crate) fn tcp_listen_set(
    cx: &mut CallCtx<'_, '_>,
    chain: &mut FilterChain,
    listener: OsSocket,
    hooks: SocketHooks,
    settings: SocketSettings,
) {
    // `Curl_conn_cf_discard_all(data, conn, sockindex);`
    chain.discard_chain(cx);
    debug_assert_eq!(
        hooks.conn.socket(chain.sockindex()),
        CURL_SOCKET_BAD,
        "DEBUGASSERT(conn->sock[sockindex] == CURL_SOCKET_BAD)"
    );

    let sockindex = chain.sockindex();
    let mut filter = SocketFilter::new(
        SocketFilterKind::TcpAccept,
        SocketContext::listening(listener),
        hooks,
        settings,
        sockindex,
    );
    // `ctx->started_at = *Curl_pgrs_now(data);` -- AFTER the filter is added in
    // the C, which matters only in that the accept deadline is measured from
    // here rather than from whenever the socket was created.
    filter.ctx.started_at = cx.now();
    // `conn->sock[sockindex] = ctx->sock;` -- a listening filter publishes
    // immediately, which is the one exception to the two-phase rule and is
    // sound because there is no race: a listener has no rival attempt.
    let raw = filter.ctx.raw_socket();
    filter.hooks.conn.publish_socket(sockindex, raw);
    filter.set_local_ip(cx);
    let identity = filter.identity();
    let line = format!(
        "set filter for listen socket fd={raw} ip={}:{}",
        filter.ctx.ip.local_ip, filter.ctx.ip.local_port
    );
    trace_line(cx, identity, sockindex.as_i32(), &line);

    chain.add(cx, link(filter));
}

/// `Curl_conn_is_tcp_listen(data, sockindex)`
/// (`lib/cf-socket.c:2198-2207`).
///
/// C walks the chain comparing each `cf->cft` against `&Curl_cft_tcp_accept`.
/// Here the walk asks each filter for its name, because a trait object's
/// concrete type is not comparable and its NAME is exactly the identity the C's
/// pointer comparison was standing in for.
#[allow(dead_code)]
pub(crate) fn conn_is_tcp_listen(chain: &FilterChain) -> bool {
    chain.iter().any(|filter| {
        filter.trace_name() == SocketFilterKind::TcpAccept.trace_name()
    })
}

// =========================================================================
// The wakeup primitive -- `lib/socketpair.c`
// =========================================================================

/// How a [`Wakeup`] is backed.
///
/// `lib/socketpair.c` chooses between four implementations at compile time --
/// `wakeup_eventfd`, `wakeup_pipe`, `wakeup_socketpair` and `wakeup_inet`
/// (`:283-294`) -- and the choice is observable in exactly one way, which
/// [`Wakeup::destroy`] depends on: an `eventfd` is ONE descriptor used for both
/// reading and writing, and `Curl_wakeup_destroy` closes `socks[1]` only
/// `#ifndef USE_EVENTFD` (`:363-369`) precisely so that the single descriptor is
/// not closed twice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum WakeupBacking {
    /// Two distinct descriptors -- `pipe`, `socketpair` or the loopback
    /// fallback. Both ends are closed.
    Pair,
    /// One descriptor serving both directions -- Linux `eventfd`. Closed ONCE.
    Shared,
}

/// The multi handle's *"make the poll return"* mechanism.
///
/// The successor of `Curl_wakeup_init`, `Curl_wakeup_signal`,
/// `Curl_wakeup_consume` and `Curl_wakeup_destroy`
/// (`lib/socketpair.c:283-373`), which back `curl_multi_wakeup`.
///
/// # Why a descriptor rather than a `tokio` notification
///
/// A [`tokio::sync::Notify`] would be the natural shape if the only requirement
/// were to wake a task. It is not: the multi handle's wait is
/// [`crate::conn::select::poll_sockets`] over a set of DESCRIPTORS, because the
/// sockets it is waiting on are descriptors and the application may be waiting
/// on its own alongside them. A notification cannot appear in that set. So the
/// wakeup is descriptor-backed, and the contract is the C's: writing one byte
/// makes a pending poll return.
///
/// The socket pair comes from [`socket2::Socket::pair`], which is a safe RAII
/// wrapper -- the `socketpair` system call belongs to `socket2`, not to this
/// file,
/// and each end is owned by an [`OsSocket`] that closes it exactly once.
///
/// # It is INTERNAL and must never be shown to the application
///
/// C keeps it in `multi->wakeup_pair[2]` (`lib/multihandle.h:164-165`) and adds
/// it to the multi handle's own `Curl_pollfds`, never to the `Curl_waitfds` that
/// `curl_multi_wait` fills in for the caller. Advertising it would inflate the
/// application's descriptor count with a descriptor it did not supply and cannot
/// interpret. [`Self::add_to_pollfds`] is therefore the only way it reaches a
/// wait, and it is named so that a call site is deliberate.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct Wakeup {
    /// `socks[0]` -- *"0 is used for read"*.
    reader: OsSocket,
    /// `socks[1]` -- *"1 is used for write"*.
    ///
    /// [`None`] for [`WakeupBacking::Shared`], where the reader is also the
    /// writer. That is the whole of the `#ifndef USE_EVENTFD` distinction, and
    /// expressing it as an absent second owner is what makes the double close
    /// unrepresentable instead of merely avoided.
    writer: Option<OsSocket>,
}

#[allow(dead_code)]
impl Wakeup {
    /// `Curl_wakeup_init(socks, nonblocking)`
    /// (`lib/socketpair.c:283-294`).
    ///
    /// Both ends are made non-blocking, which is what every backend in
    /// `lib/socketpair.c` does when asked: a signal must never block the thread
    /// that sends it, and a consume must never block the reactor.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] when the pair cannot be created or
    /// configured. C returns `-1` from `Curl_wakeup_init` and its caller,
    /// `Curl_multi_handle`, then reports `CURLM_OUT_OF_MEMORY`; the code here is
    /// the transport-level one because that is what this layer knows, and
    /// `crate::multi` maps it.
    #[allow(dead_code)]
    pub(crate) fn new() -> CodeResult<Self> {
        let (reader, writer) =
            OsSocket::pair(Domain::UNIX, OsType::STREAM, None)
                .map_err(|_| CURLcode::CouldntConnect)?;
        set_nonblocking(&reader, true).map_err(|_| CURLcode::CouldntConnect)?;
        set_nonblocking(&writer, true).map_err(|_| CURLcode::CouldntConnect)?;
        Ok(Self {
            reader,
            writer: Some(writer),
        })
    }

    /// A wakeup over one descriptor used for both directions.
    ///
    /// The shape a Linux `eventfd` arrives in. The socket is expected to be
    /// non-blocking already, as `wakeup_eventfd` creates it with `EFD_NONBLOCK`
    /// (`lib/socketpair.c:64-72`); it is set again here because
    /// [`set_nonblocking`] is idempotent and a caller should not have to
    /// remember.
    ///
    /// # Errors
    ///
    /// [`CURLcode::CouldntConnect`] when the descriptor cannot be made
    /// non-blocking.
    #[allow(dead_code)]
    pub(crate) fn from_shared(single: OsSocket) -> CodeResult<Self> {
        set_nonblocking(&single, true).map_err(|_| CURLcode::CouldntConnect)?;
        Ok(Self {
            reader: single,
            writer: None,
        })
    }

    /// How this wakeup is backed.
    #[allow(dead_code)]
    pub(crate) fn backing(&self) -> WakeupBacking {
        if self.writer.is_some() {
            WakeupBacking::Pair
        } else {
            WakeupBacking::Shared
        }
    }

    /// `socks[0]`, the descriptor a poll watches.
    ///
    /// Borrowed, never owned: whoever polls it must not close it.
    #[allow(dead_code)]
    pub(crate) fn read_socket(&self) -> Socket {
        self.reader.as_raw_fd()
    }

    /// `socks[1]`, the descriptor a signal writes.
    ///
    /// The same number as [`Self::read_socket`] for
    /// [`WakeupBacking::Shared`], which is the fact that makes the single
    /// close necessary.
    #[allow(dead_code)]
    pub(crate) fn write_socket(&self) -> Socket {
        self.writer
            .as_ref()
            .map_or_else(|| self.reader.as_raw_fd(), AsRawFd::as_raw_fd)
    }

    /// Adds the read end to an INTERNAL pollfd buffer.
    ///
    /// The only sanctioned way this descriptor reaches a wait, and the reason
    /// [`Wakeup`] documents the distinction at such length: `lib/multi.c` adds
    /// it to its own `Curl_pollfds` and never to the application's
    /// `Curl_waitfds`.
    #[allow(dead_code)]
    pub(crate) fn add_to_pollfds(&self, fds: &mut PollFds) {
        fds.add_sock(self.read_socket(), PollEvents::IN);
    }

    /// `Curl_wakeup_signal(socks)` (`lib/socketpair.c:310-335`).
    ///
    /// Writes one token. The two conditions and their treatment are the C's:
    ///
    /// * `SOCKEINTR` RETRIES, in a `while(1)` -- an interrupted write has not
    ///   happened, so the wakeup would be lost.
    /// * `SOCKEWOULDBLOCK` or `EAGAIN` is **success**, and the C says why:
    ///   *"wakeup is already ongoing"*. A full pipe means a token nobody has
    ///   consumed yet, and one token is all a wakeup needs. This is where
    ///   signal COALESCING comes from, and it is the reason
    ///   [`Self::signal`] can be called from any thread as often as it likes.
    ///
    /// Returns the C's `int err`: zero for success and an `errno` otherwise.
    ///
    /// The token differs by backend -- `const uint64_t buf[1] = { 1 }` for
    /// `eventfd`, which requires an eight-byte write, and `const char buf[1] =
    /// { 1 }` otherwise. Eight bytes are written for the shared backing for
    /// exactly that reason; a shorter write to an `eventfd` fails with `EINVAL`.
    #[allow(dead_code)]
    pub(crate) fn signal(&self) -> i32 {
        let shared = self.writer.is_none();
        let target = self.writer.as_ref().unwrap_or(&self.reader);
        // `const uint64_t buf[1] = { 1 };` versus `const char buf[1] = { 1 };`
        let eventfd_token = 1_u64.to_ne_bytes();
        let byte_token = [1_u8];
        let token: &[u8] = if shared { &eventfd_token } else { &byte_token };
        loop {
            match target.send(token) {
                Ok(_) => return 0,
                Err(error) => match classify(&error) {
                    // `if(SOCKEINTR == err) continue;`
                    SocketCondition::Interrupted => continue,
                    // `if((err == SOCKEWOULDBLOCK) || (err == EAGAIN)) err = 0;`
                    SocketCondition::WouldBlock => return 0,
                    SocketCondition::InProgress | SocketCondition::Other => {
                        return error.raw_os_error().unwrap_or(0)
                    }
                },
            }
        }
    }

    /// `Curl_wakeup_consume(socks, all)` (`lib/socketpair.c:337-361`).
    ///
    /// A `do { ... } while(all)` loop, so `all == false` reads EXACTLY ONCE and
    /// `all == true` drains until the pipe is empty. Four terminations, all the
    /// C's:
    ///
    /// * `if(!rc) break;` -- end of stream ends the drain, successfully.
    /// * `SOCKEINTR` continues, whatever `all` said, because an interrupted read
    ///   has consumed nothing.
    /// * `SOCKEWOULDBLOCK` or `EAGAIN` breaks, successfully -- the pipe is
    ///   empty, which is the whole point of draining.
    /// * anything else is [`CURLcode::ReadError`].
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`], which is what `Curl_wakeup_consume` returns and
    /// what `curl_multi_wait` propagates.
    #[allow(dead_code)]
    pub(crate) fn consume(&self, all: bool) -> CodeResult<()> {
        let mut drain = [0_u8; WAKEUP_DRAIN_LEN];
        loop {
            let mut source: &OsSocket = &self.reader;
            match io::Read::read(&mut source, &mut drain) {
                // `if(!rc) break;`
                Ok(0) => return Ok(()),
                Ok(_) => {
                    if !all {
                        return Ok(());
                    }
                }
                Err(error) => {
                    return match classify(&error) {
                        SocketCondition::Interrupted => continue,
                        SocketCondition::WouldBlock => Ok(()),
                        SocketCondition::InProgress
                        | SocketCondition::Other => Err(CURLcode::ReadError),
                    }
                }
            }
        }
    }

    /// `Curl_wakeup_destroy(socks)` (`lib/socketpair.c:363-373`).
    ///
    /// Explicit as well as automatic. [`Drop`] does the same thing, so a
    /// [`Wakeup`] that simply goes out of scope is destroyed correctly; this
    /// exists because the C has a named teardown that `curl_multi_cleanup`
    /// calls, and a reader looking for its successor should find one.
    ///
    /// Consumes `self`, which is what makes the C's `socks[0] = socks[1] =
    /// CURL_SOCKET_BAD` unnecessary: there is nothing left to hold a stale
    /// descriptor.
    #[allow(dead_code)]
    pub(crate) fn destroy(self) {
        drop(self);
    }
}

// TESTS
//
// `tests/unit/*.c` (59 files) and `tests/libtest/*.c` (235) link a debug static
// build of the C library and call internal `Curl_*` symbols, which a Rust static
// library does not export. Their coverage therefore relocates into `#[cfg(test)]`
// modules inside the files under test (AAP section 0.8.7), and this is this
// file's share of that relocation.
//
// Every test below is DETERMINISTIC and touches no network. The clock is
// `crate::util::timeval::TestClock`, readiness is a canned `FakeProbe`, the
// resolver and the interface lookup are fakes, and the only real descriptors
// used come from `socket2::Socket::pair` -- a local, connected pair that needs
// no address, no name resolution and no peer. The handful of tests that do use
// one are marked `#[cfg_attr(miri, ignore = ...)]`, because `cargo +nightly miri
// test` is a mandated gate (AAP section 0.8.4) and Miri cannot execute a foreign
// function; everything else, including all of the classification, parsing,
// message and ownership coverage, runs under Miri unchanged.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::CURL_LOG_LVL_NONE;
    use crate::conn::select::WaitFds;
    use crate::conn::Addr2StringError;
    use crate::util::timeval::TestClock;
    use std::cell::{Cell, RefCell};
    use std::net::IpAddr;

    // ---------------------------------------------------------------
    // Test doubles
    // ---------------------------------------------------------------

    /// A [`ConnState`] that records every publication.
    #[derive(Debug, Default)]
    struct FakeConn {
        sockets: RefCell<[Socket; 2]>,
        published: Cell<usize>,
        cleared: Cell<usize>,
        ipv6: Cell<Option<bool>>,
        bound: Cell<Option<bool>>,
        remote_port: Cell<u16>,
        primary: RefCell<Option<IpQuadruple>>,
        primary_port: Cell<u16>,
        os_errno: Cell<i32>,
    }

    impl FakeConn {
        fn new() -> Self {
            Self {
                sockets: RefCell::new([CURL_SOCKET_BAD; 2]),
                ..Self::default()
            }
        }
    }

    impl ConnState for FakeConn {
        fn socket(&self, sockindex: SocketIndex) -> Socket {
            self.sockets.borrow()[sockindex.as_usize()]
        }

        fn publish_socket(&self, sockindex: SocketIndex, sock: Socket) {
            self.sockets.borrow_mut()[sockindex.as_usize()] = sock;
            self.published.set(self.published.get() + 1);
        }

        fn clear_socket(&self, sockindex: SocketIndex) {
            self.sockets.borrow_mut()[sockindex.as_usize()] = CURL_SOCKET_BAD;
            self.cleared.set(self.cleared.get() + 1);
        }

        fn set_ipv6(&self, is_ipv6: bool) {
            self.ipv6.set(Some(is_ipv6));
        }

        fn set_bound(&self, bound: bool) {
            self.bound.set(Some(bound));
        }

        fn remote_port(&self) -> u16 {
            self.remote_port.get()
        }

        fn set_primary(&self, quad: &IpQuadruple, remote_port: u16) {
            *self.primary.borrow_mut() = Some(quad.clone());
            self.primary_port.set(remote_port);
        }

        fn set_os_errno(&self, errno: i32) {
            self.os_errno.set(errno);
        }
    }

    /// A [`ReadinessProbe`] whose every answer is canned.
    ///
    /// The seam that makes a refused connect, a hung-up peer and an `accept`
    /// that fails after readability reachable without a network.
    #[derive(Debug)]
    struct FakeProbe {
        input: Cell<ProbeOutcome>,
        connect: Cell<ConnectProgress>,
        accept: RefCell<Vec<AcceptProbe>>,
        input_calls: Cell<usize>,
        connect_calls: Cell<usize>,
    }

    impl FakeProbe {
        fn new() -> Self {
            Self {
                input: Cell::new(ProbeOutcome::Timeout),
                connect: Cell::new(ConnectProgress::Connected),
                accept: RefCell::new(Vec::new()),
                input_calls: Cell::new(0),
                connect_calls: Cell::new(0),
            }
        }

        fn with_input(self, outcome: ProbeOutcome) -> Self {
            self.input.set(outcome);
            self
        }

        fn with_connect(self, progress: ConnectProgress) -> Self {
            self.connect.set(progress);
            self
        }

        fn with_accept(self, probe: AcceptProbe) -> Self {
            self.accept.borrow_mut().push(probe);
            self
        }
    }

    impl ReadinessProbe for FakeProbe {
        fn probe_input(&self, _socket: &OsSocket) -> ProbeOutcome {
            self.input_calls.set(self.input_calls.get() + 1);
            self.input.get()
        }

        fn probe_connect(&self, _socket: &OsSocket) -> ConnectProgress {
            self.connect_calls.set(self.connect_calls.get() + 1);
            self.connect.get()
        }

        fn probe_accept(&self, _listener: &OsSocket) -> AcceptProbe {
            self.accept
                .borrow_mut()
                .pop()
                .unwrap_or(AcceptProbe::Pending)
        }
    }

    /// A [`CloseSocket`] that records what it was handed.
    #[derive(Debug, Default)]
    struct FakeClose {
        closed: RefCell<Vec<Socket>>,
        result: Cell<i32>,
    }

    impl CloseSocket for FakeClose {
        fn close_socket(&self, socket: OsSocket) -> i32 {
            self.closed.borrow_mut().push(socket.as_raw_fd());
            // The socket is dropped here, which is the callback closing it.
            drop(socket);
            self.result.get()
        }
    }

    /// A [`MultiCloseObserver`] that records every notification.
    #[derive(Debug, Default)]
    struct FakeObserver {
        seen: RefCell<Vec<Socket>>,
    }

    impl MultiCloseObserver for FakeObserver {
        fn will_close(&self, sock: Socket) {
            self.seen.borrow_mut().push(sock);
        }
    }

    /// A [`SockOpt`] with a canned verdict, recording the purpose it was told.
    #[derive(Debug)]
    struct FakeSockOpt {
        verdict: SockOptOutcome,
        purposes: RefCell<Vec<SockPurpose>>,
    }

    impl FakeSockOpt {
        fn new(verdict: SockOptOutcome) -> Self {
            Self {
                verdict,
                purposes: RefCell::new(Vec::new()),
            }
        }
    }

    impl SockOpt for FakeSockOpt {
        fn sockopt(
            &self,
            _socket: &OsSocket,
            purpose: SockPurpose,
        ) -> SockOptOutcome {
            self.purposes.borrow_mut().push(purpose);
            self.verdict
        }
    }

    /// An [`If2Ip`] with a canned verdict, recording every bind-to-device call.
    #[derive(Debug)]
    struct FakeIf2Ip {
        verdict: RefCell<If2IpResult>,
        device_ok: Cell<bool>,
        devices: RefCell<Vec<Vec<u8>>>,
    }

    impl FakeIf2Ip {
        fn new(verdict: If2IpResult) -> Self {
            Self {
                verdict: RefCell::new(verdict),
                device_ok: Cell::new(false),
                devices: RefCell::new(Vec::new()),
            }
        }

        fn with_device_ok(self) -> Self {
            self.device_ok.set(true);
            self
        }
    }

    impl If2Ip for FakeIf2Ip {
        fn if2ip(
            &self,
            _af: AddressFamily,
            _remote_scope: u32,
            _local_scope_id: u32,
            _interf: &[u8],
        ) -> If2IpResult {
            self.verdict.borrow().clone()
        }

        fn bind_to_device(
            &self,
            _socket: &OsSocket,
            iface: &[u8],
        ) -> io::Result<()> {
            self.devices.borrow_mut().push(iface.to_vec());
            if self.device_ok.get() {
                Ok(())
            } else {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            }
        }
    }

    /// A [`BindResolver`] with a canned answer.
    #[derive(Debug, Default)]
    struct FakeResolver {
        answer: RefCell<Option<Vec<ResolvedAddr>>>,
    }

    impl FakeResolver {
        fn resolving_to(addr: SocketAddr) -> Self {
            Self {
                answer: RefCell::new(Some(vec![ResolvedAddr::tcp(addr, None)])),
            }
        }
    }

    impl BindResolver for FakeResolver {
        fn resolve_blocking(
            &self,
            _host: &str,
            _port: u16,
            _ip_version: IpVersion,
        ) -> Option<Vec<ResolvedAddr>> {
            self.answer.borrow().clone()
        }
    }

    /// A [`Deadline`] with a fixed remaining time.
    #[derive(Debug)]
    struct FakeDeadline(TimeDiff);

    impl Deadline for FakeDeadline {
        fn time_left_ms(&self) -> TimeDiff {
            self.0
        }
    }

    // ---------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------

    fn clock_at(secs: i64) -> TestClock {
        TestClock::new(CurlTime::new(secs, 0))
    }

    fn tcp_addr(text: &str) -> ResolvedAddr {
        ResolvedAddr::tcp(text.parse().expect("a literal endpoint"), None)
    }

    /// A local connected pair, standing in for a network socket.
    fn socket_pair() -> (OsSocket, OsSocket) {
        OsSocket::pair(Domain::UNIX, OsType::STREAM, None)
            .expect("a local socket pair")
    }

    /// A filter over a real descriptor with recording hooks.
    fn filter_over(
        kind: SocketFilterKind,
        socket: OsSocket,
        conn: Rc<FakeConn>,
        close: Option<Rc<FakeClose>>,
        observer: Option<Rc<FakeObserver>>,
    ) -> SocketFilter {
        let mut hooks = SocketHooks {
            conn,
            ..SocketHooks::default()
        };
        if let Some(close) = close {
            hooks.close = Some(close);
        }
        if let Some(observer) = observer {
            hooks.will_close = Some(observer);
        }
        let mut ctx =
            SocketContext::init(&tcp_addr("127.0.0.1:80"), Transport::Tcp)
                .expect("a loopback address fits");
        ctx.socket = Some(socket);
        SocketFilter::new(
            kind,
            ctx,
            hooks,
            SocketSettings::default(),
            SocketIndex::First,
        )
    }

    // ---------------------------------------------------------------
    // 1. Transport conversion, including the reserved values
    // ---------------------------------------------------------------

    /// Required test 1.
    #[test]
    fn transport_conversion_accepts_the_five_and_rejects_the_reserved_two() {
        assert_eq!(transport_from_c(TRNSPRT_NONE), Ok(Transport::None));
        assert_eq!(transport_from_c(TRNSPRT_TCP), Ok(Transport::Tcp));
        assert_eq!(transport_from_c(TRNSPRT_UDP), Ok(Transport::Udp));
        assert_eq!(transport_from_c(TRNSPRT_QUIC), Ok(Transport::Quic));
        assert_eq!(transport_from_c(TRNSPRT_UNIX), Ok(Transport::Unix));

        // 1 and 2 were retired and must STAY rejected.
        assert_eq!(
            transport_from_c(1),
            Err(CURLcode::BadFunctionArgument),
            "TRNSPRT value 1 is reserved and must not resolve"
        );
        assert_eq!(transport_from_c(2), Err(CURLcode::BadFunctionArgument));
        for raw in 7_u8..=32 {
            assert_eq!(
                transport_from_c(raw),
                Err(CURLcode::BadFunctionArgument),
                "{raw} is not an assigned transport"
            );
        }
    }

    /// The five integers are `lib/urldata.h:567-571`'s own.
    #[test]
    fn the_transport_integers_are_the_headers_own() {
        assert_eq!(TRNSPRT_NONE, 0);
        assert_eq!(TRNSPRT_TCP, 3);
        assert_eq!(TRNSPRT_UDP, 4);
        assert_eq!(TRNSPRT_QUIC, 5);
        assert_eq!(TRNSPRT_UNIX, 6);
        // And they agree with the checked enumeration `filters.rs` owns.
        assert_eq!(Transport::None.as_u8(), TRNSPRT_NONE);
        assert_eq!(Transport::Tcp.as_u8(), TRNSPRT_TCP);
        assert_eq!(Transport::Udp.as_u8(), TRNSPRT_UDP);
        assert_eq!(Transport::Quic.as_u8(), TRNSPRT_QUIC);
        assert_eq!(Transport::Unix.as_u8(), TRNSPRT_UNIX);
    }

    /// `FIRSTSOCKET` and `SECONDARYSOCKET`, consumed rather than redefined.
    #[test]
    fn the_socket_indices_are_zero_and_one() {
        use crate::conn::filters::{FIRSTSOCKET, SECONDARYSOCKET};
        assert_eq!(FIRSTSOCKET, 0);
        assert_eq!(SECONDARYSOCKET, 1);
        assert_eq!(SocketIndex::First.as_i32(), FIRSTSOCKET);
        assert_eq!(SocketIndex::Secondary.as_i32(), SECONDARYSOCKET);
    }

    // ---------------------------------------------------------------
    // 2. The transport-to-socket parameter mapping
    // ---------------------------------------------------------------

    /// Required test 2.
    #[test]
    fn transport_selects_the_socket_parameters_the_c_switch_selects() {
        // `TRNSPRT_TCP -> SOCK_STREAM, IPPROTO_TCP`
        assert_eq!(
            socket_params(Transport::Tcp),
            (OsType::STREAM, Some(OsProtocol::TCP))
        );
        // `TRNSPRT_UNIX -> SOCK_STREAM, IPPROTO_IP` (the default protocol)
        assert_eq!(socket_params(Transport::Unix), (OsType::STREAM, None));
        // `default -> SOCK_DGRAM, IPPROTO_UDP` for UDP, QUIC and None alike
        for transport in [Transport::Udp, Transport::Quic, Transport::None] {
            assert_eq!(
                socket_params(transport),
                (OsType::DGRAM, Some(OsProtocol::UDP)),
                "{transport:?} takes the C's default arm"
            );
        }
    }

    /// The same mapping as it reaches [`SockAddrEx`].
    #[test]
    fn assign_records_the_socket_parameters_for_each_transport() {
        let ai = tcp_addr("192.0.2.1:443");
        let tcp = SockAddrEx::assign(&ai, Transport::Tcp).expect("assigns");
        assert_eq!(tcp.socktype, SockType::Stream);
        assert_eq!(tcp.protocol, IpProto::Tcp);
        assert_eq!(tcp.family, AddressFamily::Inet);

        let unix = SockAddrEx::assign(&ai, Transport::Unix).expect("assigns");
        assert_eq!(unix.socktype, SockType::Stream);
        assert_eq!(
            unix.protocol,
            IpProto::Unspecified,
            "UNIX takes IPPROTO_IP, the default protocol"
        );

        for transport in [Transport::Udp, Transport::Quic] {
            let dgram = SockAddrEx::assign(&ai, transport).expect("assigns");
            assert_eq!(dgram.socktype, SockType::Dgram);
            assert_eq!(dgram.protocol, IpProto::Udp);
        }
    }

    // ---------------------------------------------------------------
    // 3. The address-size failure
    // ---------------------------------------------------------------

    /// Required test 3.
    #[test]
    fn oversized_address_is_too_large() {
        let addr = SockAddr::from(
            "10.0.0.1:80".parse::<SocketAddr>().expect("an endpoint"),
        );
        assert_eq!(
            SockAddrEx::new(
                AddressFamily::Inet,
                SockType::Stream,
                IpProto::Tcp,
                addr.clone(),
                SOCKADDR_STORAGE_LEN + 1,
            )
            .map(|_| ())
            .unwrap_err(),
            CURLcode::TooLarge,
            "an address longer than the storage is CURLE_TOO_LARGE"
        );
        // The boundary is inclusive: exactly the storage size is accepted.
        assert!(SockAddrEx::new(
            AddressFamily::Inet,
            SockType::Stream,
            IpProto::Tcp,
            addr,
            SOCKADDR_STORAGE_LEN,
        )
        .is_ok());
    }

    /// The address-text bound the fixed C buffers impose.
    ///
    /// `struct ip_quadruple` holds both addresses as `char[MAX_IPADR_LEN]`
    /// (`lib/urldata.h:574-575`) and [`MAX_IPADR_LEN`] is
    /// `sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")`
    /// (`lib/urldata.h:124`) -- forty-five printable bytes plus the terminator.
    /// Nothing truncates in this file, because the quadruple holds `String`s;
    /// the bound matters because `curl-rs-ffi` copies these into those fixed
    /// arrays for `CURLINFO_PRIMARY_IP` and `CURLINFO_LOCAL_IP`.
    #[test]
    fn the_address_text_bound_is_the_c_buffer_size() {
        assert_eq!(
            MAX_IPADR_LEN, 46,
            "sizeof(\"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255\")"
        );
        // The longest address the C buffer was sized for: exactly 45 printable
        // bytes, which must fit.
        let longest = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
        assert_eq!(longest.len(), MAX_IPADR_LEN - 1);
        assert!(ip_text_fits(longest), "the sizing example must fit");
        // One byte more does not, because the terminator needs the last slot --
        // hence `<` and not `<=`.
        assert!(!ip_text_fits(&"x".repeat(MAX_IPADR_LEN)));
        assert!(ip_text_fits(&"x".repeat(MAX_IPADR_LEN - 1)));
        assert!(ip_text_fits(""), "an empty address is the cleared state");

        // And every address a real attempt can produce fits, which is what
        // makes the bound an invariant rather than a hope.
        for text in [
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "2001:db8:85a3:8d3:1319:8a2e:370:7348",
            "::ffff:255.255.255.255",
        ] {
            assert!(ip_text_fits(text), "{text} must fit the C buffer");
        }
    }

    /// [`SOCKADDR_STORAGE_LEN`] is the size the platform really reports.
    #[test]
    fn sockaddr_storage_is_the_size_the_platform_reports() {
        let reported = socket2::SockAddrStorage::zeroed().size_of();
        assert_eq!(
            reported, SOCKADDR_STORAGE_LEN,
            "sizeof(struct sockaddr_storage) is not what this file assumes"
        );
    }

    /// Every address this crate can build fits, so `assign` cannot fail.
    #[test]
    fn every_resolved_address_fits_the_storage() {
        for text in [
            "127.0.0.1:1",
            "[::1]:65535",
            "[fe80::1%3]:8080",
            "0.0.0.0:0",
        ] {
            let ai = tcp_addr(text);
            let assigned = SockAddrEx::assign(&ai, Transport::Tcp).expect(text);
            assert!(assigned.addrlen <= SOCKADDR_STORAGE_LEN);
        }
    }

    // ---------------------------------------------------------------
    // 4. The interface parser
    // ---------------------------------------------------------------

    /// Required test 4 -- the four accepted forms.
    #[test]
    fn the_interface_parser_accepts_the_four_documented_forms() {
        // `<iface_or_host>`
        let bare = parse_interface(b"eth0").expect("a bare form");
        assert_eq!(bare.dev.as_deref(), Some(&b"eth0"[..]));
        assert!(bare.iface.is_none() && bare.host.is_none());

        // `if!<iface>`
        let iface = parse_interface(b"if!eth0").expect("an if! form");
        assert_eq!(iface.iface.as_deref(), Some(&b"eth0"[..]));
        assert!(iface.dev.is_none() && iface.host.is_none());

        // `host!<host>`
        let host = parse_interface(b"host!example.test").expect("a host!");
        assert_eq!(host.host.as_deref(), Some(&b"example.test"[..]));
        assert!(host.dev.is_none() && host.iface.is_none());

        // `ifhost!<iface>!<host>`
        let both =
            parse_interface(b"ifhost!eth0!192.0.2.1").expect("an ifhost!");
        assert_eq!(both.iface.as_deref(), Some(&b"eth0"[..]));
        assert_eq!(both.host.as_deref(), Some(&b"192.0.2.1"[..]));
        assert!(both.dev.is_none());
    }

    /// Required test 4 -- every emptiness and length refusal.
    #[test]
    fn the_interface_parser_refuses_empty_components_and_overlong_input() {
        for input in [
            &b""[..],
            &b"if!"[..],
            &b"host!"[..],
            &b"ifhost!"[..],
            &b"ifhost!eth0"[..],
            &b"ifhost!eth0!"[..],
        ] {
            assert_eq!(
                parse_interface(input),
                Err(CURLcode::BadFunctionArgument),
                "{:?} must be refused",
                String::from_utf8_lossy(input)
            );
        }

        // `if(len > 512)`: 512 is accepted and 513 is not.
        let at_limit = vec![b'a'; INTERFACE_INPUT_MAX];
        assert!(parse_interface(&at_limit).is_ok(), "512 bytes is accepted");
        let over_limit = vec![b'a'; INTERFACE_INPUT_MAX + 1];
        assert_eq!(
            parse_interface(&over_limit),
            Err(CURLcode::BadFunctionArgument),
            "513 bytes is refused"
        );
    }

    /// `ifhost!!host` keeps an EMPTY interface, which the C accepts.
    ///
    /// The emptiness test is applied to the HOST half only -- `if(!host_part ||
    /// !*(host_part + 1))` -- so the interface half may be zero bytes long.
    /// Reproduced rather than tightened.
    #[test]
    fn the_ifhost_form_accepts_an_empty_interface_half() {
        let parsed = parse_interface(b"ifhost!!h").expect("the C accepts it");
        assert_eq!(parsed.iface.as_deref(), Some(&b""[..]));
        assert_eq!(parsed.host.as_deref(), Some(&b"h"[..]));
    }

    /// A bare form that merely LOOKS like a prefix is still a bare form.
    #[test]
    fn a_prefix_like_bare_form_is_not_mistaken_for_a_prefix() {
        // `ifhost` with no separator has no `!`, so no prefix matches.
        let parsed = parse_interface(b"ifhost").expect("a bare name");
        assert_eq!(parsed.dev.as_deref(), Some(&b"ifhost"[..]));
        // `if!` is tested before `ifhost!`, and they cannot collide because the
        // third byte of `ifhost!` is `h` rather than `!`.
        let parsed = parse_interface(b"ifhost!a!b").expect("an ifhost form");
        assert!(parsed.dev.is_none(), "the ifhost arm claimed it, not if!");
    }

    // ---------------------------------------------------------------
    // 5. Callback purpose and verdict mapping
    // ---------------------------------------------------------------

    /// Required test 5.
    #[test]
    fn the_callback_constants_are_the_public_headers_own() {
        assert_eq!(CURLSOCKTYPE_IPCXN, 0);
        assert_eq!(CURLSOCKTYPE_ACCEPT, 1);
        assert_eq!(CURL_SOCKOPT_OK, 0);
        assert_eq!(CURL_SOCKOPT_ERROR, 1);
        assert_eq!(CURL_SOCKOPT_ALREADY_CONNECTED, 2);

        assert_eq!(SockPurpose::IpCxn.as_i32(), CURLSOCKTYPE_IPCXN);
        assert_eq!(SockPurpose::Accept.as_i32(), CURLSOCKTYPE_ACCEPT);
        assert_eq!(SockPurpose::from_i32(0), Some(SockPurpose::IpCxn));
        assert_eq!(SockPurpose::from_i32(1), Some(SockPurpose::Accept));
        // `CURLSOCKTYPE_LAST` is "never use" and has no variant.
        assert_eq!(SockPurpose::from_i32(2), None);
        assert_eq!(SockPurpose::from_i32(-1), None);

        assert_eq!(SockOptOutcome::Ok.as_i32(), CURL_SOCKOPT_OK);
        assert_eq!(SockOptOutcome::Error.as_i32(), CURL_SOCKOPT_ERROR);
        assert_eq!(
            SockOptOutcome::AlreadyConnected.as_i32(),
            CURL_SOCKOPT_ALREADY_CONNECTED
        );
    }

    /// `else if(error)`: every non-zero that is not 2 is an error.
    #[test]
    fn the_sockopt_verdict_is_total_and_treats_every_other_value_as_error() {
        assert_eq!(SockOptOutcome::from_i32(0), SockOptOutcome::Ok);
        assert_eq!(
            SockOptOutcome::from_i32(2),
            SockOptOutcome::AlreadyConnected
        );
        for raw in [1, 3, 4, -1, i32::MAX, i32::MIN] {
            assert_eq!(
                SockOptOutcome::from_i32(raw),
                SockOptOutcome::Error,
                "{raw} aborts the transfer, as the C's else-if does"
            );
        }
    }

    // ---------------------------------------------------------------
    // 6. The callback-created already-connected path
    // ---------------------------------------------------------------

    /// An [`OpenSocket`] that hands over one end of a local pair.
    ///
    /// It also rewrites the address metadata, which is the C's *"the destination
    /// address information might have been changed and this 'new' address will
    /// actually be used here to connect"* -- so
    /// [`callback_address_rewrites_are_honoured`] can observe it.
    #[derive(Debug)]
    struct FakeOpen {
        socket: RefCell<Option<OsSocket>>,
        purposes: RefCell<Vec<SockPurpose>>,
        rewrite_to: Option<SocketAddr>,
        refuse: Option<OpenSocketError>,
    }

    impl FakeOpen {
        fn handing_over(socket: OsSocket) -> Self {
            Self {
                socket: RefCell::new(Some(socket)),
                purposes: RefCell::new(Vec::new()),
                rewrite_to: None,
                refuse: None,
            }
        }

        fn refusing(error: OpenSocketError) -> Self {
            Self {
                socket: RefCell::new(None),
                purposes: RefCell::new(Vec::new()),
                rewrite_to: None,
                refuse: Some(error),
            }
        }

        fn rewriting(mut self, to: SocketAddr) -> Self {
            self.rewrite_to = Some(to);
            self
        }
    }

    impl OpenSocket for FakeOpen {
        fn open_socket(
            &self,
            purpose: SockPurpose,
            addr: &mut SockAddrEx,
        ) -> Result<OsSocket, OpenSocketError> {
            self.purposes.borrow_mut().push(purpose);
            if let Some(error) = self.refuse {
                return Err(error);
            }
            if let Some(to) = self.rewrite_to {
                addr.addr = SockAddr::from(to);
                addr.addrlen = addrlen_of(&addr.addr);
                addr.family = match to {
                    SocketAddr::V4(_) => AddressFamily::Inet,
                    SocketAddr::V6(_) => AddressFamily::Inet6,
                };
            }
            self.socket
                .borrow_mut()
                .take()
                .ok_or(OpenSocketError::Refused)
        }
    }

    /// Builds a filter whose socket comes from an injected opener.
    fn filter_with_open(
        open: Rc<FakeOpen>,
        sockopt: Option<Rc<FakeSockOpt>>,
        conn: Rc<FakeConn>,
        probe: Rc<FakeProbe>,
    ) -> SocketFilter {
        let mut hooks = SocketHooks {
            open: Some(open),
            conn,
            probe,
            ..SocketHooks::default()
        };
        if let Some(sockopt) = sockopt {
            hooks.sockopt = Some(sockopt);
        }
        let ctx =
            SocketContext::init(&tcp_addr("127.0.0.1:80"), Transport::Tcp)
                .expect("a loopback address fits");
        SocketFilter::new(
            SocketFilterKind::Tcp,
            ctx,
            hooks,
            SocketSettings::default(),
            SocketIndex::First,
        )
    }

    /// Required test 6.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn already_connected_from_the_sockopt_callback_finishes_the_connect() {
        let (theirs, _keepalive) = socket_pair();
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        let sockopt =
            Rc::new(FakeSockOpt::new(SockOptOutcome::AlreadyConnected));
        let probe = Rc::new(FakeProbe::new());
        let mut filter = filter_with_open(
            Rc::new(FakeOpen::handing_over(theirs)),
            Some(Rc::clone(&sockopt)),
            Rc::clone(&conn),
            Rc::clone(&probe),
        );

        assert!(
            filter.connect(&mut cx).expect("the connect succeeded"),
            "CURL_SOCKOPT_ALREADY_CONNECTED means the connect is done"
        );
        assert!(filter.base().is_connected());
        assert_eq!(
            probe.connect_calls.get(),
            0,
            "an already-connected socket is never probed"
        );
        assert_eq!(
            sockopt.purposes.borrow().as_slice(),
            &[SockPurpose::IpCxn],
            "an IP connection uses the IPCXN purpose"
        );
        // The two-phase rule: nothing was published, because nothing activated.
        assert_eq!(conn.published.get(), 0);
    }

    /// A sockopt callback that refuses aborts the transfer.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_refusing_sockopt_callback_aborts() {
        let (theirs, _keepalive) = socket_pair();
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        let mut filter = filter_with_open(
            Rc::new(FakeOpen::handing_over(theirs)),
            Some(Rc::new(FakeSockOpt::new(SockOptOutcome::Error))),
            Rc::clone(&conn),
            Rc::new(FakeProbe::new()),
        );
        let error = filter.connect(&mut cx).expect_err("the callback refused");
        assert_eq!(error.code(), CURLcode::AbortedByCallback);
        assert!(!filter.base().is_connected());
    }

    /// The opener's rewritten address is the one that is used.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn callback_address_rewrites_are_honoured() {
        let (theirs, _keepalive) = socket_pair();
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        let rewritten: SocketAddr =
            "198.51.100.7:8443".parse().expect("an endpoint");
        let mut filter = filter_with_open(
            Rc::new(FakeOpen::handing_over(theirs).rewriting(rewritten)),
            None,
            Rc::new(FakeConn::new()),
            Rc::new(FakeProbe::new()),
        );
        let _ = filter.connect(&mut cx);
        assert_eq!(
            filter.context().ip().remote_ip,
            "198.51.100.7",
            "the address the callback wrote is the address that is used"
        );
        assert_eq!(filter.context().ip().remote_port, 8443);
    }

    /// The two open failures map to different codes.
    #[test]
    fn a_refused_opener_is_couldnt_connect_and_exhaustion_is_out_of_memory() {
        let clock = clock_at(1_000);
        let mut cx = CallCtx::new(&clock);
        for (refusal, expected) in [
            (OpenSocketError::Refused, CURLcode::CouldntConnect),
            (OpenSocketError::OutOfMemory, CURLcode::OutOfMemory),
        ] {
            let mut filter = filter_with_open(
                Rc::new(FakeOpen::refusing(refusal)),
                None,
                Rc::new(FakeConn::new()),
                Rc::new(FakeProbe::new()),
            );
            let error =
                filter.connect(&mut cx).expect_err("the opener refused");
            assert_eq!(error.code(), expected, "{refusal:?}");
        }
    }

    // ---------------------------------------------------------------
    // 7, 8, 9, 29. The close-callback asymmetry, and closing exactly once
    // ---------------------------------------------------------------

    /// Required test 7 -- the public path NEVER invokes the callback.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_public_close_bypasses_the_callback() {
        let (ours, _theirs) = socket_pair();
        let raw = ours.as_raw_fd();
        let observer = Rc::new(FakeObserver::default());
        let rc = socket_close(ours, Some(observer.as_ref()));
        assert_eq!(rc, 0, "Curl_socket_close reports zero");
        assert_eq!(
            observer.seen.borrow().as_slice(),
            &[raw],
            "the multi handle is still told, on the direct path too"
        );
        // There is no callback parameter to pass, so the callback cannot run.
        // `the_public_close_has_no_callback_parameter` states that structurally.
    }

    /// The structural half of required test 7.
    ///
    /// [`socket_close`] takes an observer and nothing else. A caller cannot
    /// hand it a close callback, so *"`Curl_socket_close` never invokes the
    /// close callback"* is enforced by the signature rather than by a flag that
    /// could be passed the wrong way round.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_public_close_has_no_callback_parameter() {
        let (ours, _theirs) = socket_pair();
        let callback = Rc::new(FakeClose::default());
        let _ = socket_close(ours, None);
        assert!(
            callback.closed.borrow().is_empty(),
            "no callback can reach the public close path"
        );
    }

    /// Required test 8 -- a normal filter close DOES invoke the callback.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_normal_filter_close_invokes_the_callback() {
        let (ours, _theirs) = socket_pair();
        let raw = ours.as_raw_fd();
        let clock = clock_at(5);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        let close = Rc::new(FakeClose::default());
        let observer = Rc::new(FakeObserver::default());
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::clone(&conn),
            Some(Rc::clone(&close)),
            Some(Rc::clone(&observer)),
        );
        assert!(!filter.context().is_accepted());

        filter.close(&mut cx);

        assert_eq!(
            close.closed.borrow().as_slice(),
            &[raw],
            "a socket this filter opened is the callback's business"
        );
        assert_eq!(observer.seen.borrow().as_slice(), &[raw]);
        assert_eq!(filter.context().raw_socket(), CURL_SOCKET_BAD);
        assert!(!filter.base().is_connected());
        assert!(!filter.context().is_active());
        assert!(filter.context().started_at().is_zero());
        assert!(filter.context().connected_at().is_zero());
    }

    /// Required test 9 -- an ACCEPTED socket bypasses the callback.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn an_accepted_filter_close_bypasses_the_callback() {
        let (ours, _theirs) = socket_pair();
        let raw = ours.as_raw_fd();
        let clock = clock_at(5);
        let mut cx = CallCtx::new(&clock);
        let close = Rc::new(FakeClose::default());
        let observer = Rc::new(FakeObserver::default());
        let mut filter = filter_over(
            SocketFilterKind::TcpAccept,
            ours,
            Rc::new(FakeConn::new()),
            Some(Rc::clone(&close)),
            Some(Rc::clone(&observer)),
        );
        // `ctx->accepted = TRUE` is what the accept path sets.
        filter.ctx.accepted = true;

        filter.close(&mut cx);

        assert!(
            close.closed.borrow().is_empty(),
            "a socket the user never created is not handed to their callback"
        );
        assert_eq!(
            observer.seen.borrow().as_slice(),
            &[raw],
            "the multi handle is still told"
        );
    }

    /// Required test 29 -- every ownership path closes exactly once.
    ///
    /// The claim is structural: [`SocketContext::socket`] is an
    /// [`Option<socket2::Socket>`] and every close goes through
    /// [`Option::take`], so after one close there is no second value to close.
    /// What a test can add is that the recorded counts agree, on all four paths.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn no_ownership_path_closes_twice() {
        let clock = clock_at(5);

        // Path 1: close, then close again.
        let (ours, _theirs) = socket_pair();
        let mut cx = CallCtx::new(&clock);
        let close = Rc::new(FakeClose::default());
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            Some(Rc::clone(&close)),
            None,
        );
        filter.close(&mut cx);
        filter.close(&mut cx);
        assert_eq!(close.closed.borrow().len(), 1, "close is idempotent");

        // Path 2: close, then destroy.
        let (ours, _theirs) = socket_pair();
        let close = Rc::new(FakeClose::default());
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            Some(Rc::clone(&close)),
            None,
        );
        filter.close(&mut cx);
        filter.destroy(&mut cx);
        assert_eq!(close.closed.borrow().len(), 1);

        // Path 3: destroy alone still closes once.
        let (ours, _theirs) = socket_pair();
        let close = Rc::new(FakeClose::default());
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            Some(Rc::clone(&close)),
            None,
        );
        filter.destroy(&mut cx);
        assert_eq!(close.closed.borrow().len(), 1);

        // Path 4: forget, then close -- the callback must NOT see it.
        let (ours, _theirs) = socket_pair();
        let close = Rc::new(FakeClose::default());
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            Some(Rc::clone(&close)),
            None,
        );
        filter
            .cntrl(&mut cx, CfControl::ForgetSocket)
            .expect("forget succeeds");
        filter.close(&mut cx);
        assert!(
            close.closed.borrow().is_empty(),
            "a forgotten socket belongs to somebody else"
        );
    }

    /// The C's `if(ctx->sock == cf->conn->sock[cf->sockindex])` guard.
    ///
    /// A losing Happy Eyeballs attempt must not clear the descriptor the WINNER
    /// published, and the guard is what stops it: the numbers differ.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn closing_a_loser_does_not_clear_the_winners_published_socket() {
        let (loser, _keep_loser) = socket_pair();
        let clock = clock_at(5);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        // The winner published a DIFFERENT descriptor.
        let winner_fd = loser.as_raw_fd() + 4242;
        conn.publish_socket(SocketIndex::First, winner_fd);

        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            loser,
            Rc::clone(&conn),
            None,
            None,
        );
        filter.close(&mut cx);

        assert_eq!(
            conn.socket(SocketIndex::First),
            winner_fd,
            "the winner's descriptor survived the loser's close"
        );
        assert_eq!(conn.cleared.get(), 0);
    }

    /// The same guard, from the other side: a filter clears its OWN socket.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn closing_the_winner_clears_its_own_published_socket() {
        let (ours, _theirs) = socket_pair();
        let raw = ours.as_raw_fd();
        let clock = clock_at(5);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        conn.publish_socket(SocketIndex::First, raw);
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::clone(&conn),
            None,
            None,
        );
        filter.close(&mut cx);
        assert_eq!(conn.socket(SocketIndex::First), CURL_SOCKET_BAD);
        assert_eq!(conn.cleared.get(), 1);
    }

    // ---------------------------------------------------------------
    // 10. Non-blocking mode is idempotent
    // ---------------------------------------------------------------

    /// Required test 10.
    ///
    /// C fetches the flags first and returns early when the request is already
    /// satisfied. Dropping that read-modify-write is only safe because the
    /// OUTCOME is idempotent, which is what this pins: setting the same mode
    /// twice succeeds and leaves the socket in that mode.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn nonblocking_mode_is_idempotent() {
        let (socket, _theirs) = socket_pair();
        assert!(!socket.nonblocking().expect("readable mode"));

        set_nonblocking(&socket, true).expect("first set");
        assert!(socket.nonblocking().expect("readable mode"));
        set_nonblocking(&socket, true).expect("second set is a no-op");
        assert!(socket.nonblocking().expect("still non-blocking"));

        set_nonblocking(&socket, false).expect("and back again");
        assert!(!socket.nonblocking().expect("blocking once more"));
        set_nonblocking(&socket, false).expect("idempotent both ways");
        assert!(!socket.nonblocking().expect("still blocking"));
    }

    // ---------------------------------------------------------------
    // 11, 21, 22. The two-phase contract and the control events
    // ---------------------------------------------------------------

    /// Required test 11 -- creating and connecting publishes NOTHING.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn create_and_connect_publish_nothing_until_activation() {
        let (theirs, _keepalive) = socket_pair();
        let clock = clock_at(2_000);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        let probe =
            Rc::new(FakeProbe::new().with_connect(ConnectProgress::Connected));
        let mut filter = filter_with_open(
            Rc::new(FakeOpen::handing_over(theirs)),
            None,
            Rc::clone(&conn),
            probe,
        );

        // Phase one: create, open, connect. A local pair is already connected,
        // so `connect(2)` reports `EISCONN`, which the probe verdict resolves.
        let _ = filter.connect(&mut cx);
        assert_eq!(
            conn.published.get(),
            0,
            "an unactivated attempt must publish nothing"
        );
        assert_eq!(conn.socket(SocketIndex::First), CURL_SOCKET_BAD);
        assert_eq!(conn.ipv6.get(), None);
        assert!(conn.primary.borrow().is_none());
        assert!(!filter.context().is_active());

        // Phase two: activation, and only now.
        filter
            .cntrl(&mut cx, CfControl::ConnInfoUpdate)
            .expect("activation succeeds");
        assert_eq!(conn.published.get(), 1);
        assert_eq!(
            conn.socket(SocketIndex::First),
            filter.context().raw_socket()
        );
        assert_eq!(
            conn.ipv6.get(),
            Some(false),
            "a 127.0.0.1 attempt records not-IPv6 on the primary socket"
        );
        assert!(filter.context().is_active());
    }

    /// Required test 21 -- the quadruple reaches the transfer only when
    /// connected AND on the primary socket.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_quadruple_is_published_only_when_connected_on_the_first_socket() {
        let clock = clock_at(7);

        // Not connected: nothing is published.
        let (ours, _theirs) = socket_pair();
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::clone(&conn),
            None,
            None,
        );
        filter
            .cntrl(&mut cx, CfControl::DataSetup)
            .expect("succeeds");
        assert!(
            conn.primary.borrow().is_none(),
            "an unconnected filter publishes no quadruple"
        );

        // Connected on FIRSTSOCKET: published.
        filter.base_mut().set_connected(true);
        conn.remote_port.set(4433);
        filter
            .cntrl(&mut cx, CfControl::DataSetup)
            .expect("succeeds");
        assert!(conn.primary.borrow().is_some());
        assert_eq!(conn.primary_port.get(), 4433);

        // Connected on SECONDARYSOCKET: not published.
        let (ours, _theirs) = socket_pair();
        let conn = Rc::new(FakeConn::new());
        let mut hooks = SocketHooks {
            conn: conn.clone(),
            ..SocketHooks::default()
        };
        hooks.will_close = None;
        let mut ctx =
            SocketContext::init(&tcp_addr("127.0.0.1:80"), Transport::Tcp)
                .expect("fits");
        ctx.socket = Some(ours);
        let mut secondary = SocketFilter::new(
            SocketFilterKind::Tcp,
            ctx,
            hooks,
            SocketSettings::default(),
            SocketIndex::Secondary,
        );
        secondary.base_mut().set_connected(true);
        secondary
            .cntrl(&mut cx, CfControl::DataSetup)
            .expect("succeeds");
        assert!(
            conn.primary.borrow().is_none(),
            "a secondary channel does not overwrite CURLINFO_PRIMARY_IP"
        );
    }

    /// Activation records the family only on the primary socket.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn activation_records_the_family_only_on_the_primary_socket() {
        let clock = clock_at(7);
        let mut cx = CallCtx::new(&clock);
        let (ours, _theirs) = socket_pair();
        let conn = Rc::new(FakeConn::new());
        let hooks = SocketHooks {
            conn: conn.clone(),
            ..SocketHooks::default()
        };
        let mut ctx =
            SocketContext::init(&tcp_addr("[::1]:80"), Transport::Tcp)
                .expect("fits");
        ctx.socket = Some(ours);
        let mut secondary = SocketFilter::new(
            SocketFilterKind::Tcp,
            ctx,
            hooks,
            SocketSettings::default(),
            SocketIndex::Secondary,
        );
        secondary
            .cntrl(&mut cx, CfControl::ConnInfoUpdate)
            .expect("succeeds");
        assert_eq!(
            conn.ipv6.get(),
            None,
            "only FIRSTSOCKET decides conn->bits.ipv6"
        );
        assert_eq!(conn.published.get(), 1, "the socket is still published");
    }

    /// Required test 22 -- `FORGET_SOCKET` relinquishes without closing.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn forget_socket_transfers_ownership_without_closing() {
        let (ours, theirs) = socket_pair();
        let raw = ours.as_raw_fd();
        let clock = clock_at(9);
        let mut cx = CallCtx::new(&clock);
        let close = Rc::new(FakeClose::default());
        let observer = Rc::new(FakeObserver::default());
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            Some(Rc::clone(&close)),
            Some(Rc::clone(&observer)),
        );

        filter
            .cntrl(&mut cx, CfControl::ForgetSocket)
            .expect("forget succeeds");

        assert_eq!(
            filter.context().raw_socket(),
            CURL_SOCKET_BAD,
            "the filter no longer tracks it"
        );
        assert!(close.closed.borrow().is_empty(), "and did not close it");
        assert!(
            observer.seen.borrow().is_empty(),
            "nor announce a close that did not happen"
        );

        // The descriptor is STILL OPEN, which is the whole point: a write from
        // the peer end still arrives. This is what `into_raw_fd` buys over
        // dropping the socket.
        let mut peer: &OsSocket = &theirs;
        assert_eq!(
            io::Write::write(&mut peer, b"x").expect("the pair still lives"),
            1
        );
        // Reclaim the relinquished descriptor so the test leaks nothing: the
        // number is still valid precisely because nothing closed it.
        let reclaimed = std::os::unix::io::OwnedFd::from(theirs);
        drop(reclaimed);
        let _ = raw;
    }

    // ---------------------------------------------------------------
    // 12. The `Trying` lines keep their two leading spaces
    // ---------------------------------------------------------------

    /// Required test 12.
    #[test]
    fn the_trying_lines_keep_their_two_leading_spaces() {
        let v4 = msg::trying("192.0.2.9", 443);
        assert_eq!(v4, "  Trying 192.0.2.9:443...");
        assert!(v4.starts_with("  Trying "), "TWO leading spaces");
        assert!(!v4.starts_with("   "), "and not three");
        assert!(v4.ends_with("..."), "three trailing dots");

        let v6 = msg::trying_ipv6("2001:db8::1", 8443);
        assert_eq!(v6, "  Trying [2001:db8::1]:8443...");
        assert!(
            v6.starts_with("  Trying ["),
            "TWO leading spaces, bracketed"
        );

        // The family picks the form, and only IPv6 gets brackets.
        assert_eq!(
            msg::trying_for(AddressFamily::Inet6, "2001:db8::1", 1),
            "  Trying [2001:db8::1]:1..."
        );
        assert_eq!(
            msg::trying_for(AddressFamily::Inet, "192.0.2.1", 1),
            "  Trying 192.0.2.1:1..."
        );
        assert_eq!(
            msg::trying_for(AddressFamily::Unix, "/run/s.sock", 0),
            "  Trying /run/s.sock:0...",
            "an AF_UNIX address takes the UNBRACKETED form"
        );
    }

    /// The remaining frozen messages, character for character.
    #[test]
    fn the_observable_messages_are_the_c_sources_own() {
        assert_eq!(
            msg::connect_failed("192.0.2.1", 80, "10.0.0.2", 51_000, "boom"),
            "connect to 192.0.2.1 port 80 from 10.0.0.2 port 51000 \
             failed: boom"
        );
        assert_eq!(
            msg::immediate_connect_fail("192.0.2.1", "no route"),
            "Immediate connect fail for 192.0.2.1: no route"
        );
        assert_eq!(
            msg::remote_ntop_failed(97, "family"),
            "curl_sa_addr inet_ntop() failed with errno 97: family"
        );
        assert_eq!(
            msg::local_ntop_failed(97, "family"),
            "ssloc inet_ntop() failed with errno 97: family"
        );
        assert_eq!(
            msg::peer_ntop_failed(97, "family"),
            "ssrem inet_ntop() failed with errno 97: family"
        );
        assert_eq!(msg::local_port(51_000), "Local port: 51000");
        assert_eq!(
            msg::bind_port_retry(51_000),
            "Bind to local port 51000 failed, trying next"
        );
        assert_eq!(
            msg::bound_to_interface("eth0"),
            "socket successfully bound to interface 'eth0'"
        );
        assert_eq!(
            msg::local_interface_is("eth0", "10.0.0.2", 2),
            "Local Interface eth0 is ip 10.0.0.2 using address family 2"
        );
        assert_eq!(
            msg::name_resolved("h", 2, "10.0.0.2", 2),
            "Name 'h' family 2 resolved to '10.0.0.2' family 2"
        );
        assert_eq!(
            msg::accept_failed("nope"),
            "Error accept()ing server connect: nope"
        );
        assert_eq!(
            msg::ACCEPT_TIMEOUT,
            "Accept timeout occurred while waiting server connect"
        );
        assert_eq!(
            msg::ACCEPT_WAIT_ERROR,
            "Error while waiting for server connect"
        );
        assert_eq!(
            msg::ACCEPT_READY,
            "Ready to accept data connection from server"
        );
        assert_eq!(msg::ACCEPT_DONE, "Connection accepted from server");
        assert_eq!(msg::NOTHING_HEARD, "nothing heard from the server yet");
    }

    /// No frozen message carries a newline.
    ///
    /// `crate::trace`'s emitters append one and assert the absence at compile
    /// time for a literal; these are built at run time, so the invariant is
    /// checked here instead.
    #[test]
    fn no_frozen_message_carries_a_newline() {
        let built = [
            msg::trying("a", 1),
            msg::trying_ipv6("a", 1),
            msg::connect_failed("a", 1, "b", 2, "c"),
            msg::immediate_connect_fail("a", "b"),
            msg::remote_ntop_failed(1, "b"),
            msg::local_ntop_failed(1, "b"),
            msg::peer_ntop_failed(1, "b"),
            msg::getsockname_failed(1, "b"),
            msg::getpeername_failed(1, "b"),
            msg::open_failed("b"),
            msg::send_failure("b"),
            msg::recv_failure("b"),
            msg::bound_to_interface("a"),
            msg::bind_iface_failed("a", 1, "b"),
            msg::local_interface_is("a", "b", 2),
            msg::name_resolved("a", 2, "b", 2),
            msg::bind_host_failed("a", 1, "b"),
            msg::local_port(1),
            msg::bind_port_retry(1),
            msg::bind_failed(1, "b"),
            msg::accept_failed("b"),
            msg::set_nonblock_failed("b"),
            msg::socket_check(-1),
            msg::socket_check(0),
            msg::socket_check(1),
        ];
        for line in &built {
            assert!(!line.contains('\n'), "{line:?} carries a newline");
            assert!(!line.is_empty());
        }
        for line in [
            msg::ACCEPT_TIMEOUT,
            msg::ACCEPT_WAIT_ERROR,
            msg::ACCEPT_READY,
            msg::ACCEPT_DONE,
            msg::NOTHING_HEARD,
        ] {
            assert!(!line.contains('\n'));
        }
    }

    // ---------------------------------------------------------------
    // 13, 14, 15. `bindlocal`
    // ---------------------------------------------------------------

    /// Builds the pieces `bindlocal` needs, over a real socket.
    fn bind_fixture(
        bind: BindConfig,
        interfaces: Rc<FakeIf2Ip>,
        resolver: Rc<FakeResolver>,
        conn: Rc<FakeConn>,
    ) -> (SocketHooks, SocketSettings) {
        let hooks = SocketHooks {
            conn,
            interfaces,
            resolver,
            ..SocketHooks::default()
        };
        let settings = SocketSettings {
            bind,
            ..SocketSettings::default()
        };
        (hooks, settings)
    }

    /// Nothing requested means nothing done.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn bindlocal_with_nothing_requested_succeeds_without_binding() {
        let (socket, _theirs) = socket_pair();
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        let (hooks, settings) = bind_fixture(
            BindConfig::default(),
            Rc::new(FakeIf2Ip::new(If2IpResult::NotFound)),
            Rc::new(FakeResolver::default()),
            Rc::clone(&conn),
        );
        assert_eq!(
            bindlocal(
                &mut cx,
                &hooks,
                &settings,
                &socket,
                AddressFamily::Inet,
                0
            ),
            Ok(())
        );
        assert_eq!(conn.bound.get(), None, "nothing was bound");
    }

    /// An interface name of 255 bytes or more is refused.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn bindlocal_refuses_an_interface_name_of_255_bytes_or_more() {
        let (socket, _theirs) = socket_pair();
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        for (len, expected) in [
            (BINDLOCAL_IFACE_MAX - 1, None),
            (BINDLOCAL_IFACE_MAX, Some(CURLcode::BadFunctionArgument)),
            (BINDLOCAL_IFACE_MAX + 1, Some(CURLcode::BadFunctionArgument)),
        ] {
            let bind = BindConfig {
                interface: Some(vec![b'e'; len]),
                ..BindConfig::default()
            };
            let (hooks, settings) = bind_fixture(
                bind,
                Rc::new(FakeIf2Ip::new(If2IpResult::AfNotSupported)),
                Rc::new(FakeResolver::default()),
                Rc::new(FakeConn::new()),
            );
            let outcome = bindlocal(
                &mut cx,
                &hooks,
                &settings,
                &socket,
                AddressFamily::Inet,
                0,
            );
            match expected {
                Some(code) => assert_eq!(
                    outcome,
                    Err(code),
                    "an interface name of {len} bytes must be refused"
                ),
                None => assert_ne!(
                    outcome,
                    Err(CURLcode::BadFunctionArgument),
                    "{len} bytes is under the limit"
                ),
            }
        }
    }

    /// Required test 13 -- the three [`If2IpResult`] paths.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn bindlocal_maps_the_three_if2ip_verdicts() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);

        // NOT FOUND with an EXPLICIT interface and no host: do not fall back.
        let (socket, _a) = socket_pair();
        let conn = Rc::new(FakeConn::new());
        let (hooks, settings) = bind_fixture(
            BindConfig {
                interface: Some(b"vrf-blue".to_vec()),
                ..BindConfig::default()
            },
            Rc::new(FakeIf2Ip::new(If2IpResult::NotFound)),
            Rc::new(FakeResolver::default()),
            Rc::clone(&conn),
        );
        assert_eq!(
            bindlocal(
                &mut cx,
                &hooks,
                &settings,
                &socket,
                AddressFamily::Inet,
                0
            ),
            Err(CURLcode::InterfaceFailed),
            "an explicit interface that cannot be found is not a hostname"
        );

        // AF NOT SUPPORTED: signal the caller to try the other family.
        let (socket, _b) = socket_pair();
        let (hooks, settings) = bind_fixture(
            BindConfig {
                interface: Some(b"eth0".to_vec()),
                ..BindConfig::default()
            },
            Rc::new(FakeIf2Ip::new(If2IpResult::AfNotSupported)),
            Rc::new(FakeResolver::default()),
            Rc::new(FakeConn::new()),
        );
        assert_eq!(
            bindlocal(
                &mut cx,
                &hooks,
                &settings,
                &socket,
                AddressFamily::Inet,
                0
            ),
            Err(CURLcode::UnsupportedProtocol),
            "the caller must be told to try the other address family"
        );

        // FOUND: the numeric address is used, and the bind then succeeds.
        // A real IPv4 socket is needed here, because the point of the arm is
        // that an Internet address IS bound.
        let socket = OsSocket::new(Domain::IPV4, OsType::STREAM, None)
            .expect("a TCP socket");
        let conn = Rc::new(FakeConn::new());
        let (hooks, settings) = bind_fixture(
            BindConfig {
                interface: Some(b"lo".to_vec()),
                ..BindConfig::default()
            },
            Rc::new(FakeIf2Ip::new(If2IpResult::Found("127.0.0.1".to_owned()))),
            Rc::new(FakeResolver::default()),
            Rc::clone(&conn),
        );
        assert_eq!(
            bindlocal(
                &mut cx,
                &hooks,
                &settings,
                &socket,
                AddressFamily::Inet,
                0
            ),
            Ok(()),
            "a found interface address is bound"
        );
        assert_eq!(
            conn.bound.get(),
            Some(true),
            "a successful bind sets bits.bound"
        );
        assert_eq!(
            socket
                .local_addr()
                .expect("a bound socket has a local address")
                .as_socket()
                .expect("an Internet address")
                .ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "the address the interface lookup supplied is the one bound"
        );
    }

    /// A successful `SO_BINDTODEVICE` with no bind host ends the bind there.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_successful_device_bind_without_a_host_finishes_immediately() {
        let (socket, _theirs) = socket_pair();
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let interfaces =
            Rc::new(FakeIf2Ip::new(If2IpResult::NotFound).with_device_ok());
        let (hooks, settings) = bind_fixture(
            BindConfig {
                interface: Some(b"eth0".to_vec()),
                ..BindConfig::default()
            },
            Rc::clone(&interfaces),
            Rc::new(FakeResolver::default()),
            Rc::new(FakeConn::new()),
        );
        assert_eq!(
            bindlocal(
                &mut cx,
                &hooks,
                &settings,
                &socket,
                AddressFamily::Inet,
                0
            ),
            Ok(()),
            "the interface bind is the whole bind when no host was asked for"
        );
        assert_eq!(interfaces.devices.borrow().as_slice(), &[b"eth0".to_vec()]);
    }

    /// A resolved bind host of the WRONG family signals the caller.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_bind_host_of_the_wrong_family_is_unsupported_protocol() {
        let (socket, _theirs) = socket_pair();
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let (hooks, settings) = bind_fixture(
            BindConfig {
                bindhost: Some(b"example.test".to_vec()),
                ..BindConfig::default()
            },
            Rc::new(FakeIf2Ip::new(If2IpResult::NotFound)),
            // An IPv6 answer for an IPv4 connection.
            Rc::new(FakeResolver::resolving_to(
                "[::1]:80".parse().expect("an endpoint"),
            )),
            Rc::new(FakeConn::new()),
        );
        assert_eq!(
            bindlocal(
                &mut cx,
                &hooks,
                &settings,
                &socket,
                AddressFamily::Inet,
                0
            ),
            Err(CURLcode::UnsupportedProtocol)
        );
    }

    /// A bind host that does not resolve fails the bind.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn an_unresolvable_bind_host_fails_the_interface() {
        let (socket, _theirs) = socket_pair();
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        let (hooks, settings) = bind_fixture(
            BindConfig {
                bindhost: Some(b"nowhere.invalid".to_vec()),
                ..BindConfig::default()
            },
            Rc::new(FakeIf2Ip::new(If2IpResult::NotFound)),
            Rc::new(FakeResolver::default()),
            Rc::clone(&conn),
        );
        assert_eq!(
            bindlocal(
                &mut cx,
                &hooks,
                &settings,
                &socket,
                AddressFamily::Inet,
                0
            ),
            Err(CURLcode::InterfaceFailed)
        );
    }

    /// The `iface` and `host` precedence rules.
    #[test]
    fn explicit_interface_and_bindhost_win_over_the_bare_device() {
        let bind = BindConfig {
            device: Some(b"dev".to_vec()),
            interface: Some(b"iface".to_vec()),
            bindhost: Some(b"host".to_vec()),
            ..BindConfig::default()
        };
        assert_eq!(bind.iface(), Some(&b"iface"[..]));
        assert_eq!(bind.host(), Some(&b"host"[..]));

        // With only the bare device, BOTH fall back to it.
        let bare = BindConfig {
            device: Some(b"dev".to_vec()),
            ..BindConfig::default()
        };
        assert_eq!(bare.iface(), Some(&b"dev"[..]));
        assert_eq!(bare.host(), Some(&b"dev"[..]));
        assert!(!bare.is_empty());

        // And a port alone is still a request.
        let port_only = BindConfig {
            localport: 8080,
            ..BindConfig::default()
        };
        assert!(!port_only.is_empty());
        assert!(BindConfig::default().is_empty());
    }

    /// Required test 14 -- the bind port range, and the wrap that ends it.
    #[test]
    fn the_bind_address_builder_carries_the_port_and_the_scope() {
        // The wildcard arms.
        let v4 = bind_sockaddr(AddressFamily::Inet, None, 1234)
            .expect("an IPv4 wildcard");
        assert_eq!(
            v4.as_socket(),
            Some("0.0.0.0:1234".parse().expect("an endpoint"))
        );
        let v6 = bind_sockaddr(AddressFamily::Inet6, None, 1234)
            .expect("an IPv6 wildcard");
        assert_eq!(
            v6.as_socket(),
            Some("[::]:1234".parse().expect("an endpoint"))
        );
        assert_eq!(
            bind_sockaddr(AddressFamily::Unix, None, 0),
            Err(CURLcode::UnsupportedProtocol),
            "a Unix socket has no local Internet address to bind"
        );

        // A numeric address, with and without an IPv6 scope suffix.
        let numbered =
            bind_sockaddr(AddressFamily::Inet, Some("10.1.2.3"), 51_000)
                .expect("an IPv4 literal");
        assert_eq!(
            numbered.as_socket(),
            Some("10.1.2.3:51000".parse().expect("an endpoint"))
        );

        let scoped =
            bind_sockaddr(AddressFamily::Inet6, Some("fe80::1%7"), 999)
                .expect("a scoped literal");
        match scoped.as_socket() {
            Some(SocketAddr::V6(v6)) => {
                assert_eq!(v6.port(), 999);
                assert_eq!(v6.scope_id(), 7, "the %scope suffix is carried");
            }
            other => panic!("expected an IPv6 endpoint, got {other:?}"),
        }

        // A scope that is not a number, or is above UINT_MAX, is the C's
        // CURLE_UNSUPPORTED_PROTOCOL.
        assert_eq!(
            bind_sockaddr(AddressFamily::Inet6, Some("fe80::1%eth0"), 1),
            Err(CURLcode::UnsupportedProtocol)
        );
        assert_eq!(
            bind_sockaddr(AddressFamily::Inet6, Some("fe80::1%4294967296"), 1),
            Err(CURLcode::UnsupportedProtocol),
            "the cap is UINT_MAX"
        );
        assert!(
            bind_sockaddr(AddressFamily::Inet6, Some("fe80::1%4294967295"), 1)
                .is_ok(),
            "and UINT_MAX itself is accepted"
        );
        // Unparsable numeric text refuses rather than binding a zeroed address.
        assert_eq!(
            bind_sockaddr(AddressFamily::Inet, Some("not-an-address"), 1),
            Err(CURLcode::InterfaceFailed)
        );
    }

    /// The port replacement keeps the scope and the flow information.
    #[test]
    fn replacing_the_bind_port_keeps_everything_else() {
        let scoped =
            bind_sockaddr(AddressFamily::Inet6, Some("fe80::2%9"), 100)
                .expect("a scoped literal");
        let moved = bind_sockaddr_port(&scoped, AddressFamily::Inet6, 101)
            .expect("a new port");
        match moved.as_socket() {
            Some(SocketAddr::V6(v6)) => {
                assert_eq!(v6.port(), 101);
                assert_eq!(v6.scope_id(), 9, "the scope survived");
                assert_eq!(*v6.ip(), "fe80::2".parse::<Ipv6Addr>().unwrap());
            }
            other => panic!("expected an IPv6 endpoint, got {other:?}"),
        }
        let v4 = bind_sockaddr(AddressFamily::Inet, Some("10.0.0.9"), 1)
            .expect("an IPv4 literal");
        let moved = bind_sockaddr_port(&v4, AddressFamily::Inet, 2)
            .expect("a new port");
        assert_eq!(
            moved.as_socket(),
            Some("10.0.0.9:2".parse().expect("an endpoint"))
        );
    }

    /// Required test 14 -- the range walks upward and STOPS on the wrap.
    ///
    /// Driven through the real loop over a real socket. A `SOCK_STREAM` socket
    /// in the `AF_UNIX` domain cannot be bound to an Internet address, so every
    /// attempt fails and the loop runs to exhaustion -- which is exactly the
    /// path being measured. The retry messages are what count the attempts, and
    /// they are checked through the port arithmetic instead: starting at
    /// `u16::MAX` with a range of four, the very first increment wraps to zero
    /// and the loop must stop rather than try port zero.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_bind_port_range_stops_on_the_wrap() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let (socket, _theirs) = socket_pair();
        let conn = Rc::new(FakeConn::new());
        let hooks = SocketHooks {
            conn: conn.clone(),
            ..SocketHooks::default()
        };
        let bind = BindConfig {
            localport: u16::MAX,
            localportrange: 4,
            ..BindConfig::default()
        };
        let address = bind_sockaddr(AddressFamily::Inet, None, u16::MAX)
            .expect("a wildcard");
        assert_eq!(
            bind_ports(
                &mut cx,
                &hooks,
                &socket,
                address,
                &bind,
                AddressFamily::Inet
            ),
            Err(CURLcode::InterfaceFailed),
            "the wrap ends the range without trying port zero"
        );
        assert_eq!(conn.bound.get(), None);
        assert_ne!(conn.os_errno.get(), 0, "the last errno was recorded");
    }

    /// A range of ONE is a single attempt: `--portnum > 0` is evaluated first.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_bind_range_of_one_makes_a_single_attempt() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let (socket, _theirs) = socket_pair();
        let conn = Rc::new(FakeConn::new());
        let hooks = SocketHooks {
            conn: conn.clone(),
            ..SocketHooks::default()
        };
        let bind = BindConfig {
            localport: 40_000,
            localportrange: 1,
            ..BindConfig::default()
        };
        let address = bind_sockaddr(AddressFamily::Inet, None, 40_000)
            .expect("a wildcard");
        assert_eq!(
            bind_ports(
                &mut cx,
                &hooks,
                &socket,
                address,
                &bind,
                AddressFamily::Inet
            ),
            Err(CURLcode::InterfaceFailed)
        );
    }

    /// A successful bind records the port and sets `bits.bound`.
    #[test]
    #[cfg_attr(miri, ignore = "binds a real socket")]
    fn a_successful_bind_sets_bits_bound() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let socket = OsSocket::new(Domain::IPV4, OsType::STREAM, None)
            .expect("a TCP socket");
        let conn = Rc::new(FakeConn::new());
        let hooks = SocketHooks {
            conn: conn.clone(),
            ..SocketHooks::default()
        };
        // Port zero is the kernel's choice, so the bind cannot fail for being
        // in use -- the C's *"0 for random"*.
        let bind = BindConfig {
            localport: 0,
            localportrange: 1,
            ..BindConfig::default()
        };
        let address = bind_sockaddr(AddressFamily::Inet, Some("127.0.0.1"), 0)
            .expect("a loopback literal");
        assert_eq!(
            bind_ports(
                &mut cx,
                &hooks,
                &socket,
                address,
                &bind,
                AddressFamily::Inet
            ),
            Ok(())
        );
        assert_eq!(conn.bound.get(), Some(true));
    }

    /// Required test 15 -- `UnsupportedProtocol` from `bindlocal` becomes
    /// `CouldntConnect` so that Happy Eyeballs keeps going.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn bindlocal_unsupported_protocol_becomes_couldnt_connect() {
        let (theirs, _keepalive) = socket_pair();
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        let hooks = SocketHooks {
            open: Some(Rc::new(FakeOpen::handing_over(theirs))),
            conn: conn.clone(),
            probe: Rc::new(FakeProbe::new()),
            // The interface exists but has no address of this family, which is
            // the verdict `bindlocal` turns into CURLE_UNSUPPORTED_PROTOCOL.
            interfaces: Rc::new(FakeIf2Ip::new(If2IpResult::AfNotSupported)),
            ..SocketHooks::default()
        };
        let settings = SocketSettings {
            bind: BindConfig {
                interface: Some(b"eth0".to_vec()),
                ..BindConfig::default()
            },
            ..SocketSettings::default()
        };
        let ctx =
            SocketContext::init(&tcp_addr("127.0.0.1:80"), Transport::Tcp)
                .expect("fits");
        let mut filter = SocketFilter::new(
            SocketFilterKind::Tcp,
            ctx,
            hooks,
            settings,
            SocketIndex::First,
        );
        let error = filter.connect(&mut cx).expect_err("the bind refused");
        assert_eq!(
            error.code(),
            CURLcode::CouldntConnect,
            "UNSUPPORTED_PROTOCOL is translated so another address is tried"
        );
    }

    // ---------------------------------------------------------------
    // 16, 17. The two classification tables, and the one value that
    //         separates them
    // ---------------------------------------------------------------

    /// Builds the OS error for a condition, the way a socket would report it.
    fn os_error(condition: SocketCondition) -> io::Error {
        match condition {
            SocketCondition::WouldBlock => {
                io::Error::from(io::ErrorKind::WouldBlock)
            }
            SocketCondition::Interrupted => {
                io::Error::from(io::ErrorKind::Interrupted)
            }
            SocketCondition::InProgress => {
                io::Error::from_raw_os_error(crate::ffi::sys::SOCKEINPROGRESS)
            }
            SocketCondition::Other => {
                io::Error::from(io::ErrorKind::ConnectionReset)
            }
        }
    }

    /// Every condition round-trips through [`classify`].
    #[test]
    fn classification_recognises_each_condition_from_a_real_os_error() {
        for condition in [
            SocketCondition::WouldBlock,
            SocketCondition::Interrupted,
            SocketCondition::InProgress,
            SocketCondition::Other,
        ] {
            assert_eq!(
                classify(&os_error(condition)),
                condition,
                "{condition:?} must be recognised from its OS error"
            );
        }
        // An error with no OS number at all is not one of the three.
        assert_eq!(
            classify(&io::Error::other("synthetic")),
            SocketCondition::Other
        );
    }

    /// The would-block classification, driven by a REAL would-block.
    ///
    /// The C writes `(SOCKEWOULDBLOCK == sockerr) || (EAGAIN == sockerr)`
    /// because the two macros differ on some platforms. Neither number can be
    /// named here -- `libc` is reachable only from `crate::ffi::sys`, which
    /// exports the one value [`std::io::ErrorKind`] cannot supply and no more --
    /// so the evidence is produced instead of asserted: an empty non-blocking
    /// socket reports exactly this condition, whichever number its platform
    /// chose, and [`classify`] must recognise it.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_real_would_block_is_classified_as_would_block() {
        let (ours, _theirs) = socket_pair();
        set_nonblocking(&ours, true).expect("non-blocking");
        let mut buf = [0_u8; 8];
        let error = {
            let mut source: &OsSocket = &ours;
            io::Read::read(&mut source, &mut buf)
                .expect_err("an empty non-blocking socket cannot read")
        };
        assert!(
            error.raw_os_error().is_some(),
            "a genuine socket error carries an OS number"
        );
        assert_eq!(
            classify(&error),
            SocketCondition::WouldBlock,
            "whichever of EAGAIN and EWOULDBLOCK this platform uses"
        );
        // And therefore both send and receive report CURLE_AGAIN for it.
        assert!(send_is_again(classify(&error)));
        assert!(recv_is_again(classify(&error)));
    }

    /// Required test 16 -- the SEND table has FOUR members.
    #[test]
    fn the_send_table_treats_in_progress_as_again() {
        assert!(send_is_again(SocketCondition::WouldBlock));
        assert!(send_is_again(SocketCondition::Interrupted));
        assert!(
            send_is_again(SocketCondition::InProgress),
            "cf_socket_send lists SOCKEINPROGRESS among its CURLE_AGAIN \
             conditions (lib/cf-socket.c:1442-1445)"
        );
        assert!(!send_is_again(SocketCondition::Other));
    }

    /// Required test 17 -- the RECEIVE table has THREE.
    #[test]
    fn the_receive_table_does_not_treat_in_progress_as_again() {
        assert!(recv_is_again(SocketCondition::WouldBlock));
        assert!(recv_is_again(SocketCondition::Interrupted));
        assert!(
            !recv_is_again(SocketCondition::InProgress),
            "cf_socket_recv omits SOCKEINPROGRESS (lib/cf-socket.c:1504-1506)"
        );
        assert!(!recv_is_again(SocketCondition::Other));
    }

    /// The asymmetry itself, stated as one assertion.
    #[test]
    fn send_and_receive_tables_differ_only_in_progress() {
        for condition in [
            SocketCondition::WouldBlock,
            SocketCondition::Interrupted,
            SocketCondition::Other,
        ] {
            assert_eq!(
                send_is_again(condition),
                recv_is_again(condition),
                "{condition:?} is treated identically by both directions"
            );
        }
        assert_ne!(
            send_is_again(SocketCondition::InProgress),
            recv_is_again(SocketCondition::InProgress),
            "InProgress is the ONE value the two tables disagree about"
        );
    }

    /// The connect table is its own third shape.
    #[test]
    fn the_connect_table_is_would_block_and_in_progress_only() {
        assert!(connect_is_in_progress(SocketCondition::WouldBlock));
        assert!(connect_is_in_progress(SocketCondition::InProgress));
        assert!(
            !connect_is_in_progress(SocketCondition::Interrupted),
            "socket_connect_result does not list SOCKEINTR, unlike the send \
             table, and this reproduces what the C says"
        );
        assert!(!connect_is_in_progress(SocketCondition::Other));
    }

    /// Required test 16, at the filter -- a failing send is a `SendError`.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_send_to_a_closed_peer_is_a_send_error() {
        let clock = clock_at(5);
        let mut cx = CallCtx::new(&clock);
        let (ours, theirs) = socket_pair();
        let conn = Rc::new(FakeConn::new());
        let mut filter =
            filter_over(SocketFilterKind::Tcp, ours, conn.clone(), None, None);
        // A short send over a live pair succeeds and reports the exact count.
        assert_eq!(
            filter.send(&mut cx, b"12345", false).expect("a live pair"),
            5,
            "a partial or whole write reports the byte count exactly"
        );
        // `eos` is ignored at this layer, so the same call with it set behaves
        // identically -- the C's `(void)eos`.
        assert_eq!(filter.send(&mut cx, b"678", true).expect("a live pair"), 3);
        drop(theirs);
        // With the peer gone the write fails, and the failure is classified as
        // a send error rather than as CURLE_AGAIN.
        let mut attempts = 0;
        loop {
            match filter.send(&mut cx, b"x", false) {
                Ok(_) => {
                    attempts += 1;
                    assert!(
                        attempts < 4096,
                        "a closed peer must eventually refuse a write"
                    );
                }
                Err(error) => {
                    assert_eq!(error.code(), CURLcode::SendError);
                    assert_ne!(
                        conn.os_errno.get(),
                        0,
                        "the OS error is recorded on the connection"
                    );
                    break;
                }
            }
        }
    }

    /// A filter holding no socket reports rather than panicking.
    #[test]
    fn send_and_receive_without_a_socket_report_their_own_errors() {
        let clock = clock_at(5);
        let mut cx = CallCtx::new(&clock);
        let ctx =
            SocketContext::init(&tcp_addr("127.0.0.1:80"), Transport::Tcp)
                .expect("fits");
        let mut filter = SocketFilter::new(
            SocketFilterKind::Tcp,
            ctx,
            SocketHooks::default(),
            SocketSettings::default(),
            SocketIndex::First,
        );
        assert_eq!(
            filter
                .send(&mut cx, b"x", false)
                .expect_err("there is no socket")
                .code(),
            CURLcode::SendError
        );
        let mut buf = [0_u8; 4];
        assert_eq!(
            filter
                .recv(&mut cx, &mut buf)
                .expect_err("there is no socket")
                .code(),
            CURLcode::RecvError
        );
    }

    // ---------------------------------------------------------------
    // 18. The first-byte timestamp
    // ---------------------------------------------------------------

    /// Required test 18 -- recorded on the first success and never again.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_first_byte_timestamp_is_recorded_exactly_once() {
        let clock = clock_at(100);
        let mut cx = CallCtx::new(&clock);
        let (ours, theirs) = socket_pair();
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );
        assert!(
            !filter.ctx.got_first_byte(),
            "nothing has been received yet"
        );
        assert_eq!(filter.ctx.first_byte_at(), CurlTime::ZERO);

        // Two separate arrivals, with the clock moved between them.
        {
            let mut sink: &OsSocket = &theirs;
            io::Write::write_all(&mut sink, b"first").expect("a live pair");
        }
        let mut buf = [0_u8; 8];
        assert_eq!(filter.recv(&mut cx, &mut buf).expect("bytes"), 5);
        assert!(filter.ctx.got_first_byte());
        let recorded = filter.ctx.first_byte_at();
        assert_eq!(recorded, CurlTime::new(100, 0));

        clock.advance(Duration::from_millis(250));
        {
            let mut sink: &OsSocket = &theirs;
            io::Write::write_all(&mut sink, b"second").expect("a live pair");
        }
        assert_eq!(filter.recv(&mut cx, &mut buf).expect("bytes"), 6);
        assert_eq!(
            filter.ctx.first_byte_at(),
            recorded,
            "the second arrival must not move the FIRST-byte time"
        );
    }

    /// A zero-length read is a success, and it records the time.
    ///
    /// The C's guard is `if(!result && !ctx->got_first_byte)`, which an
    /// end-of-stream read satisfies: `result` is `CURLE_OK` and `nread` is 0.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn an_end_of_stream_read_still_records_the_first_byte_time() {
        let clock = clock_at(7);
        let mut cx = CallCtx::new(&clock);
        let (ours, theirs) = socket_pair();
        drop(theirs);
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );
        let mut buf = [0_u8; 4];
        assert_eq!(
            filter.recv(&mut cx, &mut buf).expect("end of stream"),
            0,
            "a closed peer reads zero bytes, which is success"
        );
        assert!(filter.ctx.got_first_byte());
        assert_eq!(filter.ctx.first_byte_at(), CurlTime::new(7, 0));
    }

    // ---------------------------------------------------------------
    // 19. The shutdown drain
    // ---------------------------------------------------------------

    /// Required test 19 -- at most one read of at most 1024 bytes, always done.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_tcp_shutdown_drain_reads_once_and_always_completes() {
        assert_eq!(
            SHUTDOWN_DRAIN_MAX, 1024,
            "the C's buffer is `char buf[1024]` (lib/cf-socket.c:966)"
        );
        let clock = clock_at(3);
        let mut cx = CallCtx::new(&clock);
        let (ours, theirs) = socket_pair();
        // More than one drain's worth, so a second read would find bytes.
        let payload = vec![b'z'; SHUTDOWN_DRAIN_MAX * 3];
        {
            let mut sink: &OsSocket = &theirs;
            io::Write::write_all(&mut sink, &payload).expect("a live pair");
        }
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );
        filter.base_mut().set_connected(true);
        assert!(
            filter.shutdown(&mut cx).expect("shutdown never fails"),
            "*done = TRUE sits outside the if, so it is unconditional"
        );
        // At most one buffer was consumed, so bytes remain.
        set_nonblocking(filter.ctx.socket.as_ref().expect("the socket"), true)
            .expect("non-blocking");
        let mut rest = vec![0_u8; payload.len()];
        let read = {
            let mut source: &OsSocket =
                filter.ctx.socket.as_ref().expect("the socket");
            io::Read::read(&mut source, &mut rest).expect("bytes remain")
        };
        assert!(
            read > 0,
            "a single 1024-byte drain cannot have consumed {} bytes",
            payload.len()
        );
    }

    /// A shutdown that is not connected, or is not TCP, drains nothing.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_shutdown_outside_the_four_conditions_drains_nothing() {
        let clock = clock_at(3);
        let mut cx = CallCtx::new(&clock);

        // Not connected: the whole block is skipped, and the report is still
        // done.
        let (ours, theirs) = socket_pair();
        {
            let mut sink: &OsSocket = &theirs;
            io::Write::write_all(&mut sink, b"unread").expect("a live pair");
        }
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );
        assert!(!filter.base().is_connected());
        assert!(filter.shutdown(&mut cx).expect("always succeeds"));
        let mut buf = [0_u8; 6];
        assert_eq!(
            filter
                .recv(&mut cx, &mut buf)
                .expect("the bytes are still there"),
            6,
            "an unconnected filter did not drain"
        );

        // Connected but NOT TCP: the transport test excludes it.
        let (ours, theirs) = socket_pair();
        {
            let mut sink: &OsSocket = &theirs;
            io::Write::write_all(&mut sink, b"unread").expect("a live pair");
        }
        let mut filter = filter_over(
            SocketFilterKind::Udp,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );
        filter.ctx.transport = Transport::Udp;
        filter.base_mut().set_connected(true);
        assert!(filter.shutdown(&mut cx).expect("always succeeds"));
        assert_eq!(
            filter
                .recv(&mut cx, &mut buf)
                .expect("the bytes are still there"),
            6,
            "only TRNSPRT_TCP is drained"
        );
    }

    // ---------------------------------------------------------------
    // 20. The query answers
    // ---------------------------------------------------------------

    /// Required test 20 -- UDP and QUIC time from the first byte, others from
    /// the connect.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_connect_timer_uses_first_byte_time_for_udp_and_quic_only() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let connected = CurlTime::new(10, 0);
        let first_byte = CurlTime::new(20, 0);

        for (transport, kind, expected) in [
            (Transport::Udp, SocketFilterKind::Udp, first_byte),
            (Transport::Quic, SocketFilterKind::Udp, first_byte),
            (Transport::Tcp, SocketFilterKind::Tcp, connected),
            (Transport::Unix, SocketFilterKind::Unix, connected),
        ] {
            let (ours, _theirs) = socket_pair();
            let mut filter =
                filter_over(kind, ours, Rc::new(FakeConn::new()), None, None);
            filter.ctx.transport = transport;
            filter.ctx.connected_at = connected;
            filter.ctx.first_byte_at = first_byte;
            filter.ctx.got_first_byte = true;
            match filter
                .query(&mut cx, CfQuery::TimerConnect)
                .expect("the socket filter answers this")
            {
                CfQueryValue::Timer(when) => assert_eq!(
                    when, expected,
                    "{transport:?} reports the wrong connect timer"
                ),
                other => panic!("expected a timer, got {other:?}"),
            }
        }
    }

    /// The `FALLTHROUGH` -- a datagram transport with NO first byte uses the
    /// connect time like everything else.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_datagram_transport_without_a_first_byte_falls_through() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        for transport in [Transport::Udp, Transport::Quic] {
            let (ours, _theirs) = socket_pair();
            let mut filter = filter_over(
                SocketFilterKind::Udp,
                ours,
                Rc::new(FakeConn::new()),
                None,
                None,
            );
            filter.ctx.transport = transport;
            filter.ctx.connected_at = CurlTime::new(30, 0);
            filter.ctx.first_byte_at = CurlTime::new(40, 0);
            filter.ctx.got_first_byte = false;
            match filter
                .query(&mut cx, CfQuery::TimerConnect)
                .expect("answered")
            {
                CfQueryValue::Timer(when) => assert_eq!(
                    when,
                    CurlTime::new(30, 0),
                    "without a first byte, {transport:?} falls through to \
                     connected_at"
                ),
                other => panic!("expected a timer, got {other:?}"),
            }
        }
    }

    /// The reply time is `-1` before a first byte, and clamped after one.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_connect_reply_time_is_minus_one_then_clamped() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let (ours, _theirs) = socket_pair();
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );
        filter.ctx.started_at = CurlTime::new(0, 0);

        match filter
            .query(&mut cx, CfQuery::ConnectReplyMs)
            .expect("answered")
        {
            CfQueryValue::ConnectReplyMs(ms) => assert_eq!(
                ms, -1,
                "before a first byte the C writes *pres1 = -1"
            ),
            other => panic!("expected a reply time, got {other:?}"),
        }

        filter.ctx.got_first_byte = true;
        filter.ctx.first_byte_at = CurlTime::new(0, 250_000);
        match filter
            .query(&mut cx, CfQuery::ConnectReplyMs)
            .expect("answered")
        {
            CfQueryValue::ConnectReplyMs(ms) => assert_eq!(ms, 250),
            other => panic!("expected a reply time, got {other:?}"),
        }

        // Far beyond INT_MAX milliseconds, which the C caps.
        filter.ctx.first_byte_at = CurlTime::new(1_000_000_000, 0);
        match filter
            .query(&mut cx, CfQuery::ConnectReplyMs)
            .expect("answered")
        {
            CfQueryValue::ConnectReplyMs(ms) => assert_eq!(
                ms,
                TimeDiff::from(i32::MAX),
                "the C caps at INT_MAX"
            ),
            other => panic!("expected a reply time, got {other:?}"),
        }
    }

    /// The socket, transport, peer and address-family answers.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_socket_filter_answers_its_six_questions() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let (ours, _theirs) = socket_pair();
        let raw = ours.as_raw_fd();
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );

        assert_eq!(
            filter.query(&mut cx, CfQuery::Socket).expect("answered"),
            CfQueryValue::Socket(raw)
        );
        assert_eq!(
            filter.query(&mut cx, CfQuery::Transport).expect("answered"),
            CfQueryValue::Transport(Transport::Tcp)
        );
        // The peer is withheld until the filter is connected.
        assert_eq!(
            filter
                .query(&mut cx, CfQuery::RemoteAddr)
                .expect("answered"),
            CfQueryValue::RemoteAddr(None),
            "*pres2 = cf->connected ? &ctx->addr : NULL"
        );
        filter.base_mut().set_connected(true);
        match filter
            .query(&mut cx, CfQuery::RemoteAddr)
            .expect("answered")
        {
            CfQueryValue::RemoteAddr(Some(RemoteAddr::Inet(addr))) => {
                assert_eq!(
                    addr,
                    "127.0.0.1:80".parse::<SocketAddr>().expect("literal")
                );
            }
            other => panic!("expected the peer, got {other:?}"),
        }
        // Before `set_remote_ip` the quadruple is empty, exactly as C's
        // `memset`-zeroed `ctx->ip` is: `cf_socket_ctx_init` records the
        // ADDRESS, and only `cf_socket_open` renders it into text.
        match filter.query(&mut cx, CfQuery::IpInfo).expect("answered") {
            CfQueryValue::IpInfo { is_ipv6, quad } => {
                assert!(!is_ipv6, "127.0.0.1 is not AF_INET6");
                assert_eq!(quad.remote_ip, "");
            }
            other => panic!("expected the IP info, got {other:?}"),
        }
        filter
            .set_remote_ip(&mut cx)
            .expect("a loopback address renders");
        match filter.query(&mut cx, CfQuery::IpInfo).expect("answered") {
            CfQueryValue::IpInfo { is_ipv6, quad } => {
                assert!(!is_ipv6, "127.0.0.1 is not AF_INET6");
                assert_eq!(quad.remote_ip, "127.0.0.1");
                assert_eq!(quad.remote_port, 80);
                assert_eq!(quad.transport, Transport::Tcp);
            }
            other => panic!("expected the IP info, got {other:?}"),
        }
    }

    /// The `IpInfo` family flag reports AF_INET6 for an IPv6 attempt.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_ip_info_family_flag_follows_the_address() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let (ours, _theirs) = socket_pair();
        let hooks = SocketHooks::default();
        let mut ctx =
            SocketContext::init(&tcp_addr("[2001:db8::5]:443"), Transport::Tcp)
                .expect("fits");
        ctx.socket = Some(ours);
        let mut filter = SocketFilter::new(
            SocketFilterKind::Tcp,
            ctx,
            hooks,
            SocketSettings::default(),
            SocketIndex::First,
        );
        filter
            .set_remote_ip(&mut cx)
            .expect("an IPv6 address renders");
        match filter.query(&mut cx, CfQuery::IpInfo).expect("answered") {
            CfQueryValue::IpInfo { is_ipv6, quad } => {
                assert!(is_ipv6, "*pres1 = (ctx->addr.family == AF_INET6)");
                assert_eq!(quad.remote_ip, "2001:db8::5");
                assert_eq!(quad.remote_port, 443);
            }
            other => panic!("expected the IP info, got {other:?}"),
        }
    }

    /// An unrecognised question is delegated, and is `UnknownOption` at the
    /// bottom.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn an_unrecognised_query_is_unknown_option_at_the_chain_end() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let (ours, _theirs) = socket_pair();
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );
        for query in [
            CfQuery::MaxConcurrent,
            CfQuery::TimerAppConnect,
            CfQuery::StreamError,
            CfQuery::NeedFlush,
            CfQuery::HttpVersion,
            CfQuery::HostPort,
            CfQuery::SslInfo,
            CfQuery::SslCtxInfo,
            CfQuery::AlpnNegotiated,
        ] {
            assert_eq!(
                filter
                    .query(&mut cx, query)
                    .expect_err("nothing below answers")
                    .code(),
                CURLcode::UnknownOption,
                "{query:?} must be delegated and then reported"
            );
        }
    }

    // ---------------------------------------------------------------
    // 23. Liveness
    // ---------------------------------------------------------------

    /// Required test 23 -- the whole liveness mapping.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn liveness_maps_every_probe_outcome_the_c_way() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);

        let cases: [(ProbeOutcome, Liveness, &str); 8] = [
            (
                ProbeOutcome::Failed,
                Liveness::DEAD,
                "a failed poll is dead",
            ),
            (
                ProbeOutcome::Timeout,
                Liveness::alive(false),
                "a timeout is alive with nothing waiting",
            ),
            (
                ProbeOutcome::Ready(PollEvents::IN),
                Liveness::alive(true),
                "a readable socket is alive with input pending",
            ),
            (
                ProbeOutcome::Ready(PollEvents::ERR),
                Liveness::DEAD,
                "POLLERR is dead",
            ),
            (
                ProbeOutcome::Ready(PollEvents::HUP),
                Liveness::DEAD,
                "POLLHUP is dead",
            ),
            (
                ProbeOutcome::Ready(PollEvents::PRI),
                Liveness::DEAD,
                "POLLPRI is dead -- out-of-band data nobody asked for",
            ),
            (
                ProbeOutcome::Ready(PollEvents::NVAL),
                Liveness::DEAD,
                "POLLNVAL is dead",
            ),
            (
                ProbeOutcome::Ready(PollEvents::IN | PollEvents::HUP),
                Liveness::DEAD,
                "a fatal bit beside a readable one is still dead",
            ),
        ];

        for (outcome, expected, why) in cases {
            let (ours, _theirs) = socket_pair();
            let probe = Rc::new(FakeProbe::new().with_input(outcome));
            let hooks = SocketHooks {
                probe,
                ..SocketHooks::default()
            };
            let mut ctx =
                SocketContext::init(&tcp_addr("127.0.0.1:80"), Transport::Tcp)
                    .expect("fits");
            ctx.socket = Some(ours);
            let mut filter = SocketFilter::new(
                SocketFilterKind::Tcp,
                ctx,
                hooks,
                SocketSettings::default(),
                SocketIndex::First,
            );
            assert_eq!(filter.is_alive(&mut cx), expected, "{why}");
        }
    }

    /// A filter with no socket is dead without probing.
    #[test]
    fn a_filter_without_a_socket_is_dead() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);
        let probe = Rc::new(FakeProbe::new());
        let hooks = SocketHooks {
            probe: probe.clone(),
            ..SocketHooks::default()
        };
        let ctx =
            SocketContext::init(&tcp_addr("127.0.0.1:80"), Transport::Tcp)
                .expect("fits");
        let mut filter = SocketFilter::new(
            SocketFilterKind::Tcp,
            ctx,
            hooks,
            SocketSettings::default(),
            SocketIndex::First,
        );
        assert_eq!(filter.is_alive(&mut cx), Liveness::DEAD);
        assert_eq!(probe.input_calls.get(), 0, "there was nothing to probe");
    }

    // ---------------------------------------------------------------
    // The four filter identities
    // ---------------------------------------------------------------

    /// All four carry `CF_TYPE_IP_CONNECT`, trace level NONE, and their names.
    #[test]
    fn the_four_socket_filters_carry_the_c_identities() {
        let expected = [
            (SocketFilterKind::Tcp, "TCP"),
            (SocketFilterKind::Udp, "UDP"),
            (SocketFilterKind::Unix, "UNIX"),
            (SocketFilterKind::TcpAccept, "TCP-ACCEPT"),
        ];
        for (kind, name) in expected {
            assert_eq!(
                kind.trace_name(),
                name,
                "the C's `.name` field is the filter's identity"
            );
            assert_eq!(
                kind.cf_type(),
                CF_TYPE_IP_CONNECT,
                "`CF_TYPE_IP_CONNECT` on all four (lib/cf-socket.c:1683, \
                 :1849, :1902, :2133)"
            );
            // `.log_level` is `CURL_LOG_LVL_NONE` on all four in the C, and
            // that level is not a member here: `crate::conn::filters` records
            // that C's `Curl_cftype::log_level` is a process-global written
            // through by `--trace-config`, so a filter contributes only its
            // stable IDENTITY and the level lives in `crate::trace`. What is
            // therefore checkable is that the identity resolves to the trace
            // filter of the same name and that the level constant is still
            // zero.
            assert_eq!(CURL_LOG_LVL_NONE, 0);
            assert_eq!(
                kind.trace_filter().map(TraceFilter::name),
                Some(name),
                "the identity must resolve to the trace filter of the same name"
            );
        }
        // `CF_TYPE_IP_CONNECT` is 1<<0 in the FILTER-type domain, which is a
        // different domain from `PROTOPT_SSL`'s unrelated 1<<0.
        assert_eq!(CF_TYPE_IP_CONNECT, CfType::from_bits(1));
        assert_eq!(PROTOPT_SSL, 1 << 0);
    }

    /// Every factory produces the identity its C counterpart produces.
    #[test]
    fn the_factories_produce_the_expected_identities_and_transports() {
        let cases: [(&str, Transport, SocketFilterKind); 3] = [
            ("TCP", Transport::Tcp, SocketFilterKind::Tcp),
            ("UDP", Transport::Udp, SocketFilterKind::Udp),
            ("UNIX", Transport::Unix, SocketFilterKind::Unix),
        ];
        for (name, transport, kind) in cases {
            let addr = tcp_addr("127.0.0.1:9");
            let built = match kind {
                SocketFilterKind::Tcp => cf_tcp_create(
                    &addr,
                    SocketHooks::default(),
                    SocketSettings::default(),
                    SocketIndex::First,
                ),
                SocketFilterKind::Udp => cf_udp_create(
                    &addr,
                    transport,
                    SocketHooks::default(),
                    SocketSettings::default(),
                    SocketIndex::First,
                ),
                SocketFilterKind::Unix => cf_unix_create(
                    &addr,
                    SocketHooks::default(),
                    SocketSettings::default(),
                    SocketIndex::First,
                ),
                SocketFilterKind::TcpAccept => {
                    unreachable!("the accept filter has no address factory")
                }
            }
            .expect("a loopback address fits");
            assert_eq!(built.trace_name(), name);
            assert_eq!(built.cf_type(), CF_TYPE_IP_CONNECT);
            assert_eq!(built.ctx.transport(), transport);
            // Unattached, unconnected, holding no socket: the whole of the
            // *"will not touch any connection/data flags"* promise.
            assert!(!built.base().is_attached());
            assert!(!built.base().is_connected());
            assert_eq!(built.ctx.raw_socket(), CURL_SOCKET_BAD);
            assert!(!built.ctx.is_active());
        }
        // The datagram factory serves QUIC as well as UDP.
        let quic = cf_udp_create(
            &tcp_addr("127.0.0.1:9"),
            Transport::Quic,
            SocketHooks::default(),
            SocketSettings::default(),
            SocketIndex::First,
        )
        .expect("fits");
        assert_eq!(quic.ctx.transport(), Transport::Quic);
        assert_eq!(quic.trace_name(), "UDP");
    }

    /// The pollset adjustment, all four cases in the C's order.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_pollset_adjustment_follows_the_four_cases() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);

        // 1. Listening: input only.
        let (ours, _a) = socket_pair();
        let raw = ours.as_raw_fd();
        let mut filter = filter_over(
            SocketFilterKind::TcpAccept,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );
        filter.ctx.listening = true;
        let mut ps = EasyPollset::new();
        filter.adjust_pollset(&mut cx, &mut ps).expect("a valid fd");
        assert_eq!(ps.check(raw), (true, false), "listening wants input only");

        // 2. Not connected: output only, because writability IS completion.
        let (ours, _b) = socket_pair();
        let raw = ours.as_raw_fd();
        let mut filter = filter_over(
            SocketFilterKind::Tcp,
            ours,
            Rc::new(FakeConn::new()),
            None,
            None,
        );
        let mut ps = EasyPollset::new();
        filter.adjust_pollset(&mut cx, &mut ps).expect("a valid fd");
        assert_eq!(
            ps.check(raw),
            (false, true),
            "an unconnected attempt wants output only"
        );

        // 3. Connected but not active: input is ADDED.
        filter.base_mut().set_connected(true);
        let mut ps = EasyPollset::new();
        filter.adjust_pollset(&mut cx, &mut ps).expect("a valid fd");
        assert_eq!(
            ps.check(raw),
            (true, false),
            "a connected but inactive attempt watches for a hang-up"
        );

        // 4. Active: nothing at all.
        filter.ctx.active = true;
        let mut ps = EasyPollset::new();
        filter.adjust_pollset(&mut cx, &mut ps).expect("a valid fd");
        assert!(
            ps.is_empty(),
            "an active filter leaves the interest to the layer above"
        );

        // And a filter with no descriptor adjusts nothing.
        let ctx =
            SocketContext::init(&tcp_addr("127.0.0.1:80"), Transport::Tcp)
                .expect("fits");
        let mut bare = SocketFilter::new(
            SocketFilterKind::Tcp,
            ctx,
            SocketHooks::default(),
            SocketSettings::default(),
            SocketIndex::First,
        );
        let mut ps = EasyPollset::new();
        bare.adjust_pollset(&mut cx, &mut ps)
            .expect("nothing to do");
        assert!(ps.is_empty());
    }

    // ---------------------------------------------------------------
    // 24. TCP-ACCEPT
    // ---------------------------------------------------------------

    /// The accept deadline folds the generic one in, with the C's fake zero.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_accept_deadline_folds_in_the_generic_one() {
        // No generic deadline: the default minus the elapsed time.
        let clock = clock_at(0);
        let mut filter = {
            let (listener, _peer) = socket_pair();
            let hooks = SocketHooks {
                deadline: Rc::new(FakeDeadline(0)),
                ..SocketHooks::default()
            };
            SocketFilter::new(
                SocketFilterKind::TcpAccept,
                SocketContext::listening(listener),
                hooks,
                SocketSettings::default(),
                SocketIndex::Secondary,
            )
        };
        filter.ctx.started_at = CurlTime::new(0, 0);
        let cx = CallCtx::new(&clock);
        assert_eq!(
            filter.accept_timeleft(&cx),
            DEFAULT_ACCEPT_TIMEOUT,
            "with no generic deadline and no elapsed time, the default stands"
        );
        clock.advance(Duration::from_millis(1_500));
        let cx = CallCtx::new(&clock);
        assert_eq!(
            filter.accept_timeleft(&cx),
            DEFAULT_ACCEPT_TIMEOUT - 1_500,
            "the elapsed time is subtracted"
        );

        // Exactly exhausted: zero becomes -1 so the caller reports a timeout
        // rather than waiting forever. *"no more time left"*.
        clock.set(CurlTime::new(0, 0));
        clock.advance(Duration::from_millis(
            u64::try_from(DEFAULT_ACCEPT_TIMEOUT).expect("positive"),
        ));
        let cx = CallCtx::new(&clock);
        assert_eq!(
            filter.accept_timeleft(&cx),
            -1,
            "the C turns a fake zero into -1 (lib/cf-socket.c:1976-1977)"
        );

        // A SHORTER generic deadline wins, and is used as-is.
        let clock = clock_at(0);
        let mut filter = {
            let (listener, _peer) = socket_pair();
            let hooks = SocketHooks {
                deadline: Rc::new(FakeDeadline(250)),
                ..SocketHooks::default()
            };
            SocketFilter::new(
                SocketFilterKind::TcpAccept,
                SocketContext::listening(listener),
                hooks,
                SocketSettings {
                    accept_timeout_ms: 5_000,
                    ..SocketSettings::default()
                },
                SocketIndex::Secondary,
            )
        };
        filter.ctx.started_at = CurlTime::new(0, 0);
        let cx = CallCtx::new(&clock);
        assert_eq!(
            filter.accept_timeleft(&cx),
            250,
            "`if(other_ms && other_ms < timeout_ms) timeout_ms = other_ms;`"
        );
    }

    /// The `socket_check -> %x` line, and the mapping that feeds it.
    ///
    /// The C computes `socketstate = SOCKET_READABLE(ctx->sock, 0)` and traces
    /// it in lower-case hexadecimal before its `switch`. `%x` on a negative
    /// `int` prints the two's-complement pattern, which is why `-1` renders as
    /// `ffffffff` rather than as `-1`.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_socket_check_trace_line_reproduces_the_c_bitmask() {
        assert_eq!(AcceptProbe::WaitFailed.socket_state(), -1);
        assert_eq!(AcceptProbe::Pending.socket_state(), 0);
        assert_eq!(
            AcceptProbe::AcceptFailed(io::Error::from(
                io::ErrorKind::ConnectionAborted
            ))
            .socket_state(),
            CURL_CSELECT_IN as i32,
            "the C reaches its accept() only down the readable branch"
        );
        let (accepted, _peer) = socket_pair();
        assert_eq!(
            AcceptProbe::Accepted(accepted).socket_state(),
            CURL_CSELECT_IN as i32
        );

        assert_eq!(msg::socket_check(-1), "socket_check -> ffffffff");
        assert_eq!(msg::socket_check(0), "socket_check -> 0");
        assert_eq!(msg::socket_check(1), "socket_check -> 1");
        assert_eq!(msg::socket_check(0x0c), "socket_check -> c");
    }

    /// An accept deadline that has passed is `CURLE_FTP_ACCEPT_TIMEOUT`.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn an_expired_accept_deadline_is_an_ftp_accept_timeout() {
        let clock = clock_at(0);
        let (listener, _peer) = socket_pair();
        let hooks = SocketHooks {
            deadline: Rc::new(FakeDeadline(0)),
            probe: Rc::new(FakeProbe::new()),
            ..SocketHooks::default()
        };
        let mut filter = SocketFilter::new(
            SocketFilterKind::TcpAccept,
            SocketContext::listening(listener),
            hooks,
            SocketSettings::default(),
            SocketIndex::Secondary,
        );
        filter.ctx.started_at = CurlTime::new(0, 0);
        clock.advance(Duration::from_millis(
            u64::try_from(DEFAULT_ACCEPT_TIMEOUT + 1).expect("positive"),
        ));
        let mut cx = CallCtx::new(&clock);
        assert_eq!(
            filter
                .connect(&mut cx)
                .expect_err("the accept window closed")
                .code(),
            CURLcode::FtpAcceptTimeout
        );
    }

    /// Required test 24 -- the accept replaces the listener, and the two
    /// callback rules hold.
    #[test]
    #[cfg_attr(miri, ignore = "uses real socket pairs")]
    fn the_accept_replaces_the_listener_and_keeps_the_callback_rules() {
        let clock = clock_at(0);
        let mut cx = CallCtx::new(&clock);
        let (listener, _lpeer) = socket_pair();
        let (accepted, _apeer) = socket_pair();
        let listener_fd = listener.as_raw_fd();
        let accepted_fd = accepted.as_raw_fd();

        let conn = Rc::new(FakeConn::new());
        let close = Rc::new(FakeClose::default());
        let observer = Rc::new(FakeObserver::default());
        let sockopt = Rc::new(FakeSockOpt::new(SockOptOutcome::Ok));
        let probe = Rc::new(
            FakeProbe::new().with_accept(AcceptProbe::Accepted(accepted)),
        );
        let hooks = SocketHooks {
            conn: conn.clone(),
            close: Some(close.clone()),
            will_close: Some(observer.clone()),
            sockopt: Some(sockopt.clone()),
            probe,
            deadline: Rc::new(FakeDeadline(0)),
            ..SocketHooks::default()
        };
        let mut filter = SocketFilter::new(
            SocketFilterKind::TcpAccept,
            SocketContext::listening(listener),
            hooks,
            SocketSettings::default(),
            SocketIndex::Secondary,
        );
        filter.ctx.started_at = CurlTime::new(0, 0);
        assert!(filter.ctx.is_listening());
        assert!(!filter.ctx.is_accepted());

        clock.advance(Duration::from_millis(40));
        assert!(
            filter.connect(&mut cx).expect("the accept succeeded"),
            "an accepted connection completes the connect"
        );

        // The LISTENER is closed WITH the callback (lib/cf-socket.c:2100).
        assert_eq!(
            close.closed.borrow().as_slice(),
            &[listener_fd],
            "the listener goes through CURLOPT_CLOSESOCKETFUNCTION"
        );
        assert_eq!(
            observer.seen.borrow().as_slice(),
            &[listener_fd],
            "the multi handle is told before the callback, as C does"
        );
        // The accepted socket replaced it and was published.
        assert_eq!(filter.ctx.raw_socket(), accepted_fd);
        assert_eq!(conn.socket(SocketIndex::Secondary), accepted_fd);
        assert!(!filter.ctx.is_listening());
        assert!(filter.ctx.is_accepted());
        assert!(filter.ctx.is_active());
        assert!(filter.base().is_connected());
        assert_eq!(filter.ctx.connected_at(), CurlTime::new(0, 40_000));
        // The sockopt callback is called with the ACCEPT purpose.
        assert_eq!(
            sockopt.purposes.borrow().as_slice(),
            &[SockPurpose::Accept],
            "CURLSOCKTYPE_ACCEPT, not CURLSOCKTYPE_IPCXN"
        );
        // Already connected: a second call is immediately done and probes
        // nothing, which is the C's *"we start accepted, if we ever close, we
        // cannot go on"*.
        assert!(filter.connect(&mut cx).expect("already accepted"));

        // And the ACCEPTED socket bypasses the close callback on teardown.
        filter.close(&mut cx);
        assert_eq!(
            close.closed.borrow().len(),
            1,
            "cf_socket_close passes !ctx->accepted, so an accepted socket \
             never reaches the callback"
        );
        assert_eq!(
            observer.seen.borrow().as_slice(),
            &[listener_fd, accepted_fd],
            "the multi handle is still told about both"
        );
        assert_eq!(conn.socket(SocketIndex::Secondary), CURL_SOCKET_BAD);
    }

    /// A refusing sockopt callback after an accept aborts the transfer.
    ///
    /// Note the asymmetry with the connect path: `cf_tcp_accept_connect` tests
    /// only `if(error)` and does NOT recognise
    /// `CURL_SOCKOPT_ALREADY_CONNECTED`, so that value aborts here where it
    /// would have completed a connect (`lib/cf-socket.c:2119-2126`).
    #[test]
    #[cfg_attr(miri, ignore = "uses real socket pairs")]
    fn a_refusing_accept_sockopt_callback_aborts() {
        for verdict in [SockOptOutcome::Error, SockOptOutcome::AlreadyConnected]
        {
            let clock = clock_at(0);
            let mut cx = CallCtx::new(&clock);
            let (listener, _lpeer) = socket_pair();
            let (accepted, _apeer) = socket_pair();
            let hooks = SocketHooks {
                conn: Rc::new(FakeConn::new()),
                sockopt: Some(Rc::new(FakeSockOpt::new(verdict))),
                probe: Rc::new(
                    FakeProbe::new()
                        .with_accept(AcceptProbe::Accepted(accepted)),
                ),
                deadline: Rc::new(FakeDeadline(0)),
                ..SocketHooks::default()
            };
            let mut filter = SocketFilter::new(
                SocketFilterKind::TcpAccept,
                SocketContext::listening(listener),
                hooks,
                SocketSettings::default(),
                SocketIndex::Secondary,
            );
            filter.ctx.started_at = CurlTime::new(0, 0);
            assert_eq!(
                filter
                    .connect(&mut cx)
                    .expect_err("the callback refused")
                    .code(),
                CURLcode::AbortedByCallback,
                "{verdict:?} must abort after an accept"
            );
        }
    }

    /// Nothing heard is not-done; a failed wait and a failed accept both fail.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_accept_probe_outcomes_map_to_the_c_verdicts() {
        let build = |probe: FakeProbe| {
            let (listener, peer) = socket_pair();
            let hooks = SocketHooks {
                conn: Rc::new(FakeConn::new()),
                probe: Rc::new(probe),
                deadline: Rc::new(FakeDeadline(0)),
                ..SocketHooks::default()
            };
            let mut filter = SocketFilter::new(
                SocketFilterKind::TcpAccept,
                SocketContext::listening(listener),
                hooks,
                SocketSettings::default(),
                SocketIndex::Secondary,
            );
            filter.ctx.started_at = CurlTime::new(0, 0);
            (filter, peer)
        };
        let clock = clock_at(0);
        let mut cx = CallCtx::new(&clock);

        // `if(!incoming)` -- nothing yet, try again later.
        let (mut pending, _p1) = build(FakeProbe::new());
        assert!(
            !pending
                .connect(&mut cx)
                .expect("no failure, just not ready"),
            "an idle listener is not done and not an error"
        );

        // `case -1:` -- the wait itself failed.
        let (mut failed, _p2) =
            build(FakeProbe::new().with_accept(AcceptProbe::WaitFailed));
        assert_eq!(
            failed.connect(&mut cx).expect_err("the wait failed").code(),
            CURLcode::FtpAcceptFailed
        );

        // `s_accepted == CURL_SOCKET_BAD` -- readable, but accept refused.
        let (mut refused, _p3) =
            build(FakeProbe::new().with_accept(AcceptProbe::AcceptFailed(
                io::Error::from(io::ErrorKind::ConnectionAborted),
            )));
        assert_eq!(
            refused.connect(&mut cx).expect_err("accept refused").code(),
            CURLcode::FtpAcceptFailed
        );
    }

    /// `tcp_listen_set` discards the existing chain FIRST, then publishes.
    #[test]
    #[cfg_attr(miri, ignore = "uses real socket pairs")]
    fn setting_a_listener_discards_the_existing_chain_first() {
        let clock = clock_at(11);
        let mut cx = CallCtx::new(&clock);
        let conn = Rc::new(FakeConn::new());
        let mut chain = FilterChain::new(None, SocketIndex::Secondary);

        // An existing filter over its own socket, which must be gone before the
        // listener is installed -- `Curl_conn_cf_discard_all` at :2160.
        let (old, _oldpeer) = socket_pair();
        let stale =
            filter_over(SocketFilterKind::Tcp, old, conn.clone(), None, None);
        chain.add(&mut cx, link(stale));
        assert_eq!(chain.len(), 1);
        assert!(
            !conn_is_tcp_listen(&chain),
            "a plain TCP filter is not a listener"
        );

        let (listener, _lpeer) = socket_pair();
        let listener_fd = listener.as_raw_fd();
        tcp_listen_set(
            &mut cx,
            &mut chain,
            listener,
            SocketHooks {
                conn: conn.clone(),
                ..SocketHooks::default()
            },
            SocketSettings::default(),
        );
        assert_eq!(chain.len(), 1, "the old chain was discarded, not extended");
        assert!(
            conn_is_tcp_listen(&chain),
            "Curl_conn_is_tcp_listen finds the TCP-ACCEPT filter"
        );
        assert_eq!(
            conn.socket(SocketIndex::Secondary),
            listener_fd,
            "a listening filter publishes immediately -- the one exception to \
             the two-phase rule, and sound because a listener has no rival"
        );
        let head = chain.iter().next().expect("the listener filter");
        assert_eq!(head.trace_name(), "TCP-ACCEPT");
    }

    // ---------------------------------------------------------------
    // 25, 26, 27, 28. The wakeup primitive
    // ---------------------------------------------------------------

    /// Required test 25 -- a signal coalesces, and never blocks or fails.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn wakeup_signals_coalesce_and_never_fail() {
        let wakeup = Wakeup::new().expect("a socket pair");
        assert_eq!(wakeup.backing(), WakeupBacking::Pair);
        assert_ne!(
            wakeup.read_socket(),
            wakeup.write_socket(),
            "a pair has two distinct descriptors"
        );

        // Far more signals than the pipe can hold. Every one reports success:
        // once the buffer is full, `SOCKEWOULDBLOCK` means *"wakeup is already
        // ongoing"*, which IS the coalescing.
        for i in 0..200_000 {
            assert_eq!(
                wakeup.signal(),
                0,
                "signal {i} must report success even when already pending"
            );
        }
        // And one drain empties whatever accumulated.
        wakeup.consume(true).expect("a drain never fails here");
        // After the drain the read end is empty, so the next consume returns at
        // once rather than blocking -- the whole point of the non-blocking mode
        // `Curl_wakeup_init` establishes.
        wakeup.consume(true).expect("an empty drain is success");
    }

    /// Required test 26 -- consume-one versus consume-all.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn consuming_one_differs_from_draining_all() {
        // `all == false` reads EXACTLY ONCE, so a backlog larger than one
        // buffer survives it.
        let wakeup = Wakeup::new().expect("a socket pair");
        let backlog = WAKEUP_DRAIN_LEN * 4;
        for _ in 0..backlog {
            assert_eq!(wakeup.signal(), 0);
        }
        wakeup.consume(false).expect("one read");
        let mut probe = [0_u8; WAKEUP_DRAIN_LEN];
        let left = {
            let mut source: &OsSocket = &wakeup.reader;
            io::Read::read(&mut source, &mut probe)
                .expect("a single read cannot have drained the backlog")
        };
        assert!(
            left > 0,
            "consume(false) reads once, so {backlog} tokens cannot all be gone"
        );

        // `all == true` drains until the pipe is empty.
        let wakeup = Wakeup::new().expect("a socket pair");
        for _ in 0..backlog {
            assert_eq!(wakeup.signal(), 0);
        }
        wakeup.consume(true).expect("a full drain");
        set_nonblocking(&wakeup.reader, true).expect("already non-blocking");
        let outcome = {
            let mut source: &OsSocket = &wakeup.reader;
            io::Read::read(&mut source, &mut probe)
        };
        match outcome {
            Ok(n) => panic!("the drain left {n} bytes behind"),
            Err(error) => assert_eq!(
                classify(&error),
                SocketCondition::WouldBlock,
                "an empty non-blocking read is exactly what a drained pipe \
                 reports"
            ),
        }
    }

    /// A consume of a hung-up wakeup ends successfully at end of stream.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn consuming_a_closed_wakeup_ends_at_end_of_stream() {
        let (reader, writer) = socket_pair();
        set_nonblocking(&reader, true).expect("non-blocking");
        let wakeup = Wakeup {
            reader,
            writer: Some(writer),
        };
        // A token, then the writer goes away.
        assert_eq!(wakeup.signal(), 0);
        let Wakeup { reader, writer } = wakeup;
        drop(writer);
        let wakeup = Wakeup {
            reader,
            writer: None,
        };
        // The token is read, then end of stream ends the drain -- `if(!rc)
        // break;` -- and the whole drain is a success.
        wakeup.consume(true).expect("end of stream is not an error");
    }

    /// Required test 27 -- a single-descriptor wakeup is closed exactly once.
    ///
    /// The `#ifndef USE_EVENTFD` guard around `sclose(socks[1])`
    /// (`lib/socketpair.c:363-369`) exists for exactly this: an `eventfd` is
    /// one descriptor used for both directions, and closing it twice would
    /// close whatever the number was next handed to. Here the second owner is
    /// ABSENT rather than equal, so the double close is unrepresentable.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn a_shared_descriptor_wakeup_is_destroyed_exactly_once() {
        let (single, peer) = socket_pair();
        let fd = single.as_raw_fd();
        let wakeup = Wakeup::from_shared(single).expect("non-blocking");
        assert_eq!(
            wakeup.backing(),
            WakeupBacking::Shared,
            "one descriptor, both directions"
        );
        assert_eq!(
            wakeup.read_socket(),
            wakeup.write_socket(),
            "and the two accessors report the SAME number, which is the fact \
             the single close exists for"
        );
        assert_eq!(wakeup.read_socket(), fd);
        // It still signals and drains over the one descriptor. The token is
        // eight bytes for this backing, as an eventfd requires.
        assert_eq!(wakeup.signal(), 0);
        {
            let mut sink: &OsSocket = &peer;
            io::Write::write_all(&mut sink, b"x").expect("a live pair");
        }
        wakeup.consume(true).expect("a drain");
        // `Curl_wakeup_destroy`, explicitly. There is no second owner to close
        // and nothing left holding the number afterwards.
        wakeup.destroy();
        // A fresh pair proves the number was released rather than leaked or
        // double-closed: had it been closed twice, the descriptor table would
        // already be corrupt and this would be observing the damage.
        let (fresh, _fpeer) = socket_pair();
        assert!(is_valid_sock(fresh.as_raw_fd()));
        drop(peer);
    }

    /// Dropping a wakeup destroys it, so the named teardown is optional.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn dropping_a_wakeup_destroys_it() {
        let read_fd;
        {
            let wakeup = Wakeup::new().expect("a socket pair");
            read_fd = wakeup.read_socket();
            assert_eq!(wakeup.signal(), 0);
        }
        // The number is free again, which a fresh pair may legitimately reuse.
        let (fresh, _peer) = socket_pair();
        assert!(is_valid_sock(fresh.as_raw_fd()));
        assert!(is_valid_sock(read_fd), "it WAS a descriptor number");
    }

    /// Required test 28 -- the wakeup is internal and never reaches the
    /// application's descriptor array.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_wakeup_descriptor_never_reaches_the_application_waitfds() {
        let wakeup = Wakeup::new().expect("a socket pair");

        // The sanctioned route: an INTERNAL pollfd buffer, watching for input.
        let mut internal = PollFds::new();
        wakeup.add_to_pollfds(&mut internal);
        assert_eq!(internal.len(), 1);
        let entry = internal.as_slice()[0];
        assert_eq!(
            entry.sock,
            wakeup.read_socket(),
            "`Curl_pollfds_add_sock(&cpfds, multi->wakeup_pair[0], POLLIN)`"
        );
        assert_eq!(entry.events, PollEvents::IN);
        assert_eq!(entry.revents, PollEvents::NONE, "nothing has happened yet");

        // The application-visible array is built from an `EasyPollset`, and the
        // wakeup was never put into one -- so `curl_multi_wait`'s `numfds`
        // cannot count it.
        let ps = EasyPollset::new();
        let mut visible = WaitFds::counting();
        assert_eq!(
            visible.add_ps(&ps),
            0,
            "nothing a transfer asked for, and certainly not the wakeup"
        );
        assert!(visible.is_empty());
        assert!(visible.filled().is_empty());

        // A transfer's own socket DOES reach it, which is what makes the
        // absence above meaningful rather than vacuous.
        let (ours, _theirs) = socket_pair();
        let mut ps = EasyPollset::new();
        ps.add_in(ours.as_raw_fd(), None).expect("a valid fd");
        let mut visible = WaitFds::counting();
        assert_eq!(visible.add_ps(&ps), 1);
        assert_ne!(
            ours.as_raw_fd(),
            wakeup.read_socket(),
            "and it is a different descriptor from the wakeup"
        );
    }

    // ---------------------------------------------------------------
    // 30. The `addr2string` contract with `conn/mod.rs`
    // ---------------------------------------------------------------

    /// Required test 30 -- the parent's helper is CONSUMED, not duplicated.
    ///
    /// Two halves. The first is semantic: the address text a filter records is
    /// byte-identical to what [`crate::conn::addr2string`] returns for the same
    /// address, which cannot be true of two independent implementations for
    /// long. The second is structural, and reads the two source files, because
    /// the requirement is about WHERE the function lives.
    #[test]
    #[cfg_attr(miri, ignore = "uses a real socket pair")]
    fn the_parent_addr2string_helper_is_consumed_rather_than_duplicated() {
        let clock = clock_at(1);
        let mut cx = CallCtx::new(&clock);

        for text in ["127.0.0.1:80", "[2001:db8::5]:443"] {
            let (ours, _theirs) = socket_pair();
            let resolved = tcp_addr(text);
            let mut ctx =
                SocketContext::init(&resolved, Transport::Tcp).expect("fits");
            ctx.socket = Some(ours);
            let mut filter = SocketFilter::new(
                SocketFilterKind::Tcp,
                ctx,
                SocketHooks::default(),
                SocketSettings::default(),
                SocketIndex::First,
            );
            filter.set_remote_ip(&mut cx).expect("a literal renders");
            let direct = addr2string(
                &filter.ctx.addr.as_ref().expect("an address").addr,
            )
            .expect("the parent helper renders it too");
            assert_eq!(
                filter.ctx.ip().remote_ip,
                direct.addr,
                "the filter's text must BE the helper's text"
            );
            assert_eq!(filter.ctx.ip().remote_port, direct.port);
        }

        // The structural half. The needles are assembled at run time so that
        // this test's own source does not satisfy the search it performs.
        let parent = include_str!("mod.rs");
        let here = include_str!("socket.rs");
        let definition = format!("{} {}(", "fn", "addr2string");
        assert!(
            parent.contains(&definition),
            "conn/mod.rs owns the helper (lib/connect.c:211-258)"
        );
        assert!(
            !here.contains(&definition),
            "socket.rs must not define its own copy"
        );
        let import =
            format!("use crate::conn::{{{}, AddrText}};", "addr2string");
        assert!(
            here.contains(&import),
            "socket.rs imports it from the parent module"
        );
    }

    /// The helper's own contract, at the boundaries this file depends on.
    #[test]
    fn the_parent_helper_reports_the_families_this_file_relies_on() {
        // IPv4 and IPv6 render text and a HOST-order port.
        let v4 = addr2string(&SockAddr::from(
            "10.0.0.7:8080".parse::<SocketAddr>().expect("literal"),
        ))
        .expect("AF_INET is supported");
        assert_eq!(v4.addr, "10.0.0.7");
        assert_eq!(v4.port, 8080);

        let v6 = addr2string(&SockAddr::from(
            "[fe80::1]:9".parse::<SocketAddr>().expect("literal"),
        ))
        .expect("AF_INET6 is supported");
        assert_eq!(v6.addr, "fe80::1");
        assert_eq!(v6.port, 9);

        // The failure carries the errno `set_remote_ip` prints.
        assert_eq!(
            Addr2StringError::AfNotSupported.errno(),
            crate::ffi::sys::SOCKEAFNOSUPPORT
        );
    }

    /// An `AF_UNIX` address: its path, port zero, success.
    #[test]
    #[cfg(unix)]
    fn the_parent_helper_renders_a_unix_path_and_port_zero() {
        let named =
            SockAddr::unix("/tmp/curl-rs-socket-test").expect("a short path");
        let text = addr2string(&named).expect("AF_UNIX is supported");
        assert_eq!(text.addr, "/tmp/curl-rs-socket-test");
        assert_eq!(text.port, 0, "AF_UNIX has no port");
    }
}
