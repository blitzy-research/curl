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

//! The TLS session resumption cache, and the bytes it serialises to.
//!
//! Rust counterpart of three C files read as one:
//!
//! * `lib/vtls/vtls_scache.c` (1,222 lines) -- the cache itself: the peer
//!   key, the peer slab and its LRU, session insertion, retrieval and
//!   return, and the HMAC-protected import and export paths.
//! * `lib/vtls/vtls_scache.h` -- the contract. `:39-42` pins the two
//!   lifetime ceilings this module must reproduce exactly:
//!
//!   ```text
//!   /* RFC 8446 (TLSv1.3) restrict lifetime to one week max, for
//!    * other, less secure versions, we restrict it to a day */
//!   #define CURL_SCACHE_MAX_13_LIFETIME_SEC    (60 * 60 * 24 * 7)
//!   #define CURL_SCACHE_MAX_12_LIFETIME_SEC    (60 * 60 * 24)
//!   ```
//!
//! * `lib/vtls/vtls_spack.c` (330 lines) -- the wire format a session
//!   packs to. Every constant, every width and every field order below is
//!   transcribed from it.
//!
//! # Why the pack format is frozen, not merely stable
//!
//! `Curl_ssl_session_pack` output is not an internal detail. It reaches a
//! *consumer* through `curl_easy_ssls_import` and `curl_easy_ssls_export`,
//! which the command-line tool drives with `--ssl-sessions`: one curl run
//! writes a session file and a later run -- possibly a different build, and
//! for a drop-in replacement possibly the C build -- reads it back. A single
//! reordered field or a widened integer silently invalidates every file curl
//! 8.19.0-DEV ever wrote. So [`TlsSession::pack`] emits the C's bytes and
//! [`TlsSession::unpack`] accepts the C's bytes, and the byte-golden tests at
//! the bottom of this file are the mechanism that keeps it that way.
//!
//! # What is deliberately absent, and the measurement behind each absence
//!
//! **No backend session object.** `struct Curl_ssl_scache_peer` carries `void
//! *sobj` with a `Curl_ssl_scache_obj_dtor *sobj_free` destructor
//! (`vtls_scache.h:101-121`, `vtls_scache.c:56-57`), reached through
//! `Curl_ssl_scache_add_obj` and `Curl_ssl_scache_get_obj`. Those two
//! functions have exactly **one** consumer in the entire C tree --
//! `lib/vtls/schannel.c:864` and `:1642`, caching a Windows credential handle
//! -- and Schannel is an alternate backend that AAP 0.2.2 excludes, on
//! platforms outside the four-target matrix. With nothing ever setting the
//! slot, the C's free-peer test `if(!peers[i].sobj &&
//! !Curl_llist_count(&peers[i].sessions))` (`vtls_scache.c:698-699`)
//! degenerates to the session count alone, which is what [`SessionCache`]
//! implements. Reproducing the slot would need either [`std::any::Any`] or a
//! type parameter threaded through the whole module, for a capability no
//! in-scope build can reach.
//!
//! **No SRP identity.** `:SRP-AUTH` in the peer key
//! (`vtls_scache.c:269-275`) and the peer's `srp_username` / `srp_password`
//! pair (`:53-54`) sit behind `#ifdef USE_TLS_SRP`.
//! [`crate::version`] withholds the `TLS-SRP` token because rustls offers no
//! SRP key exchange, so this build is the `#ifdef`-off compilation: the
//! fragment is never emitted and the peer stores no SRP credentials. Modelling
//! them would advertise a capability that does not exist, and AAP 0.6.5 makes
//! over-reporting the one failure mode that turns a clean skip into a hard
//! failure.
//!
//! **No `magic` field.** `CURL_SCACHE_MAGIC` and `GOOD_SCACHE`
//! (`vtls_scache.c:66-68`) guard against a freed or wrongly typed pointer
//! arriving as a cache. Neither is expressible here: a `&mut SessionCache` is
//! a `SessionCache`, so the three `CURLE_BAD_FUNCTION_ARGUMENT` returns that
//! guard produces have no reachable condition.
//!
//! # Nothing global: the clock, the generator and the lock are injected
//!
//! The C reads `time(NULL)` in four places (`vtls_scache.c:789`, `:890`,
//! `:1128`, `:1152`) and `Curl_rand` in one (`:1005`). Both become
//! parameters: a `&dyn Clock` from [`crate::util::timeval`] and a `&mut dyn
//! Rng` from [`crate::crypto::rand`]. That is what lets the seven-day clamp,
//! the expiry sweep, the LRU and the 64-byte salt-and-code be tested exactly
//! rather than approximately, and it is the same injection discipline the
//! rest of this crate applies.
//!
//! Locking is injected for a different reason. `Curl_ssl_scache_lock`
//! (`:585-596`) takes `CURL_LOCK_DATA_SSL_SESSION` with
//! `CURL_LOCK_ACCESS_SINGLE` **only** when the selected cache is the share's:
//!
//! ```text
//! void Curl_ssl_scache_lock(struct Curl_easy *data)
//! {
//!   if(CURL_SHARE_ssl_scache(data))
//!     Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION,
//!                     CURL_LOCK_ACCESS_SINGLE);
//! }
//! ```
//!
//! A multi handle's own cache is never locked at all. The lock therefore
//! belongs to the *sharing decision*, not to the cache -- so this module
//! defines the narrow [`ScacheLock`] seam and nothing more, and the future
//! share subsystem implements it over the caller's `CURLSHOPT_LOCKFUNC`. This
//! module imports nothing from `share`, which is what keeps the dependency
//! acyclic; `share` is also not yet a directory, and inventing a
//! `share/mod.rs` import would be a dependency on a file that does not exist.
//!
//! [`ScacheGuard`] is what the seam buys. The C has to write
//! `Curl_ssl_scache_unlock(data)` on every exit path, and
//! `Curl_ssl_session_import` needs a `bool locked` variable plus a
//! `goto out` to get it right (`:1079`, `:1096`, `:1137-1138`). Here the
//! guard releases in [`Drop`], so early return, `?` propagation and panic all
//! unlock, and the critical section is exactly the guard's scope.
//!
//! # Secrets stay out of keys, out of logs and out of `Debug`
//!
//! A session ticket is resumption material: whoever holds it can resume the
//! session. A client certificate path and a pinned-key spelling are
//! configuration, but the private key behind them never enters this module at
//! all. Three consequences are enforced rather than intended:
//!
//! * The peer key carries *paths* and *hashes*, never key bytes and never a
//!   passphrase. `cf_ssl_peer_key_add_hash` (`:102-125`) hashes a blob to 32
//!   bytes of lowercase hex precisely so the blob itself does not appear, and
//!   [`peer_key_make`] does the same.
//! * [`TlsSession`]'s [`fmt::Debug`] is hand-written and reports the ticket's
//!   *length*. A derived one would dump the ticket into any failed assertion
//!   or trace line that formatted a session.
//! * [`ScachePeer`]'s [`fmt::Debug`] reports whether a salt and code are set,
//!   not their values.
//!
//! # Visibility and safety
//!
//! `pub(crate)` throughout, with no `pub` item and no test-only re-export:
//! the C's contract was a header full of `extern` declarations under a
//! `Curl_` prefix, private by convention, and it becomes private by
//! enforcement here. There is no `#[cfg(feature = "tls")]` anywhere in this
//! directory -- the manifest declares no such feature, so the expression
//! would raise `unexpected 'cfg' condition value` under `-D warnings`, and an
//! off-switchable TLS feature would contradict "rustls exclusively with
//! validation on by default".
//!
//! Nothing here is provider-specific: the digest, the keyed digest and the
//! random bytes all arrive through [`crate::crypto`], so no rustls, `ring` or
//! `aws-lc-rs` constructor is named. And nothing here needs an exemption from
//! the crate root's `#![deny(unsafe_code)]`.

use std::collections::VecDeque;
use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::crypto::hmac::{hmac_sha256, HmacContext};
use crate::crypto::rand::{rand_bytes, Rng};
use crate::crypto::sha256::{sha256, Sha256, DIGEST_LEN};
use crate::error::CURLcode;
use crate::tls::{IetfProtoVersion, ReusedSession, SslPeer};
use crate::util::dynbuf::DynBuf;
use crate::util::timeval::Clock;

// =========================================================================
// Lifetimes, ceilings and suffixes -- the pinned constants
// =========================================================================

/// `CURL_SCACHE_MAX_13_LIFETIME_SEC` (`lib/vtls/vtls_scache.h:41`).
///
/// One week, written as the C writes it so that the arithmetic is visibly the
/// same expression rather than a number that happens to agree. RFC 8446
/// section 4.6.1 caps `ticket_lifetime` at seven days and curl enforces the
/// cap itself rather than trusting the server's value.
pub(crate) const MAX_13_LIFETIME_SEC: i64 = 60 * 60 * 24 * 7;

/// `CURL_SCACHE_MAX_12_LIFETIME_SEC` (`lib/vtls/vtls_scache.h:42`).
///
/// One day, for TLS 1.2 and earlier. The header's comment gives the reason --
/// "for other, less secure versions, we restrict it to a day" -- and the
/// shorter ceiling is the whole point: a pre-1.3 session identifier is
/// reusable across connections, so it is worth less time.
pub(crate) const MAX_12_LIFETIME_SEC: i64 = 60 * 60 * 24;

/// `scache->default_lifetime_secs` as `Curl_ssl_scache_create` sets it
/// (`lib/vtls/vtls_scache.c:548`): `(24 * 60 * 60)`, one day.
///
/// Applied when a session arrives with no usable expiry --
/// `Curl_ssl_session_create` documents `valid_until` of zero as "in case this
/// is not known" (`vtls_scache.h:142-143`) and the cache reads `<= 0`
/// (`:797`), so a negative value is treated as unknown too rather than as a
/// session that expired before the epoch.
///
/// Written `24 * 60 * 60` and not `60 * 60 * 24` because that is the order
/// the C writes it in at that line; the value is identical to
/// [`MAX_12_LIFETIME_SEC`] and the two are deliberately separate constants,
/// since one is a default and the other a ceiling.
pub(crate) const DEFAULT_LIFETIME_SEC: i64 = 24 * 60 * 60;

/// `CURL_SSL_TICKET_MAX` (`lib/vtls/vtls_scache.c:995`): 16 KiB.
///
/// The ceiling on one packed session, applied by
/// `curlx_dyn_init(&sbuf, CURL_SSL_TICKET_MAX)` at `:1163`.
///
/// [`DynBuf`] reproduces the C's ceiling arithmetic including its `+ 1` for
/// the terminator curl stores and this crate does not, so a buffer with this
/// ceiling admits at most `SSL_TICKET_MAX - 1` bytes -- exactly what curl
/// admits. Crossing it is [`CURLcode::TooLarge`], the code
/// `curlx_dyn_addn` returns.
pub(crate) const SSL_TICKET_MAX: usize = 16 * 1024;

/// The ceiling on a peer key: `curlx_dyn_init(&buf, 10 * 1024)`
/// (`lib/vtls/vtls_scache.c:150`).
///
/// A key is bounded because its inputs are not: `CURLOPT_SSL_CIPHER_LIST`,
/// `CURLOPT_CAPATH` and `CURLOPT_PINNEDPUBLICKEY` are all
/// application-supplied strings of arbitrary length, and three of them can
/// appear in one key.
#[allow(dead_code)] // Read by peer_key_make; consumers land with the backend.
pub(crate) const PEER_KEY_MAX: usize = 10 * 1024;

/// `CURL_SSLS_LOCAL_SUFFIX` (`lib/vtls/vtls_scache.c:127`).
///
/// Terminates a key that could not be made position-independent, because a
/// configured relative path did not resolve. Such a key is meaningless in
/// another process with a different working directory, so a peer holding one
/// is never exportable.
#[allow(dead_code)] // Read by peer_key_make; consumers land with the backend.
pub(crate) const LOCAL_SUFFIX: &str = ":L";

/// `CURL_SSLS_GLOBAL_SUFFIX` (`lib/vtls/vtls_scache.c:128`).
///
/// Terminates a key whose every path is absolute, which is what makes the
/// peer's sessions safe to hand to another process.
pub(crate) const GLOBAL_SUFFIX: &str = ":G";

/// Length of the per-peer export salt: `CURL_SHA256_DIGEST_LENGTH`
/// (`lib/vtls/vtls_scache.c:58`).
pub(crate) const SALT_LEN: usize = DIGEST_LEN;

/// Length of the per-peer export code: `CURL_SHA256_DIGEST_LENGTH`
/// (`lib/vtls/vtls_scache.c:59`).
pub(crate) const HMAC_LEN: usize = DIGEST_LEN;

/// Length of the `shmac` blob an export emits and an import accepts: the
/// salt followed by the code, `sizeof(peer->key_salt) +
/// sizeof(peer->key_hmac)` (`lib/vtls/vtls_scache.c:1103`).
///
/// Exactly 64. `Curl_ssl_session_import` rejects any other length with
/// `CURLE_BAD_FUNCTION_ARGUMENT` and explains why in a comment: "Either
/// salt+hmac was garbled by caller or is from a curl version that does
/// things differently."
pub(crate) const SHMAC_LEN: usize = SALT_LEN + HMAC_LEN;

// =========================================================================
// The session-pack tags -- `lib/vtls/vtls_spack.c:41-47`
// =========================================================================

/// `CURL_SPACK_VERSION` = `0x01` (`lib/vtls/vtls_spack.c:41`).
///
/// Both the format version and the first byte of every payload. The decoder
/// reads it before allocating anything and refuses any other value with
/// `CURLE_READ_ERROR` (`:256-262`).
pub(crate) const SPACK_VERSION: u8 = 0x01;

/// `CURL_SPACK_IETF_ID` = `0x02` (`lib/vtls/vtls_spack.c:42`).
///
/// Introduces the negotiated protocol identifier as a big-endian `u16`.
pub(crate) const SPACK_IETF_ID: u8 = 0x02;

/// `CURL_SPACK_VALID_UNTIL` = `0x03` (`lib/vtls/vtls_spack.c:43`).
///
/// Introduces the expiry as a big-endian `u64` of seconds since the epoch.
pub(crate) const SPACK_VALID_UNTIL: u8 = 0x03;

/// `CURL_SPACK_TICKET` = `0x04` (`lib/vtls/vtls_spack.c:44`).
///
/// Introduces the ticket as a big-endian `u16` length and that many bytes.
pub(crate) const SPACK_TICKET: u8 = 0x04;

/// `CURL_SPACK_ALPN` = `0x05` (`lib/vtls/vtls_spack.c:45`).
///
/// Optional. Introduces the negotiated ALPN protocol as a big-endian `u16`
/// length and that many bytes.
pub(crate) const SPACK_ALPN: u8 = 0x05;

/// `CURL_SPACK_EARLYDATA` = `0x06` (`lib/vtls/vtls_spack.c:46`).
///
/// Optional, and omitted when zero. Introduces the peer's advertised 0-RTT
/// maximum as a big-endian `u32` -- the one field that is four bytes wide.
pub(crate) const SPACK_EARLYDATA: u8 = 0x06;

/// `CURL_SPACK_QUICTP` = `0x07` (`lib/vtls/vtls_spack.c:47`).
///
/// Optional, and omitted when empty. Introduces the QUIC transport
/// parameters as a big-endian `u16` length and that many bytes.
pub(crate) const SPACK_QUICTP: u8 = 0x07;

// =========================================================================
// The session -- `struct Curl_ssl_session` (`vtls_scache.h:124-134`)
// =========================================================================

/// One TLS session ticket and everything the cache knows about it.
///
/// The successor of `struct Curl_ssl_session`, member for member:
///
/// | C member | here |
/// |----------|------|
/// | `const void *sdata` + `size_t sdata_len` | [`Self::ticket`], a `Vec<u8>` |
/// | `curl_off_t valid_until` | [`Self::valid_until`], an [`i64`] |
/// | `int ietf_tls_id` | [`Self::ietf_tls_id`], an [`IetfProtoVersion`] |
/// | `char *alpn` | [`Self::alpn`], an `Option<String>` |
/// | `size_t earlydata_max` | [`Self::earlydata_max`] |
/// | `const unsigned char *quic_tp`, `size_t quic_tp_len` | [`Self::quic_tp`] |
/// | `struct Curl_llist_node list` | gone -- see below |
///
/// # Ownership replaces three destructors
///
/// The C's constructors document "Takes ownership of `sdata` and `sobj`
/// regardless of return code" (`vtls_scache.h:137`) and
/// `Curl_ssl_session_create2` adds the same promise for `quic_tp` (`:152`).
/// Both then have to honour it on the failure paths by hand --
/// `vtls_scache.c:352-355` frees `sdata` before returning
/// `CURLE_BAD_FUNCTION_ARGUMENT`, `:358-363` frees both before returning
/// `CURLE_OUT_OF_MEMORY`, and `:374-377` calls the list destructor on a
/// half-built session. Taking the bytes **by value** makes every one of those
/// promises structural: a `Vec<u8>` moved into a constructor that returns
/// `Err` is dropped by the compiler, on every path, with no code to write and
/// none to forget.
///
/// The same argument retires `Curl_ssl_session_destroy` (`:383-393`) and the
/// `cf_ssl_scache_session_ldestroy` list callback (`:324-332`) entirely, along
/// with the `Curl_node_llist(&s->list)` test that exists only to decide which
/// of the two to run.
///
/// # The intrusive list node is gone
///
/// `struct Curl_llist_node list` embeds the session in its own container, so a
/// session knows which list it is in and destroying it means removing it from
/// that list. Here the container owns the sessions -- a
/// [`VecDeque<TlsSession>`] on the peer -- so membership is the container's
/// property, not the element's. That is what makes taking a session out of
/// the cache a *move* rather than an unlink plus a lifetime question.
#[derive(Clone, Eq, PartialEq)]
#[allow(dead_code)] // Consumers land with tls/rustls_backend.rs and share/.
pub(crate) struct TlsSession {
    /// `sdata` and `sdata_len` as one owned buffer: the ticket bytes.
    ///
    /// Non-empty for any session built through [`Self::new`] or
    /// [`Self::with_quic_tp`]; possibly empty for one recovered by
    /// [`Self::unpack`], which is faithful and is explained there.
    ticket: Vec<u8>,

    /// `ietf_tls_id`: the protocol version that negotiated this session.
    ///
    /// Typed rather than an `int`, which removes the C's `(uint16_t)` cast at
    /// `vtls_spack.c:210` -- [`IetfProtoVersion`] is a `u16` already, so a
    /// value too wide for the wire cannot be constructed.
    ietf_tls_id: IetfProtoVersion,

    /// `alpn`: the protocol ALPN selected, or [`None`] when none was.
    alpn: Option<String>,

    /// `valid_until`: seconds since the epoch at which the ticket expires.
    ///
    /// Zero or negative means "not known" on the way in; the cache replaces
    /// it with a real deadline before storing.
    valid_until: i64,

    /// `earlydata_max`: how much 0-RTT data the peer said it would accept.
    earlydata_max: usize,

    /// `quic_tp` and `quic_tp_len`: the QUIC transport parameters, when the
    /// session came from a QUIC handshake.
    quic_tp: Option<Vec<u8>>,
}

/// Reports the session's shape without disclosing the ticket.
///
/// Hand-written rather than derived, and the reason is a security property
/// rather than a formatting preference: a session ticket is resumption
/// material. `#[derive(Debug)]` would print the whole `Vec<u8>` into any
/// failed assertion, any `{:?}` in a trace line and any panic message that
/// happened to include a session. The length is what a reader debugging the
/// cache needs; the bytes are what an attacker needs.
impl fmt::Debug for TlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSession")
            .field("ticket_len", &self.ticket.len())
            .field("ietf_tls_id", &self.ietf_tls_id)
            .field("alpn", &self.alpn)
            .field("valid_until", &self.valid_until)
            .field("earlydata_max", &self.earlydata_max)
            .field("quic_tp_len", &self.quic_tp.as_ref().map(Vec::len))
            .finish()
    }
}

#[allow(dead_code)] // Consumers land with tls/rustls_backend.rs and share/.
impl TlsSession {
    /// `Curl_ssl_session_create` (`lib/vtls/vtls_scache.c:334-342`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for an empty ticket, which is the
    /// C's own check and its own code:
    ///
    /// ```text
    /// if(!sdata || !sdata_len) {
    ///   curlx_free(sdata);
    ///   return CURLE_BAD_FUNCTION_ARGUMENT;
    /// }
    /// ```
    ///
    /// The two C conditions collapse into one here because a `Vec<u8>` cannot
    /// be null; emptiness is the only way to express "no ticket".
    pub(crate) fn new(
        ticket: Vec<u8>,
        ietf_tls_id: IetfProtoVersion,
        alpn: Option<&str>,
        valid_until: i64,
        earlydata_max: usize,
    ) -> Result<Self, CURLcode> {
        Self::with_quic_tp(
            ticket,
            ietf_tls_id,
            alpn,
            valid_until,
            earlydata_max,
            None,
        )
    }

    /// `Curl_ssl_session_create2` (`lib/vtls/vtls_scache.c:344-381`): the
    /// variation that also carries QUIC transport parameters.
    ///
    /// The C keeps two entry points because C has no default arguments and
    /// the QUIC pair has to be threaded through the general one anyway. Both
    /// are kept here for the same reason the ALPN parameter is kept -- the
    /// call sites read differently, and a `None` at every non-QUIC call site
    /// would be noise.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for an empty ticket. The C's
    /// `CURLE_OUT_OF_MEMORY` arms (`:358-363` for the session itself and
    /// `:374-377` for the ALPN copy) have no analogue: an allocation refused
    /// here aborts the process rather than returning, and there was no
    /// recovery beyond propagating the code in C either.
    pub(crate) fn with_quic_tp(
        ticket: Vec<u8>,
        ietf_tls_id: IetfProtoVersion,
        alpn: Option<&str>,
        valid_until: i64,
        earlydata_max: usize,
        quic_tp: Option<Vec<u8>>,
    ) -> Result<Self, CURLcode> {
        if ticket.is_empty() {
            return Err(CURLcode::BadFunctionArgument);
        }
        Ok(Self {
            ticket,
            ietf_tls_id,
            alpn: alpn.map(String::from),
            valid_until,
            earlydata_max,
            quic_tp,
        })
    }

    /// The ticket bytes: `sdata` over `sdata_len`.
    pub(crate) fn ticket(&self) -> &[u8] {
        &self.ticket
    }

    /// The negotiated protocol version: `ietf_tls_id`.
    pub(crate) const fn ietf_tls_id(&self) -> IetfProtoVersion {
        self.ietf_tls_id
    }

    /// The negotiated ALPN protocol: `alpn`.
    pub(crate) fn alpn(&self) -> Option<&str> {
        self.alpn.as_deref()
    }

    /// The expiry, in seconds since the epoch: `valid_until`.
    pub(crate) const fn valid_until(&self) -> i64 {
        self.valid_until
    }

    /// The peer's advertised 0-RTT maximum: `earlydata_max`.
    pub(crate) const fn earlydata_max(&self) -> usize {
        self.earlydata_max
    }

    /// The QUIC transport parameters: `quic_tp` over `quic_tp_len`.
    pub(crate) fn quic_tp(&self) -> Option<&[u8]> {
        self.quic_tp.as_deref()
    }

    /// Whether this session was negotiated by TLS 1.3.
    ///
    /// The test `s->ietf_tls_id != CURL_IETF_PROTO_TLS1_3`
    /// (`vtls_scache.c:765`, `:523`) decides the whole insertion policy, so it
    /// is named once rather than repeated.
    pub(crate) fn is_tls13(&self) -> bool {
        self.ietf_tls_id == IetfProtoVersion::TLS1_3
    }

    /// `cf_scache_session_expired` (`lib/vtls/vtls_scache.c:499-503`):
    ///
    /// ```text
    /// return (s->valid_until > 0) && (s->valid_until < now);
    /// ```
    ///
    /// Both halves matter. A non-positive `valid_until` is "unknown", not
    /// "expired in 1970", so it never expires -- which is why the cache
    /// replaces it with a real deadline on the way in. And the comparison is
    /// strict, so a session expiring exactly *now* is still live.
    pub(crate) const fn expired(&self, now: i64) -> bool {
        self.valid_until > 0 && self.valid_until < now
    }

    /// What the reuse decision needs, in the shape [`crate::tls`] already
    /// defined for it.
    ///
    /// `Curl_on_session_reuse` (`lib/vtls/vtls.c:2071-2099`) is handed a
    /// `struct Curl_ssl_session *` and reads exactly two things from it.
    /// [`ReusedSession`] is those two things, declared in `tls/mod.rs` so that
    /// the decision could be written before this module existed; this is the
    /// bridge between them, so neither side has to know the other's layout.
    pub(crate) fn reused(&self) -> ReusedSession {
        ReusedSession {
            alpn: self.alpn.clone(),
            earlydata_max: self.earlydata_max,
        }
    }

    /// Gives the session a real deadline, then holds it under the ceiling for
    /// its protocol version.
    ///
    /// The first half of `cf_scache_add_session`
    /// (`lib/vtls/vtls_scache.c:797-804`), verbatim:
    ///
    /// ```text
    /// if(s->valid_until <= 0)
    ///   s->valid_until = now + scache->default_lifetime_secs;
    ///
    /// max_lifetime = (s->ietf_tls_id == CURL_IETF_PROTO_TLS1_3) ?
    ///                CURL_SCACHE_MAX_13_LIFETIME_SEC :
    ///                CURL_SCACHE_MAX_12_LIFETIME_SEC;
    /// if(s->valid_until > (now + max_lifetime))
    ///   s->valid_until = now + max_lifetime;
    /// ```
    ///
    /// Order is load-bearing: defaulting happens first, so a session with no
    /// stated expiry gets one day rather than being clamped to seven.
    ///
    /// The additions saturate. The C's `curl_off_t` arithmetic would wrap on
    /// overflow, which for a clock near [`i64::MAX`] turns a far-future
    /// deadline into a past one and silently discards the session;
    /// [`i64::saturating_add`] keeps it in the far future, which is the
    /// behaviour the code plainly intends. Reachable only with an absurd
    /// clock, and cheaper to make correct than to reason about.
    fn clamp_validity(&mut self, now: i64, default_lifetime: i64) {
        if self.valid_until <= 0 {
            self.valid_until = now.saturating_add(default_lifetime);
        }
        let max_lifetime = if self.is_tls13() {
            MAX_13_LIFETIME_SEC
        } else {
            MAX_12_LIFETIME_SEC
        };
        let ceiling = now.saturating_add(max_lifetime);
        if self.valid_until > ceiling {
            self.valid_until = ceiling;
        }
    }
}

// =========================================================================
// The wire format -- `lib/vtls/vtls_spack.c`
// =========================================================================

/// Appends one byte: `spack_enc8` (`lib/vtls/vtls_spack.c:49-52`).
fn enc8(buf: &mut DynBuf, val: u8) -> Result<(), CURLcode> {
    buf.addn(&[val])
}

/// Appends a big-endian `u16`: `spack_enc16` (`lib/vtls/vtls_spack.c:64-70`).
///
/// The C composes the bytes by hand:
///
/// ```text
/// nval[0] = (uint8_t)(val >> 8);
/// nval[1] = (uint8_t)val;
/// ```
///
/// [`u16::to_be_bytes`] is that expression with the shift count supplied by
/// the type, which is what removes the class of defect where one width's
/// encoder is edited and another's is not.
fn enc16(buf: &mut DynBuf, val: u16) -> Result<(), CURLcode> {
    buf.addn(&val.to_be_bytes())
}

/// Appends a big-endian `u32`: `spack_enc32` (`lib/vtls/vtls_spack.c:82-90`).
fn enc32(buf: &mut DynBuf, val: u32) -> Result<(), CURLcode> {
    buf.addn(&val.to_be_bytes())
}

/// Appends a big-endian `u64`: `spack_enc64`
/// (`lib/vtls/vtls_spack.c:103-115`).
fn enc64(buf: &mut DynBuf, val: u64) -> Result<(), CURLcode> {
    buf.addn(&val.to_be_bytes())
}

/// Appends a `u16` length and that many bytes: `spack_encdata16`
/// (`lib/vtls/vtls_spack.c:160-171`).
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] when the slice is longer than
/// [`u16::MAX`], which is the C's `if(data_len > UINT16_MAX)` and its code.
/// [`CURLcode::TooLarge`] when the append would carry the buffer past its
/// ceiling.
fn encdata16(buf: &mut DynBuf, data: &[u8]) -> Result<(), CURLcode> {
    let len =
        u16::try_from(data.len()).map_err(|_| CURLcode::BadFunctionArgument)?;
    enc16(buf, len)?;
    buf.addn(data)
}

/// Appends a `u16` length and that many bytes of text: `spack_encstr16`
/// (`lib/vtls/vtls_spack.c:130-141`).
///
/// The C measures with `strlen`, so an embedded NUL would truncate; a `&str`
/// carries its length, so what is written is exactly what was held.
///
/// # Errors
///
/// As [`encdata16`]: the C's `if(slen > UINT16_MAX)` check and its code.
fn encstr16(buf: &mut DynBuf, text: &str) -> Result<(), CURLcode> {
    encdata16(buf, text.as_bytes())
}

/// A bounds-checked cursor over a packed session.
///
/// The C decodes through a `const uint8_t **src` plus a `const uint8_t *end`
/// and checks `end - *src < n` before every read (`spack_dec8` at
/// `vtls_spack.c:54-62` and its four siblings). The pair becomes one value
/// holding the *unread remainder*, so "how much is left" is `self.src.len()`
/// rather than a pointer difference, and the pointer arithmetic that the C
/// performs after each successful read cannot run past the end because there
/// is no pointer to advance.
///
/// Every method here is total: each checks the remaining length first and
/// returns [`CURLcode::ReadError`] when it is short, exactly as the C does,
/// so no method can panic and none can index outside the input.
struct SpackReader<'a> {
    /// The bytes not yet consumed.
    src: &'a [u8],
}

impl<'a> SpackReader<'a> {
    /// A cursor over `src`.
    const fn new(src: &'a [u8]) -> Self {
        Self { src }
    }

    /// Whether the whole input has been consumed: the C's `while(buf < end)`
    /// loop condition (`vtls_spack.c:270`), inverted.
    const fn is_empty(&self) -> bool {
        self.src.is_empty()
    }

    /// Consumes exactly `n` bytes.
    ///
    /// The single bounds check every other method routes through, so the
    /// check exists once rather than five times.
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] when fewer than `n` bytes remain -- the C's
    /// `if(end - *src < n) return CURLE_READ_ERROR;`.
    fn take(&mut self, n: usize) -> Result<&'a [u8], CURLcode> {
        if self.src.len() < n {
            return Err(CURLcode::ReadError);
        }
        let (head, tail) = self.src.split_at(n);
        self.src = tail;
        Ok(head)
    }

    /// Reads one byte: `spack_dec8` (`lib/vtls/vtls_spack.c:54-62`).
    fn dec8(&mut self) -> Result<u8, CURLcode> {
        // `first` cannot be `None`: `take(1)` returned a slice of length one
        // or an error. `ok_or` rather than an unwrap because this decodes
        // imported bytes, where a panic path would be a denial of service.
        self.take(1)?.first().copied().ok_or(CURLcode::ReadError)
    }

    /// Reads a big-endian `u16`: `spack_dec16`
    /// (`lib/vtls/vtls_spack.c:72-80`).
    ///
    /// The C reassembles with `(uint16_t)((*src)[0] << 8 | (*src)[1])`. The
    /// fold below is the same expression for any width, and it needs no
    /// fixed-size-array conversion -- which is what keeps this readable at
    /// the [`u64`] width and free of a fallible `try_into` whose error arm
    /// could never be reached.
    fn dec16(&mut self) -> Result<u16, CURLcode> {
        let bytes = self.take(2)?;
        Ok(bytes
            .iter()
            .fold(0_u16, |acc, &b| (acc << 8) | u16::from(b)))
    }

    /// Reads a big-endian `u32`: `spack_dec32`
    /// (`lib/vtls/vtls_spack.c:92-101`).
    fn dec32(&mut self) -> Result<u32, CURLcode> {
        let bytes = self.take(4)?;
        Ok(bytes
            .iter()
            .fold(0_u32, |acc, &b| (acc << 8) | u32::from(b)))
    }

    /// Reads a big-endian `u64`: `spack_dec64`
    /// (`lib/vtls/vtls_spack.c:117-128`).
    fn dec64(&mut self) -> Result<u64, CURLcode> {
        let bytes = self.take(8)?;
        Ok(bytes
            .iter()
            .fold(0_u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// Reads a `u16` length and that many bytes: `spack_decdata16`
    /// (`lib/vtls/vtls_spack.c:173-189`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] for a truncated length field and for a length
    /// that names more bytes than remain, which is the C's own
    /// `if(end - *src < data_len)` test.
    /// The C's trailing `CURLE_OUT_OF_MEMORY` for a refused `curlx_memdup0`
    /// has no analogue.
    fn decdata16(&mut self) -> Result<Vec<u8>, CURLcode> {
        let len = usize::from(self.dec16()?);
        Ok(self.take(len)?.to_vec())
    }

    /// Reads a `u16` length and that many bytes of text: `spack_decstr16`
    /// (`lib/vtls/vtls_spack.c:143-158`).
    ///
    /// # Errors
    ///
    /// As [`Self::decdata16`], plus [`CURLcode::ReadError`] for bytes that are
    /// not UTF-8.
    ///
    /// That last arm is a narrow, deliberate strictness over the C, which
    /// stores whatever bytes arrive as a `char *` -- confirmed by compiling
    /// `Curl_ssl_session_unpack` standalone and feeding it
    /// `05 00 02 FF FE`, which it accepts and stores verbatim. Three facts make
    /// rejecting the right call rather than a compatibility risk. The field
    /// carries an ALPN protocol identifier, and RFC 7301 registers those as
    /// IANA-assigned ASCII tokens -- `h2`, `http/1.1`, `h3` -- so no value
    /// curl produces can reach this arm. The C's own handling is already lossy
    /// for arbitrary bytes: `curlx_memdup0` NUL-terminates, and every reader
    /// of `s->alpn` is a `%s` or a `strlen`, so an embedded NUL truncates
    /// there too. And the alternative to rejecting is
    /// [`String::from_utf8_lossy`], which would silently substitute
    /// replacement characters into a protocol identifier and hand the
    /// corrupted name to ALPN comparison. [`CURLcode::ReadError`] is the code
    /// this decoder already uses for every other malformed input.
    fn decstr16(&mut self) -> Result<String, CURLcode> {
        String::from_utf8(self.decdata16()?).map_err(|_| CURLcode::ReadError)
    }
}

#[allow(dead_code)] // Consumers land with share/ and curl-rs's --ssl-sessions.
impl TlsSession {
    /// `Curl_ssl_session_pack` (`lib/vtls/vtls_spack.c:191-237`), into a
    /// freshly bounded buffer.
    ///
    /// The buffer's ceiling is [`SSL_TICKET_MAX`], which is the ceiling
    /// `Curl_ssl_session_export` gives its own `sbuf` at `:1163`, so a
    /// session too large to export fails here with the same code it fails
    /// with in C.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::pack_into`] reports.
    pub(crate) fn pack(&self) -> Result<Vec<u8>, CURLcode> {
        let mut buf = DynBuf::new(SSL_TICKET_MAX);
        self.pack_into(&mut buf)?;
        Ok(buf.take())
    }

    /// `Curl_ssl_session_pack` (`lib/vtls/vtls_spack.c:191-237`) into a
    /// caller-supplied buffer.
    ///
    /// The field order is the contract and is transcribed exactly:
    ///
    /// ```text
    /// 0x01                                  format version
    /// 0x04  u16 len  <len bytes>            TICKET
    /// 0x02  u16                             IETF_ID
    /// 0x03  u64                             VALID_UNTIL
    /// 0x05  u16 len  <len bytes>            ALPN        (when present)
    /// 0x06  u32                             EARLYDATA   (when non-zero)
    /// 0x07  u16 len  <len bytes>            QUICTP      (when non-empty)
    /// ```
    ///
    /// Two conditions are exactly the C's and are easy to get subtly wrong.
    /// `EARLYDATA` is emitted `if(!r && s->earlydata_max)` (`:220`) -- a zero
    /// maximum is *omitted*, not written as four zero bytes, and a decoder
    /// that sees no tag reports zero, so the two spellings would round-trip
    /// to the same value while producing different bytes. `QUICTP` is emitted
    /// `if(!r && s->quic_tp && s->quic_tp_len)` (`:228`) -- both a null
    /// pointer and a zero length omit it, which here is `Some(v)` with `v`
    /// non-empty.
    ///
    /// # The C's two `DEBUGASSERT`s are deliberately not reproduced
    ///
    /// `:196-197` assert `s->sdata` and `s->sdata_len`. A release build with
    /// neither writes `TICKET` with a zero length, and this does the same. The
    /// assertions are not carried across because the only way to hold a
    /// ticketless session is to have decoded one -- see [`Self::unpack`] --
    /// and a debug-build panic on a value derived from imported bytes is
    /// exactly the failure mode that must not exist here. Refusing to pack
    /// instead would break the round trip and leave an unexportable session
    /// wedged in the cache.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] for a negative [`Self::valid_until`]
    /// (the C's `if(s->valid_until < 0)` at `:199-200`), for a ticket, ALPN or
    /// transport-parameter blob longer than [`u16::MAX`], and for an
    /// [`Self::earlydata_max`] above [`u32::MAX`] (the C's `UINT32_MAX` test
    /// at `:221-222`). [`CURLcode::TooLarge`] when the payload would carry the
    /// buffer past its ceiling.
    pub(crate) fn pack_into(&self, buf: &mut DynBuf) -> Result<(), CURLcode> {
        // The C checks the sign, then casts to `uint64_t` at `:214`. The
        // checked conversion is that check and that cast in one step, and it
        // yields the same code for the same input.
        let valid_until = u64::try_from(self.valid_until)
            .map_err(|_| CURLcode::BadFunctionArgument)?;

        enc8(buf, SPACK_VERSION)?;
        enc8(buf, SPACK_TICKET)?;
        encdata16(buf, &self.ticket)?;
        enc8(buf, SPACK_IETF_ID)?;
        enc16(buf, self.ietf_tls_id.bits())?;
        enc8(buf, SPACK_VALID_UNTIL)?;
        enc64(buf, valid_until)?;
        if let Some(alpn) = self.alpn.as_deref() {
            enc8(buf, SPACK_ALPN)?;
            encstr16(buf, alpn)?;
        }
        if self.earlydata_max != 0 {
            let earlydata = u32::try_from(self.earlydata_max)
                .map_err(|_| CURLcode::BadFunctionArgument)?;
            enc8(buf, SPACK_EARLYDATA)?;
            enc32(buf, earlydata)?;
        }
        match self.quic_tp.as_deref() {
            Some(quic_tp) if !quic_tp.is_empty() => {
                enc8(buf, SPACK_QUICTP)?;
                encdata16(buf, quic_tp)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// `Curl_ssl_session_unpack` (`lib/vtls/vtls_spack.c:239-327`).
    ///
    /// The version byte is read and checked *before* anything is built
    /// (`:256-262`), then tags are read until the input is exhausted. Tag
    /// order is **not** fixed: the C's `switch` inside `while(buf < end)`
    /// accepts the six payload tags in any order, and that flexibility is
    /// preserved here rather than tightened, because a future curl may add a
    /// field and an older reader must still cope with the ones it knows.
    ///
    /// A repeated tag overwrites, as the C's repeated assignment does.
    ///
    /// # A missing `TICKET` tag is accepted, and that is the faithful choice
    ///
    /// The C's decoder has no post-loop validation, so a payload carrying no
    /// `TICKET` yields a session whose `sdata` is null. That session is
    /// useless -- it cannot resume anything -- but it is what curl builds, and
    /// [`Self::pack_into`] writes a zero-length ticket back for it, so the
    /// round trip is total in both directions. Rejecting it here instead
    /// would refuse input curl accepts, and the agent brief scopes the
    /// empty-ticket rejection to *normal construction*, which is
    /// [`Self::new`] and [`Self::with_quic_tp`].
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] for an empty input, for a first byte that is
    /// not [`SPACK_VERSION`], for a tag outside the six known values (the C's
    /// `default: r = CURLE_READ_ERROR;` at `:313-315`), for any truncated
    /// field, for a declared length naming more bytes than remain, for
    /// non-UTF-8 ALPN, and for a `VALID_UNTIL` above [`i64::MAX`].
    ///
    /// That last arm is the checked form of the C's `s->valid_until =
    /// (curl_off_t)val64` at `:311`. Measured against the C encoder and decoder
    /// compiled standalone from `vtls_spack.c`, a `VALID_UNTIL` of `u64::MAX`
    /// decodes there to `valid_until = -1`: the C treats that as "unknown", so
    /// the session never expires, and then refuses to pack it again because
    /// `Curl_ssl_session_pack` rejects a negative `valid_until` outright
    /// (`:199-200`, which the same harness confirms returns
    /// `CURLE_BAD_FUNCTION_ARGUMENT`). The value is unusable in both
    /// implementations; this one says so at the boundary instead of storing it.
    pub(crate) fn unpack(input: &[u8]) -> Result<Self, CURLcode> {
        let mut reader = SpackReader::new(input);
        if reader.dec8()? != SPACK_VERSION {
            return Err(CURLcode::ReadError);
        }

        // The C `calloc`s the session here, so every field starts zeroed and
        // any tag the payload omits keeps that zero. These are those zeros,
        // named.
        let mut session = Self {
            ticket: Vec::new(),
            ietf_tls_id: IetfProtoVersion::UNKNOWN,
            alpn: None,
            valid_until: 0,
            earlydata_max: 0,
            quic_tp: None,
        };

        while !reader.is_empty() {
            match reader.dec8()? {
                SPACK_ALPN => session.alpn = Some(reader.decstr16()?),
                SPACK_EARLYDATA => {
                    session.earlydata_max = usize::try_from(reader.dec32()?)
                        .map_err(|_| CURLcode::ReadError)?;
                }
                SPACK_IETF_ID => {
                    session.ietf_tls_id =
                        IetfProtoVersion::from_bits(reader.dec16()?);
                }
                SPACK_QUICTP => session.quic_tp = Some(reader.decdata16()?),
                SPACK_TICKET => session.ticket = reader.decdata16()?,
                SPACK_VALID_UNTIL => {
                    session.valid_until = i64::try_from(reader.dec64()?)
                        .map_err(|_| CURLcode::ReadError)?;
                }
                _ => return Err(CURLcode::ReadError),
            }
        }

        Ok(session)
    }
}

// =========================================================================
// The peer key -- `Curl_ssl_peer_key_make` (`vtls_scache.c:138-297`)
// =========================================================================

/// `TRNSPRT_TCP` (`lib/urldata.h:568`): the transport that adds no fragment.
#[allow(dead_code)] // Read by peer_key_make.
const TRNSPRT_TCP: u8 = 3;

/// `TRNSPRT_UDP` (`lib/urldata.h:569`).
#[allow(dead_code)] // Read by peer_key_make.
const TRNSPRT_UDP: u8 = 4;

/// `TRNSPRT_QUIC` (`lib/urldata.h:570`).
#[allow(dead_code)] // Read by peer_key_make.
const TRNSPRT_QUIC: u8 = 5;

/// `TRNSPRT_UNIX` (`lib/urldata.h:571`).
#[allow(dead_code)] // Read by peer_key_make.
const TRNSPRT_UNIX: u8 = 6;

/// The TLS configuration a peer key has to distinguish.
///
/// Every member is one member of `struct ssl_primary_config` that
/// `Curl_ssl_peer_key_make` reads, or one of the two `cf->conn` bits it reads
/// alongside them. The struct is declared *here* rather than imported because
/// this crate has no `ssl_primary_config` successor yet: the option surface
/// that will own those values belongs to `crate::easy`, and this module's
/// dependency set is exactly the nine files its schema names. When that
/// surface lands it constructs one of these; nothing about the key changes.
///
/// # Borrowed, not owned
///
/// Every string and blob is a borrow, because a key is computed once from
/// configuration the caller already holds and is then thrown away. Owning
/// them would copy up to three arbitrary-length application strings per
/// handshake to build a value whose only use is to be hashed and compared.
///
/// # There is no `Default` derive, and that is not an oversight
///
/// `#[derive(Default)]` would make `verifypeer` and `verifyhost` **false**,
/// which is the opposite of curl's default and would silently produce a key
/// carrying `:NO-VRFY-PEER:NO-VRFY-HOST` for a caller that configured
/// nothing. `Curl_ssl_easy_config_init` (`lib/vtls/vtls.c:181-189`) is
/// explicit about which way round it goes:
///
/// ```text
/// /*
///  * libcurl 7.10 introduced SSL verification *by default*! This needs to be
///  * switched off unless wanted.
///  */
/// data->set.ssl.primary.verifypeer = TRUE;
/// data->set.ssl.primary.verifyhost = TRUE;
/// data->set.ssl.primary.cache_session = TRUE; /* caching by default */
/// ```
///
/// So [`Default`] is written by hand to agree with that line, and validation
/// is on unless a caller turns it off.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // Populated by crate::easy once the option surface lands.
pub(crate) struct PeerKeyConfig<'a> {
    /// `ssl->verifypeer`. False adds `:NO-VRFY-PEER` and suppresses the whole
    /// trust-material group.
    pub(crate) verifypeer: bool,
    /// `ssl->verifyhost`. False adds `:NO-VRFY-HOST`.
    pub(crate) verifyhost: bool,
    /// `ssl->verifystatus`. True adds `:VRFY-STATUS`.
    pub(crate) verifystatus: bool,
    /// `cf->conn->conn_to_host.name`, when `cf->conn->bits.conn_to_host`.
    pub(crate) conn_to_host: Option<&'a str>,
    /// `cf->conn->conn_to_port`, when `cf->conn->bits.conn_to_port`.
    pub(crate) conn_to_port: Option<i32>,
    /// `ssl->version`: a `CURL_SSLVERSION_*` value.
    pub(crate) version: u8,
    /// `ssl->version_max`: a `CURL_SSLVERSION_MAX_*` value, pre-shifted by 16.
    pub(crate) version_max: i64,
    /// `ssl->ssl_options`: the `CURLSSLOPT_*` bitmask.
    pub(crate) ssl_options: u32,
    /// `ssl->cipher_list`: `CURLOPT_SSL_CIPHER_LIST`.
    pub(crate) cipher_list: Option<&'a str>,
    /// `ssl->cipher_list13`: `CURLOPT_TLS13_CIPHERS`.
    pub(crate) cipher_list13: Option<&'a str>,
    /// `ssl->curves`: `CURLOPT_SSL_EC_CURVES`.
    pub(crate) curves: Option<&'a str>,
    /// `ssl->CAfile`: `CURLOPT_CAINFO`.
    pub(crate) ca_file: Option<&'a str>,
    /// `ssl->CApath`: `CURLOPT_CAPATH`.
    pub(crate) ca_path: Option<&'a str>,
    /// `ssl->CRLfile`: `CURLOPT_CRLFILE`.
    pub(crate) crl_file: Option<&'a str>,
    /// `ssl->issuercert`: `CURLOPT_ISSUERCERT`.
    pub(crate) issuer_cert: Option<&'a str>,
    /// `ssl->cert_blob`: `CURLOPT_SSLCERT_BLOB`, hashed rather than embedded.
    pub(crate) cert_blob: Option<&'a [u8]>,
    /// `ssl->ca_info_blob`: `CURLOPT_CAINFO_BLOB`, hashed.
    pub(crate) ca_info_blob: Option<&'a [u8]>,
    /// `ssl->issuercert_blob`: `CURLOPT_ISSUERCERT_BLOB`, hashed.
    pub(crate) issuer_cert_blob: Option<&'a [u8]>,
    /// `ssl->pinned_key`: `CURLOPT_PINNEDPUBLICKEY`.
    ///
    /// A pinned key is a *public* key digest or a path to one, never private
    /// material, which is why the C embeds its spelling rather than hashing
    /// it.
    pub(crate) pinned_key: Option<&'a str>,
    /// `ssl->clientcert`: `CURLOPT_SSLCERT`.
    ///
    /// Only its presence reaches the key, as `:CCERT`. The path itself is
    /// withheld -- and so, necessarily, is the private key it implies -- while
    /// the *value* is still compared, through [`ClientAuth`], before a session
    /// may be reused.
    pub(crate) clientcert: Option<&'a str>,
}

impl Default for PeerKeyConfig<'_> {
    /// curl's own defaults: `Curl_ssl_easy_config_init`
    /// (`lib/vtls/vtls.c:181-189`).
    ///
    /// Peer and host verification on; nothing else configured.
    fn default() -> Self {
        Self {
            verifypeer: true,
            verifyhost: true,
            verifystatus: false,
            conn_to_host: None,
            conn_to_port: None,
            version: 0,
            version_max: 0,
            ssl_options: 0,
            cipher_list: None,
            cipher_list13: None,
            curves: None,
            ca_file: None,
            ca_path: None,
            crl_file: None,
            issuer_cert: None,
            cert_blob: None,
            ca_info_blob: None,
            issuer_cert_blob: None,
            pinned_key: None,
            clientcert: None,
        }
    }
}

#[allow(dead_code)] // Consumers land with crate::easy's option surface.
impl<'a> PeerKeyConfig<'a> {
    /// The client-authentication identity this configuration implies.
    ///
    /// The C reads `conn_config->clientcert` twice from one place -- once for
    /// the `:CCERT` fragment (`vtls_scache.c:264`) and once to store on a new
    /// peer (`:738`) -- and compares it on every lookup
    /// (`cf_ssl_scache_match_auth`, `:610`). Deriving the identity from the
    /// same value here is what stops the key and the identity from disagreeing
    /// about which certificate is in play.
    pub(crate) fn client_auth(&self) -> ClientAuth {
        ClientAuth::new(self.clientcert)
    }
}

/// Which client credentials a cached session was established with.
///
/// The successor of the peer's `char *clientcert` (`vtls_scache.c:52`) and of
/// `cf_ssl_scache_match_auth` (`:598-618`). A separate type rather than a bare
/// `Option<String>` because the comparison has a defined shape that must not
/// drift, and because "no configuration supplied" and "configuration supplied,
/// naming no certificate" are different questions the C's nullable
/// `conn_config` pointer answers with the same `NULL`.
///
/// # This is where SRP would be, and why it is not
///
/// The C peer also carries `srp_username` and `srp_password`, compared with
/// the constant-time `Curl_timestrcmp` -- both behind `#ifdef USE_TLS_SRP`.
/// rustls implements no SRP key exchange, [`crate::version`] withholds the
/// `TLS-SRP` token accordingly, and this build is therefore the `#ifdef`-off
/// compilation. Adding the fields would either advertise a capability that
/// does not exist or leave two members that nothing can ever set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // Consumers land with tls/rustls_backend.rs.
pub(crate) struct ClientAuth {
    /// `peer->clientcert`: the `CURLOPT_SSLCERT` spelling, or [`None`].
    clientcert: Option<String>,
}

#[allow(dead_code)] // Consumers land with tls/rustls_backend.rs.
impl ClientAuth {
    /// An identity naming `clientcert`, or naming no certificate.
    pub(crate) fn new(clientcert: Option<&str>) -> Self {
        Self {
            clientcert: clientcert.map(String::from),
        }
    }

    /// The certificate spelling, if there is one.
    pub(crate) fn clientcert(&self) -> Option<&str> {
        self.clientcert.as_deref()
    }

    /// Whether this identity carries anything confidential.
    ///
    /// The first two conjuncts of `cf_ssl_cache_peer_update`
    /// (`vtls_scache.c:434-436`): a peer whose sessions were established with
    /// client credentials must never be exported, because the importing
    /// process may hold different ones.
    pub(crate) fn is_confidential(&self) -> bool {
        self.clientcert.is_some()
    }

    /// `cf_ssl_scache_match_auth` (`lib/vtls/vtls_scache.c:598-618`), with the
    /// stored identity as the receiver.
    ///
    /// ```text
    /// if(!conn_config) {
    ///   if(peer->clientcert)   return FALSE;
    ///   return TRUE;
    /// }
    /// else if(!Curl_safecmp(peer->clientcert, conn_config->clientcert))
    ///   return FALSE;
    /// return TRUE;
    /// ```
    ///
    /// `expected` of [`None`] is the C's null `conn_config`, which the import
    /// path passes (`:1099`): a peer that was established with a client
    /// certificate must not match it.
    ///
    /// `Curl_safecmp` (`lib/strcase.c:119-124`) is `!strcmp` when both
    /// pointers are non-null and `!a && !b` otherwise -- **case-sensitive**,
    /// with both-absent counting as equal. `Option<String>`'s derived equality
    /// is exactly that. It is deliberately *not* `curl_strequal`, which is
    /// case-insensitive and which the peer-key comparison does use; the two
    /// comparisons differ in the C and differ here.
    pub(crate) fn matches(&self, expected: Option<&Self>) -> bool {
        match expected {
            None => self.clientcert.is_none(),
            Some(expected) => self.clientcert == expected.clientcert,
        }
    }
}

/// `cf_ssl_peer_key_is_global` (`lib/vtls/vtls_scache.c:130-136`).
///
/// ```text
/// size_t len = peer_key ? strlen(peer_key) : 0;
/// return (len > 2) &&
///        (peer_key[len - 1] == 'G') &&
///        (peer_key[len - 2] == ':');
/// ```
///
/// The `len > 2` is not redundant with the suffix test: it rejects the string
/// `":G"` itself, which carries no host and no configuration and so identifies
/// nothing. [`str::ends_with`] compares bytes, exactly as the two indexed
/// character tests do.
pub(crate) fn peer_key_is_global(peer_key: &str) -> bool {
    peer_key.len() > 2 && peer_key.ends_with(GLOBAL_SUFFIX)
}

/// `cf_ssl_peer_key_add_path` (`lib/vtls/vtls_scache.c:70-100`): one
/// configured path, made position-independent where possible.
///
/// The C's comment states the whole intent:
///
/// ```text
/// /* We try to add absolute paths, so that the session key can stay
///  * valid when used in another process with different CWD. However,
///  * when a path does not exist, this does not work. Then, we add
///  * the path as is. */
/// ```
///
/// Three cases, and which one applies is decided by the path's *first
/// character* rather than by asking the filesystem:
///
/// 1. **Absolute** (`path[0] == '/'`). Emitted verbatim. The C does not
///    resolve it, so neither does this: resolving would follow symlinks and
///    change the key for a configuration that did not change.
/// 2. **Relative and resolvable.** `realpath(path, NULL)` succeeds and the
///    *absolute* form is emitted. The key then survives a change of working
///    directory, which is what makes the peer exportable.
/// 3. **Relative and unresolvable.** `*is_local` is set and the path is
///    emitted as given. The key is then valid only in this process, and the
///    `:L` suffix says so.
///
/// [`std::fs::canonicalize`] is `realpath`: it resolves symlinks and requires
/// the path to exist, and it fails for the same inputs. A resolved path that
/// is not UTF-8 is treated as case 3 -- unresolvable -- which is the honest
/// reading, since a key is text and there is nothing else to do with bytes
/// that cannot appear in one.
///
/// # The `_WIN32` branch is not reproduced
///
/// `:80-84` uses `_fullpath` for *every* path, absolute ones included. No
/// mandated target is Windows, and a `#[cfg(windows)]` arm here could not be
/// built or tested by any of the four. On a Windows build this function
/// therefore takes case 3 for a drive-letter path -- the key is emitted
/// unchanged and marked local -- which is the conservative direction: a local
/// key is never exported, so nothing leaves the process that another process
/// could misread.
///
/// # Errors
///
/// Whatever the buffer reports: [`CURLcode::TooLarge`] once the key reaches
/// [`PEER_KEY_MAX`].
#[allow(dead_code)] // Read by peer_key_make.
fn peer_key_add_path(
    buf: &mut DynBuf,
    name: &str,
    path: Option<&str>,
    is_local: &mut bool,
) -> Result<(), CURLcode> {
    // The C's `if(path && path[0])`: absent and empty are the same thing.
    let path = match path {
        Some(path) if !path.is_empty() => path,
        _ => return Ok(()),
    };

    if !path.starts_with('/') {
        match std::fs::canonicalize(path) {
            Ok(resolved) => {
                if let Some(absolute) = resolved.to_str() {
                    return buf.addf(format_args!(":{name}-{absolute}"));
                }
                *is_local = true;
            }
            Err(_) => *is_local = true,
        }
    }
    buf.addf(format_args!(":{name}-{path}"))
}

/// `cf_ssl_peer_key_add_hash` (`lib/vtls/vtls_scache.c:102-125`): one
/// configured blob, as a digest.
///
/// A certificate blob can be arbitrarily large and is not necessarily text, so
/// the C hashes it rather than embedding it:
///
/// ```text
/// r = curlx_dyn_addf(buf, ":%s-", name);
/// r = Curl_sha256it(hash, blob->data, blob->len);
/// for(i = 0; i < CURL_SHA256_DIGEST_LENGTH; ++i)
///   r = curlx_dyn_addf(buf, "%02x", hash[i]);
/// ```
///
/// The `%02x` is **lowercase**, which is `{:02x}` here and not `{:02X}`. The
/// distinction is not cosmetic: the key is compared as a string, so a
/// different case is a different peer and every session for it would be
/// missed.
///
/// The C's `if(blob && blob->len)` skips an empty blob, so an empty
/// `CURLOPT_CAINFO_BLOB` produces no fragment rather than the digest of the
/// empty input.
///
/// # Errors
///
/// Whatever the buffer reports. The C's `Curl_sha256it` can return a code
/// because some backends route it through a provider; [`sha256`] cannot fail.
#[allow(dead_code)] // Read by peer_key_make.
fn peer_key_add_hash(
    buf: &mut DynBuf,
    name: &str,
    blob: Option<&[u8]>,
) -> Result<(), CURLcode> {
    let blob = match blob {
        Some(blob) if !blob.is_empty() => blob,
        _ => return Ok(()),
    };
    buf.addf(format_args!(":{name}-"))?;
    for byte in sha256(blob) {
        buf.addf(format_args!("{byte:02x}"))?;
    }
    Ok(())
}

/// `Curl_ssl_peer_key_make` (`lib/vtls/vtls_scache.c:138-297`): the key that
/// decides which sessions may be resumed against which endpoint.
///
/// Two peers share sessions if and only if they produce the same key, so every
/// fragment below exists because getting it wrong would either leak a session
/// across a configuration boundary or lose resumption for an identical
/// configuration. The order is fixed -- the key is compared as one string, so
/// reordering two fragments produces a different key for the same
/// configuration and silently disables resumption.
///
/// ```text
/// <host>:<port>                        always
/// :UDP | :QUIC | :UNIX | :TRNSPRT-<n>  unless TCP, which adds nothing
/// :NO-VRFY-PEER                        when peer verification is off
/// :NO-VRFY-HOST                        when host verification is off
/// :VRFY-STATUS                         when OCSP stapling is required
/// :CHOST-<name>                        when either is off and --connect-to
/// :CPORT-<port>                        when either is off and --connect-to
/// :TLSVER-<min>-<max>                  when a version was requested
/// :TLSOPT-<hex>                        when CURLSSLOPT_* bits are set
/// :CIPHER-<list>                       CURLOPT_SSL_CIPHER_LIST
/// :CIPHER13-<list>                     CURLOPT_TLS13_CIPHERS
/// :CURVES-<list>                       CURLOPT_SSL_EC_CURVES
/// :CA-<path> :CApath-<path>            when peer verification is ON
/// :CRL-<path> :Issuer-<path>           when peer verification is ON
/// :CertBlob-<sha256>                   when peer verification is ON
/// :CAInfoBlob-<sha256>                 when peer verification is ON
/// :IssuerBlob-<sha256>                 when peer verification is ON
/// :Pinned-<key>                        CURLOPT_PINNEDPUBLICKEY
/// :CCERT                               when a client certificate is set
/// :IMPL-<tls_id>                       always
/// :L | :G                              always, exactly one
/// ```
///
/// # Three details that are easy to read past
///
/// **The trust material is conditional on `verifypeer` alone.** `:229` opens
/// `if(ssl->verifypeer)` and the six CA, CRL, issuer and blob fragments sit
/// inside it, so with verification off the trust configuration does not
/// distinguish peers -- correctly, because it is not being used. `:Pinned-` and
/// `:CCERT` are *outside* that block and always apply.
///
/// **`:CHOST-`/`:CPORT-` are conditional the other way.** `:190` opens
/// `if(!ssl->verifypeer || !ssl->verifyhost)`. With verification on, the
/// certificate binds the session to the origin name, so a `--connect-to`
/// override cannot let one endpoint's session be reused for another. With it
/// off, nothing binds them, and the override has to enter the key.
///
/// **`:TLSVER-` prints the maximum shifted down by 16.** `:204-205` is
/// `":TLSVER-%d-%d", ssl->version, (ssl->version_max >> 16)`, because
/// `version_max` holds a `CURL_SSLVERSION_*` pre-shifted left by 16. The shift
/// is arithmetic on a signed value in both languages, so a negative maximum
/// prints negative in both. The C passes a `long` to a `%d` conversion there,
/// which reads only an `int`'s worth of it; every assigned
/// `CURL_SSLVERSION_MAX_*` value shifts down into `0..8`, so the two spellings
/// agree for every input curl can produce, and this one does not truncate.
///
/// # `:IMPL-` is what keeps two rustls versions apart
///
/// `tls_id` is documented at `vtls_scache.h:59-61` as the "identifier of TLS
/// implementation for sessions. Should include full version if session data
/// from other versions is to be avoided." A ticket is opaque to curl but not
/// to the library that minted it, so a session from another implementation --
/// or another version of the same one -- must not be offered back. The caller
/// supplies the token because it is the caller that knows the truthful one;
/// this module does not read [`crate::version`], which would be a second
/// source of truth for one answer.
///
/// # Errors
///
/// [`CURLcode::FailedInit`] for an empty `tls_id`, which is the C's own check
/// and its own code (`:277-280`). [`CURLcode::TooLarge`] once the key would
/// exceed [`PEER_KEY_MAX`]. Nothing else: the C's remaining failure mode is
/// allocation, and the final [`String::from_utf8`] cannot fail because every
/// fragment appended above is either ASCII punctuation, lowercase hex, or a
/// `&str` that was UTF-8 already -- it is written as a checked conversion
/// rather than an unwrap so that no panic path exists at all.
#[allow(dead_code)] // Consumer lands with tls/rustls_backend.rs.
pub(crate) fn peer_key_make(
    peer: &SslPeer,
    config: &PeerKeyConfig<'_>,
    tls_id: &str,
) -> Result<String, CURLcode> {
    // The three members the C reads from `const struct ssl_peer *peer`, and
    // nothing else. The transport is taken as the C integer rather than as
    // `crate::conn::filters::Transport` because the switch below is a
    // transcription of the C's, `default:` arm included, and because that
    // enumeration is not among this module's declared dependencies -- reading
    // it through the accessor needs no import and cannot disagree, since
    // `Transport::as_u8` is the same `TRNSPRT_*` value.
    peer_key_build(
        peer.hostname(),
        peer.port(),
        peer.transport().as_u8(),
        config,
        tls_id,
    )
}

/// The body of [`peer_key_make`], over the three peer facts it actually reads.
///
/// Split out for one reason: it makes every transport value -- including the
/// `default:` arm, which no [`crate::tls::SslPeer`] can be built to reach --
/// reachable from a test without constructing a connection.
fn peer_key_build(
    hostname: &str,
    port: u16,
    transport: u8,
    config: &PeerKeyConfig<'_>,
    tls_id: &str,
) -> Result<String, CURLcode> {
    let mut buf = DynBuf::new(PEER_KEY_MAX);
    let mut is_local = false;

    buf.addf(format_args!("{hostname}:{port}"))?;

    match transport {
        TRNSPRT_TCP => {}
        TRNSPRT_UDP => buf.add(":UDP")?,
        TRNSPRT_QUIC => buf.add(":QUIC")?,
        TRNSPRT_UNIX => buf.add(":UNIX")?,
        // The C's `default:` arm, which `TRNSPRT_NONE` reaches: the switch
        // names only the four transports above, so a `file://` transfer keys
        // as `:TRNSPRT-0`.
        other => buf.addf(format_args!(":TRNSPRT-{other}"))?,
    }

    if !config.verifypeer {
        buf.add(":NO-VRFY-PEER")?;
    }
    if !config.verifyhost {
        buf.add(":NO-VRFY-HOST")?;
    }
    if config.verifystatus {
        buf.add(":VRFY-STATUS")?;
    }
    if !config.verifypeer || !config.verifyhost {
        if let Some(host) = config.conn_to_host {
            buf.addf(format_args!(":CHOST-{host}"))?;
        }
        if let Some(port) = config.conn_to_port {
            buf.addf(format_args!(":CPORT-{port}"))?;
        }
    }

    if config.version != 0 || config.version_max != 0 {
        buf.addf(format_args!(
            ":TLSVER-{}-{}",
            config.version,
            config.version_max >> 16
        ))?;
    }
    if config.ssl_options != 0 {
        buf.addf(format_args!(":TLSOPT-{:x}", config.ssl_options))?;
    }
    if let Some(list) = config.cipher_list {
        buf.addf(format_args!(":CIPHER-{list}"))?;
    }
    if let Some(list) = config.cipher_list13 {
        buf.addf(format_args!(":CIPHER13-{list}"))?;
    }
    if let Some(curves) = config.curves {
        buf.addf(format_args!(":CURVES-{curves}"))?;
    }

    if config.verifypeer {
        peer_key_add_path(&mut buf, "CA", config.ca_file, &mut is_local)?;
        peer_key_add_path(&mut buf, "CApath", config.ca_path, &mut is_local)?;
        peer_key_add_path(&mut buf, "CRL", config.crl_file, &mut is_local)?;
        peer_key_add_path(
            &mut buf,
            "Issuer",
            config.issuer_cert,
            &mut is_local,
        )?;
        peer_key_add_hash(&mut buf, "CertBlob", config.cert_blob)?;
        peer_key_add_hash(&mut buf, "CAInfoBlob", config.ca_info_blob)?;
        peer_key_add_hash(&mut buf, "IssuerBlob", config.issuer_cert_blob)?;
    }

    // Outside the verification block in the C, and outside it here. Both use
    // `if(x && x[0])`, so an empty string adds nothing.
    if let Some(pinned) = config.pinned_key.filter(|key| !key.is_empty()) {
        buf.addf(format_args!(":Pinned-{pinned}"))?;
    }
    if config.clientcert.is_some_and(|cert| !cert.is_empty()) {
        buf.add(":CCERT")?;
    }

    if tls_id.is_empty() {
        return Err(CURLcode::FailedInit);
    }
    buf.addf(format_args!(":IMPL-{tls_id}"))?;

    buf.add(if is_local {
        LOCAL_SUFFIX
    } else {
        GLOBAL_SUFFIX
    })?;

    String::from_utf8(buf.take()).map_err(|_| CURLcode::BadFunctionArgument)
}

// =========================================================================
// Constant-time verification, through the wrapper and nowhere else
// =========================================================================

/// Whether two 32-byte codes are equal, without leaking *where* they differ.
///
/// The C compares with `memcmp` in both places it compares a code
/// (`vtls_scache.c:664` and `:1039-1040`), and `memcmp` returns as soon as it
/// finds a difference. One of the two operands here always arrives from
/// outside the process -- it is the `shmac` half of an imported session -- so
/// the position of the first difference is information an attacker can supply
/// input to probe.
///
/// This is the double-HMAC comparison: both values are keyed with the same key
/// and the resulting codes are checked through [`HmacContext::verify_slice`],
/// which is `Mac::verify_slice` and therefore constant-time. Equal inputs
/// produce equal codes trivially; unequal inputs producing equal codes would
/// be an HMAC-SHA-256 collision. The key is empty because it has no secret to
/// hold -- what is being bought is the constant-time *comparison*, not
/// authentication of a message that is already a code.
///
/// Written this way rather than as a hand-rolled XOR-and-fold loop for a
/// deliberate reason: [`crate::crypto::hmac`] publishes a constant-time
/// verification and *deliberately does not* publish a non-constant-time
/// alternative, precisely so that a consumer needing to compare codes reaches
/// for it instead of writing its own. This module is that consumer.
fn codes_equal(stored: &[u8; HMAC_LEN], offered: &[u8; HMAC_LEN]) -> bool {
    let mut ctx = HmacContext::<Sha256>::new(&[]);
    ctx.update(stored);
    ctx.verify_slice(&hmac_sha256(&[], offered))
}

// =========================================================================
// The peer -- `struct Curl_ssl_scache_peer` (`vtls_scache.c:50-64`)
// =========================================================================

/// How a peer slot is identified: by its key, or only by its code.
///
/// `cf_ssl_scache_peer_init` (`lib/vtls/vtls_scache.c:440-489`) is a
/// three-armed decision whose third arm is an error:
///
/// ```text
/// if(ssl_peer_key)        { peer->ssl_peer_key = strdup(...);
///                           peer->hmac_set = FALSE; }
/// else if(salt && hmac)   { memcpy(...); peer->hmac_set = TRUE; }
/// else                    { result = CURLE_BAD_FUNCTION_ARGUMENT; }
/// ```
///
/// The two valid arms become the two variants, so the error arm has no
/// reachable input and the function that used to return it cannot fail. That
/// is a faithful narrowing rather than a dropped check: all four C call sites
/// pass one or the other, and none passes neither.
#[derive(Clone, Debug, Eq, PartialEq)]
enum PeerIdentity<'a> {
    /// The peer key is known. `hmac_set` is cleared, because a salt and code
    /// for a *previous* occupant of this slot must not authenticate the new
    /// one.
    Key(&'a str),
    /// Only the salt and code are known, because the session was imported
    /// with a `shmac` and no key. The key may be recovered later, by
    /// [`SessionCache::find_peer_by_key`]'s second pass.
    Code {
        /// The 32 bytes an exporting process drew at random.
        salt: [u8; SALT_LEN],
        /// The keyed digest of that process's peer key under that salt.
        hmac: [u8; HMAC_LEN],
    },
}

/// One endpoint-and-configuration, and the sessions cached for it.
///
/// The successor of `struct Curl_ssl_scache_peer` (`vtls_scache.c:50-64`) less
/// the two members the module documentation accounts for -- the `void *sobj`
/// pair, whose only consumer is out of scope, and the SRP credentials, which
/// this build cannot have.
///
/// Private to this module. The C declares the struct in the implementation
/// file too, and every function that touches a peer is `static`; the cache is
/// the only legitimate owner, and publishing the slot would let a caller hold
/// a peer across the lock release that invalidates it.
#[derive(Default)]
struct ScachePeer {
    /// `char *ssl_peer_key`: the key, once known.
    ///
    /// [`None`] means either a free slot or a slot imported by code alone.
    /// [`Self::hmac_set`] distinguishes them.
    ssl_peer_key: Option<String>,

    /// `char *clientcert`, as the identity that must match before reuse.
    auth: ClientAuth,

    /// `struct Curl_llist sessions`: the cached tickets, oldest at the front.
    ///
    /// A [`VecDeque`] rather than a `Vec` because both ends are used: TLS 1.3
    /// appends at the back and trims from the front (`:773-776`), and a take
    /// removes from the front (`:891-893`). Front removal on a `Vec` is a
    /// shift; here it is a pointer move, and more importantly the code reads
    /// as the queue it is.
    sessions: VecDeque<TlsSession>,

    /// `unsigned char key_salt[CURL_SHA256_DIGEST_LENGTH]`: the export salt.
    key_salt: [u8; SALT_LEN],

    /// `unsigned char key_hmac[CURL_SHA256_DIGEST_LENGTH]`: the export code.
    key_hmac: [u8; HMAC_LEN],

    /// `size_t max_sessions`: how many sessions this slot may hold.
    ///
    /// Per-peer in the C as well, set once for every slot by
    /// `Curl_ssl_scache_create` (`:552-556`), which is why it survives
    /// [`Self::clear`].
    max_sessions: usize,

    /// `long age`: "just a number, the higher the more recent" (`:61`).
    ///
    /// [`i64`] because `long` is 64 bits on every one of the four mandated
    /// targets, all of which are LP64.
    age: i64,

    /// `BIT(hmac_set)`: whether [`Self::key_salt`] and [`Self::key_hmac`] hold
    /// anything.
    hmac_set: bool,

    /// `BIT(exportable)`: whether this slot's sessions may leave the process.
    ///
    /// Derived, never set directly -- see [`Self::update_exportable`].
    exportable: bool,
}

/// Reports the slot's shape without disclosing its salt, its code or its
/// tickets.
///
/// The salt and code together authenticate a peer key to an importing process,
/// and the sessions are resumption material. Both are reported as
/// *presence and counts*, for the same reason [`TlsSession`]'s own
/// [`fmt::Debug`] reports a length instead of bytes.
impl fmt::Debug for ScachePeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScachePeer")
            .field("ssl_peer_key", &self.ssl_peer_key)
            .field("clientcert", &self.auth.clientcert())
            .field("sessions", &self.sessions.len())
            .field("max_sessions", &self.max_sessions)
            .field("age", &self.age)
            .field("hmac_set", &self.hmac_set)
            .field("exportable", &self.exportable)
            .finish()
    }
}

impl ScachePeer {
    /// A free slot that may hold up to `max_sessions` sessions.
    ///
    /// `Curl_ssl_scache_create`'s per-slot initialisation (`:552-556`), which
    /// `calloc` had already zeroed.
    fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions,
            ..Self::default()
        }
    }

    /// `cf_ssl_scache_clear_peer` (`lib/vtls/vtls_scache.c:395-413`): empties
    /// the slot and makes it free again.
    ///
    /// The C frees the sessions, the object, the client certificate, the SRP
    /// pair and the key, then sets `age = 0` and `hmac_set = FALSE`. It leaves
    /// `exportable` and the salt-and-code bytes as they were.
    ///
    /// This zeroes those too, which is unobservable and strictly safer.
    /// Unobservable because both readers gate on the identity first:
    /// `Curl_ssl_session_export` skips a slot with neither key nor code before
    /// it looks at `exportable` (`:1167-1170`), and
    /// `cf_ssl_find_peer_by_hmac` requires `hmac_set` before it looks at the
    /// salt (`:1038`). Safer because a stale code cannot then authenticate a
    /// slot that has been handed to a different peer.
    ///
    /// `max_sessions` survives, as it does in the C: it is a property of the
    /// slab, configured once.
    fn clear(&mut self) {
        *self = Self::new(self.max_sessions);
    }

    /// Whether this slot is unoccupied.
    ///
    /// The C's `!peers[i].ssl_peer_key && !peers[i].hmac_set`, which appears
    /// twice -- as the first free-slot test (`:693`) and as the export skip
    /// (`:1167-1168`).
    const fn is_free(&self) -> bool {
        self.ssl_peer_key.is_none() && !self.hmac_set
    }

    /// `cf_ssl_scache_peer_init` (`lib/vtls/vtls_scache.c:440-489`).
    ///
    /// The C asserts `!peer->ssl_peer_key` on entry, because every caller
    /// reaches it through `cf_ssl_get_free_peer`, which has just cleared the
    /// slot. That ordering is preserved by the two call sites here, and the
    /// assignment below overwrites rather than leaking in any case.
    fn init(&mut self, identity: PeerIdentity<'_>, auth: Option<&ClientAuth>) {
        match identity {
            PeerIdentity::Key(key) => {
                self.ssl_peer_key = Some(String::from(key));
                self.hmac_set = false;
            }
            PeerIdentity::Code { salt, hmac } => {
                self.key_salt = salt;
                self.key_hmac = hmac;
                self.hmac_set = true;
            }
        }
        self.auth = auth.cloned().unwrap_or_default();
        self.update_exportable();
    }

    /// `cf_ssl_cache_peer_update` (`lib/vtls/vtls_scache.c:427-438`), whose
    /// comment enumerates the three conditions:
    ///
    /// ```text
    /// /* The sessions of this peer are exportable if
    ///  * - it has no confidential information
    ///  * - its peer key is not yet known, because sessions were
    ///  *   imported using only the salt+hmac
    ///  * - the peer key is global, e.g. carrying no relative paths */
    /// peer->exportable = (!peer->clientcert && !peer->srp_username &&
    ///                     !peer->srp_password &&
    ///                     (!peer->ssl_peer_key ||
    ///                      cf_ssl_peer_key_is_global(peer->ssl_peer_key)));
    /// ```
    ///
    /// The two SRP conjuncts are absent for the reason recorded on
    /// [`ClientAuth`]; the remaining structure is exact. Note that an unknown
    /// key makes a peer exportable rather than blocking it: such a slot exists
    /// only because a previous export produced its code, so re-exporting it
    /// discloses nothing that was not already disclosed.
    fn update_exportable(&mut self) {
        self.exportable = !self.auth.is_confidential()
            && match self.ssl_peer_key.as_deref() {
                None => true,
                Some(key) => peer_key_is_global(key),
            };
    }

    /// `cf_scache_peer_remove_expired` (`lib/vtls/vtls_scache.c:505-515`).
    ///
    /// The C walks the list capturing `next` before each removal, because
    /// removing a node invalidates it. [`VecDeque::retain`] is that walk with
    /// the invalidation hazard removed.
    fn remove_expired(&mut self, now: i64) {
        self.sessions.retain(|session| !session.expired(now));
    }

    /// `cf_scache_peer_remove_non13` (`lib/vtls/vtls_scache.c:517-526`).
    fn remove_non13(&mut self) {
        self.sessions.retain(TlsSession::is_tls13);
    }

    /// `cf_scache_peer_add_session` (`lib/vtls/vtls_scache.c:760-778`): the
    /// insertion policy, and the reason it differs by version.
    ///
    /// ```text
    /// /* A session not from TLSv1.3 replaces all other. */
    /// if(s->ietf_tls_id != CURL_IETF_PROTO_TLS1_3) {
    ///   Curl_llist_destroy(&peer->sessions, NULL);
    ///   Curl_llist_append(&peer->sessions, s, &s->list);
    /// }
    /// else {
    ///   /* Expire existing, append, trim from head to obey max_sessions */
    ///   cf_scache_peer_remove_expired(peer, now);
    ///   cf_scache_peer_remove_non13(peer);
    ///   Curl_llist_append(&peer->sessions, s, &s->list);
    ///   while(Curl_llist_count(&peer->sessions) > peer->max_sessions) {
    ///     Curl_node_remove(Curl_llist_head(&peer->sessions));
    ///   }
    /// }
    /// ```
    ///
    /// Before TLS 1.3 a session identifier is reusable, so exactly one is
    /// worth keeping and a new one supersedes everything. A TLS 1.3 ticket is
    /// single-use (RFC 8446 C.4), so several are worth keeping and the queue
    /// is trimmed from the *front* -- the oldest goes, which is also the one a
    /// take would have handed out next.
    ///
    /// Two asymmetries are the C's and are preserved. The pre-1.3 arm does
    /// **not** trim, so it stores its one session even where `max_sessions` is
    /// zero; the 1.3 arm's `while` loop with a maximum of zero discards
    /// everything including the session just appended. And the pre-1.3 arm
    /// does not sweep expired entries, because it removes them all anyway.
    fn add_session(&mut self, session: TlsSession, now: i64) {
        if session.is_tls13() {
            self.remove_expired(now);
            self.remove_non13();
            self.sessions.push_back(session);
            while self.sessions.len() > self.max_sessions {
                self.sessions.pop_front();
            }
        } else {
            self.sessions.clear();
            self.sessions.push_back(session);
        }
    }

    /// `cf_ssl_scache_peer_set_hmac` (`lib/vtls/vtls_scache.c:997-1017`):
    /// draws a salt and keys the peer key with it.
    ///
    /// ```text
    /// result = Curl_rand(NULL, peer->key_salt, sizeof(peer->key_salt));
    /// result = Curl_hmacit(&Curl_HMAC_SHA256,
    ///                      peer->key_salt, sizeof(peer->key_salt),
    ///                      (const unsigned char *)peer->ssl_peer_key,
    ///                      strlen(peer->ssl_peer_key),
    ///                      peer->key_hmac);
    /// if(!result) peer->hmac_set = TRUE;
    /// ```
    ///
    /// The salt is what lets a key be *recognised* without being disclosed: an
    /// importing process that already knows the key can recompute the code,
    /// and one that does not learns nothing beyond 64 opaque bytes. A fresh
    /// salt per peer per export is what stops two exports of the same key from
    /// being correlatable.
    ///
    /// The salt and code are assigned only once both are computed, so a peer
    /// cannot be left holding a salt that does not match its code.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] when the peer key is not known, which
    /// is the C's `if(!peer->ssl_peer_key)` at `:1002-1003`. The C's other
    /// arms come from `Curl_rand` and from `Curl_hmacit`'s arena allocation;
    /// neither has an analogue here.
    fn set_hmac(&mut self, rng: &mut dyn Rng) -> Result<(), CURLcode> {
        let mut salt = [0_u8; SALT_LEN];
        rand_bytes(rng, &mut salt);
        let hmac = match self.ssl_peer_key.as_deref() {
            Some(key) => hmac_sha256(&salt, key.as_bytes()),
            None => return Err(CURLcode::BadFunctionArgument),
        };
        self.key_salt = salt;
        self.key_hmac = hmac;
        self.hmac_set = true;
        Ok(())
    }

    /// The 64-byte `shmac`: this peer's salt followed by its code.
    ///
    /// `Curl_ssl_session_export` assembles it in a `dynbuf`
    /// (`vtls_scache.c:1184-1191`) and hands the pointer and length to the
    /// callback. A fixed-size array says the same thing and makes
    /// [`SHMAC_LEN`] structural rather than asserted.
    fn shmac(&self) -> [u8; SHMAC_LEN] {
        let mut shmac = [0_u8; SHMAC_LEN];
        shmac[..SALT_LEN].copy_from_slice(&self.key_salt);
        shmac[SALT_LEN..].copy_from_slice(&self.key_hmac);
        shmac
    }

    /// Whether this slot is the one `peer_key` names, for a caller holding
    /// `auth`.
    ///
    /// The first pass of `cf_ssl_find_peer_by_key`
    /// (`lib/vtls/vtls_scache.c:638-646`), as one predicate:
    ///
    /// ```text
    /// if(scache->peers[i].ssl_peer_key &&
    ///    curl_strequal(ssl_peer_key, scache->peers[i].ssl_peer_key) &&
    ///    cf_ssl_scache_match_auth(&scache->peers[i], conn_config))
    /// ```
    ///
    /// `curl_strequal` is case-**insensitive** over ASCII only
    /// (`lib/strequal.c:35-49`, folding through `Curl_raw_toupper`), which
    /// [`str::eq_ignore_ascii_case`] reproduces exactly. Rust's
    /// Unicode-aware case folding would not: it would equate keys the C keeps
    /// apart, merging two configurations into one cache slot.
    ///
    /// The authentication test is inseparable from the key test. Two transfers
    /// to the same endpoint with different client certificates produce the
    /// *same* key -- the key records only that a certificate is set, as
    /// `:CCERT` -- so without the second conjunct one transfer could resume a
    /// session the other established, presenting an identity it does not hold.
    fn matches_key(&self, peer_key: &str, auth: Option<&ClientAuth>) -> bool {
        match self.ssl_peer_key.as_deref() {
            Some(key) => {
                key.eq_ignore_ascii_case(peer_key) && self.auth.matches(auth)
            }
            None => false,
        }
    }

    /// Whether this peer's stored salt and code authenticate `peer_key`.
    ///
    /// The second pass of `cf_ssl_find_peer_by_key`
    /// (`lib/vtls/vtls_scache.c:653-664`): a slot imported by code alone can
    /// be *recognised* the moment a caller offers a key that keys to the same
    /// code under the stored salt.
    fn code_authenticates(&self, peer_key: &str) -> bool {
        let mut ctx = HmacContext::<Sha256>::new(&self.key_salt);
        ctx.update(peer_key.as_bytes());
        ctx.verify_slice(&self.key_hmac)
    }

    /// Whether this peer's *known key* keys to `offered` under `salt`.
    ///
    /// The recompute branch of `cf_ssl_find_peer_by_hmac`
    /// (`lib/vtls/vtls_scache.c:1045-1055`), which lets an import that carries
    /// only a `shmac` find a slot whose key is already known -- and so merge
    /// into it rather than evicting something to make room.
    fn key_produces_code(
        &self,
        salt: &[u8; SALT_LEN],
        offered: &[u8; HMAC_LEN],
    ) -> bool {
        match self.ssl_peer_key.as_deref() {
            Some(key) => {
                let mut ctx = HmacContext::<Sha256>::new(salt);
                ctx.update(key.as_bytes());
                ctx.verify_slice(offered)
            }
            None => false,
        }
    }
}

// =========================================================================
// Whether to cache at all -- `primary.cache_session`
// =========================================================================

/// Whether a transfer wants its sessions cached.
///
/// The successor of `ssl_config->primary.cache_session`, which
/// `Curl_ssl_scache_use` (`lib/vtls/vtls_scache.c:575-582`) reads and
/// `Curl_ssl_scache_put` (`:846`) reads again before storing anything.
///
/// A named type rather than a bare `bool` for one reason: the default has to
/// be **on**, and a `bool` parameter has no default.
/// `Curl_ssl_easy_config_init` (`lib/vtls/vtls.c:189`) sets it with the
/// comment "caching by default", and
/// [`Default`] here agrees with that line so a caller that configures nothing
/// gets curl's behaviour rather than the `bool` zero value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // Consumers land with crate::easy's option surface.
pub(crate) struct SessionCaching(bool);

impl Default for SessionCaching {
    /// `data->set.ssl.primary.cache_session = TRUE; /* caching by default */`
    /// (`lib/vtls/vtls.c:189`).
    fn default() -> Self {
        Self::ENABLED
    }
}

#[allow(dead_code)] // Consumers land with crate::easy's option surface.
impl SessionCaching {
    /// Caching on: curl's default.
    pub(crate) const ENABLED: Self = Self(true);

    /// Caching off, as `CURLOPT_SSL_SESSIONID_CACHE` set to 0 asks for.
    pub(crate) const DISABLED: Self = Self(false);

    /// The option value as the C bit.
    pub(crate) const fn from_bool(enabled: bool) -> Self {
        Self(enabled)
    }

    /// Whether sessions may be cached.
    pub(crate) const fn is_enabled(self) -> bool {
        self.0
    }
}

/// `Curl_ssl_scache_use` (`lib/vtls/vtls_scache.c:575-582`).
///
/// ```text
/// if(cf_ssl_scache_get(data)) {
///   struct ssl_config_data *ssl_config = Curl_ssl_cf_get_config(cf, data);
///   return ssl_config ? ssl_config->primary.cache_session : FALSE;
/// }
/// return FALSE;
/// ```
///
/// Both conjuncts survive: a cache must exist *and* the transfer must want
/// caching. The header explains why the first can fail -- "An ssl session
/// might not be configured or not available for 'connect-only' transfers"
/// (`vtls_scache.h:69-72`) -- and the missing-cache case is an [`Option`] here
/// rather than a null pointer, so the C's third `ssl_config ? ... : FALSE`
/// arm, which guards against a missing configuration, has no analogue.
#[allow(dead_code)] // Consumer lands with tls/rustls_backend.rs.
pub(crate) fn scache_use(
    cache: Option<&SessionCache>,
    caching: SessionCaching,
) -> bool {
    cache.is_some() && caching.is_enabled()
}

// =========================================================================
// The cache -- `struct Curl_ssl_scache` (`vtls_scache.c:299-305`)
// =========================================================================

/// A bounded slab of peers, each holding a bounded queue of sessions.
///
/// The successor of `struct Curl_ssl_scache`:
///
/// | C member | here |
/// |----------|------|
/// | `unsigned int magic` | gone -- see the module documentation |
/// | `struct Curl_ssl_scache_peer *peers` | [`Self::peers`] |
/// | `size_t peer_count` | `peers.len()` |
/// | `int default_lifetime_secs` | [`Self::default_lifetime_secs`] |
/// | `long age` | [`Self::age`] |
///
/// # Bounded in both dimensions, and never reallocated
///
/// `Curl_ssl_scache_create` `calloc`s exactly `max_peers` slots and never
/// grows them; a new peer displaces an existing one. That is the whole point
/// -- a session cache with no ceiling is a memory leak that a hostile server
/// can drive by redirecting to unlimited hostnames. The [`Vec`] below is
/// allocated once at that length and only ever has its elements replaced.
///
/// # No interior locking; read this before adding a `Mutex`
///
/// This type is plain data with `&mut self` mutators, and that is deliberate.
/// The C locks the *shared* cache and never the multi handle's own
/// (`vtls_scache.c:585-596`), so the lock belongs to the sharing decision. It
/// is reached here through [`ScacheLock`] and [`ScacheGuard`], which the future
/// share subsystem implements over the caller's `CURLSHOPT_LOCKFUNC`. A lock
/// inside this type would double-lock the shared case and would put the policy
/// in the module that cannot see which cache was selected.
#[derive(Debug)]
#[allow(dead_code)] // Consumers land with multi/ and share/.
pub(crate) struct SessionCache {
    /// `struct Curl_ssl_scache_peer *peers` with `size_t peer_count`.
    peers: Vec<ScachePeer>,

    /// `int default_lifetime_secs`: what an unknown expiry becomes.
    default_lifetime_secs: i64,

    /// `long age`: a monotonically increasing counter, bumped on every
    /// successful take, whose current value is stamped onto the peer that was
    /// used (`:894-895`). Comparing two peers' stamps orders them by last use,
    /// which is what makes the eviction in [`Self::free_peer`] an LRU without
    /// storing a timestamp or maintaining a list order.
    ///
    /// Starts at 1, not 0 (`:551`), so that a peer that has never been used --
    /// whose stamp [`ScachePeer::clear`] left at 0 -- always compares older
    /// than one that has.
    age: i64,
}

#[allow(dead_code)] // Consumers land with multi/ and share/.
impl SessionCache {
    /// `Curl_ssl_scache_create` (`lib/vtls/vtls_scache.c:528-560`).
    ///
    /// The C returns `CURLcode` for its two `calloc`s; neither can be reported
    /// here, so this is infallible.
    pub(crate) fn new(max_peers: usize, max_sessions_per_peer: usize) -> Self {
        Self {
            peers: (0..max_peers)
                .map(|_| ScachePeer::new(max_sessions_per_peer))
                .collect(),
            default_lifetime_secs: DEFAULT_LIFETIME_SEC,
            age: 1,
        }
    }

    /// How many peer slots the slab holds: the C's `peer_count`.
    pub(crate) fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Whether the slab has no slots at all.
    ///
    /// The C's `!scache->peer_count`, which `cf_ssl_add_peer` (`:727`) and
    /// `cf_scache_add_session` (`:792`) both test. Such a cache accepts
    /// nothing, which is a legitimate configuration rather than an error: both
    /// C sites return `CURLE_OK` after discarding the session.
    pub(crate) fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// The current age counter.
    pub(crate) const fn age(&self) -> i64 {
        self.age
    }

    /// What an unknown expiry becomes: `default_lifetime_secs`.
    pub(crate) const fn default_lifetime_secs(&self) -> i64 {
        self.default_lifetime_secs
    }

    /// Replaces the default lifetime.
    ///
    /// The C sets the member once, in the constructor, and nothing else writes
    /// it. Exposed here because it is the one knob that makes the defaulting
    /// path testable without a thousand-fold wait, and because a caller
    /// configuring a cache is the natural owner of the value.
    pub(crate) fn set_default_lifetime_secs(&mut self, secs: i64) {
        self.default_lifetime_secs = secs;
    }

    /// How many sessions are cached for a peer, or [`None`] when it is not
    /// cached at all.
    ///
    /// The C reads `Curl_llist_count(&peer->sessions)` inline for its trace
    /// lines (`:832`, `:904`, `:1133`). Named here so the count is observable
    /// without a trace sink, which is what lets the insertion policy be
    /// asserted.
    pub(crate) fn session_count(
        &self,
        peer_key: &str,
        auth: Option<&ClientAuth>,
    ) -> Option<usize> {
        self.peers
            .iter()
            .find(|peer| peer.matches_key(peer_key, auth))
            .map(|peer| peer.sessions.len())
    }

    /// `cf_ssl_find_peer_by_key` (`lib/vtls/vtls_scache.c:620-682`): two
    /// passes, in this order.
    ///
    /// **Pass one** looks for a slot whose key is known and equal, comparing
    /// with `curl_strequal` (`:640`). That is
    /// [`str::eq_ignore_ascii_case`]: `curl_strequal` routes to `casecompare`
    /// (`lib/strequal.c:35-49`), which folds through `Curl_raw_toupper` and is
    /// documented "capable of comparing a-z case insensitively" and
    /// "locale independent". It is deliberately *not* the comparison
    /// [`ClientAuth::matches`] performs, which is case-sensitive; the two
    /// differ in the C and differ here.
    ///
    /// **Pass two** looks for a slot that has a code but no key, and offers it
    /// the key: if the key authenticates against the stored salt, the slot is
    /// that peer, and the key is *remembered* so pass one finds it next time
    /// (`:665-673`). This is what makes an import-then-use sequence work when
    /// the import carried only a `shmac`.
    ///
    /// Recording the key changes what the peer is allowed to do, so
    /// [`ScachePeer::update_exportable`] runs immediately afterwards, exactly
    /// as `cf_ssl_cache_peer_update(&scache->peers[i])` does at `:673`: a
    /// recovered key ending in `:L` makes the peer non-exportable, which it
    /// was not while the key was unknown.
    ///
    /// The C's two `CURLcode` returns -- a refused `strdup` and a failing
    /// `Curl_hmacit` -- have no analogue, so this yields an index rather than
    /// a result.
    fn find_peer_by_key(
        &mut self,
        peer_key: &str,
        auth: Option<&ClientAuth>,
    ) -> Option<usize> {
        if let Some(found) = self
            .peers
            .iter()
            .position(|peer| peer.matches_key(peer_key, auth))
        {
            return Some(found);
        }

        let recovered = self.peers.iter().position(|peer| {
            peer.ssl_peer_key.is_none()
                && peer.hmac_set
                && peer.auth.matches(auth)
                && peer.code_authenticates(peer_key)
        })?;
        let peer = self.peers.get_mut(recovered)?;
        peer.ssl_peer_key = Some(String::from(peer_key));
        peer.update_exportable();
        Some(recovered)
    }

    /// `cf_ssl_find_peer_by_hmac` (`lib/vtls/vtls_scache.c:1019-1069`): finds
    /// the slot an imported `shmac` belongs to.
    ///
    /// One pass, three outcomes per slot, in the C's order:
    ///
    /// 1. The slot's stored salt and code are *exactly* the offered pair. This
    ///    is the only branch available for a slot that has no key, and it is
    ///    what makes repeated imports of the same export merge rather than
    ///    accumulate.
    /// 2. Otherwise, if the slot has a key, that key is keyed with the
    ///    *offered* salt and the result checked against the offered code. A
    ///    match means the exporting process held the same key, so the sessions
    ///    belong together -- and the slot adopts the offered salt and code if
    ///    it had none, which is the C's `if(!peer->hmac_set)` at `:1057-1061`.
    /// 3. Otherwise the slot is not it.
    ///
    /// Every slot is first filtered by `cf_ssl_scache_match_auth(peer, NULL)`
    /// (`:1036`): an import carries no client-certificate configuration, so a
    /// slot established with one is never a candidate.
    fn find_peer_by_hmac(
        &mut self,
        salt: &[u8; SALT_LEN],
        hmac: &[u8; HMAC_LEN],
    ) -> Option<usize> {
        for index in 0..self.peers.len() {
            let peer = self.peers.get(index)?;
            if !peer.auth.matches(None) {
                continue;
            }
            if peer.hmac_set
                && peer.key_salt == *salt
                && codes_equal(&peer.key_hmac, hmac)
            {
                return Some(index);
            }
            if peer.key_produces_code(salt, hmac) {
                let peer = self.peers.get_mut(index)?;
                if !peer.hmac_set {
                    peer.key_salt = *salt;
                    peer.key_hmac = *hmac;
                    peer.hmac_set = true;
                }
                return Some(index);
            }
        }
        None
    }

    /// `cf_ssl_get_free_peer` (`lib/vtls/vtls_scache.c:684-712`): which slot a
    /// new peer takes.
    ///
    /// ```text
    /// for(i = 0; i < scache->peer_count; ++i) {
    ///   /* free peer entry? */
    ///   if(!scache->peers[i].ssl_peer_key && !scache->peers[i].hmac_set) {
    ///     peer = &scache->peers[i]; break;
    ///   }
    ///   /* peer without sessions and obj */
    ///   if(!scache->peers[i].sobj &&
    ///      !Curl_llist_count(&scache->peers[i].sessions)) {
    ///     peer = &scache->peers[i]; break;
    ///   }
    ///   /* remember "oldest" peer */
    ///   if(!peer || (scache->peers[i].age < peer->age)) {
    ///     peer = &scache->peers[i];
    ///   }
    /// }
    /// if(peer) cf_ssl_scache_clear_peer(peer);
    /// ```
    ///
    /// Three tiers, and the order is the policy: an unoccupied slot first,
    /// then an occupied one holding nothing worth keeping, and only then the
    /// least recently used. The first two `break` out, so a scan that finds
    /// either stops without considering age -- which is why a cache with a
    /// free slot never evicts.
    ///
    /// The `!sobj` conjunct of the second test is absent for the reason the
    /// module documentation records: nothing in an in-scope build ever sets
    /// the slot, so the test is the session count alone.
    ///
    /// The chosen slot is **cleared** before being returned, so the caller
    /// receives a slot with no residue of its previous occupant -- and a
    /// caller that abandons it afterwards leaves a free slot rather than a
    /// half-initialised one.
    fn free_peer(&mut self) -> Option<usize> {
        let mut chosen: Option<usize> = None;
        for index in 0..self.peers.len() {
            let peer = self.peers.get(index)?;
            if peer.is_free() || peer.sessions.is_empty() {
                chosen = Some(index);
                break;
            }
            let older = match chosen {
                None => true,
                Some(best) => {
                    peer.age < self.peers.get(best).map_or(peer.age, |b| b.age)
                }
            };
            if older {
                chosen = Some(index);
            }
        }
        let index = chosen?;
        self.peers.get_mut(index)?.clear();
        Some(index)
    }

    /// `cf_ssl_add_peer` (`lib/vtls/vtls_scache.c:714-758`): the slot for
    /// `peer_key`, creating one if it is not already cached.
    ///
    /// [`None`] means the cache has no room at all, which is the C's
    /// `!scache->peer_count` early return (`:727-728`) and its
    /// `if(peer)`-guarded initialisation (`:737`). The C's `ssl_peer_key` is
    /// nullable at this signature but non-null at all four of its call sites,
    /// so it is a plain `&str` here and the `CURLE_BAD_FUNCTION_ARGUMENT` that
    /// `cf_ssl_scache_peer_init` would have returned for a null key with no
    /// salt is unreachable by construction -- see [`PeerIdentity`].
    fn add_peer(
        &mut self,
        peer_key: &str,
        auth: Option<&ClientAuth>,
    ) -> Option<usize> {
        if let Some(found) = self.find_peer_by_key(peer_key, auth) {
            return Some(found);
        }
        let index = self.free_peer()?;
        self.peers
            .get_mut(index)?
            .init(PeerIdentity::Key(peer_key), auth);
        Some(index)
    }

    /// `Curl_ssl_scache_put` (`lib/vtls/vtls_scache.c:836-855`) together with
    /// `cf_scache_add_session` (`:780-834`), which it wraps.
    ///
    /// The session is taken **by value**, so the C's promise that the call
    /// "takes ownership of `s` in all outcomes" (`vtls_scache.h:164`) is the
    /// signature rather than four hand-written `Curl_ssl_session_destroy`
    /// calls. Every discarding path below simply lets it drop:
    ///
    /// * caching is disabled -- `:846-849`;
    /// * the cache has no slots -- `:792-795`;
    /// * the session is already expired after clamping -- `:806-810`;
    /// * no slot could be found or made -- `:813-817`.
    ///
    /// The C returns `CURLE_OK` for all four, and reports failure only for the
    /// allocation arms that do not exist here, so this is infallible. The
    /// return value says whether the session was stored, which is what the C
    /// expresses through the session count in its trace line at `:827-832`.
    ///
    /// Order matters and is the C's: default the expiry, clamp it, *then* test
    /// for expiry. Testing first would discard a session whose stated expiry
    /// was unknown, and clamping first would give a session with no stated
    /// expiry the seven-day ceiling instead of the one-day default.
    pub(crate) fn put(
        &mut self,
        clock: &dyn Clock,
        caching: SessionCaching,
        peer_key: &str,
        auth: Option<&ClientAuth>,
        session: TlsSession,
    ) -> bool {
        if !caching.is_enabled() || self.peers.is_empty() {
            return false;
        }

        let now = clock.epoch_secs();
        let mut session = session;
        session.clamp_validity(now, self.default_lifetime_secs);
        if session.expired(now) {
            return false;
        }

        match self.add_peer(peer_key, auth) {
            Some(index) => match self.peers.get_mut(index) {
                Some(peer) => {
                    peer.add_session(session, now);
                    true
                }
                None => false,
            },
            None => false,
        }
    }

    /// `Curl_ssl_scache_take` (`lib/vtls/vtls_scache.c:870-911`): removes and
    /// yields the next session for `peer_key`.
    ///
    /// Expired entries are swept **before** the head is taken (`:890`), so a
    /// stale ticket is never handed out even though nothing sweeps the cache
    /// in the background. The head is the oldest, which is the right one to
    /// spend first: a TLS 1.3 ticket is single-use, so the queue is consumed
    /// in the order it was filled.
    ///
    /// A successful take bumps the cache's age and stamps it on the peer
    /// (`:894-895`), which is what keeps this peer out of the eviction path in
    /// [`Self::free_peer`]. A miss changes nothing -- neither counter moves --
    /// so a peer that was never usable does not defend itself against
    /// eviction by being asked for.
    ///
    /// Ownership transfers to the caller. The C hands back a pointer and
    /// documents that the caller must return it or destroy it; here the caller
    /// holds the value, so forgetting to return it drops it, which is the safe
    /// direction.
    pub(crate) fn take(
        &mut self,
        clock: &dyn Clock,
        peer_key: &str,
        auth: Option<&ClientAuth>,
    ) -> Option<TlsSession> {
        let index = self.find_peer_by_key(peer_key, auth)?;
        let now = clock.epoch_secs();
        let peer = self.peers.get_mut(index)?;
        peer.remove_expired(now);
        let session = peer.sessions.pop_front()?;
        self.age = self.age.saturating_add(1);
        if let Some(peer) = self.peers.get_mut(index) {
            peer.age = self.age;
        }
        Some(session)
    }

    /// `Curl_ssl_scache_return` (`lib/vtls/vtls_scache.c:857-868`): hands a
    /// taken session back, which re-caches it or destroys it.
    ///
    /// ```text
    /// /* See RFC 8446 C.4:
    ///  * "Clients SHOULD NOT reuse a ticket for multiple connections." */
    /// if(s && s->ietf_tls_id < 0x304)
    ///   (void)Curl_ssl_scache_put(cf, data, ssl_peer_key, s);
    /// else
    ///   Curl_ssl_session_destroy(s);
    /// ```
    ///
    /// So a TLS 1.3 ticket is **dropped** rather than returned: it has been
    /// spent, and re-caching it would offer the same ticket to a second
    /// connection, which is what RFC 8446 appendix C.4 tells clients not to
    /// do. A pre-1.3 session identifier is reusable by design, so it goes
    /// back.
    ///
    /// The C writes the literal `0x304` here where it writes
    /// `CURL_IETF_PROTO_TLS1_3` elsewhere; both are 0x0304, and the comparison
    /// is `<`, so any future version above 1.3 is also dropped -- the
    /// conservative direction for a mechanism whose whole subject is not
    /// reusing single-use material.
    ///
    /// `s` of `NULL` is accepted by the C ("Maybe called with a NULL session",
    /// `vtls_scache.h:188`); here the caller simply does not call this.
    pub(crate) fn return_session(
        &mut self,
        clock: &dyn Clock,
        caching: SessionCaching,
        peer_key: &str,
        auth: Option<&ClientAuth>,
        session: TlsSession,
    ) -> bool {
        if session.ietf_tls_id().bits() < IetfProtoVersion::TLS1_3.bits() {
            return self.put(clock, caching, peer_key, auth, session);
        }
        false
    }

    /// `Curl_ssl_scache_remove_all` (`lib/vtls/vtls_scache.c:972-991`):
    /// forgets everything cached for one peer.
    ///
    /// Called when a handshake fails in a way that implicates the cached
    /// material, so the slot has to be emptied rather than merely skipped. The
    /// return says whether a slot was found, which the C's `void` return
    /// discards.
    pub(crate) fn remove_all(
        &mut self,
        peer_key: &str,
        auth: Option<&ClientAuth>,
    ) -> bool {
        match self.find_peer_by_key(peer_key, auth) {
            Some(index) => match self.peers.get_mut(index) {
                Some(peer) => {
                    peer.clear();
                    true
                }
                None => false,
            },
            None => false,
        }
    }
}

// =========================================================================
// Import and export -- `USE_SSLS_EXPORT` (`vtls_scache.c:993-1219`)
// =========================================================================

/// One session, as the export callback receives it.
///
/// The seven arguments `Curl_ssl_session_export` passes to `export_fn`
/// (`lib/vtls/vtls_scache.c:1197-1201`), gathered into one value:
///
/// ```text
/// r = export_fn(data, userptr, peer->ssl_peer_key,
///               curlx_dyn_uptr(&hbuf), curlx_dyn_len(&hbuf),
///               curlx_dyn_uptr(&sbuf), curlx_dyn_len(&sbuf),
///               s->valid_until, s->ietf_tls_id,
///               s->alpn, s->earlydata_max);
/// ```
///
/// The two pointer-and-length pairs become slices, so the callback cannot be
/// handed a length that disagrees with its buffer. `data` and `userptr` are
/// absent: the first is the transfer the C needs only to emit a trace line,
/// and the second is a closure's captured state here.
///
/// The metadata beside the packed bytes is not redundant with them. A consumer
/// writing a session file wants the expiry, the protocol and the ALPN
/// *indexable* without unpacking every entry -- which is exactly what the
/// command-line tool's `--ssl-sessions` file does with them.
#[derive(Debug)]
#[allow(dead_code)] // Consumers land with curl-rs's --ssl-sessions support.
pub(crate) struct ExportedSession<'a> {
    /// `peer->ssl_peer_key`: the key, when this slot's key is known.
    ///
    /// [`None`] for a slot that was itself imported by code alone and whose
    /// key has not been recovered. The C passes the null pointer straight
    /// through, and a consumer that stores it stores nothing -- which is
    /// correct, because [`Self::shmac`] identifies the peer without it.
    pub(crate) peer_key: Option<&'a str>,

    /// The 64-byte salt-and-code: what identifies this peer to an importer
    /// that does not receive the key.
    pub(crate) shmac: &'a [u8; SHMAC_LEN],

    /// The packed session, as [`TlsSession::pack`] produced it.
    pub(crate) packed: &'a [u8],

    /// `s->valid_until`.
    pub(crate) valid_until: i64,

    /// `s->ietf_tls_id`.
    pub(crate) ietf_tls_id: IetfProtoVersion,

    /// `s->alpn`.
    pub(crate) alpn: Option<&'a str>,

    /// `s->earlydata_max`.
    pub(crate) earlydata_max: usize,
}

/// What an export got through.
///
/// The two counters the C's closing trace line reports -- "exported %zu
/// session tickets for %zu peers" (`lib/vtls/vtls_scache.c:1209-1210`) --
/// returned rather than only logged, so the outcome is assertable without a
/// trace sink.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // Consumers land with curl-rs's --ssl-sessions support.
pub(crate) struct ExportSummary {
    /// `npeers`: slots that contributed at least one session.
    pub(crate) peers: usize,
    /// `ntickets`: sessions handed to the callback.
    pub(crate) tickets: usize,
}

#[allow(dead_code)] // Consumers land with curl-rs's --ssl-sessions support.
impl SessionCache {
    /// `Curl_ssl_session_import` (`lib/vtls/vtls_scache.c:1071-1141`): takes a
    /// session that another process exported.
    ///
    /// A caller identifies the peer in one of exactly two ways, and the C's
    /// first check is that it chose one (`:1086-1089`):
    ///
    /// * **By key.** The slot for that key is found or made, exactly as
    ///   [`Self::put`] would find it, but with *no* client-certificate
    ///   configuration -- the C passes `NULL` for `conn_config` at `:1099`, so
    ///   a slot established with client credentials is never a candidate.
    /// * **By `shmac`.** The 64 bytes are split into salt and code and matched
    ///   through [`Self::find_peer_by_hmac`], which either recognises an
    ///   existing slot -- merging the import into it -- or reports none, in
    ///   which case a free slot is taken and initialised with the code alone.
    ///
    /// # An expired session is dropped before anything is touched
    ///
    /// This is the one place where the behaviour is deliberately not the C's,
    /// and the divergence is narrow and in the safe direction.
    /// `Curl_ssl_session_import` calls `cf_scache_peer_add_session` *directly*
    /// (`:1128`), bypassing `cf_scache_add_session` where the expiry test
    /// lives. So an already-expired import is stored -- and for a pre-1.3
    /// session, stored by an arm that first destroys every session the slot
    /// held (`:766`). A live, usable session is therefore discarded in favour
    /// of a dead one that the next take or export would sweep away anyway
    /// (`:890`, `:1173`).
    ///
    /// Testing first is what the agent brief specifies, and it makes the
    /// observable difference only in that one direction: nothing that could
    /// have been handed out is lost, because an expired session can never be
    /// taken or exported in either implementation.
    ///
    /// # What is *not* adjusted, and why that matters for round-tripping
    ///
    /// The expiry is neither defaulted nor clamped here, because the C does
    /// neither on this path. That is load-bearing rather than incidental: a
    /// session imported and then re-exported must carry the *same*
    /// `valid_until`, or a session file rewritten by a long-running process
    /// would drift its own deadlines every time it was reloaded.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] when neither a key nor a usable
    /// `shmac` was supplied, and when a `shmac` was supplied at a length other
    /// than [`SHMAC_LEN`] -- the C's comment at `:1104-1105` gives the two
    /// reasons that happens: "Either salt+hmac was garbled by caller or is
    /// from a curl version that does things differently." Plus whatever
    /// [`TlsSession::unpack`] reports for malformed bytes.
    pub(crate) fn import(
        &mut self,
        clock: &dyn Clock,
        peer_key: Option<&str>,
        shmac: Option<&[u8]>,
        sdata: &[u8],
    ) -> Result<(), CURLcode> {
        let session = TlsSession::unpack(sdata)?;
        let now = clock.epoch_secs();

        let index = match peer_key {
            Some(key) => self.add_peer(key, None),
            None => {
                // The C's two checks on the `shmac`, which its `:1086-1089`
                // and `:1103-1108` arms split across the unpack. Both yield
                // `CURLE_BAD_FUNCTION_ARGUMENT`, so testing the length once
                // here is the same outcome for the same inputs. An empty
                // slice is "absent", which is the C's `!shmac_len`.
                let shmac = shmac.filter(|bytes| !bytes.is_empty());
                let shmac = shmac.ok_or(CURLcode::BadFunctionArgument)?;
                if shmac.len() != SHMAC_LEN {
                    return Err(CURLcode::BadFunctionArgument);
                }
                let (salt, code) = shmac.split_at(SALT_LEN);
                let salt: [u8; SALT_LEN] =
                    salt.try_into().map_err(|_| CURLcode::ReadError)?;
                let code: [u8; HMAC_LEN] =
                    code.try_into().map_err(|_| CURLcode::ReadError)?;

                match self.find_peer_by_hmac(&salt, &code) {
                    Some(found) => Some(found),
                    None => {
                        let free = self.free_peer();
                        if let Some(index) = free {
                            if let Some(peer) = self.peers.get_mut(index) {
                                peer.init(
                                    PeerIdentity::Code { salt, hmac: code },
                                    None,
                                );
                            }
                        }
                        free
                    }
                }
            }
        };

        // Placed after the identity is resolved and before the session is
        // stored: an expired import must not disturb a slot, and the
        // argument errors above must still be reported for one.
        if session.expired(now) {
            return Ok(());
        }

        // `if(peer)` at `:1127`. No slot means a cache with no room, which
        // discards the session and reports success, as every other
        // out-of-room path in this module does.
        if let Some(peer) = index.and_then(|index| self.peers.get_mut(index)) {
            peer.add_session(session, now);
        }
        Ok(())
    }

    /// `Curl_ssl_session_export` (`lib/vtls/vtls_scache.c:1143-1217`): hands
    /// every eligible session to `export_fn`.
    ///
    /// Three filters, in the C's order, decide what a slot contributes:
    ///
    /// 1. `if(!peer->ssl_peer_key && !peer->hmac_set) continue;` (`:1167`) --
    ///    a free slot has nothing.
    /// 2. `if(!peer->exportable) continue;` (`:1169`) -- see
    ///    [`ScachePeer::update_exportable`] for the three conditions behind
    ///    that bit. A slot carrying client credentials, or one whose key ends
    ///    in `:L` because a configured path did not resolve, stays in the
    ///    process.
    /// 3. Expired sessions are swept, and a slot left with none contributes
    ///    nothing and is not counted (`:1173-1176`).
    ///
    /// A slot that survives and has no code yet gets one drawn now
    /// (`:1179-1183`), so the salt is fresh per export rather than per
    /// process.
    ///
    /// # Errors
    ///
    /// Whatever [`TlsSession::pack`] reports -- notably
    /// [`CURLcode::TooLarge`] for a session that does not fit
    /// [`SSL_TICKET_MAX`] -- and whatever the callback returns. The C stops at
    /// the first failure through `goto out` and so does this, which is what
    /// lets a callback abandon a partial write rather than being handed the
    /// rest of the cache after its destination has gone.
    ///
    /// The C's `if(!export_fn) return CURLE_BAD_FUNCTION_ARGUMENT` (`:1155`)
    /// has no analogue: the callback is a parameter, not a nullable pointer.
    pub(crate) fn export(
        &mut self,
        clock: &dyn Clock,
        rng: &mut dyn Rng,
        export_fn: &mut dyn FnMut(&ExportedSession<'_>) -> Result<(), CURLcode>,
    ) -> Result<ExportSummary, CURLcode> {
        let now = clock.epoch_secs();
        let mut summary = ExportSummary::default();

        for index in 0..self.peers.len() {
            // Every mutation of the slot happens here, before anything is
            // borrowed for the callback: sweep, then draw a code if needed,
            // then copy out the metadata the callback needs. That ordering is
            // what lets the callback run while nothing of this cache is
            // mutably borrowed -- so a callback cannot be handed a reference
            // that a later sweep would invalidate.
            let (shmac, peer_key, sessions) = {
                let peer = match self.peers.get_mut(index) {
                    Some(peer) => peer,
                    None => continue,
                };
                if peer.is_free() || !peer.exportable {
                    continue;
                }
                peer.remove_expired(now);
                if peer.sessions.is_empty() {
                    continue;
                }
                if !peer.hmac_set {
                    peer.set_hmac(rng)?;
                }
                (
                    peer.shmac(),
                    peer.ssl_peer_key.clone(),
                    peer.sessions.clone(),
                )
            };

            summary.peers += 1;
            for session in &sessions {
                let packed = session.pack()?;
                let item = ExportedSession {
                    peer_key: peer_key.as_deref(),
                    shmac: &shmac,
                    packed: &packed,
                    valid_until: session.valid_until(),
                    ietf_tls_id: session.ietf_tls_id(),
                    alpn: session.alpn(),
                    earlydata_max: session.earlydata_max(),
                };
                export_fn(&item)?;
                summary.tickets += 1;
            }
        }

        Ok(summary)
    }
}

// =========================================================================
// Selection and locking -- the seam, and nothing beyond it
// =========================================================================

/// `curl_lock_access` (`include/curl/curl.h`), as the session cache uses it.
///
/// The values are the public enumeration's and are written explicitly, because
/// they are what a caller's `CURLSHOPT_LOCKFUNC` receives: an application
/// compiled against curl 8.19.0-DEV holds the *integers*, so `SHARED` must be
/// 1 and `SINGLE` must be 2. The ABI spelling of the enumeration lives in
/// `curl-rs-ffi`; this is the internal vocabulary the seam speaks, and the two
/// agree by these literals rather than by one importing the other -- which
/// would make the engine depend on the ABI shim and invert the crate graph.
///
/// Only [`Self::Single`] is ever requested here: `Curl_ssl_scache_lock`
/// (`lib/vtls/vtls_scache.c:588`) asks for exclusive access unconditionally,
/// because every path that takes the lock goes on to mutate. The other two
/// values exist so that an implementation of [`ScacheLock`] can carry the whole
/// vocabulary without inventing part of it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // The share subsystem is the consumer, and has no file yet.
pub(crate) enum LockAccess {
    /// `CURL_LOCK_ACCESS_NONE` = 0.
    None = 0,
    /// `CURL_LOCK_ACCESS_SHARED` = 1: readers may overlap.
    Shared = 1,
    /// `CURL_LOCK_ACCESS_SINGLE` = 2: exclusive.
    Single = 2,
}

/// The whole of what this module needs from the sharing machinery.
///
/// `Curl_ssl_scache_lock` and `_unlock` (`lib/vtls/vtls_scache.c:585-596`)
/// reduce to two calls with one datum, `CURL_LOCK_DATA_SSL_SESSION`:
///
/// ```text
/// void Curl_ssl_scache_lock(struct Curl_easy *data)
/// {
///   if(CURL_SHARE_ssl_scache(data))
///     Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION,
///                     CURL_LOCK_ACCESS_SINGLE);
/// }
/// ```
///
/// The datum is implicit in the trait: an implementation of [`ScacheLock`]
/// *is* the SSL-session lock, so nothing here has to name a lock-data
/// enumeration or dispatch on one.
///
/// # Why a trait, and why so narrow
///
/// The mechanics behind these two calls are entirely the share subsystem's:
/// which `CURLSHOPT_SHARE` bits are set, whether the application supplied
/// `CURLSHOPT_LOCKFUNC` and `CURLSHOPT_UNLOCKFUNC`, what pointer to hand them,
/// and what to do when it supplied none. None of that belongs to TLS, and
/// importing it would point `crate::tls` at `crate::share` while
/// `crate::share` owns a `SessionCache` -- a cycle. Two methods and no
/// associated types is the smallest seam that still lets the C's exact locking
/// discipline be expressed and tested.
///
/// The header's own guidance is preserved by [`ScacheGuard`] rather than by
/// convention: "Caller should unlock this mutex as soon as possible, as it may
/// block other SSL connection from making progress" (`vtls_scache.h:77-78`).
#[allow(dead_code)] // The share subsystem is the consumer, and has no file yet.
pub(crate) trait ScacheLock: fmt::Debug {
    /// `Curl_share_lock(data, CURL_LOCK_DATA_SSL_SESSION, access)`.
    fn lock(&self, access: LockAccess);

    /// `Curl_share_unlock(data, CURL_LOCK_DATA_SSL_SESSION)`.
    fn unlock(&self);
}

/// The lock a cache that is not shared needs: none.
///
/// `Curl_ssl_scache_lock` takes nothing when the selected cache is the multi
/// handle's own, because a multi handle drives its transfers from one thread.
/// [`NoLock`] is that case as a value, so the locked and unlocked paths are one
/// code path with a different implementation rather than two code paths with a
/// conditional.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // The share subsystem is the consumer, and has no file yet.
pub(crate) struct NoLock;

impl ScacheLock for NoLock {
    /// Nothing to take.
    fn lock(&self, _access: LockAccess) {}

    /// Nothing to release.
    fn unlock(&self) {}
}

/// Where the cache a transfer will use came from.
///
/// `cf_ssl_scache_get` (`lib/vtls/vtls_scache.c:307-322`) answers two questions
/// at once -- which cache, and whether it is shared -- and the second is what
/// `Curl_ssl_scache_lock` needs, since only the share's cache is locked.
/// Returning the provenance alongside the cache is what keeps those two answers
/// from being derived independently and disagreeing.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[allow(dead_code)] // Consumers land with multi/ and share/.
pub(crate) enum CacheOrigin {
    /// `data->share->ssl_scache`: shared between handles, and locked.
    Shared,
    /// `data->multi->ssl_scache`: this multi handle's own, and not locked.
    Local,
}

/// A cache that has been selected, and the knowledge of where it came from.
///
/// Deliberately not [`Copy`] and deliberately holding `&mut`: selecting a cache
/// is what grants the right to mutate it, and that right cannot be duplicated.
#[derive(Debug)]
#[allow(dead_code)] // Consumers land with multi/ and share/.
pub(crate) struct SelectedCache<'a> {
    /// The cache itself.
    cache: &'a mut SessionCache,
    /// Which of the two it was.
    origin: CacheOrigin,
}

/// `cf_ssl_scache_get` (`lib/vtls/vtls_scache.c:307-322`): the share's cache
/// wins.
///
/// ```text
/// /* If a share is present, its ssl_scache has preference over the multi */
/// if(data->share && data->share->ssl_scache)
///   scache = data->share->ssl_scache;
/// else if(data->multi && data->multi->ssl_scache)
///   scache = data->multi->ssl_scache;
/// ```
///
/// The precedence is not arbitrary. An application that set
/// `CURLSHOPT_SHARE` with `CURL_LOCK_DATA_SSL_SESSION` asked for its handles to
/// resume each other's sessions; honouring the multi handle's private cache
/// instead would silently ignore that request and confine every session to one
/// handle.
///
/// The C's four-way nullability -- no share, a share with no cache, no multi, a
/// multi with no cache -- collapses to two [`Option`]s, because "present but
/// holding nothing" is not expressible when the value *is* the cache. The
/// `GOOD_SCACHE` validity check that follows in the C (`:315-320`) has no
/// analogue for the reason the module documentation records.
#[allow(dead_code)] // Consumers land with multi/ and share/.
pub(crate) fn select_cache<'a>(
    shared: Option<&'a mut SessionCache>,
    local: Option<&'a mut SessionCache>,
) -> Option<SelectedCache<'a>> {
    match (shared, local) {
        (Some(cache), _) => Some(SelectedCache {
            cache,
            origin: CacheOrigin::Shared,
        }),
        (None, Some(cache)) => Some(SelectedCache {
            cache,
            origin: CacheOrigin::Local,
        }),
        (None, None) => None,
    }
}

#[allow(dead_code)] // Consumers land with multi/ and share/.
impl<'a> SelectedCache<'a> {
    /// Which cache this is.
    pub(crate) const fn origin(&self) -> CacheOrigin {
        self.origin
    }

    /// Takes the external lock if this cache is the shared one, and yields a
    /// guard that releases it.
    ///
    /// This is `Curl_ssl_scache_lock` plus its matching `_unlock`, as one
    /// scope. The `if(CURL_SHARE_ssl_scache(data))` test is the
    /// [`CacheOrigin`] check below: a local cache is never locked, so `lock`
    /// is not called for one and neither is `unlock`.
    ///
    /// Requesting [`LockAccess::Single`] unconditionally is the C's choice at
    /// `:588`, and it is the right one for every caller here -- `put`, `take`,
    /// `remove_all`, `import` and `export` all mutate, the last two including
    /// `export`, which sweeps expired entries and may draw a fresh salt.
    pub(crate) fn acquire(self, lock: &'a dyn ScacheLock) -> ScacheGuard<'a> {
        let held = match self.origin {
            CacheOrigin::Shared => {
                lock.lock(LockAccess::Single);
                Some(lock)
            }
            CacheOrigin::Local => None,
        };
        ScacheGuard {
            cache: self.cache,
            lock: held,
        }
    }

    /// The cache without taking any lock.
    ///
    /// For the callers that genuinely need none: `Curl_ssl_scache_get_obj`
    /// (`:947-970`) reads the cache without locking, and the header explains
    /// that the *caller* is expected to hold the lock across such a call
    /// (`vtls_scache.h:88`). Naming the escape hatch is better than leaving
    /// callers to construct their own, because a name can carry that
    /// requirement.
    pub(crate) fn into_inner(self) -> &'a mut SessionCache {
        self.cache
    }
}

/// A locked cache, released when it goes out of scope.
///
/// What the C spells with paired calls and, in one function, a `bool locked`
/// plus a `goto`:
///
/// ```text
/// bool locked = FALSE;
/// ...
/// Curl_ssl_scache_lock(data);
/// locked = TRUE;
/// ...
/// out:
///   if(locked)
///     Curl_ssl_scache_unlock(data);
/// ```
///
/// That is `Curl_ssl_session_import` (`vtls_scache.c:1079`, `:1095-1096`,
/// `:1136-1138`), and the bookkeeping exists because the function has nine exit
/// paths. Here the release is [`Drop`], so early return, `?` propagation and
/// unwinding all release, there is no flag to get wrong, and the critical
/// section is exactly this value's scope -- which is the header's "as soon as
/// possible" made structural.
///
/// [`Deref`] and [`DerefMut`] to [`SessionCache`] so that a locked cache reads
/// as the cache it is.
#[derive(Debug)]
#[allow(dead_code)] // Consumers land with multi/ and share/.
pub(crate) struct ScacheGuard<'a> {
    /// The cache this guard grants access to.
    cache: &'a mut SessionCache,
    /// The lock to release, or [`None`] when none was taken.
    lock: Option<&'a dyn ScacheLock>,
}

impl Deref for ScacheGuard<'_> {
    type Target = SessionCache;

    fn deref(&self) -> &Self::Target {
        self.cache
    }
}

impl DerefMut for ScacheGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.cache
    }
}

impl Drop for ScacheGuard<'_> {
    /// `Curl_ssl_scache_unlock`, on every path out of the scope.
    fn drop(&mut self) {
        if let Some(lock) = self.lock {
            lock.unlock();
        }
    }
}

// Tests -- the byte-level contracts, and the cache behaviour around them
//
// Two C unit tests cover this code, and both are unreachable here. `tests/unit`
// programs link a debug static libcurl and call internal `Curl_*` symbols; a
// Rust static library does not export `pub(crate)` items, so the coverage moves
// into this module, which AAP 0.8.7 records as a documented deviation rather
// than a gap. The fixtures that drive the CLI are unaffected:
// `--ssl-sessions` exercises this file through the binary and needs nothing
// relocated.
//
// What is asserted here, and why each group exists:
//
//   * The pack format, byte for byte, per tag and per integer width. A session
//     file written by curl 8.19.0-DEV must be readable by this build and vice
//     versa, so a golden vector is the only assertion that catches a widened
//     field or a reordered one.
//   * Every rejection the decoder owes: wrong version, unknown tag, truncation
//     at every field boundary, a length naming more bytes than exist, and the
//     four checked-conversion overflows. None of them may panic, because they
//     all describe input that arrived from outside the process.
//   * Every peer-key fragment, in order, plus the canonical-versus-local path
//     decision and the 10 KiB ceiling. A key is compared as one string, so a
//     reordered fragment silently disables resumption rather than failing
//     loudly -- these tests are what make that failure loud.
//   * The lifetime arithmetic, the expiry sweep, the LRU, the per-peer trim and
//     the two insertion policies, driven by an injected clock so the seven-day
//     ceiling is asserted rather than waited for.
//   * The 64-byte salt-and-code round trip, its constant-time verification, and
//     the key-recovery path that makes an import carrying only a code usable.
//   * The sharing precedence and the locking discipline, with a recording fake
//     that proves a local cache is never locked and a shared one is always
//     unlocked -- including on the error path.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rand::TestRng;
    use crate::util::timeval::TestClock;
    use std::cell::RefCell;

    /// A clock reading exactly `secs` seconds past the epoch.
    ///
    /// Every time-dependent assertion below fixes the clock rather than
    /// sampling the host's, which is what makes "seven days from now" an exact
    /// number instead of a window.
    fn clock_at(secs: i64) -> TestClock {
        let clock = TestClock::new(crate::util::timeval::CurlTime::new(0, 0));
        clock.set_epoch_secs(secs);
        clock
    }

    /// A reproducible generator, so an exported salt is a known 32 bytes.
    fn rng() -> TestRng {
        TestRng::from_seed(0x5EED_0001)
    }

    /// A TLS 1.3 session with the given ticket and expiry.
    fn session13(ticket: &[u8], valid_until: i64) -> TlsSession {
        TlsSession::new(
            ticket.to_vec(),
            IetfProtoVersion::TLS1_3,
            None,
            valid_until,
            0,
        )
        .expect("a non-empty ticket is accepted")
    }

    /// A TLS 1.2 session with the given ticket and expiry.
    fn session12(ticket: &[u8], valid_until: i64) -> TlsSession {
        TlsSession::new(
            ticket.to_vec(),
            IetfProtoVersion::TLS1_2,
            None,
            valid_until,
            0,
        )
        .expect("a non-empty ticket is accepted")
    }

    // ------------------------------------------------ the packed byte format

    /// The seven tags, as `vtls_spack.c:41-47` defines them.
    #[test]
    fn the_pack_tags_are_the_c_constants() {
        assert_eq!(SPACK_VERSION, 0x01);
        assert_eq!(SPACK_IETF_ID, 0x02);
        assert_eq!(SPACK_VALID_UNTIL, 0x03);
        assert_eq!(SPACK_TICKET, 0x04);
        assert_eq!(SPACK_ALPN, 0x05);
        assert_eq!(SPACK_EARLYDATA, 0x06);
        assert_eq!(SPACK_QUICTP, 0x07);
    }

    /// The minimum payload, byte for byte: version, ticket, protocol, expiry
    /// and nothing else.
    ///
    /// This is the golden vector the whole format rests on. A widened field, a
    /// little-endian integer or a reordered tag all fail here, and nowhere
    /// else would catch them -- a round-trip test passes happily against a
    /// format that agrees only with itself.
    #[test]
    fn the_minimum_payload_is_byte_exact() {
        let session = TlsSession::new(
            b"ABC".to_vec(),
            IetfProtoVersion::TLS1_3,
            None,
            0x0102_0304_0506_0708,
            0,
        )
        .expect("a ticket");

        assert_eq!(
            session.pack().expect("it packs"),
            vec![
                0x01, // CURL_SPACK_VERSION
                0x04, // CURL_SPACK_TICKET
                0x00, 0x03, // u16 length, big-endian
                b'A', b'B', b'C', 0x02, // CURL_SPACK_IETF_ID
                0x03, 0x04, // 0x0304, big-endian
                0x03, // CURL_SPACK_VALID_UNTIL
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ]
        );
    }

    /// The ALPN tag: a `u16` length and the bytes, appended after the expiry.
    #[test]
    fn the_alpn_tag_is_byte_exact() {
        let session = TlsSession::new(
            b"T".to_vec(),
            IetfProtoVersion::TLS1_2,
            Some("h2"),
            1,
            0,
        )
        .expect("a ticket");

        assert_eq!(
            session.pack().expect("it packs"),
            vec![
                0x01, 0x04, 0x00, 0x01, b'T', 0x02, 0x03, 0x03, 0x03, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, //
                0x05, // CURL_SPACK_ALPN
                0x00, 0x02, // u16 length
                b'h', b'2',
            ]
        );
    }

    /// The early-data tag is the one **four**-byte field, and it is omitted
    /// when zero rather than written as four zero bytes.
    #[test]
    fn the_early_data_tag_is_a_big_endian_u32_and_omitted_when_zero() {
        let with = TlsSession::new(
            b"T".to_vec(),
            IetfProtoVersion::TLS1_3,
            None,
            1,
            0xDEAD_BEEF,
        )
        .expect("a ticket");
        let packed = with.pack().expect("it packs");
        assert_eq!(
            &packed[packed.len() - 5..],
            &[0x06, 0xDE, 0xAD, 0xBE, 0xEF]
        );

        let without = TlsSession::new(
            b"T".to_vec(),
            IetfProtoVersion::TLS1_3,
            None,
            1,
            0,
        )
        .expect("a ticket");
        let packed = without.pack().expect("it packs");
        assert!(!packed.contains(&SPACK_EARLYDATA));
        // Ending on the expiry, with nothing after it.
        assert_eq!(packed.len(), 1 + 1 + 2 + 1 + 1 + 2 + 1 + 8);
    }

    /// The QUIC tag: a `u16` length and the bytes, and omitted when the blob
    /// is absent *or* empty -- the C's `if(s->quic_tp && s->quic_tp_len)`.
    #[test]
    fn the_quic_tag_is_byte_exact_and_omitted_when_empty() {
        let with = TlsSession::with_quic_tp(
            b"T".to_vec(),
            IetfProtoVersion::TLS1_3,
            None,
            1,
            0,
            Some(vec![0xAA, 0xBB]),
        )
        .expect("a ticket");
        let packed = with.pack().expect("it packs");
        assert_eq!(
            &packed[packed.len() - 5..],
            &[0x07, 0x00, 0x02, 0xAA, 0xBB]
        );

        for empty in [None, Some(Vec::new())] {
            let without = TlsSession::with_quic_tp(
                b"T".to_vec(),
                IetfProtoVersion::TLS1_3,
                None,
                1,
                0,
                empty,
            )
            .expect("a ticket");
            let packed = without.pack().expect("it packs");
            assert!(!packed.contains(&SPACK_QUICTP));
        }
    }

    /// Every optional field present, in the C's order: version, ticket,
    /// protocol, expiry, ALPN, early data, QUIC parameters.
    #[test]
    fn a_fully_populated_payload_is_byte_exact() {
        let session = TlsSession::with_quic_tp(
            b"tk".to_vec(),
            IetfProtoVersion::TLS1_3,
            Some("h3"),
            0x0000_0000_0000_00FF,
            0x0000_0100,
            Some(vec![0x11, 0x22, 0x33]),
        )
        .expect("a ticket");

        assert_eq!(
            session.pack().expect("it packs"),
            vec![
                0x01, // version
                0x04, 0x00, 0x02, b't', b'k', // ticket
                0x02, 0x03, 0x04, // protocol
                0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0xFF, // expiry
                0x05, 0x00, 0x02, b'h', b'3', // ALPN
                0x06, 0x00, 0x00, 0x01, 0x00, // early data
                0x07, 0x00, 0x03, 0x11, 0x22, 0x33, // QUIC parameters
            ]
        );
    }

    /// Every integer width, at a value whose byte order is unambiguous.
    #[test]
    fn every_integer_width_is_big_endian() {
        let mut buf = DynBuf::new(64);
        enc8(&mut buf, 0x12).expect("it fits");
        enc16(&mut buf, 0x1234).expect("it fits");
        enc32(&mut buf, 0x1234_5678).expect("it fits");
        enc64(&mut buf, 0x1234_5678_9ABC_DEF0).expect("it fits");
        assert_eq!(
            buf.as_slice(),
            &[
                0x12, //
                0x12, 0x34, //
                0x12, 0x34, 0x56, 0x78, //
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
            ]
        );

        // And the decoders read them back.
        let mut reader = SpackReader::new(buf.as_slice());
        assert_eq!(reader.dec8(), Ok(0x12));
        assert_eq!(reader.dec16(), Ok(0x1234));
        assert_eq!(reader.dec32(), Ok(0x1234_5678));
        assert_eq!(reader.dec64(), Ok(0x1234_5678_9ABC_DEF0));
        assert!(reader.is_empty());
    }

    /// A length-prefixed string and blob, and the empty cases.
    #[test]
    fn length_prefixed_fields_carry_a_big_endian_u16() {
        let mut buf = DynBuf::new(64);
        encstr16(&mut buf, "hi").expect("it fits");
        encdata16(&mut buf, &[0xFF]).expect("it fits");
        encstr16(&mut buf, "").expect("it fits");
        encdata16(&mut buf, &[]).expect("it fits");
        assert_eq!(
            buf.as_slice(),
            &[
                0x00, 0x02, b'h', b'i', //
                0x00, 0x01, 0xFF, //
                0x00, 0x00, //
                0x00, 0x00,
            ]
        );

        let mut reader = SpackReader::new(buf.as_slice());
        assert_eq!(reader.decstr16().as_deref(), Ok("hi"));
        assert_eq!(reader.decdata16(), Ok(vec![0xFF]));
        assert_eq!(reader.decstr16().as_deref(), Ok(""));
        assert_eq!(reader.decdata16(), Ok(Vec::new()));
    }

    /// Round trips, over the full matrix of optional-field combinations.
    #[test]
    fn every_optional_field_combination_round_trips() {
        for alpn in [None, Some("h2")] {
            for earlydata in [0_usize, 1, 65_536] {
                for quic in [None, Some(vec![]), Some(vec![9_u8, 8, 7])] {
                    let original = TlsSession::with_quic_tp(
                        b"ticket".to_vec(),
                        IetfProtoVersion::TLS1_3,
                        alpn,
                        1_234_567_890,
                        earlydata,
                        quic.clone(),
                    )
                    .expect("a ticket");

                    let packed = original.pack().expect("it packs");
                    let decoded =
                        TlsSession::unpack(&packed).expect("it unpacks");

                    assert_eq!(decoded.ticket(), b"ticket");
                    assert_eq!(decoded.ietf_tls_id(), IetfProtoVersion::TLS1_3);
                    assert_eq!(decoded.alpn(), alpn);
                    assert_eq!(decoded.valid_until(), 1_234_567_890);
                    assert_eq!(decoded.earlydata_max(), earlydata);
                    // An empty blob is omitted, so it decodes as absent -- the
                    // one field whose round trip normalises rather than
                    // preserving, exactly as the C's encoder does.
                    let expected = quic.filter(|tp| !tp.is_empty());
                    assert_eq!(decoded.quic_tp(), expected.as_deref());
                    // And re-packing is byte-identical, which is what makes an
                    // import-then-export cycle stable.
                    assert_eq!(decoded.pack().expect("it packs"), packed);
                }
            }
        }
    }

    /// A ticket of every length across the `u16` boundary of the length field.
    #[test]
    fn ticket_lengths_round_trip_up_to_the_buffer_ceiling() {
        for len in [1_usize, 2, 255, 256, 257, 4_096, SSL_TICKET_MAX - 20] {
            let session = session13(&vec![0x5A; len], 1);
            let packed = session.pack().expect("it packs");
            let decoded = TlsSession::unpack(&packed).expect("it unpacks");
            assert_eq!(decoded.ticket().len(), len);
            // The u16 length field, big-endian, right after the ticket tag.
            let expected = u16::try_from(len).expect("it fits a u16");
            assert_eq!(&packed[2..4], &expected.to_be_bytes());
        }
    }

    /// `vtls_spack.c:199-200`: a negative expiry is
    /// `CURLE_BAD_FUNCTION_ARGUMENT`, and the check happens before anything is
    /// written.
    #[test]
    fn a_negative_expiry_cannot_be_packed() {
        for stated in [-1_i64, -86_400, i64::MIN] {
            let session = session13(b"t", stated);
            assert_eq!(session.pack(), Err(CURLcode::BadFunctionArgument));
        }
        // Zero and positive are fine.
        assert!(session13(b"t", 0).pack().is_ok());
        assert!(session13(b"t", i64::MAX).pack().is_ok());
    }

    /// `vtls_spack.c:164-165` and `:134-135`: a length field is a `u16`, so a
    /// longer ticket, ALPN or blob is `CURLE_BAD_FUNCTION_ARGUMENT`.
    ///
    /// The buffer's own 16 KiB ceiling fires first for a ticket, so the `u16`
    /// arm is reached through the codec directly -- which is what proves the
    /// check exists rather than being masked.
    #[test]
    fn a_field_longer_than_a_u16_cannot_be_packed() {
        let oversized = vec![0_u8; usize::from(u16::MAX) + 1];
        let mut buf = DynBuf::new(1024 * 1024);
        assert_eq!(
            encdata16(&mut buf, &oversized),
            Err(CURLcode::BadFunctionArgument)
        );
        let text = "x".repeat(usize::from(u16::MAX) + 1);
        assert_eq!(
            encstr16(&mut buf, &text),
            Err(CURLcode::BadFunctionArgument)
        );
        // Exactly u16::MAX is accepted by the codec.
        let exact = vec![0_u8; usize::from(u16::MAX)];
        let mut big = DynBuf::new(1024 * 1024);
        assert_eq!(encdata16(&mut big, &exact), Ok(()));
    }

    /// `vtls_spack.c:221-222`: an early-data maximum above `u32::MAX` is
    /// `CURLE_BAD_FUNCTION_ARGUMENT`.
    #[test]
    fn an_early_data_maximum_above_a_u32_cannot_be_packed() {
        let session = TlsSession::new(
            b"t".to_vec(),
            IetfProtoVersion::TLS1_3,
            None,
            1,
            u32_max_as_usize() + 1,
        )
        .expect("a ticket");
        assert_eq!(session.pack(), Err(CURLcode::BadFunctionArgument));

        // Exactly u32::MAX packs.
        let exact = TlsSession::new(
            b"t".to_vec(),
            IetfProtoVersion::TLS1_3,
            None,
            1,
            u32_max_as_usize(),
        )
        .expect("a ticket");
        let packed = exact.pack().expect("it packs");
        assert_eq!(
            &packed[packed.len() - 5..],
            &[0x06, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    /// `u32::MAX` as a `usize`, checked.
    ///
    /// `From<u32> for usize` does not exist -- the standard library stops at
    /// `u16`, because a `usize` is not guaranteed to be 32 bits wide. Every
    /// mandated target is 64-bit, so this cannot fail there; it is written as a
    /// checked conversion regardless, because an `as` cast in a test that
    /// exists to prove a conversion is checked would be a poor advertisement.
    fn u32_max_as_usize() -> usize {
        usize::try_from(u32::MAX).expect("a 64-bit target holds u32::MAX")
    }

    /// `vtls_scache.c:1163`: the 16 KiB ceiling, and the buffer's `+ 1` for the
    /// terminator curl stores -- so `SSL_TICKET_MAX - 1` bytes is the most a
    /// payload may occupy.
    #[test]
    fn a_payload_above_the_ticket_ceiling_is_too_large() {
        assert_eq!(
            session13(&vec![0_u8; SSL_TICKET_MAX], 1).pack(),
            Err(CURLcode::TooLarge)
        );

        // A ticket that leaves the payload exactly one byte under the ceiling
        // fits; one byte more does not.
        let overhead = 1 + 1 + 2 + 1 + 2 + 1 + 8;
        let fits = SSL_TICKET_MAX - overhead - 1;
        assert_eq!(
            session13(&vec![0_u8; fits], 1)
                .pack()
                .expect("it fits")
                .len(),
            SSL_TICKET_MAX - 1
        );
        assert_eq!(
            session13(&vec![0_u8; fits + 1], 1).pack(),
            Err(CURLcode::TooLarge)
        );
    }

    /// `vtls_spack.c:256-262`: the version byte is read first and any other
    /// value is `CURLE_READ_ERROR`.
    #[test]
    fn an_unknown_format_version_is_refused() {
        let mut packed = session13(b"t", 1).pack().expect("it packs");
        for wrong in [0x00_u8, 0x02, 0xFF] {
            packed[0] = wrong;
            assert_eq!(
                TlsSession::unpack(&packed),
                Err(CURLcode::ReadError),
                "version {wrong:#04x} must be refused"
            );
        }
        // And an empty input, which cannot even carry the version.
        assert_eq!(TlsSession::unpack(&[]), Err(CURLcode::ReadError));
    }

    /// `vtls_spack.c:313-315`: `default: r = CURLE_READ_ERROR;` -- an
    /// unrecognised tag is refused rather than skipped, because its payload
    /// length is unknown and skipping would desynchronise the reader.
    #[test]
    fn an_unknown_tag_is_refused() {
        for tag in [0x00_u8, 0x01, 0x08, 0x7F, 0xFF] {
            let payload = vec![SPACK_VERSION, tag, 0x00, 0x00];
            assert_eq!(
                TlsSession::unpack(&payload),
                Err(CURLcode::ReadError),
                "tag {tag:#04x} must be refused"
            );
        }
    }

    /// Truncation is a read error at every offset **except** the ones that fall
    /// exactly on a field boundary, and it never panics anywhere.
    ///
    /// The exception is the format's own property rather than a leniency: the
    /// decoder's loop is `while(buf < end)` (`vtls_spack.c:270`), so a payload
    /// that stops after a complete field is a shorter but well-formed payload,
    /// and the C returns `CURLE_OK` for it. Every other offset lands inside a
    /// tag's fixed-width value or inside a length-prefixed body, and every one
    /// of those is `CURLE_READ_ERROR`.
    #[test]
    fn truncation_is_a_read_error_everywhere_except_a_field_boundary() {
        let session = TlsSession::with_quic_tp(
            b"tk".to_vec(),
            IetfProtoVersion::TLS1_3,
            Some("h3"),
            0x0102_0304_0506_0708,
            0x0000_0100,
            Some(vec![0x11, 0x22, 0x33]),
        )
        .expect("a ticket");
        let packed = session.pack().expect("it packs");
        // 1 version + (1+2+2) ticket + (1+2) protocol + (1+8) expiry
        // + (1+2+2) ALPN + (1+4) early data + (1+2+3) QUIC = 34.
        assert_eq!(packed.len(), 34);

        // The offsets that end a field: after the version byte, then after
        // each of the six tagged fields. This exact set was read off the C
        // decoder, compiled standalone from `vtls_spack.c` and fed every
        // prefix of this same payload: it reported success at 1, 6, 9, 18, 23,
        // 28 and 34 and `CURLE_READ_ERROR` (26) at all twenty-seven others.
        let boundaries = [1_usize, 6, 9, 18, 23, 28, 34];

        // An empty input cannot even carry the version byte.
        assert_eq!(TlsSession::unpack(&[]), Err(CURLcode::ReadError));

        for cut in 1..=packed.len() {
            let outcome = TlsSession::unpack(&packed[..cut]);
            if boundaries.contains(&cut) {
                let decoded = outcome.unwrap_or_else(|error| {
                    panic!("a {cut}-byte prefix ends a field: {error:?}")
                });
                // A prefix decodes to exactly the fields it carries, so the
                // ticket appears from offset 6 and the expiry from 18.
                assert_eq!(decoded.ticket().is_empty(), cut < 6);
                assert_eq!(decoded.valid_until() != 0, cut >= 18);
                assert_eq!(decoded.alpn().is_some(), cut >= 23);
                assert_eq!(decoded.earlydata_max() != 0, cut >= 28);
                assert_eq!(decoded.quic_tp().is_some(), cut >= 34);
            } else {
                assert_eq!(
                    outcome,
                    Err(CURLcode::ReadError),
                    "a {cut}-byte prefix cuts a field and must be refused"
                );
            }
        }
    }

    /// `vtls_spack.c:153` and `:183`: a declared length naming more bytes than
    /// remain is a read error, not a panic and not a short read.
    #[test]
    fn a_length_beyond_the_input_is_a_read_error() {
        // A ticket claiming 0xFFFF bytes with one byte present.
        let payload = vec![SPACK_VERSION, SPACK_TICKET, 0xFF, 0xFF, b'a'];
        assert_eq!(TlsSession::unpack(&payload), Err(CURLcode::ReadError));

        // The same for ALPN and for the QUIC blob.
        for tag in [SPACK_ALPN, SPACK_QUICTP] {
            let payload = vec![SPACK_VERSION, tag, 0x00, 0x05, b'a', b'b'];
            assert_eq!(TlsSession::unpack(&payload), Err(CURLcode::ReadError));
        }
    }

    /// `vtls_spack.c:270-317`: tags are accepted in **any** order, because the
    /// C's `switch` inside `while(buf < end)` imposes none. A future curl may
    /// add a field, and an older reader must still cope with the ones it knows.
    #[test]
    fn tag_order_is_flexible() {
        // The exact reverse of the encoder's order, hand-assembled.
        let payload = vec![
            SPACK_VERSION,
            SPACK_QUICTP,
            0x00,
            0x01,
            0xEE,
            SPACK_EARLYDATA,
            0x00,
            0x00,
            0x00,
            0x07,
            SPACK_ALPN,
            0x00,
            0x02,
            b'h',
            b'2',
            SPACK_VALID_UNTIL,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x2A,
            SPACK_IETF_ID,
            0x03,
            0x04,
            SPACK_TICKET,
            0x00,
            0x01,
            b'T',
        ];
        let decoded = TlsSession::unpack(&payload).expect("order is flexible");
        assert_eq!(decoded.ticket(), b"T");
        assert_eq!(decoded.ietf_tls_id(), IetfProtoVersion::TLS1_3);
        assert_eq!(decoded.alpn(), Some("h2"));
        assert_eq!(decoded.valid_until(), 42);
        assert_eq!(decoded.earlydata_max(), 7);
        assert_eq!(decoded.quic_tp(), Some(&[0xEE][..]));
    }

    /// A repeated tag overwrites, which is what the C's repeated assignment
    /// into the same member does.
    #[test]
    fn a_repeated_tag_overwrites() {
        let payload = vec![
            SPACK_VERSION,
            SPACK_IETF_ID,
            0x03,
            0x03,
            SPACK_IETF_ID,
            0x03,
            0x04,
            SPACK_TICKET,
            0x00,
            0x01,
            b'a',
            SPACK_TICKET,
            0x00,
            0x01,
            b'b',
        ];
        let decoded = TlsSession::unpack(&payload).expect("it unpacks");
        assert_eq!(decoded.ietf_tls_id(), IetfProtoVersion::TLS1_3);
        assert_eq!(decoded.ticket(), b"b");
    }

    /// The C's decoder has no post-loop validation, so a payload with no
    /// ticket yields a ticketless session, and this reproduces that,
    /// including re-packing it as a zero-length ticket. The empty-ticket
    /// rejection is scoped to normal construction.
    #[test]
    fn a_payload_with_no_ticket_decodes_and_repacks() {
        let payload = vec![SPACK_VERSION, SPACK_IETF_ID, 0x03, 0x04];
        let decoded = TlsSession::unpack(&payload).expect("the C accepts this");
        assert!(decoded.ticket().is_empty());
        assert_eq!(decoded.valid_until(), 0);
        assert_eq!(decoded.alpn(), None);

        assert_eq!(
            decoded.pack().expect("it packs"),
            vec![
                0x01, 0x04, 0x00, 0x00, // a zero-length ticket
                0x02, 0x03, 0x04, //
                0x03, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );

        // Normal construction still refuses it.
        assert_eq!(
            TlsSession::new(Vec::new(), IetfProtoVersion::TLS1_3, None, 1, 0),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(
            TlsSession::with_quic_tp(
                Vec::new(),
                IetfProtoVersion::TLS1_3,
                None,
                1,
                0,
                Some(vec![1])
            ),
            Err(CURLcode::BadFunctionArgument)
        );
    }

    /// `vtls_spack.c:311`: the C casts a `u64` expiry to `curl_off_t`, which
    /// for a value above `i64::MAX` yields a negative deadline its own packer
    /// then refuses. The checked conversion says so at the boundary instead.
    #[test]
    fn an_expiry_above_the_signed_range_is_a_read_error() {
        let mut payload = vec![SPACK_VERSION, SPACK_VALID_UNTIL];
        payload.extend_from_slice(&u64::MAX.to_be_bytes());
        assert_eq!(TlsSession::unpack(&payload), Err(CURLcode::ReadError));

        // Exactly i64::MAX is accepted. Written as a checked conversion so
        // that this file carries no numeric `as` cast at all, in code or in
        // tests -- the only casts that remain are enumeration-discriminant
        // reads, which cannot lose information.
        let mut payload = vec![SPACK_VERSION, SPACK_VALID_UNTIL];
        let top = u64::try_from(i64::MAX).expect("i64::MAX is non-negative");
        payload.extend_from_slice(&top.to_be_bytes());
        let decoded = TlsSession::unpack(&payload).expect("it unpacks");
        assert_eq!(decoded.valid_until(), i64::MAX);
    }

    /// Non-UTF-8 ALPN bytes are a read error rather than a corrupted protocol
    /// name. RFC 7301 registers ALPN identifiers as ASCII tokens, so no value
    /// curl produces reaches this arm.
    #[test]
    fn a_non_utf8_alpn_is_a_read_error() {
        let payload = vec![SPACK_VERSION, SPACK_ALPN, 0x00, 0x02, 0xFF, 0xFE];
        assert_eq!(TlsSession::unpack(&payload), Err(CURLcode::ReadError));
    }

    /// The decoder never panics and never reads past its input, over an
    /// exhaustive sweep of short and adversarial payloads.
    #[test]
    fn the_decoder_is_total_over_adversarial_input() {
        // Every one- and two-byte input.
        for first in 0..=u8::MAX {
            let _ = TlsSession::unpack(&[first]);
            for second in 0..=u8::MAX {
                let _ = TlsSession::unpack(&[first, second]);
            }
        }
        // Every tag followed by every one-byte remainder.
        for tag in 0..=u8::MAX {
            for byte in 0..=u8::MAX {
                let _ = TlsSession::unpack(&[SPACK_VERSION, tag, byte]);
            }
        }
        // A maximal declared length against a minimal body, for each
        // length-prefixed tag.
        for tag in [SPACK_TICKET, SPACK_ALPN, SPACK_QUICTP] {
            for len in [0x0000_u16, 0x0001, 0x00FF, 0xFFFF] {
                let mut payload = vec![SPACK_VERSION, tag];
                payload.extend_from_slice(&len.to_be_bytes());
                let _ = TlsSession::unpack(&payload);
                payload.push(0x41);
                let _ = TlsSession::unpack(&payload);
            }
        }
    }

    /// [`TlsSession::pack_into`] appends to a caller's buffer, which is how
    /// `Curl_ssl_session_export` reuses one `sbuf` across every session
    /// (`vtls_scache.c:1192-1193`).
    #[test]
    fn pack_into_appends_to_a_reused_buffer() {
        let mut buf = DynBuf::new(SSL_TICKET_MAX);
        let first = session13(b"1", 1);
        let second = session13(b"2", 1);

        first.pack_into(&mut buf).expect("it packs");
        assert_eq!(buf.as_slice(), first.pack().expect("it packs").as_slice());

        // Reset, as the C does before each session, and the buffer is reusable.
        buf.reset();
        second.pack_into(&mut buf).expect("it packs");
        assert_eq!(buf.as_slice(), second.pack().expect("it packs").as_slice());

        // Without a reset it appends, which is what "into" means.
        first.pack_into(&mut buf).expect("it packs");
        assert_eq!(
            buf.len(),
            second.pack().expect("it packs").len()
                + first.pack().expect("it packs").len()
        );
    }

    /// [`TlsSession::reused`] carries exactly the two facts
    /// `Curl_on_session_reuse` reads (`lib/vtls/vtls.c:2071-2099`).
    #[test]
    fn a_session_reports_what_the_reuse_decision_needs() {
        let session = TlsSession::new(
            b"t".to_vec(),
            IetfProtoVersion::TLS1_3,
            Some("h2"),
            1,
            8_192,
        )
        .expect("a ticket");
        assert_eq!(
            session.reused(),
            ReusedSession {
                alpn: Some(String::from("h2")),
                earlydata_max: 8_192,
            }
        );

        let bare = session13(b"t", 1);
        assert_eq!(bare.reused(), ReusedSession::default());
    }

    /// The version constants come from the whitelisted digest module, so a
    /// change there cannot leave this module claiming 32 bytes of something
    /// else.
    #[test]
    fn the_salt_and_code_lengths_follow_the_digest_module() {
        assert_eq!(SALT_LEN, DIGEST_LEN);
        assert_eq!(HMAC_LEN, DIGEST_LEN);
        assert_eq!(DIGEST_LEN, 32);
        assert_eq!(SHMAC_LEN, SALT_LEN + HMAC_LEN);
    }

    // ---------------------------------------------------------------- keys

    /// The shortest key curl can produce: host, port, implementation, global.
    #[test]
    fn a_minimal_peer_key_is_host_port_impl_and_the_global_suffix() {
        let key = peer_key_build(
            "example.com",
            443,
            TRNSPRT_TCP,
            &PeerKeyConfig::default(),
            "rustls/0.23.42",
        )
        .expect("a minimal key fits");
        assert_eq!(key, "example.com:443:IMPL-rustls/0.23.42:G");
    }

    /// `vtls_scache.c:156-171`: TCP adds nothing and every other transport
    /// adds its own fragment, with the `default:` arm printing the integer.
    #[test]
    fn each_transport_adds_exactly_the_c_fragment() {
        let config = PeerKeyConfig::default();
        let build = |transport: u8| {
            peer_key_build("h", 1, transport, &config, "i")
                .expect("a short key fits")
        };
        assert_eq!(build(TRNSPRT_TCP), "h:1:IMPL-i:G");
        assert_eq!(build(TRNSPRT_UDP), "h:1:UDP:IMPL-i:G");
        assert_eq!(build(TRNSPRT_QUIC), "h:1:QUIC:IMPL-i:G");
        assert_eq!(build(TRNSPRT_UNIX), "h:1:UNIX:IMPL-i:G");
        // `TRNSPRT_NONE` is 0 and the C's switch does not name it, so it
        // reaches `default:` -- which is what a `file://` transfer keys as.
        assert_eq!(build(0), "h:1:TRNSPRT-0:IMPL-i:G");
        // The two retired values, 1 and 2, and one beyond the table.
        assert_eq!(build(1), "h:1:TRNSPRT-1:IMPL-i:G");
        assert_eq!(build(2), "h:1:TRNSPRT-2:IMPL-i:G");
        assert_eq!(build(9), "h:1:TRNSPRT-9:IMPL-i:G");
    }

    /// `vtls_scache.c:175-189`: the three verification fragments, in order.
    #[test]
    fn the_verification_fragments_appear_in_the_c_order() {
        let config = PeerKeyConfig {
            verifypeer: false,
            verifyhost: false,
            verifystatus: true,
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(key, "h:1:NO-VRFY-PEER:NO-VRFY-HOST:VRFY-STATUS:IMPL-i:G");
    }

    /// `vtls_scache.c:190-201`: `--connect-to` enters the key only when a
    /// verification flag is off, because otherwise the certificate binds the
    /// session to the origin name.
    #[test]
    fn connect_to_overrides_enter_the_key_only_when_verification_is_off() {
        let with_override = |verifypeer: bool, verifyhost: bool| {
            let config = PeerKeyConfig {
                verifypeer,
                verifyhost,
                conn_to_host: Some("other.example"),
                conn_to_port: Some(8443),
                ..PeerKeyConfig::default()
            };
            peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
                .expect("a short key fits")
        };

        // Both on: the override is absent.
        assert_eq!(with_override(true, true), "h:1:IMPL-i:G");
        // Peer verification off.
        assert_eq!(
            with_override(false, true),
            "h:1:NO-VRFY-PEER:CHOST-other.example:CPORT-8443:IMPL-i:G"
        );
        // Host verification off.
        assert_eq!(
            with_override(true, false),
            "h:1:NO-VRFY-HOST:CHOST-other.example:CPORT-8443:IMPL-i:G"
        );
    }

    /// `vtls_scache.c:203-228`: the five configuration fragments, in order,
    /// with the maximum version shifted down by 16 and the options in hex.
    #[test]
    fn the_tls_configuration_fragments_are_exact() {
        let config = PeerKeyConfig {
            version: 6,
            version_max: 7 << 16,
            ssl_options: 0x2b,
            cipher_list: Some("AES"),
            cipher_list13: Some("TLS_AES_128_GCM_SHA256"),
            curves: Some("X25519"),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(
            key,
            "h:1:TLSVER-6-7:TLSOPT-2b:CIPHER-AES\
             :CIPHER13-TLS_AES_128_GCM_SHA256:CURVES-X25519:IMPL-i:G"
        );
    }

    /// `vtls_scache.c:203`: `if(ssl->version || ssl->version_max)` -- a
    /// maximum alone is enough, and the minimum then prints as zero.
    #[test]
    fn a_version_maximum_alone_still_emits_the_version_fragment() {
        let config = PeerKeyConfig {
            version_max: 1 << 16,
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(key, "h:1:TLSVER-0-1:IMPL-i:G");
    }

    /// `vtls_scache.c:229-257`: the trust material is inside
    /// `if(ssl->verifypeer)`, so with peer verification off none of it
    /// distinguishes peers.
    #[test]
    fn the_trust_material_is_omitted_when_peer_verification_is_off() {
        let config = PeerKeyConfig {
            verifypeer: false,
            ca_file: Some("/etc/ssl/certs/ca.pem"),
            ca_path: Some("/etc/ssl/certs"),
            crl_file: Some("/etc/ssl/crl.pem"),
            issuer_cert: Some("/etc/ssl/issuer.pem"),
            cert_blob: Some(b"cert"),
            ca_info_blob: Some(b"cainfo"),
            issuer_cert_blob: Some(b"issuer"),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(key, "h:1:NO-VRFY-PEER:IMPL-i:G");
    }

    /// `vtls_scache.c:230-241`: the four path labels, in order, with absolute
    /// paths passed through unchanged and the key still global.
    #[test]
    fn absolute_trust_paths_pass_through_and_keep_the_key_global() {
        let config = PeerKeyConfig {
            ca_file: Some("/ca.pem"),
            ca_path: Some("/certs"),
            crl_file: Some("/crl.pem"),
            issuer_cert: Some("/issuer.pem"),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(
            key,
            "h:1:CA-/ca.pem:CApath-/certs:CRL-/crl.pem\
             :Issuer-/issuer.pem:IMPL-i:G"
        );
    }

    /// `vtls_scache.c:75`: `if(path && path[0])` -- an empty path adds no
    /// fragment and does not make the key local.
    #[test]
    fn an_empty_trust_path_adds_nothing() {
        let config = PeerKeyConfig {
            ca_file: Some(""),
            ca_path: None,
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(key, "h:1:IMPL-i:G");
    }

    /// `vtls_scache.c:86-95`: a relative path that resolves is emitted
    /// **absolute**, and the key stays global -- which is what makes the peer
    /// exportable.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir and realpath")]
    fn a_resolvable_relative_path_is_canonicalised_and_stays_global() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let file = dir.path().join("ca.pem");
        std::fs::write(&file, b"x").expect("the file is writable");
        let cwd = std::env::current_dir().expect("a working directory");
        // The C decides on `path[0] != '/'`, so the path handed in must be
        // relative for the resolution branch to be taken at all.
        let relative = pathdiff_relative(&file, &cwd);

        let config = PeerKeyConfig {
            ca_file: Some(&relative),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");

        let expected = std::fs::canonicalize(&file)
            .expect("the file resolves")
            .to_str()
            .expect("the temporary path is UTF-8")
            .to_string();
        assert_eq!(key, format!("h:1:CA-{expected}:IMPL-i:G"));
        assert!(peer_key_is_global(&key));
        assert!(!key.contains(&relative));
    }

    /// `vtls_scache.c:94`: a relative path that does **not** resolve is
    /// emitted as given and the key becomes local, so the peer can never be
    /// exported.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses realpath")]
    fn an_unresolvable_relative_path_makes_the_key_local() {
        let config = PeerKeyConfig {
            ca_file: Some("no/such/ca.pem"),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(key, "h:1:CA-no/such/ca.pem:IMPL-i:L");
        assert!(!peer_key_is_global(&key));
        assert!(key.ends_with(LOCAL_SUFFIX));
    }

    /// One unresolvable path among several resolvable ones still makes the
    /// whole key local: the C threads one `bool *is_local` through all four
    /// calls.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses realpath")]
    fn one_unresolvable_path_makes_the_whole_key_local() {
        let config = PeerKeyConfig {
            ca_file: Some("/ca.pem"),
            crl_file: Some("no/such/crl.pem"),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(key, "h:1:CA-/ca.pem:CRL-no/such/crl.pem:IMPL-i:L");
    }

    /// `vtls_scache.c:102-125`: a blob becomes 64 lowercase hex digits of its
    /// SHA-256, under the three C label names, and the blob itself never
    /// appears in the key.
    #[test]
    fn blobs_are_hashed_to_lowercase_hex_under_the_c_labels() {
        let config = PeerKeyConfig {
            cert_blob: Some(b"cert-bytes"),
            ca_info_blob: Some(b"cainfo-bytes"),
            issuer_cert_blob: Some(b"issuer-bytes"),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");

        let hex = |blob: &[u8]| {
            sha256(blob)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            key,
            format!(
                "h:1:CertBlob-{}:CAInfoBlob-{}:IssuerBlob-{}:IMPL-i:G",
                hex(b"cert-bytes"),
                hex(b"cainfo-bytes"),
                hex(b"issuer-bytes"),
            )
        );
        // The blob bytes are absent, and every hex digit is lowercase --
        // `%02x`, not `%02X`. A key is compared as a string, so the wrong
        // case would be a different peer and every session would be missed.
        assert!(!key.contains("cert-bytes"));
        assert!(!key.contains("cainfo-bytes"));
        assert!(!key.contains("issuer-bytes"));
        assert!(key
            .chars()
            .all(|ch| !ch.is_ascii_uppercase() || "CABIMPLIG".contains(ch)));
    }

    /// `vtls_scache.c:107`: `if(blob && blob->len)` -- an empty blob produces
    /// no fragment rather than the digest of the empty input.
    #[test]
    fn an_empty_blob_is_not_hashed() {
        let config = PeerKeyConfig {
            cert_blob: Some(&[]),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(key, "h:1:IMPL-i:G");
    }

    /// `vtls_scache.c:258-268`: both fragments sit **outside** the
    /// verification block, so they apply even with verification off, and both
    /// require a non-empty string.
    #[test]
    fn pinned_key_and_client_certificate_apply_regardless_of_verification() {
        let config = PeerKeyConfig {
            verifypeer: false,
            verifyhost: false,
            pinned_key: Some("sha256//abc="),
            clientcert: Some("/client.pem"),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert_eq!(
            key,
            "h:1:NO-VRFY-PEER:NO-VRFY-HOST:Pinned-sha256//abc=:CCERT\
             :IMPL-i:G"
        );

        // Empty strings add nothing, which is the C's `if(x && x[0])`.
        let empty = PeerKeyConfig {
            pinned_key: Some(""),
            clientcert: Some(""),
            ..PeerKeyConfig::default()
        };
        assert_eq!(
            peer_key_build("h", 1, TRNSPRT_TCP, &empty, "i")
                .expect("a short key fits"),
            "h:1:IMPL-i:G"
        );
    }

    /// The client certificate's *path* never reaches the key -- only the fact
    /// that one is set. The value is still compared, through [`ClientAuth`].
    #[test]
    fn the_client_certificate_path_is_withheld_from_the_key() {
        let config = PeerKeyConfig {
            clientcert: Some("/home/user/secret-identity.pem"),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert!(key.contains(":CCERT"));
        assert!(!key.contains("secret-identity"));
    }

    /// No SRP marker is ever emitted, because this build has no SRP. The C's
    /// `:SRP-AUTH` fragment is `#ifdef USE_TLS_SRP`.
    #[test]
    fn no_srp_fragment_is_ever_emitted() {
        let config = PeerKeyConfig {
            clientcert: Some("/client.pem"),
            pinned_key: Some("p"),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a short key fits");
        assert!(!key.contains("SRP"));
    }

    /// `vtls_scache.c:277-283`: an empty implementation token is
    /// `CURLE_FAILED_INIT`, and the token is otherwise embedded verbatim so
    /// two versions of one library do not share sessions.
    #[test]
    fn an_empty_implementation_token_is_refused() {
        let config = PeerKeyConfig::default();
        assert_eq!(
            peer_key_build("h", 1, TRNSPRT_TCP, &config, ""),
            Err(CURLcode::FailedInit)
        );
        assert!(
            peer_key_build("h", 1, TRNSPRT_TCP, &config, "rustls/0.23.42")
                .expect("a short key fits")
                .contains(":IMPL-rustls/0.23.42:")
        );
    }

    /// `vtls_scache.c:150`: the key is bounded at 10 KiB, and crossing the
    /// bound is `CURLE_TOO_LARGE`.
    #[test]
    fn the_peer_key_is_bounded_at_ten_kibibytes() {
        let huge = "c".repeat(PEER_KEY_MAX);
        let config = PeerKeyConfig {
            cipher_list: Some(&huge),
            ..PeerKeyConfig::default()
        };
        assert_eq!(
            peer_key_build("h", 1, TRNSPRT_TCP, &config, "i"),
            Err(CURLcode::TooLarge)
        );

        // Just inside the bound still succeeds. The buffer's ceiling counts
        // the terminator curl stores, so it admits `PEER_KEY_MAX - 1` bytes.
        let fits = "c".repeat(PEER_KEY_MAX - 64);
        let config = PeerKeyConfig {
            cipher_list: Some(&fits),
            ..PeerKeyConfig::default()
        };
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, "i")
            .expect("a key just inside the bound fits");
        assert!(key.len() < PEER_KEY_MAX);
    }

    /// The ceiling is enforced at **every** append, not only at the first
    /// oversized one, so an overflow that first bites on a late fragment is
    /// still reported rather than silently truncating the key.
    ///
    /// The boundary is computed from the parts rather than written as a
    /// literal, because the buffer admits `PEER_KEY_MAX - 1` bytes -- it counts
    /// the terminator curl stores and this crate does not -- and a literal
    /// would encode that off-by-one invisibly.
    #[test]
    fn the_peer_key_ceiling_is_enforced_on_late_fragments_too() {
        // Fill most of the budget with an early fragment, then vary the
        // implementation token, which is the second-to-last thing written.
        let bulk = "c".repeat(PEER_KEY_MAX - 200);
        let config = PeerKeyConfig {
            cipher_list: Some(&bulk),
            ..PeerKeyConfig::default()
        };

        // "h:1" + ":CIPHER-" + bulk + ":IMPL-" + token + ":G"
        let fixed = "h:1".len()
            + ":CIPHER-".len()
            + bulk.len()
            + ":IMPL-".len()
            + GLOBAL_SUFFIX.len();
        let headroom = PEER_KEY_MAX - 1 - fixed;

        // Exactly filling the budget, suffix included, succeeds.
        let token = "i".repeat(headroom);
        let key = peer_key_build("h", 1, TRNSPRT_TCP, &config, &token)
            .expect("a key that exactly fills the budget is accepted");
        assert_eq!(key.len(), PEER_KEY_MAX - 1);
        assert!(key.ends_with(GLOBAL_SUFFIX));

        // One byte more overflows -- and it overflows on `:IMPL-`, long after
        // the first append, which is the point of this test.
        let token = "i".repeat(headroom + 1);
        assert_eq!(
            peer_key_build("h", 1, TRNSPRT_TCP, &config, &token),
            Err(CURLcode::TooLarge)
        );

        // A token that leaves room for `:IMPL-` but not for the `:G` suffix
        // fails on that very last append.
        let token = "i".repeat(headroom + GLOBAL_SUFFIX.len() - 1);
        assert_eq!(
            peer_key_build("h", 1, TRNSPRT_TCP, &config, &token),
            Err(CURLcode::TooLarge)
        );

        // Overflowing much later still reports the same code.
        let token = "i".repeat(PEER_KEY_MAX);
        assert_eq!(
            peer_key_build("h", 1, TRNSPRT_TCP, &config, &token),
            Err(CURLcode::TooLarge)
        );
    }

    /// Every fragment, in the C's order, in one key -- the integration
    /// assertion that catches a reordering no single-fragment test would.
    #[test]
    fn the_full_fragment_order_matches_the_c_exactly() {
        let config = PeerKeyConfig {
            verifypeer: false,
            verifyhost: false,
            verifystatus: true,
            conn_to_host: Some("ch"),
            conn_to_port: Some(81),
            version: 6,
            version_max: 7 << 16,
            ssl_options: 0xff,
            cipher_list: Some("CL"),
            cipher_list13: Some("C13"),
            curves: Some("CV"),
            // Inside the verification block, which is closed here, so these
            // must NOT appear.
            ca_file: Some("/ca"),
            cert_blob: Some(b"blob"),
            pinned_key: Some("PK"),
            clientcert: Some("CC"),
            ..PeerKeyConfig::default()
        };
        let key =
            peer_key_build("host", 443, TRNSPRT_QUIC, &config, "impl/1.0")
                .expect("a short key fits");
        assert_eq!(
            key,
            "host:443:QUIC:NO-VRFY-PEER:NO-VRFY-HOST:VRFY-STATUS\
             :CHOST-ch:CPORT-81:TLSVER-6-7:TLSOPT-ff:CIPHER-CL:CIPHER13-C13\
             :CURVES-CV:Pinned-PK:CCERT:IMPL-impl/1.0:G"
        );
    }

    /// `cf_ssl_peer_key_is_global` (`vtls_scache.c:130-136`), including the
    /// `len > 2` guard that rejects the bare suffix.
    #[test]
    fn the_global_suffix_test_matches_the_c_including_its_length_guard() {
        assert!(peer_key_is_global("h:1:IMPL-i:G"));
        assert!(!peer_key_is_global("h:1:IMPL-i:L"));
        // len == 2: identifies nothing, so not global.
        assert!(!peer_key_is_global(":G"));
        // len == 3 is the shortest key the C accepts as global.
        assert!(peer_key_is_global("a:G"));
        assert!(!peer_key_is_global(""));
        assert!(!peer_key_is_global("G"));
        // The colon must be there.
        assert!(!peer_key_is_global("abcG"));
        // Case matters: the C compares the character 'G'.
        assert!(!peer_key_is_global("h:1:g"));
    }

    /// [`peer_key_make`] reads the host, port and transport off the peer, and
    /// the result is what [`crate::tls::SslPeer::set_scache_key`] is for.
    ///
    /// `crate::conn::filters::Transport` is imported here and nowhere else in
    /// this file: it is a parameter of `SslPeer::new`, which belongs to the
    /// declared dependency `tls/mod.rs`, and there is no other way to build a
    /// peer. Production code reads the transport through the accessor instead,
    /// so the module itself needs no such import.
    #[test]
    fn peer_key_make_reads_the_peer_and_feeds_set_scache_key() {
        use crate::conn::filters::Transport;

        let mut peer = SslPeer::new(
            "example.com",
            None,
            8443,
            Transport::Quic,
            String::new(),
        )
        .expect("a named peer is accepted");
        assert_eq!(peer.scache_key(), "");

        let key =
            peer_key_make(&peer, &PeerKeyConfig::default(), "rustls/0.23.42")
                .expect("a short key fits");
        assert_eq!(key, "example.com:8443:QUIC:IMPL-rustls/0.23.42:G");

        peer.set_scache_key(key.clone());
        assert_eq!(peer.scache_key(), key);
    }

    // ------------------------------------------- selection and locking

    /// A lock that records what was asked of it, in order.
    ///
    /// The share subsystem's real implementation will call the application's
    /// `CURLSHOPT_LOCKFUNC`; this one records, which is what lets the *shape*
    /// of the locking be asserted -- that a local cache is never locked, that
    /// a shared one is always unlocked, and that the access requested is
    /// exclusive.
    #[derive(Debug, Default)]
    struct RecordingLock {
        events: RefCell<Vec<String>>,
    }

    impl RecordingLock {
        fn events(&self) -> Vec<String> {
            self.events.borrow().clone()
        }
    }

    impl ScacheLock for RecordingLock {
        fn lock(&self, access: LockAccess) {
            self.events.borrow_mut().push(format!("lock({access:?})"));
        }

        fn unlock(&self) {
            self.events.borrow_mut().push(String::from("unlock"));
        }
    }

    /// `cf_ssl_scache_get` (`vtls_scache.c:310-314`): "If a share is present,
    /// its ssl_scache has preference over the multi".
    #[test]
    fn a_shared_cache_takes_precedence_over_the_local_one() {
        let mut shared = SessionCache::new(4, 2);
        shared.set_default_lifetime_secs(11);
        let mut local = SessionCache::new(4, 2);
        local.set_default_lifetime_secs(22);

        let selected = select_cache(Some(&mut shared), Some(&mut local))
            .expect("a cache is present");
        assert_eq!(selected.origin(), CacheOrigin::Shared);
        assert_eq!(selected.into_inner().default_lifetime_secs(), 11);
    }

    /// The `else if(data->multi && data->multi->ssl_scache)` arm.
    #[test]
    fn the_local_cache_is_used_when_no_share_supplies_one() {
        let mut local = SessionCache::new(4, 2);
        local.set_default_lifetime_secs(22);

        let selected =
            select_cache(None, Some(&mut local)).expect("a cache is present");
        assert_eq!(selected.origin(), CacheOrigin::Local);
        assert_eq!(selected.into_inner().default_lifetime_secs(), 22);
    }

    /// Neither present is the C's `scache == NULL`, which every caller treats
    /// as "no caching" rather than as an error.
    #[test]
    fn no_cache_at_all_selects_nothing() {
        assert!(select_cache(None, None).is_none());
    }

    /// `Curl_ssl_scache_lock` (`vtls_scache.c:585-589`): a **shared** cache is
    /// locked for exclusive access, and [`ScacheGuard`] releases it at the end
    /// of the scope.
    #[test]
    fn a_shared_cache_is_locked_exclusively_and_unlocked_on_drop() {
        let mut shared = SessionCache::new(4, 2);
        let lock = RecordingLock::default();

        {
            let selected =
                select_cache(Some(&mut shared), None).expect("a cache");
            let mut guard = selected.acquire(&lock);
            assert_eq!(lock.events(), vec![String::from("lock(Single)")]);
            // The guard is the cache, through Deref.
            assert_eq!(guard.peer_count(), 4);
            guard.set_default_lifetime_secs(5);
        }

        assert_eq!(
            lock.events(),
            vec![String::from("lock(Single)"), String::from("unlock")]
        );
        assert_eq!(shared.default_lifetime_secs(), 5);
    }

    /// `if(CURL_SHARE_ssl_scache(data))` -- a multi handle's own cache is
    /// never locked at all, so neither call is made.
    #[test]
    fn a_local_cache_is_never_locked() {
        let mut local = SessionCache::new(4, 2);
        let lock = RecordingLock::default();

        {
            let selected = select_cache(None, Some(&mut local)).expect("cache");
            let _guard = selected.acquire(&lock);
        }

        assert!(lock.events().is_empty());
    }

    /// The point of the guard: the C needs a `bool locked` and a `goto out` to
    /// unlock on all nine exit paths of `Curl_ssl_session_import`
    /// (`:1079`, `:1096`, `:1137-1138`). Here an early `?` return unlocks.
    #[test]
    fn the_guard_unlocks_on_an_error_path_too() {
        let mut shared = SessionCache::new(4, 2);
        let lock = RecordingLock::default();

        let outcome: Result<(), CURLcode> = (|| {
            let selected =
                select_cache(Some(&mut shared), None).expect("a cache");
            let mut guard = selected.acquire(&lock);
            // A malformed import, propagated with `?` from inside the scope.
            guard.import(&clock_at(0), Some("k"), None, &[0xFF])?;
            Ok(())
        })();

        assert_eq!(outcome, Err(CURLcode::ReadError));
        assert_eq!(
            lock.events(),
            vec![String::from("lock(Single)"), String::from("unlock")]
        );
    }

    /// `Curl_ssl_scache_get_obj` (`:947-970`) reads without locking, and the
    /// header says the caller is expected to hold the lock across such a call.
    #[test]
    fn into_inner_takes_no_lock() {
        let mut shared = SessionCache::new(4, 2);
        let lock = RecordingLock::default();
        let selected = select_cache(Some(&mut shared), None).expect("a cache");
        let cache = selected.into_inner();
        assert_eq!(cache.peer_count(), 4);
        assert!(lock.events().is_empty());
    }

    /// The `curl_lock_access` integers an application compiled against curl
    /// 8.19.0-DEV holds (`include/curl/curl.h:3043-3048`).
    #[test]
    fn the_lock_access_values_are_the_public_enumeration_values() {
        assert_eq!(LockAccess::None as i32, 0);
        assert_eq!(LockAccess::Shared as i32, 1);
        assert_eq!(LockAccess::Single as i32, 2);
    }

    /// [`NoLock`] is the "cache is not shared" case as a value: it does
    /// nothing, and it is usable through the trait object the seam is written
    /// against, so a caller with no share can hand it in unconditionally.
    #[test]
    fn the_no_op_lock_does_nothing_and_is_object_safe() {
        let lock: &dyn ScacheLock = &NoLock;
        lock.lock(LockAccess::Single);
        lock.unlock();

        let mut shared = SessionCache::new(1, 1);
        {
            let selected =
                select_cache(Some(&mut shared), None).expect("a cache");
            // Shared origin, so the seam IS exercised -- and still nothing
            // happens, because this implementation does nothing.
            let guard = selected.acquire(lock);
            assert_eq!(guard.peer_count(), 1);
        }
        assert_eq!(shared.peer_count(), 1);
    }

    /// `Curl_ssl_scache_use` (`vtls_scache.c:575-582`): both conjuncts.
    #[test]
    fn caching_requires_a_cache_and_the_option() {
        let cache = SessionCache::new(4, 2);
        assert!(scache_use(Some(&cache), SessionCaching::ENABLED));
        assert!(!scache_use(Some(&cache), SessionCaching::DISABLED));
        assert!(!scache_use(None, SessionCaching::ENABLED));
        assert!(!scache_use(None, SessionCaching::DISABLED));
    }

    /// `data->set.ssl.primary.cache_session = TRUE; /* caching by default */`
    /// (`lib/vtls/vtls.c:189`).
    #[test]
    fn session_caching_defaults_to_enabled() {
        assert_eq!(SessionCaching::default(), SessionCaching::ENABLED);
        assert!(SessionCaching::default().is_enabled());
        assert!(SessionCaching::from_bool(true).is_enabled());
        assert!(!SessionCaching::from_bool(false).is_enabled());
    }

    // ------------------------------------------------ time and lifetimes

    /// The two ceilings, as `vtls_scache.h:41-42` writes them.
    #[test]
    fn the_lifetime_ceilings_are_the_header_values() {
        assert_eq!(MAX_13_LIFETIME_SEC, 604_800);
        assert_eq!(MAX_13_LIFETIME_SEC, 60 * 60 * 24 * 7);
        assert_eq!(MAX_12_LIFETIME_SEC, 86_400);
        assert_eq!(MAX_12_LIFETIME_SEC, 60 * 60 * 24);
        assert_eq!(DEFAULT_LIFETIME_SEC, 24 * 60 * 60);
    }

    /// `vtls_scache.c:797-798`: an unknown expiry becomes one day from now.
    /// Both zero and a negative value are "unknown", because the C tests
    /// `<= 0`.
    #[test]
    fn an_unknown_expiry_becomes_one_day_from_now() {
        let clock = clock_at(1_000_000);
        for stated in [0_i64, -1, i64::MIN] {
            let mut cache = SessionCache::new(2, 4);
            assert!(cache.put(
                &clock,
                SessionCaching::ENABLED,
                "k",
                None,
                session13(b"t", stated),
            ));
            assert_eq!(
                stored_validities(&cache, "k"),
                vec![1_000_000 + DEFAULT_LIFETIME_SEC]
            );
        }
    }

    /// `vtls_scache.c:800-804`: a TLS 1.3 ticket is held to seven days.
    #[test]
    fn a_tls13_ticket_is_clamped_to_seven_days() {
        let clock = clock_at(1_000_000);
        let mut cache = SessionCache::new(2, 4);
        // A year out.
        assert!(cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"t", 1_000_000 + 31_536_000),
        ));
        assert_eq!(
            stored_validities(&cache, "k"),
            vec![1_000_000 + MAX_13_LIFETIME_SEC]
        );
    }

    /// The same ceiling, one second under, is left alone: the C's test is
    /// `if(s->valid_until > (now + max_lifetime))`.
    #[test]
    fn an_expiry_inside_the_ceiling_is_left_untouched() {
        let clock = clock_at(1_000_000);
        let mut cache = SessionCache::new(2, 4);
        let exact = 1_000_000 + MAX_13_LIFETIME_SEC;
        assert!(cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"t", exact),
        ));
        assert_eq!(stored_validities(&cache, "k"), vec![exact]);
    }

    /// `vtls_scache.c:800-802`: anything below TLS 1.3 gets the one-day
    /// ceiling, which is the shorter of the two.
    #[test]
    fn a_pre_tls13_session_is_clamped_to_one_day() {
        let clock = clock_at(1_000_000);
        let mut cache = SessionCache::new(2, 4);
        assert!(cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session12(b"t", 1_000_000 + 31_536_000),
        ));
        assert_eq!(
            stored_validities(&cache, "k"),
            vec![1_000_000 + MAX_12_LIFETIME_SEC]
        );
    }

    /// `cf_scache_session_expired` (`vtls_scache.c:499-503`): both halves,
    /// including that the comparison is strict so "expires exactly now" is
    /// still live, and that a non-positive expiry never expires.
    #[test]
    fn the_expiry_test_matches_the_c_exactly() {
        let session = session13(b"t", 100);
        assert!(!session.expired(99));
        assert!(!session.expired(100));
        assert!(session.expired(101));

        let unknown = session13(b"t", 0);
        assert!(!unknown.expired(i64::MAX));
        let negative = session13(b"t", -5);
        assert!(!negative.expired(i64::MAX));
    }

    /// `vtls_scache.c:806-810`: a session that is expired after clamping is
    /// discarded silently and the call still succeeds.
    #[test]
    fn an_already_expired_session_is_discarded_silently() {
        let clock = clock_at(1_000_000);
        let mut cache = SessionCache::new(2, 4);
        cache.set_default_lifetime_secs(-10);
        // With a negative default lifetime the defaulted expiry lands in the
        // past, which is the only way the C's own check can fire.
        assert!(!cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"t", 0),
        ));
        assert_eq!(cache.session_count("k", None), None);
    }

    /// `vtls_scache.c:846-849`: caching disabled discards the session.
    #[test]
    fn caching_disabled_discards_the_session() {
        let clock = clock_at(0);
        let mut cache = SessionCache::new(2, 4);
        assert!(!cache.put(
            &clock,
            SessionCaching::DISABLED,
            "k",
            None,
            session13(b"t", 0),
        ));
        assert_eq!(cache.session_count("k", None), None);
    }

    /// `vtls_scache.c:792-795`: a cache with no slots accepts nothing, and
    /// reports success while doing so.
    #[test]
    fn a_cache_with_no_slots_accepts_nothing() {
        let clock = clock_at(0);
        let mut cache = SessionCache::new(0, 4);
        assert!(cache.is_empty());
        assert!(!cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"t", 0),
        ));
        assert!(cache.take(&clock, "k", None).is_none());
    }

    /// `vtls_scache.c:890`: expired entries are swept before the head is
    /// taken, so a stale ticket is never handed out.
    #[test]
    fn take_sweeps_expired_entries_before_yielding_one() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"early", 2_000),
        );
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"late", 9_000),
        );
        assert_eq!(cache.session_count("k", None), Some(2));

        // Move past the first ticket's expiry but not the second's.
        let later = clock_at(5_000);
        let taken = cache
            .take(&later, "k", None)
            .expect("the live ticket is available");
        assert_eq!(taken.ticket(), b"late");
        assert_eq!(cache.session_count("k", None), Some(0));
    }

    /// A peer whose every ticket has expired yields nothing, and the sweep
    /// leaves the slot empty rather than holding dead entries.
    #[test]
    fn a_peer_with_only_expired_tickets_yields_nothing() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"t", 2_000),
        );
        let later = clock_at(9_999);
        assert!(cache.take(&later, "k", None).is_none());
        assert_eq!(cache.session_count("k", None), Some(0));
    }

    /// `vtls_scache.c:894-895`: a successful take bumps the cache age and
    /// stamps it on the peer, which is what keeps that peer out of the
    /// eviction path.
    #[test]
    fn a_successful_take_bumps_the_age_and_stamps_the_peer() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        assert_eq!(cache.age(), 1);
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"t", 9_000),
        );
        assert_eq!(cache.age(), 1);

        assert!(cache.take(&clock, "k", None).is_some());
        assert_eq!(cache.age(), 2);
        let peer = cache
            .peers
            .iter()
            .find(|peer| peer.matches_key("k", None))
            .expect("the peer is present");
        assert_eq!(peer.age, 2);
    }

    /// A miss moves neither counter, so asking about a peer does not defend it
    /// against eviction.
    #[test]
    fn a_missed_take_moves_no_counter() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        assert!(cache.take(&clock, "absent", None).is_none());
        assert_eq!(cache.age(), 1);
    }

    /// `cf_ssl_get_free_peer` tier one (`vtls_scache.c:693-696`): a free slot
    /// is taken before anything is evicted.
    #[test]
    fn a_free_slot_is_taken_before_anything_is_evicted() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(3, 4);
        for key in ["a", "b"] {
            cache.put(
                &clock,
                SessionCaching::ENABLED,
                key,
                None,
                session13(b"t", 9_000),
            );
            // Give each peer a distinct age so an LRU choice would be visible.
            cache.take(&clock, key, None).map(|session| {
                cache.put(&clock, SessionCaching::ENABLED, key, None, session)
            });
        }
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "c",
            None,
            session13(b"t", 9_000),
        );

        // All three are present: nothing was evicted.
        for key in ["a", "b", "c"] {
            assert_eq!(cache.session_count(key, None), Some(1), "{key}");
        }
    }

    /// `cf_ssl_get_free_peer` tier two (`vtls_scache.c:697-702`): an occupied
    /// slot holding no sessions is reused before the least recently used one.
    #[test]
    fn a_slot_with_no_sessions_is_reused_before_the_oldest() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        // Slot 0 keeps a session; slot 1 is emptied by taking its only one.
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "keeps",
            None,
            session13(b"t", 9_000),
        );
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "empties",
            None,
            session13(b"t", 9_000),
        );
        assert!(cache.take(&clock, "empties", None).is_some());

        // A third peer must take the emptied slot, not evict "keeps" -- even
        // though "empties" has the *higher* age, because the session-count
        // test comes first and breaks out.
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "third",
            None,
            session13(b"t", 9_000),
        );
        assert_eq!(cache.session_count("keeps", None), Some(1));
        assert_eq!(cache.session_count("third", None), Some(1));
        assert_eq!(cache.session_count("empties", None), None);
    }

    /// `cf_ssl_get_free_peer` tier three (`vtls_scache.c:703-706`): with every
    /// slot occupied and non-empty, the least recently used one goes.
    #[test]
    fn the_least_recently_used_peer_is_evicted_when_every_slot_is_busy() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        for key in ["old", "new"] {
            cache.put(
                &clock,
                SessionCaching::ENABLED,
                key,
                None,
                session13(b"t", 9_000),
            );
        }
        // Use "old" first, then "new", so "new" carries the higher stamp. Both
        // are refilled so neither slot is empty.
        for key in ["old", "new"] {
            let session = cache
                .take(&clock, key, None)
                .expect("each peer has a session");
            cache.put(&clock, SessionCaching::ENABLED, key, None, session);
        }

        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "third",
            None,
            session13(b"t", 9_000),
        );
        assert_eq!(cache.session_count("old", None), None);
        assert_eq!(cache.session_count("new", None), Some(1));
        assert_eq!(cache.session_count("third", None), Some(1));
    }

    // ---------------------------------- insertion, take and return policy

    /// `cf_scache_peer_add_session` (`vtls_scache.c:764-768`): "A session not
    /// from TLSv1.3 replaces all other."
    #[test]
    fn a_pre_tls13_session_replaces_every_cached_session() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        for ticket in [&b"a"[..], b"b", b"c"] {
            cache.put(
                &clock,
                SessionCaching::ENABLED,
                "k",
                None,
                session13(ticket, 9_000),
            );
        }
        assert_eq!(cache.session_count("k", None), Some(3));

        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session12(b"legacy", 9_000),
        );
        assert_eq!(stored_tickets(&cache, "k"), vec![b"legacy".to_vec()]);
    }

    /// The pre-1.3 arm does not trim, so it stores its one session even where
    /// the per-peer maximum is zero -- an asymmetry with the 1.3 arm that the C
    /// has and that is preserved.
    #[test]
    fn a_pre_tls13_session_is_stored_even_with_a_zero_maximum() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 0);
        assert!(cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session12(b"legacy", 9_000),
        ));
        assert_eq!(cache.session_count("k", None), Some(1));
    }

    /// `cf_scache_peer_add_session` (`vtls_scache.c:769-777`): a TLS 1.3 ticket
    /// removes the pre-1.3 sessions rather than joining them.
    #[test]
    fn a_tls13_ticket_evicts_the_pre_tls13_sessions() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session12(b"legacy", 9_000),
        );
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"modern", 9_000),
        );
        assert_eq!(stored_tickets(&cache, "k"), vec![b"modern".to_vec()]);
    }

    /// TLS 1.3 tickets accumulate at the **tail**, in arrival order, because
    /// each is single-use and several are worth keeping.
    #[test]
    fn tls13_tickets_accumulate_in_arrival_order() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        for ticket in [&b"first"[..], b"second", b"third"] {
            cache.put(
                &clock,
                SessionCaching::ENABLED,
                "k",
                None,
                session13(ticket, 9_000),
            );
        }
        assert_eq!(
            stored_tickets(&cache, "k"),
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
    }

    /// `vtls_scache.c:774-776`: the queue is trimmed from the **head**, so the
    /// oldest tickets go and the newest survive.
    #[test]
    fn the_per_peer_maximum_trims_the_oldest_tickets() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 2);
        for ticket in [&b"1"[..], b"2", b"3", b"4"] {
            cache.put(
                &clock,
                SessionCaching::ENABLED,
                "k",
                None,
                session13(ticket, 9_000),
            );
        }
        assert_eq!(
            stored_tickets(&cache, "k"),
            vec![b"3".to_vec(), b"4".to_vec()]
        );
    }

    /// With a maximum of zero the 1.3 `while` loop discards everything,
    /// including the ticket just appended -- the other half of the asymmetry.
    #[test]
    fn a_zero_maximum_discards_every_tls13_ticket() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 0);
        // The slot is created, so the peer exists with no sessions.
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"t", 9_000),
        );
        assert_eq!(cache.session_count("k", None), Some(0));
    }

    /// `vtls_scache.c:771`: the 1.3 arm sweeps expired entries before
    /// appending, so a stale ticket does not occupy one of the slots the trim
    /// then counts.
    #[test]
    fn the_tls13_arm_sweeps_expired_entries_before_appending() {
        let early = clock_at(1_000);
        let mut cache = SessionCache::new(1, 2);
        cache.put(
            &early,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"stale", 2_000),
        );
        cache.put(
            &early,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"fresh", 9_000),
        );

        // At t=5000 "stale" has expired. Appending a third ticket sweeps it,
        // so the trim to two leaves "fresh" and the newcomer rather than
        // dropping "fresh".
        let later = clock_at(5_000);
        cache.put(
            &later,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"new", 9_000),
        );
        assert_eq!(
            stored_tickets(&cache, "k"),
            vec![b"fresh".to_vec(), b"new".to_vec()]
        );
    }

    /// `Curl_ssl_scache_take` (`vtls_scache.c:891-893`): the **head** is
    /// taken, so tickets are spent in the order they arrived.
    #[test]
    fn take_yields_the_head_and_leaves_the_rest() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 4);
        for ticket in [&b"1"[..], b"2", b"3"] {
            cache.put(
                &clock,
                SessionCaching::ENABLED,
                "k",
                None,
                session13(ticket, 9_000),
            );
        }
        let taken = cache.take(&clock, "k", None).expect("a ticket");
        assert_eq!(taken.ticket(), b"1");
        assert_eq!(
            stored_tickets(&cache, "k"),
            vec![b"2".to_vec(), b"3".to_vec()]
        );
    }

    /// `Curl_ssl_scache_return` (`vtls_scache.c:862-867`): a TLS 1.3 ticket is
    /// **destroyed**, not returned. RFC 8446 appendix C.4: "Clients SHOULD NOT
    /// reuse a ticket for multiple connections."
    #[test]
    fn a_returned_tls13_ticket_is_destroyed_rather_than_recached() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 4);
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"once", 9_000),
        );
        let taken = cache.take(&clock, "k", None).expect("a ticket");
        assert_eq!(cache.session_count("k", None), Some(0));

        assert!(!cache.return_session(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            taken,
        ));
        assert_eq!(cache.session_count("k", None), Some(0));
    }

    /// The other arm: a pre-1.3 session identifier is reusable by design, so
    /// it goes back into the cache.
    #[test]
    fn a_returned_pre_tls13_session_is_recached() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 4);
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session12(b"reusable", 9_000),
        );
        let taken = cache.take(&clock, "k", None).expect("a session");
        assert_eq!(cache.session_count("k", None), Some(0));

        assert!(cache.return_session(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            taken,
        ));
        assert_eq!(stored_tickets(&cache, "k"), vec![b"reusable".to_vec()]);
    }

    /// The comparison is `< 0x304`, so every version at or above TLS 1.3 --
    /// including any future one -- is dropped. That is the conservative
    /// direction for a mechanism about not reusing single-use material.
    #[test]
    fn return_drops_every_version_at_or_above_tls13() {
        let clock = clock_at(1_000);
        let below = [
            IetfProtoVersion::SSL3,
            IetfProtoVersion::TLS1,
            IetfProtoVersion::TLS1_1,
            IetfProtoVersion::TLS1_2,
        ];
        for version in below {
            let mut cache = SessionCache::new(1, 4);
            let session =
                TlsSession::new(b"t".to_vec(), version, None, 9_000, 0)
                    .expect("a ticket");
            assert!(
                cache.return_session(
                    &clock,
                    SessionCaching::ENABLED,
                    "k",
                    None,
                    session
                ),
                "{version:?} is below 0x304 and must be recached"
            );
        }

        // TLS 1.3 itself and a hypothetical successor.
        for version in [
            IetfProtoVersion::TLS1_3,
            IetfProtoVersion::from_bits(0x0305),
        ] {
            let mut cache = SessionCache::new(1, 4);
            let session =
                TlsSession::new(b"t".to_vec(), version, None, 9_000, 0)
                    .expect("a ticket");
            assert!(
                !cache.return_session(
                    &clock,
                    SessionCaching::ENABLED,
                    "k",
                    None,
                    session
                ),
                "{version:?} is single-use and must be dropped"
            );
        }
    }

    // -------------------------------------- client authentication identity

    /// `cf_ssl_scache_match_auth` (`vtls_scache.c:598-618`), all four
    /// combinations. `Curl_safecmp` is case-**sensitive** with both-absent
    /// counting as equal.
    #[test]
    fn the_client_auth_comparison_matches_curl_safecmp() {
        let none = ClientAuth::new(None);
        let one = ClientAuth::new(Some("/a.pem"));
        let other = ClientAuth::new(Some("/b.pem"));

        // conn_config == NULL: only a peer with no certificate matches.
        assert!(none.matches(None));
        assert!(!one.matches(None));

        // Both present and equal; both absent; one absent.
        assert!(one.matches(Some(&one)));
        assert!(none.matches(Some(&none)));
        assert!(!one.matches(Some(&other)));
        assert!(!one.matches(Some(&none)));
        assert!(!none.matches(Some(&one)));

        // Case-sensitive, unlike the peer-key comparison.
        let upper = ClientAuth::new(Some("/A.PEM"));
        assert!(!one.matches(Some(&upper)));

        // A supplied configuration naming no certificate behaves exactly like
        // no configuration at all.
        assert!(none.matches(Some(&ClientAuth::default())));
        assert!(!one.matches(Some(&ClientAuth::default())));
    }

    /// The key records only *that* a certificate is set, as `:CCERT`, so two
    /// transfers with different certificates share a key -- and the identity
    /// check is the only thing stopping one from resuming the other's session.
    #[test]
    fn a_session_is_not_reused_across_different_client_certificates() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        let mine = ClientAuth::new(Some("/mine.pem"));
        let yours = ClientAuth::new(Some("/yours.pem"));

        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "h:443:CCERT:IMPL-i:G",
            Some(&mine),
            session13(b"mine", 9_000),
        );

        // The same key, a different identity: no match, and a *new* slot.
        assert!(cache
            .take(&clock, "h:443:CCERT:IMPL-i:G", Some(&yours))
            .is_none());
        // And with no identity at all.
        assert!(cache.take(&clock, "h:443:CCERT:IMPL-i:G", None).is_none());
        // The owner still finds it.
        let taken = cache
            .take(&clock, "h:443:CCERT:IMPL-i:G", Some(&mine))
            .expect("the owning identity matches");
        assert_eq!(taken.ticket(), b"mine");
    }

    /// A [`PeerKeyConfig`] and the [`ClientAuth`] derived from it name the same
    /// certificate, so the key and the identity cannot disagree.
    #[test]
    fn the_client_auth_is_derived_from_the_same_configuration_as_the_key() {
        let config = PeerKeyConfig {
            clientcert: Some("/client.pem"),
            ..PeerKeyConfig::default()
        };
        assert_eq!(config.client_auth().clientcert(), Some("/client.pem"));
        assert!(config.client_auth().is_confidential());

        let plain = PeerKeyConfig::default();
        assert_eq!(plain.client_auth().clientcert(), None);
        assert!(!plain.client_auth().is_confidential());
    }

    /// `cf_ssl_find_peer_by_key` (`vtls_scache.c:640`) compares keys with
    /// `curl_strequal`, which is ASCII-case-insensitive.
    #[test]
    fn the_peer_key_lookup_is_ascii_case_insensitive() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "Example.COM:443:IMPL-i:G",
            None,
            session13(b"t", 9_000),
        );
        assert_eq!(
            cache.session_count("example.com:443:impl-i:g", None),
            Some(1)
        );
        let taken = cache
            .take(&clock, "EXAMPLE.com:443:IMPL-I:G", None)
            .expect("case does not distinguish keys");
        assert_eq!(taken.ticket(), b"t");
    }

    /// `Curl_ssl_scache_remove_all` (`vtls_scache.c:972-991`): the slot is
    /// emptied and becomes free again.
    #[test]
    fn remove_all_empties_the_slot_and_frees_it() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k",
            None,
            session13(b"t", 9_000),
        );
        assert!(cache.remove_all("k", None));
        assert_eq!(cache.session_count("k", None), None);
        // The slot is genuinely free, so `max_sessions` survived the clear.
        let peer = cache.peers.first().expect("a slot");
        assert!(peer.is_free());
        assert_eq!(peer.max_sessions, 4);
        assert_eq!(peer.age, 0);
        assert!(!peer.hmac_set);

        // Removing an absent peer reports so and changes nothing.
        assert!(!cache.remove_all("absent", None));
    }

    // ------------------------------------------------------ exportability

    /// `cf_ssl_cache_peer_update` (`vtls_scache.c:427-438`), all three
    /// conditions.
    #[test]
    fn exportability_requires_no_credentials_and_a_global_or_absent_key() {
        let mut peer = ScachePeer::new(4);

        // Global key, no credentials: exportable.
        peer.init(PeerIdentity::Key("h:1:IMPL-i:G"), None);
        assert!(peer.exportable);

        // Local key: not exportable, because the key names an unresolved
        // relative path and means nothing in another process.
        peer.clear();
        peer.init(PeerIdentity::Key("h:1:CA-rel:IMPL-i:L"), None);
        assert!(!peer.exportable);

        // Global key but client credentials: not exportable.
        peer.clear();
        peer.init(
            PeerIdentity::Key("h:1:CCERT:IMPL-i:G"),
            Some(&ClientAuth::new(Some("/c.pem"))),
        );
        assert!(!peer.exportable);

        // No key at all, imported by code: exportable, because a previous
        // export already produced that code.
        peer.clear();
        peer.init(
            PeerIdentity::Code {
                salt: [7; SALT_LEN],
                hmac: [9; HMAC_LEN],
            },
            None,
        );
        assert!(peer.exportable);
        assert!(peer.hmac_set);
        assert!(peer.ssl_peer_key.is_none());
    }

    /// A key recovered by the second lookup pass re-derives exportability, so
    /// a slot that was exportable while its key was unknown stops being so if
    /// the recovered key turns out to be local.
    #[test]
    fn recovering_a_local_key_withdraws_exportability() {
        let mut cache = SessionCache::new(1, 4);
        let local_key = "h:1:CA-rel:IMPL-i:L";
        let salt = [3_u8; SALT_LEN];
        let hmac = hmac_sha256(&salt, local_key.as_bytes());

        let peer = cache.peers.get_mut(0).expect("a slot");
        peer.init(PeerIdentity::Code { salt, hmac }, None);
        assert!(peer.exportable, "an unknown key is exportable");

        let found = cache
            .find_peer_by_key(local_key, None)
            .expect("the code authenticates the key");
        let peer = cache.peers.get(found).expect("the slot");
        assert_eq!(peer.ssl_peer_key.as_deref(), Some(local_key));
        assert!(!peer.exportable, "a recovered local key withdraws it");
    }

    /// `ScachePeer::clear` zeroes the salt, the code and the exportable bit,
    /// which the C leaves stale. The C's staleness is unobservable -- both
    /// readers gate on the identity first -- and zeroing is strictly safer.
    #[test]
    fn clearing_a_peer_leaves_no_residue() {
        let mut peer = ScachePeer::new(3);
        peer.init(
            PeerIdentity::Code {
                salt: [1; SALT_LEN],
                hmac: [2; HMAC_LEN],
            },
            Some(&ClientAuth::new(Some("/c.pem"))),
        );
        peer.age = 42;
        peer.sessions.push_back(session13(b"t", 9_000));

        peer.clear();
        assert!(peer.is_free());
        assert!(peer.sessions.is_empty());
        assert_eq!(peer.key_salt, [0; SALT_LEN]);
        assert_eq!(peer.key_hmac, [0; HMAC_LEN]);
        assert!(!peer.exportable);
        assert_eq!(peer.age, 0);
        assert_eq!(peer.auth, ClientAuth::default());
        // The slab property survives.
        assert_eq!(peer.max_sessions, 3);
    }

    // ------------------------------------------------- import and export

    /// Collects everything an export hands the callback.
    fn collect_export(
        cache: &mut SessionCache,
        clock: &TestClock,
    ) -> Result<(ExportSummary, Vec<ExportedRecord>), CURLcode> {
        let mut generator = rng();
        let mut records = Vec::new();
        let summary = cache.export(clock, &mut generator, &mut |item| {
            records.push(ExportedRecord {
                peer_key: item.peer_key.map(String::from),
                shmac: item.shmac.to_vec(),
                packed: item.packed.to_vec(),
                valid_until: item.valid_until,
                ietf_tls_id: item.ietf_tls_id,
                alpn: item.alpn.map(String::from),
                earlydata_max: item.earlydata_max,
            });
            Ok(())
        })?;
        Ok((summary, records))
    }

    /// One callback invocation, captured by value so it outlives the borrow.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ExportedRecord {
        peer_key: Option<String>,
        shmac: Vec<u8>,
        packed: Vec<u8>,
        valid_until: i64,
        ietf_tls_id: IetfProtoVersion,
        alpn: Option<String>,
        earlydata_max: usize,
    }

    /// `cf_ssl_scache_peer_set_hmac` (`vtls_scache.c:1005-1013`): a 32-byte
    /// salt from the injected generator, and HMAC-SHA-256 of the peer key
    /// under it.
    #[test]
    fn the_export_code_is_hmac_sha256_of_the_peer_key_under_the_salt() {
        let mut peer = ScachePeer::new(4);
        peer.init(PeerIdentity::Key("h:1:IMPL-i:G"), None);
        assert!(!peer.hmac_set);

        let mut generator = rng();
        peer.set_hmac(&mut generator).expect("the key is known");
        assert!(peer.hmac_set);

        // The salt is exactly what the injected generator produced, and the
        // code is the keyed digest of the key under it -- recomputed here
        // independently of the implementation.
        let mut expected_salt = [0_u8; SALT_LEN];
        rand_bytes(&mut rng(), &mut expected_salt);
        assert_eq!(peer.key_salt, expected_salt);
        assert_eq!(peer.key_salt.len(), 32);
        assert_eq!(peer.key_hmac, hmac_sha256(&expected_salt, b"h:1:IMPL-i:G"));
        assert_eq!(peer.key_hmac.len(), 32);
    }

    /// `vtls_scache.c:1002-1003`: a slot with no key cannot be given a code.
    #[test]
    fn a_keyless_peer_cannot_be_given_a_code() {
        let mut peer = ScachePeer::new(4);
        let mut generator = rng();
        assert_eq!(
            peer.set_hmac(&mut generator),
            Err(CURLcode::BadFunctionArgument)
        );
        assert!(!peer.hmac_set);
    }

    /// `vtls_scache.c:1184-1191`: `shmac` is the salt followed by the code,
    /// exactly 64 bytes.
    #[test]
    fn the_shmac_is_the_salt_followed_by_the_code() {
        let mut peer = ScachePeer::new(4);
        peer.init(PeerIdentity::Key("k:G"), None);
        peer.set_hmac(&mut rng()).expect("the key is known");

        let shmac = peer.shmac();
        assert_eq!(shmac.len(), SHMAC_LEN);
        assert_eq!(SHMAC_LEN, 64);
        assert_eq!(&shmac[..SALT_LEN], &peer.key_salt[..]);
        assert_eq!(&shmac[SALT_LEN..], &peer.key_hmac[..]);
    }

    /// The comparison used on an imported code is constant-time and accepts
    /// only the exact value -- and a wrong length is a mismatch rather than an
    /// error, which is what `Mac::verify_slice` reports.
    #[test]
    fn code_verification_accepts_only_the_matching_value() {
        let salt = [5_u8; SALT_LEN];
        let key = "h:1:IMPL-i:G";
        let code = hmac_sha256(&salt, key.as_bytes());

        let mut peer = ScachePeer::new(4);
        peer.init(PeerIdentity::Code { salt, hmac: code }, None);

        assert!(peer.code_authenticates(key));
        assert!(!peer.code_authenticates("h:1:IMPL-i:L"));
        assert!(!peer.code_authenticates(""));

        // The other direction: a peer with a known key keys the OFFERED salt.
        let mut known = ScachePeer::new(4);
        known.init(PeerIdentity::Key(key), None);
        assert!(known.key_produces_code(&salt, &code));
        assert!(!known.key_produces_code(&[6; SALT_LEN], &code));
        assert!(!known.key_produces_code(&salt, &[0; HMAC_LEN]));

        // A slot with no key can never produce one.
        assert!(!ScachePeer::new(4).key_produces_code(&salt, &code));
    }

    /// [`codes_equal`] is equality, and it is reached through the keyed-digest
    /// wrapper rather than through `==` on the codes.
    #[test]
    fn constant_time_code_equality_agrees_with_equality() {
        let a = [1_u8; HMAC_LEN];
        let b = [1_u8; HMAC_LEN];
        let mut c = [1_u8; HMAC_LEN];
        c[HMAC_LEN - 1] = 2;
        let mut d = [1_u8; HMAC_LEN];
        d[0] = 2;

        assert!(codes_equal(&a, &b));
        // Differing in the last byte and in the first are both rejected, which
        // is the property a short-circuiting comparison would leak.
        assert!(!codes_equal(&a, &c));
        assert!(!codes_equal(&a, &d));
        assert!(codes_equal(&[0; HMAC_LEN], &[0; HMAC_LEN]));
    }

    /// `Curl_ssl_session_export` (`vtls_scache.c:1197-1201`): the callback
    /// receives the key, the 64-byte code, the packed bytes and the four
    /// metadata fields.
    #[test]
    fn export_hands_the_callback_every_field_the_c_passes() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        let session = TlsSession::with_quic_tp(
            b"ticket".to_vec(),
            IetfProtoVersion::TLS1_3,
            Some("h2"),
            9_000,
            16_384,
            Some(b"tp".to_vec()),
        )
        .expect("a ticket");
        assert!(cache.put(
            &clock,
            SessionCaching::ENABLED,
            "h:1:IMPL-i:G",
            None,
            session.clone(),
        ));

        let (summary, records) =
            collect_export(&mut cache, &clock).expect("the export succeeds");
        assert_eq!(
            summary,
            ExportSummary {
                peers: 1,
                tickets: 1
            }
        );
        assert_eq!(records.len(), 1);
        let record = records.first().expect("one record");
        assert_eq!(record.peer_key.as_deref(), Some("h:1:IMPL-i:G"));
        assert_eq!(record.shmac.len(), SHMAC_LEN);
        assert_eq!(record.packed, session.pack().expect("the session packs"));
        assert_eq!(record.valid_until, 9_000);
        assert_eq!(record.ietf_tls_id, IetfProtoVersion::TLS1_3);
        assert_eq!(record.alpn.as_deref(), Some("h2"));
        assert_eq!(record.earlydata_max, 16_384);

        // The code in the record authenticates the peer key.
        let mut salt = [0_u8; SALT_LEN];
        let mut code = [0_u8; HMAC_LEN];
        salt.copy_from_slice(&record.shmac[..SALT_LEN]);
        code.copy_from_slice(&record.shmac[SALT_LEN..]);
        assert_eq!(code, hmac_sha256(&salt, b"h:1:IMPL-i:G"));
    }

    /// `vtls_scache.c:1167-1176`: free slots, non-exportable slots and slots
    /// whose every session expired all contribute nothing, and none is counted.
    #[test]
    fn export_skips_free_non_exportable_and_empty_slots() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(4, 4);
        // Exportable.
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "good:G",
            None,
            session13(b"g", 9_000),
        );
        // Local key: not exportable.
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "local:L",
            None,
            session13(b"l", 9_000),
        );
        // Client credentials: not exportable.
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "cert:G",
            Some(&ClientAuth::new(Some("/c.pem"))),
            session13(b"c", 9_000),
        );
        // Everything expires before the export runs.
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "stale:G",
            None,
            session13(b"s", 2_000),
        );

        let later = clock_at(5_000);
        let (summary, records) =
            collect_export(&mut cache, &later).expect("the export succeeds");
        assert_eq!(
            summary,
            ExportSummary {
                peers: 1,
                tickets: 1
            }
        );
        assert_eq!(
            records
                .iter()
                .map(|record| record.peer_key.clone())
                .collect::<Vec<_>>(),
            vec![Some(String::from("good:G"))]
        );
        // The expired slot was swept even though it exported nothing.
        assert_eq!(cache.session_count("stale:G", None), Some(0));
    }

    /// Several tickets for one peer share one code and are all handed over.
    #[test]
    fn every_ticket_of_a_peer_shares_one_code() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 4);
        for ticket in [&b"1"[..], b"2", b"3"] {
            cache.put(
                &clock,
                SessionCaching::ENABLED,
                "k:G",
                None,
                session13(ticket, 9_000),
            );
        }
        let (summary, records) =
            collect_export(&mut cache, &clock).expect("the export succeeds");
        assert_eq!(
            summary,
            ExportSummary {
                peers: 1,
                tickets: 3
            }
        );
        let first = records.first().expect("a record").shmac.clone();
        assert!(records.iter().all(|record| record.shmac == first));
    }

    /// The C stops at the first callback failure through `goto out`, and so
    /// does this -- which is what lets a consumer abandon a partial write.
    #[test]
    fn export_stops_at_the_first_callback_failure() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 4);
        for ticket in [&b"1"[..], b"2", b"3"] {
            cache.put(
                &clock,
                SessionCaching::ENABLED,
                "k:G",
                None,
                session13(ticket, 9_000),
            );
        }
        let mut seen = 0_usize;
        let outcome = cache.export(&clock, &mut rng(), &mut |_item| {
            seen += 1;
            if seen == 2 {
                return Err(CURLcode::WriteError);
            }
            Ok(())
        });
        assert_eq!(outcome, Err(CURLcode::WriteError));
        assert_eq!(seen, 2);
    }

    /// `vtls_scache.c:1163`: a session too large to pack fails the export with
    /// the buffer's own code rather than being silently skipped.
    #[test]
    fn export_refuses_a_session_larger_than_the_ticket_ceiling() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 4);
        // u16 lengths cap a ticket at 65535, so the 16 KiB ceiling is what
        // this crosses.
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k:G",
            None,
            session13(&vec![0x5A; SSL_TICKET_MAX], 9_000),
        );
        let outcome = cache.export(&clock, &mut rng(), &mut |_item| Ok(()));
        assert_eq!(outcome, Err(CURLcode::TooLarge));
    }

    /// A slot imported by code alone exports with `peer_key` of [`None`], and
    /// the code it carries is the one it was imported with.
    #[test]
    fn a_code_only_slot_exports_without_a_key() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 4);
        let mut shmac = [0_u8; SHMAC_LEN];
        shmac[..SALT_LEN].copy_from_slice(&[4; SALT_LEN]);
        shmac[SALT_LEN..].copy_from_slice(&[8; HMAC_LEN]);

        let packed = session13(b"t", 9_000).pack().expect("it packs");
        cache
            .import(&clock, None, Some(&shmac), &packed)
            .expect("the import succeeds");

        let (summary, records) =
            collect_export(&mut cache, &clock).expect("the export succeeds");
        assert_eq!(
            summary,
            ExportSummary {
                peers: 1,
                tickets: 1
            }
        );
        let record = records.first().expect("a record");
        assert_eq!(record.peer_key, None);
        assert_eq!(record.shmac, shmac.to_vec());
    }

    /// `Curl_ssl_session_import` (`vtls_scache.c:1098-1102`): identified by an
    /// explicit key, the session lands in that key's slot.
    #[test]
    fn an_import_by_key_lands_in_that_keys_slot() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        let packed = session13(b"imported", 9_000).pack().expect("it packs");

        cache
            .import(&clock, Some("k:G"), None, &packed)
            .expect("the import succeeds");
        assert_eq!(stored_tickets(&cache, "k:G"), vec![b"imported".to_vec()]);
    }

    /// `vtls_scache.c:1086-1089` and `:1103-1108`: neither identification, and
    /// a garbled code length, are both `CURLE_BAD_FUNCTION_ARGUMENT`.
    #[test]
    fn an_import_must_carry_a_key_or_a_sixty_four_byte_code() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        let packed = session13(b"t", 9_000).pack().expect("it packs");

        // Neither.
        assert_eq!(
            cache.import(&clock, None, None, &packed),
            Err(CURLcode::BadFunctionArgument)
        );
        // An empty code is "absent", which is the C's `!shmac_len`.
        assert_eq!(
            cache.import(&clock, None, Some(&[]), &packed),
            Err(CURLcode::BadFunctionArgument)
        );
        // Every wrong length, on both sides of 64.
        for len in [1_usize, 32, 63, 65, 128] {
            assert_eq!(
                cache.import(&clock, None, Some(&vec![0; len]), &packed),
                Err(CURLcode::BadFunctionArgument),
                "a {len}-byte code must be refused"
            );
        }
        // Exactly 64 is accepted.
        assert_eq!(
            cache.import(&clock, None, Some(&[0; SHMAC_LEN]), &packed),
            Ok(())
        );
    }

    /// A garbled code alongside an explicit key is ignored, because the C only
    /// inspects the code in the branch where no key was supplied.
    #[test]
    fn a_key_makes_the_code_irrelevant() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        let packed = session13(b"t", 9_000).pack().expect("it packs");
        assert_eq!(
            cache.import(&clock, Some("k:G"), Some(&[0; 3]), &packed),
            Ok(())
        );
        assert_eq!(cache.session_count("k:G", None), Some(1));
    }

    /// `cf_ssl_find_peer_by_hmac` (`vtls_scache.c:1038-1044`): a repeated
    /// import of the same code merges into the same slot rather than taking a
    /// second one.
    #[test]
    fn repeated_imports_of_one_code_merge_into_one_slot() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(4, 4);
        let shmac = [7_u8; SHMAC_LEN];

        for ticket in [&b"1"[..], b"2"] {
            let packed = session13(ticket, 9_000).pack().expect("it packs");
            cache
                .import(&clock, None, Some(&shmac), &packed)
                .expect("the import succeeds");
        }

        let occupied =
            cache.peers.iter().filter(|peer| !peer.is_free()).count();
        assert_eq!(occupied, 1);
        let peer = cache
            .peers
            .iter()
            .find(|peer| !peer.is_free())
            .expect("the slot");
        assert_eq!(peer.sessions.len(), 2);
    }

    /// `cf_ssl_find_peer_by_hmac` (`vtls_scache.c:1036-1037`): a slot
    /// established with client credentials is never a candidate for an import,
    /// because an import carries no client-certificate configuration.
    ///
    /// That is a privacy guarantee rather than an optimisation: merging an
    /// imported session into a client-authenticated slot would let a transfer
    /// resume a session it never established, presenting an identity the
    /// exporting process held and this one may not.
    #[test]
    fn an_import_never_lands_in_a_client_authenticated_slot() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(1, 4);
        let key = "h:1:CCERT:IMPL-i:G";
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            key,
            Some(&ClientAuth::new(Some("/mine.pem"))),
            session13(b"authenticated", 9_000),
        );

        // A code that this very key produces -- so the only thing keeping the
        // import out is the credential check.
        let salt = [17_u8; SALT_LEN];
        let code = hmac_sha256(&salt, key.as_bytes());
        let mut shmac = [0_u8; SHMAC_LEN];
        shmac[..SALT_LEN].copy_from_slice(&salt);
        shmac[SALT_LEN..].copy_from_slice(&code);

        let packed = session13(b"imported", 9_000).pack().expect("it packs");
        cache
            .import(&clock, None, Some(&shmac), &packed)
            .expect("the import reports success");

        // The only slot was taken over as a free slot rather than merged into,
        // so the authenticated session is gone and the import stands alone
        // under the code -- never under the credentialed identity.
        assert_eq!(
            cache.session_count(key, Some(&ClientAuth::new(Some("/mine.pem")))),
            None
        );
        let peer = cache.peers.first().expect("a slot");
        assert!(peer.ssl_peer_key.is_none());
        assert!(peer.hmac_set);
        assert_eq!(peer.auth, ClientAuth::default());
        assert_eq!(peer.sessions.len(), 1);
    }

    /// `cf_ssl_find_peer_by_hmac` (`vtls_scache.c:1045-1065`): a slot whose key
    /// is already known and which keys to the offered code adopts the code and
    /// receives the session -- so an import merges with live sessions instead
    /// of evicting them.
    #[test]
    fn an_import_merges_into_a_slot_whose_known_key_produces_the_code() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        let key = "h:1:IMPL-i:G";
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            key,
            None,
            session13(b"live", 9_000),
        );

        // A code computed elsewhere, over the same key with a fresh salt.
        let salt = [11_u8; SALT_LEN];
        let code = hmac_sha256(&salt, key.as_bytes());
        let mut shmac = [0_u8; SHMAC_LEN];
        shmac[..SALT_LEN].copy_from_slice(&salt);
        shmac[SALT_LEN..].copy_from_slice(&code);

        let packed = session13(b"imported", 9_000).pack().expect("it packs");
        cache
            .import(&clock, None, Some(&shmac), &packed)
            .expect("the import succeeds");

        assert_eq!(
            stored_tickets(&cache, key),
            vec![b"live".to_vec(), b"imported".to_vec()]
        );
        // The slot adopted the offered salt and code, which it had none of.
        let peer = cache
            .peers
            .iter()
            .find(|peer| peer.matches_key(key, None))
            .expect("the slot");
        assert!(peer.hmac_set);
        assert_eq!(peer.key_salt, salt);
        assert_eq!(peer.key_hmac, code);
    }

    /// `cf_ssl_find_peer_by_key`'s second pass (`vtls_scache.c:648-678`): a
    /// slot imported by code alone becomes usable the moment a caller offers
    /// the matching key, and the key is remembered for the next lookup.
    #[test]
    fn a_code_only_slot_is_recovered_by_offering_its_key() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        let key = "h:1:IMPL-i:G";
        let salt = [13_u8; SALT_LEN];
        let code = hmac_sha256(&salt, key.as_bytes());
        let mut shmac = [0_u8; SHMAC_LEN];
        shmac[..SALT_LEN].copy_from_slice(&salt);
        shmac[SALT_LEN..].copy_from_slice(&code);

        let packed = session13(b"recovered", 9_000).pack().expect("it packs");
        cache
            .import(&clock, None, Some(&shmac), &packed)
            .expect("the import succeeds");
        // Before recovery the slot has no key.
        assert!(cache.peers.iter().all(|peer| peer.ssl_peer_key.is_none()));

        // Offering the key both finds and remembers it.
        let taken = cache
            .take(&clock, key, None)
            .expect("the code authenticates the key");
        assert_eq!(taken.ticket(), b"recovered");
        let peer = cache
            .peers
            .iter()
            .find(|peer| peer.ssl_peer_key.as_deref() == Some(key))
            .expect("the key was remembered");
        assert!(peer.hmac_set);

        // A key that does not authenticate finds nothing.
        let mut other = SessionCache::new(1, 4);
        let peer = other.peers.get_mut(0).expect("a slot");
        peer.init(PeerIdentity::Code { salt, hmac: code }, None);
        assert!(other.find_peer_by_key("h:1:IMPL-i:L", None).is_none());
    }

    /// An expired import is dropped in silence and disturbs nothing -- neither
    /// the slot's live sessions nor, for a pre-1.3 import, the whole slot.
    #[test]
    fn an_expired_import_is_dropped_without_disturbing_the_slot() {
        let clock = clock_at(5_000);
        let mut cache = SessionCache::new(2, 4);
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k:G",
            None,
            session13(b"live", 9_000),
        );

        // A TLS 1.2 import would otherwise destroy every session in the slot.
        let packed = session12(b"stale", 2_000).pack().expect("it packs");
        assert_eq!(cache.import(&clock, Some("k:G"), None, &packed), Ok(()));
        assert_eq!(stored_tickets(&cache, "k:G"), vec![b"live".to_vec()]);
    }

    /// Malformed bytes are reported, never absorbed, and never panic.
    #[test]
    fn a_malformed_import_is_reported() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        for bytes in [
            &[][..],
            &[0x00],
            &[0x02],
            &[0x01, 0xEE],
            &[0x01, SPACK_TICKET],
            &[0x01, SPACK_TICKET, 0x00],
            &[0x01, SPACK_TICKET, 0x00, 0x09, b'a'],
        ] {
            let outcome = cache.import(&clock, Some("k:G"), None, bytes);
            assert_eq!(
                outcome,
                Err(CURLcode::ReadError),
                "{bytes:?} must be refused"
            );
        }
        assert_eq!(cache.session_count("k:G", None), None);
    }

    /// The whole point of the pair: what one process exports, another imports
    /// -- identified only by the 64 opaque bytes, with no key in sight.
    #[test]
    fn an_export_round_trips_through_an_import_by_code_alone() {
        let clock = clock_at(1_000);
        let key = "example.com:443:IMPL-rustls/0.23.42:G";

        let mut source = SessionCache::new(2, 4);
        let original = TlsSession::with_quic_tp(
            b"the-ticket".to_vec(),
            IetfProtoVersion::TLS1_3,
            Some("h3"),
            9_000,
            4_096,
            Some(b"quic-tp".to_vec()),
        )
        .expect("a ticket");
        source.put(
            &clock,
            SessionCaching::ENABLED,
            key,
            None,
            original.clone(),
        );

        let (_summary, records) =
            collect_export(&mut source, &clock).expect("the export succeeds");
        let record = records.first().expect("one record");

        // The importing process knows nothing but the bytes.
        let mut sink = SessionCache::new(2, 4);
        sink.import(&clock, None, Some(&record.shmac), &record.packed)
            .expect("the import succeeds");

        // And then learns the key, which the code authenticates.
        let taken = sink.take(&clock, key, None).expect("the session is there");
        assert_eq!(taken, original);
        assert_eq!(taken.ticket(), b"the-ticket");
        assert_eq!(taken.alpn(), Some("h3"));
        assert_eq!(taken.quic_tp(), Some(&b"quic-tp"[..]));
        assert_eq!(taken.earlydata_max(), 4_096);
        assert_eq!(taken.valid_until(), 9_000);
    }

    /// The same round trip carrying the key explicitly, which is what a
    /// consumer that stored it does.
    #[test]
    fn an_export_round_trips_through_an_import_by_key() {
        let clock = clock_at(1_000);
        let mut source = SessionCache::new(2, 4);
        source.put(
            &clock,
            SessionCaching::ENABLED,
            "k:G",
            None,
            session13(b"t", 9_000),
        );
        let (_summary, records) =
            collect_export(&mut source, &clock).expect("the export succeeds");
        let record = records.first().expect("one record");
        let key = record.peer_key.clone().expect("the key is known");

        let mut sink = SessionCache::new(2, 4);
        sink.import(&clock, Some(&key), None, &record.packed)
            .expect("the import succeeds");
        assert_eq!(sink.session_count(&key, None), Some(1));
    }

    /// An import does **not** default or clamp the expiry, so a session
    /// imported and re-exported carries the same deadline. Without that, a
    /// long-running process reloading its own file would drift every deadline.
    #[test]
    fn an_import_preserves_the_expiry_exactly() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        // Far beyond the seven-day ceiling `put` would have applied.
        let far = 1_000 + MAX_13_LIFETIME_SEC + 999_999;
        let packed = session13(b"t", far).pack().expect("it packs");
        cache
            .import(&clock, Some("k:G"), None, &packed)
            .expect("the import succeeds");
        assert_eq!(stored_validities(&cache, "k:G"), vec![far]);

        // And a re-export reports the same value.
        let (_summary, records) =
            collect_export(&mut cache, &clock).expect("the export succeeds");
        assert_eq!(records.first().expect("a record").valid_until, far);
    }

    /// An import into a cache with no room discards the session and reports
    /// success, as every other out-of-room path does.
    #[test]
    fn an_import_into_a_full_cache_of_zero_slots_succeeds_silently() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(0, 4);
        let packed = session13(b"t", 9_000).pack().expect("it packs");
        assert_eq!(cache.import(&clock, Some("k:G"), None, &packed), Ok(()));
        assert_eq!(
            cache.import(&clock, None, Some(&[0; SHMAC_LEN]), &packed),
            Ok(())
        );
    }

    /// The salt comes from the **injected** generator and from nowhere else, so
    /// two exports driven by equal generators produce equal codes and a
    /// different generator produces a different one.
    ///
    /// This is the assertion that would fail if any ambient entropy leaked in
    /// -- a `thread_rng`, an `OsRng` or a lazily initialised global. It is the
    /// reason `Curl_rand(NULL, ...)` (`vtls_scache.c:1005`) became a parameter
    /// rather than a call.
    #[test]
    fn the_export_code_is_governed_by_the_injected_generator() {
        let clock = clock_at(1_000);
        let shmac_with = |mut generator: TestRng| {
            let mut cache = SessionCache::new(1, 4);
            cache.put(
                &clock,
                SessionCaching::ENABLED,
                "k:G",
                None,
                session13(b"t", 9_000),
            );
            let mut captured = Vec::new();
            cache
                .export(&clock, &mut generator, &mut |item| {
                    captured.push(item.shmac.to_vec());
                    Ok(())
                })
                .expect("the export succeeds");
            captured
        };

        let first = shmac_with(TestRng::from_seed(0x1234_5678));
        let again = shmac_with(TestRng::from_seed(0x1234_5678));
        let other = shmac_with(TestRng::from_seed(0x8765_4321));

        assert_eq!(first.len(), 1);
        assert_eq!(first, again, "the same generator gives the same code");
        assert_ne!(first, other, "a different generator gives a different one");
        // And a salt drawn twice from one generator differs, so the code is not
        // a constant that happens to be reproducible.
        let mut generator = TestRng::from_seed(0x1234_5678);
        let mut a = [0_u8; SALT_LEN];
        let mut b = [0_u8; SALT_LEN];
        rand_bytes(&mut generator, &mut a);
        rand_bytes(&mut generator, &mut b);
        assert_ne!(a, b);
    }

    /// The whole cache is usable **through the guard**, which is how a shared
    /// cache is reached: select, acquire, work, and let the scope end.
    #[test]
    fn a_full_lifecycle_runs_through_the_guard() {
        let clock = clock_at(1_000);
        let mut shared = SessionCache::new(2, 4);
        let lock = RecordingLock::default();
        let key = "example.com:443:IMPL-rustls/0.23.42:G";

        {
            let selected =
                select_cache(Some(&mut shared), None).expect("a cache");
            let mut guard = selected.acquire(&lock);

            assert!(guard.put(
                &clock,
                SessionCaching::ENABLED,
                key,
                None,
                session13(b"first", 9_000),
            ));
            assert!(guard.put(
                &clock,
                SessionCaching::ENABLED,
                key,
                None,
                session13(b"second", 9_000),
            ));
            assert_eq!(guard.session_count(key, None), Some(2));

            let taken = guard.take(&clock, key, None).expect("a ticket");
            assert_eq!(taken.ticket(), b"first");
            // A TLS 1.3 ticket is spent, so returning it drops it.
            assert!(!guard.return_session(
                &clock,
                SessionCaching::ENABLED,
                key,
                None,
                taken,
            ));
            assert_eq!(guard.session_count(key, None), Some(1));

            assert!(guard.remove_all(key, None));
            assert_eq!(guard.session_count(key, None), None);
        }

        // Exactly one lock and one unlock, around the whole sequence.
        assert_eq!(
            lock.events(),
            vec![String::from("lock(Single)"), String::from("unlock")]
        );
        // And the work landed on the cache itself, not on a copy.
        assert_eq!(shared.age(), 2);
    }

    /// [`SessionCache::session_count`] answers about a *peer*, so an identity
    /// that does not match reports absence rather than the other identity's
    /// count.
    #[test]
    fn the_session_count_respects_the_client_identity() {
        let clock = clock_at(1_000);
        let mut cache = SessionCache::new(2, 4);
        let mine = ClientAuth::new(Some("/mine.pem"));
        cache.put(
            &clock,
            SessionCaching::ENABLED,
            "k:G",
            Some(&mine),
            session13(b"t", 9_000),
        );
        assert_eq!(cache.session_count("k:G", Some(&mine)), Some(1));
        assert_eq!(cache.session_count("k:G", None), None);
        assert_eq!(
            cache.session_count("k:G", Some(&ClientAuth::new(Some("/x.pem")))),
            None
        );
    }

    // ------------------------------------------------------------- secrecy

    /// Neither the ticket bytes nor the salt-and-code appear in a `Debug`
    /// rendering, because both are material an attacker wants and neither is
    /// something a reader debugging the cache needs.
    #[test]
    fn debug_renderings_disclose_no_secret_material() {
        let session = TlsSession::with_quic_tp(
            b"SECRET-TICKET-BYTES".to_vec(),
            IetfProtoVersion::TLS1_3,
            Some("h2"),
            9_000,
            0,
            Some(b"SECRET-QUIC-PARAMS".to_vec()),
        )
        .expect("a ticket");
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("SECRET"));
        assert!(rendered.contains("ticket_len: 19"));
        assert!(rendered.contains("quic_tp_len: Some(18)"));

        let mut peer = ScachePeer::new(4);
        peer.init(PeerIdentity::Key("k:G"), None);
        peer.set_hmac(&mut rng()).expect("the key is known");
        peer.sessions.push_back(session);
        let rendered = format!("{peer:?}");
        assert!(!rendered.contains("SECRET"));
        // The salt and code are reported as a bit, not as bytes.
        assert!(rendered.contains("hmac_set: true"));
        assert!(!rendered.contains(&format!("{:?}", peer.key_salt)));
        assert!(!rendered.contains(&format!("{:?}", peer.key_hmac)));

        // The cache's own rendering inherits both.
        let mut cache = SessionCache::new(1, 1);
        cache.put(
            &clock_at(0),
            SessionCaching::ENABLED,
            "k:G",
            None,
            session13(b"SECRET-2", 9_000),
        );
        assert!(!format!("{cache:?}").contains("SECRET"));
    }

    /// The validities cached for one peer, oldest first.
    fn stored_validities(cache: &SessionCache, peer_key: &str) -> Vec<i64> {
        cache
            .peers
            .iter()
            .filter(|peer| peer.matches_key(peer_key, None))
            .flat_map(|peer| peer.sessions.iter().map(TlsSession::valid_until))
            .collect()
    }

    /// The tickets cached for one peer, oldest first.
    fn stored_tickets(cache: &SessionCache, peer_key: &str) -> Vec<Vec<u8>> {
        cache
            .peers
            .iter()
            .filter(|peer| peer.matches_key(peer_key, None))
            .flat_map(|peer| peer.sessions.iter().map(|s| s.ticket().to_vec()))
            .collect()
    }

    /// Renders `path` relative to `base`, for the one test that needs a
    /// relative path to hand to the resolution branch.
    ///
    /// A four-line helper rather than a dependency: the only case it has to
    /// handle is a temporary directory that shares no prefix with the working
    /// directory, which is `..` up to the root followed by the target.
    fn pathdiff_relative(
        path: &std::path::Path,
        base: &std::path::Path,
    ) -> String {
        let ups = base.components().count().saturating_sub(1);
        let mut out = String::new();
        for _ in 0..ups {
            out.push_str("../");
        }
        out.push_str(
            path.strip_prefix("/")
                .unwrap_or(path)
                .to_str()
                .expect("the temporary path is UTF-8"),
        );
        out
    }
}
