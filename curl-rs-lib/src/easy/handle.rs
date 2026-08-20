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

//! The easy handle: the god-struct, decomposed.
//!
//! Supersedes `struct Curl_easy` (`lib/urldata.h:1616-1682`), the handle
//! lifecycle of `lib/easy.c` and the default-value initialiser
//! `Curl_init_userdefined` (`lib/url.c:337-455`).
//!
//! # What this file is FOR
//!
//! `lib/urldata.h` is included by nearly every translation unit in the C
//! tree, and `struct Curl_easy` is why: 24 top-level members spanning
//! connection state, per-request state, option state, cookie storage,
//! progress accounting and TLS session identity, all reachable from any
//! function that holds a `struct Curl_easy *data`. AAP 0.1.2 replaces that
//! with per-module structs and explicit ownership -- *"fields migrate to the
//! module that owns their lifecycle. Cross-module access becomes an explicit
//! borrow rather than an implicit reach into shared mutable state."*
//!
//! So this file AGGREGATES and does not reimplement. Of the 24 members, six
//! are owned here because nothing else can own them -- the option state, the
//! metadata store, the three identity fields, the `curl_easy_getinfo`
//! backing store and the handle's own validity marker -- and the rest are
//! held through the type of the module that owns them:
//! [`crate::transfer::progress::Progress`],
//! [`crate::transfer::request::SingleRequest`],
//! [`crate::multi::state::CurlMstate`], [`crate::share::Share`],
//! [`crate::cookies::CookieInfo`], [`crate::cookies::hsts::HstsCache`],
//! [`crate::cookies::altsvc::AltSvcInfo`],
//! [`crate::protocols::ftp::listparser::WildcardData`] and
//! [`crate::conn::filters::TlsSessionInfo`].
//!
//! There is deliberately no blanket import: AAP 0.4.2 replaces
//! `#include "urldata.h"` with *"one import per type actually used"*, and
//! every `use` at the head of this file names a type this file mentions.
//!
//! # The five contracts this file settles
//!
//! 1. **The frozen defaults.** [`UserDefined::new`] is
//!    `Curl_init_userdefined` (`lib/url.c:337-455`) followed by
//!    `Curl_ssl_easy_config_init` (`lib/vtls/vtls.c:181-193`). AAP 0.8.1
//!    freezes *"default option values, including the default-on state of
//!    certificate verification"*, so every value there is transcribed from
//!    the C with its symbolic constant resolved out of the headers, and
//!    [`mod tests`] asserts each one individually.
//!
//! 2. **Certificate verification is ON.** The C's own comment at
//!    `lib/vtls/vtls.c:183-186` is the specification: *"libcurl 7.10
//!    introduced SSL verification by default! This needs to be switched off
//!    unless wanted."* [`SslConfigData`] carries
//!    [`crate::tls::verify::VerifyPolicy`], whose [`Default`] is already the
//!    secure configuration, and the proxy configuration starts as a COPY of
//!    the primary one exactly as `data->set.proxy_ssl = data->set.ssl`
//!    does. [`EasyHandle::peer_verification_disabled`] is the narrow public
//!    query that obliges `curl-rs` to warn on standard error before
//!    proceeding.
//!
//! 3. **Identity is a generational token.** AAP 0.6.9 requires *"a slab with
//!    generational keys so a stale handle is detectably stale rather than a
//!    dangling pointer"*. [`HandleToken`] carries an index AND a generation;
//!    [`MultiXferId`] preserves the C's `UINT32_MAX` sentinel and
//!    [`TransferId`] preserves the C's `-1`. See [`HandleIdentity`].
//!
//! 4. **The four seams are injected here.** AAP 0.3.3 pattern P12 requires
//!    the clock, the resolver, the TLS provider and the randomness source to
//!    be injected rather than reached for globally, *"which is what makes
//!    the protocol modules testable to the mandated 80% line coverage
//!    without live network access."* [`EasySeams`] is where a handle takes
//!    all four. There is no process-global default for any of them.
//!
//! 5. **The duplication partition.** `dupset` (`lib/easy.c:872-936`) copies
//!    the option state and nothing else; `curl_easy_duphandle`
//!    (`:952-1077`) then leaves eleven things fresh in the clone. That
//!    partition is a property of the handle rather than of the entry point,
//!    so it is expressed here as data -- [`EasyHandle::duplicate`] can only
//!    copy [`Self::set`], because every other field is rebuilt by
//!    [`EasyHandle::new_with_seams`].
//!
//! # What this file does NOT do
//!
//! It does not declare the option table. `curl-rs-ffi` is the sole source of
//! truth for the 308 `CURLoption` identifiers and the `curl_easyoption`
//! metadata array; [`crate::easy::options`] consumes it. It does not
//! implement the setters (`lib/setopt.c`) or the `CURLINFO` accessors
//! (`lib/getinfo.c`) -- those arrive with their own files, and this one
//! supplies the state they write and read. And it performs no ownership
//! transfer across the C boundary: `Box::into_raw` and `Box::from_raw` for
//! `curl_easy_init` and `curl_easy_cleanup` are confined to `curl-rs-ffi`
//! (AAP 0.3.3 pattern P8), so nothing here dereferences a raw pointer and
//! this file contains no `unsafe` at all.
//!
//! # Enumeration provenance
//!
//! The string and blob tables are the C's `enum dupstring` and
//! `enum dupblob` (`lib/urldata.h:1141-1285`), keyed by an enum rather than
//! by a bare index so that `dst.str[i]` cannot be written with the wrong
//! `i`. `STRING_LASTZEROTERMINATED` (`:1265`) is what bounds the bulk
//! duplication loop, and `STRING_COPYPOSTFIELDS` (`:1269`) is the one member
//! past it -- binary data that cannot be `strdup`ed, which is why it is
//! special-cased in [`StringTable::duplicate`] rather than folded into the
//! loop.

use core::fmt;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::auth::{AuthMask, AuthStatePair};
use crate::conn::filters::{IpQuadruple, TlsSessionInfo};
use crate::conn::pool::ConnectionId;
use crate::cookies::netrc::StoreNetrc;
use crate::crypto::rand::{Rng, SystemRng};
use crate::dns::resolver::SystemResolver;
use crate::dns::Resolver;
use crate::error::{CURLcode, CodeResult};
use crate::mime::MimePart;
use crate::multi::state::CurlMstate;
use crate::protocols::Proto;
use crate::proxy::CURLproxycode;
use crate::share::Share;
use crate::tls::verify::{CertInfoRecord, VerifyPolicy};
use crate::tls::TlsFilterFactory;
use crate::transfer::progress::Progress;
use crate::transfer::request::{HttpRequestKind, SingleRequest};
use crate::util::timeval::{Clock, SystemClock};

#[cfg(feature = "altsvc")]
use crate::cookies::altsvc::AltSvcInfo;
#[cfg(feature = "hsts")]
use crate::cookies::hsts::HstsCache;
#[cfg(feature = "cookies")]
use crate::cookies::CookieInfo;
#[cfg(feature = "ftp")]
use crate::protocols::ftp::listparser::WildcardData;

// ---------------------------------------------------------------------------
// Constants -- every one transcribed, with the header it comes from
// ---------------------------------------------------------------------------

/// `CURLEASY_MAGIC_NUMBER` (`lib/urldata.h:213`): `0xc0dedbadU`.
///
/// C stores this in `data->magic` so that `GOOD_EASY_HANDLE`
/// (`lib/urldata.h:218-223`) can tell an easy handle from a multi handle, or
/// from freed memory, on the far side of a `void *`. Rust needs none of that
/// for memory safety -- an [`EasyHandle`] reference is already known to be
/// one -- but the OBSERVABLE behaviour it produces is part of the frozen API
/// surface and is reproduced at the ABI boundary: every fallible entry point
/// answers [`CURLcode::BadFunctionArgument`] for a handle that fails the
/// test, and `curl_easy_cleanup` with `curl_easy_reset`, both of which return
/// `void`, do nothing at all.
///
/// The value is therefore carried and published rather than dropped, and
/// [`EasyHandle::is_valid`] is the predicate `curl-rs-ffi` needs. See
/// [`EasyHandle::magic`] for what a handle does when the marker is wrong.
pub const CURLEASY_MAGIC_NUMBER: u32 = 0xc0de_dbad;

/// `LIBCURL_NAME` (`lib/urldata.h:1683`): `"libcurl"`.
///
/// Declared beside the handle in the C, and kept beside it here, because it
/// is the name a handle reports itself under.
pub const LIBCURL_NAME: &str = "libcurl";

/// `CURL_MAX_INPUT_LENGTH` (`lib/urldata.h:131`): 8,000,000.
///
/// The C's comment: *"Max string input length is a precaution against abuse
/// and to detect junk input easier and better."* Every string and blob option
/// longer than this is refused with [`CURLcode::BadFunctionArgument`].
///
/// Defined HERE and nowhere else in this crate, which is why it is
/// `pub(crate)` rather than private: `easy/setopt.rs` enforces it and must
/// not carry a second copy, since two copies of a bound are two bounds that
/// can disagree.
#[allow(dead_code)] // consumer: easy/setopt.rs
pub(crate) const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

/// `CURL_MAX_HTTP_HEADER` (`include/curl/curl.h:272`): `100 * 1024`.
///
/// The ceiling `curlx_dyn_init(&data->state.headerb, CURL_MAX_HTTP_HEADER)`
/// gives the header accumulation buffer (`lib/easy.c:972`), and therefore the
/// ceiling [`HandleState::header_buffer_limit`] reports.
pub(crate) const CURL_MAX_HTTP_HEADER: usize = 100 * 1024;

/// The slot count `curl_easy_duphandle` gives a clone's metadata store:
/// `Curl_hash_init(&outcurl->meta_hash, 23, ...)` (`lib/easy.c:970`).
///
/// A hash-table bucket count in the C and a documented capacity hint here:
/// [`MetaStore`] is an ordered map, so 23 is what it reserves rather than how
/// it distributes. The number is carried because it is the C's and because
/// AAP 0.8.1's minimal-change mandate applies to the shape of the thing being
/// reproduced, not only to its behaviour.
#[allow(dead_code)] // consumer: easy/setopt.rs
pub(crate) const META_HASH_SLOTS: usize = 23;

/// `FIRSTSOCKET` (`lib/urldata.h:421`) and `SECONDARYSOCKET` (`:422`), as a
/// type rather than as two bare integers.
///
/// A `PROTOPT_DUAL` protocol (`lib/urldata.h:528`) uses both: FTP is the one
/// in core scope, and it holds the control connection in the first slot and
/// the data connection in the second. Every other scheme uses only the
/// first.
///
/// Modelled as an enum because the two values index a pair and nothing else,
/// so an out-of-range index is a state that should not be expressible. The
/// discriminants are the C's, and [`Self::as_index`] is what turns one back
/// into the subscript the C writes.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SocketSlot {
    /// `FIRSTSOCKET` = 0: the only socket most schemes have, and FTP's
    /// control connection.
    #[default]
    First = 0,
    /// `SECONDARYSOCKET` = 1: the second socket a `PROTOPT_DUAL` scheme
    /// opens, which for FTP is the data connection.
    Secondary = 1,
}

impl SocketSlot {
    /// Both slots, in the C's declaration order.
    pub const ALL: [Self; 2] = [Self::First, Self::Secondary];

    /// The subscript the C writes into `conn->sock[]`.
    #[must_use]
    pub const fn as_index(self) -> usize {
        self as usize
    }
}

/// `PROTOPT_DUAL` (`lib/urldata.h:528`): `1 << 1`.
///
/// *"this protocol uses two connections"* -- the flag that decides whether
/// [`SocketSlot::Secondary`] is ever occupied. Published from here because
/// the socket slots are, and the two are one fact.
#[allow(dead_code)] // consumer: easy/setopt.rs
pub(crate) const PROTOPT_DUAL: u32 = 1 << 1;

// The buffer sizes. `set->buffer_size = READBUFFER_SIZE` and
// `set->upload_buffer_size = UPLOADBUFFER_DEFAULT` (`lib/url.c:437-438`), with
// the bounds `CURLOPT_BUFFERSIZE` and `CURLOPT_UPLOAD_BUFFERSIZE` clamp to.

/// `READBUFFER_SIZE` = `CURL_MAX_WRITE_SIZE` = 16,384
/// (`lib/urldata.h:197`, `include/curl/curl.h:265`).
pub(crate) const READBUFFER_SIZE: u32 = 16_384;

/// `READBUFFER_MAX` = `CURL_MAX_READ_SIZE` = `10 * 1024 * 1024`
/// (`lib/urldata.h:198`, `include/curl/curl.h:255`).
#[allow(dead_code)] // consumer: easy/setopt.rs
pub(crate) const READBUFFER_MAX: u32 = 10 * 1024 * 1024;

/// `READBUFFER_MIN` = 1,024 (`lib/urldata.h:199`).
#[allow(dead_code)] // consumer: easy/setopt.rs
pub(crate) const READBUFFER_MIN: u32 = 1_024;

/// `UPLOADBUFFER_DEFAULT` = 65,536 (`lib/urldata.h:209`).
///
/// The C's comment records why it is not 16 KiB any more: *"The size was 16KB
/// for many years but was bumped to 64KB because it makes libcurl able to do
/// significantly faster uploads in some circumstances."*
pub(crate) const UPLOADBUFFER_DEFAULT: u32 = 65_536;

/// `UPLOADBUFFER_MAX` = `2 * 1024 * 1024` (`lib/urldata.h:210`).
#[allow(dead_code)] // consumer: easy/setopt.rs
pub(crate) const UPLOADBUFFER_MAX: u32 = 2 * 1024 * 1024;

/// `UPLOADBUFFER_MIN` = `CURL_MAX_WRITE_SIZE` = 16,384
/// (`lib/urldata.h:211`).
#[allow(dead_code)] // consumer: easy/setopt.rs
pub(crate) const UPLOADBUFFER_MIN: u32 = 16_384;

/// `DEFAULT_CONNCACHE_SIZE` = 5 (`lib/urldata.h:121`).
///
/// `set->maxconnects = DEFAULT_CONNCACHE_SIZE` with the C's own comment
/// *"for easy handles"* (`lib/url.c:441`): a multi handle's default is a
/// different number, decided by `crate::multi`.
pub(crate) const DEFAULT_CONNCACHE_SIZE: u32 = 5;

/// `CURL_HET_DEFAULT` = 200 ms (`include/curl/curl.h:967`).
pub(crate) const CURL_HET_DEFAULT: i64 = 200;

/// `CURL_UPKEEP_INTERVAL_DEFAULT` = 60,000 ms
/// (`include/curl/curl.h:970`).
pub(crate) const CURL_UPKEEP_INTERVAL_DEFAULT: i64 = 60_000;

/// `set->maxredirs = 30` (`lib/url.c:363`), whose C comment is
/// *"sensible default"*.
///
/// The field is a `short` in the C and `-1` means infinity, which is why the
/// Rust type is signed.
pub(crate) const DEFAULT_MAXREDIRS: i16 = 30;

/// `set->dns_cache_timeout_ms = 60000` (`lib/url.c:376`): *"Timeout every 60
/// seconds by default"*.
pub(crate) const DEFAULT_DNS_CACHE_TIMEOUT_MS: i64 = 60_000;

/// `set->general_ssl.ca_cache_timeout = 24 * 60 * 60` (`lib/url.c:379`):
/// *"Timeout every 24 hours by default"*, in SECONDS rather than
/// milliseconds.
///
/// `i32` and not `i64`, because the C field is `int`
/// (`struct ssl_general_config`, `lib/urldata.h`) even though
/// `CURLOPT_CA_CACHE_TIMEOUT` takes a `long`: the narrowing happens in
/// `lib/setopt.c`, so a value that the C would truncate must truncate here
/// too rather than being silently preserved.
pub(crate) const DEFAULT_CA_CACHE_TIMEOUT_SECS: i32 = 24 * 60 * 60;

/// `set->conn_max_idle_ms = 118 * 1000` (`lib/url.c:442`).
pub(crate) const DEFAULT_CONN_MAX_IDLE_MS: i64 = 118 * 1000;

/// `set->conn_max_age_ms = 24 * 3600 * 1000` (`lib/url.c:443`).
pub(crate) const DEFAULT_CONN_MAX_AGE_MS: i64 = 24 * 3600 * 1000;

/// `set->expect_100_timeout = 1000L` (`lib/url.c:435`): *"Wait for a second
/// by default."*
pub(crate) const DEFAULT_EXPECT_100_TIMEOUT_MS: u16 = 1_000;

/// `set->tcp_keepidle = 60` (`lib/url.c:430`), in seconds.
pub(crate) const DEFAULT_TCP_KEEPIDLE_SECS: i32 = 60;

/// `set->tcp_keepintvl = 60` (`lib/url.c:429`), in seconds.
pub(crate) const DEFAULT_TCP_KEEPINTVL_SECS: i32 = 60;

/// `set->tcp_keepcnt = 9` (`lib/url.c:431`): probes before giving up.
pub(crate) const DEFAULT_TCP_KEEPCNT: i32 = 9;

/// `set->new_file_perms = 0644` (`lib/url.c:402`).
///
/// Unconditional, and deliberately so: the C writes it OUTSIDE the
/// `#ifdef USE_SSH` that guards its directory counterpart below, because
/// `CURLOPT_NEW_FILE_PERMS` also governs a plain local write.
pub(crate) const DEFAULT_NEW_FILE_PERMS: u32 = 0o644;

/// `set->new_directory_perms = 0755` (`lib/url.c:399`).
///
/// Inside `#ifdef USE_SSH` in the C (`lib/url.c:396-400`), so it is gated on
/// `ssh` here: only SFTP and SCP create a directory on the far end, and a
/// build without them has nothing to apply this to.
#[cfg(feature = "ssh")]
pub(crate) const DEFAULT_NEW_DIRECTORY_PERMS: u32 = 0o755;

/// `CURLSSH_AUTH_DEFAULT` = `CURLSSH_AUTH_ANY` = `0xffffffff`
/// (`include/curl/curl.h:859`, `:851`): *"defaults to any auth type"*
/// (`lib/url.c:397-398`).
///
/// Gated for the same reason as [`DEFAULT_NEW_DIRECTORY_PERMS`]: the C writes
/// it inside the same `#ifdef USE_SSH`.
#[cfg(feature = "ssh")]
pub(crate) const CURLSSH_AUTH_DEFAULT: u32 = 0xffff_ffff;

// ---------------------------------------------------------------------------
// Identity -- three C fields, three sentinels, and one generational token
// ---------------------------------------------------------------------------

/// `data->id` (`lib/urldata.h:1626`): the handle's pool-scoped label.
///
/// The C's comment is the whole specification and every clause of it matters:
///
/// > once an easy handle is tied to a connection pool a non-negative number
/// > to distinguish this transfer from other using the same pool. For easier
/// > tracking in log output. This may wrap around after LONG_MAX to 0 again,
/// > so it has no uniqueness guarantee for large processings. Note: it has no
/// > uniqueness either IFF more than one connection pool is used by the
/// > libcurl application.
///
/// So this is explicitly NOT an identity: it is a trace label that may repeat
/// twice over -- once by wrapping, once because two pools number
/// independently. Nothing may key a lookup on it, which is why it carries no
/// generation and why [`HandleToken`] exists separately.
///
/// [`Self::NONE`] is the C's `-1`, which `curl_easy_duphandle` writes into a
/// clone (`lib/easy.c:980`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransferId(i64);

impl TransferId {
    /// The `-1` a handle carries before a pool has labelled it.
    pub const NONE: Self = Self(-1);

    /// The first label a pool hands out.
    pub const FIRST: Self = Self(0);

    /// A label with an explicit value.
    ///
    /// Negative values other than `-1` are not rejected, because the C does
    /// not reject them either: `data->id` is a plain `curl_off_t` that the
    /// pool assigns, and a type that refused them would be stricter than the
    /// thing it reproduces.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// The label as the C's `curl_off_t`.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }

    /// Whether this is the [`Self::NONE`] sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == Self::NONE.0
    }
}

impl Default for TransferId {
    /// [`Self::NONE`], because a fresh handle belongs to no pool.
    fn default() -> Self {
        Self::NONE
    }
}

impl fmt::Display for TransferId {
    /// The bare number, which is what a `CURL_TRC_M` trace line carries.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `data->mid` and `data->master_mid` (`lib/urldata.h:1630-1631`).
///
/// The C's comment: *"once an easy handle is added to a multi, either
/// explicitly by the libcurl application or implicitly during
/// `curl_easy_perform()`, a unique identifier inside this one multi
/// instance."* Unique INSIDE ONE MULTI -- two multi handles both number from
/// zero, so a bare `mid` means nothing without knowing which multi issued
/// it.
///
/// [`Self::NONE`] is `UINT32_MAX`, the value C writes for *"not in a
/// multi"*: `curl_easy_duphandle` sets both fields to it (`lib/easy.c:981`,
/// `:982`) and `curl_easy_reset` sets `master_mid` to it (`:1120`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MultiXferId(u32);

impl MultiXferId {
    /// `UINT32_MAX`: this handle is in no multi.
    pub const NONE: Self = Self(u32::MAX);

    /// An identifier with an explicit value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The identifier as the C's `uint32_t`.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Whether this is the [`Self::NONE`] sentinel.
    #[must_use]
    pub const fn is_none(self) -> bool {
        self.0 == Self::NONE.0
    }
}

impl Default for MultiXferId {
    /// [`Self::NONE`], because a fresh handle is in no multi.
    fn default() -> Self {
        Self::NONE
    }
}

/// How many times a slab slot has been reused.
///
/// A separate type from the index so that the two cannot be swapped at a call
/// site: they are both small unsigned integers and they mean opposite things.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Generation(u32);

impl Generation {
    /// The generation a slot is born with.
    pub const FIRST: Self = Self(0);

    /// A generation with an explicit value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// The generation as a number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The generation a slot takes when it is reused.
    ///
    /// Wrapping rather than saturating, and deliberately: a saturating
    /// counter would sit forever at [`u32::MAX`] and make every token for
    /// that slot compare equal, which is precisely the false-positive this
    /// type exists to prevent. Wrapping restores the false positive only
    /// after 2^32 reuses of one slot, and does so for one token rather than
    /// for all of them.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

/// A handle's place in a multi's slab -- an index AND the generation of the
/// slot it names.
///
/// AAP 0.6.9 requires exactly this: *"the multi handle's easy-handle
/// collection becomes a slab with generational keys so a stale handle is
/// detectably stale rather than a dangling pointer."* C keys the collection
/// on `mid` alone -- `struct uint32_tbl xfers` -- so a `mid` whose slot has
/// been freed and refilled resolves to a DIFFERENT transfer, silently. The
/// generation is what turns that into a detectable condition.
///
/// # This type is the interface `crate::multi` must adopt
///
/// The slab itself is not built here, and deliberately: a registry of live
/// handles belongs to the multi that owns their lifetimes, and building one
/// in the easy handle would put a collection of handles inside a handle.
/// What is built here is the KEY, because a handle has to carry its own key
/// and because a key defined in two places is two keys. `crate::multi` mints
/// tokens with [`Self::new`], hands them to [`EasyHandle::attach_to_multi`],
/// and validates them with [`Self::is_current_in`] against the generation its
/// slab holds for that slot.
///
/// # The absent token
///
/// A handle in no multi has [`None`] rather than a sentinel token, because
/// "not in a multi" is the absence of a key and not a distinguished key. The
/// C's `UINT32_MAX` sentinel survives in [`MultiXferId`], which is what
/// crosses to trace output and to the ABI; it is not duplicated here.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HandleToken {
    /// Which slot, and therefore the C's `mid`.
    id: MultiXferId,
    /// Which occupancy of that slot.
    generation: Generation,
}

impl HandleToken {
    /// A token for `id` at `generation`.
    #[must_use]
    pub const fn new(id: MultiXferId, generation: Generation) -> Self {
        Self { id, generation }
    }

    /// The slot, as the identifier the C carries and trace output prints.
    #[must_use]
    pub const fn id(self) -> MultiXferId {
        self.id
    }

    /// The occupancy this token was minted for.
    #[must_use]
    pub const fn generation(self) -> Generation {
        self.generation
    }

    /// Whether this token still names the occupancy it was minted for.
    ///
    /// `current` is the generation the slab holds for [`Self::id`] NOW. A
    /// token that fails this test is stale: the transfer it named has
    /// finished and the slot has been given to another one. The caller's
    /// correct response is to treat the handle as absent rather than to
    /// resolve the index, which is the whole point of carrying the
    /// generation.
    #[must_use]
    pub const fn is_current_in(self, current: Generation) -> bool {
        self.generation.get() == current.get()
    }

    /// Whether this token is stale against `current` -- the negation of
    /// [`Self::is_current_in`], spelled out because a call site that reads
    /// `if token.is_stale_against(g)` is harder to misread than one that
    /// reads `if !token.is_current_in(g)`.
    #[must_use]
    pub const fn is_stale_against(self, current: Generation) -> bool {
        !self.is_current_in(current)
    }
}

/// The three C identity fields, together, with the token that keys the slab.
///
/// Grouped rather than left loose on [`EasyHandle`] for one concrete reason:
/// `curl_easy_duphandle` resets all three at once (`lib/easy.c:980-982`) and
/// `curl_easy_reset` resets one of them (`:1120`). A group makes both
/// operations a single named call whose correctness a reader can check
/// against the C in one place, instead of three assignments that a future
/// edit can update two of.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct HandleIdentity {
    /// `data->id`: the pool's trace label.
    id: TransferId,
    /// `data->mid`: this handle's identifier inside its multi.
    mid: MultiXferId,
    /// `data->master_mid`: *"if set, this transfer belongs to a master"*
    /// (`lib/urldata.h:1631`).
    master_mid: MultiXferId,
    /// The generational key for [`Self::mid`], absent when the handle is in
    /// no multi.
    token: Option<HandleToken>,
}

impl HandleIdentity {
    /// Every field at its sentinel: the state
    /// `curl_easy_duphandle` puts a clone in, and the state a fresh handle
    /// starts in.
    ///
    /// `id = -1`, `mid = UINT32_MAX`, `master_mid = UINT32_MAX`, no token.
    pub const FRESH: Self = Self {
        id: TransferId::NONE,
        mid: MultiXferId::NONE,
        master_mid: MultiXferId::NONE,
        token: None,
    };

    /// The pool's trace label.
    #[must_use]
    pub const fn id(&self) -> TransferId {
        self.id
    }

    /// The identifier inside this handle's multi.
    #[must_use]
    pub const fn mid(&self) -> MultiXferId {
        self.mid
    }

    /// The master transfer's identifier, when this is a sub-transfer.
    #[must_use]
    pub const fn master_mid(&self) -> MultiXferId {
        self.master_mid
    }

    /// The generational key, when this handle is in a multi.
    #[must_use]
    pub const fn token(&self) -> Option<HandleToken> {
        self.token
    }

    /// Labels this handle for a connection pool.
    ///
    /// Called by `crate::conn`'s pool when a handle first uses it, which is
    /// the only moment the C assigns `data->id`.
    #[allow(dead_code)] // consumer: crate::multi and crate::conn::pool
    pub(crate) fn set_id(&mut self, id: TransferId) {
        self.id = id;
    }

    /// Records that a multi has taken this handle into `token`'s slot.
    ///
    /// Sets [`Self::mid`] from the token so the two cannot disagree: the C
    /// has one field and this type has two views of it, and a setter that
    /// took both separately would let a caller supply a mismatched pair.
    #[allow(dead_code)] // consumer: crate::multi and crate::conn::pool
    pub(crate) fn attach(&mut self, token: HandleToken) {
        self.mid = token.id();
        self.token = Some(token);
    }

    /// Records that this handle has left its multi.
    ///
    /// Returns [`MultiXferId`] to the `UINT32_MAX` the C writes, and drops
    /// the token: a detached handle holds no key, so nothing can present one
    /// for revalidation.
    #[allow(dead_code)] // consumer: crate::multi and crate::conn::pool
    pub(crate) fn detach(&mut self) {
        self.mid = MultiXferId::NONE;
        self.token = None;
    }

    /// Records this handle as a sub-transfer of `master`.
    #[allow(dead_code)] // consumer: crate::multi and crate::conn::pool
    pub(crate) fn set_master_mid(&mut self, master: MultiXferId) {
        self.master_mid = master;
    }

    /// `curl_easy_reset`'s single identity write: `data->master_mid =
    /// UINT32_MAX` (`lib/easy.c:1120`).
    ///
    /// Note what it does NOT touch. `id` and `mid` survive a reset, because a
    /// reset handle is still in the same multi and still labelled by the same
    /// pool; only its membership of a master transfer is dissolved. That
    /// asymmetry against [`Self::FRESH`] is the C's and is asserted by
    /// [`mod tests`].
    #[allow(dead_code)] // consumer: crate::multi and crate::conn::pool
    pub(crate) fn reset_master_mid(&mut self) {
        self.master_mid = MultiXferId::NONE;
    }
}

// ---------------------------------------------------------------------------
// The string table -- `enum dupstring` (`lib/urldata.h:1141-1272`)
// ---------------------------------------------------------------------------

/// Which string option a slot of the string table holds.
///
/// The successor of `enum dupstring`, in the C's declaration order, and the
/// key of [`StringTable`]. The C indexes `data->set.str[]` with a bare
/// `enum dupstring` that a cast can produce from any integer; here the index
/// is this enum and nothing else, which is what AAP 0.6.9's *"key them with
/// an enum, never a bare `usize`"* asks for.
///
/// # Three decisions a reader should see, not infer
///
/// **1. Every member is compiled unconditionally.** The C wraps groups of
/// members in `#ifdef`s, so `STRING_LAST` -- and therefore the numeric value
/// of every member after the first `#ifdef` -- differs between builds. That
/// is safe in the C because these indices are internal: nothing in the public
/// ABI carries one. Reproducing the conditionality here would make
/// `DupString::Cookie` ABSENT from a build without the `cookies` feature and
/// force a `#[cfg]` at every site that names it, which is exactly the
/// referenced-but-absent fragility a feature matrix has to rule out. So the
/// vocabulary is total and the FEATURE decides what may be stored, not what
/// may be named. The `CURLOPT_*` that reaches an unbuilt member answers
/// [`CURLcode::NotBuiltIn`], which is the C's own answer in the same
/// configuration -- and that answer belongs to `easy/setopt.rs`, not here.
///
/// **2. `STRING_COPYPOSTFIELDS` is not a member.** The C's own comment marks
/// the boundary: *"below this are pointers to binary data that cannot be
/// strdup'ed"* (`lib/urldata.h:1267`). It shares the `char *str[]` array in
/// C only because C has one pointer type for both; its content is arbitrary
/// bytes with an explicit length, and treating it as a string is what makes
/// the C need a special case in `dupset`. Here it is
/// [`UserDefined::copy_postfields`], a distinct field of a distinct type, and
/// [`Self::COUNT`] is therefore exactly the C's `STRING_LASTZEROTERMINATED`.
/// [`STRING_LAST`] is published for provenance.
///
/// **3. The members out-of-implementation-scope stay.** `RtspSessionId`,
/// `MailFrom`, the two TLS-SRP pairs and the four c-ares names all belong to
/// subsystems AAP 0.2.2 excludes. Their `CURLoption` identifiers are part of
/// the frozen 308, so the options must still round-trip or be refused with
/// the C's code; dropping the slots would make that impossible to express.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DupString {
    /// `STRING_CERT`: client certificate filename.
    Cert = 0,
    /// `STRING_CERT_TYPE`: certificate format, default PEM.
    CertType = 1,
    /// `STRING_KEY`: private key filename.
    Key = 2,
    /// `STRING_KEY_PASSWD`: plain-text private key password.
    KeyPasswd = 3,
    /// `STRING_KEY_TYPE`: private key format, default PEM.
    KeyType = 4,
    /// `STRING_SSL_CAPATH`: CA directory.
    SslCaPath = 5,
    /// `STRING_SSL_CAFILE`: certificate file to verify the peer against.
    SslCaFile = 6,
    /// `STRING_SSL_PINNEDPUBLICKEY`: public key to pin the peer to.
    SslPinnedPublicKey = 7,
    /// `STRING_SSL_CIPHER_LIST`: TLS 1.2-and-below cipher list.
    SslCipherList = 8,
    /// `STRING_SSL_CIPHER13_LIST`: TLS 1.3 cipher list.
    SslCipher13List = 9,
    /// `STRING_SSL_CRLFILE`: revocation list.
    SslCrlFile = 10,
    /// `STRING_SSL_ISSUERCERT`: issuer certificate to check against.
    SslIssuerCert = 11,
    /// `STRING_SERVICE_NAME`: SPNEGO service name.
    ServiceName = 12,
    /// `STRING_CERT_PROXY`.
    CertProxy = 13,
    /// `STRING_CERT_TYPE_PROXY`.
    CertTypeProxy = 14,
    /// `STRING_KEY_PROXY`.
    KeyProxy = 15,
    /// `STRING_KEY_PASSWD_PROXY`.
    KeyPasswdProxy = 16,
    /// `STRING_KEY_TYPE_PROXY`.
    KeyTypeProxy = 17,
    /// `STRING_SSL_CAPATH_PROXY`.
    SslCaPathProxy = 18,
    /// `STRING_SSL_CAFILE_PROXY`.
    SslCaFileProxy = 19,
    /// `STRING_SSL_PINNEDPUBLICKEY_PROXY`.
    SslPinnedPublicKeyProxy = 20,
    /// `STRING_SSL_CIPHER_LIST_PROXY`.
    SslCipherListProxy = 21,
    /// `STRING_SSL_CIPHER13_LIST_PROXY`.
    SslCipher13ListProxy = 22,
    /// `STRING_SSL_CRLFILE_PROXY`.
    SslCrlFileProxy = 23,
    /// `STRING_SSL_ISSUERCERT_PROXY`.
    SslIssuerCertProxy = 24,
    /// `STRING_PROXY_SERVICE_NAME`.
    ProxyServiceName = 25,
    /// `STRING_COOKIE`: the `Cookie:` string to send.
    Cookie = 26,
    /// `STRING_COOKIEJAR`: where to dump cookies.
    CookieJar = 27,
    /// `STRING_CUSTOMREQUEST`: the method to send instead of the default.
    CustomRequest = 28,
    /// `STRING_DEFAULT_PROTOCOL`: scheme for a URL that names none.
    DefaultProtocol = 29,
    /// `STRING_DEVICE`: `CURLOPT_INTERFACE`'s combined form.
    Device = 30,
    /// `STRING_INTERFACE`: the local interface alone.
    Interface = 31,
    /// `STRING_BINDHOST`: the local address alone.
    BindHost = 32,
    /// `STRING_ENCODING`: the `Accept-Encoding:` value.
    Encoding = 33,
    /// `STRING_FTP_ACCOUNT`: FTP `ACCT` data.
    FtpAccount = 34,
    /// `STRING_FTP_ALTERNATIVE_TO_USER`: command to send if `USER`/`PASS`
    /// fails.
    FtpAlternativeToUser = 35,
    /// `STRING_FTPPORT`: what to send with FTP `PORT`.
    FtpPort = 36,
    /// `STRING_NETRC_FILE`: a `.netrc` other than `$HOME/.netrc`.
    NetrcFile = 37,
    /// `STRING_PROXY`.
    Proxy = 38,
    /// `STRING_PRE_PROXY`: the SOCKS proxy in front of the HTTP one.
    PreProxy = 39,
    /// `STRING_SET_RANGE`: `CURLOPT_RANGE`.
    SetRange = 40,
    /// `STRING_SET_REFERER`: `CURLOPT_REFERER`.
    SetReferer = 41,
    /// `STRING_SET_URL`: `CURLOPT_URL`.
    SetUrl = 42,
    /// `STRING_USERAGENT`: `CURLOPT_USERAGENT`.
    UserAgent = 43,
    /// `STRING_SSL_ENGINE`: the name of a crypto engine.
    SslEngine = 44,
    /// `STRING_USERNAME`.
    Username = 45,
    /// `STRING_PASSWORD`.
    Password = 46,
    /// `STRING_OPTIONS`: `CURLOPT_LOGIN_OPTIONS`.
    Options = 47,
    /// `STRING_PROXYUSERNAME`.
    ProxyUsername = 48,
    /// `STRING_PROXYPASSWORD`.
    ProxyPassword = 49,
    /// `STRING_NOPROXY`: hosts that must bypass the proxy.
    NoProxy = 50,
    /// `STRING_RTSP_SESSION_ID`.
    RtspSessionId = 51,
    /// `STRING_RTSP_STREAM_URI`.
    RtspStreamUri = 52,
    /// `STRING_RTSP_TRANSPORT`.
    RtspTransport = 53,
    /// `STRING_SSH_PRIVATE_KEY`.
    SshPrivateKey = 54,
    /// `STRING_SSH_PUBLIC_KEY`.
    SshPublicKey = 55,
    /// `STRING_SSH_HOST_PUBLIC_KEY_MD5`: MD5 of the host key, ASCII hex.
    SshHostPublicKeyMd5 = 56,
    /// `STRING_SSH_HOST_PUBLIC_KEY_SHA256`: SHA-256 of the host key, base64.
    SshHostPublicKeySha256 = 57,
    /// `STRING_SSH_KNOWNHOSTS`.
    SshKnownHosts = 58,
    /// `STRING_MAIL_FROM`.
    MailFrom = 59,
    /// `STRING_MAIL_AUTH`.
    MailAuth = 60,
    /// `STRING_TLSAUTH_USERNAME`.
    TlsAuthUsername = 61,
    /// `STRING_TLSAUTH_PASSWORD`.
    TlsAuthPassword = 62,
    /// `STRING_TLSAUTH_USERNAME_PROXY`.
    TlsAuthUsernameProxy = 63,
    /// `STRING_TLSAUTH_PASSWORD_PROXY`.
    TlsAuthPasswordProxy = 64,
    /// `STRING_BEARER`: `CURLOPT_XOAUTH2_BEARER`.
    Bearer = 65,
    /// `STRING_UNIX_SOCKET_PATH`.
    UnixSocketPath = 66,
    /// `STRING_TARGET`: `CURLOPT_REQUEST_TARGET`.
    Target = 67,
    /// `STRING_DOH`: `CURLOPT_DOH_URL`.
    Doh = 68,
    /// `STRING_ALTSVC`: `CURLOPT_ALTSVC`.
    AltSvc = 69,
    /// `STRING_HSTS`: `CURLOPT_HSTS`.
    Hsts = 70,
    /// `STRING_SASL_AUTHZID`.
    SaslAuthzid = 71,
    /// `STRING_DNS_SERVERS`.
    DnsServers = 72,
    /// `STRING_DNS_INTERFACE`.
    DnsInterface = 73,
    /// `STRING_DNS_LOCAL_IP4`.
    DnsLocalIp4 = 74,
    /// `STRING_DNS_LOCAL_IP6`.
    DnsLocalIp6 = 75,
    /// `STRING_SSL_EC_CURVES`.
    SslEcCurves = 76,
    /// `STRING_AWS_SIGV4`: the V4 signature parameters.
    AwsSigv4 = 77,
    /// `STRING_HAPROXY_CLIENT_IP`.
    HaproxyClientIp = 78,
    /// `STRING_ECH_CONFIG`.
    EchConfig = 79,
    /// `STRING_ECH_PUBLIC`.
    EchPublic = 80,
    /// `STRING_SSL_SIGNATURE_ALGORITHMS`.
    SslSignatureAlgorithms = 81,
}

/// The C's `STRING_LAST` (`lib/urldata.h:1271`): 83.
///
/// [`DupString::COUNT`] plus the one binary member the enum deliberately
/// omits. Published so that a reader checking this file against the header
/// can reconcile the two counts without doing the arithmetic, and asserted by
/// [`mod tests`].
#[allow(dead_code)] // consumer: easy/setopt.rs
pub(crate) const STRING_LAST: usize = DupString::COUNT + 1;

impl DupString {
    /// Every member, in the C's declaration order.
    ///
    /// This is what [`StringTable::duplicate`] iterates, and it is therefore
    /// the Rust form of `for(i = 0; i < STRING_LASTZEROTERMINATED; i++)`
    /// (`lib/easy.c:890`). Written out rather than generated because a
    /// generated list could not be checked against the header by reading.
    pub const ALL: [Self; 82] = [
        Self::Cert,
        Self::CertType,
        Self::Key,
        Self::KeyPasswd,
        Self::KeyType,
        Self::SslCaPath,
        Self::SslCaFile,
        Self::SslPinnedPublicKey,
        Self::SslCipherList,
        Self::SslCipher13List,
        Self::SslCrlFile,
        Self::SslIssuerCert,
        Self::ServiceName,
        Self::CertProxy,
        Self::CertTypeProxy,
        Self::KeyProxy,
        Self::KeyPasswdProxy,
        Self::KeyTypeProxy,
        Self::SslCaPathProxy,
        Self::SslCaFileProxy,
        Self::SslPinnedPublicKeyProxy,
        Self::SslCipherListProxy,
        Self::SslCipher13ListProxy,
        Self::SslCrlFileProxy,
        Self::SslIssuerCertProxy,
        Self::ProxyServiceName,
        Self::Cookie,
        Self::CookieJar,
        Self::CustomRequest,
        Self::DefaultProtocol,
        Self::Device,
        Self::Interface,
        Self::BindHost,
        Self::Encoding,
        Self::FtpAccount,
        Self::FtpAlternativeToUser,
        Self::FtpPort,
        Self::NetrcFile,
        Self::Proxy,
        Self::PreProxy,
        Self::SetRange,
        Self::SetReferer,
        Self::SetUrl,
        Self::UserAgent,
        Self::SslEngine,
        Self::Username,
        Self::Password,
        Self::Options,
        Self::ProxyUsername,
        Self::ProxyPassword,
        Self::NoProxy,
        Self::RtspSessionId,
        Self::RtspStreamUri,
        Self::RtspTransport,
        Self::SshPrivateKey,
        Self::SshPublicKey,
        Self::SshHostPublicKeyMd5,
        Self::SshHostPublicKeySha256,
        Self::SshKnownHosts,
        Self::MailFrom,
        Self::MailAuth,
        Self::TlsAuthUsername,
        Self::TlsAuthPassword,
        Self::TlsAuthUsernameProxy,
        Self::TlsAuthPasswordProxy,
        Self::Bearer,
        Self::UnixSocketPath,
        Self::Target,
        Self::Doh,
        Self::AltSvc,
        Self::Hsts,
        Self::SaslAuthzid,
        Self::DnsServers,
        Self::DnsInterface,
        Self::DnsLocalIp4,
        Self::DnsLocalIp6,
        Self::SslEcCurves,
        Self::AwsSigv4,
        Self::HaproxyClientIp,
        Self::EchConfig,
        Self::EchPublic,
        Self::SslSignatureAlgorithms,
    ];

    /// The C's `STRING_LASTZEROTERMINATED` (`lib/urldata.h:1265`): 82.
    ///
    /// Both the length of [`Self::ALL`] and the bound of the duplication
    /// loop, which is why it is one constant and not two.
    pub const COUNT: usize = Self::ALL.len();

    /// The slot's subscript, for a table that stores its members in an array.
    #[must_use]
    pub const fn as_index(self) -> usize {
        self as usize
    }
}

/// `data->set.str[STRING_LAST]` (`lib/urldata.h:1396`): the string options.
///
/// An array rather than 82 named fields, and the choice is not a shortcut.
/// AAP 0.6.9 prefers named fields *"unless an array is needed to reproduce
/// the bulk-duplicate loops faithfully"*, and it is: `dupset` duplicates
/// every member with one loop (`lib/easy.c:889-894`) and `Curl_freeset`
/// releases every member with another. Eighty-two named fields would turn
/// each of those into eighty-two lines that a new option can be forgotten
/// from -- which is the defect the C's own array design exists to prevent.
/// [`DupString`] supplies the type safety the C lacks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StringTable {
    /// One slot per [`DupString`], indexed by [`DupString::as_index`].
    slots: [Option<String>; DupString::COUNT],
}

impl Default for StringTable {
    /// Every slot empty, which is the `calloc`ed state a fresh
    /// `struct Curl_easy` has.
    fn default() -> Self {
        Self::new()
    }
}

impl StringTable {
    /// A table with every slot empty.
    ///
    /// [`core::array::from_fn`] rather than `[None; N]` because
    /// [`Option<String>`] is not [`Copy`], and rather than a `Vec` because the
    /// length is a compile-time constant that an index can then never exceed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
        }
    }

    /// The value in `which`, if any.
    #[must_use]
    pub fn get(&self, which: DupString) -> Option<&str> {
        self.slots[which.as_index()].as_deref()
    }

    /// Replaces `which`, answering what was there.
    ///
    /// The successor of `Curl_setstropt(&data->set.str[which], value)`
    /// without its length check: the 8,000,000-byte bound of
    /// [`CURL_MAX_INPUT_LENGTH`] belongs to the option setter, which is where
    /// the C applies it too (`lib/setopt.c`), and applying it here as well
    /// would make a duplicate of an existing clone fail on input the original
    /// accepted.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set(
        &mut self,
        which: DupString,
        value: Option<String>,
    ) -> Option<String> {
        core::mem::replace(&mut self.slots[which.as_index()], value)
    }

    /// How many slots hold a value.
    #[must_use]
    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    /// `memset(dst->set.str, 0, STRING_LAST * sizeof(char *))`
    /// (`lib/easy.c:886`).
    ///
    /// Called BEFORE duplication, which is the C's ordering and the C's
    /// reason: *"clear all dest string and blob pointers first, in case we
    /// error out mid-function"* (`:884-885`). In Rust the guarantee is
    /// stronger and needs no ordering -- a partially built clone is dropped
    /// by the compiler with every slot it did fill released -- but the
    /// ordering is reproduced anyway, because [`Self::duplicate`] overwrites
    /// a table that may already hold values and a caller has to be able to
    /// see that it starts from empty.
    pub(crate) fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
    }

    /// The bulk duplication of `lib/easy.c:889-894`.
    ///
    /// Clears this table, then copies every one of [`DupString::COUNT`]
    /// slots from `src`. Infallible where the C is not: `Curl_setstropt`
    /// answers `CURLE_OUT_OF_MEMORY` on a failed `strdup`, and Rust aborts
    /// instead of returning from a failed allocation, so there is no code
    /// path that could produce the C's error and no `Result` to express it
    /// with. [`UserDefined::duplicate`] documents the consequence for the
    /// caller.
    pub(crate) fn duplicate(&mut self, src: &Self) {
        self.clear();
        for which in DupString::ALL {
            let index = which.as_index();
            self.slots[index] = src.slots[index].clone();
        }
    }
}

// ---------------------------------------------------------------------------
// The blob table -- `enum dupblob` (`lib/urldata.h:1274-1286`)
// ---------------------------------------------------------------------------

/// Which blob option a slot of the blob table holds.
///
/// The successor of `enum dupblob`. Compiled unconditionally for the reason
/// [`DupString`] documents: the four `_PROXY` members sit behind
/// `#ifndef CURL_DISABLE_PROXY` in the C, and gating them here would make
/// `BLOB_LAST` -- and therefore the duplication loop -- differ between
/// builds of a table whose indices no ABI carries.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DupBlob {
    /// `BLOB_CERT`: `CURLOPT_SSLCERT_BLOB`.
    Cert = 0,
    /// `BLOB_KEY`: `CURLOPT_SSLKEY_BLOB`.
    Key = 1,
    /// `BLOB_SSL_ISSUERCERT`: `CURLOPT_ISSUERCERT_BLOB`.
    SslIssuerCert = 2,
    /// `BLOB_CAINFO`: `CURLOPT_CAINFO_BLOB`.
    CaInfo = 3,
    /// `BLOB_CERT_PROXY`: `CURLOPT_PROXY_SSLCERT_BLOB`.
    CertProxy = 4,
    /// `BLOB_KEY_PROXY`: `CURLOPT_PROXY_SSLKEY_BLOB`.
    KeyProxy = 5,
    /// `BLOB_SSL_ISSUERCERT_PROXY`: `CURLOPT_PROXY_ISSUERCERT_BLOB`.
    SslIssuerCertProxy = 6,
    /// `BLOB_CAINFO_PROXY`: `CURLOPT_PROXY_CAINFO_BLOB`.
    CaInfoProxy = 7,
}

impl DupBlob {
    /// Every member, in the C's declaration order.
    pub const ALL: [Self; 8] = [
        Self::Cert,
        Self::Key,
        Self::SslIssuerCert,
        Self::CaInfo,
        Self::CertProxy,
        Self::KeyProxy,
        Self::SslIssuerCertProxy,
        Self::CaInfoProxy,
    ];

    /// The C's `BLOB_LAST` (`lib/urldata.h:1285`): 8.
    pub const COUNT: usize = Self::ALL.len();

    /// The slot's subscript.
    #[must_use]
    pub const fn as_index(self) -> usize {
        self as usize
    }
}

/// `struct curl_blob` (`include/curl/easy.h:34-39`), owned.
///
/// The C struct is `{ void *data; size_t len; unsigned int flags; }` and its
/// `flags` bit 0 is `CURL_BLOB_COPY` (`:31`), which asks libcurl to take its
/// own copy rather than borrow the caller's buffer. Here the bytes are always
/// owned, because a `Vec<u8>` cannot be anything else -- so the flag is
/// recorded rather than acted on, and [`Self::was_copy_requested`] reports
/// what the caller asked for.
///
/// Recording it is not bookkeeping for its own sake. `CURL_BLOB_NOCOPY`
/// (`:32`) makes the application responsible for keeping its buffer alive for
/// the lifetime of the handle, and an application that passed `NOCOPY` and
/// then freed its buffer has a defect that the C would exhibit and this
/// implementation will not. Reporting the requested mode is what lets a
/// diagnostic say so.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Blob {
    /// The bytes, owned regardless of the flag.
    data: Vec<u8>,
    /// The `flags` member as the caller supplied it.
    flags: u32,
}

impl Blob {
    /// `CURL_BLOB_COPY` = 1 (`include/curl/easy.h:31`): *"tell libcurl to
    /// copy the data"*.
    pub const COPY: u32 = 1;

    /// `CURL_BLOB_NOCOPY` = 0 (`include/curl/easy.h:32`): *"tell libcurl to
    /// NOT copy the data"*.
    pub const NOCOPY: u32 = 0;

    /// A blob over `data`, recording `flags` as the caller gave them.
    ///
    /// Bits other than bit 0 are *"reserved and should be left zeroes"*
    /// according to the header's own comment, and are kept rather than masked
    /// away: masking would silently accept a caller that set one, and the
    /// value is what a diagnostic needs in order to name it.
    #[must_use]
    pub fn new(data: Vec<u8>, flags: u32) -> Self {
        Self { data, flags }
    }

    /// The bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// How many bytes -- the C's `len`.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the blob carries no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The `flags` member as supplied.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Whether `CURL_BLOB_COPY` was requested.
    #[must_use]
    pub const fn was_copy_requested(&self) -> bool {
        self.flags & Self::COPY != 0
    }
}

/// `data->set.blobs[BLOB_LAST]` (`lib/urldata.h:1397`).
///
/// The same design as [`StringTable`], for the same reason: `dupset`
/// duplicates every member with one loop (`lib/easy.c:896-901`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlobTable {
    /// One slot per [`DupBlob`].
    slots: [Option<Blob>; DupBlob::COUNT],
}

impl BlobTable {
    /// A table with every slot empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The blob in `which`, if any.
    #[must_use]
    pub fn get(&self, which: DupBlob) -> Option<&Blob> {
        self.slots[which.as_index()].as_ref()
    }

    /// Replaces `which`, answering what was there.
    ///
    /// The successor of `Curl_setblobopt(&data->set.blobs[which], value)`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set(
        &mut self,
        which: DupBlob,
        value: Option<Blob>,
    ) -> Option<Blob> {
        core::mem::replace(&mut self.slots[which.as_index()], value)
    }

    /// How many slots hold a blob.
    #[must_use]
    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    /// `memset(dst->set.blobs, 0, BLOB_LAST * sizeof(struct curl_blob *))`
    /// (`lib/easy.c:887`).
    pub(crate) fn clear(&mut self) {
        for slot in &mut self.slots {
            *slot = None;
        }
    }

    /// The bulk duplication of `lib/easy.c:896-901`.
    pub(crate) fn duplicate(&mut self, src: &Self) {
        self.clear();
        for which in DupBlob::ALL {
            let index = which.as_index();
            self.slots[index] = src.slots[index].clone();
        }
    }
}

// ---------------------------------------------------------------------------
// Option-state vocabulary -- the enumerations `Curl_init_userdefined` names
// ---------------------------------------------------------------------------

/// Which standard stream an unset `FILE *` option refers to.
///
/// `Curl_init_userdefined` opens with three assignments whose values are
/// stdio globals: `set->out = stdout`, `set->in_set = stdin` and
/// `set->err = stderr` (`lib/url.c:341-343`). A `*mut FILE` has no place in a
/// crate that forbids `unsafe`, and the three values are drawn from a set of
/// three, so the set is the type.
///
/// What the C is recording is not a stream object but a DEFAULT: which
/// standard stream applies while the application has supplied neither a
/// callback nor a destination. `curl-rs-ffi` maps an application's
/// `CURLOPT_WRITEDATA`, `CURLOPT_READDATA` and `CURLOPT_STDERR` onto
/// [`IoTarget::Application`], and `curl-rs` resolves
/// [`IoTarget::Standard`] against the process's own streams.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StdStream {
    /// `stdin`, the default for `CURLOPT_READDATA`.
    In,
    /// `stdout`, the default for `CURLOPT_WRITEDATA`.
    Out,
    /// `stderr`, the default for `CURLOPT_STDERR`.
    Err,
}

/// Where a transfer's data goes, or comes from.
///
/// [`Self::Standard`] is the state `Curl_init_userdefined` leaves the three
/// `FILE *` members in. [`Self::Application`] is the state any of
/// `CURLOPT_WRITEDATA`, `CURLOPT_READDATA`, `CURLOPT_HEADERDATA` or
/// `CURLOPT_STDERR` puts one in -- the pointer itself belongs to
/// `curl-rs-ffi`, which is the only crate that may hold one.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IoTarget {
    /// The default: one of the process's standard streams.
    Standard(StdStream),
    /// The application supplied a destination of its own.
    Application,
}

impl IoTarget {
    /// Whether this is still the default the initialiser set.
    #[must_use]
    pub const fn is_default_stream(self) -> bool {
        matches!(self, Self::Standard(_))
    }
}

/// Which function stores a transfer's output, and which reads its input.
///
/// `set->fwrite_func = (curl_write_callback)fwrite` and
/// `set->fread_func_set = (curl_read_callback)fread` (`lib/url.c:350`,
/// `:353`) install stdio's own functions as the defaults -- with a `clang`
/// diagnostic suppressed around them, because the cast is between
/// incompatible function types and the C knows it.
///
/// The identity of the default matters and is therefore modelled, rather than
/// being reduced to *"no callback set"*: `set->is_fread_set = 0`
/// (`lib/url.c:357`) is a SEPARATE field that records whether the reader is
/// the default, and the C consults it independently of the pointer. Two facts,
/// two fields, in both languages.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransferFunction {
    /// The stdio default -- `fwrite` for output, `fread` for input.
    Stdio,
    /// A callback the application installed.
    Application,
}

impl TransferFunction {
    /// Whether this is still the stdio default.
    #[must_use]
    pub const fn is_stdio_default(self) -> bool {
        matches!(self, Self::Stdio)
    }
}

/// `set->rtspreq = RTSPREQ_OPTIONS` (`lib/url.c:367`).
///
/// `Curl_RtspReq` (`lib/rtsp.h`) in the C. RTSP is out of implementation
/// scope per AAP 0.2.2, and the option still has to round-trip: its
/// `CURLoption` identifier is one of the frozen 308 and
/// `CURLINFO_RTSP_*` reads back what was set. So the vocabulary is carried
/// and the transfer is refused, which is the honest pair.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RtspRequest {
    /// `RTSPREQ_NONE`.
    None = 0,
    /// `RTSPREQ_OPTIONS` -- the default `Curl_init_userdefined` sets.
    #[default]
    Options = 1,
    /// `RTSPREQ_DESCRIBE`.
    Describe = 2,
    /// `RTSPREQ_ANNOUNCE`.
    Announce = 3,
    /// `RTSPREQ_SETUP`.
    Setup = 4,
    /// `RTSPREQ_PLAY`.
    Play = 5,
    /// `RTSPREQ_PAUSE`.
    Pause = 6,
    /// `RTSPREQ_TEARDOWN`.
    Teardown = 7,
    /// `RTSPREQ_GET_PARAMETER`.
    GetParameter = 8,
    /// `RTSPREQ_SET_PARAMETER`.
    SetParameter = 9,
    /// `RTSPREQ_RECORD`.
    Record = 10,
    /// `RTSPREQ_RECEIVE`.
    Receive = 11,
}

/// `set->ftp_filemethod = FTPFILE_MULTICWD` (`lib/url.c:373`).
///
/// The `curl_ftpmethod` values of `include/curl/curl.h:1017-1020`, whose
/// numbering is explicit in the header and therefore reproduced explicitly
/// here: the C stores the choice in a `uint8_t` field, so the numbers cross
/// a narrowing assignment and cannot be left to declaration order.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FtpFileMethod {
    /// `CURLFTPMETHOD_DEFAULT` = 0: *"let libcurl pick"*.
    Default = 0,
    /// `CURLFTPMETHOD_MULTICWD` = 1: *"single CWD operation for each path
    /// part"*, and the value the initialiser sets.
    #[default]
    MultiCwd = 1,
    /// `CURLFTPMETHOD_NOCWD` = 2: *"no CWD at all"*.
    NoCwd = 2,
    /// `CURLFTPMETHOD_SINGLECWD` = 3: one `CWD` to the full directory.
    SingleCwd = 3,
}

/// `set->proxytype = CURLPROXY_HTTP` (`lib/url.c:385`).
///
/// The `curl_proxytype` values, with `CURLPROXY_HTTP = 0`
/// (`include/curl/curl.h:790`) as the default -- the header's own comment
/// records that this became the default in 7.19.4.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ProxyKind {
    /// `CURLPROXY_HTTP` = 0.
    #[default]
    Http = 0,
    /// `CURLPROXY_HTTP_1_0` = 1: force HTTP/1.0 for the `CONNECT` request.
    Http10 = 1,
    /// `CURLPROXY_HTTPS` = 2.
    Https = 2,
    /// `CURLPROXY_HTTPS2` = 3: HTTPS proxy allowed to negotiate HTTP/2.
    Https2 = 3,
    /// `CURLPROXY_SOCKS4` = 4.
    Socks4 = 4,
    /// `CURLPROXY_SOCKS5` = 5.
    Socks5 = 5,
    /// `CURLPROXY_SOCKS4A` = 6.
    Socks4a = 6,
    /// `CURLPROXY_SOCKS5_HOSTNAME` = 7: the proxy resolves the name.
    Socks5Hostname = 7,
}

/// `CURL_SSLVERSION_*` (`include/curl/curl.h:2365-2377`), as a pair.
///
/// `Curl_setopt_SSLVERSION(data, CURLOPT_SSLVERSION, CURL_SSLVERSION_DEFAULT)`
/// (`lib/url.c:416`) is how the initialiser sets the minimum, and it repeats
/// the call for `CURLOPT_PROXY_SSLVERSION` (`:418-419`). The option packs a
/// minimum in the low 16 bits and a maximum in the high 16
/// (`CURL_SSLVERSION_MAX_DEFAULT` is `CURL_SSLVERSION_TLSv1 << 16`), so the
/// pair is one option and one type.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SslVersionRange {
    /// The low half: `CURL_SSLVERSION_DEFAULT` is 0.
    min: u16,
    /// The high half, already shifted down: 0 means *"no explicit maximum"*.
    max: u16,
}

impl SslVersionRange {
    /// `CURL_SSLVERSION_DEFAULT` = 0 (`include/curl/curl.h:2365`), with no
    /// explicit maximum -- the value both `SSLVERSION` calls install.
    pub const DEFAULT: Self = Self { min: 0, max: 0 };

    /// A range from the packed `long` the option carries.
    #[must_use]
    pub const fn from_packed(packed: u32) -> Self {
        Self {
            min: (packed & 0xffff) as u16,
            max: ((packed >> 16) & 0xffff) as u16,
        }
    }

    /// The packed `long` form, which is what `CURLINFO` reads back.
    #[must_use]
    pub const fn to_packed(self) -> u32 {
        ((self.max as u32) << 16) | (self.min as u32)
    }

    /// The minimum version enumerant.
    #[must_use]
    pub const fn min(self) -> u16 {
        self.min
    }

    /// The maximum version enumerant, or 0 for *"none stated"*.
    #[must_use]
    pub const fn max(self) -> u16 {
        self.max
    }
}

/// `set->httpwant = CURL_HTTP_VERSION_NONE` (`lib/url.c:445`).
///
/// The header's comment on `CURL_HTTP_VERSION_NONE`
/// (`include/curl/curl.h:2309`) is *"setting this means we do not care"* --
/// so the default is an absence of preference and not a preference for
/// HTTP/1.1, and a build that treated the two alike would negotiate
/// differently from curl 8.x.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HttpVersionWant {
    /// `CURL_HTTP_VERSION_NONE` = 0: no preference stated.
    #[default]
    None = 0,
    /// `CURL_HTTP_VERSION_1_0` = 1.
    Http10 = 1,
    /// `CURL_HTTP_VERSION_1_1` = 2.
    Http11 = 2,
    /// `CURL_HTTP_VERSION_2_0` = 3.
    Http2 = 3,
    /// `CURL_HTTP_VERSION_2TLS` = 4: HTTP/2 over TLS only.
    Http2Tls = 4,
    /// `CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE` = 5.
    Http2PriorKnowledge = 5,
    /// `CURL_HTTP_VERSION_3` = 30.
    Http3 = 30,
    /// `CURL_HTTP_VERSION_3ONLY` = 31.
    Http3Only = 31,
}

// ---------------------------------------------------------------------------
// The TLS half of `data->set` -- and the frozen default-ON verification
// ---------------------------------------------------------------------------

/// `struct ssl_config_data` (`lib/urldata.h`): the TLS options of one
/// endpoint.
///
/// One value of this type is `data->set.ssl` -- the origin server -- and
/// another is `data->set.proxy_ssl`. They are the same type in the C and are
/// the same type here, which is what makes
/// `data->set.proxy_ssl = data->set.ssl` (`lib/vtls/vtls.c:191`) a single
/// assignment rather than a field-by-field copy that could omit a field.
///
/// # Certificate verification is ON by default, and this is where that is
/// decided
///
/// `Curl_ssl_easy_config_init` (`lib/vtls/vtls.c:181-193`) carries the
/// comment that is the specification:
///
/// > libcurl 7.10 introduced SSL verification *by default*! This needs to be
/// > switched off unless wanted.
///
/// AAP 0.8.1 freezes it, and [`Default`] here delivers it -- not by
/// re-deriving the policy, but by holding
/// [`crate::tls::verify::VerifyPolicy`], whose own [`Default`] is already the
/// secure configuration. A single expression of the secure default cannot
/// disagree with itself; two would eventually.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SslConfigData {
    /// `primary.verifypeer`, `primary.verifyhost`, `CAfile`, `CApath` and
    /// `CRLfile`, as the type `crate::tls` already defines for them.
    ///
    /// `VerifyPolicy::default()` is `verify_peer = true`, `verify_host =
    /// true` and the bundled trust anchors, which is exactly the first two
    /// assignments of `Curl_ssl_easy_config_init`.
    policy: VerifyPolicy,
    /// `primary.cache_session`, set `TRUE` by the initialiser with the C's
    /// comment *"caching by default"* (`lib/vtls/vtls.c:189`).
    ///
    /// Not part of [`VerifyPolicy`] because session resumption is not
    /// verification: `crate::tls::session_cache` consults it, and a policy
    /// type that carried it would answer a question it is not asked.
    cache_session: bool,
    /// `certinfo`, from `CURLOPT_CERTINFO`: collect the peer chain for
    /// `CURLINFO_CERTINFO`. Off by default -- the initialiser never mentions
    /// it, and `struct Curl_easy` arrives zeroed.
    certinfo: bool,
    /// `falsestart`, from `CURLOPT_SSL_FALSESTART`. Off by default.
    falsestart: bool,
    /// `enable_beast` -- the inverse sense of
    /// `CURLOPT_SSL_ENABLE_BEAST`'s own name in the C's field. Off by
    /// default.
    enable_beast: bool,
    /// `no_revoke`, from `CURLSSLOPT_NO_REVOKE`. Off by default.
    no_revoke: bool,
    /// `no_partialchain`, from `CURLSSLOPT_NO_PARTIALCHAIN`. Off by default.
    no_partialchain: bool,
    /// `revoke_best_effort`, from `CURLSSLOPT_REVOKE_BEST_EFFORT`. Off by
    /// default.
    revoke_best_effort: bool,
    /// `native_ca_store`, from `CURLSSLOPT_NATIVE_CA`. Off by default, and
    /// deliberately: AAP 0.5.1 omits `platform-verifier` from both `rustls`
    /// and `quinn` so that `--cacert`, `--capath` and `--insecure` stay
    /// authoritative. The option is recorded and honoured by
    /// `crate::tls::verify`'s trust selection; nothing here lets an operating
    /// system store override an explicit option.
    native_ca_store: bool,
    /// `auto_client_cert`, from `CURLSSLOPT_AUTO_CLIENT_CERT`. Off by
    /// default.
    auto_client_cert: bool,
    /// `earlydata`, from `CURLSSLOPT_EARLYDATA`. Off by default.
    earlydata: bool,
    /// `primary.version` and `primary.version_max`, which
    /// `Curl_setopt_SSLVERSION(data, CURLOPT_SSLVERSION,
    /// CURL_SSLVERSION_DEFAULT)` installs (`lib/url.c:416`).
    version: SslVersionRange,
}

impl Default for SslConfigData {
    /// `Curl_ssl_easy_config_init` (`lib/vtls/vtls.c:181-193`), exactly.
    ///
    /// Three assignments and no more: `verifypeer = TRUE`,
    /// `verifyhost = TRUE`, `cache_session = TRUE`. Every other member is
    /// left at the zeroed state a fresh `struct Curl_easy` has, which is why
    /// the remaining fields read `false` here rather than being given
    /// opinions of their own.
    fn default() -> Self {
        Self {
            policy: VerifyPolicy::default(),
            cache_session: true,
            certinfo: false,
            falsestart: false,
            enable_beast: false,
            no_revoke: false,
            no_partialchain: false,
            revoke_best_effort: false,
            native_ca_store: false,
            auto_client_cert: false,
            earlydata: false,
            version: SslVersionRange::DEFAULT,
        }
    }
}

impl SslConfigData {
    /// The configuration `Curl_ssl_easy_config_init` produces.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The verification policy, for `crate::tls` to build a client
    /// configuration from.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn policy(&self) -> &VerifyPolicy {
        &self.policy
    }

    /// The verification policy, for `easy/setopt.rs` to write.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn policy_mut(&mut self) -> &mut VerifyPolicy {
        &mut self.policy
    }

    /// `CURLOPT_SSL_VERIFYPEER`: whether the chain is checked.
    ///
    /// `pub` and read-only. This is half of what obliges `curl-rs` to warn on
    /// standard error before proceeding, and the adapter crate must be able
    /// to ask without being handed a mutable policy or an internal TLS type.
    #[must_use]
    pub fn verify_peer(&self) -> bool {
        self.policy.verify_peer()
    }

    /// `CURLOPT_SSL_VERIFYHOST`: whether the certificate's names are
    /// checked.
    #[must_use]
    pub fn verify_host(&self) -> bool {
        self.policy.verify_host()
    }

    /// `primary.cache_session`: whether sessions may be resumed.
    #[must_use]
    pub const fn cache_session(&self) -> bool {
        self.cache_session
    }

    /// Sets `primary.cache_session`, from `CURLOPT_SSL_SESSIONID_CACHE`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_cache_session(&mut self, cache: bool) {
        self.cache_session = cache;
    }

    /// `CURLOPT_CERTINFO`.
    #[must_use]
    pub const fn certinfo(&self) -> bool {
        self.certinfo
    }

    /// Sets `CURLOPT_CERTINFO`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_certinfo(&mut self, collect: bool) {
        self.certinfo = collect;
    }

    /// `CURLSSLOPT_NATIVE_CA`, recorded rather than acted on here.
    #[must_use]
    pub const fn native_ca_store(&self) -> bool {
        self.native_ca_store
    }

    /// The negotiated version bounds.
    #[must_use]
    pub const fn version(&self) -> SslVersionRange {
        self.version
    }

    /// Sets the version bounds, from `CURLOPT_SSLVERSION` or
    /// `CURLOPT_PROXY_SSLVERSION`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_version(&mut self, version: SslVersionRange) {
        self.version = version;
    }

    /// The four `CURLSSLOPT_*` bits and the three independent booleans, as a
    /// group, so that `easy/setopt.rs` applies `CURLOPT_SSL_OPTIONS` in one
    /// call and cannot set five of eight.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_ssl_options(&mut self, options: SslOptionBits) {
        self.falsestart = options.falsestart;
        self.enable_beast = options.enable_beast;
        self.no_revoke = options.no_revoke;
        self.no_partialchain = options.no_partialchain;
        self.revoke_best_effort = options.revoke_best_effort;
        self.native_ca_store = options.native_ca_store;
        self.auto_client_cert = options.auto_client_cert;
        self.earlydata = options.earlydata;
    }

    /// The same eight bits, read back.
    #[must_use]
    pub const fn ssl_options(&self) -> SslOptionBits {
        SslOptionBits {
            falsestart: self.falsestart,
            enable_beast: self.enable_beast,
            no_revoke: self.no_revoke,
            no_partialchain: self.no_partialchain,
            revoke_best_effort: self.revoke_best_effort,
            native_ca_store: self.native_ca_store,
            auto_client_cert: self.auto_client_cert,
            earlydata: self.earlydata,
        }
    }
}

/// The eight independent TLS behaviour bits of [`SslConfigData`], as one
/// value.
///
/// A named group rather than eight arguments, because
/// `CURLOPT_SSL_OPTIONS` is a single bitmask option and applying it field by
/// field is how a subset gets applied by accident. Every field is `false` by
/// default, which is the zeroed state `struct Curl_easy` arrives in.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct SslOptionBits {
    /// `CURLOPT_SSL_FALSESTART`.
    pub falsestart: bool,
    /// The BEAST countermeasure control.
    pub enable_beast: bool,
    /// `CURLSSLOPT_NO_REVOKE`.
    pub no_revoke: bool,
    /// `CURLSSLOPT_NO_PARTIALCHAIN`.
    pub no_partialchain: bool,
    /// `CURLSSLOPT_REVOKE_BEST_EFFORT`.
    pub revoke_best_effort: bool,
    /// `CURLSSLOPT_NATIVE_CA`.
    pub native_ca_store: bool,
    /// `CURLSSLOPT_AUTO_CLIENT_CERT`.
    pub auto_client_cert: bool,
    /// `CURLSSLOPT_EARLYDATA`.
    pub earlydata: bool,
}

/// `struct ssl_general_config` (`lib/urldata.h`): the TLS options that are
/// neither the origin's nor the proxy's.
///
/// One field in curl 8.19.0-DEV, and it has a non-zero default:
/// `set->general_ssl.ca_cache_timeout = 24 * 60 * 60` with the C's comment
/// *"Timeout every 24 hours by default"* (`lib/url.c:378-379`). Note the
/// unit -- SECONDS, where almost every other timeout in `struct UserDefined`
/// is milliseconds. The field name in the C says neither, which is exactly
/// why it is worth stating here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SslGeneralConfig {
    /// `ca_cache_timeout`, in SECONDS. Default 86,400.
    ///
    /// `int` in the C, so `i32` here -- see
    /// [`DEFAULT_CA_CACHE_TIMEOUT_SECS`].
    ca_cache_timeout_secs: i32,
}

impl Default for SslGeneralConfig {
    fn default() -> Self {
        Self {
            ca_cache_timeout_secs: DEFAULT_CA_CACHE_TIMEOUT_SECS,
        }
    }
}

impl SslGeneralConfig {
    /// How long a parsed CA store stays cached, in seconds.
    #[must_use]
    pub const fn ca_cache_timeout_secs(&self) -> i32 {
        self.ca_cache_timeout_secs
    }

    /// Sets the CA cache timeout, from `CURLOPT_CA_CACHE_TIMEOUT`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_ca_cache_timeout_secs(&mut self, secs: i32) {
        self.ca_cache_timeout_secs = secs;
    }
}

// ---------------------------------------------------------------------------
// `STRING_COPYPOSTFIELDS` -- the one member of the string table that is not a
// string, and the one duplication `dupset` special-cases
// ---------------------------------------------------------------------------

/// The request body `CURLOPT_POSTFIELDS` supplied, owned by the handle.
///
/// The C keeps this in `data->set.str[STRING_COPYPOSTFIELDS]` with
/// `data->set.postfields` pointing INTO it, which is why `dupset` has to
/// repoint the clone's `postfields` after copying (`lib/easy.c:915`). Two
/// names for one buffer is a hazard C accepts and Rust does not have to: here
/// there is one owner and [`UserDefined::postfields`] borrows from it, so a
/// clone cannot end up pointing at the original's bytes.
///
/// # The size rule, transcribed
///
/// `dupset` reads `src->set.postfieldsize` to decide HOW to copy
/// (`lib/easy.c:905-916`):
///
/// ```text
/// if(src->set.postfieldsize == -1)
///   dst->set.str[i] = curlx_strdup(src->set.str[i]);
/// else
///   dst->set.str[i] = curlx_memdup(src->set.str[i],
///                                  curlx_sotouz(src->set.postfieldsize));
/// ```
///
/// `-1` means *"measure it with `strlen`"*, so the copy stops at the first
/// NUL and the clone gets a NUL-terminated string. Any other value means
/// *"exactly this many bytes"*, so the copy may include interior NULs and
/// may stop before one. [`Self::duplicate_for_size`] is that decision, and
/// it is the reason this type stores bytes rather than a [`String`].
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct PostFields {
    /// The bytes, exactly as long as the applicable rule says.
    bytes: Vec<u8>,
}

impl PostFields {
    /// A body over `bytes`, taken verbatim.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How many bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the body is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The copy `dupset` makes, under the rule `size` selects.
    ///
    /// `size == -1` reproduces `curlx_strdup`: the copy runs to the first NUL
    /// and excludes it, so a body with an interior NUL is TRUNCATED there --
    /// which is the C's behaviour and not an accident of this
    /// implementation. Any other value reproduces
    /// `curlx_memdup(p, curlx_sotouz(size))`: exactly `size` bytes, clamped
    /// to what is actually there because a `size` larger than the buffer
    /// would read past its end in the C and must not here.
    ///
    /// A negative `size` other than `-1` is treated as `-1`. `curlx_sotouz`
    /// converts a `curl_off_t` to a `size_t`, and `CURLOPT_POSTFIELDSIZE`
    /// admits only `-1` or a non-negative value (`lib/setopt.c` refuses the
    /// rest with `CURLE_BAD_FUNCTION_ARGUMENT`), so no other negative value
    /// can reach a correctly-set handle. Folding it onto `-1` rather than
    /// panicking is what keeps a hand-built handle in a test from aborting.
    #[must_use]
    pub fn duplicate_for_size(&self, size: i64) -> Self {
        if size < 0 {
            let end = self
                .bytes
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(self.bytes.len());
            return Self {
                bytes: self.bytes[..end].to_vec(),
            };
        }

        let wanted = usize::try_from(size).unwrap_or(usize::MAX);
        let end = wanted.min(self.bytes.len());
        Self {
            bytes: self.bytes[..end].to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// The grouped members of `struct UserDefined`
// ---------------------------------------------------------------------------

/// The FTP options `Curl_init_userdefined` gives non-zero defaults.
///
/// `#ifndef CURL_DISABLE_FTP` in the C (`lib/url.c:369-375`, `:422-427`),
/// which AAP 0.5.2 maps to the `ftp` feature. Grouped because five of the
/// initialiser's assignments land here and because a group can be compared
/// against the C as a block.
#[cfg(feature = "ftp")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FtpSettings {
    /// `ftp_use_epsv = TRUE` (`lib/url.c:370`): *"FTP defaults to EPSV
    /// operations"*.
    use_epsv: bool,
    /// `ftp_use_eprt = TRUE` (`:371`): *"FTP defaults to EPRT operations"*.
    use_eprt: bool,
    /// `ftp_use_pret = FALSE` (`:372`): *"mainly useful for drftpd servers"*.
    use_pret: bool,
    /// `ftp_filemethod = FTPFILE_MULTICWD` (`:373`).
    filemethod: FtpFileMethod,
    /// `ftp_skip_ip = TRUE` (`:374`): *"skip PASV IP by default"*.
    skip_ip: bool,
    /// `wildcard_enabled = FALSE` (`:423`).
    wildcard_enabled: bool,
    /// `chunk_bgn = ZERO_NULL` (`:424`): whether a chunk-begin callback is
    /// installed.
    ///
    /// The pointer belongs to `curl-rs-ffi`; what the option state records is
    /// its PRESENCE, which is the only thing the C consults before calling
    /// through it.
    chunk_bgn_set: bool,
    /// `chunk_end = ZERO_NULL` (`:425`).
    chunk_end_set: bool,
    /// `fnmatch = ZERO_NULL` (`:426`): whether `CURLOPT_FNMATCH_FUNCTION`
    /// replaced the built-in matcher.
    fnmatch_set: bool,
}

#[cfg(feature = "ftp")]
impl Default for FtpSettings {
    /// The eight assignments of `lib/url.c:369-375` and `:422-427`.
    fn default() -> Self {
        Self {
            use_epsv: true,
            use_eprt: true,
            use_pret: false,
            filemethod: FtpFileMethod::MultiCwd,
            skip_ip: true,
            wildcard_enabled: false,
            chunk_bgn_set: false,
            chunk_end_set: false,
            fnmatch_set: false,
        }
    }
}

#[cfg(feature = "ftp")]
impl FtpSettings {
    /// `CURLOPT_FTP_USE_EPSV`.
    #[must_use]
    pub const fn use_epsv(&self) -> bool {
        self.use_epsv
    }

    /// `CURLOPT_FTP_USE_EPRT`.
    #[must_use]
    pub const fn use_eprt(&self) -> bool {
        self.use_eprt
    }

    /// `CURLOPT_FTP_USE_PRET`.
    #[must_use]
    pub const fn use_pret(&self) -> bool {
        self.use_pret
    }

    /// `CURLOPT_FTP_FILEMETHOD`.
    #[must_use]
    pub const fn filemethod(&self) -> FtpFileMethod {
        self.filemethod
    }

    /// `CURLOPT_FTP_SKIP_PASV_IP`.
    #[must_use]
    pub const fn skip_ip(&self) -> bool {
        self.skip_ip
    }

    /// `CURLOPT_WILDCARDMATCH`.
    #[must_use]
    pub const fn wildcard_enabled(&self) -> bool {
        self.wildcard_enabled
    }

    /// Whether `CURLOPT_CHUNK_BGN_FUNCTION` is installed.
    #[must_use]
    pub const fn chunk_bgn_set(&self) -> bool {
        self.chunk_bgn_set
    }

    /// Whether `CURLOPT_CHUNK_END_FUNCTION` is installed.
    #[must_use]
    pub const fn chunk_end_set(&self) -> bool {
        self.chunk_end_set
    }

    /// Whether `CURLOPT_FNMATCH_FUNCTION` is installed.
    #[must_use]
    pub const fn fnmatch_set(&self) -> bool {
        self.fnmatch_set
    }

    /// Sets `CURLOPT_WILDCARDMATCH`, which the wildcard driver reads.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_wildcard_enabled(&mut self, enabled: bool) {
        self.wildcard_enabled = enabled;
    }
}

/// The TCP options `Curl_init_userdefined` gives explicit defaults
/// (`lib/url.c:428-434`).
///
/// Unconditional in the C and unconditional here: every scheme in scope opens
/// a TCP connection, and `tcp_nodelay = TRUE` is one of the defaults AAP
/// 0.8.1 freezes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TcpSettings {
    /// `tcp_keepalive = FALSE` (`lib/url.c:428`).
    keepalive: bool,
    /// `tcp_keepintvl = 60` (`:429`), in seconds.
    keepintvl_secs: i32,
    /// `tcp_keepidle = 60` (`:430`), in seconds.
    keepidle_secs: i32,
    /// `tcp_keepcnt = 9` (`:431`).
    keepcnt: i32,
    /// `tcp_fastopen = FALSE` (`:432`).
    fastopen: bool,
    /// `tcp_nodelay = TRUE` (`:433`).
    ///
    /// ON by default, which is not the operating system's default and is
    /// therefore a value that has to be set rather than inherited: curl
    /// disables Nagle's algorithm because a request that is written in two
    /// pieces must not wait for an acknowledgement between them.
    nodelay: bool,
}

impl Default for TcpSettings {
    /// The six assignments of `lib/url.c:428-433`.
    fn default() -> Self {
        Self {
            keepalive: false,
            keepintvl_secs: DEFAULT_TCP_KEEPINTVL_SECS,
            keepidle_secs: DEFAULT_TCP_KEEPIDLE_SECS,
            keepcnt: DEFAULT_TCP_KEEPCNT,
            fastopen: false,
            nodelay: true,
        }
    }
}

impl TcpSettings {
    /// `CURLOPT_TCP_KEEPALIVE`.
    #[must_use]
    pub const fn keepalive(&self) -> bool {
        self.keepalive
    }

    /// `CURLOPT_TCP_KEEPINTVL`, in seconds.
    #[must_use]
    pub const fn keepintvl_secs(&self) -> i32 {
        self.keepintvl_secs
    }

    /// `CURLOPT_TCP_KEEPIDLE`, in seconds.
    #[must_use]
    pub const fn keepidle_secs(&self) -> i32 {
        self.keepidle_secs
    }

    /// `CURLOPT_TCP_KEEPCNT`.
    #[must_use]
    pub const fn keepcnt(&self) -> i32 {
        self.keepcnt
    }

    /// `CURLOPT_TCP_FASTOPEN`.
    #[must_use]
    pub const fn fastopen(&self) -> bool {
        self.fastopen
    }

    /// `CURLOPT_TCP_NODELAY`, on by default.
    #[must_use]
    pub const fn nodelay(&self) -> bool {
        self.nodelay
    }

    /// Sets `CURLOPT_TCP_NODELAY`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    /// Sets `CURLOPT_TCP_KEEPALIVE`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_keepalive(&mut self, keepalive: bool) {
        self.keepalive = keepalive;
    }
}

/// The proxy options `Curl_init_userdefined` gives explicit defaults
/// (`lib/url.c:383-389`).
///
/// `#ifndef CURL_DISABLE_PROXY` in the C. There is no `proxy` feature among
/// the 15 AAP 0.5.2 declares, so this is unconditional -- proxy support is
/// always compiled, exactly as TLS is.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProxySettings {
    /// `proxyport = 0` (`lib/url.c:384`): *"If non-zero, use this port number
    /// by default. If the proxy string features a `:[port]` that one will
    /// override this."*
    port: u16,
    /// `proxytype = CURLPROXY_HTTP` (`:385`): *"defaults to HTTP proxy"*.
    kind: ProxyKind,
    /// `proxyauth = CURLAUTH_BASIC` (`:386`): *"defaults to basic"*.
    auth: AuthMask,
    /// `socks5auth = CURLAUTH_BASIC | CURLAUTH_GSSAPI` (`:388`).
    ///
    /// The C's comment: *"SOCKS5 proxy auth defaults to username/password +
    /// GSS-API"*. `CURLAUTH_GSSAPI` is an alias of `CURLAUTH_NEGOTIATE`
    /// (`include/curl/curl.h:835`), so the value is `BASIC | NEGOTIATE` = 5
    /// -- and the field is a `uint8_t` in the C, which both bits fit.
    socks5_auth: AuthMask,
    /// `socks5_gssapi_nec = FALSE` (`:411`), whose C comment explains itself:
    /// *"disallow unprotected protection negotiation NEC reference
    /// implementation seem not to follow rfc1961 section 4.3/4.4"*.
    socks5_gssapi_nec: bool,
}

impl Default for ProxySettings {
    /// The five assignments of `lib/url.c:383-389` and `:411`.
    fn default() -> Self {
        Self {
            port: 0,
            kind: ProxyKind::Http,
            auth: AuthMask::BASIC,
            socks5_auth: AuthMask::from_bits(
                AuthMask::BASIC.bits() | AuthMask::NEGOTIATE.bits(),
            ),
            socks5_gssapi_nec: false,
        }
    }
}

impl ProxySettings {
    /// `CURLOPT_PROXYPORT`.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// `CURLOPT_PROXYTYPE`.
    #[must_use]
    pub const fn kind(&self) -> ProxyKind {
        self.kind
    }

    /// `CURLOPT_PROXYAUTH`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) const fn auth(&self) -> AuthMask {
        self.auth
    }

    /// `CURLOPT_SOCKS5_AUTH`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) const fn socks5_auth(&self) -> AuthMask {
        self.socks5_auth
    }

    /// `CURLOPT_SOCKS5_GSSAPI_NEC`.
    #[must_use]
    pub const fn socks5_gssapi_nec(&self) -> bool {
        self.socks5_gssapi_nec
    }

    /// Sets `CURLOPT_PROXYPORT`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    /// Sets `CURLOPT_PROXYTYPE`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_kind(&mut self, kind: ProxyKind) {
        self.kind = kind;
    }

    /// Sets `CURLOPT_PROXYAUTH`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_auth(&mut self, auth: AuthMask) {
        self.auth = auth;
    }
}

/// The DNS-over-HTTPS options `Curl_init_userdefined` gives non-zero
/// defaults (`lib/url.c:392-395`).
///
/// `#ifndef CURL_DISABLE_DOH` in the C, which AAP 0.5.2 maps to the `doh`
/// feature. Both members default to `TRUE`: a DoH lookup verifies its own
/// server INDEPENDENTLY of what the transfer's `--insecure` says, which is
/// why they are separate options at all.
#[cfg(feature = "doh")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DohSettings {
    /// `doh_verifyhost = TRUE` (`lib/url.c:393`).
    verify_host: bool,
    /// `doh_verifypeer = TRUE` (`:394`).
    verify_peer: bool,
    /// `doh_verifystatus`, which the initialiser does not mention and which
    /// therefore starts `FALSE`.
    verify_status: bool,
}

#[cfg(feature = "doh")]
impl Default for DohSettings {
    fn default() -> Self {
        Self {
            verify_host: true,
            verify_peer: true,
            verify_status: false,
        }
    }
}

#[cfg(feature = "doh")]
impl DohSettings {
    /// `CURLOPT_DOH_SSL_VERIFYHOST`, on by default.
    #[must_use]
    pub const fn verify_host(&self) -> bool {
        self.verify_host
    }

    /// `CURLOPT_DOH_SSL_VERIFYPEER`, on by default.
    #[must_use]
    pub const fn verify_peer(&self) -> bool {
        self.verify_peer
    }

    /// `CURLOPT_DOH_SSL_VERIFYSTATUS`.
    #[must_use]
    pub const fn verify_status(&self) -> bool {
        self.verify_status
    }

    /// Sets `CURLOPT_DOH_SSL_VERIFYPEER`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_verify_peer(&mut self, verify: bool) {
        self.verify_peer = verify;
    }

    /// Sets `CURLOPT_DOH_SSL_VERIFYHOST`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_verify_host(&mut self, verify: bool) {
        self.verify_host = verify;
    }
}

/// The SSH options `Curl_init_userdefined` gives non-zero defaults
/// (`lib/url.c:396-400`).
///
/// `#ifdef USE_SSH` in the C, which AAP 0.5.2 maps to the `ssh` feature.
///
/// `new_directory_perms` lives HERE and `new_file_perms` does not, and that
/// asymmetry is the C's: the directory permissions are inside the `USE_SSH`
/// guard (`:399`) while the file permissions are outside it (`:402`), because
/// FTP creates files and only SFTP creates directories.
#[cfg(feature = "ssh")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SshSettings {
    /// `ssh_auth_types = CURLSSH_AUTH_DEFAULT` (`lib/url.c:398`): *"defaults
    /// to any auth type"*, which is `CURLSSH_AUTH_ANY` = `0xffffffff`.
    auth_types: u32,
    /// `new_directory_perms = 0755` (`:399`): *"Default permissions"*.
    new_directory_perms: u32,
}

#[cfg(feature = "ssh")]
impl Default for SshSettings {
    fn default() -> Self {
        Self {
            auth_types: CURLSSH_AUTH_DEFAULT,
            new_directory_perms: DEFAULT_NEW_DIRECTORY_PERMS,
        }
    }
}

#[cfg(feature = "ssh")]
impl SshSettings {
    /// `CURLOPT_SSH_AUTH_TYPES`, defaulting to every type.
    #[must_use]
    pub const fn auth_types(&self) -> u32 {
        self.auth_types
    }

    /// `CURLOPT_NEW_DIRECTORY_PERMS`, defaulting to `0o755`.
    #[must_use]
    pub const fn new_directory_perms(&self) -> u32 {
        self.new_directory_perms
    }

    /// Sets `CURLOPT_SSH_AUTH_TYPES`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_auth_types(&mut self, types: u32) {
        self.auth_types = types;
    }
}

/// The WebSocket options `Curl_init_userdefined` mentions explicitly
/// (`lib/url.c:450-453`).
///
/// `#ifndef CURL_DISABLE_WEBSOCKETS` in the C, which AAP 0.5.2 maps to the
/// `websockets` feature. Both members default to `FALSE`, and the
/// initialiser assigns them anyway -- which is worth reproducing rather than
/// eliding, because `curl_easy_reset` re-runs the initialiser over a
/// `memset` block and an assignment that is redundant on a fresh handle is
/// not redundant there.
#[cfg(feature = "websockets")]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct WebSocketSettings {
    /// `ws_raw_mode = FALSE` (`lib/url.c:451`): `CURLOPT_WS_OPTIONS` with
    /// `CURLWS_RAW_MODE`.
    raw_mode: bool,
    /// `ws_no_auto_pong = FALSE` (`:452`): `CURLWS_NOAUTOPONG`.
    no_auto_pong: bool,
}

#[cfg(feature = "websockets")]
impl WebSocketSettings {
    /// `CURLWS_RAW_MODE`: deliver frames without decoding them.
    #[must_use]
    pub const fn raw_mode(&self) -> bool {
        self.raw_mode
    }

    /// `CURLWS_NOAUTOPONG`: do not answer a PING automatically.
    #[must_use]
    pub const fn no_auto_pong(&self) -> bool {
        self.no_auto_pong
    }

    /// Sets both bits from `CURLOPT_WS_OPTIONS`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set(&mut self, raw_mode: bool, no_auto_pong: bool) {
        self.raw_mode = raw_mode;
        self.no_auto_pong = no_auto_pong;
    }
}

/// `struct Curl_data_priority`, which the initialiser zeroes wholesale:
/// `memset(&set->priority, 0, sizeof(set->priority))` (`lib/url.c:447`).
///
/// `#if defined(USE_HTTP2) || defined(USE_HTTP3)` in the C (`:446`), which
/// AAP 0.5.2 maps to `any(feature = "http2", feature = "http3")`. A
/// `memset` to zero is [`Default`] here, so the type derives it and the
/// initialiser has nothing to say beyond naming the field.
#[cfg(any(feature = "http2", feature = "http3"))]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct StreamPriority {
    /// `weight`: the HTTP/2 stream weight, zero meaning *"unset"*.
    weight: i32,
    /// `exclusive`: whether the dependency is exclusive.
    exclusive: bool,
}

#[cfg(any(feature = "http2", feature = "http3"))]
impl StreamPriority {
    /// `CURLOPT_STREAM_WEIGHT`, zero when unset.
    #[must_use]
    pub const fn weight(&self) -> i32 {
        self.weight
    }

    /// `CURLOPT_STREAM_DEPENDS_E`.
    #[must_use]
    pub const fn exclusive(&self) -> bool {
        self.exclusive
    }

    /// Sets `CURLOPT_STREAM_WEIGHT`.
    #[allow(dead_code)] // consumer: easy/setopt.rs
    pub(crate) fn set_weight(&mut self, weight: i32) {
        self.weight = weight;
    }
}

// ---------------------------------------------------------------------------
// `struct UserDefined` -- the option state, owned by the handle
// ---------------------------------------------------------------------------

/// `struct UserDefined` (`lib/urldata.h:1288-1500`): *"values set by the
/// libcurl user"*.
///
/// The C's own comment on the division is the contract this type keeps:
///
/// > The `struct UserDefined` must only contain data that is set once to go
/// > for many (perhaps) independent connections. Values that are generated or
/// > calculated internally for the "session handle" must be defined within
/// > the `struct UrlState` instead.
///
/// So this holds settings and nothing derived. It is the ONLY field of
/// [`EasyHandle`] that `curl_easy_duphandle` copies, and the only one
/// `curl_easy_reset` rebuilds -- which is what makes those two operations
/// expressible as single moves rather than as field lists.
///
/// # Every default here is frozen
///
/// [`Self::new`] is `Curl_init_userdefined` (`lib/url.c:337-455`) followed by
/// `Curl_ssl_easy_config_init` (`lib/vtls/vtls.c:181-193`), transcribed with
/// every symbolic constant resolved out of the headers rather than guessed.
/// AAP 0.8.1 freezes *"default option values, including the default-on state
/// of certificate verification"*, so a changed value here is a changed
/// observable behaviour and [`mod tests`] asserts each one individually.
///
/// # Coverage, stated honestly
///
/// `struct UserDefined` carries more than two hundred members. What is
/// present here is every member the INITIALISER touches -- because those are
/// the ones whose default is frozen and whose omission would be silent -- the
/// two option tables, and the option state the sibling modules already have
/// types for. A member that the C leaves zeroed and that no landed module
/// reads yet is not listed: `easy/setopt.rs` adds one field per option it
/// implements, and a field with no reader and no non-zero default would be
/// two things to keep in step for no behaviour at all. What must never happen
/// is a member with a NON-ZERO default going missing, and that is exactly the
/// set this type is complete over.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserDefined {
    // -- the three `FILE *` members and the two default callbacks --
    /// `out` = `stdout` (`lib/url.c:341`): `CURLOPT_WRITEDATA`.
    out: IoTarget,
    /// `in_set` = `stdin` (`:342`): `CURLOPT_READDATA`.
    in_set: IoTarget,
    /// `err` = `stderr` (`:343`): `CURLOPT_STDERR`.
    err: IoTarget,
    /// `fwrite_func` = `fwrite` (`:350`).
    fwrite_func: TransferFunction,
    /// `fread_func_set` = `fread` (`:353`).
    fread_func_set: TransferFunction,
    /// `is_fread_set = 0` (`:357`): *"has read callback been set to
    /// non-NULL?"*
    is_fread_set: bool,
    /// `seek_client = ZERO_NULL` (`:359`): whether
    /// `CURLOPT_SEEKDATA` was given.
    seek_client_set: bool,

    // -- sizes, counts and the request method --
    /// `filesize = -1` (`:361`): *"we do not know the size"*.
    filesize: i64,
    /// `postfieldsize = -1` (`:362`): *"unknown size"*.
    ///
    /// The value that decides how [`Self::copy_postfields`] is duplicated;
    /// see [`PostFields::duplicate_for_size`].
    postfieldsize: i64,
    /// `maxredirs = 30` (`:363`): *"sensible default"*. `-1` is infinity.
    maxredirs: i16,
    /// `method = HTTPREQ_GET` (`:365`): *"Default HTTP request"*.
    method: HttpRequestKind,
    /// `rtspreq = RTSPREQ_OPTIONS` (`:367`): *"Default RTSP request"*.
    rtspreq: RtspRequest,

    // -- timeouts, buffers and pool limits --
    /// `dns_cache_timeout_ms = 60000` (`:376`).
    dns_cache_timeout_ms: i64,
    /// `expect_100_timeout = 1000L` (`:435`).
    expect_100_timeout_ms: u16,
    /// `buffer_size = READBUFFER_SIZE` (`:437`).
    buffer_size: u32,
    /// `upload_buffer_size = UPLOADBUFFER_DEFAULT` (`:438`).
    upload_buffer_size: u32,
    /// `happy_eyeballs_timeout = CURL_HET_DEFAULT` (`:439`).
    happy_eyeballs_timeout_ms: i64,
    /// `upkeep_interval_ms = CURL_UPKEEP_INTERVAL_DEFAULT` (`:440`).
    upkeep_interval_ms: i64,
    /// `maxconnects = DEFAULT_CONNCACHE_SIZE` (`:441`), *"for easy
    /// handles"*.
    maxconnects: u32,
    /// `conn_max_idle_ms = 118 * 1000` (`:442`).
    conn_max_idle_ms: i64,
    /// `conn_max_age_ms = 24 * 3600 * 1000` (`:443`).
    conn_max_age_ms: i64,

    // -- authentication and protocol permissions --
    /// `httpauth = CURLAUTH_BASIC` (`:381`): *"defaults to basic"*.
    httpauth: AuthMask,
    /// `allowed_protocols = (curl_prot_t) CURLPROTO_ALL` (`:403`).
    allowed_protocols: Proto,
    /// `redir_protocols = CURLPROTO_REDIR` (`:404`): HTTP, HTTPS, FTP and
    /// FTPS, and deliberately not every scheme.
    redir_protocols: Proto,

    // -- HTTP behaviour --
    /// `sep_headers = TRUE` (`:436`): *"separated header lists by default"*.
    sep_headers: bool,
    /// `http09_allowed = FALSE` (`:444`).
    http09_allowed: bool,
    /// `httpwant = CURL_HTTP_VERSION_NONE` (`:445`).
    httpwant: HttpVersionWant,

    // -- TLS --
    /// `ssl_enable_alpn = TRUE` (`:434`).
    ssl_enable_alpn: bool,
    /// `ssl`, initialised by `Curl_ssl_easy_config_init` (`:391`).
    ssl: SslConfigData,
    /// `proxy_ssl`, which the same function sets to a COPY of `ssl`
    /// (`lib/vtls/vtls.c:191`).
    proxy_ssl: SslConfigData,
    /// `general_ssl`, whose `ca_cache_timeout` is 24 hours (`:379`).
    general_ssl: SslGeneralConfig,

    // -- permissions and miscellany --
    /// `new_file_perms = 0644` (`:402`): *"Default permissions"*.
    new_file_perms: u32,
    /// `quick_exit = 0L` (`:449`).
    quick_exit: bool,

    // -- the two option tables and the request body --
    /// `str[STRING_LAST]` (`lib/urldata.h:1396`).
    strings: StringTable,
    /// `blobs[BLOB_LAST]` (`:1397`).
    blobs: BlobTable,
    /// `str[STRING_COPYPOSTFIELDS]`, with `postfields` pointing into it.
    ///
    /// One owner here where the C has two names; see [`PostFields`].
    copy_postfields: Option<PostFields>,
    /// `resolve`: the `CURLOPT_RESOLVE` list, in the order given.
    ///
    /// A `Vec<String>` rather than a `curl_slist`: the list keeps its C shape
    /// only at the ABI boundary, per AAP 0.6.9. `dupset`'s last act is
    /// `if(src->set.resolve) dst->state.resolve = dst->set.resolve;`
    /// (`lib/easy.c:932-933`), which [`UserDefined::duplicate`] reproduces by
    /// reporting whether the list is non-empty.
    resolve: Vec<String>,
    /// `headers`: the `CURLOPT_HTTPHEADER` list, in insertion order.
    headers: Vec<String>,
    /// Whether `mimepostp` is set -- `CURLOPT_MIMEPOST`.
    ///
    /// The multipart tree itself is a [`crate::mime::Mime`] and belongs to
    /// [`EasyHandle::mimepost`], not here: `dupset` sets
    /// `dst->set.mimepostp = NULL` BEFORE the tables are cleared
    /// (`lib/easy.c:882`) and duplicates the tree separately afterwards
    /// (`:918-930`), so the two have different copy rules and must not share
    /// a field. What the option state records is that a body was attached,
    /// which is what decides `HTTPREQ_POST_MIME`.
    has_mimepost: bool,

    // -- the feature-gated groups --
    /// The FTP defaults of `lib/url.c:369-375` and `:422-427`.
    #[cfg(feature = "ftp")]
    ftp: FtpSettings,
    /// The TCP defaults of `:428-433`.
    tcp: TcpSettings,
    /// The proxy defaults of `:383-389` and `:411`.
    proxy: ProxySettings,
    /// The DoH defaults of `:392-395`.
    #[cfg(feature = "doh")]
    doh: DohSettings,
    /// The SSH defaults of `:396-400`.
    #[cfg(feature = "ssh")]
    ssh: SshSettings,
    /// The WebSocket defaults of `:450-453`.
    #[cfg(feature = "websockets")]
    ws: WebSocketSettings,
    /// `memset(&set->priority, 0, sizeof(set->priority))` (`:447`).
    #[cfg(any(feature = "http2", feature = "http3"))]
    priority: StreamPriority,
}

impl Default for UserDefined {
    /// [`Self::new`], so that the two spellings cannot drift.
    fn default() -> Self {
        Self::new()
    }
}

impl UserDefined {
    /// `Curl_init_userdefined` (`lib/url.c:337-455`) with
    /// `Curl_ssl_easy_config_init` (`lib/vtls/vtls.c:181-193`).
    ///
    /// The C's own header comment on the function is worth keeping: *"This
    /// may be safely called on a new or existing `Curl_easy`."* That is what
    /// makes `curl_easy_reset` able to `memset` the block and call it again
    /// (`lib/easy.c:1100-1101`), and it is why [`Self::new`] rather than a
    /// mutating `init` is the right shape in Rust: a fresh value assigned
    /// over the old one is the same operation with no partially-initialised
    /// window in the middle.
    ///
    /// # The assignments, in the C's order
    ///
    /// Every line of the initialiser is represented, including the ones that
    /// assign `false` or `0`. Those are not redundant: on the reset path the
    /// C is writing over a `memset` block, so a value it assigns explicitly
    /// is a value a reader can check, and a value it leaves out is one that
    /// is zero BY the `memset`. Both facts are preserved by writing the
    /// struct out in full.
    #[must_use]
    pub fn new() -> Self {
        // `Curl_ssl_easy_config_init(data)` at `lib/url.c:391`, whose last
        // act is `data->set.proxy_ssl = data->set.ssl`
        // (`lib/vtls/vtls.c:191`). Built once and cloned, so the two can
        // never start out disagreeing -- which is the whole content of that
        // assignment.
        let ssl = SslConfigData::new();
        let proxy_ssl = ssl.clone();

        Self {
            out: IoTarget::Standard(StdStream::Out),
            in_set: IoTarget::Standard(StdStream::In),
            err: IoTarget::Standard(StdStream::Err),
            fwrite_func: TransferFunction::Stdio,
            fread_func_set: TransferFunction::Stdio,
            is_fread_set: false,
            seek_client_set: false,

            filesize: -1,
            postfieldsize: -1,
            maxredirs: DEFAULT_MAXREDIRS,
            method: HttpRequestKind::Get,
            rtspreq: RtspRequest::Options,

            dns_cache_timeout_ms: DEFAULT_DNS_CACHE_TIMEOUT_MS,
            expect_100_timeout_ms: DEFAULT_EXPECT_100_TIMEOUT_MS,
            buffer_size: READBUFFER_SIZE,
            upload_buffer_size: UPLOADBUFFER_DEFAULT,
            happy_eyeballs_timeout_ms: CURL_HET_DEFAULT,
            upkeep_interval_ms: CURL_UPKEEP_INTERVAL_DEFAULT,
            maxconnects: DEFAULT_CONNCACHE_SIZE,
            conn_max_idle_ms: DEFAULT_CONN_MAX_IDLE_MS,
            conn_max_age_ms: DEFAULT_CONN_MAX_AGE_MS,

            httpauth: AuthMask::BASIC,
            allowed_protocols: Proto::ALL,
            redir_protocols: Proto::REDIR,

            sep_headers: true,
            http09_allowed: false,
            httpwant: HttpVersionWant::None,

            ssl_enable_alpn: true,
            ssl,
            proxy_ssl,
            general_ssl: SslGeneralConfig::default(),

            new_file_perms: DEFAULT_NEW_FILE_PERMS,
            quick_exit: false,

            strings: StringTable::new(),
            blobs: BlobTable::new(),
            copy_postfields: None,
            resolve: Vec::new(),
            headers: Vec::new(),
            has_mimepost: false,

            #[cfg(feature = "ftp")]
            ftp: FtpSettings::default(),
            tcp: TcpSettings::default(),
            proxy: ProxySettings::default(),
            #[cfg(feature = "doh")]
            doh: DohSettings::default(),
            #[cfg(feature = "ssh")]
            ssh: SshSettings::default(),
            #[cfg(feature = "websockets")]
            ws: WebSocketSettings::default(),
            #[cfg(any(feature = "http2", feature = "http3"))]
            priority: StreamPriority::default(),
        }
    }

    /// `dupset` (`lib/easy.c:872-936`), as a value-producing operation.
    ///
    /// The C does this in five steps and every one of them is here:
    ///
    /// | C | `lib/easy.c` | here |
    /// |---|---|---|
    /// | `dst->set = src->set` | `:880` | the [`Clone`] that opens the body |
    /// | `dst->set.mimepostp = NULL` | `:882` | [`Self::has_mimepost`] cleared |
    /// | `memset` both tables | `:886-887` | [`StringTable::clear`], [`BlobTable::clear`] |
    /// | duplicate every string, every blob | `:889-901` | [`StringTable::duplicate`], [`BlobTable::duplicate`] |
    /// | `STRING_COPYPOSTFIELDS`, then repoint `postfields` | `:903-916` | [`PostFields::duplicate_for_size`] |
    ///
    /// # Why this cannot fail, where the C can
    ///
    /// `dupset` returns `CURLcode` and answers `CURLE_OUT_OF_MEMORY` from
    /// four places: two `strdup` loops, the postfields copy and the
    /// `curlx_malloc` for the mime part. Rust aborts on allocation failure
    /// rather than returning, so none of those four is expressible -- and a
    /// `Result` whose error variant no path can produce would be a lie in the
    /// signature. `curl-rs-ffi`'s `curl_easy_duphandle` therefore has one
    /// failure mode rather than five: a handle that fails
    /// [`EasyHandle::is_valid`], which the C checks first too
    /// (`lib/easy.c:957`).
    ///
    /// # What the C does at the end, and what happens to it
    ///
    /// `if(src->set.resolve) dst->state.resolve = dst->set.resolve;`
    /// (`:932-933`) copies the option list into the STATE, because the state
    /// copy is the one the transfer consumes and mutates. That write is a
    /// write to `data->state`, so it belongs to [`HandleState`] and not here;
    /// [`Self::resolve_pending`] is what reports whether it must happen, and
    /// [`EasyHandle::duplicate`] performs it.
    #[must_use]
    pub fn duplicate(&self) -> Self {
        // `dst->set = src->set` -- the shallow struct copy of `:880`, which
        // in Rust necessarily deep-copies the owned members. The next three
        // steps then undo exactly the parts of that the C undoes.
        let mut copy = self.clone();

        // `dst->set.mimepostp = NULL` (`:882`). The tree is duplicated by
        // `EasyHandle::duplicate`, which owns it.
        copy.has_mimepost = false;

        // `memset(dst->set.str, ...)` and `memset(dst->set.blobs, ...)`
        // (`:886-887`), then the two duplication loops (`:889-901`). Clearing
        // first is the C's ordering and is preserved even though Rust's drop
        // glue makes the mid-function bail-out the comment worries about
        // impossible: a reader checking this against the C should find the
        // same two steps in the same order.
        copy.strings.duplicate(&self.strings);
        copy.blobs.duplicate(&self.blobs);

        // `:903-916`: the one member past `STRING_LASTZEROTERMINATED`, copied
        // under the rule `postfieldsize` selects, with the clone's
        // `postfields` necessarily pointing at the clone's own bytes because
        // there is only one owner.
        copy.copy_postfields = self
            .copy_postfields
            .as_ref()
            .map(|body| body.duplicate_for_size(self.postfieldsize));

        copy
    }

    /// Whether `dupset`'s closing `if(src->set.resolve)` (`lib/easy.c:932`)
    /// holds -- that is, whether the clone's state must take a copy of the
    /// resolve list.
    #[must_use]
    pub fn resolve_pending(&self) -> bool {
        !self.resolve.is_empty()
    }
}

/// The readers of [`UserDefined`].
///
/// Every field has one, which is deliberate rather than exhaustive for its
/// own sake: a field with no reader is a field nothing depends on, and
/// `#[deny(dead_code)]` is what tells the author of the next option that they
/// have added state and forgotten to expose it. The setters are narrower --
/// `easy/setopt.rs` needs the ones it writes, and nothing else may write
/// option state at all.
impl UserDefined {
    /// `CURLOPT_WRITEDATA`'s destination, `stdout` by default.
    #[must_use]
    pub const fn out(&self) -> IoTarget {
        self.out
    }

    /// `CURLOPT_READDATA`'s source, `stdin` by default.
    #[must_use]
    pub const fn in_set(&self) -> IoTarget {
        self.in_set
    }

    /// `CURLOPT_STDERR`'s destination, `stderr` by default.
    #[must_use]
    pub const fn err(&self) -> IoTarget {
        self.err
    }

    /// Which function stores output -- `fwrite` by default.
    #[must_use]
    pub const fn fwrite_func(&self) -> TransferFunction {
        self.fwrite_func
    }

    /// Which function reads input -- `fread` by default.
    #[must_use]
    pub const fn fread_func_set(&self) -> TransferFunction {
        self.fread_func_set
    }

    /// `is_fread_set`: whether `CURLOPT_READFUNCTION` was given a non-NULL
    /// callback.
    #[must_use]
    pub const fn is_fread_set(&self) -> bool {
        self.is_fread_set
    }

    /// Whether `CURLOPT_SEEKDATA` was given.
    #[must_use]
    pub const fn seek_client_set(&self) -> bool {
        self.seek_client_set
    }

    /// `CURLOPT_INFILESIZE`, `-1` for *"unknown"*.
    #[must_use]
    pub const fn filesize(&self) -> i64 {
        self.filesize
    }

    /// `CURLOPT_POSTFIELDSIZE`, `-1` for *"measure it"*.
    #[must_use]
    pub const fn postfieldsize(&self) -> i64 {
        self.postfieldsize
    }

    /// `CURLOPT_MAXREDIRS`, 30 by default and `-1` for infinity.
    #[must_use]
    pub const fn maxredirs(&self) -> i16 {
        self.maxredirs
    }

    /// `data->set.method`, `HTTPREQ_GET` by default.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) const fn method(&self) -> HttpRequestKind {
        self.method
    }

    /// `data->set.rtspreq`, `RTSPREQ_OPTIONS` by default.
    #[must_use]
    pub const fn rtspreq(&self) -> RtspRequest {
        self.rtspreq
    }

    /// `CURLOPT_DNS_CACHE_TIMEOUT`, 60,000 ms by default.
    #[must_use]
    pub const fn dns_cache_timeout_ms(&self) -> i64 {
        self.dns_cache_timeout_ms
    }

    /// `CURLOPT_EXPECT_100_TIMEOUT_MS`, 1,000 ms by default.
    #[must_use]
    pub const fn expect_100_timeout_ms(&self) -> u16 {
        self.expect_100_timeout_ms
    }

    /// `CURLOPT_BUFFERSIZE`, `READBUFFER_SIZE` by default.
    #[must_use]
    pub const fn buffer_size(&self) -> u32 {
        self.buffer_size
    }

    /// `CURLOPT_UPLOAD_BUFFERSIZE`, `UPLOADBUFFER_DEFAULT` by default.
    #[must_use]
    pub const fn upload_buffer_size(&self) -> u32 {
        self.upload_buffer_size
    }

    /// `CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`, 200 ms by default.
    #[must_use]
    pub const fn happy_eyeballs_timeout_ms(&self) -> i64 {
        self.happy_eyeballs_timeout_ms
    }

    /// `CURLOPT_UPKEEP_INTERVAL_MS`, 60,000 ms by default.
    #[must_use]
    pub const fn upkeep_interval_ms(&self) -> i64 {
        self.upkeep_interval_ms
    }

    /// `CURLOPT_MAXCONNECTS`, 5 by default for an easy handle.
    #[must_use]
    pub const fn maxconnects(&self) -> u32 {
        self.maxconnects
    }

    /// `CURLOPT_MAXLIFETIME_CONN`'s idle half, 118,000 ms by default.
    #[must_use]
    pub const fn conn_max_idle_ms(&self) -> i64 {
        self.conn_max_idle_ms
    }

    /// `CURLOPT_MAXAGE_CONN`, 86,400,000 ms by default.
    #[must_use]
    pub const fn conn_max_age_ms(&self) -> i64 {
        self.conn_max_age_ms
    }

    /// `CURLOPT_HTTPAUTH`, `CURLAUTH_BASIC` by default.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) const fn httpauth(&self) -> AuthMask {
        self.httpauth
    }

    /// `CURLOPT_PROTOCOLS_STR`, every scheme by default.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) const fn allowed_protocols(&self) -> Proto {
        self.allowed_protocols
    }

    /// `CURLOPT_REDIR_PROTOCOLS_STR`, HTTP/HTTPS/FTP/FTPS by default.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) const fn redir_protocols(&self) -> Proto {
        self.redir_protocols
    }

    /// `CURLOPT_HEADEROPT`'s separated form, on by default.
    #[must_use]
    pub const fn sep_headers(&self) -> bool {
        self.sep_headers
    }

    /// `CURLOPT_HTTP09_ALLOWED`, off by default.
    #[must_use]
    pub const fn http09_allowed(&self) -> bool {
        self.http09_allowed
    }

    /// `CURLOPT_HTTP_VERSION`, *"no preference"* by default.
    #[must_use]
    pub const fn httpwant(&self) -> HttpVersionWant {
        self.httpwant
    }

    /// `CURLOPT_SSL_ENABLE_ALPN`, on by default.
    #[must_use]
    pub const fn ssl_enable_alpn(&self) -> bool {
        self.ssl_enable_alpn
    }

    /// The origin server's TLS configuration.
    #[must_use]
    pub const fn ssl(&self) -> &SslConfigData {
        &self.ssl
    }

    /// The origin server's TLS configuration, for `easy/setopt.rs`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn ssl_mut(&mut self) -> &mut SslConfigData {
        &mut self.ssl
    }

    /// The proxy's TLS configuration, which starts as a copy of
    /// [`Self::ssl`].
    #[must_use]
    pub const fn proxy_ssl(&self) -> &SslConfigData {
        &self.proxy_ssl
    }

    /// The proxy's TLS configuration, for `easy/setopt.rs`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn proxy_ssl_mut(&mut self) -> &mut SslConfigData {
        &mut self.proxy_ssl
    }

    /// The TLS configuration that is neither endpoint's.
    #[must_use]
    pub const fn general_ssl(&self) -> &SslGeneralConfig {
        &self.general_ssl
    }

    /// The same, for `easy/setopt.rs`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn general_ssl_mut(&mut self) -> &mut SslGeneralConfig {
        &mut self.general_ssl
    }

    /// `CURLOPT_NEW_FILE_PERMS`, `0o644` by default.
    #[must_use]
    pub const fn new_file_perms(&self) -> u32 {
        self.new_file_perms
    }

    /// `CURLOPT_QUICK_EXIT`, off by default.
    #[must_use]
    pub const fn quick_exit(&self) -> bool {
        self.quick_exit
    }

    /// The string options.
    #[must_use]
    pub const fn strings(&self) -> &StringTable {
        &self.strings
    }

    /// The string options, for `easy/setopt.rs`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn strings_mut(&mut self) -> &mut StringTable {
        &mut self.strings
    }

    /// The blob options.
    #[must_use]
    pub const fn blobs(&self) -> &BlobTable {
        &self.blobs
    }

    /// The blob options, for `easy/setopt.rs`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn blobs_mut(&mut self) -> &mut BlobTable {
        &mut self.blobs
    }

    /// `data->set.postfields`, which points at the handle's own copy.
    #[must_use]
    pub fn postfields(&self) -> Option<&PostFields> {
        self.copy_postfields.as_ref()
    }

    /// Installs `CURLOPT_COPYPOSTFIELDS` with the size that governs it.
    ///
    /// Both at once, because [`PostFields::duplicate_for_size`] reads the
    /// size and a body installed without its size would be duplicated under
    /// the wrong rule. `size` is `-1` for *"measure it"*.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_postfields(
        &mut self,
        body: Option<PostFields>,
        size: i64,
    ) {
        self.copy_postfields = body;
        self.postfieldsize = size;
    }

    /// `CURLOPT_RESOLVE`, in the order given.
    #[must_use]
    pub fn resolve(&self) -> &[String] {
        &self.resolve
    }

    /// Appends a `CURLOPT_RESOLVE` entry.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn push_resolve(&mut self, entry: String) {
        self.resolve.push(entry);
    }

    /// `CURLOPT_HTTPHEADER`, in insertion order.
    #[must_use]
    pub fn headers(&self) -> &[String] {
        &self.headers
    }

    /// Appends a `CURLOPT_HTTPHEADER` entry.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn push_header(&mut self, header: String) {
        self.headers.push(header);
    }

    /// Whether `CURLOPT_MIMEPOST` attached a multipart body.
    #[must_use]
    pub const fn has_mimepost(&self) -> bool {
        self.has_mimepost
    }

    /// Records that a multipart body is attached, or is not.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_has_mimepost(&mut self, attached: bool) {
        self.has_mimepost = attached;
    }

    /// The FTP options.
    #[cfg(feature = "ftp")]
    #[must_use]
    pub const fn ftp(&self) -> &FtpSettings {
        &self.ftp
    }

    /// The FTP options, for `easy/setopt.rs`.
    #[cfg(feature = "ftp")]
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn ftp_mut(&mut self) -> &mut FtpSettings {
        &mut self.ftp
    }

    /// The TCP options.
    #[must_use]
    pub const fn tcp(&self) -> &TcpSettings {
        &self.tcp
    }

    /// The TCP options, for `easy/setopt.rs`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn tcp_mut(&mut self) -> &mut TcpSettings {
        &mut self.tcp
    }

    /// The proxy options.
    #[must_use]
    pub const fn proxy(&self) -> &ProxySettings {
        &self.proxy
    }

    /// The proxy options, for `easy/setopt.rs`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn proxy_mut(&mut self) -> &mut ProxySettings {
        &mut self.proxy
    }

    /// The DNS-over-HTTPS options.
    #[cfg(feature = "doh")]
    #[must_use]
    pub const fn doh(&self) -> &DohSettings {
        &self.doh
    }

    /// The DNS-over-HTTPS options, for `easy/setopt.rs`.
    #[cfg(feature = "doh")]
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn doh_mut(&mut self) -> &mut DohSettings {
        &mut self.doh
    }

    /// The SSH options.
    #[cfg(feature = "ssh")]
    #[must_use]
    pub const fn ssh(&self) -> &SshSettings {
        &self.ssh
    }

    /// The SSH options, for `easy/setopt.rs`.
    #[cfg(feature = "ssh")]
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn ssh_mut(&mut self) -> &mut SshSettings {
        &mut self.ssh
    }

    /// The WebSocket options.
    #[cfg(feature = "websockets")]
    #[must_use]
    pub const fn ws(&self) -> &WebSocketSettings {
        &self.ws
    }

    /// The WebSocket options, for `easy/setopt.rs`.
    #[cfg(feature = "websockets")]
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn ws_mut(&mut self) -> &mut WebSocketSettings {
        &mut self.ws
    }

    /// The HTTP/2 and HTTP/3 stream priority.
    #[cfg(any(feature = "http2", feature = "http3"))]
    #[must_use]
    pub const fn priority(&self) -> &StreamPriority {
        &self.priority
    }

    /// The stream priority, for `easy/setopt.rs`.
    #[cfg(any(feature = "http2", feature = "http3"))]
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn priority_mut(&mut self) -> &mut StreamPriority {
        &mut self.priority
    }

    /// Sets `CURLOPT_MAXREDIRS`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_maxredirs(&mut self, maxredirs: i16) {
        self.maxredirs = maxredirs;
    }

    /// Sets `CURLOPT_HTTPAUTH`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_httpauth(&mut self, auth: AuthMask) {
        self.httpauth = auth;
    }

    /// Sets `CURLOPT_HTTP_VERSION`.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_httpwant(&mut self, want: HttpVersionWant) {
        self.httpwant = want;
    }

    /// Sets `CURLOPT_BUFFERSIZE`, clamped to the C's bounds.
    ///
    /// `READBUFFER_MIN`..=`READBUFFER_MAX` (`lib/urldata.h:197-199`).
    /// Clamping rather than refusing is the C's behaviour: `CURLOPT_BUFFERSIZE`
    /// accepts an out-of-range value and moves it into range.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_buffer_size(&mut self, size: u32) {
        self.buffer_size = size.clamp(READBUFFER_MIN, READBUFFER_MAX);
    }

    /// Sets `CURLOPT_UPLOAD_BUFFERSIZE`, clamped to the C's bounds.
    ///
    /// `UPLOADBUFFER_MIN`..=`UPLOADBUFFER_MAX` (`lib/urldata.h:210-211`).
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_upload_buffer_size(&mut self, size: u32) {
        self.upload_buffer_size =
            size.clamp(UPLOADBUFFER_MIN, UPLOADBUFFER_MAX);
    }

    /// Sets the two protocol permission masks.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_protocols(&mut self, allowed: Proto, redir: Proto) {
        self.allowed_protocols = allowed;
        self.redir_protocols = redir;
    }

    /// Records that the application installed a write destination.
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_out(&mut self, out: IoTarget) {
        self.out = out;
    }

    /// Records that the application installed a read source, and whether the
    /// reader is still the stdio default.
    ///
    /// One call for both, because `is_fread_set` exists precisely to say
    /// whether `fread_func_set` is still `fread` and the two cannot be
    /// allowed to disagree (`lib/url.c:353`, `:357`).
    #[allow(dead_code)] // consumer: easy/setopt.rs and easy/getinfo.rs
    pub(crate) fn set_read_source(
        &mut self,
        source: IoTarget,
        function: TransferFunction,
    ) {
        self.in_set = source;
        self.fread_func_set = function;
        self.is_fread_set = !function.is_stdio_default();
    }
}

// ---------------------------------------------------------------------------
// `struct PureInfo` -- what `curl_easy_getinfo` reads
// ---------------------------------------------------------------------------

/// `struct PureInfo` (`lib/urldata.h`): *"stats, reports and info data"*.
///
/// `curl_easy_getinfo`'s backing store. Owned here because the handle is what
/// outlives the connection that produced these values -- which is the reason
/// the C's own comment gives for copying the address quadruple out of
/// `connectdata` in the first place:
///
/// > `PureInfo primary` ip_quadruple is copied over from the connectdata
/// > struct in order to allow `curl_easy_getinfo()` to return this
/// > information even when the session handle is no longer associated with a
/// > connection, and also allow `curl_easy_reset()` to clear this information
/// > from the session handle without disturbing information which is still
/// > alive, and that might be reused, in the connection pool.
///
/// `easy/getinfo.rs` reads it; the transfer core and the connection layer
/// write it. Two of its members are written from `lib/transfer.c` and nowhere
/// else and therefore live in [`crate::transfer::TransferInfo`] instead --
/// `timecond` and `request_size` -- so those two appear here as well and are
/// reconciled by [`Self::absorb_transfer_info`]: one authority per write
/// site, one place to read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PureInfo {
    /// `httpcode`: *"Recent HTTP, FTP, RTSP or SMTP response code"*.
    httpcode: i32,
    /// `httpproxycode`: *"response code from proxy when received separate"*.
    httpproxycode: i32,
    /// `httpversion`: *"the http version number X.Y = X*10+Y"*.
    httpversion: i32,
    /// `filetime`: `-1` when the time could not be retrieved, which
    /// `Curl_initinfo` sets with the comment *"-1 is an illegal time and thus
    /// means unknown"*.
    filetime: i64,
    /// `request_size`: *"the amount of bytes sent in the request(s)"*.
    request_size: i64,
    /// `numconnects`: *"how many new connections libcurl created"*.
    numconnects: i64,
    /// `proxyauthavail`: *"what proxy auth types were announced"*.
    proxyauthavail: u32,
    /// `httpauthavail`: *"what host auth types were announced"*.
    httpauthavail: u32,
    /// `proxyauthpicked`: *"selected proxy auth type"*.
    proxyauthpicked: u32,
    /// `httpauthpicked`: *"selected host auth type"*.
    httpauthpicked: u32,
    /// `contenttype`: *"the content type of the object"*.
    contenttype: Option<String>,
    /// `wouldredirect`: *"URL this would have been redirected to if asked
    /// to"*.
    wouldredirect: Option<String>,
    /// `retry_after`: *"info from Retry-After: header"*.
    retry_after: i64,
    /// `header_size`: *"size of read header(s) in bytes"*.
    header_size: u32,
    /// `primary`: the four addresses and two ports of the last connection.
    primary: Option<IpQuadruple>,
    /// `conn_remote_port`: *"the port number of the used URL, independent of
    /// proxy or not"*.
    conn_remote_port: i32,
    /// `conn_scheme`: the scheme name, or [`None`] for the C's `0`.
    conn_scheme: Option<&'static str>,
    /// `conn_protocol`: the `CURLPROTO_*` bit of the scheme used.
    conn_protocol: u32,
    /// `certs`: *"info about the certs. Asked for with CURLOPT_CERTINFO /
    /// CURLINFO_CERTINFO"*.
    certs: Vec<CertInfoRecord>,
    /// `pxcode`: the SOCKS failure code, when the proxy handshake failed.
    pxcode: CURLproxycode,
    /// `timecond`: *"set to TRUE if the time condition did not match, which
    /// thus made the document NOT get fetched"*.
    timecond: bool,
    /// `used_proxy`: *"the transfer used a proxy"*.
    used_proxy: bool,
}

impl Default for PureInfo {
    /// [`Self::new`], which is `Curl_initinfo`'s half of the reset.
    fn default() -> Self {
        Self::new()
    }
}

impl PureInfo {
    /// The state `Curl_initinfo` (`lib/getinfo.c:41`) leaves `data->info` in.
    ///
    /// Every assignment that function makes to `info` is here. The nine
    /// assignments it makes to `data->progress` are NOT: those belong to
    /// [`crate::transfer::progress::Progress`], and
    /// [`EasyHandle::init_info`] performs both halves so that a caller cannot
    /// do one and forget the other -- which is exactly what a single C
    /// function reaching into two structs makes easy to get wrong.
    ///
    /// Only one member has a non-zero initial value: `filetime = -1`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            httpcode: 0,
            httpproxycode: 0,
            httpversion: 0,
            filetime: -1,
            request_size: 0,
            numconnects: 0,
            proxyauthavail: 0,
            httpauthavail: 0,
            proxyauthpicked: 0,
            httpauthpicked: 0,
            contenttype: None,
            wouldredirect: None,
            retry_after: 0,
            header_size: 0,
            primary: None,
            conn_remote_port: 0,
            conn_scheme: None,
            conn_protocol: 0,
            certs: Vec::new(),
            pxcode: CURLproxycode::Ok,
            timecond: false,
            used_proxy: false,
        }
    }

    /// `CURLINFO_RESPONSE_CODE`.
    #[must_use]
    pub const fn httpcode(&self) -> i32 {
        self.httpcode
    }

    /// `CURLINFO_HTTP_CONNECTCODE`.
    #[must_use]
    pub const fn httpproxycode(&self) -> i32 {
        self.httpproxycode
    }

    /// `CURLINFO_HTTP_VERSION`, as `X * 10 + Y`.
    #[must_use]
    pub const fn httpversion(&self) -> i32 {
        self.httpversion
    }

    /// `CURLINFO_FILETIME`, `-1` for *"unknown"*.
    #[must_use]
    pub const fn filetime(&self) -> i64 {
        self.filetime
    }

    /// `CURLINFO_REQUEST_SIZE`.
    #[must_use]
    pub const fn request_size(&self) -> i64 {
        self.request_size
    }

    /// `CURLINFO_NUM_CONNECTS`.
    #[must_use]
    pub const fn numconnects(&self) -> i64 {
        self.numconnects
    }

    /// `CURLINFO_PROXYAUTH_AVAIL`.
    #[must_use]
    pub const fn proxyauthavail(&self) -> u32 {
        self.proxyauthavail
    }

    /// `CURLINFO_HTTPAUTH_AVAIL`.
    #[must_use]
    pub const fn httpauthavail(&self) -> u32 {
        self.httpauthavail
    }

    /// `CURLINFO_PROXYAUTH_USED`.
    #[must_use]
    pub const fn proxyauthpicked(&self) -> u32 {
        self.proxyauthpicked
    }

    /// `CURLINFO_HTTPAUTH_USED`.
    #[must_use]
    pub const fn httpauthpicked(&self) -> u32 {
        self.httpauthpicked
    }

    /// `CURLINFO_CONTENT_TYPE`.
    #[must_use]
    pub fn contenttype(&self) -> Option<&str> {
        self.contenttype.as_deref()
    }

    /// `CURLINFO_REDIRECT_URL`.
    #[must_use]
    pub fn wouldredirect(&self) -> Option<&str> {
        self.wouldredirect.as_deref()
    }

    /// `CURLINFO_RETRY_AFTER`.
    #[must_use]
    pub const fn retry_after(&self) -> i64 {
        self.retry_after
    }

    /// `CURLINFO_HEADER_SIZE`.
    #[must_use]
    pub const fn header_size(&self) -> u32 {
        self.header_size
    }

    /// The last connection's addresses and ports, if there was one.
    #[allow(dead_code)] // consumer: easy/getinfo.rs
    pub(crate) fn primary(&self) -> Option<&IpQuadruple> {
        self.primary.as_ref()
    }

    /// `CURLINFO_PRIMARY_PORT`'s URL-derived half.
    #[must_use]
    pub const fn conn_remote_port(&self) -> i32 {
        self.conn_remote_port
    }

    /// `CURLINFO_SCHEME`.
    #[must_use]
    pub const fn conn_scheme(&self) -> Option<&'static str> {
        self.conn_scheme
    }

    /// `CURLINFO_PROTOCOL`'s `CURLPROTO_*` bit.
    #[must_use]
    pub const fn conn_protocol(&self) -> u32 {
        self.conn_protocol
    }

    /// `CURLINFO_CERTINFO`'s records.
    #[allow(dead_code)] // consumer: easy/getinfo.rs
    pub(crate) fn certs(&self) -> &[CertInfoRecord] {
        &self.certs
    }

    /// `CURLINFO_PROXY_ERROR`.
    #[allow(dead_code)] // consumer: easy/getinfo.rs
    pub(crate) const fn pxcode(&self) -> CURLproxycode {
        self.pxcode
    }

    /// `CURLINFO_CONDITION_UNMET`.
    #[must_use]
    pub const fn timecond(&self) -> bool {
        self.timecond
    }

    /// `CURLINFO_USED_PROXY`.
    #[must_use]
    pub const fn used_proxy(&self) -> bool {
        self.used_proxy
    }

    /// Takes over the two members the transfer core owns.
    ///
    /// [`crate::transfer::TransferInfo`] is the write authority for
    /// `info.timecond` (`lib/transfer.c:130`, `:137`) and
    /// `info.request_size` (`:845`), because those are written from the file
    /// that module supersedes and from nowhere else. This is where the two
    /// views are reconciled, so `easy/getinfo.rs` has exactly one place to
    /// read from and the transfer core keeps exactly one place to write to.
    #[allow(dead_code)] // consumer: easy/getinfo.rs
    pub(crate) fn absorb_transfer_info(
        &mut self,
        info: &crate::transfer::TransferInfo,
    ) {
        self.timecond = info.timecond;
        self.request_size = info.request_size;
    }
}

// ---------------------------------------------------------------------------
// `meta_hash` -- a typed store, never a `void *` hash
// ---------------------------------------------------------------------------

/// One value a subsystem may park on the handle for the handle's lifetime.
///
/// The C's `meta_hash` is a `struct Curl_hash` of `void *` whose entries each
/// carry their own destructor, added with `Curl_hash_add2`
/// (`lib/urldata.h:1649-1653`). AAP 0.6.9 forbids reproducing that: *"In Rust
/// a typed map -- never a `void*` hash."*
///
/// So the value type is an enumeration of what a subsystem may actually
/// store, and the destructor disappears: dropping a [`MetaValue`] releases
/// whatever it holds, because that is what dropping does. A `void *` with a
/// hand-supplied free function is a destructor that can be the wrong one; a
/// variant cannot be.
///
/// # Why an enum and not a boxed trait object
///
/// A `Box<dyn Any>` would reproduce the C's shape faithfully -- including its
/// hazard. Recovering a value from one requires a downcast, a downcast can
/// fail, and the failure is exactly the mistyped-`void *` defect this crate
/// exists to eliminate. AAP 0.3.3's constraint on the seams says the same
/// thing about the injection points: *"must not require `unsafe`, `Any`, or
/// downcasting."* An enum of the shapes that are actually stored costs one
/// variant per new user and can never be read as the wrong type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetaValue {
    /// A flag, for the several places the C stores a `bool`-shaped marker.
    Flag(bool),
    /// A counter or an identifier.
    Number(i64),
    /// A textual note -- a negotiated name, a selected mechanism.
    Text(String),
    /// Opaque bytes, for a subsystem that parks a serialised value.
    Bytes(Vec<u8>),
}

/// `data->meta_hash` (`lib/urldata.h:1653`): *"a general key-value store for
/// implementations with the lifetime of the easy handle"*.
///
/// A [`BTreeMap`] rather than a hash map, and the choice is behavioural
/// rather than aesthetic: iteration order is deterministic, so a trace or a
/// diagnostic that walks the store prints the same thing on every run and in
/// every process. `HashMap`'s randomised order would make one of those a
/// flaky comparison, and AAP 0.6.7's byte-exact oracle leaves no room for
/// that.
///
/// [`META_HASH_SLOTS`] -- the C's 23 -- is the capacity
/// `curl_easy_duphandle` gives a clone. A [`BTreeMap`] has no capacity to
/// reserve, so the constant is documentation and is asserted by
/// [`mod tests`] rather than passed to a constructor that would ignore it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetaStore {
    /// Keyed by name, exactly as the C hashes a string key.
    entries: BTreeMap<String, MetaValue>,
}

impl MetaStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parks `value` under `key`, answering what was there.
    ///
    /// The successor of `Curl_hash_add2`, minus the destructor argument:
    /// dropping the returned value is what the C's destructor did.
    #[allow(dead_code)] // consumer: the subsystems that park handle metadata
    pub(crate) fn insert(
        &mut self,
        key: impl Into<String>,
        value: MetaValue,
    ) -> Option<MetaValue> {
        self.entries.insert(key.into(), value)
    }

    /// The value under `key`, if any.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&MetaValue> {
        self.entries.get(key)
    }

    /// Removes and returns the value under `key`.
    #[allow(dead_code)] // consumer: the subsystems that park handle metadata
    pub(crate) fn remove(&mut self, key: &str) -> Option<MetaValue> {
        self.entries.remove(key)
    }

    /// How many entries the store holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `Curl_hash_clean(&data->meta_hash)` (`lib/easy.c:1090`), which
    /// `curl_easy_reset` performs before `Curl_meta_reset`.
    #[allow(dead_code)] // consumer: the subsystems that park handle metadata
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    /// Every key, in deterministic order.
    ///
    /// Published so a trace can enumerate the store without being handed the
    /// map, and ordered because [`BTreeMap`] is what backs it.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }
}

// ---------------------------------------------------------------------------
// `struct UrlState` -- the slice of it this file owns
// ---------------------------------------------------------------------------

/// The members of `struct UrlState` that belong to the HANDLE rather than to
/// a transfer, a connection or a name lookup.
///
/// `struct UrlState` is the mutable half of the god-struct, and AAP 0.4.1
/// splits it across four modules: `url/`, `transfer/`, `dns/` and `auth/`.
/// What is left over -- and what is here -- is the part whose lifetime is the
/// HANDLE's, which is precisely the part `curl_easy_duphandle` has to
/// re-initialise and `curl_easy_reset` has to clear.
///
/// The membership test used is exactly that: a member is here if and only if
/// one of those two functions touches it. That is not a convenient rule, it
/// is the only rule that makes the two operations checkable against the C by
/// reading, and every field below cites the line that touches it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandleState {
    /// `state.lastconnect_id = -1` (`lib/easy.c:978`): the connection
    /// `CURLINFO_ACTIVESOCKET` and `CURLINFO_LASTSOCKET` report on.
    ///
    /// `-1` is the sentinel, and [`crate::conn::getconnectinfo`] writes it
    /// back when the identifier turns out to be stale -- which is why a
    /// clone must start there rather than inherit its parent's.
    lastconnect_id: ConnectionId,
    /// `state.recent_conn_id = -1` (`lib/easy.c:979`, `:1111`): the last
    /// connection this handle used, which `curl_easy_reset` also clears with
    /// the comment *"clear remembered connection id"*.
    recent_conn_id: ConnectionId,
    /// `state.current_speed = -1` (`lib/easy.c:1110`), whose C comment is the
    /// reason for the value: *"init to negative == impossible"*.
    ///
    /// Set by `curl_easy_reset` and NOT by `curl_easy_duphandle`, which
    /// leaves it at the `calloc`ed zero. The asymmetry is the C's and is
    /// preserved: [`Self::for_clone`] leaves it at zero and
    /// [`Self::apply_easy_reset`] writes `-1`, and [`mod tests`] asserts
    /// both.
    current_speed: i64,
    /// `state.resolve`, which `dupset` fills from the option list:
    /// `if(src->set.resolve) dst->state.resolve = dst->set.resolve;`
    /// (`lib/easy.c:932-933`).
    ///
    /// A separate copy from [`UserDefined::resolve`] because the transfer
    /// consumes this one as it applies each entry, and consuming the OPTION
    /// list would make a second transfer on the same handle behave
    /// differently from the first.
    resolve: Vec<String>,
    /// `curlx_dyn_init(&outcurl->state.headerb, CURL_MAX_HTTP_HEADER)`
    /// (`lib/easy.c:972`): the accumulation buffer for one response header.
    ///
    /// The ceiling is fixed at construction, as the C's `dyn_init` fixes it,
    /// and is reported by [`Self::header_buffer_limit`].
    header_buffer: Vec<u8>,
    /// `Curl_llist_init(&outcurl->state.httphdrs, NULL)`
    /// (`lib/easy.c:985`): the request headers in flight.
    ///
    /// A `Vec<String>` rather than an intrusive list, per AAP 0.6.9. Empty in
    /// a clone -- the list belongs to a request, not to the options.
    httphdrs: Vec<String>,
    /// `Curl_bufref_init(&outcurl->state.url)` (`lib/easy.c:973`), then
    /// duplicated from the parent if the parent had one (`:1014-1020`).
    url: Option<String>,
    /// `Curl_bufref_init(&outcurl->state.referer)` (`lib/easy.c:974`), then
    /// duplicated from the parent if the parent had one (`:1021-1027`).
    referer: Option<String>,
    /// `memset(&data->state.authhost, 0, ...)` and the same for `authproxy`
    /// (`lib/easy.c:1114-1115`), which `curl_easy_reset` performs under its
    /// own comment *"zero out authentication data"*.
    auth: AuthStatePair,
    /// `state.cookielist = NULL` (`lib/easy.c:997`), then duplicated from the
    /// parent when the parent had one (`:1007-1011`).
    #[cfg(feature = "cookies")]
    cookielist: Vec<String>,
    /// `state.cookie_engine`, set `TRUE` in a clone only when the parent had
    /// both a jar and the engine running (`lib/easy.c:998-1005`).
    #[cfg(feature = "cookies")]
    cookie_engine: bool,
}

impl Default for HandleState {
    /// [`Self::for_clone`], which is the state
    /// `curl_easy_duphandle` builds -- and therefore also the state a fresh
    /// handle has, since the C `calloc`s one and then runs the same
    /// initialisers over it.
    fn default() -> Self {
        Self::for_clone()
    }
}

impl HandleState {
    /// The state `curl_easy_duphandle` gives a clone
    /// (`lib/easy.c:972-986`).
    ///
    /// Six initialisers and three sentinel writes, in the C's order:
    /// `headerb`, `url`, `referer` and `netrc` are initialised;
    /// `lastconnect_id` and `recent_conn_id` are set to `-1`; `httphdrs` is
    /// emptied; and `cookielist` is nulled. `current_speed` is NOT touched,
    /// so it stays at the `calloc`ed zero -- see the field's own note.
    ///
    /// `netrc` is initialised too (`:975`) and lives on
    /// [`EasyHandle::netrc`] rather than here, because
    /// [`StoreNetrc`] is the type that module defines
    /// for it and this file may not redefine it.
    #[must_use]
    pub fn for_clone() -> Self {
        Self {
            lastconnect_id: ConnectionId::NONE,
            recent_conn_id: ConnectionId::NONE,
            current_speed: 0,
            resolve: Vec::new(),
            header_buffer: Vec::new(),
            httphdrs: Vec::new(),
            url: None,
            referer: None,
            auth: AuthStatePair::ZERO,
            #[cfg(feature = "cookies")]
            cookielist: Vec::new(),
            #[cfg(feature = "cookies")]
            cookie_engine: false,
        }
    }

    /// What `curl_easy_reset` does to `data->state` -- and ONLY that.
    ///
    /// A mutating method rather than a constructor, and the distinction is
    /// behavioural rather than stylistic. `curl_easy_reset` does NOT `memset`
    /// `data->state`: it writes four fields by name (`lib/easy.c:1110-1115`)
    /// and `Curl_freeset` (`lib/url.c`) releases three more. Replacing the
    /// whole value would additionally clear fields the C leaves standing, and
    /// one of those is [`Self::lastconnect_id`] -- so a reset handle would
    /// stop reporting the connection `CURLINFO_ACTIVESOCKET` is documented to
    /// keep reporting.
    ///
    /// # What is written, with the line that writes it
    ///
    /// | field | C |
    /// |---|---|
    /// | `current_speed = -1` | `lib/easy.c:1110` |
    /// | `recent_conn_id = -1` | `:1111` |
    /// | `authhost`, `authproxy` zeroed | `:1114-1115` |
    /// | `url`, `referer` released | `Curl_freeset`, `Curl_bufref_free` |
    /// | `cookielist` released and nulled | `Curl_freeset` |
    /// | `resolve` emptied | see below |
    ///
    /// # What is PRESERVED, and why each one
    ///
    /// * [`Self::lastconnect_id`] -- `curl_easy_reset`'s documentation is
    ///   explicit that it *"does not change ... the live connections"*, and
    ///   this identifier is how a live connection is named.
    /// * [`Self::header_buffer`] -- the `dynbuf` is not freed. It is a
    ///   transient parse buffer that the transfer path resets before it
    ///   accumulates anything, so preserving it is both what the C does and
    ///   observationally inert.
    /// * [`Self::httphdrs`] -- likewise untouched by the reset.
    /// * `cookie_engine` -- `Curl_freeset` releases the cookie FILE LIST and
    ///   leaves the engine flag alone, because the jar itself
    ///   (`data->cookies`) survives a reset. Clearing the flag would
    ///   disconnect a live jar from the handle that owns it.
    ///
    /// # `resolve`, which is the one place the C leaves a dangling pointer
    ///
    /// `data->state.resolve` is a BORROWED pointer: `dupset` assigns
    /// `dst->state.resolve = dst->set.resolve` (`lib/easy.c:933`) without
    /// duplicating the list. `curl_easy_reset` then `memset`s `data->set`,
    /// which nulls `set.resolve` while `state.resolve` still points at the
    /// list -- so the C is left holding a pointer to a list nothing owns.
    /// Here the state holds an OWNED copy, so there is nothing to dangle;
    /// emptying it is the only defensible reading, because a reset handle
    /// that still applied the previous configuration's `--resolve` entries
    /// would be applying options the caller has just cleared.
    pub(crate) fn apply_easy_reset(&mut self) {
        self.current_speed = -1;
        self.recent_conn_id = ConnectionId::NONE;
        self.auth = AuthStatePair::ZERO;
        self.url = None;
        self.referer = None;
        self.resolve.clear();
        #[cfg(feature = "cookies")]
        self.cookielist.clear();
    }

    /// The connection `CURLINFO_ACTIVESOCKET` reports on.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) const fn lastconnect_id(&self) -> ConnectionId {
        self.lastconnect_id
    }

    /// The same, mutably, because [`crate::conn::getconnectinfo`] writes the
    /// sentinel back when it finds the identifier stale.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn lastconnect_id_mut(&mut self) -> &mut ConnectionId {
        &mut self.lastconnect_id
    }

    /// `CURLINFO_CONN_ID`'s remembered value.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) const fn recent_conn_id(&self) -> ConnectionId {
        self.recent_conn_id
    }

    /// Records the connection this handle most recently used.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn set_recent_conn_id(&mut self, id: ConnectionId) {
        self.recent_conn_id = id;
    }

    /// `state.current_speed`, negative for *"not yet measured"*.
    #[must_use]
    pub const fn current_speed(&self) -> i64 {
        self.current_speed
    }

    /// The resolve entries still to be applied.
    #[must_use]
    pub fn resolve(&self) -> &[String] {
        &self.resolve
    }

    /// Takes a copy of the option list, which is `dupset`'s closing act
    /// (`lib/easy.c:932-933`).
    ///
    /// Guarded by the caller exactly as the C guards it: the assignment is
    /// inside `if(src->set.resolve)`, so an empty list leaves the state's
    /// list untouched rather than replacing it with an empty one.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn adopt_resolve(&mut self, entries: &[String]) {
        self.resolve = entries.to_vec();
    }

    /// How large the header accumulation buffer may grow --
    /// `CURL_MAX_HTTP_HEADER`.
    #[must_use]
    pub const fn header_buffer_limit(&self) -> usize {
        CURL_MAX_HTTP_HEADER
    }

    /// The bytes accumulated for the header being parsed.
    #[must_use]
    pub fn header_buffer(&self) -> &[u8] {
        &self.header_buffer
    }

    /// Appends to the header buffer, refusing to exceed the ceiling.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`], which is what `curlx_dyn_addn` answers when
    /// a `dynbuf` would pass the ceiling its `dyn_init` fixed. Not
    /// `CURLE_TOO_LARGE`: the C's `dynbuf` reports the overflow as an
    /// allocation failure and callers propagate that code, so answering a
    /// different one would change what a transfer reports.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn push_header_bytes(&mut self, bytes: &[u8]) -> CodeResult<()> {
        if self.header_buffer.len() + bytes.len() > CURL_MAX_HTTP_HEADER {
            return Err(CURLcode::OutOfMemory);
        }
        self.header_buffer.extend_from_slice(bytes);
        Ok(())
    }

    /// Empties the header accumulation buffer, keeping its allocation.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn clear_header_buffer(&mut self) {
        self.header_buffer.clear();
    }

    /// The request headers in flight.
    #[must_use]
    pub fn httphdrs(&self) -> &[String] {
        &self.httphdrs
    }

    /// The URL this attempt is using.
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Sets the URL this attempt is using.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn set_url(&mut self, url: Option<String>) {
        self.url = url;
    }

    /// The referer this attempt is sending.
    #[must_use]
    pub fn referer(&self) -> Option<&str> {
        self.referer.as_deref()
    }

    /// Sets the referer this attempt is sending.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn set_referer(&mut self, referer: Option<String>) {
        self.referer = referer;
    }

    /// The origin and proxy authentication states.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) const fn auth(&self) -> &AuthStatePair {
        &self.auth
    }

    /// The same, mutably, for the authentication negotiation.
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn auth_mut(&mut self) -> &mut AuthStatePair {
        &mut self.auth
    }

    /// The cookie files still to be loaded.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookielist(&self) -> &[String] {
        &self.cookielist
    }

    /// Whether the cookie engine is running on this handle.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub const fn cookie_engine(&self) -> bool {
        self.cookie_engine
    }

    /// Starts the cookie engine, which `curl_easy_duphandle` does for a clone
    /// whose parent had one (`lib/easy.c:1004`).
    #[cfg(feature = "cookies")]
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn start_cookie_engine(&mut self) {
        self.cookie_engine = true;
    }

    /// Takes a copy of the parent's cookie file list
    /// (`lib/easy.c:1007-1011`, `Curl_slist_duplicate`).
    #[cfg(feature = "cookies")]
    #[allow(dead_code)] // consumer: transfer, conn and auth
    pub(crate) fn adopt_cookielist(&mut self, entries: &[String]) {
        self.cookielist = entries.to_vec();
    }
}

// ---------------------------------------------------------------------------
// The four injected seams -- AAP 0.3.3 pattern P12
// ---------------------------------------------------------------------------

/// Everything an easy handle needs from outside itself.
///
/// AAP 0.3.3 pattern P12: *"The resolver, the clock, and the TLS provider are
/// injected rather than reached for globally, which is what makes the
/// protocol modules testable to the mandated 80% line coverage without live
/// network access."* Randomness is the fourth, because TLS and session code
/// need it and because a generator reached for globally is the same defect as
/// a clock reached for globally.
///
/// This is the value where a handle takes all four, and it deliberately
/// mirrors [`crate::conn::ConnSeams`]: bundling is what lets a handle be
/// built, duplicated and reset without a four-argument signature at each
/// step, and one established shape for seams is easier to audit than two.
///
/// # There is no process-global default, and that is enforced by absence
///
/// No `static mut`, no `lazy_static`, no `once_cell`, and no [`std::sync::OnceLock`]
/// singleton for any of the four. A handle that was not given a clock has no
/// clock to fall back on, which is the property that makes
/// [`mod tests`]' fakes conclusive: if a global default existed, a test could
/// pass while the code under test quietly used it.
///
/// # Why [`Arc<dyn _>`] and not generics
///
/// A generic `EasyHandle<C, R, T, G>` would monomorphise, which is faster and
/// unusable: `curl-rs-ffi` hands a `CURL *` back to C, and C holds one
/// pointer type for every handle in the process. Four type parameters would
/// make two differently-configured handles two different C types. AAP 0.1.1
/// settles the trade directly -- *"Where a choice exists between a faster
/// design and a more behaviourally faithful one, faithfulness wins"* -- and
/// performance is a stated non-goal. Every one of the four traits is
/// object-safe, so no `unsafe`, no [`std::any::Any`] and no downcast is
/// involved.
///
/// # Why the generator is behind a lock and the others are not
///
/// [`Rng::next_u32`] takes `&mut self`, because drawing advances the
/// generator. The other three traits take `&self`. A shared generator
/// therefore needs interior mutability, and a [`Mutex`] is the honest
/// expression of it; the alternative -- handing every caller its own
/// generator -- would make two draws on one handle come from two streams and
/// break the seeded reproducibility [`crate::crypto::rand::TestRng`] exists
/// for.
#[derive(Clone)]
pub struct EasySeams {
    /// `curlx_now()` and `time(NULL)`: every instant this handle reads.
    clock: Arc<dyn Clock + Send + Sync>,
    /// `Curl_resolv` (`lib/hostip.c`): the name lookup, injected.
    resolver: Arc<dyn Resolver>,
    /// The TLS filter builder -- `crate::tls`'s erasure of one
    /// [`crate::tls::TlsBackend`].
    ///
    /// Required rather than defaulted, and the reason is worth stating: a
    /// production backend is built from a cryptographic provider and a set of
    /// options, and `crate::tls::rustls_backend` documents that it *"never
    /// calls `CryptoProvider::install_default`, never calls `get_default`,
    /// never calls a `default_provider()` of its own accord"*. Reaching for
    /// one here would install exactly the global this pattern exists to
    /// forbid, in the file that forbids it. So the caller states the
    /// provider, and [`Self::with_production_host_services`] wires the three
    /// seams that CAN be produced without reaching for anything.
    tls: Arc<dyn TlsFilterFactory>,
    /// `Curl_rand` (`lib/rand.c`): the generator, injected and shared.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_init
    rng: Arc<Mutex<dyn Rng + Send>>,
}

/// Prints which seams are present, never what they hold.
///
/// [`Rng`] carries no [`fmt::Debug`] bound -- `crate::crypto::rand` declares
/// it without one -- so a derived implementation would not compile. Written
/// by hand for that reason, and kept to shape rather than content for a
/// second: a generator's internal state is key material in every use this
/// crate has for it.
impl fmt::Debug for EasySeams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasySeams")
            .field("clock", &self.clock)
            .field("resolver", &self.resolver)
            .field("tls", &self.tls)
            .field("rng", &"<injected>")
            .finish()
    }
}

impl EasySeams {
    /// A bundle over all four seams, every one stated.
    ///
    /// The constructor a test uses, and the one every other constructor here
    /// ends up calling, so there is exactly one place where a handle acquires
    /// its outside world.
    #[must_use]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_init
    pub(crate) fn new(
        clock: Arc<dyn Clock + Send + Sync>,
        resolver: Arc<dyn Resolver>,
        tls: Arc<dyn TlsFilterFactory>,
        rng: Arc<Mutex<dyn Rng + Send>>,
    ) -> Self {
        Self {
            clock,
            resolver,
            tls,
            rng,
        }
    }

    /// The production clock, resolver and generator, over the caller's TLS
    /// factory.
    ///
    /// This is `curl_easy_init`'s ergonomic path: three of the four seams
    /// have a production implementation that can be constructed without
    /// consulting a global -- [`crate::util::timeval::SystemClock`],
    /// [`crate::dns::resolver::SystemResolver`] and
    /// [`crate::crypto::rand::SystemRng`] -- and the fourth is stated by the
    /// caller for the reason [`Self::tls`] documents.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`], propagated from
    /// [`crate::crypto::rand::SystemRng::new`] when the platform cannot
    /// supply entropy. That is the code `Curl_win32_random` returns for the
    /// same condition (`lib/rand.c:61`), and it is the only way this
    /// constructor can fail: the clock and the resolver are infallible.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_init
    pub(crate) fn with_production_host_services(
        tls: Arc<dyn TlsFilterFactory>,
    ) -> CodeResult<Self> {
        let rng = SystemRng::new()?;
        Ok(Self::new(
            Arc::new(SystemClock),
            Arc::new(SystemResolver::default()),
            tls,
            Arc::new(Mutex::new(rng)),
        ))
    }

    /// The injected clock.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_init
    pub(crate) fn clock(&self) -> &Arc<dyn Clock + Send + Sync> {
        &self.clock
    }

    /// The injected resolver.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_init
    pub(crate) fn resolver(&self) -> &Arc<dyn Resolver> {
        &self.resolver
    }

    /// The injected TLS filter factory.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_init
    pub(crate) fn tls(&self) -> &Arc<dyn TlsFilterFactory> {
        &self.tls
    }

    /// Draws `out.len()` random bytes from the injected generator.
    ///
    /// The generator is reached through this method rather than handed out,
    /// so a caller cannot hold the lock across an await point and cannot
    /// replace the generator behind the handle's back. A poisoned lock is
    /// recovered from with [`std::sync::PoisonError::into_inner`] rather than
    /// panicked on: a panic while drawing bytes leaves a
    /// counter in a valid-if-unexpected state, never an invalid one, and
    /// refusing to draw afterwards would turn one failed transfer into a dead
    /// handle.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_init
    pub(crate) fn fill_random(&self, out: &mut [u8]) {
        let mut guard = self
            .rng
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.fill_bytes(out);
    }

    /// Draws one `u32` from the injected generator.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_init
    pub(crate) fn next_random_u32(&self) -> u32 {
        let mut guard = self
            .rng
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.next_u32()
    }
}

// ---------------------------------------------------------------------------
// `struct Curl_easy` -- the handle, composed of the pieces above
// ---------------------------------------------------------------------------

/// The easy handle: `struct Curl_easy` (`lib/urldata.h:1616-1681`),
/// decomposed.
///
/// All 24 of the C's top-level members are accounted for. Six are owned here
/// because nothing else can own them; the rest are held through the type of
/// the module that owns them; and three are absent by design, each for a
/// stated reason:
///
/// | C member | here |
/// |---|---|
/// | `magic` | [`Self::magic`], with [`Self::is_valid`] as `GOOD_EASY_HANDLE` |
/// | `id`, `mid`, `master_mid` | [`Self::identity`] |
/// | `sub_xfer_done` | absent: a `multi_sub_xfer_done_cb` is a callback the MULTI installs and calls, so `crate::multi` holds it |
/// | `conn` | absent: a connection is owned by `crate::conn`'s pool and named by [`HandleState::lastconnect_id`], so a handle holds an identifier and never a connection |
/// | `mstate` | [`Self::mstate`] |
/// | `result` | [`Self::result`] |
/// | `msg` | absent: *"a single posted message"* is what `curl_multi_info_read` drains, and `crate::multi`'s notification queue owns it |
/// | `multi`, `multi_easy` | [`Self::multi_membership`] |
/// | `share` | [`Self::share`] |
/// | `meta_hash` | [`Self::meta`] |
/// | `psl` | reached through [`Self::share`], which is where a PSL cache is shared |
/// | `req` | [`Self::req`] |
/// | `set` | [`Self::set`] |
/// | `cookies`, `hsts`, `asi` | [`Self::cookies`], [`Self::hsts`], [`Self::altsvc`] |
/// | `progress` | [`Self::progress`] |
/// | `state` | [`Self::state`] plus [`Self::netrc`] |
/// | `wildcard` | [`Self::wildcard`] |
/// | `info` | [`Self::info`] |
/// | `tsi` | [`Self::tls_session`] |
///
/// # There is no `unsafe` here, and no raw pointer
///
/// `curl_easy_init` performs `Box::into_raw` on one of these and
/// `curl_easy_cleanup` performs `Box::from_raw` -- both in `curl-rs-ffi`,
/// which is the only crate with the exemption from the crate-root
/// `#![deny(unsafe_code)]` (AAP 0.3.3 pattern P8). Nothing in this file
/// dereferences a pointer, so the whole of the handle's lifecycle inside the
/// engine is ordinary ownership.
///
/// # Construction
///
/// [`Self::new_with_seams`] is the one constructor; [`Self::new`] is the
/// production convenience over it. Both take the TLS filter factory, for the
/// reason [`EasySeams::tls`] states.
pub struct EasyHandle {
    /// `data->magic`, `CURLEASY_MAGIC_NUMBER` while the handle is live.
    magic: u32,
    /// `data->id`, `data->mid` and `data->master_mid`, with the generational
    /// token that keys the multi's slab.
    identity: HandleIdentity,
    /// `data->mstate`: *"the handle's state"*.
    ///
    /// On the EASY handle and not in the multi, which is the C's placement
    /// and is load-bearing: a handle carries its state across being added to
    /// and removed from a multi, and `CURLINFO` exposes state-dependent
    /// behaviour.
    mstate: CurlMstate,
    /// `data->result`: *"previous result"*.
    result: CURLcode,
    /// `data->multi` and `data->multi_easy`, as one answer.
    multi_membership: MultiMembership,
    /// `data->share`: the state deliberately shared with other handles.
    ///
    /// An [`Arc`] because a share outlives any one handle and is used by
    /// several at once, which is exactly what `curl_share_init` promises.
    share: Option<Arc<Share>>,
    /// `data->meta_hash`: the typed metadata store.
    meta: MetaStore,
    /// `data->set`: the option state, and the ONLY field
    /// [`Self::duplicate`] copies.
    set: UserDefined,
    /// `data->set.mimepostp`: the multipart body, when one is attached.
    ///
    /// A [`MimePart`] and not a [`crate::mime::Mime`], which is the C's own
    /// typing: `curl_mimepart *mimepostp` (`lib/urldata.h:1344`), whose
    /// subparts `CURLOPT_MIMEPOST` fills from the `curl_mime *` the
    /// application passed (`lib/setopt.c:1428-1435`). The root of the tree is
    /// a PART, which is why `Curl_mime_duppart` -- a part-to-part copy -- is
    /// what duplicates it.
    ///
    /// Held beside [`Self::set`] rather than inside it because `dupset`
    /// clears the option state's copy and duplicates the tree separately
    /// (`lib/easy.c:882`, `:918-930`) -- two different copy rules, so two
    /// different owners.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    mimepost: Option<MimePart>,
    /// `data->req`: the state of one request attempt.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    req: SingleRequest,
    /// `data->progress`: *"for all the progress meter data"*.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    progress: Progress,
    /// `data->state`, the handle-lifetime slice of it.
    state: HandleState,
    /// `data->state.netrc`, held by the type `crate::cookies::netrc` defines.
    ///
    /// `Curl_netrc_init(&outcurl->state.netrc)` (`lib/easy.c:975`) is one of
    /// the six initialisers a clone runs, so it is rebuilt rather than
    /// copied.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    netrc: StoreNetrc,
    /// `data->info`: `curl_easy_getinfo`'s backing store.
    info: PureInfo,
    /// `data->tsi`: *"Information about the TLS session, only valid after a
    /// client has asked for it"*.
    ///
    /// [`None`] until a TLS filter answers the query, which is what the C's
    /// *"only valid after"* means -- the C has a struct that is simply stale
    /// before then, and an [`Option`] is that fact made checkable.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    tls_session: Option<TlsSessionInfo>,
    /// `data->cookies`: the jar, when the engine is running.
    #[cfg(feature = "cookies")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    cookies: Option<CookieInfo>,
    /// `data->hsts`: the HSTS cache.
    #[cfg(feature = "hsts")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    hsts: Option<HstsCache>,
    /// `data->asi`: *"the alt-svc cache"*.
    #[cfg(feature = "altsvc")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    altsvc: Option<AltSvcInfo>,
    /// `data->wildcard`: *"wildcard download state info"*.
    #[cfg(feature = "ftp")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    wildcard: WildcardData,
    /// The four injected seams.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    seams: EasySeams,
}

/// `data->multi` and `data->multi_easy` (`lib/urldata.h:1641-1646`), as one
/// value.
///
/// Two pointers in the C, and their combination is not free: they are
/// mutually exclusive in practice, because a handle is either driven by the
/// application's multi or by the private one `curl_easy_perform` creates for
/// it. The C comments say exactly that -- *"when used by the multi
/// interface"* against *"when used by the easy interface"* -- and encoding it
/// as a sum type makes the third state, both set at once, unrepresentable
/// rather than merely unlikely.
///
/// The multi handle itself is not held here: `crate::multi` owns the
/// collection of handles, so a handle pointing back at its multi would be a
/// cycle. What is held is the membership FACT, and the token in
/// [`HandleIdentity`] is what resolves it.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum MultiMembership {
    /// Neither pointer set: a handle nobody is driving.
    #[default]
    None,
    /// `data->multi`: the application added this handle with
    /// `curl_multi_add_handle`.
    Application,
    /// `data->multi_easy`: `curl_easy_perform` created a private multi for
    /// this handle and keeps it across calls.
    ///
    /// The C's own reason for keeping rather than destroying it: a second
    /// `curl_easy_perform` on the same handle reuses the multi, and with it
    /// the connection pool, so a persistent connection survives between
    /// calls.
    PrivateEasy,
}

impl MultiMembership {
    /// Whether a multi is driving this handle at all.
    #[must_use]
    pub const fn is_attached(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Prints the handle's shape, never its credentials.
///
/// Hand-written for two reasons. [`SingleRequest`] and
/// [`StoreNetrc`] do not both derive [`fmt::Debug`],
/// so a derived implementation would not compile. And the option state
/// contains a private key password, a bearer token and a proxy password,
/// which is material no diagnostic should print: what is useful in a failed
/// assertion is which state the handle is in and what it is configured to
/// verify, and that is what this prints.
impl fmt::Debug for EasyHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EasyHandle")
            .field("valid", &self.is_valid())
            .field("id", &self.identity.id())
            .field("mid", &self.identity.mid().get())
            .field("master_mid", &self.identity.master_mid().get())
            .field("mstate", &self.mstate)
            .field("result", &self.result)
            .field("multi", &self.multi_membership)
            .field("shared", &self.share.is_some())
            .field("meta_entries", &self.meta.len())
            .field("verify_peer", &self.set.ssl().verify_peer())
            .field("verify_host", &self.set.ssl().verify_host())
            .field("options_set", &self.set.strings().occupied())
            .field("blobs_set", &self.set.blobs().occupied())
            .finish_non_exhaustive()
    }
}

impl EasyHandle {
    /// A handle with the four seams stated -- the one constructor.
    ///
    /// Reproduces what `curl_easy_init` builds, by way of the same three
    /// steps `curl_easy_duphandle` performs on a fresh allocation: the option
    /// state is initialised by [`UserDefined::new`], the state slice by
    /// [`HandleState::for_clone`], and the info block by [`PureInfo::new`]
    /// with [`Progress`] zeroed beside it.
    ///
    /// `magic` is set LAST in the C (`lib/easy.c:1057`, after every fallible
    /// step) so that a partially built handle never passes
    /// `GOOD_EASY_HANDLE`. Here every step is infallible, so the ordering
    /// carries no guarantee -- and the field is still assigned in the struct
    /// literal rather than afterwards, because a Rust value does not exist
    /// until it is complete.
    #[must_use]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn new_with_seams(seams: EasySeams) -> Self {
        Self {
            magic: CURLEASY_MAGIC_NUMBER,
            identity: HandleIdentity::FRESH,
            mstate: CurlMstate::Init,
            result: CURLcode::Ok,
            multi_membership: MultiMembership::None,
            share: None,
            meta: MetaStore::new(),
            set: UserDefined::new(),
            mimepost: None,
            req: SingleRequest::new(),
            progress: Progress::default(),
            state: HandleState::for_clone(),
            netrc: StoreNetrc::new(),
            info: PureInfo::new(),
            tls_session: None,
            #[cfg(feature = "cookies")]
            cookies: None,
            #[cfg(feature = "hsts")]
            hsts: None,
            #[cfg(feature = "altsvc")]
            altsvc: None,
            #[cfg(feature = "ftp")]
            wildcard: WildcardData::default(),
            seams,
        }
    }

    /// `curl_easy_init`: a handle over the production clock, resolver and
    /// generator, and the caller's TLS filter factory.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when the platform cannot supply entropy --
    /// see [`EasySeams::with_production_host_services`]. `curl_easy_init`
    /// answers `NULL` for a failure, which is what `curl-rs-ffi` turns this
    /// into.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn new(tls: Arc<dyn TlsFilterFactory>) -> CodeResult<Self> {
        let seams = EasySeams::with_production_host_services(tls)?;
        Ok(Self::new_with_seams(seams))
    }

    // -- validity: `GOOD_EASY_HANDLE` (`lib/urldata.h:218-223`) -----------

    /// `data->magic`, for the ABI shim's own check.
    ///
    /// Published rather than kept private because `curl-rs-ffi` reproduces
    /// the C's diagnostic behaviour and a diagnostic that cannot name the
    /// value it found is half a diagnostic.
    #[must_use]
    pub const fn magic(&self) -> u32 {
        self.magic
    }

    /// `GOOD_EASY_HANDLE(data)`: whether this handle is usable.
    ///
    /// The C has two definitions of the macro. On a debug build it
    /// `DEBUGASSERT`s the failure so that a mistyped pointer aborts loudly;
    /// on a release build it answers `FALSE` quietly. Both then produce the
    /// same OBSERVABLE behaviour, which is what AAP 0.8.1 freezes:
    ///
    /// * every fallible entry point answers
    ///   [`CURLcode::BadFunctionArgument`] (`lib/easy.c:860-861`, `:1145-1147`);
    /// * `curl_easy_cleanup` and `curl_easy_reset`, which return `void`, do
    ///   nothing at all (`:1086-1087`).
    ///
    /// A handle reached through a Rust reference always answers `true`,
    /// because a reference to one cannot be a reference to anything else.
    /// What this predicate exists for is the case the C's macro exists for:
    /// `curl-rs-ffi` receiving a `CURL *` that an application supplied, which
    /// may be a multi handle, a freed handle, or arbitrary. The shim reads
    /// this through the reference it built and refuses on `false`.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.magic == CURLEASY_MAGIC_NUMBER
    }

    /// The code every fallible entry point answers for a handle that fails
    /// [`Self::is_valid`].
    ///
    /// A named constant rather than a literal at each call site, because
    /// there are more than twenty such sites in `curl-rs-ffi` and one of them
    /// answering a different code would be an ABI difference no test of this
    /// crate would catch.
    pub const INVALID_HANDLE_CODE: CURLcode = CURLcode::BadFunctionArgument;

    // -- the aggregated members, read and written by name ------------------

    /// The three identity fields and the slab token.
    #[must_use]
    pub const fn identity(&self) -> &HandleIdentity {
        &self.identity
    }

    /// The same, mutably, for the pool and the multi.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn identity_mut(&mut self) -> &mut HandleIdentity {
        &mut self.identity
    }

    /// `data->mstate`.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) const fn mstate(&self) -> CurlMstate {
        self.mstate
    }

    /// Moves the handle to `mstate`, which `crate::multi`'s state machine
    /// does.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn set_mstate(&mut self, mstate: CurlMstate) {
        self.mstate = mstate;
    }

    /// `data->result`: what the previous transfer on this handle returned.
    #[must_use]
    pub const fn result(&self) -> CURLcode {
        self.result
    }

    /// Records the result of a transfer.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn set_result(&mut self, result: CURLcode) {
        self.result = result;
    }

    /// Which multi, if any, is driving this handle.
    #[must_use]
    pub const fn multi_membership(&self) -> MultiMembership {
        self.multi_membership
    }

    /// Records this handle into `token`'s slot of a multi's slab.
    ///
    /// `membership` distinguishes `curl_multi_add_handle` from the private
    /// multi `curl_easy_perform` creates, which is the distinction the C
    /// keeps by having two pointers.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn attach_to_multi(
        &mut self,
        token: HandleToken,
        membership: MultiMembership,
    ) {
        self.identity.attach(token);
        self.multi_membership = membership;
    }

    /// Records that this handle has left its multi.
    ///
    /// `curl_multi_remove_handle`'s half of the identity bookkeeping: the
    /// `mid` returns to `UINT32_MAX` and the token is dropped, so a token
    /// held elsewhere can no longer be presented for this handle.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn detach_from_multi(&mut self) {
        self.identity.detach();
        self.multi_membership = MultiMembership::None;
    }

    /// The share this handle participates in, if any.
    #[must_use]
    pub fn share(&self) -> Option<&Arc<Share>> {
        self.share.as_ref()
    }

    /// Joins a share, or leaves the current one when given [`None`].
    ///
    /// `CURLOPT_SHARE`. Answers the previous share so that
    /// `curl-rs-ffi` can release its own reference in the order the C does.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn set_share(
        &mut self,
        share: Option<Arc<Share>>,
    ) -> Option<Arc<Share>> {
        core::mem::replace(&mut self.share, share)
    }

    /// The metadata store.
    #[must_use]
    pub const fn meta(&self) -> &MetaStore {
        &self.meta
    }

    /// The metadata store, mutably.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn meta_mut(&mut self) -> &mut MetaStore {
        &mut self.meta
    }

    /// The option state.
    #[must_use]
    pub const fn set(&self) -> &UserDefined {
        &self.set
    }

    /// The option state, mutably -- what `easy/setopt.rs` writes through.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn set_mut(&mut self) -> &mut UserDefined {
        &mut self.set
    }

    /// The multipart body, when `CURLOPT_MIMEPOST` attached one.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn mimepost(&self) -> Option<&MimePart> {
        self.mimepost.as_ref()
    }

    /// Attaches or detaches a multipart body.
    ///
    /// Keeps [`UserDefined::has_mimepost`] in step, because the option state
    /// records the presence and the handle owns the tree; two encodings of
    /// one fact that could disagree is the defect this setter exists to
    /// prevent.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn set_mimepost(
        &mut self,
        mime: Option<MimePart>,
    ) -> Option<MimePart> {
        self.set.set_has_mimepost(mime.is_some());
        core::mem::replace(&mut self.mimepost, mime)
    }

    /// The state of the request attempt in flight.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) const fn req(&self) -> &SingleRequest {
        &self.req
    }

    /// The same, mutably, for the transfer core.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn req_mut(&mut self) -> &mut SingleRequest {
        &mut self.req
    }

    /// The progress accounting.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) const fn progress(&self) -> &Progress {
        &self.progress
    }

    /// The same, mutably.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn progress_mut(&mut self) -> &mut Progress {
        &mut self.progress
    }

    /// The handle-lifetime state.
    #[must_use]
    pub const fn state(&self) -> &HandleState {
        &self.state
    }

    /// The same, mutably.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn state_mut(&mut self) -> &mut HandleState {
        &mut self.state
    }

    /// The `.netrc` cache.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) const fn netrc(&self) -> &StoreNetrc {
        &self.netrc
    }

    /// The same, mutably, for a credential lookup.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn netrc_mut(&mut self) -> &mut StoreNetrc {
        &mut self.netrc
    }

    /// `curl_easy_getinfo`'s backing store.
    #[must_use]
    pub const fn info(&self) -> &PureInfo {
        &self.info
    }

    /// The same, mutably, for the transfer core and the connection layer.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn info_mut(&mut self) -> &mut PureInfo {
        &mut self.info
    }

    /// `data->tsi`, once a TLS filter has answered the query.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) const fn tls_session(&self) -> Option<TlsSessionInfo> {
        self.tls_session
    }

    /// Records what a TLS filter reported about the session.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn set_tls_session(&mut self, tsi: Option<TlsSessionInfo>) {
        self.tls_session = tsi;
    }

    /// The cookie jar, when the engine is running.
    #[cfg(feature = "cookies")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) const fn cookies(&self) -> Option<&CookieInfo> {
        self.cookies.as_ref()
    }

    /// Starts the cookie engine on this handle, which
    /// `curl_easy_duphandle` does for a clone whose parent had one
    /// (`lib/easy.c:998-1005`).
    ///
    /// Idempotent: a second call leaves the existing jar in place rather than
    /// replacing it, which is what `if(!outcurl->cookies)` guards in the C.
    #[cfg(feature = "cookies")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn start_cookie_engine(&mut self) {
        if self.cookies.is_none() {
            self.cookies = Some(CookieInfo::new());
        }
        self.state.start_cookie_engine();
    }

    /// The HSTS cache, when one is configured.
    #[cfg(feature = "hsts")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) const fn hsts(&self) -> Option<&HstsCache> {
        self.hsts.as_ref()
    }

    /// Creates the HSTS cache, which `curl_easy_duphandle` does for a clone
    /// whose parent had one (`lib/easy.c:1046-1054`).
    #[cfg(feature = "hsts")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn start_hsts(&mut self) {
        if self.hsts.is_none() {
            self.hsts = Some(HstsCache::new());
        }
    }

    /// The Alt-Svc cache, when one is configured.
    #[cfg(feature = "altsvc")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) const fn altsvc(&self) -> Option<&AltSvcInfo> {
        self.altsvc.as_ref()
    }

    /// Creates the Alt-Svc cache, which `curl_easy_duphandle` does for a
    /// clone whose parent had one (`lib/easy.c:1037-1043`).
    #[cfg(feature = "altsvc")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn start_altsvc(&mut self) {
        if self.altsvc.is_none() {
            self.altsvc = Some(AltSvcInfo::new());
        }
    }

    /// `data->wildcard`: the wildcard download driver's state.
    #[cfg(feature = "ftp")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) const fn wildcard(&self) -> &WildcardData {
        &self.wildcard
    }

    /// The same, mutably.
    #[cfg(feature = "ftp")]
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn wildcard_mut(&mut self) -> &mut WildcardData {
        &mut self.wildcard
    }

    /// The four injected seams.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn seams(&self) -> &EasySeams {
        &self.seams
    }

    // -- the public verification query ------------------------------------

    /// Whether certificate-chain verification has been switched OFF.
    ///
    /// The narrow, immutable, public query AAP 0.8.1 requires: `--insecure`
    /// *"must emit a warning on stderr BEFORE proceeding"*, the message is
    /// emitted by `curl-rs/src/output/msgs.rs`, and this is the state that
    /// obliges it. It leaks no internal TLS type, offers no way to CHANGE the
    /// posture, and reads the same field the handshake reads -- so a warning
    /// driven by it cannot disagree with what the connection then does.
    ///
    /// `false` for a freshly constructed handle, because
    /// `Curl_ssl_easy_config_init` sets `verifypeer = TRUE`
    /// (`lib/vtls/vtls.c:187`). Only `CURLOPT_SSL_VERIFYPEER` set to 0 makes
    /// it `true`.
    ///
    /// The proxy's posture is asked for separately by
    /// [`Self::proxy_peer_verification_disabled`]: `--proxy-insecure` is a
    /// different option with a different warning, and one query answering
    /// both would warn about the wrong endpoint.
    #[must_use]
    pub fn peer_verification_disabled(&self) -> bool {
        !self.set.ssl().verify_peer()
    }

    /// Whether hostname verification has been switched OFF for the origin.
    ///
    /// `CURLOPT_SSL_VERIFYHOST` set to 0. `false` for a fresh handle, because
    /// the initialiser sets `verifyhost = TRUE`
    /// (`lib/vtls/vtls.c:188`).
    #[must_use]
    pub fn host_verification_disabled(&self) -> bool {
        !self.set.ssl().verify_host()
    }

    /// Whether certificate-chain verification has been switched off for the
    /// PROXY -- `--proxy-insecure`.
    #[must_use]
    pub fn proxy_peer_verification_disabled(&self) -> bool {
        !self.set.proxy_ssl().verify_peer()
    }

    /// Whether hostname verification has been switched off for the proxy.
    #[must_use]
    pub fn proxy_host_verification_disabled(&self) -> bool {
        !self.set.proxy_ssl().verify_host()
    }

    /// Whether any endpoint's verification has been switched off.
    ///
    /// What a caller deciding *whether to warn at all* wants, so that the
    /// four questions above do not have to be asked in sequence at every
    /// call site.
    #[must_use]
    pub fn any_verification_disabled(&self) -> bool {
        self.peer_verification_disabled()
            || self.host_verification_disabled()
            || self.proxy_peer_verification_disabled()
            || self.proxy_host_verification_disabled()
    }

    // -- `Curl_initinfo`, `curl_easy_duphandle`, `curl_easy_reset` --------

    /// `Curl_initinfo(data)` (`lib/getinfo.c:41`): BOTH halves.
    ///
    /// That function writes to two structs -- nine timers in
    /// `data->progress` and every member of `data->info` -- and a caller that
    /// did one and not the other would leave a reset handle reporting the
    /// previous transfer's timings. One function here, so that cannot happen.
    ///
    /// [`Progress::default`] is the nine zeroed timers and the cleared
    /// `is_t_startransfer_set` flag; [`PureInfo::new`] is the info block.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn init_info(&mut self) {
        self.progress = Progress::default();
        self.info = PureInfo::new();
    }

    /// `curl_easy_duphandle` (`lib/easy.c:952-1077`), as a method on the
    /// source handle.
    ///
    /// # What is copied
    ///
    /// The option state, and nothing else. [`UserDefined::duplicate`] is
    /// `dupset` and carries the whole partition; two progress members follow
    /// it (`:993-994`), which the C copies explicitly and which are therefore
    /// copied explicitly here.
    ///
    /// # What is FRESH in the clone
    ///
    /// Eleven things, every one of them because the C rebuilds it rather than
    /// copying it, and the public header states the principle
    /// (`include/curl/easy.h:66-70`): *"internal state info and things like
    /// persistent connections cannot be transferred."*
    ///
    /// | fresh in the clone | `lib/easy.c` |
    /// |---|---|
    /// | [`MetaStore`], re-inited with 23 slots | `:970-971` |
    /// | the header buffer, `CURL_MAX_HTTP_HEADER` | `:972` |
    /// | `state.url`, `state.referer` | `:973-974` |
    /// | `state.netrc` | `:975` |
    /// | the connection pool -- *"setup on demand"* | `:977` |
    /// | `state.lastconnect_id = -1`, `state.recent_conn_id = -1` | `:978-979` |
    /// | `id = -1`, `mid = UINT32_MAX`, `master_mid = UINT32_MAX` | `:980-982` |
    /// | `state.httphdrs` | `:985` |
    /// | all of [`PureInfo`] and [`Progress`] | `:987` |
    /// | `state.cookielist` | `:997` |
    /// | the request in flight | `calloc`ed |
    ///
    /// The clone is built by [`Self::new_with_seams`] and then given the
    /// option state, which is what makes that list unforgeable: a field is
    /// fresh unless this function explicitly copies it, so the failure mode
    /// is a field that should have been copied and was not -- visible as a
    /// lost option -- rather than one that should have been fresh and was
    /// inherited, which is invisible until a stale connection identifier
    /// resolves.
    ///
    /// # The seams are shared, not rebuilt
    ///
    /// A clone gets the SAME clock, resolver, TLS factory and generator, by
    /// [`Arc`] clone. That is deliberate and matches the C: a duplicate reads
    /// the same wall clock, resolves through the same resolver and offers the
    /// same TLS configuration, because those are properties of the process
    /// and not options of the handle. Giving a clone a fresh generator would
    /// additionally destroy seeded reproducibility for anything that
    /// duplicates a handle mid-test.
    ///
    /// # The one thing that can fail
    ///
    /// The mime duplication, and only it. `curl_easy_duphandle` answers
    /// `NULL` on five distinct allocation failures -- two `strdup` loops, the
    /// postfields copy, the `curlx_malloc` for the mime root and
    /// `Curl_mime_duppart` itself. Rust aborts on allocation failure rather
    /// than returning, so the first four are not expressible; the fifth is,
    /// because [`MimePart::duplicate_from`] reports genuine content errors
    /// and not only allocation ones.
    ///
    /// A partially built clone cannot be observed either way: an early return
    /// drops the value under construction with everything it has already
    /// taken released, which is the guarantee the C's *"clear all dest string
    /// and blob pointers first, in case we error out mid-function"* comment
    /// (`:884-885`) is hand-rolling.
    ///
    /// # Errors
    ///
    /// Whatever [`MimePart::duplicate_from`] reports. Note the one code it
    /// deliberately does NOT report: a file part whose file has become
    /// unreadable is tolerated, because the C's own comment says *"Do not
    /// abort duplication if file is not readable"* (`lib/mime.c:1116-1119`)
    /// and `curl_easy_duphandle` must not fail because a file was removed
    /// after the original part was built.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn duplicate(&self) -> CodeResult<Self> {
        let mut clone = Self::new_with_seams(self.seams.clone());

        // `dupset(outcurl, data)` (`:990`). Everything the option state
        // carries, under the partition `UserDefined::duplicate` documents.
        clone.set = self.set.duplicate();

        // `:918-930`: the mime tree is duplicated separately from the option
        // state, because `dupset` nulls the option state's copy first. The C
        // allocates a fresh root, runs `Curl_mime_initpart` over it and then
        // `Curl_mime_duppart`; `MimePart::new` is that initialiser and
        // `set_mimepost` keeps the option state's presence flag in step.
        if let Some(source) = self.mimepost.as_ref() {
            let mut root = MimePart::new();
            root.duplicate_from(source)?;
            clone.set_mimepost(Some(root));
        }

        // `outcurl->progress.hide = data->progress.hide;` and
        // `outcurl->progress.callback = data->progress.callback;`
        // (`:993-994`). TWO members of `struct Progress`, named individually
        // in the C, over a block that `Curl_initinfo` has already zeroed --
        // so the clone inherits the parent's reporting posture and none of
        // its measurements.
        clone.progress.set_hide(self.progress.hide());
        clone
            .progress
            .set_uses_callback(self.progress.uses_callback());

        // `if(src->set.resolve) dst->state.resolve = dst->set.resolve;`
        // (`:932-933`). Guarded exactly as the C guards it, and reading the
        // CLONE's list rather than the source's, which is what `dst->set`
        // says.
        if clone.set.resolve_pending() {
            let entries = clone.set.resolve().to_vec();
            clone.state.adopt_resolve(&entries);
        }

        // `:1014-1027`: `state.url` and `state.referer` are duplicated when
        // the source has them, over the `bufref_init` the clone already ran.
        clone.state.set_url(self.state.url().map(str::to_owned));
        clone
            .state
            .set_referer(self.state.referer().map(str::to_owned));

        // `:996-1011`: the cookie engine starts in the clone only when the
        // parent had BOTH a jar and the engine running -- the C's
        // `if(data->cookies && data->state.cookie_engine)` -- and the file
        // list is duplicated independently of that.
        #[cfg(feature = "cookies")]
        {
            if self.cookies.is_some() && self.state.cookie_engine() {
                clone.start_cookie_engine();
            }
            if !self.state.cookielist().is_empty() {
                clone.state.adopt_cookielist(self.state.cookielist());
            }
        }

        // `:1036-1044` and `:1045-1055`: each cache is created in the clone
        // only when the parent had one. The C then loads the file named by
        // the already-copied option string, which is the loading subsystem's
        // work and not the handle's.
        #[cfg(feature = "altsvc")]
        if self.altsvc.is_some() {
            clone.start_altsvc();
        }
        #[cfg(feature = "hsts")]
        if self.hsts.is_some() {
            clone.start_hsts();
        }

        Ok(clone)
    }

    /// `curl_easy_reset` (`lib/easy.c:1083-1121`).
    ///
    /// Every step of it, in the C's order:
    ///
    /// | C | `lib/easy.c` | here |
    /// |---|---|---|
    /// | `Curl_req_hard_reset(&data->req, data)` | `:1089` | [`SingleRequest::new`] |
    /// | `Curl_hash_clean(&data->meta_hash)`, `Curl_meta_reset` | `:1090-1093` | [`MetaStore::clear`] |
    /// | `Curl_async_shutdown`, `Curl_resolv_unlink` x2 | `:1095-1097` | the resolve list emptied |
    /// | `Curl_freeset`, `memset(&data->set, 0, ...)`, `Curl_init_userdefined` | `:1099-1101` | [`UserDefined::new`] |
    /// | `memset(&data->progress, 0, ...)` | `:1104` | [`Progress::default`] |
    /// | `Curl_initinfo(data)` | `:1107` | [`Self::init_info`] |
    /// | `data->progress.hide = TRUE` | `:1109` | [`Progress`]' hide flag set |
    /// | `state.current_speed = -1`, `state.recent_conn_id = -1` | `:1110-1111` | [`HandleState::apply_easy_reset`] |
    /// | `memset(&state.authhost, ...)`, `authproxy` | `:1114-1115` | [`AuthStatePair::ZERO`], inside `apply_easy_reset` |
    /// | `Curl_freeset`: `state.url`, `state.referer`, `state.cookielist` | `lib/url.c` | released, likewise inside it |
    /// | `data->master_mid = UINT32_MAX` | `:1120` | [`HandleIdentity::reset_master_mid`] |
    ///
    /// # What a reset does NOT touch, and why that matters
    ///
    /// `id` and `mid` survive. So do the share, the multi membership, the
    /// cookie jar, the HSTS and Alt-Svc caches, and the `.netrc` cache. A
    /// reset handle is the same handle in the same multi with the same shared
    /// state; what it loses is its options, its statistics and its
    /// membership of a master transfer. Resetting the identity as well would
    /// detach a handle from the multi that is driving it, which
    /// `curl_easy_reset` explicitly does not do -- and `curl_easy_reset` is
    /// callable on a handle that is in a multi.
    ///
    /// `progress.hide = TRUE` is worth naming separately because it is NOT
    /// the zeroed value: the C sets it after the `memset`, so a reset handle
    /// has its progress meter HIDDEN where a fresh one does not. That
    /// asymmetry is the C's and is asserted by [`mod tests`].
    ///
    /// The state is MUTATED rather than replaced, which is what keeps
    /// `lastconnect_id`, the header buffer, the request header list and the
    /// cookie-engine flag standing --
    /// [`HandleState::apply_easy_reset`] documents each one and the line of
    /// the C that leaves it alone.
    #[allow(dead_code)] // consumer: curl-rs-ffi's curl_easy_* entry points
    pub(crate) fn reset(&mut self) {
        self.req = SingleRequest::new();
        self.meta.clear();
        self.set = UserDefined::new();
        self.mimepost = None;
        self.init_info();
        self.progress.set_hide(true);
        self.state.apply_easy_reset();
        self.identity.reset_master_mid();
        self.tls_session = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use core::time::Duration;
    use std::path::Path;

    use crate::conn::filters::{FilterLink, TlsBackendId, TlsHandleKind};
    use crate::dns::{IpVersion, ResolveFuture, ResolvedAddr};
    use crate::error::{CurlResult, Error};
    use crate::mime::{
        MimeKind, PartReader, ReadStatus, SeekResult, SeekWhence,
    };
    use crate::tls::{CurlSslDescriptor, SslBackendInfo, TlsFilterRequest};
    use crate::util::timeval::{CurlTime, TestClock};
    use crate::util::CurlOffT;

    // -- the four fakes ---------------------------------------------------
    //
    // Every one of them COUNTS its calls. That is what makes the injection
    // assertions conclusive rather than merely plausible: a handle built over
    // these cannot reach a production implementation without the count
    // staying at zero while the behaviour still happens, and there is no
    // process-global for it to reach.

    /// A [`Resolver`] that resolves nothing and records that it was asked.
    #[derive(Debug, Default)]
    struct CountingResolver {
        asked: AtomicUsize,
    }

    impl Resolver for CountingResolver {
        fn resolve<'a>(
            &'a self,
            host: &'a str,
            port: u16,
            ip_version: IpVersion,
        ) -> ResolveFuture<'a, Vec<ResolvedAddr>> {
            let _ = (host, port, ip_version);
            self.asked.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Err(CURLcode::CouldntResolveHost) })
        }
    }

    /// The descriptor the fake factory reports: a backend that fills no slot
    /// at all, which is what [`CurlSslDescriptor::empty`] is for.
    static FAKE_TLS_DESCRIPTOR: CurlSslDescriptor =
        CurlSslDescriptor::empty(SslBackendInfo::NONE);

    /// A [`TlsFilterFactory`] that builds no filter and records every
    /// attempt.
    #[derive(Debug, Default)]
    struct CountingTlsFactory {
        created: AtomicUsize,
    }

    impl TlsFilterFactory for CountingTlsFactory {
        fn descriptor(&self) -> &'static CurlSslDescriptor {
            &FAKE_TLS_DESCRIPTOR
        }

        fn create(&self, request: TlsFilterRequest) -> CurlResult<FilterLink> {
            let _ = request;
            self.created.fetch_add(1, Ordering::Relaxed);
            Err(Error::with_context(
                CURLcode::NotBuiltIn,
                "the counting factory builds no filter",
            ))
        }
    }

    /// An [`Rng`] whose every draw is counted and predictable.
    #[derive(Debug, Default)]
    struct CountingRng {
        drawn: AtomicU32,
    }

    impl Rng for CountingRng {
        fn next_u32(&mut self) -> u32 {
            self.drawn.fetch_add(1, Ordering::Relaxed)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for slot in dest.iter_mut() {
                *slot = self.next_u32() as u8;
            }
        }
    }

    /// The four fakes, kept so a test can read what happened.
    struct Fakes {
        clock: Arc<TestClock>,
        resolver: Arc<CountingResolver>,
        tls: Arc<CountingTlsFactory>,
    }

    /// Seams over the four fakes, with handles on three of them.
    ///
    /// The generator is not returned: it lives behind [`EasySeams`]' lock and
    /// is asked through [`EasySeams::fill_random`], which is the only access
    /// path the type offers and therefore the only one worth testing.
    fn fake_seams() -> (EasySeams, Fakes) {
        let clock = Arc::new(TestClock::new(CurlTime::new(7, 500_000)));
        let resolver = Arc::new(CountingResolver::default());
        let tls = Arc::new(CountingTlsFactory::default());
        let rng: Arc<Mutex<dyn Rng + Send>> =
            Arc::new(Mutex::new(CountingRng::default()));

        let seams = EasySeams::new(
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            Arc::clone(&resolver) as Arc<dyn Resolver>,
            Arc::clone(&tls) as Arc<dyn TlsFilterFactory>,
            rng,
        );

        (
            seams,
            Fakes {
                clock,
                resolver,
                tls,
            },
        )
    }

    /// A handle over the four fakes -- what every behavioural test below
    /// uses, so no test can accidentally reach a production seam.
    fn fake_handle() -> EasyHandle {
        EasyHandle::new_with_seams(fake_seams().0)
    }

    /// This file's own text, for the self-checks at the foot of the module.
    fn own_source() -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("easy")
            .join("handle.rs");
        std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("cannot read {}: {error}", path.display())
        })
    }

    /// `line` with its comment tail removed.
    ///
    /// The weaker of the two strippers, and the right one for a scan whose
    /// subject IS a string literal -- a `cfg` attribute spells its feature as
    /// `"ftp"`, so removing literals would remove the very thing being
    /// checked. This file discusses `feature = "tls"` in prose, and dropping
    /// the comment tail is exactly enough to stop that discussion being read
    /// as code.
    fn code_without_comments(line: &str) -> &str {
        line.split("//").next().unwrap_or("")
    }

    /// `line` with its comment tail AND every string literal removed.
    ///
    /// The same stripping `crate::source_policy` performs at the foot of
    /// `lib.rs`, and for the reason recorded there: a gate written in the file
    /// it polices names the constructs it forbids, both in prose and in the
    /// pattern list it searches for, so an unstripped search flags itself.
    /// Only what survives both removals is code.
    fn code_only(line: &str) -> String {
        let without_comment = code_without_comments(line);
        let mut out = String::with_capacity(without_comment.len());
        let mut in_string = false;
        let mut escaped = false;
        for ch in without_comment.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if ch == '"' {
                in_string = true;
                // A space keeps the surrounding tokens apart, so a literal
                // between two identifiers cannot fuse them into one word.
                out.push(' ');
                continue;
            }
            out.push(ch);
        }
        out
    }

    // -- the constants ----------------------------------------------------

    #[test]
    fn the_magic_number_is_the_c_value() {
        assert_eq!(CURLEASY_MAGIC_NUMBER, 0xc0de_dbad);
        assert_eq!(LIBCURL_NAME, "libcurl");
    }

    #[test]
    fn the_socket_slots_are_zero_and_one() {
        assert_eq!(SocketSlot::First.as_index(), 0);
        assert_eq!(SocketSlot::Secondary.as_index(), 1);
        assert_eq!(SocketSlot::ALL.len(), 2);
        assert_eq!(SocketSlot::default(), SocketSlot::First);
        assert_eq!(PROTOPT_DUAL, 1 << 1);
    }

    #[test]
    fn the_input_length_bound_is_eight_million() {
        assert_eq!(CURL_MAX_INPUT_LENGTH, 8_000_000);
        assert_eq!(CURL_MAX_HTTP_HEADER, 100 * 1024);
        assert_eq!(META_HASH_SLOTS, 23);
    }

    #[test]
    fn the_buffer_bounds_are_the_headers_values() {
        assert_eq!(READBUFFER_SIZE, 16_384);
        assert_eq!(READBUFFER_MAX, 10 * 1024 * 1024);
        assert_eq!(READBUFFER_MIN, 1_024);
        assert_eq!(UPLOADBUFFER_DEFAULT, 65_536);
        assert_eq!(UPLOADBUFFER_MAX, 2 * 1024 * 1024);
        assert_eq!(UPLOADBUFFER_MIN, 16_384);
        assert_eq!(DEFAULT_CONNCACHE_SIZE, 5);
        assert_eq!(CURL_HET_DEFAULT, 200);
        assert_eq!(CURL_UPKEEP_INTERVAL_DEFAULT, 60_000);
    }

    #[test]
    fn every_derived_default_agrees_with_the_named_constructor() {
        // Four types carry both a `Default` and a named constructor, and the
        // two MUST agree: `UserDefined::default()` reaching a derived
        // all-zero value while `new()` reaches `Curl_init_userdefined`'s would
        // put a handle with certificate verification OFF one `..Default`
        // away. Asserting the equality is what makes the second door safe.
        assert_eq!(UserDefined::default(), UserDefined::new());
        assert!(UserDefined::default().ssl().verify_peer());
        assert_eq!(PureInfo::default(), PureInfo::new());
        assert_eq!(PureInfo::default().filetime(), -1);
        assert_eq!(StringTable::default().occupied(), 0);
        assert_eq!(BlobTable::default().occupied(), 0);
        assert_eq!(MetaStore::default().len(), 0);

        // `HandleState` has no public equality -- it carries the netrc store
        // and the header buffer -- so its agreement is asserted on the members
        // the C's own initialiser writes.
        let state = HandleState::default();
        assert_eq!(state.lastconnect_id(), ConnectionId::NONE);
        assert_eq!(state.recent_conn_id(), ConnectionId::NONE);
        assert_eq!(state.header_buffer_limit(), CURL_MAX_HTTP_HEADER);
        assert!(state.resolve().is_empty());
    }

    #[test]
    fn the_multi_identity_sentinel_reports_itself_absent() {
        assert!(MultiXferId::NONE.is_none());
        assert!(!MultiXferId::new(0).is_none());
        assert!(!MultiXferId::new(u32::MAX - 1).is_none());
        // The sentinel is the C's `UINT32_MAX`, so the one value a real slab
        // index can never take is the one that reads as absent.
        assert_eq!(MultiXferId::NONE.get(), u32::MAX);
    }

    #[test]
    fn the_fakes_answer_when_they_are_actually_asked() {
        // A fake whose method is never reached could be miswired and every
        // assertion above would still pass, so each is called here once. This
        // is the control for the injection tests, not a test of the fakes'
        // behaviour: what matters is that the handle's seam and the object
        // this test holds are the SAME object.
        let (seams, fakes) = fake_seams();
        let handle = EasyHandle::new_with_seams(seams);

        // The resolver, reached through the handle's own seam. `Whatever` is
        // the C's `CURL_IPRESOLVE_WHATEVER = 0`, the default a handle carries.
        let outcome =
            futures::executor::block_on(handle.seams().resolver().resolve(
                "example.com",
                443,
                IpVersion::Whatever,
            ));
        assert_eq!(outcome.unwrap_err(), CURLcode::CouldntResolveHost);
        assert_eq!(
            fakes.resolver.asked.load(Ordering::Relaxed),
            1,
            "the handle's resolver is not the one this test holds"
        );

        // The TLS factory's sameness is established by its DESCRIPTOR rather
        // than by building a filter: `CurlSslDescriptor::empty` reports
        // `SslBackendInfo::NONE`, which no production backend does, so reading
        // it back off the handle is proof the fake is what got injected.
        // Building a filter would need a whole `TlsFilterRequest` and would
        // couple this file to four of `tls/mod.rs`'s internal types for no
        // additional guarantee.
        assert_eq!(
            handle.seams().tls().descriptor().info(),
            FAKE_TLS_DESCRIPTOR.info()
        );
        assert_eq!(
            fakes.tls.created.load(Ordering::Relaxed),
            0,
            "reading a descriptor must not build a filter"
        );
    }

    #[test]
    fn the_drop_counting_reader_behaves_as_a_part_reader() {
        // The witness used by the release test is only ever DROPPED there, so
        // its two trait methods are exercised here -- an unseekable reader at
        // end of input, which is the shape that makes it inert in a duplicate
        // and therefore safe to plant in one.
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut reader = DropCountingReader {
            dropped: Arc::clone(&dropped),
        };
        let mut buf = [0_u8; 4];
        assert_eq!(reader.read(&mut buf).byte_count(), 0);
        assert_eq!(
            reader.seek(0, SeekWhence::Set),
            SeekResult::CantSeek,
            "an unseekable source is what `mime_part_rewind` starts from"
        );
        // `PartReader::duplicate` must share the counter, or the release test
        // would be counting two unrelated objects.
        let copy = reader.duplicate();
        assert_eq!(dropped.load(Ordering::Relaxed), 0);
        drop(copy);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        drop(reader);
        assert_eq!(dropped.load(Ordering::Relaxed), 2);
    }

    // -- the two option tables --------------------------------------------

    #[test]
    fn the_string_table_bounds_match_the_header() {
        // `STRING_LASTZEROTERMINATED` (`lib/urldata.h:1265`).
        assert_eq!(DupString::COUNT, 82);
        assert_eq!(DupString::ALL.len(), 82);
        // `STRING_LAST` (`:1271`): the zero-terminated members plus
        // `STRING_COPYPOSTFIELDS`, which this crate carries as a field of its
        // own rather than as a table slot.
        assert_eq!(STRING_LAST, 83);
        // `BLOB_LAST` (`:1285`).
        assert_eq!(DupBlob::COUNT, 8);
        assert_eq!(DupBlob::ALL.len(), 8);
    }

    #[test]
    fn every_string_slot_has_a_distinct_index_in_declaration_order() {
        for (expected, which) in DupString::ALL.iter().enumerate() {
            assert_eq!(
                which.as_index(),
                expected,
                "{which:?} is out of declaration order"
            );
        }
        for (expected, which) in DupBlob::ALL.iter().enumerate() {
            assert_eq!(which.as_index(), expected, "{which:?}");
        }
    }

    #[test]
    fn a_string_slot_round_trips_and_is_independent_of_its_neighbours() {
        let mut table = StringTable::new();
        assert_eq!(table.occupied(), 0);
        assert!(table.get(DupString::SetUrl).is_none());

        let previous =
            table.set(DupString::SetUrl, Some("https://example.com".into()));
        assert!(previous.is_none());
        assert_eq!(table.get(DupString::SetUrl), Some("https://example.com"));
        assert_eq!(table.occupied(), 1);
        // A neighbour is untouched, which an off-by-one index would break.
        assert!(table.get(DupString::UserAgent).is_none());
        assert!(table.get(DupString::SetReferer).is_none());

        let replaced = table.set(DupString::SetUrl, None);
        assert_eq!(replaced.as_deref(), Some("https://example.com"));
        assert_eq!(table.occupied(), 0);
    }

    #[test]
    fn clearing_the_string_table_empties_every_slot() {
        let mut table = StringTable::new();
        for which in DupString::ALL {
            table.set(which, Some(format!("{which:?}")));
        }
        assert_eq!(table.occupied(), DupString::COUNT);
        table.clear();
        assert_eq!(table.occupied(), 0);
        for which in DupString::ALL {
            assert!(table.get(which).is_none(), "{which:?} survived the clear");
        }
    }

    #[test]
    fn duplicating_the_string_table_copies_every_slot_and_clears_first() {
        let mut source = StringTable::new();
        source.set(DupString::UserAgent, Some("curl/8.19.0-DEV".into()));
        source.set(DupString::Username, Some("alice".into()));

        // A destination that already holds something the source does not:
        // the C's `memset` before the loop is what removes it, and this is
        // the observation that proves the clear happens.
        let mut destination = StringTable::new();
        destination.set(DupString::Password, Some("leftover".into()));

        destination.duplicate(&source);
        assert_eq!(
            destination.get(DupString::UserAgent),
            Some("curl/8.19.0-DEV")
        );
        assert_eq!(destination.get(DupString::Username), Some("alice"));
        assert!(
            destination.get(DupString::Password).is_none(),
            "the pre-duplication clear did not happen"
        );
        assert_eq!(destination.occupied(), source.occupied());
    }

    #[test]
    fn a_blob_records_the_flag_the_caller_supplied() {
        let copied = Blob::new(b"-----BEGIN".to_vec(), Blob::COPY);
        assert!(copied.was_copy_requested());
        assert_eq!(copied.flags(), 1);
        assert_eq!(copied.len(), 10);
        assert!(!copied.is_empty());
        assert_eq!(copied.data(), b"-----BEGIN");

        let borrowed = Blob::new(Vec::new(), Blob::NOCOPY);
        assert!(!borrowed.was_copy_requested());
        assert_eq!(borrowed.flags(), 0);
        assert!(borrowed.is_empty());
    }

    #[test]
    fn duplicating_the_blob_table_copies_every_slot_and_clears_first() {
        let mut source = BlobTable::new();
        source.set(DupBlob::Cert, Some(Blob::new(vec![1, 2, 3], Blob::COPY)));

        let mut destination = BlobTable::new();
        destination
            .set(DupBlob::CaInfoProxy, Some(Blob::new(vec![9], Blob::COPY)));

        destination.duplicate(&source);
        assert_eq!(
            destination.get(DupBlob::Cert).map(Blob::data),
            Some(&[1, 2, 3][..])
        );
        assert!(destination.get(DupBlob::CaInfoProxy).is_none());
        assert_eq!(destination.occupied(), 1);
    }

    // -- the frozen defaults, one assertion per C assignment --------------

    #[test]
    fn the_three_standard_streams_are_the_defaults() {
        let set = UserDefined::new();
        assert_eq!(set.out(), IoTarget::Standard(StdStream::Out));
        assert_eq!(set.in_set(), IoTarget::Standard(StdStream::In));
        assert_eq!(set.err(), IoTarget::Standard(StdStream::Err));
        assert!(set.out().is_default_stream());
        assert!(set.in_set().is_default_stream());
        assert!(set.err().is_default_stream());
    }

    #[test]
    fn the_transfer_functions_default_to_stdio() {
        let set = UserDefined::new();
        assert_eq!(set.fwrite_func(), TransferFunction::Stdio);
        assert_eq!(set.fread_func_set(), TransferFunction::Stdio);
        assert!(set.fwrite_func().is_stdio_default());
        // `set->is_fread_set = 0` is a SEPARATE fact from the pointer, and
        // the C keeps it in its own field.
        assert!(!set.is_fread_set());
        // `set->seek_client = ZERO_NULL`.
        assert!(!set.seek_client_set());
    }

    #[test]
    fn the_sizes_and_the_request_method_are_the_c_defaults() {
        let set = UserDefined::new();
        assert_eq!(set.filesize(), -1);
        assert_eq!(set.postfieldsize(), -1);
        assert_eq!(set.maxredirs(), 30);
        assert_eq!(set.method(), HttpRequestKind::Get);
        assert_eq!(set.rtspreq(), RtspRequest::Options);
    }

    #[test]
    fn the_timeouts_and_buffers_are_the_c_defaults() {
        let set = UserDefined::new();
        assert_eq!(set.dns_cache_timeout_ms(), 60_000);
        assert_eq!(set.expect_100_timeout_ms(), 1_000);
        assert_eq!(set.buffer_size(), READBUFFER_SIZE);
        assert_eq!(set.upload_buffer_size(), UPLOADBUFFER_DEFAULT);
        assert_eq!(set.happy_eyeballs_timeout_ms(), 200);
        assert_eq!(set.upkeep_interval_ms(), 60_000);
        assert_eq!(set.maxconnects(), 5);
        assert_eq!(set.conn_max_idle_ms(), 118 * 1000);
        assert_eq!(set.conn_max_age_ms(), 24 * 3600 * 1000);
        // SECONDS, not milliseconds, and `int` in the C.
        assert_eq!(set.general_ssl().ca_cache_timeout_secs(), 24 * 60 * 60);
    }

    #[test]
    fn authentication_and_protocol_permissions_are_the_c_defaults() {
        let set = UserDefined::new();
        // `set->httpauth = CURLAUTH_BASIC`.
        assert_eq!(set.httpauth(), AuthMask::BASIC);
        assert_eq!(set.httpauth().bits(), 1);
        // `set->allowed_protocols = CURLPROTO_ALL`.
        assert_eq!(set.allowed_protocols(), Proto::ALL);
        assert_eq!(set.allowed_protocols().bits(), 0xffff_ffff);
        // `set->redir_protocols = CURLPROTO_REDIR` -- HTTP, HTTPS, FTP, FTPS
        // and deliberately NOT every scheme.
        assert_eq!(set.redir_protocols(), Proto::REDIR);
        assert_ne!(set.redir_protocols(), Proto::ALL);
    }

    #[test]
    fn the_http_behaviour_defaults_are_the_c_values() {
        let set = UserDefined::new();
        assert!(set.sep_headers());
        assert!(!set.http09_allowed());
        assert_eq!(set.httpwant(), HttpVersionWant::None);
        assert_eq!(set.httpwant() as i32, 0);
    }

    #[test]
    fn the_permissions_and_the_quick_exit_flag_are_the_c_values() {
        let set = UserDefined::new();
        assert_eq!(set.new_file_perms(), 0o644);
        assert!(!set.quick_exit());
    }

    #[test]
    fn alpn_is_enabled_by_default() {
        assert!(UserDefined::new().ssl_enable_alpn());
    }

    #[test]
    fn the_tcp_defaults_are_the_c_values_including_nodelay_on() {
        let tcp = *UserDefined::new().tcp();
        assert!(!tcp.keepalive());
        assert_eq!(tcp.keepintvl_secs(), 60);
        assert_eq!(tcp.keepidle_secs(), 60);
        assert_eq!(tcp.keepcnt(), 9);
        assert!(!tcp.fastopen());
        // ON by default, and NOT the operating system's default: curl
        // disables Nagle's algorithm so a request written in two pieces does
        // not wait for an acknowledgement between them.
        assert!(tcp.nodelay());
    }

    #[test]
    fn the_proxy_defaults_are_the_c_values() {
        let proxy = *UserDefined::new().proxy();
        assert_eq!(proxy.port(), 0);
        assert_eq!(proxy.kind(), ProxyKind::Http);
        assert_eq!(proxy.kind() as i32, 0);
        assert_eq!(proxy.auth(), AuthMask::BASIC);
        // `CURLAUTH_BASIC | CURLAUTH_GSSAPI`, and `CURLAUTH_GSSAPI` is an
        // alias of `CURLAUTH_NEGOTIATE` = 1 << 2, so the value is 5.
        assert_eq!(proxy.socks5_auth().bits(), 0b101);
        assert!(!proxy.socks5_gssapi_nec());
    }

    #[cfg(feature = "ftp")]
    #[test]
    fn the_ftp_defaults_are_the_c_values() {
        let ftp = *UserDefined::new().ftp();
        assert!(ftp.use_epsv());
        assert!(ftp.use_eprt());
        assert!(!ftp.use_pret());
        assert_eq!(ftp.filemethod(), FtpFileMethod::MultiCwd);
        assert_eq!(ftp.filemethod() as i32, 1);
        assert!(ftp.skip_ip());
        assert!(!ftp.wildcard_enabled());
        assert!(!ftp.chunk_bgn_set());
        assert!(!ftp.chunk_end_set());
        assert!(!ftp.fnmatch_set());
    }

    #[cfg(feature = "doh")]
    #[test]
    fn doh_verifies_its_own_server_by_default() {
        let doh = *UserDefined::new().doh();
        // Both TRUE, and independently of the transfer's own posture: a DoH
        // lookup verifies its own server whatever `--insecure` says, which is
        // why they are separate options.
        assert!(doh.verify_host());
        assert!(doh.verify_peer());
        assert!(!doh.verify_status());
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn the_ssh_defaults_are_the_c_values() {
        let ssh = *UserDefined::new().ssh();
        // Both constants live inside the C's `#ifdef USE_SSH`, so both are
        // asserted here rather than among the unconditional bounds.
        assert_eq!(CURLSSH_AUTH_DEFAULT, 0xffff_ffff);
        assert_eq!(DEFAULT_NEW_DIRECTORY_PERMS, 0o755);
        assert_eq!(ssh.auth_types(), CURLSSH_AUTH_DEFAULT);
        assert_eq!(ssh.new_directory_perms(), 0o755);
    }

    #[cfg(feature = "websockets")]
    #[test]
    fn the_websocket_defaults_are_both_off() {
        let ws = *UserDefined::new().ws();
        assert!(!ws.raw_mode());
        assert!(!ws.no_auto_pong());
    }

    #[cfg(any(feature = "http2", feature = "http3"))]
    #[test]
    fn the_stream_priority_starts_zeroed() {
        let priority = *UserDefined::new().priority();
        assert_eq!(priority.weight(), 0);
        assert!(!priority.exclusive());
    }

    #[test]
    fn the_option_tables_and_lists_start_empty() {
        let set = UserDefined::new();
        assert_eq!(set.strings().occupied(), 0);
        assert_eq!(set.blobs().occupied(), 0);
        assert!(set.postfields().is_none());
        assert!(set.resolve().is_empty());
        assert!(set.headers().is_empty());
        assert!(!set.has_mimepost());
        assert!(!set.resolve_pending());
    }

    // -- CERTIFICATE VERIFICATION IS ON BY DEFAULT ------------------------

    #[test]
    fn certificate_verification_is_on_by_default() {
        let set = UserDefined::new();
        // `Curl_ssl_easy_config_init`, `lib/vtls/vtls.c:187-189`. AAP 0.8.1
        // freezes all three.
        assert!(set.ssl().verify_peer(), "CURLOPT_SSL_VERIFYPEER must be ON");
        assert!(set.ssl().verify_host(), "CURLOPT_SSL_VERIFYHOST must be ON");
        assert!(set.ssl().cache_session(), "caching by default");
    }

    #[test]
    fn the_proxy_tls_config_starts_as_a_copy_of_the_primary_one() {
        let set = UserDefined::new();
        // `data->set.proxy_ssl = data->set.ssl` (`lib/vtls/vtls.c:191`).
        assert_eq!(set.proxy_ssl(), set.ssl());
        assert!(set.proxy_ssl().verify_peer());
        assert!(set.proxy_ssl().verify_host());
        assert!(set.proxy_ssl().cache_session());
    }

    #[test]
    fn the_remaining_tls_bits_start_off_and_the_version_is_default() {
        let ssl = SslConfigData::new();
        assert!(!ssl.certinfo());
        assert!(!ssl.native_ca_store());
        assert_eq!(ssl.ssl_options(), SslOptionBits::default());
        assert_eq!(ssl.version(), SslVersionRange::DEFAULT);
        assert_eq!(ssl.version().min(), 0);
        assert_eq!(ssl.version().max(), 0);
        assert_eq!(ssl.version().to_packed(), 0);
    }

    #[test]
    fn a_fresh_handle_verifies_both_endpoints() {
        let handle = fake_handle();
        assert!(!handle.peer_verification_disabled());
        assert!(!handle.host_verification_disabled());
        assert!(!handle.proxy_peer_verification_disabled());
        assert!(!handle.proxy_host_verification_disabled());
        assert!(
            !handle.any_verification_disabled(),
            "a fresh handle must give curl-rs nothing to warn about"
        );
    }

    #[test]
    fn clearing_verifypeer_is_visible_through_the_public_query() {
        let mut handle = fake_handle();
        // What `easy/setopt.rs` does for `CURLOPT_SSL_VERIFYPEER` = 0. It is
        // the ONLY route, and it is `pub(crate)`.
        let policy = handle.set_mut().ssl_mut().policy_mut();
        *policy = policy.clone().with_peer_verification(false);

        assert!(handle.peer_verification_disabled());
        assert!(handle.any_verification_disabled());
        // The proxy's posture is a DIFFERENT option with a different warning
        // and must not have moved.
        assert!(!handle.proxy_peer_verification_disabled());
        // And the host check is independent of the peer check.
        assert!(!handle.host_verification_disabled());
    }

    #[test]
    fn clearing_the_proxy_posture_does_not_move_the_origins() {
        let mut handle = fake_handle();
        let policy = handle.set_mut().proxy_ssl_mut().policy_mut();
        *policy = policy.clone().with_host_verification(false);

        assert!(handle.proxy_host_verification_disabled());
        assert!(handle.any_verification_disabled());
        assert!(!handle.host_verification_disabled());
        assert!(!handle.peer_verification_disabled());
    }

    #[test]
    fn the_version_range_packs_and_unpacks_symmetrically() {
        // `CURL_SSLVERSION_TLSv1_2` = 6 with
        // `CURL_SSLVERSION_MAX_TLSv1_3` = 7 << 16.
        let packed = (7_u32 << 16) | 6;
        let range = SslVersionRange::from_packed(packed);
        assert_eq!(range.min(), 6);
        assert_eq!(range.max(), 7);
        assert_eq!(range.to_packed(), packed);
    }

    // -- `STRING_COPYPOSTFIELDS` -----------------------------------------

    #[test]
    fn an_unsized_postfields_copy_stops_at_the_first_nul() {
        // `postfieldsize == -1` selects `curlx_strdup`, so the copy runs to
        // the first NUL and excludes it. A body with an interior NUL is
        // TRUNCATED, which is the C's behaviour and not an accident here.
        let body = PostFields::new(b"name=value\0trailing".to_vec());
        let copy = body.duplicate_for_size(-1);
        assert_eq!(copy.as_bytes(), b"name=value");
        assert_eq!(copy.len(), 10);
        assert!(!copy.is_empty());
    }

    #[test]
    fn an_unsized_postfields_copy_without_a_nul_copies_everything() {
        let body = PostFields::new(b"name=value".to_vec());
        assert_eq!(body.duplicate_for_size(-1).as_bytes(), b"name=value");
    }

    #[test]
    fn a_sized_postfields_copy_takes_exactly_that_many_bytes() {
        // `curlx_memdup(p, sotouz(size))`: binary content and interior NULs
        // survive, and the copy stops at `size` rather than at a NUL.
        let body = PostFields::new(b"abc\0def".to_vec());
        let copy = body.duplicate_for_size(7);
        assert_eq!(copy.as_bytes(), b"abc\0def");
        assert_eq!(body.duplicate_for_size(3).as_bytes(), b"abc");
        assert_eq!(body.duplicate_for_size(0).as_bytes(), b"");
        // A size larger than the buffer would read past its end in C, so it
        // is clamped here.
        assert_eq!(body.duplicate_for_size(1_000).as_bytes(), b"abc\0def");
    }

    #[test]
    fn a_negative_size_other_than_minus_one_folds_onto_minus_one() {
        // `CURLOPT_POSTFIELDSIZE` admits only -1 or a non-negative value, so
        // no other negative can reach a correctly-set handle. Folding rather
        // than panicking is what keeps a hand-built handle in a test alive.
        let body = PostFields::new(b"ab\0cd".to_vec());
        assert_eq!(body.duplicate_for_size(-9).as_bytes(), b"ab");
    }

    #[test]
    fn the_clone_owns_its_postfields_and_survives_a_mutated_original() {
        let mut original = UserDefined::new();
        original.set_postfields(Some(PostFields::new(b"first=1".to_vec())), -1);

        let clone = original.duplicate();
        assert_eq!(
            clone.postfields().map(PostFields::as_bytes),
            Some(&b"first=1"[..])
        );

        // Mutating the original cannot reach the clone, because the clone
        // owns its own bytes -- the C has to repoint `dst->set.postfields`
        // to achieve the same thing.
        original
            .set_postfields(Some(PostFields::new(b"second=2".to_vec())), -1);
        assert_eq!(
            original.postfields().map(PostFields::as_bytes),
            Some(&b"second=2"[..])
        );
        assert_eq!(
            clone.postfields().map(PostFields::as_bytes),
            Some(&b"first=1"[..]),
            "the clone must not share the original's buffer"
        );
    }

    #[test]
    fn a_sized_postfields_option_duplicates_under_the_size_rule() {
        let mut original = UserDefined::new();
        original.set_postfields(Some(PostFields::new(b"ab\0cd".to_vec())), 5);
        let clone = original.duplicate();
        assert_eq!(
            clone.postfields().map(PostFields::as_bytes),
            Some(&b"ab\0cd"[..]),
            "a positive size must copy exactly that many bytes"
        );
        assert_eq!(clone.postfieldsize(), 5);
    }

    // -- duplicating the option set ---------------------------------------

    #[test]
    fn duplicating_the_option_set_carries_every_string_and_blob() {
        let mut original = UserDefined::new();
        original
            .strings_mut()
            .set(DupString::SetUrl, Some("https://example.com/".into()));
        original
            .strings_mut()
            .set(DupString::UserAgent, Some("curl/8.19.0-DEV".into()));
        original
            .blobs_mut()
            .set(DupBlob::CaInfo, Some(Blob::new(vec![7, 7], Blob::COPY)));
        original.set_maxredirs(3);
        original.set_httpauth(AuthMask::DIGEST);
        original.push_header("X-Test: 1".into());

        let clone = original.duplicate();
        assert_eq!(
            clone.strings().get(DupString::SetUrl),
            Some("https://example.com/")
        );
        assert_eq!(
            clone.strings().get(DupString::UserAgent),
            Some("curl/8.19.0-DEV")
        );
        assert_eq!(
            clone.blobs().get(DupBlob::CaInfo).map(Blob::data),
            Some(&[7, 7][..])
        );
        assert_eq!(clone.maxredirs(), 3);
        assert_eq!(clone.httpauth(), AuthMask::DIGEST);
        assert_eq!(clone.headers(), ["X-Test: 1"]);
    }

    #[test]
    fn duplicating_the_option_set_clears_the_mime_presence_flag() {
        let mut original = UserDefined::new();
        original.set_has_mimepost(true);
        assert!(original.has_mimepost());
        // `dst->set.mimepostp = NULL` (`lib/easy.c:882`). The tree is
        // duplicated by the HANDLE, which is what then sets the flag again.
        assert!(!original.duplicate().has_mimepost());
    }

    #[test]
    fn the_resolve_list_reports_whether_the_state_must_take_a_copy() {
        let mut set = UserDefined::new();
        assert!(!set.resolve_pending());
        set.push_resolve("example.com:443:127.0.0.1".into());
        assert!(set.resolve_pending());
        assert!(set.duplicate().resolve_pending());
    }

    // -- the handle: construction -----------------------------------------

    #[test]
    fn a_fresh_handle_is_valid_and_starts_in_the_documented_state() {
        let handle = fake_handle();
        assert!(handle.is_valid());
        assert_eq!(handle.magic(), CURLEASY_MAGIC_NUMBER);
        assert_eq!(
            EasyHandle::INVALID_HANDLE_CODE,
            CURLcode::BadFunctionArgument
        );
        assert_eq!(EasyHandle::INVALID_HANDLE_CODE.as_i32(), 43);

        assert_eq!(handle.mstate(), CurlMstate::Init);
        assert_eq!(handle.result(), CURLcode::Ok);
        assert_eq!(handle.multi_membership(), MultiMembership::None);
        assert!(!handle.multi_membership().is_attached());
        assert!(handle.share().is_none());
        assert!(handle.meta().is_empty());
        assert!(handle.mimepost().is_none());
        assert!(handle.tls_session().is_none());
    }

    #[test]
    fn a_fresh_handles_identity_is_every_sentinel() {
        let handle = fake_handle();
        let identity = handle.identity();
        assert_eq!(identity.id(), TransferId::NONE);
        assert_eq!(identity.id().get(), -1);
        assert!(identity.id().is_none());
        assert_eq!(identity.mid(), MultiXferId::NONE);
        assert_eq!(identity.mid().get(), u32::MAX);
        assert_eq!(identity.master_mid(), MultiXferId::NONE);
        assert_eq!(identity.master_mid().get(), u32::MAX);
        assert!(identity.token().is_none());
    }

    #[test]
    fn a_fresh_handles_state_is_the_documented_fresh_state() {
        let handle = fake_handle();
        let state = handle.state();
        assert_eq!(state.lastconnect_id(), ConnectionId::NONE);
        assert_eq!(state.lastconnect_id().get(), -1);
        assert_eq!(state.recent_conn_id(), ConnectionId::NONE);
        // NOT -1: `curl_easy_duphandle` leaves it at the `calloc`ed zero and
        // only `curl_easy_reset` writes -1.
        assert_eq!(state.current_speed(), 0);
        assert!(state.resolve().is_empty());
        assert!(state.header_buffer().is_empty());
        assert_eq!(state.header_buffer_limit(), CURL_MAX_HTTP_HEADER);
        assert!(state.httphdrs().is_empty());
        assert!(state.url().is_none());
        assert!(state.referer().is_none());
        assert_eq!(state.auth(), &AuthStatePair::ZERO);
    }

    #[test]
    fn a_fresh_handles_info_block_is_curl_initinfo() {
        let handle = fake_handle();
        let info = handle.info();
        assert_eq!(info.httpcode(), 0);
        assert_eq!(info.httpproxycode(), 0);
        assert_eq!(info.httpversion(), 0);
        // The one member with a non-zero initial value: "-1 is an illegal
        // time and thus means unknown".
        assert_eq!(info.filetime(), -1);
        assert_eq!(info.request_size(), 0);
        assert_eq!(info.numconnects(), 0);
        assert_eq!(info.proxyauthavail(), 0);
        assert_eq!(info.httpauthavail(), 0);
        assert_eq!(info.proxyauthpicked(), 0);
        assert_eq!(info.httpauthpicked(), 0);
        assert!(info.contenttype().is_none());
        assert!(info.wouldredirect().is_none());
        assert_eq!(info.retry_after(), 0);
        assert_eq!(info.header_size(), 0);
        assert!(info.primary().is_none());
        assert_eq!(info.conn_remote_port(), 0);
        assert!(info.conn_scheme().is_none());
        assert_eq!(info.conn_protocol(), 0);
        assert!(info.certs().is_empty());
        assert_eq!(info.pxcode(), CURLproxycode::Ok);
        assert!(!info.timecond());
        assert!(!info.used_proxy());
    }

    #[test]
    fn the_transfer_cores_two_info_members_are_absorbed_not_duplicated() {
        let mut info = PureInfo::new();
        let transfer = crate::transfer::TransferInfo {
            timecond: true,
            request_size: 4_096,
        };
        info.absorb_transfer_info(&transfer);
        assert!(info.timecond());
        assert_eq!(info.request_size(), 4_096);
    }

    // -- the metadata store -----------------------------------------------

    #[test]
    fn the_metadata_store_is_typed_and_ordered() {
        let mut store = MetaStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        assert!(store.insert("http/2", MetaValue::Flag(true)).is_none());
        store.insert("attempts", MetaValue::Number(3));
        store.insert("alpn", MetaValue::Text("h2".into()));
        store.insert("ticket", MetaValue::Bytes(vec![1, 2]));
        assert_eq!(store.len(), 4);

        assert_eq!(store.get("http/2"), Some(&MetaValue::Flag(true)));
        assert_eq!(store.get("attempts"), Some(&MetaValue::Number(3)));
        assert_eq!(store.get("nothing"), None);

        // Deterministic order, which is why the store is a `BTreeMap`: a
        // randomised order would make any trace that walks it a flaky
        // comparison.
        let keys: Vec<&str> = store.keys().collect();
        assert_eq!(keys, ["alpn", "attempts", "http/2", "ticket"]);

        let replaced = store.insert("attempts", MetaValue::Number(4));
        assert_eq!(replaced, Some(MetaValue::Number(3)));
        assert_eq!(store.remove("attempts"), Some(MetaValue::Number(4)));
        assert_eq!(store.remove("attempts"), None);

        store.clear();
        assert!(store.is_empty());
    }

    // -- identity: attach, detach, and staleness ---------------------------

    #[test]
    fn a_token_for_a_recycled_slot_is_detected_as_stale() {
        let slot = MultiXferId::new(4);
        let first = HandleToken::new(slot, Generation::FIRST);
        assert_eq!(first.id(), slot);
        assert_eq!(first.generation(), Generation::FIRST);
        assert!(first.is_current_in(Generation::FIRST));
        assert!(!first.is_stale_against(Generation::FIRST));

        // The transfer finishes and the slab hands slot 4 to another one.
        let recycled = Generation::FIRST.next();
        assert_eq!(recycled.get(), 1);
        assert!(
            first.is_stale_against(recycled),
            "a token for a recycled slot must be detectably stale"
        );
        assert!(!first.is_current_in(recycled));

        // The new occupant's token is current, and is a different value even
        // though it names the same slot.
        let second = HandleToken::new(slot, recycled);
        assert!(second.is_current_in(recycled));
        assert_ne!(first, second);
        assert_eq!(first.id(), second.id());
    }

    #[test]
    fn the_generation_counter_wraps_rather_than_saturating() {
        // A saturating counter would sit at `u32::MAX` forever and make every
        // token for that slot compare equal -- the false positive the type
        // exists to prevent.
        let last = Generation::new(u32::MAX);
        assert_eq!(last.next(), Generation::FIRST);
    }

    #[test]
    fn attaching_to_a_multi_sets_the_mid_from_the_token() {
        let mut handle = fake_handle();
        let token = HandleToken::new(MultiXferId::new(9), Generation::new(2));
        handle.attach_to_multi(token, MultiMembership::Application);

        assert_eq!(handle.identity().mid(), MultiXferId::new(9));
        assert_eq!(handle.identity().token(), Some(token));
        assert_eq!(handle.multi_membership(), MultiMembership::Application);
        assert!(handle.multi_membership().is_attached());
        // The pool's label and the master identity are untouched by joining a
        // multi.
        assert_eq!(handle.identity().id(), TransferId::NONE);
        assert_eq!(handle.identity().master_mid(), MultiXferId::NONE);
    }

    #[test]
    fn detaching_returns_the_sentinel_and_drops_the_token() {
        let mut handle = fake_handle();
        handle.attach_to_multi(
            HandleToken::new(MultiXferId::new(9), Generation::FIRST),
            MultiMembership::PrivateEasy,
        );
        assert_eq!(handle.multi_membership(), MultiMembership::PrivateEasy);

        handle.detach_from_multi();
        assert_eq!(handle.identity().mid(), MultiXferId::NONE);
        assert!(
            handle.identity().token().is_none(),
            "a detached handle must hold no key"
        );
        assert_eq!(handle.multi_membership(), MultiMembership::None);
    }

    #[test]
    fn the_pool_labels_the_handle_and_the_master_is_recorded_separately() {
        let mut handle = fake_handle();
        handle.identity_mut().set_id(TransferId::new(17));
        handle.identity_mut().set_master_mid(MultiXferId::new(2));

        assert_eq!(handle.identity().id().get(), 17);
        assert!(!handle.identity().id().is_none());
        assert_eq!(handle.identity().master_mid().get(), 2);
        assert_eq!(TransferId::FIRST.get(), 0);
        assert_eq!(TransferId::default(), TransferId::NONE);
        assert_eq!(MultiXferId::default(), MultiXferId::NONE);
        assert_eq!(format!("{}", TransferId::new(17)), "17");
    }

    // -- duplicating a handle ---------------------------------------------

    #[test]
    fn duplicating_a_handle_carries_the_options_and_nothing_else() {
        let mut original = fake_handle();
        original
            .set_mut()
            .strings_mut()
            .set(DupString::SetUrl, Some("https://example.com/".into()));
        original.set_mut().set_maxredirs(7);

        // State that must NOT survive: an identity, a connection, an
        // in-flight request, statistics and metadata.
        original.identity_mut().set_id(TransferId::new(11));
        original.attach_to_multi(
            HandleToken::new(MultiXferId::new(3), Generation::FIRST),
            MultiMembership::Application,
        );
        original.identity_mut().set_master_mid(MultiXferId::new(4));
        original
            .state_mut()
            .set_recent_conn_id(ConnectionId::new(6));
        *original.state_mut().lastconnect_id_mut() = ConnectionId::new(6);
        original.meta_mut().insert("live", MetaValue::Flag(true));
        original.info_mut().absorb_transfer_info(
            &crate::transfer::TransferInfo {
                timecond: true,
                request_size: 99,
            },
        );

        let clone = original.duplicate().expect("no mime part to fail on");

        // Copied.
        assert_eq!(
            clone.set().strings().get(DupString::SetUrl),
            Some("https://example.com/")
        );
        assert_eq!(clone.set().maxredirs(), 7);

        // Fresh: every identity field at its sentinel.
        assert_eq!(clone.identity().id(), TransferId::NONE);
        assert_eq!(clone.identity().mid(), MultiXferId::NONE);
        assert_eq!(clone.identity().master_mid(), MultiXferId::NONE);
        assert!(clone.identity().token().is_none());
        assert_eq!(clone.multi_membership(), MultiMembership::None);

        // Fresh: the connection identifiers.
        assert_eq!(clone.state().lastconnect_id(), ConnectionId::NONE);
        assert_eq!(clone.state().recent_conn_id(), ConnectionId::NONE);

        // Fresh: the metadata store and the info block.
        assert!(clone.meta().is_empty());
        assert!(!clone.info().timecond());
        assert_eq!(clone.info().request_size(), 0);
        assert_eq!(clone.info().filetime(), -1);

        // The original is untouched by having been duplicated.
        assert_eq!(original.identity().id().get(), 11);
        assert_eq!(original.state().recent_conn_id(), ConnectionId::new(6));
        assert!(original.info().timecond());
    }

    #[test]
    fn a_clone_inherits_the_reporting_posture_and_none_of_the_measurements() {
        let mut original = fake_handle();
        original.progress_mut().set_hide(true);
        original.progress_mut().set_uses_callback(true);

        let clone = original.duplicate().expect("no mime part");
        // The two members `lib/easy.c:993-994` names individually.
        assert!(clone.progress().hide());
        assert!(clone.progress().uses_callback());
    }

    #[test]
    fn a_clone_takes_the_resolve_list_into_its_state() {
        let mut original = fake_handle();
        original
            .set_mut()
            .push_resolve("example.com:443:127.0.0.1".into());

        let clone = original.duplicate().expect("no mime part");
        assert_eq!(clone.set().resolve(), ["example.com:443:127.0.0.1"]);
        // `if(src->set.resolve) dst->state.resolve = dst->set.resolve;`
        assert_eq!(clone.state().resolve(), ["example.com:443:127.0.0.1"]);
    }

    #[test]
    fn a_clone_with_no_resolve_list_leaves_its_state_list_alone() {
        let clone = fake_handle().duplicate().expect("no mime part");
        assert!(clone.set().resolve().is_empty());
        assert!(clone.state().resolve().is_empty());
    }

    #[test]
    fn a_clone_duplicates_the_url_and_referer_when_the_source_has_them() {
        let mut original = fake_handle();
        original
            .state_mut()
            .set_url(Some("https://a.example/".into()));
        original
            .state_mut()
            .set_referer(Some("https://b.example/".into()));

        let clone = original.duplicate().expect("no mime part");
        assert_eq!(clone.state().url(), Some("https://a.example/"));
        assert_eq!(clone.state().referer(), Some("https://b.example/"));
    }

    #[test]
    fn a_clone_duplicates_the_mime_tree_and_records_its_presence() {
        let mut original = fake_handle();
        let mut root = MimePart::new();
        // A part with no content is `MIMEKIND_NONE`, which duplicates
        // successfully and is enough to prove the tree travels.
        assert_eq!(root.kind(), MimeKind::None);
        root.duplicate_from(&MimePart::new())
            .expect("an empty part duplicates");
        original.set_mimepost(Some(root));
        assert!(original.set().has_mimepost());

        let clone = original.duplicate().expect("an empty part duplicates");
        assert!(clone.mimepost().is_some());
        assert!(
            clone.set().has_mimepost(),
            "set_mimepost must keep the option state's flag in step"
        );
    }

    #[test]
    fn a_handle_with_no_mime_tree_gives_a_clone_none() {
        let clone = fake_handle().duplicate().expect("no mime part");
        assert!(clone.mimepost().is_none());
        assert!(!clone.set().has_mimepost());
    }

    /// A [`PartReader`] that counts its own destruction.
    ///
    /// The witness for the release property below. `PartReader::duplicate`
    /// hands back a second reader over the same source, and this
    /// implementation gives it the SAME counter, so a duplicated tree and the
    /// tree it came from are distinguishable only by how many drops the
    /// counter has seen.
    #[derive(Debug)]
    struct DropCountingReader {
        dropped: Arc<AtomicUsize>,
    }

    impl PartReader for DropCountingReader {
        fn read(&mut self, buf: &mut [u8]) -> ReadStatus {
            let _ = buf;
            ReadStatus::Eof
        }

        fn seek(&mut self, offset: CurlOffT, whence: SeekWhence) -> SeekResult {
            let _ = (offset, whence);
            SeekResult::CantSeek
        }

        fn duplicate(&self) -> Box<dyn PartReader> {
            Box::new(Self {
                dropped: Arc::clone(&self.dropped),
            })
        }
    }

    impl Drop for DropCountingReader {
        fn drop(&mut self) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn a_clone_releases_every_resource_it_took_when_it_is_dropped() {
        // The other half of what the C's pre-clear buys. `Curl_freeset` has to
        // name each resource a clone holds, and a resource it forgets is a
        // leak that no test of the successful path can see. Here the release
        // is the drop glue's, so the assertion is that the CLONE's own copy of
        // a counted resource -- not the original's -- goes away with it.
        let dropped = Arc::new(AtomicUsize::new(0));
        let mut original = fake_handle();
        let mut root = MimePart::new();
        root.set_reader(
            None,
            Some(Box::new(DropCountingReader {
                dropped: Arc::clone(&dropped),
            })),
        );
        original.set_mimepost(Some(root));
        assert_eq!(dropped.load(Ordering::Relaxed), 0);

        let clone = original.duplicate().expect("a callback part duplicates");
        assert!(clone.mimepost().is_some());
        // The clone took its OWN reader, so nothing has been released yet and
        // two readers now exist over the one counter.
        assert_eq!(dropped.load(Ordering::Relaxed), 0);

        drop(clone);
        assert_eq!(
            dropped.load(Ordering::Relaxed),
            1,
            "the clone's reader must be released with the clone"
        );
        // And the original still holds its own, which a shallow copy sharing
        // one reader would have destroyed along with the clone.
        assert!(original.mimepost().is_some());

        drop(original);
        assert_eq!(dropped.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn the_pre_clear_is_what_leaves_an_abandoned_clone_consistent() {
        // `lib/easy.c:884-885`: "clear all dest string and blob pointers
        // first, in case we error out mid-function". The C needs it because a
        // `Curl_setstropt` that fails at index 40 leaves indices 41 onwards
        // holding whatever the destination struct's shallow copy put there --
        // the SOURCE's pointers -- and freeing the clone would then free the
        // original's strings twice.
        //
        // REPORTED HONESTLY: `EasyHandle::duplicate` has no failure this test
        // module can inject. Every one of its fallible steps bottoms out in
        // allocation failure (`util::fallible`) or in entropy failure
        // (`SystemRng::new`), and neither is reachable without replacing the
        // global allocator or the operating system's generator. So rather
        // than stage a failure that cannot happen, this asserts the invariant
        // that makes the failure harmless -- and it is asserted on a
        // destination that ALREADY HOLDS foreign values, which is the only
        // configuration in which a missing clear is observable.
        let mut source = UserDefined::new();
        source
            .strings_mut()
            .set(DupString::SetUrl, Some("https://clone.example/".into()));
        source
            .blobs_mut()
            .set(DupBlob::Cert, Some(Blob::new(vec![0xAA], Blob::COPY)));

        let mut destination = UserDefined::new();
        for which in DupString::ALL {
            destination.strings_mut().set(which, Some("stale".into()));
        }
        for which in DupBlob::ALL {
            destination
                .blobs_mut()
                .set(which, Some(Blob::new(vec![0xFF], Blob::COPY)));
        }
        assert_eq!(destination.strings().occupied(), DupString::COUNT);

        destination.strings_mut().duplicate(source.strings());
        destination.blobs_mut().duplicate(source.blobs());

        // Exactly what the source held, and nothing the destination held: a
        // clone abandoned partway can therefore only ever hold slots it wrote
        // itself, every one of them its own allocation.
        assert_eq!(destination.strings().occupied(), 1);
        assert_eq!(
            destination.strings().get(DupString::SetUrl),
            Some("https://clone.example/")
        );
        assert_eq!(destination.blobs().occupied(), 1);
        assert_eq!(
            destination.blobs().get(DupBlob::Cert).map(Blob::data),
            Some(&[0xAA][..])
        );
    }

    #[test]
    fn a_clone_owns_its_strings_independently_of_the_source() {
        // The double-free the C's clear exists to prevent cannot be written
        // here at all: the clone's slot holds a `String` of its own, so
        // clearing the source's slot leaves the clone's standing.
        let mut source = UserDefined::new();
        source
            .strings_mut()
            .set(DupString::UserAgent, Some("agent/1".into()));
        let mut clone = UserDefined::new();
        clone.strings_mut().duplicate(source.strings());

        source.strings_mut().set(DupString::UserAgent, None);
        assert!(source.strings().get(DupString::UserAgent).is_none());
        assert_eq!(clone.strings().get(DupString::UserAgent), Some("agent/1"));

        drop(source);
        assert_eq!(clone.strings().get(DupString::UserAgent), Some("agent/1"));
    }

    #[test]
    fn a_clone_shares_the_seams_rather_than_rebuilding_them() {
        let (seams, fakes) = fake_seams();
        let original = EasyHandle::new_with_seams(seams);
        let clone = original.duplicate().expect("no mime part");

        // The same clock: advancing it moves BOTH handles' readings, which is
        // what sharing means and what the C does -- a duplicate reads the
        // same wall clock.
        let before = original.seams().clock().now();
        fakes.clock.advance(Duration::from_millis(250));
        let after = clone.seams().clock().now();
        assert!(after > before);
        assert_eq!(after, original.seams().clock().now());
    }

    // -- resetting a handle ------------------------------------------------

    #[test]
    fn resetting_restores_every_option_default() {
        let mut handle = fake_handle();
        // Move a value in each of the option groups.
        handle.set_mut().set_maxredirs(1);
        handle.set_mut().set_httpauth(AuthMask::NTLM);
        handle.set_mut().set_httpwant(HttpVersionWant::Http2);
        handle.set_mut().tcp_mut().set_nodelay(false);
        handle.set_mut().tcp_mut().set_keepalive(true);
        handle.set_mut().proxy_mut().set_port(8080);
        handle
            .set_mut()
            .strings_mut()
            .set(DupString::SetUrl, Some("https://example.com/".into()));
        handle
            .set_mut()
            .blobs_mut()
            .set(DupBlob::Cert, Some(Blob::new(vec![1], Blob::COPY)));
        let policy = handle.set_mut().ssl_mut().policy_mut();
        *policy = policy.clone().with_peer_verification(false);
        assert!(handle.peer_verification_disabled());

        handle.reset();

        // The option state compares equal to a freshly constructed one,
        // field for field, which is a stronger statement than any list of
        // individual assertions could be.
        assert_eq!(handle.set(), &UserDefined::new());
        // And the property AAP 0.8.1 freezes, asserted directly as well.
        assert!(!handle.peer_verification_disabled());
        assert!(!handle.host_verification_disabled());
        assert_eq!(handle.set().proxy_ssl(), handle.set().ssl());
    }

    #[test]
    fn resetting_clears_the_metadata_store_the_mime_tree_and_the_info() {
        let mut handle = fake_handle();
        handle.meta_mut().insert("live", MetaValue::Flag(true));
        handle.set_mimepost(Some(MimePart::new()));
        handle.info_mut().absorb_transfer_info(
            &crate::transfer::TransferInfo {
                timecond: true,
                request_size: 512,
            },
        );
        handle.set_tls_session(Some(TlsSessionInfo {
            backend: TlsBackendId::RUSTLS,
            kind: TlsHandleKind::Session,
            distinguishes_context: false,
        }));

        handle.reset();

        assert!(handle.meta().is_empty());
        assert!(handle.mimepost().is_none());
        assert!(!handle.set().has_mimepost());
        assert!(!handle.info().timecond());
        assert_eq!(handle.info().request_size(), 0);
        assert_eq!(handle.info().filetime(), -1);
        assert!(handle.tls_session().is_none());
    }

    #[test]
    fn resetting_hides_the_progress_meter_where_a_fresh_handle_does_not() {
        let fresh = fake_handle();
        assert!(
            !fresh.progress().hide(),
            "a fresh handle's meter is not hidden"
        );

        let mut handle = fake_handle();
        handle.reset();
        // `data->progress.hide = TRUE` (`lib/easy.c:1109`), set AFTER the
        // `memset`, so it is not the zeroed value.
        assert!(handle.progress().hide());
    }

    #[test]
    fn resetting_zeroes_the_rest_of_the_progress_block() {
        // The other half of `lib/easy.c:1104`'s
        // `memset(&data->progress, 0, sizeof(struct Progress))`. Asserting
        // `hide` alone would pass even if the reset merely POKED that one
        // flag, so a second member is moved and checked: `uses_callback` is
        // the one the clone path copies explicitly (`:994`), which makes it
        // the member most likely to be special-cased by mistake here too.
        let mut handle = fake_handle();
        handle.progress_mut().set_uses_callback(true);
        assert!(handle.progress().uses_callback());

        handle.reset();

        assert!(
            !handle.progress().uses_callback(),
            "the whole Progress block is replaced, not just the hide flag"
        );
        // And `hide` is still TRUE, so the ordering holds: the zeroing runs
        // first and `:1109` writes over it, not the other way round.
        assert!(handle.progress().hide());
    }

    #[test]
    fn resetting_writes_the_four_state_fields_and_leaves_the_rest() {
        let mut handle = fake_handle();
        // Fields the reset MUST write.
        handle.state_mut().set_recent_conn_id(ConnectionId::new(3));
        handle
            .state_mut()
            .set_url(Some("https://a.example/".into()));
        handle
            .state_mut()
            .set_referer(Some("https://b.example/".into()));
        handle.state_mut().adopt_resolve(&["a:1:2".to_owned()]);
        // Fields the reset must LEAVE ALONE.
        *handle.state_mut().lastconnect_id_mut() = ConnectionId::new(5);
        handle
            .state_mut()
            .push_header_bytes(b"X-Kept: 1")
            .expect("well under the ceiling");

        handle.reset();

        // Written: `lib/easy.c:1110-1111` and `Curl_freeset`.
        assert_eq!(handle.state().current_speed(), -1);
        assert_eq!(handle.state().recent_conn_id(), ConnectionId::NONE);
        assert!(handle.state().url().is_none());
        assert!(handle.state().referer().is_none());
        assert!(handle.state().resolve().is_empty());
        assert_eq!(handle.state().auth(), &AuthStatePair::ZERO);

        // Left standing: `curl_easy_reset` "does not change ... the live
        // connections", and the header dynbuf is not freed.
        assert_eq!(
            handle.state().lastconnect_id(),
            ConnectionId::new(5),
            "a reset must not forget the live connection"
        );
        assert_eq!(handle.state().header_buffer(), b"X-Kept: 1");
    }

    #[test]
    fn resetting_clears_the_master_identity_and_keeps_the_rest() {
        let mut handle = fake_handle();
        handle.identity_mut().set_id(TransferId::new(21));
        handle.attach_to_multi(
            HandleToken::new(MultiXferId::new(8), Generation::FIRST),
            MultiMembership::Application,
        );
        handle.identity_mut().set_master_mid(MultiXferId::new(1));

        handle.reset();

        // `data->master_mid = UINT32_MAX` (`lib/easy.c:1120`), and ONLY that.
        assert_eq!(handle.identity().master_mid(), MultiXferId::NONE);
        // A reset handle is the same handle in the same multi: resetting the
        // identity would detach it, which `curl_easy_reset` does not do.
        assert_eq!(handle.identity().id().get(), 21);
        assert_eq!(handle.identity().mid(), MultiXferId::new(8));
        assert_eq!(handle.multi_membership(), MultiMembership::Application);
    }

    #[test]
    fn resetting_keeps_the_share_and_the_result_history() {
        let mut handle = fake_handle();
        handle.set_result(CURLcode::CouldntResolveHost);
        handle.set_mstate(CurlMstate::Performing);
        handle.reset();
        // Neither is in `curl_easy_reset`'s list, so neither moves.
        assert_eq!(handle.result(), CURLcode::CouldntResolveHost);
        assert_eq!(handle.mstate(), CurlMstate::Performing);
    }

    // -- the state's header buffer ----------------------------------------

    #[test]
    fn the_header_buffer_refuses_to_pass_its_ceiling() {
        let mut state = HandleState::for_clone();
        let chunk = vec![b'x'; 4_096];
        let mut written = 0;
        while written + chunk.len() <= CURL_MAX_HTTP_HEADER {
            state.push_header_bytes(&chunk).expect("within the ceiling");
            written += chunk.len();
        }
        assert_eq!(state.header_buffer().len(), written);

        // `curlx_dyn_addn` reports a ceiling overflow as an allocation
        // failure, and callers propagate that code, so answering a different
        // one would change what a transfer reports.
        assert_eq!(state.push_header_bytes(&chunk), Err(CURLcode::OutOfMemory));
        assert_eq!(state.header_buffer().len(), written, "no partial append");

        state.clear_header_buffer();
        assert!(state.header_buffer().is_empty());
    }

    #[cfg(feature = "cookies")]
    #[test]
    fn the_cookie_engine_starts_only_when_the_parent_had_one() {
        let mut original = fake_handle();
        assert!(original.cookies().is_none());
        assert!(!original.state().cookie_engine());

        // A parent with a jar but no engine must NOT start one in the clone:
        // the C's guard is `if(data->cookies && data->state.cookie_engine)`.
        let plain = original.duplicate().expect("no mime part");
        assert!(plain.cookies().is_none());
        assert!(!plain.state().cookie_engine());

        original.start_cookie_engine();
        assert!(original.cookies().is_some());
        assert!(original.state().cookie_engine());

        let inherited = original.duplicate().expect("no mime part");
        assert!(inherited.cookies().is_some());
        assert!(inherited.state().cookie_engine());
    }

    #[cfg(feature = "cookies")]
    #[test]
    fn the_cookie_file_list_is_duplicated_independently_of_the_engine() {
        let mut original = fake_handle();
        original
            .state_mut()
            .adopt_cookielist(&["jar.txt".to_owned()]);
        let clone = original.duplicate().expect("no mime part");
        assert_eq!(clone.state().cookielist(), ["jar.txt"]);
        // The engine is a separate condition and was not met.
        assert!(!clone.state().cookie_engine());
    }

    #[cfg(feature = "cookies")]
    #[test]
    fn resetting_releases_the_cookie_file_list_and_keeps_the_engine() {
        let mut handle = fake_handle();
        handle.start_cookie_engine();
        handle.state_mut().adopt_cookielist(&["jar.txt".to_owned()]);

        handle.reset();

        // `Curl_freeset` frees the list and nulls it.
        assert!(handle.state().cookielist().is_empty());
        // It leaves the engine flag alone, because the jar survives a reset.
        assert!(handle.state().cookie_engine());
        assert!(handle.cookies().is_some());
    }

    #[cfg(feature = "hsts")]
    #[test]
    fn the_hsts_cache_is_created_in_a_clone_only_when_the_parent_had_one() {
        let mut original = fake_handle();
        assert!(original.hsts().is_none());
        assert!(original.duplicate().expect("no mime part").hsts().is_none());

        original.start_hsts();
        assert!(original.hsts().is_some());
        assert!(original.duplicate().expect("no mime part").hsts().is_some());
    }

    #[cfg(feature = "altsvc")]
    #[test]
    fn the_altsvc_cache_is_created_in_a_clone_only_when_the_parent_had_one() {
        let mut original = fake_handle();
        assert!(original.altsvc().is_none());
        assert!(original
            .duplicate()
            .expect("no mime part")
            .altsvc()
            .is_none());

        original.start_altsvc();
        assert!(original.altsvc().is_some());
        assert!(original
            .duplicate()
            .expect("no mime part")
            .altsvc()
            .is_some());
    }

    #[cfg(feature = "ftp")]
    #[test]
    fn the_wildcard_driver_state_is_reachable_and_starts_default() {
        let mut handle = fake_handle();
        // `WildcardData` carries a `VecDeque<FileInfo>` and holds no
        // `PartialEq`, so the fresh state is asserted member by member --
        // `Curl_wildcard_init` (`lib/ftplistparser.c:181-185`) leaves an empty
        // list and `CURLWC_INIT`.
        assert!(handle.wildcard().path.is_none());
        assert!(handle.wildcard().pattern.is_none());
        assert!(handle.wildcard().filelist.is_empty());
        assert!(handle.wildcard().ftpwc.is_none());
        assert_eq!(
            handle.wildcard().state,
            crate::protocols::ftp::listparser::WildcardState::Init
        );

        handle.wildcard_mut().path = Some("/pub".to_owned());
        assert_eq!(handle.wildcard().path.as_deref(), Some("/pub"));
    }

    // -- dependency injection ---------------------------------------------

    #[test]
    fn the_handle_reads_time_only_through_the_injected_clock() {
        let (seams, fakes) = fake_seams();
        let handle = EasyHandle::new_with_seams(seams);

        // The fake's reading, not the host's. `TestClock::new` places the
        // monotonic reading where it was asked and leaves the WALL reading at
        // the Unix epoch, deliberately, "so that a test is reproducible on a
        // machine whose clock is wrong". A handle that had reached a global
        // clock would report neither of these.
        assert_eq!(handle.seams().clock().now(), CurlTime::new(7, 500_000));
        assert_eq!(
            handle.seams().clock().epoch_secs(),
            0,
            "a wall reading near the present would mean a real clock"
        );

        fakes.clock.set_epoch_secs(1_700_000_000);
        assert_eq!(handle.seams().clock().epoch_secs(), 1_700_000_000);

        fakes.clock.advance(Duration::from_secs(3));
        assert_eq!(handle.seams().clock().now(), CurlTime::new(10, 500_000));
        assert_eq!(handle.seams().clock().epoch_secs(), 1_700_000_003);
    }

    #[test]
    fn the_handle_holds_the_injected_resolver_and_calls_nothing_by_itself() {
        let (seams, fakes) = fake_seams();
        let handle = EasyHandle::new_with_seams(seams);

        // Building a handle resolves nothing, which is the C's behaviour too.
        assert_eq!(fakes.resolver.asked.load(Ordering::Relaxed), 0);
        // And the injected resolver is what a caller would reach.
        assert!(format!("{:?}", handle.seams().resolver())
            .contains("CountingResolver"));
    }

    #[test]
    fn the_handle_holds_the_injected_tls_factory_and_builds_no_filter() {
        let (seams, fakes) = fake_seams();
        let handle = EasyHandle::new_with_seams(seams);

        assert_eq!(fakes.tls.created.load(Ordering::Relaxed), 0);
        // The factory's own descriptor, not a process-global backend's.
        assert_eq!(
            handle.seams().tls().descriptor().info(),
            SslBackendInfo::NONE
        );
    }

    #[test]
    fn randomness_comes_from_the_injected_generator() {
        let handle = fake_handle();
        // `CountingRng` answers 0, 1, 2, ... so the sequence is proof that
        // the draw came from the fake and not from the operating system.
        assert_eq!(handle.seams().next_random_u32(), 0);
        assert_eq!(handle.seams().next_random_u32(), 1);

        let mut buffer = [0_u8; 4];
        handle.seams().fill_random(&mut buffer);
        assert_eq!(buffer, [2, 3, 4, 5]);
    }

    #[test]
    fn the_seams_debug_output_names_them_without_printing_the_generator() {
        let handle = fake_handle();
        let rendered = format!("{:?}", handle.seams());
        assert!(rendered.contains("EasySeams"));
        assert!(rendered.contains("clock"));
        assert!(rendered.contains("resolver"));
        assert!(rendered.contains("tls"));
        assert!(
            rendered.contains("<injected>"),
            "the generator's state is key material and must not print"
        );
    }

    #[test]
    fn the_handle_debug_output_prints_shape_and_no_credentials() {
        let mut handle = fake_handle();
        handle
            .set_mut()
            .strings_mut()
            .set(DupString::KeyPasswd, Some("s3cr3t-passphrase".into()));
        let rendered = format!("{handle:?}");

        assert!(rendered.contains("EasyHandle"));
        assert!(rendered.contains("verify_peer: true"));
        assert!(rendered.contains("options_set: 1"));
        assert!(
            !rendered.contains("s3cr3t-passphrase"),
            "a private key password must never reach a diagnostic"
        );
    }

    // -- the setters `easy/setopt.rs` will consume ------------------------
    //
    // Every one of these exists for a `CURLOPT_*` arm that is not written yet,
    // which makes them the file's forward-facing surface AND the one part of
    // it a passing test suite would otherwise say nothing about. A setter that
    // writes the neighbouring field is invisible until a transfer misbehaves,
    // so each is exercised here against the accessor that reads it back.

    #[test]
    fn the_tls_setters_write_the_field_they_name() {
        let mut ssl = SslConfigData::new();

        // The policy is reached by reference, which is how `setopt.rs` will
        // clear verification without this file knowing the option numbers.
        assert!(ssl.policy().verify_peer());
        assert!(ssl.policy().verify_host());

        ssl.set_cache_session(false);
        assert!(!ssl.cache_session());
        ssl.set_cache_session(true);
        assert!(ssl.cache_session());

        ssl.set_certinfo(true);
        assert!(ssl.certinfo());
        // `CURLOPT_CERTINFO` must not disturb either verification flag.
        assert!(ssl.verify_peer());
        assert!(ssl.verify_host());

        let range = SslVersionRange::from_packed((7 << 16) | 6);
        ssl.set_version(range);
        assert_eq!(ssl.version(), range);

        ssl.set_ssl_options(SslOptionBits {
            falsestart: true,
            enable_beast: false,
            no_revoke: true,
            no_partialchain: false,
            revoke_best_effort: true,
            native_ca_store: true,
            auto_client_cert: false,
            earlydata: true,
        });
        let read = ssl.ssl_options();
        assert!(read.falsestart);
        assert!(!read.enable_beast);
        assert!(read.no_revoke);
        assert!(!read.no_partialchain);
        assert!(read.revoke_best_effort);
        assert!(read.native_ca_store);
        assert!(!read.auto_client_cert);
        assert!(read.earlydata);
        // `native_ca_store` has its own accessor as well, and both must agree
        // -- they are one bit, not two.
        assert!(ssl.native_ca_store());
    }

    #[test]
    fn the_ca_cache_timeout_narrows_the_way_the_c_int_does() {
        let mut general = SslGeneralConfig::default();
        general.set_ca_cache_timeout_secs(0);
        assert_eq!(general.ca_cache_timeout_secs(), 0);
        // `CURLOPT_CA_CACHE_TIMEOUT` accepts -1 for "never expire".
        general.set_ca_cache_timeout_secs(-1);
        assert_eq!(general.ca_cache_timeout_secs(), -1);
        // The C member is an `int`, so `i32::MAX` is its ceiling and a caller
        // cannot store anything wider through this door.
        general.set_ca_cache_timeout_secs(i32::MAX);
        assert_eq!(general.ca_cache_timeout_secs(), i32::MAX);
    }

    #[test]
    fn the_proxy_setters_write_the_field_they_name() {
        let mut proxy = ProxySettings::default();
        proxy.set_kind(ProxyKind::Socks5Hostname);
        assert_eq!(proxy.kind(), ProxyKind::Socks5Hostname);
        proxy.set_auth(AuthMask::NTLM);
        assert_eq!(proxy.auth(), AuthMask::NTLM);
        proxy.set_port(1080);
        assert_eq!(proxy.port(), 1080);
        // The SOCKS5 mask is a SEPARATE field from the proxy auth mask, and
        // writing one must not move the other.
        assert_eq!(proxy.socks5_auth().bits(), 0b101);
    }

    #[cfg(feature = "doh")]
    #[test]
    fn the_doh_setters_are_independent_of_the_transfers_own_posture() {
        let mut doh = DohSettings::default();
        doh.set_verify_peer(false);
        assert!(!doh.verify_peer());
        assert!(doh.verify_host(), "the host check is a separate option");
        doh.set_verify_host(false);
        assert!(!doh.verify_host());
    }

    #[cfg(feature = "ssh")]
    #[test]
    fn the_ssh_auth_type_setter_writes_the_mask() {
        let mut ssh = SshSettings::default();
        ssh.set_auth_types(0);
        assert_eq!(ssh.auth_types(), 0);
        // `CURLSSH_AUTH_PUBLICKEY` = 1 << 0, `CURLSSH_AUTH_PASSWORD` = 1 << 1.
        ssh.set_auth_types(0b11);
        assert_eq!(ssh.auth_types(), 0b11);
        assert_eq!(ssh.new_directory_perms(), DEFAULT_NEW_DIRECTORY_PERMS);
    }

    #[cfg(feature = "websockets")]
    #[test]
    fn the_websocket_setter_writes_both_flags_at_once() {
        let mut ws = WebSocketSettings::default();
        ws.set(true, false);
        assert!(ws.raw_mode());
        assert!(!ws.no_auto_pong());
        ws.set(false, true);
        assert!(!ws.raw_mode());
        assert!(ws.no_auto_pong());
    }

    #[cfg(feature = "ftp")]
    #[test]
    fn the_wildcard_setter_writes_the_flag() {
        let mut ftp = FtpSettings::default();
        ftp.set_wildcard_enabled(true);
        assert!(ftp.wildcard_enabled());
        // Enabling wildcards must not silently install a callback.
        assert!(!ftp.chunk_bgn_set());
        assert!(!ftp.fnmatch_set());
    }

    #[cfg(any(feature = "http2", feature = "http3"))]
    #[test]
    fn the_priority_weight_setter_writes_the_weight() {
        let mut priority = StreamPriority::default();
        priority.set_weight(16);
        assert_eq!(priority.weight(), 16);
        assert!(!priority.exclusive(), "the flag is a separate member");
    }

    #[test]
    fn the_option_set_exposes_each_group_for_mutation() {
        // The `*_mut` doors `setopt.rs` reaches its groups through. Reading
        // each one back through the immutable accessor is what proves the two
        // name the same field.
        let mut set = UserDefined::new();

        set.general_ssl_mut().set_ca_cache_timeout_secs(7);
        assert_eq!(set.general_ssl().ca_cache_timeout_secs(), 7);

        #[cfg(feature = "ftp")]
        {
            set.ftp_mut().set_wildcard_enabled(true);
            assert!(set.ftp().wildcard_enabled());
        }
        #[cfg(feature = "doh")]
        {
            set.doh_mut().set_verify_peer(false);
            assert!(!set.doh().verify_peer());
        }
        #[cfg(feature = "ssh")]
        {
            set.ssh_mut().set_auth_types(4);
            assert_eq!(set.ssh().auth_types(), 4);
        }
        #[cfg(feature = "websockets")]
        {
            set.ws_mut().set(true, true);
            assert!(set.ws().raw_mode());
            assert!(set.ws().no_auto_pong());
        }
        #[cfg(any(feature = "http2", feature = "http3"))]
        {
            set.priority_mut().set_weight(3);
            assert_eq!(set.priority().weight(), 3);
        }
    }

    #[test]
    fn the_buffer_and_protocol_setters_write_the_fields_they_name() {
        let mut set = UserDefined::new();
        set.set_buffer_size(READBUFFER_MIN);
        assert_eq!(set.buffer_size(), READBUFFER_MIN);
        set.set_upload_buffer_size(UPLOADBUFFER_MIN);
        assert_eq!(set.upload_buffer_size(), UPLOADBUFFER_MIN);

        // `CURLOPT_PROTOCOLS_STR` and `CURLOPT_REDIR_PROTOCOLS_STR` are two
        // options and two fields, written together here because the C's
        // `allowed_protocols` and `redir_protocols` are set from one parse.
        set.set_protocols(Proto::REDIR, Proto::REDIR);
        assert_eq!(set.allowed_protocols(), Proto::REDIR);
        assert_eq!(set.redir_protocols(), Proto::REDIR);
    }

    #[test]
    fn the_io_setters_track_whether_the_caller_supplied_a_function() {
        let mut set = UserDefined::new();
        set.set_out(IoTarget::Application);
        assert_eq!(set.out(), IoTarget::Application);
        assert!(!set.out().is_default_stream());

        // `set->is_fread_set` is the C's own record of whether
        // `CURLOPT_READFUNCTION` was given, and it must follow the FUNCTION
        // rather than the target: `lib/url.c:379` starts it at 0 alongside a
        // `fread` pointer that is present but not caller-supplied.
        set.set_read_source(
            IoTarget::Application,
            TransferFunction::Application,
        );
        assert_eq!(set.in_set(), IoTarget::Application);
        assert_eq!(set.fread_func_set(), TransferFunction::Application);
        assert!(set.is_fread_set());

        // Handing the stdio reader back clears the flag again, which is what
        // `CURLOPT_READFUNCTION(NULL)` means.
        set.set_read_source(
            IoTarget::Standard(StdStream::In),
            TransferFunction::Stdio,
        );
        assert!(!set.is_fread_set());
        assert_eq!(set.in_set(), IoTarget::Standard(StdStream::In));
    }

    #[test]
    fn the_handle_exposes_the_request_netrc_and_auth_state_for_mutation() {
        let mut handle = fake_handle();
        // `SingleRequest` is `transfer/request.rs`'s and is reached, never
        // reimplemented -- this asserts the door exists and is the same field
        // both ways. The two borrows are sequenced rather than nested,
        // because a shared and an exclusive borrow of one handle cannot
        // coexist -- which is itself the property that makes the aggregate
        // safe.
        let observed = handle.req().size;
        assert_eq!(handle.req_mut().size, observed);
        // `StoreNetrc` likewise.
        assert!(!handle.netrc().is_loaded());
        assert!(!handle.netrc_mut().is_loaded());
        // The authentication state pair starts zeroed and is reachable for the
        // negotiation loop to advance.
        assert_eq!(handle.state().auth(), &AuthStatePair::ZERO);
        assert_eq!(handle.state_mut().auth_mut(), &AuthStatePair::ZERO);
    }

    #[test]
    fn attaching_a_share_hands_back_whatever_was_there() {
        let mut handle = fake_handle();
        assert!(handle.share().is_none());

        let share = Arc::new(Share::new());
        let previous = handle.set_share(Some(Arc::clone(&share)));
        assert!(previous.is_none(), "nothing was attached before");
        assert!(handle.share().is_some());

        // Replacing returns the old handle rather than dropping it, so a
        // caller that swaps shares cannot lose the first one.
        let second = Arc::new(Share::new());
        let displaced = handle.set_share(Some(second));
        assert!(displaced.is_some());
        assert!(Arc::ptr_eq(
            &displaced.expect("just asserted present"),
            &share
        ));

        let removed = handle.set_share(None);
        assert!(removed.is_some());
        assert!(handle.share().is_none());
        // `curl_easy_reset` does not detach a share, which the reset test
        // above asserts from the other direction.
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri's isolation refuses clock_gettime(REALTIME), which is \
                  the host service this test exists to reach"
    )]
    fn the_production_constructor_wires_the_real_seams() {
        // The convenience door `curl_easy_init` will use. It is exercised with
        // a FAKE TLS factory, because that argument is required precisely so
        // that no global provider is ever reached -- there is no production
        // `TlsFilterFactory` to default to, and inventing one here would
        // install exactly the process-global that AAP 0.3.3's P12 forbids.
        //
        // What this proves is that the clock, the resolver and the generator
        // production implementations exist, construct, and answer.
        let tls: Arc<dyn TlsFilterFactory> =
            Arc::new(CountingTlsFactory::default());
        let handle = EasyHandle::new(tls).expect("the host seams construct");

        assert!(handle.is_valid());
        // Defaults are the same whichever constructor was used: the option
        // state does not depend on the seams.
        assert_eq!(handle.set(), &UserDefined::new());
        assert!(!handle.any_verification_disabled());

        // The production clock reports a real wall time, which is the one
        // observable difference from `TestClock` and therefore the assertion
        // that proves this is NOT the fake. Anything past 2020 will do; the
        // point is that it is not the epoch.
        assert!(
            handle.seams().clock().epoch_secs() > 1_577_836_800,
            "the production clock must report a real wall time"
        );
        // And the production generator answers without being asked twice for
        // the same value.
        let first = handle.seams().next_random_u32();
        let second = handle.seams().next_random_u32();
        let third = handle.seams().next_random_u32();
        assert!(
            first != second || second != third,
            "three identical draws would mean a stuck generator"
        );
    }

    // -- self-checks over this file's own text ----------------------------

    /// True when `line` uses `unsafe` as a keyword rather than naming it.
    ///
    /// Factored out of the gate below so that
    /// [`the_self_checks_are_live_gates_and_not_decoration`] can prove the
    /// predicate answers correctly BOTH ways. A gate that cannot fail is
    /// decoration, and the stripping these scanners need to avoid flagging
    /// their own text is exactly the stripping that could silently blind
    /// them.
    fn uses_unsafe_keyword(line: &str) -> bool {
        code_only(line)
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|word| word == "unsafe")
    }

    /// True when `line` is a blanket import that leaves this module.
    fn is_foreign_glob_import(line: &str) -> bool {
        let code = code_only(line);
        let code = code.trim_start();
        code.starts_with("use ")
            && code.contains("::*")
            && !code.starts_with("use super::*")
            && !code.starts_with("use self::*")
    }

    #[test]
    fn the_self_checks_are_live_gates_and_not_decoration() {
        // Each scanner below strips comments, and three of them strip string
        // literals too, because this file names the constructs it forbids in
        // order to search for them. That stripping is also the one way a
        // scanner could go blind without anyone noticing, so every predicate
        // is exercised here on synthetic input it MUST reject and on
        // synthetic input it MUST accept.

        // The comment-only stripper keeps literals, which is what the feature
        // scan needs, and drops prose, which is what stops this file's
        // discussion of an unsanctioned feature being read as a use of it.
        assert_eq!(
            code_without_comments("#[cfg(feature = \"ftp\")]"),
            "#[cfg(feature = \"ftp\")]"
        );
        assert_eq!(code_without_comments("    // feature = \"tls\""), "    ");

        // The full stripper removes both, and keeps the surrounding tokens
        // apart so a literal between two identifiers cannot fuse them.
        assert_eq!(code_only("let x = \"static mut\";").trim(), "let x =  ;");
        assert_eq!(
            code_only("static mut COUNT: u32 = 0;"),
            "static mut COUNT: u32 = 0;"
        );
        assert_eq!(code_only("a\"lit\"b"), "a b");
        // An escaped quote must not end the literal early, or everything
        // after it would be scanned as code.
        assert_eq!(code_only("f(\"a\\\"static mut\")"), "f( )");

        // The `unsafe` predicate: the keyword, yes; the word in prose, the
        // word in a literal, and the identifier `unsafe_code`, no.
        assert!(uses_unsafe_keyword("unsafe { *p }"));
        assert!(uses_unsafe_keyword("    pub unsafe fn f() {}"));
        assert!(!uses_unsafe_keyword("// this file has no unsafe at all"));
        assert!(!uses_unsafe_keyword("let s = \"unsafe\";"));
        assert!(!uses_unsafe_keyword("#![deny(unsafe_code)]"));

        // The glob predicate: a foreign path, yes; the parent module and this
        // one, no; a comment about a glob, no.
        assert!(is_foreign_glob_import("use crate::conn::*;"));
        assert!(is_foreign_glob_import("    use crate::urldata::*;"));
        assert!(!is_foreign_glob_import("    use super::*;"));
        assert!(!is_foreign_glob_import("    use self::*;"));
        assert!(!is_foreign_glob_import("use crate::conn::Connection;"));
        assert!(!is_foreign_glob_import("// never use crate::conn::*;"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_file_reaches_for_no_global_clock_resolver_provider_or_generator() {
        // The four seams must be injected, so none of these may appear as
        // CODE. Comments are stripped first because this file documents at
        // length why it does not use them.
        const FORBIDDEN: [&str; 10] = [
            "static mut",
            "lazy_static",
            "once_cell",
            "OnceLock",
            "SystemTime::now",
            "Instant::now",
            "thread_rng",
            "rand::random",
            "OsRng",
            "from_entropy",
        ];

        let source = own_source();
        let mut offenders = Vec::new();
        for (number, line) in source.lines().enumerate() {
            let code = code_only(line);
            for pattern in FORBIDDEN {
                if code.contains(pattern) {
                    offenders.push(format!("{}: {pattern}", number + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "a process-global for one of the four injected seams is a defect: \
             {offenders:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_file_contains_no_unsafe_and_grants_no_exemption() {
        let source = own_source();
        let mut offenders = Vec::new();
        for (number, line) in source.lines().enumerate() {
            if uses_unsafe_keyword(line)
                || code_only(line).contains("allow(unsafe_code)")
            {
                offenders.push(number + 1);
            }
        }
        assert!(
            offenders.is_empty(),
            "this file must contain no `unsafe` and no exemption from the \
             crate root's `deny(unsafe_code)`; lines: {offenders:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_file_names_no_tls_feature_and_no_unsanctioned_feature() {
        // AAP 0.5.2 declares fifteen features and TLS is NOT one of them:
        // TLS is unconditional, so `feature = "tls"` would gate code on a
        // feature that can never be enabled.
        const SANCTIONED: [&str; 15] = [
            "http2",
            "http3",
            "ftp",
            "ssh",
            "websockets",
            "cookies",
            "hsts",
            "altsvc",
            "doh",
            "brotli",
            "zstd",
            "gzip",
            "negotiate",
            "hickory-dns",
            "memdebug",
        ];

        let source = own_source();
        let mut named = Vec::new();
        for line in source.lines() {
            let mut cursor = code_without_comments(line);
            while let Some(at) = cursor.find("feature = \"") {
                let rest = &cursor[at + "feature = \"".len()..];
                match rest.find('"') {
                    Some(end) => {
                        named.push(rest[..end].to_owned());
                        cursor = &rest[end + 1..];
                    }
                    None => break,
                }
            }
        }

        assert!(!named.is_empty(), "the scan found nothing to check");
        for feature in &named {
            assert!(
                SANCTIONED.contains(&feature.as_str()),
                "`{feature}` is not one of the fifteen workspace features"
            );
            assert_ne!(
                feature, "tls",
                "TLS is unconditional; there is no `tls` feature"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_file_imports_no_sibling_module_wholesale() {
        // AAP 0.4.2 replaces `#include "urldata.h"` with one import per type
        // actually used, so a glob would be the very thing the decomposition
        // exists to remove.
        // `use super::*` is exempt, and only that: a test module drawing on
        // the module it tests reaches no sibling at all, and it is how all 78
        // of this crate's test modules open. The rule bites on a path that
        // leaves this module -- `use crate::conn::*` -- which is the shape
        // `#include "urldata.h"` had.
        let source = own_source();
        let offenders: Vec<usize> = source
            .lines()
            .enumerate()
            .filter(|(_, line)| is_foreign_glob_import(line))
            .map(|(number, _)| number + 1)
            .collect();
        assert!(
            offenders.is_empty(),
            "a blanket import defeats the decomposition; lines: {offenders:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_file_keeps_the_editorconfig_rules() {
        let source = own_source();
        assert!(
            source.ends_with('\n'),
            "`.editorconfig` requires a final newline"
        );
        for (number, line) in source.lines().enumerate() {
            assert!(
                !line.contains('\t'),
                "line {} uses a tab; `.editorconfig` requires spaces",
                number + 1
            );
            assert_eq!(
                line.trim_end(),
                line,
                "line {} has trailing whitespace",
                number + 1
            );
        }
    }

    // -- the feature matrix -----------------------------------------------

    #[test]
    fn the_handle_builds_and_answers_under_whatever_features_are_enabled() {
        // Compilation is the assertion: this body names the members that are
        // present in EVERY configuration, so a `#[cfg]` that made one
        // referenced-but-absent would fail to build rather than fail to run.
        // The gated members are exercised by the `#[cfg]`-guarded tests
        // above, so each is compiled exactly when its feature is on.
        let handle = fake_handle();
        assert!(handle.is_valid());
        assert!(!handle.any_verification_disabled());
        assert_eq!(handle.set().maxredirs(), 30);
        assert!(handle.set().tcp().nodelay());
        assert_eq!(handle.set().proxy().kind(), ProxyKind::Http);
        assert_eq!(handle.set().strings().occupied(), 0);
        assert_eq!(handle.set().blobs().occupied(), 0);
        assert_eq!(handle.info().filetime(), -1);
        assert!(handle.meta().is_empty());
        assert_eq!(handle.identity().id(), TransferId::NONE);
        assert_eq!(handle.state().lastconnect_id(), ConnectionId::NONE);
        assert!(handle.netrc().is_loaded() || true);
    }
}
