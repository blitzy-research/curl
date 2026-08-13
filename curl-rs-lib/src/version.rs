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

//! Version, feature and protocol reporting: a machine-read contract.
//!
//! This module supersedes `lib/version.c` and produces the values behind the
//! two exported functions `curl_version()` and `curl_version_info()`.
//! Presenting those across the C ABI is `curl-rs-ffi`'s obligation, discharged
//! in `curl-rs-ffi/src/ffi/misc.rs`, which declares both symbols and reads
//! their payload from here; what this module owes that file is the payload,
//! not the symbols.
//!
//! # The governing principle: under-report, never over-report
//!
//! 874 of the 1,914 fixtures gate on `<features>`. The asymmetry is decisive:
//!
//! > Under-reporting a capability makes a fixture skip; over-reporting makes
//! > it run and fail. Truthful advertisement is therefore the optimal
//! > strategy, not merely the honest one.
//!
//! # What this module does *not* report
//!
//! The harness builds its feature map from two programs, not one
//! (`tests/runtests.pl:543-551`). The `curlinfo` diagnostic binary
//! (`src/curlinfo.c`, becoming `curl-rs/src/bin/curlinfo.rs`) prints
//! `name: ON|OFF` lines, and that is where `proxy` (228 fixtures), `cookies`
//! (51), `digest` (76), `crypto` (98), `Mime` (48) and `unittest` (65) come
//! from. None of them is a `CURL_VERSION_*` bit and none belongs here.
//!
//! Two further additions are the command-line tool's, not the library's, and
//! must not be duplicated here:
//!
//! - `ipfs` and `ipns` are inserted into the printed `Protocols:` line by
//!   `src/tool_help.c:326-353`. `curl_version_info()->protocols` does not
//!   contain them, and neither does [`protocols`].
//! - the printed `Features:` line is re-sorted case-insensitively by
//!   `src/tool_help.c:372-373` before display. [`feature_names`] therefore
//!   preserves the **C table order**, which is what the C array has always
//!   held. Re-sorting for display is the command-line tool's to do, and must
//!   not be done here.
//!
//! # Three deliberate omissions, each with its measured cost
//!
//! ## 1. The TLS token says `rustls`, not `rustls-ffi`
//!
//! `tests/runtests.pl:585-586` is the only arm that recognises rustls:
//!
//! ```text
//! elsif($libcurl =~ /\srustls-ffi\b/i) { $feature{"rustls"} = 1; }
//! ```
//!
//! That token exists because the C backend reports **rustls-ffi's** version
//! (`cr_version()` at `lib/vtls/rustls.c:1377-1381` calls the FFI crate's
//! `rustls_version()`). This implementation uses rustls *natively*, so
//! emitting `rustls-ffi/...` would misdescribe it. The trade-off is resolved in
//! favour of accuracy, and [`SSL_VERSION`] is therefore `rustls/<crate
//! version>`, which does not match the pattern.
//!
//! The measured cost is **zero fixtures**: exactly one fixture in
//! `tests/data/` mentions `rustls` at all and it is `%if !rustls`, which
//! requires the feature to be *absent*. Accuracy makes that one eligible
//! rather than skipped. Ten fixtures require `SSLpinning`, which the rustls
//! arm deliberately never sets -- identical to a C rustls build, so parity,
//! not a deviation. Note too that `$feature{"SSL"}` is set from the **Features** line
//! (`/SSL/i`, `tests/runtests.pl:662`), not from the banner token, so the 138
//! SSL-gated fixtures stay eligible regardless. That is what makes the
//! accuracy choice affordable. **Do not "fix" this by faking the FFI token.**
//!
//! ## 2. `Debug` is never emitted
//!
//! `tests/runtests.pl:658-660` derives *two* harness features from one match:
//!
//! ```text
//! $feature{"TrackMemory"} = $feat =~ /Debug/i;
//! $feature{"Debug"}       = $feat =~ /Debug/i;
//! ```
//!
//! Withholding `Debug` therefore makes every leak check and every
//! `<limits>` allocation cap inert (`tests/runtests.pl:1759`), which is the
//! deliberate choice here, because a Rust allocator's call counts cannot match
//! a C one's. **The cost, stated as required: 98 fixtures require
//! `Debug` and will skip, and `make torture-test` is inapplicable** -- it
//! hard-requires the feature and dies without it
//! (`tests/runtests.pl:846-849`).
//!
//! The row below is a literal `false` rather than a gate on the `memdebug`
//! Cargo feature, and that is deliberate. `memdebug` supplies only the
//! allocation log that `tests/memanalyzer.pm` parses; a C `DEBUGBUILD`
//! additionally changes internal behaviour that the 98 `Debug` fixtures
//! exercise. Advertising `Debug` because allocation tracking is on would be
//! over-reporting of exactly the kind that turns a clean skip into a hard
//! failure, so the token stays withheld even under `--all-features`.
//!
//! ## 3. Six rows are withheld because they cannot be asserted here
//!
//! `MultiSSL` (there is one backend, and `/MultiSSL/i` is matched separately
//! at `tests/runtests.pl:663`), `SSPI`, `Unicode`, `TLS-SRP` and `gsasl` are
//! structurally impossible in this build. `AppleSecTrust`, `NativeCA`,
//! `SSLS-EXPORT`, `HTTPSRR`, `ECH` and `asyn-rr` are withheld because nothing
//! this module can read fixes them: the first two would claim a default trust
//! source that `tls/verify.rs` has not yet fixed, `SSLS-EXPORT` is off by
//! default in the reference build too (`CMakeLists.txt:1076`), and the last
//! three have no Cargo feature to key on. Each row carries its own reason.
//! Measured costs: `HTTPSRR` 0 fixtures, `ECH` 2, `TLS-SRP` 5, and
//! `SSLS-EXPORT`/`AppleSecTrust`/`NativeCA` are not parsed by the harness at
//! all. 114 fixtures require `!SSPI` -- its *absence* -- which this build
//! satisfies naturally.
//!
//! # One table, two views
//!
//! The `Features:` names and the `features` bitmask are two projections of
//! the single [`FEATURES`] table, and [`feature_names`] and
//! [`features_bitmask`] both walk it with the C selection rule from
//! `lib/version.c:684-688`:
//!
//! ```text
//! if(!p->present || p->present(&version_info)) {
//!   features |= p->bitmask;
//!   feature_names[n++] = p->name;
//! }
//! ```
//!
//! Two hand-maintained lists would drift, and a bitmask that disagreed with
//! the names would be undetectable in review; deriving both from one table
//! makes the disagreement unrepresentable, and
//! `tests::bitmask_and_names_agree_in_both_directions` proves it in both
//! directions anyway.
//!
//! # Three protocol-name tables exist; they are not unified
//!
//! The C tree spells scheme names three different ways for three different
//! consumers, and each is correct for its own:
//!
//! 1. **the lookup registry** -- `lib/url.c`'s scheme table, which holds
//!    `"WS"`, `"WSS"`, `"SFTP"` and `"SCP"` in upper case and is searched
//!    case-insensitively (`Curl_getn_scheme`, `lib/url.c:1477`);
//! 2. **the banner** -- `supported_protocols[]` (`lib/version.c:302`), which
//!    is entirely lower case and is what this module reproduces;
//! 3. **the build metadata** -- `curl-config --protocols` and `libcurl.pc`,
//!    which use upper case throughout (`@SUPPORT_PROTOCOLS@`).
//!
//! [`PROTOCOLS`] is therefore built here from its own literals and is *not*
//! derived from `crate::protocols`' registry. Deriving it would import that
//! table's upper-case spellings into a lower-case contract, and "fixing" the
//! registry would break case-insensitive lookup parity instead.
//!
//! # Nine schemes in scope, twenty-four out of it, and none served yet
//!
//! [`PROTOCOLS`] carries a row for each of the nine schemes AAP 0.2.1 puts in
//! scope and for no other. Which of those nine it ADVERTISES is a separate
//! question answered per row by `compiled_in`, and measured over this checkout
//! the answer is none of them: no scheme has an executor, so [`protocols`]
//! returns an empty slice and the `Protocols:` banner line is empty.
//! The other 24 registered schemes (`dict`, `gopher`, `gophers`, `imap`,
//! `imaps`, `ldap`, `ldaps`, `mqtt`, `mqtts`, `pop3`, `pop3s`, `rtmp`,
//! `rtmpe`, `rtmps`, `rtmpt`, `rtmpte`, `rtmpts`, `rtsp`, `smb`, `smbs`,
//! `smtp`, `smtps`, `telnet`, `tftp`) are never named, so their 283 fixtures
//! -- 14.8% of the corpus -- skip cleanly instead of running and failing.
//! Their `CURLPROTO_*` constants remain in the public header and a request for
//! one still returns `CURLE_UNSUPPORTED_PROTOCOL` from `crate::protocols`'
//! stub registration; that is a separate concern from the banner and is not
//! this module's business.
//!
//! # Version identity is frozen
//!
//! [`LIBCURL_VERSION`] is `8.19.0-DEV` and [`LIBCURL_VERSION_NUM`] is
//! `0x081300`, measured at `include/curl/curlver.h:35` and `:61`. Every parity
//! claim in this work is against curl/libcurl 8.19.0-DEV, so **nothing here may
//! bump them**. This module is also the single place the workspace spells the
//! version: the default `User-Agent` that `src/config2setopts.c:906-907` builds
//! as `CURL_NAME "/" CURL_VERSION` is [`DEFAULT_USER_AGENT`], and the fixtures'
//! `%VERSION` substitution only matches if the request bytes and the banner
//! agree.
//!
//! # Safety
//!
//! Nothing in this module needs `unsafe`, and none is present. The crate root
//! carries `#![deny(unsafe_code)]` rather than `forbid`, because the crate does
//! need one exemption -- `#[allow(unsafe_code)]` on its `mod ffi` declaration
//! -- and `forbid` cannot be overridden from an inner scope. `deny` therefore
//! reaches every module except that one, this module included. The C original's
//! `static char out[300]` and its manual `memcpy` loop become a [`String`]
//! behind a [`OnceLock`], which is what makes "repeated invokes generate the
//! exact same string" (`lib/version.c:136-141`) a type-level guarantee rather
//! than a convention.

use std::sync::OnceLock;

// Version identity
//
// Every literal in this block is measured from include/curl/curlver.h, which
// the C build treats as its single version oracle: CMakeLists.txt:54-65 greps
// LIBCURL_VERSION out of that header and feeds the semantic prefix to
// project(CURL VERSION ...). All of it is frozen.

/// The version literal, in one place. See [`LIBCURL_VERSION`].
macro_rules! libcurl_version_literal {
    () => {
        "8.19.0-DEV"
    };
}

/// The library name literal, in one place. See [`LIBCURL_NAME`].
macro_rules! libcurl_name_literal {
    () => {
        "libcurl"
    };
}

/// The tool name literal, in one place. See [`CURL_NAME`].
macro_rules! curl_name_literal {
    () => {
        "curl"
    };
}

/// `LIBCURL_NAME` -- the name that opens the banner (`lib/version.c:205`).
pub const LIBCURL_NAME: &str = libcurl_name_literal!();

/// `CURL_NAME` -- the command-line tool's name (`src/tool_version.h:28`).
///
/// Exposed here rather than in `curl-rs` so that the tool, the library and
/// `crate::protocols::http1`'s `User-Agent` cannot disagree.
pub const CURL_NAME: &str = curl_name_literal!();

/// `LIBCURL_VERSION` -- `"8.19.0-DEV"` (`include/curl/curlver.h:35`).
///
/// Frozen. The test suite substitutes this string into fixture
/// expectations through its `%VERSION` placeholder, so a change here changes
/// the expected bytes of 1,476 wire comparisons.
pub const LIBCURL_VERSION: &str = libcurl_version_literal!();

/// `LIBCURL_VERSION_MAJOR` -- `8` (`include/curl/curlver.h:39`).
pub const LIBCURL_VERSION_MAJOR: u32 = 8;

/// `LIBCURL_VERSION_MINOR` -- `19` (`include/curl/curlver.h:40`).
pub const LIBCURL_VERSION_MINOR: u32 = 19;

/// `LIBCURL_VERSION_PATCH` -- `0` (`include/curl/curlver.h:41`).
pub const LIBCURL_VERSION_PATCH: u32 = 0;

/// `LIBCURL_VERSION_NUM` -- `0x081300` (`include/curl/curlver.h:61`).
///
/// The header is explicit that this is written as a full literal rather than
/// through [`version_bits`], because "curl's own configure script greps for it
/// and needs it to contain the full number" (`include/curl/curlver.h:57-59`).
/// `tests::version_num_agrees_with_its_parts` asserts the two agree.
pub const LIBCURL_VERSION_NUM: u32 = 0x0008_1300;

/// `LIBCURL_TIMESTAMP` -- `"[unreleased]"` (`include/curl/curlver.h:72`).
///
/// Printed verbatim as the `Release-Date:` line by `src/tool_help.c:323`. The
/// C comment records that the real timestamp is stamped into release tarballs
/// by `maketgz` and is deliberately not stored in git.
pub const LIBCURL_TIMESTAMP: &str = "[unreleased]";

/// `LIBCURL_COPYRIGHT` (`include/curl/curlver.h:31`).
pub const LIBCURL_COPYRIGHT: &str = "Daniel Stenberg, <daniel@haxx.se>.";

/// The default `User-Agent`, built exactly as `src/config2setopts.c:906-907`
/// builds it: `CURL_NAME "/" CURL_VERSION`.
pub const DEFAULT_USER_AGENT: &str =
    concat!(curl_name_literal!(), "/", libcurl_version_literal!());

/// `CURL_VERSION_BITS(x, y, z)` -- `include/curl/curlver.h:74`.
///
/// ```text
/// #define CURL_VERSION_BITS(x, y, z) ((x) << 16 | (y) << 8 | (z))
/// ```
#[must_use]
pub const fn version_bits(x: u32, y: u32, z: u32) -> u32 {
    (x << 16) | (y << 8) | z
}

/// `CURL_AT_LEAST_VERSION(x, y, z)` -- `include/curl/curlver.h:75-76`.
///
/// True when the version reported by this build is at least `x.y.z`.
#[must_use]
pub const fn at_least_version(x: u32, y: u32, z: u32) -> bool {
    LIBCURL_VERSION_NUM >= version_bits(x, y, z)
}

// Host triple -- the Rust counterpart of CURL_OS
//
// Composition rather than a table of literals is the point: it is correct for
// every target, including ones outside the four-target matrix, and it cannot
// go stale. For the four mandated targets it yields exactly their triples:
//
//     x86_64-unknown-linux-gnu     aarch64-unknown-linux-gnu
//     x86_64-apple-darwin          aarch64-apple-darwin

/// The vendor component of the target triple.
const HOST_VENDOR: &str = if cfg!(target_vendor = "apple") {
    "apple"
} else if cfg!(target_vendor = "pc") {
    "pc"
} else {
    // Rust's own default for every mandated Linux target.
    "unknown"
};

/// The environment (ABI) component, or `""` when the target has none.
///
/// Apple targets carry no environment component, which is why the empty case
/// exists and why [`host`] omits the separator for it.
const HOST_ENV: &str = if cfg!(target_env = "gnu") {
    "gnu"
} else if cfg!(target_env = "musl") {
    "musl"
} else if cfg!(target_env = "msvc") {
    "msvc"
} else if cfg!(target_env = "uclibc") {
    "uclibc"
} else if cfg!(target_env = "newlib") {
    "newlib"
} else {
    ""
};

/// The `cpu-vendor-os[-env]` triple describing this build.
#[must_use]
pub fn host() -> &'static str {
    static HOST: OnceLock<String> = OnceLock::new();

    HOST.get_or_init(|| {
        let os = match std::env::consts::OS {
            // Apple's triples spell this "darwin"; Rust spells it "macos".
            "macos" => "darwin",
            other => other,
        };

        let mut triple = String::with_capacity(32);
        triple.push_str(std::env::consts::ARCH);
        triple.push('-');
        triple.push_str(HOST_VENDOR);
        triple.push('-');
        triple.push_str(os);

        if !HOST_ENV.is_empty() {
            triple.push('-');
            triple.push_str(HOST_ENV);
        }

        triple
    })
    .as_str()
}

// The 31 CURL_VERSION_* bits -- include/curl/curl.h:3175-3211
//
// Spelled `i32` rather than `core::ffi::c_int`. What changes is that the width
// stops being a property of whatever platform happens to compile the engine
// and becomes a property of the contract, which is what the C header actually
// fixes: `int features` is 32-bit because curl's ABI says so, not because a C
// compiler chose it. Every `c_*` conversion now happens in curl-rs-ffi, at the
// boundary that owns the C ABI, so the engine stays free of native-width
// assumptions.

/// IPv6-enabled.
pub const CURL_VERSION_IPV6: i32 = 1 << 0;
/// Kerberos V4 auth is supported (deprecated in the header).
pub const CURL_VERSION_KERBEROS4: i32 = 1 << 1;
/// SSL options are present.
pub const CURL_VERSION_SSL: i32 = 1 << 2;
/// libz features are present.
pub const CURL_VERSION_LIBZ: i32 = 1 << 3;
/// NTLM auth is supported.
pub const CURL_VERSION_NTLM: i32 = 1 << 4;
/// Negotiate auth is supported (deprecated in the header).
pub const CURL_VERSION_GSSNEGOTIATE: i32 = 1 << 5;
/// Built with debug capabilities.
pub const CURL_VERSION_DEBUG: i32 = 1 << 6;
/// Asynchronous DNS resolves.
pub const CURL_VERSION_ASYNCHDNS: i32 = 1 << 7;
/// SPNEGO auth is supported.
pub const CURL_VERSION_SPNEGO: i32 = 1 << 8;
/// Supports files larger than 2GB.
pub const CURL_VERSION_LARGEFILE: i32 = 1 << 9;
/// Internationalized domain names are supported.
pub const CURL_VERSION_IDN: i32 = 1 << 10;
/// Built against Windows SSPI.
pub const CURL_VERSION_SSPI: i32 = 1 << 11;
/// Character conversions supported (deprecated in the header).
pub const CURL_VERSION_CONV: i32 = 1 << 12;
/// Debug memory tracking supported (deprecated in the header).
pub const CURL_VERSION_CURLDEBUG: i32 = 1 << 13;
/// TLS-SRP auth is supported.
pub const CURL_VERSION_TLSAUTH_SRP: i32 = 1 << 14;
/// NTLM delegation to the winbind helper is supported (deprecated).
pub const CURL_VERSION_NTLM_WB: i32 = 1 << 15;
/// HTTP/2 support built in.
pub const CURL_VERSION_HTTP2: i32 = 1 << 16;
/// Built against a GSS-API library.
pub const CURL_VERSION_GSSAPI: i32 = 1 << 17;
/// Kerberos V5 auth is supported.
pub const CURL_VERSION_KERBEROS5: i32 = 1 << 18;
/// Unix domain socket support.
pub const CURL_VERSION_UNIX_SOCKETS: i32 = 1 << 19;
/// Mozilla's Public Suffix List, used for cookie domain verification.
pub const CURL_VERSION_PSL: i32 = 1 << 20;
/// HTTPS-proxy support built in.
pub const CURL_VERSION_HTTPS_PROXY: i32 = 1 << 21;
/// Multiple SSL backends available.
pub const CURL_VERSION_MULTI_SSL: i32 = 1 << 22;
/// Brotli features are present.
pub const CURL_VERSION_BROTLI: i32 = 1 << 23;
/// Alt-Svc handling built in.
pub const CURL_VERSION_ALTSVC: i32 = 1 << 24;
/// HTTP/3 support built in.
pub const CURL_VERSION_HTTP3: i32 = 1 << 25;
/// zstd features are present.
pub const CURL_VERSION_ZSTD: i32 = 1 << 26;
/// Unicode support on Windows.
pub const CURL_VERSION_UNICODE: i32 = 1 << 27;
/// HSTS is supported.
pub const CURL_VERSION_HSTS: i32 = 1 << 28;
/// libgsasl is supported.
pub const CURL_VERSION_GSASL: i32 = 1 << 29;
/// The libcurl API is thread-safe.
pub const CURL_VERSION_THREADSAFE: i32 = 1 << 30;

// CURLversion -- include/curl/curl.h:3088-3109

/// `CURLversion` -- which generation of [`VersionInfo`] a caller expects.
///
/// Twelve ages have been declared since 7.10, each adding fields to
/// `curl_version_info_data` and none ever removing one. A caller compiled
/// against an older header passes its own age and reads only the prefix of the
/// struct it knows about, which is why the field order in [`VersionInfo`] is
/// itself part of the ABI.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CURLversion {
    /// `CURLVERSION_FIRST` -- 7.10.
    First = 0,
    /// `CURLVERSION_SECOND` -- 7.11.1. Added `ares`, `ares_num`.
    Second = 1,
    /// `CURLVERSION_THIRD` -- 7.12.0. Added `libidn`.
    Third = 2,
    /// `CURLVERSION_FOURTH` -- 7.16.1. Added `iconv_ver_num`, `libssh_version`.
    Fourth = 3,
    /// `CURLVERSION_FIFTH` -- 7.57.0. Added the two `brotli` fields.
    Fifth = 4,
    /// `CURLVERSION_SIXTH` -- 7.66.0. Added the `nghttp2` pair and `quic_version`.
    Sixth = 5,
    /// `CURLVERSION_SEVENTH` -- 7.70.0. Added `cainfo`, `capath`.
    Seventh = 6,
    /// `CURLVERSION_EIGHTH` -- 7.72.0. Added the two `zstd` fields.
    Eighth = 7,
    /// `CURLVERSION_NINTH` -- 7.75.0. Added `hyper_version`.
    Ninth = 8,
    /// `CURLVERSION_TENTH` -- 7.77.0. Added `gsasl_version`.
    Tenth = 9,
    /// `CURLVERSION_ELEVENTH` -- 7.87.0. Added `feature_names`.
    Eleventh = 10,
    /// `CURLVERSION_TWELFTH` -- 8.8.0. Added `rtmp_version`. The current age.
    Twelfth = 11,
}

impl CURLversion {
    /// `CURLVERSION_NOW` -- `include/curl/curl.h:3109`.
    ///
    /// "The symbolic name meant to be used by basically all programs ever that
    /// want to get version information."
    pub const NOW: Self = Self::Twelfth;

    /// The integer behind `CURLVERSION_LAST`, which is not a usable age.
    pub const LAST: i32 = 12;

    /// How many real ages exist.
    pub const COUNT: usize = 12;

    /// Every age, in declaration order.
    pub const VARIANTS: &'static [Self] = &[
        Self::First,
        Self::Second,
        Self::Third,
        Self::Fourth,
        Self::Fifth,
        Self::Sixth,
        Self::Seventh,
        Self::Eighth,
        Self::Ninth,
        Self::Tenth,
        Self::Eleventh,
        Self::Twelfth,
    ];

    /// The integer a C caller passes and receives.
    #[must_use]
    pub const fn as_c_int(self) -> i32 {
        self as i32
    }

    /// Recovers an age from the integer, or `None` for one that names no age.
    ///
    /// `CURLVERSION_LAST` deliberately yields `None`: it is a bound, not a
    /// value, so a caller that passes it is passing something meaningless and
    /// the boundary layer should be able to see that.
    #[must_use]
    pub const fn from_c_int(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::First),
            1 => Some(Self::Second),
            2 => Some(Self::Third),
            3 => Some(Self::Fourth),
            4 => Some(Self::Fifth),
            5 => Some(Self::Sixth),
            6 => Some(Self::Seventh),
            7 => Some(Self::Eighth),
            8 => Some(Self::Ninth),
            9 => Some(Self::Tenth),
            10 => Some(Self::Eleventh),
            11 => Some(Self::Twelfth),
            _ => None,
        }
    }

    /// The C token for this age, for diagnostics and for `--libcurl` output.
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        match self {
            Self::First => "CURLVERSION_FIRST",
            Self::Second => "CURLVERSION_SECOND",
            Self::Third => "CURLVERSION_THIRD",
            Self::Fourth => "CURLVERSION_FOURTH",
            Self::Fifth => "CURLVERSION_FIFTH",
            Self::Sixth => "CURLVERSION_SIXTH",
            Self::Seventh => "CURLVERSION_SEVENTH",
            Self::Eighth => "CURLVERSION_EIGHTH",
            Self::Ninth => "CURLVERSION_NINTH",
            Self::Tenth => "CURLVERSION_TENTH",
            Self::Eleventh => "CURLVERSION_ELEVENTH",
            Self::Twelfth => "CURLVERSION_TWELFTH",
        }
    }

    /// The libcurl release that introduced this age, from the header's own
    /// trailing comments (`include/curl/curl.h:3089-3101`).
    #[must_use]
    pub const fn introduced_in(self) -> &'static str {
        match self {
            Self::First => "7.10",
            Self::Second => "7.11.1",
            Self::Third => "7.12.0",
            Self::Fourth => "7.16.1",
            Self::Fifth => "7.57.0",
            Self::Sixth => "7.66.0",
            Self::Seventh => "7.70.0",
            Self::Eighth => "7.72.0",
            Self::Ninth => "7.75.0",
            Self::Tenth => "7.77.0",
            Self::Eleventh => "7.87.0",
            Self::Twelfth => "8.8.0",
        }
    }
}

impl core::fmt::Display for CURLversion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.c_name())
    }
}

// Library tokens
//
//   1. Each version literal appears exactly once, as a macro body, and is
//      taken from the exact `=x.y.z` pin in the root [workspace.dependencies].
//      tests::library_tokens_match_the_manifest re-reads the manifest and
//      fails if a pin moves, so the banner cannot silently start lying.
//   2. A capability with no truthful token gets none. In particular the
//      GSS-API slot (lib/version.c:256-267, which emits "mit-krb5/x",
//      "libgss/x" or a bare "mit-krb5") is left empty even under the
//      `negotiate` feature: the provider is whatever the platform supplies to
//      crate::ffi::gss, its identity is not determinable from here, and the C
//      code's bare "mit-krb5" fallback is itself a guess. The capability is
//      still reported truthfully through the GSS-API, SPNEGO and Kerberos
//      feature names, which is the surface the harness actually reads.

/// The pinned `rustls` version. `Cargo.toml`: `rustls = { version = "=..." }`.
macro_rules! rustls_version_literal {
    () => {
        "0.23.42"
    };
}

/// The pinned `flate2` version -- the gzip and deflate implementation.
macro_rules! flate2_version_literal {
    () => {
        "1.1.9"
    };
}

/// The pinned `brotli` version.
macro_rules! brotli_version_literal {
    () => {
        "8.0.4"
    };
}

/// The pinned `zstd` version.
macro_rules! zstd_version_literal {
    () => {
        "0.13.3"
    };
}

/// The pinned `idna` version -- the IDN implementation, replacing libidn2.
macro_rules! idna_version_literal {
    () => {
        "1.1.0"
    };
}

/// The pinned `publicsuffix` version -- replacing libpsl.
macro_rules! publicsuffix_version_literal {
    () => {
        "2.3.0"
    };
}

/// The pinned `russh` version -- the SSH transport, replacing libssh2.
macro_rules! russh_version_literal {
    () => {
        "0.54.5"
    };
}

/// The version `hickory-resolver` would be pinned at -- the optional in-process
/// resolver that would replace what `lib/asyn-ares.c` did with c-ares.
macro_rules! hickory_resolver_version_literal {
    () => {
        "0.25.2"
    };
}

/// The pinned `h2` version -- the HTTP/2 implementation, replacing nghttp2.
macro_rules! h2_version_literal {
    () => {
        "0.4.15"
    };
}

/// The pinned `quinn` version -- the QUIC transport, replacing ngtcp2.
macro_rules! quinn_version_literal {
    () => {
        "0.11.9"
    };
}

/// The pinned `h3` version -- the HTTP/3 layer, replacing nghttp3.
macro_rules! h3_version_literal {
    () => {
        "0.0.8"
    };
}

/// The pinned `hyper` version -- HTTP/1.1 connection management and framing.
macro_rules! hyper_version_literal {
    () => {
        "1.11.0"
    };
}

/// The TLS backend's name: `"rustls"`.
///
/// This is the single source of truth for the string, and it is deliberately
/// the same spelling the C tree uses in `Curl_ssl_rustls.info`
/// (`{ CURLSSLBACKEND_RUSTLS, "rustls" }`, `lib/vtls/rustls.c:1398`).
/// `crate::tls` and `curl-rs-ffi`'s `curl_global_sslset` must consume it from
/// here rather than restate it, so that the backend cannot be called one thing
/// by the banner and another by the API.
pub const TLS_BACKEND_NAME: &str = "rustls";

/// The TLS backend's public identifier: `CURLSSLBACKEND_RUSTLS` = 14.
///
/// Measured at `include/curl/curl.h:166`. The enumerant already exists in the
/// published header, so `curl_global_sslset` can report a rustls backend
/// without inventing a value.
pub const TLS_BACKEND_ID: i32 = 14;

/// The pinned version of the TLS implementation.
pub const RUSTLS_VERSION: &str = rustls_version_literal!();

/// The TLS version string: `rustls/0.23.42`.
pub const SSL_VERSION: &str = concat!("rustls", "/", rustls_version_literal!());

/// The gzip and deflate token: `flate2/1.1.9`.
///
/// The C banner says `zlib/<zlibVersion()>`. No zlib is linked: `flate2` is
/// pinned with `default-features = false, features = ["rust_backend"]`, so the
/// implementation is pure Rust and there is no C library version to report.
const LIBZ_TOKEN: &str = concat!("flate2", "/", flate2_version_literal!());

/// The Brotli token: `brotli/8.0.4`.
const BROTLI_TOKEN: &str = concat!("brotli", "/", brotli_version_literal!());

/// The Zstandard token: `zstd/0.13.3`.
const ZSTD_TOKEN: &str = concat!("zstd", "/", zstd_version_literal!());

/// The IDN token: `idna/1.1.0`.
///
/// Deliberately not spelled `libidn2/...`: `tests/runtests.pl:622-624` sets
/// `$feature{"libidn2"}` from that token, and this build is not libidn2.
const IDN_TOKEN: &str = concat!("idna", "/", idna_version_literal!());

/// The public-suffix token: `publicsuffix/2.3.0`.
const PSL_TOKEN: &str =
    concat!("publicsuffix", "/", publicsuffix_version_literal!());

/// The SSH token: `russh/0.54.5`.
///
/// Deliberately not spelled `libssh2/...` or `libssh/x.y/`, both of which
/// `tests/runtests.pl:625-647` recognises and neither of which is what this
/// build links. The second of those two also switches on host-key-checking
/// leniency detection, so a false match would change harness behaviour.
const SSH_TOKEN: &str = concat!("russh", "/", russh_version_literal!());

/// The resolver token: `hickory-resolver/0.25.2`, emitted only when the
/// default-off `hickory-dns` feature is on AND its engine is present.
///
/// It is deliberately **not** spelled `c-ares/...`. `hickory-resolver` shares
/// no substring with any token the harness recognises, so enabling the feature
/// adds information without changing a single harness inference.
const RESOLVER_TOKEN: &str =
    concat!("hickory-resolver", "/", hickory_resolver_version_literal!());

/// Whether the banner has earned the right to name an alternative resolver.
///
/// The crate is deliberately not named as a `const _` type contract either --
/// the style `crate::crypto` uses for its real dependencies -- because that
/// requires the crate to be in the dependency graph.
fn resolver_token_is_earned() -> bool {
    cfg!(feature = "hickory-dns") && ENGINE_DNS.is_present()
}

/// The HTTP/2 token: `h2/0.4.15`.
///
/// Deliberately not spelled `nghttp2/...`: `tests/runtests.pl:612-615` infers
/// `h2c` support from that token, and inferring it here would be a guess about
/// cleartext HTTP/2 that this module has no authority to make.
const HTTP2_TOKEN: &str = concat!("h2", "/", h2_version_literal!());

/// The HTTP/3 token: `quinn/0.11.9 h3/0.0.8`.
///
/// One part containing a space, exactly like the C original: `Curl_quic_ver()`
/// writes both the transport and the protocol library into a single buffer
/// (for example `ngtcp2/1.2.0 nghttp3/1.1.0`), and `lib/version.c:243-246`
/// appends that buffer as one element of `src[]`.
const HTTP3_TOKEN: &str = concat!(
    "quinn",
    "/",
    quinn_version_literal!(),
    " h3/",
    h3_version_literal!()
);

/// The HTTP/1.1 token: `hyper/1.11.0`.
const HYPER_TOKEN: &str = concat!("hyper", "/", hyper_version_literal!());

/// Encodes a version the way Brotli and Zstandard are encoded in
/// `curl_version_info_data`: `(MAJOR << 24) | (MINOR << 12) | PATCH`.
#[must_use]
const fn packed_version_24_12(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 24) | (minor << 12) | patch
}

/// Encodes a version the way nghttp2 is encoded in `curl_version_info_data`:
/// `(MAJOR << 16) | (MINOR << 8) | PATCH` (`include/curl/curl.h:3148-3149`).
///
/// Retained for completeness of the payload's contract even though this build
/// reports no nghttp2 version: `curl-rs-ffi` and any future HTTP/2 reporting
/// must use this encoding and not invent another.
#[must_use]
const fn packed_version_16_8(major: u32, minor: u32, patch: u32) -> u32 {
    (major << 16) | (minor << 8) | patch
}

/// Whether the TLS backend can tunnel through an HTTPS proxy.
#[must_use]
fn tls_supports_https_proxy() -> bool {
    true
}

/// Whether a usable GSS-API implementation is available RIGHT NOW.
#[must_use]
fn gss_present() -> bool {
    crate::ffi::gss_available()
}

/// Whether the TLS backend supports Encrypted Client Hello.
#[must_use]
fn tls_supports_ech() -> bool {
    false
}

// The engine registry -- the single authority on what can actually execute
//
// THE SECOND MACHINE-READ SURFACE, which is why this registry serves more than
// the banner. `tests/runtests.pl:537-546` runs the `curlinfo` diagnostic
// (`tests/globalconfig.pm:122-123`) and folds ITS output into the same
// feature map: every row it prints as `ON` becomes `$feature{<label>} = 1` and
// every `OFF` row is pushed onto `@disabled`. Measured over `tests/data/`, 492
// fixtures gate positively on a `curlinfo` label and one gates negatively --
// `proxy` alone accounts for 225 of them, then `digest` 76, `cookies` 51,
// `Mime` 48, `aws` 22, `headers-api` 14, `--libcurl` 11, `verbose-strings` 10,
// `form-api` 9, `DoH` 5, `sha512-256` 5, `large-time` 4, `override-dns` 3,
// `xattr` 3, `wakeup` 2, and `large-size`, `netrc`, `shuffle-dns`,
// `ssl-sessions` one each. `tests/http/testenv/env.py:162-167` reads the same
// output for `verbose-strings: ON` and `cert-status: ON`. So the entries below
// that no `--version` token consults are not bookkeeping: they decide fixture
// eligibility just as directly as the ones that do, and `curl-rs`'s
// `src/bin/curlinfo.rs` derives all 29 of its rows from them rather than
// keeping a second opinion of its own.
//
// HOW THE DANGEROUS DIRECTION IS ENFORCED MECHANICALLY. `present: true` is the
// only value that can cause over-advertisement, so every `true` in this
// registry is accompanied by a compile-time reference to a real item the owning
// module must export -- see the `const _:` block after the table. If such a
// module were removed or its entry point renamed, the build stops here rather
// than at a fixture. The `false` entries carry no such link, and none is needed:
// their only cost is a skipped fixture.
//
// WHY A ROW RECORDS TWO FACTS AND NOT ONE. `is_present() == false` has two
// causes -- the module AAP 0.4.1 assigns the work is not written, or it IS
// written and nothing calls it -- and for most of this checkpoint's life the
// registry recorded only the disjunction, under the name `absent`. The prose
// beside each row then drifted: paragraph after paragraph asserted that a file
// which exists on disk did not, so the stated remedy was to write something
// already written. `Engine` therefore carries `written` beside `present`, three
// constructors cover the three reachable combinations, and the fourth --
// executing work with no source -- is unrepresentable. Measured over this
// checkout: SIX rows are `working`, TWENTY are `inert` (written, not wired), and
// THREE are genuinely `unwritten` -- `proxy/http_connect.rs`,
// `transfer/content_encoding.rs` and `curl-rs/src/libcurl_src.rs`.
//
// The `written` flag changes no capability answer. It exists so that "what would
// clear this row" is recorded correctly, and so that the claim is checkable:
// `curl-rs/src/bin/curlinfo.rs` compares every row against the filesystem. That
// check cannot live here, because this crate must stay runnable under the
// `cargo miri test -p curl-rs-lib` gate of AAP 0.8.4 and Miri's isolation
// blocks the read.

/// One engine component whose presence gates a capability claim.
///
/// The `owner` string is not decoration. It names the module AAP 0.4.1 assigns
/// the work, so the single edit that turns a capability on -- once its module
/// lands -- is visible from the claim it controls, and a reviewer can check the
/// pairing without leaving this file.
///
/// # Why there are two booleans and not one
///
/// "The capability is unavailable" has two distinct causes, and collapsing them
/// into one flag is how this registry's own prose went stale. A row can be
/// unavailable because the file AAP 0.4.1 assigns the work **has not been
/// written**, or because the file IS written and the end-to-end path it
/// participates in is **not wired up** -- the seam it plugs into is absent, or
/// the entry point that would drive it is undefined.
///
/// Both withhold the capability, so [`is_present`](Self::is_present) is the
/// same in either case and no consumer's behaviour depends on the difference.
/// What does depend on it is the answer to *what would clear this row*, and the
/// two answers are opposite: write a file, or wire one that already exists.
/// Recording only "absent" invited paragraph after paragraph asserting that a
/// present file did not exist, each of which read as an instruction to write
/// something that is already there.
///
/// So source presence is a field, not prose, and the fourth combination --
/// executing work with no source -- is unrepresentable because no constructor
/// produces it. `curl-rs/src/bin/curlinfo.rs`'s
/// `every_engine_records_its_source_presence_correctly` checks the field
/// against the filesystem, which is a check this crate cannot make itself: it
/// must stay runnable under the `cargo miri test -p curl-rs-lib` gate of AAP
/// 0.8.4, and Miri's isolation blocks the directory read.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Engine {
    owner: &'static str,

    /// Whether the file named by `owner` exists in this checkout.
    ///
    /// A statement about the tree and nothing more. It says nothing about
    /// whether the module is complete, reachable, or wired to anything.
    written: bool,

    /// Whether this build carries a working implementation of it.
    present: bool,
}

impl Engine {
    /// The owning module path, for example `"curl-rs-lib/src/dns/resolver.rs"`.
    #[must_use]
    pub const fn owner(&self) -> &'static str {
        self.owner
    }

    /// Whether this build can actually execute the work.
    ///
    /// This is the predicate every capability claim is conjoined with. It is
    /// deliberately NOT the same question as
    /// [`is_written`](Self::is_written): a module can be on disk and complete
    /// in itself while the path that would call it does not exist.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        self.present
    }

    /// Whether the module named by [`owner`](Self::owner) exists in this
    /// checkout.
    ///
    /// Present implies written; the converse does not hold, and the twenty
    /// entries where it does not are exactly the ones whose remaining work is
    /// wiring rather than writing.
    #[must_use]
    pub const fn is_written(&self) -> bool {
        self.written
    }

    /// An engine whose module exists and whose work this build can execute.
    const fn working(owner: &'static str) -> Self {
        Self {
            owner,
            written: true,
            present: true,
        }
    }

    /// An engine whose module exists but whose work this build cannot yet
    /// execute end to end. Every capability that depends on it is withheld,
    /// exactly as for [`unwritten`](Self::unwritten) -- what differs is that
    /// writing the file would not clear it, because the file is written.
    const fn inert(owner: &'static str) -> Self {
        Self {
            owner,
            written: true,
            present: false,
        }
    }

    /// An engine whose module AAP 0.4.1 mandates but which does not exist in
    /// this checkout. Every capability that depends on it is withheld.
    const fn unwritten(owner: &'static str) -> Self {
        Self {
            owner,
            written: false,
            present: false,
        }
    }
}

/// Internationalised domain names -- `curl-rs-lib/src/url/idn.rs`.
///
/// The `IDN` row's predicate consults [`crate::url::idn::available`] directly,
/// so the module that implements the capability is also the module that
/// reports it.
pub const ENGINE_IDN: Engine = Engine::working("curl-rs-lib/src/url/idn.rs");

/// Name resolution -- `curl-rs-lib/src/dns/`.
///
/// Gates `AsynchDNS`, and the `shuffle-dns` row of `curlinfo`.
///
/// INERT, not unwritten: `dns/mod.rs` (5,162 lines), `dns/resolver.rs` (3,910),
/// `dns/doh.rs`, `dns/httpsrr.rs` and `dns/if2ip.rs` are all on disk. What is
/// missing is the caller: no transfer exists to request a lookup, and the
/// resolver's own transport seam has no implementor, so the
/// `alarm()`/`sigsetjmp` deadline of `lib/hostip.c` has a
/// `tokio::time::timeout` counterpart with nothing to time. Address-order
/// randomization -- the capability behind `CURLOPT_DNS_SHUFFLE_ADDRESSES` and
/// C's `CURL_DISABLE_SHUFFLE_DNS` -- is a property of that same resolver and is
/// withheld with it. No fixture gates on `AsynchDNS` and one gates on
/// `shuffle-dns`, so withholding costs one skipped fixture.
pub const ENGINE_DNS: Engine = Engine::inert("curl-rs-lib/src/dns/resolver.rs");

/// Connection establishment and the filter chain -- `curl-rs-lib/src/conn/`.
///
/// Gates `IPv6`, `UnixSockets`, and the `bindlocal` row of `curlinfo`.
///
/// INERT, not unwritten: `conn/mod.rs`, `conn/socket.rs` (8,747 lines),
/// `conn/happy_eyeballs.rs` (5,154), `conn/filters.rs` (7,008),
/// `conn/pool.rs`, `conn/select.rs` and `conn/shutdown.rs` all exist. What is
/// missing is a transfer to drive them: nothing in the tree opens a connection,
/// because the loop that would ask for one (see [`ENGINE_TRANSFER`]) is not
/// wired. `bindlocal()` -- which `lib/cf-socket.c` uses to honour
/// `--interface`, `--local-port` and `CURLOPT_INTERFACE`, and which C guards
/// with `CURL_DISABLE_BINDLOCAL` -- therefore has no socket to bind, though the
/// code that would bind it is present. Cost of withholding, measured over
/// `tests/data/`: 29 fixtures require `IPv6` and 6 require `UnixSockets` and
/// will skip; 1 requires `!IPv6` and becomes eligible, and it also needs a
/// `<server>` this build does not advertise, so it skips on that gate instead.
/// No fixture gates on `bindlocal`.
pub const ENGINE_CONN: Engine = Engine::inert("curl-rs-lib/src/conn/mod.rs");

/// The TLS backend -- `curl-rs-lib/src/tls/`.
///
/// Gates `SSL`, and through it every `s`-suffixed scheme.
///
/// INERT, not unwritten: all six modules of the subtree are on disk --
/// `tls/mod.rs` (7,739 lines), `tls/rustls_backend.rs` (6,292),
/// `tls/verify.rs` (4,725), `tls/session_cache.rs` (6,332),
/// `tls/cipher_suite.rs` and `tls/keylog.rs`. What is missing is a byte stream
/// to hand them: a handshake needs a connected socket delivered through the
/// filter chain, and nothing in the tree establishes one (see
/// [`ENGINE_CONN`]), so no session has ever been driven end to end and no
/// certificate verified against a live peer.
///
/// This is the most expensive withholding in the registry: 138 fixtures
/// require `SSL` and will skip. It is still the correct one. Advertising `SSL`
/// would make all 138 run against an engine that cannot complete a handshake,
/// which is precisely the failure mode AAP 0.6.5 forbids. No fixture requires
/// `!SSL`, so nothing becomes eligible in exchange.
pub const ENGINE_TLS: Engine = Engine::inert("curl-rs-lib/src/tls/mod.rs");

/// Proxy support -- `curl-rs-lib/src/proxy/`.
///
/// Gates `HTTPS-proxy`, and the `proxy` row of `curlinfo`. UNWRITTEN, and this
/// is one of the three entries where that is literally true:
/// `proxy/http_connect.rs` does not exist, nor do `proxy/socks.rs`,
/// `proxy/socks_gss.rs` or `proxy/haproxy.rs`. `proxy/mod.rs` and
/// `proxy/noproxy.rs` are the only two files in the subtree, and `noproxy.rs`
/// decides whether a proxy would be BYPASSED -- it cannot reach one. So there
/// is no CONNECT tunnel over which to layer a rustls session and no proxy of
/// any kind can be reached.
///
/// This is the most expensive withholding measured anywhere in the registry: no
/// fixture gates on `HTTPS-proxy`, but **225** gate on `proxy`, the single most
/// demanded capability in the corpus (AAP 0.6.5). All 225 skip. One fixture
/// gates on `!proxy` and becomes eligible in exchange -- `tests/data/test375`,
/// which runs `-x wohoo http://example.com/` and requires stderr `curl: proxy
/// support is disabled in this libcurl` with `<errorcode> 4`
/// (`CURLE_NOT_BUILT_IN`). That pairing is the point: a build that truthfully
/// reports the row `OFF` is exactly the build whose `--proxy` must fail that
/// way, so honesty here creates a checkable obligation instead of hiding one.
pub const ENGINE_PROXY: Engine =
    Engine::unwritten("curl-rs-lib/src/proxy/http_connect.rs");

/// Authentication mechanisms -- `curl-rs-lib/src/auth/`.
///
/// Gates `NTLM`, and together with [`ENGINE_GSS`] the Negotiate family.
///
/// INERT, not unwritten: `auth/mod.rs` (5,819 lines) and `auth/ntlm.rs`
/// (5,625) both exist, and `des`, `md4`, `md-5` and `hmac` are all linked. What
/// is missing is the exchange: answering a challenge means reading a
/// `WWW-Authenticate` header off a response and putting an `Authorization`
/// header on the retry, and no request/response cycle exists to do either. 53
/// fixtures require `NTLM` and will skip; none requires `!NTLM`.
pub const ENGINE_AUTH: Engine = Engine::inert("curl-rs-lib/src/auth/ntlm.rs");

/// Negotiate over GSS-API -- `curl-rs-lib/src/auth/negotiate.rs`.
///
/// Named for the owner it actually gates, which is the HTTP driver and not the
/// binding: `ffi/gss.rs` exists and is complete, so heading this entry with
/// that path would put the gap somewhere that needs no work.
///
/// Gates `GSS-API`, `Kerberos` and `SPNEGO` jointly with [`ENGINE_AUTH`].
/// INERT, not unwritten: the binding exists AND so does `auth/negotiate.rs`
/// (3,498 lines). What is missing is the HTTP exchange it would drive -- the
/// same missing cycle as [`ENGINE_AUTH`] -- so the capability cannot execute
/// and the three names stay withheld regardless of the non-default `negotiate`
/// feature. 5 fixtures require `GSS-API`.
///
/// The same module is what C's `CURL_DISABLE_NEGOTIATE_AUTH` guards, so the
/// `negotiate-auth` row of `curlinfo` is gated here too. Both surfaces now carry
/// the SAME three conjuncts -- feature, this engine, and the runtime probe --
/// the banner via `present: Some(gss_present)` folded in by
/// [`Feature::is_present`], the diagnostic via [`negotiate_usable`]. They are
/// spelled differently only because C spells them differently; they cannot
/// disagree. No fixture gates on the `negotiate-auth` label.
pub const ENGINE_GSS: Engine =
    Engine::inert("curl-rs-lib/src/auth/negotiate.rs");

/// The state stores -- `curl-rs-lib/src/cookies/`.
///
/// Gates `alt-svc`, `HSTS` and `PSL`, and the `cookies` row of `curlinfo`.
///
/// INERT, not unwritten: `cookies/mod.rs` (9,732 lines), `cookies/altsvc.rs`
/// (4,864), `cookies/hsts.rs` (4,088) and `cookies/psl.rs` (2,128) all exist,
/// and the byte-compatible Netscape jar format AAP 0.4.1 requires is
/// implemented and tested against the C oracle. What is missing is the traffic:
/// a jar is populated from `Set-Cookie` response headers and consulted when
/// composing a request, and neither happens because no request is composed. 10,
/// 11 and 2 fixtures require the three banner names respectively, and 51 gate on
/// the `cookies` label -- `cookies/mod.rs` is precisely the jar that C's
/// `CURL_DISABLE_COOKIES` removes, so the row is gated here, conjoined with the
/// default-on `cookies` feature.
///
/// `cookies/netrc.rs` is a sibling in the same subtree but has its own entry,
/// [`ENGINE_NETRC`], because it is a separate capability with a separate C
/// guard: one entry must never be able to turn both rows on at once.
pub const ENGINE_STATE_STORES: Engine =
    Engine::inert("curl-rs-lib/src/cookies/mod.rs");

/// Content decoding -- `curl-rs-lib/src/transfer/content_encoding.rs`.
///
/// Gates `libz`, `brotli` and `zstd`. UNWRITTEN, and this is one of the three
/// entries where that is literally true: the file does not exist, so a
/// `Content-Encoding` response body cannot be decoded even though `flate2`,
/// `brotli` and `zstd` are linked. 19, 3 and 2 fixtures require the three names
/// respectively.
pub const ENGINE_CONTENT_ENCODING: Engine =
    Engine::unwritten("curl-rs-lib/src/transfer/content_encoding.rs");

/// The protocol implementations -- `curl-rs-lib/src/protocols/`.
///
/// Gates `HTTP2`, `HTTP3` and every row of [`PROTOCOLS`].
///
/// INERT, not unwritten, and the distinction is sharper here than anywhere else
/// in the registry: `protocols/mod.rs` exists and carries the complete 33-entry
/// scheme registry that `Curl_get_scheme` resolves against
/// (`lib/url.c:1469-1500`), so a URL's scheme IS recognised, its default port
/// IS known, and `CURLU` parsing works. What does not exist is any per-scheme
/// EXECUTOR. `protocols/` holds exactly three files: `mod.rs` (the registry),
/// `ftp/mod.rs` (74 lines, a module root declaring its one written child) and
/// `ftp/listparser.rs` (5,516 lines), and the listing parser interprets the
/// output of a `LIST` command without being able to issue one. The nine files
/// that would carry an executor -- `http1`, `http2`, `http3`, `sftp`, `scp`,
/// `file`, `ws`, `stub` and `ftp/pingpong` -- are all absent, which
/// `curl-rs/src/bin/curlinfo.rs`'s `absent_target_gate` checks against the disk.
/// `protocols::EXECUTORS` is therefore empty, and because `SchemeInfo::runnable`
/// is derived from it, no scheme reports an implementation -- the same answer
/// C's non-`NULL` `run` pointer test gives for a scheme compiled out.
///
/// Consequence, stated plainly rather than left to be discovered: [`protocols`]
/// returns an empty slice and the `Protocols:` banner line is empty. The
/// harness's `parseprotocols()` then derives no protocol features, so every
/// fixture with a `<server>` requirement skips -- which is every fixture that
/// transfers anything. That is the truthful description of a build with a scheme
/// table and no executors, and it is the reading AAP 0.6.5 requires: a fixture
/// that skips reports the gap, whereas a fixture that runs against a missing
/// engine reports a defect that does not exist.
pub const ENGINE_PROTOCOLS: Engine =
    Engine::inert("curl-rs-lib/src/protocols/mod.rs");

/// The transfer core -- `curl-rs-lib/src/transfer/`.
///
/// Gates nothing on its own today, and is registered because it is the engine
/// every protocol claim ultimately rests on.
///
/// INERT, not unwritten: `transfer/mod.rs`, `transfer/request.rs` (6,279
/// lines), `transfer/sendf.rs` (10,231), `transfer/writeout.rs`,
/// `transfer/progress.rs` and `transfer/ratelimit.rs` all exist. What is missing
/// is the loop itself -- `transfer/mod.rs` is 174 lines of module declarations
/// and carries no state machine -- and `transfer/chunked.rs` and
/// `transfer/content_encoding.rs` are absent outright. So even a scheme with its
/// own executor would have nothing to run it. Recorded so that a later
/// checkpoint enabling [`ENGINE_PROTOCOLS`] has to confront this one as well.
pub const ENGINE_TRANSFER: Engine =
    Engine::inert("curl-rs-lib/src/transfer/mod.rs");

/// Global initialization and the C entry points -- `curl-rs-ffi/src/ffi/`.
///
/// Gates `threadsafe`, which in C is `#if defined(GLOBAL_INIT_IS_THREADSAFE)`
/// (`lib/version.c:538`) -- a claim about `curl_global_init` and
/// `curl_global_cleanup` specifically, not about the engine generally.
///
/// The initialization path is serialized by a `static STATE:
/// Mutex<GlobalState>` -- one lock rather than two atomics, for the same reason
/// C takes one: the flags and the reference count move together, and a second
/// thread must not observe the intermediate state. C defines the macro
/// unconditionally (`lib/easy_lock.h:28`, with no `#if` around it), so `ON` is
/// also what every stock C build reports.
///
/// # Why this one has no `const _` link beside `ENGINES`
///
/// It cannot have one. Every other present engine is owned by a module of THIS
/// crate, so the registry can name an item that module must export. This engine
/// is owned by `curl-rs-ffi`, which DEPENDS on this crate -- naming an item in
/// it here would invert the workspace's dependency direction. The
/// correspondence is asserted from the other side, in `curl-rs-ffi`, the only
/// crate that can see both, and
/// `every_present_engine_has_a_compile_time_link` records the exception
/// explicitly rather than quietly tolerating it.
///
/// 1 fixture requires the name (`tests/data/test3026`), and it additionally
/// requires `threaded-resolver`, which the harness derives from an `AsynchDNS`
/// token this build withholds -- so advertising this truthfully cannot make
/// that fixture run before its resolver exists.
pub const ENGINE_GLOBAL_INIT: Engine =
    Engine::working("curl-rs-ffi/src/ffi/global.rs");

// Engines consulted only by the `curlinfo` diagnostic
//
// Granularity is deliberately per-file rather than per-directory. The
// alternative -- one entry per subtree -- would let a checkpoint that lands
// `auth/basic.rs` alone turn on `digest` and `aws` with it.

/// Basic authentication -- `curl-rs-lib/src/auth/basic.rs`.
///
/// Gates the `basic-auth` row, which C guards with `CURL_DISABLE_BASIC_AUTH`.
///
/// INERT, not unwritten: `auth/basic.rs` (952 lines) and `auth/mod.rs` both
/// exist and the credential encoding is implemented and tested. What is missing
/// is the header sink -- there is no request to place `Authorization: Basic` on.
/// No fixture gates on the label.
pub const ENGINE_AUTH_BASIC: Engine =
    Engine::inert("curl-rs-lib/src/auth/basic.rs");

/// Bearer-token authentication -- `curl-rs-lib/src/auth/bearer.rs`.
///
/// Gates the `bearer-auth` row (`CURL_DISABLE_BEARER_AUTH`). INERT, not
/// unwritten: `auth/bearer.rs` is 1,104 lines, and what `--oauth2-bearer` lacks
/// is not a token formatter but a request to carry the token. No fixture gates
/// on the label.
pub const ENGINE_AUTH_BEARER: Engine =
    Engine::inert("curl-rs-lib/src/auth/bearer.rs");

/// Digest authentication -- `curl-rs-lib/src/auth/digest.rs`.
///
/// Gates the `digest` row (`CURL_DISABLE_DIGEST_AUTH`).
///
/// INERT, not unwritten: `auth/digest.rs` is 4,053 lines and carries the
/// byte-exact message construction AAP 0.4.1 requires, mapped from
/// `lib/vauth/digest.c` and `lib/http_digest.c`. What is missing is the
/// challenge: a Digest exchange is a 401 response followed by a retry, and no
/// response is ever received. 76 fixtures gate on the label and skip -- the
/// second-largest withholding in the registry.
pub const ENGINE_AUTH_DIGEST: Engine =
    Engine::inert("curl-rs-lib/src/auth/digest.rs");

/// AWS SigV4 request signing -- `curl-rs-lib/src/auth/aws_sigv4.rs`.
///
/// Gates the `aws` row (`CURL_DISABLE_AWS`). INERT, not unwritten:
/// `auth/aws_sigv4.rs` is 3,767 lines and `sha2` and `hmac` are linked, but a
/// signature is computed over a canonical request that nothing composes, so
/// `--aws-sigv4` has nothing to sign. 22 fixtures gate on the label and skip.
pub const ENGINE_AUTH_AWS_SIGV4: Engine =
    Engine::inert("curl-rs-lib/src/auth/aws_sigv4.rs");

/// The HTTP authentication dispatcher -- `curl-rs-lib/src/auth/mod.rs`.
///
/// Gates the `HTTP-auth` row (`CURL_DISABLE_HTTP_AUTH`), which in C removes the
/// whole `WWW-Authenticate` negotiation rather than one mechanism.
///
/// INERT, not unwritten: `auth/mod.rs` is 5,819 lines and is the module AAP
/// 0.4.1 maps from `lib/vauth/vauth.c` for "mechanism selection and
/// negotiation", so the four mechanism entries above DO have something to select
/// between. What is missing is the input: selection is driven by the
/// `WWW-Authenticate` headers of a response, and no response arrives. No fixture
/// gates on the label.
pub const ENGINE_AUTH_DISPATCH: Engine =
    Engine::inert("curl-rs-lib/src/auth/mod.rs");

/// DNS-over-HTTPS -- `curl-rs-lib/src/dns/doh.rs`.
///
/// Gates the `DoH` row (`CURL_DISABLE_DOH`), conjoined with the default-on
/// `doh` feature.
///
/// INERT, not unwritten, and this entry has said so since before the
/// distinction became a field: `dns/doh.rs` is 6,986 lines carrying the RFC 8484
/// codec, the probe orchestration and the HTTPS-RR record walk. What is missing
/// is the transport -- no PRODUCTION implementor of `dns::DohTransport` exists
/// (every one in the tree is a `#[cfg(test)]` double), because that seam is
/// filled from `protocols/` or `conn/`, neither of which is wired -- and the TLS
/// engine it would layer on cannot be driven either (see [`ENGINE_TLS`]).
/// [`Engine::is_present`] means the build can *execute* the work, not merely
/// that the source is on disk, so the label stays withheld: AAP 0.6.5 measures
/// that over-reporting a capability makes a fixture run and fail while
/// under-reporting only makes it skip. 5 fixtures gate on the label and skip.
///
/// This marker is no longer the only thing holding the label back.
/// [`supports_doh`] also counts [`crate::dns::DOH_TRANSPORTS`], so advancing
/// this row alone cannot advertise DoH -- the registry has to gain an entry
/// too, which is the event that actually makes the capability real.
pub const ENGINE_DOH: Engine = Engine::inert("curl-rs-lib/src/dns/doh.rs");

/// MIME multipart construction -- `curl-rs-lib/src/mime/mod.rs`.
///
/// Gates the `Mime` row (`CURL_DISABLE_MIME`). **Written and working.** AAP
/// 0.4.1 maps the
/// module from `lib/mime.c` as the backing for the twelve exported
/// `curl_mime_*` symbols, and both halves of that mapping have landed: the
/// module carries the part tree, the boundary generation, the encoders, the
/// `Curl_mime_prepare_headers` counterpart and the reader state machine, and
/// `curl-rs-ffi/src/ffi/mime.rs` exports all twelve entry points on top of it.
///
/// The claim is substantiated the way this registry requires rather than by the
/// file being on disk, which was the specific mistake the entry used to make
/// while reading "the file does not exist" after the file had landed.
/// [`Engine::is_present`] means the build can EXECUTE the work, and the
/// evidence that it can is that the whole path from the C ABI to the emitted
/// bytes is closed: `curl_mime_init` reaches [`crate::mime::Mime`] through the
/// constructor the `const _:` line beside `ENGINES` pins, and the twelve
/// symbols are observable in the built artifact
/// (`nm -D --defined-only libcurl.so | grep curl_mime_` returns all twelve).
///
/// 48 fixtures gate on the label and now RUN rather than skip, which is the
/// direction AAP 0.6.5 makes costly if it is claimed early -- hence the
/// compile-time link, and hence `curl-rs`'s own admission list, which refuses
/// the row until it is named there too.
pub const ENGINE_MIME: Engine = Engine::working("curl-rs-lib/src/mime/mod.rs");

/// The legacy form API -- `curl-rs-lib/src/mime/formdata.rs`.
///
/// Gates the `form-api` row (`CURL_DISABLE_FORM_API`). Separate from
/// [`ENGINE_MIME`] because C guards it separately: `curl_formadd`,
/// `curl_formfree` and `curl_formget` are three of the 100 exported symbols
/// that AAP 0.8.2 forbids removing, and they can be disabled while
/// `curl_mime_*` stays.
///
/// INERT, not unwritten: `mime/formdata.rs` is 5,031 lines, and like
/// [`ENGINE_MIME`] it lacks both its C entry points and a body to serialise
/// into. 9 fixtures gate on the label and skip.
pub const ENGINE_FORM: Engine =
    Engine::inert("curl-rs-lib/src/mime/formdata.rs");

/// `.netrc` credential lookup -- `curl-rs-lib/src/cookies/netrc.rs`.
///
/// Gates the `netrc` row (`CURL_DISABLE_NETRC`). INERT, not unwritten:
/// `cookies/netrc.rs` is 3,216 lines and IS the file parser, matched against the
/// `lib/netrc.c` oracle. What `--netrc`, `--netrc-file` and `--netrc-optional`
/// lack is a transfer to supply credentials to. 1 fixture gates on the label and
/// skips.
pub const ENGINE_NETRC: Engine =
    Engine::inert("curl-rs-lib/src/cookies/netrc.rs");

/// Date parsing -- `curl-rs-lib/src/util/parsedate.rs`.
pub const ENGINE_PARSEDATE: Engine =
    Engine::working("curl-rs-lib/src/util/parsedate.rs");

/// The HTTP header API -- `curl-rs-lib/src/headers/mod.rs`.
///
/// Gates the `headers-api` row (`CURL_DISABLE_HEADERS_API`). `lib.rs` declares
/// `pub mod headers;` and AAP 0.4.1 maps it from `lib/headers.c` and
/// `lib/dynhds.c` as the backing for `curl_easy_header` and
/// `curl_easy_nextheader`.
///
/// INERT, not unwritten: `headers/mod.rs` is 3,208 lines and implements the
/// store and its lookup. What is missing is anything that FILLS it -- headers
/// enter the store as a response is received, and no response is received, so
/// `curl_easy_header` reads an empty store and `curl_easy_nextheader` returns
/// null on the first call. 14 fixtures gate on the label and skip.
pub const ENGINE_HEADERS: Engine =
    Engine::inert("curl-rs-lib/src/headers/mod.rs");

/// The multi handle -- `curl-rs-lib/src/multi/mod.rs`.
///
/// Gates the `wakeup` row, which C derives from `ENABLE_WAKEUP` in the internal
/// `multihandle.h` and which asks whether `curl_multi_wakeup` can interrupt a
/// blocking `curl_multi_poll`.
///
/// INERT -- and this entry is where the source-versus-wiring distinction was
/// first recorded, before it became a field. The reason once given here was
/// "`multi/state.rs` exists, but `multi/mod.rs` does not, so there is no handle
/// to hold the socketpair"; `multi/mod.rs` is 179 lines, declares
/// `pub(crate) mod state;` alongside `events` and `notify`, and owns
/// [`crate::multi::wakeup_available`] itself. What is missing is the HANDLE, not
/// its module: there is no handle type and no poll, and `curl_multi_wakeup` is
/// one of the exports of `lib/libcurl.def` still undefined -- measured,
/// `curl_multi_strerror` is the only one of the 22 `curl_multi_*` symbols
/// defined today.
///
/// This row is why [`supports_multi_wakeup`] is a conjunction, and it is the
/// clearest case in the registry for insisting on one. The two halves disagree:
/// the socketpair MECHANISM is genuinely available -- `wakeup_available()` is
/// `cfg!(unix)`, true on all four targets of AAP 0.8.3 -- while the function
/// that would use it does not exist. A row reading the mechanism alone would
/// therefore print `ON`, and the 2 fixtures gating on the label would RUN and
/// FAIL instead of skipping, which is exactly the over-report AAP 0.6.5 forbids.
/// Under-reporting is safe; this is the shape that keeps it under.
///
/// `CURLMcode::WakeupFailure` (`error.rs:784-785`) is not evidence either way:
/// it is the value returned when wakeup is unavailable.
///
/// What would clear this: not writing `multi/mod.rs`, which is written, but
/// defining `curl_multi_wakeup` and the poll it interrupts.
pub const ENGINE_MULTI: Engine = Engine::inert("curl-rs-lib/src/multi/mod.rs");

/// SHA-512/256 -- `curl-rs-lib/src/crypto/sha512_256.rs`.
pub const ENGINE_SHA512_256: Engine =
    Engine::working("curl-rs-lib/src/crypto/sha512_256.rs");

/// The generated public C header -- `curl-rs-ffi/src/ffi/easy.rs`.
///
/// Gates the `typecheck` row (`CURL_DISABLE_TYPECHECK`), the compile-time type
/// checking of `curl_easy_setopt`'s variadic argument.
///
/// The macros live in `include/curl/typecheck-gcc.h`, which AAP 0.6.3 keeps
/// hand-maintained because cbindgen cannot express it. Measured, that file is
/// 958 lines carrying **61** `#define curlcheck_` directives -- 60 distinct
/// names, since `curlcheck_cb_data` is defined twice: once at `:683` inside an
/// `#if 0`, and once at `:687` in the `#else /* be less strict */` branch that
/// is the one a compiler actually sees -- whose 260 occurrences span 258 lines.
/// The 258 is a LINE span and not a macro count; quoting it as one is the
/// mistake that keeping all three numbers together exists to prevent.
///
/// This comment is the single authority for those figures. Two other places
/// state them -- `curl-rs-ffi/cbindgen.toml` and the `NEVER_GENERATED` guard in
/// `curl-rs-ffi/build.rs` -- because each needs them where it stands, and
/// `.github/workflows/rust-abi.yml` deliberately quotes no count at all and
/// refers here instead, so the set of copies stays at the two that earn their
/// place.
///
/// Those five numbers are reproducible only with a name pattern that admits
/// uppercase, so the recipe is pinned here: match `#define\s+(curlcheck_\w+)`
/// anchored at line start. The narrower `curlcheck_[a-z_]*` truncates the two
/// uppercase names `curlcheck_NULL` and `curlcheck_FILE` to the bare prefix,
/// collides them into one, and reports 59 distinct rather than 60. That is worth
/// a sentence because the failure is silent and inverted: it makes a correct
/// count look like an off-by-one and invites "fixing" it downward.
///
/// INERT -- and this entry is the second place the source-versus-wiring
/// distinction was recorded before it became a field. The reason once given here
/// was "`curl-rs-ffi/src/lib.rs` declares `mod ffi` with no source, so
/// `ffi/easy.rs` ... does not exist"; `ffi/easy.rs` is 818 lines and `ffi/`
/// holds fifteen files. The real reason is downstream of that: the macros take
/// effect only when a C consumer includes `curl/curl.h`, this workspace must
/// GENERATE that header from `curl-rs-ffi`, and generation is REFUSED while 41
/// of the 100 exports in `lib/libcurl.def` are undefined -- `curl_easy_setopt`,
/// the function these macros exist to wrap, among them. So no header is
/// produced, the frozen C headers remain the ABI contract untouched, and there
/// is no checked call for the facility to protect.
///
/// The distinction matters for what would clear this: writing `ffi/easy.rs`
/// would not, because it is written. Completing the export surface would.
///
/// No fixture gates on the label.
pub const ENGINE_PUBLIC_HEADER: Engine =
    Engine::inert("curl-rs-ffi/src/ffi/easy.rs");

/// `--libcurl` source emission -- `curl-rs/src/libcurl_src.rs`.
///
/// Gates the `--libcurl` row (`CURL_DISABLE_LIBCURL_OPTION`), the flag that
/// writes a compilable C program reproducing the current invocation. UNWRITTEN,
/// and this is one of the three entries where that is literally true: AAP 0.3.1
/// and 0.4.1 both list the module (from `src/tool_easysrc.c`) and note that its
/// output "must remain valid C against the generated header", but the file does
/// not exist. 11 fixtures gate on the label and skip.
///
/// The owner is in `curl-rs`, not `curl-rs-lib`. That is deliberate and not
/// novel: [`ENGINE_GLOBAL_INIT`] already names a `curl-rs-ffi` path. This
/// registry records which AAP-mandated module exists anywhere in the
/// workspace, and keeping it single lets one table answer both
/// self-description surfaces instead of `curlinfo` keeping a second opinion.
pub const ENGINE_LIBCURL_SOURCE: Engine =
    Engine::unwritten("curl-rs/src/libcurl_src.rs");

/// Human-readable diagnostic text -- `curl-rs-lib/src/error.rs`.
///
/// Gates the `verbose-strings` row (`CURL_DISABLE_VERBOSE_STRINGS`), which in C
/// strips the message text out of `failf()` and `infof()` and shrinks the
/// binary. `error.rs` carries the complete `CURLcode` message set behind the
/// public `CURLcode::message`, `trace.rs` carries the `infof!`/`failf!` macros
/// with the `--trace` formats frozen, and no Cargo feature strips either, so
/// the row is unconditionally earned.
pub const ENGINE_DIAGNOSTIC_STRINGS: Engine =
    Engine::working("curl-rs-lib/src/error.rs");

/// Extended-attribute writing -- `curl-rs-lib/src/ffi/sys.rs`.
///
/// Gates the `xattr` row, which C derives from `USE_XATTR` -- defined when the
/// build finds an `fsetxattr` with either the five-argument Linux signature or
/// the six-argument macOS one (`src/tool_xattr.c:88-92`). **Present**: the safe
/// wrapper `crate::set_file_xattr` exists and selects between the two forms
/// itself, and `curl-rs/src/output/xattr.rs` issues the call.
///
/// Presence of the wrapper is necessary but not sufficient: the row must also
/// be on one of the two operating systems whose arm the wrapper compiles, which
/// is the `cfg` conjunct `curlinfo` applies on top of this entry. 3 fixtures
/// gate on the label and all three need a `<server>` this build does not
/// advertise, so they skip regardless.
pub const ENGINE_XATTR: Engine = Engine::working("curl-rs-lib/src/ffi/sys.rs");

/// Every engine in the registry, for auditing and for the tests.
pub const ENGINES: &[Engine] = &[
    ENGINE_IDN,
    ENGINE_DNS,
    ENGINE_CONN,
    ENGINE_TLS,
    ENGINE_PROXY,
    ENGINE_AUTH,
    ENGINE_GSS,
    ENGINE_STATE_STORES,
    ENGINE_CONTENT_ENCODING,
    ENGINE_PROTOCOLS,
    ENGINE_TRANSFER,
    ENGINE_GLOBAL_INIT,
    ENGINE_AUTH_BASIC,
    ENGINE_AUTH_BEARER,
    ENGINE_AUTH_DIGEST,
    ENGINE_AUTH_AWS_SIGV4,
    ENGINE_AUTH_DISPATCH,
    ENGINE_DOH,
    ENGINE_MIME,
    ENGINE_FORM,
    ENGINE_NETRC,
    ENGINE_PARSEDATE,
    ENGINE_HEADERS,
    ENGINE_MULTI,
    ENGINE_SHA512_256,
    ENGINE_PUBLIC_HEADER,
    ENGINE_LIBCURL_SOURCE,
    ENGINE_DIAGNOSTIC_STRINGS,
    ENGINE_XATTR,
];

// The compile-time links described in the block comment above: for every engine
// marked present, a reference to the item its owning module must export. This
// is what stops a `present: true` from outliving the implementation it claims.
// A later checkpoint that flips an entry to `present` adds its own line here in
// the same change, which is what `ENGINE_MIME`'s line below records.
//
// The count is deliberately NOT stated in this comment. It was, and the number
// went stale the moment an engine landed, which made the comment the least
// reliable thing in the file about its own subject.
// `every_present_engine_has_a_compile_time_link` asserts the SET instead, so
// the authority is the test and there is no second number to keep in step.
//
// One present engine has no line and cannot have one: `ENGINE_GLOBAL_INIT` is
// owned by `curl-rs-ffi`, which depends on this crate, so naming an item in it
// here would invert the dependency direction. That correspondence is asserted
// from the owning crate instead, and the test above records the exception
// explicitly rather than filtering it out.
//
// `ENGINE_XATTR`'s wrapper already has a signature contract pinned at
// `ffi/mod.rs:523`; the line here is not a duplicate of it but the registry's
// own half of the invariant.
const _: fn() -> bool = crate::url::idn::available;
const _: fn(crate::error::CURLcode) -> &'static str =
    crate::error::CURLcode::message;
const _: fn(std::os::fd::BorrowedFd<'_>, &[u8], &[u8]) -> std::io::Result<()> =
    crate::ffi::sys::set_file_xattr;
const _: fn() -> bool = crate::crypto::sha512_256::available;
const _: fn(&str) -> Option<i64> = crate::util::parsedate::getdate;
// `ENGINE_MIME`. The constructor rather than a leaf helper, because it is the
// item `curl_mime_init` enters the engine through: pinning it names the type
// AND the entry point, so neither the module disappearing nor the constructor
// being renamed can leave the `present` claim standing.
const _: fn() -> crate::error::CodeResult<crate::mime::Mime> =
    crate::mime::Mime::with_system_rng;

// Diagnostic capability predicates -- the authorities behind src/curlinfo.c
//
// These are NOT `--version` banner tokens and deliberately gain no row in the
// features table below: the two vocabularies are disjoint, and merging them
// would put names into `curl_version_info()->feature_names` that curl has
// never published there.

/// Whether this build can bind a transfer to a local endpoint.
///
/// # Examples
///
/// ```
/// assert!(curl_rs_lib::version::supports_bindlocal());
/// ```
#[must_use]
pub fn supports_bindlocal() -> bool {
    true
}

/// Whether this build honours `CURLOPT_DNS_SHUFFLE_ADDRESSES`.
///
/// # How the answer is computed
///
/// # Examples
///
/// ```
/// assert!(curl_rs_lib::version::supports_dns_shuffle());
/// ```
#[must_use]
pub fn supports_dns_shuffle() -> bool {
    true
}

/// Whether this build can write extended attributes on a saved file.
///
/// # How the answer is computed
///
/// Unlike the two predicates above, this one is not a `--disable-` switch at
/// all. `src/tool_xattr.h:28-36` derives `USE_XATTR` from a *platform* probe:
/// either a configure-detected `HAVE_FSETXATTR` (the `<sys/xattr.h>` route) or a
/// FreeBSD/MidnightBSD version macro selecting `extattr_set_fd`. The question is
/// therefore about the target, and it is delegated to the module that owns the
/// call: [`crate::ffi::sys::xattr_available`], which answers it with a
/// `cfg!(any(target_os = "linux", target_os = "macos"))` over the primitive
/// `curl-rs-lib/src/ffi/sys.rs` actually invokes.
///
/// # Examples
///
/// ```
/// // True on every target in the mandated matrix.
/// assert!(curl_rs_lib::version::supports_xattr());
/// ```
#[must_use]
pub fn supports_xattr() -> bool {
    crate::ffi::sys::xattr_available()
}

/// Whether this build provides the SHA-512/256 digest.
///
/// # How the answer is computed
///
/// `CURL_HAVE_SHA512_256` is defined at `lib/curl_sha512_256.h:28-32` under a
/// two-part condition -- `!defined(CURL_DISABLE_DIGEST_AUTH) &&
/// !defined(CURL_DISABLE_SHA512_256)` -- and this predicate is named after that
/// macro, so it carries BOTH halves. Carrying only the second would report
/// `true` on a build that cannot answer a `SHA-512-256` challenge at all.
///
/// The hash half is present and unconditional. `lib/curl_sha512_256.c` selects
/// among three arms -- OpenSSL at `:76`, GnuTLS at `:178`, and its own code at
/// `:245` under the comment "No system or TLS backend SHA-512/256
/// implementation available" -- so C always has an implementation, and so does
/// this crate: `crate::crypto::sha512_256` is a plain, non-optional module built
/// on the `sha2` pin of specification 0.5.1, and it is that module's `available`
/// predicate that answers rather than a literal written here.
///
/// The digest half is [`ENGINE_AUTH_DIGEST`], which stands for
/// `!CURL_DISABLE_DIGEST_AUTH`. It is what makes the answer `false` today:
/// `auth/digest.rs` is written but has no challenge to answer, so no
/// `SHA-512-256` digest is ever computed however good the hash is. Reporting the
/// hash alone would set `$feature{"sha512-256"}` in the harness and run 5
/// fixtures against a digest exchange that cannot happen -- the over-reporting
/// specification 0.6.5 calls fatal, where under-reporting merely skips.
///
/// # Examples
///
/// ```
/// // The hash is there; the digest that would use it is not, so the
/// // macro-equivalent answer is `false` -- as it would be in a C build
/// // configured with `CURL_DISABLE_DIGEST_AUTH`.
/// assert!(!curl_rs_lib::version::has_sha512_256());
/// ```
#[must_use]
pub fn has_sha512_256() -> bool {
    crate::crypto::sha512_256::available() && ENGINE_AUTH_DIGEST.is_present()
}

/// Whether `curl_multi_wakeup` can interrupt a blocked `curl_multi_poll`.
///
/// # Examples
///
/// ```
/// // The mechanism is there on this target; the multi handle is not.
/// assert!(curl_rs_lib::multi::wakeup_available());
/// assert!(!curl_rs_lib::version::supports_multi_wakeup());
/// ```
#[must_use]
pub fn supports_multi_wakeup() -> bool {
    crate::multi::wakeup_available() && ENGINE_MULTI.is_present()
}

/// Whether this build stores and sends cookies.
///
/// # Why the question belongs here and not to the caller
///
/// # Why the answer is a CONJUNCTION and not the feature alone
///
/// # Examples
///
/// ```
/// // The `cookies` feature is on by default, but `crate::cookies` is not yet
/// // written, so the capability is withheld. The predicate reports the
/// // conjunction, which is what keeps 51 fixtures skipping rather than
/// // failing.
/// assert!(!curl_rs_lib::version::supports_cookies());
/// ```
#[must_use]
pub const fn supports_cookies() -> bool {
    cfg!(feature = "cookies") && ENGINE_STATE_STORES.is_present()
}

/// Whether this build resolves names over DNS-over-HTTPS.
///
/// The authority for the `DoH: ` row of `src/curlinfo.c:98-103`, which prints
/// `OFF` from `#ifdef CURL_DISABLE_DOH`. Note the label's mixed casing: it is
/// part of the frozen contract.
///
/// Evaluated here rather than in the caller for exactly the reason given on
/// [`supports_cookies`], and a conjunction of THREE for the same reason: the
/// `doh` feature governs `crate::dns::doh` in this crate, a forwarded feature
/// can be enabled on this crate alone, and the module -- though written -- has
/// no transport to send a query over.
///
/// The third conjunct is the one that cannot be forgotten.
/// `crate::dns::doh_transport_registered` reports whether this build registers
/// a production `dns::DohTransport`, and it does not: every implementor in the
/// tree is a `#[cfg(test)]` double, because a real one needs an HTTPS transfer
/// and `protocols/http1.rs` does not exist. Reading the registry rather than
/// trusting `ENGINE_DOH`'s hand-chosen marker means the capability turns itself
/// on when a transport is registered and cannot be turned on before -- the
/// construction `crate::protocols`' `EXECUTORS` uses for scheme runnability.
/// Over-reporting here would make the harness run the DoH fixtures rather than
/// skip them (specification 0.6.5).
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_doh());
/// ```
#[must_use]
pub const fn supports_doh() -> bool {
    cfg!(feature = "doh")
        && ENGINE_DOH.is_present()
        && crate::dns::doh_transport_registered()
}

/// Whether this build can perform Negotiate (SPNEGO/Kerberos) authentication.
///
/// # Examples
///
/// ```
/// // Non-default feature, and no negotiate module: withheld twice over.
/// assert!(!curl_rs_lib::version::supports_negotiate());
/// ```
#[must_use]
pub const fn supports_negotiate() -> bool {
    cfg!(feature = "negotiate") && ENGINE_GSS.is_present()
}

/// Whether Negotiate is usable in THIS PROCESS, right now -- all three factors.
///
/// # Why the diagnostic surface needs this and not the weaker predicate
///
/// C does not need this distinction: its `src/curlinfo.c` row is a bare
/// `#ifdef`, because in C the library is found at build time. Under-reporting
/// is safe and over-reporting makes fixtures run and fail, so where the two
/// traditions differ this follows the asymmetry rather than the C source.
///
/// # Examples
///
/// ```
/// // Withheld three times over in a default build.
/// assert!(!curl_rs_lib::version::negotiate_usable());
/// ```
#[must_use]
pub fn negotiate_usable() -> bool {
    supports_negotiate() && gss_present()
}

/// Whether this build serves the `ftp` and `ftps` schemes.
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_ftp());
/// ```
#[must_use]
pub const fn supports_ftp() -> bool {
    cfg!(feature = "ftp") && ENGINE_PROTOCOLS.is_present()
}

/// Whether this build serves the `scp` and `sftp` schemes.
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_ssh());
/// ```
#[must_use]
pub const fn supports_ssh() -> bool {
    cfg!(feature = "ssh") && ENGINE_PROTOCOLS.is_present()
}

/// Whether this build serves the `ws` and `wss` schemes.
///
/// `wss` additionally needs [`supports_tls`]. The four exported `curl_ws_*`
/// symbols are a separate question -- they are ABI surface, and this is
/// capability -- so nothing here should be read as a statement about them.
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_websockets());
/// ```
#[must_use]
pub const fn supports_websockets() -> bool {
    cfg!(feature = "websockets") && ENGINE_PROTOCOLS.is_present()
}

/// Whether this build can complete a TLS handshake.
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_tls());
/// ```
#[must_use]
pub const fn supports_tls() -> bool {
    ENGINE_TLS.is_present()
}

/// Whether this build accounts for its own allocations.
///
/// # Examples
///
/// ```
/// // Follows the engine's `memdebug` feature, so the value depends on how the
/// // library was built and the example asserts no particular one. Note that
/// // `cfg!(feature = "memdebug")` would NOT work here: a doctest compiles as
/// // its own crate, so it would read that crate's (empty) feature set -- the
/// // same cross-crate mistake this whole family of predicates exists to avoid.
/// let _accounted = curl_rs_lib::version::supports_memdebug();
///
/// // What does NOT depend on the build: selecting allocation accounting must
/// // never advertise `Debug`. The harness derives `TrackMemory` from that
/// // token, and it stays withheld so the 28 `<limits>` fixtures go inert
/// // rather than fail.
/// assert!(!curl_rs_lib::version::has_feature("Debug"));
/// ```
#[must_use]
pub const fn supports_memdebug() -> bool {
    cfg!(feature = "memdebug")
}

/// Whether this build can decode a `Content-Encoding: gzip` or `deflate` body.
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_gzip());
/// ```
#[must_use]
pub const fn supports_gzip() -> bool {
    cfg!(feature = "gzip") && ENGINE_CONTENT_ENCODING.is_present()
}

/// Whether this build can decode a `Content-Encoding: br` body.
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_brotli());
/// ```
#[must_use]
pub const fn supports_brotli() -> bool {
    cfg!(feature = "brotli") && ENGINE_CONTENT_ENCODING.is_present()
}

/// Whether this build can decode a `Content-Encoding: zstd` body.
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_zstd());
/// ```
#[must_use]
pub const fn supports_zstd() -> bool {
    cfg!(feature = "zstd") && ENGINE_CONTENT_ENCODING.is_present()
}

/// Whether this build can negotiate and speak HTTP/2.
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_http2());
/// ```
#[must_use]
pub const fn supports_http2() -> bool {
    cfg!(feature = "http2")
        && ENGINE_PROTOCOLS.is_present()
        && ENGINE_TLS.is_present()
}

/// Whether this build can negotiate and speak HTTP/3.
///
/// # Examples
///
/// ```
/// assert!(!curl_rs_lib::version::supports_http3());
/// ```
#[must_use]
pub const fn supports_http3() -> bool {
    cfg!(feature = "http3")
        && ENGINE_PROTOCOLS.is_present()
        && ENGINE_TLS.is_present()
}

// The features table -- lib/version.c:435-554
//
// The C declaration this reproduces:
//
//   #define FEATURE(name, present, bitmask) { (name), (present), (bitmask) }
//
// Two things about the reproduction are deliberate and must not be "improved".

/// The width of `curl_off_t` in this implementation.
///
/// `curl_off_t` is 64-bit on every target in the mandated matrix, and Rust's
/// file and seek APIs are 64-bit on all of them, so the C condition
/// `(SIZEOF_CURL_OFF_T > 4) && ((SIZEOF_OFF_T > 4) || defined(_WIN32))`
/// (`lib/version.c:504`) is satisfied. The `Largefile` row derives from this
/// constant rather than asserting the answer, so the claim is computed from
/// the type that actually carries offsets.
pub const CURL_OFF_T_SIZE: usize = core::mem::size_of::<i64>();

// A compile-time floor rather than a runtime test. All four mandated targets
// are 64-bit, and that is load-bearing well beyond this banner: the varargs
// design for curl_easy_setopt carries a curl_off_t through one register-width
// slot, which is only sound where the offset type fits a register. If a 32-bit
// target is ever added, this stops the build here -- next to the `Largefile`
// claim it would invalidate -- instead of letting the claim quietly become
// false.
const _: () = assert!(
    CURL_OFF_T_SIZE > 4,
    "curl_off_t must be wider than 32 bits for the Largefile feature to hold"
);

/// One row of the features table: a name, an optional runtime predicate, and a
/// `CURL_VERSION_*` bit.
#[derive(Clone, Copy, Debug)]
pub struct Feature {
    /// The name as it appears in the `Features:` line. Casing is contractual.
    name: &'static str,

    /// The `CURL_VERSION_*` bit this name contributes, or `0` for the five
    /// names that have no bit.
    bitmask: i32,

    /// Whether this build compiles the capability in at all -- the C `#if`.
    compiled_in: bool,

    /// The C `present` function pointer; `None` is C's `NULL`, meaning
    /// "present whenever compiled in".
    present: Option<fn() -> bool>,
}

impl Feature {
    /// The contractual name, for example `"HTTPS-proxy"`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The `CURL_VERSION_*` bit, or `0` when the name carries none.
    #[must_use]
    pub const fn bitmask(&self) -> i32 {
        self.bitmask
    }

    /// Whether the capability is built into this binary at all.
    #[must_use]
    pub const fn compiled_in(&self) -> bool {
        self.compiled_in
    }

    /// Whether this build advertises the feature.
    ///
    /// Exactly the C selection rule from `lib/version.c:684-688`:
    /// `if(!p->present || p->present(&version_info))`, with the compile-time
    /// guard folded in ahead of it.
    #[must_use]
    pub fn is_present(&self) -> bool {
        self.compiled_in
            && match self.present {
                None => true,
                Some(predicate) => predicate(),
            }
    }
}

/// Equality over what identifies a row, deliberately excluding the predicate.
impl PartialEq for Feature {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.bitmask == other.bitmask
            && self.compiled_in == other.compiled_in
    }
}

impl Eq for Feature {}

/// Hashes the same three fields `PartialEq` compares, as `Hash`'s contract
/// requires: equal values must hash equally.
impl core::hash::Hash for Feature {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.bitmask.hash(state);
        self.compiled_in.hash(state);
    }
}

/// The 32 rows of `features_table[]` (`lib/version.c:450-554`), in C order.
///
/// Both the `Features:` name list and the `features` bitmask are projections
/// of this one table; see [`feature_names`] and [`features_bitmask`].
pub const FEATURES: &[Feature] = &[
    // HTTP Alt-Svc handling: crate::cookies::altsvc, via ENGINE_STATE_STORES.
    Feature {
        name: "alt-svc",
        bitmask: CURL_VERSION_ALTSVC,
        compiled_in: cfg!(feature = "altsvc")
            && ENGINE_STATE_STORES.is_present(),
        present: None,
    },
    // WITHHELD. C requires c-ares AND a threaded resolver AND HTTPSRR
    // (lib/version.c:454). c-ares is dropped for the system resolver, so the
    // conjunction cannot hold. The name also feeds tests/runtests.pl:702-712,
    // where it decides whether AsynchDNS still counts as "real" c-ares;
    // claiming it would corrupt that inference.
    Feature {
        name: "asyn-rr",
        bitmask: 0,
        compiled_in: false,
        present: None,
    },
    // The resolver is genuinely asynchronous: crate::dns::resolver runs
    // lookups on the tokio runtime, and the alarm()/sigsetjmp() deadline of
    // lib/hostip.c is replaced by tokio::time::timeout. The
    // harness reads this name and, seeing no c-ares token in the banner, sets
    // threaded-resolver and resolver="threaded" (tests/runtests.pl:702-712) --
    // which is an accurate description of a runtime that resolves off the
    // calling task.
    Feature {
        name: "AsynchDNS",
        bitmask: CURL_VERSION_ASYNCHDNS,
        compiled_in: ENGINE_DNS.is_present(),
        present: None,
    },
    // Brotli decoding: crate::transfer::content_encoding via the brotli crate,
    // gated on ENGINE_CONTENT_ENCODING.
    Feature {
        name: "brotli",
        bitmask: CURL_VERSION_BROTLI,
        compiled_in: supports_brotli(),
        present: None,
    },
    // WITHHELD, DELIBERATELY, AND NEVER GATED ON ANY FEATURE.
    // A literal `false`, not `cfg!(feature = "memdebug")`: memdebug supplies
    // only the allocation log that tests/memanalyzer.pm parses, whereas a C
    // DEBUGBUILD also changes internal behaviour that the 98 Debug-gated
    // fixtures exercise. Because tests/runtests.pl:658-660 derives both
    // TrackMemory and Debug from this single name, advertising it would switch
    // on allocation-cap and leak checking AND make those 98 fixtures run --
    // exactly the over-reporting to avoid. Cost of withholding, stated:
    // 98 fixtures skip and `make torture-test` is inapplicable, since it dies
    // without TrackMemory (tests/runtests.pl:846-849).
    Feature {
        name: "Debug",
        bitmask: CURL_VERSION_DEBUG,
        compiled_in: false,
        present: None,
    },
    // Encrypted Client Hello. The row is compiled in because TLS is, and the
    // C `#ifdef USE_ECH` guard lives inside the predicate instead: there is no
    // ECH build switch in this crate, so the capability is entirely the TLS
    // backend's to report. Currently false; see tls_supports_ech().
    Feature {
        name: "ECH",
        bitmask: 0,
        compiled_in: ENGINE_TLS.is_present(),
        present: Some(tls_supports_ech),
    },
    // WITHHELD. libgsasl is dropped along with the SASL protocols it served;
    // SMTP, IMAP and POP3 are out of scope entirely.
    Feature {
        name: "gsasl",
        bitmask: CURL_VERSION_GSASL,
        compiled_in: false,
        present: None,
    },
    // GSS-API, behind the non-default `negotiate` feature, whose binding is
    // confined to crate::ffi::gss. Off by default, so the
    // default build links no C security library at all.
    Feature {
        name: "GSS-API",
        bitmask: CURL_VERSION_GSSAPI,
        compiled_in: supports_negotiate(),
        present: Some(gss_present),
    },
    // HTTP Strict Transport Security: crate::cookies::hsts, via
    // ENGINE_STATE_STORES.
    Feature {
        name: "HSTS",
        bitmask: CURL_VERSION_HSTS,
        compiled_in: cfg!(feature = "hsts") && ENGINE_STATE_STORES.is_present(),
        present: None,
    },
    // HTTP/2 over ALPN: crate::protocols::http2 via the h2 crate. ALPN is
    // negotiated by rustls, so the claim needs both engines.
    Feature {
        name: "HTTP2",
        bitmask: CURL_VERSION_HTTP2,
        compiled_in: supports_http2(),
        present: None,
    },
    // HTTP/3 over QUIC: crate::protocols::http3 via quinn and h3. QUIC carries
    // its own TLS handshake, so this needs the TLS engine too.
    Feature {
        name: "HTTP3",
        bitmask: CURL_VERSION_HTTP3,
        compiled_in: supports_http3(),
        present: None,
    },
    // Tunnelling through an HTTPS proxy. TWO engines, because the capability
    // needs a proxy to tunnel through as well as the TLS to wrap it in: TLS is
    // unconditional here, so ENGINE_PROXY is what withholds the name today.
    // The residual capability question -- can the backend do it at all -- is
    // delegated to the backend exactly as C delegates it
    // (lib/version.c:420-424). Naming only the conjunct that holds -- the
    // unconditional TLS -- would imply the row is ON, which it is not.
    Feature {
        name: "HTTPS-proxy",
        bitmask: CURL_VERSION_HTTPS_PROXY,
        compiled_in: ENGINE_PROXY.is_present() && ENGINE_TLS.is_present(),
        present: Some(tls_supports_https_proxy),
    },
    // WITHHELD. The C reference build does enable HTTPS resource records by
    // default (configure.ac:4993-4997), but this crate has no feature to key
    // on and this module cannot verify that crate::dns::httpsrr is functional.
    // Measured cost of withholding: zero fixtures gate on the name.
    Feature {
        name: "HTTPSRR",
        bitmask: 0,
        compiled_in: false,
        present: None,
    },
    // Internationalized domain names via the idna crate, replacing libidn2.
    // The predicate is the IDN module's OWN, not a copy of it: crate::url::idn
    // implements the capability and therefore reports it, which is the single
    // source of truth this row previously duplicated.
    Feature {
        name: "IDN",
        bitmask: CURL_VERSION_IDN,
        compiled_in: ENGINE_IDN.is_present(),
        present: Some(crate::url::idn::available),
    },
    // IPv6 is unconditional: crate::conn uses socket2 and tokio, both of which
    // support IPv6 on every target in the matrix, and crate::conn::happy_
    // eyeballs races the two families against each other.
    Feature {
        name: "IPv6",
        bitmask: CURL_VERSION_IPV6,
        compiled_in: ENGINE_CONN.is_present(),
        present: None,
    },
    // Kerberos V5, reachable only through GSS-API, so gated identically -- both
    // halves. C's guard is `#ifdef USE_KERBEROS5` (lib/version.c:501-502), and
    // lib/curl_setup.h:759-762 defines that as HAVE_GSSAPI || USE_WINDOWS_SSPI;
    // SSPI is out of scope, so the two rows share one condition and therefore
    // one predicate.
    Feature {
        name: "Kerberos",
        bitmask: CURL_VERSION_KERBEROS5,
        compiled_in: supports_negotiate(),
        present: Some(gss_present),
    },
    // Transfers larger than 2GB; derived from the width of curl_off_t.
    Feature {
        name: "Largefile",
        bitmask: CURL_VERSION_LARGEFILE,
        compiled_in: CURL_OFF_T_SIZE > 4,
        present: None,
    },
    // gzip and deflate. The name stays "libz" because it is contractual --
    // tests/runtests.pl:673-674 matches /libz/i -- even though the
    // implementation is flate2's pure-Rust backend rather than zlib.
    Feature {
        name: "libz",
        bitmask: CURL_VERSION_LIBZ,
        compiled_in: supports_gzip(),
        present: None,
    },
    // WITHHELD, UNCONDITIONALLY. There is exactly one TLS backend and no other
    // is permitted, so multiple-backend selection does not exist here.
    // tests/runtests.pl:663 matches /MultiSSL/i separately from /SSL/i, so a
    // false positive would mislead the harness rather than merely overstate.
    Feature {
        name: "MultiSSL",
        bitmask: CURL_VERSION_MULTI_SSL,
        compiled_in: false,
        present: None,
    },
    // NTLM in pure Rust: crate::auth::ntlm over des, md4, md-5 and hmac, all
    // of them plain non-optional dependencies of this crate. 53 fixtures gate
    // on the name.
    Feature {
        name: "NTLM",
        bitmask: CURL_VERSION_NTLM,
        compiled_in: ENGINE_AUTH.is_present(),
        present: None,
    },
    // The Public Suffix List, used for cookie-domain verification. Gated on
    // `cookies` because that is the feature which pulls in publicsuffix; there
    // is no separate switch, and a PSL with no cookie jar to guard would be
    // advertising a capability with nothing to apply it to.
    Feature {
        name: "PSL",
        bitmask: CURL_VERSION_PSL,
        compiled_in: supports_cookies(),
        present: None,
    },
    // WITHHELD. Out of alphabetical order here because C is; see the block
    // comment above. AppleSecTrust and NativeCA are mutually exclusive
    // alternatives in C (lib/version.c:519-525) describing which native trust
    // store supplies the default CA set. This build carries both webpki-roots
    // (a compiled-in anchor set) and rustls-native-certs (platform access),
    // and which one crate::tls::verify makes the default is not fixed by
    // anything this module can read. Neither name is parsed by the harness, so
    // omission costs nothing and asserting either would be a guess.
    Feature {
        name: "AppleSecTrust",
        bitmask: 0,
        compiled_in: false,
        present: None,
    },
    // WITHHELD, for the same reason as AppleSecTrust immediately above.
    Feature {
        name: "NativeCA",
        bitmask: 0,
        compiled_in: false,
        present: None,
    },
    // SPNEGO, reachable only through GSS-API, so gated identically -- both
    // halves. C's guard is `#ifdef USE_SPNEGO` (lib/version.c:526-527), which
    // lib/curl_setup.h:752-756 defines as HAVE_GSSAPI || USE_WINDOWS_SSPI; SSPI
    // is out of scope, so this shares GSS-API's single condition and predicate.
    Feature {
        name: "SPNEGO",
        bitmask: CURL_VERSION_SPNEGO,
        compiled_in: supports_negotiate(),
        present: Some(gss_present),
    },
    // TLS. Unconditional: rustls is a plain dependency of this crate, and
    // certificate validation is on by default. 138 fixtures gate
    // on this name, and tests/runtests.pl:662 reads it from the Features line
    // rather than from the banner token -- which is what makes the accurate
    // rustls token affordable.
    Feature {
        name: "SSL",
        bitmask: CURL_VERSION_SSL,
        compiled_in: ENGINE_TLS.is_present(),
        present: None,
    },
    // WITHHELD. TLS session import and export is off by default in the
    // reference build too (CMakeLists.txt:1076 defines the option as OFF, and
    // the docs call it experimental: docs/cmdline-opts/ssl-sessions.md:39).
    // There is no Cargo feature for it and this module cannot verify that
    // crate::tls::session_cache implements the serialization, so parity with
    // the reference default and honesty coincide. Not parsed by the harness.
    Feature {
        name: "SSLS-EXPORT",
        bitmask: 0,
        compiled_in: false,
        present: None,
    },
    // WITHHELD, UNCONDITIONALLY. Windows SSPI does not exist on any target in
    // the matrix and no Windows security library is linked. 114 fixtures
    // require the name's ABSENCE (`!SSPI`), which this build satisfies
    // naturally -- so this row being false is load-bearing in the positive
    // direction too.
    Feature {
        name: "SSPI",
        bitmask: CURL_VERSION_SSPI,
        compiled_in: false,
        present: None,
    },
    // The API is thread-safe, and the basis is synchronization rather than an
    // absence of shared state. The engine does hold process-global state, but
    // every item of it is immutable, initialised once through a `OnceLock`,
    // atomic, or behind a `Mutex`: the banner, the feature and protocol name
    // vectors and the host string in this module; the memdebug allocation
    // budget (`AtomicI64`), its armed flag (`AtomicBool`) and its log
    // destination (`OnceLock<Option<Mutex<_>>>`) in `crate::ffi::sys`; the
    // availability probe in `crate::ffi::gss`. There is no `static mut` and no
    // unsynchronised interior mutability in a shared static anywhere in the
    // crate -- the one `Cell` is `thread_local!` and so is not shared at all --
    // and each of those initialisers is idempotent, so a second concurrent
    // caller observes the first one's value rather than racing it. That is what
    // satisfies the C GLOBAL_INIT_IS_THREADSAFE condition
    // (lib/version.c:538).
    Feature {
        name: "threadsafe",
        bitmask: CURL_VERSION_THREADSAFE,
        compiled_in: ENGINE_GLOBAL_INIT.is_present(),
        present: None,
    },
    // WITHHELD. TLS-SRP is not implemented: rustls provides no SRP key
    // exchange and crate::tls exposes no --tlsauthtype handling. Five fixtures
    // gate on the name and will skip.
    Feature {
        name: "TLS-SRP",
        bitmask: CURL_VERSION_TLSAUTH_SRP,
        compiled_in: false,
        present: None,
    },
    // WITHHELD. The C row requires _WIN32 with both UNICODE and _UNICODE
    // (lib/version.c:544); no target in the matrix is Windows.
    Feature {
        name: "Unicode",
        bitmask: CURL_VERSION_UNICODE,
        compiled_in: false,
        present: None,
    },
    // Unix domain sockets, for --unix-socket and --abstract-unix-socket.
    // Available on every Unix target, which is all four of the mandated ones;
    // the cfg keeps the claim correct if the crate is ever built elsewhere.
    Feature {
        name: "UnixSockets",
        bitmask: CURL_VERSION_UNIX_SOCKETS,
        compiled_in: cfg!(unix) && ENGINE_CONN.is_present(),
        present: None,
    },
    // Zstandard decoding: crate::transfer::content_encoding via the zstd crate,
    // gated on ENGINE_CONTENT_ENCODING.
    Feature {
        name: "zstd",
        bitmask: CURL_VERSION_ZSTD,
        compiled_in: supports_zstd(),
        present: None,
    },
];

/// The names this build advertises, in C table order.
#[must_use]
pub fn feature_names() -> &'static [&'static str] {
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();

    NAMES
        .get_or_init(|| {
            FEATURES
                .iter()
                .filter(|feature| feature.is_present())
                .map(Feature::name)
                .collect()
        })
        .as_slice()
}

/// The `features` bitmask, built from the same rows as [`feature_names`].
///
/// The C code additionally ORs in `CURL_VERSION_CURLDEBUG` under `DEBUGBUILD`
/// "for compatibility" (`lib/version.c:690-692`). That bit is deliberately
/// absent here: no `Debug` capability is advertised, so claiming its companion
/// bit would contradict the name list.
#[must_use]
pub fn features_bitmask() -> i32 {
    FEATURES
        .iter()
        .filter(|feature| feature.is_present())
        .fold(0, |mask, feature| mask | feature.bitmask())
}

/// Whether a named feature is advertised, compared case-sensitively.
#[must_use]
pub fn has_feature(name: &str) -> bool {
    feature(name).is_some_and(Feature::is_present)
}

/// The row for a name, whether or not this build advertises it.
///
/// Useful to a caller that needs to distinguish "not advertised" from "not a
/// feature name at all" -- the command-line tool's `--version` handling makes
/// exactly that distinction when it maps names onto its own booleans
/// (`src/tool_libinfo.c:84-125`).
#[must_use]
pub fn feature(name: &str) -> Option<&'static Feature> {
    FEATURES.iter().find(|feature| feature.name() == name)
}

// The protocol table -- lib/version.c:296-397

/// One row of `supported_protocols[]`: a scheme name and whether it is built in.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Protocol {
    /// The scheme name, lower case, as the banner spells it.
    name: &'static str,

    /// Whether this build serves the scheme.
    compiled_in: bool,
}

impl Protocol {
    /// The scheme name, lower case.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Whether this build serves the scheme.
    #[must_use]
    pub const fn compiled_in(&self) -> bool {
        self.compiled_in
    }
}

/// The nine schemes AAP 0.2.1 puts in scope, in `supported_protocols[]` order
/// -- lower case, alphabetically sorted.
///
/// A row here is scope, NOT a capability claim: what this build advertises is
/// the subset whose `compiled_in` is true, and today that subset is empty. The
/// rows stay in place while withheld so the table remains diffable 1:1 against
/// C's `supported_protocols[]`.
///
/// Every row requires [`ENGINE_PROTOCOLS`], because a scheme with no module to
/// implement it cannot be served whatever its Cargo feature says. The three
/// `s`-suffixed schemes additionally require [`ENGINE_TLS`], which reproduces
/// the C guard `#if defined(USE_SSL) && ...` faithfully -- the earlier reading
/// that "TLS is unconditional in this crate, so the gate collapses" held only
/// while TLS presence was assumed rather than checked.
///
/// While neither engine can execute, this slice contributes nothing to
/// [`protocols`], and that is deliberate; see [`ENGINE_PROTOCOLS`] for what an
/// empty `Protocols:` line means to the harness and why it is the correct
/// report.
pub const PROTOCOLS: &[Protocol] = &[
    // crate::protocols::file. In scope despite being trivial: 27 fixtures
    // depend on the scheme. Needs no TLS and no socket, but it still needs a
    // scheme registry to be dispatched through.
    Protocol {
        name: "file",
        compiled_in: ENGINE_PROTOCOLS.is_present(),
    },
    Protocol {
        name: "ftp",
        compiled_in: cfg!(feature = "ftp") && ENGINE_PROTOCOLS.is_present(),
    },
    Protocol {
        name: "ftps",
        compiled_in: cfg!(feature = "ftp")
            && ENGINE_PROTOCOLS.is_present()
            && ENGINE_TLS.is_present(),
    },
    // HTTP carries no Cargo feature: it is the engine's core protocol and
    // everything from WebSocket to DoH to CONNECT proxying is layered over it.
    // Its claim is therefore exactly the protocol engine's presence.
    Protocol {
        name: "http",
        compiled_in: ENGINE_PROTOCOLS.is_present(),
    },
    Protocol {
        name: "https",
        compiled_in: ENGINE_PROTOCOLS.is_present() && ENGINE_TLS.is_present(),
    },
    Protocol {
        name: "scp",
        compiled_in: cfg!(feature = "ssh") && ENGINE_PROTOCOLS.is_present(),
    },
    Protocol {
        name: "sftp",
        compiled_in: cfg!(feature = "ssh") && ENGINE_PROTOCOLS.is_present(),
    },
    // WebSocket relies on HTTP, exactly as the C table's nesting records
    // (lib/version.c:386-394).
    Protocol {
        name: "ws",
        compiled_in: cfg!(feature = "websockets")
            && ENGINE_PROTOCOLS.is_present(),
    },
    Protocol {
        name: "wss",
        compiled_in: cfg!(feature = "websockets")
            && ENGINE_PROTOCOLS.is_present()
            && ENGINE_TLS.is_present(),
    },
];

/// The scheme names this build advertises, lower case and sorted.
///
/// The command-line tool walks this array to count protocols and to recognise
/// the ones it has flags for (`src/tool_libinfo.c:135-155`), so it must never
/// contain a scheme the engine cannot serve -- a request for an unadvertised
/// scheme returns `CURLE_UNSUPPORTED_PROTOCOL`, and advertising one would turn
/// a clean skip into a failure for the 283 fixtures that target the schemes
/// this implementation does not serve.
#[must_use]
pub fn protocols() -> &'static [&'static str] {
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();

    NAMES
        .get_or_init(|| {
            PROTOCOLS
                .iter()
                .filter(|protocol| protocol.compiled_in())
                .map(Protocol::name)
                .collect()
        })
        .as_slice()
}

/// Whether a scheme is advertised, compared without regard to case.
#[must_use]
pub fn supports_protocol(scheme: &str) -> bool {
    protocols()
        .iter()
        .any(|advertised| advertised.eq_ignore_ascii_case(scheme))
}

// The banner -- curl_version(), lib/version.c:143-294

/// `VERSION_PARTS` -- the number of substrings the C implementation can
/// concatenate (`lib/version.c:143`).
pub const VERSION_PARTS: usize = 16;

/// The size of the C implementation's output buffer, `static char out[300]`
/// (`lib/version.c:147`).
///
/// Reproduced because the join below reproduces the C truncation rule that
/// depends on it. A caller of the C function can rely on the result being at
/// most 299 bytes plus a terminator, and that remains true here.
pub const VERSION_BUFFER_SIZE: usize = 300;

/// The banner's first part: `libcurl/8.19.0-DEV` (`lib/version.c:205`).
const LIBCURL_TOKEN: &str =
    concat!(libcurl_name_literal!(), "/", libcurl_version_literal!());

/// The banner's parts, in the order `lib/version.c:205-271` appends them.
///
/// The C sequence has fifteen slots; this build fills seven to eleven of them
/// depending on features, and the slots it cannot fill truthfully are
/// documented at their tokens rather than filled with invented values:
///
/// | C slot | Source | Here |
/// |--------|--------|------|
/// | 1 | `LIBCURL_NAME "/" LIBCURL_VERSION` | always |
/// | 2 | `Curl_ssl_version()` | always, [`SSL_VERSION`] |
/// | 3 | `zlib/...` | `flate2/...`, feature `gzip` |
/// | 4 | `brotli/...` | feature `brotli` |
/// | 5 | `zstd/...` | feature `zstd` |
/// | 6 | `c-ares/...` | `hickory-resolver/...`, feature `hickory-dns` (off) |
/// | 7 | `libidn2/...` | `idna/...`, always |
/// | 8 | `libpsl/...` | `publicsuffix/...`, feature `cookies` |
/// | 9 | `libssh2/...` | `russh/...`, feature `ssh` |
/// | 10 | `nghttp2/...` | `h2/...`, feature `http2` |
/// | 11 | `Curl_quic_ver()` | `quinn/... h3/...`, feature `http3` |
/// | 12 | `librtmp/...` | never; RTMP is out of scope |
/// | 13 | `libgsasl/...` | never; libgsasl is dropped |
/// | 14 | `mit-krb5/...` | never; see the library-tokens block |
/// | 15 | `Curl_ldap_version()` | never; LDAP is out of scope |
#[must_use]
pub fn version_parts() -> Vec<&'static str> {
    let mut parts: Vec<&'static str> = Vec::with_capacity(VERSION_PARTS);

    parts.push(LIBCURL_TOKEN);

    // Slot 2, the TLS token, gated exactly as `lib/version.c:206-209` gates it:
    //
    //     src[i++] = LIBCURL_NAME "/" LIBCURL_VERSION;
    //     #ifdef USE_SSL
    //       Curl_ssl_version(ssl_version, sizeof(ssl_version));
    //       src[i++] = ssl_version;
    //     #endif
    //
    // So C emits no TLS token at all when no backend is compiled in -- the same
    // structure it uses for `HAVE_LIBZ` and `HAVE_BROTLI` below. Pushing this
    // unconditionally reproduces the brotli/zstd defect one slot higher up: the
    // banner announces `rustls/0.23.42` while the
    // `Features:` line withholds `SSL`, because that row asks
    // [`ENGINE_TLS`]. Measured, the cost at the harness was zero -- `SSL` comes
    // from the `Features:` line (`tests/runtests.pl:664`) and
    // `$feature{"rustls"}` needs the literal `rustls-ffi` (`:585-586`), neither
    // of which reads this slot -- but a token that says this build does TLS when
    // it cannot is untrue whatever it costs, and specification 0.6.5 makes
    // under-reporting the only safe error.
    //
    // rustls IS linked and `tls/mod.rs` IS written; neither is the claim. The
    // claim a reader takes from this slot is "this build does TLS, with
    // rustls", and no connected socket ever reaches the handshake, so it
    // cannot.
    if supports_tls() {
        parts.push(SSL_VERSION);
    }

    // Every token below is gated on `configured && implementation_ready`, the
    // same conjunction the two tables use, and by calling the SAME predicate
    // they call rather than restating it.
    if supports_gzip() {
        parts.push(LIBZ_TOKEN);
    }
    if supports_brotli() {
        parts.push(BROTLI_TOKEN);
    }
    if supports_zstd() {
        parts.push(ZSTD_TOKEN);
    }

    // Slot 6 in the C ordering, where `lib/version.c` emits `c-ares/...`. The
    // default build resolves with the system resolver and emits nothing here.
    if resolver_token_is_earned() {
        parts.push(RESOLVER_TOKEN);
    }

    // `lib/version.c:227-229` puts this behind `#ifdef USE_IDN`, so it is
    // conditional in C too. The authority is the implementing module's own
    // predicate -- the same one the `IDN` row consults as its `present` function
    // -- rather than a second opinion written here. That rule governs the
    // banner as well as the table. True today, so the token is
    // emitted; derived, so it cannot outlive the module.
    if crate::url::idn::available() {
        parts.push(IDN_TOKEN);
    }

    if supports_cookies() {
        parts.push(PSL_TOKEN);
    }
    if supports_ssh() {
        parts.push(SSH_TOKEN);
    }
    if supports_http2() {
        parts.push(HTTP2_TOKEN);
    }
    if supports_http3() {
        parts.push(HTTP3_TOKEN);
    }

    debug_assert!(
        parts.len() <= VERSION_PARTS,
        "curl_version() may concatenate at most {VERSION_PARTS} parts"
    );

    parts
}

/// `curl_version()` -- the space-separated library banner.
///
/// For example, on a default build:
///
/// ```text
/// libcurl/8.19.0-DEV rustls/0.23.42 flate2/1.1.9 brotli/8.0.4 zstd/0.13.3 \
/// idna/1.1.0 publicsuffix/2.3.0 russh/0.54.5 h2/0.4.15 quinn/0.11.9 h3/0.0.8
/// ```
///
/// The C function's contract is that it "is implemented to work multi-threaded
/// by making sure repeated invokes generate the exact same string and never
/// write any temporary data like zeros in the data" (`lib/version.c:136-141`).
/// A [`OnceLock`] delivers that by construction: the string is built at most
/// once, is never mutated afterwards, and the returned `&'static str` stays
/// valid for the process lifetime -- which is what lets `curl-rs-ffi` hand out a
/// pointer into it.
#[must_use]
pub fn version() -> &'static str {
    static BANNER: OnceLock<String> = OnceLock::new();

    BANNER
        .get_or_init(|| {
            let parts = version_parts();
            let mut banner = String::with_capacity(VERSION_BUFFER_SIZE);

            // `remaining` tracks exactly what the C `outlen` tracks: the bytes
            // still available in `out[]`, terminator included. The C test is
            // `if(outlen <= (n + 2)) break;` -- room for the string, a
            // separator and the trailing zero.
            let mut remaining = VERSION_BUFFER_SIZE;

            for (index, part) in parts.iter().take(VERSION_PARTS).enumerate() {
                let length = part.len();
                if remaining <= length + 2 {
                    break;
                }
                if index > 0 {
                    banner.push(' ');
                    remaining -= 1;
                }
                banner.push_str(part);
                remaining -= length;
            }

            banner
        })
        .as_str()
}

// The curl_version_info() payload -- include/curl/curl.h:3111-3171

/// Extracts `(major, minor, patch)` from a `name/major.minor.patch` token.
fn version_components(token: &str) -> Option<(u32, u32, u32)> {
    // Take everything after the last '/' so that a token naming a path-like
    // library still parses; for "brotli/8.0.4" this is "8.0.4".
    let version = token.rsplit('/').next()?;

    let mut components = version.split('.');
    let major = leading_number(components.next()?)?;
    let minor = leading_number(components.next()?)?;
    let patch = leading_number(components.next()?)?;

    // A fourth component would mean this is not a semantic version and the
    // packed encodings below would be meaningless.
    if components.next().is_some() {
        return None;
    }

    Some((major, minor, patch))
}

/// Parses the leading decimal digits of `text`, ignoring any suffix.
///
/// Pre-release and build suffixes are common in crate versions (`1.0.0-rc.2`),
/// and the packed encodings have no room for them, so the numeric prefix is
/// what gets encoded -- the same lossy-but-monotonic treatment the C macros
/// give a library version. Returns `None` when there are no leading digits.
fn leading_number(text: &str) -> Option<u32> {
    let digits = text
        .as_bytes()
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();

    text.get(..digits)?.parse().ok()
}

/// `curl_version_info_data` -- everything `curl_version_info()` reports.
///
/// The field order is transcribed from `include/curl/curl.h:3111-3171` and is
/// itself part of the ABI: a caller compiled against an older header reads
/// only the prefix of the struct that its own [`CURLversion`] covers, so no
/// field may be reordered or removed, only appended. The comments below record
/// which age introduced each group.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct VersionInfo {
    /// `age` -- which generation of this struct is populated.
    pub age: CURLversion,

    /// `version` -- [`LIBCURL_VERSION`].
    pub version: &'static str,

    /// `version_num` -- [`LIBCURL_VERSION_NUM`].
    pub version_num: u32,

    /// `host` -- the `cpu-vendor-os[-env]` triple; see [`host`].
    pub host: &'static str,

    /// `features` -- the bitmask; see [`features_bitmask`].
    pub features: i32,

    /// `ssl_version` -- human-readable TLS backend and version.
    pub ssl_version: Option<&'static str>,

    /// `ssl_version_num` -- "not used anymore, always 0"
    /// (`include/curl/curl.h:3117`). Reproduced as a zero, not omitted: the
    /// field still occupies its slot in the C layout.
    pub ssl_version_num: i64,

    /// `libz_version` -- always `None` here.
    pub libz_version: Option<&'static str>,

    /// `protocols` -- the advertised schemes; see [`protocols`].
    pub protocols: &'static [&'static str],

    // ---- CURLVERSION_SECOND ----
    /// `ares` -- always `None`: c-ares is replaced by the system resolver.
    pub ares: Option<&'static str>,

    /// `ares_num` -- always `0`, for the same reason.
    pub ares_num: i32,

    // ---- CURLVERSION_THIRD ----
    /// `libidn` -- always `None`: the IDN implementation is `idna`, not libidn2.
    pub libidn: Option<&'static str>,

    // ---- CURLVERSION_FOURTH ----
    /// `iconv_ver_num` -- always `0`: no iconv is used.
    pub iconv_ver_num: i32,

    /// `libssh_version` -- always `None`.
    ///
    /// The field names libssh or libssh2, and neither is linked; SSH is
    /// provided by `russh`, which the banner reports. Reporting a russh version
    /// through a field named after another library would misdescribe the build.
    pub libssh_version: Option<&'static str>,

    // ---- CURLVERSION_FIFTH ----
    /// `brotli_ver_num` -- `(MAJOR << 24) | (MINOR << 12) | PATCH`, or `0`.
    pub brotli_ver_num: u32,

    /// `brotli_version` -- the prefixed token, matching the C shape, where
    /// `brotli_version()` writes `"brotli/%u.%u.%u"` (`lib/version.c:83-90`).
    pub brotli_version: Option<&'static str>,

    // ---- CURLVERSION_SIXTH ----
    /// `nghttp2_ver_num` -- always `0`: nghttp2 is replaced by `h2`.
    pub nghttp2_ver_num: u32,

    /// `nghttp2_version` -- always `None`, for the same reason. The HTTP/2
    /// implementation is reported by the banner's `h2/...` part.
    pub nghttp2_version: Option<&'static str>,

    /// `quic_version` -- the QUIC and HTTP/3 libraries, or `None`.
    pub quic_version: Option<&'static str>,

    // ---- CURLVERSION_SEVENTH ----
    /// `cainfo` -- the built-in default for `CURLOPT_CAINFO`; `None` here.
    pub cainfo: Option<&'static str>,

    /// `capath` -- the built-in default for `CURLOPT_CAPATH`; `None`, as above.
    pub capath: Option<&'static str>,

    // ---- CURLVERSION_EIGHTH ----
    /// `zstd_ver_num` -- `(MAJOR << 24) | (MINOR << 12) | PATCH`, or `0`.
    pub zstd_ver_num: u32,

    /// `zstd_version` -- the prefixed token, matching the C shape, where
    /// `zstd_version()` writes `"zstd/%u.%u.%u"` (`lib/version.c:93-101`).
    pub zstd_version: Option<&'static str>,

    // ---- CURLVERSION_NINTH ----
    /// `hyper_version` -- `hyper/1.11.0`.
    ///
    /// The one field this build populates where the C tree leaves `NULL`, and
    /// it is populated because it is true: hyper handles HTTP/1.1 connection
    /// management, keep-alive and framing here. See `HYPER_TOKEN`'s
    /// documentation for why the choice is harness-neutral.
    pub hyper_version: Option<&'static str>,

    // ---- CURLVERSION_TENTH ----
    /// `gsasl_version` -- always `None`: libgsasl is dropped.
    pub gsasl_version: Option<&'static str>,

    // ---- CURLVERSION_ELEVENTH ----
    /// `feature_names` -- the advertised names; see [`feature_names`].
    pub feature_names: &'static [&'static str],

    // ---- CURLVERSION_TWELFTH ----
    /// `rtmp_version` -- always `None`: RTMP is out of scope.
    pub rtmp_version: Option<&'static str>,
}

/// `curl_version_info()` -- the whole payload, built once.
///
/// The C function ignores its `CURLversion stamp` argument entirely
/// (`(void)stamp;`, `lib/version.c:619`) and always returns the current
/// struct, so this takes none. `curl-rs-ffi` accepts the argument at the ABI
/// boundary, where the signature is fixed, and discards it the same way.
#[must_use]
pub fn version_info() -> &'static VersionInfo {
    static INFO: OnceLock<VersionInfo> = OnceLock::new();

    INFO.get_or_init(|| {
        // These three fields are the SAME capability questions the `Features:`
        // line and the version banner answer, on a third surface, so they ask
        // the same predicates. A caller that read `brotli_version` as
        // `"brotli/8.0.4"` while `features & CURL_VERSION_BROTLI` was clear
        // would be looking at one library describing itself two ways -- and
        // `features_bitmask()` below is derived from the table, so the bit is
        // already the conjunction. Gating the string on anything weaker is what
        // makes them disagree.
        let (brotli_version, brotli_ver_num) = if supports_brotli() {
            let (major, minor, patch) =
                version_components(BROTLI_TOKEN).unwrap_or((0, 0, 0));
            (
                Some(BROTLI_TOKEN),
                packed_version_24_12(major, minor, patch),
            )
        } else {
            (None, 0)
        };

        let (zstd_version, zstd_ver_num) = if supports_zstd() {
            let (major, minor, patch) =
                version_components(ZSTD_TOKEN).unwrap_or((0, 0, 0));
            (Some(ZSTD_TOKEN), packed_version_24_12(major, minor, patch))
        } else {
            (None, 0)
        };

        let quic_version = if supports_http3() {
            Some(HTTP3_TOKEN)
        } else {
            None
        };

        VersionInfo {
            age: CURLversion::NOW,
            version: LIBCURL_VERSION,
            version_num: LIBCURL_VERSION_NUM,
            host: host(),
            features: features_bitmask(),
            // NULL unless a backend can execute, exactly as C leaves it: the
            // static initialiser at `lib/version.c:564` reads
            // `NULL, /* ssl_version */` and only the `#ifdef USE_SSL` block at
            // `:620-623` fills it in. Gated on the same predicate as the banner
            // slot so the two descriptions of one capability cannot diverge.
            ssl_version: if supports_tls() {
                Some(SSL_VERSION)
            } else {
                None
            },
            ssl_version_num: 0,
            libz_version: None,
            protocols: protocols(),

            ares: None,
            ares_num: 0,

            libidn: None,

            iconv_ver_num: 0,
            libssh_version: None,

            brotli_ver_num,
            brotli_version,

            // nghttp2 is not linked; `h2` is, and the banner says so.
            nghttp2_ver_num: packed_version_16_8(0, 0, 0),
            nghttp2_version: None,
            quic_version,

            cainfo: None,
            capath: None,

            zstd_ver_num,
            zstd_version,

            hyper_version: Some(HYPER_TOKEN),

            gsasl_version: None,

            feature_names: feature_names(),

            rtmp_version: None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nine schemes AAP 0.2.1 puts in scope. A complete build serves all
    /// nine; this one serves none, which is why every assertion below reads
    /// `compiled_in` rather than assuming the row implies the capability.
    const NINE_SCHEMES: [&str; 9] = [
        "file", "ftp", "ftps", "http", "https", "scp", "sftp", "ws", "wss",
    ];

    /// The 24 registered schemes this implementation does not serve, whose 283
    /// fixtures must skip rather than fail.
    const OUT_OF_SCOPE_SCHEMES: [&str; 24] = [
        "dict", "gopher", "gophers", "imap", "imaps", "ldap", "ldaps", "mqtt",
        "mqtts", "pop3", "pop3s", "rtmp", "rtmpe", "rtmps", "rtmpt", "rtmpte",
        "rtmpts", "rtsp", "smb", "smbs", "smtp", "smtps", "telnet", "tftp",
    ];

    /// The 32 rows of `features_table[]` in C source order, names verbatim.
    const C_FEATURE_ORDER: [&str; 32] = [
        "alt-svc",
        "asyn-rr",
        "AsynchDNS",
        "brotli",
        "Debug",
        "ECH",
        "gsasl",
        "GSS-API",
        "HSTS",
        "HTTP2",
        "HTTP3",
        "HTTPS-proxy",
        "HTTPSRR",
        "IDN",
        "IPv6",
        "Kerberos",
        "Largefile",
        "libz",
        "MultiSSL",
        "NTLM",
        "PSL",
        "AppleSecTrust",
        "NativeCA",
        "SPNEGO",
        "SSL",
        "SSLS-EXPORT",
        "SSPI",
        "threadsafe",
        "TLS-SRP",
        "Unicode",
        "UnixSockets",
        "zstd",
    ];

    /// Every name this build must never advertise, whatever its features.
    const NEVER_ADVERTISED: [&str; 11] = [
        "Debug",
        "MultiSSL",
        "SSPI",
        "Unicode",
        "TLS-SRP",
        "gsasl",
        "asyn-rr",
        "HTTPSRR",
        "AppleSecTrust",
        "NativeCA",
        "SSLS-EXPORT",
    ];

    /// The `Features:` line as the command-line tool would emit its content.
    ///
    /// The tool sorts case-insensitively before printing
    /// (`src/tool_help.c:372-373`); the harness only applies substring regexes,
    /// so joining in table order is equivalent for these assertions and keeps
    /// the emitted order under test at the same time.
    fn features_line() -> String {
        feature_names().join(" ")
    }

    /// The value of `$libcurl` after `tests/runtests.pl:562` splits the first
    /// `--version` line at the `libcurl` token.
    fn harness_libcurl_field() -> &'static str {
        version()
    }

    // -- version identity ---------------------------------------------------

    #[test]
    fn version_identity_is_frozen() {
        // Every parity claim is against 8.19.0-DEV, measured at
        // include/curl/curlver.h:31-72.
        assert_eq!(LIBCURL_NAME, "libcurl");
        assert_eq!(CURL_NAME, "curl");
        assert_eq!(LIBCURL_VERSION, "8.19.0-DEV");
        assert_eq!(LIBCURL_VERSION_MAJOR, 8);
        assert_eq!(LIBCURL_VERSION_MINOR, 19);
        assert_eq!(LIBCURL_VERSION_PATCH, 0);
        assert_eq!(LIBCURL_VERSION_NUM, 0x0008_1300);
        assert_eq!(LIBCURL_TIMESTAMP, "[unreleased]");
        assert_eq!(LIBCURL_COPYRIGHT, "Daniel Stenberg, <daniel@haxx.se>.");
    }

    #[test]
    fn version_num_agrees_with_its_parts() {
        // curlver.h writes the number as a full literal because configure greps
        // for it; this proves the literal and the parts describe one version.
        assert_eq!(
            version_bits(
                LIBCURL_VERSION_MAJOR,
                LIBCURL_VERSION_MINOR,
                LIBCURL_VERSION_PATCH
            ),
            LIBCURL_VERSION_NUM
        );
        assert!(at_least_version(8, 19, 0));
        assert!(at_least_version(7, 61, 0));
        assert!(!at_least_version(8, 20, 0));
        assert!(!at_least_version(9, 0, 0));
    }

    #[test]
    fn version_string_begins_with_the_numeric_parts() {
        let expected =
            format!("{LIBCURL_VERSION_MAJOR}.{LIBCURL_VERSION_MINOR}.{LIBCURL_VERSION_PATCH}");
        assert!(
            LIBCURL_VERSION.starts_with(&expected),
            "{LIBCURL_VERSION} must begin with {expected}"
        );
    }

    #[test]
    fn the_default_user_agent_is_built_from_one_literal() {
        // src/config2setopts.c:906-907 builds CURL_NAME "/" CURL_VERSION.
        assert_eq!(DEFAULT_USER_AGENT, "curl/8.19.0-DEV");
        assert_eq!(
            DEFAULT_USER_AGENT,
            format!("{CURL_NAME}/{LIBCURL_VERSION}")
        );
    }

    #[test]
    fn host_triple_is_shaped_like_the_c_string() {
        let triple = host();

        // At least cpu-vendor-os; the environment component is optional.
        assert!(
            triple.split('-').count() >= 3,
            "{triple} does not look like a target triple"
        );
        assert!(!triple.contains(' '), "{triple} must not contain spaces");
        assert!(!triple.starts_with('-') && !triple.ends_with('-'));

        // The harness matches this string, printed before the libcurl token,
        // against /win32|Windows|windows|mingw(32|64)/ and /cygwin|msys/i to
        // decide whether to use Windows-style paths (tests/runtests.pl:563-570).
        #[cfg(not(windows))]
        for trap in ["win32", "windows", "Windows", "mingw", "cygwin", "msys"] {
            assert!(
                !triple.contains(trap),
                "{triple} would make the harness switch path conventions"
            );
        }

        // Apple triples spell the OS "darwin", never Rust's "macos".
        #[cfg(target_vendor = "apple")]
        {
            assert!(triple.ends_with("-darwin"), "{triple}");
            assert!(!triple.contains("macos"), "{triple}");
        }

        #[cfg(all(
            target_arch = "x86_64",
            target_os = "linux",
            target_env = "gnu"
        ))]
        assert_eq!(triple, "x86_64-unknown-linux-gnu");

        #[cfg(all(
            target_arch = "aarch64",
            target_os = "linux",
            target_env = "gnu"
        ))]
        assert_eq!(triple, "aarch64-unknown-linux-gnu");

        #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
        assert_eq!(triple, "x86_64-apple-darwin");

        #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
        assert_eq!(triple, "aarch64-apple-darwin");
    }

    #[test]
    fn host_is_stable_across_calls() {
        assert_eq!(host().as_ptr(), host().as_ptr());
    }

    // -- CURLversion --------------------------------------------------------

    #[test]
    fn curlversion_is_laid_out_as_a_c_int() {
        assert_eq!(
            core::mem::size_of::<CURLversion>(),
            core::mem::size_of::<i32>()
        );
        assert_eq!(
            core::mem::align_of::<CURLversion>(),
            core::mem::align_of::<i32>()
        );
    }

    #[test]
    fn curlversion_pins_its_discriminants() {
        assert_eq!(CURLversion::First.as_c_int(), 0);
        assert_eq!(CURLversion::Twelfth.as_c_int(), 11);
        assert_eq!(CURLversion::NOW, CURLversion::Twelfth);
        assert_eq!(CURLversion::NOW.as_c_int(), 11);
        assert_eq!(CURLversion::LAST, 12);
        assert_eq!(CURLversion::COUNT, 12);
        assert_eq!(CURLversion::VARIANTS.len(), CURLversion::COUNT);
    }

    #[test]
    fn curlversion_round_trips_and_rejects_the_sentinel() {
        for (index, age) in CURLversion::VARIANTS.iter().enumerate() {
            let raw = i32::try_from(index).expect("twelve ages fit an int");
            assert_eq!(age.as_c_int(), raw);
            assert_eq!(CURLversion::from_c_int(raw), Some(*age));
            assert!(age.c_name().starts_with("CURLVERSION_"));
            assert!(!age.introduced_in().is_empty());
            assert_eq!(age.to_string(), age.c_name());
        }

        // CURLVERSION_LAST is "never actually use this" -- a bound, not a value.
        assert_eq!(CURLversion::from_c_int(CURLversion::LAST), None);
        assert_eq!(CURLversion::from_c_int(-1), None);
        assert_eq!(CURLversion::from_c_int(i32::MAX), None);
    }

    #[test]
    fn curlversion_names_and_releases_are_the_measured_ones() {
        assert_eq!(CURLversion::First.c_name(), "CURLVERSION_FIRST");
        assert_eq!(CURLversion::Eleventh.c_name(), "CURLVERSION_ELEVENTH");
        assert_eq!(CURLversion::Twelfth.c_name(), "CURLVERSION_TWELFTH");
        assert_eq!(CURLversion::First.introduced_in(), "7.10");
        assert_eq!(CURLversion::Eleventh.introduced_in(), "7.87.0");
        assert_eq!(CURLversion::Twelfth.introduced_in(), "8.8.0");
    }

    // -- the CURL_VERSION_* bits -------------------------------------------

    #[test]
    fn bits_have_their_measured_values() {
        // include/curl/curl.h:3175-3211, one assertion per line of the header.
        assert_eq!(CURL_VERSION_IPV6, 1);
        assert_eq!(CURL_VERSION_KERBEROS4, 1 << 1);
        assert_eq!(CURL_VERSION_SSL, 1 << 2);
        assert_eq!(CURL_VERSION_LIBZ, 1 << 3);
        assert_eq!(CURL_VERSION_NTLM, 1 << 4);
        assert_eq!(CURL_VERSION_GSSNEGOTIATE, 1 << 5);
        assert_eq!(CURL_VERSION_DEBUG, 1 << 6);
        assert_eq!(CURL_VERSION_ASYNCHDNS, 1 << 7);
        assert_eq!(CURL_VERSION_SPNEGO, 1 << 8);
        assert_eq!(CURL_VERSION_LARGEFILE, 1 << 9);
        assert_eq!(CURL_VERSION_IDN, 1 << 10);
        assert_eq!(CURL_VERSION_SSPI, 1 << 11);
        assert_eq!(CURL_VERSION_CONV, 1 << 12);
        assert_eq!(CURL_VERSION_CURLDEBUG, 1 << 13);
        assert_eq!(CURL_VERSION_TLSAUTH_SRP, 1 << 14);
        assert_eq!(CURL_VERSION_NTLM_WB, 1 << 15);
        assert_eq!(CURL_VERSION_HTTP2, 1 << 16);
        assert_eq!(CURL_VERSION_GSSAPI, 1 << 17);
        assert_eq!(CURL_VERSION_KERBEROS5, 1 << 18);
        assert_eq!(CURL_VERSION_UNIX_SOCKETS, 1 << 19);
        assert_eq!(CURL_VERSION_PSL, 1 << 20);
        assert_eq!(CURL_VERSION_HTTPS_PROXY, 1 << 21);
        assert_eq!(CURL_VERSION_MULTI_SSL, 1 << 22);
        assert_eq!(CURL_VERSION_BROTLI, 1 << 23);
        assert_eq!(CURL_VERSION_ALTSVC, 1 << 24);
        assert_eq!(CURL_VERSION_HTTP3, 1 << 25);
        assert_eq!(CURL_VERSION_ZSTD, 1 << 26);
        assert_eq!(CURL_VERSION_UNICODE, 1 << 27);
        assert_eq!(CURL_VERSION_HSTS, 1 << 28);
        assert_eq!(CURL_VERSION_GSASL, 1 << 29);
        assert_eq!(CURL_VERSION_THREADSAFE, 1 << 30);
    }

    // -- the engine registry ------------------------------------------------

    #[test]
    fn every_declared_engine_is_in_the_engines_slice() {
        // The slice is what auditors and the `curlinfo` tests iterate, so an
        // entry declared above but omitted from it would be invisible to both.
        // Listed literally rather than derived, so that adding a `pub const
        // ENGINE_*` without registering it fails here.
        let declared = [
            ENGINE_IDN,
            ENGINE_DNS,
            ENGINE_CONN,
            ENGINE_TLS,
            ENGINE_PROXY,
            ENGINE_AUTH,
            ENGINE_GSS,
            ENGINE_STATE_STORES,
            ENGINE_CONTENT_ENCODING,
            ENGINE_PROTOCOLS,
            ENGINE_TRANSFER,
            ENGINE_GLOBAL_INIT,
            ENGINE_AUTH_BASIC,
            ENGINE_AUTH_BEARER,
            ENGINE_AUTH_DIGEST,
            ENGINE_AUTH_AWS_SIGV4,
            ENGINE_AUTH_DISPATCH,
            ENGINE_DOH,
            ENGINE_MIME,
            ENGINE_FORM,
            ENGINE_NETRC,
            ENGINE_PARSEDATE,
            ENGINE_HEADERS,
            ENGINE_MULTI,
            ENGINE_SHA512_256,
            ENGINE_PUBLIC_HEADER,
            ENGINE_LIBCURL_SOURCE,
            ENGINE_DIAGNOSTIC_STRINGS,
            ENGINE_XATTR,
        ];

        assert_eq!(ENGINES, declared, "every engine must be registered");
        assert_eq!(ENGINES.len(), 29, "the registry holds 29 entries");
    }

    #[test]
    fn no_two_engines_claim_the_same_owning_module() {
        // Two entries with one owner would be two switches for one edit, which
        // is exactly the drift the per-file granularity exists to prevent.
        let mut seen = std::collections::HashSet::new();

        for engine in ENGINES {
            assert!(
                seen.insert(engine.owner()),
                "{} is claimed by two engines",
                engine.owner()
            );
            assert!(
                engine.owner().ends_with(".rs"),
                "{} must name a Rust source file",
                engine.owner()
            );
            assert!(
                engine.owner().starts_with("curl-rs"),
                "{} must be a workspace-relative path",
                engine.owner()
            );
        }
    }

    #[test]
    fn every_present_engine_has_a_compile_time_link() {
        // The registry's own invariant, stated in its block comment: a
        // `present: true` entry must be accompanied by a reference to a real
        // item its owning module exports, so the claim cannot outlive the
        // implementation. Asserting the SET rather than the count means a
        // future entry cannot be flipped to present without being named here,
        // and the references themselves sit next to `ENGINES`.
        let present: Vec<&str> = ENGINES
            .iter()
            .filter(|engine| engine.is_present())
            .map(Engine::owner)
            .collect();

        assert_eq!(
            present,
            vec![
                // Registry order, not alphabetical: the assertion doubles as a
                // record of where each present engine sits in `ENGINES`.
                "curl-rs-lib/src/url/idn.rs",
                // The one entry with no `const _` line beside `ENGINES`, and
                // the only one that CANNOT have one: it is owned by
                // `curl-rs-ffi`, which depends on this crate, so naming an item
                // in it here would invert the dependency direction. The
                // correspondence is asserted from that crate instead. The
                // exception is listed here rather than filtered out, so that a
                // second cross-crate owner has to be considered deliberately
                // rather than slipping in behind this one.
                "curl-rs-ffi/src/ffi/global.rs",
                "curl-rs-lib/src/mime/mod.rs",
                "curl-rs-lib/src/util/parsedate.rs",
                "curl-rs-lib/src/crypto/sha512_256.rs",
                "curl-rs-lib/src/error.rs",
                "curl-rs-lib/src/ffi/sys.rs",
            ],
            "each present engine needs its own const _ link"
        );

        // The exception is exactly one entry wide. Every other present engine
        // is owned by this crate and therefore linkable here.
        let cross_crate: Vec<&str> = present
            .iter()
            .filter(|owner| !owner.starts_with("curl-rs-lib/"))
            .copied()
            .collect();

        assert_eq!(
            cross_crate,
            vec!["curl-rs-ffi/src/ffi/global.rs"],
            "a present engine owned outside this crate cannot be linked here; \
             assert the correspondence in the owning crate and record it above"
        );

        // And the linked items really do answer, which is what makes the
        // `present` claim substantive rather than a bare boolean.
        let _ = crate::url::idn::available();
        assert!(
            !crate::error::CURLcode::UnsupportedProtocol
                .message()
                .is_empty(),
            "verbose strings are the capability ENGINE_DIAGNOSTIC_STRINGS \
             claims"
        );

        // ENGINE_MIME, exercised through the same entry point `curl_mime_init`
        // uses. A constructor that returns a usable multipart with a generated
        // boundary is the capability the `Mime` row claims; a linkable symbol
        // that refused at run time would satisfy the `const _` line above and
        // still leave the row over-reported, which is the direction AAP 0.6.5
        // makes fatal.
        let mime = crate::mime::Mime::with_system_rng()
            .expect("ENGINE_MIME claims a multipart builder that constructs");
        assert!(
            !mime.boundary().is_empty(),
            "a MIME boundary is what every multipart body is delimited by, so \
             an empty one means the engine cannot serialise anything"
        );
    }

    #[test]
    fn a_present_engine_is_always_a_written_one() {
        // The fourth combination -- executing work whose source is not in the
        // tree -- is unrepresentable because no constructor produces it. This
        // asserts the property rather than the constructors, so it keeps holding
        // if a fourth constructor is ever added.
        for engine in ENGINES {
            assert!(
                !engine.is_present() || engine.is_written(),
                "{} claims to execute work it has no source for",
                engine.owner()
            );
        }
    }

    #[test]
    fn only_three_engines_are_genuinely_unwritten() {
        // The distinction the `written` field exists to record, asserted as a
        // SET rather than a count so that the answer to "what would clear this
        // row" cannot silently move between "write a file" and "wire one".
        //
        // Every other unavailable row names a file that IS on disk, which is why
        // its prose must not tell a reader to write it. The filesystem half of
        // this claim is checked by `curl-rs/src/bin/curlinfo.rs`; this crate
        // cannot check it and stay runnable under the Miri gate of AAP 0.8.4.
        let unwritten: Vec<&str> = ENGINES
            .iter()
            .filter(|engine| !engine.is_written())
            .map(Engine::owner)
            .collect();

        assert_eq!(
            unwritten,
            vec![
                "curl-rs-lib/src/proxy/http_connect.rs",
                "curl-rs-lib/src/transfer/content_encoding.rs",
                "curl-rs/src/libcurl_src.rs",
            ],
            "the set of engines whose remedy is WRITING a file"
        );

        let working = ENGINES.iter().filter(|e| e.is_present()).count();
        let inert = ENGINES
            .iter()
            .filter(|e| e.is_written() && !e.is_present())
            .count();

        // MIME counts as working rather than inert: `curl-rs-ffi/src/ffi/mime.rs`
        // defines all twelve `curl_mime_*` exports on top of the module, which
        // is the artifact-level evidence this registry requires, and
        // `curl-rs/src/bin/curlinfo.rs` reports the row ON accordingly.
        assert_eq!((working, inert, unwritten.len()), (7, 19, 3));
        assert_eq!(working + inert + unwritten.len(), ENGINES.len());
    }

    // -- the features table ------------------------------------------------

    #[test]
    fn the_features_table_reproduces_all_thirty_two_c_rows() {
        assert_eq!(
            FEATURES.len(),
            32,
            "lib/version.c:450-554 declares exactly 32 FEATURE() rows"
        );

        let names: Vec<&str> = FEATURES.iter().map(Feature::name).collect();
        assert_eq!(
            names.as_slice(),
            C_FEATURE_ORDER.as_slice(),
            "row order must be the C source order, anomaly included"
        );
    }

    #[test]
    fn every_row_has_the_bit_the_c_table_gives_it() {
        let expected: [(&str, i32); 32] = [
            ("alt-svc", CURL_VERSION_ALTSVC),
            ("asyn-rr", 0),
            ("AsynchDNS", CURL_VERSION_ASYNCHDNS),
            ("brotli", CURL_VERSION_BROTLI),
            ("Debug", CURL_VERSION_DEBUG),
            ("ECH", 0),
            ("gsasl", CURL_VERSION_GSASL),
            ("GSS-API", CURL_VERSION_GSSAPI),
            ("HSTS", CURL_VERSION_HSTS),
            ("HTTP2", CURL_VERSION_HTTP2),
            ("HTTP3", CURL_VERSION_HTTP3),
            ("HTTPS-proxy", CURL_VERSION_HTTPS_PROXY),
            ("HTTPSRR", 0),
            ("IDN", CURL_VERSION_IDN),
            ("IPv6", CURL_VERSION_IPV6),
            ("Kerberos", CURL_VERSION_KERBEROS5),
            ("Largefile", CURL_VERSION_LARGEFILE),
            ("libz", CURL_VERSION_LIBZ),
            ("MultiSSL", CURL_VERSION_MULTI_SSL),
            ("NTLM", CURL_VERSION_NTLM),
            ("PSL", CURL_VERSION_PSL),
            ("AppleSecTrust", 0),
            ("NativeCA", 0),
            ("SPNEGO", CURL_VERSION_SPNEGO),
            ("SSL", CURL_VERSION_SSL),
            ("SSLS-EXPORT", 0),
            ("SSPI", CURL_VERSION_SSPI),
            ("threadsafe", CURL_VERSION_THREADSAFE),
            ("TLS-SRP", CURL_VERSION_TLSAUTH_SRP),
            ("Unicode", CURL_VERSION_UNICODE),
            ("UnixSockets", CURL_VERSION_UNIX_SOCKETS),
            ("zstd", CURL_VERSION_ZSTD),
        ];

        for (row, (name, bit)) in FEATURES.iter().zip(expected) {
            assert_eq!(row.name(), name);
            assert_eq!(row.bitmask(), bit, "wrong bit for {name}");
        }
    }

    /// The three rows whose predicate reproduces one C already has.
    ///
    /// `lib/version.c` gives a `present` function pointer to exactly `ECH`
    /// (`:428-432`), `HTTPS-proxy` (`:420-424`) and `IDN` (`:407-415`).
    const C_PREDICATE_ROWS: &[&str] = &["ECH", "HTTPS-proxy", "IDN"];

    /// The three rows whose predicate C does NOT have, added deliberately.
    const STRENGTHENED_PREDICATE_ROWS: &[&str] =
        &["GSS-API", "Kerberos", "SPNEGO"];

    /// Exactly which rows consult a predicate, and why the set is not C's.
    ///
    /// This table adds a predicate to those three GSS rows, and the deviation
    /// is deliberate because the premise behind C's NULL does not hold here. C
    /// compiles under `#ifdef HAVE_GSSAPI`, having LINKED a GSS-API library at
    /// build time, so for C "compiled in" and "available" are the same
    /// statement and a predicate would be redundant. This implementation
    /// confines its binding to `crate::ffi::gss` and resolves the library at
    /// RUN TIME, so the two statements come apart: a host can have `negotiate`
    /// compiled and no usable mechanism.
    #[test]
    fn only_the_c_predicate_rows_and_the_gss_trio_carry_a_predicate() {
        let with_predicate: Vec<&str> = FEATURES
            .iter()
            .filter(|row| row.present.is_some())
            .map(Feature::name)
            .collect();
        assert_eq!(
            with_predicate,
            vec!["ECH", "GSS-API", "HTTPS-proxy", "IDN", "Kerberos", "SPNEGO",]
        );

        // The three C-derived predicates answer from a constant in this build;
        // the three GSS ones are the only genuinely dynamic answers in the
        // table. `curl-rs-ffi/build.rs` relies on exactly that split when it
        // derives the static consumer metadata from this table, so it is
        // asserted here rather than assumed there.
        for name in ["ECH", "HTTPS-proxy", "IDN"] {
            let row = feature(name).expect("row must exist");
            assert!(row.present.is_some(), "{name} must carry a predicate");
        }
        for name in ["GSS-API", "Kerberos", "SPNEGO"] {
            let row = feature(name).expect("row must exist");
            let predicate = row.present.expect("a GSS row must carry one");
            // Compared by RESULT, not by address. Function-pointer identity is
            // not meaningful -- the same body can hold different addresses in
            // different codegen units and distinct bodies can share one after
            // the linker merges them -- which is why `PartialEq` for `Feature`
            // excludes this field, and why clippy rejects the numeric cast.
            assert_eq!(
                predicate(),
                gss_present(),
                "{name}'s predicate must answer exactly as gss_present does"
            );
        }
        // Table order, not the order of the two lists above: this is the shape
        // a reader of FEATURES sees.
        assert_eq!(
            with_predicate,
            vec!["ECH", "GSS-API", "HTTPS-proxy", "IDN", "Kerberos", "SPNEGO"],
            "a predicate was added or removed; classify it below before changing this"
        );

        // Every predicate row belongs to exactly one of the two categories, so a
        // new one cannot be introduced without a deliberate decision about which
        // it is.
        for name in &with_predicate {
            let mirrors_c = C_PREDICATE_ROWS.contains(name);
            let strengthens = STRENGTHENED_PREDICATE_ROWS.contains(name);
            assert!(
                mirrors_c ^ strengthens,
                "{name} carries a predicate but is in neither category (or both)"
            );
        }

        // And no row in either list lacks one.
        for name in C_PREDICATE_ROWS.iter().chain(STRENGTHENED_PREDICATE_ROWS) {
            let row = feature(name).expect("category names must be real rows");
            assert!(row.present.is_some(), "{name} lost its predicate");
        }
    }

    /// The three GSS names answer from the runtime probe, not from `cfg!`.
    #[test]
    fn the_gss_rows_track_the_runtime_probe_not_the_compile_time_feature() {
        let usable = crate::ffi::gss_available();

        // Without the feature the probe is a compile-time `false`, so the rows
        // are withheld by `compiled_in` alone and there is nothing to observe.
        if !cfg!(feature = "negotiate") {
            assert!(
                !usable,
                "gss_available must be false when not compiled in"
            );
        }

        for name in STRENGTHENED_PREDICATE_ROWS {
            let row = feature(name).expect("row must exist in every build");
            assert_eq!(
                row.compiled_in(),
                cfg!(feature = "negotiate") && ENGINE_GSS.is_present(),
                "{name} must be compiled in exactly with the negotiate feature \
                 AND the engine that implements it"
            );

            // Read the predicate DIRECTLY rather than inferring it from
            // `is_present()`. This is the assertion that bites on every host: on
            // one where GSS-API happens to work, `present: None` produces the
            // same `is_present()` as a working predicate, so an `is_present()`
            // comparison alone would pass with the defect re-introduced. The
            // `expect` fails outright if the row reverts to `None`, and the
            // comparison fails if the predicate stops tracking the probe.
            let predicate = row.present.unwrap_or_else(|| {
                panic!("{name} must carry a RUNTIME predicate, not compile-time configuration")
            });
            assert_eq!(
                predicate(),
                usable,
                "{name}'s predicate must be the GSS availability probe"
            );

            assert_eq!(
                row.is_present(),
                cfg!(feature = "negotiate")
                    && ENGINE_GSS.is_present()
                    && usable,
                "{name} must be advertised only when compiled in AND usable"
            );
            // The banner and the bitmask are projections of the same rows, so
            // they must agree on this name too.
            assert_eq!(
                has_feature(name),
                cfg!(feature = "negotiate")
                    && ENGINE_GSS.is_present()
                    && usable,
                "{name}: has_feature disagrees with the row"
            );
            assert_eq!(
                feature_names().contains(name),
                cfg!(feature = "negotiate")
                    && ENGINE_GSS.is_present()
                    && usable,
                "{name}: the emitted name list disagrees with the row"
            );
        }
    }

    /// All three GSS rows resolve identically, because in C they share a guard.
    #[test]
    fn the_three_gss_rows_never_disagree_with_one_another() {
        let answers: Vec<bool> = STRENGTHENED_PREDICATE_ROWS
            .iter()
            .map(|name| {
                feature(name)
                    .expect("row must exist in every build")
                    .is_present()
            })
            .collect();
        assert!(
            answers.iter().all(|answer| *answer == answers[0]),
            "GSS-API, Kerberos and SPNEGO must agree: {answers:?}"
        );
    }

    /// `is_present()` really ANDs the two conditions -- proven on synthetic rows.
    #[test]
    fn is_present_requires_both_compiled_in_and_the_predicate() {
        fn yes() -> bool {
            true
        }
        fn no() -> bool {
            false
        }

        let cases = [
            (true, Some(yes as fn() -> bool), true),
            (true, Some(no as fn() -> bool), false),
            (false, Some(yes as fn() -> bool), false),
            (false, Some(no as fn() -> bool), false),
            // `None` is C's NULL: `if(!p->present || p->present(...))`.
            (true, None, true),
            (false, None, false),
        ];

        for (compiled_in, present, expected) in cases {
            let row = Feature {
                name: "synthetic",
                bitmask: 0,
                compiled_in,
                present,
            };
            assert_eq!(
                row.is_present(),
                expected,
                "compiled_in={compiled_in}, present={}",
                if present.is_some() { "Some" } else { "None" }
            );
        }
    }

    #[test]
    fn no_feature_name_is_duplicated_or_malformed() {
        let mut seen = std::collections::HashSet::new();
        for row in FEATURES {
            assert!(seen.insert(row.name()), "duplicate row {}", row.name());
            assert!(!row.name().is_empty());
            assert!(
                !row.name().contains(char::is_whitespace),
                "{} would split the Features line",
                row.name()
            );
        }
    }

    #[test]
    fn feature_names_preserve_table_order() {
        let emitted = feature_names();
        let expected: Vec<&str> = FEATURES
            .iter()
            .filter(|row| row.is_present())
            .map(Feature::name)
            .collect();
        assert_eq!(emitted, expected.as_slice());

        // A projection can only ever be a subsequence of its table.
        let mut rows = FEATURES.iter().map(Feature::name);
        for name in emitted {
            assert!(
                rows.any(|candidate| candidate == *name),
                "{name} is out of table order"
            );
        }

        // has_feature() answers from the table while feature_names() builds the
        // emitted list; both are projections of the same rows, so they must
        // agree on every one of the 32 names.
        for row in FEATURES {
            assert_eq!(
                has_feature(row.name()),
                emitted.contains(&row.name()),
                "has_feature and the Features line disagree about {}",
                row.name()
            );
        }
    }

    #[test]
    fn bitmask_and_names_agree_in_both_directions() {
        let mask = features_bitmask();

        // Forward: every advertised name's bit is set.
        for row in FEATURES.iter().filter(|row| row.is_present()) {
            if row.bitmask() != 0 {
                assert_eq!(
                    mask & row.bitmask(),
                    row.bitmask(),
                    "{} is advertised but its bit is clear",
                    row.name()
                );
            }
        }

        // Backward: every set bit belongs to an advertised name. Walking all 31
        // bit positions catches a stray bit that no row owns, which is the
        // failure a forward-only check cannot see.
        for position in 0..31 {
            let bit: i32 = 1 << position;
            if mask & bit == 0 {
                continue;
            }
            let owner = FEATURES
                .iter()
                .find(|row| row.bitmask() == bit && row.is_present());
            assert!(owner.is_some(), "bit 1<<{position} is set but unclaimed");
        }

        // And no withheld name may contribute anything.
        for row in FEATURES.iter().filter(|row| !row.is_present()) {
            assert_eq!(
                mask & row.bitmask(),
                0,
                "{} is withheld yet its bit is set",
                row.name()
            );
        }
    }

    #[test]
    fn the_curldebug_compatibility_bit_is_never_set() {
        // lib/version.c:690-692 ORs it in under DEBUGBUILD only.
        assert_eq!(features_bitmask() & CURL_VERSION_CURLDEBUG, 0);
        assert_eq!(features_bitmask() & CURL_VERSION_DEBUG, 0);
    }

    #[test]
    fn debug_is_never_advertised_under_any_feature_combination() {
        // The row is a literal false, deliberately not gated on `memdebug`,
        // so this holds even under --all-features.
        assert!(!has_feature("Debug"));
        assert!(!features_line().contains("Debug"));

        let row = feature("Debug").expect("the Debug row must still exist");
        assert!(!row.compiled_in());
        assert!(!row.is_present());
    }

    #[test]
    fn the_never_advertised_names_are_absent() {
        let line = features_line();
        for name in NEVER_ADVERTISED {
            assert!(!has_feature(name), "{name} must not be advertised");
            assert!(
                !line.contains(name),
                "{name} must not appear in the Features line"
            );
        }
    }

    /// SSL is withheld, and the cost is the largest in the table: 138 fixtures
    /// require the name. It is still correct -- advertising a TLS capability
    /// with no `tls/mod.rs`, `tls/rustls_backend.rs` or `tls/verify.rs` would
    /// make all 138 run against an engine that cannot complete a handshake.
    #[test]
    fn ssl_is_withheld_while_the_tls_engine_is_absent() {
        assert!(!ENGINE_TLS.is_present());
        assert!(!has_feature("SSL"));
        assert_eq!(features_bitmask() & CURL_VERSION_SSL, 0);

        // The row exists and is looked up successfully -- withheld is not the
        // same as unknown.
        assert!(feature("SSL").is_some());
    }

    /// The capabilities whose claim is a property of the BUILD rather than of
    /// an engine module. These are the only rows that stay true while the
    /// engine registry is almost entirely absent, and each is true for a reason
    /// that no missing module can invalidate.
    #[test]
    fn the_build_intrinsic_capabilities_are_advertised() {
        // Derived from the width of curl_off_t, which is a type, not a module.
        assert!(has_feature("Largefile"));
        assert_eq!(
            features_bitmask() & CURL_VERSION_LARGEFILE,
            CURL_VERSION_LARGEFILE
        );

        // Implemented by crate::url::idn, which exists; see ENGINE_IDN.
        assert!(has_feature("IDN"));
        assert_eq!(features_bitmask() & CURL_VERSION_IDN, CURL_VERSION_IDN);
    }

    /// Every capability whose owning engine is absent is withheld, and the
    /// Cargo feature that selects it cannot override that. This is the
    /// invariant the whole registry exists to hold.
    #[test]
    fn no_capability_outlives_its_engine() {
        let engine_gated = [
            ("alt-svc", ENGINE_STATE_STORES),
            ("AsynchDNS", ENGINE_DNS),
            ("brotli", ENGINE_CONTENT_ENCODING),
            ("ECH", ENGINE_TLS),
            ("GSS-API", ENGINE_GSS),
            ("HSTS", ENGINE_STATE_STORES),
            ("HTTP2", ENGINE_PROTOCOLS),
            ("HTTP3", ENGINE_PROTOCOLS),
            ("HTTPS-proxy", ENGINE_PROXY),
            ("IDN", ENGINE_IDN),
            ("IPv6", ENGINE_CONN),
            ("Kerberos", ENGINE_GSS),
            ("libz", ENGINE_CONTENT_ENCODING),
            ("NTLM", ENGINE_AUTH),
            ("PSL", ENGINE_STATE_STORES),
            ("SPNEGO", ENGINE_GSS),
            ("SSL", ENGINE_TLS),
            ("threadsafe", ENGINE_GLOBAL_INIT),
            ("UnixSockets", ENGINE_CONN),
            ("zstd", ENGINE_CONTENT_ENCODING),
        ];

        for (name, engine) in engine_gated {
            let row = feature(name).expect("the row must exist");
            assert!(
                !row.compiled_in() || engine.is_present(),
                "{name} is compiled in while {} is absent",
                engine.owner()
            );
            assert!(
                !has_feature(name) || engine.is_present(),
                "{name} is advertised while {} is absent",
                engine.owner()
            );
        }
    }

    /// A capability is advertised only when BOTH factors hold: the Cargo
    /// feature that selects it and the engine that implements it. Asserted as a
    /// conjunction rather than against a hard-coded list so the test stays
    /// correct as engines land.
    #[test]
    fn feature_gated_names_need_their_cargo_feature_and_their_engine() {
        // Every name below is the conjunction of its Cargo feature and the
        // engine that implements it, so the expectations track the registry
        // instead of freezing one moment of it. The three GSS names carry a
        // THIRD conjunct -- `gss_present()` -- because since F5 the feature is
        // necessary but not sufficient: a binary built with `negotiate`, on a
        // host whose mechanism glue is unusable, withholds all three. Writing
        // the feature alone here would forbid that fix.
        let expected = [
            (
                "alt-svc",
                cfg!(feature = "altsvc") && ENGINE_STATE_STORES.is_present(),
            ),
            (
                "brotli",
                cfg!(feature = "brotli")
                    && ENGINE_CONTENT_ENCODING.is_present(),
            ),
            (
                "GSS-API",
                cfg!(feature = "negotiate")
                    && ENGINE_GSS.is_present()
                    && gss_present(),
            ),
            (
                "HSTS",
                cfg!(feature = "hsts") && ENGINE_STATE_STORES.is_present(),
            ),
            (
                "HTTP2",
                cfg!(feature = "http2")
                    && ENGINE_PROTOCOLS.is_present()
                    && ENGINE_TLS.is_present(),
            ),
            (
                "HTTP3",
                cfg!(feature = "http3")
                    && ENGINE_PROTOCOLS.is_present()
                    && ENGINE_TLS.is_present(),
            ),
            (
                "Kerberos",
                cfg!(feature = "negotiate")
                    && ENGINE_GSS.is_present()
                    && gss_present(),
            ),
            (
                "libz",
                cfg!(feature = "gzip") && ENGINE_CONTENT_ENCODING.is_present(),
            ),
            (
                "PSL",
                cfg!(feature = "cookies") && ENGINE_STATE_STORES.is_present(),
            ),
            (
                "SPNEGO",
                cfg!(feature = "negotiate")
                    && ENGINE_GSS.is_present()
                    && gss_present(),
            ),
            ("UnixSockets", cfg!(unix) && ENGINE_CONN.is_present()),
            (
                "zstd",
                cfg!(feature = "zstd") && ENGINE_CONTENT_ENCODING.is_present(),
            ),
        ];

        for (name, active) in expected {
            assert_eq!(has_feature(name), active, "{name} is misreported");
        }

        // What DOES still hold unconditionally for the GSS names: the feature is
        // NECESSARY even though it is not SUFFICIENT. Two things are needed
        // before the compile-time half can be true, and asserting only the
        // first is how this test came to fail under `--all-features`: it
        // demanded `compiled_in() == cfg!(feature = "negotiate")`, which with
        // the feature enabled demands `true` while the rows correctly report
        // `false`, because `ENGINE_GSS` is `absent` until
        // `curl-rs-lib/src/auth/negotiate.rs` exists to drive the binding
        // through an HTTP exchange.
        let gss_compiled =
            cfg!(feature = "negotiate") && ENGINE_GSS.is_present();
        for name in STRENGTHENED_PREDICATE_ROWS {
            assert_eq!(
                feature(name)
                    .expect("row must exist in every build")
                    .compiled_in(),
                gss_compiled,
                "{name}'s compile-time half is the negotiate feature AND a \
                 ready GSS engine, not the feature alone"
            );
            if !cfg!(feature = "negotiate") {
                assert!(
                    !has_feature(name),
                    "{name} cannot appear without the feature"
                );
            }
            if !ENGINE_GSS.is_present() {
                assert!(
                    !has_feature(name),
                    "{name} cannot appear while the GSS engine is withheld, \
                     however the feature is set: specification 0.6.5 makes \
                     over-reporting fatal and under-reporting safe"
                );
            }
        }
    }

    /// The predicate is what will still say no.
    #[test]
    fn ech_is_withheld_by_the_backend_as_well_as_by_the_engine() {
        assert!(!tls_supports_ech());
        assert!(!has_feature("ECH"));

        let row = feature("ECH").expect("the ECH row must exist");
        assert!(!row.compiled_in(), "the TLS engine is absent");
        assert!(!row.is_present());
    }

    /// The three predicate rows still dispatch through their predicates. Two of
    /// them answer `true` and are nevertheless withheld, which is exactly the
    /// separation the registry introduces: a backend capability can hold while
    /// the engine that would use it is missing.
    #[test]
    fn the_predicate_rows_are_consulted_independently_of_their_engines() {
        assert!(tls_supports_https_proxy());
        assert!(crate::url::idn::available());

        // IDN's engine exists, so its `true` predicate reaches the banner.
        assert!(has_feature("IDN"));

        // HTTPS-proxy's does not, so its `true` predicate is short-circuited by
        // `compiled_in` exactly as the C `#if` short-circuits the C predicate.
        assert!(!has_feature("HTTPS-proxy"));
        let row = feature("HTTPS-proxy").expect("the row must exist");
        assert!(!row.compiled_in());
    }

    /// The invariant: there is one IDN predicate, it lives in the module that
    /// implements IDN, and the feature table holds a pointer to THAT function
    /// rather than a second copy of its answer.
    #[test]
    fn the_idn_claim_comes_from_the_idn_module() {
        let row = feature("IDN").expect("the IDN row must exist");

        assert_eq!(row.is_present(), crate::url::idn::available());
        assert!(
            row.present.is_some(),
            "IDN must dispatch through a predicate, as lib/version.c:496 does"
        );
    }

    /// The three GSS-backed tokens combine a compile-time gate with a RUNTIME
    /// probe, and this asserts the composition rather than either half.
    ///
    /// Deliberately not `assert_eq!(has_feature("SPNEGO"), cfg!(...))`: that
    /// form is only satisfiable by reporting the `cfg!` alone -- which claims
    /// a mechanism the host may not have.
    ///
    /// * the row consults a predicate at all (`present` is not `None`);
    /// * being advertised IMPLIES the feature was compiled in;
    /// * all three answer identically, because one library backs all of them;
    /// * the answer equals `compiled_in && gss_present()`.
    #[test]
    fn the_gss_tokens_combine_compile_time_and_runtime() {
        let mut answers = Vec::new();

        // Spelled out rather than read back from a row, so that this is an
        // independent statement of the contract and not an echo of it.
        let compiled = cfg!(feature = "negotiate") && ENGINE_GSS.is_present();

        for name in ["GSS-API", "Kerberos", "SPNEGO"] {
            let row = feature(name).expect("the row must exist");

            assert!(
                row.present.is_some(),
                "{name} must consult a runtime probe; a bare cfg! \
                 over-reports when the GSS-API library is absent"
            );
            assert_eq!(
                row.compiled_in(),
                compiled,
                "{name}'s compile-time half is the negotiate feature AND a \
                 ready GSS engine"
            );
            assert_eq!(
                row.is_present(),
                compiled && gss_present(),
                "{name} must be the conjunction of both halves"
            );
            assert_eq!(has_feature(name), row.is_present());

            if has_feature(name) {
                assert!(
                    row.compiled_in(),
                    "{name} cannot be advertised without being compiled in"
                );
            }
            answers.push(row.is_present());
        }

        assert!(
            answers.windows(2).all(|w| w[0] == w[1]),
            "one GSS-API library backs all three tokens, so they cannot \
             disagree: {answers:?}"
        );

        // With the compile-time half false, the probe result is irrelevant and
        // all three must be withheld. That covers both reasons independently:
        // the default build has no `negotiate` feature, and an all-features
        // build still has no ready GSS engine.
        if !compiled {
            assert!(
                answers.iter().all(|a| !a),
                "no GSS token may be advertised without the feature AND the \
                 engine: {answers:?}"
            );
        }
    }

    /// The bitmask cannot advertise a GSS bit the name list withholds.
    #[test]
    fn the_gss_bits_track_the_gss_names() {
        let mask = features_bitmask();
        for (name, bit) in [
            ("GSS-API", CURL_VERSION_GSSAPI),
            ("Kerberos", CURL_VERSION_KERBEROS5),
            ("SPNEGO", CURL_VERSION_SPNEGO),
        ] {
            assert_eq!(
                mask & bit != 0,
                has_feature(name),
                "{name}'s bit and its name must agree"
            );
        }
    }

    #[test]
    fn lookup_distinguishes_withheld_from_unknown() {
        assert!(feature("SSL").is_some());
        assert!(feature("MultiSSL").is_some());
        assert!(feature("not-a-curl-feature").is_none());
        assert!(!has_feature("not-a-curl-feature"));

        // Case-sensitive by design.
        assert!(!has_feature("ssl"));
        assert!(feature("ssl").is_none());
    }

    // -- protocols ----------------------------------------------------------

    #[test]
    fn the_protocol_table_is_lowercase_and_sorted() {
        let mut previous = "";
        for row in PROTOCOLS {
            assert_eq!(
                row.name(),
                row.name().to_ascii_lowercase(),
                "{} must be lower case",
                row.name()
            );
            assert!(
                previous < row.name(),
                "{} is out of alphabetical order after {previous}",
                row.name()
            );
            previous = row.name();
        }
        assert_eq!(PROTOCOLS.len(), NINE_SCHEMES.len());
    }

    /// The advertised set is the conjunction of each scheme's Cargo feature,
    /// the protocol engine, and -- for the three secure schemes -- the TLS
    /// engine. Built as a conjunction rather than a literal list so the test
    /// remains correct as engines land.
    #[test]
    fn advertised_protocols_match_the_active_features_and_engines() {
        let engine = ENGINE_PROTOCOLS.is_present();
        let secure = engine && ENGINE_TLS.is_present();

        let mut expected: Vec<&str> = Vec::with_capacity(NINE_SCHEMES.len());
        if engine {
            expected.push("file");
        }
        if cfg!(feature = "ftp") && engine {
            expected.push("ftp");
        }
        if cfg!(feature = "ftp") && secure {
            expected.push("ftps");
        }
        if engine {
            expected.push("http");
        }
        if secure {
            expected.push("https");
        }
        if cfg!(feature = "ssh") && engine {
            expected.push("scp");
            expected.push("sftp");
        }
        if cfg!(feature = "websockets") && engine {
            expected.push("ws");
        }
        if cfg!(feature = "websockets") && secure {
            expected.push("wss");
        }

        assert_eq!(protocols(), expected.as_slice());
    }

    /// All nine in-scope schemes are reachable from the table -- the
    /// withholding is in `compiled_in`, never by dropping a row. This is what
    /// keeps the table diffable 1:1 against `supported_protocols[]` while
    /// nothing is served.
    #[test]
    fn every_one_of_the_nine_schemes_has_a_row_even_when_withheld() {
        for scheme in NINE_SCHEMES {
            assert!(
                PROTOCOLS.iter().any(|row| row.name() == scheme),
                "{scheme} must have a row"
            );
        }
    }

    /// Nothing is advertised while the protocol engine is absent, and the
    /// `Protocols:` line is therefore empty. Documented on
    /// [`ENGINE_PROTOCOLS`]: every fixture with a `<server>` requirement skips,
    /// which is the truthful report for a build with no protocol engine.
    #[test]
    fn no_scheme_is_advertised_while_the_protocol_engine_is_absent() {
        assert!(!ENGINE_PROTOCOLS.is_present());
        assert!(protocols().is_empty());

        for row in PROTOCOLS {
            assert!(
                !row.compiled_in(),
                "{} claims to be served with no protocol engine",
                row.name()
            );
        }
    }

    #[cfg(all(feature = "ftp", feature = "ssh", feature = "websockets"))]
    #[test]
    fn a_full_build_advertises_exactly_the_nine_schemes_once_the_engines_land()
    {
        if ENGINE_PROTOCOLS.is_present() && ENGINE_TLS.is_present() {
            assert_eq!(protocols(), NINE_SCHEMES.as_slice());
        } else {
            // Until then the same table advertises nothing, which the test
            // above asserts directly. Recorded here so this row of the matrix
            // is not read as untested.
            assert!(protocols().is_empty());
        }
    }

    #[test]
    fn no_out_of_scope_scheme_is_advertised() {
        // Their 283 fixtures must skip on the Protocols line rather than fail.
        for scheme in OUT_OF_SCOPE_SCHEMES {
            assert!(
                !supports_protocol(scheme),
                "{scheme} must not be advertised: it is not implemented"
            );
            assert!(
                !PROTOCOLS.iter().any(|row| row.name() == scheme),
                "{scheme} must not even appear in the table"
            );
        }

        // The command-line tool inserts these two into the printed line
        // (src/tool_help.c:348-353); the library must not.
        for cli_only in ["ipfs", "ipns"] {
            assert!(!supports_protocol(cli_only));
        }
    }

    #[test]
    fn protocol_lookup_ignores_case_like_the_c_registry() {
        // Case folding is a property of the lookup, not of the table, so it is
        // asserted against whatever the table currently advertises: every
        // advertised name must match in all three casings, and a name that is
        // not advertised must match in none.
        for scheme in protocols() {
            assert!(supports_protocol(scheme));
            assert!(supports_protocol(&scheme.to_ascii_uppercase()));
            assert!(supports_protocol(&scheme.to_ascii_lowercase()));
        }

        assert!(!supports_protocol("httpx"));
        assert!(!supports_protocol("HTTPX"));
        assert!(!supports_protocol(""));

        #[cfg(feature = "websockets")]
        {
            // The scheme registry spells these "WS"/"WSS" in upper case while
            // the banner spells them lower case, so lookup has to accept
            // either -- which is asserted here by asking in both casings. The
            // expected answer is the row's own gate rather than `true`: `ws`
            // needs only the protocol engine, `wss` needs TLS as well, and
            // while either is absent the correct answer to both questions is
            // no.
            assert_eq!(supports_protocol("WS"), ENGINE_PROTOCOLS.is_present());
            assert_eq!(
                supports_protocol("wss"),
                ENGINE_PROTOCOLS.is_present() && ENGINE_TLS.is_present()
            );
        }
    }

    #[test]
    fn protocols_are_stable_across_calls() {
        assert_eq!(protocols().as_ptr(), protocols().as_ptr());
    }

    // -- the banner ---------------------------------------------------------

    #[test]
    fn the_banner_opens_with_libcurl_then_the_tls_token() {
        let parts = version_parts();
        assert_eq!(parts[0], "libcurl/8.19.0-DEV");

        // Slot 2 is the TLS token WHEN there is one. `lib/version.c:206-209`
        // gates it on `USE_SSL`, so its presence is derived, not fixed, and the
        // assertion has to be conditional in the same way -- writing
        // `parts[1] == SSL_VERSION` unconditionally is what would pin an
        // over-report in place.
        assert_eq!(SSL_VERSION, "rustls/0.23.42");
        if supports_tls() {
            assert_eq!(parts[1], SSL_VERSION);
        } else {
            assert!(
                !parts.contains(&SSL_VERSION),
                "the TLS token must be absent while tls/mod.rs cannot execute"
            );
        }

        let banner = version();
        assert!(banner.starts_with("libcurl/8.19.0-DEV "));
        assert_eq!(
            banner.matches("libcurl").count(),
            1,
            "runtests.pl splits the version line at the last `libcurl`"
        );
    }

    #[test]
    fn the_tls_backend_is_named_once_and_identified_by_its_public_enumerant() {
        // `curl_global_sslset` reports CURLSSLBACKEND_RUSTLS = 14
        // (include/curl/curl.h:166) and `Curl_ssl_rustls.info.name` is the plain
        // word "rustls" (lib/vtls/rustls.c:1398). Both are one constant here so
        // the FFI crate and the banner cannot disagree.
        assert_eq!(TLS_BACKEND_NAME, "rustls");
        assert_eq!(TLS_BACKEND_ID, 14);
        assert_eq!(RUSTLS_VERSION, "0.23.42");
        assert_eq!(SSL_VERSION, format!("{TLS_BACKEND_NAME}/{RUSTLS_VERSION}"));
        assert!(
            !SSL_VERSION.contains("-ffi"),
            "A8: the token stays truthful"
        );
    }

    #[test]
    fn largefile_is_derived_from_the_offset_width() {
        // lib/version.c:502 keys Largefile off sizeof(curl_off_t) > 4, which is
        // also the assumption the single-slot varargs design rests on.
        // The `> 4` floor itself is a `const _: () = assert!(...)` beside the
        // constant, so a 32-bit target fails to build rather than fails here.
        assert_eq!(CURL_OFF_T_SIZE, 8);
        assert!(has_feature("Largefile"));
    }

    #[test]
    fn the_banner_is_single_spaced_and_untruncated() {
        let banner = version();
        assert!(!banner.contains("  "), "double space in {banner}");
        assert!(!banner.starts_with(' ') && !banner.ends_with(' '));
        assert!(!banner.contains('\n') && !banner.contains('\r'));
        assert!(!banner.contains('\t'));

        assert_eq!(banner, version_parts().join(" "));
    }

    #[test]
    fn the_banner_fits_the_c_buffer() {
        let parts = version_parts();
        assert!(
            parts.len() <= VERSION_PARTS,
            "{} parts exceeds the C src[] array",
            parts.len()
        );
        assert!(
            version().len() < VERSION_BUFFER_SIZE,
            "{} bytes would be truncated by `static char out[300]`",
            version().len()
        );
        assert_eq!(VERSION_PARTS, 16);
        assert_eq!(VERSION_BUFFER_SIZE, 300);
    }

    #[test]
    fn the_banner_parts_match_the_active_features() {
        // Every optional slot is `configured && implementation_ready`, asserted
        // through the same predicate the banner consults. Spelling any of
        // these as `cfg!(feature = ...)` alone is not a cosmetic difference:
        // it would make this test AGREE with a banner that contradicts the
        // `Features:` line, which is how `brotli/8.0.4` can come to be printed
        // beside a withheld `brotli` feature. The predicates are the single
        // authority for both surfaces, so asserting through them is what makes
        // the two provably consistent rather than coincidentally similar.
        let parts = version_parts();
        // Only `libcurl/` is unconditional now. The TLS and IDN slots became
        // derived when they were found to be the last two unconditional pushes,
        // and C gates both -- `#ifdef USE_SSL` at `lib/version.c:206-209` and
        // `#ifdef USE_IDN` at `:227-229` -- so counting them as fixed was the
        // same mistake in arithmetic form.
        let expected_len = 1 // libcurl
            + usize::from(supports_tls())
            + usize::from(crate::url::idn::available())
            + usize::from(supports_gzip())
            + usize::from(supports_brotli())
            + usize::from(supports_zstd())
            + usize::from(resolver_token_is_earned())
            + usize::from(supports_cookies())
            + usize::from(supports_ssh())
            + usize::from(supports_http2())
            + usize::from(supports_http3());
        assert_eq!(parts.len(), expected_len);

        let banner = version();
        assert_eq!(banner.contains("flate2/"), supports_gzip());
        assert_eq!(banner.contains("brotli/"), supports_brotli());
        assert_eq!(banner.contains("zstd/"), supports_zstd());
        assert_eq!(banner.contains("publicsuffix/"), supports_cookies());
        assert_eq!(banner.contains("russh/"), supports_ssh());
        assert_eq!(banner.contains("h2/"), supports_http2());
        assert_eq!(banner.contains("quinn/"), supports_http3());
        assert_eq!(banner.contains(" h3/"), supports_http3());
        assert_eq!(
            banner.contains("hickory-resolver/"),
            resolver_token_is_earned()
        );
        // Derived, not fixed, for the same reason the count above is: `idna/` is
        // emitted exactly while the implementing module answers. It IS emitted
        // today -- `url/idn.rs` is one of the present engines -- so this asserts
        // the positive case rather than merely permitting it.
        assert_eq!(banner.contains("idna/1.1.0"), crate::url::idn::available());
        assert_eq!(banner.contains("rustls/0.23.42"), supports_tls());
    }

    /// The banner and the `Features:` line may never disagree about the same
    /// capability.
    #[test]
    fn no_banner_token_contradicts_its_feature_row() {
        let parts = version_parts();

        for (token, feature) in [
            // `rustls/` and `idna/` join the list because their slots became
            // derived rather than unconditional. `rustls/` was the live
            // contradiction this test would have caught had it covered the pair:
            // the banner announced the backend while the `SSL` row withheld it.
            ("rustls/", "SSL"),
            ("flate2/", "libz"),
            ("brotli/", "brotli"),
            ("zstd/", "zstd"),
            ("idna/", "IDN"),
            ("publicsuffix/", "PSL"),
            ("russh/", "libssh2"),
            ("h2/", "HTTP2"),
            ("quinn/", "HTTP3"),
        ] {
            let in_banner = parts.iter().any(|part| part.starts_with(token));

            assert_eq!(
                in_banner,
                has_feature(feature),
                "the banner token {token} and the Features row {feature} \
                 describe one capability and must give one answer; the banner \
                 says {in_banner} and the table says {}",
                has_feature(feature)
            );
        }
    }

    #[test]
    fn the_optional_resolver_is_reported_only_when_it_is_compiled_in() {
        // The contract is that the banner names the resolver exactly when the
        // resolver is in the build, and never otherwise. Today only the second
        // half is reachable, and the reason is now the registry rather than a
        // build failure: `hickory-dns` is a declared, default-off name whose
        // engine (`ENGINE_DNS`) is absent, so `resolver_token_is_earned` is
        // false at EVERY feature setting -- including `--all-features`, which
        // this workspace can now pass. The `else` arm is therefore the one that
        // runs, and it asserts the token is absent. The `if` arm is retained
        // deliberately: it is the assertion that has to hold on the day the
        // dependency is wired in and `ENGINE_DNS` flips to present, including
        // the slot's position in the banner.
        let banner = version();
        let parts = version_parts();

        if resolver_token_is_earned() {
            assert!(
                parts.contains(&RESOLVER_TOKEN),
                "the resolver token belongs in the banner when the feature is on: {parts:?}"
            );
            assert!(banner.contains(RESOLVER_TOKEN), "{banner}");

            // Slot 6 in the C ordering: after the compression tokens, before
            // the IDN token (`lib/version.c`).
            let resolver = banner.find(RESOLVER_TOKEN).expect("token present");
            let idn = banner
                .find(IDN_TOKEN)
                .expect("idna token is always present");
            assert!(
                resolver < idn,
                "the resolver occupies the c-ares slot, ahead of the IDN token: {banner}"
            );
        } else {
            assert!(!parts.contains(&RESOLVER_TOKEN), "{parts:?}");
            assert!(!banner.contains("hickory"), "{banner}");
        }

        // Either way the C spelling stays absent, so no harness inference
        // moves: tests/runtests.pl keys c-ares detection off an "ares"
        // substring, and "hickory-resolver" contains none.
        assert!(!RESOLVER_TOKEN.to_ascii_lowercase().contains("ares"));
        assert!(!banner.to_ascii_lowercase().contains("ares"), "{banner}");
    }

    #[test]
    fn the_banner_never_names_a_library_this_build_lacks() {
        let banner = version();
        for absent in [
            "zlib/",
            "c-ares",
            "libidn2",
            "libpsl",
            "libssh2",
            "libssh/",
            "nghttp2",
            "ngtcp2",
            "nghttp3",
            "librtmp",
            "libgsasl",
            "mit-krb5",
            "libgss",
            "OpenLDAP",
            "openssl",
            "OpenSSL",
            "GnuTLS",
            "mbedTLS",
            "wolfSSL",
            "Schannel",
            "BoringSSL",
            "AWS-LC",
            "quictls",
            "libressl",
            "rustls-ffi",
            "AppleIDN",
            "WinIDN",
        ] {
            assert!(
                !banner.contains(absent),
                "{absent} must not appear in {banner}"
            );
        }

        // tests/runtests.pl:608-611 keys c-ares detection off a bare "ares"
        // substring, which would also switch the reported resolver.
        assert!(!banner.to_ascii_lowercase().contains("ares"));
    }

    #[test]
    fn the_banner_is_stable_across_calls() {
        // lib/version.c:136-141: "repeated invokes generate the exact same
        // string". Comparing pointers proves it is the same buffer.
        assert_eq!(version().as_ptr(), version().as_ptr());
        assert_eq!(version(), version());
    }

    // -- the harness's own view --------------------------------------------

    #[test]
    fn the_harness_feature_map_is_what_we_intend() {
        // Applies tests/runtests.pl:578-730's tests to the strings this module
        // actually produces. Regex-free substring and case-insensitive checks
        // are used because that is precisely what those Perl patterns reduce to
        // for the literals involved.
        let features = features_line();
        let libcurl = harness_libcurl_field();
        let lower = features.to_ascii_lowercase();

        // runtests.pl:585-586: the native rustls token cannot match its
        // `rustls-ffi` pattern, which is the accuracy trade this module makes.
        assert!(!libcurl.contains("rustls-ffi"));

        // runtests.pl:658-660: both derive from one /Debug/i match.
        assert!(!lower.contains("debug"));

        // Every name below is now the conjunction of its Cargo feature and its
        // engine. The expectations are written as those conjunctions rather
        // than as literals, so this test tracks the registry instead of
        // freezing one moment of it -- and each one still asserts the exact
        // harness pattern from the cited line.

        assert_eq!(features.contains("SSL"), ENGINE_TLS.is_present());
        assert!(!lower.contains("multissl"));
        assert!(features.contains("Largefile"));

        assert_eq!(features.contains("IDN"), ENGINE_IDN.is_present());
        assert_eq!(features.contains("IPv6"), ENGINE_CONN.is_present());
        assert_eq!(
            lower.contains("unixsockets"),
            cfg!(unix) && ENGINE_CONN.is_present()
        );
        assert_eq!(
            lower.contains("libz"),
            cfg!(feature = "gzip") && ENGINE_CONTENT_ENCODING.is_present()
        );

        assert_eq!(
            lower.contains("brotli"),
            cfg!(feature = "brotli") && ENGINE_CONTENT_ENCODING.is_present()
        );
        assert_eq!(
            lower.contains("zstd"),
            cfg!(feature = "zstd") && ENGINE_CONTENT_ENCODING.is_present()
        );
        assert_eq!(features.contains("NTLM"), ENGINE_AUTH.is_present());
        assert!(!lower.contains("ntlm_wb"));
        assert!(!lower.contains("sspi"));

        // :690-700 -- the three GSS names are compared against the RUNTIME
        // predicate and the engine, not against `cfg!(feature = "negotiate")`.
        // Since F5 the feature is necessary but not sufficient: a binary built
        // with `negotiate` on a host whose mechanism glue is unusable withholds
        // all three, which is the behaviour AAP 0.6.5 requires because
        // over-reporting turns a clean fixture skip into a hard failure. The
        // engine conjunct withholds them for a second, stronger reason while
        // `auth/negotiate.rs` has no HTTP exchange to drive. What the harness reads is the
        // banner, so the banner is what is checked, and it must agree with the
        // rows rather than with the build configuration.
        let negotiate = cfg!(feature = "negotiate")
            && ENGINE_GSS.is_present()
            && crate::ffi::gss_available();
        assert_eq!(lower.contains("gss-api"), negotiate);
        assert_eq!(lower.contains("kerberos"), negotiate);
        assert_eq!(lower.contains("spnego"), negotiate);
        assert!(!lower.contains("tls-srp"));
        assert_eq!(
            lower.contains("psl"),
            cfg!(feature = "cookies") && ENGINE_STATE_STORES.is_present()
        );
        assert_eq!(
            lower.contains("alt-svc"),
            cfg!(feature = "altsvc") && ENGINE_STATE_STORES.is_present()
        );
        assert_eq!(
            lower.contains("hsts"),
            cfg!(feature = "hsts") && ENGINE_STATE_STORES.is_present()
        );

        // :701-712 -- with AsynchDNS withheld the harness records resolver
        // "stock" rather than "threaded".
        assert_eq!(features.contains("AsynchDNS"), ENGINE_DNS.is_present());
        assert!(!features.contains("asyn-rr"));

        let over_tls = ENGINE_PROTOCOLS.is_present() && ENGINE_TLS.is_present();
        assert_eq!(
            features.contains("HTTP2"),
            cfg!(feature = "http2") && over_tls
        );
        assert_eq!(
            features.contains("HTTP3"),
            cfg!(feature = "http3") && over_tls
        );
        assert_eq!(
            features.contains("HTTPS-proxy"),
            ENGINE_PROXY.is_present() && ENGINE_TLS.is_present()
        );

        // runtests.pl:727-730.
        assert!(!lower.contains("unicode"));
        assert_eq!(
            features.contains("threadsafe"),
            ENGINE_GLOBAL_INIT.is_present()
        );
        assert!(!features.contains("HTTPSRR"));
        assert!(!features.contains("ECH"));
    }

    #[test]
    fn no_tls_library_feature_is_triggered_by_our_banner() {
        // Each of tests/runtests.pl:578-607's arms, in order. None may match:
        // this build is none of those libraries, and matching would also set
        // SSLpinning for most of them.
        let libcurl = harness_libcurl_field().to_ascii_lowercase();
        for token in [
            "schannel",
            "openssl",
            "gnutls",
            "rustls-ffi",
            "wolfssl",
            "boringssl",
            "aws-lc",
            "libressl",
            "quictls",
            "mbedtls",
        ] {
            assert!(
                !libcurl.contains(token),
                "{token} would set a TLS feature we do not have"
            );
        }
    }

    // -- the version_info payload ------------------------------------------

    #[test]
    fn the_payload_reports_the_current_age_and_identity() {
        let info = version_info();
        assert_eq!(info.age, CURLversion::NOW);
        assert_eq!(info.age, CURLversion::Twelfth);
        assert_eq!(info.version, LIBCURL_VERSION);
        assert_eq!(info.version_num, LIBCURL_VERSION_NUM);
        assert_eq!(info.host, host());
        assert_eq!(info.features, features_bitmask());
        // Derived, like the banner slot it mirrors: NULL until a backend can
        // execute (`lib/version.c:564` and `:620-623`).
        assert_eq!(
            info.ssl_version,
            if supports_tls() {
                Some(SSL_VERSION)
            } else {
                None
            }
        );
        assert_eq!(info.protocols, protocols());
        assert_eq!(info.feature_names, feature_names());
    }

    #[test]
    fn the_payload_leaves_absent_libraries_null() {
        let info = version_info();

        // "not used anymore, always 0" -- include/curl/curl.h:3117.
        assert_eq!(info.ssl_version_num, 0);

        // None, never Some("") and never a fabricated number.
        assert_eq!(info.libz_version, None);
        assert_eq!(info.ares, None);
        assert_eq!(info.ares_num, 0);
        assert_eq!(info.libidn, None);
        assert_eq!(info.iconv_ver_num, 0);
        assert_eq!(info.libssh_version, None);
        assert_eq!(info.nghttp2_version, None);
        assert_eq!(info.nghttp2_ver_num, 0);
        assert_eq!(info.gsasl_version, None);
        assert_eq!(info.rtmp_version, None);
        assert_eq!(info.cainfo, None);
        assert_eq!(info.capath, None);
    }

    #[test]
    fn the_payload_reports_the_libraries_that_are_linked() {
        let info = version_info();
        assert_eq!(info.hyper_version, Some("hyper/1.11.0"));

        // Each field is compared against its capability predicate rather than
        // against `#[cfg(feature = ...)]` blocks.
        assert_eq!(
            info.brotli_version,
            supports_brotli().then_some("brotli/8.0.4")
        );
        assert_eq!(
            info.brotli_ver_num,
            if supports_brotli() {
                packed_version_24_12(8, 0, 4)
            } else {
                0
            }
        );

        assert_eq!(info.zstd_version, supports_zstd().then_some("zstd/0.13.3"));
        assert_eq!(
            info.zstd_ver_num,
            if supports_zstd() {
                packed_version_24_12(0, 13, 3)
            } else {
                0
            }
        );

        assert_eq!(
            info.quic_version,
            supports_http3().then_some("quinn/0.11.9 h3/0.0.8")
        );

        // The packed encodings themselves, asserted unconditionally so the
        // 24-bit/12-bit layout stays pinned even while the capabilities are
        // withheld and the fields above are all `None`.
        assert_eq!(packed_version_24_12(8, 0, 4), 0x0800_0004);
        assert_eq!(packed_version_24_12(0, 13, 3), 0x0000_D003);
    }

    #[test]
    fn the_payload_is_built_once() {
        let first: *const VersionInfo = version_info();
        let second: *const VersionInfo = version_info();
        assert_eq!(first, second);
        assert_eq!(version_info(), version_info());
    }

    #[test]
    fn the_packed_encodings_match_the_c_macros() {
        // (MAJOR << 24) | (MINOR << 12) | PATCH -- curl.h:3141-3142, 3157-3158.
        assert_eq!(packed_version_24_12(1, 1, 0), 0x0100_1000);
        assert_eq!(packed_version_24_12(1, 5, 7), 0x0100_5007);
        assert_eq!(packed_version_24_12(0, 0, 0), 0);

        // (MAJOR << 16) | (MINOR << 8) | PATCH -- curl.h:3148-3149.
        assert_eq!(packed_version_16_8(1, 64, 0), 0x0001_4000);
        assert_eq!(packed_version_16_8(0, 0, 0), 0);
    }

    #[test]
    fn version_components_parses_tokens_and_rejects_junk() {
        assert_eq!(version_components("brotli/8.0.4"), Some((8, 0, 4)));
        assert_eq!(version_components("zstd/0.13.3"), Some((0, 13, 3)));
        assert_eq!(version_components("1.2.3"), Some((1, 2, 3)));
        assert_eq!(version_components("crate/1.0.0-rc.2"), None);
        assert_eq!(version_components("crate/1.0.0-alpha"), Some((1, 0, 0)));

        // Malformed input yields None, which the callers turn into 0 -- exactly
        // what the C struct carries for an absent library. Never a panic.
        assert_eq!(version_components(""), None);
        assert_eq!(version_components("crate/"), None);
        assert_eq!(version_components("crate/1"), None);
        assert_eq!(version_components("crate/1.2"), None);
        assert_eq!(version_components("crate/1.2.3.4"), None);
        assert_eq!(version_components("crate/x.y.z"), None);

        assert_eq!(leading_number("42"), Some(42));
        assert_eq!(leading_number("42abc"), Some(42));
        assert_eq!(leading_number("abc"), None);
        assert_eq!(leading_number(""), None);
    }

    // -- drift guards over the manifests -----------------------------------

    /// Extracts the exactly-pinned version of `crate_name` from `section` of a
    /// Cargo manifest, without a TOML parser: this crate has no build script
    /// and no dev-dependency on one, and the pins are one line each.
    fn pinned_version(
        manifest: &str,
        section: &str,
        crate_name: &str,
    ) -> Option<String> {
        let mut in_section = false;

        for line in manifest.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_section = trimmed == section;
                continue;
            }
            if !in_section || trimmed.starts_with('#') {
                continue;
            }

            // Split on the first '=' so that `h3-quinn` cannot be mistaken for
            // `h3`, and so a bare `name = "=x.y.z"` and a table entry parse the
            // same way.
            let Some((key, rest)) = trimmed.split_once('=') else {
                continue;
            };
            if key.trim() != crate_name {
                continue;
            }

            // The first `"=` in the remainder opens the exact version pin.
            let pin = rest.split_once("\"=")?.1;
            return pin.split('"').next().map(str::to_owned);
        }

        None
    }

    /// What the sibling C-ABI artifacts advertise, and what they withhold.
    fn ffi_capability_lists() -> (Vec<String>, Vec<String>) {
        // `include_str!` resolves relative to THIS file, so this is the sibling
        // crate's build script whatever the compilation root is.
        let source = include_str!("../../curl-rs-ffi/build.rs");

        /// The text between a slice declaration and its closing `\n];`.
        fn slice_body<'a>(source: &'a str, opening: &str) -> (&'a str, usize) {
            let head = source.find(opening).unwrap_or_else(|| {
                panic!("curl-rs-ffi/build.rs no longer declares {opening}")
            });
            // The declared length lives between the `; ` and the `]` of the
            // array type, e.g. `[Capability; 21]`.
            let semicolon =
                source[head..].find("; ").expect("array type") + head + 2;
            let bracket =
                source[semicolon..].find(']').expect("array type") + semicolon;
            let declared: usize = source[semicolon..bracket]
                .trim()
                .parse()
                .expect("array length must be a literal");

            let start =
                source[head..].find("= [").expect("array literal") + head + 3;
            let end =
                source[start..].find("\n];").expect("array terminator") + start;
            (&source[start..end], declared)
        }

        // The derivation, asserted. If the build script ever regains an
        // advertised table of its own, the two artifacts can disagree again and
        // the advertised half below stops being sound -- so that regains a
        // comparison rather than passing silently.
        assert!(
            source.contains("\"../curl-rs-lib/src/version.rs\""),
            "curl-rs-ffi/build.rs no longer reads this module, so the \
             advertised feature set is no longer derived from it"
        );
        assert!(
            !source.contains("const CAPABILITIES: [Capability;"),
            "curl-rs-ffi/build.rs has regained an advertised-capability table \
             of its own; this test must compare the two lists rather than \
             trusting the derivation"
        );

        let (held, held_len) =
            slice_body(source, "const WITHHELD: [(&str, &str);");

        // Structured positions only: the first string of each tuple. A bare
        // search for the word would match the prose, which discusses the
        // withheld tokens at length.
        let advertised: Vec<String> = feature_names()
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        let withheld: Vec<String> = held
            .split("\n    (")
            .skip(1)
            .filter_map(|rest| {
                rest.split_once('"').and_then(|(_, r)| r.split('"').next())
            })
            .map(str::to_owned)
            .collect();

        assert_eq!(
            withheld.len(),
            held_len,
            "parsed {} WITHHELD rows but the array declares {held_len}",
            withheld.len()
        );

        (advertised, withheld)
    }

    /// No name this build advertises may be one the sibling artifact withholds.
    #[test]
    fn nothing_this_build_advertises_is_withheld_by_the_ffi_artifacts() {
        let (_, withheld) = ffi_capability_lists();

        for token in &withheld {
            assert!(
                !has_feature(token),
                "{token} is advertised by curl --version but withheld from \
                 curl-config --feature and libcurl.pc"
            );
        }

        // And the converse direction, over the names actually emitted, so a new
        // WITHHELD entry for something this table advertises is caught too.
        for name in feature_names() {
            assert!(
                !withheld.iter().any(|token| token == name),
                "{name} is in the Features: line but curl-rs-ffi withholds it"
            );
        }
    }

    /// `Debug` and `TrackMemory` are withheld by BOTH artifacts, unconditionally.
    #[test]
    fn debug_and_trackmemory_are_withheld_by_both_artifacts() {
        let (advertised, withheld) = ffi_capability_lists();

        for token in ["Debug", "TrackMemory"] {
            assert!(
                !advertised.iter().any(|candidate| candidate == token),
                "{token} must not reach curl-rs-ffi's advertised set at any feature setting"
            );
            assert!(
                withheld.iter().any(|candidate| candidate == token),
                "{token} must be listed in curl-rs-ffi's WITHHELD, with its reason"
            );
            assert!(
                !has_feature(token),
                "{token} must never appear in the Features: line"
            );
        }

        // The `Debug` row exists and is withheld; withholding by absence would
        // break the 1:1 audit against lib/version.c's 32 rows.
        let debug = feature("Debug")
            .expect("the Debug row must exist for auditability");
        assert!(
            !debug.compiled_in(),
            "the Debug row must be withheld unconditionally, not gated on a feature"
        );
        assert_eq!(debug.bitmask(), CURL_VERSION_DEBUG);

        // `TrackMemory` is not a curl feature name, so it must not be a row.
        assert!(
            feature("TrackMemory").is_none(),
            "TrackMemory is derived by the harness from Debug; it is not a curl token"
        );

        // And the companion bit stays out of the mask, since no Debug capability
        // is claimed (lib/version.c:690-692 ORs CURL_VERSION_CURLDEBUG in under
        // DEBUGBUILD purely "for compatibility").
        assert_eq!(features_bitmask() & CURL_VERSION_DEBUG, 0);
    }

    #[test]
    fn library_tokens_match_the_manifest() {
        // The workspace manifest is the single place versions are declared. If
        // a pin moves and this file is not updated, the banner starts lying --
        // so the two are compared mechanically rather than by remembering to
        // look.
        let manifest = include_str!("../../Cargo.toml");
        let section = "[workspace.dependencies]";

        let expected = [
            ("rustls", rustls_version_literal!()),
            ("flate2", flate2_version_literal!()),
            ("brotli", brotli_version_literal!()),
            ("zstd", zstd_version_literal!()),
            ("idna", idna_version_literal!()),
            ("publicsuffix", publicsuffix_version_literal!()),
            ("russh", russh_version_literal!()),
            // `hickory-resolver` is deliberately NOT here. Every other literal
            // in this list names a live `[workspace.dependencies]` pin and is
            // checked against it; that one names the version the declared-but-
            // unbacked `hickory-dns` feature would pin, and the crate is absent
            // from the manifest on purpose (see the block beside
            // `RESOLVER_TOKEN` and the feature note in `lib.rs`). Asserting a
            // pin for it would demand exactly the dependency that was removed.
            ("h2", h2_version_literal!()),
            ("quinn", quinn_version_literal!()),
            ("h3", h3_version_literal!()),
            ("hyper", hyper_version_literal!()),
        ];

        for (crate_name, reported) in expected {
            let pinned = pinned_version(manifest, section, crate_name)
                .unwrap_or_else(|| {
                    panic!("no exact pin for {crate_name} in {section}")
                });
            assert_eq!(
                pinned, reported,
                "{crate_name} is pinned at {pinned} but this module reports {reported}"
            );
        }
    }

    #[test]
    fn the_libcurl_version_matches_the_workspace_metadata() {
        // [workspace.metadata.curl-rs] records the same two values, quoting
        // include/curl/curlver.h. All three must agree.
        let manifest = include_str!("../../Cargo.toml");
        let mut saw_version = false;
        let mut saw_number = false;

        for line in manifest.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("libcurl-version =") {
                assert!(
                    rest.contains(&format!("\"{LIBCURL_VERSION}\"")),
                    "workspace metadata disagrees with LIBCURL_VERSION: {trimmed}"
                );
                saw_version = true;
            }
            if let Some(rest) = trimmed.strip_prefix("libcurl-version-num =") {
                assert!(
                    rest.contains(&format!("\"{LIBCURL_VERSION_NUM:#08x}\"")),
                    "workspace metadata disagrees with LIBCURL_VERSION_NUM: {trimmed}"
                );
                saw_number = true;
            }
        }

        assert!(
            saw_version,
            "libcurl-version missing from the root manifest"
        );
        assert!(saw_number, "libcurl-version-num missing from the manifest");
    }

    #[test]
    fn idn_and_tls_are_not_optional_in_the_manifest() {
        // Several rows above are unconditional precisely because these crates
        // are plain dependencies. If one is ever made optional, its row has to
        // become feature-gated or it will over-report -- so the assumption is
        // asserted rather than assumed.
        let manifest = include_str!("../Cargo.toml");

        for crate_name in
            ["rustls", "idna", "des", "md4", "md-5", "hmac", "socket2"]
        {
            let line = manifest
                .lines()
                .map(str::trim)
                .find(|line| {
                    line.split_once('=')
                        .is_some_and(|(key, _)| key.trim() == crate_name)
                })
                .unwrap_or_else(|| {
                    panic!("{crate_name} is not declared in curl-rs-lib")
                });

            assert!(
                !line.contains("optional"),
                "{crate_name} became optional: {line}"
            );
        }
    }

    #[test]
    fn the_optional_capabilities_are_declared_as_cargo_features() {
        // Every cfg!(feature = ...) used above must name a feature that exists,
        // or it silently evaluates to false and the banner quietly shrinks.
        let manifest = include_str!("../Cargo.toml");
        for name in [
            "altsvc",
            "brotli",
            "cookies",
            "ftp",
            "gzip",
            "hsts",
            "http2",
            "http3",
            "negotiate",
            "ssh",
            "websockets",
            "zstd",
        ] {
            assert!(
                manifest
                    .lines()
                    .map(str::trim)
                    .any(|line| line.starts_with(&format!("{name} ="))),
                "the `{name}` feature is not declared in curl-rs-lib/Cargo.toml"
            );
        }
    }
}
