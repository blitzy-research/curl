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
//! This module supersedes `lib/version.c` (707 lines) and backs the two
//! exported functions `curl_version()` and `curl_version_info()`, which
//! `curl-rs-ffi/src/ffi/misc.rs` re-exports across the C ABI.
//!
//! **Nothing here is documentation.** `tests/runtests.pl` runs
//! `curl --version` during start-up and *parses* the three lines this module
//! produces, then uses the result to decide which of the 1,914 fixtures under
//! `tests/data/` are eligible to run. A wrong string does not read badly; it
//! converts a clean skip into a hard failure, or hides a real defect behind a
//! skip. Every literal below -- every capital letter, every hyphen, every
//! single space -- is part of a parsed contract and must not be "tidied".
//!
//! # Where each claim comes from
//!
//! | Fact reproduced here | Authority |
//! |----------------------|-----------|
//! | banner assembly, part order, 300-byte join | `lib/version.c:143-294` |
//! | `supported_protocols[]`, 33 lowercase entries | `lib/version.c:296-397` |
//! | the three runtime presence predicates | `lib/version.c:399-433` |
//! | `FEATURE()` macro and `struct feat` | `lib/version.c:435-448` |
//! | the 32-row features table | `lib/version.c:450-554` |
//! | `curl_version_info()` and its bitmask loop | `lib/version.c:556-706` |
//! | version identity macros | `include/curl/curlver.h:31-76` |
//! | `curl_version_info_data`, 12 ages, 31 bits | `include/curl/curl.h:3088-3211` |
//! | the TLS token the harness matches | `lib/vtls/rustls.c:1377-1381` |
//! | **the consumer** | `tests/runtests.pl:520-730` |
//!
//! Those line ranges were measured in this tree rather than copied, so a few
//! differ by a line or two from the anchors the specification quotes. Both are
//! recorded here so neither a reader following the specification nor a reader
//! grepping this tree is left hunting. The specification cites
//! `lib/version.c:145-290` for banner assembly (`curl_version()` in fact opens
//! at `:145` and closes at `:294`, and `VERSION_PARTS` is declared just above
//! it at `:143`), `lib/version.c:302` for `supported_protocols[]` (the array
//! opens at `:296` and its 33 entries run to `:397`),
//! `lib/version.c:442` for the `FEATURE()` macro (`:442` exactly, with
//! `struct feat` immediately after at `:444-448`), `lib/version.c:452-551` for
//! the 32 rows (the table statement spans `:450-554` including its opening line
//! and its `{NULL, NULL, 0}` terminator), `lib/version.c:567` for the
//! `curl_version_info` wiring (the static initialiser spans `:558-594` and the
//! function itself `:596-706`), `include/curl/curlver.h` for version identity,
//! `include/curl/curl.h:3112-3211` for the payload struct and the bits (the
//! `CURLversion` ages that precede them start at `:3088`, so the range quoted
//! above opens there), and `tests/runtests.pl:565-730` as the consumer (the
//! `--version` invocation that feeds it is at `:520-527`, which is why the
//! range quoted above opens at `:520`).
//!
//! # The governing principle: under-report, never over-report
//!
//! 874 of the 1,914 fixtures gate on `<features>`. The asymmetry is decisive
//! (AAP 0.6.5):
//!
//! > Under-reporting a capability makes a fixture skip; over-reporting makes
//! > it run and fail. Truthful advertisement is therefore the optimal
//! > strategy, not merely the honest one.
//!
//! So every row of the tables below reports what this build genuinely has.
//! Where a capability cannot be asserted truthfully from this module, the row
//! is withheld and the reason is written down next to it. Nothing is
//! fabricated to unlock a fixture, and no version number is invented: every
//! library version reported here is the version of the **Rust crate** that
//! implements the capability, exactly as pinned in the workspace manifest's
//! `[workspace.dependencies]`, and `tests::library_tokens_match_the_manifest`
//! re-reads that manifest to prove it still does.
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
//!   held; display order is `curl-rs/src/cli/help.rs`'s business.
//!
//! # Three deliberate omissions, each with its measured cost
//!
//! ## 1. The TLS token says `rustls`, not `rustls-ffi` (AAP 0.8.6/A8)
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
//! emitting `rustls-ffi/...` would misdescribe it. AAP 0.8.6/A8 resolves the
//! trade-off in favour of accuracy, and [`SSL_VERSION`] is therefore
//! `rustls/<crate version>`, which does not match the pattern.
//!
//! The measured cost is **zero fixtures**: exactly one fixture in
//! `tests/data/` mentions `rustls` at all and it is `%if !rustls`, which
//! requires the feature to be *absent*. Accuracy makes that one eligible
//! rather than skipped. Ten fixtures require `SSLpinning`, which the rustls
//! arm deliberately never sets -- identical to a C rustls build, so parity,
//! not a deviation. And `$feature{"SSL"}` is set from the **Features** line
//! (`/SSL/i`, `tests/runtests.pl:662`), not from the banner token, so the 138
//! SSL-gated fixtures stay eligible regardless. That is what makes the
//! accuracy choice affordable. **Do not "fix" this by faking the FFI token.**
//!
//! ## 2. `Debug` is never emitted (AAP 0.6.6)
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
//! decision AAP 0.6.6 records, because a Rust allocator's call counts cannot
//! match a C one's. **The cost, stated as required: 98 fixtures require
//! `Debug` and will skip, and `make torture-test` is inapplicable** -- it
//! hard-requires the feature and dies without it
//! (`tests/runtests.pl:846-849`).
//!
//! The row below is a literal `false` rather than a gate on the `memdebug`
//! Cargo feature, and that is deliberate. `memdebug` supplies only the
//! allocation log that `tests/memanalyzer.pm` parses; a C `DEBUGBUILD`
//! additionally changes internal behaviour that the 98 `Debug` fixtures
//! exercise. Advertising `Debug` because allocation tracking is on would be
//! over-reporting in exactly the way AAP 0.6.5 warns against, so the token
//! stays withheld even under `--all-features`.
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
//! # Nine schemes, twenty-four withheld
//!
//! [`PROTOCOLS`] advertises only the nine schemes this implementation serves.
//! The other 24 registered schemes (`dict`, `gopher`, `gophers`, `imap`,
//! `imaps`, `ldap`, `ldaps`, `mqtt`, `mqtts`, `pop3`, `pop3s`, `rtmp`,
//! `rtmpe`, `rtmps`, `rtmpt`, `rtmpte`, `rtmpts`, `rtsp`, `smb`, `smbs`,
//! `smtp`, `smtps`, `telnet`, `tftp`) are never named, so their 283 fixtures
//! -- 14.8% of the corpus -- skip cleanly instead of running and failing
//! (AAP 0.2.2, 0.6.5). Their `CURLPROTO_*` constants remain in the public
//! header and a request for one still returns `CURLE_UNSUPPORTED_PROTOCOL`
//! from `crate::protocols`' stub registration; that is a separate concern
//! from the banner and is not this module's business.
//!
//! # Version identity is frozen
//!
//! [`LIBCURL_VERSION`] is `8.19.0-DEV` and [`LIBCURL_VERSION_NUM`] is
//! `0x081300`, measured at `include/curl/curlver.h:35` and `:61`. AAP 0.8.5/C6
//! binds every parity claim in this work to curl/libcurl 8.19.0-DEV at commit
//! `54cf587b9c`, so **nothing here may bump them**. This module is also the
//! single place the workspace spells the version: the default `User-Agent`
//! that `src/config2setopts.c:906-907` builds as `CURL_NAME "/" CURL_VERSION`
//! is [`DEFAULT_USER_AGENT`], and the fixtures' `%VERSION` substitution
//! (AAP 0.6.7) only matches if the request bytes and the banner agree.
//!
//! # Safety
//!
//! Nothing in this module needs `unsafe`, and none is present:
//! `#![forbid(unsafe_code)]` at the crate root (AAP 0.1.1 G6) covers it with
//! no exemption. The C original's `static char out[300]` and its manual
//! `memcpy` loop become a [`String`] behind a [`OnceLock`], which is what
//! makes "repeated invokes generate the exact same string" (`lib/version.c:
//! 136-141`) a type-level guarantee rather than a convention.
//!
//! # Language floor
//!
//! Edition 2021 and the mandated minimum supported Rust version of 1.75
//! (AAP 0.8.3, `rust-version` in the workspace manifest, `msrv` in
//! `clippy.toml`). This is not aspirational: `cargo +1.75.0 check` and
//! `cargo +1.75.0 test -p curl-rs-lib` both pass over this module, with and
//! without default features. The newest constructs used are let-else (1.65),
//! `Option::is_some_and` (1.70), inline format arguments (1.58) and `assert!`
//! in a `const` item (1.57), so anything reached for here in future must clear
//! the same bar.

use core::ffi::{c_int, c_long, c_uint};
use std::sync::OnceLock;

// ===========================================================================
// Version identity
//
// Every literal in this block is measured from include/curl/curlver.h, which
// the C build treats as its single version oracle: CMakeLists.txt:54-65 greps
// LIBCURL_VERSION out of that header and feeds the semantic prefix to
// project(CURL VERSION ...). AAP 0.8.5/C6 freezes all of it.
//
// Each value appears exactly ONCE, as the body of a private macro, so that
// concat! can build the derived tokens at compile time without the version
// being written twice anywhere in the workspace.
// ===========================================================================

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
/// Frozen by AAP 0.8.5/C6. The test suite substitutes this string into fixture
/// expectations through its `%VERSION` placeholder, so a change here changes
/// the expected bytes of 1,476 wire comparisons.
pub const LIBCURL_VERSION: &str = libcurl_version_literal!();

/// `LIBCURL_VERSION_MAJOR` -- `8` (`include/curl/curlver.h:39`).
pub const LIBCURL_VERSION_MAJOR: c_uint = 8;

/// `LIBCURL_VERSION_MINOR` -- `19` (`include/curl/curlver.h:40`).
pub const LIBCURL_VERSION_MINOR: c_uint = 19;

/// `LIBCURL_VERSION_PATCH` -- `0` (`include/curl/curlver.h:41`).
pub const LIBCURL_VERSION_PATCH: c_uint = 0;

/// `LIBCURL_VERSION_NUM` -- `0x081300` (`include/curl/curlver.h:61`).
///
/// The header is explicit that this is written as a full literal rather than
/// through [`version_bits`], because "curl's own configure script greps for it
/// and needs it to contain the full number" (`include/curl/curlver.h:57-59`).
/// `tests::version_num_agrees_with_its_parts` asserts the two agree.
pub const LIBCURL_VERSION_NUM: c_uint = 0x0008_1300;

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
///
/// The command-line tool applies this when `--user-agent` is absent, and
/// `crate::protocols::http1` must emit precisely these bytes: the fixtures
/// compare the full request as one string with header order significant
/// (AAP 0.6.7), so the `User-Agent` value is wire-visible. Consuming this
/// constant is what keeps the version from being spelled twice in the
/// workspace.
pub const DEFAULT_USER_AGENT: &str = concat!(curl_name_literal!(), "/", libcurl_version_literal!());

/// `CURL_VERSION_BITS(x, y, z)` -- `include/curl/curlver.h:74`.
///
/// ```text
/// #define CURL_VERSION_BITS(x, y, z) ((x) << 16 | (y) << 8 | (z))
/// ```
///
/// The shifts are performed on [`c_uint`] so that the result is directly
/// comparable with [`LIBCURL_VERSION_NUM`]. Components wider than eight bits
/// would overlap, exactly as they do in C; the C macro is equally unchecked,
/// and reproducing that is deliberate -- this is a parity surface, not a place
/// to add validation the callers of the C macro never had.
#[must_use]
pub const fn version_bits(x: c_uint, y: c_uint, z: c_uint) -> c_uint {
    (x << 16) | (y << 8) | z
}

/// `CURL_AT_LEAST_VERSION(x, y, z)` -- `include/curl/curlver.h:75-76`.
///
/// True when the version reported by this build is at least `x.y.z`.
#[must_use]
pub const fn at_least_version(x: c_uint, y: c_uint, z: c_uint) -> bool {
    LIBCURL_VERSION_NUM >= version_bits(x, y, z)
}

// ===========================================================================
// Host triple -- the Rust counterpart of CURL_OS
//
// The C build bakes in a string: configure substitutes the autoconf ${host}
// triple (configure.ac:505) and CMake substitutes CMAKE_C_COMPILER_TARGET or
// CMAKE_SYSTEM_NAME (CMakeLists.txt:147-149). Cargo has no equivalent
// substitution and this crate deliberately has no build script (its manifest
// says so), so the triple is composed from the target configuration instead.
//
// Composition rather than a table of literals is the point: it is correct for
// every target, including ones outside the four-target matrix, and it cannot
// go stale. For the four mandated targets it yields exactly their triples:
//
//     x86_64-unknown-linux-gnu     aarch64-unknown-linux-gnu
//     x86_64-apple-darwin          aarch64-apple-darwin
//
// One harness consequence makes this load-bearing rather than cosmetic. This
// string is printed before the "libcurl" token, and tests/runtests.pl:563-570
// matches that prefix against /win32|Windows|windows|mingw(32|64)/ and
// /cygwin|msys/i to decide whether to switch to Windows-style paths. On the
// mandated targets it must match neither, and
// tests::host_triple_is_shaped_like_the_c_string asserts that.
// ===========================================================================

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
///
/// This is what [`VersionInfo::host`] carries and what the command-line tool
/// prints inside the parentheses of its first `--version` line, which
/// `src/tool_version.h:34` assembles as
/// `CURL_NAME " " CURL_VERSION " (" CURL_OS ") "`.
///
/// The operating-system component follows the triple's spelling rather than
/// Rust's: Rust reports `macos` where every Apple target triple says `darwin`,
/// and the translation happens here so that callers never have to know.
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

// ===========================================================================
// The 31 CURL_VERSION_* bits -- include/curl/curl.h:3175-3211
//
// Transcribed value by value. The C declarations are `int` macros and the
// struct field they populate is `int features`, so every constant here is
// c_int; the highest bit used is 1<<30, which is why a signed representation
// is sufficient and why no bit may ever be added at 1<<31.
//
// Five are deprecated in the header and are reproduced anyway. They cost
// nothing, they keep this vocabulary complete for curl-rs-ffi, and
// tests/test1177.pl checks that every CURL_VERSION_ bit in the header is
// documented -- a check that presumes the full set exists.
// ===========================================================================

/// IPv6-enabled.
pub const CURL_VERSION_IPV6: c_int = 1 << 0;
/// Kerberos V4 auth is supported (deprecated in the header).
pub const CURL_VERSION_KERBEROS4: c_int = 1 << 1;
/// SSL options are present.
pub const CURL_VERSION_SSL: c_int = 1 << 2;
/// libz features are present.
pub const CURL_VERSION_LIBZ: c_int = 1 << 3;
/// NTLM auth is supported.
pub const CURL_VERSION_NTLM: c_int = 1 << 4;
/// Negotiate auth is supported (deprecated in the header).
pub const CURL_VERSION_GSSNEGOTIATE: c_int = 1 << 5;
/// Built with debug capabilities.
pub const CURL_VERSION_DEBUG: c_int = 1 << 6;
/// Asynchronous DNS resolves.
pub const CURL_VERSION_ASYNCHDNS: c_int = 1 << 7;
/// SPNEGO auth is supported.
pub const CURL_VERSION_SPNEGO: c_int = 1 << 8;
/// Supports files larger than 2GB.
pub const CURL_VERSION_LARGEFILE: c_int = 1 << 9;
/// Internationalized domain names are supported.
pub const CURL_VERSION_IDN: c_int = 1 << 10;
/// Built against Windows SSPI.
pub const CURL_VERSION_SSPI: c_int = 1 << 11;
/// Character conversions supported (deprecated in the header).
pub const CURL_VERSION_CONV: c_int = 1 << 12;
/// Debug memory tracking supported (deprecated in the header).
pub const CURL_VERSION_CURLDEBUG: c_int = 1 << 13;
/// TLS-SRP auth is supported.
pub const CURL_VERSION_TLSAUTH_SRP: c_int = 1 << 14;
/// NTLM delegation to the winbind helper is supported (deprecated).
pub const CURL_VERSION_NTLM_WB: c_int = 1 << 15;
/// HTTP/2 support built in.
pub const CURL_VERSION_HTTP2: c_int = 1 << 16;
/// Built against a GSS-API library.
pub const CURL_VERSION_GSSAPI: c_int = 1 << 17;
/// Kerberos V5 auth is supported.
pub const CURL_VERSION_KERBEROS5: c_int = 1 << 18;
/// Unix domain socket support.
pub const CURL_VERSION_UNIX_SOCKETS: c_int = 1 << 19;
/// Mozilla's Public Suffix List, used for cookie domain verification.
pub const CURL_VERSION_PSL: c_int = 1 << 20;
/// HTTPS-proxy support built in.
pub const CURL_VERSION_HTTPS_PROXY: c_int = 1 << 21;
/// Multiple SSL backends available.
pub const CURL_VERSION_MULTI_SSL: c_int = 1 << 22;
/// Brotli features are present.
pub const CURL_VERSION_BROTLI: c_int = 1 << 23;
/// Alt-Svc handling built in.
pub const CURL_VERSION_ALTSVC: c_int = 1 << 24;
/// HTTP/3 support built in.
pub const CURL_VERSION_HTTP3: c_int = 1 << 25;
/// zstd features are present.
pub const CURL_VERSION_ZSTD: c_int = 1 << 26;
/// Unicode support on Windows.
pub const CURL_VERSION_UNICODE: c_int = 1 << 27;
/// HSTS is supported.
pub const CURL_VERSION_HSTS: c_int = 1 << 28;
/// libgsasl is supported.
pub const CURL_VERSION_GSASL: c_int = 1 << 29;
/// The libcurl API is thread-safe.
pub const CURL_VERSION_THREADSAFE: c_int = 1 << 30;

// ===========================================================================
// CURLversion -- include/curl/curl.h:3088-3109
// ===========================================================================

/// `CURLversion` -- which generation of [`VersionInfo`] a caller expects.
///
/// Twelve ages have been declared since 7.10, each adding fields to
/// `curl_version_info_data` and none ever removing one. A caller compiled
/// against an older header passes its own age and reads only the prefix of the
/// struct it knows about, which is why the field order in [`VersionInfo`] is
/// itself part of the ABI.
///
/// # No `Last` variant
///
/// `include/curl/curl.h:3101` annotates `CURLVERSION_LAST` as "never actually
/// use this". Following `crate::multi::state`'s treatment of `MSTATE_LAST`, a
/// value that must never be used is not made constructible here: the sentinel
/// survives as the integers [`Self::LAST`] and [`Self::COUNT`], so a caller
/// that needs the bound still has it while every `match` over this type covers
/// only real ages.
///
/// `curl_version_info()` ignores its argument entirely (`(void)stamp;`,
/// `lib/version.c:619`) and always returns the current struct. This type
/// exists so that `curl-rs-ffi` can name the ages, and so that
/// [`VersionInfo::age`] reports [`Self::NOW`] rather than a bare integer.
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
    pub const LAST: c_int = 12;

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
    pub const fn as_c_int(self) -> c_int {
        self as c_int
    }

    /// Recovers an age from the integer, or `None` for one that names no age.
    ///
    /// `CURLVERSION_LAST` deliberately yields `None`: it is a bound, not a
    /// value, so a caller that passes it is passing something meaningless and
    /// the boundary layer should be able to see that.
    #[must_use]
    pub const fn from_c_int(raw: c_int) -> Option<Self> {
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

// ===========================================================================
// Library tokens
//
// The C banner names each linked library and its version: "zlib/1.3.1",
// "brotli/1.1.0", "libidn2/2.3.8" and so on (lib/version.c:205-271). This
// build links none of those C libraries, so every token below names the Rust
// crate that does the same job and reports THAT crate's version. Two rules
// govern the block, both from AAP 0.6.5's under-report-never-over-report
// asymmetry and the agent brief's "if nothing truthful can be said, omit the
// part; do not fabricate a version":
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
// ===========================================================================

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
/// without inventing a value (AAP 0.1.1 G4).
pub const TLS_BACKEND_ID: c_int = 14;

/// The pinned version of the TLS implementation.
pub const RUSTLS_VERSION: &str = rustls_version_literal!();

/// The TLS version string: `rustls/0.23.42`.
///
/// This is the second part of the banner and the value of
/// [`VersionInfo::ssl_version`], matching the C build where
/// `Curl_ssl_version()` fills the buffer from the backend alone with no prefix
/// of its own (`lib/vtls/vtls.c:600-607`).
///
/// It intentionally does **not** match `tests/runtests.pl:585-586`'s
/// `/\srustls-ffi\b/i`. See this module's documentation for the measured cost
/// of that choice, which is zero fixtures.
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
const PSL_TOKEN: &str = concat!("publicsuffix", "/", publicsuffix_version_literal!());

/// The SSH token: `russh/0.54.5`.
///
/// Deliberately not spelled `libssh2/...` or `libssh/x.y/`, both of which
/// `tests/runtests.pl:625-647` recognises and neither of which is what this
/// build links. The second of those two also switches on host-key-checking
/// leniency detection, so a false match would change harness behaviour.
const SSH_TOKEN: &str = concat!("russh", "/", russh_version_literal!());

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
///
/// Reported through [`VersionInfo::hyper_version`] rather than as a banner
/// part, because the C banner has no hyper slot -- `version_info.hyper_version`
/// is the field the C tree reserved for it (`include/curl/curl.h:3163-3164`),
/// and it is left NULL there. Populating it is truthful: this implementation
/// genuinely uses hyper for HTTP/1.1 connection management, keep-alive and
/// framing.
///
/// Harness-neutrality was measured, not assumed, because populating a field the
/// C tree leaves NULL is exactly the kind of change that could turn a skip into
/// a failure: a case-insensitive search for `hyper` finds 0 of the 1,914
/// fixtures under `tests/data/`, 0 lines across `tests/runtests.pl` and the
/// harness `.pm` modules, and 0 of the 129 programs under `docs/examples/`. The
/// only mention anywhere is the field's own declaration in
/// `docs/libcurl/curl_version_info.md:101`. The choice is therefore decided
/// purely on accuracy.
const HYPER_TOKEN: &str = concat!("hyper", "/", hyper_version_literal!());

/// Encodes a version the way Brotli and Zstandard are encoded in
/// `curl_version_info_data`: `(MAJOR << 24) | (MINOR << 12) | PATCH`.
///
/// Measured at `include/curl/curl.h:3141-3142` and `:3157-3158`. The C build
/// obtains these numbers from `BrotliDecoderVersion()` and
/// `ZSTD_versionNumber()`; here they are computed from the same crate versions
/// the corresponding token reports, so the number and the string can never
/// disagree.
#[must_use]
const fn packed_version_24_12(major: c_uint, minor: c_uint, patch: c_uint) -> c_uint {
    (major << 24) | (minor << 12) | patch
}

/// Encodes a version the way nghttp2 is encoded in `curl_version_info_data`:
/// `(MAJOR << 16) | (MINOR << 8) | PATCH` (`include/curl/curl.h:3148-3149`).
///
/// Retained for completeness of the payload's contract even though this build
/// reports no nghttp2 version: `curl-rs-ffi` and any future HTTP/2 reporting
/// must use this encoding and not invent another.
#[must_use]
const fn packed_version_16_8(major: c_uint, minor: c_uint, patch: c_uint) -> c_uint {
    (major << 16) | (minor << 8) | patch
}

/// Whether the TLS backend can tunnel through an HTTPS proxy.
///
/// The C counterpart is `https_proxy_present()` (`lib/version.c:420-424`),
/// which asks the backend directly via
/// `Curl_ssl_supports(NULL, SSLSUPP_HTTPS_PROXY)`. The C rustls backend
/// declares that capability in its own support mask
/// (`lib/vtls/rustls.c:1399-1405`), and this implementation provides it in
/// `crate::proxy::http_connect`, which layers a rustls session over the
/// CONNECT tunnel for both HTTP/1 and HTTP/2 proxies.
///
/// TLS is not optional in this crate -- `rustls` is a plain dependency, not a
/// feature-gated one -- so the answer is constant for a given build rather
/// than genuinely dynamic. It stays a function because the C table stores a
/// function pointer here, and because the honest place to consult a backend
/// capability is a call, not a literal at the call site.
#[must_use]
fn tls_supports_https_proxy() -> bool {
    true
}

/// Whether the TLS backend supports Encrypted Client Hello.
///
/// The C counterpart is `ech_present()` (`lib/version.c:428-432`). The C
/// rustls-ffi backend sets `SSLSUPP_ECH`, but that says nothing about this
/// build: `rustls` is pinned with `default-features = false` and the feature
/// list `["ring", "std", "tls12", "logging"]`, which does not include ECH, and
/// `crate::tls` exposes no ECH configuration. Claiming it would make the two
/// ECH-gated fixtures run and fail instead of skipping.
#[must_use]
fn tls_supports_ech() -> bool {
    false
}

/// Whether an internationalized-domain-name implementation is present.
///
/// The C counterpart is `idn_present()` (`lib/version.c:407-415`), which has
/// two branches: for libidn2 it reports `info->libidn != NULL`, and for the
/// Windows and Apple IDN backends it returns true unconditionally because
/// those have no version string to publish. This build follows the second
/// branch -- `idna` is a plain, non-optional dependency of this crate, and
/// [`VersionInfo::libidn`] is `None` precisely because libidn2 is *not* what
/// is linked.
///
/// `tests::idn_and_tls_are_not_optional_in_the_manifest` asserts that the
/// manifest still declares `idna` without `optional = true`, so if that ever
/// changes this row must be gated rather than silently over-report.
#[must_use]
fn idn_present() -> bool {
    true
}

// ===========================================================================
// The features table -- lib/version.c:435-554
//
// The C declaration this reproduces:
//
//   #define FEATURE(name, present, bitmask) { (name), (present), (bitmask) }
//
//   struct feat {
//     const char *name;
//     int        (*present)(curl_version_info_data *info);
//     int        bitmask;
//   };
//
// Two things about the reproduction are deliberate and must not be "improved".
//
// ROW ORDER IS THE C SOURCE ORDER, NOT ALPHABETICAL ORDER. The C table's
// comment says "Keep the features alphabetically sorted", and 30 of its 32
// rows are; AppleSecTrust and NativeCA are not, because they sit inside the
// `#ifdef USE_SSL` block between PSL and SPNEGO (lib/version.c:519-525). This
// table carries the same anomaly at the same position. The order is what
// curl_version_info()->feature_names has always held, and the command-line
// tool re-sorts for display anyway (src/tool_help.c:372-373).
//
// EVERY ONE OF THE 32 ROWS IS PRESENT, including the ones this build cannot
// have. A row whose C `#if` is false for this build carries `compiled_in:
// false` and states why on the spot. That keeps the table auditable 1:1
// against lib/version.c -- a reviewer can diff 32 rows against 32 rows -- and
// it puts each withholding decision next to the name it withholds instead of
// leaving a silent gap that looks like an oversight.
// ===========================================================================

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
///
/// The C `struct feat` has three fields; this has four, because C expresses
/// one of them in the preprocessor. `#ifdef USE_SSL` around a `FEATURE(...)`
/// row decides at compile time whether the row exists at all, and
/// [`Self::compiled_in`] is that decision made explicit. Keeping it as data
/// rather than as `#[cfg]` attributes on the rows means the table is always 32
/// rows long, is always fully type-checked, and can be tested under any
/// feature combination.
#[derive(Clone, Copy, Debug)]
pub struct Feature {
    /// The name as it appears in the `Features:` line. Casing is contractual.
    name: &'static str,

    /// The `CURL_VERSION_*` bit this name contributes, or `0` for the five
    /// names that have no bit.
    bitmask: c_int,

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
    pub const fn bitmask(&self) -> c_int {
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
///
/// `PartialEq` is written by hand rather than derived because the derive would
/// compare the `present` function pointers, and comparing function addresses is
/// not meaningful: the same function can have different addresses in different
/// codegen units, and distinct functions can share one address after the linker
/// merges identical bodies. Rust warns about exactly that
/// (`unpredictable_function_pointer_comparisons`), and the workspace builds
/// with warnings denied.
///
/// A row's identity is its name, its bit and whether it is compiled in. Two
/// rows carrying the same three values describe the same capability whichever
/// predicate function they happen to point at, so this is also the comparison
/// a caller actually wants.
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
    // HTTP Alt-Svc handling: crate::cookies::altsvc.
    Feature {
        name: "alt-svc",
        bitmask: CURL_VERSION_ALTSVC,
        compiled_in: cfg!(feature = "altsvc"),
        present: None,
    },
    // WITHHELD. C requires c-ares AND a threaded resolver AND HTTPSRR
    // (lib/version.c:454). c-ares is dropped for the system resolver
    // (AAP 0.5.2), so the conjunction cannot hold. The name also feeds
    // tests/runtests.pl:702-712, where it decides whether AsynchDNS still
    // counts as "real" c-ares; claiming it would corrupt that inference.
    Feature {
        name: "asyn-rr",
        bitmask: 0,
        compiled_in: false,
        present: None,
    },
    // The resolver is genuinely asynchronous: crate::dns::resolver runs
    // lookups on the tokio runtime, and the alarm()/sigsetjmp() deadline of
    // lib/hostip.c is replaced by tokio::time::timeout (AAP 0.6.9). The
    // harness reads this name and, seeing no c-ares token in the banner, sets
    // threaded-resolver and resolver="threaded" (tests/runtests.pl:702-712) --
    // which is an accurate description of a runtime that resolves off the
    // calling task.
    Feature {
        name: "AsynchDNS",
        bitmask: CURL_VERSION_ASYNCHDNS,
        compiled_in: true,
        present: None,
    },
    // Brotli decoding: crate::transfer::content_encoding via the brotli crate.
    Feature {
        name: "brotli",
        bitmask: CURL_VERSION_BROTLI,
        compiled_in: cfg!(feature = "brotli"),
        present: None,
    },
    // WITHHELD, DELIBERATELY, AND NEVER GATED ON ANY FEATURE (AAP 0.6.6).
    // A literal `false`, not `cfg!(feature = "memdebug")`: memdebug supplies
    // only the allocation log that tests/memanalyzer.pm parses, whereas a C
    // DEBUGBUILD also changes internal behaviour that the 98 Debug-gated
    // fixtures exercise. Because tests/runtests.pl:658-660 derives both
    // TrackMemory and Debug from this single name, advertising it would switch
    // on allocation-cap and leak checking AND make those 98 fixtures run --
    // the exact over-reporting AAP 0.6.5 forbids. Cost of withholding, stated:
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
        compiled_in: true,
        present: Some(tls_supports_ech),
    },
    // WITHHELD. libgsasl is dropped along with the SASL protocols it served
    // (AAP 0.5.2); SMTP, IMAP and POP3 are out of scope entirely.
    Feature {
        name: "gsasl",
        bitmask: CURL_VERSION_GSASL,
        compiled_in: false,
        present: None,
    },
    // GSS-API, behind the non-default `negotiate` feature, whose binding is
    // confined to crate::ffi::gss (AAP 0.8.5/C2). Off by default, so the
    // default build links no C security library at all.
    Feature {
        name: "GSS-API",
        bitmask: CURL_VERSION_GSSAPI,
        compiled_in: cfg!(feature = "negotiate"),
        present: None,
    },
    // HTTP Strict Transport Security: crate::cookies::hsts.
    Feature {
        name: "HSTS",
        bitmask: CURL_VERSION_HSTS,
        compiled_in: cfg!(feature = "hsts"),
        present: None,
    },
    // HTTP/2 over ALPN: crate::protocols::http2 via the h2 crate.
    Feature {
        name: "HTTP2",
        bitmask: CURL_VERSION_HTTP2,
        compiled_in: cfg!(feature = "http2"),
        present: None,
    },
    // HTTP/3 over QUIC: crate::protocols::http3 via quinn and h3.
    Feature {
        name: "HTTP3",
        bitmask: CURL_VERSION_HTTP3,
        compiled_in: cfg!(feature = "http3"),
        present: None,
    },
    // Tunnelling through an HTTPS proxy. Compiled in because TLS is
    // unconditional here; the capability question is delegated to the backend
    // exactly as C delegates it (lib/version.c:420-424).
    Feature {
        name: "HTTPS-proxy",
        bitmask: CURL_VERSION_HTTPS_PROXY,
        compiled_in: true,
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
    // The predicate mirrors the C one; see idn_present().
    Feature {
        name: "IDN",
        bitmask: CURL_VERSION_IDN,
        compiled_in: true,
        present: Some(idn_present),
    },
    // IPv6 is unconditional: crate::conn uses socket2 and tokio, both of which
    // support IPv6 on every target in the matrix, and crate::conn::happy_
    // eyeballs races the two families against each other.
    Feature {
        name: "IPv6",
        bitmask: CURL_VERSION_IPV6,
        compiled_in: true,
        present: None,
    },
    // Kerberos V5, reachable only through GSS-API, so gated identically.
    Feature {
        name: "Kerberos",
        bitmask: CURL_VERSION_KERBEROS5,
        compiled_in: cfg!(feature = "negotiate"),
        present: None,
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
        compiled_in: cfg!(feature = "gzip"),
        present: None,
    },
    // WITHHELD, UNCONDITIONALLY. There is exactly one TLS backend (AAP 0.8.2
    // forbids any other), so multiple-backend selection does not exist here.
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
        compiled_in: true,
        present: None,
    },
    // The Public Suffix List, used for cookie-domain verification. Gated on
    // `cookies` because that is the feature which pulls in publicsuffix; there
    // is no separate switch, and a PSL with no cookie jar to guard would be
    // advertising a capability with nothing to apply it to.
    Feature {
        name: "PSL",
        bitmask: CURL_VERSION_PSL,
        compiled_in: cfg!(feature = "cookies"),
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
    // SPNEGO, reachable only through GSS-API, so gated identically.
    Feature {
        name: "SPNEGO",
        bitmask: CURL_VERSION_SPNEGO,
        compiled_in: cfg!(feature = "negotiate"),
        present: None,
    },
    // TLS. Unconditional: rustls is a plain dependency of this crate, and
    // certificate validation is on by default (AAP 0.8.1). 138 fixtures gate
    // on this name, and tests/runtests.pl:662 reads it from the Features line
    // rather than from the banner token -- which is what makes the accurate
    // rustls token affordable.
    Feature {
        name: "SSL",
        bitmask: CURL_VERSION_SSL,
        compiled_in: true,
        present: None,
    },
    // WITHHELD. TLS session import and export is off by default in the
    // reference build too (CMakeLists.txt:1076 defines the option as OFF, and
    // the docs call it experimental: docs/cmdline-opts/ssl-sessions.md:39).
    // There is no Cargo feature for it and this module cannot verify that
    // crate::tls::session_cache implements the serialisation, so parity with
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
    // The API is thread-safe. This is structural rather than configured: the
    // engine holds no process-global mutable state, `#![forbid(unsafe_code)]`
    // makes unsynchronised shared mutation unrepresentable, and global
    // initialisation is idempotent -- so the C GLOBAL_INIT_IS_THREADSAFE
    // condition (lib/version.c:538) is met by construction.
    Feature {
        name: "threadsafe",
        bitmask: CURL_VERSION_THREADSAFE,
        compiled_in: true,
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
        compiled_in: cfg!(unix),
        present: None,
    },
    // Zstandard decoding: crate::transfer::content_encoding via the zstd crate.
    Feature {
        name: "zstd",
        bitmask: CURL_VERSION_ZSTD,
        compiled_in: cfg!(feature = "zstd"),
        present: None,
    },
];

/// The names this build advertises, in C table order.
///
/// This is `curl_version_info_data::feature_names`, which
/// `include/curl/curl.h:3170` documents as "terminated by an entry with a NULL
/// feature name". The terminator belongs to the C view of the array and is
/// added by `curl-rs-ffi`; a Rust slice carries its own length.
///
/// The command-line tool consumes this array directly when the reported age is
/// at least [`CURLversion::Eleventh`] (`src/tool_libinfo.c:145-147`), falling
/// back to rebuilding the names from the bitmask otherwise -- one more reason
/// the two projections must agree.
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
/// `lib/version.c:682-695` builds the mask and the name array in one loop, and
/// this function walks the same table with the same predicate, so the mask can
/// only ever contain bits belonging to advertised names.
///
/// The C code additionally ORs in `CURL_VERSION_CURLDEBUG` under `DEBUGBUILD`
/// "for compatibility" (`lib/version.c:690-692`). That bit is deliberately
/// absent here: no `Debug` capability is advertised, so claiming its companion
/// bit would contradict the name list.
#[must_use]
pub fn features_bitmask() -> c_int {
    FEATURES
        .iter()
        .filter(|feature| feature.is_present())
        .fold(0, |mask, feature| mask | feature.bitmask())
}

/// Whether a named feature is advertised, compared case-sensitively.
///
/// Case matters: `Debug` and `debug` are not the same claim, and the harness's
/// own matching is deliberately loose in ways this API should not imitate.
///
/// Answered from the table rather than from the emitted name list, so that this
/// predicate, `feature_names` and `features_bitmask` are all projections of the
/// same 32 rows and cannot disagree.
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

// ===========================================================================
// The protocol table -- lib/version.c:296-397
//
// Nine rows, not 33. The features table above reproduces all 32 of its C rows
// because every one of those names is a vocabulary item the harness may read,
// so a withheld one still has to be accounted for. The protocol table is
// different: the 24 schemes outside this implementation's scope are not
// "withheld pending a decision", they are not implemented at all (AAP 0.2.2),
// and adding 24 rows of `compiled_in: false` would invite exactly the wrong
// edit. They are enumerated in this module's documentation instead, and
// tests::no_out_of_scope_scheme_is_advertised checks all 24 by name.
//
// Lower case throughout, sorted alphabetically, and built from literals that
// belong to this module. See this module's documentation for why the scheme
// registry's upper-case spellings must not be reused here.
// ===========================================================================

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

/// The nine schemes this implementation serves, in `supported_protocols[]`
/// order -- lower case, alphabetically sorted.
///
/// Every `s`-suffixed scheme additionally requires TLS in C
/// (`#if defined(USE_SSL) && ...`); TLS is unconditional in this crate, so the
/// gate collapses to the protocol's own feature.
pub const PROTOCOLS: &[Protocol] = &[
    // crate::protocols::file. In scope despite being trivial: 27 fixtures
    // depend on the scheme (AAP 0.2.1).
    Protocol {
        name: "file",
        compiled_in: true,
    },
    Protocol {
        name: "ftp",
        compiled_in: cfg!(feature = "ftp"),
    },
    Protocol {
        name: "ftps",
        compiled_in: cfg!(feature = "ftp"),
    },
    // HTTP is unconditional: it is the engine's core protocol and everything
    // from WebSocket to DoH to CONNECT proxying is layered over it.
    Protocol {
        name: "http",
        compiled_in: true,
    },
    Protocol {
        name: "https",
        compiled_in: true,
    },
    Protocol {
        name: "scp",
        compiled_in: cfg!(feature = "ssh"),
    },
    Protocol {
        name: "sftp",
        compiled_in: cfg!(feature = "ssh"),
    },
    // WebSocket relies on HTTP, exactly as the C table's nesting records
    // (lib/version.c:386-394).
    Protocol {
        name: "ws",
        compiled_in: cfg!(feature = "websockets"),
    },
    Protocol {
        name: "wss",
        compiled_in: cfg!(feature = "websockets"),
    },
];

/// The scheme names this build advertises, lower case and sorted.
///
/// This is `curl_version_info_data::protocols`, which
/// `include/curl/curl.h:3122` documents as "terminated by an entry with a NULL
/// protoname"; the terminator belongs to the C view and is added by
/// `curl-rs-ffi`.
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
///
/// Case-insensitive because that is how the C tree resolves a scheme from a
/// URL: `Curl_getn_scheme()` (`lib/url.c:1477`) compares with
/// `curl_strnequal`, and a URL may be written `HTTPS://` or `Https://`. This is
/// a convenience over the advertised list only; the authoritative registry
/// lives in `crate::protocols`.
#[must_use]
pub fn supports_protocol(scheme: &str) -> bool {
    protocols()
        .iter()
        .any(|advertised| advertised.eq_ignore_ascii_case(scheme))
}

// ===========================================================================
// The banner -- curl_version(), lib/version.c:143-294
// ===========================================================================

/// `VERSION_PARTS` -- the number of substrings the C implementation can
/// concatenate (`lib/version.c:143`).
///
/// The C code asserts `i <= VERSION_PARTS` in debug builds
/// (`lib/version.c:273`) because `src[]` is a fixed-size array of that length.
/// [`version_parts`] can never exceed it -- there are fewer slots than that --
/// and `tests::the_banner_fits_the_c_buffer` proves it, so the bound is
/// preserved as a checked property rather than as an array size.
pub const VERSION_PARTS: usize = 16;

/// The size of the C implementation's output buffer, `static char out[300]`
/// (`lib/version.c:147`).
///
/// Reproduced because the join below reproduces the C truncation rule that
/// depends on it. A caller of the C function can rely on the result being at
/// most 299 bytes plus a terminator, and that remains true here.
pub const VERSION_BUFFER_SIZE: usize = 300;

/// The banner's first part: `libcurl/8.19.0-DEV` (`lib/version.c:205`).
const LIBCURL_TOKEN: &str = concat!(libcurl_name_literal!(), "/", libcurl_version_literal!());

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
/// | 6 | `c-ares/...` | never; the system resolver is used |
/// | 7 | `libidn2/...` | `idna/...`, always |
/// | 8 | `libpsl/...` | `publicsuffix/...`, feature `cookies` |
/// | 9 | `libssh2/...` | `russh/...`, feature `ssh` |
/// | 10 | `nghttp2/...` | `h2/...`, feature `http2` |
/// | 11 | `Curl_quic_ver()` | `quinn/... h3/...`, feature `http3` |
/// | 12 | `librtmp/...` | never; RTMP is out of scope |
/// | 13 | `libgsasl/...` | never; libgsasl is dropped |
/// | 14 | `mit-krb5/...` | never; see the library-tokens block |
/// | 15 | `Curl_ldap_version()` | never; LDAP is out of scope |
///
/// Feature gating uses `cfg!` rather than `#[cfg]` attributes so that every
/// token is referenced under every feature combination. With attributes, a
/// disabled feature would leave its token unreferenced and the build would
/// emit a `dead_code` warning -- which AAP 0.8.4's first gate, "zero warnings",
/// does not tolerate.
#[must_use]
pub fn version_parts() -> Vec<&'static str> {
    let mut parts: Vec<&'static str> = Vec::with_capacity(VERSION_PARTS);

    parts.push(LIBCURL_TOKEN);
    parts.push(SSL_VERSION);

    if cfg!(feature = "gzip") {
        parts.push(LIBZ_TOKEN);
    }
    if cfg!(feature = "brotli") {
        parts.push(BROTLI_TOKEN);
    }
    if cfg!(feature = "zstd") {
        parts.push(ZSTD_TOKEN);
    }

    parts.push(IDN_TOKEN);

    if cfg!(feature = "cookies") {
        parts.push(PSL_TOKEN);
    }
    if cfg!(feature = "ssh") {
        parts.push(SSH_TOKEN);
    }
    if cfg!(feature = "http2") {
        parts.push(HTTP2_TOKEN);
    }
    if cfg!(feature = "http3") {
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
///
/// # Truncation
///
/// The join reproduces `lib/version.c:275-291` exactly, including its
/// truncation rule: a part is appended only while at least its length plus a
/// separator and a terminator remain within [`VERSION_BUFFER_SIZE`], and
/// otherwise the loop stops. Today's banner is far shorter than the bound, so
/// the rule never fires; it is reproduced anyway because a caller of the C
/// function can rely on the length limit, and because a future part must
/// truncate rather than silently change the guarantee.
///
/// # The debug-build override is deliberately absent
///
/// `lib/version.c:196-203` lets a `DEBUGBUILD` replace the whole string from
/// the `CURL_VERSION` environment variable. There is no `DEBUGBUILD` analogue
/// here, and honouring the variable would mean advertising a `Debug`
/// capability this build does not have (see this module's documentation), so
/// the override is not implemented. The environment cannot change what this
/// function returns.
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

// ===========================================================================
// The curl_version_info() payload -- include/curl/curl.h:3111-3171
// ===========================================================================

/// Extracts `(major, minor, patch)` from a `name/major.minor.patch` token.
///
/// This exists so that a version appears exactly once in this file. The packed
/// numeric forms that [`VersionInfo`] carries for Brotli and Zstandard are
/// derived from the very token strings that report those versions, instead of
/// being written a second time as three integer literals that could drift out
/// of step with the string.
///
/// Total by construction: a token it cannot parse yields `None`, and the
/// caller then reports `0`, which is precisely what the C struct carries when
/// the library is absent. Nothing here can panic.
fn version_components(token: &str) -> Option<(c_uint, c_uint, c_uint)> {
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
fn leading_number(text: &str) -> Option<c_uint> {
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
///
/// # This is the payload, not the C view
///
/// `curl-rs-ffi` owns the `#[repr(C)]` mirror of this struct, the `NULL`
/// terminators that the two arrays need, the `CString` storage behind every
/// pointer, and the `'static` lifetime management that lets a C caller hold the
/// result forever (AAP 0.3.1 puts the ABI in that crate and the protocol
/// knowledge in this one). What lives here is the *content*: `Option` where C
/// has a nullable pointer, and a Rust slice where C has a `NULL`-terminated
/// array.
///
/// # `#[non_exhaustive]`
///
/// Fields are readable everywhere and the struct is constructible only inside
/// this crate, where [`version_info`] is its only constructor. That keeps a
/// single source of truth for the payload -- nothing outside can assemble a
/// second, divergent one -- and it makes appending the thirteenth age's fields a
/// non-breaking change, mirroring the C struct's own append-only rule.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub struct VersionInfo {
    /// `age` -- which generation of this struct is populated.
    pub age: CURLversion,

    /// `version` -- [`LIBCURL_VERSION`].
    pub version: &'static str,

    /// `version_num` -- [`LIBCURL_VERSION_NUM`].
    pub version_num: c_uint,

    /// `host` -- the `cpu-vendor-os[-env]` triple; see [`host`].
    pub host: &'static str,

    /// `features` -- the bitmask; see [`features_bitmask`].
    pub features: c_int,

    /// `ssl_version` -- human-readable TLS backend and version.
    pub ssl_version: Option<&'static str>,

    /// `ssl_version_num` -- "not used anymore, always 0"
    /// (`include/curl/curl.h:3117`). Reproduced as a zero, not omitted: the
    /// field still occupies its slot in the C layout.
    pub ssl_version_num: c_long,

    /// `libz_version` -- always `None` here.
    ///
    /// The C field carries a bare zlib version such as `"1.3.1"`. No zlib is
    /// linked: `flate2` is pinned to its pure-Rust backend, so putting that
    /// crate's number here would read as an ancient, long-superseded zlib to
    /// anyone comparing it -- a fabrication the shape of the field invites. The
    /// capability is reported truthfully by the `libz` feature name and by the
    /// banner's `flate2/...` part instead.
    pub libz_version: Option<&'static str>,

    /// `protocols` -- the advertised schemes; see [`protocols`].
    pub protocols: &'static [&'static str],

    // ---- CURLVERSION_SECOND ----
    /// `ares` -- always `None`: c-ares is replaced by the system resolver.
    pub ares: Option<&'static str>,

    /// `ares_num` -- always `0`, for the same reason.
    pub ares_num: c_int,

    // ---- CURLVERSION_THIRD ----
    /// `libidn` -- always `None`: the IDN implementation is `idna`, not libidn2.
    ///
    /// This is what makes `idn_present()`'s branch choice matter. The C
    /// predicate reports `info->libidn != NULL` when libidn2 is the backend and
    /// an unconditional true for the Windows and Apple backends, which publish
    /// no version through this field. This build is in the second category.
    pub libidn: Option<&'static str>,

    // ---- CURLVERSION_FOURTH ----
    /// `iconv_ver_num` -- always `0`: no iconv is used.
    pub iconv_ver_num: c_int,

    /// `libssh_version` -- always `None`.
    ///
    /// The field names libssh or libssh2, and neither is linked; SSH is
    /// provided by `russh`, which the banner reports. Reporting a russh version
    /// through a field named after another library would misdescribe the build.
    pub libssh_version: Option<&'static str>,

    // ---- CURLVERSION_FIFTH ----
    /// `brotli_ver_num` -- `(MAJOR << 24) | (MINOR << 12) | PATCH`, or `0`.
    pub brotli_ver_num: c_uint,

    /// `brotli_version` -- the prefixed token, matching the C shape, where
    /// `brotli_version()` writes `"brotli/%u.%u.%u"` (`lib/version.c:83-90`).
    pub brotli_version: Option<&'static str>,

    // ---- CURLVERSION_SIXTH ----
    /// `nghttp2_ver_num` -- always `0`: nghttp2 is replaced by `h2`.
    pub nghttp2_ver_num: c_uint,

    /// `nghttp2_version` -- always `None`, for the same reason. The HTTP/2
    /// implementation is reported by the banner's `h2/...` part.
    pub nghttp2_version: Option<&'static str>,

    /// `quic_version` -- the QUIC and HTTP/3 libraries, or `None`.
    pub quic_version: Option<&'static str>,

    // ---- CURLVERSION_SEVENTH ----
    /// `cainfo` -- the built-in default for `CURLOPT_CAINFO`; `None` here.
    ///
    /// The C build substitutes a configured bundle path. This build has no
    /// default *path*: the default trust source is compiled in -- the
    /// `webpki-roots` anchor set -- and a compiled-in anchor set has no
    /// filename to report. `--cacert` remains fully honoured, and reporting a
    /// path that does not exist would send callers looking for a file.
    pub cainfo: Option<&'static str>,

    /// `capath` -- the built-in default for `CURLOPT_CAPATH`; `None`, as above.
    pub capath: Option<&'static str>,

    // ---- CURLVERSION_EIGHTH ----
    /// `zstd_ver_num` -- `(MAJOR << 24) | (MINOR << 12) | PATCH`, or `0`.
    pub zstd_ver_num: c_uint,

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
/// The C function rebuilds its bitmask and name array on every call into
/// `static` storage (`lib/version.c:596-706`); doing that once and handing back
/// a shared reference is equivalent and removes the data race the C version
/// avoids only by writing identical bytes each time.
///
/// The C function ignores its `CURLversion stamp` argument entirely
/// (`(void)stamp;`, `lib/version.c:619`) and always returns the current
/// struct, so this takes none. `curl-rs-ffi` accepts the argument at the ABI
/// boundary, where the signature is fixed, and discards it the same way.
#[must_use]
pub fn version_info() -> &'static VersionInfo {
    static INFO: OnceLock<VersionInfo> = OnceLock::new();

    INFO.get_or_init(|| {
        let (brotli_version, brotli_ver_num) = if cfg!(feature = "brotli") {
            let (major, minor, patch) = version_components(BROTLI_TOKEN).unwrap_or((0, 0, 0));
            (
                Some(BROTLI_TOKEN),
                packed_version_24_12(major, minor, patch),
            )
        } else {
            (None, 0)
        };

        let (zstd_version, zstd_ver_num) = if cfg!(feature = "zstd") {
            let (major, minor, patch) = version_components(ZSTD_TOKEN).unwrap_or((0, 0, 0));
            (Some(ZSTD_TOKEN), packed_version_24_12(major, minor, patch))
        } else {
            (None, 0)
        };

        let quic_version = if cfg!(feature = "http3") {
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
            ssl_version: Some(SSL_VERSION),
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

    /// The nine schemes a fully featured build serves.
    const NINE_SCHEMES: [&str; 9] = [
        "file", "ftp", "ftps", "http", "https", "scp", "sftp", "ws", "wss",
    ];

    /// The 24 registered schemes this implementation does not serve, whose 283
    /// fixtures must skip rather than fail (AAP 0.2.2).
    const OUT_OF_SCOPE_SCHEMES: [&str; 24] = [
        "dict", "gopher", "gophers", "imap", "imaps", "ldap", "ldaps", "mqtt", "mqtts", "pop3",
        "pop3s", "rtmp", "rtmpe", "rtmps", "rtmpt", "rtmpte", "rtmpts", "rtsp", "smb", "smbs",
        "smtp", "smtps", "telnet", "tftp",
    ];

    /// The 32 rows of `features_table[]` in C source order, names verbatim.
    ///
    /// Diffed row by row against `lib/version.c:450-554`. Casing is the point
    /// of this constant: `AsynchDNS`, `GSS-API`, `HTTPS-proxy`, `IPv6`,
    /// `TLS-SRP`, `UnixSockets`, `alt-svc`, `asyn-rr`, `libz`, `threadsafe` and
    /// `zstd` are each spelled exactly one way and the harness matches them
    /// literally.
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
        // AAP 0.8.5/C6 binds every parity claim to 8.19.0-DEV. Measured at
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
        assert_eq!(DEFAULT_USER_AGENT, format!("{CURL_NAME}/{LIBCURL_VERSION}"));
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

        #[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
        assert_eq!(triple, "x86_64-unknown-linux-gnu");

        #[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
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
            core::mem::size_of::<c_int>()
        );
        assert_eq!(
            core::mem::align_of::<CURLversion>(),
            core::mem::align_of::<c_int>()
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
            let raw = c_int::try_from(index).expect("twelve ages fit an int");
            assert_eq!(age.as_c_int(), raw);
            assert_eq!(CURLversion::from_c_int(raw), Some(*age));
            assert!(age.c_name().starts_with("CURLVERSION_"));
            assert!(!age.introduced_in().is_empty());
            assert_eq!(age.to_string(), age.c_name());
        }

        // CURLVERSION_LAST is "never actually use this" -- a bound, not a value.
        assert_eq!(CURLversion::from_c_int(CURLversion::LAST), None);
        assert_eq!(CURLversion::from_c_int(-1), None);
        assert_eq!(CURLversion::from_c_int(c_int::MAX), None);
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
        let expected: [(&str, c_int); 32] = [
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

    #[test]
    fn only_the_three_c_predicate_rows_carry_a_predicate() {
        // lib/version.c gives a function pointer to exactly ECH,
        // HTTPS-proxy and IDN; every other row passes NULL.
        let with_predicate: Vec<&str> = FEATURES
            .iter()
            .filter(|row| row.present.is_some())
            .map(Feature::name)
            .collect();
        assert_eq!(with_predicate, vec!["ECH", "HTTPS-proxy", "IDN"]);
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
            let bit: c_int = 1 << position;
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
        // AAP 0.6.6. The row is a literal false, deliberately not gated on
        // `memdebug`, so this holds even under --all-features.
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

    #[test]
    fn ssl_is_advertised() {
        // 138 fixtures gate on this name, and it is what makes the accurate
        // rustls banner token affordable.
        assert!(has_feature("SSL"));
        assert_eq!(features_bitmask() & CURL_VERSION_SSL, CURL_VERSION_SSL);
    }

    #[test]
    fn the_unconditional_capabilities_are_advertised() {
        for name in [
            "AsynchDNS",
            "HTTPS-proxy",
            "IDN",
            "IPv6",
            "Largefile",
            "NTLM",
            "SSL",
            "threadsafe",
        ] {
            assert!(has_feature(name), "{name} must be advertised");
        }

        #[cfg(unix)]
        assert!(has_feature("UnixSockets"));
    }

    #[test]
    fn feature_gated_names_track_their_cargo_features() {
        let expected = [
            ("alt-svc", cfg!(feature = "altsvc")),
            ("brotli", cfg!(feature = "brotli")),
            ("GSS-API", cfg!(feature = "negotiate")),
            ("HSTS", cfg!(feature = "hsts")),
            ("HTTP2", cfg!(feature = "http2")),
            ("HTTP3", cfg!(feature = "http3")),
            ("Kerberos", cfg!(feature = "negotiate")),
            ("libz", cfg!(feature = "gzip")),
            ("PSL", cfg!(feature = "cookies")),
            ("SPNEGO", cfg!(feature = "negotiate")),
            ("UnixSockets", cfg!(unix)),
            ("zstd", cfg!(feature = "zstd")),
        ];

        for (name, active) in expected {
            assert_eq!(has_feature(name), active, "{name} is misreported");
        }
    }

    #[test]
    fn ech_is_withheld_because_the_backend_cannot_do_it() {
        assert!(!tls_supports_ech());
        assert!(!has_feature("ECH"));

        // The row itself is compiled in; only the predicate withholds it, so
        // enabling ECH in the TLS layer is a one-function change here.
        let row = feature("ECH").expect("the ECH row must exist");
        assert!(row.compiled_in());
        assert!(!row.is_present());
    }

    #[test]
    fn the_predicate_rows_report_their_capabilities() {
        assert!(tls_supports_https_proxy());
        assert!(idn_present());
        assert!(has_feature("HTTPS-proxy"));
        assert!(has_feature("IDN"));
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

    #[test]
    fn advertised_protocols_match_the_active_features() {
        let mut expected: Vec<&str> = Vec::with_capacity(NINE_SCHEMES.len());
        expected.push("file");
        if cfg!(feature = "ftp") {
            expected.push("ftp");
            expected.push("ftps");
        }
        expected.push("http");
        expected.push("https");
        if cfg!(feature = "ssh") {
            expected.push("scp");
            expected.push("sftp");
        }
        if cfg!(feature = "websockets") {
            expected.push("ws");
            expected.push("wss");
        }

        assert_eq!(protocols(), expected.as_slice());
    }

    #[cfg(all(feature = "ftp", feature = "ssh", feature = "websockets"))]
    #[test]
    fn a_full_build_advertises_exactly_the_nine_schemes() {
        assert_eq!(protocols(), NINE_SCHEMES.as_slice());
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
        assert!(supports_protocol("http"));
        assert!(supports_protocol("HTTP"));
        assert!(supports_protocol("HttpS"));
        assert!(!supports_protocol("httpx"));
        assert!(!supports_protocol(""));

        #[cfg(feature = "websockets")]
        {
            // The registry stores "WS"/"WSS" in upper case; the banner is lower
            // case; lookup must accept either.
            assert!(supports_protocol("WS"));
            assert!(supports_protocol("wss"));
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
        assert_eq!(parts[1], SSL_VERSION);
        assert_eq!(SSL_VERSION, "rustls/0.23.42");

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
        // also the assumption the varargs design in AAP 0.6.2 rests on.
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

        // Nothing was dropped by the C truncation rule.
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
        let parts = version_parts();
        let expected_len = 3 // libcurl, rustls, idna
            + usize::from(cfg!(feature = "gzip"))
            + usize::from(cfg!(feature = "brotli"))
            + usize::from(cfg!(feature = "zstd"))
            + usize::from(cfg!(feature = "cookies"))
            + usize::from(cfg!(feature = "ssh"))
            + usize::from(cfg!(feature = "http2"))
            + usize::from(cfg!(feature = "http3"));
        assert_eq!(parts.len(), expected_len);

        let banner = version();
        assert_eq!(banner.contains("flate2/"), cfg!(feature = "gzip"));
        assert_eq!(banner.contains("brotli/"), cfg!(feature = "brotli"));
        assert_eq!(banner.contains("zstd/"), cfg!(feature = "zstd"));
        assert_eq!(banner.contains("publicsuffix/"), cfg!(feature = "cookies"));
        assert_eq!(banner.contains("russh/"), cfg!(feature = "ssh"));
        assert_eq!(banner.contains("h2/"), cfg!(feature = "http2"));
        assert_eq!(banner.contains("quinn/"), cfg!(feature = "http3"));
        assert_eq!(banner.contains(" h3/"), cfg!(feature = "http3"));
        assert!(banner.contains("idna/1.1.0"));
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
        // string". Comparing pointers proves it is the very same buffer.
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

        // :585-586 -- accuracy choice A8: the native token cannot match.
        assert!(!libcurl.contains("rustls-ffi"));

        // :658-660 -- both derive from one /Debug/i match.
        assert!(!lower.contains("debug"));

        // :662-666
        assert!(features.contains("SSL"));
        assert!(!lower.contains("multissl"));
        assert!(features.contains("Largefile"));

        // :668-676
        assert!(features.contains("IDN"));
        assert!(features.contains("IPv6"));
        assert_eq!(lower.contains("unixsockets"), cfg!(unix));
        assert_eq!(lower.contains("libz"), cfg!(feature = "gzip"));

        // :678-688
        assert_eq!(lower.contains("brotli"), cfg!(feature = "brotli"));
        assert_eq!(lower.contains("zstd"), cfg!(feature = "zstd"));
        assert!(features.contains("NTLM"));
        assert!(!lower.contains("ntlm_wb"));
        assert!(!lower.contains("sspi"));

        // :690-700
        assert_eq!(lower.contains("gss-api"), cfg!(feature = "negotiate"));
        assert_eq!(lower.contains("kerberos"), cfg!(feature = "negotiate"));
        assert_eq!(lower.contains("spnego"), cfg!(feature = "negotiate"));
        assert!(!lower.contains("tls-srp"));
        assert_eq!(lower.contains("psl"), cfg!(feature = "cookies"));
        assert_eq!(lower.contains("alt-svc"), cfg!(feature = "altsvc"));
        assert_eq!(lower.contains("hsts"), cfg!(feature = "hsts"));

        // :701-712 -- AsynchDNS present and no c-ares token means the harness
        // records a threaded resolver, which describes this build correctly.
        assert!(features.contains("AsynchDNS"));
        assert!(!features.contains("asyn-rr"));

        // :714-726
        assert_eq!(features.contains("HTTP2"), cfg!(feature = "http2"));
        assert_eq!(features.contains("HTTP3"), cfg!(feature = "http3"));
        assert!(features.contains("HTTPS-proxy"));

        // :727-730
        assert!(!lower.contains("unicode"));
        assert!(features.contains("threadsafe"));
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
        assert_eq!(info.ssl_version, Some(SSL_VERSION));
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

        #[cfg(feature = "brotli")]
        {
            assert_eq!(info.brotli_version, Some("brotli/8.0.4"));
            assert_eq!(info.brotli_ver_num, packed_version_24_12(8, 0, 4));
            assert_eq!(info.brotli_ver_num, 0x0800_0004);
        }
        #[cfg(not(feature = "brotli"))]
        {
            assert_eq!(info.brotli_version, None);
            assert_eq!(info.brotli_ver_num, 0);
        }

        #[cfg(feature = "zstd")]
        {
            assert_eq!(info.zstd_version, Some("zstd/0.13.3"));
            assert_eq!(info.zstd_ver_num, packed_version_24_12(0, 13, 3));
            assert_eq!(info.zstd_ver_num, 0x0000_D003);
        }
        #[cfg(not(feature = "zstd"))]
        {
            assert_eq!(info.zstd_version, None);
            assert_eq!(info.zstd_ver_num, 0);
        }

        #[cfg(feature = "http3")]
        assert_eq!(info.quic_version, Some("quinn/0.11.9 h3/0.0.8"));
        #[cfg(not(feature = "http3"))]
        assert_eq!(info.quic_version, None);
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
    fn pinned_version(manifest: &str, section: &str, crate_name: &str) -> Option<String> {
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

    #[test]
    fn library_tokens_match_the_manifest() {
        // The workspace manifest is the single place versions are declared
        // (AAP 0.4.2). If a pin moves and this file is not updated, the banner
        // starts lying -- so the two are compared mechanically rather than by
        // remembering to look.
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
            ("h2", h2_version_literal!()),
            ("quinn", quinn_version_literal!()),
            ("h3", h3_version_literal!()),
            ("hyper", hyper_version_literal!()),
        ];

        for (crate_name, reported) in expected {
            let pinned = pinned_version(manifest, section, crate_name)
                .unwrap_or_else(|| panic!("no exact pin for {crate_name} in {section}"));
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

        for crate_name in ["rustls", "idna", "des", "md4", "md-5", "hmac", "socket2"] {
            let line = manifest
                .lines()
                .map(str::trim)
                .find(|line| {
                    line.split_once('=')
                        .is_some_and(|(key, _)| key.trim() == crate_name)
                })
                .unwrap_or_else(|| panic!("{crate_name} is not declared in curl-rs-lib"));

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
