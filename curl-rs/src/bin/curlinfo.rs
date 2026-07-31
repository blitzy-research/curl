// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

// THE SAFETY INVARIANT, ASSERTED LOCALLY.
//
// `src/bin/curlinfo.rs` is its OWN crate root: Cargo compiles it as a
// separate crate from `src/main.rs` (both are declared explicitly in
// curl-rs/Cargo.toml, at :168-170 and :179-181). An attribute written in
// `src/main.rs` therefore does not reach this file, so the invariant is
// restated here rather than inherited.
//
// `forbid` is used, not `deny`. The engine crate settles for
// `#![deny(unsafe_code)]` because it must grant exactly one exemption --
// `#[allow(unsafe_code)]` on `pub(crate) mod ffi`, and `forbid` cannot be
// overridden from an inner scope at all (curl-rs-lib/src/lib.rs:126 records
// the measured `error[E0453]`). This crate has no `mod ffi` and needs no
// exemption, so it takes the strictly stronger form: with `forbid`, not even
// a deliberate inner `#[allow(unsafe_code)]` can re-enable the keyword.
// AAP 0.1.1 goal G6 and AAP 0.6.9 require exactly this.
#![forbid(unsafe_code)]

//! `curlinfo` -- the build-capability diagnostic.
//!
//! A faithful translation of `src/curlinfo.c` (271 lines), whose own purpose
//! comment at :24-31 explains why the tool exists: "to figure out which, if
//! any, features that are disabled which should otherwise exist and work.
//! These are not visible in regular curl -V output." It adds that "Disabled
//! protocols are visible in `curl_version_info()` and are not included in
//! this table."
//!
//! The C build treats it as a development diagnostic rather than a shipped
//! artifact -- `src/Makefile.am:51-52` declares `curlinfo_SOURCES =
//! curlinfo.c` under `noinst_PROGRAMS`, and `src/CMakeLists.txt:111` uses
//! `add_executable(curlinfo EXCLUDE_FROM_ALL "curlinfo.c")`. AAP 0.3.1
//! nevertheless lists it explicitly ("`curl-rs/src/bin/curlinfo.rs`
//! separate diagnostic binary"), and AAP 0.4.1 maps it CREATE from
//! `src/curlinfo.c`, so it is in scope and is reproduced here.
//!
//! # The output contract
//!
//! `main()` in the C is deliberately trivial (`:260-271`): it discards `argc`
//! and `argv` with `(void)` casts, walks the `disabled[]` array, and `puts()`
//! each element. Because every element already ends in `": "` and `puts`
//! appends a newline, the observable contract is:
//!
//! - exactly 29 newline-terminated lines, in table order rather than sorted;
//! - each line is a label followed by the token `ON` or `OFF`, and nothing
//!   else -- there is no third token, no header, no banner and no separator;
//! - no blank line anywhere, including at the start and the end;
//! - nothing on stderr;
//! - exit status 0 unconditionally, even when every row reads `OFF`.
//!
//! The blank lines visible inside the C array literal (after `cookies` at
//! `:61-62`, `Mime` at `:118-119`, `sha512-256` at `:210-211` and
//! `win32-ca-search-safe` at `:227-228`) are source formatting between
//! initialiser elements. They are not string contents and they emit nothing.
//!
//! Labels are copied byte-for-byte, including the non-uniform casing of
//! `DoH: `, `HTTP-auth: ` and `Mime: `, the leading `--` of `--libcurl: `,
//! and the single space after every colon. Normalising any of them for
//! "consistency" would silently change program output, which AAP 0.8.2
//! forbids: "a refactor that produces different-but-arguably-better output
//! has failed."
//!
//! # Why the values cannot be transliterated
//!
//! The C reads its answers straight out of the preprocessor. `:32-38`
//! includes five *internal* library headers purely to observe build macros
//! (`curl_setup.h` for the `CURL_DISABLE_*` family, `multihandle.h` for
//! `ENABLE_WAKEUP`, `tool_xattr.h` for `USE_XATTR`, `curl_sha512_256.h` for
//! `CURL_HAVE_SHA512_256`, `asyn.h` for `CURLRES_ARES` and
//! `fake_addrinfo.h` for `USE_FAKE_GETADDRINFO`), plus
//! `<openssl/opensslconf.h>` at `:42-44` for `OPENSSL_NO_OCSP`.
//!
//! None of that is reachable from Rust, by design. AAP 0.4.2 converts the C
//! tree's `Curl_`-prefixed "private by convention" linkage into `pub(crate)`
//! "private by enforcement", and `curl-rs-lib` exposes exactly eight public
//! modules -- `error`, `version`, `url`, `headers`, `mime`, `share`, `easy`
//! and `multi`. The twelve that would carry these answers (`trace`, `util`,
//! `ffi`, `crypto`, `dns`, `conn`, `tls`, `proxy`, `auth`, `cookies`,
//! `transfer`, `protocols`) are `pub(crate)` and invisible here.
//!
//! Every value below therefore comes from exactly one of two legitimate
//! sources:
//!
//! 1. `curl_rs_lib::version`, the public module that also backs
//!    `curl_version_info` and the `--version` banner. Preferring it keeps
//!    `curl-rs-lib` the single owner of the truth, which is the
//!    transformation rule AAP 0.1.2 states as "a single Rust module is the
//!    sole source of truth".
//! 2. `cfg!(feature = "...")` over this crate's own compiled feature set.
//!    `curl-rs/Cargo.toml` declares exactly fifteen features and forwards
//!    each to `curl-rs-lib/<name>` while holding `default-features = false`
//!    on the path dependency, so the tool's feature set cannot diverge from
//!    the engine's. There is no `tls` feature and none is invented here.
//!
//! # The polarity is not uniform
//!
//! Twenty-one rows are negative tests whose true branch yields `OFF`
//! (nineteen `#ifdef CURL_DISABLE_*` plus the two compound `win32-*`
//! conditions), two are numeric width tests, three are `#ifndef` and are
//! therefore inverted, and three are plain positive tests whose true branch
//! yields `ON`. A mechanical `#ifdef` to `OFF` transliteration would invert
//! six of the twenty-nine, so each row below was re-derived from its own
//! `#if*` line and carries that line number.
//!
//! # Honesty over completeness
//!
//! AAP 0.6.5 records the asymmetry that governs every uncertain row:
//! "under-reporting a capability makes a fixture skip; over-reporting makes
//! it run and fail." Five rows describe capabilities whose status no public
//! predicate can currently establish. Each reports `OFF`, never a third
//! token, and each carries the exact predicate `curl-rs-lib` would need to
//! expose in order to answer properly. Guessing `ON` would be the one
//! failure mode the AAP names by hand.

use std::io::{self, Write};

use curl_rs_lib::version;

// ===========================================================================
// The two output tokens
//
// The vocabulary is closed: `ON` and `OFF`, nothing else. There is
// deliberately no `UNKNOWN`, no `N/A` and no empty string -- the C emits one
// of these two for all 29 rows, and a consumer parsing the table would break
// on a third value.
// ===========================================================================

/// The token a compiled-in capability renders as.
const ON: &str = "ON";

/// The token an absent capability renders as.
const OFF: &str = "OFF";

// ===========================================================================
// Derivation classes
//
// Named rather than written as bare `true`/`false` literals so that each row
// of the table declares WHY it holds its value, not merely what the value
// is. The three names below are all the classes the table needs beyond the
// rows that are computed.
// ===========================================================================

/// A capability this implementation always compiles in.
///
/// The C reports these from `#ifdef CURL_DISABLE_<X>`, a macro the
/// Autotools and CMake builds define only when a `--disable-<x>` switch is
/// passed. This workspace has no equivalent switch for them: they are not
/// among the fifteen Cargo features, so no build configuration can turn them
/// off, exactly as a C build that never defines the macro reports `ON`.
const ALWAYS_COMPILED_IN: bool = true;

/// A capability whose status no public predicate can currently establish.
///
/// Used by the five rows enumerated in this module's documentation. Rendering
/// `OFF` is the honest choice under AAP 0.6.5's asymmetry, and it is paired
/// with a named required predicate at each use site so the gap is actionable
/// rather than merely recorded.
const NOT_DETERMINABLE: bool = false;

/// A capability this build definitively does not provide.
///
/// Distinct from [`NOT_DETERMINABLE`]: here the answer is known, and it is
/// negative. Kept separate so a future reader can tell "we cannot tell" from
/// "we can tell, and it is absent".
const NOT_PRESENT: bool = false;

// ===========================================================================
// Macro analogues that are permanently false in this implementation
//
// These mirror C macros the transformation removed outright. They are named
// after the macro they replace so the compound conditions further down can be
// read against the C source line by line.
// ===========================================================================

/// `CURLRES_ARES` -- the c-ares resolver backend.
///
/// AAP 0.5.2 drops c-ares entirely ("Replaced by the system resolver;
/// `hickory-dns` remains an optional, default-off feature"), and
/// `lib/asyn-ares.c` is listed among the excluded sources in AAP 0.4.1. No
/// Cargo feature can define this, so it is permanently false.
const CURLRES_ARES: bool = false;

/// `USE_FAKE_GETADDRINFO` -- the test-only resolver interception hook.
///
/// `lib/fake_addrinfo.c` has no target in the AAP 0.4.1 transformation map,
/// so the capability does not exist here in any configuration.
const USE_FAKE_GETADDRINFO: bool = false;

/// The `curl_version_info` feature name that reports TLS session export.
///
/// `src/tool_libinfo.c:114` lists `{ "SSLS-EXPORT", &feature_ssls_export, 0 }`
/// in its `maybe_feature[]` table, which means the C command-line tool
/// already derives this capability from the PUBLIC feature-name list rather
/// than from the `USE_SSLS_EXPORT` build macro. Reusing that route here is
/// the sanctioned way to answer row 28 without reaching into the engine.
const SSLS_EXPORT_FEATURE: &str = "SSLS-EXPORT";

/// The number of rows in the table, fixed by `src/curlinfo.c:46-258`.
///
/// Verified mechanically: `grep -c ': "$' src/curlinfo.c` reports 29, and the
/// array literal closes at `:258` with no trailing comma. [`capabilities`]
/// returns an array of exactly this length, so adding or removing a row is a
/// compile error rather than a silent change to the line count.
const CAPABILITY_COUNT: usize = 29;

/// One row of the C `disabled[]` table: a label and whether it is enabled.
struct Capability {
    /// The label, byte-verbatim from the C including its `": "` suffix.
    label: &'static str,

    /// Whether this build provides the capability.
    enabled: bool,
}

impl Capability {
    /// Builds one row.
    const fn new(label: &'static str, enabled: bool) -> Self {
        Self { label, enabled }
    }

    /// The token this row renders as: [`ON`] or [`OFF`], never anything else.
    const fn token(&self) -> &'static str {
        if self.enabled {
            ON
        } else {
            OFF
        }
    }
}

// ===========================================================================
// The computed rows
//
// Four rows are not a single constant or a single feature flag. Each is given
// a named function so its derivation sits next to the C condition it
// reproduces, and so the `#[cfg(test)]` module can assert it by name.
// ===========================================================================

/// Row 21, `large-time`. C: `#if (SIZEOF_TIME_T < 5)` yields `OFF`
/// (`src/curlinfo.c:190-195`).
///
/// The C asks whether `time_t` can represent instants beyond the 32-bit
/// epoch. This implementation carries timestamps as a 64-bit signed value,
/// mirroring `curl_off_t` (`curl_rs_lib::version::CURL_OFF_T_SIZE` is
/// `size_of::<i64>()`), so the width is evaluated genuinely instead of being
/// asserted: a hypothetical narrow target would correctly report `OFF`.
const fn large_time() -> bool {
    core::mem::size_of::<i64>() >= 5
}

/// Row 22, `large-size`. C: `#if (SIZEOF_SIZE_T < 5)` yields `OFF`
/// (`src/curlinfo.c:197-202`).
///
/// `usize` is Rust's spelling of C's `size_t`, so this is an exact analogue
/// rather than an approximation. All four targets in the AAP 0.1.1 goal G8
/// matrix are 64-bit, giving 8 bytes and therefore `ON`.
const fn large_size() -> bool {
    core::mem::size_of::<usize>() >= 5
}

/// Row 27, `override-dns`. C (`src/curlinfo.c:236-242`), a POSITIVE test:
/// `#if defined(CURL_MEMDEBUG) && (defined(CURLRES_ARES) ||
/// defined(USE_FAKE_GETADDRINFO))` yields `ON`.
///
/// The structure of the C condition is preserved so the reasoning is
/// checkable, but the second conjunct is permanently unsatisfiable here:
/// both [`CURLRES_ARES`] and [`USE_FAKE_GETADDRINFO`] are gone from this
/// implementation. The row is therefore `OFF` whatever the `memdebug`
/// feature is set to, which is why the first conjunct is still evaluated
/// rather than dropped -- deleting it would hide the fact that flipping
/// `memdebug` alone cannot change the answer.
fn override_dns() -> bool {
    let alternative_resolver = CURLRES_ARES || USE_FAKE_GETADDRINFO;

    cfg!(feature = "memdebug") && alternative_resolver
}

/// Row 28, `ssl-sessions`. C (`src/curlinfo.c:244-249`), a POSITIVE test:
/// `#ifdef USE_SSLS_EXPORT` yields `ON`.
///
/// Answered through the public engine surface, per
/// [`SSLS_EXPORT_FEATURE`]. This is not duplication of the `--version`
/// banner: the label printed here is `ssl-sessions: ` while the banner token
/// is `SSLS-EXPORT`, and the two vocabularies are disjoint (verified
/// programmatically against both `src/tool_libinfo.c`'s 30 tokens and
/// `curl_rs_lib::version::FEATURES`' 32 rows -- zero overlap, which is what
/// `src/curlinfo.c:26-27` asserts when it says these entries are "not
/// visible in regular curl -V output"). Deriving the value from one
/// vocabulary while printing the other label is exactly the intended
/// pattern, and it is what keeps the two self-description surfaces from
/// drifting apart.
fn ssl_sessions() -> bool {
    version::has_feature(SSLS_EXPORT_FEATURE)
}

// ===========================================================================
// The table
//
// Order is table order, matching `src/curlinfo.c:46-258` element for element.
// It is deliberately not sorted: the C groups related capabilities and a
// consumer diffing two builds compares line by line.
//
// A function rather than a `const`, because row 28 calls
// `curl_rs_lib::version::has_feature`, whose `Feature::is_present` consults a
// function pointer and so cannot be evaluated in a constant. The return type
// is a fixed-length array rather than a slice or a `Vec` so that the row
// count is enforced by the type system. No mutable global state is involved:
// there is no `static mut` and no `thread_local!` anywhere in this file.
// ===========================================================================

/// The 29 diagnostic rows, in the order `src/curlinfo.c:46-258` declares them.
fn capabilities() -> [Capability; CAPABILITY_COUNT] {
    [
        // 1. C `:47-52`: `#ifdef CURL_DISABLE_BINDLOCAL` -> OFF.
        //
        // GAP 1 of 5. Binding a transfer to a local interface, address or
        // port. The engine plainly has the machinery -- AAP 0.4.1 maps
        // `curl-rs-lib/src/dns/if2ip.rs` from `lib/if2ip.c` for
        // "`--interface` resolution", and `curl-rs-lib/src/ffi/sys.rs`
        // discusses `bindlocal` at :661, :673, :732 and :2058 -- but both
        // `dns` and `ffi` are `pub(crate)`, so no predicate is reachable
        // from this crate.
        //
        // REQUIRED PREDICATE: `curl_rs_lib::version::has_feature("...")`
        // gains no row for this (it is not a `--version` token, and adding
        // one would breach the disjoint vocabularies this file keeps), so the
        // right shape is a dedicated public capability predicate on the
        // engine, e.g. `pub fn curl_rs_lib::version::supports_bindlocal()
        // -> bool` backed by `crate::dns::if2ip`.
        Capability::new("bindlocal: ", NOT_DETERMINABLE),
        // 2. C `:55-60`: `#ifdef CURL_DISABLE_COOKIES` -> OFF.
        //
        // A genuine Cargo feature, default ON (`curl-rs/Cargo.toml`
        // `default` list), forwarding to `curl-rs-lib/cookies`.
        Capability::new("cookies: ", cfg!(feature = "cookies")),
        // 3. C `:63-68`: `#ifdef CURL_DISABLE_BASIC_AUTH` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/auth/basic.rs` CREATE from
        // `lib/vauth/cleartext.c`. Not a Cargo feature, so unconditional.
        Capability::new("basic-auth: ", ALWAYS_COMPILED_IN),
        // 4. C `:70-75`: `#ifdef CURL_DISABLE_BEARER_AUTH` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/auth/bearer.rs` from
        // `lib/vauth/oauth2.c`.
        Capability::new("bearer-auth: ", ALWAYS_COMPILED_IN),
        // 5. C `:77-82`: `#ifdef CURL_DISABLE_DIGEST_AUTH` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/auth/digest.rs` from
        // `lib/vauth/digest.c` and `lib/http_digest.c`, with message
        // construction byte-exact.
        Capability::new("digest: ", ALWAYS_COMPILED_IN),
        // 6. C `:84-89`: `#ifdef CURL_DISABLE_NEGOTIATE_AUTH` -> OFF.
        //
        // A Cargo feature, default OFF. AAP 0.8.5 conflict C2 keeps
        // Negotiate behind a non-default `negotiate` feature so that the
        // default build links no C security library at all, which is what
        // reconciles "no C TLS linkage at any configuration" with
        // "Negotiate where OS Kerberos is available".
        Capability::new("negotiate-auth: ", cfg!(feature = "negotiate")),
        // 7. C `:91-96`: `#ifdef CURL_DISABLE_AWS` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/auth/aws_sigv4.rs` from
        // `lib/http_aws_sigv4.c`.
        Capability::new("aws: ", ALWAYS_COMPILED_IN),
        // 8. C `:98-103`: `#ifdef CURL_DISABLE_DOH` -> OFF.
        //
        // A Cargo feature, default ON, forwarding to `curl-rs-lib/doh`
        // (AAP 0.4.1: `curl-rs-lib/src/dns/doh.rs` from `lib/doh.c`).
        Capability::new("DoH: ", cfg!(feature = "doh")),
        // 9. C `:105-110`: `#ifdef CURL_DISABLE_HTTP_AUTH` -> OFF.
        //
        // The HTTP authentication dispatcher, AAP 0.4.1
        // `curl-rs-lib/src/auth/mod.rs` from `lib/vauth/vauth.c`. Not a
        // Cargo feature; the individual mechanisms above are what vary.
        Capability::new("HTTP-auth: ", ALWAYS_COMPILED_IN),
        // 10. C `:112-117`: `#ifdef CURL_DISABLE_MIME` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/mime/mod.rs` from `lib/mime.c`,
        // backing the 12 exported `curl_mime_*` symbols. `mime` is one of
        // the engine's eight PUBLIC modules, so the capability is not merely
        // planned, it is reachable.
        Capability::new("Mime: ", ALWAYS_COMPILED_IN),
        // 11. C `:120-125`: `#ifdef CURL_DISABLE_NETRC` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/cookies/netrc.rs` from `lib/netrc.c`.
        Capability::new("netrc: ", ALWAYS_COMPILED_IN),
        // 12. C `:127-132`: `#ifdef CURL_DISABLE_PARSEDATE` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/util/parsedate.rs` from
        // `lib/parsedate.c`. Cannot be optional here even in principle --
        // `curl_getdate` is one of the 100 exported symbols, so the parser
        // is part of the ABI.
        Capability::new("parsedate: ", ALWAYS_COMPILED_IN),
        // 13. C `:134-139`: `#ifdef CURL_DISABLE_PROXY` -> OFF.
        //
        // AAP 0.4.1 maps the whole `curl-rs-lib/src/proxy/` tree; 228
        // fixtures gate on the `proxy` feature name (AAP 0.6.5), the single
        // most demanded capability in the corpus.
        Capability::new("proxy: ", ALWAYS_COMPILED_IN),
        // 14. C `:141-146`: `#ifdef CURL_DISABLE_SHUFFLE_DNS` -> OFF.
        //
        // GAP 2 of 5. Randomising the order of resolved addresses, the
        // capability behind `CURLOPT_DNS_SHUFFLE_ADDRESSES`. Searched the
        // whole of `curl-rs-lib/src` for `shuffle` (case-insensitive): zero
        // occurrences, in code or in comments. The owning module would be
        // `crate::dns`, which is `pub(crate)`.
        //
        // REQUIRED PREDICATE: a public capability predicate on the engine,
        // e.g. `pub fn curl_rs_lib::version::supports_dns_shuffle() -> bool`
        // -- or, more generally, for `curl-rs-lib` to expose whether a given
        // `CURLoption` is honoured, which would answer this row and row 1
        // together.
        Capability::new("shuffle-dns: ", NOT_DETERMINABLE),
        // 15. C `:148-153`: `#ifdef CURL_DISABLE_TYPECHECK` -> OFF.
        //
        // Compile-time type checking of `curl_easy_setopt`'s variadic
        // argument. AAP 0.6.3 records that
        // `include/curl/typecheck-gcc.h` -- 958 lines of 258 `curlcheck_`
        // macros that cbindgen cannot express -- "is carried as a
        // hand-maintained header shipped verbatim beside the generated one",
        // and that "it must remain correct because the 129 example programs
        // compile with it active". The facility is therefore present.
        Capability::new("typecheck: ", ALWAYS_COMPILED_IN),
        // 16. C `:155-160`: `#ifdef CURL_DISABLE_VERBOSE_STRINGS` -> OFF.
        //
        // Human-readable diagnostic text. AAP 0.4.1 maps
        // `curl-rs-lib/src/trace.rs` from `lib/curl_trc.c` with the
        // `--trace` formats frozen, and `curl-rs-lib/src/error.rs` carries
        // the full `CURLcode` message set rather than bare numbers. Nothing
        // in this workspace strips those strings.
        Capability::new("verbose-strings: ", ALWAYS_COMPILED_IN),
        // 17. C `:162-167`: `#ifndef ENABLE_WAKEUP` -> OFF. INVERTED.
        //
        // GAP 3 of 5. Whether `curl_multi_wakeup` can interrupt a blocking
        // `curl_multi_poll`. The C learns this by including the internal
        // `multihandle.h`. Here `curl_rs_lib::multi` IS public, but it
        // exposes no wakeup predicate: the only related symbol anywhere in
        // the engine is `CURLMcode::WakeupFailure`
        // (`curl-rs-lib/src/error.rs:784-785`, "Wakeup is unavailable or
        // failed"), and an error code cannot serve as a capability
        // predicate -- it is precisely the value returned when wakeup is
        // unavailable, so its existence proves nothing either way.
        //
        // REQUIRED PREDICATE: `pub fn curl_rs_lib::multi::wakeup_available()
        // -> bool`, sited on the public `multi` module that owns the
        // socketpair the capability depends on.
        Capability::new("wakeup: ", NOT_DETERMINABLE),
        // 18. C `:169-174`: `#ifdef CURL_DISABLE_HEADERS_API` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/headers/mod.rs` from `lib/headers.c`
        // and `lib/dynhds.c`, backing `curl_easy_header` and
        // `curl_easy_nextheader`. `headers` is one of the eight PUBLIC
        // modules, so this is reachable rather than merely planned.
        Capability::new("headers-api: ", ALWAYS_COMPILED_IN),
        // 19. C `:176-181`: `#ifndef USE_XATTR` -> OFF. INVERTED.
        //
        // GAP 4 of 5, and the one row whose answer is settled by an
        // explicit cross-file mandate rather than by inference.
        // `curl-rs/src/output/xattr.rs:165-169` -- the module that owns
        // `--xattr` -- states: "`src/curlinfo.c:176-181` prints `xattr: `
        // followed by `ON` or `OFF` from `#ifndef USE_XATTR`, so while this
        // gap stands the diagnostic binary must report `xattr: OFF`".
        //
        // The reason it stands: `std` has no extended-attribute API, no
        // `xattr` crate is among the workspace pins, and
        // `curl-rs-lib/src/ffi/sys.rs` -- the only sanctioned home for such
        // a call -- re-exports five things, none of them `fsetxattr`. That
        // module documents at :141-154 that it adopts upstream's own
        // unavailable-arm, `src/tool_xattr.h:46`'s
        // `#define fwrite_xattr(a, b, c) 0`, so `--xattr` is the same
        // silent no-op a real curl built without `USE_XATTR` performs.
        // Reporting `OFF` here is therefore CONSISTENT with what the tool
        // actually does, which is the requirement -- not a guess.
        //
        // REQUIRED PREDICATE: `fsetxattr`/`extattr_set_fd` wrappers added to
        // `curl-rs-lib/src/ffi/sys.rs` and surfaced as
        // `pub fn curl_rs_lib::version::supports_xattr() -> bool`. Closing
        // it means changing `set_file_xattr` and this row, and nothing else.
        Capability::new("xattr: ", NOT_DETERMINABLE),
        // 20. C `:183-188`: `#ifdef CURL_DISABLE_FORM_API` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/mime/formdata.rs` from
        // `lib/formdata.c`, backing the three legacy `curl_form*` symbols
        // that AAP 0.8.2 forbids removing.
        Capability::new("form-api: ", ALWAYS_COMPILED_IN),
        // 21. C `:190-195`: `#if (SIZEOF_TIME_T < 5)` -> OFF. NUMERIC.
        Capability::new("large-time: ", large_time()),
        // 22. C `:197-202`: `#if (SIZEOF_SIZE_T < 5)` -> OFF. NUMERIC.
        Capability::new("large-size: ", large_size()),
        // 23. C `:204-209`: `#ifndef CURL_HAVE_SHA512_256` -> OFF. INVERTED.
        //
        // GAP 5 of 5. SHA-512/256, used by HTTP Digest. AAP 0.4.1 does map
        // `curl-rs-lib/src/crypto/sha512_256.rs` from
        // `lib/curl_sha512_256.c`, and the dependency inventory in AAP
        // 0.5.1 pins `sha2 0.10.9` which provides the primitive -- but
        // `crate::crypto` is `pub(crate)` (the only trace of it reachable
        // from outside is a prose mention at
        // `curl-rs-lib/src/lib.rs:620`), so this crate cannot confirm the
        // primitive is wired in. AAP 0.6.5's asymmetry decides the tie:
        // claiming `ON` for a digest this binary cannot see would be the
        // over-report that makes fixtures run and fail.
        //
        // REQUIRED PREDICATE: `pub fn curl_rs_lib::version::has_sha512_256()
        // -> bool` (or a public `crypto` digest-capability enumeration)
        // backed by `crate::crypto::sha512_256`.
        Capability::new("sha512-256: ", NOT_DETERMINABLE),
        // 24. C `:212-219`: `#if !defined(_WIN32) ||
        // (defined(CURL_WINDOWS_UWP) || defined(CURL_DISABLE_CA_SEARCH) ||
        // defined(CURL_CA_SEARCH_SAFE))` -> OFF.
        //
        // The FIRST disjunct settles it. AAP 0.1.1 goal G8 fixes the target
        // matrix at `x86_64-unknown-linux-gnu`,
        // `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` and
        // `aarch64-apple-darwin`; AAP 0.2.2 puts every Windows source out of
        // scope. `_WIN32` is therefore never defined, `!defined(_WIN32)` is
        // always true, and the row is always `OFF`.
        //
        // Deliberately NOT written as `!cfg!(windows)`: there is no Windows
        // arm in this file, and a `cfg` would falsely suggest the value
        // could vary. The row must still EXIST, however -- omitting it would
        // make the output 28 lines instead of 29.
        Capability::new("win32-ca-searchpath: ", NOT_PRESENT),
        // 25. C `:221-226`: `#if !defined(_WIN32) ||
        // !defined(CURL_CA_SEARCH_SAFE)` -> OFF. Same reasoning as row 24.
        Capability::new("win32-ca-search-safe: ", NOT_PRESENT),
        // 26. C `:229-234`: `#ifdef CURL_DISABLE_LIBCURL_OPTION` -> OFF.
        //
        // The `--libcurl` flag, which emits a compilable C program
        // reproducing the current invocation. AAP 0.3.1 and 0.4.1 both list
        // `curl-rs/src/libcurl_src.rs` (from `src/tool_easysrc.c`), and AAP
        // 0.3.1 notes the obligation that its output "must remain valid C
        // against the generated header". Not a Cargo feature.
        Capability::new("--libcurl: ", ALWAYS_COMPILED_IN),
        // 27. C `:236-242`: POSITIVE test -> ON. See `override_dns`.
        Capability::new("override-dns: ", override_dns()),
        // 28. C `:244-249`: POSITIVE test -> ON. See `ssl_sessions`.
        Capability::new("ssl-sessions: ", ssl_sessions()),
        // 29. C `:251-257`: POSITIVE test `#if defined(USE_GNUTLS) ||
        // ((defined(USE_QUICHE) || defined(USE_OPENSSL)) &&
        // !defined(OPENSSL_NO_OCSP))` -> ON.
        //
        // Every macro in that condition names a backend this workspace does
        // not link. AAP 0.1.1 goal G4 makes rustls the sole TLS
        // implementation "not as a default, not behind a feature flag, not
        // as a fallback"; AAP 0.2.2 drops `lib/vtls/gtls.c`,
        // `lib/vtls/openssl.c` and `lib/vquic/curl_quiche.c` outright. With
        // neither GnuTLS nor OpenSSL nor the third QUIC backend present,
        // no disjunct can hold, so OCSP-based certificate status stapling
        // is definitively absent -- known, not merely undeterminable.
        Capability::new("cert-status: ", NOT_PRESENT),
    ]
}

// ===========================================================================
// Rendering
//
// The sink is a parameter rather than `println!` for two reasons. It lets the
// `#[cfg(test)]` module capture the exact bytes without spawning a process,
// and it avoids the panic `println!` raises when stdout is a closed pipe --
// `puts` in the C returns EOF and is ignored (`src/curlinfo.c:267-268`
// discards the return value), so aborting would be a behaviour change.
// ===========================================================================

/// Writes the 29 rows, one newline-terminated line each, and nothing else.
///
/// No leading, trailing or interior blank line is emitted: `writeln!` appends
/// exactly one `\n` per row, mirroring `puts`.
fn render<W: Write>(sink: &mut W) -> io::Result<()> {
    for capability in capabilities() {
        writeln!(sink, "{}{}", capability.label, capability.token())?;
    }

    Ok(())
}

/// Prints the table to standard output.
///
/// Deliberately mirrors `src/curlinfo.c:260-271` in every observable respect:
///
/// - Arguments are ignored. The C discards them explicitly at `:264-265`
///   with `(void)argc; (void)argv;`. Nothing here reads `std::env::args`, so
///   `--help`, `--version` and any positional argument all produce the
///   identical 29 lines. No argument parser is involved and `clap` is not a
///   dependency of this binary.
/// - Nothing is written to standard error, on any path.
/// - The exit status is always 0. The return type is `()` rather than
///   `ExitCode`, so no failure path can change it -- which matches the C's
///   unconditional `return 0` at `:270`, reached even when every row is
///   `OFF`. A write failure is consequently discarded rather than reported:
///   there is no channel left to report it on that would not itself breach
///   the contract.
/// - No identity string is emitted. `env!("CARGO_PKG_NAME")`,
///   `env!("CARGO_BIN_NAME")` and `env!("CARGO_PKG_VERSION")` are absent by
///   design: the Cargo package is `curl-rs` while every self-reported name in
///   this project stays `curl` (`src/tool_version.h:28`), and the version
///   anchors in `include/curl/curlver.h` are frozen by AAP 0.8.5 conflict C6.
///   Printing nothing but the table, as the C does, sidesteps the question
///   entirely and keeps the output a pure function of the compiled feature
///   set and the target (AAP 0.7's reproducibility obligation).
fn main() {
    let stdout = io::stdout();
    let mut sink = stdout.lock();

    let _ = render(&mut sink);
    let _ = sink.flush();
}

// ===========================================================================
// Tests
//
// Kept inside this file because `src/bin/` is a Cargo convention directory for
// binary auto-discovery, not a Rust module: there is no `mod.rs` here and a
// sibling file could not be reached from this crate root. Integration tests
// live in the top-level `tests-rs/` tree (AAP 0.3.1), so no
// `curl-rs/tests/` directory is created either.
//
// `assert!`/`assert_eq!` are the test vocabulary and are used freely; the
// production code above contains no `unwrap`, `expect` or `panic!`, and these
// helpers deliberately return `Option` rather than panicking so that a
// missing label is reported by an assertion instead of a unwinding helper.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// The 29 labels, transcribed byte-for-byte from `src/curlinfo.c:46-258`.
    ///
    /// Independently re-extracted with `grep -n ': "$' src/curlinfo.c`, which
    /// reports 29 lines at :47, :55, :63, :70, :77, :84, :91, :98, :105,
    /// :112, :120, :127, :134, :141, :148, :155, :162, :169, :176, :183,
    /// :190, :197, :204, :212, :221, :229, :236, :244 and :251. The
    /// non-uniform casing (`DoH`, `HTTP-auth`, `Mime`), the leading `--` on
    /// `--libcurl` and the single trailing space after every colon are all
    /// part of the contract and are asserted, not normalised.
    const EXPECTED_LABELS: [&str; CAPABILITY_COUNT] = [
        "bindlocal: ",
        "cookies: ",
        "basic-auth: ",
        "bearer-auth: ",
        "digest: ",
        "negotiate-auth: ",
        "aws: ",
        "DoH: ",
        "HTTP-auth: ",
        "Mime: ",
        "netrc: ",
        "parsedate: ",
        "proxy: ",
        "shuffle-dns: ",
        "typecheck: ",
        "verbose-strings: ",
        "wakeup: ",
        "headers-api: ",
        "xattr: ",
        "form-api: ",
        "large-time: ",
        "large-size: ",
        "sha512-256: ",
        "win32-ca-searchpath: ",
        "win32-ca-search-safe: ",
        "--libcurl: ",
        "override-dns: ",
        "ssl-sessions: ",
        "cert-status: ",
    ];

    /// The value of one row, or `None` when the label is not in the table.
    ///
    /// Returning `Option` rather than panicking keeps the helper free of
    /// `unwrap`/`expect`: callers assert against `Some(true)` or
    /// `Some(false)`, so a renamed or deleted label fails the assertion with
    /// a clear diff instead of unwinding.
    fn value_of(label: &str) -> Option<bool> {
        capabilities()
            .iter()
            .find(|capability| capability.label == label)
            .map(|capability| capability.enabled)
    }

    /// The exact bytes `render` produces, captured without spawning anything.
    ///
    /// `from_utf8_lossy` is used in place of a fallible conversion so that no
    /// `unwrap` appears; `output_is_pure_ascii` proves the conversion is
    /// lossless, which is what makes that substitution sound.
    fn rendered() -> String {
        let mut buffer: Vec<u8> = Vec::new();
        let outcome = render(&mut buffer);

        assert!(outcome.is_ok(), "rendering into a Vec must not fail");

        String::from_utf8_lossy(&buffer).into_owned()
    }

    // -- Shape of the table -------------------------------------------------

    #[test]
    fn the_table_has_exactly_twenty_nine_rows() {
        // The array type already guarantees this at compile time; asserting it
        // documents the number and pins the constant to the measured value.
        assert_eq!(CAPABILITY_COUNT, 29, "src/curlinfo.c declares 29 rows");
        assert_eq!(capabilities().len(), 29, "the table must have 29 rows");
        assert_eq!(EXPECTED_LABELS.len(), 29, "29 labels are expected");
    }

    #[test]
    fn labels_are_byte_identical_to_the_c_table_and_in_c_order() {
        let table = capabilities();

        for (index, (capability, expected)) in
            table.iter().zip(EXPECTED_LABELS.iter()).enumerate()
        {
            assert_eq!(
                capability.label, *expected,
                "row {index} label must match src/curlinfo.c byte for byte"
            );
        }
    }

    #[test]
    fn every_label_ends_with_a_colon_and_exactly_one_space() {
        for capability in &capabilities() {
            let label = capability.label;

            assert!(
                label.ends_with(": "),
                "label {label:?} must end with a colon and one space"
            );
            assert!(
                !label.ends_with(":  "),
                "label {label:?} must not end with two spaces"
            );
            assert!(!label.is_empty(), "no label may be empty");
            assert!(
                !label.contains('\n'),
                "label {label:?} must not contain a newline"
            );
        }
    }

    #[test]
    fn every_label_is_unique() {
        let table = capabilities();

        for (index, capability) in table.iter().enumerate() {
            let duplicates = table
                .iter()
                .filter(|other| other.label == capability.label)
                .count();

            assert_eq!(
                duplicates, 1,
                "label {:?} at row {index} appears more than once",
                capability.label
            );
        }
    }

    // -- The closed ON/OFF vocabulary --------------------------------------

    #[test]
    fn every_value_renders_as_exactly_on_or_off() {
        for capability in &capabilities() {
            let token = capability.token();

            assert!(
                token == ON || token == OFF,
                "token {token:?} for {:?} must be ON or OFF",
                capability.label
            );
            assert!(!token.is_empty(), "no token may be the empty string");
        }
    }

    #[test]
    fn the_token_follows_the_boolean() {
        assert_eq!(Capability::new("t: ", true).token(), "ON");
        assert_eq!(Capability::new("f: ", false).token(), "OFF");
    }

    // -- Shape of the rendered output --------------------------------------

    #[test]
    fn output_is_twenty_nine_newline_terminated_lines() {
        let text = rendered();

        assert_eq!(text.lines().count(), 29, "output must be 29 lines");
        assert!(text.ends_with('\n'), "every line is newline terminated");
        assert!(!text.contains("\n\n"), "no interior blank line is emitted");
        assert!(!text.starts_with('\n'), "no leading blank line");
        assert!(
            !text.ends_with("\n\n"),
            "no trailing blank line after the last row"
        );
    }

    #[test]
    fn every_output_line_is_a_label_followed_by_its_token() {
        let text = rendered();
        let table = capabilities();

        for (line, capability) in text.lines().zip(table.iter()) {
            let expected =
                format!("{}{}", capability.label, capability.token());

            assert_eq!(line, expected, "line must be label then token");
            assert!(
                line.ends_with(ON) || line.ends_with(OFF),
                "line {line:?} must end in ON or OFF"
            );
        }
    }

    #[test]
    fn output_is_pure_ascii() {
        // Justifies the lossy conversion in `rendered`, and confirms nothing
        // non-ASCII crept into a label.
        let text = rendered();

        assert!(text.is_ascii(), "the table is ASCII, as the C emits");
    }

    #[test]
    fn every_byte_goes_to_the_injected_sink() {
        // `render` writes to its sink and to nothing else, so the captured
        // length must account for the entire table: label + token + one
        // newline per row. This is the in-process form of "nothing is written
        // to stderr"; the process-level check runs the binary with
        // `2>&1 1>/dev/null` during validation.
        let text = rendered();
        let expected: usize = capabilities()
            .iter()
            .map(|capability| {
                capability.label.len() + capability.token().len() + 1
            })
            .sum();

        assert_eq!(text.len(), expected, "no byte may be diverted or lost");
    }

    // -- Polarity, asserted by name so a mechanical edit cannot flip it ----

    #[test]
    fn the_three_ifndef_inverted_rows_are_off() {
        // `#ifndef ENABLE_WAKEUP` (:163), `#ifndef USE_XATTR` (:177) and
        // `#ifndef CURL_HAVE_SHA512_256` (:205). A naive `#ifdef` to `OFF`
        // transliteration would render these ON; they are OFF here because
        // no public predicate can establish them (rows 17, 19 and 23), and
        // for `xattr` because `curl-rs/src/output/xattr.rs:165-169`
        // explicitly requires it.
        assert_eq!(value_of("wakeup: "), Some(false), "wakeup is inverted");
        assert_eq!(value_of("xattr: "), Some(false), "xattr is inverted");
        assert_eq!(
            value_of("sha512-256: "),
            Some(false),
            "sha512-256 is inverted"
        );
    }

    #[test]
    fn the_three_positive_test_rows_are_off() {
        // Rows 27, 28 and 29 are the only ones whose TRUE branch yields ON.
        // All three evaluate false in this build, for three different and
        // individually documented reasons.
        assert_eq!(
            value_of("override-dns: "),
            Some(false),
            "override-dns needs c-ares or a fake resolver; both are gone"
        );
        assert_eq!(
            value_of("ssl-sessions: "),
            Some(false),
            "ssl-sessions follows the SSLS-EXPORT feature, which is withheld"
        );
        assert_eq!(
            value_of("cert-status: "),
            Some(false),
            "cert-status needs GnuTLS or OpenSSL with OCSP; rustls is sole"
        );
    }

    // -- Numeric width rows -------------------------------------------------

    #[test]
    fn large_time_and_large_size_are_on_because_the_word_is_wide() {
        // The C tests `SIZEOF_TIME_T < 5` and `SIZEOF_SIZE_T < 5`. Asserting
        // against the measured widths documents WHY the answer is ON rather
        // than hard-coding it: all four targets in the AAP 0.1.1 G8 matrix
        // are 64-bit, so both widths are 8.
        let pointer_width = core::mem::size_of::<usize>();
        let time_width = core::mem::size_of::<i64>();

        assert!(pointer_width >= 5, "size_t must be at least 5 bytes wide");
        assert!(time_width >= 5, "time_t must be at least 5 bytes wide");

        assert_eq!(value_of("large-time: "), Some(true), "large-time is ON");
        assert_eq!(value_of("large-size: "), Some(true), "large-size is ON");
        assert_eq!(large_time(), time_width >= 5, "row 21 tracks the width");
        assert_eq!(large_size(), pointer_width >= 5, "row 22 tracks it too");
    }

    // -- The two Windows rows ----------------------------------------------

    #[test]
    fn the_two_win32_rows_are_off_on_every_mandated_target() {
        // `!defined(_WIN32)` is the first disjunct of both conditions and is
        // always true here: AAP 0.1.1 G8 lists only Linux and macOS targets
        // and AAP 0.2.2 excludes every Windows source. The rows must still
        // be present so the output stays 29 lines.
        assert_eq!(
            value_of("win32-ca-searchpath: "),
            Some(false),
            "no Windows target exists in the matrix"
        );
        assert_eq!(
            value_of("win32-ca-search-safe: "),
            Some(false),
            "no Windows target exists in the matrix"
        );
    }

    /// The platform invariant behind rows 24 and 25, checked at compile time.
    ///
    /// Written as an anonymous constant rather than an `assert!` inside a test
    /// because the condition folds to a constant, which
    /// `clippy::assertions_on_constants` correctly rejects in a runtime
    /// assertion. As a `const` item it becomes a build-time guarantee: if
    /// this crate were ever aimed at a Windows target, the two `win32-*` rows
    /// would need real conditions and this line would stop the build first.
    const _: () = assert!(
        !cfg!(windows),
        "curlinfo has no Windows arm; AAP 0.1.1 G8 lists no Windows target"
    );

    // -- Feature-driven rows, asserted under both settings ------------------

    #[cfg(not(feature = "negotiate"))]
    #[test]
    fn negotiate_auth_is_off_without_the_negotiate_feature() {
        assert_eq!(
            value_of("negotiate-auth: "),
            Some(false),
            "negotiate is a default-OFF feature (AAP 0.8.5 conflict C2)"
        );
    }

    #[cfg(feature = "negotiate")]
    #[test]
    fn negotiate_auth_is_on_with_the_negotiate_feature() {
        assert_eq!(
            value_of("negotiate-auth: "),
            Some(true),
            "--features negotiate must turn the row ON"
        );
    }

    #[cfg(feature = "cookies")]
    #[test]
    fn cookies_is_on_with_default_features() {
        assert_eq!(value_of("cookies: "), Some(true), "cookies defaults ON");
    }

    #[cfg(not(feature = "cookies"))]
    #[test]
    fn cookies_is_off_without_the_cookies_feature() {
        assert_eq!(
            value_of("cookies: "),
            Some(false),
            "--no-default-features must turn the row OFF"
        );
    }

    #[cfg(feature = "doh")]
    #[test]
    fn doh_is_on_with_default_features() {
        assert_eq!(value_of("DoH: "), Some(true), "doh defaults ON");
    }

    #[cfg(not(feature = "doh"))]
    #[test]
    fn doh_is_off_without_the_doh_feature() {
        assert_eq!(
            value_of("DoH: "),
            Some(false),
            "--no-default-features must turn the row OFF"
        );
    }

    #[test]
    fn override_dns_is_off_whatever_memdebug_is_set_to() {
        // The second conjunct of the C condition is permanently false, so
        // `memdebug` alone cannot flip the row. Asserted unconditionally
        // precisely so that building with `--features memdebug` still holds.
        assert!(!override_dns(), "the resolver conjunct is false");
        assert_eq!(value_of("override-dns: "), Some(false), "row 27 is OFF");
    }

    #[test]
    fn the_row_count_is_independent_of_the_feature_set() {
        // Every feature-driven row flips a boolean; none is conditionally
        // compiled away. This is what keeps the line count at 29 under
        // `--no-default-features` and under any `--features` combination.
        assert_eq!(capabilities().len(), CAPABILITY_COUNT);
        assert_eq!(rendered().lines().count(), CAPABILITY_COUNT);
    }

    // -- Consistency with the engine's own self-description ----------------

    #[test]
    fn ssl_sessions_agrees_with_curl_rs_lib_version() {
        // The single-source-of-truth check. Row 28 is not an independent
        // opinion: it IS `version::has_feature("SSLS-EXPORT")`.
        let advertised = version::has_feature(SSLS_EXPORT_FEATURE);

        assert_eq!(ssl_sessions(), advertised, "row 28 must not diverge");
        assert_eq!(
            value_of("ssl-sessions: "),
            Some(advertised),
            "the table must carry the engine's answer, not a copy of it"
        );
        assert_eq!(
            SSLS_EXPORT_FEATURE, "SSLS-EXPORT",
            "the name must match src/tool_libinfo.c:114 exactly"
        );
    }

    #[test]
    fn no_label_duplicates_a_version_feature_token() {
        // Anti-drift, per `src/curlinfo.c:26-30`: this table reports what
        // `curl -V` does NOT. The two vocabularies must stay disjoint, so a
        // future edit that moves a token here is caught. Compared case
        // insensitively because a casing-only collision would be just as
        // confusing to a reader.
        for capability in &capabilities() {
            let label = capability
                .label
                .trim_end()
                .trim_end_matches(':')
                .to_ascii_lowercase();

            for feature in version::FEATURES {
                assert_ne!(
                    label,
                    feature.name().to_ascii_lowercase(),
                    "label {:?} collides with a --version feature token",
                    capability.label
                );
            }
        }
    }

    #[test]
    fn no_label_names_a_protocol() {
        // `src/curlinfo.c:29-30`: "Disabled protocols are visible in
        // curl_version_info() and are not included in this table."
        for capability in &capabilities() {
            let label = capability
                .label
                .trim_end()
                .trim_end_matches(':')
                .to_ascii_lowercase();

            for scheme in version::protocols() {
                assert_ne!(
                    label, *scheme,
                    "label {:?} names a protocol; protocols belong in -V",
                    capability.label
                );
            }
        }
    }

    // -- Argument handling and exit status ---------------------------------

    #[test]
    fn rendering_is_deterministic_and_cannot_depend_on_arguments() {
        // `render` and `capabilities` take no argument source: the only
        // parameter is the sink. The table is therefore a pure function of
        // the compiled feature set and the target, which is both AAP 0.7's
        // reproducibility obligation and the reason `--help`, `--version`
        // and stray positional arguments cannot change the output.
        //
        // `main` returns `()`, so there is no path that yields a non-zero
        // exit status. The process-level confirmations -- running the binary
        // with arguments, checking `echo $?` and checking that stderr is
        // empty -- are performed against the built executable during
        // validation, because they cannot be observed from inside the
        // process.
        assert_eq!(rendered(), rendered(), "the table must be deterministic");
    }
}
