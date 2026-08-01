// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

// THE SAFETY INVARIANT, ASSERTED LOCALLY.
//
// `src/bin/curlinfo.rs` is its OWN crate root: Cargo compiles it as a
// separate crate from `src/main.rs` (both are declared as explicit
// `[[bin]]` targets in curl-rs/Cargo.toml). An attribute written in
// `src/main.rs` therefore does not reach this file, so the invariant is
// restated here rather than inherited.
//
// `forbid` is used, not `deny`. The engine crate settles for
// `#![deny(unsafe_code)]` because it must grant exactly one exemption --
// `#[allow(unsafe_code)]` on `pub(crate) mod ffi`, and `forbid` cannot be
// overridden from an inner scope at all -- the engine crate root records the
// measured `error[E0453]` beside its own attribute. This crate has no
// `mod ffi` and needs no exemption, so it takes the strictly stronger form:
// with `forbid`, not even a deliberate inner `#[allow(unsafe_code)]` can
// re-enable the keyword.
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
//! `add_executable(curlinfo EXCLUDE_FROM_ALL "curlinfo.c")`. It is
//! nevertheless in scope as a separate diagnostic binary derived from
//! `src/curlinfo.c`, and is reproduced here.
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
//! "consistency" would silently change program output: a refactor that
//! produces different-but-arguably-better output has failed.
//!
//! # These 29 lines are machine-read, and they gate 492 fixtures
//!
//! The C's own purpose comment presents this as a human diagnostic, and its
//! build classification agrees. That framing is incomplete, and the omission
//! matters more than anything else in this file: the test harness parses this
//! output and uses it to decide which fixtures to run.
//! `tests/runtests.pl:537-546` executes the binary named by
//! `tests/globalconfig.pm:122-123` and folds every line into its feature map:
//!
//! ```text
//! open(my $disabledh, "-|", exerunner() . shell_quote($CURLINFO));
//! while(<$disabledh>) {
//!   if($_ =~ /([^:]*): ([ONF]*)/) {
//!     my ($val, $toggle) = ($1, $2);
//!     push @disabled, $val if($toggle eq "OFF");
//!     $feature{$val} = 1   if($toggle eq "ON");
//!   }
//! }
//! ```
//!
//! So each label is a *feature name* in exactly the sense
//! `tests/data/test*`'s `<features>` blocks mean it, and each `ON` grants
//! eligibility while each `OFF` withdraws it. Measured over the corpus, 492
//! fixtures gate positively on a label here and one gates negatively;
//! `proxy` alone accounts for 225, then `digest` 76, `cookies` 51, `Mime`
//! 48, `aws` 22, `headers-api` 14, `--libcurl` 11, `verbose-strings` 10,
//! `form-api` 9. `tests/http/testenv/env.py:162-167` reads the same output
//! for `verbose-strings: ON` and `cert-status: ON`, and raises if the exit
//! status is non-zero -- which is why the unconditional `return 0` below is a
//! contract and not a stylistic choice.
//!
//! AAP 0.6.5's asymmetry therefore applies here with full force, identically
//! to the `Features:` line of `curl --version`: "under-reporting a
//! capability makes a fixture skip; over-reporting makes it run and fail."
//! A row that claims `ON` for an implementation this workspace does not carry
//! does not merely mislead a reader -- it converts a clean skip into a hard
//! failure, hundreds of times over.
//!
//! # Where the values come from
//!
//! The C reads its answers straight out of the preprocessor. `:32-38`
//! includes five *internal* library headers purely to observe build macros
//! (`curl_setup.h` for the `CURL_DISABLE_*` family, `multihandle.h` for
//! `ENABLE_WAKEUP`, `tool_xattr.h` for `USE_XATTR`, `curl_sha512_256.h` for
//! `CURL_HAVE_SHA512_256`, `asyn.h` for `CURLRES_ARES` and
//! `fake_addrinfo.h` for `USE_FAKE_GETADDRINFO`), plus
//! `<openssl/opensslconf.h>` at `:42-44` for `OPENSSL_NO_OCSP`.
//!
//! None of that is reachable from Rust, by design. The C tree's
//! `Curl_`-prefixed "private by convention" linkage becomes `pub(crate)`
//! "private by enforcement", and `curl-rs-lib` exposes exactly eight public
//! modules -- `error`, `version`, `url`, `headers`, `mime`, `share`, `easy`
//! and `multi`. The twelve that would carry these answers (`trace`, `util`,
//! `ffi`, `crypto`, `dns`, `conn`, `tls`, `proxy`, `auth`, `cookies`,
//! `transfer`, `protocols`) are `pub(crate)` and invisible here.
//!
//! The substitute is not a guess, and it is not a table of literals. It is
//! the engine capability registry -- `curl_rs_lib::version::Engine` and the
//! `ENGINE_*` constants -- which records, for every module AAP 0.4.1 assigns
//! a capability, whether this build carries a working implementation of it.
//! That registry is the same one the `--version` banner consults, so the two
//! self-description surfaces cannot disagree, which is the transformation
//! rule AAP 0.1.2 states as "a single Rust module is the sole source of
//! truth". Every value below comes from exactly one of these sources:
//!
//! 1. An `ENGINE_*` entry, on its own or conjoined with a Cargo feature. A
//!    capability claim has two independent preconditions -- was it *selected*
//!    for this build, and does the module that *honours* it exist -- and C
//!    never had to separate them because its `#if` decided both at once.
//!    Twenty-two rows are answered this way.
//! 2. `cfg!(feature = "...")` over this crate's own compiled feature set,
//!    always as one conjunct of an engine test rather than alone.
//!    `curl-rs/Cargo.toml` declares exactly fifteen features and forwards
//!    each to `curl-rs-lib/<name>` while holding `default-features = false`
//!    on the path dependency, so the tool's feature set cannot diverge from
//!    the engine's. There is no `tls` feature and none is invented here.
//! 3. A genuine build-intrinsic fact: the width of a machine word (rows 21
//!    and 22), or the absence of a platform or a TLS backend that AAP 0.1.1
//!    and 0.2.2 exclude outright (rows 24, 25, 29). These are properties of
//!    the build, not of an unwritten module, so no engine gates them.
//! 4. Named analogues of C macros the transformation removed, for the one
//!    compound condition that needs them (row 27).
//!
//! Nothing here reports a capability it cannot substantiate, and nothing
//! reports a third token. Exactly four rows read `ON`: `verbose-strings` and
//! `xattr`, each naming a module that exists and an item it exports which the
//! registry pins at compile time, and `large-time` and `large-size`, which
//! measure a machine word. The other twenty-five read `OFF`, and each says
//! which named module or excluded platform makes it so.
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
//! One asymmetry governs every uncertain row: under-reporting a capability
//! makes a fixture skip, while over-reporting makes it run and fail. Four
//! rows -- `bindlocal`, `shuffle-dns`, `wakeup` and `sha512-256` -- once had
//! no public predicate that could establish them at all, and were reported
//! `OFF` on that basis. They are still `OFF`, but no longer on that basis:
//! each now reads a named engine in `curl_rs_lib::version`, so the row says
//! "this module is measurably absent" rather than "this file cannot see far
//! enough to tell", and each will turn `ON` by itself on the day its module
//! lands. The Derivation classes note below records the change in full.
//!
//! Two tokens only, never a third. An `UNKNOWN` would be a new spelling in
//! frozen output (`src/curlinfo.c` emits `ON` or `OFF`), and a reader who
//! saw it could not act on it, whereas `OFF` is both truthful and
//! actionable while the module is missing.
//!
//! `xattr` is the row where that asymmetry resolved the other way. The
//! wrapper it needed now exists in `curl-rs-lib/src/ffi/sys.rs` and
//! `curl-rs/src/output/xattr.rs` really writes the attribute, so the row
//! reports `ON` on the strength of the implementation rather than of a
//! guess -- see [`use_xattr`], which conjoins the wrapper's engine with the
//! two operating systems whose arm it compiles.

use std::io::{self, Write};

use curl_rs_lib::version;

// The two output tokens
//
// The vocabulary is closed: `ON` and `OFF`, nothing else. There is
// deliberately no `UNKNOWN`, no `N/A` and no empty string -- the C emits one
// of these two for all 29 rows, and a consumer parsing the table would break
// on a third value.

/// The token a compiled-in capability renders as.
const ON: &str = "ON";

/// The token an absent capability renders as.
const OFF: &str = "OFF";

// Derivation classes
//
// Named rather than written as bare `true`/`false` literals so that each row
// declares WHY it holds its value, not merely what the value is. One name is
// left, for the one class of row that no engine gates. Everything else in the
// table derives from `curl_rs_lib::version`'s engine registry, from a machine
// word width, or from a named macro analogue, so there is nothing left for a
// `true` literal to stand for.
//
// Two names that used to live here are gone, and their removal is the whole of
// this file's compliance story:
//
// * `ALWAYS_COMPILED_IN: bool = true` forced fourteen rows ON -- the five auth
//   mechanisms, MIME, the form API, netrc, parsedate, proxy, typecheck,
//   verbose-strings, the header API and `--libcurl` -- on the reasoning that no
//   Cargo feature could switch them off. That reasoning confused CONFIGURATION
//   with IMPLEMENTATION: the absence of a switch says nothing about whether the
//   module behind the switch was ever written, and eleven of those fourteen
//   modules do not exist. Between them those rows over-advertised 462 fixtures
//   into running against nothing.
// * `NOT_DETERMINABLE: bool = false` marked four rows as unanswerable and
//   listed, at each use site, the public predicate `curl-rs-lib` would have to
//   grow. Those predicates now exist, so the name has nothing left to mark.
//   `bindlocal` reads `ENGINE_CONN`, `shuffle-dns` reads `ENGINE_DNS`, `wakeup`
//   reads `ENGINE_MULTI` and `sha512-256` reads `ENGINE_SHA512_256`. All four
//   still render OFF -- but now because a named module is measurably absent,
//   not because this file could not see far enough to tell.

/// A capability this build definitively does not provide, for reasons no
/// engine can change.
///
/// Used by exactly three rows, and only where the answer is *known* rather
/// than merely unwritten: the two `win32-*` rows, which need a platform
/// AAP 0.1.1 goal G8 excludes from the target matrix, and `cert-status`,
/// which needs a TLS backend AAP 0.1.1 goal G4 excludes from every
/// configuration. Writing a module cannot flip any of the three, which is
/// what distinguishes them from the twenty-two engine-gated rows: those will
/// turn ON when their implementation lands, and these will not.
const NOT_PRESENT: bool = false;

// Macro analogues that are permanently false in this implementation
//
// These mirror C macros the transformation removed outright. They are named
// after the macro they replace so the compound conditions further down can be
// read against the C source line by line.

/// `CURLRES_ARES` -- the c-ares resolver backend.
///
/// c-ares is dropped entirely, replaced by the system resolver, with
/// `hickory-dns` an optional default-off alternative; `lib/asyn-ares.c` is
/// among the excluded sources. No Cargo feature can define this, so it is
/// permanently false.
const CURLRES_ARES: bool = false;

/// `USE_FAKE_GETADDRINFO` -- the test-only resolver interception hook.
///
/// `lib/fake_addrinfo.c` has no counterpart in this workspace, so the
/// capability does not exist here in any configuration.
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

// The computed rows
//
// These rows are not a single constant or a single feature flag. Each is given
// a named function so its derivation sits next to the C condition it
// reproduces, and so the `#[cfg(test)]` module can assert it by name.

/// Row 16, `verbose-strings`. C: `#ifdef CURL_DISABLE_VERBOSE_STRINGS` yields
/// `OFF` (`src/curlinfo.c:155-160`).
///
/// One of the two rows that reads `ON`, and the claim is narrow: that this
/// build carries human-readable diagnostic *text*, not that it can describe a
/// transfer. C's macro shrinks the binary by emptying `failf()` and `infof()`
/// of their message strings; here `curl-rs-lib/src/error.rs` carries the
/// complete `CURLcode` message set behind the public `CURLcode::message`, and
/// `curl-rs-lib/src/trace.rs` carries the `infof!`/`failf!` macros with the
/// `--trace` formats frozen. No Cargo feature strips either, and
/// [`version::ENGINE_DIAGNOSTIC_STRINGS`] pins that pairing at compile time.
///
/// `tests/data/test1538` is the corroboration: it gates on `verbose-strings`
/// and is titled "libcurl strerror API call tests", which is exactly what
/// `CURLcode::message` answers. The value is read from the registry rather
/// than probed locally so that this row and the `--version` banner cannot
/// drift; the registry's own
/// `every_present_engine_has_a_compile_time_link` test is what proves the
/// message table is really there.
const fn verbose_strings() -> bool {
    version::ENGINE_DIAGNOSTIC_STRINGS.is_present()
}

/// Row 19, `xattr`. C: `#ifndef USE_XATTR` yields `OFF`
/// (`src/curlinfo.c:176-181`), so the C test is INVERTED and this function
/// answers its positive form.
///
/// C defines `USE_XATTR` when the build detects an `fsetxattr` with either the
/// five-argument Linux signature or the six-argument macOS one
/// (`HAVE_FSETXATTR_5` and `HAVE_FSETXATTR_6`, selected at
/// `src/tool_xattr.c:88-92`). `curl-rs/src/output/xattr.rs` issues that call
/// through `curl_rs_lib::set_file_xattr`, which selects between the two forms
/// itself, so the capability is present wherever either spelling is.
///
/// Both conjuncts are load-bearing and neither implies the other.
/// [`version::ENGINE_XATTR`] says the wrapper exists -- a fact this crate root
/// could not otherwise establish, since `bin/curlinfo.rs` is compiled
/// separately from `src/main.rs` and so does not fail to build when the
/// wrapper disappears from under `curl-rs/src/output/xattr.rs`. The `cfg`
/// says this is one of the two operating systems whose arm the wrapper
/// compiles; AAP 0.2.2 puts every other platform out of scope, so a build for
/// one would correctly report `OFF` rather than advertise a syscall it cannot
/// issue.
const fn use_xattr() -> bool {
    version::ENGINE_XATTR.is_present()
        && cfg!(any(target_os = "linux", target_os = "macos"))
}

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
/// rather than an approximation. All four mandated targets are 64-bit, giving
/// 8 bytes and therefore `ON`.
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

/// The 29 diagnostic rows, in the order `src/curlinfo.c:46-258` declares them.
fn capabilities() -> [Capability; CAPABILITY_COUNT] {
    [
        // 1. C `:47-52`: `#ifdef CURL_DISABLE_BINDLOCAL` -> OFF.
        //
        // Binding a transfer to a local interface, address or port -- C's
        // `bindlocal()` in `lib/cf-socket.c`, behind `--interface`,
        // `--local-port` and `CURLOPT_INTERFACE`. AAP 0.4.1 maps that file
        // to `curl-rs-lib/src/conn/socket.rs` and `lib/if2ip.c` to
        // `curl-rs-lib/src/dns/if2ip.rs`; neither exists, so there is no
        // socket to bind. No fixture gates on the label.
        Capability::new("bindlocal: ", version::ENGINE_CONN.is_present()),
        // 2. C `:55-60`: `#ifdef CURL_DISABLE_COOKIES` -> OFF.
        //
        // Both preconditions, and the second is what changed: the `cookies`
        // Cargo feature is default ON (`curl-rs/Cargo.toml` `default` list)
        // and forwards to `curl-rs-lib/cookies`, but `cookies/mod.rs` -- the
        // jar itself -- is unwritten, so the feature selects nothing. 51
        // fixtures gate on the label and skip.
        Capability::new(
            "cookies: ",
            cfg!(feature = "cookies")
                && version::ENGINE_STATE_STORES.is_present(),
        ),
        // 3. C `:63-68`: `#ifdef CURL_DISABLE_BASIC_AUTH` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/auth/basic.rs` CREATE from
        // `lib/vauth/cleartext.c`. Unwritten, so no `Authorization: Basic`
        // header can be composed. That no Cargo feature switches it off is
        // beside the point: the C macro's absence means "not disabled", not
        // "implemented".
        Capability::new(
            "basic-auth: ",
            version::ENGINE_AUTH_BASIC.is_present(),
        ),
        // 4. C `:70-75`: `#ifdef CURL_DISABLE_BEARER_AUTH` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/auth/bearer.rs` from
        // `lib/vauth/oauth2.c`. Unwritten, so `--oauth2-bearer` has nothing
        // to serve it.
        Capability::new(
            "bearer-auth: ",
            version::ENGINE_AUTH_BEARER.is_present(),
        ),
        // 5. C `:77-82`: `#ifdef CURL_DISABLE_DIGEST_AUTH` -> OFF.
        //
        // Backed by `curl-rs-lib/src/auth/digest.rs`, from
        // `lib/vauth/digest.c` and `lib/http_digest.c`, with message
        // construction byte-exact. Unwritten -- and none of that byte-exact
        // construction exists to be exact about. 76 fixtures gate on the
        // label and skip, the second-largest withholding in the table.
        Capability::new("digest: ", version::ENGINE_AUTH_DIGEST.is_present()),
        // 6. C `:84-89`: `#ifdef CURL_DISABLE_NEGOTIATE_AUTH` -> OFF.
        //
        // A Cargo feature, default OFF. AAP 0.8.5 conflict C2 keeps
        // Negotiate behind a non-default `negotiate` feature so that the
        // default build links no C security library at all, which is what
        // reconciles "no C TLS linkage at any configuration" with
        // "Negotiate where OS Kerberos is available". The engine conjunct is
        // the same one the `SPNEGO` banner token uses: `curl-rs-lib/src/
        // ffi/gss.rs` exists, but `auth/negotiate.rs` -- the module that
        // would drive it through an HTTP exchange -- does not.
        Capability::new(
            "negotiate-auth: ",
            cfg!(feature = "negotiate") && version::ENGINE_GSS.is_present(),
        ),
        // 7. C `:91-96`: `#ifdef CURL_DISABLE_AWS` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/auth/aws_sigv4.rs` from
        // `lib/http_aws_sigv4.c`. Unwritten, so `--aws-sigv4` cannot sign
        // anything even though `sha2` and `hmac` are linked. 22 fixtures
        // gate on the label and skip.
        Capability::new("aws: ", version::ENGINE_AUTH_AWS_SIGV4.is_present()),
        // 8. C `:98-103`: `#ifdef CURL_DISABLE_DOH` -> OFF.
        //
        // A Cargo feature, default ON, forwarding to `curl-rs-lib/doh`
        // (AAP 0.4.1: `curl-rs-lib/src/dns/doh.rs` from `lib/doh.c`).
        // Doubly unreachable: the module is unwritten and so are the
        // resolver and TLS layers it would issue its query over. 5 fixtures
        // gate on the label and skip.
        Capability::new(
            "DoH: ",
            cfg!(feature = "doh") && version::ENGINE_DOH.is_present(),
        ),
        // 9. C `:105-110`: `#ifdef CURL_DISABLE_HTTP_AUTH` -> OFF.
        //
        // The HTTP authentication dispatcher, AAP 0.4.1
        // `curl-rs-lib/src/auth/mod.rs` from `lib/vauth/vauth.c`. Not a
        // Cargo feature; the individual mechanisms above are what vary in a
        // C build. Unwritten, so there is nothing to select between.
        Capability::new(
            "HTTP-auth: ",
            version::ENGINE_AUTH_DISPATCH.is_present(),
        ),
        // 10. C `:112-117`: `#ifdef CURL_DISABLE_MIME` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/mime/mod.rs` from `lib/mime.c`,
        // backing the 12 exported `curl_mime_*` symbols. `lib.rs:787`
        // declares `pub mod mime;` -- but a declaration is not an
        // implementation, and the file does not exist. Reading reachability
        // off the `pub` keyword was the specific mistake this row used to
        // make. 48 fixtures gate on the label and skip.
        Capability::new("Mime: ", version::ENGINE_MIME.is_present()),
        // 11. C `:120-125`: `#ifdef CURL_DISABLE_NETRC` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/cookies/netrc.rs` from `lib/netrc.c`.
        // Unwritten, so `--netrc`, `--netrc-file` and `--netrc-optional`
        // have no file parser. Gated on its own engine rather than on the
        // cookie jar's, even though the two files are siblings, so that
        // landing one cannot silently advertise the other.
        Capability::new("netrc: ", version::ENGINE_NETRC.is_present()),
        // 12. C `:127-132`: `#ifdef CURL_DISABLE_PARSEDATE` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/util/parsedate.rs` from
        // `lib/parsedate.c`. `util/mod.rs:334` declares the module and the
        // file does not exist, so `curl_getdate` -- one of the 100 exported
        // symbols -- has no parser behind it and `--time-cond` cannot
        // interpret its argument. Being part of the ABI makes the row
        // mandatory, not true.
        Capability::new("parsedate: ", version::ENGINE_PARSEDATE.is_present()),
        // 13. C `:134-139`: `#ifdef CURL_DISABLE_PROXY` -> OFF.
        //
        // AAP 0.4.1 maps the whole `curl-rs-lib/src/proxy/` tree and none of
        // it exists. This is the costliest row in the table: 225 fixtures
        // gate on the `proxy` label and skip. One gates on `!proxy` and
        // becomes eligible -- `tests/data/test375`, which requires `-x` to
        // fail with `curl: proxy support is disabled in this libcurl` and
        // `<errorcode> 4`. That is the right pairing rather than a
        // regression: reporting OFF is what makes that obligation visible.
        Capability::new("proxy: ", version::ENGINE_PROXY.is_present()),
        // 14. C `:141-146`: `#ifdef CURL_DISABLE_SHUFFLE_DNS` -> OFF.
        //
        // Randomising the order of resolved addresses, the capability behind
        // `CURLOPT_DNS_SHUFFLE_ADDRESSES`. A property of the resolver, so it
        // reads the resolver's engine: `dns/mod.rs` and `dns/resolver.rs`
        // are unwritten, and a case-insensitive search of
        // `curl-rs-lib/src` for `shuffle` still finds nothing. 1 fixture
        // gates on the label and skips.
        Capability::new("shuffle-dns: ", version::ENGINE_DNS.is_present()),
        // 15. C `:148-153`: `#ifdef CURL_DISABLE_TYPECHECK` -> OFF.
        //
        // Compile-time type checking of `curl_easy_setopt`'s variadic
        // argument. AAP 0.6.3 records that `include/curl/typecheck-gcc.h` --
        // 958 lines of 258 `curlcheck_` macros that cbindgen cannot express
        // -- "is carried as a hand-maintained header shipped verbatim beside
        // the generated one". That header does exist; what does not is the
        // generated one beside it. The macros take effect only when a C
        // consumer includes `curl/curl.h`, which `curl-rs-ffi/build.rs` must
        // produce with cbindgen from `curl-rs-ffi/src/ffi/` -- and
        // `curl-rs-ffi/src/lib.rs:852` declares `mod ffi` with no source, so
        // `ffi/easy.rs`, holding the very `curl_easy_setopt` those macros
        // wrap, is absent. A facility with nothing to check is not present.
        Capability::new(
            "typecheck: ",
            version::ENGINE_PUBLIC_HEADER.is_present(),
        ),
        // 16. C `:155-160`: `#ifdef CURL_DISABLE_VERBOSE_STRINGS` -> OFF.
        //
        // ON. See [`verbose_strings`]: the claim is about diagnostic TEXT,
        // and `error.rs` and `trace.rs` both exist and carry it.
        Capability::new("verbose-strings: ", verbose_strings()),
        // 17. C `:162-167`: `#ifndef ENABLE_WAKEUP` -> OFF. INVERTED.
        //
        // Whether `curl_multi_wakeup` can interrupt a blocking
        // `curl_multi_poll`. The C learns this from the internal
        // `multihandle.h`; here it reads the multi handle's own engine.
        // `lib.rs:897` declares `pub mod multi;` and `multi/state.rs`
        // exists, but `multi/mod.rs` does not, so there is no handle to own
        // the socketpair the capability depends on.
        // `CURLMcode::WakeupFailure` (`error.rs:784-785`) remains no
        // evidence either way -- it is precisely the value returned when
        // wakeup is unavailable. 2 fixtures gate on the label and skip.
        Capability::new("wakeup: ", version::ENGINE_MULTI.is_present()),
        // 18. C `:169-174`: `#ifdef CURL_DISABLE_HEADERS_API` -> OFF.
        //
        // Backed by `curl-rs-lib/src/headers/mod.rs`, from `lib/headers.c`
        // and `lib/dynhds.c`, backing `curl_easy_header` and
        // `curl_easy_nextheader`. `lib.rs:653` declares `pub mod headers;`
        // and, as with `Mime`, the declaration is all there is. 14 fixtures
        // gate on the label and skip.
        Capability::new("headers-api: ", version::ENGINE_HEADERS.is_present()),
        // 19. C `:176-181`: `#ifndef USE_XATTR` -> OFF. INVERTED.
        //
        // ON. Derived, not asserted: [`use_xattr`] answers the positive form
        // of C's test from two conjuncts -- that the engine's `fsetxattr`
        // wrapper exists, and that this is one of the operating systems
        // whose arm it compiles. `curl-rs/src/output/xattr.rs` issues that
        // call, so the row reports what `--xattr` actually does.
        Capability::new("xattr: ", use_xattr()),
        // 20. C `:183-188`: `#ifdef CURL_DISABLE_FORM_API` -> OFF.
        //
        // Backed by `curl-rs-lib/src/mime/formdata.rs`, from
        // `lib/formdata.c`, backing the three legacy `curl_form*` symbols
        // that AAP 0.8.2 forbids removing. Unwritten. Gated separately from
        // `Mime` because C guards the two separately and either can be
        // disabled alone. 9 fixtures gate on the label and skip.
        Capability::new("form-api: ", version::ENGINE_FORM.is_present()),
        // 21. C `:190-195`: `#if (SIZEOF_TIME_T < 5)` -> OFF. NUMERIC.
        Capability::new("large-time: ", large_time()),
        // 22. C `:197-202`: `#if (SIZEOF_SIZE_T < 5)` -> OFF. NUMERIC.
        Capability::new("large-size: ", large_size()),
        // 23. C `:204-209`: `#ifndef CURL_HAVE_SHA512_256` -> OFF. INVERTED.
        //
        // SHA-512/256, which HTTP Digest consults for `SHA-512-256`
        // challenges. AAP 0.4.1 maps `curl-rs-lib/src/crypto/sha512_256.rs`
        // from `lib/curl_sha512_256.c` and AAP 0.5.1 pins `sha2 0.10.9`,
        // which provides the primitive; `crypto/mod.rs:369` declares the
        // module and the file does not exist, so nothing wires the primitive
        // to a digest. 5 fixtures gate on the label and skip.
        Capability::new(
            "sha512-256: ",
            version::ENGINE_SHA512_256.is_present(),
        ),
        // 24. C `:212-219`: `#if !defined(_WIN32) ||
        // (defined(CURL_WINDOWS_UWP) || defined(CURL_DISABLE_CA_SEARCH) ||
        // defined(CURL_CA_SEARCH_SAFE))` -> OFF.
        //
        // The FIRST disjunct settles it. The target matrix is
        // `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
        // `x86_64-apple-darwin` and `aarch64-apple-darwin`, and every Windows
        // source is out of scope. `_WIN32` is therefore never defined,
        // `!defined(_WIN32)` is always true, and the row is always `OFF`.
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
        // against the generated header". Not a Cargo feature, and not
        // written: the file does not exist. The engine entry names a path in
        // THIS crate rather than in the engine, which the registry already
        // supports -- `ENGINE_GLOBAL_INIT` names a `curl-rs-ffi` path -- and
        // which is what lets one table answer both self-description
        // surfaces. 11 fixtures gate on the label and skip.
        Capability::new(
            "--libcurl: ",
            version::ENGINE_LIBCURL_SOURCE.is_present(),
        ),
        // 27. C `:236-242`: POSITIVE test -> ON. See `override_dns`.
        Capability::new("override-dns: ", override_dns()),
        // 28. C `:244-249`: POSITIVE test -> ON. See `ssl_sessions`.
        Capability::new("ssl-sessions: ", ssl_sessions()),
        // 29. C `:251-257`: POSITIVE test `#if defined(USE_GNUTLS) ||
        // ((defined(USE_QUICHE) || defined(USE_OPENSSL)) &&
        // !defined(OPENSSL_NO_OCSP))` -> ON.
        //
        // Every macro in that condition names a backend this workspace does not
        // link. rustls is the sole TLS implementation -- not as a default, not
        // behind a feature flag, not as a fallback -- and this workspace drops
        // `lib/vtls/gtls.c`, `lib/vtls/openssl.c` and `lib/vquic/curl_quiche.c`
        // outright. With neither GnuTLS nor OpenSSL nor the third QUIC backend
        // present, no disjunct can hold, so OCSP-based certificate status
        // stapling is definitively absent -- known, not merely undeterminable.
        // Unlike the engine-gated rows above, this one will not turn ON when a
        // module lands: no rustls configuration satisfies the C condition, so
        // it is [`NOT_PRESENT`] rather than a capability awaiting an
        // implementation.
        Capability::new("cert-status: ", NOT_PRESENT),
    ]
}

// Rendering
//
// The sink is a parameter rather than `println!` for two reasons. It lets the
// `#[cfg(test)]` module capture the exact bytes without spawning a process,
// and it avoids the panic `println!` raises when stdout is a closed pipe --
// `puts` in the C returns EOF and is ignored (`src/curlinfo.c:267-268`
// discards the return value), so aborting would be a behaviour change.

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
///   anchors in `include/curl/curlver.h` are frozen.
///   Printing nothing but the table, as the C does, sidesteps the question
///   entirely and keeps the output a pure function of the compiled feature
///   set and the target, which reproducibility requires.
fn main() {
    let stdout = io::stdout();
    let mut sink = stdout.lock();

    let _ = render(&mut sink);
    let _ = sink.flush();
}

// Tests
//
// Kept inside this file because `src/bin/` is a Cargo convention directory for
// binary auto-discovery, not a Rust module: there is no `mod.rs` here and a
// sibling file could not be reached from this crate root. Integration tests
// belong in the top-level `tests-rs/` tree, so no `curl-rs/tests/`
// directory is created either.
//
// `assert!`/`assert_eq!` are the test vocabulary and are used freely; the
// production code above contains no `unwrap`, `expect` or `panic!`, and these
// helpers deliberately return `Option` rather than panicking so that a
// missing label is reported by an assertion instead of a unwinding helper.

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
    fn the_two_inverted_rows_with_absent_engines_are_off() {
        // `#ifndef ENABLE_WAKEUP` (:163) and `#ifndef CURL_HAVE_SHA512_256`
        // (:205). A naive `#ifdef` to `OFF` transliteration would render
        // these ON. They are OFF here for a stated, checkable reason --
        // `multi/mod.rs` and `crypto/sha512_256.rs` are absent -- so the
        // assertion tracks those engines rather than a literal, and it will
        // start demanding ON the moment either module lands.
        assert_eq!(
            value_of("wakeup: "),
            Some(version::ENGINE_MULTI.is_present()),
            "row 17 tracks the multi handle"
        );
        assert_eq!(
            value_of("sha512-256: "),
            Some(version::ENGINE_SHA512_256.is_present()),
            "row 23 tracks the SHA-512/256 module"
        );
    }

    #[test]
    fn the_xattr_row_follows_the_engine_wrapper() {
        // `#ifndef USE_XATTR` (:177), also inverted -- and derived from two
        // conjuncts, so both are asserted. On every target in the AAP 0.1.1
        // goal G8 matrix the engine's `fsetxattr` wrapper exists AND the
        // platform is one of the two its arms compile, so the row is ON, and
        // `curl-rs/src/output/xattr.rs` issues that call.
        assert_eq!(value_of("xattr: "), Some(use_xattr()));
        assert_eq!(
            use_xattr(),
            version::ENGINE_XATTR.is_present()
                && cfg!(any(target_os = "linux", target_os = "macos")),
            "neither conjunct may be dropped"
        );
        assert!(use_xattr(), "all four mandated targets are Linux or macOS");
        assert!(
            version::ENGINE_XATTR.is_present(),
            "curl_rs_lib::set_file_xattr is what this row reports on"
        );
    }

    #[test]
    fn the_verbose_strings_row_follows_the_diagnostic_text_engine() {
        // `#ifdef CURL_DISABLE_VERBOSE_STRINGS` (:156). ON, and the claim is
        // substantiated at its point of use rather than trusted: the engine
        // entry says `error.rs` carries the message set, and the message set
        // answers.
        assert_eq!(value_of("verbose-strings: "), Some(verbose_strings()));
        assert_eq!(
            verbose_strings(),
            version::ENGINE_DIAGNOSTIC_STRINGS.is_present(),
            "row 16 is the registry's answer, not a second opinion"
        );
        assert!(
            !curl_rs_lib::CURLcode::UnsupportedProtocol
                .message()
                .is_empty(),
            "the text this row advertises must really be present"
        );
    }

    #[test]
    fn the_xattr_row_reports_the_capability_that_is_implemented() {
        // `#ifndef USE_XATTR` (:177), the third inverted row, and the one whose
        // answer changed when the write became real. `curl-rs/src/output/xattr.rs`
        // calls `curl_rs_lib::set_file_xattr` for every attribute, so `ON` is
        // what the tool actually does; its
        // `the_diagnostic_binary_agrees_that_xattr_is_on` asserts the same fact
        // from the other side so the pair cannot drift.
        assert_eq!(value_of("xattr: "), Some(true), "xattr is implemented");
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

    // -- Every row traces to a typed predicate ------------------------------

    /// The engine each of the 22 engine-gated rows derives from.
    ///
    /// Transcribed from the table above so that the two cannot drift: if a row
    /// is rewired to a different engine, or a new bare literal is introduced,
    /// [`no_row_outlives_the_engine_that_would_implement_it`] stops agreeing.
    /// The seven rows deliberately absent from this list are the two machine
    /// word widths (21, 22), the two `win32-*` rows and `cert-status` (24, 25,
    /// 29), `override-dns` (27) and `ssl-sessions` (28) -- each covered by its
    /// own test below or above.
    const ROW_ENGINES: [(&str, version::Engine); 22] = [
        ("bindlocal: ", version::ENGINE_CONN),
        ("cookies: ", version::ENGINE_STATE_STORES),
        ("basic-auth: ", version::ENGINE_AUTH_BASIC),
        ("bearer-auth: ", version::ENGINE_AUTH_BEARER),
        ("digest: ", version::ENGINE_AUTH_DIGEST),
        ("negotiate-auth: ", version::ENGINE_GSS),
        ("aws: ", version::ENGINE_AUTH_AWS_SIGV4),
        ("DoH: ", version::ENGINE_DOH),
        ("HTTP-auth: ", version::ENGINE_AUTH_DISPATCH),
        ("Mime: ", version::ENGINE_MIME),
        ("netrc: ", version::ENGINE_NETRC),
        ("parsedate: ", version::ENGINE_PARSEDATE),
        ("proxy: ", version::ENGINE_PROXY),
        ("shuffle-dns: ", version::ENGINE_DNS),
        ("typecheck: ", version::ENGINE_PUBLIC_HEADER),
        ("verbose-strings: ", version::ENGINE_DIAGNOSTIC_STRINGS),
        ("wakeup: ", version::ENGINE_MULTI),
        ("headers-api: ", version::ENGINE_HEADERS),
        ("xattr: ", version::ENGINE_XATTR),
        ("form-api: ", version::ENGINE_FORM),
        ("sha512-256: ", version::ENGINE_SHA512_256),
        ("--libcurl: ", version::ENGINE_LIBCURL_SOURCE),
    ];

    /// The only rows that this build may legitimately report `ON`.
    ///
    /// Two are engine-backed by a module that exists (`verbose-strings` from
    /// `error.rs`, `xattr` from `ffi/sys.rs`) and two are build-intrinsic
    /// machine word widths. Every other row describes a module AAP 0.4.1
    /// mandates and this workspace has not written, or a platform or backend
    /// excluded outright.
    ///
    /// This list is the deliberate-edit point: a checkpoint that lands, say,
    /// `mime/mod.rs` flips `ENGINE_MIME` and adds `"Mime: "` here in the same
    /// change, and until it does the claim is refused by
    /// [`no_row_outside_the_substantiated_ones_is_on`].
    const ROWS_THAT_MAY_BE_ON: [&str; 4] = [
        "verbose-strings: ",
        "xattr: ",
        "large-time: ",
        "large-size: ",
    ];

    #[test]
    fn no_row_outlives_the_engine_that_would_implement_it() {
        // The invariant the whole rewiring exists to hold, and the direction
        // that matters: an absent engine must force its row OFF. Stated as an
        // implication rather than as 22 literals so that the test keeps
        // working -- and keeps being meaningful -- as engines land one by one.
        for (label, engine) in ROW_ENGINES {
            assert!(
                version::ENGINES.contains(&engine),
                "{label:?} names an unregistered engine"
            );

            if !engine.is_present() {
                assert_eq!(
                    value_of(label),
                    Some(false),
                    "{label:?} claims a capability {} cannot provide",
                    engine.owner()
                );
            }
        }
    }

    #[test]
    fn every_engine_gated_row_exists_and_names_a_module() {
        // Guards the transcription itself: a typo in a label above would make
        // `value_of` return `None`, and an engine with no owning module would
        // make the pairing unauditable.
        for (label, engine) in ROW_ENGINES {
            assert!(
                value_of(label).is_some(),
                "{label:?} is not a row of the table"
            );
            assert!(
                engine.owner().ends_with(".rs"),
                "{label:?} must name a Rust source file, got {}",
                engine.owner()
            );
        }

        assert_eq!(
            ROW_ENGINES.len() + 7,
            CAPABILITY_COUNT,
            "22 engine-gated rows plus 7 accounted for individually"
        );
    }

    #[test]
    fn no_row_outside_the_substantiated_ones_is_on() {
        // AAP 0.6.5, enforced rather than documented: over-reporting makes
        // fixtures run and fail, and `tests/runtests.pl:537-546` turns every
        // ON row here into a `<features>` gate. 492 fixtures gate on these
        // labels, so a single wrong ON is worth hundreds of spurious
        // failures.
        for capability in &capabilities() {
            if !ROWS_THAT_MAY_BE_ON.contains(&capability.label) {
                assert!(
                    !capability.enabled,
                    "{:?} is ON with nothing behind it",
                    capability.label
                );
            }
        }
    }

    #[test]
    fn the_substantiated_rows_are_on_and_each_for_its_own_reason() {
        // The other direction: under-reporting is safe but it is not
        // truthful, and a row whose capability really is present must say so.
        assert_eq!(value_of("verbose-strings: "), Some(true));
        assert_eq!(value_of("xattr: "), Some(true));
        assert_eq!(value_of("large-time: "), Some(true));
        assert_eq!(value_of("large-size: "), Some(true));

        for label in ROWS_THAT_MAY_BE_ON {
            assert!(
                value_of(label).is_some(),
                "{label:?} is not a row of the table"
            );
        }
    }

    #[test]
    fn the_labels_the_harness_would_disable_are_the_off_rows() {
        // `tests/runtests.pl:539-543` splits the output in two: `ON` rows
        // become `$feature{<label>}`, `OFF` rows are pushed onto `@disabled`.
        // Reproducing that split here proves the two sets partition the table
        // exactly -- no row can land in both, and none in neither, which is
        // what the closed ON/OFF vocabulary guarantees.
        let table = capabilities();
        let enabled: Vec<&str> = table
            .iter()
            .filter(|capability| capability.enabled)
            .map(|capability| capability.label)
            .collect();
        let disabled: Vec<&str> = table
            .iter()
            .filter(|capability| !capability.enabled)
            .map(|capability| capability.label)
            .collect();

        assert_eq!(
            enabled.len() + disabled.len(),
            CAPABILITY_COUNT,
            "every row is in exactly one of the harness's two sets"
        );
        assert_eq!(
            enabled.len(),
            ROWS_THAT_MAY_BE_ON.len(),
            "only substantiated rows may reach the feature map"
        );

        for label in &enabled {
            assert!(
                !disabled.contains(label),
                "{label:?} cannot be both a feature and disabled"
            );
        }
    }

    // -- Numeric width rows -------------------------------------------------

    #[test]
    fn large_time_and_large_size_are_on_because_the_word_is_wide() {
        // The C tests `SIZEOF_TIME_T < 5` and `SIZEOF_SIZE_T < 5`. Asserting
        // against the measured widths documents WHY the answer is ON rather
        // than hard-coding it: all four mandated targets are 64-bit, so both
        // widths are 8.
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
        // always true here: the mandated targets are Linux and macOS only,
        // and every Windows source is excluded. The rows must still
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

    #[test]
    fn the_three_feature_gated_rows_need_the_feature_and_the_engine() {
        // Written as conjunctions rather than as literals, so the test tracks
        // the registry instead of restating a snapshot of it. Each row is ON
        // only when BOTH preconditions hold, which is the distinction the C
        // never had to draw because its `#if` decided selection and
        // compilation together.
        assert_eq!(
            value_of("cookies: "),
            Some(
                cfg!(feature = "cookies")
                    && version::ENGINE_STATE_STORES.is_present()
            ),
            "row 2 needs the cookies feature and the cookie jar"
        );
        assert_eq!(
            value_of("negotiate-auth: "),
            Some(
                cfg!(feature = "negotiate") && version::ENGINE_GSS.is_present()
            ),
            "row 6 needs the negotiate feature and auth/negotiate.rs"
        );
        assert_eq!(
            value_of("DoH: "),
            Some(cfg!(feature = "doh") && version::ENGINE_DOH.is_present()),
            "row 8 needs the doh feature and dns/doh.rs"
        );
    }

    #[cfg(not(feature = "negotiate"))]
    #[test]
    fn negotiate_auth_is_off_without_the_negotiate_feature() {
        // The feature half of the conjunction, asserted absolutely: with the
        // default-OFF feature absent (AAP 0.8.5 conflict C2), no engine
        // landing can turn the row ON.
        assert_eq!(value_of("negotiate-auth: "), Some(false));
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
        // the compiled feature set and the target, which is both what
        // reproducibility requires and the reason `--help`, `--version`
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
