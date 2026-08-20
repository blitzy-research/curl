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
//! Comments throughout this crate cite `AAP <section>` -- the frozen
//! migration specification that this implementation is measured against.
//! Its section numbers are stable, and a citation marks a decision the
//! specification fixes rather than one this code is free to change.
//!
//! A faithful translation of `src/curlinfo.c`, whose own purpose
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
//! The reporting asymmetry therefore applies here with full force, identically
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
//! `ENGINE_*` constants -- which records, for every module the transformation
//! map assigns
//! a capability, whether this build carries a working implementation of it.
//! That registry is the same one the `--version` banner consults, so the two
//! self-description surfaces cannot disagree, which is the transformation
//! rule that a single Rust module is the sole source of
//! truth". Every value below comes from exactly one of these sources:
//!
//! 1. An `ENGINE_*` entry, on its own or conjoined with a Cargo feature. A
//!    capability claim has two independent preconditions -- was it *selected*
//!    for this build, and does the module that *honours* it exist -- and C
//!    never had to separate them because its `#if` decided both at once.
//!    Twenty-two rows are answered this way.
//! 2. A `curl_rs_lib::version::supports_*` predicate, for the three rows whose
//!    answer also depends on a Cargo feature. The predicate is the whole
//!    conjunction, evaluated INSIDE the engine, and this file evaluates no
//!    `cfg!(feature = "...")` of its own at all -- a rule the
//!    `no_local_feature_tests` module at the end of this file enforces against
//!    this file's own source text. (Named rather than linked: it is a
//!    `#[cfg(test)]` module, so an intra-doc link to it does not resolve when
//!    the documentation is built.)
//!
//!    It is tempting to argue that because `curl-rs/Cargo.toml` declares
//!    fifteen features, forwards each to `curl-rs-lib/<name>`, and holds
//!    `default-features = false` on the path dependency, "the tool's feature
//!    set cannot diverge from the engine's". That is false, and measurably so.
//!    Building `-p curl-rs -p curl-rs-ffi --features curl-rs-ffi/negotiate`
//!    and reading cargo's `--unit-graph` shows `curl_rs_lib` compiled once
//!    with `negotiate` ENABLED while this binary's own unit is compiled with
//!    it DISABLED. Forwarding is one-directional: it makes
//!    `--features curl-rs/negotiate` imply the engine's, but leaves
//!    `--features curl-rs-lib/negotiate` and `--features
//!    curl-rs-ffi/negotiate` free to enable the engine's alone. In such a
//!    build a `cfg!` compiled here reads false while the linked library
//!    plainly has the capability. There is no `tls` feature -- rustls is
//!    unconditional -- so `supports_tls` asks only readiness.
//! 3. A genuine build-intrinsic fact: the width of a machine word (rows 21
//!    and 22), or the absence of a platform or a TLS backend that the target
//!    matrix excludes outright (rows 24, 25, 29). These are properties of
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
//! guess -- see [`use_xattr`], which conjoins the wrapper's engine with
//! [`version::supports_xattr`], the engine predicate that answers which
//! operating systems the wrapper's arm compiles for.

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
// Two rules keep this table honest, and neither may be replaced by a constant
// in this file:
//
// * A row is never forced ON by the argument that no Cargo feature can switch
//   it off. That argument confuses CONFIGURATION with IMPLEMENTATION: the
//   absence of a switch says nothing about whether the module behind the switch
//   can execute, and every row so forced over-advertises its fixtures into
//   running against nothing.
// * No row is "not determinable" from here. Every one of them reads a public
//   predicate of `curl-rs-lib`: `bindlocal` reads `ENGINE_CONN`, `shuffle-dns`
//   reads `ENGINE_DNS`, `wakeup` reads `ENGINE_MULTI` and `sha512-256` reads
//   `ENGINE_SHA512_256`. An OFF row therefore always names the engine that
//   earned it, rather than recording that this file could not see far enough to
//   tell.

/// A capability this build definitively does not provide, for reasons no
/// engine can change.
///
/// Used by exactly three rows, and only where the answer is *known* rather
/// than merely unwritten: the two `win32-*` rows, which need a platform
/// the target matrix excludes, and `cert-status`,
/// which needs a TLS backend excluded from every
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
/// wrapper disappears from under `curl-rs/src/output/xattr.rs`.
/// [`version::supports_xattr`] says this is one of the two operating systems
/// whose arm the wrapper compiles; every other platform is out of
/// scope, so a build for one would correctly report `OFF` rather than
/// advertise a syscall it cannot issue.
///
/// The second conjunct is *asked of the engine* rather than spelled here, and
/// that is the whole point of the line. [`version::supports_xattr`] documents
/// itself as "the authority for the `xattr:` row" and gives the reason in its
/// own words -- "delegating rather than repeating the `cfg!` here is the
/// point: the predicate and the syscall can never disagree, because there is
/// one expression". Repeating that
/// `cfg!(any(target_os = "linux", target_os = "macos"))` inline here would
/// break the claim twice over: it would create a second expression free to
/// drift from the syscall it describes, and it would leave the declared
/// authority with no consumer, so nothing would catch the drift. The
/// predicate is
/// no longer `const` because the engine's is not, which costs nothing:
/// [`capabilities`] is an ordinary `fn` and no const context calls this.
fn use_xattr() -> bool {
    version::ENGINE_XATTR.is_present() && version::supports_xattr()
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
///
/// The first conjunct is asked of the ENGINE rather than of this crate's own
/// feature set, for the reason set out at the top of this file: the two can
/// differ, and only the engine's answer describes the library that is
/// actually linked.
fn override_dns() -> bool {
    let alternative_resolver = CURLRES_ARES || USE_FAKE_GETADDRINFO;

    version::supports_memdebug() && alternative_resolver
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
        // `--local-port` and `CURLOPT_INTERFACE`. The owners are
        // `curl-rs-lib/src/conn/socket.rs` and, for `lib/if2ip.c`,
        // `curl-rs-lib/src/dns/if2ip.rs`, and the row claims a socket can be
        // bound. No fixture gates on the label.
        Capability::new("bindlocal: ", version::ENGINE_CONN.is_present()),
        // 2. C `:55-60`: `#ifdef CURL_DISABLE_COOKIES` -> OFF.
        //
        // Both preconditions, and the second is what changed: the `cookies`
        // Cargo feature is default ON (`curl-rs/Cargo.toml` `default` list)
        // and forwards to `curl-rs-lib/cookies`, but the row claims a working
        // jar rather than a selected feature, so the engine decides it. 51
        // fixtures gate on the label.
        //
        // Both halves are asked by `supports_cookies` INSIDE the engine, not
        // restated here: see this file's header note on why a `cfg!` compiled
        // into this crate is the wrong question.
        Capability::new("cookies: ", version::supports_cookies()),
        // 3. C `:63-68`: `#ifdef CURL_DISABLE_BASIC_AUTH` -> OFF.
        //
        // Backed by `curl-rs-lib/src/auth/basic.rs`, from
        // `lib/vauth/cleartext.c`; the row claims an `Authorization: Basic`
        // header can be composed. That no Cargo feature switches it off is
        // beside the point: the C macro's absence means "not disabled", not
        // "implemented".
        Capability::new(
            "basic-auth: ",
            version::ENGINE_AUTH_BASIC.is_present(),
        ),
        // 4. C `:70-75`: `#ifdef CURL_DISABLE_BEARER_AUTH` -> OFF.
        //
        // Backed by `curl-rs-lib/src/auth/bearer.rs`, from
        // `lib/vauth/oauth2.c`; the row claims `--oauth2-bearer` has something
        // to serve it.
        Capability::new(
            "bearer-auth: ",
            version::ENGINE_AUTH_BEARER.is_present(),
        ),
        // 5. C `:77-82`: `#ifdef CURL_DISABLE_DIGEST_AUTH` -> OFF.
        //
        // Backed by `curl-rs-lib/src/auth/digest.rs`, from
        // `lib/vauth/digest.c` and `lib/http_digest.c`, with message
        // construction byte-exact, which is what the row claims. 76 fixtures
        // gate on the label, the second-largest withholding in the table.
        Capability::new("digest: ", version::ENGINE_AUTH_DIGEST.is_present()),
        // 6. C `:84-89`: `#ifdef CURL_DISABLE_NEGOTIATE_AUTH` -> OFF.
        //
        // A Cargo feature, default OFF. Negotiate stays behind a non-default
        // `negotiate` feature so that the
        // default build links no C security library at all, which is what
        // reconciles "no C TLS linkage at any configuration" with
        // "Negotiate where OS Kerberos is available". The engine conjunct is
        // the same one the `SPNEGO` banner token uses: the binding in
        // `curl-rs-lib/src/ffi/gss.rs` is not enough on its own, because
        // `auth/negotiate.rs` is what drives it through an HTTP exchange.
        //
        // THREE conjuncts, via `negotiate_usable()`, not the two of
        // `supports_negotiate()`. The third is the runtime probe: the GSS-API
        // library resolves at load time, so a host can satisfy both
        // compile-time factors and still have nothing usable. C needs no such
        // test -- its row is a bare `#ifdef`, the library being found at build
        // time -- but `tests/runtests.pl:537-546` folds every ON row of this
        // diagnostic into the same `%feature` map the banner feeds, and the
        // banner already consults the probe through `Feature::is_present`.
        // Reading only the compile-time half here would let one capability be
        // described by two surfaces that disagree, with this one over-reporting.
        Capability::new("negotiate-auth: ", version::negotiate_usable()),
        // 7. C `:91-96`: `#ifdef CURL_DISABLE_AWS` -> OFF.
        //
        // Backed by `curl-rs-lib/src/auth/aws_sigv4.rs`, from
        // `lib/http_aws_sigv4.c`; the row claims `--aws-sigv4` can sign, which
        // linking `sha2` and `hmac` does not by itself earn. 22 fixtures gate
        // on the label.
        Capability::new("aws: ", version::ENGINE_AUTH_AWS_SIGV4.is_present()),
        // 8. C `:98-103`: `#ifdef CURL_DISABLE_DOH` -> OFF.
        //
        // A Cargo feature, default ON, forwarding to `curl-rs-lib/doh`
        // (`curl-rs-lib/src/dns/doh.rs`, from `lib/doh.c`).
        // Three layers have to run together: the codec, the resolver it is
        // driven from, and the TLS the query travels over. 5 fixtures gate on
        // the label.
        Capability::new("DoH: ", version::supports_doh()),
        // 9. C `:105-110`: `#ifdef CURL_DISABLE_HTTP_AUTH` -> OFF.
        //
        // The HTTP authentication dispatcher,
        // `curl-rs-lib/src/auth/mod.rs`, from `lib/vauth/vauth.c`. Not a
        // Cargo feature; the individual mechanisms above are what vary in a
        // C build. The row claims there is something to select between.
        Capability::new(
            "HTTP-auth: ",
            version::ENGINE_AUTH_DISPATCH.is_present(),
        ),
        // 10. C `:112-117`: `#ifdef CURL_DISABLE_MIME` -> OFF.
        //
        // AAP 0.4.1: `curl-rs-lib/src/mime/mod.rs` from `lib/mime.c`,
        // backing the 12 exported `curl_mime_*` symbols. **ON**: the module
        // and all twelve entry points have landed, and the engine registry
        // records the evidence beside `ENGINE_MIME` rather than here, so this
        // row cannot disagree with the banner.
        //
        // Reading reachability off the `pub mod mime;` line was the mistake
        // this row used to make, and the correction is NOT that the earlier
        // caution was wrong -- it is that the caution is now satisfied. The
        // row stayed OFF for exactly as long as the declaration had nothing
        // behind it. 48 fixtures gate on the label and now run.
        Capability::new("Mime: ", version::ENGINE_MIME.is_present()),
        // 11. C `:120-125`: `#ifdef CURL_DISABLE_NETRC` -> OFF.
        //
        // Backed by `curl-rs-lib/src/cookies/netrc.rs`, from `lib/netrc.c`,
        // the file parser `--netrc`, `--netrc-file` and `--netrc-optional`
        // need. Gated on its own engine rather than on the
        // cookie jar's, even though the two files are siblings, so that
        // landing one cannot silently advertise the other.
        Capability::new("netrc: ", version::ENGINE_NETRC.is_present()),
        // 12. C `:127-132`: `#ifdef CURL_DISABLE_PARSEDATE` -> OFF.
        //
        // Backed by `curl-rs-lib/src/util/parsedate.rs`, from
        // `lib/parsedate.c`: the parser behind `curl_getdate`, one of the 100
        // exported symbols, and what lets `--time-cond` interpret its
        // argument. Being part of the ABI makes the row mandatory, not true --
        // the engine decides whether it is on.
        Capability::new("parsedate: ", version::ENGINE_PARSEDATE.is_present()),
        // 13. C `:134-139`: `#ifdef CURL_DISABLE_PROXY` -> OFF.
        //
        // The owner is the whole `curl-rs-lib/src/proxy/` tree, and the row
        // claims all of it. This is the costliest row in the table: 225
        // fixtures gate on the `proxy` label. One gates on `!proxy` and
        // becomes eligible -- `tests/data/test375`, which requires `-x` to
        // fail with `curl: proxy support is disabled in this libcurl` and
        // `<errorcode> 4`. That is the right pairing rather than a
        // regression: reporting OFF is what makes that obligation visible.
        Capability::new("proxy: ", version::ENGINE_PROXY.is_present()),
        // 14. C `:141-146`: `#ifdef CURL_DISABLE_SHUFFLE_DNS` -> OFF.
        //
        // Randomising the order of resolved addresses, the capability behind
        // `CURLOPT_DNS_SHUFFLE_ADDRESSES`. A property of the resolver, so it
        // reads the resolver's engine rather than carrying a switch of its
        // own. 1 fixture gates on the label.
        Capability::new("shuffle-dns: ", version::ENGINE_DNS.is_present()),
        // 15. C `:148-153`: `#ifdef CURL_DISABLE_TYPECHECK` -> OFF.
        //
        // Compile-time type checking of `curl_easy_setopt`'s variadic
        // argument. `include/curl/typecheck-gcc.h` cannot be expressed by
        // cbindgen, so it is carried as a hand-maintained header shipped
        // verbatim beside the generated one.
        //
        // That header exists; the generated one beside it is what does not. The
        // macros take effect only when a C consumer includes `curl/curl.h`,
        // which `curl-rs-ffi/build.rs` must produce with cbindgen -- and
        // generation is refused while any export named by `lib/libcurl.def` is
        // undefined, `curl_easy_setopt` among them. A facility with nothing to
        // check is not present, and what clears the row is completing the
        // export surface rather than writing another source file.
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
        // `multihandle.h`; here it asks the engine, through the predicate the
        // multi module owns.
        //
        // OFF, from two conjuncts that disagree -- which is why the row must
        // read `supports_multi_wakeup()` and not either half. The socketpair
        // MECHANISM is available (`multi::wakeup_available()` is `cfg!(unix)`,
        // true on all four targets), but `curl_multi_wakeup` is one of the 76
        // exports still undefined. Reading the mechanism alone would print `ON`
        // and make the 2 fixtures gating on the label RUN and FAIL rather than
        // skip -- the over-report that is forbidden.
        //
        // Reading `ENGINE_MULTI.is_present()` directly would give the same
        // answer today, because that engine is absent for a different and true
        // reason -- no handle, no poll. `multi/mod.rs` is 142 lines and owns
        // the predicate, so reading the engine here instead would leave the
        // mechanism conjunct out of the row entirely.
        // `CURLMcode::WakeupFailure` (`error.rs:784-785`) remains no evidence
        // either way -- it is precisely the value returned when wakeup is
        // unavailable.
        Capability::new("wakeup: ", version::supports_multi_wakeup()),
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
        // whose removal is forbidden. Gated separately from `Mime`
        // because C guards the two separately and either can be disabled
        // alone. 9 fixtures gate on the label.
        Capability::new("form-api: ", version::ENGINE_FORM.is_present()),
        // 21. C `:190-195`: `#if (SIZEOF_TIME_T < 5)` -> OFF. NUMERIC.
        Capability::new("large-time: ", large_time()),
        // 22. C `:197-202`: `#if (SIZEOF_SIZE_T < 5)` -> OFF. NUMERIC.
        Capability::new("large-size: ", large_size()),
        // 23. C `:204-209`: `#ifndef CURL_HAVE_SHA512_256` -> OFF. INVERTED.
        //
        // SHA-512/256, which HTTP Digest consults for `SHA-512-256`
        // challenges.
        //
        // C prints `ON` from `#ifndef CURL_HAVE_SHA512_256`, and that macro is
        // defined at `lib/curl_sha512_256.h:28-32` under TWO conditions:
        // `!defined(CURL_DISABLE_DIGEST_AUTH) && !defined(CURL_DISABLE_SHA512_256)`.
        // So the row is not a question about the hash alone, and
        // `version::has_sha512_256()` -- named after the macro -- carries both
        // halves. The hash half is present: `crypto/mod.rs:396` declares
        // `crypto/sha512_256.rs`, a complete implementation on the `sha2
        // 0.10.9` pin. The digest half is not, so the row reads
        // OFF and 5 fixtures gate on the label and skip.
        //
        // Reading `ENGINE_SHA512_256.is_present()` alone would give the same
        // answer for the wrong reason: the hash primitive is present, and what
        // is missing is `auth/digest.rs`. A wrong reason here is worse than
        // usual, because the fix it implies -- write the hash -- is already
        // done, so acting on it would flip the row ON while this build still
        // cannot answer a challenge.
        Capability::new("sha512-256: ", version::has_sha512_256()),
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
        // reproducing the current invocation. Its owner is
        // `curl-rs/src/libcurl_src.rs` (from `src/tool_easysrc.c`), whose output
        // must remain valid C against the generated header. Not a Cargo
        // feature, and not
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
        // (:205). A naive `#ifdef` to `OFF` transliteration would render these
        // ON. They are OFF here for a stated, checkable reason, so each
        // assertion tracks the authority that decides it rather than a literal,
        // and each will start demanding ON the moment its reason is removed.
        //
        // The two authorities are deliberately of different shapes, because the
        // two C conditions are. `ENABLE_WAKEUP` is one switch, so the row is one
        // engine. `CURL_HAVE_SHA512_256` is a conjunction of two
        // (`lib/curl_sha512_256.h:28`), so the row is
        // `version::has_sha512_256()` -- which is why this assertion does NOT
        // read `ENGINE_SHA512_256.is_present()`. It used to, together with a
        // comment saying `crypto/sha512_256.rs` was absent; the file is in fact
        // a complete implementation, and reading that engine alone now reports
        // `true` while the row is correctly `OFF` because the digest that would
        // consume the hash is what is missing.
        assert_eq!(
            value_of("wakeup: "),
            Some(version::supports_multi_wakeup()),
            "row 17 tracks the multi handle's wakeup support"
        );
        assert_eq!(
            value_of("sha512-256: "),
            Some(version::has_sha512_256()),
            "row 23 tracks C's two-part CURL_HAVE_SHA512_256 condition"
        );
    }

    #[test]
    fn the_xattr_row_follows_the_engine_wrapper() {
        // `#ifndef USE_XATTR` (:177), also inverted -- and derived from two
        // conjuncts, so both are asserted. On every target in the supported
        // matrix the engine's `fsetxattr` wrapper exists AND the
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
    ///
    /// Two rows read a CONJUNCTION of which the engine named here is one
    /// conjunct: `sha512-256` reads `version::has_sha512_256()` and `wakeup`
    /// reads `version::supports_multi_wakeup()`, each pairing its engine with a
    /// second precondition C also requires. That is why the test below asserts
    /// an implication -- absent engine forces the row OFF -- rather than
    /// equality. A conjunction can only be MORE restrictive than the engine
    /// alone, so the direction that matters is preserved, while equality would
    /// forbid the second conjunct from ever mattering.
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
    /// Four are engine-backed by a module that exists (`verbose-strings` from
    /// `error.rs`, `xattr` from `ffi/sys.rs`, `parsedate` from
    /// `util/parsedate.rs`, `Mime` from `mime/mod.rs`) and two are
    /// build-intrinsic machine word widths. Every other row describes a module
    /// AAP 0.4.1 mandates and this workspace has not written, or a platform or
    /// backend excluded outright.
    ///
    /// This list is the deliberate-edit point: a checkpoint that lands a module
    /// flips its engine and adds its row here in the same change, and until it
    /// does the claim is refused by
    /// [`no_row_outside_the_substantiated_ones_is_on`].
    ///
    /// `parsedate` was the first row admitted by that process rather than by the
    /// original transcription, and it is worth recording why it took a
    /// correction to notice: the registry had marked its engine absent with the
    /// reason "the file does not exist", while `util/parsedate.rs` was a
    /// 1,430-line parser with 22 tests backing the exported `curl_getdate`.
    /// `Mime` is the second, and it went stale the same way -- the registry
    /// still read "the file does not exist" while `mime/mod.rs` carried the
    /// part tree, the boundary generation, the encoders and the reader, with all
    /// twelve `curl_mime_*` symbols exported on top of it. Two instances of one
    /// failure mode is a pattern, so the direction it hides in is worth naming:
    /// the gate above enforces the FATAL direction -- no unsubstantiated ON --
    /// and by construction cannot detect an ON that is merely missing, which is
    /// what [`the_substantiated_rows_are_on_and_each_for_its_own_reason`] is
    /// for and why that test names a distinct reason per row rather than
    /// looping.
    const ROWS_THAT_MAY_BE_ON: [&str; 6] = [
        "verbose-strings: ",
        "xattr: ",
        "parsedate: ",
        "Mime: ",
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
        // Enforced rather than documented: over-reporting makes
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
        // This is the assertion that a silently-withheld capability trips, and
        // two rows are here because they were silently withheld: `parsedate`,
        // whose engine claimed the parser did not exist while `curl_getdate`
        // was already exported and backed by it, and `Mime`, whose engine said
        // the same of `mime/mod.rs` while all twelve `curl_mime_*` symbols were
        // exported on top of it.
        assert_eq!(value_of("verbose-strings: "), Some(true));
        assert_eq!(value_of("xattr: "), Some(true));
        assert_eq!(value_of("parsedate: "), Some(true));
        assert_eq!(value_of("Mime: "), Some(true));
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
    fn the_three_feature_gated_rows_come_from_the_engine_predicates() {
        // Each row is ON only when BOTH preconditions hold -- the feature was
        // selected AND the module that honours it exists -- which is the
        // distinction the C never had to draw, because its `#if` decided
        // selection and compilation together.
        //
        // The conjunction is NOT restated here. Spelling it as
        // `cfg!(feature = "cookies") && ENGINE_STATE_STORES.is_present()`
        // would reintroduce in the test exactly the defect the production rows
        // are shaped to avoid: the `cfg!` reads THIS crate's forwarded feature
        // copy, which a measured `--unit-graph` shows can differ from the
        // engine's. The row and the test would then disagree for a reason
        // neither is wrong about.
        assert_eq!(
            value_of("cookies: "),
            Some(version::supports_cookies()),
            "row 2 must be the engine's cookie verdict, not a local cfg!"
        );
        // Three conjuncts, not two: `negotiate_usable()` adds the runtime GSS
        // probe that no `cfg!` can see. Asserting `supports_negotiate()` here
        // would permit the row to over-report on a host whose mechanism glue is
        // unusable, which is the direction `tests/runtests.pl` punishes.
        assert_eq!(
            value_of("negotiate-auth: "),
            Some(version::negotiate_usable()),
            "row 6 must be the engine's negotiate verdict, runtime probe included"
        );
        assert_eq!(
            value_of("DoH: "),
            Some(version::supports_doh()),
            "row 8 must be the engine's DoH verdict"
        );
    }

    /// The direction that is fatal, pinned separately.
    ///
    /// The test above states where each row's value comes from; this one states
    /// what the value may never be. Over-reporting a capability turns a clean
    /// skip into a hard failure, so a row whose implementation is withheld must
    /// be OFF no matter which Cargo features are selected. Checked against the
    /// registry directly, so it holds even if a predicate is rewritten.
    #[test]
    fn a_withheld_implementation_forces_its_row_off() {
        for (label, engine) in [
            ("cookies: ", version::ENGINE_STATE_STORES),
            ("negotiate-auth: ", version::ENGINE_GSS),
            ("DoH: ", version::ENGINE_DOH),
        ] {
            if !engine.is_present() {
                assert_eq!(
                    value_of(label),
                    Some(false),
                    "{label}claims a capability whose implementation \
                     ({}) does not exist; over-reporting makes a fixture \
                     fail where under-reporting only makes it skip",
                    engine.owner()
                );
            }
        }
    }

    // NO TEST HERE MAY BE GATED ON THIS CRATE'S OWN FEATURE SET, in any form:
    // not `cfg!(feature = "x")`, not `#[cfg(feature = "x")]`, and not
    // `#[cfg(not(feature = "x"))]`. A build may enable a forwarded feature on
    // the engine alone (`--features curl-rs-lib/cookies`), and such a test then
    // compiles -- because this crate's copy is absent -- while the row it
    // examines is driven by an engine that does have the capability, so it fails
    // for a reason the implementation was not wrong about. The negated attribute
    // form is the one that reads least like a capability decision, which is why
    // the gate below forbids `feature = "` in code in every form rather than
    // just `cfg!`.
    //
    // The feature half's necessity belongs to the engine and is asserted there
    // over all three rows at once (`curl_rs_lib::version`'s
    // `feature_gated_names_need_their_cargo_feature_and_their_engine`). What is
    // this file's business -- that each row equals its engine predicate, and
    // that a withheld implementation forces the row OFF -- is asserted by the
    // two tests immediately above, in every configuration.

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

/// A structural gate forbidding `cfg!(feature = ...)` anywhere in this file.
///
/// Every capability question this tool answers is a question about the LIBRARY
/// it links, and `cfg!` compiled into this crate cannot answer it. That is not
/// a stylistic preference; it was measured. Building
/// `-p curl-rs -p curl-rs-ffi --features curl-rs-ffi/negotiate` and reading
/// cargo's own `--unit-graph` shows `curl_rs_lib` compiled ONCE with
/// `negotiate` enabled while this binary's unit is compiled with it disabled --
/// one build, two different answers to `cfg!(feature = "negotiate")`, and only
/// the engine's is about the code that will run. Feature forwarding does not
/// prevent this: it makes `--features curl-rs/negotiate` imply the engine's,
/// but leaves `--features curl-rs-lib/negotiate` and
/// `--features curl-rs-ffi/negotiate` free to enable the engine's alone.
///
/// The behavioural tests above cannot catch a regression here, because in a
/// non-divergent build a local `cfg!` and the engine's predicate agree -- which
/// is precisely why the defect survived review. So the property is asserted
/// against the source text, the way `curl-rs/src/main.rs`'s
/// `mandatory_warning_gate` and `curl-rs-ffi/src/lib.rs`'s unsafe-boundary gate
/// already do, with comments and string literals stripped so that the prose in
/// this comment itself -- which spells the forbidden token repeatedly -- cannot
/// trip it.
#[cfg(test)]
mod no_local_feature_tests {
    /// This file's own text; `include_str!` resolves relative to this file.
    const SOURCE: &str = include_str!("curlinfo.rs");

    /// The construct that must not appear in code.
    ///
    /// Deliberately the feature TEST rather than the `cfg!` macro, so that one
    /// rule covers every spelling: `cfg!(feature = "x")`,
    /// `#[cfg(feature = "x")]`, `#[cfg(not(feature = "x"))]` and
    /// `#[cfg(all(feature = "x", ...))]` are the same cross-crate mistake, and
    /// the attribute forms are the easier ones to miss because they do not read
    /// like a capability decision at all. Three `#[cfg(not(feature = ...))]`
    /// test gates were removed from this crate for exactly that reason.
    ///
    /// The trailing quote is deliberately NOT part of the token. [`code_only`]
    /// replaces each string literal with a space, so by the time a line reaches
    /// the comparison, `cfg!(feature = "x")` reads `cfg!(feature =  )` and the
    /// quote is already gone -- a token spelled with it would match nothing and
    /// the gate would pass vacuously forever. `feature =` is sound here because
    /// neither guarded file contains any other use of it in code, which
    /// [`the_gate_is_not_vacuous`] keeps honest from the other direction.
    const FORBIDDEN: &str = "feature =";

    /// `line` with its trailing `//` comment and every string literal removed.
    ///
    /// Literals collapse to a space so that stripping cannot fuse two adjacent
    /// tokens into one. [`the_gate_sees_no_raw_strings`] rules out the one case
    /// this cannot handle rather than assuming it away.
    fn code_only(line: &str) -> String {
        let without_comment = line.split("//").next().unwrap_or("");
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
                out.push(' ');
                continue;
            }
            out.push(ch);
        }

        out
    }

    /// Whether `text` opens a raw string literal in CODE.
    ///
    /// Two naive spellings of this were tried and both were wrong, each caught
    /// by this file's own contents rather than by inspection:
    ///
    /// * `text.contains("r\"")` matches a plain literal that merely ENDS in the
    ///   letter `r`, which this file does at three places (`header"`, `stderr"`,
    ///   `for"`).
    /// * Adding a token-boundary rule fixes those but still matches the same
    ///   letter at the end of a longer literal (`"...ending in r"`) and the
    ///   token `r"` written inside a doc comment -- both of which this file also
    ///   contains, in the lines just above.
    ///
    /// The distinction cannot be made without knowing whether the position is
    /// inside a comment or a literal already, so this tracks both. A raw string
    /// is reported only for an `r` that begins a token, in code, immediately
    /// followed by `"` or `#"`.
    fn opens_raw_string(text: &str) -> bool {
        for line in text.lines() {
            let bytes = line.as_bytes();
            let mut index = 0;
            let mut in_string = false;

            while index < bytes.len() {
                let byte = bytes[index];

                if in_string {
                    match byte {
                        b'\\' => index += 1,
                        b'"' => in_string = false,
                        _ => {}
                    }
                    index += 1;
                    continue;
                }
                // A `//` outside a literal begins a comment: nothing after it
                // on this line is code, and `code_only` discards it too.
                if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
                    break;
                }
                if byte == b'"' {
                    in_string = true;
                    index += 1;
                    continue;
                }
                if byte == b'r' {
                    let starts_token = index == 0
                        || !(bytes[index - 1].is_ascii_alphanumeric()
                            || bytes[index - 1] == b'_');
                    let hashed = bytes.get(index + 1) == Some(&b'#')
                        && bytes.get(index + 2) == Some(&b'"');

                    if starts_token
                        && (bytes.get(index + 1) == Some(&b'"') || hashed)
                    {
                        return true;
                    }
                }
                index += 1;
            }
        }

        false
    }

    /// A `//` inside a raw string literal would truncate a line early and let
    /// the gate miss code after it. This file contains no raw string literal,
    /// and this test keeps that true rather than trusting it.
    #[test]
    fn the_gate_sees_no_raw_strings() {
        assert!(
            !opens_raw_string(SOURCE),
            "a raw string literal would blind `code_only`; if one is added, \
             teach the stripper about it rather than deleting this test"
        );
    }

    /// The raw-string detector must distinguish a prefix from three things that
    /// merely look like one, or the test above would fire forever -- as two
    /// earlier versions of it did -- or never fire at all.
    #[test]
    fn the_raw_string_detector_reads_token_boundaries() {
        assert!(opens_raw_string("let s = r\"x\";"), "a real prefix");
        assert!(opens_raw_string("let s = r#\"x\"#;"), "a hashed prefix");
        assert!(
            !opens_raw_string("\"header\".len()"),
            "a short literal ending in the letter r"
        );
        assert!(
            !opens_raw_string("panic!(\"a literal ending in r\");"),
            "a long literal ending in the letter r"
        );
        assert!(
            !opens_raw_string("// the token r\" written in prose"),
            "a comment mentioning the construct"
        );
        assert!(!opens_raw_string("let var = 1;"), "no literal at all");
    }

    /// The gate itself.
    #[test]
    fn no_capability_is_decided_by_this_crates_own_features() {
        let offenders: Vec<usize> = SOURCE
            .lines()
            .enumerate()
            .filter(|(_, line)| code_only(line).contains(FORBIDDEN))
            .map(|(index, _)| index + 1)
            .collect();

        assert!(
            offenders.is_empty(),
            "curlinfo.rs decides a capability from its OWN feature set at \
             line(s) {offenders:?}. Ask `curl_rs_lib::version` instead: a \
             forwarded feature can be enabled on the engine alone, and then \
             this crate's copy reads false while the linked library plainly \
             has the capability."
        );
    }

    /// The gate must be able to fail. A stripper that returned nothing, or a
    /// token that never matches anything, would make the test above pass
    /// vacuously forever.
    #[test]
    fn the_gate_is_not_vacuous() {
        assert!(
            code_only("        cfg!(feature = \"negotiate\")")
                .contains(FORBIDDEN),
            "the macro form must be caught"
        );
        assert!(
            code_only("    #[cfg(feature = \"negotiate\")]")
                .contains(FORBIDDEN),
            "the plain attribute form must be caught"
        );
        assert!(
            code_only("    #[cfg(not(feature = \"negotiate\"))]")
                .contains(FORBIDDEN),
            "the negated attribute form must be caught -- this is the one \
             that was actually present and actually missed"
        );
        assert!(
            !code_only("        // cfg!(feature = \"negotiate\") in prose")
                .contains(FORBIDDEN),
            "a comment must not trip the gate"
        );
        assert!(
            !code_only("        let s = \"cfg!(feature = x\";")
                .contains(FORBIDDEN),
            "a string literal must not trip the gate"
        );
    }
}

/// The engine registry's source-presence claim, checked against the tree.
///
/// `curl_rs_lib::version::Engine` records two independent facts: whether the
/// module AAP 0.4.1 assigns the work exists in this checkout, and whether the
/// build can execute that work end to end. Only the second gates a capability,
/// and it is checked from inside that crate. The first cannot be: it is a
/// statement about the filesystem, and `curl-rs-lib` must stay runnable under
/// the `cargo miri test -p curl-rs-lib` gate of AAP 0.8.4, whose isolation
/// blocks a directory read.
///
/// So the check lives here, in the registry's largest consumer. It is worth
/// making at all because the fact it verifies is the one that went wrong: for
/// most of this checkpoint's life the registry recorded a single `absent`
/// boolean, and its prose came to assert that twenty files which are on disk
/// were unwritten -- each of which read as an instruction to write something
/// already written. An unchecked claim about the tree drifts from the tree.
#[cfg(test)]
mod source_presence_gate {
    use curl_rs_lib::version::{Engine, ENGINES};
    use std::path::{Path, PathBuf};

    /// The workspace root.
    ///
    /// `CARGO_MANIFEST_DIR` is `<root>/curl-rs`, so one `parent()` reaches it.
    /// Engine owners are workspace-relative, which
    /// `no_two_engines_claim_the_same_owning_module` already asserts.
    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("CARGO_MANIFEST_DIR always has a parent")
            .to_path_buf()
    }

    #[test]
    fn every_engine_records_its_source_presence_correctly() {
        let root = repo_root();

        for engine in ENGINES {
            let path = root.join(engine.owner());
            assert_eq!(
                engine.is_written(),
                path.is_file(),
                "{} claims is_written() == {} but the file {} on disk",
                engine.owner(),
                engine.is_written(),
                if path.is_file() { "IS" } else { "is NOT" }
            );
        }
    }

    #[test]
    fn the_gate_covers_both_answers() {
        // A gate that only ever saw one answer would pass vacuously: if every
        // row were written, a broken `is_written()` that returned `true`
        // unconditionally would still pass. Both answers must be present in the
        // registry for the comparison above to be able to fail either way.
        let written = ENGINES.iter().filter(|e| e.is_written()).count();
        let unwritten = ENGINES.len() - written;

        assert!(written > 0, "no row exercises the written arm");
        assert!(unwritten > 0, "no row exercises the unwritten arm");
    }

    #[test]
    fn no_engine_claims_to_execute_work_it_has_no_source_for() {
        // The same implication `curl-rs-lib` asserts internally, re-checked here
        // against the filesystem rather than against the field -- so a row that
        // claimed both `present` and a written source while the file was absent
        // fails here even if the internal invariant were relaxed.
        let root = repo_root();

        for engine in ENGINES.iter().filter(|e| e.is_present()) {
            assert!(
                root.join(engine.owner()).is_file(),
                "{} reports a working implementation but its source is absent",
                engine.owner()
            );
        }

        // And the accessor pair really is an implication, not two unrelated
        // booleans.
        assert!(ENGINES
            .iter()
            .all(|e| !e.is_present() || Engine::is_written(e)));
    }
}

/// The module targets the target design assigns that no file implements yet,
/// enumerated once for the whole workspace and checked against the disk.
///
/// The engine registry above covers `curl-rs-lib` only, and it covers it by
/// capability: one owning module per capability, so a capability whose owner
/// exists reports `is_written()` even when siblings the design also assigns are
/// missing. That is the right granularity for a version banner and the wrong
/// granularity for answering "what is left". This gate answers that, across all
/// three crates, at file granularity.
///
/// It exists in this binary for the same reason the registry gate does: reading
/// a directory needs filesystem access, `curl-rs-lib` must stay runnable under
/// Miri, and Miri's isolation refuses the read. `curlinfo` is a diagnostic
/// binary that nothing links against, so the check costs nothing it owns.
///
/// **The list is deliberately expected to be WRONG eventually, and to say so.**
/// Each of these files is a separate planned unit of work, authored elsewhere;
/// when one lands, `every_named_target_is_still_absent` fails and names it. That
/// failure is the notification, and the fix is to delete the row -- not to
/// weaken the assertion.
#[cfg(test)]
mod absent_target_gate {
    use std::path::{Path, PathBuf};

    /// The 3 `curl-rs-lib` targets with no file.
    ///
    /// The same three `curl-rs-lib/src/lib.rs` enumerates in prose; here
    /// so that the prose cannot outlive the fact. All three are easy-handle
    /// modules. **No per-scheme protocol EXECUTOR is absent any more**, which
    /// is the change `protocols/http3.rs` made, and **no proxy mechanism is
    /// absent either**, which is the change `proxy/http_connect.rs` made: the
    /// `protocols/` and `proxy/` directories are now both complete on disk,
    /// and everything still missing from a transfer is an easy handle to
    /// originate it.
    ///
    /// `protocols/file.rs` was the twelfth and has LANDED -- the FIRST
    /// per-scheme executor to do so, and the sparsest, filling 5 of `struct
    /// Curl_protocol`'s 17 slots (`lib/file.c:601-619`). Its row is gone from
    /// this gate, which is the gate working as designed. Note what its landing
    /// does NOT change: `curl-rs-lib/src/version.rs`'s `ENGINE_PROTOCOLS` stays
    /// inert and the `Protocols:` banner still withholds `file`, because
    /// `protocols/mod.rs`'s `SCHEMES` is a `const` table and cannot hold a
    /// handler that owns per-transfer state, and because
    /// `crate::transfer::TransferIo::xfer_ctx` borrows its owner mutably and so
    /// cannot hand `do_it` the transfer-side seam as well. That module's own
    /// documentation carries both, and until they change the executor exists
    /// without being reachable -- a wiring gap in delivered files, which this
    /// gate is the wrong instrument for.
    ///
    /// `protocols/http1.rs` was the eleventh and has LANDED too. It carries the
    /// request writer of `lib/http.c` -- the 20-slot default header order, the
    /// three `Host:` forms, the request target and the shared 8-of-17 vtable
    /// that `Curl_scheme_http` and `Curl_scheme_https` both point at -- and it
    /// exports the two assembled registry rows for this table's own registry to
    /// adopt. What is still outstanding for HTTP is WIRING and not writing: no
    /// easy handle exists to build a request specification from, so
    /// `protocols/mod.rs` keeps `run: None` on both rows and
    /// `curl-rs-lib/src/version.rs`'s `ENGINE_PROTOCOLS` stays inert. Landing a
    /// file and reaching it are separate obligations, and only the second is
    /// still open here -- the same distinction `file.rs` above is held by.
    ///
    /// `protocols/http2.rs` has now LANDED as well. It carries the HTTP/2
    /// connection filter, exact SETTINGS and h2c upgrade bytes, HPACK-backed
    /// request/response processing, flow control and push-header contract. It
    /// does not make HTTP reachable by itself: the easy-handle modules that
    /// construct requests remain absent, so this is another delivered executor
    /// whose remaining gap is wiring rather than source.
    ///
    /// `protocols/http3.rs` has now LANDED as the LAST of them, and with it the
    /// `protocols/` directory holds every file the target design assigns. It
    /// carries the HTTP/3 connection filter of `lib/vquic/curl_ngtcp2.c` --
    /// `Curl_cft_http3`'s four type flags, all fifteen typed queries, the
    /// `quinn` transport parameters `quic_settings` sets, the handshake
    /// deadline, qlog, and the QUIC row of `conn/happy_eyeballs.rs`'s transport
    /// registry -- with `quinn` + `h3` + `h3-quinn` in place of ngtcp2 and
    /// nghttp3. Its gap is the same wiring gap the other executors have:
    /// `curl-rs-lib/src/version.rs` still withholds the `HTTP3` feature and the
    /// `h3` protocol token, deliberately, because under-reporting a capability
    /// makes a fixture SKIP while over-reporting makes it run and fail.
    ///
    /// `protocols/sftp.rs` was the tenth and has LANDED, and it was the first
    /// executor whose row was WIRED. `protocols/scp.rs` has now landed as the
    /// thin SCP-specific layer over that shared core, so both SSH rows in
    /// `curl-rs-lib/src/protocols/mod.rs` carry implementations when the `ssh`
    /// feature is enabled. `protocols/mod.rs`'s
    /// `nothing_is_runnable_in_this_checkout`, whose own documentation said it
    /// was to be DELETED rather than edited by exactly this checkpoint, is
    /// therefore gone, and neither SSH file belongs in this absence gate.
    ///
    /// `protocols/ftp/pingpong.rs` was the ninth and has LANDED: the FTP
    /// request/response cadence of `lib/pingpong.c` -- the command writer, the
    /// reply-line framer, the per-response timeout and the readiness loop --
    /// now exists, and `protocols/ftp/mod.rs` has since taken the command
    /// sequencing of `lib/ftp.c` that drives it, so the directory carries the
    /// 37-state machine, both data-channel modes and the wildcard driver. What
    /// FTP still lacks is a CALLER, exactly as HTTP does, so
    /// `ENGINE_PROTOCOLS` stays inert and the `Protocols:` banner stays silent
    /// about `ftp`.
    ///
    /// `protocols/stub.rs` has LANDED, which is why the phrase above says
    /// executors rather than protocol modules: the 24 out-of-scope schemes are
    /// now registered by their own module, and what is left under `protocols/`
    /// is the files that would actually perform a transfer -- eight when
    /// `stub.rs` landed, NONE now that `file.rs`, `http1.rs`, `http2.rs`,
    /// `http3.rs`, `sftp.rs`, `scp.rs`, `ftp/pingpong.rs` and `ws.rs` have.
    /// Registering a
    /// scheme and serving one are separate obligations, and only the second is
    /// still outstanding -- `curl-rs-lib/src/version.rs`'s `ENGINE_PROTOCOLS`
    /// records that on those terms, and `stub.rs` deliberately contributes
    /// nothing to the `Protocols:` banner.
    ///
    /// `protocols/ftp/pingpong.rs` was the ninth, `protocols/sftp.rs` the
    /// tenth, `protocols/http1.rs` the eleventh, `protocols/file.rs` the
    /// twelfth, `protocols/ws.rs` the nineteenth, and `protocols/http2.rs`
    /// and `protocols/scp.rs` have now joined them,
    /// `transfer/chunked.rs` the eighteenth,
    /// `transfer/content_encoding.rs` the seventeenth,
    /// `proxy/socks.rs` the sixteenth, `proxy/haproxy.rs` the fifteenth,
    /// `proxy/socks_gss.rs` the fourteenth and `protocols/stub.rs` the
    /// thirteenth; all thirteen have landed, so all thirteen rows are gone --
    /// which is what this gate exists to force. The transfer directory now has no
    /// absent file at all, and the loop itself has landed too, so what
    /// `version.rs`'s `ENGINE_TRANSFER` still records is a wiring gap -- no
    /// executor for the driver to run -- rather than a missing file.
    ///
    /// `proxy/http_connect.rs` was the twentieth and has now LANDED, which
    /// empties the proxy directory from this gate entirely. It carries all
    /// three CONNECT filters -- `"HTTP-PROXY"` dispatching on the negotiated
    /// ALPN, `"H1-PROXY"` running the six-state HTTP/1.x tunnel of
    /// `lib/cf-h1-proxy.c`, and `"H2-PROXY"` running the five-state HTTP/2
    /// tunnel of `lib/cf-h2-proxy.c` -- alongside the `CONNECT` request
    /// builder whose bytes 31 `<verify><proxy>` fixtures compare literally. So
    /// every proxy mechanism curl has is now written: the `"SOCKS"` filter of
    /// `lib/socks.c`, the SOCKS5 GSS-API sub-negotiation of
    /// `lib/socks_gssapi.c` behind the default-off `negotiate` feature, the
    /// PROXY protocol header filter of `lib/cf-haproxy.c`, and the three
    /// tunnel filters. None of them makes a proxy REACHABLE, because no
    /// production `crate::conn::ConnectionFilterFactories` exists to install
    /// one, which is why `curl-rs-lib/src/version.rs` still withholds the
    /// `proxy` capability -- but it now withholds it as `inert` rather than as
    /// `unwritten`, and that row is no longer below.
    /// `easy/handle.rs` has now LANDED, so its row is gone from below and the
    /// three-strong `easy/` group is down to two. It carries the decomposed
    /// easy handle: `struct Curl_easy`'s 24 members apportioned to the modules
    /// that own their lifecycles, `Curl_init_userdefined`'s frozen defaults
    /// with certificate verification ON, the generational identity token that
    /// `multi/` will key its slab with, and the four injected seams -- clock,
    /// resolver, TLS factory and generator -- that let the protocol and
    /// transfer modules be exercised without a live network.
    ///
    /// It does not by itself make a transfer possible, and the distinction is
    /// the same one every executor above is held by: `setopt.rs` and
    /// `getinfo.rs` remain absent, so nothing can yet WRITE an option onto a
    /// handle or READ a statistic off one, and `protocols/mod.rs` still keeps
    /// `run: None` on every row. A handle that can be built and defaulted is a
    /// delivered file whose gap is wiring, not source.
    const ENGINE_TARGETS: &[&str] = &[
        "curl-rs-lib/src/easy/setopt.rs",
        "curl-rs-lib/src/easy/getinfo.rs",
    ];

    /// The 13 `curl-rs` targets with no file.
    ///
    /// No CLI renderer now, two configuration stages, the three-module
    /// operation driver, all seven transfer callbacks, and the `--libcurl`
    /// emitter. `curl-rs/src/callbacks/mod.rs` is on disk and declares none of
    /// its seven children, which is why an invocation parses and then has
    /// nothing to hand a transfer.
    ///
    /// Both CLI renderers have now landed -- `curl-rs/src/cli/help.rs` and
    /// `curl-rs/src/cli/ipfs.rs` -- so both rows are gone, which is this gate
    /// working as designed rather than being weakened. The renderers exist;
    /// wiring the `--help`, `--version` and `--engine list` dispatch arms to
    /// them belongs to the operation driver, three of whose own modules are
    /// still listed below.
    ///
    /// `curl-rs/src/config/parseconfig.rs` was the third configuration stage
    /// and has landed too, so it is named by [`the_gate_can_see_a_present_file`]
    /// rather than here. Its reader is complete; what remains is the two lines
    /// that reach it, because `ParseHost::parse_config`
    /// (`curl-rs/src/cli/args.rs:2173`) does not yet take the
    /// `&mut GlobalConfig` the re-entry needs. That is a signature gap in a
    /// delivered file, not an absent file, so this gate is the wrong instrument
    /// for it and the module's own documentation carries it.
    const TOOL_TARGETS: &[&str] = &[
        "curl-rs/src/config/to_setopts.rs",
        "curl-rs/src/config/ssls.rs",
        "curl-rs/src/operate/mod.rs",
        "curl-rs/src/operate/single.rs",
        "curl-rs/src/operate/parallel.rs",
        "curl-rs/src/callbacks/write.rs",
        "curl-rs/src/callbacks/read.rs",
        "curl-rs/src/callbacks/header.rs",
        "curl-rs/src/callbacks/debug.rs",
        "curl-rs/src/callbacks/seek.rs",
        "curl-rs/src/callbacks/progress.rs",
        "curl-rs/src/callbacks/socket.rs",
        "curl-rs/src/libcurl_src.rs",
    ];

    /// The 1 `curl-rs-ffi` target with no file.
    ///
    /// It carries 21 of the 34 undefined exports -- the whole of
    /// `curl_multi_*`. The remaining 13 are
    /// the `curl_easy_*` core, whose module `ffi/easy.rs` does exist and today
    /// defines only the three option-introspection entry points. The counts are
    /// the ABI inventory's, published by `curl-rs-ffi/build.rs`.
    ///
    /// `curl-rs-ffi/src/ffi/ws.rs` was the second and has LANDED, which is why
    /// the figures above read 1/21/34 where they read 2/25/38 before it and
    /// 3/28/41 before `ffi/share.rs`. It carries all four `curl_ws_*` names --
    /// the last four entries of `lib/libcurl.def` -- and answers
    /// `CURLE_NOT_BUILT_IN` from three of them and NULL from `curl_ws_meta`,
    /// which is `lib/ws.c:1938-1980` exactly: the branch a build without
    /// WebSocket support carries. That is not a stub but the C's own second
    /// definition, selected from `curl_rs_lib::version::supports_websockets`,
    /// and it flips to the built-in branch when `ENGINE_PROTOCOLS` becomes
    /// present. `ffi/share.rs` was the third-to-last to land and
    /// carries three of the four `curl_share_*` names -- `ffi/strerror.rs` has
    /// always carried `curl_share_strerror`, because `lib/strerror.c` defines
    /// all four strerror functions in one translation unit and the crate's
    /// partition follows the definition rather than the declaring header.
    const ABI_TARGETS: &[&str] = &["curl-rs-ffi/src/ffi/multi.rs"];

    /// `CARGO_MANIFEST_DIR` is `<root>/curl-rs`, so one `parent()` reaches the
    /// workspace root.
    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("CARGO_MANIFEST_DIR always has a parent")
            .to_path_buf()
    }

    fn every_target() -> Vec<&'static str> {
        let mut all = Vec::with_capacity(16);
        all.extend_from_slice(ENGINE_TARGETS);
        all.extend_from_slice(TOOL_TARGETS);
        all.extend_from_slice(ABI_TARGETS);
        all
    }

    #[test]
    fn every_named_target_is_still_absent() {
        let root = repo_root();
        let landed: Vec<&str> = every_target()
            .into_iter()
            .filter(|path| root.join(path).is_file())
            .collect();

        assert!(
            landed.is_empty(),
            "these targets have landed -- remove them from this gate and \
             refresh the counts in curl-rs-lib/src/lib.rs, \
             curl-rs-ffi/src/lib.rs and README.md: {landed:?}"
        );
    }

    /// The split, as a total this test's own NAME carries.
    ///
    /// It read five/thirteen/two until `protocols/http3.rs` and
    /// `proxy/http_connect.rs` landed and their rows left [`ENGINE_TARGETS`],
    /// and until `curl-rs-ffi/src/ffi/ws.rs` landed and its row left
    /// [`ABI_TARGETS`]; it read three/thirteen/one until `easy/handle.rs`
    /// landed and left [`ENGINE_TARGETS`] too. Renaming rather than loosening
    /// the numbers is deliberate: a count in a name cannot drift silently, and
    /// the rename is the same notification the absence gate gives.
    #[test]
    fn the_split_is_two_thirteen_one() {
        assert_eq!(ENGINE_TARGETS.len(), 2, "curl-rs-lib");
        assert_eq!(TOOL_TARGETS.len(), 13, "curl-rs");
        assert_eq!(ABI_TARGETS.len(), 1, "curl-rs-ffi");
        assert_eq!(every_target().len(), 16, "the workspace total");
    }

    #[test]
    fn no_target_is_named_twice_and_each_names_its_own_crate() {
        let all = every_target();
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "a path is listed twice");

        for path in ENGINE_TARGETS {
            assert!(path.starts_with("curl-rs-lib/src/"), "{path}");
        }
        for path in TOOL_TARGETS {
            assert!(path.starts_with("curl-rs/src/"), "{path}");
        }
        for path in ABI_TARGETS {
            assert!(path.starts_with("curl-rs-ffi/src/ffi/"), "{path}");
        }
    }

    /// The absence above is a measurement, so the measuring has to be able to
    /// see a file that IS there. One sibling per crate, chosen because each is
    /// named in the same design tables as the missing ones, plus the target
    /// that most recently moved off [`ABI_TARGETS`] -- `ffi/ws.rs`, which
    /// took the whole `curl_ws_*` family with it -- the target
    /// that most recently moved off [`TOOL_TARGETS`], and the fourteen that
    /// most recently moved off [`ENGINE_TARGETS`] -- `easy/handle.rs`, the
    /// most recent of them and the first file in the `easy/` group to land,
    /// `protocols/http3.rs`, the
    /// last per-scheme executor to land and the only filter that terminates
    /// its own chain, `proxy/http_connect.rs`, the three CONNECT filters that
    /// empty the proxy directory from the absence gate, `protocols/ws.rs`,
    /// whose
    /// handler delegates to `protocols/http1.rs`'s and so could not have
    /// landed before it, `protocols/http2.rs`, the connection filter that
    /// installs beneath that same handler, `protocols/scp.rs`, the thin layer
    /// over the SSH session core that lives in `protocols/sftp.rs`,
    /// `protocols/file.rs`, the first per-scheme executor to land,
    /// `protocols/http1.rs`, `protocols/sftp.rs`, the first whose registry row
    /// is wired, and `protocols/ftp/pingpong.rs`, with
    /// `protocols/stub.rs` and `proxy/socks_gss.rs` behind
    /// them -- which makes this the
    /// assertion that fails first if a landed file is ever double-counted as
    /// both present and absent. `proxy/socks_gss.rs` is checked here even
    /// though it compiles only under the `negotiate` feature, because what is
    /// measured is the file on disk and that is there unconditionally.
    #[test]
    fn the_gate_can_see_a_present_file() {
        let root = repo_root();
        for present in [
            "curl-rs-lib/src/easy/mod.rs",
            "curl-rs-lib/src/easy/handle.rs",
            "curl-rs-lib/src/protocols/ftp/listparser.rs",
            "curl-rs-lib/src/protocols/ftp/pingpong.rs",
            "curl-rs/src/callbacks/mod.rs",
            "curl-rs/src/config/mod.rs",
            "curl-rs/src/config/parseconfig.rs",
            "curl-rs-lib/src/protocols/sftp.rs",
            "curl-rs-lib/src/protocols/scp.rs",
            "curl-rs-lib/src/protocols/stub.rs",
            "curl-rs-lib/src/protocols/file.rs",
            "curl-rs-lib/src/proxy/socks.rs",
            "curl-rs-lib/src/proxy/socks_gss.rs",
            "curl-rs-lib/src/proxy/haproxy.rs",
            "curl-rs-lib/src/proxy/http_connect.rs",
            "curl-rs-lib/src/protocols/http1.rs",
            "curl-rs-lib/src/protocols/http2.rs",
            "curl-rs-lib/src/protocols/http3.rs",
            "curl-rs-lib/src/protocols/ws.rs",
            "curl-rs-ffi/src/ffi/easy.rs",
            "curl-rs-ffi/src/ffi/ws.rs",
        ] {
            assert!(
                root.join(present).is_file(),
                "{present} should exist; if it does not, this gate is \
                 measuring the wrong directory"
            );
        }
    }
}
