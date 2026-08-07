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

//! Persisted client state: the cookie jar, `.netrc`, HSTS and Alt-Svc.
//!
//! This file has two jobs. It is the module root for `src/cookies/`, and it
//! is the cookie engine itself: the successor of `lib/cookie.c` (1,638
//! lines) and `lib/cookie.h` (143 lines), including the **Netscape
//! cookie-jar file format**.
//!
//! The five children of this directory share a module because every one of
//! them reads and writes a file on the user's disk whose format is FROZEN. A
//! jar written by curl 8.19.0-DEV must be readable here and one written here
//! must be readable there, and the same obligation applies to the HSTS and
//! Alt-Svc caches and to `.netrc`. That is why the jar is implemented
//! natively rather than delegated to a general-purpose cookie crate -- no
//! such crate commits to the Netscape on-disk shape -- and why
//! `publicsuffix` is used for nothing but the domain-matching rules that
//! libpsl previously supplied. AAP 0.5.1 records the omission as
//! deliberate.
//!
//! `pub(crate)`: no exported symbol of `lib/libcurl.def` resolves a name
//! here. The cookie engine, the caches and `.netrc` are all reached through
//! an easy handle's option surface -- `CURLOPT_COOKIE` (10022),
//! `CURLOPT_COOKIEFILE` (10031), `CURLOPT_COOKIEJAR` (10082),
//! `CURLOPT_COOKIESESSION` (96), `CURLOPT_COOKIELIST` (10135) and
//! `CURLINFO_COOKIELIST`. Those identifiers are listed for cross-reference
//! only; the enumeration itself belongs to `curl-rs-ffi/src/ffi/opts.rs` and
//! is not redefined here.
//!
//! # TWO BYTE-LEVEL CONTRACTS MEET IN THIS FILE
//!
//! 1. **The jar file.** `tests/data/test1920`, `test31`, `test46` and
//!    `test1160` compare a saved jar against literal bytes, so every tab,
//!    every `TRUE`, the `#HttpOnly_` prefix, the Mozilla-style leading dot
//!    and the trailing blank line of the header are the specification.
//! 2. **The `Cookie:` request header, content AND order.** AAP 0.6.7:
//!    `compareparts` joins both sides into a single string and compares them
//!    whole, with no per-line matching and no normalization, across 1,476 of
//!    the 1,914 fixtures. `tests/data/test8` pins the exact bytes, and 51
//!    fixtures gate on the `cookies` label.
//!
//! Neither contract tolerates an improvement. AAP 0.8.2: *a refactor that
//! produces different-but-arguably-better output has failed.* Performance is
//! a non-goal (AAP 0.1.1), so where a faster design and a more faithful one
//! disagree, the faithful one wins. Every deliberately preserved wart below
//! carries a comment naming its `lib/cookie.c` line.
//!
//! # FOUR DIFFERENT STRING-COMPARISON POLICIES COEXIST HERE
//!
//! Getting any one of them wrong is a silent behaviour change, so the table
//! is stated once, here, with the C function each row reproduces.
//!
//! | What is compared | C function | Policy |
//! |---|---|---|
//! | name against name, in `replace_existing` | `strcmp` (`:834`, `:875`) | **case-SENSITIVE** |
//! | domain against domain, in `replace_existing` | `curl_strequal` (`:839`, `:879`) | case-INsensitive |
//! | path against path, in `replace_existing` | `curl_strequal` (`:891`) | case-INsensitive |
//! | cookie path against URI path, in `pathmatch` | `strncmp` (`:139`) | **case-SENSITIVE** |
//! | domain tail, in `cookie_tailmatch` | `curl_strnequal` (`:82`) | case-INsensitive |
//! | `__Secure-` / `__Host-` in a HEADER | `strncmp` (`:501`, `:503`) | **case-SENSITIVE** |
//! | `__Secure-` / `__Host-` in a JAR LINE | `curl_strnequal` (`:744`, `:746`) | case-INsensitive |
//!
//! The C comments the fourth row itself: *"not using checkprefix() because
//! matching should be case-sensitive"*. The asymmetry between the last two
//! rows is deliberate and is preserved; see `parse_netscape`.
//!
//! The insensitive rows go through [`crate::util::strcase`], which folds the
//! 26 ASCII letter pairs and nothing else, whatever the process locale says.
//! `char::to_lowercase` is never used: it is Unicode-aware and
//! locale-shaped, and a Turkish dotless i would change which cookies are
//! sent.
//!
//! # Bytes, not text
//!
//! Cookie names, values, domains and paths are untrusted bytes and the C
//! never validates UTF-8: `tests/data/test31` sets a cookie whose name and
//! value are both non-UTF-8 and requires them in the saved jar verbatim. So
//! every stored field is `Vec<u8>` and every parser takes `&[u8]`. The one
//! place text appears is a diagnostic message, and it is lossy there on
//! purpose.
//!
//! This is also the most adversarially exposed file in the directory: it
//! parses `Set-Cookie:` headers straight off the wire and jar files straight
//! off disk. There is no `unwrap`, no `expect`, no `panic!`, no panicking
//! index and no panicking arithmetic anywhere below -- a panic here could
//! unwind toward a C caller through `curl-rs-ffi`, which is undefined
//! behaviour at the ABI boundary. Every length and every byte is treated as
//! hostile.
//!
//! # The clock is injected
//!
//! `lib/cookie.c` calls `time(NULL)` at `:284`, `:590`, `:626` and through
//! `cap_expires`, which is the WALL clock. Every one of those becomes
//! `Clock::epoch_secs`, supplied by the caller (AAP 0.3.3 pattern P12).
//! `SystemTime::now` is never called here.
//!
//! The injection is faithful rather than invented: the C tree already
//! substitutes its own clock for testability, at `lib/hsts.c:50-64` and
//! `lib/altsvc.c:431-447`, where a `#if defined(DEBUGBUILD) ||
//! defined(UNITTESTS)` shim reads the `CURL_TIME` environment variable and
//! then `#define`s `time` away. That mechanism is NOT reproduced -- reading
//! an environment variable to decide what year it is has no place in
//! shipped code -- but it settles the question of whether displacing the
//! clock is a liberty. It is not.
//!
//! # `share/` owns the locking, and this module owns none of it
//!
//! `Curl_cookie_loadfiles` (`:1157`), `Curl_cookie_list` (`:1583`),
//! `Curl_flush_cookies` (`:1605`) and `Curl_cookie_run` (`:1630`) each take
//! `CURL_LOCK_DATA_COOKIE` with `CURL_LOCK_ACCESS_SINGLE`
//! (`include/curl/curl.h:3033`) around their whole body, and
//! `lib/setopt.c`'s `cookielist()` does the same for all four command words.
//! `crate::share` does not exist at this commit, so the contract is written
//! down here rather than guessed at later:
//!
//! * **Exclusive access is required** for `CookieInfo::add`,
//!   `CookieInfo::load`, `CookieInfo::loadfiles`,
//!   `CookieInfo::getlist` (it prunes), `CookieInfo::list` (it prunes),
//!   `CookieInfo::clearall`, `CookieInfo::clearsess`,
//!   `CookieInfo::run` and `CookieInfo::save`. Every one of those takes
//!   `&mut self`, so the requirement is in the signature and not only in
//!   this paragraph.
//! * **Shared access suffices** for the read accessors and for
//!   `CookieInfo::write_to`, which takes `&self`.
//! * `Curl_flush_cookies` saves the jar only when a `CURLOPT_COOKIEJAR` name
//!   is set AND `running` is true, and it tears the store down **only when
//!   the store is not shared** -- `if(cleanup && (!data->share ||
//!   (data->cookies != data->share->cookies)))` at `:1647`. That ownership
//!   question is `share/`'s to answer, so `CookieInfo::flush` reports what
//!   it did and does not destroy anything.
//!
//! One hazard is worth recording before `share/` is written, because the
//! compiler will state it as a puzzle rather than as advice. `lib.rs`
//! declares `pub mod share;` but `pub(crate) mod cookies;`, so a `pub`
//! signature in `share/` that names `CookieInfo` is
//! `error[E0446]: private type in public interface`. The resolution is
//! `share/`'s: keep the store behind its own opaque `pub` wrapper, which is
//! what the C does -- `CURLSH` is literally `typedef void CURLSH` -- or add
//! a curated `pub use` at the crate root. These types stay effectively
//! `pub(crate)` and must not be widened from here.
//!
//! # Where the `Cookie:` header line is actually assembled
//!
//! `Curl_cookie_getlist` selects and orders the cookies; the header line is
//! built by `http_cookies` at `lib/http.c:2543-2586`. That is
//! `protocols/http1.rs`'s file, and it does not exist yet, so
//! `CookieInfo::cookie_header_value` reproduces the composition here --
//! the `MAX_COOKIE_HEADER_LEN` cap is declared in `lib/cookie.h:97` and the
//! selection rules are this module's -- and `http1.rs` is expected to call
//! it rather than re-derive it. The boundary is stated on that function:
//! everything from the `Cookie: ` prefix outwards, including the `CRLF` and
//! the `CURLOPT_COOKIE` tail, stays with the request writer.

// The four children of this directory. A `mod` line without its file is
// `error[E0583]`, which no attribute can suppress, so each declaration lands
// with the file it names.

/// The Alt-Svc cache (RFC 7838), behind `--alt-svc <file>`.
///
/// Supersedes `lib/altsvc.c` and `lib/altsvc.h`, and backs `CURLOPT_ALTSVC`
/// (10287) and `CURLOPT_ALTSVC_CTRL` (286).
///
/// **Gated on `altsvc`**, the successor of C's `CURL_DISABLE_ALTSVC`. The C
/// additionally gates the file on `CURL_DISABLE_HTTP` (`lib/altsvc.c:30`);
/// there is no counterpart, because the crate's capability vocabulary is
/// closed at fifteen names and none of them switches HTTP off.
///
/// It carries two things beyond the cache itself, and both are recorded here
/// so that a later module imports rather than redeclares them: `AlpnId`, the
/// successor of `enum alpnid` (`lib/hostip.h:49-54`), whose eventual home is
/// `crate::dns`; and the two name conversions of `lib/connect.c:73-95`, whose
/// eventual home is `crate::conn`. Neither module provides them at this
/// commit. The child's own header states the contract for moving them.
#[cfg(feature = "altsvc")]
pub(crate) mod altsvc;

/// `.netrc` credential lookup, behind `--netrc`, `--netrc-file` and
/// `--netrc-optional`.
///
/// Supersedes `lib/netrc.c` and `lib/netrc.h`, and backs `CURLOPT_NETRC`
/// (51) and `CURLOPT_NETRC_FILE` (10118).
///
/// **Declared unconditionally, and it must stay that way.** The C has
/// `#ifndef CURL_DISABLE_NETRC` (`lib/netrc.h:28`), but credential lookup
/// serves every protocol rather than only HTTP -- `lib/url.c:2608` runs it
/// for any scheme that can carry a user and a password -- so attaching it to
/// the cookie engine would silently disable `--netrc` for FTP and SFTP. The
/// crate's capability vocabulary is closed at fifteen names in
/// `curl-rs-lib/Cargo.toml` and none of them is a netrc switch, so there is
/// nothing to attach it to in any case. It compiles and is reachable under
/// `cargo build -p curl-rs-lib --no-default-features`.
pub(crate) mod netrc;

/// The Public Suffix List -- may this host set a cookie for this domain, or
/// would that be a "super cookie" set at registry level?
///
/// Supersedes `lib/psl.c` and `lib/psl.h`, replacing the `libpsl` binding
/// with the `publicsuffix` crate. Its two consumers are [`is_public_suffix`]
/// in this file, the port of `lib/cookie.c:774-819`, and
/// [`crate::version`], which must report the `PSL` capability truthfully
/// rather than assume it.
///
/// **Gated on `cookies`**, unlike [`netrc`] above, and the reason is
/// mechanical rather than stylistic: the public-suffix rules are the one
/// child of this module that reaches an external crate, and `publicsuffix`
/// is declared `optional` in `curl-rs-lib/Cargo.toml` with
/// `cookies = ["dep:publicsuffix"]` as its only activator, so an
/// unconditional declaration would fail to RESOLVE the crate under
/// `--no-default-features` rather than merely compile a larger tree.
///
/// Availability is therefore a RUN-TIME property inside the module as well
/// as a compile-time one: the list source is injected, so "configured but
/// unloadable" fails closed exactly as the C's `USE_LIBPSL` arm with a null
/// list does, while "never configured" reproduces the `#ifndef USE_LIBPSL`
/// arm in which no cookie is dropped on public-suffix grounds.
#[cfg(feature = "cookies")]
pub(crate) mod psl;

/// The HTTP Strict Transport Security cache, behind `--hsts <file>`.
///
/// Supersedes `lib/hsts.c` and `lib/hsts.h`, and backs `CURLOPT_HSTS`
/// (10300), `CURLOPT_HSTS_CTRL` (299) and the four callback options
/// `CURLOPT_HSTSREADFUNCTION` (20301), `CURLOPT_HSTSREADDATA` (10302),
/// `CURLOPT_HSTSWRITEFUNCTION` (20303) and `CURLOPT_HSTSWRITEDATA` (10304).
///
/// **Gated on `hsts`**, matching the C's `CURL_DISABLE_HSTS`. The C
/// additionally requires HTTP -- `#if !defined(CURL_DISABLE_HTTP) &&
/// !defined(CURL_DISABLE_HSTS)` at `lib/hsts.c:30` -- which has no
/// counterpart here because HTTP/1.1 is unconditional in this crate and the
/// capability vocabulary is closed at fifteen names in
/// `curl-rs-lib/Cargo.toml`, none of which is an HTTP switch.
///
/// Its on-disk format is a frozen, consumer-visible contract and is NOT this
/// file's: the HSTS header carries no trailing blank line where the jar's
/// does. Three files in this directory write three different headers and the
/// three are deliberately not shared.
#[cfg(feature = "hsts")]
pub(crate) mod hsts;

// ---------------------------------------------------------------------------
// Everything below is the cookie engine, and every item carries
// `#[cfg(feature = "cookies")]`. The FILE carries no top-level gate, because
// `lib.rs` declares `pub(crate) mod cookies;` unconditionally and `netrc`
// above must remain reachable under `--no-default-features`.
// ---------------------------------------------------------------------------

#[cfg(feature = "cookies")]
use core::fmt;
#[cfg(feature = "cookies")]
use std::collections::VecDeque;
#[cfg(feature = "cookies")]
use std::fs::File;
#[cfg(feature = "cookies")]
use std::io::{self, BufRead, BufReader, Write};
#[cfg(feature = "cookies")]
use std::path::Path;

#[cfg(feature = "cookies")]
use crate::error::{CURLcode, CodeResult};
#[cfg(feature = "cookies")]
use crate::util::dynbuf::DynBuf;
#[cfg(feature = "cookies")]
use crate::util::fopen;
#[cfg(feature = "cookies")]
use crate::util::get_line::get_line;
#[cfg(feature = "cookies")]
use crate::util::inet::{pton4, pton6};
#[cfg(feature = "cookies")]
use crate::util::llist;
#[cfg(feature = "cookies")]
use crate::util::memrchr::memrchr;
#[cfg(feature = "cookies")]
use crate::util::parsedate::{self, Outcome};
#[cfg(feature = "cookies")]
use crate::util::slist::SList;
#[cfg(feature = "cookies")]
use crate::util::strcase::{
    casecompare, ncasecompare, raw_toupper, strntolower,
};
#[cfg(feature = "cookies")]
use crate::util::strparse::{
    str_casecompare, str_cspn, str_number, str_passblanks, str_single,
    str_trimblanks, StrError,
};
#[cfg(feature = "cookies")]
use crate::util::timeval::Clock;
#[cfg(feature = "cookies")]
use crate::util::CurlOffT;

// ---------------------------------------------------------------------------
// The limits -- `lib/cookie.h:66-102` and `lib/cookie.c:44`, `:372`.
// ---------------------------------------------------------------------------

/// `COOKIE_HASH_SIZE` -- `lib/cookie.h:54`.
///
/// The number of buckets in the jar, and **not** a tuning parameter. It is
/// observable through `CURLINFO_COOKIELIST`, which walks the buckets in index
/// order (`lib/cookie.c:1570`) and emits whatever it finds, so the value
/// decides the order of that list. Changing it changes an output a fixture
/// compares.
#[cfg(feature = "cookies")]
pub(crate) const COOKIE_HASH_SIZE: usize = 63;

/// `MAX_COOKIE_LINE` -- `lib/cookie.h:80`.
///
/// *"The longest we allow a line to be when reading a cookie from an HTTP
/// header or from a cookie jar."* A longer `Set-Cookie:` line is discarded in
/// silence (`lib/cookie.c:447-449`), and it is also the `dynbuf` ceiling the
/// jar reader gives `Curl_get_line` (`:1116`).
#[cfg(feature = "cookies")]
pub(crate) const MAX_COOKIE_LINE: usize = 5000;

/// `MAX_NAME` -- `lib/cookie.h:84`.
///
/// RFC 6265 section 6.1 asks for *"at least 4096 bytes per cookie"*, and the
/// 6265bis draft phrases it as a hard limit: *"If the sum of the lengths of
/// the name string and the value string is more than 4096 octets, abort these
/// steps and ignore the set-cookie-string entirely."*
///
/// The C applies it as three separate tests, not one, and the asymmetry is
/// real: each of the name and the value must be **strictly less than**
/// `MAX_NAME - 1`, while their sum must not **exceed** `MAX_NAME`
/// (`lib/cookie.c:487-489`). So 4095 + 1 is accepted and 4094 + 4094 is not.
#[cfg(feature = "cookies")]
pub(crate) const MAX_NAME: usize = 4096;

/// `MAX_DATE_LENGTH` -- `lib/cookie.c:372`.
///
/// The ceiling on an `Expires` attribute's length. The C's comment: *"The
/// standard date formats are within the 30 bytes range. This adds an extra
/// margin just to make sure it realistically works with what is used out
/// there."* A longer value makes the whole attribute unrecognised, which
/// leaves the cookie a session cookie rather than dropping it.
#[cfg(feature = "cookies")]
pub(crate) const MAX_DATE_LENGTH: usize = 80;

/// `MAX_SET_COOKIE_AMOUNT` -- `lib/cookie.h:89`.
///
/// *"Maximum number of `Set-Cookie:` lines accepted in a single response. If
/// more such header lines are received, they are ignored."* The C adds a
/// constraint on the value itself -- *"This value must be less than 256 since
/// an unsigned char is used to count"* -- and asserts it at
/// `lib/cookie.c:952`. The counter is `u32` here, so the ceiling is not
/// forced by a type; the assertion is kept as a test instead, because the
/// value is part of the observable behaviour either way.
#[cfg(feature = "cookies")]
pub(crate) const MAX_SET_COOKIE_AMOUNT: u32 = 50;

/// `MAX_COOKIE_HEADER_LEN` -- `lib/cookie.h:97`.
///
/// *"Maximum size for an outgoing cookie line libcurl will use in an http
/// request. This is the default maximum length used in some versions of
/// Apache httpd."* Applied by
/// [`CookieInfo::cookie_header_value`], which is where the C applies it too
/// -- at `lib/http.c:2559`, not in `lib/cookie.c`.
#[cfg(feature = "cookies")]
pub(crate) const MAX_COOKIE_HEADER_LEN: usize = 8190;

/// `MAX_COOKIE_SEND_AMOUNT` -- `lib/cookie.h:102`.
///
/// *"Maximum number of cookies libcurl will send in a single request, even if
/// there might be more cookies that match. One reason to cap the number is to
/// keep the maximum HTTP request within the maximum allowed size."*
#[cfg(feature = "cookies")]
pub(crate) const MAX_COOKIE_SEND_AMOUNT: usize = 150;

/// `COOKIES_MAXAGE` -- `lib/cookie.c:44`, *"number of seconds in 400 days"*.
///
/// The RFC 6265bis draft-19 ceiling on how far into the future a cookie may
/// expire. 400 * 24 * 3600 = 34,560,000.
#[cfg(feature = "cookies")]
pub(crate) const COOKIES_MAXAGE: CurlOffT = 400 * 24 * 3600;

/// `COOKIE_PREFIX__SECURE` -- `lib/cookie.h:51`.
///
/// Reproduced as a constant even though this implementation stores the two
/// prefixes as separate bits on [`Cookie`] rather than as a mask: the values
/// are part of the vocabulary of *draft-ietf-httpbis-rfc6265bis-02* that the
/// C names here, and a later reader comparing the two files should find them.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Documents the C's mask; the bits are separate fields.
pub(crate) const COOKIE_PREFIX_SECURE: u32 = 1 << 0;

/// `COOKIE_PREFIX__HOST` -- `lib/cookie.h:52`.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Documents the C's mask; the bits are separate fields.
pub(crate) const COOKIE_PREFIX_HOST: u32 = 1 << 1;

/// `COOKIE_PIECES` -- `lib/cookie.c:379`.
///
/// The four spans `parse_cookie_header` accumulates before it commits any of
/// them: `COOKIE_NAME` 0, `COOKIE_VALUE` 1, `COOKIE_DOMAIN` 2 and
/// `COOKIE_PATH` 3 (`:374-377`). This implementation names the four fields of
/// [`CookiePieces`] instead of indexing an array, so the count is here for
/// provenance and is asserted against that struct by test.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Provenance for CookiePieces; asserted by test.
pub(crate) const COOKIE_PIECES: usize = 4;

/// `CURL_OFF_T_MAX` for the 64-bit `curl_off_t` of all four mandated targets.
///
/// Used as the "no expiry information yet" sentinel for
/// [`CookieInfo::next_expiration`] (`lib/cookie.c:1077`) and as the ceiling
/// `curlx_str_number` is given for both `Max-Age` and the jar's expiry field.
/// `TIME_T_MAX` in `cap_expires` is the same value on these targets, and the
/// C uses both spellings for it.
#[cfg(feature = "cookies")]
pub(crate) const CURL_OFF_T_MAX: CurlOffT = CurlOffT::MAX;

/// The three comment lines and the blank line that open a saved jar --
/// `lib/cookie.c:1488-1491`, one `fputs`.
///
/// **Written unconditionally**, before any cookie and even when there are
/// none at all: `tests/data/test1160` saves a jar from an empty store and
/// requires exactly these bytes and nothing more.
///
/// **The trailing blank line is unique to the jar.** `hsts.rs` and
/// `altsvc.rs` each write a two-line header with no blank line after it. Three
/// files in this directory, three headers, deliberately not shared -- see the
/// module header.
#[cfg(feature = "cookies")]
#[rustfmt::skip]
pub(crate) const FILE_HEADER: &[u8] =
    b"# Netscape HTTP Cookie File\n\
      # https://curl.se/docs/http-cookies.html\n\
      # This file was generated by libcurl! Edit at your own risk.\n\
      \n";

/// The `#HttpOnly_` marker that opens a jar line for an `HttpOnly` cookie.
///
/// Read at `lib/cookie.c:672` with a **case-sensitive** `strncmp` and written
/// at `:1436`. The C explains the format at `:667-671`: *"In 2008, Internet
/// Explorer introduced HTTP-only cookies to prevent XSS attacks. Cookies
/// marked httpOnly are not accessible to JavaScript. In Firefox's cookie
/// files, they are prefixed `#HttpOnly_` and the rest remains as usual, so we
/// skip 10 characters of the line."*
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const HTTPONLY_PREFIX: &[u8] = b"#HttpOnly_";

/// The literal a jar's boolean field carries when it is set.
///
/// Written at `lib/cookie.c:1447` and `:1449`, upper case, and read at
/// `:707`, `:710`, `:711` and `:727`. Both the reader's comparisons and the
/// writer's output are frozen: `docs/HTTP-COOKIES.md` documents fields 1 and
/// 3 as booleans and every fixture jar spells them this way.
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const TRUE_WORD: &[u8] = b"TRUE";

/// The literal a jar's boolean field carries when it is clear.
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const FALSE_WORD: &[u8] = b"FALSE";

/// What the writer emits for a cookie with no domain -- `lib/cookie.c:1444`.
///
/// Reachable only for a cookie set from a `Set-Cookie:` header that carried
/// no `Domain` attribute AND was added with no default domain, which is what
/// `CURLOPT_COOKIELIST` and a header line inside a loaded cookie file both
/// do. A cookie read from a jar line always has a domain, possibly the empty
/// one, because `parse_netscape` assigns field 0 unconditionally.
///
/// Note that such a cookie is skipped by both the jar writer (`:1508-1509`)
/// and `CURLINFO_COOKIELIST` (`:1573-1574`), so this literal is reached only
/// through a direct call to [`get_netscape_format`].
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const UNKNOWN_DOMAIN: &[u8] = b"unknown";

/// The default path, and what the writer emits for a cookie with none --
/// `lib/cookie.c:1446`, `:235` and `:718`.
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const ROOT_PATH: &[u8] = b"/";

/// The bytes that end a name in a `Set-Cookie:` header --
/// `lib/cookie.c:457`, `curlx_str_cspn(&ptr, &name, ";\t\r\n=")`.
///
/// **The TAB is in this set and is NOT in [`VALUE_DELIMITERS`].** The
/// difference is why a TAB inside a value survives as far as the explicit
/// rejection at `:493-497`, and why `tests/data/test8`'s `cookie9` -- whose
/// value is `junk--` followed by a TAB -- is accepted with the TAB trimmed
/// off rather than rejected.
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const NAME_DELIMITERS: &[u8] = b";\t\r\n=";

/// The bytes that end a value in a `Set-Cookie:` header --
/// `lib/cookie.c:462`, `curlx_str_cspn(&ptr, &val, ";\r\n")`.
///
/// No TAB. See [`NAME_DELIMITERS`].
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const VALUE_DELIMITERS: &[u8] = b";\r\n";

/// The bytes that end a field in a jar line -- `lib/cookie.c:688`,
/// `strcspn(ptr, "\t\r\n")`.
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const FIELD_DELIMITERS: &[u8] = b"\t\r\n";

/// The `__Secure-` cookie-name prefix of
/// *draft-ietf-httpbis-cookie-prefixes-00*.
///
/// Matched **case-sensitively** against a header (`lib/cookie.c:501`) and
/// **case-insensitively** against a jar line (`:744`). The asymmetry is
/// deliberate; see [`parse_netscape`].
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const PREFIX_SECURE_NAME: &[u8] = b"__Secure-";

/// The `__Host-` cookie-name prefix.
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const PREFIX_HOST_NAME: &[u8] = b"__Host-";

// ---------------------------------------------------------------------------
// Small helpers that stand in for a C idiom rather than for a named function.
// ---------------------------------------------------------------------------

/// The `const char *` view of `bytes`: everything up to the first zero.
///
/// Every scan in `lib/cookie.c` runs over a NUL-terminated string, so a zero
/// byte ends the input for `strlen` at `:443`, for `strcspn` at `:688`, for
/// `curlx_str_cspn` at `:457` and for the `while(len && *p)` of
/// `invalid_octets` at `:357`. Truncating once, at each entry point, makes
/// every scan below total without a terminator emulation in each of them.
///
/// A cookie line therefore cannot contain a zero byte, which matches the way
/// one arrives: `Curl_get_line` already truncates a jar line at the first
/// zero (`lib/curl_get_line.c:46`), and a header value comes from a
/// NUL-terminated buffer. `hsts.rs` and `netrc.rs` each solve the same
/// problem the same way; the three helpers are independent because no module
/// may widen its surface for another.
#[cfg(feature = "cookies")]
fn c_string(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        Some(nul) => &bytes[..nul],
        None => bytes,
    }
}

/// `Curl_host_is_ipnum(host)` -- declared `lib/hostip.h:75`, and defined as
/// exactly `Curl_inet_pton(AF_INET, host, &t) > 0 || Curl_inet_pton(AF_INET6,
/// host, &t) > 0`.
///
/// Written out here, over [`crate::util::inet`], rather than reached for
/// through `crate::dns`: the C's definition lives in `lib/hostip.c` and the
/// cookie engine has no other reason to know about name resolution, so
/// borrowing three lines is cheaper than a dependency edge this module would
/// otherwise carry for the life of the crate.
///
/// **curl's `pton4` is strict**, which is load-bearing rather than
/// incidental. It requires exactly four dotted octets, rejects a leading
/// zero, and accepts no hexadecimal, octal or shorthand form -- so `127.1` is
/// NOT an ipnum here even though a browser and `crate::url`'s
/// `ipv4_normalize` both accept it, and `01.2.3.4` is not one either.
/// `std::net::Ipv4Addr::from_str` has its own rules and is deliberately not
/// used. `pton6` likewise rejects a zone identifier.
///
/// Two consumers depend on the strictness: [`cookiehash`], where every
/// ipnum-shaped domain lands in bucket 0, and the `Domain` attribute check in
/// [`parse_cookie_header`], where an ipnum host demands an exact domain match
/// instead of a tail match. `tests/data/test8` turns on it -- `domain=.0.0.1`
/// against host `127.0.0.1` must NOT match, and it does not, because `0.0.1`
/// is not an ipnum while `127.0.0.1` is.
#[cfg(feature = "cookies")]
fn host_is_ipnum(host: &[u8]) -> bool {
    pton4(host).is_some() || pton6(host).is_some()
}

/// `Curl_getdate_capped` over a byte span.
///
/// [`crate::util::parsedate::getdate_capped`] is the designated successor of
/// `Curl_getdate_capped` (`lib/parsedate.c:581-585`) and takes a [`str`],
/// because its shape is a settled cross-crate contract that
/// `curl-rs-ffi/src/ffi/misc.rs` produces a `&str` for. A `Set-Cookie:`
/// header is not required to be valid text and this module never requires it
/// to be, so the byte-native engine is called directly -- exactly what
/// `parsedate.rs` documents `parsedate` as being `pub(crate)` for. The two
/// map [`Outcome`] identically, and a test asserts they agree on every input
/// that is valid text.
///
/// `Outcome::Later` is a SUCCESS, carrying `TIME_T_MAX`: the C's body is
/// `return (rc == PARSEDATE_FAIL);`, so only a genuinely unparsable string is
/// an error. The `-1`-to-`0` adjustment of the exported `curl_getdate` is NOT
/// applied here, because this entry point reports failure out of band and
/// needs no sentinel.
///
/// `hsts.rs` and `altsvc.rs` each carry the same three-line helper for the
/// same reason.
#[cfg(feature = "cookies")]
fn getdate_capped(date: &[u8]) -> Option<CurlOffT> {
    match parsedate::parsedate(date) {
        Outcome::Ok(seconds) | Outcome::Later(seconds) => Some(seconds),
        Outcome::Fail => None,
    }
}

/// Writes `bytes` whole, mapping any failure to `CURLE_WRITE_ERROR`.
///
/// The C ignores what `fputs` at `lib/cookie.c:1488` and `curl_mfprintf` at
/// `:1524` return, so a full disk produces a truncated jar and a save that
/// reports success. **This propagates instead**, and the divergence is
/// recorded rather than buried:
///
/// * No byte of a SUCCESSFUL save differs. The two behaviours are
///   distinguishable only when the underlying write fails.
/// * `cookie_output` already handles the error it cannot currently receive:
///   the `error:` block at `:1547-1554` closes the handle and unlinks the
///   temporary file, and the dropped return values are exactly what makes
///   that block unreachable from a write failure. Propagating makes the C's
///   own intent reachable rather than inventing new behaviour.
/// * The alternative costs data. Ignoring the error renames a truncated
///   temporary over the jar; propagating removes the temporary and leaves the
///   jar as `Curl_fopen` left it.
/// * No fixture can reach either path, because no fixture can make a write
///   fail.
///
/// Contrast the warts listed in the module header, which ARE reproduced. Each
/// of those is reachable from a test and observable in output; this one is
/// neither. `hsts.rs` reaches the same conclusion for the same reason.
#[cfg(feature = "cookies")]
fn emit<W: Write>(out: &mut W, bytes: &[u8]) -> CodeResult<()> {
    out.write_all(bytes).map_err(|_| CURLcode::WriteError)
}

/// `strncmp(literal, span, span.len()) == 0` for a NUL-terminated literal.
///
/// The C compares a literal against a length-limited span twice in
/// [`parse_netscape`] -- `strncmp("TRUE", ptr, len)` and `strncmp("FALSE",
/// ptr, len)` at `:709` -- and the result is NOT "the span equals the
/// literal". `strncmp` stops at the terminator of either argument, so with
/// `len` bytes of span and a literal of `k` bytes it answers zero exactly
/// when `len <= k` and the span is a prefix of the literal:
///
/// * `len > k` compares the literal's terminator against a real span byte and
///   differs, so a longer span never matches.
/// * `len <= k` compares `len` bytes and no terminator is reached.
///
/// An EMPTY span therefore matches every literal, which is precisely how the
/// jar's optional path field is absorbed -- see [`parse_netscape`] field 2.
/// Spelling that out as `literal.starts_with(span)` is the whole function, and
/// it is a named function so the call site can be read against the C without
/// re-deriving the argument order.
#[cfg(feature = "cookies")]
fn strncmp_prefix(literal: &[u8], span: &[u8]) -> bool {
    literal.starts_with(span)
}

// ---------------------------------------------------------------------------
// The diagnostic sink -- the successor of `infof`.
// ---------------------------------------------------------------------------

/// Where this module's diagnostics go.
///
/// `lib/cookie.c` calls `infof(data, ...)` at `:477`, `:490`, `:497`, `:522`,
/// `:568`, `:802`, `:806`, `:868`, `:1029` and `:1109`, and `infof` is a
/// macro that tests `Curl_trc_is_verbose(data)` BEFORE formatting anything
/// (`lib/curl_trc.h:138-142`). The successor of that macro is
/// [`crate::trace`], which is not among this file's declared dependencies, so
/// the sink is injected -- the same shape [`psl`] uses for its list source,
/// [`netrc`] for its home directory and `altsvc.rs` for its own four
/// messages.
///
/// The argument is [`fmt::Arguments`] precisely so that the C's ordering
/// survives: nothing is formatted unless an implementation chooses to look at
/// it, so a transfer that is not verbose pays for no message here either.
///
/// The strings are reproduced verbatim because `--verbose` output is
/// observable behaviour and AAP 0.8.1 freezes it. Two of them are compared by
/// a fixture: `tests/data/test1105` expects `Restricted outgoing cookies due
/// to header size` and `tests/data/test1160` the oversize report, so the
/// wording is not merely conventional.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Implemented by the transfer layer's trace bridge.
pub(crate) trait CookieLog {
    /// Emits one diagnostic line, or discards it.
    fn infof(&self, message: fmt::Arguments<'_>);
}

/// The sink that discards -- `lib/curl_trc.h:212-215`, the arm C compiles
/// when tracing is disabled entirely.
///
/// Zero-sized, so passing it costs nothing. `altsvc.rs` declares a sibling of
/// the same name for its own trait; the two are distinct paths and neither
/// may reach for the other, because `altsvc` is gated on a different
/// capability than this file's engine.
#[cfg(feature = "cookies")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // Passed by a caller that is not tracing.
pub(crate) struct NoLog;

#[cfg(feature = "cookies")]
impl CookieLog for NoLog {
    fn infof(&self, _message: fmt::Arguments<'_>) {}
}

/// A byte span as text, for a diagnostic only.
///
/// The C prints cookie names, values and domains with `%s`, and those are raw
/// bytes that no part of this module requires to be valid text. The one place
/// they have to become text substitutes the replacement character for each
/// invalid sequence, exactly as [`String::from_utf8_lossy`] does.
///
/// This affects a diagnostic and nothing else: no stored byte, no byte
/// written to the jar and no byte on the wire passes through here.
#[cfg(feature = "cookies")]
struct Text<'a>(&'a [u8]);

#[cfg(feature = "cookies")]
impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&String::from_utf8_lossy(self.0))
    }
}

/// An optional byte span as text, printing `(nil)` for an absent one.
///
/// `lib/cookie.c:1029` hands `co->domain` and `co->path` to `infof` with
/// `%s`, and either can be a null pointer at that point -- a cookie set from
/// `CURLOPT_COOKIELIST` with no `Domain` attribute has both. glibc's printf
/// renders a null `%s` as `(nil)`, which is what a curl built against it
/// prints, so that is what this renders. It is a diagnostic only.
#[cfg(feature = "cookies")]
struct OptText<'a>(Option<&'a [u8]>);

#[cfg(feature = "cookies")]
impl fmt::Display for OptText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(bytes) => fmt::Display::fmt(&Text(bytes), f),
            None => f.write_str("(nil)"),
        }
    }
}

/// The header name a cookie file line may carry, and the 11 bytes both
/// readers skip past it.
///
/// `checkprefix("Set-Cookie:", lineptr)` at `lib/cookie.c:1123` is
/// case-INsensitive, and `lib/setopt.c`'s `cookielist()` uses the same
/// predicate. The two then differ, and the difference is preserved: the file
/// reader passes blanks afterwards (`:1126`) and `CURLOPT_COOKIELIST` does
/// not.
#[cfg(feature = "cookies")]
#[rustfmt::skip]
const SET_COOKIE_HEADER: &[u8] = b"Set-Cookie:";

/// `CURL_MAX_INPUT_LENGTH` -- `lib/urldata.h:131`.
///
/// The C's *"general protection against mistakes and abuse"* on a
/// `CURLOPT_COOKIELIST` string, applied in `lib/setopt.c`'s `cookielist()`
/// AFTER the four command words have been ruled out. Exposed here because
/// [`cookie_command`] is where that decision is made.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Applied by the option surface, which is later code.
pub(crate) const CURL_MAX_INPUT_LENGTH: usize = 8_000_000;

// ---------------------------------------------------------------------------
// `struct Cookie` -- `lib/cookie.h:30-45`.
// ---------------------------------------------------------------------------

/// One stored cookie.
///
/// The C's fields one for one, minus the two intrusive list nodes: `node` for
/// the bucket it lives in and `getnode` for the temporary list
/// `Curl_cookie_getlist` builds. Both disappear because a Rust collection
/// owns its elements rather than threading links through them, which is what
/// AAP 0.6.9 replaces the intrusive lists with. The `getnode` in particular
/// let the C put one cookie on two lists at once; [`CookieInfo::getlist`]
/// returns borrowed references instead, so nothing is threaded anywhere.
///
/// # `None` and empty are DIFFERENT, and the difference is observable
///
/// The C distinguishes a null `char *` from a pointer to `""` in three places
/// that a reader can see:
///
/// * A cookie with **no domain** is skipped entirely by the jar writer
///   (`:1508-1509`) and by `CURLINFO_COOKIELIST` (`:1573-1574`); a cookie
///   with an EMPTY domain is written, as the empty field 0 of a jar line.
/// * A cookie with **no path** matches every request path
///   (`if(!co->path || pathmatch(...))` at `:1298`) and sorts as length zero;
///   a cookie with the path `"/"` matches every path too but sorts as length
///   one, which changes the order of the `Cookie:` header.
/// * A cookie with **no value** is skipped by the header writer
///   (`lib/http.c:2551`); a cookie with an EMPTY value is sent as
///   `name=`. `tests/data/test46` requires exactly that: `Cookie: empty=;`.
///
/// So `value`, `path` and `domain` are `Option<Vec<u8>>` and `strstore`'s rule
/// -- a zero length stores `""`, not a null pointer (`:265-268`) -- is
/// reproduced where the C applies it and nowhere else.
///
/// `name` is not optional. `parse_cookie_header` refuses an empty one
/// (`:474`) and `parse_netscape` cannot reach seven fields without assigning
/// it, so the C's `co->name ? strlen(co->name) : 0` in `cookie_sort` (`:1200`)
/// is defensive rather than reachable -- and `get_netscape_format` prints it
/// with no fallback at all (`:1451`), which would be undefined if it could be
/// null. An EMPTY name is reachable, from a jar line whose field 5 is empty,
/// and is stored as such.
#[cfg(feature = "cookies")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Cookie {
    /// `char *name` -- *"`<this>` = value"*.
    name: Vec<u8>,
    /// `char *value` -- *"name = `<this>`"*.
    value: Option<Vec<u8>>,
    /// `char *path` -- *"canonical path"*, already through
    /// [`sanitize_cookie_path`] by the time it is stored.
    path: Option<Vec<u8>>,
    /// `char *domain` -- *"domain = `<this>`"*, with any single leading dot
    /// already stripped.
    domain: Option<Vec<u8>>,
    /// `curl_off_t expires` -- seconds since the epoch, **and `0` means a
    /// session cookie** rather than the epoch itself. `parse_cookie_header`
    /// bumps a genuine epoch expiry to 1 for exactly that reason (`:625`).
    expires: CurlOffT,
    /// `unsigned int creationtime` -- *"time when the cookie was written"*,
    /// which is a monotonically increasing counter and not a clock reading:
    /// `co->creationtime = ++ci->lastct` at `:988`. It is the fourth
    /// tiebreaker of the `Cookie:` header order and the sole key of the jar's
    /// order, and **a replacement inherits the old value** (`:914`).
    creationtime: u32,
    /// `BIT(tailmatch)` -- *"tail-match the domain name"*. Set when a
    /// `Domain` attribute named a non-ipnum domain, and field 1 of a jar
    /// line.
    tailmatch: bool,
    /// `BIT(secure)` -- *"the `secure` keyword was used"*.
    secure: bool,
    /// `BIT(livecookie)` -- *"updated from server, not a stored file"*, which
    /// is `ci->running` at the moment of the add (`:987`). A cookie read from
    /// a file never replaces a live one (`:896-904`).
    livecookie: bool,
    /// `BIT(httponly)` -- *"the httponly directive is present"*. Written as
    /// the `#HttpOnly_` prefix on field 0.
    httponly: bool,
    /// `BIT(prefix_secure)` -- the name began `__Secure-`.
    prefix_secure: bool,
    /// `BIT(prefix_host)` -- the name began `__Host-`.
    prefix_host: bool,
}

#[cfg(feature = "cookies")]
#[allow(dead_code)] // The option and transfer surfaces are later code.
impl Cookie {
    /// The cookie's name, never absent and possibly empty.
    pub(crate) fn name(&self) -> &[u8] {
        &self.name
    }

    /// The cookie's value, absent when no `=` value was ever stored.
    pub(crate) fn value(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }

    /// The cookie's canonical path, absent when neither a `Path` attribute
    /// nor a default request path was available.
    pub(crate) fn path(&self) -> Option<&[u8]> {
        self.path.as_deref()
    }

    /// The cookie's domain, absent when neither a `Domain` attribute nor a
    /// default host was available.
    pub(crate) fn domain(&self) -> Option<&[u8]> {
        self.domain.as_deref()
    }

    /// Seconds since the epoch, or `0` for a session cookie.
    pub(crate) fn expires(&self) -> CurlOffT {
        self.expires
    }

    /// The insertion counter this cookie was stamped with.
    pub(crate) fn creationtime(&self) -> u32 {
        self.creationtime
    }

    /// Whether the domain tail-matches rather than matching exactly.
    pub(crate) fn tailmatch(&self) -> bool {
        self.tailmatch
    }

    /// Whether the cookie may be sent only over a secure context.
    pub(crate) fn secure(&self) -> bool {
        self.secure
    }

    /// Whether the cookie arrived in a response header rather than a file.
    pub(crate) fn livecookie(&self) -> bool {
        self.livecookie
    }

    /// Whether the `HttpOnly` attribute was present.
    pub(crate) fn httponly(&self) -> bool {
        self.httponly
    }

    /// Whether the name carries the `__Secure-` prefix.
    #[allow(dead_code)] // Read by the option surface, which is later code.
    pub(crate) fn prefix_secure(&self) -> bool {
        self.prefix_secure
    }

    /// Whether the name carries the `__Host-` prefix.
    #[allow(dead_code)] // Read by the option surface, which is later code.
    pub(crate) fn prefix_host(&self) -> bool {
        self.prefix_host
    }

    /// The length `cookie_sort` gives this cookie's path -- zero when there
    /// is none (`lib/cookie.c:1194-1195`).
    fn path_len(&self) -> usize {
        self.path.as_ref().map_or(0, Vec::len)
    }

    /// The length `cookie_sort` gives this cookie's domain
    /// (`lib/cookie.c:1201-1202`).
    fn domain_len(&self) -> usize {
        self.domain.as_ref().map_or(0, Vec::len)
    }
}

// ---------------------------------------------------------------------------
// The helper functions of `lib/cookie.c`, in the order the C declares them.
// ---------------------------------------------------------------------------

/// Caps an expiry at 400 days into the future -- `cap_expires`
/// (`lib/cookie.c:52-61`).
///
/// ```text
/// if(co->expires && (TIME_T_MAX - COOKIES_MAXAGE - 30) > now) {
///   timediff_t cap = now + COOKIES_MAXAGE;
///   if(co->expires > cap) {
///     cap += 30;
///     co->expires = (cap / 60) * 60;
///   }
/// }
/// ```
///
/// The ceiling is *from RFC6265bis draft-19*, and the C states why the result
/// is rounded: *"For the sake of easier testing, align the capped time to an
/// even 60 second boundary."* The `+30` before the truncating division is what
/// makes that alignment round to the NEAREST minute rather than down, so a
/// fixture can assert a stable value whatever second it runs in --
/// `tests/data/test31` and `test46` both use the harness's `%days[400]`
/// substitution and depend on it.
///
/// Three details are easy to lose and each one is reproduced deliberately:
///
/// * A session cookie is exempt. `co->expires && ...` leaves `0` alone, so
///   capping never turns a session cookie into a dated one.
/// * The guard subtracts BOTH the age and the 30, so it fails a whole minute
///   before overflow rather than at it. Reproduced as written.
/// * The `+30` is added to `cap`, not to `co->expires`, and only inside the
///   branch that is about to overwrite the expiry. So the cap actually applied
///   is `((now + COOKIES_MAXAGE + 30) / 60) * 60`, which can exceed
///   `now + COOKIES_MAXAGE` by up to 29 seconds.
///
/// The arithmetic is `saturating` throughout. The guard already excludes
/// overflow on these targets, so saturation is unreachable rather than a
/// behaviour change -- it is there because a signed overflow is a panic in a
/// debug build, and a panic in this file could unwind into a C caller.
#[cfg(feature = "cookies")]
fn cap_expires(now: CurlOffT, expires: &mut CurlOffT) {
    // `:54` -- `co->expires &&` first, so a session cookie is untouched.
    if *expires == 0 {
        return;
    }

    // `:54` -- `(TIME_T_MAX - COOKIES_MAXAGE - 30) > now`. TIME_T_MAX and
    // CURL_OFF_T_MAX are the same value on all four mandated targets.
    let headroom = CURL_OFF_T_MAX
        .saturating_sub(COOKIES_MAXAGE)
        .saturating_sub(30);
    if headroom <= now {
        return;
    }

    // `:55` -- `timediff_t cap = now + COOKIES_MAXAGE;`
    let mut cap = now.saturating_add(COOKIES_MAXAGE);

    // `:56`
    if *expires > cap {
        // `:57-58` -- the 30 lands on `cap`, then the truncating division.
        cap = cap.saturating_add(30);
        *expires = (cap / 60).saturating_mul(60);
    }
}

/// Whether `cookie_domain` tail-matches `hostname` -- `cookie_tailmatch`
/// (`lib/cookie.c:73-100`).
///
/// The C cites RFC 6265 4.1.2.3: *"For example, if the value of the Domain
/// attribute is `example.com`, the user agent will include the cookie in the
/// Cookie header when making HTTP requests to example.com, www.example.com,
/// and www.corp.example.com."*
///
/// Three conditions, in the C's order:
///
/// 1. The host must be at least as long as the domain (`:80-81`).
/// 2. The host's tail must equal the domain, **case-insensitively** (`:83-86`)
///    -- `curl_strnequal`, which is why `WWW.EXAMPLE.COM` matches
///    `example.com`.
/// 3. Either the lengths are equal, or the byte immediately before the tail is
///    a dot (`:95-98`). That last clause is what stops `evilexample.com`
///    matching `example.com` while allowing `www.example.com` to.
///
/// The stored domain never carries a leading dot -- both parsers strip one --
/// so condition 3 is not defeated by a `.example.com` spelling.
///
/// The byte before the tail is reached as the last byte of the head rather
/// than by indexing `at - 1`, so no subtraction appears here and the check is
/// total for every possible split point.
#[cfg(feature = "cookies")]
fn cookie_tailmatch(cookie_domain: &[u8], hostname: &[u8]) -> bool {
    // `:80-81`
    let Some(at) = hostname.len().checked_sub(cookie_domain.len()) else {
        return false;
    };

    // `:83-86` -- `curl_strnequal(cookie_domain, hostname + hostname_len -
    // cookie_domain_len, cookie_domain_len)`.
    let Some(tail) = hostname.get(at..) else {
        return false;
    };
    if !ncasecompare(cookie_domain, tail, cookie_domain.len()) {
        return false;
    }

    // `:95-96`
    if at == 0 {
        return true;
    }

    // `:97-98` -- `'.' == *(hostname + hostname_len - cookie_domain_len - 1)`
    hostname.get(..at).and_then(<[u8]>::last) == Some(&b'.')
}

/// Whether `cookie_path` matches `uri_path` -- `pathmatch`
/// (`lib/cookie.c:106-156`), *"RFC6265 5.1.4 Paths and Path-Match"*.
///
/// The C deviates from the RFC on purpose and says so at `:126-134`: the
/// algorithm would truncate the URI path at its last `/`, but *"URL path
/// /hoge?fuga=xxx means /hoge/index.cgi?fuga=xxx in some site without
/// redirect. Ignore this algorithm because /hoge is uri path for this case"*.
/// The truncation is therefore NOT performed here either.
///
/// * A cookie path of exactly one byte matches everything (`:112-116`). The
///   C's comment says *"cookie_path must be `/`"*, and a stored path always
///   is, because [`sanitize_cookie_path`] refuses anything that does not start
///   with one.
/// * An empty URI path, or one that does not begin with `/`, is treated as
///   `"/"` (`:118-119`). Fragments are already gone: *"#-fragments are already
///   cut off!"*
/// * A URI path shorter than the cookie path cannot match (`:138-139`).
/// * The prefix comparison is **case-SENSITIVE**, and the C comments the
///   reason on the line itself: *"not using checkprefix() because matching
///   should be case-sensitive"* (`:141-142`). `tests/data/test8` depends on
///   it: a cookie for `/WE` is not sent for `/we/want/8`.
/// * Equal lengths match (`:145-148`); otherwise the URI path must have a `/`
///   at the cookie path's length, so `/login` matches `/login/en` but not
///   `/loginhelper` (`:151-154`).
#[cfg(feature = "cookies")]
fn pathmatch(cookie_path: &[u8], uri_path: &[u8]) -> bool {
    // `:112-116`
    if cookie_path.len() == 1 {
        return true;
    }

    // `:118-119`
    let uri_path = if uri_path.is_empty() || uri_path.first() != Some(&b'/') {
        ROOT_PATH
    } else {
        uri_path
    };

    // `:138-139`
    if uri_path.len() < cookie_path.len() {
        return false;
    }

    // `:141-142` -- `strncmp`, case-sensitive, over `cookie_path_len` bytes.
    if !uri_path.starts_with(cookie_path) {
        return false;
    }

    // `:145-148`
    if cookie_path.len() == uri_path.len() {
        return true;
    }

    // `:151-154` -- `uri_path[cookie_path_len] == '/'`. The index is known to
    // be inside the slice by the length test above, but it is still reached
    // through `get` so that no arithmetic here can ever be the reason this
    // file panics.
    uri_path.get(cookie_path.len()) == Some(&b'/')
}

/// The last two labels of `domain` -- `get_top_domain`
/// (`lib/cookie.c:161-180`), *"Return the top-level domain, for optimal
/// hashing."*
///
/// Two backward searches for a dot: the last one, then the last one before
/// that. The span returned starts one byte after the second dot, so
/// `www.corp.example.com` yields `example.com` and `example.com` yields
/// itself. A domain with no dot at all, or with exactly one, is returned
/// whole.
///
/// **Used only for hashing.** No matching decision consults it, so the fact
/// that it collapses `a.example.com` and `b.example.com` onto one bucket is
/// the point rather than a loss of precision.
///
/// `memchr::memrchr` is [`crate::util::memrchr`], the successor of the C's
/// own `memrchr` fallback at `lib/curl_memrchr.c`.
#[cfg(feature = "cookies")]
fn get_top_domain(domain: &[u8]) -> &[u8] {
    // `:169` -- `last = memrchr(domain, '.', len);`
    let Some(last) = memrchr(b'.', domain) else {
        return domain;
    };

    // `:171` -- `first = memrchr(domain, '.', (last - domain));`, which
    // searches the bytes STRICTLY BEFORE the dot just found.
    let Some(head) = domain.get(..last) else {
        return domain;
    };
    let Some(first) = memrchr(b'.', head) else {
        return domain;
    };

    // `:173` -- `len -= (++first - domain);`, so the span begins one byte
    // past the second dot. `first + 1` cannot exceed the length: `first` is
    // an index into `head`, which is shorter than `domain`.
    domain.get(first + 1..).unwrap_or(domain)
}

/// A case-insensitive hash of a domain -- `cookie_hash_domain`
/// (`lib/cookie.c:190-202`).
///
/// ```text
/// size_t h = 5381;
/// while(domain < end) {
///   size_t j = (size_t)Curl_raw_toupper(*domain++);
///   h += h << 5;
///   h ^= j;
/// }
/// return (h % COOKIE_HASH_SIZE);
/// ```
///
/// **This is `cookie.c`'s own hash and it is NOT [`crate::util::hash`]'s
/// `hash_str`.** The two differ in two ways that both matter: this one folds
/// case to UPPER before mixing, and it XORs the byte in where the other adds
/// it. Substituting the shared helper would put every cookie in a different
/// bucket, which would reorder `CURLINFO_COOKIELIST` -- an output a fixture
/// compares. So it is implemented here, privately, and `crate::util::hash` is
/// a context-only dependency of this file.
///
/// `h` is `size_t` in the C, which is 64 bits on all four mandated targets, so
/// the accumulator is `u64` here. The C's `h += h << 5` overflows silently and
/// is expected to; `wrapping_shl`-free `wrapping_add` and `wrapping_shl` say
/// so explicitly, because a debug build would otherwise panic on the same
/// input a release build hashes happily.
///
/// The upper-case fold is [`crate::util::strcase::raw_toupper`], the
/// successor of `Curl_raw_toupper` the C calls here; it folds the 26 ASCII
/// letters and nothing else, whatever the locale.
#[cfg(feature = "cookies")]
fn cookie_hash_domain(domain: &[u8]) -> usize {
    let mut h: u64 = 5381;
    for &byte in domain {
        // `:196` -- the fold happens BEFORE the mix, on the byte, and it is
        // ASCII-only.
        let folded = u64::from(raw_toupper(byte));
        // `:197-198` -- `h += h << 5; h ^= j;`
        h = h.wrapping_add(h.wrapping_shl(5));
        h ^= folded;
    }

    // `:201` -- the modulus is by the bucket count, and the count is not a
    // power of two, so no mask can stand in for it.
    //
    // The conversion cannot lose information: the remainder is below 63.
    (h % COOKIE_HASH_SIZE as u64) as usize
}

/// The bucket a domain belongs to -- `cookiehash` (`lib/cookie.c:211-221`).
///
/// ```text
/// if(!domain || Curl_host_is_ipnum(domain))
///   return 0;
/// top = get_top_domain(domain, &len);
/// return cookie_hash_domain(top, len);
/// ```
///
/// **Every ipnum-shaped domain lands in bucket 0, and so does every cookie
/// with no domain at all.** That is not a degenerate case to be improved: it
/// is what makes a lookup by host work, because a request to `127.0.0.1`
/// hashes to bucket 0 too and would otherwise never find its own cookies.
/// [`host_is_ipnum`] records why the strictness of curl's `pton4` is
/// load-bearing here.
#[cfg(feature = "cookies")]
fn cookiehash(domain: Option<&[u8]>) -> usize {
    // `:217-218`
    let Some(domain) = domain else {
        return 0;
    };
    if host_is_ipnum(domain) {
        return 0;
    }

    // `:220`
    cookie_hash_domain(get_top_domain(domain))
}

/// Canonicalises a cookie path -- `sanitize_cookie_path`
/// (`lib/cookie.c:226-248`).
///
/// Four steps, in the C's order:
///
/// 1. *"some sites send path attribute within `\"`"* -- one leading quote is
///    dropped, and then one trailing quote (`:229-235`). The trailing quote is
///    only looked for when the leading one was found, so `/a"` keeps its
///    quote. `tests/data/test8` exercises the quoted form:
///    `path="/silly/"` becomes `/silly`.
/// 2. *"RFC6265 5.2.4 The Path Attribute"* -- an empty path, or one that does
///    not begin with `/`, becomes the default path `"/"` (`:238-240`).
/// 3. *"remove trailing slash when path is non-empty ... convert /hoge/ to
///    /hoge"* -- exactly ONE trailing slash, and only when more than one byte
///    remains (`:242-245`), so `"/"` survives.
/// 4. The result is copied, which here is simply an owned `Vec`.
#[cfg(feature = "cookies")]
fn sanitize_cookie_path(cookie_path: &[u8]) -> Vec<u8> {
    let mut path = cookie_path;

    // `:229-235`
    if path.first() == Some(&b'"') {
        path = path.get(1..).unwrap_or(&[]);
        if path.last() == Some(&b'"') {
            path = path.get(..path.len() - 1).unwrap_or(&[]);
        }
    }

    // `:238-240`
    if path.is_empty() || path.first() != Some(&b'/') {
        return ROOT_PATH.to_vec();
    }

    // `:242-245`
    if path.len() > 1 && path.last() == Some(&b'/') {
        path = path.get(..path.len() - 1).unwrap_or(&[]);
    }

    path.to_vec()
}

/// Whether a span holds a byte no cookie name or value may carry --
/// `invalid_octets` (`lib/cookie.c:354-365`).
///
/// The C quotes RFC 6265 section 4.1.1's permitted range and then declines to
/// enforce it:
///
/// ```text
/// cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
/// ```
///
/// *"But Firefox and Chrome as of June 2022 accept space, comma and
/// double-quotes fine. The prime reason for filtering out control bytes is
/// that some HTTP servers return 400 for requests that contain such."* So
/// what is actually rejected is `\x01` through `\x1f` **except `\x09` (TAB)**,
/// plus `\x7f`, and **space, comma and double-quote are accepted**. Every
/// byte at or above `\x80` is accepted too, which `tests/data/test31` relies
/// on: it sets a cookie whose name and value are both non-UTF-8 and requires
/// them in the saved jar.
///
/// The C's loop is `while(len && *p)`, so a zero byte ends the scan and any
/// byte after it goes unexamined. Every span reaching here has already been
/// through [`c_string`], so there is no zero to stop at and the two agree.
///
/// TAB being accepted here is why the value gets a SEPARATE rejection at
/// `:493-497`; the name needs none, because a TAB terminates a name.
#[cfg(feature = "cookies")]
fn invalid_octets(span: &[u8]) -> bool {
    span.iter().any(|&byte| {
        // `:361` -- `((*p != 9) && (*p < 0x20)) || (*p == 0x7f)`
        (byte != 9 && byte < 0x20) || byte == 0x7f
    })
}

/// Whether a domain is one no cookie may be set for without a public-suffix
/// list -- `bad_domain` (`lib/cookie.c:327-342`). **Returns `true` for BAD.**
///
/// ```text
/// if((len == 9) && curl_strnequal(domain, "localhost", 9))
///   return FALSE;
/// else {
///   const char *dot = memchr(domain, '.', len);
///   if(dot) {
///     size_t i = dot - domain;
///     if((len - i) > 1)
///       return FALSE;
///   }
/// }
/// return TRUE;
/// ```
///
/// **`#ifndef USE_LIBPSL` only.** The C's comment states the purpose:
/// *"Without PSL we do not know when the incoming cookie is set on a TLD or
/// otherwise `protected` suffix. To reduce risk, we require a dot OR the exact
/// hostname being `localhost`."* So this is the no-list arm's whole defence,
/// and `docs/HTTP-COOKIES.md` is candid about how thin it is: without a list
/// curl *"has no ability to stop super cookies"*.
///
/// Two measured details:
///
/// * The dot found is the FIRST one, and *"that dot must not be a trailing
///   dot"* -- so `example.` is bad while `.example` would be good if the
///   caller had not already stripped its leading dot. `example..tld` is good,
///   which `tests/data/test46` depends on.
/// * The `localhost` test is exact and length-gated, so `localhost.` and
///   `mylocalhost` both fall through to the dot rule.
///
/// [`is_public_suffix`] decides at run time which of the two C arms applies;
/// see there for the mapping.
#[cfg(feature = "cookies")]
fn bad_domain(domain: &[u8]) -> bool {
    // `:330-331` -- exact length nine, folded case.
    if domain.len() == 9 && ncasecompare(domain, b"localhost", 9) {
        return false;
    }

    // `:334-340`
    if let Some(dot) = domain.iter().position(|&byte| byte == b'.') {
        // `(len - i) > 1` -- there is at least one byte after the dot.
        if domain.len().saturating_sub(dot) > 1 {
            return false;
        }
    }

    true
}

// ---------------------------------------------------------------------------
// `struct CookieInfo` -- `lib/cookie.h:56-64`. The jar.
// ---------------------------------------------------------------------------

/// The cookie store.
///
/// The C's fields one for one, with `struct Curl_llist cookielist[63]`
/// becoming an array of [`VecDeque`] of the same length.
///
/// # It is an ARRAY, and it must never become a map
///
/// `cookie_list` (`lib/cookie.c:1568-1590`) backs `CURLINFO_COOKIELIST` by
/// walking the buckets in index order and, within each, in insertion order,
/// emitting one formatted line per cookie **without sorting anything**. So the
/// order of that list is a function of the bucket count, of
/// [`cookie_hash_domain`], and of the order cookies arrived in -- all three of
/// which are reproduced exactly. A [`std::collections::HashMap`] keyed by
/// domain would iterate in an order randomised per process and would change
/// that output run to run; `HashMap::retain` additionally has the opposite
/// polarity to the C's removal predicates. Neither substitution is available
/// here.
///
/// [`VecDeque`] rather than [`Vec`] is the shape [`crate::util::llist`]
/// supersedes `Curl_llist` with, and its helpers are used for the removals so
/// that the C's disposal ORDER is explicit at the call site rather than
/// inherited from drop glue.
///
/// # Locking
///
/// Every method that takes `&mut self` requires `CURL_LOCK_DATA_COOKIE` with
/// `CURL_LOCK_ACCESS_SINGLE`; see the module header for the full transition
/// contract that `crate::share` is to implement.
#[cfg(feature = "cookies")]
#[derive(Debug)]
pub(crate) struct CookieInfo {
    /// `struct Curl_llist cookielist[COOKIE_HASH_SIZE]` -- *"linked lists of
    /// cookies we know of"*.
    cookielist: Vec<VecDeque<Cookie>>,
    /// `curl_off_t next_expiration` -- *"the next time at which expiration
    /// happens"*, and [`CURL_OFF_T_MAX`] for *"we do not have enough
    /// information yet"* (`lib/cookie.c:1073-1077`).
    next_expiration: CurlOffT,
    /// `unsigned int numcookies` -- *"number of cookies in the jar"*. It
    /// counts cookies with and without a domain alike, and the jar writer
    /// sizes its array from it before filtering (`:1499`), so it is an upper
    /// bound there rather than the number of lines written.
    numcookies: u32,
    /// `unsigned int lastct` -- *"last creation-time used in the jar"*. A
    /// counter, not a clock.
    lastct: u32,
    /// `BIT(running)` -- *"state info, for cookie adding information"*.
    /// `false` while a file is being read and `true` once a transfer has
    /// begun. It is read by BOTH parsers' `secure` gates, with opposite
    /// polarity; see [`parse_cookie_header`] and [`parse_netscape`].
    running: bool,
    /// `BIT(newsession)` -- *"new session, discard session cookies on load"*,
    /// which is `CURLOPT_COOKIESESSION` and `--junk-session-cookies`.
    newsession: bool,
}

#[cfg(feature = "cookies")]
#[allow(dead_code)] // Constructed by the option surface, which is later code.
impl Default for CookieInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "cookies")]
#[allow(dead_code)] // The option surface and easy-handle teardown come later.
impl CookieInfo {
    /// A new, empty store -- `Curl_cookie_init` (`lib/cookie.c:1061-1079`).
    ///
    /// The C allocates with `calloc`, initialises all 63 lists with a NULL
    /// destructor, and sets `next_expiration` to `CURL_OFF_T_MAX`. Its comment
    /// explains the NULL destructor: *"This does not use the destructor
    /// callback since we want to add and remove to lists while keeping the
    /// cookie struct intact"* -- a concern that does not survive the
    /// translation, because a Rust collection owns its elements and a cookie
    /// moved out of one is not freed by the move.
    ///
    /// The C returns NULL on out of memory, which has no counterpart: an
    /// allocation failure aborts in Rust, and the option surface that calls
    /// this is the layer that maps a construction failure to
    /// `CURLE_OUT_OF_MEMORY` in the C.
    pub(crate) fn new() -> Self {
        Self {
            // `:1071-1072` -- all 63, in order. `vec!` rather than an array
            // literal because `[T; 63]: Default` is not implemented for a
            // non-`Copy` T at this crate's minimum supported Rust version,
            // and the length is fixed by construction below.
            cookielist: (0..COOKIE_HASH_SIZE)
                .map(|_| VecDeque::new())
                .collect(),
            // `:1077`
            next_expiration: CURL_OFF_T_MAX,
            numcookies: 0,
            lastct: 0,
            running: false,
            newsession: false,
        }
    }

    /// The number of cookies held, with or without a domain -- `numcookies`.
    pub(crate) fn numcookies(&self) -> u32 {
        self.numcookies
    }

    /// The counter the next cookie will be stamped from -- `lastct`.
    pub(crate) fn lastct(&self) -> u32 {
        self.lastct
    }

    /// The earliest future expiry known, or [`CURL_OFF_T_MAX`] when none is.
    pub(crate) fn next_expiration(&self) -> CurlOffT {
        self.next_expiration
    }

    /// Whether a transfer has begun -- `running`.
    pub(crate) fn running(&self) -> bool {
        self.running
    }

    /// Whether session cookies are to be discarded on load -- `newsession`,
    /// which is `CURLOPT_COOKIESESSION`.
    pub(crate) fn newsession(&self) -> bool {
        self.newsession
    }

    /// Sets the `newsession` flag.
    ///
    /// The C writes it inside `cookie_load` from the argument
    /// `data->set.cookiesession` (`lib/cookie.c:1099`), so a store loaded
    /// with no file never has it set. [`Self::load`] does the same; this
    /// setter exists for the option surface, which must be able to record
    /// `CURLOPT_COOKIESESSION` before any file is named.
    pub(crate) fn set_newsession(&mut self, newsession: bool) {
        self.newsession = newsession;
    }

    /// Marks the store as running -- `Curl_cookie_run`
    /// (`lib/cookie.c:1630-1636`).
    ///
    /// The C's whole body, inside the cookie lock, is
    /// `if(data->cookies) data->cookies->running = TRUE;`. From here on a
    /// `secure` cookie arriving in a header requires a secure context, and a
    /// `secure` cookie arriving from a file is accepted -- the inversion the
    /// two parsers document.
    pub(crate) fn run(&mut self) {
        self.running = true;
    }

    /// Every cookie held, in bucket order and then insertion order.
    ///
    /// The traversal `cookie_list` and the jar writer both perform. Exposed so
    /// that `crate::share` and the option surface can enumerate the store
    /// without this module handing out its buckets.
    pub(crate) fn cookies(&self) -> impl Iterator<Item = &Cookie> + '_ {
        self.cookielist.iter().flatten()
    }

    /// Drops every cookie -- `Curl_cookie_clearall` (`lib/cookie.c:1361-1377`).
    ///
    /// All 63 buckets, and `numcookies` back to zero. `next_expiration` is
    /// **not** reset, which is the C's behaviour and not an oversight: the
    /// field is a lower bound on when a scan becomes worthwhile, and leaving
    /// it where it was only ever costs one unnecessary scan of an empty store.
    ///
    /// [`llist::dispose_tail_first`] rather than [`VecDeque::clear`] because
    /// the C disposes through `Curl_node_remove` in list order and the helper
    /// is where that distinction is recorded; no cookie's destructor observes
    /// the difference, since a `Cookie` owns nothing but its own buffers.
    pub(crate) fn clearall(&mut self) {
        // `:1364-1374`
        for bucket in &mut self.cookielist {
            llist::dispose_tail_first(bucket);
        }
        // `:1375`
        self.numcookies = 0;
    }

    /// Drops every session cookie -- `Curl_cookie_clearsess`
    /// (`lib/cookie.c:1384-1405`).
    ///
    /// A session cookie is one with `expires == 0`, and the count is
    /// decremented per removal rather than recomputed. The C walks with a
    /// look-ahead pointer *"in case the node is removed, get it early"*; here
    /// the walk runs backwards over indices instead, which needs no
    /// look-ahead because removing at a higher index cannot disturb a lower
    /// one.
    pub(crate) fn clearsess(&mut self) {
        for bucket in &mut self.cookielist {
            // `:1391-1403`
            let mut index = bucket.len();
            while index > 0 {
                index -= 1;
                // `:1397`
                let session =
                    bucket.get(index).is_some_and(|cookie| cookie.expires == 0);
                if session && llist::dispose(bucket, index) {
                    // `:1400`
                    self.numcookies = self.numcookies.saturating_sub(1);
                }
            }
        }
    }

    /// Tears the store down -- `Curl_cookie_cleanup`
    /// (`lib/cookie.c:1412-1417`).
    ///
    /// The C's body is `Curl_cookie_clearall(ci); free(ci);`. The free has no
    /// counterpart -- dropping the value is the free -- so what remains is the
    /// clear, and this method exists so that a caller holding the store behind
    /// a shared handle can empty it without dropping it. That is exactly the
    /// case `Curl_flush_cookies` distinguishes at `:1647`.
    pub(crate) fn cleanup(&mut self) {
        self.clearall();
    }

    /// Removes expired cookies -- `remove_expired` (`lib/cookie.c:281-323`).
    ///
    /// The C's own description: *"Remove expired cookies from the hash by
    /// inspecting the expires timestamp on each cookie in the hash, freeing
    /// and deleting any where the timestamp is in the past. If the cookiejar
    /// has recorded the next timestamp at which one or more cookies expire,
    /// then processing will exit early in case this timestamp is in the
    /// future."*
    ///
    /// Four details, each reproduced as written:
    ///
    /// * **The early exit.** `now < next_expiration && next_expiration !=
    ///   CURL_OFF_T_MAX` returns without scanning (`:295-297`). The second
    ///   conjunct is the C's *"safe fallback of checking all cookies"* when no
    ///   expiry has been recorded yet -- without it, a store whose sentinel is
    ///   still the maximum would never be scanned at all.
    /// * **The reset.** When the scan does run, `next_expiration` goes back to
    ///   the sentinel first and is rebuilt from what survives (`:299`).
    /// * **The comparison is strict.** `co->expires < now` (`:308`), so a
    ///   cookie expiring exactly now survives this pass.
    /// * **Session cookies are exempt.** The outer `if(co->expires)` (`:307`)
    ///   skips them, so they neither expire nor contribute to the next
    ///   deadline.
    ///
    /// The clock is the WALL clock -- the C's `time(NULL)` at `:284`.
    pub(crate) fn remove_expired(&mut self, clock: &dyn Clock) {
        // `:284`
        let now = clock.epoch_secs();

        // `:295-300`
        if now < self.next_expiration && self.next_expiration != CURL_OFF_T_MAX
        {
            return;
        }
        self.next_expiration = CURL_OFF_T_MAX;

        // `:301-322` -- all 63 buckets.
        let mut earliest = CURL_OFF_T_MAX;
        let mut dropped = 0u32;
        for bucket in &mut self.cookielist {
            let mut index = bucket.len();
            while index > 0 {
                index -= 1;
                let Some(cookie) = bucket.get(index) else {
                    continue;
                };
                // `:307`
                if cookie.expires == 0 {
                    continue;
                }
                if cookie.expires < now {
                    // `:309-311`
                    if llist::dispose(bucket, index) {
                        dropped = dropped.saturating_add(1);
                    }
                } else if cookie.expires < earliest {
                    // `:313-318` -- *"If this cookie has an expiration
                    // timestamp earlier than what we have seen so far then
                    // record it for the next round of expirations."*
                    earliest = cookie.expires;
                }
            }
        }

        self.numcookies = self.numcookies.saturating_sub(dropped);
        self.next_expiration = earliest;
    }
}

// ---------------------------------------------------------------------------
// The `Set-Cookie:` parser -- `lib/cookie.c:374-648`.
// ---------------------------------------------------------------------------

/// The four spans `parse_cookie_header` accumulates before committing any of
/// them -- `struct Curl_str cookie[COOKIE_PIECES]` (`lib/cookie.c:444`) with
/// the four indices of `:374-377`.
///
/// Named fields rather than an array, because the C's indices are only ever
/// used as literals and a named field cannot be confused for a neighbour. The
/// C's `memset` initialisation -- with the comment *"memset instead of
/// initializer because gcc 4.8.1 is silly"* -- becomes [`Default`].
///
/// Accumulating rather than assigning as it goes is what makes the attributes
/// LAST-WINS: `domain=a; domain=b` stores `b`, because the second assignment
/// simply overwrites the field. `tests/data/test8` and `test31` both send a
/// doubled `domain` attribute and depend on it.
#[cfg(feature = "cookies")]
#[derive(Clone, Copy, Debug, Default)]
struct CookiePieces<'a> {
    /// `cookie[COOKIE_NAME]`. Empty until the first `name=value` pair has been
    /// accepted, which is what marks that pair as the cookie itself.
    name: &'a [u8],
    /// `cookie[COOKIE_VALUE]`.
    value: &'a [u8],
    /// `cookie[COOKIE_DOMAIN]`, with any single leading dot already nudged
    /// off.
    domain: &'a [u8],
    /// `cookie[COOKIE_PATH]`, still raw -- [`sanitize_cookie_path`] runs in
    /// [`storecookie`], not here.
    path: &'a [u8],
}

/// Commits the four accumulated spans onto the cookie -- `storecookie`
/// (`lib/cookie.c:381-423`).
///
/// The name and the value are stored through the C's `strstore`, whose rule is
/// that **a zero length stores `""` rather than a null pointer**
/// (`:263-266`). So a `Set-Cookie: a=` yields an EMPTY value, not an absent
/// one, and is later sent as `a=`.
///
/// The path is the interesting one (`:388-407`):
///
/// * A non-empty `Path` attribute is used as given.
/// * Otherwise, if a request path was supplied, *"No path was given in the
///   header line, set the default"*: the request path truncated at its LAST
///   `/`, **including that slash** -- `plen = (endslash - path + 1)`. With no
///   slash anywhere, the whole path. So `/we/want/31` gives `/we/want/`, which
///   [`sanitize_cookie_path`] then shortens to `/we/want`. That is exactly
///   what `tests/data/test31` requires in the saved jar.
/// * With neither, `co->path` stays absent -- `if(path)` at `:401` guards the
///   store, and a cookie added through `CURLOPT_COOKIELIST` has no request
///   path at all.
///
/// The domain is the same shape: the attribute if it has one, else the default
/// host if there is one, else absent (`:409-419`).
///
/// The C returns `CURLE_OUT_OF_MEMORY` from every one of these stores. There
/// is no counterpart: a Rust allocation failure aborts rather than returning,
/// so this function cannot fail and does not pretend to.
#[cfg(feature = "cookies")]
fn storecookie(
    cookie: &mut Cookie,
    pieces: &CookiePieces<'_>,
    path: Option<&[u8]>,
    domain: Option<&[u8]>,
) {
    // `:384-387` -- `strstore` on both, so an empty span becomes an empty
    // string rather than nothing at all.
    cookie.name = pieces.name.to_vec();
    cookie.value = Some(pieces.value.to_vec());

    // `:388-407`
    let chosen_path: Option<&[u8]> = if !pieces.path.is_empty() {
        // `:391-393`
        Some(pieces.path)
    } else {
        // `:394-400` -- the default, truncated at the last slash INCLUSIVE.
        path.map(|request_path| {
            match memrchr(b'/', request_path) {
                // `:397-398` -- `plen = endslash - path + 1`.
                Some(endslash) => {
                    request_path.get(..endslash + 1).unwrap_or(request_path)
                }
                // `:400` -- `plen = strlen(path)`.
                None => request_path,
            }
        })
    };
    if let Some(raw) = chosen_path {
        // `:402`
        cookie.path = Some(sanitize_cookie_path(raw));
    }

    // `:409-419`
    if !pieces.domain.is_empty() {
        cookie.domain = Some(pieces.domain.to_vec());
    } else if let Some(default) = domain {
        // `:415-417` -- *"no domain was given in the header line, set the
        // default"*.
        cookie.domain = Some(default.to_vec());
    }
}

/// The inputs `Curl_cookie_add` carries besides the line itself.
///
/// The C passes them as five separate parameters (`lib/cookie.c:935-943`) plus
/// a read of `data->req.setcookies`. They are bundled because the successor of
/// `data` is not one object here -- the store, the clock, the diagnostic sink
/// and the public-suffix list are all injected separately -- and because
/// eleven parameters on one function is a lint failure under this workspace's
/// `too-many-arguments-threshold`.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Built by every caller of `CookieInfo::add`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AddContext<'a> {
    /// `bool httpheader` -- *"TRUE if HTTP header-style line"*. It selects the
    /// parser, and it is also the flag that makes the add count against
    /// [`MAX_SET_COOKIE_AMOUNT`] (`:1041-1042`).
    pub(crate) httpheader: bool,
    /// `bool noexpire` -- *"if TRUE, skip `remove_expired()`"*. Set only by
    /// the file reader, which runs one sweep after the whole file instead of
    /// one per line (`:1131`).
    pub(crate) noexpire: bool,
    /// `const char *domain` -- the default domain, which is the request host.
    /// `None` for a cookie added from a file or from `CURLOPT_COOKIELIST`,
    /// where there is no request.
    pub(crate) domain: Option<&'a [u8]>,
    /// `const char *path` -- *"full path used when this cookie is set, used to
    /// get default path for the cookie unless set"*.
    pub(crate) path: Option<&'a [u8]>,
    /// `bool secure` -- *"TRUE if connection is over secure origin"*, which is
    /// [`secure_context`] at the call site in `lib/http.c:3551`. Both file
    /// readers pass `TRUE` unconditionally (`:1131`, `lib/setopt.c:1617`).
    pub(crate) secure: bool,
    /// `data->req.setcookies` -- how many `Set-Cookie:` lines this response
    /// has already contributed. The counter lives on the request in the C, not
    /// on the store, because it resets per response; the caller owns it and
    /// increments it when this returns `Ok(true)` for a header line.
    pub(crate) setcookies: u32,
}

/// Parses one `Set-Cookie:` header value -- `parse_cookie_header`
/// (`lib/cookie.c:427-648`).
///
/// `true` means the C's `*okay`: the pieces were committed and the caller may
/// proceed. `false` is every one of the C's `return CURLE_OK` refusals, each of
/// which leaves nothing stored. The C additionally returns
/// `CURLE_OUT_OF_MEMORY` from `storecookie`; there is no counterpart, so there
/// is no error channel here.
///
/// # The pair loop
///
/// ```text
/// do {
///   if(!curlx_str_cspn(&ptr, &name, ";\t\r\n=")) {
///     curlx_str_trimblanks(&name);
///     if(!curlx_str_single(&ptr, '=')) {
///       sep = TRUE;
///       if(!curlx_str_cspn(&ptr, &val, ";\r\n")) curlx_str_trimblanks(&val);
///     }
///     ... dispatch on `name` ...
///   }
/// } while(!curlx_str_single(&ptr, ';'));
/// ```
///
/// `sep` records whether an `=` was consumed, which is how a stand-alone word
/// such as `secure` is told from an attribute with an empty value. The two
/// delimiter sets differ by one byte and the difference is load-bearing: see
/// [`NAME_DELIMITERS`].
///
/// # Preserved warts, each with its line
///
/// * `:447-449` -- a line longer than [`MAX_COOKIE_LINE`] is discarded
///   **silently**, with no diagnostic at all.
/// * `:501-503` -- the two reserved-prefix tests are **case-SENSITIVE** here
///   and case-INsensitive in [`parse_netscape`]. Deliberate; preserved.
/// * `:520` -- `if(secure || !ci->running)`. Note the negation, and compare
///   `parse_netscape`'s `:728`, which has `ci->running` with no negation. The
///   inversion is deliberate: a `secure` cookie may be stored from a FILE
///   whatever the connection is, and from a HEADER only over a secure context.
///   Both are reproduced verbatim and neither is harmonised.
/// * `:544-545` -- when [`bad_domain`] refuses the domain, the DEFAULT domain
///   is replaced by a `":"` sentinel rather than the cookie being dropped on
///   the spot. Nothing tail-matches a single colon, so the effect is a
///   refusal one step later -- and the sentinel PERSISTS for the rest of the
///   line, so a second `Domain` attribute is judged against it too.
/// * `:585` -- a `Max-Age` that is negative or otherwise unparsable sets the
///   expiry to `1`, which is the distant past, so the cookie is stored and
///   then swept. An unparsable `Expires` instead sets `0`, making it a SESSION
///   cookie. The two failures mean opposite things.
/// * `:604` -- the `Expires` branch is gated on `!co->expires`, so **`Max-Age`
///   WINS** whichever order they arrive in.
/// * `:568` -- the diagnostic prints the domain with `%s` from the value's
///   first byte, and the span is not terminated there, so a verbose curl
///   prints the REST OF THE HEADER LINE after it. Reproduced.
///
/// # Every unrecognised attribute is ignored, `SameSite` included
///
/// The dispatch chain ends without an `else`, so anything it does not
/// recognise falls out of the loop and is forgotten. `SameSite` is one of
/// those: `grep -rin samesite lib/` over curl 8.19.0-DEV returns **zero**
/// hits, so it is not implemented at all and must not be implemented here.
/// Honouring it would change which cookies are sent, which is a behaviour
/// change AAP 0.8.2 forbids outright.
#[cfg(feature = "cookies")]
fn parse_cookie_header(
    cookie: &mut Cookie,
    running: bool,
    line: &[u8],
    ctx: &AddContext<'_>,
    use_libpsl: bool,
    clock: &dyn Clock,
    log: &dyn CookieLog,
) -> bool {
    // `:443` -- `strlen(ptr)`, which stops at a zero byte, so the length test
    // and every scan below see the same string.
    let line = c_string(line);

    // `:446-448` -- *"discard overly long lines at once"*, and in silence.
    if line.len() > MAX_COOKIE_LINE {
        return false;
    }

    // `:444`, `:451`
    let mut pieces = CookiePieces::default();

    // `:441` -- the lazily read clock. Zero is the C's own sentinel for "not
    // read yet", reproduced rather than replaced by an `Option`, so that a
    // clock genuinely reading zero behaves as the C does.
    let mut now: CurlOffT = 0;

    // `:934-943` -- the default domain is a local because `:545` overwrites
    // it, and the overwrite has to persist across iterations.
    let mut domain = ctx.domain;

    let mut cursor: &[u8] = line;
    loop {
        // `:457`
        if let Ok(raw_name) = str_cspn(&mut cursor, NAME_DELIMITERS) {
            // `:459`
            let name = str_trimblanks(raw_name);

            // `:461-469`
            let mut sep = false;
            let mut value: &[u8] = &[];
            // The cursor as it stands where the value BEGINS -- just past the
            // `=` -- kept so that the `:568` diagnostic can reproduce the C's
            // `%s` overrun past the end of the span.
            let mut value_line: &[u8] = &[];
            if str_single(&mut cursor, b'=').is_ok() {
                sep = true;
                value_line = cursor;
                if let Ok(raw_value) = str_cspn(&mut cursor, VALUE_DELIMITERS) {
                    value = str_trimblanks(raw_value);
                }
            }

            if pieces.name.is_empty() {
                // `:471` -- *"The first name/value pair is the actual cookie
                // name"*.
                if !sep
                    || invalid_octets(name)
                    || invalid_octets(value)
                    || name.is_empty()
                {
                    // `:477-478`
                    log.infof(format_args!(
                        "invalid octets in name/value, cookie dropped"
                    ));
                    return false;
                }

                // `:481-491` -- *"Check for too long individual name or
                // contents, or too long combination of name + contents.
                // Chrome and Firefox support 4095 or 4096 bytes combo"*. Note
                // the asymmetry: each part is tested against `MAX_NAME - 1`
                // with `>=`, and the sum against `MAX_NAME` with `>`.
                if name.len() >= MAX_NAME - 1
                    || value.len() >= MAX_NAME - 1
                    || name.len().saturating_add(value.len()) > MAX_NAME
                {
                    log.infof(format_args!(
                        "oversized cookie dropped, name/val {} + {} bytes",
                        name.len(),
                        value.len()
                    ));
                    return false;
                }

                // `:493-497` -- *"Reject cookies with a TAB inside the
                // value"*. The name needs no such test because a TAB
                // terminates a name; the value reaches here with one because
                // its delimiter set has none. A value that is ONLY blanks and
                // tabs has already been trimmed to nothing, which is why
                // `tests/data/test8`'s `cookie9` survives.
                if value.contains(&b'\t') {
                    log.infof(format_args!("cookie contains TAB, dropping"));
                    return false;
                }

                // `:500-503` -- CASE-SENSITIVE, unlike the jar reader's.
                if name.starts_with(PREFIX_SECURE_NAME) {
                    cookie.prefix_secure = true;
                } else if name.starts_with(PREFIX_HOST_NAME) {
                    cookie.prefix_host = true;
                }

                // `:505-506`
                pieces.name = name;
                pieces.value = value;
            } else if !sep {
                // `:508-511` -- *"this is a `<name>` with no content"*.
                if str_casecompare(name, b"secure") {
                    // `:513-527`. *"secure cookies are only allowed to be set
                    // when the connection is using a secure protocol, or when
                    // the cookie is being set by reading from file"*. THE
                    // NEGATION IS DELIBERATE -- see the note on this function.
                    if ctx.secure || !running {
                        cookie.secure = true;
                    } else {
                        log.infof(format_args!(
                            "skipped cookie because not 'secure'"
                        ));
                        return false;
                    }
                } else if str_casecompare(name, b"httponly") {
                    // `:528-529`
                    cookie.httponly = true;
                }
            } else if str_casecompare(name, b"path") {
                // `:531-533` -- stored raw; sanitised in `storecookie`.
                pieces.path = value;
            } else if str_casecompare(name, b"domain") && !value.is_empty() {
                // `:534-573`
                if !parse_domain_attribute(
                    cookie,
                    &mut pieces,
                    &mut domain,
                    value,
                    value_line,
                    use_libpsl,
                    log,
                ) {
                    return false;
                }
            } else if str_casecompare(name, b"max-age") && !value.is_empty() {
                // `:574-601`
                parse_max_age(cookie, value, &mut now, clock);
            } else if str_casecompare(name, b"expires")
                && !value.is_empty()
                // `:604` -- *"Let max-age have priority."*
                && cookie.expires == 0
                && value.len() < MAX_DATE_LENGTH
            {
                // `:602-627`
                parse_expires(cookie, value, &mut now, clock);
            }
        }

        // `:629` -- `while(!curlx_str_single(&ptr, ';'))`.
        if str_single(&mut cursor, b';').is_err() {
            break;
        }
    }

    // `:631-637`
    if pieces.name.is_empty() {
        return false;
    }
    storecookie(cookie, &pieces, ctx.path, domain);
    true
}

/// The `Domain` attribute -- `lib/cookie.c:534-573`. `false` drops the cookie.
///
/// ```text
/// if('.' == *v) curlx_str_nudge(&val, 1);          /* ONE leading dot */
/// #ifndef USE_LIBPSL
///   if(bad_domain(...)) domain = ":";
/// #endif
/// is_ip = Curl_host_is_ipnum(domain ? domain : curlx_str(&val));
/// if(!domain ||
///    (is_ip && exact-equality(val, domain)) ||
///    (!is_ip && cookie_tailmatch(val, domain))) { accept }
/// else { infof("skipped cookie with bad tailmatch domain: %s", val); drop }
/// ```
///
/// Three readings that are easy to get wrong, so each is spelled out:
///
/// * **`is_ip` describes the HOST, not the cookie's domain**, whenever a
///   default domain exists. Only when there is none does it describe the
///   value. `tests/data/test8` turns on it: with host `127.0.0.1`, a
///   `domain=.0.0.1` is judged by exact equality rather than by tail match,
///   and fails.
/// * **`!domain` accepts anything.** A cookie added from a file or from
///   `CURLOPT_COOKIELIST` has no request host to be checked against, so its
///   `Domain` is taken as given. `CURLOPT_COOKIELIST`'s manual page warns
///   about exactly this.
/// * **`tailmatch` is set from `!is_ip`, not from whether the tail matched.**
///   The C's comment: *"we always do that if the domain name was given"*. So
///   an ipnum domain is stored with `tailmatch` FALSE and is written to the
///   jar without a leading dot.
///
/// The `USE_LIBPSL` arm is selected at run time from `use_libpsl`; see
/// [`is_public_suffix`] for the whole mapping.
#[cfg(feature = "cookies")]
fn parse_domain_attribute<'a>(
    cookie: &mut Cookie,
    pieces: &mut CookiePieces<'a>,
    domain: &mut Option<&'a [u8]>,
    value: &'a [u8],
    value_line: &[u8],
    use_libpsl: bool,
    log: &dyn CookieLog,
) -> bool {
    // `:542-543` -- ONE leading dot, through `curlx_str_nudge(&val, 1)`.
    let value = match value.first() {
        Some(&b'.') => value.get(1..).unwrap_or(&[]),
        _ => value,
    };

    // `:546-554` -- `#ifndef USE_LIBPSL` only. *"Without PSL we do not know
    // when the incoming cookie is set on a TLD or otherwise `protected`
    // suffix. To reduce risk, we require a dot OR the exact hostname being
    // `localhost`."* THE SENTINEL PERSISTS: `domain` is the caller's local,
    // and a later `Domain` attribute on the same line is judged against `":"`
    // too.
    if !use_libpsl && bad_domain(value) {
        *domain = Some(b":");
    }

    // `:556`
    let is_ip = host_is_ipnum(domain.unwrap_or(value));

    // `:558-563`
    let accepted = match *domain {
        None => true,
        Some(host) => {
            if is_ip {
                // `:559-560` -- `!strncmp(val, domain, val_len) && (val_len ==
                // strlen(domain))`, which is byte-exact, CASE-SENSITIVE
                // equality.
                value == host
            } else {
                // `:561-562`
                cookie_tailmatch(value, host)
            }
        }
    };

    if !accepted {
        // `:565-571`. The C hands `curlx_str(&val)` to `%s` and the span is
        // not terminated there, so what a verbose curl actually prints is the
        // value FOLLOWED BY THE REST OF THE HEADER LINE. Reproduced rather
        // than tidied: `--verbose` output is frozen behaviour. The leading
        // blanks `trimblanks` removed are skipped the same way it skipped
        // them, so the two start at the same byte.
        let lead = value_line
            .iter()
            .take_while(|&&byte| byte == b' ' || byte == b'\t')
            .count();
        let printed = value_line.get(lead..).unwrap_or(value_line);
        log.infof(format_args!(
            "skipped cookie with bad tailmatch domain: {}",
            Text(printed)
        ));
        return false;
    }

    // `:564`
    pieces.domain = value;
    // `:565-566` -- from `!is_ip`, NOT from the match.
    if !is_ip {
        cookie.tailmatch = true;
    }
    true
}

/// The `Max-Age` attribute -- `lib/cookie.c:574-601`.
///
/// The C quotes RFC 2109: *"Optional. The Max-Age attribute defines the
/// lifetime of the cookie, in seconds. The delta-seconds value is a decimal
/// non-negative integer. After delta-seconds seconds elapse, the client should
/// discard the cookie. A value of zero means the cookie should be discarded
/// immediately."*
///
/// ```text
/// if(*maxage == '\"') maxage++;                 /* ONE leading quote */
/// rc = curlx_str_number(&maxage, &co->expires, CURL_OFF_T_MAX);
/// if(!now) now = time(NULL);
/// switch(rc) {
///   case STRE_OVERFLOW: co->expires = CURL_OFF_T_MAX; break;
///   default:            co->expires = 1;              break;
///   case STRE_OK:
///     if(!co->expires)                      co->expires = 1;
///     else if(CURL_OFF_T_MAX - now < co->expires) co->expires = CURL_OFF_T_MAX;
///     else                                  co->expires += now;
/// }
/// cap_expires(now, co);
/// ```
///
/// Four things worth naming:
///
/// * **A parse failure means `1`, not a refusal.** `1` is one second after the
///   epoch, so the cookie is stored and then removed by the next
///   `remove_expired`. That is how `Max-Age: -1` and `Max-Age: banana` both
///   delete a cookie.
/// * `Max-Age: 0` also becomes `1`, because `0` is the session-cookie marker
///   and would otherwise make the cookie immortal for this session.
/// * Overflow saturates rather than failing.
/// * Only ONE leading quote is skipped, and no trailing quote is looked for --
///   `curlx_str_number` simply stops at it.
#[cfg(feature = "cookies")]
fn parse_max_age(
    cookie: &mut Cookie,
    value: &[u8],
    now: &mut CurlOffT,
    clock: &dyn Clock,
) {
    // `:585-586`
    let mut cursor = match value.first() {
        Some(&b'"') => value.get(1..).unwrap_or(&[]),
        _ => value,
    };

    // `:587`
    let parsed = str_number(&mut cursor, CURL_OFF_T_MAX);

    // `:588-589` -- the clock is read before the switch, whatever the outcome.
    if *now == 0 {
        *now = clock.epoch_secs();
    }

    // `:590-600`
    cookie.expires = match parsed {
        // `:591-594`
        Err(StrError::Overflow) => CURL_OFF_T_MAX,
        // `:595-597` -- *"negative or otherwise bad, expire"*.
        Err(_) => 1,
        // `:598-606`
        Ok(0) => 1,
        Ok(seconds) => {
            // The arithmetic is saturating rather than plain, for the reason
            // given on `cap_expires`: the C's `CURL_OFF_T_MAX - now` is signed
            // overflow -- undefined -- for a wall clock reading before the
            // epoch, and a panic in this file could unwind into a C caller.
            // For every non-negative `now`, which is every real reading, the
            // two are identical.
            if CURL_OFF_T_MAX.saturating_sub(*now) < seconds {
                CURL_OFF_T_MAX
            } else {
                seconds.saturating_add(*now)
            }
        }
    };

    // `:608`
    cap_expires(*now, &mut cookie.expires);
}

/// The `Expires` attribute -- `lib/cookie.c:602-627`.
///
/// The C's comment: *"Let max-age have priority. If the date cannot get parsed
/// for whatever reason, the cookie will be treated as a session cookie."* The
/// priority is enforced by the caller's `!co->expires` guard, not here.
///
/// ```text
/// if(!Curl_getdate_capped(dbuf, &date)) {
///   if(!date) date++;
///   co->expires = (curl_off_t)date;
/// }
/// else
///   co->expires = 0;
/// if(!now) now = time(NULL);
/// cap_expires(now, co);
/// ```
///
/// `if(!date) date++` is what keeps a date that genuinely falls on the epoch
/// from being mistaken for the session-cookie marker, and it is the mirror of
/// the `-1`-to-`0` adjustment the exported `curl_getdate` makes for its own
/// sentinel. A date far in the future arrives here already saturated at
/// `TIME_T_MAX` by [`getdate_capped`], and [`cap_expires`] then pulls it back
/// to 400 days out.
///
/// The C copies the span into an 81-byte stack buffer to terminate it; the
/// caller's `strlen(val) < MAX_DATE_LENGTH` guard is what makes that copy
/// safe. The guard is preserved, the buffer is not needed, and the byte span
/// goes straight to the parser.
#[cfg(feature = "cookies")]
fn parse_expires(
    cookie: &mut Cookie,
    value: &[u8],
    now: &mut CurlOffT,
    clock: &dyn Clock,
) {
    // `:619-625`
    cookie.expires = match getdate_capped(value) {
        // `:621-623`
        Some(0) => 1,
        Some(date) => date,
        // `:624-625` -- a session cookie, NOT a refusal.
        None => 0,
    };

    // `:626-627`
    if *now == 0 {
        *now = clock.epoch_secs();
    }
    cap_expires(*now, &mut cookie.expires);
}

// ---------------------------------------------------------------------------
// The jar reader -- `parse_netscape` (`lib/cookie.c:650-772`).
// ---------------------------------------------------------------------------

/// Parses one line of a Netscape cookie jar -- `parse_netscape`
/// (`lib/cookie.c:650-772`).
///
/// `true` means the C's `*okay`. The C's own framing: *"This line is NOT an
/// HTTP header style line, we do offer support for reading the odd netscape
/// cookies-file format here."*
///
/// Seven TAB-separated fields, split with `len = strcspn(ptr, "\t\r\n")` and
/// `next = (ptr[len] == '\t' ? &ptr[len + 1] : NULL)`. So a line ending in a
/// TAB has one more field -- an empty one -- than a line that does not, which
/// is exactly how `tests/data/test46`'s `empty` cookie gets an empty value.
///
/// # THE ORDER OF THE FIRST TWO TESTS MATTERS
///
/// `#HttpOnly_` is looked for FIRST (`:672-675`) and only then is a leading
/// `#` treated as a comment (`:677-679`). Reversing them would make every
/// `HttpOnly` line a comment and silently lose those cookies on every load.
/// The prefix test is `strncmp`, so it is **case-sensitive**;
/// `docs/HTTP-COOKIES.md` says the same: `#` lines are comments *"An exception
/// is lines that start with `#HttpOnly_`"*.
///
/// # What each field does, and which ones can drop the line
///
/// | # | Field | Behaviour |
/// |---|---|---|
/// | 0 | domain | ONE leading dot stripped; always stored, possibly empty |
/// | 1 | include-subdomains | `curl_strnequal(ptr, "TRUE", len)`; **never rejects** |
/// | 2 | path | a boolean-looking or EMPTY field falls through to field 3 |
/// | 3 | HTTPS-only | drops the line only when TRUE and the inverted gate refuses |
/// | 4 | expires | a number-parse failure DROPS the line |
/// | 5 | name | the two prefix tests, **case-INsensitive** here |
/// | 6 | value | stored |
///
/// Then `fields == 6` supplies an empty value and counts it, and `fields != 7`
/// drops the line (`:753-765`).
///
/// # The three counter-intuitive readings, each measured from the C
///
/// * **Field 1 never rejects anything.** `curl_strnequal` is a length-limited
///   prefix compare, so `T`, `TR` and `TRU` all read as TRUE, and -- because
///   `ncasecompare` returns 1 the moment its budget reaches zero
///   (`lib/strequal.c:60-61`) -- **an EMPTY field 1 also reads as TRUE**.
///   Anything else simply yields FALSE and the line survives.
/// * **Field 2 falls through.** `if(strncmp("TRUE", ptr, len) &&
///   strncmp("FALSE", ptr, len))` is a prefix test in the opposite direction
///   ([`strncmp_prefix`] explains why), so `TRUE`, `FALSE`, any prefix of
///   either, and the EMPTY field all look like a boolean. In that case the
///   path becomes `"/"`, `fields` is incremented and control **falls through
///   to field 3** with the same span. That is the whole mechanism by which a
///   six-field file is read: *"The file format allows the path field to remain
///   not filled in"*.
/// * **Field 3 rejects only a TRUE it may not honour.** `co->secure` is
///   cleared first and only a TRUE-looking field enters the gate, so `FALSE`,
///   `banana` and an empty field all leave `secure` false and keep the line.
///
/// # The inverted `secure` gate
///
/// `:727-731` is `if(secure || ci->running)`, where the header parser's `:520`
/// is `if(secure || !ci->running)`. **The negation differs and that is
/// deliberate.** A jar being read into a store that is already running is
/// trusted with its `secure` cookies; a header on an insecure connection is
/// not. Both are reproduced verbatim and neither is harmonised.
///
/// # The prefix asymmetry
///
/// `:744` and `:746` use `curl_strnequal`, so `__secure-` in a jar file sets
/// the prefix bit where `__secure-` in a header does not. Deliberate, and
/// preserved.
#[cfg(feature = "cookies")]
fn parse_netscape(
    cookie: &mut Cookie,
    running: bool,
    line: &[u8],
    secure: bool,
) -> bool {
    // Every scan below is a `strcspn` or an index into a NUL-terminated
    // string, so the line is cut at its first zero byte once, here.
    let line = c_string(line);

    // `:672-675` -- BEFORE the comment test. Ten bytes, case-sensitively.
    let mut rest = line;
    if rest.starts_with(HTTPONLY_PREFIX) {
        rest = rest.get(HTTPONLY_PREFIX.len()..).unwrap_or(&[]);
        cookie.httponly = true;
    }

    // `:677-679` -- *"do not even try the comments"*.
    if rest.first() == Some(&b'#') {
        return false;
    }

    // `:685-686`
    let mut fields = 0usize;
    let mut next: Option<&[u8]> = Some(rest);

    while let Some(ptr) = next {
        // `:688-689`. `len` is the field, and the separator decides whether
        // another field follows: a `\r` or `\n` ends the line, and running out
        // of bytes does too.
        let len = ptr
            .iter()
            .position(|byte| FIELD_DELIMITERS.contains(byte))
            .unwrap_or(ptr.len());
        let field = ptr.get(..len).unwrap_or(ptr);
        next = match ptr.get(len) {
            Some(&b'\t') => Some(ptr.get(len + 1..).unwrap_or(&[])),
            _ => None,
        };

        // `:690` -- `switch(fields)`. Field 2 can advance `fields` and fall
        // through to field 3 with the same span, which a `match` cannot
        // express, so the two are written as one arm.
        match fields {
            // `:691-699` -- *"skip preceding dots"*, but only ONE. `len`
            // cannot be zero when the first byte is a dot, so the C's
            // `len--` cannot underflow; `get(1..)` says the same without
            // arithmetic.
            0 => {
                let domain = match field.first() {
                    Some(&b'.') => field.get(1..).unwrap_or(&[]),
                    _ => field,
                };
                // ALWAYS stored, even when empty -- `curlx_memdup0(ptr, 0)`
                // yields `""`, not NULL. So no jar-loaded cookie is ever
                // written as `unknown`.
                cookie.domain = Some(domain.to_vec());
            }

            // `:700-708`. The C's comment: *"flag: A TRUE/FALSE value
            // indicating if all machines within a given domain can access the
            // variable. Set TRUE when the cookie says .example.com and to
            // false when the domain is complete www.example.com"*.
            1 => {
                cookie.tailmatch = ncasecompare(field, TRUE_WORD, len);
            }

            // `:709-724` and `:725-734`. Field 2 either takes a path or
            // decides it is looking at field 3's boolean, and in the second
            // case it makes the path `"/"`, counts the extra field and FALLS
            // THROUGH. `FALLTHROUGH()` at `:723` is the C saying so.
            2 => {
                if !strncmp_prefix(TRUE_WORD, field)
                    && !strncmp_prefix(FALSE_WORD, field)
                {
                    // `:711-716` -- *"only if the path does not look like a
                    // boolean option!"*
                    cookie.path = Some(sanitize_cookie_path(field));
                } else {
                    // `:718-722` -- *"this does not look like a path, make one
                    // up!"*
                    cookie.path = Some(ROOT_PATH.to_vec());
                    fields += 1;
                    if !parse_netscape_secure(
                        cookie, running, field, len, secure,
                    ) {
                        return false;
                    }
                }
            }

            // `:725-734`
            3 => {
                if !parse_netscape_secure(cookie, running, field, len, secure) {
                    return false;
                }
            }

            // `:735-738` -- a number-parse failure DROPS the line. The C reads
            // from `ptr` rather than from the field, so a trailing non-digit
            // inside the field simply ends the number; the length is not
            // consulted at all.
            4 => {
                let mut cursor = field;
                match str_number(&mut cursor, CURL_OFF_T_MAX) {
                    Ok(expires) => cookie.expires = expires,
                    Err(_) => return false,
                }
            }

            // `:739-751`. *"For Netscape file format cookies we check prefix
            // on the name"* -- and here the two tests are `curl_strnequal`,
            // CASE-INSENSITIVE, where `:501-503` used `strncmp`. Deliberate.
            5 => {
                cookie.name = field.to_vec();
                if ncasecompare(
                    PREFIX_SECURE_NAME,
                    &cookie.name,
                    PREFIX_SECURE_NAME.len(),
                ) {
                    cookie.prefix_secure = true;
                } else if ncasecompare(
                    PREFIX_HOST_NAME,
                    &cookie.name,
                    PREFIX_HOST_NAME.len(),
                ) {
                    cookie.prefix_host = true;
                }
            }

            // `:752-756`
            6 => {
                cookie.value = Some(field.to_vec());
            }

            // `:690-757` -- the C's switch has no `default`, so an eighth
            // field and beyond are counted and discarded.
            _ => {}
        }

        fields += 1;
    }

    // `:758-765` -- *"we got a cookie with blank contents, fix it"*.
    if fields == 6 {
        cookie.value = Some(Vec::new());
        fields += 1;
    }

    // `:767-769` -- *"we did not find the sufficient number of fields"*.
    if fields != 7 {
        return false;
    }

    // `:771`
    true
}

/// Field 3 of a jar line -- `lib/cookie.c:725-734`. `false` drops the line.
///
/// ```text
/// co->secure = FALSE;
/// if(curl_strnequal(ptr, "TRUE", len)) {
///   if(secure || ci->running)
///     co->secure = TRUE;
///   else
///     return CURLE_OK;
/// }
/// ```
///
/// Written as a function only because field 2 falls through into it, and a
/// `match` arm cannot fall through to the next. **The gate is `secure ||
/// running`, with no negation** -- the header parser's is `secure ||
/// !running`. See [`parse_netscape`].
#[cfg(feature = "cookies")]
fn parse_netscape_secure(
    cookie: &mut Cookie,
    running: bool,
    field: &[u8],
    len: usize,
    secure: bool,
) -> bool {
    // `:726` -- cleared first, unconditionally.
    cookie.secure = false;

    // `:727`
    if ncasecompare(field, TRUE_WORD, len) {
        // `:728-731` -- NOT negated. Deliberate; see `parse_netscape`.
        if secure || running {
            cookie.secure = true;
        } else {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// The public-suffix check -- `is_public_suffix` (`lib/cookie.c:774-819`).
// ---------------------------------------------------------------------------

/// The public-suffix list, injected.
///
/// `lib/psl.c` reaches its list through `data->multi->psl` or
/// `data->share->psl` and its own `Curl_psl_use`/`Curl_psl_release` pair. The
/// successor of that ownership question is `crate::share`, which does not
/// exist yet, so the two halves a check needs -- the cache to consult and the
/// source to refresh it from -- are handed in together.
///
/// **`None` is not the same as a `Some` that cannot load.** `None` is the C's
/// `#ifndef USE_LIBPSL` build: there is no list and there never was going to
/// be one, so no cookie is dropped on public-suffix grounds and
/// [`bad_domain`] is the only defence. A `Some` whose source cannot produce a
/// list is the `#ifdef` arm with a null list, and that FAILS CLOSED. See
/// [`is_public_suffix`].
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Built by `crate::share`, which is later code.
pub(crate) struct PslContext<'a> {
    /// The cache `Curl_psl_use` reads and refreshes.
    pub(crate) cache: &'a mut psl::PslCache,
    /// Where a refreshed list comes from.
    pub(crate) source: &'a dyn psl::PslSource,
}

#[cfg(feature = "cookies")]
impl fmt::Debug for PslContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The source is a trait object whose `Debug` is part of `PslSource`,
        // and the cache holds a parsed list that has no useful rendering, so
        // what is shown is the state a reader would want: whether a list is
        // loaded and where one would come from.
        f.debug_struct("PslContext")
            .field("has_list", &self.cache.has_list())
            .field("source", &self.source)
            .finish()
    }
}

/// Whether this cookie's domain is one it may not be set for --
/// `is_public_suffix` (`lib/cookie.c:774-819`). **`true` drops the cookie.**
///
/// ```text
/// if(data && (domain && co->domain && !Curl_host_is_ipnum(co->domain))) {
///   bool acceptable = FALSE;
///   char lcase[256]; char lcookie[256];
///   size_t dlen = strlen(domain); size_t clen = strlen(co->domain);
///   if((dlen < sizeof(lcase)) && (clen < sizeof(lcookie))) {
///     const psl_ctx_t *psl = Curl_psl_use(data);
///     if(psl) {
///       Curl_strntolower(lcase, domain, dlen + 1);
///       Curl_strntolower(lcookie, co->domain, clen + 1);
///       acceptable = psl_is_cookie_domain_acceptable(psl, lcase, lcookie);
///       Curl_psl_release(data);
///     }
///     else
///       infof(data, "libpsl problem, rejecting cookie for safety");
///   }
///   if(!acceptable) {
///     infof(data, "cookie '%s' dropped, domain '%s' must not "
///           "set cookies for '%s'", co->name, domain, co->domain);
///     return TRUE;
///   }
/// }
/// ```
///
/// # The two C arms, selected at run time
///
/// `USE_LIBPSL` is a compile-time switch in the C and cannot be one here,
/// because `publicsuffix 2.3.0` ships no list of its own and the list source
/// is therefore a run-time input. The mapping, which [`psl`] states from its
/// own side:
///
/// * **`psl` is `None`** -- no source was ever configured. This is `#ifndef
///   USE_LIBPSL`: the function returns `false` for everything, and
///   [`bad_domain`] with its `":"` sentinel in [`parse_domain_attribute`] is
///   the whole defence. `crate::version` must not emit `PSL` in that build,
///   and `docs/HTTP-COOKIES.md` describes the consequence plainly -- without a
///   list curl *"has no ability to stop super cookies"*.
/// * **`psl` is `Some` and a list loads** -- the `#ifdef` arm, and the verdict
///   is [`psl::is_cookie_domain_acceptable`]'s.
/// * **`psl` is `Some` and no list loads** -- the `#ifdef` arm with a null
///   `psl_ctx_t`. **Fails closed**, with the C's exact message.
///
/// # The 256-byte buffers drop a long domain in SILENCE
///
/// The C lowers both names into fixed `char[256]` stack buffers, and when
/// either is too long it **skips the check with `acceptable` still FALSE** --
/// so the cookie is dropped, and the length is not mentioned in any
/// diagnostic. That is reproduced, using [`psl::MAX_PSL_DOMAIN_LEN`] so that
/// the two files cannot disagree about the number. Note the C's `dlen <
/// sizeof(lcase)` is strict, because `Curl_strntolower` is asked for
/// `dlen + 1` bytes to copy the terminator too.
///
/// # The guard, term by term
///
/// `data` has no counterpart. `domain` is the default domain, so a cookie
/// added with no request host -- from a file, or from `CURLOPT_COOKIELIST` --
/// is NEVER checked; the C's own `CURLOPT_COOKIELIST` manual page warns about
/// that. `co->domain` absent means nothing to check. And an ipnum cookie
/// domain is exempt, because a bare address has no public suffix.
#[cfg(feature = "cookies")]
fn is_public_suffix(
    psl: Option<&mut PslContext<'_>>,
    cookie: &Cookie,
    domain: Option<&[u8]>,
    clock: &dyn Clock,
    log: &dyn CookieLog,
) -> bool {
    // The `#ifndef USE_LIBPSL` arm at `:812-818`: the C's `#else` never drops
    // a cookie, and neither does this.
    let Some(psl) = psl else {
        return false;
    };

    // `:786` -- every term.
    let (Some(host), Some(cookie_domain)) = (domain, cookie.domain()) else {
        return false;
    };
    if host_is_ipnum(cookie_domain) {
        return false;
    }

    let mut acceptable = false;

    // `:791` -- both tests strict, because `dlen + 1` bytes are copied.
    if host.len() < psl::MAX_PSL_DOMAIN_LEN
        && cookie_domain.len() < psl::MAX_PSL_DOMAIN_LEN
    {
        // `:792` -- `Curl_psl_use`, which refreshes a stale list and answers
        // `NULL` when none can be had.
        match psl.cache.use_list(clock, psl.source) {
            Some(list) => {
                // `:795-796` -- *"the PSL check requires lowercase domain name
                // and pattern"*. The fold is ASCII-only, which is the whole
                // reason `Curl_strntolower` exists rather than `tolower`.
                let mut lcase = vec![0u8; host.len()];
                let mut lcookie = vec![0u8; cookie_domain.len()];
                strntolower(&mut lcase, host);
                strntolower(&mut lcookie, cookie_domain);

                // `:797` -- HOST FIRST, cookie domain second. Reversing them
                // silently inverts the check.
                acceptable =
                    psl::is_cookie_domain_acceptable(list, &lcase, &lcookie);
            }
            None => {
                // `:801-802` -- fail closed, and say so.
                log.infof(format_args!(
                    "libpsl problem, rejecting cookie for safety"
                ));
            }
        }
    }

    // `:805-810`
    if !acceptable {
        log.infof(format_args!(
            "cookie '{}' dropped, domain '{}' must not set cookies for '{}'",
            Text(cookie.name()),
            Text(host),
            Text(cookie_domain)
        ));
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// Supersession -- `replace_existing` (`lib/cookie.c:822-924`).
// ---------------------------------------------------------------------------

/// What [`replace_existing`] decided.
#[cfg(feature = "cookies")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Replacement {
    /// The C's `return FALSE`: the new cookie is refused outright, either
    /// because it would overlay a secure cookie or because a live cookie of
    /// the same identity already exists.
    Refused,
    /// The C's `return TRUE` with `*replacep == FALSE`: store the new cookie
    /// alongside what is already there.
    Insert,
    /// The C's `return TRUE` with `*replacep == TRUE`: the cookie at this
    /// index was removed, and the new one inherits its creation time.
    Replaced { creationtime: u32 },
}

/// Removes any cookie the new one supersedes -- `replace_existing`
/// (`lib/cookie.c:822-924`).
///
/// **One walk over the bucket, two independent tests.** The C's single loop
/// body contains two `if(!strcmp(clist->name, co->name))` blocks that do
/// different jobs, and only the second is guarded by `!replace_n` -- so the
/// first runs against EVERY cookie in the bucket even after a replacement
/// candidate has been found.
///
/// # Test A -- a non-secure cookie may not overlay a secure one
///
/// `:836-873`, and the C states the rule with an example: *"A non-secure
/// cookie may not overlay an existing secure cookie. For an existing cookie
/// `a` with path `/login`, refuse a new cookie `a` with for example path
/// `/login/en`, while the path `/loginhelper` is ok."*
///
/// It applies when the names are equal (`strcmp`, **case-sensitive**), the
/// domains are equal (`curl_strequal`, case-insensitive, or both absent), BOTH
/// have paths, and `clist->secure && !co->secure && !secure`. The prefix
/// length compared is the offset of the **second** `/` in the existing path --
/// `strchr(clist->path + 1, '/')` -- or the whole path when there is no second
/// one. `docs/HTTP-COOKIES.md` records that this protection is implemented.
///
/// # Test B -- the replacement candidate
///
/// `:875-908`. Names equal; domains equal **and `tailmatch` equal**, or both
/// domains absent; then paths must be equal (`curl_strequal`) and an
/// absent-against-present path disqualifies (`!clist->path != !co->path`).
///
/// The last condition is the one worth naming: `if(replace_old &&
/// !co->livecookie && clist->livecookie) return FALSE;` -- **a cookie read
/// from a file never replaces a live cookie received in a header.** The C
/// explains it at `:896-901` and `CURLOPT_COOKIELIST`'s manual page repeats it:
/// *"A live cookie is not replaced by one read from a file."*
///
/// # The retained creation time
///
/// `:912-913` -- *"when replacing, creationtime is kept from old"*. This is
/// load-bearing for BOTH orders this module produces: the jar's
/// descending-creation-time order and the fourth tiebreak of the `Cookie:`
/// header. `tests/data/test31` pins it -- an `overwrite` cookie replaced by a
/// later `Set-Cookie:` keeps its original position in the saved jar rather
/// than moving to the front.
///
/// The C removes the superseded cookie here, inside this function, and the
/// caller then appends. This returns the decision and the inherited time
/// instead, and the caller does both -- which keeps the `&mut` borrow of the
/// bucket to one place and makes the ordering of remove-then-append explicit.
#[cfg(feature = "cookies")]
fn replace_existing(
    bucket: &mut VecDeque<Cookie>,
    cookie: &Cookie,
    secure: bool,
    log: &dyn CookieLog,
) -> Replacement {
    let mut replace_at: Option<usize> = None;

    // `:831`
    for (index, clist) in bucket.iter().enumerate() {
        // `:834` -- `strcmp`, CASE-SENSITIVE.
        if clist.name != cookie.name {
            continue;
        }

        // `:836-845`
        let matching_domains = match (clist.domain(), cookie.domain()) {
            // `:839-841` -- `curl_strequal`, case-INsensitive.
            (Some(existing), Some(new)) => casecompare(existing, new),
            // `:843-844`
            (None, None) => true,
            _ => false,
        };

        // `:847-873`
        if matching_domains
            && clist.path.is_some()
            && cookie.path.is_some()
            && clist.secure
            && !cookie.secure
            && !secure
        {
            if let Some(existing_path) = clist.path() {
                // `:859-865` -- the offset of the SECOND `/`, or the whole
                // path. `existing_path[0]` is `/` for every stored path, which
                // is what the C's `DEBUGASSERT(clist->path[0])` asserts, so
                // the search starts at index 1.
                let cllen = existing_path
                    .get(1..)
                    .and_then(|tail| tail.iter().position(|&byte| byte == b'/'))
                    .map_or(existing_path.len(), |at| at + 1);

                // `:867-871` -- `curl_strnequal`, case-INsensitive.
                let new_path = cookie.path().unwrap_or(&[]);
                if ncasecompare(existing_path, new_path, cllen) {
                    log.infof(format_args!(
                        "cookie '{}' for domain '{}' dropped, \
                         would overlay an existing cookie",
                        Text(cookie.name()),
                        OptText(cookie.domain())
                    ));
                    return Replacement::Refused;
                }
            }
        }

        // `:875` -- `if(!replace_n && !strcmp(...))`. The name test already
        // passed above; this half of the body runs only until a candidate is
        // found.
        if replace_at.is_some() {
            continue;
        }

        // `:878-887`
        let mut replace_old = match (clist.domain(), cookie.domain()) {
            // `:879-882` -- domains equal AND `tailmatch` equal.
            (Some(existing), Some(new)) => {
                casecompare(existing, new)
                    && clist.tailmatch == cookie.tailmatch
            }
            // `:884-885`
            (None, None) => true,
            _ => false,
        };

        // `:887-894`
        if replace_old {
            match (clist.path(), cookie.path()) {
                // `:890-892` -- `curl_strequal`, case-INsensitive.
                (Some(existing), Some(new)) => {
                    if !casecompare(existing, new) {
                        replace_old = false;
                    }
                }
                // `:893-894` -- `!clist->path != !co->path`: one absent and
                // one present disqualifies; both absent does not.
                (None, None) => {}
                _ => replace_old = false,
            }
        }

        // `:896-904` -- *"Both cookies matched fine, except that the already
        // present cookie is `live`, which means it was set from a header, while
        // the new one was read from a file and thus is not `live`. `live`
        // cookies are preferred so the new cookie is freed."*
        if replace_old && !cookie.livecookie && clist.livecookie {
            return Replacement::Refused;
        }

        // `:905-906`
        if replace_old {
            replace_at = Some(index);
        }
    }

    // `:909-921`
    match replace_at {
        Some(index) => {
            // `:912-913` -- the inherited creation time, read before the
            // removal.
            let creationtime =
                bucket.get(index).map_or(0, Cookie::creationtime);
            // `:916-919` -- unlink the old and free it.
            llist::dispose(bucket, index);
            Replacement::Replaced { creationtime }
        }
        // `:922` -- `*replacep = replace_old`, which is FALSE on every path
        // that reaches here with no candidate.
        None => Replacement::Insert,
    }
}

// ---------------------------------------------------------------------------
// The orchestrator -- `Curl_cookie_add` (`lib/cookie.c:934-1045`).
// ---------------------------------------------------------------------------

#[cfg(feature = "cookies")]
#[allow(dead_code)] // Called by the response-header path, which is later code.
impl CookieInfo {
    /// Adds one cookie line to the store -- `Curl_cookie_add`
    /// (`lib/cookie.c:934-1045`).
    ///
    /// The C's own note: *"Add a single cookie line to the cookie keeping
    /// object. Be aware that sometimes we get an IP-only hostname, and that
    /// might also be a numerical IPv6 address."*
    ///
    /// `Ok(true)` means the cookie was stored. `Ok(false)` is every one of the
    /// C's `goto fail` paths, all of which it reports as `CURLE_OK` with
    /// nothing stored -- a malformed cookie is not a transfer error.
    ///
    /// # When the caller must increment its own counter
    ///
    /// `data->req.setcookies++` at `:1041-1042` sits on the success path only;
    /// the `fail:` label returns without it. So the counter passed in
    /// [`AddContext::setcookies`] is to be incremented by the caller exactly
    /// when this returns `Ok(true)` for a header line. The counter lives on the
    /// request rather than on the store because it resets per response.
    ///
    /// # The fourteen steps, in the C's order
    ///
    /// The order is behaviour, not style: step 6 stamps the creation time
    /// BEFORE steps 8 and 9 can refuse the cookie, so a refusal still consumes
    /// a counter value, and step 7 sweeps the store BEFORE the supersession
    /// test, so an expired cookie cannot be the one that is replaced.
    ///
    /// 1. `:953-954` -- at or past [`MAX_SET_COOKIE_AMOUNT`], *"silently
    ///    ignore"*. No diagnostic at all.
    /// 2. `:959-963` -- parse, with `httpheader` selecting which parser.
    /// 3. `:968-970` -- *"The `__Secure-` prefix only requires that the cookie
    ///    be set secure"*.
    /// 4. `:972-982` -- *"The `__Host-` prefix requires the cookie to be
    ///    secure, have a `/` path and not have a domain set."* All four
    ///    conjuncts, and the third is a byte-exact comparison against `"/"`.
    /// 5. `:984-987` -- `CURLOPT_COOKIESESSION` and
    ///    `--junk-session-cookies`: while reading a file, discard cookies with
    ///    no expiry.
    /// 6. `:987-988` -- `livecookie` from `running`, and
    ///    `creationtime = ++lastct`.
    /// 7. `:996-998` -- sweep, unless [`AddContext::noexpire`].
    /// 8. `:1000-1001` -- the public-suffix check.
    /// 9. `:1003-1004` -- supersession.
    /// 10. `:1015-1016` -- **TAIL-append** to the bucket
    ///     [`cookiehash`] chooses. Insertion order within a bucket is
    ///     `CURLINFO_COOKIELIST`'s order, so appending rather than prepending
    ///     is observable.
    /// 11. `:1018-1024` -- the diagnostic, *"Only show this when NOT reading
    ///     the cookies from a file"*.
    /// 12. `:1026-1027` -- the count rises only for a genuine insertion.
    /// 13. `:1033-1038` -- *"Now that we have added a new cookie to the jar,
    ///     update the expiration tracker in case it is the next one to
    ///     expire."*
    /// 14. `:1041-1042` -- the caller's counter; see above.
    ///
    /// # Errors
    ///
    /// None are reachable. The C returns `CURLE_OUT_OF_MEMORY` from
    /// `strstore`, from the heap copy at `:1007` and from
    /// `Curl_cookie_getlist`'s array, and a Rust allocation failure aborts
    /// instead of returning. The `Result` is retained because
    /// `lib/http.c:3554` and `lib/setopt.c:1616` both propagate a `CURLcode`
    /// from this call and their successors must have one to propagate; AAP
    /// 0.4.2 fixes that shape for an internal `CURLcode` function.
    pub(crate) fn add(
        &mut self,
        line: &[u8],
        ctx: &AddContext<'_>,
        clock: &dyn Clock,
        log: &dyn CookieLog,
        psl: Option<&mut PslContext<'_>>,
    ) -> CodeResult<bool> {
        // STEP 1 -- `:953-954`. The C asserts `MAX_SET_COOKIE_AMOUNT <= 255`
        // at `:952` because its counter is an `unsigned char`; the counter is
        // a `u32` here, so the bound is asserted by test instead.
        if ctx.setcookies >= MAX_SET_COOKIE_AMOUNT {
            return Ok(false);
        }

        // `:956-957` -- a zeroed stack cookie, filled in by the parser and
        // discarded on every refusal.
        let mut cookie = Cookie::default();

        // STEP 2 -- `:959-963`.
        let use_libpsl = psl.is_some();
        let okay = if ctx.httpheader {
            parse_cookie_header(
                &mut cookie,
                self.running,
                line,
                ctx,
                use_libpsl,
                clock,
                log,
            )
        } else {
            parse_netscape(&mut cookie, self.running, line, ctx.secure)
        };
        if !okay {
            return Ok(false);
        }

        // STEP 3 -- `:968-970`.
        if cookie.prefix_secure && !cookie.secure {
            return Ok(false);
        }

        // STEP 4 -- `:972-982`. The C spells this as an empty `if` body with
        // the refusal in the `else`; the negation is written out here.
        if cookie.prefix_host {
            let host_ok = cookie.secure
                && cookie.path() == Some(ROOT_PATH)
                && !cookie.tailmatch;
            if !host_ok {
                return Ok(false);
            }
        }

        // STEP 5 -- `:984-987`. *"read from a file"*, *"clean session
        // cookies"*, *"this is a session cookie"*.
        if !self.running && self.newsession && cookie.expires == 0 {
            return Ok(false);
        }

        // STEP 6 -- `:987-988`.
        cookie.livecookie = self.running;
        // `++ci->lastct`. Saturating rather than wrapping: the C's `unsigned
        // int` would wrap after four billion cookies and silently corrupt both
        // orderings; saturating degrades the tiebreak instead, which is the
        // lesser failure and is unreachable in practice.
        self.lastct = self.lastct.saturating_add(1);
        cookie.creationtime = self.lastct;

        // STEP 7 -- `:996-998`.
        if !ctx.noexpire {
            self.remove_expired(clock);
        }

        // STEP 8 -- `:1000-1001`.
        if is_public_suffix(psl, &cookie, ctx.domain, clock, log) {
            return Ok(false);
        }

        // STEP 9 -- `:1003-1004`. The bucket is chosen from the cookie's own
        // domain, exactly as `replace_existing` does at `:830`.
        let myhash = cookiehash(cookie.domain());
        let Some(bucket) = self.cookielist.get_mut(myhash) else {
            // Unreachable: `cookiehash` returns a value below
            // `COOKIE_HASH_SIZE` and the vector has that many buckets. Handled
            // rather than indexed so that no arithmetic in this file can be
            // the reason it panics.
            return Ok(false);
        };
        let replaces = match replace_existing(bucket, &cookie, ctx.secure, log)
        {
            Replacement::Refused => return Ok(false),
            Replacement::Insert => false,
            Replacement::Replaced { creationtime } => {
                // `:912-913` -- *"when replacing, creationtime is kept from
                // old"*.
                cookie.creationtime = creationtime;
                true
            }
        };

        // STEP 10 -- `:1015-1016`. TAIL-append.
        let expires = cookie.expires;
        // `:1018-1024` is written before the move so that the diagnostic can
        // borrow the cookie's own bytes; the C reads them after the append,
        // from the heap copy, and the bytes are the same either way.
        if self.running {
            log.infof(format_args!(
                "{} cookie {}=\"{}\" for domain {}, path {}, expire {}",
                if replaces { "Replaced" } else { "Added" },
                Text(cookie.name()),
                OptText(cookie.value()),
                OptText(cookie.domain()),
                OptText(cookie.path()),
                expires
            ));
        }
        bucket.push_back(cookie);

        // STEP 12 -- `:1026-1027`.
        if !replaces {
            self.numcookies = self.numcookies.saturating_add(1);
        }

        // STEP 13 -- `:1033-1038`.
        if expires != 0 && expires < self.next_expiration {
            self.next_expiration = expires;
        }

        // STEP 14 is the caller's; see this function's documentation.
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Selecting and ordering what to send -- `Curl_secure_context` and
// `Curl_cookie_getlist` (`lib/cookie.c:1234-1354`), plus the header line that
// `http_cookies` builds from them (`lib/http.c:2523-2592`).
// ---------------------------------------------------------------------------

/// Whether this request counts as a secure origin -- `Curl_secure_context`
/// (`lib/cookie.c:1234-1240`).
///
/// ```text
/// return conn->scheme->protocol & (CURLPROTO_HTTPS | CURLPROTO_WSS) ||
///   curl_strequal("localhost", host) ||
///   !strcmp(host, "127.0.0.1") ||
///   !strcmp(host, "::1");
/// ```
///
/// **Four tests, and they do not all use the same comparison.** `localhost` is
/// matched case-INsensitively with `curl_strequal`; the two literal addresses
/// are matched case-SENSITIVELY with `strcmp`. That distinction is invisible
/// for `127.0.0.1`, which has no letters, and visible for `::1` only in that
/// there is nothing to fold -- so the two policies happen to coincide on these
/// inputs. They are reproduced separately anyway, because the C wrote them
/// separately and a later change to either literal would make the difference
/// real.
///
/// `docs/HTTP-COOKIES.md` gives the intent: curl *"considers
/// `http://localhost` to be a secure context, meaning that it allows and uses
/// cookies marked with the `secure` keyword even when done over plain HTTP for
/// this host. curl does this to match how popular browsers work with secure
/// cookies."*
///
/// # `tls_scheme` rather than a connection
///
/// The first term reads the `CURLPROTO_*` bit off the scheme table, which is
/// `crate::protocols`' to own and does not exist yet. `crate::url`'s
/// `SchemeInfo` deliberately omits the same bit for the same reason and injects
/// scheme facts at the consumer, so the caller passes the answer: `true`
/// exactly when the scheme is `https` or `wss`. Reproducing the mask here would
/// mean redeclaring public ABI constants that belong to
/// `curl-rs-ffi/src/ffi/opts.rs`.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Called by the response-header path, which is later code.
pub(crate) fn secure_context(tls_scheme: bool, host: &[u8]) -> bool {
    // `:1236` -- the scheme bit, supplied by the caller.
    tls_scheme
        // `:1237` -- `curl_strequal`, case-INsensitive.
        || casecompare(b"localhost", host)
        // `:1238-1239` -- `strcmp`, case-SENSITIVE.
        || host == b"127.0.0.1"
        || host == b"::1"
}

/// The sort key of `cookie_sort` (`lib/cookie.c:1190-1218`).
///
/// Four levels, **every one of them descending**, and the C's own comment says
/// why: *"Helper function to sort cookies such that the longest path gets
/// before the shorter path. Path, domain and name lengths are considered in
/// that order, with the creationtime as the tiebreaker. The creationtime is
/// guaranteed to be unique per cookie, so we know we will get an ordering at
/// that point."*
///
/// An absent path, domain or name counts as length zero (`:1194-1195`,
/// `:1201-1202`, `:1208-1209`), which is not the same as a present-but-empty
/// one only in that the C cannot store an empty path or an empty name from a
/// header. `tests/data/test8` exercises the difference directly: a cookie with
/// no path at all sorts last, behind one whose path is `"/"`.
///
/// [`std::cmp::Reverse`] over a tuple gives exactly the C's ordering, and the
/// sort applied to it is a STABLE one. The C's `qsort` is not stable, which
/// costs it nothing because creation times are unique -- `++ci->lastct` -- so
/// the comparator never reports equality for two distinct cookies. Using a
/// stable sort therefore cannot differ from the C on any reachable input, and
/// it removes the one way an unstable sort could: two cookies sharing a
/// creation time, which only a replacement can produce and which cannot
/// coexist because the replacement removes the original.
#[cfg(feature = "cookies")]
fn cookie_sort_key(
    cookie: &Cookie,
) -> (
    core::cmp::Reverse<usize>,
    core::cmp::Reverse<usize>,
    core::cmp::Reverse<usize>,
    core::cmp::Reverse<u32>,
) {
    use core::cmp::Reverse;
    (
        // `:1194-1199` -- path length.
        Reverse(cookie.path_len()),
        // `:1201-1206` -- domain length.
        Reverse(cookie.domain_len()),
        // `:1208-1213` -- name length.
        Reverse(cookie.name.len()),
        // `:1216` -- creation time.
        Reverse(cookie.creationtime),
    )
}

/// The composed `Cookie:` header line, and what the caller still has to know.
///
/// The C keeps these three in locals of `http_cookies` (`lib/http.c:2526-2546`)
/// and appends straight into the request buffer. They are returned together
/// here because the request writer -- `protocols/http1.rs` -- does not exist
/// yet, and because `linecap` changes what that writer does with
/// `CURLOPT_COOKIE`.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Read by the request writer, which is later code.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CookieHeader {
    /// The `name=value` pairs, joined by `"; "` and with no prefix and no
    /// terminator. Empty when nothing was included.
    pub(crate) value: Vec<u8>,
    /// The C's `count` -- how many cookies went in. Zero means no header line
    /// is emitted at all unless `CURLOPT_COOKIE` supplies one.
    pub(crate) count: usize,
    /// The C's `linecap` (`lib/http.c:2562`): the size ceiling was reached, so
    /// **`CURLOPT_COOKIE`'s string must not be appended** (`:2577`). A caller
    /// that ignores this sends a header longer than
    /// [`MAX_COOKIE_HEADER_LEN`].
    pub(crate) linecap: bool,
}

#[cfg(feature = "cookies")]
#[allow(dead_code)] // Called by the request writer, which is later code.
impl CookieInfo {
    /// The cookies to send, in the order to send them --
    /// `Curl_cookie_getlist` (`lib/cookie.c:1253-1354`).
    ///
    /// The C's contract: *"For a given host and path, return a linked list of
    /// cookies that the client should send to the server if used now. The
    /// secure boolean informs the cookie if a secure connection is achieved or
    /// not. It shall only return cookies that have not expired."*
    ///
    /// # The early return happens BEFORE the sweep
    ///
    /// `:1271-1272` returns when the selected bucket is empty, so
    /// `remove_expired` does not run at all for a host with no cookies. That is
    /// measurable -- a store whose only expired cookie lives in another bucket
    /// keeps it -- and it is reproduced.
    ///
    /// # The matching tests, in the C's order
    ///
    /// * `:1282` -- `if(co->secure ? secure : TRUE)`. A cookie that demands a
    ///   secure context is skipped without one; one that does not is always
    ///   eligible.
    /// * `:1285-1288` -- the domain. An absent domain matches everything. A
    ///   `tailmatch` cookie tail-matches, **but only when the host is not an
    ///   ipnum**. Otherwise the host and the domain must be equal,
    ///   case-INsensitively (`curl_strequal`).
    /// * `:1298` -- the path, through [`pathmatch`], and an absent path
    ///   matches everything.
    /// * `:1304-1309` -- stop at [`MAX_COOKIE_SEND_AMOUNT`], with a
    ///   diagnostic.
    ///
    /// Only the bucket [`cookiehash`] selects is scanned, which is why an
    /// ipnum host and every ipnum cookie domain share bucket 0.
    ///
    /// # The C's `*okay` has no counterpart
    ///
    /// It is `TRUE` whenever the bucket was non-empty and `FALSE` on the two
    /// early returns, and its only reader is `lib/http.c:2544`'s
    /// `if(!result && okay)` guarding a loop over the list. An empty list makes
    /// that loop run zero times, so the flag cannot be observed and an empty
    /// [`Vec`] carries the same information.
    pub(crate) fn getlist(
        &mut self,
        host: &[u8],
        path: &[u8],
        tls_scheme: bool,
        clock: &dyn Clock,
        log: &dyn CookieLog,
    ) -> Vec<&Cookie> {
        // `:1260-1263`
        let is_ip = host_is_ipnum(host);
        let myhash = cookiehash(Some(host));
        let secure = secure_context(tls_scheme, host);

        // `:1271-1272` -- BEFORE the sweep.
        if self.cookielist.get(myhash).map_or(true, VecDeque::is_empty) {
            return Vec::new();
        }

        // `:1274-1275` -- *"at first, remove expired cookies"*.
        self.remove_expired(clock);

        let Some(bucket) = self.cookielist.get(myhash) else {
            return Vec::new();
        };

        // `:1277-1312`
        let mut matched: Vec<&Cookie> = Vec::new();
        for cookie in bucket {
            // `:1282`
            if cookie.secure && !secure {
                continue;
            }

            // `:1285-1288`
            let domain_ok = match cookie.domain() {
                None => true,
                Some(domain) => {
                    if cookie.tailmatch && !is_ip {
                        cookie_tailmatch(domain, host)
                    } else {
                        casecompare(host, domain)
                    }
                }
            };
            if !domain_ok {
                continue;
            }

            // `:1298`
            let path_ok = match cookie.path() {
                None => true,
                Some(cookie_path) => pathmatch(cookie_path, path),
            };
            if !path_ok {
                continue;
            }

            // `:1303-1310`
            matched.push(cookie);
            if matched.len() >= MAX_COOKIE_SEND_AMOUNT {
                log.infof(format_args!(
                    "Included max number of cookies ({}) in request!",
                    matched.len()
                ));
                break;
            }
        }

        // `:1314-1345` -- *"Now we need to make sure that if there is a name
        // appearing more than once, the longest specified path version comes
        // first. To make this the swiftest way, we just sort them all based on
        // path length."*
        matched.sort_by_key(|cookie| cookie_sort_key(cookie));
        matched
    }

    /// The complete `Cookie:` request header line -- `http_cookies`
    /// (`lib/http.c:2523-2592`).
    ///
    /// **This is wire-parity-critical.** AAP 0.6.7's comparison joins the whole
    /// request into one string, so the separator, the casing and the order are
    /// all frozen. `tests/data/test8` pins the exact bytes:
    ///
    /// ```text
    /// Cookie: name with space=is weird but; trailingspace=removed; \
    /// cookie=perhaps; cookie=yes; foobar=name; blexp=yesyes; cookie9=junk--
    /// ```
    ///
    /// `None` means no header line at all, which is the C's `if(count)` at
    /// `:2585` deciding not to terminate a line it never began.
    ///
    /// # The composition, term by term
    ///
    /// * `:2546` -- the running length starts at **8**, the width of the
    ///   `"Cookie: "` prefix.
    /// * `:2551` -- **a cookie with no value is skipped entirely.** Not sent as
    ///   a bare name; skipped. An EMPTY value is sent, as `name=`.
    /// * `:2558` -- `add = strlen(name) + strlen(value) + 1`, the `+1` being
    ///   the `=`.
    /// * `:2559-2564` -- `clen + add >= MAX_COOKIE_HEADER_LEN` stops the walk,
    ///   names the cookie that did not fit, and sets `linecap`.
    /// * `:2565-2566` -- `"%s%s=%s"` with `"; "` before every pair but the
    ///   first.
    /// * `:2569` -- `clen += add + (count ? 2 : 0)`, so the two bytes of the
    ///   separator are charged to the cookie that follows it.
    /// * `:2577-2584` -- `CURLOPT_COOKIE`'s string is appended verbatim, with
    ///   the same separator, **and only when `linecap` is clear**. The C
    ///   additionally requires that the application has not set its own
    ///   `Cookie` header (`:2531-2533`), which is the caller's test to make.
    ///
    /// `addcookies` is `CURLOPT_COOKIE` (10022). It is appended without any
    /// parsing or validation, exactly as the C appends it.
    pub(crate) fn cookie_header_line(
        &mut self,
        host: &[u8],
        path: &[u8],
        tls_scheme: bool,
        addcookies: Option<&[u8]>,
        clock: &dyn Clock,
        log: &dyn CookieLog,
    ) -> Option<Vec<u8>> {
        let header = self.cookie_header(host, path, tls_scheme, clock, log);

        // `:2577-2584`
        let mut count = header.count;
        let mut value = header.value;
        if let Some(extra) = addcookies {
            if !header.linecap {
                if count != 0 {
                    value.extend_from_slice(b"; ");
                }
                value.extend_from_slice(extra);
                count += 1;
            }
        }

        // `:2585-2586`
        if count == 0 {
            return None;
        }

        // `:2554` and `:2579` -- the prefix, then `:2586` -- the terminator.
        let mut line = Vec::with_capacity(value.len() + 10);
        line.extend_from_slice(b"Cookie: ");
        line.extend_from_slice(&value);
        line.extend_from_slice(b"\r\n");
        Some(line)
    }

    /// The `name=value` pairs of a `Cookie:` header, with the cap applied --
    /// the inner loop of `http_cookies` (`lib/http.c:2548-2572`).
    ///
    /// Split out from [`Self::cookie_header_line`] so that the cap and the
    /// separator can be tested without a `CURLOPT_COOKIE` string in the way,
    /// and so that a caller wanting the pieces -- the count, or `linecap` --
    /// need not re-derive them from the line.
    pub(crate) fn cookie_header(
        &mut self,
        host: &[u8],
        path: &[u8],
        tls_scheme: bool,
        clock: &dyn Clock,
        log: &dyn CookieLog,
    ) -> CookieHeader {
        let mut out = CookieHeader::default();

        // `:2546` -- *"hold the size of the generated Cookie: header"*.
        let mut clen = 8usize;

        for cookie in self.getlist(host, path, tls_scheme, clock, log) {
            // `:2551` -- no value, no cookie.
            let Some(value) = cookie.value() else {
                continue;
            };

            // `:2558`
            let add = cookie
                .name()
                .len()
                .saturating_add(value.len())
                .saturating_add(1);

            // `:2559-2564`
            if clen.saturating_add(add) >= MAX_COOKIE_HEADER_LEN {
                log.infof(format_args!(
                    "Restricted outgoing cookies due to header size, \
                     '{}' not sent",
                    Text(cookie.name())
                ));
                out.linecap = true;
                break;
            }

            // `:2565-2566`
            if out.count != 0 {
                out.value.extend_from_slice(b"; ");
            }
            out.value.extend_from_slice(cookie.name());
            out.value.push(b'=');
            out.value.extend_from_slice(value);

            // `:2569-2570`
            clen = clen.saturating_add(add).saturating_add(if out.count != 0 {
                2
            } else {
                0
            });
            out.count += 1;
        }

        out
    }
}

// ---------------------------------------------------------------------------
// The jar writer -- `get_netscape_format` and `cookie_output`
// (`lib/cookie.c:1427-1556`).
// ---------------------------------------------------------------------------

/// One jar line, WITHOUT its newline -- `get_netscape_format`
/// (`lib/cookie.c:1427-1451`).
///
/// The C's own note: *"Formats a string for Netscape output file, w/o a newline
/// at the end."* The caller adds it, with `curl_mfprintf(out, "%s\n", ...)` at
/// `:1524`. Both consumers do -- the jar writer and `CURLINFO_COOKIELIST` --
/// and `docs/HTTP-COOKIES.md` is explicit that *"A valid line must end with a
/// newline character"*.
///
/// ```text
/// "%s"               /* httponly preamble */
/// "%s%s\t"           /* domain */
/// "%s\t"             /* tailmatch */
/// "%s\t"             /* path */
/// "%s\t"             /* secure */
/// "%" FMT_OFF_T "\t" /* expires */
/// "%s\t"             /* name */
/// "%s"               /* value */
/// ```
///
/// **Seven TAB-separated fields**, and `docs/HTTP-COOKIES.md` numbers them: 0
/// domain, 1 include-subdomains, 2 path, 3 HTTPS-only, 4 expires *"seconds
/// since Jan 1st 1970, or 0"*, 5 name, 6 value.
///
/// * The `#HttpOnly_` preamble when the cookie is `HttpOnly` (`:1435`).
/// * Then a leading `.` **iff `tailmatch && domain && domain[0] != '.'`**
///   (`:1437-1443`). The C calls it *"Mozilla-style"*: *"Make sure all domains
///   are prefixed with a dot if they allow tailmatching."* The stored domain
///   never begins with a dot, because both parsers strip one, so the third
///   conjunct is defensive -- and it is reproduced because a domain read from a
///   jar line of `..example.com` keeps one of its two dots.
/// * Uppercase `TRUE` and `FALSE`, for `tailmatch` (`:1447`) and `secure`
///   (`:1449`).
/// * Fallbacks for an absent field: the domain becomes [`UNKNOWN_DOMAIN`]
///   (`:1444`), the path becomes [`ROOT_PATH`] (`:1446`) and the value becomes
///   empty (`:1450`). **The name has none** -- the C hands `co->name` to `%s`
///   unguarded.
/// * The expiry is printed as a bare `curl_off_t`, so `0` is written as `0` and
///   means a session cookie.
///
/// **Tabs, not spaces**, and this is a file-format contract rather than
/// formatting: `#[rustfmt::skip]` keeps a formatter from touching any of it.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Reached through the jar writer and CURLINFO_COOKIELIST.
#[rustfmt::skip]
pub(crate) fn get_netscape_format(cookie: &Cookie) -> Vec<u8> {
    let mut line = Vec::new();

    // `:1435` -- the preamble.
    if cookie.httponly {
        line.extend_from_slice(HTTPONLY_PREFIX);
    }

    // `:1437-1444` -- the Mozilla-style dot, then the domain or `unknown`.
    match cookie.domain() {
        Some(domain) => {
            if cookie.tailmatch && domain.first() != Some(&b'.') {
                line.push(b'.');
            }
            line.extend_from_slice(domain);
        }
        None => line.extend_from_slice(UNKNOWN_DOMAIN),
    }
    line.push(b'\t');

    // `:1447` -- field 1.
    line.extend_from_slice(
        if cookie.tailmatch { TRUE_WORD } else { FALSE_WORD },
    );
    line.push(b'\t');

    // `:1446` -- field 2.
    line.extend_from_slice(cookie.path().unwrap_or(ROOT_PATH));
    line.push(b'\t');

    // `:1449` -- field 3.
    line.extend_from_slice(
        if cookie.secure { TRUE_WORD } else { FALSE_WORD },
    );
    line.push(b'\t');

    // `:1448` -- field 4, a bare decimal `curl_off_t`.
    line.extend_from_slice(itoa(cookie.expires).as_bytes());
    line.push(b'\t');

    // `:1450` -- field 5, with no fallback.
    line.extend_from_slice(cookie.name());
    line.push(b'\t');

    // `:1450` -- field 6.
    line.extend_from_slice(cookie.value().unwrap_or(b""));

    line
}

/// A `curl_off_t` as the C's `FMT_OFF_T` renders it.
///
/// `core::fmt`'s `Display` for `i64` produces exactly what `%` `PRId64` does --
/// an optional `-` and then decimal digits, with no padding, no grouping and no
/// locale -- so this is one call. It is a named function so that the jar
/// writer's use of it reads as "the C's expiry format" rather than as an
/// incidental conversion, and so there is one place to look if the two ever
/// have to differ.
#[cfg(feature = "cookies")]
fn itoa(value: CurlOffT) -> String {
    value.to_string()
}

/// Where a jar is read from or written to -- the C's `filename` argument,
/// classified.
///
/// `cookie_load` (`lib/cookie.c:1102-1113`) and `cookie_output`
/// (`:1477-1486`) each test the same two things about the name they are given,
/// and the tests are reproduced once here so the two cannot drift:
///
/// * An EMPTY name means *do not touch a file at all*. `cookie_load` guards on
///   `if(file && *file)` and then never opens anything, yet still marks the
///   store running -- which is how `CURLOPT_COOKIEFILE ""` activates the
///   engine without loading. `tests/libtest/lib1549.c` and
///   `tests/libtest/lib3103.c` both rely on it.
/// * The name `"-"` means standard input for a load and standard output for a
///   save. `docs/libcurl/opts/CURLOPT_COOKIEJAR.md` documents the second.
///
/// A [`Path`] rather than bytes for the third variant, following
/// `crate::cookies::netrc`: the byte-to-path conversion belongs to the option
/// surface, which already holds an operating-system string, and pushing it here
/// would make this module choose an encoding for a filename it only ever
/// forwards.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Built by the option surface, which is later code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CookieFile<'a> {
    /// An empty name: activate the engine, touch no file.
    ///
    /// For a SAVE this is not something the C can reach with a valid name, and
    /// it behaves as `Curl_fopen("")` does -- a write error. See
    /// [`CookieInfo::save`].
    Inactive,
    /// The name `"-"`: standard input for a load, standard output for a save.
    Stdio,
    /// A named file.
    Path(&'a Path),
}

#[cfg(feature = "cookies")]
#[allow(dead_code)] // Called by easy-handle teardown, which is later code.
impl CookieInfo {
    /// The jar's bytes -- the whole of `cookie_output` except the sweep and the
    /// file handling (`lib/cookie.c:1488-1529`).
    ///
    /// Generic over [`Write`] so that byte-exactness is asserted in memory: the
    /// tests compare against the literal contents of `tests/data/test1920`,
    /// `test31`, `test46` and `test1160` without touching a filesystem, which
    /// is also what makes them runnable under Miri.
    ///
    /// # The header is unconditional
    ///
    /// One `fputs` of [`FILE_HEADER`] at `:1488-1491`, before any cookie and
    /// even when there are none. `tests/data/test1160` requires exactly those
    /// bytes from an empty store -- three comment lines and a blank line.
    ///
    /// # Which cookies, and in which order
    ///
    /// * `:1493` -- the whole collection is skipped when `numcookies` is zero.
    ///   Reproduced, though it cannot differ from walking an empty store.
    /// * `:1505-1512` -- *"only sort the cookies with a domain property"*: a
    ///   cookie with no domain is **not written at all**, and the buckets are
    ///   walked in index order to collect the rest.
    /// * `:1514` -- then sorted by `cookie_sort_ct`, which is
    ///   **DESCENDING creation time and nothing else** (`:1226-1232`,
    ///   `return (c2->creationtime > c1->creationtime) ? 1 : -1`).
    ///   `tests/data/test1920` pins it: a cookie received during the transfer
    ///   is written ABOVE one loaded from the file beforehand.
    /// * `:1516-1527` -- one line per cookie, each with a trailing newline.
    ///
    /// The C's comparator is a strict two-way test with no equality case, so it
    /// is not a valid total order and `qsort` may do anything with a tie. There
    /// are none: `++ci->lastct` makes every creation time unique, and a
    /// replacement inherits a time only after removing the cookie that held
    /// it. A STABLE sort is used here so that the behaviour is defined even if
    /// that invariant is ever broken, and on every reachable input it agrees
    /// with the C exactly.
    ///
    /// # Errors
    ///
    /// `CURLcode::WriteError` from [`emit`]; see there for why this propagates
    /// where the C discards the same failure.
    pub(crate) fn write_to<W: Write>(&self, out: &mut W) -> CodeResult<()> {
        // `:1488-1491`
        emit(out, FILE_HEADER)?;

        // `:1493`
        if self.numcookies == 0 {
            return Ok(());
        }

        // `:1505-1512` -- bucket order, and only cookies with a domain.
        let mut valid: Vec<&Cookie> = self
            .cookielist
            .iter()
            .flatten()
            .filter(|cookie| cookie.domain.is_some())
            .collect();

        // `:1514` -- `cookie_sort_ct`, descending creation time.
        valid.sort_by_key(|cookie| core::cmp::Reverse(cookie.creationtime));

        // `:1516-1527`
        for cookie in valid {
            emit(out, &get_netscape_format(cookie))?;
            emit(out, b"\n")?;
        }
        Ok(())
    }

    /// Writes the jar to a file or to standard output -- `cookie_output`
    /// (`lib/cookie.c:1461-1556`).
    ///
    /// # The sweep comes first
    ///
    /// `:1474-1475` -- *"at first, remove expired cookies"*, before the file is
    /// even opened, so an expired cookie is never written.
    ///
    /// # Standard output bypasses everything
    ///
    /// `:1477-1481` sets `out = stdout` and `use_stdout = TRUE`, and every
    /// later `if(!use_stdout)` skips the close, the rename and the unlink
    /// (`:1531`, `:1548`). There is no temporary file on that path and the
    /// handle is not closed.
    ///
    /// # The atomic replace, and the truncation that is not atomic
    ///
    /// Otherwise `Curl_fopen` is [`crate::util::fopen::open_for_write`], which
    /// answers one of two shapes:
    ///
    /// * `crate::util::fopen::OpenedFile::Direct` -- the target is **not a regular file**, so it is
    ///   written straight through with no rename. That is what keeps
    ///   `-c /dev/null` and a FIFO working.
    /// * `crate::util::fopen::OpenedFile::Temp` -- a sibling temporary file was created, and the
    ///   close-then-rename of `:1531-1538` is [`crate::util::fopen::OpenedFile::commit`],
    ///   including the `CURLE_WRITE_ERROR` a failed rename produces. The
    ///   `error:` block's `unlink(tempstore)` at `:1548-1554` is
    ///   [`crate::util::fopen::OpenedFile::discard`].
    ///
    /// **THE TARGET IS TRUNCATED BEFORE THE TEMPORARY FILE EXISTS.**
    /// `Curl_fopen` opens the target with `"w"` in order to `fstat` it
    /// (`lib/curl_fopen.c:99`), so the original jar is already gone before any
    /// replacement has been created, and a save that fails afterwards has
    /// destroyed it. Measured C behaviour, preserved, and not quietly improved.
    ///
    /// # `rand_suffix`
    ///
    /// The randomness for the temporary file's name, injected into
    /// [`crate::util::fopen::open_for_write`] rather than drawn here -- see that
    /// module for the contract. It is called at most once, and not at all for
    /// standard output or a non-regular target.
    ///
    /// # Errors
    ///
    /// `CURLcode::WriteError` when the target cannot be opened, when a write
    /// fails, or when the rename fails -- and in the last two cases the
    /// temporary file is removed. [`CookieFile::Inactive`] is also a write
    /// error, which is what `Curl_fopen` answers for the empty name that
    /// produces it.
    pub(crate) fn save<F>(
        &mut self,
        target: CookieFile<'_>,
        rand_suffix: F,
        clock: &dyn Clock,
    ) -> CodeResult<()>
    where
        F: FnOnce() -> CodeResult<String>,
    {
        // `:1470-1472` -- *"no cookie engine alive"* has no counterpart: the
        // store exists because this is a method on it.

        // `:1474-1475`
        self.remove_expired(clock);

        match target {
            // `:1477-1481`
            CookieFile::Stdio => {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                self.write_to(&mut handle)
            }
            // The empty name. `Curl_fopen` reaches `fopen("", "w")`, which
            // fails, and `:1484-1485` turns that into `CURLE_WRITE_ERROR`.
            CookieFile::Inactive => Err(CURLcode::WriteError),
            CookieFile::Path(path) => self.save_to_path(path, rand_suffix),
        }
    }

    /// The file half of [`Self::save`] -- `lib/cookie.c:1483-1554`.
    ///
    /// Split out so that the C's `goto error` control flow reads as an ordinary
    /// early return rather than as a labelled jump.
    fn save_to_path<F>(&self, path: &Path, rand_suffix: F) -> CodeResult<()>
    where
        F: FnOnce() -> CodeResult<String>,
    {
        // `:1484` -- `Curl_fopen(data, filename, &out, &tempstore)`. See the
        // truncation note on [`Self::save`].
        let mut opened = fopen::open_for_write(path, rand_suffix)?;

        // `:1488-1529`
        match self.write_to(opened.file_mut()) {
            // `:1531-1538` -- close, then rename when there is a temporary.
            Ok(()) => opened.commit(path),
            // `:1548-1554` -- close and unlink the temporary.
            Err(code) => {
                opened.discard();
                Err(code)
            }
        }
    }

    /// Saves the jar if there is one to save -- the inner half of
    /// `Curl_flush_cookies` (`lib/cookie.c:1605-1653`).
    ///
    /// ```text
    /// if(data->set.str[STRING_COOKIEJAR] && data->cookies->running) {
    ///   CURLcode result = cookie_output(data, data->cookies,
    ///                                   data->set.str[STRING_COOKIEJAR]);
    ///   if(result)
    ///     infof(data, "WARNING: failed to save cookies in %s: %s",
    ///           data->set.str[STRING_COOKIEJAR], curl_easy_strerror(result));
    /// }
    /// ```
    ///
    /// The C's comment explains the second conjunct: *"only save the cookie
    /// file if a transfer was started (`cookies->running` is set), as otherwise
    /// the cookies were not completely initialized and there might be cookie
    /// files that were not loaded so saving the file is the wrong thing."*
    ///
    /// `None` means no save was attempted -- no jar name, or the store is not
    /// running. `Some` carries the outcome, and the warning has already been
    /// emitted for a failure. **The failure is not propagated**, which is the C
    /// swallowing it into a diagnostic; the value is returned so that a caller
    /// and a test can see what happened.
    ///
    /// # What this deliberately does NOT do
    ///
    /// `:1647-1650` -- *"`if(cleanup && (!data->share || (data->cookies !=
    /// data->share->cookies)))`"* then destroys the store. **That ownership
    /// question is `crate::share`'s**, not this module's: whether the store is
    /// shared is knowable only where the share handle is, and a store this
    /// method tore down would leave a dangling handle behind. So nothing is
    /// destroyed here, and the module header records the rule `share/` has to
    /// apply. `tests/libtest/lib506.c` and `lib586.c` exercise exactly that
    /// path with a shared cookie store.
    pub(crate) fn flush<F>(
        &mut self,
        jar: Option<CookieFile<'_>>,
        rand_suffix: F,
        clock: &dyn Clock,
        log: &dyn CookieLog,
    ) -> Option<CodeResult<()>>
    where
        F: FnOnce() -> CodeResult<String>,
    {
        // `:1613`
        let jar = jar?;
        if !self.running {
            return None;
        }

        // `:1615-1616`
        let outcome = self.save(jar, rand_suffix, clock);

        // `:1617-1620`
        if let Err(code) = outcome {
            log.infof(format_args!(
                "WARNING: failed to save cookies in {}: {}",
                JarName(jar),
                code.message()
            ));
        }

        Some(outcome)
    }
}

/// A [`CookieFile`] as the C's `%s` renders the name behind it.
///
/// `lib/cookie.c:1618-1619` prints `data->set.str[STRING_COOKIEJAR]`, which is
/// the name as the application supplied it. [`Path`] is shown through
/// [`Path::display`], which is lossy for a name that is not valid text and is
/// the only total rendering available; the two stream names are shown as the
/// `"-"` the application would have passed. Used in a diagnostic only.
#[cfg(feature = "cookies")]
struct JarName<'a>(CookieFile<'a>);

#[cfg(feature = "cookies")]
impl fmt::Display for JarName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            CookieFile::Inactive => f.write_str(""),
            CookieFile::Stdio => f.write_str("-"),
            CookieFile::Path(path) => write!(f, "{}", path.display()),
        }
    }
}

// ---------------------------------------------------------------------------
// Loading -- `cookie_load` and `Curl_cookie_loadfiles`
// (`lib/cookie.c:1090-1174`).
// ---------------------------------------------------------------------------

#[cfg(feature = "cookies")]
#[allow(dead_code)] // Called by the option surface, which is later code.
impl CookieInfo {
    /// Reads cookies from an already-open stream -- the `if(fp)` body of
    /// `cookie_load` (`lib/cookie.c:1114-1149`).
    ///
    /// Generic over [`BufRead`] so that the reader's tolerances can be asserted
    /// in memory, which is also what makes those tests runnable under Miri.
    ///
    /// # What each line is parsed as
    ///
    /// `checkprefix("Set-Cookie:", lineptr)` (`:1123`) is
    /// **case-INsensitive**. On a match, 11 bytes are skipped and
    /// `curlx_str_passblanks` runs (`:1124-1127`), and the line goes to the
    /// HEADER parser; otherwise it goes to the JAR parser. So a cookie file may
    /// hold either format, or both, which is what
    /// `docs/libcurl/opts/CURLOPT_COOKIEFILE.md` documents -- while advising
    /// against the header form.
    ///
    /// **`CURLOPT_COOKIELIST` skips the same 11 bytes but does NOT pass
    /// blanks** (`lib/setopt.c`'s `cookielist()`). The difference is preserved;
    /// see [`cookie_command`].
    ///
    /// # The arguments the C fixes here
    ///
    /// `Curl_cookie_add(data, ci, headerline, TRUE, lineptr, NULL, NULL, TRUE)`
    /// at `:1131-1132`:
    ///
    /// * `noexpire` is **TRUE**, so no line sweeps the store. The C says why at
    ///   `:1139-1142`: *"Remove expired cookies from the hash. We must make
    ///   sure to run this after reading the file, and not on every cookie."*
    /// * the default domain and path are **absent**, so a header line in a
    ///   cookie file yields a cookie with no domain and no path -- which
    ///   matches everything. `tests/data/test8` is built on that.
    /// * `secure` is **TRUE** unconditionally. Combined with `running` being
    ///   false during a load, this makes both parsers' `secure` gates pass.
    ///
    /// # Errors
    ///
    /// The C notes at `:1133-1134` that *"File reading cookie failures are not
    /// propagated back to the caller because there is no way to do that"* --
    /// so its loop condition `while(!result && !eof)` can only stop early on
    /// the `CURLE_OUT_OF_MEMORY` that `Curl_get_line` and `Curl_cookie_add`
    /// return, never on a malformed line. Here the same is true of a
    /// `Curl_get_line` failure, which is a read error or a line past
    /// [`MAX_COOKIE_LINE`], and it stops the loop and is propagated.
    pub(crate) fn read_from<R: BufRead>(
        &mut self,
        input: &mut R,
        clock: &dyn Clock,
        log: &dyn CookieLog,
        mut psl: Option<&mut PslContext<'_>>,
    ) -> CodeResult<()> {
        // `:1116`
        let mut buf = DynBuf::new(MAX_COOKIE_LINE);

        // `:1117-1137` -- `do { ... } while(!result && !eof)`.
        loop {
            let eof = get_line(&mut buf, input)?;
            {
                let line = buf.as_slice();

                // `:1121-1127`
                let (httpheader, line) =
                    if crate::util::strcase::checkprefix("Set-Cookie:", line) {
                        let mut rest =
                            line.get(SET_COOKIE_HEADER.len()..).unwrap_or(&[]);
                        str_passblanks(&mut rest);
                        (true, rest)
                    } else {
                        (false, line)
                    };

                // `:1131-1132`
                let ctx = AddContext {
                    httpheader,
                    noexpire: true,
                    domain: None,
                    path: None,
                    secure: true,
                    setcookies: 0,
                };
                let reborrowed = psl.as_deref_mut();
                self.add(line, &ctx, clock, log, reborrowed)?;
            }

            if eof {
                break;
            }
        }

        // `:1143`
        self.remove_expired(clock);
        Ok(())
    }

    /// Reads one cookie file -- `cookie_load` (`lib/cookie.c:1090-1151`).
    ///
    /// The C's contract: *"Reads cookies from a local file. This is always
    /// called before any cookies are set. If file is `-` then STDIN is read. If
    /// `newsession` is TRUE, discard all session cookies on read from file."*
    ///
    /// # `running` is false during the read and true afterwards
    ///
    /// `:1100` clears it -- *"this is not running, this is init"* -- and
    /// `:1147` sets it, **on every path**, including the one where no file was
    /// opened at all. So `CURLOPT_COOKIEFILE ""` activates the engine and marks
    /// it running without reading anything, which is exactly what
    /// [`CookieFile::Inactive`] expresses, and `:1146`'s
    /// `data->state.cookie_engine = TRUE` is the caller's flag to set.
    ///
    /// # A missing file is a WARNING, not an error
    ///
    /// `:1108-1109` -- `infof(data, "WARNING: failed to open cookie file
    /// \"%s\"", file)` and then nothing: no error is returned and the load
    /// continues. Note the quotes are part of the message.
    ///
    /// # The mode is `"rb"`, spelled out
    ///
    /// `:1107` opens with a literal `"rb"` rather than with `FOPEN_READTEXT`,
    /// which is the macro every other reader in the C tree uses. The two are
    /// identical on the four mandated targets and neither performs any
    /// translation here, so the distinction is recorded rather than acted on.
    ///
    /// # Errors
    ///
    /// Only what [`Self::read_from`] propagates. An unopenable file is not one.
    pub(crate) fn load(
        &mut self,
        file: CookieFile<'_>,
        newsession: bool,
        clock: &dyn Clock,
        log: &dyn CookieLog,
        psl: Option<&mut PslContext<'_>>,
    ) -> CodeResult<()> {
        // `:1099-1100`
        self.newsession = newsession;
        self.running = false;

        let result = match file {
            // `:1102` -- `if(file && *file)` is false, so nothing is opened and
            // `remove_expired` does not run either.
            CookieFile::Inactive => Ok(()),
            // `:1103-1104`
            CookieFile::Stdio => {
                let stdin = io::stdin();
                let mut handle = stdin.lock();
                self.read_from(&mut handle, clock, log, psl)
            }
            // `:1106-1111`
            CookieFile::Path(path) => match File::open(path) {
                Ok(handle) => {
                    let mut reader = BufReader::new(handle);
                    self.read_from(&mut reader, clock, log, psl)
                }
                Err(_) => {
                    // `:1108-1109` -- a warning, and no error.
                    log.infof(format_args!(
                        "WARNING: failed to open cookie file \"{}\"",
                        path.display()
                    ));
                    Ok(())
                }
            },
        };

        // `:1147` -- *"now, we are running"*, whatever happened above.
        self.running = true;
        result
    }

    /// Reads every configured cookie file, in order --
    /// `Curl_cookie_loadfiles` (`lib/cookie.c:1157-1174`).
    ///
    /// The C walks `data->state.cookielist`, which is the
    /// `CURLOPT_COOKIEFILE` slist, from head to tail and **stops at the first
    /// error** (`:1170-1171`). Order is the contract, not an accident: a cookie
    /// read from an earlier file is already present when a later file is read,
    /// so it wins the `livecookie` comparison in [`replace_existing`] only if
    /// the earlier read was live -- and it wins the identity comparison
    /// outright, because a duplicate is skipped rather than replacing.
    /// `crate::util::slist` preserves that order exactly: it appends at the
    /// tail, and it neither sorts, deduplicates nor trims.
    ///
    /// The whole body runs under `CURL_LOCK_DATA_COOKIE` with
    /// `CURL_LOCK_ACCESS_SINGLE` (`:1163`, `:1176`); see the module header.
    ///
    /// # A slice rather than an [`SList`]
    ///
    /// The C's slist holds `char *` names and `cookie_load` classifies each one
    /// itself. Here the classification is the caller's, for the reason
    /// [`CookieFile`] gives: converting a filename from bytes to a [`Path`]
    /// means choosing an encoding, and the option surface already holds an
    /// operating-system string that needs no choosing. The order of the slice
    /// is the order of the slist.
    ///
    /// # Errors
    ///
    /// The first failure any [`Self::load`] reports, with the remaining files
    /// unread.
    pub(crate) fn loadfiles(
        &mut self,
        files: &[CookieFile<'_>],
        newsession: bool,
        clock: &dyn Clock,
        log: &dyn CookieLog,
        mut psl: Option<&mut PslContext<'_>>,
    ) -> CodeResult<()> {
        // `:1168-1172`
        for file in files {
            let reborrowed = psl.as_deref_mut();
            self.load(*file, newsession, clock, log, reborrowed)?;
        }
        Ok(())
    }

    /// Every cookie as a jar line -- `cookie_list` (`lib/cookie.c:1558-1595`),
    /// which backs `CURLINFO_COOKIELIST`.
    ///
    /// # The order is bucket order, then insertion order, and NOTHING is sorted
    ///
    /// `:1570-1572` walks the 63 buckets by index and each bucket from its
    /// head. That makes the output a function of [`cookie_hash_domain`], of the
    /// bucket count and of the order cookies arrived in -- which is why the
    /// store is an array of ordered lists and can never become a map. See
    /// [`CookieInfo`].
    ///
    /// `:1573-1574` skips a cookie with no domain, exactly as the jar writer
    /// does.
    ///
    /// # `None` for an empty result, matching the C's NULL
    ///
    /// `:1566-1567` returns NULL when `numcookies` is zero -- **before the
    /// sweep**, so a store holding nothing but expired cookies is reported as
    /// empty without being swept. And a store whose every cookie lacks a domain
    /// leaves the C's `list` pointer NULL too, which is the same answer by a
    /// different route. Both are `None` here.
    ///
    /// `tests/libtest/lib1549.c` prints this list and counts it, which is the
    /// coverage this reproduces.
    pub(crate) fn list(&mut self, clock: &dyn Clock) -> Option<SList> {
        // `:1566-1567` -- before the sweep.
        if self.numcookies == 0 {
            return None;
        }

        // `:1569-1570`
        self.remove_expired(clock);

        // `:1570-1589`
        let mut list = SList::new();
        for cookie in self.cookielist.iter().flatten() {
            // `:1573-1574`
            if cookie.domain.is_none() {
                continue;
            }
            // `:1575` and `:1581` -- `Curl_slist_append_nodup(list, line)`,
            // which takes ownership of the formatted line rather than copying
            // it.
            list.append_nodup(get_netscape_format(cookie));
        }

        // The C's `list` is still NULL if nothing was appended.
        if list.is_empty() {
            return None;
        }
        Some(list)
    }
}

// ---------------------------------------------------------------------------
// The `CURLOPT_COOKIELIST` command words -- `lib/setopt.c`'s `cookielist()`.
// ---------------------------------------------------------------------------

/// What a `CURLOPT_COOKIELIST` string asks for.
///
/// `docs/libcurl/opts/CURLOPT_COOKIELIST.md` lists the four commands and their
/// effects verbatim: `ALL` *"erases all cookies held in memory"*, `SESS`
/// *"erases all session cookies held in memory"*, `FLUSH` *"writes all known
/// cookies to the file specified by CURLOPT_COOKIEJAR(3)"* and `RELOAD` *"loads
/// all cookies from the files specified by CURLOPT_COOKIEFILE(3)"*.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Matched on by the option surface, which is later code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CookieCommand {
    /// `ALL` -- [`CookieInfo::clearall`].
    All,
    /// `SESS` -- [`CookieInfo::clearsess`].
    Sess,
    /// `FLUSH` -- [`CookieInfo::flush`], *"takes care of the locking"*.
    Flush,
    /// `RELOAD` -- [`CookieInfo::loadfiles`].
    Reload,
    /// Anything else: the string is a cookie to be added.
    ///
    /// The C then applies two further rules, in this order: *"general
    /// protection against mistakes and abuse"* rejects a string longer than
    /// [`CURL_MAX_INPUT_LENGTH`] with `CURLE_BAD_FUNCTION_ARGUMENT`, and
    /// `checkprefix("Set-Cookie:", ptr)` selects the header parser over the jar
    /// parser. The `bool` here is that prefix test's answer, and the length
    /// check belongs to the option surface because it returns a `CURLcode` that
    /// this function has no channel for.
    ///
    /// **The header path skips exactly 11 bytes and does NOT pass blanks**,
    /// unlike [`CookieInfo::read_from`], which does. `parse_cookie_header`
    /// trims the name anyway, so the two agree on every input -- but the
    /// difference is real and is preserved rather than tidied.
    Add {
        /// Whether the string carried a `Set-Cookie:` prefix, which
        /// [`AddContext::httpheader`] is then set from.
        httpheader: bool,
    },
}

/// Classifies a `CURLOPT_COOKIELIST` string -- `lib/setopt.c`'s
/// `cookielist()`.
///
/// The four command words are compared with `curl_strequal`, so the match is
/// **case-INsensitive and whole-string**: `all` is the command, `ALLOW` is a
/// cookie. `checkprefix` is case-insensitive too.
///
/// `None` has no counterpart here: the C's `if(!ptr) return CURLE_OK;` guards a
/// null pointer, which is the option surface's concern.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Called by the option surface, which is later code.
pub(crate) fn cookie_command(text: &[u8]) -> CookieCommand {
    if casecompare(text, b"ALL") {
        CookieCommand::All
    } else if casecompare(text, b"SESS") {
        CookieCommand::Sess
    } else if casecompare(text, b"FLUSH") {
        CookieCommand::Flush
    } else if casecompare(text, b"RELOAD") {
        CookieCommand::Reload
    } else {
        CookieCommand::Add {
            httpheader: crate::util::strcase::checkprefix("Set-Cookie:", text),
        }
    }
}

/// The bytes a `CURLOPT_COOKIELIST` header string is parsed from -- `ptr + 11`
/// (`lib/setopt.c:1616`).
///
/// Eleven bytes, the length of [`SET_COOKIE_HEADER`], and **no blanks passed
/// afterwards**. Separate from [`cookie_command`] so that the offset appears
/// once and beside the constant it comes from.
#[cfg(feature = "cookies")]
#[allow(dead_code)] // Called by the option surface, which is later code.
pub(crate) fn strip_set_cookie_prefix(text: &[u8]) -> &[u8] {
    text.get(SET_COOKIE_HEADER.len()..).unwrap_or(&[])
}

// TESTS
//
// There is NO `tests/unit/unit*.c` for the cookie engine -- measured: no file
// under `tests/unit/` carries a cookie assertion. The C-side coverage this
// relocates is `tests/libtest/lib506.c` (370 lines, a shared store driven from
// four threads), `lib586.c` (240, the same with lock callbacks), `lib676.c`
// (68, clearing by setting `CURLOPT_COOKIEFILE` to NULL), `lib1549.c` (75,
// enumerating `CURLINFO_COOKIELIST`), `lib1920.c` (55, jar content across a
// handle reset), `lib1940.c` (121, the header API, which touches `set-cookie`
// only incidentally) and `lib3103.c` (64, a cookie with neither `Max-Age` nor
// `Expires` over a shared store). Those seven link a debug static libcurl and
// call internal `Curl_*` symbols, which a Rust static library does not export,
// so their coverage relocates here rather than being made to link -- a
// documented deviation (AAP 0.8.7), not a defect to work around, and NOT a
// reason to re-export anything.
//
// THE EXPECTATIONS BELOW ARE AN ORACLE, NOT A RESTATEMENT. Every jar and every
// `Cookie:` header compared here was transcribed from a fixture under
// `tests/data/`, which is to say from bytes curl 8.19.0-DEV actually emitted:
// `test1160` (an empty jar), `test1920` (the writer's order), `test31` (17
// entries and every attribute quirk), `test8` (the definitive `Cookie:` header)
// and `test46` (the creation-time tiebreak, six-field lines and empty values).
// A disagreement means this implementation is wrong, which is the only useful
// direction for a parity test to point.
//
// Every test injects its clock, so no assertion depends on when it runs.

#[cfg(all(test, feature = "cookies"))]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::util::timeval::TestClock;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// A clock whose WALL reading is `secs`.
    ///
    /// `TestClock::new` places the MONOTONIC reading; the wall reading is what
    /// this module uses everywhere, so it is set explicitly.
    fn clock_at(secs: i64) -> TestClock {
        let clock = TestClock::default();
        clock.set_epoch_secs(secs);
        clock
    }

    /// A sink that keeps every diagnostic, so the C's wording can be asserted.
    #[derive(Debug, Default)]
    struct Recorder {
        lines: RefCell<Vec<String>>,
    }

    impl CookieLog for Recorder {
        fn infof(&self, message: fmt::Arguments<'_>) {
            self.lines.borrow_mut().push(message.to_string());
        }
    }

    impl Recorder {
        fn count(&self) -> usize {
            self.lines.borrow().len()
        }

        fn said(&self, needle: &str) -> bool {
            self.lines.borrow().iter().any(|line| line.contains(needle))
        }

        fn joined(&self) -> String {
            self.lines.borrow().join("\n")
        }
    }

    /// A 40-character suffix drawn from [`crate::util::fopen::RAND_ALPHABET`],
    /// which is that module's contract for the provider.
    fn fixed_suffix() -> CodeResult<String> {
        Ok("a".repeat(crate::util::fopen::RAND_SUFFIX_LEN))
    }

    /// `Curl_cookie_add(..., httpheader = TRUE, ...)` with the arguments
    /// `lib/http.c:3554` passes.
    fn header_ctx<'a>(
        domain: Option<&'a [u8]>,
        path: Option<&'a [u8]>,
        secure: bool,
    ) -> AddContext<'a> {
        AddContext {
            httpheader: true,
            noexpire: false,
            domain,
            path,
            secure,
            setcookies: 0,
        }
    }

    /// `Curl_cookie_add(..., httpheader = FALSE, noexpire = TRUE, NULL, NULL,
    /// TRUE)` -- the arguments `cookie_load` passes for a jar line.
    fn jar_ctx() -> AddContext<'static> {
        AddContext {
            httpheader: false,
            noexpire: true,
            domain: None,
            path: None,
            secure: true,
            setcookies: 0,
        }
    }

    /// Adds a `Set-Cookie:` value, reporting whether it was stored.
    fn add_header(
        jar: &mut CookieInfo,
        line: &[u8],
        domain: Option<&[u8]>,
        path: Option<&[u8]>,
        secure: bool,
        clock: &dyn Clock,
    ) -> bool {
        matches!(
            jar.add(
                line,
                &header_ctx(domain, path, secure),
                clock,
                &NoLog,
                None
            ),
            Ok(true)
        )
    }

    /// Adds a jar line, reporting whether it was stored.
    fn add_jar(jar: &mut CookieInfo, line: &[u8], clock: &dyn Clock) -> bool {
        matches!(jar.add(line, &jar_ctx(), clock, &NoLog, None), Ok(true))
    }

    /// The bytes [`CookieInfo::write_to`] produces.
    fn saved(jar: &CookieInfo) -> Vec<u8> {
        let mut out = Vec::new();
        assert!(jar.write_to(&mut out).is_ok());
        out
    }

    /// A jar's bytes as text, for a readable assertion failure.
    fn text(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// Loads jar text into a fresh store, as `cookie_load` would.
    fn load_text(text: &[u8], clock: &dyn Clock) -> CookieInfo {
        let mut jar = CookieInfo::new();
        let mut input = text;
        assert!(jar.read_from(&mut input, clock, &NoLog, None).is_ok());
        jar
    }

    /// The one cookie a store holds, for a test that stored exactly one.
    ///
    /// The count is asserted first, so the fallback below is unreachable --
    /// which is how this reads a value out of an [`Option`] without an
    /// `unwrap`, a policy this module holds even in its tests because a panic
    /// unwinding toward a C caller through `curl-rs-ffi` is undefined
    /// behaviour and the grep gate that forbids one does not know which side
    /// of a `#[cfg(test)]` it is looking at.
    fn only(jar: &CookieInfo) -> Cookie {
        let mut found: Vec<Cookie> = jar.cookies().cloned().collect();
        assert_eq!(found.len(), 1, "exactly one cookie must be stored");
        found.pop().unwrap_or_default()
    }

    /// Every cookie a store holds, in `CURLINFO_COOKIELIST` order.
    fn all(jar: &CookieInfo) -> Vec<Cookie> {
        jar.cookies().cloned().collect()
    }

    /// The first cookie a store holds, cloned so that a closure can return it
    /// without borrowing a store that is about to go out of scope.
    fn first(jar: &CookieInfo) -> Option<Cookie> {
        jar.cookies().next().cloned()
    }

    // -----------------------------------------------------------------------
    // The limits, and the one constraint the C asserts about them.
    // -----------------------------------------------------------------------

    #[test]
    fn the_limits_are_the_c_headers() {
        assert_eq!(COOKIE_HASH_SIZE, 63);
        assert_eq!(MAX_COOKIE_LINE, 5000);
        assert_eq!(MAX_NAME, 4096);
        assert_eq!(MAX_DATE_LENGTH, 80);
        assert_eq!(MAX_SET_COOKIE_AMOUNT, 50);
        assert_eq!(MAX_COOKIE_HEADER_LEN, 8190);
        assert_eq!(MAX_COOKIE_SEND_AMOUNT, 150);
        assert_eq!(COOKIES_MAXAGE, 34_560_000);
        assert_eq!(COOKIE_PREFIX_SECURE, 1);
        assert_eq!(COOKIE_PREFIX_HOST, 2);
        assert_eq!(CURL_MAX_INPUT_LENGTH, 8_000_000);
        assert_eq!(CURL_OFF_T_MAX, i64::MAX);

        // `DEBUGASSERT(MAX_SET_COOKIE_AMOUNT <= 255)` at `lib/cookie.c:952`
        // -- *"This value must be less than 256 since an unsigned char is used
        // to count"*. The counter is a `u32` here, so the bound is asserted
        // rather than enforced by the type, and at COMPILE time so that raising
        // the limit cannot get as far as a test run.
        const _: () = assert!(MAX_SET_COOKIE_AMOUNT <= 255);

        // `COOKIE_PIECES` counts the fields of `CookiePieces`.
        assert_eq!(COOKIE_PIECES, 4);
        let pieces = CookiePieces::default();
        assert!(pieces.name.is_empty());
        assert!(pieces.value.is_empty());
        assert!(pieces.domain.is_empty());
        assert!(pieces.path.is_empty());
    }

    #[test]
    fn a_new_store_starts_as_the_c_calloc_leaves_it() {
        let jar = CookieInfo::new();
        assert_eq!(jar.cookielist.len(), COOKIE_HASH_SIZE);
        assert!(jar.cookielist.iter().all(VecDeque::is_empty));
        // `:1077`
        assert_eq!(jar.next_expiration(), CURL_OFF_T_MAX);
        assert_eq!(jar.numcookies(), 0);
        assert_eq!(jar.lastct(), 0);
        assert!(!jar.running());
        assert!(!jar.newsession());
        assert_eq!(CookieInfo::default().numcookies(), 0);
    }

    // -----------------------------------------------------------------------
    // `cap_expires` -- `lib/cookie.c:52-61`.
    // -----------------------------------------------------------------------

    #[test]
    fn cap_expires_leaves_a_session_cookie_alone() {
        let mut expires = 0;
        cap_expires(1_000_000, &mut expires);
        assert_eq!(expires, 0);
    }

    #[test]
    fn cap_expires_leaves_an_expiry_inside_the_window_alone() {
        let now = 1_000_000;
        let mut expires = now + COOKIES_MAXAGE - 1;
        cap_expires(now, &mut expires);
        assert_eq!(expires, now + COOKIES_MAXAGE - 1);
    }

    #[test]
    fn cap_expires_rounds_to_a_sixty_second_boundary() {
        // The C: `cap = now + COOKIES_MAXAGE; cap += 30;
        //         co->expires = (cap / 60) * 60;`
        for now in [0_i64, 1, 29, 30, 31, 59, 1_700_000_000, 1_700_000_037] {
            let mut expires = CURL_OFF_T_MAX;
            cap_expires(now, &mut expires);
            let expected = ((now + COOKIES_MAXAGE + 30) / 60) * 60;
            assert_eq!(expires, expected, "now = {now}");
            assert_eq!(expires % 60, 0, "now = {now}");
            // The rounding is to the NEAREST minute, so the result may exceed
            // the nominal cap by up to 29 seconds.
            assert!(expires >= now + COOKIES_MAXAGE - 30);
            assert!(expires <= now + COOKIES_MAXAGE + 30);
        }
    }

    #[test]
    fn cap_expires_declines_to_act_near_the_ceiling() {
        // `(TIME_T_MAX - COOKIES_MAXAGE - 30) > now` fails a whole minute
        // before overflow, not at it.
        let boundary = CURL_OFF_T_MAX - COOKIES_MAXAGE - 30;

        let mut just_inside = CURL_OFF_T_MAX;
        cap_expires(boundary - 1, &mut just_inside);
        assert_ne!(just_inside, CURL_OFF_T_MAX);

        for now in [boundary, boundary + 1, CURL_OFF_T_MAX] {
            let mut untouched = CURL_OFF_T_MAX;
            cap_expires(now, &mut untouched);
            assert_eq!(untouched, CURL_OFF_T_MAX, "now = {now}");
        }
    }

    // -----------------------------------------------------------------------
    // `cookie_tailmatch` -- `lib/cookie.c:73-100`.
    // -----------------------------------------------------------------------

    #[test]
    fn cookie_tailmatch_reproduces_rfc6265_4_1_2_3() {
        // The C's own example.
        for host in [
            &b"example.com"[..],
            b"www.example.com",
            b"www.corp.example.com",
        ] {
            assert!(cookie_tailmatch(b"example.com", host), "{}", text(host));
        }

        // The label boundary is what stops a suffix that is not a subdomain.
        assert!(!cookie_tailmatch(b"example.com", b"evilexample.com"));
        assert!(!cookie_tailmatch(b"example.com", b"notexample.com"));

        // Shorter host, no match.
        assert!(!cookie_tailmatch(b"www.example.com", b"example.com"));

        // Case-insensitive, ASCII only.
        assert!(cookie_tailmatch(b"EXAMPLE.com", b"WWW.example.COM"));

        // An empty domain matches only a host ending in a dot, which is what
        // `tests/data/test977` turns on.
        assert!(cookie_tailmatch(b"", b"firsthost.me."));
        assert!(!cookie_tailmatch(b"", b"firsthost.me"));
        assert!(cookie_tailmatch(b"", b""));

        // An IP address is NOT special here. `0.0.1` DOES tail-match
        // `127.0.0.1`, because the byte before the suffix is the dot at index
        // three, and the C's *"lot of precautions"* comment is only about the
        // label boundary. The protection against a cookie being set for a
        // parent of an address lives one level up, in
        // `Curl_cookie_getlist`'s `!is_ip` term and in
        // `parse_domain_attribute`'s exact-equality requirement -- NOT here.
        assert!(cookie_tailmatch(b"0.0.1", b"127.0.0.1"));
        assert!(cookie_tailmatch(b"127.0.0.1", b"127.0.0.1"));
        // Whereas these two are refused, because the byte before the suffix is
        // `7` and `2` respectively. Note that a LEADING dot in the cookie
        // domain does not help -- it is part of the compared suffix, so it
        // moves the boundary test one byte earlier rather than satisfying it.
        assert!(!cookie_tailmatch(b".0.0.1", b"127.0.0.1"));
        assert!(!cookie_tailmatch(b"7.0.0.1", b"127.0.0.1"));

        // `tests/data/test46`: a doubled dot is still a boundary.
        assert!(cookie_tailmatch(b"domain..tld", b"domain..tld"));
        assert!(cookie_tailmatch(b".tld", b"domain..tld"));
    }

    // -----------------------------------------------------------------------
    // `pathmatch` -- `lib/cookie.c:106-156`.
    // -----------------------------------------------------------------------

    #[test]
    fn pathmatch_reproduces_rfc6265_5_1_4_with_curls_deviation() {
        // A one-byte cookie path matches everything.
        assert!(pathmatch(b"/", b"/anything/at/all"));
        assert!(pathmatch(b"/", b""));
        assert!(pathmatch(b"x", b"whatever"));

        // Equal paths.
        assert!(pathmatch(b"/we/want", b"/we/want"));

        // A prefix at a slash boundary.
        assert!(pathmatch(b"/we/want", b"/we/want/31"));
        assert!(pathmatch(b"/login", b"/login/en"));

        // A prefix that is not at a boundary.
        assert!(!pathmatch(b"/login", b"/loginhelper"));

        // Shorter URI path.
        assert!(!pathmatch(b"/we/want", b"/we"));

        // CASE-SENSITIVE -- `tests/data/test8`'s `nocookie` for `/WE` is not
        // sent for `/we/want/8`.
        assert!(!pathmatch(b"/WE", b"/we/want/8"));
        assert!(!pathmatch(b"/we", b"/WE/want/8"));

        // An empty or relative URI path is treated as `"/"`, so only a
        // one-byte cookie path can match it.
        assert!(!pathmatch(b"/we", b""));
        assert!(!pathmatch(b"/we", b"we/want"));

        // curl's documented deviation: the URI path is NOT truncated at its
        // last slash, so `/hoge` matches `/hoge?fuga=xxx`-derived paths.
        assert!(pathmatch(b"/hoge", b"/hoge"));
    }

    // -----------------------------------------------------------------------
    // `get_top_domain`, `cookie_hash_domain`, `cookiehash`.
    // -----------------------------------------------------------------------

    #[test]
    fn get_top_domain_keeps_the_last_two_labels() {
        assert_eq!(get_top_domain(b"www.corp.example.com"), b"example.com");
        assert_eq!(get_top_domain(b"example.com"), b"example.com");
        assert_eq!(get_top_domain(b"localhost"), b"localhost");
        assert_eq!(get_top_domain(b""), b"");
        assert_eq!(get_top_domain(b"."), b".");
        assert_eq!(get_top_domain(b".com"), b".com");
        assert_eq!(get_top_domain(b"a.b.c.d"), b"c.d");
        // A trailing dot is a label boundary like any other.
        assert_eq!(get_top_domain(b"firsthost.me."), b"me.");
    }

    #[test]
    fn cookie_hash_domain_is_the_uppercase_folded_djb2_of_the_c() {
        // An independent transcription of `lib/cookie.c:190-202`, so a
        // disagreement is a defect here rather than a restatement.
        fn reference(domain: &[u8]) -> usize {
            let mut h: u64 = 5381;
            for &byte in domain {
                let folded = if byte.is_ascii_lowercase() {
                    byte - 32
                } else {
                    byte
                };
                h = h.wrapping_add(h << 5);
                h ^= u64::from(folded);
            }
            (h % 63) as usize
        }

        for domain in [
            &b""[..],
            b"a",
            b"example.com",
            b"EXAMPLE.COM",
            b"test31.curl",
            b"domain..tld",
            b"\xff\xfe\x80",
            b"localhost",
        ] {
            assert_eq!(
                cookie_hash_domain(domain),
                reference(domain),
                "{}",
                text(domain)
            );
            assert!(cookie_hash_domain(domain) < COOKIE_HASH_SIZE);
        }

        // The empty domain hashes 5381 % 63.
        assert_eq!(cookie_hash_domain(b""), 5381 % 63);

        // UPPERCASE-folded, so the two cases share a bucket. That is the whole
        // difference from `crate::util::hash`'s `hash_str`, which does not
        // fold, and substituting it would reorder `CURLINFO_COOKIELIST`.
        assert_eq!(
            cookie_hash_domain(b"Example.COM"),
            cookie_hash_domain(b"eXAMPLE.com")
        );
    }

    #[test]
    fn every_ip_numeric_domain_hashes_to_bucket_zero() {
        for domain in [
            &b"127.0.0.1"[..],
            b"1.2.3.4",
            b"0.0.0.0",
            b"255.255.255.255",
            b"::1",
            b"fe80::1",
            b"2001:db8::dead:beef",
        ] {
            assert_eq!(cookiehash(Some(domain)), 0, "{}", text(domain));
        }

        // And so does an absent domain.
        assert_eq!(cookiehash(None), 0);

        // curl's `pton4` is STRICT, so these are not ipnums and hash normally.
        // `127.1` in particular is accepted by a browser and by
        // `crate::url`'s own normaliser, and is NOT an ipnum here.
        for domain in [
            &b"127.1"[..],
            b"01.2.3.4",
            b"1.2.3.256",
            b"0.0.1",
            b"1.2.3.4.5",
            b"::1%eth0",
        ] {
            assert_eq!(
                cookiehash(Some(domain)),
                cookie_hash_domain(get_top_domain(domain)),
                "{}",
                text(domain)
            );
        }
    }

    #[test]
    fn host_is_ipnum_is_pton4_or_pton6() {
        assert!(host_is_ipnum(b"127.0.0.1"));
        assert!(host_is_ipnum(b"::1"));
        assert!(host_is_ipnum(b"2001:db8::1"));
        assert!(!host_is_ipnum(b"127.1"));
        assert!(!host_is_ipnum(b"01.0.0.1"));
        assert!(!host_is_ipnum(b"example.com"));
        assert!(!host_is_ipnum(b""));
        // A zone identifier is refused by curl's `pton6`.
        assert!(!host_is_ipnum(b"fe80::1%eth0"));
    }

    // -----------------------------------------------------------------------
    // `sanitize_cookie_path` -- `lib/cookie.c:226-248`.
    // -----------------------------------------------------------------------

    #[test]
    fn sanitize_cookie_path_reproduces_every_arm() {
        // One leading quote, then one trailing quote --
        // `tests/data/test8`'s `path="/silly/"`.
        assert_eq!(sanitize_cookie_path(b"\"/silly/\""), b"/silly");
        // A trailing quote without a leading one is kept.
        assert_eq!(sanitize_cookie_path(b"/a\""), b"/a\"");
        // Empty, or not rooted, becomes the default path.
        assert_eq!(sanitize_cookie_path(b""), b"/");
        assert_eq!(sanitize_cookie_path(b"relative"), b"/");
        assert_eq!(sanitize_cookie_path(b"\""), b"/");
        assert_eq!(sanitize_cookie_path(b"\"\""), b"/");
        // Exactly ONE trailing slash, and never the only byte.
        assert_eq!(sanitize_cookie_path(b"/"), b"/");
        assert_eq!(sanitize_cookie_path(b"/hoge/"), b"/hoge");
        assert_eq!(sanitize_cookie_path(b"/hoge//"), b"/hoge/");
        assert_eq!(sanitize_cookie_path(b"/we/want/"), b"/we/want");
        // Bytes are preserved, including ones that are not text.
        assert_eq!(sanitize_cookie_path(b"/\xff\xfe"), b"/\xff\xfe");
    }

    // -----------------------------------------------------------------------
    // `invalid_octets` -- `lib/cookie.c:354-365`.
    // -----------------------------------------------------------------------

    #[test]
    fn invalid_octets_rejects_the_control_bytes_and_nothing_else() {
        for byte in 1u8..=0x1f {
            let span = [b'a', byte, b'b'];
            let expected = byte != 9;
            assert_eq!(
                invalid_octets(&span),
                expected,
                "byte {byte:#04x} -- TAB is the one exception"
            );
        }
        assert!(invalid_octets(&[0x7f]));

        // Deliberately ACCEPTED, per the C's Firefox and Chrome note.
        assert!(!invalid_octets(b" "));
        assert!(!invalid_octets(b","));
        assert!(!invalid_octets(b"\""));
        assert!(!invalid_octets(b"\t"));
        assert!(!invalid_octets(b""));

        // Every byte at or above 0x80 is accepted -- `tests/data/test31`
        // stores a cookie whose name and value are both non-UTF-8.
        for byte in 0x80u8..=0xff {
            assert!(!invalid_octets(&[byte]), "byte {byte:#04x}");
        }
    }

    // -----------------------------------------------------------------------
    // `bad_domain` -- `lib/cookie.c:327-342`. TRUE means BAD.
    // -----------------------------------------------------------------------

    #[test]
    fn bad_domain_requires_a_dot_or_exactly_localhost() {
        assert!(!bad_domain(b"localhost"));
        assert!(!bad_domain(b"LOCALHOST"));
        assert!(!bad_domain(b"example.com"));
        assert!(!bad_domain(b"a.b"));
        // `tests/data/test46` depends on a doubled dot being good.
        assert!(!bad_domain(b"domain..tld"));

        // No dot at all.
        assert!(bad_domain(b"se"));
        assert!(bad_domain(b"com"));
        assert!(bad_domain(b""));
        // The length gate means `localhost` with anything appended falls
        // through to the dot rule.
        assert!(bad_domain(b"mylocalhost"));
        // A trailing dot is not enough: *"that dot must not be a trailing
        // dot"*, and the dot examined is the FIRST one.
        assert!(bad_domain(b"example."));
        assert!(bad_domain(b"."));
        // Ten bytes, so the `localhost` arm's exact length test misses and the
        // dot rule applies -- and its only dot is the last byte.
        assert!(bad_domain(b"localhost."));
        // The dot examined is the FIRST one, so a first dot with something
        // after it is good however the name ends.
        assert!(!bad_domain(b"a.b."));
    }

    // -----------------------------------------------------------------------
    // `strncmp_prefix` -- the direction that makes field 2 fall through.
    // -----------------------------------------------------------------------

    #[test]
    fn strncmp_prefix_matches_the_cs_argument_order() {
        // A prefix of the literal matches, including the empty one.
        for span in [&b""[..], b"T", b"TR", b"TRU", b"TRUE"] {
            assert!(strncmp_prefix(TRUE_WORD, span), "{}", text(span));
        }
        // Anything longer, or different, does not.
        for span in [&b"TRUEX"[..], b"FALSE", b"true", b"X"] {
            assert!(!strncmp_prefix(TRUE_WORD, span), "{}", text(span));
        }
        assert!(strncmp_prefix(FALSE_WORD, b"F"));
        assert!(strncmp_prefix(FALSE_WORD, b"FALSE"));
        assert!(!strncmp_prefix(FALSE_WORD, b"FALSEHOOD"));
    }

    // -----------------------------------------------------------------------
    // `Curl_secure_context` -- `lib/cookie.c:1234-1240`.
    // -----------------------------------------------------------------------

    #[test]
    fn secure_context_has_four_terms() {
        // The scheme bit, for `https` and `wss`.
        assert!(secure_context(true, b"example.com"));

        // `localhost`, case-INsensitively.
        assert!(secure_context(false, b"localhost"));
        assert!(secure_context(false, b"LocalHost"));
        assert!(secure_context(false, b"LOCALHOST"));

        // The two literal addresses, case-sensitively -- which is invisible
        // for these two inputs and is reproduced as written anyway.
        assert!(secure_context(false, b"127.0.0.1"));
        assert!(secure_context(false, b"::1"));

        // Everything else over plain HTTP is not a secure context.
        assert!(!secure_context(false, b"example.com"));
        assert!(!secure_context(false, b"127.0.0.2"));
        assert!(!secure_context(false, b"localhost.localdomain"));
        assert!(!secure_context(false, b"0:0:0:0:0:0:0:1"));
        assert!(!secure_context(false, b""));
    }

    // -----------------------------------------------------------------------
    // The jar writer: `get_netscape_format` (`lib/cookie.c:1427-1451`) and
    // `cookie_output` (`:1461-1556`).
    // -----------------------------------------------------------------------

    #[test]
    fn the_jar_header_is_three_comments_and_one_blank_line() {
        // Transcribed from `tests/data/test1160`, whose whole expected jar is
        // these four lines and nothing else. The trailing blank line is unique
        // to the jar: `hsts.rs` and `altsvc.rs` each write a TWO-line header
        // with no blank line after it, and the three must not be unified.
        #[rustfmt::skip]
        let expected: &[u8] = b"\
# Netscape HTTP Cookie File\n\
# https://curl.se/docs/http-cookies.html\n\
# This file was generated by libcurl! Edit at your own risk.\n\
\n";

        assert_eq!(FILE_HEADER, expected);
        assert_eq!(FILE_HEADER.len(), 131);
        // The header is one `fputs` of a single literal whose last two bytes
        // are newlines (`:1488-1491`).
        assert!(FILE_HEADER.ends_with(b".\n\n"));
        assert_eq!(FILE_HEADER.iter().filter(|&&b| b == b'\n').count(), 4);
        assert_eq!(FILE_HEADER.iter().filter(|&&b| b == b'#').count(), 3);
    }

    #[test]
    fn an_empty_jar_is_still_written() {
        // `:1493` returns after the header when there is nothing to list, so
        // the file exists and holds exactly the header. `tests/data/test1160`
        // compares that jar byte for byte.
        let jar = CookieInfo::new();
        assert_eq!(jar.numcookies(), 0);
        assert_eq!(saved(&jar), FILE_HEADER);
    }

    #[test]
    fn a_jar_entry_is_seven_tab_separated_fields() {
        let cookie = Cookie {
            name: b"cookiename".to_vec(),
            value: Some(b"cookiecontent".to_vec()),
            path: Some(b"/".to_vec()),
            domain: Some(b"127.0.0.1".to_vec()),
            ..Cookie::default()
        };

        // `tests/data/test1920`'s first expected line, with `%HOSTIP`
        // resolved.
        assert_eq!(
            get_netscape_format(&cookie),
            b"127.0.0.1\tFALSE\t/\tFALSE\t0\tcookiename\tcookiecontent"
        );

        let line = get_netscape_format(&cookie);
        // Tabs, and exactly six of them.
        assert_eq!(line.iter().filter(|&&b| b == b'\t').count(), 6);
        assert!(!line.contains(&b' '));
        // `get_netscape_format` does NOT terminate the line: the caller does,
        // with `curl_mfprintf(out, "%s\n", ...)` at `:1524`.
        assert!(!line.ends_with(b"\n"));
    }

    #[test]
    fn the_two_boolean_fields_are_uppercase_words() {
        assert_eq!(TRUE_WORD, b"TRUE");
        assert_eq!(FALSE_WORD, b"FALSE");

        // Field 1 is `tailmatch`; field 3 is `secure`. They are independent.
        for (tailmatch, secure, expected) in [
            (false, false, &b"h\tFALSE\t/\tFALSE\t0\tn\tv"[..]),
            (false, true, b"h\tFALSE\t/\tTRUE\t0\tn\tv"),
            (true, false, b".h\tTRUE\t/\tFALSE\t0\tn\tv"),
            (true, true, b".h\tTRUE\t/\tTRUE\t0\tn\tv"),
        ] {
            let cookie = Cookie {
                name: b"n".to_vec(),
                value: Some(b"v".to_vec()),
                path: Some(b"/".to_vec()),
                domain: Some(b"h".to_vec()),
                tailmatch,
                secure,
                ..Cookie::default()
            };
            assert_eq!(get_netscape_format(&cookie), expected);
        }
    }

    #[test]
    fn the_httponly_prefix_goes_before_the_mozilla_dot() {
        assert_eq!(HTTPONLY_PREFIX, b"#HttpOnly_");

        // `tests/data/test46`'s expected jar contains
        // `#HttpOnly_domain..tld<TAB>FALSE<TAB>/want<TAB>...`, so the prefix
        // precedes the domain and the domain keeps no added dot when
        // `tailmatch` is clear.
        let mut cookie = Cookie {
            name: b"mooo2".to_vec(),
            value: Some(b"indeed2".to_vec()),
            path: Some(b"/want".to_vec()),
            domain: Some(b"domain..tld".to_vec()),
            expires: 2_139_150_993,
            httponly: true,
            ..Cookie::default()
        };
        assert_eq!(
            get_netscape_format(&cookie),
            b"#HttpOnly_domain..tld\tFALSE\t/want\tFALSE\t2139150993\
              \tmooo2\tindeed2"
        );

        // With `tailmatch` the dot lands BETWEEN the prefix and the domain --
        // `:1435` writes the prefix first and `:1439-1443` the dot second.
        cookie.tailmatch = true;
        assert!(get_netscape_format(&cookie)
            .starts_with(b"#HttpOnly_.domain..tld\tTRUE\t"));
    }

    #[test]
    fn the_mozilla_dot_is_prepended_only_when_it_is_needed() {
        let build = |domain: &[u8], tailmatch: bool| {
            get_netscape_format(&Cookie {
                name: b"n".to_vec(),
                value: Some(b"v".to_vec()),
                domain: Some(domain.to_vec()),
                tailmatch,
                ..Cookie::default()
            })
        };

        // `:1439` -- `co->tailmatch && co->domain && co->domain[0] != '.'`.
        assert!(build(b"example.com", true).starts_with(b".example.com\t"));
        assert!(build(b"example.com", false).starts_with(b"example.com\t"));
        // Already dotted: no second dot.
        assert!(build(b".example.com", true).starts_with(b".example.com\t"));
        // An EMPTY domain has no first byte, so the dot IS prepended --
        // `co->domain[0]` is the terminator, which is not `'.'`.
        assert!(build(b"", true).starts_with(b".\tTRUE\t"));
        assert!(build(b"", false).starts_with(b"\tFALSE\t"));
    }

    #[test]
    fn the_writer_has_three_fallback_literals_and_no_more() {
        // `:1444` -- a NULL domain prints `unknown`. Only a cookie set from a
        // header with no `Domain` attribute AND no default domain can reach
        // this, because `parse_netscape` always assigns a domain (possibly
        // empty). `tests/data/test8` creates exactly such cookies.
        assert_eq!(UNKNOWN_DOMAIN, b"unknown");
        assert_eq!(ROOT_PATH, b"/");

        let bare = Cookie {
            name: b"n".to_vec(),
            ..Cookie::default()
        };
        // domain `unknown`, path `/`, value empty -- and the trailing TAB
        // before the empty value is still written.
        assert_eq!(
            get_netscape_format(&bare),
            b"unknown\tFALSE\t/\tFALSE\t0\tn\t"
        );

        // An EMPTY domain is NOT absent, so it does not become `unknown`.
        let empty_domain = Cookie {
            name: b"n".to_vec(),
            domain: Some(Vec::new()),
            ..Cookie::default()
        };
        assert_eq!(
            get_netscape_format(&empty_domain),
            b"\tFALSE\t/\tFALSE\t0\tn\t"
        );

        // An EMPTY value likewise. `tests/data/test46` expects
        // `domain..tld<TAB>FALSE<TAB>/<TAB>FALSE<TAB>0<TAB>justaname<TAB>`.
        let empty_value = Cookie {
            name: b"justaname".to_vec(),
            value: Some(Vec::new()),
            path: Some(b"/".to_vec()),
            domain: Some(b"domain..tld".to_vec()),
            ..Cookie::default()
        };
        assert_eq!(
            get_netscape_format(&empty_value),
            b"domain..tld\tFALSE\t/\tFALSE\t0\tjustaname\t"
        );

        // The NAME has no fallback at all, and an empty one is reachable from
        // a jar line whose field 5 is empty.
        let empty_name = Cookie {
            value: Some(b"v".to_vec()),
            ..Cookie::default()
        };
        assert_eq!(
            get_netscape_format(&empty_name),
            b"unknown\tFALSE\t/\tFALSE\t0\t\tv"
        );
    }

    #[test]
    fn field_four_is_a_bare_decimal_and_zero_means_a_session_cookie() {
        let render = |expires: CurlOffT| {
            let line = get_netscape_format(&Cookie {
                name: b"n".to_vec(),
                value: Some(b"v".to_vec()),
                expires,
                ..Cookie::default()
            });
            let text = text(&line);
            text.split('\t')
                .nth(4)
                .map(str::to_owned)
                .unwrap_or_default()
        };

        // `docs/HTTP-COOKIES.md`: field 4 is *"the UNIX time when the cookie
        // expires... zero if it is a session cookie"*.
        assert_eq!(render(0), "0");
        assert_eq!(render(1), "1");
        assert_eq!(render(2_139_150_993), "2139150993");
        // `%if large-time` in `tests/data/test46` uses a value past 2038, so
        // the field is a 64-bit quantity and not a 32-bit `time_t`.
        assert_eq!(render(22_139_150_993), "22139150993");
        assert_eq!(render(CURL_OFF_T_MAX), "9223372036854775807");
        // No padding, no grouping, no sign for a positive value.
        assert_eq!(render(-1), "-1");
        assert_eq!(itoa(0), "0");
    }

    #[test]
    fn a_jar_line_may_hold_bytes_that_are_not_text() {
        // `tests/data/test31` stores a cookie whose name and value are both
        // high-bit bytes, so the writer must be byte-transparent.
        let cookie = Cookie {
            name: b"\xe5\xe4\xf6".to_vec(),
            value: Some(b"\xf6\xe4\xe5".to_vec()),
            path: Some(b"/".to_vec()),
            domain: Some(b"example.com".to_vec()),
            ..Cookie::default()
        };
        assert_eq!(
            get_netscape_format(&cookie),
            b"example.com\tFALSE\t/\tFALSE\t0\t\xe5\xe4\xf6\t\xf6\xe4\xe5"
        );
    }

    #[test]
    fn the_writer_emits_in_descending_creation_time() {
        // `tests/data/test1920`'s expected jar, which puts the cookie received
        // from the response ABOVE the one loaded from the file even though the
        // file was read first. That is `cookie_sort_ct` at `:1514`.
        let mut jar = CookieInfo::new();
        let clock = clock_at(1_000_000);

        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t0\thas_js\t1",
            &clock
        ));
        jar.run();
        assert!(add_header(
            &mut jar,
            b" cookiename=cookiecontent;",
            Some(b"127.0.0.1"),
            Some(b"/"),
            false,
            &clock
        ));

        #[rustfmt::skip]
        let expected: Vec<u8> = [
            FILE_HEADER,
            b"127.0.0.1\tFALSE\t/\tFALSE\t0\tcookiename\tcookiecontent\n",
            b"example.com\tFALSE\t/\tFALSE\t0\thas_js\t1\n",
        ]
        .concat();

        assert_eq!(text(&saved(&jar)), text(&expected));
    }

    #[test]
    fn only_cookies_with_a_domain_are_written() {
        // `:1505-1512` -- *"just ignore whatever failed"*: a cookie with no
        // domain is skipped by the collector, so it is counted by
        // `numcookies` and never appears in the file. `tests/data/test8`'s
        // header-format cookie file produces several of them.
        let mut jar = CookieInfo::new();
        let clock = clock_at(1_000_000);

        assert!(add_header(
            &mut jar,
            b" nodomain=here; path=/we",
            None,
            None,
            false,
            &clock
        ));
        assert!(add_header(
            &mut jar,
            b" withdomain=here; domain=example.com",
            None,
            None,
            false,
            &clock
        ));

        assert_eq!(jar.numcookies(), 2);
        let bytes = saved(&jar);
        assert!(!text(&bytes).contains("nodomain"));
        assert!(!text(&bytes).contains("unknown"));
        assert!(text(&bytes).contains("withdomain"));
        // Header, then exactly one entry line.
        assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 5);
    }

    // -----------------------------------------------------------------------
    // The jar reader: `parse_netscape` (`lib/cookie.c:650-772`).
    // -----------------------------------------------------------------------

    #[test]
    fn the_httponly_prefix_is_tested_before_the_comment_rule() {
        let clock = clock_at(1_000_000);

        // `:664-668` consumes ten bytes and sets `httponly`; ONLY THEN does
        // `:670-671` reject a line beginning `#`. Reversing the two would make
        // every HttpOnly line a comment, and `tests/data/test46` would lose
        // `mooo2` from both its jar and its `Cookie:` header.
        let jar = load_text(
            b"#HttpOnly_example.com\tFALSE\t/\tFALSE\t0\tn\tv\n",
            &clock,
        );
        assert_eq!(jar.numcookies(), 1);
        let stored = only(&jar);
        assert!(stored.httponly());
        assert_eq!(stored.domain(), Some(&b"example.com"[..]));
        // It round-trips with the prefix back in place.
        assert!(text(&saved(&jar)).contains("#HttpOnly_example.com\t"));

        // CASE-SENSITIVE: `strncmp`, not `curl_strnequal`. A differently-cased
        // spelling is an ordinary comment and stores nothing.
        for spelling in [
            &b"#httponly_example.com\tFALSE\t/\tFALSE\t0\tn\tv\n"[..],
            b"#HTTPONLY_example.com\tFALSE\t/\tFALSE\t0\tn\tv\n",
            b"#HttpOnly example.com\tFALSE\t/\tFALSE\t0\tn\tv\n",
        ] {
            let jar = load_text(spelling, &clock);
            assert_eq!(jar.numcookies(), 0, "{}", text(spelling));
        }

        // And an ordinary comment is still a comment.
        let jar = load_text(b"# a comment\n#\n", &clock);
        assert_eq!(jar.numcookies(), 0);
    }

    #[test]
    fn field_zero_strips_exactly_one_leading_dot_and_is_never_absent() {
        let clock = clock_at(1_000_000);

        let domain_of = |line: &[u8]| {
            first(&load_text(line, &clock))
                .map(|cookie| cookie.domain().map(<[u8]>::to_vec))
        };

        // `:678-681`
        assert_eq!(
            domain_of(b".example.com\tTRUE\t/\tFALSE\t0\tn\tv\n"),
            Some(Some(b"example.com".to_vec()))
        );
        // Exactly ONE dot.
        assert_eq!(
            domain_of(b"..example.com\tTRUE\t/\tFALSE\t0\tn\tv\n"),
            Some(Some(b".example.com".to_vec()))
        );
        // No dot to strip.
        assert_eq!(
            domain_of(b"example.com\tTRUE\t/\tFALSE\t0\tn\tv\n"),
            Some(Some(b"example.com".to_vec()))
        );
        // An EMPTY field 0 still ASSIGNS the domain -- as `Some(b"")`, never
        // `None`. This is why the writer's `unknown` fallback is unreachable
        // for a jar-loaded cookie.
        assert_eq!(
            domain_of(b"\tTRUE\t/\tFALSE\t0\tn\tv\n"),
            Some(Some(Vec::new()))
        );
    }

    #[test]
    fn field_one_is_a_length_limited_prefix_test_that_never_rejects() {
        let clock = clock_at(1_000_000);

        let tailmatch_of = |field: &[u8]| {
            let mut line = Vec::new();
            line.extend_from_slice(b"example.com\t");
            line.extend_from_slice(field);
            line.extend_from_slice(b"\t/\tFALSE\t0\tn\tv\n");
            first(&load_text(&line, &clock)).map(|cookie| cookie.tailmatch())
        };

        // `:684` -- `!!curl_strnequal(ptr, "TRUE", len)`, so any PREFIX of
        // `TRUE` counts, including the empty one: `ncasecompare` with `max ==
        // 0` returns 1 at `lib/strequal.c:60-61`.
        for field in [&b"TRUE"[..], b"T", b"TR", b"TRU", b"true", b"tRuE", b""]
        {
            assert_eq!(
                tailmatch_of(field),
                Some(true),
                "field 1 = {}",
                text(field)
            );
        }

        // Anything else is FALSE -- **and the line is NOT dropped.** Only
        // fields 3 and 4 can drop a line.
        for field in [&b"FALSE"[..], b"banana", b"TRUEX", b"X", b"0"] {
            assert_eq!(
                tailmatch_of(field),
                Some(false),
                "field 1 = {}",
                text(field)
            );
        }
    }

    #[test]
    fn field_two_falls_through_and_absorbs_a_six_field_line() {
        let clock = clock_at(1_000_000);

        // `:690-700` -- when field 2 looks like a BOOLEAN the path becomes
        // `"/"`, `fields` is bumped and control drops into the field-3 arm
        // with the SAME token. That is how a six-field file is read.
        let jar =
            load_text(b"example.com\tFALSE\tTRUE\t0\tsix\tfields\n", &clock);
        assert_eq!(jar.numcookies(), 1);
        let stored = only(&jar);
        assert_eq!(stored.path(), Some(&b"/"[..]));
        assert!(stored.secure());
        assert_eq!(stored.expires(), 0);
        assert_eq!(stored.name(), b"six");
        assert_eq!(stored.value(), Some(&b"fields"[..]));

        // An EMPTY field 2 also falls through: `strncmp` is length-limited,
        // so a zero length compares equal to both literals. The token it then
        // hands field 3 is also empty, and `ncasecompare` with `max == 0`
        // answers TRUE (`lib/strequal.c:60-61`), so `secure` ends up SET.
        let jar = load_text(b"example.com\tFALSE\t\t0\tn\tv\n", &clock);
        let stored = only(&jar);
        assert_eq!(stored.path(), Some(&b"/"[..]));
        assert!(stored.secure());
        assert_eq!(stored.expires(), 0);
        assert_eq!(stored.name(), b"n");

        // The fall-through only reconciles a SIX-field line. A line that has
        // all seven fields AND an empty field 2 ends up counting EIGHT, and
        // `fields != 7` drops it -- the count is bumped by the fall-through
        // whether or not the file was short.
        let jar = load_text(b"example.com\tFALSE\t\tFALSE\t0\tn\tv\n", &clock);
        assert_eq!(jar.numcookies(), 0);

        // `strncmp` is CASE-SENSITIVE, so a lowercase spelling is a genuine
        // path -- which then fails `sanitize_cookie_path`'s rooted test and
        // becomes `"/"` anyway, but through the OTHER arm, so the line keeps
        // seven fields.
        let jar =
            load_text(b"example.com\tFALSE\ttrue\tFALSE\t0\tn\tv\n", &clock);
        assert_eq!(only(&jar).path(), Some(&b"/"[..]));

        // A real path is sanitised on the way in.
        let jar =
            load_text(b"example.com\tFALSE\t/want/\tFALSE\t0\tn\tv\n", &clock);
        assert_eq!(only(&jar).path(), Some(&b"/want"[..]));
    }

    #[test]
    fn field_three_sets_secure_and_only_drops_through_the_inverted_gate() {
        let clock = clock_at(1_000_000);

        let secure_of = |field: &[u8], running: bool| {
            let mut line = Vec::new();
            line.extend_from_slice(b"example.com\tFALSE\t/\t");
            line.extend_from_slice(field);
            line.extend_from_slice(b"\t0\tn\tv");
            let mut jar = CookieInfo::new();
            if running {
                jar.run();
            }
            let stored = matches!(
                jar.add(
                    &line,
                    &AddContext {
                        httpheader: false,
                        noexpire: true,
                        domain: None,
                        path: None,
                        // `secure = FALSE`, which the real loaders never pass;
                        // it is the only way to reach the gate's else arm.
                        secure: false,
                        setcookies: 0,
                    },
                    &clock,
                    &NoLog,
                    None,
                ),
                Ok(true)
            );
            (stored, first(&jar).map(|cookie| cookie.secure()))
        };

        // `:721-731`. `co->secure` is cleared FIRST, so a field that is not
        // TRUE-looking leaves it clear and the line survives whatever
        // `running` is. A non-boolean value does NOT drop the line.
        for field in [&b"FALSE"[..], b"F", b"banana", b"0"] {
            assert_eq!(
                secure_of(field, false),
                (true, Some(false)),
                "field 3 = {}",
                text(field)
            );
            assert_eq!(secure_of(field, true), (true, Some(false)));
        }

        // A TRUE-looking field enters the gate `if(secure || ci->running)`.
        // Note: NO negation, unlike the header parser's `:520`.
        for field in [&b"TRUE"[..], b"T", b"true", b""] {
            // Not running and not a secure origin: DROPPED.
            assert_eq!(
                secure_of(field, false),
                (false, None),
                "field 3 = {}",
                text(field)
            );
            // Running: stored, and secure.
            assert_eq!(secure_of(field, true), (true, Some(true)));
        }

        // Which is why the real loader passes `secure = TRUE` at `:1131`: a
        // secure cookie in a jar loads whatever the connection is.
        let jar = load_text(b"example.com\tFALSE\t/\tTRUE\t0\tn\tv\n", &clock);
        assert!(only(&jar).secure());
    }

    #[test]
    fn field_four_drops_the_line_when_it_is_not_a_number() {
        // The epoch itself, so that an expiry of `1` is not swept by the
        // `remove_expired` that `read_from` runs once at the end of the file.
        let clock = clock_at(0);

        let expires_of = |field: &[u8]| {
            let mut line = Vec::new();
            line.extend_from_slice(b"example.com\tFALSE\t/\tFALSE\t");
            line.extend_from_slice(field);
            line.extend_from_slice(b"\tn\tv\n");
            first(&load_text(&line, &clock)).map(|cookie| cookie.expires())
        };

        // `:735-739`
        assert_eq!(expires_of(b"0"), Some(0));
        assert_eq!(expires_of(b"1"), Some(1));
        assert_eq!(expires_of(b"2139150993"), Some(2_139_150_993));
        // `tests/data/test46`'s `%if large-time` branch.
        assert_eq!(expires_of(b"22139150993"), Some(22_139_150_993));

        // `curlx_str_number` reads digits from the cursor and stops at the
        // first byte that is not one; it does NOT require the whole field to be
        // consumed, and `parse_netscape` never checks the field length here.
        // So trailing rubbish is simply ignored.
        assert_eq!(expires_of(b"1x"), Some(1));
        assert_eq!(expires_of(b"12 34"), Some(12));

        // A parse failure DROPS the line -- one of only two field-level drops.
        // No digit at all, or a value past `CURL_OFF_T_MAX`.
        for field in [
            &b""[..],
            b"banana",
            b"-1",
            b" 1",
            b"+1",
            b"99999999999999999999999999",
            b"9223372036854775808",
        ] {
            assert_eq!(expires_of(field), None, "field 4 = {}", text(field));
        }
    }

    #[test]
    fn the_reserved_prefixes_are_case_insensitive_in_a_jar_line() {
        let clock = clock_at(1_000_000);

        // Field 3 is TRUE throughout, because `Curl_cookie_add` STEP 3
        // (`:968-970`) refuses a `__Secure-` cookie that is not secure and
        // STEP 4 (`:972-982`) refuses a `__Host-` cookie that is not secure,
        // not rooted at `"/"`, or tail-matching. The prefix flags are only
        // observable on a cookie that survives those two gates.
        let flags_of = |name: &[u8]| {
            let mut line = Vec::new();
            line.extend_from_slice(b"example.com\tFALSE\t/\tTRUE\t0\t");
            line.extend_from_slice(name);
            line.extend_from_slice(b"\tv\n");
            first(&load_text(&line, &clock))
                .map(|cookie| (cookie.prefix_secure(), cookie.prefix_host()))
        };

        // `:744` and `:746` use `curl_strnequal`, so case does NOT matter
        // here -- whereas the HEADER parser's `:501`/`:503` use `strncmp` and
        // it does. The asymmetry is deliberate and is preserved.
        assert_eq!(flags_of(b"__Secure-x"), Some((true, false)));
        assert_eq!(flags_of(b"__secure-x"), Some((true, false)));
        assert_eq!(flags_of(b"__SECURE-X"), Some((true, false)));
        assert_eq!(flags_of(b"__hOsT-x"), Some((false, true)));
        assert_eq!(flags_of(b"ordinary"), Some((false, false)));
        assert_eq!(flags_of(b"__Secur-x"), Some((false, false)));
    }

    #[test]
    fn a_line_needs_seven_fields_and_six_are_completed_with_an_empty_value() {
        let clock = clock_at(1_000_000);

        // `:757-760` -- exactly six fields means an absent VALUE, which
        // becomes empty and brings the count to seven.
        let jar =
            load_text(b"example.com\tFALSE\t/want\tFALSE\t0\tempty\n", &clock);
        assert_eq!(only(&jar).value(), Some(&b""[..]));

        // `tests/data/test46`'s `empty%TAB` line: a TRAILING TAB makes a
        // seventh, empty field, which is the same outcome by a different
        // route.
        let jar = load_text(
            b"domain..tld\tFALSE\t/want\tFALSE\t0\tempty\t\n",
            &clock,
        );
        assert_eq!(only(&jar).value(), Some(&b""[..]));

        // `:761-764` -- anything else is dropped.
        for line in [
            &b"example.com\n"[..],
            b"example.com\tFALSE\n",
            b"example.com\tFALSE\t/\n",
            b"example.com\tFALSE\t/\tFALSE\n",
            b"example.com\tFALSE\t/\tFALSE\t0\n",
            b"example.com\tFALSE\t/\tFALSE\t0\tn\tv\textra\n",
            b"\n",
        ] {
            let jar = load_text(line, &clock);
            assert_eq!(jar.numcookies(), 0, "{}", text(line));
        }
    }

    #[test]
    fn a_carriage_return_is_a_field_terminator_so_crlf_jars_load() {
        let clock = clock_at(1_000_000);

        // `len = strcspn(ptr, "\t\r\n")` at `:674`, so a CR ends the last
        // field rather than becoming part of the value.
        assert_eq!(FIELD_DELIMITERS, b"\t\r\n");
        let jar =
            load_text(b"example.com\tFALSE\t/\tFALSE\t0\tn\tv\r\n", &clock);
        assert_eq!(only(&jar).value(), Some(&b"v"[..]));
    }

    // -----------------------------------------------------------------------
    // THE ROUND TRIP -- the single most important test in this directory.
    //
    // The bytes below are `tests/data/test46`'s paired input and expected
    // jars, which is to say bytes curl 8.19.0-DEV wrote and bytes it read.
    // Nothing here is derived from this implementation.
    // -----------------------------------------------------------------------

    /// `tests/data/test46`'s `injar46`, with the canonical header substituted
    /// for the one that fixture happens to carry (any `#` line is a comment,
    /// so the header text does not affect the parse) and `%if large-time`
    /// resolved to its `%else` branch.
    #[rustfmt::skip]
    const JAR_ASCENDING: &[u8] = b"\
# Netscape HTTP Cookie File\n\
# https://curl.se/docs/http-cookies.html\n\
# This file was generated by libcurl! Edit at your own risk.\n\
\n\
www.fake.come\tFALSE\t/\tFALSE\t2147483647\tcookiecliente\tsi\n\
www.loser.com\tFALSE\t/\tFALSE\t2139150993\tUID\t99\n\
domain..tld\tFALSE\t/\tFALSE\t2139150993\tmooo\tindeed\n\
#HttpOnly_domain..tld\tFALSE\t/want\tFALSE\t2139150993\tmooo2\tindeed2\n\
domain..tld\tFALSE\t/want\tFALSE\t0\tempty\t\n";

    /// The same five entries in the order the writer produces from them, which
    /// is the last five lines of `tests/data/test46`'s expected `jar46`.
    #[rustfmt::skip]
    const JAR_DESCENDING: &[u8] = b"\
# Netscape HTTP Cookie File\n\
# https://curl.se/docs/http-cookies.html\n\
# This file was generated by libcurl! Edit at your own risk.\n\
\n\
domain..tld\tFALSE\t/want\tFALSE\t0\tempty\t\n\
#HttpOnly_domain..tld\tFALSE\t/want\tFALSE\t2139150993\tmooo2\tindeed2\n\
domain..tld\tFALSE\t/\tFALSE\t2139150993\tmooo\tindeed\n\
www.loser.com\tFALSE\t/\tFALSE\t2139150993\tUID\t99\n\
www.fake.come\tFALSE\t/\tFALSE\t2147483647\tcookiecliente\tsi\n";

    /// A moment before every dated entry above expires.
    const BEFORE_EXPIRY: i64 = 1_000_000_000;

    #[test]
    fn a_curl_written_jar_reads_back_into_five_faithful_cookies() {
        let clock = clock_at(BEFORE_EXPIRY);
        let jar = load_text(JAR_ASCENDING, &clock);
        assert_eq!(jar.numcookies(), 5);

        // Insertion order, which is also creation-time order because
        // `co->creationtime = ++ci->lastct` (`:988`). The store is bucketed, so
        // `cookies()` walks buckets and this asserts the parse rather than the
        // order -- the order is asserted by the writer tests below.
        let mut byname: Vec<(Vec<u8>, Cookie)> = all(&jar)
            .into_iter()
            .map(|cookie| (cookie.name().to_vec(), cookie))
            .collect();
        byname.sort_by(|left, right| left.0.cmp(&right.0));
        let names: Vec<String> =
            byname.iter().map(|(name, _)| text(name)).collect();
        assert_eq!(
            names,
            vec!["UID", "cookiecliente", "empty", "mooo", "mooo2"]
        );

        let find = |wanted: &[u8]| -> Cookie {
            let mut hits: Vec<Cookie> = all(&jar)
                .into_iter()
                .filter(|cookie| cookie.name() == wanted)
                .collect();
            assert_eq!(hits.len(), 1, "{} must be stored once", text(wanted));
            hits.pop().unwrap_or_default()
        };

        let mooo2 = find(b"mooo2");
        assert!(mooo2.httponly());
        assert_eq!(mooo2.domain(), Some(&b"domain..tld"[..]));
        assert_eq!(mooo2.path(), Some(&b"/want"[..]));
        assert!(!mooo2.tailmatch());
        assert!(!mooo2.secure());
        assert_eq!(mooo2.expires(), 2_139_150_993);
        assert_eq!(mooo2.value(), Some(&b"indeed2"[..]));
        // Loaded from a file, so NOT live -- which is what stops it replacing
        // a cookie that arrived in a response (`:896-904`).
        assert!(!mooo2.livecookie());

        // The trailing TAB gave `empty` a seventh, empty field.
        let empty = find(b"empty");
        assert_eq!(empty.value(), Some(&b""[..]));
        assert_eq!(empty.expires(), 0);
        assert!(!empty.httponly());

        // Creation times are 1..=5 in file order, with no gaps.
        let mut times: Vec<u32> =
            all(&jar).iter().map(Cookie::creationtime).collect();
        times.sort_unstable();
        assert_eq!(times, vec![1, 2, 3, 4, 5]);
        assert_eq!(jar.lastct(), 5);

        // `next_expiration` is the earliest FUTURE expiry, ignoring the
        // session cookie's zero (`:1033-1038`).
        assert_eq!(jar.next_expiration(), 2_139_150_993);
    }

    #[test]
    fn writing_a_loaded_jar_reproduces_curls_bytes_exactly() {
        let clock = clock_at(BEFORE_EXPIRY);
        let jar = load_text(JAR_ASCENDING, &clock);

        // ONE pass REVERSES the file, because creation times ascend with read
        // order while `cookie_sort_ct` (`:1226`) descends. This is not a
        // deficiency: `tests/data/test46` expects exactly this, its input jar
        // and its expected jar being reverses of one another.
        assert_eq!(text(&saved(&jar)), text(JAR_DESCENDING));

        // TWO passes are therefore the identity.
        let round = load_text(&saved(&jar), &clock);
        assert_eq!(text(&saved(&round)), text(JAR_ASCENDING));

        // And a third agrees with the first, so the cycle is exactly two.
        let thrice = load_text(&saved(&round), &clock);
        assert_eq!(saved(&thrice), saved(&jar));
    }

    #[test]
    fn a_round_trip_preserves_every_flag_and_every_edge_case() {
        let clock = clock_at(BEFORE_EXPIRY);

        // One line per hazard: HttpOnly, a tail-matching domain that gains its
        // Mozilla dot back, a secure cookie, a session cookie, an empty value,
        // an IP-numeric domain (which hashes to bucket 0), a six-field line
        // completed to seven, a non-UTF-8 name and value, and a 2^40 expiry.
        #[rustfmt::skip]
        let written: &[u8] = b"\
#HttpOnly_secret.example\tFALSE\t/admin\tTRUE\t2139150993\tsid\tabc\n\
.wild.example\tTRUE\t/\tFALSE\t2139150993\twide\tyes\n\
127.0.0.1\tFALSE\t/\tFALSE\t0\tlocal\t1\n\
plain.example\tFALSE\t/\tFALSE\t0\tblank\t\n\
bytes.example\tFALSE\t/\tFALSE\t1099511627776\t\xe5\xe4\xf6\t\xf6\xe4\xe5\n";

        let mut input = Vec::new();
        input.extend_from_slice(FILE_HEADER);
        input.extend_from_slice(written);

        let jar = load_text(&input, &clock);
        assert_eq!(jar.numcookies(), 5);

        // The writer reverses, so reversing the expectation recovers the file.
        let lines: Vec<&[u8]> = written
            .split(|&byte| byte == b'\n')
            .filter(|line| !line.is_empty())
            .collect();
        let mut expected = FILE_HEADER.to_vec();
        for line in lines.iter().rev() {
            expected.extend_from_slice(line);
            expected.push(b'\n');
        }
        assert_eq!(text(&saved(&jar)), text(&expected));

        // Two passes are the identity here too.
        let round = load_text(&saved(&jar), &clock);
        assert_eq!(text(&saved(&round)), text(&input));
    }

    #[test]
    fn a_session_cookie_survives_a_round_trip_as_a_session_cookie() {
        // `docs/HTTP-COOKIES.md`: field 4 is *"zero if it is a session
        // cookie"*, and `--junk-session-cookies` is the only thing that drops
        // one on load.
        let clock = clock_at(BEFORE_EXPIRY);
        let jar = load_text(JAR_ASCENDING, &clock);
        let sessions: Vec<Cookie> = all(&jar)
            .into_iter()
            .filter(|cookie| cookie.expires() == 0)
            .collect();
        assert_eq!(sessions.len(), 1);
        assert!(text(&saved(&jar)).contains("\tFALSE\t0\tempty\t\n"));

        // With `newsession` set -- `CURLOPT_COOKIESESSION`, which
        // `--junk-session-cookies` sets -- the same file loses it (`:984-987`).
        let mut junked = CookieInfo::new();
        junked.set_newsession(true);
        let mut input = JAR_ASCENDING;
        assert!(junked.read_from(&mut input, &clock, &NoLog, None).is_ok());
        assert_eq!(junked.numcookies(), 4);
        assert!(!text(&saved(&junked)).contains("empty"));
    }

    #[test]
    fn an_expired_entry_is_swept_by_the_load_and_never_written_back() {
        // `cookie_load` runs ONE sweep after the whole file (`:1131`), so an
        // entry whose expiry has passed is read, stored and then dropped.
        let clock = clock_at(2_139_150_994);
        let jar = load_text(JAR_ASCENDING, &clock);

        // `mooo`, `mooo2` and `UID` all expire at 2139150993, which is now
        // PAST; `cookiecliente` and the session cookie survive.
        assert_eq!(jar.numcookies(), 2);
        let saved_text = text(&saved(&jar));
        assert!(saved_text.contains("cookiecliente"));
        assert!(saved_text.contains("empty"));
        assert!(!saved_text.contains("mooo"));
        assert!(!saved_text.contains("UID"));
    }

    // -----------------------------------------------------------------------
    // `Set-Cookie:` parsing -- `parse_cookie_header` (`lib/cookie.c:427-648`).
    // -----------------------------------------------------------------------

    #[test]
    fn the_first_pair_is_the_cookie_and_blanks_are_trimmed() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `tests/data/test8` proves both trims: `name with space` keeps its
        // inner spaces, and `trailingspace    = removed` loses the run before
        // the `=` and the one after it.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" name with space=is weird but; path=/we/want;",
            None,
            None,
            false,
            &clock
        ));
        let stored = only(&jar);
        assert_eq!(stored.name(), b"name with space");
        assert_eq!(stored.value(), Some(&b"is weird but"[..]));

        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" trailingspace    = removed; path=/we/want;",
            None,
            None,
            false,
            &clock
        ));
        let stored = only(&jar);
        assert_eq!(stored.name(), b"trailingspace");
        assert_eq!(stored.value(), Some(&b"removed"[..]));

        // The C's caller hands over the bytes after `Set-Cookie:` INCLUDING
        // the leading space and the trailing CRLF (`lib/http.c:3187`), and
        // both delimiter sets plus `trimblanks` absorb them.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" crlf=terminated\r\n",
            None,
            None,
            false,
            &clock
        ));
        assert_eq!(only(&jar).value(), Some(&b"terminated"[..]));
    }

    #[test]
    fn a_pair_with_no_equals_sign_is_not_a_cookie() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `:487` -- `if(!sep)`, plus the octet and emptiness tests, share one
        // diagnostic at `:492`.
        for line in [&b" justaword"[..], b" =novalue", b" ; ;"] {
            let mut jar = CookieInfo::new();
            let outcome = jar.add(
                line,
                &header_ctx(None, None, false),
                &clock,
                &log,
                None,
            );
            assert_eq!(outcome, Ok(false), "{}", text(line));
            assert_eq!(jar.numcookies(), 0);
        }
        assert!(log.said("invalid octets in name/value, cookie dropped"));

        // An EMPTY value with the `=` present IS a cookie --
        // `tests/data/test46`'s `justaname=`.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" justaname=; path=/;",
            None,
            None,
            false,
            &clock
        ));
        let stored = only(&jar);
        assert_eq!(stored.name(), b"justaname");
        assert_eq!(stored.value(), Some(&b""[..]));
    }

    #[test]
    fn the_two_delimiter_sets_differ_by_one_byte() {
        // `:455` and `:459`. The NAME set contains TAB; the VALUE set does
        // not, which is why a TAB inside a value reaches the dedicated
        // rejection at `:512` instead of ending the token.
        assert_eq!(NAME_DELIMITERS, b";\t\r\n=");
        assert_eq!(VALUE_DELIMITERS, b";\r\n");
        assert!(NAME_DELIMITERS.contains(&b'\t'));
        assert!(!VALUE_DELIMITERS.contains(&b'\t'));
        assert!(NAME_DELIMITERS.contains(&b'='));
        assert!(!VALUE_DELIMITERS.contains(&b'='));

        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // A TAB in the middle of the value: not a terminator, and not
        // survivable.
        let mut jar = CookieInfo::new();
        let outcome = jar.add(
            b" tabbed=has\there; path=/",
            &header_ctx(None, None, false),
            &clock,
            &log,
            None,
        );
        assert_eq!(outcome, Ok(false));
        assert!(log.said("cookie contains TAB, dropping"));

        // A TRAILING TAB is stripped by `trimblanks` BEFORE that test, so
        // `tests/data/test8`'s `cookie9=junk--<TAB>` survives as `junk--`.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" cookie9=junk--\t",
            None,
            None,
            false,
            &clock
        ));
        assert_eq!(only(&jar).value(), Some(&b"junk--"[..]));

        // An `=` inside the VALUE is ordinary data, because the value's set
        // does not contain it.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" b64=YWJjZA==; path=/",
            None,
            None,
            false,
            &clock
        ));
        assert_eq!(only(&jar).value(), Some(&b"YWJjZA=="[..]));
    }

    #[test]
    fn the_octet_rules_accept_what_browsers_accept() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `tests/data/test8` sends one cookie per control byte and expects
        // every one of them to be dropped, `cookie9`'s trailing TAB excepted.
        for byte in 1u8..=0x1f {
            if byte == b'\t' || byte == b'\r' || byte == b'\n' {
                // TAB is legal in the octet test, and CR and LF terminate the
                // value rather than appearing in it.
                continue;
            }
            let mut line = b" ctl=".to_vec();
            line.push(byte);
            line.extend_from_slice(b"-junk");
            let mut jar = CookieInfo::new();
            assert!(
                !add_header(&mut jar, &line, None, None, false, &clock),
                "byte {byte:#04x} must be refused"
            );
        }

        // `\x7f` too -- `tests/data/test8`'s last line.
        let mut jar = CookieInfo::new();
        assert!(!add_header(
            &mut jar,
            b" ctl=\x7f-junk",
            None,
            None,
            false,
            &clock
        ));

        // Space, comma and double quote are ACCEPTED. The C's comment names
        // Firefox and Chrome as of June 2022.
        for value in [&b"has space"[..], b"has,comma", b"has\"quote"] {
            let mut line = b" ok=".to_vec();
            line.extend_from_slice(value);
            line.extend_from_slice(b"; path=/");
            let mut jar = CookieInfo::new();
            assert!(
                add_header(&mut jar, &line, None, None, false, &clock),
                "{} must be accepted",
                text(value)
            );
            assert_eq!(only(&jar).value(), Some(value));
        }

        // And so is every byte at or above 0x80 -- `tests/data/test31`.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" \xe5\xe4\xf6=\xf6\xe4\xe5; path=/",
            None,
            None,
            false,
            &clock
        ));
        assert_eq!(only(&jar).name(), b"\xe5\xe4\xf6");
    }

    #[test]
    fn an_oversized_name_or_value_is_dropped_and_named() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `:496-499` -- three tests, all against `MAX_NAME`: the name alone,
        // the value alone, and the pair.
        let big = vec![b'x'; MAX_NAME];
        let mut line = b" n=".to_vec();
        line.extend_from_slice(&big);
        let mut jar = CookieInfo::new();
        let outcome =
            jar.add(&line, &header_ctx(None, None, false), &clock, &log, None);
        assert_eq!(outcome, Ok(false));
        assert!(log.said("oversized cookie dropped, name/val"));

        let mut line = b" ".to_vec();
        line.extend_from_slice(&big);
        line.extend_from_slice(b"=v");
        let mut jar = CookieInfo::new();
        assert!(!add_header(&mut jar, &line, None, None, false, &clock));

        // The pair test is `namelen + valuelen > MAX_NAME`, so two halves that
        // each pass individually can still fail together.
        let half = vec![b'y'; MAX_NAME / 2];
        let mut line = b" ".to_vec();
        line.extend_from_slice(&half);
        line.push(b'=');
        line.extend_from_slice(&half);
        line.push(b'z');
        let mut jar = CookieInfo::new();
        assert!(!add_header(&mut jar, &line, None, None, false, &clock));

        // `tests/data/test46`'s `simplyhuge` is 3998 bytes and IS accepted.
        let mut line = b" simplyhuge=".to_vec();
        line.extend_from_slice(&vec![b'z'; 3998]);
        let mut jar = CookieInfo::new();
        assert!(add_header(&mut jar, &line, None, None, false, &clock));
        assert_eq!(only(&jar).value().map(<[u8]>::len), Some(3998));
    }

    #[test]
    fn a_line_past_the_ceiling_is_discarded_in_silence() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `:447-449` -- no diagnostic at all, which is the whole point of
        // asserting the sink stayed empty.
        let mut line = b" n=".to_vec();
        line.extend_from_slice(&vec![b'v'; MAX_COOKIE_LINE]);
        assert!(line.len() > MAX_COOKIE_LINE);

        let mut jar = CookieInfo::new();
        let outcome =
            jar.add(&line, &header_ctx(None, None, false), &clock, &log, None);
        assert_eq!(outcome, Ok(false));
        assert_eq!(jar.numcookies(), 0);
        assert_eq!(log.count(), 0, "{}", log.joined());

        // Exactly at the ceiling it is parsed -- and then refused by the
        // `MAX_NAME` test, which is a different refusal with a diagnostic.
        let mut line = b" n=".to_vec();
        line.extend_from_slice(&vec![b'v'; MAX_COOKIE_LINE - 3]);
        assert_eq!(line.len(), MAX_COOKIE_LINE);
        let mut jar = CookieInfo::new();
        assert!(!add_header(&mut jar, &line, None, None, false, &clock));
    }

    #[test]
    fn the_reserved_prefixes_are_case_sensitive_in_a_header() {
        let clock = clock_at(BEFORE_EXPIRY);

        assert_eq!(PREFIX_SECURE_NAME, b"__Secure-");
        assert_eq!(PREFIX_HOST_NAME, b"__Host-");

        let flags_of = |line: &[u8]| {
            let mut jar = CookieInfo::new();
            let stored = add_header(&mut jar, line, None, None, true, &clock);
            (
                stored,
                first(&jar).map(|c| (c.prefix_secure(), c.prefix_host())),
            )
        };

        // `:501` and `:503` use `strncmp`, so ONLY this spelling counts --
        // where `parse_netscape`'s `:744`/`:746` fold case. Deliberate.
        assert_eq!(
            flags_of(b" __Secure-x=v; secure; path=/"),
            (true, Some((true, false)))
        );
        assert_eq!(
            flags_of(b" __Host-x=v; secure; path=/"),
            (true, Some((false, true)))
        );
        // A differently-cased spelling sets NO flag, so it is an ordinary
        // cookie and needs neither `secure` nor a rooted path.
        assert_eq!(
            flags_of(b" __secure-x=v; path=/deep"),
            (true, Some((false, false)))
        );
        assert_eq!(
            flags_of(b" __HOST-x=v; path=/deep"),
            (true, Some((false, false)))
        );

        // `__Secure-` without `secure` is refused (`:968-970`).
        assert_eq!(flags_of(b" __Secure-x=v; path=/"), (false, None));

        // `__Host-` needs ALL of secure, a `"/"` path and no tailmatch
        // (`:972-982`).
        assert_eq!(flags_of(b" __Host-x=v; path=/"), (false, None));
        assert_eq!(flags_of(b" __Host-x=v; secure; path=/deep"), (false, None));
        assert_eq!(
            flags_of(b" __Host-x=v; secure; path=/; domain=example.com"),
            (false, None)
        );
    }

    #[test]
    fn the_standalone_words_are_secure_and_httponly() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:506-524` and `:525-528`, both matched with `str_casecompare`.
        for spelling in [&b"secure"[..], b"SECURE", b"Secure"] {
            let mut line = b" n=v; ".to_vec();
            line.extend_from_slice(spelling);
            line.extend_from_slice(b"; path=/");
            let mut jar = CookieInfo::new();
            assert!(add_header(&mut jar, &line, None, None, true, &clock));
            assert!(only(&jar).secure(), "{}", text(spelling));
        }

        for spelling in [&b"httponly"[..], b"HttpOnly", b"HTTPONLY"] {
            let mut line = b" n=v; ".to_vec();
            line.extend_from_slice(spelling);
            let mut jar = CookieInfo::new();
            assert!(add_header(&mut jar, &line, None, None, false, &clock));
            assert!(only(&jar).httponly(), "{}", text(spelling));
        }

        // The branch is guarded by `else if(!sep)` at `:508`, so a `secure`
        // or `httponly` attribute that carries an `=` is NOT the standalone
        // word: it falls past `path`, past `domain`, past `max-age`, past
        // `expires`, and is discarded like any unrecognised attribute. A
        // server writing `Secure=TRUE` therefore gets an insecure cookie, and
        // that is curl's behaviour rather than an oversight here.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" n=v; secure=whatever; path=/",
            None,
            None,
            true,
            &clock
        ));
        assert!(!only(&jar).secure());

        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" n=v; httponly=1; path=/",
            None,
            None,
            true,
            &clock
        ));
        assert!(!only(&jar).httponly());

        // And an EMPTY standalone word is not one either -- `secure=` has an
        // `=`, so `sep` is set even though the value is empty.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" n=v; secure=; path=/",
            None,
            None,
            true,
            &clock
        ));
        assert!(!only(&jar).secure());
    }

    #[test]
    fn the_secure_gate_is_inverted_between_the_two_parsers() {
        // `:520` is `if(secure || !ci->running)`; `:728` is `if(secure ||
        // ci->running)`. The negation is deliberate, and the four cases below
        // are exactly where the two disagree.
        let clock = clock_at(BEFORE_EXPIRY);

        let from_header = |running: bool, secure: bool| {
            let mut jar = CookieInfo::new();
            if running {
                jar.run();
            }
            add_header(
                &mut jar,
                b" n=v; secure; path=/",
                None,
                None,
                secure,
                &clock,
            )
        };
        let from_jar = |running: bool, secure: bool| {
            let mut jar = CookieInfo::new();
            if running {
                jar.run();
            }
            matches!(
                jar.add(
                    b"example.com\tFALSE\t/\tTRUE\t0\tn\tv",
                    &AddContext {
                        httpheader: false,
                        noexpire: true,
                        domain: None,
                        path: None,
                        secure,
                        setcookies: 0,
                    },
                    &clock,
                    &NoLog,
                    None,
                ),
                Ok(true)
            )
        };

        // Over a secure origin both accept.
        assert!(from_header(true, true));
        assert!(from_jar(true, true));
        assert!(from_header(false, true));
        assert!(from_jar(false, true));

        // Over an INSECURE origin they disagree, and that is the whole point:
        // a header must not mark a cookie secure over plain HTTP once the
        // engine is running, while a FILE may say so at any time.
        assert!(!from_header(true, false));
        assert!(from_jar(true, false));
        // Before the engine is running the header parser is permissive --
        // which is how a header-format cookie FILE loads `secure` cookies.
        assert!(from_header(false, false));
        assert!(!from_jar(false, false));

        // `tests/data/test31` depends on the first of those: a standalone
        // `secure` arriving over plain HTTP mid-transfer is dropped.
        let log = Recorder::default();
        let mut jar = CookieInfo::new();
        jar.run();
        let outcome = jar.add(
            b" n=v; secure",
            &header_ctx(Some(b"example.com"), Some(b"/"), false),
            &clock,
            &log,
            None,
        );
        assert_eq!(outcome, Ok(false));
        assert!(log.said("skipped cookie because not 'secure'"));
    }

    #[test]
    fn the_path_attribute_is_taken_raw_and_sanitised_afterwards() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:529-531` stores the span as-is; `storecookie` (`:403`) runs it
        // through `sanitize_cookie_path`. `tests/data/test8`'s
        // `path="/silly/"` exercises both halves.
        let path_of = |line: &[u8], default: Option<&[u8]>| {
            let mut jar = CookieInfo::new();
            assert!(add_header(&mut jar, line, None, default, false, &clock));
            only(&jar).path().map(<[u8]>::to_vec)
        };

        assert_eq!(
            path_of(b" n=v; path=\"/silly/\"", None),
            Some(b"/silly".to_vec())
        );
        assert_eq!(
            path_of(b" n=v; path=/we/want", None),
            Some(b"/we/want".to_vec())
        );
        assert_eq!(path_of(b" n=v; path=relative", None), Some(b"/".to_vec()));

        // An EMPTY `path=` is length zero, so `storecookie`'s
        // `if(curlx_strlen(&cp[COOKIE_PATH]))` at `:392` fails and the DEFAULT
        // is used instead -- the attribute is indistinguishable from absent.
        assert_eq!(path_of(b" n=v; path=", None), None);
        assert_eq!(
            path_of(b" n=v; path=", Some(b"/want/46")),
            Some(b"/want".to_vec())
        );

        // With NO `path` attribute the default comes from the request path,
        // truncated at its LAST `/` inclusive (`:392-401`) and then sanitised,
        // which is how `tests/data/test46`'s `/want/46` becomes `/want`.
        assert_eq!(
            path_of(b" n=v", Some(b"/want/46")),
            Some(b"/want".to_vec())
        );
        assert_eq!(
            path_of(b" n=v", Some(b"/we/want/8")),
            Some(b"/we/want".to_vec())
        );
        assert_eq!(path_of(b" n=v", Some(b"/top")), Some(b"/".to_vec()));
        assert_eq!(path_of(b" n=v", Some(b"/")), Some(b"/".to_vec()));
        // No slash at all: the whole span is the path, which then fails the
        // rooted test and becomes `"/"`.
        assert_eq!(path_of(b" n=v", Some(b"noslash")), Some(b"/".to_vec()));
        // And with no request path either, the path stays ABSENT -- not `"/"`.
        // `tests/data/test8`'s `blexp` and `cookie9` are exactly this, and the
        // distinction is visible in the `Cookie:` sort, where an absent path
        // counts as length zero.
        assert_eq!(path_of(b" n=v", None), None);
    }

    #[test]
    fn the_domain_attribute_is_checked_against_the_request_host() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        let domain_of = |line: &[u8], host: Option<&[u8]>| {
            let mut jar = CookieInfo::new();
            let stored =
                add_header(&mut jar, line, host, Some(b"/"), false, &clock);
            (
                stored,
                first(&jar)
                    .map(|c| (c.domain().map(<[u8]>::to_vec), c.tailmatch())),
            )
        };

        // `:539-540` -- ONE leading dot removed, via `str_nudge`.
        assert_eq!(
            domain_of(b" n=v; domain=.example.com", Some(b"www.example.com")),
            (true, Some((Some(b"example.com".to_vec()), true)))
        );
        // A parent domain tail-matches, and sets `tailmatch`.
        assert_eq!(
            domain_of(b" n=v; domain=example.com", Some(b"www.example.com")),
            (true, Some((Some(b"example.com".to_vec()), true)))
        );
        // A domain that does NOT tail-match is refused, with the C's wording.
        let mut jar = CookieInfo::new();
        let outcome = jar.add(
            b" n=v; domain=other.example",
            &header_ctx(Some(b"www.example.com"), Some(b"/"), false),
            &clock,
            &log,
            None,
        );
        assert_eq!(outcome, Ok(false));
        assert!(log.said("skipped cookie with bad tailmatch domain:"));

        // `:557-560` -- an IP-numeric host demands EXACT equality, both in
        // content and in length, and never sets `tailmatch`.
        assert_eq!(
            domain_of(b" n=v; domain=127.0.0.1", Some(b"127.0.0.1")),
            (true, Some((Some(b"127.0.0.1".to_vec()), false)))
        );
        assert_eq!(
            domain_of(b" n=v; domain=0.0.1", Some(b"127.0.0.1")),
            (false, None)
        );
        assert_eq!(
            domain_of(b" n=v; domain=127.0.0.11", Some(b"127.0.0.1")),
            (false, None)
        );

        // An EMPTY `domain=` fails `curlx_strlen(&val)` at `:532`, so the
        // attribute is skipped entirely and the DEFAULT domain is used --
        // `tests/data/test31` relies on this, and the result has `tailmatch`
        // clear.
        assert_eq!(
            domain_of(b" n=v; domain=", Some(b"example.com")),
            (true, Some((Some(b"example.com".to_vec()), false)))
        );

        // With no request host the check cannot run, so any domain is taken --
        // which is what makes a header-format cookie FILE loadable.
        assert_eq!(
            domain_of(b" n=v; domain=anything.example", None),
            (true, Some((Some(b"anything.example".to_vec()), true)))
        );
    }

    #[test]
    fn a_bad_domain_becomes_a_colon_sentinel_rather_than_a_refusal() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:544-545`, the `#ifndef USE_LIBPSL` arm: a domain with no dot is
        // not rejected on the spot. The DEFAULT domain is replaced by `":"`,
        // which nothing tail-matches, so the refusal happens one step later at
        // `:562`. `tests/data/test46`'s name -- *"HTTP with bad domain name"*
        // -- is about exactly this.
        let mut jar = CookieInfo::new();
        assert!(!add_header(
            &mut jar,
            b" n=v; domain=tld",
            Some(b"host.tld"),
            Some(b"/"),
            false,
            &clock
        ));

        // `localhost` is the one dotless domain that is good (`:330-331`).
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" n=v; domain=localhost",
            Some(b"localhost"),
            Some(b"/"),
            false,
            &clock
        ));
        assert_eq!(only(&jar).domain(), Some(&b"localhost"[..]));

        // And the sentinel PERSISTS for the rest of the line, so a second,
        // GOOD `domain` attribute is judged against `":"` and also fails.
        let mut jar = CookieInfo::new();
        assert!(!add_header(
            &mut jar,
            b" n=v; domain=tld; domain=host.tld",
            Some(b"host.tld"),
            Some(b"/"),
            false,
            &clock
        ));

        // Whereas two GOOD `domain` attributes are simply applied twice --
        // `tests/data/test8`'s `duplicate` and `blexp` lines.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" n=v; domain=host.tld; domain=host.tld",
            Some(b"host.tld"),
            Some(b"/"),
            false,
            &clock
        ));
        assert_eq!(only(&jar).domain(), Some(&b"host.tld"[..]));
    }

    #[test]
    fn max_age_beats_expires_whichever_order_they_arrive_in() {
        let now = 1_700_000_000;
        let clock = clock_at(now);

        let expires_of = |line: &[u8]| {
            let mut jar = CookieInfo::new();
            assert!(add_header(
                &mut jar,
                line,
                None,
                Some(b"/"),
                false,
                &clock
            ));
            only(&jar).expires()
        };

        // `:604` gates the `Expires` branch on `!co->expires`, so whichever is
        // parsed first wins -- and `Max-Age` always sets a non-zero value.
        let by_max_age = now + 60;
        assert_eq!(expires_of(b" n=v; max-age=60"), by_max_age);
        assert_eq!(
            expires_of(
                b" n=v; max-age=60; expires=Fri, 13-Feb-2037 11:56:27 GMT"
            ),
            by_max_age
        );
        assert_eq!(
            expires_of(
                b" n=v; expires=Fri, 13-Feb-2037 11:56:27 GMT; max-age=60"
            ),
            by_max_age
        );

        // `Expires` alone is honoured, and is capped at 400 days.
        let capped = ((now + COOKIES_MAXAGE + 30) / 60) * 60;
        assert_eq!(
            expires_of(b" n=v; expires=Fri, 13-Feb-2037 11:56:27 GMT"),
            capped
        );
    }

    #[test]
    fn the_two_expiry_failures_mean_opposite_things() {
        let now = 1_700_000_000;
        let clock = clock_at(now);

        let expires_of = |line: &[u8]| {
            let mut jar = CookieInfo::new();
            let stored =
                add_header(&mut jar, line, None, Some(b"/"), false, &clock);
            (stored, first(&jar).map(|c| c.expires()))
        };

        // `:585` -- an unparsable `Max-Age` sets `1`, the distant past, so the
        // cookie is stored and then swept. NOT a session cookie.
        for line in [
            &b" n=v; max-age=banana"[..],
            b" n=v; max-age=-1",
            b" n=v; max-age=+1",
        ] {
            assert_eq!(expires_of(line), (true, Some(1)), "{}", text(line));
        }

        // An EMPTY `max-age=` fails the `curlx_strlen(&val)` term at `:569`,
        // so the attribute is skipped ENTIRELY rather than failing to parse --
        // and the cookie is a session cookie, not an expired one. `expires=`
        // has no such length term (only `< MAX_DATE_LENGTH`), so it IS offered
        // to the date parser, fails, and reaches zero the other way.
        assert_eq!(expires_of(b" n=v; max-age="), (true, Some(0)));

        // `:459-460` trims the VALUE before the dispatch, so a leading blank
        // is not a parse failure -- `max-age= 1` is `max-age=1`.
        assert_eq!(expires_of(b" n=v; max-age= 1"), (true, Some(now + 1)));
        assert_eq!(expires_of(b" n=v; max-age=\t60 "), (true, Some(now + 60)));

        // `:624-625` -- an unparsable `Expires` sets `0`, which makes it a
        // SESSION cookie that survives until the handle goes away.
        // `tests/data/test8`'s `blexp=yesyes; ...; expiry=totally bad` is the
        // adjacent case: `expiry` is not `expires`, so it is ignored outright
        // and the cookie is a session cookie for that reason instead.
        for line in [
            &b" n=v; expires=totally bad"[..],
            b" n=v; expires=",
            b" n=v; expires=Fri, 99-Xxx-9999 99:99:99 GMT",
        ] {
            assert_eq!(expires_of(line), (true, Some(0)), "{}", text(line));
        }

        // `:578-580` -- `max-age=0` is bumped to `1`, because zero already
        // means "session" and a server asking for immediate expiry must not
        // get a permanent cookie.
        assert_eq!(expires_of(b" n=v; max-age=0"), (true, Some(1)));

        // `:571-572` -- a leading double quote on `Max-Age` is skipped.
        assert_eq!(expires_of(b" n=v; max-age=\"60\""), (true, Some(now + 60)));

        // `:576-577` -- an overflow saturates at `CURL_OFF_T_MAX` and is then
        // capped by `cap_expires`.
        let capped = ((now + COOKIES_MAXAGE + 30) / 60) * 60;
        assert_eq!(
            expires_of(b" n=v; max-age=99999999999999999999999"),
            (true, Some(capped))
        );

        // `:597-599` -- an `Expires` value at or past `MAX_DATE_LENGTH` is not
        // even offered to the parser, so it too becomes a session cookie.
        let mut line = b" n=v; expires=".to_vec();
        line.extend_from_slice(&[b'0'; MAX_DATE_LENGTH]);
        assert_eq!(expires_of(&line), (true, Some(0)));
    }

    #[test]
    fn every_unrecognised_attribute_is_ignored_and_samesite_is_one_of_them() {
        let now = 1_700_000_000;
        let clock = clock_at(now);

        // curl 8.19.0-DEV does not implement `SameSite` -- `grep -rin samesite
        // lib/` returns ZERO hits -- so it falls out of the dispatch chain
        // like any other unknown attribute. Honouring it would change which
        // cookies are sent, which AAP 0.8.2 forbids. This test exists to
        // assert the ABSENCE of a behaviour.
        for attribute in [
            &b"samesite=strict"[..],
            b"SameSite=Lax",
            b"samesite=none",
            b"priority=high",
            b"expiry=totally bad",
            b"version=1",
            b"comment=hello",
            b"partitioned",
            b"unknown",
        ] {
            let mut line = b" n=v; path=/; ".to_vec();
            line.extend_from_slice(attribute);
            let mut jar = CookieInfo::new();
            assert!(
                add_header(&mut jar, &line, None, None, false, &clock),
                "{}",
                text(attribute)
            );
            let stored = only(&jar);
            assert_eq!(stored.name(), b"n");
            assert_eq!(stored.value(), Some(&b"v"[..]));
            assert_eq!(stored.path(), Some(&b"/"[..]));
            assert_eq!(stored.expires(), 0, "{}", text(attribute));
            assert!(!stored.secure(), "{}", text(attribute));
            assert!(!stored.httponly(), "{}", text(attribute));
            assert!(!stored.tailmatch(), "{}", text(attribute));
        }
    }

    #[test]
    fn a_semicolon_run_and_a_trailing_semicolon_are_tolerated() {
        let clock = clock_at(BEFORE_EXPIRY);

        // The terminator is `while(!curlx_str_single(&ptr, ';'))`, so an empty
        // pair between two semicolons is simply skipped by the `str_cspn` that
        // finds nothing. Most fixtures end their `Set-Cookie:` line with `;`.
        for line in [
            &b" n=v;"[..],
            b" n=v; ;",
            b" n=v;;path=/;;",
            b" n=v ; path = / ;",
        ] {
            let mut jar = CookieInfo::new();
            assert!(
                add_header(&mut jar, line, None, None, false, &clock),
                "{}",
                text(line)
            );
            let stored = only(&jar);
            assert_eq!(stored.name(), b"n", "{}", text(line));
            assert_eq!(stored.value(), Some(&b"v"[..]), "{}", text(line));
        }
    }

    // -----------------------------------------------------------------------
    // The `Cookie:` request header -- `Curl_cookie_getlist`
    // (`lib/cookie.c:1253-1354`) and `http_cookies` (`lib/http.c:2523-2592`).
    //
    // WIRE-PARITY-CRITICAL. AAP 0.6.7's comparison joins the whole request
    // into ONE string, so the order, the separator and the casing are frozen.
    // -----------------------------------------------------------------------

    /// `tests/data/test8`'s `heads8.txt`, with `%HOSTIP` resolved to
    /// `127.0.0.1` and every `%hex[..]hex%` escape expanded.
    ///
    /// It is a HEADER-format cookie file, which `cookie_load` detects line by
    /// line with `checkprefix("Set-Cookie:", ...)`. The four response lines at
    /// the top are not cookies and reach the JAR parser, where they fail the
    /// seven-field test and are discarded -- which is itself worth exercising.
    fn test8_cookie_file() -> Vec<u8> {
        #[rustfmt::skip]
        let mut file: Vec<u8> = b"\
HTTP/1.1 200 OK\n\
Date: Tue, 09 Nov 2010 14:49:00 GMT\n\
Server: test-server/fake\n\
Content-Type: text/html\n\
Funny-head: yesyes\n\
Set-Cookie: foobar=name; domain=127.0.0.1; path=/;\n\
Set-Cookie: mismatch=this; domain=127.0.0.1; path=\"/silly/\";\n\
Set-Cookie: partmatch=present; domain=.0.0.1; path=/w;\n\
Set-Cookie: duplicate=test; domain=.0.0.1; domain=.0.0.1; path=/donkey;\n\
Set-Cookie: cookie=yes; path=/we;\n\
Set-Cookie: cookie=perhaps; path=/we/want;\n\
Set-Cookie: name with space=is weird but; path=/we/want;\n\
Set-Cookie: trailingspace    = removed; path=/we/want;\n\
Set-Cookie: nocookie=yes; path=/WE;\n\
Set-Cookie: blexp=yesyes; domain=127.0.0.1; domain=127.0.0.1; \
expiry=totally bad;\n\
Set-Cookie: partialip=nono; domain=.0.0.1;\n"
            .to_vec();

        // `cookie1` through `cookie8`, then `cookie11`, `cookie12` and
        // `cookie14` through `cookie31` -- one per control byte, with `\n`
        // (10) and `\r` (13) absent because they would end the line.
        let mut push = |index: u32, byte: u8, trailing: bool| {
            file.extend_from_slice(b"Set-Cookie: cookie");
            file.extend_from_slice(index.to_string().as_bytes());
            file.push(b'=');
            if trailing {
                file.extend_from_slice(b"junk--");
                file.push(byte);
            } else {
                file.push(byte);
                file.extend_from_slice(b"-junk");
            }
            file.push(b'\n');
        };
        for byte in 1u8..=8 {
            push(u32::from(byte), byte, false);
        }
        // `cookie9`'s TAB is TRAILING, so `trimblanks` removes it and the
        // cookie survives as `junk--`.
        push(9, b'\t', true);
        push(11, 0x0b, false);
        push(12, 0x0c, false);
        for byte in 0x0eu8..=0x1f {
            push(u32::from(byte), byte, false);
        }
        // The fixture reuses the name `cookie31` for `\x7f`.
        push(31, 0x7f, false);

        file
    }

    /// The exact `Cookie:` line `tests/data/test8` expects, transcribed from
    /// its `<protocol>` block with `%TESTNUMBER` resolved.
    #[rustfmt::skip]
    const TEST8_COOKIE_HEADER: &[u8] = b"Cookie: name with space=is weird but; \
trailingspace=removed; cookie=perhaps; cookie=yes; foobar=name; \
blexp=yesyes; cookie9=junk--\r\n";

    #[test]
    fn test8s_cookie_header_is_reproduced_byte_for_byte() {
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = load_text(&test8_cookie_file(), &clock);

        // Twelve cookies survive: the nine well-formed ones, plus the three
        // whose domain is `0.0.1`, plus `cookie9`. Everything with a control
        // byte in its value is refused.
        assert_eq!(jar.numcookies(), 12);

        let line = jar.cookie_header_line(
            b"127.0.0.1",
            b"/we/want/8",
            false,
            None,
            &clock,
            &NoLog,
        );

        assert_eq!(line.as_deref().map(text), Some(text(TEST8_COOKIE_HEADER)));
    }

    #[test]
    fn test46s_cookie_header_is_reproduced_byte_for_byte() {
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = load_text(JAR_ASCENDING, &clock);

        let line = jar.cookie_header_line(
            b"domain..tld",
            b"/want/46",
            false,
            None,
            &clock,
            &NoLog,
        );
        assert_eq!(
            line.as_deref().map(text),
            Some(text(b"Cookie: empty=; mooo2=indeed2; mooo=indeed\r\n"))
        );

        // The two cookies for other hosts are in the store and are simply not
        // sent, and `www.loser.com` proves the walk is per-bucket rather than
        // over everything.
        assert_eq!(jar.numcookies(), 5);
    }

    #[test]
    fn the_send_order_is_four_levels_and_every_one_descends() {
        let clock = clock_at(BEFORE_EXPIRY);

        // One cookie per level, built so that exactly one key differs at each
        // step. `cookie_sort` (`:1190-1224`) compares path length, then domain
        // length, then name length, then creation time -- all DESCENDING.
        let mut jar = CookieInfo::new();
        for line in [
            // Shortest path, so last of the path group.
            &b" aaaa=1; domain=b.example.com; path=/"[..],
            // Longest path wins outright.
            b" a=2; domain=b.example.com; path=/deep/deeper",
            // Same path as the next two; longest DOMAIN comes first.
            b" a=3; domain=b.example.com; path=/deep",
            b" a=4; domain=example.com; path=/deep",
            // Same path and domain as `a=3`; longer NAME comes first.
            b" aaa=5; domain=b.example.com; path=/deep",
        ] {
            assert!(add_header(
                &mut jar,
                line,
                Some(b"x.b.example.com"),
                Some(b"/deep/deeper/leaf"),
                false,
                &clock
            ));
        }

        let sent = jar.getlist(
            b"x.b.example.com",
            b"/deep/deeper/leaf",
            false,
            &clock,
            &NoLog,
        );
        let order: Vec<String> = sent
            .iter()
            .map(|cookie| cookie.value().map(text).unwrap_or_default())
            .collect();

        // path 12 -> then path 5 with domain 13 and name 3 -> path 5 domain 13
        // name 1 -> path 5 domain 11 -> path 1.
        assert_eq!(order, vec!["2", "5", "3", "4", "1"]);
    }

    #[test]
    fn creation_time_is_the_final_tiebreak_and_it_descends() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `tests/data/test46`'s `Cookie: empty=; mooo2=indeed2; mooo=indeed`
        // turns on this: `empty` and `mooo2` agree on all three lengths and
        // `empty` was created LATER.
        let mut jar = CookieInfo::new();
        for name in [&b"aaa"[..], b"bbb", b"ccc"] {
            let mut line = b" ".to_vec();
            line.extend_from_slice(name);
            line.extend_from_slice(b"=v; domain=example.com; path=/p");
            assert!(add_header(
                &mut jar,
                &line,
                Some(b"example.com"),
                Some(b"/p"),
                false,
                &clock
            ));
        }

        let sent = jar.getlist(b"example.com", b"/p", false, &clock, &NoLog);
        let order: Vec<String> =
            sent.iter().map(|cookie| text(cookie.name())).collect();
        assert_eq!(order, vec!["ccc", "bbb", "aaa"]);
    }

    #[test]
    fn an_absent_path_or_domain_counts_as_length_zero() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `cookie_sort` reads `co->path ? strlen(co->path) : 0` (`:1192`), and
        // `tests/data/test8` puts `blexp` (domain, no path) before `cookie9`
        // (neither) for exactly that reason.
        // The host is IP-numeric so that all three cookies share bucket 0 --
        // which is precisely `tests/data/test8`'s arrangement, and the reason
        // that fixture can compare a domain-less cookie against a domained one
        // in one header.
        let mut jar = CookieInfo::new();
        // No path, no domain.
        assert!(add_header(&mut jar, b" bare=1", None, None, false, &clock));
        // A domain, still no path.
        assert!(add_header(
            &mut jar,
            b" domained=2; domain=127.0.0.1",
            Some(b"127.0.0.1"),
            None,
            false,
            &clock
        ));
        // Both.
        assert!(add_header(
            &mut jar,
            b" both=3; domain=127.0.0.1; path=/",
            Some(b"127.0.0.1"),
            Some(b"/"),
            false,
            &clock
        ));

        let sent = jar.getlist(b"127.0.0.1", b"/p", false, &clock, &NoLog);
        let order: Vec<String> =
            sent.iter().map(|cookie| text(cookie.name())).collect();
        assert_eq!(order, vec!["both", "domained", "bare"]);
    }

    #[test]
    fn a_cookie_with_no_domain_lives_in_bucket_zero_and_stays_there() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `cookiehash(NULL)` is 0 (`:213`), and `Curl_cookie_getlist` scans
        // only `ci->cookielist[cookiehash(host)]` (`:1262`, `:1277`). So a
        // cookie stored with no domain -- which `tests/data/test8` produces in
        // quantity -- is reachable ONLY from a host that also hashes to zero,
        // and `:1285`'s domain test is then skipped so it is sent
        // unconditionally. That is a genuine consequence of the bucketing and
        // not a matching rule.
        assert_eq!(cookiehash(None), 0);

        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" bare=1",
            None,
            Some(b"/"),
            false,
            &clock
        ));

        // Every IP-numeric host hashes to zero, so every one of them gets it.
        for host in [&b"127.0.0.1"[..], b"10.1.2.3", b"::1", b"2001:db8::1"] {
            assert_eq!(
                jar.getlist(host, b"/", false, &clock, &NoLog).len(),
                1,
                "{}",
                text(host)
            );
        }

        // A named host that hashes elsewhere does not, however similar it
        // looks. The search below is over the SAME hash the store uses, so it
        // cannot drift from the implementation.
        let mut host = b"a.example".to_vec();
        while cookiehash(Some(&host)) == 0 {
            host.insert(0, b'z');
        }
        assert!(jar.getlist(&host, b"/", false, &clock, &NoLog).is_empty());

        // And a named host that DOES hash to zero gets it, which shows the
        // rule is the bucket rather than the address family.
        let mut host = b"a.example".to_vec();
        while cookiehash(Some(&host)) != 0 {
            host.insert(0, b'z');
        }
        assert_eq!(jar.getlist(&host, b"/", false, &clock, &NoLog).len(), 1);
    }

    #[test]
    fn a_secure_cookie_is_withheld_from_an_insecure_request() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:1282` -- the very first test in the match loop.
        let mut jar = load_text(
            b"example.com\tFALSE\t/\tTRUE\t0\tsid\tsecret\n\
              example.com\tFALSE\t/\tFALSE\t0\tplain\tok\n",
            &clock,
        );

        let over_http =
            jar.getlist(b"example.com", b"/", false, &clock, &NoLog);
        let names: Vec<String> =
            over_http.iter().map(|c| text(c.name())).collect();
        assert_eq!(names, vec!["plain"]);

        let over_https =
            jar.getlist(b"example.com", b"/", true, &clock, &NoLog);
        let mut names: Vec<String> =
            over_https.iter().map(|c| text(c.name())).collect();
        names.sort();
        assert_eq!(names, vec!["plain", "sid"]);

        // And `localhost` counts as secure without TLS, per
        // `docs/HTTP-COOKIES.md`: *"to match how popular browsers work"*.
        let mut jar =
            load_text(b"localhost\tFALSE\t/\tTRUE\t0\tsid\tsecret\n", &clock);
        assert_eq!(
            jar.getlist(b"localhost", b"/", false, &clock, &NoLog).len(),
            1
        );
    }

    #[test]
    fn a_tailmatching_cookie_is_not_tailmatched_against_an_ip_host() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:1285` -- `co->tailmatch && !is_ip`. For an IP host the comparison
        // falls back to exact, case-insensitive equality, which is what stops
        // a cookie for `0.0.1` reaching `127.0.0.1` even though
        // `cookie_tailmatch` on its own would say yes.
        assert!(cookie_tailmatch(b"0.0.1", b"127.0.0.1"));

        let mut jar =
            load_text(b"0.0.1\tTRUE\t/\tFALSE\t0\tpartial\tnono\n", &clock);
        assert_eq!(jar.numcookies(), 1);
        assert!(jar
            .getlist(b"127.0.0.1", b"/", false, &clock, &NoLog)
            .is_empty());

        // Whereas a non-IP host does tail-match.
        let mut jar =
            load_text(b"example.com\tTRUE\t/\tFALSE\t0\twide\tyes\n", &clock);
        assert_eq!(
            jar.getlist(b"www.example.com", b"/", false, &clock, &NoLog)
                .len(),
            1
        );

        // An exact, case-insensitive match is always accepted.
        let mut jar =
            load_text(b"Example.COM\tFALSE\t/\tFALSE\t0\texact\tyes\n", &clock);
        assert_eq!(
            jar.getlist(b"eXaMpLe.com", b"/", false, &clock, &NoLog)
                .len(),
            1
        );
    }

    #[test]
    fn the_send_count_is_capped_and_the_cap_is_announced() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `:1303-1310` -- `MAX_COOKIE_SEND_AMOUNT` cookies and then a
        // diagnostic and a `break`.
        let mut jar = CookieInfo::new();
        for index in 0..(MAX_COOKIE_SEND_AMOUNT + 20) {
            let mut line = b"example.com\tFALSE\t/\tFALSE\t0\tn".to_vec();
            line.extend_from_slice(index.to_string().as_bytes());
            line.extend_from_slice(b"\tv\n");
            assert!(add_jar(&mut jar, &line, &clock));
        }
        assert_eq!(
            jar.numcookies(),
            u32::try_from(MAX_COOKIE_SEND_AMOUNT + 20).unwrap_or(u32::MAX)
        );

        let sent = jar.getlist(b"example.com", b"/", false, &clock, &log);
        assert_eq!(sent.len(), MAX_COOKIE_SEND_AMOUNT);
        assert!(log.said("Included max number of cookies (150) in request!"));
    }

    #[test]
    fn the_header_length_cap_stops_the_walk_and_sets_linecap() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `lib/http.c:2546` seeds the running length at 8 -- the width of
        // `"Cookie: "` -- and `:2558-2564` stops when adding a pair would
        // reach `MAX_COOKIE_HEADER_LEN`.
        let mut jar = CookieInfo::new();
        for index in 0..4u32 {
            let mut line = b"example.com\tFALSE\t/\tFALSE\t0\tn".to_vec();
            line.extend_from_slice(index.to_string().as_bytes());
            line.push(b'\t');
            line.extend_from_slice(&vec![b'v'; 3000]);
            line.push(b'\n');
            assert!(add_jar(&mut jar, &line, &clock));
        }

        let header =
            jar.cookie_header(b"example.com", b"/", false, &clock, &log);
        // Two pairs of 3003 bytes fit under 8190 with their separator; the
        // third does not.
        assert_eq!(header.count, 2);
        assert!(header.linecap);
        assert!(header.value.len() < MAX_COOKIE_HEADER_LEN);
        assert!(log.said("Restricted outgoing cookies due to header size"));

        // `:2577` -- `CURLOPT_COOKIE` is NOT appended once `linecap` is set.
        let line = jar.cookie_header_line(
            b"example.com",
            b"/",
            false,
            Some(b"extra=yes"),
            &clock,
            &NoLog,
        );
        assert!(!line
            .as_deref()
            .map(text)
            .unwrap_or_default()
            .contains("extra"));
    }

    #[test]
    fn curlopt_cookie_is_appended_verbatim_and_can_stand_alone() {
        let clock = clock_at(BEFORE_EXPIRY);

        // With no stored cookie the option's string is the whole header, and
        // `count` becomes 1 so the line IS terminated (`:2580-2586`).
        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.cookie_header_line(
                b"example.com",
                b"/",
                false,
                Some(b"name=value"),
                &clock,
                &NoLog
            )
            .as_deref()
            .map(text),
            Some(text(b"Cookie: name=value\r\n"))
        );

        // With one stored cookie the separator is the same `"; "`.
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t0\tstored\tyes\n",
            &clock
        ));
        assert_eq!(
            jar.cookie_header_line(
                b"example.com",
                b"/",
                false,
                Some(b"name=value"),
                &clock,
                &NoLog
            )
            .as_deref()
            .map(text),
            Some(text(b"Cookie: stored=yes; name=value\r\n"))
        );

        // It is appended without parsing, so anything at all goes through --
        // `docs/libcurl/opts/CURLOPT_COOKIE.md` is explicit that the string is
        // used as-is.
        assert_eq!(
            jar.cookie_header_line(
                b"example.com",
                b"/",
                false,
                Some(b"not even a pair"),
                &clock,
                &NoLog
            )
            .as_deref()
            .map(text),
            Some(text(b"Cookie: stored=yes; not even a pair\r\n"))
        );

        // And with neither, there is no header line at all.
        let mut empty = CookieInfo::new();
        assert!(empty
            .cookie_header_line(
                b"example.com",
                b"/",
                false,
                None,
                &clock,
                &NoLog
            )
            .is_none());
    }

    #[test]
    fn a_cookie_with_no_value_is_skipped_but_an_empty_one_is_sent() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `lib/http.c:2551` -- `if(co->value)`. A cookie can only reach the
        // store without a value through a header with no `Path`... in fact it
        // cannot at all, because `storecookie` always stores a value; so this
        // asserts the guard against a store built directly, which is what
        // `crate::share` and the option surface could produce.
        let mut jar = CookieInfo::new();
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t0\tempty\t\n",
            &clock
        ));
        assert_eq!(
            jar.cookie_header_line(
                b"example.com",
                b"/",
                false,
                None,
                &clock,
                &NoLog
            )
            .as_deref()
            .map(text),
            Some(text(b"Cookie: empty=\r\n"))
        );

        // `tests/data/test46` expects exactly that leading `empty=`.
        assert_eq!(only(&jar).value(), Some(&b""[..]));
    }

    #[test]
    fn an_empty_bucket_returns_before_the_sweep() {
        // `:1271-1272` -- the early return is BEFORE `remove_expired`, so a
        // request for a host with nothing stored does not sweep the store.
        // Observable through `next_expiration`, which a sweep would reset.
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = load_text(JAR_ASCENDING, &clock);
        assert_eq!(jar.next_expiration(), 2_139_150_993);

        // `nothing.here` hashes to a bucket that holds no cookie.
        let mut host = b"zzz.nothing.here".to_vec();
        while cookiehash(Some(&host)) == cookiehash(Some(b"domain..tld"))
            || cookiehash(Some(&host)) == 0
        {
            host.insert(0, b'z');
        }
        assert!(jar.getlist(&host, b"/", false, &clock, &NoLog).is_empty());
        assert_eq!(jar.numcookies(), 5);
    }

    // -----------------------------------------------------------------------
    // Supersession -- `replace_existing` (`lib/cookie.c:822-924`).
    // -----------------------------------------------------------------------

    #[test]
    fn a_matching_cookie_replaces_and_inherits_the_old_creation_time() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `tests/data/test31` proves the inheritance from the outside: its
        // `overwrite=this2` entry sits FOURTH from the end of the expected jar,
        // in the slot the FIRST `overwrite=this` occupied, not last.
        let mut jar = CookieInfo::new();
        for name in [&b"first"[..], b"overwrite", b"third"] {
            let mut line = b" ".to_vec();
            line.extend_from_slice(name);
            line.extend_from_slice(b"=this; domain=example.com; path=/");
            assert!(add_header(
                &mut jar,
                &line,
                Some(b"example.com"),
                Some(b"/"),
                false,
                &clock
            ));
        }
        assert_eq!(jar.numcookies(), 3);
        assert_eq!(jar.lastct(), 3);

        // The replacement.
        assert!(add_header(
            &mut jar,
            b" overwrite=this2; domain=example.com; path=/",
            Some(b"example.com"),
            Some(b"/"),
            false,
            &clock
        ));

        // `:1026-1027` -- a replacement does NOT increase the count...
        assert_eq!(jar.numcookies(), 3);
        // ...but `:988` still consumed a creation-time ticket, which is why
        // the counter is 4 while the retained time is 2.
        assert_eq!(jar.lastct(), 4);

        let replaced: Vec<Cookie> = all(&jar)
            .into_iter()
            .filter(|cookie| cookie.name() == b"overwrite")
            .collect();
        assert_eq!(replaced.len(), 1);
        assert_eq!(
            replaced.first().map(Cookie::creationtime),
            Some(2),
            "`:912-913` keeps the OLD creation time"
        );
        assert_eq!(
            replaced.first().and_then(Cookie::value),
            Some(&b"this2"[..])
        );

        // Which is observable in BOTH orders. The jar writes descending
        // creation time, so the replacement stays in the middle.
        let written = text(&saved(&jar));
        let lines: Vec<&str> = written.lines().skip(4).collect();
        assert_eq!(lines.len(), 3);
        assert!(lines.first().unwrap_or(&"").contains("third"));
        assert!(lines.get(1).unwrap_or(&"").contains("overwrite\tthis2"));
        assert!(lines.get(2).unwrap_or(&"").contains("first"));

        // The `Cookie:` header sees the same retained time. Here the third
        // sort level fires first -- `overwrite` is nine bytes against five --
        // so it leads, and the two five-byte names then fall to the creation
        // time. The retained `2` is what puts `overwrite` where it is rather
        // than a fresh `4`, and swapping in a fresh time would give `4, 3, 1`.
        let sent = jar.getlist(b"example.com", b"/", false, &clock, &NoLog);
        let order: Vec<u32> =
            sent.iter().map(|cookie| cookie.creationtime()).collect();
        assert_eq!(order, vec![2, 3, 1]);
        let names: Vec<String> =
            sent.iter().map(|cookie| text(cookie.name())).collect();
        assert_eq!(names, vec!["overwrite", "third", "first"]);
    }

    #[test]
    fn replacement_requires_the_name_the_domain_the_tailmatch_and_the_path() {
        let clock = clock_at(BEFORE_EXPIRY);

        // Each case adds a base cookie and then one that differs in exactly
        // one key, and asserts the store grew rather than being overwritten.
        let base = b" n=old; domain=example.com; path=/p";
        // Each row carries its own request host, because the `Domain`
        // attribute is checked against it before any of this is reached.
        let cases: [(&[u8], &[u8], &str); 3] = [
            // A different NAME -- `strcmp`, so CASE-SENSITIVE (`:834`).
            (
                b" N=new; domain=example.com; path=/p",
                b"www.example.com",
                "name case",
            ),
            // A different DOMAIN.
            (
                b" n=new; domain=other.example; path=/p",
                b"www.other.example",
                "domain",
            ),
            // A different PATH.
            (
                b" n=new; domain=example.com; path=/q",
                b"www.example.com",
                "path",
            ),
        ];

        for (variant, host, what) in cases {
            let mut jar = CookieInfo::new();
            assert!(add_header(
                &mut jar,
                base,
                Some(b"www.example.com"),
                Some(b"/p"),
                false,
                &clock
            ));
            assert!(
                add_header(
                    &mut jar,
                    variant,
                    Some(host),
                    Some(b"/p"),
                    false,
                    &clock
                ),
                "{what} must be stored"
            );
            assert_eq!(jar.numcookies(), 2, "{what} must not replace");
        }

        // The same four keys agreeing DOES replace.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            base,
            Some(b"www.example.com"),
            Some(b"/p"),
            false,
            &clock
        ));
        assert!(add_header(
            &mut jar,
            b" n=new; domain=example.com; path=/p",
            Some(b"www.example.com"),
            Some(b"/p"),
            false,
            &clock
        ));
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(only(&jar).value(), Some(&b"new"[..]));

        // The PATH comparison here is `curl_strequal` (`:891`), which folds
        // case, so `/P` DOES replace `/p`. That is the opposite of `pathmatch`
        // (`:139`), which compares a cookie path against a URI path with
        // `strncmp` and is CASE-SENSITIVE. Two different policies on the same
        // field, three lines apart in this file's own table; both are
        // reproduced.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            base,
            Some(b"www.example.com"),
            Some(b"/p"),
            false,
            &clock
        ));
        assert!(add_header(
            &mut jar,
            b" n=new; domain=example.com; path=/P",
            Some(b"www.example.com"),
            Some(b"/p"),
            false,
            &clock
        ));
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(only(&jar).value(), Some(&b"new"[..]));
        // And the surviving cookie keeps the NEW path, so a later request for
        // `/p` no longer matches it.
        assert_eq!(only(&jar).path(), Some(&b"/P"[..]));
        assert!(!pathmatch(b"/P", b"/p/deeper"));

        // `tailmatch` must agree too (`:879-881`). A jar line with field 1
        // FALSE and the same domain, name and path as a tail-matching cookie
        // is a DIFFERENT cookie.
        let mut jar = CookieInfo::new();
        assert!(add_jar(
            &mut jar,
            b"example.com\tTRUE\t/p\tFALSE\t0\tn\twide\n",
            &clock
        ));
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/p\tFALSE\t0\tn\tnarrow\n",
            &clock
        ));
        assert_eq!(jar.numcookies(), 2);

        // Two cookies with NO domain at all match each other (`:842-843`).
        let mut jar = CookieInfo::new();
        assert!(add_header(&mut jar, b" n=old", None, None, false, &clock));
        assert!(add_header(&mut jar, b" n=new", None, None, false, &clock));
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(only(&jar).value(), Some(&b"new"[..]));

        // Whereas one with a domain and one without do not (`:838-843`).
        let mut jar = CookieInfo::new();
        assert!(add_header(&mut jar, b" n=old", None, None, false, &clock));
        assert!(add_header(
            &mut jar,
            b" n=new; domain=127.0.0.1",
            Some(b"127.0.0.1"),
            None,
            false,
            &clock
        ));
        assert_eq!(jar.numcookies(), 2);

        // And a NULL-versus-present PATH disqualifies (`:891-893`).
        let mut jar = CookieInfo::new();
        assert!(add_header(&mut jar, b" n=old", None, None, false, &clock));
        assert!(add_header(
            &mut jar,
            b" n=new; path=/",
            None,
            None,
            false,
            &clock
        ));
        assert_eq!(jar.numcookies(), 2);
    }

    #[test]
    fn livecookie_follows_the_stores_running_flag_not_the_line_format() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:987` -- `co->livecookie = ci->running;`. It records the STORE's
        // state, not whether the line was a header or a jar entry. So a jar
        // line added to a running store IS live, and the *"cookies read from a
        // file never replace live ones"* rule at `:896-904` only bites while
        // `cookie_load` has the flag down (`:1100`).
        let mut running = CookieInfo::new();
        running.run();
        assert!(add_jar(
            &mut running,
            b"example.com\tTRUE\t/\tFALSE\t0\tsid\tfromfile\n",
            &clock
        ));
        assert!(only(&running).livecookie());

        let mut quiet = CookieInfo::new();
        assert!(add_header(
            &mut quiet,
            b" sid=v; domain=example.com; path=/",
            Some(b"example.com"),
            Some(b"/"),
            false,
            &clock
        ));
        assert!(!only(&quiet).livecookie());

        // Two live cookies replace each other freely, in either direction.
        let mut jar = CookieInfo::new();
        jar.run();
        assert!(add_header(
            &mut jar,
            b" sid=live; domain=example.com; path=/",
            Some(b"example.com"),
            Some(b"/"),
            false,
            &clock
        ));
        // The jar line carries field 1 TRUE, because a `Domain` attribute that
        // is not an address always sets `tailmatch` (`:565-566`) and `:879-881`
        // demands the two agree before a replacement is even considered.
        assert!(only(&jar).tailmatch());
        assert!(add_jar(
            &mut jar,
            b"example.com\tTRUE\t/\tFALSE\t0\tsid\tsecond\n",
            &clock
        ));
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(only(&jar).value(), Some(&b"second"[..]));

        // And two NON-live cookies likewise, the rule being about the EXISTING
        // cookie being live rather than about files as such.
        let mut jar = CookieInfo::new();
        assert!(add_jar(
            &mut jar,
            b"example.com\tTRUE\t/\tFALSE\t0\tsid\tone\n",
            &clock
        ));
        assert!(add_jar(
            &mut jar,
            b"example.com\tTRUE\t/\tFALSE\t0\tsid\ttwo\n",
            &clock
        ));
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(only(&jar).value(), Some(&b"two"[..]));

        // The refusal itself needs a load, which needs a file; see
        // `a_reload_does_not_displace_a_live_cookie` in the filesystem group.
    }
    #[test]
    fn a_plain_cookie_may_not_overlay_a_secure_one() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `:846-874`. All six terms must hold: the names identical, the domains
        // identical, BOTH paths present, the existing cookie secure, the new
        // one not, and the connection not secure.
        let with_existing = |new: &[u8], connection_secure: bool| {
            let mut jar = CookieInfo::new();
            assert!(add_jar(
                &mut jar,
                b"example.com\tFALSE\t/login\tTRUE\t0\ta\tsecret\n",
                &clock
            ));
            jar.run();
            let outcome = jar.add(
                new,
                &header_ctx(
                    Some(b"example.com"),
                    Some(b"/login"),
                    connection_secure,
                ),
                &clock,
                &log,
                None,
            );
            (outcome, jar.numcookies())
        };

        // The C's own example: a deeper path under the existing one.
        assert_eq!(
            with_existing(
                b" a=plain; domain=example.com; path=/login/en",
                false
            ),
            (Ok(false), 1)
        );
        assert!(log.said("would overlay an existing cookie"));

        // `cllen` is the offset of the SECOND `/` in the existing path, or the
        // whole path when there is none. `/login` has none, so the comparison
        // covers all six bytes and `/loginhelper` shares them -- meaning it is
        // ALSO refused, even though the C's comment at `:855-858` says it is
        // *"ok"*. The arithmetic at `:860-865` is authoritative and the comment
        // is aspirational; the measured behaviour is reproduced.
        assert_eq!(
            with_existing(
                b" a=plain; domain=example.com; path=/loginhelper",
                false
            ),
            (Ok(false), 1)
        );

        // An unrelated path is not an overlay, so it is stored alongside.
        assert_eq!(
            with_existing(b" a=plain; domain=example.com; path=/other", false),
            (Ok(true), 2)
        );

        // Over a SECURE connection the rule does not apply at all, and the
        // cookie then replaces rather than being added.
        assert_eq!(
            with_existing(
                b" a=plain; domain=example.com; path=/login/en",
                true
            ),
            (Ok(true), 2)
        );

        // And a new cookie that is itself secure is never an overlay.
        let mut jar = CookieInfo::new();
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/login\tTRUE\t0\ta\tsecret\n",
            &clock
        ));
        jar.run();
        assert!(add_header(
            &mut jar,
            b" a=alsosecure; domain=example.com; path=/login/en; secure",
            Some(b"example.com"),
            Some(b"/login"),
            true,
            &clock
        ));
        assert_eq!(jar.numcookies(), 2);
    }

    #[test]
    fn the_second_slash_bounds_the_overlay_comparison() {
        let clock = clock_at(BEFORE_EXPIRY);

        // With a two-segment existing path the comparison covers only the
        // first segment, so a sibling of the second segment IS refused --
        // which is the case the C's comment is really describing.
        let with_existing = |new: &[u8]| {
            let mut jar = CookieInfo::new();
            assert!(add_jar(
                &mut jar,
                b"example.com\tFALSE\t/login/en\tTRUE\t0\ta\tsecret\n",
                &clock
            ));
            jar.run();
            let outcome = jar.add(
                new,
                &header_ctx(Some(b"example.com"), Some(b"/login/en"), false),
                &clock,
                &NoLog,
                None,
            );
            outcome
        };

        // `strchr("/login/en" + 1, '/')` lands at index 6, so `cllen` is 6 and
        // the comparison is against `"/login"`.
        assert_eq!(
            with_existing(b" a=p; domain=example.com; path=/login/fr"),
            Ok(false)
        );
        assert_eq!(
            with_existing(b" a=p; domain=example.com; path=/login"),
            Ok(false)
        );
        assert_eq!(
            with_existing(b" a=p; domain=example.com; path=/other"),
            Ok(true)
        );

        // A one-byte existing path makes `cllen` 1, so EVERY rooted path is an
        // overlay -- a secure cookie at `"/"` shuts out its plain namesake
        // entirely.
        let mut jar = CookieInfo::new();
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tTRUE\t0\ta\tsecret\n",
            &clock
        ));
        jar.run();
        assert_eq!(
            jar.add(
                b" a=p; domain=example.com; path=/anything",
                &header_ctx(Some(b"example.com"), Some(b"/anything"), false),
                &clock,
                &NoLog,
                None,
            ),
            Ok(false)
        );
    }

    // -----------------------------------------------------------------------
    // `Curl_cookie_add`'s fourteen steps (`lib/cookie.c:934-1045`).
    // -----------------------------------------------------------------------

    #[test]
    fn the_set_cookie_count_silences_the_fifty_first_header() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `:953-954` -- at the limit the line is ignored with NO diagnostic,
        // which is why the sink is asserted empty. The counter lives on the
        // REQUEST, not the store, so it is the caller's to keep.
        let mut jar = CookieInfo::new();
        let mut ctx = header_ctx(Some(b"example.com"), Some(b"/"), false);
        ctx.setcookies = MAX_SET_COOKIE_AMOUNT;
        assert_eq!(jar.add(b" n=v", &ctx, &clock, &log, None), Ok(false));
        assert_eq!(jar.numcookies(), 0);
        assert_eq!(log.count(), 0);

        // One below the limit still works.
        ctx.setcookies = MAX_SET_COOKIE_AMOUNT - 1;
        assert_eq!(jar.add(b" n=v", &ctx, &clock, &log, None), Ok(true));
        assert_eq!(jar.numcookies(), 1);

        // And it is only counted for a HEADER line: a jar line has
        // `httpheader` clear, so the counter never moves for it (`:1040-1042`
        // is inside `if(headerline)`).
        let mut ctx = jar_ctx();
        ctx.setcookies = MAX_SET_COOKIE_AMOUNT;
        assert_eq!(
            jar.add(
                b"example.com\tFALSE\t/\tFALSE\t0\tfromfile\tv",
                &ctx,
                &clock,
                &log,
                None
            ),
            Ok(false),
            "the gate is checked BEFORE the parser, so it applies either way"
        );
    }

    #[test]
    fn junk_session_cookies_refuses_a_session_cookie_from_a_file() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:984-987` -- *"Session cookies are not stored when we read from
        // file"*, gated on all three of `!running`, `newsession` and a zero
        // expiry. This is `CURLOPT_COOKIESESSION` and
        // `--junk-session-cookies`.
        let mut jar = CookieInfo::new();
        jar.set_newsession(true);
        assert!(jar.newsession());
        assert!(!add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t0\tsession\tv\n",
            &clock
        ));
        // A DATED cookie from the same file is kept.
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t2139150993\tdated\tv\n",
            &clock
        ));
        assert_eq!(jar.numcookies(), 1);

        // Once the engine is running the rule stops applying, so a session
        // cookie from a RESPONSE is always kept.
        jar.run();
        assert!(add_header(
            &mut jar,
            b" fromheader=v; domain=example.com; path=/",
            Some(b"example.com"),
            Some(b"/"),
            false,
            &clock
        ));
        assert_eq!(jar.numcookies(), 2);
    }

    #[test]
    fn the_add_reports_what_it_did_but_only_once_running() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `:1018-1024` is inside `if(ci->running)`, so a load is silent.
        let mut jar = CookieInfo::new();
        assert!(matches!(
            jar.add(
                b"example.com\tFALSE\t/\tFALSE\t0\tn\tv",
                &jar_ctx(),
                &clock,
                &log,
                None
            ),
            Ok(true)
        ));
        assert_eq!(log.count(), 0);

        jar.run();
        assert!(matches!(
            jar.add(
                b" n2=v2; domain=example.com; path=/",
                &header_ctx(Some(b"example.com"), Some(b"/"), false),
                &clock,
                &log,
                None
            ),
            Ok(true)
        ));
        assert!(log.said(
            "Added cookie n2=\"v2\" for domain example.com, \
                          path /, expire 0"
        ));

        // A replacement says so.
        assert!(matches!(
            jar.add(
                b" n2=v3; domain=example.com; path=/",
                &header_ctx(Some(b"example.com"), Some(b"/"), false),
                &clock,
                &log,
                None
            ),
            Ok(true)
        ));
        assert!(log.said("Replaced cookie n2=\"v3\""));
    }

    #[test]
    fn next_expiration_tracks_the_earliest_future_expiry() {
        let clock = clock_at(1_000);

        // `:1033-1038` -- only a non-zero expiry counts, and only when it is
        // sooner than what is recorded.
        let mut jar = CookieInfo::new();
        assert_eq!(jar.next_expiration(), CURL_OFF_T_MAX);

        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t5000\tlate\tv\n",
            &clock
        ));
        assert_eq!(jar.next_expiration(), 5000);

        // Sooner: adopted.
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t2000\tsoon\tv\n",
            &clock
        ));
        assert_eq!(jar.next_expiration(), 2000);

        // Later: ignored.
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t9000\tlater\tv\n",
            &clock
        ));
        assert_eq!(jar.next_expiration(), 2000);

        // A session cookie never moves it.
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t0\tsession\tv\n",
            &clock
        ));
        assert_eq!(jar.next_expiration(), 2000);
    }

    // -----------------------------------------------------------------------
    // `remove_expired` (`lib/cookie.c:281-323`).
    // -----------------------------------------------------------------------

    #[test]
    fn the_sweep_uses_a_strict_comparison_at_the_boundary() {
        // `:305` -- `co->expires && co->expires < now`. A cookie expiring
        // exactly NOW survives this sweep and goes on the next second.
        let mut jar = CookieInfo::new();
        let clock = clock_at(1_000);
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t1000\tboundary\tv\n",
            &clock
        ));
        assert_eq!(jar.numcookies(), 1);

        jar.remove_expired(&clock);
        assert_eq!(jar.numcookies(), 1);

        clock.set_epoch_secs(1_001);
        jar.remove_expired(&clock);
        assert_eq!(jar.numcookies(), 0);
        // `:293` resets it before the scan and nothing future was found.
        assert_eq!(jar.next_expiration(), CURL_OFF_T_MAX);
    }

    #[test]
    fn the_sweep_returns_immediately_until_the_recorded_moment() {
        // `:288-292` -- *"If time() returns a small value, and
        // next_expiration is CURL_OFF_T_MAX, this will not exit early"*. The
        // early exit is observable because the sweep is what would remove an
        // expired cookie, and until the recorded moment arrives it does not
        // even look.
        let clock = clock_at(1_000);
        let mut jar = CookieInfo::new();
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t3000\tlate\tv\n",
            &clock
        ));
        assert_eq!(jar.next_expiration(), 3000);

        // Reach past the cookie's expiry but describe the store as not due
        // until 3000: the sweep runs, because 2999 < 3000 is the early exit and
        // 3001 is not.
        clock.set_epoch_secs(2_999);
        jar.remove_expired(&clock);
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(jar.next_expiration(), 3000);

        clock.set_epoch_secs(3_001);
        jar.remove_expired(&clock);
        assert_eq!(jar.numcookies(), 0);
    }

    #[test]
    fn the_sweep_scans_every_bucket_and_keeps_the_count_honest() {
        let clock = clock_at(1_000);
        let mut jar = CookieInfo::new();

        // Twenty distinct domains, so several buckets are populated, half of
        // them expiring before the second sweep.
        for index in 0..20u32 {
            let expires = if index % 2 == 0 { 2_000 } else { 9_000 };
            let mut line = Vec::new();
            line.extend_from_slice(b"host");
            line.extend_from_slice(index.to_string().as_bytes());
            line.extend_from_slice(b".example\tFALSE\t/\tFALSE\t");
            line.extend_from_slice(expires.to_string().as_bytes());
            line.extend_from_slice(b"\tn\tv\n");
            assert!(add_jar(&mut jar, &line, &clock));
        }
        assert_eq!(jar.numcookies(), 20);
        assert_eq!(jar.next_expiration(), 2_000);

        clock.set_epoch_secs(5_000);
        jar.remove_expired(&clock);
        assert_eq!(jar.numcookies(), 10);
        // The earliest surviving expiry, found by the same scan.
        assert_eq!(jar.next_expiration(), 9_000);
        assert!(all(&jar).iter().all(|cookie| cookie.expires() == 9_000));

        clock.set_epoch_secs(9_001);
        jar.remove_expired(&clock);
        assert_eq!(jar.numcookies(), 0);
        assert!(jar.cookies().next().is_none());
    }

    // -----------------------------------------------------------------------
    // `CURLINFO_COOKIELIST` -- `cookie_list` (`lib/cookie.c:1558-1595`).
    // -----------------------------------------------------------------------

    #[test]
    fn the_cookie_list_is_bucket_order_then_insertion_order_and_unsorted() {
        let clock = clock_at(BEFORE_EXPIRY);

        // The store must be a fixed ARRAY of ordered lists for this to be
        // reproducible, which is why `CookieInfo` is `Vec<VecDeque<Cookie>>` of
        // length 63 and never a map. The expectation below is computed from
        // `cookiehash` and the insertion order -- the two things the C's
        // traversal reads -- so a map's randomised iteration would fail it and
        // a different bucket count would too.
        let mut jar = CookieInfo::new();
        let hosts: [&[u8]; 6] = [
            b"one.example",
            b"two.example",
            b"three.example",
            b"four.example",
            b"one.example",
            b"two.example",
        ];
        for (index, host) in hosts.iter().enumerate() {
            let mut line = host.to_vec();
            line.extend_from_slice(b"\tFALSE\t/\tFALSE\t0\tn");
            line.extend_from_slice(index.to_string().as_bytes());
            line.extend_from_slice(b"\tv\n");
            assert!(add_jar(&mut jar, &line, &clock));
        }
        assert_eq!(jar.numcookies(), 6);

        let mut expected: Vec<(usize, usize)> = hosts
            .iter()
            .enumerate()
            .map(|(index, host)| (cookiehash(Some(host)), index))
            .collect();
        expected.sort_by_key(|&(bucket, index)| (bucket, index));

        let list = jar.list(&clock);
        let lines: Vec<String> = list
            .as_ref()
            .map(|slist| slist.iter().map(text).collect())
            .unwrap_or_default();
        assert_eq!(lines.len(), 6);

        for (position, &(_, index)) in expected.iter().enumerate() {
            let mut wanted = b"\tn".to_vec();
            wanted.extend_from_slice(index.to_string().as_bytes());
            wanted.extend_from_slice(b"\tv");
            assert!(
                lines
                    .get(position)
                    .map(|line| line.ends_with(&text(&wanted)))
                    .unwrap_or(false),
                "position {position} should be n{index}: {lines:?}"
            );
        }

        // Every line is exactly what the jar writer would emit for that
        // cookie -- `:1581` calls `get_netscape_format` too -- and carries NO
        // trailing newline, because `Curl_slist_append_nodup` stores the
        // formatted line as-is.
        let formatted: Vec<String> = all(&jar)
            .iter()
            .map(|c| text(&get_netscape_format(c)))
            .collect();
        let mut sorted_lines = lines.clone();
        let mut sorted_formatted = formatted;
        sorted_lines.sort();
        sorted_formatted.sort();
        assert_eq!(sorted_lines, sorted_formatted);
        assert!(lines.iter().all(|line| !line.ends_with('\n')));
    }

    #[test]
    fn the_cookie_list_skips_a_domainless_cookie_and_answers_none_when_empty() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:1566-1567` -- `if(!ci->numcookies) return NULL;`, checked BEFORE
        // the sweep.
        let mut jar = CookieInfo::new();
        assert!(jar.list(&clock).is_none());

        // `:1573-1574` -- a cookie with no domain is skipped, exactly as the
        // jar writer skips it. With nothing else to list, the C's `list` local
        // is still NULL when the walk finishes, and NULL is what it returns --
        // so a store holding only domain-less cookies reports NOTHING rather
        // than an empty list. The two are the same value in C and are modelled
        // as the same `None` here.
        assert!(add_header(&mut jar, b" bare=1", None, None, false, &clock));
        assert_eq!(jar.numcookies(), 1);
        assert!(jar.list(&clock).is_none());

        // With one listable cookie the list has one entry.
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t0\tn\tv\n",
            &clock
        ));
        let list = jar.list(&clock);
        assert_eq!(list.as_ref().map(SList::len), Some(1));
    }

    #[test]
    fn the_cookie_list_sweeps_before_it_reports() {
        // `:1569-1570`
        let clock = clock_at(1_000);
        let mut jar = CookieInfo::new();
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t2000\tdated\tv\n",
            &clock
        ));
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t0\tsession\tv\n",
            &clock
        ));
        assert_eq!(jar.list(&clock).as_ref().map(SList::len), Some(2));

        clock.set_epoch_secs(3_000);
        assert_eq!(jar.list(&clock).as_ref().map(SList::len), Some(1));
        assert_eq!(jar.numcookies(), 1);
    }

    // -----------------------------------------------------------------------
    // Clearing -- `Curl_cookie_clearall` (`:1361`), `_clearsess` (`:1384`)
    // and `_cleanup` (`:1412`).
    // -----------------------------------------------------------------------

    #[test]
    fn clearsess_removes_exactly_the_session_cookies() {
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = load_text(JAR_ASCENDING, &clock);
        assert_eq!(jar.numcookies(), 5);

        jar.clearsess();
        assert_eq!(jar.numcookies(), 4);
        assert!(all(&jar).iter().all(|cookie| cookie.expires() != 0));
        assert!(!text(&saved(&jar)).contains("empty"));

        // Idempotent, and it does not disturb `running` or `lastct`.
        let before = (jar.running(), jar.lastct());
        jar.clearsess();
        assert_eq!(jar.numcookies(), 4);
        assert_eq!((jar.running(), jar.lastct()), before);
    }

    #[test]
    fn clearall_empties_every_bucket_and_cleanup_resets_the_engine() {
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = load_text(JAR_ASCENDING, &clock);
        jar.run();

        jar.clearall();
        assert_eq!(jar.numcookies(), 0);
        assert!(jar.cookies().next().is_none());
        assert!(jar.list(&clock).is_none());
        // Still running, and the header is still written for an empty jar.
        assert!(jar.running());
        assert_eq!(saved(&jar), FILE_HEADER);
        // `:1361-1377` deliberately leaves `next_expiration` alone; it is only
        // a lower bound on when a scan is worthwhile.
        assert_eq!(jar.next_expiration(), 2_139_150_993);

        // `Curl_cookie_cleanup` is `Curl_cookie_clearall(ci); free(ci);`. The
        // free has no counterpart -- dropping the value IS the free -- so what
        // this method performs is the clear, and the flags are deliberately
        // left where they were. There is no C state to compare against after a
        // `free`, and the case the method exists for is `:1647`, where a SHARED
        // store must be emptied without being dropped.
        let mut jar = load_text(JAR_ASCENDING, &clock);
        jar.run();
        jar.set_newsession(true);
        jar.cleanup();
        assert_eq!(jar.numcookies(), 0);
        assert!(jar.cookies().next().is_none());
        assert!(jar.running());
        assert!(jar.newsession());
        assert_eq!(jar.lastct(), 5);

        // And it is reusable afterwards, which is what
        // `tests/libtest/lib676.c` needs: it sets `CURLOPT_COOKIEFILE` to NULL
        // mid-handle and then carries on making requests. The creation-time
        // counter continues rather than restarting, so a cookie added now
        // still sorts after everything that came before.
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t0\tafter\tv\n",
            &clock
        ));
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(jar.lastct(), 6);
        assert_eq!(only(&jar).creationtime(), 6);

        // A brand-new store is the way to get the flags back, and that is what
        // `Curl_cookie_init` does.
        let fresh = CookieInfo::new();
        assert_eq!(fresh.lastct(), 0);
        assert!(!fresh.running());
        assert!(!fresh.newsession());
        assert_eq!(fresh.next_expiration(), CURL_OFF_T_MAX);
    }

    // -----------------------------------------------------------------------
    // `CURLOPT_COOKIELIST`'s command words -- `lib/setopt.c`'s `cookielist()`.
    // -----------------------------------------------------------------------

    #[test]
    fn the_four_command_words_are_matched_case_insensitively_and_whole() {
        // `docs/libcurl/opts/CURLOPT_COOKIELIST.md` documents all four, and the
        // C compares them with `curl_strequal`, so the whole string must match.
        for (word, expected) in [
            (&b"ALL"[..], CookieCommand::All),
            (b"all", CookieCommand::All),
            (b"AlL", CookieCommand::All),
            (b"SESS", CookieCommand::Sess),
            (b"sess", CookieCommand::Sess),
            (b"FLUSH", CookieCommand::Flush),
            (b"flush", CookieCommand::Flush),
            (b"RELOAD", CookieCommand::Reload),
            (b"reload", CookieCommand::Reload),
        ] {
            assert_eq!(cookie_command(word), expected, "{}", text(word));
        }

        // Anything else is a cookie to add, and the flag records whether the
        // header parser is wanted.
        assert_eq!(
            cookie_command(b"example.com\tFALSE\t/\tFALSE\t0\tn\tv"),
            CookieCommand::Add { httpheader: false }
        );
        assert_eq!(
            cookie_command(b"Set-Cookie: n=v"),
            CookieCommand::Add { httpheader: true }
        );
        // `checkprefix` folds case, so the prefix test does too.
        assert_eq!(
            cookie_command(b"set-cookie: n=v"),
            CookieCommand::Add { httpheader: true }
        );
        // A command word with anything appended is NOT a command.
        assert_eq!(
            cookie_command(b"ALLTHINGS"),
            CookieCommand::Add { httpheader: false }
        );
        assert_eq!(
            cookie_command(b" ALL"),
            CookieCommand::Add { httpheader: false }
        );
        assert_eq!(
            cookie_command(b""),
            CookieCommand::Add { httpheader: false }
        );
    }

    #[test]
    fn the_option_surface_skips_eleven_bytes_and_does_not_pass_blanks() {
        // `lib/setopt.c:1616` -- `ptr + 11`, with NO `str_passblanks`, unlike
        // `cookie_load` at `:1123-1126` which does pass them. The difference is
        // real and is preserved; `parse_cookie_header` trims the name anyway,
        // so the two agree on every input.
        assert_eq!(SET_COOKIE_HEADER.len(), 11);
        assert_eq!(strip_set_cookie_prefix(b"Set-Cookie: n=v"), b" n=v");
        assert_eq!(strip_set_cookie_prefix(b"Set-Cookie:n=v"), b"n=v");
        assert_eq!(strip_set_cookie_prefix(b"Set-Cookie:"), b"");
        // Shorter than the prefix: an empty span rather than a panic.
        assert_eq!(strip_set_cookie_prefix(b"Set-"), b"");
        assert_eq!(strip_set_cookie_prefix(b""), b"");

        // And the leading blank the option surface leaves behind is harmless,
        // because the name is trimmed.
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            strip_set_cookie_prefix(b"Set-Cookie: n=v; domain=example.com"),
            Some(b"example.com"),
            Some(b"/"),
            false,
            &clock
        ));
        assert_eq!(only(&jar).name(), b"n");
    }

    #[test]
    fn the_input_length_ceiling_is_the_generic_one() {
        // `lib/setopt.c` guards `CURLOPT_COOKIELIST` with
        // `CURL_MAX_INPUT_LENGTH` and answers `CURLE_BAD_FUNCTION_ARGUMENT`.
        // The constant lives here so the option surface and this module cannot
        // disagree about it; the check itself belongs there, because this
        // function has no channel for a `CURLcode`.
        assert_eq!(CURL_MAX_INPUT_LENGTH, 8_000_000);
        assert_eq!(CURLcode::BadFunctionArgument as i32, 43);
    }

    // -----------------------------------------------------------------------
    // Public-suffix checking -- `is_public_suffix` (`lib/cookie.c:774-819`)
    // through `crate::cookies::psl`.
    // -----------------------------------------------------------------------

    /// The mini list `crate::cookies::psl`'s own tests use, transcribed from
    /// the shapes the real Public Suffix List contains: a plain rule, a
    /// wildcard, an exception, and a private-section entry.
    #[rustfmt::skip]
    const MINI_PSL: &str = concat!(
        "// ===BEGIN ICANN DOMAINS===\n",
        "com\n",
        "uk\n",
        "co.uk\n",
        "*.ck\n",
        "!www.ck\n",
        "// ===END ICANN DOMAINS===\n",
        "// ===BEGIN PRIVATE DOMAINS===\n",
        "blogspot.com\n",
        "*.compute-1.amazonaws.com\n",
        "// ===END PRIVATE DOMAINS===\n",
    );

    #[test]
    fn a_registry_level_domain_is_refused_when_a_list_is_available() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();
        let source = psl::MemoryPslSource::builtin(MINI_PSL);
        let mut cache = psl::PslCache::new();
        assert!(psl::available(Some(&source)));

        let mut ctx = PslContext {
            cache: &mut cache,
            source: &source,
        };

        // `tests/data/test1136`'s rejections, in the shapes this list carries.
        let mut jar = CookieInfo::new();
        let outcome = jar.add(
            b" n=v; domain=co.uk",
            &header_ctx(Some(b"www.co.uk"), Some(b"/"), false),
            &clock,
            &log,
            Some(&mut ctx),
        );
        assert_eq!(outcome, Ok(false));
        assert!(log.said(
            "cookie 'n' dropped, domain 'www.co.uk' must not set cookies \
             for 'co.uk'"
        ));

        // A registrable domain is accepted.
        let mut jar = CookieInfo::new();
        let outcome = jar.add(
            b" n=v; domain=example.co.uk",
            &header_ctx(Some(b"www.example.co.uk"), Some(b"/"), false),
            &clock,
            &log,
            Some(&mut ctx),
        );
        assert_eq!(outcome, Ok(true));
        assert_eq!(jar.numcookies(), 1);

        // The wildcard rule bites two labels deep, which is
        // `tests/data/test1136`'s `example.ck` case.
        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.add(
                b" n=v; domain=example.ck",
                &header_ctx(Some(b"www.example.ck"), Some(b"/"), false),
                &clock,
                &log,
                Some(&mut ctx),
            ),
            Ok(false)
        );

        // And its exception un-bites it.
        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.add(
                b" n=v; domain=www.ck",
                &header_ctx(Some(b"a.www.ck"), Some(b"/"), false),
                &clock,
                &log,
                Some(&mut ctx),
            ),
            Ok(true)
        );
    }

    #[test]
    fn an_ip_numeric_cookie_domain_is_never_offered_to_the_list() {
        let clock = clock_at(BEFORE_EXPIRY);
        let source = psl::MemoryPslSource::builtin(MINI_PSL);
        let mut cache = psl::PslCache::new();
        let mut ctx = PslContext {
            cache: &mut cache,
            source: &source,
        };

        // `:786` -- `!Curl_host_is_ipnum(co->domain)` is a term of the guard,
        // so an address is accepted without consulting the list at all.
        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.add(
                b" n=v; domain=127.0.0.1",
                &header_ctx(Some(b"127.0.0.1"), Some(b"/"), false),
                &clock,
                &NoLog,
                Some(&mut ctx),
            ),
            Ok(true)
        );
        // The list was never loaded, because the guard short-circuits first.
        assert!(!cache.has_list());
    }

    #[test]
    fn a_domain_at_or_past_the_buffer_size_is_dropped_without_a_word() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();
        let source = psl::MemoryPslSource::builtin(MINI_PSL);
        let mut cache = psl::PslCache::new();
        let mut ctx = PslContext {
            cache: &mut cache,
            source: &source,
        };

        // `:788-789` -- the C copies into two `char[256]` stack buffers and
        // `:791` demands STRICTLY less than that, because `dlen + 1` bytes are
        // written. Over the limit, `acceptable` stays FALSE and the cookie is
        // dropped -- with the generic rejection line, and with no separate
        // diagnostic saying why the check was skipped.
        assert_eq!(psl::MAX_PSL_DOMAIN_LEN, 256);

        let long_label = "a".repeat(psl::MAX_PSL_DOMAIN_LEN);
        let mut line = b" n=v; domain=".to_vec();
        line.extend_from_slice(long_label.as_bytes());
        line.extend_from_slice(b".com");

        let mut host = long_label.clone().into_bytes();
        host.extend_from_slice(b".com");

        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.add(
                &line,
                &header_ctx(Some(&host), Some(b"/"), false),
                &clock,
                &log,
                Some(&mut ctx),
            ),
            Ok(false)
        );
        assert!(log.said("must not set cookies for"));
        assert!(!log.said("libpsl problem"));
    }

    #[test]
    fn a_configured_but_broken_list_fails_closed() {
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `:800-803` -- `Curl_psl_use` answering NULL is the `psl == NULL`
        // arm, and the C's choice there is to REFUSE the cookie. A source that
        // is configured and cannot produce a list is exactly that state.
        let source = psl::MemoryPslSource::empty();
        assert!(!psl::available(Some(&source)));
        let mut cache = psl::PslCache::new();
        let mut ctx = PslContext {
            cache: &mut cache,
            source: &source,
        };

        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.add(
                b" n=v; domain=example.com",
                &header_ctx(Some(b"www.example.com"), Some(b"/"), false),
                &clock,
                &log,
                Some(&mut ctx),
            ),
            Ok(false)
        );
        assert!(log.said("libpsl problem, rejecting cookie for safety"));
        assert!(log.said("must not set cookies for"));
    }

    #[test]
    fn with_no_list_configured_the_bad_domain_arm_governs_instead() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `psl = None` is the `#ifndef USE_LIBPSL` build. `is_public_suffix`
        // never drops a cookie, and the protection that remains is
        // `bad_domain` plus the `":"` sentinel -- which
        // `docs/HTTP-COOKIES.md` describes honestly as having *"no ability to
        // stop super cookies"*. `crate::version` must not emit `PSL` here.
        assert!(!psl::available(None));

        // A registry-level domain that PSL would refuse is accepted, because
        // it has a dot.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" n=v; domain=co.uk",
            Some(b"www.co.uk"),
            Some(b"/"),
            false,
            &clock
        ));
        assert_eq!(only(&jar).domain(), Some(&b"co.uk"[..]));

        // A dotless one is still refused, through the sentinel.
        let mut jar = CookieInfo::new();
        assert!(!add_header(
            &mut jar,
            b" n=v; domain=uk",
            Some(b"www.uk"),
            Some(b"/"),
            false,
            &clock
        ));
    }

    #[test]
    fn the_host_comes_first_in_the_acceptability_question() {
        // `:797` -- `psl_is_cookie_domain_acceptable(psl, lcase, lcookie)`, the
        // HOST then the cookie domain. Both orders are plausible from the name
        // alone, and swapping them silently INVERTS the check, so the direction
        // is asserted through the engine rather than by reading the call.
        //
        // The discriminating case: a host being given a cookie for its own
        // registrable parent is acceptable, while the reverse -- a parent
        // setting a cookie for a name BELOW it -- is not. Under a swap the
        // assertion below would refuse the cookie.
        let clock = clock_at(BEFORE_EXPIRY);
        let source = psl::MemoryPslSource::builtin(MINI_PSL);
        let mut cache = psl::PslCache::new();
        let mut ctx = PslContext {
            cache: &mut cache,
            source: &source,
        };

        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.add(
                b" n=v; domain=example.co.uk",
                &header_ctx(Some(b"deep.www.example.co.uk"), Some(b"/"), false),
                &clock,
                &NoLog,
                Some(&mut ctx),
            ),
            Ok(true),
            "a host may be given a cookie for its registrable parent"
        );

        // And the list really was consulted, so the acceptance is the
        // predicate's answer and not the guard short-circuiting.
        assert!(cache.has_list());

        // The refusal in the other direction is the registry-level case that
        // `a_registry_level_domain_is_refused_when_a_list_is_available`
        // asserts: `domain=co.uk` for host `www.co.uk` is dropped, and a swap
        // would make it acceptable. The two tests together pin the order from
        // both sides.
    }
    // -----------------------------------------------------------------------
    // Coverage relocated from the C test programs (AAP 0.8.7).
    //
    // These seven link a debug static libcurl and call internal `Curl_*`
    // symbols, which a Rust static library does not export. What each one
    // actually asserts about the cookie engine is reproduced here; nothing is
    // re-exported to make them link, because that would defeat the
    // encapsulation the zero-`unsafe` guarantee rests on.
    // -----------------------------------------------------------------------

    #[test]
    fn one_store_accumulates_cookies_from_several_transfers() {
        // `tests/libtest/lib506.c` (370 lines) and `lib586.c` (240) drive four
        // easy handles that SHARE one cookie store, through
        // `CURLSHOPT_SHARE`/`CURL_LOCK_DATA_COOKIE` and, in lib586's case, with
        // user-supplied lock callbacks. The locking is `crate::share`'s to
        // build -- see the module header's transition contract -- so what
        // relocates here is the store behaviour those tests depend on: every
        // transfer's cookies land in the one store, none is lost, and
        // `CURLINFO_COOKIELIST` enumerates them all.
        let clock = clock_at(BEFORE_EXPIRY);
        let mut shared = CookieInfo::new();
        shared.run();

        for handle in 0..4u32 {
            let mut line = b" c".to_vec();
            line.extend_from_slice(handle.to_string().as_bytes());
            line.extend_from_slice(b"=v; domain=host");
            line.extend_from_slice(handle.to_string().as_bytes());
            line.extend_from_slice(b".example; path=/");
            let mut host = b"host".to_vec();
            host.extend_from_slice(handle.to_string().as_bytes());
            host.extend_from_slice(b".example");
            assert!(add_header(
                &mut shared,
                &line,
                Some(&host),
                Some(b"/"),
                false,
                &clock
            ));
        }
        assert_eq!(shared.numcookies(), 4);
        assert_eq!(shared.lastct(), 4);

        let list = shared.list(&clock);
        assert_eq!(list.as_ref().map(SList::len), Some(4));

        // Each handle then sends back exactly its own cookie, because the
        // domains differ.
        for handle in 0..4u32 {
            let mut host = b"host".to_vec();
            host.extend_from_slice(handle.to_string().as_bytes());
            host.extend_from_slice(b".example");
            let mut wanted = b"Cookie: c".to_vec();
            wanted.extend_from_slice(handle.to_string().as_bytes());
            wanted.extend_from_slice(b"=v\r\n");
            assert_eq!(
                shared
                    .cookie_header_line(
                        &host, b"/", false, None, &clock, &NoLog
                    )
                    .as_deref()
                    .map(text),
                Some(text(&wanted))
            );
        }
    }

    #[test]
    fn an_empty_cookiefile_activates_the_engine_without_reading_anything() {
        // `tests/libtest/lib1549.c` and `lib3103.c` both set
        // `CURLOPT_COOKIEFILE` to `""`, which is how an application turns the
        // engine on with no file at all. `cookie_load`'s `if(file && *file)` at
        // `:1102` then opens nothing, and `:1147` still marks the store
        // running.
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();
        let mut jar = CookieInfo::new();
        assert!(!jar.running());

        assert_eq!(
            jar.load(CookieFile::Inactive, false, &clock, &log, None),
            Ok(())
        );
        assert!(jar.running());
        assert_eq!(jar.numcookies(), 0);
        // Nothing was opened, so nothing was warned about.
        assert_eq!(log.count(), 0);

        // `lib1549.c` then performs a transfer and enumerates
        // `CURLINFO_COOKIELIST`, printing one line per cookie and counting
        // them. With no transfer the list is absent rather than empty.
        assert!(jar.list(&clock).is_none());

        // And with one cookie from a response, exactly one line.
        assert!(add_header(
            &mut jar,
            b" c1=v1; domain=localhost",
            Some(b"localhost"),
            Some(b"/"),
            false,
            &clock
        ));
        let list = jar.list(&clock);
        assert_eq!(list.as_ref().map(SList::len), Some(1));
        assert_eq!(
            list.as_ref()
                .and_then(|slist| slist.iter().next().map(text)),
            // The leading dot is the Mozilla-style one `:1439-1443` prepends
            // because `tailmatch` is set; `localhost` itself has no dot in the
            // header.
            Some(text(b".localhost\tTRUE\t/\tFALSE\t0\tc1\tv1"))
        );
    }

    #[test]
    fn a_cookie_with_neither_max_age_nor_expires_is_a_session_cookie() {
        // `tests/libtest/lib3103.c` (64 lines) injects exactly
        // `Set-Cookie: c1=v1; domain=localhost` through `CURLOPT_COOKIELIST`
        // into a SHARED store and performs a transfer. What it is guarding is
        // that a cookie with no expiry is stored as a session cookie and is
        // then sent -- the bug it was written for being a crash on the
        // shared-store path.
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.load(CookieFile::Inactive, false, &clock, &NoLog, None),
            Ok(())
        );

        // The option surface classifies the string and strips the prefix.
        let raw = b"Set-Cookie: c1=v1; domain=localhost";
        assert_eq!(
            cookie_command(raw),
            CookieCommand::Add { httpheader: true }
        );
        let rest = strip_set_cookie_prefix(raw);
        assert!(matches!(
            jar.add(
                rest,
                &AddContext {
                    httpheader: true,
                    noexpire: false,
                    domain: None,
                    path: None,
                    secure: true,
                    setcookies: 0,
                },
                &clock,
                &NoLog,
                None,
            ),
            Ok(true)
        ));

        let stored = only(&jar);
        assert_eq!(stored.expires(), 0, "no expiry means a session cookie");
        assert_eq!(stored.domain(), Some(&b"localhost"[..]));
        assert!(stored.tailmatch());
        // No `Path` attribute and no request path, so the path is ABSENT.
        assert_eq!(stored.path(), None);

        // It is sent to `localhost`, which is also a secure context.
        assert_eq!(
            jar.cookie_header_line(
                b"localhost",
                b"/",
                false,
                None,
                &clock,
                &NoLog
            )
            .as_deref()
            .map(text),
            Some(text(b"Cookie: c1=v1\r\n"))
        );

        // And `clearsess` -- the `SESS` command word -- removes it.
        jar.clearsess();
        assert_eq!(jar.numcookies(), 0);
    }

    #[test]
    fn a_jar_survives_a_handle_reset() {
        // `tests/libtest/lib1920.c` (55 lines) loads a jar, performs a
        // transfer, calls `curl_easy_reset` and only then cleans up, checking
        // that the jar still holds both cookies afterwards. The engine is what
        // has to survive; here that is the store outliving the request.
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = CookieInfo::new();
        let mut input: &[u8] = b"# Netscape HTTP Cookie File\n\
            example.com\tFALSE\t/\tFALSE\t0\thas_js\t1\n";
        assert!(jar.read_from(&mut input, &clock, &NoLog, None).is_ok());
        jar.run();

        // The response cookie.
        assert!(add_header(
            &mut jar,
            b" cookiename=cookiecontent;",
            Some(b"127.0.0.1"),
            Some(b"/"),
            false,
            &clock
        ));

        // A reset does not touch the store, so the jar written at cleanup has
        // both -- newest first, which is `tests/data/test1920`'s expectation.
        #[rustfmt::skip]
        let expected: Vec<u8> = [
            FILE_HEADER,
            b"127.0.0.1\tFALSE\t/\tFALSE\t0\tcookiename\tcookiecontent\n",
            b"example.com\tFALSE\t/\tFALSE\t0\thas_js\t1\n",
        ]
        .concat();
        assert_eq!(text(&saved(&jar)), text(&expected));
    }

    // -- The filesystem ---------------------------------------------------
    //
    // Grouped and separately gated, because Miri's isolation refuses `mkdir`.
    // Everything above runs under Miri, which is why the reader and the writer
    // are generic over [`BufRead`] and [`Write`] rather than taking paths.

    /// Binds a scratch directory, failing loudly if the environment cannot
    /// provide one.
    ///
    /// A macro rather than a function because the failure arm has to leave the
    /// *test*. Modelled on the helper of the same name in
    /// [`crate::util::fopen`] and in `crate::cookies::hsts`, so that a reader
    /// who knows one knows all three.
    macro_rules! scratch {
        ($name:ident) => {
            let $name = tempfile::tempdir();
            assert!(
                $name.is_ok(),
                "this test needs a scratch directory: {:?}",
                $name.as_ref().err()
            );
            let Ok($name) = $name else { return };
        };
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_jar_round_trips_through_real_files() {
        scratch!(dir);
        let path = dir.path().join("cookies.txt");
        let clock = clock_at(BEFORE_EXPIRY);

        // Write curl's bytes out with the ordinary filesystem tools, so the
        // input really is a file this module did not create.
        assert!(std::fs::write(&path, JAR_ASCENDING).is_ok());

        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.load(CookieFile::Path(&path), false, &clock, &NoLog, None),
            Ok(())
        );
        assert_eq!(jar.numcookies(), 5);
        assert!(jar.running());

        // Save over the same path and compare against the fixture's expected
        // jar, byte for byte.
        let out = dir.path().join("out.txt");
        assert_eq!(
            jar.save(CookieFile::Path(&out), fixed_suffix, &clock),
            Ok(())
        );
        let on_disk = std::fs::read(&out);
        assert!(on_disk.is_ok());
        assert_eq!(
            on_disk.as_deref().map(text).ok(),
            Some(text(JAR_DESCENDING))
        );

        // The temporary file is gone, the rename having moved it into place.
        let strays: Vec<String> = std::fs::read_dir(dir.path())
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| {
                        entry.file_name().to_string_lossy().into_owned()
                    })
                    .filter(|name| name != "cookies.txt" && name != "out.txt")
                    .collect()
            })
            .unwrap_or_default();
        assert!(strays.is_empty(), "a temporary was left behind: {strays:?}");

        // A second generation through real files is the identity.
        let mut second = CookieInfo::new();
        assert_eq!(
            second.load(CookieFile::Path(&out), false, &clock, &NoLog, None),
            Ok(())
        );
        let third = dir.path().join("third.txt");
        assert_eq!(
            second.save(CookieFile::Path(&third), fixed_suffix, &clock),
            Ok(())
        );
        assert_eq!(
            std::fs::read(&third).as_deref().map(text).ok(),
            Some(text(JAR_ASCENDING))
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_missing_cookie_file_is_a_warning_and_not_an_error() {
        scratch!(dir);
        let path = dir.path().join("absent.txt");
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();

        // `:1108-1110` -- *"WARNING: failed to open cookie file"*, and
        // `CURLE_OK`. The engine still ends up running, which is what lets an
        // application name a jar that does not exist yet.
        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.load(CookieFile::Path(&path), false, &clock, &log, None),
            Ok(())
        );
        assert!(jar.running());
        assert_eq!(jar.numcookies(), 0);
        assert!(log.said("WARNING: failed to open cookie file"));
        assert!(log.said("absent.txt"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_header_format_cookie_file_loads_through_the_header_parser() {
        scratch!(dir);
        let path = dir.path().join("heads.txt");
        let clock = clock_at(BEFORE_EXPIRY);

        // `tests/data/test8` supplies a saved response as the cookie file, and
        // `:1121-1127` detects each `Set-Cookie:` line with `checkprefix`,
        // skips eleven bytes, passes blanks and parses it as a header.
        assert!(std::fs::write(&path, test8_cookie_file()).is_ok());

        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.load(CookieFile::Path(&path), false, &clock, &NoLog, None),
            Ok(())
        );
        assert_eq!(jar.numcookies(), 12);

        assert_eq!(
            jar.cookie_header_line(
                b"127.0.0.1",
                b"/we/want/8",
                false,
                None,
                &clock,
                &NoLog
            )
            .as_deref()
            .map(text),
            Some(text(TEST8_COOKIE_HEADER))
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn cookie_files_are_read_in_the_order_they_were_configured() {
        scratch!(dir);
        let clock = clock_at(BEFORE_EXPIRY);

        // `Curl_cookie_loadfiles` walks the `CURLOPT_COOKIEFILE` slist head to
        // tail (`:1168-1172`), and `crate::util::slist` preserves that order
        // exactly. The creation times therefore follow the configuration
        // order, which the jar's own order then reverses.
        let first = dir.path().join("a.txt");
        let second = dir.path().join("b.txt");
        assert!(std::fs::write(
            &first,
            b"a.example\tFALSE\t/\tFALSE\t0\tfrom\ta\n"
        )
        .is_ok());
        assert!(std::fs::write(
            &second,
            b"b.example\tFALSE\t/\tFALSE\t0\tfrom\tb\n"
        )
        .is_ok());

        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.loadfiles(
                &[CookieFile::Path(&first), CookieFile::Path(&second)],
                false,
                &clock,
                &NoLog,
                None
            ),
            Ok(())
        );
        assert_eq!(jar.numcookies(), 2);
        let written = text(&saved(&jar));
        let from_b = written.find("from\tb");
        let from_a = written.find("from\ta");
        assert!(from_b.is_some() && from_a.is_some());
        assert!(from_b < from_a, "newest first: {written}");

        // Reversing the configuration reverses the outcome.
        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.loadfiles(
                &[CookieFile::Path(&second), CookieFile::Path(&first)],
                false,
                &clock,
                &NoLog,
                None
            ),
            Ok(())
        );
        let written = text(&saved(&jar));
        assert!(written.find("from\ta") < written.find("from\tb"));

        // A missing file in the middle does not stop the walk, because a
        // failed open is not an error.
        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.loadfiles(
                &[
                    CookieFile::Path(&first),
                    CookieFile::Path(&dir.path().join("gone.txt")),
                    CookieFile::Path(&second),
                ],
                false,
                &clock,
                &NoLog,
                None
            ),
            Ok(())
        );
        assert_eq!(jar.numcookies(), 2);

        // An UNREADABLE line does, though: `:1170-1171` is `if(result) return
        // result;`, so the walk stops at the first genuine error and the
        // remaining files are never opened.
        let broken = dir.path().join("broken.txt");
        let mut over = b"c.example\tFALSE\t/\tFALSE\t0\tn\t".to_vec();
        let pad = MAX_COOKIE_LINE - over.len();
        over.extend_from_slice(&vec![b'v'; pad]);
        over.push(b'\n');
        assert!(std::fs::write(&broken, &over).is_ok());

        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.loadfiles(
                &[
                    CookieFile::Path(&first),
                    CookieFile::Path(&broken),
                    CookieFile::Path(&second),
                ],
                false,
                &clock,
                &NoLog,
                None
            ),
            Err(CURLcode::TooLarge)
        );
        // The first file was read; the third never was.
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(only(&jar).value(), Some(&b"a"[..]));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_reload_does_not_displace_a_live_cookie() {
        scratch!(dir);
        let path = dir.path().join("jar.txt");
        let clock = clock_at(BEFORE_EXPIRY);

        // The end of the in-memory test named after `livecookie`.
        // `:1100` puts the flag DOWN for the duration of a load, so cookies
        // read from the file are not live while the one already present is --
        // and `:896-904` then refuses the file's version. This is the
        // `CURLOPT_COOKIELIST: RELOAD` path.
        let mut jar = CookieInfo::new();
        jar.run();
        assert!(add_header(
            &mut jar,
            b" sid=live; domain=example.com; path=/",
            Some(b"example.com"),
            Some(b"/"),
            false,
            &clock
        ));
        assert!(only(&jar).livecookie());

        assert!(std::fs::write(
            &path,
            b"example.com\tTRUE\t/\tFALSE\t0\tsid\tfromfile\n"
        )
        .is_ok());
        assert_eq!(
            jar.load(CookieFile::Path(&path), false, &clock, &NoLog, None),
            Ok(())
        );

        // Still one cookie, and still the live one.
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(only(&jar).value(), Some(&b"live"[..]));
        assert!(jar.running());

        // Whereas a DIFFERENT cookie from the same file is taken.
        assert!(std::fs::write(
            &path,
            b"example.com\tTRUE\t/\tFALSE\t0\tother\tfromfile\n"
        )
        .is_ok());
        assert_eq!(
            jar.load(CookieFile::Path(&path), false, &clock, &NoLog, None),
            Ok(())
        );
        assert_eq!(jar.numcookies(), 2);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_failed_save_has_already_truncated_the_target() {
        scratch!(dir);
        let path = dir.path().join("jar.txt");
        let clock = clock_at(BEFORE_EXPIRY);

        // `Curl_fopen` opens the target `"w"` in order to `fstat` it
        // (`lib/curl_fopen.c:99-102`), which TRUNCATES it before the temporary
        // file exists. So a save that fails after that point has already
        // destroyed the jar it was asked to replace. Measured C behaviour, and
        // preserved rather than tidied -- see the note on
        // `CookieInfo::save`.
        //
        // The failure is arranged by making the temporary-name provider fail,
        // which is the first thing after the truncation (`:109-111`), and which
        // needs no permissions and no root-bypass probe.
        assert!(std::fs::write(&path, JAR_ASCENDING).is_ok());
        assert_eq!(
            std::fs::read(&path).map(|b| b.len()).ok(),
            Some(JAR_ASCENDING.len())
        );

        let mut jar = load_text(JAR_ASCENDING, &clock);
        assert_eq!(
            jar.save(
                CookieFile::Path(&path),
                || Err(CURLcode::OutOfMemory),
                &clock
            ),
            // The provider's code is propagated unchanged, not remapped to a
            // write error.
            Err(CURLcode::OutOfMemory)
        );

        // And the original jar is gone.
        assert_eq!(std::fs::read(&path).map(|bytes| bytes.len()).ok(), Some(0));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn an_unopenable_target_is_a_write_error() {
        scratch!(dir);
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = load_text(JAR_ASCENDING, &clock);

        // `:1484-1486` -- *"Failed to create file %s"* becomes
        // `CURLE_WRITE_ERROR`. A path whose parent does not exist is `ENOENT`
        // and does not depend on the process's privileges.
        let unreachable = dir.path().join("no-such-dir").join("jar.txt");
        assert_eq!(
            jar.save(CookieFile::Path(&unreachable), fixed_suffix, &clock),
            Err(CURLcode::WriteError)
        );

        // A directory is also unopenable for writing.
        assert_eq!(
            jar.save(CookieFile::Path(dir.path()), fixed_suffix, &clock),
            Err(CURLcode::WriteError)
        );

        // And the empty name, which `Curl_fopen` reaches as `fopen("", "w")`.
        assert_eq!(
            jar.save(CookieFile::Inactive, fixed_suffix, &clock),
            Err(CURLcode::WriteError)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not model /dev/null")]
    fn a_target_that_is_not_a_regular_file_is_written_directly() {
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = load_text(JAR_ASCENDING, &clock);
        let devnull = Path::new("/dev/null");
        if !devnull.exists() {
            return;
        }

        // `Curl_fopen`'s `!S_ISREG` arm keeps the handle and makes no
        // temporary, so there is no rename and the device node survives. A
        // rename here would replace `/dev/null` with a regular file.
        assert_eq!(
            jar.save(CookieFile::Path(devnull), fixed_suffix, &clock),
            Ok(())
        );
        let metadata = std::fs::metadata(devnull);
        assert!(metadata.is_ok());
        assert_eq!(metadata.map(|m| m.is_file()).ok(), Some(false));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn the_flush_saves_only_when_a_jar_is_named_and_the_engine_is_running() {
        scratch!(dir);
        let path = dir.path().join("jar.txt");
        let clock = clock_at(BEFORE_EXPIRY);

        // `:1613` -- `if(data->set.str[STRING_COOKIEJAR] && cookies->running)`.
        // Both terms, and neither is optional.
        let mut jar = load_text(JAR_ASCENDING, &clock);
        assert!(!jar.running());
        assert!(jar
            .flush(Some(CookieFile::Path(&path)), fixed_suffix, &clock, &NoLog)
            .is_none());
        assert!(!path.exists());

        jar.run();
        assert!(jar.flush(None, fixed_suffix, &clock, &NoLog).is_none());
        assert!(!path.exists());

        assert_eq!(
            jar.flush(
                Some(CookieFile::Path(&path)),
                fixed_suffix,
                &clock,
                &NoLog
            ),
            Some(Ok(()))
        );
        assert_eq!(
            std::fs::read(&path).as_deref().map(text).ok(),
            Some(text(JAR_DESCENDING))
        );

        // `:1616-1620` -- a failure is reported AND announced.
        let log = Recorder::default();
        let unreachable = dir.path().join("no-such-dir").join("jar.txt");
        assert_eq!(
            jar.flush(
                Some(CookieFile::Path(&unreachable)),
                fixed_suffix,
                &clock,
                &log
            ),
            Some(Err(CURLcode::WriteError))
        );
        assert!(log.said("WARNING: failed to save cookies in"));

        // The store is untouched by a flush, whichever way it went: destroying
        // it is `:1645-1650`'s decision and it depends on whether the store is
        // shared, which is `crate::share`'s to know.
        assert_eq!(jar.numcookies(), 5);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not model stdout redirection")]
    fn the_name_dash_writes_the_jar_to_standard_output() {
        // `:1477-1481` -- *"use stdout"*, and that path bypasses `Curl_fopen`
        // entirely: no temporary file, no rename, no unlink.
        // `docs/libcurl/opts/CURLOPT_COOKIEJAR.md` documents the name.
        // The bytes go to this test's captured stdout, so what is asserted is
        // that the path is taken and reports success.
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = load_text(JAR_ASCENDING, &clock);
        assert_eq!(jar.save(CookieFile::Stdio, fixed_suffix, &clock), Ok(()));

        // And the bytes it sends are the ones `write_to` produces, which the
        // in-memory tests already compare against curl's own.
        assert_eq!(text(&saved(&jar)), text(JAR_DESCENDING));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri does not model /dev/full")]
    fn a_write_that_fails_midway_reports_it_and_cleans_up() {
        // The one way a save can fail AFTER `Curl_fopen` has succeeded, which
        // is the C's `if(result && tempstore) unlink(tempstore)` arm at
        // `:1548-1554`. `/dev/full` accepts an open and answers `ENOSPC` to
        // every write, and being a character device it takes `Curl_fopen`'s
        // `!S_ISREG` path -- so there is no temporary to remove and the device
        // node is not replaced.
        let full = Path::new("/dev/full");
        if !full.exists() {
            return;
        }
        let clock = clock_at(BEFORE_EXPIRY);
        let mut jar = load_text(JAR_ASCENDING, &clock);

        assert_eq!(
            jar.save(CookieFile::Path(full), fixed_suffix, &clock),
            Err(CURLcode::WriteError)
        );
        let metadata = std::fs::metadata(full);
        assert_eq!(metadata.map(|m| m.is_file()).ok(), Some(false));
        // The store is untouched by a failed save.
        assert_eq!(jar.numcookies(), 5);
    }

    // -----------------------------------------------------------------------
    // The remaining branches, each reached deliberately rather than left to
    // chance. Together with everything above these bring the file's own line
    // coverage to the high nineties; the handful that stay unvisited are
    // defensive arms whose C originals are equally unreachable, and each is
    // named in the comment beside it.
    // -----------------------------------------------------------------------

    #[test]
    fn a_line_is_truncated_at_the_first_zero_byte() {
        // `c_string` stands in for the C's NUL termination, which
        // `Curl_get_line` has already applied to a jar line
        // (`lib/curl_get_line.c:46`) and which a header value inherits from
        // the buffer it lives in.
        assert_eq!(c_string(b"abc\0def"), b"abc");
        assert_eq!(c_string(b"\0abc"), b"");
        assert_eq!(c_string(b"abc"), b"abc");
        assert_eq!(c_string(b""), b"");

        let clock = clock_at(BEFORE_EXPIRY);

        // End to end, on both parsers: everything past the zero is invisible.
        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" n=v\0; domain=evil.example",
            None,
            Some(b"/"),
            false,
            &clock
        ));
        let stored = only(&jar);
        assert_eq!(stored.value(), Some(&b"v"[..]));
        assert_eq!(stored.domain(), None);

        let jar = load_text(
            b"example.com\tFALSE\t/\tFALSE\t0\tn\tv\0extra\n",
            &clock,
        );
        assert_eq!(only(&jar).value(), Some(&b"v"[..]));
    }

    #[test]
    fn the_diagnostic_renderers_match_the_c_format_strings() {
        // The C prints these spans with `%s`, so a byte that is not text has to
        // survive the trip, and an ABSENT pointer has to render the way glibc
        // renders one -- which is what a reader comparing a `--verbose`
        // transcript will see.
        assert_eq!(format!("{}", Text(b"example.com")), "example.com");
        assert_eq!(format!("{}", Text(b"")), "");
        assert_eq!(
            format!("{}", Text(b"\xe5\xe4\xf6")),
            "\u{fffd}\u{fffd}\u{fffd}"
        );
        assert_eq!(format!("{}", OptText(Some(b"x"))), "x");
        assert_eq!(format!("{}", OptText(None)), "(nil)");

        // And a store with no domain really does reach that arm, through
        // `replace_existing`'s overlay diagnostic.
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();
        let mut jar = CookieInfo::new();
        // A secure cookie with a path but no domain, then its plain namesake.
        assert!(add_header(
            &mut jar,
            b" a=secret; path=/login; secure",
            None,
            None,
            true,
            &clock
        ));
        jar.run();
        assert_eq!(
            jar.add(
                b" a=plain; path=/login/en",
                &header_ctx(None, None, false),
                &clock,
                &log,
                None,
            ),
            Ok(false)
        );
        assert!(log.said("would overlay an existing cookie"));
        assert!(log.joined().contains("(nil)"));
    }

    #[test]
    fn the_psl_context_renders_its_state_rather_than_its_list() {
        // A parsed list has no useful rendering and the source is a trait
        // object, so `Debug` shows what a reader would want: whether a list is
        // loaded, and where one would come from.
        let source = psl::MemoryPslSource::builtin(MINI_PSL);
        let mut cache = psl::PslCache::new();
        let ctx = PslContext {
            cache: &mut cache,
            source: &source,
        };
        let rendered = format!("{ctx:?}");
        assert!(rendered.contains("PslContext"));
        assert!(rendered.contains("has_list"));
        assert!(rendered.contains("false"));
    }

    #[test]
    fn the_jar_name_renders_the_two_nameless_targets() {
        // `Curl_flush_cookies`'s warning prints the filename with `%s`, and the
        // C's filename for those two cases is the empty string and `"-"`.
        let clock = clock_at(BEFORE_EXPIRY);
        let log = Recorder::default();
        let mut jar = load_text(JAR_ASCENDING, &clock);
        jar.run();

        // `Inactive` is the empty name, which `Curl_fopen` cannot open.
        assert_eq!(
            jar.flush(Some(CookieFile::Inactive), fixed_suffix, &clock, &log),
            Some(Err(CURLcode::WriteError))
        );
        assert!(log.said("WARNING: failed to save cookies in "));

        // And `Stdio` renders as `-`, which is the name that selected it.
        assert_eq!(format!("{}", JarName(CookieFile::Stdio)), "-");
        assert_eq!(format!("{}", JarName(CookieFile::Inactive)), "");
        assert_eq!(
            format!("{}", JarName(CookieFile::Path(Path::new("/tmp/j.txt")))),
            "/tmp/j.txt"
        );
    }

    #[test]
    fn a_max_age_at_the_ceiling_takes_the_overflow_guard() {
        let now = 1_700_000_000;
        let clock = clock_at(now);

        // `:576-577` clamps a `STRE_OVERFLOW` to `CURL_OFF_T_MAX`, but a value
        // that PARSES and only overflows when `now` is added reaches the
        // addition itself -- which is why that addition is guarded rather than
        // plain. The C wraps here on a signed type; this saturates, because a
        // panic in this file could unwind into a C caller.
        let mut jar = CookieInfo::new();
        let mut line = b" n=v; path=/; max-age=".to_vec();
        line.extend_from_slice(CURL_OFF_T_MAX.to_string().as_bytes());
        assert!(add_header(&mut jar, &line, None, None, false, &clock));

        let capped = ((now + COOKIES_MAXAGE + 30) / 60) * 60;
        assert_eq!(only(&jar).expires(), capped);
    }

    #[test]
    fn an_expiry_at_the_epoch_is_bumped_off_zero() {
        let now = 1_700_000_000;
        let clock = clock_at(now);

        // `:621-623` -- *"this cookie is expired, so it is not stored as a
        // session cookie"*: a date that resolves to exactly the epoch would be
        // indistinguishable from *no expiry*, so it becomes 1.
        assert_eq!(getdate_capped(b"Thu, 01-Jan-1970 00:00:00 GMT"), Some(0));

        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" n=v; path=/; expires=Thu, 01-Jan-1970 00:00:00 GMT",
            None,
            None,
            false,
            &clock
        ));
        assert_eq!(only(&jar).expires(), 1);
        // And it is swept on the next pass, being long past.
        jar.remove_expired(&clock);
        assert_eq!(jar.numcookies(), 0);
    }

    #[test]
    fn a_six_field_line_can_still_be_refused_by_the_fall_through() {
        let clock = clock_at(BEFORE_EXPIRY);

        // Field 2's fall-through hands its own span to field 3, so a SIX-field
        // line can be dropped by the inverted `secure` gate exactly as a
        // seven-field one can.
        let mut jar = CookieInfo::new();
        assert_eq!(
            jar.add(
                b"example.com\tFALSE\tTRUE\t0\tn\tv",
                &AddContext {
                    httpheader: false,
                    noexpire: true,
                    domain: None,
                    path: None,
                    secure: false,
                    setcookies: 0,
                },
                &clock,
                &NoLog,
                None,
            ),
            Ok(false)
        );
        assert_eq!(jar.numcookies(), 0);

        // The same line with the store running is stored, secure, at `"/"`.
        let mut jar = CookieInfo::new();
        jar.run();
        assert!(matches!(
            jar.add(
                b"example.com\tFALSE\tTRUE\t0\tn\tv",
                &AddContext {
                    httpheader: false,
                    noexpire: true,
                    domain: None,
                    path: None,
                    secure: false,
                    setcookies: 0,
                },
                &clock,
                &NoLog,
                None,
            ),
            Ok(true)
        ));
        let stored = only(&jar);
        assert!(stored.secure());
        assert_eq!(stored.path(), Some(&b"/"[..]));
    }

    #[test]
    fn the_public_suffix_guard_needs_a_request_host() {
        let clock = clock_at(BEFORE_EXPIRY);
        let source = psl::MemoryPslSource::builtin(MINI_PSL);
        let mut cache = psl::PslCache::new();
        let mut ctx = PslContext {
            cache: &mut cache,
            source: &source,
        };

        // `:786` -- `data && domain && co->domain && !ipnum`. A FILE load has
        // no request host, so the check cannot run and the cookie is accepted
        // however registry-level its domain is. That is the C's behaviour and
        // the reason a jar can carry anything a previous run put there.
        let mut jar = CookieInfo::new();
        assert!(matches!(
            jar.add(
                b"co.uk\tTRUE\t/\tFALSE\t0\tn\tv",
                &jar_ctx(),
                &clock,
                &NoLog,
                Some(&mut ctx),
            ),
            Ok(true)
        ));
        assert_eq!(only(&jar).domain(), Some(&b"co.uk"[..]));
        // The list was never consulted.
        assert!(!cache.has_list());
    }

    #[test]
    fn the_replacement_search_stops_at_the_first_candidate() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:875` -- `if(!replace_n && ...)`. Once a candidate is found the rest
        // of the bucket is only scanned for the SECURE OVERLAY test, not for
        // another replacement, so a second identical cookie could never be
        // reached even if one existed.
        let mut jar = CookieInfo::new();
        for line in [
            &b" n=old; domain=example.com; path=/p"[..],
            b" other=x; domain=example.com; path=/p",
        ] {
            assert!(add_header(
                &mut jar,
                line,
                Some(b"www.example.com"),
                Some(b"/p"),
                false,
                &clock
            ));
        }
        assert!(add_header(
            &mut jar,
            b" n=new; domain=example.com; path=/p",
            Some(b"www.example.com"),
            Some(b"/p"),
            false,
            &clock
        ));

        assert_eq!(jar.numcookies(), 2);
        let values: Vec<String> = all(&jar)
            .iter()
            .map(|cookie| cookie.value().map(text).unwrap_or_default())
            .collect();
        assert!(values.contains(&"new".to_owned()));
        assert!(values.contains(&"x".to_owned()));
        // The replacement inherits the old CREATION TIME but NOT the old
        // slot: `:906-909` removes the node and `:1015-1016` TAIL-appends the
        // new cookie, so the bucket order becomes `other`, then `n`. That is
        // precisely why the creation time has to be carried over -- the
        // position no longer records it, and `CURLINFO_COOKIELIST` reports
        // bucket order while the jar reports creation order.
        assert_eq!(
            all(&jar).first().and_then(|c| c.value().map(text)),
            Some("x".to_owned())
        );
        assert_eq!(all(&jar).first().map(Cookie::creationtime), Some(2));
        assert_eq!(
            all(&jar).get(1).map(Cookie::creationtime),
            Some(1),
            "the replacement kept the first cookie's creation time"
        );
        // So the jar, which sorts on that time, still lists `other` first.
        let written = text(&saved(&jar));
        assert!(written.find("other") < written.find("\tn\tnew"));
    }

    #[test]
    fn a_bucket_neighbour_with_the_wrong_domain_is_skipped() {
        let clock = clock_at(BEFORE_EXPIRY);

        // Buckets are keyed on the TOP domain (`cookiehash` via
        // `get_top_domain`), so two different hosts under one registrable name
        // share a bucket and `:1285`'s domain test is what separates them.
        assert_eq!(
            cookiehash(Some(b"a.example.com")),
            cookiehash(Some(b"b.example.com"))
        );

        let mut jar = CookieInfo::new();
        assert!(add_header(
            &mut jar,
            b" mine=1; domain=a.example.com; path=/",
            Some(b"a.example.com"),
            Some(b"/"),
            false,
            &clock
        ));
        assert!(add_header(
            &mut jar,
            b" theirs=2; domain=b.example.com; path=/",
            Some(b"b.example.com"),
            Some(b"/"),
            false,
            &clock
        ));
        assert_eq!(jar.numcookies(), 2);

        for (host, wanted) in [
            (&b"a.example.com"[..], "mine"),
            (b"b.example.com", "theirs"),
        ] {
            let sent = jar.getlist(host, b"/", false, &clock, &NoLog);
            let names: Vec<String> =
                sent.iter().map(|cookie| text(cookie.name())).collect();
            assert_eq!(names, vec![wanted.to_owned()], "{}", text(host));
        }
    }

    #[test]
    fn a_cookie_with_no_value_at_all_is_left_out_of_the_header() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `lib/http.c:2551` is `if(co->value)`, and no parser can produce a
        // valueless cookie -- `storecookie` always stores one, empty at worst.
        // The guard is the C's and is reproduced, so it is reached the only way
        // it can be: by placing such a cookie in the store directly, which is
        // what `crate::share` or a future option surface could do.
        let mut jar = CookieInfo::new();
        assert!(add_jar(
            &mut jar,
            b"example.com\tFALSE\t/\tFALSE\t0\thas\tvalue\n",
            &clock
        ));

        let bucket = cookiehash(Some(b"example.com"));
        if let Some(list) = jar.cookielist.get_mut(bucket) {
            list.push_back(Cookie {
                name: b"novalue".to_vec(),
                value: None,
                path: Some(b"/".to_vec()),
                domain: Some(b"example.com".to_vec()),
                creationtime: 2,
                ..Cookie::default()
            });
        }
        jar.numcookies = 2;

        // Both are matched...
        assert_eq!(
            jar.getlist(b"example.com", b"/", false, &clock, &NoLog)
                .len(),
            2
        );
        // ...and only the one with a value is sent.
        assert_eq!(
            jar.cookie_header_line(
                b"example.com",
                b"/",
                false,
                None,
                &clock,
                &NoLog
            )
            .as_deref()
            .map(text),
            Some(text(b"Cookie: has=value\r\n"))
        );

        // The jar writer, by contrast, emits it -- with an empty seventh field,
        // because `get_netscape_format` falls back to `""` (`:1450`).
        assert!(text(&saved(&jar)).contains("\t0\tnovalue\t\n"));
    }

    #[test]
    fn two_cookies_of_one_name_can_share_a_bucket_and_only_one_is_replaced() {
        let clock = clock_at(BEFORE_EXPIRY);

        // Buckets are keyed on the top domain, so one name can appear twice in
        // a bucket with different domains. `replace_existing` then keeps
        // scanning past the candidate it found -- the secure-overlay test still
        // has to see every namesake -- but takes no second candidate.
        let mut jar = CookieInfo::new();
        for host in [&b"a.example.com"[..], b"b.example.com"] {
            let mut line = b" n=first-".to_vec();
            line.extend_from_slice(host);
            line.extend_from_slice(b"; domain=");
            line.extend_from_slice(host);
            line.extend_from_slice(b"; path=/");
            assert!(add_header(
                &mut jar,
                &line,
                Some(host),
                Some(b"/"),
                false,
                &clock
            ));
        }
        assert_eq!(jar.numcookies(), 2);

        // Replacing the FIRST leaves the second untouched.
        assert!(add_header(
            &mut jar,
            b" n=second; domain=a.example.com; path=/",
            Some(b"a.example.com"),
            Some(b"/"),
            false,
            &clock
        ));
        assert_eq!(jar.numcookies(), 2);

        let mut pairs: Vec<(String, String)> = all(&jar)
            .iter()
            .map(|cookie| {
                (
                    cookie.domain().map(text).unwrap_or_default(),
                    cookie.value().map(text).unwrap_or_default(),
                )
            })
            .collect();
        pairs.sort();
        assert_eq!(
            pairs,
            vec![
                ("a.example.com".to_owned(), "second".to_owned()),
                ("b.example.com".to_owned(), "first-b.example.com".to_owned()),
            ]
        );
    }

    /// A sink that accepts `budget` bytes and then fails, so the writer's
    /// error path can be reached without a full filesystem.
    struct ShortSink {
        budget: usize,
        written: Vec<u8>,
    }

    impl Write for ShortSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.budget == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the sink is full",
                ));
            }
            let take = buf.len().min(self.budget);
            self.written.extend_from_slice(&buf[..take]);
            self.budget -= take;
            Ok(take)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_write_failure_partway_through_the_entries_is_propagated() {
        let clock = clock_at(BEFORE_EXPIRY);
        let jar = load_text(JAR_ASCENDING, &clock);

        // The C ignores every `curl_mfprintf` result in `cookie_output` and
        // reports success for a jar it only half wrote; this propagates
        // instead, and the divergence is documented on `emit`. A sink that
        // takes the header and the first entry and then refuses reaches the
        // entry loop's error arm rather than the header's.
        let header_and_one = FILE_HEADER.len() + 40;
        let mut sink = ShortSink {
            budget: header_and_one,
            written: Vec::new(),
        };
        assert_eq!(jar.write_to(&mut sink), Err(CURLcode::WriteError));
        assert!(sink.written.starts_with(FILE_HEADER));
        assert_eq!(sink.written.len(), header_and_one);

        // And a sink that refuses the header itself fails at the first call.
        let mut sink = ShortSink {
            budget: 0,
            written: Vec::new(),
        };
        assert_eq!(jar.write_to(&mut sink), Err(CURLcode::WriteError));
        assert!(sink.written.is_empty());

        // A sink with room for everything agrees with the in-memory writer.
        let mut sink = ShortSink {
            budget: usize::MAX,
            written: Vec::new(),
        };
        assert_eq!(jar.write_to(&mut sink), Ok(()));
        assert_eq!(text(&sink.written), text(JAR_DESCENDING));

        // And the line TERMINATOR is a write of its own -- `:1524` is one
        // `curl_mfprintf("%s\n", line)` in the C, split here so that the entry
        // and its newline are separate `emit` calls -- so a sink with room for
        // exactly the header and the first entry fails on the newline.
        let body: &[u8] =
            JAR_DESCENDING.get(FILE_HEADER.len()..).unwrap_or_default();
        let first_len =
            body.iter().position(|&byte| byte == b'\n').unwrap_or(0);
        assert!(first_len > 0);
        let mut sink = ShortSink {
            budget: FILE_HEADER.len() + first_len,
            written: Vec::new(),
        };
        assert_eq!(jar.write_to(&mut sink), Err(CURLcode::WriteError));
        assert_eq!(sink.written.len(), FILE_HEADER.len() + first_len);
        assert!(!sink.written.ends_with(b"\n"));
    }

    #[test]
    fn a_jar_line_past_the_ceiling_stops_the_read() {
        let clock = clock_at(BEFORE_EXPIRY);

        // `:1116` sizes the line buffer at `MAX_COOKIE_LINE`, and a dynbuf
        // whose ceiling is `n` accepts at most `n - 1` bytes -- the C counts
        // the terminating zero in its `fit` (`lib/curlx/dynbuf.c:72`). So
        // `Curl_get_line` refuses a longer line and `:1137`'s `while(!result &&
        // !eof)` ends the read.
        //
        // This is the ONLY way a load reports an error at all: a malformed line
        // never does, which the C says outright at `:1133-1134` -- *"File
        // reading cookie failures are not propagated back to the caller because
        // there is no way to do that"*. Note the contrast with the HEADER
        // parser, where an over-long line is discarded in silence and the
        // caller is told nothing.
        // `total` counts the NEWLINE, because `Curl_get_line` keeps it in the
        // buffer -- it is how the function knows the line is complete
        // (`lib/curl_get_line.c:54-58`) -- so it is charged against the
        // ceiling like any other byte.
        let prefix: &[u8] = b"example.com\tFALSE\t/\tFALSE\t0\tn\t";
        let jar_line = |total: usize| -> Vec<u8> {
            let mut line = prefix.to_vec();
            line.extend_from_slice(&vec![b'v'; total - 1 - prefix.len()]);
            line.push(b'\n');
            debug_assert_eq!(line.len(), total);
            line
        };

        // One byte past the ceiling: refused, and with the dynbuf's own code
        // rather than a remapped one.
        let mut jar = CookieInfo::new();
        let over = jar_line(MAX_COOKIE_LINE);
        let mut input = over.as_slice();
        assert_eq!(
            jar.read_from(&mut input, &clock, &NoLog, None),
            Err(CURLcode::TooLarge)
        );
        assert_eq!(jar.numcookies(), 0);

        // Exactly at the ceiling: accepted, so the boundary is the buffer's
        // `n - 1` and nothing smaller.
        let mut jar = CookieInfo::new();
        let fits = jar_line(MAX_COOKIE_LINE - 1);
        let mut input = fits.as_slice();
        assert_eq!(jar.read_from(&mut input, &clock, &NoLog, None), Ok(()));
        assert_eq!(jar.numcookies(), 1);
        assert_eq!(
            only(&jar).value().map(<[u8]>::len),
            Some(MAX_COOKIE_LINE - 2 - prefix.len())
        );

        // An over-long line stops the read where it stands, so a good line
        // AFTER it is never seen -- the C's loop condition, not a skip.
        let mut both = jar_line(MAX_COOKIE_LINE);
        both.extend_from_slice(
            b"later.example\tFALSE\t/\tFALSE\t0\tlater\tv\n",
        );
        let mut jar = CookieInfo::new();
        let mut input = both.as_slice();
        assert!(jar.read_from(&mut input, &clock, &NoLog, None).is_err());
        assert_eq!(jar.numcookies(), 0);
    }
}
