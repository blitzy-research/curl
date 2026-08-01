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

//! Result codes: the type foundation of `curl-rs-lib`.
//!
//! This module supersedes `lib/strerror.c` (676 lines) and declares the five
//! public result enumerations that every other module in this crate returns.
//! Each one is transcribed from the C header that owns it, measured rather
//! than remembered:
//!
//! | Enumeration    | C declaration                   | Tokens | Sentinel            |
//! |----------------|---------------------------------|--------|---------------------|
//! | [`CURLcode`]   | `include/curl/curl.h:518-648`   | 103    | `CURL_LAST` = 102   |
//! | [`CURLMcode`]  | `include/curl/multi.h:59-78`    | 15     | `CURLM_LAST` = 13   |
//! | [`CURLUcode`]  | `include/curl/urlapi.h:34-68`   | 33     | `CURLUE_LAST` = 32  |
//! | [`CURLHcode`]  | `include/curl/header.h:47-56`   | 8      | none, by design     |
//! | [`CURLSHcode`] | `include/curl/curl.h:3058-3066` | 7      | `CURLSHE_LAST` = 6  |
//!
//! # Integers are the contract, not names
//!
//! A C program compiled against curl 8.19.0-DEV embeds the *numeric* value of
//! every enumerator it uses directly in its instruction stream. Reproducing
//! the names without the numbers yields a library that links and then
//! misbehaves: a caller comparing against `CURLE_SSL_CONNECT_ERROR` would
//! match some entirely different condition, with no diagnostic anywhere.
//!
//! Three consequences follow, and they are absolute:
//!
//! 1. **Every discriminant is written out.** Not one value is left to Rust's
//!    implicit "previous + 1". The `codes:` table of each declaration below
//!    carries a literal integer on every row, exactly as the row's third
//!    column carries the literal message.
//! 2. **Every result enumeration is `#[repr(i32)]`.** The C enumerations are
//!    passed and returned as `int` throughout the public API. `CURLMcode`
//!    additionally *requires* a signed representation because its first
//!    enumerator, `CURLM_CALL_MULTI_PERFORM`, is `-1`. ([`CodeKind`], which has
//!    no C counterpart, is deliberately the exception; see its documentation.)
//! 3. **Retired placeholders are kept.** `CURLcode` carries 15
//!    `CURLE_OBSOLETE*` enumerators at exactly
//!    `{20, 24, 29, 32, 34, 40, 41, 44, 46, 50, 51, 57, 62, 75, 76}`. They
//!    hold nothing but their positions, and dropping a single one would
//!    silently shift every later code by one. They are reproduced in full.
//!
//! ## On the declaration macro
//!
//! The five enumerations are declared through the private `result_code!`
//! macro. The macro **never infers an integer**: it receives each
//! discriminant as a literal and emits it verbatim as the enumerator's
//! discriminant, as the pattern in `from_i32`, and as the text of the
//! generated documentation. What it removes is only the conversion
//! boilerplate that would otherwise be written five times, once per family,
//! with five chances to make a copy-and-paste mistake.
//!
//! The upside is a single auditable table per family, one row per code,
//! carrying the Rust name, the pinned integer, the C token and the exact
//! message together. Reordering rows cannot renumber anything, because the
//! values are literals; the unit tests at the foot of this file assert both
//! the individual anchors and the contiguity of each family, so a dropped or
//! duplicated row fails the build rather than shipping.
//!
//! `rustfmt` does not reformat macro bodies, so the tables' alignment is
//! stable under `cargo fmt --check`.
//!
//! # Message text is part of the contract
//!
//! `curl-rs-ffi` exports `curl_easy_strerror`, `curl_multi_strerror`,
//! `curl_share_strerror` and `curl_url_strerror` as thin adapters, so the
//! strings live here, behind [`CURLcode::message`] and its counterparts.
//! Every one is transcribed verbatim from `lib/strerror.c`. None may be
//! "improved": no trailing stop is added, no letter case is normalized,
//! no wording is clarified.
//!
//! ## Three fallbacks, not one
//!
//! The four C functions do **not** share an unknown-value string. Measured at
//! the four `return` statements that terminate them:
//!
//! | Function              | Site                | Fallback              |
//! |-----------------------|---------------------|-----------------------|
//! | `curl_easy_strerror`  | `strerror.c:317`    | `"Unknown error"`     |
//! | `curl_multi_strerror` | `strerror.c:376`    | `"Unknown error"`     |
//! | `curl_share_strerror` | `strerror.c:411`    | `"CURLSHcode unknown"` |
//! | `curl_url_strerror`   | `strerror.c:524`    | `"CURLUcode unknown"` |
//!
//! Each family's value is exposed as its `UNKNOWN_MESSAGE` associated
//! constant and is returned by its `message_for` associated function for any
//! integer outside the enumeration. The distinction is deliberate and is
//! asserted by test.
//!
//! Note also that the C `switch` statements do not name every enumerator. The
//! 15 `CURLE_OBSOLETE*` codes and `CURL_LAST` reach `default: break;`, and
//! `CURLM_LAST`, `CURLSHE_LAST` and `CURLUE_LAST` are `break` arms; all of
//! them therefore fall through to their family's fallback. The tables below
//! record that resolved behaviour on the row itself, so `message()` reproduces
//! the C functions exactly for every value they can be handed.
//!
//! ## `CURLHcode` has no C `strerror`
//!
//! There is no `curl_header_strerror` anywhere in the C tree, and no string
//! table for `CURLHE_*` under `lib/`, `src/` or `include/`. The eight
//! [`CURLHcode`] messages are consequently *not* frozen ABI text: they are
//! derived from the header's own inline comments at
//! `include/curl/header.h:48-55` and written in `curl_easy_strerror`'s house
//! style. No C consumer can observe them, and no oracle exists to diff them
//! against. Anyone tempted to "correct" them against `lib/strerror.c` should
//! stop here: the counterpart does not exist.
//!
//! ## This build is always verbose
//!
//! In C every arm of every one of those four functions sits inside
//! `#ifdef CURLVERBOSE`. The `#else` branch collapses the whole table to
//! `if(!error) return "No error"; else return "Error";`, which is what a
//! `--disable-verbose` build ships.
//!
//! The Rust workspace declares no verbosity feature -- the capability
//! vocabulary is `http2`, `http3`, `ftp`, `ssh`, `websockets`, `cookies`,
//! `hsts`, `altsvc`, `doh`, `brotli`, `zstd`, `gzip`, `negotiate`,
//! `hickory-dns` and `memdebug` -- so there is nothing to gate on and the full
//! string tables are unconditionally present. The absence of a terse branch is
//! a decision, not an oversight.
//!
//! # What this module deliberately does not contain
//!
//! - **`CURLoption` and `CURLINFO`.** Both are composed arithmetically from a
//!   type base rather than ordinally (`CURLOPT(na, t, nu) = t + nu`), and their
//!   sole source of truth is one module in the ABI crate --
//!   `curl-rs-ffi/src/ffi/opts.rs` -- which emits both the identifiers and the
//!   `curl_easyoption` metadata array that backs `curl_easy_option_by_name`.
//!   Restating even one identifier here would create the second table that
//!   guarantees eventual drift. This module owns the *result* codes and nothing
//!   else.
//! - **The legacy `#define` aliases.** `include/curl/curl.h:650-736` defines
//!   40 backward-compatibility macros inside its `CURL_NO_OLDIES` block, among
//!   them `CURLE_FUNCTION_NOT_FOUND` for `CURLE_OBSOLETE41` and
//!   `CURLE_SSL_CACERT` for `CURLE_PEER_FAILED_VERIFICATION`. Those are
//!   preprocessor macros over the enumerators reproduced here, not
//!   enumerators in their own right, and they belong to the generated public
//!   header -- and so does the one alias that is not a `CURLcode` macro,
//!   `CURLM_CALL_MULTI_SOCKET`. `include/curl/multi.h:83` defines it as
//!   `#define CURLM_CALL_MULTI_SOCKET CURLM_CALL_MULTI_PERFORM` so that
//!   socket-driven C reads naturally, and `curl-rs-ffi/build.rs` splices that
//!   line into the generated `multi.h` verbatim, because cbindgen cannot express
//!   a `#define` whose value is another identifier. That splice is the ONE
//!   authoritative representation.
//!
//!   It is deliberately NOT mirrored here as
//!   `pub const CURLM_CALL_MULTI_SOCKET: CURLMcode`. The reasoning that "a
//!   Rust caller cannot name a C macro, so the alias is provided as a real
//!   item" does not hold: no Rust caller names it and none is planned --
//!   `curl-rs-ffi` reads the alias from the spliced header and `curl-rs` never
//!   touches the multi C API -- so it would be a second definition of one ABI
//!   value, maintained for a hypothetical consumer, in a module whose stated
//!   rule two paragraphs above is that "restating even one identifier here
//!   would create the second table that guarantees eventual drift". A Rust
//!   caller that ever does need it should name
//!   [`CURLMcode::CallMultiPerform`], which is the value the macro expands to.
//! - **Internal `Curl_*` re-exports.** Nothing here is widened beyond what a
//!   dependent genuinely consumes.
//!
//! # Safety
//!
//! This module contains no `unsafe` code and does not relax the `unsafe_code`
//! lint. The crate root denies that lint, and its single exemption is the
//! `mod ffi` declaration in `curl-rs-lib/src/lib.rs`.
//!
//! The root must use `deny`, not `forbid`. `forbid` is `deny` plus a
//! prohibition on relaxing the level later, so a `forbid` root followed by a
//! relaxation on `mod ffi` fails to compile with `error[E0453]` ("incompatible
//! with previous forbid"), and the `unsafe` blocks inside `ffi` are rejected as
//! well. Verified by compiling both constructions on the pinned toolchain:
//! `forbid` plus a relaxation errors, `deny` plus a relaxation builds clean.

use std::borrow::Cow;
use std::ffi::CStr;

/// Which result family an integer was being interpreted as.
///
/// Carried by [`UnknownCode`] so that a conversion failure reports the family
/// it failed against. The five variants correspond one-to-one to the five
/// enumerations in this module, and [`Display`](core::fmt::Display) renders
/// the C type name so a diagnostic reads the way a C programmer expects.
///
/// This is the one enumeration in this module with **no ABI significance**: it
/// has no C counterpart, appears in no public header, and crosses no boundary.
/// Its discriminants are therefore left implicit on purpose, because pinning
/// them would imply a contract that does not exist. The `#[repr(u8)]` is present
/// only so that the type has a stated layout rather than an inferred one; it is
/// deliberately *not* `i32`, so that no reader mistakes it for one of the five
/// result families.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum CodeKind {
    /// [`CURLcode`], the easy-interface result family.
    Easy,
    /// [`CURLMcode`], the multi-interface result family.
    Multi,
    /// [`CURLUcode`], the URL API result family.
    Url,
    /// [`CURLHcode`], the header API result family.
    Header,
    /// [`CURLSHcode`], the share-interface result family.
    Share,
}

impl CodeKind {
    /// The C type name of this family, spelled exactly as the public headers
    /// spell it.
    #[must_use]
    pub const fn c_name(self) -> &'static str {
        match self {
            Self::Easy => "CURLcode",
            Self::Multi => "CURLMcode",
            Self::Url => "CURLUcode",
            Self::Header => "CURLHcode",
            Self::Share => "CURLSHcode",
        }
    }
}

impl core::fmt::Display for CodeKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.c_name())
    }
}

/// An integer that does not name any member of a result family.
///
/// Produced by the `TryFrom<i32>` implementation of each enumeration, which is
/// how the FFI boundary validates an integer arriving from C before it becomes
/// a Rust value. Callers that would rather tolerate an unknown integer than
/// reject it should use `from_i32` (which yields [`None`]) or `message_for`
/// (which yields the family's fallback string).
///
/// `thiserror` derives the [`Display`](core::fmt::Display) and
/// [`Error`](std::error::Error) implementations here. That is the intended use
/// of the crate in this module: *behind* the pinned representation, on a
/// helper type that crosses no ABI boundary, never on the enumerations
/// themselves.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, thiserror::Error)]
#[error("{value} is not a valid {kind} value")]
pub struct UnknownCode {
    /// The family the integer was checked against.
    pub kind: CodeKind,
    /// The offending integer, preserved exactly as it was received.
    pub value: i32,
}

impl UnknownCode {
    /// Records `value` as not belonging to `kind`.
    #[must_use]
    pub const fn new(kind: CodeKind, value: i32) -> Self {
        Self { kind, value }
    }
}

/// Declares one curl result enumeration together with its conversion surface.
///
/// This macro is the mechanism behind design pattern P7, "newtype with pinned
/// representation": it is what makes the integer-exactness requirement
/// impossible to violate by accident.
///
/// # What it does and does not do
///
/// Each `codes:` row is `Variant = <literal>, "<C token>", "<message>";`. The
/// literal is emitted verbatim in three places -- the enumerator's
/// discriminant, the match pattern in `from_i32`, and the generated
/// documentation -- so a discriminant is never computed, inferred, or derived
/// from position. Optional outer attributes may precede a row and are applied
/// to that enumerator; the generated documentation is appended after them.
///
/// # Generated surface
///
/// Given a family `F` with success enumerator `S`:
///
/// - `F::KIND`, `F::UNKNOWN_MESSAGE`, `F::VARIANTS`
/// - `F::as_i32`, `F::is_ok`, `F::message`, `F::c_name`, `F::into_result`
/// - `F::from_i32` and `F::message_for` as associated functions over a raw
///   `i32`, for the FFI boundary
/// - `Display` (rendering `message()`), [`std::error::Error`],
///   `From<F> for i32`, and `TryFrom<i32> for F` with [`UnknownCode`]
macro_rules! result_code {
    (
        $(#[$enum_meta:meta])*
        $name:ident {
            kind: $kind:expr,
            success: $success:ident,
            unknown: $unknown:literal,
            codes: [
                $(
                    $(#[$code_meta:meta])*
                    $variant:ident = $value:literal, $c_name:literal,
                        $message:literal;
                )+
            ]
        }
    ) => {
        $(#[$enum_meta])*
        #[repr(i32)]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub enum $name {
            $(
                $(#[$code_meta])*
                #[doc = concat!("`", $c_name, "` = `", stringify!($value), "`.")]
                ///
                // `concat!` splices the literal's VALUE, not its source text, so
                // a message the C original spelled as two adjoining literals is
                // documented already joined -- exactly as `message()` returns it.
                #[doc = concat!("Message: `\"", $message, "\"`.")]
                $variant = $value,
            )+
        }

        impl $name {
            /// The family this enumeration belongs to.
            pub const KIND: CodeKind = $kind;

            /// The string the corresponding C function returns for a value
            /// outside this enumeration.
            ///
            /// The four C functions do not agree on this, which is why it is a
            /// per-family constant rather than a shared one.
            pub const UNKNOWN_MESSAGE: &'static str = $unknown;

            /// [`Self::UNKNOWN_MESSAGE`] as a NUL-terminated C string.
            ///
            /// The SAME literal, viewed twice: `concat!` appends the
            /// terminator at compile time, so there is no second copy of the
            /// text to keep in step and no allocation at run time. This is
            /// what lets the C ABI shim hand a `const char *` straight out of
            /// this table.
            pub const UNKNOWN_MESSAGE_C: &'static CStr =
                match CStr::from_bytes_with_nul(concat!($unknown, "\0").as_bytes()) {
                    Ok(text) => text,
                    Err(_) => panic!("an unknown-code message may not contain a NUL"),
                };

            /// Every member of this enumeration, in declaration order, which
            /// for these families is also ascending numeric order.
            ///
            /// Exhaustive by construction: the same macro expansion produces
            /// this slice and the enumeration itself, so the two cannot
            /// disagree.
            pub const VARIANTS: &'static [Self] = &[$(Self::$variant,)+];

            /// The pinned integer for this code, as a C consumer sees it.
            #[must_use]
            pub const fn as_i32(self) -> i32 {
                self as i32
            }

            /// Whether this is the family's success code.
            ///
            /// True only for the success enumerator itself, mirroring the C
            /// idiom `if(result != <FAMILY>_OK)`.
            #[must_use]
            pub const fn is_ok(self) -> bool {
                matches!(self, Self::$success)
            }

            /// Interprets a raw integer, yielding [`None`] if it names no
            /// member of this enumeration.
            ///
            /// This is the inbound half of the FFI boundary's validation; the
            /// outbound half is `From<Self> for i32`.
            #[must_use]
            pub const fn from_i32(raw: i32) -> Option<Self> {
                match raw {
                    $($value => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// The exact message the corresponding C function returns for this
            /// code.
            #[must_use]
            pub const fn message(self) -> &'static str {
                match self {
                    $(Self::$variant => $message,)+
                }
            }

            /// The exact message the corresponding C function returns for a
            /// raw integer, including one outside this enumeration.
            ///
            /// Reproduces the C function in full: known values resolve through
            /// [`Self::message`], everything else through
            /// [`Self::UNKNOWN_MESSAGE`]. The ABI shim needs no fallback logic
            /// of its own, which is what keeps the fallback in one place.
            #[must_use]
            pub const fn message_for(raw: i32) -> &'static str {
                match Self::from_i32(raw) {
                    Some(code) => code.message(),
                    None => Self::UNKNOWN_MESSAGE,
                }
            }

            /// [`Self::message`] as a NUL-terminated C string.
            ///
            /// The four exported `curl_*_strerror` functions return
            /// `const char *`, and a Rust `&str` is not NUL-terminated, so
            /// something has to supply the terminator. It is supplied HERE, by
            /// `concat!` at compile time against the same `$message` literal
            /// that [`Self::message`] returns, for two reasons:
            ///
            /// * A second table of NUL-terminated copies in the ABI shim would
            ///   be a mirrored source of truth, and mirrored tables drift.
            /// * Interning at run time would need an allocation and a cache
            ///   behind a lock, for text that is already static.
            ///
            /// The result is a `&'static CStr` computed entirely at compile
            /// time, so the shim's whole job is `.as_ptr()`.
            #[must_use]
            pub const fn message_c(self) -> &'static CStr {
                match self {
                    $(
                        Self::$variant => match CStr::from_bytes_with_nul(
                            concat!($message, "\0").as_bytes(),
                        ) {
                            Ok(text) => text,
                            Err(_) => panic!("a code message may not contain a NUL"),
                        },
                    )+
                }
            }

            /// [`Self::message_for`] as a NUL-terminated C string.
            ///
            /// The exact function the corresponding `curl_*_strerror` becomes:
            /// known values resolve through [`Self::message_c`], everything
            /// else -- values outside the enumeration, the retired
            /// placeholders, and the family's `*_LAST` bound -- through
            /// [`Self::UNKNOWN_MESSAGE_C`].
            #[must_use]
            pub const fn message_for_c(raw: i32) -> &'static CStr {
                match Self::from_i32(raw) {
                    Some(code) => code.message_c(),
                    None => Self::UNKNOWN_MESSAGE_C,
                }
            }

            /// The C identifier for this code, spelled exactly as the public
            /// header spells it.
            ///
            /// Present so that diagnostics and the cross-crate ABI parity
            /// tests can name a code the way the header does, without a second
            /// table to keep in step.
            #[must_use]
            pub const fn c_name(self) -> &'static str {
                match self {
                    $(Self::$variant => $c_name,)+
                }
            }

            /// Converts a code into a [`Result`], discarding the success
            /// value.
            ///
            /// `Ok(())` for the success code, `Err(self)` for every other,
            /// which lets a C-shaped return participate in `?`.
            pub const fn into_result(self) -> Result<(), Self> {
                if self.is_ok() {
                    Ok(())
                } else {
                    Err(self)
                }
            }
        }

        impl core::fmt::Display for $name {
            /// Renders [`Self::message`], so `to_string()` and
            /// `curl_*_strerror` agree byte for byte.
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.message())
            }
        }

        impl std::error::Error for $name {}

        impl From<$name> for i32 {
            /// The outbound half of the FFI boundary: a code becomes its
            /// pinned integer.
            fn from(code: $name) -> Self {
                code as Self
            }
        }

        impl core::convert::TryFrom<i32> for $name {
            type Error = UnknownCode;

            /// The inbound half of the FFI boundary: an integer from C is
            /// admitted only if it names a member of this enumeration.
            fn try_from(raw: i32) -> Result<Self, UnknownCode> {
                match Self::from_i32(raw) {
                    Some(code) => Ok(code),
                    None => Err(UnknownCode::new($kind, raw)),
                }
            }
        }
    };
}

result_code! {
    /// Every error a libcurl function can report: `CURLcode`.
    ///
    /// Transcribed from `include/curl/curl.h:518-648`, whose leading comment is
    /// the whole specification of this type:
    ///
    /// > Always add new return codes last. Never *EVER* remove any. The return
    /// > codes must remain the same!
    ///
    /// 103 enumerators occupy `0..=102` with no gaps. In C only `CURLE_OK = 0`
    /// is written explicitly and the remaining 102 take their value from
    /// declaration order; here every one is a literal.
    ///
    /// Fifteen of them are retired `CURLE_OBSOLETE*` placeholders at exactly
    /// `{20, 24, 29, 32, 34, 40, 41, 44, 46, 50, 51, 57, 62, 75, 76}`. They are
    /// reproduced because removing one would shift every later code by one, and
    /// because `include/curl/curl.h:650-736` still defines compatibility macros
    /// over several of them. They are never returned.
    ///
    /// `CURL_LAST` = 102 is a bound for range checks, not a value; the highest
    /// real error is `CURLE_ECH_REQUIRED` = 101.
    ///
    /// Messages come from `curl_easy_strerror` (`lib/strerror.c:34-324`). The
    /// 87 codes it names carry their own string; the 15 placeholders and
    /// `CURL_LAST` reach its `default:` arm and so resolve to
    /// [`Self::UNKNOWN_MESSAGE`], `"Unknown error"` (`lib/strerror.c:317`).
    CURLcode {
        kind: CodeKind::Easy,
        success: Ok,
        unknown: "Unknown error",
        codes: [
            Ok = 0, "CURLE_OK",
                "No error";
            UnsupportedProtocol = 1, "CURLE_UNSUPPORTED_PROTOCOL",
                "Unsupported protocol";
            FailedInit = 2, "CURLE_FAILED_INIT",
                "Failed initialization";
            UrlMalformat = 3, "CURLE_URL_MALFORMAT",
                "URL using bad/illegal format or missing URL";
            NotBuiltIn = 4, "CURLE_NOT_BUILT_IN",
                "A requested feature, protocol or option was not found built-in in \
                             this libcurl due to a build-time decision.";
            CouldntResolveProxy = 5, "CURLE_COULDNT_RESOLVE_PROXY",
                "Could not resolve proxy name";
            CouldntResolveHost = 6, "CURLE_COULDNT_RESOLVE_HOST",
                "Could not resolve hostname";
            CouldntConnect = 7, "CURLE_COULDNT_CONNECT",
                "Could not connect to server";
            WeirdServerReply = 8, "CURLE_WEIRD_SERVER_REPLY",
                "Weird server reply";
            RemoteAccessDenied = 9, "CURLE_REMOTE_ACCESS_DENIED",
                "Access denied to remote resource";
            FtpAcceptFailed = 10, "CURLE_FTP_ACCEPT_FAILED",
                "FTP: The server failed to connect to data port";
            FtpWeirdPassReply = 11, "CURLE_FTP_WEIRD_PASS_REPLY",
                "FTP: unknown PASS reply";
            FtpAcceptTimeout = 12, "CURLE_FTP_ACCEPT_TIMEOUT",
                "FTP: Accepting server connect has timed out";
            FtpWeirdPasvReply = 13, "CURLE_FTP_WEIRD_PASV_REPLY",
                "FTP: unknown PASV reply";
            FtpWeird227Format = 14, "CURLE_FTP_WEIRD_227_FORMAT",
                "FTP: unknown 227 response format";
            FtpCantGetHost = 15, "CURLE_FTP_CANT_GET_HOST",
                "FTP: cannot figure out the host in the PASV response";
            Http2 = 16, "CURLE_HTTP2",
                "Error in the HTTP2 framing layer";
            FtpCouldntSetType = 17, "CURLE_FTP_COULDNT_SET_TYPE",
                "FTP: could not set file type";
            PartialFile = 18, "CURLE_PARTIAL_FILE",
                "Transferred a partial file";
            FtpCouldntRetrFile = 19, "CURLE_FTP_COULDNT_RETR_FILE",
                "FTP: could not retrieve (RETR failed) the specified file";
            /// **Retired placeholder.** Held solely to keep position 20 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED". Never returned.
            Obsolete20 = 20, "CURLE_OBSOLETE20",
                "Unknown error";
            QuoteError = 21, "CURLE_QUOTE_ERROR",
                "Quote command returned error";
            HttpReturnedError = 22, "CURLE_HTTP_RETURNED_ERROR",
                "HTTP response code said error";
            WriteError = 23, "CURLE_WRITE_ERROR",
                "Failed writing received data to disk/application";
            /// **Retired placeholder.** Held solely to keep position 24 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED". Never returned.
            Obsolete24 = 24, "CURLE_OBSOLETE24",
                "Unknown error";
            UploadFailed = 25, "CURLE_UPLOAD_FAILED",
                "Upload failed (at start/before it took off)";
            ReadError = 26, "CURLE_READ_ERROR",
                "Failed to open/read local data from file/application";
            OutOfMemory = 27, "CURLE_OUT_OF_MEMORY",
                "Out of memory";
            OperationTimedout = 28, "CURLE_OPERATION_TIMEDOUT",
                "Timeout was reached";
            /// **Retired placeholder.** Held solely to keep position 29 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED". Never returned.
            Obsolete29 = 29, "CURLE_OBSOLETE29",
                "Unknown error";
            FtpPortFailed = 30, "CURLE_FTP_PORT_FAILED",
                "FTP: command PORT failed";
            FtpCouldntUseRest = 31, "CURLE_FTP_COULDNT_USE_REST",
                "FTP: command REST failed";
            /// **Retired placeholder.** Held solely to keep position 32 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED". Never returned.
            Obsolete32 = 32, "CURLE_OBSOLETE32",
                "Unknown error";
            RangeError = 33, "CURLE_RANGE_ERROR",
                "Requested range was not delivered by the server";
            /// **Retired placeholder.** Held solely to keep position 34 occupied so that every
            /// later code retains its value. The C header annotates it "the alias
            /// CURLE_HTTP_POST_ERROR, removed in 7.56.0". Never returned.
            Obsolete34 = 34, "CURLE_OBSOLETE34",
                "Unknown error";
            SslConnectError = 35, "CURLE_SSL_CONNECT_ERROR",
                "SSL connect error";
            BadDownloadResume = 36, "CURLE_BAD_DOWNLOAD_RESUME",
                "Could not resume download";
            FileCouldntReadFile = 37, "CURLE_FILE_COULDNT_READ_FILE",
                "Could not read a file:// file";
            LdapCannotBind = 38, "CURLE_LDAP_CANNOT_BIND",
                "LDAP: cannot bind";
            LdapSearchFailed = 39, "CURLE_LDAP_SEARCH_FAILED",
                "LDAP: search failed";
            /// **Retired placeholder.** Held solely to keep position 40 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED". Never returned.
            Obsolete40 = 40, "CURLE_OBSOLETE40",
                "Unknown error";
            /// **Retired placeholder.** Held solely to keep position 41 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED starting with
            /// 7.53.0". Never returned.
            Obsolete41 = 41, "CURLE_OBSOLETE41",
                "Unknown error";
            AbortedByCallback = 42, "CURLE_ABORTED_BY_CALLBACK",
                "Operation was aborted by an application callback";
            BadFunctionArgument = 43, "CURLE_BAD_FUNCTION_ARGUMENT",
                "A libcurl function was given a bad argument";
            /// **Retired placeholder.** Held solely to keep position 44 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED". Never returned.
            Obsolete44 = 44, "CURLE_OBSOLETE44",
                "Unknown error";
            InterfaceFailed = 45, "CURLE_INTERFACE_FAILED",
                "Failed binding local connection end";
            /// **Retired placeholder.** Held solely to keep position 46 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED". Never returned.
            Obsolete46 = 46, "CURLE_OBSOLETE46",
                "Unknown error";
            TooManyRedirects = 47, "CURLE_TOO_MANY_REDIRECTS",
                "Number of redirects hit maximum amount";
            UnknownOption = 48, "CURLE_UNKNOWN_OPTION",
                "An unknown option was passed in to libcurl";
            SetoptOptionSyntax = 49, "CURLE_SETOPT_OPTION_SYNTAX",
                "Malformed option provided in a setopt";
            /// **Retired placeholder.** Held solely to keep position 50 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED". Never returned.
            Obsolete50 = 50, "CURLE_OBSOLETE50",
                "Unknown error";
            /// **Retired placeholder.** Held solely to keep position 51 occupied so that every
            /// later code retains its value. The C header annotates it "NOT USED". Never returned.
            Obsolete51 = 51, "CURLE_OBSOLETE51",
                "Unknown error";
            GotNothing = 52, "CURLE_GOT_NOTHING",
                "Server returned nothing (no headers, no data)";
            SslEngineNotfound = 53, "CURLE_SSL_ENGINE_NOTFOUND",
                "SSL crypto engine not found";
            SslEngineSetfailed = 54, "CURLE_SSL_ENGINE_SETFAILED",
                "Can not set SSL crypto engine as default";
            SendError = 55, "CURLE_SEND_ERROR",
                "Failed sending data to the peer";
            RecvError = 56, "CURLE_RECV_ERROR",
                "Failure when receiving data from the peer";
            /// **Retired placeholder.** Held solely to keep position 57 occupied so that every
            /// later code retains its value. The C header annotates it "NOT IN USE". Never
            /// returned.
            Obsolete57 = 57, "CURLE_OBSOLETE57",
                "Unknown error";
            SslCertproblem = 58, "CURLE_SSL_CERTPROBLEM",
                "Problem with the local SSL certificate";
            SslCipher = 59, "CURLE_SSL_CIPHER",
                "Could not use specified SSL cipher";
            PeerFailedVerification = 60, "CURLE_PEER_FAILED_VERIFICATION",
                "SSL peer certificate or SSH remote key was not OK";
            BadContentEncoding = 61, "CURLE_BAD_CONTENT_ENCODING",
                "Unrecognized or bad HTTP Content or Transfer-Encoding";
            /// **Retired placeholder.** Held solely to keep position 62 occupied so that every
            /// later code retains its value. The C header annotates it "NOT IN USE since 7.82.0".
            /// Never returned.
            Obsolete62 = 62, "CURLE_OBSOLETE62",
                "Unknown error";
            FilesizeExceeded = 63, "CURLE_FILESIZE_EXCEEDED",
                "Maximum file size exceeded";
            UseSslFailed = 64, "CURLE_USE_SSL_FAILED",
                "Requested SSL level failed";
            SendFailRewind = 65, "CURLE_SEND_FAIL_REWIND",
                "Send failed since rewinding of the data stream failed";
            SslEngineInitfailed = 66, "CURLE_SSL_ENGINE_INITFAILED",
                "Failed to initialise SSL crypto engine";
            LoginDenied = 67, "CURLE_LOGIN_DENIED",
                "Login denied";
            TftpNotfound = 68, "CURLE_TFTP_NOTFOUND",
                "TFTP: File Not Found";
            TftpPerm = 69, "CURLE_TFTP_PERM",
                "TFTP: Access Violation";
            RemoteDiskFull = 70, "CURLE_REMOTE_DISK_FULL",
                "Disk full or allocation exceeded";
            TftpIllegal = 71, "CURLE_TFTP_ILLEGAL",
                "TFTP: Illegal operation";
            TftpUnknownid = 72, "CURLE_TFTP_UNKNOWNID",
                "TFTP: Unknown transfer ID";
            RemoteFileExists = 73, "CURLE_REMOTE_FILE_EXISTS",
                "Remote file already exists";
            TftpNosuchuser = 74, "CURLE_TFTP_NOSUCHUSER",
                "TFTP: No such user";
            /// **Retired placeholder.** Held solely to keep position 75 occupied so that every
            /// later code retains its value. The C header annotates it "NOT IN USE since 7.82.0".
            /// Never returned.
            Obsolete75 = 75, "CURLE_OBSOLETE75",
                "Unknown error";
            /// **Retired placeholder.** Held solely to keep position 76 occupied so that every
            /// later code retains its value. The C header annotates it "NOT IN USE since 7.82.0".
            /// Never returned.
            Obsolete76 = 76, "CURLE_OBSOLETE76",
                "Unknown error";
            SslCacertBadfile = 77, "CURLE_SSL_CACERT_BADFILE",
                "Problem with the SSL CA cert (path? access rights?)";
            RemoteFileNotFound = 78, "CURLE_REMOTE_FILE_NOT_FOUND",
                "Remote file not found";
            Ssh = 79, "CURLE_SSH",
                "Error in the SSH layer";
            SslShutdownFailed = 80, "CURLE_SSL_SHUTDOWN_FAILED",
                "Failed to shut down the SSL connection";
            Again = 81, "CURLE_AGAIN",
                "Socket not ready for send/recv";
            SslCrlBadfile = 82, "CURLE_SSL_CRL_BADFILE",
                "Failed to load CRL file (path? access rights?, format?)";
            SslIssuerError = 83, "CURLE_SSL_ISSUER_ERROR",
                "Issuer check against peer certificate failed";
            FtpPretFailed = 84, "CURLE_FTP_PRET_FAILED",
                "FTP: The server did not accept the PRET command.";
            RtspCseqError = 85, "CURLE_RTSP_CSEQ_ERROR",
                "RTSP CSeq mismatch or invalid CSeq";
            RtspSessionError = 86, "CURLE_RTSP_SESSION_ERROR",
                "RTSP session error";
            FtpBadFileList = 87, "CURLE_FTP_BAD_FILE_LIST",
                "Unable to parse FTP file list";
            ChunkFailed = 88, "CURLE_CHUNK_FAILED",
                "Chunk callback failed";
            NoConnectionAvailable = 89, "CURLE_NO_CONNECTION_AVAILABLE",
                "The max connection limit is reached";
            SslPinnedpubkeynotmatch = 90, "CURLE_SSL_PINNEDPUBKEYNOTMATCH",
                "SSL public key does not match pinned public key";
            SslInvalidcertstatus = 91, "CURLE_SSL_INVALIDCERTSTATUS",
                "SSL server certificate status verification FAILED";
            Http2Stream = 92, "CURLE_HTTP2_STREAM",
                "Stream error in the HTTP/2 framing layer";
            RecursiveApiCall = 93, "CURLE_RECURSIVE_API_CALL",
                "API function called from within callback";
            AuthError = 94, "CURLE_AUTH_ERROR",
                "An authentication function returned an error";
            Http3 = 95, "CURLE_HTTP3",
                "HTTP/3 error";
            QuicConnectError = 96, "CURLE_QUIC_CONNECT_ERROR",
                "QUIC connection error";
            Proxy = 97, "CURLE_PROXY",
                "proxy handshake error";
            SslClientcert = 98, "CURLE_SSL_CLIENTCERT",
                "SSL Client Certificate required";
            UnrecoverablePoll = 99, "CURLE_UNRECOVERABLE_POLL",
                "Unrecoverable error in select/poll";
            TooLarge = 100, "CURLE_TOO_LARGE",
                "A value or data field grew larger than allowed";
            EchRequired = 101, "CURLE_ECH_REQUIRED",
                "ECH attempted but failed";
            /// **Sentinel.** Commented "never use" in the C header: a bound for range checks, not a
            /// returnable value.
            Last = 102, "CURL_LAST",
                "Unknown error";
        ]
    }
}

result_code! {
    /// Every result a multi-interface function can report: `CURLMcode`.
    ///
    /// Transcribed from `include/curl/multi.h:59-78`. 15 enumerators occupy
    /// `-1..=13` with no gaps.
    ///
    /// The first enumerator is **negative**, and it is the only value the C
    /// declaration writes explicitly:
    ///
    /// ```c
    /// CURLM_CALL_MULTI_PERFORM = -1, /* please call curl_multi_perform() or
    ///                                   curl_multi_socket*() soon */
    /// CURLM_OK,
    /// ```
    ///
    /// That is why `#[repr(i32)]` is not merely conventional here but load
    /// bearing: no unsigned representation can hold `-1`, and the sequence
    /// restarts at `0` immediately afterwards, so inferring values from
    /// position would place every later code one off.
    ///
    /// `CURLM_CALL_MULTI_PERFORM` is in practice an internal
    /// "run again immediately" signal rather than a value an API caller
    /// observes: `lib/multi.c` sets it in 24 places and the loop at
    /// `lib/multi.c:2740`, `while((mresult == CURLM_CALL_MULTI_PERFORM) || ...)`,
    /// drains it before `curl_multi_perform` returns. It remains part of the
    /// ABI, the public header aliases it as the macro
    /// `CURLM_CALL_MULTI_SOCKET` (`include/curl/multi.h:83`, spliced verbatim by
    /// `curl-rs-ffi/build.rs` and deliberately not mirrored as a Rust item --
    /// see this module's documentation), and [`Self::is_ok`] reports `false`
    /// for it, matching the C tests that compare against `CURLM_OK` alone.
    ///
    /// Messages come from `curl_multi_strerror` (`lib/strerror.c:326-383`),
    /// whose `CURLM_LAST` arm is a bare `break` and therefore resolves to
    /// [`Self::UNKNOWN_MESSAGE`], `"Unknown error"` (`lib/strerror.c:376`).
    CURLMcode {
        kind: CodeKind::Multi,
        success: Ok,
        unknown: "Unknown error",
        codes: [
            CallMultiPerform = -1, "CURLM_CALL_MULTI_PERFORM",
                "Please call curl_multi_perform() soon";
            Ok = 0, "CURLM_OK",
                "No error";
            BadHandle = 1, "CURLM_BAD_HANDLE",
                "Invalid multi handle";
            BadEasyHandle = 2, "CURLM_BAD_EASY_HANDLE",
                "Invalid easy handle";
            OutOfMemory = 3, "CURLM_OUT_OF_MEMORY",
                "Out of memory";
            InternalError = 4, "CURLM_INTERNAL_ERROR",
                "Internal error";
            BadSocket = 5, "CURLM_BAD_SOCKET",
                "Invalid socket argument";
            UnknownOption = 6, "CURLM_UNKNOWN_OPTION",
                "Unknown option";
            AddedAlready = 7, "CURLM_ADDED_ALREADY",
                "The easy handle is already added to a multi handle";
            RecursiveApiCall = 8, "CURLM_RECURSIVE_API_CALL",
                "API function called from within callback";
            WakeupFailure = 9, "CURLM_WAKEUP_FAILURE",
                "Wakeup is unavailable or failed";
            BadFunctionArgument = 10, "CURLM_BAD_FUNCTION_ARGUMENT",
                "A libcurl function was given a bad argument";
            AbortedByCallback = 11, "CURLM_ABORTED_BY_CALLBACK",
                "Operation was aborted by an application callback";
            UnrecoverablePoll = 12, "CURLM_UNRECOVERABLE_POLL",
                "Unrecoverable error in select/poll";
            /// **Sentinel.** Commented "never use" in the C header: a bound for range checks, not a
            /// returnable value.
            Last = 13, "CURLM_LAST",
                "Unknown error";
        ]
    }
}

result_code! {
    /// Every result a URL API function can report: `CURLUcode`.
    ///
    /// Transcribed from `include/curl/urlapi.h:34-68`. 33 enumerators occupy
    /// `0..=32` with no gaps, and **none** of them is explicit in C.
    ///
    /// The C declaration carries drift-guard comments -- `/* 1 */` through
    /// `/* 31 */` -- beside its members precisely because the values are
    /// implicit there. Here the explicit discriminant *is* the guard, so those
    /// comments have no counterpart; the values are identical.
    ///
    /// `CURLUE_LAST` = 32 is a bound, not a value; the highest real error is
    /// `CURLUE_TOO_LARGE` = 31.
    ///
    /// Messages come from `curl_url_strerror` (`lib/strerror.c:420-531`). Note
    /// that this family's fallback is `"CURLUcode unknown"`
    /// (`lib/strerror.c:524`) and **not** `"Unknown error"`; the `CURLUE_LAST`
    /// arm is a bare `break` and resolves to it.
    CURLUcode {
        kind: CodeKind::Url,
        success: Ok,
        unknown: "CURLUcode unknown",
        codes: [
            Ok = 0, "CURLUE_OK",
                "No error";
            BadHandle = 1, "CURLUE_BAD_HANDLE",
                "An invalid CURLU pointer was passed as argument";
            BadPartpointer = 2, "CURLUE_BAD_PARTPOINTER",
                "An invalid 'part' argument was passed as argument";
            MalformedInput = 3, "CURLUE_MALFORMED_INPUT",
                "Malformed input to a URL function";
            BadPortNumber = 4, "CURLUE_BAD_PORT_NUMBER",
                "Port number was not a decimal number between 0 and 65535";
            UnsupportedScheme = 5, "CURLUE_UNSUPPORTED_SCHEME",
                "Unsupported URL scheme";
            Urldecode = 6, "CURLUE_URLDECODE",
                "URL decode error, most likely because of rubbish in the input";
            OutOfMemory = 7, "CURLUE_OUT_OF_MEMORY",
                "A memory function failed";
            UserNotAllowed = 8, "CURLUE_USER_NOT_ALLOWED",
                "Credentials was passed in the URL when prohibited";
            UnknownPart = 9, "CURLUE_UNKNOWN_PART",
                "An unknown part ID was passed to a URL API function";
            NoScheme = 10, "CURLUE_NO_SCHEME",
                "No scheme part in the URL";
            NoUser = 11, "CURLUE_NO_USER",
                "No user part in the URL";
            NoPassword = 12, "CURLUE_NO_PASSWORD",
                "No password part in the URL";
            NoOptions = 13, "CURLUE_NO_OPTIONS",
                "No options part in the URL";
            NoHost = 14, "CURLUE_NO_HOST",
                "No host part in the URL";
            NoPort = 15, "CURLUE_NO_PORT",
                "No port part in the URL";
            NoQuery = 16, "CURLUE_NO_QUERY",
                "No query part in the URL";
            NoFragment = 17, "CURLUE_NO_FRAGMENT",
                "No fragment part in the URL";
            NoZoneid = 18, "CURLUE_NO_ZONEID",
                "No zoneid part in the URL";
            BadFileUrl = 19, "CURLUE_BAD_FILE_URL",
                "Bad file:// URL";
            BadFragment = 20, "CURLUE_BAD_FRAGMENT",
                "Bad fragment";
            BadHostname = 21, "CURLUE_BAD_HOSTNAME",
                "Bad hostname";
            BadIpv6 = 22, "CURLUE_BAD_IPV6",
                "Bad IPv6 address";
            BadLogin = 23, "CURLUE_BAD_LOGIN",
                "Bad login part";
            BadPassword = 24, "CURLUE_BAD_PASSWORD",
                "Bad password";
            BadPath = 25, "CURLUE_BAD_PATH",
                "Bad path";
            BadQuery = 26, "CURLUE_BAD_QUERY",
                "Bad query";
            BadScheme = 27, "CURLUE_BAD_SCHEME",
                "Bad scheme";
            BadSlashes = 28, "CURLUE_BAD_SLASHES",
                "Unsupported number of slashes following scheme";
            BadUser = 29, "CURLUE_BAD_USER",
                "Bad user";
            LacksIdn = 30, "CURLUE_LACKS_IDN",
                "libcurl lacks IDN support";
            TooLarge = 31, "CURLUE_TOO_LARGE",
                "A value or data field is larger than allowed";
            /// **Sentinel.** Commented "never use" in the C header: a bound for range checks, not a
            /// returnable value.
            Last = 32, "CURLUE_LAST",
                "CURLUcode unknown";
        ]
    }
}

result_code! {
    /// Every result a header API function can report: `CURLHcode`.
    ///
    /// Transcribed from `include/curl/header.h:47-56`. 8 enumerators occupy
    /// `0..=7` with no gaps, none explicit in C. Returned by
    /// `curl_easy_header`.
    ///
    /// # There is no `CURLHE_LAST`
    ///
    /// This family has **no sentinel**, unlike the other four, and none is
    /// invented here. Inventing one would add a name that no C consumer has and
    /// that `docs/libcurl/symbols-in-versions` does not list. Symmetry is the
    /// wrong instinct: the highest member, `CURLHE_NOT_BUILT_IN` = 7, is a real
    /// returnable error.
    ///
    /// # These messages are not ABI text
    ///
    /// The C tree has no `curl_header_strerror` and no `CURLHE_*` string table
    /// anywhere under `lib/`, `src/` or `include/`, so no C consumer can
    /// observe these strings and no oracle exists to compare them against.
    /// They are derived from the header's own inline comments at
    /// `include/curl/header.h:48-55`, in the house style of
    /// `curl_easy_strerror`. [`Self::UNKNOWN_MESSAGE`] is `"Unknown error"` by
    /// the same reasoning: a value is needed, and none is prescribed.
    CURLHcode {
        kind: CodeKind::Header,
        success: Ok,
        unknown: "Unknown error",
        codes: [
            Ok = 0, "CURLHE_OK",
                "No error";
            Badindex = 1, "CURLHE_BADINDEX",
                "The header exists but not with this index";
            Missing = 2, "CURLHE_MISSING",
                "No such header exists";
            Noheaders = 3, "CURLHE_NOHEADERS",
                "No headers at all exist yet";
            Norequest = 4, "CURLHE_NOREQUEST",
                "No request with this number was used";
            OutOfMemory = 5, "CURLHE_OUT_OF_MEMORY",
                "Out of memory while processing headers";
            BadArgument = 6, "CURLHE_BAD_ARGUMENT",
                "A function argument was not okay";
            NotBuiltIn = 7, "CURLHE_NOT_BUILT_IN",
                "The header API was disabled in this build";
        ]
    }
}

result_code! {
    /// Every result a share-interface function can report: `CURLSHcode`.
    ///
    /// Transcribed from `include/curl/curl.h:3058-3066`. 7 enumerators occupy
    /// `0..=6` with no gaps, none explicit in C. Returned by
    /// `curl_share_setopt` and `curl_share_cleanup`.
    ///
    /// `CURLSHE_LAST` = 6 is a bound, not a value; the highest real error is
    /// `CURLSHE_NOT_BUILT_IN` = 5.
    ///
    /// Messages come from `curl_share_strerror` (`lib/strerror.c:385-418`).
    /// This family's fallback is `"CURLSHcode unknown"`
    /// (`lib/strerror.c:411`), again **not** `"Unknown error"`; the
    /// `CURLSHE_LAST` arm is a bare `break` and resolves to it.
    CURLSHcode {
        kind: CodeKind::Share,
        success: Ok,
        unknown: "CURLSHcode unknown",
        codes: [
            Ok = 0, "CURLSHE_OK",
                "No error";
            BadOption = 1, "CURLSHE_BAD_OPTION",
                "Unknown share option";
            InUse = 2, "CURLSHE_IN_USE",
                "Share currently in use";
            Invalid = 3, "CURLSHE_INVALID",
                "Invalid share handle";
            Nomem = 4, "CURLSHE_NOMEM",
                "Out of memory";
            NotBuiltIn = 5, "CURLSHE_NOT_BUILT_IN",
                "Feature not enabled in this library";
            /// **Sentinel.** Commented "never use" in the C header: a bound for range checks, not a
            /// returnable value.
            Last = 6, "CURLSHE_LAST",
                "CURLSHcode unknown";
        ]
    }
}

/// A [`CURLcode`] carried together with the context that produced it.
///
/// The C tree reports an error twice over: the function returns a `CURLcode`,
/// and separately `Curl_failf` writes a specific human-readable line into the
/// buffer that `CURLOPT_ERRORBUFFER` designates. `curl_easy_strerror` only ever
/// yields the generic string for the code. This type keeps both halves
/// together, which is what lets an internal `Result<_, Error>` carry the
/// specific line while the ABI boundary still returns the pinned integer.
///
/// # It is an addition, never a replacement
///
/// The conversion into [`CURLcode`] is **total and infallible**: every `Error`
/// has a code, and that code is always one of the 103 pinned discriminants.
/// Nothing in this crate can return a value that is not one of them, whatever
/// context it accumulates on the way out.
///
/// # Why the implementations here are hand written
///
/// `thiserror` is a dependency of this crate and [`UnknownCode`] uses it. It is
/// not used for this type, because [`Display`](core::fmt::Display) must fall
/// back from the optional context to [`CURLcode::message`] at run time, which
/// no `#[error(...)]` format string expresses. The alternative would be an
/// attribute calling a helper method, which is less readable than the six lines
/// it replaces.
///
/// # Examples
///
/// ```ignore
/// let err = Error::with_context(CURLcode::CouldntResolveHost, "no address for example.com");
/// assert_eq!(err.code(), CURLcode::CouldntResolveHost);
/// assert_eq!(err.to_string(), "no address for example.com");
/// // The generic string stays reachable for curl_easy_strerror.
/// assert_eq!(err.code().message(), "Could not resolve hostname");
/// // And the conversion the FFI boundary performs cannot fail.
/// assert_eq!(CURLcode::from(err), CURLcode::CouldntResolveHost);
/// ```
#[derive(Debug)]
pub struct Error {
    /// The pinned code this error resolves to at the ABI boundary.
    code: CURLcode,
    /// The specific line, when one is known. `Cow` so that the overwhelmingly
    /// common static message costs no allocation while a formatted one is still
    /// possible.
    context: Option<Cow<'static, str>>,
    /// The underlying failure, when this error wraps one.
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl Error {
    /// An error carrying only its code.
    ///
    /// [`Display`](core::fmt::Display) then renders the same generic string
    /// that `curl_easy_strerror` returns.
    #[must_use]
    pub const fn new(code: CURLcode) -> Self {
        Self {
            code,
            context: None,
            source: None,
        }
    }

    /// An error carrying a specific message alongside its code.
    ///
    /// The message is what `Curl_failf` would have written into
    /// `CURLOPT_ERRORBUFFER`.
    #[must_use]
    pub fn with_context(
        code: CURLcode,
        context: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            code,
            context: Some(context.into()),
            source: None,
        }
    }

    /// An error wrapping an underlying failure, reachable through
    /// [`std::error::Error::source`].
    ///
    /// Used where a dependency's error must be preserved for diagnostics while
    /// the caller still receives a curl code -- a `rustls` handshake failure
    /// behind [`CURLcode::SslConnectError`], for instance.
    #[must_use]
    pub fn with_source(
        code: CURLcode,
        context: impl Into<Cow<'static, str>>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            code,
            context: Some(context.into()),
            source: Some(Box::new(source)),
        }
    }

    /// The pinned code this error resolves to.
    #[must_use]
    pub const fn code(&self) -> CURLcode {
        self.code
    }

    /// The specific message, if this error carries one.
    #[must_use]
    pub fn context(&self) -> Option<&str> {
        self.context.as_deref()
    }

    /// The most specific message available: the context if there is one,
    /// otherwise the code's generic string.
    #[must_use]
    pub fn message(&self) -> &str {
        match self.context.as_deref() {
            Some(context) => context,
            None => self.code.message(),
        }
    }

    /// Discards the context and yields the code.
    ///
    /// The same conversion as `From<Error> for CURLcode`, named for the places
    /// that read better as a method call.
    #[must_use]
    pub fn into_code(self) -> CURLcode {
        self.code
    }

    /// Attaches a message to an existing error, replacing any it already had.
    #[must_use]
    pub fn context_with(
        mut self,
        context: impl Into<Cow<'static, str>>,
    ) -> Self {
        self.context = Some(context.into());
        self
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // `as_deref` would yield `&(dyn Error + Send + Sync)`, which is a
        // different trait object type; the cast widens it to the one the trait
        // requires.
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn std::error::Error + 'static))
    }
}

impl From<CURLcode> for Error {
    /// Lifts a bare code, so a function returning `Result<_, Error>` can
    /// propagate one with `?`.
    fn from(code: CURLcode) -> Self {
        Self::new(code)
    }
}

impl From<Error> for CURLcode {
    /// The total, infallible conversion the ABI boundary depends on.
    fn from(error: Error) -> Self {
        error.code
    }
}

impl From<Error> for i32 {
    /// The same conversion carried one step further, to the integer C receives.
    fn from(error: Error) -> Self {
        error.code as Self
    }
}

/// The crate's ordinary fallible result: a [`CURLcode`] plus its context.
///
/// This is the alias internal functions use, standing where the C tree wrote
/// `CURLcode Curl_xyz(...)`.
pub type CurlResult<T> = Result<T, Error>;

/// A result over a bare [`CURLcode`], with no context attached.
///
/// For the boundary layers, where the code is all that survives.
pub type CodeResult<T> = Result<T, CURLcode>;

/// A result over [`CURLMcode`], for the multi interface.
pub type MultiResult<T> = Result<T, CURLMcode>;

/// A result over [`CURLUcode`], for the URL API.
pub type UrlResult<T> = Result<T, CURLUcode>;

/// A result over [`CURLHcode`], for the header API.
pub type HeaderResult<T> = Result<T, CURLHcode>;

/// A result over [`CURLSHcode`], for the share interface.
pub type ShareResult<T> = Result<T, CURLSHcode>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The checks that every family must satisfy identically.
    ///
    /// `tests/unit/*.c` cannot link against a Rust static library, because
    /// `pub(crate)` items are genuinely absent from its symbol table rather
    /// than merely hidden. Their coverage is relocated here instead, and this
    /// macro is what keeps the relocation from becoming five copies of the same
    /// assertions.
    macro_rules! family_invariants {
        ($test:ident, $name:ident, $kind:expr, $count:expr, $first:expr, $unknown:expr) => {
            #[test]
            fn $test() {
                // The representation itself, before any value. `#[repr(i32)]`
                // must give the exact layout of the C `int` that every public
                // prototype returns; a wider, narrower or unsigned repr would
                // corrupt the boundary no matter how right the discriminants
                // are. All four mandated targets are ILP32-int, so `i32` is
                // the correct oracle on every one of them.
                assert_eq!(
                    core::mem::size_of::<$name>(),
                    core::mem::size_of::<i32>(),
                    concat!(stringify!($name), " must be laid out as a C int")
                );
                assert_eq!(
                    core::mem::align_of::<$name>(),
                    core::mem::align_of::<i32>(),
                    concat!(stringify!($name), " must align as a C int")
                );

                // Exactly as many members as the C header declares. A dropped
                // or duplicated row fails here.
                assert_eq!(
                    $name::VARIANTS.len(),
                    $count,
                    concat!(
                        stringify!($name),
                        " must declare exactly ",
                        $count,
                        " members"
                    )
                );

                // Contiguous from the first value, which is what proves no
                // placeholder was skipped and nothing was renumbered.
                for (index, code) in $name::VARIANTS.iter().enumerate() {
                    let expected = $first + index as i32;
                    assert_eq!(
                        code.as_i32(),
                        expected,
                        "{} must sit at {}",
                        code.c_name(),
                        expected
                    );
                }

                // Every discriminant distinct.
                let mut seen: Vec<i32> =
                    $name::VARIANTS.iter().map(|c| c.as_i32()).collect();
                seen.sort_unstable();
                let total = seen.len();
                seen.dedup();
                assert_eq!(seen.len(), total, "duplicate discriminant");

                // Both halves of the FFI boundary round-trip for every member.
                for &code in $name::VARIANTS {
                    let raw = code.as_i32();
                    assert_eq!($name::from_i32(raw), Some(code));
                    assert_eq!($name::try_from(raw), Ok(code));
                    assert_eq!(i32::from(code), raw);
                    assert_eq!($name::message_for(raw), code.message());
                    // The NUL-terminated view is the SAME text: one literal,
                    // two shapes. This is the assertion that makes the
                    // "no mirrored table" claim on `message_c` executable.
                    assert_eq!(
                        code.message_c()
                            .to_str()
                            .expect("message must be UTF-8"),
                        code.message(),
                        "the C view of a message must equal the Rust view"
                    );
                    assert_eq!($name::message_for_c(raw), code.message_c());
                    // Display is defined in terms of message().
                    assert_eq!(code.to_string(), code.message());
                    // Non-empty, non-padded message text.
                    assert!(!code.message().is_empty());
                    assert_eq!(code.message().trim(), code.message());
                    // The C token is spelled out and greppable.
                    assert!(code.c_name().starts_with("CURL"));
                }

                // Family identity and the per-family fallback.
                assert_eq!($name::KIND, $kind);
                assert_eq!($name::UNKNOWN_MESSAGE, $unknown);
                assert_eq!(
                    $name::UNKNOWN_MESSAGE_C
                        .to_str()
                        .expect("the unknown-code message must be UTF-8"),
                    $unknown
                );

                // Integers outside the enumeration are refused inbound and
                // resolve to the fallback for messaging.
                for raw in [i32::MIN, -9999, 100_000, i32::MAX] {
                    assert_eq!($name::from_i32(raw), None);
                    assert_eq!(
                        $name::try_from(raw),
                        Err(UnknownCode::new($kind, raw))
                    );
                    assert_eq!($name::message_for(raw), $unknown);
                    assert_eq!(
                        $name::message_for_c(raw),
                        $name::UNKNOWN_MESSAGE_C
                    );
                }

                // Exactly one success code, and into_result agrees with it.
                let successes: Vec<_> = $name::VARIANTS
                    .iter()
                    .filter(|c| c.is_ok())
                    .copied()
                    .collect();
                assert_eq!(successes.len(), 1);
                assert_eq!(successes[0].as_i32(), 0);
                for &code in $name::VARIANTS {
                    assert_eq!(
                        code.into_result(),
                        if code.is_ok() { Ok(()) } else { Err(code) }
                    );
                }

                // Usable as an ordinary Rust error.
                let boxed: Box<dyn std::error::Error> =
                    Box::new($name::VARIANTS[0]);
                assert_eq!(boxed.to_string(), $name::VARIANTS[0].message());
            }
        };
    }

    family_invariants!(
        easy_family_invariants,
        CURLcode,
        CodeKind::Easy,
        103,
        0,
        "Unknown error"
    );
    family_invariants!(
        multi_family_invariants,
        CURLMcode,
        CodeKind::Multi,
        15,
        -1,
        "Unknown error"
    );
    family_invariants!(
        url_family_invariants,
        CURLUcode,
        CodeKind::Url,
        33,
        0,
        "CURLUcode unknown"
    );
    family_invariants!(
        header_family_invariants,
        CURLHcode,
        CodeKind::Header,
        8,
        0,
        "Unknown error"
    );
    family_invariants!(
        share_family_invariants,
        CURLSHcode,
        CodeKind::Share,
        7,
        0,
        "CURLSHcode unknown"
    );

    /// Every anchor value verified against `include/curl/curl.h:518-648`.
    #[test]
    fn curlcode_anchor_values() {
        assert_eq!(CURLcode::Ok as i32, 0);
        assert_eq!(CURLcode::UnsupportedProtocol as i32, 1);
        assert_eq!(CURLcode::FailedInit as i32, 2);
        assert_eq!(CURLcode::UrlMalformat as i32, 3);
        assert_eq!(CURLcode::NotBuiltIn as i32, 4);
        assert_eq!(CURLcode::CouldntResolveProxy as i32, 5);
        assert_eq!(CURLcode::CouldntResolveHost as i32, 6);
        assert_eq!(CURLcode::CouldntConnect as i32, 7);
        assert_eq!(CURLcode::OutOfMemory as i32, 27);
        assert_eq!(CURLcode::OperationTimedout as i32, 28);
        assert_eq!(CURLcode::SslConnectError as i32, 35);
        assert_eq!(CURLcode::TooManyRedirects as i32, 47);
        assert_eq!(CURLcode::PeerFailedVerification as i32, 60);
        assert_eq!(CURLcode::TooLarge as i32, 100);
        assert_eq!(CURLcode::EchRequired as i32, 101);
        assert_eq!(CURLcode::Last as i32, 102);
    }

    /// The 15 retired placeholders occupy exactly the measured positions.
    ///
    /// Omitting any one of them would shift every later code by one, so this is
    /// the single most consequential assertion in the file.
    #[test]
    fn curlcode_obsolete_placeholders_hold_their_positions() {
        let placeholders: Vec<i32> = CURLcode::VARIANTS
            .iter()
            .filter(|code| code.c_name().starts_with("CURLE_OBSOLETE"))
            .map(|code| code.as_i32())
            .collect();

        assert_eq!(
            placeholders,
            vec![20, 24, 29, 32, 34, 40, 41, 44, 46, 50, 51, 57, 62, 75, 76],
            "the retired CURLE_OBSOLETE* set must match include/curl/curl.h exactly"
        );
        assert_eq!(placeholders.len(), 15);

        // Each is named after the position it holds, so the header and this
        // file can be grepped against one another.
        for value in placeholders {
            let code =
                CURLcode::from_i32(value).expect("placeholder must exist");
            assert_eq!(code.c_name(), format!("CURLE_OBSOLETE{value}"));
            // C reaches `default:` for all of them.
            assert_eq!(code.message(), "Unknown error");
        }
    }

    /// `CURLMcode`'s first discriminant is negative, and it is declared before
    /// the success code.
    #[test]
    fn curlmcode_first_discriminant_is_negative() {
        assert_eq!(CURLMcode::CallMultiPerform as i32, -1);
        assert_eq!(CURLMcode::Ok as i32, 0);
        assert_eq!(CURLMcode::BadHandle as i32, 1);
        assert_eq!(CURLMcode::UnrecoverablePoll as i32, 12);
        assert_eq!(CURLMcode::Last as i32, 13);

        // `#[repr(i32)]` and the derived ordering follow the discriminants, not
        // declaration position, so the negative value really does sort first.
        assert!(CURLMcode::CallMultiPerform < CURLMcode::Ok);
        assert!(CURLMcode::CallMultiPerform.as_i32() < 0);
        assert!(!CURLMcode::CallMultiPerform.is_ok());
    }

    /// The value `CURLM_CALL_MULTI_SOCKET` expands to, asserted where it lives.
    ///
    /// `include/curl/multi.h:83` makes the alias a `#define` over
    /// `CURLM_CALL_MULTI_PERFORM`, and `curl-rs-ffi/build.rs` carries that line
    /// verbatim, so the alias itself has no Rust item to test. What this module
    /// owns is the value it resolves to, and that is what a consumer comparing
    /// against either spelling depends on: the integer `-1` and the C name
    /// `CURLM_CALL_MULTI_PERFORM`. Both are asserted here so that removing the
    /// mirrored `pub const` cost no coverage.
    #[test]
    fn the_value_the_call_multi_socket_alias_expands_to_is_pinned() {
        assert_eq!(CURLMcode::CallMultiPerform.as_i32(), -1);
        assert_eq!(
            CURLMcode::CallMultiPerform.c_name(),
            "CURLM_CALL_MULTI_PERFORM"
        );
    }

    /// `CURLUcode` bounds, from `include/curl/urlapi.h:34-68`.
    #[test]
    fn curlucode_bounds() {
        assert_eq!(CURLUcode::Ok as i32, 0);
        assert_eq!(CURLUcode::BadHandle as i32, 1);
        assert_eq!(CURLUcode::BadPartpointer as i32, 2);
        assert_eq!(CURLUcode::LacksIdn as i32, 30);
        assert_eq!(CURLUcode::TooLarge as i32, 31);
        assert_eq!(CURLUcode::Last as i32, 32);
    }

    /// `CURLHcode` has eight members and deliberately no sentinel.
    #[test]
    fn curlhcode_has_eight_members_and_no_sentinel() {
        assert_eq!(CURLHcode::VARIANTS.len(), 8);
        assert_eq!(CURLHcode::Ok as i32, 0);
        assert_eq!(CURLHcode::Badindex as i32, 1);
        assert_eq!(CURLHcode::Missing as i32, 2);
        assert_eq!(CURLHcode::Noheaders as i32, 3);
        assert_eq!(CURLHcode::Norequest as i32, 4);
        assert_eq!(CURLHcode::OutOfMemory as i32, 5);
        assert_eq!(CURLHcode::BadArgument as i32, 6);
        assert_eq!(CURLHcode::NotBuiltIn as i32, 7);

        // No `_LAST`: the highest member is a real, returnable error. The other
        // four families all have one, and inventing one here would add a name
        // no C consumer has.
        assert!(
            !CURLHcode::VARIANTS
                .iter()
                .any(|code| code.c_name().ends_with("_LAST")),
            "CURLHcode must not gain a sentinel"
        );
        assert_eq!(CURLHcode::from_i32(8), None);
    }

    /// The other four families do each carry a sentinel, and it is the highest
    /// member.
    #[test]
    fn the_other_four_families_end_with_their_sentinel() {
        assert_eq!(CURLcode::VARIANTS.last().copied(), Some(CURLcode::Last));
        assert_eq!(CURLcode::Last.c_name(), "CURL_LAST"); // note: not CURLE_LAST
        assert_eq!(CURLMcode::VARIANTS.last().copied(), Some(CURLMcode::Last));
        assert_eq!(CURLMcode::Last.c_name(), "CURLM_LAST");
        assert_eq!(CURLUcode::VARIANTS.last().copied(), Some(CURLUcode::Last));
        assert_eq!(CURLUcode::Last.c_name(), "CURLUE_LAST");
        assert_eq!(
            CURLSHcode::VARIANTS.last().copied(),
            Some(CURLSHcode::Last)
        );
        assert_eq!(CURLSHcode::Last.c_name(), "CURLSHE_LAST");
    }

    /// `CURLSHcode`, from `include/curl/curl.h:3058-3066`.
    #[test]
    fn curlshcode_values() {
        assert_eq!(CURLSHcode::Ok as i32, 0);
        assert_eq!(CURLSHcode::BadOption as i32, 1);
        assert_eq!(CURLSHcode::InUse as i32, 2);
        assert_eq!(CURLSHcode::Invalid as i32, 3);
        assert_eq!(CURLSHcode::Nomem as i32, 4);
        assert_eq!(CURLSHcode::NotBuiltIn as i32, 5);
        assert_eq!(CURLSHcode::Last as i32, 6);
    }

    /// Message text from `curl_easy_strerror`, byte for byte.
    #[test]
    fn easy_messages_are_byte_exact() {
        assert_eq!(CURLcode::Ok.message(), "No error");
        assert_eq!(
            CURLcode::UnsupportedProtocol.message(),
            "Unsupported protocol"
        );
        assert_eq!(CURLcode::FailedInit.message(), "Failed initialization");
        assert_eq!(
            CURLcode::UrlMalformat.message(),
            "URL using bad/illegal format or missing URL"
        );
        assert_eq!(CURLcode::OutOfMemory.message(), "Out of memory");
        assert_eq!(
            CURLcode::OperationTimedout.message(),
            "Timeout was reached"
        );
        assert_eq!(CURLcode::SslConnectError.message(), "SSL connect error");
        assert_eq!(
            CURLcode::TooManyRedirects.message(),
            "Number of redirects hit maximum amount"
        );
        assert_eq!(
            CURLcode::PeerFailedVerification.message(),
            "SSL peer certificate or SSH remote key was not OK"
        );
        assert_eq!(CURLcode::EchRequired.message(), "ECH attempted but failed");
        assert_eq!(CURLcode::Proxy.message(), "proxy handshake error"); // lower case in C
        assert_eq!(
            CURLcode::SslInvalidcertstatus.message(),
            "SSL server certificate status verification FAILED" // upper case in C
        );
        assert_eq!(
            CURLcode::FtpPretFailed.message(),
            "FTP: The server did not accept the PRET command."
        );
    }

    /// The only message the C source splits across two literals
    /// (`lib/strerror.c:51-52`) must join to exactly one string.
    #[test]
    fn the_concatenated_easy_message_joins_correctly() {
        assert_eq!(
            CURLcode::NotBuiltIn.message(),
            "A requested feature, protocol or option was not found built-in in this libcurl \
             due to a build-time decision."
        );
        // No doubled or missing space at the seam.
        assert!(!CURLcode::NotBuiltIn.message().contains("  "));
        assert!(CURLcode::NotBuiltIn
            .message()
            .contains("built-in in this libcurl due to"));
    }

    /// Message text from `curl_multi_strerror`, byte for byte.
    #[test]
    fn multi_messages_are_byte_exact() {
        assert_eq!(
            CURLMcode::CallMultiPerform.message(),
            "Please call curl_multi_perform() soon"
        );
        assert_eq!(CURLMcode::Ok.message(), "No error");
        assert_eq!(CURLMcode::BadHandle.message(), "Invalid multi handle");
        assert_eq!(CURLMcode::BadEasyHandle.message(), "Invalid easy handle");
        assert_eq!(CURLMcode::OutOfMemory.message(), "Out of memory");
        assert_eq!(CURLMcode::InternalError.message(), "Internal error");
        assert_eq!(CURLMcode::BadSocket.message(), "Invalid socket argument");
        assert_eq!(CURLMcode::UnknownOption.message(), "Unknown option");
        assert_eq!(
            CURLMcode::AddedAlready.message(),
            "The easy handle is already added to a multi handle"
        );
        assert_eq!(
            CURLMcode::RecursiveApiCall.message(),
            "API function called from within callback"
        );
        assert_eq!(
            CURLMcode::WakeupFailure.message(),
            "Wakeup is unavailable or failed"
        );
        assert_eq!(
            CURLMcode::BadFunctionArgument.message(),
            "A libcurl function was given a bad argument"
        );
        assert_eq!(
            CURLMcode::AbortedByCallback.message(),
            "Operation was aborted by an application callback"
        );
        assert_eq!(
            CURLMcode::UnrecoverablePoll.message(),
            "Unrecoverable error in select/poll"
        );
        // The C arm is a bare `break`, so it falls through to the fallback.
        assert_eq!(CURLMcode::Last.message(), "Unknown error");
    }

    /// Message text from `curl_url_strerror`, byte for byte.
    #[test]
    fn url_messages_are_byte_exact() {
        assert_eq!(CURLUcode::Ok.message(), "No error");
        assert_eq!(
            CURLUcode::BadHandle.message(),
            "An invalid CURLU pointer was passed as argument"
        );
        assert_eq!(
            CURLUcode::BadPartpointer.message(),
            "An invalid 'part' argument was passed as argument"
        );
        assert_eq!(
            CURLUcode::MalformedInput.message(),
            "Malformed input to a URL function"
        );
        assert_eq!(
            CURLUcode::BadPortNumber.message(),
            "Port number was not a decimal number between 0 and 65535"
        );
        assert_eq!(
            CURLUcode::UnsupportedScheme.message(),
            "Unsupported URL scheme"
        );
        assert_eq!(
            CURLUcode::Urldecode.message(),
            "URL decode error, most likely because of rubbish in the input"
        );
        assert_eq!(
            CURLUcode::OutOfMemory.message(),
            "A memory function failed"
        );
        assert_eq!(
            CURLUcode::UserNotAllowed.message(),
            "Credentials was passed in the URL when prohibited"
        );
        assert_eq!(CURLUcode::BadFileUrl.message(), "Bad file:// URL");
        assert_eq!(
            CURLUcode::BadSlashes.message(),
            "Unsupported number of slashes following scheme"
        );
        assert_eq!(CURLUcode::LacksIdn.message(), "libcurl lacks IDN support");
        assert_eq!(
            CURLUcode::TooLarge.message(),
            "A value or data field is larger than allowed" // "is", not "grew"
        );
        assert_eq!(CURLUcode::Last.message(), "CURLUcode unknown");

        // The embedded apostrophe survives verbatim.
        assert!(CURLUcode::BadPartpointer.message().contains('\''));
    }

    /// Message text from `curl_share_strerror`, byte for byte.
    #[test]
    fn share_messages_are_byte_exact() {
        assert_eq!(CURLSHcode::Ok.message(), "No error");
        assert_eq!(CURLSHcode::BadOption.message(), "Unknown share option");
        assert_eq!(CURLSHcode::InUse.message(), "Share currently in use");
        assert_eq!(CURLSHcode::Invalid.message(), "Invalid share handle");
        assert_eq!(CURLSHcode::Nomem.message(), "Out of memory");
        assert_eq!(
            CURLSHcode::NotBuiltIn.message(),
            "Feature not enabled in this library"
        );
        assert_eq!(CURLSHcode::Last.message(), "CURLSHcode unknown");
    }

    /// `CURLHcode` messages have no C oracle, so the contract asserted here is
    /// only that they exist, are distinct and follow the house style.
    #[test]
    fn header_messages_are_present_and_distinct() {
        assert_eq!(CURLHcode::Ok.message(), "No error");
        assert_eq!(
            CURLHcode::NotBuiltIn.message(),
            "The header API was disabled in this build"
        );

        let mut messages: Vec<&str> = CURLHcode::VARIANTS
            .iter()
            .map(|code| code.message())
            .collect();
        let total = messages.len();
        messages.sort_unstable();
        messages.dedup();
        assert_eq!(messages.len(), total, "header messages must be distinct");

        for code in CURLHcode::VARIANTS {
            let message = code.message();
            assert!(!message.ends_with('.'), "house style: no trailing stop");
            assert!(
                message.starts_with(|c: char| c.is_ascii_uppercase()),
                "house style: capitalized"
            );
        }
    }

    /// The four C functions do not share a fallback string.
    #[test]
    fn the_three_fallbacks_are_distinct() {
        // lib/strerror.c:317 and :376
        assert_eq!(CURLcode::UNKNOWN_MESSAGE, "Unknown error");
        assert_eq!(CURLMcode::UNKNOWN_MESSAGE, "Unknown error");
        // lib/strerror.c:411
        assert_eq!(CURLSHcode::UNKNOWN_MESSAGE, "CURLSHcode unknown");
        // lib/strerror.c:524 -- measured, and NOT "Unknown error"
        assert_eq!(CURLUcode::UNKNOWN_MESSAGE, "CURLUcode unknown");

        assert_ne!(CURLSHcode::UNKNOWN_MESSAGE, CURLcode::UNKNOWN_MESSAGE);
        assert_ne!(CURLUcode::UNKNOWN_MESSAGE, CURLcode::UNKNOWN_MESSAGE);
        assert_ne!(CURLUcode::UNKNOWN_MESSAGE, CURLSHcode::UNKNOWN_MESSAGE);

        // And they are what an out-of-range integer resolves to.
        assert_eq!(CURLcode::message_for(103), "Unknown error");
        assert_eq!(CURLMcode::message_for(14), "Unknown error");
        assert_eq!(CURLUcode::message_for(33), "CURLUcode unknown");
        assert_eq!(CURLSHcode::message_for(7), "CURLSHcode unknown");
        assert_eq!(CURLHcode::message_for(8), "Unknown error");
    }

    /// `CodeKind` renders the C type names.
    #[test]
    fn code_kind_renders_c_type_names() {
        assert_eq!(CodeKind::Easy.to_string(), "CURLcode");
        assert_eq!(CodeKind::Multi.to_string(), "CURLMcode");
        assert_eq!(CodeKind::Url.to_string(), "CURLUcode");
        assert_eq!(CodeKind::Header.to_string(), "CURLHcode");
        assert_eq!(CodeKind::Share.to_string(), "CURLSHcode");
    }

    /// A rejected integer reports both the family and the offending value.
    #[test]
    fn unknown_code_reports_family_and_value() {
        let error =
            CURLcode::try_from(4242).expect_err("4242 is not a CURLcode");
        assert_eq!(error, UnknownCode::new(CodeKind::Easy, 4242));
        assert_eq!(error.kind, CodeKind::Easy);
        assert_eq!(error.value, 4242);
        assert_eq!(error.to_string(), "4242 is not a valid CURLcode value");

        let error = CURLUcode::try_from(-7).expect_err("-7 is not a CURLUcode");
        assert_eq!(error.to_string(), "-7 is not a valid CURLUcode value");

        let boxed: Box<dyn std::error::Error> = Box::new(error);
        assert!(boxed.source().is_none());
    }

    /// `Error` carries a code plus the specific line, and renders the more
    /// specific of the two.
    #[test]
    fn error_carries_code_and_context() {
        let bare = Error::new(CURLcode::CouldntResolveHost);
        assert_eq!(bare.code(), CURLcode::CouldntResolveHost);
        assert_eq!(bare.context(), None);
        assert_eq!(bare.message(), "Could not resolve hostname");
        assert_eq!(bare.to_string(), "Could not resolve hostname");

        let detailed = Error::with_context(
            CURLcode::CouldntResolveHost,
            "no address for example.com",
        );
        assert_eq!(detailed.code(), CURLcode::CouldntResolveHost);
        assert_eq!(detailed.context(), Some("no address for example.com"));
        assert_eq!(detailed.to_string(), "no address for example.com");
        // The generic string stays reachable, which is what strerror needs.
        assert_eq!(detailed.code().message(), "Could not resolve hostname");

        let owned = Error::with_context(
            CURLcode::TooLarge,
            format!("{} bytes", 1 << 20),
        );
        assert_eq!(owned.context(), Some("1048576 bytes"));

        let relabelled =
            Error::new(CURLcode::WriteError).context_with("disk full");
        assert_eq!(relabelled.code(), CURLcode::WriteError);
        assert_eq!(relabelled.context(), Some("disk full"));
    }

    /// The conversion into `CURLcode` is total: it exists for every code and
    /// cannot fail.
    #[test]
    fn error_conversion_into_curlcode_is_total() {
        for &code in CURLcode::VARIANTS {
            assert_eq!(CURLcode::from(Error::new(code)), code);
            assert_eq!(Error::new(code).into_code(), code);
            assert_eq!(i32::from(Error::new(code)), code.as_i32());
            // Context never changes the code that reaches the boundary.
            assert_eq!(
                CURLcode::from(Error::with_context(code, "context")),
                code
            );
            // And the lift back is the identity on the code.
            assert_eq!(Error::from(code).code(), code);
        }
    }

    /// A wrapped failure stays reachable through `source()`.
    #[test]
    fn error_source_is_reachable() {
        let inner = UnknownCode::new(CodeKind::Easy, 999);
        let outer = Error::with_source(
            CURLcode::SslConnectError,
            "handshake failed",
            inner,
        );

        assert_eq!(outer.code(), CURLcode::SslConnectError);
        assert_eq!(outer.to_string(), "handshake failed");

        let source = std::error::Error::source(&outer)
            .expect("source must be reachable");
        assert_eq!(source.to_string(), "999 is not a valid CURLcode value");

        assert!(std::error::Error::source(&Error::new(CURLcode::Ok)).is_none());
    }

    /// The result aliases name the types they advertise.
    #[test]
    fn result_aliases_are_wired_to_their_families() {
        let curl: CurlResult<u8> = Err(Error::new(CURLcode::Again));
        assert_eq!(curl.map_err(CURLcode::from), Err(CURLcode::Again));

        let code: CodeResult<u8> = Err(CURLcode::Again);
        assert_eq!(code, Err(CURLcode::Again));

        let multi: MultiResult<u8> = Err(CURLMcode::BadHandle);
        assert_eq!(multi, Err(CURLMcode::BadHandle));

        let url: UrlResult<u8> = Err(CURLUcode::BadScheme);
        assert_eq!(url, Err(CURLUcode::BadScheme));

        let header: HeaderResult<u8> = Err(CURLHcode::Missing);
        assert_eq!(header, Err(CURLHcode::Missing));

        let share: ShareResult<u8> = Err(CURLSHcode::InUse);
        assert_eq!(share, Err(CURLSHcode::InUse));

        // `into_result` already produces the aliased type, with no conversion.
        let ok: CodeResult<()> = CURLcode::Ok.into_result();
        assert_eq!(ok, Ok(()));
        let failed: CodeResult<()> = CURLcode::WriteError.into_result();
        assert_eq!(failed, Err(CURLcode::WriteError));
    }
}
