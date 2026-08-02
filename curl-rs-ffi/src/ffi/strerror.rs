// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The four exported result-code-to-text functions -- supersedes the public
//! half of `lib/strerror.c`.
//!
//! Line numbers in the "Defined" column below are `lib/strerror.c`.
//!
//! | Symbol | Defined | Declared | Family |
//! |---|---|---|---|
//! | `curl_easy_strerror` | `:34` | `curl.h:3232` | `CURLcode` |
//! | `curl_multi_strerror` | `:326` | `multi.h:272` | `CURLMcode` |
//! | `curl_share_strerror` | `:385` | `curl.h:3243` | `CURLSHcode` |
//! | `curl_url_strerror` | `:420` | `urlapi.h:149` | `CURLUcode` |
//!
//! # Why four different prefixes share one module
//!
//! Because DEFINITION LOCATION is not DECLARATION LOCATION. The four names
//! belong to four different symbol families and are declared across three
//! different public headers, but `lib/strerror.c` defines all four in ONE
//! translation unit. The partition follows the definition: this module owns
//! them, and `easy`, `multi`, `share` and `url` each own their family LESS
//! its strerror member -- 18 rather than 21, 21 rather than 22, 3 rather
//! than 4, and 5 rather than 6. That subtraction is what makes the twelve
//! modules' counts sum to the 100 names in `lib/libcurl.def` rather than to
//! 106; the crate root tabulates the whole partition and its arithmetic.
//! The definitions are NOT moved to match their declaring headers.
//!
//! # Where the message text lives, and why not here
//!
//! Not one message literal appears in this file. Each function is a call to
//! the engine's `message_for_c` for that family, plus a pointer return.
//!
//! The text lives in `curl-rs-lib/src/error.rs`, where one `result_code!`
//! invocation per family declares each enumerator, its pinned integer, its C
//! spelling and its message TOGETHER. That single declaration is what makes
//! the two tables impossible to desynchronise: adding an enumerator without
//! a message does not compile. This is precisely the protection the C author
//! bought with `gcc -Wall -Werror`, and he says so --
//! `lib/strerror.c:303-316` records that the switch is written out longhand
//! so that a missing enumerant is a build failure rather than a silent
//! fall-through. A second table of NUL-terminated copies here would be a
//! mirrored source of truth, and mirrored tables drift.
//!
//! The four families surfaced here hold 158 messages between them -- 103
//! `CURLcode`, 15 `CURLMcode`, 7 `CURLSHcode` and 33 `CURLUcode` -- reached
//! through 142 explicit `case` labels in the C, plus the two distinct
//! fallback strings described below. Those counts are asserted rather than
//! merely claimed; see `the_c_switches_reconcile_with_the_enumerations`.
//!
//! Nothing was missing from the engine's public surface, so there is no
//! absent re-export to report: `curl-rs-lib/src/lib.rs` re-exports all four
//! families at its crate root, and this module reaches for no private path
//! and adds no blanket re-export of its own.
//!
//! # The returned pointer is immortal, and the caller never frees it
//!
//! All four return `const char *` into STATIC storage. The C contract is
//! that the caller does not free it, and consumers hand the result straight
//! to `printf("%s")`. The engine's `message_c` builds each `&'static CStr`
//! with `concat!` at COMPILE time, so the pointer returned here addresses
//! immutable read-only data that outlives every handle and costs nothing to
//! produce. There is consequently no `CString`, no heap allocation and no
//! `Box::into_raw` anywhere in this file: a pointer into any of those would
//! dangle the instant the temporary dropped, and that is this module's
//! single highest-risk property.
//!
//! # The four fallbacks are NOT the same string
//!
//! This is the detail one shared "unknown" constant would get wrong. Read
//! from the C, and separately confirmed by running the shipped library over
//! every input from -2 past each family's bound:
//!
//! ```text
//! curl_easy_strerror  -> "Unknown error"       lib/strerror.c:317
//! curl_multi_strerror -> "Unknown error"       lib/strerror.c:376
//! curl_share_strerror -> "CURLSHcode unknown"  lib/strerror.c:411
//! curl_url_strerror   -> "CURLUcode unknown"   lib/strerror.c:524
//! ```
//!
//! Two are generic and two are family-named. Recorded here because a sibling
//! specification for `curl-rs-lib/src/error.rs` stated `"Unknown error"` for
//! the `CURLUcode` family: the C says `"CURLUcode unknown"` at `:524`, the
//! measurement wins, and the engine's `CURLUcode::UNKNOWN_MESSAGE` is in
//! fact correct as written. The contradiction is reported rather than
//! quietly reconciled, so that a reader who later meets the other document
//! knows which of the two was checked against the tree.
//!
//! # Every match is exhaustive, and no arm is a wildcard
//!
//! The C switches are not uniform either, and the asymmetry is load-bearing:
//!
//! | Function | Explicit `case` labels | Terminator |
//! |---|---|---|
//! | `curl_easy_strerror` | 87 | `default:` at `:301` |
//! | `curl_multi_strerror` | 15 | `case CURLM_LAST: break;` |
//! | `curl_share_strerror` | 7 | `case CURLSHE_LAST: break;` |
//! | `curl_url_strerror` | 33 | `case CURLUE_LAST: break;` |
//!
//! ONLY `curl_easy_strerror` has a `default:` arm. It is at `:301`, and the
//! `return "Unknown error";` it falls through to is at `:317`. The other
//! three are exhaustive over their whole enumeration and end in a bare
//! `break`. The easy function's `default:` is not laziness either: it
//! absorbs exactly the 15 retired `CURLE_OBSOLETE*` placeholders and the
//! `CURL_LAST` bound, which reconciles the switch with the enumeration --
//!
//! > 87 explicit cases + 15 `CURLE_OBSOLETE*` + 1 `CURL_LAST` = 103
//!
//! -- exactly the `CURLcode` token count, and a second structural proof that
//! `super::codes`' enumeration is complete.
//!
//! The Rust side reproduces the `-Wall -Werror` property with an EXHAUSTIVE
//! `match` carrying NO wildcard arm. `message_c` in
//! `curl-rs-lib/src/error.rs` matches on `self`, so every one of the 103
//! `CURLcode`, 15 `CURLMcode`, 7 `CURLSHcode` and 33 `CURLUcode` variants is
//! named -- the placeholders and the four `*_LAST` bounds included, each
//! carrying the literal its family's fallback would have produced. Only an
//! integer naming NO enumerator reaches the fallback constant, by way of
//! `from_i32` returning `None`. Adding a variant without a message therefore
//! fails the build, which is the whole point of writing it out.
//!
//! # `CURLVERBOSE` is defined by default, so the text is unconditional
//!
//! All four C functions are wrapped in `#ifdef CURLVERBOSE` (`:36`, `:328`,
//! `:387`, `:422`), with a two-branch `"No error"` / `"Error"` fallback in
//! the `#else`. `CURLVERBOSE` is defined BY DEFAULT, at
//! `lib/curl_setup.h:1597`; it is suppressed only by
//! `CURL_DISABLE_VERBOSE_STRINGS`, and only where C99 variadic macros are
//! available. No Cargo feature in this workspace corresponds to that macro,
//! so there is nothing here to gate on: the full text is compiled
//! UNCONDITIONALLY, the two-branch fallback is not reproduced at all, and
//! `--no-default-features` still exports all four symbols with every message
//! intact.
//!
//! # Signature shape, and why these four headers are not generated
//!
//! The frozen prototypes take the enumerated type by value through an
//! UNNAMED parameter, and the unnamedness is ABI-visible rather than
//! cosmetic: `.github/scripts/verify-synopsis.pl` compiles manual-page
//! synopses against the public header and rewrites `, parameter);` into
//! `, ...);` as it does so, a transformation that acts directly on
//! unnamed-parameter synopses.
//!
//! ```c
//! CURL_EXTERN const char *curl_easy_strerror(CURLcode);
//! CURL_EXTERN const char *curl_multi_strerror(CURLMcode);
//! CURL_EXTERN const char *curl_share_strerror(CURLSHcode);
//! CURL_EXTERN const char *curl_url_strerror(CURLUcode);
//! ```
//!
//! Each Rust parameter is nevertheless a `c_int` and NOT the matching
//! `#[repr(C)]` enum from `super::codes`. A C caller may legally pass any
//! integer of the enum's underlying type -- the shipped library answers for
//! -2, and 16 of the 103 `CURLcode` values are positions a caller can hold
//! that no arm returns -- and materialising a value with no enumerator in a
//! Rust enum parameter is an invalid value for that type. Accepting `c_int`
//! and resolving it through a total lookup is the only shape that is sound
//! for every input C can produce.
//!
//! Those two facts do not meet, so the declarations for these four are not
//! generated. cbindgen has no directive that spells a parameter as an enum
//! while the Rust type is an integer -- measured: it emitted `int error` --
//! so all four are excluded in `cbindgen.toml` ("Group 5e", reason 1) and
//! `build.rs` carries the frozen declaration verbatim instead, at `:2369`,
//! `:1138`, `:2372` and `:1234`. Both the enum spelling and the unnamed
//! parameter survive because that declaration is never regenerated.
//!
//! # Panic containment: the fallback is text, never NULL
//!
//! Every entry point runs inside `super::panic_boundary::guard`, the crate's
//! single `catch_unwind` helper, and each passes its OWN family's
//! `UNKNOWN_MESSAGE_C` as the recovery value. The `guard_const_ptr`
//! convenience is deliberately NOT used here: it recovers with a null
//! pointer, which is right for an entry point that has a documented failure
//! return and wrong for these four, whose C contract has none. A consumer
//! writing `printf("%s", curl_easy_strerror(rc))` would dereference that
//! null.
//!
//! None of these bodies can panic -- each is a `match` over a `const` table
//! followed by `as_ptr` -- but the guard is applied uniformly rather than
//! case by case, because unwinding across the C ABI is undefined behaviour
//! and "this one cannot panic" stops being true the moment a body changes.
//! The recovery value is a plain pointer the caller computes, so the
//! recovery path is incapable of the fault it recovers from.
//!
//! # Evidence
//!
//! Two independent differential oracles, neither of them hand-written.
//! `every_message_matches_lib_strerror_c` parses THIS TREE's
//! `lib/strerror.c` and checks all 142 arms, both fallbacks and all four
//! switch shapes against what a C caller actually receives.
//! `every_row_matches_the_frozen_c_library` replays a 177-row transcript
//! taken from the shipped library.

use core::ffi::{c_char, c_int};

use curl_rs_lib::{CURLMcode, CURLSHcode, CURLUcode, CURLcode};

use super::panic_boundary::guard;

/// Turns a `CURLcode` into the equivalent human-readable error string.
///
/// Supersedes `curl_easy_strerror` (`lib/strerror.c:34`, declared at
/// `curl.h:3232`).
///
/// `error` is a `c_int` rather than the enumeration because C may pass any
/// integer; the engine's lookup is total, so a value naming no enumerator
/// yields `"Unknown error"` (`lib/strerror.c:317`), as do the 15 retired
/// `CURLE_OBSOLETE*` placeholders and the `CURL_LAST` bound.
///
/// The returned pointer addresses immortal static text. It is never NULL,
/// the caller must not free it, and it stays valid for the life of the
/// process -- which is what the C contract promises.
#[no_mangle]
pub extern "C" fn curl_easy_strerror(error: c_int) -> *const c_char {
    guard(CURLcode::UNKNOWN_MESSAGE_C.as_ptr(), || {
        CURLcode::message_for_c(error).as_ptr()
    })
}

/// Turns a `CURLMcode` into the equivalent human-readable error string.
///
/// Supersedes `curl_multi_strerror` (`lib/strerror.c:326`, declared at
/// `multi.h:272`). The C switch is exhaustive over all 15 enumerators and
/// ends in `case CURLM_LAST: break;`, so both `CURLM_LAST` and any integer
/// outside the enumeration yield `"Unknown error"` (`lib/strerror.c:376`).
///
/// The returned pointer is static, never NULL, and never freed by the
/// caller.
#[no_mangle]
pub extern "C" fn curl_multi_strerror(error: c_int) -> *const c_char {
    guard(CURLMcode::UNKNOWN_MESSAGE_C.as_ptr(), || {
        CURLMcode::message_for_c(error).as_ptr()
    })
}

/// Turns a `CURLSHcode` into the equivalent human-readable error string.
///
/// Supersedes `curl_share_strerror` (`lib/strerror.c:385`, declared in the
/// share block of `curl.h:3243`). Its fallback is NOT the one the two
/// functions above use: `CURLSHE_LAST` and every integer outside the
/// enumeration yield `"CURLSHcode unknown"` (`lib/strerror.c:411`).
///
/// The returned pointer is static, never NULL, and never freed by the
/// caller.
#[no_mangle]
pub extern "C" fn curl_share_strerror(error: c_int) -> *const c_char {
    guard(CURLSHcode::UNKNOWN_MESSAGE_C.as_ptr(), || {
        CURLSHcode::message_for_c(error).as_ptr()
    })
}

/// Turns a `CURLUcode` into the equivalent human-readable error string.
///
/// Supersedes `curl_url_strerror` (`lib/strerror.c:420`, declared at
/// `urlapi.h:149`). Its fallback is family-named too: `CURLUE_LAST` and
/// every integer outside the enumeration yield `"CURLUcode unknown"`
/// (`lib/strerror.c:524`).
///
/// The returned pointer is static, never NULL, and never freed by the
/// caller.
#[no_mangle]
pub extern "C" fn curl_url_strerror(error: c_int) -> *const c_char {
    guard(CURLUcode::UNKNOWN_MESSAGE_C.as_ptr(), || {
        CURLUcode::message_for_c(error).as_ptr()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::CStr;

    /// Reads back exactly what a C caller would see.
    fn text(ptr: *const c_char) -> &'static str {
        assert!(!ptr.is_null(), "these four never return NULL");
        // SAFETY: every one of the four functions returns either
        // `message_c().as_ptr()` or `UNKNOWN_MESSAGE_C.as_ptr()`, and both
        // are `&'static CStr` values that `concat!` builds at compile time,
        // so the target is NUL-terminated, immutable and immortal. This is
        // the only `unsafe` in the file, and it exists only under
        // `#[cfg(test)]`: the four exported bodies contain none.
        unsafe { CStr::from_ptr(ptr) }
            .to_str()
            .expect("the message tables are ASCII")
    }

    /// `C spelling -> pinned integer` for every member of one family, taken
    /// from the engine's own `VARIANTS` and `c_name`.
    ///
    /// Deliberately derived rather than written out: a literal table here
    /// would be the mirrored source of truth this module exists to avoid.
    macro_rules! name_to_value {
        ($family:ty) => {{
            let mut map = BTreeMap::new();
            for code in <$family>::VARIANTS {
                assert!(
                    map.insert(code.c_name(), code.as_i32()).is_none(),
                    "a family may not spell two enumerators the same"
                );
            }
            map
        }};
    }

    // -- The primary oracle: this tree's own `lib/strerror.c`. ------------
    //
    // Specification 0.1.1 makes the C tree "the executable specification",
    // so the strongest available check is to parse it and compare. The
    // include is resolved relative to THIS file, so it names the repository
    // root's `lib/strerror.c`; `printf.rs` reaches into `include/curl/` the
    // same way.

    /// `lib/strerror.c`, verbatim, at compile time.
    const C_SOURCE: &str = include_str!("../../../lib/strerror.c");

    /// One C `switch` reduced to what this module has to reproduce.
    struct CSwitch {
        /// Every `case` label in source order, paired with the literal its
        /// arm returns, or `None` where the arm is a bare `break`.
        arms: Vec<(String, Option<String>)>,
        /// Whether the switch carries a `default:` label.
        has_default: bool,
        /// The literal returned once the switch has fallen through.
        fallback: String,
    }

    /// `text` with C comments removed and string literals left intact.
    ///
    /// String awareness is not decorative: two messages contain `//` inside
    /// the literal -- `"Could not read a file:// file"` and
    /// `"Bad file:// URL"` -- and a naive split on `//` truncates both.
    /// Newlines inside a block comment are preserved so that the
    /// line-oriented walk below stays aligned with the source.
    fn strip_comments(text: &str) -> String {
        let source: Vec<char> = text.chars().collect();
        let mut out = String::with_capacity(text.len());
        let mut index = 0;
        let mut in_string = false;
        while index < source.len() {
            let ch = source[index];
            if in_string {
                out.push(ch);
                if ch == '"' {
                    in_string = false;
                }
                index += 1;
                continue;
            }
            if ch == '"' {
                in_string = true;
                out.push(ch);
                index += 1;
                continue;
            }
            if ch == '/' && source.get(index + 1) == Some(&'*') {
                index += 2;
                while index < source.len()
                    && !(source[index] == '*'
                        && source.get(index + 1) == Some(&'/'))
                {
                    if source[index] == '\n' {
                        out.push('\n');
                    }
                    index += 1;
                }
                index += 2;
                continue;
            }
            if ch == '/' && source.get(index + 1) == Some(&'/') {
                while index < source.len() && source[index] != '\n' {
                    index += 1;
                }
                continue;
            }
            out.push(ch);
            index += 1;
        }
        out
    }

    /// The `#ifdef CURLVERBOSE` branch of one exported C function, with
    /// comments removed.
    ///
    /// The `#else` branch is excluded on purpose. `CURLVERBOSE` is defined by
    /// default (`lib/curl_setup.h:1597`), so the verbose branch is the one
    /// this crate reproduces; the two-branch `"No error"` / `"Error"`
    /// fallback is unreachable in a default build and is not implemented.
    fn verbose_branch(function: &str) -> String {
        let signature = format!("const char *{function}(");
        let start = C_SOURCE.find(&signature).unwrap_or_else(|| {
            panic!("lib/strerror.c must still define {function}")
        });
        let body = &C_SOURCE[start..];
        let open = body
            .find("#ifdef CURLVERBOSE")
            .unwrap_or_else(|| panic!("{function} must be verbose-gated"));
        let close = body[open..]
            .find("\n#else")
            .unwrap_or_else(|| panic!("{function} must have an #else"));
        strip_comments(&body[open..open + close])
    }

    /// Every string literal in one C statement, spliced as the compiler
    /// splices adjoining literals.
    ///
    /// Escape sequences are returned as written rather than interpreted,
    /// which is sound only because there are none;
    /// `the_c_switches_contain_no_escape_sequences` asserts that rather than
    /// leaving it as an assumption.
    fn joined_literals(statement: &str) -> String {
        let mut out = String::new();
        let mut in_string = false;
        for ch in statement.chars() {
            if in_string {
                if ch == '"' {
                    in_string = false;
                } else {
                    out.push(ch);
                }
            } else if ch == '"' {
                in_string = true;
            }
        }
        out
    }

    /// Parses one of the four C functions into a [`CSwitch`].
    fn parse(function: &str) -> CSwitch {
        let branch = verbose_branch(function);
        let mut arms = Vec::new();
        let mut has_default = false;
        let mut pending: Vec<String> = Vec::new();
        let mut fallback = None;
        let mut statement = String::new();

        for line in branch.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if !statement.is_empty() {
                // The continuation of a `return` whose literal spans two
                // lines. `CURLE_NOT_BUILT_IN` is the only one that does.
                statement.push(' ');
                statement.push_str(trimmed);
            } else if let Some(label) = trimmed.strip_prefix("case ") {
                pending.push(label.trim_end_matches(':').trim().to_owned());
                continue;
            } else if trimmed == "default:" {
                has_default = true;
                pending.push("default".to_owned());
                continue;
            } else if trimmed == "break;" {
                assert!(!pending.is_empty(), "a break needs a label above it");
                for label in pending.drain(..) {
                    arms.push((label, None));
                }
                continue;
            } else if trimmed.starts_with("return ") {
                statement.push_str(trimmed);
            } else {
                // `#ifdef CURLVERBOSE`, `switch(error) {` and the closing
                // brace are the only other lines the branch contains.
                continue;
            }
            if statement.ends_with(';') {
                let literal = joined_literals(&statement);
                if pending.is_empty() {
                    assert!(
                        fallback.is_none(),
                        "{function} may fall through to one string only"
                    );
                    fallback = Some(literal);
                } else {
                    for label in pending.drain(..) {
                        arms.push((label, Some(literal.clone())));
                    }
                }
                statement.clear();
            }
        }

        assert!(pending.is_empty(), "{function} left a label unresolved");
        assert!(statement.is_empty(), "{function} left a statement open");
        CSwitch {
            arms,
            has_default,
            fallback: fallback
                .unwrap_or_else(|| panic!("{function} needs a fallback")),
        }
    }

    /// Compares one family's whole C switch with what a C caller receives.
    ///
    /// Returns the number of explicit `case` labels, so the caller can
    /// reconcile the four totals against the 142 the C tree contains.
    macro_rules! check_family {
        ($family:ty, $function:ident, $labels:literal, $default:literal) => {{
            let parsed = parse(stringify!($function));
            assert_eq!(
                parsed.has_default,
                $default,
                "{}: presence of a default: arm",
                stringify!($function)
            );
            assert_eq!(
                parsed.fallback,
                <$family>::UNKNOWN_MESSAGE,
                "{}: the string it falls through to",
                stringify!($function)
            );
            let values = name_to_value!($family);
            let mut labels = 0usize;
            for (label, message) in &parsed.arms {
                if label == "default" {
                    continue;
                }
                labels += 1;
                let value = *values.get(label.as_str()).unwrap_or_else(|| {
                    panic!("the engine does not enumerate {label}")
                });
                // A bare `break` arm falls through to the fallback, which is
                // how `CURLM_LAST`, `CURLSHE_LAST` and `CURLUE_LAST` behave.
                let expected =
                    message.as_deref().unwrap_or(<$family>::UNKNOWN_MESSAGE);
                assert_eq!(
                    text($function(value)),
                    expected,
                    "{}({label} = {value})",
                    stringify!($function)
                );
            }
            assert_eq!(
                labels,
                $labels,
                "{}: explicit case labels",
                stringify!($function)
            );
            labels
        }};
    }

    /// The C source's literals contain no escape sequence, which is what
    /// makes [`joined_literals`] correct rather than merely adequate.
    #[test]
    fn the_c_switches_contain_no_escape_sequences() {
        for function in [
            "curl_easy_strerror",
            "curl_multi_strerror",
            "curl_share_strerror",
            "curl_url_strerror",
        ] {
            assert!(
                !verbose_branch(function).contains('\\'),
                "{function} gained an escape; joined_literals must interpret it"
            );
        }
    }

    /// THE primary oracle. Every arm of every switch in this tree's
    /// `lib/strerror.c`, compared against the bytes a C caller gets.
    ///
    /// Nothing here is transcribed, so a divergence means the crate
    /// disagrees with the repository's own C rather than with somebody's
    /// reading of it. This is the mechanical form of the requirement that
    /// every message be reproduced character for character.
    #[test]
    fn every_message_matches_lib_strerror_c() {
        let easy = check_family!(CURLcode, curl_easy_strerror, 87, true);
        let multi = check_family!(CURLMcode, curl_multi_strerror, 15, false);
        let share = check_family!(CURLSHcode, curl_share_strerror, 7, false);
        let url = check_family!(CURLUcode, curl_url_strerror, 33, false);
        assert_eq!(
            easy + multi + share + url,
            142,
            "the four switches carry 142 explicit case labels between them"
        );
    }

    /// The reconciliation that proves `super::codes`' enumerations are whole.
    ///
    /// > 87 explicit cases + 15 `CURLE_OBSOLETE*` + 1 `CURL_LAST` = 103
    ///
    /// The other three switches need no such arithmetic: they are exhaustive
    /// over their enumerations already, which is why only the easy function
    /// has a `default:` arm at all.
    #[test]
    fn the_c_switches_reconcile_with_the_enumerations() {
        let easy = parse("curl_easy_strerror");
        let explicit = easy
            .arms
            .iter()
            .filter(|(label, _)| label != "default")
            .count();
        let obsolete = CURLcode::VARIANTS
            .iter()
            .filter(|code| code.c_name().starts_with("CURLE_OBSOLETE"))
            .count();

        assert_eq!(explicit, 87, "explicit cases in curl_easy_strerror");
        assert_eq!(obsolete, 15, "retired CURLE_OBSOLETE* placeholders");
        assert_eq!(
            explicit + obsolete + 1,
            CURLcode::VARIANTS.len(),
            "the switch plus the placeholders plus CURL_LAST is the whole"
        );
        assert_eq!(CURLcode::VARIANTS.len(), 103, "CURLcode tokens");
        assert_eq!(CURLMcode::VARIANTS.len(), 15, "CURLMcode tokens");
        assert_eq!(CURLSHcode::VARIANTS.len(), 7, "CURLSHcode tokens");
        assert_eq!(CURLUcode::VARIANTS.len(), 33, "CURLUcode tokens");
        assert_eq!(
            CURLcode::VARIANTS.len()
                + CURLMcode::VARIANTS.len()
                + CURLSHcode::VARIANTS.len()
                + CURLUcode::VARIANTS.len(),
            158,
            "the message count this module's documentation states"
        );
    }

    // -- The secondary oracle: the shipped library's own answers. ---------

    /// The 177-row transcript of the shipped `libcurl.so.4`, produced by a C
    /// program that called each of the four functions over every input from
    /// -2 up past each family's bound. Rows are `family value message`, the
    /// families being `E`, `M`, `S` and `U` in the order the table at the top
    /// of this file lists them.
    ///
    /// A second ORACLE, independent of the source parse above: one checks
    /// this crate against the C the repository contains, the other against
    /// the C a consumer has already linked.
    const C_ORACLE: &str = include_str!("strerror_oracle.txt");

    #[test]
    fn every_row_matches_the_frozen_c_library() {
        let mut rows = 0usize;
        for line in C_ORACLE.lines() {
            if line.is_empty() {
                continue;
            }
            let (family, rest) = line.split_at(1);
            let mut parts = rest.trim_start().splitn(2, '\t');
            let value: c_int = parts
                .next()
                .expect("each row starts with a value")
                .parse()
                .expect("the value column is an integer");
            let expected = parts.next().expect("each row carries a message");
            let got = match family {
                "E" => text(curl_easy_strerror(value)),
                "M" => text(curl_multi_strerror(value)),
                "S" => text(curl_share_strerror(value)),
                "U" => text(curl_url_strerror(value)),
                other => panic!("unknown family column {other:?}"),
            };
            assert_eq!(
                got, expected,
                "{family} {value}: C said {expected:?} and this says {got:?}"
            );
            rows += 1;
        }
        assert_eq!(rows, 177, "the oracle transcript must be complete");
    }

    /// The four fallbacks are two distinct strings, and pairing them wrongly
    /// is the mistake a single shared constant would make. Asserted directly
    /// so the intent survives even if both oracles are regenerated.
    #[test]
    fn the_four_fallbacks_are_not_interchangeable() {
        assert_eq!(text(curl_easy_strerror(-2)), "Unknown error");
        assert_eq!(text(curl_multi_strerror(-2)), "Unknown error");
        assert_eq!(text(curl_share_strerror(-2)), "CURLSHcode unknown");
        assert_eq!(text(curl_url_strerror(-2)), "CURLUcode unknown");
        assert_ne!(
            text(curl_share_strerror(-2)),
            text(curl_easy_strerror(-2)),
            "the share family is family-named, not generic"
        );
        assert_ne!(
            text(curl_url_strerror(-2)),
            text(curl_share_strerror(-2)),
            "and the two family-named fallbacks differ from each other"
        );
    }

    /// The 15 retired placeholders and the four family bounds report the
    /// fallback rather than a message, exactly as the C arms do.
    #[test]
    fn the_retired_placeholders_and_the_bounds_report_the_fallback() {
        for obsolete in
            [20, 24, 29, 32, 34, 40, 41, 44, 46, 50, 51, 57, 62, 75, 76]
        {
            assert_eq!(
                text(curl_easy_strerror(obsolete)),
                "Unknown error",
                "CURLE_OBSOLETE{obsolete} must not carry a message"
            );
        }
        assert_eq!(text(curl_easy_strerror(102)), "Unknown error", "CURL_LAST");
        assert_eq!(
            text(curl_multi_strerror(13)),
            "Unknown error",
            "CURLM_LAST"
        );
        assert_eq!(
            text(curl_share_strerror(6)),
            "CURLSHcode unknown",
            "CURLSHE_LAST"
        );
        assert_eq!(
            text(curl_url_strerror(32)),
            "CURLUcode unknown",
            "CURLUE_LAST"
        );
    }

    /// A sanity anchor on the success codes, the values a consumer sees most
    /// and the only ones all four families agree about.
    #[test]
    fn zero_is_no_error_in_all_four_families() {
        assert_eq!(text(curl_easy_strerror(0)), "No error");
        assert_eq!(text(curl_multi_strerror(0)), "No error");
        assert_eq!(text(curl_share_strerror(0)), "No error");
        assert_eq!(text(curl_url_strerror(0)), "No error");
    }

    /// The messages a user sees when certificate validation fails.
    ///
    /// Pinned separately from the oracles because these four are the ones
    /// that must stay legible: softening or dropping one would make a TLS
    /// failure harder to diagnose than it is in curl 8.x, and validation is
    /// on by default.
    #[test]
    fn the_tls_failure_messages_are_reproduced_exactly() {
        assert_eq!(text(curl_easy_strerror(35)), "SSL connect error");
        assert_eq!(
            text(curl_easy_strerror(60)),
            "SSL peer certificate or SSH remote key was not OK"
        );
        assert_eq!(
            text(curl_easy_strerror(77)),
            "Problem with the SSL CA cert (path? access rights?)"
        );
        assert_eq!(
            text(curl_easy_strerror(90)),
            "SSL public key does not match pinned public key"
        );
        assert_eq!(
            text(curl_easy_strerror(91)),
            "SSL server certificate status verification FAILED"
        );
    }

    /// No input produces a null pointer, because the C contract has no
    /// failure return and consumers pass the result to `printf("%s")`.
    ///
    /// The sweep covers every enumerated value, the gaps between them, both
    /// extremes of the parameter's range and the negatives, which together
    /// are everything a C caller can hand over.
    #[test]
    fn no_input_produces_a_null_pointer() {
        let mut probes: Vec<c_int> =
            vec![c_int::MIN, c_int::MAX, -1, -2, -1000];
        probes.extend(-8..=200);
        for value in probes {
            for got in [
                curl_easy_strerror(value),
                curl_multi_strerror(value),
                curl_share_strerror(value),
                curl_url_strerror(value),
            ] {
                assert!(!got.is_null(), "a null answer for {value}");
                // Reading it proves the target is genuinely NUL-terminated
                // rather than merely non-null.
                assert!(!text(got).is_empty(), "an empty answer for {value}");
            }
        }
    }

    /// The returned storage is `'static`: the same pointer comes back every
    /// time, and it still reads correctly after unrelated calls.
    ///
    /// Pointer identity is the part that matters. A `CString` or any other
    /// allocation would hand out a fresh address per call and would already
    /// have been freed by the time the caller looked at it.
    #[test]
    fn the_returned_pointers_are_static_and_never_reallocated() {
        const EXPECTED: &str = "SSL peer certificate or SSH remote key was \
                                not OK";
        let first = curl_easy_strerror(60);
        assert_eq!(text(first), EXPECTED);

        for value in [0, 1, 27, 77, 90, 102, -1] {
            let _ = curl_easy_strerror(value);
            let _ = curl_multi_strerror(value);
            let _ = curl_share_strerror(value);
            let _ = curl_url_strerror(value);
        }

        assert_eq!(text(first), EXPECTED, "the first pointer still reads");
        assert_eq!(
            first,
            curl_easy_strerror(60),
            "static storage returns one address, not a fresh allocation"
        );
    }

    /// A contained panic recovers with the family's own fallback text.
    ///
    /// The four bodies cannot panic -- each is a `match` over a `const`
    /// table -- so the recovery value is exercised here by handing the same
    /// `guard` a body that does. What this rules out is the null recovery
    /// that `guard_const_ptr` would have installed.
    #[test]
    fn a_contained_panic_yields_the_family_default_and_not_null() {
        let easy: *const c_char =
            guard(CURLcode::UNKNOWN_MESSAGE_C.as_ptr(), || panic!("contained"));
        let multi: *const c_char =
            guard(CURLMcode::UNKNOWN_MESSAGE_C.as_ptr(), || {
                panic!("contained")
            });
        let share: *const c_char =
            guard(CURLSHcode::UNKNOWN_MESSAGE_C.as_ptr(), || {
                panic!("contained")
            });
        let url: *const c_char =
            guard(CURLUcode::UNKNOWN_MESSAGE_C.as_ptr(), || {
                panic!("contained")
            });

        assert_eq!(text(easy), "Unknown error");
        assert_eq!(text(multi), "Unknown error");
        assert_eq!(text(share), "CURLSHcode unknown");
        assert_eq!(text(url), "CURLUcode unknown");
    }

    /// The prohibitions this module is held to, checked against its own
    /// source rather than trusted.
    ///
    /// Only the half above `#[cfg(test)]` is examined, and only its code:
    /// every comment in that half is a whole-line `//`, `///` or `//!`, so
    /// dropping such lines leaves exactly what the compiler sees.
    #[test]
    fn the_exported_half_carries_no_wildcard_no_cfg_and_no_unsafe() {
        let source = include_str!("strerror.rs");
        let exported = source
            .split("#[cfg(test)]")
            .next()
            .expect("the file has an exported half");
        let code: String = exported
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        assert_eq!(
            code.matches("#[no_mangle]").count(),
            4,
            "exactly four exported symbols live in this module"
        );
        for name in [
            "curl_easy_strerror",
            "curl_multi_strerror",
            "curl_share_strerror",
            "curl_url_strerror",
        ] {
            let definition = format!("pub extern \"C\" fn {name}(");
            assert_eq!(
                code.matches(definition.as_str()).count(),
                1,
                "{name} must be defined exactly once"
            );
        }
        for forbidden in [
            "_ =>",
            "#[cfg(",
            "CString",
            "into_raw",
            "null",
            "unsafe",
            "guard_const_ptr",
        ] {
            assert!(
                !code.contains(forbidden),
                "the exported half must not contain {forbidden:?}"
            );
        }
    }
}
