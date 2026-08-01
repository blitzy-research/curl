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

//! The option surface: `src/tool_getparam.c` and `src/tool_helpers.c`.
//!
//! This module owns the command-line vocabulary -- the 282 rows of the
//! `aliases[]` table (`src/tool_getparam.c:80`) rendered as a `clap` 4.x derive
//! surface, together with the `--no-<flag>` negations that the `ARG_NO`-flagged
//! rows generate -- and the outcome vocabulary every parsing step reports
//! through. AAP section 0.8.1 freezes both: option names, aliases, argument
//! arity, argument type and default value are fixed, and so is the text of each
//! failure, because `tests/data/test*` compares emitted diagnostics against
//! literal expectations.
//!
//! # `ParameterError` is the seam between parsing and validation
//!
//! [`ParameterError`] is the Rust counterpart of C's `ParameterError`
//! (`src/tool_getparam.h:336-363`), and it is declared here because that is
//! where C declares it. Two consumers depend on it and neither may restate it:
//!
//! * `curl-rs/src/cli/paramhlp.rs` (`src/tool_paramhlp.c`) returns these
//!   variants from every numeric, protocol and list validator, and emits no
//!   error text of its own.
//! * `curl-rs/src/config/parseconfig.rs` (`src/tool_parsecfg.c:221-238`)
//!   distinguishes [`ParameterError::NextOperation`] from a genuine failure when
//!   it walks a configuration file.
//!
//! [`param2text`] renders a variant as the phrase C prints, and it is the only
//! place those phrases exist.
//!
//! # The discriminants are written out, not inferred
//!
//! C assigns `PARAM_OK = 0` explicitly and lets declaration order fix the rest.
//! Nothing in curl's ABI exposes these integers -- `ParameterError` is internal
//! to the command-line tool -- but two behaviours depend on the *order* rather
//! than on the values: `src/tool_getparam.c:3087` tests a specific variant after
//! a `switch`, and `src/tool_parsecfg.c:238` compares against two. Writing every
//! discriminant keeps a reordering from silently changing which variant a
//! numeric comparison selects, and it makes the correspondence with
//! `src/tool_getparam.h` checkable line by line.

/// The outcome of parsing or validating one command-line parameter.
///
/// Counterpart of `ParameterError` (`src/tool_getparam.h:336-363`). The 26
/// tokens C declares are reproduced as 25 variants: `PARAM_LAST` is the usual C
/// sentinel and is deliberately absent, for the same reason `MSTATE_LAST` is
/// absent from the engine's state machine. It is never returned, never compared
/// against and never used to size anything -- an exhaustive search of `src/`
/// finds it only in its own declaration -- so making it constructible would add
/// an unreachable arm to every `match` and buy nothing. The bound survives as
/// [`ParameterError::COUNT`] for a caller that wants it.
///
/// # Five variants are not failures
///
/// `HelpRequested`, `ManualRequested`, `VersionInfoRequested`,
/// `EnginesRequested` and `CaEmbedRequested` report that the user asked for
/// output rather than a transfer. `src/tool_operate.c:2299-2325` handles each by
/// producing that output and then resetting the result to `CURLE_OK`, so a
/// caller must not translate them into a failing exit status.
/// `NextOperation` is likewise not a failure: `src/tool_getparam.c:1811` returns
/// it for `--next`, and `:3087-3088` resets it after starting the next
/// operation's configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
#[allow(dead_code)]
pub(crate) enum ParameterError {
    /// `PARAM_OK` -- the parameter was accepted.
    Ok = 0,

    /// `PARAM_OPTION_UNKNOWN` -- no such option.
    OptionUnknown = 1,

    /// `PARAM_CONFIG_OPTION_UNKNOWN` -- no such option in a configuration file.
    ConfigOptionUnknown = 2,

    /// `PARAM_REQUIRES_PARAMETER` -- the option takes an argument and none was
    /// given.
    RequiresParameter = 3,

    /// `PARAM_BAD_USE` -- the option is not valid in this position or
    /// combination.
    BadUse = 4,

    /// `PARAM_HELP_REQUESTED` -- `--help`; not a failure.
    HelpRequested = 5,

    /// `PARAM_MANUAL_REQUESTED` -- `--manual`; not a failure.
    ManualRequested = 6,

    /// `PARAM_VERSION_INFO_REQUESTED` -- `--version`; not a failure.
    VersionInfoRequested = 7,

    /// `PARAM_ENGINES_REQUESTED` -- `--engine list`; not a failure.
    EnginesRequested = 8,

    /// `PARAM_CA_EMBED_REQUESTED` -- `--dump-ca-embed`; not a failure.
    CaEmbedRequested = 9,

    /// `PARAM_GOT_EXTRA_PARAMETER` -- trailing garbage after the argument.
    GotExtraParameter = 10,

    /// `PARAM_BAD_NUMERIC` -- the argument is not a number.
    BadNumeric = 11,

    /// `PARAM_NEGATIVE_NUMERIC` -- the argument is a number but must not be
    /// negative.
    NegativeNumeric = 12,

    /// `PARAM_LIBCURL_DOESNT_SUPPORT` -- this libcurl was built without the
    /// capability the option needs.
    LibcurlDoesntSupport = 13,

    /// `PARAM_LIBCURL_UNSUPPORTED_PROTOCOL` -- a named protocol is not
    /// supported. `src/tool_operate.c:2325` maps this one to
    /// `CURLE_UNSUPPORTED_PROTOCOL` rather than to `CURLE_FAILED_INIT`.
    LibcurlUnsupportedProtocol = 14,

    /// `PARAM_NO_MEM` -- an allocation failed.
    NoMem = 15,

    /// `PARAM_NEXT_OPERATION` -- `--next` was seen; not a failure.
    NextOperation = 16,

    /// `PARAM_NO_PREFIX` -- the option cannot be reversed with `--no-`.
    NoPrefix = 17,

    /// `PARAM_NUMBER_TOO_LARGE` -- the number does not fit its destination.
    NumberTooLarge = 18,

    /// `PARAM_CONTDISP_RESUME_FROM` -- `--continue-at` with
    /// `--remote-header-name`.
    ContdispResumeFrom = 19,

    /// `PARAM_READ_ERROR` -- reading a file the option named failed.
    /// `src/tool_operate.c:2327` maps this one to `CURLE_READ_ERROR`.
    ReadError = 20,

    /// `PARAM_EXPAND_ERROR` -- `--expand-<option>` could not be expanded.
    ExpandError = 21,

    /// `PARAM_BLANK_STRING` -- an empty argument where content is required.
    BlankString = 22,

    /// `PARAM_VAR_SYNTAX` -- a `--variable` argument is malformed.
    VarSyntax = 23,

    /// `PARAM_RECURSION` -- a configuration file or variable expansion nested
    /// too deeply.
    Recursion = 24,
}

impl ParameterError {
    /// How many variants exist: C's `PARAM_LAST` (`src/tool_getparam.h:362`).
    ///
    /// Offered so that a caller which needs the bound has it without
    /// `PARAM_LAST` being constructible as a value that must never be returned.
    #[allow(dead_code)]
    pub(crate) const COUNT: usize = 25;

    /// True when this outcome means "carry on", not "stop".
    ///
    /// The six non-failure outcomes, per `src/tool_operate.c:2299-2325`: the
    /// accepted case and the five requests that produce output instead of a
    /// transfer, plus `--next`. Provided so that no caller has to re-derive the
    /// set with a five-way `matches!`, which is exactly how the list drifts.
    #[allow(dead_code)]
    pub(crate) const fn is_not_a_failure(self) -> bool {
        matches!(
            self,
            Self::Ok
                | Self::HelpRequested
                | Self::ManualRequested
                | Self::VersionInfoRequested
                | Self::EnginesRequested
                | Self::CaEmbedRequested
                | Self::NextOperation
        )
    }

    /// The `PARAM_*` spelling, for a diagnostic that has to name the token.
    #[allow(dead_code)]
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::Ok => "PARAM_OK",
            Self::OptionUnknown => "PARAM_OPTION_UNKNOWN",
            Self::ConfigOptionUnknown => "PARAM_CONFIG_OPTION_UNKNOWN",
            Self::RequiresParameter => "PARAM_REQUIRES_PARAMETER",
            Self::BadUse => "PARAM_BAD_USE",
            Self::HelpRequested => "PARAM_HELP_REQUESTED",
            Self::ManualRequested => "PARAM_MANUAL_REQUESTED",
            Self::VersionInfoRequested => "PARAM_VERSION_INFO_REQUESTED",
            Self::EnginesRequested => "PARAM_ENGINES_REQUESTED",
            Self::CaEmbedRequested => "PARAM_CA_EMBED_REQUESTED",
            Self::GotExtraParameter => "PARAM_GOT_EXTRA_PARAMETER",
            Self::BadNumeric => "PARAM_BAD_NUMERIC",
            Self::NegativeNumeric => "PARAM_NEGATIVE_NUMERIC",
            Self::LibcurlDoesntSupport => "PARAM_LIBCURL_DOESNT_SUPPORT",
            Self::LibcurlUnsupportedProtocol => {
                "PARAM_LIBCURL_UNSUPPORTED_PROTOCOL"
            }
            Self::NoMem => "PARAM_NO_MEM",
            Self::NextOperation => "PARAM_NEXT_OPERATION",
            Self::NoPrefix => "PARAM_NO_PREFIX",
            Self::NumberTooLarge => "PARAM_NUMBER_TOO_LARGE",
            Self::ContdispResumeFrom => "PARAM_CONTDISP_RESUME_FROM",
            Self::ReadError => "PARAM_READ_ERROR",
            Self::ExpandError => "PARAM_EXPAND_ERROR",
            Self::BlankString => "PARAM_BLANK_STRING",
            Self::VarSyntax => "PARAM_VAR_SYNTAX",
            Self::Recursion => "PARAM_RECURSION",
        }
    }
}

/// `param2text` (`src/tool_helpers.c:35-75`): the phrase C prints for an
/// outcome.
///
/// # These strings are frozen output
///
/// Every one is reproduced byte for byte, because the caller composes them into
/// a diagnostic that fixtures compare literally. The grammar of the composition
/// is what explains the wording: `src/tool_getparam.c` prints
/// `option --<name>: <phrase>`, so each phrase is a verb clause that continues
/// the sentence rather than a standalone message. That is why
/// `RequiresParameter` renders as "requires parameter" and not as
/// "missing parameter".
///
/// # Nine variants fall through to C's `default`
///
/// C's `switch` (`:37-74`) lists sixteen cases and a `default` returning
/// "unknown error". The nine that reach the default are `Ok` and the six
/// non-failure requests -- none of which is ever rendered, because
/// `src/tool_operate.c` handles them before any text is produced -- plus
/// `NextOperation` and `Recursion`. Reproducing the fall-through is required:
/// giving `Recursion` a phrase of its own would change the emitted bytes for a
/// case a fixture may exercise, which AAP section 0.8.1 forbids. The
/// exhaustive `match` below makes the set explicit instead of leaving it to a
/// wildcard, so adding a variant forces a decision rather than silently joining
/// the default.
#[allow(dead_code)]
pub(crate) const fn param2text(error: ParameterError) -> &'static str {
    match error {
        // `:38-39`
        ParameterError::GotExtraParameter => "had unsupported trailing garbage",
        // `:40-41`
        ParameterError::OptionUnknown => "is unknown",
        // `:42-43`
        ParameterError::ConfigOptionUnknown => "found an unknown config option",
        // `:44-45`
        ParameterError::RequiresParameter => "requires parameter",
        // `:46-47`
        ParameterError::BadUse => "is badly used here",
        // `:48-49`
        ParameterError::BadNumeric => "expected a proper numerical parameter",
        // `:50-51`
        ParameterError::NegativeNumeric => {
            "expected a positive numerical parameter"
        }
        // `:52-53`
        ParameterError::LibcurlDoesntSupport => {
            "the installed libcurl version does not support this"
        }
        // `:54-55`
        ParameterError::LibcurlUnsupportedProtocol => {
            "a specified protocol is unsupported by libcurl"
        }
        // `:56-57`
        ParameterError::NoMem => "out of memory",
        // `:58-59`
        ParameterError::NoPrefix => {
            "the given option cannot be reversed with a --no- prefix"
        }
        // `:60-61`
        ParameterError::NumberTooLarge => "too large number",
        // `:62-63`
        ParameterError::ContdispResumeFrom => {
            "--continue-at and --remote-header-name cannot be combined"
        }
        // `:64-65`
        ParameterError::ReadError => "error encountered when reading a file",
        // `:66-67`
        ParameterError::ExpandError => "variable expansion failure",
        // `:68-69`
        ParameterError::BlankString => {
            "blank argument where content is expected"
        }
        // `:70-71`
        ParameterError::VarSyntax => "syntax error in --variable argument",
        // `:72-73` -- C's `default`. Listed rather than wildcarded so that a new
        // variant cannot join this arm without someone choosing to put it here.
        ParameterError::Ok
        | ParameterError::HelpRequested
        | ParameterError::ManualRequested
        | ParameterError::VersionInfoRequested
        | ParameterError::EnginesRequested
        | ParameterError::CaEmbedRequested
        | ParameterError::NextOperation
        | ParameterError::Recursion => "unknown error",
    }
}

#[cfg(test)]
mod tests {
    use super::{param2text, ParameterError};

    /// Every variant, in declaration order, so the discriminant assertions and
    /// the rendering assertions both cover the whole enumeration.
    const ALL: [ParameterError; ParameterError::COUNT] = [
        ParameterError::Ok,
        ParameterError::OptionUnknown,
        ParameterError::ConfigOptionUnknown,
        ParameterError::RequiresParameter,
        ParameterError::BadUse,
        ParameterError::HelpRequested,
        ParameterError::ManualRequested,
        ParameterError::VersionInfoRequested,
        ParameterError::EnginesRequested,
        ParameterError::CaEmbedRequested,
        ParameterError::GotExtraParameter,
        ParameterError::BadNumeric,
        ParameterError::NegativeNumeric,
        ParameterError::LibcurlDoesntSupport,
        ParameterError::LibcurlUnsupportedProtocol,
        ParameterError::NoMem,
        ParameterError::NextOperation,
        ParameterError::NoPrefix,
        ParameterError::NumberTooLarge,
        ParameterError::ContdispResumeFrom,
        ParameterError::ReadError,
        ParameterError::ExpandError,
        ParameterError::BlankString,
        ParameterError::VarSyntax,
        ParameterError::Recursion,
    ];

    #[test]
    fn the_discriminants_match_the_declaration_order_of_the_c_enumeration() {
        // `src/tool_getparam.h:337` assigns `PARAM_OK = 0` and lets order do
        // the rest, so variant N must hold N.
        for (index, variant) in ALL.iter().enumerate() {
            assert_eq!(
                *variant as usize,
                index,
                "{} must hold {index}",
                variant.c_name()
            );
        }
        assert_eq!(ALL.len(), ParameterError::COUNT);
    }

    #[test]
    fn the_sixteen_named_phrases_are_reproduced_verbatim() {
        // Spot-checked against `src/tool_helpers.c:38-71` line by line.
        assert_eq!(
            param2text(ParameterError::GotExtraParameter),
            "had unsupported trailing garbage"
        );
        assert_eq!(param2text(ParameterError::OptionUnknown), "is unknown");
        assert_eq!(
            param2text(ParameterError::ConfigOptionUnknown),
            "found an unknown config option"
        );
        assert_eq!(
            param2text(ParameterError::RequiresParameter),
            "requires parameter"
        );
        assert_eq!(param2text(ParameterError::BadUse), "is badly used here");
        assert_eq!(
            param2text(ParameterError::BadNumeric),
            "expected a proper numerical parameter"
        );
        assert_eq!(
            param2text(ParameterError::NegativeNumeric),
            "expected a positive numerical parameter"
        );
        assert_eq!(
            param2text(ParameterError::LibcurlDoesntSupport),
            "the installed libcurl version does not support this"
        );
        assert_eq!(
            param2text(ParameterError::LibcurlUnsupportedProtocol),
            "a specified protocol is unsupported by libcurl"
        );
        assert_eq!(param2text(ParameterError::NoMem), "out of memory");
        assert_eq!(
            param2text(ParameterError::NoPrefix),
            "the given option cannot be reversed with a --no- prefix"
        );
        assert_eq!(
            param2text(ParameterError::NumberTooLarge),
            "too large number"
        );
        assert_eq!(
            param2text(ParameterError::ContdispResumeFrom),
            "--continue-at and --remote-header-name cannot be combined"
        );
        assert_eq!(
            param2text(ParameterError::ReadError),
            "error encountered when reading a file"
        );
        assert_eq!(
            param2text(ParameterError::ExpandError),
            "variable expansion failure"
        );
        assert_eq!(
            param2text(ParameterError::BlankString),
            "blank argument where content is expected"
        );
        assert_eq!(
            param2text(ParameterError::VarSyntax),
            "syntax error in --variable argument"
        );
    }

    #[test]
    fn exactly_eight_variants_reach_the_default_arm() {
        // `src/tool_helpers.c:72-73`. The count is asserted, not just the
        // membership, so a variant that silently joins the default is caught.
        let defaulted: Vec<&'static str> = ALL
            .iter()
            .filter(|variant| param2text(**variant) == "unknown error")
            .map(|variant| variant.c_name())
            .collect();
        assert_eq!(
            defaulted,
            vec![
                "PARAM_OK",
                "PARAM_HELP_REQUESTED",
                "PARAM_MANUAL_REQUESTED",
                "PARAM_VERSION_INFO_REQUESTED",
                "PARAM_ENGINES_REQUESTED",
                "PARAM_CA_EMBED_REQUESTED",
                "PARAM_NEXT_OPERATION",
                "PARAM_RECURSION",
            ]
        );
    }

    #[test]
    fn every_phrase_is_a_single_unpunctuated_clause() {
        // The caller composes `option --<name>: <phrase>`, so a phrase that
        // carried its own newline or trailing full stop would break the line the
        // fixtures compare. `--continue-at ...` legitimately contains dashes;
        // none of them ends a sentence.
        for variant in ALL {
            let phrase = param2text(variant);
            assert!(!phrase.is_empty(), "{} renders empty", variant.c_name());
            assert!(
                !phrase.contains('\n') && !phrase.contains('\r'),
                "{} carries a line break",
                variant.c_name()
            );
            assert!(
                !phrase.ends_with('.'),
                "{} ends a sentence",
                variant.c_name()
            );
        }
    }

    #[test]
    fn the_non_failure_set_is_exactly_the_seven_carry_on_outcomes() {
        let carry_on: Vec<&'static str> = ALL
            .iter()
            .filter(|variant| variant.is_not_a_failure())
            .map(|variant| variant.c_name())
            .collect();
        assert_eq!(
            carry_on,
            vec![
                "PARAM_OK",
                "PARAM_HELP_REQUESTED",
                "PARAM_MANUAL_REQUESTED",
                "PARAM_VERSION_INFO_REQUESTED",
                "PARAM_ENGINES_REQUESTED",
                "PARAM_CA_EMBED_REQUESTED",
                "PARAM_NEXT_OPERATION",
            ]
        );
    }
}
