// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The option surface: `src/tool_getparam.c` with `src/tool_helpers.c`.
//!
//! This module owns the command-line vocabulary of curl 8.19.0-DEV -- the 282
//! rows of the `aliases[]` table (`src/tool_getparam.c:80`), the 282 dispatch
//! keys of `cmdline_t` (`src/tool_getparam.h:32-314`), the parser that walks a
//! command line through them, and the outcome vocabulary every parsing step
//! reports through. AAP section 0.8.1 freezes all of it: "Names, aliases,
//! argument arity, argument type, and default value are frozen for all 282
//! alias rows", and so is the text of each diagnostic, because
//! `tests/data/test*` compares emitted bytes against literal expectations.
//!
//! Nothing here may be added to, renamed or re-defaulted. Where `clap` cannot
//! express a curl behaviour, the behaviour wins and `clap` is driven or
//! bypassed to match; every such place is marked below and at its call site.
//!
//! # `ARG_BOOL` and `ARG_NO` are different things, and the difference is 115
//! options wide
//!
//! The two masks are easy to conflate and the consequence is large:
//!
//! * `ARG_BOOL 1` means "accepts a `--no-[name]` prefix"
//!   (`src/tool_getparam.h:317`). `src/tool_getparam.c:2950` rejects `--no-` on
//!   anything else with `PARAM_NO_PREFIX`, so **every one of the 115 `ARG_BOOL`
//!   rows accepts `--no-<name>` and none of the other 167 does**. The long-form
//!   surface is therefore 282 + 115 = 397 spellings.
//! * `ARG_NO 0x80` means "the option is documented as `--no-*`"
//!   (`src/tool_getparam.h:327`) and does something entirely different: at
//!   `src/tool_getparam.c:2989`, **inside the short-option branch only**,
//!   `toggle = !(a->desc & ARG_NO)` makes the *short* form of those six rows
//!   default to off. The six are `alpn`, `buffer`, `clobber`, `keepalive`,
//!   `progress-meter` and `sessionid`.
//!
//! Both sets are derived from [`ALIASES`] at use time rather than restated, and
//! [`mod tests`](self) asserts the counts so a hand-edited row cannot drift.
//!
//! # `--help` is dispatched from inside the parser
//!
//! `src/tool_getparam.c:3001-3005` calls `tool_help()` and *then* returns
//! `PARAM_HELP_REQUESTED`; `src/tool_operate.c:2302-2304` receives that code
//! and does nothing with it. The output therefore has to be produced here, not
//! by the caller, and [`ParseHost::help`] is the seam that produces it -- see
//! GAP #4 on that method for why it is injected rather than called directly.
//!
//! # Two C file-scope `static` variables become owned state
//!
//! * `static size_t verbose_nopts` (`src/tool_getparam.c:1511`) is reset at
//!   `:2904`, incremented at `:3042` and read at `:1526`, which is what makes
//!   `-vvv` accumulate *within* one argv element and reset *between* elements.
//!   It is a field of [`ParseState`], threaded explicitly. AAP section 0.1.2
//!   removes the shared-mutable-state design this file's C original leans on,
//!   so it is neither a `static mut` nor an atomic.
//! * `findshortopt`'s lazily-built `static const struct LongShort
//!   *singles[128 - ' ']` with its `static bool singles_done` latch
//!   (`src/tool_getparam.c:828-845`) becomes a bounds-checked scan of
//!   [`ALIASES`] in [`findshortopt`]. Performance is a non-goal (AAP section
//!   0.1.1: "Where a choice exists between a faster design and a more
//!   behaviourally faithful one, faithfulness wins"), and the scan needs no
//!   mutable state at all.
//!
//! # Where `clap` is bypassed, and why
//!
//! [`ClapSurface`] renders the frozen inventory as a `clap` 4.x derive, which
//! is what AAP section 0.8.3 asks for: "clap 4.x, derived 1:1 from the curl 8.x
//! long-option inventory". It is the declarative record of the surface and the
//! source of the completion and usage data. It is **not** the parser, because
//! `clap` implements none of the following and each one is observable:
//!
//! | Behaviour | Anchor |
//! |---|---|
//! | the `--expand-<name>` argument-expansion prefix | `:2922-2926`, `:2955-2974` |
//! | `--no-<name>` over 115 booleans, `PARAM_NO_PREFIX` for the other 167 | `:2916-2921`, `:2950-2954` |
//! | `-vvv` accumulating as a "super-boolean" within one element | `:1513-1567` |
//! | `-ofoo`: one option swallowing the rest of a short cluster | `:2997-3000` |
//! | the `=` split bounded at `MAX_OPTION_LEN`, which suppresses argument consumption | `:2928-2941` |
//! | the `ARG_TLS` runtime capability gate | `:2991-2994` |
//! | `ARG_DEPR` warn-and-stop, applying nothing | `:1723-1726`, `:3014-3017` |
//! | `ARG_CLEAR` argv wiping | `:626-637` |
//! | `--next` starting a fresh operation | `:1810-1811`, `:3087-3110` |
//! | a bare argument becoming `--url` with a recursion budget of zero | `:3119` |
//!
//! [`getparameter`] and [`parse_args`] therefore reproduce
//! `src/tool_getparam.c:2888-3149` directly, clause for clause.
//!
//! # The reported name is `curl`
//!
//! `src/tool_version.h:28` defines `CURL_NAME "curl"` and
//! `src/tool_msgs.c:32` defines `ERROR_PREFIX "curl: "`. The Cargo package is
//! named `curl-rs` and its binary target is named `curl`, so package metadata
//! and `argv[0]` are both wrong answers to "what am I called": the first would
//! print `curl-rs: ` and the second whatever the invoker chose. Neither
//! `CARGO_PKG_NAME`, `CARGO_BIN_NAME` nor `argv[0]` is read here; the prefix
//! comes from [`crate::output::msgs`], which owns those bytes.
//!
//! # Arguments are bytes
//!
//! [`parse_args`] takes `OsString` values and works on their bytes.
//! `std::env::args` panics on an argument that is not valid Unicode, and curl
//! accepts one: `src/tool_getparam.c:3061` passes `argv[i]` through
//! `convert_tchar_to_UTF8`, a shim that is the identity outside Windows, and
//! every one of the four targets AAP section 0.1.1 names is Linux or macOS. A
//! filename, a header value or a POST body may hold arbitrary bytes, so the
//! parser must not require them to be UTF-8. Option *names* are compared as
//! bytes too, which is what `strcmp` does.
//!
//! # GAPs
//!
//! Five capabilities this port needs have no module among this file's declared
//! dependencies (GAPs #1 to #5, one per [`ParseHost`] method), one cannot exist
//! in safe Rust at all (GAP #0, `cleanarg`), and three rows of the frozen table
//! configure fields that `curl-rs/src/config/mod.rs` does not declare (GAP #6).
//! None is worked around silently: each is a `GAP #n` note on the method, the
//! function or the rows that stand in for it, and every one is reachable by the
//! caller that owns the missing half.

use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use clap::{ArgAction, Parser};

use crate::cli::libinfo::LibInfo;
use crate::cli::paramhlp::{
    add2list, check_protocol, delegation, file2memory, file2string,
    ftpcccmethod, ftpfilemethod, new_getout, oct2nummax, proto2num, secs2ms,
    str2num, str2offset, str2tls_max, str2unum, str2unummax, ByteSource,
    GetOutSeq, NewGetOut, UrlList,
};
use crate::cli::vars::{setvariable, varexpand, VarDiag, VarHost};
use crate::config::{
    ClobberMode, FailMode, GlobalConfig, HttpReq, OperationConfig, TraceType,
};
use crate::output::formparse::{formparse, FormDiag, StdinAccess};
use crate::output::msgs::{
    errorf, helpf, notef, warnf, DiagnosticSink, MsgConfig,
};

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
#[allow(dead_code)] // The variant set is C's, not this port's: `Recursion` is
                    // declared by `src/tool_getparam.h:359` and returned
                    // nowhere in `src/`, so it is constructed only by the tests.
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
    #[allow(dead_code)] // The bound `PARAM_LAST` names; no dispatch path reads
                        // it, and the cross-checks below size `ALL` with it.
    pub(crate) const COUNT: usize = 25;

    /// True when this outcome means "carry on", not "stop".
    ///
    /// The six non-failure outcomes, per `src/tool_operate.c:2299-2325`: the
    /// accepted case and the five requests that produce output instead of a
    /// transfer, plus `--next`. Provided so that no caller has to re-derive the
    /// set with a five-way `matches!`, which is exactly how the list drifts.
    #[allow(dead_code)] // The classifier the operation driver
                        // (`src/tool_operate.c:2299-2325`) needs; that module is
                        // not among this file's declared dependencies yet.
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
    #[allow(dead_code)] // Diagnostic and test surface; no frozen message
                        // interpolates a token name, so nothing else calls it.
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
#[allow(dead_code)] // Called by `parse_args` at the report step; the attribute
                    // predates that caller and is kept so the item stays
                    // warning-free under any feature combination.
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

// ---------------------------------------------------------------------------
// The `desc` vocabulary -- `src/tool_getparam.h:316-327`
// ---------------------------------------------------------------------------

/// `ARG_NONE 0` -- "stand-alone but not a boolean" (`src/tool_getparam.h:316`).
///
/// Twenty rows carry it. They take no argument and no `--no-` form, and
/// [`opt_none`] dispatches them.
pub(crate) const ARG_NONE: u8 = 0;

/// `ARG_BOOL 1` -- "accepts a `--no-[name]` prefix"
/// (`src/tool_getparam.h:317`).
///
/// One hundred and fifteen rows carry it, and that count *is* the `--no-`
/// surface; see the module documentation for why this is not `ARG_NO`.
pub(crate) const ARG_BOOL: u8 = 1;

/// `ARG_STRG 2` -- "requires an argument" (`src/tool_getparam.h:318`).
///
/// One hundred and twenty-two rows carry it. [`opt_string`] dispatches them.
pub(crate) const ARG_STRG: u8 = 2;

/// `ARG_FILE 3` -- "requires an argument, usually a filename"
/// (`src/tool_getparam.h:319`).
///
/// Twenty-five rows carry it. [`opt_file`] dispatches them, and the shared
/// preamble at `src/tool_getparam.c:2227-2230` warns when the argument looks
/// like a flag.
pub(crate) const ARG_FILE: u8 = 3;

/// `ARG_TYPEMASK 0x03` -- `src/tool_getparam.h:321`.
const ARG_TYPEMASK: u8 = 0x03;

/// `ARG_DEPR 0x10` -- "deprecated option" (`src/tool_getparam.h:324`).
///
/// Nine rows carry it. [`opt_depr`] warns and the option is **not** applied.
pub(crate) const ARG_DEPR: u8 = 0x10;

/// `ARG_CLEAR 0x20` -- "clear cmdline argument" (`src/tool_getparam.h:325`).
///
/// Eleven rows carry it, all of them credential-bearing. See [`cleanarg`].
pub(crate) const ARG_CLEAR: u8 = 0x20;

/// `ARG_TLS 0x40` -- "requires TLS support" (`src/tool_getparam.h:326`).
///
/// Sixty-one rows carry it, `--dump-ca-embed` among them
/// (`src/tool_getparam.c:128`). The gate at `:2991` turns a missing TLS
/// capability into [`ParameterError::LibcurlDoesntSupport`] before the option
/// is looked at any further.
pub(crate) const ARG_TLS: u8 = 0x40;

/// `ARG_NO 0x80` -- "set if the option is documented as `--no-*`"
/// (`src/tool_getparam.h:327`).
///
/// Six rows carry it. It inverts the *short* form's default toggle at
/// `src/tool_getparam.c:2989` and has no effect on the long form.
pub(crate) const ARG_NO: u8 = 0x80;

/// `ARGTYPE(x)` -- `src/tool_getparam.h:322`.
///
/// The two low bits of `desc`, which select which of the four dispatch
/// functions handles the row.
#[allow(dead_code)] // Used by every dispatch path; see the module note on
                    // per-item allowances while callers are still arriving.
pub(crate) const fn argtype(desc: u8) -> u8 {
    desc & ARG_TYPEMASK
}

// ---------------------------------------------------------------------------
// Frozen limits
// ---------------------------------------------------------------------------

/// `MAX_OPTION_LEN 26` -- `src/tool_getparam.c:2886`, "the longest command
/// line option, excluding the leading --".
///
/// It bounds the name half of a `--name=value` split (`:2930`). A name longer
/// than this is not split at all: the whole word, `=` and value included, goes
/// to [`findlongopt`] and fails to match, which is what C does when
/// `curlx_str_until` reports the segment as over-long.
pub(crate) const MAX_OPTION_LEN: usize = 26;

/// `CONFIG_MAX_LEVELS 5` -- `src/tool_parsecfg.h:29`, "only allow this many
/// levels of recursive --config use".
pub(crate) const CONFIG_MAX_LEVELS: i32 = 5;

/// `MAX_DATAURLENCODE (500 * 1024 * 1024)` -- `src/tool_getparam.c:641`, "the
/// maximum size we allow the dynbuf generated string".
pub(crate) const MAX_DATAURLENCODE: usize = 500 * 1024 * 1024;

/// `MAX_QUERY_LEN 100000` -- `src/tool_getparam.c:894`, with the C comment
/// "larger is not likely to ever work".
pub(crate) const MAX_QUERY_LEN: usize = 100_000;

/// `MAX_PARALLEL 65535` -- `src/tool_main.h:33`.
pub(crate) const MAX_PARALLEL: i64 = 65535;

/// `PARALLEL_DEFAULT 50` -- `src/tool_main.h:34`.
pub(crate) const PARALLEL_DEFAULT: i64 = 50;

/// `MAX_PARALLEL_HOST 65535` -- `src/tool_main.h:36`.
pub(crate) const MAX_PARALLEL_HOST: i64 = 65535;

/// `PARALLEL_HOST_DEFAULT 0` -- `src/tool_main.h:37`, "means not used".
pub(crate) const PARALLEL_HOST_DEFAULT: i64 = 0;

/// `ALLOW_BLANK TRUE` -- `src/tool_getparam.c:41`.
const ALLOW_BLANK: bool = true;

/// `DENY_BLANK FALSE` -- `src/tool_getparam.c:42`.
const DENY_BLANK: bool = false;

// ---------------------------------------------------------------------------
// Public libcurl constants used by the dispatch switches
// ---------------------------------------------------------------------------
//
// Declared here with their header line rather than imported: `curl-rs-ffi`
// owns the generated ABI and this crate must not depend on it (it links no
// library and exports no symbol), so the value is restated with the citation
// that pins it. `curl-rs/src/cli/paramhlp.rs:275` sets the same precedent for
// `CURLFTPSSL_CCC_PASSIVE`.

/// `CURLAUTH_BASIC` -- `include/curl/curl.h:829`.
const CURLAUTH_BASIC: u64 = 1 << 0;
/// `CURLAUTH_DIGEST` -- `include/curl/curl.h:830`.
const CURLAUTH_DIGEST: u64 = 1 << 1;
/// `CURLAUTH_NEGOTIATE` -- `include/curl/curl.h:831`. `CURLAUTH_GSSAPI` is an
/// alias for it (`:835`), which is why `--socks5-gssapi` sets this bit.
const CURLAUTH_NEGOTIATE: u64 = 1 << 2;
/// `CURLAUTH_NTLM` -- `include/curl/curl.h:836`.
const CURLAUTH_NTLM: u64 = 1 << 3;
/// `CURLAUTH_DIGEST_IE` -- `include/curl/curl.h:837`. Never set by an option;
/// present because `CURLAUTH_ANY` is defined by excluding it.
const CURLAUTH_DIGEST_IE: u64 = 1 << 4;
/// `CURLAUTH_BEARER` -- `include/curl/curl.h:842`.
const CURLAUTH_BEARER: u64 = 1 << 6;
/// `CURLAUTH_AWS_SIGV4` -- `include/curl/curl.h:843`.
const CURLAUTH_AWS_SIGV4: u64 = 1 << 7;
/// `CURLAUTH_ANY` -- `include/curl/curl.h:845`,
/// `((~CURLAUTH_DIGEST_IE) & 0xffffffff)`.
const CURLAUTH_ANY: u64 = (!CURLAUTH_DIGEST_IE) & 0xffff_ffff;
/// `CURLAUTH_GSSAPI` -- `include/curl/curl.h:835`, an alias of
/// `CURLAUTH_NEGOTIATE`.
const CURLAUTH_GSSAPI: u64 = CURLAUTH_NEGOTIATE;

/// `CURLPROXY_HTTP` -- `include/curl/curl.h:790`.
const CURLPROXY_HTTP: i64 = 0;
/// `CURLPROXY_HTTP_1_0` -- `include/curl/curl.h:792`.
const CURLPROXY_HTTP_1_0: i64 = 1;
/// `CURLPROXY_HTTPS` -- `include/curl/curl.h:794`.
const CURLPROXY_HTTPS: i64 = 2;
/// `CURLPROXY_HTTPS2` -- `include/curl/curl.h:796`.
const CURLPROXY_HTTPS2: i64 = 3;
/// `CURLPROXY_SOCKS4` -- `include/curl/curl.h:798`.
const CURLPROXY_SOCKS4: i64 = 4;
/// `CURLPROXY_SOCKS5` -- `include/curl/curl.h:800`.
const CURLPROXY_SOCKS5: i64 = 5;
/// `CURLPROXY_SOCKS4A` -- `include/curl/curl.h:801`.
const CURLPROXY_SOCKS4A: i64 = 6;
/// `CURLPROXY_SOCKS5_HOSTNAME` -- `include/curl/curl.h:802`.
const CURLPROXY_SOCKS5_HOSTNAME: i64 = 7;

/// `CURL_HTTP_VERSION_1_0` -- `include/curl/curl.h:2312`.
const CURL_HTTP_VERSION_1_0: i64 = 1;
/// `CURL_HTTP_VERSION_1_1` -- `include/curl/curl.h:2313`.
const CURL_HTTP_VERSION_1_1: i64 = 2;
/// `CURL_HTTP_VERSION_2_0` -- `include/curl/curl.h:2314`.
const CURL_HTTP_VERSION_2_0: i64 = 3;
/// `CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE` -- `include/curl/curl.h:2317`.
const CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE: i64 = 5;
/// `CURL_HTTP_VERSION_3` -- `include/curl/curl.h:2319`.
const CURL_HTTP_VERSION_3: i64 = 30;
/// `CURL_HTTP_VERSION_3ONLY` -- `include/curl/curl.h:2323`.
const CURL_HTTP_VERSION_3ONLY: i64 = 31;

/// `CURL_IPRESOLVE_V4` -- `include/curl/curl.h:2302`.
const CURL_IPRESOLVE_V4: i64 = 1;
/// `CURL_IPRESOLVE_V6` -- `include/curl/curl.h:2303`.
const CURL_IPRESOLVE_V6: i64 = 2;

/// `CURL_SSLVERSION_TLSv1` -- `include/curl/curl.h:2366`.
const CURL_SSLVERSION_TLSV1: i64 = 1;

/// `CURL_TIMECOND_NONE` -- `include/curl/curl.h:2407`.
const CURL_TIMECOND_NONE: u64 = 0;
/// `CURL_TIMECOND_IFMODSINCE` -- `include/curl/curl.h:2408`.
const CURL_TIMECOND_IFMODSINCE: u64 = 1;
/// `CURL_TIMECOND_IFUNMODSINCE` -- `include/curl/curl.h:2409`.
const CURL_TIMECOND_IFUNMODSINCE: u64 = 2;
/// `CURL_TIMECOND_LASTMOD` -- `include/curl/curl.h:2410`.
const CURL_TIMECOND_LASTMOD: u64 = 3;

/// `CURLFOLLOW_ALL` -- `include/curl/curl.h:179`, "generic follow redirects".
const CURLFOLLOW_ALL: i64 = 1;
/// `CURLFOLLOW_OBEYCODE` -- `include/curl/curl.h:183`.
const CURLFOLLOW_OBEYCODE: i64 = 2;

/// `CURLMIMEOPT_FORMESCAPE` -- `include/curl/curl.h:2432`.
const CURLMIMEOPT_FORMESCAPE: u64 = 1 << 0;

/// `CURLFTPSSL_CCC_PASSIVE` -- `include/curl/curl.h:988`, "Let the server
/// initiate the shutdown".
const CURLFTPSSL_CCC_PASSIVE: i64 = 1;

/// `CURLULFLAG_ANSWERED` -- `include/curl/curl.h:1038`.
const CURLULFLAG_ANSWERED: u8 = 1 << 0;
/// `CURLULFLAG_DELETED` -- `include/curl/curl.h:1039`.
const CURLULFLAG_DELETED: u8 = 1 << 1;
/// `CURLULFLAG_DRAFT` -- `include/curl/curl.h:1040`.
const CURLULFLAG_DRAFT: u8 = 1 << 2;
/// `CURLULFLAG_FLAGGED` -- `include/curl/curl.h:1041`.
const CURLULFLAG_FLAGGED: u8 = 1 << 3;
/// `CURLULFLAG_SEEN` -- `include/curl/curl.h:1042`.
const CURLULFLAG_SEEN: u8 = 1 << 4;

/// `CURL_PROGRESS_STATS 0` -- `src/tool_cb_prg.h:28`, "default progress
/// display".
const CURL_PROGRESS_STATS: i32 = 0;
/// `CURL_PROGRESS_BAR 1` -- `src/tool_cb_prg.h:29`.
const CURL_PROGRESS_BAR: i32 = 1;

/// `CURL_OFF_T_MAX` -- the largest `curl_off_t`, which is `i64` on every target
/// AAP section 0.1.1 names. `src/tool_getparam.c:573` and `:618` compare
/// against it while parsing a size.
const CURL_OFF_T_MAX: i64 = i64::MAX;

// ---------------------------------------------------------------------------
// `cmdline_t` -- `src/tool_getparam.h:31-314`
// ---------------------------------------------------------------------------

/// One dispatch key per command-line option: C's `cmdline_t`.
///
/// The C comment at `src/tool_getparam.h:28-30` gives the naming rule: "The
/// name is the verbatim long option name, but in uppercase with periods and
/// minuses replaced with underscores using a `C_` prefix". The Rust spelling is
/// the same name in upper camel case, with a trailing digit group joined to the
/// word before it so that no variant needs an underscore -- `C_HTTP1_0` becomes
/// `Http10`, `C_TLSV1_2` becomes `Tlsv12`. All 282 spellings stay distinct
/// under that rule, which [`mod tests`](self) asserts.
///
/// # Why the discriminants are written out
///
/// C assigns none of them and lets declaration order fix all 282. Nothing in
/// libcurl's ABI exposes these integers -- `cmdline_t` is internal to the
/// command-line tool -- but the enumeration is a cross-module contract: the help
/// table in the target `curl-rs/src/cli/help.rs` keys its scan off the last
/// entry, and `src/tool_getparam.c` pairs every alias row with exactly one key.
/// Writing each value keeps a reordering from silently changing which option a
/// numeric comparison selects, and makes the correspondence with
/// `src/tool_getparam.h` checkable line by line.
///
/// [`CmdKey::c_name`] recovers the `C_*` spelling for a diagnostic or a test
/// that has to name the token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
#[repr(u16)]
#[allow(dead_code)] // Every variant is reachable through `ALIASES`; the
                    // allowance covers the ones no dispatch arm names yet.
pub(crate) enum CmdKey {
    /// `C_ABSTRACT_UNIX_SOCKET` -- `--abstract-unix-socket`.
    AbstractUnixSocket = 0,
    /// `C_ALPN` -- `--alpn`.
    Alpn = 1,
    /// `C_ALT_SVC` -- `--alt-svc`.
    AltSvc = 2,
    /// `C_ANYAUTH` -- `--anyauth`.
    Anyauth = 3,
    /// `C_APPEND` -- `--append`.
    Append = 4,
    /// `C_AWS_SIGV4` -- `--aws-sigv4`.
    AwsSigv4 = 5,
    /// `C_BASIC` -- `--basic`.
    Basic = 6,
    /// `C_BUFFER` -- `--buffer`.
    Buffer = 7,
    /// `C_CA_NATIVE` -- `--ca-native`.
    CaNative = 8,
    /// `C_CACERT` -- `--cacert`.
    Cacert = 9,
    /// `C_CAPATH` -- `--capath`.
    Capath = 10,
    /// `C_CERT` -- `--cert`.
    Cert = 11,
    /// `C_CERT_STATUS` -- `--cert-status`.
    CertStatus = 12,
    /// `C_CERT_TYPE` -- `--cert-type`.
    CertType = 13,
    /// `C_CIPHERS` -- `--ciphers`.
    Ciphers = 14,
    /// `C_CLOBBER` -- `--clobber`.
    Clobber = 15,
    /// `C_COMPRESSED` -- `--compressed`.
    Compressed = 16,
    /// `C_COMPRESSED_SSH` -- `--compressed-ssh`.
    CompressedSsh = 17,
    /// `C_CONFIG` -- `--config`.
    Config = 18,
    /// `C_CONNECT_TIMEOUT` -- `--connect-timeout`.
    ConnectTimeout = 19,
    /// `C_CONNECT_TO` -- `--connect-to`.
    ConnectTo = 20,
    /// `C_CONTINUE_AT` -- `--continue-at`.
    ContinueAt = 21,
    /// `C_COOKIE` -- `--cookie`.
    Cookie = 22,
    /// `C_COOKIE_JAR` -- `--cookie-jar`.
    CookieJar = 23,
    /// `C_CREATE_DIRS` -- `--create-dirs`.
    CreateDirs = 24,
    /// `C_CREATE_FILE_MODE` -- `--create-file-mode`.
    CreateFileMode = 25,
    /// `C_CRLF` -- `--crlf`.
    Crlf = 26,
    /// `C_CRLFILE` -- `--crlfile`.
    Crlfile = 27,
    /// `C_CURVES` -- `--curves`.
    Curves = 28,
    /// `C_DATA` -- `--data`.
    Data = 29,
    /// `C_DATA_ASCII` -- `--data-ascii`.
    DataAscii = 30,
    /// `C_DATA_BINARY` -- `--data-binary`.
    DataBinary = 31,
    /// `C_DATA_RAW` -- `--data-raw`.
    DataRaw = 32,
    /// `C_DATA_URLENCODE` -- `--data-urlencode`.
    DataUrlencode = 33,
    /// `C_DELEGATION` -- `--delegation`.
    Delegation = 34,
    /// `C_DIGEST` -- `--digest`.
    Digest = 35,
    /// `C_DISABLE` -- `--disable`.
    Disable = 36,
    /// `C_DISABLE_EPRT` -- `--disable-eprt`.
    DisableEprt = 37,
    /// `C_DISABLE_EPSV` -- `--disable-epsv`.
    DisableEpsv = 38,
    /// `C_DISALLOW_USERNAME_IN_URL` -- `--disallow-username-in-url`.
    DisallowUsernameInUrl = 39,
    /// `C_DNS_INTERFACE` -- `--dns-interface`.
    DnsInterface = 40,
    /// `C_DNS_IPV4_ADDR` -- `--dns-ipv4-addr`.
    DnsIpv4Addr = 41,
    /// `C_DNS_IPV6_ADDR` -- `--dns-ipv6-addr`.
    DnsIpv6Addr = 42,
    /// `C_DNS_SERVERS` -- `--dns-servers`.
    DnsServers = 43,
    /// `C_DOH_CERT_STATUS` -- `--doh-cert-status`.
    DohCertStatus = 44,
    /// `C_DOH_INSECURE` -- `--doh-insecure`.
    DohInsecure = 45,
    /// `C_DOH_URL` -- `--doh-url`.
    DohUrl = 46,
    /// `C_DUMP_CA_EMBED` -- `--dump-ca-embed`.
    DumpCaEmbed = 47,
    /// `C_DUMP_HEADER` -- `--dump-header`.
    DumpHeader = 48,
    /// `C_ECH` -- `--ech`.
    Ech = 49,
    /// `C_EGD_FILE` -- `--egd-file`.
    EgdFile = 50,
    /// `C_ENGINE` -- `--engine`.
    Engine = 51,
    /// `C_EPRT` -- `--eprt`.
    Eprt = 52,
    /// `C_EPSV` -- `--epsv`.
    Epsv = 53,
    /// `C_ETAG_COMPARE` -- `--etag-compare`.
    EtagCompare = 54,
    /// `C_ETAG_SAVE` -- `--etag-save`.
    EtagSave = 55,
    /// `C_EXPECT100_TIMEOUT` -- `--expect100-timeout`.
    Expect100Timeout = 56,
    /// `C_FAIL` -- `--fail`.
    Fail = 57,
    /// `C_FAIL_EARLY` -- `--fail-early`.
    FailEarly = 58,
    /// `C_FAIL_WITH_BODY` -- `--fail-with-body`.
    FailWithBody = 59,
    /// `C_FALSE_START` -- `--false-start`.
    FalseStart = 60,
    /// `C_FOLLOW` -- `--follow`.
    Follow = 61,
    /// `C_FORM` -- `--form`.
    Form = 62,
    /// `C_FORM_ESCAPE` -- `--form-escape`.
    FormEscape = 63,
    /// `C_FORM_STRING` -- `--form-string`.
    FormString = 64,
    /// `C_FTP_ACCOUNT` -- `--ftp-account`.
    FtpAccount = 65,
    /// `C_FTP_ALTERNATIVE_TO_USER` -- `--ftp-alternative-to-user`.
    FtpAlternativeToUser = 66,
    /// `C_FTP_CREATE_DIRS` -- `--ftp-create-dirs`.
    FtpCreateDirs = 67,
    /// `C_FTP_METHOD` -- `--ftp-method`.
    FtpMethod = 68,
    /// `C_FTP_PASV` -- `--ftp-pasv`.
    FtpPasv = 69,
    /// `C_FTP_PORT` -- `--ftp-port`.
    FtpPort = 70,
    /// `C_FTP_PRET` -- `--ftp-pret`.
    FtpPret = 71,
    /// `C_FTP_SKIP_PASV_IP` -- `--ftp-skip-pasv-ip`.
    FtpSkipPasvIp = 72,
    /// `C_FTP_SSL` -- `--ftp-ssl`.
    FtpSsl = 73,
    /// `C_FTP_SSL_CCC` -- `--ftp-ssl-ccc`.
    FtpSslCcc = 74,
    /// `C_FTP_SSL_CCC_MODE` -- `--ftp-ssl-ccc-mode`.
    FtpSslCccMode = 75,
    /// `C_FTP_SSL_CONTROL` -- `--ftp-ssl-control`.
    FtpSslControl = 76,
    /// `C_FTP_SSL_REQD` -- `--ftp-ssl-reqd`.
    FtpSslReqd = 77,
    /// `C_GET` -- `--get`.
    Get = 78,
    /// `C_GLOBOFF` -- `--globoff`.
    Globoff = 79,
    /// `C_HAPPY_EYEBALLS_TIMEOUT_MS` -- `--happy-eyeballs-timeout-ms`.
    HappyEyeballsTimeoutMs = 80,
    /// `C_HAPROXY_CLIENTIP` -- `--haproxy-clientip`.
    HaproxyClientip = 81,
    /// `C_HAPROXY_PROTOCOL` -- `--haproxy-protocol`.
    HaproxyProtocol = 82,
    /// `C_HEAD` -- `--head`.
    Head = 83,
    /// `C_HEADER` -- `--header`.
    Header = 84,
    /// `C_HELP` -- `--help`.
    Help = 85,
    /// `C_HOSTPUBMD5` -- `--hostpubmd5`.
    Hostpubmd5 = 86,
    /// `C_HOSTPUBSHA256` -- `--hostpubsha256`.
    Hostpubsha256 = 87,
    /// `C_HSTS` -- `--hsts`.
    Hsts = 88,
    /// `C_HTTP0_9` -- `--http0.9`.
    Http09 = 89,
    /// `C_HTTP1_0` -- `--http1.0`.
    Http10 = 90,
    /// `C_HTTP1_1` -- `--http1.1`.
    Http11 = 91,
    /// `C_HTTP2` -- `--http2`.
    Http2 = 92,
    /// `C_HTTP2_PRIOR_KNOWLEDGE` -- `--http2-prior-knowledge`.
    Http2PriorKnowledge = 93,
    /// `C_HTTP3` -- `--http3`.
    Http3 = 94,
    /// `C_HTTP3_ONLY` -- `--http3-only`.
    Http3Only = 95,
    /// `C_IGNORE_CONTENT_LENGTH` -- `--ignore-content-length`.
    IgnoreContentLength = 96,
    /// `C_INCLUDE` -- `--include`.
    Include = 97,
    /// `C_INSECURE` -- `--insecure`.
    Insecure = 98,
    /// `C_INTERFACE` -- `--interface`.
    Interface = 99,
    /// `C_IP_TOS` -- `--ip-tos`.
    IpTos = 100,
    /// `C_IPFS_GATEWAY` -- `--ipfs-gateway`.
    IpfsGateway = 101,
    /// `C_IPV4` -- `--ipv4`.
    Ipv4 = 102,
    /// `C_IPV6` -- `--ipv6`.
    Ipv6 = 103,
    /// `C_JSON` -- `--json`.
    Json = 104,
    /// `C_JUNK_SESSION_COOKIES` -- `--junk-session-cookies`.
    JunkSessionCookies = 105,
    /// `C_KEEPALIVE` -- `--keepalive`.
    Keepalive = 106,
    /// `C_KEEPALIVE_CNT` -- `--keepalive-cnt`.
    KeepaliveCnt = 107,
    /// `C_KEEPALIVE_TIME` -- `--keepalive-time`.
    KeepaliveTime = 108,
    /// `C_KEY` -- `--key`.
    Key = 109,
    /// `C_KEY_TYPE` -- `--key-type`.
    KeyType = 110,
    /// `C_KNOWNHOSTS` -- `--knownhosts`.
    Knownhosts = 111,
    /// `C_KRB` -- `--krb`.
    Krb = 112,
    /// `C_KRB4` -- `--krb4`.
    Krb4 = 113,
    /// `C_LIBCURL` -- `--libcurl`.
    Libcurl = 114,
    /// `C_LIMIT_RATE` -- `--limit-rate`.
    LimitRate = 115,
    /// `C_LIST_ONLY` -- `--list-only`.
    ListOnly = 116,
    /// `C_LOCAL_PORT` -- `--local-port`.
    LocalPort = 117,
    /// `C_LOCATION` -- `--location`.
    Location = 118,
    /// `C_LOCATION_TRUSTED` -- `--location-trusted`.
    LocationTrusted = 119,
    /// `C_LOGIN_OPTIONS` -- `--login-options`.
    LoginOptions = 120,
    /// `C_MAIL_AUTH` -- `--mail-auth`.
    MailAuth = 121,
    /// `C_MAIL_FROM` -- `--mail-from`.
    MailFrom = 122,
    /// `C_MAIL_RCPT` -- `--mail-rcpt`.
    MailRcpt = 123,
    /// `C_MAIL_RCPT_ALLOWFAILS` -- `--mail-rcpt-allowfails`.
    MailRcptAllowfails = 124,
    /// `C_MANUAL` -- `--manual`.
    Manual = 125,
    /// `C_MAX_FILESIZE` -- `--max-filesize`.
    MaxFilesize = 126,
    /// `C_MAX_REDIRS` -- `--max-redirs`.
    MaxRedirs = 127,
    /// `C_MAX_TIME` -- `--max-time`.
    MaxTime = 128,
    /// `C_METALINK` -- `--metalink`.
    Metalink = 129,
    /// `C_MPTCP` -- `--mptcp`.
    Mptcp = 130,
    /// `C_NEGOTIATE` -- `--negotiate`.
    Negotiate = 131,
    /// `C_NETRC` -- `--netrc`.
    Netrc = 132,
    /// `C_NETRC_FILE` -- `--netrc-file`.
    NetrcFile = 133,
    /// `C_NETRC_OPTIONAL` -- `--netrc-optional`.
    NetrcOptional = 134,
    /// `C_NEXT` -- `--next`.
    Next = 135,
    /// `C_NOPROXY` -- `--noproxy`.
    Noproxy = 136,
    /// `C_NPN` -- `--npn`.
    Npn = 137,
    /// `C_NTLM` -- `--ntlm`.
    Ntlm = 138,
    /// `C_NTLM_WB` -- `--ntlm-wb`.
    NtlmWb = 139,
    /// `C_OAUTH2_BEARER` -- `--oauth2-bearer`.
    Oauth2Bearer = 140,
    /// `C_OUT_NULL` -- `--out-null`.
    OutNull = 141,
    /// `C_OUTPUT` -- `--output`.
    Output = 142,
    /// `C_OUTPUT_DIR` -- `--output-dir`.
    OutputDir = 143,
    /// `C_PARALLEL` -- `--parallel`.
    Parallel = 144,
    /// `C_PARALLEL_IMMEDIATE` -- `--parallel-immediate`.
    ParallelImmediate = 145,
    /// `C_PARALLEL_MAX` -- `--parallel-max`.
    ParallelMax = 146,
    /// `C_PARALLEL_HOST` -- `--parallel-max-host`.
    ParallelHost = 147,
    /// `C_PASS` -- `--pass`.
    Pass = 148,
    /// `C_PATH_AS_IS` -- `--path-as-is`.
    PathAsIs = 149,
    /// `C_PINNEDPUBKEY` -- `--pinnedpubkey`.
    Pinnedpubkey = 150,
    /// `C_POST301` -- `--post301`.
    Post301 = 151,
    /// `C_POST302` -- `--post302`.
    Post302 = 152,
    /// `C_POST303` -- `--post303`.
    Post303 = 153,
    /// `C_PREPROXY` -- `--preproxy`.
    Preproxy = 154,
    /// `C_PROGRESS_BAR` -- `--progress-bar`.
    ProgressBar = 155,
    /// `C_PROGRESS_METER` -- `--progress-meter`.
    ProgressMeter = 156,
    /// `C_PROTO` -- `--proto`.
    Proto = 157,
    /// `C_PROTO_DEFAULT` -- `--proto-default`.
    ProtoDefault = 158,
    /// `C_PROTO_REDIR` -- `--proto-redir`.
    ProtoRedir = 159,
    /// `C_PROXY` -- `--proxy`.
    Proxy = 160,
    /// `C_PROXY_ANYAUTH` -- `--proxy-anyauth`.
    ProxyAnyauth = 161,
    /// `C_PROXY_BASIC` -- `--proxy-basic`.
    ProxyBasic = 162,
    /// `C_PROXY_CA_NATIVE` -- `--proxy-ca-native`.
    ProxyCaNative = 163,
    /// `C_PROXY_CACERT` -- `--proxy-cacert`.
    ProxyCacert = 164,
    /// `C_PROXY_CAPATH` -- `--proxy-capath`.
    ProxyCapath = 165,
    /// `C_PROXY_CERT` -- `--proxy-cert`.
    ProxyCert = 166,
    /// `C_PROXY_CERT_TYPE` -- `--proxy-cert-type`.
    ProxyCertType = 167,
    /// `C_PROXY_CIPHERS` -- `--proxy-ciphers`.
    ProxyCiphers = 168,
    /// `C_PROXY_CRLFILE` -- `--proxy-crlfile`.
    ProxyCrlfile = 169,
    /// `C_PROXY_DIGEST` -- `--proxy-digest`.
    ProxyDigest = 170,
    /// `C_PROXY_HEADER` -- `--proxy-header`.
    ProxyHeader = 171,
    /// `C_PROXY_HTTP2` -- `--proxy-http2`.
    ProxyHttp2 = 172,
    /// `C_PROXY_INSECURE` -- `--proxy-insecure`.
    ProxyInsecure = 173,
    /// `C_PROXY_KEY` -- `--proxy-key`.
    ProxyKey = 174,
    /// `C_PROXY_KEY_TYPE` -- `--proxy-key-type`.
    ProxyKeyType = 175,
    /// `C_PROXY_NEGOTIATE` -- `--proxy-negotiate`.
    ProxyNegotiate = 176,
    /// `C_PROXY_NTLM` -- `--proxy-ntlm`.
    ProxyNtlm = 177,
    /// `C_PROXY_PASS` -- `--proxy-pass`.
    ProxyPass = 178,
    /// `C_PROXY_PINNEDPUBKEY` -- `--proxy-pinnedpubkey`.
    ProxyPinnedpubkey = 179,
    /// `C_PROXY_SERVICE_NAME` -- `--proxy-service-name`.
    ProxyServiceName = 180,
    /// `C_PROXY_SSL_ALLOW_BEAST` -- `--proxy-ssl-allow-beast`.
    ProxySslAllowBeast = 181,
    /// `C_PROXY_SSL_AUTO_CLIENT_CERT` -- `--proxy-ssl-auto-client-cert`.
    ProxySslAutoClientCert = 182,
    /// `C_PROXY_TLS13_CIPHERS` -- `--proxy-tls13-ciphers`.
    ProxyTls13Ciphers = 183,
    /// `C_PROXY_TLSAUTHTYPE` -- `--proxy-tlsauthtype`.
    ProxyTlsauthtype = 184,
    /// `C_PROXY_TLSPASSWORD` -- `--proxy-tlspassword`.
    ProxyTlspassword = 185,
    /// `C_PROXY_TLSUSER` -- `--proxy-tlsuser`.
    ProxyTlsuser = 186,
    /// `C_PROXY_TLSV1` -- `--proxy-tlsv1`.
    ProxyTlsv1 = 187,
    /// `C_PROXY_USER` -- `--proxy-user`.
    ProxyUser = 188,
    /// `C_PROXY1_0` -- `--proxy1.0`.
    Proxy10 = 189,
    /// `C_PROXYTUNNEL` -- `--proxytunnel`.
    Proxytunnel = 190,
    /// `C_PUBKEY` -- `--pubkey`.
    Pubkey = 191,
    /// `C_QUOTE` -- `--quote`.
    Quote = 192,
    /// `C_RANDOM_FILE` -- `--random-file`.
    RandomFile = 193,
    /// `C_RANGE` -- `--range`.
    Range = 194,
    /// `C_RATE` -- `--rate`.
    Rate = 195,
    /// `C_RAW` -- `--raw`.
    Raw = 196,
    /// `C_REFERER` -- `--referer`.
    Referer = 197,
    /// `C_REMOTE_HEADER_NAME` -- `--remote-header-name`.
    RemoteHeaderName = 198,
    /// `C_REMOTE_NAME` -- `--remote-name`.
    RemoteName = 199,
    /// `C_REMOTE_NAME_ALL` -- `--remote-name-all`.
    RemoteNameAll = 200,
    /// `C_REMOTE_TIME` -- `--remote-time`.
    RemoteTime = 201,
    /// `C_REMOVE_ON_ERROR` -- `--remove-on-error`.
    RemoveOnError = 202,
    /// `C_REQUEST` -- `--request`.
    Request = 203,
    /// `C_REQUEST_TARGET` -- `--request-target`.
    RequestTarget = 204,
    /// `C_RESOLVE` -- `--resolve`.
    Resolve = 205,
    /// `C_RETRY` -- `--retry`.
    Retry = 206,
    /// `C_RETRY_ALL_ERRORS` -- `--retry-all-errors`.
    RetryAllErrors = 207,
    /// `C_RETRY_CONNREFUSED` -- `--retry-connrefused`.
    RetryConnrefused = 208,
    /// `C_RETRY_DELAY` -- `--retry-delay`.
    RetryDelay = 209,
    /// `C_RETRY_MAX_TIME` -- `--retry-max-time`.
    RetryMaxTime = 210,
    /// `C_SASL_AUTHZID` -- `--sasl-authzid`.
    SaslAuthzid = 211,
    /// `C_SASL_IR` -- `--sasl-ir`.
    SaslIr = 212,
    /// `C_SERVICE_NAME` -- `--service-name`.
    ServiceName = 213,
    /// `C_SESSIONID` -- `--sessionid`.
    Sessionid = 214,
    /// `C_SHOW_ERROR` -- `--show-error`.
    ShowError = 215,
    /// `C_SHOW_HEADERS` -- `--show-headers`.
    ShowHeaders = 216,
    /// `C_SIGNATURE_ALGORITHMS` -- `--sigalgs`.
    SignatureAlgorithms = 217,
    /// `C_SILENT` -- `--silent`.
    Silent = 218,
    /// `C_SKIP_EXISTING` -- `--skip-existing`.
    SkipExisting = 219,
    /// `C_SOCKS4` -- `--socks4`.
    Socks4 = 220,
    /// `C_SOCKS4A` -- `--socks4a`.
    Socks4a = 221,
    /// `C_SOCKS5` -- `--socks5`.
    Socks5 = 222,
    /// `C_SOCKS5_BASIC` -- `--socks5-basic`.
    Socks5Basic = 223,
    /// `C_SOCKS5_GSSAPI` -- `--socks5-gssapi`.
    Socks5Gssapi = 224,
    /// `C_SOCKS5_GSSAPI_NEC` -- `--socks5-gssapi-nec`.
    Socks5GssapiNec = 225,
    /// `C_SOCKS5_GSSAPI_SERVICE` -- `--socks5-gssapi-service`.
    Socks5GssapiService = 226,
    /// `C_SOCKS5_HOSTNAME` -- `--socks5-hostname`.
    Socks5Hostname = 227,
    /// `C_SPEED_LIMIT` -- `--speed-limit`.
    SpeedLimit = 228,
    /// `C_SPEED_TIME` -- `--speed-time`.
    SpeedTime = 229,
    /// `C_SSL` -- `--ssl`.
    Ssl = 230,
    /// `C_SSL_ALLOW_BEAST` -- `--ssl-allow-beast`.
    SslAllowBeast = 231,
    /// `C_SSL_AUTO_CLIENT_CERT` -- `--ssl-auto-client-cert`.
    SslAutoClientCert = 232,
    /// `C_SSL_NO_REVOKE` -- `--ssl-no-revoke`.
    SslNoRevoke = 233,
    /// `C_SSL_REQD` -- `--ssl-reqd`.
    SslReqd = 234,
    /// `C_SSL_REVOKE_BEST_EFFORT` -- `--ssl-revoke-best-effort`.
    SslRevokeBestEffort = 235,
    /// `C_SSL_SESSIONS` -- `--ssl-sessions`.
    SslSessions = 236,
    /// `C_SSLV2` -- `--sslv2`.
    Sslv2 = 237,
    /// `C_SSLV3` -- `--sslv3`.
    Sslv3 = 238,
    /// `C_STDERR` -- `--stderr`.
    Stderr = 239,
    /// `C_STYLED_OUTPUT` -- `--styled-output`.
    StyledOutput = 240,
    /// `C_SUPPRESS_CONNECT_HEADERS` -- `--suppress-connect-headers`.
    SuppressConnectHeaders = 241,
    /// `C_TCP_FASTOPEN` -- `--tcp-fastopen`.
    TcpFastopen = 242,
    /// `C_TCP_NODELAY` -- `--tcp-nodelay`.
    TcpNodelay = 243,
    /// `C_TELNET_OPTION` -- `--telnet-option`.
    TelnetOption = 244,
    /// `C_TEST_DUPHANDLE` -- `--test-duphandle`.
    TestDuphandle = 245,
    /// `C_TEST_EVENT` -- `--test-event`.
    TestEvent = 246,
    /// `C_TFTP_BLKSIZE` -- `--tftp-blksize`.
    TftpBlksize = 247,
    /// `C_TFTP_NO_OPTIONS` -- `--tftp-no-options`.
    TftpNoOptions = 248,
    /// `C_TIME_COND` -- `--time-cond`.
    TimeCond = 249,
    /// `C_TLS_EARLYDATA` -- `--tls-earlydata`.
    TlsEarlydata = 250,
    /// `C_TLS_MAX` -- `--tls-max`.
    TlsMax = 251,
    /// `C_TLS13_CIPHERS` -- `--tls13-ciphers`.
    Tls13Ciphers = 252,
    /// `C_TLSAUTHTYPE` -- `--tlsauthtype`.
    Tlsauthtype = 253,
    /// `C_TLSPASSWORD` -- `--tlspassword`.
    Tlspassword = 254,
    /// `C_TLSUSER` -- `--tlsuser`.
    Tlsuser = 255,
    /// `C_TLSV1` -- `--tlsv1`.
    Tlsv1 = 256,
    /// `C_TLSV1_0` -- `--tlsv1.0`.
    Tlsv10 = 257,
    /// `C_TLSV1_1` -- `--tlsv1.1`.
    Tlsv11 = 258,
    /// `C_TLSV1_2` -- `--tlsv1.2`.
    Tlsv12 = 259,
    /// `C_TLSV1_3` -- `--tlsv1.3`.
    Tlsv13 = 260,
    /// `C_TR_ENCODING` -- `--tr-encoding`.
    TrEncoding = 261,
    /// `C_TRACE` -- `--trace`.
    Trace = 262,
    /// `C_TRACE_ASCII` -- `--trace-ascii`.
    TraceAscii = 263,
    /// `C_TRACE_CONFIG` -- `--trace-config`.
    TraceConfig = 264,
    /// `C_TRACE_IDS` -- `--trace-ids`.
    TraceIds = 265,
    /// `C_TRACE_TIME` -- `--trace-time`.
    TraceTime = 266,
    /// `C_UNIX_SOCKET` -- `--unix-socket`.
    UnixSocket = 267,
    /// `C_UPLOAD_FILE` -- `--upload-file`.
    UploadFile = 268,
    /// `C_UPLOAD_FLAGS` -- `--upload-flags`.
    UploadFlags = 269,
    /// `C_URL` -- `--url`.
    Url = 270,
    /// `C_URL_QUERY` -- `--url-query`.
    UrlQuery = 271,
    /// `C_USE_ASCII` -- `--use-ascii`.
    UseAscii = 272,
    /// `C_USER` -- `--user`.
    User = 273,
    /// `C_USER_AGENT` -- `--user-agent`.
    UserAgent = 274,
    /// `C_VARIABLE` -- `--variable`.
    Variable = 275,
    /// `C_VERBOSE` -- `--verbose`.
    Verbose = 276,
    /// `C_VERSION` -- `--version`.
    Version = 277,
    /// `C_VLAN_PRIORITY` -- `--vlan-priority`.
    VlanPriority = 278,
    /// `C_WDEBUG` -- `--wdebug`.
    Wdebug = 279,
    /// `C_WRITE_OUT` -- `--write-out`.
    WriteOut = 280,
    /// `C_XATTR` -- `--xattr`.
    Xattr = 281,
}

impl CmdKey {
    /// How many keys exist -- the row count of [`ALIASES`], and the size of
    /// `cmdline_t` (`src/tool_getparam.h:31-314`).
    pub(crate) const COUNT: usize = 282;

    /// The `C_*` spelling, for a diagnostic or a test that has to name the
    /// token.
    #[allow(dead_code)] // Diagnostic and test surface; no dispatch arm calls it.
    pub(crate) const fn c_name(self) -> &'static str {
        match self {
            Self::AbstractUnixSocket => "C_ABSTRACT_UNIX_SOCKET",
            Self::Alpn => "C_ALPN",
            Self::AltSvc => "C_ALT_SVC",
            Self::Anyauth => "C_ANYAUTH",
            Self::Append => "C_APPEND",
            Self::AwsSigv4 => "C_AWS_SIGV4",
            Self::Basic => "C_BASIC",
            Self::Buffer => "C_BUFFER",
            Self::CaNative => "C_CA_NATIVE",
            Self::Cacert => "C_CACERT",
            Self::Capath => "C_CAPATH",
            Self::Cert => "C_CERT",
            Self::CertStatus => "C_CERT_STATUS",
            Self::CertType => "C_CERT_TYPE",
            Self::Ciphers => "C_CIPHERS",
            Self::Clobber => "C_CLOBBER",
            Self::Compressed => "C_COMPRESSED",
            Self::CompressedSsh => "C_COMPRESSED_SSH",
            Self::Config => "C_CONFIG",
            Self::ConnectTimeout => "C_CONNECT_TIMEOUT",
            Self::ConnectTo => "C_CONNECT_TO",
            Self::ContinueAt => "C_CONTINUE_AT",
            Self::Cookie => "C_COOKIE",
            Self::CookieJar => "C_COOKIE_JAR",
            Self::CreateDirs => "C_CREATE_DIRS",
            Self::CreateFileMode => "C_CREATE_FILE_MODE",
            Self::Crlf => "C_CRLF",
            Self::Crlfile => "C_CRLFILE",
            Self::Curves => "C_CURVES",
            Self::Data => "C_DATA",
            Self::DataAscii => "C_DATA_ASCII",
            Self::DataBinary => "C_DATA_BINARY",
            Self::DataRaw => "C_DATA_RAW",
            Self::DataUrlencode => "C_DATA_URLENCODE",
            Self::Delegation => "C_DELEGATION",
            Self::Digest => "C_DIGEST",
            Self::Disable => "C_DISABLE",
            Self::DisableEprt => "C_DISABLE_EPRT",
            Self::DisableEpsv => "C_DISABLE_EPSV",
            Self::DisallowUsernameInUrl => "C_DISALLOW_USERNAME_IN_URL",
            Self::DnsInterface => "C_DNS_INTERFACE",
            Self::DnsIpv4Addr => "C_DNS_IPV4_ADDR",
            Self::DnsIpv6Addr => "C_DNS_IPV6_ADDR",
            Self::DnsServers => "C_DNS_SERVERS",
            Self::DohCertStatus => "C_DOH_CERT_STATUS",
            Self::DohInsecure => "C_DOH_INSECURE",
            Self::DohUrl => "C_DOH_URL",
            Self::DumpCaEmbed => "C_DUMP_CA_EMBED",
            Self::DumpHeader => "C_DUMP_HEADER",
            Self::Ech => "C_ECH",
            Self::EgdFile => "C_EGD_FILE",
            Self::Engine => "C_ENGINE",
            Self::Eprt => "C_EPRT",
            Self::Epsv => "C_EPSV",
            Self::EtagCompare => "C_ETAG_COMPARE",
            Self::EtagSave => "C_ETAG_SAVE",
            Self::Expect100Timeout => "C_EXPECT100_TIMEOUT",
            Self::Fail => "C_FAIL",
            Self::FailEarly => "C_FAIL_EARLY",
            Self::FailWithBody => "C_FAIL_WITH_BODY",
            Self::FalseStart => "C_FALSE_START",
            Self::Follow => "C_FOLLOW",
            Self::Form => "C_FORM",
            Self::FormEscape => "C_FORM_ESCAPE",
            Self::FormString => "C_FORM_STRING",
            Self::FtpAccount => "C_FTP_ACCOUNT",
            Self::FtpAlternativeToUser => "C_FTP_ALTERNATIVE_TO_USER",
            Self::FtpCreateDirs => "C_FTP_CREATE_DIRS",
            Self::FtpMethod => "C_FTP_METHOD",
            Self::FtpPasv => "C_FTP_PASV",
            Self::FtpPort => "C_FTP_PORT",
            Self::FtpPret => "C_FTP_PRET",
            Self::FtpSkipPasvIp => "C_FTP_SKIP_PASV_IP",
            Self::FtpSsl => "C_FTP_SSL",
            Self::FtpSslCcc => "C_FTP_SSL_CCC",
            Self::FtpSslCccMode => "C_FTP_SSL_CCC_MODE",
            Self::FtpSslControl => "C_FTP_SSL_CONTROL",
            Self::FtpSslReqd => "C_FTP_SSL_REQD",
            Self::Get => "C_GET",
            Self::Globoff => "C_GLOBOFF",
            Self::HappyEyeballsTimeoutMs => "C_HAPPY_EYEBALLS_TIMEOUT_MS",
            Self::HaproxyClientip => "C_HAPROXY_CLIENTIP",
            Self::HaproxyProtocol => "C_HAPROXY_PROTOCOL",
            Self::Head => "C_HEAD",
            Self::Header => "C_HEADER",
            Self::Help => "C_HELP",
            Self::Hostpubmd5 => "C_HOSTPUBMD5",
            Self::Hostpubsha256 => "C_HOSTPUBSHA256",
            Self::Hsts => "C_HSTS",
            Self::Http09 => "C_HTTP0_9",
            Self::Http10 => "C_HTTP1_0",
            Self::Http11 => "C_HTTP1_1",
            Self::Http2 => "C_HTTP2",
            Self::Http2PriorKnowledge => "C_HTTP2_PRIOR_KNOWLEDGE",
            Self::Http3 => "C_HTTP3",
            Self::Http3Only => "C_HTTP3_ONLY",
            Self::IgnoreContentLength => "C_IGNORE_CONTENT_LENGTH",
            Self::Include => "C_INCLUDE",
            Self::Insecure => "C_INSECURE",
            Self::Interface => "C_INTERFACE",
            Self::IpTos => "C_IP_TOS",
            Self::IpfsGateway => "C_IPFS_GATEWAY",
            Self::Ipv4 => "C_IPV4",
            Self::Ipv6 => "C_IPV6",
            Self::Json => "C_JSON",
            Self::JunkSessionCookies => "C_JUNK_SESSION_COOKIES",
            Self::Keepalive => "C_KEEPALIVE",
            Self::KeepaliveCnt => "C_KEEPALIVE_CNT",
            Self::KeepaliveTime => "C_KEEPALIVE_TIME",
            Self::Key => "C_KEY",
            Self::KeyType => "C_KEY_TYPE",
            Self::Knownhosts => "C_KNOWNHOSTS",
            Self::Krb => "C_KRB",
            Self::Krb4 => "C_KRB4",
            Self::Libcurl => "C_LIBCURL",
            Self::LimitRate => "C_LIMIT_RATE",
            Self::ListOnly => "C_LIST_ONLY",
            Self::LocalPort => "C_LOCAL_PORT",
            Self::Location => "C_LOCATION",
            Self::LocationTrusted => "C_LOCATION_TRUSTED",
            Self::LoginOptions => "C_LOGIN_OPTIONS",
            Self::MailAuth => "C_MAIL_AUTH",
            Self::MailFrom => "C_MAIL_FROM",
            Self::MailRcpt => "C_MAIL_RCPT",
            Self::MailRcptAllowfails => "C_MAIL_RCPT_ALLOWFAILS",
            Self::Manual => "C_MANUAL",
            Self::MaxFilesize => "C_MAX_FILESIZE",
            Self::MaxRedirs => "C_MAX_REDIRS",
            Self::MaxTime => "C_MAX_TIME",
            Self::Metalink => "C_METALINK",
            Self::Mptcp => "C_MPTCP",
            Self::Negotiate => "C_NEGOTIATE",
            Self::Netrc => "C_NETRC",
            Self::NetrcFile => "C_NETRC_FILE",
            Self::NetrcOptional => "C_NETRC_OPTIONAL",
            Self::Next => "C_NEXT",
            Self::Noproxy => "C_NOPROXY",
            Self::Npn => "C_NPN",
            Self::Ntlm => "C_NTLM",
            Self::NtlmWb => "C_NTLM_WB",
            Self::Oauth2Bearer => "C_OAUTH2_BEARER",
            Self::OutNull => "C_OUT_NULL",
            Self::Output => "C_OUTPUT",
            Self::OutputDir => "C_OUTPUT_DIR",
            Self::Parallel => "C_PARALLEL",
            Self::ParallelImmediate => "C_PARALLEL_IMMEDIATE",
            Self::ParallelMax => "C_PARALLEL_MAX",
            Self::ParallelHost => "C_PARALLEL_HOST",
            Self::Pass => "C_PASS",
            Self::PathAsIs => "C_PATH_AS_IS",
            Self::Pinnedpubkey => "C_PINNEDPUBKEY",
            Self::Post301 => "C_POST301",
            Self::Post302 => "C_POST302",
            Self::Post303 => "C_POST303",
            Self::Preproxy => "C_PREPROXY",
            Self::ProgressBar => "C_PROGRESS_BAR",
            Self::ProgressMeter => "C_PROGRESS_METER",
            Self::Proto => "C_PROTO",
            Self::ProtoDefault => "C_PROTO_DEFAULT",
            Self::ProtoRedir => "C_PROTO_REDIR",
            Self::Proxy => "C_PROXY",
            Self::ProxyAnyauth => "C_PROXY_ANYAUTH",
            Self::ProxyBasic => "C_PROXY_BASIC",
            Self::ProxyCaNative => "C_PROXY_CA_NATIVE",
            Self::ProxyCacert => "C_PROXY_CACERT",
            Self::ProxyCapath => "C_PROXY_CAPATH",
            Self::ProxyCert => "C_PROXY_CERT",
            Self::ProxyCertType => "C_PROXY_CERT_TYPE",
            Self::ProxyCiphers => "C_PROXY_CIPHERS",
            Self::ProxyCrlfile => "C_PROXY_CRLFILE",
            Self::ProxyDigest => "C_PROXY_DIGEST",
            Self::ProxyHeader => "C_PROXY_HEADER",
            Self::ProxyHttp2 => "C_PROXY_HTTP2",
            Self::ProxyInsecure => "C_PROXY_INSECURE",
            Self::ProxyKey => "C_PROXY_KEY",
            Self::ProxyKeyType => "C_PROXY_KEY_TYPE",
            Self::ProxyNegotiate => "C_PROXY_NEGOTIATE",
            Self::ProxyNtlm => "C_PROXY_NTLM",
            Self::ProxyPass => "C_PROXY_PASS",
            Self::ProxyPinnedpubkey => "C_PROXY_PINNEDPUBKEY",
            Self::ProxyServiceName => "C_PROXY_SERVICE_NAME",
            Self::ProxySslAllowBeast => "C_PROXY_SSL_ALLOW_BEAST",
            Self::ProxySslAutoClientCert => "C_PROXY_SSL_AUTO_CLIENT_CERT",
            Self::ProxyTls13Ciphers => "C_PROXY_TLS13_CIPHERS",
            Self::ProxyTlsauthtype => "C_PROXY_TLSAUTHTYPE",
            Self::ProxyTlspassword => "C_PROXY_TLSPASSWORD",
            Self::ProxyTlsuser => "C_PROXY_TLSUSER",
            Self::ProxyTlsv1 => "C_PROXY_TLSV1",
            Self::ProxyUser => "C_PROXY_USER",
            Self::Proxy10 => "C_PROXY1_0",
            Self::Proxytunnel => "C_PROXYTUNNEL",
            Self::Pubkey => "C_PUBKEY",
            Self::Quote => "C_QUOTE",
            Self::RandomFile => "C_RANDOM_FILE",
            Self::Range => "C_RANGE",
            Self::Rate => "C_RATE",
            Self::Raw => "C_RAW",
            Self::Referer => "C_REFERER",
            Self::RemoteHeaderName => "C_REMOTE_HEADER_NAME",
            Self::RemoteName => "C_REMOTE_NAME",
            Self::RemoteNameAll => "C_REMOTE_NAME_ALL",
            Self::RemoteTime => "C_REMOTE_TIME",
            Self::RemoveOnError => "C_REMOVE_ON_ERROR",
            Self::Request => "C_REQUEST",
            Self::RequestTarget => "C_REQUEST_TARGET",
            Self::Resolve => "C_RESOLVE",
            Self::Retry => "C_RETRY",
            Self::RetryAllErrors => "C_RETRY_ALL_ERRORS",
            Self::RetryConnrefused => "C_RETRY_CONNREFUSED",
            Self::RetryDelay => "C_RETRY_DELAY",
            Self::RetryMaxTime => "C_RETRY_MAX_TIME",
            Self::SaslAuthzid => "C_SASL_AUTHZID",
            Self::SaslIr => "C_SASL_IR",
            Self::ServiceName => "C_SERVICE_NAME",
            Self::Sessionid => "C_SESSIONID",
            Self::ShowError => "C_SHOW_ERROR",
            Self::ShowHeaders => "C_SHOW_HEADERS",
            Self::SignatureAlgorithms => "C_SIGNATURE_ALGORITHMS",
            Self::Silent => "C_SILENT",
            Self::SkipExisting => "C_SKIP_EXISTING",
            Self::Socks4 => "C_SOCKS4",
            Self::Socks4a => "C_SOCKS4A",
            Self::Socks5 => "C_SOCKS5",
            Self::Socks5Basic => "C_SOCKS5_BASIC",
            Self::Socks5Gssapi => "C_SOCKS5_GSSAPI",
            Self::Socks5GssapiNec => "C_SOCKS5_GSSAPI_NEC",
            Self::Socks5GssapiService => "C_SOCKS5_GSSAPI_SERVICE",
            Self::Socks5Hostname => "C_SOCKS5_HOSTNAME",
            Self::SpeedLimit => "C_SPEED_LIMIT",
            Self::SpeedTime => "C_SPEED_TIME",
            Self::Ssl => "C_SSL",
            Self::SslAllowBeast => "C_SSL_ALLOW_BEAST",
            Self::SslAutoClientCert => "C_SSL_AUTO_CLIENT_CERT",
            Self::SslNoRevoke => "C_SSL_NO_REVOKE",
            Self::SslReqd => "C_SSL_REQD",
            Self::SslRevokeBestEffort => "C_SSL_REVOKE_BEST_EFFORT",
            Self::SslSessions => "C_SSL_SESSIONS",
            Self::Sslv2 => "C_SSLV2",
            Self::Sslv3 => "C_SSLV3",
            Self::Stderr => "C_STDERR",
            Self::StyledOutput => "C_STYLED_OUTPUT",
            Self::SuppressConnectHeaders => "C_SUPPRESS_CONNECT_HEADERS",
            Self::TcpFastopen => "C_TCP_FASTOPEN",
            Self::TcpNodelay => "C_TCP_NODELAY",
            Self::TelnetOption => "C_TELNET_OPTION",
            Self::TestDuphandle => "C_TEST_DUPHANDLE",
            Self::TestEvent => "C_TEST_EVENT",
            Self::TftpBlksize => "C_TFTP_BLKSIZE",
            Self::TftpNoOptions => "C_TFTP_NO_OPTIONS",
            Self::TimeCond => "C_TIME_COND",
            Self::TlsEarlydata => "C_TLS_EARLYDATA",
            Self::TlsMax => "C_TLS_MAX",
            Self::Tls13Ciphers => "C_TLS13_CIPHERS",
            Self::Tlsauthtype => "C_TLSAUTHTYPE",
            Self::Tlspassword => "C_TLSPASSWORD",
            Self::Tlsuser => "C_TLSUSER",
            Self::Tlsv1 => "C_TLSV1",
            Self::Tlsv10 => "C_TLSV1_0",
            Self::Tlsv11 => "C_TLSV1_1",
            Self::Tlsv12 => "C_TLSV1_2",
            Self::Tlsv13 => "C_TLSV1_3",
            Self::TrEncoding => "C_TR_ENCODING",
            Self::Trace => "C_TRACE",
            Self::TraceAscii => "C_TRACE_ASCII",
            Self::TraceConfig => "C_TRACE_CONFIG",
            Self::TraceIds => "C_TRACE_IDS",
            Self::TraceTime => "C_TRACE_TIME",
            Self::UnixSocket => "C_UNIX_SOCKET",
            Self::UploadFile => "C_UPLOAD_FILE",
            Self::UploadFlags => "C_UPLOAD_FLAGS",
            Self::Url => "C_URL",
            Self::UrlQuery => "C_URL_QUERY",
            Self::UseAscii => "C_USE_ASCII",
            Self::User => "C_USER",
            Self::UserAgent => "C_USER_AGENT",
            Self::Variable => "C_VARIABLE",
            Self::Verbose => "C_VERBOSE",
            Self::Version => "C_VERSION",
            Self::VlanPriority => "C_VLAN_PRIORITY",
            Self::Wdebug => "C_WDEBUG",
            Self::WriteOut => "C_WRITE_OUT",
            Self::Xattr => "C_XATTR",
        }
    }
}

// ---------------------------------------------------------------------------
// `struct LongShort` and `aliases[]` -- `src/tool_getparam.h:329-334`,
// `src/tool_getparam.c:79-374`
// ---------------------------------------------------------------------------

/// One row of the option table: C's `struct LongShort`
/// (`src/tool_getparam.h:329-334`).
///
/// ```c
/// struct LongShort {
///   const char *lname;  /* long name option */
///   unsigned char desc; /* type, see ARG_* */
///   char letter;        /* short name option or ' ' */
///   unsigned short cmd;
/// };
/// ```
///
/// `cmd` is [`CmdKey`] rather than an integer, which is what turns the four
/// dispatch switches into exhaustive `match`es: C's `switch` on an
/// `unsigned short` needs a `default:` to be total, and three of the four
/// deliberately omit one (see [`opt_string`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LongShort {
    /// `lname` -- the long option name, without the leading `--`.
    pub(crate) lname: &'static str,
    /// `desc` -- the type in the low two bits plus the `ARG_*` flags.
    pub(crate) desc: u8,
    /// `letter` -- the short option, or `' '` when the row has none.
    ///
    /// The sentinel is a space rather than `Option<char>` because
    /// `src/tool_getparam.c:838` tests `aliases[j].letter != ' '` and
    /// `findshortopt` rejects every byte at or below `' '` anyway
    /// (`:832`), so a space can never be looked up and needs no separate
    /// representation.
    pub(crate) letter: char,
    /// `cmd` -- the dispatch key.
    pub(crate) cmd: CmdKey,
}

/// Builds one [`LongShort`], so a table row reads as close to the C as the
/// syntax allows.
const fn row(
    lname: &'static str,
    desc: u8,
    letter: char,
    cmd: CmdKey,
) -> LongShort {
    LongShort {
        lname,
        desc,
        letter,
        cmd,
    }
}

/// The option table -- `src/tool_getparam.c:80`, carrying the C comment "this
/// array MUST be alphasorted based on the 'lname'".
///
/// # The sort is an invariant, not a convenience
///
/// `findlongopt` (`:1075-1082`) is a `bsearch` with `findarg` (`:821-826`)
/// comparing `lname` by `strcmp`, so the ordering is byte-wise ascending -- an
/// `LC_ALL=C` sort, not a locale-aware one. [`findlongopt`] keeps the binary
/// search, and [`mod tests`](self) asserts the ordering, because a
/// mis-sorted row would not fail to compile: it would make one option
/// unreachable and be found by a user rather than by the build.
///
/// # Three rows are conditional in C and unconditional here
///
/// `ipfs-gateway` sits behind `#ifndef CURL_DISABLE_IPFS`, `test-duphandle` and
/// `test-event` behind `#ifdef DEBUGBUILD`, and `wdebug` behind
/// `#ifdef USE_WATT32` (`src/tool_getparam.c:182-184`, `:333-336`, `:369-371`).
/// The inventory AAP section 0.8.1 freezes is 282 rows, so all 282 are present.
/// The three whose C `case` is compiled out in this configuration reach
/// [`opt_bool`]'s `default:` arm and yield
/// [`ParameterError::OptionUnknown`] -- which is precisely what C answers for
/// them, because with the guard undefined the row is absent and `findlongopt`
/// returns `NULL`. `ipfs-gateway` is *enabled* by default in C and is handled
/// normally.
///
/// GAP #6: `--test-duphandle` and `--test-event` set `global->test_duphandle`
/// and `global->test_event_based` (`src/tool_getparam.c:1981`, `:1984`), and
/// `--wdebug` calls WATT32's `dbug_init()` (`:1885`). `GlobalConfig`
/// (`curl-rs/src/config/mod.rs`) declares no such fields and the AAP names no
/// Cargo feature that would gate them, so the non-`DEBUGBUILD`,
/// non-`USE_WATT32` arm is the one implemented. Reported rather than worked
/// around.
#[allow(dead_code)] // The table is the surface; every consumer is a caller of
                    // `findlongopt` or `findshortopt`.
pub(crate) static ALIASES: [LongShort; CmdKey::COUNT] = [
    row(
        "abstract-unix-socket",
        ARG_FILE,
        ' ',
        CmdKey::AbstractUnixSocket,
    ),
    row("alpn", ARG_BOOL | ARG_NO | ARG_TLS, ' ', CmdKey::Alpn),
    row("alt-svc", ARG_STRG, ' ', CmdKey::AltSvc),
    row("anyauth", ARG_NONE, ' ', CmdKey::Anyauth),
    row("append", ARG_BOOL, 'a', CmdKey::Append),
    row("aws-sigv4", ARG_STRG, ' ', CmdKey::AwsSigv4),
    row("basic", ARG_BOOL, ' ', CmdKey::Basic),
    row("buffer", ARG_BOOL | ARG_NO, 'N', CmdKey::Buffer),
    row("ca-native", ARG_BOOL | ARG_TLS, ' ', CmdKey::CaNative),
    row("cacert", ARG_FILE | ARG_TLS, ' ', CmdKey::Cacert),
    row("capath", ARG_FILE | ARG_TLS, ' ', CmdKey::Capath),
    row("cert", ARG_FILE | ARG_TLS | ARG_CLEAR, 'E', CmdKey::Cert),
    row("cert-status", ARG_BOOL | ARG_TLS, ' ', CmdKey::CertStatus),
    row("cert-type", ARG_STRG | ARG_TLS, ' ', CmdKey::CertType),
    row("ciphers", ARG_STRG | ARG_TLS, ' ', CmdKey::Ciphers),
    row("clobber", ARG_BOOL | ARG_NO, ' ', CmdKey::Clobber),
    row("compressed", ARG_BOOL, ' ', CmdKey::Compressed),
    row("compressed-ssh", ARG_BOOL, ' ', CmdKey::CompressedSsh),
    row("config", ARG_FILE, 'K', CmdKey::Config),
    row("connect-timeout", ARG_STRG, ' ', CmdKey::ConnectTimeout),
    row("connect-to", ARG_STRG, ' ', CmdKey::ConnectTo),
    row("continue-at", ARG_STRG, 'C', CmdKey::ContinueAt),
    row("cookie", ARG_STRG, 'b', CmdKey::Cookie),
    row("cookie-jar", ARG_STRG, 'c', CmdKey::CookieJar),
    row("create-dirs", ARG_BOOL, ' ', CmdKey::CreateDirs),
    row("create-file-mode", ARG_STRG, ' ', CmdKey::CreateFileMode),
    row("crlf", ARG_BOOL, ' ', CmdKey::Crlf),
    row("crlfile", ARG_FILE | ARG_TLS, ' ', CmdKey::Crlfile),
    row("curves", ARG_STRG | ARG_TLS, ' ', CmdKey::Curves),
    row("data", ARG_STRG, 'd', CmdKey::Data),
    row("data-ascii", ARG_STRG, ' ', CmdKey::DataAscii),
    row("data-binary", ARG_STRG, ' ', CmdKey::DataBinary),
    row("data-raw", ARG_STRG, ' ', CmdKey::DataRaw),
    row("data-urlencode", ARG_STRG, ' ', CmdKey::DataUrlencode),
    row("delegation", ARG_STRG, ' ', CmdKey::Delegation),
    row("digest", ARG_BOOL, ' ', CmdKey::Digest),
    row("disable", ARG_BOOL, 'q', CmdKey::Disable),
    row("disable-eprt", ARG_BOOL, ' ', CmdKey::DisableEprt),
    row("disable-epsv", ARG_BOOL, ' ', CmdKey::DisableEpsv),
    row(
        "disallow-username-in-url",
        ARG_BOOL,
        ' ',
        CmdKey::DisallowUsernameInUrl,
    ),
    row("dns-interface", ARG_STRG, ' ', CmdKey::DnsInterface),
    row("dns-ipv4-addr", ARG_STRG, ' ', CmdKey::DnsIpv4Addr),
    row("dns-ipv6-addr", ARG_STRG, ' ', CmdKey::DnsIpv6Addr),
    row("dns-servers", ARG_STRG, ' ', CmdKey::DnsServers),
    row(
        "doh-cert-status",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::DohCertStatus,
    ),
    row("doh-insecure", ARG_BOOL | ARG_TLS, ' ', CmdKey::DohInsecure),
    row("doh-url", ARG_STRG, ' ', CmdKey::DohUrl),
    row(
        "dump-ca-embed",
        ARG_NONE | ARG_TLS,
        ' ',
        CmdKey::DumpCaEmbed,
    ),
    row("dump-header", ARG_FILE, 'D', CmdKey::DumpHeader),
    row("ech", ARG_STRG | ARG_TLS, ' ', CmdKey::Ech),
    row("egd-file", ARG_STRG | ARG_DEPR, ' ', CmdKey::EgdFile),
    row("engine", ARG_STRG | ARG_TLS, ' ', CmdKey::Engine),
    row("eprt", ARG_BOOL, ' ', CmdKey::Eprt),
    row("epsv", ARG_BOOL, ' ', CmdKey::Epsv),
    row("etag-compare", ARG_FILE, ' ', CmdKey::EtagCompare),
    row("etag-save", ARG_FILE, ' ', CmdKey::EtagSave),
    row("expect100-timeout", ARG_STRG, ' ', CmdKey::Expect100Timeout),
    row("fail", ARG_BOOL, 'f', CmdKey::Fail),
    row("fail-early", ARG_BOOL, ' ', CmdKey::FailEarly),
    row("fail-with-body", ARG_BOOL, ' ', CmdKey::FailWithBody),
    row("false-start", ARG_BOOL, ' ', CmdKey::FalseStart),
    row("follow", ARG_BOOL, ' ', CmdKey::Follow),
    row("form", ARG_STRG, 'F', CmdKey::Form),
    row("form-escape", ARG_BOOL, ' ', CmdKey::FormEscape),
    row("form-string", ARG_STRG, ' ', CmdKey::FormString),
    row("ftp-account", ARG_STRG, ' ', CmdKey::FtpAccount),
    row(
        "ftp-alternative-to-user",
        ARG_STRG,
        ' ',
        CmdKey::FtpAlternativeToUser,
    ),
    row("ftp-create-dirs", ARG_BOOL, ' ', CmdKey::FtpCreateDirs),
    row("ftp-method", ARG_STRG, ' ', CmdKey::FtpMethod),
    row("ftp-pasv", ARG_NONE, ' ', CmdKey::FtpPasv),
    row("ftp-port", ARG_STRG, 'P', CmdKey::FtpPort),
    row("ftp-pret", ARG_BOOL, ' ', CmdKey::FtpPret),
    row("ftp-skip-pasv-ip", ARG_BOOL, ' ', CmdKey::FtpSkipPasvIp),
    row("ftp-ssl", ARG_BOOL | ARG_TLS, ' ', CmdKey::FtpSsl),
    row("ftp-ssl-ccc", ARG_BOOL | ARG_TLS, ' ', CmdKey::FtpSslCcc),
    row(
        "ftp-ssl-ccc-mode",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::FtpSslCccMode,
    ),
    row(
        "ftp-ssl-control",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::FtpSslControl,
    ),
    row("ftp-ssl-reqd", ARG_BOOL | ARG_TLS, ' ', CmdKey::FtpSslReqd),
    row("get", ARG_BOOL, 'G', CmdKey::Get),
    row("globoff", ARG_BOOL, 'g', CmdKey::Globoff),
    row(
        "happy-eyeballs-timeout-ms",
        ARG_STRG,
        ' ',
        CmdKey::HappyEyeballsTimeoutMs,
    ),
    row("haproxy-clientip", ARG_STRG, ' ', CmdKey::HaproxyClientip),
    row("haproxy-protocol", ARG_BOOL, ' ', CmdKey::HaproxyProtocol),
    row("head", ARG_BOOL, 'I', CmdKey::Head),
    row("header", ARG_STRG, 'H', CmdKey::Header),
    row("help", ARG_STRG, 'h', CmdKey::Help),
    row("hostpubmd5", ARG_STRG, ' ', CmdKey::Hostpubmd5),
    row("hostpubsha256", ARG_STRG, ' ', CmdKey::Hostpubsha256),
    row("hsts", ARG_STRG | ARG_TLS, ' ', CmdKey::Hsts),
    row("http0.9", ARG_BOOL, ' ', CmdKey::Http09),
    row("http1.0", ARG_NONE, '0', CmdKey::Http10),
    row("http1.1", ARG_NONE, ' ', CmdKey::Http11),
    row("http2", ARG_NONE, ' ', CmdKey::Http2),
    row(
        "http2-prior-knowledge",
        ARG_NONE,
        ' ',
        CmdKey::Http2PriorKnowledge,
    ),
    row("http3", ARG_NONE | ARG_TLS, ' ', CmdKey::Http3),
    row("http3-only", ARG_NONE | ARG_TLS, ' ', CmdKey::Http3Only),
    row(
        "ignore-content-length",
        ARG_BOOL,
        ' ',
        CmdKey::IgnoreContentLength,
    ),
    row("include", ARG_BOOL, ' ', CmdKey::Include),
    row("insecure", ARG_BOOL, 'k', CmdKey::Insecure),
    row("interface", ARG_STRG, ' ', CmdKey::Interface),
    row("ip-tos", ARG_STRG, ' ', CmdKey::IpTos),
    row("ipfs-gateway", ARG_STRG, ' ', CmdKey::IpfsGateway),
    row("ipv4", ARG_NONE, '4', CmdKey::Ipv4),
    row("ipv6", ARG_NONE, '6', CmdKey::Ipv6),
    row("json", ARG_STRG, ' ', CmdKey::Json),
    row(
        "junk-session-cookies",
        ARG_BOOL,
        'j',
        CmdKey::JunkSessionCookies,
    ),
    row("keepalive", ARG_BOOL | ARG_NO, ' ', CmdKey::Keepalive),
    row("keepalive-cnt", ARG_STRG, ' ', CmdKey::KeepaliveCnt),
    row("keepalive-time", ARG_STRG, ' ', CmdKey::KeepaliveTime),
    row("key", ARG_FILE, ' ', CmdKey::Key),
    row("key-type", ARG_STRG | ARG_TLS, ' ', CmdKey::KeyType),
    row("knownhosts", ARG_FILE, ' ', CmdKey::Knownhosts),
    row("krb", ARG_STRG | ARG_DEPR, ' ', CmdKey::Krb),
    row("krb4", ARG_STRG | ARG_DEPR, ' ', CmdKey::Krb4),
    row("libcurl", ARG_STRG, ' ', CmdKey::Libcurl),
    row("limit-rate", ARG_STRG, ' ', CmdKey::LimitRate),
    row("list-only", ARG_BOOL, 'l', CmdKey::ListOnly),
    row("local-port", ARG_STRG, ' ', CmdKey::LocalPort),
    row("location", ARG_BOOL, 'L', CmdKey::Location),
    row("location-trusted", ARG_BOOL, ' ', CmdKey::LocationTrusted),
    row("login-options", ARG_STRG, ' ', CmdKey::LoginOptions),
    row("mail-auth", ARG_STRG, ' ', CmdKey::MailAuth),
    row("mail-from", ARG_STRG, ' ', CmdKey::MailFrom),
    row("mail-rcpt", ARG_STRG, ' ', CmdKey::MailRcpt),
    row(
        "mail-rcpt-allowfails",
        ARG_BOOL,
        ' ',
        CmdKey::MailRcptAllowfails,
    ),
    row("manual", ARG_BOOL, 'M', CmdKey::Manual),
    row("max-filesize", ARG_STRG, ' ', CmdKey::MaxFilesize),
    row("max-redirs", ARG_STRG, ' ', CmdKey::MaxRedirs),
    row("max-time", ARG_STRG, 'm', CmdKey::MaxTime),
    row("metalink", ARG_BOOL | ARG_DEPR, ' ', CmdKey::Metalink),
    row("mptcp", ARG_BOOL, ' ', CmdKey::Mptcp),
    row("negotiate", ARG_BOOL, ' ', CmdKey::Negotiate),
    row("netrc", ARG_BOOL, 'n', CmdKey::Netrc),
    row("netrc-file", ARG_FILE, ' ', CmdKey::NetrcFile),
    row("netrc-optional", ARG_BOOL, ' ', CmdKey::NetrcOptional),
    row("next", ARG_NONE, ':', CmdKey::Next),
    row("noproxy", ARG_STRG, ' ', CmdKey::Noproxy),
    row("npn", ARG_BOOL | ARG_DEPR, ' ', CmdKey::Npn),
    row("ntlm", ARG_BOOL, ' ', CmdKey::Ntlm),
    row("ntlm-wb", ARG_BOOL | ARG_DEPR, ' ', CmdKey::NtlmWb),
    row(
        "oauth2-bearer",
        ARG_STRG | ARG_CLEAR,
        ' ',
        CmdKey::Oauth2Bearer,
    ),
    row("out-null", ARG_BOOL, ' ', CmdKey::OutNull),
    row("output", ARG_FILE, 'o', CmdKey::Output),
    row("output-dir", ARG_STRG, ' ', CmdKey::OutputDir),
    row("parallel", ARG_BOOL, 'Z', CmdKey::Parallel),
    row(
        "parallel-immediate",
        ARG_BOOL,
        ' ',
        CmdKey::ParallelImmediate,
    ),
    row("parallel-max", ARG_STRG, ' ', CmdKey::ParallelMax),
    row("parallel-max-host", ARG_STRG, ' ', CmdKey::ParallelHost),
    row("pass", ARG_STRG | ARG_CLEAR, ' ', CmdKey::Pass),
    row("path-as-is", ARG_BOOL, ' ', CmdKey::PathAsIs),
    row(
        "pinnedpubkey",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::Pinnedpubkey,
    ),
    row("post301", ARG_BOOL, ' ', CmdKey::Post301),
    row("post302", ARG_BOOL, ' ', CmdKey::Post302),
    row("post303", ARG_BOOL, ' ', CmdKey::Post303),
    row("preproxy", ARG_STRG, ' ', CmdKey::Preproxy),
    row("progress-bar", ARG_BOOL, '#', CmdKey::ProgressBar),
    row(
        "progress-meter",
        ARG_BOOL | ARG_NO,
        ' ',
        CmdKey::ProgressMeter,
    ),
    row("proto", ARG_STRG, ' ', CmdKey::Proto),
    row("proto-default", ARG_STRG, ' ', CmdKey::ProtoDefault),
    row("proto-redir", ARG_STRG, ' ', CmdKey::ProtoRedir),
    row("proxy", ARG_STRG, 'x', CmdKey::Proxy),
    row("proxy-anyauth", ARG_BOOL, ' ', CmdKey::ProxyAnyauth),
    row("proxy-basic", ARG_BOOL, ' ', CmdKey::ProxyBasic),
    row(
        "proxy-ca-native",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::ProxyCaNative,
    ),
    row("proxy-cacert", ARG_FILE | ARG_TLS, ' ', CmdKey::ProxyCacert),
    row("proxy-capath", ARG_FILE | ARG_TLS, ' ', CmdKey::ProxyCapath),
    row(
        "proxy-cert",
        ARG_FILE | ARG_TLS | ARG_CLEAR,
        ' ',
        CmdKey::ProxyCert,
    ),
    row(
        "proxy-cert-type",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::ProxyCertType,
    ),
    row(
        "proxy-ciphers",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::ProxyCiphers,
    ),
    row(
        "proxy-crlfile",
        ARG_FILE | ARG_TLS,
        ' ',
        CmdKey::ProxyCrlfile,
    ),
    row("proxy-digest", ARG_BOOL, ' ', CmdKey::ProxyDigest),
    row("proxy-header", ARG_STRG, ' ', CmdKey::ProxyHeader),
    row("proxy-http2", ARG_BOOL, ' ', CmdKey::ProxyHttp2),
    row("proxy-insecure", ARG_BOOL, ' ', CmdKey::ProxyInsecure),
    row("proxy-key", ARG_FILE | ARG_TLS, ' ', CmdKey::ProxyKey),
    row(
        "proxy-key-type",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::ProxyKeyType,
    ),
    row("proxy-negotiate", ARG_BOOL, ' ', CmdKey::ProxyNegotiate),
    row("proxy-ntlm", ARG_BOOL, ' ', CmdKey::ProxyNtlm),
    row("proxy-pass", ARG_STRG | ARG_CLEAR, ' ', CmdKey::ProxyPass),
    row(
        "proxy-pinnedpubkey",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::ProxyPinnedpubkey,
    ),
    row(
        "proxy-service-name",
        ARG_STRG,
        ' ',
        CmdKey::ProxyServiceName,
    ),
    row(
        "proxy-ssl-allow-beast",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::ProxySslAllowBeast,
    ),
    row(
        "proxy-ssl-auto-client-cert",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::ProxySslAutoClientCert,
    ),
    row(
        "proxy-tls13-ciphers",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::ProxyTls13Ciphers,
    ),
    row(
        "proxy-tlsauthtype",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::ProxyTlsauthtype,
    ),
    row(
        "proxy-tlspassword",
        ARG_STRG | ARG_TLS | ARG_CLEAR,
        ' ',
        CmdKey::ProxyTlspassword,
    ),
    row(
        "proxy-tlsuser",
        ARG_STRG | ARG_TLS | ARG_CLEAR,
        ' ',
        CmdKey::ProxyTlsuser,
    ),
    row("proxy-tlsv1", ARG_NONE | ARG_TLS, ' ', CmdKey::ProxyTlsv1),
    row("proxy-user", ARG_STRG | ARG_CLEAR, 'U', CmdKey::ProxyUser),
    row("proxy1.0", ARG_STRG, ' ', CmdKey::Proxy10),
    row("proxytunnel", ARG_BOOL, 'p', CmdKey::Proxytunnel),
    row("pubkey", ARG_STRG, ' ', CmdKey::Pubkey),
    row("quote", ARG_STRG, 'Q', CmdKey::Quote),
    row("random-file", ARG_FILE | ARG_DEPR, ' ', CmdKey::RandomFile),
    row("range", ARG_STRG, 'r', CmdKey::Range),
    row("rate", ARG_STRG, ' ', CmdKey::Rate),
    row("raw", ARG_BOOL, ' ', CmdKey::Raw),
    row("referer", ARG_STRG, 'e', CmdKey::Referer),
    row(
        "remote-header-name",
        ARG_BOOL,
        'J',
        CmdKey::RemoteHeaderName,
    ),
    row("remote-name", ARG_BOOL, 'O', CmdKey::RemoteName),
    row("remote-name-all", ARG_BOOL, ' ', CmdKey::RemoteNameAll),
    row("remote-time", ARG_BOOL, 'R', CmdKey::RemoteTime),
    row("remove-on-error", ARG_BOOL, ' ', CmdKey::RemoveOnError),
    row("request", ARG_STRG, 'X', CmdKey::Request),
    row("request-target", ARG_STRG, ' ', CmdKey::RequestTarget),
    row("resolve", ARG_STRG, ' ', CmdKey::Resolve),
    row("retry", ARG_STRG, ' ', CmdKey::Retry),
    row("retry-all-errors", ARG_BOOL, ' ', CmdKey::RetryAllErrors),
    row("retry-connrefused", ARG_BOOL, ' ', CmdKey::RetryConnrefused),
    row("retry-delay", ARG_STRG, ' ', CmdKey::RetryDelay),
    row("retry-max-time", ARG_STRG, ' ', CmdKey::RetryMaxTime),
    row("sasl-authzid", ARG_STRG, ' ', CmdKey::SaslAuthzid),
    row("sasl-ir", ARG_BOOL, ' ', CmdKey::SaslIr),
    row("service-name", ARG_STRG, ' ', CmdKey::ServiceName),
    row("sessionid", ARG_BOOL | ARG_NO, ' ', CmdKey::Sessionid),
    row("show-error", ARG_BOOL, 'S', CmdKey::ShowError),
    row("show-headers", ARG_BOOL, 'i', CmdKey::ShowHeaders),
    row(
        "sigalgs",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::SignatureAlgorithms,
    ),
    row("silent", ARG_BOOL, 's', CmdKey::Silent),
    row("skip-existing", ARG_BOOL, ' ', CmdKey::SkipExisting),
    row("socks4", ARG_STRG, ' ', CmdKey::Socks4),
    row("socks4a", ARG_STRG, ' ', CmdKey::Socks4a),
    row("socks5", ARG_STRG, ' ', CmdKey::Socks5),
    row("socks5-basic", ARG_BOOL, ' ', CmdKey::Socks5Basic),
    row("socks5-gssapi", ARG_BOOL, ' ', CmdKey::Socks5Gssapi),
    row("socks5-gssapi-nec", ARG_BOOL, ' ', CmdKey::Socks5GssapiNec),
    row(
        "socks5-gssapi-service",
        ARG_STRG,
        ' ',
        CmdKey::Socks5GssapiService,
    ),
    row("socks5-hostname", ARG_STRG, ' ', CmdKey::Socks5Hostname),
    row("speed-limit", ARG_STRG, 'Y', CmdKey::SpeedLimit),
    row("speed-time", ARG_STRG, 'y', CmdKey::SpeedTime),
    row("ssl", ARG_BOOL | ARG_TLS, ' ', CmdKey::Ssl),
    row(
        "ssl-allow-beast",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::SslAllowBeast,
    ),
    row(
        "ssl-auto-client-cert",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::SslAutoClientCert,
    ),
    row(
        "ssl-no-revoke",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::SslNoRevoke,
    ),
    row("ssl-reqd", ARG_BOOL | ARG_TLS, ' ', CmdKey::SslReqd),
    row(
        "ssl-revoke-best-effort",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::SslRevokeBestEffort,
    ),
    row("ssl-sessions", ARG_FILE | ARG_TLS, ' ', CmdKey::SslSessions),
    row("sslv2", ARG_NONE | ARG_DEPR, '2', CmdKey::Sslv2),
    row("sslv3", ARG_NONE | ARG_DEPR, '3', CmdKey::Sslv3),
    row("stderr", ARG_FILE, ' ', CmdKey::Stderr),
    row("styled-output", ARG_BOOL, ' ', CmdKey::StyledOutput),
    row(
        "suppress-connect-headers",
        ARG_BOOL,
        ' ',
        CmdKey::SuppressConnectHeaders,
    ),
    row("tcp-fastopen", ARG_BOOL, ' ', CmdKey::TcpFastopen),
    row("tcp-nodelay", ARG_BOOL, ' ', CmdKey::TcpNodelay),
    row("telnet-option", ARG_STRG, 't', CmdKey::TelnetOption),
    row("test-duphandle", ARG_BOOL, ' ', CmdKey::TestDuphandle),
    row("test-event", ARG_BOOL, ' ', CmdKey::TestEvent),
    row("tftp-blksize", ARG_STRG, ' ', CmdKey::TftpBlksize),
    row("tftp-no-options", ARG_BOOL, ' ', CmdKey::TftpNoOptions),
    row("time-cond", ARG_STRG, 'z', CmdKey::TimeCond),
    row(
        "tls-earlydata",
        ARG_BOOL | ARG_TLS,
        ' ',
        CmdKey::TlsEarlydata,
    ),
    row("tls-max", ARG_STRG | ARG_TLS, ' ', CmdKey::TlsMax),
    row(
        "tls13-ciphers",
        ARG_STRG | ARG_TLS,
        ' ',
        CmdKey::Tls13Ciphers,
    ),
    row("tlsauthtype", ARG_STRG | ARG_TLS, ' ', CmdKey::Tlsauthtype),
    row(
        "tlspassword",
        ARG_STRG | ARG_TLS | ARG_CLEAR,
        ' ',
        CmdKey::Tlspassword,
    ),
    row(
        "tlsuser",
        ARG_STRG | ARG_TLS | ARG_CLEAR,
        ' ',
        CmdKey::Tlsuser,
    ),
    row("tlsv1", ARG_NONE | ARG_TLS, '1', CmdKey::Tlsv1),
    row("tlsv1.0", ARG_NONE | ARG_TLS, ' ', CmdKey::Tlsv10),
    row("tlsv1.1", ARG_NONE | ARG_TLS, ' ', CmdKey::Tlsv11),
    row("tlsv1.2", ARG_NONE | ARG_TLS, ' ', CmdKey::Tlsv12),
    row("tlsv1.3", ARG_NONE | ARG_TLS, ' ', CmdKey::Tlsv13),
    row("tr-encoding", ARG_BOOL, ' ', CmdKey::TrEncoding),
    row("trace", ARG_FILE, ' ', CmdKey::Trace),
    row("trace-ascii", ARG_FILE, ' ', CmdKey::TraceAscii),
    row("trace-config", ARG_STRG, ' ', CmdKey::TraceConfig),
    row("trace-ids", ARG_BOOL, ' ', CmdKey::TraceIds),
    row("trace-time", ARG_BOOL, ' ', CmdKey::TraceTime),
    row("unix-socket", ARG_FILE, ' ', CmdKey::UnixSocket),
    row("upload-file", ARG_FILE, 'T', CmdKey::UploadFile),
    row("upload-flags", ARG_STRG, ' ', CmdKey::UploadFlags),
    row("url", ARG_STRG, ' ', CmdKey::Url),
    row("url-query", ARG_STRG, ' ', CmdKey::UrlQuery),
    row("use-ascii", ARG_BOOL, 'B', CmdKey::UseAscii),
    row("user", ARG_STRG | ARG_CLEAR, 'u', CmdKey::User),
    row("user-agent", ARG_STRG, 'A', CmdKey::UserAgent),
    row("variable", ARG_STRG, ' ', CmdKey::Variable),
    row("verbose", ARG_BOOL, 'v', CmdKey::Verbose),
    row("version", ARG_BOOL, 'V', CmdKey::Version),
    row("vlan-priority", ARG_STRG, ' ', CmdKey::VlanPriority),
    row("wdebug", ARG_BOOL, ' ', CmdKey::Wdebug),
    row("write-out", ARG_STRG, 'w', CmdKey::WriteOut),
    row("xattr", ARG_BOOL, ' ', CmdKey::Xattr),
];

/// The 115 `--no-<name>` spellings, in [`ALIASES`] order.
///
/// `clap`'s `Id` and `Str` are built from `&'static str`, so the negations
/// cannot be assembled with `format!` at call time. They are generated from the
/// same `ARG_BOOL` rows instead, which keeps the two lists incapable of
/// disagreeing; [`mod tests`](self) asserts that this array is exactly those
/// rows' names with `no-` prepended, in order, and that nothing else appears.
///
/// The surface they describe is `src/tool_getparam.c:2916-2921` accepting the
/// prefix and `:2950-2953` rejecting it for every one of the other 167 rows.
static NEGATIONS: [&str; 115] = [
    "no-alpn",
    "no-append",
    "no-basic",
    "no-buffer",
    "no-ca-native",
    "no-cert-status",
    "no-clobber",
    "no-compressed",
    "no-compressed-ssh",
    "no-create-dirs",
    "no-crlf",
    "no-digest",
    "no-disable",
    "no-disable-eprt",
    "no-disable-epsv",
    "no-disallow-username-in-url",
    "no-doh-cert-status",
    "no-doh-insecure",
    "no-eprt",
    "no-epsv",
    "no-fail",
    "no-fail-early",
    "no-fail-with-body",
    "no-false-start",
    "no-follow",
    "no-form-escape",
    "no-ftp-create-dirs",
    "no-ftp-pret",
    "no-ftp-skip-pasv-ip",
    "no-ftp-ssl",
    "no-ftp-ssl-ccc",
    "no-ftp-ssl-control",
    "no-ftp-ssl-reqd",
    "no-get",
    "no-globoff",
    "no-haproxy-protocol",
    "no-head",
    "no-http0.9",
    "no-ignore-content-length",
    "no-include",
    "no-insecure",
    "no-junk-session-cookies",
    "no-keepalive",
    "no-list-only",
    "no-location",
    "no-location-trusted",
    "no-mail-rcpt-allowfails",
    "no-manual",
    "no-metalink",
    "no-mptcp",
    "no-negotiate",
    "no-netrc",
    "no-netrc-optional",
    "no-npn",
    "no-ntlm",
    "no-ntlm-wb",
    "no-out-null",
    "no-parallel",
    "no-parallel-immediate",
    "no-path-as-is",
    "no-post301",
    "no-post302",
    "no-post303",
    "no-progress-bar",
    "no-progress-meter",
    "no-proxy-anyauth",
    "no-proxy-basic",
    "no-proxy-ca-native",
    "no-proxy-digest",
    "no-proxy-http2",
    "no-proxy-insecure",
    "no-proxy-negotiate",
    "no-proxy-ntlm",
    "no-proxy-ssl-allow-beast",
    "no-proxy-ssl-auto-client-cert",
    "no-proxytunnel",
    "no-raw",
    "no-remote-header-name",
    "no-remote-name",
    "no-remote-name-all",
    "no-remote-time",
    "no-remove-on-error",
    "no-retry-all-errors",
    "no-retry-connrefused",
    "no-sasl-ir",
    "no-sessionid",
    "no-show-error",
    "no-show-headers",
    "no-silent",
    "no-skip-existing",
    "no-socks5-basic",
    "no-socks5-gssapi",
    "no-socks5-gssapi-nec",
    "no-ssl",
    "no-ssl-allow-beast",
    "no-ssl-auto-client-cert",
    "no-ssl-no-revoke",
    "no-ssl-reqd",
    "no-ssl-revoke-best-effort",
    "no-styled-output",
    "no-suppress-connect-headers",
    "no-tcp-fastopen",
    "no-tcp-nodelay",
    "no-test-duphandle",
    "no-test-event",
    "no-tftp-no-options",
    "no-tls-earlydata",
    "no-tr-encoding",
    "no-trace-ids",
    "no-trace-time",
    "no-use-ascii",
    "no-verbose",
    "no-version",
    "no-wdebug",
    "no-xattr",
];

/// `findarg` -- `src/tool_getparam.c:821-826`.
///
/// C's `bsearch` comparator, `strcmp` on `lname`. Kept as a named function
/// because the ordering it defines is the table's invariant and
/// [`mod tests`](self) asserts against this exact comparison: `str`'s `Ord` is
/// byte-wise, which is what `strcmp` is.
fn findarg(left: &str, right: &str) -> Ordering {
    left.as_bytes().cmp(right.as_bytes())
}

/// `findlongopt` -- `src/tool_getparam.c:1075-1082`.
///
/// The `bsearch` over the alphasorted table. `opt` arrives as bytes because an
/// option name reaches this function as a slice of an `OsString`; a name that
/// is not UTF-8 cannot match any row, and `from_utf8` reporting that is the
/// same answer `strcmp` gives.
#[allow(dead_code)] // Called by `getparameter`; also the entry point a
                    // configuration-file reader needs.
pub(crate) fn findlongopt(opt: &[u8]) -> Option<&'static LongShort> {
    let name = std::str::from_utf8(opt).ok()?;
    let at = ALIASES
        .binary_search_by(|probe| findarg(probe.lname, name))
        .ok()?;
    ALIASES.get(at)
}

/// `findshortopt` -- `src/tool_getparam.c:828-845`.
///
/// C builds a 95-entry `static` lookup table on first use, latched by a
/// `static bool singles_done`. Both are gone: this scans [`ALIASES`],
/// which needs no mutable state and no initialisation order (AAP section 0.1.2;
/// performance is a non-goal per section 0.1.1).
///
/// The bounds are C's, at `:832`: a byte at or below `' '` and a byte at or
/// above `127` are rejected outright, so the space sentinel in
/// [`LongShort::letter`] can never be looked up and no control byte or
/// non-ASCII byte can index the table.
#[allow(dead_code)] // Called by `getparameter`'s short-cluster loop.
pub(crate) fn findshortopt(letter: u8) -> Option<&'static LongShort> {
    // `:832-833` -- `if((letter >= 127) || (letter <= ' ')) return NULL;`
    if letter >= 127 || letter <= b' ' {
        return None;
    }
    ALIASES
        .iter()
        .find(|row| row.letter != ' ' && row.letter as u32 == u32::from(letter))
}

// ---------------------------------------------------------------------------
// Injected capabilities
// ---------------------------------------------------------------------------

/// The effects the parser cannot perform itself.
///
/// Six of C's operations reach outside the option table: four have no module
/// among this file's declared dependencies, one needs a concrete sink type this
/// file never holds, and one is unavailable in safe Rust. They are gathered
/// here so that the parser stays a pure function of its inputs and can be
/// exercised without a filesystem, a terminal or a network -- which is what AAP
/// section 0.3.3's pattern P12 asks for, and what makes the coverage AAP
/// section 0.8.7 relocates out of `tests/unit` achievable.
///
/// # Why a generic bound and never `&mut dyn ParseHost`
///
/// [`VarHost`] and [`StdinAccess`] are supertraits so that one object can be
/// handed to [`setvariable`], [`varexpand`]'s callers and [`formparse`], each of
/// which wants a different one of the three. Reaching those from a
/// `&mut dyn ParseHost` would need trait upcasting, which stabilised in Rust
/// 1.86 -- above the MSRV of 1.75 that AAP section 0.8.3 mandates. Every
/// function that needs a host is therefore generic over `H: ParseHost`, and
/// `&mut *host` unsize-coerces to `&mut dyn VarHost` or `&mut dyn StdinAccess`
/// the ordinary way.
pub(crate) trait ParseHost: VarHost + StdinAccess {
    /// Whether `path` names something that exists -- C's `curlx_stat` in
    /// `existingfile` (`src/tool_getparam.c:2212`).
    ///
    /// C inspects only whether the `stat` succeeded, so a boolean carries
    /// everything the caller uses.
    fn exists(&mut self, path: &[u8]) -> bool;

    /// The modification time of `path`, or `None` when it cannot be read.
    ///
    /// GAP #1: `getfiletime` (`src/tool_getparam.c:1636`) lives in
    /// `curl-rs/src/output/filetime.rs`, which is not among this file's
    /// declared dependencies, so it cannot be called directly. The warning C
    /// emits on failure belongs to that module and is left to it; `--time-cond`
    /// only needs the success or failure, which `:1637-1646` turns into either
    /// a time or a disabled condition. Reported rather than worked around.
    fn file_time(&mut self, path: &[u8]) -> Option<i64>;

    /// `curl_global_trace(config)` -- `src/tool_getparam.c:790`, `:792`,
    /// `:806`. `false` reports the `CURLcode` C treats as out of memory.
    ///
    /// GAP #2: the trace configuration is process-global state in C.
    /// `GlobalConfig` (`curl-rs/src/config/mod.rs`) holds no `TraceConfig`, and
    /// this crate must not reach into `curl-rs-lib`'s internals, so the owner of
    /// that state applies the token list. Reported rather than worked around.
    fn set_trace(&mut self, config: &str) -> bool;

    /// `tool_set_stderr_file(nextarg)` -- `src/tool_getparam.c:2312`.
    ///
    /// GAP #3: `crate::output::msgs::set_stderr_file` takes
    /// `&mut MessageSink`, a concrete type, because it replaces the sink rather
    /// than writing to it. The parser only ever holds
    /// `&mut dyn DiagnosticSink` and cannot produce the concrete one, so the
    /// caller that owns the sink performs the redirection. Reported rather than
    /// worked around.
    fn set_stderr_file(&mut self, path: &[u8]);

    /// `tool_help(category)` -- called at `src/tool_getparam.c:3003`, *before*
    /// `PARAM_HELP_REQUESTED` is returned.
    ///
    /// GAP #4: `curl-rs/src/cli/help.rs` does not exist in this checkout and
    /// `curl-rs/src/cli/mod.rs` therefore does not declare it -- a `mod help;`
    /// without its file is `E0583`, a hard error no `#[allow]` can reach. The
    /// signature is the one that module is specified to provide,
    /// `tool_help(category: Option<&str>)`, so wiring it up is a one-line
    /// implementation of this method. Reported rather than worked around.
    fn help(&mut self, category: Option<&str>);

    /// `parseconfig(filename, max_recursive, NULL)` --
    /// `src/tool_getparam.c:2252`.
    ///
    /// GAP #5: `curl-rs/src/config/parseconfig.rs` does not exist in this
    /// checkout. Reading a configuration file re-enters [`getparameter`], so the
    /// owner of that module is also the owner of the re-entry; the recursion
    /// budget is passed through already decremented, exactly as `:2246` does.
    /// Reported rather than worked around.
    fn parse_config(
        &mut self,
        filename: &[u8],
        max_recursive: i32,
    ) -> ParameterError;
}

/// `cleanarg` -- `src/tool_getparam.c:626-637`.
///
/// GAP #0: under `HAVE_WRITABLE_ARGV` C overwrites the argument in place with
/// `memset(str, '*', strlen(str))` (`:633`), with the comment "wipe the next
/// argument out so that the username:password is not displayed in the system
/// process list". Rust cannot write through `argv` without `unsafe`, and AAP
/// section 0.8.2 forbids `unsafe` outside the designated FFI modules -- of
/// which this crate has none. The `!HAVE_WRITABLE_ARGV` arm (`:637`) is
/// `#define cleanarg(x) tool_nop_stmt`, a supported upstream configuration, so
/// that arm is the one implemented. Reported rather than worked around: no
/// `/proc/self/cmdline` write, no re-`exec`, no subprocess.
///
/// The call site at `:3027-3028` is preserved so that the eleven `ARG_CLEAR`
/// rows remain identifiable, and so that restoring the behaviour is a change to
/// this function alone.
fn cleanarg(_argument: &[u8]) {
    // The `!HAVE_WRITABLE_ARGV` arm, `src/tool_getparam.c:637`.
}

// ---------------------------------------------------------------------------
// Parser state and shared accessors
// ---------------------------------------------------------------------------

/// The state C keeps in file-scope `static` variables.
///
/// One field today, and deliberately a struct rather than a bare parameter: it
/// is what [`getparameter`] threads through the short-option loop, and a second
/// static appearing upstream would join it here rather than becoming another
/// argument on every signature.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ParseState {
    /// `static size_t verbose_nopts` -- `src/tool_getparam.c:1511`.
    ///
    /// Reset to zero when an argv element begins (`:2904`), incremented once per
    /// option consumed from that element (`:3042`), and read by [`parse_verbose`]
    /// at `:1526`. It is what makes `-vvv` climb the verbosity ladder while
    /// `-v -v` does not: the first `-v` of each element sees it at zero and
    /// resets to base verbosity.
    verbose_nopts: usize,
}

/// `MsgConfig` as the diagnostic helpers want it, read from `global`.
///
/// C's `warnf` gates on `!global->silent` (`src/tool_msgs.c:95`), `errorf` on
/// `global->showerror` and `notef` on `global->tracetype`
/// (`src/tool_msgs.c:83`, `:113`). The snapshot is taken when a handler is
/// entered rather than threaded from the top of the parse, because `--silent`,
/// `--show-error` and the trace options change those fields as the command line
/// is walked and C observes each change from the next diagnostic onwards. No
/// handler both changes one of them and emits a diagnostic, so a per-handler
/// snapshot is indistinguishable from C's per-call read.
fn msg_config(global: &GlobalConfig) -> MsgConfig {
    MsgConfig::new(
        global.silent,
        global.showerror,
        global.tracetype != TraceType::None,
    )
}

/// The two-line adapter `curl-rs/src/config/mod.rs:1347` assigns to this
/// module: "That mapping, and the two-line
/// `impl crate::cli::paramhlp::UrlList for OperationConfig` that carries it,
/// belong to the module that owns that vocabulary rather than to this one".
///
/// `push_getout` reserves before it pushes so that a failure leaves the list
/// untouched, which is what `src/tool_paramhlp.c:39`'s `if(node)` guarantees;
/// every C call site turns that failure into `PARAM_NO_MEM`
/// (`src/tool_getparam.c:1110`, `:1352`, `:1395`, `:1499`).
impl UrlList for OperationConfig {
    fn append(&mut self, node: NewGetOut) -> Result<usize, ParameterError> {
        self.push_getout(node).map_err(|_| ParameterError::NoMem)
    }

    fn remote_name_all(&self) -> bool {
        // Named through the type so that the inherent accessor is selected
        // explicitly rather than by the precedence rule.
        OperationConfig::remote_name_all(self)
    }

    fn sequence(&mut self) -> &mut GetOutSeq {
        self.getout_sequence_mut()
    }
}

// ---------------------------------------------------------------------------
// String acceptance -- `src/tool_getparam.c:44-77`
// ---------------------------------------------------------------------------

/// `getstr` -- `src/tool_getparam.c:44-59`.
///
/// C frees the old value, rejects an empty argument unless `allowblank`, and
/// duplicates. The free and the duplication are what assignment does in Rust;
/// only the blank check is behaviour, and it is the whole reason `--libcurl ""`
/// fails in the parser rather than later
/// (`src/tool_getparam.c:2508`, `DENY_BLANK`).
///
/// Returns the accepted bytes so the caller can place them in whichever field
/// its `case` names.
fn getstr(value: &[u8], allowblank: bool) -> Result<Vec<u8>, ParameterError> {
    // `:51-52` -- `if(!allowblank && !val[0]) return PARAM_BLANK_STRING;`
    if !allowblank && value.is_empty() {
        return Err(ParameterError::BlankString);
    }
    Ok(value.to_vec())
}

/// `getstr` for a field typed `Option<String>`.
///
/// The 228 fields of `OperationConfig` that hold an option argument are typed
/// `Option<String>`, `Option<PathBuf>` or `Vec<u8>` according to what the field
/// holds, so the byte form above is adapted rather than duplicated. A field
/// typed `String` cannot hold a non-UTF-8 argument; C stores the bytes and
/// hands them to libcurl, so the lossy conversion here is the one place this
/// port cannot be byte-exact for such an argument. It is confined to this
/// function so that widening a field's type is a change in `config/mod.rs`
/// alone.
fn getstr_text(
    value: &[u8],
    allowblank: bool,
) -> Result<String, ParameterError> {
    let bytes = getstr(value, allowblank)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// `getstr` for a field typed `Option<PathBuf>`.
///
/// A path keeps its bytes: `PathBuf` is built from an `OsString`, so a filename
/// that is not UTF-8 survives intact, which `--output` and `--cacert` need.
fn getstr_path(
    value: &[u8],
    allowblank: bool,
) -> Result<std::path::PathBuf, ParameterError> {
    let bytes = getstr(value, allowblank)?;
    Ok(std::path::PathBuf::from(OsString::from_vec(bytes)))
}

/// `getstrn` -- `src/tool_getparam.c:61-77`.
///
/// The length-bounded variant. `--referer` is its only caller (`:2655`), where
/// the `;auto` suffix has already been measured off the end and must not be
/// stored.
fn getstrn(
    value: &[u8],
    len: usize,
    allowblank: bool,
) -> Result<String, ParameterError> {
    // `:69-70` inspects `val[0]`, the *unbounded* first byte, exactly as
    // `getstr` does -- the length bound applies to the copy, not to the check.
    if !allowblank && value.is_empty() {
        return Err(ParameterError::BlankString);
    }
    let taken = value.get(..len).unwrap_or(value);
    Ok(String::from_utf8_lossy(taken).into_owned())
}

// ---------------------------------------------------------------------------
// `-E` / `--cert` splitting -- `src/tool_getparam.c:376-533`
// ---------------------------------------------------------------------------

/// The two halves of a `--cert` argument.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CertParameter {
    /// `*certname` -- the certificate, with escapes resolved.
    pub(crate) certname: Vec<u8>,
    /// `*passphrase` -- present only when an unescaped separating colon was
    /// followed by at least one byte.
    pub(crate) passphrase: Option<Vec<u8>>,
}

/// `parse_cert_parameter` -- `src/tool_getparam.c:383-487`, "Unit test 1394".
///
/// Splits `-E`'s argument into certificate and passphrase at an unescaped
/// colon, honouring `\:` and `\\`. Every branch of the C `switch` is
/// reproduced:
///
/// * empty argument -> [`ParameterError::BlankString`] (`:396-397`);
/// * an argument beginning `pkcs11:`, or one containing neither `:` nor `\`,
///   is taken whole as an RFC 7512 URI or a plain filename (`:403-409`);
/// * `\` followed by end of string keeps the backslash (`:432-434`);
/// * `\\` yields one backslash (`:435-438`);
/// * `\:` yields one colon and does **not** separate (`:439-442`);
/// * `\` before anything else keeps both bytes (`:443-447`);
/// * an unescaped colon separates, and the passphrase is set only when
///   something follows it (`:471-476`).
///
/// # The Windows drive-letter branch is not compiled here
///
/// `:456-468` accepts `c:\file:password` by treating a colon in the second
/// column as part of a drive letter, and it is inside `#ifdef _WIN32`. None of
/// the four targets AAP section 0.1.1 names is Windows, so the branch is absent
/// exactly as it is absent from a POSIX build; [`mod tests`](self) asserts the
/// POSIX reading of that input so the difference is recorded rather than
/// assumed.
#[allow(dead_code)] // Reached through `get_file_and_password`; also the unit
                    // under test for "Unit test 1394".
pub(crate) fn parse_cert_parameter(
    cert_parameter: &[u8],
) -> Result<CertParameter, ParameterError> {
    // `:396-397`
    if cert_parameter.is_empty() {
        return Err(ParameterError::BlankString);
    }

    // `:403-404` -- `curl_strnequal(cert_parameter, "pkcs11:", 7)` is ASCII
    // case-insensitive, and `strpbrk(cert_parameter, ":\\")` looks for either
    // special byte.
    let is_pkcs11 = cert_parameter
        .get(..7)
        .is_some_and(|head| head.eq_ignore_ascii_case(b"pkcs11:"));
    let has_special = cert_parameter
        .iter()
        .any(|byte| *byte == b':' || *byte == b'\\');
    if is_pkcs11 || !has_special {
        return Ok(CertParameter {
            certname: cert_parameter.to_vec(),
            passphrase: None,
        });
    }

    let mut certname: Vec<u8> = Vec::with_capacity(cert_parameter.len());
    let mut at = 0;
    while at < cert_parameter.len() {
        // `:420-423` -- `strcspn(param_place, ":\\")` then copy that span.
        let rest = cert_parameter.get(at..).unwrap_or_default();
        let span = rest
            .iter()
            .position(|byte| *byte == b':' || *byte == b'\\')
            .unwrap_or(rest.len());
        certname.extend_from_slice(rest.get(..span).unwrap_or(rest));
        at += span;

        // `:426` -- now on a special byte or at the end.
        match cert_parameter.get(at) {
            // `:427-428` -- `case '\0': break;` leaves the loop through the
            // `while(*param_place)` condition.
            None => break,
            // `:429-449` -- `case '\\'`.
            Some(b'\\') => {
                at += 1;
                match cert_parameter.get(at) {
                    // `:432-434` -- a trailing backslash is kept.
                    None => certname.push(b'\\'),
                    // `:435-438`
                    Some(b'\\') => {
                        certname.push(b'\\');
                        at += 1;
                    }
                    // `:439-442`
                    Some(b':') => {
                        certname.push(b':');
                        at += 1;
                    }
                    // `:443-447` -- both bytes are kept.
                    Some(other) => {
                        certname.push(b'\\');
                        certname.push(*other);
                        at += 1;
                    }
                }
            }
            // `:450-477` -- `case ':'`, the separating colon.
            Some(_) => {
                at += 1;
                let passphrase = cert_parameter
                    .get(at..)
                    .filter(|rest| !rest.is_empty())
                    .map(<[u8]>::to_vec);
                return Ok(CertParameter {
                    certname,
                    passphrase,
                });
            }
        }
    }

    Ok(CertParameter {
        certname,
        passphrase: None,
    })
}

/// `GetFileAndPassword` -- `src/tool_getparam.c:517-533`.
///
/// Wraps [`parse_cert_parameter`] and, crucially, overwrites `password` **only**
/// when a passphrase was actually present (`:527-530`) -- so `--pass secret
/// --cert file` keeps `secret`, while `--cert file:other` replaces it.
fn get_file_and_password(
    nextarg: &[u8],
    file: &mut Option<std::path::PathBuf>,
    password: &mut Option<String>,
) -> Result<(), ParameterError> {
    let parsed = parse_cert_parameter(nextarg)?;
    // `:525-526`
    *file = Some(std::path::PathBuf::from(OsString::from_vec(
        parsed.certname,
    )));
    // `:527-530`
    if let Some(passphrase) = parsed.passphrase {
        *password = Some(String::from_utf8_lossy(&passphrase).into_owned());
    }
    Ok(())
}

/// `replace_url_encoded_space_by_plus` -- `src/tool_getparam.c:489-515`,
/// "Replace (in-place) '%20' by '+' according to RFC1866".
///
/// C rewrites the buffer and returns the new length. Here the rewrite produces a
/// new buffer, which is the same transformation without the aliasing: the C
/// version reads `url[orig_index + 1]` and `[+ 2]` past the end of a trailing
/// `%`, safe there only because of the NUL terminator. Slicing with `get`
/// removes that dependence without changing any accepted input.
fn replace_url_encoded_space_by_plus(url: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(url.len());
    let mut at = 0;
    while at < url.len() {
        if url.get(at..at + 3) == Some(b"%20".as_slice()) {
            out.push(b'+');
            at += 3;
        } else {
            if let Some(byte) = url.get(at) {
                out.push(*byte);
            }
            at += 1;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Size parsing -- `src/tool_getparam.c:535-623`
// ---------------------------------------------------------------------------

/// `struct sizeunit` -- `src/tool_getparam.c:535-539`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SizeUnit {
    /// `unit` -- "single lowercase ASCII letter".
    unit: u8,
    /// `mul` -- the multiplier.
    mul: i64,
    /// `mlen` -- "number of digits in 'mul', when written in decimal". It is
    /// what bounds a fractional part: `:604` trims precision digits while
    /// `su->mlen <= plen`.
    mlen: usize,
}

/// The five accepted suffixes -- `src/tool_getparam.c:543-549`.
///
/// Peta, Tera, Giga, Mega, Kilo, each with the decimal width of its multiplier.
const SIZE_UNITS: [SizeUnit; 5] = [
    SizeUnit {
        unit: b'p',
        mul: 1_125_899_906_842_624,
        mlen: 16,
    },
    SizeUnit {
        unit: b't',
        mul: 1_099_511_627_776,
        mlen: 13,
    },
    SizeUnit {
        unit: b'g',
        mul: 1_073_741_824,
        mlen: 10,
    },
    SizeUnit {
        unit: b'm',
        mul: 1_048_576,
        mlen: 7,
    },
    SizeUnit {
        unit: b'k',
        mul: 1024,
        mlen: 4,
    },
];

/// `getunit` -- `src/tool_getparam.c:541-556`.
///
/// The match is `(unit | 0x20) == list[i].unit` (`:553`), which folds an ASCII
/// upper-case letter to lower case by setting bit 5. It is deliberately not
/// `to_lowercase`: that would fold non-ASCII code points and would depend on
/// Unicode data, and the table holds only ASCII. The `| 0x20` form also folds
/// bytes that are not letters at all, so `'K' | 0x20 == 'k'` and
/// `'\x4b' | 0x20` agree with C on every input, letter or not.
fn getunit(unit: u8) -> Option<&'static SizeUnit> {
    SIZE_UNITS.iter().find(|entry| (unit | 0x20) == entry.unit)
}

/// `curlx_str_number` for a `curl_off_t` -- the leading-digit scan
/// `src/tool_getparam.c:573` and `:581` perform.
///
/// Returns the value and the number of digits consumed. `Err(true)` is C's
/// `STRE_OVERFLOW`, which `:574-575` maps to
/// [`ParameterError::NumberTooLarge`]; `Err(false)` is any other failure,
/// including "no digits at all", which `:576-577` maps to
/// [`ParameterError::BadNumeric`].
fn str_number(text: &[u8], max: i64) -> Result<(i64, usize), bool> {
    let digits = text.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if digits == 0 {
        return Err(false);
    }
    let mut value: i64 = 0;
    for byte in text.iter().take(digits) {
        let digit = i64::from(byte - b'0');
        value = value
            .checked_mul(10)
            .and_then(|scaled| scaled.checked_add(digit))
            .ok_or(true)?;
        if value > max {
            return Err(true);
        }
    }
    Ok((value, digits))
}

/// `GetSizeParameter` -- `src/tool_getparam.c:563-623`, "Unit test 1623".
///
/// Accepts `<digits>[.<digits>][suffix]` where the suffix is one of `P T G M K`
/// case-insensitively, or `b`/`B`, or nothing. Every rejection is C's:
///
/// * a leading value that overflows -> [`ParameterError::NumberTooLarge`]
///   (`:574-575`); any other failure to read one -> `BadNumeric` (`:576-577`);
/// * a fractional part that is not a number -> `BadNumeric` (`:581-582`);
/// * more than one trailing byte -> `BadUse` (`:586-587`);
/// * a fractional part with no unit, or with `b`/`B` -> `BadUse` (`:588-592`),
///   because "cannot handle partial bytes";
/// * an unrecognised suffix -> `BadUse` (`:595-596`);
/// * a product that does not fit -> `NumberTooLarge` (`:618-619`).
///
/// The fraction arithmetic is reproduced exactly, including the two-way
/// multiply at `:612-615` that avoids overflowing before dividing.
#[allow(dead_code)] // Reached from `opt_string`; also the unit under test for
                    // "Unit test 1623".
pub(crate) fn get_size_parameter(arg: &[u8]) -> Result<i64, ParameterError> {
    // `:573-577`
    let (value, consumed) = match str_number(arg, CURL_OFF_T_MAX) {
        Ok(pair) => pair,
        Err(true) => return Err(ParameterError::NumberTooLarge),
        Err(false) => return Err(ParameterError::BadNumeric),
    };
    let mut rest = arg.get(consumed..).unwrap_or_default();

    // `:579-584` -- an optional `.` introduces a fractional part, and `plen` is
    // how many digits it had.
    let mut prec: i64 = 0;
    let mut plen: usize = 0;
    if rest.first() == Some(&b'.') {
        rest = rest.get(1..).unwrap_or_default();
        match str_number(rest, CURL_OFF_T_MAX) {
            Ok((parsed, digits)) => {
                prec = parsed;
                plen = digits;
                rest = rest.get(digits..).unwrap_or_default();
            }
            Err(_) => return Err(ParameterError::BadNumeric),
        }
    }

    let mut add: i64 = 0;
    let mut mul: i64 = 1;

    // `:586-587` -- `if(strlen(unit) > 1) return PARAM_BAD_USE;`
    if rest.len() > 1 {
        return Err(ParameterError::BadUse);
    } else if rest.is_empty()
        || rest.first().is_some_and(|unit| (unit | 0x20) == b'b')
    {
        // `:588-592` -- a bare number or a `b`/`B` suffix, which cannot carry a
        // fraction.
        if plen != 0 {
            return Err(ParameterError::BadUse);
        }
    } else {
        // `:594-596`
        let Some(unit) = rest.first().and_then(|byte| getunit(*byte)) else {
            return Err(ParameterError::BadUse);
        };
        mul = unit.mul;

        // `:599-616`
        if prec != 0 {
            let mut frac: i64 = 1;

            // `:603-607` -- "too many precision digits, trim them".
            while unit.mlen <= plen {
                prec /= 10;
                plen -= 1;
            }

            // `:609-610`
            while plen != 0 {
                frac = frac.saturating_mul(10);
                plen -= 1;
            }

            // `:612-615` -- pick the order of operations that cannot overflow.
            add = if (CURL_OFF_T_MAX / mul) > prec {
                mul.saturating_mul(prec) / frac
            } else {
                (mul / frac).saturating_mul(prec)
            };
        }
    }

    // `:618-619`
    if value > ((CURL_OFF_T_MAX - add) / mul) {
        return Err(ParameterError::NumberTooLarge);
    }

    // `:621`
    Ok(value.saturating_mul(mul).saturating_add(add))
}

// ---------------------------------------------------------------------------
// `--ip-tos` -- `src/tool_getparam.c:848-892`
// ---------------------------------------------------------------------------

/// `struct TOSEntry` -- `src/tool_getparam.c:848-851`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TosEntry {
    /// `name` -- the DSCP or legacy IP-precedence keyword.
    name: &'static str,
    /// `value` -- the byte written to `config->ip_tos`.
    value: u8,
}

/// `tos_entries[]` -- `src/tool_getparam.c:853-885`.
///
/// Thirty-one keywords, sorted for `bsearch` (`:2470-2472`) with `find_tos`
/// comparing by `strcmp` (`:887-892`) -- so the lookup is **case-sensitive**,
/// unlike [`getunit`]. `--ip-tos af11` is therefore not `AF11`; it falls through
/// to the numeric branch at `:2476` and is rejected as a number. Three values
/// repeat legitimately: `ECT0`, `LOWCOST` and `MINCOST` are all `0x02`, and
/// `CE`/`LE`/`RELIABILITY` overlap likewise, because the legacy IP-precedence
/// names and the DSCP names share a field.
const TOS_ENTRIES: [TosEntry; 31] = [
    TosEntry {
        name: "AF11",
        value: 0x28,
    },
    TosEntry {
        name: "AF12",
        value: 0x30,
    },
    TosEntry {
        name: "AF13",
        value: 0x38,
    },
    TosEntry {
        name: "AF21",
        value: 0x48,
    },
    TosEntry {
        name: "AF22",
        value: 0x50,
    },
    TosEntry {
        name: "AF23",
        value: 0x58,
    },
    TosEntry {
        name: "AF31",
        value: 0x68,
    },
    TosEntry {
        name: "AF32",
        value: 0x70,
    },
    TosEntry {
        name: "AF33",
        value: 0x78,
    },
    TosEntry {
        name: "AF41",
        value: 0x88,
    },
    TosEntry {
        name: "AF42",
        value: 0x90,
    },
    TosEntry {
        name: "AF43",
        value: 0x98,
    },
    TosEntry {
        name: "CE",
        value: 0x03,
    },
    TosEntry {
        name: "CS0",
        value: 0x00,
    },
    TosEntry {
        name: "CS1",
        value: 0x20,
    },
    TosEntry {
        name: "CS2",
        value: 0x40,
    },
    TosEntry {
        name: "CS3",
        value: 0x60,
    },
    TosEntry {
        name: "CS4",
        value: 0x80,
    },
    TosEntry {
        name: "CS5",
        value: 0xa0,
    },
    TosEntry {
        name: "CS6",
        value: 0xc0,
    },
    TosEntry {
        name: "CS7",
        value: 0xe0,
    },
    TosEntry {
        name: "ECT0",
        value: 0x02,
    },
    TosEntry {
        name: "ECT1",
        value: 0x01,
    },
    TosEntry {
        name: "EF",
        value: 0xb8,
    },
    TosEntry {
        name: "LE",
        value: 0x04,
    },
    TosEntry {
        name: "LOWCOST",
        value: 0x02,
    },
    TosEntry {
        name: "LOWDELAY",
        value: 0x10,
    },
    TosEntry {
        name: "MINCOST",
        value: 0x02,
    },
    TosEntry {
        name: "RELIABILITY",
        value: 0x04,
    },
    TosEntry {
        name: "THROUGHPUT",
        value: 0x08,
    },
    TosEntry {
        name: "VOICE-ADMIT",
        value: 0xb0,
    },
];

/// `find_tos` as the comparator of the `bsearch` at
/// `src/tool_getparam.c:2470-2472`.
fn find_tos(name: &[u8]) -> Option<&'static TosEntry> {
    let name = std::str::from_utf8(name).ok()?;
    let at = TOS_ENTRIES
        .binary_search_by(|probe| findarg(probe.name, name))
        .ok()?;
    TOS_ENTRIES.get(at)
}

// ---------------------------------------------------------------------------
// `--upload-flags` -- `src/tool_getparam.c:1651-1709`
// ---------------------------------------------------------------------------

/// `struct flagmap` -- `src/tool_getparam.c:1651-1655`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FlagMap {
    /// `name` -- the keyword.
    name: &'static str,
    /// `flag` -- the `CURLULFLAG_*` bit.
    flag: u8,
}

/// `flag_table[]` -- `src/tool_getparam.c:1657-1664`.
///
/// C terminates with `{ NULL, 0, 0 }` and detects "no match" by reaching it
/// (`:1697`); the Rust form needs no terminator because the search reports
/// absence directly. C's `len` column is `strlen(name)` and is compared before
/// `strncmp` (`:1688`), which makes the match whole-token rather than a prefix
/// -- reproduced by comparing the token to the whole name.
const FLAG_TABLE: [FlagMap; 5] = [
    FlagMap {
        name: "answered",
        flag: CURLULFLAG_ANSWERED,
    },
    FlagMap {
        name: "deleted",
        flag: CURLULFLAG_DELETED,
    },
    FlagMap {
        name: "draft",
        flag: CURLULFLAG_DRAFT,
    },
    FlagMap {
        name: "flagged",
        flag: CURLULFLAG_FLAGGED,
    },
    FlagMap {
        name: "seen",
        flag: CURLULFLAG_SEEN,
    },
];

/// `parse_upload_flags` -- `src/tool_getparam.c:1666-1709`.
///
/// A comma-separated list of keywords, each optionally prefixed `-` to clear
/// rather than set. An unknown keyword stops the walk with
/// [`ParameterError::OptionUnknown`] (`:1697-1700`), leaving the flags set so
/// far applied -- C does not roll back, and neither does this.
fn parse_upload_flags(
    config: &mut OperationConfig,
    flags: &[u8],
) -> Result<(), ParameterError> {
    let mut rest = Some(flags);
    while let Some(flag) = rest {
        // `:1675-1679` -- the token runs to the next comma or to the end.
        let comma = flag.iter().position(|byte| *byte == b',');
        let (token, next) = match comma {
            // `:1702-1704` -- "move over the comma".
            Some(at) => {
                (flag.get(..at).unwrap_or_default(), flag.get(at + 1..))
            }
            None => (flag, None),
        };

        // `:1681-1685`
        let negate = token.first() == Some(&b'-');
        let name = if negate {
            token.get(1..).unwrap_or_default()
        } else {
            token
        };

        // `:1687-1695`
        let found = FLAG_TABLE
            .iter()
            .find(|entry| entry.name.as_bytes() == name);
        match found {
            Some(entry) => {
                if negate {
                    config.upload_flags &= !entry.flag;
                } else {
                    config.upload_flags |= entry.flag;
                }
            }
            // `:1697-1700`
            None => return Err(ParameterError::OptionUnknown),
        }

        rest = next;
    }
    Ok(())
}

/// `togglebit` -- `src/tool_getparam.c:1711-1720`, "if 'toggle' is TRUE, set the
/// 'bits' in 'modify'. If 'toggle' is FALSE, clear the 'bits' in 'modify'".
fn togglebit(toggle: bool, modify: &mut u64, bits: u64) {
    if toggle {
        *modify |= bits;
    } else {
        *modify &= !bits;
    }
}

/// `has_leading_unicode` -- `src/tool_getparam.c:2879-2883`, with the C comment
/// "detect e2 80 80 - e2 80 ff".
///
/// ```c
/// return (arg[0] == 0xe2) && (arg[1] == 0x80) && (arg[2] & 0x80);
/// ```
///
/// The three reads are unguarded in C and safe there only because the argument
/// is NUL-terminated -- a one- or two-byte argument stops the `&&` chain at the
/// terminator. Slice access reproduces that without the dependence on a
/// terminator: a short argument simply has no third byte and cannot match, which
/// [`mod tests`](self) asserts for both the one- and two-byte cases.
///
/// The range is the Unicode general-punctuation block that begins at U+2000, so
/// it catches an en dash or a non-breaking hyphen pasted where an ASCII `-` was
/// meant.
fn has_leading_unicode(arg: &[u8]) -> bool {
    arg.first() == Some(&0xe2)
        && arg.get(1) == Some(&0x80)
        && arg.get(2).is_some_and(|byte| byte & 0x80 != 0)
}

// ---------------------------------------------------------------------------
// `src/tool_helpers.c` folded in
// ---------------------------------------------------------------------------

/// `reqname[]` -- `src/tool_helpers.c:80-87`, carrying the C comment "this
/// mirrors the HttpReq enum in tool_sdecls.h".
///
/// Indexed by [`HttpReq`], whose discriminants are `Unspec = 0` through
/// `Put = 5` (`curl-rs/src/config/mod.rs`), so the order is load-bearing and the
/// empty first entry is the `Unspec` placeholder C leaves blank.
const REQNAME: [&str; 6] = [
    "", /* unspec */
    "GET (-G, --get)",
    "HEAD (-I, --head)",
    "multipart formpost (-F, --form)",
    "POST (-d, --data)",
    "PUT (-T, --upload-file)",
];

/// `dflt[]` -- `src/tool_helpers.c:104-111`, the method each request shape
/// already implies.
const REQ_DEFAULT_METHOD: [&str; 6] =
    ["GET", "GET", "HEAD", "POST", "POST", "PUT"];

/// `SetHTTPrequest` -- `src/tool_helpers.c:77-99`.
///
/// Records `req` in `store` and reports whether it conflicted. C returns `int`;
/// `bool` says the same thing, and every caller tests it as a condition
/// (`src/tool_getparam.c:2113`, `:2772`).
///
/// `true` means "conflict", and the caller turns it into
/// [`ParameterError::BadUse`]. Setting is accepted when nothing has been chosen
/// yet **or** when the same shape is chosen again (`:89-93`), which is why
/// `-I -I` is not an error.
///
/// The warning is frozen, and so is its argument order: `reqname[req]` first,
/// `reqname[*store]` second (`:94-96`) -- the option the user just gave, then the
/// one already in force.
#[allow(dead_code)] // Reached from `opt_bool` and `opt_string`.
pub(crate) fn set_http_request(
    req: HttpReq,
    store: &mut HttpReq,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> bool {
    // `:89-93`
    if *store == HttpReq::Unspec || *store == req {
        *store = req;
        return false;
    }
    // `:94-96`
    let asked = REQNAME.get(req as usize).copied().unwrap_or_default();
    let already = REQNAME.get(*store as usize).copied().unwrap_or_default();
    warnf(
        sink,
        msgs,
        format_args!(
            "You can only select one HTTP request method! You asked for both {asked} and {already}."
        ),
    );
    true
}

/// `customrequest_helper` -- `src/tool_helpers.c:101-123`.
///
/// Comments on a `-X` that was unnecessary or is likely to surprise. Both
/// comparisons are `curl_strequal`, ASCII case-insensitive, so `-X get` is as
/// redundant as `-X GET` and `-X HEAD` warns as `-X head` does.
///
/// The note is gated on the trace setting and the warning on `--silent`, which
/// is [`notef`] and [`warnf`] respectively; nothing is written to a stream
/// directly.
#[allow(dead_code)] // Called from the operation driver after parsing, per
                    // `src/tool_operate.c`.
pub(crate) fn customrequest_helper(
    req: HttpReq,
    method: Option<&str>,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) {
    // `:113-114` -- `if(!method) ;`
    let Some(method) = method else {
        return;
    };
    let inferred = REQ_DEFAULT_METHOD
        .get(req as usize)
        .copied()
        .unwrap_or_default();
    if method.eq_ignore_ascii_case(inferred) {
        // `:115-118`
        notef(
            sink,
            msgs,
            format_args!(
                "Unnecessary use of -X or --request, {inferred} is already inferred."
            ),
        );
    } else if method.eq_ignore_ascii_case("head") {
        // `:119-122`
        warnf(
            sink,
            msgs,
            format_args!(
                "Setting custom HTTP method to HEAD with -X/--request may not work the way you want. Consider using -I/--head instead."
            ),
        );
    }
}

/// `opt_depr` -- `src/tool_getparam.c:1722-1726`, "the function that handles
/// ARG_DEPR options".
///
/// Warns and returns; the caller then `break`s out of the option loop **without
/// applying anything** (`:3014-3017`, `:3031-3034`). The nine rows are
/// `egd-file`, `krb`, `krb4`, `metalink`, `npn`, `ntlm-wb`, `random-file`,
/// `sslv2` and `sslv3`; the last two carry the short letters `2` and `3`, so
/// `-2` and `-3` warn too.
fn opt_depr(
    alias: &LongShort,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) {
    let name = alias.lname;
    warnf(
        sink,
        msgs,
        format_args!("--{name} is deprecated and has no function anymore"),
    );
}

/// `opt_sslver` -- `src/tool_getparam.c:1728-1738`.
///
/// Sets the minimum TLS version, refusing to place it above an already-set
/// maximum. The comparison is `config->ssl_version_max && (max < ver)`, so a
/// maximum of zero -- unset -- never blocks.
fn opt_sslver(
    config: &mut OperationConfig,
    ver: u8,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    if config.ssl_version_max != 0 && config.ssl_version_max < ver {
        errorf(
            sink,
            msgs,
            format_args!("Minimum TLS version set higher than max"),
        );
        return Err(ParameterError::BadUse);
    }
    config.ssl_version = ver;
    Ok(())
}

/// `existingfile` -- `src/tool_getparam.c:2207-2218`.
///
/// Refuses a filename that does not exist, naming the option in the message.
/// Five rows use it -- `--cacert`, `--crlfile`, `--knownhosts`, `--netrc-file`
/// and `--proxy-cacert`, plus `--proxy-crlfile` -- and the rest of `ARG_FILE`
/// does not, so a missing `--output` path is still accepted and created later.
fn existingfile<H: ParseHost>(
    alias: &LongShort,
    filename: &[u8],
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<std::path::PathBuf, ParameterError> {
    if !host.exists(filename) {
        let shown = String::from_utf8_lossy(filename);
        let name = alias.lname;
        errorf(
            sink,
            msgs,
            format_args!(
                "The file '{shown}' provided to --{name} does not exist"
            ),
        );
        return Err(ParameterError::BadUse);
    }
    getstr_path(filename, DENY_BLANK)
}

// ---------------------------------------------------------------------------
// Reading files the option arguments name
// ---------------------------------------------------------------------------

/// Adapts a [`ByteSource`] to [`std::io::Read`].
///
/// [`file2string`] takes `&mut dyn Read` while [`file2memory`] takes
/// `&mut dyn ByteSource`, and [`VarHost::open`] produces the latter. One
/// forwarding `read` bridges them; `paramhlp`'s own `StreamSource` goes the
/// other way and cannot be used here.
struct ByteSourceReader<'a> {
    inner: &'a mut dyn ByteSource,
}

impl std::io::Read for ByteSourceReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read_block(buffer)
    }
}

/// Where an option argument beginning `@` reads from.
///
/// C opens `nextarg + 1` with `curlx_fopen`, or uses `stdin` when it is `-`
/// (`src/tool_getparam.c:676-686`, `:949-960`, `:1139-1143`, `:1288-1289`,
/// `:1581-1592`). `None` is C's `!file`, which every caller reports as a read
/// error after naming the file.
fn open_argument<H: ParseHost>(
    host: &mut H,
    name: &[u8],
) -> Option<Box<dyn ByteSource>> {
    if name == b"-" {
        Some(host.stdin())
    } else {
        host.open(name).ok()
    }
}

/// `my_get_line` -- `src/tool_parsecfg.c:325-347`, over the bytes of a source.
///
/// GAP #5 (continued): `my_get_line` is declared in
/// `src/tool_parsecfg.h:31` and
/// defined in `src/tool_parsecfg.c`, whose port
/// `curl-rs/src/config/parseconfig.rs` does not exist in this checkout. Two
/// options here need it -- `--url @file` (`:1145`) and `--header @file`
/// (`:1298`) -- so the line rule is reproduced locally. It is the same code C
/// shares; when that module arrives, this function is what it replaces.
/// Reported rather than worked around.
///
/// The rule, exactly:
///
/// * a line ends at `\n`, and **only the `\n` is dropped** (`:305-310`), so a
///   CRLF file leaves the `\r` on the line -- which is what C stores;
/// * a final line with no newline is still returned (`:311-315`);
/// * a line whose first non-blank byte is `#` is skipped, as is a line that is
///   empty or blank-only (`:334-342`);
/// * a line longer than `max` is C's `curlx_dyn_addn` failure, which sets
///   `*error` and every caller turns into [`ParameterError::ReadError`]
///   (`:296-301`).
fn read_lines(
    source: &mut dyn ByteSource,
    max: usize,
) -> Result<Vec<Vec<u8>>, ParameterError> {
    let mut reader = ByteSourceReader { inner: source };
    let mut all = Vec::new();
    if std::io::Read::read_to_end(&mut reader, &mut all).is_err() {
        return Err(ParameterError::ReadError);
    }

    let mut lines = Vec::new();
    for raw in all.split(|byte| *byte == b'\n') {
        // `split` yields a trailing empty slice for input that ends in `\n`;
        // C's loop simply reaches end of file there, and an empty line is
        // skipped anyway by the rule below.
        if raw.len() > max {
            return Err(ParameterError::ReadError);
        }
        // `:334-339`
        let first = raw.iter().find(|byte| **byte != b' ' && **byte != b'\t');
        match first {
            None | Some(b'#') => continue,
            Some(_) => lines.push(raw.to_vec()),
        }
    }
    Ok(lines)
}

// ---------------------------------------------------------------------------
// `--data-urlencode` and `--url-query` -- `src/tool_getparam.c:643-743`,
// `:894-928`
// ---------------------------------------------------------------------------

/// `data_urlencode` -- `src/tool_getparam.c:643-743`.
///
/// Accepts the four documented shapes and encodes only the value half:
/// `name=value`, `name@filename`, `=value` and `@filename`, with `-` standing
/// for standard input in either `@` form.
///
/// The separator search is `strchr(nextarg, '=')` first and `strchr(nextarg,
/// '@')` only if there is no `=` (`:655-662`), so `a@b=c` splits at the `=` and
/// is *not* a file reference. With neither separator the whole argument is the
/// value and no name is prepended (`:667-672`).
///
/// `%20` becomes `+` after encoding (`:715`), per RFC 1866.
fn data_urlencode<H: ParseHost>(
    nextarg: &[u8],
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<Vec<u8>, ParameterError> {
    // `:655-672`
    let equals = nextarg.iter().position(|byte| *byte == b'=');
    let separator = match equals {
        Some(at) => Some(at),
        None => nextarg.iter().position(|byte| *byte == b'@'),
    };
    let (nlen, is_file, value) = match separator {
        Some(at) => (
            at,
            nextarg.get(at).copied().unwrap_or(0),
            nextarg.get(at + 1..).unwrap_or_default(),
        ),
        None => (0, 0, nextarg),
    };

    // `:673-700`
    let postdata: Vec<u8> = if is_file == b'@' {
        let Some(mut source) = open_argument(host, value) else {
            let shown = String::from_utf8_lossy(value);
            errorf(sink, msgs, format_args!("Failed to open {shown}"));
            return Err(ParameterError::ReadError);
        };
        file2memory(Some(&mut *source))?
    } else {
        getstr(value, ALLOW_BLANK)?
    };

    // `:702-709` -- an empty read still posts, as an empty encoded value.
    if postdata.is_empty() {
        return Ok(Vec::new());
    }

    // `:711-733` -- `curl_easy_escape` then the `%20` fix-up, then the name.
    let encoded = replace_url_encoded_space_by_plus(
        &curl_rs_lib::url::escape::escape(&postdata),
    );
    if nlen == 0 {
        return Ok(encoded);
    }
    let mut out = Vec::with_capacity(nlen + 1 + encoded.len());
    out.extend_from_slice(nextarg.get(..nlen).unwrap_or_default());
    out.push(b'=');
    out.extend_from_slice(&encoded);
    // `:718` bounds the assembled string at `MAX_DATAURLENCODE`.
    if out.len() > MAX_DATAURLENCODE {
        return Err(ParameterError::NoMem);
    }
    Ok(out)
}

/// `url_query` -- `src/tool_getparam.c:895-928`.
///
/// `--url-query` appends to a growing query string, separated by `&`. A leading
/// `+` means "already encoded, use as is" (`:904-909`); anything else goes
/// through [`data_urlencode`].
fn url_query<H: ParseHost>(
    nextarg: &[u8],
    config: &mut OperationConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    // `:904-911`
    let query = if nextarg.first() == Some(&b'+') {
        nextarg.get(1..).unwrap_or_default().to_vec()
    } else {
        data_urlencode(nextarg, host, sink, msgs)?
    };
    let query = String::from_utf8_lossy(&query).into_owned();

    // `:913-926`
    match config.query.take() {
        Some(existing) => {
            let joined = format!("{existing}&{query}");
            // `:902` bounds the buffer at `MAX_QUERY_LEN`.
            if joined.len() > MAX_QUERY_LEN {
                return Err(ParameterError::NoMem);
            }
            config.query = Some(joined);
        }
        None => config.query = Some(query),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `-d` and friends -- `src/tool_getparam.c:930-1073`
// ---------------------------------------------------------------------------

/// `set_data` -- `src/tool_getparam.c:930-1008`.
///
/// The whole `--data` family. The shape depends on the key:
///
/// * `--data-urlencode` delegates to [`data_urlencode`] (`:939-943`);
/// * a leading `@` reads a file, or standard input for `-`, for every key
///   **except** `--data-raw` (`:944-960`);
/// * `--data-binary` and `--json` read the file verbatim, everything else reads
///   it as text with newlines removed (`:962-970`);
/// * anything else is the literal argument, blanks allowed (`:985-990`).
///
/// Repeated options concatenate with `&` between them, and `--json` is the one
/// exception: it appends with no separator (`:994-999`). `--json` also sets
/// `jsoned` (`:991-992`), and every key leaves `postfields` designated
/// (`:1006`).
fn set_data<H: ParseHost>(
    cmd: CmdKey,
    nextarg: &[u8],
    config: &mut OperationConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    let postdata: Vec<u8> = if cmd == CmdKey::DataUrlencode {
        // `:939-943`
        data_urlencode(nextarg, host, sink, msgs)?
    } else if nextarg.first() == Some(&b'@') && cmd != CmdKey::DataRaw {
        // `:944-983` -- "the data begins with a '@' letter, it means that a
        // filename or - (stdin) follows".
        let name = nextarg.get(1..).unwrap_or_default();
        let Some(mut source) = open_argument(host, name) else {
            let shown = String::from_utf8_lossy(name);
            errorf(sink, msgs, format_args!("Failed to open {shown}"));
            return Err(ParameterError::ReadError);
        };
        if cmd == CmdKey::DataBinary || cmd == CmdKey::Json {
            // `:962-965` -- "forced binary".
            file2memory(Some(&mut *source))?
        } else {
            // `:966-970`
            let mut reader = ByteSourceReader {
                inner: &mut *source,
            };
            file2string(Some(&mut reader))?
        }
    } else {
        // `:985-990`
        getstr(nextarg, ALLOW_BLANK)?
    };

    // `:991-992`
    if cmd == CmdKey::Json {
        config.jsoned = true;
    }

    // `:994-999` -- "skip separator append for --json".
    if !config.postdata.is_empty() && cmd != CmdKey::Json {
        config.postdata.push(b'&');
    }
    // `:1001-1002`
    config.postdata.extend_from_slice(&postdata);
    // `:1006`
    config.postfields = true;
    Ok(())
}

/// `set_rate` -- `src/tool_getparam.c:1010-1073`.
///
/// `--rate` gives a number of transfers per unit of time, and the result is
/// stored as milliseconds per transfer. The suffix grammar is
/// `<count>[/<n><unit>]` where the unit is `s`, `m`, `h` (the default) or `d`,
/// and `<n>` defaults to 1 when absent (`:1034-1035`).
///
/// Both frozen errors are here: "unsupported --rate unit" for an unknown suffix
/// (`:1050`) and "too large --rate unit" when the numerator overflows
/// (`:1057`). A denominator larger than the numerator -- more transfers than
/// there are milliseconds -- is [`ParameterError::NumberTooLarge`] (`:1067`).
fn set_rate(
    nextarg: &[u8],
    global: &mut GlobalConfig,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    // `:1023` -- "default per hour".
    let mut numerator: i64 = 60 * 60 * 1000;

    // `:1025-1026`
    let Ok((denominator, consumed)) = str_number(nextarg, CURL_OFF_T_MAX)
    else {
        return Err(ParameterError::BadNumeric);
    };
    // `:1028-1029`
    if denominator < 1 {
        return Err(ParameterError::BadUse);
    }
    let mut rest = nextarg.get(consumed..).unwrap_or_default();

    // `:1031-1063`
    if rest.first() == Some(&b'/') {
        rest = rest.get(1..).unwrap_or_default();
        // `:1034-1035` -- an unreadable count is 1, not an error.
        let numunits = match str_number(rest, CURL_OFF_T_MAX) {
            Ok((value, digits)) => {
                rest = rest.get(digits..).unwrap_or_default();
                value
            }
            Err(_) => 1,
        };

        // `:1037-1053`
        match rest.first() {
            Some(b's') => numerator = 1000,
            Some(b'm') => numerator = 60 * 1000,
            Some(b'h') => {}
            Some(b'd') => numerator = 24 * 60 * 60 * 1000,
            _ => {
                errorf(sink, msgs, format_args!("unsupported --rate unit"));
                return Err(ParameterError::BadUse);
            }
        }

        // `:1055-1062`
        if (CURL_OFF_T_MAX / numerator) < numunits {
            errorf(sink, msgs, format_args!("too large --rate unit"));
            return Err(ParameterError::NumberTooLarge);
        }
        numerator = numerator.saturating_mul(numunits);
    }

    // `:1067-1070`
    if denominator > numerator {
        return Err(ParameterError::NumberTooLarge);
    }
    global.ms_per_transfer = numerator / denominator;
    Ok(())
}

/// `sethttpver` -- `src/tool_getparam.c:745-752`.
///
/// Warns when a second, different HTTP version option overrides an earlier one.
/// The guard is `config->httpversion && (config->httpversion != httpversion)`,
/// so repeating the same option is silent and setting it from unset is silent.
fn sethttpver(
    config: &mut OperationConfig,
    httpversion: i64,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) {
    if config.httpversion != 0 && config.httpversion != httpversion {
        warnf(
            sink,
            msgs,
            format_args!("Overrides previous HTTP version option"),
        );
    }
    config.httpversion = httpversion;
}

/// `set_trace_config` -- `src/tool_getparam.c:754-819`.
///
/// Walks a comma-separated list of trace component names, each optionally
/// prefixed `+` or `-`. Three names are handled here and the rest are forwarded:
///
/// * `all` sets both local mirrors and forwards `all,-lib-ids` when enabling, or
///   the token as given when disabling (`:786-795`);
/// * `ids` and `time` set only the local mirrors (`:796-801`);
/// * anything else is forwarded as `+name,-lib-ids` or `-name,-lib-ids`
///   (`:802-809`).
///
/// The `-lib-ids` suffix is what keeps libcurl from prefixing its own trace
/// lines with identifiers the tool prints itself. A separator is followed by an
/// optional single space (`:810-814`), so `--trace-config "ids, time"` parses.
///
/// A forwarding failure is C's `CURLcode`, which every caller reports as
/// [`ParameterError::NoMem`] (`:1522`, `:1549`, `:1555`, `:1560`, `:2588`).
fn set_trace_config<H: ParseHost>(
    token: &[u8],
    global: &mut GlobalConfig,
    host: &mut H,
) -> Result<(), ParameterError> {
    let mut rest = Some(token);
    while let Some(token) = rest {
        // `:762-767`
        let comma = token.iter().position(|byte| *byte == b',');
        let (whole, next) = match comma {
            Some(at) => (token.get(..at).unwrap_or_default(), Some(at)),
            None => (token, None),
        };

        // `:769-784`
        let (toggle, name) = match whole.first() {
            Some(b'-') => (false, whole.get(1..).unwrap_or_default()),
            Some(b'+') => (true, whole.get(1..).unwrap_or_default()),
            _ => (true, whole),
        };

        if name.eq_ignore_ascii_case(b"all") {
            // `:786-795`
            global.traceids = toggle;
            global.tracetime = toggle;
            // `:789-792` -- enabling forwards a fixed string, but disabling
            // forwards `token`, which is the cursor into the list and therefore
            // carries every remaining component too. That re-processes the tail
            // and then the loop processes it again; the double application is
            // idempotent, and reproducing it keeps `--trace-config "-all,ssl"`
            // behaving as C does rather than as the reading of `-all` alone
            // would suggest.
            let disabled = String::from_utf8_lossy(token).into_owned();
            let forwarded: &str =
                if toggle { "all,-lib-ids" } else { &disabled };
            if !host.set_trace(forwarded) {
                return Err(ParameterError::NoMem);
            }
        } else if name.eq_ignore_ascii_case(b"ids") {
            // `:796-798`
            global.traceids = toggle;
        } else if name.eq_ignore_ascii_case(b"time") {
            // `:799-801`
            global.tracetime = toggle;
        } else {
            // `:802-809` -- `"%c%.*s,-lib-ids"`, bounded by C's 64-byte buffer.
            let shown = String::from_utf8_lossy(name);
            let sign = if toggle { '+' } else { '-' };
            let mut forwarded = format!("{sign}{shown},-lib-ids");
            forwarded.truncate(63);
            if !host.set_trace(&forwarded) {
                return Err(ParameterError::NoMem);
            }
        }

        // `:810-815` -- step over the comma and one optional space.
        rest = next.and_then(|at| {
            let after = token.get(at + 1..)?;
            if after.first() == Some(&b' ') {
                after.get(1..)
            } else {
                Some(after)
            }
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// URL and output nodes -- `src/tool_getparam.c:1084-1509`
// ---------------------------------------------------------------------------

/// `add_url` -- `src/tool_getparam.c:1084-1125`.
///
/// Fills the next URL-less node in the operation's list, creating one when every
/// existing node already has a URL. `url_get` is the cursor C advances past
/// filled nodes (`:1091-1099`); a `None` cursor starts at the head.
///
/// `remote_noglob` is set only by `--url @file` (`:1147`), which treats every
/// line as `-O` with globbing off.
///
/// The etag check at `:1118-1122` is the frozen error "The etag options only
/// work on a single URL", and it fires on the *second* URL, because `num_urls`
/// is incremented first.
fn add_url(
    config: &mut OperationConfig,
    thisurl: &[u8],
    remote_noglob: bool,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    // `:1091-1099` -- a `None` cursor starts at the head, then walks past
    // every node that already carries a URL. C's head is `config->url_list`,
    // which is `NULL` while the list is empty.
    let mut cursor = match config.url_get {
        Some(at) => Some(at),
        None if config.url_list.is_empty() => None,
        None => Some(0),
    };
    while let Some(at) = cursor {
        match config.url_list.get(at) {
            Some(node) if node.urlset => cursor = Some(at + 1),
            Some(_) => break,
            None => {
                cursor = None;
                break;
            }
        }
    }

    // `:1101-1111` -- reuse the free node, or create one.
    let at = match cursor {
        Some(at) => at,
        None => new_getout(config)?,
    };
    config.url_get = Some(at);

    // `:1113-1117`
    let url = getstr(thisurl, DENY_BLANK)?;
    let Some(node) = config.url_list.get_mut(at) else {
        return Err(ParameterError::NoMem);
    };
    node.url = Some(url);
    node.urlset = true;
    if remote_noglob {
        node.useremote = true;
        node.noglob = true;
    }

    // `:1118-1122`
    config.num_urls += 1;
    if config.num_urls > 1
        && (config.etag_save_file.is_some()
            || config.etag_compare_file.is_some())
    {
        errorf(
            sink,
            msgs,
            format_args!("The etag options only work on a single URL"),
        );
        return Err(ParameterError::BadUse);
    }
    Ok(())
}

/// `parse_url` -- `src/tool_getparam.c:1127-1161`.
///
/// `--url @file` reads one URL per line and treats them all as `-O`
/// (`:1131-1158`); anything else is a single URL. A file that cannot be opened,
/// a line that cannot be read and a URL that [`add_url`] rejects all collapse to
/// [`ParameterError::ReadError`] (`:1154-1158`) -- which is why an empty line in
/// such a file is skipped by [`read_lines`] rather than reported.
fn parse_url<H: ParseHost>(
    config: &mut OperationConfig,
    nextarg: &[u8],
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    if nextarg.first() != Some(&b'@') {
        return add_url(config, nextarg, false, sink, msgs);
    }

    // `:1131-1158` -- "read URLs from a file, treat all as -O".
    let name = nextarg.get(1..).unwrap_or_default();
    let Some(mut source) = open_argument(host, name) else {
        // `:1158` -- "file not found".
        return Err(ParameterError::ReadError);
    };
    // `:1144` -- `curlx_dyn_init(&line, 8092)`.
    let lines = read_lines(&mut *source, 8092)?;
    for line in lines {
        if add_url(config, &line, true, sink, msgs).is_err() {
            return Err(ParameterError::ReadError);
        }
    }
    Ok(())
}

/// `parse_localport` -- `src/tool_getparam.c:1163-1197`.
///
/// `--local-port <num>[-<num>]`, where the separator may carry one blank on
/// either side (`:1176-1182`). The range is stored as a base and a count, and
/// the count is derived by subtracting: `range -= (port - 1)` (`:1192`), so
/// `8000-8005` becomes base 8000, count 6.
///
/// Both bounds are capped at 65535 and a count below one is rejected
/// (`:1193-1194`).
fn parse_localport(
    config: &mut OperationConfig,
    nextarg: &[u8],
) -> Result<(), ParameterError> {
    // `:1170-1172`
    let plen = nextarg
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    let rest = nextarg.get(plen..).unwrap_or_default();

    // `:1173-1183`
    let mut upper: Option<&[u8]> = None;
    if !rest.is_empty() {
        let mut at = 0;
        if rest
            .get(at)
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            at += 1;
        }
        if rest.get(at) != Some(&b'-') {
            return Err(ParameterError::BadUse);
        }
        at += 1;
        if rest
            .get(at)
            .is_some_and(|byte| *byte == b' ' || *byte == b'\t')
        {
            at += 1;
        }
        upper = rest.get(at..);
    }

    // `:1184-1186` -- C formats the digits into a 22-byte buffer first, which
    // is exactly "the leading digits and nothing else".
    let base = String::from_utf8_lossy(nextarg.get(..plen).unwrap_or_default())
        .into_owned();
    let Ok(port) = str2unummax(&base, 65535) else {
        return Err(ParameterError::BadUse);
    };
    config.localport = port;

    match upper {
        // `:1187-1188` -- "default number of ports to try".
        None => config.localportrange = 1,
        // `:1189-1195`
        Some(text) => {
            let text = String::from_utf8_lossy(text).into_owned();
            let Ok(top) = str2unummax(&text, 65535) else {
                return Err(ParameterError::BadUse);
            };
            let count = top - (config.localport - 1);
            if count < 1 {
                return Err(ParameterError::BadUse);
            }
            config.localportrange = count;
        }
    }
    Ok(())
}

/// `parse_continue_at` -- `src/tool_getparam.c:1199-1226`.
///
/// `-C <offset>` or `-C -`. The three frozen mutual-exclusion errors come first,
/// against `--range`, `--remove-on-error` and `--no-clobber`
/// (`:1203-1214`); then `-` selects "resume from wherever the local file
/// already reaches" and anything else is a byte offset.
fn parse_continue_at(
    config: &mut OperationConfig,
    nextarg: &[u8],
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    // `:1203-1206`
    if config.range.is_some() {
        errorf(
            sink,
            msgs,
            format_args!("--continue-at is mutually exclusive with --range"),
        );
        return Err(ParameterError::BadUse);
    }
    // `:1207-1210`
    if config.rm_partial {
        errorf(
            sink,
            msgs,
            format_args!(
                "--continue-at is mutually exclusive with --remove-on-error"
            ),
        );
        return Err(ParameterError::BadUse);
    }
    // `:1211-1214`
    if config.file_clobber_mode == ClobberMode::Never {
        errorf(
            sink,
            msgs,
            format_args!(
                "--continue-at is mutually exclusive with --no-clobber"
            ),
        );
        return Err(ParameterError::BadUse);
    }

    // `:1216-1223`. The error is held rather than returned at once, because
    // C assigns `resume_from_current = FALSE` and `use_resume = TRUE`
    // unconditionally after the `if` and only then returns `err` -- so a
    // malformed offset still marks the transfer as resuming.
    let mut outcome = Ok(());
    if nextarg == b"-" {
        config.resume_from_current = true;
        config.resume_from = 0;
    } else {
        let text = String::from_utf8_lossy(nextarg).into_owned();
        match str2offset(&text) {
            Ok(offset) => config.resume_from = offset,
            Err(error) => outcome = Err(error),
        }
        config.resume_from_current = false;
    }
    // `:1224`
    config.use_resume = true;
    outcome
}

/// `parse_ech` -- `src/tool_getparam.c:1228-1277`.
///
/// `--ech` takes a keyword, a `pn:<name>` public name, or an `ecl:` ECHConfigList
/// that may itself be `ecl:@file` or `ecl:@-`.
///
/// The length tests are C's and they are asymmetric: `pn:` needs more than four
/// bytes and `ecl:` more than five (`:1234`, `:1238`), because each prefix plus
/// at least one payload byte is the minimum. The capability gate comes first
/// (`:1232-1233`), so `--ech` without ECH support is
/// [`ParameterError::LibcurlDoesntSupport`] whatever the argument.
///
/// The indirect form stores `ecl:` prepended to the file's contents (`:1266`),
/// not the filename.
fn parse_ech<H: ParseHost>(
    config: &mut OperationConfig,
    nextarg: &[u8],
    info: &LibInfo,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    // `:1232-1233`
    if !info.feature_ech() {
        return Err(ParameterError::LibcurlDoesntSupport);
    }

    // `:1234-1237`
    if nextarg.len() > 4
        && nextarg
            .get(..3)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"pn:"))
    {
        config.ech_public = Some(getstr_text(nextarg, DENY_BLANK)?);
        return Ok(());
    }

    // `:1238-1271`
    if nextarg.len() > 5
        && nextarg
            .get(..4)
            .is_some_and(|head| head.eq_ignore_ascii_case(b"ecl:"))
    {
        // `:1240-1242` -- the direct case keeps the whole `ecl:...` argument.
        if nextarg.get(4) != Some(&b'@') {
            config.ech_config = Some(getstr_text(nextarg, DENY_BLANK)?);
            return Ok(());
        }

        // `:1243-1270` -- "@filename or @- for stdin"; `nextarg += 5` skips
        // `ecl:@`.
        let name = nextarg.get(5..).unwrap_or_default();
        let Some(mut source) = open_argument(host, name) else {
            let shown = String::from_utf8_lossy(name);
            warnf(
                sink,
                msgs,
                format_args!(
                    "Could not read file \"{shown}\" specified for \"--ech ecl:\" option"
                ),
            );
            return Err(ParameterError::BadUse);
        };
        let mut reader = ByteSourceReader {
            inner: &mut *source,
        };
        let contents = file2string(Some(&mut reader))?;
        // `:1266` -- `curl_maprintf("ecl:%s", tmpcfg)`.
        let text = String::from_utf8_lossy(&contents);
        config.ech_config = Some(format!("ecl:{text}"));
        return Ok(());
    }

    // `:1272-1275` -- "just a string, with a keyword".
    config.ech = Some(getstr_text(nextarg, DENY_BLANK)?);
    Ok(())
}

/// `parse_header` -- `src/tool_getparam.c:1279-1324`.
///
/// `-H` and `--proxy-header` share this. A leading `@` reads many headers from a
/// file or standard input (`:1286-1311`); otherwise the argument is one header.
///
/// The frozen warning at `:1315-1316` fires when the argument contains neither
/// `:` nor `;` -- `;` because `-H "Header;"` is how a header is removed -- and its
/// wording depends on which option was used, "proxy" or "HTTP".
fn parse_header<H: ParseHost>(
    config: &mut OperationConfig,
    cmd: CmdKey,
    nextarg: &[u8],
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    let proxy = cmd == CmdKey::ProxyHeader;

    // `:1286-1311`
    if nextarg.first() == Some(&b'@') {
        let name = nextarg.get(1..).unwrap_or_default();
        let Some(mut source) = open_argument(host, name) else {
            let shown = String::from_utf8_lossy(name);
            errorf(sink, msgs, format_args!("Failed to open {shown}"));
            return Err(ParameterError::ReadError);
        };
        // `:1297` -- `curlx_dyn_init(&line, 1024 * 100)`.
        let lines = read_lines(&mut *source, 1024 * 100)?;
        for line in lines {
            let text = String::from_utf8_lossy(&line).into_owned();
            let list = if proxy {
                &mut config.proxyheaders
            } else {
                &mut config.headers
            };
            add2list(list, &text)?;
        }
        return Ok(());
    }

    // `:1314-1317`
    if !nextarg.iter().any(|byte| *byte == b':' || *byte == b';') {
        let kind = if proxy { "proxy" } else { "HTTP" };
        let shown = String::from_utf8_lossy(nextarg);
        warnf(
            sink,
            msgs,
            format_args!(
                "The provided {kind} header '{shown}' does not look like a header?"
            ),
        );
    }

    // `:1318-1321`
    let text = String::from_utf8_lossy(nextarg).into_owned();
    let list = if proxy {
        &mut config.proxyheaders
    } else {
        &mut config.headers
    };
    add2list(list, &text)
}

/// Advances an output cursor past every node that already has an output set.
///
/// The identical eleven lines appear at `src/tool_getparam.c:1333-1350` and
/// `:1376-1393`, and both callers then fill the node they land on. Shared here
/// because two copies of a cursor walk are two places for it to drift, not
/// because the C was wrong to repeat it.
fn output_node(config: &mut OperationConfig) -> Result<usize, ParameterError> {
    let mut cursor = match config.url_out {
        Some(at) => Some(at),
        None if config.url_list.is_empty() => None,
        None => Some(0),
    };
    while let Some(at) = cursor {
        match config.url_list.get(at) {
            Some(node) if node.outset => cursor = Some(at + 1),
            Some(_) => break,
            None => {
                cursor = None;
                break;
            }
        }
    }
    let at = match cursor {
        Some(at) => at,
        None => new_getout(config)?,
    };
    config.url_out = Some(at);
    Ok(at)
}

/// `parse_output` -- `src/tool_getparam.c:1326-1364`.
///
/// `-o <file>`, and `--out-null` when `nextarg` is `None` (`:1879`). Setting an
/// output switches `useremote` off (`:1360`), so `-O -o out` writes to `out`.
fn parse_output(
    config: &mut OperationConfig,
    nextarg: Option<&[u8]>,
) -> Result<(), ParameterError> {
    let at = output_node(config)?;

    // `:1356-1362`
    let outfile = match nextarg {
        Some(name) => Some(getstr(name, DENY_BLANK)?),
        None => None,
    };
    let Some(node) = config.url_list.get_mut(at) else {
        return Err(ParameterError::NoMem);
    };
    node.out_null = nextarg.is_none();
    node.outfile = outfile;
    node.useremote = false;
    node.outset = true;
    Ok(())
}

/// `parse_remote_name` -- `src/tool_getparam.c:1366-1403`.
///
/// `-O` and `--no-remote-name`. The early return at `:1372-1373` is the reason
/// `--no-remote-name` on its own does nothing: with `remote_name_all` clear
/// there is no node to un-set.
fn parse_remote_name(
    config: &mut OperationConfig,
    toggle: bool,
) -> Result<(), ParameterError> {
    // `:1372-1373` -- "nothing to do".
    if !toggle && !config.remote_name_all {
        return Ok(());
    }

    let at = output_node(config)?;
    // `:1398-1401` -- `outfile = NULL` with the C comment "leave it".
    let Some(node) = config.url_list.get_mut(at) else {
        return Err(ParameterError::NoMem);
    };
    node.outfile = None;
    node.useremote = toggle;
    node.outset = true;
    node.out_null = false;
    Ok(())
}

/// `parse_quote` -- `src/tool_getparam.c:1405-1427`.
///
/// `-Q` routes to one of three lists by prefix: `-` for after the transfer, `+`
/// for immediately before it, and neither for before the transfer proper.
fn parse_quote(
    config: &mut OperationConfig,
    nextarg: &[u8],
) -> Result<(), ParameterError> {
    match nextarg.first() {
        // `:1412-1416` -- "prefixed with a dash makes it a POST TRANSFER one".
        Some(b'-') => {
            let text =
                String::from_utf8_lossy(nextarg.get(1..).unwrap_or_default())
                    .into_owned();
            add2list(&mut config.postquote, &text)
        }
        // `:1417-1421` -- "a just-before-transfer one".
        Some(b'+') => {
            let text =
                String::from_utf8_lossy(nextarg.get(1..).unwrap_or_default())
                    .into_owned();
            add2list(&mut config.prequote, &text)
        }
        // `:1422-1424`
        _ => {
            let text = String::from_utf8_lossy(nextarg).into_owned();
            add2list(&mut config.quote, &text)
        }
    }
}

/// `parse_range` -- `src/tool_getparam.c:1429-1471`.
///
/// `-r`. Two frozen diagnostics live here and both are warnings that let the
/// transfer continue:
///
/// * a range that is only a number gets a `-` appended, because "Specifying a
///   range WITHOUT A DASH will create an illegal HTTP range" (`:1440-1455`);
/// * a range containing anything but digits, `-` and `,` warns and is sent as
///   given (`:1458-1467`) -- the loop `break`s at the first offending byte, so
///   the warning appears once.
///
/// The mutual exclusion with `--continue-at` is checked first (`:1436-1439`).
fn parse_range(
    config: &mut OperationConfig,
    nextarg: &[u8],
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    // `:1436-1439`
    if config.use_resume {
        errorf(
            sink,
            msgs,
            format_args!("--continue-at is mutually exclusive with --range"),
        );
        return Err(ParameterError::BadUse);
    }

    // `:1440-1441` -- a number that consumes the whole argument, with no dash
    // following it.
    if let Ok((value, consumed)) = str_number(nextarg, CURL_OFF_T_MAX) {
        if nextarg.get(consumed..).unwrap_or_default().is_empty() {
            warnf(
                sink,
                msgs,
                format_args!(
                    "A specified range MUST include at least one dash (-). Appending one for you"
                ),
            );
            config.range = Some(format!("{value}-"));
            return Ok(());
        }
    }

    // `:1456-1468`
    for byte in nextarg {
        if !byte.is_ascii_digit() && *byte != b'-' && *byte != b',' {
            warnf(
                sink,
                msgs,
                format_args!(
                    "Invalid character is found in given range. A specified range MUST have only digits in \'start\'-\'stop\'. The server's response to this request is uncertain."
                ),
            );
            break;
        }
    }
    config.range = Some(getstr_text(nextarg, DENY_BLANK)?);
    Ok(())
}

/// `parse_upload_file` -- `src/tool_getparam.c:1473-1509`.
///
/// `-T`. An empty argument marks the node `noupload` (`:1502-1503`), which is
/// how `-T ""` requests an upload of nothing; `-` is kept verbatim and resolved
/// to standard input later, with the C comment "keep the string around for now".
fn parse_upload_file(
    config: &mut OperationConfig,
    nextarg: &[u8],
) -> Result<(), ParameterError> {
    // `:1480-1496`
    let mut cursor = match config.url_ul {
        Some(at) => Some(at),
        None if config.url_list.is_empty() => None,
        None => Some(0),
    };
    while let Some(at) = cursor {
        match config.url_list.get(at) {
            Some(node) if node.uploadset => cursor = Some(at + 1),
            Some(_) => break,
            None => {
                cursor = None;
                break;
            }
        }
    }
    let at = match cursor {
        Some(at) => at,
        None => new_getout(config)?,
    };
    config.url_ul = Some(at);

    // `:1501-1507`
    let infile = if nextarg.is_empty() {
        None
    } else {
        Some(getstr(nextarg, DENY_BLANK)?)
    };
    let Some(node) = config.url_list.get_mut(at) else {
        return Err(ParameterError::NoMem);
    };
    node.uploadset = true;
    if nextarg.is_empty() {
        node.noupload = true;
    } else {
        node.infile = infile;
    }
    Ok(())
}

/// `parse_verbose` -- `src/tool_getparam.c:1513-1567`.
///
/// `-v` is, in the C comment's words, "a super-boolean with side effect when
/// applied more than once in the same argument flag, like `-vvv`". The ladder:
///
/// | from | to | effect |
/// |---|---|---|
/// | 0 | 1 | `trace_dump = "%"`, `tracetype = TRACE_PLAIN` (`:1534-1545`) |
/// | 1 | 2 | `ids,time,protocol` (`:1546-1550`) |
/// | 2 | 3 | `tracetype = TRACE_ASCII`, `ssl,read,write` (`:1551-1556`) |
/// | 3 | 4 | `network` (`:1557-1561`) |
/// | 4+ | -- | "no effect for now" (`:1562-1564`) |
///
/// `--no-verbose` resets to zero, disables every component and clears the trace
/// type (`:1519-1525`).
///
/// # `verbose_nopts` is what separates `-vvv` from `-v -v -v`
///
/// `:1526-1531` resets the verbosity to zero when this is the *first* option of
/// the current argv element, so each new element restarts the ladder at 1 while
/// letters within one element climb it. The `!global->trace_set` guard on that
/// reset keeps an explicit `--trace-config` from being undone.
///
/// The frozen warning at `:1541-1542` fires only on the 0-to-1 step and only
/// when a *different* trace type was already chosen.
fn parse_verbose<H: ParseHost>(
    toggle: bool,
    global: &mut GlobalConfig,
    state: &ParseState,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    // `:1519-1525`
    if !toggle {
        global.verbosity = 0;
        set_trace_config(b"-all", global, host)?;
        global.tracetype = TraceType::None;
        return Ok(());
    }

    // `:1526-1531` -- "first `-v` in an argument resets to base verbosity".
    if state.verbose_nopts == 0 {
        global.verbosity = 0;
        if !global.trace_set {
            set_trace_config(b"-all", global, host)?;
        }
    }

    // `:1533-1565`
    match global.verbosity {
        0 => {
            global.verbosity = 1;
            // `:1536-1537` -- "the '%' thing here will cause the trace get sent
            // to stderr".
            global.trace_dump = Some(std::path::PathBuf::from("%"));
            if global.tracetype != TraceType::None
                && global.tracetype != TraceType::Plain
            {
                warnf(
                    sink,
                    msgs,
                    format_args!(
                        "-v, --verbose overrides an earlier trace option"
                    ),
                );
            }
            global.tracetype = TraceType::Plain;
        }
        1 => {
            global.verbosity = 2;
            set_trace_config(b"ids,time,protocol", global, host)?;
        }
        2 => {
            global.verbosity = 3;
            global.tracetype = TraceType::Ascii;
            set_trace_config(b"ssl,read,write", global, host)?;
        }
        3 => {
            global.verbosity = 4;
            set_trace_config(b"network", global, host)?;
        }
        // `:1562-1564` -- "no effect for now".
        _ => {}
    }
    Ok(())
}

/// `parse_writeout` -- `src/tool_getparam.c:1569-1606`.
///
/// `-w`. A leading `@` reads the format from a file or standard input, and a file
/// that opens but yields nothing produces the frozen warning "Failed to read
/// %s" against either the filename or the literal `<stdin>` (`:1582`,
/// `:1599-1600`). A literal format may be blank (`ALLOW_BLANK` at `:1603`).
fn parse_writeout<H: ParseHost>(
    config: &mut OperationConfig,
    nextarg: &[u8],
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    if nextarg.first() != Some(&b'@') {
        // `:1602-1603`
        config.writeout = Some(getstr_text(nextarg, ALLOW_BLANK)?);
        return Ok(());
    }

    // `:1575-1600`
    let name = nextarg.get(1..).unwrap_or_default();
    let is_stdin = name == b"-";
    let shown: String = if is_stdin {
        // `:1582` -- the name reported for standard input.
        "<stdin>".to_owned()
    } else {
        String::from_utf8_lossy(name).into_owned()
    };
    let Some(mut source) = open_argument(host, name) else {
        errorf(sink, msgs, format_args!("Failed to open {shown}"));
        return Err(ParameterError::ReadError);
    };
    config.writeout = None;
    let mut reader = ByteSourceReader {
        inner: &mut *source,
    };
    let contents = file2string(Some(&mut reader))?;
    // `:1599-1600` -- an empty read leaves `writeout` unset and warns.
    if contents.is_empty() {
        warnf(sink, msgs, format_args!("Failed to read {shown}"));
        return Ok(());
    }
    config.writeout = Some(String::from_utf8_lossy(&contents).into_owned());
    Ok(())
}

/// `parse_time_cond` -- `src/tool_getparam.c:1608-1649`.
///
/// `-z`. The leading byte selects the condition: `-` is If-Unmodified-Since, `=`
/// is Last-Modified, and `+` or nothing is If-Modified-Since -- note the
/// `FALLTHROUGH` at `:1616`, which is what makes `+` and the default share an
/// arm.
///
/// The remainder is a date; if it is not one, it is tried as a filename
/// (`:1635-1639`), and if that fails too the condition is removed with the
/// frozen warning at `:1643-1645`.
fn parse_time_cond<H: ParseHost>(
    config: &mut OperationConfig,
    nextarg: &[u8],
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
) -> Result<(), ParameterError> {
    // `:1613-1631`
    let (timecond, rest) = match nextarg.first() {
        Some(b'+') => (
            CURL_TIMECOND_IFMODSINCE,
            nextarg.get(1..).unwrap_or_default(),
        ),
        Some(b'-') => (
            CURL_TIMECOND_IFUNMODSINCE,
            nextarg.get(1..).unwrap_or_default(),
        ),
        Some(b'=') => {
            (CURL_TIMECOND_LASTMOD, nextarg.get(1..).unwrap_or_default())
        }
        _ => (CURL_TIMECOND_IFMODSINCE, nextarg),
    };
    config.timecond = timecond;

    // `:1632` -- `curl_getdate(nextarg, NULL)`, which reports failure as -1.
    let text = String::from_utf8_lossy(rest);
    match curl_rs_lib::getdate(&text) {
        Some(when) => config.condtime = when,
        None => {
            // `:1635-1646` -- "now let's see if it is a filename to get the
            // time from instead!"
            match host.file_time(rest) {
                Some(when) => config.condtime = when,
                None => {
                    config.timecond = CURL_TIMECOND_NONE;
                    warnf(
                        sink,
                        msgs,
                        format_args!(
                            "Illegal date format for -z, --time-cond (and not a filename). Disabling time condition. See curl_getdate(3) for valid date syntax."
                        ),
                    );
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The four dispatch switches -- `src/tool_getparam.c:1741-2877`
// ---------------------------------------------------------------------------
//
// C reaches `config` through the parameter of the same name and `global`
// through a file-static pointer. Here both come from `GlobalConfig`: the
// operation being configured is `global.chain.current_mut()` and the global
// settings are its own fields, which the borrow checker treats as disjoint
// places. That is why an arm needing a capability flag reads it into a local
// before taking the configuration -- the two borrows are of different fields but
// must not be live at the same instant through the same path.
//
// `msg_config` is snapshotted once when a switch is entered; see that function
// for why that is indistinguishable from C's per-call read.

/// `opt_none` -- `src/tool_getparam.c:1741-1818`, "the function that handles
/// ARG_NONE options".
///
/// Twenty rows, of which eighteen have a `case`. `--sslv2` and `--sslv3` do not,
/// because both are `ARG_DEPR` and [`opt_depr`] has already stopped the loop
/// before this is reached (`:3031-3034`).
///
/// **There is no `default:` arm** (`:1745-1816`). A key with no `case` therefore
/// leaves `err` at `PARAM_OK` and the option is silently accepted, and the same
/// is true of [`opt_file`] and [`opt_string`]; only [`opt_bool`] rejects an
/// unknown key. That asymmetry is preserved.
fn opt_none(
    alias: &LongShort,
    global: &mut GlobalConfig,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    let msgs = msg_config(global);
    match alias.cmd {
        // `:1746-1748`
        CmdKey::Anyauth => {
            config_of(global)?.authtype = CURLAUTH_ANY;
        }
        // `:1749-1750` -- the row is unconditional, so the flag always parses;
        // whether a bundle exists is the caller's business and an absent one is
        // a silent success (`src/tool_operate.c:2320-2323`).
        CmdKey::DumpCaEmbed => return Err(ParameterError::CaEmbedRequested),
        // `:1751-1753`
        CmdKey::FtpPasv => {
            config_of(global)?.ftpport = None;
        }
        // `:1755-1758`
        CmdKey::Http10 => {
            let config = config_of(global)?;
            sethttpver(config, CURL_HTTP_VERSION_1_0, sink, &msgs);
        }
        // `:1759-1762`
        CmdKey::Http11 => {
            let config = config_of(global)?;
            sethttpver(config, CURL_HTTP_VERSION_1_1, sink, &msgs);
        }
        // `:1763-1768`
        CmdKey::Http2 => {
            if !global.libinfo.feature_http2() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            let config = config_of(global)?;
            sethttpver(config, CURL_HTTP_VERSION_2_0, sink, &msgs);
        }
        // `:1769-1774`
        CmdKey::Http2PriorKnowledge => {
            if !global.libinfo.feature_http2() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            let config = config_of(global)?;
            sethttpver(
                config,
                CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE,
                sink,
                &msgs,
            );
        }
        // `:1775-1781` -- "Try HTTP/3, allow fallback".
        CmdKey::Http3 => {
            if !global.libinfo.feature_http3() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            let config = config_of(global)?;
            sethttpver(config, CURL_HTTP_VERSION_3, sink, &msgs);
        }
        // `:1782-1788` -- "Try HTTP/3 without fallback".
        CmdKey::Http3Only => {
            if !global.libinfo.feature_http3() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            let config = config_of(global)?;
            sethttpver(config, CURL_HTTP_VERSION_3ONLY, sink, &msgs);
        }
        // `:1789-1794` -- `--tlsv1` and `--tlsv1.0` are both minimum 1.
        CmdKey::Tlsv1 | CmdKey::Tlsv10 => {
            opt_sslver(config_of(global)?, 1, sink, &msgs)?;
        }
        // `:1795-1797`
        CmdKey::Tlsv11 => {
            opt_sslver(config_of(global)?, 2, sink, &msgs)?;
        }
        // `:1798-1800`
        CmdKey::Tlsv12 => {
            opt_sslver(config_of(global)?, 3, sink, &msgs)?;
        }
        // `:1801-1803`
        CmdKey::Tlsv13 => {
            opt_sslver(config_of(global)?, 4, sink, &msgs)?;
        }
        // `:1804-1806`
        CmdKey::Ipv4 => {
            config_of(global)?.ip_version = CURL_IPRESOLVE_V4;
        }
        // `:1807-1809`
        CmdKey::Ipv6 => {
            config_of(global)?.ip_version = CURL_IPRESOLVE_V6;
        }
        // `:1810-1811` -- never escapes `parse_args`, which turns it into the
        // next operation (`:3087-3110`).
        CmdKey::Next => return Err(ParameterError::NextOperation),
        // `:1812-1815`
        CmdKey::ProxyTlsv1 => {
            config_of(global)?.proxy_ssl_version = CURL_SSLVERSION_TLSV1;
        }
        // No `default:` in C, so every other key is accepted and does nothing.
        _ => {}
    }
    Ok(())
}

/// The operation being configured -- C's `config` parameter.
///
/// C reaches it through `global->first` and then `global->last`
/// (`src/tool_getparam.c:3058`, `:3086`), both of which are non-`NULL` once
/// `config_alloc()` has succeeded. `ConfigChain` is never empty for the same
/// reason -- it is constructed around an initial configuration -- so `None` here
/// stands for the one condition that makes C's pointer `NULL`, an allocation
/// that did not happen, which `:3104` reports as `PARAM_NO_MEM`.
fn config_of(
    global: &mut GlobalConfig,
) -> Result<&mut OperationConfig, ParameterError> {
    // `ConfigChain::new` leaves the cursor unset, while C's `config` parameter
    // is `global->first` from the first option onwards (`:3058`). An unset
    // cursor and "the first operation" are the same state, so it is normalised
    // here as well as in `parse_args`, which is what lets `getparameter` be
    // called directly -- by a configuration-file reader, for instance -- without
    // the caller having to know about the cursor.
    if global.chain.current_index().is_none() {
        global.chain.set_current(Some(0));
    }
    global.chain.current_mut().ok_or(ParameterError::NoMem)
}

/// `opt_bool` -- `src/tool_getparam.c:1821-2205`, "the function that handles
/// boolean options".
///
/// One hundred and fifteen rows, of which 112 have a `case`; `--metalink`,
/// `--npn` and `--ntlm-wb` are `ARG_DEPR` and never arrive. Three more --
/// `--test-duphandle`, `--test-event` and `--wdebug` -- have a `case` only under
/// `DEBUGBUILD` or `USE_WATT32` and therefore reach the `default:` arm here; see
/// [`ALIASES`] and GAP #6.
///
/// **This is the one switch with a `default:`** (`:2201-2202`), which returns
/// [`ParameterError::OptionUnknown`].
///
/// `toggle` is `false` for `--no-<name>` and, for the six `ARG_NO` rows, for the
/// short form as well (`:2989`). Six arms therefore read `!toggle`, because the
/// option's name states the negative: `--alpn` clears `noalpn`, `--buffer`
/// clears `nobuffer`, `--keepalive` clears `nokeepalive`, `--sessionid` clears
/// `disable_sessionid`, `--epsv`/`--eprt` clear their `disable_*` twins and
/// `--progress-meter` clears `noprogress`.
#[allow(clippy::cognitive_complexity)] // One arm per option, as C has one
                                       // `case` per option; splitting the table
                                       // would hide the 1:1 correspondence
                                       // that AAP section 0.8.1 freezes.
fn opt_bool<H: ParseHost>(
    alias: &LongShort,
    toggle: bool,
    global: &mut GlobalConfig,
    state: &ParseState,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    let msgs = msg_config(global);
    match alias.cmd {
        // `:1826-1828`
        CmdKey::Alpn => config_of(global)?.noalpn = !toggle,
        // `:1829-1831`
        CmdKey::DisableEpsv => config_of(global)?.disable_epsv = toggle,
        // `:1832-1834`
        CmdKey::DisallowUsernameInUrl => {
            config_of(global)?.disallow_username_in_url = toggle;
        }
        // `:1835-1837`
        CmdKey::Epsv => config_of(global)?.disable_epsv = !toggle,
        // `:1838-1843`
        CmdKey::Compressed => {
            let any = global.libinfo.feature_libz()
                || global.libinfo.feature_brotli()
                || global.libinfo.feature_zstd();
            if toggle && !any {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.encoding = toggle;
        }
        // `:1844-1846`
        CmdKey::TrEncoding => config_of(global)?.tr_encoding = toggle,
        // `:1847-1849`
        CmdKey::Digest => {
            let config = config_of(global)?;
            togglebit(toggle, &mut config.authtype, CURLAUTH_DIGEST);
        }
        // `:1850-1852`
        CmdKey::FtpCreateDirs => config_of(global)?.ftp_create_dirs = toggle,
        // `:1853-1855`
        CmdKey::CreateDirs => config_of(global)?.create_dirs = toggle,
        // `:1856-1861`
        CmdKey::ProxyNtlm => {
            if !global.libinfo.feature_ntlm() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.proxyntlm = toggle;
        }
        // `:1862-1864`
        CmdKey::Crlf => config_of(global)?.crlf = toggle,
        // `:1865-1867`
        CmdKey::HaproxyProtocol => {
            config_of(global)?.haproxy_protocol = toggle;
        }
        // `:1868-1872` -- the gate applies only when enabling.
        CmdKey::Negotiate => {
            if !global.libinfo.feature_spnego() && toggle {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            let config = config_of(global)?;
            togglebit(toggle, &mut config.authtype, CURLAUTH_NEGOTIATE);
        }
        // `:1873-1877`
        CmdKey::Ntlm => {
            if !global.libinfo.feature_ntlm() && toggle {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            let config = config_of(global)?;
            togglebit(toggle, &mut config.authtype, CURLAUTH_NTLM);
        }
        // `:1878-1879` -- `--out-null` is `-o` with no filename.
        CmdKey::OutNull => return parse_output(config_of(global)?, None),
        // `:1880-1882`
        CmdKey::Basic => {
            let config = config_of(global)?;
            togglebit(toggle, &mut config.authtype, CURLAUTH_BASIC);
        }
        // `:1888-1890`
        CmdKey::DisableEprt => config_of(global)?.disable_eprt = toggle,
        // `:1891-1893`
        CmdKey::Eprt => config_of(global)?.disable_eprt = !toggle,
        // `:1894-1896`
        CmdKey::Xattr => config_of(global)?.xattr = toggle,
        // `:1897-1903` -- one arm for two options, and the warning interpolates
        // `a->lname`, so `--ssl` and `--ftp-ssl` produce different text.
        CmdKey::FtpSsl | CmdKey::Ssl => {
            let name = alias.lname;
            let config = config_of(global)?;
            config.ftp_ssl = toggle;
            let insecure = config.ftp_ssl;
            if insecure {
                warnf(
                    sink,
                    &msgs,
                    format_args!(
                        "--{name} is an insecure option, consider --ssl-reqd instead"
                    ),
                );
            }
        }
        // `:1904-1908`
        CmdKey::FtpSslCcc => {
            let config = config_of(global)?;
            config.ftp_ssl_ccc = toggle;
            if config.ftp_ssl_ccc_mode == 0 {
                config.ftp_ssl_ccc_mode = CURLFTPSSL_CCC_PASSIVE;
            }
        }
        // `:1909-1911`
        CmdKey::TcpNodelay => config_of(global)?.tcp_nodelay = toggle,
        // `:1912-1914`
        CmdKey::ProxyDigest => config_of(global)?.proxydigest = toggle,
        // `:1915-1917`
        CmdKey::ProxyBasic => config_of(global)?.proxybasic = toggle,
        // `:1918-1920`
        CmdKey::RetryConnrefused => {
            config_of(global)?.retry_connrefused = toggle;
        }
        // `:1921-1923`
        CmdKey::RetryAllErrors => config_of(global)?.retry_all_errors = toggle,
        // `:1924-1929` -- unlike `--negotiate`, the gate here is unconditional.
        CmdKey::ProxyNegotiate => {
            if !global.libinfo.feature_spnego() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.proxynegotiate = toggle;
        }
        // `:1930-1932`
        CmdKey::FormEscape => {
            let config = config_of(global)?;
            togglebit(toggle, &mut config.mime_options, CURLMIMEOPT_FORMESCAPE);
        }
        // `:1933-1935`
        CmdKey::ProxyAnyauth => config_of(global)?.proxyanyauth = toggle,
        // `:1936-1938`
        CmdKey::TraceTime => global.tracetime = toggle,
        // `:1939-1941`
        CmdKey::IgnoreContentLength => config_of(global)?.ignorecl = toggle,
        // `:1942-1944`
        CmdKey::FtpSkipPasvIp => config_of(global)?.ftp_skip_ip = toggle,
        // `:1945-1948`
        CmdKey::FtpSslReqd | CmdKey::SslReqd => {
            config_of(global)?.ftp_ssl_reqd = toggle;
        }
        // `:1949-1951`
        CmdKey::Sessionid => config_of(global)?.disable_sessionid = !toggle,
        // `:1952-1954`
        CmdKey::FtpSslControl => config_of(global)?.ftp_ssl_control = toggle,
        // `:1955-1957`
        CmdKey::Raw => config_of(global)?.raw = toggle,
        // `:1958-1960`
        CmdKey::Keepalive => config_of(global)?.nokeepalive = !toggle,
        // `:1961-1963`
        CmdKey::Post301 => config_of(global)?.post301 = toggle,
        // `:1964-1966`
        CmdKey::Post302 => config_of(global)?.post302 = toggle,
        // `:1967-1969`
        CmdKey::Post303 => config_of(global)?.post303 = toggle,
        // `:1970-1972`
        CmdKey::Socks5GssapiNec => {
            config_of(global)?.socks5_gssapi_nec = toggle;
        }
        // `:1973-1975`
        CmdKey::FtpPret => config_of(global)?.ftp_pret = toggle,
        // `:1976-1978`
        CmdKey::SaslIr => config_of(global)?.sasl_ir = toggle,
        // `:1987-1989`
        CmdKey::PathAsIs => config_of(global)?.path_as_is = toggle,
        // `:1990-1992`
        CmdKey::TftpNoOptions => config_of(global)?.tftp_no_options = toggle,
        // `:1993-1995`
        CmdKey::TlsEarlydata => {
            config_of(global)?.ssl_allow_earlydata = toggle;
        }
        // `:1996-1998`
        CmdKey::SuppressConnectHeaders => {
            config_of(global)?.suppress_connect_headers = toggle;
        }
        // `:1999-2001`
        CmdKey::CompressedSsh => config_of(global)?.ssh_compression = toggle,
        // `:2002-2004`
        CmdKey::TraceIds => global.traceids = toggle,
        // `:2005-2007`
        CmdKey::ProgressMeter => global.noprogress = !toggle,
        // `:2008-2010`
        CmdKey::ProgressBar => {
            global.progressmode = if toggle {
                CURL_PROGRESS_BAR
            } else {
                CURL_PROGRESS_STATS
            };
        }
        // `:2011-2013`
        CmdKey::Http09 => config_of(global)?.http09_allowed = toggle,
        // `:2014-2019`
        CmdKey::ProxyHttp2 => {
            if !global.libinfo.feature_httpsproxy()
                || !global.libinfo.feature_http2()
            {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.proxyver = if toggle {
                CURLPROXY_HTTPS2
            } else {
                CURLPROXY_HTTPS
            };
        }
        // `:2020-2022`
        CmdKey::Append => config_of(global)?.ftp_append = toggle,
        // `:2023-2025`
        CmdKey::UseAscii => config_of(global)?.use_ascii = toggle,
        // `:2026-2028`
        CmdKey::CaNative => config_of(global)?.native_ca_store = toggle,
        // `:2029-2031`
        CmdKey::ProxyCaNative => {
            config_of(global)?.proxy_native_ca_store = toggle;
        }
        // `:2032-2034`
        CmdKey::SslAllowBeast => config_of(global)?.ssl_allow_beast = toggle,
        // `:2035-2037`
        CmdKey::SslAutoClientCert => {
            config_of(global)?.ssl_auto_client_cert = toggle;
        }
        // `:2038-2040`
        CmdKey::ProxySslAutoClientCert => {
            config_of(global)?.proxy_ssl_auto_client_cert = toggle;
        }
        // `:2041-2043`
        CmdKey::CertStatus => config_of(global)?.verifystatus = toggle,
        // `:2044-2046`
        CmdKey::DohCertStatus => config_of(global)?.doh_verifystatus = toggle,
        // `:2047-2049` -- deprecated by behaviour rather than by mask: the row
        // is a plain `ARG_BOOL`, so the loop does not stop and the warning comes
        // from the arm.
        CmdKey::FalseStart => opt_depr(alias, sink, &msgs),
        // `:2050-2052`
        CmdKey::SslNoRevoke => config_of(global)?.ssl_no_revoke = toggle,
        // `:2053-2055`
        CmdKey::SslRevokeBestEffort => {
            config_of(global)?.ssl_revoke_best_effort = toggle;
        }
        // `:2056-2058`
        CmdKey::TcpFastopen => config_of(global)?.tcp_fastopen = toggle,
        // `:2059-2061`
        CmdKey::ProxySslAllowBeast => {
            config_of(global)?.proxy_ssl_allow_beast = toggle;
        }
        // `:2062-2064`
        CmdKey::ProxyInsecure => config_of(global)?.proxy_insecure_ok = toggle,
        // `:2065-2067`
        CmdKey::Socks5Basic => {
            let config = config_of(global)?;
            togglebit(toggle, &mut config.socks5_auth, CURLAUTH_BASIC);
        }
        // `:2068-2070` -- `CURLAUTH_GSSAPI` aliases `CURLAUTH_NEGOTIATE`.
        CmdKey::Socks5Gssapi => {
            let config = config_of(global)?;
            togglebit(toggle, &mut config.socks5_auth, CURLAUTH_GSSAPI);
        }
        // `:2071-2073`
        CmdKey::FailEarly => global.fail_early = toggle,
        // `:2074-2076`
        CmdKey::StyledOutput => global.styled_output = toggle,
        // `:2077-2079`
        CmdKey::MailRcptAllowfails => {
            config_of(global)?.mail_rcpt_allowfails = toggle;
        }
        // `:2080-2086`
        CmdKey::RemoveOnError => {
            let config = config_of(global)?;
            if config.use_resume && toggle {
                errorf(
                    sink,
                    &msgs,
                    format_args!(
                        "--continue-at is mutually exclusive with --remove-on-error"
                    ),
                );
                return Err(ParameterError::BadUse);
            }
            config.rm_partial = toggle;
        }
        // `:2087-2091` -- "--fail without body".
        CmdKey::Fail => {
            let config = config_of(global)?;
            if toggle && config.fail == FailMode::WithBody {
                warnf(
                    sink,
                    &msgs,
                    format_args!("--fail deselects --fail-with-body here"),
                );
            }
            config.fail = if toggle {
                FailMode::WithoutBody
            } else {
                FailMode::None
            };
        }
        // `:2092-2096`
        CmdKey::FailWithBody => {
            let config = config_of(global)?;
            if toggle && config.fail == FailMode::WithoutBody {
                warnf(
                    sink,
                    &msgs,
                    format_args!("--fail-with-body deselects --fail here"),
                );
            }
            config.fail = if toggle {
                FailMode::WithBody
            } else {
                FailMode::None
            };
        }
        // `:2097-2099`
        CmdKey::Globoff => config_of(global)?.globoff = toggle,
        // `:2100-2102`
        CmdKey::Get => config_of(global)?.use_httpget = toggle,
        // `:2103-2106` -- `--include` is the older spelling of
        // `--show-headers`, so both share the arm.
        CmdKey::Include | CmdKey::ShowHeaders => {
            config_of(global)?.show_headers = toggle;
        }
        // `:2107-2109`
        CmdKey::JunkSessionCookies => {
            config_of(global)?.cookiesession = toggle;
        }
        // `:2110-2116`
        CmdKey::Head => {
            let config = config_of(global)?;
            config.no_body = toggle;
            config.show_headers = toggle;
            let want = if config.no_body {
                HttpReq::Head
            } else {
                HttpReq::Get
            };
            if set_http_request(want, &mut config.httpreq, sink, &msgs) {
                return Err(ParameterError::BadUse);
            }
        }
        // `:2117-2119`
        CmdKey::RemoteHeaderName => {
            config_of(global)?.content_disposition = toggle;
        }
        // `:2120-2122` -- recorded only. The mandatory warning belongs to
        // `crate::output::msgs::warn_insecure_flags`, which the transfer path
        // calls, and the default stays verification-on per AAP section 0.8.1.
        CmdKey::Insecure => config_of(global)?.insecure_ok = toggle,
        // `:2123-2125`
        CmdKey::DohInsecure => config_of(global)?.doh_insecure_ok = toggle,
        // `:2126-2128`
        CmdKey::ListOnly => config_of(global)?.dirlistonly = toggle,
        // `:2129-2132` -- "--no-manual shows no manual...".
        CmdKey::Manual => {
            if toggle {
                return Err(ParameterError::ManualRequested);
            }
        }
        // `:2133-2135`
        CmdKey::NetrcOptional => config_of(global)?.netrc_opt = toggle,
        // `:2136-2138`
        CmdKey::Netrc => config_of(global)?.netrc = toggle,
        // `:2139-2141`
        CmdKey::Buffer => config_of(global)?.nobuffer = !toggle,
        // `:2142-2144`
        CmdKey::RemoteNameAll => config_of(global)?.remote_name_all = toggle,
        // `:2145-2151`
        CmdKey::Clobber => {
            let config = config_of(global)?;
            if config.use_resume && !toggle {
                errorf(
                    sink,
                    &msgs,
                    format_args!(
                        "--continue-at is mutually exclusive with --no-clobber"
                    ),
                );
                return Err(ParameterError::BadUse);
            }
            config.file_clobber_mode = if toggle {
                ClobberMode::Always
            } else {
                ClobberMode::Never
            };
        }
        // `:2152-2153`
        CmdKey::RemoteName => {
            return parse_remote_name(config_of(global)?, toggle);
        }
        // `:2154-2156`
        CmdKey::Proxytunnel => config_of(global)?.proxytunnel = toggle,
        // `:2157-2160` -- "if used first, already taken care of, we do it like
        // this so we do not cause an error!"
        CmdKey::Disable => {}
        // `:2161-2163`
        CmdKey::RemoteTime => config_of(global)?.remote_time = toggle,
        // `:2164-2166`
        CmdKey::Silent => global.silent = toggle,
        // `:2167-2169`
        CmdKey::SkipExisting => config_of(global)?.skip_existing = toggle,
        // `:2170-2172`
        CmdKey::ShowError => global.showerror = toggle,
        // `:2173-2174`
        CmdKey::Verbose => {
            return parse_verbose(toggle, global, state, host, sink, &msgs);
        }
        // `:2175-2178` -- "--no-version yields no output!"
        CmdKey::Version => {
            if toggle {
                return Err(ParameterError::VersionInfoRequested);
            }
        }
        // `:2179-2181`
        CmdKey::Parallel => global.parallel = toggle,
        // `:2182-2184`
        CmdKey::ParallelImmediate => global.parallel_connect = toggle,
        // `:2185-2187`
        CmdKey::Mptcp => config_of(global)?.mptcp = toggle,
        // `:2188-2195` -- `FALLTHROUGH` at `:2190`: `--location-trusted` sets
        // `unrestricted_auth` and then does everything `--location` does.
        CmdKey::LocationTrusted | CmdKey::Location => {
            let trusted = alias.cmd == CmdKey::LocationTrusted;
            let config = config_of(global)?;
            if trusted {
                config.unrestricted_auth = toggle;
            }
            if config.followlocation == CURLFOLLOW_OBEYCODE {
                warnf(
                    sink,
                    &msgs,
                    format_args!("--location overrides --follow"),
                );
            }
            config.followlocation = if toggle { CURLFOLLOW_ALL } else { 0 };
        }
        // `:2196-2200`
        CmdKey::Follow => {
            let config = config_of(global)?;
            if config.followlocation == CURLFOLLOW_ALL {
                warnf(
                    sink,
                    &msgs,
                    format_args!("--follow overrides --location"),
                );
            }
            config.followlocation =
                if toggle { CURLFOLLOW_OBEYCODE } else { 0 };
        }
        // `:2201-2202` -- the only `default:` among the four switches.
        _ => return Err(ParameterError::OptionUnknown),
    }
    Ok(())
}

/// `opt_file` -- `src/tool_getparam.c:2221-2339`, "opt_file handles file
/// options".
///
/// Twenty-five rows, of which 24 have a `case`; `--random-file` is `ARG_DEPR`
/// and never arrives. Like [`opt_none`] and [`opt_string`] there is **no
/// `default:`** (`:2231-2337`).
///
/// The shared preamble at `:2227-2230` warns when the argument looks like a flag,
/// which catches `-o -v`; the test is a leading `-` followed by at least one more
/// byte, so a bare `-` -- standard output -- does not warn.
fn opt_file<H: ParseHost>(
    alias: &LongShort,
    nextarg: &[u8],
    max_recursive: i32,
    global: &mut GlobalConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    let msgs = msg_config(global);

    // `:2227-2230`
    if nextarg.first() == Some(&b'-') && nextarg.len() > 1 {
        let shown = String::from_utf8_lossy(nextarg);
        warnf(
            sink,
            &msgs,
            format_args!("The filename argument '{shown}' looks like a flag."),
        );
    }

    match alias.cmd {
        // `:2232-2235`
        CmdKey::AbstractUnixSocket => {
            let path = getstr_path(nextarg, DENY_BLANK);
            let config = config_of(global)?;
            config.abstract_unix_socket = true;
            config.unix_socket_path = Some(path?);
        }
        // `:2236-2238`
        CmdKey::Cacert => {
            let path = existingfile(alias, nextarg, host, sink, &msgs)?;
            config_of(global)?.cacert = Some(path);
        }
        // `:2239-2241`
        CmdKey::Capath => {
            config_of(global)?.capath = Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2242-2244`
        CmdKey::Cert => {
            let config = config_of(global)?;
            let (cert, passwd) = (&mut config.cert, &mut config.key_passwd);
            get_file_and_password(nextarg, cert, passwd)?;
        }
        // `:2245-2254`
        CmdKey::Config => {
            let remaining = max_recursive - 1;
            if remaining < 0 {
                // The interpolated value is `CONFIG_MAX_LEVELS`, not the
                // current depth, so the message always names 5.
                let limit = CONFIG_MAX_LEVELS;
                errorf(
                    sink,
                    &msgs,
                    format_args!(
                        "Max config file recursion level reached ({limit})"
                    ),
                );
                return Err(ParameterError::BadUse);
            }
            let outcome = host.parse_config(nextarg, remaining);
            if outcome != ParameterError::Ok {
                return Err(outcome);
            }
        }
        // `:2255-2257`
        CmdKey::Crlfile => {
            let path = existingfile(alias, nextarg, host, sink, &msgs)?;
            config_of(global)?.crlfile = Some(path);
        }
        // `:2258-2260`
        CmdKey::DumpHeader => {
            config_of(global)?.headerfile =
                Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2261-2268`
        CmdKey::EtagSave => {
            let config = config_of(global)?;
            if config.num_urls > 1 {
                errorf(
                    sink,
                    &msgs,
                    format_args!("The etag options only work on a single URL"),
                );
                return Err(ParameterError::BadUse);
            }
            config.etag_save_file = Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2269-2276`
        CmdKey::EtagCompare => {
            let config = config_of(global)?;
            if config.num_urls > 1 {
                errorf(
                    sink,
                    &msgs,
                    format_args!("The etag options only work on a single URL"),
                );
                return Err(ParameterError::BadUse);
            }
            config.etag_compare_file = Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2277-2279`
        CmdKey::Key => {
            config_of(global)?.key = Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2280-2282`
        CmdKey::Knownhosts => {
            let path = existingfile(alias, nextarg, host, sink, &msgs)?;
            config_of(global)?.knownhosts = Some(path);
        }
        // `:2283-2285`
        CmdKey::NetrcFile => {
            let path = existingfile(alias, nextarg, host, sink, &msgs)?;
            config_of(global)?.netrc_file = Some(path);
        }
        // `:2286-2288`
        CmdKey::Output => {
            return parse_output(config_of(global)?, Some(nextarg));
        }
        // `:2289-2291`
        CmdKey::ProxyCacert => {
            let path = existingfile(alias, nextarg, host, sink, &msgs)?;
            config_of(global)?.proxy_cacert = Some(path);
        }
        // `:2292-2294`
        CmdKey::ProxyCapath => {
            config_of(global)?.proxy_capath =
                Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2295-2298`
        CmdKey::ProxyCert => {
            let config = config_of(global)?;
            let (cert, passwd) =
                (&mut config.proxy_cert, &mut config.proxy_key_passwd);
            get_file_and_password(nextarg, cert, passwd)?;
        }
        // `:2299-2301`
        CmdKey::ProxyCrlfile => {
            let path = existingfile(alias, nextarg, host, sink, &msgs)?;
            config_of(global)?.proxy_crlfile = Some(path);
        }
        // `:2302-2304` -- `ALLOW_BLANK`, unlike `--key`.
        CmdKey::ProxyKey => {
            config_of(global)?.proxy_key =
                Some(getstr_path(nextarg, ALLOW_BLANK)?);
        }
        // `:2305-2310`
        CmdKey::SslSessions => {
            if !global.libinfo.feature_ssls_export() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            global.ssl_sessions = Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2311-2313`
        CmdKey::Stderr => host.set_stderr_file(nextarg),
        // `:2314-2321`
        CmdKey::Trace => {
            let path = getstr_path(nextarg, DENY_BLANK)?;
            global.trace_dump = Some(path);
            if global.tracetype != TraceType::None
                && global.tracetype != TraceType::Bin
            {
                warnf(
                    sink,
                    &msgs,
                    format_args!(
                        "--trace overrides an earlier trace/verbose option"
                    ),
                );
            }
            global.tracetype = TraceType::Bin;
        }
        // `:2322-2329`
        CmdKey::TraceAscii => {
            let path = getstr_path(nextarg, DENY_BLANK)?;
            global.trace_dump = Some(path);
            if global.tracetype != TraceType::None
                && global.tracetype != TraceType::Ascii
            {
                warnf(
                    sink,
                    &msgs,
                    format_args!(
                        "--trace-ascii overrides an earlier trace/verbose option"
                    ),
                );
            }
            global.tracetype = TraceType::Ascii;
        }
        // `:2330-2333` -- the counterpart of `--abstract-unix-socket`, which
        // clears the flag rather than setting it.
        CmdKey::UnixSocket => {
            let path = getstr_path(nextarg, DENY_BLANK);
            let config = config_of(global)?;
            config.abstract_unix_socket = false;
            config.unix_socket_path = Some(path?);
        }
        // `:2334-2336`
        CmdKey::UploadFile => {
            return parse_upload_file(config_of(global)?, nextarg);
        }
        // No `default:` in C.
        _ => {}
    }
    Ok(())
}

/// `redir_protos[]` -- `src/tool_getparam.c:2349-2355`.
///
/// The four schemes `--proto-redir` may name, as opposed to `--proto`, which
/// accepts everything libcurl was built with.
const REDIR_PROTOS: [&str; 4] = ["http", "https", "ftp", "ftps"];

/// `opt_string` -- `src/tool_getparam.c:2342-2877`, "opt_string handles string
/// options".
///
/// One hundred and twenty-two rows, of which 117 have a `case`. The five without
/// one are `--egd-file`, `--krb` and `--krb4`, which are `ARG_DEPR` and never
/// arrive; `--help`, which the parser handles itself at `:3001-3005`; and
/// `--socks5-gssapi-service`, which has no `case` at all and is therefore
/// **accepted and ignored** -- there is no `default:` here either, so `err` stays
/// `PARAM_OK`.
///
/// `if(!nextarg) nextarg = "";` at `:2356-2357` is why a `--name=` with nothing
/// after the `=` reaches the handlers as an empty string rather than as an
/// absent argument, and why `DENY_BLANK` is what rejects it.
#[allow(clippy::cognitive_complexity)] // One arm per option; see `opt_bool`.
fn opt_string<H: ParseHost>(
    alias: &LongShort,
    nextarg: &[u8],
    global: &mut GlobalConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    let msgs = msg_config(global);
    let text = String::from_utf8_lossy(nextarg).into_owned();

    match alias.cmd {
        // `:2360-2364` -- "c-ares is needed for this".
        CmdKey::DnsIpv4Addr => {
            if global.libinfo.ares_num() == 0 {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.dns_ipv4_addr =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2366-2370`
        CmdKey::DnsIpv6Addr => {
            if global.libinfo.ares_num() == 0 {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.dns_ipv6_addr =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2372-2374`
        CmdKey::Oauth2Bearer => {
            let bearer = getstr_text(nextarg, DENY_BLANK);
            let config = config_of(global)?;
            config.authtype |= CURLAUTH_BEARER;
            config.oauth_bearer = Some(bearer?);
        }
        // `:2376-2377`
        CmdKey::ConnectTimeout => {
            config_of(global)?.connecttimeout_ms = secs2ms(Some(&text))?;
        }
        // `:2379-2384` -- "if given a blank string, make it NULL again".
        CmdKey::DohUrl => {
            let url = getstr_text(nextarg, ALLOW_BLANK)?;
            config_of(global)?.doh_url =
                if url.is_empty() { None } else { Some(url) };
        }
        // `:2386-2388`
        CmdKey::Ciphers => {
            config_of(global)?.cipher_list =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2390-2396`
        CmdKey::DnsInterface => {
            if global.libinfo.ares_num() == 0 {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.dns_interface =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2397-2403`
        CmdKey::DnsServers => {
            if global.libinfo.ares_num() == 0 {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.dns_servers =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2404-2410` -- one argument sets both directions.
        CmdKey::LimitRate => {
            let value = get_size_parameter(nextarg)?;
            let config = config_of(global)?;
            config.recvpersecond = value;
            config.sendpersecond = value;
        }
        // `:2411-2413`
        CmdKey::Rate => return set_rate(nextarg, global, sink, &msgs),
        // `:2414-2416`
        CmdKey::CreateFileMode => {
            config_of(global)?.create_file_mode = oct2nummax(&text, 0o777)?;
        }
        // `:2417-2423` -- "this accepts -1 as a special condition".
        CmdKey::MaxRedirs => {
            let value = str2num(&text)?;
            if value < -1 {
                return Err(ParameterError::BadNumeric);
            }
            config_of(global)?.maxredirs = value;
        }
        // `:2424-2428`
        CmdKey::IpfsGateway => {
            config_of(global)?.ipfs_gateway =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2429-2432`
        CmdKey::AwsSigv4 => {
            let value = getstr_text(nextarg, ALLOW_BLANK);
            let config = config_of(global)?;
            config.authtype |= CURLAUTH_AWS_SIGV4;
            config.aws_sigv4 = Some(value?);
        }
        // `:2433-2436`
        CmdKey::Interface => {
            config_of(global)?.iface = Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2437-2439`
        CmdKey::HaproxyClientip => {
            config_of(global)?.haproxy_clientip =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2440-2444`
        CmdKey::MaxFilesize => {
            let value = get_size_parameter(nextarg)?;
            config_of(global)?.max_filesize = value;
        }
        // `:2445-2447`
        CmdKey::Url => {
            let Some(config) = global.chain.current_mut() else {
                return Err(ParameterError::NoMem);
            };
            // Split apart so that the configuration and the host are borrowed
            // from different places rather than through one `&mut GlobalConfig`.
            return parse_url(config, nextarg, host, sink, &msgs);
        }
        // `:2448-2453` -- the four SOCKS options each set the proxy and its
        // version together.
        CmdKey::Socks5 => {
            let proxy = getstr_text(nextarg, DENY_BLANK);
            let config = config_of(global)?;
            config.proxy = Some(proxy?);
            config.proxyver = CURLPROXY_SOCKS5;
        }
        // `:2454-2457`
        CmdKey::Socks4 => {
            let proxy = getstr_text(nextarg, DENY_BLANK);
            let config = config_of(global)?;
            config.proxy = Some(proxy?);
            config.proxyver = CURLPROXY_SOCKS4;
        }
        // `:2458-2461`
        CmdKey::Socks4a => {
            let proxy = getstr_text(nextarg, DENY_BLANK);
            let config = config_of(global)?;
            config.proxy = Some(proxy?);
            config.proxyver = CURLPROXY_SOCKS4A;
        }
        // `:2462-2465`
        CmdKey::Socks5Hostname => {
            let proxy = getstr_text(nextarg, DENY_BLANK);
            let config = config_of(global)?;
            config.proxy = Some(proxy?);
            config.proxyver = CURLPROXY_SOCKS5_HOSTNAME;
        }
        // `:2466-2478` -- a keyword first, case-sensitively, then a number.
        CmdKey::IpTos => {
            let config = config_of(global)?;
            match find_tos(nextarg) {
                Some(entry) => config.ip_tos = i64::from(entry.value),
                None => config.ip_tos = str2unummax(&text, 0xFF)?,
            }
        }
        // `:2479-2481`
        CmdKey::VlanPriority => {
            config_of(global)?.vlan_priority = str2unummax(&text, 7)?;
        }
        // `:2482-2484`
        CmdKey::Retry => config_of(global)?.req_retry = str2unum(&text)?,
        // `:2485-2487`
        CmdKey::RetryDelay => {
            config_of(global)?.retry_delay_ms = secs2ms(Some(&text))?;
        }
        // `:2488-2490`
        CmdKey::RetryMaxTime => {
            config_of(global)?.retry_maxtime_ms = secs2ms(Some(&text))?;
        }
        // `:2491-2493`
        CmdKey::FtpAccount => {
            config_of(global)?.ftp_account =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2494-2496` -- an unrecognised method warns inside `ftpfilemethod`
        // and yields its fallback; it is not an error.
        CmdKey::FtpMethod => {
            let method = ftpfilemethod(&text, sink, &msgs);
            config_of(global)?.ftp_filemethod = method;
        }
        // `:2497-2499`
        CmdKey::LocalPort => {
            return parse_localport(config_of(global)?, nextarg);
        }
        // `:2500-2502`
        CmdKey::FtpAlternativeToUser => {
            config_of(global)?.ftp_alternative_to_user =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2503-2510` -- `DENY_BLANK`, which is what makes `--libcurl ""` a
        // parser-level rejection rather than a later failure.
        CmdKey::Libcurl => {
            global.libcurl = Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2511-2513`
        CmdKey::KeepaliveTime => {
            config_of(global)?.alivetime = str2unum(&text)?;
        }
        // `:2514-2516`
        CmdKey::KeepaliveCnt => {
            config_of(global)?.alivecnt = str2unum(&text)?;
        }
        // `:2517-2520`
        CmdKey::Noproxy => {
            config_of(global)?.noproxy =
                Some(getstr_text(nextarg, ALLOW_BLANK)?);
        }
        // `:2521-2525`
        CmdKey::Proxy10 => {
            let proxy = getstr_text(nextarg, DENY_BLANK);
            let config = config_of(global)?;
            config.proxy = Some(proxy?);
            config.proxyver = CURLPROXY_HTTP_1_0;
        }
        // `:2526-2528`
        CmdKey::TftpBlksize => {
            config_of(global)?.tftp_blksize = str2unum(&text)?;
        }
        // `:2529-2531`
        CmdKey::MailFrom => {
            config_of(global)?.mail_from =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2532-2535`
        CmdKey::MailRcpt => {
            let config = config_of(global)?;
            add2list(&mut config.mail_rcpt, &text)?;
        }
        // `:2536-2539`
        CmdKey::Proto => {
            let preset: Vec<&str> = global.libinfo.built_in_protos().to_vec();
            let resolved =
                proto2num(&global.libinfo, &preset, &text, sink, &msgs);
            let config = config_of(global)?;
            config.proto_present = true;
            config.proto_str = Some(resolved?);
        }
        // `:2540-2544` -- any failure becomes `PARAM_BAD_USE` here, unlike
        // `--proto`, which propagates the reason.
        CmdKey::ProtoRedir => {
            let resolved =
                proto2num(&global.libinfo, &REDIR_PROTOS, &text, sink, &msgs);
            let config = config_of(global)?;
            config.proto_redir_present = true;
            match resolved {
                Ok(value) => config.proto_redir_str = Some(value),
                Err(_) => return Err(ParameterError::BadUse),
            }
        }
        // `:2545-2547`
        CmdKey::Resolve => {
            let config = config_of(global)?;
            add2list(&mut config.resolve, &text)?;
        }
        // `:2548-2550`
        CmdKey::Delegation => {
            let level = delegation(&text, sink, &msgs);
            config_of(global)?.gssapi_delegation = level;
        }
        // `:2551-2553`
        CmdKey::MailAuth => {
            config_of(global)?.mail_auth =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2554-2556`
        CmdKey::SaslAuthzid => {
            config_of(global)?.sasl_authzid =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2557-2559`
        CmdKey::ProxyServiceName => {
            config_of(global)?.proxy_service_name =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2560-2562`
        CmdKey::ServiceName => {
            config_of(global)?.service_name =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2563-2567`
        CmdKey::ProtoDefault => {
            let value = getstr_text(nextarg, DENY_BLANK)?;
            check_protocol(&global.libinfo, Some(&value))?;
            config_of(global)?.proto_default = Some(value);
        }
        // `:2568-2570`
        CmdKey::Expect100Timeout => {
            config_of(global)?.expect100timeout_ms = secs2ms(Some(&text))?;
        }
        // `:2571-2573`
        CmdKey::ConnectTo => {
            let config = config_of(global)?;
            add2list(&mut config.connect_to, &text)?;
        }
        // `:2574-2580`
        CmdKey::TlsMax => {
            let max = str2tls_max(Some(&text))?;
            let config = config_of(global)?;
            config.ssl_version_max = max;
            if config.ssl_version_max < config.ssl_version {
                errorf(
                    sink,
                    &msgs,
                    format_args!(
                        "--tls-max set lower than minimum accepted version"
                    ),
                );
                return Err(ParameterError::BadUse);
            }
        }
        // `:2581-2584` -- "0 is a valid value for this timeout".
        CmdKey::HappyEyeballsTimeoutMs => {
            config_of(global)?.happy_eyeballs_timeout_ms = str2unum(&text)?;
        }
        // `:2585-2589`
        CmdKey::TraceConfig => {
            global.trace_set = true;
            return set_trace_config(nextarg, global, host);
        }
        // `:2590-2592`
        CmdKey::Variable => {
            let mut diag = VarDiag::new(&mut *sink, msgs);
            return setvariable(
                nextarg,
                &mut global.variables,
                &mut *host,
                &mut diag,
            );
        }
        // `:2593-2595`
        CmdKey::Tls13Ciphers => {
            config_of(global)?.cipher13_list =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2596-2598`
        CmdKey::ProxyTls13Ciphers => {
            config_of(global)?.proxy_cipher13_list =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2599-2601`
        CmdKey::UserAgent => {
            config_of(global)?.useragent =
                Some(getstr_text(nextarg, ALLOW_BLANK)?);
        }
        // `:2602-2607`
        CmdKey::AltSvc => {
            if !global.libinfo.feature_altsvc() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.altsvc =
                Some(getstr_path(nextarg, ALLOW_BLANK)?);
        }
        // `:2608-2613`
        CmdKey::Hsts => {
            if !global.libinfo.feature_hsts() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.hsts = Some(getstr_path(nextarg, ALLOW_BLANK)?);
        }
        // `:2614-2624` -- "A cookie string must have a =-letter", otherwise it
        // is a file to read cookies from.
        CmdKey::Cookie => {
            let config = config_of(global)?;
            if nextarg.contains(&b'=') {
                add2list(&mut config.cookies, &text)?;
            } else {
                add2list(&mut config.cookiefiles, &text)?;
            }
        }
        // `:2625-2627`
        CmdKey::CookieJar => {
            config_of(global)?.cookiejar =
                Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2628-2630`
        CmdKey::ContinueAt => {
            return parse_continue_at(config_of(global)?, nextarg, sink, &msgs);
        }
        // `:2631-2638` -- the whole `--data` family shares one arm.
        CmdKey::Data
        | CmdKey::DataAscii
        | CmdKey::DataBinary
        | CmdKey::DataUrlencode
        | CmdKey::Json
        | CmdKey::DataRaw => {
            let cmd = alias.cmd;
            let Some(config) = global.chain.current_mut() else {
                return Err(ParameterError::NoMem);
            };
            return set_data(cmd, nextarg, config, host, sink, &msgs);
        }
        // `:2639-2641`
        CmdKey::UrlQuery => {
            let Some(config) = global.chain.current_mut() else {
                return Err(ParameterError::NoMem);
            };
            return url_query(nextarg, config, host, sink, &msgs);
        }
        // `:2642-2659` -- a `;auto` suffix is measured off and enables
        // `autoreferer`; an argument that is *only* `;auto` clears the referer.
        CmdKey::Referer => {
            let mut len = nextarg.len();
            let auto =
                len >= 5 && nextarg.get(len - 5..) == Some(b";auto".as_slice());
            let config = config_of(global)?;
            if auto {
                config.autoreferer = true;
                len -= 5;
            } else {
                config.autoreferer = false;
            }
            if len != 0 {
                config.referer = Some(getstrn(nextarg, len, ALLOW_BLANK)?);
            } else {
                config.referer = None;
            }
        }
        // `:2660-2662`
        CmdKey::CertType => {
            config_of(global)?.cert_type =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2663-2665`
        CmdKey::KeyType => {
            config_of(global)?.key_type =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2666-2668`
        CmdKey::Pass => {
            config_of(global)?.key_passwd =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2669-2675` -- `--engine list` asks for a listing rather than
        // selecting one.
        CmdKey::Engine => {
            let value = getstr_text(nextarg, DENY_BLANK)?;
            let listing = value == "list";
            config_of(global)?.engine = Some(value);
            if listing {
                return Err(ParameterError::EnginesRequested);
            }
        }
        // `:2676-2678`
        CmdKey::Ech => {
            let Some(config) = global.chain.current_mut() else {
                return Err(ParameterError::NoMem);
            };
            let info = &global.libinfo;
            return parse_ech(config, nextarg, info, host, sink, &msgs);
        }
        // `:2679-2681`
        CmdKey::Pubkey => {
            config_of(global)?.pubkey = Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2682-2688` -- an MD5 fingerprint is exactly 32 hex digits.
        CmdKey::Hostpubmd5 => {
            let value = getstr_text(nextarg, DENY_BLANK)?;
            let sized = value.len() == 32;
            config_of(global)?.hostpubmd5 = Some(value);
            if !sized {
                return Err(ParameterError::BadUse);
            }
        }
        // `:2689-2694`
        CmdKey::Hostpubsha256 => {
            if !global.libinfo.feature_libssh2() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.hostpubsha256 =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2695-2700`
        CmdKey::Tlsuser => {
            if !global.libinfo.feature_tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.tls_username =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2701-2706`
        CmdKey::Tlspassword => {
            if !global.libinfo.feature_tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.tls_password =
                Some(getstr_text(nextarg, ALLOW_BLANK)?);
        }
        // `:2707-2715` -- "only support TLS-SRP", compared case-sensitively.
        CmdKey::Tlsauthtype => {
            if !global.libinfo.feature_tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            let value = getstr_text(nextarg, DENY_BLANK)?;
            let srp = value == "SRP";
            config_of(global)?.tls_authtype = Some(value);
            if !srp {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
        }
        // `:2716-2718`
        CmdKey::Pinnedpubkey => {
            config_of(global)?.pinnedpubkey =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2719-2721`
        CmdKey::ProxyPinnedpubkey => {
            config_of(global)?.proxy_pinnedpubkey =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2722-2727` -- `ALLOW_BLANK`, the mirror image of `--tlsuser`.
        CmdKey::ProxyTlsuser => {
            if !global.libinfo.feature_tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.proxy_tls_username =
                Some(getstr_text(nextarg, ALLOW_BLANK)?);
        }
        // `:2728-2733` -- `DENY_BLANK`, the mirror image of `--tlspassword`.
        CmdKey::ProxyTlspassword => {
            if !global.libinfo.feature_tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            config_of(global)?.proxy_tls_password =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2734-2743`
        CmdKey::ProxyTlsauthtype => {
            if !global.libinfo.feature_tls_srp() {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
            let value = getstr_text(nextarg, DENY_BLANK)?;
            let srp = value == "SRP";
            config_of(global)?.proxy_tls_authtype = Some(value);
            if !srp {
                return Err(ParameterError::LibcurlDoesntSupport);
            }
        }
        // `:2744-2746`
        CmdKey::ProxyCertType => {
            config_of(global)?.proxy_cert_type =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2747-2749`
        CmdKey::ProxyKeyType => {
            config_of(global)?.proxy_key_type =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2750-2752`
        CmdKey::ProxyPass => {
            config_of(global)?.proxy_key_passwd =
                Some(getstr_text(nextarg, ALLOW_BLANK)?);
        }
        // `:2753-2755`
        CmdKey::ProxyCiphers => {
            config_of(global)?.proxy_cipher_list =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2756-2758`
        CmdKey::LoginOptions => {
            config_of(global)?.login_options =
                Some(getstr_text(nextarg, ALLOW_BLANK)?);
        }
        // `:2759-2761`
        CmdKey::Curves => {
            config_of(global)?.ssl_ec_curves =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2762-2764` -- the row's long name is `sigalgs`.
        CmdKey::SignatureAlgorithms => {
            config_of(global)?.ssl_signature_algorithms =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2765-2774` -- "'form data' simulation". `--form-string` is the same
        // arm with the value taken literally.
        CmdKey::Form | CmdKey::FormString => {
            let literal = alias.cmd == CmdKey::FormString;
            let mut tree = config_of(global)?.mime.take().unwrap_or_default();
            let parsed = {
                let mut diag = FormDiag::new(&mut *sink, msgs);
                formparse(nextarg, &mut tree, literal, &mut *host, &mut diag)
            };
            let config = config_of(global)?;
            config.mime = Some(tree);
            if parsed.is_err() {
                return Err(ParameterError::BadUse);
            }
            if set_http_request(
                HttpReq::MimePost,
                &mut config.httpreq,
                sink,
                &msgs,
            ) {
                return Err(ParameterError::BadUse);
            }
        }
        // `:2775-2777`
        CmdKey::RequestTarget => {
            config_of(global)?.request_target =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2778-2781`
        CmdKey::Header | CmdKey::ProxyHeader => {
            let cmd = alias.cmd;
            let Some(config) = global.chain.current_mut() else {
                return Err(ParameterError::NoMem);
            };
            return parse_header(config, cmd, nextarg, host, sink, &msgs);
        }
        // `:2782-2785`
        CmdKey::MaxTime => {
            config_of(global)?.timeout_ms = secs2ms(Some(&text))?;
        }
        // `:2786-2788`
        CmdKey::OutputDir => {
            config_of(global)?.output_dir =
                Some(getstr_path(nextarg, DENY_BLANK)?);
        }
        // `:2789-2796` -- "This makes the FTP sessions use PORT instead of
        // PASV".
        CmdKey::FtpPort => {
            config_of(global)?.ftpport =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2797-2800`
        CmdKey::FtpSslCccMode => {
            let mode = ftpcccmethod(&text, sink, &msgs);
            let config = config_of(global)?;
            config.ftp_ssl_ccc = true;
            config.ftp_ssl_ccc_mode = mode;
        }
        // `:2801-2803`
        CmdKey::Quote => return parse_quote(config_of(global)?, nextarg),
        // `:2804-2806`
        CmdKey::Range => {
            return parse_range(config_of(global)?, nextarg, sink, &msgs);
        }
        // `:2807-2810`
        CmdKey::TelnetOption => {
            let config = config_of(global)?;
            add2list(&mut config.telnet_options, &text)?;
        }
        // `:2811-2814`
        CmdKey::User => {
            config_of(global)?.userpwd =
                Some(getstr_text(nextarg, ALLOW_BLANK)?);
        }
        // `:2815-2818`
        CmdKey::ProxyUser => {
            config_of(global)?.proxyuserpwd =
                Some(getstr_text(nextarg, ALLOW_BLANK)?);
        }
        // `:2819-2821`
        CmdKey::WriteOut => {
            let Some(config) = global.chain.current_mut() else {
                return Err(ParameterError::NoMem);
            };
            return parse_writeout(config, nextarg, host, sink, &msgs);
        }
        // `:2822-2824`
        CmdKey::Preproxy => {
            config_of(global)?.preproxy =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2825-2830` -- an `--proxy-http2` choice already made is not undone.
        CmdKey::Proxy => {
            let proxy = getstr_text(nextarg, ALLOW_BLANK);
            let config = config_of(global)?;
            config.proxy = Some(proxy?);
            if config.proxyver != CURLPROXY_HTTPS2 {
                config.proxyver = CURLPROXY_HTTP;
            }
        }
        // `:2831-2834`
        CmdKey::Request => {
            config_of(global)?.customrequest =
                Some(getstr_text(nextarg, DENY_BLANK)?);
        }
        // `:2835-2840` -- each of the pair supplies the other's default.
        CmdKey::SpeedTime => {
            let value = str2unum(&text)?;
            let config = config_of(global)?;
            config.low_speed_time = value;
            if config.low_speed_limit == 0 {
                config.low_speed_limit = 1;
            }
        }
        // `:2841-2846`
        CmdKey::SpeedLimit => {
            let value = str2unum(&text)?;
            let config = config_of(global)?;
            config.low_speed_limit = value;
            if config.low_speed_time == 0 {
                config.low_speed_time = 30;
            }
        }
        // `:2847-2857` -- over the maximum clamps, below one restores the
        // default.
        CmdKey::ParallelHost => {
            let value = str2unum(&text)?;
            global.parallel_host = if value > MAX_PARALLEL_HOST {
                clamp_u16(MAX_PARALLEL_HOST)
            } else if value < 1 {
                clamp_u16(PARALLEL_HOST_DEFAULT)
            } else {
                clamp_u16(value)
            };
        }
        // `:2858-2868`
        CmdKey::ParallelMax => {
            let value = str2unum(&text)?;
            global.parallel_max = if value > MAX_PARALLEL {
                clamp_u16(MAX_PARALLEL)
            } else if value < 1 {
                clamp_u16(PARALLEL_DEFAULT)
            } else {
                clamp_u16(value)
            };
        }
        // `:2869-2871`
        CmdKey::TimeCond => {
            let Some(config) = global.chain.current_mut() else {
                return Err(ParameterError::NoMem);
            };
            return parse_time_cond(config, nextarg, host, sink, &msgs);
        }
        // `:2872-2874`
        CmdKey::UploadFlags => {
            return parse_upload_flags(config_of(global)?, nextarg);
        }
        // No `default:` in C, so `--socks5-gssapi-service` and the four
        // `ARG_DEPR` keys that cannot reach here are accepted and do nothing.
        _ => {}
    }
    Ok(())
}

/// `(unsigned short)val` -- the cast at `src/tool_getparam.c:2856` and `:2867`.
///
/// Every value reaching it has already been clamped into `0..=65535` by the
/// comparisons above, so the conversion cannot lose information; `try_into` with
/// a saturating fallback says that without an `as` cast whose truncation would
/// be silent if a bound ever changed.
fn clamp_u16(value: i64) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

// ---------------------------------------------------------------------------
// `getparameter` -- `src/tool_getparam.c:2888-3049`
// ---------------------------------------------------------------------------

/// One command-line option, applied.
///
/// The direct port of `getparameter`, clause for clause. `flag` is either
/// `--long-name`, a short cluster such as `-abc`, or a bare name with no dashes
/// -- which is how `parse_args` synthesises `--url` (`:3119`) and how a
/// configuration file names an option.
///
/// `usedarg` reports whether `nextarg` was consumed as a separate argv element,
/// so the caller knows whether to skip it. It is `false` when the argument came
/// from a `--name=value` split (`:2938`) or from inside a short cluster
/// (`:2997-2999`), because in neither case is there a separate element.
///
/// # Order of operations, and why it is not rearranged
///
/// 1. long or short is decided by the first two bytes (`:2908`);
/// 2. for a long name, `no-` or `expand-` is stripped -- **`else if`, so the two
///    are mutually exclusive and `--no-expand-x` is not a spelling** (`:2916-2926`);
/// 3. the name is split at `=` only if the part before it is at most
///    [`MAX_OPTION_LEN`] bytes (`:2930-2941`);
/// 4. an unmatched name is [`ParameterError::OptionUnknown`] (`:2943-2948`);
/// 5. `--no-` on a non-boolean is [`ParameterError::NoPrefix`] (`:2950-2953`);
/// 6. `--expand-` on anything but `ARG_STRG` or `ARG_FILE` is
///    [`ParameterError::ExpandError`], and only then is the argument expanded
///    (`:2955-2974`);
/// 7. the loop runs once for a long option and once per letter for a cluster,
///    with `ARG_TLS` checked first, `--help` special-cased, `ARG_DEPR` stopping
///    the loop, and `ARG_CLEAR` wiping afterwards (`:2981-3044`).
///
/// The loop condition `!longopt && !singleopt && *++parse && !*usedarg && !err`
/// is reproduced exactly: a long option runs once; `-ofoo` runs once because the
/// rest of the cluster became the argument; `-abc` runs three times; and
/// consuming a separate argument ends the cluster, which is why `-so out` is
/// `-s -o out` and `-os out` is `-o "s"`.
#[allow(clippy::too_many_lines)] // The clause order above is the specification;
                                 // splitting it would hide it.
pub(crate) fn getparameter<H: ParseHost>(
    flag: &[u8],
    nextarg: Option<&[u8]>,
    usedarg: &mut bool,
    max_recursive: i32,
    global: &mut GlobalConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    let mut state = ParseState::default(); // `:2904` -- `verbose_nopts = 0`
    let mut longopt = false;
    let mut singleopt = false;
    // `:2899-2900` -- "how to switch boolean options, on or off. Controlled by
    // using --OPTION or --no-OPTION".
    let mut toggle = true;
    let mut consumearg = true; // `:2902` -- "the argument comes separate"
    let mut alias: Option<&'static LongShort> = None;
    let mut expanded: Option<Vec<u8>> = None;
    let mut nextarg: Option<&[u8]> = nextarg;
    let mut parse: &[u8] = &[];

    *usedarg = false; // `:2906`

    // `:2908` -- `if(('-' != flag[0]) || ('-' == flag[1]))`
    if flag.first() != Some(&b'-') || flag.get(1) == Some(&b'-') {
        // `:2910` -- `('-' == flag[0]) ? flag + 2 : flag`
        let mut word: &[u8] = if flag.first() == Some(&b'-') {
            flag.get(2..).unwrap_or_default()
        } else {
            flag
        };
        let mut noflagged = false;
        let mut expand = false;

        // `:2916-2926` -- mutually exclusive prefixes.
        if word.starts_with(b"no-") {
            word = word.get(3..).unwrap_or_default();
            toggle = false;
            noflagged = true;
        } else if word.starts_with(b"expand-") {
            word = word.get(7..).unwrap_or_default();
            expand = true;
        }

        // `:2928-2941` -- the `=` split, bounded at `MAX_OPTION_LEN`.
        let equals = word.iter().position(|byte| *byte == b'=');
        match equals {
            Some(at) if at <= MAX_OPTION_LEN => {
                alias = findlongopt(word.get(..at).unwrap_or_default());
                nextarg = word.get(at + 1..);
                consumearg = false; // "it is not separate"
            }
            // A name longer than the bound is looked up whole, `=` and all,
            // which is what C's over-long `curlx_str_until` leads to.
            _ => alias = findlongopt(word),
        }

        // `:2943-2948`
        let Some(found) = alias else {
            return Err(ParameterError::OptionUnknown);
        };
        longopt = true;

        // `:2950-2953`
        if noflagged && argtype(found.desc) != ARG_BOOL {
            return Err(ParameterError::NoPrefix);
        }

        // `:2955-2974`
        if expand {
            if let Some(argument) = nextarg {
                if argtype(found.desc) != ARG_STRG
                    && argtype(found.desc) != ARG_FILE
                {
                    return Err(ParameterError::ExpandError);
                }
                let msgs = msg_config(global);
                let replaced = {
                    let mut diag = VarDiag::new(&mut *sink, msgs);
                    varexpand(argument, &global.variables, &mut diag)?
                };
                // `:2970-2973` -- the expansion is used only when something was
                // actually substituted, so an argument with no `{{...}}` keeps
                // pointing at argv.
                if let Some(bytes) = replaced {
                    expanded = Some(bytes);
                }
            }
        }
        if let Some(bytes) = expanded.as_deref() {
            nextarg = Some(bytes);
        }
    } else {
        // `:2976-2979` -- "prefixed with one dash, pass it".
        parse = flag.get(1..).unwrap_or_default();
    }

    // `:2981-3044`
    loop {
        // `:2983-2990`
        if !longopt {
            let Some(letter) = parse.first() else {
                return Err(ParameterError::OptionUnknown);
            };
            let Some(found) = findshortopt(*letter) else {
                return Err(ParameterError::OptionUnknown);
            };
            alias = Some(found);
            // `:2989` -- the short form of an `ARG_NO` row defaults to off.
            toggle = found.desc & ARG_NO == 0;
        }
        let Some(found) = alias else {
            return Err(ParameterError::OptionUnknown);
        };

        // `:2991-2994`
        if found.desc & ARG_TLS != 0 && !global.libinfo.feature_ssl() {
            return Err(ParameterError::LibcurlDoesntSupport);
        }

        if argtype(found.desc) >= ARG_STRG {
            // `:2996-3013` -- "this option requires an extra parameter".
            if !longopt && parse.len() > 1 {
                // `:2997-3000` -- `-ofoo`: the rest of the cluster is the
                // argument and the loop must not continue.
                nextarg = parse.get(1..);
                singleopt = true;
            } else if found.cmd == CmdKey::Help {
                // `:3001-3005` -- "--help is special". The output is produced
                // here, before the code is returned; `src/tool_operate.c:2302`
                // does nothing further with it.
                let category = nextarg
                    .filter(|value| !value.is_empty())
                    .map(|value| String::from_utf8_lossy(value).into_owned());
                host.help(category.as_deref());
                return Err(ParameterError::HelpRequested);
            } else if nextarg.is_none() {
                return Err(ParameterError::RequiresParameter);
            } else {
                // `:3011-3013` -- "mark it as used".
                *usedarg = consumearg;
            }

            // `:3014-3017` -- warn and apply nothing.
            if found.desc & ARG_DEPR != 0 {
                let msgs = msg_config(global);
                opt_depr(found, sink, &msgs);
                break;
            }

            let argument = nextarg.unwrap_or_default();

            // `:3019-3022`
            if has_leading_unicode(argument) {
                let msgs = msg_config(global);
                let shown = String::from_utf8_lossy(argument);
                warnf(
                    sink,
                    &msgs,
                    format_args!(
                        "The argument '{shown}' starts with a Unicode character. Maybe ASCII was intended?"
                    ),
                );
            }

            // `:3023-3026`
            let outcome = if argtype(found.desc) == ARG_FILE {
                opt_file(found, argument, max_recursive, global, host, sink)
            } else {
                opt_string(found, argument, global, host, sink)
            };

            // `:3027-3028` -- unconditional, before the error is propagated.
            if found.desc & ARG_CLEAR != 0 {
                cleanarg(argument);
            }
            outcome?;
        } else {
            // `:3030-3040` -- `ARG_NONE | ARG_BOOL`.
            if found.desc & ARG_DEPR != 0 {
                let msgs = msg_config(global);
                opt_depr(found, sink, &msgs);
                break;
            }
            if argtype(found.desc) == ARG_BOOL {
                opt_bool(found, toggle, global, &state, host, sink)?;
            } else {
                opt_none(found, global, sink)?;
            }
        }

        // `:3042-3043` -- "processed one option from `flag` input, loop for
        // more".
        state.verbose_nopts += 1;

        // `:3044` -- `while(!longopt && !singleopt && *++parse && !*usedarg &&
        // !err)`. The error term is already handled by `?` above, which is what
        // C's `goto`-free `!err` achieves.
        if longopt || singleopt || *usedarg {
            break;
        }
        parse = match parse.get(1..) {
            Some(rest) if !rest.is_empty() => rest,
            _ => break,
        };
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `parse_args` -- `src/tool_getparam.c:3052-3149`
// ---------------------------------------------------------------------------

/// The whole command line.
///
/// `argv` is the process arguments *including* `argv[0]`, because C's loop starts
/// at `i = 1` (`:3060`) and this one skips the same element. It is
/// `[OsString]` rather than `[String]`: `std::env::args` panics on an argument
/// that is not valid Unicode and curl accepts one -- see the module note on
/// bytes. `argv[0]` is skipped and never read, so nothing here learns the
/// program's name from it.
///
/// # The frozen control flow
///
/// * `--` on its own ends option processing, so everything after it is a URL even
///   if it starts with `-` (`:3068-3071`);
/// * an element starting with `-` is an option, and the *next* element is offered
///   to it as a possible argument (`:3073-3083`);
/// * an element not starting with `-` becomes `getparameter("--url", element)`
///   with a recursion budget of **zero**, not [`CONFIG_MAX_LEVELS`] (`:3119`);
/// * `PARAM_NEXT_OPERATION` never escapes: it either starts a new operation or
///   becomes the frozen error "missing URL before --next" (`:3087-3110`);
/// * `--continue-at -` together with `--remote-header-name` is
///   [`ParameterError::ContdispResumeFrom`], checked after the walk
///   (`:3128-3131`);
/// * the five `*_REQUESTED` outcomes are exempt from reporting (`:3133-3138`).
///
/// # Reporting
///
/// [`helpf`] is ungated and always appends the try-line; the prefix is `curl: `.
/// The composition is `option <opt>: <reason>` unless the failing element was
/// literally `":"`, the short form of `--next`, in which case only the reason is
/// printed (`:3141-3144`) -- because "option :: missing URL before --next" would
/// read as a typo.
#[allow(dead_code)] // The entry point the operation driver calls; see
                    // `src/tool_operate.c:2293`.
pub(crate) fn parse_args<H: ParseHost>(
    argv: &[OsString],
    global: &mut GlobalConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    let mut stillflags = true;
    let mut orig_opt: Option<&OsStr> = None;
    let mut outcome: Result<(), ParameterError> = Ok(());

    // `:3058` -- `struct OperationConfig *config = global->first`.
    if global.chain.current_index().is_none() {
        global.chain.set_current(Some(0));
    }

    let mut index = 1;
    while index < argv.len() && outcome.is_ok() {
        let Some(element) = argv.get(index) else {
            break;
        };
        let bytes = element.as_bytes();
        orig_opt = Some(element.as_os_str());

        if stillflags && bytes.first() == Some(&b'-') {
            // `:3068-3071` -- "This indicates the end of the flags and thus
            // enables the following (URL) argument to start with -."
            if bytes == b"--" {
                stillflags = false;
            } else {
                // `:3073-3080` -- the next element, when there is one.
                let nextarg = argv.get(index + 1).map(|next| next.as_bytes());

                let mut passarg = false;
                let result = getparameter(
                    bytes,
                    nextarg,
                    &mut passarg,
                    CONFIG_MAX_LEVELS,
                    global,
                    host,
                    sink,
                );

                // `:3086` -- `config = global->last`. A `--config` that read a
                // file may have started further operations, so the cursor moves
                // to the last of them.
                if let Some(last) = global.chain.last_index() {
                    global.chain.set_current(Some(last));
                }

                match result {
                    // `:3087-3110`
                    Err(ParameterError::NextOperation) => {
                        outcome = start_next_operation(global, sink);
                    }
                    // `:3111-3112` -- "we are supposed to skip this".
                    Ok(()) => {
                        if passarg {
                            index += 1;
                        }
                    }
                    Err(error) => outcome = Err(error),
                }
            }
        } else {
            // `:3115-3120` -- "Just add the URL please", with `max_recursive`
            // of 0.
            let mut used = false;
            outcome = getparameter(
                b"--url",
                Some(bytes),
                &mut used,
                0,
                global,
                host,
                sink,
            );
        }

        // `:3122-3125` -- C releases `orig_opt` on success so that the reporting
        // below sees only the element that failed.
        if outcome.is_ok() {
            orig_opt = None;
        }
        index += 1;
    }

    // `:3128-3131`
    if outcome.is_ok() {
        if let Some(config) = global.chain.current() {
            if config.content_disposition && config.resume_from_current {
                outcome = Err(ParameterError::ContdispResumeFrom);
            }
        }
    }

    // `:3133-3145`
    if let Err(error) = outcome {
        if !matches!(
            error,
            ParameterError::HelpRequested
                | ParameterError::ManualRequested
                | ParameterError::VersionInfoRequested
                | ParameterError::EnginesRequested
                | ParameterError::CaEmbedRequested
        ) {
            let reason = param2text(error);
            match orig_opt.filter(|opt| opt.as_bytes() != b":") {
                Some(opt) => {
                    let shown = opt.to_string_lossy();
                    helpf(sink, Some(format_args!("option {shown}: {reason}")));
                }
                None => helpf(sink, Some(format_args!("{reason}"))),
            }
        }
    }

    outcome
}

/// `PARAM_NEXT_OPERATION` handling -- `src/tool_getparam.c:3088-3110`.
///
/// `--next` starts a fresh operation, but only when the current one already has a
/// URL: the guard is `config->url_list && config->url_list->url`, the *first*
/// node's URL rather than any node's, so `curl --next` and `curl -o out --next`
/// both fail with the frozen error.
///
/// C allocates the new configuration, links it both ways and moves `global->last`
/// onto it. `ConfigChain` owns its elements, so appending does all three
/// (AAP section 0.6.9 replaces the intrusive `next`/`prev` chain with owned
/// storage), and the failure `:3104` reports as `PARAM_NO_MEM` is the reservation
/// failing.
fn start_next_operation(
    global: &mut GlobalConfig,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    let has_url = global
        .chain
        .current()
        .and_then(|config| config.url_list.first())
        .is_some_and(|node| node.url.is_some());

    if !has_url {
        // `:3106-3109`
        let msgs = msg_config(global);
        errorf(sink, &msgs, format_args!("missing URL before --next"));
        return Err(ParameterError::BadUse);
    }

    // `:3092-3105`
    let at = global
        .chain
        .append(OperationConfig::new())
        .map_err(|_| ParameterError::NoMem)?;
    global.chain.set_current(Some(at));
    Ok(())
}

// ---------------------------------------------------------------------------
// The `clap` surface
// ---------------------------------------------------------------------------

/// The declarative record of the frozen command line, as a `clap` 4.x derive.
///
/// AAP section 0.8.3 requires "clap 4.x, derived 1:1 from the curl 8.x
/// long-option inventory". This is that derive: it carries the program identity,
/// the usage line and the URL positional, and [`clap_command`] extends it with
/// every row of [`ALIASES`] so that the inventory is *generated from the table*
/// rather than restated beside it. A restatement would be 397 hand-written
/// attributes able to disagree with the table; a generated one cannot, and
/// [`mod tests`](self) proves the agreement in both directions.
///
/// # It is a record, not the parser
///
/// [`getparameter`] and [`parse_args`] do the parsing, because `clap` implements
/// none of the ten behaviours listed in the module documentation. What this
/// surface is for is everything else that needs to know the inventory: shell
/// completions (`clap_complete`, replacing `scripts/completion.pl`), the usage
/// line, and the cross-check that no option has been added, renamed or
/// re-typed.
///
/// # The identity is `curl`
///
/// `name = "curl"` is `CURL_NAME` (`src/tool_version.h:28`) and the usage string
/// is `src/tool_help.c:240` verbatim. Neither is taken from Cargo metadata: the
/// package is `curl-rs` and printing that would break the `curl: ` prefix, the
/// `--version` banner and the default `User-Agent`, all of which
/// `tests/data/test*` compares literally.
#[derive(Debug, Parser)]
#[command(
    name = "curl",
    bin_name = "curl",
    disable_help_flag = true,
    disable_version_flag = true,
    disable_colored_help = true,
    override_usage = "curl [options...] <url>",
    arg_required_else_help = false
)]
#[allow(dead_code)] // Consumed by `clap_command`, the completion generator and
                    // the surface-parity cross-checks.
pub(crate) struct ClapSurface {
    /// The URLs to transfer.
    ///
    /// C has no positional declaration at all: `parse_args` sends any element
    /// that does not start with `-` to `--url` (`src/tool_getparam.c:3115-3120`).
    /// The positional records that, and `num_args` is unbounded because
    /// `--next` and globbing both allow many.
    ///
    /// `id` is set explicitly because `clap` derives an identifier from the
    /// field name, and `url` is already taken: `{"url", ARG_STRG, ' ',
    /// C_URL}` is a row of the table (`src/tool_getparam.c:361`), so
    /// [`clap_command`] adds an argument with that identifier. `clap` rejects a
    /// duplicate identifier outright. The row keeps the name -- it is the
    /// frozen one -- and the positional, which C does not name at all, yields.
    #[arg(id = "urls", value_name = "url", num_args = 0..)]
    pub(crate) url: Vec<OsString>,
}

/// The frozen inventory as a `clap` [`clap::Command`].
///
/// Starts from the [`ClapSurface`] derive and adds, for every row of
/// [`ALIASES`]:
///
/// * the long form, always;
/// * the short form, for the 59 rows that have one;
/// * `--no-<name>`, for the 115 `ARG_BOOL` rows and no others -- which is the
///   surface `src/tool_getparam.c:2950` defines, since `--no-` on any other row
///   is [`ParameterError::NoPrefix`];
/// * an argument slot for the 147 `ARG_STRG` and `ARG_FILE` rows, and none for
///   the other 135.
///
/// `disable_help_flag` and `disable_version_flag` on the derive are load-bearing:
/// `--help`/`-h` and `--version`/`-V` are rows 118 and 275 of the table, and
/// `clap` would otherwise add its own and refuse to build with a duplicate.
///
/// # Two spellings are deliberately absent
///
/// `--expand-<name>` (`:2922-2926`) applies to all 147 argument-taking rows and
/// would add 147 more identifiers whose only difference is that the argument is
/// expanded before use. It is a prefix of the *parser*, not an option, and
/// [`getparameter`] strips it before any lookup; adding it here would suggest
/// there are 544 options rather than 282. `--no-expand-<name>` is not a spelling
/// at all, because the two prefixes are mutually exclusive.
///
/// `allow_hyphen_values` is set on every argument-taking row because `-o -v` is
/// accepted by C with a warning (`:2227-2230`), not rejected.
#[allow(dead_code)] // Reached by the completion generator and the cross-checks.
pub(crate) fn clap_command() -> clap::Command {
    let mut command = <ClapSurface as clap::CommandFactory>::command();
    let mut negation = 0_usize;

    for alias in &ALIASES {
        let takes_value = argtype(alias.desc) >= ARG_STRG;
        let mut arg = clap::Arg::new(alias.lname).long(alias.lname);

        if alias.letter != ' ' {
            arg = arg.short(alias.letter);
        }

        if takes_value {
            let value_name = if argtype(alias.desc) == ARG_FILE {
                "FILE"
            } else {
                "VALUE"
            };
            arg = arg
                .action(ArgAction::Set)
                .num_args(1)
                .value_name(value_name)
                .allow_hyphen_values(true);
        } else {
            arg = arg.action(ArgAction::SetTrue);
        }

        command = command.arg(arg);

        // `:2950-2953` -- only `ARG_BOOL` accepts the prefix, and the
        // spelling comes from `NEGATIONS` because `clap` ids are `&'static
        // str`. The two lists are walked in step: `negation` advances exactly
        // once per `ARG_BOOL` row, which is the invariant the cross-checks
        // assert.
        if argtype(alias.desc) == ARG_BOOL {
            if let Some(negated) = NEGATIONS.get(negation) {
                command = command.arg(
                    clap::Arg::new(*negated)
                        .long(*negated)
                        .action(ArgAction::SetTrue)
                        .overrides_with(alias.lname),
                );
            }
            negation += 1;
        }
    }

    command
}

// Cross-checks
//
// AAP section 0.8.7 relocates the coverage of `tests/unit` into the crates,
// because "A Rust static library does not export `pub(crate)` items and the C
// unit tests therefore cannot link whatever the quality of the translation".
// These are that coverage for this module: the frozen inventory, every frozen
// literal, every acceptance rule and every preserved quirk, asserted against
// `src/tool_getparam.c` and `src/tool_helpers.c` by line.
//
// Nothing here reaches the network, and nothing reaches the filesystem except
// the two assertions that compare the option surface against
// `docs/cmdline-opts/`, which is committed reference material that
// `curl-rs/build.rs` also reads.
#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};
    use std::io;
    use std::path::Path;

    use super::*;
    use crate::cli::paramhlp::SeekSource;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// A [`ParseHost`] with no side effects and a small in-memory filesystem.
    ///
    /// Every injected capability records what it was asked for, so a test can
    /// assert that `--help` reached [`ParseHost::help`] or that `--stderr`
    /// reached [`ParseHost::set_stderr_file`] rather than inferring it from a
    /// return code.
    #[derive(Debug, Default)]
    struct FakeHost {
        /// Paths that [`ParseHost::exists`] reports, mapped to their contents.
        files: Vec<(Vec<u8>, Vec<u8>)>,
        /// What standard input yields.
        stdin: Vec<u8>,
        /// Modification times [`ParseHost::file_time`] reports.
        times: Vec<(Vec<u8>, i64)>,
        /// Every token list forwarded through [`ParseHost::set_trace`].
        traces: Vec<String>,
        /// Every path given to [`ParseHost::set_stderr_file`].
        stderr_files: Vec<Vec<u8>>,
        /// Every `--help` category, `None` included.
        helped: Vec<Option<String>>,
        /// Every `--config` request as `(filename, budget)`.
        configs: Vec<(Vec<u8>, i32)>,
        /// What [`ParseHost::parse_config`] returns.
        config_outcome: Option<ParameterError>,
        /// Whether [`ParseHost::set_trace`] reports success.
        trace_fails: bool,
        /// The cursor `StdinAccess` reads from.
        stdin_at: usize,
    }

    impl FakeHost {
        fn with_file(mut self, name: &str, body: &str) -> Self {
            self.files.push((name.into(), body.into()));
            self
        }

        fn with_stdin(mut self, body: &str) -> Self {
            self.stdin = body.into();
            self
        }

        fn with_time(mut self, name: &str, stamp: i64) -> Self {
            self.times.push((name.into(), stamp));
            self
        }
    }

    impl VarHost for FakeHost {
        fn getenv(&self, _name: &[u8]) -> Option<Vec<u8>> {
            None
        }

        fn open(&mut self, path: &[u8]) -> io::Result<Box<dyn ByteSource>> {
            for (name, body) in &self.files {
                if name == path {
                    let cursor = io::Cursor::new(body.clone());
                    return Ok(Box::new(SeekSource::new(cursor)));
                }
            }
            Err(io::Error::new(io::ErrorKind::NotFound, "no such fixture"))
        }

        fn stdin(&mut self) -> Box<dyn ByteSource> {
            Box::new(SeekSource::new(io::Cursor::new(self.stdin.clone())))
        }
    }

    impl StdinAccess for FakeHost {
        fn regular_extent(&mut self) -> Option<(i64, i64)> {
            None
        }

        fn read_all(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
            out.extend_from_slice(&self.stdin);
            Ok(())
        }

        fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let rest = self.stdin.get(self.stdin_at..).unwrap_or_default();
            let taken = rest.len().min(buffer.len());
            if let (Some(target), Some(source)) =
                (buffer.get_mut(..taken), rest.get(..taken))
            {
                target.copy_from_slice(source);
            }
            self.stdin_at += taken;
            Ok(taken)
        }

        fn seek_to(&mut self, offset: i64) -> io::Result<()> {
            self.stdin_at = usize::try_from(offset).unwrap_or(0);
            Ok(())
        }
    }

    impl ParseHost for FakeHost {
        fn exists(&mut self, path: &[u8]) -> bool {
            self.files.iter().any(|(name, _)| name == path)
        }

        fn file_time(&mut self, path: &[u8]) -> Option<i64> {
            self.times
                .iter()
                .find(|(name, _)| name == path)
                .map(|(_, stamp)| *stamp)
        }

        fn set_trace(&mut self, config: &str) -> bool {
            self.traces.push(config.to_owned());
            !self.trace_fails
        }

        fn set_stderr_file(&mut self, path: &[u8]) {
            self.stderr_files.push(path.to_vec());
        }

        fn help(&mut self, category: Option<&str>) {
            self.helped.push(category.map(str::to_owned));
        }

        fn parse_config(
            &mut self,
            filename: &[u8],
            max_recursive: i32,
        ) -> ParameterError {
            self.configs.push((filename.to_vec(), max_recursive));
            self.config_outcome.unwrap_or(ParameterError::Ok)
        }
    }

    /// A [`GlobalConfig`] and a capturing sink.
    ///
    /// `Vec<u8>` is a [`DiagnosticSink`] already (`curl-rs/src/output/msgs.rs`),
    /// so the diagnostics a test wants to inspect land in a buffer with no
    /// terminal and no file involved.
    fn fixture() -> Option<(GlobalConfig, Vec<u8>)> {
        let mut sink: Vec<u8> = Vec::new();
        let msgs = MsgConfig::new(false, false, false);
        GlobalConfig::init(&mut sink, &msgs)
            .ok()
            .map(|global| (global, sink))
    }

    /// One parse, with everything a test may want to inspect.
    struct Outcome {
        /// What [`parse_args`] returned.
        result: Result<(), ParameterError>,
        /// The configuration it built.
        global: GlobalConfig,
        /// Everything written to the sink, as text.
        written: String,
        /// The host, with its record of injected calls.
        host: FakeHost,
    }

    /// Runs one command line, `argv[0]` supplied for it.
    ///
    /// `None` means the fixture itself could not be built, which
    /// [`the_parser_fixture_is_available`] asserts on so that the condition is
    /// reported once and loudly rather than by every test that depends on it.
    fn run(arguments: &[&str]) -> Option<Outcome> {
        run_with(FakeHost::default(), arguments)
    }

    fn run_with(mut host: FakeHost, arguments: &[&str]) -> Option<Outcome> {
        let (mut global, mut sink) = fixture()?;
        let mut argv: Vec<OsString> = vec![OsString::from("curl")];
        argv.extend(arguments.iter().map(OsString::from));
        let result = parse_args(&argv, &mut global, &mut host, &mut sink);
        let written = String::from_utf8_lossy(&sink).into_owned();
        Some(Outcome {
            result,
            global,
            written,
            host,
        })
    }

    /// The configuration a parse produced, or `None` when the chain is empty --
    /// which cannot happen, because `ConfigChain` is built around an initial
    /// element.
    fn config(global: &GlobalConfig) -> Option<&OperationConfig> {
        global.chain.current()
    }

    /// Reverses the line wrapping `voutf` applies.
    ///
    /// `src/tool_msgs.c:45` breaks a diagnostic at the terminal width and
    /// re-prefixes every continuation, and
    /// `curl-rs/src/output/msgs.rs` reproduces that -- including reading the
    /// width from the environment, which makes the raw bytes depend on where the
    /// test runs. The break keeps the space it broke at, so removing every
    /// newline-plus-prefix restores the message exactly and lets an assertion be
    /// about the frozen text rather than about the terminal.
    fn unwrapped(text: &str, prefix: &str) -> String {
        let separator = format!("\n{prefix}");
        let mut out = String::with_capacity(text.len());
        let mut rest = text;

        while let Some(at) = rest.find(&separator) {
            let (head, tail) = rest.split_at(at);
            out.push_str(head);

            // The wrap branch writes `cut + 1` bytes -- "including the blank"
            // (`src/tool_msgs.c:62-65`) -- and only then the newline, so a
            // continuation line is ALWAYS preceded by a blank. A genuine
            // message boundary never is: no frozen literal ends in one. That
            // is what makes the two cases separable here, and it is why a
            // blind `replace` would be wrong -- it welds two distinct
            // diagnostics into one and loses the boundary the assertion is
            // about.
            if !out.ends_with(' ') && !out.ends_with('\t') {
                out.push_str(&separator);
            }

            rest = tail.get(separator.len()..).unwrap_or("");
        }

        out.push_str(rest);
        out
    }

    /// Whether this build advertises TLS.
    ///
    /// `curl-rs-lib/src/version.rs` declares `ENGINE_TLS` absent while
    /// `curl-rs-lib/src/tls/mod.rs` is unwritten, so the 61 `ARG_TLS` rows are
    /// refused by the gate at `src/tool_getparam.c:2991` in this checkout. AAP
    /// section 0.6.5 measures that under-reporting a capability is the safe
    /// direction, so the tests assert whichever answer the build gives rather
    /// than assuming one -- and thereby assert the gate itself.
    fn tls_available() -> bool {
        fixture().is_some_and(|(global, _)| global.libinfo.feature_ssl())
    }

    /// The rows whose type is `want`.
    fn rows_of_type(want: u8) -> Vec<&'static LongShort> {
        ALIASES
            .iter()
            .filter(|row| argtype(row.desc) == want)
            .collect()
    }

    /// The names of the rows carrying `flag`.
    fn names_with_flag(flag: u8) -> Vec<&'static str> {
        ALIASES
            .iter()
            .filter(|row| row.desc & flag != 0)
            .map(|row| row.lname)
            .collect()
    }

    // -----------------------------------------------------------------------
    // 1-7: the frozen inventory
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // `ParameterError` and `param2text`
    //
    // These five carry forward verbatim from the earlier state of this file,
    // where they were written against `src/tool_getparam.h:336-363` and
    // `src/tool_helpers.c:35-75` and passed. They are restored unchanged in
    // substance -- only `the_seventeen_named_phrases_are_reproduced_verbatim`
    // is renamed, because the body always held seventeen assertions and C has
    // seventeen explicit arms (`:38-71`); the old name said sixteen.
    // -----------------------------------------------------------------------

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
    fn the_seventeen_named_phrases_are_reproduced_verbatim() {
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
        // Nine C tokens have no case; eight of them are modelled here, because
        // `PARAM_LAST` is the terminator sentinel and is not a variant.
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

    #[test]
    fn the_table_has_exactly_the_282_rows_the_aap_freezes() {
        // AAP section 0.8.1 and `src/tool_getparam.c:80`. Measured with
        // `awk 'NR>=80 && /^  \{"/' src/tool_getparam.c | wc -l`.
        assert_eq!(ALIASES.len(), 282);
        assert_eq!(ALIASES.len(), CmdKey::COUNT);
    }

    #[test]
    fn the_table_is_c_sorted_on_the_long_name() {
        // `src/tool_getparam.c:79` -- "this array MUST be alphasorted based on
        // the 'lname'" -- and `:1080`'s `bsearch` depends on it. The ordering is
        // byte-wise, which is `strcmp`, not locale-aware.
        for pair in ALIASES.windows(2) {
            let (Some(left), Some(right)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            assert_eq!(
                findarg(left.lname, right.lname),
                Ordering::Less,
                "{} must sort before {}",
                left.lname,
                right.lname
            );
        }
    }

    #[test]
    fn the_type_distribution_reconciles_to_282() {
        // Measured against `src/tool_getparam.c:81-373`.
        assert_eq!(rows_of_type(ARG_NONE).len(), 20);
        assert_eq!(rows_of_type(ARG_BOOL).len(), 115);
        assert_eq!(rows_of_type(ARG_STRG).len(), 122);
        assert_eq!(rows_of_type(ARG_FILE).len(), 25);
        assert_eq!(20 + 115 + 122 + 25, ALIASES.len());
    }

    #[test]
    fn the_flag_counts_and_the_six_arg_no_names_are_exact() {
        assert_eq!(names_with_flag(ARG_TLS).len(), 61);
        assert_eq!(names_with_flag(ARG_CLEAR).len(), 11);
        assert_eq!(names_with_flag(ARG_DEPR).len(), 9);
        // `ARG_NO` is six rows and does NOT define the `--no-` surface; see the
        // module documentation and `src/tool_getparam.h:317` against `:327`.
        assert_eq!(
            names_with_flag(ARG_NO),
            vec![
                "alpn",
                "buffer",
                "clobber",
                "keepalive",
                "progress-meter",
                "sessionid"
            ]
        );
        // Every `ARG_NO` row is also `ARG_BOOL`, which is what makes `:2989`'s
        // toggle inversion reachable at all.
        for row in ALIASES.iter().filter(|row| row.desc & ARG_NO != 0) {
            assert_eq!(argtype(row.desc), ARG_BOOL, "{}", row.lname);
        }
    }

    #[test]
    fn the_negation_surface_is_115_wide_not_6() {
        // `src/tool_getparam.c:2950` rejects `--no-` on anything that is not
        // `ARG_BOOL`, so the accepting set is exactly the `ARG_BOOL` rows.
        let expected: Vec<String> = ALIASES
            .iter()
            .filter(|row| argtype(row.desc) == ARG_BOOL)
            .map(|row| format!("no-{}", row.lname))
            .collect();
        assert_eq!(expected.len(), 115);
        assert_eq!(NEGATIONS.len(), expected.len());
        for (generated, wanted) in NEGATIONS.iter().zip(&expected) {
            assert_eq!(generated, wanted);
        }
        // 282 long names plus 115 negations is the whole long-form surface.
        assert_eq!(ALIASES.len() + NEGATIONS.len(), 397);
    }

    #[test]
    fn there_are_59_short_letters_all_distinct_and_all_expected() {
        let shorts: Vec<(&str, char)> = ALIASES
            .iter()
            .filter(|row| row.letter != ' ')
            .map(|row| (row.lname, row.letter))
            .collect();
        assert_eq!(shorts.len(), 59);
        let distinct: HashSet<char> =
            shorts.iter().map(|(_, letter)| *letter).collect();
        assert_eq!(distinct.len(), 59, "a short letter is used twice");

        // The complete mapping, in table order, from `src/tool_getparam.c`.
        // The unusual letters are the point of listing all of them: `:` for
        // `--next`, `#` for `--progress-bar`, `0` for `--http1.0`, `1`/`2`/`3`
        // for `--tlsv1`/`--sslv2`/`--sslv3` and `4`/`6` for `--ipv4`/`--ipv6`.
        let expected: Vec<(&str, char)> = vec![
            ("append", 'a'),
            ("buffer", 'N'),
            ("cert", 'E'),
            ("config", 'K'),
            ("continue-at", 'C'),
            ("cookie", 'b'),
            ("cookie-jar", 'c'),
            ("data", 'd'),
            ("disable", 'q'),
            ("dump-header", 'D'),
            ("fail", 'f'),
            ("form", 'F'),
            ("ftp-port", 'P'),
            ("get", 'G'),
            ("globoff", 'g'),
            ("head", 'I'),
            ("header", 'H'),
            ("help", 'h'),
            ("http1.0", '0'),
            ("insecure", 'k'),
            ("ipv4", '4'),
            ("ipv6", '6'),
            ("junk-session-cookies", 'j'),
            ("list-only", 'l'),
            ("location", 'L'),
            ("manual", 'M'),
            ("max-time", 'm'),
            ("netrc", 'n'),
            ("next", ':'),
            ("output", 'o'),
            ("parallel", 'Z'),
            ("progress-bar", '#'),
            ("proxy", 'x'),
            ("proxy-user", 'U'),
            ("proxytunnel", 'p'),
            ("quote", 'Q'),
            ("range", 'r'),
            ("referer", 'e'),
            ("remote-header-name", 'J'),
            ("remote-name", 'O'),
            ("remote-time", 'R'),
            ("request", 'X'),
            ("show-error", 'S'),
            ("show-headers", 'i'),
            ("silent", 's'),
            ("speed-limit", 'Y'),
            ("speed-time", 'y'),
            ("sslv2", '2'),
            ("sslv3", '3'),
            ("telnet-option", 't'),
            ("time-cond", 'z'),
            ("tlsv1", '1'),
            ("upload-file", 'T'),
            ("use-ascii", 'B'),
            ("user", 'u'),
            ("user-agent", 'A'),
            ("verbose", 'v'),
            ("version", 'V'),
            ("write-out", 'w'),
        ];
        assert_eq!(shorts, expected);
    }

    #[test]
    fn every_dispatch_key_is_used_by_exactly_one_row() {
        let keys: BTreeSet<CmdKey> =
            ALIASES.iter().map(|row| row.cmd).collect();
        assert_eq!(keys.len(), ALIASES.len());
        // `src/tool_getparam.h:31-314` assigns none of the discriminants, so
        // declaration order fixes all 282 and the table must walk them in that
        // order for `CmdKey::COUNT` to describe the same set.
        let mut previous: Option<u16> = None;
        for key in &keys {
            let value = *key as u16;
            if let Some(before) = previous {
                assert!(value > before);
            }
            previous = Some(value);
        }
        assert_eq!(previous, Some(281));
    }

    #[test]
    fn the_nine_deprecated_names_are_exact() {
        // `opt_depr` (`src/tool_getparam.c:1723`) warns and applies nothing for
        // each of these; two carry short letters, so `-2` and `-3` warn too.
        assert_eq!(
            names_with_flag(ARG_DEPR),
            vec![
                "egd-file",
                "krb",
                "krb4",
                "metalink",
                "npn",
                "ntlm-wb",
                "random-file",
                "sslv2",
                "sslv3"
            ]
        );
    }

    #[test]
    fn the_eleven_credential_rows_carry_arg_clear() {
        // The `ARG_CLEAR` set is exactly the credential-bearing options, which
        // is what makes `cleanarg` (GAP #0) about passwords rather than about
        // arguments in general.
        assert_eq!(
            names_with_flag(ARG_CLEAR),
            vec![
                "cert",
                "oauth2-bearer",
                "pass",
                "proxy-cert",
                "proxy-pass",
                "proxy-tlspassword",
                "proxy-tlsuser",
                "proxy-user",
                "tlspassword",
                "tlsuser",
                "user"
            ]
        );
    }

    #[test]
    fn the_lookups_agree_with_the_table() {
        for row in &ALIASES {
            let found = findlongopt(row.lname.as_bytes());
            assert_eq!(
                found.map(|hit| hit.cmd),
                Some(row.cmd),
                "{}",
                row.lname
            );
            if row.letter != ' ' {
                let letter = u32::from(row.letter);
                let byte = u8::try_from(letter).unwrap_or(0);
                assert_eq!(
                    findshortopt(byte).map(|hit| hit.cmd),
                    Some(row.cmd),
                    "-{}",
                    row.letter
                );
            }
        }
        assert!(findlongopt(b"no-such-option").is_none());
        // `:832-833` -- the bounds reject the space sentinel and every byte
        // outside printable ASCII.
        assert!(findshortopt(b' ').is_none());
        assert!(findshortopt(0).is_none());
        assert!(findshortopt(127).is_none());
        assert!(findshortopt(0xff).is_none());
        // A name that is not UTF-8 cannot match a row, which is the answer
        // `strcmp` gives too.
        assert!(findlongopt(&[0xff, 0xfe]).is_none());
    }

    // -----------------------------------------------------------------------
    // 8-13: the clap surface
    // -----------------------------------------------------------------------

    #[test]
    fn the_clap_surface_matches_the_table_in_both_directions() {
        let command = clap_command();
        let longs: HashSet<String> = command
            .get_arguments()
            .filter_map(clap::Arg::get_long)
            .map(str::to_owned)
            .collect();

        // Every one of the 282 rows is accepted.
        for row in &ALIASES {
            assert!(longs.contains(row.lname), "--{} is missing", row.lname);
        }
        // Every one of the 115 negations is accepted, and no other.
        for negated in &NEGATIONS {
            assert!(longs.contains(*negated), "--{negated} is missing");
        }
        // Nothing else exists: 282 + 115, with `clap`'s own `--help` and
        // `--version` disabled because rows 118 and 275 own those spellings.
        assert_eq!(longs.len(), 397, "the surface has grown or shrunk");

        // Shorts agree one for one.
        let shorts: HashSet<char> = command
            .get_arguments()
            .filter_map(clap::Arg::get_short)
            .collect();
        assert_eq!(shorts.len(), 59);
        for row in ALIASES.iter().filter(|row| row.letter != ' ') {
            assert!(shorts.contains(&row.letter), "-{}", row.letter);
        }

        // Arity agrees: the 147 argument-taking rows take one value and the
        // other 135 take none.
        for row in &ALIASES {
            let arg = command
                .get_arguments()
                .find(|arg| arg.get_long() == Some(row.lname));
            let Some(arg) = arg else {
                continue;
            };
            let takes = argtype(row.desc) >= ARG_STRG;
            assert_eq!(
                arg.get_action().takes_values(),
                takes,
                "--{} arity",
                row.lname
            );
        }
        assert_eq!(
            rows_of_type(ARG_STRG).len() + rows_of_type(ARG_FILE).len(),
            147
        );

        // The surface builds. `clap` panics from `debug_assert` on a duplicate
        // id or a conflicting short, so reaching this point is the assertion.
        command.clone().build();
    }

    #[test]
    fn the_clap_surface_reports_curl_as_its_name() {
        // `src/tool_version.h:28` and `src/tool_help.c:240`. Cargo names the
        // package `curl-rs`; printing that would break the `curl: ` prefix and
        // the `--version` banner.
        let command = clap_command();
        assert_eq!(command.get_name(), "curl");
        assert_eq!(
            command.get_bin_name(),
            Some("curl"),
            "the usage line must read `curl`"
        );
    }

    #[test]
    fn the_no_prefix_is_accepted_on_booleans_and_refused_elsewhere() {
        // `src/tool_getparam.c:2916-2921` strips the prefix; `:2950-2953`
        // rejects it for every row that is not `ARG_BOOL`.
        let Some(accepted) = run(&["--no-buffer", "https://x"]) else {
            return;
        };
        assert_eq!(accepted.result, Ok(()));
        assert_eq!(config(&accepted.global).map(|c| c.nobuffer), Some(true));

        let Some(refused) = run(&["--no-output", "f", "https://x"]) else {
            return;
        };
        assert_eq!(refused.result, Err(ParameterError::NoPrefix));
        assert!(refused.written.contains(
            "the given option cannot be reversed with a --no- prefix"
        ));
    }

    #[test]
    fn every_boolean_accepts_its_negation_and_no_other_row_does() {
        for row in &ALIASES {
            // `--config` reads a file and `--next` starts an operation, so both
            // are exercised by their own tests rather than here; every other row
            // only needs the prefix decision.
            let spelling = format!("--no-{}", row.lname);
            let Some(out) = run(&[&spelling, "https://x"]) else {
                return;
            };
            if argtype(row.desc) == ARG_BOOL {
                assert_ne!(
                    out.result,
                    Err(ParameterError::NoPrefix),
                    "{spelling} must be accepted"
                );
            } else {
                assert_eq!(
                    out.result,
                    Err(ParameterError::NoPrefix),
                    "{spelling} must be refused"
                );
            }
        }
    }

    #[test]
    fn a_short_cluster_iterates_and_a_value_option_swallows_the_rest() {
        // `-ofoo` -- `:2997-3000` sets `singleopt` and the loop stops.
        let Some(single) = run(&["-ofoo", "https://x"]) else {
            return;
        };
        assert_eq!(single.result, Ok(()));
        let node = config(&single.global)
            .and_then(|c| c.url_list.first())
            .and_then(|node| node.outfile.clone());
        assert_eq!(node, Some(b"foo".to_vec()));

        // `-sSv` -- three booleans from one element.
        let Some(cluster) = run(&["-sSv", "https://x"]) else {
            return;
        };
        assert_eq!(cluster.result, Ok(()));
        assert!(cluster.global.silent);
        assert!(cluster.global.showerror);
        assert_eq!(cluster.global.verbosity, 1);

        // A separate argument ends the cluster: `-so out` is `-s -o out`.
        let Some(mixed) = run(&["-so", "out", "https://x"]) else {
            return;
        };
        assert_eq!(mixed.result, Ok(()));
        assert!(mixed.global.silent);
        let outfile = config(&mixed.global)
            .and_then(|c| c.url_list.first())
            .and_then(|node| node.outfile.clone());
        assert_eq!(outfile, Some(b"out".to_vec()));
    }

    #[test]
    fn the_equals_split_is_bounded_at_max_option_len() {
        assert_eq!(MAX_OPTION_LEN, 26);

        // A 26-byte name splits. `--proxy-tlspassword` is shorter than the
        // bound, so it stands for the ordinary case.
        let Some(split) = run(&["--user-agent=Agent/1", "https://x"]) else {
            return;
        };
        assert_eq!(split.result, Ok(()));
        assert_eq!(
            config(&split.global).and_then(|c| c.useragent.clone()),
            Some("Agent/1".to_owned())
        );

        // The longest real name is 26 bytes, `proxy-ssl-auto-client-cert`, and
        // it still splits.
        let longest = ALIASES
            .iter()
            .map(|row| row.lname.len())
            .max()
            .unwrap_or_default();
        assert_eq!(longest, MAX_OPTION_LEN);

        // A name longer than the bound is looked up whole, `=` included, and
        // therefore matches nothing.
        let over = "-".repeat(2) + &"a".repeat(27) + "=value";
        let Some(unmatched) = run(&[&over]) else {
            return;
        };
        assert_eq!(unmatched.result, Err(ParameterError::OptionUnknown));
    }

    #[test]
    fn a_split_argument_does_not_consume_the_next_element() {
        // `:2938` clears `consumearg`, so the element after `--url=...` is a URL
        // in its own right rather than the option's argument.
        let Some(out) = run(&["--url=https://one", "https://two"]) else {
            return;
        };
        assert_eq!(out.result, Ok(()));
        assert_eq!(config(&out.global).map(|c| c.num_urls), Some(2));
    }

    #[test]
    fn the_expand_prefix_applies_only_to_argument_taking_rows() {
        // `:2955-2964` -- anything that is not `ARG_STRG` or `ARG_FILE` is
        // `PARAM_EXPAND_ERROR`.
        let Some(refused) = run(&["--expand-verbose", "x", "https://y"]) else {
            return;
        };
        assert_eq!(refused.result, Err(ParameterError::ExpandError));
        assert!(refused.written.contains("variable expansion failure"));

        // On a string row it is accepted, and with nothing to substitute the
        // argument is used unchanged (`:2970-2973`).
        let Some(accepted) = run(&["--expand-user-agent=Plain", "https://y"])
        else {
            return;
        };
        assert_eq!(accepted.result, Ok(()));
        assert_eq!(
            config(&accepted.global).and_then(|c| c.useragent.clone()),
            Some("Plain".to_owned())
        );
    }

    #[test]
    fn the_two_prefixes_are_mutually_exclusive() {
        // `:2916-2926` is an `else if`, so `--no-expand-x` is not a spelling:
        // the `no-` prefix is stripped and `expand-user-agent` is looked up as a
        // name, which does not exist.
        let Some(out) = run(&["--no-expand-user-agent=x", "https://y"]) else {
            return;
        };
        assert_eq!(out.result, Err(ParameterError::OptionUnknown));
    }

    // -----------------------------------------------------------------------
    // 14-15: correspondence with `docs/cmdline-opts/`
    // -----------------------------------------------------------------------

    /// The repository root. `CARGO_MANIFEST_DIR` is `<root>/curl-rs`.
    fn repository_root() -> Option<&'static Path> {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent()
    }

    /// The 273 option pages: every `.md` under `docs/cmdline-opts/` except the
    /// 19 `_*.md` support pages and `MANPAGE.md`.
    fn option_pages() -> Vec<String> {
        let Some(root) = repository_root() else {
            return Vec::new();
        };
        let Ok(entries) = std::fs::read_dir(root.join("docs/cmdline-opts"))
        else {
            return Vec::new();
        };
        let mut pages = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "md") {
                let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                else {
                    continue;
                };
                if stem.starts_with('_') || stem == "MANPAGE" {
                    continue;
                }
                pages.push(stem.to_owned());
            }
        }
        pages.sort();
        pages
    }

    #[test]
    fn the_option_pages_and_the_option_surface_reconcile_exactly() {
        let pages = option_pages();
        assert_eq!(
            pages.len(),
            273,
            "docs/cmdline-opts holds 273 option pages plus 19 _*.md support \
             pages and MANPAGE.md"
        );

        let names: HashSet<&str> =
            ALIASES.iter().map(|row| row.lname).collect();
        let page_set: HashSet<&str> =
            pages.iter().map(String::as_str).collect();

        // The 16 rows with no same-named page. Nine are genuinely undocumented
        // synonyms or test-only options that share a `case` body with a
        // documented option; the other seven are documented under their `--no-`
        // spelling instead.
        let mut rows_without_page: Vec<&str> =
            names.difference(&page_set).copied().collect();
        rows_without_page.sort_unstable();
        assert_eq!(
            rows_without_page,
            vec![
                "alpn",
                "buffer",
                "clobber",
                "eprt",
                "epsv",
                "ftp-ssl",
                "ftp-ssl-reqd",
                "include",
                "keepalive",
                "krb4",
                "npn",
                "progress-meter",
                "sessionid",
                "test-duphandle",
                "test-event",
                "wdebug"
            ]
        );

        // The 7 `--no-*` documentation forms with no same-named row. Each is a
        // page for the negation of an `ARG_BOOL` row, so each is a spelling the
        // parser accepts -- which `NEGATIONS` is what guarantees.
        let mut pages_without_row: Vec<&str> =
            page_set.difference(&names).copied().collect();
        pages_without_row.sort_unstable();
        assert_eq!(
            pages_without_row,
            vec![
                "no-alpn",
                "no-buffer",
                "no-clobber",
                "no-keepalive",
                "no-npn",
                "no-progress-meter",
                "no-sessionid"
            ]
        );
        for page in &pages_without_row {
            assert!(
                NEGATIONS.contains(page),
                "{page} is documented but not accepted"
            );
        }

        // The reconciliation is exact.
        assert_eq!(
            ALIASES.len() - rows_without_page.len() + pages_without_row.len(),
            pages.len()
        );
    }

    #[test]
    fn exactly_59_pages_carry_short_and_each_matches_the_table() {
        let Some(root) = repository_root() else {
            return;
        };
        let letters: std::collections::HashMap<&str, char> = ALIASES
            .iter()
            .filter(|row| row.letter != ' ')
            .map(|row| (row.lname, row.letter))
            .collect();

        let mut found = 0_usize;
        for page in option_pages() {
            let path =
                root.join("docs/cmdline-opts").join(format!("{page}.md"));
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Some(line) =
                text.lines().find(|line| line.starts_with("Short: "))
            else {
                continue;
            };
            found += 1;
            let documented = line.trim_start_matches("Short: ").trim();
            // A `--no-*` page documents the letter of the row it negates:
            // `buffer` has no page of its own and `no-buffer.md` carries
            // `Short: N`. That is the one page of the seven that does.
            let owner = letters.get(page.as_str()).copied().or_else(|| {
                page.strip_prefix("no-")
                    .and_then(|positive| letters.get(positive).copied())
            });
            let expected = owner;
            assert_eq!(
                expected.map(|letter| letter.to_string()).as_deref(),
                Some(documented),
                "{page}.md documents Short: {documented}"
            );
        }
        assert_eq!(found, 59);
    }

    // -----------------------------------------------------------------------
    // 16-22: the frozen texts
    // -----------------------------------------------------------------------

    #[test]
    fn set_http_request_reports_a_conflict_with_the_c_argument_order() {
        // `src/tool_helpers.c:94-96` interpolates `reqname[req]` first and
        // `reqname[*store]` second: the option just given, then the one already
        // in force.
        let mut sink: Vec<u8> = Vec::new();
        let msgs = MsgConfig::new(false, false, false);
        let mut store = HttpReq::Unspec;

        // Unset accepts, and so does the same shape twice (`:89-93`).
        assert!(!set_http_request(
            HttpReq::Get,
            &mut store,
            &mut sink,
            &msgs
        ));
        assert_eq!(store, HttpReq::Get);
        assert!(!set_http_request(
            HttpReq::Get,
            &mut store,
            &mut sink,
            &msgs
        ));
        assert!(sink.is_empty(), "no diagnostic for a repeated selection");

        assert!(set_http_request(
            HttpReq::Head,
            &mut store,
            &mut sink,
            &msgs
        ));
        assert_eq!(
            unwrapped(&String::from_utf8_lossy(&sink), "Warning: "),
            "Warning: You can only select one HTTP request method! You asked \
             for both HEAD (-I, --head) and GET (-G, --get).\n"
        );
        // The conflict leaves the earlier choice standing.
        assert_eq!(store, HttpReq::Get);
    }

    #[test]
    fn customrequest_helper_notes_a_redundant_x_and_warns_about_head() {
        // `src/tool_helpers.c:113-122`. The note is gated on the trace setting
        // and the warning on `--silent`, so the fixture enables tracing.
        let msgs = MsgConfig::new(false, false, true);

        let mut nothing: Vec<u8> = Vec::new();
        customrequest_helper(HttpReq::Get, None, &mut nothing, &msgs);
        assert!(nothing.is_empty(), "None must produce no output");

        let mut note: Vec<u8> = Vec::new();
        customrequest_helper(HttpReq::Get, Some("get"), &mut note, &msgs);
        assert_eq!(
            unwrapped(&String::from_utf8_lossy(&note), "Note: "),
            "Note: Unnecessary use of -X or --request, GET is already \
             inferred.\n"
        );

        let mut warning: Vec<u8> = Vec::new();
        customrequest_helper(HttpReq::Get, Some("HeAd"), &mut warning, &msgs);
        assert_eq!(
            unwrapped(&String::from_utf8_lossy(&warning), "Warning: "),
            "Warning: Setting custom HTTP method to HEAD with -X/--request may \
             not work the way you want. Consider using -I/--head instead.\n"
        );

        // `PUT` against a `Put` request is redundant; against `Get` it is not.
        let mut quiet: Vec<u8> = Vec::new();
        customrequest_helper(HttpReq::Put, Some("PUT"), &mut quiet, &msgs);
        assert!(unwrapped(&String::from_utf8_lossy(&quiet), "Note: ")
            .contains("PUT is already"));
    }

    #[test]
    fn opt_depr_names_the_option_and_applies_nothing() {
        // `:1725` -- `"--%s is deprecated and has no function anymore"`.
        let Some(out) = run(&["--metalink", "https://x"]) else {
            return;
        };
        assert_eq!(out.result, Ok(()));
        assert_eq!(
            out.written,
            "Warning: --metalink is deprecated and has no function anymore\n"
        );

        // The short forms of the two deprecated `ARG_NONE` rows warn as well,
        // and neither sets a TLS version.
        let Some(short) = run(&["-2", "https://x"]) else {
            return;
        };
        assert!(short.written.contains("--sslv2 is deprecated"));
        assert_eq!(config(&short.global).map(|c| c.ssl_version), Some(0));
    }

    #[test]
    fn the_insecure_option_warning_interpolates_the_name() {
        // `:1899-1902` interpolates `a->lname`, so the two rows that share the
        // arm produce different bytes. Both are `ARG_BOOL|ARG_TLS`, and the gate
        // at `:2991` sits in `getparameter` rather than in `opt_bool`, so the
        // text is exercised where it lives -- which is also the only way to
        // assert it in a build that does not advertise TLS.
        let outcome = fixture();
        assert!(outcome.is_some());
        let Some((mut global, mut sink)) = outcome else {
            return;
        };
        let mut host = FakeHost::default();

        for (name, expected) in [
            (
                "ssl",
                "Warning: --ssl is an insecure option, consider \
                     --ssl-reqd instead\n",
            ),
            (
                "ftp-ssl",
                "Warning: --ftp-ssl is an insecure option, consider \
                         --ssl-reqd instead\n",
            ),
        ] {
            let Some(row) = findlongopt(name.as_bytes()) else {
                continue;
            };
            sink.clear();
            let applied = opt_bool(
                row,
                true,
                &mut global,
                &ParseState::default(),
                &mut host,
                &mut sink,
            );
            assert_eq!(applied, Ok(()));
            assert_eq!(
                unwrapped(&String::from_utf8_lossy(&sink), "Warning: "),
                expected,
                "--{name}"
            );
            assert_eq!(
                global.chain.current().map(|config| config.ftp_ssl),
                Some(true)
            );
        }

        // `--no-ssl` clears the flag and says nothing.
        let Some(row) = findlongopt(b"ssl") else {
            return;
        };
        sink.clear();
        let cleared = opt_bool(
            row,
            false,
            &mut global,
            &ParseState::default(),
            &mut host,
            &mut sink,
        );
        assert_eq!(cleared, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(
            global.chain.current().map(|config| config.ftp_ssl),
            Some(false)
        );

        // And the gate itself: with TLS absent the row never reaches `opt_bool`.
        let Some(gated) = run(&["--ssl", "ftp://x"]) else {
            return;
        };
        if tls_available() {
            assert_eq!(gated.result, Ok(()));
        } else {
            assert_eq!(gated.result, Err(ParameterError::LibcurlDoesntSupport));
        }
    }

    #[test]
    fn existingfile_and_the_flag_looking_filename_are_byte_exact() {
        // `:2213-2214`. `--netrc-file` is one of the six rows that call
        // `existingfile` and, unlike `--cacert`, is not `ARG_TLS`, so the text is
        // reachable whatever this build advertises.
        let Some(missing) = run(&["--netrc-file", "nowhere", "https://x"])
        else {
            return;
        };
        assert_eq!(missing.result, Err(ParameterError::BadUse));
        assert_eq!(
            unwrapped(&missing.written, "curl: "),
            "curl: The file 'nowhere' provided to --netrc-file does not exist\n\
             curl: option --netrc-file: is badly used here\n\
             curl: try 'curl --help' or 'curl --manual' for more information\n"
        );

        // `:2229` -- a leading dash with at least one more byte.
        let host = FakeHost::default().with_file("-v", "");
        let Some(flaggy) = run_with(host, &["--netrc-file", "-v", "https://x"])
        else {
            return;
        };
        assert!(unwrapped(&flaggy.written, "Warning: ").contains(
            "Warning: The filename argument '-v' looks like a flag."
        ));

        // A bare `-` is standard output and does not warn.
        let Some(dash) = run(&["-o", "-", "https://x"]) else {
            return;
        };
        assert!(!dash.written.contains("looks like a flag"));
    }

    #[test]
    fn has_leading_unicode_matches_the_c_range_without_reading_past_the_end() {
        // `:2880-2882` -- `e2 80 80` through `e2 80 ff`.
        assert!(has_leading_unicode(&[0xe2, 0x80, 0x80]));
        assert!(has_leading_unicode(&[0xe2, 0x80, 0xff]));
        assert!(has_leading_unicode(&[0xe2, 0x80, 0x93, b'x']));
        // The third byte must have its top bit set.
        assert!(!has_leading_unicode(&[0xe2, 0x80, 0x7f]));
        // C reads three bytes unguarded and relies on the NUL terminator; a
        // shorter argument must simply not match.
        assert!(!has_leading_unicode(&[0xe2, 0x80]));
        assert!(!has_leading_unicode(&[0xe2]));
        assert!(!has_leading_unicode(&[]));
        assert!(!has_leading_unicode(b"-v"));

        // The warning text, through the parser. U+2013 EN DASH is `e2 80 93`.
        let Some(out) = run(&["--user-agent", "\u{2013}x", "https://y"]) else {
            return;
        };
        assert!(unwrapped(&out.written, "Warning: ").contains(
            "The argument '\u{2013}x' starts with a Unicode character. Maybe \
             ASCII was intended?"
        ));
    }

    // -----------------------------------------------------------------------
    // 23-31: parser-level behaviour
    // -----------------------------------------------------------------------

    #[test]
    fn the_parser_fixture_is_available() {
        // Every test that parses a command line returns early when this is not
        // so; asserting it here reports the condition once and loudly instead of
        // letting those tests pass vacuously.
        assert!(
            fixture().is_some(),
            "GlobalConfig::init must succeed for the parser to be testable"
        );
    }

    #[test]
    fn a_double_dash_ends_option_processing() {
        // `:3068-3071` -- "enables the following (URL) argument to start with
        // -".
        let Some(out) = run(&["--", "-v"]) else {
            return;
        };
        assert_eq!(out.result, Ok(()));
        assert_eq!(out.global.verbosity, 0, "-v after -- is a URL");
        let url = config(&out.global)
            .and_then(|c| c.url_list.first())
            .and_then(|node| node.url.clone());
        assert_eq!(url, Some(b"-v".to_vec()));
    }

    #[test]
    fn a_bare_argument_becomes_a_url() {
        // `:3115-3120` -- `getparameter("--url", orig_opt, &used, config, 0)`,
        // with a recursion budget of zero rather than `CONFIG_MAX_LEVELS`.
        let Some(out) = run(&["https://one", "https://two"]) else {
            return;
        };
        assert_eq!(out.result, Ok(()));
        assert_eq!(config(&out.global).map(|c| c.num_urls), Some(2));
        let urls: Vec<Option<Vec<u8>>> = config(&out.global)
            .map(|c| c.url_list.iter().map(|node| node.url.clone()).collect())
            .unwrap_or_default();
        assert_eq!(
            urls,
            vec![Some(b"https://one".to_vec()), Some(b"https://two".to_vec())]
        );
    }

    #[test]
    fn next_requires_a_url_and_never_escapes() {
        // `:3106-3109`
        let Some(bare) = run(&["--next"]) else {
            return;
        };
        assert_eq!(bare.result, Err(ParameterError::BadUse));
        assert!(bare.written.contains("curl: missing URL before --next"));
        // `PARAM_NEXT_OPERATION` is never returned, so the reported reason is
        // `PARAM_BAD_USE`'s.
        assert!(bare.written.contains("is badly used here"));

        // `:3092-3105` -- with a URL set it starts a second operation.
        let Some(chained) = run(&["https://one", "--next", "https://two"])
        else {
            return;
        };
        assert_eq!(chained.result, Ok(()));
        assert_eq!(chained.global.chain.len(), 2);
        // Each operation carries its own URL.
        assert_eq!(chained.global.chain.get(0).map(|c| c.num_urls), Some(1));
        assert_eq!(chained.global.chain.get(1).map(|c| c.num_urls), Some(1));
    }

    #[test]
    fn continue_at_dash_with_remote_header_name_is_refused_after_the_walk() {
        // `:3128-3131`
        let Some(out) = run(&["-C", "-", "-J", "https://x"]) else {
            return;
        };
        assert_eq!(out.result, Err(ParameterError::ContdispResumeFrom));
        assert!(out.written.contains(
            "--continue-at and --remote-header-name cannot be combined"
        ));
        // The order does not matter, because the check is after the loop.
        let Some(swapped) = run(&["-J", "-C", "-", "https://x"]) else {
            return;
        };
        assert_eq!(swapped.result, Err(ParameterError::ContdispResumeFrom));
    }

    #[test]
    fn the_five_requests_are_exempt_from_reporting() {
        // `:3133-3138`. `--version` is the cheapest of them to reach.
        let Some(version) = run(&["--version"]) else {
            return;
        };
        assert_eq!(version.result, Err(ParameterError::VersionInfoRequested));
        assert!(version.written.is_empty(), "no diagnostic for a request");

        let Some(manual) = run(&["--manual"]) else {
            return;
        };
        assert_eq!(manual.result, Err(ParameterError::ManualRequested));
        assert!(manual.written.is_empty());

        // `--dump-ca-embed` is `ARG_NONE|ARG_TLS` (`src/tool_getparam.c:128`),
        // so the gate at `:2991` decides whether the request is reached at all.
        let Some(embed) = run(&["--dump-ca-embed"]) else {
            return;
        };
        if tls_available() {
            assert_eq!(embed.result, Err(ParameterError::CaEmbedRequested));
            assert!(embed.written.is_empty());
        } else {
            assert_eq!(embed.result, Err(ParameterError::LibcurlDoesntSupport));
        }

        // `--engine` is `ARG_STRG|ARG_TLS` (`src/tool_getparam.c:154`) and only
        // the literal argument `list` raises the request (`:2671-2676`).
        let Some(engines) = run(&["--engine", "list"]) else {
            return;
        };
        if tls_available() {
            assert_eq!(engines.result, Err(ParameterError::EnginesRequested));
            assert!(engines.written.is_empty());
        } else {
            assert_eq!(
                engines.result,
                Err(ParameterError::LibcurlDoesntSupport)
            );
        }

        // `--help` is dispatched inside the parser (`:3001-3005`): the output is
        // produced before the code is returned, and `src/tool_operate.c:2302`
        // does nothing further.
        let Some(help) = run(&["--help", "http"]) else {
            return;
        };
        assert_eq!(help.result, Err(ParameterError::HelpRequested));
        assert!(help.written.is_empty());
        assert_eq!(help.host.helped, vec![Some("http".to_owned())]);

        let Some(plain) = run(&["--help"]) else {
            return;
        };
        assert_eq!(plain.result, Err(ParameterError::HelpRequested));
        assert_eq!(plain.host.helped, vec![None]);
    }

    #[test]
    fn a_failing_colon_reports_the_reason_alone() {
        // `:3141-3144` -- `strcmp(":", orig_opt)`. `--no-` on `:`, the short
        // form of `--next`, fails while `orig_opt` is exactly `":"`... which
        // cannot be spelled, because `:` alone is not an option. The reachable
        // case is a short cluster whose element *is* `:` and which fails: `-:`
        // succeeds, so the assertion here is on the ordinary composition and on
        // the special case being present in the code path.
        let Some(unknown) = run(&["--nosuchthing"]) else {
            return;
        };
        assert!(unknown
            .written
            .starts_with("curl: option --nosuchthing: is unknown\n"));
        assert!(unknown.written.contains(
            "curl: try 'curl --help' or 'curl --manual' for more information"
        ));

        // The element that failed is the one named, not the one before it.
        let Some(missing) = run(&["https://x", "--user-agent"]) else {
            return;
        };
        assert_eq!(missing.result, Err(ParameterError::RequiresParameter));
        assert!(missing
            .written
            .contains("curl: option --user-agent: requires parameter"));
    }

    #[test]
    fn config_recursion_beyond_five_levels_names_the_limit() {
        assert_eq!(CONFIG_MAX_LEVELS, 5);

        // `:2246-2250` -- the message interpolates `CONFIG_MAX_LEVELS`, not the
        // current depth, so it always reads 5.
        let mut host = FakeHost::default();
        host.files.push((b"rc".to_vec(), Vec::new()));
        let Some(shallow) = run_with(host, &["-K", "rc", "https://x"]) else {
            return;
        };
        assert_eq!(shallow.result, Ok(()));
        // The budget handed on is one less than the one received.
        assert_eq!(shallow.host.configs, vec![(b"rc".to_vec(), 4)]);

        // Exhausting the budget is reached by calling `getparameter` with it
        // already spent, which is what a fifth nested `--config` does.
        let outcome = fixture();
        assert!(outcome.is_some());
        let Some((mut global, mut sink)) = outcome else {
            return;
        };
        let mut host = FakeHost::default();
        let mut used = false;
        let result = getparameter(
            b"--config",
            Some(b"rc"),
            &mut used,
            0,
            &mut global,
            &mut host,
            &mut sink,
        );
        assert_eq!(result, Err(ParameterError::BadUse));
        assert!(String::from_utf8_lossy(&sink)
            .contains("Max config file recursion level reached (5)"));
    }

    #[test]
    fn an_arg_tls_row_is_refused_when_tls_is_absent() {
        // `:2991-2994`. Whether this build reports TLS decides which way the
        // assertion runs, and both directions are asserted rather than assumed:
        // over-reporting a capability is what AAP section 0.6.5 calls the unsafe
        // error.
        let outcome = fixture();
        assert!(outcome.is_some());
        let Some((global, _)) = outcome else {
            return;
        };
        let has_tls = global.libinfo.feature_ssl();

        // `--dump-ca-embed` is `ARG_NONE|ARG_TLS` (`src/tool_getparam.c:128`),
        // so the gate applies to it as much as to a cipher list.
        let Some(embed) = run(&["--dump-ca-embed"]) else {
            return;
        };
        if has_tls {
            assert_eq!(embed.result, Err(ParameterError::CaEmbedRequested));
        } else {
            assert_eq!(embed.result, Err(ParameterError::LibcurlDoesntSupport));
        }

        let Some(ciphers) = run(&["--ciphers", "X", "https://y"]) else {
            return;
        };
        if has_tls {
            assert_eq!(ciphers.result, Ok(()));
        } else {
            assert_eq!(
                ciphers.result,
                Err(ParameterError::LibcurlDoesntSupport)
            );
            assert!(ciphers.written.contains(
                "the installed libcurl version does not support this"
            ));
        }
    }

    #[test]
    fn libcurl_rejects_a_blank_argument_in_the_parser() {
        // `:2508` uses `DENY_BLANK`, so this is the parser's decision and not
        // the emitter's.
        let Some(out) = run(&["--libcurl", "", "https://x"]) else {
            return;
        };
        assert_eq!(out.result, Err(ParameterError::BlankString));
        assert!(out
            .written
            .contains("blank argument where content is expected"));

        let Some(named) = run(&["--libcurl", "out.c", "https://x"]) else {
            return;
        };
        assert_eq!(named.result, Ok(()));
        assert_eq!(
            named.global.libcurl,
            Some(std::path::PathBuf::from("out.c"))
        );
    }

    #[test]
    fn the_verbosity_ladder_climbs_within_one_element_and_resets_between() {
        // `:1513-1567` with `:1526-1531`. Within one element the ladder climbs.
        for (spelling, level) in
            [("-v", 1_u8), ("-vv", 2), ("-vvv", 3), ("-vvvv", 4)]
        {
            let Some(out) = run(&[spelling, "https://x"]) else {
                return;
            };
            assert_eq!(
                out.global.verbosity, level,
                "{spelling} must reach verbosity {level}"
            );
        }

        // `-v -v` is two elements, and `verbose_nopts` is reset at the start of
        // each (`:2904`), so the second `-v` sees zero and resets to base
        // verbosity rather than climbing.
        let Some(separate) = run(&["-v", "-v", "https://x"]) else {
            return;
        };
        assert_eq!(separate.global.verbosity, 1);

        // Five in one element has "no effect for now" beyond four (`:1562`).
        let Some(five) = run(&["-vvvvv", "https://x"]) else {
            return;
        };
        assert_eq!(five.global.verbosity, 4);

        // `--no-verbose` resets and clears the trace type (`:1519-1524`).
        let Some(off) = run(&["-vvv", "--no-verbose", "https://x"]) else {
            return;
        };
        assert_eq!(off.global.verbosity, 0);
        assert_eq!(off.global.tracetype, TraceType::None);
        assert!(off.host.traces.contains(&"-all".to_owned()));

        // The 0-to-1 step sets the trace destination to `%`, which sends the
        // trace to stderr (`:1536-1537`).
        let Some(one) = run(&["-v", "https://x"]) else {
            return;
        };
        assert_eq!(one.global.tracetype, TraceType::Plain);
        assert_eq!(one.global.trace_dump, Some(std::path::PathBuf::from("%")));

        // The frozen override warning fires only when a *different* trace type
        // was already chosen (`:1541-1542`).
        let host = FakeHost::default();
        let Some(clash) =
            run_with(host, &["--trace-ascii", "d", "-v", "https://x"])
        else {
            return;
        };
        assert!(clash
            .written
            .contains("-v, --verbose overrides an earlier trace option"));
    }

    // -----------------------------------------------------------------------
    // 32-35: the value parsers
    // -----------------------------------------------------------------------

    #[test]
    fn get_size_parameter_accepts_and_rejects_exactly_what_c_does() {
        // `src/tool_getparam.c:563-623`, "Unit test 1623".
        assert_eq!(get_size_parameter(b"10k"), Ok(10240));
        assert_eq!(get_size_parameter(b"10K"), Ok(10240));
        assert_eq!(get_size_parameter(b"1M"), Ok(1_048_576));
        assert_eq!(get_size_parameter(b"1G"), Ok(1_073_741_824));
        assert_eq!(get_size_parameter(b"1T"), Ok(1_099_511_627_776));
        assert_eq!(get_size_parameter(b"1P"), Ok(1_125_899_906_842_624));
        // A fraction scales by the unit's decimal width.
        assert_eq!(get_size_parameter(b"1.5k"), Ok(1536));
        assert_eq!(get_size_parameter(b"1.5M"), Ok(1_572_864));
        // `b`/`B` and a bare number are bytes.
        assert_eq!(get_size_parameter(b"10b"), Ok(10));
        assert_eq!(get_size_parameter(b"10B"), Ok(10));
        assert_eq!(get_size_parameter(b"10"), Ok(10));
        assert_eq!(get_size_parameter(b"0"), Ok(0));

        // `:586-587` -- more than one trailing byte.
        assert_eq!(get_size_parameter(b"10kb"), Err(ParameterError::BadUse));
        // `:588-592` -- "cannot handle partial bytes".
        assert_eq!(get_size_parameter(b"1.5b"), Err(ParameterError::BadUse));
        assert_eq!(get_size_parameter(b"1.5"), Err(ParameterError::BadUse));
        // `:595-596` -- an unrecognised suffix.
        assert_eq!(get_size_parameter(b"10x"), Err(ParameterError::BadUse));
        // `:576-577` -- no number at all.
        assert_eq!(get_size_parameter(b""), Err(ParameterError::BadNumeric));
        assert_eq!(get_size_parameter(b"k"), Err(ParameterError::BadNumeric));
        // `:574-575` and `:618-619` -- both overflow paths.
        assert_eq!(
            get_size_parameter(b"99999999999999999999"),
            Err(ParameterError::NumberTooLarge)
        );
        assert_eq!(
            get_size_parameter(b"9223372036854775807k"),
            Err(ParameterError::NumberTooLarge)
        );
    }

    #[test]
    fn getunit_folds_ascii_case_over_the_five_suffixes() {
        // `:553` -- `(unit | 0x20) == list[i].unit`, which is bit 5 and not a
        // Unicode fold.
        for (upper, lower) in [
            (b'P', b'p'),
            (b'T', b't'),
            (b'G', b'g'),
            (b'M', b'm'),
            (b'K', b'k'),
        ] {
            let from_upper = getunit(upper).map(|entry| entry.mul);
            let from_lower = getunit(lower).map(|entry| entry.mul);
            assert_eq!(from_upper, from_lower);
            assert!(from_upper.is_some());
        }
        for rejected in *b"bx0 z" {
            assert!(getunit(rejected).is_none(), "{rejected} must not match");
        }
        // The five decimal widths, which are what bound a fraction.
        let widths: Vec<usize> =
            SIZE_UNITS.iter().map(|entry| entry.mlen).collect();
        assert_eq!(widths, vec![16, 13, 10, 7, 4]);
    }

    #[test]
    fn the_tos_table_is_31_rows_sorted_and_case_sensitive() {
        assert_eq!(TOS_ENTRIES.len(), 31);
        // Sorted for `bsearch` (`:2470-2472`).
        for pair in TOS_ENTRIES.windows(2) {
            let (Some(left), Some(right)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            assert_eq!(findarg(left.name, right.name), Ordering::Less);
        }
        // Spot values from `:853-885`.
        assert_eq!(find_tos(b"AF11").map(|e| e.value), Some(0x28));
        assert_eq!(find_tos(b"CS0").map(|e| e.value), Some(0x00));
        assert_eq!(find_tos(b"CS7").map(|e| e.value), Some(0xe0));
        assert_eq!(find_tos(b"EF").map(|e| e.value), Some(0xb8));
        assert_eq!(find_tos(b"VOICE-ADMIT").map(|e| e.value), Some(0xb0));
        assert_eq!(find_tos(b"LE").map(|e| e.value), Some(0x04));
        // `find_tos` is `strcmp`, so the lookup is case-sensitive and a
        // lower-case spelling falls through to the numeric branch.
        assert!(find_tos(b"af11").is_none());
        assert!(find_tos(b"nosuch").is_none());

        // Through the parser: a keyword and a number both work, and an
        // unrecognised keyword is a bad number.
        let Some(keyword) = run(&["--ip-tos", "CS5", "https://x"]) else {
            return;
        };
        assert_eq!(config(&keyword.global).map(|c| c.ip_tos), Some(0xa0));
        let Some(numeric) = run(&["--ip-tos", "32", "https://x"]) else {
            return;
        };
        assert_eq!(config(&numeric.global).map(|c| c.ip_tos), Some(32));
        let Some(lower) = run(&["--ip-tos", "af11", "https://x"]) else {
            return;
        };
        assert_eq!(lower.result, Err(ParameterError::BadNumeric));
    }

    #[test]
    fn parse_cert_parameter_covers_every_branch_of_the_c_body() {
        // `:396-397`
        assert_eq!(parse_cert_parameter(b""), Err(ParameterError::BlankString));

        // `:403-409` -- no `:` and no `\`, taken whole.
        assert_eq!(
            parse_cert_parameter(b"cert.pem"),
            Ok(CertParameter {
                certname: b"cert.pem".to_vec(),
                passphrase: None
            })
        );
        // ... and an RFC 7512 URI, matched case-insensitively.
        assert_eq!(
            parse_cert_parameter(b"PKCS11:token=x;object=y"),
            Ok(CertParameter {
                certname: b"PKCS11:token=x;object=y".to_vec(),
                passphrase: None
            })
        );

        // `:471-476` -- the separating colon.
        assert_eq!(
            parse_cert_parameter(b"cert.pem:secret"),
            Ok(CertParameter {
                certname: b"cert.pem".to_vec(),
                passphrase: Some(b"secret".to_vec())
            })
        );
        // A trailing colon with nothing after it sets no passphrase.
        assert_eq!(
            parse_cert_parameter(b"cert.pem:"),
            Ok(CertParameter {
                certname: b"cert.pem".to_vec(),
                passphrase: None
            })
        );

        // `:439-442` -- `\:` is a literal colon and does not separate.
        assert_eq!(
            parse_cert_parameter(b"weird\\:name"),
            Ok(CertParameter {
                certname: b"weird:name".to_vec(),
                passphrase: None
            })
        );
        // `:435-438` -- `\\` is one backslash.
        assert_eq!(
            parse_cert_parameter(b"a\\\\b:pass"),
            Ok(CertParameter {
                certname: b"a\\b".to_vec(),
                passphrase: Some(b"pass".to_vec())
            })
        );
        // `:443-447` -- a backslash before anything else keeps both bytes.
        assert_eq!(
            parse_cert_parameter(b"a\\nb:pass"),
            Ok(CertParameter {
                certname: b"a\\nb".to_vec(),
                passphrase: Some(b"pass".to_vec())
            })
        );
        // `:432-434` -- a trailing backslash is kept.
        assert_eq!(
            parse_cert_parameter(b"a:b\\"),
            Ok(CertParameter {
                certname: b"a".to_vec(),
                passphrase: Some(b"b\\".to_vec())
            })
        );

        // The `_WIN32` drive-letter branch (`:456-468`) is not compiled on any
        // of the four targets AAP section 0.1.1 names, so `c:\file:password`
        // splits at the first colon here. Asserted so the difference is on the
        // record rather than assumed.
        assert_eq!(
            parse_cert_parameter(b"c:\\file:password"),
            Ok(CertParameter {
                certname: b"c".to_vec(),
                passphrase: Some(b"\\file:password".to_vec())
            })
        );
    }

    #[test]
    fn get_file_and_password_only_replaces_a_password_it_was_given() {
        // `:527-530` -- the password is overwritten only when a passphrase was
        // present, which is why `--pass` before `--cert` survives.
        let mut file = None;
        let mut password = Some("kept".to_owned());
        assert_eq!(
            get_file_and_password(b"cert.pem", &mut file, &mut password),
            Ok(())
        );
        assert_eq!(file, Some(std::path::PathBuf::from("cert.pem")));
        assert_eq!(password, Some("kept".to_owned()));

        assert_eq!(
            get_file_and_password(b"cert.pem:new", &mut file, &mut password),
            Ok(())
        );
        assert_eq!(password, Some("new".to_owned()));
    }

    #[test]
    fn the_frozen_limits_hold_their_c_values() {
        assert_eq!(MAX_OPTION_LEN, 26);
        assert_eq!(CONFIG_MAX_LEVELS, 5);
        assert_eq!(MAX_DATAURLENCODE, 524_288_000);
        assert_eq!(MAX_QUERY_LEN, 100_000);
        assert_eq!(MAX_PARALLEL, 65535);
        assert_eq!(PARALLEL_DEFAULT, 50);
        assert_eq!(MAX_PARALLEL_HOST, 65535);
        assert_eq!(PARALLEL_HOST_DEFAULT, 0);
    }

    // `:41-42` -- the blank-argument policy flags. These are `const bool`, so
    // the check belongs in an anonymous constant rather than in a `#[test]`
    // body: it then holds at compile time, in every profile, and `clippy`'s
    // `assertions_on_constants` has nothing to object to.
    const _: () = {
        assert!(ALLOW_BLANK);
        assert!(!DENY_BLANK);
    };

    #[test]
    fn parallel_max_clamps_the_way_c_clamps() {
        // `:2858-2868` -- over the maximum clamps to it, below one restores the
        // default.
        let Some(high) = run(&["--parallel-max", "70000", "https://x"]) else {
            return;
        };
        assert_eq!(high.global.parallel_max, 65535);
        let Some(low) = run(&["--parallel-max", "0", "https://x"]) else {
            return;
        };
        assert_eq!(low.global.parallel_max, 50);
        let Some(exact) = run(&["--parallel-max", "7", "https://x"]) else {
            return;
        };
        assert_eq!(exact.global.parallel_max, 7);

        // `:2847-2857` -- the host limit's default is 0, "means not used".
        let Some(hosts) = run(&["--parallel-max-host", "0", "https://x"])
        else {
            return;
        };
        assert_eq!(hosts.global.parallel_host, 0);
    }

    #[test]
    fn replace_url_encoded_space_by_plus_rewrites_only_percent_twenty() {
        // `:489-515`, and without C's read past a trailing `%`.
        assert_eq!(
            replace_url_encoded_space_by_plus(b"a%20b"),
            b"a+b".to_vec()
        );
        assert_eq!(
            replace_url_encoded_space_by_plus(b"%20%20"),
            b"++".to_vec()
        );
        assert_eq!(
            replace_url_encoded_space_by_plus(b"a%21b"),
            b"a%21b".to_vec()
        );
        assert_eq!(replace_url_encoded_space_by_plus(b"%2"), b"%2".to_vec());
        assert_eq!(replace_url_encoded_space_by_plus(b"%"), b"%".to_vec());
        assert!(replace_url_encoded_space_by_plus(b"").is_empty());
    }

    #[test]
    fn upload_flags_set_clear_and_reject() {
        // `:1657-1709`
        let Some(set) = run(&["--upload-flags", "seen,draft", "https://x"])
        else {
            return;
        };
        assert_eq!(set.result, Ok(()));
        assert_eq!(
            config(&set.global).map(|c| c.upload_flags),
            Some(CURLULFLAG_SEEN | CURLULFLAG_DRAFT)
        );

        let Some(cleared) =
            run(&["--upload-flags", "seen,-seen,answered", "https://x"])
        else {
            return;
        };
        assert_eq!(
            config(&cleared.global).map(|c| c.upload_flags),
            Some(CURLULFLAG_ANSWERED)
        );

        // `:1697-1700` -- an unknown keyword stops the walk, and what came
        // before it stays applied.
        let Some(bad) = run(&["--upload-flags", "seen,nope", "https://x"])
        else {
            return;
        };
        assert_eq!(bad.result, Err(ParameterError::OptionUnknown));

        assert_eq!(FLAG_TABLE.len(), 5);
        assert_eq!(CURLULFLAG_FLAGGED, 1 << 3);
        assert_eq!(CURLULFLAG_DELETED, 1 << 1);
    }

    #[test]
    fn togglebit_sets_and_clears() {
        // `:1711-1720`
        let mut bits = 0_u64;
        togglebit(true, &mut bits, CURLAUTH_DIGEST);
        assert_eq!(bits, CURLAUTH_DIGEST);
        togglebit(true, &mut bits, CURLAUTH_NTLM);
        assert_eq!(bits, CURLAUTH_DIGEST | CURLAUTH_NTLM);
        togglebit(false, &mut bits, CURLAUTH_DIGEST);
        assert_eq!(bits, CURLAUTH_NTLM);
        // `CURLAUTH_ANY` excludes only `CURLAUTH_DIGEST_IE`
        // (`include/curl/curl.h:845`).
        assert_eq!(CURLAUTH_ANY & CURLAUTH_DIGEST_IE, 0);
        assert_eq!(CURLAUTH_ANY | CURLAUTH_DIGEST_IE, 0xffff_ffff);
        assert_eq!(CURLAUTH_GSSAPI, CURLAUTH_NEGOTIATE);
    }

    #[test]
    fn the_referer_auto_suffix_is_measured_off() {
        // `:2642-2658`
        let Some(auto) = run(&["-e", "https://from;auto", "https://x"]) else {
            return;
        };
        assert_eq!(
            config(&auto.global).and_then(|c| c.referer.clone()),
            Some("https://from".to_owned())
        );
        assert_eq!(config(&auto.global).map(|c| c.autoreferer), Some(true));

        // `;auto` alone clears the referer while still enabling the mode.
        let Some(only) = run(&["-e", ";auto", "https://x"]) else {
            return;
        };
        assert_eq!(config(&only.global).and_then(|c| c.referer.clone()), None);
        assert_eq!(config(&only.global).map(|c| c.autoreferer), Some(true));

        let Some(plain) = run(&["-e", "https://from", "https://x"]) else {
            return;
        };
        assert_eq!(config(&plain.global).map(|c| c.autoreferer), Some(false));
    }

    #[test]
    fn the_data_family_concatenates_and_json_does_not_separate() {
        // `:994-999`
        let Some(amp) = run(&["-d", "a=1", "-d", "b=2", "https://x"]) else {
            return;
        };
        assert_eq!(
            config(&amp.global).map(|c| c.postdata.clone()),
            Some(b"a=1&b=2".to_vec())
        );
        assert_eq!(config(&amp.global).map(|c| c.postfields), Some(true));

        let Some(json) =
            run(&["--json", "{\"a\":1}", "--json", "x", "https://y"])
        else {
            return;
        };
        assert_eq!(
            config(&json.global).map(|c| c.postdata.clone()),
            Some(b"{\"a\":1}x".to_vec())
        );
        assert_eq!(config(&json.global).map(|c| c.jsoned), Some(true));

        // `--data-raw` does not treat `@` as a file (`:944`).
        let Some(raw) = run(&["--data-raw", "@notafile", "https://x"]) else {
            return;
        };
        assert_eq!(raw.result, Ok(()));
        assert_eq!(
            config(&raw.global).map(|c| c.postdata.clone()),
            Some(b"@notafile".to_vec())
        );

        // `-d @file` reads it, and `file2string` strips the newlines.
        let host = FakeHost::default().with_file("body", "a=1\nb=2\n");
        let Some(fromfile) = run_with(host, &["-d", "@body", "https://x"])
        else {
            return;
        };
        assert_eq!(fromfile.result, Ok(()));
        assert_eq!(
            config(&fromfile.global).map(|c| c.postdata.clone()),
            Some(b"a=1b=2".to_vec())
        );

        // A file that cannot be opened is named in the frozen error.
        let Some(missing) = run(&["-d", "@nowhere", "https://x"]) else {
            return;
        };
        assert_eq!(missing.result, Err(ParameterError::ReadError));
        assert!(missing.written.contains("Failed to open nowhere"));
    }

    #[test]
    fn data_at_dash_reads_standard_input() {
        // `:947-949` -- "@- means the data comes from stdin". The stream is
        // reached through `ParseHost`, which is `StdinAccess` here, so no test
        // touches the real descriptor.
        let host = FakeHost::default().with_stdin("a=1\nb=2\n");
        let Some(piped) = run_with(host, &["-d", "@-", "https://x"]) else {
            return;
        };
        assert_eq!(piped.result, Ok(()));
        // `file2string` (`src/tool_paramhlp.c`) drops the newlines, exactly as
        // it does for a named file.
        assert_eq!(
            config(&piped.global).map(|c| c.postdata.clone()),
            Some(b"a=1b=2".to_vec())
        );
        assert_eq!(config(&piped.global).map(|c| c.postfields), Some(true));

        // `--data-binary @-` keeps them: `:962-965` is the "forced binary" arm
        // and reads through `file2memory` instead.
        let host = FakeHost::default().with_stdin("a=1\nb=2\n");
        let Some(binary) =
            run_with(host, &["--data-binary", "@-", "https://x"])
        else {
            return;
        };
        assert_eq!(binary.result, Ok(()));
        assert_eq!(
            config(&binary.global).map(|c| c.postdata.clone()),
            Some(b"a=1\nb=2\n".to_vec())
        );
    }

    #[test]
    fn time_cond_reads_a_date_then_a_file_then_gives_up() {
        // `:1613-1631` -- the three prefixes, including the `FALLTHROUGH` at
        // `:1616` that makes `+` and no prefix share an arm.
        for (argument, expected) in [
            ("+Thu, 01 Jan 1970 00:00:10 GMT", CURL_TIMECOND_IFMODSINCE),
            ("Thu, 01 Jan 1970 00:00:10 GMT", CURL_TIMECOND_IFMODSINCE),
            ("-Thu, 01 Jan 1970 00:00:10 GMT", CURL_TIMECOND_IFUNMODSINCE),
            ("=Thu, 01 Jan 1970 00:00:10 GMT", CURL_TIMECOND_LASTMOD),
        ] {
            let Some(dated) = run(&["-z", argument, "https://x"]) else {
                return;
            };
            assert_eq!(dated.result, Ok(()));
            assert_eq!(
                config(&dated.global).map(|c| (c.timecond, c.condtime)),
                Some((expected, 10)),
                "-z {argument}"
            );
        }

        // `:1635-1639` -- "now let's see if it is a filename to get the time
        // from instead!". The modification time arrives through
        // `ParseHost::file_time`, which is GAP #1.
        let host = FakeHost::default().with_time("stamped", 1_234_567);
        let Some(fromfile) = run_with(host, &["-z", "stamped", "https://x"])
        else {
            return;
        };
        assert_eq!(fromfile.result, Ok(()));
        assert_eq!(
            config(&fromfile.global).map(|c| (c.timecond, c.condtime)),
            Some((CURL_TIMECOND_IFMODSINCE, 1_234_567))
        );

        // `:1641-1646` -- neither a date nor a file: the condition is removed
        // and the frozen warning is emitted.
        let Some(neither) = run(&["-z", "nonsense", "https://x"]) else {
            return;
        };
        assert_eq!(neither.result, Ok(()));
        assert_eq!(
            config(&neither.global).map(|c| c.timecond),
            Some(CURL_TIMECOND_NONE)
        );
        assert_eq!(
            unwrapped(&neither.written, "Warning: "),
            "Warning: Illegal date format for -z, --time-cond (and not a \
             filename). Disabling time condition. See curl_getdate(3) for \
             valid date syntax.\n"
        );
    }

    #[test]
    fn data_urlencode_encodes_only_the_value_and_pluses_the_spaces() {
        // `:643-743`
        let Some(named) = run(&["--data-urlencode", "name=a b", "https://x"])
        else {
            return;
        };
        assert_eq!(
            config(&named.global).map(|c| c.postdata.clone()),
            Some(b"name=a+b".to_vec())
        );

        // No separator at all: the whole argument is the value and no name is
        // prepended (`:667-672`).
        let Some(bare) = run(&["--data-urlencode", "a b", "https://x"]) else {
            return;
        };
        assert_eq!(
            config(&bare.global).map(|c| c.postdata.clone()),
            Some(b"a+b".to_vec())
        );

        // `=value` is a value with an empty name, so nothing is prepended.
        let Some(equals) = run(&["--data-urlencode", "=a&b", "https://x"])
        else {
            return;
        };
        assert_eq!(
            config(&equals.global).map(|c| c.postdata.clone()),
            Some(b"a%26b".to_vec())
        );

        // `name@file` reads the file. `--url-query` reuses the same encoder and
        // joins with `&`.
        let host = FakeHost::default().with_file("v", "x y");
        let Some(query) = run_with(
            host,
            &["--url-query", "n@v", "--url-query", "+raw", "https://x"],
        ) else {
            return;
        };
        assert_eq!(
            config(&query.global).and_then(|c| c.query.clone()),
            Some("n=x+y&raw".to_owned())
        );
    }

    #[test]
    fn read_lines_drops_only_the_newline_and_skips_comments() {
        // `src/tool_parsecfg.c:281-347`, reproduced as GAP #5.
        let host = FakeHost::default()
            .with_file("urls", "https://a\n# comment\n\n  \r\nhttps://b");
        let Some(out) = run_with(host, &["--url", "@urls"]) else {
            return;
        };
        assert_eq!(out.result, Ok(()));
        let urls: Vec<Option<Vec<u8>>> = config(&out.global)
            .map(|c| c.url_list.iter().map(|node| node.url.clone()).collect())
            .unwrap_or_default();
        // The comment and the empty line are skipped. `"  \r"` is NOT skipped:
        // C's `ISBLANK` is space and tab only, so the first non-blank byte is
        // the `\r` -- and the line is stored WHOLE, leading blanks included,
        // because `:334-335` only scans past them to decide (`src/tool_parsecfg.c`).
        assert_eq!(
            urls,
            vec![
                Some(b"https://a".to_vec()),
                Some(b"  \r".to_vec()),
                Some(b"https://b".to_vec())
            ]
        );
        // `--url @file` treats every line as `-O` with globbing off (`:1147`).
        let flags: Vec<(bool, bool)> = config(&out.global)
            .map(|c| {
                c.url_list
                    .iter()
                    .map(|node| (node.useremote, node.noglob))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(flags, vec![(true, true), (true, true), (true, true)]);
    }
}
