// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! `--variable` definitions and `{{name:func}}` expansion: `src/var.c` and
//! `src/var.h`.
//!
//! This module owns two halves of one feature. [`setvariable`] is the
//! `--variable` argument grammar (`src/var.c:372-492`), which defines a
//! variable from a literal, a file, standard input or the process
//! environment. [`varexpand`] is the substitution pass
//! (`src/var.c:206-335`) that `src/tool_getparam.c:2966` runs over the
//! argument of any `--expand-<option>`, and the five text functions
//! (`src/var.c:75-204`) it can chain onto a value.
//!
//! Comments throughout cite `src/var.c:<line>` so that every frozen string,
//! constant and behavioural quirk can be checked against the oracle line by
//! line. AAP section 0.8.1 freezes all of it: option semantics, default
//! values and every byte the tool prints.
//!
//! # The `replaced` flag is load-bearing, so it is in the type
//!
//! C's `varexpand(line, out, replaced)` writes an output buffer *and* a
//! boolean, and `src/tool_getparam.c:2967-2971` keeps the ORIGINAL argument
//! when that boolean is false -- the buffer having been discarded by
//! `src/var.c:332-333`. [`varexpand`] returns
//! `Result<Option<Vec<u8>>, ParameterError>` instead, where `Ok(None)` is
//! exactly "nothing was substituted, there is no buffer" and `Ok(Some(bytes))`
//! is "substituted, here it is". That is the same contract with one class of
//! defect removed: a caller cannot read a buffer that was discarded, because
//! there is no buffer to read.
//!
//! # Storage: a `Vec`, and the newest definition wins
//!
//! C keeps an intrusive singly-linked list of `struct tool_var`
//! (`src/var.h:28-33`) hanging off `global->variables`, with the name as a
//! flexible array member. AAP section 0.6.9 replaces intrusive lists with
//! owned collections, so [`Variables`] holds a `Vec<ToolVar>`.
//!
//! Two properties of that list are observable and are preserved:
//!
//! * **`addvariable` PREPENDS** (`src/var.c:363-364`:
//!   `p->next = global->variables; global->variables = p;`) while
//!   `varcontent` walks from the head (`:50-56`). A redefinition therefore
//!   shadows the earlier entry, which is still present. [`Variables::add`]
//!   uses `Vec::insert(0, ..)` with a forward search, so the NEWEST wins. A
//!   plain `push` with a forward search would return the OLDEST, which is
//!   wrong; `push` with a reverse search would also have worked, and
//!   `insert(0, ..)` was chosen because it keeps the storage order identical
//!   to the C list rather than merely making the lookup agree.
//! * **Lookup is exact-length and case-SENSITIVE** (`:52`:
//!   `strlen(list->name) == nlen && !strncmp(...)`). Nothing here folds case.
//!
//! `varcleanup()` (`src/var.c:37-46`) has no counterpart and needs none: it
//! walks the list freeing each node's content and then the node, which is
//! precisely what dropping the `Vec<ToolVar>` does. The function disappears
//! rather than being translated.
//!
//! The storage stays deliberately opaque, as `src/var.c:337-341` asks -- "so
//! that we can improve this if we want better performance when managing many
//! at a later point". A linear scan is the faithful translation of the C
//! list; upstream has not replaced it with a map and neither does this. AAP
//! section 0.1.1 makes performance an explicit non-goal: "Where a choice
//! exists between a faster design and a more behaviourally faithful one,
//! faithfulness wins."
//!
//! # Content is bytes, not a string
//!
//! [`ToolVar`]'s content is a `Vec<u8>`, and that is not a stylistic
//! preference. `src/var.c:302-311` proves a variable may legitimately
//! *contain* a NUL byte: the diagnostic `variable contains null byte` fires
//! only when the value is about to be inserted into an expansion, never when
//! it is defined. Storing content as a `String` would either reject such a
//! value at definition time -- a behaviour change -- or lose the byte.
//! `--variable %NAME` and `--variable name@file` can both yield bytes that
//! are not valid UTF-8 for the same reason.
//!
//! The arguments are `&[u8]` throughout, matching
//! [`crate::output::formparse`], because they come from `argv` and are not
//! required to be UTF-8 either.
//!
//! # Three helpers belong to other modules and are called, not copied
//!
//! | C call | Owner here |
//! |---|---|
//! | `jsonquoted` (`src/var.c:117`) | [`crate::output::writeout::json_quoted`] |
//! | `curl_easy_escape` (`:127`) | `curl_rs_lib::url::escape::escape` |
//! | `file2memory_range` (`:455`) | [`crate::cli::paramhlp::file2memory_range`] |
//!
//! A second JSON escaper would drift from `--write-out '%{json}'`, a second
//! percent-encoder from `curl_easy_escape`, and a second range reader from
//! `--data @file`. None is written here.
//!
//! `curlx_base64_encode` and `curlx_base64_decode` (`:147`, `:167`) have no
//! reachable owner. See [`base64_encode`] for GAP #1 and for what the two
//! affected functions do in its absence.
//!
//! # Translation differences, each deliberate
//!
//! 1. **No pointer arithmetic anywhere.** The C original leans on
//!    `envp[-1] == '\\'` reading *backwards* from a `strstr` result
//!    (`:216`), an unguarded `while(ISSPACE(*c))` that trusts the NUL
//!    terminator (`:99-102`), in-place NUL writes into `char name[128]`
//!    (`:268`), and pointer differences across three buffers. Every one of
//!    them is an index or a slice here, and none can leave its bounds.
//! 2. **Input is truncated at its first NUL on entry.** C receives
//!    `const char *` and every `strstr`, `strlen` and `%s` in it stops at the
//!    terminator. A `&[u8]` carries no such convention, so [`until_nul`] is
//!    applied once at each entry point. `argv` cannot contain a NUL, so this
//!    is unobservable in production and exact in a test.
//! 3. **Diagnostics are routed, never printed.** No `println!` or
//!    `eprintln!` appears here. All four frozen texts go through
//!    [`crate::output::msgs`] so that the `--silent` and trace gates, the
//!    terminal wrapping and the 1,023-byte bound stay in one place.
//! 4. **The frozen texts keep their C format strings.** They are `const`
//!    items rendered by [`render`], a plain byte scanner. They are never
//!    handed to `format!`, which would collapse the `}}` in
//!    [`MSG_MISSING_CLOSE`] to a single brace and silently change the
//!    emitted bytes.
//!
//! # Why so much of this module is `#[allow(dead_code)]`
//!
//! `curl-rs/src/cli/args.rs` is the intended caller -- it consumes
//! [`varexpand`] for the `--expand-` prefix (`src/tool_getparam.c:2921-2925`,
//! applied at `:2955-2972`) and [`setvariable`] for row `:365` -- and the
//! `clap` surface that reaches both is not yet delivered. The attribute marks
//! a *pending caller*, not dead logic: every item below is exercised by the
//! tests at the end of this file. The same convention is used throughout this
//! crate for the same reason.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use crate::cli::args::ParameterError;
use crate::cli::paramhlp::{
    file2memory_range, ByteSource, SeekSource, StreamSource,
};
use crate::output::msgs::{self, DiagnosticSink, MsgConfig};
use crate::output::writeout::json_quoted;

// Constants -- src/var.c:33-34

/// `MAX_EXPAND_CONTENT` -- `src/var.c:33`.
///
/// The `curlx_dyn_init` cap on every buffer this module builds: the expansion
/// output (`:213`) and the working buffer the function chain writes into
/// (`:292`). Exceeding it makes the append fail, which the C maps to
/// `PARAM_NO_MEM` -- an over-long expansion is an ERROR, never a silent
/// truncation. See [`dyn_addn`] for the exact bound, which is one byte below
/// this value.
pub(crate) const MAX_EXPAND_CONTENT: usize = 10_000_000;

/// `MAX_VAR_LEN` -- `src/var.c:34`, "max length of a name".
///
/// Used two ways, and both matter. It sizes `char name[MAX_VAR_LEN]` in
/// `varexpand`, where a name is rejected by `nlen >= sizeof(name)` (`:253`),
/// and `char buf[MAX_VAR_LEN]` in `setvariable`, where the same rejection is
/// spelled `nlen >= MAX_VAR_LEN` (`:395`). Both tests are `>=`, so the
/// longest accepted name is 127 bytes.
pub(crate) const MAX_VAR_LEN: usize = 128;

/// `CURL_OFF_T_MAX` -- the open-ended upper bound of a byte range
/// (`src/var.c:385`).
///
/// `curl_off_t` is 64-bit on all four targets AAP section 0.1.1 mandates, so
/// this is `i64::MAX`. It is both the default `endoffset` and the sentinel
/// `:470` tests against to decide whether a range was given at all.
const CURL_OFF_T_MAX: i64 = i64::MAX;

// The frozen diagnostics -- verbatim C format strings with their anchors.
//
// Held as `const` items so that each appears exactly once and can be checked
// byte for byte with `grep -F`. They are rendered ONLY by `render`; see
// translation difference 4 in the module documentation for why `format!` is
// not an option.

/// `warnf` -- `src/var.c:240`.
const MSG_MISSING_CLOSE: &str = "missing close '}}' in '%s'";

/// `warnf` -- `src/var.c:254`.
const MSG_BAD_NAME_LENGTH: &str = "bad variable name length '%s'";

/// `warnf` -- `src/var.c:274`.
const MSG_BAD_NAME: &str = "bad variable name: %s";

/// `errorf` -- `src/var.c:308`.
const MSG_NULL_BYTE: &str = "variable contains null byte";

/// `errorf` -- `src/var.c:184`.
///
/// The `%.*s` precision is `flen`, the length of the WHOLE function chain
/// measured from its first colon, and the pointer is `finput`, that same
/// first colon. The message therefore shows the entire `:a:b:c` chain rather
/// than just the name that failed to match.
const MSG_UNKNOWN_FUNC: &str = "unknown variable function in '%.*s'";

/// `warnf` -- `src/var.c:396`.
///
/// C prints a `size_t` through `%zd`, the signed conversion. Every value that
/// reaches it is either 0 or at least [`MAX_VAR_LEN`], and both render as a
/// plain decimal.
const MSG_BAD_SETVAR_NAME_LENGTH: &str =
    "Bad variable name length (%zd), skipping";

/// `errorf` -- `src/var.c:411`.
const MSG_IMPORT_FAIL: &str = "Variable '%s' import fail, not set";

/// `errorf` -- `src/var.c:449`. Two arguments: the name, then the
/// operating-system reason.
const MSG_OPEN_FAIL: &str = "Failed to open %s: %s";

/// `warnf` -- `src/var.c:483`.
const MSG_BAD_SYNTAX: &str = "Bad --variable syntax, skipping: %s";

/// `notef` -- `src/var.c:352`.
const MSG_OVERWRITING: &str = "Overwriting variable '%s'";

/// The sentinel `64dec` emits when the decoder REJECTS its input --
/// `src/var.c:170`.
///
/// Frozen, byte for byte. A decode failure is deliberately NOT an error: the
/// text goes into the expansion and the chain continues.
const B64DEC_FAIL: &str = "[64dec-fail]";

/// Every frozen text this module can emit, in `src/var.c` line order.
///
/// Exists so a test can assert the set is complete and unaltered without
/// naming each constant twice. Nothing in the emitting paths reads it.
#[cfg(test)]
const FROZEN_TEXTS: [&str; 11] = [
    MSG_UNKNOWN_FUNC,
    MSG_MISSING_CLOSE,
    MSG_BAD_NAME_LENGTH,
    MSG_BAD_NAME,
    MSG_NULL_BYTE,
    MSG_OVERWRITING,
    MSG_BAD_SETVAR_NAME_LENGTH,
    MSG_IMPORT_FAIL,
    MSG_OPEN_FAIL,
    MSG_BAD_SYNTAX,
    B64DEC_FAIL,
];

// Byte primitives: curl's own character classes and buffer bound

/// `ISSPACE` -- `lib/curl_ctype.h:46`, which is
/// `ISBLANK(x) || ((x) >= 0xa && (x) <= 0x0d)`.
///
/// The set is space, tab, `\n`, **`\v`**, `\f` and `\r`. Rust's
/// [`u8::is_ascii_whitespace`] is NOT the same set -- it omits `\v` (0x0B) --
/// so it is not used and the six bytes are spelled out. `trim` would
/// otherwise leave a vertical tab behind that curl strips.
///
/// C applies the macro to a `char`, which is signed on all four mandated
/// targets, so a byte at or above 0x80 promotes to a negative `int` and
/// matches none of the three tests. Comparing on `u8` has exactly the same
/// effect: no byte outside ASCII is whitespace.
const fn is_space(byte: u8) -> bool {
    byte == b' ' || byte == b'\t' || matches!(byte, 0x0a..=0x0d)
}

/// `ISALNUM(x) || ((x) == '_')` -- the only bytes a variable name may hold
/// (`src/var.c:271` and `:392`).
///
/// `ISALNUM` (`lib/curl_ctype.h:41`) is ASCII digit, `a`-`z` or `A`-`Z`, which
/// is precisely [`u8::is_ascii_alphanumeric`]. As with [`is_space`], the C
/// macro's signed-`char` promotion makes it ASCII-only, so no byte at or above
/// 0x80 is ever accepted.
const fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The prefix of `bytes` a C `char *` would have covered.
///
/// C's `strstr`, `strlen` and `%s` all stop at the first NUL. A `&[u8]`
/// carries no terminator, so this is applied at each entry point and before
/// interpolating a value into a frozen text. See translation difference 2 in
/// the module documentation.
fn until_nul(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        Some(nul) => bytes.get(..nul).unwrap_or(bytes),
        None => bytes,
    }
}

/// The first occurrence of `needle` in `haystack` -- C's `strstr` and
/// `memchr`.
///
/// Returns `Some(0)` for an empty needle, which is what `strstr` does, and
/// `None` when the needle is longer than the haystack. `windows` is only ever
/// called with a non-zero length, which is the one input it rejects.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// One `curlx_dyn_addn` against a [`MAX_EXPAND_CONTENT`] cap.
///
/// `dyn_nappend` (`lib/curlx/dynbuf.c:67-85`) computes
/// `fit = len + idx + 1` -- the new bytes, the bytes already held, and the NUL
/// it always keeps room for -- and fails when `fit > toobig`. The usable length
/// is therefore one byte BELOW the cap: 9,999,999 here, not 10,000,000.
///
/// # Errors
///
/// [`ParameterError::NoMem`], which is what `src/var.c` reports for every
/// `curlx_dyn_*` failure. C also frees the buffer on that path
/// (`lib/curlx/dynbuf.c:83`); here the `Err` propagates and the `Vec` is
/// dropped, so no partial output can reach a caller either way.
fn dyn_addn(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ParameterError> {
    let fit = bytes.len().saturating_add(out.len()).saturating_add(1);
    if fit > MAX_EXPAND_CONTENT {
        return Err(ParameterError::NoMem);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

// Rendering the frozen texts

/// Substitutes the conversion specifiers of a frozen C format string.
///
/// Handles exactly the four forms the constants above use -- `%s`, `%zd`,
/// `%.*s` and `%%` -- each consuming one entry of `args` in order except `%%`,
/// which consumes none. A `%` introducing anything else is copied through
/// verbatim; that arm is unreachable for the constants in this module and
/// exists so the function is total.
///
/// `%.*s`'s precision is applied by the CALLER, which slices its argument to
/// `flen` before passing it. The specifier's two C varargs -- an `int`
/// precision and a pointer -- thus become one already-bounded slice, which is
/// what the specifier means and removes any way for the two to disagree.
///
/// This exists instead of `format!` because [`MSG_MISSING_CLOSE`] contains
/// `}}`: a `format!` would treat that as an escaped single brace and emit
/// `missing close '}' in '...'`, one byte short of the frozen text.
fn render(format: &str, args: &[&[u8]]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(format.len());
    let mut next = 0usize;
    let mut rest: &[u8] = format.as_bytes();

    while let Some((&byte, tail)) = rest.split_first() {
        if byte != b'%' {
            out.push(byte);
            rest = tail;
            continue;
        }
        if let Some(after) = strip_prefix(tail, b"%") {
            out.push(b'%');
            rest = after;
        } else if let Some(after) = strip_prefix(tail, b"s") {
            push_arg(&mut out, args, &mut next);
            rest = after;
        } else if let Some(after) = strip_prefix(tail, b"zd") {
            push_arg(&mut out, args, &mut next);
            rest = after;
        } else if let Some(after) = strip_prefix(tail, b".*s") {
            push_arg(&mut out, args, &mut next);
            rest = after;
        } else {
            out.push(b'%');
            rest = tail;
        }
    }

    out
}

/// The remainder of `bytes` after `prefix`, or `None` when it does not match.
fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.starts_with(prefix) {
        bytes.get(prefix.len()..)
    } else {
        None
    }
}

/// Appends the next argument, then advances past it.
///
/// A missing argument contributes nothing rather than panicking, so a
/// mismatch between a format string and its argument list can never abort the
/// tool over a diagnostic.
fn push_arg(out: &mut Vec<u8>, args: &[&[u8]], next: &mut usize) {
    if let Some(arg) = args.get(*next) {
        out.extend_from_slice(arg);
    }
    *next = next.saturating_add(1);
}

// Diagnostics

/// Where this module's diagnostics go, and the gates that decide whether they
/// are emitted at all.
///
/// C reaches a mutable global (`global->silent`, `global->showerror`,
/// `global->tracetype`) and a global `FILE *tool_stderr`. Both are owned by
/// the caller here and threaded explicitly, which is what makes the frozen
/// texts assertable in a unit test. The shape follows
/// [`crate::output::formparse`]'s `FormDiag` so that the two argument-parsing
/// modules report the same way.
///
/// The three emitters are private: the frozen texts are this module's, and
/// nothing outside it has a reason to send one.
pub(crate) struct VarDiag<'a> {
    /// The destination, byte-faithful unless it is a terminal.
    sink: &'a mut dyn DiagnosticSink,

    /// `--silent`, `--show-error` and the trace selection.
    config: MsgConfig,
}

impl<'a> VarDiag<'a> {
    /// Binds a sink and the three gate predicates.
    #[allow(dead_code)]
    pub(crate) fn new(
        sink: &'a mut dyn DiagnosticSink,
        config: MsgConfig,
    ) -> Self {
        Self { sink, config }
    }

    /// `warnf` (`src/tool_msgs.c:93-101`): prefix `Warning: `, suppressed by
    /// `--silent` and NOT restored by `--show-error`.
    ///
    /// Routed through `warnf_bytes` rather than `warnf` because every one of
    /// the four warnings here interpolates text taken straight from `argv`,
    /// which is not required to be valid UTF-8. Rendering such a value through
    /// `Display` would substitute U+FFFD and change the emitted bytes. The
    /// prefix, the terminal wrapping and the 1,023-byte bound are identical on
    /// both paths.
    fn warn(&mut self, format: &str, args: &[&[u8]]) {
        let message = render(format, args);
        msgs::warnf_bytes(&mut *self.sink, &self.config, &message);
    }

    /// `errorf` (`src/tool_msgs.c:129-137`): prefix `curl: `, suppressed by
    /// `--silent` unless `--show-error` is also given.
    ///
    /// Byte-routed for the same reason as [`VarDiag::warn`]: `Failed to open
    /// %s: %s` reports a filename from the command line.
    fn error(&mut self, format: &str, args: &[&[u8]]) {
        let message = render(format, args);
        msgs::errorf_bytes(&mut *self.sink, &self.config, &message);
    }

    /// `notef` (`src/tool_msgs.c:79-87`): prefix `Note: `, emitted ONLY under
    /// a trace or verbose selection and never gated on `--silent`.
    ///
    /// `crate::output::msgs` offers no byte-oriented note, and none is needed:
    /// the single note this module emits interpolates a variable name, and a
    /// name is ASCII alphanumeric or underscore by construction
    /// (`src/var.c:271`, `:392`), so the lossy conversion cannot alter a byte.
    fn note(&mut self, format: &str, args: &[&[u8]]) {
        let message = render(format, args);
        let text = String::from_utf8_lossy(&message);
        msgs::notef(&mut *self.sink, &self.config, format_args!("{}", text));
    }
}

// The variable store

/// One defined variable -- `struct tool_var` (`src/var.h:29-34`).
///
/// C allocates the name as a flexible array inside the node
/// (`char name[1]`, sized at `malloc` time) and keeps `content` plus an
/// explicit `clen` beside it. Both become owned Rust values, so the `clen`
/// field disappears into `Vec::len` and the `next` pointer into the enclosing
/// [`Variables`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ToolVar {
    /// The name, guaranteed by construction to be shorter than
    /// [`MAX_VAR_LEN`] and to hold only bytes accepted by [`is_name_byte`].
    /// That makes it ASCII, hence a `String` rather than a `Vec<u8>`.
    name: String,

    /// The content, as bytes.
    ///
    /// This is deliberately NOT a `String`. `src/var.c:303-311` proves a
    /// variable may legitimately hold a NUL -- and, by the same argument, any
    /// other non-UTF-8 byte, since `--variable name@file` reads a file in
    /// binary mode (`:452`) and `--variable %NAME` takes whatever the
    /// environment holds. The diagnostic `variable contains null byte` fires
    /// when the value is about to be substituted, not when it is defined, so
    /// rejecting such a value here would be a behaviour change.
    content: Vec<u8>,
}

impl ToolVar {
    /// The variable's name.
    #[allow(dead_code)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The variable's content, which is arbitrary bytes.
    #[allow(dead_code)]
    pub(crate) fn content(&self) -> &[u8] {
        &self.content
    }
}

/// Every variable defined by `--variable`, in lookup order.
///
/// C keeps these on `global->variables`, an intrusive singly-linked list
/// reached through the mutable global config. AAP 0.6.9 replaces intrusive
/// lists with owned collections, and AAP 0.1.2 replaces reaches into shared
/// mutable state with explicit ownership, so this is a plain `Vec` that the
/// caller owns and lends.
///
/// # Why a `Vec` and not a `HashMap`
///
/// `src/var.c:339-341` documents the storage as deliberately opaque, "so that
/// we can improve this if we want better performance when managing many at a
/// later point". Upstream has not made that change, and AAP 0.1.1 settles the
/// trade-off the other way in any case: "Where a choice exists between a
/// faster design and a more behaviourally faithful one, faithfulness wins."
/// A linear scan is the faithful translation.
///
/// # Why the order is load-bearing
///
/// `addvariable` PREPENDS (`p->next = global->variables; global->variables =
/// p;` at `src/var.c:363-364`) and `varcontent` walks from the head, so a
/// redefinition shadows the earlier entry while that entry remains in the
/// list. [`Variables::add`] therefore uses `Vec::insert(0, ..)` and
/// [`Variables::varcontent`] searches forward: newest wins. A plain `push`
/// with a forward search would return the OLDEST, which is wrong; a `push`
/// with a reverse search would be equally correct but would put the
/// difference in the reader's way at every lookup rather than once at
/// definition.
///
/// # `varcleanup`
///
/// `varcleanup` (`src/var.c:37-46`) walks the list freeing each node's content
/// and the node itself. It has no counterpart here: dropping this struct drops
/// the `Vec`, which drops each [`ToolVar`], which drops its `String` and
/// `Vec<u8>`. The one call site (`src/tool_main.c` by way of
/// `free_globalconfig`) disappears with it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Variables {
    /// Newest first, so a forward scan finds the most recent definition.
    vars: Vec<ToolVar>,
}

impl Variables {
    /// `varcontent` (`src/var.c:48-58`): the variable named by `name`, or
    /// `None`.
    ///
    /// The C comparison is `(strlen(list->name) == nlen) && !strncmp(name,
    /// list->name, nlen)` -- exact length and case-SENSITIVE. `strncmp`, not
    /// `strncasecmp`; `Variable` and `variable` are two different variables.
    #[allow(dead_code)]
    pub(crate) fn varcontent(&self, name: &[u8]) -> Option<&ToolVar> {
        self.vars.iter().find(|var| var.name.as_bytes() == name)
    }

    /// `addvariable` (`src/var.c:342-370`): defines `name`, replacing any
    /// earlier definition in lookup order.
    ///
    /// The note at `:352` is emitted BEFORE the new entry goes in, and only
    /// when an entry with this name already exists. It is a note, not a
    /// warning, so it appears only under `--verbose` or a trace selection
    /// (`src/tool_msgs.c:79-87`) -- see [`VarDiag::note`].
    ///
    /// C's `DEBUGASSERT(nlen)` at `:347` becomes a `debug_assert!`. Both
    /// callers reject an empty name before reaching here
    /// (`src/var.c:395` and `:252`), so this is a statement about this
    /// module's own consistency rather than about user input, and compiling it
    /// out of a release build is the same choice C makes.
    fn add(&mut self, name: &[u8], content: Vec<u8>, diag: &mut VarDiag<'_>) {
        debug_assert!(!name.is_empty());

        if let Some(existing) = self.varcontent(name) {
            // `src/var.c:352`. The name is ASCII by construction, so the
            // borrow can be cloned cheaply to release `self` before the
            // emitter runs.
            let existing = existing.name.clone();
            diag.note(MSG_OVERWRITING, &[existing.as_bytes()]);
        }

        // A name reaching here consists only of bytes accepted by
        // `is_name_byte`, all of which are ASCII, so the conversion cannot
        // fail. `from_utf8_lossy` is used rather than an `unwrap` so that no
        // path in this module can panic; on the impossible branch it would
        // substitute U+FFFD, which is still a valid `String`.
        let name = String::from_utf8_lossy(name).into_owned();
        self.vars.insert(0, ToolVar { name, content });
    }

    /// How many definitions are held, shadowed entries included.
    ///
    /// Counts nodes, not distinct names, exactly as walking C's list would:
    /// a redefinition leaves the earlier node in place.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.vars.len()
    }

    /// Whether no variable has been defined.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

// The five variable functions

/// One of the five functions a `{{name:...}}` chain may name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VarFunc {
    /// `trim` -- strip leading and trailing whitespace (`src/var.c:64`).
    Trim,

    /// `json` -- escape for a JSON string body (`src/var.c:66`).
    Json,

    /// `url` -- percent-encode (`src/var.c:68`).
    Url,

    /// `b64` -- base64-encode (`src/var.c:70`).
    B64,

    /// `64dec` -- base64-decode; the C spells the comment
    /// `/* base64 decode */` (`src/var.c:72`).
    Dec64,
}

/// The function names, in the order the C's `else if` ladder tests them
/// (`src/var.c:94-181`).
///
/// The order has no observable effect -- no name is a prefix of another, and
/// `ENDOFFUNC` would separate them even if one were -- but it is kept so the
/// two ladders read the same way.
const FUNCS: [(VarFunc, &[u8]); 5] = [
    (VarFunc::Trim, b"trim"),
    (VarFunc::Json, b"json"),
    (VarFunc::Url, b"url"),
    (VarFunc::B64, b"b64"),
    (VarFunc::Dec64, b"64dec"),
];

/// `FUNCMATCH` across all five names (`src/var.c:61-62`), returning the
/// function and the length to advance by.
///
/// ```c
/// #define ENDOFFUNC(x) (((x) == '}') || ((x) == ':'))
/// #define FUNCMATCH(ptr, name, len) \
///   (!strncmp(ptr, name, len) && ENDOFFUNC((ptr)[len]))
/// ```
///
/// The `ENDOFFUNC` half is what makes this a whole-token match rather than a
/// prefix match: `trimx` does NOT match `trim`, and neither does `trim` at the
/// very end of the input, because the byte after the name must be `}` or `:`.
/// C reads that byte from a NUL-terminated string, so at the end of input it
/// sees `\0`, which is neither; `slice::get` returning `None` is the same
/// answer without the terminator.
fn match_func(f: &[u8]) -> Option<(VarFunc, usize)> {
    for (func, name) in FUNCS {
        // `!strncmp(ptr, name, len)`. `strncmp` stops at the first difference,
        // so it never reads past a shorter string's terminator; `starts_with`
        // is false for a shorter slice for the same reason.
        if f.starts_with(name) {
            // `ENDOFFUNC((ptr)[len])`
            if let Some(b'}' | b':') = f.get(name.len()) {
                return Some((func, name.len()));
            }
        }
    }
    None
}

/// What a base64 call produced.
///
/// C's `curlx_base64_encode` and `curlx_base64_decode` return a `CURLcode`,
/// and `src/var.c` treats a non-zero return two different ways: the encode
/// path reports `PARAM_NO_MEM` (`:148-151`) while the decode path emits
/// `[64dec-fail]` and carries on (`:169-172`). Those are the `Rejected` and
/// `Produced` cases. The third case exists because of GAP #1 below and is kept
/// distinct so that neither of the first two can be reported for a reason that
/// is not about the input.
///
/// The `Produced` and `Rejected` variants are constructed only by tests while
/// GAP #1 stands. They are retained rather than deferred because they are the
/// shape [`apply_b64`] and [`apply_64dec`] need, and because the
/// `[64dec-fail]` behaviour they drive is frozen and therefore has to stay
/// asserted.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum CodecOutcome {
    /// The call succeeded and produced these bytes.
    Produced(Vec<u8>),

    /// The call ran and refused the input -- a `CURLcode` about the data.
    Rejected,

    /// The call could not be made at all. See GAP #1 on [`encode_base64`].
    Unavailable,
}

/// `curlx_base64_encode(c, clen, &enc, &elen)` -- `src/var.c:147`.
///
/// Blocked: see the `GAP #1` comment in the body.
///
/// The owner fixed by AAP section 0.4.1 is
/// `curl-rs-lib/src/util/base64.rs`, from `lib/curlx/base64.c`. That file does
/// not exist, and `curl-rs-lib`'s `mod util` is `pub(crate)`
/// (`curl-rs-lib/src/lib.rs:623`), so even once it does exist it will not be
/// visible from this crate without a re-export the owning unit of work has to
/// add. Every public module of `curl-rs-lib` was searched -- `error`,
/// `version`, `url` and `multi` are the four that exist, and the crate root's
/// re-export list holds no base64 entry.
///
/// Adding the `base64` crate and hand-rolling the codec are both ruled out, so
/// this reports [`CodecOutcome::Unavailable`] and the two call sites turn that
/// into `PARAM_NO_MEM` -- the same code C reports when the encode call fails,
/// and never a claim about the caller's data.
fn encode_base64(_input: &[u8]) -> CodecOutcome {
    // GAP #1: curl-rs-lib exposes no public base64; src/var.c:148,:167 needs
    // curlx_base64_encode/decode for the {{name:b64}} and {{name:64dec}}
    // functions.
    CodecOutcome::Unavailable
}

/// `curlx_base64_decode(c, &enc, &elen)` -- `src/var.c:167`.
///
/// Blocked by GAP #1 on [`encode_base64`]. Reports
/// [`CodecOutcome::Unavailable`] rather than [`CodecOutcome::Rejected`]
/// precisely so that `[64dec-fail]`, which asserts the input was bad base64,
/// is never emitted for an input nobody looked at.
fn decode_base64(_input: &[u8]) -> CodecOutcome {
    CodecOutcome::Unavailable
}

/// The `b64` tail of `src/var.c:141-160`.
///
/// `if(result) { err = PARAM_NO_MEM; break; }` at `:148-151`: an encode
/// failure aborts the whole chain. There is no sentinel on this side.
fn apply_b64(
    out: &mut Vec<u8>,
    outcome: CodecOutcome,
) -> Result<(), ParameterError> {
    match outcome {
        // `:154`
        CodecOutcome::Produced(bytes) => dyn_addn(out, &bytes),
        // `:148-151`, and GAP #1's reported outcome.
        CodecOutcome::Rejected | CodecOutcome::Unavailable => {
            Err(ParameterError::NoMem)
        }
    }
}

/// The `64dec` tail of `src/var.c:161-181`.
///
/// A decode failure is **not** an error: `:169-172` puts the literal
/// `[64dec-fail]` in the output and the chain continues, so a following
/// function sees those twelve bytes as its input. Only a buffer failure ends
/// the chain.
fn apply_64dec(
    out: &mut Vec<u8>,
    outcome: CodecOutcome,
) -> Result<(), ParameterError> {
    match outcome {
        // `:174`
        CodecOutcome::Produced(bytes) => dyn_addn(out, &bytes),
        // `:170` -- frozen, byte for byte, and not an error.
        CodecOutcome::Rejected => dyn_addn(out, B64DEC_FAIL.as_bytes()),
        // GAP #1: nothing looked at the input, so `[64dec-fail]` would be a
        // false claim about it.
        CodecOutcome::Unavailable => Err(ParameterError::NoMem),
    }
}

/// `varfunc` (`src/var.c:75-204`): runs a `:a:b:c` chain over `content`, left
/// to right.
///
/// `functions` is the chain starting AT the colon that separates it from the
/// name, running to the end of the line -- which is what C passes, since its
/// `f` is a pointer into the still-terminated input rather than a bounded
/// span. That is safe here for the same reason it is safe there: the loop stops
/// as soon as it sees `}` (`:87-89`), and `FUNCMATCH` requires the byte after
/// a name to be `}` or `:`, so no name can match across the closing `}}`.
///
/// `flen` is the chain's true length, `clp - funcp` (`src/var.c:295`). It is
/// used for exactly one thing: the precision of the unknown-function
/// diagnostic's `%.*s`, which shows the WHOLE chain from the first colon and
/// not just the offending name.
///
/// # Errors
///
/// [`ParameterError::ExpandError`] for a name that is not one of the five, and
/// [`ParameterError::NoMem`] for a buffer or codec failure. C frees the output
/// buffer on either path (`:201-202`); returning `Err` does the same by
/// dropping it, so a caller can never see partial output.
fn varfunc(
    content: &[u8],
    functions: &[u8],
    flen: usize,
    diag: &mut VarDiag<'_>,
) -> Result<Vec<u8>, ParameterError> {
    // `c`/`clen`. C starts with the caller's pointer and switches to an owned
    // `curlx_memdup0` copy after the first lap; owning it from the start is
    // the same value with one fewer branch. An undefined variable arrives here
    // as an empty slice, which is C's `value == NULL, vlen == 0`.
    let mut working: Vec<u8> = content.to_vec();

    // The `out` dynbuf, capped by the caller at `MAX_EXPAND_CONTENT`
    // (`src/var.c:292`).
    let mut out: Vec<u8> = Vec::new();

    // `f`, and `finput` for the diagnostic.
    let mut f: &[u8] = functions;

    // `while(*f && !err)` -- `:86`. The `!err` half is the `?` operator here.
    while let Some(&first) = f.first() {
        // `:87-89` -- end of the chain.
        if first == b'}' {
            break;
        }

        // `:93` -- move over the colon. Known to be one: the caller only calls
        // this when `memchr` found a colon, and every later lap arrives here
        // through `FUNCMATCH`, which accepts only `}` or `:` after a name.
        f = f.get(1..).unwrap_or(&[]);

        let Some((func, len)) = match_func(f) else {
            // `:182-187`. `finput` is the chain's start and `flen` its full
            // length, so the message shows `:a:b:c`, not the failing name.
            let chain = functions.get(..flen).unwrap_or(functions);
            diag.error(MSG_UNKNOWN_FUNC, &[chain]);
            return Err(ParameterError::ExpandError);
        };

        // `f += FUNC_x_LEN`
        f = f.get(len..).unwrap_or(&[]);

        // Every arm opens with `curlx_dyn_reset(out)`, so it is hoisted.
        out.clear();

        match func {
            // `:94-112`
            VarFunc::Trim => {
                let mut start = 0usize;
                let mut end = working.len();

                // `if(clen)` at `:97`. With no content the whole trimming
                // block is skipped and the empty result is emitted unchanged.
                if !working.is_empty() {
                    // `:99-102` -- "skip leading white space, including CRLF".
                    // C's loop is `while(ISSPACE(*c))`, unbounded, relying on
                    // the terminator to stop it. Bounding by the length is
                    // exactly equivalent: `is_space(0)` is false, so an
                    // interior NUL stops the scan at the same byte the
                    // terminator would, and the byte at `clen` is the
                    // terminator itself.
                    while start < end
                        && working.get(start).is_some_and(|&b| is_space(b))
                    {
                        start = start.saturating_add(1);
                    }

                    // `:103-104` -- `while(len && ISSPACE(c[len - 1])) len--`.
                    // C's `c` has advanced by the leading count and its `len`
                    // shrunk by the same amount, so `c[len - 1]` is the
                    // absolute byte `end - 1` and `len != 0` is `end > start`.
                    while end > start
                        && working
                            .get(end.saturating_sub(1))
                            .is_some_and(|&b| is_space(b))
                    {
                        end = end.saturating_sub(1);
                    }
                }

                // `:107-111`
                let trimmed = working.get(start..end).unwrap_or(&[]);
                dyn_addn(&mut out, trimmed)?;
            }

            // `:113-121`
            VarFunc::Json => {
                if !working.is_empty() {
                    // `jsonquoted(c, clen, out, FALSE)` -- lowercase FALSE.
                    // The limit is the dynbuf's own cap, which
                    // `src/var.c:292` set to `MAX_EXPAND_CONTENT`; the sibling
                    // applies the same `len + used + 1 > toobig` rule.
                    //
                    // Delegated rather than reimplemented so that this and
                    // `--write-out '%{json}'` cannot drift apart.
                    json_quoted(&working, &mut out, false, MAX_EXPAND_CONTENT)
                        .map_err(|()| ParameterError::NoMem)?;
                }
            }

            // `:123-140`
            VarFunc::Url => {
                if !working.is_empty() {
                    // `curl_easy_escape(NULL, c, (int)clen)`, which takes an
                    // explicit length and therefore escapes an interior NUL as
                    // `%00` rather than stopping at it. The engine's version
                    // is infallible, so C's `if(!enc)` out-of-memory arm at
                    // `:128-131` has no counterpart. The C then appends with
                    // `curlx_dyn_add`, i.e. bounded by `strlen`; escaping
                    // never emits a NUL, so the two agree.
                    let encoded = curl_rs_lib::url::escape::escape(&working);
                    dyn_addn(&mut out, &encoded)?;
                }
            }

            // `:141-160`
            VarFunc::B64 => {
                if !working.is_empty() {
                    apply_b64(&mut out, encode_base64(&working))?;
                }
            }

            // `:161-181`
            VarFunc::Dec64 => {
                if !working.is_empty() {
                    apply_64dec(&mut out, decode_base64(&working))?;
                }
            }
        }

        // `:188-197` -- the output becomes the next lap's input. C frees the
        // previous copy and takes a fresh `curlx_memdup0`; reusing the buffer
        // is the same copy without the allocation, and `out` still holds the
        // value this function returns if the chain ends here.
        working.clear();
        working.extend_from_slice(&out);
    }

    Ok(out)
}

// `{{name:func}}` expansion

/// `varexpand` (`src/var.c:206-335`): substitutes every `{{name}}` and
/// `{{name:func}}` in `line`.
///
/// Returns `Some(expanded)` when at least one substitution was made and `None`
/// when none was -- which is C's `*replaced` out-parameter, and it is
/// load-bearing rather than informational. `src/tool_getparam.c:2967-2971`
/// keeps the ORIGINAL argument when `replaced` is false, and C reinforces that
/// by freeing the output buffer at `:332-333`. An `Option` makes the two
/// inseparable: there is no way to read a buffer that was not replaced.
///
/// # The escaped-brace quirk, preserved deliberately
///
/// `\{{x}}` takes the backslash branch at `:216-229`, which emits the text
/// without the backslash, emits `{{`, and -- this is the point -- does NOT set
/// `added`. So an input whose only `{{` is escaped finishes with `added ==
/// false`, the carefully built buffer is discarded, and the caller keeps the
/// original string WITH the backslash still in it. The escape therefore only
/// takes effect when some other `{{` in the same argument was expanded.
/// AAP section 0.8.2 forbids a change justified by improvement, and this is
/// squarely that: it is reproduced, not fixed.
///
/// # Errors
///
/// [`ParameterError::ExpandError`] for a value holding a NUL byte or an unknown
/// function, and [`ParameterError::NoMem`] when the output would exceed
/// [`MAX_EXPAND_CONTENT`]. An over-long expansion is an error, never a silent
/// truncation.
#[allow(dead_code)]
pub(crate) fn varexpand(
    line: &[u8],
    vars: &Variables,
    diag: &mut VarDiag<'_>,
) -> Result<Option<Vec<u8>>, ParameterError> {
    // `input` at `:211`: the whole argument, kept for the two `%s`
    // diagnostics, which report it rather than the position that failed.
    let input = until_nul(line);

    // `line`, the cursor. C advances a pointer; this rebinds a slice.
    let mut line: &[u8] = input;

    // The `out` dynbuf of `:213`, capped by [`dyn_addn`].
    let mut out: Vec<u8> = Vec::new();

    // `added` at `:210`
    let mut added = false;

    // `do { envp = strstr(line, "{{"); ... } while(envp);` at `:214-324`.
    //
    // The C is a do-while whose body opens with the search, so when the search
    // finds nothing both of the body's branches are skipped -- `(envp > line)`
    // is false for a null `envp`, and so is `else if(envp)` -- and the
    // `while(envp)` test then ends the loop. A `while let` over the search is
    // that shape exactly, with no iteration in which `envp` is null.
    while let Some(at) = find(line, b"{{") {
        // `:216` -- `(envp > line) && envp[-1] == '\\'`. The `envp > line`
        // half is why a `{{` at position 0 can never be escaped: there is no
        // byte in front of it to look at.
        if at > 0 && line.get(at.saturating_sub(1)) == Some(&b'\\') {
            // `:219-222` -- the text up to here, MINUS the backslash.
            let head = line.get(..at.saturating_sub(1)).unwrap_or(&[]);
            dyn_addn(&mut out, head)?;

            // `:224-227` -- then the two braces verbatim.
            dyn_addn(&mut out, b"{{")?;

            // `:228`. `added` is deliberately left alone; see the quirk above.
            line = line.get(at.saturating_add(2)..).unwrap_or(&[]);
            continue;
        }

        // `:235` -- `clp = strstr(envp, "}}")`, searched from the `{{` itself.
        // Starting two bytes later would give the same answer, because `{{`
        // cannot be `}}`, but this is where C starts.
        let braces = line.get(at..).unwrap_or(&[]);
        let Some(offset) = find(braces, b"}}") else {
            // `:238-242` -- uneven braces. `break`, not `continue`: nothing
            // after an unclosed `{{` is examined.
            diag.warn(MSG_MISSING_CLOSE, &[input]);
            break;
        };

        // The index of the closing `}}` within `line`.
        let clp = at.saturating_add(offset);

        // `:244-245` -- `prefix = 2; envp += 2;` move over the `{{`.
        let prefix = 2usize;
        let envp = at.saturating_add(prefix);

        // `:247-252` -- a colon strictly before the `}}` ends the name.
        let inner = line.get(envp..clp).unwrap_or(&[]);
        let funcp = find(inner, b":").map(|c| envp.saturating_add(c));
        let nlen = match funcp {
            Some(colon) => colon.saturating_sub(envp),
            None => clp.saturating_sub(envp),
        };

        if nlen == 0 || nlen >= MAX_VAR_LEN {
            // `:253-258`. The bound is `nlen >= sizeof(name)` with
            // `char name[MAX_VAR_LEN]`, so 127 fits and 128 does not.
            diag.warn(MSG_BAD_NAME_LENGTH, &[input]);

            // `curlx_dyn_addn(out, line, clp - line + prefix)` -- from the
            // cursor through the closing `}}` inclusive, verbatim. Note this
            // span starts at `line`, so it carries the preceding text with it;
            // the two verbatim spans in this function are NOT the same
            // expression and are not unified.
            let span = line.get(..clp.saturating_add(prefix)).unwrap_or(line);
            dyn_addn(&mut out, span)?;
        } else {
            // `:260-264` -- `curlx_dyn_addn(out, line, envp - prefix - line)`,
            // the text in front of the `{{`.
            let head = line.get(..envp.saturating_sub(prefix)).unwrap_or(line);
            dyn_addn(&mut out, head)?;

            // `:266-268` -- C copies the name into `char name[MAX_VAR_LEN]`
            // and terminates it, purely so `varcontent` and `%s` have a
            // C string. A slice needs neither the copy nor the terminator.
            let name = line.get(envp..envp.saturating_add(nlen)).unwrap_or(&[]);

            // `:270-272` -- every byte must be alphanumeric or `_`.
            if !name.iter().copied().all(is_name_byte) {
                // `:273-274`. `%s` reads the copied buffer, which stops at the
                // terminator C wrote at `nlen`; `until_nul` is the same bound.
                // It cannot bite here, because `input` was already truncated
                // at its first NUL, and it documents the C's reach.
                diag.warn(MSG_BAD_NAME, &[until_nul(name)]);

                // `:275-278` --
                // `curlx_dyn_addn(out, envp - prefix, clp - envp + prefix + 2)`
                // -- the whole `{{...}}` including BOTH brace pairs, and
                // nothing before it, because the preceding text already went
                // in above.
                let start = envp.saturating_sub(prefix);
                let len = clp
                    .saturating_sub(envp)
                    .saturating_add(prefix)
                    .saturating_add(2);
                let span =
                    line.get(start..start.saturating_add(len)).unwrap_or(&[]);
                dyn_addn(&mut out, span)?;
            } else {
                // `:281-290` -- an undefined variable is `value == NULL` with
                // `vlen == 0`, which expands to nothing, warns about nothing,
                // and still counts as a substitution.
                let base: &[u8] = match vars.varcontent(name) {
                    Some(var) => var.content(),
                    None => &[],
                };

                // `:292-301` -- apply the function chain, if any. C returns
                // immediately on failure, leaking its `buf`; propagating drops
                // ours.
                let produced: Option<Vec<u8>> = match funcp {
                    Some(colon) => {
                        // `:295` -- `flen = clp - funcp`.
                        let flen = clp.saturating_sub(colon);
                        let functions = line.get(colon..).unwrap_or(&[]);
                        Some(varfunc(base, functions, flen, diag)?)
                    }
                    None => None,
                };
                let value: &[u8] = match produced.as_deref() {
                    Some(bytes) => bytes,
                    None => base,
                };

                // `:303-311` -- checked on the value that is about to be
                // inserted, so it runs on the function chain's OUTPUT when
                // there is a chain. `{{v:b64}}` of a NUL-bearing value would
                // therefore not trip it, while `{{v:trim}}` would.
                if !value.is_empty() && value.contains(&0) {
                    diag.error(MSG_NULL_BYTE, &[]);
                    return Err(ParameterError::ExpandError);
                }

                // `:312-313`
                dyn_addn(&mut out, value)?;

                // `:318` -- only this branch counts as a substitution.
                added = true;
            }
        }

        // `:321` -- `line = &clp[2]`, reached by all three branches above.
        line = line.get(clp.saturating_add(2)..).unwrap_or(&[]);
    }

    // `:325-330` -- the trailing text, but only if something was substituted.
    if added && !line.is_empty() {
        dyn_addn(&mut out, line)?;
    }

    // `:331-333` -- `*replaced = added`, and the buffer is freed when nothing
    // was substituted.
    if added {
        Ok(Some(out))
    } else {
        Ok(None)
    }
}

// `--variable` argument parsing

/// C's `STRE_*` parse failures (`lib/curlx/strparse.h`), named so the two
/// helpers below read like their originals. Every one of them reaches the same
/// place: [`ParameterError::VarSyntax`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StrError {
    /// `STRE_NO_NUM` -- the first byte was not a digit.
    NoNum,

    /// `STRE_OVERFLOW` -- the value would exceed the caller's maximum.
    Overflow,

    /// `STRE_BYTE` -- the required byte was not there.
    Byte,
}

/// `curlx_str_number` at base 10 (`lib/curlx/strparse.c:157-193`).
///
/// "Get an unsigned decimal number with no leading space or minus. Leading
/// zeroes are accepted." No sign, no blanks, no `0x`, and at least one digit.
/// `pos` advances only on success, exactly as the C leaves `*linep` untouched
/// when it returns non-zero.
///
/// C's low-`max` special case at `:174-181` is unreachable from this module:
/// the only caller passes [`CURL_OFF_T_MAX`], which is far above the base.
///
/// # Errors
///
/// [`StrError::NoNum`] when the first byte is not a digit, and
/// [`StrError::Overflow`] when the accumulated value would pass `max`.
fn str_number(
    input: &[u8],
    pos: &mut usize,
    max: i64,
) -> Result<i64, StrError> {
    let mut index = *pos;

    // `:170-171` -- `if(!valid_digit(*p, m)) return STRE_NO_NUM;`
    if !input.get(index).is_some_and(u8::is_ascii_digit) {
        return Err(StrError::NoNum);
    }

    let mut num: i64 = 0;
    // `:183-188`, a do-while whose first iteration the check above guarantees.
    while let Some(&byte) = input.get(index) {
        if !byte.is_ascii_digit() {
            break;
        }
        let digit = i64::from(byte.wrapping_sub(b'0'));

        // `:184-185` -- `if(num > ((max - n) / base)) return STRE_OVERFLOW;`
        // This is what makes the multiply-add below exact: it can only run
        // when the result is at most `max`, so the saturating forms never
        // saturate and are used purely so no path here can panic.
        if num > max.saturating_sub(digit) / 10 {
            return Err(StrError::Overflow);
        }
        num = num.saturating_mul(10).saturating_add(digit);
        index = index.saturating_add(1);
    }

    // `:190-191`
    *pos = index;
    Ok(num)
}

/// `curlx_str_single` (`lib/curlx/strparse.c:125-132`): consume exactly `byte`.
///
/// # Errors
///
/// [`StrError::Byte`] when the next byte is not `byte`, including at the end of
/// the input -- where C reads the terminator and finds it equal to neither of
/// the two bytes this module asks for.
fn str_single(input: &[u8], pos: &mut usize, byte: u8) -> Result<(), StrError> {
    if input.get(*pos) != Some(&byte) {
        return Err(StrError::Byte);
    }
    *pos = pos.saturating_add(1);
    Ok(())
}

/// The three operating-system facilities `setvariable` reaches for.
///
/// `src/var.c` calls `getenv` at `:408`, `curlx_fopen(line, "rb")` at `:446`
/// and takes `stdin` at `:444`. All three are injected rather than reached for,
/// per AAP section 0.3.3's P12, and for two concrete reasons rather than as a
/// matter of taste:
///
/// * every branch -- including the `Failed to open` diagnostic and the
///   blank-versus-absent environment distinction of `:400-401` -- becomes
///   assertable without touching a real path or a real variable, which is what
///   the coverage requirement needs;
/// * a test no longer has to call `std::env::set_var`, which mutates process
///   state that every other test in the same binary reads concurrently. The
///   production path still reads the live environment at run time, as
///   [`OsVarHost::getenv`] shows.
///
/// [`OsVarHost`] is the production implementation and the only one outside the
/// tests below.
pub(crate) trait VarHost {
    /// `getenv(name)` -- `src/var.c:408`.
    ///
    /// `Some(bytes)` for a variable that exists, **including one whose value is
    /// empty**, and `None` only for one that does not. That distinction is the
    /// whole point of `:400-401` and is not recoverable from emptiness.
    fn getenv(&self, name: &[u8]) -> Option<Vec<u8>>;

    /// `curlx_fopen(path, "rb")` -- `src/var.c:446`.
    ///
    /// # Errors
    ///
    /// Whatever the platform reports; the message is rendered by
    /// [`MSG_OPEN_FAIL`].
    fn open(&mut self, path: &[u8]) -> io::Result<Box<dyn ByteSource>>;

    /// `stdin` -- `src/var.c:444`.
    fn stdin(&mut self) -> Box<dyn ByteSource>;
}

/// The live process environment and the real filesystem.
///
/// `"rb"` has no counterpart on the four mandated targets, all of which are
/// Unix: there is no text mode to opt out of, and
/// `lib/curlx/fopen.h:65` makes `curlx_fopen` a plain `fopen` off Windows.
#[allow(dead_code)]
pub(crate) struct OsVarHost;

impl VarHost for OsVarHost {
    fn getenv(&self, name: &[u8]) -> Option<Vec<u8>> {
        // Read at run time, on every call, and never captured at build time --
        // a baked-in value would make the binary non-reproducible and would
        // also be wrong the moment the environment changed.
        //
        // `var_os` rather than `var`: an environment value is arbitrary bytes
        // on Unix and `var` rejects anything that is not UTF-8, which would
        // turn a usable value into a miss. It also preserves the empty string,
        // which `curl_getenv` would too but which `:400-401` singles out
        // because the C deliberately avoids that wrapper.
        env::var_os(OsStr::from_bytes(name)).map(OsString::into_vec)
    }

    fn open(&mut self, path: &[u8]) -> io::Result<Box<dyn ByteSource>> {
        // A path from `argv` is arbitrary bytes on Unix, so it is carried as
        // bytes rather than round-tripped through `str`, which would reject or
        // mangle a non-UTF-8 name.
        let file = File::open(Path::new(OsStr::from_bytes(path)))?;
        // Seekable, so `file2memory_range` positions rather than drains
        // (`src/tool_paramhlp.c:130-133`).
        Ok(Box::new(SeekSource::new(file)))
    }

    fn stdin(&mut self) -> Box<dyn ByteSource> {
        // Not seekable, so `file2memory_range` reads and discards the leading
        // bytes instead (`src/tool_paramhlp.c:135-137`). Standard input is
        // never closed, which is also what C's
        // `if(!use_stdin && file) fclose(file)` arranges.
        Box::new(StreamSource::new(io::stdin()))
    }
}

/// `setvariable` (`src/var.c:372-492`): defines one variable from a
/// `--variable` argument.
///
/// The grammar, in the order the C tests it:
///
/// ```text
/// [%] name [ '[' N '-' [M] ']' ] ( '@' path | '@-' | '=' content )
/// ```
///
/// A leading `%` imports from the environment. A bad name length and an
/// unrecognised trailing form are **warnings** that leave the variable
/// undefined and report success; only an import miss, a malformed range and a
/// read failure are errors. That asymmetry is frozen.
///
/// # Errors
///
/// [`ParameterError::ExpandError`] when `%name` names an unset variable and no
/// fallback follows, [`ParameterError::VarSyntax`] for a malformed byte range,
/// and [`ParameterError::ReadError`] when `@path` cannot be opened or read.
#[allow(dead_code)]
pub(crate) fn setvariable(
    input: &[u8],
    vars: &mut Variables,
    host: &mut dyn VarHost,
    diag: &mut VarDiag<'_>,
) -> Result<(), ParameterError> {
    let input = until_nul(input);

    // `:387-390`
    let import = input.first() == Some(&b'%');
    let mut pos: usize = usize::from(import);

    // `:391-394`
    let name_start = pos;
    while input.get(pos).copied().is_some_and(is_name_byte) {
        pos = pos.saturating_add(1);
    }
    let nlen = pos.saturating_sub(name_start);
    let name = input.get(name_start..pos).unwrap_or(&[]);

    // `:395-398` -- a warning, and success. `%zd` is C's signed spelling of a
    // `size_t`; for any length that can exist it prints the same decimal.
    if nlen == 0 || nlen >= MAX_VAR_LEN {
        let count = nlen.to_string();
        diag.warn(MSG_BAD_SETVAR_NAME_LENGTH, &[count.as_bytes()]);
        return Ok(());
    }

    // `:376` -- `content` starts unset. `Some(Vec::new())` and `None` are
    // NOT the same state: the first is an environment variable that exists and
    // is blank, the second is one that does not exist. `:400-401` records that
    // this is deliberate -- "this does not use curl_getenv() because we want
    // \"\" support for blank content" -- so the distinction is carried in the
    // `Option` and never inferred from emptiness.
    let mut content: Option<Vec<u8>> = None;

    // `:399-419`
    if import {
        // `:402-407` -- C copies the name into `char buf[MAX_VAR_LEN]` when
        // something follows it, purely to obtain a terminator for `getenv`.
        // A slice is already bounded, so the copy has no counterpart.
        //
        // `std::env::var_os`, which [`OsVarHost::getenv`] calls, documents a
        // panic for a key that is empty or holds `=` or NUL. None is
        // reachable: `nlen >= 1` was just checked and every byte satisfied
        // `is_name_byte`, which admits only ASCII alphanumerics and `_`.
        let value = host.getenv(name);

        // `:402` and `:409` both test `*line`, i.e. whether anything follows
        // the name.
        let no_action = pos >= input.len();

        if no_action && value.is_none() {
            // `:409-413` -- no assignment and no such variable.
            diag.error(MSG_IMPORT_FAIL, &[name]);
            return Err(ParameterError::ExpandError);
        } else if let Some(value) = value {
            // `:414-418` -- `content = ge; clen = strlen(ge);`
            content = Some(value);
        }
    }

    // `:384-385`
    let mut startoffset: i64 = 0;
    let mut endoffset: i64 = CURL_OFF_T_MAX;

    // `:420-433`. This runs even when the import already produced a value,
    // which is why `--variable %HOME[0-3]` can still fail with a syntax error
    // while never applying the range -- see the `if(content) ;` note below.
    if input.get(pos) == Some(&b'[')
        && input
            .get(pos.saturating_add(1))
            .is_some_and(u8::is_ascii_digit)
    {
        // `:422`
        pos = pos.saturating_add(1);

        // `:423-425`. C's `||` short-circuits, so a bad number never reaches
        // the `-`; `?` does the same.
        startoffset = str_number(input, &mut pos, CURL_OFF_T_MAX)
            .map_err(|_| ParameterError::VarSyntax)?;
        str_single(input, &mut pos, b'-')
            .map_err(|_| ParameterError::VarSyntax)?;

        // `:426-430` -- an immediate `]` leaves `endoffset` at
        // `CURL_OFF_T_MAX`, which is the open-ended `[N-]` form.
        if str_single(input, &mut pos, b']').is_err() {
            endoffset = str_number(input, &mut pos, CURL_OFF_T_MAX)
                .map_err(|_| ParameterError::VarSyntax)?;
            str_single(input, &mut pos, b']')
                .map_err(|_| ParameterError::VarSyntax)?;
        }

        // `:431-432`
        if startoffset > endoffset {
            return Err(ParameterError::VarSyntax);
        }
    }

    // `:434-435` -- `if(content) ;` short-circuits every remaining form. An
    // imported value therefore wins over a `=` fallback AND over the range
    // that was just parsed: `--variable %HOME=fallback` ignores the fallback
    // when `HOME` is set, and `--variable %HOME[0-3]` stores all of `HOME`.
    let content = match content {
        Some(bytes) => bytes,
        None => {
            if input.get(pos) == Some(&b'@') {
                // `:436-464` -- read from a file or from standard input.
                pos = pos.saturating_add(1);
                let path = input.get(pos..).unwrap_or(&[]);

                // `:442` -- `use_stdin = !strcmp(line, "-")`
                let mut source: Box<dyn ByteSource> = if path == b"-" {
                    host.stdin()
                } else {
                    match host.open(path) {
                        Ok(file) => file,
                        Err(error) => {
                            // `:447-452`. C renders `curlx_strerror(errno)`;
                            // the engine's `os_error_message` is the safe
                            // equivalent and strips the parenthesised code
                            // Rust appends.
                            let reason = curl_rs_lib::os_error_message(&error);
                            diag.error(
                                MSG_OPEN_FAIL,
                                &[path, reason.as_bytes()],
                            );
                            return Err(ParameterError::ReadError);
                        }
                    }
                };

                // `:455`. The range is inclusive at both ends, and the sibling
                // owns the reading -- including the non-seekable drain -- so
                // it is not repeated here.
                file2memory_range(
                    Some(source.as_mut()),
                    startoffset,
                    endoffset,
                )?
            } else if input.get(pos) == Some(&b'=') {
                // `:465-481` -- the literal rest of the argument.
                pos = pos.saturating_add(1);
                let literal = input.get(pos..).unwrap_or(&[]);

                // `:467-469` -- `clen = strlen(line); content = line;`
                let mut clen = literal.len();
                let mut start: usize = 0;

                // `:470` -- the guard. Equivalent to applying the clamp
                // unconditionally, since the defaults are a no-op, but it is
                // the branch C takes.
                if startoffset != 0 || endoffset != CURL_OFF_T_MAX {
                    let len = i64::try_from(clen).unwrap_or(i64::MAX);
                    if startoffset >= len {
                        // `:471-472` -- the range begins past the end.
                        clen = 0;
                    } else {
                        // `:474-476` -- "make the end offset no larger than
                        // the last byte". C writes the clamp back into
                        // `endoffset`, which the next line then reads.
                        let mut end = endoffset;
                        if end >= len {
                            end = len.saturating_sub(1);
                        }

                        // `:477-478`. `end >= startoffset` holds because
                        // `:431` rejected the inverted range, so the count is
                        // at least one, and `startoffset < len` bounds the
                        // conversion.
                        let count =
                            end.saturating_sub(startoffset).saturating_add(1);
                        clen = usize::try_from(count).unwrap_or(0);
                        start = usize::try_from(startoffset).unwrap_or(0);
                    }
                }

                literal
                    .get(start..start.saturating_add(clen))
                    .unwrap_or(&[])
                    .to_vec()
            } else {
                // `:482-485` -- a warning, and success.
                diag.warn(MSG_BAD_SYNTAX, &[input]);
                return Ok(());
            }
        }
    };

    // `:486-491`. C's only failure here is an allocation failure, which has no
    // counterpart.
    vars.add(name, content, diag);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_64dec, apply_b64, decode_base64, dyn_addn, encode_base64, find,
        is_name_byte, is_space, match_func, render, setvariable, str_number,
        str_single, until_nul, varexpand, ByteSource, CodecOutcome, MsgConfig,
        OsVarHost, ParameterError, SeekSource, StrError, StreamSource, ToolVar,
        VarDiag, VarFunc, VarHost, Variables, B64DEC_FAIL, CURL_OFF_T_MAX,
        FROZEN_TEXTS, MAX_EXPAND_CONTENT, MAX_VAR_LEN, MSG_BAD_NAME,
        MSG_BAD_NAME_LENGTH, MSG_BAD_SETVAR_NAME_LENGTH, MSG_BAD_SYNTAX,
        MSG_IMPORT_FAIL, MSG_MISSING_CLOSE, MSG_NULL_BYTE, MSG_OPEN_FAIL,
        MSG_OVERWRITING, MSG_UNKNOWN_FUNC,
    };
    use std::env;
    use std::io::{self, Cursor};

    /// `src/tool_msgs.c:29` -- `warnf`'s prefix.
    const WARN: &str = "Warning: ";

    /// `src/tool_msgs.c:30` -- `notef`'s prefix.
    const NOTE: &str = "Note: ";

    /// `src/tool_msgs.c:28` -- `errorf`'s prefix.
    const ERROR: &str = "curl: ";

    /// The message a diagnostic carried, with the line breaks `voutf_bytes`
    /// inserted for the terminal width taken back out.
    ///
    /// `crate::output::msgs` wraps at the terminal width, and that width comes
    /// from the ambient `COLUMNS` or a `TIOCGWINSZ` probe, so a test that
    /// compared raw sink bytes would pass under `cargo test` from a pipe and
    /// fail from a terminal. Reversing the wrap is exact rather than
    /// approximate: the prefix is written at the start of every emitted line
    /// and no byte is dropped at a break -- the blank it breaks on is written
    /// as part of the line it ends -- so deleting each newline-plus-prefix pair
    /// reconstructs the message byte for byte at any width.
    ///
    /// `None` when the sink does not look like exactly one diagnostic with this
    /// prefix.
    fn unwrapped(sink: &[u8], prefix: &str) -> Option<Vec<u8>> {
        let mut rest = sink.strip_prefix(prefix.as_bytes())?;

        let mut needle: Vec<u8> = Vec::with_capacity(prefix.len() + 1);
        needle.push(b'\n');
        needle.extend_from_slice(prefix.as_bytes());

        let mut out: Vec<u8> = Vec::new();
        while let Some(at) = find(rest, &needle) {
            out.extend_from_slice(rest.get(..at)?);
            rest = rest.get(at + needle.len()..)?;
        }
        out.extend_from_slice(rest.strip_suffix(b"\n")?);
        Some(out)
    }

    /// Asserts the sink holds exactly one diagnostic with `prefix` and `text`.
    fn assert_diag(sink: &[u8], prefix: &str, text: &[u8]) {
        assert_eq!(
            unwrapped(sink, prefix).as_deref(),
            Some(text),
            "sink was {:?}",
            String::from_utf8_lossy(sink)
        );
    }

    /// A [`VarHost`] serving canned values, so that every arm of
    /// `src/var.c:399-464` -- the blank-versus-absent environment distinction,
    /// both content sources, and the open failure -- runs without touching a
    /// real path or mutating the process environment.
    struct FakeHost {
        /// What `getenv` yields, as name-and-value pairs. A pair whose value is
        /// empty is an existing BLANK variable, which `:400-401` distinguishes
        /// from an absent one; a name that is not listed is absent.
        env: Vec<(Vec<u8>, Vec<u8>)>,

        /// What `open` yields: bytes, or a raw `errno` to report.
        file: Result<Vec<u8>, i32>,

        /// What `stdin` yields.
        stdin: Vec<u8>,

        /// The path the last `open` call was given.
        asked: Vec<u8>,
    }

    impl FakeHost {
        /// A host with an empty environment, file and standard input.
        fn empty() -> Self {
            Self {
                env: Vec::new(),
                file: Ok(Vec::new()),
                stdin: Vec::new(),
                asked: Vec::new(),
            }
        }

        /// A host whose file holds `bytes`.
        fn with_file(bytes: &[u8]) -> Self {
            Self {
                file: Ok(bytes.to_vec()),
                ..Self::empty()
            }
        }

        /// A host whose standard input holds `bytes`.
        fn with_stdin(bytes: &[u8]) -> Self {
            Self {
                stdin: bytes.to_vec(),
                ..Self::empty()
            }
        }

        /// A host that fails every `open` with `errno`.
        fn failing(errno: i32) -> Self {
            Self {
                file: Err(errno),
                ..Self::empty()
            }
        }

        /// The same host with `name` present and holding `value`.
        fn with_var(mut self, name: &str, value: &[u8]) -> Self {
            self.env.push((name.as_bytes().to_vec(), value.to_vec()));
            self
        }
    }

    impl VarHost for FakeHost {
        fn getenv(&self, name: &[u8]) -> Option<Vec<u8>> {
            self.env
                .iter()
                .find(|(key, _)| key.as_slice() == name)
                .map(|(_, value)| value.clone())
        }

        fn open(&mut self, path: &[u8]) -> io::Result<Box<dyn ByteSource>> {
            self.asked = path.to_vec();
            match &self.file {
                // Seekable, matching a real `fopen`.
                Ok(bytes) => {
                    Ok(Box::new(SeekSource::new(Cursor::new(bytes.clone()))))
                }
                Err(errno) => Err(io::Error::from_raw_os_error(*errno)),
            }
        }

        fn stdin(&mut self) -> Box<dyn ByteSource> {
            // Not seekable, matching standard input.
            Box::new(StreamSource::new(Cursor::new(self.stdin.clone())))
        }
    }

    /// [`varexpand`] over a byte-faithful sink with C's zero-initialised gates:
    /// warnings and errors emitted, notes not.
    // Justification (O2): the tuple pairs varexpand's own return type with the
    // captured sink, so a type alias would only rename what the tests must see.
    #[allow(clippy::type_complexity)]
    fn expand(
        vars: &Variables,
        line: &[u8],
    ) -> (Result<Option<Vec<u8>>, ParameterError>, Vec<u8>) {
        let mut sink: Vec<u8> = Vec::new();
        let outcome = {
            let mut diag = VarDiag::new(&mut sink, MsgConfig::default());
            varexpand(line, vars, &mut diag)
        };
        (outcome, sink)
    }

    /// [`setvariable`] with the host and the gates chosen by the caller.
    fn define_with(
        vars: &mut Variables,
        input: &[u8],
        host: &mut dyn VarHost,
        config: MsgConfig,
    ) -> (Result<(), ParameterError>, Vec<u8>) {
        let mut sink: Vec<u8> = Vec::new();
        let outcome = {
            let mut diag = VarDiag::new(&mut sink, config);
            setvariable(input, vars, host, &mut diag)
        };
        (outcome, sink)
    }

    /// [`setvariable`] with an empty host and C's zero-initialised gates.
    fn define(
        vars: &mut Variables,
        input: &[u8],
    ) -> (Result<(), ParameterError>, Vec<u8>) {
        let mut host = FakeHost::empty();
        define_with(vars, input, &mut host, MsgConfig::default())
    }

    /// A store holding one variable, defined by the literal form.
    fn one(name: &str, content: &[u8]) -> Variables {
        let mut vars = Variables::default();
        let mut input = name.as_bytes().to_vec();
        input.push(b'=');
        input.extend_from_slice(content);
        let (outcome, sink) = define(&mut vars, &input);
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        vars
    }

    // Constants and frozen texts

    /// `#define MAX_EXPAND_CONTENT 10000000` and `#define MAX_VAR_LEN 128`
    /// (`src/var.c:33-34`).
    #[test]
    fn constants_match_the_c_defines() {
        assert_eq!(MAX_EXPAND_CONTENT, 10_000_000);
        assert_eq!(MAX_VAR_LEN, 128);
        assert_eq!(CURL_OFF_T_MAX, i64::MAX);
    }

    /// Every frozen text, byte for byte.
    ///
    /// These strings are compared against literal expectations in the fixture
    /// corpus, so a single altered byte is a behaviour change. Spelled out here
    /// rather than derived, because deriving them from the constants would
    /// assert only that a constant equals itself.
    #[test]
    fn frozen_texts_are_byte_for_byte() {
        // `src/var.c:184`
        assert_eq!(MSG_UNKNOWN_FUNC, "unknown variable function in '%.*s'");
        // `src/var.c:240` -- note the doubled closing brace.
        assert_eq!(MSG_MISSING_CLOSE, "missing close '}}' in '%s'");
        // `src/var.c:254`
        assert_eq!(MSG_BAD_NAME_LENGTH, "bad variable name length '%s'");
        // `src/var.c:274`
        assert_eq!(MSG_BAD_NAME, "bad variable name: %s");
        // `src/var.c:308`
        assert_eq!(MSG_NULL_BYTE, "variable contains null byte");
        // `src/var.c:352`
        assert_eq!(MSG_OVERWRITING, "Overwriting variable '%s'");
        // `src/var.c:396`
        assert_eq!(
            MSG_BAD_SETVAR_NAME_LENGTH,
            "Bad variable name length (%zd), skipping"
        );
        // `src/var.c:411`
        assert_eq!(MSG_IMPORT_FAIL, "Variable '%s' import fail, not set");
        // `src/var.c:449`
        assert_eq!(MSG_OPEN_FAIL, "Failed to open %s: %s");
        // `src/var.c:483`
        assert_eq!(MSG_BAD_SYNTAX, "Bad --variable syntax, skipping: %s");
        // `src/var.c:170`
        assert_eq!(B64DEC_FAIL, "[64dec-fail]");

        // The table is the set, so a text added without a test is caught.
        assert_eq!(FROZEN_TEXTS.len(), 11);
        assert!(FROZEN_TEXTS.contains(&MSG_UNKNOWN_FUNC));
        assert!(FROZEN_TEXTS.contains(&B64DEC_FAIL));

        // `src/tool_msgs.c:45` -- `DEBUGASSERT(!strchr(fmt, '\n'))`. No format
        // string may carry a newline, because the wrapping in `voutf` owns
        // every line break.
        for text in FROZEN_TEXTS {
            assert!(!text.contains('\n'), "{text} holds a newline");
        }
    }

    // The renderer

    /// `render` handles exactly the four specifiers the frozen texts use.
    #[test]
    fn render_substitutes_the_four_specifiers() {
        // `%s`
        assert_eq!(render("a %s b", &[b"X"]), b"a X b".to_vec());
        // `%zd`
        assert_eq!(render("(%zd)", &[b"128"]), b"(128)".to_vec());
        // `%.*s` -- the precision is applied by the caller, which passes an
        // already-bounded slice.
        assert_eq!(render("'%.*s'", &[b":a:b"]), b"':a:b'".to_vec());
        // `%%` consumes no argument.
        assert_eq!(render("100%%", &[]), b"100%".to_vec());
        // Two arguments, in order.
        assert_eq!(
            render(MSG_OPEN_FAIL, &[b"/tmp/x", b"No such file"]),
            b"Failed to open /tmp/x: No such file".to_vec()
        );
        // A missing argument contributes nothing rather than panicking.
        assert_eq!(render("<%s>", &[]), b"<>".to_vec());
        // A specifier this module never uses is copied through.
        assert_eq!(render("%q", &[]), b"%q".to_vec());
        // A trailing `%` is copied through.
        assert_eq!(render("x%", &[]), b"x%".to_vec());
        // No specifier at all.
        assert_eq!(
            render(MSG_NULL_BYTE, &[]),
            b"variable contains null byte".to_vec()
        );
        // Arbitrary bytes survive: a value from `argv` need not be UTF-8.
        assert_eq!(render("%s", &[&[0xff, 0xfe]]), vec![0xff, 0xfe]);
    }

    /// The doubled brace of [`MSG_MISSING_CLOSE`] survives rendering.
    ///
    /// This is the whole reason `render` exists. `format!` and
    /// `format_args!` read `}}` as an escaped single `}`, so routing this text
    /// through either would emit `missing close '}' in '...'` -- one byte short
    /// of the frozen text, and silently so.
    #[test]
    fn render_never_collapses_the_doubled_brace() {
        let rendered = render(MSG_MISSING_CLOSE, &[b"{{v"]);
        assert_eq!(rendered, b"missing close '}}' in '{{v'".to_vec());
        assert_eq!(
            rendered.iter().filter(|&&byte| byte == b'}').count(),
            2,
            "both closing braces must survive"
        );

        // The failure mode this avoids, written the way it would actually be
        // introduced: a format literal transcribed from the C text, where the
        // doubled brace is an escape for a single one.
        let naive = format!("missing close '}}' in '{}'", "{{v");
        assert_eq!(naive, "missing close '}' in '{{v'");
        assert_ne!(naive.as_bytes(), rendered.as_slice());
        assert_eq!(naive.len() + 1, rendered.len(), "exactly one byte short");
    }

    // Byte primitives

    /// curl's `ISSPACE` (`lib/curl_ctype.h:46`) includes `\v`, which Rust's
    /// [`u8::is_ascii_whitespace`] does not.
    #[test]
    fn is_space_matches_curl_isspace_including_vertical_tab() {
        for byte in [b' ', b'\t', b'\n', 0x0b, 0x0c, b'\r'] {
            assert!(is_space(byte), "{byte:#04x} is ISSPACE");
        }
        // The divergence, stated as an assertion so it cannot regress.
        assert!(is_space(0x0b));
        assert!(!0x0b_u8.is_ascii_whitespace());

        for byte in [0u8, b'a', b'0', b'_', 0x1f, 0x7f, 0x80, 0xa0, 0xff] {
            assert!(!is_space(byte), "{byte:#04x} is not ISSPACE");
        }
    }

    /// `ISALNUM(x) || ((x) == '_')` -- `src/var.c:271` and `:392`.
    #[test]
    fn is_name_byte_admits_only_ascii_alnum_and_underscore() {
        for byte in *b"azAZ09_" {
            assert!(is_name_byte(byte));
        }
        for byte in [b'-', b'.', b':', b'{', b'}', b' ', 0u8, 0x80, 0xff] {
            assert!(!is_name_byte(byte), "{byte:#04x} is not a name byte");
        }
    }

    /// A `char *` stops at the first NUL, and so does every entry point here.
    #[test]
    fn until_nul_truncates_at_the_first_nul() {
        assert_eq!(until_nul(b"abc"), b"abc");
        assert_eq!(until_nul(b"ab\0cd"), b"ab");
        assert_eq!(until_nul(b"\0abc"), b"");
        assert_eq!(until_nul(b""), b"");
    }

    /// `strstr` and `memchr`.
    #[test]
    fn find_locates_the_first_occurrence() {
        assert_eq!(find(b"a{{b", b"{{"), Some(1));
        assert_eq!(find(b"{{{{", b"{{"), Some(0));
        assert_eq!(find(b"ab", b"}}"), None);
        // A needle longer than the haystack.
        assert_eq!(find(b"{", b"{{"), None);
        // `strstr` with an empty needle returns the haystack.
        assert_eq!(find(b"abc", b""), Some(0));
    }

    /// The [`MAX_EXPAND_CONTENT`] cap, which is one byte below the limit
    /// because `dyn_nappend` reserves room for a terminator
    /// (`lib/curlx/dynbuf.c:67-85`).
    #[test]
    fn dyn_addn_rejects_at_the_cap() {
        let mut out: Vec<u8> = Vec::new();
        let fits = vec![b'x'; MAX_EXPAND_CONTENT - 1];
        assert_eq!(dyn_addn(&mut out, &fits), Ok(()));
        assert_eq!(out.len(), MAX_EXPAND_CONTENT - 1);

        // One more byte would make `len + used + 1` exceed the cap.
        assert_eq!(dyn_addn(&mut out, b"y"), Err(ParameterError::NoMem));
        assert_eq!(out.len(), MAX_EXPAND_CONTENT - 1, "nothing was appended");

        // A zero-length append always fits, matching `curlx_dyn_addn` with a
        // null pointer and a length of zero at `src/var.c:313`.
        assert_eq!(dyn_addn(&mut out, b""), Ok(()));
    }

    // FUNCMATCH

    /// All five names, with `ENDOFFUNC` satisfied by each of its two bytes.
    #[test]
    fn match_func_accepts_all_five_names() {
        assert_eq!(match_func(b"trim}"), Some((VarFunc::Trim, 4)));
        assert_eq!(match_func(b"trim:"), Some((VarFunc::Trim, 4)));
        assert_eq!(match_func(b"json}"), Some((VarFunc::Json, 4)));
        assert_eq!(match_func(b"json:"), Some((VarFunc::Json, 4)));
        assert_eq!(match_func(b"url}"), Some((VarFunc::Url, 3)));
        assert_eq!(match_func(b"url:"), Some((VarFunc::Url, 3)));
        assert_eq!(match_func(b"b64}"), Some((VarFunc::B64, 3)));
        assert_eq!(match_func(b"b64:"), Some((VarFunc::B64, 3)));
        assert_eq!(match_func(b"64dec}"), Some((VarFunc::Dec64, 5)));
        assert_eq!(match_func(b"64dec:"), Some((VarFunc::Dec64, 5)));
    }

    /// `FUNCMATCH` is a whole-token match: the byte after the name must be `}`
    /// or `:` (`src/var.c:61-62`).
    #[test]
    fn match_func_requires_endoffunc() {
        // The example the specification names: `trimx` is not `trim`.
        assert_eq!(match_func(b"trimx}"), None);
        assert_eq!(match_func(b"b64x}"), None);
        assert_eq!(match_func(b"64decs}"), None);
        // A name at the very end of the input: C reads the terminator, which
        // is neither `}` nor `:`.
        assert_eq!(match_func(b"trim"), None);
        assert_eq!(match_func(b"64dec"), None);
        // A shorter prefix never matches.
        assert_eq!(match_func(b"tri}"), None);
        assert_eq!(match_func(b"}"), None);
        assert_eq!(match_func(b""), None);
        // An unrelated name.
        assert_eq!(match_func(b"upper}"), None);
    }

    // The base64 codecs and their two appliers

    /// `[64dec-fail]` on a rejected input, and it is **not** an error
    /// (`src/var.c:169-172`).
    #[test]
    fn apply_64dec_emits_the_frozen_sentinel_on_rejection() {
        let mut out: Vec<u8> = Vec::new();
        assert_eq!(apply_64dec(&mut out, CodecOutcome::Rejected), Ok(()));
        assert_eq!(out, b"[64dec-fail]".to_vec());
        assert_eq!(out, B64DEC_FAIL.as_bytes().to_vec());

        // A decode that succeeded contributes its bytes instead.
        let mut out: Vec<u8> = Vec::new();
        let produced = CodecOutcome::Produced(b"hi".to_vec());
        assert_eq!(apply_64dec(&mut out, produced), Ok(()));
        assert_eq!(out, b"hi".to_vec());

        // An unavailable codec never claims the input was bad.
        let mut out: Vec<u8> = Vec::new();
        assert_eq!(
            apply_64dec(&mut out, CodecOutcome::Unavailable),
            Err(ParameterError::NoMem)
        );
        assert!(out.is_empty());
    }

    /// The encode side has no sentinel: a failure aborts the chain
    /// (`src/var.c:148-151`).
    #[test]
    fn apply_b64_has_no_sentinel() {
        let mut out: Vec<u8> = Vec::new();
        assert_eq!(
            apply_b64(&mut out, CodecOutcome::Rejected),
            Err(ParameterError::NoMem)
        );
        assert!(out.is_empty());

        let mut out: Vec<u8> = Vec::new();
        assert_eq!(
            apply_b64(&mut out, CodecOutcome::Unavailable),
            Err(ParameterError::NoMem)
        );
        assert!(out.is_empty());

        let mut out: Vec<u8> = Vec::new();
        let produced = CodecOutcome::Produced(b"aGk=".to_vec());
        assert_eq!(apply_b64(&mut out, produced), Ok(()));
        assert_eq!(out, b"aGk=".to_vec());
    }

    /// GAP #1, asserted so that its resolution is visible as a test change.
    ///
    /// When a public base64 becomes reachable from `curl-rs-lib`, these two
    /// calls start reporting `Produced`, this test fails, and the failure is
    /// the reminder to point [`encode_base64`] and [`decode_base64`] at it.
    #[test]
    fn base64_is_unavailable_per_gap_one() {
        assert_eq!(encode_base64(b"hi"), CodecOutcome::Unavailable);
        assert_eq!(decode_base64(b"aGk="), CodecOutcome::Unavailable);
    }

    // The store

    /// `varcontent` compares exact length with `strncmp`, not `strncasecmp`
    /// (`src/var.c:48-58`).
    #[test]
    fn lookup_is_exact_length_and_case_sensitive() {
        let vars = one("Var", b"value");
        assert_eq!(vars.len(), 1);
        assert!(!vars.is_empty());
        assert_eq!(
            vars.varcontent(b"Var").map(ToolVar::content),
            Some(&b"value"[..])
        );
        assert_eq!(vars.varcontent(b"Var").map(ToolVar::name), Some("Var"));

        // Case matters.
        assert!(vars.varcontent(b"var").is_none());
        assert!(vars.varcontent(b"VAR").is_none());
        // A prefix is not a match: the C tests `strlen(name) == nlen` first.
        assert!(vars.varcontent(b"Va").is_none());
        assert!(vars.varcontent(b"Vars").is_none());
        assert!(Variables::default().is_empty());
    }

    /// `notef("Overwriting variable '%s'", ...)` at `src/var.c:352`, and the
    /// prepend at `:363-364` that makes the NEWEST definition win.
    #[test]
    fn redefinition_notes_and_the_newest_wins() {
        let mut vars = one("v", b"one");
        let mut host = FakeHost::empty();

        // Notes are gated on `global->tracetype`, so the trace flag is what
        // makes this observable at all.
        let trace = MsgConfig::new(false, false, true);
        let (outcome, sink) =
            define_with(&mut vars, b"v=two", &mut host, trace);
        assert_eq!(outcome, Ok(()));
        assert_diag(&sink, NOTE, b"Overwriting variable 'v'");

        // Both nodes remain, as they do in C's list, and the lookup finds the
        // newer one.
        assert_eq!(vars.len(), 2);
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"two"[..])
        );

        // A third definition shadows the second.
        let (outcome, _) = define_with(&mut vars, b"v=three", &mut host, trace);
        assert_eq!(outcome, Ok(()));
        assert_eq!(vars.len(), 3);
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"three"[..])
        );

        // And the expansion follows the lookup.
        let (outcome, sink) = expand(&vars, b"{{v}}");
        assert_eq!(outcome, Ok(Some(b"three".to_vec())));
        assert!(sink.is_empty());
    }

    /// The overwrite note is silent without a trace selection, and `--silent`
    /// does not suppress it (`src/tool_msgs.c:79-87`).
    #[test]
    fn overwriting_note_follows_the_trace_gate_only() {
        let mut host = FakeHost::empty();

        // No trace: nothing is emitted.
        let mut vars = one("v", b"one");
        let quiet = MsgConfig::default();
        let (outcome, sink) =
            define_with(&mut vars, b"v=two", &mut host, quiet);
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());

        // Silent AND traced: still emitted, because `notef` never consults
        // `silent`.
        let mut vars = one("v", b"one");
        let silent_trace = MsgConfig::new(true, false, true);
        let (outcome, sink) =
            define_with(&mut vars, b"v=two", &mut host, silent_trace);
        assert_eq!(outcome, Ok(()));
        assert_diag(&sink, NOTE, b"Overwriting variable 'v'");
    }

    // varexpand

    /// `:282-291` -- an undefined variable expands to nothing, warns about
    /// nothing, and still counts as a substitution.
    #[test]
    fn undefined_variable_expands_to_nothing_without_warning() {
        let vars = Variables::default();

        let (outcome, sink) = expand(&vars, b"{{nope}}");
        assert_eq!(outcome, Ok(Some(Vec::new())));
        assert!(sink.is_empty(), "no diagnostic for an undefined variable");

        // With text on both sides, to show the surrounding bytes survive.
        let (outcome, sink) = expand(&vars, b"a{{nope}}b");
        assert_eq!(outcome, Ok(Some(b"ab".to_vec())));
        assert!(sink.is_empty());
    }

    /// A line with no `{{` at all is not replaced, so the caller keeps its
    /// original argument (`:331-333`).
    #[test]
    fn a_line_without_a_construct_is_not_replaced() {
        let vars = one("v", b"V");
        let (outcome, sink) = expand(&vars, b"plain text");
        assert_eq!(outcome, Ok(None));
        assert!(sink.is_empty());

        let (outcome, _) = expand(&vars, b"");
        assert_eq!(outcome, Ok(None));
    }

    /// `trim` strips the whole `ISSPACE` set, `\v` included (`:98-104`).
    #[test]
    fn trim_strips_the_whole_curl_isspace_set() {
        // Every ISSPACE byte on both sides.
        let vars = one("v", b" \t\n\x0b\x0c\rmiddle \t\n\x0b\x0c\r");
        let (outcome, sink) = expand(&vars, b"{{v:trim}}");
        assert_eq!(outcome, Ok(Some(b"middle".to_vec())));
        assert!(sink.is_empty());

        // The vertical tab alone, which `is_ascii_whitespace` would leave.
        let vars = one("v", b"\x0bx\x0b");
        let (outcome, _) = expand(&vars, b"{{v:trim}}");
        assert_eq!(outcome, Ok(Some(b"x".to_vec())));

        // Interior whitespace is untouched.
        let vars = one("v", b"  a  b  ");
        let (outcome, _) = expand(&vars, b"{{v:trim}}");
        assert_eq!(outcome, Ok(Some(b"a  b".to_vec())));

        // All whitespace trims to nothing.
        let vars = one("v", b" \t\r\n");
        let (outcome, _) = expand(&vars, b"{{v:trim}}");
        assert_eq!(outcome, Ok(Some(Vec::new())));

        // `if(clen)` at `:97`: empty content skips the whole block.
        let vars = one("v", b"");
        let (outcome, _) = expand(&vars, b"{{v:trim}}");
        assert_eq!(outcome, Ok(Some(Vec::new())));

        // An undefined variable reaches `varfunc` as `value == NULL` with
        // `vlen == 0`, which the same guard covers.
        let (outcome, _) = expand(&Variables::default(), b"{{nope:trim}}");
        assert_eq!(outcome, Ok(Some(Vec::new())));
    }

    /// `json` delegates to `jsonquoted` with `lowercase` false
    /// (`src/var.c:117`).
    #[test]
    fn json_function_delegates_to_the_writeout_escaper() {
        // A quote, a backslash, a control byte with a short escape, and one
        // without -- the last proving the lowercase `\u00xx` form is in use.
        let vars = one("v", b"a\"b\\c\nd\x01e");
        let (outcome, sink) = expand(&vars, b"{{v:json}}");
        assert_eq!(
            outcome,
            Ok(Some(br#"a\"b\\c\nd\u0001e"#.to_vec())),
            "the sibling escaper must be the one that ran"
        );
        assert!(sink.is_empty());

        // Case is preserved: the `lowercase` argument is FALSE here, unlike
        // the header-name path in `--write-out`.
        let vars = one("v", b"MiXeD");
        let (outcome, _) = expand(&vars, b"{{v:json}}");
        assert_eq!(outcome, Ok(Some(b"MiXeD".to_vec())));

        // Empty content skips the call entirely (`:116`).
        let vars = one("v", b"");
        let (outcome, _) = expand(&vars, b"{{v:json}}");
        assert_eq!(outcome, Ok(Some(Vec::new())));
    }

    /// `url` percent-encodes with `curl_easy_escape` (`src/var.c:127`).
    #[test]
    fn url_function_percent_encodes() {
        let vars = one("v", b"a b&c=d/e");
        let (outcome, sink) = expand(&vars, b"{{v:url}}");
        assert_eq!(outcome, Ok(Some(b"a%20b%26c%3Dd%2Fe".to_vec())));
        assert!(sink.is_empty());

        // The unreserved set passes through.
        let vars = one("v", b"aZ09-._~");
        let (outcome, _) = expand(&vars, b"{{v:url}}");
        assert_eq!(outcome, Ok(Some(b"aZ09-._~".to_vec())));

        // Empty content skips the call (`:126`).
        let vars = one("v", b"");
        let (outcome, _) = expand(&vars, b"{{v:url}}");
        assert_eq!(outcome, Ok(Some(Vec::new())));
    }

    /// A chain runs left to right, each function taking the previous output
    /// (`:188-197`).
    #[test]
    fn function_chain_runs_left_to_right() {
        // trim then url: the spaces are removed before encoding, so no `%20`
        // appears at the ends.
        let vars = one("v", b"  a b  ");
        let (outcome, sink) = expand(&vars, b"{{v:trim:url}}");
        assert_eq!(outcome, Ok(Some(b"a%20b".to_vec())));
        assert!(sink.is_empty());

        // The other order encodes the outer spaces, which `trim` can then no
        // longer see.
        let (outcome, _) = expand(&vars, b"{{v:url:trim}}");
        assert_eq!(outcome, Ok(Some(b"%20%20a%20b%20%20".to_vec())));

        // Three deep.
        let vars = one("v", b" \"x\" ");
        let (outcome, _) = expand(&vars, b"{{v:trim:json:url}}");
        assert_eq!(outcome, Ok(Some(b"%5C%22x%5C%22".to_vec())));
    }

    /// `:182-187` -- the unknown-function diagnostic shows the WHOLE chain
    /// from the first colon, truncated to `flen`, not the offending name.
    #[test]
    fn unknown_function_reports_the_whole_chain() {
        let vars = one("v", b"V");

        // The specification's example: `trimx` is not `trim`.
        let (outcome, sink) = expand(&vars, b"{{v:trimx}}");
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert_diag(&sink, ERROR, b"unknown variable function in ':trimx'");

        // A later function in a chain still reports the whole chain, because
        // `finput` is the chain's start and `flen` its full length.
        let (outcome, sink) = expand(&vars, b"{{v:trim:nope:url}}");
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert_diag(
            &sink,
            ERROR,
            b"unknown variable function in ':trim:nope:url'",
        );

        // The precision stops at the closing braces: trailing text after
        // `}}` is not part of the chain.
        let (outcome, sink) = expand(&vars, b"{{v:zz}}tail");
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert_diag(&sink, ERROR, b"unknown variable function in ':zz'");

        // An empty function name.
        let (outcome, sink) = expand(&vars, b"{{v:}}");
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert_diag(&sink, ERROR, b"unknown variable function in ':'");
    }

    /// All five names are recognised by `varexpand`, which is what separates a
    /// missing codec from a misspelled function.
    ///
    /// `b64` and `64dec` cannot yet produce bytes -- see GAP #1 on
    /// [`encode_base64`] -- so what is asserted for those two is that the name
    /// MATCHED: the outcome is `PARAM_NO_MEM` with an empty sink, and
    /// emphatically not the unknown-function error.
    #[test]
    fn all_five_function_names_are_recognised() {
        let vars = one("v", b"aGk=");

        let (outcome, sink) = expand(&vars, b"{{v:trim}}");
        assert_eq!(outcome, Ok(Some(b"aGk=".to_vec())));
        assert!(sink.is_empty());

        let (outcome, sink) = expand(&vars, b"{{v:json}}");
        assert_eq!(outcome, Ok(Some(b"aGk=".to_vec())));
        assert!(sink.is_empty());

        let (outcome, sink) = expand(&vars, b"{{v:url}}");
        assert_eq!(outcome, Ok(Some(b"aGk%3D".to_vec())));
        assert!(sink.is_empty());

        for line in [&b"{{v:b64}}"[..], &b"{{v:64dec}}"[..]] {
            let (outcome, sink) = expand(&vars, line);
            assert_eq!(
                outcome,
                Err(ParameterError::NoMem),
                "{} is blocked by GAP #1",
                String::from_utf8_lossy(line)
            );
            assert!(
                sink.is_empty(),
                "{} must not report an unknown function",
                String::from_utf8_lossy(line)
            );
        }

        // With empty content neither codec is called at all, so both succeed.
        let empty = one("v", b"");
        let (outcome, _) = expand(&empty, b"{{v:b64}}");
        assert_eq!(outcome, Ok(Some(Vec::new())));
        let (outcome, _) = expand(&empty, b"{{v:64dec}}");
        assert_eq!(outcome, Ok(Some(Vec::new())));
    }

    /// `:216-229` -- an escaped `{{` is emitted verbatim, and `added` is NOT
    /// set, so the whole expansion reports "not replaced" and the caller keeps
    /// the original argument WITH its backslash.
    ///
    /// This is a genuine quirk of curl 8.19.0-DEV rather than an oversight
    /// here. AAP section 0.8.2 forbids a change justified by improvement.
    #[test]
    fn escaped_braces_leave_replaced_false() {
        let vars = one("v", b"V");

        let (outcome, sink) = expand(&vars, br"\{{x}}");
        assert_eq!(
            outcome,
            Ok(None),
            "the caller keeps the original, backslash included"
        );
        assert!(sink.is_empty(), "the escape is not a diagnostic");

        // Even with an otherwise expandable name inside.
        let (outcome, _) = expand(&vars, br"\{{v}}");
        assert_eq!(outcome, Ok(None));

        // A `{{` at position 0 cannot be escaped: there is no byte in front of
        // it, which is what the `envp > line` guard at `:216` says.
        let (outcome, _) = expand(&vars, b"{{v}}");
        assert_eq!(outcome, Ok(Some(b"V".to_vec())));
    }

    /// The escape does take effect when something else in the same argument
    /// was expanded, because only then is the buffer kept.
    #[test]
    fn escaped_braces_take_effect_alongside_a_real_expansion() {
        let vars = one("v", b"V");
        let (outcome, sink) = expand(&vars, br"\{{x}}{{v}}");
        assert_eq!(outcome, Ok(Some(b"{{x}}V".to_vec())));
        assert!(sink.is_empty());

        // The backslash is dropped and the braces kept, with the preceding
        // text intact.
        let (outcome, _) = expand(&vars, br"pre\{{lit}}post{{v}}");
        assert_eq!(outcome, Ok(Some(b"pre{{lit}}postV".to_vec())));
    }

    /// `:238-242` -- an unclosed `{{` warns and stops; nothing after it is
    /// examined, because C `break`s rather than continuing.
    #[test]
    fn missing_close_warns_and_stops() {
        let vars = one("v", b"V");

        let (outcome, sink) = expand(&vars, b"{{v");
        assert_eq!(outcome, Ok(None));
        assert_diag(&sink, WARN, b"missing close '}}' in '{{v'");

        // The diagnostic reports the WHOLE original argument, not the cursor.
        //
        // What is kept is what was substituted before the break PLUS the rest
        // of the line verbatim: `:241` breaks without advancing the cursor, so
        // the suffix append at `:325-330` -- which `added` has already enabled
        // -- emits the unclosed remainder unchanged, `{{` included.
        let (outcome, sink) = expand(&vars, b"head{{v}}tail{{oops");
        assert_eq!(outcome, Ok(Some(b"headVtail{{oops".to_vec())));
        assert_diag(
            &sink,
            WARN,
            b"missing close '}}' in 'head{{v}}tail{{oops'",
        );

        // A `}}` that appears BEFORE the `{{` does not close it.
        let (outcome, sink) = expand(&vars, b"}}{{v");
        assert_eq!(outcome, Ok(None));
        assert_diag(&sink, WARN, b"missing close '}}' in '}}{{v'");
    }

    /// `:253` -- the bound is `nlen >= sizeof(name)` with
    /// `char name[MAX_VAR_LEN]`, so 127 is accepted and 128 is not.
    #[test]
    fn expansion_name_length_boundary_is_127_and_128() {
        let vars = Variables::default();

        let mut line: Vec<u8> = b"{{".to_vec();
        line.extend(std::iter::repeat(b'a').take(MAX_VAR_LEN - 1));
        line.extend_from_slice(b"}}");
        let (outcome, sink) = expand(&vars, &line);
        assert_eq!(
            outcome,
            Ok(Some(Vec::new())),
            "127 bytes is a well-formed name"
        );
        assert!(sink.is_empty());

        let mut line: Vec<u8> = b"{{".to_vec();
        line.extend(std::iter::repeat(b'a').take(MAX_VAR_LEN));
        line.extend_from_slice(b"}}");
        let (outcome, sink) = expand(&vars, &line);
        assert_eq!(outcome, Ok(None), "128 bytes is rejected");
        let mut expected: Vec<u8> = b"bad variable name length '".to_vec();
        expected.extend_from_slice(&line);
        expected.push(b'\'');
        assert_diag(&sink, WARN, &expected);

        // An empty name takes the same branch (`!nlen`).
        let (outcome, sink) = expand(&vars, b"{{}}");
        assert_eq!(outcome, Ok(None));
        assert_diag(&sink, WARN, b"bad variable name length '{{}}'");

        // So does an empty name with a function, since the colon ends it.
        let (outcome, sink) = expand(&vars, b"{{:trim}}");
        assert_eq!(outcome, Ok(None));
        assert_diag(&sink, WARN, b"bad variable name length '{{:trim}}'");
    }

    /// `:255-256` -- the bad-length span runs from the CURSOR through the
    /// closing braces, so it carries the preceding text with it. This is a
    /// different expression from the bad-character span below and the two are
    /// deliberately not unified.
    #[test]
    fn bad_name_length_span_carries_the_preceding_text() {
        let vars = one("v", b"V");
        // `{{}}` is inserted verbatim TOGETHER with the `pre` in front of it,
        // and the `{{v}}` that follows is what sets `added`.
        let (outcome, sink) = expand(&vars, b"pre{{}}mid{{v}}post");
        assert_eq!(outcome, Ok(Some(b"pre{{}}midVpost".to_vec())));
        assert_diag(
            &sink,
            WARN,
            b"bad variable name length 'pre{{}}mid{{v}}post'",
        );
    }

    /// `:270-278` -- a name byte outside `ISALNUM` and `_` warns and inserts
    /// the whole construct verbatim, both brace pairs included.
    #[test]
    fn bad_name_characters_insert_the_whole_construct_verbatim() {
        let vars = one("v", b"V");

        // A hyphen. The trailing `{{v}}` is what sets `added`, without which
        // the buffer would be discarded and the insertion unobservable.
        let (outcome, sink) = expand(&vars, b"{{a-b}}{{v}}");
        assert_eq!(outcome, Ok(Some(b"{{a-b}}V".to_vec())));
        assert_diag(&sink, WARN, b"bad variable name: a-b");

        // A dot.
        let (outcome, sink) = expand(&vars, b"{{a.b}}{{v}}");
        assert_eq!(outcome, Ok(Some(b"{{a.b}}V".to_vec())));
        assert_diag(&sink, WARN, b"bad variable name: a.b");

        // The diagnostic carries the NAME, while the insertion carries the
        // construct; and the text before the construct is added separately at
        // `:262`, so it appears exactly once.
        let (outcome, sink) = expand(&vars, b"pre{{a b}}post{{v}}");
        assert_eq!(outcome, Ok(Some(b"pre{{a b}}postV".to_vec())));
        assert_diag(&sink, WARN, b"bad variable name: a b");

        // Alone, with nothing to set `added`, the outcome is "not replaced".
        let (outcome, sink) = expand(&vars, b"{{a-b}}");
        assert_eq!(outcome, Ok(None));
        assert_diag(&sink, WARN, b"bad variable name: a-b");

        // The name is checked, not the function part: a bad byte after the
        // colon is an unknown function instead.
        let (outcome, sink) = expand(&vars, b"{{v:a-b}}");
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert_diag(&sink, ERROR, b"unknown variable function in ':a-b'");
    }

    /// `:302-311` -- a value holding a NUL byte cannot be substituted.
    ///
    /// The value is storable: `src/var.c` rejects it at expansion time, not at
    /// definition time, which is why the content is carried as bytes.
    #[test]
    fn null_byte_in_a_value_fails_expansion() {
        let mut vars = Variables::default();
        let mut host = FakeHost::with_file(b"a\0b");
        let (outcome, sink) =
            define_with(&mut vars, b"v@bin", &mut host, MsgConfig::default());
        assert_eq!(outcome, Ok(()), "the NUL is accepted at definition time");
        assert!(sink.is_empty());
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"a\0b"[..])
        );

        let (outcome, sink) = expand(&vars, b"{{v}}");
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert_diag(&sink, ERROR, b"variable contains null byte");

        // A function that keeps the NUL still trips the check, because it runs
        // on what is about to be inserted.
        let (outcome, sink) = expand(&vars, b"{{v:trim}}");
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert_diag(&sink, ERROR, b"variable contains null byte");
    }

    /// `:303` -- the check runs on the function chain's OUTPUT, so a function
    /// that removes the NUL makes the value substitutable.
    #[test]
    fn null_byte_check_runs_on_the_function_output() {
        let mut vars = Variables::default();
        let mut host = FakeHost::with_file(b"a\0b");
        let (outcome, _) =
            define_with(&mut vars, b"v@bin", &mut host, MsgConfig::default());
        assert_eq!(outcome, Ok(()));

        // `url` escapes the NUL as `%00`, so nothing NUL reaches the output.
        let (outcome, sink) = expand(&vars, b"{{v:url}}");
        assert_eq!(outcome, Ok(Some(b"a%00b".to_vec())));
        assert!(sink.is_empty(), "no null-byte error once it is escaped");

        // `json` does the same with its own escape.
        let (outcome, sink) = expand(&vars, b"{{v:json}}");
        assert_eq!(outcome, Ok(Some(br"a\u0000b".to_vec())));
        assert!(sink.is_empty());
    }

    /// `:325-330` -- the trailing text is appended only when something was
    /// substituted, and `:214-324` keeps walking after each construct.
    #[test]
    fn several_constructs_and_the_suffix() {
        let mut vars = one("a", b"A");
        let mut host = FakeHost::empty();
        let (outcome, _) =
            define_with(&mut vars, b"b=B", &mut host, MsgConfig::default());
        assert_eq!(outcome, Ok(()));

        let (outcome, sink) = expand(&vars, b"1{{a}}2{{b}}3{{a}}4");
        assert_eq!(outcome, Ok(Some(b"1A2B3A4".to_vec())));
        assert!(sink.is_empty());

        // Adjacent constructs, and no suffix at all.
        let (outcome, _) = expand(&vars, b"{{a}}{{b}}");
        assert_eq!(outcome, Ok(Some(b"AB".to_vec())));

        // A construct at the very end leaves `line` empty, so the `*line`
        // guard at `:325` skips the suffix append.
        let (outcome, _) = expand(&vars, b"x{{a}}");
        assert_eq!(outcome, Ok(Some(b"xA".to_vec())));
    }

    /// The [`MAX_EXPAND_CONTENT`] cap is reported, never silently applied.
    #[test]
    fn expansion_cap_is_an_error_not_a_truncation() {
        // A value exactly at the cap cannot be appended, because `dyn_nappend`
        // needs one more byte for the terminator it always keeps room for.
        let mut input: Vec<u8> = b"v=".to_vec();
        input.resize(2 + MAX_EXPAND_CONTENT, b'x');
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, &input);
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(
            vars.varcontent(b"v").map(|var| var.content().len()),
            Some(MAX_EXPAND_CONTENT)
        );

        let (outcome, sink) = expand(&vars, b"{{v}}");
        assert_eq!(outcome, Err(ParameterError::NoMem));
        assert!(sink.is_empty(), "the cap is silent, but it is an error");
    }

    // The `[N-M]` range scanner

    /// `curlx_str_number` at base 10: unsigned, no space, no sign, no `0x`,
    /// leading zeroes accepted (`lib/curlx/strparse.c:157-193`).
    #[test]
    fn str_number_matches_the_c_acceptance_rules() {
        let mut pos = 0usize;
        assert_eq!(str_number(b"123]", &mut pos, CURL_OFF_T_MAX), Ok(123));
        assert_eq!(pos, 3, "the cursor stops at the first non-digit");

        // Leading zeroes.
        let mut pos = 0usize;
        assert_eq!(str_number(b"007", &mut pos, CURL_OFF_T_MAX), Ok(7));
        assert_eq!(pos, 3);

        // At least one digit.
        let mut pos = 0usize;
        assert_eq!(
            str_number(b"-1", &mut pos, CURL_OFF_T_MAX),
            Err(StrError::NoNum)
        );
        assert_eq!(pos, 0, "a failure does not advance the cursor");

        // No leading space, and no sign.
        let mut pos = 0usize;
        assert_eq!(
            str_number(b" 1", &mut pos, CURL_OFF_T_MAX),
            Err(StrError::NoNum)
        );
        let mut pos = 0usize;
        assert_eq!(
            str_number(b"+1", &mut pos, CURL_OFF_T_MAX),
            Err(StrError::NoNum)
        );
        // End of input.
        let mut pos = 0usize;
        assert_eq!(
            str_number(b"", &mut pos, CURL_OFF_T_MAX),
            Err(StrError::NoNum)
        );

        // No `0x` prefix support: the `x` simply ends the number.
        let mut pos = 0usize;
        assert_eq!(str_number(b"0x10", &mut pos, CURL_OFF_T_MAX), Ok(0));
        assert_eq!(pos, 1);

        // The maximum itself is accepted.
        let mut pos = 0usize;
        let max = i64::MAX.to_string();
        assert_eq!(
            str_number(max.as_bytes(), &mut pos, CURL_OFF_T_MAX),
            Ok(i64::MAX)
        );

        // One past it is an overflow, not a wrap.
        let mut pos = 0usize;
        assert_eq!(
            str_number(b"9223372036854775808", &mut pos, CURL_OFF_T_MAX),
            Err(StrError::Overflow)
        );
    }

    /// `curlx_str_single` (`lib/curlx/strparse.c:125-132`).
    #[test]
    fn str_single_consumes_exactly_one_byte() {
        let mut pos = 0usize;
        assert_eq!(str_single(b"-]", &mut pos, b'-'), Ok(()));
        assert_eq!(pos, 1);
        assert_eq!(str_single(b"-]", &mut pos, b']'), Ok(()));
        assert_eq!(pos, 2);

        // The wrong byte, and the end of input, both fail without advancing.
        let mut pos = 0usize;
        assert_eq!(str_single(b"x", &mut pos, b'-'), Err(StrError::Byte));
        assert_eq!(pos, 0);
        let mut pos = 0usize;
        assert_eq!(str_single(b"", &mut pos, b'-'), Err(StrError::Byte));
        assert_eq!(pos, 0);
    }

    // setvariable

    /// `:465-481` -- the literal form stores the rest of the argument exactly.
    #[test]
    fn literal_definition_stores_the_rest_of_the_argument() {
        let vars = one("v", b"some content");
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"some content"[..])
        );

        // An empty value is a valid definition.
        let vars = one("v", b"");
        assert_eq!(vars.varcontent(b"v").map(ToolVar::content), Some(&b""[..]));

        // Everything after the first `=` belongs to the content, `=` included.
        let vars = one("v", b"a=b=c");
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"a=b=c"[..])
        );

        // A name may hold digits and underscores.
        let vars = one("A_1", b"x");
        assert_eq!(
            vars.varcontent(b"A_1").map(ToolVar::content),
            Some(&b"x"[..])
        );
    }

    /// `:395-398` -- a bad name length is a WARNING and success, and the
    /// variable is simply not defined. `%zd` prints the length.
    #[test]
    fn bad_name_length_is_a_warning_and_success() {
        // Zero length: the first byte is not a name byte.
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"=value");
        assert_eq!(outcome, Ok(()), "a warning, not a failure");
        assert!(vars.is_empty());
        assert_diag(&sink, WARN, b"Bad variable name length (0), skipping");

        // Zero length after the import marker.
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"%=value");
        assert_eq!(outcome, Ok(()));
        assert!(vars.is_empty());
        assert_diag(&sink, WARN, b"Bad variable name length (0), skipping");

        // An empty argument.
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"");
        assert_eq!(outcome, Ok(()));
        assert_diag(&sink, WARN, b"Bad variable name length (0), skipping");

        // 127 is accepted, 128 is not -- the same bound as `varexpand`.
        let mut vars = Variables::default();
        let name: Vec<u8> =
            std::iter::repeat(b'n').take(MAX_VAR_LEN - 1).collect();
        let mut input = name.clone();
        input.extend_from_slice(b"=x");
        let (outcome, sink) = define(&mut vars, &input);
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(
            vars.varcontent(&name).map(ToolVar::content),
            Some(&b"x"[..])
        );

        let mut vars = Variables::default();
        let name: Vec<u8> = std::iter::repeat(b'n').take(MAX_VAR_LEN).collect();
        let mut input = name.clone();
        input.extend_from_slice(b"=x");
        let (outcome, sink) = define(&mut vars, &input);
        assert_eq!(outcome, Ok(()));
        assert!(vars.is_empty());
        assert_diag(&sink, WARN, b"Bad variable name length (128), skipping");
    }

    /// `:482-485` -- an unrecognised trailing form is a WARNING and success,
    /// and the diagnostic reports the whole argument.
    #[test]
    fn unrecognised_trailing_form_is_a_warning_and_success() {
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"v");
        assert_eq!(outcome, Ok(()));
        assert!(vars.is_empty());
        assert_diag(&sink, WARN, b"Bad --variable syntax, skipping: v");

        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"v:x");
        assert_eq!(outcome, Ok(()));
        assert_diag(&sink, WARN, b"Bad --variable syntax, skipping: v:x");

        // A range with nothing after it takes the same branch.
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"v[1-2]");
        assert_eq!(outcome, Ok(()));
        assert_diag(&sink, WARN, b"Bad --variable syntax, skipping: v[1-2]");

        // `--silent` suppresses it, and the outcome is unchanged
        // (`src/tool_msgs.c:95`).
        let mut vars = Variables::default();
        let mut host = FakeHost::empty();
        let silent = MsgConfig::new(true, false, false);
        let (outcome, sink) = define_with(&mut vars, b"v", &mut host, silent);
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
    }

    /// `:399-418` -- `%NAME` imports from the environment, and a variable that
    /// exists but is blank is a HIT.
    ///
    /// `src/var.c:400-401` records the intent: "this does not use
    /// curl_getenv() because we want \"\" support for blank content".
    #[test]
    fn import_of_a_blank_variable_succeeds() {
        let mut vars = Variables::default();
        let mut host = FakeHost::empty().with_var("BLANK", b"");
        let (outcome, sink) =
            define_with(&mut vars, b"%BLANK", &mut host, MsgConfig::default());
        assert_eq!(outcome, Ok(()), "an existing blank value is not a miss");
        assert!(sink.is_empty());
        assert_eq!(
            vars.varcontent(b"BLANK").map(ToolVar::content),
            Some(&b""[..])
        );

        // A value that is not valid UTF-8 survives, because `var_os` is used
        // rather than `var`.
        let mut vars = Variables::default();
        let mut host = FakeHost::empty().with_var("RAW", &[0xff, 0xfe]);
        let (outcome, _) =
            define_with(&mut vars, b"%RAW", &mut host, MsgConfig::default());
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"RAW").map(ToolVar::content),
            Some(&[0xff, 0xfe][..])
        );
    }

    /// `:409-413` -- an unset variable with no fallback is an ERROR.
    #[test]
    fn import_miss_without_fallback_is_an_error() {
        let mut vars = Variables::default();
        // The environment is empty, so `UNSET` is absent -- which is a
        // different state from present-and-blank above.
        let mut host = FakeHost::empty();
        let (outcome, sink) =
            define_with(&mut vars, b"%UNSET", &mut host, MsgConfig::default());
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert!(vars.is_empty());
        assert_diag(&sink, ERROR, b"Variable 'UNSET' import fail, not set");

        // `--silent` suppresses the message but not the failure; with
        // `--show-error` it returns (`src/tool_msgs.c:131`).
        let mut vars = Variables::default();
        let mut host = FakeHost::empty();
        let silent = MsgConfig::new(true, false, false);
        let (outcome, sink) =
            define_with(&mut vars, b"%UNSET", &mut host, silent);
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert!(sink.is_empty());

        let mut vars = Variables::default();
        let mut host = FakeHost::empty();
        let shown = MsgConfig::new(true, true, false);
        let (outcome, sink) =
            define_with(&mut vars, b"%UNSET", &mut host, shown);
        assert_eq!(outcome, Err(ParameterError::ExpandError));
        assert_diag(&sink, ERROR, b"Variable 'UNSET' import fail, not set");
    }

    /// `:402` and `:419` -- an unset variable WITH a trailing action falls
    /// through to that action instead of failing.
    #[test]
    fn import_miss_with_fallback_falls_through() {
        // The `=` fallback.
        let mut vars = Variables::default();
        let mut host = FakeHost::empty();
        let (outcome, sink) = define_with(
            &mut vars,
            b"%GONE=fallback",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(
            vars.varcontent(b"GONE").map(ToolVar::content),
            Some(&b"fallback"[..])
        );

        // The `@` fallback.
        let mut vars = Variables::default();
        let mut host = FakeHost::with_file(b"file bytes");
        let (outcome, sink) = define_with(
            &mut vars,
            b"%GONE@from-file",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(host.asked, b"from-file".to_vec());
        assert_eq!(
            vars.varcontent(b"GONE").map(ToolVar::content),
            Some(&b"file bytes"[..])
        );

        // A range applies to the fallback, because nothing short-circuited it.
        let mut vars = Variables::default();
        let mut host = FakeHost::empty();
        let (outcome, _) = define_with(
            &mut vars,
            b"%GONE[1-2]=abcdef",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"GONE").map(ToolVar::content),
            Some(&b"bc"[..])
        );
    }

    /// `:434-435` -- `if(content) ;` short-circuits every remaining form, so an
    /// imported value beats both a fallback AND the byte range.
    #[test]
    fn import_hit_short_circuits_the_fallback_and_the_range() {
        let present = || FakeHost::empty().with_var("HIT", b"environment");

        // The `=` fallback is ignored.
        let mut vars = Variables::default();
        let mut host = present();
        let (outcome, sink) = define_with(
            &mut vars,
            b"%HIT=ignored",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(
            vars.varcontent(b"HIT").map(ToolVar::content),
            Some(&b"environment"[..])
        );

        // The range is PARSED but never APPLIED: the whole value is stored.
        let mut vars = Variables::default();
        let mut host = present();
        let (outcome, sink) = define_with(
            &mut vars,
            b"%HIT[0-3]",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(
            vars.varcontent(b"HIT").map(ToolVar::content),
            Some(&b"environment"[..]),
            "the range is parsed before the short-circuit, and discarded"
        );

        // It IS parsed, though, so a malformed one still fails even here.
        let mut vars = Variables::default();
        let mut host = present();
        let (outcome, _) = define_with(
            &mut vars,
            b"%HIT[5-2]",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Err(ParameterError::VarSyntax));

        // The `@` form is short-circuited too, so no path is ever opened.
        let mut vars = Variables::default();
        let mut host = present();
        let (outcome, _) = define_with(
            &mut vars,
            b"%HIT@never-opened",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert!(host.asked.is_empty(), "the file was never opened");
        assert_eq!(
            vars.varcontent(b"HIT").map(ToolVar::content),
            Some(&b"environment"[..])
        );
    }

    /// [`OsVarHost::getenv`] against the live environment, without mutating it.
    ///
    /// The production path has to be exercised as well as the double, or the
    /// double would be the only thing under test. Nothing is set or removed
    /// here: `std::env::set_var` mutates state that every other test in this
    /// binary reads concurrently, and the properties that matter are reachable
    /// from the environment as it already is.
    #[test]
    fn os_var_host_reads_the_live_environment() {
        let host = OsVarHost;

        // A name that cannot plausibly exist is absent.
        assert_eq!(host.getenv(b"BLITZY_CURL_RS_VARS_NO_SUCH_NAME"), None);

        // Any variable that does exist and whose name a `--variable %NAME`
        // argument could carry reports its exact bytes. Iterating rather than
        // naming one keeps the test independent of the ambient environment.
        let existing = env::vars_os().find(|(name, _)| {
            let bytes = name.as_encoded_bytes();
            !bytes.is_empty()
                && bytes.len() < MAX_VAR_LEN
                && bytes.iter().copied().all(is_name_byte)
        });
        if let Some((name, value)) = existing {
            assert_eq!(
                host.getenv(name.as_encoded_bytes()).as_deref(),
                Some(value.as_encoded_bytes()),
                "the live value must arrive byte for byte"
            );
        }
    }

    /// `:420-432` -- the three range forms, and every way to malform one.
    #[test]
    fn byte_range_forms_and_their_failures() {
        // `[0-]` -- open ended, and with `startoffset == 0` the clamp guard at
        // `:470` is not even entered.
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"v[0-]=abcdef");
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"abcdef"[..])
        );

        // `[2-]` -- open ended from an offset.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[2-]=abcdef");
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"cdef"[..])
        );

        // `[2-5]` -- inclusive at BOTH ends, so four bytes.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[2-5]=abcdef");
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"cdef"[..])
        );

        // `[0-0]` -- one byte.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[0-0]=abcdef");
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"a"[..])
        );

        // `[5-2]` -- inverted, rejected at `:431-432`.
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"v[5-2]=abcdef");
        assert_eq!(outcome, Err(ParameterError::VarSyntax));
        assert!(sink.is_empty(), "a syntax failure carries no message here");
        assert!(vars.is_empty());

        // A missing `-`.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[2]=abcdef");
        assert_eq!(outcome, Err(ParameterError::VarSyntax));

        // A missing `]`.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[2-5=abcdef");
        assert_eq!(outcome, Err(ParameterError::VarSyntax));

        // A non-numeric end.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[2-x]=abcdef");
        assert_eq!(outcome, Err(ParameterError::VarSyntax));

        // `ISDIGIT(line[1])` at `:420` gates the whole block, so `[x-1]` is not
        // a range at all -- it is an unrecognised trailing form.
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"v[x-1]=abcdef");
        assert_eq!(outcome, Ok(()));
        assert_diag(
            &sink,
            WARN,
            b"Bad --variable syntax, skipping: v[x-1]=abcdef",
        );

        // And a bare `[` likewise.
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"v[=abcdef");
        assert_eq!(outcome, Ok(()));
        assert_diag(&sink, WARN, b"Bad --variable syntax, skipping: v[=abcdef");
    }

    /// `:470-480` -- the literal form's clamp, copied exactly because C writes
    /// the clamped end back into `endoffset` before computing the count.
    #[test]
    fn literal_range_clamping() {
        // `endoffset >= clen`: the end is pulled back to the last byte.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[1-99]=abc");
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"bc"[..])
        );

        // Exactly the last byte.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[2-2]=abc");
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"c"[..])
        );

        // `startoffset >= clen`: nothing is kept, and this is still a success.
        let mut vars = Variables::default();
        let (outcome, sink) = define(&mut vars, b"v[9-]=abc");
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(vars.varcontent(b"v").map(ToolVar::content), Some(&b""[..]));

        // The boundary: an offset equal to the length keeps nothing.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[3-9]=abc");
        assert_eq!(outcome, Ok(()));
        assert_eq!(vars.varcontent(b"v").map(ToolVar::content), Some(&b""[..]));

        // An empty value with a range.
        let mut vars = Variables::default();
        let (outcome, _) = define(&mut vars, b"v[0-2]=");
        assert_eq!(outcome, Ok(()));
        assert_eq!(vars.varcontent(b"v").map(ToolVar::content), Some(&b""[..]));
    }

    /// `:436-463` -- the `@` form reads a file, and the range is applied by the
    /// sibling `file2memory_range` rather than here.
    #[test]
    fn file_definition_reads_the_requested_range() {
        let mut vars = Variables::default();
        let mut host = FakeHost::with_file(b"0123456789");
        let (outcome, sink) = define_with(
            &mut vars,
            b"v@data.bin",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert_eq!(host.asked, b"data.bin".to_vec());
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"0123456789"[..])
        );

        // A closed range, inclusive at both ends.
        let mut vars = Variables::default();
        let mut host = FakeHost::with_file(b"0123456789");
        let (outcome, _) = define_with(
            &mut vars,
            b"v[2-4]@data.bin",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"234"[..])
        );

        // An open-ended range.
        let mut vars = Variables::default();
        let mut host = FakeHost::with_file(b"0123456789");
        let (outcome, _) = define_with(
            &mut vars,
            b"v[7-]@data.bin",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"789"[..])
        );

        // A path that is not valid UTF-8 is carried through as bytes.
        let mut vars = Variables::default();
        let mut host = FakeHost::with_file(b"x");
        let input: Vec<u8> = vec![b'v', b'@', 0xff, 0xfe];
        let (outcome, _) =
            define_with(&mut vars, &input, &mut host, MsgConfig::default());
        assert_eq!(outcome, Ok(()));
        assert_eq!(host.asked, vec![0xff, 0xfe]);
    }

    /// `:442-444` -- `@-` reads standard input, which cannot seek, so the
    /// leading bytes of a range are drained instead.
    #[test]
    fn stdin_definition_reads_the_dash_form() {
        let mut vars = Variables::default();
        let mut host = FakeHost::with_stdin(b"from stdin");
        let (outcome, sink) =
            define_with(&mut vars, b"v@-", &mut host, MsgConfig::default());
        assert_eq!(outcome, Ok(()));
        assert!(sink.is_empty());
        assert!(host.asked.is_empty(), "no path was opened");
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"from stdin"[..])
        );

        // With a range, over the non-seekable path.
        let mut vars = Variables::default();
        let mut host = FakeHost::with_stdin(b"0123456789");
        let (outcome, _) = define_with(
            &mut vars,
            b"v[3-5]@-",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Ok(()));
        assert_eq!(
            vars.varcontent(b"v").map(ToolVar::content),
            Some(&b"345"[..])
        );

        // `!strcmp(line, "-")` is an exact comparison: `-x` is a filename.
        let mut vars = Variables::default();
        let mut host = FakeHost::with_file(b"dash-x");
        let (outcome, _) =
            define_with(&mut vars, b"v@-x", &mut host, MsgConfig::default());
        assert_eq!(outcome, Ok(()));
        assert_eq!(host.asked, b"-x".to_vec());
    }

    /// `:447-452` -- an unopenable path reports `Failed to open %s: %s` and
    /// fails with `PARAM_READ_ERROR`.
    #[test]
    fn file_open_failure_reports_and_fails() {
        // 2 is `ENOENT` on both mandated platforms.
        let mut vars = Variables::default();
        let mut host = FakeHost::failing(2);
        let (outcome, sink) = define_with(
            &mut vars,
            b"v@missing.bin",
            &mut host,
            MsgConfig::default(),
        );
        assert_eq!(outcome, Err(ParameterError::ReadError));
        assert!(vars.is_empty());

        // The reason is whatever the platform reports, so it is computed the
        // same way rather than hard coded.
        let reason =
            curl_rs_lib::os_error_message(&io::Error::from_raw_os_error(2));
        let expected = format!("Failed to open missing.bin: {reason}");
        assert_diag(&sink, ERROR, expected.as_bytes());

        // `--silent` suppresses it; `--silent --show-error` restores it
        // (`src/tool_msgs.c:131`).
        let mut vars = Variables::default();
        let mut host = FakeHost::failing(2);
        let silent = MsgConfig::new(true, false, false);
        let (outcome, sink) =
            define_with(&mut vars, b"v@missing.bin", &mut host, silent);
        assert_eq!(outcome, Err(ParameterError::ReadError));
        assert!(sink.is_empty());

        let mut vars = Variables::default();
        let mut host = FakeHost::failing(2);
        let shown = MsgConfig::new(true, true, false);
        let (outcome, sink) =
            define_with(&mut vars, b"v@missing.bin", &mut host, shown);
        assert_eq!(outcome, Err(ParameterError::ReadError));
        assert_diag(&sink, ERROR, expected.as_bytes());
    }

    /// A definition followed by the expansion that uses it, which is the whole
    /// point of the module.
    #[test]
    fn definition_and_expansion_together() {
        let mut vars = Variables::default();
        let mut host = FakeHost::empty();
        let config = MsgConfig::default();

        for input in [
            &b"host=example.com"[..],
            &b"path=/a b"[..],
            &b"padded=  spaced  "[..],
        ] {
            let (outcome, sink) =
                define_with(&mut vars, input, &mut host, config);
            assert_eq!(outcome, Ok(()));
            assert!(sink.is_empty());
        }
        assert_eq!(vars.len(), 3);

        let (outcome, sink) =
            expand(&vars, b"https://{{host}}{{path:url}}?p={{padded:trim}}");
        assert_eq!(
            outcome,
            Ok(Some(b"https://example.com%2Fa%20b?p=spaced".to_vec()))
        );
        assert!(sink.is_empty());
    }
}
