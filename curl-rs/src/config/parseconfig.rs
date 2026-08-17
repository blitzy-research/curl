// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! Reading a configuration file -- `src/tool_parsecfg.c`.
//!
//! This is the `.curlrc` and `-K` / `--config` reader. It turns each line of a
//! configuration file into the `(option, argument)` pair that
//! [`crate::cli::args::getparameter`] already knows how to apply, so a file and
//! a command line reach the same parser by the same route.
//!
//! # The two items this module exports, and who consumes them
//!
//! `src/tool_parsecfg.h:30-32` declares exactly two non-static functions, and
//! both are reproduced:
//!
//! * [`parseconfig`] -- the reader. Its two C call sites are
//!   `src/tool_operate.c:2279`, `parseconfig(NULL, CONFIG_MAX_LEVELS,
//!   &curlrc_path)`, the implicit default-`.curlrc` load, and
//!   `src/tool_getparam.c:2252`, `parseconfig(nextarg, max_recursive, NULL)`,
//!   the explicit `-K` load.
//! * [`my_get_line`] -- the line reader. It is **not** static in C, because
//!   `src/tool_ssls.c:80` drives it too, so it is `pub(crate)` here for
//!   `crate::config::ssls` to use rather than copy. `get_line` is static in C
//!   and is private here.
//!
//! # The acceptance grammar is frozen, and it is security-relevant
//!
//! A configuration file can set `--insecure`, `--cacert`, `--capath`,
//! `--proxy-insecure` and credentials, so a parser that mis-splits a line can
//! silently disarm a verification setting or bind a credential to the wrong
//! option. The grammar is therefore reproduced byte for byte rather than
//! approximated, and it is never made more permissive: a file curl accepts is
//! accepted, a file curl rejects is rejected, and every argument binds to the
//! same option with the same bytes.
//!
//! Three consequences of that are easy to "clean up" by accident, so each is
//! stated here and asserted by a test below:
//!
//! 1. **The empty-argument asymmetry.** An empty *quoted* argument (`""`)
//!    yields an empty string (`:172`), while an empty *unquoted* argument
//!    yields no argument at all (`:205-208`). The two are different values,
//!    and [`Directive::param`] keeps them apart as `Some(empty)` against
//!    [`None`].
//! 2. **The reader keeps `'\r'`.** `get_line` strips exactly one `'\n'`
//!    (`:302-306`) and nothing else, so on a CRLF file the carriage return
//!    reaches the tokeniser. That is why the tokeniser tests for it explicitly
//!    at `:181` and `:195`. Stripping it in the reader would change which byte
//!    sequences the tokeniser sees.
//! 3. **`=` and `:` separate only undashed options.** `ISSEP` (`:36`) is
//!    disabled once the option began with a dash, so `url=x` splits and
//!    `--url=x` does not.
//!
//! # No global: the configuration is threaded explicitly
//!
//! C reads and writes the file-scope singleton `global`
//! (`extern struct GlobalConfig *global;`, `src/tool_cfgable.h:42`) at
//! `src/tool_parsecfg.c:87`, `:215` and `:227`. AAP section 0.1.2 replaces the
//! god-struct and its shared mutable state with "per-module structs with
//! explicit ownership", so [`parseconfig`] takes the owning [`GlobalConfig`] as
//! a parameter. There is no `static mut` here -- it could not compile under the
//! `#![forbid(unsafe_code)]` that `curl-rs/src/main.rs:49` carries -- and no
//! `thread_local!` or `OnceLock` substitute either.
//!
//! C's `config` local is the chain cursor, and this crate already models it:
//! `crate::config::ConfigChain`'s `current` is that variable, which is what
//! `crate::cli::args`'s `config_of` normalises so that `getparameter` can be
//! called directly by a configuration-file reader.
//!
//! # Two constants that live elsewhere, and are not redefined here
//!
//! * `CONFIG_MAX_LEVELS 5` (`src/tool_parsecfg.h:28-29`, "only allow this many
//!   levels of recursive --config use") is declared by
//!   `crate::cli::args::CONFIG_MAX_LEVELS`, beside the `--config` case that
//!   spends the budget. It is neither restated nor re-exported here: two
//!   spellings of one frozen number is one more than a frozen number can have,
//!   and a second path to the same constant is a second thing to keep in step.
//!   The header that declares it in C is this module's, so the placement is
//!   worth naming rather than leaving to be discovered -- but the decrement and
//!   the depth check are the argument parser's
//!   (`src/tool_getparam.c:2246`, `if(--max_recursive < 0)`), so the constant
//!   sits with them and this module only threads the value through as
//!   `max_recursive`.
//! * `MAX_CONFIG_LINE_LENGTH` (`src/tool_cfgable.h:32`) belongs to
//!   [`crate::config`] and is imported. Both C line buffers are capped at it
//!   (`:130-131`).
//!
//! # Two translation decisions, recorded because they are not obvious
//!
//! **A read failure is not a read error, and that is C's behaviour rather than
//! an oversight.** C's `get_line` never inspects `ferror`: `fgets` returning
//! `NULL` means end of input *or* a failed read, and both take the `:313-316`
//! path, which yields the partial line if there is one and otherwise reports a
//! clean end of input. The error flag is set at exactly one place, `:296-300`,
//! where appending to the capped buffer failed. This module reproduces that
//! split, so the 10 MiB cap is a read error while a mid-file `EIO` is end of
//! input. `ErrorKind::Interrupted` is retried, which cannot change which byte
//! content is accepted.
//!
//! **Three preprocessor-gated blocks are omitted rather than stubbed**, which
//! together with the mapping above accounts for every line of the original:
//!
//! * `:101-112` is `#ifdef _WIN32` and looks for `.curlrc` then `_curlrc`
//!   beside the executable through `tool_execpath`. The four mandated targets
//!   are `x86_64` and `aarch64` on Linux and macOS (AAP section 0.2.2), so
//!   there is no `#[cfg(windows)]` scaffolding here and no `tool_execpath`
//!   counterpart.
//! * `:156-158` and `:211-213` are `#ifdef DEBUG_CONFIG` and print the option
//!   token and the argument to standard error. `DEBUG_CONFIG` is a C
//!   preprocessor symbol and **not** one of the fifteen Cargo features, so
//!   there is no `#[cfg(feature = ...)]` to hang them on and inventing a
//!   sixteenth feature to carry two `printf`s is not warranted. Nothing else
//!   in the file depends on them.
//!
//! # One gap, reported rather than worked around
//!
//! Nothing calls [`parseconfig`] yet, and it cannot be wired up from this file.
//! `crate::cli::args::ParseHost::parse_config` (`curl-rs/src/cli/args.rs:2173`)
//! is the hook, and its signature omits the `&mut GlobalConfig` that reading a
//! file needs in order to re-enter `getparameter`. Adding that parameter is a
//! one-line change to the trait plus a one-line change to its implementation in
//! `curl-rs/src/main.rs:590-627`, and neither file is this one's to edit --
//! `main.rs` is not among its declared dependencies, and changing the trait
//! alone would break that implementation. The reader below is complete and
//! tested; only the two lines that reach it are outstanding.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, BufRead, BufReader, StdinLock};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::cli::args::{getparameter, param2text, ParameterError, ParseHost};
use crate::config::findfile::{findfile, CURLRC_DOTSCORE};
use crate::config::{
    GlobalConfig, OperationConfig, TraceType, MAX_CONFIG_LINE_LENGTH,
};
use crate::output::msgs::{
    errorf_bytes, warnf_bytes, DiagnosticSink, MsgConfig,
};

/// `sizeof(buffer)` for the `char buffer[128]` of `src/tool_parsecfg.c:284`.
///
/// The chunk size is observable through the cap: `fgets` reads at most
/// `sizeof(buffer) - 1` bytes per call, and the accumulated line is what the
/// cap applies to, so a different chunk size would move the boundary at which
/// a line becomes too long.
const FGETS_BUFFER_SIZE: usize = 128;

/// `ISBLANK` -- `lib/curl_ctype.h:45`, space and horizontal tab only.
///
/// Deliberately **not** `u8::is_ascii_whitespace`, which also accepts `'\n'`,
/// `'\r'` and `'\f'`. The difference is load-bearing: a line consisting solely
/// of `"\r"` is not blank by this test, so `my_get_line` returns it and the
/// tokeniser runs on it.
const fn is_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// `ISSPACE` -- `lib/curl_ctype.h:46`, `ISBLANK` plus `0x0a..=0x0d`.
///
/// That range is `'\n'`, `'\v'`, `'\f'` and `'\r'`, which is what lets an
/// unquoted argument stop at a carriage return (`:181`, "stop also on CRLF").
const fn is_space(byte: u8) -> bool {
    is_blank(byte) || matches!(byte, 0x0a..=0x0d)
}

/// `ISSEP(x, dash)` -- `src/tool_parsecfg.c:36`.
///
/// C's comment at `:34-35` is the whole rule: "only acknowledge colon or equals
/// as separators if the option was not specified with an initial dash!"
const fn is_sep(byte: u8, dashed: bool) -> bool {
    !dashed && matches!(byte, b'=' | b':')
}

/// The one failure `curlx_dyn_addn` reports to this file -- either the line
/// exceeded [`MAX_CONFIG_LINE_LENGTH`] or the allocation failed.
///
/// C conflates them too: `dyn_nappend` returns `CURLE_TOO_LARGE`
/// (`lib/curlx/dynbuf.c:84`) or `CURLE_OUT_OF_MEMORY` (`:108`), and
/// `src/tool_parsecfg.c:296-300` treats any non-zero result as "too long line
/// or out of memory". A named type rather than `Result<(), ()>`, which
/// `clippy::result_unit_err` rejects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BufferFull;

/// `curlx_dyn_addn(buf, mem, len)` over a [`Vec`], cap included.
///
/// The bound is the measured one rather than a restatement of the constant.
/// `lib/curlx/dynbuf.c:72` computes `fit = len + idx + 1` -- new bytes, bytes
/// already held, and the terminating zero -- and `:82` fails when
/// `fit > s->toobig`. The greatest line this accepts is therefore
/// `MAX_CONFIG_LINE_LENGTH - 1` bytes, not `MAX_CONFIG_LINE_LENGTH`.
///
/// On failure C calls `curlx_dyn_free(s)` (`:83`, `:107`), which releases the
/// buffer rather than merely truncating it; releasing the allocation here does
/// the same and matters at this cap, which is 10 MiB.
fn append(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), BufferFull> {
    let fits = buf
        .len()
        .checked_add(bytes.len())
        .and_then(|held| held.checked_add(1))
        .is_some_and(|fit| fit <= MAX_CONFIG_LINE_LENGTH);

    // `:82-85` -- over the cap, and `:104-109` -- the reallocation failed.
    // `try_reserve` is what makes the second one reportable instead of an
    // abort; C's `realloc` returning `NULL` is the same condition.
    if !fits || buf.try_reserve(bytes.len()).is_err() {
        *buf = Vec::new();
        return Err(BufferFull);
    }

    buf.extend_from_slice(bytes);
    Ok(())
}

/// `unslashquote` -- `src/tool_parsecfg.c:44-78`.
///
/// C's own description, at `:38-43`: "Copies the string from line to the param
/// dynbuf, unquoting backslash-quoted characters and null-terminating the
/// output string. Stops at the first non-backslash-quoted double quote
/// character or the end of the input string. param must be at least as long as
/// the input string. Returns 0 on success."
///
/// The escape set is exactly `\t`, `\n`, `\r` and `\v`, plus C's `default:`
/// arm at `:53-54` whose comment reads "default is to output the letter after
/// the backslash". So `\"` is a quote, `\\` is a backslash, and `\q` is `q`.
///
/// **There is no `\0` octal escape, no `\x` hex escape and no `\a`, `\b` or
/// `\f`.** `\a` produces a literal `a` and `\x41` produces `x41`. A backslash
/// at the very end of the input ends the copy, which is C's `case '\0':
/// continue` at `:55-56` reached with the cursor on the terminator.
///
/// # Errors
///
/// [`BufferFull`] when the output exceeds [`MAX_CONFIG_LINE_LENGTH`] or cannot
/// be allocated, which is C's non-zero return at `:71` and `:75`.
fn unslashquote(line: &[u8], param: &mut Vec<u8>) -> Result<(), BufferFull> {
    // `curlx_dyn_reset(param)` -- `:46`.
    param.clear();

    let mut at = 0;

    // `while(*line && (*line != '\"'))` -- `:48`.
    while let Some(&byte) = line.get(at) {
        if byte == b'"' {
            break;
        }

        if byte == b'\\' {
            // `line++` -- `:51`, then the switch on the byte that follows.
            at += 1;
            let Some(&escaped) = line.get(at) else {
                // `case '\0': continue;` -- `:55-56`, whose comment reads
                // "this breaks out of the loop": the cursor now sits on the
                // terminator, so the `while` condition ends the copy.
                break;
            };
            let out = match escaped {
                b't' => b'\t',
                b'n' => b'\n',
                b'r' => b'\r',
                b'v' => 0x0b,
                // `:53-54` -- "default is to output the letter after the
                // backslash".
                other => other,
            };
            append(param, &[out])?;
            // `line++` -- `:72`.
            at += 1;
        } else {
            // `curlx_dyn_addn(param, line++, 1)` -- `:74`.
            append(param, &[byte])?;
            at += 1;
        }
    }

    Ok(())
}

// The line readers -- `src/tool_parsecfg.c:281-347`

/// What one call to [`my_get_line`] or `get_line` produced.
///
/// C returns a `bool` and reports the third state through a `bool *error`
/// out-parameter (`src/tool_parsecfg.h:32`). The three states are kept apart
/// because the caller treats them differently: a read error becomes
/// [`ParameterError::ReadError`] (`:263-264`) while a clean end of input is
/// success. Collapsing the error into the end of input would turn a truncated
/// configuration file into a silently accepted one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LineOutcome {
    /// A line was produced, and the buffer holds it without its newline.
    Line,
    /// The input ended with no further line to give.
    Eof,
    /// The line could not be read: it exceeded [`MAX_CONFIG_LINE_LENGTH`] or
    /// the buffer could not grow. C's `*error = TRUE` at `:298`.
    ReadError,
}

/// What one `fgets` call observed.
struct Chunk {
    /// How many bytes it placed in the caller's buffer, C's non-`NULL` return
    /// with `strlen(b)` still to be applied.
    len: usize,
    /// `feof(input)` as `:310` reads it: the read stopped because the input
    /// ended rather than because the buffer filled or a newline arrived.
    eof: bool,
}

/// `fgets(buffer, sizeof(buffer), input)` -- `src/tool_parsecfg.c:287`.
///
/// Reproduces the three ways `fgets` stops: after a `'\n'`, which it keeps;
/// after `sizeof(buffer) - 1` bytes; and at the end of the input. A zero-length
/// result stands for `fgets` returning `NULL`.
///
/// A failed read reports the end of the input rather than an error, because
/// that is what C does with it -- see the module documentation.
/// `Interrupted` is
/// retried, which no complete input can observe.
fn fgets<R: BufRead + ?Sized>(
    input: &mut R,
    buffer: &mut [u8; FGETS_BUFFER_SIZE],
) -> Chunk {
    // `fgets` writes at most `size - 1` bytes and terminates what it wrote.
    let capacity = FGETS_BUFFER_SIZE - 1;
    let mut len = 0;

    while len < capacity {
        let available = match input.fill_buf() {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(_) => return Chunk { len, eof: true },
        };

        if available.is_empty() {
            return Chunk { len, eof: true };
        }

        // Never more than the room left, so the copy below cannot overrun.
        let room = capacity - len;
        let slice = available.get(..room.min(available.len()));
        let Some(slice) = slice else {
            return Chunk { len, eof: true };
        };

        // `fgets` stops *after* a newline and keeps it.
        let newline = slice.iter().position(|byte| *byte == b'\n');
        let used = match newline {
            Some(at) => at + 1,
            None => slice.len(),
        };

        let source = slice.get(..used);
        let target = buffer.get_mut(len..len + used);
        let (Some(source), Some(target)) = (source, target) else {
            return Chunk { len, eof: true };
        };
        target.copy_from_slice(source);

        len += used;
        input.consume(used);

        if newline.is_some() {
            return Chunk { len, eof: false };
        }
    }

    Chunk { len, eof: false }
}

/// `get_line` -- `src/tool_parsecfg.c:281-319`, static in C and private here.
///
/// Accumulates [`FGETS_BUFFER_SIZE`]-byte chunks into `buf` until the line
/// ends, and strips **exactly one** `'\n'` when it does (`:302-306`). It strips
/// no `'\r'`: on a CRLF file the carriage return stays in the line, which is
/// what the tokeniser's `'\r'` cases at `:181` and `:195` exist to handle.
fn get_line<R: BufRead + ?Sized>(
    input: &mut R,
    buf: &mut Vec<u8>,
) -> LineOutcome {
    let mut buffer = [0u8; FGETS_BUFFER_SIZE];

    // `curlx_dyn_reset(buf)` -- `:285`.
    buf.clear();

    loop {
        let chunk = fgets(input, &mut buffer);

        // `if(b)` -- `:289`. A zero-length chunk is `fgets` returning `NULL`,
        // which `:313-316` answers with the partial line if there is one and
        // otherwise with no line at all.
        if chunk.len == 0 {
            return if buf.is_empty() {
                LineOutcome::Eof
            } else {
                LineOutcome::Line
            };
        }

        let read = buffer.get(..chunk.len).unwrap_or_default();

        // `size_t rlen = strlen(b);` -- `:290`. C measures the chunk as a C
        // string, so an embedded zero byte truncates it and the bytes behind it
        // are dropped from the line. Reproduced rather than tidied: it decides
        // which bytes reach the tokeniser.
        let text = match read.iter().position(|byte| *byte == 0) {
            Some(nul) => read.get(..nul).unwrap_or_default(),
            None => read,
        };

        // `if(!rlen) break;` -- `:292-293`. A chunk that *begins* with a zero
        // byte ends the read with no line, discarding whatever earlier chunks
        // had accumulated. This is a different state from `fgets` returning
        // `NULL` above, which keeps the partial line.
        if text.is_empty() {
            return LineOutcome::Eof;
        }

        // `:295-300` -- "too long line or out of memory".
        if append(buf, text).is_err() {
            return LineOutcome::ReadError;
        }

        // `:302-308` -- "end of the line, drop the newline".
        if text.last() == Some(&b'\n') {
            buf.pop();
            return LineOutcome::Line;
        }

        // `:310-311` -- a partial chunk at the end of the input is still a
        // line.
        if chunk.eof {
            return LineOutcome::Line;
        }
    }
}

/// `my_get_line` -- `src/tool_parsecfg.c:325-347`.
///
/// C's own description, at `:321-324`: "Returns a line from the given file.
/// Every line is null-terminated (no newline). Skips #-commented and
/// space/tabs-only lines automatically."
///
/// A line is skipped when its first non-blank column holds `'#'` -- C's comment
/// at `:337` reads "a line with # in the first non-blank column is a comment!"
/// -- or when it holds nothing at all, which covers both the empty buffer of
/// `:341-342` ("avoid returning an empty line") and the all-blank line of
/// `:338`. "Blank" is [`is_blank`], so a line of just `"\r"` is **not** blank
/// and is returned.
///
/// `buf` is the caller's, reused across calls exactly as the C `dynbuf` is, and
/// holds the line on [`LineOutcome::Line`]. This is the signature
/// `crate::config::ssls` consumes; `src/tool_ssls.c:80` drives the C original
/// the same way, one call per line with the buffer read after each.
#[allow(dead_code)] // Consumed by `parseconfig` below and, once it lands, by
                    // `crate::config::ssls` -- `src/tool_ssls.c:80`.
pub(crate) fn my_get_line<R: BufRead + ?Sized>(
    input: &mut R,
    buf: &mut Vec<u8>,
) -> LineOutcome {
    // `do { ... } while(retcode);` -- `:328-345`. Only a produced line can be
    // skipped, so only a produced line loops.
    loop {
        let outcome = get_line(input, buf);

        // `if(!*error && retcode)` -- `:330`.
        if outcome == LineOutcome::Line {
            match buf.iter().position(|byte| !is_blank(*byte)) {
                // `if((*line == '#') || !*line) continue;` -- `:338-339`.
                Some(at) if buf.get(at) == Some(&b'#') => continue,
                Some(_) => {}
                // Nothing but blanks, or nothing at all -- `:338` and
                // `:341-342`.
                None => continue,
            }
        }

        // `break;` -- `:344`.
        return outcome;
    }
}

// The tokeniser -- `src/tool_parsecfg.c:143-209`

/// One configuration line, split into the pair `getparameter` takes.
///
/// C splits in place: `:154` and `:185` write `'\0'` into the line buffer and
/// walk a pointer past it. Nothing is mutated here -- the option is a subslice
/// of the caller's line and the argument is owned -- which is both what
/// `#![forbid(unsafe_code)]` prefers and what makes the empty-argument
/// asymmetry below expressible at all.
#[derive(Debug, Eq, PartialEq)]
struct Directive<'a> {
    /// `option` -- `:144`, "the option keywords starts here".
    option: &'a [u8],

    /// `param` -- the argument, and the place the asymmetry lives.
    ///
    /// [`None`] is C's `param = NULL` at `:205-208`, reached only from the
    /// unquoted branch. `Some` holding an empty slice is C's `""` at `:172`,
    /// reached only from the quoted branch. The two mean different things to
    /// `getparameter`, so they are different values here.
    param: Option<Vec<u8>>,

    /// The argument began with `'\''` -- `:175`, which earns the frozen warning
    /// of `:176-178`.
    leading_single_quote: bool,

    /// Something other than a comment or a line ending followed the argument --
    /// C's `default:` at `:199`, which earns the frozen warning of `:200-202`.
    unquoted_whitespace: bool,
}

/// Splits one line into its option and its argument -- `:143-209`.
///
/// # Errors
///
/// [`ParameterError::BadUse`] when `unslashquote` fails on a quoted argument,
/// which is C's `err = PARAM_BAD_USE; break;` at `:168-171`. That one ends the
/// whole read rather than the line.
fn split_line(line: &[u8]) -> Result<Directive<'_>, ParameterError> {
    // `dashed_option = (option[0] == '-');` -- `:147`.
    let dashed = line.first() == Some(&b'-');

    // `while(*line && !ISBLANK(*line) && !ISSEP(*line, dashed_option))` --
    // `:149-150`.
    let mut at = 0;
    while let Some(&byte) = line.get(at) {
        if is_blank(byte) || is_sep(byte, dashed) {
            break;
        }
        at += 1;
    }
    let option = line.get(..at).unwrap_or(line);

    // `if(*line) *line++ = '\0';` -- `:153-154`. The terminator has no
    // counterpart -- `option` is already bounded -- so only the step remains.
    if line.get(at).is_some() {
        at += 1;
    }

    // `while(ISBLANK(*line) || ISSEP(*line, dashed_option)) line++;` --
    // `:161-162`, "pass spaces and separator(s)". Blanks and separators are
    // skipped together, so `url : x` and `url::x` both reach the same argument.
    while let Some(&byte) = line.get(at) {
        if is_blank(byte) || is_sep(byte, dashed) {
            at += 1;
        } else {
            break;
        }
    }

    let rest = line.get(at..).unwrap_or_default();

    // `if(*line == '\"')` -- `:165`, "quoted parameter, do the quote dance".
    if rest.first() == Some(&b'"') {
        let mut param = Vec::new();
        // `unslashquote(++line, &pbuf)` -- `:167`, from *after* the quote.
        if unslashquote(rest.get(1..).unwrap_or_default(), &mut param).is_err()
        {
            // `:168-171`.
            return Err(ParameterError::BadUse);
        }

        // `:172` -- `curlx_dyn_len(&pbuf) ? curlx_dyn_ptr(&pbuf) : ""`. Both
        // arms are a string, so an empty quoted argument is an empty string and
        // never an absent one. Half of the asymmetry.
        return Ok(Directive {
            option,
            param: Some(param),
            leading_single_quote: false,
            unquoted_whitespace: false,
        });
    }

    Ok(unquoted_argument(option, rest))
}

/// The unquoted branch -- `src/tool_parsecfg.c:174-209`.
///
/// Split out from [`split_line`] so that each branch of `:165` reads as one
/// unit; the behaviour is C's, statement for statement.
fn unquoted_argument<'a>(option: &'a [u8], rest: &'a [u8]) -> Directive<'a> {
    // `if(*line == '\'')` -- `:175`.
    let leading_single_quote = rest.first() == Some(&b'\'');

    // `param = line;` then
    // `while(*line && !ISSPACE(*line)) line++;` -- `:180-182`, whose comment
    // reads "stop also on CRLF". `ISSPACE` is wider than `ISBLANK`: this is
    // where a retained carriage return terminates the argument.
    let mut end = 0;
    while let Some(&byte) = rest.get(end) {
        if is_space(byte) {
            break;
        }
        end += 1;
    }
    let param = rest.get(..end).unwrap_or(rest);

    let mut unquoted_whitespace = false;

    // `if(*line)` -- `:184`. Only when a byte followed the argument is there
    // anything to inspect.
    if rest.get(end).is_some() {
        // `*line = '\0'; line++;` -- `:185-188`, "to detect mistakes better,
        // see if there is data following", then `:190-191` "pass all spaces".
        let mut after = end + 1;
        while let Some(&byte) = rest.get(after) {
            if is_blank(byte) {
                after += 1;
            } else {
                break;
            }
        }

        // `switch(*line)` -- `:193-203`. `'\0'` is C's terminator, which here
        // is the end of the line; `'\r'` and `'\n'` are a line ending the
        // reader kept; `'#'` is C's "comment", so a trailing comment after an
        // argument is accepted in silence.
        match rest.get(after).copied() {
            None | Some(b'\r' | b'\n' | b'#') => {}
            // C's `default:` at `:199`.
            Some(_) => unquoted_whitespace = true,
        }
    }

    // `:205-208` -- the other half of the asymmetry, with C's comment carried
    // because the two branches disagreeing is deliberate:
    //   if(!*param)
    //     /* do this so getparameter can check for required parameters.
    //        Otherwise it always thinks there is a parameter. */
    //     param = NULL;
    let param = if param.is_empty() {
        None
    } else {
        Some(param.to_vec())
    };

    Directive {
        option,
        param,
        leading_single_quote,
        unquoted_whitespace,
    }
}

// The frozen messages -- `src/tool_parsecfg.c:176-178`, `:200-202`, `:249-250`
// and `:270`
//
// Held as constants so that a test can assert the bytes against the C rather
// than against a restatement of them, and assembled as bytes rather than
// formatted through `Display`: both the filename and the option token are
// arbitrary bytes on the mandated targets -- one comes from the command line,
// the other from the file -- and rendering either through `Path::display` would
// substitute U+FFFD and change the emitted bytes. `crate::output::formparse`
// takes the same route for the same reason.

/// The text between the location and the option name, shared by `:176-178` and
/// `:200-202`.
const OPTION_HEAD: &str = "Option '";

/// The tail of the leading-single-quote warning -- `:176-178`, one logical
/// string split across two C source lines.
const LEADING_SINGLE_QUOTE_TAIL: &str =
    "' uses argument with leading single quote. It is probably a mistake. \
     Consider double quotes.";

/// The tail of the unquoted-whitespace warning -- `:200-202`.
const UNQUOTED_WHITESPACE_TAIL: &str =
    "' uses argument with unquoted whitespace. This may cause side-effects. \
     Consider double quotes.";

/// The text between the location and the option name of `:249-250`.
const BAD_OPTION_HEAD: &str = "config file option '";

/// The head of the unreadable-file error -- `:270`.
const CANNOT_READ_HEAD: &str = "cannot read config from '";

/// The name substituted for `-` when a message is formatted -- `:240-242`.
const STDIN_NAME: &str = "<stdin>";

/// `"%s:%d "` -- the location every in-file message opens with.
fn location(filename: &[u8], lineno: i32) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(filename);
    message.push(b':');
    // C's `%d` over an `int`. `to_string` is total; no width or padding is
    // applied, matching the bare conversion.
    message.extend_from_slice(lineno.to_string().as_bytes());
    message.push(b' ');
    message
}

/// `MsgConfig` as the diagnostic helpers want it, read from the configuration
/// this file was handed.
///
/// Mirrors the private `msg_config` of `curl-rs/src/cli/args.rs:2234-2240`,
/// which is not reachable from here. The gates it reproduces are
/// `src/tool_msgs.c:95` for a warning and `:131` for an error.
fn msg_config(global: &GlobalConfig) -> MsgConfig {
    MsgConfig::new(
        global.silent,
        global.showerror,
        global.tracetype != TraceType::None,
    )
}

/// Emits one of the two frozen warnings -- `:176-178` and `:200-202`.
///
/// Routed through `crate::output::msgs` rather than to standard error directly,
/// so that the `!global->silent` gate of `src/tool_msgs.c:95` applies and the
/// message is word-wrapped the way every other diagnostic is.
fn warn_argument(
    sink: &mut dyn DiagnosticSink,
    msgs: &MsgConfig,
    filename: &[u8],
    lineno: i32,
    option: &[u8],
    tail: &str,
) {
    let mut message = location(filename, lineno);
    message.extend_from_slice(OPTION_HEAD.as_bytes());
    message.extend_from_slice(option);
    message.extend_from_slice(tail.as_bytes());
    warnf_bytes(sink, msgs, &message);
}

// `parseconfig` -- `src/tool_parsecfg.c:81-279`

/// Where the configuration bytes come from -- `:94`, `:116` and `:118`.
///
/// Two variants because C has two, and the distinction is observable: `:259`
/// reads `if(file != stdin)` before closing, so standard input must survive the
/// read. Ownership expresses that instead of a comparison -- the file is closed
/// by its own drop, and [`StdinLock`] only ever releases the lock -- so the
/// close cannot reach descriptor 0 even if this code is restructured later.
enum ConfigSource {
    /// A named file, `fopen(..., FOPEN_READTEXT)` at `:94` or `:116`.
    ///
    /// `FOPEN_READTEXT` is `"r"` on the mandated targets
    /// (`lib/curl_setup.h:1258`), so there is no text-mode translation to
    /// reproduce. Buffered because `get_line` reads in 127-byte chunks and
    /// [`BufRead`] is what supplies them.
    File(BufReader<File>),

    /// The process's standard input, selected by a filename of `-` at
    /// `:117-118`.
    Stdin(StdinLock<'static>),
}

impl ConfigSource {
    /// `fopen`'s result, wrapped -- `:94`, `:116`.
    fn file(file: File) -> Self {
        Self::File(BufReader::new(file))
    }

    /// `file = stdin;` -- `:118`.
    fn stdin() -> Self {
        Self::Stdin(io::stdin().lock())
    }

    /// The reader the line loop drives.
    fn reader(&mut self) -> &mut dyn BufRead {
        match self {
            Self::File(file) => file,
            Self::Stdin(stdin) => stdin,
        }
    }
}

/// Applies one already-split line -- `:214-255`.
///
/// Returns this line's own result, C's `res`, which the caller folds
/// into `err`.
/// Kept separate from [`parse_lines`] so that the loop's shape stays legible;
/// the statement order below is C's and is what the tests assert.
fn apply_directive<H: ParseHost>(
    directive: &Directive<'_>,
    filename: &mut Vec<u8>,
    lineno: i32,
    max_recursive: i32,
    global: &mut GlobalConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    let mut usedarg = false;

    // `res = getparameter(option, param, &usedarg, config, max_recursive);` --
    // `:214`.
    let mut res = getparameter(
        directive.option,
        directive.param.as_deref(),
        &mut usedarg,
        max_recursive,
        global,
        host,
        sink,
    );

    // `config = global->last;` -- `:215`. Re-read rather than cached: a
    // `--config` on this line may itself have started further operations, so
    // the cursor moves to the last of them. C's `config` local is this crate's
    // chain cursor; see the module documentation.
    global.chain.set_current(global.chain.last_index());

    // `if(!res && param && *param && !usedarg)` -- `:217-219`, "we passed in a
    // parameter that was not used!". All four conditions, so an empty-string
    // argument -- which only the quoted branch can produce -- does not trigger
    // it.
    if res.is_ok()
        && directive
            .param
            .as_deref()
            .is_some_and(|param| !param.is_empty())
        && !usedarg
    {
        res = Err(ParameterError::GotExtraParameter);
    }

    // `if(res == PARAM_NEXT_OPERATION)` -- `:221-236`.
    if res == Err(ParameterError::NextOperation) {
        res = start_next_operation(global);
    }

    // `if(res != PARAM_OK && res != PARAM_NEXT_OPERATION)` -- `:238`.
    if let Err(reason) = res {
        if reason != ParameterError::NextOperation {
            res = report_bad_option(
                reason,
                filename,
                lineno,
                directive.option,
                global,
                sink,
            );
        }
    }

    res
}

/// `--next` inside a configuration file -- `src/tool_parsecfg.c:221-236`.
///
/// # This is not `parse_args`'s `--next`
///
/// `crate::cli::args`'s `start_next_operation` reproduces
/// `src/tool_getparam.c:3088-3110`, which **errors** with
/// `missing URL before --next` when the current operation has no URL. The
/// configuration-file path at `:222` is a plain `if` with no `else`: without a
/// URL the new operation is simply not created, `res` stays
/// [`ParameterError::NextOperation`], `:238` excludes it from the error report,
/// and parsing continues on the *same* operation. The two must not be
/// interchanged.
fn start_next_operation(
    global: &mut GlobalConfig,
) -> Result<(), ParameterError> {
    // `if(config->url_list && config->url_list->url)` -- `:222`.
    let has_url = global
        .chain
        .current()
        .and_then(|config| config.url_list.first())
        .is_some_and(|node| node.url.is_some());

    if has_url {
        // `config->next = config_alloc();` -- `:224`, then `:227-231` moving
        // `global->last` and the cursor onto it. The `prev`/`next` links
        // have no
        // counterpart: the chain is owned storage, so position supplies both.
        match global.chain.append(OperationConfig::new()) {
            Ok(at) => {
                global.chain.set_current(Some(at));
            }
            // `else res = PARAM_NO_MEM;` -- `:233-234`.
            Err(_) => return Err(ParameterError::NoMem),
        }
    }

    // `res` is untouched on both remaining paths, so it is still
    // `PARAM_NEXT_OPERATION` when `:238` inspects it.
    Err(ParameterError::NextOperation)
}

/// Reports a rejected line -- `src/tool_parsecfg.c:239-254`.
///
/// Returns the result the caller should adopt, which is C's `res` after the
/// remap at `:251-252`. The five help-ish outcomes are returned unchanged and
/// leave `err` untouched, which is why parsing continues past them.
fn report_bad_option(
    reason: ParameterError,
    filename: &mut Vec<u8>,
    lineno: i32,
    option: &[u8],
    global: &GlobalConfig,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    // `if(!strcmp(filename, "-")) filename = "<stdin>";` -- `:240-242`. Before
    // the message is formatted, and it sticks: a later line's warning shows the
    // substituted name too, because C reassigns the variable rather than
    // formatting a copy.
    if filename.as_slice() == b"-" {
        *filename = STDIN_NAME.as_bytes().to_vec();
    }

    // `:243-247` -- "the help request is not really an error". These five
    // produce no message and are not folded into `err`.
    if matches!(
        reason,
        ParameterError::HelpRequested
            | ParameterError::ManualRequested
            | ParameterError::VersionInfoRequested
            | ParameterError::EnginesRequested
            | ParameterError::CaEmbedRequested
    ) {
        return Err(reason);
    }

    // `const char *reason = param2text(res);` -- `:248`, then the frozen
    // message at `:249-250`.
    let mut message = location(filename, lineno);
    message.extend_from_slice(BAD_OPTION_HEAD.as_bytes());
    message.extend_from_slice(option);
    message.extend_from_slice(b"' ");
    message.extend_from_slice(param2text(reason).as_bytes());
    errorf_bytes(sink, &msg_config(global), &message);

    // `:251-252` -- the remap happens *after* the message, so the text reports
    // the original reason ("is unknown") while the caller receives the
    // configuration-file flavour of it.
    if reason == ParameterError::OptionUnknown {
        return Err(ParameterError::ConfigOptionUnknown);
    }
    Err(reason)
}

/// The per-line loop -- `src/tool_parsecfg.c:134-256`, plus the `fileerror`
/// fold of `:263-264`.
///
/// Folding the read error in here is behaviour-identical to C's placement after
/// the close: the loop condition is `!err && my_get_line(...)`, so a read error
/// can only be observed while `err` is still `PARAM_OK`, and closing a file
/// cannot change `err`.
fn parse_lines<H: ParseHost>(
    input: &mut dyn BufRead,
    filename: &mut Vec<u8>,
    max_recursive: i32,
    global: &mut GlobalConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    // `struct OperationConfig *config = global->last;` -- `:87`. C reads the
    // file-scope singleton `global` (`src/tool_cfgable.h:42`) there; AAP
    // section
    // 0.1.2 replaces that shared mutable state with explicit ownership, so the
    // value arrives as a parameter and C's `config` local is this crate's chain
    // cursor -- which is exactly what `crate::cli::args`'s `config_of`
    // normalises so that `getparameter` can be called by a configuration-file
    // reader.
    //
    // Positioned here rather than at `:87`'s line, deliberately: C's read is
    // pure, and every use of `config` (`:214`, `:215`, `:222-231`) is inside
    // `if(file)`. Moving the cursor before knowing a file opened would be a
    // mutation C has no counterpart for. This is also a precondition for the
    // first line dispatched -- `CmdKey::Url` reads the cursor directly
    // (`curl-rs/src/cli/args.rs:5143-5146`) rather than through `config_of`.
    global.chain.set_current(global.chain.last_index());

    // `:122-131` -- the two capped buffers. One `Vec` each, reused across
    // lines exactly as the C `dynbuf`s are.
    let mut buf: Vec<u8> = Vec::new();
    // `int lineno = 0;` -- `:125`.
    let mut lineno: i32 = 0;
    let mut err: Result<(), ParameterError> = Ok(());

    // `while(!err && my_get_line(file, &buf, &fileerror))` -- `:134`.
    while err.is_ok() {
        match my_get_line(input, &mut buf) {
            LineOutcome::Line => {}
            LineOutcome::Eof => break,
            // `if(fileerror) err = PARAM_READ_ERROR;` -- `:263-264`.
            LineOutcome::ReadError => {
                err = Err(ParameterError::ReadError);
                break;
            }
        }

        // `lineno++;` -- `:136`.
        //
        // It counts the lines `my_get_line` HANDED OUT, not the physical lines
        // of the file. The increment sits inside the loop, after the reader has
        // already skipped comments and blank lines at `:328-345`, so a `#`
        // comment or an empty line does not advance the number that the three
        // in-file messages report. That is surprising enough to be "fixed" into
        // a physical line count by someone reading the messages, which would be
        // a behaviour change; it is asserted by
        // `skipped_lines_do_not_advance_the_reported_line_number`.
        //
        // Saturating rather than wrapping: C's signed `int` overflow is
        // undefined, and a file with 2^31 significant lines is at least 2 GiB.
        lineno = lineno.saturating_add(1);

        // `:137-141` has no counterpart -- `curlx_dyn_ptr` returns `NULL` only
        // for a buffer that was never allocated, and `my_get_line` reports that
        // as no line rather than as a line whose pointer is absent. The split
        // borrows the buffer rather than copying out of it, which is C's
        // "we have a local copy of the data" (`:154`) without the copy.
        let res = match split_line(&buf) {
            Ok(directive) => {
                // `:175-179` and `:199-202`, in C's order: both warnings are
                // emitted during the split, ahead of `getparameter` at `:214`,
                // and a single line can earn both.
                let msgs = msg_config(global);
                if directive.leading_single_quote {
                    warn_argument(
                        sink,
                        &msgs,
                        filename,
                        lineno,
                        directive.option,
                        LEADING_SINGLE_QUOTE_TAIL,
                    );
                }
                if directive.unquoted_whitespace {
                    warn_argument(
                        sink,
                        &msgs,
                        filename,
                        lineno,
                        directive.option,
                        UNQUOTED_WHITESPACE_TAIL,
                    );
                }

                apply_directive(
                    &directive,
                    filename,
                    lineno,
                    max_recursive,
                    global,
                    host,
                    sink,
                )
            }
            // `err = PARAM_BAD_USE; break;` -- `:168-171`, which leaves the
            // loop rather than continuing to the next line.
            Err(reason) => {
                err = Err(reason);
                break;
            }
        };

        // C assigns `err = res` only inside `:253`, which the five help-ish
        // outcomes never reach; every other failure ends the loop.
        if let Err(reason) = res {
            if !matches!(
                reason,
                ParameterError::NextOperation
                    | ParameterError::HelpRequested
                    | ParameterError::ManualRequested
                    | ParameterError::VersionInfoRequested
                    | ParameterError::EnginesRequested
                    | ParameterError::CaEmbedRequested
            ) {
                err = Err(reason);
            }
        }
    }

    err
}

/// Reads a configuration file -- `parseconfig`,
/// `src/tool_parsecfg.c:81-279`. C's comment at `:80` reads "return 0 on
/// everything-is-fine, and non-zero otherwise".
///
/// `filename` is [`None`] for C's `NULL`, whose comment at `:91` reads "NULL
/// means load .curlrc from homedir!", `Some(b"-")` for standard input, and
/// otherwise the name to open. `resolved` is C's `char **resolved`: when
/// supplied, it receives the name actually read, which the default-`.curlrc`
/// caller uses to report the file it loaded (`src/tool_operate.c:2296`).
///
/// `global`, `host` and `sink` replace the file-scope singleton C reaches for;
/// see the module documentation.
///
/// # Errors
///
/// * [`ParameterError::ReadError`] -- no file could be opened (`:266-267`) or
///   a line exceeded [`MAX_CONFIG_LINE_LENGTH`] (`:263-264`). Both emit the
///   frozen `cannot read config from '%s'` (`:270`), except the unopenable
///   `.curlrc` of `:95-98`, which returns before that message because `:269`'s
///   guard is a non-`NULL` filename.
/// * [`ParameterError::BadUse`] -- a quoted argument could not be unquoted
///   (`:168-171`).
/// * whatever `getparameter` reported for a line, after the
///   [`ParameterError::OptionUnknown`] remap of `:251-252`.
///
/// Note that an absent `.curlrc` is [`ParameterError::ReadError`] and is not a
/// user-visible failure: `src/tool_operate.c:2279-2280` uses the result only to
/// decide whether to report which file was read.
#[allow(dead_code)] // The two call sites are `operate/`'s implicit `.curlrc`
                    // load and the `--config` case of `crate::cli::args`, whose
                    // host hook is the gap the module documentation reports.
pub(crate) fn parseconfig<H: ParseHost>(
    filename: Option<&[u8]>,
    max_recursive: i32,
    resolved: Option<&mut Option<PathBuf>>,
    global: &mut GlobalConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
) -> Result<(), ParameterError> {
    parseconfig_with(
        filename,
        max_recursive,
        resolved,
        global,
        host,
        sink,
        findfile,
    )
}

/// [`parseconfig`] with the `.curlrc` lookup supplied.
///
/// The seam exists for the same reason `crate::config::findfile`'s does: the
/// search reads `HOME` and the password database, and a test that mutated the
/// process environment to steer it would race every other test in the binary.
/// [`parseconfig`] is this function with `findfile`.
fn parseconfig_with<H, L>(
    filename: Option<&[u8]>,
    max_recursive: i32,
    resolved: Option<&mut Option<PathBuf>>,
    global: &mut GlobalConfig,
    host: &mut H,
    sink: &mut dyn DiagnosticSink,
    locate: L,
) -> Result<(), ParameterError>
where
    H: ParseHost,
    L: FnOnce(&OsStr, i32) -> Option<PathBuf>,
{
    // C's `filename` variable, which the error path may reassign to
    // `"<stdin>"`. `named` is `filename != NULL`, the guard at `:269`.
    let mut display: Vec<u8> = Vec::new();
    let mut named = false;
    let mut source: Option<ConfigSource> = None;

    match filename {
        // `:90-92` -- "NULL means load .curlrc from homedir!".
        None => {
            if let Some(curlrc) = locate(OsStr::new(".curlrc"), CURLRC_DOTSCORE)
            {
                // `:94-98` -- an unopenable `.curlrc` returns immediately, and
                // silently: `filename` is still `NULL` when `:269` tests it, so
                // no message is emitted on this path.
                let Ok(file) = File::open(&curlrc) else {
                    return Err(ParameterError::ReadError);
                };
                // `filename = pathalloc = curlrc;` -- `:99`.
                display = curlrc.into_os_string().into_vec();
                named = true;
                source = Some(ConfigSource::file(file));
            }
            // `:101-112` is `#ifdef _WIN32` and is deliberately absent; see the
            // module documentation and AAP section 0.2.2.
        }
        Some(name) => {
            // `:115-118`. The name is recorded either way, so an unopenable
            // file still reaches the message at `:269-270`.
            if name == b"-" {
                source = Some(ConfigSource::stdin());
            } else if let Ok(file) =
                File::open(Path::new(OsStr::from_bytes(name)))
            {
                source = Some(ConfigSource::file(file));
            }
            display = name.to_vec();
            named = true;
        }
    }

    // `if(file)` -- `:121`, with `:266-267` as its `else`.
    let err = match source {
        Some(mut source) => {
            // `DEBUGASSERT(filename);` -- `:132`. A debug assertion as C's is,
            // never a runtime panic: every path that produced a source above
            // also recorded a name.
            debug_assert!(named, "src/tool_parsecfg.c:132");
            parse_lines(
                source.reader(),
                &mut display,
                max_recursive,
                global,
                host,
                sink,
            )
            // `if(file != stdin) curlx_fclose(file);` -- `:259-260`. Dropping
            // the source here closes a file and leaves standard input open.
        }
        // `else err = PARAM_READ_ERROR;` -- `:266-267`, "could not open the
        // file".
        None => Err(ParameterError::ReadError),
    };

    // `if((err == PARAM_READ_ERROR) && filename)` -- `:269-270`. One message
    // for both causes, over the possibly-substituted name.
    if err == Err(ParameterError::ReadError) && named {
        let mut message = Vec::new();
        message.extend_from_slice(CANNOT_READ_HEAD.as_bytes());
        message.extend_from_slice(&display);
        message.push(b'\'');
        errorf_bytes(sink, &msg_config(global), &message);
    }

    // `if(!err && resolved)` -- `:272-276`. C's `:274-275` maps a failed
    // `curlx_strdup` to `PARAM_NO_MEM`; there is no counterpart because the
    // conversion below cannot fail.
    if err.is_ok() {
        if let Some(slot) = resolved {
            *slot = Some(PathBuf::from(OsString::from_vec(display)));
        }
    }

    // `curlx_free(pathalloc);` -- `:277`. Ownership performs it.
    err
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::paramhlp::{ByteSource, SeekSource};
    use crate::cli::vars::VarHost;
    use crate::output::formparse::StdinAccess;
    use crate::output::msgs::{ERROR_PREFIX, WARN_PREFIX};
    use std::fs;
    use std::io::Cursor;
    use tempfile::TempDir;

    /// A [`ParseHost`] that touches nothing outside itself.
    ///
    /// Modelled on the one in `curl-rs/src/main.rs:1712-1793`: every member
    /// answers the "nothing is there" case, so the tests below are independent
    /// of the machine they run on. [`FakeHost::configs`] records the recursive
    /// `--config` loads the parser forwarded, which is the hook the module
    /// documentation reports as unwired.
    #[derive(Debug, Default)]
    struct FakeHost {
        /// Every `(filename, budget)` a nested `--config` asked for.
        configs: Vec<(Vec<u8>, i32)>,
        /// Every `--help` category the parser forwarded.
        helped: Vec<Option<String>>,
    }

    impl VarHost for FakeHost {
        fn getenv(&self, _name: &[u8]) -> Option<Vec<u8>> {
            None
        }

        fn open(&mut self, _path: &[u8]) -> io::Result<Box<dyn ByteSource>> {
            Err(io::Error::other("no filesystem in this test"))
        }

        fn stdin(&mut self) -> Box<dyn ByteSource> {
            Box::new(SeekSource::new(Cursor::new(Vec::new())))
        }
    }

    impl StdinAccess for FakeHost {
        fn regular_extent(&mut self) -> Option<(i64, i64)> {
            None
        }

        fn read_all(&mut self, _out: &mut Vec<u8>) -> io::Result<()> {
            Ok(())
        }

        fn read_chunk(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn seek_to(&mut self, _offset: i64) -> io::Result<()> {
            Ok(())
        }
    }

    impl ParseHost for FakeHost {
        fn exists(&mut self, _path: &[u8]) -> bool {
            false
        }

        fn file_time(
            &mut self,
            _path: &[u8],
            _sink: &mut dyn DiagnosticSink,
            _msgs: &MsgConfig,
        ) -> Option<i64> {
            None
        }

        fn set_trace(&mut self, _config: &str) -> bool {
            true
        }

        fn set_stderr_file(&mut self, _path: &[u8], _msgs: &MsgConfig) {}

        fn help(
            &mut self,
            category: Option<&str>,
            _sink: &mut dyn DiagnosticSink,
            _msgs: &MsgConfig,
        ) {
            self.helped.push(category.map(str::to_owned));
        }

        fn parse_config(
            &mut self,
            filename: &[u8],
            max_recursive: i32,
            _sink: &mut dyn DiagnosticSink,
            _msgs: &MsgConfig,
        ) -> ParameterError {
            self.configs.push((filename.to_vec(), max_recursive));
            ParameterError::Ok
        }
    }

    /// A [`GlobalConfig`] and a capturing sink.
    ///
    /// `Vec<u8>` is a [`DiagnosticSink`] already
    /// (`curl-rs/src/output/msgs.rs:422`), so the diagnostics a test wants to
    /// inspect land in a buffer with no terminal and no file involved.
    /// Shaped as
    /// the one in `curl-rs/src/cli/args.rs:6466-6472`, and [`Option`] for the
    /// same reason: a test returns early rather than unwrapping, and
    /// [`the_fixture_is_available`] reports the condition once and loudly so
    /// nothing passes vacuously.
    fn fixture() -> Option<(GlobalConfig, Vec<u8>)> {
        let mut sink: Vec<u8> = Vec::new();
        let msgs = MsgConfig::new(false, false, false);
        GlobalConfig::init(&mut sink, &msgs)
            .ok()
            .map(|global| (global, sink))
    }

    /// One run of [`parse_lines`] over bytes held in memory.
    struct Run {
        /// What the loop returned.
        result: Result<(), ParameterError>,
        /// The configuration it built.
        global: GlobalConfig,
        /// Everything written to the diagnostic sink.
        written: Vec<u8>,
        /// The display name afterwards, which the error path may have replaced
        /// with [`STDIN_NAME`].
        shown: Vec<u8>,
        /// The host, with its record of forwarded calls.
        host: FakeHost,
    }

    /// Drives [`parse_lines`] over `text` as if it had been read from
    /// `filename`, with no filesystem and no process environment involved.
    fn run(filename: &[u8], text: &[u8]) -> Option<Run> {
        run_at(filename, text, false)
    }

    /// [`run`] with `--silent` already in force, so the gate of
    /// `src/tool_msgs.c:95` can be observed.
    fn run_silent(filename: &[u8], text: &[u8]) -> Option<Run> {
        run_at(filename, text, true)
    }

    /// [`run`] with the verbosity chosen by the caller.
    fn run_at(filename: &[u8], text: &[u8], silent: bool) -> Option<Run> {
        let (mut global, mut written) = fixture()?;
        global.silent = silent;
        let mut host = FakeHost::default();
        let mut input = Cursor::new(text.to_vec());
        let mut shown = filename.to_vec();

        let result = parse_lines(
            &mut input,
            &mut shown,
            crate::cli::args::CONFIG_MAX_LEVELS,
            &mut global,
            &mut host,
            &mut written,
        );

        Some(Run {
            result,
            global,
            written,
            shown,
            host,
        })
    }

    /// Every line [`my_get_line`] hands out, and the state it finished in.
    fn lines(text: &[u8]) -> (Vec<Vec<u8>>, LineOutcome) {
        let mut input = Cursor::new(text.to_vec());
        let mut buf = Vec::new();
        let mut out = Vec::new();
        loop {
            match my_get_line(&mut input, &mut buf) {
                LineOutcome::Line => out.push(buf.clone()),
                other => return (out, other),
            }
        }
    }

    /// The message bodies of one emission, with the repeated prefix removed.
    ///
    /// `voutf` wraps at the terminal width and re-emits the prefix on every
    /// wrapped line (`src/tool_msgs.c:49`), so a message longer than the
    /// terminal arrives in pieces. Reassembling is how
    /// `curl-rs/src/output/msgs.rs:1543-1553` asserts a full message, and the
    /// same route is taken here so that no test depends on the width of
    /// whatever terminal it runs under.
    fn reassemble(output: &[u8], prefix: &str) -> Vec<u8> {
        let mut joined = Vec::new();
        for line in output.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let body = line.strip_prefix(prefix.as_bytes()).unwrap_or(line);
            joined.extend_from_slice(body);
        }
        joined
    }

    /// The argument [`split_line`] found, for a line that splits cleanly.
    fn param_of(line: &[u8]) -> Option<Vec<u8>> {
        match split_line(line) {
            Ok(directive) => directive.param,
            Err(_) => None,
        }
    }

    /// The argument of a quoted line, which is where the escapes live.
    fn quoted(body: &[u8]) -> Option<Vec<u8>> {
        let mut line = b"opt \"".to_vec();
        line.extend_from_slice(body);
        line.push(b'"');
        param_of(&line)
    }

    #[test]
    fn the_fixture_is_available() {
        // Every test that needs a configuration returns early when this is not
        // so; asserting it here reports the condition once instead of letting
        // those tests pass vacuously.
        assert!(
            fixture().is_some(),
            "GlobalConfig::init must succeed for this reader to be testable"
        );
    }

    // The line readers -- `src/tool_parsecfg.c:281-347`

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        // `:334-342`: a `#` in the first non-blank column is a comment, an
        // empty line is skipped by `:341-342` and an all-blank line by `:338`.
        let (got, end) = lines(
            b"# a comment\n\
              \t  # indented, still a comment\n\
              \n\
              \t   \t\n\
              url one\n",
        );

        assert_eq!(got, vec![b"url one".to_vec()]);
        assert_eq!(end, LineOutcome::Eof);
    }

    #[test]
    fn a_line_of_only_a_carriage_return_is_not_blank() {
        // `ISBLANK` (`lib/curl_ctype.h:45`) is space and tab only, so `"\r"` is
        // not blank-only and `:338`'s test does not skip it.
        let (got, end) = lines(b"\r\n");

        assert_eq!(got, vec![b"\r".to_vec()]);
        assert_eq!(end, LineOutcome::Eof);
    }

    #[test]
    fn crlf_keeps_the_carriage_return_and_the_argument_stops_at_it() {
        // `:302-306` drops exactly the `'\n'`, so the `'\r'` reaches the
        // tokeniser, and `:181`'s `ISSPACE` -- "stop also on CRLF" -- ends the
        // argument on it without including it.
        let (got, _) = lines(b"url one\r\nurl two\r\n");
        assert_eq!(got, vec![b"url one\r".to_vec(), b"url two\r".to_vec()]);

        assert_eq!(param_of(b"url one\r").as_deref(), Some(&b"one"[..]));
    }

    #[test]
    fn a_final_line_without_a_newline_is_still_a_line() {
        // `:313-314` -- `fgets` gave nothing but the buffer holds something.
        let (got, end) = lines(b"url one\nurl two");
        assert_eq!(got, vec![b"url one".to_vec(), b"url two".to_vec()]);
        assert_eq!(end, LineOutcome::Eof);
    }

    #[test]
    fn a_line_longer_than_one_chunk_is_assembled() {
        // `:286-317` loops over `FGETS_BUFFER_SIZE`-byte reads, so a line
        // crossing the boundary must arrive whole.
        let long = vec![b'x'; FGETS_BUFFER_SIZE * 3 + 7];
        let mut text = b"url ".to_vec();
        text.extend_from_slice(&long);
        text.push(b'\n');

        let (got, end) = lines(&text);
        assert_eq!(got.len(), 1);
        assert_eq!(
            param_of(got.first().map_or(&[][..], Vec::as_slice)).as_deref(),
            Some(long.as_slice())
        );
        assert_eq!(end, LineOutcome::Eof);
    }

    #[test]
    fn an_embedded_zero_byte_truncates_the_chunk() {
        // `size_t rlen = strlen(b);` -- `:290`. C measures the chunk as a C
        // string, so the bytes behind an embedded zero are dropped from the
        // line and the read continues into the next physical line.
        let (got, end) = lines(b"url one\0dropped\nurl two\n");

        assert_eq!(got, vec![b"url oneurl two".to_vec()]);
        assert_eq!(end, LineOutcome::Eof);
    }

    #[test]
    fn a_chunk_beginning_with_a_zero_byte_ends_the_read() {
        // `if(!rlen) break;` -- `:292-293`, a different state from `fgets`
        // returning `NULL` at `:313-316`: the accumulated partial line is
        // discarded rather than returned.
        let (got, end) = lines(b"url one\n\0url two\n");

        assert_eq!(got, vec![b"url one".to_vec()]);
        assert_eq!(end, LineOutcome::Eof);
    }

    #[test]
    fn my_get_line_reports_three_distinguishable_states() {
        // The reason the third state exists: `:263-264` maps it to
        // `PARAM_READ_ERROR` while a clean end of input is success. This is
        // also how `crate::config::ssls` drives it -- `src/tool_ssls.c:80`,
        // one call per line with the buffer read after each.
        let mut input = Cursor::new(b"first\nsecond\n".to_vec());
        let mut buf = Vec::new();

        assert_eq!(my_get_line(&mut input, &mut buf), LineOutcome::Line);
        assert_eq!(buf, b"first");
        assert_eq!(my_get_line(&mut input, &mut buf), LineOutcome::Line);
        assert_eq!(buf, b"second");
        assert_eq!(my_get_line(&mut input, &mut buf), LineOutcome::Eof);

        // And the third is reachable and distinct.
        let mut over = Cursor::new(vec![b'x'; MAX_CONFIG_LINE_LENGTH]);
        assert_eq!(my_get_line(&mut over, &mut buf), LineOutcome::ReadError);
    }

    #[test]
    fn the_cap_is_the_measured_bound_rather_than_the_constant() {
        // `fit = len + idx + 1` with `if(fit > s->toobig)` --
        // `lib/curlx/dynbuf.c:72` and `:82`. The longest line accepted is
        // therefore one byte short of the constant.
        let mut buf = Vec::new();
        let widest = vec![b'a'; MAX_CONFIG_LINE_LENGTH - 1];
        assert_eq!(append(&mut buf, &widest), Ok(()));
        assert_eq!(buf.len(), MAX_CONFIG_LINE_LENGTH - 1);

        // One more byte pushes `fit` past the cap, and the failure releases the
        // buffer as `curlx_dyn_free` does at `:83`.
        assert_eq!(append(&mut buf, b"a"), Err(BufferFull));
        assert!(buf.is_empty());

        let mut exact = Vec::new();
        let at_cap = vec![b'a'; MAX_CONFIG_LINE_LENGTH];
        assert_eq!(append(&mut exact, &at_cap), Err(BufferFull));
    }

    // The tokeniser -- `src/tool_parsecfg.c:143-209`

    #[test]
    fn the_dash_prefix_is_what_disables_the_separators() {
        // `ISSEP(x, dash)` -- `:36`: "only acknowledge colon or equals as
        // separators if the option was not specified with an initial dash!"
        for line in [
            &b"url = x"[..],
            b"url: x",
            b"url=x",
            b"url:x",
            b"url x",
            b"url\tx",
        ] {
            let split = split_line(line);
            assert_eq!(
                split.as_ref().map(|found| found.option),
                Ok(&b"url"[..]),
                "{line:?}"
            );
            assert_eq!(param_of(line).as_deref(), Some(&b"x"[..]), "{line:?}");
        }

        // A dashed option keeps the `=` and everything after it, so the whole
        // word goes to the option lookup.
        let dashed = split_line(b"--url=x");
        assert_eq!(
            dashed.as_ref().map(|found| found.option),
            Ok(&b"--url=x"[..])
        );
        assert_eq!(param_of(b"--url=x"), None);

        // The same holds for a colon and for a single dash.
        assert_eq!(
            split_line(b"-url:x").as_ref().map(|found| found.option),
            Ok(&b"-url:x"[..])
        );
    }

    #[test]
    fn no_comment_syntax_beyond_the_hash_is_recognised() {
        // The only comment introducer is `'#'`, and only in the first non-blank
        // column of a line (`:337-338`) or after an argument (`:197`). Nothing
        // else is one, and a parser that accepted more would silently discard a
        // line curl applies -- including one that turns certificate
        // verification off.
        for line in [&b"; url x"[..], b"//url x", b"-- url x", b"' url x"] {
            let split = split_line(line);
            let option = split.as_ref().map(|found| found.option);
            assert_ne!(option, Ok(&b""[..]), "{line:?} must still tokenise");
            // The whole line was not thrown away: an option token was produced,
            // which `getparameter` then rejects as unknown.
            assert!(option.is_ok(), "{line:?}");
        }

        // A `'#'` inside the option word is an ordinary byte, not a comment:
        // the scan at `:149-150` stops only on a blank or a separator.
        assert_eq!(
            split_line(b"url#x").as_ref().map(|found| found.option),
            Ok(&b"url#x"[..])
        );

        // And a `'#'` that opens a line really is a comment, so the pair above
        // is a contrast rather than a vacuous assertion.
        let (got, _) = lines(b"#url x\n; url x\n");
        assert_eq!(got, vec![b"; url x".to_vec()]);
    }

    #[test]
    fn blanks_and_separators_are_skipped_together() {
        // `while(ISBLANK(*line) || ISSEP(*line, dashed_option)) line++;` --
        // `:161-162`, "pass spaces and separator(s)".
        for line in [&b"url : x"[..], b"url::x", b"url = = x", b"url \t : \t x"]
        {
            assert_eq!(param_of(line).as_deref(), Some(&b"x"[..]), "{line:?}");
        }
    }

    #[test]
    fn quoting_maps_exactly_the_four_escapes() {
        // `:53-68`. The mapped set is `\t`, `\n`, `\r` and `\v`; anything
        // else
        // takes C's `default:` arm and yields the byte after the backslash.
        assert_eq!(quoted(b"a b").as_deref(), Some(&b"a b"[..]));
        assert_eq!(quoted(br"a\tb").as_deref(), Some(&b"a\tb"[..]));
        assert_eq!(quoted(br"a\nb").as_deref(), Some(&b"a\nb"[..]));
        assert_eq!(quoted(br"a\rb").as_deref(), Some(&b"a\rb"[..]));
        assert_eq!(quoted(br"a\vb").as_deref(), Some(&b"a\x0bb"[..]));

        // `\"` and `\\` reach the same `default:` arm, which is what lets a
        // quoted argument hold a quote or a backslash at all.
        assert_eq!(quoted(br#"a\"b"#).as_deref(), Some(&b"a\"b"[..]));
        assert_eq!(quoted(br"a\\b").as_deref(), Some(&br"a\b"[..]));

        // And so does any other letter -- `\q` is `q`.
        assert_eq!(quoted(br"a\qb").as_deref(), Some(&b"aqb"[..]));

        // A trailing lone backslash ends the copy cleanly -- `:55-56`.
        let mut trailing = b"opt \"a".to_vec();
        trailing.push(b'\\');
        assert_eq!(param_of(&trailing).as_deref(), Some(&b"a"[..]));
    }

    #[test]
    fn no_escape_curl_does_not_have_is_invented() {
        // There is no `\a`, `\b`, `\f`, no octal and no hex escape. Asserted
        // explicitly so that nobody "adds the missing ones".
        assert_eq!(quoted(br"\a").as_deref(), Some(&b"a"[..]));
        assert_eq!(quoted(br"\b").as_deref(), Some(&b"b"[..]));
        assert_eq!(quoted(br"\f").as_deref(), Some(&b"f"[..]));
        assert_eq!(quoted(br"\x41").as_deref(), Some(&b"x41"[..]));
        assert_eq!(quoted(br"\101").as_deref(), Some(&b"101"[..]));
        assert_eq!(quoted(br"\0").as_deref(), Some(&b"0"[..]));
    }

    #[test]
    fn unslashquote_stops_at_the_first_unescaped_quote() {
        // `while(*line && (*line != '\"'))` -- `:48`. Everything after the
        // closing quote is discarded, including a trailing comment.
        assert_eq!(quoted(b"a\" trailing junk").as_deref(), Some(&b"a"[..]));

        let mut param = Vec::new();
        assert_eq!(unslashquote(b"kept\"dropped", &mut param), Ok(()));
        assert_eq!(param, b"kept");
    }

    #[test]
    fn an_empty_quoted_argument_is_an_empty_string() {
        // `:172` -- `curlx_dyn_len(&pbuf) ? curlx_dyn_ptr(&pbuf) : ""`. Both
        // arms are a string, so this is `Some`, never `None`. Half of the
        // asymmetry; the other half is the test below.
        let found = param_of(b"opt \"\"");
        assert_eq!(found.as_deref(), Some(&b""[..]));
        assert!(found.is_some());
    }

    #[test]
    fn an_empty_unquoted_argument_is_absent() {
        // `:205-208` -- "do this so getparameter can check for required
        // parameters. Otherwise it always thinks there is a parameter." The
        // deliberate disagreement with the quoted branch above.
        assert_eq!(param_of(b"opt"), None);
        assert_eq!(param_of(b"opt "), None);
        assert_eq!(param_of(b"opt = "), None);
        assert_eq!(param_of(b"opt\r"), None);

        // And the two are genuinely different values, not two spellings of one.
        assert_ne!(param_of(b"opt \"\""), param_of(b"opt"));
    }

    #[test]
    fn the_argument_stops_at_the_first_space_byte() {
        // `while(*line && !ISSPACE(*line))` -- `:181-182`. `ISSPACE`
        // (`lib/curl_ctype.h:46`) is `ISBLANK` plus `0x0a..=0x0d`.
        for terminator in [b' ', b'\t', b'\n', 0x0b, 0x0c, b'\r'] {
            let mut line = b"opt value".to_vec();
            line.push(terminator);
            line.extend_from_slice(b"more");
            assert_eq!(
                param_of(&line).as_deref(),
                Some(&b"value"[..]),
                "terminator {terminator:#04x}"
            );
        }
    }

    #[test]
    fn a_non_utf8_argument_survives_the_split() {
        // The tokeniser works on bytes, so an argument that is not valid UTF-8
        // reaches `getparameter` unchanged rather than being replaced or
        // rejected.
        assert_eq!(
            param_of(b"opt \xff\xfe\x80").as_deref(),
            Some(&b"\xff\xfe\x80"[..])
        );
        assert_eq!(
            quoted(b"\xc3\x28\xff").as_deref(),
            Some(&b"\xc3\x28\xff"[..])
        );
    }

    // The frozen messages -- `:176-178`, `:200-202`, `:249-250` and `:270`

    #[test]
    fn the_four_frozen_message_texts_are_the_c_texts() {
        // Transcribed from the C rather than from the constants, so this fails
        // if either side is edited.
        assert_eq!(
            format!("%s:%d {OPTION_HEAD}%s{LEADING_SINGLE_QUOTE_TAIL}"),
            "%s:%d Option '%s' uses argument with leading single quote. \
             It is probably a mistake. Consider double quotes."
        );
        assert_eq!(
            format!("%s:%d {OPTION_HEAD}%s{UNQUOTED_WHITESPACE_TAIL}"),
            "%s:%d Option '%s' uses argument with unquoted whitespace. \
             This may cause side-effects. Consider double quotes."
        );
        assert_eq!(
            format!("%s:%d {BAD_OPTION_HEAD}%s' %s"),
            "%s:%d config file option '%s' %s"
        );
        assert_eq!(
            format!("{CANNOT_READ_HEAD}%s'"),
            "cannot read config from '%s'"
        );

        // `voutf` asserts the format holds no newline (`src/tool_msgs.c:45`).
        for text in [
            OPTION_HEAD,
            LEADING_SINGLE_QUOTE_TAIL,
            UNQUOTED_WHITESPACE_TAIL,
            BAD_OPTION_HEAD,
            CANNOT_READ_HEAD,
            STDIN_NAME,
        ] {
            assert!(!text.contains('\n'), "{text}");
        }
    }

    #[test]
    fn the_location_prefix_is_the_one_based_line_number() {
        // `%s:%d ` with `lineno` starting at 1 -- `:125` and `:136`.
        assert_eq!(location(b"cfg", 1), b"cfg:1 ");
        assert_eq!(location(b"/etc/curlrc", 42), b"/etc/curlrc:42 ");
        // A filename that is not UTF-8 is carried through as its bytes.
        assert_eq!(location(b"\xff", 7), b"\xff:7 ");
    }

    #[test]
    fn the_leading_single_quote_warning_is_byte_exact() {
        // `:176-178`, with the filename, the 1-based line number and the option
        // name in that order.
        let Some(outcome) =
            run(b"/etc/curlrc", b"user-agent x\nurl 'http://example.com/'\n")
        else {
            return;
        };

        assert_eq!(outcome.result, Ok(()));
        assert_eq!(
            reassemble(&outcome.written, WARN_PREFIX),
            b"/etc/curlrc:2 Option 'url' uses argument with leading single \
              quote. It is probably a mistake. Consider double quotes."
        );
    }

    #[test]
    fn skipped_lines_do_not_advance_the_reported_line_number() {
        // `lineno++` at `:136` runs after `my_get_line` has already skipped
        // comments and blank lines at `:328-345`, so the number in a message
        // counts SIGNIFICANT lines rather than physical ones. Surprising, and
        // therefore asserted: turning it into a physical line count would be a
        // behaviour change.
        let Some(outcome) = run(
            b"cfg",
            b"# one\n\
              \n\
              \t \n\
              # two\n\
              url 'http://example.com/'\n",
        ) else {
            return;
        };

        // Physically the fifth line, reported as the first.
        assert!(
            reassemble(&outcome.written, WARN_PREFIX).starts_with(b"cfg:1 "),
            "five physical lines, one significant"
        );

        // And a significant line does advance it, so the counter is live.
        let Some(second) = run(
            b"cfg",
            b"user-agent x\n# skipped\nurl 'http://example.com/'\n",
        ) else {
            return;
        };
        assert!(
            reassemble(&second.written, WARN_PREFIX).starts_with(b"cfg:2 "),
            "the second significant line is line 2"
        );
    }

    #[test]
    fn the_unquoted_whitespace_warning_is_byte_exact() {
        // `:200-202`.
        let Some(outcome) = run(b"cfg", b"url http://a/ trailing\n") else {
            return;
        };

        assert_eq!(
            reassemble(&outcome.written, WARN_PREFIX),
            b"cfg:1 Option 'url' uses argument with unquoted whitespace. \
              This may cause side-effects. Consider double quotes."
        );
    }

    #[test]
    fn one_line_can_earn_both_argument_warnings_in_the_c_order() {
        // `:175-179` runs before the argument is scanned and `:199-202` after,
        // so a single-quoted argument holding a space earns both.
        let Some(outcome) = run(b"cfg", b"url 'http://a/ b'\n") else {
            return;
        };

        let joined = reassemble(&outcome.written, WARN_PREFIX);
        let leading = joined
            .windows(LEADING_SINGLE_QUOTE_TAIL.len())
            .position(|window| window == LEADING_SINGLE_QUOTE_TAIL.as_bytes());
        let unquoted = joined
            .windows(UNQUOTED_WHITESPACE_TAIL.len())
            .position(|window| window == UNQUOTED_WHITESPACE_TAIL.as_bytes());

        assert!(leading.is_some() && unquoted.is_some(), "both must appear");
        assert!(leading < unquoted, "the leading-quote warning comes first");
    }

    #[test]
    fn both_argument_warnings_are_suppressed_when_silent() {
        // `warnf`'s gate is `if(!global->silent)` -- `src/tool_msgs.c:95`. The
        // warnings go through that sink precisely so this holds.
        let Some(outcome) = run_silent(b"cfg", b"url 'http://a/ b'\n") else {
            return;
        };

        assert!(
            outcome.written.is_empty(),
            "silent must suppress both warnings"
        );
    }

    #[test]
    fn a_trailing_comment_does_not_warn_but_trailing_data_does() {
        // `:193-198` accepts `'\0'`, `'\r'`, `'\n'` and `'#'` in silence;
        // `:199-202` is everything else.
        for quiet in [
            &b"url http://a/ # a comment\n"[..],
            b"url http://a/#glued\n",
            b"url http://a/ \r\n",
            b"url http://a/ \n",
            b"url http://a/ ",
        ] {
            let Some(outcome) = run(b"cfg", quiet) else {
                return;
            };
            assert!(outcome.written.is_empty(), "{quiet:?} must not warn");
        }

        let Some(loud) = run(b"cfg", b"url http://a/ nope\n") else {
            return;
        };
        assert!(!loud.written.is_empty(), "trailing data must warn");
    }

    #[test]
    fn the_bad_option_error_is_byte_exact() {
        // `:249-250`, with the reason from `param2text`.
        let Some(outcome) = run(b"/etc/curlrc", b"bogus-option value\n") else {
            return;
        };

        assert_eq!(
            reassemble(&outcome.written, ERROR_PREFIX),
            b"/etc/curlrc:1 config file option 'bogus-option' is unknown"
        );
    }

    #[test]
    fn a_filename_of_one_dash_is_shown_as_stdin() {
        // `if(!strcmp(filename, "-")) filename = "<stdin>";` -- `:240-242`,
        // performed before the message is formatted.
        let Some(outcome) = run(b"-", b"bogus-option value\n") else {
            return;
        };

        assert_eq!(
            reassemble(&outcome.written, ERROR_PREFIX),
            b"<stdin>:1 config file option 'bogus-option' is unknown"
        );
        // C reassigns the variable rather than formatting a copy, so the
        // substitution outlives the line that caused it.
        assert_eq!(outcome.shown, STDIN_NAME.as_bytes());
    }

    #[test]
    fn an_unknown_option_is_remapped_after_the_message_is_formatted() {
        // `:251-252`. The order is observable: the text carries the reason for
        // `PARAM_OPTION_UNKNOWN` while the caller receives
        // `PARAM_CONFIG_OPTION_UNKNOWN`.
        let original = param2text(ParameterError::OptionUnknown);
        let remapped = param2text(ParameterError::ConfigOptionUnknown);
        assert_ne!(original, remapped, "the two reasons must differ");

        let Some(outcome) = run(b"cfg", b"bogus-option value\n") else {
            return;
        };

        assert_eq!(outcome.result, Err(ParameterError::ConfigOptionUnknown));
        let text = reassemble(&outcome.written, ERROR_PREFIX);
        assert!(
            text.ends_with(original.as_bytes()),
            "message keeps the original"
        );
        assert!(!text.ends_with(remapped.as_bytes()), "not the remapped one");
    }

    #[test]
    fn all_five_help_requests_produce_no_message_and_keep_their_code() {
        // `:243-247` -- "the help request is not really an error". Driven
        // through the reporter directly so that all five are covered, including
        // the two that no option can currently reach end to end; see
        // [`the_reachable_help_requests_do_not_stop_parsing`].
        let Some((global, mut written)) = fixture() else {
            return;
        };

        for reason in [
            ParameterError::HelpRequested,
            ParameterError::ManualRequested,
            ParameterError::VersionInfoRequested,
            ParameterError::EnginesRequested,
            ParameterError::CaEmbedRequested,
        ] {
            let mut shown = b"cfg".to_vec();
            let got = report_bad_option(
                reason,
                &mut shown,
                1,
                b"whatever",
                &global,
                &mut written,
            );

            assert_eq!(got, Err(reason), "{}", reason.c_name());
            assert!(written.is_empty(), "{} must be silent", reason.c_name());
        }

        // And the reporter does speak for a genuine failure, so the emptiness
        // above is the exclusion list at work rather than a mute sink.
        let mut shown = b"cfg".to_vec();
        let _ = report_bad_option(
            ParameterError::BadUse,
            &mut shown,
            1,
            b"whatever",
            &global,
            &mut written,
        );
        assert!(!written.is_empty());
    }

    #[test]
    fn the_reachable_help_requests_do_not_stop_parsing() {
        // The other half of `:243-247`: `err` is left untouched, so the lines
        // after the request are still read.
        //
        // Two of the five options are absent from this list on measured grounds
        // rather than by oversight. `--engine` is `ARG_STRG|ARG_TLS` and
        // `--dump-ca-embed` is `ARG_NONE|ARG_TLS` -- in the C table at
        // `src/tool_getparam.c:128` and in this port at
        // `curl-rs/src/cli/args.rs:1505-1510` and `:1514` -- so the gate at
        // `src/tool_getparam.c:2991-2994`, reproduced at
        // `curl-rs/src/cli/args.rs:5939-5941`, answers
        // `PARAM_LIBCURL_DOESNT_SUPPORT` while the library withholds `SSL`.
        // That is the option surface's behaviour and not this reader's; both
        // outcomes are exercised above regardless, and this list grows by two
        // when `feature_ssl()` becomes true.
        for option in ["help", "manual", "version"] {
            let mut text = option.as_bytes().to_vec();
            text.extend_from_slice(b"\nurl http://example.com/\n");

            let Some(outcome) = run(b"cfg", &text) else {
                return;
            };

            assert_eq!(outcome.result, Ok(()), "{option}");
            assert!(outcome.written.is_empty(), "{option} must be silent");

            let reached = outcome
                .global
                .chain
                .first()
                .and_then(|config| config.url_list.first())
                .and_then(|node| node.url.clone());
            assert_eq!(
                reached.as_deref(),
                Some(&b"http://example.com/"[..]),
                "{option} must not stop the read"
            );
        }
    }

    // Dispatch -- `:214-236`

    #[test]
    fn an_extra_parameter_needs_all_four_conditions() {
        // `if(!res && param && *param && !usedarg)` -- `:217-219`. `--silent`
        // is a boolean, so it never consumes an argument.
        let Some(outcome) = run(b"cfg", b"silent yes\n") else {
            return;
        };
        assert_eq!(outcome.result, Err(ParameterError::GotExtraParameter));
    }

    #[test]
    fn an_empty_string_argument_is_not_an_extra_parameter() {
        // The third condition is `*param`, and an empty string only reaches it
        // from the quoted branch of `:172`. This is the behavioural consequence
        // of the asymmetry, and the reason it cannot be collapsed.
        let Some(outcome) = run(b"cfg", b"silent \"\"\n") else {
            return;
        };
        assert_eq!(outcome.result, Ok(()));
        assert!(outcome.global.silent, "the option still applied");

        // The unquoted spelling gives no argument at all, so it also passes --
        // by the second condition rather than the third.
        let Some(bare) = run(b"cfg", b"silent\n") else {
            return;
        };
        assert_eq!(bare.result, Ok(()));
    }

    #[test]
    fn an_argument_that_is_used_is_not_extra() {
        let Some(outcome) = run(b"cfg", b"url http://example.com/\n") else {
            return;
        };
        assert_eq!(outcome.result, Ok(()));
        assert!(outcome.written.is_empty());
    }

    #[test]
    fn next_without_a_url_is_a_silent_no_op() {
        // `:221-236` is a plain `if` with no `else`. This is where the
        // configuration-file path and `parse_args` genuinely differ:
        // `src/tool_getparam.c:3106-3109` errors with `missing URL before
        // --next`, and this one does not.
        let Some(outcome) = run(b"cfg", b"next\nsilent\n") else {
            return;
        };

        assert_eq!(outcome.result, Ok(()));
        assert_eq!(outcome.global.chain.len(), 1, "no operation was appended");
        assert!(outcome.written.is_empty(), "and nothing was reported");
        assert!(
            outcome.global.silent,
            "parsing continued on the same config"
        );
    }

    #[test]
    fn next_with_a_url_appends_and_moves_the_cursor() {
        // `:222-231` -- the new operation is created and both `global->last`
        // and `config` move onto it.
        let Some(outcome) =
            run(b"cfg", b"url http://a/\nnext\nurl http://b/\n")
        else {
            return;
        };

        assert_eq!(outcome.result, Ok(()));
        assert_eq!(outcome.global.chain.len(), 2);
        assert_eq!(outcome.global.chain.current_index(), Some(1));

        let url_at = |at: usize| -> Option<Vec<u8>> {
            outcome
                .global
                .chain
                .get(at)
                .and_then(|config| config.url_list.first())
                .and_then(|node| node.url.clone())
        };
        assert_eq!(url_at(0).as_deref(), Some(&b"http://a/"[..]));
        assert_eq!(url_at(1).as_deref(), Some(&b"http://b/"[..]));
    }

    #[test]
    fn a_nested_config_line_is_forwarded_with_the_decremented_budget() {
        // `src/tool_getparam.c:2246-2252` -- `--config` decrements the budget
        // and re-enters this reader through the host hook the module
        // documentation reports as unwired. What is asserted here is the value
        // threaded to it, which is C's.
        let Some(outcome) = run(b"cfg", b"config /etc/other\n") else {
            return;
        };

        assert_eq!(outcome.result, Ok(()));
        assert_eq!(
            outcome.host.configs,
            vec![(
                b"/etc/other".to_vec(),
                crate::cli::args::CONFIG_MAX_LEVELS - 1
            )]
        );
    }

    #[test]
    fn a_line_over_the_cap_is_a_read_error_rather_than_a_truncation() {
        // `:296-300` sets the error flag and `:263-264` turns it into
        // `PARAM_READ_ERROR`. Nothing is silently shortened.
        let mut text = b"url ".to_vec();
        text.extend_from_slice(&vec![b'x'; MAX_CONFIG_LINE_LENGTH]);
        text.push(b'\n');

        let Some(outcome) = run(b"cfg", &text) else {
            return;
        };
        assert_eq!(outcome.result, Err(ParameterError::ReadError));
    }

    // `parseconfig` -- source selection, teardown and the resolved name

    /// [`parseconfig_with`] over a locator that answers with `found`.
    ///
    /// Nothing here reads `HOME` or the password database, so no test
    /// steers the
    /// search by mutating the process environment -- which would race every
    /// other test in the binary.
    fn read_config(
        filename: Option<&[u8]>,
        found: Option<PathBuf>,
    ) -> Option<(Result<(), ParameterError>, Option<PathBuf>, Vec<u8>)> {
        let (mut global, mut written) = fixture()?;
        let mut host = FakeHost::default();
        let mut resolved: Option<PathBuf> = None;

        let result = parseconfig_with(
            filename,
            crate::cli::args::CONFIG_MAX_LEVELS,
            Some(&mut resolved),
            &mut global,
            &mut host,
            &mut written,
            |_name, _dotscore| found,
        );

        Some((result, resolved, written))
    }

    #[test]
    fn the_default_load_asks_for_curlrc_with_the_dotscore_flag() {
        // `findfile(".curlrc", CURLRC_DOTSCORE)` -- `:92`.
        let Some((mut global, mut written)) = fixture() else {
            return;
        };
        let mut host = FakeHost::default();
        let mut asked: Option<(OsString, i32)> = None;

        let result = parseconfig_with(
            None,
            crate::cli::args::CONFIG_MAX_LEVELS,
            None,
            &mut global,
            &mut host,
            &mut written,
            |name, dotscore| {
                asked = Some((name.to_os_string(), dotscore));
                None
            },
        );

        assert_eq!(asked, Some((OsString::from(".curlrc"), CURLRC_DOTSCORE)));
        // `:266-267` with a `NULL` filename, so `:269`'s guard fails and no
        // message is emitted. `src/tool_operate.c:2279-2280` reads the result
        // only to decide whether to report the file it loaded.
        assert_eq!(result, Err(ParameterError::ReadError));
        assert!(written.is_empty(), "an absent .curlrc is not reported");
    }

    #[test]
    fn an_unopenable_curlrc_returns_without_a_message() {
        // `:94-98` returns before `:269`, whose guard is a non-`NULL` filename.
        let Some(home) = TempDir::new().ok() else {
            return;
        };
        let missing = home.path().join("never-created");

        let Some((result, resolved, written)) =
            read_config(None, Some(missing))
        else {
            return;
        };

        assert_eq!(result, Err(ParameterError::ReadError));
        assert_eq!(resolved, None);
        assert!(written.is_empty(), "this path is silent, unlike :269-270");
    }

    #[test]
    fn an_unopenable_named_file_reports_the_frozen_message() {
        // `:266-267` then `:269-270`, which is the half `curl -K /nope`
        // produces.
        let Some(dir) = TempDir::new().ok() else {
            return;
        };
        let missing = dir.path().join("nope.rc");
        let name = missing.as_os_str().as_bytes().to_vec();

        let Some((result, resolved, written)) = read_config(Some(&name), None)
        else {
            return;
        };

        assert_eq!(result, Err(ParameterError::ReadError));
        assert_eq!(resolved, None);

        let mut expected = CANNOT_READ_HEAD.as_bytes().to_vec();
        expected.extend_from_slice(&name);
        expected.push(b'\'');
        assert_eq!(reassemble(&written, ERROR_PREFIX), expected);
    }

    #[test]
    fn a_readable_file_is_applied_and_its_name_handed_back() {
        // `:272-276` -- the name the default-`.curlrc` caller reports at
        // `src/tool_operate.c:2296`.
        let Some(dir) = TempDir::new().ok() else {
            return;
        };
        let path = dir.path().join("curlrc");
        if fs::write(&path, b"# a comment\nsilent\nurl http://example.com/\n")
            .is_err()
        {
            return;
        }

        let Some((result, resolved, written)) =
            read_config(None, Some(path.clone()))
        else {
            return;
        };

        assert_eq!(result, Ok(()));
        assert_eq!(resolved.as_deref(), Some(path.as_path()));
        assert!(written.is_empty());
    }

    #[test]
    fn a_non_utf8_filename_round_trips_without_a_lossy_conversion() {
        // Both the name and the resolved value are bytes throughout; a
        // `Display`
        // route would substitute U+FFFD and change what the caller reports.
        let Some(dir) = TempDir::new().ok() else {
            return;
        };
        let mut raw = dir.path().as_os_str().as_bytes().to_vec();
        raw.extend_from_slice(b"/cfg-\xff\xfe");
        let path = PathBuf::from(OsStr::from_bytes(&raw));
        if fs::write(&path, b"silent\n").is_err() {
            return;
        }

        let Some((result, resolved, _)) = read_config(Some(&raw), None) else {
            return;
        };

        assert_eq!(result, Ok(()));
        assert_eq!(
            resolved.as_ref().map(|found| found.as_os_str().as_bytes()),
            Some(&raw[..])
        );
    }

    #[test]
    fn an_over_long_line_in_a_real_file_reports_the_frozen_message() {
        // The other cause of `:269-270`: the file opened but a line could not
        // be read (`:263-264`).
        let Some(dir) = TempDir::new().ok() else {
            return;
        };
        let path = dir.path().join("huge.rc");
        let mut body = b"url ".to_vec();
        body.extend_from_slice(&vec![b'x'; MAX_CONFIG_LINE_LENGTH]);
        body.push(b'\n');
        if fs::write(&path, &body).is_err() {
            return;
        }

        let name = path.as_os_str().as_bytes().to_vec();
        let Some((result, resolved, written)) = read_config(Some(&name), None)
        else {
            return;
        };

        assert_eq!(result, Err(ParameterError::ReadError));
        assert_eq!(resolved, None);

        let mut expected = CANNOT_READ_HEAD.as_bytes().to_vec();
        expected.extend_from_slice(&name);
        expected.push(b'\'');
        assert_eq!(reassemble(&written, ERROR_PREFIX), expected);
    }

    #[test]
    fn a_bad_quoted_argument_ends_the_read_with_bad_use() {
        // `:168-171`. Only an oversized or unallocatable output can produce it,
        // so it is driven through `unslashquote` directly as well as asserted
        // to be the code the reader adopts.
        let mut param = Vec::new();
        let over = vec![b'x'; MAX_CONFIG_LINE_LENGTH];
        assert_eq!(unslashquote(&over, &mut param), Err(BufferFull));

        let mut line = b"url \"".to_vec();
        line.extend_from_slice(&over);
        assert_eq!(split_line(&line).err(), Some(ParameterError::BadUse));
    }

    #[test]
    fn selecting_standard_input_never_closes_it() {
        // `if(file != stdin) curlx_fclose(file);` -- `:259-260`. The design
        // cannot close descriptor 0 because it never owns it: the variant holds
        // a borrowed `StdinLock`, whose drop releases only the lock.
        let descriptor = Path::new("/proc/self/fd/0");
        let observable = descriptor.symlink_metadata().is_ok();

        for _ in 0..3 {
            let mut source = ConfigSource::stdin();
            assert!(matches!(source, ConfigSource::Stdin(_)));
            // Reaching the reader is what a real read would do first.
            let _ = source.reader();
            drop(source);
        }

        // Had the drop closed it, the descriptor's entry would be gone. Guarded
        // because only one of the two mandated operating systems has `/proc`.
        if observable {
            assert!(
                descriptor.symlink_metadata().is_ok(),
                "descriptor 0 must survive -- src/tool_parsecfg.c:259-260"
            );
        }
    }

    #[test]
    fn a_named_file_is_closed_by_its_own_drop() {
        // The other half of `:259-260`: a file source owns its handle.
        let Some(dir) = TempDir::new().ok() else {
            return;
        };
        let path = dir.path().join("closed.rc");
        if fs::write(&path, b"silent\n").is_err() {
            return;
        }

        let Some(file) = File::open(&path).ok() else {
            return;
        };
        let source = ConfigSource::file(file);
        assert!(matches!(source, ConfigSource::File(_)));
        drop(source);

        // Re-opening proves nothing was left in a state that prevents it, and
        // the handle is gone with the value.
        assert!(File::open(&path).is_ok());
    }
}
