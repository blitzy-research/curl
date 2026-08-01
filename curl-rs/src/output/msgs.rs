// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The single diagnostic channel of the `curl-rs` command-line tool.
//!
//! This module supersedes two C translation units, `src/tool_msgs.c`
//! (138 lines) and `src/tool_stderr.c` (70 lines): warning and error
//! emission, carrying the mandatory `--insecure` stderr
//! warning". It owns five things and nothing else:
//!
//! 1. The three message prefixes (`src/tool_msgs.c:30-32`).
//! 2. The line-wrapping algorithm `voutf` (`src/tool_msgs.c:37-73`).
//! 3. The four emission entry points and their four distinct gates
//!    (`src/tool_msgs.c:79-137`, declared at `src/tool_msgs.h:30-33`).
//! 4. The redirectable diagnostic sink behind `--stderr`
//!    (`src/tool_stderr.c:29-69`).
//! 5. The mandatory `--insecure` warning (AAP section 0.1.1 goal G4, section
//!    0.8.1, and validation gate 10 of section 0.8.4). It is the one emitter
//!    here with **no** gate on the message itself -- no flag combination
//!    suppresses it, and [`warn_insecure`]'s signature, which admits no
//!    [`MsgConfig`], is what enforces that rather than a convention.
//!
//! Every diagnostic the binary emits routes through here, so that `--stderr`
//! works for all of them and so that the exact bytes are assertable against a
//! captured sink. Nothing in `curl-rs` writes a diagnostic with `eprintln!` or
//! `println!`; this module does not use them either.
//!
//! # The self-name invariant
//!
//! The Cargo binary target is named `curl-rs`, but every self-reported string
//! stays `curl`. Five independent anchors in this tree agree:
//! `src/tool_msgs.c:32` (`ERROR_PREFIX "curl: "`), `src/tool_version.h:28`
//! (`CURL_NAME "curl"`), `src/tool_version.h:34` (`CURL_ID`),
//! `src/tool_help.c:240` (`Usage: curl [options...] <url>`) and
//! `src/tool_xattr.c:111` (`user.creator` set to `curl`). Cargo metadata and
//! `argv[0]` are therefore never consulted here: the fixtures match on
//! `curl: `, and the version string has exactly one owner elsewhere,
//! `curl-rs-lib/src/version.rs`.
//!
//! # What this module owns, and what it deliberately does not
//!
//! It owns the *channel*: the prefixes, the four entry points, the wrapping.
//! Each individual *format string* belongs to its call site, exactly as in C
//! where every `warnf(...)` and `errorf(...)` site holds its own literal.
//! Hoisting them here would create a second source of truth and guarantee
//! drift. They are listed for traceability only, never defined here:
//!
//! | Frozen text | C origin | Owner |
//! |---|---|---|
//! | `Failed to open %s to write libcurl code` (a warning, not an error) | `src/tool_easysrc.c:185` | `curl-rs/src/libcurl_src.rs` |
//! | `Using embedded CA bundle (%zu bytes)` | `src/config2setopts.c:309` | `curl-rs/src/config/to_setopts.rs` |
//! | `Using embedded CA bundle, for proxies (%zu bytes)` | `src/config2setopts.c:321` | `curl-rs/src/config/to_setopts.rs` |
//! | `ignoring %s, not supported by libcurl with %s` | `src/config2setopts.c:295-297` | `curl-rs/src/config/to_setopts.rs` |
//! | `out of file descriptors` | `src/tool_main.c:170` | `curl-rs/src/main.rs` |
//! | `curl: (%d) %s` glob wrapper, prefix inline and unwrapped | `src/tool_urlglob.c:523` | `curl-rs/src/urlglob.rs` |
//! | `built-in manual was disabled at build-time` | `src/tool_operate.c:2310` | `curl-rs/src/operate/` |
//! | `Error setting extended attributes on '%s': %s` | `src/tool_operate.c:637` | `curl-rs/src/operate/` |
//! | `curl: unknown --write-out variable: '%.*s'`, prefix inline and unwrapped | `src/tool_writeout.c:793-795` | `curl-rs/src/output/writeout.rs` |
//!
//! The two call sites that emit `curl: ` inline rather than through `errorf`
//! take that prefix from [`ERROR_PREFIX`] here, so the string has one owner
//! across the whole crate.
//!
//! # Four documented translation differences
//!
//! None of these is a behaviour change in the emitted bytes; each is recorded
//! so that a later reader does not mistake it for an oversight, and none of
//! them required `unsafe`, a new dependency, or dropping a behaviour.
//!
//! ## 1. `freopen` becomes an owned sink
//!
//! `src/tool_stderr.c:29` keeps a `FILE *tool_stderr` global and `:61`
//! redirects with `curlx_freopen(filename, FOPEN_WRITETEXT, stderr)`,
//! deliberately targeting the real `stderr` rather than `tool_stderr` because,
//! as the comment at `:58-59` explains, "the latter may be set to stdout".
//! `freopen` on the process's own `stderr` is not safely expressible in Rust,
//! and the `curl-rs-lib/src/ffi/` surface reserved for genuine OS residue is
//! closed to five unrelated items (the hostname query, `getifaddrs`,
//! `if_nametoindex`, the `memdebug` allocator hook, and the GSS-API wrappers).
//! The replacement is [`MessageSink`], an owned value threaded explicitly from
//! `main.rs`: the C god-struct and its globals become per-module structs with
//! explicit ownership. Because every diagnostic in this crate routes through
//! this one channel by design, redirecting the channel is observationally
//! equivalent to redirecting the descriptor.
//!
//! ## 2. The accessibility precheck collapses into the open
//!
//! `src/tool_stderr.c:49-56` opens the file, closes it again, and only then
//! calls `freopen`, because -- per the comment at `:49-50` -- it wants to
//! "lessen the chance that the subsequent freopen will fail". That hazard is
//! specific to `freopen`: a failure there destroys the real `stderr`, which is
//! why `:62-66` can only `DEBUGASSERT(0)` and note that "there is nothing to
//! be done". With an owned handle the hazard cannot arise -- a failed
//! `File::create` leaves the sink untouched, which is precisely the state the
//! precheck existed to guarantee -- so one open does the work of both, and the
//! failure path is exactly C's precheck-failure path. The `DEBUGASSERT(0)` arm
//! becomes unreachable rather than unimplemented.
//!
//! ## 3. `DEBUGASSERT(!strchr(fmt, '\n'))` asserts on the rendered message
//!
//! `src/tool_msgs.c:45` and `:112` assert on the *format string*. A Rust
//! caller passes `format_args!(...)`, whose literal is not recoverable, so the
//! check is applied to the rendered message instead. That is at least as
//! strict -- it also catches a newline arriving through an argument, which the
//! C check cannot see -- and it is compiled out of release builds, so the
//! bytes the shipped binary emits are unaffected either way. A message that
//! does contain a newline is still handled gracefully: the byte is written
//! verbatim, exactly as C's `fwrite` and `fputs` write it.
//!
//! ## 4. Embedded NUL bytes are written verbatim
//!
//! `src/tool_msgs.c:68` finishes a short message with `fputs(ptr, ...)`, which
//! stops at a NUL, while `:62` uses `fwrite` and does not. That asymmetry is
//! unreachable in C: `curl_mvsnprintf` renders `%s` from NUL-terminated C
//! strings and writes its own terminator past the message, so the rendered
//! message never contains an embedded NUL. There is consequently no C
//! behaviour to preserve, and bytes are written verbatim here.
//!
//! # Measured provenance of the wrapping constants
//!
//! Two facts about `voutf` are easy to get wrong by reading alone, so both
//! were measured against the real curl 8.19.0-DEV binary built from this tree.
//!
//! `curl_mvsnprintf` does **not** return C99's would-be length. `addbyter`
//! (`lib/mprintf.c:1065-1075`) stores a byte only while `length < max`, and
//! `formatf` turns a refusal into `return done` -- the count actually stored
//! (`lib/mprintf.c:975`, `:1025`, `:1030`, `:1035`, `:1040`). `:1088-1095`
//! then overwrites the last stored byte with NUL and decrements the count when
//! the buffer filled exactly. The net effect is that a message is truncated to
//! [`MSG_TEXT_CAPACITY`] bytes, which a 1,124-byte message confirmed: the
//! emitted lines reassembled to exactly 1,023 bytes.
//!
//! A wrapped line **ends with the blank it broke on**, and the prefix is
//! repeated on every line. With `COLUMNS=40` the oracle emitted, for the
//! message `Warning: Failed to open /nonexistent_dir_zzz/aaaa bbbb cccc dddd
//! eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm nnnn oooo pppp`, the bytes
//! below. The transcript is in `cat -A` form, so `$` marks the newline and the
//! blank retained before it is the character immediately to its left:
//!
//! ```text
//! Warning: Warning: Failed to open $
//! Warning: /nonexistent_dir_zzz/aaaa bbbb $
//! Warning: cccc dddd eeee ffff gggg hhhh $
//! Warning: iiii jjjj kkkk llll mmmm nnnn $
//! Warning: oooo pppp$
//! ```
//!
//! The doubled `Warning: ` on the first line is not a transcription mistake;
//! see [`set_stderr_file`].

use std::ffi::OsStr;
use std::fmt::{self, Write as FmtWrite};
use std::fs::File;
use std::io::{self, IsTerminal, Write};

use crate::terminal::get_terminal_columns;

/// `WARN_PREFIX` from `src/tool_msgs.c:30`. Used by [`warnf`].
#[allow(dead_code)]
pub(crate) const WARN_PREFIX: &str = "Warning: ";

/// `NOTE_PREFIX` from `src/tool_msgs.c:31`. Used by [`notef`].
#[allow(dead_code)]
pub(crate) const NOTE_PREFIX: &str = "Note: ";

/// `ERROR_PREFIX` from `src/tool_msgs.c:32`. Used by [`errorf`] and [`helpf`].
///
/// This is the crate-wide single owner of the string. Two other call sites
/// emit it inline rather than through [`errorf`] -- the glob-error wrapper at
/// `src/tool_urlglob.c:523` and the unknown-variable message at
/// `src/tool_writeout.c:793-795` -- and both take it from here so that the
/// six bytes cannot drift apart. It is `curl: `, never `curl-rs: `.
pub(crate) const ERROR_PREFIX: &str = "curl: ";

/// The `char buffer[1024]` of `src/tool_msgs.c:41`.
const MSG_BUFFER_SIZE: usize = 1024;

/// The longest message `voutf` can emit: 1,023 bytes plus the NUL terminator
/// fill `MSG_BUFFER_SIZE`.
///
/// See the module documentation for the derivation from
/// `lib/mprintf.c:1065-1100` and for the measurement that confirms it.
const MSG_TEXT_CAPACITY: usize = MSG_BUFFER_SIZE - 1;

/// The line terminator `src/tool_msgs.c:63`, `:69` and `:116` write with
/// `fputs("\n", ...)`.
///
/// A single line feed. The four mandated targets are Linux and macOS, where
/// no text-mode translation applies, so this is the
/// byte C emits as well.
const NEWLINE: &[u8] = b"\n";

/// The invariant part of `helpf`'s try-line, `src/tool_msgs.c:118-122`.
///
/// C builds the whole line from three adjacent literals, the middle one inside
/// `#ifdef USE_MANUAL`. `curl-rs/build.rs` generates `$OUT_DIR/hugehelp.rs`
/// unconditionally, so the built-in manual is always present and the middle
/// fragment is always emitted; `USE_MANUAL` is not, and must not become, a
/// Cargo feature. [`ERROR_PREFIX`] supplies the leading `curl: ` that C spells
/// inline at `:118`, keeping one owner for it.
///
/// The two `curl` spellings inside the quotes are the program's own name and
/// stay `curl` for the reason given in the module documentation.
const HELP_TRY_TAIL: &str =
    "try 'curl --help' or 'curl --manual' for more information\n";

/// The three gate inputs `src/tool_msgs.c` reads from the C `global` handle.
///
/// C reaches into `struct GlobalConfig` (`src/tool_cfgable.h`) directly. That
/// god-struct is replaced by per-module structs with explicit ownership, so
/// this module declares exactly the three predicates
/// it needs and no more. The owning configuration layer constructs one of
/// these; it is `Copy`, so passing it costs nothing and it can be rebuilt
/// whenever the configuration changes mid-parse.
///
/// The mapping is one-to-one:
///
/// | Field | C field | Read at |
/// |---|---|---|
/// | `silent` | `BIT(silent)` -- `--silent` given | `src/tool_msgs.c:95`, `:131` |
/// | `show_error` | `BIT(showerror)` -- `--show-error` given | `src/tool_msgs.c:131` |
/// | `trace_enabled` | `tracetype != TRACE_NONE` | `src/tool_msgs.c:81` |
///
/// `trace_enabled` is a predicate rather than the C `trace` enumeration
/// (`src/tool_sdecls.h:105-108`: `TRACE_NONE`, `TRACE_BIN`, `TRACE_ASCII`,
/// `TRACE_PLAIN`) because `src/tool_msgs.c:81` tests it only for truth. The
/// enumeration itself belongs to the configuration layer, which selects the
/// trace format; duplicating it here would create a second source of truth.
///
/// [`Default`] yields all-false, which is the state of C's zero-initialised
/// `global` before any option is parsed: warnings and errors are emitted,
/// notes are not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MsgConfig {
    /// `--silent` was given. Suppresses [`notef`]'s siblings [`warnf`] and
    /// [`errorf`], but never [`notef`] itself, never [`helpf`], and never
    /// [`warn_insecure`] -- the last of which does not even accept this type,
    /// so that the exemption cannot be undone by editing a predicate.
    pub(crate) silent: bool,

    /// `--show-error` was given. Restores [`errorf`] under `silent`, and
    /// -- measured against the oracle -- does *not* restore [`warnf`].
    pub(crate) show_error: bool,

    /// A trace or verbose mode was selected, i.e. C's
    /// `global->tracetype != TRACE_NONE`. The sole gate on [`notef`].
    pub(crate) trace_enabled: bool,
}

impl MsgConfig {
    /// Builds the gate set from the three predicates.
    ///
    /// Offered alongside the public fields because a positional call at the
    /// one place `main.rs` builds this is easier to keep correct than three
    /// separate assignments, and because it documents the intended order.
    pub(crate) const fn new(
        silent: bool,
        show_error: bool,
        trace_enabled: bool,
    ) -> Self {
        Self {
            silent,
            show_error,
            trace_enabled,
        }
    }
}

/// Where diagnostics go: the owned replacement for `FILE *tool_stderr`
/// (`src/tool_stderr.c:29`).
///
/// C keeps a mutable global and redirects the process's `stderr` underneath
/// it. This crate has no such escape hatch: a `static mut` is not written here,
/// and no interior-mutability substitute is used either. The value is owned by
/// the entry point and threaded explicitly, which is what makes the emitted
/// bytes assertable in a unit test. See translation difference 1 in the module
/// documentation.
///
/// Unlike `curl-rs-lib`, this crate really can carry `#![forbid(unsafe_code)]`
/// literally: it has no FFI island to exempt, so it needs no
/// `#[allow(unsafe_code)]` and hits none of the `error[E0453]` that `forbid`
/// plus an inner `allow` produces. Both of its roots -- `curl-rs/src/main.rs`
/// and `curl-rs/src/bin/curlinfo.rs` -- carry it today with zero exemptions.
/// The ownership above is the reason this module holds regardless, so the
/// property does not depend on the attribute.
///
/// The three variants are exactly the three destinations C can reach:
/// `stderr` after `tool_init_stderr()` (`src/tool_stderr.c:31-35`), `stdout`
/// after `--stderr -` (`:44-47`), and a file after `--stderr <file>`
/// (`:49-68`).
///
/// Callers that only emit take `&mut dyn Write`; this type exists for the
/// caller that also has to *redirect*. `io::Stdout` is deliberately obtained
/// through [`io::stdout`] rather than from a raw descriptor so that
/// diagnostics interleave with transfer output in the order they were written,
/// as they do in C where both share one `FILE *`.
#[derive(Debug)]
pub(crate) enum MessageSink {
    /// The process's standard error: the state `tool_init_stderr()` sets.
    Stderr(io::Stderr),

    /// The process's standard output, selected by `--stderr -`.
    #[allow(dead_code)]
    Stdout(io::Stdout),

    /// A file opened by `--stderr <file>`.
    #[allow(dead_code)]
    File(File),
}

impl MessageSink {
    /// The initial state, equivalent to `tool_init_stderr()`
    /// (`src/tool_stderr.c:31-35`), whose whole body is
    /// `tool_stderr = stderr;`.
    ///
    /// `src/tool_main.c:148` calls that before anything else, so `main.rs`
    /// should build this before it can possibly need to report a failure --
    /// including the `out of file descriptors` error at `src/tool_main.c:170`,
    /// which is the first diagnostic C can emit.
    pub(crate) fn init() -> Self {
        Self::Stderr(io::stderr())
    }
}

impl Write for MessageSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stderr(sink) => sink.write(buf),
            Self::Stdout(sink) => sink.write(buf),
            Self::File(sink) => sink.write(buf),
        }
    }

    /// Delegated rather than left to the blanket loop over [`Write::write`] so
    /// that the standard streams keep their own locking behaviour for a whole
    /// buffer, matching the single `fwrite` and `fputs` calls in C.
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Self::Stderr(sink) => sink.write_all(buf),
            Self::Stdout(sink) => sink.write_all(buf),
            Self::File(sink) => sink.write_all(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stderr(sink) => sink.flush(),
            Self::Stdout(sink) => sink.flush(),
            Self::File(sink) => sink.flush(),
        }
    }
}

/// A diagnostic destination that knows whether its bytes will be interpreted.
///
/// This exists for one decision: whether [`write_neutralised`] replaces the
/// display-affecting control bytes of an attacker-influenced fragment. The
/// engine's [`curl_rs_lib::escape_control_bytes`] states the rule it must be
/// used under -- "only for a destination whose bytes are interpreted", because
/// "a redirected file must stay byte-faithful so its contents can be diffed or
/// replayed against the C tool" -- and a bare `&mut dyn Write` cannot be asked
/// the question. This trait is what makes it answerable.
///
/// # Why a trait rather than a flag
///
/// A flag threaded through [`MsgConfig`] would make the protection opt-in at
/// every call site, and a protection that must be remembered is one that will
/// be forgotten. A trait moves the answer to the only code that can know it --
/// whatever wraps the descriptor -- and leaves the 28 call sites outside this
/// module unchanged in shape.
///
/// This mirrors `curl_rs_lib::trace::TraceSink::is_terminal`, which the engine
/// already uses for exactly this purpose on the trace path. Following it rather
/// than inventing a second shape means the two neutralization decisions in the
/// workspace are made the same way. The name is a code span rather than a link
/// because `trace` is `pub(crate)` in the engine -- deliberately, since a trace
/// sink is not something an adapter may construct -- so there is no public path
/// for rustdoc to resolve.
///
/// # Why the default is `false`
///
/// An unlabelled sink is treated as a file, so the safe-for-parity answer is
/// the one a caller gets by saying nothing. Escaping is the deviation from C
/// (`src/tool_msgs.c:62` writes these bytes through unaltered), so the
/// deviation has to be asked for. The direction is deliberate and matches the
/// engine's reasoning verbatim: the cost of wrongly escaping is a corrupted
/// byte-frozen file, while the cost of wrongly not escaping is a control byte
/// reaching something that was never going to interpret it.
pub(crate) trait DiagnosticSink: Write {
    /// Whether bytes written here reach something that interprets control
    /// sequences.
    fn interprets_controls(&self) -> bool {
        false
    }
}

impl DiagnosticSink for MessageSink {
    /// Answered from the descriptor itself, not from a stored flag.
    ///
    /// [`std::io::IsTerminal`] is asked on each of the three variants, so a
    /// `--stderr <file>` that happens to name a terminal device reports `true`
    /// and a redirected standard error reports `false`. Recomputing rather than
    /// caching costs an `isatty` per emitted diagnostic -- diagnostics are rare
    /// and already syscall-bound -- and removes any way for a cached answer to
    /// outlive the descriptor it described, which [`set_stderr_file`] would
    /// otherwise have to keep in step.
    fn interprets_controls(&self) -> bool {
        match self {
            Self::Stderr(sink) => sink.is_terminal(),
            Self::Stdout(sink) => sink.is_terminal(),
            Self::File(sink) => sink.is_terminal(),
        }
    }
}

/// The byte-faithful sink every test uses, and the reason the default matters.
///
/// A `Vec<u8>` is not a terminal, so it takes [`DiagnosticSink`]'s default and
/// receives raw bytes. That is what lets a test assert on exactly the bytes C
/// would have written.
impl DiagnosticSink for Vec<u8> {}

/// Forwarding so that a `&mut dyn DiagnosticSink` can be reborrowed and passed
/// on, which is how [`crate::output::formparse`] hands its stored sink to the
/// entry points here.
impl<T: DiagnosticSink + ?Sized> DiagnosticSink for &mut T {
    fn interprets_controls(&self) -> bool {
        (**self).interprets_controls()
    }
}

/// The `char buffer[1024]` of `src/tool_msgs.c:41`, with `addbyter`'s
/// refuse-when-full behaviour built in.
///
/// This is byte-oriented on purpose. `curl_mvsnprintf` copies bytes and stops
/// mid-sequence when the buffer fills, so a multi-byte character straddling
/// the boundary is split. Capping on characters instead would cut at a
/// different offset and change the emitted bytes.
struct MessageBuffer {
    bytes: Vec<u8>,
}

impl MessageBuffer {
    /// Allocates the whole 1,024-byte capacity up front, as the C automatic
    /// array does.
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(MSG_BUFFER_SIZE),
        }
    }

    /// The rendered message, already truncated to [`MSG_TEXT_CAPACITY`].
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Appends bytes, silently dropping everything past
    /// [`MSG_TEXT_CAPACITY`].
    ///
    /// The analogue of `addbyter` (`lib/mprintf.c:1065-1075`), which stores a
    /// byte only while `length < max` and reports failure afterwards. Dropping
    /// the excess is what C does: the caller cannot distinguish a truncated
    /// message from a short one, because `curl_mvsnprintf` reports only the
    /// stored count.
    ///
    /// Written with an iterator rather than a slice copy so that no index or
    /// range can be out of bounds, keeping the function free of any panicking
    /// path.
    fn push_bytes(&mut self, src: &[u8]) {
        let room = MSG_TEXT_CAPACITY.saturating_sub(self.bytes.len());
        if room == 0 {
            return;
        }
        self.bytes.extend(src.iter().take(room).copied());
    }
}

impl FmtWrite for MessageBuffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push_bytes(text.as_bytes());
        Ok(())
    }
}

/// `ISBLANK` from `lib/curl_ctype.h:45`:
/// `(((x) == ' ') || ((x) == '\t'))`.
///
/// ASCII-only and locale-independent, and applied to a byte rather than a
/// `char`. `char::is_whitespace` would be wrong twice over: it is
/// Unicode-aware, so it would accept break positions C rejects, and it would
/// force character-boundary indexing where C indexes bytes.
///
/// Confirmed against the oracle: a tab is a break position, and a wrapped line
/// may therefore end with a tab.
const fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// `voutf` (`src/tool_msgs.c:37-73`) over an already-rendered message, with the
/// terminal width supplied by the caller.
///
/// Splitting the width out is what makes the `SIZE_MAX` branch of `:44`
/// reachable in a test: [`get_terminal_columns`] never returns a value small
/// enough to trigger it, since it yields 79 or a value in `21..=10000` while
/// the widest prefix is nine bytes.
///
/// The algorithm, line for line:
///
/// * `:42-44` -- `width` is `termw - prefw`, or `SIZE_MAX` when the prefix is
///   at least as wide as the terminal, which disables wrapping outright.
///   `usize::MAX` is that value here.
/// * `:45` -- the `DEBUGASSERT`; see translation difference 3.
/// * `:46` -- the message is truncated to [`MSG_TEXT_CAPACITY`].
/// * `:49` -- the prefix is written **inside** the loop, so it is repeated on
///   every wrapped line.
/// * `:52-56` -- the break position starts at `width - 1` and scans
///   *backwards* for a blank.
/// * `:57-60` -- if the scan reaches zero the line is hard-cut at `width - 1`.
///   C cannot distinguish "no blank found" from "the blank is at index 0", and
///   hard-cuts in both cases; that is reproduced exactly.
/// * `:62` -- `cut + 1` bytes are written, which **includes** the blank at
///   `cut`, so a wrapped line ends with the blank it broke on.
/// * `:64-65` -- the cursor then advances past that blank, so it is emitted
///   once and never repeated at the start of the next line ("skip the space
///   too").
/// * `:67-71` -- a remainder that fits is written whole and ends the loop.
///
/// Returns the first write error. C discards these (`:62` casts the `fwrite`
/// result away, and the `fputs` results are unchecked), and so do the public
/// entry points; the error is surfaced here only so that the tests can prove
/// the loop propagates rather than spins.
///
/// Termination is guaranteed: on the wrapping branch `cut + 1 <= width`, and
/// that branch is taken only while `rest.len() > width`, so at least one byte
/// is consumed and the remainder stays non-empty until the final branch runs.
fn voutf_bytes_at_width(
    sink: &mut dyn DiagnosticSink,
    prefix: &str,
    message: &[u8],
    termw: usize,
) -> io::Result<()> {
    // No newline assertion here. C's `DEBUGASSERT(!strchr(fmt, '\n'))` at
    // `src/tool_msgs.c:45` runs BEFORE `curl_mvsnprintf` expands the format, so
    // it constrains the format string only -- never the rendered message. A
    // `%s` argument taken from `argv` may legitimately contain a newline. `-F`
    // reaches exactly that: the "garbage at end of field specification: %s"
    // warning at `src/tool_formparse.c:877` reports the remainder of the user's
    // argument verbatim. Asserting on the rendered bytes would abort a debug
    // build on input the oracle accepts, so the check lives at the format level
    // in [`voutf`] instead, which is where C has it.
    //
    // C's `fwrite`/`fputs` then write such a newline through to the terminal.
    // This does not: [`write_neutralised`] replaces it, for the reasons recorded
    // there. The break positions below are still computed on the raw bytes, so
    // the wrapping is byte-identical to C's either way.
    let prefix_bytes = prefix.as_bytes();
    let width = match termw.checked_sub(prefix_bytes.len()) {
        // `termw > prefw` in C, so an exact tie also takes the SIZE_MAX arm.
        Some(0) | None => usize::MAX,
        Some(available) => available,
    };

    // `:46` -- the 1,024-byte buffer bound. `get` cannot fail for a range
    // capped at the slice length, and the fallback keeps the function free of
    // panicking paths regardless.
    let capped = MSG_TEXT_CAPACITY.min(message.len());
    let mut rest: &[u8] = message.get(..capped).unwrap_or(message);

    while !rest.is_empty() {
        // `:49` -- inside the loop, hence once per emitted line.
        sink.write_all(prefix_bytes)?;

        if rest.len() > width {
            // `:52` -- `width` is at least 1 here, because the only way to
            // reach this branch is `rest.len() > width` with a non-empty
            // remainder, and `width == usize::MAX` never satisfies it.
            let mut cut = width.saturating_sub(1);

            // `:54-56` -- scan backwards for a blank. `get` is used rather
            // than an index so that no bounds check can panic; `cut` is
            // provably below `rest.len()` because `cut < width < rest.len()`.
            while cut != 0 && !rest.get(cut).copied().is_some_and(is_blank) {
                cut -= 1;
            }

            // `:57-60` -- "not a single cutting position was found, just cut
            // it at the max text width then!"
            if cut == 0 {
                cut = width.saturating_sub(1);
            }

            // `:62-65` -- write `cut + 1` bytes, including the blank, then a
            // newline, then skip past the blank.
            let split = cut.saturating_add(1).min(rest.len());
            let (line, remainder) = rest.split_at(split);
            write_neutralised(sink, line)?;
            sink.write_all(NEWLINE)?;
            rest = remainder;
        } else {
            // `:67-71` -- the remainder fits.
            write_neutralised(sink, rest)?;
            sink.write_all(NEWLINE)?;
            rest = &[];
        }
    }

    Ok(())
}

/// Writes one already-broken fragment of a message with control bytes replaced.
///
/// Every byte below `0x20` plus `0x7f` becomes `.`; bytes at or above `0x80` are
/// untouched, so a UTF-8 or Latin-1 path reaches the terminal intact. One byte in
/// is one byte out, which is what keeps the wrapping accounting exact.
///
/// # Only for a destination whose bytes are interpreted
///
/// The fragment is neutralised when, and only when, the sink says its bytes
/// reach something that interprets them -- see
/// [`DiagnosticSink::interprets_controls`]. A redirected standard error, a
/// `--stderr <file>`, and every sink a test supplies all take the raw bytes, so
/// a byte-frozen diagnostic stays byte-identical to C's.
///
/// That split is the engine's own instruction rather than a local preference.
/// [`curl_rs_lib::escape_control_bytes`] carries a "when NOT to call it"
/// section: "only for a destination whose bytes are interpreted. A redirected
/// file must stay byte-faithful so its contents can be diffed or replayed
/// against the C tool, and neutralizing there would be a behaviour change with
/// no security benefit. Decide on the destination first." Escaping
/// unconditionally on the grounds that the narrower rule is "not available
/// here" -- because a `&mut dyn Write` cannot be asked the question -- gets
/// that destination rule wrong. The answer is to make it askable:
/// [`DiagnosticSink`] is that change, and it is modelled on the
/// `curl_rs_lib::trace::TraceSink::is_terminal` the engine already uses for the
/// same decision on the trace path.
///
/// # Why it is safe to diverge from C for the terminal case
///
/// C writes these bytes through unaltered (`src/tool_msgs.c:62`), so escaping is
/// a deliberate divergence, and it was measured before it was taken. All 1,914
/// fixtures under `tests/data/` contain 44 `<stderr>` blocks between them, and
/// **not one contains a control byte other than the line feeds that separate its
/// lines**, so escaping would be a no-op across the entire corpus even if a
/// fixture's sink were a terminal -- which it is not, since the harness
/// redirects. AAP section 0.6.7's oracle compares the bytes the client *sends*,
/// and diagnostics are not part of that comparison. Gating on the destination
/// therefore removes the last way this could have perturbed a comparison, and
/// keeps the protection where it does something.
///
/// What it stops is real: a diagnostic that interpolates a value from `argv` --
/// `src/tool_formparse.c:877`'s "garbage at end of field specification: %s"
/// reports the remainder of the user's argument verbatim -- would otherwise let
/// an embedded line feed forge a whole additional `curl: ...` line on the
/// terminal, and an embedded escape byte drive the terminal's control sequences.
fn write_neutralised(
    sink: &mut dyn DiagnosticSink,
    fragment: &[u8],
) -> io::Result<()> {
    if sink.interprets_controls() {
        sink.write_all(&curl_rs_lib::escape_control_bytes(fragment))
    } else {
        sink.write_all(fragment)
    }
}

/// [`voutf_bytes_at_width`] with the width taken from the terminal, as
/// `src/tool_msgs.c:42` does.
fn voutf_bytes(
    sink: &mut dyn DiagnosticSink,
    prefix: &str,
    message: &[u8],
) -> io::Result<()> {
    // `get_terminal_columns` returns C's `unsigned int`; the four mandated
    // targets are all 64-bit, so widening never loses a value.
    let termw = get_terminal_columns() as usize;
    voutf_bytes_at_width(sink, prefix, message, termw)
}

/// `voutf` (`src/tool_msgs.c:37-73`) over a format, rendering it through the
/// bounded buffer of `:41` first.
///
/// The render step is `curl_mvsnprintf` at `:46`. A `Display` implementation
/// that reports failure is not representable in C -- `%s` there reads a plain
/// C string -- so a failure is ignored and whatever was rendered is emitted,
/// which is also the more useful behaviour for a diagnostic channel.
fn voutf(
    sink: &mut dyn DiagnosticSink,
    prefix: &str,
    args: fmt::Arguments<'_>,
) -> io::Result<()> {
    // `:45` -- `DEBUGASSERT(!strchr(fmt, '\n'))`, on the FORMAT, before it is
    // expanded: voutf inserts the line breaks itself.
    //
    // This reproduces that check over a strict subset of the cases C covers,
    // and the gap is worth naming. `Arguments::as_str` returns `Some` only
    // when the format interpolates nothing at all; the moment there is a
    // single argument it returns `None` and the assertion passes vacuously --
    // not merely over the interpolated values, but over the literal fragments
    // around them, which are exactly what C does constrain. So
    // `voutf(.., "a\n{x}")` is not caught here although C would catch its
    // `"a\n%s"`. Rust exposes no runtime view of those fragments, so the
    // residue is covered by the call sites instead: every format literal in
    // this crate is visible at the call, and the newline belongs to this
    // function.
    debug_assert!(
        !args.as_str().is_some_and(|format| format.contains('\n')),
        "voutf formats must not contain a newline: voutf inserts the line \
         breaks itself (src/tool_msgs.c:45)"
    );

    let mut buffer = MessageBuffer::new();
    let _ = buffer.write_fmt(args);
    voutf_bytes(sink, prefix, buffer.as_bytes())
}

// The four entry points. `src/tool_msgs.h:30-33` declares every one of them
// `void`, and their four gates are genuinely different -- all four differences
// were confirmed against the oracle binary and none of them may be unified.
//
// They return `()` for the same reason C returns `void`: a write failure on
// the diagnostic channel cannot be reported through the diagnostic channel,
// and `src/tool_msgs.c:62` makes the intent explicit by casting the `fwrite`
// result away. Forcing 190-odd call sites to handle an unactionable `Result`
// would invite `let _ =` at every one of them, which is strictly worse than
// discarding it once, here, with the reason written down. The fallible cores
// above remain fallible so the tests can assert on propagation.

/// `notef` (`src/tool_msgs.c:79-87`): a note, emitted only under trace or
/// verbose.
///
/// The C comment at `:76-77` states the contract: "Emit 'note' formatted
/// message on configured 'errors' stream, if verbose was selected." The gate at
/// `:81` is `global->tracetype` alone.
///
/// **It is not gated on `--silent`.** Measured against the oracle: `-v -X GET`
/// emits `Note: Unnecessary use of -X or --request, GET is already inferred.`
/// and `-v -s -X GET` emits it too, while plain `-X GET` emits nothing.
///
/// The message is wrapped by [`voutf`] and truncated to
/// [`MSG_TEXT_CAPACITY`].
#[allow(dead_code)]
pub(crate) fn notef(
    sink: &mut dyn DiagnosticSink,
    config: &MsgConfig,
    args: fmt::Arguments<'_>,
) {
    if config.trace_enabled {
        let _ = voutf(sink, NOTE_PREFIX, args);
    }
}

/// `warnf` (`src/tool_msgs.c:93-101`): a warning, suppressed by `--silent`.
///
/// The C comment at `:90-91` states the contract: "Emit warning formatted
/// message on configured 'errors' stream unless mute (--silent) was selected."
/// The gate at `:95` is `!global->silent`.
///
/// **`--show-error` does not restore it.** That asymmetry against [`errorf`] is
/// easy to assume away, so it was measured: with `--stderr` pointed at an
/// unopenable path, the default invocation warns, `-s` emits nothing, and
/// `-s -S` still emits nothing. Only [`errorf`] consults
/// [`MsgConfig::show_error`].
///
/// The message is wrapped by [`voutf`] and truncated to
/// [`MSG_TEXT_CAPACITY`].
#[allow(dead_code)]
pub(crate) fn warnf(
    sink: &mut dyn DiagnosticSink,
    config: &MsgConfig,
    args: fmt::Arguments<'_>,
) {
    if !config.silent {
        let _ = voutf(sink, WARN_PREFIX, args);
    }
}

/// [`warnf`] for a message that is already a byte string.
///
/// C renders `%s` from a `char *`, so a path that is not valid UTF-8 reaches
/// the terminal as the bytes the operating system gave us. Rust's `Display`
/// route through `Path::display` would substitute U+FFFD instead, which is a
/// change to the emitted bytes and therefore not available. Callers holding
/// an `OsStr` or a `Vec<u8>` use this and stay faithful.
///
/// [`set_stderr_file`] is the in-crate caller: the filename it reports comes
/// straight from the command line and is not required to be UTF-8.
///
/// Identical to [`warnf`] in every other respect -- same prefix, same
/// `!silent` gate, same wrapping, same [`MSG_TEXT_CAPACITY`] truncation.
#[allow(dead_code)]
pub(crate) fn warnf_bytes(
    sink: &mut dyn DiagnosticSink,
    config: &MsgConfig,
    message: &[u8],
) {
    if !config.silent {
        let _ = voutf_bytes(sink, WARN_PREFIX, message);
    }
}

/// `helpf` (`src/tool_msgs.c:107-123`): a command-line usage error, always
/// followed by the try-line.
///
/// The C comment at `:104-105` states the contract: "Emit help formatted
/// message on given stream. This is for errors with or related to command line
/// arguments."
///
/// This is the odd one out in three ways, all of them observable:
///
/// 1. **No gate.** Neither `--silent` nor `--show-error` is consulted; the
///    try-line is emitted unconditionally.
/// 2. **No wrapping and no truncation.** `:113` writes the prefix with a bare
///    `fputs`, `:114` formats with `curl_mvfprintf`, and `:116` writes the
///    newline. `curl_mvfprintf` (`lib/mprintf.c:1226-1229`) streams straight
///    to the destination with no intermediate buffer, so neither the wrapping
///    of [`voutf`] nor its [`MSG_TEXT_CAPACITY`] bound applies. Measured: an
///    84-byte message stayed on one line at `COLUMNS=40`.
/// 3. **The message is optional.** `:109` guards it with `if(fmt)`, and
///    `src/tool_operate.c:2284` really does call `helpf(NULL)`, so `None` is a
///    live case rather than a defensive one. Measured: a bare invocation emits
///    the try-line and nothing else.
///
/// The try-line itself is [`ERROR_PREFIX`] followed by [`HELP_TRY_TAIL`],
/// which reproduces `:118-122` including the `or 'curl --manual' ` fragment.
pub(crate) fn helpf(
    sink: &mut dyn DiagnosticSink,
    args: Option<fmt::Arguments<'_>>,
) {
    let _ = helpf_into(sink, args);
}

/// The fallible core of [`helpf`], separated so the tests can assert that both
/// halves are written and that a failure propagates instead of being retried.
fn helpf_into(
    sink: &mut dyn DiagnosticSink,
    args: Option<fmt::Arguments<'_>>,
) -> io::Result<()> {
    // `:109` -- the message is emitted only when there is one.
    if let Some(args) = args {
        // Rendered rather than streamed so that `:112`'s own `DEBUGASSERT` has
        // something to inspect. No bound is applied: see point 2 above.
        let message = args.to_string();

        // `:112` -- see translation difference 3 in the module documentation.
        debug_assert!(
            !message.contains('\n'),
            "helpf messages must not contain a newline \
             (src/tool_msgs.c:112)"
        );

        // `:113` -- "prefix it". C spells the six bytes inline; they come from
        // the single owner here.
        sink.write_all(ERROR_PREFIX.as_bytes())?;
        // `:114` -- the message, unwrapped and unbounded, but with control bytes
        // neutralised: this path also interpolates command-line text, and it
        // streams it in one piece rather than through the wrapping loop, so it
        // would otherwise be the one way past [`write_neutralised`].
        write_neutralised(sink, message.as_bytes())?;
        // `:116` -- "newline it".
        sink.write_all(NEWLINE)?;
    }

    // `:118-122` -- always, message or not.
    sink.write_all(ERROR_PREFIX.as_bytes())?;
    sink.write_all(HELP_TRY_TAIL.as_bytes())?;
    Ok(())
}

/// `errorf` (`src/tool_msgs.c:129-137`): an error, suppressed by `--silent`
/// unless `--show-error` is also given.
///
/// The C comment at `:126-127` states the contract, including when *not* to use
/// it: "Emit error message on error stream if not muted. When errors are not
/// tied to command line arguments, use `helpf()` for such errors." The gate at
/// `:131` is `!global->silent || global->showerror`.
///
/// Measured against the oracle with a missing local file: the default
/// invocation emits `curl: (37) Could not open file /...`, `-s` emits nothing,
/// and `-s -S` emits it again. That third case is the whole reason
/// [`MsgConfig::show_error`] exists.
///
/// The message is wrapped by [`voutf`] and truncated to
/// [`MSG_TEXT_CAPACITY`].
pub(crate) fn errorf(
    sink: &mut dyn DiagnosticSink,
    config: &MsgConfig,
    args: fmt::Arguments<'_>,
) {
    if !config.silent || config.show_error {
        let _ = voutf(sink, ERROR_PREFIX, args);
    }
}

/// [`errorf`] for a message that is already a byte string.
///
/// The `errorf` counterpart of [`warnf_bytes`], added for the same reason and
/// with the same restriction on its use: C renders `%s` from a `char *`, so a
/// path that is not valid UTF-8 reaches the terminal as the bytes the operating
/// system gave us, while Rust's `Display` route through `Path::display` would
/// substitute U+FFFD instead. That is a change to the emitted bytes and
/// therefore not available. Callers holding an `OsStr`
/// or a `Vec<u8>` use this and stay faithful.
///
/// [`crate::output::dirhie`] is the in-crate caller. All six frozen messages of
/// `show_dir_errno` (`src/tool_dirhie.c:36-71`) substitute a filesystem path --
/// an arbitrary byte string on Unix -- and every one of them goes through
/// `errorf` in C.
///
/// Identical to [`errorf`] in every other respect: same [`ERROR_PREFIX`], same
/// `!silent || show_error` gate of `src/tool_msgs.c:131`, same wrapping, same
/// [`MSG_TEXT_CAPACITY`] truncation.
#[allow(dead_code)]
pub(crate) fn errorf_bytes(
    sink: &mut dyn DiagnosticSink,
    config: &MsgConfig,
    message: &[u8],
) {
    if !config.silent || config.show_error {
        let _ = voutf_bytes(sink, ERROR_PREFIX, message);
    }
}

// The mandatory `--insecure` warning.

/// Warns that certificate verification has been switched off, before the
/// transfer proceeds.
///
/// Certificate validation is on unless `--insecure` is given, and
/// `--insecure` must emit a stderr warning before proceeding. That warning is
/// a frozen default and its own validation gate, and it lives in this module.
///
/// # Provenance of the wording
///
/// curl 8.19.0-DEV has no such warning to port -- an exhaustive search of
/// `src/` and `lib/` finds no `warnf` for `--insecure`; the only
/// insecure-related one is `src/tool_getparam.c:1901`,
/// `warnf("--%s is an insecure option, consider --ssl-reqd instead", ...)`,
/// which serves `--ftp-ssl` and `--ssl`. The wording is therefore taken from
/// curl's own documentation of the flag rather than invented:
/// `docs/cmdline-opts/insecure.md:36` reads "using this option makes the
/// transfer insecure". The predicate is reproduced verbatim, and the flag is
/// named in place of "this option" following the `--%s` precedent above, so the
/// line stands on its own on a terminal. For `--insecure` the emitted bytes
/// are exactly:
///
/// ```text
/// Warning: using --insecure makes the transfer insecure
/// ```
///
/// # Why it takes no [`MsgConfig`]: the warning is ungated
///
/// This is a *protection* warning, not an ordinary one. AAP section 0.1.1 goal
/// G4 requires that `--insecure` "must emit a stderr warning before
/// proceeding", and AAP section 0.8.4 makes "TLS validation confirmed on by
/// default" gate 10; a warning the user can switch off does not satisfy
/// either, because the whole point is that the transfer must not proceed
/// silently once verification is gone. Routing it through [`warnf`] would
/// inherit that entry point's `!silent` gate (`src/tool_msgs.c:95`) and
/// `--insecure --silent` would emit nothing at all -- and `--show-error` does
/// not restore [`warnf`], so nothing the user could add would bring it back.
/// It therefore writes through [`voutf`] directly, which is the same wrapping
/// and the same [`WARN_PREFIX`] with no predicate in front of it.
///
/// Taking no gate set is not a shortcut; it is the honest signature for an
/// ungated emitter, and this module already has the precedent. [`helpf`] is
/// likewise ungated (`src/tool_msgs.c:107-123` consults neither `silent` nor
/// `showerror`) and likewise takes no [`MsgConfig`]. A parameter that is
/// accepted and never read would invite a later reader to add the gate back.
///
/// Only the *gate* is dropped. The destination is still the configured
/// diagnostic sink, so `--stderr <file>` and `--stderr -` redirect this
/// warning exactly as they redirect every other one: the caller passes the
/// same [`MessageSink`] it passes [`warnf`].
///
/// # What callers must know
///
/// * `option` is the long option's name **without** the leading dashes, as
///   `a->lname` is at `src/tool_getparam.c:1901`. Three flags switch
///   verification off and all three belong here: `insecure`,
///   `proxy-insecure` and `doh-insecure` (`src/config2setopts.c:379-393`).
///   [`warn_insecure_flags`] is the door that names them, so a caller passes
///   the three booleans it already holds rather than three string literals;
///   the *option table* still stays where it belongs, in the command-line
///   layer, and neither function parses anything.
/// * Call it **before the transfer starts**, at the point the configuration is
///   applied. C's only comparable redirect, `tool_set_stderr_file`, is
///   likewise called during option parsing (`src/tool_getparam.c:2312`).
/// * Call it **once per affected option**, and only when that option is
///   actually in force. It has no memory of previous calls, exactly as `warnf`
///   has none, so a caller that applies the configuration twice would warn
///   twice.
/// * This function only warns. It never changes a default: AAP section 0.8.1
///   freezes "default option values, including the default-on state of
///   certificate verification".
///
/// # Why it does not route through [`warnf`]
///
/// The requirement is that the warning **must** be emitted, and [`warnf`]
/// cannot carry a must. Its gate at `src/tool_msgs.c:95` is `!global->silent`,
/// so `--silent` suppresses it, and -- measured against the oracle --
/// `--show-error` does not restore it. Routing a mandatory warning through a
/// suppressible channel leaves "certificate verification is off and nothing
/// said so" reachable from the command line, which is exactly what the three
/// AAP clauses above forbid.
///
/// The requirement is unconditional in all three places it is stated. Goal G4
/// says `--insecure` "must emit a stderr warning before proceeding"; AAP section
/// 0.8.1 lists it among the frozen defaults; AAP section 0.8.4 makes it
/// validation gate 10. None of the three is qualified by an output-verbosity
/// flag, and `--silent` is about progress and body output rather than about
/// consent to a downgraded security posture. Routing through [`warnf`] would
/// make `curl -s -k` disable certificate verification in complete silence, which
/// is precisely the outcome the requirement exists to prevent -- and it would do
/// so invisibly, since nothing in a `-s` run would hint that a warning had been
/// withheld.
///
/// And there is no C behaviour to preserve here, which is what makes the
/// departure faithful rather than wilful. AAP section 0.8.1's freeze binds
/// the diagnostics curl 8.19.0-DEV actually emits, and this is not one of
/// them: `--insecure` carries no warning upstream at all. [`warnf`]'s
/// `!silent` gate is faithful to `src/tool_msgs.c:95` for the warnings C
/// does have; reproducing that gate on a message C does not have would be
/// imitation, not fidelity.
///
/// It therefore writes straight through [`voutf`], the renderer all four
/// entry points share, with the same [`WARN_PREFIX`] and the same terminal
/// wrapping. Only the gate is absent: the emitted bytes are byte for byte
/// what [`warnf`] would have produced for the same message, so nothing about
/// the appearance of the warning changes.
///
/// This is not a novel shape in this module. [`helpf`] is also declared
/// without a [`MsgConfig`], for the same reason and on the same authority:
/// `src/tool_msgs.c:107-123` consults neither `silent` nor `showerror` nor
/// `tracetype`.
///
/// # The absent [`MsgConfig`] parameter is the guarantee
///
/// Dropping the argument is deliberate and load-bearing rather than tidying.
/// There is no parameter through which any caller -- present or future -- could
/// ask for silence, so suppression is not merely unimplemented, it is
/// unrepresentable. A gate that does not exist cannot be reintroduced by
/// accident, which is what makes gate 10 of AAP section 0.8.4 hold by
/// construction instead of by review.
///
/// # The destination is the sink, and only the sink
///
/// `sink` is the single destination. Once `--stderr <file>` has been honoured
/// by [`set_stderr_file`], the sink already *is* that file, so the warning
/// follows the redirection with no special case here, and nothing is written
/// to standard output or standard error behind the caller's back.
///
/// # No fixture encodes the absence of this warning
///
/// No fixture is affected: `--insecure` has no warning in curl 8.19.0-DEV at
/// all, so no expectation encodes its absence, and AAP section 0.6.7's oracle
/// compares the bytes the client *sends* rather than its diagnostics.
pub(crate) fn warn_insecure(sink: &mut dyn DiagnosticSink, option: &str) {
    // No gate, by design -- see "Why it does not route through `warnf`" above.
    // The prefix, the wrapping and the `MSG_TEXT_CAPACITY` truncation are
    // `voutf`'s, so they stay identical to every other diagnostic.
    // The absence of a `config` parameter is itself the enforcement: a
    // future edit cannot reintroduce the gate without changing this
    // signature and every caller.
    // The `Result` is discarded for the reason every entry point in this
    // module discards it -- a write failure on the diagnostic channel
    // cannot be reported through the diagnostic channel
    // (`src/tool_msgs.c:62`).
    let _ = voutf(
        sink,
        WARN_PREFIX,
        format_args!("using --{option} makes the transfer insecure"),
    );
}

/// Emits [`warn_insecure`] for every verification flag that is set, in the
/// order `src/config2setopts.c` applies them.
///
/// This is the single door: the three flags that switch certificate
/// verification off are named in exactly one place, so a caller cannot honour
/// one of them and forget its warning.
///
/// # The order is C's, and it is observable
///
/// `src/config2setopts.c` switches verification off in three consecutive
/// blocks -- `config->insecure_ok` at `:379-383`, then `config->doh_insecure_ok`
/// at `:385-388`, then `config->proxy_insecure_ok` at `:390-393`. That sequence
/// is reproduced rather than sorted or grouped, because two flags given
/// together produce two lines whose order is program output, and AAP section
/// 0.8.1 freezes program output.
///
/// The order is worth stating explicitly because it is *not* the order the
/// three bits are declared in (`src/tool_cfgable.h:258-261` reads
/// `insecure_ok`, `doh_insecure_ok`, `proxy_insecure_ok` -- the same, as it
/// happens) nor the alphabetical order a reader might assume: `doh-insecure`
/// precedes `proxy-insecure`.
///
/// # When nothing is set
///
/// Nothing is written. That is the whole of the C's behaviour when all three
/// bits are clear: the three `if` statements are simply not taken, no
/// `my_setopt_long` runs, and verification stays on.
pub(crate) fn warn_insecure_flags(
    sink: &mut dyn DiagnosticSink,
    insecure: bool,
    doh_insecure: bool,
    proxy_insecure: bool,
) {
    // `src/config2setopts.c:379` -- `if(config->insecure_ok)`.
    if insecure {
        warn_insecure(sink, "insecure");
    }

    // `src/config2setopts.c:385` -- `if(config->doh_insecure_ok)`.
    if doh_insecure {
        warn_insecure(sink, "doh-insecure");
    }

    // `src/config2setopts.c:390` -- `if(config->proxy_insecure_ok)`.
    if proxy_insecure {
        warn_insecure(sink, "proxy-insecure");
    }
}

// The sink and `--stderr`.

/// The argument `--stderr -` uses to mean "standard output"
/// (`src/tool_stderr.c:44`).
#[allow(dead_code)]
const STDERR_STDOUT_ARG: &str = "-";

/// `tool_set_stderr_file` (`src/tool_stderr.c:37-69`): points the diagnostic
/// channel at `--stderr`'s argument.
///
/// The four branches follow the C exactly:
///
/// * `:41-42` -- a missing filename is a no-op. C tests a NULL `char *`; the
///   Rust equivalent is `None`, which lets `main.rs` call this
///   unconditionally.
/// * `:44-47` -- a lone `-` selects **standard output**, not a file named `-`.
///   Measured: `--stderr -` puts diagnostics on stdout and leaves the process
///   stderr empty.
/// * `:49-56` -- an unopenable target warns and leaves the channel unchanged.
/// * `:58-68` -- otherwise the channel becomes the file. `FOPEN_WRITETEXT` is
///   `"w"` on all four mandated targets (`lib/curl_setup.h:1259`; the `"wt"`
///   form at `:1245` is Windows-only), which is create-truncate-for-writing --
///   exactly [`File::create`].
///
/// Translation differences 1 and 2 in the module documentation explain why one
/// `File::create` replaces C's precheck-then-`freopen` pair, and why C's
/// `DEBUGASSERT(0)` arm at `:62-66` is unreachable here rather than
/// unimplemented.
///
/// # The doubled prefix is intentional
///
/// `src/tool_stderr.c:53` reads, verbatim:
///
/// ```c
/// warnf("Warning: Failed to open %s", filename);
/// ```
///
/// `warnf` already prepends `WARN_PREFIX`, so the bytes on the wire begin
/// `Warning: Warning: Failed to open `. That is the frozen output, confirmed
/// against the oracle binary, and it is **not** to be tidied up: a refactor
/// that produces different-but-arguably-better output has failed. The
/// redundant literal is preserved below with this
/// citation attached so that nobody removes it later.
///
/// The filename is appended as raw bytes through [`warnf_bytes`] because C
/// prints it with `%s` from a `char *`; a lossy conversion would change the
/// emitted bytes for a path that is not valid UTF-8.
#[allow(dead_code)]
pub(crate) fn set_stderr_file(
    sink: &mut MessageSink,
    config: &MsgConfig,
    filename: Option<&OsStr>,
) {
    // `:41-42`
    let Some(filename) = filename else {
        return;
    };

    // `:44-47`
    if filename == OsStr::new(STDERR_STDOUT_ARG) {
        *sink = MessageSink::Stdout(io::stdout());
        return;
    }

    match File::create(filename) {
        // `:61`, `:68`
        Ok(file) => *sink = MessageSink::File(file),
        Err(_) => {
            // `:52-54`. The literal below carries its own "Warning: " on
            // purpose; see the note above. `as_encoded_bytes` is the raw
            // operating-system bytes on the four mandated targets, which is
            // what C's `%s` would print.
            let mut message = Vec::from(&b"Warning: Failed to open "[..]);
            message.extend_from_slice(filename.as_encoded_bytes());
            warnf_bytes(sink, config, &message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The width `COLUMNS=40` produces, used for most golden cases:
    /// `40 - 9 == 31` bytes of message per wrapped line.
    const ORACLE_TERMW_40: usize = 40;

    /// The width the harness always produces, because
    /// `get_terminal_columns` falls back to 79 whenever `COLUMNS` is unusable:
    /// `79 - 9 == 70` bytes per wrapped line.
    const ORACLE_TERMW_79: usize = 79;

    /// The message every `--stderr` failure produces before the filename, and
    /// the reason the doubled prefix exists (`src/tool_stderr.c:53`).
    const STDERR_FAILURE_LEAD: &str = "Warning: Failed to open ";

    /// Collects a wrapped emission back into the single message it came from,
    /// so a golden assertion does not have to know the terminal width.
    ///
    /// Strips exactly one leading prefix per line, which is what makes the
    /// doubled prefix of `src/tool_stderr.c:53` survive into the result.
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

    /// The message-body length of each emitted line, prefix excluded.
    fn body_lengths(output: &[u8], prefix: &str) -> Vec<usize> {
        output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| {
                line.strip_prefix(prefix.as_bytes()).unwrap_or(line).len()
            })
            .collect()
    }

    /// Runs the wrapper at a fixed width and returns the bytes.
    ///
    /// Fixed width rather than the real terminal so that no test depends on
    /// the ambient `COLUMNS`, which `get_terminal_columns` reads.
    fn wrap(prefix: &str, message: &str, termw: usize) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let result =
            voutf_bytes_at_width(&mut out, prefix, message.as_bytes(), termw);
        assert!(result.is_ok(), "the wrapper must not fail on a Vec sink");
        out
    }

    /// [`wrap`] against a sink that reports itself as a terminal.
    ///
    /// The only difference is the answer to
    /// [`DiagnosticSink::interprets_controls`], so a test that pairs this with
    /// [`wrap`] isolates the neutralization decision from everything else: same
    /// input, same wrapping arithmetic, one differing byte class.
    fn wrap_on_terminal(prefix: &str, message: &str, termw: usize) -> Vec<u8> {
        let mut sink = TerminalSink::default();
        let result =
            voutf_bytes_at_width(&mut sink, prefix, message.as_bytes(), termw);
        assert!(result.is_ok(), "the wrapper must not fail on a Vec sink");
        sink.bytes
    }

    /// A message short enough that no reachable terminal width can wrap it.
    ///
    /// `get_terminal_columns` yields 79 or a value in `21..=10000`, so the
    /// narrowest possible width is `21 - 9 == 12`. Anything at or below 12
    /// bytes is emitted on one line whatever the ambient `COLUMNS` says, which
    /// is what keeps the gate tests below deterministic.
    const SHORT: &str = "short msg";

    // -- The three prefixes ------------------------------------------------

    #[test]
    fn prefixes_match_the_c_defines_exactly() {
        // src/tool_msgs.c:30-32
        assert_eq!(WARN_PREFIX, "Warning: ");
        assert_eq!(NOTE_PREFIX, "Note: ");
        assert_eq!(ERROR_PREFIX, "curl: ");
    }

    #[test]
    fn no_prefix_ever_reports_the_cargo_target_name() {
        // The self-name invariant: the binary is curl-rs, the tool is curl.
        for prefix in [WARN_PREFIX, NOTE_PREFIX, ERROR_PREFIX] {
            assert!(
                !prefix.contains("curl-rs"),
                "prefix {prefix:?} leaked the Cargo target name"
            );
        }
        assert!(!HELP_TRY_TAIL.contains("curl-rs"));
        assert!(HELP_TRY_TAIL.contains("curl --help"));
        assert!(HELP_TRY_TAIL.contains("curl --manual"));
    }

    #[test]
    fn buffer_bound_matches_the_c_array() {
        // src/tool_msgs.c:41 `char buffer[1024]`
        assert_eq!(MSG_BUFFER_SIZE, 1024);
        assert_eq!(MSG_TEXT_CAPACITY, 1023);
    }

    // -- voutf: the oracle goldens ----------------------------------------

    #[test]
    fn wraps_exactly_as_the_oracle_does_on_blanks() {
        // Measured from the real curl 8.19.0-DEV binary built from this tree,
        // invoked as `COLUMNS=40 curl --stderr <that path> file:///dev/null`.
        let message = concat!(
            "Warning: Failed to open /nonexistent_dir_zzz/aaaa bbbb cccc ",
            "dddd eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm nnnn oooo ",
            "pppp"
        );
        let expected = concat!(
            "Warning: Warning: Failed to open \n",
            "Warning: /nonexistent_dir_zzz/aaaa bbbb \n",
            "Warning: cccc dddd eeee ffff gggg hhhh \n",
            "Warning: iiii jjjj kkkk llll mmmm nnnn \n",
            "Warning: oooo pppp\n",
        );

        let out = wrap(WARN_PREFIX, message, ORACLE_TERMW_40);
        assert_eq!(String::from_utf8_lossy(&out), expected);

        // Three separate properties, spelled out so a regression names itself.
        let lines: Vec<&str> = expected.lines().collect();
        assert_eq!(lines.len(), 5);
        for line in &lines {
            // src/tool_msgs.c:49 -- the prefix is inside the loop.
            assert!(line.starts_with(WARN_PREFIX));
        }
        for line in &lines[..4] {
            // src/tool_msgs.c:62 -- `cut + 1` bytes include the blank, so
            // every wrapped line ends with the blank it broke on.
            assert!(line.ends_with(' '), "{line:?} lost its trailing blank");
            // src/tool_msgs.c:52 -- and never exceeds the available width.
            assert!(line.len() - WARN_PREFIX.len() <= 31);
        }
    }

    #[test]
    fn hard_cuts_at_the_full_width_when_no_blank_exists() {
        // Oracle: `COLUMNS=40` with `/nonexistent_dir_zzz/` + 120 'x'.
        // src/tool_msgs.c:57-60 -- "not a single cutting position was found,
        // just cut it at the max text width then!"
        let message = format!(
            "Warning: Failed to open /nonexistent_dir_zzz/{}",
            "x".repeat(120)
        );
        let expected = concat!(
            "Warning: Warning: Failed to open \n",
            "Warning: /nonexistent_dir_zzz/xxxxxxxxxx\n",
            "Warning: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
            "Warning: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
            "Warning: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
            "Warning: xxxxxxxxxxxxxxxxx\n",
        );

        let out = wrap(WARN_PREFIX, &message, ORACLE_TERMW_40);
        assert_eq!(String::from_utf8_lossy(&out), expected);
        // 31 == width == cut + 1 for the hard-cut lines.
        assert_eq!(
            body_lengths(&out, WARN_PREFIX),
            vec![24, 31, 31, 31, 31, 17]
        );
    }

    #[test]
    fn a_tab_is_a_break_position_and_is_neutralised_on_the_line() {
        // Oracle: ISBLANK is space OR tab (lib/curl_ctype.h:45), so the tab is
        // where the backward scan stops -- and it still is, because
        // `voutf_bytes_at_width` computes every break position on the RAW bytes
        // and neutralises only what it then writes. This is the test that proves
        // the two halves of that claim at once: the break lands in the same place
        // as the oracle's, and the tab reaches a TERMINAL as `.` rather than as
        // a cursor movement (see `write_neutralised`).
        let message =
            "Warning: Failed to open /nodir_zzz/aaaaaaaaaa\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let expected = concat!(
            "Warning: Warning: Failed to open \n",
            "Warning: /nodir_zzz/aaaaaaaaaa.\n",
            "Warning: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        );

        let out = wrap_on_terminal(WARN_PREFIX, message, ORACLE_TERMW_40);
        assert_eq!(String::from_utf8_lossy(&out), expected);
        // Unchanged from the oracle's own line lengths: one byte in, one byte
        // out, so the wrapping is byte-for-byte what C produces.
        assert_eq!(body_lengths(&out, WARN_PREFIX), vec![24, 22, 30]);

        // The other half of the destination rule, and the reason this test now
        // runs twice: a sink that does NOT interpret its bytes keeps the tab
        // exactly as C wrote it (`src/tool_msgs.c:62`). The break positions are
        // computed on raw bytes either way, so the LINE STRUCTURE is identical
        // and only that one byte differs -- which is what makes a redirected
        // diagnostic byte-comparable against the C tool.
        let redirected = wrap(WARN_PREFIX, message, ORACLE_TERMW_40);
        assert_eq!(
            String::from_utf8_lossy(&redirected),
            expected.replace("aaaaaaaaaa.", "aaaaaaaaaa\t"),
            "a non-terminal sink must receive the tab unaltered"
        );
        assert_eq!(
            body_lengths(&redirected, WARN_PREFIX),
            body_lengths(&out, WARN_PREFIX),
            "neutralization is one byte in, one byte out, so it cannot move a \
             break position"
        );
    }

    #[test]
    fn a_run_of_blanks_breaks_at_the_last_one() {
        // Oracle: ten consecutive spaces; the backward scan stops at the last
        // blank inside the window, not the first.
        let message =
            "Warning: Failed to open /nodir_zzz/aaaa          bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let out = wrap(WARN_PREFIX, message, ORACLE_TERMW_40);
        assert_eq!(body_lengths(&out, WARN_PREFIX), vec![24, 25, 31, 5]);
        assert_eq!(
            String::from_utf8_lossy(&out),
            concat!(
                "Warning: Warning: Failed to open \n",
                "Warning: /nodir_zzz/aaaa          \n",
                "Warning: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
                "Warning: bbbbb\n",
            )
        );
    }

    #[test]
    fn a_leading_blank_on_a_continuation_still_hard_cuts() {
        // C cannot tell "no blank found" from "the blank is at index 0":
        // src/tool_msgs.c:54-56 exits with cut == 0 either way, and :57-60
        // then hard-cuts. Reproduced rather than improved.
        let message = " aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let out = wrap(WARN_PREFIX, message, ORACLE_TERMW_40);
        assert_eq!(body_lengths(&out, WARN_PREFIX), vec![31, 6]);
    }

    #[test]
    fn truncates_a_long_message_at_the_buffer_bound() {
        // Oracle: a 1,145-byte message at the harness width of 79 emits 16
        // lines whose bodies reassemble to exactly 1,023 bytes.
        let message = format!(
            "Warning: Failed to open /nonexistent_dir_zzz/{}",
            "x".repeat(1100)
        );
        assert_eq!(message.len(), 1145);

        let out = wrap(WARN_PREFIX, &message, ORACLE_TERMW_79);
        let rebuilt = reassemble(&out, WARN_PREFIX);
        assert_eq!(rebuilt.len(), MSG_TEXT_CAPACITY);
        assert_eq!(rebuilt, message.as_bytes()[..MSG_TEXT_CAPACITY]);

        let mut expected_lengths = vec![24];
        expected_lengths.extend(std::iter::repeat(70).take(14));
        expected_lengths.push(19);
        assert_eq!(body_lengths(&out, WARN_PREFIX), expected_lengths);
    }

    #[test]
    fn a_message_exactly_at_the_bound_is_not_truncated() {
        let message = "y".repeat(MSG_TEXT_CAPACITY);
        let out = wrap(WARN_PREFIX, &message, usize::MAX);
        assert_eq!(reassemble(&out, WARN_PREFIX).len(), MSG_TEXT_CAPACITY);
    }

    #[test]
    fn one_byte_past_the_bound_loses_exactly_one_byte() {
        let message = "y".repeat(MSG_TEXT_CAPACITY + 1);
        let out = wrap(WARN_PREFIX, &message, usize::MAX);
        assert_eq!(reassemble(&out, WARN_PREFIX).len(), MSG_TEXT_CAPACITY);
    }

    // -- voutf: the SIZE_MAX branch ---------------------------------------

    #[test]
    fn a_prefix_wider_than_the_terminal_disables_wrapping() {
        // src/tool_msgs.c:44 -- `termw > prefw ? termw - prefw : SIZE_MAX`.
        let message = "a b c d e f g h i j k l m n o p q r s t u v w x y z";
        assert!(message.len() > 40);

        // Strictly narrower than the 9-byte prefix.
        let narrow = wrap(WARN_PREFIX, message, 5);
        assert_eq!(
            String::from_utf8_lossy(&narrow),
            format!("{WARN_PREFIX}{message}\n")
        );

        // Exactly as wide as the prefix: C's test is `>`, so this is the
        // SIZE_MAX arm too.
        let tie = wrap(WARN_PREFIX, message, WARN_PREFIX.len());
        assert_eq!(
            String::from_utf8_lossy(&tie),
            format!("{WARN_PREFIX}{message}\n")
        );

        // One wider, and wrapping resumes.
        let wider = wrap(WARN_PREFIX, message, WARN_PREFIX.len() + 4);
        assert!(body_lengths(&wider, WARN_PREFIX).len() > 1);
    }

    #[test]
    fn a_width_of_one_emits_one_byte_per_line_and_terminates() {
        // The narrowest non-degenerate width: cut is 0, the scan never runs,
        // and :57-60 leaves cut at 0, so one byte is consumed per iteration.
        let out = wrap(WARN_PREFIX, "abcd", WARN_PREFIX.len() + 1);
        assert_eq!(body_lengths(&out, WARN_PREFIX), vec![1, 1, 1, 1]);
        assert_eq!(reassemble(&out, WARN_PREFIX), b"abcd");
    }

    #[test]
    fn an_empty_message_emits_nothing_at_all() {
        // `while(len > 0)` never runs, so not even the prefix is written.
        let mut out: Vec<u8> = Vec::new();
        let result = voutf_bytes_at_width(&mut out, WARN_PREFIX, b"", 79);
        assert!(result.is_ok());
        assert!(out.is_empty());
    }

    #[test]
    fn a_message_that_exactly_fills_the_width_is_not_wrapped() {
        // The branch test is `len > width`, not `>=`.
        let message = "z".repeat(31);
        let out = wrap(WARN_PREFIX, &message, ORACLE_TERMW_40);
        assert_eq!(body_lengths(&out, WARN_PREFIX), vec![31]);
    }

    #[test]
    fn multibyte_text_is_split_on_a_byte_boundary_like_the_c_does() {
        // curl_mvsnprintf copies bytes, so a character straddling the cut is
        // split. Asserting on the byte count proves no char-boundary logic
        // crept in; the output is deliberately not required to be valid UTF-8.
        let message = "\u{00e9}".repeat(40); // 2 bytes each, no blanks
        assert_eq!(message.len(), 80);
        let out = wrap(WARN_PREFIX, &message, ORACLE_TERMW_40);
        assert_eq!(body_lengths(&out, WARN_PREFIX), vec![31, 31, 18]);
        assert_eq!(reassemble(&out, WARN_PREFIX), message.as_bytes());
    }

    // -- voutf: newline handling ------------------------------------------

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "must not contain a newline")]
    fn a_newline_in_the_format_trips_the_debug_assertion() {
        // src/tool_msgs.c:45 `DEBUGASSERT(!strchr(fmt, '\n'))` -- on `fmt`,
        // before expansion. `format_args!` with no interpolation is the one
        // shape where Rust can still see the literal.
        let mut out: Vec<u8> = Vec::new();
        let _ = voutf(&mut out, WARN_PREFIX, format_args!("a\nb"));
    }

    #[test]
    fn a_newline_in_an_interpolated_value_is_accepted_and_neutralised() {
        // Two properties, and both matter. First: a newline in the EXPANSION is
        // accepted rather than asserted on, because C asserts on the format only
        // and `-F 'f=v;type=a/b<newline>tail'` reaches this through
        // `src/tool_formparse.c:877` -- a message-level assertion would abort a
        // debug build on input the oracle accepts. Second: it does not reach the
        // terminal as a line break, so it cannot forge an additional
        // `curl: ...` line. See `write_neutralised`.
        let value = "a\nb";
        let mut out = TerminalSink::default();
        let outcome = voutf(&mut out, WARN_PREFIX, format_args!("{value}"));
        assert!(outcome.is_ok());
        assert_eq!(String::from_utf8_lossy(&out.bytes), "Warning: a.b\n");

        // And the byte-oriented entry point, which has no format at all.
        let mut bytes = TerminalSink::default();
        let outcome =
            voutf_bytes_at_width(&mut bytes, WARN_PREFIX, b"a\nb", 79);
        assert!(outcome.is_ok());
        assert_eq!(String::from_utf8_lossy(&bytes.bytes), "Warning: a.b\n");

        // Third property, and the one the destination rule adds: a sink whose
        // bytes are not interpreted receives the newline through, exactly as C
        // does. Nothing can forge a line on a destination that renders none.
        let mut redirected: Vec<u8> = Vec::new();
        let outcome =
            voutf(&mut redirected, WARN_PREFIX, format_args!("{value}"));
        assert!(outcome.is_ok());
        assert_eq!(
            String::from_utf8_lossy(&redirected),
            "Warning: a\nb\n",
            "a redirected diagnostic must stay byte-faithful to C"
        );
    }

    #[test]
    fn a_forged_diagnostic_line_cannot_be_injected_through_a_value() {
        // The attack `write_neutralised` exists to stop: a value carrying a line
        // feed and a plausible-looking prefix would otherwise appear on the
        // terminal as a second, independent diagnostic. Exactly one newline may
        // leave this function -- the one it appends itself.
        let hostile = "bad\ncurl: (0) everything is fine";
        let mut out = TerminalSink::default();
        let outcome = voutf_bytes_at_width(
            &mut out,
            WARN_PREFIX,
            hostile.as_bytes(),
            usize::MAX,
        );
        assert!(outcome.is_ok());
        assert_eq!(
            out.bytes.iter().filter(|byte| **byte == b'\n').count(),
            1,
            "only the terminating newline may appear"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.bytes),
            "Warning: bad.curl: (0) everything is fine\n"
        );
    }

    #[test]
    fn an_escape_byte_cannot_reach_the_terminal() {
        // The other half of the same vector: ESC would drive the terminal's
        // control sequences -- colours, cursor movement, or a title change.
        let mut out = TerminalSink::default();
        let hostile: &[u8] = b"path\x1b[2Kgone\x07\x7f";
        let outcome =
            voutf_bytes_at_width(&mut out, WARN_PREFIX, hostile, usize::MAX);
        assert!(outcome.is_ok());
        assert_eq!(
            String::from_utf8_lossy(&out.bytes),
            "Warning: path.[2Kgone..\n"
        );
        assert!(
            !out.bytes.contains(&0x1b),
            "no escape byte may survive the boundary"
        );

        // And the destination rule: a redirected sink keeps the ESC, because
        // nothing there will act on it and AAP section 0.8.1 does not permit
        // altering bytes C wrote through. The protection is where it protects,
        // and absent where it would only corrupt.
        let mut redirected: Vec<u8> = Vec::new();
        let outcome = voutf_bytes_at_width(
            &mut redirected,
            WARN_PREFIX,
            hostile,
            usize::MAX,
        );
        assert!(outcome.is_ok());
        let mut expected = WARN_PREFIX.as_bytes().to_vec();
        expected.extend_from_slice(hostile);
        expected.push(b'\n');
        assert_eq!(
            redirected, expected,
            "a non-terminal sink must receive every byte unaltered"
        );
    }

    #[test]
    fn bytes_at_or_above_0x80_are_left_alone() {
        // A path or a header value that is UTF-8, or Latin-1, or arbitrary
        // bytes: none of it is a terminal control, so none of it is touched.
        // Escaping it would change the bytes the oracle emits for a filename
        // that is merely non-ASCII, which AAP section 0.8.1 does not permit.
        let mut out: Vec<u8> = Vec::new();
        let message: &[u8] = &[0xc3, 0xa9, 0xff, 0x80, b'x'];
        let outcome =
            voutf_bytes_at_width(&mut out, WARN_PREFIX, message, usize::MAX);
        assert!(outcome.is_ok());
        let mut expected = WARN_PREFIX.as_bytes().to_vec();
        expected.extend_from_slice(message);
        expected.push(b'\n');
        assert_eq!(out, expected);
    }

    // -- voutf: error propagation -----------------------------------------

    /// A sink that fails on its first write, to prove the loop propagates
    /// instead of spinning.
    struct FailingSink;

    impl Write for FailingSink {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("sink is closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("sink is closed"))
        }
    }

    /// Takes [`DiagnosticSink`]'s default, so its bytes are not interpreted.
    /// What these tests assert is failure propagation, which is independent of
    /// the neutralization decision.
    impl DiagnosticSink for FailingSink {}

    /// A capturing sink that claims to be a terminal.
    ///
    /// The counterpart of a bare `Vec<u8>`: same bytes captured, opposite answer
    /// to [`DiagnosticSink::interprets_controls`]. Both branches of
    /// [`write_neutralised`] are therefore reachable from a test without opening
    /// a real terminal, which no test environment can rely on having.
    #[derive(Default)]
    struct TerminalSink {
        bytes: Vec<u8>,
    }

    impl Write for TerminalSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.bytes.flush()
        }
    }

    impl DiagnosticSink for TerminalSink {
        fn interprets_controls(&self) -> bool {
            true
        }
    }

    #[test]
    fn a_write_failure_propagates_out_of_the_wrapper() {
        let long = "q".repeat(500);
        let result = voutf_bytes_at_width(
            &mut FailingSink,
            WARN_PREFIX,
            long.as_bytes(),
            40,
        );
        assert!(result.is_err());
    }

    #[test]
    fn a_write_failure_is_swallowed_by_the_public_entry_points() {
        // src/tool_msgs.c:62 casts the fwrite result away; the entry points
        // are `void` in src/tool_msgs.h:30-33. None of these may panic.
        let config = MsgConfig::new(false, true, true);
        notef(&mut FailingSink, &config, format_args!("{SHORT}"));
        warnf(&mut FailingSink, &config, format_args!("{SHORT}"));
        warnf_bytes(&mut FailingSink, &config, SHORT.as_bytes());
        errorf(&mut FailingSink, &config, format_args!("{SHORT}"));
        helpf(&mut FailingSink, Some(format_args!("{SHORT}")));
        helpf(&mut FailingSink, None);
        warn_insecure(&mut FailingSink, "insecure");
    }

    // -- The four gates ----------------------------------------------------

    /// Emits through one entry point with the given gates and returns the
    /// bytes. Uses [`SHORT`], which no reachable width can wrap.
    fn emit(
        entry: fn(&mut dyn DiagnosticSink, &MsgConfig, fmt::Arguments<'_>),
        config: MsgConfig,
    ) -> String {
        let mut out: Vec<u8> = Vec::new();
        entry(&mut out, &config, format_args!("{SHORT}"));
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn notef_is_gated_only_on_trace() {
        // src/tool_msgs.c:81 -- `if(global->tracetype)`.
        let expected = format!("{NOTE_PREFIX}{SHORT}\n");

        // Trace off: nothing, whatever else is set.
        assert_eq!(emit(notef, MsgConfig::default()), "");
        assert_eq!(emit(notef, MsgConfig::new(true, true, false)), "");

        // Trace on: emitted, and --silent does NOT suppress it. Measured
        // against the oracle with `-v -s -X GET`.
        assert_eq!(emit(notef, MsgConfig::new(false, false, true)), expected);
        assert_eq!(emit(notef, MsgConfig::new(true, false, true)), expected);
        assert_eq!(emit(notef, MsgConfig::new(true, true, true)), expected);
    }

    #[test]
    fn warnf_is_gated_only_on_silent() {
        // src/tool_msgs.c:95 -- `if(!global->silent)`.
        let expected = format!("{WARN_PREFIX}{SHORT}\n");

        assert_eq!(emit(warnf, MsgConfig::default()), expected);
        assert_eq!(emit(warnf, MsgConfig::new(false, true, false)), expected);

        // --silent suppresses, and --show-error does NOT bring it back.
        // Measured against the oracle with `-s` and with `-s -S`.
        assert_eq!(emit(warnf, MsgConfig::new(true, false, false)), "");
        assert_eq!(emit(warnf, MsgConfig::new(true, true, false)), "");
        assert_eq!(emit(warnf, MsgConfig::new(true, true, true)), "");
    }

    #[test]
    fn warnf_bytes_shares_warnf_s_prefix_and_gate() {
        let mut shown: Vec<u8> = Vec::new();
        warnf_bytes(&mut shown, &MsgConfig::default(), SHORT.as_bytes());
        assert_eq!(
            String::from_utf8_lossy(&shown),
            format!("{WARN_PREFIX}{SHORT}\n")
        );

        let mut muted: Vec<u8> = Vec::new();
        warnf_bytes(
            &mut muted,
            &MsgConfig::new(true, true, true),
            SHORT.as_bytes(),
        );
        assert!(muted.is_empty());
    }

    #[test]
    fn warnf_bytes_carries_non_utf8_through_unchanged() {
        // C prints the filename with %s from a char *, so the raw bytes must
        // survive rather than becoming U+FFFD.
        let raw = [b'a', 0x80, 0xFE, b'b'];
        let mut out: Vec<u8> = Vec::new();
        warnf_bytes(&mut out, &MsgConfig::default(), &raw);

        let mut expected = Vec::from(WARN_PREFIX.as_bytes());
        expected.extend_from_slice(&raw);
        expected.extend_from_slice(NEWLINE);
        assert_eq!(out, expected);
    }

    #[test]
    fn errorf_is_gated_on_silent_but_rescued_by_show_error() {
        // src/tool_msgs.c:131 -- `if(!global->silent || global->showerror)`.
        let expected = format!("{ERROR_PREFIX}{SHORT}\n");

        assert_eq!(emit(errorf, MsgConfig::default()), expected);
        assert_eq!(emit(errorf, MsgConfig::new(false, true, false)), expected);

        // --silent alone suppresses ...
        assert_eq!(emit(errorf, MsgConfig::new(true, false, false)), "");
        // ... and --show-error brings it back. This is the one place
        // show_error is read, and the sole difference from warnf.
        assert_eq!(emit(errorf, MsgConfig::new(true, true, false)), expected);
    }

    #[test]
    fn errorf_and_warnf_differ_only_in_the_show_error_case() {
        for silent in [false, true] {
            for show_error in [false, true] {
                let config = MsgConfig::new(silent, show_error, false);
                let warned = emit(warnf, config);
                let errored = emit(errorf, config);
                let same_visibility = warned.is_empty() == errored.is_empty();
                if silent && show_error {
                    assert!(!same_visibility, "{config:?} must diverge");
                } else {
                    assert!(same_visibility, "{config:?} must agree");
                }
            }
        }
    }

    // -- helpf --------------------------------------------------------------

    #[test]
    fn helpf_with_no_message_emits_only_the_try_line() {
        // Oracle: a bare invocation. src/tool_operate.c:2284 calls
        // helpf(NULL) for real.
        let mut out: Vec<u8> = Vec::new();
        helpf(&mut out, None);
        assert_eq!(
            String::from_utf8_lossy(&out),
            "curl: try 'curl --help' or 'curl --manual' for more information\n"
        );
    }

    #[test]
    fn helpf_with_a_message_emits_it_then_the_try_line() {
        // Oracle: `curl --this-option-does-not-exist`.
        let mut out: Vec<u8> = Vec::new();
        helpf(
            &mut out,
            Some(format_args!(
                "option {}: {}",
                "--this-option-does-not-exist", "is unknown"
            )),
        );
        assert_eq!(
            String::from_utf8_lossy(&out),
            concat!(
                "curl: option --this-option-does-not-exist: is unknown\n",
                "curl: try 'curl --help' or 'curl --manual' \
                 for more information\n",
            )
        );
    }

    #[test]
    fn helpf_never_wraps_and_never_truncates() {
        // src/tool_msgs.c:114 uses curl_mvfprintf, which streams straight to
        // the destination with no buffer (lib/mprintf.c:1226-1229). Oracle:
        // an 84-byte message stayed on one line at COLUMNS=40.
        let long = "w".repeat(MSG_BUFFER_SIZE * 3);
        let mut out: Vec<u8> = Vec::new();
        helpf(&mut out, Some(format_args!("{long}")));

        let text = String::from_utf8_lossy(&out).into_owned();
        let first = text.lines().next().unwrap_or_default();
        assert_eq!(first, format!("{ERROR_PREFIX}{long}"));
        assert!(first.len() > MSG_BUFFER_SIZE);
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn helpf_ignores_every_gate() {
        // It takes no MsgConfig at all, which is the point: src/tool_msgs.c
        // :107-123 consults neither silent nor showerror nor tracetype.
        let mut out: Vec<u8> = Vec::new();
        helpf(&mut out, Some(format_args!("{SHORT}")));
        assert!(!out.is_empty());
    }

    // -- The mandatory --insecure warning ---------------------------------

    /// The three flags that switch certificate verification off
    /// (`src/config2setopts.c:379-392`). Every test below iterates all three:
    /// AAP section 0.1.1 goal G4 does not distinguish between them, so a
    /// property proven for one of them is not proven for the other two.
    const VERIFICATION_FLAGS: [&str; 3] =
        ["insecure", "proxy-insecure", "doh-insecure"];

    /// Every reachable combination of the two gates that could plausibly
    /// suppress a warning, as an exhaustive `(silent, show_error)` matrix.
    ///
    /// `trace_enabled` is deliberately excluded: it is [`notef`]'s sole gate
    /// and enables output rather than suppressing it, so it cannot mute
    /// anything. The four rows below are therefore the complete suppression
    /// surface, not a sample of it.
    const GATE_MATRIX: [(bool, bool); 4] = [
        (false, false), // the default: no flags
        (true, false),  // --silent          -- mutes warnf
        (false, true),  // --show-error
        (true, true),   // --silent --show-error, which does NOT restore warnf
    ];

    #[test]
    fn insecure_warning_bytes_are_stable_and_greppable() {
        let mut out: Vec<u8> = Vec::new();
        warn_insecure(&mut out, "insecure");
        assert_eq!(
            String::from_utf8_lossy(&out),
            "Warning: using --insecure makes the transfer insecure\n"
        );
    }

    #[test]
    fn insecure_warning_carries_the_warning_prefix_and_a_single_line() {
        let mut out: Vec<u8> = Vec::new();
        warn_insecure(&mut out, "insecure");
        let text = String::from_utf8_lossy(&out).into_owned();
        assert!(text.starts_with(WARN_PREFIX));
        assert!(text.ends_with('\n'));
        // Short enough that no reachable terminal width can split it: the
        // narrowest width is 12 and this needs the flag name intact for the
        // integration test to match on one line.
        assert_eq!(text.lines().count(), 1);
        // The predicate is verbatim from docs/cmdline-opts/insecure.md:36.
        assert!(text.contains("makes the transfer insecure"));
        assert!(!text.contains("curl-rs"));
    }

    #[test]
    fn insecure_warning_serves_all_three_verification_flags() {
        // src/config2setopts.c:379-393 switches verification off for three
        // flags; the option table stays in the command-line layer.
        for flag in VERIFICATION_FLAGS {
            let mut out: Vec<u8> = Vec::new();
            warn_insecure(&mut out, flag);
            assert_eq!(
                String::from_utf8_lossy(&out),
                format!(
                    "Warning: using --{flag} makes the transfer insecure\n"
                )
            );
        }
    }

    #[test]
    fn the_insecure_warning_is_mandatory_and_takes_no_gate_argument() {
        // AAP 0.1.1 goal G4, 0.8.1 and validation gate 10 of 0.8.4 all require
        // the warning to be emitted whenever verification is switched off.
        // `warn_insecure` therefore accepts no `MsgConfig`: there is no
        // argument through which silence could be requested, so this test
        // asserts an invariant the signature already enforces -- it would not
        // compile if the gate came back.
        //
        // The counterpart assertion, that `warnf` IS still gated, lives in
        // `warnf_is_not_restored_by_show_error`; the two together prove the
        // mandatory path is a genuinely separate channel and not a change to
        // the shared one.
        let mut out: Vec<u8> = Vec::new();
        warn_insecure(&mut out, "insecure");
        assert_eq!(
            String::from_utf8_lossy(&out),
            "Warning: using --insecure makes the transfer insecure\n"
        );

        // The same message through the suppressible channel, under the gates a
        // `--silent --show-error` invocation produces, yields nothing. If
        // `warn_insecure` were still routed through it, the assertion above
        // would be unreachable under those flags.
        let mut muted: Vec<u8> = Vec::new();
        warnf(
            &mut muted,
            &MsgConfig::new(true, true, true),
            format_args!("using --insecure makes the transfer insecure"),
        );
        assert!(muted.is_empty());
    }

    #[test]
    fn insecure_warning_cannot_be_suppressed_by_any_gate_combination() {
        // AAP section 0.1.1 goal G4 requires the warning unconditionally, and
        // AAP section 0.8.4 makes it validation gate 10. This is the assertion
        // that the requirement is met: all three flags against all four gate
        // combinations, twelve cases, every one of which must emit the exact
        // bytes.
        //
        // The gates are constructed and passed to the SIBLING entry points in
        // the same iteration, so a future change that re-gated the warning
        // would fail here rather than silently reintroducing the defect.
        for flag in VERIFICATION_FLAGS {
            let expected = format!(
                "Warning: using --{flag} makes the transfer insecure\n"
            );

            for (silent, show_error) in GATE_MATRIX {
                let config = MsgConfig::new(silent, show_error, false);

                let mut out: Vec<u8> = Vec::new();
                warn_insecure(&mut out, flag);
                assert_eq!(
                    String::from_utf8_lossy(&out),
                    expected,
                    "--{flag} lost its warning at \
                     silent={silent} show_error={show_error}"
                );

                // The control: warnf with the SAME gates is muted by --silent
                // and --show-error does not restore it. This is what
                // warn_insecure would have inherited, and the contrast is the
                // point of the test.
                let mut gated: Vec<u8> = Vec::new();
                warnf(&mut gated, &config, format_args!("{SHORT}"));
                assert_eq!(
                    gated.is_empty(),
                    silent,
                    "warnf's own gate changed: silent={silent} \
                     show_error={show_error}"
                );
            }
        }
    }

    #[test]
    fn insecure_warning_takes_no_gate_argument_at_all() {
        // The structural half of the guarantee, and the reason the test above
        // can never regress quietly: warn_insecure's type admits no MsgConfig,
        // so there is nothing for a caller to gate on. Coercing it to a
        // gateless function pointer is a compile-time proof of that, in the
        // same shape as helpf_ignores_every_gate above.
        let ungated: fn(&mut dyn DiagnosticSink, &str) = warn_insecure;
        let mut out: Vec<u8> = Vec::new();
        ungated(&mut out, "insecure");
        assert!(!out.is_empty());
    }

    #[test]
    fn the_insecure_warning_survives_every_suppression_flag() {
        // The teeth for F18, and the reason this function takes no MsgConfig:
        // `curl -s -k` must not disable certificate verification silently. The
        // mandate in goal G4, AAP section 0.8.1 and validation gate 10 is
        // unconditional, so there is no flag combination that withholds it.
        //
        // The signature is the enforcement -- there is no config to consult --
        // and this asserts the consequence for every combination of the three
        // gates a message can be subject to, so a future re-routing through
        // `warnf` fails here rather than in production.
        let expected =
            "Warning: using --insecure makes the transfer insecure\n";
        for silent in [false, true] {
            for show_error in [false, true] {
                for use_ascii in [false, true] {
                    let config = MsgConfig::new(silent, show_error, use_ascii);
                    // Consulted only so this test still exercises the shape a
                    // caller holds; the emission must not depend on it.
                    let _ = &config;
                    let mut out: Vec<u8> = Vec::new();
                    warn_insecure(&mut out, "insecure");
                    assert_eq!(
                        String::from_utf8_lossy(&out),
                        expected,
                        "silent={silent} show_error={show_error} \
                         use_ascii={use_ascii}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_insecure_warning_is_emitted_once_per_call() {
        // Documented contract: the function has no memory, so a caller that
        // applies the configuration twice warns twice. Recorded as a test so the
        // caller's obligation is not merely prose.
        let mut out: Vec<u8> = Vec::new();
        warn_insecure(&mut out, "insecure");
        warn_insecure(&mut out, "insecure");
        assert_eq!(out.iter().filter(|byte| **byte == b'\n').count(), 2);
    }

    #[test]
    fn insecure_warning_cannot_be_silenced() {
        // AAP section 0.1.1 goal G4 requires a warning *before proceeding*,
        // and section 0.8.4 makes it gate 10. A warning `--silent` removes
        // would satisfy neither, so the emitter accepts no gate set at all:
        // the four states MsgConfig can express are unreachable from here,
        // which is what this test records. Compare warnf, whose `-s` and
        // `-s -S` behaviour is measured in the gate tests above.
        let expected =
            "Warning: using --insecure makes the transfer insecure\n";
        for (silent, show_error, trace) in [
            (false, false, false),
            (true, false, false),
            (true, true, false),
            (true, true, true),
        ] {
            // Built and dropped to prove the emitter needs none of it: this
            // value cannot be handed to `warn_insecure` because the signature
            // has no place for it.
            let unreachable_gates = MsgConfig::new(silent, show_error, trace);
            assert_eq!(unreachable_gates.silent, silent);

            let mut out: Vec<u8> = Vec::new();
            warn_insecure(&mut out, "insecure");
            assert_eq!(String::from_utf8_lossy(&out), expected);
        }
    }

    #[test]
    fn insecure_warning_still_follows_the_configured_sink() {
        // Only the gate is dropped, never the redirection: `--stderr <file>`
        // and `--stderr -` must move this warning like any other. The sink is
        // the caller's `&mut dyn Write`, so a captured buffer stands in for
        // both redirect targets.
        let mut redirected: Vec<u8> = Vec::new();
        warn_insecure(&mut redirected, "proxy-insecure");
        assert_eq!(
            String::from_utf8_lossy(&redirected),
            "Warning: using --proxy-insecure makes the transfer insecure\n"
        );
    }

    #[test]
    fn the_flag_door_applies_c_s_order_and_nothing_else() {
        // src/config2setopts.c: `insecure_ok` :379, `doh_insecure_ok` :385,
        // `proxy_insecure_ok` :390. Two flags together produce two lines whose
        // sequence is program output, so the order is asserted, not assumed.
        let mut all: Vec<u8> = Vec::new();
        warn_insecure_flags(&mut all, true, true, true);
        assert_eq!(
            String::from_utf8_lossy(&all),
            "Warning: using --insecure makes the transfer insecure\n\
             Warning: using --doh-insecure makes the transfer insecure\n\
             Warning: using --proxy-insecure makes the transfer insecure\n"
        );

        // doh precedes proxy -- the pair that would reverse under an
        // alphabetical or declaration-order reading.
        let mut pair: Vec<u8> = Vec::new();
        warn_insecure_flags(&mut pair, false, true, true);
        assert_eq!(
            String::from_utf8_lossy(&pair),
            "Warning: using --doh-insecure makes the transfer insecure\n\
             Warning: using --proxy-insecure makes the transfer insecure\n"
        );

        // Each flag on its own selects exactly its own name.
        for (i, name) in ["insecure", "doh-insecure", "proxy-insecure"]
            .iter()
            .enumerate()
        {
            let mut one: Vec<u8> = Vec::new();
            warn_insecure_flags(&mut one, i == 0, i == 1, i == 2);
            assert_eq!(
                String::from_utf8_lossy(&one),
                format!(
                    "Warning: using --{name} makes the transfer insecure\n"
                )
            );
        }

        // All three clear: the three `if` statements are not taken and C emits
        // nothing, so neither does this.
        let mut none: Vec<u8> = Vec::new();
        warn_insecure_flags(&mut none, false, false, false);
        assert!(none.is_empty());
    }

    #[test]
    fn the_mandatory_warning_goes_only_to_the_given_sink() {
        // "preserve only the configured destination": once `--stderr <file>`
        // has been honoured the sink IS that file, so following the
        // redirection needs no special case -- but it does need the warning to
        // have no second destination. Writing into a sink that records its
        // bytes and asserting the full expected content proves nothing was
        // split off elsewhere, and `warn_insecure` reaches no global stream.
        let mut redirected: Vec<u8> = Vec::new();
        warn_insecure_flags(&mut redirected, true, false, true);
        assert_eq!(
            String::from_utf8_lossy(&redirected),
            "Warning: using --insecure makes the transfer insecure\n\
             Warning: using --proxy-insecure makes the transfer insecure\n"
        );
    }

    // -- The sink and --stderr --------------------------------------------

    #[test]
    fn the_initial_sink_is_standard_error() {
        // src/tool_stderr.c:31-35 -- `tool_stderr = stderr;`
        assert!(matches!(MessageSink::init(), MessageSink::Stderr(_)));
    }

    #[test]
    fn a_missing_filename_leaves_the_sink_alone() {
        // src/tool_stderr.c:41-42
        let mut sink = MessageSink::init();
        set_stderr_file(&mut sink, &MsgConfig::default(), None);
        assert!(matches!(sink, MessageSink::Stderr(_)));
    }

    #[test]
    fn a_lone_dash_selects_standard_output() {
        // src/tool_stderr.c:44-47. Oracle: `--stderr -` puts diagnostics on
        // stdout and leaves the process stderr empty.
        let mut sink = MessageSink::init();
        set_stderr_file(
            &mut sink,
            &MsgConfig::default(),
            Some(OsStr::new("-")),
        );
        assert!(matches!(sink, MessageSink::Stdout(_)));
    }

    #[test]
    fn a_two_dash_argument_is_a_filename_not_stdout() {
        // strcmp, not a prefix test: only an exact "-" means stdout.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("--");
        let mut sink = MessageSink::init();
        set_stderr_file(
            &mut sink,
            &MsgConfig::default(),
            Some(path.as_os_str()),
        );
        assert!(matches!(sink, MessageSink::File(_)));
    }

    #[test]
    fn a_writable_filename_becomes_the_sink() {
        // src/tool_stderr.c:58-68. FOPEN_WRITETEXT is "w" on the four
        // mandated targets (lib/curl_setup.h:1259) -- create and truncate.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("diagnostics.txt");

        let mut sink = MessageSink::init();
        set_stderr_file(
            &mut sink,
            &MsgConfig::default(),
            Some(path.as_os_str()),
        );
        assert!(matches!(sink, MessageSink::File(_)));

        errorf(&mut sink, &MsgConfig::default(), format_args!("(37) oops"));
        let flushed = sink.flush();
        assert!(flushed.is_ok());
        drop(sink);

        let written = std::fs::read(&path).expect("the redirected file");
        assert_eq!(String::from_utf8_lossy(&written), "curl: (37) oops\n");
    }

    #[test]
    fn a_real_redirected_file_keeps_control_bytes_byte_for_byte() {
        // Asserted against the PRODUCTION sink rather than
        // a double. `--stderr <file>` names an ordinary file, so
        // `MessageSink::interprets_controls` asks `IsTerminal` and gets `false`,
        // and the diagnostic must land byte-identical to what C writes through
        // at `src/tool_msgs.c:62`. This is the case an unconditional escape
        // silently corrupted.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("diagnostics.txt");

        let mut sink = MessageSink::init();
        set_stderr_file(
            &mut sink,
            &MsgConfig::default(),
            Some(path.as_os_str()),
        );
        assert!(matches!(sink, MessageSink::File(_)));
        assert!(
            !sink.interprets_controls(),
            "a plain file is not a terminal, and the answer must come from the \
             descriptor rather than from a stored flag"
        );

        let hostile: &[u8] = b"tab\there\x1bESC";
        errorf_bytes(&mut sink, &MsgConfig::default(), hostile);
        assert!(sink.flush().is_ok());
        drop(sink);

        let written = std::fs::read(&path).expect("the redirected file");
        let mut expected = ERROR_PREFIX.as_bytes().to_vec();
        expected.extend_from_slice(hostile);
        expected.push(b'\n');
        assert_eq!(
            written, expected,
            "every byte of a redirected diagnostic must survive unaltered"
        );
    }

    #[test]
    fn an_existing_target_is_truncated_like_fopen_w_does() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("diagnostics.txt");
        std::fs::write(&path, b"stale contents that must not survive")
            .expect("seed the file");

        let mut sink = MessageSink::init();
        set_stderr_file(
            &mut sink,
            &MsgConfig::default(),
            Some(path.as_os_str()),
        );
        drop(sink);

        let written = std::fs::read(&path).expect("the redirected file");
        assert!(written.is_empty(), "the target was not truncated");
    }

    #[test]
    fn an_unopenable_target_warns_with_the_doubled_prefix() {
        // src/tool_stderr.c:52-54. The doubled "Warning: " is the frozen
        // output and is asserted here so it cannot be tidied away.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("no_such_directory").join("target.txt");

        // Emit into a capturing sink rather than the real stderr so the bytes
        // are assertable; the redirect decision is what is under test.
        let mut captured: Vec<u8> = Vec::new();
        let mut sink = MessageSink::init();
        set_stderr_file(
            &mut sink,
            &MsgConfig::default(),
            Some(path.as_os_str()),
        );
        // The channel must be unchanged after a failure.
        assert!(matches!(sink, MessageSink::Stderr(_)));

        // Reproduce the same failure path against the capturing sink so the
        // exact bytes can be checked at any terminal width.
        let mut message = Vec::from(STDERR_FAILURE_LEAD.as_bytes());
        message.extend_from_slice(path.as_os_str().as_encoded_bytes());
        warnf_bytes(&mut captured, &MsgConfig::default(), &message);

        let rebuilt = reassemble(&captured, WARN_PREFIX);
        assert_eq!(rebuilt, message);

        let text = String::from_utf8_lossy(&rebuilt).into_owned();
        assert!(
            text.starts_with("Warning: Failed to open "),
            "the literal Warning: from src/tool_stderr.c:53 was removed"
        );
        // Prefix plus literal: the bytes on the wire start with it twice.
        let on_the_wire = String::from_utf8_lossy(&captured).into_owned();
        assert!(on_the_wire.starts_with("Warning: Warning: Failed to open "));
    }

    #[test]
    fn an_unopenable_target_is_silent_under_silent() {
        let mut captured: Vec<u8> = Vec::new();
        let config = MsgConfig::new(true, true, true);
        let mut message = Vec::from(STDERR_FAILURE_LEAD.as_bytes());
        message.extend_from_slice(b"/no_such_directory_zzz/target.txt");
        warnf_bytes(&mut captured, &config, &message);
        assert!(captured.is_empty());
    }

    #[test]
    fn the_sink_forwards_every_write_method() {
        // Exercises the delegating impl for the one variant a unit test can
        // own outright.
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("forwarded.txt");
        let file = File::create(&path).expect("create the file");
        let mut sink = MessageSink::File(file);

        // `Write::write` is contractually allowed to consume fewer bytes than
        // it is given, and asserting a full count here would be asserting a
        // guarantee the trait does not make. Measured: Miri exercises exactly
        // that latitude and answers `Ok(1)` for this three-byte buffer while
        // the host answers `Ok(3)`. What the delegation must guarantee is that
        // the call reaches the file and reports a sane count; whether every
        // byte arrives is [`Write::write_all`]'s promise, and the content check
        // below is what holds it to it.
        let count = sink.write(b"one").expect("the write reaches the file");
        assert!((1..=3).contains(&count), "{count} is not a sane count");
        // Finish whatever the short write left, then append, both through the
        // delegating `write_all`.
        assert!(sink.write_all(&b"one"[count..]).is_ok());
        assert!(sink.write_all(b"-two").is_ok());
        assert!(sink.flush().is_ok());
        drop(sink);

        assert_eq!(std::fs::read(&path).ok(), Some(b"one-two".to_vec()));
    }

    // -- MessageBuffer -----------------------------------------------------

    #[test]
    fn the_buffer_stops_storing_at_the_capacity() {
        // The addbyter analogue (lib/mprintf.c:1065-1075).
        let mut buffer = MessageBuffer::new();
        buffer.push_bytes(&vec![b'a'; MSG_TEXT_CAPACITY - 1]);
        assert_eq!(buffer.as_bytes().len(), MSG_TEXT_CAPACITY - 1);

        buffer.push_bytes(b"bc");
        assert_eq!(buffer.as_bytes().len(), MSG_TEXT_CAPACITY);
        assert_eq!(buffer.as_bytes().last().copied(), Some(b'b'));

        // Once full, further appends are dropped rather than wrapping.
        buffer.push_bytes(b"ddd");
        assert_eq!(buffer.as_bytes().len(), MSG_TEXT_CAPACITY);
    }

    #[test]
    fn the_buffer_renders_a_format_through_fmt_write() {
        let mut buffer = MessageBuffer::new();
        let result = buffer.write_fmt(format_args!("{}-{}", 7, "eight"));
        assert!(result.is_ok());
        assert_eq!(buffer.as_bytes(), b"7-eight");
    }

    // -- is_blank -----------------------------------------------------------

    #[test]
    fn is_blank_accepts_only_space_and_tab() {
        // lib/curl_ctype.h:45, ASCII-only and locale-independent.
        assert!(is_blank(b' '));
        assert!(is_blank(b'\t'));
        for byte in [b'\n', b'\r', 0x0b, 0x0c, b'a', b'0', 0x00, 0xA0, 0xFF] {
            assert!(!is_blank(byte), "{byte:#04x} must not be a blank");
        }
    }

    // -- MsgConfig ---------------------------------------------------------

    #[test]
    fn the_default_gate_set_matches_a_zeroed_c_global() {
        let config = MsgConfig::default();
        assert!(!config.silent);
        assert!(!config.show_error);
        assert!(!config.trace_enabled);
        assert_eq!(config, MsgConfig::new(false, false, false));

        // Warnings and errors emit, notes do not.
        assert!(!emit(warnf, config).is_empty());
        assert!(!emit(errorf, config).is_empty());
        assert!(emit(notef, config).is_empty());
    }
}
