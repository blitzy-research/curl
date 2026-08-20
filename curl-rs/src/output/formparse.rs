// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The `-F` / `--form-string` mini-language: parsing, and translation of the
//! parse result into a libcurl MIME tree.
//!
//! This module supersedes `src/tool_formparse.c` (893 lines), which implements
//! `-F` parsing. It reproduces that translation unit in full:
//! the tool-local MIME tree (`src/tool_formparse.h:40-58`), the field parser
//! (`src/tool_formparse.c:714-893`), the `;attr=` loop
//! (`src/tool_formparse.c:471-656`), the quoting rules
//! (`src/tool_formparse.c:342-397`), the standard-input part
//! (`src/tool_formparse.c:96-176`, `:195-249`) and the fixed-order translation
//! into libcurl calls (`src/tool_formparse.c:253-335`).
//!
//! # Why this file is wire-visible, and therefore frozen
//!
//! `-F` composes the request body. Whatever this parse produces becomes the
//! multipart payload: the part order, each part's `Content-Disposition`, and
//! the presence or absence of a `Content-Type` per part all follow from it.
//!
//! The oracle that enforces this is measurable. 1,476 of the
//! 1,914 fixtures -- 77.1% -- carry a byte-exact `<protocol>` block, and
//! `compareparts` (`tests/getpart.pm:351+`) joins both arrays into a single
//! string and compares them as one string. There is no per-line matching, no
//! normalization and no reordering, so header order, header casing, spacing
//! and the presence or absence of each default header are all absolutely
//! significant. The only escape hatches are the `%alternatives[a,b]`
//! construct and the `<strip>` regular expressions applied before comparison
//! (`tests/runtests.pl:1416`).
//!
//! Two consequences follow and are honoured throughout:
//!
//! * This module must not alter what it hands to the serialiser. Every
//!   acceptance rule below is the C rule, including the ones that look like
//!   accidents.
//! * No file under `tests/` may be edited. A failing fixture is evidence of
//!   an implementation defect; editing a fixture to make it pass is
//!   prohibited.
//!
//! The accurate success criterion is that every fixture eligible under the
//! advertised feature and protocol set passes unmodified -- roughly 1,413
//! eligible (73.8%) with 283 legitimately skipping (14.8%). A 100% pass rate
//! is never claimed.
//!
//! # This parser infers no content type; the serialiser does
//!
//! The division of labour matters, and getting it wrong changes wire bytes in
//! either direction. Three anchors fix what this file must do:
//!
//! 1. `src/tool_formparse.c:508` -- `if(!endct && checkprefix("type=", p))`.
//!    That is the *only* place the tool obtains a content type, and it comes
//!    from the user's explicit `;type=` attribute.
//! 2. `src/tool_formparse.c:310` -- `curl_mime_type(part, m->type)` is called
//!    unconditionally, *even when `m->type` is NULL*, which passes "none
//!    specified" down rather than guessing one here.
//! 3. `src/tool_formparse.c:669` -- the documentation comment reads "Supports
//!    specified given Content-Type of the files. Such as
//!    `;type=<content-type>`", and `:672` records that `literal_value` makes
//!    even an embedded `;type=` lose its meaning.
//!
//! Nothing in this file therefore derives a type from a filename, an extension
//! or file contents. What must *not* be concluded from that is that curl sends
//! no type: when the tool supplies none, libcurl's MIME serialiser fills one
//! in. `Curl_mime_contenttype` (`lib/mime.c:1619-1654`) matches the filename
//! against a ten-extension table -- `.gif`, `.jpg`, `.jpeg`, `.png`, `.svg`,
//! `.txt`, `.htm`, `.html`, `.pdf`, `.xml` -- and `lib/mime.c:1700-1717`
//! resolves the remainder: a multipart part takes `multipart/mixed`, while a
//! file part tries the filename, then the data, then falls back to
//! `application/octet-stream` when a filename is present (both constants at
//! `lib/mime.h:38-39`).
//!
//! For this file that is a prohibition rather than a licence. It passes the
//! user's `;type=` through and passes `None` when there is none, because
//! inferring here would preempt the serialiser and could type a part
//! differently from the way curl types it. `curl-rs/Cargo.toml` records the
//! same division as its reason for declaring no media-type-guessing crate: the
//! guessing belongs to the engine's `mime` module, which owns curl's table and
//! must not widen it. `src/tool_xattr.c:39`'s
//! `{ "user.mime_type", CURLINFO_CONTENT_TYPE }` writes the *server's*
//! `Content-Type` and is not inference either.
//!
//! # Four documented translation differences
//!
//! None of these changes the bytes the tool puts on the wire. Each is recorded
//! so a later reader does not mistake it for an oversight, and none of them
//! needed a raw-pointer escape hatch, a new dependency, or a dropped
//! behaviour.
//!
//! ## 1. Parsing is by index, not by planting NUL bytes
//!
//! C copies the argument with `curlx_strdup` (`:742`) and then chops it up in
//! place, writing NUL bytes at word ends (`:503`, `:535`, `:557`, `:586`,
//! `:608`, `:622`, `:630`) and restoring one of them again to format a warning
//! (`:876`). [`Scanner`] keeps the same mutable copy but records `(start,
//! end)` index pairs instead of terminators, and reads a byte past the end as
//! `0` so that every `*p` test against the C terminator behaves identically.
//! The one C write that genuinely moves bytes -- the in-place unescaping at
//! `:366-375` -- is reproduced exactly, with index arithmetic over a mutable
//! byte slice.
//!
//! ## 2. The MIME calls go through an injected builder
//!
//! `src/tool_formparse.c:253-335` calls `curl_mime_*` directly. Injecting such
//! a collaborator instead of reaching for it globally is what makes this file
//! testable without a live engine. The [`MimeBuilder`] trait mirrors the
//! `curl_mime_*` entry points one-to-one: twelve methods against the twelve
//! `curl_mime_*` symbols of `lib/libcurl.def`, which is the whole family and
//! nothing beyond it. No MIME serialization happens here -- the engine's `mime`
//! module is the sole serialiser, and the production implementation of this
//! trait is a thin adapter over it written by the configuration layer.
//!
//! ## 3. Allocation failure is surfaced with `try_reserve`
//!
//! Three C sites report an out-of-memory condition when `curl_slist_append`
//! or `curl_maprintf` returns NULL (`:454`, `:462`, `:588`). Rust's ordinary
//! collection growth aborts rather than returning, so those branches would be
//! silently dropped. They are kept reachable with `Vec::try_reserve`, stable
//! since Rust 1.57 and therefore inside the mandated MSRV of 1.75.
//!
//! ## 4. Standard input is buffered rather than read lazily
//!
//! `src/tool_formparse.c:129-139` avoids buffering when standard input is a
//! regular file, using `fileno`, `ftell` and `fstat` to learn its extent and
//! reading it later through `fread`/`fseek`. The standard library exposes no
//! equivalent for the process's own standard input without a raw-descriptor
//! escape hatch, which this crate does not grant, and
//! `curl-rs-lib/src/ffi/sys.rs` -- the one place reserved for genuine
//! operating-system residue -- is closed to unrelated items.
//!
//! [`StdinAccess`] therefore keeps the decision injectable and
//! [`ProcessStdin::regular_extent`] answers `None`, which selects C's own
//! buffering branch at `:140` -- the branch C takes for every pipe, terminal
//! and socket. The bytes sent are identical and so is the reported size, since
//! for a regular file `st_size - origin` equals the number of bytes a full
//! read returns. Both code paths are implemented and both are exercised by the
//! tests below through a seekable test stream. The exact engine addition that
//! would let the production binary take the lazy path is named in
//! [`ProcessStdin::regular_extent`].

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use crate::output::msgs::{self, DiagnosticSink, MsgConfig};

// Byte classification -- ASCII-only and locale-independent, as curl's is.

/// `ISBLANK` (`lib/curl_ctype.h:45`): a space or a horizontal tab.
#[allow(dead_code)]
const fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// `ISSPACE` (`lib/curl_ctype.h:46`): `ISBLANK` plus the five control bytes
/// `0x0a` through `0x0d`.
///
/// Deliberately hand-rolled rather than delegated to `u8::is_ascii_whitespace`,
/// which omits the vertical tab `0x0b` and would therefore accept a narrower
/// set than curl does. The Unicode-aware predicate on `char` is worse still --
/// it would accept a wider one. curl's own comment on the neighbouring
/// case-folding helper (`lib/strequal.c:66-72`) states the intent: "locale
/// independent", comparing only what "we know are safe".
#[allow(dead_code)]
const fn is_space(byte: u8) -> bool {
    is_blank(byte) || matches!(byte, 0x0a..=0x0d)
}

/// `ISNEWLINE` (`lib/curl_ctype.h:50`): a line feed or a carriage return.
#[allow(dead_code)]
const fn is_newline(byte: u8) -> bool {
    byte == b'\n' || byte == b'\r'
}

/// `checkprefix(prefix, data)` (`src/tool_cfgable.h:34`), which expands to
/// `curl_strnequal(data, prefix, strlen(prefix))`.
///
/// Case-insensitive over ASCII only: `curl_strnequal` (`lib/strequal.c:87`)
/// folds through `Curl_raw_toupper`, and the comment at `lib/strequal.c:66-72`
/// records that this is "meant to be locale independent" and is "capable of
/// comparing a-z case insensitively". So `;TYPE=` and `;FileName=` are
/// accepted exactly as `;type=` and `;filename=` are.
///
/// C's comparison stops at `data`'s NUL terminator and then fails, which the
/// length test reproduces: a remainder shorter than the prefix cannot match.
#[allow(dead_code)]
fn check_prefix(prefix: &[u8], data: &[u8]) -> bool {
    data.len() >= prefix.len()
        && data[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// The `strcspn` reject set that ends a content-type value
/// (`src/tool_formparse.c:516`): `"()<>@,;:\\\"[]?=\r\n "`.
///
/// Seventeen bytes -- the RFC 822 tspecials plus carriage return, line feed and
/// space. Reproduced exactly; widening or narrowing it would change which
/// bytes reach `curl_mime_type` and therefore change the emitted part header.
#[allow(dead_code)]
const CONTENT_TYPE_TERMINATORS: &[u8] = b"()<>@,;:\\\"[]?=\r\n ";

/// The filename that selects standard input (`src/tool_formparse.c:105`).
#[allow(dead_code)]
const STDIN_FILENAME: &[u8] = b"-";

// Width conversions.

/// `uztoso` (`src/tool_formparse.c:78-94`): `size_t` to `curl_off_t` with the
/// sign bit masked off.
///
/// C keeps the `DEBUGASSERT(uznum <= (size_t)CURL_MASK_SCOFFT)` and then masks
/// with `CURL_MASK_SCOFFT`, so the result is always non-negative. The
/// `debug_assert!` mirrors the `DEBUGASSERT` -- the only assertion form this
/// file uses, and only where C asserts too.
#[allow(dead_code)]
fn uztoso(value: usize) -> i64 {
    debug_assert!(
        value <= i64::MAX as usize,
        "size exceeds curl_off_t (src/tool_formparse.c:88)"
    );
    (value & (i64::MAX as usize)) as i64
}

/// `curlx_sotouz` (`lib/curlx/warnless.c:209-221`): `curl_off_t` to `size_t`,
/// for a value already known non-negative.
///
/// Used where C narrows a byte count it has just bounded, at
/// `src/tool_formparse.c:207` and `:212`. C asserts `sonum >= 0` and then
/// returns `sonum & CURL_MASK_USIZE_T`, so with assertions compiled out a
/// negative input yields the bit pattern -- `SIZE_MAX` for `-1`. This clamps to
/// zero instead, which cannot be observed: the assertion holds at every call
/// site, `m->size` is tested for `>= 0` before `:207` narrows anything, and a
/// clamp keeps the function free of any path that could index out of bounds.
#[allow(dead_code)]
fn sotouz(value: i64) -> usize {
    debug_assert!(value >= 0, "negative curl_off_t narrowed to size_t");
    if value < 0 {
        0
    } else {
        value as usize
    }
}

// `strerror` rendering: not implemented here.
//
// Two frozen diagnostics in this file interpolate `strerror(errno)` --
// `src/tool_formparse.c:220` (`stdin: %s`) and `:561`
// (`Cannot read from %s: %s`) -- and both take their text from
// `curl_rs_lib::os_error_message`, the workspace's single renderer. C yields
// just the message, for example `No such file or directory`, while Rust's
// `std::io::Error` `Display` appends ` (os error 2)`; the shared helper removes
// that annotation, so these bytes are identical to C's and to every other
// diagnostic in the tool.
//
// A local copy used to live here and stripped only ONE trailing annotation.
// That was not a stylistic difference: under Miri `std` renders two, so the
// local copy left one behind and these two frozen texts changed depending on
// which tool observed them, while `output/filetime.rs` -- rendering the same
// kind of error -- did not. Anything that reintroduces a private stripper here
// reintroduces that divergence, so nothing is defined in this section on
// purpose. See `curl-rs-lib`'s `os_error_message` for the measurement.

// The diagnostic channel.

/// The `warnf` / `errorf` channel of `src/tool_msgs.h:30-33`, bundled so that
/// the recursive parser can carry it without repeating two parameters at every
/// level.
///
/// `curl-rs/src/output/msgs.rs` owns the channel -- the `Warning: ` and
/// `curl: ` prefixes, the gates and the wrapping. It deliberately does not own
/// the *texts*: each of the sixteen frozen format strings this file emits sits
/// at its own call site, exactly as every `warnf(...)` and `errorf(...)`
/// literal does in C. Hoisting them would create a second source of truth and
/// guarantee drift.
///
/// The sink is a `&mut dyn Write` so that a test can capture the exact bytes,
/// which is what makes the frozen texts assertable.
#[allow(dead_code)]
pub(crate) struct FormDiag<'a> {
    sink: &'a mut dyn DiagnosticSink,
    config: MsgConfig,
}

impl<'a> FormDiag<'a> {
    /// Binds a diagnostic sink and the three gate predicates that decide
    /// whether a message is emitted at all.
    #[allow(dead_code)]
    pub(crate) fn new(
        sink: &'a mut dyn DiagnosticSink,
        config: MsgConfig,
    ) -> Self {
        Self { sink, config }
    }

    /// A warning whose text is entirely UTF-8, routed through
    /// `curl-rs/src/output/msgs.rs`'s `warnf`.
    #[allow(dead_code)]
    fn warn(&mut self, args: fmt::Arguments<'_>) {
        msgs::warnf(&mut *self.sink, &self.config, args);
    }

    /// A warning whose `%s` argument is a byte string that need not be UTF-8.
    ///
    /// A `-F` field can carry a filename, a header or a content type straight
    /// from the command line, and none of those is required to be valid UTF-8.
    /// Rendering such a value through `Display` would substitute U+FFFD and
    /// change the emitted bytes, which is not permitted, so
    /// the message is assembled as bytes and handed to `warnf_bytes`.
    ///
    /// `literal` is the frozen text up to and including the `%s`'s position;
    /// `value` is the interpolated argument.
    #[allow(dead_code)]
    fn warn_value(&mut self, literal: &str, value: &[u8]) {
        let mut message = Vec::new();
        message.extend_from_slice(literal.as_bytes());
        message.extend_from_slice(value);
        msgs::warnf_bytes(&mut *self.sink, &self.config, &message);
    }

    /// A warning with two byte-string arguments, for
    /// `src/tool_formparse.c:561`'s `Cannot read from %s: %s`.
    #[allow(dead_code)]
    fn warn_two_values(
        &mut self,
        literal: &str,
        first: &[u8],
        separator: &str,
        second: &[u8],
    ) {
        let mut message = Vec::new();
        message.extend_from_slice(literal.as_bytes());
        message.extend_from_slice(first);
        message.extend_from_slice(separator.as_bytes());
        message.extend_from_slice(second);
        msgs::warnf_bytes(&mut *self.sink, &self.config, &message);
    }

    /// An error, routed through `curl-rs/src/output/msgs.rs`'s `errorf`.
    #[allow(dead_code)]
    fn error(&mut self, args: fmt::Arguments<'_>) {
        msgs::errorf(&mut *self.sink, &self.config, args);
    }
}

// Standard input.

/// Everything `src/tool_formparse.c` does with the process's standard input,
/// behind one injectable contract.
///
/// C reaches for the `stdin` global at five points: `fileno`/`ftell`/`fstat`
/// to learn whether it is a regular file and where it currently is (`:121`,
/// `:128`, `:131-135`), `file2memory` to slurp it (`:143`), `fread` to read it
/// lazily (`:216`) and `fseek` to rewind it for a retry (`:244`). Injecting
/// them keeps the parser testable without a live descriptor, and is the
/// dependency-injection pattern AAP section 0.3.3 P12 prescribes.
#[allow(dead_code)]
pub(crate) trait StdinAccess {
    /// `fd >= 0 && origin >= 0 && !curlx_fstat(fd, &sbuf) && S_ISREG(...)`
    /// (`src/tool_formparse.c:131-135`).
    ///
    /// Returns `Some((origin, total_size))` when standard input is a regular
    /// file whose extent is known and which can be read lazily, where `origin`
    /// is `ftell(stdin)` (`:128`) and `total_size` is `sbuf.st_size`. `None`
    /// selects C's buffering branch at `:140`.
    fn regular_extent(&mut self) -> Option<(i64, i64)>;

    /// `file2memory(&data, &stdinsize, stdin)`
    /// (`src/tool_formparse.c:143`).
    ///
    /// On failure an implementation must leave `out` exactly as
    /// `file2memory_range` leaves its buffer: emptied. That routine's `ferror`
    /// arm frees the accumulated data and sets `*size = 0; *bufp = NULL`
    /// (`src/tool_paramhlp.c`), which is precisely why
    /// `src/tool_formparse.c:812`'s `part->size > 0` test can never fire
    /// through this path in C. Returning partial data instead would make that
    /// branch live; both behaviours are exercised by the tests below.
    fn read_all(&mut self, out: &mut Vec<u8>) -> io::Result<()>;

    /// `fread(buffer, 1, nitems, stdin)` (`src/tool_formparse.c:216`).
    ///
    /// A short return is end of input, as it is for `fread` without `ferror`.
    /// An error stands for `ferror(stdin)` and makes the read callback abort.
    fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize>;

    /// `curlx_fseek(stdin, offset, SEEK_SET)`
    /// (`src/tool_formparse.c:244`), where `offset` already includes the
    /// origin.
    ///
    /// An error stands for a non-zero `fseek` return and yields
    /// `CURL_SEEKFUNC_CANTSEEK`.
    fn seek_to(&mut self, offset: i64) -> io::Result<()>;
}

/// [`StdinAccess`] over the real process standard input.
#[derive(Debug)]
pub(crate) struct ProcessStdin {
    stdin: io::Stdin,
}

impl Default for ProcessStdin {
    fn default() -> Self {
        Self { stdin: io::stdin() }
    }
}

impl ProcessStdin {
    /// Binds the process's standard input.
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl StdinAccess for ProcessStdin {
    /// `Some` exactly when descriptor 0 is a regular file whose offset is known.
    ///
    /// The `fstat` and `lseek` this needs have no safe equivalent in `std`:
    /// `io::Stdin` implements `AsFd` but there is no metadata-from-descriptor
    /// call, and building a `File` from a raw descriptor needs the escape hatch
    /// that AAP section 0.1.1 goal G6 closes for this crate. They therefore live
    /// where AAP section 0.8.5 conflict C3 puts such residue --
    /// `curl-rs-lib/src/ffi/sys.rs`, behind the injected `SysCalls` seam -- and
    /// arrive here as `curl_rs_lib::regular_file_extent`.
    ///
    /// [`None`] selects C's buffering branch at `src/tool_formparse.c:140` and
    /// is the answer for every pipe, socket, terminal and directory, exactly as
    /// C's compound condition at `:131-135` collapses all of them into it.
    fn regular_extent(&mut self) -> Option<(i64, i64)> {
        curl_rs_lib::regular_file_extent(self.stdin.as_fd())
    }

    fn read_all(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
        match self.stdin.read_to_end(out) {
            Ok(_) => Ok(()),
            Err(error) => {
                // `file2memory_range`'s `ferror` arm discards what it read;
                // see [`StdinAccess::read_all`].
                out.clear();
                Err(error)
            }
        }
    }

    /// Reads the descriptor, deliberately **not** the buffered [`io::Stdin`].
    ///
    /// This path is taken only when [`Self::regular_extent`] answered `Some`,
    /// and on that path [`Self::seek_to`] repositions the same descriptor for a
    /// retry. Reading through `io::Stdin` would leave its internal buffer
    /// holding bytes from before the seek, and the retry would replay them. C
    /// has no such hazard because `fseek` on a `FILE *` discards that stream's
    /// own buffer; keeping both operations on the raw descriptor is how the same
    /// property is obtained here.
    fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        curl_rs_lib::read_file_descriptor(self.stdin.as_fd(), buffer)
    }

    fn seek_to(&mut self, offset: i64) -> io::Result<()> {
        // `fseek` on a stream that cannot seek returns non-zero, which
        // `src/tool_formparse.c:244-245` turns into CURL_SEEKFUNC_CANTSEEK. That
        // is now a real answer from `lseek` rather than an unconditional
        // refusal: the lazy path is reachable, so this is reachable with it.
        curl_rs_lib::seek_file_descriptor(self.stdin.as_fd(), offset)
    }
}

/// The outcome of [`StdinSource::read`], mirroring the `curl_read_callback`
/// contract that `src/tool_formparse.c:195-227` implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum StdinRead {
    /// The number of bytes placed in the caller's buffer. `0` is end of input,
    /// which is what `:204` returns at `curpos >= size`.
    Bytes(usize),

    /// `CURL_READFUNC_ABORT` (`src/tool_formparse.c:221`), returned after the
    /// `stdin: %s` warning.
    Abort,
}

/// The outcome of [`StdinSource::seek`], mirroring the `curl_seek_callback`
/// contract that `src/tool_formparse.c:229-249` implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum StdinSeek {
    /// `CURL_SEEKFUNC_OK` (`src/tool_formparse.c:248`).
    Done,

    /// `CURL_SEEKFUNC_CANTSEEK` (`src/tool_formparse.c:242`, `:245`).
    CantSeek,
}

/// The three `whence` values `src/tool_formparse.c:233-240` handles.
///
/// `SEEK_SET` is the `switch`'s implicit default: it falls through with the
/// offset untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum SeekWhence {
    /// `SEEK_SET`.
    Set,
    /// `SEEK_CUR` (`src/tool_formparse.c:234-236`).
    Cur,
    /// `SEEK_END` (`src/tool_formparse.c:237-239`).
    End,
}

/// The standard-input state of a `TOOLMIME_STDIN` or `TOOLMIME_STDINDATA`
/// part.
///
/// These are the four fields `src/tool_formparse.h:54-57` groups under the
/// comment "TOOLMIME_STDIN/TOOLMIME_STDINDATA fields", plus C's shared `data`
/// pointer, which for those two kinds holds the buffered content rather than a
/// filename.
///
/// The buffer is an `Arc<[u8]>` so that handing a copy to the MIME builder is
/// cheap: the bytes are read-only once captured, and only `curpos` is
/// per-reader state.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct StdinSource {
    /// `m->data`: the buffered content, or `None` when it is to be read
    /// lazily. `src/tool_formparse.c:210` and `:243` both branch on this
    /// pointer being non-NULL, so the distinction is load-bearing rather than
    /// an optimization -- an empty-but-present buffer reports end of input,
    /// while an absent one reads from the stream.
    data: Option<Arc<[u8]>>,

    /// `m->origin`: `ftell(stdin)` when the part was captured
    /// (`src/tool_formparse.c:128`, `:159`), added back when seeking.
    origin: i64,

    /// `m->size`: the part's length, or `-1` once a read error has been
    /// deferred (`src/tool_formparse.c:817`, `:850`).
    size: i64,

    /// `m->curpos`: how far the reader has got.
    curpos: i64,
}

impl StdinSource {
    /// The part's length as `curl_mime_data_cb` receives it
    /// (`src/tool_formparse.c:296`). `-1` means unknown.
    #[allow(dead_code)]
    pub(crate) const fn size(&self) -> i64 {
        self.size
    }

    /// `src/tool_formparse.c:816-818`: drops the buffer, marks the length
    /// unknown and lets libcurl rediscover the read error during the transfer.
    ///
    /// The C comment at `:810-811` states the intent: "if read has started,
    /// issue the error now. Else, delay it until processed by libcurl."
    #[allow(dead_code)]
    fn defer_read_error(&mut self) {
        self.data = None;
        self.size = -1;
    }

    /// `tool_mime_stdin_read` (`src/tool_formparse.c:195-227`).
    ///
    /// C's `size` parameter is "Always 1: ignored" (`:200`), so the request is
    /// simply the caller's buffer length.
    #[allow(dead_code)]
    pub(crate) fn read(
        &mut self,
        buffer: &mut [u8],
        stdin: &mut dyn StdinAccess,
        diag: &mut FormDiag<'_>,
    ) -> StdinRead {
        let mut nitems = buffer.len();

        // :202-208 -- a known length bounds the read and defines end of input.
        if self.size >= 0 {
            if self.curpos >= self.size {
                return StdinRead::Bytes(0);
            }
            let bytesleft = self.size - self.curpos;
            if uztoso(nitems) > bytesleft {
                nitems = sotouz(bytesleft);
            }
        }

        if nitems > 0 {
            match self.data.as_deref() {
                // :210-213 -- return data from memory.
                Some(data) => {
                    debug_assert!(
                        sotouz(self.curpos).saturating_add(nitems)
                            <= data.len(),
                        "buffered stdin read beyond the captured length"
                    );
                    let start = sotouz(self.curpos).min(data.len());
                    let end = start.saturating_add(nitems).min(data.len());
                    let chunk = &data[start..end];
                    nitems = chunk.len();
                    buffer[..nitems].copy_from_slice(chunk);
                }
                // :214-223 -- read from the stream.
                None => match stdin.read_chunk(&mut buffer[..nitems]) {
                    Ok(count) => nitems = count,
                    Err(error) => {
                        // :217-222 -- "Show error only once."
                        diag.warn_value(
                            "stdin: ",
                            curl_rs_lib::os_error_message(&error).as_bytes(),
                        );
                        return StdinRead::Abort;
                    }
                },
            }
            self.curpos += uztoso(nitems);
        }
        StdinRead::Bytes(nitems)
    }

    /// `tool_mime_stdin_seek` (`src/tool_formparse.c:229-249`).
    ///
    /// The additions are saturating rather than wrapping. C's are plain `+=` on
    /// a `curl_off_t`, so an overflow there would be undefined; saturating
    /// keeps the result finite and still fails closed, because any value that
    /// could overflow is far beyond the part's length and the subsequent seek
    /// or bounds check rejects it.
    #[allow(dead_code)]
    pub(crate) fn seek(
        &mut self,
        offset: i64,
        whence: SeekWhence,
        stdin: &mut dyn StdinAccess,
    ) -> StdinSeek {
        let offset = match whence {
            SeekWhence::Set => offset,
            SeekWhence::Cur => offset.saturating_add(self.curpos),
            SeekWhence::End => offset.saturating_add(self.size),
        };

        if offset < 0 {
            return StdinSeek::CantSeek;
        }

        // :243-246 -- only an unbuffered part seeks the stream.
        if self.data.is_none()
            && stdin.seek_to(offset.saturating_add(self.origin)).is_err()
        {
            return StdinSeek::CantSeek;
        }

        self.curpos = offset;
        StdinSeek::Done
    }
}

// The tool-local MIME tree.

/// `toolmimekind` (`src/tool_formparse.h:30-38`), value for value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum ToolMimeKind {
    /// `TOOLMIME_NONE`: the `curlx_calloc` default. C's translation switch
    /// notes at `src/tool_formparse.c:302-304` that the remaining cases are
    /// "not possible in this context"; the variant exists so the enumeration
    /// matches the C one.
    #[allow(dead_code)]
    None,

    /// `TOOLMIME_PARTS`: a nested multipart, opened by `(`.
    Parts,

    /// `TOOLMIME_DATA`: literal field content.
    Data,

    /// `TOOLMIME_FILE`: a file uploaded with `@`, whose name is sent.
    File,

    /// `TOOLMIME_FILEDATA`: a file's contents read with `<`, whose name is
    /// not sent.
    FileData,

    /// `TOOLMIME_STDIN`: standard input read with `@-`, reported as `-`.
    Stdin,

    /// `TOOLMIME_STDINDATA`: standard input read with `<-`, unnamed.
    StdinData,
}

/// `struct tool_mime` (`src/tool_formparse.h:40-58`).
///
/// Three of C's fields have no counterpart, and their absence is the point.
/// `parent` and `prev` are the intrusive links replaced by owned collections:
/// children live in [`ToolMime::subparts`] in the order
/// the user wrote them, and the walk back to a parent is a
/// [`MimeTree`] cursor rather than a pointer. `kind` keeps its own field
/// because the `--libcurl` emitter and the translation switch both dispatch on
/// it.
///
/// The tree owns everything it holds, so `tool_mime_free`
/// (`src/tool_formparse.c:177-192`) has no counterpart either: dropping the
/// root frees the whole tree. No `Drop` implementation is needed or wanted.
///
/// C's `type` field is spelled `content_type` here because `type` is a Rust
/// keyword. It holds the user's explicit `;type=` value and nothing else -- see
/// the module documentation on content-type inference.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct ToolMime {
    /// `m->kind`.
    pub(crate) kind: ToolMimeKind,

    /// `m->data`: literal content for [`ToolMimeKind::Data`], or the filename
    /// for [`ToolMimeKind::File`] and [`ToolMimeKind::FileData`].
    ///
    /// For the two standard-input kinds the buffered content lives in
    /// [`ToolMime::stdin`] instead, which is where C's shared `data` pointer
    /// points for those kinds.
    pub(crate) data: Option<Vec<u8>>,

    /// `m->name`: the field name, set last (`src/tool_formparse.c:882`).
    pub(crate) name: Option<Vec<u8>>,

    /// `m->filename`: the `;filename=` override.
    pub(crate) filename: Option<Vec<u8>>,

    /// `m->type`: the `;type=` value, and only that.
    pub(crate) content_type: Option<Vec<u8>>,

    /// `m->encoder`: the `;encoder=` value.
    pub(crate) encoder: Option<Vec<u8>>,

    /// `m->headers`: the `;headers=` list.
    ///
    /// C uses a `struct curl_slist *`. `curl_slist` keeps its C shape at the
    /// ABI boundary only; internally it is a `Vec`.
    pub(crate) headers: Vec<Vec<u8>>,

    /// `m->subparts`, but in the order the user wrote them.
    ///
    /// C prepends (`src/tool_formparse.c:42-43`: `m->prev = parent->subparts;
    /// parent->subparts = m;`) so its list runs newest-first, and
    /// `tool2curlparts` compensates by recursing on `m->prev` before emitting
    /// `m` (`:262`). The net effect is user order, which a forward `Vec` gives
    /// directly. `subparts.last()` is therefore C's `parent->subparts` -- the
    /// most recently added child, which `:826` names.
    pub(crate) subparts: Vec<ToolMime>,

    /// The standard-input state, present exactly for
    /// [`ToolMimeKind::Stdin`] and [`ToolMimeKind::StdinData`].
    pub(crate) stdin: Option<StdinSource>,
}

impl ToolMime {
    /// `tool_mime_new` (`src/tool_formparse.c:33-47`) without the parent link:
    /// a zeroed node of the given kind.
    #[allow(dead_code)]
    fn new(kind: ToolMimeKind) -> Self {
        Self {
            kind,
            data: None,
            name: None,
            filename: None,
            content_type: None,
            encoder: None,
            headers: Vec::new(),
            subparts: Vec::new(),
            stdin: None,
        }
    }

    /// `tool_mime_new_data` (`src/tool_formparse.c:54-69`).
    #[allow(dead_code)]
    fn new_data(data: &[u8]) -> Self {
        let mut node = Self::new(ToolMimeKind::Data);
        node.data = Some(data.to_vec());
        node
    }
}

/// The pair of handles `formparse` threads through
/// `struct OperationConfig` -- `mimeroot` and `mimecurrent`
/// (`src/tool_cfgable.h:151-152`).
///
/// `mimeroot` is the outermost `TOOLMIME_PARTS` node; `mimecurrent` is the
/// group that the next field joins, which `(` pushes into and `)` pops out of.
/// Here the cursor is the path of child indices from the root, so
/// [`MimeTree::at_root`] is C's `*mimecurrent == *mimeroot`
/// (`src/tool_formparse.c:769`) and popping the path is C's
/// `*mimecurrent = (*mimecurrent)->parent` (`:773`) -- without a parent
/// pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct MimeTree {
    root: ToolMime,
    current: Vec<usize>,
}

impl Default for MimeTree {
    /// `tool_mime_new_parts(NULL)` (`src/tool_formparse.c:735`), with the
    /// cursor on the root.
    fn default() -> Self {
        Self {
            root: ToolMime::new(ToolMimeKind::Parts),
            current: Vec::new(),
        }
    }
}

impl MimeTree {
    /// An empty tree whose root is the outermost multipart.
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The root group, which is what `tool2curlmime` is handed
    /// (`src/config2setopts.c:800` passes `config->mimeroot`).
    #[allow(dead_code)]
    pub(crate) fn root(&self) -> &ToolMime {
        &self.root
    }

    /// Whether the cursor is still on the root, i.e. C's
    /// `*mimecurrent == *mimeroot` (`src/tool_formparse.c:769`).
    #[allow(dead_code)]
    fn at_root(&self) -> bool {
        self.current.is_empty()
    }

    /// The cursor itself: the path to C's `*mimecurrent`.
    #[allow(dead_code)]
    fn current_path(&self) -> &[usize] {
        &self.current
    }

    /// Walks `path` from `root`, stopping early if a step is missing.
    ///
    /// A missing step cannot occur: every path this module builds is the index
    /// of a child it has just pushed, and nothing removes children. The early
    /// return exists so that the walk cannot fault, which is why there is no
    /// fallible accessor anywhere above it.
    #[allow(dead_code)]
    fn node_at_mut<'t>(
        root: &'t mut ToolMime,
        path: &[usize],
    ) -> &'t mut ToolMime {
        let mut node = root;
        for &index in path {
            // Checked before the step is taken, so the step itself cannot
            // fault and needs no fallible arm.
            let reachable = index < node.subparts.len();
            debug_assert!(reachable, "MimeTree cursor left the tree");
            if !reachable {
                break;
            }
            node = &mut node.subparts[index];
        }
        node
    }

    /// The group the next field joins: C's `*mimecurrent`.
    #[allow(dead_code)]
    fn current_mut(&mut self) -> &mut ToolMime {
        Self::node_at_mut(&mut self.root, &self.current)
    }

    /// The node `path` names.
    #[allow(dead_code)]
    fn node_mut(&mut self, path: &[usize]) -> &mut ToolMime {
        Self::node_at_mut(&mut self.root, path)
    }

    /// Appends `node` to the group at `path` and returns the path to it.
    ///
    /// This is what `tool_mime_new`'s parent link does
    /// (`src/tool_formparse.c:40-44`): the node joins its group at creation,
    /// before any attribute is applied to it, which is why the standard-input
    /// error at `:812` can leave a half-configured node in the tree.
    #[allow(dead_code)]
    fn push_child(&mut self, path: &[usize], node: ToolMime) -> Vec<usize> {
        let index = {
            let group = Self::node_at_mut(&mut self.root, path);
            group.subparts.push(node);
            group.subparts.len() - 1
        };
        let mut child = path.to_vec();
        child.push(index);
        child
    }

    /// Appends `node` to C's `*mimecurrent` and returns the path to it.
    #[allow(dead_code)]
    fn push_current(&mut self, node: ToolMime) -> Vec<usize> {
        let path = self.current.clone();
        self.push_child(&path, node)
    }

    /// The path to the most recently added child of `*mimecurrent`, which is
    /// what `src/tool_formparse.c:826`'s `(*mimecurrent)->subparts` names.
    #[allow(dead_code)]
    fn last_child_path(&mut self) -> Option<Vec<usize>> {
        let count = self.current_mut().subparts.len();
        if count == 0 {
            return None;
        }
        let mut path = self.current.clone();
        path.push(count - 1);
        Some(path)
    }

    /// `*mimecurrent = part` (`src/tool_formparse.c:762`).
    #[allow(dead_code)]
    fn descend(&mut self, path: Vec<usize>) {
        self.current = path;
    }

    /// `*mimecurrent = (*mimecurrent)->parent` (`src/tool_formparse.c:773`).
    #[allow(dead_code)]
    fn ascend(&mut self) {
        self.current.pop();
    }
}

// Failure signals.

/// The single failure signal `formparse` reports.
///
/// C returns `int` and has exactly one failure value: any non-zero result is
/// turned into `PARAM_BAD_USE` by the one caller,
/// `src/tool_getparam.c:2769-2771`. There is therefore nothing to carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct FormParseError;

/// An allocation that could not be made, standing for a `curl_slist_append` or
/// `curl_maprintf` that returned NULL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
struct OutOfMemory;

/// `slist_append` (`src/tool_formparse.c:400-409`): appends `data` to `list`,
/// reporting failure rather than aborting.
///
/// `Vec::try_reserve` keeps C's out-of-memory arm reachable; see translation
/// difference 3 in the module documentation.
#[allow(dead_code)]
fn slist_append(
    list: &mut Vec<Vec<u8>>,
    data: &[u8],
) -> Result<(), OutOfMemory> {
    if list.try_reserve(1).is_err() {
        return Err(OutOfMemory);
    }
    let mut item = Vec::new();
    if item.try_reserve(data.len()).is_err() {
        return Err(OutOfMemory);
    }
    item.extend_from_slice(data);
    list.push(item);
    Ok(())
}

// Reading field headers from a file.

/// C's `char buffer[128]` for `fgets` (`src/tool_parsecfg.c:283`) holds at most
/// 127 payload bytes before the terminator.
#[allow(dead_code)]
const FGETS_CAPACITY: usize = 127;

/// The `toobig` bound of both dynamic buffers `read_field_headers` uses.
///
/// `curlx_dyn_init(&line, 8092)` at `src/tool_formparse.c:418` and
/// `curlx_dyn_init(&amend, 8092)` at `:439`. The literal is the same in both, and
/// so is the bound applied here.
///
/// Without it, a `-F 'name=@file;headers=@hdrs'` whose header file contains a
/// single overlong line -- or a fold chain that grows without limit -- makes the
/// tool accumulate the whole thing in memory, where the oracle refuses at 8 KiB.
/// The header file is named on the command line, so its size is attacker-chosen
/// whenever the command line is.
const HEADER_DYNBUF_TOOBIG: usize = 8092;

/// Whether `curlx_dyn_addn` would accept `added` more bytes on top of `held`.
///
/// `lib/curlx/dynbuf.c:72,82-85` computes `fit = len + idx + 1` -- the new bytes,
/// the bytes already held, and the terminating NUL C always leaves room for --
/// and returns `CURLE_TOO_LARGE` when `fit > toobig`. **The consequence is that
/// the largest content a 8092-byte buffer accepts is 8091 bytes, not 8092**, and
/// that off-by-one is reproduced rather than rounded off: it decides the exact
/// input at which the oracle starts refusing.
///
/// `saturating_add` cannot mask a real overflow into acceptance, because the
/// saturated value is `usize::MAX`, which fails the comparison.
fn dynbuf_would_fit(held: usize, added: usize) -> bool {
    let fit = added.saturating_add(held).saturating_add(1);
    fit <= HEADER_DYNBUF_TOOBIG
}

/// The `fgets`-based line reader `read_field_headers` drives.
///
/// `src/tool_formparse.c:419` calls `my_get_line`
/// (`src/tool_parsecfg.c:325-347`), which filters blank and comment lines and
/// delegates to `get_line` (`src/tool_parsecfg.c:281-323`), which in turn calls
/// `fgets`. All three are reproduced, including the two details that a
/// higher-level line iterator would quietly change: the 127-byte chunking, and
/// `strlen`'s truncation of a chunk at an embedded NUL.
///
/// In C the length bound belongs to the *caller*, because `get_line` writes into
/// a dynamic buffer the caller initialised: `read_field_headers` supplies an
/// 8092-byte one (`src/tool_formparse.c:418`) while `parseconfig` supplies a
/// `MAX_CONFIG_LINE_LENGTH` one (`src/tool_parsecfg.c:130`). This reproduction
/// serves only the first caller and therefore hard-codes
/// [`HEADER_DYNBUF_TOOBIG`]; both it and this type are private to the module so
/// that a future `parseconfig` cannot inherit the wrong bound by reusing them.
#[allow(dead_code)]
struct TextLines<'r> {
    input: &'r mut dyn Read,

    /// `feof(input)`, consulted at `src/tool_parsecfg.c:306`.
    eof: bool,
}

impl TextLines<'_> {
    /// `fgets(buffer, sizeof(buffer), input)`: at most [`FGETS_CAPACITY`]
    /// bytes, stopping after a line feed.
    ///
    /// Returns whether `fgets` would have returned its buffer rather than NULL.
    /// A read error is reported as NULL, which is what `fgets` does, and the
    /// caller then takes C's own `else if(curlx_dyn_len(buf))` path.
    #[allow(dead_code)]
    fn fgets(&mut self, chunk: &mut Vec<u8>) -> bool {
        chunk.clear();
        while chunk.len() < FGETS_CAPACITY {
            let mut byte = [0u8; 1];
            match self.input.read(&mut byte) {
                Ok(0) => {
                    self.eof = true;
                    break;
                }
                Ok(_) => {
                    chunk.push(byte[0]);
                    if byte[0] == b'\n' {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        !chunk.is_empty()
    }

    /// `get_line` (`src/tool_parsecfg.c:281-323`): one whole line with its
    /// trailing line feed removed.
    #[allow(dead_code)]
    fn get_line(&mut self, line: &mut Vec<u8>) -> bool {
        line.clear();
        let mut chunk = Vec::new();
        loop {
            if self.fgets(&mut chunk) {
                // `strlen(b)`: the chunk ends at an embedded NUL.
                let rlen = match chunk.iter().position(|&byte| byte == 0) {
                    Some(nul) => nul,
                    None => chunk.len(),
                };
                // :288-289 -- `if(!rlen) break;`, abandoning the whole read.
                if rlen == 0 {
                    return false;
                }
                // `:295-300` -- `curlx_dyn_addn(buf, b, rlen)` and the
                // `if(result)` arm: "too long line or out of memory" sets
                // `*error = TRUE` and returns FALSE. `curlx_dyn_addn` also frees
                // the buffer on that path (`lib/curlx/dynbuf.c:83`), discarding
                // the partial line, so `clear()` precedes the return.
                //
                // The `error` flag itself needs no counterpart: `my_get_line`
                // breaks out of its loop on `!*error && retcode` being false, and
                // `retcode` is already FALSE here, so both of C's failure reasons
                // reach `read_field_headers` as the same "no more lines" answer.
                // That is why the caller's `err` stays 0 and an over-long header
                // line truncates the list rather than failing the transfer --
                // faithfully reproduced, and asserted by
                // `an_over_long_header_line_truncates_the_list_without_an_error`.
                if !dynbuf_would_fit(line.len(), rlen) {
                    line.clear();
                    return false;
                }
                line.extend_from_slice(&chunk[..rlen]);
                let last = match chunk.get(rlen - 1) {
                    Some(&byte) => byte,
                    None => 0,
                };
                // :299-303 -- end of the line, drop the newline.
                if last == b'\n' {
                    line.pop();
                    return true;
                }
                if self.eof {
                    return true;
                }
            } else {
                // C exits twice here (`src/tool_parsecfg.c:309-313`): a
                // non-empty buffer is a final line that had no newline, an
                // empty one is a plain end of input.
                return !line.is_empty();
            }
        }
    }

    /// `my_get_line` (`src/tool_parsecfg.c:325-347`): `get_line` with blank and
    /// `#`-commented lines skipped.
    ///
    /// The comment check skips leading blanks first, so ` # x` is a comment
    /// too -- which is why `src/tool_formparse.c:423`'s own `ptr[0] == '#'`
    /// test can never fire. It is reproduced there all the same.
    #[allow(dead_code)]
    fn my_get_line(&mut self, line: &mut Vec<u8>) -> bool {
        loop {
            if !self.get_line(line) {
                return false;
            }
            if line.is_empty() {
                continue;
            }
            let mut index = 0;
            while is_blank(byte_of(line, index)) {
                index += 1;
            }
            let first = byte_of(line, index);
            if first == b'#' || first == 0 {
                continue;
            }
            return true;
        }
    }
}

/// The byte at `index`, or `0` past the end -- C's read of a NUL-terminated
/// buffer.
#[allow(dead_code)]
fn byte_of(bytes: &[u8], index: usize) -> u8 {
    match bytes.get(index) {
        Some(&byte) => byte,
        None => 0,
    }
}

/// `read_field_headers` (`src/tool_formparse.c:412-469`).
///
/// Read errors are deliberately ignored: C captures `my_get_line`'s `error`
/// flag at `:415` and never tests it after the loop, so a truncated header file
/// simply contributes fewer headers.
#[allow(dead_code)]
fn read_field_headers(
    input: &mut dyn Read,
    headers: &mut Vec<Vec<u8>>,
    diag: &mut FormDiag<'_>,
) -> Result<(), FormParseError> {
    let mut lines = TextLines { input, eof: false };
    let mut line = Vec::new();

    while lines.my_get_line(&mut line) {
        let first = byte_of(&line, 0);
        if first == b'#' {
            continue;
        }
        let folded = first == b' ';

        // :427-429 -- trim off trailing CRLFs and whitespaces.
        let mut len = line.len();
        while len > 0 {
            let byte = byte_of(&line, len - 1);
            if !is_newline(byte) && !is_blank(byte) {
                break;
            }
            len -= 1;
        }

        if len == 0 {
            continue;
        }
        // :433 -- `curlx_dyn_setlen`.
        line.truncate(len);

        if folded && !headers.is_empty() {
            // :435-457 -- append this new line onto the previous line. The
            // continuation's leading blanks are kept, exactly as C's
            // `curlx_dyn_addn(&amend, ptr, len)` keeps them.
            let existing = match headers.last() {
                Some(last) => last.len(),
                None => 0,
            };
            let mut amend = Vec::new();
            // :443 -- `curlx_dyn_add(&amend, l->data) || curlx_dyn_addn(&amend,
            // ptr, len)`. Two appends into one 8092-byte buffer, so the bound is
            // checked twice against the running length, exactly as the C's two
            // calls do. Either refusal takes the same `:444-447` arm as an
            // allocation failure, which is what C's `||` already expresses:
            // `CURLE_TOO_LARGE` and `CURLE_OUT_OF_MEMORY` are both simply
            // non-zero there.
            let too_large = !dynbuf_would_fit(0, existing)
                || !dynbuf_would_fit(existing, line.len());
            if too_large
                || amend
                    .try_reserve(existing.saturating_add(line.len()))
                    .is_err()
            {
                // :444-447 -- `err = -1; break;` with no message at all,
                // because the `break` skips the shared report below.
                return Err(FormParseError);
            }
            if let Some(last) = headers.last() {
                amend.extend_from_slice(last);
            }
            amend.extend_from_slice(&line);

            // :449-451 -- the `curl_maprintf` copy that replaces the node's
            // data, and :453-456 its own failure report.
            let mut replacement = Vec::new();
            if replacement.try_reserve(amend.len()).is_err() {
                diag.error(format_args!("Out of memory for field headers"));
                // :461-465 -- reached with `err = 1`, so this second,
                // identically worded report is emitted too. Both sites are
                // preserved deliberately.
                diag.error(format_args!("Out of memory for field headers"));
                return Err(FormParseError);
            }
            replacement.extend_from_slice(&amend);
            if let Some(last) = headers.last_mut() {
                *last = replacement;
            }
        } else if slist_append(headers, &line).is_err() {
            // :459 then :461-465.
            diag.error(format_args!("Out of memory for field headers"));
            return Err(FormParseError);
        }
    }

    Ok(())
}

// The scanner.

/// A half-open byte range into [`Scanner::buffer`].
///
/// This is what replaces C's planted NUL terminators; see translation
/// difference 1 in the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
struct Span {
    start: usize,
    end: usize,
}

impl Span {
    /// Whether the range is empty, which is C's test of the first byte of a
    /// freshly terminated word -- `if(*unknown)` at
    /// `src/tool_formparse.c:623`.
    #[allow(dead_code)]
    const fn is_empty(self) -> bool {
        self.end <= self.start
    }
}

/// One word from `get_param_word`, with the fact the callers need in order to
/// decide whether to strip trailing blanks.
#[derive(Clone, Copy, Debug)]
#[allow(dead_code)]
struct Word {
    span: Span,

    /// Whether the word was quoted.
    ///
    /// C infers this by comparing the returned pointer against the position it
    /// passed in (`src/tool_formparse.c:499`, `:531`, `:553`, `:582`, `:604`):
    /// a quoted word starts one byte later. Carrying the fact explicitly says
    /// the same thing, and gets the missing-end-quote case right for the same
    /// reason C does -- the fallback at `:389-390` rewinds to the original
    /// position, so the word counts as unquoted.
    quoted: bool,
}

/// Which byte class a caller strips from the tail of an unquoted word.
///
/// The asymmetry is real and is preserved: four sites use `ISBLANK`
/// (`src/tool_formparse.c:500`, `:532`, `:554`, `:583`) and the `;encoder=`
/// site uses `ISSPACE` (`:605`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum TrailingClass {
    /// `ISBLANK`: space and tab only.
    Blank,
    /// `ISSPACE`: `ISBLANK` plus `0x0a` through `0x0d`.
    Space,
}

/// Which of `get_param_part`'s out-parameters the caller passed as non-NULL.
///
/// C signals "this attribute is not accepted here" by passing NULL, and then
/// warns if the attribute turned up anyway
/// (`src/tool_formparse.c:632-652`). The four call sites in `formparse` use
/// three distinct combinations, given as the associated constants below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
struct Slots {
    content_type: bool,
    filename: bool,
    encoder: bool,
    headers: bool,
}

impl Slots {
    /// `@` (`src/tool_formparse.c:785-786`) and literal data (`:858-859`):
    /// every attribute is accepted.
    #[allow(dead_code)]
    const ALL: Self = Self {
        content_type: true,
        filename: true,
        encoder: true,
        headers: true,
    };

    /// `(` (`src/tool_formparse.c:756`): no filename and no encoder, so both
    /// trip their "not allowed here" warning.
    #[allow(dead_code)]
    const GROUP: Self = Self {
        content_type: true,
        filename: false,
        encoder: false,
        headers: true,
    };

    /// `<` (`src/tool_formparse.c:831-832`): `;type=` and `;encoder=` are
    /// accepted, `;filename=` is not.
    #[allow(dead_code)]
    const FILE_CONTENT: Self = Self {
        content_type: true,
        filename: false,
        encoder: true,
        headers: true,
    };
}

/// The attributes and content one `get_param_part` call produced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(dead_code)]
struct ParamPart {
    /// The word before the first `;`.
    data: Vec<u8>,

    /// The `;type=` value, when accepted here.
    content_type: Option<Vec<u8>>,

    /// The `;filename=` value, when accepted here.
    filename: Option<Vec<u8>>,

    /// The `;encoder=` value, when accepted here.
    encoder: Option<Vec<u8>>,

    /// The `;headers=` list, when accepted here.
    headers: Vec<Vec<u8>>,

    /// The byte the scan stopped on: C's `return sep & 0xFF`
    /// (`src/tool_formparse.c:655`). `0` is the end of the field.
    sep: u8,
}

/// The mutable copy of the `-F` argument, plus the read position.
///
/// C makes the copy at `src/tool_formparse.c:742` precisely so it can be
/// overwritten. The copy is kept for the same reason -- the in-place unescaping
/// at `:366-375` genuinely moves bytes -- but word boundaries are recorded as
/// [`Span`]s rather than written into the buffer.
#[allow(dead_code)]
struct Scanner {
    buffer: Vec<u8>,
    pos: usize,
}

impl Scanner {
    /// `contents = curlx_strdup(input)` (`src/tool_formparse.c:742`).
    ///
    /// `curlx_strdup` copies a C string, so it stops at the first NUL and
    /// everything after it is invisible to the parser. Truncating here reaches
    /// the same state once, rather than repeating the test at every read.
    /// Command-line arguments cannot contain a NUL, so in practice the whole
    /// argument is kept; the truncation exists so that a caller which does pass
    /// one is handled exactly as C handles it.
    #[allow(dead_code)]
    fn new(input: &[u8]) -> Self {
        let end = match input.iter().position(|&byte| byte == 0) {
            Some(index) => index,
            None => input.len(),
        };
        Self {
            buffer: input[..end].to_vec(),
            pos: 0,
        }
    }

    /// The byte at `index`, or `0` past the end.
    ///
    /// This is what makes every `*p` test read exactly as C's does, including
    /// the loops that stop on the terminator and the `endchar == '\0'` calls
    /// whose end condition therefore collapses into the same test.
    #[allow(dead_code)]
    fn byte_at(&self, index: usize) -> u8 {
        byte_of(&self.buffer, index)
    }

    /// The byte at the read position: C's `*p`.
    #[allow(dead_code)]
    fn current(&self) -> u8 {
        self.byte_at(self.pos)
    }

    /// The bytes a [`Span`] covers.
    #[allow(dead_code)]
    fn slice(&self, span: Span) -> &[u8] {
        let end = span.end.min(self.buffer.len());
        let start = span.start.min(end);
        &self.buffer[start..end]
    }

    /// A [`Span`]'s bytes, copied out of the buffer.
    #[allow(dead_code)]
    fn owned(&self, span: Span) -> Vec<u8> {
        self.slice(span).to_vec()
    }

    /// Everything from the read position onwards: C's `contp` seen as a string.
    #[allow(dead_code)]
    fn remainder(&self) -> &[u8] {
        let start = self.pos.min(self.buffer.len());
        &self.buffer[start..]
    }

    /// `while(ISBLANK(*p)) p++;` (`src/tool_formparse.c:494-495` and the four
    /// per-attribute repetitions).
    #[allow(dead_code)]
    fn skip_blanks(&mut self) {
        while is_blank(self.current()) {
            self.pos += 1;
        }
    }

    /// `checkprefix(prefix, p)` at the read position.
    #[allow(dead_code)]
    fn at_prefix(&self, prefix: &[u8]) -> bool {
        check_prefix(prefix, self.remainder())
    }

    /// `strcspn(p, set)` as an absolute end index
    /// (`src/tool_formparse.c:516-517`).
    #[allow(dead_code)]
    fn strcspn(&self, set: &[u8]) -> usize {
        let mut index = self.pos;
        while self.byte_at(index) != 0 && !set.contains(&self.byte_at(index)) {
            index += 1;
        }
        index
    }

    /// The callers' "If not quoted, strip trailing spaces" step.
    #[allow(dead_code)]
    fn strip_trailing(&self, word: Word, class: TrailingClass) -> Span {
        let mut span = word.span;
        if word.quoted {
            return span;
        }
        while span.end > span.start {
            let byte = self.byte_at(span.end - 1);
            let strip = match class {
                TrailingClass::Blank => is_blank(byte),
                TrailingClass::Space => is_space(byte),
            };
            if !strip {
                break;
            }
            span.end -= 1;
        }
        span
    }

    /// `get_param_word` (`src/tool_formparse.c:342-397`).
    ///
    /// After the call the read position is either the end of the buffer or one
    /// of the end characters, which is the contract C's comment at `:337-341`
    /// states.
    #[allow(dead_code)]
    fn get_param_word(&mut self, endchar: u8, diag: &mut FormDiag<'_>) -> Word {
        let word_begin = self.pos;
        let mut ptr = self.pos;
        let mut escape: Option<usize> = None;

        // :350 -- a leading double quote opens a quoted word.
        if self.byte_at(ptr) == b'"' {
            ptr += 1;
            while self.byte_at(ptr) != 0 {
                // :353-361 -- inside a quoted word only \\ and \" escape.
                if self.byte_at(ptr) == b'\\' {
                    let next = self.byte_at(ptr + 1);
                    if next == b'\\' || next == b'"' {
                        // :355-357 -- remember the first escape position.
                        if escape.is_none() {
                            escape = Some(ptr);
                        }
                        ptr += 2;
                        continue;
                    }
                }

                if self.byte_at(ptr) == b'"' {
                    let mut end_pos = ptr;

                    if let Some(escape) = escape {
                        // :366-375 -- restore the unescaped string in place.
                        // The rewrite is confined to the quoted word, so every
                        // span already recorded stays valid and the bytes after
                        // the closing quote are untouched.
                        let mut src = escape;
                        let mut dst = escape;
                        loop {
                            if self.byte_at(src) == b'\\' {
                                let next = self.byte_at(src + 1);
                                if next == b'\\' || next == b'"' {
                                    src += 1;
                                }
                            }
                            let byte = self.byte_at(src);
                            if let Some(slot) = self.buffer.get_mut(dst) {
                                *slot = byte;
                            }
                            dst += 1;
                            src += 1;
                            if src >= end_pos {
                                break;
                            }
                        }
                        end_pos = dst;
                    }

                    ptr += 1;

                    // :377-381 -- anything but whitespace here is a mistake.
                    let mut trailing_data = false;
                    while self.byte_at(ptr) != 0
                        && self.byte_at(ptr) != b';'
                        && self.byte_at(ptr) != endchar
                    {
                        if !is_space(self.byte_at(ptr)) {
                            trailing_data = true;
                        }
                        ptr += 1;
                    }
                    if trailing_data {
                        diag.warn(format_args!(
                            "Trailing data after quoted form parameter"
                        ));
                    }

                    self.pos = ptr;
                    return Word {
                        span: Span {
                            start: word_begin + 1,
                            end: end_pos,
                        },
                        quoted: true,
                    };
                }
                ptr += 1;
            }
            // :389-390 -- "end quote is missing, treat it as non-quoted."
            ptr = word_begin;
        }

        while self.byte_at(ptr) != 0
            && self.byte_at(ptr) != b';'
            && self.byte_at(ptr) != endchar
        {
            ptr += 1;
        }
        self.pos = ptr;
        Word {
            span: Span {
                start: word_begin,
                end: ptr,
            },
            quoted: false,
        }
    }

    /// `get_param_part` (`src/tool_formparse.c:471-656`): the `;attr=` loop.
    ///
    /// Returns the separator the scan stopped on. C returns `-1` instead when a
    /// header list could not be built, which is [`FormParseError`] here.
    #[allow(dead_code)]
    fn get_param_part(
        &mut self,
        endchar: u8,
        slots: Slots,
        diag: &mut FormDiag<'_>,
    ) -> Result<ParamPart, FormParseError> {
        let mut content_type: Option<Span> = None;
        let mut filename: Option<Span> = None;
        let mut encoder: Option<Span> = None;
        let mut headers: Vec<Vec<u8>> = Vec::new();

        // C's `endct` (`src/tool_formparse.c:483`), as a predicate: non-NULL
        // exactly while the content type is still open to extension by a
        // following unrecognised block (`:610-616`), and cleared by any other
        // recognised attribute (`:522-525`, `:538-541`, `:595-598`). It also
        // guards `:508`, so a second `;type=` immediately after the first is
        // absorbed into the first rather than replacing it.
        let mut content_type_open = false;

        self.skip_blanks();

        let word = self.get_param_word(endchar, diag);
        let data = self.strip_trailing(word, TrailingClass::Blank);
        let mut sep = self.current();

        while sep == b';' {
            // :505-506 -- step over the ';', then over any blanks.
            self.pos += 1;
            self.skip_blanks();

            if !content_type_open && self.at_prefix(b"type=") {
                // :508-520 -- the ONLY place a content type is obtained, and
                // it is the user's explicit `;type=` value. See the module
                // documentation: nothing infers one.
                self.pos += 5;
                self.skip_blanks();
                let start = self.pos;
                let end = self.strcspn(CONTENT_TYPE_TERMINATORS);
                self.pos = end;
                content_type = Some(Span { start, end });
                content_type_open = true;
                sep = self.current();
            } else if self.at_prefix(b"filename=") {
                content_type_open = false;
                self.pos += 9;
                self.skip_blanks();
                let word = self.get_param_word(endchar, diag);
                filename =
                    Some(self.strip_trailing(word, TrailingClass::Blank));
                sep = self.current();
            } else if self.at_prefix(b"headers=") {
                content_type_open = false;
                self.pos += 8;
                if self.current() == b'@' || self.current() == b'<' {
                    // :543-572 -- read the headers from a file.
                    // :547-549 -- `do { p++; } while(ISBLANK(*p));`
                    loop {
                        self.pos += 1;
                        if !is_blank(self.current()) {
                            break;
                        }
                    }
                    let word = self.get_param_word(endchar, diag);
                    let span = self.strip_trailing(word, TrailingClass::Blank);
                    sep = self.current();
                    let hdrfile = self.owned(span);
                    // The value comes straight from the command line and need
                    // not be valid UTF-8, so it reaches the file system as the
                    // bytes it is.
                    let path = Path::new(OsStr::from_bytes(&hdrfile));
                    match File::open(path) {
                        Err(error) => diag.warn_two_values(
                            "Cannot read from ",
                            &hdrfile,
                            ": ",
                            curl_rs_lib::os_error_message(&error).as_bytes(),
                        ),
                        Ok(file) => {
                            let mut reader = io::BufReader::new(file);
                            read_field_headers(
                                &mut reader,
                                &mut headers,
                                diag,
                            )?;
                        }
                    }
                } else {
                    // :574-592 -- the value is the header itself.
                    self.skip_blanks();
                    let word = self.get_param_word(endchar, diag);
                    let span = self.strip_trailing(word, TrailingClass::Blank);
                    sep = self.current();
                    let header = self.owned(span);
                    if slist_append(&mut headers, &header).is_err() {
                        // :587-591 -- SINGULAR "field header". Deliberately
                        // not normalised against the two plural sites in
                        // `read_field_headers`.
                        diag.error(format_args!(
                            "Out of memory for field header"
                        ));
                        return Err(FormParseError);
                    }
                }
            } else if self.at_prefix(b"encoder=") {
                content_type_open = false;
                self.pos += 8;
                self.skip_blanks();
                let word = self.get_param_word(endchar, diag);
                // :605 strips with ISSPACE where every sibling site uses
                // ISBLANK. The asymmetry is C's and is preserved.
                encoder = Some(self.strip_trailing(word, TrailingClass::Space));
                sep = self.current();
            } else if content_type_open {
                // :610-616 -- an unrecognised block right after a `;type=` is
                // part of the content type. The separating ';' and any blanks
                // stay inside the value, because C never terminated the first
                // piece; only trailing blanks are excluded.
                let mut end = self.pos;
                while self.current() != 0
                    && self.current() != b';'
                    && self.current() != endchar
                {
                    if !is_blank(self.current()) {
                        end = self.pos + 1;
                    }
                    self.pos += 1;
                }
                if let Some(span) = content_type.as_mut() {
                    span.end = end;
                }
                sep = self.current();
            } else {
                // :617-625 -- unknown prefix, skip to the next block. No
                // trailing-blank strip here, so the reported value keeps them.
                let word = self.get_param_word(endchar, diag);
                sep = self.current();
                if !word.span.is_empty() {
                    diag.warn_value(
                        "skip unknown form field: ",
                        self.slice(word.span),
                    );
                }
            }
        }

        // :628-630 -- "Terminate content type." The span already records where
        // it ends, so there is nothing to write.

        let content_type = match content_type {
            Some(span) if slots.content_type => Some(self.owned(span)),
            Some(span) => {
                diag.warn_value(
                    "Field content type not allowed here: ",
                    self.slice(span),
                );
                None
            }
            None => None,
        };

        let filename = match filename {
            Some(span) if slots.filename => Some(self.owned(span)),
            Some(span) => {
                diag.warn_value(
                    "Field filename not allowed here: ",
                    self.slice(span),
                );
                None
            }
            None => None,
        };

        let encoder = match encoder {
            Some(span) if slots.encoder => Some(self.owned(span)),
            Some(span) => {
                diag.warn_value(
                    "Field encoder not allowed here: ",
                    self.slice(span),
                );
                None
            }
            None => None,
        };

        // :647-652 -- the warning reports `headers->data`, the FIRST list item.
        let headers = if slots.headers {
            headers
        } else {
            if let Some(first) = headers.first() {
                diag.warn_value("Field headers not allowed here: ", first);
            }
            Vec::new()
        };

        Ok(ParamPart {
            data: self.owned(data),
            content_type,
            filename,
            encoder,
            headers,
            sep,
        })
    }
}

// Capturing a file or standard input.

/// The `*errcode` outcome of `tool_mime_new_filedata`
/// (`src/tool_formparse.c:96-176`).
///
/// C's third possibility, `CURLE_OUT_OF_MEMORY`, is reported by returning a
/// NULL node (`:104`) and has no counterpart: the node is always built here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum StdinCapture {
    /// `CURLE_OK`.
    Ok,

    /// `CURLE_READ_ERROR` (`src/tool_formparse.c:147`).
    ReadError,
}

/// `tool_mime_new_filedata` (`src/tool_formparse.c:96-176`).
///
/// `isremotefile` decides whether the part's filename reaches the server: `@`
/// passes `TRUE` (`:804`) and `<` passes `FALSE` (`:836`), and the latter turns
/// the kind into [`ToolMimeKind::FileData`] or [`ToolMimeKind::StdinData`], for
/// which `tool2curlparts` clears the filename at `:287-288`.
#[allow(dead_code)]
fn new_filedata(
    filename: &[u8],
    isremotefile: bool,
    stdin: &mut dyn StdinAccess,
) -> (ToolMime, StdinCapture) {
    // :105 -- `if(strcmp(filename, "-"))`, so only an exact `-` is stdin.
    if filename != STDIN_FILENAME {
        // :106-118 -- a normal file.
        let kind = if isremotefile {
            ToolMimeKind::File
        } else {
            ToolMimeKind::FileData
        };
        let mut node = ToolMime::new(kind);
        node.data = Some(filename.to_vec());
        return (node, StdinCapture::Ok);
    }

    // :120-173 -- standard input.
    let mut status = StdinCapture::Ok;
    let data: Option<Arc<[u8]>>;
    let size: i64;
    let origin: i64;

    match stdin.regular_extent() {
        // :129-139 -- a regular file, so do not buffer: keep the extent and
        // read it when needed. `size = sbuf.st_size - origin`, floored at 0.
        Some((file_origin, total)) => {
            origin = file_origin;
            size = (total - file_origin).max(0);
            data = None;
        }

        // :140-160 -- not suitable for direct use, buffer stdin data.
        None => {
            let mut buffer = Vec::new();
            let outcome = stdin.read_all(&mut buffer);
            origin = 0;
            match outcome {
                // :146-148. `file2memory`'s own contract -- restated on
                // [`StdinAccess::read_all`] -- is that it leaves no data
                // behind, so C's out-parameter is NULL and the size is zero.
                // The node is therefore built exactly as C builds it. An
                // implementation that leaves partial data instead makes
                // `:812`'s `part->size > 0` test live, which is the only route
                // to the two `error while reading standard input` warnings.
                Err(_) => {
                    status = StdinCapture::ReadError;
                    size = uztoso(buffer.len());
                    data = None;
                }

                // :149-156 -- on success, C re-creates zero-length data as an
                // empty string so that the read callback still sees a buffered
                // part rather than reading the stream. Keeping the buffer,
                // empty or not, is the same thing.
                Ok(()) => {
                    size = uztoso(buffer.len());
                    data = Some(Arc::from(buffer));
                }
            }
        }
    }

    let kind = if isremotefile {
        ToolMimeKind::Stdin
    } else {
        ToolMimeKind::StdinData
    };
    let mut node = ToolMime::new(kind);
    node.stdin = Some(StdinSource {
        data,
        origin,
        size,
        curpos: 0,
    });
    (node, status)
}

/// Applies `src/tool_formparse.c:809-819` and its twin at `:841-852`.
///
/// A read error on standard input is reported now only if the read had already
/// produced bytes; otherwise it is deferred so that libcurl rediscovers it
/// during the transfer. The C comment at `:810-811` states the intent: "if read
/// has started, issue the error now. Else, delay it until processed by
/// libcurl."
#[allow(dead_code)]
fn settle_stdin_read_error(
    node: &mut ToolMime,
    status: StdinCapture,
    diag: &mut FormDiag<'_>,
) -> Result<(), FormParseError> {
    if status != StdinCapture::ReadError {
        return Ok(());
    }

    let size = match node.stdin.as_ref() {
        Some(source) => source.size,
        None => 0,
    };

    // :812-815 and :845-848 -- the same frozen text at both sites.
    if size > 0 {
        diag.warn(format_args!("error while reading standard input"));
        return Err(FormParseError);
    }

    // :816-818 and :849-851
    if let Some(source) = node.stdin.as_mut() {
        source.defer_read_error();
    }
    Ok(())
}

// The entry point.

/// `formparse` (`src/tool_formparse.c:714-893`): one `-F` or `--form-string`
/// argument.
///
/// Reads a `name=value` parameter and extends `tree` with the parts it
/// describes. `literal_value` is `true` for `--form-string`, where an initial
/// `@` or `<` loses its special meaning, as does an embedded `;type=`
/// (`src/tool_formparse.c:671-672`).
///
/// C's lazy allocation of the root (`:734-739`) has no counterpart: a
/// [`MimeTree`] always has a root, which is the same state C reaches on its
/// first call.
///
/// C returns `int`, and the one caller
/// (`src/tool_getparam.c:2769-2771`) turns any non-zero value into
/// `PARAM_BAD_USE`. There is exactly one failure value, so
/// [`FormParseError`] carries no payload.
#[allow(dead_code)]
pub(crate) fn formparse(
    input: &[u8],
    tree: &mut MimeTree,
    literal_value: bool,
    stdin: &mut dyn StdinAccess,
    diag: &mut FormDiag<'_>,
) -> Result<(), FormParseError> {
    // :742 -- a copy that can be overwritten.
    let mut scanner = Scanner::new(input);

    // :747 -- scan for the end of the name.
    let equals = match scanner.buffer.iter().position(|&byte| byte == b'=') {
        Some(index) => index,
        None => {
            diag.warn(format_args!("Illegally formatted input field"));
            return Err(FormParseError);
        }
    };

    // :750-751 -- a name exists only when something precedes the '=', so
    // `=value` is nameless.
    let name = if equals > 0 {
        Some(scanner.owned(Span {
            start: 0,
            end: equals,
        }))
    } else {
        None
    };

    // :752 -- `*contp++ = '\0'`: the name is terminated and the read position
    // moves past the '='.
    scanner.pos = equals + 1;

    // C's `part`: the node the field name lands on at `:882`. The `)` branch
    // leaves it NULL, and its own condition guarantees there is no name to
    // apply, so the pair is either both present or the assignment is skipped.
    let mut name_target: Option<Vec<usize>> = None;

    // C keeps one `sep` for the whole function (`:749`) but every read of it
    // sits in the same branch as the write, so a per-branch value says the same
    // thing: `:794` and `:825` are the `@` branch's, `:875` is the trailing
    // branch's, and `:757`/`:787`/`:833`/`:860`'s `sep < 0` test is the `?` on
    // [`Scanner::get_param_part`].
    if scanner.current() == b'(' && !literal_value {
        // :754-766 -- starting a multipart.
        //
        // C does not step over the '(' before scanning, so the character is
        // absorbed into the data word, which a group discards. Reproduced
        // exactly: moving past it would change which attributes parse.
        let part = scanner.get_param_part(0, Slots::GROUP, diag)?;

        // :759 -- the group joins the current group, then becomes it.
        let mut node = ToolMime::new(ToolMimeKind::Parts);
        node.headers = part.headers;
        node.content_type = part.content_type;
        let path = tree.push_current(node);
        tree.descend(path.clone());
        name_target = Some(path);
    } else if name.is_none() && scanner.remainder() == b")" && !literal_value {
        // :767-774 -- ending a multipart. C's `!strcmp(contp, ")")` demands the
        // whole remainder be exactly that one byte.
        if tree.at_root() {
            diag.warn(format_args!("no multipart to terminate"));
            return Err(FormParseError);
        }
        tree.ascend();
    } else if scanner.current() == b'@' && !literal_value {
        // :775-827 -- the '@' introduces one or more files.
        //
        // C's `subparts`: the group each file joins. It stays unresolved until
        // the first iteration has seen whether a second file follows.
        let mut group: Option<Vec<usize>> = None;

        loop {
            // :784 -- step over the '@' on the first pass, and over the
            // separator the previous pass stopped on afterwards.
            scanner.pos += 1;
            let part = scanner.get_param_part(b',', Slots::ALL, diag)?;
            let sep = part.sep;

            // :793-801 -- decided once, on the first iteration only. A single
            // file goes straight into the current group; two or more get a
            // sub-multipart of their own.
            let target = match group {
                Some(ref path) => path.clone(),
                None => {
                    let path = if sep == b',' {
                        tree.push_current(ToolMime::new(ToolMimeKind::Parts))
                    } else {
                        tree.current_path().to_vec()
                    };
                    group = Some(path.clone());
                    path
                }
            };

            // :804 -- `isremotefile` is TRUE, so the filename is sent.
            let (mut node, status) = new_filedata(&part.data, true, stdin);
            node.headers = part.headers;
            let path = tree.push_child(&target, node);

            // :809-819 -- may fail, and when it does the node stays in the
            // tree without its attributes, exactly as C leaves it.
            settle_stdin_read_error(tree.node_mut(&path), status, diag)?;

            // :820-822 -- applied per file.
            let node = tree.node_mut(&path);
            node.filename = part.filename;
            node.content_type = part.content_type;
            node.encoder = part.encoder;

            // :824-825 -- "*contp could be '\0', so we just check with the
            // delimiter."
            if sep == 0 {
                break;
            }
        }

        // :826 -- the name goes on the group: the sub-multipart when there were
        // several files, or the single file itself.
        name_target = tree.last_child_path();
    } else {
        let sep;
        let path;

        if scanner.current() == b'<' && !literal_value {
            // :829-853 -- file content only.
            scanner.pos += 1;
            let part = scanner.get_param_part(0, Slots::FILE_CONTENT, diag)?;
            sep = part.sep;

            // :836 -- `isremotefile` is FALSE, so `tool2curlparts` clears the
            // filename at `:287-288` and none is sent.
            let (mut node, status) = new_filedata(&part.data, false, stdin);
            node.headers = part.headers;
            path = tree.push_current(node);

            settle_stdin_read_error(tree.node_mut(&path), status, diag)?;

            // :871-873. `;filename=` is not an accepted attribute here, so
            // C's `filename` local is still the NULL it was initialised to at
            // `:726` and the assignment is a no-op; `part.filename` is `None`
            // for the same reason.
            let node = tree.node_mut(&path);
            node.filename = part.filename;
            node.content_type = part.content_type;
            node.encoder = part.encoder;
        } else {
            // :854-869 -- literal field content.
            let part = if literal_value {
                // :855-856 -- the entire remainder is the value, with no
                // attribute parsing at all. C leaves `type`, `filename`,
                // `encoder` and `headers` at the NULL they were initialised to,
                // so `:871-873` are no-ops.
                ParamPart {
                    data: scanner.remainder().to_vec(),
                    ..ParamPart::default()
                }
            } else {
                scanner.get_param_part(0, Slots::ALL, diag)?
            };
            sep = part.sep;

            let mut node = ToolMime::new_data(&part.data);
            node.headers = part.headers;
            node.filename = part.filename;
            node.content_type = part.content_type;
            node.encoder = part.encoder;
            path = tree.push_current(node);
        }

        name_target = Some(path);

        // :875-878. C restores the separator byte at `:876` before formatting
        // so that the message shows it; nothing overwrote it here, so the
        // remainder already begins with it.
        if sep != 0 {
            let garbage = scanner.remainder().to_vec();
            diag.warn_value(
                "garbage at end of field specification: ",
                &garbage,
            );
        }
    }

    // :882 -- the part name is set LAST.
    if let (Some(path), Some(name)) = (name_target, name) {
        tree.node_mut(&path).name = Some(name);
    }

    Ok(())
}

// Translating the tree into libcurl MIME calls.

/// The libcurl MIME surface `tool2curlparts` drives: one method per
/// `curl_mime_*` entry point `src/tool_formparse.c:253-335` calls, with the
/// same arguments in the same order.
///
/// The surface is a trait rather than a direct call for two reasons. The
/// serialiser lives in `curl-rs-lib` -- `lib/mime.c` becomes
/// `curl-rs-lib/src/mime/mod.rs` -- and nothing in this crate may compose a
/// boundary, a `Content-Disposition` or a part header. The fixed call order at
/// `:307-316` is wire-critical, so it has to be observable in a test rather
/// than buried inside a dependency.
///
/// The implementation this crate uses in production is a thin adapter over
/// `curl_rs_lib::mime`, whose module does not exist yet; it is not listed among
/// this file's dependencies and so is not imported. Nothing else is required to
/// wire it up.
#[allow(dead_code)]
pub(crate) trait MimeBuilder {
    /// What a failed call reports. libcurl uses `CURLcode`.
    type Error;

    /// A `curl_mime *`.
    type Mime;

    /// A `curl_mimepart *`.
    type Part;

    /// `curl_mime_init` (`src/tool_formparse.c:325`), whose NULL return is
    /// `CURLE_OUT_OF_MEMORY` (`:326-327`).
    fn init(&mut self) -> Result<Self::Mime, Self::Error>;

    /// `curl_mime_free` (`src/tool_formparse.c:331`).
    fn free(&mut self, mime: Self::Mime);

    /// `curl_mime_addpart` (`src/tool_formparse.c:264`), whose NULL return is
    /// `CURLE_OUT_OF_MEMORY` (`:265-266`).
    fn add_part(
        &mut self,
        mime: &mut Self::Mime,
    ) -> Result<Self::Part, Self::Error>;

    /// `curl_mime_subparts` (`src/tool_formparse.c:274`).
    ///
    /// Ownership of `sub` passes to `part`, which is why C frees it at `:276`
    /// only when the call fails: taking it by value puts that obligation on the
    /// implementation, where it belongs.
    fn subparts(
        &mut self,
        part: &mut Self::Part,
        sub: Self::Mime,
    ) -> Result<(), Self::Error>;

    /// `curl_mime_data(part, data, CURL_ZERO_TERMINATED)`
    /// (`src/tool_formparse.c:281`).
    fn data(
        &mut self,
        part: &mut Self::Part,
        data: &[u8],
    ) -> Result<(), Self::Error>;

    /// `curl_mime_filedata` (`src/tool_formparse.c:286`).
    fn filedata(
        &mut self,
        part: &mut Self::Part,
        filename: &[u8],
    ) -> Result<(), Self::Error>;

    /// `curl_mime_data_cb(part, m->size, read, seek, NULL, m)`
    /// (`src/tool_formparse.c:296-299`).
    ///
    /// C hands over two function pointers plus `m` itself as their argument.
    /// [`StdinSource`] carries the same state and owns the two operations as
    /// [`StdinSource::read`] and [`StdinSource::seek`], so passing it is the
    /// same handover. `size` mirrors C's separate `datasize` argument.
    fn data_cb(
        &mut self,
        part: &mut Self::Part,
        size: i64,
        source: StdinSource,
    ) -> Result<(), Self::Error>;

    /// `curl_mime_filename` (`src/tool_formparse.c:288`, `:308`).
    ///
    /// `None` is C's NULL, which *clears* the filename: that is how `<` and
    /// `<-` avoid sending one at all (`:287-288`).
    fn filename(
        &mut self,
        part: &mut Self::Part,
        filename: Option<&[u8]>,
    ) -> Result<(), Self::Error>;

    /// `curl_mime_type` (`src/tool_formparse.c:310`).
    ///
    /// Called on every part, `None` included, because that is what C does.
    /// `None` is not "send no type": it clears any type set at this level and
    /// leaves the engine's MIME serialiser to infer one from the filename, the
    /// data, or its `application/octet-stream` fallback. This method receives
    /// the user's explicit `;type=` value or nothing, and must never substitute
    /// a guess of its own; see the module documentation.
    fn content_type(
        &mut self,
        part: &mut Self::Part,
        value: Option<&[u8]>,
    ) -> Result<(), Self::Error>;

    /// `curl_mime_headers(part, headers, 0)` (`src/tool_formparse.c:312`).
    ///
    /// C's third argument is `take = 0`, so the list stays owned by the caller;
    /// passing a slice says the same thing.
    fn headers(
        &mut self,
        part: &mut Self::Part,
        headers: &[Vec<u8>],
    ) -> Result<(), Self::Error>;

    /// `curl_mime_encoder` (`src/tool_formparse.c:314`).
    fn encoder(
        &mut self,
        part: &mut Self::Part,
        value: Option<&[u8]>,
    ) -> Result<(), Self::Error>;

    /// `curl_mime_name` (`src/tool_formparse.c:316`).
    fn name(
        &mut self,
        part: &mut Self::Part,
        value: Option<&[u8]>,
    ) -> Result<(), Self::Error>;
}

/// The bytes a `TOOLMIME_DATA`, `TOOLMIME_FILE` or `TOOLMIME_FILEDATA` node
/// carries in C's shared `data` pointer.
///
/// Those three kinds always set it -- `tool_mime_new_data`
/// (`src/tool_formparse.c:60-66`) and `tool_mime_new_filedata`
/// (`:108-112`) both fail rather than leave it NULL -- so the fallback is
/// unreachable. It is an empty slice because that is what libcurl makes of an
/// empty string, which is the closest thing to C's behaviour were the pointer
/// ever NULL.
#[allow(dead_code)]
fn payload(node: &ToolMime) -> &[u8] {
    debug_assert!(node.data.is_some(), "a data-bearing part with no data");
    match node.data.as_deref() {
        Some(data) => data,
        None => &[],
    }
}

/// `tool2curlparts` (`src/tool_formparse.c:253-319`).
///
/// C recurses on `m->prev` before emitting `m` (`:262`), which walks the
/// prepended list back to the first part the user wrote and emits forwards from
/// there. [`ToolMime::subparts`] already holds that order, so the recursion
/// over `prev` becomes a forward loop -- the part ordering AAP section 0.6.7
/// freezes is preserved by construction rather than by a second reversal.
#[allow(dead_code)]
fn tool2curlparts<B: MimeBuilder>(
    builder: &mut B,
    parts: &[ToolMime],
    mime: &mut B::Mime,
) -> Result<(), B::Error> {
    for node in parts {
        let mut part = builder.add_part(mime)?;

        let mut filename: Option<&[u8]> = node.filename.as_deref();

        match node.kind {
            ToolMimeKind::Parts => {
                let sub = tool2curlmime(builder, node)?;
                builder.subparts(&mut part, sub)?;
            }

            ToolMimeKind::Data => {
                builder.data(&mut part, payload(node))?;
            }

            ToolMimeKind::File | ToolMimeKind::FileData => {
                builder.filedata(&mut part, payload(node))?;
                if node.kind == ToolMimeKind::FileData && filename.is_none() {
                    // :287-288 -- `<` sends no filename, so the one
                    // `curl_mime_filedata` derived from the path is cleared.
                    builder.filename(&mut part, None)?;
                }
            }

            ToolMimeKind::Stdin | ToolMimeKind::StdinData => {
                // :291-294 -- `@-` reports itself as `-`, and then falls
                // through to the shared callback setup.
                if node.kind == ToolMimeKind::Stdin && filename.is_none() {
                    filename = Some(STDIN_FILENAME);
                }

                debug_assert!(
                    node.stdin.is_some(),
                    "a standard-input part with no source"
                );
                let source = match node.stdin.as_ref() {
                    Some(source) => source.clone(),
                    // Unreachable: `new_filedata` sets the source for both
                    // standard-input kinds. C would pass its zeroed `m`, whose
                    // NULL `data` and zero `size` make the first read report
                    // end of input, which is what this stands in for.
                    None => StdinSource {
                        data: None,
                        origin: 0,
                        size: 0,
                        curpos: 0,
                    },
                };
                builder.data_cb(&mut part, source.size(), source)?;
            }

            ToolMimeKind::None => {
                // :302-304 -- "Other cases not possible in this context."
            }
        }

        // :307-316 -- the FIXED order: filename, type, headers, encoder, name.
        // It decides what the serialiser sees, so it is not to be rearranged.

        if filename.is_some() {
            builder.filename(&mut part, filename)?;
        }

        // :309-310 -- unconditional, `None` included.
        builder.content_type(&mut part, node.content_type.as_deref())?;

        builder.headers(&mut part, &node.headers)?;

        builder.encoder(&mut part, node.encoder.as_deref())?;

        builder.name(&mut part, node.name.as_deref())?;
    }
    Ok(())
}

/// `tool2curlmime` (`src/tool_formparse.c:321-335`).
///
/// `root` is the tree's outermost group -- C is handed `config->mimeroot`
/// (`src/config2setopts.c:800`) and builds from `m->subparts` (`:329`).
#[allow(dead_code)]
pub(crate) fn tool2curlmime<B: MimeBuilder>(
    builder: &mut B,
    root: &ToolMime,
) -> Result<B::Mime, B::Error> {
    let mut mime = builder.init()?;

    match tool2curlparts(builder, &root.subparts, &mut mime) {
        Ok(()) => Ok(mime),
        Err(error) => {
            builder.free(mime);
            Err(error)
        }
    }
}

// Tests
//
// The coverage of `tests/unit` moves into the crate,
// because a Rust static library does not export `pub(crate)` items and the C
// unit tests therefore cannot link against them. These tests are that
// relocation for this file. Nothing here touches the network, and nothing here
// edits a fixture: the oracle is `src/tool_formparse.c` itself.

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Doubles

    /// A standard-input double.
    ///
    /// The two branches of `tool_mime_new_filedata`
    /// (`src/tool_formparse.c:129-160`) are selected by `regular`, so both are
    /// exercised: a regular file keeps its extent and is read lazily, anything
    /// else is buffered in full.
    #[derive(Debug, Default)]
    struct TestStdin {
        data: Vec<u8>,
        pos: usize,

        /// Whether the stream is a regular file at a known offset. `false`
        /// selects C's buffering branch at `:140`.
        regular: bool,

        /// Makes `read_all` fail after this many bytes.
        fail_after: Option<usize>,

        /// Whether a failing `read_all` leaves behind the bytes it did read.
        ///
        /// `file2memory_range` does not -- it frees its buffer and reports a
        /// size of zero -- so `false` is the faithful default, and it is why
        /// `:812`'s `part->size > 0` test never fires in curl itself. `true`
        /// is a deliberately non-conforming stream, and it is the only way to
        /// reach the two "error while reading standard input" warnings.
        keep_partial: bool,

        /// Makes `read_chunk` fail, which is C's `ferror(stdin)` at `:217`.
        chunk_fails: bool,

        /// Makes `seek_to` fail, which is C's failed `fseek` at `:244`.
        seek_fails: bool,

        /// Every offset `seek_to` was asked for, in order.
        seeks: Vec<i64>,
    }

    impl TestStdin {
        fn with(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                ..Self::default()
            }
        }

        fn regular_with(data: &[u8]) -> Self {
            Self {
                data: data.to_vec(),
                regular: true,
                ..Self::default()
            }
        }

        fn available(&self) -> usize {
            self.data
                .len()
                .saturating_sub(self.pos.min(self.data.len()))
        }

        fn failure() -> io::Error {
            io::Error::other("stdin unavailable")
        }
    }

    impl StdinAccess for TestStdin {
        fn regular_extent(&mut self) -> Option<(i64, i64)> {
            if self.regular {
                Some((uztoso(self.pos), uztoso(self.data.len())))
            } else {
                None
            }
        }

        fn read_all(&mut self, out: &mut Vec<u8>) -> io::Result<()> {
            let start = self.pos.min(self.data.len());
            match self.fail_after {
                Some(limit) => {
                    if self.keep_partial {
                        let taken = limit.min(self.available());
                        out.extend_from_slice(&self.data[start..start + taken]);
                        self.pos = start + taken;
                    } else {
                        out.clear();
                    }
                    Err(TestStdin::failure())
                }
                None => {
                    out.extend_from_slice(&self.data[start..]);
                    self.pos = self.data.len();
                    Ok(())
                }
            }
        }

        fn read_chunk(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.chunk_fails {
                return Err(TestStdin::failure());
            }
            let start = self.pos.min(self.data.len());
            let count = self.available().min(buffer.len());
            buffer[..count].copy_from_slice(&self.data[start..start + count]);
            self.pos = start + count;
            Ok(count)
        }

        fn seek_to(&mut self, offset: i64) -> io::Result<()> {
            self.seeks.push(offset);
            if self.seek_fails || offset < 0 {
                return Err(TestStdin::failure());
            }
            self.pos = sotouz(offset);
            Ok(())
        }
    }

    /// One call the translation layer made, with its arguments.
    #[derive(Clone, Debug, PartialEq, Eq)]
    enum Call {
        Init(usize),
        Free(usize),
        AddPart { mime: usize, part: usize },
        Subparts { part: usize, sub: usize },
        Data { part: usize, data: Vec<u8> },
        FileData { part: usize, filename: Vec<u8> },
        DataCb { part: usize, size: i64 },
        Filename { part: usize, value: Option<Vec<u8>> },
        ContentType { part: usize, value: Option<Vec<u8>> },
        Headers { part: usize, headers: Vec<Vec<u8>> },
        Encoder { part: usize, value: Option<Vec<u8>> },
        Name { part: usize, value: Option<Vec<u8>> },
    }

    impl Call {
        /// The `curl_mime_*` entry point this call stands for.
        fn tag(&self) -> &'static str {
            match self {
                Self::Init(_) => "init",
                Self::Free(_) => "free",
                Self::AddPart { .. } => "addpart",
                Self::Subparts { .. } => "subparts",
                Self::Data { .. } => "data",
                Self::FileData { .. } => "filedata",
                Self::DataCb { .. } => "data_cb",
                Self::Filename { .. } => "filename",
                Self::ContentType { .. } => "type",
                Self::Headers { .. } => "headers",
                Self::Encoder { .. } => "encoder",
                Self::Name { .. } => "name",
            }
        }

        /// Which part the call configured, where it configured one.
        fn part(&self) -> Option<usize> {
            match *self {
                Self::Init(_) | Self::Free(_) => None,
                Self::AddPart { part, .. }
                | Self::Subparts { part, .. }
                | Self::Data { part, .. }
                | Self::FileData { part, .. }
                | Self::DataCb { part, .. }
                | Self::Filename { part, .. }
                | Self::ContentType { part, .. }
                | Self::Headers { part, .. }
                | Self::Encoder { part, .. }
                | Self::Name { part, .. } => Some(part),
            }
        }
    }

    /// A [`MimeBuilder`] that records rather than serialises, so that the fixed
    /// call order at `src/tool_formparse.c:307-316` is observable.
    #[derive(Debug, Default)]
    struct Recorder {
        calls: Vec<Call>,
        mimes: usize,
        parts: usize,

        /// Makes the `n`th `add_part` fail, exercising `:265-266`.
        fail_add_part_at: Option<usize>,
    }

    impl Recorder {
        /// Every call, as its entry-point name.
        fn tags(&self) -> Vec<&'static str> {
            self.calls.iter().map(Call::tag).collect()
        }

        /// The calls that configured one part, as entry-point names.
        fn tags_for(&self, part: usize) -> Vec<&'static str> {
            self.calls
                .iter()
                .filter(|call| call.part() == Some(part))
                .map(Call::tag)
                .collect()
        }

        fn contains(&self, call: &Call) -> bool {
            self.calls.contains(call)
        }
    }

    impl MimeBuilder for Recorder {
        type Error = ();
        type Mime = usize;
        type Part = usize;

        fn init(&mut self) -> Result<usize, ()> {
            self.mimes += 1;
            let mime = self.mimes;
            self.calls.push(Call::Init(mime));
            Ok(mime)
        }

        fn free(&mut self, mime: usize) {
            self.calls.push(Call::Free(mime));
        }

        fn add_part(&mut self, mime: &mut usize) -> Result<usize, ()> {
            self.parts += 1;
            if self.fail_add_part_at == Some(self.parts) {
                return Err(());
            }
            let part = self.parts;
            self.calls.push(Call::AddPart { mime: *mime, part });
            Ok(part)
        }

        fn subparts(&mut self, part: &mut usize, sub: usize) -> Result<(), ()> {
            self.calls.push(Call::Subparts { part: *part, sub });
            Ok(())
        }

        fn data(&mut self, part: &mut usize, data: &[u8]) -> Result<(), ()> {
            self.calls.push(Call::Data {
                part: *part,
                data: data.to_vec(),
            });
            Ok(())
        }

        fn filedata(
            &mut self,
            part: &mut usize,
            filename: &[u8],
        ) -> Result<(), ()> {
            self.calls.push(Call::FileData {
                part: *part,
                filename: filename.to_vec(),
            });
            Ok(())
        }

        fn data_cb(
            &mut self,
            part: &mut usize,
            size: i64,
            source: StdinSource,
        ) -> Result<(), ()> {
            debug_assert_eq!(size, source.size(), "datasize must be m->size");
            self.calls.push(Call::DataCb { part: *part, size });
            Ok(())
        }

        fn filename(
            &mut self,
            part: &mut usize,
            filename: Option<&[u8]>,
        ) -> Result<(), ()> {
            self.calls.push(Call::Filename {
                part: *part,
                value: filename.map(<[u8]>::to_vec),
            });
            Ok(())
        }

        fn content_type(
            &mut self,
            part: &mut usize,
            value: Option<&[u8]>,
        ) -> Result<(), ()> {
            self.calls.push(Call::ContentType {
                part: *part,
                value: value.map(<[u8]>::to_vec),
            });
            Ok(())
        }

        fn headers(
            &mut self,
            part: &mut usize,
            headers: &[Vec<u8>],
        ) -> Result<(), ()> {
            self.calls.push(Call::Headers {
                part: *part,
                headers: headers.to_vec(),
            });
            Ok(())
        }

        fn encoder(
            &mut self,
            part: &mut usize,
            value: Option<&[u8]>,
        ) -> Result<(), ()> {
            self.calls.push(Call::Encoder {
                part: *part,
                value: value.map(<[u8]>::to_vec),
            });
            Ok(())
        }

        fn name(
            &mut self,
            part: &mut usize,
            value: Option<&[u8]>,
        ) -> Result<(), ()> {
            self.calls.push(Call::Name {
                part: *part,
                value: value.map(<[u8]>::to_vec),
            });
            Ok(())
        }
    }

    // Helpers

    /// What one or more `-F` arguments produced: the tree, the diagnostics and
    /// the outcome.
    struct Parsed {
        tree: MimeTree,
        output: String,
        outcome: Result<(), FormParseError>,
    }

    impl Parsed {
        /// The node a path of child indices names, walking from the root.
        fn at(&self, path: &[usize]) -> &ToolMime {
            let mut node = self.tree.root();
            for &index in path {
                assert!(index < node.subparts.len(), "no part at {path:?}");
                match node.subparts.get(index) {
                    Some(child) => node = child,
                    None => break,
                }
            }
            node
        }

        /// The tree's parts, translated, so that call order can be asserted.
        fn build(&self) -> Recorder {
            let mut recorder = Recorder::default();
            let outcome = tool2curlmime(&mut recorder, self.tree.root());
            assert!(outcome.is_ok(), "translation failed");
            recorder
        }

        /// [`Self::output`] with `voutf`'s line wrapping undone, for a test
        /// that asserts on the TEXT of one diagnostic.
        ///
        /// `voutf` (`src/tool_msgs.c:37-73`) wraps at the terminal width: it
        /// cuts the message at the last blank before the limit, writes the
        /// bytes up to and including that blank, emits a newline, and then
        /// re-emits the `"Warning: "` prefix for the remainder. So a single
        /// long warning arrives as several lines whose join point is exactly
        /// `"\nWarning: "`, with the blank retained on the first line -- which
        /// is why removing that separator alone reconstitutes the message.
        ///
        /// This matters because the width at which a message wraps depends on
        /// its length, and a message that interpolates a path is as long as
        /// the path is. A test asserting on a contiguous substring of such a
        /// message is otherwise sensitive to where the temporary directory
        /// happens to live -- `TMPDIR=/tmp` wraps in one place and
        /// `TMPDIR=/tmp/curl-rs-0` in another, and only one of them keeps the
        /// substring intact. Undoing the wrap first makes the assertion about
        /// the text, which is what it is for. The wrapping itself is frozen
        /// behaviour and is asserted on its own in `output::msgs`.
        ///
        /// Only for a single expected diagnostic: joining is indiscriminate,
        /// so two warnings would run together.
        fn unwrapped(&self) -> String {
            self.output.replace("\nWarning: ", "")
        }
    }

    fn parse_many(
        inputs: &[&[u8]],
        literal_value: bool,
        stdin: &mut dyn StdinAccess,
    ) -> Parsed {
        let mut tree = MimeTree::new();
        let mut sink: Vec<u8> = Vec::new();
        let mut outcome = Ok(());
        {
            let mut diag = FormDiag::new(&mut sink, MsgConfig::default());
            for input in inputs {
                outcome = formparse(
                    input,
                    &mut tree,
                    literal_value,
                    stdin,
                    &mut diag,
                );
                if outcome.is_err() {
                    break;
                }
            }
        }
        Parsed {
            tree,
            output: String::from_utf8_lossy(&sink).into_owned(),
            outcome,
        }
    }

    fn parse_bytes(input: &[u8]) -> Parsed {
        let mut stdin = TestStdin::default();
        parse_many(&[input], false, &mut stdin)
    }

    fn parse(input: &str) -> Parsed {
        parse_bytes(input.as_bytes())
    }

    fn parse_literal(input: &str) -> Parsed {
        let mut stdin = TestStdin::default();
        parse_many(&[input.as_bytes()], true, &mut stdin)
    }

    fn parse_seq(inputs: &[&str]) -> Parsed {
        let mut stdin = TestStdin::default();
        let bytes: Vec<&[u8]> =
            inputs.iter().map(|text| text.as_bytes()).collect();
        parse_many(&bytes, false, &mut stdin)
    }

    fn text(value: &Option<Vec<u8>>) -> Option<&str> {
        match value {
            Some(bytes) => std::str::from_utf8(bytes).ok(),
            None => None,
        }
    }

    /// A temporary directory, or a failed test.
    ///
    /// A macro rather than a function because the failure path has to leave the
    /// test itself: no panicking helper appears anywhere in this file, tests
    /// included. The assertion is what reports the failure; the `else` arm
    /// exists only to satisfy the type checker and cannot be taken once the
    /// assertion holds.
    macro_rules! temp_dir {
        () => {{
            let outcome = tempfile::tempdir();
            assert!(outcome.is_ok(), "a temporary directory is required");
            let Ok(directory) = outcome else { return };
            directory
        }};
    }

    /// The standard-input source of a part, or a failed test.
    macro_rules! stdin_source {
        ($part:expr) => {{
            let held = $part.stdin.clone();
            assert!(held.is_some(), "the part must carry a source");
            let Some(source) = held else { return };
            source
        }};
    }

    // Content-type inference: there is none

    /// The headline invariant. `src/tool_formparse.c:508` is the only place a
    /// content type is obtained and it reads the user's `;type=`; `:310` passes
    /// that value on unconditionally, NULL included, which clears the type
    /// rather than guessing one. A filename with a well-known extension must
    /// therefore produce no content type at all.
    #[test]
    fn no_content_type_is_inferred_from_an_extension() {
        for spec in [
            "field=@photo.png",
            "field=@page.html",
            "field=@notes.txt",
            "field=@archive.tar.gz",
            "field=@data.json",
            "field=<photo.png",
            "field=plain.png",
        ] {
            let parsed = parse(spec);
            assert!(parsed.outcome.is_ok(), "{spec}");
            let part = parsed.at(&[0]);
            assert_eq!(part.content_type, None, "{spec} gained a type");

            // And the absence survives translation: `curl_mime_type` is still
            // called, with NULL, exactly as `:310` calls it.
            let recorder = parsed.build();
            assert!(
                recorder.contains(&Call::ContentType {
                    part: 1,
                    value: None,
                }),
                "{spec} must clear the type, not set one"
            );
        }
    }

    /// An explicit `;type=` is honoured verbatim -- the same input that gains
    /// nothing without the attribute.
    #[test]
    fn an_explicit_type_is_honoured() {
        let parsed = parse("field=@photo.png;type=text/plain");
        assert!(parsed.outcome.is_ok());
        let part = parsed.at(&[0]);
        assert_eq!(text(&part.content_type), Some("text/plain"));
        assert_eq!(part.data.as_deref(), Some(&b"photo.png"[..]));

        let recorder = parsed.build();
        assert!(recorder.contains(&Call::ContentType {
            part: 1,
            value: Some(b"text/plain".to_vec()),
        }));
    }

    /// `;type=` accepts parameters, which arrive as one string because C never
    /// terminated the first piece (`src/tool_formparse.c:610-616`).
    #[test]
    fn a_type_absorbs_a_following_unknown_block() {
        let parsed = parse("field=value;type=text/plain;charset=utf-8");
        assert_eq!(
            text(&parsed.at(&[0]).content_type),
            Some("text/plain;charset=utf-8")
        );
        assert_eq!(parsed.output, "");
    }

    /// The `!endct` guard at `:508` means a second `;type=` is absorbed into
    /// the first rather than replacing it.
    #[test]
    fn a_second_type_is_absorbed_not_applied() {
        let parsed = parse("field=value;type=a/b;type=c/d");
        assert_eq!(text(&parsed.at(&[0]).content_type), Some("a/b;type=c/d"));
    }

    /// A recognised attribute closes the content type -- the `*endct = '\0'`
    /// at `:522-525`, `:538-541` and `:595-598` -- so a later unknown block is
    /// no longer folded into it and is reported instead.
    #[test]
    fn a_recognised_attribute_closes_the_type() {
        let parsed = parse("field=value;type=a/b;filename=n;bogus=1");
        let part = parsed.at(&[0]);
        assert_eq!(text(&part.content_type), Some("a/b"));
        assert_eq!(text(&part.filename), Some("n"));
        assert!(
            parsed.output.contains("skip unknown form field: bogus=1"),
            "a closed type must not absorb the block: {}",
            parsed.output
        );
    }

    /// Once the type is closed, a further `;type=` passes the `!endct` guard
    /// again and REPLACES the value, because `:513` assigns unconditionally.
    ///
    /// Measured against the oracle, which is the point: the intuitive reading
    /// -- first one wins -- is wrong, and only the immediately repeated form
    /// tested by [`a_second_type_is_absorbed_not_applied`] is absorbed.
    #[test]
    fn a_reopened_type_replaces_the_earlier_value() {
        let parsed = parse("field=value;type=a/b;filename=n;type=c/d");
        let part = parsed.at(&[0]);
        assert_eq!(text(&part.content_type), Some("c/d"));
        assert_eq!(text(&part.filename), Some("n"));
        assert_eq!(parsed.output, "");
    }

    /// `:516`'s terminator set, byte for byte.
    #[test]
    fn the_type_value_stops_at_every_tspecial() {
        assert_eq!(CONTENT_TYPE_TERMINATORS, b"()<>@,;:\\\"[]?=\r\n ");
        for &terminator in CONTENT_TYPE_TERMINATORS {
            let mut spec = b"field=value;type=a/b".to_vec();
            spec.push(terminator);
            spec.extend_from_slice(b"tail");
            let parsed = parse_bytes(&spec);

            // `;` ends the `strcspn` like every other byte in the set, and then
            // the attribute loop's `:610-616` arm folds the following block
            // back into the value -- so the terminator did its job either way.
            let expected = if terminator == b';' {
                "a/b;tail"
            } else {
                "a/b"
            };
            assert_eq!(
                text(&parsed.at(&[0]).content_type),
                Some(expected),
                "terminator {terminator:#04x} did not end the type"
            );
        }
    }

    // Literal data

    #[test]
    fn literal_content_has_no_filename_and_no_type() {
        let parsed = parse("field=value");
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.output, "");
        let part = parsed.at(&[0]);
        assert_eq!(part.kind, ToolMimeKind::Data);
        assert_eq!(part.data.as_deref(), Some(&b"value"[..]));
        assert_eq!(part.filename, None);
        assert_eq!(part.content_type, None);
        assert_eq!(part.encoder, None);
        assert!(part.headers.is_empty());
        assert_eq!(text(&part.name), Some("field"));
    }

    /// `:750-751` records a name only when something precedes the `=`.
    #[test]
    fn a_leading_equals_leaves_the_part_nameless() {
        let parsed = parse("=value");
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.at(&[0]).name, None);
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b"value"[..]));
    }

    /// `:747` finds the FIRST `=`, so a later one belongs to the value.
    #[test]
    fn only_the_first_equals_separates_name_from_value() {
        let parsed = parse("a=b=c");
        assert_eq!(text(&parsed.at(&[0]).name), Some("a"));
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b"b=c"[..]));
    }

    #[test]
    fn an_empty_value_is_accepted() {
        let parsed = parse("field=");
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b""[..]));
    }

    // Files: `@` versus `<`

    /// `:804` passes `isremotefile = TRUE`, so the kind is `TOOLMIME_FILE` and
    /// `tool2curlparts` never clears the filename.
    #[test]
    fn an_at_sign_sends_the_filename() {
        let parsed = parse("field=@upload.txt");
        let part = parsed.at(&[0]);
        assert_eq!(part.kind, ToolMimeKind::File);
        assert_eq!(part.data.as_deref(), Some(&b"upload.txt"[..]));

        let recorder = parsed.build();
        assert!(recorder.contains(&Call::FileData {
            part: 1,
            filename: b"upload.txt".to_vec(),
        }));
        assert!(
            !recorder.contains(&Call::Filename {
                part: 1,
                value: None,
            }),
            "'@' must not clear the filename"
        );
    }

    /// `:836` passes `isremotefile = FALSE`, so the kind is
    /// `TOOLMIME_FILEDATA` and `:287-288` clears the filename.
    #[test]
    fn a_less_than_sign_does_not_send_the_filename() {
        let parsed = parse("field=<content.txt");
        let part = parsed.at(&[0]);
        assert_eq!(part.kind, ToolMimeKind::FileData);
        assert_eq!(part.data.as_deref(), Some(&b"content.txt"[..]));

        let recorder = parsed.build();
        assert!(recorder.contains(&Call::FileData {
            part: 1,
            filename: b"content.txt".to_vec(),
        }));
        assert!(
            recorder.contains(&Call::Filename {
                part: 1,
                value: None,
            }),
            "'<' must clear the filename"
        );
    }

    /// A `;filename=` override survives, and then `:287-288` does not fire
    /// because `filename` is no longer NULL.
    #[test]
    fn a_filename_override_is_applied() {
        let parsed = parse("field=@real.txt;filename=shown.txt");
        let part = parsed.at(&[0]);
        assert_eq!(text(&part.filename), Some("shown.txt"));

        let recorder = parsed.build();
        assert!(recorder.contains(&Call::Filename {
            part: 1,
            value: Some(b"shown.txt".to_vec()),
        }));
    }

    /// `:831-832` passes NULL for `pfilename`, so `<` rejects `;filename=`
    /// while still accepting `;type=` and `;encoder=`.
    #[test]
    fn a_less_than_sign_rejects_a_filename_attribute() {
        let parsed = parse("field=<c.txt;filename=n;type=a/b;encoder=base64");
        let part = parsed.at(&[0]);
        assert_eq!(part.filename, None);
        assert_eq!(text(&part.content_type), Some("a/b"));
        assert_eq!(text(&part.encoder), Some("base64"));
        assert!(
            parsed.output.contains("Field filename not allowed here: n"),
            "{}",
            parsed.output
        );
    }

    /// `:785-786` accepts every attribute for `@`.
    #[test]
    fn an_at_sign_accepts_every_attribute() {
        let parsed = parse(
            "field=@f.txt;type=a/b;filename=n;encoder=base64;headers=X: y",
        );
        let part = parsed.at(&[0]);
        assert_eq!(text(&part.content_type), Some("a/b"));
        assert_eq!(text(&part.filename), Some("n"));
        assert_eq!(text(&part.encoder), Some("base64"));
        assert_eq!(part.headers, vec![b"X: y".to_vec()]);
        assert_eq!(parsed.output, "");
    }

    // Several files behind one name

    /// `:793-801` creates a sub-multipart only once a second file is known to
    /// follow, and `:826` puts the field name on the group.
    #[test]
    fn several_files_share_a_sub_multipart_in_order() {
        let parsed = parse("field=@a,b,c");
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.output, "");

        let group = parsed.at(&[0]);
        assert_eq!(group.kind, ToolMimeKind::Parts);
        assert_eq!(text(&group.name), Some("field"));
        assert_eq!(group.subparts.len(), 3);
        for (index, expected) in [&b"a"[..], b"b", b"c"].iter().enumerate() {
            let part = parsed.at(&[0, index]);
            assert_eq!(part.kind, ToolMimeKind::File);
            assert_eq!(part.data.as_deref(), Some(*expected));
            assert_eq!(part.name, None, "only the group is named");
        }
    }

    /// `:794-795`: one file goes straight into the current group.
    #[test]
    fn a_single_file_gets_no_sub_multipart() {
        let parsed = parse("field=@a");
        let part = parsed.at(&[0]);
        assert_eq!(part.kind, ToolMimeKind::File);
        assert_eq!(text(&part.name), Some("field"));
        assert!(part.subparts.is_empty());
    }

    /// `:820-822` applies the attributes per file, so each one keeps its own.
    #[test]
    fn each_file_keeps_its_own_attributes() {
        let parsed = parse("field=@a;type=x/1,b;type=x/2,c");
        assert_eq!(text(&parsed.at(&[0, 0]).content_type), Some("x/1"));
        assert_eq!(text(&parsed.at(&[0, 1]).content_type), Some("x/2"));
        assert_eq!(parsed.at(&[0, 2]).content_type, None);
    }

    /// A quoted filename keeps the comma that would otherwise split the list
    /// (`src/tool_formparse.c:679-681`).
    #[test]
    fn a_quoted_filename_keeps_its_comma() {
        let parsed = parse("field=@\"a,b\"");
        let part = parsed.at(&[0]);
        assert_eq!(part.data.as_deref(), Some(&b"a,b"[..]));
        assert!(part.subparts.is_empty(), "no list, so no sub-multipart");
    }

    // `--form-string`

    /// `:855-856` takes the whole remainder with no attribute parsing at all,
    /// and `:754`, `:767`, `:775` and `:829` are all suppressed
    /// (`:671-672`).
    #[test]
    fn form_string_treats_everything_as_text() {
        for spec in [
            "field=@file.txt",
            "field=<file.txt",
            "field=(group",
            "field=value;type=a/b",
            "field=value;filename=n",
            "field=\"quoted\"",
        ] {
            let parsed = parse_literal(spec);
            assert!(parsed.outcome.is_ok(), "{spec}");
            assert_eq!(parsed.output, "", "{spec}");
            let part = parsed.at(&[0]);
            assert_eq!(part.kind, ToolMimeKind::Data, "{spec}");
            let expected = spec.split_once('=').map(|pair| pair.1);
            assert_eq!(
                part.data.as_deref(),
                expected.map(str::as_bytes),
                "{spec}"
            );
            assert_eq!(part.content_type, None, "{spec}");
            assert_eq!(part.filename, None, "{spec}");
            assert_eq!(part.encoder, None, "{spec}");
            assert!(part.headers.is_empty(), "{spec}");
        }
    }

    /// `)` is ordinary text under `--form-string`, so it cannot terminate a
    /// group.
    #[test]
    fn form_string_cannot_terminate_a_multipart() {
        let mut stdin = TestStdin::default();
        let parsed = parse_many(&[b"=)"], true, &mut stdin);
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.output, "");
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b")"[..]));
    }

    // Multipart grouping

    /// `:754-766` opens a group, `:767-774` closes it, and the parts written in
    /// between belong to it.
    #[test]
    fn a_group_opens_and_closes() {
        let parsed = parse_seq(&[
            "outer=(;type=multipart/alternative",
            "a=1",
            "b=2",
            "=)",
        ]);
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.output, "");

        let group = parsed.at(&[0]);
        assert_eq!(group.kind, ToolMimeKind::Parts);
        assert_eq!(text(&group.name), Some("outer"));
        assert_eq!(text(&group.content_type), Some("multipart/alternative"));
        assert_eq!(group.subparts.len(), 2);
        assert_eq!(text(&parsed.at(&[0, 0]).name), Some("a"));
        assert_eq!(text(&parsed.at(&[0, 1]).name), Some("b"));

        // The cursor came back out, so the next field is a sibling.
        assert!(parsed.tree.at_root());
    }

    /// `:769-771` at the root.
    #[test]
    fn closing_with_no_group_open_fails() {
        let parsed = parse("=)");
        assert!(parsed.outcome.is_err());
        assert!(
            parsed.output.contains("no multipart to terminate"),
            "{}",
            parsed.output
        );
    }

    /// `:767`'s conditions are all three necessary: a name, or anything other
    /// than exactly `)`, makes it ordinary content.
    #[test]
    fn only_a_bare_close_paren_terminates() {
        let named = parse_seq(&["outer=(", "name=)"]);
        assert!(named.outcome.is_ok());
        assert_eq!(named.at(&[0]).subparts.len(), 1, "`name=)` is content");
        assert!(!named.tree.at_root(), "the group is still open");

        let trailing = parse_seq(&["outer=(", "=) "]);
        assert!(trailing.outcome.is_ok());
        assert_eq!(
            trailing.at(&[0]).subparts.len(),
            1,
            "`=) ` is not exactly `)`"
        );
    }

    /// `:756` passes NULL for both `pfilename` and `pencoder`, so a group
    /// rejects them while accepting `;type=` and `;headers=`.
    #[test]
    fn a_group_rejects_a_filename_and_an_encoder() {
        let parsed = parse("outer=(;filename=n;encoder=base64;headers=X: y");
        assert!(parsed.outcome.is_ok());
        assert!(
            parsed.output.contains("Field filename not allowed here: n"),
            "{}",
            parsed.output
        );
        assert!(
            parsed
                .output
                .contains("Field encoder not allowed here: base64"),
            "{}",
            parsed.output
        );
        let group = parsed.at(&[0]);
        assert_eq!(group.filename, None);
        assert_eq!(group.encoder, None);
        assert_eq!(group.headers, vec![b"X: y".to_vec()]);
    }

    /// Groups nest, and each `)` pops exactly one level.
    #[test]
    fn groups_nest() {
        let parsed =
            parse_seq(&["a=(", "b=(", "c=1", "=)", "d=2", "=)", "e=3"]);
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.output, "");
        assert_eq!(text(&parsed.at(&[0]).name), Some("a"));
        assert_eq!(text(&parsed.at(&[0, 0]).name), Some("b"));
        assert_eq!(text(&parsed.at(&[0, 0, 0]).name), Some("c"));
        assert_eq!(text(&parsed.at(&[0, 1]).name), Some("d"));
        assert_eq!(text(&parsed.at(&[1]).name), Some("e"));
    }

    // Quoting

    /// `:350-361`: inside a quoted word only `\\` and `\"` are escapes.
    #[test]
    fn a_quoted_word_unescapes_only_backslash_and_quote() {
        let cases: [(&str, &[u8]); 6] = [
            ("field=\"a,b\"", b"a,b"),
            ("field=\"a;b\"", b"a;b"),
            ("field=\"a\\\"b\"", b"a\"b"),
            ("field=\"a\\\\b\"", b"a\\b"),
            ("field=\"a\\nb\"", b"a\\nb"),
            ("field=\"a\\tb\"", b"a\\tb"),
        ];
        for (spec, expected) in cases {
            let parsed = parse(spec);
            assert_eq!(
                parsed.at(&[0]).data.as_deref(),
                Some(expected),
                "{spec}"
            );
            assert_eq!(parsed.output, "", "{spec}");
        }
    }

    /// `:389-390`: "end quote is missing, treat it as non-quoted."
    #[test]
    fn a_missing_end_quote_falls_back_to_unquoted() {
        let parsed = parse("field=\"unterminated");
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.output, "");
        assert_eq!(
            parsed.at(&[0]).data.as_deref(),
            Some(&b"\"unterminated"[..]),
            "the opening quote is part of the value"
        );
    }

    /// The fallback is complete: the word counts as unquoted, so trailing
    /// blanks are stripped from it (`:499-501`).
    #[test]
    fn a_missing_end_quote_also_restores_blank_stripping() {
        let parsed = parse("field=\"unterminated   ");
        assert_eq!(
            parsed.at(&[0]).data.as_deref(),
            Some(&b"\"unterminated"[..])
        );
    }

    /// `:382-383`: any non-space byte after the closing quote warns.
    #[test]
    fn trailing_data_after_a_quoted_word_warns() {
        let parsed = parse("field=\"quoted\"junk");
        assert!(parsed.outcome.is_ok());
        assert!(
            parsed
                .output
                .contains("Trailing data after quoted form parameter"),
            "{}",
            parsed.output
        );
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b"quoted"[..]));
    }

    /// Whitespace after the closing quote is accepted silently, because the
    /// scan at `:379-386` only objects to non-`ISSPACE` bytes.
    #[test]
    fn trailing_space_after_a_quoted_word_is_silent() {
        let parsed = parse("field=\"quoted\"  \t");
        assert_eq!(parsed.output, "");
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b"quoted"[..]));
    }

    /// `:499-501` strips trailing blanks from an unquoted word only, so a
    /// quoted one keeps them.
    #[test]
    fn trailing_blanks_survive_only_inside_quotes() {
        let unquoted = parse("field=value   ");
        assert_eq!(unquoted.at(&[0]).data.as_deref(), Some(&b"value"[..]));

        let quoted = parse("field=\"value   \"");
        assert_eq!(
            quoted.at(&[0]).data.as_deref(),
            Some(&b"value   "[..]),
            "a quoted word is taken exactly"
        );
    }

    /// `:494-495` skips blanks before the word, so leading blanks never reach
    /// the value.
    #[test]
    fn leading_blanks_are_skipped() {
        let parsed = parse("field=   value");
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b"value"[..]));
    }

    // `;headers=`

    #[test]
    fn an_inline_header_is_taken_as_written() {
        let parsed = parse("field=value;headers=X-Test: 1");
        assert_eq!(parsed.output, "");
        assert_eq!(parsed.at(&[0]).headers, vec![b"X-Test: 1".to_vec()]);
    }

    #[test]
    fn headers_are_read_from_a_file() {
        let dir = temp_dir!();
        let path = dir.path().join("h");
        let written = std::fs::write(
            &path,
            "# a comment\nX-One: 1\nX-Two: 2\n  folded\n\nX-Three: 3\n",
        );
        assert!(written.is_ok(), "the fixture file must be writable");

        let spec = format!("field=value;headers=@{}", path.display());
        let parsed = parse(&spec);
        assert_eq!(parsed.output, "");
        assert_eq!(
            parsed.at(&[0]).headers,
            vec![
                b"X-One: 1".to_vec(),
                b"X-Two: 2  folded".to_vec(),
                b"X-Three: 3".to_vec(),
            ],
            "comments are skipped, blank lines dropped, folds appended"
        );
    }

    /// `:543` accepts `<` as well as `@` for a header file.
    #[test]
    fn headers_are_read_from_a_file_with_a_less_than_sign() {
        let dir = temp_dir!();
        let path = dir.path().join("h");
        let written = std::fs::write(&path, "X-One: 1\n");
        assert!(written.is_ok(), "the fixture file must be writable");
        let spec = format!("field=value;headers=<{}", path.display());
        let parsed = parse(&spec);
        assert_eq!(parsed.at(&[0]).headers, vec![b"X-One: 1".to_vec()]);
    }

    /// `:559-563`, including the strerror suffix strip.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's strerror_r doubles the suffix")]
    fn an_unreadable_header_file_warns() {
        let dir = temp_dir!();
        let path = dir.path().join("absent");
        let spec = format!("field=value;headers=@{}", path.display());
        let parsed = parse(&spec);
        assert!(parsed.outcome.is_ok(), "the warning is not fatal");
        assert!(
            parsed.output.contains("Cannot read from "),
            "{}",
            parsed.output
        );
        // Through `unwrapped` because the interpolated path makes this
        // message long enough for `voutf` to break it, and where it breaks
        // depends on how long the temporary directory's path is.
        assert!(
            parsed.unwrapped().contains("No such file or directory"),
            "{}",
            parsed.output
        );
        assert!(
            !parsed.output.contains("(os error"),
            "the ` (os error N)` suffix must be stripped: {}",
            parsed.output
        );
        assert!(parsed.at(&[0]).headers.is_empty());
    }

    /// Several `;headers=` blocks accumulate onto one list.
    #[test]
    fn header_attributes_accumulate() {
        let parsed = parse("field=value;headers=A: 1;headers=B: 2");
        assert_eq!(
            parsed.at(&[0]).headers,
            vec![b"A: 1".to_vec(), b"B: 2".to_vec()]
        );
    }

    /// `read_field_headers` drives `my_get_line`, whose 127-byte `fgets`
    /// chunking (`src/tool_parsecfg.c:281-323`) must not split a long header.
    #[test]
    fn a_long_header_survives_the_fgets_chunking() {
        let long = "X-Long: ".to_string() + &"v".repeat(400);
        let mut input = Cursor::new(format!("{long}\n"));
        let mut headers = Vec::new();
        let mut sink: Vec<u8> = Vec::new();
        let mut diag = FormDiag::new(&mut sink, MsgConfig::default());
        let outcome = read_field_headers(&mut input, &mut headers, &mut diag);
        assert!(outcome.is_ok());
        assert_eq!(headers, vec![long.into_bytes()]);
        assert!(sink.is_empty());
    }

    /// `:436-437` treats a leading space as a continuation, and `:449-457`
    /// appends it to the previous header with its spaces intact.
    #[test]
    fn a_fold_before_any_header_becomes_its_own_header() {
        let mut input = Cursor::new("  orphan\nX-One: 1\n");
        let mut headers = Vec::new();
        let mut sink: Vec<u8> = Vec::new();
        let mut diag = FormDiag::new(&mut sink, MsgConfig::default());
        let outcome = read_field_headers(&mut input, &mut headers, &mut diag);
        assert!(outcome.is_ok());
        assert_eq!(
            headers,
            vec![b"  orphan".to_vec(), b"X-One: 1".to_vec()],
            "with no previous header there is nothing to fold onto"
        );
    }

    /// The final line need not be terminated.
    #[test]
    fn an_unterminated_final_header_is_kept() {
        let mut input = Cursor::new("X-One: 1");
        let mut headers = Vec::new();
        let mut sink: Vec<u8> = Vec::new();
        let mut diag = FormDiag::new(&mut sink, MsgConfig::default());
        let outcome = read_field_headers(&mut input, &mut headers, &mut diag);
        assert!(outcome.is_ok());
        assert_eq!(headers, vec![b"X-One: 1".to_vec()]);
    }

    // The 8092-byte bound on both header dynamic buffers

    /// The `fit = len + idx + 1` arithmetic of `lib/curlx/dynbuf.c:72,82`.
    #[test]
    fn the_dynbuf_bound_reserves_one_byte_for_the_terminator() {
        // Empty buffer: 8091 content bytes fit, 8092 do not, because C always
        // counts the NUL it will append.
        assert!(dynbuf_would_fit(0, HEADER_DYNBUF_TOOBIG - 1));
        assert!(!dynbuf_would_fit(0, HEADER_DYNBUF_TOOBIG));
        // The bound is on the total, so a partially filled buffer accepts
        // correspondingly less.
        assert!(dynbuf_would_fit(8000, 91));
        assert!(!dynbuf_would_fit(8000, 92));
        assert!(dynbuf_would_fit(HEADER_DYNBUF_TOOBIG - 1, 0));
        assert!(!dynbuf_would_fit(HEADER_DYNBUF_TOOBIG, 0));
        // A length that would overflow saturates to usize::MAX, which fails the
        // comparison rather than wrapping into acceptance.
        assert!(!dynbuf_would_fit(usize::MAX, 1));
        assert!(!dynbuf_would_fit(1, usize::MAX));
    }

    /// What one `read_field_headers` call produced.
    struct HeaderParse {
        outcome: Result<(), FormParseError>,
        headers: Vec<Vec<u8>>,
        output: String,
    }

    /// Reads one header file through `read_field_headers`.
    ///
    /// Collecting the outcome, the accepted headers and whatever the
    /// diagnostics sink received in one place lets each bound test below state
    /// only the case it is about.
    fn headers_of(text: &str) -> HeaderParse {
        let mut input = Cursor::new(text.to_string());
        let mut headers = Vec::new();
        let mut sink: Vec<u8> = Vec::new();
        let outcome = {
            let mut diag = FormDiag::new(&mut sink, MsgConfig::default());
            read_field_headers(&mut input, &mut headers, &mut diag)
        };
        HeaderParse {
            outcome,
            headers,
            output: String::from_utf8_lossy(&sink).into_owned(),
        }
    }

    /// The largest content a `\n`-terminated header line may carry.
    ///
    /// `get_line` appends the line feed and only then drops it
    /// (`src/tool_parsecfg.c:295`, `:302-305`), so the newline is counted
    /// against the bound: `8092 - 1` accepted bytes minus the newline itself.
    const LONGEST_TERMINATED_HEADER: usize = HEADER_DYNBUF_TOOBIG - 2;

    /// A terminated header line at the bound is accepted whole.
    #[test]
    fn a_terminated_header_line_at_the_bound_is_accepted() {
        let line = "X: ".to_string()
            + &"v".repeat(LONGEST_TERMINATED_HEADER - "X: ".len());
        assert_eq!(line.len(), LONGEST_TERMINATED_HEADER);

        let parsed = headers_of(&format!("{line}\n"));

        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.headers, vec![line.into_bytes()]);
        assert!(parsed.output.is_empty());
    }

    /// Without a line feed the whole bound is available for content.
    ///
    /// The one-byte difference from the test above is not cosmetic: it shows the
    /// bound counts the bytes handed to `curlx_dyn_addn`, not the header text.
    #[test]
    fn an_unterminated_header_line_may_use_the_whole_bound() {
        let line = "X: ".to_string()
            + &"v".repeat(HEADER_DYNBUF_TOOBIG - 1 - "X: ".len());
        assert_eq!(line.len(), LONGEST_TERMINATED_HEADER + 1);

        let parsed = headers_of(&line);

        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.headers, vec![line.into_bytes()]);
        assert!(parsed.output.is_empty());
    }

    /// One byte past the bound truncates the list and still reports success.
    ///
    /// The teeth for the F23 line bound, and it asserts C's odd-looking but
    /// measured behaviour rather than an improvement on it: `curlx_dyn_addn`
    /// answers `CURLE_TOO_LARGE`, so `get_line` sets `*error` and returns FALSE
    /// (`src/tool_parsecfg.c:295-300`), `my_get_line` stops, and
    /// `read_field_headers`'s `while` exits with `err` still `0`
    /// (`src/tool_formparse.c:419`) -- success, with fewer headers than the file
    /// contained and nothing said about it. Without the bound the line would be
    /// accumulated whole, however long it is, and the two later headers would be
    /// accepted as well.
    #[test]
    fn an_over_long_header_line_truncates_the_list_without_an_error() {
        let over = "X: ".to_string()
            + &"v".repeat(LONGEST_TERMINATED_HEADER + 1 - "X: ".len());
        let text = format!("X-First: 1\n{over}\nX-Third: 3\n");

        let parsed = headers_of(&text);

        assert!(parsed.outcome.is_ok(), "C's err stays 0 on this path");
        assert_eq!(
            parsed.headers,
            vec![b"X-First: 1".to_vec()],
            "the over-long line, and everything after it, is dropped"
        );
        // Nothing is reported: the two `Out of memory for field headers` sites
        // at `:454` and `:462` are on the fold and append paths, not this one.
        assert!(parsed.output.is_empty());
    }

    /// The largest folded header the amend buffer accepts.
    ///
    /// `:443` appends the existing header and then the continuation into one
    /// 8092-byte buffer, so the bound applies to their sum: `8092 - 1`, with no
    /// newline involved because both lines have already had theirs dropped.
    const LONGEST_FOLDED_HEADER: usize = HEADER_DYNBUF_TOOBIG - 1;

    /// Builds a header plus a continuation whose folded length is `total`.
    fn fold_case(total: usize) -> String {
        let first = "X: ".to_string() + &"a".repeat(4_000 - "X: ".len());
        let second = " ".to_string() + &"b".repeat(total - 4_000 - 1);
        assert_eq!(first.len() + second.len(), total);
        format!("{first}\n{second}\n")
    }

    /// A fold whose sum is exactly at the bound still folds.
    #[test]
    fn a_fold_at_the_bound_is_accepted() {
        let parsed = headers_of(&fold_case(LONGEST_FOLDED_HEADER));

        assert!(parsed.outcome.is_ok());
        assert_eq!(
            parsed.headers.len(),
            1,
            "the continuation folded onto the header"
        );
        assert_eq!(parsed.headers[0].len(), LONGEST_FOLDED_HEADER);
        assert!(parsed.output.is_empty());
    }

    /// One byte past it fails, and says nothing.
    ///
    /// `:439`'s second `curlx_dyn_init(&amend, 8092)` is a separate buffer with
    /// the same limit, and `:443`'s `||` sends either refusal to the
    /// `err = -1; break;` arm at `:444-447` -- whose `break` skips the shared
    /// report at `:461-465`, so no message is emitted. Without the bound a
    /// folded header would grow without limit across as many continuation lines
    /// as the file contains.
    #[test]
    fn a_fold_one_byte_past_the_bound_fails_without_a_message() {
        let parsed = headers_of(&fold_case(LONGEST_FOLDED_HEADER + 1));

        assert!(parsed.outcome.is_err(), "`err = -1` is a failure return");
        assert!(
            parsed.output.is_empty(),
            "the `break` at :447 skips the report at :461-465"
        );
    }

    /// An ordinary fold is untouched by either bound.
    #[test]
    fn a_short_fold_is_unaffected() {
        let parsed = headers_of("X: one\n  two\n");

        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.headers, vec![b"X: one  two".to_vec()]);
        assert!(parsed.output.is_empty());
    }

    // Unknown and misplaced attributes

    /// `:623-624`.
    #[test]
    fn an_unknown_attribute_warns_and_is_skipped() {
        let parsed = parse("field=value;bogus=1");
        assert!(parsed.outcome.is_ok());
        assert!(
            parsed.output.contains("skip unknown form field: bogus=1"),
            "{}",
            parsed.output
        );
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b"value"[..]));
    }

    /// `:623`'s `if(*unknown)` suppresses the warning for an empty block, so
    /// a stray `;` is silent.
    #[test]
    fn an_empty_unknown_block_is_silent() {
        let parsed = parse("field=value;");
        assert_eq!(parsed.output, "");
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b"value"[..]));
    }

    // Malformed input

    /// `:884-886`.
    #[test]
    fn a_missing_equals_fails() {
        let parsed = parse("field");
        assert!(parsed.outcome.is_err());
        assert!(
            parsed.output.contains("Illegally formatted input field"),
            "{}",
            parsed.output
        );
        assert!(parsed.tree.root().subparts.is_empty());
    }

    #[test]
    fn an_empty_argument_fails() {
        let parsed = parse("");
        assert!(parsed.outcome.is_err());
        assert!(parsed.output.contains("Illegally formatted input field"));
    }

    /// `:875-878`, with the separator restored at `:876` so the message shows
    /// it.
    ///
    /// The only route to a leftover separator in this branch is `;type=`, whose
    /// `strcspn` set (`:516`) is wider than the `;` and `endchar` that
    /// `get_param_word` stops on.
    #[test]
    fn a_leftover_separator_warns() {
        for (spec, shown) in [
            ("field=v;type=a/b(x", "(x"),
            ("field=v;type=a/b tail", " tail"),
            ("field=v;type=a/b,rest", ",rest"),
            ("field=v;type=a/b=x", "=x"),
            ("field=v;type=a/b\"q", "\"q"),
        ] {
            let parsed = parse(spec);
            assert!(parsed.outcome.is_ok(), "{spec}");
            let expected =
                format!("garbage at end of field specification: {shown}");
            assert!(
                parsed.output.contains(&expected),
                "{spec} produced {}",
                parsed.output
            );
            assert_eq!(
                text(&parsed.at(&[0]).content_type),
                Some("a/b"),
                "{spec}"
            );
        }
    }

    /// With `endchar == '\0'` the unquoted word scan runs to the end of the
    /// argument (`:393-394`), so a comma in literal content is content -- not a
    /// separator, and not garbage.
    #[test]
    fn a_comma_in_literal_content_is_not_a_separator() {
        let parsed = parse("field=a,b,c");
        assert_eq!(parsed.output, "");
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b"a,b,c"[..]));
        assert!(parsed.at(&[0]).subparts.is_empty());
    }

    // Non-UTF-8 input

    /// A `-F` argument is `argv` and need not be valid UTF-8, so names,
    /// filenames and content all travel as bytes.
    #[test]
    fn non_utf8_bytes_survive_the_round_trip() {
        // 0xff and 0xfe are not valid UTF-8 in any position.
        let mut spec = b"na\xffme=@fi\xfele.bin;filename=sh\xffown".to_vec();
        spec.extend_from_slice(b";type=a/b");
        let parsed = parse_bytes(&spec);
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.output, "");

        let part = parsed.at(&[0]);
        assert_eq!(part.name.as_deref(), Some(&b"na\xffme"[..]));
        assert_eq!(part.data.as_deref(), Some(&b"fi\xfele.bin"[..]));
        assert_eq!(part.filename.as_deref(), Some(&b"sh\xffown"[..]));
        assert_eq!(part.content_type.as_deref(), Some(&b"a/b"[..]));

        // And the bytes reach the builder unchanged.
        let recorder = parsed.build();
        assert!(recorder.contains(&Call::Name {
            part: 1,
            value: Some(b"na\xffme".to_vec()),
        }));
        assert!(recorder.contains(&Call::FileData {
            part: 1,
            filename: b"fi\xfele.bin".to_vec(),
        }));
    }

    /// A non-UTF-8 `;headers=@file` path reaches the file system as its bytes,
    /// which is what [`OsStr`] is for here.
    #[test]
    fn a_non_utf8_header_file_path_is_opened_as_bytes() {
        let dir = temp_dir!();
        let name = OsStr::from_bytes(b"h\xffdr");
        let path = dir.path().join(name);
        let written = std::fs::write(&path, "X-One: 1\n");
        assert!(written.is_ok(), "the fixture file must be writable");

        let mut spec = b"field=value;headers=@".to_vec();
        spec.extend_from_slice(path.as_os_str().as_bytes());
        let parsed = parse_bytes(&spec);
        assert_eq!(parsed.output, "");
        assert_eq!(parsed.at(&[0]).headers, vec![b"X-One: 1".to_vec()]);
    }

    // Standard input

    /// `:105` selects standard input on an exact `-`, and `:140` buffers it
    /// when the stream is not a regular file.
    #[test]
    fn at_dash_buffers_standard_input() {
        let mut stdin = TestStdin::with(b"payload");
        let parsed = parse_many(&[b"field=@-"], false, &mut stdin);
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.output, "");

        let part = parsed.at(&[0]);
        assert_eq!(part.kind, ToolMimeKind::Stdin);
        assert_eq!(part.data, None, "the filename slot stays empty");
        let source = stdin_source!(part);
        assert_eq!(source.size(), 7);
        assert_eq!(source.data.as_deref(), Some(&b"payload"[..]));
        assert_eq!(source.origin, 0);
    }

    /// `:169-170`: `<-` is the unnamed kind.
    #[test]
    fn less_than_dash_is_the_unnamed_standard_input_kind() {
        let mut stdin = TestStdin::with(b"payload");
        let parsed = parse_many(&[b"field=<-"], false, &mut stdin);
        assert_eq!(parsed.at(&[0]).kind, ToolMimeKind::StdinData);
    }

    /// Only an exact `-` is standard input: `-x` and `x-` are filenames.
    #[test]
    fn only_a_bare_dash_means_standard_input() {
        for spec in ["field=@-x", "field=@x-", "field=@--"] {
            let mut stdin = TestStdin::with(b"payload");
            let parsed = parse_many(&[spec.as_bytes()], false, &mut stdin);
            assert_eq!(parsed.at(&[0]).kind, ToolMimeKind::File, "{spec}");
            assert!(parsed.at(&[0]).stdin.is_none(), "{spec}");
        }
    }

    /// `:149-156` re-creates a zero-length capture as an empty buffer, so the
    /// reader still sees a buffered part rather than reading the stream.
    #[test]
    fn empty_standard_input_stays_buffered() {
        let mut stdin = TestStdin::with(b"");
        let parsed = parse_many(&[b"field=@-"], false, &mut stdin);
        let source = stdin_source!(parsed.at(&[0]));
        assert_eq!(source.size(), 0);
        assert_eq!(
            source.data.as_deref(),
            Some(&b""[..]),
            "present but empty, which is C's strdup(\"\")"
        );
    }

    /// `:129-139`: a regular file keeps its extent and is NOT buffered, so the
    /// size is `st_size - origin` and the bytes are read later.
    #[test]
    fn a_regular_standard_input_keeps_its_extent() {
        let mut stdin = TestStdin::regular_with(b"0123456789");
        stdin.pos = 4;
        let parsed = parse_many(&[b"field=@-"], false, &mut stdin);
        let source = stdin_source!(parsed.at(&[0]));
        assert_eq!(source.origin, 4);
        assert_eq!(source.size(), 6, "st_size - origin");
        assert_eq!(source.data, None, "read lazily, not buffered");
    }

    /// `:136-138` floors the size at zero when the offset is past the end.
    #[test]
    fn a_regular_standard_input_size_is_floored_at_zero() {
        let mut stdin = TestStdin::regular_with(b"abc");
        stdin.pos = 9;
        let parsed = parse_many(&[b"field=@-"], false, &mut stdin);
        let source = stdin_source!(parsed.at(&[0]));
        assert_eq!(source.size(), 0);
    }

    /// `:816-818` and `:849-851`: a read error with nothing read is DEFERRED --
    /// the size becomes `-1` and parsing succeeds, so libcurl rediscovers it.
    #[test]
    fn a_standard_input_read_error_with_no_bytes_is_deferred() {
        for spec in [&b"field=@-"[..], b"field=<-"] {
            let mut stdin = TestStdin::with(b"payload");
            stdin.fail_after = Some(4);
            let parsed = parse_many(&[spec], false, &mut stdin);
            assert!(parsed.outcome.is_ok(), "the error is deferred");
            assert_eq!(parsed.output, "", "and reported by nobody yet");
            let source = stdin_source!(parsed.at(&[0]));
            assert_eq!(source.size(), -1);
            assert_eq!(source.data, None);
        }
    }

    /// `:812-814` and `:845-847`: a read error AFTER bytes were produced is
    /// reported immediately and fails the parse.
    ///
    /// Reaching it needs a stream that keeps what it read, because
    /// `file2memory_range` discards its buffer on failure and reports a size of
    /// zero -- which is why the branch never fires in curl itself. The frozen
    /// text is duplicated at both C sites and both are asserted.
    #[test]
    fn a_standard_input_read_error_after_bytes_is_reported_now() {
        for spec in [&b"field=@-"[..], b"field=<-"] {
            let mut stdin = TestStdin::with(b"payload");
            stdin.fail_after = Some(4);
            stdin.keep_partial = true;
            let parsed = parse_many(&[spec], false, &mut stdin);
            assert!(parsed.outcome.is_err());
            assert!(
                parsed.output.contains("error while reading standard input"),
                "{}",
                parsed.output
            );
        }
    }

    /// `:202-213`: a buffered part reads from memory and reports end of input
    /// at its length.
    #[test]
    fn a_buffered_source_reads_from_memory() {
        let mut stdin = TestStdin::with(b"abcdef");
        let parsed = parse_many(&[b"field=@-"], false, &mut stdin);
        let mut source = stdin_source!(parsed.at(&[0]));

        let mut sink: Vec<u8> = Vec::new();
        let mut diag = FormDiag::new(&mut sink, MsgConfig::default());
        let mut buffer = [0_u8; 4];

        assert_eq!(
            source.read(&mut buffer, &mut stdin, &mut diag),
            StdinRead::Bytes(4)
        );
        assert_eq!(&buffer, b"abcd");
        assert_eq!(
            source.read(&mut buffer, &mut stdin, &mut diag),
            StdinRead::Bytes(2),
            "the known size caps the final read"
        );
        assert_eq!(&buffer[..2], b"ef");
        assert_eq!(
            source.read(&mut buffer, &mut stdin, &mut diag),
            StdinRead::Bytes(0),
            "end of input"
        );
        assert!(sink.is_empty());
    }

    /// `:214-223`: an unbuffered part reads the stream, and `ferror` warns
    /// `stdin: %s` once and aborts.
    #[test]
    fn an_unbuffered_source_reads_the_stream_and_reports_failure() {
        let mut stdin = TestStdin::regular_with(b"abcdef");
        let parsed = parse_many(&[b"field=@-"], false, &mut stdin);
        let mut source = stdin_source!(parsed.at(&[0]));
        assert_eq!(source.data, None);

        let mut sink: Vec<u8> = Vec::new();
        let mut buffer = [0_u8; 3];
        {
            let mut diag = FormDiag::new(&mut sink, MsgConfig::default());
            assert_eq!(
                source.read(&mut buffer, &mut stdin, &mut diag),
                StdinRead::Bytes(3)
            );
            assert_eq!(&buffer, b"abc");

            stdin.chunk_fails = true;
            assert_eq!(
                source.read(&mut buffer, &mut stdin, &mut diag),
                StdinRead::Abort
            );
        }
        let output = String::from_utf8_lossy(&sink);
        assert!(output.contains("stdin: "), "{output}");
        assert!(
            !output.contains("(os error"),
            "the strerror suffix must be stripped: {output}"
        );
    }

    /// `:229-249`, including the `whence` arithmetic and the negative-offset
    /// rejection.
    #[test]
    fn seeking_a_buffered_source_stays_in_memory() {
        let mut stdin = TestStdin::with(b"abcdef");
        let parsed = parse_many(&[b"field=@-"], false, &mut stdin);
        let mut source = stdin_source!(parsed.at(&[0]));

        assert_eq!(
            source.seek(2, SeekWhence::Set, &mut stdin),
            StdinSeek::Done
        );
        assert_eq!(source.curpos, 2);
        assert_eq!(
            source.seek(1, SeekWhence::Cur, &mut stdin),
            StdinSeek::Done
        );
        assert_eq!(source.curpos, 3);
        assert_eq!(
            source.seek(-2, SeekWhence::End, &mut stdin),
            StdinSeek::Done
        );
        assert_eq!(source.curpos, 4, "size 6 minus 2");
        assert_eq!(
            source.seek(-1, SeekWhence::Set, &mut stdin),
            StdinSeek::CantSeek
        );
        assert!(
            stdin.seeks.is_empty(),
            "a buffered part never seeks the stream"
        );
    }

    /// `:243-246`: an unbuffered part seeks the stream, at `offset + origin`,
    /// and a failed seek is `CURL_SEEKFUNC_CANTSEEK`.
    #[test]
    fn seeking_an_unbuffered_source_seeks_the_stream() {
        let mut stdin = TestStdin::regular_with(b"0123456789");
        stdin.pos = 4;
        let parsed = parse_many(&[b"field=@-"], false, &mut stdin);
        let mut source = stdin_source!(parsed.at(&[0]));

        assert_eq!(
            source.seek(2, SeekWhence::Set, &mut stdin),
            StdinSeek::Done
        );
        assert_eq!(stdin.seeks, vec![6], "offset plus origin");
        assert_eq!(source.curpos, 2);

        stdin.seek_fails = true;
        assert_eq!(
            source.seek(1, SeekWhence::Set, &mut stdin),
            StdinSeek::CantSeek
        );
        assert_eq!(source.curpos, 2, "a failed seek moves nothing");
    }

    // Translation: order and the fixed attribute sequence

    /// `:262`'s recursion on `prev` emits the parts in the order the user wrote
    /// them. That order is frozen.
    #[test]
    fn parts_are_emitted_in_user_order() {
        let parsed = parse_seq(&["first=1", "second=2", "third=3"]);
        let recorder = parsed.build();
        let names: Vec<Option<Vec<u8>>> = recorder
            .calls
            .iter()
            .filter_map(|call| match call {
                Call::Name { value, .. } => Some(value.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            names,
            vec![
                Some(b"first".to_vec()),
                Some(b"second".to_vec()),
                Some(b"third".to_vec()),
            ]
        );
    }

    /// `:307-316`: filename, type, headers, encoder, name -- in that order,
    /// every time.
    #[test]
    fn the_attribute_calls_keep_their_fixed_order() {
        let parsed = parse(
            "field=@f.txt;filename=n;type=a/b;encoder=base64;headers=X: y",
        );
        let recorder = parsed.build();
        assert_eq!(
            recorder.tags_for(1),
            vec![
                "addpart", "filedata", "filename", "type", "headers",
                "encoder", "name",
            ]
        );
    }

    /// The order holds when the attributes are absent too, because `:310-316`
    /// call unconditionally.
    #[test]
    fn the_attribute_calls_are_made_even_when_empty() {
        let parsed = parse("field=value");
        let recorder = parsed.build();
        assert_eq!(
            recorder.tags_for(1),
            vec!["addpart", "data", "type", "headers", "encoder", "name"],
            "no filename call, because `filename` is NULL at :307"
        );
        assert!(recorder.contains(&Call::ContentType {
            part: 1,
            value: None,
        }));
        assert!(recorder.contains(&Call::Encoder {
            part: 1,
            value: None,
        }));
        assert!(recorder.contains(&Call::Headers {
            part: 1,
            headers: Vec::new(),
        }));
    }

    /// `:271-277`: a group is translated by a nested `curl_mime_init` whose
    /// handle is then attached with `curl_mime_subparts`.
    #[test]
    fn a_group_becomes_nested_subparts() {
        let parsed = parse_seq(&["outer=(", "a=1", "=)"]);
        let recorder = parsed.build();
        assert_eq!(
            recorder.tags(),
            vec![
                "init",    // the root mime
                "addpart", // the group's part in the root
                "init",    // the group's own mime
                "addpart", // `a=1`
                "data", "type", "headers", "encoder", "name",
                "subparts", // attached after the sub-tree is built
                "type", "headers", "encoder", "name",
            ]
        );
    }

    /// `:291-293` defaults the reported filename of `@-` to `-` and then falls
    /// through to `curl_mime_data_cb`; `<-` gets neither.
    #[test]
    fn standard_input_reports_itself_as_a_dash() {
        let mut stdin = TestStdin::with(b"payload");
        let remote = parse_many(&[b"field=@-"], false, &mut stdin);
        let recorder = remote.build();
        assert_eq!(
            recorder.tags_for(1),
            vec![
                "addpart", "data_cb", "filename", "type", "headers", "encoder",
                "name",
            ]
        );
        assert!(recorder.contains(&Call::Filename {
            part: 1,
            value: Some(b"-".to_vec()),
        }));
        assert!(recorder.contains(&Call::DataCb { part: 1, size: 7 }));

        let mut stdin = TestStdin::with(b"payload");
        let local = parse_many(&[b"field=<-"], false, &mut stdin);
        let recorder = local.build();
        assert_eq!(
            recorder.tags_for(1),
            vec!["addpart", "data_cb", "type", "headers", "encoder", "name",],
            "`<-` reports no filename at all"
        );
    }

    /// `:292`'s `if(!filename)` leaves an explicit override in place.
    #[test]
    fn an_override_beats_the_dash_default() {
        let mut stdin = TestStdin::with(b"payload");
        let parsed =
            parse_many(&[b"field=@-;filename=given"], false, &mut stdin);
        let recorder = parsed.build();
        assert!(recorder.contains(&Call::Filename {
            part: 1,
            value: Some(b"given".to_vec()),
        }));
        assert!(!recorder.contains(&Call::Filename {
            part: 1,
            value: Some(b"-".to_vec()),
        }));
    }

    /// `:330-333`: a failed translation frees the mime it created.
    #[test]
    fn a_failed_translation_frees_the_mime() {
        let parsed = parse("field=value");
        let mut recorder = Recorder {
            fail_add_part_at: Some(1),
            ..Recorder::default()
        };
        let outcome = tool2curlmime(&mut recorder, parsed.tree.root());
        assert!(outcome.is_err());
        assert_eq!(recorder.tags(), vec!["init", "free"]);
    }

    /// An empty tree still produces a mime handle, because `:325` runs before
    /// `:329` looks at the parts.
    #[test]
    fn an_empty_tree_still_initialises_a_mime() {
        let tree = MimeTree::new();
        let mut recorder = Recorder::default();
        let outcome = tool2curlmime(&mut recorder, tree.root());
        assert!(outcome.is_ok());
        assert_eq!(recorder.tags(), vec!["init"]);
    }

    // Primitives

    /// `lib/curl_ctype.h:45-50`, which are ASCII-only and locale-independent.
    #[test]
    fn the_byte_classes_match_the_c_macros() {
        assert!(is_blank(b' '));
        assert!(is_blank(b'\t'));
        assert!(!is_blank(b'\n'));
        assert!(!is_blank(0x0b));

        // ISSPACE is ISBLANK plus 0x0a..=0x0d, so the vertical tab counts --
        // which `u8::is_ascii_whitespace` does not, hence the hand-rolled test.
        for byte in 0x0a..=0x0d {
            assert!(is_space(byte), "{byte:#04x}");
        }
        assert!(is_space(b' '));
        assert!(is_space(b'\t'));
        assert!(!is_space(b'a'));
        assert!(!is_space(0x09_u8.wrapping_sub(1)));

        assert!(is_newline(b'\n'));
        assert!(is_newline(b'\r'));
        assert!(!is_newline(b' '));

        // No byte above ASCII is ever a space, whatever the locale.
        for byte in 0x80..=0xff_u8 {
            assert!(!is_space(byte), "{byte:#04x}");
            assert!(!is_blank(byte), "{byte:#04x}");
        }
    }

    /// `src/tool_cfgable.h:34` defines `checkprefix` through
    /// `curl_strnequal`, which `lib/strequal.c:66-72` documents as raw and
    /// locale-independent: "capable of comparing a-z case insensitively".
    #[test]
    fn the_prefix_test_folds_ascii_case_only() {
        assert!(check_prefix(b"type=", b"type=a/b"));
        assert!(check_prefix(b"type=", b"TYPE=a/b"));
        assert!(check_prefix(b"type=", b"TyPe=a/b"));
        assert!(!check_prefix(b"type=", b"typ"));
        assert!(!check_prefix(b"type=", b"other=1"));
        assert!(check_prefix(b"", b"anything"));
        // Not Unicode case folding: the Kelvin sign must not match `k`.
        assert!(!check_prefix(b"k", "\u{212a}".as_bytes()));
    }

    /// An upper-case attribute really does parse, which is what
    /// `checkprefix`'s case folding buys.
    #[test]
    fn attributes_are_recognised_case_insensitively() {
        let parsed =
            parse("field=v;TYPE=a/b;FileName=n;ENCODER=e;Headers=X: y");
        let part = parsed.at(&[0]);
        assert_eq!(text(&part.content_type), Some("a/b"));
        assert_eq!(text(&part.filename), Some("n"));
        assert_eq!(text(&part.encoder), Some("e"));
        assert_eq!(part.headers, vec![b"X: y".to_vec()]);
        assert_eq!(parsed.output, "");
    }

    /// `:78-94` and `lib/curlx/warnless.c:209-221`: the conversions
    /// round-trip.
    ///
    /// Neither is exercised with a negative input, because both C originals
    /// assert against it (`DEBUGASSERT(sonum >= 0)`) and every call site here
    /// bounds the value first -- `:202` tests `m->size >= 0` before `:207`
    /// narrows anything. The `-1` deferred-error sentinel therefore never
    /// reaches [`sotouz`]; it is only ever compared.
    #[test]
    fn the_size_conversions_round_trip() {
        for value in [0_usize, 1, 7, 4096, 1 << 20] {
            assert_eq!(sotouz(uztoso(value)), value);
        }
        assert_eq!(uztoso(0), 0);
        assert_eq!(uztoso(usize::from(u8::MAX)), 255);
    }

    /// The frozen texts at `:220` and `:561` carry the bare system message.
    ///
    /// The suffix-stripping POLICY is owned and unit-tested by
    /// `curl-rs-lib`'s `os_error_message`, including the crafted shapes it must
    /// leave alone and the Miri double-annotation case; duplicating those
    /// assertions here is what let the two implementations drift in the first
    /// place. What belongs to this file is that its two call sites really do go
    /// through that helper, which is asserted on the emitted bytes.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's strerror_r doubles the suffix")]
    fn the_os_error_suffix_is_stripped() {
        // ENOENT, rendered by the shared helper. The expected value is not
        // spelled out because the text is the platform's and differs between
        // Linux and Darwin; what matters is that this file emits exactly it.
        let expected =
            curl_rs_lib::os_error_message(&io::Error::from_raw_os_error(2));
        assert!(!expected.contains("(os error"));

        // `:561` -- `Cannot read from %s: %s` over an absent header file.
        let dir = temp_dir!();
        let path = dir.path().join("absent");
        let spec = format!("field=value;headers=@{}", path.display());
        let parsed = parse(&spec);
        // `unwrapped` for the reason given on that method: the path this
        // message carries decides where `voutf` breaks the line.
        assert!(
            parsed.unwrapped().contains(expected.as_str()),
            "the shared renderer's text must appear verbatim: {}",
            parsed.output
        );
        assert!(
            !parsed.output.contains("(os error"),
            "the annotation must not survive: {}",
            parsed.output
        );
    }

    /// `slist_append` mirrors `:400-409`: it appends, and the order is the
    /// order of appending.
    #[test]
    fn the_header_list_appends_in_order() {
        let mut list: Vec<Vec<u8>> = Vec::new();
        assert!(slist_append(&mut list, b"A: 1").is_ok());
        assert!(slist_append(&mut list, b"B: 2").is_ok());
        assert_eq!(list, vec![b"A: 1".to_vec(), b"B: 2".to_vec()]);
    }

    /// An embedded NUL ends the argument, because `curlx_strdup` at `:742`
    /// copies a C string.
    #[test]
    fn an_embedded_nul_ends_the_argument() {
        let parsed = parse_bytes(b"field=value\0ignored");
        assert!(parsed.outcome.is_ok());
        assert_eq!(parsed.at(&[0]).data.as_deref(), Some(&b"value"[..]));

        // And a NUL before the '=' hides it entirely.
        let parsed = parse_bytes(b"field\0=value");
        assert!(parsed.outcome.is_err());
        assert!(parsed.output.contains("Illegally formatted input field"));
    }

    // Diagnostic inventory

    /// Every diagnostic this file can emit, at the severity C emits it, with
    /// the text frozen.
    ///
    /// Thirteen of the sixteen texts at `src/tool_formparse.c` are reachable
    /// and are asserted here or in the focused tests above. The remaining three
    /// -- `:454` and `:462` ("Out of memory for field headers", deliberately
    /// duplicated) and `:588` ("Out of memory for field header", deliberately
    /// SINGULAR) -- are allocation-failure paths behind `Vec::try_reserve`.
    /// They cannot be reached without a real allocation failure, so they are
    /// verified by inspection rather than by execution; they are kept distinct
    /// and unnormalised, which is the property that mattered.
    #[test]
    fn the_reachable_diagnostics_are_frozen() {
        let cases: [(&str, &str); 10] = [
            (
                "field=\"q\"junk",
                "Trailing data after quoted form parameter",
            ),
            ("field=v;bogus=1", "skip unknown form field: bogus=1"),
            ("outer=(;filename=n", "Field filename not allowed here: n"),
            ("outer=(;encoder=e", "Field encoder not allowed here: e"),
            ("field=<f;filename=n", "Field filename not allowed here: n"),
            ("=)", "no multipart to terminate"),
            ("field", "Illegally formatted input field"),
            (
                "field=v;type=a/b,x",
                "garbage at end of field specification: ,x",
            ),
            (
                "field=v;type=a/b(x",
                "garbage at end of field specification: (x",
            ),
            ("field=\"q\"x", "Trailing data after quoted form parameter"),
        ];
        for (spec, expected) in cases {
            let parsed = parse(spec);
            assert!(
                parsed.output.contains(expected),
                "{spec} did not emit {expected:?}; it emitted {:?}",
                parsed.output
            );
            assert!(
                parsed.output.starts_with(msgs::WARN_PREFIX),
                "{spec} must warn, not error: {:?}",
                parsed.output
            );
        }
    }

    /// The two "not allowed here" texts that no `-F` argument can reach.
    ///
    /// Measured across all four `get_param_part` call sites in
    /// `src/tool_formparse.c` -- `:756` (a group), `:785` (`@`), `:831` (`<`)
    /// and `:858` (literal) -- `ptype` and `pheaders` are `&type` and
    /// `&headers` every single time, never NULL. So `:635` and `:650` are
    /// unreachable through the command line in curl 8.19.0-DEV; they guard the
    /// shared helper for a caller that shuts those slots. Both are reproduced
    /// anyway, because deleting an unreachable branch is still deleting
    /// behaviour, and are asserted here by driving the helper directly.
    #[test]
    fn shut_slots_report_content_type_and_headers() {
        // `get_param_part` is the shared gate, so drive it with every slot shut
        // -- which is what `:632-652` guards.
        let mut sink: Vec<u8> = Vec::new();
        let mut diag = FormDiag::new(&mut sink, MsgConfig::default());
        let mut scanner = Scanner::new(b"v;type=a/b;headers=X: y");
        let shut = Slots {
            content_type: false,
            filename: false,
            encoder: false,
            headers: false,
        };
        let outcome = scanner.get_param_part(0, shut, &mut diag);
        assert!(outcome.is_ok(), "the scan succeeds");
        let Ok(part) = outcome else { return };
        assert_eq!(part.content_type, None);
        assert!(part.headers.is_empty());

        let output = String::from_utf8_lossy(&sink);
        assert!(
            output.contains("Field content type not allowed here: a/b"),
            "{output}"
        );
        assert!(
            output.contains("Field headers not allowed here: X: y"),
            "{output}"
        );
    }

    /// `--silent` suppresses these warnings, because they travel through
    /// `warnf` (`src/tool_msgs.c:95-104`).
    #[test]
    fn silent_suppresses_the_warnings() {
        let mut tree = MimeTree::new();
        let mut stdin = TestStdin::default();
        let mut sink: Vec<u8> = Vec::new();
        {
            let silent = MsgConfig::new(true, false, false);
            let mut diag = FormDiag::new(&mut sink, silent);
            let outcome =
                formparse(b"field", &mut tree, false, &mut stdin, &mut diag);
            assert!(outcome.is_err(), "the failure still happens");
        }
        assert!(sink.is_empty(), "but nothing is said about it");
    }

    // `ProcessStdin`: the real descriptor, not a double
    //
    // Every test above drives `TestStdin`, which proves the parser's branching
    // and nothing about the three platform calls `ProcessStdin` makes. A double
    // cannot: a `regular_extent` that always answered `None`, a `read_chunk`
    // that returned `Ok(0)` and a `seek_to` that did nothing would leave all of
    // them green. So the production implementation is exercised against a real
    // descriptor here.
    //
    // Standard input cannot be redirected from inside a process without `dup2`,
    // which is `unsafe` and which AAP section 0.1.1 goal G6 closes for this
    // crate. Re-running the test as a child with `Stdio` set is how the same
    // observation is obtained safely, and it needs nothing of the host beyond a
    // writable temporary directory.

    /// Names a child test the way the libtest harness does.
    ///
    /// `module_path!()` is prefixed with the crate name, which `--exact` does
    /// not want. Deriving the rest keeps this working in whichever crate the
    /// file is compiled as part of.
    fn child_test_path(function: &str) -> String {
        let full = module_path!();
        let within_crate = full.split_once("::").map_or(full, |(_, rest)| rest);
        format!("{within_crate}::{function}")
    }

    /// Set for a child run, and carries the bytes standard input holds.
    const STDIN_CHILD_VAR: &str = "BLITZY_FORMPARSE_STDIN_CONTENT";

    /// What the child finds on its standard input. Short, and not all one byte,
    /// so a read that returned the wrong offset would show.
    const STDIN_CHILD_CONTENT: &str = "0123456789abcdef";

    /// Runs one child test with standard input taken from `source`.
    ///
    /// Returns `None` when the child could not be spawned at all, which is a
    /// skip rather than a failure: there is nothing to assert about the host in
    /// that case.
    fn spawn_stdin_child(
        function: &str,
        source: std::fs::File,
    ) -> Option<std::process::Output> {
        let exe = std::env::current_exe().ok()?;
        std::process::Command::new(exe)
            .args(["--exact", &child_test_path(function), "--nocapture"])
            .env(STDIN_CHILD_VAR, STDIN_CHILD_CONTENT)
            .stdin(std::process::Stdio::from(source))
            .output()
            .ok()
    }

    #[test]
    #[cfg_attr(miri, ignore = "spawning a process is unsupported")]
    fn a_regular_standard_input_is_read_and_repositioned() {
        if std::env::var_os(STDIN_CHILD_VAR).is_some() {
            // The child half is below; a parent inside a child would recurse.
            return;
        }
        let dir = temp_dir!();
        let path = dir.path().join("stdin");
        let written = std::fs::write(&path, STDIN_CHILD_CONTENT);
        assert!(written.is_ok(), "the fixture file must be writable");
        let opened = std::fs::File::open(&path);
        assert!(opened.is_ok(), "the fixture file must be readable");
        let Ok(source) = opened else { return };

        let child =
            spawn_stdin_child("stdin_child_reads_a_regular_file", source);
        let Some(output) = child else { return };

        assert!(
            output.status.success(),
            "the child failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The child half of the test above. Inert unless the variable is set.
    #[test]
    fn stdin_child_reads_a_regular_file() {
        let held = std::env::var(STDIN_CHILD_VAR);
        let Ok(expected) = held else { return };
        let size = expected.len();
        let mut stdin = ProcessStdin::new();

        // `:128` and `:131-135`: a fresh child is positioned at the start, and
        // the extent is the whole file.
        assert_eq!(
            stdin.regular_extent(),
            Some((0, size as i64)),
            "a redirected regular file must select the lazy branch"
        );

        // `:216` -- `fread(buffer, 1, nitems, stdin)`.
        let mut first = [0u8; 4];
        let read = stdin.read_chunk(&mut first);
        assert_eq!(read.ok(), Some(first.len()));
        assert_eq!(&first, &expected.as_bytes()[..first.len()]);

        // The offset really is consulted rather than assumed: C reads `ftell`
        // at `:128` for exactly this reason, because `-F` may be given after
        // something else has already consumed part of standard input.
        assert_eq!(
            stdin.regular_extent(),
            Some((first.len() as i64, size as i64)),
            "the origin must follow the descriptor"
        );

        // `:244` -- the retry rewind, and then the same bytes again. This is
        // what would replay stale buffered data if the read went through
        // `io::Stdin` instead of the descriptor.
        assert!(stdin.seek_to(0).is_ok());
        let mut again = [0u8; 4];
        assert_eq!(stdin.read_chunk(&mut again).ok(), Some(again.len()));
        assert_eq!(again, first, "the rewind must undo the read");

        // Reading past the end is end of input, not an error.
        assert!(stdin.seek_to(size as i64).is_ok());
        let mut past = [0u8; 4];
        assert_eq!(stdin.read_chunk(&mut past).ok(), Some(0));
    }

    #[test]
    #[cfg_attr(miri, ignore = "spawning a process is unsupported")]
    fn a_character_device_standard_input_is_buffered_instead() {
        if std::env::var_os(STDIN_CHILD_VAR).is_some() {
            return;
        }
        let opened = std::fs::File::open("/dev/null");
        // A host without `/dev/null` would make this a statement about the
        // host, so it is a skip.
        let Ok(source) = opened else { return };

        let child = spawn_stdin_child(
            "stdin_child_rejects_a_non_regular_stream",
            source,
        );
        let Some(output) = child else { return };

        assert!(
            output.status.success(),
            "the child failed:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// The child half of the test above. Inert unless the variable is set.
    #[test]
    fn stdin_child_rejects_a_non_regular_stream() {
        if std::env::var_os(STDIN_CHILD_VAR).is_none() {
            return;
        }
        // `/dev/null` is seekable, so `ftell` succeeds and only `S_ISREG` can
        // reject it -- which makes this the case that proves the file-type test
        // is really made. `:131-135` collapses it into the buffering branch.
        assert_eq!(
            ProcessStdin::new().regular_extent(),
            None,
            "a character device must not select the lazy branch"
        );
    }
}
