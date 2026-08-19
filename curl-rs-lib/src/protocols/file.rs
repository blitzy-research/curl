// /***************************************************************************
//  *                                  _   _ ____  _
//  *  Project                     ___| | | |  _ \| |
//  *                             / __| | | | |_) | |
//  *                            | (__| |_| |  _ <| |___
//  *                             \___|\___/|_| \_\_____|
//  *
//  * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//  *
//  * This software is licensed as described in the file COPYING, which
//  * you should have received as part of this distribution. The terms
//  * are also available at https://curl.se/docs/copyright.html.
//  *
//  * You may opt to use, copy, modify, merge, publish, distribute and/or sell
//  * copies of the Software, and permit persons to whom the Software is
//  * furnished to do so, under the terms of the COPYING file.
//  *
//  * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
//  * KIND, either express or implied.
//  *
//  * SPDX-License-Identifier: curl
//  *
//  ***************************************************************************/
//! The `file://` scheme.
//!
//! # What this file supersedes, with locators
//!
//! The whole of **`lib/file.c`, 637 lines**:
//!
//! * `lib/file.c:78-83` -- `struct FILEPROTO`, the per-transfer state;
//!   [`FileState`] here.
//! * `lib/file.c:76` -- the meta key `"meta:proto:file:easy"` under which that
//!   state is stashed on the easy handle; see [`FileProtocol`] for what
//!   replaces the hash lookup.
//! * `lib/file.c:85-93` -- `file_cleanup`; [`FileState::cleanup`].
//! * `lib/file.c:95-102` -- `file_easy_dtor`, which has no successor: dropping
//!   a [`FileState`] runs the same release.
//! * `lib/file.c:104-116` -- `file_setup_connection`;
//!   [`Protocol::setup_connection`].
//! * `lib/file.c:118-129` -- `file_done`; [`Protocol::done`].
//! * `lib/file.c:136-247` -- `file_connect`; [`Protocol::connect_it`].
//! * `lib/file.c:249-256` -- `file_disconnect`; [`Protocol::disconnect`].
//! * `lib/file.c:264-374` -- `file_upload`; [`FileProtocol::upload`].
//! * `lib/file.c:384-599` -- `file_do`; [`FileProtocol::perform`].
//! * **`lib/file.c:601-619`** -- `Curl_protocol_file`, the 17-slot vtable, of
//!   which exactly **5 slots are occupied** and twelve are `ZERO_NULL`:
//!   `setup_connection`, `do_it`, `done`, `connect_it` and `disconnect`. This
//!   is the sparsest handler in the C tree.
//! * **`lib/file.c:626`** -- `const struct Curl_scheme Curl_scheme_file`, whose
//!   six columns are reproduced by [`SCHEME_NAME`], [`SCHEME_PROTOCOL_BITS`],
//!   [`SCHEME_FLAGS`] and [`SCHEME_DEFPORT`] and assembled into the single
//!   33-row registry by [`super::SCHEMES`]. **No second registry is built
//!   here.**
//!
//! Read rather than superseded:
//!
//! * `lib/curl_range.c:35-89` -- `Curl_range`, which `file_do` calls at
//!   `lib/file.c:474`. The grammar itself belongs to
//!   [`crate::util::range`] and is only APPLIED here, by [`apply_range`].
//! * `lib/urlapi.c:857-905` -- the `file://` authority rule. An authority is
//!   accepted only when it is empty, `localhost` or `127.0.0.1`; anything else
//!   is `CURLE_URL_MALFORMAT`. That test happens in the URL parser, is already
//!   superseded by `crate::url` (`curl-rs-lib/src/url/mod.rs:1778-1830`), and
//!   is deliberately NOT repeated here -- `tests/data/test1145` is that layer's
//!   oracle, not this file's. What reaches this module is an
//!   already-validated `data->state.up.path`.
//! * `lib/parsedate.c:83-92` -- `Curl_wkday` and `Curl_month`, whose guard
//!   names `CURL_DISABLE_FILE` explicitly and whose comment is *"These names
//!   are also used by FTP and FILE code"*. Consumed from
//!   [`crate::util::parsedate`]; not restated.
//! * `lib/curlx/timeval.c:251-272` -- `curlx_gmtime`. Consumed as
//!   [`crate::util::timeval::gmtime`], the crate's only calendar conversion.
//!
//! # `PROTOPT_NONETWORK` is the semantic core of this module
//!
//! `lib/file.c:635` registers `PROTOPT_NONETWORK | PROTOPT_NOURLQUERY`, and the
//! first of those two flags is a hard invariant rather than an optimisation:
//!
//! **No socket is ever opened, no connection filter chain is built, no name is
//! resolved and no proxy setting applies.** Nothing in this file names
//! `crate::conn::filters`, `crate::dns`, `crate::proxy` or
//! `crate::tls`; the only I/O is against the local filesystem, through the
//! injected [`FileSystem`] seam. [`mod tests`](self) asserts the invariant from
//! the registry side -- the row carries `NONETWORK`, its default port is `0`,
//! and a whole transfer completes against a [`TransferCtx`] whose filter chains
//! stay empty.
//!
//! `PROTOPT_NOURLQUERY` is the second half: the URL's query component is not
//! appended to the path, so `file:///x?y` reads `/x` and never `/x?y`. That is
//! enforced by the URL layer honouring the flag, and this module simply never
//! looks at a query.
//!
//! # The vtable takes `data`, and this trait hands over `conn`
//!
//! Every one of the five occupied slots below ignores its [`TransferCtx`], and
//! that is not a shortcut -- it is precisely what the C does. `file://` reads
//! nothing from `struct connectdata`: `file_setup_connection` opens with
//! `(void)conn` (`lib/file.c:108`), `file_disconnect` with `(void)conn` and
//! `(void)dead_connection` (`:253-254`), and `file_connect`, `file_do` and
//! `file_done` take `struct Curl_easy *data` alone.
//!
//! [`TransferCtx`] is `conn`'s half of that pair -- the filter chains, the
//! injected clock, the scheme row and the socket index. `data`'s half is what
//! this scheme needs, and it arrives through the two seams this file declares:
//! [`FileClient`], one member per `data->` field `lib/file.c` touches, and
//! [`FileSystem`], the filesystem those fields are read and written against.
//! A [`FileProtocol`] binds both **for one transfer**, exactly as each C easy
//! handle carries its own `struct FILEPROTO` -- which is what makes two
//! concurrent `file://` transfers in one multi handle independent.
//!
//! # Why [`super::SCHEMES`]'s `file` row still carries `run: None`
//!
//! Recorded here because it is a measured property of the current checkout and
//! not an oversight, and because the remedy belongs to two other files:
//!
//! 1. [`super::SCHEMES`] is a `const` table (`protocols/mod.rs:956`). A `const`
//!    may not refer to a `static` (`error[E0013]`) and may not hold a reference
//!    to interior-mutable data (`error[E0492]`), so the registry can only carry
//!    a STATELESS handler. A [`FileProtocol`] owns per-transfer state and is
//!    therefore not placeable in it.
//! 2. `crate::transfer::TransferIo::xfer_ctx(&mut self) -> TransferCtx<'_>`
//!    borrows its owner mutably, so the transfer core cannot hand `do_it` both
//!    a context and the `&mut dyn TransferIo` that a [`FileClient`] would
//!    project from. Until that borrow split changes, no stateful scheme is
//!    reachable through the registry.
//!
//! Leaving the row `None` is also the truthful answer rather than merely the
//! available one. `crate::version`'s `ENGINE_PROTOCOLS` is
//! `Engine::inert`, so the `Protocols:` banner withholds `file`, and
//! specification 0.6.5 measures that asymmetry precisely: under-reporting a
//! capability makes a fixture SKIP, over-reporting makes it RUN AND FAIL.
//! Advertising a runnable `file://` that no driver can reach would convert 27
//! clean skips into 27 spurious failures.
//!
//! What this file supplies is everything the wiring needs: the five slots, the
//! two seams, the production [`StdFileSystem`], and the four registration facts
//! [`mod tests`](self) asserts `super`'s row against.
//!
//! # Byte-exactness, and the three places it bites
//!
//! `compareparts` (`tests/getpart.pm:351+`) joins both arrays into a single
//! string and compares them as one -- no per-line matching, no normalisation,
//! no reordering. For `file://` the observable output is the body plus the
//! header-like lines this scheme FABRICATES, so all three of the following are
//! frozen and are asserted byte for byte below:
//!
//! * `Content-Length: <n>\r\n`, emitted only when the size is known.
//! * `Accept-ranges: bytes\r\n` -- **note the lower-case `r` in `ranges`.**
//!   `lib/file.c:430` spells it that way, HTTP spells it `Accept-Ranges`, and
//!   the C's spelling is what reaches the client. It is not a typo to fix.
//! * `Last-Modified: <wkday>, <dd> <Mon> <yyyy> <hh>:<mm>:<ss> GMT\r\n`,
//!   followed by a bare `\r\n` that ends the synthesised header block.
//!
//! In that order, all four with [`ClientWriteFlags::HEADER`] and none with
//! `STATUS` -- `crate::headers` stores a write only when it is `HEADER`
//! WITHOUT `STATUS`, so adding `STATUS` here would withhold these lines from
//! `curl_easy_header`.
//!
//! # No wall clock is consulted, by construction
//!
//! `lib/file.c` calls no clock function. The one timestamp it formats is the
//! file's own `st_mtime`, read from the filesystem, and the one comparison it
//! makes is `Curl_meets_timecondition(data, data->info.filetime)` against
//! `data->set.timevalue` -- a stored option, not `time(NULL)`. So this file
//! contains no `Instant::now()` and no `SystemTime::now()`: the injected
//! [`crate::util::timeval::Clock`] on [`TransferCtx`] is genuinely unused, and
//! [`mod tests`](self) proves it by advancing a
//! [`crate::util::timeval::TestClock`] between two transfers and asserting the
//! emitted bytes are identical.

use core::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::UNIX_EPOCH;

use crate::conn::ProtocolOptions;
use crate::error::{CURLcode, CodeResult};
use crate::protocols::{ProtoFuture, Protocol, TransferCtx};
use crate::transfer::sendf::ClientWriteFlags;
use crate::url::escape::{urldecode, UrlReject};
use crate::util::parsedate::{MONTH, WKDAY};
use crate::util::range::{self, MAXDOWNLOAD_UNLIMITED};
use crate::util::timeval::gmtime;

// The registration facts -- `Curl_scheme_file` (`lib/file.c:626-637`)

/// The `name` column: `"file"`, **lower case**.
///
/// `lib/file.c:627`. Four rows of the same table are UPPER CASE -- `"SFTP"`,
/// `"SCP"`, `"WS"` and `"WSS"` -- and this one is not; the comparison is
/// case-folded on both sides, so the spelling is reproduced rather than
/// normalised. `tests/data/test202` requests the same file twice, once as
/// `file://` and once as `FILE://`, which is the fixture that would catch a
/// case-sensitive lookup.
// Consumer: `super::SCHEMES`'s `file` row, asserted equal by `mod tests`.
#[allow(dead_code)]
pub(crate) const SCHEME_NAME: &[u8] = b"file";

/// The `flags` column: `PROTOPT_NONETWORK | PROTOPT_NOURLQUERY`.
///
/// `lib/file.c:635`. The bits are CONSUMED from
/// [`crate::conn::ProtocolOptions`], which owns the one definition of all
/// seventeen `PROTOPT_*` values, and are deliberately not redeclared here:
/// `NONETWORK` is `1 << 4` and `NOURLQUERY` is `1 << 6`
/// (`curl-rs-lib/src/conn/mod.rs:363` and `:371`).
///
/// [`super::FLAGS_FILE`] holds the same fold for the registry row itself.
/// Both exist, and that is the point: this one is written from `lib/file.c`
/// and that one from the registry's side, and [`mod tests`](self) asserts they
/// agree, so a mistake in either is caught rather than confirmed.
// Consumer: `super::FLAGS_FILE`, asserted equal by `mod tests`.
#[allow(dead_code)]
pub(crate) const SCHEME_FLAGS: ProtocolOptions =
    ProtocolOptions::NONETWORK.union(ProtocolOptions::NOURLQUERY);

/// The `defport` column: **`0`**.
///
/// `lib/file.c:636`, written as a bare literal in the C rather than as one of
/// the `PORT_*` macros, because the scheme has no network endpoint at all. It
/// is the only zero default port in the 33-row registry, and it pairs with
/// [`ProtocolOptions::NONETWORK`].
// Consumer: `super::SCHEMES`'s `file` row, asserted equal by `mod tests`.
#[allow(dead_code)]
pub(crate) const SCHEME_DEFPORT: u16 = 0;

/// The `protocol` and `family` columns, which are the SAME bit:
/// `CURLPROTO_FILE`.
///
/// `lib/file.c:633-634`. Four rows of the registry have a family differing
/// from their protocol -- `ftps` is `FTP`, and `https`, `WS` and `WSS` are all
/// `HTTP` -- and `file` is not one of them. Expressed as one constant because
/// the C writes the same token twice and a reader should see that it is the
/// same token.
// Consumer: `super::SCHEMES`'s `file` row, asserted equal by `mod tests`.
#[allow(dead_code)]
pub(crate) const SCHEME_PROTOCOL_BITS: super::Proto = super::Proto::FILE;

// The user-visible diagnostics -- every `failf` of `lib/file.c`

/// `failf` text of `file_connect` for a file that would not open
/// (`lib/file.c:240`).
///
/// The C formats `data->state.up.path`, which is the **still-encoded** URL
/// path, and not the percent-decoded path it just failed to open. That
/// distinction is user-visible -- a URL of `file:///no%20such` reports
/// `/no%20such` rather than `/no such` -- so the argument is the raw path
/// here too.
fn could_not_open(up_path: &[u8]) -> String {
    format!("Could not open file {}", String::from_utf8_lossy(up_path))
}

/// `failf` text of `file_upload` for a target that would not open for writing
/// (`lib/file.c:304`).
///
/// This one formats `file->path`, the DECODED path, unlike
/// [`could_not_open`] above. The asymmetry is the C's.
fn cannot_open_for_writing(path: &[u8]) -> String {
    format!("cannot open {} for writing", String::from_utf8_lossy(path))
}

/// `failf` text of `file_upload` when the target's size cannot be read
/// (`lib/file.c:316`), which is only reached for a negative resume offset.
fn cannot_get_the_size_of(path: &[u8]) -> String {
    format!("cannot get the size of {}", String::from_utf8_lossy(path))
}

/// `failf` text of `file_do` when a negative resume offset needs a size that
/// `fstat` did not supply (`lib/file.c:482`).
///
/// The trailing full stop is the C's and is part of the string.
const CANNOT_GET_SIZE_OF_FILE: &str = "cannot get the size of file.";

/// `failf` text of `file_do` for a resume offset past the end
/// (`lib/file.c:495`).
const FAILED_TO_RESUME: &str = "failed to resume file:// transfer";

// The synthesised header block -- `lib/file.c:424-471`

/// `"Content-Length: "`, the first synthesised line's field name.
///
/// `lib/file.c:434` formats `"Content-Length: %" FMT_OFF_T "\r\n"`. Split into
/// a prefix constant and a rendered number so that the field name is one
/// literal a reader can compare against the C, and so that
/// [`mod tests`](self) can assert the exact bytes of each without rebuilding
/// the format string.
#[rustfmt::skip]
const CONTENT_LENGTH: &str = "Content-Length: ";

/// `"Accept-ranges: bytes\r\n"`, emitted verbatim.
///
/// `lib/file.c:430`, where it is a `static const char[]` and is written with
/// `sizeof(accept_ranges) - 1` so the NUL is not sent.
///
/// **The lower-case `r` in `ranges` is curl's, and it is deliberate to keep
/// it.** RFC 9110 spells the field `Accept-Ranges`; `lib/file.c` does not, the
/// bytes reach the client through the writer chain, and specification 0.8.1
/// freezes them. `rustfmt` must not reflow this line, hence the attribute.
#[rustfmt::skip]
const ACCEPT_RANGES: &str = "Accept-ranges: bytes\r\n";

/// `"Last-Modified: "`, the third synthesised line's field name.
///
/// `lib/file.c:453`, whose full format string is
/// `"Last-Modified: %s, %02d %s %4d %02d:%02d:%02d GMT\r\n"`.
#[rustfmt::skip]
const LAST_MODIFIED: &str = "Last-Modified: ";

/// The bare `"\r\n"` that ends the synthesised header block
/// (`lib/file.c:464`).
///
/// Written by the C as `Curl_client_write(data, CLIENTWRITE_HEADER, "\r\n", 2)`
/// -- two bytes, with the length spelled out.
#[rustfmt::skip]
const END_OF_HEADERS: &str = "\r\n";

/// Renders one `Content-Length:` line exactly as `lib/file.c:432-434` does.
///
/// The C writes into `char header[80]` with `curl_msnprintf`. The widest value
/// this line can carry is `i64::MIN`, giving 38 bytes including the CRLF, so
/// the C's buffer never truncates and no truncation is emulated.
fn content_length_line(size: i64) -> String {
    format!("{CONTENT_LENGTH}{size}\r\n")
}

/// Renders one `Last-Modified:` line exactly as `lib/file.c:451-460` does.
///
/// Three details are load-bearing and each is the C's:
///
/// * **The weekday index is `wday ? wday - 1 : 6`.** [`WKDAY`] starts at
///   Monday while [`crate::util::timeval::BrokenTime::wday`] numbers Sunday
///   zero, so Sunday maps to index 6 and every other day to `wday - 1`. Two
///   weekday conventions coexist in this workspace and mixing them shifts
///   every date by one day.
/// * **The month index is used as-is.** Both [`MONTH`] and
///   [`crate::util::timeval::BrokenTime::mon`] are 0-based.
/// * **The year field is `%4d`, not `%04d`.** Width four, SPACE padded. A year
///   below 1000 therefore renders with a leading space, which is what the C
///   emits and what `{:4}` reproduces.
///
/// # Errors
///
/// Whatever [`gmtime`] reports -- [`CURLcode::BadFunctionArgument`] for an
/// instant whose year does not fit the field that carries it, which is the
/// code `curlx_gmtime` itself returns when the platform function fails
/// (`lib/curlx/timeval.c:255`). `lib/file.c:446-448` propagates it unchanged.
fn last_modified_line(filetime: i64) -> CodeResult<String> {
    // `result = curlx_gmtime(filetime, &buffer); if(result) return result;`
    let at = gmtime(filetime)?;

    // `Curl_wkday[tm->tm_wday ? tm->tm_wday - 1 : 6]`. Both subscripts are
    // bounded by `gmtime`'s own postconditions -- `wday` is `0..=6` and `mon`
    // is `0..=11` -- so the lookups cannot miss; they are written with `get`
    // and a fallback rather than with `[]` because this crate admits no
    // panicking index on a transfer path.
    let weekday_index = if at.wday == 0 {
        6
    } else {
        usize::try_from(at.wday.saturating_sub(1)).unwrap_or(0)
    };
    let weekday = WKDAY.get(weekday_index).copied().unwrap_or("");
    let month = MONTH
        .get(usize::try_from(at.mon).unwrap_or(0))
        .copied()
        .unwrap_or("");

    // The date itself first, so that the C's format string stays on ONE line
    // and cannot be reflowed or spliced by a line continuation. It is a
    // wire-bearing literal, and the `#[rustfmt::skip]` on [`LAST_MODIFIED`]
    // protects only the field name.
    #[rustfmt::skip]
    let date = format!(
        "{weekday}, {:02} {month} {:4} {:02}:{:02}:{:02} GMT",
        at.mday, at.year, at.hour, at.min, at.sec,
    );

    Ok(format!("{LAST_MODIFIED}{date}\r\n"))
}

// The filesystem seam -- `curlx_open`, `curlx_fstat`, `read`, `write`,
// `curl_lseek`, `opendir` and `readdir`

/// The three fields of `struct stat` that `lib/file.c` reads.
///
/// `curlx_fstat` fills a whole `struct stat`; `file_do` and `file_upload`
/// consult exactly `st_size`, `st_mtime` and `S_ISDIR(st_mode)`
/// (`lib/file.c:412-418`, `:485`, `:517`, `:531`, `:314-319`). Carrying only
/// those three keeps the seam narrow enough for an in-memory implementor and
/// makes the dependency on the platform's `stat` layout disappear.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileMeta {
    /// `st_size`. Meaningful only when [`Self::is_dir`] is false, because
    /// `file_do` reads it only under `if(!S_ISDIR(statbuf.st_mode))`.
    pub(crate) size: i64,

    /// `st_mtime`, in seconds since the Unix epoch.
    ///
    /// Read UNCONDITIONALLY by `lib/file.c:416`, outside the `S_ISDIR` guard,
    /// so a directory has one too and its `Last-Modified:` line is emitted.
    pub(crate) mtime: i64,

    /// `S_ISDIR(st_mode)`.
    pub(crate) is_dir: bool,
}

/// One open file -- the successor of the `int fd` of `struct FILEPROTO`.
///
/// Object-safe on purpose: [`FileState`] stores a `Box<dyn FileHandle>`, so a
/// test hands the engine an in-memory handle and no real file is opened.
///
/// # Errors are the platform's, and are never inspected
///
/// Every method reports [`std::io::Error`] rather than a code of this crate's
/// own, because `lib/file.c` never examines `errno`: it tests `fd == -1`,
/// `curlx_fstat(...) != -1`, `nread <= 0` and `nwritten != nread`, and maps
/// each to one fixed [`CURLcode`]. Inventing a richer error type here would
/// invite a caller to branch on something the C cannot see.
pub(crate) trait FileHandle: fmt::Debug + Send {
    /// `curlx_fstat(fd, &statbuf)` (`lib/file.c:412`, `:314`).
    ///
    /// # Errors
    ///
    /// Whatever the platform reports. The C's caller treats any failure as
    /// `fstated = FALSE` and carries on.
    fn stat(&mut self) -> std::io::Result<FileMeta>;

    /// `read(fd, buf, blen)` (`lib/file.c:544`).
    ///
    /// # Errors
    ///
    /// Whatever the platform reports. **The C's caller treats an error exactly
    /// as it treats end of file** -- see [`FileProtocol::download`].
    fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize>;

    /// `write(fd, buf, blen)` (`lib/file.c:357`).
    ///
    /// Returns the number of bytes accepted, which the caller COMPARES against
    /// the number offered: a short write is [`CURLcode::SendError`] in the C,
    /// so this must not be a write-everything helper.
    ///
    /// # Errors
    ///
    /// Whatever the platform reports.
    fn write(&mut self, from: &[u8]) -> std::io::Result<usize>;

    /// `curl_lseek(fd, offset, SEEK_SET)` (`lib/file.c:519`).
    ///
    /// Returns the resulting absolute position, which the caller compares
    /// against the offset it asked for.
    ///
    /// # Errors
    ///
    /// Whatever the platform reports.
    fn seek_from_start(&mut self, offset: i64) -> std::io::Result<i64>;
}

/// The filesystem itself, injected.
///
/// Three operations, one per C call site: `curlx_open(path, O_RDONLY)`
/// (`lib/file.c:231`), `curlx_open(path, O_WRONLY|O_CREAT|..., perms)`
/// (`:301`) and the `opendir`/`readdir`/`closedir` sequence (`:566-585`).
pub(crate) trait FileSystem: fmt::Debug + Send {
    /// `curlx_open(path, O_RDONLY | CURL_O_BINARY)` (`lib/file.c:231`).
    ///
    /// `CURL_O_BINARY` is `O_BINARY` on the platforms that have it and zero
    /// elsewhere; all four mandated targets are Unix, where it is zero, so
    /// there is nothing to reproduce.
    ///
    /// Note that this SUCCEEDS for a directory on the mandated targets, which
    /// is what makes the directory-listing branch of `file_do` reachable at
    /// all: the C opens the directory, `fstat`s it, sees `S_ISDIR` and then
    /// lists it by name with [`Self::read_dir`].
    ///
    /// # Errors
    ///
    /// Whatever the platform reports. The C's caller only distinguishes
    /// success from failure.
    fn open_read(&self, path: &[u8]) -> std::io::Result<Box<dyn FileHandle>>;

    /// `curlx_open(path, O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC),
    /// perms)` (`lib/file.c:288-302`).
    ///
    /// `append` carries the C's `if(data->state.resume_from) mode |= O_APPEND;
    /// else mode |= O_TRUNC;` -- **note that a NEGATIVE resume offset also
    /// appends**, because the test is `!= 0` and not `> 0`.
    ///
    /// `perms` is `data->set.new_file_perms`, whose default is `0644`. The C
    /// has three spellings of this call, differing only in how the mode is
    /// narrowed for Windows and for 32-bit Android (`:294-302`); all four
    /// mandated targets take the plain one.
    ///
    /// # Errors
    ///
    /// Whatever the platform reports. Any failure is
    /// [`CURLcode::WriteError`] to the caller.
    fn open_write(
        &self,
        path: &[u8],
        append: bool,
        perms: u32,
    ) -> std::io::Result<Box<dyn FileHandle>>;

    /// `opendir(path)` then `readdir` to exhaustion then `closedir`
    /// (`lib/file.c:566-585`).
    ///
    /// Returns the entry names in the order the platform yields them, and the
    /// caller filters them. **The order must not be sorted**: the C emits
    /// `readdir` order, those bytes are the transfer's body, and
    /// specification 0.8.1 freezes them.
    ///
    /// # Errors
    ///
    /// Whatever the platform reports. A failure is [`CURLcode::ReadError`] to
    /// the caller (`lib/file.c:569-571`).
    fn read_dir(&self, path: &[u8]) -> std::io::Result<Vec<Vec<u8>>>;
}

/// Views a byte path as a platform path.
///
/// `lib/file.c` hands the decoded bytes straight to `open()`, so nothing may be
/// lost in translation. On the four mandated targets -- Linux and macOS on
/// x86_64 and aarch64 -- a path IS a byte string, and
/// [`std::os::unix::ffi::OsStrExt`] is the lossless view of one. The
/// alternative, `std::str::from_utf8`, would refuse every path the local
/// filesystem accepts and Unicode cannot spell, which the C accepts happily;
/// the same reasoning and the same call appear in
/// `curl-rs-lib/src/mime/formdata.rs:1841-1849`,
/// `curl-rs-lib/src/cookies/hsts.rs:1198` and
/// `curl-rs-lib/src/conn/socket.rs:515-520`.
#[allow(dead_code)] // Consumer: `StdFileSystem`, once a transfer reaches it.
fn as_path(path: &[u8]) -> &Path {
    use std::os::unix::ffi::OsStrExt;
    Path::new(std::ffi::OsStr::from_bytes(path))
}

/// The production [`FileSystem`]: the host's own.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)] // Consumer: `FileProtocol::with_std_fs`.
pub(crate) struct StdFileSystem;

/// The production [`FileHandle`]: one [`File`].
#[derive(Debug)]
#[allow(dead_code)] // Consumer: `StdFileSystem`'s two open methods.
pub(crate) struct StdFileHandle {
    /// The open descriptor. Closed when this value is dropped, which is
    /// `curlx_close(file->fd)` at `lib/file.c:90` and `:370`.
    file: File,
}

impl FileHandle for StdFileHandle {
    fn stat(&mut self) -> std::io::Result<FileMeta> {
        let meta = self.file.metadata()?;
        Ok(FileMeta {
            // `st_size`. `u64` narrows to the `curl_off_t` the C carries;
            // saturating rather than wrapping, so an implausibly large file
            // reports the largest representable size instead of a negative
            // one that would read as "unknown".
            size: i64::try_from(meta.len()).unwrap_or(i64::MAX),
            // `st_mtime`. A filesystem that cannot report one leaves the C's
            // field whatever `stat` wrote, which for such a filesystem is
            // zero; the epoch is therefore the faithful substitute, and it is
            // what `Last-Modified:` will render.
            mtime: meta
                .modified()
                .ok()
                .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
                .and_then(|since| i64::try_from(since.as_secs()).ok())
                .unwrap_or(0),
            // `S_ISDIR(st_mode)`.
            is_dir: meta.is_dir(),
        })
    }

    fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
        Read::read(&mut self.file, into)
    }

    fn write(&mut self, from: &[u8]) -> std::io::Result<usize> {
        // `Write::write`, deliberately, and never `write_all`: the C compares
        // the returned count against the count it offered and reports
        // `CURLE_SEND_ERROR` when they differ (`lib/file.c:358-360`).
        Write::write(&mut self.file, from)
    }

    fn seek_from_start(&mut self, offset: i64) -> std::io::Result<i64> {
        // `curl_lseek(fd, offset, SEEK_SET)`. A negative offset is rejected by
        // the platform, exactly as `lseek` rejects it, and the caller then
        // sees the position disagree with what it asked for.
        let landed =
            Seek::seek(&mut self.file, SeekFrom::Start(offset_u64(offset)?))?;
        Ok(i64::try_from(landed).unwrap_or(i64::MAX))
    }
}

/// Narrows a seek offset for [`SeekFrom::Start`], refusing a negative one.
///
/// `lseek` with a negative absolute offset fails with `EINVAL`, so this
/// reports the same condition rather than wrapping into an enormous positive
/// offset.
#[allow(dead_code)] // Consumer: `StdFileHandle::seek_from_start`.
fn offset_u64(offset: i64) -> std::io::Result<u64> {
    u64::try_from(offset).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "negative absolute seek offset",
        )
    })
}

impl FileSystem for StdFileSystem {
    fn open_read(&self, path: &[u8]) -> std::io::Result<Box<dyn FileHandle>> {
        let file = File::open(as_path(path))?;
        Ok(Box::new(StdFileHandle { file }))
    }

    fn open_write(
        &self,
        path: &[u8],
        append: bool,
        perms: u32,
    ) -> std::io::Result<Box<dyn FileHandle>> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut options = OpenOptions::new();
        // `O_WRONLY | O_CREAT`, then exactly one of `O_APPEND` and `O_TRUNC`.
        options.write(true).create(true);
        if append {
            options.append(true);
        } else {
            options.truncate(true);
        }
        // The third argument of `curlx_open`: `data->set.new_file_perms`. It
        // applies only when the file is created, which is `open`'s own rule
        // and not something this seam adds.
        options.mode(perms);

        let file = options.open(as_path(path))?;
        Ok(Box::new(StdFileHandle { file }))
    }

    fn read_dir(&self, path: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
        use std::os::unix::ffi::OsStrExt;

        let mut names: Vec<Vec<u8>> = Vec::new();
        // `readdir` order, preserved. See [`FileSystem::read_dir`] for why it
        // is never sorted.
        //
        // One difference from `readdir` that is NOT observable:
        // `std::fs::read_dir` omits `.` and `..`, which `readdir` yields. The
        // C's caller discards every name beginning with `.` (`lib/file.c:575`),
        // so both entries are dropped either way and the emitted bytes are the
        // same. The caller reproduces that filter regardless, because the rule
        // is about dotfiles generally and not about those two names.
        for entry in std::fs::read_dir(as_path(path))? {
            names.push(entry?.file_name().as_bytes().to_vec());
        }
        Ok(names)
    }
}

// The transfer seam -- the members of `struct Curl_easy` that `lib/file.c`
// reads and writes

/// `struct Curl_easy *data`, projected down to what `file://` touches.
///
/// # Why a narrow seam and not `crate::transfer::TransferIo`
///
/// The obvious alternative is to take `&mut dyn crate::transfer::TransferIo`,
/// which already declares `client_write`, `pgrs_check`, `pgrs_update` and,
/// through `request_io()`, `client_read`, `failf`, `no_body` and `maxdownload`.
/// Two things argue against it and one for it, and the resolution keeps both
/// benefits:
///
/// * AGAINST: that trait has around seventy members, most of them about
///   connections, filter chains, redirects and shutdown -- none of which
///   `PROTOPT_NONETWORK` permits this scheme to have. Requiring all seventy of
///   an implementor would put the 80% line coverage this directory is measured
///   at out of reach without a live transfer, which is exactly what
///   specification 0.3.3's pattern P12 exists to avoid.
/// * AGAINST: `lib/file.c` touches a SPECIFIC and small set of `data->` fields.
///   Naming each one, with its C locator, is what makes this module auditable
///   against the C field by field; a wide seam would hide which fields
///   participate.
/// * FOR: one vocabulary is better than two. So the flags below are
///   [`ClientWriteFlags`], `crate::transfer`'s own, rather than a second set of
///   `CLIENTWRITE_*` bits -- and the adapter that will implement this trait
///   when the transfer core is wired is a thin projection of `TransferIo`:
///   [`Self::client_write`] onto `TransferIo::client_write`,
///   [`Self::client_read`] onto `RequestIo::client_read`, [`Self::failf`] onto
///   `RequestIo::failf`, [`Self::pgrs_check`] and [`Self::pgrs_update`] onto
///   their namesakes, and the rest onto `TransferState`, `TransferSettings`
///   and `TransferInfo` fields that already exist.
pub(crate) trait FileClient: fmt::Debug + Send {
    // -- the URL ----------------------------------------------------------

    /// `data->state.up.path` (`lib/file.c:160`, `:240`): the URL's path
    /// component, **still percent-encoded**.
    ///
    /// Already validated by the URL layer, which is where the `file://`
    /// authority rule lives -- see this module's own documentation. Decoding is
    /// this module's job and is done by [`decode_path`].
    fn up_path(&self) -> &[u8];

    // -- request state ----------------------------------------------------

    /// `data->state.upload` (`lib/file.c:239`, `:405`): this transfer is
    /// writing to the file rather than reading it.
    fn is_upload(&self) -> bool;

    /// `data->state.range` (`lib/file.c:420`, `lib/curl_range.c:37`): the raw
    /// `-r` / `CURLOPT_RANGE` string, or [`None`] when none is set.
    ///
    /// Two consumers read it and they read it differently, which is why the
    /// raw [`Option`] is exposed rather than a parsed value: `file_do` tests
    /// only whether it is SET, to decide whether the time condition applies,
    /// while `Curl_range` parses it.
    fn range(&self) -> Option<&[u8]>;

    /// `data->state.use_range` (`lib/curl_range.c:37`): the range is to be
    /// applied.
    ///
    /// Distinct from [`Self::range`] being [`Some`], and both are required:
    /// the C conjoins them, because a redirect can leave a range string set
    /// while clearing the intent to use it.
    fn use_range(&self) -> bool;

    /// `data->state.resume_from` (`lib/file.c:289`, `:313`, `:341`, `:480`).
    ///
    /// Negative means "measure from the end", which is how the `-Y` form of a
    /// range and `-C -` both travel. Zero means no resume.
    fn resume_from(&self) -> i64;

    /// Assigns `data->state.resume_from` (`lib/file.c:319`, `:343`, `:350`,
    /// `:485`, `lib/curl_range.c:51`, `:61`, `:77`).
    fn set_resume_from(&mut self, offset: i64);

    /// `data->req.maxdownload` (`lib/file.c:501`): the high-water mark, or
    /// [`MAXDOWNLOAD_UNLIMITED`] for none.
    fn maxdownload(&self) -> i64;

    /// Assigns `data->req.maxdownload` (`lib/curl_range.c:60`, `:76`, `:87`).
    fn set_maxdownload(&mut self, limit: i64);

    /// `data->req.no_body` (`lib/file.c:469`): the response has no body, so
    /// the synthesised headers are emitted and nothing else.
    fn no_body(&self) -> bool;

    /// `data->state.infilesize` (`lib/file.c:308`): the size of the upload,
    /// or `-1` when it is not known.
    fn infilesize(&self) -> i64;

    // -- settings ---------------------------------------------------------

    /// `data->set.new_file_perms` (`lib/file.c:301`): the mode a created file
    /// is given. `CURLOPT_NEW_FILE_PERMS`, default `0644`.
    fn new_file_perms(&self) -> u32;

    /// `data->set.timecondition` (`lib/file.c:420`): a time condition is set.
    ///
    /// `CURL_TIMECOND_NONE` is zero, so the C's bare `data->set.timecondition`
    /// is a "is it other than NONE" test and this member answers exactly that.
    fn has_timecondition(&self) -> bool;

    /// `Curl_meets_timecondition(data, filetime)` (`lib/file.c:421`).
    ///
    /// Takes `&mut self` because the C's implementation records
    /// `data->info.timecond` on the path that refuses.
    fn meets_timecondition(&mut self, filetime: i64) -> bool;

    /// Assigns `data->info.filetime` (`lib/file.c:416`), which is what
    /// `CURLINFO_FILETIME` reports and what `--remote-time` applies.
    /// `tests/data/test1445` is its fixture.
    fn set_filetime(&mut self, filetime: i64);

    // -- the borrowed transfer buffer --------------------------------------

    /// The length of the buffer `Curl_multi_xfer_buf_borrow` hands out
    /// (`lib/file.c:527`) and of the one `Curl_multi_xfer_ulbuf_borrow` hands
    /// out (`:322`).
    ///
    /// It is `data->set.buffer_size`, whose default is
    /// `CURL_MAX_WRITE_SIZE` -- 16384, held by
    /// `crate::transfer::writeout::CURL_MAX_WRITE_SIZE`. The value is part of
    /// the seam rather than a constant here because it decides how the body is
    /// CHUNKED, and an application's write callback sees each chunk: the
    /// download loop reads at most `len - 1` bytes at a time
    /// (`lib/file.c:538-542`), so a different length is a different sequence of
    /// callback invocations even though the concatenated bytes are identical.
    fn xfer_buf_len(&self) -> usize;

    // -- the client writer and reader chains --------------------------------

    /// `Curl_client_write(data, flags, buf, blen)` (`lib/file.c:435`, `:439`,
    /// `:461`, `:464`, `:555`, `:576`, `:580`).
    ///
    /// # Errors
    ///
    /// Whatever a writer stage reports, [`CURLcode::WriteError`] from the
    /// application's own callback included.
    fn client_write(
        &mut self,
        flags: ClientWriteFlags,
        buf: &[u8],
    ) -> CodeResult<()>;

    /// `Curl_client_read(data, buf, blen, &nread, &eos)`
    /// (`lib/file.c:331`).
    ///
    /// Returns the byte count and the end-of-stream flag the C writes through
    /// its two out-parameters.
    ///
    /// # Errors
    ///
    /// Whatever a reader stage reports.
    fn client_read(&mut self, into: &mut [u8]) -> CodeResult<(usize, bool)>;

    // -- progress accounting ------------------------------------------------

    /// `Curl_pgrsSetDownloadSize(data, size)` (`lib/file.c:468`, `:514`).
    fn pgrs_set_download_size(&mut self, size: i64);

    /// `Curl_pgrsSetUploadSize(data, size)` (`lib/file.c:310`).
    fn pgrs_set_upload_size(&mut self, size: i64);

    /// `Curl_pgrs_upload_inc(data, n)` (`lib/file.c:362`).
    fn pgrs_upload_inc(&mut self, count: u64);

    /// `Curl_pgrsCheck(data)` (`lib/file.c:364`, `:559`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::OperationTimedout`] for the low-speed limit and
    /// [`CURLcode::AbortedByCallback`] when the progress callback refused.
    fn pgrs_check(&mut self) -> CodeResult<()>;

    /// `Curl_pgrsUpdate(data)` (`lib/file.c:367`, `:594`).
    ///
    /// # Errors
    ///
    /// [`CURLcode::AbortedByCallback`] when the progress callback refused.
    fn pgrs_update(&mut self) -> CodeResult<()>;

    // -- diagnostics --------------------------------------------------------

    /// `failf(data, ...)`: the line that reaches `CURLOPT_ERRORBUFFER` and,
    /// in verbose mode, standard error.
    ///
    /// Every one of the five texts `lib/file.c` emits is user-visible and is
    /// therefore rendered byte for byte -- see [`could_not_open`],
    /// [`cannot_open_for_writing`], [`cannot_get_the_size_of`],
    /// [`CANNOT_GET_SIZE_OF_FILE`] and [`FAILED_TO_RESUME`].
    fn failf(&mut self, message: &str);
}

// URL-to-path conversion -- `lib/file.c:160-205`

/// `DIRSEP`, the directory separator `file_upload` searches for
/// (`lib/file.c:258-262`).
///
/// `'\\'` under `DOS_FILESYSTEM` and `'/'` everywhere else. All four mandated
/// targets take the second branch, so the constant is unconditional here and
/// the DOS spelling has no successor -- along with the drive-letter rewriting
/// and separator translation of `lib/file.c:165-199`, and the AmigaDOS
/// `volumename:` handling of `:207-229`, all three of which specification 0.2.2
/// puts outside the platform matrix.
const DIRSEP: u8 = b'/';

/// Turns `data->state.up.path` into the bytes to hand the filesystem.
///
/// `lib/file.c:160-205`, both steps:
///
/// 1. `Curl_urldecode(data->state.up.path, 0, &real_path, &real_path_len,
///    REJECT_ZERO)` -- percent-decoding under curl's own tables, consumed from
///    [`crate::url::escape`] rather than reimplemented and never delegated to a
///    general-purpose percent-decoder whose defaults differ.
/// 2. `if(memchr(real_path, 0, real_path_len)) return CURLE_URL_MALFORMAT;`
///    with the comment *"binary zeroes indicate foul play"*.
///
/// # Errors
///
/// [`CURLcode::UrlMalformat`] for a NUL anywhere in the decoded path, and
/// [`CURLcode::OutOfMemory`] for a refused buffer -- the two codes
/// [`urldecode`] itself reports.
fn decode_path(up_path: &[u8]) -> CodeResult<Vec<u8>> {
    let decoded = urldecode(up_path, UrlReject::Zero)?;
    reject_interior_nul(&decoded)?;
    Ok(decoded)
}

/// The second half of [`decode_path`]: `lib/file.c:201-205`.
///
/// Separated so that it is reachable on its own, because through
/// [`decode_path`] it is not: [`UrlReject::Zero`] is `REJECT_ZERO`, and
/// `lib/escape.c:140` tests every DECODED byte -- which includes a literal NUL
/// that was never escaped -- so `urldecode` has already refused anything this
/// would catch. The C's `memchr` is belt-and-braces in exactly the same way and
/// against exactly the same guarantee; it is reproduced rather than dropped
/// because the two tests together are what `lib/file.c` does, and a reader
/// comparing the two files should find both.
///
/// # Errors
///
/// [`CURLcode::UrlMalformat`].
fn reject_interior_nul(path: &[u8]) -> CodeResult<()> {
    if path.contains(&0) {
        return Err(CURLcode::UrlMalformat);
    }
    Ok(())
}

/// `Curl_range(data)` (`lib/curl_range.c:35-89`), applied to a
/// [`FileClient`].
///
/// The GRAMMAR belongs to [`crate::util::range`], which owns the whole of
/// `curlx_str_number`/`curlx_str_single` walk and every one of its rejections;
/// this function is the ASSIGNMENT half -- the four `data->` writes the C makes
/// around it -- so that `file://` and FTP accept exactly the same range
/// spellings.
///
/// Two details are the C's and are easy to get wrong:
///
/// * **Both `use_range` and a non-null `range` are required.**
///   `if(data->state.use_range && data->state.range)` (`:37`). A range string
///   left over from a redirect with the intent cleared must not apply.
/// * **The `else` branch writes `maxdownload = -1`** (`:87`). It is not a
///   no-op: `file_do` later tests `if(data->req.maxdownload > 0)`, and a stale
///   positive limit would silently truncate the body.
///   [`RangeSpec::maxdownload`](crate::util::range::RangeSpec::maxdownload)
///   returning [`None`] for the `X-` form is a THIRD case -- the C writes
///   nothing at all there, leaving whatever `lib/request.c:125` initialised --
///   so it must not be collapsed into the `-1` above.
///
/// # Errors
///
/// [`CURLcode::RangeError`], the only code the C returns here besides
/// `CURLE_OK`.
fn apply_range(client: &mut dyn FileClient) -> CodeResult<()> {
    // Copied out before the mutable borrows below. The C reads
    // `data->state.range` and then writes other members of the same struct,
    // which a `&mut` borrow cannot express against one trait object.
    let spec = client.range().map(<[u8]>::to_vec);

    let Some(spec) = spec.filter(|_| client.use_range()) else {
        // `data->req.maxdownload = -1;`
        client.set_maxdownload(MAXDOWNLOAD_UNLIMITED);
        return Ok(());
    };

    let parsed = range::parse(&spec)?;
    // `data->state.resume_from = ...`, written on every branch of the C.
    client.set_resume_from(parsed.resume_from());
    // `data->req.maxdownload = ...`, written on two branches of three.
    if let Some(limit) = parsed.maxdownload() {
        client.set_maxdownload(limit);
    }
    Ok(())
}

// The per-transfer state -- `struct FILEPROTO` (`lib/file.c:78-83`)

/// What one `file://` transfer holds between the five vtable slots.
///
/// `struct FILEPROTO` (`lib/file.c:78-83`) has three members and this has two,
/// because the third has no successor:
///
/// ```c
/// char *path;     /* the path we operate on */
/// char *freepath; /* pointer to the allocated block we must free, this might
///                    differ from the 'path' pointer */
/// int fd;         /* open file descriptor to read from! */
/// ```
///
/// `freepath` exists only because the DOS branch advances `path` past a leading
/// slash (`lib/file.c:185`) and the AmigaDOS branch past a leading slash too
/// (`:223`), leaving `path` pointing INTO the allocation rather than at it. A
/// [`Vec`] owns its buffer whatever a slice of it points at, and neither branch
/// is in the platform matrix, so one owned path is the whole of it.
#[derive(Debug, Default)]
pub(crate) struct FileState {
    /// `file->path`: the decoded path, or [`None`] before `connect_it` ran.
    ///
    /// `file->path` being non-null is the C's own "already connected" test
    /// (`lib/file.c:151`), and it is why `file_cleanup` sets it back to `NULL`
    /// (`:88`) rather than leaving it dangling: after a failed connect the next
    /// one must try again.
    path: Option<Vec<u8>>,

    /// `file->fd`: the open descriptor, or [`None`] for the C's `-1`.
    ///
    /// Dropping it closes it, which is `curlx_close(file->fd)` at
    /// `lib/file.c:90`.
    handle: Option<Box<dyn FileHandle>>,
}

impl FileState {
    /// A fresh state -- `curlx_calloc(1, sizeof(*filep))` at
    /// `lib/file.c:110`.
    ///
    /// The C zeroes the block and then relies on `file->fd` being `0`, which is
    /// a VALID descriptor, until `file_connect` assigns the real one. That is
    /// harmless there only because nothing reads `fd` before the assignment;
    /// [`None`] is the honest zero value and cannot be mistaken for standard
    /// input.
    const fn new() -> Self {
        Self {
            path: None,
            handle: None,
        }
    }

    /// `file_cleanup(file)` (`lib/file.c:85-93`).
    ///
    /// The C frees `freepath`, sets `path` to `NULL`, and closes `fd` if it is
    /// not `-1` before setting it to `-1`. All three are one assignment each
    /// here, and dropping the handle is the close.
    fn cleanup(&mut self) {
        self.path = None;
        self.handle = None;
    }

    /// `file->path != NULL` -- the C's "already connected" test
    /// (`lib/file.c:151`).
    fn is_connected(&self) -> bool {
        self.path.is_some()
    }
}

/// Everything one `file://` transfer needs: the filesystem, the transfer, and
/// the state between them.
///
/// The three are held together rather than passed separately because all three
/// are borrowed at once by every step, and because binding them once at
/// construction is what makes a [`FileProtocol`] a per-transfer value.
#[derive(Debug)]
pub(crate) struct FileSession {
    /// The filesystem, injected. [`StdFileSystem`] in production.
    fs: Box<dyn FileSystem>,

    /// `struct Curl_easy *data`, projected. See [`FileClient`].
    client: Box<dyn FileClient>,

    /// `struct FILEPROTO`, allocated by `setup_connection` and released by
    /// `done` and `disconnect`.
    state: FileState,
}

impl FileSession {
    /// Binds a filesystem and a transfer for one `file://` operation.
    #[allow(dead_code)] // Consumer: `FileProtocol::new`.
    pub(crate) fn new(
        fs: Box<dyn FileSystem>,
        client: Box<dyn FileClient>,
    ) -> Self {
        Self {
            fs,
            client,
            state: FileState::new(),
        }
    }
}

// The handler -- `Curl_protocol_file` (`lib/file.c:601-619`)

/// The `file://` transfer implementation: 5 of `struct Curl_protocol`'s 17
/// slots.
///
/// # One value per transfer, which is what the C does too
///
/// `Curl_protocol_file` is a `static const` vtable shared by every transfer,
/// and the state it works on arrives as its `struct Curl_easy *data` argument,
/// keyed per easy handle in the meta hash under `CURL_META_FILE_EASY`
/// (`lib/file.c:76`, `:112`, `:121`). [`Protocol`] hands a slot the CONNECTION
/// half instead (see this module's documentation), so the transfer half is
/// bound
/// into this value and a [`FileProtocol`] is therefore constructed per transfer
/// -- which is what keeps two concurrent `file://` transfers in one multi
/// handle
/// independent, exactly as two easy handles with two `struct FILEPROTO`s are.
///
/// # Why the session sits behind a [`Mutex`]
///
/// [`Protocol`] takes `&self` and requires [`Send`] + [`Sync`], because the
/// registry holds `&'static dyn Protocol` and a [`ProtoFuture`] borrowing
/// `&'a self` is only [`Send`] when `Self: Sync`. Mutating per-transfer state
/// through a shared reference therefore needs interior mutability, and a
/// [`Mutex`] is the one form that is [`Sync`] for a `!Sync` payload.
///
/// It is never contended in practice and never held across a suspension: none
/// of the five futures below contains an `await`. That is not an oversight but
/// the C's own design, and `lib/file.c:376-383` explains it -- *"since some
/// platforms we support do not allow select()ing etc on file handles (as
/// opposed
/// to sockets) we instead perform the whole do-operation in this function"*.
/// `PROTOPT_NONETWORK` means there is nothing to wait on, so a `file://`
/// transfer completes inside one poll.
#[derive(Debug)]
pub(crate) struct FileProtocol {
    /// The bound session. See the type's documentation for why it is locked.
    session: Mutex<FileSession>,
}

impl FileProtocol {
    /// A handler bound to one filesystem and one transfer.
    // Consumer: the transfer core, once `TransferCtx` carries the `data` seam;
    // see this module's own documentation. Exercised by `mod tests`.
    #[allow(dead_code)]
    pub(crate) fn new(
        fs: Box<dyn FileSystem>,
        client: Box<dyn FileClient>,
    ) -> Self {
        Self {
            session: Mutex::new(FileSession::new(fs, client)),
        }
    }

    /// A handler over the host filesystem -- the production constructor.
    #[allow(dead_code)] // Consumer: the transfer core, as above.
    pub(crate) fn with_std_fs(client: Box<dyn FileClient>) -> Self {
        Self::new(Box::new(StdFileSystem), client)
    }

    /// The bound session, borrowed for one step.
    ///
    /// A poisoned lock means a panic unwound while a previous step held the
    /// session. Nothing in this module panics, and the recovery is
    /// [`std::sync::PoisonError::into_inner`] rather than a re-panic for two
    /// reasons: the state is a path and a descriptor, neither of which a
    /// partial
    /// step can leave logically inconsistent, and this call sits below a C ABI
    /// where an unwind is undefined behaviour.
    fn session(&self) -> std::sync::MutexGuard<'_, FileSession> {
        self.session
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `file_connect(data, done)` (`lib/file.c:136-247`): "connecting" to a
    /// `file://` URL means opening the file.
    ///
    /// The `bool *done` the C writes is unconditionally `TRUE` on every
    /// non-error path, so it carries no information and
    /// [`Protocol::connect_it`] reports `Ok(true)`.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::UrlMalformat`] or [`CURLcode::OutOfMemory`] from
    ///   [`decode_path`].
    /// * [`CURLcode::FileCouldntReadFile`] when the file would not open **and
    ///   this is not an upload** (`lib/file.c:239-243`). The asymmetry is
    ///   deliberate in the C and is preserved: an upload's target need not
    ///   exist yet, so a failed `O_RDONLY` open is not an error for it and
    ///   `file_upload` opens the path again for writing. `tests/data/test201`
    ///   is the download side's oracle -- a missing file is exit code 37.
    fn connect(session: &mut FileSession) -> CodeResult<()> {
        let FileSession { fs, client, state } = session;

        // `if(file->path) { *done = TRUE; return CURLE_OK; }` -- with the C's
        // comment: "already connected. the handler->connect_it() is normally
        // only called once, but FILE does a special check on setting up the
        // connection which calls this explicitly."
        if state.is_connected() {
            return Ok(());
        }

        // The raw path is kept because the `failf` below formats it rather than
        // the decoded one -- see `could_not_open`.
        let raw = client.up_path().to_vec();
        let path = decode_path(&raw)?;

        // `fd = curlx_open(real_path, O_RDONLY);` -- the C stores `-1` on
        // failure and carries on, so the error is discarded here too.
        let opened = fs.open_read(&path).ok();

        // `file->path = real_path;` and `file->freepath = real_path;`, then
        // `file->fd = fd;`. The order matters: the path is recorded even when
        // the open failed, because `file_upload` reads it.
        state.path = Some(path);
        state.handle = opened;

        // `if(!data->state.upload && (fd == -1))`
        if !client.is_upload() && state.handle.is_none() {
            client.failf(&could_not_open(&raw));
            // `file_done(data, CURLE_FILE_COULDNT_READ_FILE, FALSE);` -- which
            // is `file_cleanup`, and which clears `path` so a later connect
            // starts over.
            state.cleanup();
            return Err(CURLcode::FileCouldntReadFile);
        }

        Ok(())
    }

    /// `file_do(data, done)` (`lib/file.c:384-599`): the whole transfer.
    ///
    /// The C's comment states why this slot does everything rather than setting
    /// a transfer up for the main loop: *"since some platforms we support do
    /// not
    /// allow select()ing etc on file handles (as opposed to sockets) we instead
    /// perform the whole do-operation in this function"* (`:379-382`).
    ///
    /// `*done = TRUE` is assigned unconditionally at `:401`, BEFORE the first
    /// error return, so the C reports readiness even when it reports a failure.
    /// `Curl_do`'s caller ignores `*done` for a non-`CURLE_OK` result, so
    /// `Err(code)` from [`Protocol::do_it`] is exact rather than lossy.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::upload`] or [`Self::download`] reports.
    fn perform(session: &mut FileSession) -> CodeResult<()> {
        // `if(data->state.upload) return file_upload(data, file);`
        //
        // `if(!file) return CURLE_FAILED_INIT;` at `:402-403` has no successor:
        // the session owns its `FileState`, so there is no absent-state case to
        // answer. That is the one branch of `file_do` this file does not carry,
        // and it is unreachable rather than unimplemented.
        if session.client.is_upload() {
            return Self::upload(session);
        }
        Self::download(session)
    }

    /// `file_upload(data, file)` (`lib/file.c:264-374`): writing to a local
    /// path.
    ///
    /// `tests/data/test204` is the plain case, `tests/data/test1490` the one
    /// that overwrites an existing file -- which is what makes the
    /// `O_TRUNC`-versus-`O_APPEND` choice below observable.
    ///
    /// # Errors
    ///
    /// * [`CURLcode::FileCouldntReadFile`] when the path holds no directory
    ///   separator, or holds one only as its last byte. The C's own comment on
    ///   both is `/* fix: better error code */` (`:283`, `:286`); the code is
    ///   frozen regardless.
    /// * [`CURLcode::WriteError`] when the target will not open for writing
    ///   (`:305`), and when a negative resume offset needs a size the
    ///   filesystem will not report (`:317`).
    /// * [`CURLcode::SendError`] for a short or failed write (`:359`).
    /// * Whatever the reader chain or the progress check reports.
    fn upload(session: &mut FileSession) -> CodeResult<()> {
        let FileSession { fs, client, state } = session;

        // `const char *dir = strchr(file->path, DIRSEP);`
        //
        // A `None` path would be `strchr(NULL, '/')` in the C, which is
        // undefined behaviour. It is unreachable -- `Curl_do` runs
        // `file_connect` first, and that assigns `file->path` before any path
        // to here exists -- and undefined behaviour has no behaviour to
        // preserve, so the defined answer is the one the C gives for a path
        // with no separator at all.
        let path = state.path.clone().unwrap_or_default();

        // `if(!dir) return CURLE_FILE_COULDNT_READ_FILE;`
        let Some(slash) = path.iter().position(|&byte| byte == DIRSEP) else {
            return Err(CURLcode::FileCouldntReadFile);
        };
        // `if(!dir[1]) return CURLE_FILE_COULDNT_READ_FILE;` -- the byte after
        // the FIRST separator is the terminator, so the path ends there.
        if slash.saturating_add(1) >= path.len() {
            return Err(CURLcode::FileCouldntReadFile);
        }

        // `mode = O_WRONLY | O_CREAT | CURL_O_BINARY;`
        // `if(data->state.resume_from) mode |= O_APPEND; else mode |= O_TRUNC;`
        //
        // Note `!= 0` and not `> 0`: `-C -` leaves a NEGATIVE offset here and
        // still appends.
        let append = client.resume_from() != 0;
        let Ok(mut handle) =
            fs.open_write(&path, append, client.new_file_perms())
        else {
            client.failf(&cannot_open_for_writing(&path));
            return Err(CURLcode::WriteError);
        };

        // `if(data->state.infilesize != -1) Curl_pgrsSetUploadSize(...)`
        let infilesize = client.infilesize();
        if infilesize != -1 {
            client.pgrs_set_upload_size(infilesize);
        }

        // `if(data->state.resume_from < 0)` -- "treat the negative resume
        // offset value as the case of `-`", so the offset becomes the target's
        // current size and the append starts after it.
        if client.resume_from() < 0 {
            match handle.stat() {
                Ok(meta) => client.set_resume_from(meta.size),
                Err(_) => {
                    // `curlx_close(fd);` then the message then the code. The
                    // explicit drop is that close, ordered before the `failf`
                    // exactly as the C orders it.
                    drop(handle);
                    client.failf(&cannot_get_the_size_of(&path));
                    return Err(CURLcode::WriteError);
                }
            }
        }

        Self::upload_loop(client.as_mut(), handle.as_mut())
    }

    /// The body of `file_upload`'s `while(!result && !eos)`
    /// (`lib/file.c:326-367`).
    ///
    /// Separated from [`Self::upload`] so that the borrow of the client and the
    /// borrow of the handle are independent, and so that the loop's own
    /// arithmetic can be tested without opening anything.
    ///
    /// # Errors
    ///
    /// See [`Self::upload`].
    fn upload_loop(
        client: &mut dyn FileClient,
        handle: &mut dyn FileHandle,
    ) -> CodeResult<()> {
        // `Curl_multi_xfer_ulbuf_borrow(data, &xfer_ulbuf, &xfer_ulblen)`. The
        // upload path uses the WHOLE buffer, unlike the download path's
        // `blen - 1`.
        let mut buffer = vec![0_u8; client.xfer_buf_len()];
        let mut eos = false;

        // `while(!result && !eos)`, with `result` expressed as an early return.
        while !eos {
            // `Curl_client_read(data, xfer_ulbuf, xfer_ulblen, &readcount,
            //  &eos); if(result) break;`
            let (readcount, at_eos) = client.client_read(&mut buffer)?;
            eos = at_eos;

            // `if(!readcount) break;`
            if readcount == 0 {
                break;
            }

            // "skip bytes before resume point". The offset is non-negative
            // here: a negative one was replaced by the target's size above.
            let resume = client.resume_from();
            let (start, nread) = if resume > 0 {
                // The offset as a buffer index. A POSITIVE `i64` always fits a
                // 64-bit `usize`, which every mandated target has, so the
                // saturating fallback is unreachable arithmetic rather than a
                // branch -- and saturating to `usize::MAX` keeps it total by
                // taking the "the whole read is inside the skipped region" arm,
                // which is the only answer that could be right for an offset
                // that wide.
                let skip = usize::try_from(resume).unwrap_or(usize::MAX);
                if readcount <= skip {
                    // `if((curl_off_t)nread <= data->state.resume_from)`
                    client.set_resume_from(resume.saturating_sub(
                        i64::try_from(readcount).unwrap_or(i64::MAX),
                    ));
                    (0_usize, 0_usize)
                } else {
                    // The read straddles the resume point, so part of it is
                    // sent and the offset is spent.
                    client.set_resume_from(0);
                    (skip, readcount.saturating_sub(skip))
                }
            } else {
                // `else sendbuf = xfer_ulbuf;`
                (0_usize, readcount)
            };

            // `rv = write(fd, sendbuf, nread);`
            let sendbuf = buffer.get(start..start.saturating_add(nread));
            let offered = sendbuf.unwrap_or(&[]);
            // `if(!curlx_sztouz(rv, &nwritten) || (nwritten != nread))`: a
            // failed write and a SHORT write are the same failure.
            let written = handle.write(offered).unwrap_or(usize::MAX);
            if written != nread {
                return Err(CURLcode::SendError);
            }

            // `Curl_pgrs_upload_inc(data, nwritten);`
            client.pgrs_upload_inc(u64::try_from(written).unwrap_or(u64::MAX));

            // `result = Curl_pgrsCheck(data);` -- the loop's own condition
            // then stops on a failure, which an early return expresses.
            client.pgrs_check()?;
        }

        // `if(!result) result = Curl_pgrsUpdate(data);`
        client.pgrs_update()
    }

    /// The reading half of `file_do` (`lib/file.c:408-598`).
    ///
    /// # Errors
    ///
    /// * [`CURLcode::BadFunctionArgument`] from [`last_modified_line`] for a
    ///   timestamp whose year does not fit its field.
    /// * [`CURLcode::RangeError`] from [`apply_range`].
    /// * [`CURLcode::ReadError`] when a negative resume offset needs a size
    ///   `fstat` did not supply (`:483`), and when a directory will not open
    ///   (`:570`).
    /// * [`CURLcode::BadDownloadResume`] for an offset past the end (`:496`),
    ///   for a seek that did not land where it was asked to (`:520`), and for
    ///   any resume against a directory (`:523`).
    /// * Whatever the writer chain or the progress calls report.
    fn download(session: &mut FileSession) -> CodeResult<()> {
        let FileSession { fs, client, state } = session;

        // `if(curlx_fstat(fd, &statbuf) != -1) { ... fstated = TRUE; }`
        //
        // `stat` standing in for the C's `fstated` flag AND its `statbuf` is
        // what makes the uninitialised-`statbuf` read at `:517` impossible to
        // reproduce by accident -- see the seek below.
        let mut expected_size: i64 = -1;
        let mut stat: Option<FileMeta> = None;
        if let Some(handle) = state.handle.as_mut() {
            if let Ok(meta) = handle.stat() {
                // `if(!S_ISDIR(statbuf.st_mode)) expected_size =
                //  statbuf.st_size;`
                if !meta.is_dir {
                    expected_size = meta.size;
                }
                // "and store the modification time" -- outside the S_ISDIR
                // guard, so a directory gets one too.
                client.set_filetime(meta.mtime);
                stat = Some(meta);
            }
        }

        // `if(fstated && !data->state.range && data->set.timecondition &&
        //     !Curl_meets_timecondition(data, data->info.filetime))
        //    return CURLE_OK;`
        //
        // Note `!data->state.range`: a range request bypasses the time
        // condition entirely, and note that this returns BEFORE any header is
        // written, so a refused condition emits nothing at all.
        if let Some(meta) = stat {
            if client.range().is_none()
                && client.has_timecondition()
                && !client.meets_timecondition(meta.mtime)
            {
                return Ok(());
            }
        }

        // `if(fstated) { ...the synthesised header block... }`
        if let Some(meta) = stat {
            if expected_size >= 0 {
                let line = content_length_line(expected_size);
                client
                    .client_write(ClientWriteFlags::HEADER, line.as_bytes())?;
                client.client_write(
                    ClientWriteFlags::HEADER,
                    ACCEPT_RANGES.as_bytes(),
                )?;
            }

            let line = last_modified_line(meta.mtime)?;
            client.client_write(ClientWriteFlags::HEADER, line.as_bytes())?;
            // "end of headers"
            client.client_write(
                ClientWriteFlags::HEADER,
                END_OF_HEADERS.as_bytes(),
            )?;

            // "set the file size to make it available post transfer"
            client.pgrs_set_download_size(expected_size);

            // `if(data->req.no_body) return CURLE_OK;`
            if client.no_body() {
                return Ok(());
            }
        }

        // `result = Curl_range(data); if(result) return result;`
        apply_range(client.as_mut())?;

        // "Adjust the start offset in case we want to get the N last bytes of
        // the stream if the filesize could be determined".
        if client.resume_from() < 0 {
            let Some(meta) = stat else {
                client.failf(CANNOT_GET_SIZE_OF_FILE);
                return Err(CURLcode::ReadError);
            };
            // `data->state.resume_from += (curl_off_t)statbuf.st_size;` -- the
            // RAW size, which for a directory is whatever the filesystem
            // reports rather than the `-1` `expected_size` carries.
            client.set_resume_from(
                client.resume_from().saturating_add(meta.size),
            );
        }

        if client.resume_from() > 0 {
            // "We check explicitly if we have a start offset, because
            // expected_size may be -1 if we do not know how large the file is,
            // in which case we should not adjust it."
            if client.resume_from() <= expected_size {
                expected_size =
                    expected_size.saturating_sub(client.resume_from());
            } else {
                client.failf(FAILED_TO_RESUME);
                return Err(CURLcode::BadDownloadResume);
            }
        }

        // "A high water mark has been specified so we obey..."
        if client.maxdownload() > 0 {
            expected_size = client.maxdownload();
        }

        // `if(!fstated || (expected_size <= 0)) size_known = FALSE;`
        let size_known = stat.is_some() && expected_size > 0;
        if size_known {
            client.pgrs_set_download_size(expected_size);
        }

        // `if(data->state.resume_from) { ... }`
        //
        // Reached only with a POSITIVE offset and a successful `fstat`: a
        // negative one returned above, and a positive one without a stat has
        // `expected_size == -1` and therefore already failed the
        // `resume_from <= expected_size` test. The C reads
        // `statbuf.st_mode` here regardless, which is uninitialised on the
        // unreachable path; `stat` being an `Option` makes the same code total.
        if client.resume_from() != 0 {
            let offset = client.resume_from();
            // `else return CURLE_BAD_DOWNLOAD_RESUME;` -- a directory cannot
            // be resumed.
            if stat.is_some_and(|meta| meta.is_dir) {
                return Err(CURLcode::BadDownloadResume);
            }
            // `if(data->state.resume_from != curl_lseek(fd, ..., SEEK_SET))`
            let landed = state
                .handle
                .as_mut()
                .and_then(|handle| handle.seek_from_start(offset).ok());
            if landed != Some(offset) {
                return Err(CURLcode::BadDownloadResume);
            }
        }

        // `if(!S_ISDIR(statbuf.st_mode)) { ...read loop... } else { ...listing
        //  ... }`
        if stat.is_some_and(|meta| meta.is_dir) {
            Self::list_directory(fs.as_ref(), client.as_mut(), &state.path)?;
        } else {
            Self::read_loop(
                client.as_mut(),
                state.handle.as_mut(),
                expected_size,
                size_known,
            )?;
        }

        // `if(!result) result = Curl_pgrsUpdate(data);`
        client.pgrs_update()
    }

    /// The read loop of `file_do` (`lib/file.c:531-563`).
    ///
    /// Two behaviours here are surprising, are the C's, and are preserved:
    ///
    /// * **At most `blen - 1` bytes are read at a time** (`:538-542`). The
    ///   reserved byte is where the C writes a NUL terminator at `:547`, which
    ///   nothing then reads -- `Curl_client_write` is given `nread`. The
    ///   terminator has no successor because a slice carries its length, but
    ///   the
    ///   `- 1` does, because it decides the chunk boundaries an application's
    ///   write callback sees.
    /// * **A read ERROR ends the transfer successfully.** The C tests
    ///   `nread <= 0` (`:549`) and leaves `result` at `CURLE_OK`, so a failure
    ///   part-way through a file yields `CURLE_OK` with a short body rather
    ///   than [`CURLcode::ReadError`]. Reproduced exactly; specification 0.8.1
    ///   freezes observable behaviour whether or not it looks like an
    ///   oversight.
    ///
    /// # Errors
    ///
    /// Whatever the writer chain or the progress check reports.
    fn read_loop(
        client: &mut dyn FileClient,
        handle: Option<&mut Box<dyn FileHandle>>,
        mut expected_size: i64,
        size_known: bool,
    ) -> CodeResult<()> {
        // `Curl_multi_xfer_buf_borrow(data, &xfer_buf, &xfer_blen)`.
        let capacity = client.xfer_buf_len();
        let mut buffer = vec![0_u8; capacity];
        // `xfer_blen - 1`, saturating so that a zero-length buffer asks for
        // nothing rather than wrapping to the whole address space.
        let room = capacity.saturating_sub(1);

        // An absent handle is the C's `fd == -1`, on which `read` returns `-1`
        // and the loop breaks at once. Unreachable through `Curl_do`, which
        // runs `connect_it` first, and total here rather than a panic.
        let Some(handle) = handle else {
            return Ok(());
        };

        loop {
            // "Do not fill a whole buffer if we want less than all data"
            let wanted = if size_known {
                usize::try_from(expected_size).unwrap_or(room).min(room)
            } else {
                room
            };

            let slot = buffer.get_mut(..wanted).unwrap_or(&mut []);
            // A read failure is `nread == -1`, which the test below treats
            // exactly as end of file. See this function's own documentation.
            let nread = handle.read(slot).unwrap_or(0);

            // `if(nread <= 0 || (size_known && (expected_size == 0))) break;`
            //
            // The second term is the C's belt-and-braces: when `expected_size`
            // has reached zero, `wanted` is zero too, so the read returned zero
            // and the first term already stopped the loop.
            if nread == 0 || (size_known && expected_size == 0) {
                break;
            }

            if size_known {
                expected_size = expected_size
                    .saturating_sub(i64::try_from(nread).unwrap_or(i64::MAX));
            }

            let body = buffer.get(..nread).unwrap_or(&[]);
            client.client_write(ClientWriteFlags::BODY, body)?;
            client.pgrs_check()?;
        }

        Ok(())
    }

    /// The directory-listing branch of `file_do` (`lib/file.c:564-591`).
    ///
    /// One name per line, each followed by a bare `"\n"` -- **not** CRLF -- and
    /// every name beginning with `.` skipped, which discards `.` and `..` along
    /// with every dotfile. The order is the platform's; see
    /// [`FileSystem::read_dir`] for why it is never sorted.
    ///
    /// The C's `#else` branch at `:587-590`, which reports
    /// *"Directory listing not yet implemented on this platform."*, has no
    /// successor: it is compiled only where `HAVE_OPENDIR` is undefined, and
    /// all four mandated targets define it.
    ///
    /// # Errors
    ///
    /// [`CURLcode::ReadError`] when the directory will not open (`:569-571`),
    /// and whatever the writer chain reports.
    fn list_directory(
        fs: &dyn FileSystem,
        client: &mut dyn FileClient,
        path: &Option<Vec<u8>>,
    ) -> CodeResult<()> {
        // `DIR *dir = opendir(file->path); if(!dir) { result =
        //  CURLE_READ_ERROR; goto out; }`
        //
        // An absent path takes the same branch: the C would hand `opendir` a
        // null pointer, and a directory that cannot be named cannot be opened.
        let names = path
            .as_deref()
            .and_then(|path| fs.read_dir(path).ok())
            .ok_or(CURLcode::ReadError)?;

        for name in names {
            // `if(entry->d_name[0] != '.')`
            if name.first() == Some(&b'.') {
                continue;
            }
            client.client_write(ClientWriteFlags::BODY, &name)?;
            client.client_write(ClientWriteFlags::BODY, b"\n")?;
        }

        Ok(())
    }
}

/// `Curl_protocol_file` (`lib/file.c:601-619`): 5 slots filled, 12 left to the
/// trait's defaults.
///
/// The filled five are `setup_connection`, `do_it`, `done`, `connect_it` and
/// `disconnect`, in the C's own order. The other twelve -- `do_more`,
/// `connecting`, `doing`, the four pollsets, `write_resp`, `write_resp_hd`,
/// `connection_check`, `attach` and `follow` -- are `ZERO_NULL` in the C and
/// are deliberately NOT overridden here, not even as no-ops: relying on the
/// defaults is what makes them equivalent, and writing twelve empty bodies
/// would
/// hide a default that stopped matching.
///
/// Every slot ignores its [`TransferCtx`]. That is the C's behaviour, not an
/// omission -- see this module's documentation.
impl Protocol for FileProtocol {
    // -- 1. setup_connection (`lib/file.c:602`) ---------------------------

    /// `file_setup_connection(data, conn)` (`lib/file.c:104-116`).
    ///
    /// The C allocates a zeroed `struct FILEPROTO` and installs it in the easy
    /// handle's meta hash, reporting [`CURLcode::OutOfMemory`] if either step
    /// fails. Here the state is a field of the session this handler already
    /// owns, so the allocation is a reset -- which is the same observable
    /// effect, because a fresh `calloc` leaves exactly the "no path, no
    /// descriptor" state [`FileState::new`] produces. There is no failure to
    /// report: a refused allocation aborts in Rust rather than returning a
    /// code.
    ///
    /// The reset is not vacuous. `Curl_do` may run `setup_connection` again for
    /// a second transfer on the same handle, and a stale path would make
    /// [`Self::connect`]'s "already connected" test skip the open.
    ///
    /// `(void)conn` at `:108` is the whole of the C's use of its second
    /// argument.
    fn setup_connection(&self, ctx: &mut TransferCtx<'_>) -> CodeResult<()> {
        let _ = ctx;
        self.session().state = FileState::new();
        Ok(())
    }

    // -- 2. do_it (`lib/file.c:603`) --------------------------------------

    /// `file_do(data, done)` (`lib/file.c:384-599`) -- see [`Self::perform`].
    ///
    /// Answers `true` because `*done = TRUE` is unconditional at `:401`: a
    /// `file://` transfer never leaves the DO phase unfinished, so `doing` is
    /// never reached and stays defaulted.
    fn do_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(async move {
            Self::perform(&mut self.session())?;
            Ok(true)
        })
    }

    // -- 3. done (`lib/file.c:604`) ---------------------------------------

    /// `file_done(data, status, premature)` (`lib/file.c:118-129`).
    ///
    /// `(void)status; (void)premature;` -- the C ignores both, and so does
    /// this: there is nothing to send on the way out, so nothing depends on how
    /// the transfer ended. `file_cleanup` closes the descriptor and forgets the
    /// path, and the C's `CURLE_OK` is unconditional.
    fn done<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        status: CURLcode,
        premature: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, status, premature);
        Box::pin(async move {
            self.session().state.cleanup();
            Ok(())
        })
    }

    // -- 5. connect_it (`lib/file.c:606`) ---------------------------------

    /// `file_connect(data, done)` (`lib/file.c:136-247`) -- see
    /// [`Self::connect`].
    ///
    /// Answers `true` on every success, because the C assigns `*done = TRUE`
    /// at `:156` and `:244` and nowhere assigns `FALSE`. That is why
    /// `connecting` stays defaulted: there is never anything left to continue.
    fn connect_it<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
    ) -> ProtoFuture<'a, bool> {
        let _ = ctx;
        Box::pin(async move {
            Self::connect(&mut self.session())?;
            Ok(true)
        })
    }

    // -- 12. disconnect (`lib/file.c:613`) --------------------------------

    /// `file_disconnect(data, conn, dead_connection)`
    /// (`lib/file.c:249-256`).
    ///
    /// The whole C body is `(void)dead_connection; (void)conn; return
    /// file_done(data, CURLE_OK, FALSE);`. The parameter is kept even though
    /// its
    /// value is ignored, so that the trait stays uniform and so that a scheme
    /// which MUST honour it -- FTP, whose `QUIT` would block forever on a dead
    /// socket -- reads the same shape. `PROTOPT_NONETWORK` is why it cannot
    /// matter here: there is no socket to be dead.
    fn disconnect<'a>(
        &'a self,
        ctx: &'a mut TransferCtx<'_>,
        dead_connection: bool,
    ) -> ProtoFuture<'a, ()> {
        let _ = (ctx, dead_connection);
        Box::pin(async move {
            self.session().state.cleanup();
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, PoisonError};

    use crate::conn::filters::FilterChains;
    use crate::conn::SocketIndex;
    use crate::protocols::{get_scheme, Proto, Scheme};
    use crate::util::timeval::{CurlTime, TestClock};

    // -- the in-memory filesystem -----------------------------------------

    /// One entry of [`MemFs`], plus the failure switches a test needs.
    ///
    /// Every switch corresponds to one C failure the module has to answer, so
    /// the harness can reach each branch without a filesystem in that state:
    /// `curlx_open` failing, `curlx_fstat` failing, `read` failing part-way,
    /// `write` accepting fewer bytes than offered, and `curl_lseek` landing
    /// somewhere other than where it was asked to.
    #[derive(Clone, Debug, Default)]
    struct Entry {
        data: Vec<u8>,
        mtime: i64,
        is_dir: bool,
        /// What `read_dir` yields, in this order. Never sorted.
        names: Vec<Vec<u8>>,
        deny_read: bool,
        deny_write: bool,
        deny_stat: bool,
        deny_list: bool,
        /// `write` accepts one byte fewer than offered.
        short_write: bool,
        /// `read` fails once the position has reached this offset.
        read_fails_at: Option<usize>,
        /// `curl_lseek` reports one byte past where it was asked to go.
        seek_lands_wrong: bool,
    }

    /// The filesystem's contents, shared with the test that inspects them.
    #[derive(Debug, Default)]
    struct FsShared {
        /// Path to entry, in insertion order -- a `Vec` rather than a map
        /// because [`FileSystem::read_dir`]'s order is observable and this
        /// harness must never introduce an ordering of its own.
        files: Vec<(Vec<u8>, Entry)>,
        /// Every `open_write`, with the `append` flag and mode it was given.
        write_opens: Vec<(Vec<u8>, bool, u32)>,
    }

    impl FsShared {
        fn find(&self, path: &[u8]) -> Option<&Entry> {
            self.files
                .iter()
                .find(|(key, _)| key == path)
                .map(|(_, entry)| entry)
        }

        fn find_mut(&mut self, path: &[u8]) -> Option<&mut Entry> {
            self.files
                .iter_mut()
                .find(|(key, _)| key == path)
                .map(|(_, entry)| entry)
        }

        fn insert(&mut self, path: &[u8], entry: Entry) {
            match self.find_mut(path) {
                Some(slot) => *slot = entry,
                None => self.files.push((path.to_vec(), entry)),
            }
        }
    }

    /// An in-memory [`FileSystem`]: no real file, no `tempfile`, Miri-clean.
    #[derive(Debug)]
    struct MemFs {
        shared: Arc<Mutex<FsShared>>,
    }

    fn locked<T>(shared: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        shared.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn denied() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied")
    }

    impl FileSystem for MemFs {
        fn open_read(
            &self,
            path: &[u8],
        ) -> std::io::Result<Box<dyn FileHandle>> {
            let shared = locked(&self.shared);
            match shared.find(path) {
                Some(entry) if !entry.deny_read => {
                    drop(shared);
                    Ok(Box::new(MemHandle {
                        shared: Arc::clone(&self.shared),
                        key: path.to_vec(),
                        pos: 0,
                    }))
                }
                _ => Err(denied()),
            }
        }

        fn open_write(
            &self,
            path: &[u8],
            append: bool,
            perms: u32,
        ) -> std::io::Result<Box<dyn FileHandle>> {
            let mut shared = locked(&self.shared);
            shared.write_opens.push((path.to_vec(), append, perms));
            let existing = shared.find(path).cloned();
            if existing.as_ref().is_some_and(|entry| entry.deny_write) {
                return Err(denied());
            }
            // `O_CREAT`, then exactly one of `O_APPEND` and `O_TRUNC`.
            let mut entry = existing.unwrap_or_default();
            if !append {
                entry.data.clear();
            }
            let pos = entry.data.len();
            shared.insert(path, entry);
            drop(shared);
            Ok(Box::new(MemHandle {
                shared: Arc::clone(&self.shared),
                key: path.to_vec(),
                pos,
            }))
        }

        fn read_dir(&self, path: &[u8]) -> std::io::Result<Vec<Vec<u8>>> {
            let shared = locked(&self.shared);
            match shared.find(path) {
                Some(entry) if entry.is_dir && !entry.deny_list => {
                    Ok(entry.names.clone())
                }
                _ => Err(denied()),
            }
        }
    }

    /// One open [`MemFs`] entry.
    #[derive(Debug)]
    struct MemHandle {
        shared: Arc<Mutex<FsShared>>,
        key: Vec<u8>,
        pos: usize,
    }

    impl FileHandle for MemHandle {
        fn stat(&mut self) -> std::io::Result<FileMeta> {
            let shared = locked(&self.shared);
            let entry = shared.find(&self.key).ok_or_else(denied)?;
            if entry.deny_stat {
                return Err(denied());
            }
            Ok(FileMeta {
                size: i64::try_from(entry.data.len()).unwrap_or(i64::MAX),
                mtime: entry.mtime,
                is_dir: entry.is_dir,
            })
        }

        fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
            let shared = locked(&self.shared);
            let entry = shared.find(&self.key).ok_or_else(denied)?;
            if entry.read_fails_at.is_some_and(|at| self.pos >= at) {
                return Err(denied());
            }
            let rest = entry.data.get(self.pos..).unwrap_or(&[]);
            let count = rest.len().min(into.len());
            let source = rest.get(..count).unwrap_or(&[]);
            let target = into.get_mut(..count).unwrap_or(&mut []);
            target.copy_from_slice(source);
            self.pos = self.pos.saturating_add(count);
            Ok(count)
        }

        fn write(&mut self, from: &[u8]) -> std::io::Result<usize> {
            let mut shared = locked(&self.shared);
            let short = shared
                .find(&self.key)
                .is_some_and(|entry| entry.short_write);
            let accepted = if short {
                from.len().saturating_sub(1)
            } else {
                from.len()
            };
            let entry = shared.find_mut(&self.key).ok_or_else(denied)?;
            // `truncate` is a no-op when the position is already at or past the
            // end, which is the only case that arises: `open_write` positions
            // at
            // zero or at the end, and nothing seeks a write handle.
            entry.data.truncate(self.pos);
            entry
                .data
                .extend_from_slice(from.get(..accepted).unwrap_or(&[]));
            self.pos = self.pos.saturating_add(accepted);
            Ok(accepted)
        }

        fn seek_from_start(&mut self, offset: i64) -> std::io::Result<i64> {
            let shared = locked(&self.shared);
            let entry = shared.find(&self.key).ok_or_else(denied)?;
            let wrong = entry.seek_lands_wrong;
            drop(shared);
            let landed = usize::try_from(offset).map_err(|_| denied())?;
            self.pos = landed;
            if wrong {
                return Ok(offset.saturating_add(1));
            }
            Ok(offset)
        }
    }

    // -- the in-memory transfer -------------------------------------------

    /// What a [`MemClient`] records, shared with the test that inspects it.
    #[derive(Debug, Default)]
    struct ClientShared {
        /// Every `Curl_client_write`, in order, with its flags.
        writes: Vec<(ClientWriteFlags, Vec<u8>)>,
        /// Every `failf` line, in order.
        failures: Vec<String>,
        filetime: Option<i64>,
        download_sizes: Vec<i64>,
        upload_sizes: Vec<i64>,
        uploaded: u64,
        checks: usize,
        updates: usize,
    }

    impl ClientShared {
        /// The concatenation of every write carrying `flags`, which is what
        /// `compareparts` compares: one string, in order, unnormalised.
        fn joined(&self, flags: ClientWriteFlags) -> Vec<u8> {
            let mut out = Vec::new();
            for (seen, bytes) in &self.writes {
                if *seen == flags {
                    out.extend_from_slice(bytes);
                }
            }
            out
        }

        /// The size of each BODY write, in order -- the chunk boundaries an
        /// application's write callback would see.
        fn body_chunks(&self) -> Vec<usize> {
            self.writes
                .iter()
                .filter(|(flags, _)| *flags == ClientWriteFlags::BODY)
                .map(|(_, bytes)| bytes.len())
                .collect()
        }
    }

    /// `struct Curl_easy`, in memory.
    #[derive(Debug)]
    struct MemClient {
        shared: Arc<Mutex<ClientShared>>,
        up_path: Vec<u8>,
        upload: bool,
        range: Option<Vec<u8>>,
        use_range: bool,
        resume_from: i64,
        maxdownload: i64,
        no_body: bool,
        infilesize: i64,
        perms: u32,
        timecondition: bool,
        meets_timecondition: bool,
        buf_len: usize,
        /// What the reader chain hands out, and how far it has been consumed.
        source: Vec<u8>,
        source_pos: usize,
        /// Fail the Nth `client_write` (zero-based).
        write_fails_at: Option<usize>,
        read_error: Option<CURLcode>,
        check_error: Option<CURLcode>,
        update_error: Option<CURLcode>,
    }

    impl MemClient {
        fn new(up_path: &[u8], shared: &Arc<Mutex<ClientShared>>) -> Self {
            Self {
                shared: Arc::clone(shared),
                up_path: up_path.to_vec(),
                upload: false,
                range: None,
                use_range: false,
                resume_from: 0,
                maxdownload: MAXDOWNLOAD_UNLIMITED,
                no_body: false,
                infilesize: -1,
                // `CURLOPT_NEW_FILE_PERMS`'s default.
                perms: 0o644,
                timecondition: false,
                meets_timecondition: true,
                // `CURL_MAX_WRITE_SIZE`, the C's default buffer size.
                buf_len: 16_384,
                source: Vec::new(),
                source_pos: 0,
                write_fails_at: None,
                read_error: None,
                check_error: None,
                update_error: None,
            }
        }
    }

    impl FileClient for MemClient {
        fn up_path(&self) -> &[u8] {
            &self.up_path
        }

        fn is_upload(&self) -> bool {
            self.upload
        }

        fn range(&self) -> Option<&[u8]> {
            self.range.as_deref()
        }

        fn use_range(&self) -> bool {
            self.use_range
        }

        fn resume_from(&self) -> i64 {
            self.resume_from
        }

        fn set_resume_from(&mut self, offset: i64) {
            self.resume_from = offset;
        }

        fn maxdownload(&self) -> i64 {
            self.maxdownload
        }

        fn set_maxdownload(&mut self, limit: i64) {
            self.maxdownload = limit;
        }

        fn no_body(&self) -> bool {
            self.no_body
        }

        fn infilesize(&self) -> i64 {
            self.infilesize
        }

        fn new_file_perms(&self) -> u32 {
            self.perms
        }

        fn has_timecondition(&self) -> bool {
            self.timecondition
        }

        fn meets_timecondition(&mut self, _filetime: i64) -> bool {
            self.meets_timecondition
        }

        fn set_filetime(&mut self, filetime: i64) {
            locked(&self.shared).filetime = Some(filetime);
        }

        fn xfer_buf_len(&self) -> usize {
            self.buf_len
        }

        fn client_write(
            &mut self,
            flags: ClientWriteFlags,
            buf: &[u8],
        ) -> CodeResult<()> {
            let mut shared = locked(&self.shared);
            if self.write_fails_at == Some(shared.writes.len()) {
                return Err(CURLcode::WriteError);
            }
            shared.writes.push((flags, buf.to_vec()));
            Ok(())
        }

        fn client_read(
            &mut self,
            into: &mut [u8],
        ) -> CodeResult<(usize, bool)> {
            if let Some(code) = self.read_error {
                return Err(code);
            }
            let rest = self.source.get(self.source_pos..).unwrap_or(&[]);
            let count = rest.len().min(into.len());
            let source = rest.get(..count).unwrap_or(&[]);
            let target = into.get_mut(..count).unwrap_or(&mut []);
            target.copy_from_slice(source);
            self.source_pos = self.source_pos.saturating_add(count);
            Ok((count, self.source_pos >= self.source.len()))
        }

        fn pgrs_set_download_size(&mut self, size: i64) {
            locked(&self.shared).download_sizes.push(size);
        }

        fn pgrs_set_upload_size(&mut self, size: i64) {
            locked(&self.shared).upload_sizes.push(size);
        }

        fn pgrs_upload_inc(&mut self, count: u64) {
            let mut shared = locked(&self.shared);
            shared.uploaded = shared.uploaded.saturating_add(count);
        }

        fn pgrs_check(&mut self) -> CodeResult<()> {
            locked(&self.shared).checks += 1;
            match self.check_error {
                Some(code) => Err(code),
                None => Ok(()),
            }
        }

        fn pgrs_update(&mut self) -> CodeResult<()> {
            locked(&self.shared).updates += 1;
            match self.update_error {
                Some(code) => Err(code),
                None => Ok(()),
            }
        }

        fn failf(&mut self, message: &str) {
            locked(&self.shared).failures.push(message.to_owned());
        }
    }

    // -- the harness ------------------------------------------------------

    /// The URL path every test uses unless it needs another.
    ///
    /// It carries a directory separator that is neither first nor last, which
    /// is what `file_upload`'s two guards require (`lib/file.c:282-286`).
    const UP_PATH: &[u8] = b"/dir/file.txt";

    /// `tests/data/test1445`'s timestamp: 2000-01-01T12:00:00Z, a Saturday.
    ///
    /// The same value the fixture's `postcheck` passes to
    /// `tests/libtest/test613.pl`, so the `Last-Modified:` line asserted below
    /// is the one that fixture's file would produce.
    const MTIME_2000: i64 = 946_728_000;

    /// The body every read test uses -- `tests/data/test200`'s file, verbatim.
    const TEST200_BODY: &[u8] = b"foo\n   bar\nbar\n   foo\nmoo\n";

    /// The `file` row of the production registry.
    fn file_row() -> &'static Scheme {
        get_scheme(SCHEME_NAME).expect("the file row is registered")
    }

    /// One readable regular file.
    fn regular(data: &[u8], mtime: i64) -> Entry {
        Entry {
            data: data.to_vec(),
            mtime,
            ..Entry::default()
        }
    }

    /// One directory whose listing is `names`, in that order.
    fn directory(names: &[&[u8]], mtime: i64) -> Entry {
        Entry {
            mtime,
            is_dir: true,
            names: names.iter().map(|name| name.to_vec()).collect(),
            ..Entry::default()
        }
    }

    /// A filesystem, a transfer and a handler bound together.
    struct Env {
        fs: Arc<Mutex<FsShared>>,
        recorded: Arc<Mutex<ClientShared>>,
        handler: FileProtocol,
        /// The connection's filter chains. **They stay empty for the whole of
        /// every test**, which is `PROTOPT_NONETWORK` asserted rather than
        /// described -- see [`no_filter_is_ever_installed`].
        chains: FilterChains,
        /// The injected clock. Never consulted by this module; advancing it
        /// changes nothing, which
        /// [`the_emitted_date_ignores_the_injected_clock`]
        /// asserts.
        clock: TestClock,
    }

    impl Env {
        /// Builds an environment over `files`, with `configure` applied to the
        /// transfer before it is bound.
        fn build(
            files: &[(&[u8], Entry)],
            configure: impl FnOnce(&mut MemClient),
        ) -> Self {
            let fs = Arc::new(Mutex::new(FsShared {
                files: files
                    .iter()
                    .map(|(path, entry)| (path.to_vec(), entry.clone()))
                    .collect(),
                write_opens: Vec::new(),
            }));
            let recorded = Arc::new(Mutex::new(ClientShared::default()));
            let mut client = MemClient::new(UP_PATH, &recorded);
            configure(&mut client);
            let handler = FileProtocol::new(
                Box::new(MemFs {
                    shared: Arc::clone(&fs),
                }),
                Box::new(client),
            );
            Self {
                fs,
                recorded,
                handler,
                chains: FilterChains::new(None),
                clock: TestClock::new(CurlTime::ZERO),
            }
        }

        /// One readable file at [`UP_PATH`] holding `data`.
        fn with_file(data: &[u8]) -> Self {
            Self::build(&[(UP_PATH, regular(data, MTIME_2000))], |_| {})
        }

        fn setup_connection(&mut self) -> CodeResult<()> {
            let Self {
                handler,
                chains,
                clock,
                ..
            } = self;
            let mut ctx = TransferCtx::new(chains, clock, file_row());
            let protocol: &dyn Protocol = handler;
            protocol.setup_connection(&mut ctx)
        }

        fn connect_it(&mut self) -> CodeResult<bool> {
            let Self {
                handler,
                chains,
                clock,
                ..
            } = self;
            let mut ctx = TransferCtx::new(chains, clock, file_row());
            let protocol: &dyn Protocol = handler;
            futures::executor::block_on(protocol.connect_it(&mut ctx))
        }

        fn do_it(&mut self) -> CodeResult<bool> {
            let Self {
                handler,
                chains,
                clock,
                ..
            } = self;
            let mut ctx = TransferCtx::new(chains, clock, file_row());
            let protocol: &dyn Protocol = handler;
            futures::executor::block_on(protocol.do_it(&mut ctx))
        }

        fn done(
            &mut self,
            status: CURLcode,
            premature: bool,
        ) -> CodeResult<()> {
            let Self {
                handler,
                chains,
                clock,
                ..
            } = self;
            let mut ctx = TransferCtx::new(chains, clock, file_row());
            let protocol: &dyn Protocol = handler;
            futures::executor::block_on(
                protocol.done(&mut ctx, status, premature),
            )
        }

        fn disconnect(&mut self, dead_connection: bool) -> CodeResult<()> {
            let Self {
                handler,
                chains,
                clock,
                ..
            } = self;
            let mut ctx = TransferCtx::new(chains, clock, file_row());
            let protocol: &dyn Protocol = handler;
            futures::executor::block_on(
                protocol.disconnect(&mut ctx, dead_connection),
            )
        }

        /// The four phases `Curl_do` runs, in order.
        fn transfer(&mut self) -> CodeResult<()> {
            self.setup_connection()?;
            assert!(self.connect_it()?, "connect_it always reports done");
            assert!(self.do_it()?, "do_it always reports done");
            self.done(CURLcode::Ok, false)
        }

        /// Every HEADER write, concatenated -- which is how `compareparts`
        /// compares them.
        fn headers(&self) -> Vec<u8> {
            locked(&self.recorded).joined(ClientWriteFlags::HEADER)
        }

        /// Every BODY write, concatenated.
        fn body(&self) -> Vec<u8> {
            locked(&self.recorded).joined(ClientWriteFlags::BODY)
        }

        fn failures(&self) -> Vec<String> {
            locked(&self.recorded).failures.clone()
        }

        /// The contents of one filesystem entry, for the upload assertions.
        fn contents(&self, path: &[u8]) -> Vec<u8> {
            locked(&self.fs)
                .find(path)
                .map(|entry| entry.data.clone())
                .unwrap_or_default()
        }
    }

    // -- 1. the registration facts, against `lib/file.c:626-637` ------------

    #[test]
    fn the_registration_facts_are_the_c_registrations() {
        // Written from `lib/file.c:627-636` column by column, and compared
        // against the row `super` assembled from its own transcription -- so a
        // mistake in either is caught rather than confirmed.
        assert_eq!(SCHEME_NAME, b"file");
        assert_eq!(SCHEME_PROTOCOL_BITS, Proto::FILE);
        assert_eq!(SCHEME_DEFPORT, 0);
        assert_eq!(
            SCHEME_FLAGS,
            ProtocolOptions::NONETWORK.union(ProtocolOptions::NOURLQUERY)
        );

        let row = file_row();
        assert_eq!(row.name, SCHEME_NAME);
        assert_eq!(row.protocol, SCHEME_PROTOCOL_BITS);
        // `protocol` and `family` are the SAME bit for this row, unlike
        // `ftps`, `https`, `WS` and `WSS`.
        assert_eq!(row.family, SCHEME_PROTOCOL_BITS);
        assert_eq!(row.flags, SCHEME_FLAGS);
        assert_eq!(row.flags, super::super::FLAGS_FILE);
        assert_eq!(row.defport, SCHEME_DEFPORT);
    }

    #[test]
    fn the_name_is_lower_case_and_resolves_case_insensitively() {
        // `lib/file.c:627` spells it in lower case while four rows of the same
        // table are UPPER CASE. `tests/data/test202` requests the same file as
        // `file://` and as `FILE://`, which is the fixture a case-sensitive
        // lookup would fail.
        assert_eq!(SCHEME_NAME, b"file");
        assert!(SCHEME_NAME.iter().all(u8::is_ascii_lowercase));
        for spelling in [&b"file"[..], b"FILE", b"FiLe"] {
            let row = get_scheme(spelling).expect("resolves in any case");
            assert_eq!(row.name, SCHEME_NAME);
        }
    }

    #[test]
    fn the_only_zero_default_port_in_the_registry_is_this_one() {
        // `PROTOPT_NONETWORK` and `defport == 0` are two halves of one fact.
        assert!(SCHEME_FLAGS.intersects(ProtocolOptions::NONETWORK));
        assert_eq!(SCHEME_DEFPORT, 0);

        let zero_ports: Vec<String> = super::super::SCHEMES
            .iter()
            .filter(|row| row.defport == 0)
            .map(|row| String::from_utf8_lossy(row.name).into_owned())
            .collect();
        assert_eq!(zero_ports, vec!["file".to_owned()]);
    }

    #[test]
    fn the_row_carries_no_implementation_and_that_is_deliberate() {
        // A MEASUREMENT of this checkout, with its reason in the module's own
        // documentation: `super::SCHEMES` is a `const`, so it can hold neither
        // a reference to a `static` nor a reference to interior-mutable data,
        // and a `FileProtocol` binds one transfer's state. Withholding the row
        // is also the truthful answer while `crate::version`'s
        // `ENGINE_PROTOCOLS` is inert -- under-reporting makes a fixture skip,
        // over-reporting makes it run and fail.
        //
        // The handler nevertheless EXISTS and dispatches, which the rest of
        // this module asserts. This test is expected to be deleted, not
        // edited, by the checkpoint that wires it.
        assert!(file_row().run.is_none());
        assert!(!file_row().runnable());
        assert!(file_row().in_core_scope(), "specification 0.2.1 scope");
    }

    // -- 2. the five slots and the twelve defaults --------------------------

    #[test]
    fn exactly_five_slots_are_filled_and_dispatch_behind_dyn() {
        // The five of `Curl_protocol_file` (`lib/file.c:601-619`), each
        // reached through `&dyn Protocol` so that object safety is asserted
        // rather than assumed.
        let mut env = Env::with_file(TEST200_BODY);
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Ok(true));
        assert_eq!(env.done(CURLcode::Ok, false), Ok(()));
        assert_eq!(env.disconnect(false), Ok(()));
    }

    #[test]
    fn the_twelve_defaulted_slots_answer_the_traits_own_defaults() {
        // `do_more`, `connecting`, `doing`, the four pollsets, `write_resp`,
        // `write_resp_hd`, `connection_check`, `attach` and `follow` are all
        // `ZERO_NULL` in the C. None is overridden here, and each answers what
        // `super`'s trait documents for an unset slot -- which is the whole
        // point of not writing twelve empty bodies.
        use crate::conn::pool::{ConnCheck, ConnResult};
        use crate::conn::select::EasyPollset;
        use crate::transfer::request::FollowType;

        let mut env = Env::with_file(TEST200_BODY);
        let Env {
            handler,
            chains,
            clock,
            ..
        } = &mut env;
        let mut ctx = TransferCtx::new(chains, clock, file_row());
        let protocol: &dyn Protocol = handler;

        assert_eq!(
            futures::executor::block_on(protocol.do_more(&mut ctx)),
            Ok(true)
        );
        assert_eq!(
            futures::executor::block_on(protocol.connecting(&mut ctx)),
            Ok(true)
        );
        assert_eq!(
            futures::executor::block_on(protocol.doing(&mut ctx)),
            Ok(true)
        );
        assert_eq!(
            futures::executor::block_on(
                protocol.write_resp(&mut ctx, b"x", false)
            ),
            Ok(false),
            "an unset write_resp hands the bytes to the generic chain"
        );
        assert_eq!(
            futures::executor::block_on(
                protocol.write_resp_hd(&mut ctx, b"x", false)
            ),
            Ok(false)
        );

        let mut pollset = EasyPollset::new();
        assert_eq!(protocol.proto_pollset(&mut ctx, &mut pollset), Ok(()));
        assert_eq!(protocol.doing_pollset(&mut ctx, &mut pollset), Ok(()));
        assert_eq!(protocol.domore_pollset(&mut ctx, &mut pollset), Ok(()));
        assert_eq!(protocol.perform_pollset(&mut ctx, &mut pollset), Ok(()));
        assert!(pollset.is_empty(), "PROTOPT_NONETWORK has nothing to poll");

        assert_eq!(
            protocol.connection_check(&mut ctx, ConnCheck::ISDEAD),
            ConnResult::NONE
        );
        protocol.attach(&mut ctx);
        // The default REFUSES, which is what `multi_follow` does for a
        // `ZERO_NULL` slot (`lib/multi.c:1870-1878`).
        assert_eq!(
            protocol.follow(&mut ctx, "file:///other", FollowType::Redir),
            Err(CURLcode::TooManyRedirects)
        );

        // And nothing above touched the connection: the context still points
        // at the primary chain, which is the only one `PROTOPT_NONETWORK`
        // could ever have -- `PROTOPT_DUAL`, FTP's second connection, is not
        // among this scheme's flags.
        assert_eq!(ctx.sockindex(), SocketIndex::First);
        assert!(ctx.chain().is_empty());
    }

    #[test]
    fn no_filter_is_ever_installed() {
        // `PROTOPT_NONETWORK` (`lib/file.c:635`) asserted rather than
        // described: a whole transfer runs and the connection's filter chains
        // are as empty afterwards as they were before. No socket, no name
        // resolution, no TLS session, no proxy.
        let mut env = Env::with_file(TEST200_BODY);
        assert!(env.chains.chain(SocketIndex::First).is_empty());
        assert!(env.chains.chain(SocketIndex::Secondary).is_empty());

        assert_eq!(env.transfer(), Ok(()));

        assert!(env.chains.chain(SocketIndex::First).is_empty());
        assert!(env.chains.chain(SocketIndex::Secondary).is_empty());
        assert_eq!(env.body(), TEST200_BODY);
    }

    // -- 3. the synthesised header block, byte for byte ---------------------

    #[test]
    fn a_small_file_emits_the_exact_headers_then_its_bytes() {
        let mut env = Env::with_file(TEST200_BODY);
        assert_eq!(env.transfer(), Ok(()));

        // `lib/file.c:432-464`, in order, with the lower-case `r` of
        // `Accept-ranges` and the bare CRLF that ends the block.
        assert_eq!(
            env.headers(),
            b"Content-Length: 26\r\n\
              Accept-ranges: bytes\r\n\
              Last-Modified: Sat, 01 Jan 2000 12:00:00 GMT\r\n\
              \r\n"
                .to_vec()
        );
        assert_eq!(env.body(), TEST200_BODY);

        // Four writes, all HEADER and none STATUS: `crate::headers` stores a
        // write only when it is HEADER WITHOUT STATUS, so adding STATUS would
        // withhold these lines from `curl_easy_header`.
        let recorded = locked(&env.recorded);
        let header_writes: Vec<&ClientWriteFlags> = recorded
            .writes
            .iter()
            .map(|(flags, _)| flags)
            .filter(|flags| flags.contains(ClientWriteFlags::HEADER))
            .collect();
        assert_eq!(header_writes.len(), 4);
        for flags in header_writes {
            assert!(!flags.contains(ClientWriteFlags::STATUS));
            assert!(!flags.contains(ClientWriteFlags::BODY));
        }
    }

    #[test]
    fn accept_ranges_keeps_the_c_spelling() {
        // RFC 9110 spells the field `Accept-Ranges`. `lib/file.c:430` does not,
        // and specification 0.8.1 freezes the bytes that reach the client.
        assert_eq!(ACCEPT_RANGES, "Accept-ranges: bytes\r\n");
        assert!(!ACCEPT_RANGES.contains("Accept-Ranges"));
        assert_eq!(ACCEPT_RANGES.len(), 22);
    }

    #[test]
    fn the_header_lines_are_rendered_exactly() {
        assert_eq!(content_length_line(0), "Content-Length: 0\r\n");
        assert_eq!(content_length_line(26), "Content-Length: 26\r\n");
        assert_eq!(
            content_length_line(i64::MAX),
            "Content-Length: 9223372036854775807\r\n"
        );

        // "Tue, 15 Nov 1994 12:45:26 GMT" -- the example in the C's own
        // comment at `lib/file.c:450`.
        assert_eq!(
            last_modified_line(784_903_526),
            Ok("Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT\r\n".to_owned())
        );
        // A Saturday, which exercises `wday - 1`.
        assert_eq!(
            last_modified_line(MTIME_2000),
            Ok("Last-Modified: Sat, 01 Jan 2000 12:00:00 GMT\r\n".to_owned())
        );
        // A SUNDAY, which is the `wday == 0 -> index 6` branch. Getting this
        // wrong shifts every weekday by one day.
        assert_eq!(
            last_modified_line(259_200),
            Ok("Last-Modified: Sun, 04 Jan 1970 00:00:00 GMT\r\n".to_owned())
        );
        // The epoch itself was a Thursday.
        assert_eq!(
            last_modified_line(0),
            Ok("Last-Modified: Thu, 01 Jan 1970 00:00:00 GMT\r\n".to_owned())
        );
        // `%4d`, not `%04d`: a three-digit year renders with a LEADING SPACE.
        assert_eq!(
            last_modified_line(-30_636_384_833),
            Ok("Last-Modified: Mon, 04 Mar  999 05:06:07 GMT\r\n".to_owned())
        );
    }

    #[test]
    fn an_unrepresentable_timestamp_propagates_gmtimes_own_code() {
        // `lib/file.c:446-448`: `result = curlx_gmtime(filetime, &buffer); if
        // (result) return result;`. `curlx_gmtime` reports
        // `CURLE_BAD_FUNCTION_ARGUMENT` when the platform function fails
        // (`lib/curlx/timeval.c:255`), which is what an unrepresentable year
        // is here.
        assert_eq!(
            last_modified_line(i64::MAX),
            Err(CURLcode::BadFunctionArgument)
        );

        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, i64::MAX))], |_| {});
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::BadFunctionArgument));
        // The two lines before it were already emitted, exactly as the C's
        // sequential writes leave them.
        assert_eq!(
            env.headers(),
            b"Content-Length: 26\r\nAccept-ranges: bytes\r\n".to_vec()
        );
    }

    #[test]
    fn a_failing_writer_stage_stops_the_transfer_at_that_write() {
        for (fails_at, expected) in [
            (0_usize, &b""[..]),
            (1, b"Content-Length: 26\r\n"),
            (2, b"Content-Length: 26\r\nAccept-ranges: bytes\r\n"),
            (
                3,
                b"Content-Length: 26\r\nAccept-ranges: bytes\r\n\
                  Last-Modified: Sat, 01 Jan 2000 12:00:00 GMT\r\n",
            ),
        ] {
            let mut env = Env::build(
                &[(UP_PATH, regular(TEST200_BODY, MTIME_2000))],
                |client| client.write_fails_at = Some(fails_at),
            );
            assert_eq!(env.setup_connection(), Ok(()));
            assert_eq!(env.connect_it(), Ok(true));
            assert_eq!(env.do_it(), Err(CURLcode::WriteError));
            assert_eq!(env.headers(), expected.to_vec());
            assert!(env.body().is_empty());
        }
    }

    // -- 4. ranges ----------------------------------------------------------

    /// One transfer with `-r <spec>` set.
    fn ranged(spec: &[u8], data: &[u8]) -> Env {
        Env::build(&[(UP_PATH, regular(data, MTIME_2000))], |client| {
            client.range = Some(spec.to_vec());
            client.use_range = true;
        })
    }

    #[test]
    fn a_span_range_seeks_and_truncates() {
        // `0-3` of a 26-byte file: `Curl_range` writes `resume_from = 0` and
        // `maxdownload = 4`, and `file_do` then obeys the high-water mark.
        let mut env = ranged(b"0-3", TEST200_BODY);
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), b"foo\n".to_vec());

        // `4-9` skips four bytes and takes six.
        let mut env = ranged(b"4-9", TEST200_BODY);
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), b"   bar".to_vec());
    }

    #[test]
    fn a_range_end_past_the_size_reads_to_the_end() {
        // `20-999` on a 26-byte file. `maxdownload` becomes 980, which exceeds
        // what is left, and the read loop simply runs out -- the C never
        // compares the mark against the size, and the shortfall is not an
        // error here.
        let mut env = ranged(b"20-999", TEST200_BODY);
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), b"o\nmoo\n".to_vec());
        // The full size is still what `Content-Length:` reported, because the
        // header block precedes `Curl_range` (`lib/file.c:432` before `:474`).
        assert!(env.headers().starts_with(b"Content-Length: 26\r\n"));
    }

    #[test]
    fn a_start_past_the_end_is_refused_with_the_c_message() {
        // `lib/file.c:492-497`: `resume_from <= expected_size` or
        // `CURLE_BAD_DOWNLOAD_RESUME` with `failf`.
        let mut env = ranged(b"99-", TEST200_BODY);
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::BadDownloadResume));
        assert_eq!(env.failures(), vec![FAILED_TO_RESUME.to_owned()]);
        assert_eq!(FAILED_TO_RESUME, "failed to resume file:// transfer");
        assert!(env.body().is_empty());

        // The headers were already emitted, because the refusal happens after
        // the block. A resumed transfer therefore still reports the FULL size.
        assert!(env.headers().starts_with(b"Content-Length: 26\r\n"));
    }

    #[test]
    fn an_inverted_range_is_a_range_error_before_anything_is_read() {
        // `9-4`: `lib/curl_range.c:69-70` refuses `from > to`.
        let mut env = ranged(b"9-4", TEST200_BODY);
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::RangeError));
        assert!(env.body().is_empty());
        // And `-0`, which `lib/curl_range.c:56-58` also refuses.
        let mut env = ranged(b"-0", TEST200_BODY);
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::RangeError));
    }

    #[test]
    fn the_last_bytes_form_measures_from_the_end() {
        // `-4` sets `maxdownload = 4` and `resume_from = -4`
        // (`lib/curl_range.c:60-61`), and `file_do:480-486` then adds the file
        // size to the negative offset.
        let mut env = ranged(b"-4", TEST200_BODY);
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), b"moo\n".to_vec());
    }

    #[test]
    fn a_negative_offset_without_a_size_is_a_read_error() {
        // `lib/file.c:480-484`: a negative offset needs `fstat` to have
        // succeeded, and the message's trailing full stop is part of it.
        let mut env = Env::build(
            &[(
                UP_PATH,
                Entry {
                    data: TEST200_BODY.to_vec(),
                    deny_stat: true,
                    ..Entry::default()
                },
            )],
            |client| {
                client.range = Some(b"-4".to_vec());
                client.use_range = true;
            },
        );
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::ReadError));
        assert_eq!(env.failures(), vec![CANNOT_GET_SIZE_OF_FILE.to_owned()]);
        assert_eq!(CANNOT_GET_SIZE_OF_FILE, "cannot get the size of file.");
        // No `fstat` means no header block at all.
        assert!(env.headers().is_empty());
    }

    #[test]
    fn a_seek_that_lands_elsewhere_is_refused() {
        // `lib/file.c:518-520`: the C compares `curl_lseek`'s answer against
        // the offset it asked for and refuses any difference.
        let mut env = Env::build(
            &[(
                UP_PATH,
                Entry {
                    data: TEST200_BODY.to_vec(),
                    mtime: MTIME_2000,
                    seek_lands_wrong: true,
                    ..Entry::default()
                },
            )],
            |client| {
                client.range = Some(b"4-9".to_vec());
                client.use_range = true;
            },
        );
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::BadDownloadResume));
    }

    #[test]
    fn no_range_resets_the_high_water_mark_to_unlimited() {
        // `lib/curl_range.c:87`: the `else` branch writes `-1`. It is not a
        // no-op -- `file_do:501` tests `maxdownload > 0`, so a stale positive
        // mark would silently truncate the body.
        let recorded = Arc::new(Mutex::new(ClientShared::default()));
        let mut client = MemClient::new(UP_PATH, &recorded);
        client.maxdownload = 4;
        assert_eq!(apply_range(&mut client), Ok(()));
        assert_eq!(client.maxdownload(), MAXDOWNLOAD_UNLIMITED);

        // A range string present but NOT in use takes the same branch: the C
        // conjoins `use_range` and `range`.
        client.range = Some(b"0-3".to_vec());
        client.use_range = false;
        client.maxdownload = 9;
        assert_eq!(apply_range(&mut client), Ok(()));
        assert_eq!(client.maxdownload(), MAXDOWNLOAD_UNLIMITED);
        assert_eq!(client.resume_from(), 0);

        // And the `X-` form writes the offset but leaves the mark ALONE, which
        // is the third case and must not collapse into the `-1` above.
        client.use_range = true;
        client.range = Some(b"7-".to_vec());
        client.maxdownload = 42;
        assert_eq!(apply_range(&mut client), Ok(()));
        assert_eq!(client.resume_from(), 7);
        assert_eq!(client.maxdownload(), 42);
    }

    #[test]
    fn a_high_water_mark_without_a_range_is_reset_before_it_is_read() {
        // The ORDER of `lib/file.c:474` and `:501` decides this, and it is
        // worth an assertion because the obvious reading is wrong: `Curl_range`
        // runs FIRST, and with no range in effect its `else` branch writes
        // `maxdownload = -1` (`lib/curl_range.c:87`). So a mark left over from
        // an earlier request cannot truncate a `file://` body, and
        // `if(data->req.maxdownload > 0)` is reachable only through a range.
        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, MTIME_2000))], |c| {
                c.maxdownload = 3;
            });
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), TEST200_BODY);

        // Through a range, the same mark does truncate.
        let mut env = ranged(b"0-2", TEST200_BODY);
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), b"foo".to_vec());
    }

    // -- 5. the failure codes -----------------------------------------------

    #[test]
    fn a_missing_file_is_curle_file_couldnt_read_file() {
        // `tests/data/test201`: a missing `file://` target is exit code 37, and
        // `lib/file.c:240-243` is where it comes from.
        let mut env = Env::build(&[], |_| {});
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Err(CURLcode::FileCouldntReadFile));
        assert_eq!(CURLcode::FileCouldntReadFile as i32, 37);

        // The message formats the STILL-ENCODED URL path, not the decoded one.
        assert_eq!(
            env.failures(),
            vec!["Could not open file /dir/file.txt".to_owned()]
        );
        // `file_done` ran, so a second connect starts over rather than
        // reporting the state as already connected.
        assert_eq!(env.connect_it(), Err(CURLcode::FileCouldntReadFile));
        assert_eq!(env.failures().len(), 2);
    }

    #[test]
    fn the_open_failure_message_shows_the_encoded_path() {
        // `lib/file.c:240` formats `data->state.up.path`. A URL of
        // `file:///no%20such` therefore reports `/no%20such` and not
        // `/no such`, and the asymmetry against `file_upload`'s message --
        // which
        // formats the DECODED path -- is the C's.
        assert_eq!(
            could_not_open(b"/no%20such"),
            "Could not open file /no%20such"
        );
        assert_eq!(
            cannot_open_for_writing(b"/no such"),
            "cannot open /no such for writing"
        );
        assert_eq!(
            cannot_get_the_size_of(b"/no such"),
            "cannot get the size of /no such"
        );
        // A path that is not UTF-8 still produces a diagnostic, because the
        // C's `%s` prints whatever bytes it was given.
        assert!(could_not_open(&[0xff, 0xfe]).starts_with("Could not open "));
    }

    #[test]
    fn an_unreadable_file_is_the_same_code_as_a_missing_one() {
        // The C only distinguishes `fd == -1` from success, so a permission
        // failure and a missing file are one branch.
        let mut env = Env::build(
            &[(
                UP_PATH,
                Entry {
                    data: TEST200_BODY.to_vec(),
                    deny_read: true,
                    ..Entry::default()
                },
            )],
            |_| {},
        );
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Err(CURLcode::FileCouldntReadFile));
    }

    #[test]
    fn an_upload_tolerates_a_target_that_will_not_open_for_reading() {
        // `lib/file.c:239`: the `fd == -1` refusal is guarded by
        // `!data->state.upload`, because an upload's target need not exist yet.
        // `tests/data/test204` is exactly that case.
        let mut env = Env::build(&[], |client| {
            client.upload = true;
            client.source = b"data\nin\nfile\nto\nwrite\n".to_vec();
        });
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert!(env.failures().is_empty());
        assert_eq!(env.do_it(), Ok(true));
        assert_eq!(env.contents(UP_PATH), b"data\nin\nfile\nto\nwrite\n");
    }

    #[test]
    fn a_read_failure_part_way_through_ends_the_transfer_successfully() {
        // THE C's BEHAVIOUR, preserved deliberately. `lib/file.c:549` tests
        // `nread <= 0` and leaves `result` at `CURLE_OK`, so a read error is
        // indistinguishable from end of file and yields a SHORT body with a
        // successful outcome. Specification 0.8.1 freezes observable behaviour
        // whether or not it reads like an oversight.
        let mut env = Env::build(
            &[(
                UP_PATH,
                Entry {
                    data: TEST200_BODY.to_vec(),
                    mtime: MTIME_2000,
                    read_fails_at: Some(8),
                    ..Entry::default()
                },
            )],
            |client| client.buf_len = 5,
        );
        assert_eq!(env.transfer(), Ok(()));
        // Four bytes per read with a five-byte buffer, so two reads land and
        // the third fails.
        assert_eq!(env.body(), b"foo\n   b".to_vec());
        assert!(env.headers().starts_with(b"Content-Length: 26\r\n"));
    }

    #[test]
    fn a_refused_progress_check_stops_the_read_loop() {
        // `lib/file.c:559-561`: `goto out` on a failing `Curl_pgrsCheck`, which
        // SKIPS the closing `Curl_pgrsUpdate`.
        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, MTIME_2000))], |c| {
                c.buf_len = 5;
                c.check_error = Some(CURLcode::AbortedByCallback);
            });
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::AbortedByCallback));
        assert_eq!(env.body(), b"foo\n".to_vec());
        let recorded = locked(&env.recorded);
        assert_eq!(recorded.checks, 1);
        assert_eq!(recorded.updates, 0, "pgrsUpdate is skipped by `goto out`");
    }

    #[test]
    fn the_closing_progress_update_is_the_transfers_own_result() {
        // `lib/file.c:593-594`: `if(!result) result = Curl_pgrsUpdate(data);`,
        // so a refusal there fails the transfer even though every byte was
        // delivered.
        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, MTIME_2000))], |c| {
                c.update_error = Some(CURLcode::AbortedByCallback);
            });
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::AbortedByCallback));
        assert_eq!(env.body(), TEST200_BODY);
        assert_eq!(locked(&env.recorded).updates, 1);
    }

    #[test]
    fn a_read_without_a_connect_delivers_nothing_and_succeeds() {
        // The C's `fd == -1` path through `file_do`: `curlx_fstat(-1, ...)`
        // fails, so `fstated` stays false, no header is emitted, and the first
        // `read` returns -1 and breaks the loop. Unreachable through `Curl_do`,
        // which runs `file_connect` first, and total here rather than a panic.
        let mut env = Env::with_file(TEST200_BODY);
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.do_it(), Ok(true));
        assert!(env.headers().is_empty());
        assert!(env.body().is_empty());
    }

    // -- 6. directories -----------------------------------------------------

    #[test]
    fn a_directory_lists_its_entries_and_skips_dotfiles() {
        // `lib/file.c:564-586`: one name per line, each followed by a BARE
        // `"\n"` and not a CRLF, in the platform's own order, with every name
        // beginning with `.` skipped -- which discards `.` and `..` along with
        // every dotfile.
        let mut env = Env::build(
            &[(
                UP_PATH,
                directory(
                    &[b"zebra", b".hidden", b"apple", b".", b"..", b"mango"],
                    MTIME_2000,
                ),
            )],
            |_| {},
        );
        assert_eq!(env.transfer(), Ok(()));
        // The order is the one the filesystem yielded. Sorting it would change
        // the transfer's body, which specification 0.8.1 freezes.
        assert_eq!(env.body(), b"zebra\napple\nmango\n".to_vec());

        // A directory has no `Content-Length:` and no `Accept-ranges:`, because
        // `expected_size` stays -1 under the `S_ISDIR` guard at
        // `lib/file.c:413`. It DOES get a `Last-Modified:`, because
        // `data->info.filetime` is assigned outside that guard at `:416`.
        assert_eq!(
            env.headers(),
            b"Last-Modified: Sat, 01 Jan 2000 12:00:00 GMT\r\n\r\n".to_vec()
        );
        assert_eq!(locked(&env.recorded).filetime, Some(MTIME_2000));
    }

    #[test]
    fn a_directory_that_will_not_open_is_a_read_error() {
        // `lib/file.c:569-571`.
        let mut env = Env::build(
            &[(
                UP_PATH,
                Entry {
                    is_dir: true,
                    deny_list: true,
                    mtime: MTIME_2000,
                    ..Entry::default()
                },
            )],
            |_| {},
        );
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::ReadError));
    }

    #[test]
    fn a_directory_cannot_be_resumed_by_either_route() {
        // Two DIFFERENT refusals reach the same code, and telling them apart is
        // worth an assertion because only one of them is the `S_ISDIR` test.
        //
        // `1-` on a directory never gets that far: `expected_size` is -1 under
        // the `S_ISDIR` guard at `lib/file.c:413`, so `resume_from <=
        // expected_size` fails at `:492` and the refusal is the `failf` one.
        let mut env = Env::build(
            &[(UP_PATH, directory(&[b"one", b"two"], MTIME_2000))],
            |client| {
                client.range = Some(b"1-".to_vec());
                client.use_range = true;
            },
        );
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::BadDownloadResume));
        assert_eq!(env.failures(), vec![FAILED_TO_RESUME.to_owned()]);
        assert!(env.body().is_empty());

        // `-4` DOES reach it. The offset stays negative after `:485` adds a
        // reported directory size of zero, so the `resume_from > 0` clamp at
        // `:488` is skipped entirely; `maxdownload` then supplies a positive
        // `expected_size` at `:501`; and `if(data->state.resume_from)` at
        // `:516`
        // is true for a negative offset, so `lib/file.c:522-524` refuses
        // outright without attempting a seek. This is the branch whose C reads
        // an uninitialised `statbuf` on its unreachable sibling.
        let mut env = Env::build(
            &[(UP_PATH, directory(&[b"one", b"two"], MTIME_2000))],
            |client| {
                client.range = Some(b"-4".to_vec());
                client.use_range = true;
            },
        );
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::BadDownloadResume));
        assert!(env.failures().is_empty(), "this one carries no message");
        assert!(env.body().is_empty());
    }

    // -- 7. uploads ---------------------------------------------------------

    /// One upload transfer whose reader chain hands out `source`.
    fn uploading(files: &[(&[u8], Entry)], source: &[u8]) -> Env {
        Env::build(files, |client| {
            client.upload = true;
            client.source = source.to_vec();
            client.infilesize = i64::try_from(source.len()).unwrap_or(-1);
        })
    }

    /// `tests/data/test204`'s upload payload.
    const UPLOAD_BODY: &[u8] = b"data\nin\nfile\nto\nwrite\n";

    #[test]
    fn an_upload_creates_the_target_with_the_configured_mode() {
        // `tests/data/test204`. `O_WRONLY | O_CREAT | O_TRUNC` with
        // `data->set.new_file_perms`, whose default is 0644.
        let mut env = uploading(&[], UPLOAD_BODY);
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.contents(UP_PATH), UPLOAD_BODY);

        let shared = locked(&env.fs);
        assert_eq!(
            shared.write_opens,
            vec![(UP_PATH.to_vec(), false, 0o644)],
            "one open, not appending, with the default mode"
        );
        drop(shared);

        let recorded = locked(&env.recorded);
        assert_eq!(recorded.upload_sizes, vec![22]);
        assert_eq!(recorded.uploaded, 22);
        assert_eq!(recorded.updates, 1);
        // An upload emits no synthesised header and no body write at all.
        assert!(recorded.writes.is_empty());
    }

    #[test]
    fn an_upload_truncates_an_existing_target() {
        // `tests/data/test1490`: the result file already holds "already
        // existing" and must end up holding only the uploaded bytes.
        let mut env = uploading(
            &[(UP_PATH, regular(b"already existing\n", MTIME_2000))],
            UPLOAD_BODY,
        );
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.contents(UP_PATH), UPLOAD_BODY);
    }

    #[test]
    fn a_resume_offset_appends_instead_of_truncating() {
        // `lib/file.c:289-292`: any NON-ZERO offset selects `O_APPEND`, and the
        // bytes before the offset are skipped from the SOURCE rather than
        // sought over in the target.
        let mut env = Env::build(
            &[(UP_PATH, regular(b"0123456789", MTIME_2000))],
            |client| {
                client.upload = true;
                client.source = b"ABCDEFGHIJ".to_vec();
                client.resume_from = 10;
            },
        );
        assert_eq!(env.transfer(), Ok(()));
        // Ten source bytes, all inside the skipped region, so nothing is
        // written and the target keeps what it had.
        assert_eq!(env.contents(UP_PATH), b"0123456789".to_vec());
        assert_eq!(
            locked(&env.fs).write_opens,
            vec![(UP_PATH.to_vec(), true, 0o644)]
        );
        assert_eq!(locked(&env.recorded).uploaded, 0);
    }

    #[test]
    fn a_resume_offset_inside_one_read_sends_only_the_tail() {
        // The straddling branch of `lib/file.c:347-351`.
        let mut env =
            Env::build(&[(UP_PATH, regular(b"0123", MTIME_2000))], |client| {
                client.upload = true;
                client.source = b"ABCDEFGHIJ".to_vec();
                client.resume_from = 4;
            });
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.contents(UP_PATH), b"0123EFGHIJ".to_vec());
        assert_eq!(locked(&env.recorded).uploaded, 6);
    }

    #[test]
    fn a_resume_offset_spanning_several_reads_is_spent_gradually() {
        // The `nread <= resume_from` branch of `lib/file.c:342-346`, taken
        // twice before the straddling branch.
        let mut env = Env::build(
            &[(UP_PATH, regular(b"XXXXXX", MTIME_2000))],
            |client| {
                client.upload = true;
                client.source = b"ABCDEFGHI".to_vec();
                client.resume_from = 6;
                client.buf_len = 4;
            },
        );
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.contents(UP_PATH), b"XXXXXXGHI".to_vec());
        assert_eq!(locked(&env.recorded).uploaded, 3);
    }

    #[test]
    fn a_negative_resume_offset_becomes_the_targets_current_size() {
        // `lib/file.c:312-320`: "treat the negative resume offset value as the
        // case of `-`", so `-C -` appends after whatever is already there.
        let mut env = Env::build(
            &[(UP_PATH, regular(b"0123456789", MTIME_2000))],
            |client| {
                client.upload = true;
                client.source = b"0123456789ABC".to_vec();
                client.resume_from = -1;
            },
        );
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.contents(UP_PATH), b"0123456789ABC".to_vec());
    }

    #[test]
    fn a_negative_resume_offset_needs_a_size_or_it_is_a_write_error() {
        // `lib/file.c:313-318`: the `fstat` failure closes the descriptor,
        // reports the message and answers `CURLE_WRITE_ERROR`.
        let mut env = Env::build(
            &[(
                UP_PATH,
                Entry {
                    deny_stat: true,
                    ..Entry::default()
                },
            )],
            |client| {
                client.upload = true;
                client.source = UPLOAD_BODY.to_vec();
                client.resume_from = -1;
            },
        );
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::WriteError));
        assert_eq!(
            env.failures(),
            vec!["cannot get the size of /dir/file.txt".to_owned()]
        );
    }

    #[test]
    fn a_target_that_will_not_open_for_writing_is_a_write_error() {
        // `lib/file.c:303-306`.
        let mut env = uploading(
            &[(
                UP_PATH,
                Entry {
                    deny_write: true,
                    ..Entry::default()
                },
            )],
            UPLOAD_BODY,
        );
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::WriteError));
        assert_eq!(
            env.failures(),
            vec!["cannot open /dir/file.txt for writing".to_owned()]
        );
    }

    #[test]
    fn a_short_write_is_a_send_error() {
        // `lib/file.c:358-360`: a failed write and a SHORT write are one
        // failure, which is why the seam must not offer a write-everything
        // helper.
        let mut env = uploading(
            &[(
                UP_PATH,
                Entry {
                    short_write: true,
                    ..Entry::default()
                },
            )],
            UPLOAD_BODY,
        );
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::SendError));
        assert_eq!(CURLcode::SendError as i32, 55);
    }

    #[test]
    fn a_path_with_no_directory_separator_is_refused() {
        // `lib/file.c:282-286`, both guards. The C's own comment on each is
        // `/* fix: better error code */`; the code is frozen regardless.
        for path in [&b"plainname"[..], b"/"] {
            let recorded = Arc::new(Mutex::new(ClientShared::default()));
            let mut client = MemClient::new(path, &recorded);
            client.upload = true;
            let fs = Arc::new(Mutex::new(FsShared::default()));
            let handler = FileProtocol::new(
                Box::new(MemFs {
                    shared: Arc::clone(&fs),
                }),
                Box::new(client),
            );
            let mut chains = FilterChains::new(None);
            let clock = TestClock::new(CurlTime::ZERO);
            let mut ctx = TransferCtx::new(&mut chains, &clock, file_row());
            let protocol: &dyn Protocol = &handler;
            assert_eq!(
                futures::executor::block_on(protocol.connect_it(&mut ctx)),
                Ok(true)
            );
            assert_eq!(
                futures::executor::block_on(protocol.do_it(&mut ctx)),
                Err(CURLcode::FileCouldntReadFile),
                "{} must be refused",
                String::from_utf8_lossy(path)
            );
        }
    }

    #[test]
    fn an_upload_without_a_connect_is_refused_rather_than_undefined() {
        // The C reaches `strchr(NULL, '/')` here, which is undefined
        // behaviour, and it is unreachable through `Curl_do`. Undefined
        // behaviour has no behaviour to preserve, so the defined answer is the
        // one the C gives for a path with no separator.
        let mut env = uploading(&[], UPLOAD_BODY);
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.do_it(), Err(CURLcode::FileCouldntReadFile));
    }

    #[test]
    fn an_upload_of_unknown_size_reports_no_upload_size() {
        // `lib/file.c:308-310`: the `-1` sentinel suppresses the call.
        let mut env = Env::build(&[], |client| {
            client.upload = true;
            client.source = UPLOAD_BODY.to_vec();
            client.infilesize = -1;
        });
        assert_eq!(env.transfer(), Ok(()));
        assert!(locked(&env.recorded).upload_sizes.is_empty());
        assert_eq!(env.contents(UP_PATH), UPLOAD_BODY);
    }

    #[test]
    fn a_failing_reader_chain_stops_the_upload() {
        // `lib/file.c:331-333`: `if(result) break;`, and the closing
        // `Curl_pgrsUpdate` is then guarded by `if(!result)`.
        let mut env = Env::build(&[], |client| {
            client.upload = true;
            client.source = UPLOAD_BODY.to_vec();
            client.read_error = Some(CURLcode::ReadError);
        });
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert_eq!(env.do_it(), Err(CURLcode::ReadError));
        assert_eq!(locked(&env.recorded).updates, 0);
    }

    #[test]
    fn an_empty_upload_writes_nothing_and_succeeds() {
        // `lib/file.c:335-336`: `if(!readcount) break;` before any write.
        let mut env = uploading(&[], b"");
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.contents(UP_PATH), Vec::<u8>::new());
        assert_eq!(locked(&env.recorded).uploaded, 0);
        assert_eq!(locked(&env.recorded).updates, 1);
    }

    // -- 8. the URL-to-path conversion --------------------------------------

    #[test]
    fn the_path_is_percent_decoded_with_curls_own_tables() {
        // `lib/file.c:160-161` uses `Curl_urldecode(..., REJECT_ZERO)`, which
        // `crate::url::escape` owns. A space arrives as `%20`; a `%` that does
        // not introduce two hex digits stands for itself; `+` is NOT a space,
        // because this is URL escaping and not form encoding.
        assert_eq!(decode_path(b"/dir/a%20b"), Ok(b"/dir/a b".to_vec()));
        assert_eq!(decode_path(b"/dir/100%25"), Ok(b"/dir/100%".to_vec()));
        assert_eq!(decode_path(b"/dir/a%4G"), Ok(b"/dir/a%4G".to_vec()));
        assert_eq!(decode_path(b"/dir/a+b"), Ok(b"/dir/a+b".to_vec()));
        assert_eq!(decode_path(b"/dir/%2Fx"), Ok(b"/dir//x".to_vec()));
    }

    #[test]
    fn a_percent_encoded_nul_is_url_malformat() {
        // `REJECT_ZERO`, with the C's comment "binary zeroes indicate foul
        // play" (`lib/file.c:202`).
        assert_eq!(decode_path(b"/dir/a%00b"), Err(CURLcode::UrlMalformat));
        assert_eq!(CURLcode::UrlMalformat as i32, 3);
    }

    #[test]
    fn a_raw_nul_is_url_malformat_through_either_test() {
        // `lib/file.c:201-205`'s `memchr` is belt-and-braces against a
        // guarantee `REJECT_ZERO` already gives -- `lib/escape.c:140` tests
        // every DECODED byte, and an unescaped NUL is one. Both are reproduced,
        // so both are asserted: the composed conversion refuses it, and the
        // second test refuses it on its own.
        assert_eq!(decode_path(&[b'/', 0, b'x']), Err(CURLcode::UrlMalformat));
        assert_eq!(
            reject_interior_nul(&[b'/', 0, b'x']),
            Err(CURLcode::UrlMalformat)
        );
        assert_eq!(reject_interior_nul(b"/dir/file.txt"), Ok(()));
        assert_eq!(reject_interior_nul(b""), Ok(()));
    }

    #[test]
    fn a_decoded_path_reaches_the_filesystem_verbatim() {
        // End to end: the URL says `%20`, the filesystem is asked for a space.
        let mut env = Env::build(
            &[(b"/dir/a b.txt", regular(TEST200_BODY, MTIME_2000))],
            |client| client.up_path = b"/dir/a%20b.txt".to_vec(),
        );
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), TEST200_BODY);
    }

    #[test]
    fn the_directory_separator_is_the_unix_one() {
        // `lib/file.c:258-262`: `DIRSEP` is `'\\'` only under
        // `DOS_FILESYSTEM`, and no mandated target defines it.
        assert_eq!(DIRSEP, b'/');
    }

    // -- 9. the phases, and the state between them --------------------------

    #[test]
    fn a_second_connect_is_a_no_op_because_the_path_is_already_set() {
        // `lib/file.c:151-158`, with the C's comment: "already connected. the
        // handler->connect_it() is normally only called once, but FILE does a
        // special check on setting up the connection which calls this
        // explicitly."
        let mut env = Env::with_file(TEST200_BODY);
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));

        // Refuse any FURTHER open, leaving the descriptor already held intact
        // -- which is what unlinking a file under an open `fd` does on the
        // mandated targets. A second connect that re-opened would now report
        // `CURLE_FILE_COULDNT_READ_FILE`; the early return means it does not,
        // and the transfer still delivers every byte through the first handle.
        if let Some(entry) = locked(&env.fs).find_mut(UP_PATH) {
            entry.deny_read = true;
        }
        assert_eq!(env.connect_it(), Ok(true));
        assert!(env.failures().is_empty());
        assert_eq!(env.do_it(), Ok(true));
        assert_eq!(env.body(), TEST200_BODY);
    }

    #[test]
    fn setup_connection_resets_a_stale_state() {
        // `file_setup_connection` installs a ZEROED `struct FILEPROTO`
        // (`lib/file.c:110`), so a second transfer on the same handle starts
        // with no path -- and therefore does not take the "already connected"
        // early return with a stale one.
        let mut env = Env::with_file(TEST200_BODY);
        assert_eq!(env.setup_connection(), Ok(()));
        assert_eq!(env.connect_it(), Ok(true));
        assert!(env.handler.session().state.is_connected());

        assert_eq!(env.setup_connection(), Ok(()));
        assert!(!env.handler.session().state.is_connected());
    }

    #[test]
    fn done_and_disconnect_both_release_the_handle() {
        // `file_done` is `file_cleanup` (`lib/file.c:125-126`) and
        // `file_disconnect` is `file_done(data, CURLE_OK, FALSE)` (`:255`).
        // Both ignore every argument they are given.
        for premature in [false, true] {
            let mut env = Env::with_file(TEST200_BODY);
            assert_eq!(env.setup_connection(), Ok(()));
            assert_eq!(env.connect_it(), Ok(true));
            assert!(env.handler.session().state.is_connected());
            assert_eq!(
                env.done(CURLcode::FileCouldntReadFile, premature),
                Ok(())
            );
            assert!(!env.handler.session().state.is_connected());
        }

        for dead in [false, true] {
            let mut env = Env::with_file(TEST200_BODY);
            assert_eq!(env.setup_connection(), Ok(()));
            assert_eq!(env.connect_it(), Ok(true));
            assert_eq!(env.disconnect(dead), Ok(()));
            assert!(!env.handler.session().state.is_connected());
        }
    }

    #[test]
    fn the_state_has_two_members_where_the_c_has_three() {
        // `freepath` has no successor: a `Vec` owns its buffer whatever a
        // slice of it points at, and neither branch that made `path` and
        // `freepath` differ -- the DOS drive-letter skip and the AmigaDOS
        // leading-slash skip -- is in the platform matrix.
        let mut state = FileState::new();
        assert!(!state.is_connected());
        assert!(state.path.is_none());
        assert!(state.handle.is_none());

        state.path = Some(b"/dir/file.txt".to_vec());
        assert!(state.is_connected());
        state.cleanup();
        assert!(!state.is_connected());
        // `Default` and `new` agree, so neither can drift from the other.
        assert!(FileState::default().path.is_none());
    }

    // -- 10. `no_body`, the time condition and the clock --------------------

    #[test]
    fn no_body_emits_the_headers_and_stops() {
        // `lib/file.c:469-470`, reached AFTER the header block and after
        // `Curl_pgrsSetDownloadSize`.
        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, MTIME_2000))], |c| {
                c.no_body = true;
            });
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(
            env.headers(),
            b"Content-Length: 26\r\n\
              Accept-ranges: bytes\r\n\
              Last-Modified: Sat, 01 Jan 2000 12:00:00 GMT\r\n\
              \r\n"
                .to_vec()
        );
        assert!(env.body().is_empty());
        assert_eq!(locked(&env.recorded).download_sizes, vec![26]);
        // `Curl_pgrsUpdate` is NOT reached: the C returns before it.
        assert_eq!(locked(&env.recorded).updates, 0);
    }

    #[test]
    fn a_refused_time_condition_emits_nothing_at_all() {
        // `lib/file.c:420-422` returns `CURLE_OK` BEFORE the header block, so a
        // refused condition produces no output whatsoever.
        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, MTIME_2000))], |c| {
                c.timecondition = true;
                c.meets_timecondition = false;
            });
        assert_eq!(env.transfer(), Ok(()));
        assert!(env.headers().is_empty());
        assert!(env.body().is_empty());
        // The filetime was still recorded, because `:416` precedes the test.
        assert_eq!(locked(&env.recorded).filetime, Some(MTIME_2000));
    }

    #[test]
    fn a_range_request_bypasses_the_time_condition() {
        // `lib/file.c:420`'s `!data->state.range`: a range request is exempt,
        // whatever the condition would have said.
        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, MTIME_2000))], |c| {
                c.timecondition = true;
                c.meets_timecondition = false;
                c.range = Some(b"0-3".to_vec());
                c.use_range = true;
            });
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), b"foo\n".to_vec());
    }

    #[test]
    fn a_satisfied_time_condition_transfers_normally() {
        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, MTIME_2000))], |c| {
                c.timecondition = true;
                c.meets_timecondition = true;
            });
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), TEST200_BODY);
    }

    #[test]
    fn the_emitted_date_ignores_the_injected_clock() {
        // `lib/file.c` calls no clock function: the one timestamp it formats is
        // the file's own `st_mtime`. This runs the same transfer twice with the
        // injected clock advanced by a decade in between, and asserts the bytes
        // are identical -- which is how "no wall clock is consulted" is proved
        // rather than asserted. `tests/data/test1445` depends on the same
        // property through `--remote-time`.
        let first = {
            let mut env = Env::with_file(TEST200_BODY);
            assert_eq!(env.transfer(), Ok(()));
            env.headers()
        };

        let mut env = Env::with_file(TEST200_BODY);
        env.clock
            .advance(std::time::Duration::from_secs(315_360_000));
        env.clock.set_epoch_secs(2_000_000_000);
        env.clock.set(CurlTime::new(99, 500_000));
        assert_eq!(env.transfer(), Ok(()));

        assert_eq!(env.headers(), first);
        assert!(env.headers().ends_with(
            b"Last-Modified: Sat, 01 Jan 2000 12:00:00 GMT\r\n\r\n"
        ));
        assert_eq!(locked(&env.recorded).filetime, Some(MTIME_2000));
    }

    // -- 11. chunking, which an application's write callback sees ------------

    #[test]
    fn the_read_loop_asks_for_one_byte_less_than_the_buffer() {
        // `lib/file.c:538-542`: `bytestoread` is at most `xfer_blen - 1`, the
        // reserved byte being where the C writes the NUL terminator at `:547`
        // that nothing then reads. The terminator has no successor -- a slice
        // carries its length -- but the `- 1` does, because it decides the
        // chunk boundaries a `CURLOPT_WRITEFUNCTION` sees.
        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, MTIME_2000))], |c| {
                c.buf_len = 11;
            });
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), TEST200_BODY);
        // 26 bytes in tens, not elevens.
        assert_eq!(locked(&env.recorded).body_chunks(), vec![10, 10, 6]);
        // One progress check per delivered chunk (`:559`), plus the closing
        // update (`:594`).
        let recorded = locked(&env.recorded);
        assert_eq!(recorded.checks, 3);
        assert_eq!(recorded.updates, 1);
    }

    #[test]
    fn a_ranged_read_never_asks_for_more_than_is_wanted() {
        // The `size_known` arm of `lib/file.c:537-540`: the last read is
        // clamped to what is left rather than to the buffer.
        let mut env = Env::build(
            &[(UP_PATH, regular(TEST200_BODY, MTIME_2000))],
            |client| {
                client.range = Some(b"0-14".to_vec());
                client.use_range = true;
                client.buf_len = 11;
            },
        );
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(env.body(), b"foo\n   bar\nbar\n".to_vec());
        assert_eq!(locked(&env.recorded).body_chunks(), vec![10, 5]);
    }

    #[test]
    fn a_zero_length_buffer_asks_for_nothing_and_does_not_wrap() {
        // `xfer_blen - 1` with `xfer_blen == 0` would wrap to the whole
        // address space. It saturates instead, so the loop reads nothing and
        // ends -- which is also what a C build with a zero-length transfer
        // buffer would do, since `read(fd, buf, SIZE_MAX)` fails.
        let mut env =
            Env::build(&[(UP_PATH, regular(TEST200_BODY, MTIME_2000))], |c| {
                c.buf_len = 0;
            });
        assert_eq!(env.transfer(), Ok(()));
        assert!(env.body().is_empty());
        assert!(env.headers().starts_with(b"Content-Length: 26\r\n"));
    }

    #[test]
    fn an_empty_file_emits_a_zero_length_and_no_body() {
        // `expected_size == 0` makes `size_known` false at `lib/file.c:504`,
        // so the loop reads from the buffer's full width and gets nothing.
        let mut env = Env::with_file(b"");
        assert_eq!(env.transfer(), Ok(()));
        assert_eq!(
            env.headers(),
            b"Content-Length: 0\r\n\
              Accept-ranges: bytes\r\n\
              Last-Modified: Sat, 01 Jan 2000 12:00:00 GMT\r\n\
              \r\n"
                .to_vec()
        );
        assert!(env.body().is_empty());
    }

    // -- 12. the production filesystem --------------------------------------

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri isolation refuses mkdir(2) and therefore tempfile"
    )]
    fn the_std_filesystem_reads_writes_seeks_and_lists() {
        // The one test that touches the disk, so that `StdFileSystem` is
        // exercised rather than merely compiled. Everything above runs against
        // the in-memory seam and stays Miri-clean.
        let scratch = tempfile::tempdir().expect("a temporary directory");
        let root = scratch.path().to_owned();
        let target = root.join("plainfile.txt");
        std::fs::write(&target, TEST200_BODY).expect("write the fixture");

        let fs = StdFileSystem;
        let path = {
            use std::os::unix::ffi::OsStrExt;
            target.as_os_str().as_bytes().to_vec()
        };

        // `curlx_open(path, O_RDONLY)` then `curlx_fstat` then `read`.
        let mut handle = fs.open_read(&path).expect("the fixture opens");
        let meta = handle.stat().expect("stat succeeds");
        assert_eq!(meta.size, 26);
        assert!(!meta.is_dir);
        assert!(meta.mtime > 0, "a real file has a modification time");

        let mut buffer = [0_u8; 8];
        let read = handle.read(&mut buffer).expect("the first read");
        assert_eq!(read, 8, "eight bytes were asked for and are there");
        assert_eq!(&buffer[..4], b"foo\n");

        // `curl_lseek(fd, 4, SEEK_SET)` lands where it was asked to.
        assert_eq!(handle.seek_from_start(4).ok(), Some(4));
        let mut tail = [0_u8; 6];
        let read = handle.read(&mut tail).expect("a second read");
        assert_eq!(&tail[..read], b"   bar");
        // A negative absolute offset is refused, exactly as `lseek` refuses it.
        assert!(handle.seek_from_start(-1).is_err());
        assert!(offset_u64(-1).is_err());
        assert_eq!(offset_u64(7).ok(), Some(7));

        // `curlx_open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)` then `write`.
        let created = root.join("written.txt");
        let created_path = {
            use std::os::unix::ffi::OsStrExt;
            created.as_os_str().as_bytes().to_vec()
        };
        let mut sink = fs
            .open_write(&created_path, false, 0o600)
            .expect("the target is creatable");
        assert_eq!(sink.write(b"abc").ok(), Some(3));
        drop(sink);
        assert_eq!(std::fs::read(&created).ok(), Some(b"abc".to_vec()));

        // `O_APPEND` adds rather than truncating.
        let mut sink = fs
            .open_write(&created_path, true, 0o600)
            .expect("the target reopens");
        assert_eq!(sink.write(b"def").ok(), Some(3));
        drop(sink);
        assert_eq!(std::fs::read(&created).ok(), Some(b"abcdef".to_vec()));

        // `O_TRUNC` discards it again.
        let sink = fs
            .open_write(&created_path, false, 0o600)
            .expect("the target reopens");
        drop(sink);
        assert_eq!(std::fs::read(&created).ok(), Some(Vec::new()));

        // `opendir`/`readdir`: both names are present, and `.` and `..` are
        // not, because `std::fs::read_dir` omits them and the caller would
        // discard them anyway.
        let root_path = {
            use std::os::unix::ffi::OsStrExt;
            root.as_os_str().as_bytes().to_vec()
        };
        let mut names = fs.read_dir(&root_path).expect("the directory lists");
        // Sorted HERE and nowhere else. `readdir` order is what the transfer
        // BODY carries, so `list_directory` must never reorder it -- but this
        // assertion is about the SET a real directory yields, and the order the
        // host happens to give it is not a property worth pinning.
        names.sort_unstable();
        assert_eq!(
            names,
            vec![b"plainfile.txt".to_vec(), b"written.txt".to_vec()]
        );

        // A directory OPENS for reading on the mandated targets, which is what
        // makes `file_do`'s listing branch reachable.
        let mut opened_dir =
            fs.open_read(&root_path).expect("a directory opens");
        assert!(opened_dir.stat().expect("stat a directory").is_dir);

        // And a missing path fails rather than panicking.
        assert!(fs.open_read(b"/nonexistent/curl-rs-file-test").is_err());
        assert!(
            fs.read_dir(&path).is_err(),
            "a regular file is not a directory"
        );
    }

    #[test]
    fn a_byte_path_becomes_a_platform_path_losslessly() {
        // `OsStr::from_bytes` is the lossless view on every mandated target;
        // `str::from_utf8` would refuse paths the filesystem accepts.
        assert_eq!(as_path(b"/dir/file.txt"), Path::new("/dir/file.txt"));
        let invalid = as_path(&[b'/', 0xff, 0xfe]);
        assert_eq!(invalid.as_os_str().len(), 3);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri isolation refuses mkdir(2) and therefore tempfile"
    )]
    fn an_end_to_end_transfer_runs_against_the_real_filesystem() {
        // `tests/data/test200` in miniature, driven through `&dyn Protocol`
        // with the production filesystem rather than the in-memory one, so that
        // `FileProtocol::with_std_fs` is exercised too.
        let scratch = tempfile::tempdir().expect("a temporary directory");
        let target = scratch.path().join("test200.txt");
        std::fs::write(&target, TEST200_BODY).expect("write the fixture");
        let path = {
            use std::os::unix::ffi::OsStrExt;
            target.as_os_str().as_bytes().to_vec()
        };

        let recorded = Arc::new(Mutex::new(ClientShared::default()));
        let client = MemClient::new(&path, &recorded);
        let handler = FileProtocol::with_std_fs(Box::new(client));

        let mut chains = FilterChains::new(None);
        let clock = TestClock::new(CurlTime::ZERO);
        let mut ctx = TransferCtx::new(&mut chains, &clock, file_row());
        let protocol: &dyn Protocol = &handler;

        assert_eq!(protocol.setup_connection(&mut ctx), Ok(()));
        assert_eq!(
            futures::executor::block_on(protocol.connect_it(&mut ctx)),
            Ok(true)
        );
        assert_eq!(
            futures::executor::block_on(protocol.do_it(&mut ctx)),
            Ok(true)
        );
        assert_eq!(
            futures::executor::block_on(protocol.done(
                &mut ctx,
                CURLcode::Ok,
                false
            )),
            Ok(())
        );

        let shared = locked(&recorded);
        assert_eq!(shared.joined(ClientWriteFlags::BODY), TEST200_BODY);
        let headers = shared.joined(ClientWriteFlags::HEADER);
        assert!(headers.starts_with(b"Content-Length: 26\r\n"));
        assert!(headers.ends_with(b" GMT\r\n\r\n"));
        // The filter chains never gained a filter: no socket was opened.
        assert!(chains.chain(SocketIndex::First).is_empty());
    }
}
