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

// THE BANNER ABOVE -- 23 lines, and the licence tag appears exactly once.

// NOT GATED BY ANY CARGO CAPABILITY, AND THAT IS DELIBERATE.
//
// The C wraps both `lib/netrc.c` and `lib/netrc.h` in
// `#ifndef CURL_DISABLE_NETRC` (`lib/netrc.h:28`), so a C build can compile
// the file out. This module has no such switch and must not acquire one.

//! `.netrc` credential lookup: the file behind `--netrc`, `--netrc-file`
//! and `--netrc-optional`.
//!
//! Supersedes `lib/netrc.c` and its interface `lib/netrc.h`. It answers
//! exactly one question -- *for this host, and optionally for this
//! already-known login, what login and password does the user's `.netrc`
//! supply?* -- and it answers it for every protocol, which is why it carries
//! no capability gate. The public options it backs are `CURLOPT_NETRC` (51)
//! and `CURLOPT_NETRC_FILE` (10118).
//!
//! # What the C looks like, and how the shape changes
//!
//! ```text
//! NETRCcode Curl_parsenetrc(struct store_netrc *store, const char *host,
//!                           char **loginp, char **passwordp,
//!                           const char *netrcfile);
//! ```
//!
//! `lib/netrc.h:54-58` states the contract: the caller passes an
//! empty-or-absent password, and the login is either absent -- search for
//! both a login and a password inside a `machine` section -- or present,
//! in which case the search is for a password inside that machine AND
//! that login. `lib/netrc.c:128` restates the first half as a debug
//! assertion, `DEBUGASSERT(!*passwordp)`.
//!
//! # Where the file lives, and the one call this module may not make
//!
//! `lib/netrc.c:399-464` locates the file in four steps: the `NETRC`
//! environment variable used DIRECTLY as a path, else `HOME` with `/.netrc`
//! appended, else the home directory recorded in the password database for the
//! effective user, else no file at all.
//!
//! The third step is the interesting one. Reading the password database needs
//! a C library call, and those live only under `curl-rs-lib/src/ffi/`; this
//! file may not make one. The first two steps need no such help: reading the
//! environment is plain standard library.

use std::ffi::OsString;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::{env, fmt};

use crate::error::CURLcode;
use crate::util::dynbuf::DynBuf;
use crate::util::get_line::get_line;
use crate::util::strcase::{casecompare, timestrcmp};
use crate::util::strparse::str_passblanks;

/// The ceiling on one line of the file -- `lib/netrc.c:62`.
///
/// Enforced by [`get_line`], which refuses a longer line and empties its
/// buffer. The refusal arrives here as `CURLcode::TooLarge` and leaves
/// through [`curl2netrc`] as [`NetrcCode::SyntaxError`]; see wart 1 in the
/// module documentation.
const MAX_NETRC_LINE: usize = 16384;

/// The ceiling on the whole file once comments are gone -- `lib/netrc.c:63`.
///
/// The C spells it `(128 * 1024)` and the arithmetic is kept rather than
/// folded, so the two forms can be compared by eye.
const MAX_NETRC_FILE: usize = 128 * 1024;

/// The ceiling on one token -- `lib/netrc.c:64`.
const MAX_NETRC_TOKEN: usize = 4096;

/// A login has been seen for the current machine -- `lib/netrc.c:59`.
///
/// A bit rather than a flag because the two keywords may appear in either
/// order, which `lib/netrc.c:121-122` says in as many words.
const FOUND_LOGIN: u8 = 1;

/// A password has been seen for the current machine -- `lib/netrc.c:60`.
const FOUND_PASSWORD: u8 = 2;

/// The outcome of a `.netrc` lookup -- `NETRCcode`, `lib/netrc.h:38-45`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum NetrcCode {
    /// A matching entry was found. `NETRC_OK`.
    Ok,
    /// No matching entry in the file. `NETRC_NO_MATCH`.
    NoMatch,
    /// The file does not parse. `NETRC_SYNTAX_ERROR`.
    ///
    /// Also what a size-limit breach comes out as; see [`curl2netrc`].
    SyntaxError,
    /// The file could not be opened. `NETRC_FILE_MISSING`.
    FileMissing,
    /// Allocation failed while parsing. `NETRC_OUT_OF_MEMORY`.
    ///
    /// Reachable only through [`curl2netrc`]. The C ALSO returns this from
    /// four `curlx_strdup` failures (`lib/netrc.c:278`, `:289`, `:346` and
    /// the buffer growth beneath them). Three of those four duplicate a token
    /// already parsed out of the file -- bytes that are already resident, with
    /// no amplification -- and `String`/`Vec` duplication has no stable
    /// fallible spelling at the declared minimum Rust version, so a refusal
    /// there aborts. The FOURTH, the buffer growth, does report: the line
    /// buffer beneath this parser is a `crate::util::dynbuf::DynBuf`, whose
    /// growth goes through `Vec::try_reserve_exact` and answers
    /// `CURLE_OUT_OF_MEMORY` exactly as the C's `realloc` arm does. The variant
    /// is therefore live, and dropping it would also lose one of the five
    /// messages [`NetrcCode::strerror`] owes the user.
    OutOfMemory,
}

#[allow(dead_code)] // consumer: the .netrc failure reporter of
                    // lib/url.c:2608's successor
impl NetrcCode {
    /// The message the command-line tool prints for this outcome.
    pub(crate) fn strerror(self) -> &'static str {
        match self {
            // `lib/netrc.c:372-373`.
            Self::Ok => "",
            // `lib/netrc.c:376-377`.
            Self::NoMatch => "no matching entry",
            // `lib/netrc.c:380-381`.
            Self::SyntaxError => "syntax error",
            // `lib/netrc.c:374-375`.
            Self::FileMissing => "no such file",
            // `lib/netrc.c:378-379`.
            Self::OutOfMemory => "out of memory",
        }
    }
}

/// Narrows a buffer failure to a `.netrc` failure, LOSSILY.
///
/// ```c
/// (((result) == CURLE_OUT_OF_MEMORY) ? \
///  NETRC_OUT_OF_MEMORY : NETRC_SYNTAX_ERROR)
/// ```
fn curl2netrc(result: CURLcode) -> NetrcCode {
    if result == CURLcode::OutOfMemory {
        NetrcCode::OutOfMemory
    } else {
        NetrcCode::SyntaxError
    }
}

/// The parsed file, cached across lookups -- `struct store_netrc`,
/// `lib/netrc.h:32-36`.
pub(crate) struct StoreNetrc {
    /// The file with its comments and leading blanks already gone.
    filebuf: DynBuf,
    /// Whether [`Self::filebuf`] holds the file -- the C's `BIT(loaded)`.
    loaded: bool,
}

#[allow(dead_code)] // consumer: the easy handle, which owns one of
                    // these (lib/urldata.h's successor)
impl StoreNetrc {
    /// An empty store, ready for its first lookup.
    ///
    /// Supersedes `Curl_netrc_init` (`lib/netrc.c:467-471`), which is
    /// `curlx_dyn_init(&store->filebuf, MAX_NETRC_FILE)` followed by
    /// `store->loaded = FALSE`. The ceiling is fixed at construction, as it
    /// is there, so no later call can raise it.
    pub(crate) fn new() -> Self {
        Self {
            filebuf: DynBuf::new(MAX_NETRC_FILE),
            loaded: false,
        }
    }

    /// Releases the cached file.
    ///
    /// Supersedes `Curl_netrc_cleanup` (`lib/netrc.c:472-476`). Calling it
    /// leaves the store usable: the next lookup re-reads the file, exactly
    /// as the C's does, because freeing a `dynbuf` does not destroy it.
    pub(crate) fn cleanup(&mut self) {
        self.filebuf.free();
        self.loaded = false;
    }

    /// Whether the file is currently cached.
    ///
    /// The C reads `store->loaded` directly; this crate keeps the field
    /// private, so the observable half of it is exposed here. It is what
    /// makes "the file was read once" and "the failure reset the store"
    /// assertable.
    pub(crate) fn is_loaded(&self) -> bool {
        self.loaded
    }
}

impl Default for StoreNetrc {
    fn default() -> Self {
        Self::new()
    }
}

/// Reports the store's shape and never its contents.
///
/// Written by hand rather than derived. A derived implementation would
/// print the buffer, and the buffer holds every password in the user's
/// `.netrc`. Only the byte count and the flag appear.
impl fmt::Debug for StoreNetrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoreNetrc")
            .field("loaded", &self.loaded)
            .field("bytes", &self.filebuf.len())
            .finish()
    }
}

/// What the file supplied for one host.
///
/// # Why the password can be present and empty
///
/// `lib/netrc.c:342-347` turns a matched login with no `password` keyword
/// into a BLANK password rather than an absent one, and
/// `tests/data/test479` pins the consequence on the wire:
/// `Authorization: Basic %b64[bob:]b64%`. An absent password and an empty
/// one are different answers and this type keeps them apart.
pub(crate) struct Credentials {
    /// The login the FILE supplied, or `None`.
    found_login: Option<Vec<u8>>,
    /// The password the file supplied, or `None`. **A secret.**
    password: Option<Vec<u8>>,
}

#[allow(dead_code)] // consumer: lib/url.c:2608's successor, which reads both
impl Credentials {
    /// The login the file supplied.
    ///
    /// `None` when the file named no login, and also `None` -- always --
    /// when the search fixed one. See the type documentation.
    pub(crate) fn found_login(&self) -> Option<&[u8]> {
        self.found_login.as_deref()
    }

    /// The password the file supplied.
    ///
    /// `Some(b"")` and `None` are different answers; see the type
    /// documentation. **The returned bytes are a secret**: they may not be
    /// logged, traced or formatted into a diagnostic.
    pub(crate) fn password(&self) -> Option<&[u8]> {
        self.password.as_deref()
    }

    /// Consumes the pair, handing both buffers to the caller.
    ///
    /// The C's caller takes ownership of two `strdup`ed strings, so an
    /// owning move is the faithful shape for a caller that has to store
    /// them. The order is the C's parameter order: login, then password.
    pub(crate) fn into_parts(self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        (self.found_login, self.password)
    }
}

/// Reports whether a password was found and never what it was.
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field(
                "found_login",
                &self.found_login.as_deref().map(String::from_utf8_lossy),
            )
            .field("password", &Secret(self.password.is_some()))
            .finish()
    }
}

/// A password-shaped hole in a formatting implementation.
///
/// Formats as `<redacted>` or `<absent>` and holds a single boolean, so
/// there is no route from a value of this type back to the bytes.
struct Secret(bool);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.0 { "<redacted>" } else { "<absent>" })
    }
}

/// Supplies the home directory that the environment did not.
///
/// The method returns an owned path and takes `&self`, so an implementation
/// may compute the answer lazily. That matters: the C reaches the password
/// database only when both environment variables are absent, and
/// [`netrc_path`] preserves that ordering by not calling this until then.
pub(crate) trait HomeDirectory {
    /// The effective user's home directory, or `None` if it is unknown.
    fn home_directory(&self) -> Option<PathBuf>;
}

/// An answer that was computed before the lookup started.
///
/// `Some(path)` is what `curl-rs-lib/src/ffi/sys.rs` or the command-line
/// tool produces once it has queried the password database; `None` is the
/// honest answer for a caller that cannot query it, and it makes the
/// cascade fall to `lib/netrc.c:436-438`.
impl HomeDirectory for Option<PathBuf> {
    fn home_directory(&self) -> Option<PathBuf> {
        self.clone()
    }
}

/// Reads the whole file into `filebuf`, dropping comment lines.
///
/// # Three properties of [`get_line`] this is built around
///
/// All three were measured in `src/util/get_line.rs` rather than assumed,
/// and all three are visible in the output:
///
/// 1. Every successful return ends in a line feed, and at end of input the
///    helper SYNTHESISES one. An empty file therefore yields exactly one
///    line holding `"\n"`, and the loop below runs at least once.
/// 2. A chunk is truncated at an embedded zero byte, because the C reads it
///    with `strlen`. So `"ab\0cd\nnext\n"` yields the line `"abnext\n"`.
///    Nothing here compensates for that; reproducing the helper's
///    behaviour is the point.
/// 3. A carriage return is NOT stripped. That is load-bearing twice over:
///    `lib/netrc.c:149` tests for one when ending a macro definition, and
///    wart 5 of the module documentation is the consequence of the
///    end-of-line test not doing so.
///
/// # Errors
///
/// [`NetrcCode::SyntaxError`] for an over-long line, an over-large file or
/// a read failure, and [`NetrcCode::OutOfMemory`] only for a genuine
/// allocation failure; [`curl2netrc`] explains why the first three collapse
/// into one. Either way the buffer is emptied first, as `lib/netrc.c:94`
/// does.
fn file2memory<R: BufRead>(
    input: &mut R,
    filebuf: &mut DynBuf,
) -> Result<(), NetrcCode> {
    // `lib/netrc.c:75-76`. The line buffer is local to the load and its
    // ceiling is the per-line one, not the per-file one.
    let mut linebuf = DynBuf::new(MAX_NETRC_LINE);

    // `lib/netrc.c:82-98` -- a `do`/`while(!eof)`, so the body runs before
    // the flag is tested and an empty file still contributes its
    // synthesised line.
    loop {
        let at_eof = match get_line(&mut linebuf, input) {
            Ok(at_eof) => at_eof,
            Err(result) => {
                // `lib/netrc.c:93-96`.
                filebuf.free();
                return Err(curl2netrc(result));
            }
        };

        // `lib/netrc.c:86-88`. `str_passblanks` advances the cursor over
        // spaces and tabs only -- not over the line ending, which is what
        // keeps this inside its own line.
        let mut line: &[u8] = linebuf.as_slice();
        str_passblanks(&mut line);

        // `lib/netrc.c:89-90`, inverted so that the append is the guarded
        // branch rather than the `continue`. The C reads its terminator
        // when the line is empty and finds a zero rather than a `#`, which
        // is what `first()` returning `None` models here.
        if line.first() != Some(&b'#') {
            if let Err(result) = filebuf.addn(line) {
                // `lib/netrc.c:93-96` again. The ceiling breach empties the
                // buffer inside `addn`; freeing it as well matches the C
                // statement for statement and is idempotent.
                filebuf.free();
                return Err(curl2netrc(result));
            }
        }

        if at_eof {
            return Ok(());
        }
    }
}

/// Whether a byte continues a bare token -- `lib/netrc.c:164`.
const fn continues_bare_token(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7F)
}

/// The byte at `at`, or the C string terminator past the end.
fn byte_at(buf: &[u8], at: usize) -> u8 {
    buf.get(at).copied().unwrap_or(0)
}

/// Advances over leading blanks and returns the new position.
///
/// `lib/netrc.c:146`'s `curlx_str_passblanks(&tok)` expressed on an index
/// rather than a pointer. Blank means space or tab and nothing else, so a
/// line ending stops the walk.
fn pass_blanks(buf: &[u8], at: usize) -> usize {
    let mut cursor: &[u8] = buf.get(at..).unwrap_or(&[]);
    let before = cursor.len();
    str_passblanks(&mut cursor);
    // `before` came from the same slice and `str_passblanks` only shrinks
    // it, so the difference is the number of blanks skipped and the
    // subtraction cannot go below zero. It is written in the checked form
    // anyway: this file parses an untrusted file, and an invariant that
    // holds by argument is worth one line less than an invariant the
    // compiler cannot get wrong.
    at.saturating_add(before.saturating_sub(cursor.len()))
}

/// Reads one bare token into `token` and returns the index that ended it.
///
/// # Errors
///
/// [`NetrcCode::SyntaxError`] when the token measures zero bytes
/// (`lib/netrc.c:168-171`). That happens when the byte at `at` is one the
/// walk refuses, and the only such bytes reaching here are the carriage
/// return of wart 5 and anything from 0x80 upwards.
fn read_bare(
    buf: &[u8],
    at: usize,
    token: &mut DynBuf,
) -> Result<usize, NetrcCode> {
    // `lib/netrc.c:164-167`.
    let mut end = at;
    while continues_bare_token(byte_at(buf, end)) {
        end = end.saturating_add(1);
    }

    // `lib/netrc.c:168-171`.
    if end == at {
        return Err(NetrcCode::SyntaxError);
    }

    // `lib/netrc.c:172-176`. The walk above established `at <= end` and
    // both are inside the buffer, so the span exists; the fallback keeps
    // the expression total without an assertion.
    let span = buf.get(at..end).unwrap_or(&[]);
    token.addn(span).map_err(curl2netrc)?;
    Ok(end)
}

/// Reads one quoted token into `token` and returns the index past its
/// closing quote.
///
/// # Errors
///
/// [`NetrcCode::SyntaxError`] when the input ends inside an escape or
/// without a closing quote (`lib/netrc.c:216-220`). Both are fatal for the
/// WHOLE parse rather than for the token, because the C jumps straight to
/// its exit label -- so an unterminated quote anywhere in the file loses
/// the credentials that had already been found.
fn read_quoted(
    buf: &[u8],
    at: usize,
    token: &mut DynBuf,
) -> Result<usize, NetrcCode> {
    let mut escape = false;
    let mut endquote = false;

    // `lib/netrc.c:181` -- step over the leading quote.
    let mut end = at.saturating_add(1);

    // `lib/netrc.c:182` -- `while(*tok_end)`, so the terminator ends the
    // walk with `endquote` still false and the error below fires.
    loop {
        let raw = byte_at(buf, end);
        if raw == 0 {
            break;
        }

        let mut byte = raw;
        if escape {
            // `lib/netrc.c:185-198`.
            escape = false;
            byte = match byte {
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                other => other,
            };
        } else if byte == b'\\' {
            // `lib/netrc.c:199-203` -- the backslash is consumed and not
            // stored.
            escape = true;
            end = end.saturating_add(1);
            continue;
        } else if byte == b'"' {
            // `lib/netrc.c:204-208` -- step over the closing quote.
            end = end.saturating_add(1);
            endquote = true;
            break;
        }

        // `lib/netrc.c:209-213`. One byte at a time, exactly as the C
        // appends it, so the token ceiling is reached at the same byte.
        token.addn(&[byte]).map_err(curl2netrc)?;
        end = end.saturating_add(1);
    }

    // `lib/netrc.c:216-220`.
    if escape || !endquote {
        return Err(NetrcCode::SyntaxError);
    }
    Ok(end)
}

/// Where the walk stands with respect to the host it is looking for --
/// `enum host_lookup_state`, `lib/netrc.c:46-51`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HostLookupState {
    /// Outside any entry. `NOTHING`.
    Nothing,
    /// The `machine` keyword was seen and its name is next. `HOSTFOUND`.
    HostFound,
    /// This entry is the one being looked for. `HOSTVALID`.
    HostValid,
    /// Inside a macro definition, skipping to a blank line. `MACDEF`.
    Macdef,
}

/// Which sub-keyword is expecting its value -- `enum found_state`,
/// `lib/netrc.c:53-57`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FoundState {
    /// No sub-keyword is pending. `NONE`.
    None,
    /// The next token is a login. `LOGIN`.
    Login,
    /// The next token is a password. `PASSWORD`.
    Password,
}

/// The mutable state of the switch at `lib/netrc.c:230-325`.
///
/// The C keeps these as eleven locals of `parsenetrc` and threads them through
/// one `switch`. Gathering them into a value keeps the switch's three arms
/// independently readable and independently testable while changing nothing
/// about what they do.
struct Machine<'a> {
    /// The host being looked for. Compared case-INsensitively.
    host: &'a [u8],
    /// The login the caller fixed, if any.
    ///
    /// `Some` is the C's `specific_login` being true, and the C computes
    /// that from `!!login` -- a NULLNESS test, not an emptiness test -- so
    /// `Some(b"")` is a fixed login that matches only an empty one.
    specific: Option<&'a [u8]>,
    /// `lib/netrc.c:119`.
    state: HostLookupState,
    /// `lib/netrc.c:120`.
    keyword: FoundState,
    /// `lib/netrc.c:121-122` -- the two found bits, in either order.
    found: u8,
    /// `lib/netrc.c:123` -- whether the login seen is the wanted one.
    our_login: bool,
    /// `lib/netrc.c:124`.
    done: bool,
    /// `lib/netrc.c:116` -- seeded with the caller's login.
    login: Option<Vec<u8>>,
    /// `lib/netrc.c:117`. **A secret.**
    password: Option<Vec<u8>>,
    /// `lib/netrc.c:115` -- pessimistic until a host matches.
    retcode: NetrcCode,
}

impl<'a> Machine<'a> {
    /// The starting state -- `lib/netrc.c:115-124`.
    fn new(host: &'a [u8], specific: Option<&'a [u8]>) -> Self {
        Self {
            host,
            specific,
            state: HostLookupState::Nothing,
            keyword: FoundState::None,
            found: 0,
            our_login: false,
            done: false,
            // `lib/netrc.c:116` -- `login = *loginp`. Owned here, because
            // the walk may replace it with a login read out of the file.
            login: specific.map(<[u8]>::to_vec),
            password: None,
            retcode: NetrcCode::NoMatch,
        }
    }

    /// Whether the caller fixed a login -- the C's `specific_login`.
    fn specific_login(&self) -> bool {
        self.specific.is_some()
    }

    /// Forgets the credentials at an entry boundary.
    fn forget_credentials(&mut self) {
        self.password = None;
        if !self.specific_login() {
            self.login = None;
        }
    }

    /// Feeds one token to the switch at `lib/netrc.c:230-325`.
    fn step(&mut self, tok: &[u8]) {
        match self.state {
            HostLookupState::Nothing => self.nothing(tok),
            HostLookupState::Macdef => {
                // `lib/netrc.c:254-257`. The ordinary way out of a macro
                // definition is the blank-line test the caller runs before
                // this; this arm catches the empty token a `""` produces.
                if tok.is_empty() {
                    self.state = HostLookupState::Nothing;
                }
            }
            HostLookupState::HostFound => {
                // `lib/netrc.c:258-267`. Machine names are compared
                // case-INsensitively, with the same comparator as the
                // keywords.
                if casecompare(self.host, tok) {
                    self.state = HostLookupState::HostValid;
                    self.retcode = NetrcCode::Ok;
                } else {
                    self.state = HostLookupState::Nothing;
                }
            }
            HostLookupState::HostValid => self.host_valid(tok),
        }
    }

    /// The `NOTHING` arm -- `lib/netrc.c:231-253`.
    fn nothing(&mut self, tok: &[u8]) {
        if casecompare(b"macdef", tok) {
            // A macro is defined with the given name; its body begins on
            // the next line and runs to a blank one. curl never executes
            // it, and `docs/libcurl/opts/CURLOPT_NETRC.md` says so.
            self.state = HostLookupState::Macdef;
        } else if casecompare(b"machine", tok) {
            // `lib/netrc.c:237-248`. The next token is the name, and this
            // boundary resets everything gathered for the previous entry.
            self.state = HostLookupState::HostFound;
            self.keyword = FoundState::None;
            self.found = 0;
            self.our_login = false;
            self.forget_credentials();
        } else if casecompare(b"default", tok) {
            // `lib/netrc.c:249-252`. A `default` entry matches BY
            // DEFINITION, so the outcome turns successful immediately --
            // before any credential has been read.
            self.state = HostLookupState::HostValid;
            self.retcode = NetrcCode::Ok;
        }
    }

    /// The `HOSTVALID` arm -- `lib/netrc.c:268-324`.
    ///
    /// Two of the three comparison policies of this file meet here, and
    /// using the wrong one either way is a defect:
    ///
    /// * Keywords and machine names go through `casecompare`, the body of
    ///   `curl_strequal`, so they are case-INsensitive.
    /// * A login goes through `timestrcmp`, which is constant-time and
    ///   case-SENSITIVE. It is a credential comparison and the timing
    ///   property is deliberate, so `casecompare` may never appear at that
    ///   site.
    fn host_valid(&mut self, tok: &[u8]) {
        match self.keyword {
            FoundState::Login => {
                // `lib/netrc.c:270-284`.
                if let Some(wanted) = self.specific {
                    // `lib/netrc.c:271-272`.
                    self.our_login = timestrcmp(Some(wanted), Some(tok)) == 0;
                } else {
                    // `lib/netrc.c:273-281`. With no login fixed, any login
                    // in a matching entry is "ours".
                    self.our_login = true;
                    self.login = Some(tok.to_vec());
                }
                // `lib/netrc.c:282` -- UNCONDITIONAL. This bit is set even
                // when the login is the wrong one, unlike the password bit
                // below, and the asymmetry is what lets the pair of bits
                // reach `FOUND_LOGIN` without reaching both.
                self.found |= FOUND_LOGIN;
                self.keyword = FoundState::None;
            }
            FoundState::Password => {
                // `lib/netrc.c:285-295`. The password is ALWAYS stored,
                // even for the wrong login; only the bit is conditional.
                // See `a_mismatched_login_still_yields_a_password_at_end_of
                // _file` for the consequence.
                self.password = Some(tok.to_vec());
                if !self.specific_login() || self.our_login {
                    self.found |= FOUND_PASSWORD;
                }
                self.keyword = FoundState::None;
            }
            FoundState::None => {
                if casecompare(b"login", tok) {
                    // `lib/netrc.c:296-297`.
                    self.keyword = FoundState::Login;
                } else if casecompare(b"password", tok) {
                    // `lib/netrc.c:298-299`.
                    self.keyword = FoundState::Password;
                } else if casecompare(b"machine", tok) {
                    // `lib/netrc.c:300-312`.
                    if self.found & FOUND_PASSWORD != 0 {
                        // The C's `break` leaves the switch here, so the
                        // both-bits test at the foot of this function is
                        // skipped. Returning early reproduces that; the
                        // outcome is the same either way, because `done` is
                        // already set.
                        self.done = true;
                        return;
                    }
                    self.state = HostLookupState::HostFound;
                    self.keyword = FoundState::None;
                    self.found = 0;
                    // NOTE: `our_login` is NOT reset here, although the
                    // `NOTHING` arm's `machine` branch does reset it
                    // (`lib/netrc.c:244`). `tests/data/test478` depends on
                    // the difference: the login matched two entries earlier
                    // and the flag has to survive to admit the password in
                    // the last one.
                    self.forget_credentials();
                } else if casecompare(b"default", tok) {
                    // `lib/netrc.c:313-319`.
                    self.state = HostLookupState::HostValid;
                    self.retcode = NetrcCode::Ok;
                    self.forget_credentials();
                }
            }
        }

        // `lib/netrc.c:320-323`. Runs after EVERY arm above, including the
        // two that consumed a value, which is what lets the second of the
        // pair finish the search.
        if self.found == (FOUND_PASSWORD | FOUND_LOGIN) && self.our_login {
            self.done = true;
        }
    }

    /// The post-walk fixups -- `lib/netrc.c:341-357`.
    ///
    /// # Errors
    ///
    /// Whatever the walk settled on, plus the one outcome decided here:
    /// [`NetrcCode::NoMatch`] for a `default` entry that carried no
    /// credentials at all, which `tests/data/test486` pins.
    fn finish(self) -> Result<Credentials, NetrcCode> {
        let mut login = self.login;
        let mut password = self.password;
        let mut retcode = self.retcode;

        if retcode == NetrcCode::Ok {
            if password.is_none() && self.our_login {
                // `lib/netrc.c:342-347` -- "success without a password, set
                // a blank one". BLANK, not absent: `tests/data/test479`
                // expects `Authorization: Basic %b64[bob:]b64%` on the
                // wire, which an absent password would not produce.
                password = Some(Vec::new());
            } else if login.is_none() && password.is_none() {
                // `lib/netrc.c:348-350` -- "a default with no credentials".
                retcode = NetrcCode::NoMatch;
            }
        }

        if retcode != NetrcCode::Ok {
            return Err(retcode);
        }

        // `lib/netrc.c:354-355` -- the login is handed back ONLY when the
        // caller did not fix one. See the `Credentials` documentation for
        // why the accessor is named after what the file found.
        if self.specific.is_some() {
            login = None;
        }
        Ok(Credentials {
            found_login: login,
            password,
        })
    }
}

/// Walks the loaded file and returns what it found.
///
/// # Errors
///
/// [`NetrcCode::SyntaxError`] from either tokeniser, [`NetrcCode::NoMatch`]
/// when no entry matched, and [`NetrcCode::OutOfMemory`] only from a
/// genuine allocation failure.
fn search(
    netrc: &[u8],
    host: &[u8],
    specific: Option<&[u8]>,
) -> Result<Credentials, NetrcCode> {
    // `lib/netrc.c:129`. Reset rather than reallocated per token, exactly
    // as the C reuses one buffer for the whole walk.
    let mut token = DynBuf::new(MAX_NETRC_TOKEN);
    let mut machine = Machine::new(host, specific);

    // `lib/netrc.c:138` -- `netrcbuffer`, the start of the current line.
    let mut line_start = 0usize;

    // `lib/netrc.c:140`.
    while !machine.done {
        // `lib/netrc.c:141`.
        let mut at = line_start;

        // `lib/netrc.c:142`. The C also tests its cursor for nullness,
        // which cannot arise here: an empty buffer is an empty slice rather
        // than a null pointer, and the end-of-line test below refuses it on
        // the first iteration for the same net effect.
        while !machine.done {
            // `lib/netrc.c:145-146`.
            token.reset();
            at = pass_blanks(netrc, at);

            // `lib/netrc.c:148-151`, collapsed into one condition. The C
            // nests two `if`s and this is the same test; it runs BEFORE the
            // end-of-line break and does not skip the rest of the
            // iteration, which is why a carriage return here falls through
            // into wart 5.
            if machine.state == HostLookupState::Macdef
                && matches!(byte_at(netrc, at), b'\n' | b'\r')
            {
                machine.state = HostLookupState::Nothing;
            }

            // `lib/netrc.c:153-155`. Only a line feed and the terminator
            // end the line -- notably NOT a carriage return.
            let here = byte_at(netrc, at);
            if here == 0 || here == b'\n' {
                break;
            }

            // `lib/netrc.c:158-221`. A leading double quote selects the
            // quoted reader.
            let end = if here == b'"' {
                read_quoted(netrc, at, &mut token)?
            } else {
                read_bare(netrc, at, &mut token)?
            };

            // `lib/netrc.c:223-228`. An empty token is the empty string and
            // never absent, so that the switch has nothing to special-case.
            // An empty `DynBuf` yields an empty slice, which is that.
            machine.step(token.as_slice());

            // `lib/netrc.c:326` -- `tok = ++tok_end`. Runs even once the
            // walk is finished, as the C's does.
            at = end.saturating_add(1);
        }

        if !machine.done {
            // `lib/netrc.c:328-336`.
            let rest = netrc.get(at..).unwrap_or(&[]);
            match rest.iter().position(|&byte| byte == b'\n') {
                // `at + offset` is the line feed, so the next line starts
                // one byte later.
                Some(offset) => {
                    line_start = at.saturating_add(offset).saturating_add(1);
                }
                // `lib/netrc.c:332-333` -- no further line, so stop.
                None => break,
            }
        }
    }

    machine.finish()
}

/// Searches an already-loaded store and resets it on failure.
///
/// # Errors
///
/// Whatever [`search`] returned.
fn after_load(
    store: &mut StoreNetrc,
    host: &[u8],
    login: Option<&[u8]>,
) -> Result<Credentials, NetrcCode> {
    let outcome = search(store.filebuf.as_slice(), host, login);
    if outcome.is_err() {
        // `lib/netrc.c:358-364`. The C also frees its two strings here;
        // those are owned values that go out of scope with `search`.
        store.filebuf.free();
        store.loaded = false;
    }
    outcome
}

/// Looks credentials up in a `.netrc` supplied as an open reader.
///
/// # Errors
///
/// As [`parsenetrc`], except that [`NetrcCode::FileMissing`] cannot arise
/// because no file is opened.
#[allow(dead_code)] // consumer: a caller holding a .netrc from a
                    // source that is not a path
pub(crate) fn parse_reader<R: BufRead>(
    store: &mut StoreNetrc,
    host: &[u8],
    login: Option<&[u8]>,
    input: &mut R,
) -> Result<Credentials, NetrcCode> {
    // `lib/netrc.c:131-136`. A load failure returns immediately, WITHOUT
    // the reset of `after_load`: the flag is still false and `file2memory`
    // has already emptied the buffer if it needed to.
    if !store.loaded {
        file2memory(input, &mut store.filebuf)?;
        store.loaded = true;
    }
    after_load(store, host, login)
}

/// Looks credentials up in a `.netrc` at a known path.
///
/// # Errors
///
/// As [`parsenetrc`].
fn parse_path(
    store: &mut StoreNetrc,
    host: &[u8],
    login: Option<&[u8]>,
    netrcfile: &Path,
) -> Result<Credentials, NetrcCode> {
    if !store.loaded {
        // `lib/netrc.c:73-74`.
        let file = match File::open(netrcfile) {
            Ok(file) => file,
            Err(_) => return Err(NetrcCode::FileMissing),
        };
        let mut input = BufReader::new(file);
        file2memory(&mut input, &mut store.filebuf)?;
        store.loaded = true;
    }
    after_load(store, host, login)
}

/// Whether an environment value counts as present.
///
/// `curl_getenv` on the mandated targets is one line, `lib/getenv.c:66`:
///
/// ```c
/// return (env && env[0]) ? curlx_strdup(env) : NULL;
/// ```
fn nonempty(value: &OsString) -> bool {
    !value.is_empty()
}

/// Reads an environment variable with curl's own presence rule.
fn getenv(name: &str) -> Option<OsString> {
    env::var_os(name).filter(nonempty)
}

/// Builds the default `.netrc` path from already-read environment values.
///
/// The order is the C's and it matters:
///
/// 1. `NETRC` is used **directly as the whole path** and bypasses the home
///    directory entirely (`lib/netrc.c:405-406`). It is not a directory and
///    no name is appended to it.
/// 2. Otherwise `HOME`, with `"/.netrc"` appended
///    (`lib/netrc.c:407-409`, `:440`).
/// 3. Otherwise the injected [`HomeDirectory`], which stands in for the
///    password-database lookup of `lib/netrc.c:410-425`. It is consulted
///    **only** at this point, so an implementation may do real work in it.
/// 4. Otherwise there is no file (`lib/netrc.c:436-438`).
///
/// # Errors
///
/// [`NetrcCode::FileMissing`] when no home directory can be established,
/// which is the C's own choice of code for "no home directory found".
fn netrc_path_from(
    netrc_var: Option<OsString>,
    home_var: Option<OsString>,
    home: &dyn HomeDirectory,
) -> Result<PathBuf, NetrcCode> {
    // Step 1.
    if let Some(file) = netrc_var {
        return Ok(PathBuf::from(file));
    }

    // Steps 2 and 3.
    let mut joined = match home_var {
        Some(value) => value,
        None => match home.home_directory() {
            Some(dir) => dir.into_os_string(),
            // Step 4.
            None => return Err(NetrcCode::FileMissing),
        },
    };

    // `lib/netrc.c:440`.
    joined.push("/");
    joined.push(".netrc");
    Ok(PathBuf::from(joined))
}

/// The default `.netrc` path for this process.
///
/// [`netrc_path_from`] with the two environment variables actually read.
///
/// # Errors
///
/// As [`netrc_path_from`].
fn netrc_path(home: &dyn HomeDirectory) -> Result<PathBuf, NetrcCode> {
    netrc_path_from(getenv("NETRC"), getenv("HOME"), home)
}

/// Looks credentials up in the user's `.netrc`.
///
/// # Arguments
///
/// * `store` -- the per-handle cache. The file is read on the first call
///   and reused afterwards, and dropped again on any failure.
/// * `host` -- the host to look for, compared case-INsensitively. The C's
///   contract (`lib/netrc.h:54`) assumes it is not empty.
/// * `login` -- `None` to search for a login AND a password inside a
///   matching entry; `Some` to search for the password belonging to that
///   login, compared in constant time and CASE-SENSITIVELY. This is the
///   C's `specific_login`, and it is a presence test rather than an
///   emptiness test, so `Some(b"")` is a fixed, empty login.
/// * `netrcfile` -- an explicit path, as `CURLOPT_NETRC_FILE` and
///   `--netrc-file` supply, or `None` to run the cascade of
///   [`netrc_path_from`].
/// * `home` -- the injected home directory, consulted only when neither
///   environment variable answers.
///
/// The C also takes the password as an in-out pointer and asserts at
/// `lib/netrc.c:128` that it arrives empty. There is no such parameter
/// here, so that half of the contract is satisfied by construction rather
/// than by an assertion.
///
/// # Errors
///
/// * [`NetrcCode::NoMatch`] -- the file parsed and named no usable
///   credentials for this host. `lib/url.c:2613-2618` treats this as
///   ordinary and carries on with defaults.
/// * [`NetrcCode::FileMissing`] -- the file could not be opened, or no home
///   directory could be established.
/// * [`NetrcCode::SyntaxError`] -- the file does not parse, OR a ceiling
///   was crossed, OR the read failed. See [`curl2netrc`].
/// * [`NetrcCode::OutOfMemory`] -- a genuine allocation failure.
#[allow(dead_code)] // consumer: lib/url.c:2608's successor
pub(crate) fn parsenetrc(
    store: &mut StoreNetrc,
    host: &[u8],
    login: Option<&[u8]>,
    netrcfile: Option<&Path>,
    home: &dyn HomeDirectory,
) -> Result<Credentials, NetrcCode> {
    match netrcfile {
        // `lib/netrc.c:462-463`.
        Some(path) => parse_path(store, host, login, path),
        // `lib/netrc.c:399-461`.
        None => {
            let path = netrc_path(home)?;
            parse_path(store, host, login, &path)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::Cursor;

    use super::*;

    /// The fixture of `tests/data/test1304`, byte for byte.
    ///
    /// `lib/netrc.c:387` names `@unittest: 1304`, and the harness writes
    /// this file for it. Every assertion of `tests/unit/unit1304.c` below
    /// runs against exactly these two lines.
    const UNIT1304: &[u8] =
        b"machine example.com login admin password passwd\n\
         machine curl.example.com login none password none\n";

    /// Looks up credentials in an in-memory `.netrc`.
    ///
    /// Everything the parser does is reachable this way, which is what
    /// keeps the tests below runnable under Miri: no file is opened and no
    /// environment variable is read.
    fn lookup(
        text: &[u8],
        host: &[u8],
        login: Option<&[u8]>,
    ) -> Result<Credentials, NetrcCode> {
        let mut store = StoreNetrc::new();
        let mut input = Cursor::new(text.to_vec());
        parse_reader(&mut store, host, login, &mut input)
    }

    /// The short name of an outcome, as the differential transcript spells
    /// it.
    fn tag(code: NetrcCode) -> &'static str {
        match code {
            NetrcCode::Ok => "ok",
            NetrcCode::NoMatch => "nomatch",
            NetrcCode::SyntaxError => "syntax",
            NetrcCode::FileMissing => "missing",
            NetrcCode::OutOfMemory => "oom",
        }
    }

    /// One credential field, with everything unprintable escaped.
    ///
    /// Absent is `@`, which is why `@` itself is escaped: an empty string
    /// and an absent string are different answers here and the rendering
    /// may not confuse them.
    fn field(value: Option<&[u8]>) -> String {
        let Some(bytes) = value else {
            return String::from("@");
        };
        let mut out = String::with_capacity(bytes.len());
        for &byte in bytes {
            let plain =
                matches!(byte, 0x21..=0x7E) && byte != b'\\' && byte != b'@';
            if plain {
                out.push(char::from(byte));
            } else {
                out.push_str(&format!("\\x{byte:02x}"));
            }
        }
        out
    }

    /// One transcript record: outcome, login, password.
    ///
    /// The same three fields in the same order and the same escaping that
    /// the C driver behind [`C_ORACLE`] printed, so a Rust answer and a C
    /// answer are compared as text rather than by eye.
    fn render(outcome: &Result<Credentials, NetrcCode>) -> String {
        match outcome {
            Ok(found) => format!(
                "ok|{}|{}",
                field(found.found_login()),
                field(found.password())
            ),
            Err(code) => format!("{}|@|@", tag(*code)),
        }
    }

    /// The rendering of an in-memory lookup, for compact assertions.
    fn shape(text: &[u8], host: &[u8], login: Option<&[u8]>) -> String {
        render(&lookup(text, host, login))
    }

    // ---- the constants, measured against the C -------------------------

    /// The four ceilings and the two bits are the C's.
    ///
    /// Transcribed from `lib/netrc.c:59-64`. They are behaviour rather than
    /// tuning: the ceilings decide which files are refused, and the bits
    /// decide when the walk stops.
    #[test]
    fn the_limits_match_the_c_header() {
        assert_eq!(MAX_NETRC_LINE, 16384);
        assert_eq!(MAX_NETRC_FILE, 128 * 1024);
        assert_eq!(MAX_NETRC_TOKEN, 4096);
        assert_eq!(FOUND_LOGIN, 1);
        assert_eq!(FOUND_PASSWORD, 2);
        // The two bits are a mask and must not overlap, which is the whole
        // reason the C uses a mask instead of a counter -- the keywords may
        // arrive in either order.
        assert_eq!(FOUND_LOGIN & FOUND_PASSWORD, 0);
    }

    /// The five messages reach the user, so they are compared literally.
    #[test]
    fn strerror_returns_the_five_exact_strings() {
        assert_eq!(NetrcCode::Ok.strerror(), "");
        assert_eq!(NetrcCode::FileMissing.strerror(), "no such file");
        assert_eq!(NetrcCode::NoMatch.strerror(), "no matching entry");
        assert_eq!(NetrcCode::OutOfMemory.strerror(), "out of memory");
        assert_eq!(NetrcCode::SyntaxError.strerror(), "syntax error");
    }

    /// Only out-of-memory keeps its identity -- `lib/netrc.c:66-69`.
    ///
    /// The consequence a user sees is that a size-limit breach is reported
    /// as a syntax error, which is wart 1 of the module documentation.
    #[test]
    fn curl2netrc_maps_everything_except_out_of_memory_to_syntax() {
        assert_eq!(curl2netrc(CURLcode::OutOfMemory), NetrcCode::OutOfMemory);
        assert_eq!(curl2netrc(CURLcode::TooLarge), NetrcCode::SyntaxError);
        assert_eq!(curl2netrc(CURLcode::ReadError), NetrcCode::SyntaxError);
        assert_eq!(curl2netrc(CURLcode::Ok), NetrcCode::SyntaxError);
    }

    // ---- tests/unit/unit1304.c, relocated ------------------------------

    /// A host that is not in the file -- `tests/unit/unit1304.c:46-54`.
    ///
    /// The C asserts `result == 1`, which is `NETRC_NO_MATCH`, and that
    /// both output pointers are still null.
    #[test]
    fn unit1304_a_missing_host_with_no_login() {
        assert_eq!(shape(UNIT1304, b"test.example.com", None), "nomatch|@|@");
    }

    /// A login that is not in the file -- `tests/unit/unit1304.c:56-65`.
    #[test]
    fn unit1304_a_missing_login() {
        assert_eq!(shape(UNIT1304, b"example.com", Some(b"me")), "ok|@|@");
    }

    /// A missing login AND a missing host -- `tests/unit/unit1304.c:67-76`.
    #[test]
    fn unit1304_a_missing_login_and_host() {
        assert_eq!(
            shape(UNIT1304, b"test.example.com", Some(b"me")),
            "nomatch|@|@"
        );
    }

    /// A login that is a PREFIX of the stored one --
    /// `tests/unit/unit1304.c:78-88`.
    ///
    /// `Curl_timestrcmp` compares whole strings, so a prefix is not a
    /// match. The C spells the fixture login one letter short for exactly
    /// this, and carries a spell-checker suppression on it for exactly the
    /// reason the one below exists.
    #[test]
    fn unit1304_a_login_that_is_a_prefix_does_not_match() {
        let short = b"admi"; // spellchecker:disable-line
        assert_eq!(shape(UNIT1304, b"example.com", Some(short)), "ok|@|@");
    }

    /// A login that EXTENDS the stored one --
    /// `tests/unit/unit1304.c:90-100`.
    #[test]
    fn unit1304_a_login_that_is_an_extension_does_not_match() {
        assert_eq!(shape(UNIT1304, b"example.com", Some(b"adminn")), "ok|@|@");
    }

    /// The first entry, searched with no login fixed --
    /// `tests/unit/unit1304.c:102-133`.
    ///
    /// The C runs this case twice over a freshly initialised store and
    /// expects the same answer both times, so it is asserted twice here for
    /// the same reason.
    #[test]
    fn unit1304_the_first_host_with_no_login_fixed() {
        assert_eq!(shape(UNIT1304, b"example.com", None), "ok|admin|passwd");
        assert_eq!(shape(UNIT1304, b"example.com", None), "ok|admin|passwd");
    }

    /// The second entry, searched with no login fixed --
    /// `tests/unit/unit1304.c:135-167`.
    ///
    /// Reaching it means the walk crossed a line boundary by itself, which
    /// is wart 4 of the module documentation at work.
    #[test]
    fn unit1304_the_second_host_with_no_login_fixed() {
        assert_eq!(shape(UNIT1304, b"curl.example.com", None), "ok|none|none");
        assert_eq!(shape(UNIT1304, b"curl.example.com", None), "ok|none|none");
    }

    // ---- keyword order, `default`, and the blank password --------------

    /// The two keywords may arrive in either order.
    ///
    /// That is what the found bits of `lib/netrc.c:121-122` exist for, and
    /// its own comment says so: "as they can come in any order".
    #[test]
    fn either_keyword_order_yields_the_same_credentials() {
        let login_first = b"machine h login lena password pass\n";
        let password_first = b"machine h password pass login lena\n";
        assert_eq!(shape(login_first, b"h", None), "ok|lena|pass");
        assert_eq!(shape(password_first, b"h", None), "ok|lena|pass");
    }

    /// A `default` entry with credentials matches any host.
    ///
    /// `lib/netrc.c:249-252` turns the outcome successful at the keyword
    /// itself, before a credential has been read.
    #[test]
    fn a_default_entry_with_credentials_matches_anything() {
        let text = b"default login dora password dpass\n";
        assert_eq!(shape(text, b"anywhere.example", None), "ok|dora|dpass");
    }

    /// A bare `default` is a match with nothing to offer, so it is NOT one.
    ///
    /// `lib/netrc.c:348-350` overturns the success code the keyword set,
    /// with the comment "a default with no credentials".
    /// `tests/data/test486` pins the consequence: the second request of
    /// that fixture carries no authorization header at all.
    #[test]
    fn a_bare_default_is_no_match() {
        assert_eq!(
            shape(b"default\n", b"anywhere.example", None),
            "nomatch|@|@"
        );
    }

    /// A `default` BEFORE a matching machine loses to it.
    ///
    /// The machine keyword arrives while the state is `HOSTVALID`, so
    /// `lib/netrc.c:300-312` discards what the default supplied -- unless a
    /// password had already been found, which is the early exit tested
    /// separately below.
    #[test]
    fn a_default_before_a_matching_machine_is_superseded() {
        let text = b"default login dora\n\
             machine h login lena password pass\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|pass");
    }

    /// A `default` AFTER a matching machine wins, unless a password was
    /// already found.
    ///
    /// The first entry here names a login and no password, so no password
    /// bit is set, the walk carries on, and `lib/netrc.c:313-319` clears
    /// what the machine supplied.
    #[test]
    fn a_default_after_a_matching_machine_without_a_password_wins() {
        let text = b"machine h login lena\n\
             default login dora password dpass\n";
        assert_eq!(shape(text, b"h", None), "ok|dora|dpass");
    }

    /// Once a password is found, the next `machine` ends the walk.
    ///
    /// `lib/netrc.c:302-305`. The second entry is never looked at, so its
    /// credentials cannot overwrite the first entry's.
    #[test]
    fn a_found_password_stops_the_walk_at_the_next_machine() {
        let text = b"machine h password pass\n\
             machine h login other password otherpass\n";
        assert_eq!(shape(text, b"h", None), "ok|@|pass");
    }

    /// A matched login with no password keyword yields a BLANK password.
    ///
    /// `lib/netrc.c:342-347` -- "success without a password, set a blank
    /// one". `tests/data/test479` expects `Basic %b64[bob:]b64%` on the
    /// wire, so an absent password would be a different request.
    #[test]
    fn a_matching_login_without_a_password_yields_a_blank_one() {
        let text = b"machine h login lena\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|");
    }

    /// The blank-password rule needs `our_login`, not merely a match.
    ///
    /// A machine that matches and names no login at all leaves `our_login`
    /// false, so `lib/netrc.c:348` is reached instead and the answer is
    /// no match.
    #[test]
    fn a_matching_machine_with_no_credentials_at_all_is_no_match() {
        assert_eq!(shape(b"machine h\n", b"h", None), "nomatch|@|@");
    }

    // ---- the fixed-login search ----------------------------------------

    /// A fixed login must match exactly, and its case is significant.
    ///
    /// `lib/netrc.c:271-272` compares with `Curl_timestrcmp`, which is
    /// constant-time and CASE-SENSITIVE -- unlike the keyword and machine
    /// comparisons a few lines away. Four comparison policies coexist in
    /// this directory and this is the one that must never be relaxed.
    #[test]
    fn the_fixed_login_comparison_is_case_sensitive() {
        let text = b"machine h login Lena password pass\n\
             machine h login lena password lower\n";
        // The exact spelling reaches its own password.
        assert_eq!(shape(text, b"h", Some(b"lena")), "ok|@|lower");
        assert_eq!(shape(text, b"h", Some(b"Lena")), "ok|@|pass");
    }

    /// A fixed login does not take another login's password.
    ///
    /// Two entries for the same host, and only the matching one may
    /// contribute. `tests/data/test380` -- "pick netrc password based on
    /// username in URL" -- is the fixture form of this.
    #[test]
    fn a_fixed_login_does_not_take_another_logins_password() {
        let text = b"machine h login frankenstein password wrongone\n\
             machine h login mary password yram\n";
        assert_eq!(shape(text, b"h", Some(b"mary")), "ok|@|yram");
    }

    /// A fixed login is never handed back, even on success.
    ///
    /// `lib/netrc.c:354-355` assigns `*loginp` only when no login was
    /// fixed, so the caller keeps the one it passed. That is why the
    /// accessor is named after what the FILE found.
    #[test]
    fn a_fixed_login_is_not_reported_back() {
        let text = b"machine h login lena password pass\n";
        let outcome = lookup(text, b"h", Some(b"lena"));
        assert_eq!(render(&outcome), "ok|@|pass");
        match outcome {
            Ok(found) => {
                assert_eq!(found.found_login(), None);
                assert_eq!(found.password(), Some(&b"pass"[..]));
            }
            Err(code) => assert_eq!(tag(code), "ok"),
        }
    }

    /// A FIXED login is a presence test, not an emptiness test.
    ///
    /// `lib/netrc.c:118` computes `specific_login = !!login` from a
    /// POINTER, so an empty string is a fixed login that matches only an
    /// empty one. `Some(b"")` reproduces that degenerate case exactly, and
    /// the quoted empty token is the only way a file can satisfy it.
    #[test]
    fn an_empty_fixed_login_is_still_a_fixed_login() {
        // Two entries for one host: one with an empty login, one named.
        // Which password comes back is decided entirely by which of them
        // the fixed login matched, so the assertions discriminate.
        let both = b"machine h login \"\" password empty\n\
             machine h login lena password named\n";
        assert_eq!(shape(both, b"h", Some(b"")), "ok|@|empty");
        assert_eq!(shape(both, b"h", Some(b"lena")), "ok|@|named");

        // And an empty fixed login does not match a named one: the walk
        // finds no match for it, so nothing sets the password bit and the
        // answer is the wart named in the next test rather than a match.
        let named_only = b"machine h login lena password pass\n\
             machine other login x password y\n";
        assert_eq!(shape(named_only, b"h", Some(b"")), "ok|@|@");
    }

    /// A MISMATCHED login still yields a password at end of file.
    ///
    /// `tests/unit/unit1304.c:56-65` passes only because its fixture has a
    /// SECOND `machine` line, which is what clears the password there.
    #[test]
    fn a_mismatched_login_still_yields_a_password_at_end_of_file() {
        let one_entry = b"machine h login lena password pass\n";
        assert_eq!(shape(one_entry, b"h", Some(b"nobody")), "ok|@|pass");

        // A following entry boundary clears it, which is the unit1304 case.
        let two_entries = b"machine h login lena password pass\n\
             machine other login x password y\n";
        assert_eq!(shape(two_entries, b"h", Some(b"nobody")), "ok|@|@");
    }

    // ---- macro definitions ---------------------------------------------

    /// A macro body is skipped until a blank line.
    ///
    /// `lib/netrc.c:232-236` enters the state and `:148-151` leaves it. The
    /// body here contains all three keywords, and not one of them may be
    /// interpreted -- `docs/libcurl/opts/CURLOPT_NETRC.md` states that
    /// initialisation macros are ignored.
    /// `tests/data/test494` is the fixture form, and its body is indented
    /// with tabs, which is why the blank line has to be recognised AFTER
    /// blanks are passed.
    #[test]
    fn a_macro_body_is_skipped_until_a_blank_line() {
        let text = b"macdef testmacro\n\
             \tbin\n\
             \tcd default\n\
             \tcd login\n\
             \tput login.bin\n\
             \tcd password\n\
             \tput password.bin\n\
             \tquit\n\
             \n\
             machine h login lena password pass\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|pass");
    }

    /// A macro body ends at an indentation-only line.
    ///
    /// The blank line of the previous test is empty; this one holds spaces
    /// and a tab. `lib/netrc.c:88` strips them at LOAD time, so the stored
    /// line is exactly one line feed and the terminator test sees it.
    #[test]
    fn an_indentation_only_line_ends_a_macro_body() {
        let text = b"macdef m\n\
             machine decoy login nobody password nothing\n\
             \t   \n\
             machine h login lena password pass\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|pass");
    }

    /// A macro that is never terminated swallows the rest of the file.
    #[test]
    fn an_unterminated_macro_body_swallows_the_file() {
        let text = b"macdef m\n\
             machine h login lena password pass\n";
        assert_eq!(shape(text, b"h", None), "nomatch|@|@");
    }

    /// `macdef` is recognised without regard to case, like every keyword.
    #[test]
    fn the_macro_keyword_is_case_insensitive() {
        let text = b"MacDef m\n\
             machine decoy login nobody password nothing\n\
             \n\
             machine h login lena password pass\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|pass");
    }

    /// A carriage-return line is a SYNTAX ERROR, macro or not.
    #[test]
    fn a_carriage_return_line_is_a_syntax_error() {
        // As the terminator of a macro definition.
        let macro_form = b"macdef m\n\
             body\n\
             \r\n\
             machine h login lena password pass\n";
        assert_eq!(shape(macro_form, b"h", None), "syntax|@|@");

        // And with no macro anywhere in sight.
        let plain = b"machine h login lena password pass\n\
             \r\n\
             machine other login x password y\n";
        assert_eq!(shape(plain, b"h", Some(b"nobody")), "syntax|@|@");

        // A carriage return INSIDE a line merely ends the token, so a file
        // with no blank line survives its line endings.
        let no_blank_line = b"machine h\r\nlogin lena\r\npassword pass\r\n";
        assert_eq!(shape(no_blank_line, b"h", None), "ok|lena|pass");
    }

    // ---- comments -------------------------------------------------------

    /// A comment line is invisible to the tokeniser.
    ///
    /// `lib/netrc.c:87-90` drops it at LOAD time, so the machine name it
    /// mentions is never a token. `tests/data/test130`'s fixture relies on
    /// this: it comments out a `machine` line whose password would
    /// otherwise win.
    #[test]
    fn a_comment_line_is_invisible() {
        let text = b"# the following two lines were created while testing\n\
             # machine h login lena password commented\n\
             machine h login lena password passwd1\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|passwd1");
    }

    /// An INDENTED comment is still a comment.
    ///
    /// The marker is tested after blanks are passed (`lib/netrc.c:88-89`),
    /// so leading whitespace does not protect it.
    #[test]
    fn an_indented_comment_line_is_still_a_comment() {
        let text = b"   \t # machine h login nobody password nothing\n\
             machine h login lena password pass\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|pass");
    }

    /// A `#` after text is NOT a comment -- wart 2.
    ///
    /// The marker is only recognised at the first non-blank position, so
    /// anywhere else it is an ordinary token byte and lands in the value.
    #[test]
    fn a_hash_after_text_is_an_ordinary_token_byte() {
        let text = b"machine h login lena password pa#ss # not a comment\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|pa#ss");
    }

    /// A file of nothing but comments parses to nothing.
    ///
    /// The buffer is never appended to, so the C's `curlx_dyn_ptr` hands
    /// back a null pointer and its inner loop never runs. This crate's
    /// buffer is an empty slice instead, and the end-of-line test refuses
    /// it on the first iteration for the same net answer.
    #[test]
    fn a_file_of_only_comments_is_no_match() {
        assert_eq!(shape(b"# nothing here\n", b"h", None), "nomatch|@|@");
    }

    /// An empty file is no match.
    ///
    /// [`get_line`] synthesises a line feed at end of input, so the stored
    /// file is exactly one line feed rather than nothing at all.
    #[test]
    fn an_empty_file_is_no_match() {
        assert_eq!(shape(b"", b"h", None), "nomatch|@|@");
    }

    // ---- case folding ---------------------------------------------------

    /// Keywords are matched without regard to case -- `lib/netrc.c:232-299`.
    ///
    /// Every one of them goes through the body of `curl_strequal`.
    #[test]
    fn keywords_are_case_insensitive() {
        let text = b"MACHINE h LOGIN lena PASSWORD pass\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|pass");

        let mixed = b"Default LoGiN dora PassWord dpass\n";
        assert_eq!(shape(mixed, b"anything", None), "ok|dora|dpass");
    }

    /// Machine names are matched without regard to case --
    /// `lib/netrc.c:259`.
    #[test]
    fn machine_names_are_case_insensitive() {
        let text = b"machine ExAmPle.COM login lena password pass\n";
        assert_eq!(shape(text, b"example.com", None), "ok|lena|pass");
        assert_eq!(shape(text, b"EXAMPLE.com", None), "ok|lena|pass");
    }

    // ---- the signed-char token terminator, wart 3 -----------------------

    /// A byte from 0x80 upwards ends a bare token, exactly as a space does.
    #[test]
    fn a_byte_above_ascii_terminates_a_bare_token() {
        let text = b"machine h\xff login lena password pass\n";
        // The name as written in the file does not match ...
        assert_eq!(shape(text, b"h\xff", None), "nomatch|@|@");
        // ... but its ASCII prefix does, because that is the whole token.
        assert_eq!(shape(text, b"h", None), "ok|lena|pass");
    }

    /// Two adjacent high bytes make the whole file refuse to parse.
    #[test]
    fn two_adjacent_high_bytes_are_a_syntax_error() {
        let text = b"machine h\xc3\xa9 login lena password pass\n";
        assert_eq!(shape(text, b"h", None), "syntax|@|@");
    }

    /// A high byte inside a QUOTED token is kept.
    ///
    /// The quoted reader at `lib/netrc.c:182-215` stops only at the
    /// terminator, at a quote or at an escape, so quoting is the only way a
    /// `.netrc` can carry a name or a password outside ASCII.
    #[test]
    fn a_quoted_token_keeps_its_high_bytes() {
        let text = b"machine \"h\xc3\xa9\" login lena password \"p\xffs\"\n";
        assert_eq!(shape(text, b"h\xc3\xa9", None), "ok|lena|p\\xffs");
    }

    // ---- quoting --------------------------------------------------------

    /// A quoted token may hold blanks.
    ///
    /// That is the whole reason quoting exists: `lib/netrc.c:158` selects
    /// the quoted reader, which stops at a quote rather than at a space.
    #[test]
    fn a_quoted_token_may_hold_blanks() {
        let text = b"machine h login \"a b\" password \"p\tq\"\n";
        assert_eq!(shape(text, b"h", None), "ok|a\\x20b|p\\x09q");
    }

    /// The escape set is exactly three letters -- `lib/netrc.c:187-197`.
    ///
    /// `n`, `r` and `t` become their control characters. **Anything else
    /// escaped passes through unchanged**, so `\"` is a quote, `\\` is a
    /// backslash and `\z` is a plain `z` -- there is no octal form, no hex
    /// form and no other letter.
    #[test]
    fn the_escape_set_is_three_letters_wide() {
        // \n, \r and \t.
        let controls = b"machine h login \"a\\nb\" password \"c\\rd\\te\"\n";
        assert_eq!(shape(controls, b"h", None), "ok|a\\x0ab|c\\x0dd\\x09e");

        // An escaped quote is a quote and does not end the token.
        let quote = b"machine h login \"a\\\"b\" password pass\n";
        assert_eq!(shape(quote, b"h", None), "ok|a\"b|pass");

        // An escaped backslash is one backslash.
        let backslash = b"machine h login \"a\\\\b\" password pass\n";
        assert_eq!(shape(backslash, b"h", None), "ok|a\\x5cb|pass");

        // Any other escaped byte loses only its backslash.
        let other = b"machine h login \"a\\zb\" password \"\\0\"\n";
        assert_eq!(shape(other, b"h", None), "ok|azb|0");
    }

    /// An unterminated quote loses the WHOLE parse.
    ///
    /// `lib/netrc.c:216-220` jumps to the exit label rather than skipping
    /// the token, so credentials already found are discarded with it.
    #[test]
    fn an_unterminated_quote_is_a_syntax_error() {
        let text = b"machine h login lena password \"unclosed\n";
        assert_eq!(shape(text, b"h", None), "syntax|@|@");
    }

    /// A dangling escape is a syntax error too.
    ///
    /// The walk at `lib/netrc.c:182` ends at the terminator with the escape
    /// flag still set, and `:216` refuses that.
    #[test]
    fn a_dangling_escape_is_a_syntax_error() {
        // The backslash swallows the closing quote, so the token runs to
        // the end of the buffer and neither flag is satisfied.
        let swallowed = b"machine h login \"lena\\\"\n";
        assert_eq!(shape(swallowed, b"h", None), "syntax|@|@");
    }

    /// A quoted empty token is the empty string, never absent.
    ///
    /// `lib/netrc.c:223-228` says so in a comment: the token is set to
    /// blank "to avoid having to deal with it being NULL".
    #[test]
    fn a_quoted_empty_token_is_the_empty_string() {
        let text = b"machine h login lena password \"\"\n";
        assert_eq!(shape(text, b"h", None), "ok|lena|");
    }

    /// The byte after a closing quote is CONSUMED -- wart 4.
    ///
    /// `lib/netrc.c:326` steps over whatever ended the token, and for a
    /// quoted token that is the byte after the closing quote rather than a
    /// separator. So `"lena"password` yields `lena` and then `assword`, and
    /// the keyword is lost.
    #[test]
    fn the_byte_after_a_closing_quote_is_consumed() {
        // With a space after the quote, the space is what gets eaten and
        // nothing is lost.
        let spaced = b"machine h login \"lena\" password pass\n";
        assert_eq!(shape(spaced, b"h", None), "ok|lena|pass");

        // With no space, the first byte of the next word is eaten instead.
        // `assword` is not a keyword, so the value never arrives.
        let tight = b"machine h login \"lena\"password pass\n";
        assert_eq!(shape(tight, b"h", None), "ok|lena|");
    }

    // ---- the ceilings ---------------------------------------------------

    /// A line past `MAX_NETRC_LINE` is reported as a SYNTAX error.
    ///
    /// [`get_line`] refuses it with `CURLcode::TooLarge` and
    /// [`curl2netrc`] narrows that to a syntax error -- wart 1. Nothing
    /// anywhere tells the user it was about size.
    #[test]
    fn an_over_long_line_is_reported_as_a_syntax_error() {
        let mut text = Vec::with_capacity(MAX_NETRC_LINE + 64);
        text.extend_from_slice(b"machine ");
        text.resize(MAX_NETRC_LINE + 16, b'a');
        text.push(b'\n');
        assert_eq!(shape(&text, b"h", None), "syntax|@|@");
    }

    /// A token past `MAX_NETRC_TOKEN` is reported as a syntax error.
    ///
    /// The bare reader appends the whole span at once
    /// (`lib/netrc.c:172`), so the ceiling is crossed by that one append.
    #[test]
    fn an_over_long_token_is_reported_as_a_syntax_error() {
        let mut text = Vec::with_capacity(MAX_NETRC_TOKEN + 64);
        text.extend_from_slice(b"machine ");
        text.resize(MAX_NETRC_TOKEN + 16, b'a');
        text.push(b'\n');
        assert_eq!(shape(&text, b"h", None), "syntax|@|@");
    }

    /// A quoted token past the ceiling is refused one byte at a time.
    ///
    /// The quoted reader appends single bytes (`lib/netrc.c:209`), so the
    /// ceiling is crossed on the byte that would exceed it rather than on
    /// the whole span. The outcome is the same.
    #[test]
    fn an_over_long_quoted_token_is_reported_as_a_syntax_error() {
        let mut text = Vec::with_capacity(MAX_NETRC_TOKEN + 64);
        text.extend_from_slice(b"machine \"");
        text.resize(MAX_NETRC_TOKEN + 16, b'a');
        text.extend_from_slice(b"\"\n");
        assert_eq!(shape(&text, b"h", None), "syntax|@|@");
    }

    /// The whole-file ceiling refuses the load, and it is the buffer's.
    ///
    /// Driving [`file2memory`] with a deliberately tiny ceiling exercises
    /// exactly the append that `MAX_NETRC_FILE` guards, without building a
    /// 128-kilobyte fixture. The buffer is emptied on refusal, as
    /// `lib/netrc.c:94` requires.
    #[test]
    fn the_file_ceiling_refuses_the_load_and_empties_the_buffer() {
        let mut small = DynBuf::new(8);
        let mut input = Cursor::new(b"machine h login lena\n".to_vec());
        assert_eq!(
            file2memory(&mut input, &mut small),
            Err(NetrcCode::SyntaxError)
        );
        assert!(small.as_slice().is_empty());
    }

    /// And the real ceiling refuses a real file of that size.
    ///
    /// Ignored under Miri only because the input is read one byte at a time
    /// by [`get_line`], so 132 kilobytes is 132 thousand interpreted reads
    /// for one assertion. The cheap form above covers the same code path.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "132 kB read one byte at a time is needlessly slow here"
    )]
    fn a_file_past_the_whole_file_ceiling_is_a_syntax_error() {
        let line: &[u8] = b"machine nomatch.example login a password b\n";
        let repeats = MAX_NETRC_FILE / line.len() + 2;
        let mut text = Vec::with_capacity(repeats * line.len());
        for _ in 0..repeats {
            text.extend_from_slice(line);
        }
        assert!(text.len() > MAX_NETRC_FILE);
        assert_eq!(shape(&text, b"h", None), "syntax|@|@");
    }

    /// An embedded zero byte truncates its line -- [`get_line`]'s own wart.
    #[test]
    fn an_embedded_zero_byte_truncates_its_line() {
        let text = b"machine h login le\0na\npassword pass\n";
        assert_eq!(shape(text, b"h", None), "ok|lepassword|");
    }

    // ---- the store's caching and its reset ------------------------------

    /// A successful lookup leaves the file cached.
    ///
    /// The second lookup below is handed an EMPTY reader and still answers,
    /// which is only possible if the reader was never consulted --
    /// `lib/netrc.c:131-136` guards the load on the flag.
    #[test]
    fn a_successful_lookup_caches_the_file() {
        let mut store = StoreNetrc::new();
        assert!(!store.is_loaded());

        let mut first = Cursor::new(UNIT1304.to_vec());
        let one = parse_reader(&mut store, b"example.com", None, &mut first);
        assert_eq!(render(&one), "ok|admin|passwd");
        assert!(store.is_loaded());

        let mut nothing = Cursor::new(Vec::new());
        let two =
            parse_reader(&mut store, b"curl.example.com", None, &mut nothing);
        assert_eq!(render(&two), "ok|none|none");
        assert!(store.is_loaded());
    }

    /// ANY failure drops the cache, a plain no-match included.
    ///
    /// `lib/netrc.c:358-364` frees the buffer and clears the flag for every
    /// non-success outcome. So the second lookup below really does read its
    /// reader, and being handed an empty one it finds nothing.
    #[test]
    fn a_no_match_resets_the_store() {
        let mut store = StoreNetrc::new();

        let mut first = Cursor::new(UNIT1304.to_vec());
        let one = parse_reader(&mut store, b"absent.example", None, &mut first);
        assert_eq!(render(&one), "nomatch|@|@");
        assert!(!store.is_loaded());

        let mut nothing = Cursor::new(Vec::new());
        let two = parse_reader(&mut store, b"example.com", None, &mut nothing);
        assert_eq!(render(&two), "nomatch|@|@");
    }

    /// A syntax error drops the cache too.
    #[test]
    fn a_syntax_error_resets_the_store() {
        let mut store = StoreNetrc::new();
        let mut input = Cursor::new(b"machine h login \"open\n".to_vec());
        let outcome = parse_reader(&mut store, b"h", None, &mut input);
        assert_eq!(render(&outcome), "syntax|@|@");
        assert!(!store.is_loaded());
    }

    /// Cleaning up empties the store and leaves it usable.
    ///
    /// `lib/netrc.c:472-476` frees the buffer and clears the flag without
    /// destroying either, so a later lookup reads the file again.
    #[test]
    fn cleanup_empties_the_store_and_leaves_it_usable() {
        let mut store = StoreNetrc::new();
        let mut first = Cursor::new(UNIT1304.to_vec());
        let one = parse_reader(&mut store, b"example.com", None, &mut first);
        assert_eq!(render(&one), "ok|admin|passwd");

        store.cleanup();
        assert!(!store.is_loaded());

        let mut second = Cursor::new(UNIT1304.to_vec());
        let two = parse_reader(&mut store, b"example.com", None, &mut second);
        assert_eq!(render(&two), "ok|admin|passwd");
    }

    /// A default-constructed store is a new one.
    #[test]
    fn the_default_store_is_the_new_one() {
        let store = StoreNetrc::default();
        assert!(!store.is_loaded());
        assert_eq!(format!("{store:?}"), format!("{:?}", StoreNetrc::new()));
    }

    // ---- the file-location cascade --------------------------------------

    /// A home-directory provider that records how often it was asked.
    struct CountingHome {
        answer: Option<PathBuf>,
        asked: Cell<usize>,
    }

    impl CountingHome {
        fn new(answer: Option<&str>) -> Self {
            Self {
                answer: answer.map(PathBuf::from),
                asked: Cell::new(0),
            }
        }
    }

    impl HomeDirectory for CountingHome {
        fn home_directory(&self) -> Option<PathBuf> {
            self.asked.set(self.asked.get().saturating_add(1));
            self.answer.clone()
        }
    }

    /// The environment variable is used as the WHOLE path.
    ///
    /// `lib/netrc.c:405-406` bypasses the home directory entirely, so no
    /// name is appended and the provider is never consulted -- not even
    /// when the home variable also has a value.
    #[test]
    fn the_netrc_variable_is_the_whole_path() {
        let home = CountingHome::new(Some("/from/provider"));
        let path = netrc_path_from(
            Some(OsString::from("/tmp/somewhere/else")),
            Some(OsString::from("/home/user")),
            &home,
        );
        assert_eq!(path, Ok(PathBuf::from("/tmp/somewhere/else")));
        assert_eq!(home.asked.get(), 0);
    }

    /// Otherwise the home variable, with the name appended.
    #[test]
    fn the_home_variable_supplies_the_directory() {
        let home = CountingHome::new(Some("/from/provider"));
        let path =
            netrc_path_from(None, Some(OsString::from("/home/user")), &home);
        assert_eq!(path, Ok(PathBuf::from("/home/user/.netrc")));
        assert_eq!(home.asked.get(), 0);
    }

    /// Only then is the provider consulted, and exactly once.
    ///
    /// This is the injected step that stands in for the password-database
    /// lookup of `lib/netrc.c:410-425`, and the ordering is why the trait
    /// method is lazy rather than a value.
    #[test]
    fn the_provider_is_consulted_only_when_both_variables_are_absent() {
        let home = CountingHome::new(Some("/from/provider"));
        let path = netrc_path_from(None, None, &home);
        assert_eq!(path, Ok(PathBuf::from("/from/provider/.netrc")));
        assert_eq!(home.asked.get(), 1);
    }

    /// With no home at all there is no file -- `lib/netrc.c:436-438`.
    #[test]
    fn no_home_at_all_reports_that_the_file_is_missing() {
        let home = CountingHome::new(None);
        assert_eq!(
            netrc_path_from(None, None, &home),
            Err(NetrcCode::FileMissing)
        );
        assert_eq!(home.asked.get(), 1);
    }

    /// The join is a BYTE concatenation, not a path operation.
    ///
    /// `lib/netrc.c:440` formats `"%s%s.netrc"` with a literal separator,
    /// so a home of `"/"` really does produce a doubled separator and a
    /// relative home keeps its own shape. [`PathBuf::push`] would normalise
    /// both away, which is why the bytes are assembled directly.
    #[test]
    fn the_path_join_is_a_byte_concatenation() {
        let home = CountingHome::new(None);

        let root = netrc_path_from(None, Some(OsString::from("/")), &home);
        assert_eq!(root, Ok(PathBuf::from("//.netrc")));

        let relative =
            netrc_path_from(None, Some(OsString::from("rel")), &home);
        assert_eq!(relative, Ok(PathBuf::from("rel/.netrc")));

        // A trailing separator in the value is not removed either.
        let trailing =
            netrc_path_from(None, Some(OsString::from("/home/user/")), &home);
        assert_eq!(trailing, Ok(PathBuf::from("/home/user//.netrc")));
    }

    /// `Option<PathBuf>` is itself a provider.
    ///
    /// The eager form, for a caller that has already asked the operating
    /// system. Both cases are covered because both occur.
    #[test]
    fn an_optional_path_is_a_home_directory_provider() {
        let known: Option<PathBuf> = Some(PathBuf::from("/eager"));
        assert_eq!(
            netrc_path_from(None, None, &known),
            Ok(PathBuf::from("/eager/.netrc"))
        );

        let unknown: Option<PathBuf> = None;
        assert_eq!(
            netrc_path_from(None, None, &unknown),
            Err(NetrcCode::FileMissing)
        );
    }

    /// An EMPTY variable counts as absent -- `lib/getenv.c:66`.
    ///
    /// `curl_getenv` returns a null pointer for `env[0] == 0`, which
    /// `std::env::var_os` does not, so the rule is applied explicitly. It
    /// matters twice: an empty `NETRC` must not name the empty path, and an
    /// empty `HOME` must not build `"/.netrc"`.
    #[test]
    fn an_empty_environment_value_counts_as_absent() {
        assert!(!nonempty(&OsString::from("")));
        assert!(nonempty(&OsString::from("x")));
        assert!(nonempty(&OsString::from("/")));
    }

    /// A variable that is not set reads as absent.
    ///
    /// Read-only, so it is sound beside every other test in this binary --
    /// setting a variable would not be.
    #[test]
    fn an_unset_variable_reads_as_absent() {
        assert_eq!(getenv("CURL_RS_NETRC_TEST_UNSET_VARIABLE"), None);
    }

    // ---- secrets ---------------------------------------------------------

    /// A password never reaches formatted output.
    ///
    /// The whole reason [`Credentials`] writes its own formatting
    /// implementation. A derived one would print the buffer, and this test
    /// is what stops somebody replacing it with a derive later: the
    /// assertion fails the moment the bytes appear.
    #[test]
    fn the_debug_output_never_carries_the_password() {
        // Obviously fake, and shaped so that it cannot match any provider's
        // credential pattern.
        let secret = "PLACEHOLDER-not-a-real-password";
        let mut text = Vec::new();
        text.extend_from_slice(b"machine h login lena password ");
        text.extend_from_slice(secret.as_bytes());
        text.push(b'\n');

        let outcome = lookup(&text, b"h", None);
        // The parse really did find it, so the assertions below are not
        // passing because there was nothing to leak.
        assert_eq!(
            outcome.as_ref().ok().and_then(Credentials::password),
            Some(secret.as_bytes())
        );

        let rendered = format!("{outcome:?}");
        assert!(
            !rendered.contains(secret),
            "the password reached formatted output: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        // The login is not a secret -- curl accepts it on the command line
        // and puts it in a URL -- so it is rendered, which also proves the
        // implementation is running rather than printing nothing.
        assert!(rendered.contains("lena"), "{rendered}");
    }

    /// An absent password is distinguishable from a present one, without
    /// revealing either.
    #[test]
    fn the_debug_output_distinguishes_absent_from_present() {
        let absent = Credentials {
            found_login: None,
            password: None,
        };
        assert!(format!("{absent:?}").contains("<absent>"));

        let present = Credentials {
            found_login: None,
            password: Some(Vec::new()),
        };
        // Even an EMPTY password is reported as redacted rather than as
        // absent, because the two are different answers.
        assert!(format!("{present:?}").contains("<redacted>"));
    }

    /// The store's formatting reports its size and never its contents.
    ///
    /// The buffer holds every password in the file, so a derived
    /// implementation here would be the larger leak of the two.
    #[test]
    fn the_store_debug_output_never_carries_the_file() {
        let secret = "PLACEHOLDER-not-a-real-password";
        let mut text = Vec::new();
        text.extend_from_slice(b"machine h login lena password ");
        text.extend_from_slice(secret.as_bytes());
        text.push(b'\n');

        let mut store = StoreNetrc::new();
        let mut input = Cursor::new(text.clone());
        let outcome = parse_reader(&mut store, b"h", None, &mut input);
        assert_eq!(render(&outcome), format!("ok|lena|{secret}"));

        let rendered = format!("{store:?}");
        assert!(!rendered.contains(secret), "{rendered}");
        assert!(!rendered.contains("lena"), "{rendered}");
        assert!(rendered.contains("loaded: true"), "{rendered}");
        // ONE byte more than the input, and the extra one is not a mistake:
        // [`get_line`] synthesises a line feed at end of input, so the last
        // call contributes a line holding just that and `file2memory`
        // appends it like any other. The count is asserted rather than
        // waved at, because it is the only place the synthesised line is
        // observable from outside the loader.
        assert!(
            rendered.contains(&format!("bytes: {}", text.len() + 1)),
            "{rendered}"
        );
    }

    /// The loader appends one synthesised line feed at end of input.
    #[test]
    fn the_loader_appends_one_synthesised_line_feed() {
        let mut buf = DynBuf::new(MAX_NETRC_FILE);
        let mut input = Cursor::new(b"machine h\n".to_vec());
        assert_eq!(file2memory(&mut input, &mut buf), Ok(()));
        assert_eq!(buf.as_slice(), b"machine h\n\n");

        // Without a trailing line feed the input gains one, and there is no
        // second synthesised line: the same call that read the last bytes
        // already reported the end.
        let mut ragged = DynBuf::new(MAX_NETRC_FILE);
        let mut short = Cursor::new(b"machine h".to_vec());
        assert_eq!(file2memory(&mut short, &mut ragged), Ok(()));
        assert_eq!(ragged.as_slice(), b"machine h\n");

        // An empty file is one synthesised line and nothing else.
        let mut empty = DynBuf::new(MAX_NETRC_FILE);
        let mut nothing = Cursor::new(Vec::new());
        assert_eq!(file2memory(&mut nothing, &mut empty), Ok(()));
        assert_eq!(empty.as_slice(), b"\n");
    }

    /// Leading blanks are stripped from every stored line, not only from
    /// comments.
    #[test]
    fn the_loader_strips_leading_blanks_from_every_line() {
        let mut buf = DynBuf::new(MAX_NETRC_FILE);
        let mut input = Cursor::new(
            b"  machine h\n\t  login lena\n \t \n# gone\n".to_vec(),
        );
        assert_eq!(file2memory(&mut input, &mut buf), Ok(()));
        assert_eq!(buf.as_slice(), b"machine h\nlogin lena\n\n\n");
    }

    /// This module makes no logging call at all.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn this_module_makes_no_logging_call() {
        const EMITTERS: [&str; 10] = [
            "trace", "debug", "info", "warn", "error", "log", "event", "span",
            "println", "eprintln",
        ];

        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("cookies")
            .join("netrc.rs");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            text.len() > 1024,
            "the gate must read {} and did not",
            path.display()
        );

        for (index, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for name in EMITTERS {
                let needle = format!("{name}!(");
                assert!(
                    !code.contains(&needle),
                    "{}:{} makes a {needle} call",
                    path.display(),
                    index + 1
                );
            }
        }
    }

    // ---- the fixture corpus ---------------------------------------------

    /// `tests/data/test130` -- a commented-out entry and a trailing default.
    ///
    /// Three questions off one fixture: the first login wins with no login
    /// fixed, a fixed login reaches its own entry, and an unrelated host
    /// falls through to the default.
    #[test]
    fn fixture_test130() {
        let text =
            b"# the following two lines were created while testing curl\n\
             # machine 127.0.0.1 login user1 password commented\n\
             machine 127.0.0.1 login user1 password passwd1\n\
             machine 127.0.0.1 login user2 password passwd2\n\
             default login userdef password passwddef\n";

        assert_eq!(shape(text, b"127.0.0.1", None), "ok|user1|passwd1");
        assert_eq!(shape(text, b"127.0.0.1", Some(b"user2")), "ok|@|passwd2");
        assert_eq!(shape(text, b"other.example", None), "ok|userdef|passwddef");
    }

    /// `tests/data/test380` -- pick the password from the login in the URL.
    #[test]
    fn fixture_test380() {
        let text =
            b"# the following two lines were created while testing curl\n\
             machine 127.0.0.1 login frankenstein password wrongone\n\
             machine 127.0.0.1 login mary password yram\n";
        assert_eq!(shape(text, b"127.0.0.1", Some(b"mary")), "ok|@|yram");
        assert_eq!(
            shape(text, b"127.0.0.1", Some(b"frankenstein")),
            "ok|@|wrongone"
        );
    }

    /// `tests/data/test478` -- several accounts for one host.
    ///
    /// The hardest fixture in the corpus for this module, and it exercises
    /// four separate behaviours at once: a leading blank line, two
    /// `password` keywords before a `login`, an entry with no credentials at
    /// all, and `our_login` surviving a `machine` boundary because
    /// `lib/netrc.c:300-312` does not reset it. The harness expects
    /// `Authorization: Basic %b64[debbie:second%0D]b64%` on the wire, so the
    /// password ends in a carriage return.
    #[test]
    fn fixture_test478() {
        let text = b"\n\
             machine github.com\n\
             password weird\n\
             password firstone\n\
             login daniel\n\
             \n\
             machine github.com\n\
             \n\
             machine github.com\n\
             login debbie\n\
             \n\
             machine github.com\n\
             password weird\n\
             password \"second\\r\"\n\
             login debbie\n\
             \n";
        assert_eq!(
            shape(text, b"github.com", Some(b"debbie")),
            "ok|@|second\\x0d"
        );
    }

    /// `tests/data/test479` -- a redirect onto a default without a password.
    ///
    /// The second host takes the default, which names a login and no
    /// password, so the blank-password rule of `lib/netrc.c:342-347`
    /// applies and the request carries `Basic %b64[bob:]b64%`.
    #[test]
    fn fixture_test479() {
        let text = b"\n\
             machine a.com\n\
             login alice\n\
             password alicespassword\n\
             \n\
             default\n\
             login bob\n\
             \n";
        assert_eq!(shape(text, b"a.com", None), "ok|alice|alicespassword");
        assert_eq!(shape(text, b"b.com", None), "ok|bob|");
    }

    /// `tests/data/test480` -- control codes survive this module.
    ///
    /// The fixture is named "Reject .netrc with credentials using CRLF",
    /// and the rejection is NOT here: `lib/url.c:2626-2632` checks the
    /// credentials for control codes once this module has produced them,
    /// and fails the transfer with `CURLE_READ_ERROR`. This module's job is
    /// to report what the file said, so the carriage return and the line
    /// feed come through intact.
    #[test]
    fn fixture_test480() {
        let text = b"machine 127.0.0.1\n\
             login alice\n\
             password \"password\\r\\ncommand\"\n";
        assert_eq!(
            shape(text, b"127.0.0.1", None),
            "ok|alice|password\\x0d\\x0acommand"
        );
    }

    /// `tests/data/test486` -- a default with neither a login nor a
    /// password.
    ///
    /// The keyword sets the success code and `lib/netrc.c:348-350` takes it
    /// back again, so the redirected request carries no authorization
    /// header at all.
    #[test]
    fn fixture_test486() {
        let text = b"\n\
             machine a.com\n\
             login alice\n\
             password alicespassword\n\
             \n\
             default\n\
             \n";
        assert_eq!(shape(text, b"a.com", None), "ok|alice|alicespassword");
        assert_eq!(shape(text, b"b.com", None), "nomatch|@|@");
    }

    /// `tests/data/test494` -- skip a macro when parsing.
    ///
    /// The body is indented with tabs and mentions `default`, `login` and
    /// `password`, none of which may be interpreted.
    #[test]
    fn fixture_test494() {
        let text = b"\n\
             macdef testmacro\n\
             \tbin\n\
             \tcd default\n\
             \tcd login\n\
             \tput login.bin\n\
             \tcd ..\n\
             \tcd password\n\
             \tput password.bin\n\
             \tquit\n\
             \n\
             machine 127.0.0.1 login user1 password passwd1\n";
        assert_eq!(shape(text, b"127.0.0.1", None), "ok|user1|passwd1");
    }

    // ---- the filesystem, separately gated -------------------------------
    //
    // Every test above runs entirely in memory, which is what makes them
    // runnable under Miri. The four below genuinely need a file on disk, so
    // they are grouped here and each carries the ignore attribute that keeps
    // the interpreter out of the operating system.

    /// A file that is not there reports that it is not there.
    ///
    /// `lib/netrc.c:73` seeds the return value with that code precisely so
    /// that a failed open falls out carrying it.
    #[test]
    #[cfg_attr(miri, ignore = "this touches the filesystem")]
    fn a_missing_file_reports_that_it_is_missing() {
        let created = tempfile::tempdir();
        assert!(created.is_ok(), "a temporary directory must be creatable");
        if let Ok(dir) = created {
            let absent = dir.path().join("there-is-no-netrc-here");
            let mut store = StoreNetrc::new();
            let home: Option<PathBuf> = None;
            let outcome =
                parsenetrc(&mut store, b"h", None, Some(&absent), &home);
            assert_eq!(render(&outcome), "missing|@|@");
            assert!(!store.is_loaded());
        }
    }

    /// A file on disk parses exactly as the same bytes in memory do.
    #[test]
    #[cfg_attr(miri, ignore = "this touches the filesystem")]
    fn a_file_on_disk_parses_like_one_in_memory() {
        let created = tempfile::tempdir();
        assert!(created.is_ok(), "a temporary directory must be creatable");
        if let Ok(dir) = created {
            let path = dir.path().join("netrc");
            assert!(std::fs::write(&path, UNIT1304).is_ok());

            let mut store = StoreNetrc::new();
            let home: Option<PathBuf> = None;
            let outcome = parsenetrc(
                &mut store,
                b"curl.example.com",
                None,
                Some(&path),
                &home,
            );
            assert_eq!(render(&outcome), "ok|none|none");
            assert_eq!(
                render(&outcome),
                shape(UNIT1304, b"curl.example.com", None)
            );
        }
    }

    /// The file is opened once per store, proven by deleting it.
    ///
    /// The second lookup succeeds against a path that no longer exists,
    /// which only the cache can explain. Cleaning the store then makes the
    /// third lookup reach the filesystem again and fail.
    #[test]
    #[cfg_attr(miri, ignore = "this touches the filesystem")]
    fn the_file_is_opened_once_per_store() {
        let created = tempfile::tempdir();
        assert!(created.is_ok(), "a temporary directory must be creatable");
        if let Ok(dir) = created {
            let path = dir.path().join("netrc");
            assert!(std::fs::write(&path, UNIT1304).is_ok());

            let mut store = StoreNetrc::new();
            let home: Option<PathBuf> = None;
            let one = parsenetrc(
                &mut store,
                b"example.com",
                None,
                Some(&path),
                &home,
            );
            assert_eq!(render(&one), "ok|admin|passwd");

            assert!(std::fs::remove_file(&path).is_ok());
            let two = parsenetrc(
                &mut store,
                b"curl.example.com",
                None,
                Some(&path),
                &home,
            );
            assert_eq!(render(&two), "ok|none|none");

            store.cleanup();
            let three = parsenetrc(
                &mut store,
                b"example.com",
                None,
                Some(&path),
                &home,
            );
            assert_eq!(render(&three), "missing|@|@");
        }
    }

    /// A directory where a file was expected does not hang.
    #[test]
    #[cfg_attr(miri, ignore = "this touches the filesystem")]
    fn a_directory_in_place_of_a_file_terminates() {
        let created = tempfile::tempdir();
        assert!(created.is_ok(), "a temporary directory must be creatable");
        if let Ok(dir) = created {
            let mut store = StoreNetrc::new();
            let home: Option<PathBuf> = None;
            let outcome =
                parsenetrc(&mut store, b"h", None, Some(dir.path()), &home);
            let rendered = render(&outcome);
            assert!(
                rendered == "syntax|@|@" || rendered == "missing|@|@",
                "unexpected outcome for a directory: {rendered}"
            );
            assert!(!store.is_loaded());
        }
    }

    /// The cascade branch feeds the same parser the explicit branch does.
    #[test]
    #[cfg_attr(miri, ignore = "this reads the environment and the filesystem")]
    fn the_cascade_branch_agrees_with_the_explicit_branch() {
        let home: Option<PathBuf> = None;

        let mut via_cascade = StoreNetrc::new();
        let cascade = parsenetrc(&mut via_cascade, b"h", None, None, &home);

        match netrc_path(&home) {
            Ok(path) => {
                let mut direct = StoreNetrc::new();
                let explicit =
                    parsenetrc(&mut direct, b"h", None, Some(&path), &home);
                assert_eq!(render(&cascade), render(&explicit));
            }
            Err(code) => {
                assert_eq!(render(&cascade), format!("{}|@|@", tag(code)))
            }
        }
    }

    // ---- the differential oracle ----------------------------------------
    //
    // HOW THE TRANSCRIPT WAS PRODUCED, so the numbers are auditable rather
    // than magical. A C driver was built whose only content besides a shim
    // of type definitions and allocator macros was copied VERBATIM out of
    // this repository, unedited:
    //
    //   lib/netrc.c:44-384        the enums, the ceilings, `curl2netrc`,
    //                             `file2memory`, `parsenetrc` and
    //                             `Curl_netrc_strerror`
    //   lib/netrc.c:392-476       `Curl_parsenetrc` and the init/cleanup pair
    //   lib/netrc.h:32-45         `store_netrc` and `NETRCcode`
    //   lib/curl_get_line.c:35-65 `Curl_get_line`
    //   lib/curlx/dynbuf.c:67-182 `dyn_nappend`, `curlx_dyn_reset`,
    //                             `curlx_dyn_addn`, `curlx_dyn_add`
    //   lib/curlx/strparse.c:300-304  `curlx_str_passblanks`
    //   lib/strcase.c:28-84,130-146   both folding tables, `Curl_raw_toupper`
    //                             / `_tolower` and `Curl_timestrcmp`
    //   lib/strequal.c:35-49,76-84    `casecompare` and `curl_strequal`
    //
    // The one hand-written substitution is recorded rather than hidden: the
    // home-directory cascade of `lib/netrc.c:399-461` was replaced by an
    // immediate return, because it needs `curl_getenv`, the password
    // database and `curl_maprintf`. The driver always passes an explicit
    // file, so only the `lib/netrc.c:462-463` branch is reachable and that
    // branch is byte-identical. The cascade is covered separately and
    // purely by the four tests around `netrc_path_from`.

    const ORACLE_CORPUS: [&[u8]; 43] = [
        b"",
        b"\x0a",
        b"# only a comment\x0a",
        b"machine h login lena password pass\x0a",
        b"machine h password pass login lena\x0a",
        b"machine h login lena\x0a",
        b"machine h password pass\x0a",
        b"machine h\x0a",
        b"default\x0a",
        b"default login dora password dpass\x0a",
        b"machine h login lena password pass\x0a\
          machine other login x password y\x0a",
        b"machine example.com login admin password passwd\x0a\
          machine curl.example.com login none password none\x0a",
        b"\x0amachine github.com\x0apassword weird\x0a\
          password firstone\x0alogin daniel\x0a\x0amachine github.com\x0a\
          \x0amachine github.com\x0alogin debbie\x0a\x0a\
          machine github.com\x0apassword weird\x0a\
          password \"second\\r\"\x0alogin debbie\x0a\x0a",
        b"\x0amachine a.com\x0alogin alice\x0apassword alicespassword\x0a\
          \x0adefault\x0alogin bob\x0a\x0a",
        b"\x0amachine a.com\x0alogin alice\x0apassword alicespassword\x0a\
          \x0adefault\x0a\x0a",
        b"\x0amacdef testmacro\x0a\x09bin\x0a\x09cd default\x0a\
          \x09cd login\x0a\x09put login.bin\x0a\x09cd ..\x0a\
          \x09cd password\x0a\x09put password.bin\x0a\x09quit\x0a\x0a\
          machine 127.0.0.1 login user1 password passwd1\x0a",
        b"# the following two lines were created while testing curl\x0a\
          # machine h login user1 password commented\x0a\
          machine h login user1 password passwd1\x0a\
          machine h login user2 password passwd2\x0a\
          default login userdef password passwddef\x0a",
        b"MACHINE H LOGIN lena PASSWORD pass\x0a",
        b"machine h login \"a b\" password \"p\x09q\"\x0a",
        b"machine h login \"a\\nb\" password \"c\\rd\\te\"\x0a",
        b"machine h login \"a\\\"b\" password \"a\\\\b\"\x0a",
        b"machine h login \"lena\"password pass\x0a",
        b"machine h login \"unclosed\x0a",
        b"machine h login \"lena\\\"\x0a",
        b"machine h\x0d\x0alogin lena\x0d\x0apassword pass\x0d\x0a",
        b"machine h login lena password pass\x0a\x0d\x0amachine other\x0a",
        b"macdef m\x0abody\x0a\x0amachine h login lena password pass\x0a",
        b"macdef m\x0amachine h login nobody password nothing\x0a\x0a\
          machine h login lena password pass\x0a",
        b"macdef m\x0amachine h login lena password pass\x0a",
        b"machine h\xff login lena password pass\x0a",
        b"machine h\xc3\xa9 login lena password pass\x0a",
        b"machine \"h\xc3\xa9\" login lena password \"p\xffs\"\x0a",
        b"machine h login lena password pa#ss # not a comment\x0a",
        b"   \x09 # machine h login nobody password nothing\x0a\
          machine h login lena password pass\x0a",
        b"machine h login \"\" password pass\x0a",
        b"machine h login \"\" password empty\x0a\
          machine h login lena password named\x0a",
        b"machine h login lena password \"\"\x0a",
        b"machine h login le\x00na\x0apassword pass\x0a",
        b"machine h\x0a  login lena\x0a  password pass\x0a",
        b"machine h login lena password \"a\\zb\"\x0a",
        b"default login dora password dpass\x0a\
          machine h login lena password pass\x0a",
        b"machine h login lena\x0adefault login dora password dpass\x0a",
        b"machine h password pass\x0a\
          machine h login other password otherpass\x0a",
    ];

    const ORACLE_QUERIES: [(&[u8], Option<&[u8]>); 13] = [
        (b"h", None),
        (b"h", Some(b"lena")),
        (b"h", Some(b"nobody")),
        (b"h", Some(b"")),
        (b"h", Some(b"user2")),
        (b"example.com", None),
        (b"curl.example.com", None),
        (b"github.com", Some(b"debbie")),
        (b"a.com", None),
        (b"b.com", None),
        (b"127.0.0.1", None),
        (b"H", None),
        (b"h\xc3\xa9", None),
    ];

    const ORACLE_CORPUS_BYTES: usize = 2234;
    const ORACLE_CORPUS_CHECKSUM: u32 = 202736;
    // records = 559

    const C_ORACLE: &str = concat!(
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|lena|pass\n",
        "ok|@|pass\nok|@|pass\nok|@|pass\nok|@|pass\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|lena|pass\nnomatch|@|@\nok|lena|pass\nok|@|pass\nok|@|pass\n",
        "ok|@|pass\nok|@|pass\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|lena|pass\nnomatch|@|@\n",
        "ok|lena|\nok|@|\nok|@|@\nok|@|@\nok|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|lena|\nnomatch|@|@\nok|@|pass\nok|@|pass\nok|@|pass\n",
        "ok|@|pass\nok|@|pass\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|@|pass\nnomatch|@|@\n",
        "nomatch|@|@\nok|@|@\nok|@|@\nok|@|@\nok|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|@|@\nok|@|@\nok|@|@\n",
        "ok|@|@\nnomatch|@|@\nnomatch|@|@\nok|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|dora|dpass\nok|@|dpass\nok|@|dpass\nok|@|dpass\nok|@|dpass\n",
        "ok|dora|dpass\nok|dora|dpass\nok|@|dpass\nok|dora|dpass\n",
        "ok|dora|dpass\nok|dora|dpass\nok|dora|dpass\nok|dora|dpass\n",
        "ok|lena|pass\nok|@|pass\nok|@|@\nok|@|@\nok|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|lena|pass\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nok|admin|passwd\nok|none|none\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|@|second\\x0d\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|bob|\nok|@|@\nok|@|@\nok|@|@\nok|@|@\nok|bob|\nok|bob|\n",
        "ok|@|@\nok|alice|alicespassword\nok|bob|\nok|bob|\nok|bob|\n",
        "ok|bob|\nnomatch|@|@\nok|@|@\nok|@|@\nok|@|@\nok|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nok|@|@\nok|alice|alicespassword\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|user1|passwd1\nnomatch|@|@\nnomatch|@|@\nok|user1|passwd1\n",
        "ok|@|passwddef\nok|@|passwddef\nok|@|passwddef\nok|@|passwd2\n",
        "ok|userdef|passwddef\nok|userdef|passwddef\nok|@|passwddef\n",
        "ok|userdef|passwddef\nok|userdef|passwddef\nok|userdef|passwddef\n",
        "ok|user1|passwd1\nok|userdef|passwddef\nok|lena|pass\nok|@|pass\n",
        "ok|@|pass\nok|@|pass\nok|@|pass\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|lena|pass\n",
        "nomatch|@|@\nok|a\\x20b|p\\x09q\nok|@|p\\x09q\nok|@|p\\x09q\n",
        "ok|@|p\\x09q\nok|@|p\\x09q\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|a\\x20b|p\\x09q\nnomatch|@|@\nok|a\\x0ab|c\\x0dd\\x09e\n",
        "ok|@|c\\x0dd\\x09e\nok|@|c\\x0dd\\x09e\nok|@|c\\x0dd\\x09e\n",
        "ok|@|c\\x0dd\\x09e\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|a\\x0ab|c\\x0dd\\x09e\n",
        "nomatch|@|@\nok|a\"b|a\\x5cb\nok|@|a\\x5cb\nok|@|a\\x5cb\n",
        "ok|@|a\\x5cb\nok|@|a\\x5cb\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|a\"b|a\\x5cb\nnomatch|@|@\nok|lena|\nok|@|\nok|@|@\nok|@|@\n",
        "ok|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nok|lena|\nnomatch|@|@\nsyntax|@|@\n",
        "syntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\n",
        "syntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\n",
        "syntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\n",
        "syntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\n",
        "syntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\n",
        "ok|lena|pass\nok|@|pass\nok|@|pass\nok|@|pass\nok|@|pass\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nok|lena|pass\nnomatch|@|@\nok|lena|pass\nok|@|pass\n",
        "syntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\n",
        "syntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\nok|lena|pass\n",
        "syntax|@|@\nok|lena|pass\nok|@|pass\nok|@|pass\nok|@|pass\n",
        "ok|@|pass\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nok|lena|pass\nnomatch|@|@\n",
        "ok|lena|pass\nok|@|pass\nok|@|pass\nok|@|pass\nok|@|pass\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nok|lena|pass\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nok|lena|pass\nok|@|pass\nok|@|pass\nok|@|pass\n",
        "ok|@|pass\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nok|lena|pass\nnomatch|@|@\nsyntax|@|@\n",
        "syntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\n",
        "syntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\nsyntax|@|@\n",
        "syntax|@|@\nsyntax|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|lena|p\\xffs\nok|lena|pa#ss\nok|@|pa#ss\nok|@|pa#ss\n",
        "ok|@|pa#ss\nok|@|pa#ss\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|lena|pa#ss\n",
        "nomatch|@|@\nok|lena|pass\nok|@|pass\nok|@|pass\nok|@|pass\n",
        "ok|@|pass\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nok|lena|pass\nnomatch|@|@\nok||pass\n",
        "ok|@|pass\nok|@|pass\nok|@|pass\nok|@|pass\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok||pass\nnomatch|@|@\nok||empty\nok|@|named\nok|@|named\n",
        "ok|@|empty\nok|@|named\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok||empty\nnomatch|@|@\n",
        "ok|lena|\nok|@|\nok|@|\nok|@|\nok|@|\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|lena|\n",
        "nomatch|@|@\nok|lepassword|\nok|@|@\nok|@|@\nok|@|@\nok|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nok|lepassword|\nnomatch|@|@\nok|lena|pass\n",
        "ok|@|pass\nok|@|pass\nok|@|pass\nok|@|pass\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "ok|lena|pass\nnomatch|@|@\nok|lena|azb\nok|@|azb\nok|@|azb\n",
        "ok|@|azb\nok|@|azb\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|lena|azb\nnomatch|@|@\n",
        "ok|dora|dpass\nok|@|pass\nok|@|pass\nok|@|pass\nok|@|pass\n",
        "ok|dora|dpass\nok|dora|dpass\nok|@|@\nok|dora|dpass\n",
        "ok|dora|dpass\nok|dora|dpass\nok|dora|dpass\nok|dora|dpass\n",
        "ok|dora|dpass\nok|@|dpass\nok|@|dpass\nok|@|dpass\nok|@|dpass\n",
        "ok|dora|dpass\nok|dora|dpass\nok|@|dpass\nok|dora|dpass\n",
        "ok|dora|dpass\nok|dora|dpass\nok|dora|dpass\nok|dora|dpass\n",
        "ok|@|pass\nok|@|otherpass\nok|@|otherpass\nok|@|otherpass\n",
        "ok|@|otherpass\nnomatch|@|@\nnomatch|@|@\nnomatch|@|@\n",
        "nomatch|@|@\nnomatch|@|@\nnomatch|@|@\nok|@|pass\nnomatch|@|@\n",
    );

    /// This side's corpus is byte-for-byte the one the C driver read.
    ///
    /// Both were emitted from one source of bytes, and this is what makes
    /// that claim checkable: a mistranscribed escape changes the length or
    /// the checksum, and agreement on a DIFFERENT corpus is not agreement.
    #[test]
    fn the_oracle_corpus_is_the_one_the_c_driver_read() {
        let total: usize = ORACLE_CORPUS.iter().map(|text| text.len()).sum();
        assert_eq!(total, ORACLE_CORPUS_BYTES);

        let checksum = ORACLE_CORPUS
            .iter()
            .flat_map(|text| text.iter())
            .fold(0_u32, |acc, &byte| acc.wrapping_add(u32::from(byte)));
        assert_eq!(checksum, ORACLE_CORPUS_CHECKSUM);

        // Discriminating rather than vacuous: the corpus really does carry
        // the awkward bytes the parser is supposed to survive.
        assert!(ORACLE_CORPUS.iter().any(|text| text.contains(&0x00)));
        assert!(ORACLE_CORPUS.iter().any(|text| text.contains(&0xff)));
        assert!(ORACLE_CORPUS.iter().any(|text| text.contains(&b'\r')));
        assert!(ORACLE_CORPUS.iter().any(|text| text.is_empty()));
    }

    /// Every one of the 559 answers matches curl 8.19.0-DEV's own.
    #[test]
    fn every_answer_matches_the_c_oracle() {
        let expected: Vec<&str> = C_ORACLE
            .split('\n')
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(
            expected.len(),
            ORACLE_CORPUS.len() * ORACLE_QUERIES.len(),
            "the transcript must cover exactly the calls made"
        );

        let answers = ORACLE_CORPUS.iter().flat_map(|&text| {
            ORACLE_QUERIES
                .iter()
                .map(move |&(host, login)| shape(text, host, login))
        });

        let mut compared = 0_usize;
        for (got, want) in answers.zip(expected.iter()) {
            let entry = compared / ORACLE_QUERIES.len();
            let query = compared % ORACLE_QUERIES.len();
            assert_eq!(
                &got, want,
                "corpus entry {entry}, query {query}: this crate says \
                 {got}, curl 8.19.0-DEV says {want}"
            );
            compared += 1;
        }
        assert_eq!(compared, expected.len());
    }
}
