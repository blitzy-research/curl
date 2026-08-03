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
//! The FTP `LIST` response parser, and the file-information model behind
//! wildcard downloading.
//!
//! Supersedes `lib/ftplistparser.c:28-1090` with `lib/ftplistparser.h:30-65`,
//! and `lib/fileinfo.c:30-41` with `lib/fileinfo.h:31-35`. The data model it
//! fills is declared publicly at `include/curl/curl.h:292-358`: the nine
//! `curlfiletype` values, the eight `CURLFINFOFLAG_*` bits, `struct
//! curl_fileinfo` and the five chunk-callback result codes. AAP 0.4.1 maps
//! all four C files onto this one Rust file.
//!
//! # What lives here and what does not
//!
//! This file owns the memory-safe Rust [`FileInfo`] that FTP wildcard
//! processing uses internally: owned [`String`] data, owned numbers, and no
//! pointer into a shared byte buffer. The C-layout ABI mirror of
//! `struct curl_fileinfo` -- the declaration a caller's compiler sees, with
//! its field order and its `char *` members -- belongs to `curl-rs-ffi`,
//! which is the crate that owns the ABI. It is deliberately NOT duplicated
//! here: two declarations of one layout drift, and the drift stays invisible
//! until a caller reads a field at the wrong offset.
//!
//! The same division decides the fate of the legacy private tail. The public
//! struct ends with three members annotated at `include/curl/curl.h:337-341`
//! as "libcurl private struct fields. Previously used by libcurl, so they
//! must never be interfered with": `b_data`, `b_size` and `b_used`. They hold
//! nothing in curl 8.x -- the byte buffer moved into `struct fileinfo`'s
//! `dynbuf` at `lib/fileinfo.h:34` years ago -- and they survive only because
//! removing a member from a public layout is an ABI break. They belong to the
//! C-layout mirror in `curl-rs-ffi` and must never be interfered with there.
//! [`FileInfo`] therefore does NOT carry them: reproducing three dead
//! placeholder fields in a crate-private Rust type would preserve the C's
//! padding and nothing else.
//!
//! # The parse is incremental because the C's is
//!
//! `Curl_ftp_parselist` (`lib/ftplistparser.c:1013-1089`) is installed as the
//! transfer's write callback for the duration of `LIST`, so it is handed
//! whatever slice of the response the socket produced. Every byte is pushed
//! through a finite-state machine exactly once, and all of the parse state --
//! the detected server format, the main and sub state, the accumulated line,
//! the field offsets into it, and any partially built record -- has to
//! survive between calls. [`ParselistData::push`] therefore accepts an
//! arbitrary chunk, including one byte at a time, and produces the same
//! result either way.
//!
//! Two things follow that a from-scratch parser would get wrong. Splitting
//! the response on newlines and then splitting each line on whitespace loses
//! the chunk state, and it also loses the historical edge behaviour that the
//! byte-by-byte machine encodes -- which substates tolerate a stray
//! character, which reset a field, and exactly where a carriage return is
//! removed. The C's structure is preserved for that reason, function for
//! function, and not out of nostalgia.
//!
//! # Field offsets, and the terminators that go with them
//!
//! The C accumulates each listing record into one `dynbuf` and remembers six
//! offsets into it (`lib/ftplistparser.c:165-172`). As each field ends it
//! writes a zero byte over the delimiter, so `str + offset` is a C string
//! (`ftp_pl_insert_finfo`, `:307-318`). This module keeps both halves of that
//! design: the same six offsets, and the same zero bytes written into the
//! same positions of the record buffer. That is what lets six plain indices
//! address six variable-length fields without a second table of lengths, and
//! it reproduces the C's termination byte for byte -- including the cases
//! where the C writes over a carriage return rather than over a space.
//!
//! The offsets are read only when a record completes, and only then is any
//! owned string materialized. An offset of zero means "this field was never
//! assigned", which is how `strings.perm`, `strings.user`, `strings.group`
//! and `strings.target` become absent; `filename` and `strings.time` are
//! assigned unconditionally by the C and are therefore always present.
//!
//! # Two recorded divergences from the C
//!
//! Both are stated here rather than buried, because each is a place where a
//! reader diffing against `lib/ftplistparser.c` will find a difference.
//!
//! **1. A valid `total` line is accepted.** `parse_unix` at `:838-844` sets
//! the main state to `PL_UNIX_FILETYPE` after a well-formed `total 12` line
//! and then falls through to the file-type arm, which is handed the line
//! feed that ended the line and rejects it -- `unix_filetype` (`:353-384`)
//! admits only the eight type characters. The shape predates the split into
//! sub-functions (commit `3b4e84c44f`) and is an upstream defect, not a rule:
//! no fixture in the corpus exercises it, because the listing generator at
//! `tests/directories.pm:183-201` emits no `total` line. Here the line feed
//! that completes a valid `total` line is consumed, the record buffer is
//! reset and the next byte starts a file entry -- while a NON-`t` first byte
//! is still reprocessed through the file-type arm without being lost, which
//! is the fall-through the C actually intends.
//!
//! **2. Listing bytes that are not valid text are replaced, not preserved.**
//! [`FileInfo`] holds `String` and `Option<String>`, so materializing a field
//! goes through a lossy conversion and a byte sequence that is not valid text
//! becomes the replacement character. The C hands out the raw bytes. Every
//! fixture in the corpus is ASCII, so nothing measured changes, but a server
//! that lists names in a legacy single-byte encoding would see them altered.
//! The owned-text model is what AAP 0.4.1 specifies for this file, and the
//! conversion happens in exactly one helper so that a future change of mind
//! has one place to edit.
//!
//! # Conventions
//!
//! Memory-safe Rust throughout: no raw pointers, no self-referential
//! structures, and every index bounds-checked. The C's intrusive list node
//! inside `struct fileinfo` (`lib/fileinfo.h:33`) becomes a
//! [`VecDeque`] that owns its elements, and `Curl_fileinfo_alloc` with
//! `Curl_fileinfo_cleanup` become ordinary construction and drop -- there is
//! no zeroed allocation to imitate and no memory to wipe.
//!
//! The C function names are kept, so that a grep against
//! `lib/ftplistparser.c` still lands: `unix_filetype`,
//! `ftp_pl_get_permission`, `parse_unix_totalsize`, `parse_unix_permission`,
//! `parse_unix_hlinks`, `parse_unix_user`, `parse_unix_group`,
//! `parse_unix_size`, `parse_unix_time`, `parse_unix_filename`,
//! `parse_unix_symlink`, `parse_unix`, `parse_winnt` and
//! `ftp_pl_insert_finfo`.
//!
//! The whole of the C is wrapped in `#ifndef CURL_DISABLE_FTP`
//! (`lib/ftplistparser.c:26`), so the whole of this module carries
//! `#[cfg(feature = "ftp")]`, written as an inner attribute below for the
//! same reason `util/fnmatch.rs` writes its own that way: the gate belongs
//! with the code it governs, and the parent then declares the module
//! unconditionally. There is no TLS feature in this workspace and this parser
//! has no TLS responsibility, so no other gate appears.
//!
//! Edition 2021, minimum supported Rust version 1.75, and nothing here needs
//! anything newer. No dependency is added: the record buffer is
//! [`crate::util::dynbuf`], the comparator is [`crate::util::fnmatch`], the
//! number and blank handling is [`crate::util::strparse`], and the error type
//! is [`crate::error`].

#![cfg(feature = "ftp")]

use std::collections::VecDeque;

use crate::error::{CURLcode, CurlResult, Error};
use crate::util::dynbuf::DynBuf;
use crate::util::fnmatch::{fnmatch, FnMatch};
use crate::util::strparse::{
    is_alnum, is_blank, is_digit, str_number, str_numblanks, str_passblanks,
};

// ---------------------------------------------------------------------------
// Pinned numeric contracts
// ---------------------------------------------------------------------------

/// The ceiling on one accumulated listing record, in bytes.
///
/// `MAX_FTPLIST_BUFFER` (`lib/ftplistparser.c:351`), whose own comment reads
/// "arbitrarily set". It is the `toobig` argument the C hands
/// `curlx_dyn_init` at `:1050`, and it is a hard bound rather than a hint: a
/// record that reaches it makes the append fail, which the driver loop turns
/// into `CURLE_OUT_OF_MEMORY` at `:1055-1058`.
///
/// The number of bytes actually admitted is one less than this, because
/// [`DynBuf`] measures a candidate append as `len + idx + 1` -- the C carries
/// the same `+ 1` for the terminator it stores (`lib/curlx/dynbuf.c:72`), so
/// both implementations accept 9,999 bytes and refuse the 10,000th.
pub(crate) const MAX_FTPLIST_BUFFER: usize = 10000;

/// The bit `ftp_pl_get_permission` sets when a permission character is
/// neither the one its position expects nor `-`.
///
/// `FTP_LP_MALFORMATED_PERM` (`lib/ftplistparser.c:229`). It is not a
/// permission bit: it sits far above the twelve real ones so that a single
/// test on the result detects a malformed field, which
/// `parse_unix_permission` turns into `CURLE_FTP_BAD_FILE_LIST` at
/// `:449-450`. The spelling of the C macro is preserved, typo included, so a
/// grep against the original lands.
const FTP_LP_MALFORMATED_PERM: u32 = 0x0100_0000;

/// The nine file types a listing can report.
///
/// `curlfiletype` (`include/curl/curl.h:292-304`). Every discriminant is
/// written out and none is left to Rust's implicit "previous plus one", for
/// the reason AAP 0.6.1 records for `CURLcode`: a caller compiled against
/// the C tree holds the numbers, not the names, and this value reaches such a
/// caller through `struct curl_fileinfo`. `#[repr(i32)]` because a C
/// enumeration is an `int`.
///
/// [`FileType::File`] is the default because `Curl_fileinfo_alloc`
/// (`lib/fileinfo.c:30-33`) allocates with `calloc`, so an unparsed record
/// starts at zero. Both WinNT branches then assign a type explicitly
/// (`lib/ftplistparser.c:944,953`), and the Unix parser assigns one from the
/// first character of every line, so the default is observable only for a
/// record that never reached its type field.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum FileType {
    /// `CURLFILETYPE_FILE` = `0`. A regular file.
    #[default]
    File = 0,
    /// `CURLFILETYPE_DIRECTORY` = `1`.
    Directory = 1,
    /// `CURLFILETYPE_SYMLINK` = `2`. Carries a target in
    /// [`FileInfoStrings::target`].
    Symlink = 2,
    /// `CURLFILETYPE_DEVICE_BLOCK` = `3`.
    DeviceBlock = 3,
    /// `CURLFILETYPE_DEVICE_CHAR` = `4`.
    DeviceChar = 4,
    /// `CURLFILETYPE_NAMEDPIPE` = `5`.
    NamedPipe = 5,
    /// `CURLFILETYPE_SOCKET` = `6`.
    Socket = 6,
    /// `CURLFILETYPE_DOOR` = `7`. The public header notes it "is possible
    /// only on Sun Solaris now".
    Door = 7,
    /// `CURLFILETYPE_UNKNOWN` = `8`. The header notes it "should never
    /// occur", and no parse path in this module produces it; it exists
    /// because it is part of the pinned enumeration.
    // The allowance is on the variant alone, not on the type, so that a
    // variant added later is still reported. Nothing constructs this one, by
    // design: the C never does either, and omitting it would shift nothing --
    // it is last -- but a consumer matching on `curlfiletype` must still be
    // able to name the value the header declares.
    #[allow(dead_code)]
    Unknown = 8,
}

// `VARIANTS` and `as_i32` exist for the parity tests and for a consumer
// crossing to C. Neither is on a parse path, hence the allowance; see the note
// on `impl ParselistData` for the policy.
#[allow(dead_code)]
impl FileType {
    /// Every member, in declaration order, which is also ascending numeric
    /// order.
    ///
    /// Present so that a parity test can walk the enumeration without a
    /// second list to keep in step with the first.
    pub(crate) const VARIANTS: [Self; 9] = [
        Self::File,
        Self::Directory,
        Self::Symlink,
        Self::DeviceBlock,
        Self::DeviceChar,
        Self::NamedPipe,
        Self::Socket,
        Self::Door,
        Self::Unknown,
    ];

    /// The pinned integer a C consumer sees.
    #[must_use]
    pub(crate) const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// The result of a `CURLOPT_CHUNK_BGN_FUNCTION` callback.
///
/// The three macros at `include/curl/curl.h:344-347`. The callback itself
/// returns a C `long` (`:352-354`), so the discriminants are pinned in that
/// width; a caller compiled against the C tree returns these exact integers.
///
/// An enumeration rather than three loose constants because the driver has to
/// classify whatever integer arrives, and [`ChunkBgn::from_i64`] is where
/// that classification lives instead of in a `match` the next caller would
/// write again.
// Unreferenced until the wildcard driver in `ftp/mod.rs` lands and classifies
// a callback's return value. The allowance is per item, as this crate's
// policy requires, and covers the variants along with the type.
#[allow(dead_code)]
#[repr(i64)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum ChunkBgn {
    /// `CURL_CHUNK_BGN_FUNC_OK` = `0`. Transfer this entry.
    Ok = 0,
    /// `CURL_CHUNK_BGN_FUNC_FAIL` = `1`. The header's comment: "tell the lib
    /// to end the task".
    Fail = 1,
    /// `CURL_CHUNK_BGN_FUNC_SKIP` = `2`. The header's comment: "skip this
    /// chunk over".
    Skip = 2,
}

#[allow(dead_code)]
impl ChunkBgn {
    /// Every member, in declaration order.
    pub(crate) const VARIANTS: [Self; 3] = [Self::Ok, Self::Fail, Self::Skip];

    /// The pinned integer a C consumer returns.
    #[must_use]
    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }

    /// Classifies a value returned across the callback boundary.
    ///
    /// [`None`] for anything the header does not define, which the driver is
    /// free to treat as it chooses; this function does not invent a policy
    /// for a value the public contract never described.
    #[must_use]
    pub(crate) const fn from_i64(raw: i64) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::Fail),
            2 => Some(Self::Skip),
            _ => None,
        }
    }
}

/// The result of a `CURLOPT_CHUNK_END_FUNCTION` callback.
///
/// The two macros at `include/curl/curl.h:356-358`. There is no `SKIP` here:
/// the header explains at `:360-365` that the end callback "have to be called
/// FOR ALL chunks. Even if downloading of this chunk was skipped in
/// CHUNK_BGN_FUNC", so it has nothing left to skip.
// Unreferenced for the same reason as [`ChunkBgn`].
#[allow(dead_code)]
#[repr(i64)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum ChunkEnd {
    /// `CURL_CHUNK_END_FUNC_OK` = `0`.
    Ok = 0,
    /// `CURL_CHUNK_END_FUNC_FAIL` = `1`. The header's comment: "tell the lib
    /// to end the task".
    Fail = 1,
}

#[allow(dead_code)]
impl ChunkEnd {
    /// Every member, in declaration order.
    pub(crate) const VARIANTS: [Self; 2] = [Self::Ok, Self::Fail];

    /// The pinned integer a C consumer returns.
    #[must_use]
    pub(crate) const fn as_i64(self) -> i64 {
        self as i64
    }

    /// Classifies a value returned across the callback boundary.
    #[must_use]
    pub(crate) const fn from_i64(raw: i64) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::Fail),
            _ => None,
        }
    }
}

/// The eight states of a wildcard download.
///
/// `wildcard_states` (`lib/ftplistparser.h:42-54`). `#[repr(u8)]` because the
/// C stores it in `unsigned char state` (`:65`) rather than in the
/// enumeration's own width, and the two explicit values the C writes -- 0 and
/// 1 -- make the rest positional, so all eight are written out here.
///
/// The comments the C attaches to five of them are reproduced, because they
/// are the only description of the state machine's intent in the tree.
#[allow(dead_code)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum WildcardState {
    /// `CURLWC_CLEAR` = `0`. The value a zeroed allocation starts at, before
    /// `Curl_wildcard_init` runs.
    Clear = 0,
    /// `CURLWC_INIT` = `1`. What initialization and teardown both leave
    /// behind (`lib/ftplistparser.c:184,205`).
    Init = 1,
    /// `CURLWC_MATCHING` = `2`. The C: "library is trying to get list of
    /// addresses for downloading".
    Matching = 2,
    /// `CURLWC_DOWNLOADING` = `3`.
    Downloading = 3,
    /// `CURLWC_CLEAN` = `4`. The C: "deallocate resources and reset
    /// settings".
    Clean = 4,
    /// `CURLWC_SKIP` = `5`. The C: "skip over concrete file".
    Skip = 5,
    /// `CURLWC_ERROR` = `6`. The C: "error cases".
    Error = 6,
    /// `CURLWC_DONE` = `7`. The C: "if is wildcard->state == CURLWC_DONE
    /// wildcard loop will end".
    Done = 7,
}

#[allow(dead_code)]
impl WildcardState {
    /// Every member, in declaration order.
    pub(crate) const VARIANTS: [Self; 8] = [
        Self::Clear,
        Self::Init,
        Self::Matching,
        Self::Downloading,
        Self::Clean,
        Self::Skip,
        Self::Error,
        Self::Done,
    ];

    /// The stored integer, in the width the C stores it in.
    #[must_use]
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The server listing format, once it has been recognised.
///
/// The anonymous enumeration at `lib/ftplistparser.c:143-147`. Detection
/// happens once, on the first byte of the first non-empty chunk
/// (`:1034-1037`), and never again for the life of the parser.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum OsType {
    /// `OS_TYPE_UNKNOWN` = `0`. Nothing has been parsed yet.
    #[default]
    Unknown = 0,
    /// `OS_TYPE_UNIX` = `1`. Selected by any first byte that is not an ASCII
    /// digit.
    Unix = 1,
    /// `OS_TYPE_WIN_NT` = `2`. Selected by an ASCII digit, because a DOS
    /// listing opens with a date.
    WinNt = 2,
}

#[allow(dead_code)]
impl OsType {
    /// Every member, in declaration order.
    pub(crate) const VARIANTS: [Self; 3] =
        [Self::Unknown, Self::Unix, Self::WinNt];

    /// The pinned integer.
    #[must_use]
    pub(crate) const fn as_u8(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// The file-information model
// ---------------------------------------------------------------------------

/// The textual fields of a listing entry.
///
/// The anonymous inner struct of `struct curl_fileinfo`
/// (`include/curl/curl.h:326-333`), whose own comment reads "If some of these
/// fields is not NULL, it is a pointer to b_data". Every member there is a
/// `char *` into the record buffer; here each is owned, so the buffer can be
/// dropped as soon as the record completes.
///
/// The optionality is not uniform, and it is not a style choice:
/// `ftp_pl_insert_finfo` (`lib/ftplistparser.c:309-318`) assigns `time`
/// unconditionally and guards the other four on a non-zero offset. That
/// asymmetry is reproduced exactly, so a consumer sees a value present in
/// precisely the cases the C makes it non-null.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileInfoStrings {
    /// `strings.time`. Always present: the C assigns `str + offsets.time`
    /// with no guard (`lib/ftplistparser.c:316`), and a WinNT listing leaves
    /// that offset at zero on purpose, which makes the whole date-and-time
    /// prefix of the line the value.
    ///
    /// This is the ONLY time information a listing yields. The numeric
    /// [`FileInfo::time`] beside it stays zero; see its own note.
    pub(crate) time: String,
    /// `strings.perm`. The nine permission characters, exactly as the server
    /// spelled them -- `rwxr-xr-x`. Absent for a WinNT listing, which has no
    /// permission column.
    pub(crate) perm: Option<String>,
    /// `strings.user`. The owner column, which may be a name or a bare
    /// numeric identifier: format 3 of the C's header comment
    /// (`lib/ftplistparser.c:35-36`) lists both columns as numbers.
    pub(crate) user: Option<String>,
    /// `strings.group`. The group column, with the same two shapes.
    pub(crate) group: Option<String>,
    /// `strings.target`. The C: "pointer to the target filename of a
    /// symlink". Present only for an entry the Unix parser took through its
    /// symlink states.
    pub(crate) target: Option<String>,
}

/// One listing entry.
///
/// The memory-safe counterpart of `struct curl_fileinfo`
/// (`include/curl/curl.h:315-342`). See the module documentation for the
/// division of labour: the C-layout mirror of that struct, including the three
/// legacy private members that must never be interfered with, belongs to
/// `curl-rs-ffi`.
///
/// # Which flags a parse actually sets
///
/// Eight bits are defined and the parser sets three. Measured at
/// `lib/ftplistparser.c:452` ([`FileInfo::KNOWN_PERM`]), `:490`
/// ([`FileInfo::KNOWN_HLINKCOUNT`]), and `:590` with `:956`
/// ([`FileInfo::KNOWN_SIZE`], once from the Unix size column and once from
/// the WinNT size-or-directory column). Nothing sets
/// [`FileInfo::KNOWN_FILENAME`], [`FileInfo::KNOWN_FILETYPE`],
/// [`FileInfo::KNOWN_TIME`], [`FileInfo::KNOWN_UID`] or
/// [`FileInfo::KNOWN_GID`], and this module does not start: a filename and a
/// file type are present on every entry the parser emits, so a bit claiming
/// they are "known" would carry no information the consumer does not already
/// have, and the C's callers -- `tests/libtest/lib576.c:41-52` among them --
/// are written against the three that are set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct FileInfo {
    /// `filename`. Always present.
    pub(crate) filename: String,
    /// `filetype`.
    pub(crate) filetype: FileType,
    /// `time`.
    ///
    /// Always zero. The public header annotates the member exactly that way
    /// -- `time_t time; /* always zero! */` at
    /// `include/curl/curl.h:319` -- and no path in the C parser writes it.
    /// The listing's own date and time is text and lives in
    /// [`FileInfoStrings::time`]; converting it would need a year the
    /// short Unix format omits and a time zone no listing states, so curl
    /// does not try and neither does this.
    pub(crate) time: i64,
    /// `perm`. The twelve permission bits
    /// [`ftp_pl_get_permission`](fn@ftp_pl_get_permission) computes, valid
    /// only when [`FileInfo::KNOWN_PERM`] is set in [`FileInfo::flags`].
    pub(crate) perm: u32,
    /// `uid`. Never written by this parser; a Unix listing names its owner
    /// rather than numbering it, and the numeric form a server may send is
    /// still text in the same column.
    pub(crate) uid: i32,
    /// `gid`. Never written, for the same reason as [`FileInfo::uid`].
    pub(crate) gid: i32,
    /// `size`, in bytes. Valid only when [`FileInfo::KNOWN_SIZE`] is set --
    /// except for a WinNT `<DIR>` entry, where the C assigns zero and sets
    /// the bit together (`lib/ftplistparser.c:944-956`).
    pub(crate) size: i64,
    /// `hardlinks`. Valid only when [`FileInfo::KNOWN_HLINKCOUNT`] is set.
    pub(crate) hardlinks: i64,
    /// `strings`.
    pub(crate) strings: FileInfoStrings,
    /// `flags`. A bitwise OR of the eight `CURLFINFOFLAG_*` constants
    /// declared on this type.
    pub(crate) flags: u32,
}

// The eight `CURLFINFOFLAG_*` bits, at `include/curl/curl.h:306-313`.
//
// Associated constants rather than free ones so that a reader writes
// `FileInfo::KNOWN_PERM` and gets the type along with the value, and so that
// one allowance covers the five the parser never sets. Those five are part of
// the public contract whether or not this parser reaches them, which is why
// they are declared rather than omitted -- a consumer testing for
// `CURLFINFOFLAG_KNOWN_TIME` must be able to name it.
#[allow(dead_code)]
impl FileInfo {
    /// `CURLFINFOFLAG_KNOWN_FILENAME` = `1 << 0`.
    pub(crate) const KNOWN_FILENAME: u32 = 1 << 0;
    /// `CURLFINFOFLAG_KNOWN_FILETYPE` = `1 << 1`.
    pub(crate) const KNOWN_FILETYPE: u32 = 1 << 1;
    /// `CURLFINFOFLAG_KNOWN_TIME` = `1 << 2`.
    pub(crate) const KNOWN_TIME: u32 = 1 << 2;
    /// `CURLFINFOFLAG_KNOWN_PERM` = `1 << 3`. Set at
    /// `lib/ftplistparser.c:452`.
    pub(crate) const KNOWN_PERM: u32 = 1 << 3;
    /// `CURLFINFOFLAG_KNOWN_UID` = `1 << 4`.
    pub(crate) const KNOWN_UID: u32 = 1 << 4;
    /// `CURLFINFOFLAG_KNOWN_GID` = `1 << 5`.
    pub(crate) const KNOWN_GID: u32 = 1 << 5;
    /// `CURLFINFOFLAG_KNOWN_SIZE` = `1 << 6`. Set at
    /// `lib/ftplistparser.c:590` and `:956`.
    pub(crate) const KNOWN_SIZE: u32 = 1 << 6;
    /// `CURLFINFOFLAG_KNOWN_HLINKCOUNT` = `1 << 7`. Set at
    /// `lib/ftplistparser.c:490`.
    pub(crate) const KNOWN_HLINKCOUNT: u32 = 1 << 7;

    /// The eight bits, in declaration order.
    pub(crate) const KNOWN_FLAGS: [u32; 8] = [
        Self::KNOWN_FILENAME,
        Self::KNOWN_FILETYPE,
        Self::KNOWN_TIME,
        Self::KNOWN_PERM,
        Self::KNOWN_UID,
        Self::KNOWN_GID,
        Self::KNOWN_SIZE,
        Self::KNOWN_HLINKCOUNT,
    ];

    /// Whether every bit of `mask` is set in [`FileInfo::flags`].
    #[must_use]
    pub(crate) const fn knows(&self, mask: u32) -> bool {
        self.flags & mask == mask
    }
}

/// The numeric half of a record, while the record is still being parsed.
///
/// `struct curl_fileinfo`'s scalar members, and nothing else. The textual
/// members cannot be filled yet, because each one is a span of the record
/// buffer whose end is not known until the following delimiter arrives; they
/// are materialized in one step when the record completes.
///
/// The C has no counterpart type -- it writes straight into
/// `parser->file_data->info`, the same struct it later hands the caller. The
/// split exists here because that struct's textual members are owned
/// [`String`]s: keeping the partial record's scalars apart from the finished
/// entry means there is never a moment when a [`FileInfo`] holds a
/// half-assigned string.
///
/// Zero throughout on construction, matching the `calloc` in
/// `Curl_fileinfo_alloc` (`lib/fileinfo.c:30-33`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FileInfoAccumulator {
    /// `info.filetype`.
    filetype: FileType,
    /// `info.time`. Always zero; see [`FileInfo::time`]. Carried so that the
    /// finished entry is built from one place rather than from a mixture of
    /// this accumulator and a literal.
    time: i64,
    /// `info.perm`.
    perm: u32,
    /// `info.uid`.
    uid: i32,
    /// `info.gid`.
    gid: i32,
    /// `info.size`.
    size: i64,
    /// `info.hardlinks`.
    hardlinks: i64,
    /// `info.flags`.
    flags: u32,
}

/// A listing record under construction.
///
/// `struct fileinfo` (`lib/fileinfo.h:31-35`) without its intrusive list
/// node: the accumulated scalars and the byte buffer the record's text lives
/// in. The C's `struct Curl_llist_node list` member exists so that the same
/// allocation can be threaded onto `wc->filelist` without a second one; a
/// [`VecDeque`] owns its elements, so there is nothing to thread and the
/// member has no successor.
///
/// `Curl_fileinfo_alloc` and `Curl_fileinfo_cleanup` (`lib/fileinfo.c:30-42`)
/// become [`Default`] and the ordinary drop glue. There is no zeroed
/// allocation to imitate, no `curlx_dyn_free` to remember, and no window in
/// which a partially initialized record is reachable.
#[derive(Debug)]
struct InProgressFile {
    /// The scalars parsed so far.
    info: FileInfoAccumulator,
    /// The record's bytes, with the zero terminators the parse writes into
    /// them. Bounded at [`MAX_FTPLIST_BUFFER`], exactly as
    /// `curlx_dyn_init(&parser->file_data->buf, MAX_FTPLIST_BUFFER)` bounds
    /// the C's (`lib/ftplistparser.c:1050`).
    buf: DynBuf,
}

impl Default for InProgressFile {
    fn default() -> Self {
        Self {
            info: FileInfoAccumulator::default(),
            buf: DynBuf::new(MAX_FTPLIST_BUFFER),
        }
    }
}

impl InProgressFile {
    /// Writes a zero byte at `index`, if the record holds that many bytes.
    ///
    /// The C's field terminators: `mem[10] = 0` at
    /// `lib/ftplistparser.c:447`, `mem[parser->item_offset +
    /// parser->item_length - 1] = 0` at `:487`, `:523`, `:552`, `:587`,
    /// `:664`, `:705`, `:713`, `:802`, `:813` and `:920`, `mem[... - 4] = 0`
    /// at `:776`, and `mem[len - 1] = 0` at `:979` and `:983`.
    ///
    /// Every one of those writes is in bounds at the moment the C performs
    /// it, and the arithmetic that produces each index is reproduced
    /// unchanged, so the guard here never fires on a well-formed parse. It is
    /// what makes the write total rather than conditional on that reasoning
    /// holding: a stray index skips the write instead of reaching past the
    /// buffer, and the field it would have terminated then simply runs to the
    /// next zero byte or to the end of the record.
    fn poke_nul(&mut self, index: usize) {
        if let Some(slot) = self.buf.as_mut_slice().get_mut(index) {
            *slot = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// The Unix state machine's states
// ---------------------------------------------------------------------------

/// The ten fields a Unix listing line is read in.
///
/// `pl_unix_mainstate` (`lib/ftplistparser.c:52-63`), in the C's declaration
/// order. Only `PL_UNIX_TOTALSIZE = 0` is written explicitly there and the
/// rest are positional; all ten are written out here for the reason AAP 0.6.1
/// gives, and because the order IS the grammar -- the state after the size
/// column is the time column and nothing else.
///
/// [`UnixMain::TotalSize`] is the default because the C's `calloc` starts the
/// parser there, which is what lets a leading `total 12` line be recognised
/// before any file entry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum UnixMain {
    /// `PL_UNIX_TOTALSIZE` = `0`. The optional `total <n>` header line.
    #[default]
    TotalSize = 0,
    /// `PL_UNIX_FILETYPE` = `1`. The single leading type character.
    FileType = 1,
    /// `PL_UNIX_PERMISSION` = `2`. Nine characters and the space after them.
    Permission = 2,
    /// `PL_UNIX_HLINKS` = `3`. The hard-link count.
    Hlinks = 3,
    /// `PL_UNIX_USER` = `4`. The owner column.
    User = 4,
    /// `PL_UNIX_GROUP` = `5`. The group column.
    Group = 5,
    /// `PL_UNIX_SIZE` = `6`. The size column.
    Size = 6,
    /// `PL_UNIX_TIME` = `7`. Three whitespace-separated parts.
    Time = 7,
    /// `PL_UNIX_FILENAME` = `8`. Everything to the line ending.
    Filename = 8,
    /// `PL_UNIX_SYMLINK` = `9`. Reached instead of
    /// [`UnixMain::Filename`] when the type character was `l`.
    Symlink = 9,
}

/// `total_dirsize` -- `lib/ftplistparser.c:66-69`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum TotalDirSizeSub {
    /// `PL_UNIX_TOTALSIZE_INIT` = `0`. Nothing of the line has been seen.
    #[default]
    Init = 0,
    /// `PL_UNIX_TOTALSIZE_READING` = `1`. A leading `t` was seen, so the line
    /// is being read to its end.
    Reading = 1,
}

/// `hlinks` -- `lib/ftplistparser.c:71-74`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum HlinksSub {
    /// `PL_UNIX_HLINKS_PRESPACE` = `0`. Skipping the padding before the
    /// count.
    #[default]
    PreSpace = 0,
    /// `PL_UNIX_HLINKS_NUMBER` = `1`. Inside the digits.
    Number = 1,
}

/// `user` -- `lib/ftplistparser.c:76-79`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum UserSub {
    /// `PL_UNIX_USER_PRESPACE` = `0`.
    #[default]
    PreSpace = 0,
    /// `PL_UNIX_USER_PARSING` = `1`.
    Parsing = 1,
}

/// `group` -- `lib/ftplistparser.c:81-84`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum GroupSub {
    /// `PL_UNIX_GROUP_PRESPACE` = `0`.
    #[default]
    PreSpace = 0,
    /// `PL_UNIX_GROUP_NAME` = `1`.
    Name = 1,
}

/// `size` -- `lib/ftplistparser.c:86-89`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum SizeSub {
    /// `PL_UNIX_SIZE_PRESPACE` = `0`.
    #[default]
    PreSpace = 0,
    /// `PL_UNIX_SIZE_NUMBER` = `1`.
    Number = 1,
}

/// `time` -- `lib/ftplistparser.c:91-98`.
///
/// Six substates for three parts, alternating between the padding before a
/// part and the part itself. The three parts are month, day and either a time
/// of day or a year, which is how one machine reads both formats 1 and 2 of
/// the C's header comment (`lib/ftplistparser.c:31-34`) without deciding in
/// advance which it is looking at.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum TimeSub {
    /// `PL_UNIX_TIME_PREPART1` = `0`.
    #[default]
    PrePart1 = 0,
    /// `PL_UNIX_TIME_PART1` = `1`.
    Part1 = 1,
    /// `PL_UNIX_TIME_PREPART2` = `2`.
    PrePart2 = 2,
    /// `PL_UNIX_TIME_PART2` = `3`.
    Part2 = 3,
    /// `PL_UNIX_TIME_PREPART3` = `4`.
    PrePart3 = 4,
    /// `PL_UNIX_TIME_PART3` = `5`.
    Part3 = 5,
}

/// `filename` -- `lib/ftplistparser.c:100-104`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum FilenameSub {
    /// `PL_UNIX_FILENAME_PRESPACE` = `0`.
    #[default]
    PreSpace = 0,
    /// `PL_UNIX_FILENAME_NAME` = `1`.
    Name = 1,
    /// `PL_UNIX_FILENAME_WINDOWSEOL` = `2`. A carriage return was seen and
    /// only a line feed may follow it.
    WindowsEol = 2,
}

/// `symlink` -- `lib/ftplistparser.c:106-115`.
///
/// Eight substates, four of which spell out the exact four bytes of `" -> "`
/// one at a time. Any of those four positions receiving something else sends
/// the machine back to [`SymlinkSub::Name`], which is what lets a name
/// containing a space, a hyphen or a greater-than sign parse as a name rather
/// than as the start of a target.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum SymlinkSub {
    /// `PL_UNIX_SYMLINK_PRESPACE` = `0`.
    #[default]
    PreSpace = 0,
    /// `PL_UNIX_SYMLINK_NAME` = `1`.
    Name = 1,
    /// `PL_UNIX_SYMLINK_PRETARGET1` = `2`. The space of `" -> "` was seen.
    PreTarget1 = 2,
    /// `PL_UNIX_SYMLINK_PRETARGET2` = `3`. The hyphen was seen.
    PreTarget2 = 3,
    /// `PL_UNIX_SYMLINK_PRETARGET3` = `4`. The greater-than sign was seen.
    PreTarget3 = 4,
    /// `PL_UNIX_SYMLINK_PRETARGET4` = `5`. The trailing space was seen, and
    /// the name has been terminated four bytes back.
    PreTarget4 = 5,
    /// `PL_UNIX_SYMLINK_TARGET` = `6`.
    Target = 6,
    /// `PL_UNIX_SYMLINK_WINDOWSEOL` = `7`.
    WindowsEol = 7,
}

/// The Unix substate, tagged with the field it belongs to.
///
/// `pl_unix_substate` (`lib/ftplistparser.c:65-116`) is a `union` of eight
/// anonymous enumerations. A `union` makes every substate the same storage,
/// so reading the member the current main state does not imply is undefined
/// behaviour in C and the invariant that keeps the two halves in step is
/// maintained entirely by hand.
///
/// A tagged enumeration removes the hazard rather than documenting it: the
/// substate carries which field it belongs to, so a mismatch is representable
/// and answerable instead of undefined. Every transition in this module
/// assigns both halves together through
/// [`ParselistData::set_unix`](ParselistData::set_unix), which is what keeps
/// the pair consistent by construction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum UnixSub {
    /// The `total <n>` line's substate.
    TotalDirSize(TotalDirSizeSub),
    /// The hard-link column's substate.
    Hlinks(HlinksSub),
    /// The owner column's substate.
    User(UserSub),
    /// The group column's substate.
    Group(GroupSub),
    /// The size column's substate.
    Size(SizeSub),
    /// The time column's substate.
    Time(TimeSub),
    /// The filename's substate.
    Filename(FilenameSub),
    /// The symlink's substate.
    Symlink(SymlinkSub),
}

impl Default for UnixSub {
    /// `PL_UNIX_TOTALSIZE_INIT`, which is what the C's `calloc` leaves in
    /// every member of the union.
    fn default() -> Self {
        Self::TotalDirSize(TotalDirSizeSub::Init)
    }
}

// The eight extractors below each answer "what is the substate of MY field",
// and each maps a substate belonging to another field onto its own field's
// INITIAL value.
//
// That fallback is unreachable on any parse this module performs, because
// every transition sets the main state and the substate together. It is
// written rather than left out because the alternative shapes are all worse:
// returning an `Option` would put a decision at eleven call sites that have no
// second answer to give, and reaching for a panic would convert a state this
// module makes impossible into a crash in a network-facing parser. Mapping to
// the initial value is what the C effectively does when its union is freshly
// zeroed, so the fallback is also the closest thing to the original.
impl UnixSub {
    /// The `total <n>` substate.
    const fn total_dirsize(self) -> TotalDirSizeSub {
        match self {
            Self::TotalDirSize(sub) => sub,
            _ => TotalDirSizeSub::Init,
        }
    }

    /// The hard-link substate.
    const fn hlinks(self) -> HlinksSub {
        match self {
            Self::Hlinks(sub) => sub,
            _ => HlinksSub::PreSpace,
        }
    }

    /// The owner substate.
    const fn user(self) -> UserSub {
        match self {
            Self::User(sub) => sub,
            _ => UserSub::PreSpace,
        }
    }

    /// The group substate.
    const fn group(self) -> GroupSub {
        match self {
            Self::Group(sub) => sub,
            _ => GroupSub::PreSpace,
        }
    }

    /// The size substate.
    const fn size(self) -> SizeSub {
        match self {
            Self::Size(sub) => sub,
            _ => SizeSub::PreSpace,
        }
    }

    /// The time substate.
    const fn time(self) -> TimeSub {
        match self {
            Self::Time(sub) => sub,
            _ => TimeSub::PrePart1,
        }
    }

    /// The filename substate.
    const fn filename(self) -> FilenameSub {
        match self {
            Self::Filename(sub) => sub,
            _ => FilenameSub::PreSpace,
        }
    }

    /// The symlink substate.
    const fn symlink(self) -> SymlinkSub {
        match self {
            Self::Symlink(sub) => sub,
            _ => SymlinkSub::PreSpace,
        }
    }
}

// ---------------------------------------------------------------------------
// The WinNT state machine's states
// ---------------------------------------------------------------------------

/// The four fields a WinNT listing line is read in.
///
/// `pl_winNT_mainstate` (`lib/ftplistparser.c:118-123`). Format 5 of the C's
/// header comment (`:39-40`) is the whole grammar:
/// `01-29-97 11:32PM <DIR> prog`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum WinNtMain {
    /// `PL_WINNT_DATE` = `0`. Eight characters and the space after them.
    #[default]
    Date = 0,
    /// `PL_WINNT_TIME` = `1`.
    Time = 1,
    /// `PL_WINNT_DIRORSIZE` = `2`. Either `<DIR>` or a byte count.
    DirOrSize = 2,
    /// `PL_WINNT_FILENAME` = `3`.
    Filename = 3,
}

/// `time` -- `lib/ftplistparser.c:126-129`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum NtTimeSub {
    /// `PL_WINNT_TIME_PRESPACE` = `0`.
    #[default]
    PreSpace = 0,
    /// `PL_WINNT_TIME_TIME` = `1`.
    Time = 1,
}

/// `dirorsize` -- `lib/ftplistparser.c:130-133`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum NtDirOrSizeSub {
    /// `PL_WINNT_DIRORSIZE_PRESPACE` = `0`.
    #[default]
    PreSpace = 0,
    /// `PL_WINNT_DIRORSIZE_CONTENT` = `1`.
    Content = 1,
}

/// `filename` -- `lib/ftplistparser.c:134-138`.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum NtFilenameSub {
    /// `PL_WINNT_FILENAME_PRESPACE` = `0`.
    #[default]
    PreSpace = 0,
    /// `PL_WINNT_FILENAME_CONTENT` = `1`. Spaces inside the name are kept
    /// once content has begun.
    Content = 1,
    /// `PL_WINNT_FILENAME_WINEOL` = `2`.
    WinEol = 2,
}

/// The WinNT substate, tagged with the field it belongs to.
///
/// `pl_winNT_substate` (`lib/ftplistparser.c:125-139`), another `union`, made
/// tagged here for the reasons [`UnixSub`] gives. `PL_WINNT_DATE` has no
/// substate in the C and needs none here: the date is read by counting
/// characters.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum WinNtSub {
    /// The time column's substate.
    Time(NtTimeSub),
    /// The size-or-directory column's substate.
    DirOrSize(NtDirOrSizeSub),
    /// The filename's substate.
    Filename(NtFilenameSub),
}

impl Default for WinNtSub {
    /// The zeroed union, read as its first member.
    fn default() -> Self {
        Self::Time(NtTimeSub::PreSpace)
    }
}

// The three extractors, with the fallback [`UnixSub`]'s note explains.
impl WinNtSub {
    /// The time substate.
    const fn time(self) -> NtTimeSub {
        match self {
            Self::Time(sub) => sub,
            _ => NtTimeSub::PreSpace,
        }
    }

    /// The size-or-directory substate.
    const fn dirorsize(self) -> NtDirOrSizeSub {
        match self {
            Self::DirOrSize(sub) => sub,
            _ => NtDirOrSizeSub::PreSpace,
        }
    }

    /// The filename substate.
    const fn filename(self) -> NtFilenameSub {
        match self {
            Self::Filename(sub) => sub,
            _ => NtFilenameSub::PreSpace,
        }
    }
}

/// The parse position, tagged with the listing format it belongs to.
///
/// The outer `union` at `lib/ftplistparser.c:149-159`, which pairs a main
/// state with a substate for each of the two formats. Tagging it means the
/// byte dispatcher matches once and cannot reach a Unix arm while parsing a
/// WinNT listing.
///
/// This tag and [`ParselistData::os_type`] are set together, at the single
/// point where the format is detected. They are both kept because they answer
/// different questions: the tag says which machine is running, and
/// [`OsType`] additionally has a value for "no listing byte has arrived yet",
/// which the C needs at `:1034` and which a two-variant tag cannot express.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum ParseState {
    /// Parsing a Unix listing.
    Unix {
        /// The field being read.
        main: UnixMain,
        /// How far into that field the parse is.
        sub: UnixSub,
    },
    /// Parsing a WinNT listing.
    WinNt {
        /// The field being read.
        main: WinNtMain,
        /// How far into that field the parse is.
        sub: WinNtSub,
    },
}

impl Default for ParseState {
    /// The zeroed union read as its Unix member, which is where the C's
    /// `calloc` leaves it and where a listing whose format is not yet known
    /// waits.
    fn default() -> Self {
        Self::Unix {
            main: UnixMain::TotalSize,
            sub: UnixSub::TotalDirSize(TotalDirSizeSub::Init),
        }
    }
}

/// Where each of a record's six textual fields begins.
///
/// The anonymous struct at `lib/ftplistparser.c:165-172`, with exactly its six
/// members and the C's `size_t` width. Each is an index into the record
/// buffer, and each field runs from there to the zero byte the parse wrote at
/// its end.
///
/// # Zero means absent, and the set is deliberately not cleared per record
///
/// An offset of zero is how `ftp_pl_insert_finfo` (`:310-318`) reports an
/// absent field, which works because no field of a well-formed record can
/// begin at index zero -- index zero holds the Unix type character, and a
/// WinNT record assigns only `filename` and `time`.
///
/// The C never resets this struct between records: it lives on the parser,
/// while the record buffer is replaced for every entry. That is observable. A
/// symlink assigns `symlink_target`, and the entries that follow it in the
/// same listing inherit the assignment, so each of them reports a target read
/// at that stale index of its own buffer. The behaviour is reproduced --
/// resetting the offsets would be a silent change to what a
/// `CURLOPT_CHUNK_BGN_FUNCTION` callback receives -- with one difference
/// forced by the language: a stale index beyond the shorter buffer is a read
/// past the end in C, and here it yields an empty field instead.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Offsets {
    /// `offsets.filename`.
    filename: usize,
    /// `offsets.user`.
    user: usize,
    /// `offsets.group`.
    group: usize,
    /// `offsets.time`.
    time: usize,
    /// `offsets.perm`.
    perm: usize,
    /// `offsets.symlink_target`.
    symlink_target: usize,
}

// ---------------------------------------------------------------------------
// The comparator, and the callback guard around it
// ---------------------------------------------------------------------------

/// A filename comparator, and the callback bookkeeping that goes with it.
///
/// `ftp_pl_insert_finfo` (`lib/ftplistparser.c:320-338`) does three things
/// around each candidate filename, and this trait is those three things:
///
/// ```text
/// compare = data->set.fnmatch;      /* CURLOPT_FNMATCH_FUNCTION, or NULL */
/// if(!compare)
///   compare = Curl_fnmatch;
/// Curl_set_in_callback(data, TRUE);
/// if(compare(data->set.fnmatch_data, wc->pattern, finfo->filename) == 0)
///   ...
/// Curl_set_in_callback(data, FALSE);
/// ```
///
/// It is a trait, and the parser takes it as a parameter, so that this module
/// needs no global mutable state, no type erasure, and no dependency on the
/// module that owns the wildcard driver -- which depends on this one, and so
/// may not be named from here. [`DefaultMatcher`] is the
/// `Curl_fnmatch` half, and [`ParselistData::push`] uses it, so a caller with
/// no user callback configured needs no implementation of its own.
///
/// # Zero means match
///
/// The return value is the integer contract of `curl_fnmatch_callback`
/// (`include/curl/curl.h:368-377`): `CURL_FNMATCHFUNC_MATCH` 0,
/// `CURL_FNMATCHFUNC_NOMATCH` 1 and `CURL_FNMATCHFUNC_FAIL` 2. The C admits a
/// file on zero and excludes it on anything else, which means `NOMATCH` and
/// `FAIL` are indistinguishable at this one call site. They stay distinct in
/// the type, because the callback contract distinguishes them and a user
/// implementation is entitled to return either.
pub(crate) trait FilenameMatcher {
    /// Compares `filename` against `pattern`, returning zero for a match.
    ///
    /// `&mut self` because a user callback may hold state -- the
    /// `CURLOPT_FNMATCH_DATA` pointer exists for exactly that -- and because
    /// the implementation for the default comparator would otherwise be the
    /// only one that could be shared.
    fn compare(&mut self, pattern: &[u8], filename: &[u8]) -> i32;

    /// Called with `true` immediately before [`Self::compare`] and with
    /// `false` immediately afterwards, however that call ends.
    ///
    /// `Curl_set_in_callback` (`lib/ftplistparser.c:326,338`). libcurl uses
    /// the flag to refuse a reentrant call from inside a callback, so leaving
    /// it set would disable that protection for the rest of the transfer.
    /// [`InCallbackGuard`] is what makes the pairing structural rather than a
    /// rule to remember.
    ///
    /// The default implementation does nothing, because
    /// [`DefaultMatcher`] is not a callback: `Curl_fnmatch` is
    /// libcurl's own code and entering it is not entering user code. An
    /// adapter over a user-supplied comparator overrides this.
    fn set_in_callback(&mut self, inside: bool) {
        let _ = inside;
    }
}

/// curl's own comparator: `Curl_fnmatch`.
///
/// The fallback `ftp_pl_insert_finfo` selects when `CURLOPT_FNMATCH_FUNCTION`
/// is unset (`lib/ftplistparser.c:321-323`). It holds no state, so it is a
/// unit type and every parse can use the same one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct DefaultMatcher;

impl FilenameMatcher for DefaultMatcher {
    /// [`crate::util::fnmatch::fnmatch`], with its result taken back to the
    /// integer the callback contract speaks in.
    fn compare(&mut self, pattern: &[u8], filename: &[u8]) -> i32 {
        match fnmatch(pattern, filename) {
            FnMatch::Match => 0,
            FnMatch::NoMatch => 1,
            FnMatch::Fail => 2,
        }
    }
}

/// Holds a matcher's in-callback flag set for as long as it lives.
///
/// The two `Curl_set_in_callback` calls of `ftp_pl_insert_finfo`
/// (`lib/ftplistparser.c:326,338`), turned into a scope. The C's pair is
/// correct only because nothing between them returns early; the guard's
/// [`Drop`] clears the flag however the scope ends, including on an unwind,
/// so a future edit between the two cannot leave the flag latched.
struct InCallbackGuard<'a, M: FilenameMatcher + ?Sized> {
    /// The matcher whose flag is currently set.
    matcher: &'a mut M,
}

impl<'a, M: FilenameMatcher + ?Sized> InCallbackGuard<'a, M> {
    /// Sets the flag and takes charge of clearing it.
    fn enter(matcher: &'a mut M) -> Self {
        matcher.set_in_callback(true);
        Self { matcher }
    }

    /// Runs the comparison with the flag set.
    fn compare(&mut self, pattern: &[u8], filename: &[u8]) -> i32 {
        self.matcher.compare(pattern, filename)
    }
}

impl<M: FilenameMatcher + ?Sized> Drop for InCallbackGuard<'_, M> {
    fn drop(&mut self) {
        self.matcher.set_in_callback(false);
    }
}

// ---------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------

/// The byte at `index`, or the zero the C would have read past a terminator.
///
/// Every index this module computes is derived from the C's own arithmetic and
/// is in bounds where the C dereferences it. This helper is what makes the
/// read total anyway, and it returns the same value a C read would find at the
/// end of a terminated buffer, so a caller's comparison against a character
/// behaves identically.
const fn byte_at(bytes: &[u8], index: usize) -> u8 {
    if index < bytes.len() {
        bytes[index]
    } else {
        0
    }
}

/// `strchr(set, c) != NULL`.
///
/// Three of the C's validations are spelled as `strchr` over a literal:
/// `"rwx-tTsS"` at `lib/ftplistparser.c:439`, `"0123456789-"` at `:895` and
/// `"APM0123456789:"` at `:925`. All three are reproduced through this helper
/// rather than through `contains`, for one measurable reason: `strchr` finds
/// the argument's own terminator, so `strchr(set, 0)` returns a non-null
/// pointer and a zero byte therefore PASSES every one of those three
/// validations in C. `set.contains(&0)` would refuse it. The difference shows
/// only on a listing carrying a zero byte, and reproducing it costs one
/// comparison.
fn set_contains(set: &[u8], c: u8) -> bool {
    c == 0 || set.contains(&c)
}

/// The zero-terminated field beginning at `offset`.
///
/// The C's `str + offset`, read as a C string: the bytes from `offset` up to
/// the first zero, or to the end of the record when the parse wrote no
/// terminator after it. An `offset` past the end yields an empty field, which
/// is where this differs from the C -- there the same index is a read past the
/// buffer. See [`Offsets`] for the one case that reaches it.
fn cstr_at(bytes: &[u8], offset: usize) -> &[u8] {
    let tail = match bytes.get(offset..) {
        Some(tail) => tail,
        None => &[],
    };
    match tail.iter().position(|&b| b == 0) {
        Some(end) => &tail[..end],
        None => tail,
    }
}

/// [`cstr_at`], or [`None`] when the offset is zero.
///
/// The ternaries at `lib/ftplistparser.c:310-318`, which is the whole of the
/// C's absent-field convention.
fn optional_cstr_at(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    if offset == 0 {
        None
    } else {
        Some(cstr_at(bytes, offset))
    }
}

/// The field as owned text.
///
/// The single place where a listing's bytes become a [`String`], which is what
/// makes divergence 2 of the module documentation one edit rather than seven.
/// A byte sequence that is not valid text is replaced rather than rejected: a
/// listing curl accepts must not become a transfer error here.
fn owned_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Whether `haystack` contains `needle`.
///
/// The `strstr(finfo->strings.target, " -> ")` of
/// `lib/ftplistparser.c:331`, which is the test that discards a symlink whose
/// target itself looks like a symlink line. Written as a window scan because
/// the byte slice has no `strstr`, and kept as a named helper so the call site
/// reads as the C does.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// The two field decoders
// ---------------------------------------------------------------------------

/// The file type a Unix listing's leading character names.
///
/// `unix_filetype` (`lib/ftplistparser.c:353-384`). Eight characters are
/// accepted and every other byte is a malformed listing -- including `-` in
/// any position but the first, which cannot reach here, and including a
/// letter that names a type on some other system.
///
/// # Errors
///
/// `CURLE_FTP_BAD_FILE_LIST` for any byte outside the eight.
fn unix_filetype(c: u8) -> CurlResult<FileType> {
    match c {
        b'-' => Ok(FileType::File),
        b'd' => Ok(FileType::Directory),
        b'l' => Ok(FileType::Symlink),
        b'p' => Ok(FileType::NamedPipe),
        b's' => Ok(FileType::Socket),
        b'c' => Ok(FileType::DeviceChar),
        b'b' => Ok(FileType::DeviceBlock),
        b'D' => Ok(FileType::Door),
        _ => Err(Error::with_context(
            CURLcode::FtpBadFileList,
            "FTP listing: unrecognised file type character",
        )),
    }
}

/// The twelve permission bits nine characters encode.
///
/// `ftp_pl_get_permission` (`lib/ftplistparser.c:231-294`), bit for bit. The
/// layout is the familiar octal one -- user, group and other, three bits each
/// -- with three extra bits above them for set-user-id, set-group-id and the
/// sticky bit:
///
/// ```text
/// index  0    1    2       3    4    5       6    7    8
/// char   r    w    x/s/S   r    w    x/s/S   r    w    x/t/T
/// bit  1<<8 1<<7 1<<6    1<<5 1<<4 1<<3    1<<2 1<<1 1<<0
/// extra           1<<11                    1<<10          1<<9
/// ```
///
/// The three extra positions distinguish an upper-case letter from a lower-case
/// one, and the distinction is not cosmetic: `s` means the special bit is set
/// AND the execute bit is set, while `S` means the special bit is set and the
/// execute bit is NOT. The same holds for `t` against `T` in the last
/// position. Everything else -- `1<<11` for set-user-id, `1<<10` for
/// set-group-id, `1<<9` for sticky -- follows from that.
///
/// Any position holding neither the character it expects nor `-` adds
/// [`FTP_LP_MALFORMATED_PERM`] and the rest of the field is still examined,
/// so one call reports every malformed position at once. The caller turns the
/// marker into `CURLE_FTP_BAD_FILE_LIST`.
///
/// A short slice reads as zeros through [`byte_at`], which no position
/// expects, so it too comes back marked. The C reads past its terminator
/// there; a well-formed call site cannot produce it, and this one cannot
/// misbehave if a future one does.
fn ftp_pl_get_permission(text: &[u8]) -> u32 {
    let at = |index: usize| byte_at(text, index);
    let mut permissions: u32 = 0;

    // USER -- `lib/ftplistparser.c:234-253`.
    if at(0) == b'r' {
        permissions |= 1 << 8;
    } else if at(0) != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if at(1) == b'w' {
        permissions |= 1 << 7;
    } else if at(1) != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if at(2) == b'x' {
        permissions |= 1 << 6;
    } else if at(2) == b's' {
        permissions |= 1 << 6;
        permissions |= 1 << 11;
    } else if at(2) == b'S' {
        permissions |= 1 << 11;
    } else if at(2) != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }

    // GROUP -- `:254-272`.
    if at(3) == b'r' {
        permissions |= 1 << 5;
    } else if at(3) != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if at(4) == b'w' {
        permissions |= 1 << 4;
    } else if at(4) != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if at(5) == b'x' {
        permissions |= 1 << 3;
    } else if at(5) == b's' {
        permissions |= 1 << 3;
        permissions |= 1 << 10;
    } else if at(5) == b'S' {
        permissions |= 1 << 10;
    } else if at(5) != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }

    // others -- `:273-291`.
    if at(6) == b'r' {
        permissions |= 1 << 2;
    } else if at(6) != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if at(7) == b'w' {
        permissions |= 1 << 1;
    } else if at(7) != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }
    if at(8) == b'x' {
        permissions |= 1;
    } else if at(8) == b't' {
        permissions |= 1;
        permissions |= 1 << 9;
    } else if at(8) == b'T' {
        permissions |= 1 << 9;
    } else if at(8) != b'-' {
        permissions |= FTP_LP_MALFORMATED_PERM;
    }

    permissions
}

/// A `CURLE_FTP_BAD_FILE_LIST` carrying the line that produced it.
///
/// Every rejection the C spells as `return CURLE_FTP_BAD_FILE_LIST` becomes
/// one of these. The code is frozen by AAP 0.8.1 -- an unparsable listing is
/// this error and not a more descriptive one -- so the context string is
/// diagnostic only and never reaches a caller comparing codes.
fn bad_file_list(context: &'static str) -> Error {
    Error::with_context(CURLcode::FtpBadFileList, context)
}

/// The slice beginning at `offset`, or an empty slice when `offset` is past
/// the end.
///
/// The C's `mem + parser->item_offset` handed to a number parser, which reads
/// forwards until a non-digit. Unlike [`cstr_at`] this keeps everything after
/// the field's terminator, because a caller needs to see where the parse
/// stopped -- `parse_unix_size` tests exactly that at
/// `lib/ftplistparser.c:589`.
fn tail_at(bytes: &[u8], offset: usize) -> &[u8] {
    match bytes.get(offset..) {
        Some(tail) => tail,
        None => &[],
    }
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// What the byte machine wants done with the record it was given.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    /// Keep it: the record is not finished.
    Hold,
    /// It is finished. Match it, and queue or discard it accordingly.
    Complete,
}

/// Whether the `total <n>` arm consumed the byte or handed it on.
///
/// The C expresses this by testing whether the arm changed the main state and
/// then falling through a `switch` (`lib/ftplistparser.c:842-844`). A returned
/// value says the same thing without depending on statement order, and it
/// separates the two ways the arm can leave the state at `PL_UNIX_FILETYPE`
/// -- which is the difference divergence 1 of the module documentation turns
/// on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TotalSize {
    /// The byte belonged to the `total <n>` line and is spent.
    Consumed,
    /// The byte was not a `t`, so no `total` line is present and this byte is
    /// the first character of a file entry. It must be reprocessed as a file
    /// type, not dropped.
    FallThrough,
}

/// The FTP listing parser.
///
/// `struct ftp_parselist_data` (`lib/ftplistparser.c:142-173`), whose C
/// members are all present: the detected format, the tagged main-and-substate
/// pair, the latched error, the record under construction, the current item's
/// length and offset, and the six field offsets.
///
/// Two things are held here that the C keeps on `struct WildcardData`
/// instead:
///
/// * The pattern. The C reads `wc->pattern` at the moment it compares
///   (`:327`), reaching across from the parser to the wildcard state. A copy
///   is taken at construction here so that [`ParselistData::push`] has the
///   signature AAP 0.4.1 specifies -- one slice of listing bytes and nothing
///   else -- rather than requiring the caller to thread the pattern through
///   every call. [`WildcardData::pattern`] remains the configured value and
///   outlives the parser.
/// * The accepted entries. The C appends into `wc->filelist` (`:341`), which
///   would be a borrow of the very structure that owns the parser. Entries
///   accumulate here in arrival order instead and the driver moves them across
///   with [`ParselistData::take_accepted`], which keeps the ownership acyclic
///   without changing the order or the contents.
///
/// `Curl_ftp_parselist_data_alloc` and `Curl_ftp_parselist_data_free`
/// (`:210-222`) become [`ParselistData::new`] and drop glue.
#[derive(Debug)]
pub(crate) struct ParselistData {
    /// `os_type`.
    os_type: OsType,
    /// `state`, tagged.
    state: ParseState,
    /// `error`, latched. [`None`] is the C's `CURLE_OK`.
    error: Option<CURLcode>,
    /// `file_data`.
    file_data: Option<InProgressFile>,
    /// `item_length`, in the C's `unsigned int` width.
    item_length: u32,
    /// `item_offset`, in the C's `size_t` width.
    item_offset: usize,
    /// `offsets`.
    offsets: Offsets,
    /// The wildcard pattern each filename is compared against.
    pattern: Vec<u8>,
    /// Entries that matched, in arrival order.
    accepted: VecDeque<FileInfo>,
}

// THE ALLOWANCE, AND WHEN IT COMES OFF.
//
// Nothing in this crate calls this parser yet. The one consumer AAP 0.4.1
// gives it is the wildcard driver, which arrives with `ftp/mod.rs`, and until
// then `push` is a live root reached from nowhere -- which makes every state,
// every substate variant, every field decoder and every helper in this file
// unreachable along with it, and a zero-warning build is a gate.
//
// The allowance therefore sits HERE, on the one implementation block that is
// the entry point, and not on a module: `src/lib.rs`'s
// `no_lint_level_for_dead_code_is_set_on_a_crate_or_module_root` gate forbids
// the module form outright, because a module-wide allowance would go on hiding
// the next unreferenced item somebody adds. Marking the entry point live is
// enough for the whole graph below it, so this is the only one in the file
// beyond the four on items that are part of the public contract without being
// on any parse path.
//
// It comes off when the driver lands and calls `push`.
#[allow(dead_code)]
impl ParselistData {
    /// A parser for `pattern`.
    ///
    /// Every state starts where `curlx_calloc` leaves the C's
    /// (`lib/ftplistparser.c:212`): format unknown, Unix main state at
    /// `PL_UNIX_TOTALSIZE`, no error, no record, all offsets zero.
    #[must_use]
    pub(crate) fn new(pattern: &[u8]) -> Self {
        Self {
            os_type: OsType::default(),
            state: ParseState::default(),
            error: None,
            file_data: None,
            item_length: 0,
            item_offset: 0,
            offsets: Offsets::default(),
            pattern: pattern.to_vec(),
            accepted: VecDeque::new(),
        }
    }

    /// Feeds listing bytes through the machine, comparing filenames with
    /// curl's own matcher.
    ///
    /// The write-callback replacement: `Curl_ftp_parselist`
    /// (`lib/ftplistparser.c:1013-1089`) with `data->set.fnmatch` unset, so
    /// that `Curl_fnmatch` is the comparator (`:321-323`). `bytes` may be any
    /// slice of the response, including one byte, and splitting a response
    /// differently cannot change the outcome.
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` for a listing this machine cannot read, and
    /// `CURLE_OUT_OF_MEMORY` when one record reaches
    /// [`MAX_FTPLIST_BUFFER`]. Both are frozen mappings; see
    /// [`ParselistData::push_matching`] for what a failure does to the
    /// parser.
    pub(crate) fn push(&mut self, bytes: &[u8]) -> CurlResult<()> {
        self.push_matching(bytes, &mut DefaultMatcher)
    }

    /// [`ParselistData::push`] with a caller-supplied comparator.
    ///
    /// The `CURLOPT_FNMATCH_FUNCTION` half of `:321-323`. `matcher` is
    /// `?Sized`, so a caller holding `&mut dyn FilenameMatcher` may pass it
    /// directly; nothing here requires that shape.
    ///
    /// # A failure is permanent
    ///
    /// The C latches the code into `parser->error` and every later call
    /// returns immediately from `:1024-1032`, whose comment spells out the
    /// scenario: a first call succeeds, a second fails, and the third "is
    /// skipped RIGHT HERE and the error is handled later in wc_statemach()".
    /// This reproduces that exactly. Once a call has failed, the same error
    /// comes back from every subsequent call, no byte is examined, no entry is
    /// queued and no memory is touched. The record under construction is
    /// released at the moment of the first failure, matching the C's `fail:`
    /// path at `:1080-1088`, so no half-parsed entry survives.
    ///
    /// The C additionally reports success by returning the byte count it was
    /// given -- even on failure, so that the transfer keeps feeding it until
    /// the wildcard state machine notices `parser->error`. There is no count
    /// to manufacture here: a successful call consumed the whole slice, and a
    /// failure says so directly.
    ///
    /// # Errors
    ///
    /// As [`ParselistData::push`], plus the latched error from any earlier
    /// failure.
    pub(crate) fn push_matching<M>(
        &mut self,
        bytes: &[u8],
        matcher: &mut M,
    ) -> CurlResult<()>
    where
        M: FilenameMatcher + ?Sized,
    {
        // `:1024-1032`.
        if let Some(code) = self.error {
            return Err(Error::new(code));
        }

        // `:1034-1037`. The test is on the FIRST byte of the first non-empty
        // chunk, so an empty call leaves the format unknown and decides
        // nothing -- which is what lets a server's response arrive in any
        // number of pieces.
        if self.os_type == OsType::Unknown {
            if let Some(&first) = bytes.first() {
                if is_digit(first) {
                    self.os_type = OsType::WinNt;
                    self.state = ParseState::WinNt {
                        main: WinNtMain::Date,
                        sub: WinNtSub::default(),
                    };
                } else {
                    self.os_type = OsType::Unix;
                    self.state = ParseState::Unix {
                        main: UnixMain::TotalSize,
                        sub: UnixSub::default(),
                    };
                }
            }
        }

        // `:1039-1077`. The C's `default:` arm at `:1067-1069` -- the one
        // that reports a short write when the format is still unknown -- has
        // no counterpart, and needs none: detection above precedes the loop
        // and the loop body cannot run without a byte, so the arm is
        // unreachable in the C as well. The tagged state makes it
        // unrepresentable here.
        for &c in bytes {
            self.step(c, matcher)?;
        }
        Ok(())
    }

    /// The latched error, without clearing it.
    ///
    /// `Curl_ftp_parselist_geterror` (`lib/ftplistparser.c:224-227`), whose
    /// whole body is `return pl_data->error`. `CURLcode::Ok` when no call has
    /// failed, which is the C's zero-initialized member.
    #[must_use]
    pub(crate) fn geterror(&self) -> CURLcode {
        match self.error {
            Some(code) => code,
            None => CURLcode::Ok,
        }
    }

    /// The listing format, once a byte has been seen.
    #[must_use]
    pub(crate) fn os_type(&self) -> OsType {
        self.os_type
    }

    /// The pattern filenames are compared against.
    #[must_use]
    pub(crate) fn pattern(&self) -> &[u8] {
        &self.pattern
    }

    /// The matched entries so far, oldest first.
    #[must_use]
    pub(crate) fn accepted(&self) -> &VecDeque<FileInfo> {
        &self.accepted
    }

    /// Takes the matched entries, leaving the queue empty.
    ///
    /// How the wildcard driver moves entries into
    /// [`WildcardData::filelist`] without borrowing the structure that owns
    /// this parser. Order is preserved.
    pub(crate) fn take_accepted(&mut self) -> VecDeque<FileInfo> {
        std::mem::take(&mut self.accepted)
    }

    /// `parser->item_offset + parser->item_length - 1`: the index of the
    /// delimiter that has just ended a field.
    ///
    /// The C writes its terminator there at `lib/ftplistparser.c:487`, `:523`,
    /// `:552`, `:587`, `:664`, `:705`, `:713`, `:802`, `:813` and `:920`, and
    /// reads the field from `item_offset` up to it. Both saturating steps are
    /// unreachable: `item_length` is at least one wherever this is called,
    /// because a field is only ended by the delimiter that follows at least
    /// one byte of content, and the sum is bounded by the record ceiling.
    const fn item_end(&self) -> usize {
        self.item_offset
            .saturating_add(self.item_length as usize)
            .saturating_sub(1)
    }

    /// Records the error and releases the record under construction.
    ///
    /// `parser->error = result` at `lib/ftplistparser.c:1072` together with
    /// the `fail:` path at `:1082-1086`. The record is already out of
    /// [`ParselistData::file_data`] by the time this runs -- the caller took
    /// it for the duration of the byte -- so dropping the caller's local IS
    /// the release, and the assignment here only records that the slot is
    /// empty.
    fn latch(&mut self, error: Error) -> Error {
        self.error = Some(error.code());
        self.file_data = None;
        error
    }

    /// Replaces the Unix main state and substate together.
    ///
    /// Every transition sets both, which is what keeps the pair consistent and
    /// makes [`UnixSub`]'s mismatch fallback unreachable. Where the C changes
    /// only the main state and leaves its union alone, the caller passes the
    /// substate it already holds.
    fn set_unix(&mut self, main: UnixMain, sub: UnixSub) {
        self.state = ParseState::Unix { main, sub };
    }

    /// Replaces the WinNT main state and substate together.
    fn set_winnt(&mut self, main: WinNtMain, sub: WinNtSub) {
        self.state = ParseState::WinNt { main, sub };
    }

    /// One byte through the machine.
    ///
    /// The body of the C's `while` loop (`lib/ftplistparser.c:1039-1077`), in
    /// its order: take or create the record, append the byte to it, run the
    /// format's machine, and act on what comes back.
    fn step<M>(&mut self, c: u8, matcher: &mut M) -> CurlResult<()>
    where
        M: FilenameMatcher + ?Sized,
    {
        // `:1042-1051`. The record is created lazily, once per entry, and the
        // item cursor is reset with it -- which is the only place those two
        // are reset, and the reason a completed entry leaves them alone.
        // Taking it out of the parser for the duration of the byte is what
        // lets the machine hold the record and the parser state at once.
        let mut infop = match self.file_data.take() {
            Some(existing) => existing,
            None => {
                self.item_offset = 0;
                self.item_length = 0;
                InProgressFile::default()
            }
        };

        // `:1055-1058`. Every failure the buffer can report becomes
        // `CURLE_OUT_OF_MEMORY`, the ceiling included, because that is the
        // single mapping the C performs and AAP 0.8.1 freezes it. The record
        // is not put back, so it is dropped here.
        if infop.buf.addn(&[c]).is_err() {
            return Err(self.latch(Error::with_context(
                CURLcode::OutOfMemory,
                "FTP listing: one line exceeded the record buffer",
            )));
        }

        // `:1060-1070`.
        let outcome = match self.state {
            ParseState::Unix { main, sub } => {
                self.parse_unix(main, sub, c, &mut infop)
            }
            ParseState::WinNt { main, sub } => {
                self.parse_winnt(main, sub, c, &mut infop)
            }
        };

        // `:1071-1076`.
        match outcome {
            Ok(Step::Hold) => {
                self.file_data = Some(infop);
                Ok(())
            }
            Ok(Step::Complete) => {
                self.insert_finfo(infop, matcher);
                Ok(())
            }
            Err(error) => Err(self.latch(error)),
        }
    }

    /// A completed record: compare it, then queue or discard it.
    ///
    /// `ftp_pl_insert_finfo` (`lib/ftplistparser.c:296-349`). The C's return
    /// type is `CURLcode` and its only value is `CURLE_OK`; there is nothing
    /// to propagate, so this returns nothing.
    ///
    /// The record arrives by value. That is the whole of the C's `file_data =
    /// NULL` at `:347` and its `Curl_fileinfo_cleanup` at `:344`: a queued
    /// entry is built from the record and the record is dropped, and a
    /// discarded one is dropped without being built. Either way the parser's
    /// slot is already empty, so the next byte starts a fresh entry.
    fn insert_finfo<M>(&mut self, infop: InProgressFile, matcher: &mut M)
    where
        M: FilenameMatcher + ?Sized,
    {
        let bytes = infop.buf.as_slice();

        // `:307-318`. `filename` and `time` unconditionally; the other four
        // only where the offset is non-zero.
        let filename = cstr_at(bytes, self.offsets.filename);
        let time = cstr_at(bytes, self.offsets.time);
        let perm = optional_cstr_at(bytes, self.offsets.perm);
        let user = optional_cstr_at(bytes, self.offsets.user);
        let group = optional_cstr_at(bytes, self.offsets.group);
        let target = optional_cstr_at(bytes, self.offsets.symlink_target);

        // `:320-338`. The comparator sees the record's own bytes, not the
        // owned text built below, so a name that is not valid text is still
        // compared exactly as the C compares it.
        let verdict = {
            let mut guard = InCallbackGuard::enter(matcher);
            guard.compare(&self.pattern, filename)
        };

        // `:327-337`. Zero admits the entry; anything else excludes it. A
        // symlink whose target itself contains " -> " is then excluded as
        // well, which is how a listing line carrying two arrows is refused
        // rather than half-parsed.
        let mut add = verdict == 0;
        if add && infop.info.filetype == FileType::Symlink {
            if let Some(target) = target {
                if contains_subslice(target, b" -> ") {
                    add = false;
                }
            }
        }

        // `:340-345`.
        if add {
            self.accepted.push_back(FileInfo {
                filename: owned_text(filename),
                filetype: infop.info.filetype,
                time: infop.info.time,
                perm: infop.info.perm,
                uid: infop.info.uid,
                gid: infop.info.gid,
                size: infop.info.size,
                hardlinks: infop.info.hardlinks,
                strings: FileInfoStrings {
                    time: owned_text(time),
                    perm: perm.map(owned_text),
                    user: user.map(owned_text),
                    group: group.map(owned_text),
                    target: target.map(owned_text),
                },
                flags: infop.info.flags,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// The Unix machine
// ---------------------------------------------------------------------------

impl ParselistData {
    /// One byte of a Unix listing.
    ///
    /// `parse_unix` (`lib/ftplistparser.c:829-879`), the dispatcher over the
    /// ten main states. The `total <n>` arm is handled before the dispatch
    /// because it is the one arm that can hand its byte on rather than consume
    /// it; see [`TotalSize`] and divergence 1 of the module documentation.
    fn parse_unix(
        &mut self,
        main: UnixMain,
        sub: UnixSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        // `:838-844`.
        let main = if main == UnixMain::TotalSize {
            match self.parse_unix_totalsize(sub.total_dirsize(), c, infop)? {
                TotalSize::Consumed => return Ok(Step::Hold),
                TotalSize::FallThrough => UnixMain::FileType,
            }
        } else {
            main
        };

        match main {
            // `:845-852`. `TotalSize` shares this arm only so that the match
            // stays exhaustive without a panicking arm: the branch above
            // either returned or replaced it with `FileType`, so it cannot
            // arrive here.
            UnixMain::TotalSize | UnixMain::FileType => {
                // The C writes through `&finfo->filetype`, so a rejected
                // character leaves the previous value in place. Propagating
                // before the assignment has the same effect.
                infop.info.filetype = unix_filetype(c)?;
                self.set_unix(UnixMain::Permission, sub);
                self.item_length = 0;
                // Absolute, not relative: the type character occupies index
                // zero of the record and the permissions begin at index one.
                // That holds because a record's buffer starts empty -- either
                // freshly created, or reset by a `total` line.
                self.item_offset = 1;
                Ok(Step::Hold)
            }
            UnixMain::Permission => self.parse_unix_permission(c, infop),
            UnixMain::Hlinks => self.parse_unix_hlinks(sub.hlinks(), c, infop),
            UnixMain::User => self.parse_unix_user(sub.user(), c, infop),
            UnixMain::Group => self.parse_unix_group(sub.group(), c, infop),
            UnixMain::Size => self.parse_unix_size(sub.size(), c, infop),
            UnixMain::Time => self.parse_unix_time(sub.time(), c, infop),
            UnixMain::Filename => {
                self.parse_unix_filename(sub.filename(), c, infop)
            }
            UnixMain::Symlink => {
                self.parse_unix_symlink(sub.symlink(), c, infop)
            }
        }
    }

    /// The optional `total <n>` line that opens many Unix listings.
    ///
    /// `parse_unix_totalsize` (`lib/ftplistparser.c:386-431`).
    ///
    /// Only a leading `t` enters the line: any other first byte means there is
    /// no `total` line, and that byte is the file type of the first entry and
    /// must be reprocessed rather than dropped.
    ///
    /// On the line feed the accumulated text must begin exactly `total `,
    /// followed by blanks, then digits, then nothing. `total ` with no digits
    /// at all is accepted, because the C's `endptr` then sits on the
    /// terminator and its `if(*endptr)` is false.
    ///
    /// A carriage return is removed rather than tolerated: the C decrements
    /// both the item length and the buffer length (`:405-409`), so the line
    /// the prefix test sees is the same whether the server sent LF or CRLF.
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` for a line that begins with `t` and is not a
    /// well-formed `total` line.
    fn parse_unix_totalsize(
        &mut self,
        sub: TotalDirSizeSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<TotalSize> {
        let len = infop.buf.len();

        match sub {
            // `:393-402`.
            TotalDirSizeSub::Init => {
                if c == b't' {
                    self.set_unix(
                        UnixMain::TotalSize,
                        UnixSub::TotalDirSize(TotalDirSizeSub::Reading),
                    );
                    self.item_length = self.item_length.saturating_add(1);
                    Ok(TotalSize::Consumed)
                } else {
                    self.set_unix(
                        UnixMain::FileType,
                        UnixSub::TotalDirSize(sub),
                    );
                    Ok(TotalSize::FallThrough)
                }
            }
            // `:403-428`.
            TotalDirSizeSub::Reading => {
                self.item_length = self.item_length.saturating_add(1);

                if c == b'\r' {
                    // `:405-409`. Undo the count and drop the byte from the
                    // record, so the line feed that follows sees the line
                    // without it.
                    self.item_length = self.item_length.saturating_sub(1);
                    if len != 0 {
                        // Cannot fail: a shorter length is always accepted.
                        // Reported rather than discarded so that no result is
                        // ignored anywhere in this module.
                        if let Err(code) = infop.buf.setlen(len - 1) {
                            return Err(Error::new(code));
                        }
                    }
                    return Ok(TotalSize::Consumed);
                }

                if c != b'\n' {
                    return Ok(TotalSize::Consumed);
                }

                // `:410-427`. `mem[parser->item_length - 1] = 0`: unlike every
                // other field, this one counts from the start of the record,
                // because a `total` line has no item offset. The terminator
                // goes over the line feed, so the line reads as the C's string
                // does.
                infop.poke_nul((self.item_length as usize).saturating_sub(1));

                let line = cstr_at(infop.buf.as_slice(), 0);
                let Some(digits) = line.strip_prefix(b"total ".as_slice())
                else {
                    return Err(bad_file_list(
                        "FTP listing: line begins with t but is not a total \
                         line",
                    ));
                };

                // `:416-421`. Blanks, then digits, then the terminator and
                // nothing else.
                let mut endptr = digits;
                str_passblanks(&mut endptr);
                while is_digit(byte_at(endptr, 0)) {
                    endptr = tail_at(endptr, 1);
                }
                if byte_at(endptr, 0) != 0 {
                    return Err(bad_file_list(
                        "FTP listing: total line is not a count",
                    ));
                }

                // `:422-423`. The line is discarded and the record buffer
                // starts again, so the first file entry begins at index zero
                // exactly as it would have without a total line.
                //
                // Divergence 1: the C falls through to the file-type arm here
                // and hands it this line feed, which no file type admits. The
                // line feed is spent, so it is consumed.
                self.set_unix(
                    UnixMain::FileType,
                    UnixSub::TotalDirSize(TotalDirSizeSub::Init),
                );
                infop.buf.reset();
                Ok(TotalSize::Consumed)
            }
        }
    }

    /// The nine permission characters, and the space that ends them.
    ///
    /// `parse_unix_permission` (`lib/ftplistparser.c:433-461`). The field is
    /// fixed width, so it is read by counting rather than by looking for a
    /// delimiter, and the count is what decides which of the two tests below
    /// applies.
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` for a character outside `rwx-tTsS` in the
    /// first nine positions, for anything but a space in the tenth, and for a
    /// field that [`ftp_pl_get_permission`] marks malformed -- which is the
    /// case where all nine characters are individually legal but one of them
    /// is in a position that does not accept it, `rwxrwxrwt` for instance
    /// carrying its sticky bit where the group's execute bit belongs.
    fn parse_unix_permission(
        &mut self,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        self.item_length = self.item_length.saturating_add(1);

        // `:439-440`.
        if self.item_length <= 9 && !set_contains(b"rwx-tTsS", c) {
            return Err(bad_file_list(
                "FTP listing: bad character in the permission field",
            ));
        }

        // `:442-459`.
        if self.item_length == 10 {
            if c != b' ' {
                return Err(bad_file_list(
                    "FTP listing: permission field is not nine characters",
                ));
            }

            // `:447`. Index ten, absolutely: one type character plus nine
            // permission characters, so the space just appended is there.
            infop.poke_nul(10);

            let perm = ftp_pl_get_permission(tail_at(infop.buf.as_slice(), 1));
            if perm & FTP_LP_MALFORMATED_PERM != 0 {
                return Err(bad_file_list(
                    "FTP listing: malformed permission field",
                ));
            }

            infop.info.flags |= FileInfo::KNOWN_PERM;
            infop.info.perm = perm;
            self.offsets.perm = self.item_offset;

            self.item_length = 0;
            self.set_unix(
                UnixMain::Hlinks,
                UnixSub::Hlinks(HlinksSub::PreSpace),
            );
        }
        Ok(Step::Hold)
    }

    /// The hard-link count.
    ///
    /// `parse_unix_hlinks` (`lib/ftplistparser.c:463-503`). Padding is skipped,
    /// then digits are collected to the next space.
    ///
    /// A count the number parser refuses -- one long enough to overflow the
    /// bound, which is the only way it can refuse a field already checked
    /// digit by digit -- leaves [`FileInfo::KNOWN_HLINKCOUNT`] unset and the
    /// value at zero, and the parse CONTINUES. That is the C at `:489-492`:
    /// the flag guards the value, so an unusable count is reported as absent
    /// rather than as a broken listing.
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` when the field does not begin with a digit,
    /// or when a non-digit appears inside it.
    fn parse_unix_hlinks(
        &mut self,
        sub: HlinksSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        let len = infop.buf.len();

        match sub {
            // `:471-481`.
            HlinksSub::PreSpace => {
                if c != b' ' {
                    if is_digit(c) && len != 0 {
                        self.item_offset = len - 1;
                        self.item_length = 1;
                        self.set_unix(
                            UnixMain::Hlinks,
                            UnixSub::Hlinks(HlinksSub::Number),
                        );
                    } else {
                        return Err(bad_file_list(
                            "FTP listing: hard-link count is not a number",
                        ));
                    }
                }
            }
            // `:482-501`.
            HlinksSub::Number => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b' ' {
                    infop.poke_nul(self.item_end());

                    // `:489`. `LONG_MAX` is the C's bound and equals
                    // `i64::MAX` on every target of AAP 0.8.3, all four of
                    // which are 64-bit.
                    let parsed = {
                        let mut cursor =
                            tail_at(infop.buf.as_slice(), self.item_offset);
                        str_number(&mut cursor, i64::MAX).ok()
                    };
                    if let Some(hlinks) = parsed {
                        infop.info.flags |= FileInfo::KNOWN_HLINKCOUNT;
                        infop.info.hardlinks = hlinks;
                    }

                    self.item_length = 0;
                    self.item_offset = 0;
                    self.set_unix(
                        UnixMain::User,
                        UnixSub::User(UserSub::PreSpace),
                    );
                } else if !is_digit(c) {
                    return Err(bad_file_list(
                        "FTP listing: non-digit in the hard-link count",
                    ));
                }
            }
        }
        Ok(Step::Hold)
    }

    /// The owner column.
    ///
    /// `parse_unix_user` (`lib/ftplistparser.c:506-532`). Unlike the two
    /// numeric columns this one validates nothing: format 3 of the C's header
    /// comment (`:35-36`) shows the column holding a bare number, and a server
    /// may put anything there, so the field is whatever lies between the
    /// padding and the next space.
    fn parse_unix_user(
        &mut self,
        sub: UserSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        let len = infop.buf.len();

        match sub {
            // `:513-519`.
            UserSub::PreSpace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.set_unix(
                        UnixMain::User,
                        UnixSub::User(UserSub::Parsing),
                    );
                }
            }
            // `:520-530`.
            UserSub::Parsing => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b' ' {
                    infop.poke_nul(self.item_end());
                    self.offsets.user = self.item_offset;
                    self.set_unix(
                        UnixMain::Group,
                        UnixSub::Group(GroupSub::PreSpace),
                    );
                    self.item_offset = 0;
                    self.item_length = 0;
                }
            }
        }
        Ok(Step::Hold)
    }

    /// The group column.
    ///
    /// `parse_unix_group` (`lib/ftplistparser.c:535-561`), the owner column's
    /// twin: the same two substates, the same absence of validation, and the
    /// group offset recorded instead of the owner's.
    fn parse_unix_group(
        &mut self,
        sub: GroupSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        let len = infop.buf.len();

        match sub {
            // `:542-548`.
            GroupSub::PreSpace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.set_unix(
                        UnixMain::Group,
                        UnixSub::Group(GroupSub::Name),
                    );
                }
            }
            // `:549-559`.
            GroupSub::Name => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b' ' {
                    infop.poke_nul(self.item_end());
                    self.offsets.group = self.item_offset;
                    self.set_unix(
                        UnixMain::Size,
                        UnixSub::Size(SizeSub::PreSpace),
                    );
                    self.item_offset = 0;
                    self.item_length = 0;
                }
            }
        }
        Ok(Step::Hold)
    }

    /// The size column.
    ///
    /// `parse_unix_size` (`lib/ftplistparser.c:564-604`). Three conditions have
    /// to hold before the size is believed, and the C spells all three at
    /// `:588-589`: the number must parse, the parse must have reached the
    /// field's terminator, and the value must not be the maximum -- which is
    /// the value an overflow saturates to in some parsers and is therefore
    /// treated as "no answer" rather than as a real size.
    ///
    /// If the number does not parse at all, nothing moves: no flag, no value,
    /// no state change and no error. The machine stays inside the size column,
    /// which the C reaches by returning past its whole transition block. Only
    /// a field long enough to overflow can produce it, and the next byte is
    /// then judged as a continuation of the same number.
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` when the column does not begin with a digit,
    /// or when a non-digit appears inside it.
    fn parse_unix_size(
        &mut self,
        sub: SizeSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        let len = infop.buf.len();

        match sub {
            // `:571-580`.
            SizeSub::PreSpace => {
                if c != b' ' {
                    if is_digit(c) && len != 0 {
                        self.item_offset = len - 1;
                        self.item_length = 1;
                        self.set_unix(
                            UnixMain::Size,
                            UnixSub::Size(SizeSub::Number),
                        );
                    } else {
                        return Err(bad_file_list(
                            "FTP listing: size column is not a number",
                        ));
                    }
                }
            }
            // `:582-601`.
            SizeSub::Number => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b' ' {
                    infop.poke_nul(self.item_end());

                    // `:588`. The byte the parse stopped on is the C's
                    // `p[0]`, which its next line tests against the
                    // terminator.
                    let parsed = {
                        let mut cursor =
                            tail_at(infop.buf.as_slice(), self.item_offset);
                        str_numblanks(&mut cursor)
                            .ok()
                            .map(|size| (size, byte_at(cursor, 0)))
                    };

                    if let Some((fsize, stopped_on)) = parsed {
                        // `:589-592`.
                        if stopped_on == 0 && fsize != i64::MAX {
                            infop.info.flags |= FileInfo::KNOWN_SIZE;
                            infop.info.size = fsize;
                        }
                        self.item_length = 0;
                        self.item_offset = 0;
                        self.set_unix(
                            UnixMain::Time,
                            UnixSub::Time(TimeSub::PrePart1),
                        );
                    }
                } else if !is_digit(c) {
                    return Err(bad_file_list(
                        "FTP listing: non-digit in the size column",
                    ));
                }
            }
        }
        Ok(Step::Hold)
    }

    /// The three-part date and time.
    ///
    /// `parse_unix_time` (`lib/ftplistparser.c:607-679`). Six substates read
    /// three whitespace-separated parts, which covers both `Jan 29 23:32` and
    /// `Jan 29 1997` without deciding in advance which is present -- the C's
    /// formats 1 and 2 (`:31-34`).
    ///
    /// The accepted characters widen as the parts go by: parts one and two
    /// take letters, digits and a full stop, and part three additionally takes
    /// a colon, because that is where a time of day appears. Nothing here
    /// interprets the text; the whole field becomes
    /// [`FileInfoStrings::time`] and the numeric [`FileInfo::time`] stays
    /// zero.
    ///
    /// The space that ends part three is also where the entry's shape is
    /// decided: a symlink goes on to the symlink states and everything else to
    /// the filename states.
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` when a part does not begin with a letter or
    /// digit, or contains a character its position does not accept.
    fn parse_unix_time(
        &mut self,
        sub: TimeSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        let len = infop.buf.len();
        let next = |sub| UnixSub::Time(sub);

        match sub {
            // `:616-626`. No count here: the field's own offset is taken from
            // this byte, so counting starts at one rather than continuing.
            TimeSub::PrePart1 => {
                if c != b' ' {
                    if is_alnum(c) && len != 0 {
                        self.item_offset = len - 1;
                        self.item_length = 1;
                        self.set_unix(UnixMain::Time, next(TimeSub::Part1));
                    } else {
                        return Err(bad_file_list(
                            "FTP listing: time field does not begin with a \
                             letter or digit",
                        ));
                    }
                }
            }
            // `:627-635`.
            TimeSub::Part1 => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b' ' {
                    self.set_unix(UnixMain::Time, next(TimeSub::PrePart2));
                } else if !is_alnum(c) && c != b'.' {
                    return Err(bad_file_list(
                        "FTP listing: bad character in the first time part",
                    ));
                }
            }
            // `:636-644`. The padding is counted as part of the field, which
            // is why a two-space gap survives into the stored text.
            TimeSub::PrePart2 => {
                self.item_length = self.item_length.saturating_add(1);
                if c != b' ' {
                    if is_alnum(c) {
                        self.set_unix(UnixMain::Time, next(TimeSub::Part2));
                    } else {
                        return Err(bad_file_list(
                            "FTP listing: second time part does not begin \
                             with a letter or digit",
                        ));
                    }
                }
            }
            // `:645-651`.
            TimeSub::Part2 => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b' ' {
                    self.set_unix(UnixMain::Time, next(TimeSub::PrePart3));
                } else if !is_alnum(c) && c != b'.' {
                    return Err(bad_file_list(
                        "FTP listing: bad character in the second time part",
                    ));
                }
            }
            // `:652-660`.
            TimeSub::PrePart3 => {
                self.item_length = self.item_length.saturating_add(1);
                if c != b' ' {
                    if is_alnum(c) {
                        self.set_unix(UnixMain::Time, next(TimeSub::Part3));
                    } else {
                        return Err(bad_file_list(
                            "FTP listing: third time part does not begin \
                             with a letter or digit",
                        ));
                    }
                }
            }
            // `:661-677`.
            TimeSub::Part3 => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b' ' {
                    infop.poke_nul(self.item_end());
                    self.offsets.time = self.item_offset;
                    if infop.info.filetype == FileType::Symlink {
                        self.set_unix(
                            UnixMain::Symlink,
                            UnixSub::Symlink(SymlinkSub::PreSpace),
                        );
                    } else {
                        self.set_unix(
                            UnixMain::Filename,
                            UnixSub::Filename(FilenameSub::PreSpace),
                        );
                    }
                } else if !is_alnum(c) && c != b'.' && c != b':' {
                    return Err(bad_file_list(
                        "FTP listing: bad character in the third time part",
                    ));
                }
            }
        }
        Ok(Step::Hold)
    }

    /// The filename, to the end of the line.
    ///
    /// `parse_unix_filename` (`lib/ftplistparser.c:682-722`). Everything from
    /// the first non-space to the line ending is the name, spaces inside it
    /// included, and no character is rejected -- the line ending is the only
    /// delimiter.
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` when a carriage return is followed by
    /// anything but a line feed.
    fn parse_unix_filename(
        &mut self,
        sub: FilenameSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        let len = infop.buf.len();

        match sub {
            // `:692-697`.
            FilenameSub::PreSpace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.set_unix(
                        UnixMain::Filename,
                        UnixSub::Filename(FilenameSub::Name),
                    );
                }
                Ok(Step::Hold)
            }
            // `:699-710`.
            FilenameSub::Name => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b'\r' {
                    self.set_unix(
                        UnixMain::Filename,
                        UnixSub::Filename(FilenameSub::WindowsEol),
                    );
                    Ok(Step::Hold)
                } else if c == b'\n' {
                    self.finish_unix_name(sub, infop);
                    Ok(Step::Complete)
                } else {
                    Ok(Step::Hold)
                }
            }
            // `:711-720`.
            FilenameSub::WindowsEol => {
                if c == b'\n' {
                    self.finish_unix_name(sub, infop);
                    Ok(Step::Complete)
                } else {
                    Err(bad_file_list(
                        "FTP listing: carriage return not followed by a line \
                         feed after the filename",
                    ))
                }
            }
        }
    }

    /// Terminates the filename and readies the machine for the next entry.
    ///
    /// The three lines the C repeats at `lib/ftplistparser.c:705-707` and
    /// `:713-715`. The main state returns to `PL_UNIX_FILETYPE` while the
    /// substate is left alone, exactly as the C leaves its union alone, and
    /// the item cursor is not reset here: the completed record clears
    /// [`ParselistData::file_data`], and the next byte resets the cursor when
    /// it creates the next record.
    fn finish_unix_name(
        &mut self,
        sub: FilenameSub,
        infop: &mut InProgressFile,
    ) {
        infop.poke_nul(self.item_end());
        self.offsets.filename = self.item_offset;
        self.set_unix(UnixMain::FileType, UnixSub::Filename(sub));
    }

    /// A symlink's name, the arrow between, and the target.
    ///
    /// `parse_unix_symlink` (`lib/ftplistparser.c:725-826`). The four bytes of
    /// `" -> "` are recognised one substate at a time, and any of the four
    /// positions receiving something else returns to
    /// [`SymlinkSub::Name`] rather than failing -- which is what lets a name
    /// containing a space, a hyphen or a greater-than sign parse as a name.
    /// The consequence is that the LAST arrow in the line separates name from
    /// target, and a target that still contains an arrow is discarded later by
    /// [`ParselistData::insert_finfo`].
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` when the line ends before an arrow is found,
    /// when the target is empty, and when a carriage return in the target is
    /// followed by anything but a line feed.
    fn parse_unix_symlink(
        &mut self,
        sub: SymlinkSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        let len = infop.buf.len();
        let unfinished = || {
            bad_file_list("FTP listing: symlink line ends before its target")
        };
        let next = |sub| UnixSub::Symlink(sub);

        match sub {
            // `:735-740`.
            SymlinkSub::PreSpace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.set_unix(UnixMain::Symlink, next(SymlinkSub::Name));
                }
                Ok(Step::Hold)
            }
            // `:742-750`.
            SymlinkSub::Name => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b' ' {
                    self.set_unix(
                        UnixMain::Symlink,
                        next(SymlinkSub::PreTarget1),
                    );
                    Ok(Step::Hold)
                } else if c == b'\r' || c == b'\n' {
                    Err(unfinished())
                } else {
                    Ok(Step::Hold)
                }
            }
            // `:751-760`.
            SymlinkSub::PreTarget1 => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b'-' {
                    self.set_unix(
                        UnixMain::Symlink,
                        next(SymlinkSub::PreTarget2),
                    );
                    Ok(Step::Hold)
                } else if c == b'\r' || c == b'\n' {
                    Err(unfinished())
                } else {
                    self.set_unix(UnixMain::Symlink, next(SymlinkSub::Name));
                    Ok(Step::Hold)
                }
            }
            // `:761-770`.
            SymlinkSub::PreTarget2 => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b'>' {
                    self.set_unix(
                        UnixMain::Symlink,
                        next(SymlinkSub::PreTarget3),
                    );
                    Ok(Step::Hold)
                } else if c == b'\r' || c == b'\n' {
                    Err(unfinished())
                } else {
                    self.set_unix(UnixMain::Symlink, next(SymlinkSub::Name));
                    Ok(Step::Hold)
                }
            }
            // `:771-785`.
            SymlinkSub::PreTarget3 => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b' ' {
                    self.set_unix(
                        UnixMain::Symlink,
                        next(SymlinkSub::PreTarget4),
                    );
                    // `:776`. Four back from the delimiter, which is the
                    // space before the hyphen: the name ends where `" -> "`
                    // begins.
                    let index = self
                        .item_offset
                        .saturating_add(self.item_length as usize)
                        .saturating_sub(4);
                    infop.poke_nul(index);
                    self.offsets.filename = self.item_offset;
                    self.item_length = 0;
                    self.item_offset = 0;
                    Ok(Step::Hold)
                } else if c == b'\r' || c == b'\n' {
                    Err(unfinished())
                } else {
                    self.set_unix(UnixMain::Symlink, next(SymlinkSub::Name));
                    Ok(Step::Hold)
                }
            }
            // `:786-795`. No count: this byte begins the target, so the
            // target's own offset is taken from it.
            SymlinkSub::PreTarget4 => {
                if c != b'\r' && c != b'\n' && len != 0 {
                    self.set_unix(UnixMain::Symlink, next(SymlinkSub::Target));
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    Ok(Step::Hold)
                } else {
                    Err(bad_file_list("FTP listing: symlink target is empty"))
                }
            }
            // `:796-810`.
            SymlinkSub::Target => {
                self.item_length = self.item_length.saturating_add(1);
                if c == b'\r' {
                    self.set_unix(
                        UnixMain::Symlink,
                        next(SymlinkSub::WindowsEol),
                    );
                    Ok(Step::Hold)
                } else if c == b'\n' {
                    self.finish_unix_symlink(sub, infop);
                    Ok(Step::Complete)
                } else {
                    Ok(Step::Hold)
                }
            }
            // `:811-824`.
            SymlinkSub::WindowsEol => {
                if c == b'\n' {
                    self.finish_unix_symlink(sub, infop);
                    Ok(Step::Complete)
                } else {
                    Err(bad_file_list(
                        "FTP listing: carriage return not followed by a line \
                         feed after the symlink target",
                    ))
                }
            }
        }
    }

    /// Terminates the symlink target and readies the machine for the next
    /// entry.
    ///
    /// The C repeats these lines at `lib/ftplistparser.c:802-808` and
    /// `:813-819`, where the return to `PL_UNIX_FILETYPE` is guarded on the
    /// insertion having succeeded. `ftp_pl_insert_finfo` returns `CURLE_OK`
    /// unconditionally (`:348`), so the guard never fires and the transition is
    /// made here, before the insertion, which keeps the two call sites
    /// identical.
    fn finish_unix_symlink(
        &mut self,
        sub: SymlinkSub,
        infop: &mut InProgressFile,
    ) {
        infop.poke_nul(self.item_end());
        self.offsets.symlink_target = self.item_offset;
        self.set_unix(UnixMain::FileType, UnixSub::Symlink(sub));
    }
}

// ---------------------------------------------------------------------------
// The WinNT machine
// ---------------------------------------------------------------------------

impl ParselistData {
    /// One byte of a WinNT listing.
    ///
    /// `parse_winnt` (`lib/ftplistparser.c:881-1011`). Format 5 of the C's
    /// header comment (`:39-40`) is the whole grammar --
    /// `01-29-97 11:32PM <DIR> prog` -- and four states read it: a
    /// fixed-width date, a time, either `<DIR>` or a byte count, and a name.
    ///
    /// There is no permission, owner, group or hard-link column, so a WinNT
    /// entry leaves those four offsets untouched and its
    /// [`FileInfoStrings`] reports them absent. Its
    /// [`Offsets::time`] stays at zero as well, because the item offset never
    /// moves off the start of the line -- which is exactly why the C assigns
    /// `strings.time` with no guard.
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` for a malformed date, a character outside
    /// `APM0123456789:` in the time, a size column that is neither `<DIR>` nor
    /// a number, and a carriage return not followed by a line feed.
    fn parse_winnt(
        &mut self,
        main: WinNtMain,
        sub: WinNtSub,
        c: u8,
        infop: &mut InProgressFile,
    ) -> CurlResult<Step> {
        let len = infop.buf.len();

        match main {
            // `:892-909`. Eight characters then a space, counted rather than
            // delimited. The C's own comment on the character set is "only
            // simple control": the shape is checked, the date is not
            // validated, and it is never interpreted -- it becomes part of
            // [`FileInfoStrings::time`] along with the time.
            WinNtMain::Date => {
                self.item_length = self.item_length.saturating_add(1);
                if self.item_length < 9 {
                    if !set_contains(b"0123456789-", c) {
                        return Err(bad_file_list(
                            "FTP listing: bad character in the date field",
                        ));
                    }
                } else if self.item_length == 9 {
                    if c != b' ' {
                        return Err(bad_file_list(
                            "FTP listing: date field is not eight characters",
                        ));
                    }
                    self.set_winnt(
                        WinNtMain::Time,
                        WinNtSub::Time(NtTimeSub::PreSpace),
                    );
                } else {
                    // `:907-908`. Unreachable: the arm above leaves this
                    // state at a count of exactly nine, so nothing arrives
                    // here with a larger one. Reproduced because it is what
                    // the C would answer if anything did.
                    return Err(bad_file_list(
                        "FTP listing: date field overran its width",
                    ));
                }
                Ok(Step::Hold)
            }
            // `:910-929`.
            WinNtMain::Time => {
                self.item_length = self.item_length.saturating_add(1);
                match sub.time() {
                    // `:913-916`. The first non-blank enters the time, and
                    // note what is NOT here: that byte is not checked against
                    // the character set, so a time may open with anything.
                    NtTimeSub::PreSpace => {
                        if !is_blank(c) {
                            self.set_winnt(
                                WinNtMain::Time,
                                WinNtSub::Time(NtTimeSub::Time),
                            );
                        }
                    }
                    // `:917-927`.
                    NtTimeSub::Time => {
                        if c == b' ' {
                            self.offsets.time = self.item_offset;
                            infop.poke_nul(self.item_end());
                            self.set_winnt(
                                WinNtMain::DirOrSize,
                                WinNtSub::DirOrSize(NtDirOrSizeSub::PreSpace),
                            );
                            self.item_length = 0;
                        } else if !set_contains(b"APM0123456789:", c) {
                            return Err(bad_file_list(
                                "FTP listing: bad character in the time \
                                 field",
                            ));
                        }
                    }
                }
                Ok(Step::Hold)
            }
            // `:930-963`. No count on entry: this column is delimited, so the
            // count starts when its content does.
            WinNtMain::DirOrSize => {
                match sub.dirorsize() {
                    // `:932-938`.
                    NtDirOrSizeSub::PreSpace => {
                        if c != b' ' && len != 0 {
                            self.item_offset = len - 1;
                            self.item_length = 1;
                            self.set_winnt(
                                WinNtMain::DirOrSize,
                                WinNtSub::DirOrSize(NtDirOrSizeSub::Content),
                            );
                        }
                    }
                    // `:939-961`.
                    NtDirOrSizeSub::Content => {
                        self.item_length = self.item_length.saturating_add(1);
                        if c == b' ' {
                            infop.poke_nul(self.item_end());

                            // `:943`. `strcmp` against the terminated field,
                            // so `<DIR>` must be the whole of it.
                            let is_dir =
                                cstr_at(infop.buf.as_slice(), self.item_offset)
                                    == b"<DIR>".as_slice();

                            if is_dir {
                                // `:944-945`.
                                infop.info.filetype = FileType::Directory;
                                infop.info.size = 0;
                            } else {
                                // `:947-954`. Note the asymmetry with the
                                // Unix size column: there the C insists the
                                // number reached the field's end, here it does
                                // not, so a column reading `12abc` yields a
                                // size of twelve rather than an error.
                                let parsed = {
                                    let mut cursor = tail_at(
                                        infop.buf.as_slice(),
                                        self.item_offset,
                                    );
                                    str_numblanks(&mut cursor).ok()
                                };
                                match parsed {
                                    Some(size) => infop.info.size = size,
                                    None => {
                                        return Err(bad_file_list(
                                            "FTP listing: size column is \
                                             neither a directory marker nor \
                                             a number",
                                        ))
                                    }
                                }
                                infop.info.filetype = FileType::File;
                            }

                            // `:956`. Set for both branches, the directory
                            // included, which is why a `<DIR>` entry reports
                            // a known size of zero.
                            infop.info.flags |= FileInfo::KNOWN_SIZE;
                            self.item_length = 0;
                            self.set_winnt(
                                WinNtMain::Filename,
                                WinNtSub::Filename(NtFilenameSub::PreSpace),
                            );
                        }
                    }
                }
                Ok(Step::Hold)
            }
            // `:964-1007`.
            WinNtMain::Filename => {
                self.parse_winnt_filename(sub.filename(), c, infop, len)
            }
        }
    }

    /// A WinNT filename, to the end of the line.
    ///
    /// The `PL_WINNT_FILENAME` arm of `parse_winnt`
    /// (`lib/ftplistparser.c:964-1007`), split out so that
    /// [`ParselistData::parse_winnt`] stays readable. Spaces inside the name
    /// are kept once content has begun, so a name with a space in it survives
    /// -- which matters here more than in a Unix listing, where DOS-era names
    /// are the reason the column is last.
    ///
    /// # Errors
    ///
    /// `CURLE_FTP_BAD_FILE_LIST` when a carriage return is followed by
    /// anything but a line feed.
    fn parse_winnt_filename(
        &mut self,
        sub: NtFilenameSub,
        c: u8,
        infop: &mut InProgressFile,
        len: usize,
    ) -> CurlResult<Step> {
        match sub {
            // `:966-972`.
            NtFilenameSub::PreSpace => {
                if c != b' ' && len != 0 {
                    self.item_offset = len - 1;
                    self.item_length = 1;
                    self.set_winnt(
                        WinNtMain::Filename,
                        WinNtSub::Filename(NtFilenameSub::Content),
                    );
                }
                Ok(Step::Hold)
            }
            // `:973-991`.
            NtFilenameSub::Content => {
                self.item_length = self.item_length.saturating_add(1);
                if len == 0 {
                    // `:975-976`. Unreachable: the byte was appended to the
                    // record before this machine ran, so the record holds at
                    // least one. Reproduced for the same reason as the date
                    // arm's overrun.
                    return Err(bad_file_list(
                        "FTP listing: filename with no record behind it",
                    ));
                }
                if c == b'\r' {
                    // `:977-980`. The terminator goes over the carriage
                    // return HERE, which is why the line-feed arm below does
                    // not write one.
                    self.set_winnt(
                        WinNtMain::Filename,
                        WinNtSub::Filename(NtFilenameSub::WinEol),
                    );
                    infop.poke_nul(len - 1);
                    Ok(Step::Hold)
                } else if c == b'\n' {
                    // `:981-990`.
                    self.offsets.filename = self.item_offset;
                    infop.poke_nul(len - 1);
                    self.set_winnt(
                        WinNtMain::Date,
                        WinNtSub::Filename(NtFilenameSub::PreSpace),
                    );
                    Ok(Step::Complete)
                } else {
                    Ok(Step::Hold)
                }
            }
            // `:992-1005`. No terminator is written: the carriage return arm
            // already wrote one over the byte before this line feed.
            NtFilenameSub::WinEol => {
                if c == b'\n' {
                    self.offsets.filename = self.item_offset;
                    self.set_winnt(
                        WinNtMain::Date,
                        WinNtSub::Filename(NtFilenameSub::PreSpace),
                    );
                    Ok(Step::Complete)
                } else {
                    Err(bad_file_list(
                        "FTP listing: carriage return not followed by a line \
                         feed after the filename",
                    ))
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Wildcard ownership
// ---------------------------------------------------------------------------

/// The writer slot the listing parser occupies while `LIST` runs.
///
/// The `backup` member of `struct ftp_wc` (`lib/ftp.h:89-92`), which the C
/// uses to stash `data->set.fwrite_func` and `data->set.out` so that
/// `Curl_ftp_parselist` can stand in as the write callback and the caller's
/// own writer can be put back afterwards.
///
/// What is stashed there has no counterpart here, and the reason is
/// structural rather than an omission. In C the caller's writer lives in a
/// mutable global-per-handle slot that has to be saved before it is
/// overwritten; in the Rust design the wildcard driver owns the caller's
/// writer for the whole transfer and lends the listing to this parser, so
/// there is nothing to save and nothing that could be lost. Neither the
/// callback type nor the output stream is nameable from this module in any
/// case: both belong to layers that depend on this one.
///
/// What remains is the one bit of the C's state that is genuinely observable
/// -- whether the substitution is currently in force -- which is what
/// `backup.write_function` being non-null means at
/// `lib/ftp.c`'s teardown.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct WriteBackup {
    /// Whether the listing parser is currently standing in for the caller's
    /// writer.
    pub(crate) listing_writer_installed: bool,
}

/// The FTP-specific half of a wildcard download.
///
/// `struct ftp_wc` (`lib/ftp.h:86-93`): the listing parser, and the writer
/// slot it occupies. The C reaches it through `wc->ftpwc`, a `void *` with a
/// separately stored destructor function pointer
/// (`lib/ftplistparser.h:63-64`, `:193-197`); here it is an owned field of a
/// concrete type, so the destructor is the compiler's and the `void *` is
/// gone.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct FtpWildcard {
    /// The listing parser for the directory currently being matched.
    pub(crate) parser: ParselistData,
    /// The writer slot.
    pub(crate) backup: WriteBackup,
}

impl FtpWildcard {
    /// A wildcard context whose parser matches `pattern`.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn new(pattern: &[u8]) -> Self {
        Self {
            parser: ParselistData::new(pattern),
            backup: WriteBackup::default(),
        }
    }
}

/// Everything one wildcard download needs to know.
///
/// `struct WildcardData` (`lib/ftplistparser.h:58-66`), with three of the C's
/// six members changed in kind and none in meaning:
///
/// * `char *path` and `char *pattern` become owned text, absent until the
///   driver has parsed the URL.
/// * `struct Curl_llist filelist` becomes a [`VecDeque`] that owns its
///   entries. The C's list holds pointers into separately allocated
///   `struct fileinfo`s and needs a destructor function registered at
///   `lib/ftplistparser.c:183` to free them; the queue frees its own.
/// * `struct ftp_wc *ftpwc` with its `wildcard_dtor` becomes
///   [`Option<FtpWildcard>`]. Two members collapse into one, because the
///   destructor existed only to type-erase the pointer.
///
/// `Curl_wildcard_init` (`:181-185`) and `Curl_wildcard_dtor` (`:187-208`)
/// become [`WildcardData::default`], [`WildcardData::reset`] and drop glue.
/// Both C functions leave the state at `CURLWC_INIT` -- initialization at
/// `:184` and teardown at `:205`, the latter on a structure it is about to
/// free -- and both of these do the same, so a reset structure is
/// indistinguishable from a fresh one.
///
/// There is no [`Drop`] implementation here on purpose. Every member releases
/// itself, so one would add nothing, and it would additionally forbid moving
/// a field out of the structure -- which the driver does when it takes the
/// parser out to feed it.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct WildcardData {
    /// `path`. The C: "path to the directory, where we trying
    /// wildcard-match".
    pub(crate) path: Option<String>,
    /// `pattern`. The C: "wildcard pattern". The parser holds its own copy;
    /// see [`ParselistData`].
    pub(crate) pattern: Option<String>,
    /// `filelist`. The C: "llist with struct Curl_fileinfo". Matched entries
    /// in arrival order, which is the order the server listed them and the
    /// order they are transferred in.
    pub(crate) filelist: VecDeque<FileInfo>,
    /// `ftpwc`. The C: "pointer to FTP wildcard data".
    pub(crate) ftpwc: Option<FtpWildcard>,
    /// `state`, in the C's `unsigned char` width.
    pub(crate) state: WildcardState,
}

impl Default for WildcardData {
    /// `Curl_wildcard_init` (`lib/ftplistparser.c:181-185`): an empty file
    /// list and [`WildcardState::Init`].
    ///
    /// [`WildcardState::Clear`] is the value a zeroed allocation carries
    /// BEFORE that function runs, and it is deliberately not what this
    /// produces -- there is no moment here at which a `WildcardData` exists
    /// uninitialized.
    fn default() -> Self {
        Self {
            path: None,
            pattern: None,
            filelist: VecDeque::new(),
            ftpwc: None,
            state: WildcardState::Init,
        }
    }
}

#[allow(dead_code)]
impl WildcardData {
    /// Releases everything and returns to the initialized state.
    ///
    /// `Curl_wildcard_dtor` (`lib/ftplistparser.c:187-208`) without the final
    /// `free`: the FTP context goes first, then the file list, then the path
    /// and the pattern, and the state ends at [`WildcardState::Init`]. The C
    /// runs this on a structure it is about to release, so its assignments to
    /// `NULL` and to `CURLWC_INIT` are unobservable there; here the same
    /// sequence is reusable, which is what a wildcard download needs between
    /// two directories.
    pub(crate) fn reset(&mut self) {
        self.ftpwc = None;
        self.filelist.clear();
        self.path = None;
        self.pattern = None;
        self.state = WildcardState::Init;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The unit suite for the listing parser.
///
/// AAP 0.8.7 records that `tests/libtest/*.c` and `tests/unit/*.c` cannot link
/// against a Rust `staticlib`, because a `pub(crate)` item is genuinely absent
/// from the symbol table rather than merely hidden, and that the coverage of
/// those C programs is preserved by relocating the assertions into the crate.
/// `tests/libtest/lib576.c` and its siblings drive this parser through a live
/// FTP server; what follows drives it directly, with no network and no server,
/// and asserts against the same published expectations -- `tests/data/test576`
/// and the listing generator at `tests/directories.pm:183-201` are where the
/// byte layouts below come from.
#[cfg(test)]
mod tests {
    use super::*;

    /// The five formats the C's own header comment enumerates
    /// (`lib/ftplistparser.c:28-41`), quoted exactly.
    const FORMAT_1: &str = "drwxr-xr-x 1 user01 ftp  512 Jan 29 23:32 prog\n";
    const FORMAT_2: &str = "drwxr-xr-x 1 user01 ftp  512 Jan 29 1997  prog\n";
    const FORMAT_3: &str = "drwxr-xr-x 1      1   1  512 Jan 29 23:32 prog\n";
    const FORMAT_4: &str =
        "lrwxr-xr-x 1 user01 ftp  512 Jan 29 23:32 prog -> prog2000\n";
    const FORMAT_5: &str = "01-29-97 11:32PM <DIR> prog\n";

    /// A listing in the shape `tests/directories.pm` produces for
    /// `/fully_simulated/UNIX/`: CRLF endings, a total line, directories,
    /// regular files, a symlink, a symlink whose target carries a second
    /// arrow, and one final entry ended by a bare line feed.
    const MIXED: &str = concat!(
        "total 20\r\n",
        "drwxrwxrwx    4 ftp-default ftp-default   20480 Apr 27  5:12 .\r\n",
        "drwxrwxrwx    4 ftp-default ftp-default   20480 Apr 23  3:12 ..\r\n",
        "-r--r--r--    1 ftp-default ftp-default      38 Jan 11 10:00 chmod1",
        "\r\n",
        "lrwxrwxrwx    1 ftp-default ftp-default       0 Jan  6  4:42 link ",
        "-> file.txt\r\n",
        "lrwxrwxrwx    1 ftp-default ftp-default       0 Jan  6  4:42 a -> b ",
        "-> c\r\n",
        "-rw-r--r--    1 ftp-default ftp-default      35 Apr 27 11:01 ",
        "file.txt\n",
    );

    /// Everything about a parser that must not depend on how the input was
    /// chopped up.
    ///
    /// Every field of `struct ftp_parselist_data` is here, with the record
    /// under construction represented by its bytes: two parses of the same
    /// listing have to agree on all of it, not merely on the entries they
    /// produced.
    type Snapshot = (
        OsType,
        ParseState,
        Option<CURLcode>,
        u32,
        usize,
        Offsets,
        Option<Vec<u8>>,
    );

    fn snapshot(parser: &ParselistData) -> Snapshot {
        (
            parser.os_type,
            parser.state,
            parser.error,
            parser.item_length,
            parser.item_offset,
            parser.offsets,
            parser
                .file_data
                .as_ref()
                .map(|record| record.buf.as_slice().to_vec()),
        )
    }

    /// Asserts the invariant every entry this parser emits must satisfy.
    ///
    /// `include/curl/curl.h:319` annotates the numeric member "always zero!",
    /// and no path in the C writes it. Checked on every entry every helper
    /// below produces, so the claim is tested by the whole suite rather than
    /// by one case.
    fn assert_numeric_time_is_zero(entries: &VecDeque<FileInfo>) {
        for entry in entries {
            assert_eq!(
                entry.time, 0,
                "the numeric time is always zero; {} carried {}",
                entry.filename, entry.time
            );
        }
    }

    /// Feeds a listing in one call.
    fn one_shot(pattern: &[u8], listing: &[u8]) -> ParselistData {
        let mut parser = ParselistData::new(pattern);
        let outcome = parser.push(listing);
        assert!(outcome.is_ok(), "unexpected failure: {outcome:?}");
        assert_numeric_time_is_zero(parser.accepted());
        parser
    }

    /// Feeds a listing one byte at a time.
    fn byte_by_byte(pattern: &[u8], listing: &[u8]) -> ParselistData {
        let mut parser = ParselistData::new(pattern);
        for (index, byte) in listing.iter().enumerate() {
            let outcome = parser.push(&[*byte]);
            assert!(
                outcome.is_ok(),
                "unexpected failure at byte {index}: {outcome:?}"
            );
        }
        assert_numeric_time_is_zero(parser.accepted());
        parser
    }

    /// The single entry a one-line listing must produce.
    fn only_entry(listing: &str) -> FileInfo {
        let parser = one_shot(b"*", listing.as_bytes());
        let entries = parser.accepted();
        assert_eq!(entries.len(), 1, "expected one entry, got {entries:?}");
        match entries.front() {
            Some(entry) => entry.clone(),
            None => FileInfo::default(),
        }
    }

    /// The names a parse queued, in arrival order.
    fn names(parser: &ParselistData) -> Vec<String> {
        parser
            .accepted()
            .iter()
            .map(|entry| entry.filename.clone())
            .collect()
    }

    /// The error a listing must be rejected with.
    fn rejected(pattern: &[u8], listing: &[u8]) -> CURLcode {
        let mut parser = ParselistData::new(pattern);
        let outcome = parser.push(listing);
        assert!(outcome.is_err(), "expected a rejection, got {outcome:?}");
        assert!(
            parser.accepted().is_empty(),
            "a rejected listing queued {:?}",
            names(&parser)
        );
        assert!(
            parser.file_data.is_none(),
            "the record under construction was not released"
        );
        parser.geterror()
    }

    /// A comparator that records what it was asked and what the guard did.
    ///
    /// Stands in for a `CURLOPT_FNMATCH_FUNCTION`
    /// (`lib/ftplistparser.c:321`), which is the case
    /// [`ParselistData::push_matching`] exists for.
    #[derive(Debug, Default)]
    struct RecordingMatcher {
        /// Every `(pattern, filename)` pair, in order.
        seen: Vec<(Vec<u8>, Vec<u8>)>,
        /// Every value the in-callback flag was set to, in order.
        flag: Vec<bool>,
        /// Whether the flag was set on every entry to
        /// [`FilenameMatcher::compare`].
        always_inside: bool,
        /// The verdict to return.
        verdict: i32,
        /// Filenames to admit regardless of [`Self::verdict`].
        admit: Vec<Vec<u8>>,
    }

    impl RecordingMatcher {
        fn returning(verdict: i32) -> Self {
            Self {
                always_inside: true,
                verdict,
                ..Self::default()
            }
        }

        fn admitting(names: &[&str]) -> Self {
            Self {
                always_inside: true,
                verdict: 1,
                admit: names
                    .iter()
                    .map(|name| name.as_bytes().to_vec())
                    .collect(),
                ..Self::default()
            }
        }
    }

    impl FilenameMatcher for RecordingMatcher {
        fn compare(&mut self, pattern: &[u8], filename: &[u8]) -> i32 {
            if self.flag.last() != Some(&true) {
                self.always_inside = false;
            }
            self.seen.push((pattern.to_vec(), filename.to_vec()));
            if self.admit.iter().any(|name| name == filename) {
                0
            } else {
                self.verdict
            }
        }

        fn set_in_callback(&mut self, inside: bool) {
            self.flag.push(inside);
        }
    }

    // -----------------------------------------------------------------------
    // The five documented formats
    // -----------------------------------------------------------------------

    #[test]
    fn format_1_is_a_directory_with_a_time_of_day() {
        let entry = only_entry(FORMAT_1);

        assert_eq!(entry.filename, "prog");
        assert_eq!(entry.filetype, FileType::Directory);
        assert_eq!(entry.size, 512);
        assert_eq!(entry.hardlinks, 1);
        // `rwxr-xr-x`, which is 0o755.
        assert_eq!(entry.perm, 0o755);
        assert_eq!(entry.strings.time, "Jan 29 23:32");
        assert_eq!(entry.strings.perm.as_deref(), Some("rwxr-xr-x"));
        assert_eq!(entry.strings.user.as_deref(), Some("user01"));
        assert_eq!(entry.strings.group.as_deref(), Some("ftp"));
        assert_eq!(entry.strings.target, None);
        // Exactly the three the C parser sets, and no more.
        assert_eq!(
            entry.flags,
            FileInfo::KNOWN_PERM
                | FileInfo::KNOWN_HLINKCOUNT
                | FileInfo::KNOWN_SIZE
        );
        assert!(entry.knows(FileInfo::KNOWN_PERM));
        assert!(!entry.knows(FileInfo::KNOWN_TIME));
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.gid, 0);
    }

    #[test]
    fn format_2_is_the_same_entry_with_a_year_instead_of_a_time() {
        let entry = only_entry(FORMAT_2);

        assert_eq!(entry.filename, "prog");
        assert_eq!(entry.filetype, FileType::Directory);
        assert_eq!(entry.size, 512);
        assert_eq!(entry.hardlinks, 1);
        assert_eq!(entry.perm, 0o755);
        // The two-space gap before the year is inside the field, so it
        // survives into the stored text; the SECOND pair of spaces, before
        // the name, is skipped by the filename state.
        assert_eq!(entry.strings.time, "Jan 29 1997");
        assert_eq!(entry.strings.user.as_deref(), Some("user01"));
        assert_eq!(entry.strings.group.as_deref(), Some("ftp"));
    }

    #[test]
    fn format_3_carries_numeric_owner_and_group_columns() {
        let entry = only_entry(FORMAT_3);

        assert_eq!(entry.filename, "prog");
        assert_eq!(entry.filetype, FileType::Directory);
        assert_eq!(entry.size, 512);
        assert_eq!(entry.hardlinks, 1);
        // Numbers, and still text: the parser does not turn them into
        // `uid` and `gid`, which stay zero and unflagged.
        assert_eq!(entry.strings.user.as_deref(), Some("1"));
        assert_eq!(entry.strings.group.as_deref(), Some("1"));
        assert_eq!(entry.uid, 0);
        assert_eq!(entry.gid, 0);
        assert!(!entry.knows(FileInfo::KNOWN_UID));
        assert!(!entry.knows(FileInfo::KNOWN_GID));
        assert_eq!(entry.strings.time, "Jan 29 23:32");
    }

    #[test]
    fn format_4_is_a_symlink_with_its_target() {
        let entry = only_entry(FORMAT_4);

        assert_eq!(entry.filename, "prog");
        assert_eq!(entry.filetype, FileType::Symlink);
        assert_eq!(entry.strings.target.as_deref(), Some("prog2000"));
        assert_eq!(entry.size, 512);
        assert_eq!(entry.hardlinks, 1);
        assert_eq!(entry.perm, 0o755);
        assert_eq!(entry.strings.time, "Jan 29 23:32");
        assert_eq!(entry.strings.perm.as_deref(), Some("rwxr-xr-x"));
    }

    #[test]
    fn format_5_is_a_dos_directory_with_no_unix_columns() {
        let entry = only_entry(FORMAT_5);

        assert_eq!(entry.filename, "prog");
        assert_eq!(entry.filetype, FileType::Directory);
        // `:944-945` assigns zero and `:956` flags it, so a directory
        // reports a KNOWN size of zero rather than an unknown one.
        assert_eq!(entry.size, 0);
        assert_eq!(entry.flags, FileInfo::KNOWN_SIZE);
        // The date and the time together, terminated at the space that ends
        // the time: a WinNT listing leaves the item offset at zero, which is
        // why the C assigns `strings.time` with no guard.
        assert_eq!(entry.strings.time, "01-29-97 11:32PM");
        assert_eq!(entry.strings.perm, None);
        assert_eq!(entry.strings.user, None);
        assert_eq!(entry.strings.group, None);
        assert_eq!(entry.strings.target, None);
        assert_eq!(entry.hardlinks, 0);
        assert_eq!(entry.perm, 0);
    }

    #[test]
    fn a_dos_size_column_yields_a_regular_file() {
        let entry = only_entry("04-27-10  11:01AM              35 file.txt\n");

        assert_eq!(entry.filename, "file.txt");
        assert_eq!(entry.filetype, FileType::File);
        assert_eq!(entry.size, 35);
        assert_eq!(entry.flags, FileInfo::KNOWN_SIZE);
        assert_eq!(entry.strings.time, "04-27-10  11:01AM");
    }

    #[test]
    fn a_dos_filename_keeps_its_interior_spaces() {
        let entry = only_entry("04-27-10  11:01AM      <DIR>       my dir\r\n");

        assert_eq!(entry.filename, "my dir");
        assert_eq!(entry.filetype, FileType::Directory);
    }

    // -----------------------------------------------------------------------
    // The fixture server's own listings
    // -----------------------------------------------------------------------

    /// `/fully_simulated/UNIX/` exactly as `tests/directories.pm:188-194`
    /// generates it: fourteen entries, CRLF endings, no total line.
    ///
    /// The layout is the generator's, character for character --
    /// `"$ftype$fperm $fhlink $fuser $fgroup $fsize $ftime $name$eol"` at
    /// `:232`, with `%4d` on the link count, `%7s` or `%7d` on the size and
    /// `%10s` on the time.
    const SERVER_UNIX: &str = concat!(
        "drwxrwxrwx    4 ftp-default ftp-default   20480 Apr 27  5:12 .\r\n",
        "drwxrwxrwx    4 ftp-default ftp-default   20480 Apr 23  3:12 ..\r\n",
        "-r--r--r--    1 ftp-default ftp-default      38 Jan 11 10:00 ",
        "chmod1\r\n",
        "-rw-rw-rw-    1 ftp-default ftp-default      38 Feb  1  8:00 ",
        "chmod2\r\n",
        "-rwxrwxrwx    1 ftp-default ftp-default      38 Feb  1  8:00 ",
        "chmod3\r\n",
        "d--S--S--t    1 ftp-default ftp-default    4096 May  4  4:31 ",
        "chmod4\r\n",
        "d--s--s--T    1 ftp-default ftp-default    4096 May  4  4:31 ",
        "chmod5\r\n",
        "-rw-r--r--    1 ftp-default ftp-default       0 Apr 27 11:01 ",
        "empty_file.dat\r\n",
        "-rw-r--r--    1 ftp-default ftp-default      35 Apr 27 11:01 ",
        "file.txt\r\n",
        "lrwxrwxrwx    1 ftp-default ftp-default       0 Jan  6  4:42 ",
        "link -> file.txt\r\n",
        "lrwxrwxrwx    1 ftp-default ftp-default       0 Jan  6  4:45 ",
        "link_absolute -> /data/ftp/file.txt\r\n",
        "drwxrwxrwx    4 ftp-default ftp-default    4096 Jan 23  2:05 ",
        ".NeXT\r\n",
        "-rw-r--r--    1 ftp-default ftp-default      47 Apr 27 11:01 ",
        "someothertext.txt\r\n",
        "drwxr-xrwx    2 ftp-default ftp-default    4096 Apr 23  3:12 ",
        "weirddir.txt\r\n",
    );

    /// `/fully_simulated/DOS/` exactly as `tests/directories.pm:197-201`
    /// generates it: twelve entries, `"$time $size_or_dir $name$eol"` at
    /// `:249`, with the directory marker padded to twenty columns and every
    /// size printed as `%20d`.
    const SERVER_DOS: &str = concat!(
        "04-27-10  05:12AM       <DIR>          .\r\n",
        "04-23-10  03:12AM       <DIR>          ..\r\n",
        "01-11-10  10:00AM                   38 chmod1\r\n",
        "02-01-10  08:00AM                   38 chmod2\r\n",
        "02-01-10  08:00AM                   38 chmod3\r\n",
        "05-04-10  04:31AM       <DIR>          chmod4\r\n",
        "05-04-10  04:31AM       <DIR>          chmod5\r\n",
        "04-27-10  11:01AM                    0 empty_file.dat\r\n",
        "04-27-10  11:01AM                   35 file.txt\r\n",
        "01-23-05  02:05AM       <DIR>          .NeXT\r\n",
        "04-27-10  11:01AM                   47 someothertext.txt\r\n",
        "04-23-10  03:12AM       <DIR>          weirddir.txt\r\n",
    );

    #[test]
    fn the_fixture_servers_unix_listing_matches_its_published_output() {
        // The expectations are read out of `tests/data/test576`, which is what
        // `tests/libtest/lib576.c` prints from a `CURLOPT_CHUNK_BGN_FUNCTION`
        // for this listing. Fourteen entries, in the server's order, with the
        // permissions that fixture states in octal.
        //
        // The target column deserves a word, because three of its values look
        // wrong and are not. The first nine entries have no target at all,
        // since `offsets.symlink_target` is still zero. The two symlinks have
        // the target they state. The three entries AFTER them INHERIT that
        // offset, because the C never resets the offsets between records --
        // see [`Offsets`] -- and it lands past the end of each of their
        // shorter buffers, which is a read past the buffer in C and an empty
        // field here. `lib576.c:60-64` prints a target only for a symlink,
        // which is why `tests/data/test576` shows no trace of it.
        let expected: [(&str, FileType, i64, i64, u32, &str, Option<&str>);
            14] = [
            (
                ".",
                FileType::Directory,
                20480,
                4,
                0o777,
                "Apr 27  5:12",
                None,
            ),
            (
                "..",
                FileType::Directory,
                20480,
                4,
                0o777,
                "Apr 23  3:12",
                None,
            ),
            ("chmod1", FileType::File, 38, 1, 0o444, "Jan 11 10:00", None),
            ("chmod2", FileType::File, 38, 1, 0o666, "Feb  1  8:00", None),
            ("chmod3", FileType::File, 38, 1, 0o777, "Feb  1  8:00", None),
            (
                "chmod4",
                FileType::Directory,
                4096,
                1,
                0o7001,
                "May  4  4:31",
                None,
            ),
            (
                "chmod5",
                FileType::Directory,
                4096,
                1,
                0o7110,
                "May  4  4:31",
                None,
            ),
            (
                "empty_file.dat",
                FileType::File,
                0,
                1,
                0o644,
                "Apr 27 11:01",
                None,
            ),
            (
                "file.txt",
                FileType::File,
                35,
                1,
                0o644,
                "Apr 27 11:01",
                None,
            ),
            (
                "link",
                FileType::Symlink,
                0,
                1,
                0o777,
                "Jan  6  4:42",
                Some("file.txt"),
            ),
            (
                "link_absolute",
                FileType::Symlink,
                0,
                1,
                0o777,
                "Jan  6  4:45",
                Some("/data/ftp/file.txt"),
            ),
            (
                ".NeXT",
                FileType::Directory,
                4096,
                4,
                0o777,
                "Jan 23  2:05",
                Some(""),
            ),
            (
                "someothertext.txt",
                FileType::File,
                47,
                1,
                0o644,
                "Apr 27 11:01",
                Some(""),
            ),
            (
                "weirddir.txt",
                FileType::Directory,
                4096,
                2,
                0o757,
                "Apr 23  3:12",
                Some(""),
            ),
        ];

        let parser = one_shot(b"*", SERVER_UNIX.as_bytes());
        let entries = parser.accepted();
        assert_eq!(entries.len(), expected.len(), "{:?}", names(&parser));

        for (index, expectation) in expected.iter().enumerate() {
            let (name, filetype, size, hardlinks, perm, time, target) =
                *expectation;
            let entry = match entries.get(index) {
                Some(entry) => entry,
                None => panic!("entry {index} is missing"),
            };
            assert_eq!(entry.filename, name, "entry {index} filename");
            assert_eq!(entry.filetype, filetype, "{name} filetype");
            assert_eq!(entry.size, size, "{name} size");
            assert_eq!(entry.hardlinks, hardlinks, "{name} hardlinks");
            assert_eq!(entry.perm, perm, "{name} permissions");
            assert_eq!(entry.strings.time, time, "{name} time text");
            assert_eq!(
                entry.strings.target.as_deref(),
                target,
                "{name} target"
            );
            assert_eq!(
                entry.strings.user.as_deref(),
                Some("ftp-default"),
                "{name} owner"
            );
            assert_eq!(
                entry.strings.group.as_deref(),
                Some("ftp-default"),
                "{name} group"
            );
            assert_eq!(
                entry.flags,
                FileInfo::KNOWN_PERM
                    | FileInfo::KNOWN_HLINKCOUNT
                    | FileInfo::KNOWN_SIZE,
                "{name} flags"
            );
        }
    }

    #[test]
    fn the_fixture_servers_dos_listing_parses_completely() {
        let expected: [(&str, FileType, i64); 12] = [
            (".", FileType::Directory, 0),
            ("..", FileType::Directory, 0),
            ("chmod1", FileType::File, 38),
            ("chmod2", FileType::File, 38),
            ("chmod3", FileType::File, 38),
            ("chmod4", FileType::Directory, 0),
            ("chmod5", FileType::Directory, 0),
            ("empty_file.dat", FileType::File, 0),
            ("file.txt", FileType::File, 35),
            (".NeXT", FileType::Directory, 0),
            ("someothertext.txt", FileType::File, 47),
            ("weirddir.txt", FileType::Directory, 0),
        ];

        let parser = one_shot(b"*", SERVER_DOS.as_bytes());
        assert_eq!(parser.os_type(), OsType::WinNt);
        let entries = parser.accepted();
        assert_eq!(entries.len(), expected.len(), "{:?}", names(&parser));

        for (index, expectation) in expected.iter().enumerate() {
            let (name, filetype, size) = *expectation;
            let entry = match entries.get(index) {
                Some(entry) => entry,
                None => panic!("entry {index} is missing"),
            };
            assert_eq!(entry.filename, name, "entry {index} filename");
            assert_eq!(entry.filetype, filetype, "{name} filetype");
            assert_eq!(entry.size, size, "{name} size");
            // A DOS listing has no permission, owner or group column, so the
            // size is the only thing the parser can claim to know.
            assert_eq!(entry.flags, FileInfo::KNOWN_SIZE, "{name} flags");
            assert_eq!(entry.strings.perm, None, "{name} permission text");
            assert_eq!(entry.strings.user, None, "{name} owner");
            assert_eq!(entry.strings.group, None, "{name} group");
            assert_eq!(entry.hardlinks, 0, "{name} hardlinks");
        }
        // The date and the time together, terminated at the space after the
        // time.
        match entries.front() {
            Some(entry) => {
                assert_eq!(entry.strings.time, "04-27-10  05:12AM");
            }
            None => panic!("no entries"),
        }
    }

    #[test]
    fn the_fixture_servers_listings_survive_any_split() {
        for listing in [SERVER_UNIX.as_bytes(), SERVER_DOS.as_bytes()] {
            let whole = one_shot(b"*", listing);
            let dribbled = byte_by_byte(b"*", listing);
            assert_eq!(whole.accepted(), dribbled.accepted());
            assert_eq!(snapshot(&whole), snapshot(&dribbled));
        }
    }

    #[test]
    fn a_pattern_selects_from_the_fixture_servers_listing() {
        // `tests/data/test1113` downloads `*.txt` from the DOS directory; the
        // pattern is applied to the parsed filenames, not to the listing text.
        let parser = one_shot(b"*.txt", SERVER_DOS.as_bytes());

        // Three, not two: `weirddir.txt` is a DIRECTORY whose name ends in
        // `.txt`, and the comparator sees only the name. That entry exists in
        // `tests/directories.pm:114-121` for exactly this reason, and deciding
        // what to do with a matched directory belongs to the wildcard driver
        // rather than to the parser.
        assert_eq!(
            names(&parser),
            vec!["file.txt", "someothertext.txt", "weirddir.txt"]
        );
    }

    // -----------------------------------------------------------------------
    // Chunk-boundary invariance
    // -----------------------------------------------------------------------

    #[test]
    fn one_call_and_one_byte_at_a_time_agree_exactly() {
        let listing = MIXED.as_bytes();
        let whole = one_shot(b"*", listing);
        let dribbled = byte_by_byte(b"*", listing);

        assert_eq!(whole.accepted(), dribbled.accepted());
        assert_eq!(snapshot(&whole), snapshot(&dribbled));
        assert_eq!(whole.geterror(), CURLcode::Ok);
        assert_eq!(dribbled.geterror(), CURLcode::Ok);
    }

    #[test]
    fn an_arbitrary_split_agrees_with_the_whole() {
        let listing = MIXED.as_bytes();
        let whole = one_shot(b"*", listing);

        // Every split point, including the two degenerate ones. A parser that
        // kept any state in a local rather than in itself fails somewhere in
        // this loop.
        for at in 0..=listing.len() {
            let mut parser = ParselistData::new(b"*");
            let (head, tail) = listing.split_at(at);
            assert!(parser.push(head).is_ok(), "head failed at split {at}");
            assert!(parser.push(tail).is_ok(), "tail failed at split {at}");
            assert_eq!(
                parser.accepted(),
                whole.accepted(),
                "split {at} produced different entries"
            );
            assert_eq!(
                snapshot(&parser),
                snapshot(&whole),
                "split {at} produced different state"
            );
        }
    }

    #[test]
    fn an_incomplete_final_line_survives_any_split() {
        // The interesting half of chunk-boundary invariance: a response whose
        // last line has not arrived yet leaves a record OPEN, so the two
        // parses have to agree on its accumulated bytes, its item cursor and
        // its substate, not merely on the entries already queued.
        let listing = concat!(
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 done\n",
            "drwxr-xr-x 1 user01 ftp  512 Jan 29 23:3",
        )
        .as_bytes();
        let whole = one_shot(b"*", listing);
        assert!(whole.file_data.is_some(), "the record should still be open");
        assert_eq!(names(&whole), vec!["done"]);

        for at in 0..=listing.len() {
            let mut parser = ParselistData::new(b"*");
            let (head, tail) = listing.split_at(at);
            assert!(parser.push(head).is_ok(), "head failed at split {at}");
            assert!(parser.push(tail).is_ok(), "tail failed at split {at}");
            assert_eq!(
                snapshot(&parser),
                snapshot(&whole),
                "split {at} produced different state"
            );
        }
    }

    #[test]
    fn the_mixed_listing_queues_five_of_its_six_entries() {
        let parser = one_shot(b"*", MIXED.as_bytes());

        // The total line contributes nothing, and `a -> b -> c` is discarded
        // because its target still contains an arrow.
        assert_eq!(
            names(&parser),
            vec![".", "..", "chmod1", "link", "file.txt"]
        );
        assert_eq!(parser.os_type(), OsType::Unix);
    }

    // -----------------------------------------------------------------------
    // The file-type decoder
    // -----------------------------------------------------------------------

    #[test]
    fn every_documented_type_character_decodes() {
        let pairs: [(u8, FileType); 8] = [
            (b'-', FileType::File),
            (b'd', FileType::Directory),
            (b'l', FileType::Symlink),
            (b'p', FileType::NamedPipe),
            (b's', FileType::Socket),
            (b'c', FileType::DeviceChar),
            (b'b', FileType::DeviceBlock),
            (b'D', FileType::Door),
        ];

        for (character, expected) in pairs {
            match unix_filetype(character) {
                Ok(actual) => assert_eq!(
                    actual,
                    expected,
                    "{} decoded wrongly",
                    char::from(character)
                ),
                Err(error) => {
                    panic!("{} was rejected: {error:?}", char::from(character))
                }
            }
        }
    }

    #[test]
    fn an_unknown_type_character_is_a_bad_file_list() {
        // `x` is a permission character, not a type character, which is the
        // most plausible way a caller reaches this arm.
        match unix_filetype(b'x') {
            Ok(unexpected) => panic!("x decoded as {unexpected:?}"),
            Err(error) => {
                assert_eq!(error.code(), CURLcode::FtpBadFileList);
            }
        }
    }

    #[test]
    fn a_line_opening_with_an_unknown_type_is_rejected() {
        assert_eq!(
            rejected(b"*", b"xrwxr-xr-x 1 u g 1 Jan 1 1970 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    // -----------------------------------------------------------------------
    // The permission decoder
    // -----------------------------------------------------------------------

    #[test]
    fn plain_permissions_decode_to_their_octal_value() {
        assert_eq!(ftp_pl_get_permission(b"rwxrwxrwx"), 0o777);
        assert_eq!(ftp_pl_get_permission(b"rw-r--r--"), 0o644);
        assert_eq!(ftp_pl_get_permission(b"r--r--r--"), 0o444);
    }

    #[test]
    fn no_permission_at_all_decodes_to_zero() {
        assert_eq!(ftp_pl_get_permission(b"---------"), 0);
    }

    #[test]
    fn lower_case_specials_keep_the_execute_bit() {
        // `s` and `t` mean the special bit AND the execute bit, so 0o755
        // gains 0o7000 and loses nothing.
        let perm = ftp_pl_get_permission(b"rwsr-sr-t");

        assert_eq!(perm, 0o7755);
        // Every special bit, individually, so a transposition cannot pass.
        assert_ne!(perm & (1 << 11), 0, "set-user-id");
        assert_ne!(perm & (1 << 10), 0, "set-group-id");
        assert_ne!(perm & (1 << 9), 0, "sticky");
        assert_ne!(perm & (1 << 6), 0, "user execute");
        assert_ne!(perm & (1 << 3), 0, "group execute");
        assert_ne!(perm & 1, 0, "other execute");
        assert_eq!(perm & FTP_LP_MALFORMATED_PERM, 0);
    }

    #[test]
    fn upper_case_specials_drop_the_execute_bit() {
        // `S` and `T` mean the special bit and NOT the execute bit, so 0o644
        // gains 0o7000 and stays without execute anywhere.
        let perm = ftp_pl_get_permission(b"rwSr-Sr-T");

        assert_eq!(perm, 0o7644);
        assert_ne!(perm & (1 << 11), 0, "set-user-id");
        assert_ne!(perm & (1 << 10), 0, "set-group-id");
        assert_ne!(perm & (1 << 9), 0, "sticky");
        assert_eq!(perm & (1 << 6), 0, "user execute must be clear");
        assert_eq!(perm & (1 << 3), 0, "group execute must be clear");
        assert_eq!(perm & 1, 0, "other execute must be clear");
        assert_eq!(perm & FTP_LP_MALFORMATED_PERM, 0);
    }

    #[test]
    fn a_character_in_the_wrong_position_marks_the_field_malformed() {
        // Every character below is legal SOMEWHERE in the field, so the
        // permission state's own `strchr("rwx-tTsS", c)` admits all nine and
        // only the decoder can catch this. The sticky characters belong in
        // position eight, and here they sit in positions two and five.
        let perm = ftp_pl_get_permission(b"rwtr-Trwx");

        assert_ne!(perm & FTP_LP_MALFORMATED_PERM, 0);
        // The positions that WERE well formed still contributed, because the
        // C keeps decoding after the first bad one: `r`, `w`, `r`, `r`, `w`
        // and `x` all landed, and the two misplaced characters contributed
        // nothing but the marker.
        assert_eq!(perm & 0o7777, 0o647);
    }

    #[test]
    fn a_malformed_permission_field_rejects_the_listing() {
        assert_eq!(
            rejected(b"*", b"drwtr-Trwx 1 u g 1 Jan 1 1970 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_character_outside_the_permission_alphabet_rejects_the_listing() {
        // `q` is in neither `rwx-tTsS` nor the type alphabet, so the state's
        // own check refuses it before the decoder ever runs.
        assert_eq!(
            rejected(b"*", b"drwxr-xr-q 1 u g 1 Jan 1 1970 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_permission_field_of_the_wrong_width_rejects_the_listing() {
        // Eight characters and then a space, so the ninth byte is not one the
        // permission alphabet admits.
        assert_eq!(
            rejected(b"*", b"drwxr-xr 1 u g 1 Jan 1 1970 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_tenth_permission_character_rejects_the_listing() {
        // Nine well-formed characters and then a TENTH, so the byte that has
        // to be the field's delimiter is not a space. This is the other of the
        // permission state's two rejections, and the width test above cannot
        // reach it: there the ninth byte already fails the alphabet.
        assert_eq!(
            rejected(b"*", b"drwxr-xr-xx 1 u g 1 Jan 1 1970 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_short_permission_field_decodes_as_malformed() {
        // Reached only defensively: `byte_at` yields zero past the end, and no
        // position accepts zero.
        assert_ne!(ftp_pl_get_permission(b"rwx") & FTP_LP_MALFORMATED_PERM, 0);
        assert_ne!(ftp_pl_get_permission(b"") & FTP_LP_MALFORMATED_PERM, 0);
    }

    // -----------------------------------------------------------------------
    // The `total <n>` line
    // -----------------------------------------------------------------------

    #[test]
    fn a_total_line_is_accepted_and_contributes_no_entry() {
        let parser = one_shot(
            b"*",
            concat!("total 12\n", "drwxr-xr-x 1 u g 512 Jan 29 23:32 prog\n")
                .as_bytes(),
        );

        assert_eq!(names(&parser), vec!["prog"]);
        assert_eq!(parser.geterror(), CURLcode::Ok);
    }

    #[test]
    fn a_total_line_is_accepted_with_a_carriage_return() {
        let parser = one_shot(
            b"*",
            concat!(
                "total 12\r\n",
                "drwxr-xr-x 1 u g 512 Jan 29 23:32 prog\r\n"
            )
            .as_bytes(),
        );

        assert_eq!(names(&parser), vec!["prog"]);
    }

    #[test]
    fn a_total_line_with_padded_digits_is_accepted() {
        // `curlx_str_passblanks` runs between the prefix and the digits, so a
        // server padding the count is still understood.
        let parser = one_shot(
            b"*",
            concat!(
                "total    12\n",
                "drwxr-xr-x 1 u g 512 Jan 29 23:32 prog\n"
            )
            .as_bytes(),
        );

        assert_eq!(names(&parser), vec!["prog"]);
    }

    #[test]
    fn a_total_line_with_no_count_at_all_is_accepted() {
        // The C's `endptr` sits on the terminator, so its `if(*endptr)` is
        // false and the line passes. Reproduced deliberately.
        let parser = one_shot(
            b"*",
            concat!("total \n", "drwxr-xr-x 1 u g 512 Jan 29 23:32 prog\n")
                .as_bytes(),
        );

        assert_eq!(names(&parser), vec!["prog"]);
    }

    #[test]
    fn a_line_not_beginning_with_t_falls_through_without_losing_the_byte() {
        // The type character IS the byte that decided there was no total
        // line, so a fall-through that consumed it would lose the `d` and
        // read `rwxr-xr-x ` as the permissions.
        let entry = only_entry(FORMAT_1);

        assert_eq!(entry.filetype, FileType::Directory);
        assert_eq!(entry.strings.perm.as_deref(), Some("rwxr-xr-x"));
    }

    #[test]
    fn a_line_beginning_with_t_that_is_not_a_total_line_is_rejected() {
        assert_eq!(rejected(b"*", b"totals 12\n"), CURLcode::FtpBadFileList);
    }

    #[test]
    fn a_total_line_whose_count_is_not_a_number_is_rejected() {
        assert_eq!(rejected(b"*", b"total x\n"), CURLcode::FtpBadFileList);
    }

    #[test]
    fn a_total_line_with_trailing_text_after_its_count_is_rejected() {
        assert_eq!(
            rejected(b"*", b"total 12 files\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_short_line_beginning_with_t_is_rejected() {
        // Shorter than the prefix, so the C's `strncmp` walks into its
        // terminator and fails; the successor's `strip_prefix` fails for the
        // same reason.
        assert_eq!(rejected(b"*", b"tot\n"), CURLcode::FtpBadFileList);
    }

    // -----------------------------------------------------------------------
    // Symlinks
    // -----------------------------------------------------------------------

    #[test]
    fn a_symlink_target_ending_in_crlf_parses() {
        let entry =
            only_entry("lrwxrwxrwx 1 u g 8 Jan  6  4:42 link -> file.txt\r\n");

        assert_eq!(entry.filename, "link");
        assert_eq!(entry.filetype, FileType::Symlink);
        assert_eq!(entry.strings.target.as_deref(), Some("file.txt"));
    }

    #[test]
    fn an_absolute_symlink_target_parses() {
        let entry = only_entry(concat!(
            "lrwxrwxrwx 1 u g 15 Jan  6  4:45 ",
            "link_absolute -> /data/ftp/file.txt\r\n"
        ));

        assert_eq!(entry.filename, "link_absolute");
        assert_eq!(entry.strings.target.as_deref(), Some("/data/ftp/file.txt"));
    }

    #[test]
    fn a_symlink_name_may_contain_the_arrow_characters() {
        // Each of the four pre-target substates returns to the name on an
        // unexpected byte, so `a-b`, `a>b` and `a b` are all names. The LAST
        // arrow is the separator.
        let entry = only_entry("lrwxrwxrwx 1 u g 8 Jan  6  4:42 a-b>c -> d\n");

        assert_eq!(entry.filename, "a-b>c");
        assert_eq!(entry.strings.target.as_deref(), Some("d"));
    }

    #[test]
    fn a_partial_arrow_inside_a_name_returns_the_machine_to_the_name() {
        // One case per pre-target substate, and this is the behaviour that
        // makes `" -> "` the separator rather than any of its bytes: a space
        // that is not followed by a hyphen, a hyphen not followed by a
        // greater-than sign, and a greater-than sign not followed by a space
        // all send the machine back to reading the NAME.
        let cases: [(&str, &str, &str); 3] = [
            ("lrwxrwxrwx 1 u g 8 Jan 1 1970 a b -> c\n", "a b", "c"),
            ("lrwxrwxrwx 1 u g 8 Jan 1 1970 a -b -> c\n", "a -b", "c"),
            ("lrwxrwxrwx 1 u g 8 Jan 1 1970 a ->b -> c\n", "a ->b", "c"),
        ];

        for (listing, name, target) in cases {
            let entry = only_entry(listing);
            assert_eq!(entry.filename, name, "{listing:?}");
            assert_eq!(
                entry.strings.target.as_deref(),
                Some(target),
                "{listing:?}"
            );
            assert_eq!(entry.filetype, FileType::Symlink);
        }
    }

    #[test]
    fn a_symlink_whose_target_contains_an_arrow_is_discarded() {
        // `ftp_pl_insert_finfo` at `:329-333`: the entry matched the pattern
        // and is dropped anyway, because a target holding " -> " means the
        // line carried more arrows than the grammar can attribute.
        let parser =
            one_shot(b"*", b"lrwxrwxrwx 1 u g 8 Jan  6  4:42 a -> b -> c\n");

        assert!(parser.accepted().is_empty(), "queued {:?}", names(&parser));
        assert_eq!(parser.geterror(), CURLcode::Ok);
    }

    #[test]
    fn the_arrow_test_is_the_exact_four_byte_needle() {
        // `a->b` is not the needle, so this target is kept: only the spaced
        // form is the marker of a second arrow.
        let entry = only_entry("lrwxrwxrwx 1 u g 8 Jan  6  4:42 a -> b->c\n");

        assert_eq!(entry.strings.target.as_deref(), Some("b->c"));
        assert!(contains_subslice(b"a -> b", b" -> "));
        assert!(!contains_subslice(b"a->b", b" -> "));
        assert!(!contains_subslice(b"a - > b", b" -> "));
    }

    #[test]
    fn a_non_symlink_whose_stale_target_holds_an_arrow_is_kept() {
        // The discard is guarded on the entry being a symlink, so an inherited
        // offset cannot cost a regular file its place in the queue however
        // its stale target reads.
        let parser = one_shot(
            b"*",
            concat!(
                "lrwxrwxrwx 1 u g 8 Jan  6  4:42 q -> w -> e\n",
                "-rw-r--r-- 1 u g 8 Jan  6  4:42 f\n"
            )
            .as_bytes(),
        );

        assert_eq!(names(&parser), vec!["f"]);
    }

    #[test]
    fn a_symlink_line_ending_before_its_arrow_is_rejected() {
        assert_eq!(
            rejected(b"*", b"lrwxrwxrwx 1 u g 8 Jan  6  4:42 link\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_line_ending_part_way_through_the_arrow_is_rejected() {
        // One case for each of the four pre-target substates, so that a line
        // truncated anywhere inside `" -> "` is refused rather than half
        // parsed. The fourth is the empty-target case tested below it.
        let listings: [&str; 3] = [
            "lrwxrwxrwx 1 u g 8 Jan  6  4:42 link \n",
            "lrwxrwxrwx 1 u g 8 Jan  6  4:42 link -\n",
            "lrwxrwxrwx 1 u g 8 Jan  6  4:42 link ->\n",
        ];

        for (index, listing) in listings.iter().enumerate() {
            assert_eq!(
                rejected(b"*", listing.as_bytes()),
                CURLcode::FtpBadFileList,
                "pre-target substate {}",
                index + 1
            );
        }
        // And with a carriage return in place of the line feed, which is the
        // other half of each of those three tests.
        for listing in [
            "lrwxrwxrwx 1 u g 8 Jan  6  4:42 link \r\n",
            "lrwxrwxrwx 1 u g 8 Jan  6  4:42 link -\r\n",
            "lrwxrwxrwx 1 u g 8 Jan  6  4:42 link ->\r\n",
        ] {
            assert_eq!(
                rejected(b"*", listing.as_bytes()),
                CURLcode::FtpBadFileList
            );
        }
    }

    #[test]
    fn padding_before_a_symlink_name_is_skipped() {
        // The year form leaves two spaces before the name, and the symlink
        // states have to skip the second exactly as the filename states do.
        let entry =
            only_entry("lrwxrwxrwx 1 u g 8 Jan 29 1997  link -> target\n");

        assert_eq!(entry.filename, "link");
        assert_eq!(entry.strings.target.as_deref(), Some("target"));
        assert_eq!(entry.strings.time, "Jan 29 1997");
    }

    #[test]
    fn a_symlink_with_an_empty_target_is_rejected() {
        assert_eq!(
            rejected(b"*", b"lrwxrwxrwx 1 u g 8 Jan  6  4:42 link -> \n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_stray_carriage_return_in_a_symlink_target_is_rejected() {
        assert_eq!(
            rejected(b"*", b"lrwxrwxrwx 1 u g 8 Jan 6 4:42 l -> a\rb\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_stray_carriage_return_in_a_filename_is_rejected() {
        assert_eq!(
            rejected(b"*", b"-rw-r--r-- 1 u g 8 Jan 6 4:42 a\rb\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_stray_carriage_return_in_a_dos_filename_is_rejected() {
        assert_eq!(
            rejected(b"*", b"01-29-97 11:32PM <DIR> a\rb\n"),
            CURLcode::FtpBadFileList
        );
    }

    // -----------------------------------------------------------------------
    // Absent against present, for each optional member
    // -----------------------------------------------------------------------

    #[test]
    fn a_unix_entry_has_permission_owner_and_group_but_no_target() {
        let entry = only_entry(FORMAT_1);

        assert!(entry.strings.perm.is_some(), "permission text");
        assert!(entry.strings.user.is_some(), "owner");
        assert!(entry.strings.group.is_some(), "group");
        assert_eq!(entry.strings.target, None, "target");
        // The two the C assigns unconditionally.
        assert!(!entry.filename.is_empty(), "filename");
        assert!(!entry.strings.time.is_empty(), "time text");
    }

    #[test]
    fn a_unix_symlink_has_all_five_textual_members() {
        let entry = only_entry(FORMAT_4);

        assert!(entry.strings.perm.is_some(), "permission text");
        assert!(entry.strings.user.is_some(), "owner");
        assert!(entry.strings.group.is_some(), "group");
        assert!(entry.strings.target.is_some(), "target");
        assert!(!entry.filename.is_empty(), "filename");
        assert!(!entry.strings.time.is_empty(), "time text");
    }

    #[test]
    fn a_dos_entry_has_none_of_the_four_optional_members() {
        let entry = only_entry(FORMAT_5);

        assert_eq!(entry.strings.perm, None, "permission text");
        assert_eq!(entry.strings.user, None, "owner");
        assert_eq!(entry.strings.group, None, "group");
        assert_eq!(entry.strings.target, None, "target");
        // And still both of the unconditional ones, which is the whole reason
        // `strings.time` carries no guard in the C.
        assert_eq!(entry.filename, "prog");
        assert_eq!(entry.strings.time, "01-29-97 11:32PM");
    }

    #[test]
    fn the_offsets_are_not_reset_between_entries() {
        // A recorded C quirk, reproduced rather than repaired: `offsets` lives
        // on the parser and the record buffer does not, so an entry following
        // a symlink inherits the symlink's target offset and reports whatever
        // its own buffer holds there. `tests/libtest/lib576.c:60-64` prints a
        // target only for a symlink, which is why the C's callers never see
        // it.
        let parser = one_shot(
            b"*",
            concat!(
                "lrwxrwxrwx    1 ftp-default ftp-default       0 ",
                "Jan  6  4:42 link -> file.txt\r\n",
                "-rw-r--r--    1 ftp-default ftp-default      35 ",
                "Apr 27 11:01 file.txt\n"
            )
            .as_bytes(),
        );

        assert_eq!(names(&parser), vec!["link", "file.txt"]);
        let second = match parser.accepted().get(1) {
            Some(entry) => entry.clone(),
            None => FileInfo::default(),
        };
        assert_eq!(second.filetype, FileType::File);
        // Inherited, not parsed: the second line has no target of its own.
        assert!(
            second.strings.target.is_some(),
            "the stale offset should still resolve to a field"
        );
        // A fresh parser over the same regular file reports no target at all,
        // which is what pins the difference to the inherited offset.
        let alone = only_entry(concat!(
            "-rw-r--r--    1 ftp-default ftp-default      35 ",
            "Apr 27 11:01 file.txt\n"
        ));
        assert_eq!(alone.strings.target, None);
    }

    // -----------------------------------------------------------------------
    // The record ceiling
    // -----------------------------------------------------------------------

    /// The Unix prefix through the time column, so that only the filename
    /// grows.
    const LONG_PREFIX: &str = "drwxr-xr-x 1 user01 ftp  512 Jan 29 23:32 ";

    #[test]
    fn a_record_at_the_ceiling_is_accepted() {
        // The buffer measures a candidate append as `len + 1 + 1` against
        // `MAX_FTPLIST_BUFFER`, exactly as the C does, so the largest record
        // it will hold is one byte short of the constant.
        let admitted = MAX_FTPLIST_BUFFER - 1;
        let mut listing = LONG_PREFIX.as_bytes().to_vec();
        listing.resize(admitted, b'a');
        assert_eq!(listing.len(), admitted);

        let mut parser = ParselistData::new(b"*");
        assert!(parser.push(&listing).is_ok());
        assert_eq!(parser.geterror(), CURLcode::Ok);
        // The record is still open: nothing has completed it.
        assert!(parser.file_data.is_some());
        assert!(parser.accepted().is_empty());
    }

    #[test]
    fn the_first_append_past_the_ceiling_is_out_of_memory() {
        let admitted = MAX_FTPLIST_BUFFER - 1;
        let mut listing = LONG_PREFIX.as_bytes().to_vec();
        listing.resize(admitted, b'a');

        let mut parser = ParselistData::new(b"*");
        assert!(parser.push(&listing).is_ok());

        let outcome = parser.push(b"a");
        match outcome {
            Ok(()) => panic!("the ceiling did not hold"),
            Err(error) => assert_eq!(error.code(), CURLcode::OutOfMemory),
        }
        // The mapping is the C's, and the record under construction is
        // released rather than left behind.
        assert_eq!(parser.geterror(), CURLcode::OutOfMemory);
        assert!(
            parser.file_data.is_none(),
            "the oversized record was not released"
        );
        assert!(parser.accepted().is_empty());
    }

    #[test]
    fn the_ceiling_is_per_record_and_not_per_transfer() {
        // Six entries whose bytes together far exceed the ceiling, each one
        // well inside it. A parser that bounded the transfer rather than the
        // record would fail here.
        let one = "-rw-r--r-- 1 user01 ftp 8 Jan 29 23:32 name\n";
        let repeats = (MAX_FTPLIST_BUFFER / one.len()) + 6;
        let listing = one.repeat(repeats);
        assert!(listing.len() > MAX_FTPLIST_BUFFER);

        let parser = one_shot(b"*", listing.as_bytes());
        assert_eq!(parser.accepted().len(), repeats);
        assert_eq!(parser.geterror(), CURLcode::Ok);
    }

    // -----------------------------------------------------------------------
    // The latched error
    // -----------------------------------------------------------------------

    #[test]
    fn an_error_latches_and_every_later_push_repeats_it() {
        let mut parser = ParselistData::new(b"*");

        // `x` is not a type character, so the first byte fails.
        let first = parser.push(b"x");
        match first {
            Ok(()) => panic!("the bad type character was accepted"),
            Err(error) => assert_eq!(error.code(), CURLcode::FtpBadFileList),
        }
        assert_eq!(parser.geterror(), CURLcode::FtpBadFileList);
        let after_failure = snapshot(&parser);

        // Perfectly good listing bytes, twice, and neither is examined.
        for attempt in 0..2 {
            let outcome = parser.push(FORMAT_1.as_bytes());
            match outcome {
                Ok(()) => panic!("attempt {attempt} was not short-circuited"),
                Err(error) => assert_eq!(
                    error.code(),
                    CURLcode::FtpBadFileList,
                    "attempt {attempt} reported a different error"
                ),
            }
            assert!(parser.accepted().is_empty());
            assert_eq!(
                snapshot(&parser),
                after_failure,
                "attempt {attempt} moved the parser"
            );
        }
        // Reading the error does not clear it.
        assert_eq!(parser.geterror(), CURLcode::FtpBadFileList);
        assert_eq!(parser.geterror(), CURLcode::FtpBadFileList);
    }

    #[test]
    fn entries_queued_before_a_failure_are_kept() {
        // The C appends into the wildcard's list as it goes and the failure
        // releases only the record under construction, so a listing that
        // breaks part way through still yields what it had parsed.
        let mut parser = ParselistData::new(b"*");
        let listing = concat!(
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 good\n",
            "xrw-r--r-- 1 u g 8 Jan 29 23:32 bad\n",
        );

        assert!(parser.push(listing.as_bytes()).is_err());
        assert_eq!(names(&parser), vec!["good"]);
        assert_eq!(parser.geterror(), CURLcode::FtpBadFileList);
    }

    #[test]
    fn a_fresh_parser_reports_no_error() {
        let parser = ParselistData::new(b"*.txt");

        assert_eq!(parser.geterror(), CURLcode::Ok);
        assert_eq!(parser.pattern(), b"*.txt");
        assert!(parser.accepted().is_empty());
        assert_eq!(parser.os_type(), OsType::Unknown);
    }

    // -----------------------------------------------------------------------
    // Format detection
    // -----------------------------------------------------------------------

    #[test]
    fn a_leading_digit_selects_the_dos_format() {
        let parser = one_shot(b"*", FORMAT_5.as_bytes());

        assert_eq!(parser.os_type(), OsType::WinNt);
        assert_eq!(names(&parser), vec!["prog"]);
    }

    #[test]
    fn any_other_leading_byte_selects_the_unix_format() {
        let parser = one_shot(b"*", FORMAT_1.as_bytes());

        assert_eq!(parser.os_type(), OsType::Unix);
    }

    #[test]
    fn an_empty_push_decides_nothing() {
        let mut parser = ParselistData::new(b"*");

        assert!(parser.push(b"").is_ok());
        assert_eq!(parser.os_type(), OsType::Unknown);
        assert!(parser.file_data.is_none());
        assert_eq!(parser.geterror(), CURLcode::Ok);

        // And the decision is still available to the next chunk, three empty
        // calls later.
        assert!(parser.push(b"").is_ok());
        assert!(parser.push(b"").is_ok());
        assert!(parser.push(FORMAT_5.as_bytes()).is_ok());
        assert_eq!(parser.os_type(), OsType::WinNt);
        assert_eq!(names(&parser), vec!["prog"]);
    }

    #[test]
    fn the_format_is_decided_once_and_never_revisited() {
        // A Unix listing whose SECOND line opens with a digit stays Unix, so
        // that line is read as a Unix line and rejected -- detection is not
        // per line. The first line still parsed, which is why this cannot go
        // through the helper that requires an empty queue.
        let mut parser = ParselistData::new(b"*");
        let listing = concat!(
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 f\n",
            "01-29-97 11:32PM <DIR> prog\n",
        );

        let outcome = parser.push(listing.as_bytes());
        match outcome {
            Ok(()) => panic!("the DOS line was read as a Unix line"),
            Err(error) => assert_eq!(error.code(), CURLcode::FtpBadFileList),
        }
        assert_eq!(parser.os_type(), OsType::Unix);
        assert_eq!(names(&parser), vec!["f"]);
    }

    // -----------------------------------------------------------------------
    // The DOS machine's own rejections
    // -----------------------------------------------------------------------

    #[test]
    fn a_dos_date_with_a_bad_character_is_rejected() {
        assert_eq!(
            rejected(b"*", b"01-2x-97 11:32PM <DIR> prog\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_dos_date_of_the_wrong_width_is_rejected() {
        assert_eq!(
            rejected(b"*", b"01-29-971 11:32PM <DIR> prog\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_dos_time_with_a_bad_character_is_rejected() {
        assert_eq!(
            rejected(b"*", b"01-29-97 11:3xPM <DIR> prog\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_dos_size_column_that_is_neither_marker_nor_number_is_rejected() {
        assert_eq!(
            rejected(b"*", b"01-29-97 11:32PM <FILE> prog\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_dos_size_column_with_trailing_text_keeps_its_leading_number() {
        // The asymmetry with the Unix size column, recorded on
        // `parse_winnt`: there the number must reach the field's end, here it
        // need not.
        let entry = only_entry("01-29-97 11:32PM 12abc prog\n");

        assert_eq!(entry.size, 12);
        assert_eq!(entry.filetype, FileType::File);
        assert!(entry.knows(FileInfo::KNOWN_SIZE));
    }

    // -----------------------------------------------------------------------
    // The Unix machine's numeric columns
    // -----------------------------------------------------------------------

    #[test]
    fn a_non_numeric_hard_link_count_is_rejected() {
        assert_eq!(
            rejected(b"*", b"-rw-r--r-- x u g 8 Jan 29 23:32 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_hard_link_count_with_a_letter_inside_it_is_rejected() {
        assert_eq!(
            rejected(b"*", b"-rw-r--r-- 1x u g 8 Jan 29 23:32 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn an_unusable_hard_link_count_leaves_the_flag_clear_and_parses_on() {
        // Twenty-five digits overflow the bound, which is the only way a
        // field already checked digit by digit can fail to parse. The C sets
        // no flag, keeps the value at zero, and CONTINUES.
        let entry = only_entry(concat!(
            "-rw-r--r-- 1111111111111111111111111 u g 8 ",
            "Jan 29 23:32 f\n"
        ));

        assert_eq!(entry.filename, "f");
        assert_eq!(entry.hardlinks, 0);
        assert!(!entry.knows(FileInfo::KNOWN_HLINKCOUNT));
        // The rest of the line still parsed.
        assert!(entry.knows(FileInfo::KNOWN_SIZE));
        assert_eq!(entry.size, 8);
    }

    #[test]
    fn a_non_numeric_size_column_is_rejected() {
        assert_eq!(
            rejected(b"*", b"-rw-r--r-- 1 u g x Jan 29 23:32 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_size_column_with_a_letter_inside_it_is_rejected() {
        assert_eq!(
            rejected(b"*", b"-rw-r--r-- 1 u g 8x Jan 29 23:32 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn a_large_size_parses_exactly() {
        let entry =
            only_entry("-rw-r--r-- 1 u g 9223372036854775806 Jan 29 23:32 f\n");

        assert_eq!(entry.size, 9_223_372_036_854_775_806);
        assert!(entry.knows(FileInfo::KNOWN_SIZE));
    }

    #[test]
    fn the_maximum_size_is_treated_as_no_answer() {
        // `fsize != CURL_OFF_T_MAX` at `:589`: the value an overflow
        // saturates to is not believed, even when the digits really said it.
        let entry =
            only_entry("-rw-r--r-- 1 u g 9223372036854775807 Jan 29 23:32 f\n");

        assert_eq!(entry.filename, "f");
        assert!(!entry.knows(FileInfo::KNOWN_SIZE));
        assert_eq!(entry.size, 0);
    }

    #[test]
    fn a_time_part_with_a_bad_character_is_rejected() {
        // A comma is neither alphanumeric nor one of the two punctuation
        // characters the time field admits.
        assert_eq!(
            rejected(b"*", b"-rw-r--r-- 1 u g 8 Ja,n 29 23:32 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn padding_before_the_time_field_is_skipped() {
        // The size column ends on its FIRST following space, so a server that
        // pads the gap leaves the time field's own state to skip the rest.
        let entry = only_entry("-rw-r--r-- 1 u g 8   Jan 29 23:32 f\n");

        assert_eq!(entry.filename, "f");
        assert_eq!(entry.strings.time, "Jan 29 23:32");
        assert_eq!(entry.size, 8);
    }

    #[test]
    fn a_full_stop_is_accepted_inside_the_first_two_time_parts() {
        let entry = only_entry("-rw-r--r-- 1 u g 8 Jan. 29. 23:32 f\n");

        assert_eq!(entry.strings.time, "Jan. 29. 23:32");
    }

    #[test]
    fn a_colon_is_accepted_only_in_the_third_time_part() {
        assert_eq!(
            rejected(b"*", b"-rw-r--r-- 1 u g 8 J:n 29 23:32 f\n"),
            CURLcode::FtpBadFileList
        );
    }

    #[test]
    fn each_of_the_six_time_substates_rejects_what_it_must() {
        // One case per substate, so that a transposed transition cannot pass
        // by having some other substate answer for it. The first byte of each
        // PART must be a letter or a digit; inside a part, a full stop is
        // additionally allowed, and a colon only in the third.
        let cases: [(&str, &str); 6] = [
            ("the first part does not begin with a letter or digit", "*"),
            ("a bad character inside the first part", "*"),
            ("the second part does not begin with a letter or digit", "*"),
            ("a bad character inside the second part", "*"),
            ("the third part does not begin with a letter or digit", "*"),
            ("a bad character inside the third part", "*"),
        ];
        let listings: [&str; 6] = [
            "-rw-r--r-- 1 u g 8 .Jan 29 23:32 f\n",
            "-rw-r--r-- 1 u g 8 Ja,n 29 23:32 f\n",
            "-rw-r--r-- 1 u g 8 Jan .29 23:32 f\n",
            "-rw-r--r-- 1 u g 8 Jan 2,9 23:32 f\n",
            "-rw-r--r-- 1 u g 8 Jan 29 .23:32 f\n",
            "-rw-r--r-- 1 u g 8 Jan 29 23,32 f\n",
        ];

        for (index, listing) in listings.iter().enumerate() {
            let (what, pattern) = cases[index];
            assert_eq!(
                rejected(pattern.as_bytes(), listing.as_bytes()),
                CURLcode::FtpBadFileList,
                "{what}"
            );
        }
    }

    #[test]
    fn an_unusable_size_leaves_the_machine_inside_the_size_column() {
        // Twenty-five digits overflow the bound, and unlike the hard-link
        // count the C makes NO transition when the size fails to parse: the
        // machine stays in the size column, so the month that follows is
        // judged as a continuation of the number and rejected.
        assert_eq!(
            rejected(
                b"*",
                concat!(
                    "-rw-r--r-- 1 u g 1111111111111111111111111 ",
                    "Jan 29 23:32 f\n"
                )
                .as_bytes()
            ),
            CURLcode::FtpBadFileList
        );
    }

    // -----------------------------------------------------------------------
    // The comparator and its guard
    // -----------------------------------------------------------------------

    #[test]
    fn the_default_comparator_applies_the_pattern() {
        let parser = one_shot(
            b"*.txt",
            concat!(
                "-rw-r--r-- 1 u g 8 Jan 29 23:32 keep.txt\n",
                "-rw-r--r-- 1 u g 8 Jan 29 23:32 drop.dat\n",
                "-rw-r--r-- 1 u g 8 Jan 29 23:32 also.txt\n"
            )
            .as_bytes(),
        );

        assert_eq!(names(&parser), vec!["keep.txt", "also.txt"]);
    }

    #[test]
    fn the_default_comparator_is_curls_own_matcher() {
        let mut matcher = DefaultMatcher;

        assert_eq!(matcher.compare(b"*.txt", b"a.txt"), 0);
        assert_eq!(matcher.compare(b"*.txt", b"a.dat"), 1);
        assert_eq!(matcher.compare(b"[[:digit:]]", b"7"), 0);
        // The integers are the callback contract's, not this module's.
        assert_eq!(FnMatch::Match as i32, 0);
        assert_eq!(FnMatch::NoMatch as i32, 1);
        assert_eq!(FnMatch::Fail as i32, 2);
    }

    #[test]
    fn a_supplied_comparator_replaces_the_default() {
        let mut matcher = RecordingMatcher::admitting(&["b"]);
        let mut parser = ParselistData::new(b"*");
        let listing = concat!(
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 a\n",
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 b\n",
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 c\n",
        );

        assert!(parser
            .push_matching(listing.as_bytes(), &mut matcher)
            .is_ok());

        assert_eq!(names(&parser), vec!["b"]);
        // Called once per completed entry, with the parser's pattern.
        assert_eq!(
            matcher.seen,
            vec![
                (b"*".to_vec(), b"a".to_vec()),
                (b"*".to_vec(), b"b".to_vec()),
                (b"*".to_vec(), b"c".to_vec()),
            ]
        );
    }

    #[test]
    fn the_in_callback_flag_is_set_around_every_comparison() {
        let mut matcher = RecordingMatcher::returning(0);
        let mut parser = ParselistData::new(b"*");
        let listing = concat!(
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 a\n",
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 b\n",
        );

        assert!(parser
            .push_matching(listing.as_bytes(), &mut matcher)
            .is_ok());

        assert_eq!(names(&parser), vec!["a", "b"]);
        assert!(
            matcher.always_inside,
            "a comparison ran with the flag clear"
        );
        // Set then cleared, once per entry, and never left set.
        assert_eq!(matcher.flag, vec![true, false, true, false]);
    }

    #[test]
    fn the_in_callback_flag_is_cleared_when_the_comparison_refuses() {
        let mut matcher = RecordingMatcher::returning(1);
        let mut parser = ParselistData::new(b"*");

        assert!(parser
            .push_matching(FORMAT_1.as_bytes(), &mut matcher)
            .is_ok());

        assert!(parser.accepted().is_empty());
        assert_eq!(matcher.flag, vec![true, false]);
    }

    #[test]
    fn a_comparator_reporting_failure_excludes_the_entry() {
        // `CURL_FNMATCHFUNC_FAIL` is not zero, so it excludes exactly as
        // `NOMATCH` does; the two are indistinguishable at this call site and
        // the type keeps them apart anyway.
        let mut matcher = RecordingMatcher::returning(2);
        let mut parser = ParselistData::new(b"*");

        assert!(parser
            .push_matching(FORMAT_1.as_bytes(), &mut matcher)
            .is_ok());

        assert!(parser.accepted().is_empty());
        assert_eq!(matcher.flag, vec![true, false]);
    }

    #[test]
    fn a_comparator_is_not_consulted_for_a_rejected_listing() {
        let mut matcher = RecordingMatcher::returning(0);
        let mut parser = ParselistData::new(b"*");

        assert!(parser.push_matching(b"xrw-r--r--", &mut matcher).is_err());

        assert!(matcher.seen.is_empty());
        assert!(matcher.flag.is_empty(), "the flag was touched");
    }

    #[test]
    fn a_comparator_may_be_reached_through_a_trait_object() {
        // `push_matching` takes `?Sized`, so a caller holding the comparator
        // behind a reference to the trait needs no wrapper. The wildcard
        // driver's `CURLOPT_FNMATCH_FUNCTION` adapter is that caller.
        let mut concrete = RecordingMatcher::returning(0);
        let mut parser = ParselistData::new(b"*");
        let dynamic: &mut dyn FilenameMatcher = &mut concrete;

        assert!(parser.push_matching(FORMAT_1.as_bytes(), dynamic).is_ok());

        assert_eq!(names(&parser), vec!["prog"]);
        assert_eq!(concrete.flag, vec![true, false]);
    }

    // -----------------------------------------------------------------------
    // The queue
    // -----------------------------------------------------------------------

    #[test]
    fn entries_keep_the_order_the_server_listed_them_in() {
        let listing = concat!(
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 zulu\n",
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 alpha\n",
            "-rw-r--r-- 1 u g 8 Jan 29 23:32 mike\n",
        );
        let parser = one_shot(b"*", listing.as_bytes());

        // Arrival order, not sorted order: the transfer order is the listing
        // order.
        assert_eq!(names(&parser), vec!["zulu", "alpha", "mike"]);
    }

    #[test]
    fn taking_the_queue_empties_it_and_keeps_the_order() {
        let mut parser = one_shot(b"*", MIXED.as_bytes());
        let expected = names(&parser);

        let taken = parser.take_accepted();

        assert_eq!(
            taken
                .iter()
                .map(|entry| entry.filename.clone())
                .collect::<Vec<String>>(),
            expected
        );
        assert!(parser.accepted().is_empty());
        // And the parser is still usable afterwards.
        assert!(parser.push(FORMAT_1.as_bytes()).is_ok());
        assert_eq!(names(&parser), vec!["prog"]);
    }

    // -----------------------------------------------------------------------
    // The pinned integers
    // -----------------------------------------------------------------------

    #[test]
    fn every_file_type_holds_its_declared_integer() {
        let expected: [(FileType, i32); 9] = [
            (FileType::File, 0),
            (FileType::Directory, 1),
            (FileType::Symlink, 2),
            (FileType::DeviceBlock, 3),
            (FileType::DeviceChar, 4),
            (FileType::NamedPipe, 5),
            (FileType::Socket, 6),
            (FileType::Door, 7),
            (FileType::Unknown, 8),
        ];

        for (variant, value) in expected {
            assert_eq!(variant.as_i32(), value, "{variant:?}");
            assert_eq!(variant as i32, value, "{variant:?}");
        }
        // Declaration order is ascending numeric order, with no gap and no
        // repetition.
        assert_eq!(FileType::VARIANTS.len(), 9);
        for (index, variant) in FileType::VARIANTS.iter().enumerate() {
            assert_eq!(
                variant.as_i32(),
                i32::try_from(index).unwrap_or(-1),
                "VARIANTS is out of order at {index}"
            );
        }
        // A zeroed allocation starts at `CURLFILETYPE_FILE`.
        assert_eq!(FileType::default(), FileType::File);
    }

    #[test]
    fn every_file_information_flag_holds_its_declared_bit() {
        assert_eq!(FileInfo::KNOWN_FILENAME, 1 << 0);
        assert_eq!(FileInfo::KNOWN_FILETYPE, 1 << 1);
        assert_eq!(FileInfo::KNOWN_TIME, 1 << 2);
        assert_eq!(FileInfo::KNOWN_PERM, 1 << 3);
        assert_eq!(FileInfo::KNOWN_UID, 1 << 4);
        assert_eq!(FileInfo::KNOWN_GID, 1 << 5);
        assert_eq!(FileInfo::KNOWN_SIZE, 1 << 6);
        assert_eq!(FileInfo::KNOWN_HLINKCOUNT, 1 << 7);

        // Eight distinct single bits, in declaration order.
        assert_eq!(FileInfo::KNOWN_FLAGS.len(), 8);
        let mut union = 0_u32;
        for (index, flag) in FileInfo::KNOWN_FLAGS.iter().enumerate() {
            assert_eq!(flag.count_ones(), 1, "flag {index} is not one bit");
            assert_eq!(union & flag, 0, "flag {index} repeats an earlier one");
            union |= flag;
        }
        assert_eq!(union, 0xFF);
        // And well clear of the malformed-permission marker, which shares the
        // same integer in the C but not the same field.
        assert_eq!(union & FTP_LP_MALFORMATED_PERM, 0);
    }

    #[test]
    fn the_knows_helper_requires_every_bit_of_its_mask() {
        let entry = FileInfo {
            flags: FileInfo::KNOWN_PERM | FileInfo::KNOWN_SIZE,
            ..FileInfo::default()
        };

        assert!(entry.knows(FileInfo::KNOWN_PERM));
        assert!(entry.knows(FileInfo::KNOWN_SIZE));
        assert!(entry.knows(FileInfo::KNOWN_PERM | FileInfo::KNOWN_SIZE));
        assert!(!entry.knows(FileInfo::KNOWN_PERM | FileInfo::KNOWN_TIME));
        assert!(!entry.knows(FileInfo::KNOWN_HLINKCOUNT));
    }

    #[test]
    fn every_chunk_callback_code_holds_its_declared_integer() {
        assert_eq!(ChunkBgn::Ok.as_i64(), 0);
        assert_eq!(ChunkBgn::Fail.as_i64(), 1);
        assert_eq!(ChunkBgn::Skip.as_i64(), 2);
        assert_eq!(ChunkEnd::Ok.as_i64(), 0);
        assert_eq!(ChunkEnd::Fail.as_i64(), 1);

        assert_eq!(ChunkBgn::VARIANTS.len(), 3);
        assert_eq!(ChunkEnd::VARIANTS.len(), 2);
        for variant in ChunkBgn::VARIANTS {
            assert_eq!(ChunkBgn::from_i64(variant.as_i64()), Some(variant));
        }
        for variant in ChunkEnd::VARIANTS {
            assert_eq!(ChunkEnd::from_i64(variant.as_i64()), Some(variant));
        }
        // Values the public header never described are not classified.
        assert_eq!(ChunkBgn::from_i64(3), None);
        assert_eq!(ChunkBgn::from_i64(-1), None);
        assert_eq!(ChunkEnd::from_i64(2), None);
    }

    #[test]
    fn every_wildcard_state_holds_its_declared_integer() {
        let expected: [(WildcardState, u8); 8] = [
            (WildcardState::Clear, 0),
            (WildcardState::Init, 1),
            (WildcardState::Matching, 2),
            (WildcardState::Downloading, 3),
            (WildcardState::Clean, 4),
            (WildcardState::Skip, 5),
            (WildcardState::Error, 6),
            (WildcardState::Done, 7),
        ];

        for (variant, value) in expected {
            assert_eq!(variant.as_u8(), value, "{variant:?}");
            assert_eq!(variant as u8, value, "{variant:?}");
        }
        assert_eq!(WildcardState::VARIANTS.len(), 8);
        for (index, variant) in WildcardState::VARIANTS.iter().enumerate() {
            assert_eq!(
                usize::from(variant.as_u8()),
                index,
                "VARIANTS is out of order at {index}"
            );
        }
    }

    #[test]
    fn every_format_holds_its_declared_integer() {
        assert_eq!(OsType::Unknown.as_u8(), 0);
        assert_eq!(OsType::Unix.as_u8(), 1);
        assert_eq!(OsType::WinNt.as_u8(), 2);
        assert_eq!(OsType::VARIANTS.len(), 3);
        assert_eq!(OsType::default(), OsType::Unknown);
    }

    #[test]
    fn the_state_machines_keep_the_c_declaration_order() {
        // The order IS the grammar: the state after the size column is the
        // time column and nothing else, so a reordering would silently change
        // which field a byte belongs to.
        let unix: [(UnixMain, u8); 10] = [
            (UnixMain::TotalSize, 0),
            (UnixMain::FileType, 1),
            (UnixMain::Permission, 2),
            (UnixMain::Hlinks, 3),
            (UnixMain::User, 4),
            (UnixMain::Group, 5),
            (UnixMain::Size, 6),
            (UnixMain::Time, 7),
            (UnixMain::Filename, 8),
            (UnixMain::Symlink, 9),
        ];
        for (variant, value) in unix {
            assert_eq!(variant as u8, value, "{variant:?}");
        }
        assert_eq!(UnixMain::default(), UnixMain::TotalSize);

        let winnt: [(WinNtMain, u8); 4] = [
            (WinNtMain::Date, 0),
            (WinNtMain::Time, 1),
            (WinNtMain::DirOrSize, 2),
            (WinNtMain::Filename, 3),
        ];
        for (variant, value) in winnt {
            assert_eq!(variant as u8, value, "{variant:?}");
        }
        assert_eq!(WinNtMain::default(), WinNtMain::Date);
    }

    #[test]
    fn every_substate_keeps_the_c_declaration_order() {
        assert_eq!(TotalDirSizeSub::Init as u8, 0);
        assert_eq!(TotalDirSizeSub::Reading as u8, 1);
        assert_eq!(HlinksSub::PreSpace as u8, 0);
        assert_eq!(HlinksSub::Number as u8, 1);
        assert_eq!(UserSub::PreSpace as u8, 0);
        assert_eq!(UserSub::Parsing as u8, 1);
        assert_eq!(GroupSub::PreSpace as u8, 0);
        assert_eq!(GroupSub::Name as u8, 1);
        assert_eq!(SizeSub::PreSpace as u8, 0);
        assert_eq!(SizeSub::Number as u8, 1);
        assert_eq!(TimeSub::PrePart1 as u8, 0);
        assert_eq!(TimeSub::Part1 as u8, 1);
        assert_eq!(TimeSub::PrePart2 as u8, 2);
        assert_eq!(TimeSub::Part2 as u8, 3);
        assert_eq!(TimeSub::PrePart3 as u8, 4);
        assert_eq!(TimeSub::Part3 as u8, 5);
        assert_eq!(FilenameSub::PreSpace as u8, 0);
        assert_eq!(FilenameSub::Name as u8, 1);
        assert_eq!(FilenameSub::WindowsEol as u8, 2);
        assert_eq!(SymlinkSub::PreSpace as u8, 0);
        assert_eq!(SymlinkSub::Name as u8, 1);
        assert_eq!(SymlinkSub::PreTarget1 as u8, 2);
        assert_eq!(SymlinkSub::PreTarget2 as u8, 3);
        assert_eq!(SymlinkSub::PreTarget3 as u8, 4);
        assert_eq!(SymlinkSub::PreTarget4 as u8, 5);
        assert_eq!(SymlinkSub::Target as u8, 6);
        assert_eq!(SymlinkSub::WindowsEol as u8, 7);
        assert_eq!(NtTimeSub::PreSpace as u8, 0);
        assert_eq!(NtTimeSub::Time as u8, 1);
        assert_eq!(NtDirOrSizeSub::PreSpace as u8, 0);
        assert_eq!(NtDirOrSizeSub::Content as u8, 1);
        assert_eq!(NtFilenameSub::PreSpace as u8, 0);
        assert_eq!(NtFilenameSub::Content as u8, 1);
        assert_eq!(NtFilenameSub::WinEol as u8, 2);
    }

    #[test]
    fn the_record_ceiling_is_the_declared_constant() {
        assert_eq!(MAX_FTPLIST_BUFFER, 10000);
        assert_eq!(FTP_LP_MALFORMATED_PERM, 0x0100_0000);
    }

    #[test]
    fn a_zeroed_substate_reads_as_its_own_field_initial_value() {
        // The fallback that replaces reading the wrong member of the C's
        // union. Unreachable on any parse this module performs, and total
        // rather than undefined if it ever were reached.
        let foreign = UnixSub::Symlink(SymlinkSub::Target);

        assert_eq!(foreign.total_dirsize(), TotalDirSizeSub::Init);
        assert_eq!(foreign.hlinks(), HlinksSub::PreSpace);
        assert_eq!(foreign.user(), UserSub::PreSpace);
        assert_eq!(foreign.group(), GroupSub::PreSpace);
        assert_eq!(foreign.size(), SizeSub::PreSpace);
        assert_eq!(foreign.time(), TimeSub::PrePart1);
        assert_eq!(foreign.filename(), FilenameSub::PreSpace);
        assert_eq!(foreign.symlink(), SymlinkSub::Target);

        // And the symlink extractor's own fallback, which the value above
        // matches rather than falls back from.
        assert_eq!(
            UnixSub::Filename(FilenameSub::Name).symlink(),
            SymlinkSub::PreSpace
        );

        let nt = WinNtSub::Filename(NtFilenameSub::WinEol);
        assert_eq!(nt.time(), NtTimeSub::PreSpace);
        assert_eq!(nt.dirorsize(), NtDirOrSizeSub::PreSpace);
        assert_eq!(nt.filename(), NtFilenameSub::WinEol);
        assert_eq!(
            WinNtSub::Time(NtTimeSub::Time).filename(),
            NtFilenameSub::PreSpace
        );

        // And the zeroed defaults are the C's calloc state.
        assert_eq!(
            UnixSub::default(),
            UnixSub::TotalDirSize(TotalDirSizeSub::Init)
        );
        assert_eq!(WinNtSub::default(), WinNtSub::Time(NtTimeSub::PreSpace));
        assert_eq!(
            ParseState::default(),
            ParseState::Unix {
                main: UnixMain::TotalSize,
                sub: UnixSub::TotalDirSize(TotalDirSizeSub::Init),
            }
        );
    }

    // -----------------------------------------------------------------------
    // The byte helpers
    // -----------------------------------------------------------------------

    #[test]
    fn a_read_past_the_end_yields_the_terminator() {
        assert_eq!(byte_at(b"ab", 0), b'a');
        assert_eq!(byte_at(b"ab", 1), b'b');
        assert_eq!(byte_at(b"ab", 2), 0);
        assert_eq!(byte_at(b"ab", usize::MAX), 0);
        assert_eq!(byte_at(b"", 0), 0);
    }

    #[test]
    fn a_zero_byte_is_a_member_of_every_validation_set() {
        // `strchr` finds its argument's own terminator, so the C admits a zero
        // byte in all three of its character-set checks.
        assert!(set_contains(b"rwx-tTsS", b'r'));
        assert!(!set_contains(b"rwx-tTsS", b'q'));
        assert!(set_contains(b"rwx-tTsS", 0));
        assert!(set_contains(b"0123456789-", 0));
        assert!(set_contains(b"APM0123456789:", 0));
    }

    #[test]
    fn a_field_runs_from_its_offset_to_the_next_zero() {
        let record = b"drwxr-xr-x\0   1\0user01\0";

        assert_eq!(cstr_at(record, 0), b"drwxr-xr-x");
        assert_eq!(cstr_at(record, 1), b"rwxr-xr-x");
        assert_eq!(cstr_at(record, 11), b"   1");
        assert_eq!(cstr_at(record, 16), b"user01");
        // Past the end, and at exactly the end: both empty rather than a read
        // past the buffer, which is where this differs from the C.
        assert_eq!(cstr_at(record, record.len()), b"");
        assert_eq!(cstr_at(record, record.len() + 100), b"");
        // No terminator at all: the field runs to the end.
        assert_eq!(cstr_at(b"tail", 1), b"ail");
    }

    #[test]
    fn a_zero_offset_means_the_field_is_absent() {
        let record = b"abc\0def\0";

        assert_eq!(optional_cstr_at(record, 0), None);
        assert_eq!(optional_cstr_at(record, 4), Some(&b"def"[..]));
    }

    #[test]
    fn a_slice_past_a_field_keeps_what_follows_its_terminator() {
        let record = b"512\0Jan";

        assert_eq!(tail_at(record, 0), b"512\0Jan");
        assert_eq!(tail_at(record, 4), b"Jan");
        assert_eq!(tail_at(record, record.len()), b"");
        assert_eq!(tail_at(record, record.len() + 1), b"");
    }

    #[test]
    fn a_needle_is_found_only_where_it_really_is() {
        assert!(contains_subslice(b"abc", b"abc"));
        assert!(contains_subslice(b"xabcx", b"abc"));
        assert!(contains_subslice(b"abcx", b"abc"));
        assert!(contains_subslice(b"xabc", b"abc"));
        assert!(!contains_subslice(b"ab", b"abc"));
        assert!(!contains_subslice(b"", b"abc"));
        assert!(!contains_subslice(b"abd", b"abc"));
        // An empty needle is present everywhere, matching `strstr`.
        assert!(contains_subslice(b"", b""));
        assert!(contains_subslice(b"abc", b""));
    }

    #[test]
    fn text_that_is_not_valid_survives_as_replacement_characters() {
        // Divergence 2, pinned: the conversion is lossy and never fails, so a
        // listing curl accepts cannot become a transfer error here.
        assert_eq!(owned_text(b"file.txt"), "file.txt");
        assert_eq!(owned_text(b""), "");
        assert_eq!(owned_text(&[0xC3, 0xA9]), "\u{e9}");
        assert_eq!(owned_text(&[0xFF]), "\u{fffd}");
    }

    #[test]
    fn a_filename_that_is_not_valid_text_still_produces_an_entry() {
        let mut listing = LONG_PREFIX.as_bytes().to_vec();
        listing.extend_from_slice(&[b'f', 0xFF, b'g', b'\n']);
        let parser = one_shot(b"*", &listing);

        assert_eq!(parser.accepted().len(), 1);
        assert_eq!(names(&parser), vec!["f\u{fffd}g"]);
    }

    // -----------------------------------------------------------------------
    // Wildcard ownership
    // -----------------------------------------------------------------------

    #[test]
    fn a_fresh_wildcard_is_initialized_rather_than_cleared() {
        let wildcard = WildcardData::default();

        // `Curl_wildcard_init` sets CURLWC_INIT, not CURLWC_CLEAR; the latter
        // is what a zeroed allocation held before it ran.
        assert_eq!(wildcard.state, WildcardState::Init);
        assert_ne!(wildcard.state, WildcardState::Clear);
        assert_eq!(wildcard.path, None);
        assert_eq!(wildcard.pattern, None);
        assert!(wildcard.filelist.is_empty());
        assert!(wildcard.ftpwc.is_none());
    }

    #[test]
    fn resetting_a_wildcard_releases_everything_and_returns_to_init() {
        let mut wildcard = WildcardData {
            path: Some(String::from("/pub/dir")),
            pattern: Some(String::from("*.txt")),
            filelist: one_shot(b"*", MIXED.as_bytes()).take_accepted(),
            ftpwc: Some(FtpWildcard::new(b"*.txt")),
            state: WildcardState::Downloading,
        };
        assert_eq!(wildcard.filelist.len(), 5);

        wildcard.reset();

        assert_eq!(wildcard.state, WildcardState::Init);
        assert_eq!(wildcard.path, None);
        assert_eq!(wildcard.pattern, None);
        assert!(wildcard.filelist.is_empty());
        assert!(wildcard.ftpwc.is_none());
        // Indistinguishable from a fresh one, which is what makes it reusable
        // between two directories.
        let fresh = WildcardData::default();
        assert_eq!(wildcard.state, fresh.state);
        assert_eq!(wildcard.path, fresh.path);
        assert_eq!(wildcard.pattern, fresh.pattern);
        assert_eq!(wildcard.filelist, fresh.filelist);
    }

    #[test]
    fn a_populated_wildcard_releases_itself_when_dropped() {
        // No destructor to register and none to forget: the C stores a
        // function pointer for the FTP context and a second one for the file
        // list, and both disappear here. Dropping a fully populated structure
        // is the whole test, and Miri is what makes it meaningful.
        let wildcard = WildcardData {
            path: Some(String::from("/pub/dir")),
            pattern: Some(String::from("*")),
            filelist: one_shot(b"*", MIXED.as_bytes()).take_accepted(),
            ftpwc: Some(FtpWildcard::new(b"*")),
            state: WildcardState::Matching,
        };

        assert_eq!(wildcard.filelist.len(), 5);
        drop(wildcard);
    }

    #[test]
    fn a_wildcard_context_carries_a_parser_and_an_uninstalled_writer() {
        let mut context = FtpWildcard::new(b"*.txt");

        assert_eq!(context.parser.pattern(), b"*.txt");
        assert_eq!(context.parser.geterror(), CURLcode::Ok);
        assert!(!context.backup.listing_writer_installed);

        // The driver's own use of it: feed the listing through the parser it
        // owns, then move the entries across.
        assert!(context
            .parser
            .push(b"-rw-r--r-- 1 u g 8 Jan 29 23:32 a.txt\n")
            .is_ok());
        let mut wildcard = WildcardData::default();
        wildcard.filelist.extend(context.parser.take_accepted());

        assert_eq!(wildcard.filelist.len(), 1);
        match wildcard.filelist.front() {
            Some(entry) => assert_eq!(entry.filename, "a.txt"),
            None => panic!("the entry did not survive the move"),
        }
    }
}
