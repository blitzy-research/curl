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

//! The HTTP Strict Transport Security cache -- RFC 6797.
//!
//! Supersedes `lib/hsts.c` and `lib/hsts.h`, and backs `--hsts <file>`
//! together with `CURLOPT_HSTS` (10300), `CURLOPT_HSTS_CTRL` (299),
//! `CURLOPT_HSTSREADFUNCTION` (20301), `CURLOPT_HSTSREADDATA` (10302),
//! `CURLOPT_HSTSWRITEFUNCTION` (20303) and `CURLOPT_HSTSWRITEDATA` (10304).
//!
//! # The clock is injected
//!
//! Every instant comes from [`Clock::epoch_secs`] -- the **wall** clock, since
//! the C calls `time(NULL)`. That covers the stamps written into the file, the
//! `max-age` addition and every expiry comparison. `Clock::now` is monotonic
//! and is not used here; `super::psl` is the one sibling that wants it,
//! because `lib/psl.c:52` goes through `Curl_pgrs_now` instead.
//!
//! Injection is faithful rather than invented. `lib/hsts.c:46-64` already
//! carries `hsts_debugtime`, a `DEBUGBUILD || UNITTESTS` shim that reads the
//! `CURL_TIME` environment variable plus a mutable `deltatime` and then
//! `#define time(x)`. The C needs an environment variable because C has no
//! better seam; [`Clock`] is that seam, so the `CURL_TIME` mechanism itself is
//! deliberately **not** reproduced.
//!
//! # ABI coupling, for the `curl-rs-ffi` agent
//!
//! Three public shapes belong to `curl-rs-ffi` and are **not** redefined here:
//!
//! * `struct curl_hstsentry { char *name; size_t namelen;
//!   unsigned int includeSubDomains:1; char expire[18]; }`
//!   (`include/curl/curl.h:1044-1049`). `tests/unit/unit3214.c` caps its size
//!   at 40 bytes. [`HstsEntryBuf`] is the Rust-native mirror the callbacks
//!   fill and read; the ABI crate marshals between the two, and
//!   [`HstsEntryBuf::NAME_CAPACITY`] and [`HstsEntryBuf::EXPIRE_CAPACITY`] are
//!   the two bounds it must honour.
//! * `struct curl_index { size_t index; size_t total; }`
//!   (`:1051-1054`, `index` first) is [`EntryIndex`].
//! * `CURLSTScode { CURLSTS_OK = 0, CURLSTS_DONE = 1, CURLSTS_FAIL = 2 }`
//!   (`:1056-1060`) is [`StsCode`]. The discriminants are recorded here for
//!   provenance and are pinned in the ABI crate, not in this enumeration --
//!   the same split `crate::util::strparse::StrError` draws, for the same
//!   reason: a value that never crosses the boundary must not carry the
//!   boundary's obligation.
//!
//! # Ordering is a contract
//!
//! Entries are written in list order, which is insertion order: the C walks
//! `Curl_llist_head` then `Curl_node_next` (`:354-356`). Nothing sorts, and a
//! hash map is not an option -- its iteration order is randomised and would
//! change the file bytes from run to run.

use std::collections::VecDeque;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::error::{CURLcode, CodeResult};
// The two open flags for the hardened save, from the one directory in this
// crate allowed to name `libc`; `crate::util::fopen` cannot import them itself.
use crate::ffi::{O_CLOEXEC, O_NOFOLLOW};
use crate::util::dynbuf::DynBuf;
use crate::util::fopen;
use crate::util::get_line::get_line;
use crate::util::inet;
use crate::util::llist;
use crate::util::parsedate::{self, Outcome};
use crate::util::slist::SList;
use crate::util::strcase;
use crate::util::strparse::{self, StrError};
use crate::util::timeval::{self, Clock};

// Constants -- `lib/hsts.c:41-44` and `include/curl/curl.h:1071-1072`.

/// The longest line the reader will accept -- `MAX_HSTS_LINE`
/// (`lib/hsts.c:41`).
///
/// Handed to [`DynBuf::new`] as the ceiling, exactly as `lib/hsts.c:510`
/// hands it to `curlx_dyn_init`. A longer line makes [`get_line`] return
/// `CURLcode::TooLarge`, which ends the load.
pub(crate) const MAX_HSTS_LINE: usize = 4095;

/// The longest hostname accepted anywhere in this module -- `MAX_HSTS_HOSTLEN`
/// (`lib/hsts.c:42`).
///
/// Three separate roles in the C, all reproduced: the `max` of the word
/// extractor in `hsts_add` (`:398`), the size less one of the pull buffer
/// (`:453-456`), and the upper bound of a lookup (`:235`).
pub(crate) const MAX_HSTS_HOSTLEN: usize = 2048;

/// The longest quoted date accepted by the reader -- `MAX_HSTS_DATELEN`
/// (`lib/hsts.c:43`).
///
/// Far larger than the seventeen bytes a stamp actually occupies, which is
/// what makes the reader tolerant of a hand-edited file.
pub(crate) const MAX_HSTS_DATELEN: usize = 256;

/// The stamp written for an entry that never expires -- `UNLIMITED`
/// (`lib/hsts.c:44`).
#[rustfmt::skip]
pub(crate) const UNLIMITED: &[u8] = b"unlimited";

/// The two comment lines the writer emits, and nothing else --
/// `lib/hsts.c:351-353`.
///
/// One `fputs` of exactly these bytes. **There is no trailing blank line**,
/// which is the single difference from the Netscape jar header in [`super`]
/// and the reason the two are not shared.
#[rustfmt::skip]
pub(crate) const FILE_HEADER: &[u8] =
    b"# Your HSTS cache. https://curl.se/docs/hsts.html\n\
      # This file was generated by libcurl! Edit at your own risk.\n";

/// `CURLHSTS_ENABLE` -- `include/curl/curl.h:1071`.
#[allow(dead_code)] // Read by the option surface, which is later code.
pub(crate) const CURLHSTS_ENABLE: u32 = 1 << 0;

/// `CURLHSTS_READONLYFILE` -- `include/curl/curl.h:1072`.
///
/// Bit one of `CURLOPT_HSTS_CTRL`. Set, and [`HstsCache::save`] skips the file
/// entirely -- but **still runs the write callback**, because the C's
/// `goto skipsave` at `lib/hsts.c:347` jumps past the file write and lands
/// before the callback loop.
pub(crate) const CURLHSTS_READONLYFILE: u32 = 1 << 1;

/// The largest representable instant -- C's `TIME_T_MAX`.
///
/// The C distinguishes the two spellings -- `expires` is declared `curl_off_t`
/// in `struct stsentry` (`lib/hsts.h:37`) and cast to `time_t` at each
/// formatting site (`:288`, `:311`) -- and the distinction has no width
/// consequence here, which is why one [`i64`] carries both.
pub(crate) const TIME_T_MAX: i64 = i64::MAX;

// Free helpers.

/// The bytes a C caller would see through a `const char *` -- everything up to
/// the first zero.
fn c_string(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        Some(nul) => &bytes[..nul],
        None => bytes,
    }
}

/// True when `hostname` is a numeric address literal rather than a name.
fn host_is_ipnum(hostname: &[u8]) -> bool {
    inet::pton4(hostname).is_some() || inet::pton6(hostname).is_some()
}

/// Parses a date the way the HSTS reader needs it, on raw bytes.
fn getdate_capped(date: &[u8]) -> Option<i64> {
    match parsedate::parsedate(date) {
        Outcome::Ok(instant) | Outcome::Later(instant) => Some(instant),
        Outcome::Fail => None,
    }
}

/// Renders an expiry as the **unquoted** stamp both output paths share.
///
/// Three details of the format string are load-bearing and are the reason it
/// is transcribed rather than paraphrased:
///
/// * **The year is `%d`, not `%04d`.** A year before 1000 emits fewer than
///   four digits and one past 9999 emits more. `{}` on an [`i32`] does the
///   same.
/// * **`tm_mon` is 0-based and `tm_year` counts from 1900**, which is why the C
///   writes `tm_year + 1900` and `tm_mon + 1`.
///   [`crate::util::timeval::BrokenTime`] departs from the C on exactly one of
///   those: its `year` is ABSOLUTE, so only the `+ 1` on the month survives
///   here. Adding 1900 as well would emit a year in the fourth millennium.
/// * The separator is one space and the time is colon-delimited with
///   two-digit, zero-padded fields.
///
/// # Errors
///
/// Whatever [`crate::util::timeval::gmtime`] returns --
/// `CURLcode::BadFunctionArgument` for an instant whose year does not fit,
/// which is the same code `curlx_gmtime` reports and which `hsts_push` and
/// `hsts_out` both propagate unchanged (`:289-290`, `:312-313`).
#[rustfmt::skip]
pub(crate) fn format_expiry(expires: i64) -> CodeResult<Vec<u8>> {
    // `if(sts->expires != TIME_T_MAX)` -- the sentinel takes the word, and
    // the word alone: no quotes here, at either call site.
    if expires == TIME_T_MAX {
        return Ok(UNLIMITED.to_vec());
    }

    // `curlx_gmtime((time_t)sts->expires, &stamp)`. The cast the C performs is
    // a no-op on every mandated target, where `curl_off_t` and `time_t` are
    // both signed 64-bit; see [`TIME_T_MAX`].
    let stamp = timeval::gmtime(expires)?;

    Ok(format!(
        "{}{:02}{:02} {:02}:{:02}:{:02}",
        stamp.year, stamp.mon + 1, stamp.mday,
        stamp.hour, stamp.min, stamp.sec
    )
    .into_bytes())
}

/// Writes `bytes`, discarding a write failure exactly as the C does.
///
/// # Why the failure is discarded
///
/// `hsts_out` calls `curl_mfprintf` at `lib/hsts.c:314` and `:320` and reads
/// neither result; `Curl_hsts_save` calls `curlx_fclose` at `:361` and reads
/// that one no more. A full disk therefore produces a truncated cache file and
/// a save that reports success, and that is the observable behaviour of curl
/// 8.19.0-DEV.
///
/// An earlier revision mapped the failure to `CURLE_WRITE_ERROR`, arguing that
/// it made `if(result) break;` at `:358-359` reachable and so honoured the C's
/// intent. AAP 0.8.2 settles it the other way: no behaviour change may be
/// justified by improvement, and a save returning `CURLE_WRITE_ERROR` where
/// curl returns `CURLE_OK` changes an exit status. It also changed what is left
/// on disk, since propagating unlinks the temporary file that the C renames
/// into place.
///
/// # What still propagates
///
/// `Curl_hsts_save`'s error channel is not empty. `curlx_gmtime` failing for an
/// unrepresentable year still yields `CURLE_BAD_FUNCTION_ARGUMENT` from
/// [`format_expiry`] (`:310-312`), and a failed `curlx_rename` still yields
/// `CURLE_WRITE_ERROR` (`:362-363`) -- which is why `if(result) break;` is
/// reproduced rather than deleted.
///
/// `cookies/mod.rs` reaches the same conclusion from the same reading of
/// `lib/cookie.c`.
fn emit<W: Write>(out: &mut W, bytes: &[u8]) {
    // `curl_mfprintf` evaluated as a statement, as the C evaluates it.
    let _ = out.write_all(bytes);
}

/// Writes one entry as one line of the cache file -- `hsts_out`
/// (`lib/hsts.c:307-323`).
///
/// ```text
/// %s%s "%d%02d%02d %02d:%02d:%02d"\n      /* :314 */
/// %s%s "%s"\n                             /* :320, with UNLIMITED */
/// ```
///
/// # Errors
///
/// `CURLcode::BadFunctionArgument` from [`format_expiry`] for an
/// unrepresentable year -- `:310-312`, the one code `hsts_out` itself can
/// return. A write failure is not among them; see [`emit`].
#[rustfmt::skip]
fn write_entry_line<W: Write>(
    entry: &StsEntry,
    out: &mut W,
) -> CodeResult<()> {
    let stamp = format_expiry(entry.expires)?;

    if entry.include_subdomains {
        emit(out, b".");
    }
    emit(out, &entry.host);
    emit(out, b" \"");
    emit(out, &stamp);
    emit(out, b"\"\n");
    Ok(())
}

// The callback surface -- `struct curl_hstsentry`, `struct curl_index` and
// `CURLSTScode`, in Rust-native form. The pinned ABI copies live in
// `curl-rs-ffi`; see the module header.

/// What an HSTS callback reports -- `CURLSTScode`
/// (`include/curl/curl.h:1056-1060`).
///
/// The C's values are `CURLSTS_OK = 0`, `CURLSTS_DONE = 1` and
/// `CURLSTS_FAIL = 2`, recorded here for provenance. **No `#[repr]` and no
/// pinned discriminant**, deliberately: this enumeration never crosses the C
/// boundary, `curl-rs-ffi` owns the copy that does, and attaching the ABI's
/// obligation to a value that does not carry it would put a pinned public
/// enumeration one careless reordering away from breaking a consumer. The same
/// split [`crate::util::strparse::StrError`] draws.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)] // `Done` is produced only by a callback implementor.
pub(crate) enum StsCode {
    /// `CURLSTS_OK` -- an entry was produced or consumed, and the callback is
    /// prepared to be called again.
    Ok,
    /// `CURLSTS_DONE` -- nothing more to do. Ends the loop with success.
    Done,
    /// `CURLSTS_FAIL` -- the callback failed. On the read side this becomes
    /// `CURLE_ABORTED_BY_CALLBACK` (`lib/hsts.c:480`); on the write side,
    /// `CURLE_BAD_FUNCTION_ARGUMENT` (`:301`).
    Fail,
}

/// One entry as the callbacks see it -- the Rust-native mirror of
/// `struct curl_hstsentry` (`include/curl/curl.h:1044-1049`).
///
/// ```c
/// struct curl_hstsentry {
///   char *name;
///   size_t namelen;
///   unsigned int includeSubDomains:1;
///   char expire[18]; /* YYYYMMDD HH:MM:SS [null-terminated] */
/// };
/// ```
///
/// The C struct's layout is public ABI and belongs to `curl-rs-ffi`, which
/// marshals between it and this type. `tests/unit/unit3214.c` caps its size at
/// 40 bytes. Nothing about that layout is asserted here, because nothing here
/// owns it -- what this type owns are the two BOUNDS the C encodes in
/// `namelen` and in the size of `expire`, published as [`Self::NAME_CAPACITY`]
/// and [`Self::EXPIRE_CAPACITY`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct HstsEntryBuf {
    /// `e.name`, already cut at its first zero -- see [`Self::set_name`].
    name: Vec<u8>,
    /// `e.expire`, already cut at its first zero.
    expire: Vec<u8>,
    /// `e.includeSubDomains`, the one-bit field widened to a [`bool`].
    include_subdomains: bool,
}

#[allow(dead_code)] // The marshalling side is `curl-rs-ffi`, later code.
impl HstsEntryBuf {
    /// The largest hostname the read callback may store -- the C's
    /// `e.namelen`, set to `sizeof(buffer) - 1` at `lib/hsts.c:456` over a
    /// `char buffer[MAX_HSTS_HOSTLEN + 1]`.
    pub(crate) const NAME_CAPACITY: usize = MAX_HSTS_HOSTLEN;

    /// The largest stamp the `expire` field can hold, terminator excluded.
    ///
    /// `char expire[18]` carries `"YYYYMMDD HH:MM:SS"`, which is seventeen
    /// bytes, plus its zero. `unlimited` is nine and fits with room to spare.
    pub(crate) const EXPIRE_CAPACITY: usize = 17;

    /// A buffer in the state the C establishes before each read call.
    ///
    /// `lib/hsts.c:455-459`: `e.name = buffer`, `e.namelen = sizeof(buffer) -
    /// 1`, `e.includeSubDomains = FALSE`, `e.expire[0] = 0`, `e.name[0] = 0`.
    /// The two capacities are constants here, so what remains is the three
    /// resets -- which is [`Default`].
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns the buffer to that same state, for the next iteration.
    ///
    /// The C re-establishes it by declaring `buffer` and `e` INSIDE the
    /// `do { }` body (`:453-454`), so every iteration starts clean. Reusing one
    /// allocation and clearing it is the same observable state with one fewer
    /// allocation, and clearing keeps the capacity.
    pub(crate) fn reset(&mut self) {
        self.name.clear();
        self.expire.clear();
        self.include_subdomains = false;
    }

    /// Stores a hostname the way a read callback does, reporting whether it
    /// fit.
    pub(crate) fn set_name(&mut self, name: &[u8]) -> bool {
        let name = c_string(name);
        self.name.clear();
        if name.len() > Self::NAME_CAPACITY {
            return false;
        }
        self.name.extend_from_slice(name);
        true
    }

    /// Stores a stamp the way a read callback does, reporting whether it fit.
    ///
    /// As [`Self::set_name`], against [`Self::EXPIRE_CAPACITY`]. A zero-length
    /// stamp is legal and meaningful: it is how a callback says *for ever*, and
    /// `CURLOPT_HSTSREADFUNCTION(3)` documents it as *"a zero length string for
    /// forever"*.
    pub(crate) fn set_expire(&mut self, expire: &[u8]) -> bool {
        let expire = c_string(expire);
        self.expire.clear();
        if expire.len() > Self::EXPIRE_CAPACITY {
            return false;
        }
        self.expire.extend_from_slice(expire);
        true
    }

    /// Sets `e.includeSubDomains`.
    pub(crate) fn set_include_subdomains(&mut self, subdomains: bool) {
        self.include_subdomains = subdomains;
    }

    /// The buffer the library hands to the WRITE callback -- `hsts_push`
    /// (`lib/hsts.c:278-297`).
    ///
    /// Two differences from [`Self::set_name`] and [`Self::set_expire`], both
    /// measured, because the library fills this one itself:
    ///
    /// * **`name` is not bounded.** `e.name = (char *)sts->host` at `:283` is a
    ///   pointer assignment, not a copy, and `e.namelen = strlen(sts->host)` at
    ///   `:284` reports its exact length. There is no buffer to overflow and so
    ///   no truncation.
    /// * **`expire` IS truncated.** `curl_msnprintf(e.expire,
    ///   sizeof(e.expire), ...)` at `:292` keeps
    ///   [`Self::EXPIRE_CAPACITY`] bytes and drops the rest, where
    ///   `curlx_strcopy` would have stored nothing. Reachable only for a year
    ///   of five digits or more, and reproduced rather than rounded off.
    fn for_push(host: &[u8], subdomains: bool, expire: &[u8]) -> Self {
        let kept = expire.len().min(Self::EXPIRE_CAPACITY);
        Self {
            name: host.to_vec(),
            expire: expire.get(..kept).unwrap_or_default().to_vec(),
            include_subdomains: subdomains,
        }
    }

    /// `e.name`, and `e.namelen` is its length.
    pub(crate) fn name(&self) -> &[u8] {
        &self.name
    }

    /// `e.expire`. Empty means *for ever* on the read side, and cannot be
    /// empty on the write side.
    pub(crate) fn expire(&self) -> &[u8] {
        &self.expire
    }

    /// `e.includeSubDomains`.
    pub(crate) fn include_subdomains(&self) -> bool {
        self.include_subdomains
    }
}

/// Where one entry sits in a save -- `struct curl_index`
/// (`include/curl/curl.h:1051-1054`).
///
/// ```c
/// struct curl_index {
///   size_t index; /* the provided entry's "index" or count */
///   size_t total; /* total number of entries to save */
/// };
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct EntryIndex {
    index: usize,
    total: usize,
}

#[allow(dead_code)] // Read by a callback implementor, which is later code.
impl EntryIndex {
    /// The state of `struct curl_index i` right after `lib/hsts.c:373-374`.
    pub(crate) const fn new(total: usize) -> Self {
        Self { index: 0, total }
    }

    /// `i.index` -- zero-based.
    pub(crate) const fn index(self) -> usize {
        self.index
    }

    /// `i.total` -- the number of entries the save will offer.
    pub(crate) const fn total(self) -> usize {
        self.total
    }
}

/// Supplies HSTS entries to the cache -- `CURLOPT_HSTSREADFUNCTION`.
///
/// ```c
/// CURLSTScode hstsread(CURL *easy, struct curl_hstsentry *sts, void *clientp);
/// ```
pub(crate) trait HstsReader {
    /// Fills `entry` and reports whether another call should be made.
    ///
    /// `entry` arrives in the state [`HstsEntryBuf::reset`] leaves, on every
    /// call.
    fn read_entry(&mut self, entry: &mut HstsEntryBuf) -> StsCode;
}

/// Receives HSTS entries from the cache -- `CURLOPT_HSTSWRITEFUNCTION`.
///
/// ```c
/// CURLSTScode hstswrite(CURL *easy, struct curl_hstsentry *sts,
///                       struct curl_index *count, void *clientp);
/// ```
pub(crate) trait HstsWriter {
    /// Consumes one entry and reports whether the walk should continue.
    fn write_entry(
        &mut self,
        entry: &HstsEntryBuf,
        index: EntryIndex,
    ) -> StsCode;
}

// The store -- `struct stsentry` and `struct hsts` (`lib/hsts.h:35-47`).

/// One host known to require HTTPS -- `struct stsentry` (`lib/hsts.h:35-40`).
///
/// ```c
/// struct stsentry {
///   struct Curl_llist_node node;
///   curl_off_t expires; /* the timestamp of this entry's expiry */
///   BIT(includeSubDomains);
///   char host[1];
/// };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StsEntry {
    /// The hostname, without a leading dot and without a trailing dot.
    host: Vec<u8>,
    /// The instant this entry stops applying. [`TIME_T_MAX`] means never.
    expires: i64,
    /// Whether subdomains of [`Self::host`] are covered too.
    include_subdomains: bool,
}

#[allow(dead_code)] // Consumed by connection setup, which is later code.
impl StsEntry {
    /// The hostname, dot-free at both ends.
    pub(crate) fn host(&self) -> &[u8] {
        &self.host
    }

    /// The expiry instant, in wall-clock seconds since the Unix epoch.
    pub(crate) fn expires(&self) -> i64 {
        self.expires
    }

    /// Whether a match may be a subdomain of [`Self::host`].
    pub(crate) fn include_subdomains(&self) -> bool {
        self.include_subdomains
    }

    /// True when this entry never expires -- `expires == TIME_T_MAX`.
    ///
    /// The condition `lib/hsts.c:287` and `:310` test to choose the
    /// [`UNLIMITED`] spelling over a calendar stamp.
    pub(crate) fn is_unlimited(&self) -> bool {
        self.expires == TIME_T_MAX
    }
}

/// The HSTS cache -- `struct hsts` (`lib/hsts.h:43-47`).
///
/// ```c
/// struct hsts {
///   struct Curl_llist list;
///   char *filename;
///   unsigned int flags;
/// };
/// ```
///
/// **Order is insertion order and it is a contract**, because
/// [`Self::write_to`] emits the entries in that order and the resulting bytes
/// are frozen. Nothing sorts, and a hash map would randomise the output.
#[derive(Debug, Default)]
pub(crate) struct HstsCache {
    /// The entries, in insertion order. See the type's documentation.
    list: VecDeque<StsEntry>,
    /// The private copy of the cache file name, kept so that it survives an
    /// easy handle reset (`lib/hsts.c:499-502`).
    filename: Option<PathBuf>,
    /// The `CURLOPT_HSTS_CTRL` bits: [`CURLHSTS_ENABLE`] and
    /// [`CURLHSTS_READONLYFILE`].
    flags: u32,
}

#[allow(dead_code)] // The option surface and connection setup are later code.
impl HstsCache {
    /// An empty cache -- `Curl_hsts_init` (`lib/hsts.c:66-73`).
    ///
    /// The C's `calloc` plus `Curl_llist_init(&h->list, NULL)`; the `NULL`
    /// destructor argument has no counterpart because a Rust element frees
    /// itself. The C returns `NULL` on an allocation failure and every caller
    /// maps that to `CURLE_OUT_OF_MEMORY`; there is no failure to report here.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Empties the cache -- `Curl_hsts_cleanup` (`lib/hsts.c:77-92`).
    ///
    /// [`Drop`] does the same thing implicitly, so this is only for a caller
    /// that wants the C's explicit call. It routes through
    /// [`llist::dispose_tail_first`] rather than [`VecDeque::clear`] because
    /// `Curl_llist_destroy` removes from the TAIL (`lib/llist.c:196-203`)
    /// whereas dropping a [`VecDeque`] runs front to back. The difference is
    /// **not** observable for HSTS -- an entry owns nothing but a [`Vec`] of
    /// bytes and no destructor can see another entry -- and asking for the
    /// C's order at the one site that mirrors the C's call keeps the divergence
    /// out of the type's drop glue, where nothing should depend on it.
    pub(crate) fn cleanup(&mut self) {
        llist::dispose_tail_first(&mut self.list);
        // `curlx_free(h->filename)` at `:88`.
        self.filename = None;
    }

    /// The `CURLOPT_HSTS_CTRL` bits currently set.
    pub(crate) fn flags(&self) -> u32 {
        self.flags
    }

    /// Replaces the `CURLOPT_HSTS_CTRL` bits.
    pub(crate) fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    /// The remembered cache file name, if a load has established one.
    ///
    /// `h->filename`, which [`Self::save`] falls back to when it is given no
    /// name of its own (`lib/hsts.c:342-343`).
    pub(crate) fn filename(&self) -> Option<&Path> {
        self.filename.as_deref()
    }

    /// Sets the remembered cache file name.
    ///
    /// The C establishes it only from a load (`lib/hsts.c:502`); this exists so
    /// that the option layer can set the name that `--hsts` supplied without
    /// having to read a file first.
    pub(crate) fn set_filename(&mut self, file: Option<&Path>) {
        self.filename = file.map(Path::to_path_buf);
    }

    /// The number of entries -- `Curl_llist_count(&h->list)`
    /// (`lib/hsts.c:373`).
    pub(crate) fn len(&self) -> usize {
        self.list.len()
    }

    /// True when no host is known.
    pub(crate) fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// The entries in save order, which is insertion order.
    ///
    /// Exposed so that a consumer -- and a test -- can observe the order
    /// without going through a file. See the type's documentation for why the
    /// order is a contract.
    pub(crate) fn entries(&self) -> impl Iterator<Item = &StsEntry> + '_ {
        self.list.iter()
    }

    // -- Creation ---------------------------------------------------------

    /// Appends an entry -- `hsts_create` (`lib/hsts.c:94-117`).
    ///
    /// Two behaviours of the C are easy to lose and are both kept:
    ///
    /// * **One trailing dot is stripped** (`:103-105`), so `example.com.` and
    ///   `example.com` produce the same entry. `tests/data/test441` feeds a
    ///   cache line with exactly that shape.
    /// * **An empty host creates nothing and reports SUCCESS** (`:106`,
    ///   `:116`). The C's `if(hlen)` has no `else`, so the function falls
    ///   straight to `return CURLE_OK`. It is not an error.
    ///
    /// # Errors
    ///
    /// None reachable. The signature keeps the C's `CURLcode` because the C's
    /// does -- `hsts_create` returns `CURLE_OUT_OF_MEMORY` when its `calloc`
    /// fails (`:108-109`) and both `hsts_add` and `hsts_pull` propagate that
    /// (`:435-436`, `:476-477`) -- and because dropping it here would silently
    /// remove those two propagation paths. An allocation refused in Rust
    /// aborts rather than returning, which is the standard library's policy and
    /// not this module's to change.
    fn create(
        &mut self,
        hostname: &[u8],
        subdomains: bool,
        expires: i64,
    ) -> CodeResult<()> {
        // `:103-105` -- `if(hlen && (hostname[hlen - 1] == '.')) --hlen;`
        let host = match hostname.split_last() {
            Some((&b'.', head)) => head,
            _ => hostname,
        };

        // `:106` -- `if(hlen)`, whose missing `else` is the success below.
        if host.is_empty() {
            return Ok(());
        }

        // `:107-114`. `Curl_llist_append` puts it at the TAIL, which is what
        // makes the save order insertion order.
        self.list.push_back(StsEntry {
            host: host.to_vec(),
            expires,
            include_subdomains: subdomains,
        });
        Ok(())
    }

    // -- Header parsing ---------------------------------------------------

    /// Applies a `Strict-Transport-Security` response header --
    /// `Curl_hsts_parse` (`lib/hsts.c:119-217`).
    ///
    /// # The branches, in the C's order
    ///
    /// 1. **An IP literal creates nothing** and reports success (`:131-134`).
    ///    RFC 6797: *"explicit IP address identification of all forms is
    ///    excluded."*
    /// 2. The directive loop is a `do`-`while`, so its body runs once even for
    ///    an empty header -- which is how an empty header reaches the
    ///    mandatory-`max-age` check rather than silently succeeding.
    /// 3. `max-age` needs `=`; the opening quote is **optional** and, once
    ///    opened, the closing quote is **mandatory** (`:151-165`).
    /// 4. A repeated `max-age` or a repeated `includeSubDomains` is an error
    ///    (`:142`, `:169`).
    /// 5. An unknown directive is skipped to the next `;` -- the C's own
    ///    comment calls it a *"lame attempt to skip"* (`:176`).
    /// 6. `max-age` is **mandatory**; its absence is an error (`:186-188`).
    /// 7. **`max-age=0` DELETES** the exact-match entry and creates nothing
    ///    (`:190-198`).
    /// 8. An existing exact entry is updated in place, **both** fields
    ///    (`:208-212`); otherwise one is created.
    ///
    /// # The overflow asymmetry
    ///
    /// `curlx_str_number` returns `STRE_OVERFLOW` **without advancing the
    /// cursor** (`lib/curlx/strparse.c:172`, `:181`, which return before
    /// `*linep = p`). So for an unquoted `max-age`, an overflowing value is
    /// clamped to [`TIME_T_MAX`] and accepted; for a QUOTED one, the mandatory
    /// closing quote at `:162` then looks at the first digit instead of the
    /// quote and the header is rejected. That asymmetry is measured, not
    /// intended, and it is reproduced.
    ///
    /// # Errors
    ///
    /// `CURLcode::BadFunctionArgument` for every malformed header: a missing
    /// or unparsable `max-age`, a duplicate directive, a missing `=`, or an
    /// opened quote left unclosed.
    pub(crate) fn parse(
        &mut self,
        hostname: &[u8],
        header: &[u8],
        clock: &dyn Clock,
    ) -> CodeResult<()> {
        /// The `max-age` directive, and the C's `p += 7` at `:145`.
        #[rustfmt::skip]
        const MAX_AGE: &str = "max-age";
        /// The `includeSubDomains` directive, matched case-insensitively, and
        /// the C's `p += 17` at `:172`.
        #[rustfmt::skip]
        const INCLUDE_SUBDOMAINS: &str = "includesubdomains";

        // `:122-129`. `strlen(hostname)` at `:129` is why both arguments go
        // through `c_string`.
        let hostname = c_string(hostname);
        let mut cursor = c_string(header);
        let mut expires: i64 = 0;
        let mut gotma = false;
        let mut gotinc = false;
        let mut subdomains = false;
        // `time(NULL)` at `:128` -- the WALL clock.
        let now = clock.epoch_secs();

        // `:131-134`
        if host_is_ipnum(hostname) {
            return Ok(());
        }

        // `:136-184` -- `do { ... } while(*p);`
        loop {
            // `:137`
            strparse::str_passblanks(&mut cursor);

            if strcase::checkprefix(MAX_AGE, cursor) {
                // `:142-143`
                if gotma {
                    return Err(CURLcode::BadFunctionArgument);
                }

                // `:145-146` -- `p += 7`, in range because the prefix test
                // above proves seven bytes matched.
                cursor = cursor.get(MAX_AGE.len()..).unwrap_or_default();
                strparse::str_passblanks(&mut cursor);

                // `:147-148` -- the `=` is required.
                if strparse::str_single(&mut cursor, b'=').is_err() {
                    return Err(CURLcode::BadFunctionArgument);
                }
                strparse::str_passblanks(&mut cursor);

                // `:151-152` -- the opening quote is OPTIONAL, and consumed
                // when it is there.
                let quoted = strparse::str_single(&mut cursor, b'"').is_ok();

                // `:154-159`
                match strparse::str_number(&mut cursor, TIME_T_MAX) {
                    Ok(value) => expires = value,
                    // `:155-156` -- `expires = CURL_OFF_T_MAX`, which is the
                    // same number as `TIME_T_MAX` here. THE CURSOR HAS NOT
                    // MOVED; see this function's documentation.
                    Err(StrError::Overflow) => expires = TIME_T_MAX,
                    // `:157-159` -- every other parse failure is fatal.
                    Err(_) => return Err(CURLcode::BadFunctionArgument),
                }

                // `:161-165` -- once opened, the closing quote is MANDATORY.
                // `&&` short-circuits, so the quote is consumed only on the
                // path the C consumes it on.
                if quoted && strparse::str_single(&mut cursor, b'"').is_err() {
                    return Err(CURLcode::BadFunctionArgument);
                }

                // `:166`
                gotma = true;
            } else if strcase::checkprefix(INCLUDE_SUBDOMAINS, cursor) {
                // `:169-170`
                if gotinc {
                    return Err(CURLcode::BadFunctionArgument);
                }
                // `:171-173`
                subdomains = true;
                cursor =
                    cursor.get(INCLUDE_SUBDOMAINS.len()..).unwrap_or_default();
                gotinc = true;
            } else {
                // `:175-179` -- `while(*p && (*p != ';')) p++;`
                let stop = cursor
                    .iter()
                    .position(|&byte| byte == b';')
                    .unwrap_or(cursor.len());
                cursor = cursor.get(stop..).unwrap_or_default();
            }

            // `:181-183` -- blanks, then at most one `;`. The C does not look
            // at whether the semicolon was there, so neither does this.
            strparse::str_passblanks(&mut cursor);
            let _ = strparse::str_single(&mut cursor, b';');

            // `:184` -- `} while(*p);`
            if cursor.is_empty() {
                break;
            }
        }

        // `:186-188` -- max-age is mandatory.
        if !gotma {
            return Err(CURLcode::BadFunctionArgument);
        }

        // `:190-198` -- "remove the entry if present verbatim (without
        // subdomain match)". This path creates and updates nothing.
        if expires == 0 {
            if let Some(index) = self.lookup_index(hostname, false, now) {
                llist::dispose(&mut self.list, index);
            }
            return Ok(());
        }

        // `:200-204`. The C guards with `if(CURL_OFF_T_MAX - now < expires)`,
        // which is itself an overflow for a negative `now`; `saturating_add`
        // agrees with it for every non-negative `now` -- that is, for every
        // value `time(NULL)` can produce without the C's own guard
        // overflowing -- and stays total for the rest.
        let expires = expires.saturating_add(now);

        // `:206-214`
        if let Some(index) = self.lookup_index(hostname, false, now) {
            // `:208-212` -- "just update these fields", BOTH of them. This is
            // the difference from the reader's merge rule in
            // [`Self::add_line`], which keeps the larger expiry and leaves
            // `includeSubDomains` alone.
            if let Some(entry) = self.list.get_mut(index) {
                entry.expires = expires;
                entry.include_subdomains = subdomains;
            }
            Ok(())
        } else {
            // `:213-214`
            self.create(hostname, subdomains, expires)
        }
    }

    // -- Lookup -----------------------------------------------------------

    /// Is this host currently an HSTS host? -- `Curl_hsts`
    /// (`lib/hsts.c:225-268`).
    ///
    /// # Matching
    ///
    /// * `hlen > MAX_HSTS_HOSTLEN` or a zero length answers `None` before
    ///   anything is walked (`:235-236`), so a pathological name cannot prune.
    /// * One trailing dot is ignored (`:237-239`).
    /// * A subdomain match needs **all** of: the caller asked for one, the
    ///   entry carries `includeSubDomains`, the entry's name is strictly
    ///   shorter, the byte immediately before the tail is `'.'`, and the tail
    ///   compares equal case-insensitively (`:252-261`). Among candidates the
    ///   **longest** tail wins.
    /// * **An exact match returns immediately** (`:262-264`), so it beats every
    ///   subdomain match, including one already found.
    /// * The hostname is a slice with no separate length and is never assumed
    ///   to be terminated -- the C comment at `:262` is explicit about this.
    pub(crate) fn lookup(
        &mut self,
        hostname: &[u8],
        subdomain: bool,
        clock: &dyn Clock,
    ) -> Option<&StsEntry> {
        // `time(NULL)` at `:230`.
        let now = clock.epoch_secs();
        let index = self.lookup_index(hostname, subdomain, now)?;
        self.list.get(index)
    }

    /// [`Self::lookup`] with the clock already read, answering a position.
    fn lookup_index(
        &mut self,
        hostname: &[u8],
        subdomain: bool,
        now: i64,
    ) -> Option<usize> {
        // `:235-236`. Note this precedes the walk, so an out-of-range name
        // prunes nothing.
        let mut hlen = hostname.len();
        if hlen > MAX_HSTS_HOSTLEN || hlen == 0 {
            return None;
        }

        // `:237-239` -- `if(hostname[hlen - 1] == '.') --hlen;`. The index is
        // in range because `hlen` is non-zero, and the decrement cannot
        // underflow for the same reason.
        if hostname.get(hlen - 1) == Some(&b'.') {
            hlen -= 1;
        }
        let host = hostname.get(..hlen).unwrap_or_default();

        let mut bestsub: Option<usize> = None;
        let mut blen = 0_usize;
        let mut index = 0_usize;

        // `:241-265` -- `for(e = head; e; e = n)`, where `n` is taken before
        // the body so that a removal cannot invalidate the walk.
        while index < self.list.len() {
            let Some((expires, ntail, subs)) = self
                .list
                .get(index)
                .map(|e| (e.expires, e.host.len(), e.include_subdomains))
            else {
                break;
            };

            // `:245-250` -- THE PRUNE, and the reason this method is `&mut`.
            if expires <= now {
                llist::dispose(&mut self.list, index);
                // No increment: the successor has slid into this position,
                // which is what the C's pre-taken `n` amounts to.
                continue;
            }

            // `:252-261`. `ntail < hlen` makes both subtractions below sound:
            // `offs` is at least one, so `offs - 1` cannot underflow either.
            if subdomain && subs && ntail < hlen {
                let offs = hlen - ntail;
                let tail_matches = self.list.get(index).is_some_and(|entry| {
                    // `hostname[offs - 1] == '.'`
                    host.get(offs - 1) == Some(&b'.')
                        // `curl_strnequal(&hostname[offs], sts->host, ntail)`,
                        // argument order preserved: the TAIL governs the loop.
                        && strcase::ncasecompare(
                            host.get(offs..).unwrap_or_default(),
                            &entry.host,
                            ntail,
                        )
                });
                // `(ntail > blen)` -- keep the longest tail.
                if tail_matches && ntail > blen {
                    bestsub = Some(index);
                    blen = ntail;
                }
            }

            // `:262-264` -- an exact match wins outright, and returns before
            // the rest of the list is examined or pruned.
            if hlen == ntail {
                let exact = self.list.get(index).is_some_and(|entry| {
                    strcase::ncasecompare(host, &entry.host, hlen)
                });
                if exact {
                    return Some(index);
                }
            }

            index += 1;
        }

        // `:267`
        bestsub
    }
}

// Reading -- `hsts_add`, `hsts_load`, `Curl_hsts_loadfile`,
// `Curl_hsts_loadcb`, `Curl_hsts_loadfiles` and `hsts_pull`.

#[allow(dead_code)] // The option surface and easy-handle teardown come later.
impl HstsCache {
    /// Absorbs one line of a cache file -- `hsts_add` (`lib/hsts.c:389-440`).
    ///
    /// ```text
    /// example.com "20191231 10:00:00"
    /// .example.net "20191231 10:00:00"
    /// ```
    ///
    /// # A malformed line is DROPPED, not rejected
    ///
    /// 1. `curlx_str_word` up to [`MAX_HSTS_HOSTLEN`] -- a word ends at a
    ///    space, a zero or the end.
    /// 2. `curlx_str_singlespace` -- **exactly one** space. Two spaces fail,
    ///    and so does a tab.
    /// 3. `curlx_str_quotedword` up to [`MAX_HSTS_DATELEN`] -- quotes are
    ///    required at both ends, and nothing is unescaped.
    /// 4. `curlx_str_newline` -- the line must end here, so trailing content
    ///    drops the line.
    ///
    /// # The merge rule
    ///
    /// `:425-434`. The host is looked up with the subdomain flag the line
    /// itself carries. Absent, an entry is created. Present **and named the
    /// same** -- `curlx_str_casecompare`, which the Rust port spells as a plain
    /// `bool` -- the **larger** expiry wins and `includeSubDomains` is
    /// deliberately **not** touched. Present but named differently, which is
    /// what a subdomain hit means, and nothing at all happens.
    ///
    /// # Errors
    ///
    /// Only what [`Self::create`] returns, which is nothing reachable. A
    /// syntactically invalid line is `Ok(())`.
    fn add_line(&mut self, line: &[u8], now: i64) -> CodeResult<()> {
        let mut cursor = line;

        // Step 1 -- `:398`
        let Ok(host) = strparse::str_word(&mut cursor, MAX_HSTS_HOSTLEN) else {
            return Ok(());
        };
        // Step 2 -- `:399`
        if strparse::str_singlespace(&mut cursor).is_err() {
            return Ok(());
        }
        // Step 3 -- `:400`
        let Ok(date) = strparse::str_quotedword(&mut cursor, MAX_HSTS_DATELEN)
        else {
            return Ok(());
        };
        // Step 4 -- `:401`
        if strparse::str_newline(&mut cursor).is_err() {
            return Ok(());
        }

        // `:408` and `:416-419`.
        let expires = if date == UNLIMITED {
            // `:416-417` -- `strcmp`, so exact and case-sensitive.
            TIME_T_MAX
        } else {
            // `:419` -- WART: the result is discarded, so an unparsable date
            // leaves the zero of `:408` in place.
            getdate_capped(date).unwrap_or(0)
        };

        // `:421-424` -- the leading dot IS the `includeSubDomains` flag, and
        // it is removed from the name. `str_nudge` cannot fail here: the byte
        // it drops is the one just tested for.
        let (host, subdomain) = if host.first() == Some(&b'.') {
            (strparse::str_nudge(host, 1).unwrap_or_default(), true)
        } else {
            (host, false)
        };

        // `:425-434`
        match self.lookup_index(host, subdomain, now) {
            // `:427-429`
            None => self.create(host, subdomain, expires),
            Some(index) => {
                // `:430` -- only when the names actually match. A subdomain
                // hit reaches here with a DIFFERENT name and is left alone.
                let same_name = self.list.get(index).is_some_and(|entry| {
                    strparse::str_casecompare(host, &entry.host)
                });
                if same_name {
                    // `:431-433` -- "use the largest expire time".
                    // `includeSubDomains` is not updated on this path.
                    if let Some(entry) = self.list.get_mut(index) {
                        if expires > entry.expires {
                            entry.expires = expires;
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Reads a whole cache file from an already-open reader -- the loop of
    /// `hsts_load` (`lib/hsts.c:508-528`).
    ///
    /// # Errors
    ///
    /// Only what [`get_line`] returns: `CURLcode::TooLarge` for a line longer
    /// than [`MAX_HSTS_LINE`], `CURLcode::OutOfMemory`, or
    /// `CURLcode::ReadError`. A malformed line is not an error -- `:524`
    /// discards `hsts_add`'s result.
    pub(crate) fn read_from<R: BufRead>(
        &mut self,
        input: &mut R,
        clock: &dyn Clock,
    ) -> CodeResult<()> {
        // `:508-510` -- one buffer for the whole file, with the line ceiling
        // the C sets. `curlx_dyn_free(&buf)` at `:527` is this value's own
        // destructor here.
        let mut buf = DynBuf::new(MAX_HSTS_LINE);

        // `:511-526` -- `do { ... } while(!result && !eof);`
        loop {
            // The `while(!result ...)` half of `:526`: a read failure stops
            // the walk and is reported unchanged.
            let last = get_line(&mut buf, input)?;

            // `:514-515`
            let mut lineptr = c_string(buf.as_slice());
            strparse::str_passblanks(&mut lineptr);

            // `:521-522` -- `if((*lineptr == '#') || strlen(lineptr) <= 1)
            // continue;`, negated. An empty remainder takes the same branch a
            // comment does.
            if lineptr.first() != Some(&b'#') && lineptr.len() > 1 {
                // `:524` -- WART: the result is discarded on purpose.
                let _ = self.add_line(lineptr, clock.epoch_secs());
            }

            // The `!eof` half.
            if last {
                return Ok(());
            }
        }
    }

    /// Loads a cache file by name -- `hsts_load` plus `Curl_hsts_loadfile`
    /// (`lib/hsts.c:494-542`).
    ///
    /// # Errors
    ///
    /// As [`Self::read_from`], once the file is open.
    pub(crate) fn loadfile(
        &mut self,
        file: &Path,
        clock: &dyn Clock,
    ) -> CodeResult<()> {
        // `:501-504`
        self.filename = Some(file.to_path_buf());

        // `:506-507` -- WART: no file, no error, no work.
        let Ok(handle) = File::open(file) else {
            return Ok(());
        };

        let mut input = BufReader::new(handle);
        self.read_from(&mut input, clock)
    }

    /// Loads every cache file of a `CURLOPT_HSTS` list --
    /// `Curl_hsts_loadfiles` (`lib/hsts.c:554-570`).
    ///
    /// The `Curl_share_lock(data, CURL_LOCK_DATA_HSTS,
    /// CURL_LOCK_ACCESS_SINGLE)` that brackets the whole walk at `:559` and
    /// `:567` has no counterpart here; see the module header for the contract
    /// `share/` implements. The C also skips the lock entirely for an empty
    /// list (`:558`), which an empty iterator reproduces.
    ///
    /// # Errors
    ///
    /// The first error any [`Self::loadfile`] reports, with the remaining
    /// elements unread.
    pub(crate) fn loadfiles(
        &mut self,
        files: &SList,
        clock: &dyn Clock,
    ) -> CodeResult<()> {
        for name in files.iter() {
            self.loadfile(Path::new(OsStr::from_bytes(name)), clock)?;
        }
        Ok(())
    }

    /// Populates the cache from a read callback -- `hsts_pull` plus
    /// `Curl_hsts_loadcb` (`lib/hsts.c:446-552`).
    ///
    /// # The three answers
    ///
    /// * [`StsCode::Ok`] -- an entry was produced. An **empty name** is
    ///   `CURLE_BAD_FUNCTION_ARGUMENT` (`:464-467`); the C also
    ///   `DEBUGASSERT`s it, so a debug build stops there.
    /// * [`StsCode::Fail`] -- `CURLE_ABORTED_BY_CALLBACK` (`:479-480`), which
    ///   `tests/data/test1915` observes as `Second request returned 42`.
    /// * [`StsCode::Done`] -- success, and the walk ends (`:481`, `:483`).
    ///
    /// # Errors
    ///
    /// `CURLcode::BadFunctionArgument` for an empty name,
    /// `CURLcode::AbortedByCallback` for [`StsCode::Fail`], and whatever
    /// [`Self::create`] returns.
    pub(crate) fn load_from_callback(
        &mut self,
        reader: &mut dyn HstsReader,
    ) -> CodeResult<()> {
        // `:453-454` -- re-established on every iteration by `reset` below.
        let mut buf = HstsEntryBuf::new();

        // `:452-481` -- `do { ... } while(sc == CURLSTS_OK);`
        loop {
            // `:455-459`
            buf.reset();

            // `:460`
            match reader.read_entry(&mut buf) {
                StsCode::Ok => {
                    // `:464-467`
                    if buf.name.is_empty() {
                        return Err(CURLcode::BadFunctionArgument);
                    }

                    // `:462`, `:468-471`
                    let expires = if buf.expire.is_empty() {
                        TIME_T_MAX
                    } else {
                        getdate_capped(&buf.expire).unwrap_or(0)
                    };

                    // `:472-477`
                    self.create(&buf.name, buf.include_subdomains, expires)?;
                }
                // `:479-480`
                StsCode::Fail => return Err(CURLcode::AbortedByCallback),
                // `:481` -- the `while` condition is false, and `:483`.
                StsCode::Done => return Ok(()),
            }
        }
    }
}

// Writing -- `hsts_out`, `hsts_push` and `Curl_hsts_save`.

#[allow(dead_code)] // The option surface and easy-handle teardown come later.
impl HstsCache {
    /// Serialises the whole cache -- the file half of `Curl_hsts_save`
    /// (`lib/hsts.c:351-360`).
    ///
    /// # Errors
    ///
    /// `CURLcode::BadFunctionArgument` from [`format_expiry`] for an
    /// unrepresentable year -- the one code the C's own walk can break on
    /// (`:357-359`). A write failure is not among them; see [`emit`].
    pub(crate) fn write_to<W: Write>(&self, out: &mut W) -> CodeResult<()> {
        // `:351-353`
        emit(out, FILE_HEADER);

        // `:354-360`
        for entry in &self.list {
            write_entry_line(entry, out)?;
        }
        Ok(())
    }

    /// Writes the cache to a file and to a write callback -- `Curl_hsts_save`
    /// (`lib/hsts.c:328-386`).
    ///
    /// # Errors
    ///
    /// `CURLcode::WriteError` when the target cannot be opened, when a write
    /// fails, or when the rename of the temporary file over the target fails --
    /// in which case the temporary file is removed (`:362-366`).
    /// `CURLcode::BadFunctionArgument` for an unrepresentable year or for a
    /// callback answering [`StsCode::Fail`].
    pub(crate) fn save<F>(
        &self,
        file: Option<&Path>,
        rand_suffix: F,
        writer: Option<&mut dyn HstsWriter>,
    ) -> CodeResult<()>
    where
        F: FnOnce() -> CodeResult<String>,
    {
        // `:342-343` -- "if no new name is given, use the one we stored from
        // the load".
        let target = file.or(self.filename.as_deref());

        // `:345-347`. `!file[0]` is the empty-name case, which `--hsts ""`
        // produces and which means "in-memory only".
        let skip = (self.flags & CURLHSTS_READONLYFILE) != 0
            || target.map_or(true, |path| path.as_os_str().is_empty());

        // `:349-368`. NOT propagated with `?`: the C keeps going to
        // `skipsave:` whatever happened here.
        let mut result = Ok(());
        if !skip {
            if let Some(path) = target {
                result = self.save_to_path(path, rand_suffix);
            }
        }

        // `:369-384` -- the `skipsave:` label.
        if let Some(writer) = writer {
            if let Some(outcome) = self.push_all(writer) {
                // `:379` -- assignment, not composition. See above.
                result = outcome;
            }
        }

        // `:385`
        result
    }

    /// The file half of [`Self::save`] -- `lib/hsts.c:349-368`.
    ///
    /// Split out so that the `goto skipsave` control flow of the C reads as an
    /// ordinary early return here rather than as a labelled jump.
    fn save_to_path<F>(&self, path: &Path, rand_suffix: F) -> CodeResult<()>
    where
        F: FnOnce() -> CodeResult<String>,
    {
        // `:349` -- `Curl_fopen(data, file, &out, &tempstore)`.
        //
        // `StoreClass::Public`: an HSTS entry is a hostname that asked to be
        // reached over HTTPS, which is not a secret, so the C's mode handling
        // is kept exactly -- the temporary file clones whatever mode the target
        // already had. Only the cookie jar is classified `Credential`.
        //
        // `NoFollow` carries the platform's `O_NOFOLLOW` from `crate::ffi`,
        // injected because `crate::util` may not name that module; see the
        // hardening section of `crate::util::fopen`.
        let mut opened = fopen::open_for_write(
            path,
            fopen::StoreClass::Public,
            fopen::NoFollow::new(O_NOFOLLOW | O_CLOEXEC),
            rand_suffix,
        )?;

        // `:351-360`
        let written = self.write_to(opened.file_mut());

        match written {
            // `:361-363` -- close, then rename when there is a temporary.
            // `OpenedFile::commit` is that sequence, including the
            // `CURLE_WRITE_ERROR` a failed rename produces and the unlink that
            // follows it. `OpenedFile::Direct` closes and does NOT rename,
            // which is what keeps `--hsts /dev/null` working.
            Ok(()) => opened.commit(path),
            // `:365-366` -- `if(result && tempstore) unlink(tempstore);`, with
            // the close of `:361` folded in.
            Err(code) => {
                opened.discard();
                Err(code)
            }
        }
    }

    /// Offers every entry to a write callback -- the `skipsave:` loop
    /// (`lib/hsts.c:370-384`).
    fn push_all(&self, writer: &mut dyn HstsWriter) -> Option<CodeResult<()>> {
        // `:372-374` -- the count is taken once, before the walk.
        let mut cursor = EntryIndex::new(self.list.len());
        let mut outcome = None;

        // `:375-383`
        for entry in &self.list {
            let (result, stop) = push_one(writer, entry, cursor);
            let failed = result.is_err();
            outcome = Some(result);

            // `:380-381`
            if failed || stop {
                break;
            }

            // `:382`
            cursor.index += 1;
        }

        outcome
    }
}

/// Hands one entry to a write callback -- `hsts_push` (`lib/hsts.c:273-302`).
fn push_one(
    writer: &mut dyn HstsWriter,
    entry: &StsEntry,
    cursor: EntryIndex,
) -> (CodeResult<()>, bool) {
    // `:287-297`
    let stamp = match format_expiry(entry.expires) {
        Ok(stamp) => stamp,
        // `:289-290`
        Err(code) => return (Err(code), false),
    };

    // `:283-285` -- `e.name` is the stored host verbatim and `e.namelen` its
    // exact length, because the C assigns a POINTER rather than copying.
    let buf =
        HstsEntryBuf::for_push(&entry.host, entry.include_subdomains, &stamp);

    // `:299`
    let code = writer.write_entry(&buf, cursor);

    // `:300` -- `*stop = (sc != CURLSTS_OK);` So DONE stops the walk too, and
    // does so without being an error.
    let stop = code != StsCode::Ok;

    // `:301` -- only FAIL is an error.
    let result = if code == StsCode::Fail {
        Err(CURLcode::BadFunctionArgument)
    } else {
        Ok(())
    };

    (result, stop)
}

// TESTS
//
// Two of them carry byte-exact ORACLES in `tests/data/`, and those are the two
// most valuable tests in this file:
//
//   * `tests/data/test1660` pins the wall clock with `CURL_TIME=1548369261`,
//     supplies an input cache file, traces 23 parse and lookup steps with their
//     exact expiry integers, and states the exact bytes of the saved file. It is
//     ported verbatim below, including the ten-second expiry walk.
//   * `tests/data/test1915` states the write callback's output, which is what
//     pins the UNQUOTED stamp and the empty-stamp-means-for-ever rule.
#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::Path;

    use super::{
        c_string, format_expiry, getdate_capped, host_is_ipnum, EntryIndex,
        HstsCache, HstsEntryBuf, HstsReader, HstsWriter, StsCode,
        CURLHSTS_ENABLE, CURLHSTS_READONLYFILE, FILE_HEADER, MAX_HSTS_DATELEN,
        MAX_HSTS_HOSTLEN, MAX_HSTS_LINE, TIME_T_MAX, UNLIMITED,
    };
    use crate::error::CURLcode;
    use crate::util::fopen::{RAND_ALPHABET, RAND_SUFFIX_LEN};
    use crate::util::slist::SList;
    use crate::util::timeval::{Clock, CurlTime, TestClock};

    // -- Fixture constants, transcribed from the C tree -------------------

    /// `CURL_TIME` from `tests/data/test1660`, whose own comment reads *"This
    /// date is exactly `20190124 22:34:21` UTC"*.
    const T1660_NOW: i64 = 1_548_369_261;

    /// The input cache file of `tests/data/test1660`.
    const T1660_INPUT: &[u8] = b"\
# Your HSTS cache. https://curl.se/docs/hsts.html\n\
# This file was generated by libcurl! Edit at your own risk.\n\
.readfrom.example \"20211001 04:47:41\"\n\
.old.example \"20161001 04:47:41\"\n\
.new.example \"unlimited\"\n";

    /// The `%LOGDIR/hsts1660.save` file of `tests/data/test1660`, byte for
    /// byte.
    const T1660_SAVED: &[u8] = b"\
# Your HSTS cache. https://curl.se/docs/hsts.html\n\
# This file was generated by libcurl! Edit at your own risk.\n\
.new.example \"unlimited\"\n\
.example.com \"20191001 04:47:41\"\n\
example.org \"20200124 22:34:21\"\n";

    // -- Helpers ----------------------------------------------------------

    /// A clock whose WALL reading is `secs`, which is the only reading this
    /// module uses.
    ///
    /// [`TestClock::new`] places the MONOTONIC reading and leaves the wall
    /// reading at the epoch, so the wall reading has to be set separately --
    /// which is exactly the distinction this module depends on.
    fn clock_at(secs: i64) -> TestClock {
        let clock = TestClock::new(CurlTime::ZERO);
        clock.set_epoch_secs(secs);
        clock
    }

    /// Loads a cache from bytes, the way [`HstsCache::loadfile`] would from a
    /// file, and asserts the load reported success.
    fn cache_from(bytes: &[u8], clock: &dyn Clock) -> HstsCache {
        let mut cache = HstsCache::new();
        let mut input = Cursor::new(bytes.to_vec());
        assert_eq!(cache.read_from(&mut input, clock), Ok(()));
        cache
    }

    /// The bytes [`HstsCache::write_to`] produces.
    fn saved(cache: &HstsCache) -> Vec<u8> {
        let mut out = Vec::new();
        assert_eq!(cache.write_to(&mut out), Ok(()));
        out
    }

    /// Renders bytes for an assertion message without assuming UTF-8.
    fn show(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// A deterministic stand-in for `Curl_rand_alnum`, satisfying the contract
    /// [`crate::util::fopen::open_for_write`] states: exactly
    /// [`RAND_SUFFIX_LEN`] characters, every one from [`RAND_ALPHABET`].
    fn fixed_suffix() -> Result<String, CURLcode> {
        Ok(RAND_ALPHABET
            .iter()
            .cycle()
            .take(RAND_SUFFIX_LEN)
            .map(|byte| char::from(*byte))
            .collect())
    }

    /// A read callback driven by a fixed script -- the shape of
    /// `tests/libtest/lib1915.c:33-70`.
    struct ScriptedReader {
        /// `(name, expire, includeSubDomains)` triples, consumed in order.
        script: Vec<(Vec<u8>, Vec<u8>, bool)>,
        /// The C's `struct state { int index; }`.
        index: usize,
        /// What to answer once the script is exhausted.
        terminal: StsCode,
    }

    impl ScriptedReader {
        fn new(script: &[(&str, &str, bool)], terminal: StsCode) -> Self {
            Self {
                script: script
                    .iter()
                    .map(|(name, expire, subs)| {
                        (
                            name.as_bytes().to_vec(),
                            expire.as_bytes().to_vec(),
                            *subs,
                        )
                    })
                    .collect(),
                index: 0,
                terminal,
            }
        }
    }

    impl HstsReader for ScriptedReader {
        fn read_entry(&mut self, entry: &mut HstsEntryBuf) -> StsCode {
            let Some((name, expire, subs)) = self.script.get(self.index) else {
                return self.terminal;
            };
            self.index += 1;
            assert!(entry.set_name(name), "the fixture names all fit");
            assert!(entry.set_expire(expire), "the fixture stamps all fit");
            entry.set_include_subdomains(*subs);
            StsCode::Ok
        }
    }

    /// A write callback that records `[index/total] name expire`, which is the
    /// exact line `tests/libtest/lib1915.c:88` prints and `tests/data/test1915`
    /// asserts.
    struct RecordingWriter {
        lines: Vec<String>,
        /// Answered after every call; `Ok` lets the walk continue.
        answer: StsCode,
        /// Answer this instead, once this many calls have been made.
        switch_after: usize,
    }

    impl RecordingWriter {
        fn new() -> Self {
            Self {
                lines: Vec::new(),
                answer: StsCode::Ok,
                switch_after: usize::MAX,
            }
        }

        fn stopping_after(calls: usize, answer: StsCode) -> Self {
            Self {
                lines: Vec::new(),
                answer,
                switch_after: calls,
            }
        }
    }

    impl HstsWriter for RecordingWriter {
        fn write_entry(
            &mut self,
            entry: &HstsEntryBuf,
            index: EntryIndex,
        ) -> StsCode {
            self.lines.push(format!(
                "[{}/{}] {} {}",
                index.index(),
                index.total(),
                show(entry.name()),
                show(entry.expire())
            ));
            if self.lines.len() > self.switch_after {
                self.answer
            } else {
                StsCode::Ok
            }
        }
    }

    // -- The file format --------------------------------------------------

    /// The header is two comment lines and stops -- `lib/hsts.c:351-353`.
    #[test]
    fn the_header_is_exactly_two_comment_lines() {
        assert_eq!(
            FILE_HEADER,
            b"# Your HSTS cache. https://curl.se/docs/hsts.html\n\
              # This file was generated by libcurl! Edit at your own risk.\n"
                .as_slice()
        );
        assert_eq!(
            FILE_HEADER.iter().filter(|byte| **byte == b'\n').count(),
            2
        );
    }

    /// The header has NO trailing blank line, unlike the cookie jar's.
    #[test]
    fn an_empty_cache_writes_the_header_and_nothing_else() {
        let cache = HstsCache::new();
        let out = saved(&cache);
        assert_eq!(out, FILE_HEADER);
        assert!(
            !out.ends_with(b"\n\n"),
            "the HSTS header must not end in a blank line: {}",
            show(&out)
        );
    }

    /// The two lines `docs/HSTS.md` documents round-trip verbatim.
    ///
    /// `example.com "20191231 10:00:00"` and `.example.net "20191231
    /// 10:00:00"` are the C's own examples, quoted in the comment at
    /// `lib/hsts.c:391-394`.
    #[test]
    fn the_documented_example_lines_round_trip_verbatim() {
        const BODY: &[u8] = b"\
example.com \"20191231 10:00:00\"\n\
.example.net \"20191231 10:00:00\"\n";

        let mut input = Vec::from(FILE_HEADER);
        input.extend_from_slice(BODY);

        // Well before the 2019 expiry, so nothing is pruned on the way in.
        let clock = clock_at(1_000_000_000);
        let cache = cache_from(&input, &clock);

        assert_eq!(cache.len(), 2);
        assert_eq!(saved(&cache), input);
    }

    /// A calendar stamp is `%d%02d%02d %02d:%02d:%02d` over UTC.
    #[test]
    fn a_stamp_is_the_utc_calendar_rendering() {
        assert_eq!(format_expiry(0), Ok(b"19700101 00:00:00".to_vec()));
        assert_eq!(
            format_expiry(1_548_369_261),
            Ok(b"20190124 22:34:21".to_vec())
        );
        assert_eq!(
            format_expiry(1_569_905_261),
            Ok(b"20191001 04:47:41".to_vec())
        );
        // A leap day, and a two-digit month and day either side of it.
        assert_eq!(
            format_expiry(951_782_400),
            Ok(b"20000229 00:00:00".to_vec())
        );
    }

    /// `TIME_T_MAX` writes the word, not a date.
    #[test]
    fn the_sentinel_writes_the_unlimited_word_unquoted() {
        assert_eq!(format_expiry(TIME_T_MAX), Ok(UNLIMITED.to_vec()));
        assert_eq!(UNLIMITED, b"unlimited");
    }

    /// The year is `%d`, so it is NOT padded to four digits.
    ///
    /// `lib/hsts.c:314` writes `%d` for the year while every other field is
    /// `%02d`. Year 1 emits one digit and year 999 emits three, and a
    /// transcription that assumed `%04d` would silently change the bytes of a
    /// hand-edited cache file.
    #[test]
    fn the_year_is_not_zero_padded() {
        // 0001-01-01T00:00:00Z, computed from the proleptic Gregorian
        // calendar; the value is negative because it precedes the epoch.
        let stamp = format_expiry(-62_135_596_800);
        assert_eq!(stamp, Ok(b"10101 00:00:00".to_vec()));

        // 0999-12-31T00:00:00Z -- three digits, still unpadded.
        let stamp = format_expiry(-30_610_310_400);
        assert_eq!(stamp, Ok(b"9991231 00:00:00".to_vec()));

        // 9999-10-01T00:00:00Z -- the four-digit ceiling `tests/data/test440`
        // exercises with its `99991001 04:47:41` line.
        let stamp = format_expiry(253_394_352_000);
        assert_eq!(stamp, Ok(b"99991001 00:00:00".to_vec()));
    }

    /// A year too large for the field is an error, propagated unchanged.
    ///
    /// `curlx_gmtime`'s failure is `CURLE_BAD_FUNCTION_ARGUMENT`, and both
    /// `hsts_push` (`:289-290`) and `hsts_out` (`:312-313`) return it as-is.
    /// Reachable because `TIME_T_MAX` is the only value that takes the
    /// `unlimited` branch: one second less does not.
    #[test]
    fn an_unrepresentable_year_is_reported_rather_than_written() {
        assert_eq!(
            format_expiry(TIME_T_MAX - 1),
            Err(CURLcode::BadFunctionArgument)
        );

        let mut cache = HstsCache::new();
        let clock = clock_at(0);
        // `max-age` at the ceiling saturates to TIME_T_MAX, so build the
        // entry through the reader instead, where an arbitrary instant can be
        // stated.
        assert_eq!(
            cache.read_from(&mut Cursor::new(Vec::new()), &clock),
            Ok(())
        );
        assert_eq!(
            cache.parse(b"h.example", b"max-age=1", &clock_at(TIME_T_MAX - 2)),
            Ok(())
        );
        let mut out = Vec::new();
        assert_eq!(
            cache.write_to(&mut out),
            Err(CURLcode::BadFunctionArgument)
        );
    }

    /// The leading dot is the `includeSubDomains` flag, and the stored host
    /// never carries it.
    #[test]
    fn the_leading_dot_is_the_subdomain_flag_and_is_not_stored() {
        let clock = clock_at(1_000_000_000);
        let cache = cache_from(
            b"\
.sub.example \"unlimited\"\n\
exact.example \"unlimited\"\n",
            &clock,
        );

        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].host(), b"sub.example");
        assert!(entries[0].include_subdomains());
        assert!(entries[0].is_unlimited());
        assert_eq!(entries[1].host(), b"exact.example");
        assert!(!entries[1].include_subdomains());

        // And it comes back.
        assert!(saved(&cache).ends_with(
            b".sub.example \"unlimited\"\nexact.example \"unlimited\"\n"
        ));
    }

    // -- The reader's tolerance -------------------------------------------

    /// Comments and blank lines are skipped -- `lib/hsts.c:517-522`.
    ///
    /// `docs/HSTS.md`: *"Lines starting with `#` are ignored"*. The `strlen <=
    /// 1` half covers a line that is nothing but its newline, and leading
    /// blanks are skipped before either test, so an indented comment is still
    /// a comment.
    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let clock = clock_at(1_000_000_000);
        let cache = cache_from(
            b"\
# a comment\n\
\n\
   \n\
\t\n\
      # an indented comment\n\
   kept.example \"unlimited\"\n",
            &clock,
        );

        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 1, "only one line carries an entry");
        assert_eq!(entries[0].host(), b"kept.example");
    }

    /// Every way of malforming a line, and each one is DROPPED rather than
    /// failing the load -- `lib/hsts.c:398-402`, whose result `:524` discards.
    #[test]
    fn a_malformed_line_is_dropped_and_never_fails_the_load() {
        let clock = clock_at(1_000_000_000);
        let mut oversized = Vec::new();
        oversized.extend(std::iter::repeat(b'h').take(MAX_HSTS_HOSTLEN + 1));
        oversized.extend_from_slice(b" \"unlimited\"\n");

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("two spaces", b"a.example  \"unlimited\"\n".to_vec()),
            ("no space", b"a.example\"unlimited\"\n".to_vec()),
            ("a tab", b"a.example\t\"unlimited\"\n".to_vec()),
            ("no opening quote", b"a.example unlimited\"\n".to_vec()),
            ("no closing quote", b"a.example \"unlimited\n".to_vec()),
            ("unquoted date", b"a.example unlimited\n".to_vec()),
            ("trailing junk", b"a.example \"unlimited\" junk\n".to_vec()),
            ("host only", b"a.example\n".to_vec()),
            ("an over-long host", oversized),
        ];

        for (label, line) in cases {
            let mut input = Vec::from(FILE_HEADER);
            input.extend_from_slice(&line);
            let mut cache = HstsCache::new();
            let mut reader = Cursor::new(input);
            assert_eq!(
                cache.read_from(&mut reader, &clock),
                Ok(()),
                "{label}: a bad line must not fail the load"
            );
            assert_eq!(cache.len(), 0, "{label}: nothing should be stored");
        }
    }

    /// A host of exactly the maximum length is accepted; one byte more is not.
    ///
    /// `curlx_str_word`'s bound is inclusive -- the C's post-increment test
    /// admits `max` bytes and refuses `max + 1` -- so this pins the boundary
    /// rather than assuming it.
    #[test]
    fn the_host_length_bound_is_inclusive() {
        let clock = clock_at(1_000_000_000);
        for (len, expected) in
            [(MAX_HSTS_HOSTLEN, 1), (MAX_HSTS_HOSTLEN + 1, 0)]
        {
            let mut line: Vec<u8> = std::iter::repeat(b'h').take(len).collect();
            line.extend_from_slice(b" \"unlimited\"\n");
            let cache = cache_from(&line, &clock);
            assert_eq!(cache.len(), expected, "host length {len}");
        }
    }

    /// An unparsable date yields `expires == 0`, so the entry is dead on
    /// arrival -- `lib/hsts.c:419`, whose result is discarded.
    #[test]
    fn an_unparsable_date_is_accepted_as_already_expired() {
        let clock = clock_at(1_000_000_000);
        let mut cache = cache_from(b"a.example \"not a date\"\n", &clock);

        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 1, "the line is ACCEPTED");
        assert_eq!(entries[0].expires(), 0, "with the initial zero intact");

        // And the next lookup prunes it.
        assert!(cache.lookup(b"a.example", true, &clock).is_none());
        assert_eq!(cache.len(), 0);
        assert_eq!(saved(&cache), FILE_HEADER);
    }

    /// The `unlimited` comparison is `strcmp`, so it is CASE-SENSITIVE.
    ///
    /// `lib/hsts.c:416`. Upper case goes to the date parser, fails there, and
    /// lands on the zero of the previous test.
    #[test]
    fn the_unlimited_word_is_matched_case_sensitively() {
        let clock = clock_at(1_000_000_000);

        let lower = cache_from(b"a.example \"unlimited\"\n", &clock);
        let lower: Vec<_> = lower.entries().collect();
        assert_eq!(lower.len(), 1);
        assert_eq!(lower[0].expires(), TIME_T_MAX);

        for spelling in ["UNLIMITED", "Unlimited", "unlimiteD"] {
            let line = format!("a.example \"{spelling}\"\n");
            let cache = cache_from(line.as_bytes(), &clock);
            let entries: Vec<_> = cache.entries().collect();
            assert_eq!(entries.len(), 1, "{spelling}");
            assert_eq!(
                entries[0].expires(),
                0,
                "{spelling} must reach the date parser and fail"
            );
        }
    }

    /// Loading the same host twice keeps the LARGER expiry and does not touch
    /// `includeSubDomains` -- `lib/hsts.c:430-434`.
    #[test]
    fn the_merge_rule_keeps_the_larger_expiry_and_not_the_flag() {
        let clock = clock_at(1_000_000_000);

        // Larger second: the expiry moves.
        let cache = cache_from(
            b"\
a.example \"20300101 00:00:00\"\n\
a.example \"20400101 00:00:00\"\n",
            &clock,
        );
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 1, "one host, one entry");
        assert_eq!(entries[0].expires(), 2_208_988_800);

        // Smaller second: the expiry does NOT move.
        let cache = cache_from(
            b"\
a.example \"20400101 00:00:00\"\n\
a.example \"20300101 00:00:00\"\n",
            &clock,
        );
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].expires(), 2_208_988_800);

        // The flag is left alone even when the second line carries the dot.
        let cache = cache_from(
            b"\
a.example \"20300101 00:00:00\"\n\
.a.example \"20400101 00:00:00\"\n",
            &clock,
        );
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 1, "the dot does not make a second entry");
        assert_eq!(entries[0].expires(), 2_208_988_800, "expiry still merges");
        assert!(
            !entries[0].include_subdomains(),
            "includeSubDomains is NOT updated by the merge rule"
        );
    }

    /// A trailing dot on the stored host is stripped -- `lib/hsts.c:103-105`.
    ///
    /// `tests/data/test441` feeds a cache line with exactly this shape.
    #[test]
    fn a_trailing_dot_on_a_stored_host_is_stripped() {
        let clock = clock_at(1_000_000_000);
        let cache = cache_from(b"this.hsts.example. \"unlimited\"\n", &clock);

        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].host(), b"this.hsts.example");
        assert!(saved(&cache).ends_with(b"this.hsts.example \"unlimited\"\n"));
    }

    /// A line longer than the ceiling ends the load with an error.
    ///
    /// The one genuine failure the reader can report, and the one place where
    /// `hsts_load` does NOT keep going: `while(!result && !eof)` at
    /// `lib/hsts.c:526`.
    #[test]
    fn a_line_past_the_ceiling_ends_the_load() {
        let clock = clock_at(1_000_000_000);
        let mut line: Vec<u8> =
            std::iter::repeat(b'h').take(MAX_HSTS_LINE + 10).collect();
        line.push(b'\n');

        let mut cache = HstsCache::new();
        let mut input = Cursor::new(line);
        assert_eq!(
            cache.read_from(&mut input, &clock),
            Err(CURLcode::TooLarge)
        );
        assert_eq!(cache.len(), 0);
    }

    /// The date bound is [`MAX_HSTS_DATELEN`], and a longer quoted word drops
    /// the line.
    #[test]
    fn the_date_length_bound_is_inclusive() {
        let clock = clock_at(1_000_000_000);
        for (len, expected) in
            [(MAX_HSTS_DATELEN, 1), (MAX_HSTS_DATELEN + 1, 0)]
        {
            // Padding the real stamp with trailing spaces keeps it parsable
            // while pushing the quoted word past the bound.
            let mut date = b"20300101 00:00:00".to_vec();
            while date.len() < len {
                date.push(b' ');
            }
            let mut line = b"a.example \"".to_vec();
            line.extend_from_slice(&date);
            line.extend_from_slice(b"\"\n");

            let cache = cache_from(&line, &clock);
            assert_eq!(cache.len(), expected, "date length {len}");
        }
    }

    // -- `Strict-Transport-Security` parsing ------------------------------

    /// `max-age` is mandatory, and its absence is an error --
    /// `lib/hsts.c:186-188`.
    ///
    /// The empty header is the interesting case: the C's loop is a `do`-`while`,
    /// so its body runs once even with nothing to read, and control still
    /// reaches the mandatory check rather than falling out early.
    #[test]
    fn max_age_is_mandatory() {
        let clock = clock_at(T1660_NOW);
        for header in [
            "",
            " ",
            ";",
            "includeSubDomains",
            "includeSubDomains; ",
            "max=\"31536\";",
            "unknown=1; other=2",
        ] {
            let mut cache = HstsCache::new();
            assert_eq!(
                cache.parse(b"a.example", header.as_bytes(), &clock),
                Err(CURLcode::BadFunctionArgument),
                "header {header:?}"
            );
            assert_eq!(cache.len(), 0, "header {header:?}");
        }
    }

    /// A duplicate `max-age` or `includeSubDomains` is an error --
    /// `lib/hsts.c:142`, `:169`.
    #[test]
    fn a_duplicate_directive_is_rejected() {
        let clock = clock_at(T1660_NOW);
        for header in [
            "max-age=\"21536000\"; includeSubDomains; max-age=\"3\";",
            "max-age=1; max-age=2",
            "max-age=\"21536000\"; includeSubDomains; includeSubDomains;",
            "includeSubDomains; max-age=1; includeSubDomains",
        ] {
            let mut cache = HstsCache::new();
            assert_eq!(
                cache.parse(b"a.example", header.as_bytes(), &clock),
                Err(CURLcode::BadFunctionArgument),
                "header {header:?}"
            );
        }
    }

    /// The `=` is required, and the opening quote is optional while the closing
    /// quote is not -- `lib/hsts.c:147-165`.
    #[test]
    fn the_quoting_rules_of_max_age() {
        let clock = clock_at(T1660_NOW);

        let accepted = [
            // Unquoted.
            ("max-age=7", T1660_NOW + 7),
            // Quoted, closed.
            ("max-age=\"7\"", T1660_NOW + 7),
            // Blanks either side of the `=`, which `str_passblanks` eats.
            ("max-age = 7", T1660_NOW + 7),
            ("max-age =\t\"7\"", T1660_NOW + 7),
            // Leading zeros are accepted by `curlx_str_number`.
            ("max-age=0007", T1660_NOW + 7),
            // `tests/unit/unit1660.c:57` -- unquoted number, then a stray
            // quote that the SECOND loop iteration eats as an unknown
            // directive. This is CURLE_OK in the C.
            ("max-age=31536\"", T1660_NOW + 31_536),
            // Case folding on the directive name.
            ("MAX-AGE=7", T1660_NOW + 7),
        ];
        for (header, expected) in accepted {
            let mut cache = HstsCache::new();
            assert_eq!(
                cache.parse(b"a.example", header.as_bytes(), &clock),
                Ok(()),
                "header {header:?}"
            );
            let entries: Vec<_> = cache.entries().collect();
            assert_eq!(entries.len(), 1, "header {header:?}");
            assert_eq!(entries[0].expires(), expected, "header {header:?}");
        }

        let rejected = [
            "max-age",
            "max-age;",
            "max-age 7",
            // An opened quote MUST be closed.
            "max-age=\"31536",
            "max-age=\"7",
            // Not a number at all.
            "max-age=x",
            "max-age=\"x\"",
            "max-age=-1",
        ];
        for header in rejected {
            let mut cache = HstsCache::new();
            assert_eq!(
                cache.parse(b"a.example", header.as_bytes(), &clock),
                Err(CURLcode::BadFunctionArgument),
                "header {header:?}"
            );
        }
    }

    /// An unknown directive is skipped to the next `;` -- `lib/hsts.c:175-179`,
    /// whose own comment calls it a *"lame attempt to skip"*.
    #[test]
    fn an_unknown_directive_is_skipped() {
        let clock = clock_at(T1660_NOW);
        let cases = [
            ("max-age=\"21536000\"; include; includeSubDomains;", true),
            ("bogus; max-age=7", false),
            ("bogus=value; max-age=7; alsobogus", false),
            ("max-age=7; includeSubDomains; bogus", true),
            ("includesub; max-age=7", false),
        ];

        for (header, subdomains) in cases {
            let mut cache = HstsCache::new();
            assert_eq!(
                cache.parse(b"a.example", header.as_bytes(), &clock),
                Ok(()),
                "header {header:?}"
            );
            let entries: Vec<_> = cache.entries().collect();
            assert_eq!(entries.len(), 1, "header {header:?}");
            assert_eq!(
                entries[0].include_subdomains(),
                subdomains,
                "header {header:?}"
            );
        }
    }

    /// The overflow asymmetry: unquoted clamps, quoted is REJECTED.
    ///
    /// `curlx_str_number` returns `STRE_OVERFLOW` without advancing the cursor,
    /// so the mandatory closing quote of `lib/hsts.c:162` then finds the first
    /// digit instead of a quote. Measured, not intended, and reproduced.
    #[test]
    fn an_overflowing_max_age_clamps_unquoted_and_fails_quoted() {
        let clock = clock_at(T1660_NOW);
        const HUGE: &str = "99999999999999999999999";

        let mut cache = HstsCache::new();
        let header = format!("max-age={HUGE}");
        assert_eq!(
            cache.parse(b"a.example", header.as_bytes(), &clock),
            Ok(())
        );
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].expires(),
            TIME_T_MAX,
            "an unquoted overflow clamps to the sentinel"
        );
        // And it therefore writes as the word.
        assert!(saved(&cache).ends_with(b"a.example \"unlimited\"\n"));

        let mut cache = HstsCache::new();
        let header = format!("max-age=\"{HUGE}\"");
        assert_eq!(
            cache.parse(b"a.example", header.as_bytes(), &clock),
            Err(CURLcode::BadFunctionArgument),
            "a QUOTED overflow is rejected, because the cursor never moved"
        );
    }

    /// `expires + now` saturates rather than wrapping -- `lib/hsts.c:200-204`.
    #[test]
    fn the_expiry_addition_saturates() {
        let clock = clock_at(TIME_T_MAX - 5);
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"a.example", b"max-age=100", &clock), Ok(()));
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries[0].expires(), TIME_T_MAX);
    }

    /// `max-age=0` DELETES the exact entry and creates nothing --
    /// `lib/hsts.c:190-198`.
    #[test]
    fn max_age_zero_deletes_the_exact_entry() {
        let clock = clock_at(T1660_NOW);
        let mut cache = HstsCache::new();

        assert_eq!(
            cache.parse(
                b"example.com",
                b"max-age=600; includeSubDomains",
                &clock
            ),
            Ok(())
        );
        assert_eq!(
            cache.parse(b"sub.example.com", b"max-age=600", &clock),
            Ok(())
        );
        assert_eq!(cache.len(), 2);

        // Deleting the subdomain host leaves the covering entry in place.
        assert_eq!(
            cache.parse(b"sub.example.com", b"max-age=0", &clock),
            Ok(())
        );
        assert_eq!(cache.len(), 1);
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries[0].host(), b"example.com");

        // Deleting an absent host is not an error and creates nothing.
        assert_eq!(
            cache.parse(b"absent.example", b"max-age=0", &clock),
            Ok(())
        );
        assert_eq!(cache.len(), 1);

        // And `max-age="0"` -- the quoted spelling `tests/unit/unit1660.c:47`
        // uses -- deletes just the same.
        assert_eq!(
            cache.parse(b"example.com", b"max-age=\"0\"", &clock),
            Ok(())
        );
        assert_eq!(cache.len(), 0);
    }

    /// An existing exact entry is updated in place, BOTH fields --
    /// `lib/hsts.c:208-212`.
    ///
    /// This is where the header parser differs from the file reader: the reader
    /// keeps the larger expiry and never touches the flag, while this
    /// overwrites both -- so a header can turn `includeSubDomains` back OFF.
    #[test]
    fn an_existing_entry_is_updated_in_place_including_the_flag() {
        let clock = clock_at(T1660_NOW);
        let mut cache = HstsCache::new();

        assert_eq!(
            cache.parse(
                b"a.example",
                b"max-age=600; includeSubDomains",
                &clock
            ),
            Ok(())
        );
        // A SMALLER expiry, and no flag: both are taken.
        assert_eq!(cache.parse(b"a.example", b"max-age=1", &clock), Ok(()));

        assert_eq!(cache.len(), 1, "no second entry is created");
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries[0].expires(), T1660_NOW + 1);
        assert!(
            !entries[0].include_subdomains(),
            "the header parser DOES clear the flag"
        );
    }

    /// An IP literal never gets an entry -- `lib/hsts.c:131-134`.
    ///
    /// RFC 6797: *"explicit IP address identification of all forms is
    /// excluded."* The header is not even parsed, so a malformed one still
    /// reports success.
    #[test]
    fn an_ip_literal_host_creates_nothing() {
        let clock = clock_at(T1660_NOW);
        for host in [
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "2001:db8::1",
            "fe80::1",
            "::ffff:192.0.2.1",
        ] {
            let mut cache = HstsCache::new();
            assert!(host_is_ipnum(host.as_bytes()), "{host} is an IP literal");
            assert_eq!(
                cache.parse(host.as_bytes(), b"max-age=600", &clock),
                Ok(()),
                "{host}"
            );
            assert_eq!(cache.len(), 0, "{host} must create nothing");

            // The early return precedes the whole directive loop, so even a
            // header that would be rejected reports success.
            assert_eq!(
                cache.parse(host.as_bytes(), b"nonsense", &clock),
                Ok(()),
                "{host}"
            );
        }
    }

    /// Names that merely look numeric DO get entries.
    #[test]
    fn a_host_that_only_looks_numeric_still_gets_an_entry() {
        let clock = clock_at(T1660_NOW);
        for host in [
            "010.1.1.1", // A leading zero -- not an address to curl.
            "1.2.3",     // Three octets.
            "1.2.3.4.5", // Five.
            "256.1.1.1", // Out of range.
            "1.2.3.4a",  // Trailing junk.
            "example.com",
        ] {
            let mut cache = HstsCache::new();
            assert!(
                !host_is_ipnum(host.as_bytes()),
                "{host} must NOT read as an address"
            );
            assert_eq!(
                cache.parse(host.as_bytes(), b"max-age=600", &clock),
                Ok(()),
                "{host}"
            );
            assert_eq!(cache.len(), 1, "{host} must get an entry");
        }
    }

    /// An empty hostname creates nothing and reports success --
    /// `lib/hsts.c:106`, `:116`.
    #[test]
    fn an_empty_hostname_creates_nothing() {
        let clock = clock_at(T1660_NOW);
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"", b"max-age=600", &clock), Ok(()));
        assert_eq!(cache.len(), 0);

        // A lone dot is stripped to nothing, and takes the same path.
        assert_eq!(cache.parse(b".", b"max-age=600", &clock), Ok(()));
        assert_eq!(cache.len(), 0);
    }

    /// Both arguments are read as C strings, so each stops at its first zero.
    ///
    /// `strlen(hostname)` at `lib/hsts.c:129` and `while(*p)` at `:184`. A byte
    /// slice can carry a zero where a `const char *` cannot, and cutting at one
    /// is what keeps the two implementations looking at the same input.
    #[test]
    fn a_zero_byte_ends_the_hostname_and_the_header() {
        assert_eq!(c_string(b"abc\0def"), b"abc");
        assert_eq!(c_string(b"abc"), b"abc");
        assert_eq!(c_string(b"\0abc"), b"");

        let clock = clock_at(T1660_NOW);

        // The header stops at the zero, so the trailing directive is unseen --
        // and the duplicate `max-age` behind it therefore does NOT fire.
        let mut cache = HstsCache::new();
        assert_eq!(
            cache.parse(b"a.example", b"max-age=7\0; max-age=9", &clock),
            Ok(())
        );
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries[0].expires(), T1660_NOW + 7);

        // The hostname stops there too.
        let mut cache = HstsCache::new();
        assert_eq!(
            cache.parse(b"a.example\0ignored", b"max-age=7", &clock),
            Ok(())
        );
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries[0].host(), b"a.example");
    }

    // -- Lookup -----------------------------------------------------------

    /// A cache with one covering entry, for the matching tests below.
    fn covering_cache(clock: &dyn Clock) -> HstsCache {
        let mut cache = HstsCache::new();
        assert_eq!(
            cache.parse(
                b"example.com",
                b"max-age=600; includeSubDomains",
                clock
            ),
            Ok(())
        );
        cache
    }

    /// An exact match returns immediately and beats every subdomain match --
    /// `lib/hsts.c:262-264`.
    ///
    /// The covering entry is inserted FIRST and would otherwise be found as a
    /// tail match, so the assertion really does distinguish the two.
    #[test]
    fn an_exact_match_beats_a_subdomain_match() {
        let clock = clock_at(T1660_NOW);
        let mut cache = covering_cache(&clock);
        assert_eq!(
            cache.parse(b"a.example.com", b"max-age=900", &clock),
            Ok(())
        );

        let found = cache.lookup(b"a.example.com", true, &clock);
        assert!(found.is_some());
        if let Some(entry) = found {
            assert_eq!(entry.host(), b"a.example.com");
            assert_eq!(entry.expires(), T1660_NOW + 900);
            assert!(!entry.include_subdomains());
        }
    }

    /// Among subdomain candidates, the LONGEST tail wins -- `(ntail > blen)`
    /// at `lib/hsts.c:256`.
    #[test]
    fn the_longest_subdomain_tail_wins() {
        let clock = clock_at(T1660_NOW);
        let mut cache = HstsCache::new();
        // Inserted shortest-first, so a walk that kept the first hit would
        // answer `com` and fail this.
        for host in ["com", "example.com", "deep.example.com"] {
            assert_eq!(
                cache.parse(
                    host.as_bytes(),
                    b"max-age=600; includeSubDomains",
                    &clock
                ),
                Ok(()),
                "{host}"
            );
        }

        let found = cache.lookup(b"a.deep.example.com", true, &clock);
        assert!(found.is_some());
        if let Some(entry) = found {
            assert_eq!(entry.host(), b"deep.example.com");
        }

        // And inserted longest-first, the answer is the same.
        let mut cache = HstsCache::new();
        for host in ["deep.example.com", "example.com", "com"] {
            assert_eq!(
                cache.parse(
                    host.as_bytes(),
                    b"max-age=600; includeSubDomains",
                    &clock
                ),
                Ok(())
            );
        }
        let found = cache.lookup(b"a.deep.example.com", true, &clock);
        assert!(found.is_some());
        if let Some(entry) = found {
            assert_eq!(entry.host(), b"deep.example.com");
        }
    }

    /// A subdomain match needs a `'.'` immediately before the tail --
    /// `hostname[offs - 1] == '.'` at `lib/hsts.c:254`.
    ///
    /// `forexample.net` against `example.net` is `tests/unit/unit1660.c:92-96`,
    /// which exists precisely to check that the boundary is required.
    #[test]
    fn a_subdomain_match_requires_a_label_boundary() {
        let clock = clock_at(T1660_NOW);
        let mut cache = HstsCache::new();
        assert_eq!(
            cache.parse(
                b"example.net",
                b"max-age=600; includeSubDomains",
                &clock
            ),
            Ok(())
        );

        assert!(
            cache.lookup(b"forexample.net", true, &clock).is_none(),
            "no dot before the tail"
        );
        assert!(
            cache.lookup(b"sub.example.net", true, &clock).is_some(),
            "a dot before the tail"
        );
        assert!(
            cache.lookup(b"xexample.net", true, &clock).is_none(),
            "one byte, still no dot"
        );
    }

    /// Every other condition of a subdomain match, one at a time.
    #[test]
    fn the_remaining_subdomain_conditions() {
        let clock = clock_at(T1660_NOW);

        // The CALLER must ask for it.
        let mut cache = covering_cache(&clock);
        assert!(cache.lookup(b"a.example.com", false, &clock).is_none());
        assert!(cache.lookup(b"a.example.com", true, &clock).is_some());

        // The ENTRY must carry the flag.
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"example.com", b"max-age=600", &clock), Ok(()));
        assert!(cache.lookup(b"a.example.com", true, &clock).is_none());

        // `ntail < hlen` is STRICT, so an equal length can only ever be an
        // exact match -- which is what keeps a same-length mismatch from being
        // examined as a tail.
        let mut cache = covering_cache(&clock);
        assert!(cache.lookup(b"example.net", true, &clock).is_none());
        assert!(cache.lookup(b"example.com", true, &clock).is_some());

        // Folding is case-insensitive on both sides.
        let mut cache = covering_cache(&clock);
        assert!(cache.lookup(b"A.EXAMPLE.COM", true, &clock).is_some());
        assert!(cache.lookup(b"ExAmPlE.cOm", true, &clock).is_some());
    }

    /// A trailing dot on the QUERY is ignored -- `lib/hsts.c:237-239`.
    #[test]
    fn a_trailing_dot_on_the_query_is_ignored() {
        let clock = clock_at(T1660_NOW);
        let mut cache = covering_cache(&clock);
        assert!(cache.lookup(b"example.com.", true, &clock).is_some());
        assert!(cache.lookup(b"a.example.com.", true, &clock).is_some());
        // Only ONE dot is stripped, so two leaves an empty final label.
        assert!(cache.lookup(b"example.com..", true, &clock).is_none());
    }

    /// A zero-length or over-long query answers `None` before anything is
    /// walked -- `lib/hsts.c:235-236`.
    ///
    /// The ordering matters: the guard precedes the loop, so a pathological
    /// name cannot prune an expired entry as a side effect. That is asserted
    /// here rather than assumed.
    #[test]
    fn an_out_of_range_query_answers_none_without_pruning() {
        let clock = clock_at(T1660_NOW);
        // One live entry and one already expired. The expired one is loaded
        // LAST on purpose: `hsts_add` looks a host up BEFORE creating it
        // (`lib/hsts.c:426-429`), so any earlier line would have been pruned by
        // the walk the next line performs. This is the only arrangement in
        // which an expired entry survives its own load.
        let mut cache = cache_from(
            b"\
live.example \"unlimited\"\n\
dead.example \"20000101 00:00:00\"\n",
            &clock,
        );
        assert_eq!(cache.len(), 2, "the expired entry is loaded, then lingers");

        assert!(cache.lookup(b"", true, &clock).is_none());
        assert_eq!(cache.len(), 2, "an empty query prunes nothing");

        let long: Vec<u8> =
            std::iter::repeat(b'h').take(MAX_HSTS_HOSTLEN + 1).collect();
        assert!(cache.lookup(&long, true, &clock).is_none());
        assert_eq!(cache.len(), 2, "an over-long query prunes nothing");

        // A name of exactly the maximum length is IN range and does prune.
        let atmax: Vec<u8> =
            std::iter::repeat(b'h').take(MAX_HSTS_HOSTLEN).collect();
        assert!(cache.lookup(&atmax, true, &clock).is_none());
        assert_eq!(
            cache.len(),
            1,
            "the walk ran and removed the expired entry"
        );
    }

    /// A lookup PRUNES, and the removal is observable in the next save --
    /// `lib/hsts.c:245-250`.
    #[test]
    fn a_lookup_removes_expired_entries_as_a_side_effect() {
        let clock = clock_at(1_000);
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"a.example", b"max-age=10", &clock), Ok(()));
        assert_eq!(cache.parse(b"b.example", b"max-age=30", &clock), Ok(()));
        assert_eq!(cache.len(), 2);

        // The boundary is `<=`, so the entry is gone AT its expiry, not after.
        let clock = clock_at(1_009);
        assert!(cache.lookup(b"a.example", true, &clock).is_some());
        let clock = clock_at(1_010);
        assert!(cache.lookup(b"a.example", true, &clock).is_none());
        assert_eq!(cache.len(), 1, "and it was removed, not merely hidden");

        assert_eq!(
            saved(&cache),
            [FILE_HEADER, b"b.example \"19700101 00:17:10\"\n"].concat()
        );

        // Looking up something unrelated prunes the rest.
        let clock = clock_at(9_999);
        assert!(cache.lookup(b"unrelated.example", true, &clock).is_none());
        assert_eq!(cache.len(), 0);
        assert_eq!(saved(&cache), FILE_HEADER);
    }

    /// The query is never assumed to be terminated -- `lib/hsts.c:262`.
    ///
    /// A zero inside the slice is an ordinary byte here, unlike in
    /// [`HstsCache::parse`], because this entry point takes an explicit length
    /// in the C and its comment says so.
    #[test]
    fn the_lookup_query_is_not_a_c_string() {
        let clock = clock_at(T1660_NOW);
        let mut cache = covering_cache(&clock);

        // Were the slice cut at the zero, this would match `example.com`.
        assert!(cache.lookup(b"example.com\0junk", true, &clock).is_none());
        // And a longer slice of a borrowed buffer matches only its own bytes.
        let buffer = b"example.comEXTRA";
        assert!(cache.lookup(&buffer[..11], true, &clock).is_some());
        assert!(cache.lookup(buffer, true, &clock).is_none());
    }

    // -- The callback surface ---------------------------------------------

    /// The two capacities `struct curl_hstsentry` encodes.
    #[test]
    fn the_callback_buffer_publishes_the_c_bounds() {
        assert_eq!(HstsEntryBuf::NAME_CAPACITY, MAX_HSTS_HOSTLEN);
        assert_eq!(HstsEntryBuf::NAME_CAPACITY, 2048);
        // `char expire[18]` holds "YYYYMMDD HH:MM:SS" plus its zero.
        assert_eq!(HstsEntryBuf::EXPIRE_CAPACITY, 17);
        assert_eq!(b"YYYYMMDD HH:MM:SS".len(), HstsEntryBuf::EXPIRE_CAPACITY);
        // And every stamp this module can write fits.
        assert!(UNLIMITED.len() <= HstsEntryBuf::EXPIRE_CAPACITY);
        if let Ok(stamp) = format_expiry(0) {
            assert_eq!(stamp.len(), HstsEntryBuf::EXPIRE_CAPACITY);
        }
    }

    /// A stored value that does not fit leaves the field EMPTY, it does not
    /// truncate -- `curlx_strcopy` (`lib/curlx/strcopy.c:38-51`).
    #[test]
    fn the_callback_buffer_stores_all_or_nothing() {
        let mut buf = HstsEntryBuf::new();

        let atmax: Vec<u8> = std::iter::repeat(b'h')
            .take(HstsEntryBuf::NAME_CAPACITY)
            .collect();
        assert!(buf.set_name(&atmax), "exactly the capacity fits");
        assert_eq!(buf.name().len(), HstsEntryBuf::NAME_CAPACITY);

        let toobig: Vec<u8> = std::iter::repeat(b'h')
            .take(HstsEntryBuf::NAME_CAPACITY + 1)
            .collect();
        assert!(!buf.set_name(&toobig), "one byte more does not");
        assert!(buf.name().is_empty(), "and leaves the field EMPTY");

        assert!(buf.set_expire(b"20191231 10:00:00"));
        assert_eq!(buf.expire(), b"20191231 10:00:00");
        assert!(!buf.set_expire(b"20191231 10:00:00 too long"));
        assert!(buf.expire().is_empty());

        // A stored name is cut at its first zero, because the C passes
        // `strlen(host)` and the library later reads `strlen(e.name)`.
        assert!(buf.set_name(b"a.example\0ignored"));
        assert_eq!(buf.name(), b"a.example");

        // And `reset` returns all three fields to the state
        // `lib/hsts.c:455-459` establishes.
        buf.set_include_subdomains(true);
        buf.reset();
        assert!(buf.name().is_empty());
        assert!(buf.expire().is_empty());
        assert!(!buf.include_subdomains());
    }

    /// The read callback drives the cache until it stops -- `hsts_pull`
    /// (`lib/hsts.c:446-484`).
    #[test]
    fn the_read_callback_populates_the_cache_in_order() {
        let mut reader = ScriptedReader::new(
            &[
                ("1.example.com", "20300320 01:02:03", false),
                ("2.example.com", "20300320 03:02:01", true),
            ],
            StsCode::Done,
        );

        let mut cache = HstsCache::new();
        assert_eq!(cache.load_from_callback(&mut reader), Ok(()));

        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 2, "insertion order, not sorted");
        assert_eq!(entries[0].host(), b"1.example.com");
        assert!(!entries[0].include_subdomains());
        assert_eq!(entries[1].host(), b"2.example.com");
        assert!(entries[1].include_subdomains());
    }

    /// An EMPTY stamp from the read callback means for ever -- the opposite
    /// default from the file reader.
    #[test]
    fn an_empty_stamp_from_the_callback_means_for_ever() {
        let mut reader = ScriptedReader::new(
            &[
                ("forever.example", "", false),
                ("dead.example", "not a date", false),
                ("literal.example", "unlimited", false),
            ],
            StsCode::Done,
        );

        let mut cache = HstsCache::new();
        assert_eq!(cache.load_from_callback(&mut reader), Ok(()));

        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].expires(), TIME_T_MAX, "empty means for ever");
        assert_eq!(entries[1].expires(), 0, "unparsable means zero");
        assert_eq!(
            entries[2].expires(),
            0,
            "the UNLIMITED word is the FILE reader's spelling, not this one"
        );
    }

    /// An empty name from the read callback is
    /// `CURLE_BAD_FUNCTION_ARGUMENT` -- `lib/hsts.c:464-467`.
    #[test]
    fn an_empty_name_from_the_callback_is_rejected() {
        /// A reader that answers `Ok` while storing nothing at all, which is
        /// what a callback whose name did not fit produces.
        struct EmptyReader;
        impl HstsReader for EmptyReader {
            fn read_entry(&mut self, _entry: &mut HstsEntryBuf) -> StsCode {
                StsCode::Ok
            }
        }

        let mut cache = HstsCache::new();
        assert_eq!(
            cache.load_from_callback(&mut EmptyReader),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(cache.len(), 0);
    }

    /// `CURLSTS_FAIL` from the read callback is
    /// `CURLE_ABORTED_BY_CALLBACK` -- `lib/hsts.c:479-480`.
    ///
    /// `tests/data/test1915` observes it as `Second request returned 42`, and
    /// 42 is `CURLE_ABORTED_BY_CALLBACK`. Entries produced before the failure
    /// stay in the cache, because the C creates each one as it arrives.
    #[test]
    fn a_failing_read_callback_aborts_the_load() {
        // Failing immediately, as `hstsreadfail` in
        // `tests/libtest/lib1915.c:72-79` does.
        let mut reader = ScriptedReader::new(&[], StsCode::Fail);
        let mut cache = HstsCache::new();
        assert_eq!(
            cache.load_from_callback(&mut reader),
            Err(CURLcode::AbortedByCallback)
        );
        assert_eq!(cache.len(), 0);

        // Failing after producing one entry: the entry survives.
        let mut reader =
            ScriptedReader::new(&[("kept.example", "", false)], StsCode::Fail);
        let mut cache = HstsCache::new();
        assert_eq!(
            cache.load_from_callback(&mut reader),
            Err(CURLcode::AbortedByCallback)
        );
        assert_eq!(cache.len(), 1);
    }

    /// The write callback receives the stamp UNQUOTED, and the bare word
    /// `unlimited` -- `lib/hsts.c:292` and `:297`, against the file writer's
    /// `:314` and `:320`.
    #[test]
    fn the_write_callback_stamp_is_unquoted_but_the_file_stamp_is_quoted() {
        let clock = clock_at(0);
        let cache = cache_from(
            b"\
dated.example \"20300101 00:00:00\"\n\
.forever.example \"unlimited\"\n",
            &clock,
        );

        let mut writer = RecordingWriter::new();
        assert_eq!(cache.save(None, fixed_suffix, Some(&mut writer)), Ok(()));
        assert_eq!(
            writer.lines,
            vec![
                "[0/2] dated.example 20300101 00:00:00".to_string(),
                "[1/2] forever.example unlimited".to_string(),
            ]
        );

        // The very same entries, through the file writer.
        assert_eq!(
            saved(&cache),
            [
                FILE_HEADER,
                b"dated.example \"20300101 00:00:00\"\n",
                b".forever.example \"unlimited\"\n",
            ]
            .concat()
        );
    }

    /// `curl_index` counts from zero and reports the total, and the callback's
    /// `name` is the stored host WITHOUT the subdomain dot.
    ///
    /// The dot belongs to the file format alone: `hsts_push` assigns
    /// `e.name = (char *)sts->host` at `lib/hsts.c:283` with no dot in sight,
    /// which the previous test's `forever.example` line already shows.
    #[test]
    fn the_index_counts_from_zero_and_carries_the_total() {
        let clock = clock_at(0);
        let mut cache = HstsCache::new();
        for host in ["a.example", "b.example", "c.example"] {
            assert_eq!(
                cache.parse(host.as_bytes(), b"max-age=600", &clock),
                Ok(())
            );
        }

        let mut writer = RecordingWriter::new();
        assert_eq!(cache.save(None, fixed_suffix, Some(&mut writer)), Ok(()));
        assert_eq!(
            writer.lines,
            vec![
                "[0/3] a.example 19700101 00:10:00".to_string(),
                "[1/3] b.example 19700101 00:10:00".to_string(),
                "[2/3] c.example 19700101 00:10:00".to_string(),
            ]
        );

        // An empty cache offers nothing and reports a total of zero only if
        // asked; the loop body never runs, so no line is recorded at all.
        let empty = HstsCache::new();
        let mut writer = RecordingWriter::new();
        assert_eq!(empty.save(None, fixed_suffix, Some(&mut writer)), Ok(()));
        assert!(writer.lines.is_empty());
    }

    /// `CURLSTS_DONE` from the write callback stops the walk WITHOUT being an
    /// error -- `lib/hsts.c:300-301`.
    ///
    /// `*stop = (sc != CURLSTS_OK)` covers `DONE` as well as `FAIL`, but only
    /// `FAIL` maps to a `CURLcode`. And the index is not advanced past the
    /// stopping entry, because `i.index++` at `:382` comes after the break.
    #[test]
    fn a_stopping_write_callback_ends_the_walk() {
        let clock = clock_at(0);
        let mut cache = HstsCache::new();
        for host in ["a.example", "b.example", "c.example"] {
            assert_eq!(
                cache.parse(host.as_bytes(), b"max-age=600", &clock),
                Ok(())
            );
        }

        let mut writer = RecordingWriter::stopping_after(1, StsCode::Done);
        assert_eq!(
            cache.save(None, fixed_suffix, Some(&mut writer)),
            Ok(()),
            "DONE stops the walk but is not an error"
        );
        assert_eq!(writer.lines.len(), 2, "the stopping call still happened");
        assert!(
            writer.lines[1].starts_with("[1/3]"),
            "index not advanced past"
        );

        let mut writer = RecordingWriter::stopping_after(1, StsCode::Fail);
        assert_eq!(
            cache.save(None, fixed_suffix, Some(&mut writer)),
            Err(CURLcode::BadFunctionArgument),
            "FAIL is an error"
        );
        assert_eq!(writer.lines.len(), 2);
    }

    /// `CURLHSTS_READONLYFILE` skips the file but STILL runs the callback --
    /// `lib/hsts.c:345-347` jumping to the `skipsave:` label at `:369`.
    ///
    /// The same is true of an absent name and of an empty one, which is what
    /// `--hsts ""` produces.
    #[test]
    fn the_file_is_skipped_but_the_callback_always_runs() {
        let clock = clock_at(0);
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"a.example", b"max-age=600", &clock), Ok(()));

        // Read-only, with a name that would otherwise be written. The path is
        // never opened, so a directory that does not exist proves it.
        cache.set_flags(CURLHSTS_ENABLE | CURLHSTS_READONLYFILE);
        let unwritable = Path::new("/nonexistent-directory-1660/hsts");
        let mut writer = RecordingWriter::new();
        assert_eq!(
            cache.save(Some(unwritable), fixed_suffix, Some(&mut writer)),
            Ok(())
        );
        assert_eq!(writer.lines.len(), 1);

        // No name at all.
        cache.set_flags(CURLHSTS_ENABLE);
        let mut writer = RecordingWriter::new();
        assert_eq!(cache.save(None, fixed_suffix, Some(&mut writer)), Ok(()));
        assert_eq!(writer.lines.len(), 1);

        // An EMPTY name -- `!file[0]` at `:345`.
        let mut writer = RecordingWriter::new();
        assert_eq!(
            cache.save(Some(Path::new("")), fixed_suffix, Some(&mut writer)),
            Ok(())
        );
        assert_eq!(writer.lines.len(), 1);
    }

    /// A file error survives an EMPTY cache and is REPLACED by a non-empty
    /// one -- `result = hsts_push(...)` at `lib/hsts.c:379`.
    ///
    /// The C assigns into the same variable the file write used, so the
    /// callback's outcome overwrites the file's. An empty cache never enters
    /// the loop, so there the file error survives. Reproduced, oddity and all.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri's isolation refuses open, even of an \
                               unwritable path"
    )]
    fn the_callback_outcome_replaces_the_file_outcome() {
        let unwritable = Path::new("/nonexistent-directory-1660/hsts");

        // Empty cache: nothing overwrites the file error.
        let empty = HstsCache::new();
        let mut writer = RecordingWriter::new();
        assert_eq!(
            empty.save(Some(unwritable), fixed_suffix, Some(&mut writer)),
            Err(CURLcode::WriteError)
        );
        assert!(writer.lines.is_empty());

        // Non-empty: the callback's success REPLACES the file error.
        let clock = clock_at(0);
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"a.example", b"max-age=600", &clock), Ok(()));
        let mut writer = RecordingWriter::new();
        assert_eq!(
            cache.save(Some(unwritable), fixed_suffix, Some(&mut writer)),
            Ok(()),
            "the file failed, and the callback's success hides it"
        );
        assert_eq!(writer.lines.len(), 1);

        // With no callback at all, the file error is what is reported.
        assert_eq!(
            cache.save(Some(unwritable), fixed_suffix, None),
            Err(CURLcode::WriteError)
        );
    }

    // -- The relocated fixtures -------------------------------------------

    /// `tests/data/test1660` in full: the 23 traced steps, the entry count, the
    /// ten-second expiry walk, and the exact saved bytes.
    ///
    /// The single most valuable test in this file. It is the port of
    /// `tests/unit/unit1660.c` driven by that fixture's `CURL_TIME`, and it
    /// exercises the header parser, the file reader, the mutating lookup, the
    /// pruning, the deletion path, the in-place update, the insertion order and
    /// the writer -- against expectations produced by curl 8.19.0-DEV rather
    /// than by this implementation.
    #[test]
    fn unit1660_reproduces_the_test1660_fixture_byte_for_byte() {
        // `tests/unit/unit1660.c:44-102`. `"-"` in the first column is the
        // fixture's "no header, just look up"; the third column is the header;
        // the fourth is the expected `CURLcode` as an integer.
        #[rustfmt::skip]
        const STEPS: &[(&str, Option<&str>, Option<&str>, i32)] = &[
            ("-", Some("readfrom.example"), None, 0),
            ("-", Some("old.example"), None, 0),
            ("readfrom.example", None, Some("max-age=\"0\""), 0),
            ("example.com", None, Some("max-age=\"31536000\"\r\n"), 0),
            ("example.com", None, Some("max-age=\"21536000\"\r\n"), 0),
            ("example.com", None, Some("max-age=\"21536000\"; \r\n"), 0),
            ("example.com", None,
             Some("max-age=\"21536000\"; includeSubDomains\r\n"), 0),
            ("example.org", None, Some("max-age=\"31536000\"\r\n"), 0),
            ("this.example", None, Some("max=\"31536\";"), 43),
            ("this.example", None, Some("max-age=\"31536"), 43),
            ("this.example", None, Some("max-age=31536\""), 0),
            ("this.example", None, Some("max-age=0"), 0),
            ("another.example", None, Some("includeSubDomains; "), 43),
            ("example.com", None,
             Some("max-age=\"21536000\"; includeSubDomains; max-age=\"3\";"),
             43),
            ("2.example.com", None,
             Some("max-age=\"21536000\"; includeSubDomains; \
                   includeSubDomains;"), 43),
            ("3.example.com", None,
             Some("max-age=\"21536000\"; include; includeSubDomains;"), 0),
            ("3.example.com", None,
             Some("max-age=\"0\"; includeSubDomains;"), 0),
            ("-", Some("foo.example.com"), None, 0),
            ("-", Some("foo.xample.com"), None, 0),
            ("example.net", Some("forexample.net"),
             Some("max-age=\"31536000\"\r\n"), 0),
            ("example.net", Some("forexample.net"),
             Some("max-age=\"31536000\"; includeSubDomains\r\n"), 0),
            ("example.net", None,
             Some("max-age=\"0\"; includeSubDomains\r\n"), 0),
            ("expire.example", None, Some("max-age=\"7\"\r\n"), 0),
        ];

        /// The `<stdout>` block of `tests/data/test1660`, verbatim.
        #[rustfmt::skip]
        const EXPECTED: &[&str] = &[
            "readfrom.example [readfrom.example]: 1633063661 includeSubDomains",
            "'old.example' is not HSTS",
            "'readfrom.example' is not HSTS",
            "example.com [example.com]: 1579905261",
            "example.com [example.com]: 1569905261",
            "example.com [example.com]: 1569905261",
            "example.com [example.com]: 1569905261 includeSubDomains",
            "example.org [example.org]: 1579905261",
            "Input 8: error 43",
            "Input 9: error 43",
            "this.example [this.example]: 1548400797",
            "'this.example' is not HSTS",
            "Input 12: error 43",
            "Input 13: error 43",
            "Input 14: error 43",
            "3.example.com [3.example.com]: 1569905261 includeSubDomains",
            "3.example.com [example.com]: 1569905261 includeSubDomains",
            "foo.example.com [example.com]: 1569905261 includeSubDomains",
            "'foo.xample.com' is not HSTS",
            "'forexample.net' is not HSTS",
            "'forexample.net' is not HSTS",
            "'example.net' is not HSTS",
            "expire.example [expire.example]: 1548369268",
            "Number of entries: 4",
            "expire.example [expire.example]: 1548369268",
            "expire.example [expire.example]: 1548369268",
            "expire.example [expire.example]: 1548369268",
            "expire.example [expire.example]: 1548369268",
            "expire.example [expire.example]: 1548369268",
            "expire.example [expire.example]: 1548369268",
            "expire.example [expire.example]: 1548369268",
            "'expire.example' is not HSTS",
            "'expire.example' is not HSTS",
            "'expire.example' is not HSTS",
        ];

        // `showsts` (`tests/unit/unit1660.c:31-42`).
        fn showsts(
            cache: &mut HstsCache,
            chost: &str,
            clock: &dyn Clock,
        ) -> String {
            match cache.lookup(chost.as_bytes(), true, clock) {
                None => format!("'{chost}' is not HSTS"),
                Some(entry) => format!(
                    "{chost} [{}]: {}{}",
                    show(entry.host()),
                    entry.expires(),
                    if entry.include_subdomains() {
                        " includeSubDomains"
                    } else {
                        ""
                    }
                ),
            }
        }

        // The C's `deltatime`, which `hsts_debugtime` adds to `CURL_TIME`.
        let clock = clock_at(T1660_NOW);
        let mut trace: Vec<String> = Vec::new();

        // `Curl_hsts_loadfile(easy, h, arg)` at `:112`.
        let mut cache = cache_from(T1660_INPUT, &clock);

        // `:114-133`
        for (index, (host, chost, header, expected)) in STEPS.iter().enumerate()
        {
            if let Some(header) = header {
                let result =
                    cache.parse(host.as_bytes(), header.as_bytes(), &clock);
                let code = match result {
                    Ok(()) => 0,
                    Err(code) => code as i32,
                };
                assert_eq!(code, *expected, "step {index}: header {header:?}");
                if code != 0 {
                    // `:129-131` -- `printf("Input %u: error %d\n", ...)` and
                    // then `continue`, so no lookup happens.
                    trace.push(format!("Input {index}: error {code}"));
                    continue;
                }
            }
            // `:133-135`
            let chost = chost.unwrap_or(host);
            trace.push(showsts(&mut cache, chost, &clock));
        }

        // `:137`
        trace.push(format!("Number of entries: {}", cache.len()));

        // `:140-145` -- ten lookups, advancing the wall clock one second after
        // each, which is the C's `deltatime++`.
        for delta in 0..10 {
            clock.set_epoch_secs(T1660_NOW + delta);
            trace.push(showsts(&mut cache, "expire.example", &clock));
        }

        assert_eq!(
            trace, EXPECTED,
            "the traced steps must match tests/data/test1660 exactly"
        );

        // `:147-148` -- `Curl_hsts_save(easy, h, savename)`, compared against
        // the fixture's expected `%LOGDIR/hsts1660.save`.
        let out = saved(&cache);
        assert_eq!(
            show(&out),
            show(T1660_SAVED),
            "the saved bytes must match tests/data/test1660 exactly"
        );
        assert_eq!(out, T1660_SAVED);
    }

    /// `tests/data/test1915`: the read and write callbacks end to end.
    ///
    /// The port of `tests/libtest/lib1915.c`.
    #[test]
    fn lib1915_reproduces_the_test1915_callback_output() {
        #[rustfmt::skip]
        const PRELOAD: &[(&str, &str, bool)] = &[
            ("1.example.com", "25250320 01:02:03", false),
            ("2.example.com", "25250320 03:02:01", false),
            ("3.example.com", "25250319 01:02:03", false),
            ("4.example.com", "", false),
        ];

        /// The `<stdout>` block of `tests/data/test1915`, `%if large-time` arm.
        #[rustfmt::skip]
        const EXPECTED: &[&str] = &[
            "[0/4] 1.example.com 25250320 01:02:03",
            "[1/4] 2.example.com 25250320 03:02:01",
            "[2/4] 3.example.com 25250319 01:02:03",
            "[3/4] 4.example.com unlimited",
        ];

        let mut reader = ScriptedReader::new(PRELOAD, StsCode::Done);
        let mut cache = HstsCache::new();
        assert_eq!(cache.load_from_callback(&mut reader), Ok(()));
        assert_eq!(cache.len(), 4);

        let mut writer = RecordingWriter::new();
        assert_eq!(cache.save(None, fixed_suffix, Some(&mut writer)), Ok(()));
        assert_eq!(writer.lines, EXPECTED);

        // The stamps are far enough in the future that no lookup prunes them.
        let clock = clock_at(T1660_NOW);
        assert!(cache.lookup(b"1.example.com", true, &clock).is_some());
        assert_eq!(cache.len(), 4);

        // Independently: the two parsers agree on the fixture's own stamps.
        for (_, stamp, _) in PRELOAD.iter().filter(|(_, s, _)| !s.is_empty()) {
            let parsed = getdate_capped(stamp.as_bytes());
            assert!(parsed.is_some(), "{stamp} must parse");
            if let Some(instant) = parsed {
                assert_eq!(
                    format_expiry(instant),
                    Ok(stamp.as_bytes().to_vec()),
                    "{stamp} must round-trip"
                );
            }
        }
    }

    /// `tests/libtest/lib1900.c`: two `CURLOPT_HSTS` names, and the second wins
    /// the remembered one.
    ///
    /// The C sets `CURLOPT_HSTS` twice and then duplicates the handle, which
    /// exercises the option-list plumbing rather than this module. What IS this
    /// module's is the ordering contract of [`HstsCache::loadfiles`] and the
    /// private filename copy, so both are asserted here against files that do
    /// not exist -- which is legitimate, because a missing cache file is not an
    /// error.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "Miri's isolation refuses open, even of an \
                               absent file"
    )]
    fn lib1900_loads_every_name_in_order_and_remembers_the_last() {
        let clock = clock_at(T1660_NOW);
        let mut names = SList::new();
        names.append(b"first-hsts.txt");
        names.append(b"second-hsts.txt");

        let mut cache = HstsCache::new();
        assert_eq!(
            cache.loadfiles(&names, &clock),
            Ok(()),
            "neither file exists, and that is not an error"
        );
        assert_eq!(cache.len(), 0);
        assert_eq!(
            cache.filename(),
            Some(Path::new("second-hsts.txt")),
            "the LAST name walked is the one remembered"
        );

        // An empty list walks nothing and leaves the name alone.
        let empty = SList::new();
        assert_eq!(cache.loadfiles(&empty, &clock), Ok(()));
        assert_eq!(cache.filename(), Some(Path::new("second-hsts.txt")));

        // And `set_filename` is the option layer's way in.
        cache.set_filename(Some(Path::new("third-hsts.txt")));
        assert_eq!(cache.filename(), Some(Path::new("third-hsts.txt")));
        cache.set_filename(None);
        assert_eq!(cache.filename(), None);
    }

    /// The merge rule across two files depends on the order they are read in --
    /// which is why [`HstsCache::loadfiles`] must not reorder.
    #[test]
    fn the_load_order_of_two_files_is_observable() {
        let clock = clock_at(1_000_000_000);
        let earlier = b"a.example \"20300101 00:00:00\"\n";
        let later = b"a.example \"20400101 00:00:00\"\n";

        // Larger second: it wins.
        let mut cache = HstsCache::new();
        assert_eq!(
            cache.read_from(&mut Cursor::new(earlier.to_vec()), &clock),
            Ok(())
        );
        assert_eq!(
            cache.read_from(&mut Cursor::new(later.to_vec()), &clock),
            Ok(())
        );
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].expires(), 2_208_988_800);

        // Smaller second: the larger first value is KEPT, so the two orders do
        // agree here -- the rule is "largest wins", not "last wins".
        let mut cache = HstsCache::new();
        assert_eq!(
            cache.read_from(&mut Cursor::new(later.to_vec()), &clock),
            Ok(())
        );
        assert_eq!(
            cache.read_from(&mut Cursor::new(earlier.to_vec()), &clock),
            Ok(())
        );
        let entries: Vec<_> = cache.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].expires(), 2_208_988_800);
    }

    /// [`HstsCache::cleanup`] empties the cache and forgets the name --
    /// `Curl_hsts_cleanup` (`lib/hsts.c:77-92`).
    #[test]
    fn cleanup_empties_the_cache_and_forgets_the_name() {
        let clock = clock_at(T1660_NOW);
        let mut cache = cache_from(T1660_INPUT, &clock);
        cache.set_filename(Some(Path::new("hsts.txt")));
        cache.set_flags(CURLHSTS_ENABLE);
        assert!(!cache.is_empty());

        cache.cleanup();

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.filename(), None);
        // `Curl_hsts_cleanup` does not clear `flags`, and neither does this.
        assert_eq!(cache.flags(), CURLHSTS_ENABLE);
        assert_eq!(saved(&cache), FILE_HEADER);
    }

    // -- The filesystem ---------------------------------------------------
    //
    // Grouped and separately gated, because Miri's isolation refuses `mkdir`.
    // Everything above runs under Miri.

    /// Binds a scratch directory, failing loudly if the environment cannot
    /// provide one.
    ///
    /// A macro rather than a function because the failure arm has to leave the
    /// *test*. Modelled on the helper of the same name in
    /// [`crate::util::fopen`], so that a reader who knows one knows both.
    macro_rules! scratch {
        ($name:ident) => {
            let $name = tempfile::tempdir();
            assert!(
                $name.is_ok(),
                "this test needs a scratch directory: {:?}",
                $name.as_ref().err()
            );
            let Ok($name) = $name else { return };
        };
    }

    /// A cache file written by this module is read back identically, through
    /// real files -- the round trip the module exists to guarantee.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_saved_file_round_trips_through_the_filesystem() {
        scratch!(dir);
        let path = dir.path().join("hsts.txt");

        let clock = clock_at(T1660_NOW);
        let first = cache_from(T1660_INPUT, &clock);
        assert_eq!(first.save(Some(&path), fixed_suffix, None), Ok(()));

        // What landed on disk is what `write_to` produces.
        let on_disk = std::fs::read(&path);
        assert!(on_disk.is_ok(), "the file must exist");
        if let Ok(bytes) = &on_disk {
            assert_eq!(bytes, &saved(&first));
        }

        // And reading it back gives the same cache, byte for byte, on save.
        let mut second = HstsCache::new();
        assert_eq!(second.loadfile(&path, &clock), Ok(()));
        assert_eq!(second.len(), first.len());
        assert_eq!(saved(&second), saved(&first));
        assert_eq!(second.filename(), Some(path.as_path()));

        // A third generation is still identical, so nothing drifts.
        let third = dir.path().join("hsts2.txt");
        assert_eq!(second.save(Some(&third), fixed_suffix, None), Ok(()));
        let a = std::fs::read(&path);
        let b = std::fs::read(&third);
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(a.ok(), b.ok());
    }

    /// A missing file is not an error, and the name is remembered anyway --
    /// `lib/hsts.c:499-507`.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_missing_cache_file_is_not_an_error() {
        scratch!(dir);
        let absent = dir.path().join("never-written.txt");

        let clock = clock_at(T1660_NOW);
        let mut cache = HstsCache::new();
        assert_eq!(cache.loadfile(&absent, &clock), Ok(()));
        assert_eq!(cache.len(), 0);
        assert_eq!(
            cache.filename(),
            Some(absent.as_path()),
            "the name is copied BEFORE the open, so a failed open still \
             remembers it"
        );

        // Which means a later save with no name of its own finds this one.
        assert_eq!(cache.parse(b"a.example", b"max-age=600", &clock), Ok(()));
        assert_eq!(cache.save(None, fixed_suffix, None), Ok(()));
        assert!(absent.is_file(), "the remembered name was used");

        // A DIRECTORY is a different case, and the honest answer is a read
        // error. `open(2)` on a directory succeeds, so the C's `fopen` does
        // too and the `if(fp)` body IS entered -- and then `fgets` fails with
        // EISDIR while `feof` stays false, so `Curl_get_line`'s
        // `while(1)` at `lib/curl_get_line.c:39` never terminates: it
        // re-reads, gets NULL again, and neither of its two exits can fire.
        // `crate::util::get_line` maps a failed read to `CURLcode::ReadError`
        // instead, which is where the divergence lives; terminating is the
        // only defensible behaviour and no fixture reaches the path.
        let mut cache = HstsCache::new();
        assert_eq!(
            cache.loadfile(dir.path(), &clock),
            Err(CURLcode::ReadError)
        );
        assert_eq!(cache.len(), 0);
        assert_eq!(
            cache.filename(),
            Some(dir.path()),
            "and the name is still remembered, because the copy came first"
        );
    }

    /// The `Temp` path renames over an existing regular file, and leaves no
    /// temporary behind -- `lib/hsts.c:361-368`.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn saving_over_a_regular_file_renames_a_temporary_into_place() {
        scratch!(dir);
        let path = dir.path().join("hsts.txt");
        assert!(std::fs::write(&path, b"stale content\n").is_ok());

        let clock = clock_at(0);
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"a.example", b"max-age=600", &clock), Ok(()));
        assert_eq!(cache.save(Some(&path), fixed_suffix, None), Ok(()));

        assert_eq!(std::fs::read(&path).ok(), Some(saved(&cache)));

        // Exactly one file in the directory: no `.tmp` survivor.
        let entries = std::fs::read_dir(dir.path());
        assert!(entries.is_ok());
        if let Ok(entries) = entries {
            let names: Vec<String> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                names,
                vec!["hsts.txt".to_string()],
                "no temporary left"
            );
        }
    }

    /// The `Direct` path writes straight through and does NOT rename, which is
    /// what keeps `--hsts /dev/null` working.
    #[test]
    #[cfg_attr(miri, ignore = "Miri does not model /dev/null")]
    fn saving_to_a_device_node_writes_directly() {
        let devnull = Path::new("/dev/null");
        if !devnull.exists() {
            return;
        }

        let clock = clock_at(0);
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"a.example", b"max-age=600", &clock), Ok(()));

        // A `rand_suffix` that would fail if it were ever called: the C returns
        // at `lib/curl_fopen.c:103` before reaching the generator, so this
        // proves the `Direct` path really is taken.
        let never = || Err(CURLcode::OutOfMemory);
        assert_eq!(cache.save(Some(devnull), never, None), Ok(()));
        assert!(devnull.exists(), "and the device node still exists");
    }

    /// A target that cannot be opened is `CURLE_WRITE_ERROR`.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn an_unopenable_target_is_a_write_error() {
        scratch!(dir);
        // A path whose parent is a regular file cannot be opened.
        let blocker = dir.path().join("blocker");
        assert!(std::fs::write(&blocker, b"x").is_ok());
        let path = blocker.join("hsts.txt");

        let clock = clock_at(0);
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"a.example", b"max-age=600", &clock), Ok(()));
        assert_eq!(
            cache.save(Some(&path), fixed_suffix, None),
            Err(CURLcode::WriteError)
        );
    }

    /// A save that fails leaves the previous cache file intact.
    ///
    /// `Curl_fopen` opens the target with `"w"` in order to `fstat` it
    /// (`lib/curl_fopen.c:99`), which truncates it before the temporary file
    /// exists, so in the C a save that fails afterwards has destroyed the
    /// original. This test used to assert that DATA LOSS on the grounds that it
    /// was measured C behaviour.
    ///
    /// It no longer holds, deliberately. `crate::util::fopen` does not pass
    /// `O_TRUNC`: `O_TRUNC` on the final target, before the protected temporary
    /// file exists, is a destructive primitive aimed by anyone who can create a
    /// name in the output directory (CWE-22, and CWE-367 for the window before
    /// the rename). The hardening section of that module argues why removing it
    /// is within AAP 0.8.1 rather than the "improvement" 0.8.2 forbids: it
    /// changes no byte on a socket, no flag the user types and no exported
    /// signature.
    ///
    /// The failure is still arranged through the injected randomness: a provider
    /// that reports an error is exactly the C's `if(result) goto fail` at
    /// `lib/curl_fopen.c:110-111`, reached immediately after the open at `:99`.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_failed_save_leaves_the_previous_cache_intact() {
        scratch!(dir);
        let path = dir.path().join("hsts.txt");
        const ORIGINAL: &[u8] = b"precious original content\n";
        assert!(std::fs::write(&path, ORIGINAL).is_ok());

        let clock = clock_at(0);
        let mut cache = HstsCache::new();
        assert_eq!(cache.parse(b"a.example", b"max-age=600", &clock), Ok(()));

        let failing = || Err(CURLcode::OutOfMemory);
        assert_eq!(
            cache.save(Some(&path), failing, None),
            Err(CURLcode::OutOfMemory),
            "the provider's code is propagated unchanged"
        );

        assert_eq!(
            std::fs::read(&path).ok().as_deref(),
            Some(ORIGINAL),
            "the original SURVIVES -- step one no longer truncates it"
        );
    }

    /// The whole option surface end to end: load a file, apply a header, save
    /// to a new name, and read that back.
    ///
    /// The shape of `tests/data/test446` and `tests/data/test780`, which drive
    /// the same sequence through the command line.
    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses mkdir")]
    fn a_load_a_header_and_a_save_compose() {
        scratch!(dir);
        let input = dir.path().join("hsts446.txt");
        // The body of `tests/data/test446`, whose expiries are in 2033.
        const BODY: &[u8] = b"\
this.hsts.example \"20330525 03:33:20\"\n\
another.example.com \"20330727 03:33:20\"\n";

        let mut seed = Vec::from(FILE_HEADER);
        seed.extend_from_slice(BODY);
        assert!(std::fs::write(&input, &seed).is_ok());

        let clock = clock_at(T1660_NOW);
        let mut cache = HstsCache::new();
        assert_eq!(cache.loadfile(&input, &clock), Ok(()));
        assert_eq!(cache.len(), 2);

        // A header for a third host, and one that upgrades the first to cover
        // subdomains.
        assert_eq!(
            cache.parse(b"third.example", b"max-age=600", &clock),
            Ok(())
        );
        assert_eq!(
            cache.parse(
                b"this.hsts.example",
                b"max-age=600; includeSubDomains",
                &clock
            ),
            Ok(())
        );
        assert_eq!(cache.len(), 3, "the second header UPDATED, not inserted");

        let output = dir.path().join("saved.txt");
        assert_eq!(cache.save(Some(&output), fixed_suffix, None), Ok(()));

        // Insertion order is preserved across the update: the upgraded entry
        // keeps its original position.
        let expected = [
            FILE_HEADER,
            b".this.hsts.example \"20190124 22:44:21\"\n",
            b"another.example.com \"20330727 03:33:20\"\n",
            b"third.example \"20190124 22:44:21\"\n",
        ]
        .concat();
        assert_eq!(std::fs::read(&output).ok(), Some(expected));

        // And the saved file loads back to the same thing.
        let mut reread = HstsCache::new();
        assert_eq!(reread.loadfile(&output, &clock), Ok(()));
        assert_eq!(saved(&reread), saved(&cache));
    }
}
