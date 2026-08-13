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
//! Header storage and the header-inspection API.
//!
//! Supersedes two C translation units and the public contract they serve:
//!
//! | C source                     | Lines | Here                          |
//! |------------------------------|-------|-------------------------------|
//! | `lib/headers.c`              | 394   | [`HeaderStore`]               |
//! | `lib/headers.h:30-37`        | 62    | [`StoredHeader`]              |
//! | `lib/dynhds.c`               | 341   | [`HeaderSet`]                 |
//! | `lib/dynhds.h:36-51`         | 184   | [`HeaderEntry`]               |
//! | `include/curl/header.h:31-38`| 74    | [`HeaderView`] (layout)       |
//! | `include/curl/header.h:41-45`| --    | the `CURLH_*` origin bits     |
//! | `include/curl/header.h:47-56`| --    | `CURLHcode`, owned by `error` |
//! | `lib/http2.c:657-702`        | --    | [`PushHeaders`]               |
//!
//! | def line | symbol                   | backed by                     |
//! |----------|--------------------------|-------------------------------|
//! | 6        | `curl_easy_header`       | [`HeaderStore::header`]       |
//! | 8        | `curl_easy_nextheader`   | [`HeaderStore::next_header`]  |
//! | 79       | `curl_pushheader_byname` | [`PushHeaders::by_name`]      |
//! | 80       | `curl_pushheader_bynum`  | [`PushHeaders::by_num`]       |
//!
//! # Two stores, two lookup rules -- do not unify them
//!
//! [`HeaderStore`] holds received response headers and looks names up
//! **case-insensitively**, because `lib/headers.c:83` uses `curl_strequal`.
//! [`PushHeaders`] holds an HTTP/2 `PUSH_PROMISE` field set and looks names
//! up **case-sensitively**, because `lib/http2.c:694` uses `strncmp`. The
//! asymmetry is shipped behaviour. Collapsing the two behind one comparison
//! would be a silent change to an observable result.
//!
//! [`HeaderSet`] is a third, separate thing: the bounded ordered set the
//! HTTP/1, HTTP/2, HTTP/3 and CONNECT-proxy layers compose requests in, and
//! the home of HTTP/2 response trailers (`stream->resp_trailers`,
//! `lib/http2.c:280`).
//!
//! # Contracts this module does not implement, and who must
//!
//! Recorded here because the modules that owe them do not exist yet, and
//! because each is invisible in the code below.
//!
//! * **Two output slots.** `lib/urldata.h:1032` declares
//!   `struct curl_header headerout[2]`. `curl_easy_header` fills slot 0
//!   (`lib/headers.c:114-116`) and `curl_easy_nextheader` fills slot 1
//!   (`lib/headers.c:176-178`), so interleaving the two APIs never lets one
//!   clobber the other's record. `curl-rs-ffi` owns those two `#[repr(C)]`
//!   slots and must keep them distinct; a [`HeaderView`] can populate
//!   either. Each returned pointer stays valid until the next call to the
//!   *same* function.
//! * **Argument null checks.** [`HeaderStore::header`] cannot express a null
//!   `name`, `hout` or handle, so the shim must reject those with
//!   `CURLHE_BAD_ARGUMENT` itself (`lib/headers.c:69-72`). Conversely
//!   [`HeaderStore::next_header`] validates NOTHING -- the C dereferences
//!   the handle immediately -- so the shim guards a null handle by returning
//!   `NULL` and adds no other check.
//! * **The collecting client writer.** `lib/headers.c:315-346` installs a
//!   writer named `"hds-collect"` at phase `CURL_CW_PROTOCOL`, exactly once
//!   (guarded by a get-by-name lookup) and only when
//!   `data->conn && (data->conn->scheme->protocol & PROTO_FAMILY_HTTP)`. A
//!   push error aborts the write; every write, header or not, is otherwise
//!   forwarded downstream. That plumbing belongs to `transfer/writeout.rs`;
//!   this module supplies [`classify_origin`] so the precedence cannot be
//!   got wrong there.
//! * **`CURLHE_NOT_BUILT_IN` is never returned from here, and IS returned by
//!   the shim.** The C guards this file with `!CURL_DISABLE_HTTP &&
//!   !CURL_DISABLE_HEADERS_API` (`lib/headers.c:31`) and supplies a second,
//!   complete definition of both entry points under the `#else`
//!   (`lib/headers.c:365-394`): `CURLHE_NOT_BUILT_IN` unconditionally, and
//!   NULL. Which of the two definitions a build uses is a question about the
//!   build, not about this module -- this module is the built-in branch's
//!   store and lookup, and it answers `CURLHE_NOHEADERS` for an empty store
//!   because that is what the built-in branch answers. `curl-rs-ffi`'s
//!   `ffi/misc.rs` selects the branch, from
//!   [`crate::version::ENGINE_HEADERS`], and today selects the `#else`: no
//!   HTTP protocol is implemented, so the collecting client writer described
//!   below has no module to live in and no store in this build has ever held
//!   a header. The variant stays defined in [`crate::error`] for that
//!   selection to use; nothing below produces it, and that is deliberate
//!   rather than an omission.
//!
//! # Safety and layering
//!
//! No `unsafe`, no raw pointers, no `#[repr(C)]` and no `extern` functions
//! appear in this file: the crate root's `#![deny(unsafe_code)]` exempts
//! only `mod ffi`, and the layout-visible `struct curl_header` mirror is
//! `curl-rs-ffi`'s to declare. Nothing here panics on hostile input --
//! malformed lines, absent colons, all-blank lines, over-long stores,
//! zero-length names and out-of-range indices all return a measured
//! `CURLcode` or `CURLHcode`.
//!
//! Imports reach only [`crate::error`] and [`crate::util`]. The protocol,
//! transfer, connection, TLS, easy and multi layers all depend on this
//! module, so an import of any of them would close a cycle.

// The allowance is never set on this module's root, because that would also
// hide the next unreferenced item somebody adds -- the crate's own policy test
// in `lib.rs` enforces the distinction.

use core::fmt;

use memchr::memchr;

use crate::error::{CURLHcode, CURLcode, CodeResult, HeaderResult};
use crate::util::dynbuf::{DynBuf, DYN_HTTP_REQUEST};
use crate::util::fallible;
use crate::util::redact::{HeaderValue, Lossy};
use crate::util::strcase::{casecompare, ncasecompare, raw_tolower};
use crate::util::strparse::is_blank;

// The `origin` bit set -- `include/curl/header.h:41-45`.
//
// Plain `u32` constants keeping their C spellings, for two reasons. The
// spelling is what makes a grep from the C source land here, and `u32` is
// what the ABI passes: `curl_easy_header` takes `unsigned int origin`, so a
// newtype would only add a conversion at the boundary that owns none of the
// meaning. The `bitflags` crate is deliberately not used -- it is not in the
// workspace dependency set, and five constants do not need it.

/// A plain server response header -- `CURLH_HEADER`.
///
/// `include/curl/header.h:41`.
pub const CURLH_HEADER: u32 = 1 << 0;

/// A trailing response header -- `CURLH_TRAILER`.
///
/// `include/curl/header.h:42`.
pub const CURLH_TRAILER: u32 = 1 << 1;

/// A header from a `CONNECT` request or response -- `CURLH_CONNECT`.
///
/// `include/curl/header.h:43`.
pub const CURLH_CONNECT: u32 = 1 << 2;

/// A header from a 1xx informational response -- `CURLH_1XX`.
///
/// `include/curl/header.h:44`.
pub const CURLH_1XX: u32 = 1 << 3;

/// An HTTP/2 or HTTP/3 pseudo-header -- `CURLH_PSEUDO`.
///
/// `include/curl/header.h:45`.
pub const CURLH_PSEUDO: u32 = 1 << 4;

/// Every origin bit the public header defines: the union of the five above.
///
/// Written as that union rather than as `0x1f` because the union is what
/// `lib/headers.c:70-71` tests against, and an added sixth bit should widen
/// this constant by being named rather than by a literal being edited. The
/// value is 31.
pub const CURLH_ORIGIN_MASK: u32 =
    CURLH_HEADER | CURLH_TRAILER | CURLH_CONNECT | CURLH_1XX | CURLH_PSEUDO;

/// The reserved bit every projected origin carries -- `lib/headers.c:50`.
const CURLH_RESERVED_BIT: u32 = 1 << 27;

// The five pseudo-header names -- `lib/http.h:237-241`.

/// `HTTP_PSEUDO_METHOD` -- `lib/http.h:237`.
pub const HTTP_PSEUDO_METHOD: &[u8] = b":method";

/// `HTTP_PSEUDO_SCHEME` -- `lib/http.h:238`.
pub const HTTP_PSEUDO_SCHEME: &[u8] = b":scheme";

/// `HTTP_PSEUDO_AUTHORITY` -- `lib/http.h:239`.
pub const HTTP_PSEUDO_AUTHORITY: &[u8] = b":authority";

/// `HTTP_PSEUDO_PATH` -- `lib/http.h:240`.
pub const HTTP_PSEUDO_PATH: &[u8] = b":path";

/// `HTTP_PSEUDO_STATUS` -- `lib/http.h:241`.
pub const HTTP_PSEUDO_STATUS: &[u8] = b":status";

/// All five pseudo-header names, in the order `lib/http.h:237-241` declares
/// them.
///
/// Each begins with a colon, and `namevalue` keeps that colon in the stored
/// name -- see the note on [`HeaderStore::push`], because getting it wrong
/// breaks HTTP/2 and HTTP/3 header inspection silently.
#[rustfmt::skip]
pub const HTTP_PSEUDO_NAMES: [&[u8]; 5] = [
    HTTP_PSEUDO_METHOD,
    HTTP_PSEUDO_SCHEME,
    HTTP_PSEUDO_AUTHORITY,
    HTTP_PSEUDO_PATH,
    HTTP_PSEUDO_STATUS,
];

// Limits.

/// The most response headers one HTTP response may contribute to a store.
pub(crate) const MAX_HTTP_RESP_HEADER_COUNT: usize = 5000;

/// The most `PUSH_PROMISE` fields [`PushHeaders`] will accept.
pub(crate) const MAX_PUSH_PROMISE_HEADERS: usize = 1280;

// Origin classification -- `lib/headers.c:296-313`.

/// `CLIENTWRITE_HEADER` -- meta information, a header. `lib/sendf.h:44`.
pub(crate) const CLIENTWRITE_HEADER: u32 = 1 << 2;

/// `CLIENTWRITE_STATUS` -- a special status header. `lib/sendf.h:45`.
pub(crate) const CLIENTWRITE_STATUS: u32 = 1 << 3;

/// `CLIENTWRITE_CONNECT` -- a `CONNECT`-related header. `lib/sendf.h:46`.
pub(crate) const CLIENTWRITE_CONNECT: u32 = 1 << 4;

/// `CLIENTWRITE_1XX` -- a 1xx-response-related header. `lib/sendf.h:47`.
pub(crate) const CLIENTWRITE_1XX: u32 = 1 << 5;

/// `CLIENTWRITE_TRAILER` -- a trailer header. `lib/sendf.h:48`.
pub(crate) const CLIENTWRITE_TRAILER: u32 = 1 << 6;

/// The origin a client write should be stored under, or [`None`] to store
/// nothing.
///
/// Supersedes the classifying half of `hds_cw_collect_write`
/// (`lib/headers.c:296-313`). Two properties of the C are easy to lose and
/// both are observable:
///
/// * **Only `HEADER` writes that are not `STATUS` are stored**
///   (`lib/headers.c:300`), so a status line such as `HTTP/1.1 200 OK` never
///   enters a store. Every other write -- a body, a 0-length flush, an
///   informational write -- yields [`None`] here and is simply forwarded.
/// * **The precedence is a first-match chain, not a union**:
///   `CONNECT` > `1XX` > `TRAILER` > `HEADER` (`lib/headers.c:301-305`).
///   Exactly one bit comes back. A write flagged both `CONNECT` and `1XX`
///   classifies as [`CURLH_CONNECT`], which a bitwise OR would get wrong.
///
/// The whole mapping, which the tests at the foot of this file assert:
///
/// ```text
/// HEADER                     -> Some(CURLH_HEADER)
/// HEADER | TRAILER           -> Some(CURLH_TRAILER)
/// HEADER | 1XX  | TRAILER    -> Some(CURLH_1XX)
/// HEADER | CONNECT | 1XX     -> Some(CURLH_CONNECT)
/// HEADER | STATUS            -> None
/// BODY                       -> None
/// ```
#[allow(dead_code)] // consumer: transfer/writeout.rs
#[must_use]
pub(crate) fn classify_origin(write_flags: u32) -> Option<u32> {
    // `lib/headers.c:300` -- a header write, and not a status line.
    if (write_flags & CLIENTWRITE_HEADER) == 0
        || (write_flags & CLIENTWRITE_STATUS) != 0
    {
        return None;
    }

    // `lib/headers.c:301-305`, an ordered chain so that the first match wins.
    if (write_flags & CLIENTWRITE_CONNECT) != 0 {
        Some(CURLH_CONNECT)
    } else if (write_flags & CLIENTWRITE_1XX) != 0 {
        Some(CURLH_1XX)
    } else if (write_flags & CLIENTWRITE_TRAILER) != 0 {
        Some(CURLH_TRAILER)
    } else {
        Some(CURLH_HEADER)
    }
}

// The iteration cursor -- the `anchor` field of `struct curl_header`.

// `HeaderCursor` packs its two 32-bit fields into one `usize` so that the ABI
// can carry it through `void *anchor`. Asserting it here turns that forfeit
// into a compile error on a 32-bit target, where the shift below would
// otherwise overflow silently in a release build.
const _: () = assert!(
    core::mem::size_of::<usize>() >= 8,
    "HeaderCursor packs a 32-bit index and a 32-bit generation into one \
     usize; 32-bit targets are out of scope (specification 0.2.2)"
);

/// A resumable position in a [`HeaderStore`], and the value behind the
/// `anchor` field of `struct curl_header`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct HeaderCursor {
    /// Index of the header this cursor points at.
    index: u32,
    /// Generation of the store the index was taken from. Never 0 for a
    /// cursor a store issued.
    generation: u32,
}

impl HeaderCursor {
    /// How far the generation is shifted when packed into a [`usize`].
    const GENERATION_SHIFT: u32 = 32;

    /// Mask selecting the index half of a packed cursor.
    const INDEX_MASK: usize = 0xffff_ffff;

    /// The opaque form the ABI stores in `void *anchor`.
    #[must_use]
    pub fn to_raw(self) -> usize {
        ((self.generation as usize) << Self::GENERATION_SHIFT)
            | (self.index as usize)
    }

    /// The inverse of [`HeaderCursor::to_raw`].
    ///
    /// Total, because the ABI cannot promise anything about the bits behind
    /// an application-supplied `anchor`. A value it was not given -- 0 most
    /// of all -- decodes to a cursor whose generation no live store shares,
    /// and iteration ends rather than misreads.
    #[must_use]
    pub fn from_raw(raw: usize) -> Self {
        Self {
            index: (raw & Self::INDEX_MASK) as u32,
            generation: (raw >> Self::GENERATION_SHIFT) as u32,
        }
    }

    /// The index this cursor points at.
    #[must_use]
    pub fn index(self) -> usize {
        self.index as usize
    }

    /// The store generation this cursor was minted against.
    #[must_use]
    pub fn generation(self) -> u32 {
        self.generation
    }
}

// The outward projection -- `include/curl/header.h:31-38`.

/// One header as the public API presents it: the safe form of
/// `struct curl_header`.
///
/// The C struct is layout-visible -- consumers read its six fields directly,
/// so their order and types are frozen ABI:
///
/// ```c
/// struct curl_header {
///   char *name;    /* this might not use the same case */
///   char *value;
///   size_t amount; /* number of headers using this name  */
///   size_t index;  /* ... of this instance, 0 or higher */
///   unsigned int origin; /* see bits below */
///   void *anchor; /* handle privately used by libcurl */
/// };
/// ```
///
/// The `#[repr(C)]` mirror and the two output slots that keep its pointers
/// alive belong to `curl-rs-ffi/src/ffi/misc.rs`. This is the borrowed view
/// that fills one, in the same field order, so the mapping is one to one.
///
/// # Borrowing
///
/// [`HeaderView::name`] and [`HeaderView::value`] borrow the store, exactly
/// as the C's `char *` fields point into `hs->buffer` rather than owning a
/// copy. They stay valid until the store is pushed to, reset or cleaned up;
/// the borrow checker enforces here what the C left to the caller's care.
///
/// Every field is always set. `lib/headers.c:33-34` states the requirement
/// as a comment -- *"This function MUST assign all struct fields in the
/// output struct"* -- and constructing a whole [`HeaderView`] at once is how
/// this file keeps it, since a struct literal cannot leave one stale.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct HeaderView<'a> {
    /// The header name, in the case it arrived in.
    pub name: &'a [u8],
    /// The header value, with leading blanks dropped and trailing blanks
    /// trimmed as [`HeaderStore::push`] describes.
    pub value: &'a [u8],
    /// How many headers in the store share this name under the queried
    /// origin mask and request number.
    pub amount: usize,
    /// Which of those this one is, counting from 0 in arrival order.
    pub index: usize,
    /// The stored origin bit, OR-ed with the reserved bit `1 << 27` that
    /// `lib/headers.c:50` adds on the way out. Test it with `&`, never
    /// with `==`; defeating `==` is precisely why the bit is there.
    pub origin: u32,
    /// The position to resume iteration from -- `void *anchor` in C.
    pub anchor: HeaderCursor,
}

/// Name-aware redaction, matching [`StoredHeader`]'s.
///
/// This is the borrowed view of a [`StoredHeader`] and is what
/// `curl_easy_header` hands out (`lib/headers.c:33-34`), so it must not
/// disclose what the stored form does not. The value renders through
/// `crate::util::redact::HeaderValue` and everything else in full.
///
/// That path is written as plain code rather than as an intra-doc link on
/// purpose: `crate::util::redact` is `pub(crate)`, and a link from the
/// documentation of a public item to a private one is an error under
/// `RUSTDOCFLAGS=-D warnings`. The same paths ARE linked elsewhere in this
/// crate, which is correct there because those items are themselves private,
/// so rustdoc resolves the link without complaint.
impl fmt::Debug for HeaderView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderView")
            .field("name", &Lossy(self.name))
            .field(
                "value",
                &HeaderValue {
                    name: self.name,
                    value: self.value,
                },
            )
            .field("amount", &self.amount)
            .field("index", &self.index)
            .field("origin", &self.origin)
            .field("anchor", &self.anchor)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The ordered header set -- `lib/dynhds.c`, `lib/dynhds.h`.

/// One name/value pair in a [`HeaderSet`] -- `struct dynhds_entry`,
/// `lib/dynhds.h:36-41`.
///
/// The C carries `namelen` and `valuelen` beside the two pointers because a
/// `char *` does not know its own length; [`Vec::len`] carries both here, so
/// the struct has two fields rather than four. The two NUL bytes the C's
/// single combined allocation reserves (`lib/dynhds.c:38-44`) are a C-string
/// artefact and have no counterpart.
///
/// Both members are arbitrary bytes. Neither is folded on the way in unless
/// [`HeaderSet::set_opts`] asked for it, and the value is never folded at
/// all.
#[derive(Clone, PartialEq, Eq)]
pub struct HeaderEntry {
    name: Vec<u8>,
    value: Vec<u8>,
}

/// Name-aware, so `Authorization` and `Cookie` never reach a log.
///
/// Hand-written rather than derived for the reason [`StoredHeader`]'s own
/// formatter records at length: this type is a leaf, so a redaction here is one
/// a parent formatter cannot undo, and the parent formatters are the ones that
/// get attached without anybody thinking about the values underneath.
impl fmt::Debug for HeaderEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeaderEntry")
            .field("name", &Lossy(&self.name))
            .field(
                "value",
                &HeaderValue {
                    name: &self.name,
                    value: &self.value,
                },
            )
            .finish()
    }
}

impl HeaderEntry {
    /// The name, in the case it was stored in.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// A bounded, ordered, duplicate-permitting set of header fields.
///
/// # Limits
///
/// Two, both from `lib/dynhds.c:139-142`, and both reported as
/// [`CURLcode::OutOfMemory`] -- not [`CURLcode::TooLarge`], which would read
/// more naturally and would be a change to observable behaviour:
///
/// * `max_entries`, where **0 means unlimited**. The C's `max_entries &&`
///   short-circuit is load-bearing, and every one of the eight
///   `Curl_dynhds_init` call sites in the tree passes 0.
/// * `max_strs_size`, the running total of all name and value lengths. The
///   test is strictly greater, so a total landing exactly on the limit is
///   accepted. All eight call sites pass `DYN_HTTP_REQUEST`, 1 MiB.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeaderSet {
    /// The entries, in arrival order. Never reordered.
    entries: Vec<HeaderEntry>,
    /// Running sum of every stored name and value length -- `strs_len`.
    strs_len: usize,
    /// Entry-count ceiling; 0 means unlimited.
    max_entries: usize,
    /// Ceiling on [`HeaderSet::strs_len`].
    max_strs_size: usize,
    /// Whether names are ASCII-folded on insertion -- `DYNHDS_OPT_LOWERCASE`.
    lowercase: bool,
}

impl Default for HeaderSet {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderSet {
    /// An empty set with the limits every call site in the C tree uses.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(0, DYN_HTTP_REQUEST)
    }

    /// An empty set with explicit limits -- `Curl_dynhds_init`,
    /// `lib/dynhds.c:57-67`.
    #[must_use]
    pub fn with_limits(max_entries: usize, max_strs_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            strs_len: 0,
            max_entries,
            max_strs_size,
            lowercase: false,
        }
    }

    /// Number of entries -- `Curl_dynhds_count`, `lib/dynhds.c:97-100`.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every entry, in arrival order.
    #[must_use]
    pub fn entries(&self) -> &[HeaderEntry] {
        &self.entries
    }

    /// The `n`-th entry, or [`None`] past the end.
    ///
    /// `Curl_dynhds_getn`, `lib/dynhds.c:107-111`.
    #[must_use]
    pub fn getn(&self, n: usize) -> Option<&HeaderEntry> {
        self.entries.get(n)
    }

    /// The FIRST entry with this name, or [`None`].
    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<&HeaderEntry> {
        self.entries.iter().find(|entry| {
            entry.name.len() == name.len()
                && ncasecompare(&entry.name, name, name.len())
        })
    }

    /// Every name and value pair, borrowed, in arrival order.
    ///
    /// This is what replaces `Curl_dynhds_to_nva` (`lib/dynhds.c:319-339`).
    /// The C allocates an `nghttp2_nv` array whose members borrow the
    /// entries; HTTP/2 and HTTP/3 here consume the borrow directly and hand
    /// it to HPACK or QPACK, so no array is built and no `nghttp2` type
    /// appears in this crate at all.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.name.as_slice(), entry.value.as_slice()))
    }

    /// Whether names are ASCII-folded on insertion.
    #[allow(dead_code)] // consumer: protocols/http2.rs
    #[must_use]
    pub(crate) fn lowercase(&self) -> bool {
        self.lowercase
    }

    /// Replace the options -- `Curl_dynhds_set_opts`, `lib/dynhds.c:102-105`.
    #[allow(dead_code)] // consumer: protocols/http2.rs
    pub(crate) fn set_opts(&mut self, lowercase: bool) {
        self.lowercase = lowercase;
    }

    /// Drop every entry, keeping the allocation and the limits.
    ///
    /// `Curl_dynhds_reset`, `lib/dynhds.c:83-95`. The C frees each entry but
    /// keeps the pointer array; [`Vec::clear`] keeps capacity, which is the
    /// same bargain. `strs_len` returns to 0; the limits and the options
    /// survive.
    #[allow(dead_code)] // consumer: protocols/http1.rs
    pub(crate) fn reset(&mut self) {
        self.entries.clear();
        self.strs_len = 0;
    }

    /// Drop every entry and release the allocation.
    ///
    /// `Curl_dynhds_free`, `lib/dynhds.c:69-81`. The difference from
    /// [`HeaderSet::reset`] is only the allocation: the C's `Curl_safefree`
    /// on `hds` zeroes `hds_allc` too. The limits and the options survive
    /// here as they do there.
    #[allow(dead_code)] // consumer: protocols/http1.rs
    pub(crate) fn free(&mut self) {
        self.entries = Vec::new();
        self.strs_len = 0;
    }

    /// Append a name and value -- `Curl_dynhds_add`, `lib/dynhds.c:131-175`.
    ///
    /// # Errors
    ///
    /// [`CURLcode::OutOfMemory`] when either limit would be exceeded: the
    /// entry count reaching a non-zero `max_entries`, or the string total
    /// growing strictly past `max_strs_size`. Both C returns are
    /// `CURLE_OUT_OF_MEMORY` and neither is changed here, however much
    /// `CURLE_TOO_LARGE` would suit the second.
    #[allow(dead_code)] // consumer: protocols/http1.rs
    pub(crate) fn add(&mut self, name: &[u8], value: &[u8]) -> CodeResult<()> {
        // `lib/dynhds.c:139-140`. The `max_entries &&` short-circuit is why
        // 0 means unlimited.
        if self.max_entries != 0 && self.entries.len() >= self.max_entries {
            return Err(CURLcode::OutOfMemory);
        }
        // `lib/dynhds.c:141-142`, strictly greater: a total landing exactly
        // on the ceiling is accepted. Summed with checked arithmetic so that
        // a hostile pair of lengths cannot wrap past the comparison.
        let added = match name.len().checked_add(value.len()) {
            Some(added) => added,
            None => return Err(CURLcode::OutOfMemory),
        };
        let total = match self.strs_len.checked_add(added) {
            Some(total) => total,
            None => return Err(CURLcode::OutOfMemory),
        };
        if total > self.max_strs_size {
            return Err(CURLcode::OutOfMemory);
        }

        // `entry_new`, `lib/dynhds.c:29-50`: the bytes are copied, and the
        // NAME is folded if and only if `DYNHDS_OPT_LOWERCASE` is set. The
        // fold is `Curl_strntolower`, which is ASCII-only -- every byte from
        // 0x80 upwards maps to itself -- and the value is never folded.
        //
        // Both copies are externally sized: a header name and value from the
        // network, bounded only by `max_strs_size` above, which the caller
        // chooses. `entry_new`'s own answer to a failed `curlx_malloc` is
        // `CURLE_OUT_OF_MEMORY` (`lib/dynhds.c:38-40`), and the same code is
        // reported here rather than aborting the process. Ordered so that
        // nothing is stored until every allocation has succeeded, which is what
        // makes a refusal leave this set exactly as it was.
        let mut stored_name =
            fallible::vec_from_slice(name).map_err(fallible::oom)?;
        if self.lowercase {
            for byte in &mut stored_name {
                *byte = raw_tolower(*byte);
            }
        }
        let stored_value =
            fallible::vec_from_slice(value).map_err(fallible::oom)?;

        // The C grows its pointer array 16 at a time, clamped to
        // `max_entries` (`lib/dynhds.c:148-165`). Growth is `fallible::push`'s
        // business here; the policy is recorded only so that a reader comparing
        // the two files does not go looking for it. Growth is not observable.
        // Order is, so nothing that could reorder is introduced.
        fallible::push(
            &mut self.entries,
            HeaderEntry {
                name: stored_name,
                value: stored_value,
            },
        )
        .map_err(fallible::oom)?;
        self.strs_len = total;
        Ok(())
    }

    /// Append one header parsed from an HTTP/1 line.
    ///
    /// `Curl_dynhds_h1_add_line`, `lib/dynhds.c:183-215`. Per
    /// `lib/dynhds.h:156-158` the line *"may contain a delimiting CRLF or
    /// just LF. Any characters after that will be ignored."*
    ///
    /// The parse, in the C's order, because each step is observable:
    ///
    /// 1. An empty line is a silent success that stores nothing --
    ///    `if(!line || !line_len) return CURLE_OK;`. It is NOT an error, and
    ///    it is not the same outcome as [`HeaderStore::push`] gives for an
    ///    unterminated line.
    /// 2. The name ends at the FIRST colon. A line beginning with a colon
    ///    therefore stores a zero-length name, which is how a pseudo-header
    ///    behaves if it is ever routed through this path.
    /// 3. Blanks -- space and tab only -- are skipped after the colon.
    /// 4. The value is truncated at the first `\r`; only if there is no `\r`
    ///    at all is the first `\n` looked for. That order matters.
    ///
    /// # Errors
    ///
    /// [`CURLcode::BadFunctionArgument`] when the line holds no colon, or
    /// whatever [`HeaderSet::add`] reports for the resulting pair.
    #[allow(dead_code)] // consumer: protocols/http1.rs
    pub(crate) fn h1_add_line(&mut self, line: &[u8]) -> CodeResult<()> {
        // `lib/dynhds.c:192-193`.
        if line.is_empty() {
            return Ok(());
        }

        // `lib/dynhds.c:195-199`. A raw byte search, deliberately unlike the
        // C-string walk in `namevalue`: `memchr` does not stop at a NUL, so a
        // colon after an embedded NUL is still found here.
        let colon = match memchr(b':', line) {
            Some(colon) => colon,
            None => return Err(CURLcode::BadFunctionArgument),
        };

        // `lib/dynhds.c:200-206`. `is_blank` is ISBLANK -- space and tab and
        // nothing else. `u8::is_ascii_whitespace` would also swallow the
        // newline, carriage return and form feed, which would change the
        // value this stores.
        let mut start = colon + 1;
        while start < line.len() && is_blank(line[start]) {
            start += 1;
        }
        let value = &line[start..];

        // `lib/dynhds.c:208-212`: carriage return first, newline only in its
        // absence.
        let end = match memchr(b'\r', value) {
            Some(at) => at,
            None => memchr(b'\n', value).unwrap_or(value.len()),
        };

        self.add(&line[..colon], &value[..end])
    }

    /// Write every header into `dbuf` in HTTP/1 form.
    ///
    /// # Errors
    ///
    /// Whatever [`DynBuf::addn`] reports -- [`CURLcode::TooLarge`] when the
    /// buffer's ceiling is reached. Emission stops at the first failure, as
    /// the C's `if(result) break;` does, and the entries after it are not
    /// written.
    #[allow(dead_code)] // consumer: protocols/http1.rs
    pub(crate) fn h1_dprint(&self, dbuf: &mut DynBuf) -> CodeResult<()> {
        if self.entries.is_empty() {
            return Ok(());
        }

        let mut line: Vec<u8> = Vec::new();
        for entry in &self.entries {
            line.clear();
            line.extend_from_slice(&entry.name);
            line.extend_from_slice(b": ");
            line.extend_from_slice(&entry.value);
            line.extend_from_slice(b"\r\n");
            dbuf.addn(&line)?;
        }
        Ok(())
    }
}

// The received-header store -- `lib/headers.c`, `lib/headers.h`.

/// One received header, as [`HeaderStore`] keeps it.
///
/// Supersedes `struct Curl_header_store` (`lib/headers.h:30-37`), which is
/// an intrusive list node followed by two pointers into a trailing blob:
///
/// ```c
/// struct Curl_header_store {
///   struct Curl_llist_node node;
///   char *name;  /* points into 'buffer' */
///   char *value; /* points into 'buffer' */
///   int request; /* 0 is the first request, then 1.. 2.. */
///   unsigned char type; /* CURLH_* defines */
///   char buffer[1]; /* this is the raw header blob */
/// };
/// ```
///
/// The `node` member and the `buffer` trick both go: the store is a [`Vec`]
/// rather than an intrusive list, and the name and value own their bytes
/// instead of pointing into a shared blob. Two field types are worth stating:
///
/// * `request` stays [`i32`], because the ABI passes `int request` and
///   accepts `-1` as "the current request".
/// * `origin` widens to [`u32`] from the C's `unsigned char`. Only the low
///   five bits are ever set, the C widens it again on output, and carrying
///   one width throughout removes a narrowing that meant nothing.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredHeader {
    name: Vec<u8>,
    value: Vec<u8>,
    request: i32,
    origin: u32,
}

/// Name-aware redaction, applied at the leaf so a parent cannot undo it.
///
/// # Why this is not `#[derive(Debug)]`
///
/// A header store holds whatever the peer and the application put in it, which
/// includes `Authorization`, `Proxy-Authorization`, `Cookie` and `Set-Cookie`.
/// A derived formatter would render every one of those verbatim, and this type
/// is reachable from `CURLINFO`-bearing state, from redirect handling and from
/// `crate::transfer`, so any `{:?}` on a parent -- including one written years
/// from now by somebody who never reads this file -- would have written a
/// session cookie into a log.
///
/// Redacting at the LEAF rather than at each parent is the whole design. A
/// parent may derive `Debug` freely and still cannot disclose a credential,
/// because the only formatter that can see these bytes is this one. The
/// alternative -- auditing every parent -- fails the first time somebody adds
/// a parent.
///
/// # What is redacted, and what deliberately is not
///
/// Only the VALUE, and only when `crate::util::redact::is_sensitive_header`
/// classifies the name. The name itself always renders, because knowing that
/// an `Authorization` header is present is exactly what a reader needs and
/// discloses nothing. `request` and `origin` are integers with no secret in
/// them. Ordinary values -- `Content-Type`, `Location` -- render in full,
/// because they are already visible in `--trace` output and redacting them
/// would cost a debugging capability for no confidentiality gain.
///
/// Nothing about the STORED bytes changes: [`Self::value`] still returns them
/// verbatim, which is what `curl_easy_header` hands to a caller
/// (`lib/headers.c:33-34`).
impl fmt::Debug for StoredHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredHeader")
            .field("name", &Lossy(&self.name))
            .field(
                "value",
                &HeaderValue {
                    name: &self.name,
                    value: &self.value,
                },
            )
            .field("request", &self.request)
            .field("origin", &self.origin)
            .finish()
    }
}

impl StoredHeader {
    /// The name, in the case it arrived in.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Which request this header belongs to; 0 is the first.
    #[must_use]
    pub fn request(&self) -> i32 {
        self.request
    }

    /// The single origin bit this header was stored under, without the
    /// reserved bit the outward projection adds.
    #[must_use]
    pub fn origin(&self) -> u32 {
        self.origin
    }

    /// Whether this header answers an origin mask and a request number.
    ///
    /// The two right-hand conjuncts of `lib/headers.c:83-85`. The origin test
    /// is a bitwise AND -- any shared bit matches -- while the request test is
    /// exact equality.
    fn matches(&self, origin: u32, request: i32) -> bool {
        (self.origin & origin) != 0 && self.request == request
    }

    /// [`StoredHeader::matches`] with the name compared too.
    ///
    /// All three conjuncts of `lib/headers.c:83-85`. The name comparison is
    /// `curl_strequal`, so it folds ASCII case and nothing else: no locale
    /// and no Unicode fold can change which headers match.
    fn matches_name(&self, name: &[u8], origin: u32, request: i32) -> bool {
        casecompare(&self.name, name) && self.matches(origin, request)
    }
}

/// Every response header received on a transfer, in arrival order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HeaderStore {
    /// Received headers, in arrival order.
    headers: Vec<StoredHeader>,
    /// Bumped on every mutation; never 0. See [`HeaderCursor`].
    generation: u32,
}

impl Default for HeaderStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HeaderStore {
    /// The first generation a store ever has.
    ///
    /// 1 rather than 0, so that the all-zero packing of [`HeaderCursor`] --
    /// what a null `void *anchor` decodes to -- can never match a live
    /// store.
    const FIRST_GENERATION: u32 = 1;

    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
            generation: Self::FIRST_GENERATION,
        }
    }

    /// Number of stored headers, across all requests and origins.
    ///
    /// `Curl_llist_count(&data->state.httphdrs)` in the C.
    #[must_use]
    pub fn count(&self) -> usize {
        self.headers.len()
    }

    /// Whether no header has been stored yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Every stored header, in arrival order.
    #[must_use]
    pub fn as_slice(&self) -> &[StoredHeader] {
        &self.headers
    }

    /// The most recently stored header -- `data->state.prevhead`,
    /// `lib/urldata.h:1033`.
    ///
    /// The C keeps the pointer so that `lib/http.c` can reach the header a
    /// continuation line folds onto. [`Vec::last`] is the same fact without
    /// the second copy of it that could fall out of step.
    #[allow(dead_code)] // consumer: protocols/http1.rs
    #[must_use]
    pub(crate) fn prevhead(&self) -> Option<&StoredHeader> {
        self.headers.last()
    }

    /// Advance the generation, invalidating every outstanding cursor.
    fn bump_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            self.generation = Self::FIRST_GENERATION;
        }
    }

    /// A cursor pointing at `at` in this store's current generation.
    fn cursor_at(&self, at: usize) -> HeaderCursor {
        HeaderCursor {
            // A store holds at most `MAX_HTTP_RESP_HEADER_COUNT` headers, so
            // the index always fits. The saturating conversion is here so
            // that the claim needs no trust: it cannot panic if it is ever
            // wrong, and `to_raw` stays lossless for every reachable index.
            index: u32::try_from(at).unwrap_or(u32::MAX),
            generation: self.generation,
        }
    }

    /// Build the outward view of the header at `at`.
    fn project(
        &self,
        at: usize,
        index: usize,
        amount: usize,
    ) -> Option<HeaderView<'_>> {
        let stored = self.headers.get(at)?;
        Some(HeaderView {
            name: &stored.name,
            value: &stored.value,
            amount,
            index,
            origin: stored.origin | CURLH_RESERVED_BIT,
            anchor: self.cursor_at(at),
        })
    }

    /// Drop every stored header, keeping the allocation.
    ///
    /// `headers_reset`, `lib/headers.c:286-290`. The C re-initialises the
    /// list and clears `prevhead`; clearing the [`Vec`] does both, since
    /// `prevhead` is [`Vec::last`] here. Outstanding cursors are invalidated.
    #[allow(dead_code)] // consumer: transfer/writeout.rs
    pub(crate) fn reset(&mut self) {
        self.headers.clear();
        self.bump_generation();
    }

    /// Free every stored header and return to the initial state.
    #[allow(dead_code)] // consumer: the easy-handle lifecycle
    pub(crate) fn cleanup(&mut self) {
        self.headers = Vec::new();
        self.bump_generation();
    }

    /// Store one received header.
    ///
    /// Supersedes `Curl_headers_push` (`lib/headers.c:221-281`). `header` is
    /// the raw line as the protocol layer saw it, CRLF-, CR- or LF-
    /// terminated. `origin` is one of the five `CURLH_*` bits -- it is a
    /// parameter rather than something inferred, so that the HTTP/2 and
    /// HTTP/3 layers can supply [`CURLH_PSEUDO`], which
    /// [`classify_origin`] never produces. `request` is the current request
    /// number, `data->state.requests` in the C.
    ///
    /// # Five outcomes, in the C's order, all observable
    ///
    /// 1. A first byte of `\r` or `\n` is the **body separator**: nothing is
    ///    stored and the call SUCCEEDS (`lib/headers.c:231-233`). Checked
    ///    before any trimming.
    /// 2. One trailing `\n` is removed, then one trailing `\r`, in that
    ///    order (`lib/headers.c:235-239`).
    /// 3. If nothing was removed, the line had **neither terminator** and
    ///    the call fails with [`CURLcode::WeirdServerReply`]
    ///    (`lib/headers.c:240-242`). Note that this is an ERROR where
    ///    outcome 1 and an empty [`HeaderSet::h1_add_line`] are successes:
    ///    three different ways for nothing to be stored, only one of which
    ///    is a failure.
    /// 4. A first byte that is blank marks a **folded continuation line**:
    ///    the leading blanks are dropped (`lib/headers.c:244-252`). A line
    ///    of nothing but blanks fails with
    ///    [`CURLcode::WeirdServerReply`].
    /// 5. A store already holding `MAX_HTTP_RESP_HEADER_COUNT` headers fails
    ///    with [`CURLcode::TooLarge`] (`lib/headers.c:253-257`) -- a
    ///    different currency from [`HeaderSet::add`]'s limits, which report
    ///    [`CURLcode::OutOfMemory`]. The two are not interchangeable.
    ///
    /// # Splitting name from value
    ///
    /// Then `namevalue` (`lib/headers.c:181-214`) applies, and three of its
    /// rules are load-bearing:
    ///
    /// * With `origin` **exactly equal** to [`CURLH_PSEUDO`] the first byte
    ///   must be a colon, and **the stored name keeps it**: `:status: 200`
    ///   stores the name `:status`. The C assigns its name pointer before
    ///   stepping over that colon, and only the search for the separating
    ///   colon starts past it.
    /// * The separator search is a C-string walk, so it stops at an embedded
    ///   NUL as readily as at a colon: a NUL before the separator means "no
    ///   colon" and yields [`CURLcode::BadFunctionArgument`].
    /// * Leading blanks after the colon are dropped and trailing blanks are
    ///   trimmed, but the trim stops one byte short of emptying a non-empty
    ///   value, because the C's loop condition is strictly greater. A line
    ///   whose every byte after the colon is blank therefore yields an EMPTY
    ///   value -- the leading skip consumed them all and the trim never ran.
    ///
    /// # Errors
    ///
    /// [`CURLcode::WeirdServerReply`], [`CURLcode::TooLarge`] or
    /// [`CURLcode::BadFunctionArgument`] as above. The C emits
    /// `failf(data, "Invalid response header")` alongside the last of these
    /// and returns the same code; diagnostics are outside the observable
    /// contract here and never change a return value.
    #[allow(dead_code)] // consumer: transfer/writeout.rs
    pub(crate) fn push(
        &mut self,
        header: &[u8],
        origin: u32,
        request: i32,
    ) -> CodeResult<()> {
        // 1. `lib/headers.c:231-233`.
        if matches!(header.first(), Some(b'\r') | Some(b'\n')) {
            return Ok(());
        }

        // 2. `lib/headers.c:235-239`: one newline, then one carriage return.
        let mut span = header;
        if let Some(rest) = span.strip_suffix(b"\n") {
            span = rest;
        }
        if let Some(rest) = span.strip_suffix(b"\r") {
            span = rest;
        }

        // 3. `lib/headers.c:240-242`.
        if span.len() == header.len() {
            return Err(CURLcode::WeirdServerReply);
        }

        // 4. `lib/headers.c:244-252`. The emptiness check sits INSIDE this
        // branch in the C, so a line whose first byte is not blank never
        // reaches it; `namevalue` rejects an empty span anyway.
        if span.first().is_some_and(|byte| is_blank(*byte)) {
            while let Some((&first, tail)) = span.split_first() {
                if !is_blank(first) {
                    break;
                }
                span = tail;
            }
            if span.is_empty() {
                return Err(CURLcode::WeirdServerReply);
            }
        }

        // 5. `lib/headers.c:253-257`.
        if self.headers.len() >= MAX_HTTP_RESP_HEADER_COUNT {
            return Err(CURLcode::TooLarge);
        }

        // `lib/headers.c:265-275`. On failure the C frees the half-built
        // entry and stores nothing; returning early is that, and the generation
        // counter is deliberately NOT bumped on a failed push, because nothing
        // was added for an iterator to have been invalidated by.
        let (name, value) = namevalue(span, origin)?;
        fallible::push(
            &mut self.headers,
            StoredHeader {
                name,
                value,
                request,
                origin,
            },
        )
        .map_err(fallible::oom)?;
        self.bump_generation();
        Ok(())
    }

    /// Look one header up by name, origin mask, request and index.
    ///
    /// # Errors
    ///
    /// In the C's order, which is the order they are tested here:
    ///
    /// * [`CURLHcode::BadArgument`] -- `origin` is 0, or has a bit outside
    ///   [`CURLH_ORIGIN_MASK`], or `request` is below -1
    ///   (`lib/headers.c:69-72`). A null `name` or output pointer belongs to
    ///   the same check in the C and is the ABI shim's to make.
    /// * [`CURLHcode::Noheaders`] -- the store is empty
    ///   (`lib/headers.c:73-74`).
    /// * [`CURLHcode::Norequest`] -- `request` exceeds `cur_request`
    ///   (`lib/headers.c:75-76`). A `request` of -1 means `cur_request` and
    ///   is substituted after this test, not before.
    /// * [`CURLHcode::Missing`] -- nothing matches
    ///   (`lib/headers.c:91-92`).
    /// * [`CURLHcode::Badindex`] -- something matches, but fewer than
    ///   `index + 1` of them (`lib/headers.c:93-94`).
    pub fn header(
        &self,
        name: &[u8],
        index: usize,
        origin: u32,
        request: i32,
        cur_request: i32,
    ) -> HeaderResult<HeaderView<'_>> {
        // `lib/headers.c:69-72`.
        if origin == 0 || origin > CURLH_ORIGIN_MASK || request < -1 {
            return Err(CURLHcode::BadArgument);
        }
        // `lib/headers.c:73-74`.
        if self.headers.is_empty() {
            return Err(CURLHcode::Noheaders);
        }
        // `lib/headers.c:75-76`.
        if request > cur_request {
            return Err(CURLHcode::Norequest);
        }
        // `lib/headers.c:77-78`.
        let request = if request == -1 { cur_request } else { request };

        // `lib/headers.c:80-90`: a first pass purely to count.
        let amount = self
            .headers
            .iter()
            .filter(|stored| stored.matches_name(name, origin, request))
            .count();

        // `lib/headers.c:91-94`.
        if amount == 0 {
            return Err(CURLHcode::Missing);
        }
        if index >= amount {
            return Err(CURLHcode::Badindex);
        }

        let at = self
            .headers
            .iter()
            .enumerate()
            .filter(|(_, stored)| stored.matches_name(name, origin, request))
            .map(|(at, _)| at)
            .nth(index);

        // `lib/headers.c:114-116`: the projection the ABI copies into
        // `headerout[0]`.
        match at.and_then(|at| self.project(at, index, amount)) {
            Some(view) => Ok(view),
            None => Err(CURLHcode::Missing),
        }
    }

    /// Step to the next header matching an origin mask and request.
    ///
    /// # This function validates nothing
    ///
    /// Deliberately, because the C does not. There is no origin-mask check
    /// and no handle check -- `lib/headers.c:133` dereferences the handle
    /// immediately -- and consequently no `CURLHE_BAD_ARGUMENT` path at all:
    /// every way of failing is a plain [`None`]. An `origin` of 0 matches
    /// nothing and simply ends iteration, and bits above
    /// [`CURLH_ORIGIN_MASK`] are ignored because no stored header carries
    /// them. Adding a validation path here would be a behaviour change; the
    /// only guard the ABI shim adds is a null handle, which it answers with
    /// `NULL`.
    pub fn next_header(
        &self,
        origin: u32,
        request: i32,
        cur_request: i32,
        prev: Option<HeaderCursor>,
    ) -> Option<HeaderView<'_>> {
        // `lib/headers.c:133-136`.
        if request > cur_request {
            return None;
        }
        let request = if request == -1 { cur_request } else { request };

        // `lib/headers.c:138-146`: resume one past the anchor, or start at
        // the head.
        let start = match prev {
            Some(cursor) => {
                if cursor.generation != self.generation {
                    return None;
                }
                cursor.index().checked_add(1)?
            }
            None => 0,
        };

        // `lib/headers.c:148-160`: advance to the next header of the wanted
        // origin and request, or report the end.
        let at = self
            .headers
            .iter()
            .enumerate()
            .skip(start)
            .find(|(_, stored)| stored.matches(origin, request))
            .map(|(at, _)| at)?;
        let selected = self.headers.get(at)?;

        // `lib/headers.c:164-174`.
        let mut amount = 0usize;
        let mut index = 0usize;
        for (position, check) in self.headers.iter().enumerate() {
            if casecompare(&selected.name, &check.name)
                && check.matches(origin, request)
            {
                amount += 1;
            }
            if position == at {
                // The selected entry always matches, so `amount` has just
                // been incremented for it and this is the count of its
                // namesakes that came before. Saturating rather than `- 1`
                // so the expression cannot underflow even if that reasoning
                // is ever invalidated.
                index = amount.saturating_sub(1);
            }
        }

        // `lib/headers.c:176-178`: the projection the ABI copies into
        // `headerout[1]` -- a different slot from `header`'s, so interleaving
        // the two never clobbers either result.
        self.project(at, index, amount)
    }
}

/// Split a stored header line into its name and value.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] when `origin` is exactly
/// [`CURLH_PSEUDO`] and the line does not begin with a colon, or when no
/// separating colon is found at all.
fn namevalue(header: &[u8], origin: u32) -> CodeResult<(Vec<u8>, Vec<u8>)> {
    // The C carries `DEBUGASSERT(hlen)` (`lib/headers.c:185`) and its one
    // caller guarantees it. An empty line cannot hold a colon, so the C's own
    // no-colon answer serves, and no debug assertion is transcribed.
    if header.is_empty() {
        return Err(CURLcode::BadFunctionArgument);
    }

    // `lib/headers.c:188-192`. EXACT equality against the pseudo bit, not a
    // bit test: in the C a combined mask does not take this path either.
    let mut scan_from = 0usize;
    if origin == CURLH_PSEUDO {
        if header.first() != Some(&b':') {
            return Err(CURLcode::BadFunctionArgument);
        }
        // `*name = header` happens at `lib/headers.c:186`, BEFORE the
        // `header++` here, so the name still starts at the colon. Only the
        // search below begins past it.
        scan_from = 1;
    }

    // `lib/headers.c:194-202`. A C-string walk -- `while(*header && (*header
    // != ':'))` -- so it ends at an embedded NUL as readily as at a colon,
    // and a NUL before the separator is "no colon". Deliberately unlike
    // `HeaderSet::h1_add_line`, whose C original uses `memchr` and does not
    // stop at a NUL.
    let mut separator = None;
    for (at, &byte) in header.iter().enumerate().skip(scan_from) {
        if byte == 0 {
            break;
        }
        if byte == b':' {
            separator = Some(at);
            break;
        }
    }
    let separator = match separator {
        Some(separator) => separator,
        None => return Err(CURLcode::BadFunctionArgument),
    };

    // `lib/headers.c:204-208`: blanks after the colon are skipped. ISBLANK is
    // space and tab and nothing else.
    let mut start = separator + 1;
    while start < header.len() && is_blank(header[start]) {
        start += 1;
    }

    // `lib/headers.c:210-212`. The C's `end` starts at the last byte of the
    // line and the loop runs while `end > header`, STRICTLY greater, where
    // `header` is by then the value's first byte -- so the trim stops one
    // byte short of emptying a non-empty value. The bound is reproduced
    // exactly rather than relaxed to `>=`, and it is worth recording that it
    // is never the BINDING test: the leading-blank skip just above leaves the
    // value starting on a non-blank byte, so on a one-byte value the ISBLANK
    // test fails first. The two forms agree on every input reachable through
    // `HeaderStore::push`, which is this function's only caller; the strict
    // form is kept because it is what the C says and because it keeps the
    // invariant true of the function on its own terms.
    let mut end = header.len();
    while end > start + 1 && is_blank(header[end - 1]) {
        end -= 1;
    }

    // Both copies are the size of a header a server sent, so both are routed
    // through `crate::util::fallible`. The C reaches them through
    // `Curl_dyn_addn` into a `dynbuf` whose refusal is
    // `CURLE_OUT_OF_MEMORY`; `CURLcode::OutOfMemory` is the same answer, and
    // the `?` ordering means a refusal on the second leaves nothing stored.
    let name = fallible::vec_from_slice(&header[..separator])
        .map_err(fallible::oom)?;
    let value =
        fallible::vec_from_slice(&header[start..end]).map_err(fallible::oom)?;
    Ok((name, value))
}

// The HTTP/2 PUSH_PROMISE field set -- `lib/http2.c`.

/// The header fields of an HTTP/2 `PUSH_PROMISE`, as the push callback sees
/// them.
///
/// # The stored form is `name:value`, with no space
///
/// `lib/http2.c:1478` builds each entry with
/// `curl_maprintf("%s:%s", name, value)` -- one colon, no following space.
/// That is NOT the wire form `name: value` that [`HeaderSet::h1_dprint`]
/// emits, and the difference is visible through the ABI:
/// [`PushHeaders::by_num`] hands back the WHOLE `name:value` string, not the
/// value. Tidying that into a value-only accessor would break every existing
/// push callback.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct PushHeaders {
    /// One `name:value` string per promised field, in arrival order.
    entries: Vec<Vec<u8>>,
}

/// Name-aware redaction over the combined `name:value` entries.
///
/// The stored form is one string per field with the name and the value joined
/// by a colon (`lib/http2.c:1478`), so classifying an entry means splitting it
/// at the first colon -- which is what the C's own consumers do. An entry with
/// no colon cannot be classified and is redacted whole, which is the safe
/// direction: a malformed promise is exactly the case where guessing wrong
/// would be worst.
///
/// A server-push promise carries the request headers the server intends to
/// answer, so `Authorization` and `Cookie` appear here for the same reason
/// they appear in [`StoredHeader`].
impl fmt::Debug for PushHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// One entry, rendered as the C stores it but with a credential value
        /// replaced by its length.
        struct Entry<'a>(&'a [u8]);

        impl fmt::Debug for Entry<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match memchr(b':', self.0) {
                    Some(at) => {
                        let (name, rest) = self.0.split_at(at);
                        // `rest` still carries the colon; skip exactly it.
                        let value = rest.get(1..).unwrap_or_default();
                        write!(
                            f,
                            "{:?}:{:?}",
                            Lossy(name),
                            HeaderValue { name, value }
                        )
                    }
                    // No colon: unclassifiable, so redact the whole entry.
                    None => fmt::Debug::fmt(
                        &HeaderValue {
                            name: b"authorization",
                            value: self.0,
                        },
                        f,
                    ),
                }
            }
        }

        f.debug_struct("PushHeaders")
            .field(
                "entries",
                &self.entries.iter().map(|e| Entry(e)).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl PushHeaders {
    /// An empty field set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// How many fields the promise carried -- `push_headers_used`.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Whether the promise carried no fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop every field -- `free_push_headers`, `lib/http2.c`.
    #[allow(dead_code)] // consumer: protocols/http2.rs
    pub(crate) fn free(&mut self) {
        self.entries = Vec::new();
    }

    /// Record one promised field.
    ///
    /// # Errors
    ///
    /// [`CURLcode::TooLarge`] once [`MAX_PUSH_PROMISE_HEADERS`] fields have
    /// been recorded, and the set is emptied at the same time -- the C's bail
    /// at `lib/http2.c:1462-1467` calls `free_push_headers()` before failing
    /// the stream, so the fields are gone there too.
    ///
    /// The code itself is a choice rather than frozen ABI, and saying so
    /// matters: the C reaches this point inside an nghttp2 callback and
    /// answers `NGHTTP2_ERR_CALLBACK_FAILURE` after
    /// `failf(data_s, "Too many PUSH_PROMISE headers")`, so no `CURLcode`
    /// exists to copy. [`CURLcode::TooLarge`] is the closest honest reading --
    /// a count limit was exceeded, the same currency
    /// `MAX_HTTP_RESP_HEADER_COUNT` uses at `lib/headers.c:256`.
    #[allow(dead_code)] // consumer: protocols/http2.rs
    pub(crate) fn push(&mut self, name: &[u8], value: &[u8]) -> CodeResult<()> {
        // `lib/http2.c:1452-1467`. The C allocates 10 slots and doubles on
        // exhaustion, refusing to grow past 1000 allocated -- which lands on
        // 1280, as `MAX_PUSH_PROMISE_HEADERS` records. Growth itself is
        // `Vec::push`'s business; only the ceiling is observable.
        if self.entries.len() >= MAX_PUSH_PROMISE_HEADERS {
            self.entries = Vec::new();
            return Err(CURLcode::TooLarge);
        }

        // `name`, a colon and `value`, in one allocation sized from the two
        // network-supplied extents. The C's `curlx_maprintf` of the same three
        // pieces answers `NGHTTP2_ERR_CALLBACK_FAILURE` when it cannot
        // allocate; `CURLcode::OutOfMemory` is the honest `CURLcode` for it,
        // and it is a DIFFERENT condition from the count ceiling above, which
        // is why the two do not share a code.
        let needed = name
            .len()
            .checked_add(value.len())
            .and_then(|sum| sum.checked_add(1))
            .ok_or(CURLcode::OutOfMemory)?;
        let mut entry =
            fallible::vec_with_capacity(needed).map_err(fallible::oom)?;
        entry.extend_from_slice(name);
        entry.extend_from_slice(b":");
        entry.extend_from_slice(value);
        fallible::push(&mut self.entries, entry).map_err(fallible::oom)?;
        Ok(())
    }

    /// The `num`-th promised field as the whole `name:value` string.
    #[must_use]
    pub fn by_num(&self, num: usize) -> Option<&[u8]> {
        self.entries.get(num).map(Vec::as_slice)
    }

    /// The value of the first field with this name, or [`None`].
    ///
    /// # Rejected queries
    ///
    /// The C's guard, transcribed:
    ///
    /// ```c
    /// if(!h || !GOOD_EASY_HANDLE(h->data) || !name || !name[0] ||
    ///    !strcmp(name, ":") || strchr(name + 1, ':'))
    ///   return NULL;
    /// ```
    ///
    /// # Matching
    ///
    /// A prefix comparison with `strncmp` -- **byte-exact, case-sensitive**,
    /// deliberately not the ASCII fold used elsewhere in this module --
    /// followed by the requirement that the very next stored byte is the
    /// colon, so `content` does not match `content-type:...`. The first hit
    /// wins, and the returned slice begins immediately after that colon with
    /// **no blank skipping**: a promise carrying `x: y` answers ` y`, space
    /// included.
    #[must_use]
    pub fn by_name(&self, name: &[u8]) -> Option<&[u8]> {
        // Every one of the C's four tests treats `name` as a C string --
        // `strcmp`, `strchr`, `strlen`, `strncmp` -- so an embedded NUL ends
        // it. Truncating once here reproduces all four at a stroke.
        let name = match memchr(0, name) {
            Some(at) => &name[..at],
            None => name,
        };

        // `lib/http2.c:694-696`: empty, exactly a colon, or a colon anywhere
        // past the first byte.
        if name.is_empty() || name == b":" {
            return None;
        }
        if name
            .get(1..)
            .is_some_and(|rest| memchr(b':', rest).is_some())
        {
            return None;
        }

        // `lib/http2.c:700-706`.
        let len = name.len();
        for entry in &self.entries {
            if !entry.starts_with(name) {
                continue;
            }
            // `lib/http2.c:702-704`: a prefix match has to be followed by the
            // colon, or it is a match inside a longer name and the C moves on
            // to the next entry rather than giving up.
            if entry.get(len) != Some(&b':') {
                continue;
            }
            return entry.get(len + 1..);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Coverage relocated from the C's `UNITTESTS` block.

    /// `Curl_dynhds_contains`, `lib/dynhds.c:225-229`.
    fn contains(set: &HeaderSet, name: &[u8]) -> bool {
        set.get(name).is_some()
    }

    /// `Curl_dynhds_count_name`, `lib/dynhds.c:236-249`.
    fn count_name(set: &HeaderSet, name: &[u8]) -> usize {
        set.entries
            .iter()
            .filter(|entry| {
                entry.name.len() == name.len()
                    && ncasecompare(name, &entry.name, name.len())
            })
            .count()
    }

    /// `Curl_dynhds_remove`, `lib/dynhds.c:264-288`.
    fn remove(set: &mut HeaderSet, name: &[u8]) -> usize {
        let mut removed = 0usize;
        let mut freed = 0usize;
        set.entries.retain(|entry| {
            let hit = entry.name.len() == name.len()
                && ncasecompare(name, &entry.name, name.len());
            if hit {
                removed += 1;
                freed += entry.name.len() + entry.value.len();
            }
            !hit
        });
        set.strs_len = set.strs_len.saturating_sub(freed);
        removed
    }

    /// `Curl_dynhds_set`, `lib/dynhds.c:256-262`.
    ///
    /// Remove-all-then-add, so the replacement lands at the END of whatever
    /// remains -- `lib/dynhds.h:128-131`.
    fn set_header(
        set: &mut HeaderSet,
        name: &[u8],
        value: &[u8],
    ) -> CodeResult<()> {
        remove(set, name);
        set.add(name, value)
    }

    /// A store populated from `(line, origin, request)` triples.
    fn store_with(lines: &[(&[u8], u32, i32)]) -> HeaderStore {
        let mut store = HeaderStore::new();
        for (line, origin, request) in lines {
            store.push(line, *origin, *request).unwrap();
        }
        store
    }

    /// A plain `CURLH_HEADER` store on request 0, from `name: value` lines.
    fn header_store(lines: &[&[u8]]) -> HeaderStore {
        let mut store = HeaderStore::new();
        for line in lines {
            store.push(line, CURLH_HEADER, 0).unwrap();
        }
        store
    }

    // The ABI integers.

    /// `include/curl/header.h:41-45`, and the mask `lib/headers.c:70-71`
    /// builds from them.
    #[test]
    fn origin_bits_have_their_abi_values() {
        assert_eq!(CURLH_HEADER, 1);
        assert_eq!(CURLH_TRAILER, 2);
        assert_eq!(CURLH_CONNECT, 4);
        assert_eq!(CURLH_1XX, 8);
        assert_eq!(CURLH_PSEUDO, 16);
        assert_eq!(CURLH_ORIGIN_MASK, 0x1f);
        assert_eq!(CURLH_ORIGIN_MASK, 31);
    }

    /// `lib/headers.c:50`. Fixed, despite the C comment saying "randomly".
    #[test]
    fn the_reserved_bit_is_fixed_at_one_shifted_twenty_seven() {
        assert_eq!(CURLH_RESERVED_BIT, 1 << 27);
        assert_eq!(CURLH_RESERVED_BIT, 0x0800_0000);
        // It is outside the mask, so it can never collide with a real origin.
        assert_eq!(CURLH_RESERVED_BIT & CURLH_ORIGIN_MASK, 0);
    }

    /// `lib/http.h:170`, and the ceiling derived from `lib/http2.c:1463`.
    #[test]
    fn the_limits_are_the_measured_ones() {
        assert_eq!(MAX_HTTP_RESP_HEADER_COUNT, 5000);
        assert_eq!(MAX_PUSH_PROMISE_HEADERS, 1280);
        assert_eq!(DYN_HTTP_REQUEST, 1024 * 1024);
    }

    /// `lib/http.h:237-241`, colons included.
    #[test]
    fn the_five_pseudo_names_keep_their_colons() {
        assert_eq!(HTTP_PSEUDO_METHOD, b":method");
        assert_eq!(HTTP_PSEUDO_SCHEME, b":scheme");
        assert_eq!(HTTP_PSEUDO_AUTHORITY, b":authority");
        assert_eq!(HTTP_PSEUDO_PATH, b":path");
        assert_eq!(HTTP_PSEUDO_STATUS, b":status");
        assert_eq!(HTTP_PSEUDO_NAMES.len(), 5);
        for name in HTTP_PSEUDO_NAMES {
            assert_eq!(name.first(), Some(&b':'), "{name:?} must lead with :");
        }
    }

    /// `lib/sendf.h:44-48`.
    #[test]
    fn the_write_flags_have_their_c_values() {
        assert_eq!(CLIENTWRITE_HEADER, 1 << 2);
        assert_eq!(CLIENTWRITE_STATUS, 1 << 3);
        assert_eq!(CLIENTWRITE_CONNECT, 1 << 4);
        assert_eq!(CLIENTWRITE_1XX, 1 << 5);
        assert_eq!(CLIENTWRITE_TRAILER, 1 << 6);
    }

    // `classify_origin` -- `lib/headers.c:296-313`.

    #[test]
    fn a_status_line_is_never_stored() {
        assert_eq!(
            classify_origin(CLIENTWRITE_HEADER | CLIENTWRITE_STATUS),
            None
        );
        // Even with an origin-bearing flag alongside it.
        assert_eq!(
            classify_origin(
                CLIENTWRITE_HEADER | CLIENTWRITE_STATUS | CLIENTWRITE_1XX
            ),
            None
        );
    }

    #[test]
    fn a_non_header_write_is_never_stored() {
        assert_eq!(classify_origin(1 << 0), None); // BODY
        assert_eq!(classify_origin(1 << 1), None); // INFO
        assert_eq!(classify_origin(1 << 7), None); // EOS
        assert_eq!(classify_origin(0), None);
        // TRAILER without HEADER is not a header write either.
        assert_eq!(classify_origin(CLIENTWRITE_TRAILER), None);
    }

    /// The precedence chain, `lib/headers.c:301-305`: first match wins, so a
    /// bitwise union would answer differently for every combined case here.
    #[test]
    fn origin_precedence_is_connect_then_1xx_then_trailer_then_header() {
        let header = CLIENTWRITE_HEADER;
        assert_eq!(classify_origin(header), Some(CURLH_HEADER));
        assert_eq!(
            classify_origin(header | CLIENTWRITE_TRAILER),
            Some(CURLH_TRAILER)
        );
        assert_eq!(
            classify_origin(header | CLIENTWRITE_1XX | CLIENTWRITE_TRAILER),
            Some(CURLH_1XX)
        );
        assert_eq!(
            classify_origin(header | CLIENTWRITE_CONNECT | CLIENTWRITE_1XX),
            Some(CURLH_CONNECT)
        );
        // CONNECT outranks every other combination.
        assert_eq!(
            classify_origin(
                header
                    | CLIENTWRITE_CONNECT
                    | CLIENTWRITE_1XX
                    | CLIENTWRITE_TRAILER
            ),
            Some(CURLH_CONNECT)
        );
    }

    /// `classify_origin` never produces the pseudo bit; HTTP/2 and HTTP/3
    /// supply it directly (`lib/headers.c:301-305` has no such arm).
    #[test]
    fn classification_never_yields_the_pseudo_bit() {
        for flags in 0u32..512 {
            assert_ne!(classify_origin(flags), Some(CURLH_PSEUDO));
        }
    }

    // `HeaderSet` -- ordering, casing and byte transparency.

    /// The property the whole module is shaped around. Forty-eight entries
    /// crosses the C's grow-by-16 boundary three times
    /// (`lib/dynhds.c:148-165`), so a reallocation cannot quietly reorder.
    #[test]
    fn insertion_order_survives_every_reallocation() {
        let mut set = HeaderSet::new();
        let mut expected: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for index in 0..48u32 {
            let name = format!("X-Header-{index:02}").into_bytes();
            let value = format!("value-{index:02}").into_bytes();
            set.add(&name, &value).unwrap();
            expected.push((name, value));
        }
        assert_eq!(set.count(), 48);

        let seen: Vec<(Vec<u8>, Vec<u8>)> = set
            .iter()
            .map(|(name, value)| (name.to_vec(), value.to_vec()))
            .collect();
        assert_eq!(seen, expected, "iter must preserve arrival order");

        for (at, (name, value)) in expected.iter().enumerate() {
            let entry = set.getn(at).unwrap();
            assert_eq!(entry.name(), name.as_slice());
            assert_eq!(entry.value(), value.as_slice());
        }
        assert!(set.getn(48).is_none());
    }

    /// Lookup folds ASCII case; storage does not. `include/curl/header.h:32`
    /// documents the second half in the ABI itself.
    #[test]
    fn lookup_folds_case_but_storage_preserves_it() {
        let mut set = HeaderSet::new();
        set.add(b"Content-Type", b"text/Plain").unwrap();

        for query in [
            b"Content-Type".as_slice(),
            b"content-type".as_slice(),
            b"CONTENT-TYPE".as_slice(),
            b"cOnTeNt-TyPe".as_slice(),
        ] {
            let entry = set.get(query).expect("case-insensitive lookup");
            assert_eq!(entry.name(), b"Content-Type", "storage kept the case");
            assert_eq!(entry.value(), b"text/Plain");
        }

        // A different length never matches, however it is cased -- the C
        // tests `namelen == namelen` before comparing at all.
        assert!(set.get(b"Content-Typ").is_none());
        assert!(set.get(b"Content-Types").is_none());
    }

    /// No path through the module may fold a stored name. Asserted through
    /// every accessor at once, because a single one of them lowercasing would
    /// be invisible from the others.
    #[test]
    fn no_accessor_lowercases_a_stored_name() {
        let names: [&[u8]; 4] =
            [b"Content-Type", b"X-MiXeD-CaSe", b"ACCEPT", b"eTaG"];
        let mut set = HeaderSet::new();
        for name in names {
            set.add(name, b"V").unwrap();
        }

        for (at, name) in names.iter().enumerate() {
            assert_eq!(set.getn(at).unwrap().name(), *name);
            assert_eq!(set.get(name).unwrap().name(), *name);
        }
        let iterated: Vec<&[u8]> = set.iter().map(|(name, _)| name).collect();
        assert_eq!(iterated, names.to_vec());

        let mut dbuf = DynBuf::new(DYN_HTTP_REQUEST);
        set.h1_dprint(&mut dbuf).unwrap();
        assert_eq!(
            dbuf.as_slice(),
            b"Content-Type: V\r\nX-MiXeD-CaSe: V\r\nACCEPT: V\r\neTaG: V\r\n"
        );

        // And the same through the response store's outward projection.
        let store = header_store(&[b"X-MiXeD-CaSe: V\r\n"]);
        let view = store
            .header(b"x-mixed-case", 0, CURLH_HEADER, 0, 0)
            .unwrap();
        assert_eq!(view.name, b"X-MiXeD-CaSe");
    }

    /// `DYNHDS_OPT_LOWERCASE`, `lib/dynhds.c:47-48`. The NAME only, and only
    /// when asked.
    #[test]
    fn the_lowercase_option_folds_only_the_name_and_only_when_set() {
        let mut plain = HeaderSet::new();
        assert!(!plain.lowercase());
        plain.add(b"Content-Type", b"Text/PLAIN").unwrap();
        assert_eq!(plain.getn(0).unwrap().name(), b"Content-Type");
        assert_eq!(plain.getn(0).unwrap().value(), b"Text/PLAIN");

        let mut folded = HeaderSet::new();
        folded.set_opts(true);
        assert!(folded.lowercase());
        folded.add(b"Content-Type", b"Text/PLAIN").unwrap();
        assert_eq!(folded.getn(0).unwrap().name(), b"content-type");
        assert_eq!(
            folded.getn(0).unwrap().value(),
            b"Text/PLAIN",
            "the value is never folded"
        );

        // `lib/dynhds.h:80-81`: setting the option leaves existing entries
        // alone.
        let mut late = HeaderSet::new();
        late.add(b"Before-It", b"v").unwrap();
        late.set_opts(true);
        late.add(b"After-It", b"v").unwrap();
        assert_eq!(late.getn(0).unwrap().name(), b"Before-It");
        assert_eq!(late.getn(1).unwrap().name(), b"after-it");
    }

    /// Both of the C's 256-entry fold tables map every byte from 0x80 upwards
    /// to itself, so no high byte may move -- with or without the option.
    #[test]
    fn folding_leaves_every_non_ascii_byte_alone() {
        let mut name: Vec<u8> = b"X-".to_vec();
        name.extend(0x80u8..=0xff);
        let value = name.clone();

        let mut folded = HeaderSet::new();
        folded.set_opts(true);
        folded.add(&name, &value).unwrap();
        let stored = folded.getn(0).unwrap();

        // The ASCII letter folds, which is the whole of what the option does.
        assert_eq!(&stored.name()[..2], b"x-");
        // Not one byte from 0x80 upwards moved: both of the C's 256-entry
        // tables are the identity over that range.
        assert_eq!(&stored.name()[2..], &name[2..]);
        // And the value keeps even its ASCII capital, because the value is
        // never folded at all.
        assert_eq!(stored.value(), value.as_slice());

        let mut plain = HeaderSet::new();
        plain.add(&name, &value).unwrap();
        assert_eq!(plain.getn(0).unwrap().name(), name.as_slice());
    }

    /// Bytes, not text: a name and value that are not valid UTF-8 survive
    /// intact, which `String` storage could not promise.
    #[test]
    fn invalid_utf8_round_trips_unchanged() {
        let name: &[u8] = &[b'X', 0xff, 0xfe, b'Y'];
        let value: &[u8] = &[0x80, 0xc0, 0xc1];
        let mut set = HeaderSet::new();
        set.add(name, value).unwrap();
        assert_eq!(set.getn(0).unwrap().name(), name);
        assert_eq!(set.getn(0).unwrap().value(), value);
        assert_eq!(set.get(name).unwrap().value(), value);
    }

    /// `lib/dynhds.h:142-143`: no duplicate check, so nothing is coalesced,
    /// deduplicated or reordered. `get` answers with the FIRST.
    #[test]
    fn duplicate_names_are_kept_separately_and_get_returns_the_first() {
        let mut set = HeaderSet::new();
        set.add(b"Set-Cookie", b"a=1").unwrap();
        set.add(b"set-cookie", b"b=2").unwrap();
        set.add(b"SET-COOKIE", b"c=3").unwrap();

        assert_eq!(set.count(), 3, "no deduplication");
        assert_eq!(set.get(b"Set-Cookie").unwrap().value(), b"a=1");
        assert_eq!(set.getn(1).unwrap().value(), b"b=2");
        assert_eq!(set.getn(2).unwrap().value(), b"c=3");
        // Each kept the case it arrived in.
        assert_eq!(set.getn(0).unwrap().name(), b"Set-Cookie");
        assert_eq!(set.getn(1).unwrap().name(), b"set-cookie");
        assert_eq!(set.getn(2).unwrap().name(), b"SET-COOKIE");
        assert_eq!(count_name(&set, b"set-cookie"), 3);
    }

    // `HeaderSet` -- limits, `lib/dynhds.c:139-142`.

    #[test]
    fn the_entry_ceiling_reports_out_of_memory_and_zero_means_unlimited() {
        let mut bounded = HeaderSet::with_limits(2, DYN_HTTP_REQUEST);
        bounded.add(b"A", b"1").unwrap();
        bounded.add(b"B", b"2").unwrap();
        assert_eq!(
            bounded.add(b"C", b"3"),
            Err(CURLcode::OutOfMemory),
            "not TooLarge -- lib/dynhds.c:140 says OUT_OF_MEMORY"
        );
        assert_eq!(bounded.count(), 2);

        let mut unlimited = HeaderSet::with_limits(0, DYN_HTTP_REQUEST);
        for index in 0..200u32 {
            unlimited.add(format!("H{index}").as_bytes(), b"v").unwrap();
        }
        assert_eq!(unlimited.count(), 200);
    }

    /// The string ceiling is tested with a strict `>`, so a total landing
    /// exactly on it is accepted and one byte more is not.
    #[test]
    fn the_string_ceiling_admits_exactly_the_limit() {
        // "AB" + "CD" is four bytes of strings.
        let mut exact = HeaderSet::with_limits(0, 4);
        exact.add(b"AB", b"CD").unwrap();
        assert_eq!(exact.strs_len, 4);
        assert_eq!(exact.count(), 1);
        // Nothing further fits, not even a single byte.
        assert_eq!(exact.add(b"E", b""), Err(CURLcode::OutOfMemory));
        // A zero-length pair adds nothing, so it still fits: the test is
        // `strs_len + 0 > max`, which is false at the boundary.
        exact.add(b"", b"").unwrap();
        assert_eq!(exact.count(), 2);

        let mut over = HeaderSet::with_limits(0, 3);
        assert_eq!(over.add(b"AB", b"CD"), Err(CURLcode::OutOfMemory));
        assert_eq!(over.count(), 0);
        assert_eq!(over.strs_len, 0);
    }

    #[test]
    fn reset_keeps_the_allocation_and_the_limits_while_free_releases_it() {
        let mut set = HeaderSet::with_limits(64, 4096);
        set.set_opts(true);
        for index in 0..20u32 {
            set.add(format!("H{index}").as_bytes(), b"value").unwrap();
        }
        assert!(set.strs_len > 0);
        let capacity = set.entries.capacity();
        assert!(capacity >= 20);

        set.reset();
        assert_eq!(set.count(), 0);
        assert!(set.is_empty());
        assert_eq!(set.strs_len, 0);
        assert_eq!(set.entries.capacity(), capacity, "reset keeps capacity");
        assert_eq!(set.max_entries, 64, "reset keeps the limits");
        assert_eq!(set.max_strs_size, 4096);
        assert!(set.lowercase(), "reset keeps the options");
        // Reusable afterwards.
        set.add(b"Fresh", b"v").unwrap();
        assert_eq!(set.count(), 1);

        set.free();
        assert_eq!(set.count(), 0);
        assert_eq!(set.strs_len, 0);
        assert_eq!(set.entries.capacity(), 0, "free releases the allocation");
        assert_eq!(set.max_entries, 64, "free keeps the limits");
        assert!(set.lowercase(), "free keeps the options");
    }

    #[test]
    fn the_default_set_uses_the_measured_call_site_limits() {
        let set = HeaderSet::default();
        assert_eq!(set.max_entries, 0, "unlimited, as all 8 call sites pass");
        assert_eq!(set.max_strs_size, DYN_HTTP_REQUEST);
        assert!(!set.lowercase());
        assert!(set.is_empty());
    }

    // `HeaderSet::h1_add_line` -- `lib/dynhds.c:183-215`.

    #[test]
    fn an_empty_h1_line_is_a_silent_success() {
        let mut set = HeaderSet::new();
        assert_eq!(set.h1_add_line(b""), Ok(()));
        assert_eq!(set.count(), 0, "nothing stored, and no error");
    }

    #[test]
    fn an_h1_line_without_a_colon_is_a_bad_argument() {
        let mut set = HeaderSet::new();
        assert_eq!(
            set.h1_add_line(b"no colon here\r\n"),
            Err(CURLcode::BadFunctionArgument)
        );
        assert_eq!(set.count(), 0);
    }

    #[test]
    fn an_h1_line_splits_at_the_first_colon_and_skips_blanks() {
        let mut set = HeaderSet::new();
        set.h1_add_line(b"Host: example.com\r\n").unwrap();
        set.h1_add_line(b"X:\t \tspaced\r\n").unwrap();
        set.h1_add_line(b"Accept:no-blank\r\n").unwrap();
        // A colon in the value is not a second separator.
        set.h1_add_line(b"X-Time: 10:30:00\r\n").unwrap();

        assert_eq!(set.getn(0).unwrap().name(), b"Host");
        assert_eq!(set.getn(0).unwrap().value(), b"example.com");
        assert_eq!(set.getn(1).unwrap().name(), b"X");
        assert_eq!(set.getn(1).unwrap().value(), b"spaced");
        assert_eq!(set.getn(2).unwrap().value(), b"no-blank");
        assert_eq!(set.getn(3).unwrap().value(), b"10:30:00");
    }

    /// `lib/dynhds.c:208-212`: the carriage return is looked for first, and
    /// the newline only when there is no carriage return at all.
    #[test]
    fn an_h1_value_is_cut_at_the_first_cr_else_the_first_lf() {
        let mut set = HeaderSet::new();
        set.h1_add_line(b"A: one\r\ntrailing junk").unwrap();
        assert_eq!(set.getn(0).unwrap().value(), b"one");

        set.h1_add_line(b"B: two\nmore junk").unwrap();
        assert_eq!(set.getn(1).unwrap().value(), b"two");

        // A newline BEFORE the carriage return: the C still cuts at the CR,
        // because it only reaches the LF search when no CR exists.
        set.h1_add_line(b"C: three\nfour\rfive").unwrap();
        assert_eq!(set.getn(2).unwrap().value(), b"three\nfour");

        // No terminator at all is fine here -- unlike `HeaderStore::push`.
        set.h1_add_line(b"D: bare").unwrap();
        assert_eq!(set.getn(3).unwrap().value(), b"bare");
    }

    #[test]
    fn an_h1_line_of_only_a_colon_stores_a_zero_length_name() {
        let mut set = HeaderSet::new();
        set.h1_add_line(b":status: 200\r\n").unwrap();
        assert_eq!(
            set.getn(0).unwrap().name(),
            b"",
            "the first colon is the separator on this path"
        );
        assert_eq!(set.getn(0).unwrap().value(), b"status: 200");
        assert_eq!(set.strs_len, b"status: 200".len());
    }

    #[test]
    fn an_h1_line_with_an_all_blank_value_stores_an_empty_value() {
        let mut set = HeaderSet::new();
        set.h1_add_line(b"A:   \r\n").unwrap();
        assert_eq!(set.getn(0).unwrap().name(), b"A");
        assert_eq!(set.getn(0).unwrap().value(), b"");
        // And with no terminator either.
        set.h1_add_line(b"B:").unwrap();
        assert_eq!(set.getn(1).unwrap().value(), b"");
    }

    /// The forward scan here is `memchr`, which does NOT stop at a NUL --
    /// deliberately unlike `namevalue`'s C-string walk.
    #[test]
    fn an_h1_line_finds_a_colon_after_an_embedded_nul() {
        let mut set = HeaderSet::new();
        set.h1_add_line(b"A\0B: v\r\n").unwrap();
        assert_eq!(set.getn(0).unwrap().name(), b"A\0B");
        assert_eq!(set.getn(0).unwrap().value(), b"v");
    }

    // `HeaderSet::h1_dprint` -- `lib/dynhds.c:297-315`.

    #[test]
    fn printing_an_empty_set_writes_nothing_and_succeeds() {
        let set = HeaderSet::new();
        let mut dbuf = DynBuf::new(DYN_HTTP_REQUEST);
        assert_eq!(set.h1_dprint(&mut dbuf), Ok(()));
        assert!(dbuf.as_slice().is_empty());
    }

    /// Byte-compared against a hand-written literal, because these are the
    /// bytes 1,476 fixtures compare: one space after the colon, CRLF endings,
    /// arrival order, and NO final blank line.
    #[test]
    fn printing_emits_the_wire_form_with_no_final_blank_line() {
        let mut set = HeaderSet::new();
        set.add(b"Host", b"example.com").unwrap();
        set.add(b"User-Agent", b"curl/8.19.0-DEV").unwrap();
        set.add(b"Accept", b"*/*").unwrap();

        let mut dbuf = DynBuf::new(DYN_HTTP_REQUEST);
        set.h1_dprint(&mut dbuf).unwrap();
        assert_eq!(
            dbuf.as_slice(),
            b"Host: example.com\r\n\
              User-Agent: curl/8.19.0-DEV\r\n\
              Accept: */*\r\n"
        );
        // The caller supplies the blank line that ends the block.
        assert!(!dbuf.as_slice().ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn printing_an_empty_name_or_value_still_emits_the_separator() {
        let mut set = HeaderSet::new();
        set.add(b"Empty", b"").unwrap();
        set.add(b"", b"orphan").unwrap();
        let mut dbuf = DynBuf::new(DYN_HTTP_REQUEST);
        set.h1_dprint(&mut dbuf).unwrap();
        assert_eq!(dbuf.as_slice(), b"Empty: \r\n: orphan\r\n");
    }

    /// Emission stops at the FIRST failure. Provable because the buffer
    /// empties itself on overflow: had the loop gone on, the short third
    /// line would have fitted and been visible.
    #[test]
    fn printing_stops_at_the_first_buffer_failure() {
        let mut set = HeaderSet::new();
        set.add(b"A", b"1").unwrap();
        set.add(b"B", &[b'x'; 200]).unwrap();
        set.add(b"C", b"3").unwrap();

        let mut dbuf = DynBuf::new(64);
        assert_eq!(set.h1_dprint(&mut dbuf), Err(CURLcode::TooLarge));
        assert!(
            dbuf.as_slice().is_empty(),
            "the third line must not have been attempted"
        );
    }

    // The relocated `UNITTESTS` helpers.

    #[test]
    fn contains_and_count_name_fold_case() {
        let mut set = HeaderSet::new();
        set.add(b"Accept", b"a").unwrap();
        set.add(b"ACCEPT", b"b").unwrap();
        set.add(b"Host", b"h").unwrap();

        assert!(contains(&set, b"accept"));
        assert!(contains(&set, b"HOST"));
        assert!(!contains(&set, b"Missing"));
        assert_eq!(count_name(&set, b"AcCePt"), 2);
        assert_eq!(count_name(&set, b"host"), 1);
        assert_eq!(count_name(&set, b"nope"), 0);
    }

    /// `lib/dynhds.c:264-288`. Every match goes, including adjacent ones --
    /// which is exactly what the C's `--i` re-examination protects.
    #[test]
    fn remove_takes_every_match_and_corrects_the_string_total() {
        let mut set = HeaderSet::new();
        set.add(b"Dup", b"1").unwrap();
        set.add(b"DUP", b"2").unwrap();
        set.add(b"Keep", b"k").unwrap();
        set.add(b"dup", b"3").unwrap();
        let before = set.strs_len;

        assert_eq!(remove(&mut set, b"dup"), 3);
        assert_eq!(set.count(), 1);
        assert_eq!(set.getn(0).unwrap().name(), b"Keep");
        // Three names of 3 bytes and three values of 1 byte have gone.
        assert_eq!(set.strs_len, before - (3 * 3 + 3));
        assert_eq!(set.strs_len, b"Keep".len() + b"k".len());
        assert_eq!(remove(&mut set, b"absent"), 0);
        assert_eq!(set.count(), 1);
    }

    /// `lib/dynhds.h:128-131`: the replacement lands at the END of what
    /// remains, not in the removed entry's position.
    #[test]
    fn set_replaces_every_match_and_appends_at_the_end() {
        let mut set = HeaderSet::new();
        set.add(b"A", b"1").unwrap();
        set.add(b"B", b"2").unwrap();
        set.add(b"a", b"3").unwrap();

        set_header(&mut set, b"A", b"final").unwrap();
        assert_eq!(set.count(), 2);
        assert_eq!(set.getn(0).unwrap().name(), b"B");
        assert_eq!(set.getn(1).unwrap().name(), b"A");
        assert_eq!(set.getn(1).unwrap().value(), b"final");
    }

    // `HeaderStore::push` -- `lib/headers.c:221-281`.

    /// `lib/headers.c:231-233`: a silent success, and checked before any
    /// trimming.
    #[test]
    fn the_body_separator_is_a_silent_success() {
        let mut store = HeaderStore::new();
        for separator in [b"\r\n".as_slice(), b"\n", b"\r", b"\r\n\r\n"] {
            assert_eq!(store.push(separator, CURLH_HEADER, 0), Ok(()));
        }
        assert!(store.is_empty(), "nothing stored, and no error");
    }

    /// `lib/headers.c:240-242`: nothing trimmed means neither terminator was
    /// present, which is not a valid header.
    #[test]
    fn a_line_with_no_terminator_is_a_weird_server_reply() {
        let mut store = HeaderStore::new();
        assert_eq!(
            store.push(b"A: b", CURLH_HEADER, 0),
            Err(CURLcode::WeirdServerReply)
        );
        assert!(store.is_empty());
        // An empty line has nothing to trim either, so it lands here too
        // rather than reading out of bounds as the C's `header[0]` would.
        assert_eq!(
            store.push(b"", CURLH_HEADER, 0),
            Err(CURLcode::WeirdServerReply)
        );
    }

    #[test]
    fn both_crlf_and_bare_lf_terminate_a_header() {
        let mut store = HeaderStore::new();
        store.push(b"A: b\r\n", CURLH_HEADER, 0).unwrap();
        store.push(b"A: b\n", CURLH_HEADER, 0).unwrap();
        assert_eq!(store.count(), 2);
        for stored in store.as_slice() {
            assert_eq!(stored.name(), b"A");
            assert_eq!(stored.value(), b"b", "the terminator is not stored");
        }
    }

    /// `lib/headers.c:244-252`: the folded-continuation case.
    #[test]
    fn a_folded_continuation_line_loses_its_leading_blanks() {
        let mut store = HeaderStore::new();
        store
            .push(b"   Name: continued\r\n", CURLH_HEADER, 0)
            .unwrap();
        store.push(b"\t\tTab: value\r\n", CURLH_HEADER, 0).unwrap();
        assert_eq!(store.as_slice()[0].name(), b"Name");
        assert_eq!(store.as_slice()[0].value(), b"continued");
        assert_eq!(store.as_slice()[1].name(), b"Tab");
    }

    #[test]
    fn an_all_blank_line_is_a_weird_server_reply() {
        let mut store = HeaderStore::new();
        assert_eq!(
            store.push(b"   \r\n", CURLH_HEADER, 0),
            Err(CURLcode::WeirdServerReply)
        );
        assert_eq!(
            store.push(b" \t \n", CURLH_HEADER, 0),
            Err(CURLcode::WeirdServerReply)
        );
        assert!(store.is_empty());
    }

    #[test]
    fn a_line_without_a_colon_is_a_bad_argument() {
        let mut store = HeaderStore::new();
        assert_eq!(
            store.push(b"no colon here\r\n", CURLH_HEADER, 0),
            Err(CURLcode::BadFunctionArgument)
        );
        assert!(store.is_empty());
        // A NUL before the colon ends the C-string walk, so the colon after
        // it is never reached -- deliberately unlike `h1_add_line`.
        assert_eq!(
            store.push(b"A\0B: v\r\n", CURLH_HEADER, 0),
            Err(CURLcode::BadFunctionArgument)
        );
        assert!(store.is_empty());
    }

    /// `lib/headers.c:253-257`. The count limit is `>=`, so the 5000th push
    /// is the last one to succeed. Note the currency: `CURLE_TOO_LARGE`,
    /// where `HeaderSet`'s limits answer `CURLE_OUT_OF_MEMORY`.
    #[test]
    fn the_five_thousandth_header_fits_and_the_next_does_not() {
        let mut store = HeaderStore::new();
        for _ in 0..MAX_HTTP_RESP_HEADER_COUNT {
            store.push(b"A: v\r\n", CURLH_HEADER, 0).unwrap();
        }
        assert_eq!(store.count(), MAX_HTTP_RESP_HEADER_COUNT);
        assert_eq!(
            store.push(b"A: v\r\n", CURLH_HEADER, 0),
            Err(CURLcode::TooLarge)
        );
        assert_eq!(store.count(), MAX_HTTP_RESP_HEADER_COUNT);
    }

    /// `lib/headers.c:186-192`. The name pointer is assigned before the
    /// colon is stepped over, so the colon stays in the stored name.
    #[test]
    fn a_pseudo_header_keeps_its_leading_colon() {
        let mut store = HeaderStore::new();
        store.push(b":status: 200\r\n", CURLH_PSEUDO, 0).unwrap();
        store
            .push(b":path: /index.html\r\n", CURLH_PSEUDO, 0)
            .unwrap();

        assert_eq!(store.as_slice()[0].name(), HTTP_PSEUDO_STATUS);
        assert_eq!(store.as_slice()[0].value(), b"200");
        assert_eq!(store.as_slice()[1].name(), HTTP_PSEUDO_PATH);
        assert_eq!(store.as_slice()[1].value(), b"/index.html");

        let view = store.header(b":status", 0, CURLH_PSEUDO, 0, 0).unwrap();
        assert_eq!(view.name, b":status");
        assert_eq!(view.value, b"200");
    }

    #[test]
    fn a_pseudo_header_must_begin_with_a_colon() {
        let mut store = HeaderStore::new();
        assert_eq!(
            store.push(b"status: 200\r\n", CURLH_PSEUDO, 0),
            Err(CURLcode::BadFunctionArgument)
        );
        assert!(store.is_empty());
    }

    /// The pseudo test is EXACT equality against the bit
    /// (`lib/headers.c:188`), so a combined mask does not take that path --
    /// and then the leading colon becomes the separator instead.
    #[test]
    fn a_combined_mask_does_not_take_the_pseudo_path() {
        let mut store = HeaderStore::new();
        store
            .push(b":status: 200\r\n", CURLH_PSEUDO | CURLH_HEADER, 0)
            .unwrap();
        assert_eq!(
            store.as_slice()[0].name(),
            b"",
            "the leading colon was read as the separator"
        );
        assert_eq!(store.as_slice()[0].value(), b"status: 200");
    }

    /// `lib/headers.c:204-212`: blanks after the colon are dropped, then
    /// trailing blanks are trimmed.
    #[test]
    fn blanks_around_a_value_are_removed() {
        let mut store = HeaderStore::new();
        store.push(b"A:  b  \r\n", CURLH_HEADER, 0).unwrap();
        store.push(b"B: \t x \t \r\n", CURLH_HEADER, 0).unwrap();
        store.push(b"C:no-blanks\r\n", CURLH_HEADER, 0).unwrap();
        store.push(b"D:    \r\n", CURLH_HEADER, 0).unwrap();

        assert_eq!(store.as_slice()[0].value(), b"b");
        assert_eq!(store.as_slice()[1].value(), b"x");
        assert_eq!(store.as_slice()[2].value(), b"no-blanks");
        // Every byte after the colon was blank, so the LEADING skip consumed
        // them all and the value is empty. The trailing trim never ran.
        assert_eq!(store.as_slice()[3].value(), b"");
        assert_eq!(store.as_slice()[3].name(), b"D");
    }

    /// The C trims while `end > header`, STRICTLY greater
    /// (`lib/headers.c:211`), which is reproduced exactly. This records why
    /// that bound is never the binding test: the leading-blank skip directly
    /// above it leaves the value starting on a NON-blank byte, so on a
    /// one-byte value the ISBLANK test fails first. The two forms therefore
    /// agree on every reachable input, and the invariant that matters -- a
    /// non-empty value is never trimmed away to nothing -- holds either way.
    #[test]
    fn trimming_never_empties_a_non_empty_value() {
        for line in [
            b"A: x \r\n".as_slice(),
            b"A: x\t\r\n",
            b"A: x    \r\n",
            b"A:  \t x \t \r\n",
        ] {
            let mut store = HeaderStore::new();
            store.push(line, CURLH_HEADER, 0).unwrap();
            assert_eq!(
                store.as_slice()[0].value(),
                b"x",
                "line {line:?} lost its value"
            );
        }
    }

    #[test]
    fn a_value_may_contain_colons_and_the_first_one_separates() {
        let mut store = HeaderStore::new();
        store
            .push(b"X-Time: 10:30:00\r\n", CURLH_HEADER, 0)
            .unwrap();
        assert_eq!(store.as_slice()[0].name(), b"X-Time");
        assert_eq!(store.as_slice()[0].value(), b"10:30:00");
    }

    // `HeaderStore::header` -- `lib/headers.c:55-118`.

    /// `lib/headers.c:69-72`, and the order matters: validation precedes the
    /// empty-store test, so a bad argument beats `CURLHE_NOHEADERS`.
    #[test]
    fn bad_arguments_are_rejected_before_anything_else() {
        let empty = HeaderStore::new();
        let store = header_store(&[b"A: 1\r\n"]);

        for subject in [&empty, &store] {
            // origin == 0
            assert_eq!(
                subject.header(b"A", 0, 0, 0, 0),
                Err(CURLHcode::BadArgument)
            );
            // a bit outside the mask
            assert_eq!(
                subject.header(b"A", 0, CURLH_ORIGIN_MASK + 1, 0, 0),
                Err(CURLHcode::BadArgument)
            );
            assert_eq!(
                subject.header(b"A", 0, CURLH_RESERVED_BIT, 0, 0),
                Err(CURLHcode::BadArgument)
            );
            // request below -1
            assert_eq!(
                subject.header(b"A", 0, CURLH_HEADER, -2, 0),
                Err(CURLHcode::BadArgument)
            );
            assert_eq!(
                subject.header(b"A", 0, CURLH_HEADER, i32::MIN, 0),
                Err(CURLHcode::BadArgument)
            );
        }
        // The whole mask is valid, and so is -1.
        assert!(store.header(b"A", 0, CURLH_ORIGIN_MASK, -1, 0).is_ok());
    }

    #[test]
    fn an_empty_store_reports_no_headers() {
        let store = HeaderStore::new();
        assert_eq!(
            store.header(b"A", 0, CURLH_HEADER, 0, 0),
            Err(CURLHcode::Noheaders)
        );
    }

    #[test]
    fn an_absent_name_is_missing_and_a_high_index_is_a_bad_index() {
        let store = header_store(&[b"A: 1\r\n", b"B: 2\r\n"]);
        assert_eq!(
            store.header(b"Nope", 0, CURLH_HEADER, 0, 0),
            Err(CURLHcode::Missing)
        );
        assert_eq!(
            store.header(b"A", 1, CURLH_HEADER, 0, 0),
            Err(CURLHcode::Badindex)
        );
        assert_eq!(
            store.header(b"A", usize::MAX, CURLH_HEADER, 0, 0),
            Err(CURLHcode::Badindex)
        );
        // An origin sharing no bit with the stored one is Missing, not
        // BadIndex: nothing matched at all.
        assert_eq!(
            store.header(b"A", 0, CURLH_TRAILER, 0, 0),
            Err(CURLHcode::Missing)
        );
    }

    /// `lib/headers.c:75-78`. The comparison happens BEFORE `-1` is
    /// substituted, which is why -1 never trips it.
    #[test]
    fn a_request_beyond_the_current_one_has_no_headers_of_its_own() {
        let store = header_store(&[b"A: 1\r\n"]);
        assert_eq!(
            store.header(b"A", 0, CURLH_HEADER, 1, 0),
            Err(CURLHcode::Norequest)
        );
        assert_eq!(
            store.header(b"A", 0, CURLH_HEADER, 9, 3),
            Err(CURLHcode::Norequest)
        );
        assert!(store.header(b"A", 0, CURLH_HEADER, -1, 7).is_err());
    }

    #[test]
    fn minus_one_means_the_current_request() {
        let store = store_with(&[
            (b"A: first\r\n", CURLH_HEADER, 0),
            (b"A: second\r\n", CURLH_HEADER, 1),
        ]);

        let current = store.header(b"A", 0, CURLH_HEADER, -1, 1).unwrap();
        assert_eq!(current.value, b"second");
        assert_eq!(current.amount, 1, "only request 1's header counts");

        let explicit = store.header(b"A", 0, CURLH_HEADER, 1, 1).unwrap();
        assert_eq!(explicit.value, b"second");

        let earlier = store.header(b"A", 0, CURLH_HEADER, 0, 1).unwrap();
        assert_eq!(earlier.value, b"first");
        assert_eq!(earlier.amount, 1);
    }

    /// Repeated names: `amount` is the total and `index` walks them in
    /// arrival order.
    #[test]
    fn repeated_names_are_indexed_in_arrival_order() {
        let store = header_store(&[
            b"Set-Cookie: a=1\r\n",
            b"Other: x\r\n",
            b"set-cookie: b=2\r\n",
            b"SET-COOKIE: c=3\r\n",
        ]);

        for (index, expected) in
            [(0usize, b"a=1".as_slice()), (1, b"b=2"), (2, b"c=3")]
        {
            let view = store
                .header(b"Set-Cookie", index, CURLH_HEADER, 0, 0)
                .unwrap();
            assert_eq!(view.amount, 3, "no coalescing");
            assert_eq!(view.index, index);
            assert_eq!(view.value, expected);
        }
        assert_eq!(
            store.header(b"Set-Cookie", 3, CURLH_HEADER, 0, 0),
            Err(CURLHcode::Badindex)
        );
    }

    /// `lib/headers.c:84`: the origin test is a bitwise AND, so any shared
    /// bit matches and a mask can select several origins at once.
    #[test]
    fn an_origin_mask_matches_on_any_shared_bit() {
        let store = store_with(&[
            (b"A: header\r\n", CURLH_HEADER, 0),
            (b"A: trailer\r\n", CURLH_TRAILER, 0),
            (b"A: connect\r\n", CURLH_CONNECT, 0),
            (b"A: informational\r\n", CURLH_1XX, 0),
        ]);

        for (origin, expected) in [
            (CURLH_HEADER, b"header".as_slice()),
            (CURLH_TRAILER, b"trailer"),
            (CURLH_CONNECT, b"connect"),
            (CURLH_1XX, b"informational"),
        ] {
            let view = store.header(b"A", 0, origin, 0, 0).unwrap();
            assert_eq!(view.amount, 1);
            assert_eq!(view.value, expected);
        }

        // Two bits select two headers, in arrival order.
        let pair = CURLH_HEADER | CURLH_CONNECT;
        let first = store.header(b"A", 0, pair, 0, 0).unwrap();
        assert_eq!(first.amount, 2);
        assert_eq!(first.value, b"header");
        let second = store.header(b"A", 1, pair, 0, 0).unwrap();
        assert_eq!(second.value, b"connect");

        // The whole mask selects all four.
        let all = store.header(b"A", 0, CURLH_ORIGIN_MASK, 0, 0).unwrap();
        assert_eq!(all.amount, 4);

        // A mask sharing no bit with any stored origin matches nothing.
        assert_eq!(
            store.header(b"A", 0, CURLH_PSEUDO, 0, 0),
            Err(CURLHcode::Missing)
        );
    }

    /// A pseudo-header stays out of an ordinary consumer's view, which falls
    /// out of honouring the mask rather than needing a special case.
    #[test]
    fn a_pseudo_header_is_hidden_from_a_mask_that_omits_it() {
        let store = store_with(&[
            (b":status: 200\r\n", CURLH_PSEUDO, 0),
            (b"Server: nginx\r\n", CURLH_HEADER, 0),
        ]);

        assert_eq!(
            store.header(b":status", 0, CURLH_HEADER, 0, 0),
            Err(CURLHcode::Missing)
        );
        assert!(store.header(b":status", 0, CURLH_PSEUDO, 0, 0).is_ok());

        // Iteration over plain headers never yields it either.
        let mut names = Vec::new();
        let mut cursor = None;
        while let Some(view) = store.next_header(CURLH_HEADER, 0, 0, cursor) {
            names.push(view.name.to_vec());
            cursor = Some(view.anchor);
        }
        assert_eq!(names, vec![b"Server".to_vec()]);
    }

    /// `lib/headers.c:50`, through the projection: `==` must fail while `&`
    /// succeeds. That is the entire purpose of the reserved bit.
    #[test]
    fn the_projection_ors_in_the_reserved_bit() {
        let store = store_with(&[
            (b"A: 1\r\n", CURLH_HEADER, 0),
            (b"B: 2\r\n", CURLH_TRAILER, 0),
        ]);

        for (name, stored) in
            [(b"A".as_slice(), CURLH_HEADER), (b"B", CURLH_TRAILER)]
        {
            let view = store.header(name, 0, stored, 0, 0).unwrap();
            assert_eq!(view.origin, stored | CURLH_RESERVED_BIT);
            assert_ne!(view.origin, stored, "== comparisons must fail");
            assert_ne!(view.origin & stored, 0, "& comparisons must succeed");
        }

        // Never stored, only projected.
        assert_eq!(store.as_slice()[0].origin(), CURLH_HEADER);
        assert_eq!(store.as_slice()[1].origin(), CURLH_TRAILER);

        // And identically through the iterating entry point.
        let view = store.next_header(CURLH_HEADER, 0, 0, None).unwrap();
        assert_eq!(view.origin, CURLH_HEADER | CURLH_RESERVED_BIT);
    }

    // `HeaderStore::next_header` and the cursor -- `lib/headers.c:121-179`.

    #[test]
    fn iteration_visits_every_match_exactly_once_in_order() {
        let store = header_store(&[b"A: 1\r\n", b"B: 2\r\n", b"a: 3\r\n"]);

        let mut seen: Vec<(Vec<u8>, Vec<u8>, usize, usize)> = Vec::new();
        let mut cursor = None;
        while let Some(view) = store.next_header(CURLH_HEADER, 0, 0, cursor) {
            seen.push((
                view.name.to_vec(),
                view.value.to_vec(),
                view.index,
                view.amount,
            ));
            cursor = Some(view.anchor);
        }

        assert_eq!(seen.len(), 3, "each header once, then the end");
        // `amount` and `index` are computed over the WHOLE store, so the two
        // `A` headers see amount 2 and indices 0 and 1 -- counted across
        // namesakes both before and after each one.
        assert_eq!(seen[0], (b"A".to_vec(), b"1".to_vec(), 0, 2));
        assert_eq!(seen[1], (b"B".to_vec(), b"2".to_vec(), 0, 1));
        assert_eq!(seen[2], (b"a".to_vec(), b"3".to_vec(), 1, 2));
    }

    #[test]
    fn iteration_over_an_empty_store_ends_immediately() {
        let store = HeaderStore::new();
        assert!(store.next_header(CURLH_HEADER, 0, 0, None).is_none());
        assert!(store.next_header(CURLH_ORIGIN_MASK, -1, 0, None).is_none());
    }

    /// `lib/headers.c:121-136` has no argument validation whatsoever, so
    /// every rejection is a plain `None` and an out-of-range origin is simply
    /// something nothing matches.
    #[test]
    fn iteration_validates_nothing_and_only_ever_answers_none() {
        let store = header_store(&[b"A: 1\r\n"]);
        // origin 0 matches nothing -- and is NOT a bad argument here, though
        // it is one for `header`.
        assert!(store.next_header(0, 0, 0, None).is_none());
        // Bits outside the mask are ignored rather than rejected.
        assert!(store.next_header(CURLH_RESERVED_BIT, 0, 0, None).is_none());
        assert!(store
            .next_header(CURLH_RESERVED_BIT | CURLH_HEADER, 0, 0, None)
            .is_some());
        // A request beyond the current one ends iteration.
        assert!(store.next_header(CURLH_HEADER, 1, 0, None).is_none());
        // A negative request below -1 is not special-cased; it simply matches
        // no stored request number.
        assert!(store.next_header(CURLH_HEADER, -2, 0, None).is_none());
    }

    #[test]
    fn iteration_respects_the_request_number() {
        let store = store_with(&[
            (b"A: zero\r\n", CURLH_HEADER, 0),
            (b"A: one\r\n", CURLH_HEADER, 1),
        ]);

        let latest = store.next_header(CURLH_HEADER, -1, 1, None).unwrap();
        assert_eq!(latest.value, b"one");
        assert!(store
            .next_header(CURLH_HEADER, -1, 1, Some(latest.anchor))
            .is_none());

        let earlier = store.next_header(CURLH_HEADER, 0, 1, None).unwrap();
        assert_eq!(earlier.value, b"zero");
    }

    /// The generational check. Each mutation invalidates every outstanding
    /// cursor, so a resumed walk ends rather than reading a shifted element.
    #[test]
    fn a_cursor_from_before_a_mutation_is_detectably_stale() {
        let mut store = header_store(&[b"A: 1\r\n", b"B: 2\r\n"]);
        let anchor =
            store.next_header(CURLH_HEADER, 0, 0, None).unwrap().anchor;
        // Same generation: iteration resumes normally.
        assert_eq!(
            store
                .next_header(CURLH_HEADER, 0, 0, Some(anchor))
                .unwrap()
                .name,
            b"B"
        );

        store.push(b"C: 3\r\n", CURLH_HEADER, 0).unwrap();
        assert!(
            store
                .next_header(CURLH_HEADER, 0, 0, Some(anchor))
                .is_none(),
            "a push must invalidate the cursor"
        );

        let anchor =
            store.next_header(CURLH_HEADER, 0, 0, None).unwrap().anchor;
        store.reset();
        assert!(
            store
                .next_header(CURLH_HEADER, 0, 0, Some(anchor))
                .is_none(),
            "a reset must invalidate the cursor"
        );

        let mut store = header_store(&[b"A: 1\r\n", b"B: 2\r\n"]);
        let anchor =
            store.next_header(CURLH_HEADER, 0, 0, None).unwrap().anchor;
        store.cleanup();
        assert!(
            store
                .next_header(CURLH_HEADER, 0, 0, Some(anchor))
                .is_none(),
            "a cleanup must invalidate the cursor"
        );
    }

    /// A cursor the store never issued -- a null `void *anchor` most of all
    /// -- ends iteration instead of being trusted.
    #[test]
    fn a_cursor_the_store_never_issued_ends_iteration() {
        let store = header_store(&[b"A: 1\r\n", b"B: 2\r\n"]);

        // Null: generation 0, which no live store ever has.
        let null = HeaderCursor::from_raw(0);
        assert_eq!(null.generation(), 0);
        assert!(store.next_header(CURLH_HEADER, 0, 0, Some(null)).is_none());

        // Right generation, absurd index: the scan starts past the end.
        let current =
            store.next_header(CURLH_HEADER, 0, 0, None).unwrap().anchor;
        let far = HeaderCursor {
            index: u32::MAX,
            generation: current.generation(),
        };
        assert!(store.next_header(CURLH_HEADER, 0, 0, Some(far)).is_none());
    }

    #[test]
    fn a_cursor_round_trips_through_its_raw_form_losslessly() {
        for (index, generation) in
            [(0u32, 1u32), (7, 3), (4999, 1), (u32::MAX, u32::MAX)]
        {
            let cursor = HeaderCursor { index, generation };
            let raw = cursor.to_raw();
            assert_eq!(HeaderCursor::from_raw(raw), cursor);
            assert_eq!(cursor.index(), index as usize);
            assert_eq!(cursor.generation(), generation);
        }

        // Every raw value decodes and re-encodes to itself, so the ABI can
        // carry an application's `anchor` back unchanged.
        for raw in [0usize, 1, 0x1_0000_0000, usize::MAX, 12345] {
            assert_eq!(HeaderCursor::from_raw(raw).to_raw(), raw);
        }

        // A cursor a store issued is never the null encoding.
        let store = header_store(&[b"A: 1\r\n"]);
        let issued = store.next_header(CURLH_HEADER, 0, 0, None).unwrap();
        assert_ne!(issued.anchor.to_raw(), 0);
    }

    /// The two public entry points fill `headerout[0]` and `headerout[1]`
    /// respectively (`lib/urldata.h:1032`), so interleaving them must not let
    /// either disturb the other's result. Here that shows up as two views
    /// coexisting with independent contents.
    #[test]
    fn lookup_and_iteration_do_not_disturb_each_other() {
        let store = header_store(&[b"A: 1\r\n", b"B: 2\r\n", b"A: 3\r\n"]);

        let first = store.next_header(CURLH_HEADER, 0, 0, None).unwrap();
        let looked_up = store.header(b"A", 1, CURLH_HEADER, 0, 0).unwrap();
        let second = store
            .next_header(CURLH_HEADER, 0, 0, Some(first.anchor))
            .unwrap();

        assert_eq!(
            (first.name, first.value),
            (b"A".as_slice(), b"1".as_slice())
        );
        assert_eq!(looked_up.value, b"3");
        assert_eq!(looked_up.index, 1);
        assert_eq!(
            (second.name, second.value),
            (b"B".as_slice(), b"2".as_slice())
        );
        // The lookup between the two iteration steps changed neither of them.
        assert_eq!(first.index, 0);
        assert_eq!(first.amount, 2);
    }

    #[test]
    fn reset_and_cleanup_empty_the_store() {
        let mut store = header_store(&[b"A: 1\r\n", b"B: 2\r\n"]);
        assert_eq!(store.prevhead().unwrap().name(), b"B");

        store.reset();
        assert!(store.is_empty());
        assert_eq!(store.count(), 0);
        assert!(store.prevhead().is_none());
        assert_eq!(
            store.header(b"A", 0, CURLH_HEADER, 0, 0),
            Err(CURLHcode::Noheaders)
        );
        // Reusable afterwards.
        store.push(b"C: 3\r\n", CURLH_HEADER, 0).unwrap();
        assert_eq!(store.count(), 1);

        store.cleanup();
        assert!(store.is_empty());
        assert!(store.as_slice().is_empty());
    }

    #[test]
    fn the_generation_advances_on_every_mutation_and_never_reaches_zero() {
        let mut store = HeaderStore::new();
        assert_eq!(store.generation, HeaderStore::FIRST_GENERATION);
        assert_ne!(store.generation, 0);

        store.push(b"A: 1\r\n", CURLH_HEADER, 0).unwrap();
        let after_push = store.generation;
        assert_ne!(after_push, HeaderStore::FIRST_GENERATION);

        store.reset();
        assert_ne!(store.generation, after_push);
        let after_reset = store.generation;
        store.cleanup();
        assert_ne!(store.generation, after_reset);

        // A failed push leaves the generation alone: nothing changed.
        let before = store.generation;
        assert!(store.push(b"bad", CURLH_HEADER, 0).is_err());
        assert_eq!(store.generation, before);

        // Wrapping skips zero.
        store.generation = u32::MAX;
        store.bump_generation();
        assert_eq!(store.generation, HeaderStore::FIRST_GENERATION);
    }

    // `PushHeaders` -- `lib/http2.c:657-702`.

    /// `lib/http2.c:1478` builds `"%s:%s"`, and `bynum` hands back the whole
    /// string rather than the value.
    #[test]
    fn by_num_returns_the_whole_name_colon_value_string() {
        let mut push = PushHeaders::new();
        push.push(b":path", b"/index.html").unwrap();
        push.push(b"accept", b"*/*").unwrap();

        assert_eq!(push.count(), 2);
        assert_eq!(push.by_num(0), Some(b":path:/index.html".as_slice()));
        assert_eq!(push.by_num(1), Some(b"accept:*/*".as_slice()));
        assert_eq!(push.by_num(2), None);
        assert_eq!(push.by_num(usize::MAX), None);
        // No space after the colon, unlike the wire form.
        assert!(!push.by_num(0).unwrap().contains(&b' '));
    }

    /// The asymmetry with `HeaderStore`: `strncmp`, so byte-exact.
    #[test]
    fn by_name_is_case_sensitive() {
        let mut push = PushHeaders::new();
        push.push(b"Content-Type", b"text/plain").unwrap();

        assert_eq!(
            push.by_name(b"Content-Type"),
            Some(b"text/plain".as_slice())
        );
        assert_eq!(push.by_name(b"content-type"), None);
        assert_eq!(push.by_name(b"CONTENT-TYPE"), None);
        assert_eq!(push.by_name(b"cOnTeNt-TyPe"), None);

        // Whereas the response store DOES fold, on the same spelling.
        let store = header_store(&[b"Content-Type: text/plain\r\n"]);
        assert!(store.header(b"content-type", 0, CURLH_HEADER, 0, 0).is_ok());
    }

    /// `lib/http2.c:694-696`.
    #[test]
    fn by_name_rejects_the_c_guards_query_set() {
        let mut push = PushHeaders::new();
        push.push(b":status", b"200").unwrap();
        push.push(b"x", b"y").unwrap();

        assert_eq!(push.by_name(b""), None, "an empty name");
        assert_eq!(push.by_name(b":"), None, "exactly a colon");
        assert_eq!(push.by_name(b"a:b"), None, "a colon in the middle");
        assert_eq!(push.by_name(b"x:"), None, "a trailing colon");
        assert_eq!(push.by_name(b":a:b"), None, "a colon past the first byte");
        assert_eq!(push.by_name(b"\0"), None, "a leading NUL is an empty name");

        // A LEADING colon is allowed -- pseudo-fields need it.
        assert_eq!(push.by_name(b":status"), Some(b"200".as_slice()));
    }

    /// A prefix match must be followed by the colon, and the C moves on to
    /// the next entry rather than giving up (`lib/http2.c:702-704`).
    #[test]
    fn by_name_requires_the_colon_to_follow_the_prefix() {
        let mut push = PushHeaders::new();
        push.push(b"content-length", b"12").unwrap();
        push.push(b"content", b"short").unwrap();

        // `content` prefixes entry 0 but is not followed by its colon, so the
        // search continues and finds entry 1.
        assert_eq!(push.by_name(b"content"), Some(b"short".as_slice()));
        assert_eq!(push.by_name(b"content-length"), Some(b"12".as_slice()));
        assert_eq!(push.by_name(b"content-len"), None);
        assert_eq!(push.by_name(b"absent"), None);
    }

    /// No blank skipping: the slice starts immediately after the colon.
    #[test]
    fn by_name_does_not_skip_blanks_and_the_first_match_wins() {
        let mut push = PushHeaders::new();
        push.push(b"x", b" padded ").unwrap();
        push.push(b"dup", b"first").unwrap();
        push.push(b"dup", b"second").unwrap();

        assert_eq!(push.by_name(b"x"), Some(b" padded ".as_slice()));
        assert_eq!(push.by_name(b"dup"), Some(b"first".as_slice()));
        // An empty value is an empty slice, not an absence.
        push.push(b"empty", b"").unwrap();
        assert_eq!(push.by_name(b"empty"), Some(b"".as_slice()));
    }

    #[test]
    fn the_push_field_ceiling_is_enforced_and_clears_the_set() {
        let mut push = PushHeaders::new();
        for _ in 0..MAX_PUSH_PROMISE_HEADERS {
            push.push(b"a", b"b").unwrap();
        }
        assert_eq!(push.count(), MAX_PUSH_PROMISE_HEADERS);
        assert_eq!(push.push(b"a", b"b"), Err(CURLcode::TooLarge));
        // `free_push_headers()` runs on that bail in the C, so the fields are
        // gone here too.
        assert!(push.is_empty());
        assert_eq!(push.by_num(0), None);
    }

    #[test]
    fn an_empty_push_set_answers_nothing() {
        let push = PushHeaders::default();
        assert!(push.is_empty());
        assert_eq!(push.count(), 0);
        assert_eq!(push.by_num(0), None);
        assert_eq!(push.by_name(b"anything"), None);
    }

    #[test]
    fn freeing_a_push_set_empties_it() {
        let mut push = PushHeaders::new();
        push.push(b"a", b"b").unwrap();
        push.free();
        assert!(push.is_empty());
        assert_eq!(push.by_name(b"a"), None);
    }

    /// A credential header's value cannot appear in a formatted store.
    ///
    /// Negative assertions, naming each secret, so a formatter change that
    /// reinstates one fails here. Every parent formatter is covered by this
    /// single test, because the redaction is at the leaf: nothing above
    /// [`StoredHeader`] can see the bytes.
    #[test]
    fn a_credential_header_value_cannot_reach_a_formatted_store() {
        let mut store = HeaderStore::new();
        for line in [
            "Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n",
            "Cookie: session=abc123deadbeef\r\n",
            "Set-Cookie: sid=cafebabe; Path=/\r\n",
            "Proxy-Authorization: Bearer proxy-token-xyz\r\n",
            "WWW-Authenticate: Digest nonce=deadbeefcafe\r\n",
            "Content-Type: text/plain\r\n",
        ] {
            store
                .push(line.as_bytes(), 1 << 0, 0)
                .expect("these headers store");
        }

        let text = format!("{store:?}");
        for secret in [
            "YWxpY2U6aHVudGVyMg==",
            "abc123deadbeef",
            "cafebabe",
            "proxy-token-xyz",
            "deadbeefcafe",
        ] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }

        // The names survive, so a reader can still see what arrived.
        for name in ["Authorization", "Cookie", "Set-Cookie"] {
            assert!(text.contains(name), "{name} is missing: {text}");
        }
        // And an ordinary value renders in full.
        assert!(text.contains("text/plain"), "{text}");

        // The stored bytes are unchanged: this is a formatting change only.
        let view = store
            .header(b"authorization", 0, 1 << 0, 0, 0)
            .expect("the header is stored");
        assert_eq!(view.value, b"Basic YWxpY2U6aHVudGVyMg==");
    }

    /// The same for a promised-push field set, whose entries are combined.
    #[test]
    fn a_credential_push_header_cannot_reach_a_formatted_set() {
        let mut push = PushHeaders::new();
        push.push(b"cookie", b"session=abc123deadbeef")
            .expect("the entry is added");
        push.push(b"content-type", b"text/plain")
            .expect("the entry is added");

        let text = format!("{push:?}");
        assert!(!text.contains("abc123deadbeef"), "{text}");
        assert!(text.contains("cookie"), "{text}");
        assert!(text.contains("text/plain"), "{text}");
    }
}
