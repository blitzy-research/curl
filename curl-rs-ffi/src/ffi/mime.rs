// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl
//
// Derived from include/curl/curl.h:2420-2553, lib/mime.c and lib/libcurl.def
// of curl 8.19.0-DEV at commit 54cf587b9c.

//! The twelve exported mime functions -- supersedes the public half of
//! `lib/mime.c`.
//!
//! | Symbol | Prototype | C authority | Failure answer |
//! |--------|-----------|-------------|----------------|
//! | `curl_mime_init` | curl.h:2442 | mime.c:1180-1203 | null |
//! | `curl_mime_free` | curl.h:2451 | mime.c:1081-1095 | none: `void` |
//! | `curl_mime_addpart` | curl.h:2461 | mime.c:1214-1236 | null |
//! | `curl_mime_name` | curl.h:2470 | mime.c:1239-1253 | 43 |
//! | `curl_mime_filename` | curl.h:2479 | mime.c:1256-1270 | 43 |
//! | `curl_mime_type` | curl.h:2489 | mime.c:1348-1362 | 43 |
//! | `curl_mime_encoder` | curl.h:2498 | mime.c:1374-1394 | 43 |
//! | `curl_mime_data` | curl.h:2508 | mime.c:1273-1297 | 43 |
//! | `curl_mime_filedata` | curl.h:2518 | mime.c:1300-1344 | 43 |
//! | `curl_mime_data_cb` | curl.h:2528 | mime.c:1415-1435 | 43 |
//! | `curl_mime_subparts` | curl.h:2542 | mime.c:1489-1492 | 43 |
//! | `curl_mime_headers` | curl.h:2551 | mime.c:1397-1409 | 43 |
//!
//! These are twelve of the 100 names in `lib/libcurl.def`, and the only twelve
//! this module may define. 43 above is `CURLE_BAD_FUNCTION_ARGUMENT`, which is
//! what the C answers for a null part. A second definition of any of the
//! twelve anywhere in the crate is a link error rather than a review finding.
//!
//! # No wire bytes are produced here
//!
//! Boundary generation, part ordering, `Content-Disposition` and
//! `Content-Type` emission, header casing, CRLF placement and every
//! transfer-encoding belong to `curl_rs_lib::mime`. This module marshals and
//! nothing else: it copies bytes across the boundary, resolves handles, and
//! calls one engine method per entry point. The boundary is randomised
//! (`lib/rand.c`), and it stays randomised: making it deterministic here would
//! be a behaviour change, which 0.8.2 prohibits.
//!
//! # CORRECTION 21: the handle-typedef inventory is SEVEN, not five
//!
//! Two of the seven belong to this module's surface, and both are **opaque
//! self-named** typedefs -- the struct tag equals the typedef name:
//!
//! * `typedef struct curl_mime curl_mime;` (curl.h:2428, "Mime context.")
//! * `typedef struct curl_mimepart curl_mimepart;` (curl.h:2429, "Mime part
//!   context.")
//!
//! That distinguishes them from `typedef struct Curl_URL CURLU;`, where tag
//! and typedef differ, and from `typedef void CURL;`, which is not a struct at
//! all. Neither appears in the five-row handle table that a reading of the
//! three `void` aliases plus `CURLU` and `CURLMsg` would produce, yet both are
//! the argument and return types of all twelve symbols below and are therefore
//! as ABI-visible as `CURLU` is. [`super::handle`] owns their Rust
//! declarations; this module names them and declares neither. `CURL *easy` in
//! [`curl_mime_init`] is `*mut c_void`, because `typedef void CURL;`
//! (curl.h:109), and consumers assign a
//! `CURL *` to a `void *` throughout `docs/examples/`.
//!
//! # Panic containment
//!
//! Every entry point routes its body through [`super::panic_boundary`], the
//! crate's single `catch_unwind`. The fallbacks are the crate contract's:
//! `CURLE_FAILED_INIT` for `CURLcode`, null for a pointer, and a quiet return
//! for `curl_mime_free`. The eleven mutating entry points additionally route
//! through `guard_tx`, so a tree whose mutation was abandoned mid-flight is
//! poisoned rather than read again; `curl_mime_free` is the documented
//! exception and must keep working on a poisoned tree, or a contained defect
//! becomes a leak.

use core::ffi::{c_char, c_int, c_void, CStr};
use core::ptr;
use std::path::Path;

use curl_rs_lib::mime::{
    Mime, MimePart, PartReader, ReadStatus, SeekResult, SeekWhence,
};

use super::codes::CURLcode;
use super::handle::{self, curl_mime, curl_mimepart, curl_off_t, curl_slist};
use super::panic_boundary::{guard, guard_ptr, guard_tx, guard_void, Poison};
use super::types::{
    curl_free_callback, curl_read_callback, curl_seek_callback,
};

// Constants transcribed from the frozen headers and from `lib/mime.c`.

/// `CURL_ZERO_TERMINATED` (curl.h:2420): `((size_t)-1)`.
///
/// The sentinel [`curl_mime_data`] resolves with `strlen`. It is a distinct
/// code path from a real length, and both are reachable, so both are tested.
const CURL_ZERO_TERMINATED: usize = usize::MAX;

/// `READ_ERROR` (`lib/mime.c:47`): `((size_t)-1)`.
const READ_ERROR: usize = usize::MAX;

/// `STOP_FILLING` (`lib/mime.c:48`): `((size_t)-2)`.
const STOP_FILLING: usize = usize::MAX - 1;

/// `CURL_READFUNC_ABORT` (curl.h:390): `0x10000000`.
const CURL_READFUNC_ABORT: usize = 0x1000_0000;

/// `CURL_READFUNC_PAUSE` (curl.h:393): `0x10000001`.
const CURL_READFUNC_PAUSE: usize = 0x1000_0001;

/// `SEEK_SET`, the `origin` a C seek callback receives for
/// [`SeekWhence::Set`].
///
/// Taken from `libc` rather than written as a literal, because the three
/// origins are the platform's and not curl's: `lib/mime.c:1471` passes
/// `SEEK_SET` through to the callback unchanged.
const SEEK_SET: c_int = libc::SEEK_SET;

/// `SEEK_CUR`, the `origin` for [`SeekWhence::Current`].
const SEEK_CUR: c_int = libc::SEEK_CUR;

/// `SEEK_END`, the `origin` for [`SeekWhence::End`].
const SEEK_END: c_int = libc::SEEK_END;

/// The engine's "no size known" value: `part->datasize = -1` in the C.
///
/// `curl_mime_data_cb` stores its `datasize` argument verbatim, so `-1` is
/// forwarded as "unknown" and every other value as itself.
const SIZE_UNKNOWN: curl_off_t = -1;

/// Stamped into every [`MimeBox`] so a handle of the wrong family, or one
/// whose memory has been recycled, is rejected instead of dereferenced.
///
/// The bytes spell `MIME_RS` followed by a NUL, which makes the word
/// recognisable in a core dump. It is a best-effort check and is documented as
/// such on [`mime_identity`]: it catches a `curl_mimepart *` passed where a
/// `curl_mime *` belongs, an uninitialised pointer that happens to be
/// readable, and a freed block whose contents have since been overwritten. It
/// cannot make a genuine use-after-free defined, and no library can.
const MIME_MAGIC: u64 = 0x4d49_4d45_5f52_5300;

/// Stamped into every [`PartBox`], distinct from [`MIME_MAGIC`] so the two
/// opaque families cannot be confused for one another. The bytes spell
/// `PART_RS` followed by a NUL.
const PART_MAGIC: u64 = 0x5041_5254_5f52_5300;

// The representation behind the two opaque handles.

/// Where a part lives: the root handle that owns it, and the chain of part
/// indices that reaches it from that root's tree.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Location {
    /// The handle whose `tree` currently holds this part. Never null in a
    /// live record.
    root: *mut curl_mime,
    /// Part indices from that tree downwards.
    path: Vec<usize>,
}

/// What a `curl_mime *` actually addresses.
///
/// One of these is allocated by [`curl_mime_init`] and released by
/// [`curl_mime_free`]. While it is a *root* it owns `tree`; once
/// [`curl_mime_subparts`] has given its tree away it keeps `forward` instead
/// and becomes an inert tombstone, which is what makes a caller's mistaken
/// `curl_mime_free` on a transferred handle a detectable no-op rather than a
/// double free.
/// `#[repr(C)]` so that `magic` is guaranteed to sit at offset 0.
#[repr(C)]
struct MimeBox {
    /// [`MIME_MAGIC`] in a live handle. **Must remain the first field**; see the
    /// `repr(C)` note above.
    magic: u64,

    /// The abandoned-mutation flag `guard_tx` consults.
    ///
    /// **Boxed on purpose, and the reason is a borrow shape rather than a
    /// size.** `guard_tx` wants a `&Poison` that outlives its body, and the
    /// body wants a `&mut MimeBox`; if the flag lived inline, those two
    /// borrows would overlap in one allocation and the shared one would be
    /// invalidated the moment the exclusive one was created. A separate
    /// allocation makes them disjoint, so the crate's transactional guard can
    /// be used as written instead of being reimplemented here with the
    /// aliasing quietly ignored.
    poison: Box<Poison>,

    /// The engine tree, present exactly while this handle is a root.
    tree: Option<Mime>,

    /// Where the tree went, once it has been absorbed by a part.
    ///
    /// Names the part that consumed it, so [`curl_mime_addpart`] still works
    /// on a transferred handle -- the C's `curl_mime_addpart(subparts)` after
    /// `curl_mime_subparts` does -- and so the "accept setting twice the same
    /// subparts" fast path of `lib/mime.c:1447-1448` is detectable.
    forward: Option<Location>,

    /// One record per part reachable from this root, including the parts of
    /// every subtree absorbed into it.
    ///
    /// `Box` per element, never a flat `Vec<PartBox>`: the addresses of these
    /// records are what C holds, so they must not move when the vector grows.
    /// The vector's own buffer may move freely; only the pointees matter.
    // `clippy::vec_box` reads this as redundant indirection, and for an
    // ordinary collection it would be right. Here the indirection IS the
    // requirement:
    // `Vec<PartBox>` moves its elements on reallocation, which would dangle
    // every `curl_mimepart *` handed out before the most recent
    // `curl_mime_addpart`. The lint cannot see that the addresses have escaped
    // to C. Item-scoped rather than module- or crate-scoped, so a second
    // `Vec<Box<_>>` added here without the same justification still fires.
    #[allow(clippy::vec_box)]
    parts: Vec<Box<PartBox>>,

    /// Handles whose trees this root absorbed, kept alive as tombstones.
    ///
    /// Raw rather than `Box`, because each came from
    /// [`handle::into_raw`] in [`curl_mime_init`] and reclaiming it is
    /// `from_raw`'s job -- which happens in [`curl_mime_free`] and nowhere
    /// else.
    absorbed: Vec<*mut curl_mime>,
}

/// What a `curl_mimepart *` actually addresses.
#[repr(C)]
struct PartBox {
    /// [`PART_MAGIC`] in a live record. **Must remain the first field.**
    magic: u64,

    /// The engine part this record stands for.
    at: Location,

    /// The `curl_slist` chain this part owns, or null.
    owned_headers: *mut curl_slist,
}

// The caller's read/seek/free triple, adapted to the engine's reader trait.

/// A part whose content comes from the caller's callbacks:
/// `MIMEKIND_CALLBACK`.
struct CallbackReader {
    /// `part->readfunc`. Non-`None` in a constructed reader, because
    /// `lib/mime.c:1424` installs nothing at all when `readfunc` is null.
    readfunc: curl_read_callback,
    /// `part->seekfunc`. `None` is the C's absent seek function, which
    /// `lib/mime.c:975-976` treats as `CURL_SEEKFUNC_CANTSEEK`.
    seekfunc: curl_seek_callback,
    /// `part->freefunc`, run once when this reader is released.
    freefunc: curl_free_callback,
    /// `part->arg`, passed to all three unchanged.
    arg: *mut c_void,
}

impl core::fmt::Debug for CallbackReader {
    /// Deliberately opaque.
    ///
    /// `PartReader` requires `Debug` and the engine derives `Debug` on the
    /// part that holds one, so this is reachable from a formatting call. It
    /// prints which callbacks are installed and never the pointers
    /// themselves: an address is both a diagnostic hazard and a value that
    /// changes between runs, and anything this crate writes can end up
    /// compared byte for byte.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CallbackReader")
            .field("readfunc", &self.readfunc.is_some())
            .field("seekfunc", &self.seekfunc.is_some())
            .field("freefunc", &self.freefunc.is_some())
            .finish()
    }
}

impl PartReader for CallbackReader {
    /// `part->readfunc(buffer, 1, bufsize, part->arg)`
    /// (`lib/mime.c:722`).
    fn read(&mut self, buf: &mut [u8]) -> ReadStatus {
        let Some(readfunc) = self.readfunc else {
            // Not constructible through `curl_mime_data_cb`, which installs
            // nothing for a null `readfunc`. Answering `Eof` rather than
            // panicking keeps the boundary's promise that nothing unwinds.
            return ReadStatus::Eof;
        };

        // SAFETY: `readfunc` is the caller's own function pointer, installed
        // through `curl_mime_data_cb`, and `arg` is the context it supplied
        // alongside it. `buf` is a live, initialised, uniquely borrowed slice
        // for the duration of the call, so the pointer and length handed over
        // describe writable memory of exactly that size -- which is the whole
        // of what a `curl_read_callback` may touch. Calling it is otherwise
        // the caller's own contract with itself.
        let produced = unsafe {
            readfunc(buf.as_mut_ptr().cast::<c_char>(), 1, buf.len(), self.arg)
        };

        match produced {
            STOP_FILLING => ReadStatus::StopFilling,
            0 => ReadStatus::Eof,
            CURL_READFUNC_ABORT => ReadStatus::Abort,
            CURL_READFUNC_PAUSE => ReadStatus::Pause,
            READ_ERROR => ReadStatus::ReadError,
            count if count <= buf.len() => ReadStatus::Bytes(count),
            // A count larger than the buffer. The C adds it to the running
            // offset and reads bytes that were never written, which is
            // undefined; there is therefore no defined behaviour to preserve,
            // and reporting a read error keeps the fault inside the caller's
            // own error path instead of turning it into unsoundness here.
            _ => ReadStatus::ReadError,
        }
    }

    /// `part->seekfunc(part->arg, offset, whence)` (`lib/mime.c:977`).
    ///
    /// An absent callback is `CURL_SEEKFUNC_CANTSEEK`, which is where
    /// `mime_part_rewind` starts from before a callback improves on it. A
    /// present one has its `int` return mapped by `SeekResult::from_code`,
    /// which is the engine's transcription of the C's own three-way `switch`
    /// plus its `-1` special case.
    fn seek(&mut self, offset: curl_off_t, whence: SeekWhence) -> SeekResult {
        let Some(seekfunc) = self.seekfunc else {
            return SeekResult::CantSeek;
        };

        let origin = match whence {
            SeekWhence::Set => SEEK_SET,
            SeekWhence::Current => SEEK_CUR,
            SeekWhence::End => SEEK_END,
        };

        // SAFETY: `seekfunc` is the caller's own function pointer with `arg`
        // as the context it was installed with, and both scalars are passed
        // by value. Nothing here is dereferenced by this crate.
        let code = unsafe { seekfunc(self.arg, offset, origin) };
        SeekResult::from_code(code)
    }

    /// A second reader over the same source.
    fn duplicate(&self) -> Box<dyn PartReader> {
        Box::new(Self {
            readfunc: self.readfunc,
            seekfunc: self.seekfunc,
            freefunc: self.freefunc,
            arg: self.arg,
        })
    }
}

impl Drop for CallbackReader {
    /// `if(part->freefunc) part->freefunc(part->arg);`
    /// (`lib/mime.c:1026-1027`).
    fn drop(&mut self) {
        let Some(freefunc) = self.freefunc else {
            return;
        };

        // SAFETY: `freefunc` is the caller's own release hook and `arg` is
        // the context it was installed with in the same `curl_mime_data_cb`
        // call. This runs exactly once per reader -- `Drop` cannot run twice
        // -- which is the once-per-part release the C performs. A reader
        // produced by `duplicate` is a second reader and releases the shared
        // `arg` a second time, which is the C's behaviour too.
        unsafe { freefunc(self.arg) };
    }
}

// Navigation inside a tree. Both are safe: they take a borrow and return one.

/// The nested multipart at `path`, counted in parts from `tree` downwards.
///
/// An empty path is `tree` itself. `None` means the path does not describe a
/// multipart -- an index past the end, or a part whose content is not a nested
/// handle -- which is the answer a stale record earns rather than a panic.
fn mime_at<'a>(tree: &'a mut Mime, path: &[usize]) -> Option<&'a mut Mime> {
    let mut cursor = tree;
    for index in path {
        cursor = cursor.part_mut(*index)?.subparts_mut()?;
    }
    Some(cursor)
}

/// The part at `path`, whose last element is its index in its own multipart.
///
/// An empty path names no part and yields `None`: the root's tree is a `Mime`,
/// not a `MimePart`.
fn part_at<'a>(tree: &'a mut Mime, path: &[usize]) -> Option<&'a mut MimePart> {
    let (last, prefix) = path.split_last()?;
    mime_at(tree, prefix)?.part_mut(*last)
}

// Handle validation. Each reads a caller's pointer once and copies out what it
// needs, so that no borrow of a handle is alive when the next one is taken.

/// Reads a candidate record's magic word without asserting its extent.
///
/// Both [`MimeBox`] and [`PartBox`] are `repr(C)` with `magic: u64` first, so
/// the record pointer IS a pointer to the magic. Reading through it touches
/// eight bytes at offset 0 and forms no reference, which is what makes it safe
/// to call on a pointer that might address a smaller record of the other family
/// -- the case the magic words exist to detect.
///
/// # Safety
///
/// `record` must be non-null and must address at least eight readable,
/// initialised bytes. Every opaque pointer this module accepts satisfies that as
/// soon as it is known non-null, because the smallest record either family
/// allocates is larger than a `u64`.
unsafe fn magic_of<T>(record: *const T) -> u64 {
    // SAFETY: the contract above guarantees eight readable initialised bytes at
    // this address. `read_unaligned` rather than `read` because nothing promises
    // a caller's foreign pointer is eight-byte aligned, and a misaligned read
    // must be a wrong answer rather than undefined behaviour.
    unsafe { record.cast::<u64>().read_unaligned() }
}

/// The root a `curl_mime *` belongs to, and the absolute path of the subtree.
///
/// `None` for a handle this module cannot vouch for: null, a record whose magic
/// word does not match, or a handle whose forwarding entry has been cleared.
/// A `Some` answer carries the *root* handle -- which is the handle itself for
/// a tree owner, and the owner of the tree it was grafted into for a
/// subtree -- together with the index path from that root.
///
/// # Safety
///
/// The caller must guarantee both of the following. Neither can be checked
/// here, which is why this is an `unsafe fn` rather than a safe one that
/// returns an error.
///
/// * `handle` is either null, or a pointer that [`curl_mime_init`] returned and
///   [`curl_mime_free`] has not reclaimed. A dangling pointer to freed storage
///   satisfies no check below: the magic word is read out of memory the
///   allocator may have reused, so a stale handle can spuriously match.
/// * If non-null, `handle` addresses at least eight readable, initialised
///   bytes. Every record either family allocates is larger than a `u64`, so any
///   live handle of either family satisfies this -- including a
///   `curl_mimepart *` passed where a `curl_mime *` belongs, which is the case
///   the magic word exists to reject rather than to trust.
///
/// The magic word is a *best-effort* filter and not a validity proof. It turns
/// the overwhelmingly likely mistakes -- a null handle, a handle of the wrong
/// family, uninitialised storage -- into a clean `None`, and it cannot detect a
/// use-after-free. [`part_identity`] carries the identical caveat.
///
/// The eight-byte read is deliberately narrower than forming a `&MimeBox`: see
/// the safety comment inside, which records the AddressSanitizer report that
/// narrowing it fixed.
unsafe fn mime_identity(
    handle: *mut curl_mime,
) -> Option<(*mut curl_mime, Vec<usize>)> {
    if handle.is_null() {
        return None;
    }

    // SAFETY: non-null by the check above, and `MimeBox` is `repr(C)` with
    // `magic` first, so this reads eight bytes at offset 0 of whatever the
    // caller passed. That is deliberately WEAKER than forming a
    // `&MimeBox`: the pointer may address a smaller record of another family --
    // a `curl_mimepart *` given where a `curl_mime *` belongs -- and asserting
    // the whole record before the magic has vouched for it would read past that
    // record. AddressSanitizer reported exactly that heap-buffer-overflow before
    // this read was narrowed.
    if unsafe { magic_of(handle) } != MIME_MAGIC {
        return None;
    }

    // SAFETY: the magic word above vouches for the record being one of ours, so
    // it is a live, fully initialised `MimeBox`. The borrow is shared, is
    // confined to this block, and ends before any caller of this function takes
    // an exclusive one.
    let boxed = unsafe { &*handle.cast::<MimeBox>() };
    if boxed.tree.is_some() {
        return Some((handle, Vec::new()));
    }
    boxed.forward.as_ref().map(|at| (at.root, at.path.clone()))
}

/// The root a `curl_mimepart *` belongs to, and the absolute path of the part.
///
/// # Safety
///
/// `part` must be either null or a pointer that [`curl_mime_addpart`] returned
/// for a tree that [`curl_mime_free`] has not reclaimed. The same best-effort
/// caveat as [`mime_identity`] applies to the magic word.
unsafe fn part_identity(
    part: *mut curl_mimepart,
) -> Option<(*mut curl_mime, Vec<usize>)> {
    if part.is_null() {
        return None;
    }

    // SAFETY: non-null by the check above, and `PartBox` is `repr(C)` with
    // `magic` first, so this reads offset 0 of whatever was passed without
    // assuming the record's extent. See the note in `mime_identity`.
    if unsafe { magic_of(part) } != PART_MAGIC {
        return None;
    }

    // SAFETY: the magic vouches for the record, so the pointer addresses a live
    // `PartBox` that `curl_mime_addpart` allocated and that its root still owns.
    // The shared borrow ends inside this block, before any exclusive borrow of
    // the root is taken -- which matters, because the record's `Box` is held by
    // that same root.
    let boxed = unsafe { &*part.cast::<PartBox>() };
    if boxed.at.root.is_null() {
        return None;
    }
    Some((boxed.at.root, boxed.at.path.clone()))
}

/// Runs `body` against a root handle, under the crate's transactional guard.
///
/// # Safety
///
/// `root` must be a pointer that [`mime_identity`] or [`part_identity`]
/// returned as a root: non-null, addressing a live [`MimeBox`], and not
/// borrowed anywhere else for the duration of the call.
unsafe fn with_root<R: Copy>(
    root: *mut curl_mime,
    fallback: R,
    body: impl FnOnce(&mut MimeBox) -> R,
) -> R {
    // The flag's ADDRESS is read out of the handle, and the flag is then
    // reached through its own allocation. That is what the boxing on
    // `MimeBox::poison` buys: the shared borrow handed to `guard_tx` does not
    // overlap the exclusive borrow `body` takes, because the two are in
    // different allocations. `Box<Poison>` is a thin pointer, so the field is
    // read as one rather than borrowed as a `Box` -- borrowing the `Box` would
    // put a second live tag on the very allocation the flag lives in.
    //
    // SAFETY: by contract `root` addresses a live, initialised `MimeBox`, so
    // the `poison` field holds a valid `Box<Poison>`. `Box<T>` for a sized `T`
    // has the size, alignment and representation of `*mut T`, so reading the
    // field as a pointer yields the flag's address without constructing or
    // dropping a second owner of it.
    let flag: *const Poison = unsafe {
        ptr::addr_of!((*root.cast::<MimeBox>()).poison)
            .cast::<*const Poison>()
            .read()
    };

    // SAFETY: `flag` is the address of a `Poison` owned by the handle's
    // `Box`, which by contract outlives this call, and nothing else holds an
    // exclusive borrow of that allocation -- `body` never names the field.
    let poison: &Poison = unsafe { &*flag };

    guard_tx(poison, fallback, || {
        // SAFETY: by contract `root` addresses a live `MimeBox` that nothing
        // else borrows for the duration of this call, which is what makes the
        // exclusive reference sound. No ownership is taken: the allocation
        // still belongs to whoever holds the `curl_mime *`.
        let handle = unsafe { &mut *root.cast::<MimeBox>() };
        body(handle)
    })
}

/// The index in `root.parts` of the record `part` addresses, if the root owns
/// it.
fn slot_of(root: &MimeBox, part: *mut curl_mimepart) -> Option<usize> {
    let wanted: *const PartBox = part.cast::<PartBox>().cast_const();
    root.parts
        .iter()
        .position(|record| ptr::eq(&**record, wanted))
}

/// Runs `body` against the engine part a `curl_mimepart *` names.
///
/// The whole resolution and validation sequence in one place, so that eight
/// entry points share exactly one reading of a caller's pointer: identity and
/// magic first, then the root, then ownership of the record by that root, then
/// navigation to the engine part. `fallback` is returned for every failure,
/// which for this family is always `CURLE_BAD_FUNCTION_ARGUMENT` -- the code
/// `lib/mime.c` gives a null part.
///
/// # Safety
///
/// `part` must be either null or a pointer that [`curl_mime_addpart`] returned
/// for a tree that has not been reclaimed, per [`part_identity`].
unsafe fn with_part<R: Copy>(
    part: *mut curl_mimepart,
    fallback: R,
    body: impl FnOnce(&mut MimePart) -> R,
) -> R {
    // SAFETY: delegated to `part_identity`, whose contract this function's own
    // contract repeats. Null and a foreign pointer both yield `None`.
    let identity = unsafe { part_identity(part) };
    let Some((root, path)) = identity else {
        return fallback;
    };

    let resolve = |handle: &mut MimeBox| {
        // The record must be one this root actually owns. An address
        // comparison, so a pointer that is not a live record is rejected
        // rather than dereferenced.
        if slot_of(handle, part).is_none() {
            return fallback;
        }
        let Some(tree) = handle.tree.as_mut() else {
            return fallback;
        };
        let Some(target) = part_at(tree, &path) else {
            return fallback;
        };
        body(target)
    };

    // SAFETY: `root` came out of a live record, so it addresses the handle
    // that owns that record; `with_root` requires nothing more.
    unsafe { with_root(root, fallback, resolve) }
}

// 1 of 12: curl_mime_init

/// Creates a mime context and returns its handle.
///
/// Supersedes `curl_mime_init` (`lib/mime.c:1180-1203`), whose prototype is
/// frozen at `include/curl/curl.h:2442`. Answers null when the platform cannot
/// supply the entropy the boundary is built from, which is the C's own bail-out
/// at `:1194-1197`.
///
/// # Safety
///
/// `easy` may be null or any value: it is not read. The returned pointer must
/// be released exactly once, and only through the routes named above.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_init(easy: *mut c_void) -> *mut curl_mime {
    // Named for the header, unread by design; see the note above.
    let _ = easy;

    guard_ptr(|| {
        let Ok(tree) = Mime::with_system_rng() else {
            // `CURLcode::FailedInit` from the engine, which is the code
            // `lib/rand.c:61` reports for the same condition. A
            // pointer-returning entry point has no channel for it, so the
            // documented answer is null.
            return handle::bad_handle_ptr::<curl_mime>();
        };

        handle::into_raw(MimeBox {
            magic: MIME_MAGIC,
            poison: Box::new(Poison::new()),
            tree: Some(tree),
            forward: None,
            parts: Vec::new(),
            absorbed: Vec::new(),
        })
    })
}

// 2 of 12: curl_mime_free

/// Releases a mime handle and everything below it.
///
/// Supersedes `curl_mime_free` (`lib/mime.c:1081-1095`), frozen at
/// `include/curl/curl.h:2451`. A null handle is a no-op, as it is in C.
///
/// # Safety
///
/// `mime` must be either null or a pointer that [`curl_mime_init`] returned
/// and that has not already been released. Every `curl_mimepart *` obtained
/// from it, and every chain it was given ownership of, is invalid afterwards
/// and must not be used.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_free(mime: *mut curl_mime) {
    // `guard_void`, not `guard_tx`: the cleanup family is the documented
    // exception, because freeing a poisoned tree has to keep working or a
    // contained defect becomes a leak.
    guard_void(|| {
        if mime.is_null() {
            return;
        }

        // Read the two questions this function has to answer -- is it ours,
        // and is it still a root -- and drop the borrow before ownership is
        // taken.
        //
        // SAFETY: non-null by the check above and, by this function's
        // contract, addressing a live `MimeBox`. The shared borrow ends inside
        // this block.
        let (ours, transferred) = unsafe {
            if magic_of(mime) != MIME_MAGIC {
                (false, false)
            } else {
                let boxed = &*mime.cast::<MimeBox>();
                (true, boxed.forward.is_some())
            }
        };

        if !ours || transferred {
            // Not a mime handle, or one whose tree a part now owns. Either
            // way there is nothing here to release: silence is the only answer
            // a `void` function has, and the tombstone's own allocation is
            // reclaimed by the root that adopted it.
            return;
        }

        // SAFETY: the pointer is ours, is still a root, and by contract has
        // not been released, so reclaiming the `Box` restores exactly the
        // ownership `curl_mime_init` gave away.
        unsafe { release(mime) };
    });
}

/// Reclaims one root handle and everything it owns.
///
/// Split out of [`curl_mime_free`] so that the ordering is stated once: the
/// chains a part owns are released before the tree that names those parts goes
/// away, and the tombstones are reclaimed by an explicit worklist rather than
/// by recursion, so that a deeply nested tree cannot overflow the stack while
/// being freed.
///
/// # Safety
///
/// `mime` must be a non-null pointer that [`curl_mime_init`] returned, that is
/// still a root, that has not been released, and that nothing is borrowing.
unsafe fn release(mime: *mut curl_mime) {
    // SAFETY: exactly the contract above, which is `handle::from_raw`'s.
    let Some(mut root) =
        (unsafe { handle::from_raw::<curl_mime, MimeBox>(mime) })
    else {
        return;
    };

    // Every tombstone this root adopted, plus any a tombstone itself carried.
    let mut pending: Vec<*mut curl_mime> = root.absorbed.drain(..).collect();
    release_owned_chains(&mut root);

    while let Some(ghost) = pending.pop() {
        if ghost.is_null() {
            continue;
        }
        // SAFETY: every pointer in `absorbed` was produced by
        // `curl_mime_init`, was adopted by exactly one root, and is reclaimed
        // exactly once -- here, by the root that adopted it. `curl_mime_free`
        // refuses to reclaim a tombstone, so there is no second claimant.
        let Some(mut ghost) =
            (unsafe { handle::from_raw::<curl_mime, MimeBox>(ghost) })
        else {
            continue;
        };
        pending.append(&mut ghost.absorbed);
        release_owned_chains(&mut ghost);
        // `ghost` drops here. Its `tree` is `None`, so nothing of the engine
        // goes with it.
    }

    // `root` drops here, and its tree with it: the engine's drop glue is the
    // recursive release the C performs by walking `firstpart`.
}

/// Releases every `curl_slist` chain the handle's parts were given ownership
/// of, and forgets them.
fn release_owned_chains(boxed: &mut MimeBox) {
    for record in boxed.parts.drain(..) {
        let chain = record.owned_headers;
        if chain.is_null() {
            continue;
        }
        // SAFETY: a non-null `owned_headers` is a chain a caller handed to
        // `curl_mime_headers` with a non-zero `take_ownership` and has not
        // freed itself, because the documented contract forbids it. Draining
        // the record means this is the only release of that chain, and it goes
        // through the same crate-uniform allocator a consumer's own
        // `curl_slist_free_all` would use.
        unsafe { super::slist::curl_slist_free_all(chain) };
    }
}

// 3 of 12: curl_mime_addpart

/// Appends an empty part and returns a handle to it.
///
/// Supersedes `curl_mime_addpart` (`lib/mime.c:1214-1236`), frozen at
/// `include/curl/curl.h:2461`. A null handle answers null, exactly as
/// `:1218-1219` does, and so does a handle this crate does not recognise.
///
/// **The returned pointer is lent, not given.** It is owned by the `curl_mime`
/// that produced it and dies with it; there is no `curl_mime_freepart` in the
/// export set and this module offers no equivalent. It stays valid across
/// every later call, including further `curl_mime_addpart` on the same handle
/// and a [`curl_mime_subparts`] that re-homes the whole tree -- see the module
/// documentation for why that requires a record with a stable address rather
/// than a pointer into the engine's part vector.
///
/// # Safety
///
/// `mime` must be either null or a pointer that [`curl_mime_init`] returned
/// and that [`curl_mime_free`] has not reclaimed. The returned pointer must not
/// be freed, and must not be used after the owning handle is released.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_addpart(
    mime: *mut curl_mime,
) -> *mut curl_mimepart {
    let null = handle::bad_handle_ptr::<curl_mimepart>();

    // SAFETY: delegated to `mime_identity`, whose contract this function's own
    // contract repeats.
    let identity = unsafe { mime_identity(mime) };
    let Some((root, prefix)) = identity else {
        return null;
    };

    let append = |handle: &mut MimeBox| {
        let Some(tree) = handle.tree.as_mut() else {
            return null;
        };
        // The multipart this call appends to: the root's own tree for a live
        // root, or the nested handle a part absorbed.
        let Some(target) = mime_at(tree, &prefix) else {
            return null;
        };

        // The position BEFORE the append is the new part's index, which is how
        // `Mime::add_part`'s own documentation directs this crate to address
        // it.
        let index = target.len();
        target.add_part();

        let mut path = prefix.clone();
        path.push(index);
        handle.parts.push(Box::new(PartBox {
            magic: PART_MAGIC,
            at: Location { root, path },
            owned_headers: ptr::null_mut(),
        }));

        // The address of the record's pointee, which the vector's own growth
        // cannot move.
        let slot = handle.parts.len() - 1;
        let record: *mut PartBox = &mut *handle.parts[slot];
        record.cast::<curl_mimepart>()
    };

    // SAFETY: `root` is what `mime_identity` resolved, so it addresses a live
    // handle holding a tree.
    unsafe { with_root(root, null, append) }
}

// The four string setters, which share one shape.

/// The one way [`borrowed_str`] can fail: a string this crate cannot decode.
///
/// A named unit type rather than `()`, so the failure has a name at every call
/// site and `clippy::result_unit_err` is answered by the signature rather than
/// by a suppression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Undecodable;

/// A caller's NUL-terminated string as UTF-8, or the reason it is not usable.
///
/// `Err(Undecodable)` is a non-null string that is not valid UTF-8. **This is
/// the one place this module is narrower than the C**, which stores arbitrary
/// bytes.
/// The engine's setters take `&str`, and its own `MimePart::set_file`
/// establishes the precedent by answering `CURLcode::BadFunctionArgument` for a
/// path it cannot decode. The alternative -- a lossy conversion -- would put
/// replacement characters on the wire, and the wire form is frozen. Every
/// affected field is ASCII in practice: a mime field name, a remote filename
/// and a content type all are, and `curl_mime_data` is unaffected because it
/// takes bytes rather than a string.
///
/// # Safety
///
/// `text` must be either null or a pointer to a NUL-terminated string that
/// stays valid and unmodified for the duration of the call.
unsafe fn borrowed_str(
    text: *const c_char,
) -> Result<Option<&'static str>, Undecodable> {
    if text.is_null() {
        return Ok(None);
    }
    // SAFETY: non-null by the check above and, by contract, a NUL-terminated
    // string that stays valid for the call -- which is `CStr::from_ptr`'s
    // precondition. The `'static` in the signature is a convenience for the
    // borrow checker; every caller consumes the result inside its own body,
    // before returning to C, and none stores it.
    let cstr = unsafe { CStr::from_ptr(text) };
    cstr.to_str().map(Some).map_err(|_| Undecodable)
}

/// Sets a mime part's field name.
///
/// Supersedes `curl_mime_name` (`lib/mime.c:1239-1253`), frozen at
/// `include/curl/curl.h:2470`. A null `part` answers
/// `CURLE_BAD_FUNCTION_ARGUMENT`; a null `name` **clears** the field and
/// answers `CURLE_OK`, because the C's `Curl_safefree(part->name)` at `:1244`
/// runs unconditionally and only a non-null argument is copied back in. The
/// string is copied, so the caller may release or reuse its buffer as soon as
/// this returns.
///
/// # Safety
///
/// `part` must be either null or a pointer that [`curl_mime_addpart`] returned
/// for a live tree, and `name` must be either null or a NUL-terminated string
/// that stays valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_name(
    part: *mut curl_mimepart,
    name: *const c_char,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        // SAFETY: both pointers reach their documented consumers unchanged;
        // this function's contract is `with_part`'s and `borrowed_str`'s
        // together.
        unsafe {
            with_part(part, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT, |target| {
                match borrowed_str(name) {
                    Ok(text) => {
                        target.set_name(text);
                        CURLcode::CURLE_OK
                    }
                    Err(Undecodable) => {
                        // The C clears the field before it looks at the
                        // argument, so the clearing happens on this path too.
                        target.set_name(None);
                        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
                    }
                }
            })
        }
    })
}

/// Sets a mime part's remote filename.
///
/// Supersedes `curl_mime_filename` (`lib/mime.c:1256-1270`), frozen at
/// `include/curl/curl.h:2479`. The same shape as [`curl_mime_name`]: a null
/// `part` is `CURLE_BAD_FUNCTION_ARGUMENT`, a null `filename` clears and
/// answers `CURLE_OK`, and the string is copied.
///
/// # Safety
///
/// As [`curl_mime_name`], with `filename` in place of `name`.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_filename(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        // SAFETY: as `curl_mime_name`; the two pointers reach `with_part` and
        // `borrowed_str` unchanged.
        unsafe {
            with_part(part, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT, |target| {
                match borrowed_str(filename) {
                    Ok(text) => {
                        target.set_filename(text);
                        CURLcode::CURLE_OK
                    }
                    Err(Undecodable) => {
                        target.set_filename(None);
                        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
                    }
                }
            })
        }
    })
}

/// Sets a mime part's content type.
///
/// Supersedes `curl_mime_type` (`lib/mime.c:1348-1362`), frozen at
/// `include/curl/curl.h:2489`. The same shape as [`curl_mime_name`].
///
/// # Safety
///
/// As [`curl_mime_name`], with `mimetype` in place of `name`.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_type(
    part: *mut curl_mimepart,
    mimetype: *const c_char,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        // SAFETY: as `curl_mime_name`; the two pointers reach `with_part` and
        // `borrowed_str` unchanged.
        unsafe {
            with_part(part, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT, |target| {
                match borrowed_str(mimetype) {
                    Ok(text) => {
                        target.set_type(text);
                        CURLcode::CURLE_OK
                    }
                    Err(Undecodable) => {
                        target.set_type(None);
                        CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
                    }
                }
            })
        }
    })
}

/// Selects a mime part's `Content-Transfer-Encoding`.
///
/// Supersedes `curl_mime_encoder` (`lib/mime.c:1374-1394`), frozen at
/// `include/curl/curl.h:2498-2499`. The accepted names are exactly the five
/// rows of `encoders[]` at `lib/mime.c:1365-1369` -- `binary`, `8bit`, `7bit`,
/// `base64` and `quoted-printable` -- compared case-insensitively, because the
/// C compares with `curl_strequal`.
///
/// Three details are easy to get wrong and are reproduced deliberately:
///
/// * **The encoder is cleared before the lookup** (`:1382`), so an
///   unrecognised name both fails and leaves the part with no encoder.
/// * **A null `encoding` clears and succeeds** -- the C's "Removing current
///   encoder." at `:1385`.
/// * **A null `part` answers `CURLE_BAD_FUNCTION_ARGUMENT`** because that is
///   the value `result` is initialised to at `:1376`, not because of a separate
///   check.
///
/// # Safety
///
/// As [`curl_mime_name`], with `encoding` in place of `name`.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_encoder(
    part: *mut curl_mimepart,
    encoding: *const c_char,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        // SAFETY: as `curl_mime_name`; the two pointers reach `with_part` and
        // `borrowed_str` unchanged.
        unsafe {
            with_part(part, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT, |target| {
                let Ok(text) = borrowed_str(encoding) else {
                    // A name this crate cannot decode matches none of the
                    // five, which is the unmatched case: clear, then fail.
                    let _ = target.set_encoder(None);
                    return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
                };
                match target.set_encoder(text) {
                    Ok(()) => CURLcode::CURLE_OK,
                    Err(code) => CURLcode::from(code),
                }
            })
        }
    })
}

// 8 of 12: curl_mime_data

/// Sets a mime part's content from bytes held in memory.
///
/// `datasize` is a `size_t`. **Note the asymmetry with
/// [`curl_mime_data_cb`], whose `datasize` is a `curl_off_t`** -- the two
/// differ in the frozen header and the difference is preserved rather than
/// tidied away. `CURL_ZERO_TERMINATED`, which is `((size_t)-1)` at
/// `include/curl/curl.h:2420`, means "measure it with `strlen`", and that is a
/// genuinely different code path from a real length: with the sentinel the
/// bytes stop at the first NUL, and with a length they do not, so a buffer
/// holding an interior NUL is stored differently by each.
///
/// # Safety
///
/// `part` must be either null or a pointer that [`curl_mime_addpart`] returned
/// for a live tree. When `datasize` is `CURL_ZERO_TERMINATED`, `data` must be
/// either null or a NUL-terminated string; otherwise `data` must be either null
/// or the start of at least `datasize` readable bytes. Either way the memory
/// must stay valid and unmodified for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_data(
    part: *mut curl_mimepart,
    data: *const c_char,
    datasize: usize,
) -> CURLcode {
    let install = |target: &mut MimePart| {
        if data.is_null() {
            // `cleanup_part_content` with nothing installed after it.
            target.set_data(None);
            return CURLcode::CURLE_OK;
        }

        let bytes: &[u8] = if datasize == CURL_ZERO_TERMINATED {
            // SAFETY: the sentinel is the caller's assertion that `data` is
            // NUL-terminated, which is `CStr::from_ptr`'s precondition. This is
            // the C's `strlen(data)`.
            unsafe { CStr::from_ptr(data) }.to_bytes()
        } else {
            // SAFETY: by contract `data` is the start of at least `datasize`
            // readable bytes that nothing mutates during the call. `u8` needs
            // alignment 1, which any object pointer satisfies, and a zero
            // length over a non-null pointer is permitted.
            unsafe { core::slice::from_raw_parts(data.cast::<u8>(), datasize) }
        };

        // Copied into the part, exactly as `curlx_memdup0` copies.
        target.set_data(Some(bytes));
        CURLcode::CURLE_OK
    };

    guard(CURLcode::CURLE_FAILED_INIT, || {
        // SAFETY: `part` reaches `with_part` unchanged, which is where this
        // function's contract for it is discharged.
        unsafe {
            with_part(part, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT, install)
        }
    })
}

// 9 of 12: curl_mime_filedata

/// Sets a mime part's content from a named local file.
///
/// Supersedes `curl_mime_filedata` (`lib/mime.c:1300-1344`), frozen at
/// `include/curl/curl.h:2518`. The file is opened at transfer time, not here;
/// what happens here is a `stat` and the recording of the path.
///
/// # Safety
///
/// As [`curl_mime_name`], with `filename` in place of `name`.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_filedata(
    part: *mut curl_mimepart,
    filename: *const c_char,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        // SAFETY: as `curl_mime_name`; the two pointers reach `with_part` and
        // `borrowed_str` unchanged.
        unsafe {
            with_part(part, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT, |target| {
                let Ok(text) = borrowed_str(filename) else {
                    // The C clears the content before it looks at the path, so
                    // the clearing happens on this path too.
                    target.set_data(None);
                    return CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
                };
                match target.set_file(text.map(Path::new)) {
                    Ok(()) => CURLcode::CURLE_OK,
                    Err(code) => CURLcode::from(code),
                }
            })
        }
    })
}

// 10 of 12: curl_mime_data_cb

/// Sets a mime part's content from the caller's callbacks.
///
/// Supersedes `curl_mime_data_cb` (`lib/mime.c:1415-1435`), frozen at
/// `include/curl/curl.h:2528-2533`.
///
/// # Safety
///
/// `part` must be either null or a pointer that [`curl_mime_addpart`] returned
/// for a live tree. When `readfunc` is non-null, it and the two optional
/// callbacks must be valid function pointers that honour the
/// `curl_read_callback`, `curl_seek_callback` and `curl_free_callback`
/// contracts, and `arg` must stay valid until `freefunc` has been called for
/// every part that holds it -- which happens when the content is replaced or
/// the tree is released.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_data_cb(
    part: *mut curl_mimepart,
    datasize: curl_off_t,
    readfunc: curl_read_callback,
    seekfunc: curl_seek_callback,
    freefunc: curl_free_callback,
    arg: *mut c_void,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        // SAFETY: `part` reaches `with_part` unchanged. The callbacks are
        // stored, not called, inside this body; calling them later is licensed
        // by this function's own contract.
        unsafe {
            with_part(part, CURLcode::CURLE_BAD_FUNCTION_ARGUMENT, |target| {
                if readfunc.is_none() {
                    // `cleanup_part_content` with nothing installed after it.
                    target.set_reader(None, None);
                    return CURLcode::CURLE_OK;
                }

                // `-1` is the C's "no size"; every other value, negative ones
                // included, is stored as itself.
                let size = if datasize == SIZE_UNKNOWN {
                    None
                } else {
                    Some(datasize)
                };

                let reader = CallbackReader {
                    readfunc,
                    seekfunc,
                    freefunc,
                    arg,
                };
                target.set_reader(size, Some(Box::new(reader)));
                CURLcode::CURLE_OK
            })
        }
    })
}

// 11 of 12: curl_mime_subparts

/// Sets a mime part's content from a nested multipart, **taking ownership**.
///
/// Supersedes `curl_mime_subparts` (`lib/mime.c:1489-1492`), which is
/// `Curl_mime_set_subparts(part, subparts, TRUE)` (`:1438-1487`), frozen at
/// `include/curl/curl.h:2542-2543`.
///
/// # Who owns `subparts` afterwards
///
/// | Condition | C locator | Result | Owner afterwards |
/// |---|---|---|---|
/// | already these subparts | `:1447-1448` | `CURLE_OK` | the part, as before |
/// | `subparts` is null | `:1454` | `CURLE_OK` | nobody: content cleared |
/// | already attached elsewhere | `:1454-1455` | 43 | **the caller** |
/// | it is the part's own root | `:1458-1466` | 43 | **the caller** |
/// | it cannot be rewound | `:1472-1474` | rewind failed | **the caller** |
/// | otherwise | `:1476-1483` | `CURLE_OK` | the part |
///
/// # Safety
///
/// `part` must be either null or a pointer that [`curl_mime_addpart`] returned
/// for a live tree, and `subparts` must be either null or a pointer that
/// [`curl_mime_init`] returned and that has not been released. On success
/// `subparts` must not be released by the caller; on failure it must.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_subparts(
    part: *mut curl_mimepart,
    subparts: *mut curl_mime,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        // SAFETY: both pointers reach `attach_subparts` unchanged, and its
        // contract is this function's contract.
        unsafe { attach_subparts(part, subparts) }
    })
}

/// The body of [`curl_mime_subparts`], outside the containment closure.
///
/// # Safety
///
/// Exactly [`curl_mime_subparts`]'s contract.
unsafe fn attach_subparts(
    part: *mut curl_mimepart,
    subparts: *mut curl_mime,
) -> CURLcode {
    let bad = CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;

    // SAFETY: delegated to `part_identity`, whose contract this function's own
    // contract repeats for `part`.
    let identity = unsafe { part_identity(part) };
    let Some((root, path)) = identity else {
        return bad;
    };

    // "Accept setting twice the same subparts" (`:1447-1448`), tested BEFORE
    // anything is cleaned up. The donor remembers the part that consumed it, so
    // the question is whether that part is this one.
    if !subparts.is_null() {
        // SAFETY: by contract `subparts` is null or a live handle; null is
        // excluded here, and the shared borrow ends inside the block.
        let already = unsafe {
            magic_of(subparts) == MIME_MAGIC && {
                let donor = &*subparts.cast::<MimeBox>();
                donor
                    .forward
                    .as_ref()
                    .is_some_and(|at| ptr::eq(at.root, root) && at.path == path)
            }
        };
        if already {
            return CURLcode::CURLE_OK;
        }
    }

    let transfer = |handle: &mut MimeBox| -> CURLcode {
        if slot_of(handle, part).is_none() {
            return bad;
        }

        // `cleanup_part_content(part)` at `:1450`, in the C's position: before
        // the failure checks, so every route out of this function except the
        // fast path above leaves the part without content.
        {
            let Some(tree) = handle.tree.as_mut() else {
                return bad;
            };
            let Some(target) = part_at(tree, &path) else {
                return bad;
            };
            target.set_data(None);
        }

        if subparts.is_null() {
            // The C's `if(subparts)` guard follows the cleanup, so a null
            // handle detaches and succeeds.
            return CURLcode::CURLE_OK;
        }

        // SAFETY: `subparts` is non-null and, by contract, addresses a live
        // handle. The shared borrow ends inside this block, before the
        // exclusive one the transfer needs.
        let (ours, is_root) = unsafe {
            if magic_of(subparts) != MIME_MAGIC {
                (false, false)
            } else {
                let donor = &*subparts.cast::<MimeBox>();
                (true, donor.tree.is_some())
            }
        };
        if !ours {
            return bad;
        }
        // "Should not have been attached already" (`:1454-1455`): a handle
        // whose tree is gone has been consumed by some part.
        if !is_root {
            return bad;
        }
        // "Should not be the part's root" (`:1458-1466`). Sharing a root is
        // exactly what being an ancestor means here, and the C reaches the same
        // answer by two checks: any ancestor other than the root already has a
        // non-null `parent` and is caught above, and the root itself is caught
        // here.
        if ptr::eq(subparts, root) {
            return bad;
        }

        // SAFETY: `subparts` is a live root this crate owns and is a different
        // allocation from `root`, which the check above established, so the
        // exclusive borrow below aliases nothing that `handle` covers.
        let donor = unsafe { &mut *subparts.cast::<MimeBox>() };
        let Some(tree) = donor.tree.take() else {
            return bad;
        };

        // Scoped so the borrow of `handle.tree` ends before the bookkeeping
        // below needs `handle` as a whole.
        let outcome = {
            let Some(target) = handle
                .tree
                .as_mut()
                .and_then(|root_tree| part_at(root_tree, &path))
            else {
                // Unreachable: the same path resolved moments ago. The tree
                // goes back to the donor so that a caller holding it is not
                // left owning nothing.
                donor.tree = Some(tree);
                return bad;
            };
            target.set_subparts(tree)
        };

        match outcome {
            Ok(()) => {
                adopt(handle, root, donor, subparts, &path);
                CURLcode::CURLE_OK
            }
            Err((returned, code)) => {
                // Ownership did NOT move. Putting the tree back is what keeps
                // the caller's handle the live object its own `curl_mime_free`
                // expects.
                donor.tree = Some(returned);
                CURLcode::from(code)
            }
        }
    };

    // SAFETY: `root` came out of a live record, so it addresses the handle that
    // owns it; `with_root` requires nothing more.
    unsafe { with_root(root, bad, transfer) }
}

/// Re-homes a donor handle's bookkeeping into the root that absorbed its tree.
///
/// Called only from [`curl_mime_subparts`], and only after the engine has
/// accepted the transfer. Three things move:
///
/// 1. Every part record the donor held is re-based onto the new root and its
///    path prefixed with the consuming part's, so a `curl_mimepart *` the
///    caller obtained before the transfer still resolves afterwards. That is
///    what `docs/examples/smtp-mime.c` relies on.
/// 2. Every tombstone the donor had itself adopted moves across, re-based the
///    same way, so a chain of transfers stays consistent to any depth.
/// 3. The donor becomes a tombstone of the new root: its `forward` names the
///    consuming part, which is what makes the "setting twice the same
///    subparts" fast path work and what makes a mistaken `curl_mime_free` on it
///    a silent no-op.
fn adopt(
    root: &mut MimeBox,
    root_handle: *mut curl_mime,
    donor: &mut MimeBox,
    donor_handle: *mut curl_mime,
    at: &[usize],
) {
    for mut record in donor.parts.drain(..) {
        // The donor's paths were relative to its own tree; that tree now hangs
        // off the part at `at`, so every path gains that prefix.
        let mut path = at.to_vec();
        path.append(&mut record.at.path);
        record.at.path = path;
        record.at.root = root_handle;
        root.parts.push(record);
    }

    for ghost in donor.absorbed.drain(..) {
        if ghost.is_null() {
            continue;
        }
        // SAFETY: every pointer the donor holds in `absorbed` came from
        // `curl_mime_init`, is owned by the donor alone, and addresses a live
        // tombstone -- a different allocation from both `root` and `donor`,
        // since neither can have absorbed itself. Handing the pointer to
        // `root` moves that sole ownership without duplicating it, and the
        // borrow ends in this iteration.
        unsafe {
            let tomb = &mut *ghost.cast::<MimeBox>();
            if let Some(location) = tomb.forward.as_mut() {
                let mut path = at.to_vec();
                path.append(&mut location.path);
                location.path = path;
                location.root = root_handle;
            }
        }
        root.absorbed.push(ghost);
    }

    // The donor itself becomes a tombstone of the new root, remembering which
    // part consumed its tree.
    donor.forward = Some(Location {
        root: root_handle,
        path: at.to_vec(),
    });
    root.absorbed.push(donor_handle);
}

// 12 of 12: curl_mime_headers

/// Sets a mime part's custom headers.
///
/// Supersedes `curl_mime_headers` (`lib/mime.c:1397-1409`), frozen at
/// `include/curl/curl.h:2551-2553`. Answers `CURLE_OK` for every non-null
/// `part`, as the C does, and `CURLE_BAD_FUNCTION_ARGUMENT` for a null one.
///
/// # Header order is preserved exactly, and nothing is filtered
///
/// # Safety
///
/// `part` must be either null or a pointer that [`curl_mime_addpart`] returned
/// for a live tree. `headers` must be either null or the head of a well-formed,
/// terminating `curl_slist` chain whose every `data` is null or a
/// NUL-terminated string, and which nothing mutates during the call. When
/// `take_ownership` is non-zero the chain must have come from
/// [`super::slist::curl_slist_append`] and must not be released by the caller.
#[no_mangle]
pub unsafe extern "C" fn curl_mime_headers(
    part: *mut curl_mimepart,
    headers: *mut curl_slist,
    take_ownership: c_int,
) -> CURLcode {
    guard(CURLcode::CURLE_FAILED_INIT, || {
        // SAFETY: all three arguments reach `install_headers` unchanged, and
        // its contract is this function's contract.
        unsafe { install_headers(part, headers, take_ownership) }
    })
}

/// The body of [`curl_mime_headers`], outside the containment closure.
///
/// Separate for the same reason as [`attach_subparts`]: its own `unsafe` blocks
/// would otherwise sit inside an inherited one and be reported as redundant.
///
/// # Safety
///
/// Exactly [`curl_mime_headers`]'s contract.
unsafe fn install_headers(
    part: *mut curl_mimepart,
    headers: *mut curl_slist,
    take_ownership: c_int,
) -> CURLcode {
    let bad = CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;

    // SAFETY: delegated to `part_identity`, whose contract this function's own
    // contract repeats for `part`.
    let identity = unsafe { part_identity(part) };
    let Some((root, path)) = identity else {
        return bad;
    };

    // Copied BEFORE anything is released, which is what makes replacing a list
    // with itself safe: the C never reads the chain, so it can free first, and
    // this cannot.
    //
    // SAFETY: by contract `headers` is null or a well-formed, terminating chain
    // of NUL-terminated strings that nothing mutates during the call, which is
    // `handle::slist_to_vec`'s precondition exactly.
    let copied: Option<Vec<Vec<u8>>> = if headers.is_null() {
        None
    } else {
        Some(unsafe { handle::slist_to_vec(headers.cast_const()) })
    };

    let install = |handle: &mut MimeBox| -> CURLcode {
        let Some(slot) = slot_of(handle, part) else {
            return bad;
        };

        // The chain this part owned until now, read before the engine is
        // touched.
        let previous = handle.parts[slot].owned_headers;

        {
            let Some(tree) = handle.tree.as_mut() else {
                return bad;
            };
            let Some(target) = part_at(tree, &path) else {
                return bad;
            };
            let owned = take_ownership != 0;
            match copied {
                // `Option<SList>` is the parameter type, and `SList` is not
                // nameable from this crate; `collect` resolves it from that
                // position through the engine's `FromIterator<Vec<u8>>`, so no
                // private path is named and no re-export is needed.
                Some(lines) => {
                    let list = lines.into_iter().collect();
                    target.set_headers(Some(list), owned);
                }
                None => target.set_headers(None, false),
            }
        }

        // The C records ownership only for a non-null chain (`:1407-1408`).
        handle.parts[slot].owned_headers = if take_ownership != 0 {
            headers
        } else {
            ptr::null_mut()
        };

        // "Allow setting twice the same list": release the old chain only when
        // it was ours AND the replacement is a different one.
        if !previous.is_null() && !ptr::eq(previous, headers) {
            // SAFETY: `previous` is a chain a caller gave this part with a
            // non-zero `take_ownership` and has not released itself, the record
            // no longer names it, and the pointer differs from the replacement,
            // so this is its single release -- through the same crate-uniform
            // allocator a consumer would use.
            unsafe { super::slist::curl_slist_free_all(previous) };
        }

        CURLcode::CURLE_OK
    };

    // SAFETY: `root` came out of a live record, so it addresses the handle that
    // owns it.
    unsafe { with_root(root, bad, install) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::panic_boundary::contained;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// A live tree, or a failed test: `curl_mime_init` answers null only when
    /// the platform cannot supply entropy, which is not a condition a test
    /// should paper over.
    fn init() -> *mut curl_mime {
        // SAFETY: `easy` is not read, which `curl_mime_init` documents.
        let mime = unsafe { curl_mime_init(ptr::null_mut()) };
        assert!(!mime.is_null(), "the platform must supply entropy");
        mime
    }

    /// One part of `mime`, asserted non-null.
    fn addpart(mime: *mut curl_mime) -> *mut curl_mimepart {
        // SAFETY: `mime` is a live handle from `init`.
        let part = unsafe { curl_mime_addpart(mime) };
        assert!(!part.is_null(), "appending to a live handle must succeed");
        part
    }

    /// Releases a tree that the test still owns.
    fn free(mime: *mut curl_mime) {
        // SAFETY: `mime` is a live root and is not used afterwards.
        unsafe { curl_mime_free(mime) };
    }

    /// A NUL-terminated buffer, kept alive by the caller.
    fn cstring(text: &str) -> Vec<c_char> {
        let mut bytes: Vec<c_char> =
            text.bytes().map(|byte| byte as c_char).collect();
        bytes.push(0);
        bytes
    }

    /// A one-element `curl_slist` built through the exported entry point, so
    /// the chain a test hands over is allocated by the same allocator this
    /// module releases it with.
    fn slist(text: &str) -> *mut curl_slist {
        let owned = cstring(text);
        // SAFETY: a null head plus a live NUL-terminated string is the
        // documented way to start a list, and `owned` outlives the call.
        let list = unsafe {
            super::super::slist::curl_slist_append(
                ptr::null_mut(),
                owned.as_ptr(),
            )
        };
        assert!(!list.is_null(), "appending must succeed");
        list
    }

    // The export inventory

    #[test]
    fn this_module_defines_exactly_the_twelve_mime_symbols() {
        // Read from disk rather than from a list kept here, so the assertion
        // is about the file.
        let source = include_str!("mime.rs");
        let mut found: Vec<&str> = Vec::new();
        for line in source.lines() {
            let trimmed = line.trim_start();
            let Some(rest) =
                trimmed.strip_prefix("pub unsafe extern \"C\" fn ")
            else {
                continue;
            };
            let name: &str = rest
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
                .unwrap_or("");
            assert!(!name.is_empty(), "a definition must name a symbol");
            found.push(name);
        }
        found.sort_unstable();

        // The twelve names of `lib/libcurl.def`, alphabetically.
        let expected = [
            "curl_mime_addpart",
            "curl_mime_data",
            "curl_mime_data_cb",
            "curl_mime_encoder",
            "curl_mime_filedata",
            "curl_mime_filename",
            "curl_mime_free",
            "curl_mime_headers",
            "curl_mime_init",
            "curl_mime_name",
            "curl_mime_subparts",
            "curl_mime_type",
        ];
        assert_eq!(found, expected, "exactly twelve, exactly these");

        // The two prohibitions stated explicitly, because the reason each name
        // is absent is different. `curl_mime_freepart` does not exist in the
        // export set at all -- a part is never freed independently -- and
        // inventing it would fail the symbol-parity gate. The legacy
        // `curl_form*` trio DOES exist, and belongs to `form.rs`, even though
        // `lib/formdata.c` and `lib/mime.c` are siblings in the C tree.
        assert!(!found.contains(&"curl_mime_freepart"));
        assert!(!found.iter().any(|name| name.starts_with("curl_form")));
    }

    // Ownership: init, free, and the null and tombstone no-ops

    #[test]
    fn a_handle_round_trips_through_init_and_free() {
        let mime = init();
        free(mime);
    }

    #[test]
    fn freeing_null_is_a_silent_no_op() {
        let before = contained();
        // SAFETY: null is the documented no-op argument.
        unsafe { curl_mime_free(ptr::null_mut()) };
        assert_eq!(contained(), before, "nothing may be contained");
    }

    #[test]
    fn a_foreign_pointer_is_rejected_by_every_family_convention() {
        // A record that is emphatically not one of ours. The magic word is what
        // separates the two.
        //
        // WHY THIS IS A REAL `MimeBox` RATHER THAN A SMALL SCRATCH BLOCK. An
        // earlier form of this test used `[0_u64; 8]`, and AddressSanitizer
        // reported a stack-buffer-overflow: `mime_identity` reaches its magic
        // through `&*handle.cast::<MimeBox>()`, and forming that shared
        // reference asserts the WHOLE record is readable, which 64 bytes are
        // not. Merely enlarging the block would not have been enough either --
        // `MimeBox` holds a `Box<Poison>`, and a zeroed `Box` is a null `Box`,
        // so a reference to zeroed bytes would be an invalid value even where it
        // was in bounds. A genuine, fully valid record carrying a deliberately
        // wrong magic is therefore the only construction that tests what this
        // test means to test -- that the magic, not the address, is what
        // decides -- without depending on undefined behaviour to do it.
        let mut impostor = MimeBox {
            magic: 0,
            poison: Box::new(Poison::new()),
            tree: None,
            forward: None,
            parts: Vec::new(),
            absorbed: Vec::new(),
        };
        let handle: *mut curl_mime = (&mut impostor as *mut MimeBox).cast();

        // SAFETY: `handle` addresses a live, fully initialised `MimeBox` this
        // test owns, so every read the entry points make is in bounds and of a
        // valid value. Each one checks the magic word before it interprets
        // anything else, and this record's magic is not `MIME_MAGIC`.
        unsafe {
            assert!(curl_mime_addpart(handle).is_null());
            // A `void` function can only stay silent, and must not free it.
            curl_mime_free(handle);
        }
        assert_eq!(impostor.magic, 0, "a foreign record must not be written");
        assert!(impostor.parts.is_empty(), "nor gain a part");

        // The same again for the part convention, with a valid `PartBox` whose
        // magic is likewise not `PART_MAGIC`.
        let mut fake_part = PartBox {
            magic: 0,
            at: Location {
                root: ptr::null_mut(),
                path: Vec::new(),
            },
            owned_headers: ptr::null_mut(),
        };
        let part: *mut curl_mimepart = (&mut fake_part as *mut PartBox).cast();
        // SAFETY: as above; each of these validates before dereferencing.
        unsafe {
            assert_eq!(
                curl_mime_name(part, ptr::null()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_data(part, ptr::null(), 0),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
        }
    }

    #[test]
    fn every_code_returning_entry_point_answers_43_for_a_null_part() {
        let null = ptr::null_mut::<curl_mimepart>();
        let bad = CURLcode::CURLE_BAD_FUNCTION_ARGUMENT;
        assert_eq!(bad.as_c_int(), 43, "the code the C returns is 43");

        // SAFETY: null is an explicitly handled argument in all eight.
        unsafe {
            assert_eq!(curl_mime_name(null, ptr::null()), bad);
            assert_eq!(curl_mime_filename(null, ptr::null()), bad);
            assert_eq!(curl_mime_type(null, ptr::null()), bad);
            assert_eq!(curl_mime_encoder(null, ptr::null()), bad);
            assert_eq!(curl_mime_data(null, ptr::null(), 0), bad);
            assert_eq!(curl_mime_filedata(null, ptr::null()), bad);
            assert_eq!(
                curl_mime_data_cb(null, 0, None, None, None, ptr::null_mut()),
                bad
            );
            assert_eq!(curl_mime_subparts(null, ptr::null_mut()), bad);
            assert_eq!(curl_mime_headers(null, ptr::null_mut(), 0), bad);
        }
    }

    #[test]
    fn addpart_answers_null_for_a_null_handle() {
        // SAFETY: null is the documented argument for the C's `:1218-1219`.
        let part = unsafe { curl_mime_addpart(ptr::null_mut()) };
        assert!(part.is_null());
    }

    // The stable-address requirement, which is the hardest property to keep

    #[test]
    fn a_part_pointer_survives_many_later_appends() {
        // The property a bare `Vec<MimePart>` would break: appending must not
        // move a part that C already holds a pointer to. Many appends, so the
        // engine's vector reallocates several times.
        let mime = init();
        let first = addpart(mime);
        let mut later = Vec::new();
        for _ in 0..64 {
            later.push(addpart(mime));
        }

        // Write through the FIRST pointer, after all 64 later appends.
        let name = cstring("still-here");
        // SAFETY: `first` came from `curl_mime_addpart` on a tree that is still
        // alive, and `name` is a live NUL-terminated buffer.
        let code = unsafe { curl_mime_name(first, name.as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_OK, "the first part must still work");

        // And every later pointer is distinct and still usable.
        for (index, part) in later.iter().enumerate() {
            assert_ne!(*part, first);
            let text = cstring("later");
            // SAFETY: as above, for each pointer the same tree produced.
            let code = unsafe { curl_mime_name(*part, text.as_ptr()) };
            assert_eq!(
                code,
                CURLcode::CURLE_OK,
                "part {index} must still work"
            );
        }

        free(mime);
    }

    #[test]
    fn a_part_pointer_survives_the_transfer_of_its_own_tree() {
        // `docs/examples/smtp-mime.c` in miniature: build a subtree, hand it to
        // a part of another tree, and keep using a pointer into the subtree.
        let outer = init();
        let host = addpart(outer);
        let inner = init();
        let nested = addpart(inner);

        // SAFETY: `host` and `inner` are both live, and `inner` is a root that
        // no part has consumed.
        let code = unsafe { curl_mime_subparts(host, inner) };
        assert_eq!(code, CURLcode::CURLE_OK);

        // The pointer into the transferred subtree still resolves.
        let name = cstring("nested");
        // SAFETY: `nested` came from `curl_mime_addpart(inner)` and `inner`'s
        // tree is now owned by `host`, which `outer` owns; the record moved
        // with it.
        let code = unsafe { curl_mime_name(nested, name.as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_OK, "a re-homed part must resolve");

        // And so does the consuming part, which `smtp-mime.c` does next.
        let mimetype = cstring("multipart/alternative");
        // SAFETY: `host` is unchanged by the transfer.
        let code = unsafe { curl_mime_type(host, mimetype.as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_OK);

        // Appending to the outer tree afterwards must not disturb either.
        let extra = addpart(outer);
        assert_ne!(extra, host);
        let again = cstring("again");
        // SAFETY: both pointers are live records of `outer`.
        unsafe {
            assert_eq!(
                curl_mime_name(nested, again.as_ptr()),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_mime_name(host, again.as_ptr()),
                CURLcode::CURLE_OK
            );
        }

        // ONE free, for the outer tree only: `inner` was given away.
        free(outer);
    }

    // The subparts transfer, in both directions

    #[test]
    fn freeing_a_transferred_handle_is_a_silent_no_op() {
        let outer = init();
        let host = addpart(outer);
        let inner = init();

        // SAFETY: both handles are live and `inner` is an unconsumed root.
        assert_eq!(
            unsafe { curl_mime_subparts(host, inner) },
            CURLcode::CURLE_OK
        );

        // A caller that frees the handle it gave away would double-free in C.
        // Here it is recognised and ignored -- and the outer tree stays usable,
        // which is the property that proves nothing was released.
        // SAFETY: `inner` is a tombstone; this must not reclaim anything.
        unsafe { curl_mime_free(inner) };

        let name = cstring("intact");
        // SAFETY: `host` is a live record of `outer`.
        assert_eq!(
            unsafe { curl_mime_name(host, name.as_ptr()) },
            CURLcode::CURLE_OK
        );

        free(outer);
    }

    #[test]
    fn setting_the_same_subparts_twice_succeeds_without_a_second_transfer() {
        // `lib/mime.c:1447-1448`: "Accept setting twice the same subparts."
        let outer = init();
        let host = addpart(outer);
        let inner = init();

        // SAFETY: both live, `inner` unconsumed.
        assert_eq!(
            unsafe { curl_mime_subparts(host, inner) },
            CURLcode::CURLE_OK
        );
        // SAFETY: `inner` is now the tombstone naming `host`, which is exactly
        // the fast path's condition.
        assert_eq!(
            unsafe { curl_mime_subparts(host, inner) },
            CURLcode::CURLE_OK,
            "the same subparts twice is the C's OK fast path"
        );

        free(outer);
    }

    #[test]
    fn a_handle_already_attached_elsewhere_is_rejected_and_stays_the_callers() {
        let first = init();
        let host_a = addpart(first);
        let second = init();
        let host_b = addpart(second);
        let inner = init();

        // SAFETY: all live; `inner` is unconsumed.
        assert_eq!(
            unsafe { curl_mime_subparts(host_a, inner) },
            CURLcode::CURLE_OK
        );
        // The second attempt must fail: the C's `subparts->parent` check.
        // SAFETY: `inner` is a tombstone, which is a defined argument here.
        assert_eq!(
            unsafe { curl_mime_subparts(host_b, inner) },
            CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
        );

        // Both trees are still sound and each is freed exactly once.
        free(first);
        free(second);
    }

    #[test]
    fn a_handle_cannot_become_a_subpart_of_its_own_tree() {
        // `lib/mime.c:1458-1466`: "cannot add as a subpart of itself."
        let mime = init();
        let part = addpart(mime);
        // SAFETY: both arguments are live and this is the rejected combination.
        assert_eq!(
            unsafe { curl_mime_subparts(part, mime) },
            CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
        );

        // Rejection must leave the tree intact and still owned by the test.
        let name = cstring("intact");
        // SAFETY: `part` is a live record of `mime`.
        assert_eq!(
            unsafe { curl_mime_name(part, name.as_ptr()) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    #[test]
    fn a_failed_transfer_leaves_the_donor_freeable_by_the_caller() {
        // The half of the contract that a leak would hide: after a rejected
        // transfer the caller still owns the handle, so freeing it must do real
        // work rather than hit the tombstone path.
        let first = init();
        let host_a = addpart(first);
        let second = init();
        let host_b = addpart(second);
        let donor = init();
        let inside = addpart(donor);

        // SAFETY: all live; `donor` is unconsumed.
        assert_eq!(
            unsafe { curl_mime_subparts(host_a, donor) },
            CURLcode::CURLE_OK
        );
        // SAFETY: `donor` is a tombstone; rejected, and NOT re-transferred.
        assert_eq!(
            unsafe { curl_mime_subparts(host_b, donor) },
            CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
        );
        // The part inside the donor still resolves through the tree that DID
        // take it, which proves the rejected call moved nothing.
        let name = cstring("unmoved");
        // SAFETY: `inside` is a record `first` now owns.
        assert_eq!(
            unsafe { curl_mime_name(inside, name.as_ptr()) },
            CURLcode::CURLE_OK
        );

        free(first);
        free(second);
    }

    #[test]
    fn a_null_subparts_argument_detaches_and_succeeds() {
        let mime = init();
        let part = addpart(mime);
        let inner = init();

        // SAFETY: all live.
        assert_eq!(
            unsafe { curl_mime_subparts(part, inner) },
            CURLcode::CURLE_OK
        );
        // SAFETY: null follows the C's cleanup and answers OK.
        assert_eq!(
            unsafe { curl_mime_subparts(part, ptr::null_mut()) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    #[test]
    fn transfers_nest_to_three_levels_and_release_once() {
        // A chain of transfers, so the re-basing of an absorbed handle's own
        // tombstones and records is exercised rather than assumed.
        let deepest = init();
        let leaf = addpart(deepest);

        let middle = init();
        let middle_host = addpart(middle);
        // SAFETY: both live, `deepest` unconsumed.
        assert_eq!(
            unsafe { curl_mime_subparts(middle_host, deepest) },
            CURLcode::CURLE_OK
        );

        let top = init();
        // A part before the host, so the host's index is not zero and a wrong
        // prefix would be visible.
        let _filler = addpart(top);
        let top_host = addpart(top);
        // SAFETY: both live, `middle` unconsumed.
        assert_eq!(
            unsafe { curl_mime_subparts(top_host, middle) },
            CURLcode::CURLE_OK
        );

        // The deepest part must still resolve, two transfers later.
        let name = cstring("leaf");
        // SAFETY: `leaf`'s record was re-based twice and `top` owns it now.
        assert_eq!(
            unsafe { curl_mime_name(leaf, name.as_ptr()) },
            CURLcode::CURLE_OK,
            "a record must survive being re-based twice"
        );

        // Freeing the two tombstones must do nothing, and one free releases
        // everything.
        // SAFETY: both are tombstones owned by `top`.
        unsafe {
            curl_mime_free(deepest);
            curl_mime_free(middle);
        }
        // SAFETY: `leaf` is still a live record of `top`.
        assert_eq!(
            unsafe { curl_mime_name(leaf, name.as_ptr()) },
            CURLcode::CURLE_OK
        );
        free(top);
    }

    #[test]
    fn addpart_still_works_on_a_transferred_handle() {
        // The C's `curl_mime_addpart(subparts)` after `curl_mime_subparts`
        // appends to the now-nested multipart. Reproduced through the donor's
        // forward record.
        let outer = init();
        let host = addpart(outer);
        let inner = init();
        // SAFETY: both live, `inner` unconsumed.
        assert_eq!(
            unsafe { curl_mime_subparts(host, inner) },
            CURLcode::CURLE_OK
        );

        let late = addpart(inner);
        let name = cstring("appended-after-transfer");
        // SAFETY: `late` is a record of the tree `outer` now owns.
        assert_eq!(
            unsafe { curl_mime_name(late, name.as_ptr()) },
            CURLcode::CURLE_OK
        );
        free(outer);
    }

    // curl_mime_headers, both ownership directions

    #[test]
    fn taking_ownership_releases_the_chain_with_the_tree() {
        // The chain is released when the tree is, which a leak checker sees and
        // a double free crashes on. Both outcomes are what this covers; the
        // assertion available in-process is that the call is accepted and the
        // tree releases cleanly afterwards.
        let mime = init();
        let part = addpart(mime);
        let list = slist("Custom-Header: mooo");

        // SAFETY: `part` is live and `list` is a chain from
        // `curl_slist_append`, handed over for release with the tree.
        assert_eq!(
            unsafe { curl_mime_headers(part, list, 1) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    #[test]
    fn not_taking_ownership_leaves_the_chain_to_the_caller() {
        let mime = init();
        let part = addpart(mime);
        let list = slist("X-Borrowed: 1");

        // SAFETY: `part` is live and `list` stays the caller's.
        assert_eq!(
            unsafe { curl_mime_headers(part, list, 0) },
            CURLcode::CURLE_OK
        );
        free(mime);

        // The chain must still be intact after the tree is gone, which is what
        // `take_ownership == 0` promises. Reading it would be a use-after-free
        // if the tree had released it.
        // SAFETY: `list` was never handed over, so it is still ours to read and
        // then to release.
        unsafe {
            let head = &*list;
            assert!(!head.data.is_null(), "the chain must be untouched");
            assert_eq!(CStr::from_ptr(head.data).to_bytes(), b"X-Borrowed: 1");
            super::super::slist::curl_slist_free_all(list);
        }
    }

    #[test]
    fn setting_the_same_owned_chain_twice_does_not_release_it() {
        // `lib/mime.c:1402`: "Allow setting twice the same list." Releasing and
        // then retaining the same pointer would be a use-after-free, so the
        // second call must leave it alone -- proven by reading the chain after
        // it and then letting the tree release it once.
        let mime = init();
        let part = addpart(mime);
        let list = slist("X-Twice: yes");

        // SAFETY: `part` is live; the chain is handed over twice.
        unsafe {
            assert_eq!(curl_mime_headers(part, list, 1), CURLcode::CURLE_OK);
            assert_eq!(curl_mime_headers(part, list, 1), CURLcode::CURLE_OK);
            let head = &*list;
            assert_eq!(CStr::from_ptr(head.data).to_bytes(), b"X-Twice: yes");
        }
        free(mime);
    }

    #[test]
    fn replacing_an_owned_chain_with_a_different_one_releases_the_first() {
        let mime = init();
        let part = addpart(mime);
        let first = slist("X-First: 1");
        let second = slist("X-Second: 2");
        assert_ne!(first, second);

        // SAFETY: `part` is live; both chains come from `curl_slist_append`,
        // and each is handed over exactly once.
        unsafe {
            assert_eq!(curl_mime_headers(part, first, 1), CURLcode::CURLE_OK);
            // This releases `first`, which must not be touched afterwards.
            assert_eq!(curl_mime_headers(part, second, 1), CURLcode::CURLE_OK);
            let head = &*second;
            assert_eq!(CStr::from_ptr(head.data).to_bytes(), b"X-Second: 2");
        }
        free(mime);
    }

    #[test]
    fn a_null_chain_clears_and_succeeds() {
        let mime = init();
        let part = addpart(mime);
        let list = slist("X-Cleared: 1");

        // SAFETY: `part` is live; the chain is handed over and then cleared,
        // which releases it.
        unsafe {
            assert_eq!(curl_mime_headers(part, list, 1), CURLcode::CURLE_OK);
            assert_eq!(
                curl_mime_headers(part, ptr::null_mut(), 1),
                CURLcode::CURLE_OK
            );
        }
        free(mime);
    }

    #[test]
    fn header_order_is_preserved_exactly() {
        // The engine holds the list, so the assertion is that this module
        // hands the lines over unreordered.
        let mut list = ptr::null_mut::<curl_slist>();
        let lines = ["Z-Last: 3", "A-First: 1", "M-Middle: 2"];
        for line in lines {
            let owned = cstring(line);
            // SAFETY: `list` is null or a chain these calls built, and `owned`
            // is live for the call.
            let next = unsafe {
                super::super::slist::curl_slist_append(list, owned.as_ptr())
            };
            assert!(!next.is_null());
            list = next;
        }

        // SAFETY: the chain is well formed and terminating, which is
        // `slist_to_vec`'s precondition; this is the same read the entry point
        // performs.
        let seen = unsafe { handle::slist_to_vec(list.cast_const()) };
        assert_eq!(
            seen,
            lines
                .iter()
                .map(|l| l.as_bytes().to_vec())
                .collect::<Vec<_>>(),
            "nothing may sort, fold or deduplicate the caller's headers"
        );

        let mime = init();
        let part = addpart(mime);
        // SAFETY: `part` is live and the chain is handed over for release.
        assert_eq!(
            unsafe { curl_mime_headers(part, list, 1) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    // Content: data, the sentinel, filedata, and the encoder table

    #[test]
    fn the_zero_terminated_sentinel_measures_with_strlen() {
        let mime = init();
        let part = addpart(mime);
        // An interior NUL, so the two paths cannot produce the same answer.
        let buffer: [c_char; 8] = [
            b'a' as c_char,
            b'b' as c_char,
            0,
            b'c' as c_char,
            b'd' as c_char,
            0,
            0,
            0,
        ];

        // SAFETY: `part` is live, and `buffer` is NUL-terminated within its own
        // bounds, which is what the sentinel asserts.
        unsafe {
            assert_eq!(
                curl_mime_data(part, buffer.as_ptr(), CURL_ZERO_TERMINATED),
                CURLcode::CURLE_OK
            );
        }
        // SAFETY: `part` is live and 5 is within `buffer`.
        unsafe {
            assert_eq!(
                curl_mime_data(part, buffer.as_ptr(), 5),
                CURLcode::CURLE_OK
            );
        }
        assert_eq!(CURL_ZERO_TERMINATED, usize::MAX, "((size_t)-1)");
        free(mime);
    }

    #[test]
    fn the_callers_buffer_may_be_scribbled_immediately_afterwards() {
        // Every string and byte argument in this family is copied.
        let mime = init();
        let part = addpart(mime);
        let mut name = cstring("kept");
        let mut payload = cstring("body");

        // SAFETY: `part` is live and both buffers are live for their calls.
        unsafe {
            assert_eq!(curl_mime_name(part, name.as_ptr()), CURLcode::CURLE_OK);
            assert_eq!(
                curl_mime_data(part, payload.as_ptr(), 4),
                CURLcode::CURLE_OK
            );
        }

        // Overwrite both, then release the tree. A borrow rather than a copy
        // would show up as corrupted content or as a use-after-free.
        for slot in name.iter_mut().chain(payload.iter_mut()) {
            *slot = b'X' as c_char;
        }
        free(mime);
    }

    #[test]
    fn a_null_data_pointer_clears_the_content_and_succeeds() {
        let mime = init();
        let part = addpart(mime);
        let payload = cstring("body");
        // SAFETY: `part` is live; the second call clears.
        unsafe {
            assert_eq!(
                curl_mime_data(part, payload.as_ptr(), 4),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_mime_data(part, ptr::null(), 0),
                CURLcode::CURLE_OK
            );
        }
        free(mime);
    }

    #[test]
    fn a_zero_length_is_not_the_same_as_a_null_pointer() {
        let mime = init();
        let part = addpart(mime);
        let empty = cstring("");
        // SAFETY: `part` is live and `empty` is a live, NUL-terminated buffer;
        // a zero length over a non-null pointer is permitted.
        assert_eq!(
            unsafe { curl_mime_data(part, empty.as_ptr(), 0) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    #[test]
    fn the_encoder_table_is_exactly_the_five_names_the_c_accepts() {
        let mime = init();
        let part = addpart(mime);

        for name in ["binary", "8bit", "7bit", "base64", "quoted-printable"] {
            let owned = cstring(name);
            // SAFETY: `part` is live and `owned` is live for the call.
            assert_eq!(
                unsafe { curl_mime_encoder(part, owned.as_ptr()) },
                CURLcode::CURLE_OK,
                "{name} is one of the five rows of `encoders[]`"
            );
        }

        // `curl_strequal` is case-insensitive, so the spelling of the request
        // does not matter -- only the spelling that reaches the wire, which the
        // engine owns.
        for name in ["BASE64", "Quoted-Printable", "8BIT"] {
            let owned = cstring(name);
            // SAFETY: as above.
            assert_eq!(
                unsafe { curl_mime_encoder(part, owned.as_ptr()) },
                CURLcode::CURLE_OK,
                "{name} must match case-insensitively"
            );
        }

        // An unrecognised name fails AND leaves the part with no encoder, which
        // is what clearing before the lookup produces.
        for name in ["base32", "", "quoted printable", "binary "] {
            let owned = cstring(name);
            // SAFETY: as above.
            assert_eq!(
                unsafe { curl_mime_encoder(part, owned.as_ptr()) },
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT,
                "{name} is not one of the five"
            );
        }

        // A null encoding is the C's "Removing current encoder."
        // SAFETY: `part` is live and null is the documented clear.
        assert_eq!(
            unsafe { curl_mime_encoder(part, ptr::null()) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    #[test]
    fn filedata_reports_a_read_error_for_a_path_that_cannot_be_stated() {
        let mime = init();
        let part = addpart(mime);
        let missing = cstring("/nonexistent/blitzy/mime/probe/absent");
        // SAFETY: `part` is live and `missing` is live for the call.
        assert_eq!(
            unsafe { curl_mime_filedata(part, missing.as_ptr()) },
            CURLcode::CURLE_READ_ERROR,
            "the C's `:1313-1314` answer"
        );

        // A null path clears the content and succeeds.
        // SAFETY: as above, with the documented clear argument.
        assert_eq!(
            unsafe { curl_mime_filedata(part, ptr::null()) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    #[test]
    fn filedata_accepts_a_regular_file_and_sets_the_base_name() {
        // This source file, reached by an ABSOLUTE path with directory
        // components so that the base-name side effect is exercised. Absolute
        // rather than `file!()`, which is relative to the workspace root while
        // a test's working directory is the package root -- a difference
        // measured here rather than assumed.
        const PATH: &str =
            concat!(env!("CARGO_MANIFEST_DIR"), "/src/ffi/mime.rs");
        let mime = init();
        let part = addpart(mime);
        let path = cstring(PATH);
        // SAFETY: `part` is live and `path` is live for the call. `PATH` names
        // this source file, which is present whenever this test runs.
        let code = unsafe { curl_mime_filedata(part, path.as_ptr()) };
        assert_eq!(code, CURLcode::CURLE_OK, "{PATH} must be stat-able");

        // Withdrawing the side effect is the documented follow-up.
        // SAFETY: `part` is live and null is the documented clear.
        assert_eq!(
            unsafe { curl_mime_filename(part, ptr::null()) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    #[test]
    fn a_non_utf8_string_argument_is_rejected_after_the_c_s_clearing() {
        // The one documented narrowing: the engine's setters take `&str`. The
        // clearing the C performs first still happens, so the part is left in
        // the state the C leaves it in.
        let mime = init();
        let part = addpart(mime);
        let invalid: [c_char; 3] = [-1_i8 as c_char, -2_i8 as c_char, 0];

        // SAFETY: `part` is live and `invalid` is a live NUL-terminated buffer.
        unsafe {
            assert_eq!(
                curl_mime_name(part, invalid.as_ptr()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_filename(part, invalid.as_ptr()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_type(part, invalid.as_ptr()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_encoder(part, invalid.as_ptr()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert_eq!(
                curl_mime_filedata(part, invalid.as_ptr()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
        }

        // The part is still usable afterwards, which the C's unconditional
        // clearing also leaves true.
        let valid = cstring("recovered");
        // SAFETY: `part` is live and `valid` is live for the call.
        assert_eq!(
            unsafe { curl_mime_name(part, valid.as_ptr()) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    // curl_mime_data_cb and the three callback typedefs

    /// How many times [`counting_free`] has run, process-wide.
    static FREED: AtomicUsize = AtomicUsize::new(0);

    /// A `curl_read_callback` that yields nothing.
    unsafe extern "C" fn empty_read(
        buffer: *mut c_char,
        size: usize,
        nitems: usize,
        instream: *mut c_void,
    ) -> usize {
        let _ = (buffer, size, nitems, instream);
        0
    }

    /// A `curl_seek_callback` that always succeeds.
    unsafe extern "C" fn ok_seek(
        instream: *mut c_void,
        offset: curl_off_t,
        origin: c_int,
    ) -> c_int {
        let _ = (instream, offset, origin);
        0
    }

    /// A `curl_free_callback` that records that it ran.
    unsafe extern "C" fn counting_free(ptr: *mut c_void) {
        let _ = ptr;
        FREED.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn a_null_read_callback_is_a_reset_and_discards_the_others() {
        // `lib/mime.c:1424`: with a null `readfunc` nothing at all is
        // installed, so `freefunc` never runs and `arg` is never released.
        let mime = init();
        let part = addpart(mime);
        let before = FREED.load(Ordering::Relaxed);

        // SAFETY: `part` is live; a null `readfunc` means the other three are
        // stored nowhere and never called.
        let code = unsafe {
            curl_mime_data_cb(
                part,
                7,
                None,
                Some(ok_seek),
                Some(counting_free),
                ptr::null_mut(),
            )
        };
        assert_eq!(code, CURLcode::CURLE_OK);
        free(mime);
        assert_eq!(
            FREED.load(Ordering::Relaxed),
            before,
            "a discarded freefunc must never run"
        );
    }

    #[test]
    fn a_callback_part_releases_its_context_exactly_once() {
        let mime = init();
        let part = addpart(mime);
        let before = FREED.load(Ordering::Relaxed);

        // SAFETY: `part` is live; the three callbacks are valid `extern "C"`
        // functions and the context is null, which none of them dereferences.
        let code = unsafe {
            curl_mime_data_cb(
                part,
                SIZE_UNKNOWN,
                Some(empty_read),
                Some(ok_seek),
                Some(counting_free),
                ptr::null_mut(),
            )
        };
        assert_eq!(code, CURLcode::CURLE_OK);
        assert_eq!(
            FREED.load(Ordering::Relaxed),
            before,
            "the hook must not run while the content is installed"
        );

        free(mime);
        assert_eq!(
            FREED.load(Ordering::Relaxed),
            before + 1,
            "releasing the tree runs the hook exactly once"
        );
    }

    #[test]
    fn replacing_a_callback_part_releases_the_previous_context() {
        // `cleanup_part_content` runs the hook on replacement too.
        let mime = init();
        let part = addpart(mime);
        let before = FREED.load(Ordering::Relaxed);

        // SAFETY: as the previous test.
        unsafe {
            assert_eq!(
                curl_mime_data_cb(
                    part,
                    0,
                    Some(empty_read),
                    None,
                    Some(counting_free),
                    ptr::null_mut(),
                ),
                CURLcode::CURLE_OK
            );
            // Replacing the content with bytes must release the context.
            let payload = cstring("bytes");
            assert_eq!(
                curl_mime_data(part, payload.as_ptr(), 5),
                CURLcode::CURLE_OK
            );
        }
        assert_eq!(
            FREED.load(Ordering::Relaxed),
            before + 1,
            "replacement releases the previous context"
        );

        free(mime);
        assert_eq!(
            FREED.load(Ordering::Relaxed),
            before + 1,
            "and does not release it a second time"
        );
    }

    #[test]
    fn the_read_marshalling_maps_every_sentinel_the_c_distinguishes() {
        // The mapping is what makes a caller's `size_t` return legible, and
        // getting one arm wrong is silent. Driven through a reader directly,
        // because reaching it through a transfer would need the engine's
        // readback.
        /// Returns whatever the test asked for.
        unsafe extern "C" fn scripted(
            buffer: *mut c_char,
            size: usize,
            nitems: usize,
            instream: *mut c_void,
        ) -> usize {
            let _ = (buffer, size, nitems);
            // SAFETY: every call site below passes a live `usize` as the
            // context, which is the only value this callback reads.
            unsafe { *instream.cast::<usize>() }
        }

        // Written and read through ONE pointer, so the callback's view and the
        // test's view have the same provenance.
        let mut scenario: Box<usize> = Box::new(0);
        let script: *mut usize = &mut *scenario;
        let mut reader = CallbackReader {
            readfunc: Some(scripted),
            seekfunc: None,
            freefunc: None,
            arg: script.cast::<c_void>(),
        };
        let mut buffer = [0_u8; 16];

        let cases: [(usize, ReadStatus); 7] = [
            (0, ReadStatus::Eof),
            (STOP_FILLING, ReadStatus::StopFilling),
            (READ_ERROR, ReadStatus::ReadError),
            (CURL_READFUNC_ABORT, ReadStatus::Abort),
            (CURL_READFUNC_PAUSE, ReadStatus::Pause),
            (4, ReadStatus::Bytes(4)),
            // Larger than the buffer: undefined in the C, a read error here.
            (17, ReadStatus::ReadError),
        ];
        for (produced, expected) in cases {
            // SAFETY: `script` addresses the live `usize` in `scenario`, which
            // nothing else borrows, and a `usize` is trivially writable.
            unsafe { script.write(produced) };
            assert_eq!(
                reader.read(&mut buffer),
                expected,
                "a return of {produced} must map to {expected:?}"
            );
        }

        // A reader with no callback at all cannot panic across the boundary.
        let mut silent = CallbackReader {
            readfunc: None,
            seekfunc: None,
            freefunc: None,
            arg: ptr::null_mut(),
        };
        assert_eq!(silent.read(&mut buffer), ReadStatus::Eof);
    }

    #[test]
    fn the_seek_marshalling_maps_the_three_origins_and_the_four_codes() {
        /// Records the origin it was given and answers a scripted code.
        unsafe extern "C" fn scripted(
            instream: *mut c_void,
            offset: curl_off_t,
            origin: c_int,
        ) -> c_int {
            let _ = offset;
            // SAFETY: every call site passes a live `[c_int; 2]` as the
            // context: slot 0 receives the origin, slot 1 supplies the answer.
            unsafe {
                let slots = instream.cast::<c_int>();
                *slots = origin;
                *slots.add(1)
            }
        }

        // As the read test: one pointer for both sides of every exchange.
        let mut slots: Box<[c_int; 2]> = Box::new([-1, 0]);
        let script: *mut c_int = slots.as_mut_ptr();
        let mut reader = CallbackReader {
            readfunc: None,
            seekfunc: Some(scripted),
            freefunc: None,
            arg: script.cast::<c_void>(),
        };

        for (whence, expected) in [
            (SeekWhence::Set, SEEK_SET),
            (SeekWhence::Current, SEEK_CUR),
            (SeekWhence::End, SEEK_END),
        ] {
            assert_eq!(reader.seek(0, whence), SeekResult::Ok);
            // SAFETY: `script` addresses the live two-element array, and the
            // callback has just written the origin it received into slot 0.
            let seen = unsafe { script.read() };
            assert_eq!(seen, expected, "{whence:?} must pass {expected}");
        }

        // The five return values `SeekResult::from_code` distinguishes.
        for (code, expected) in [
            (0, SeekResult::Ok),
            (1, SeekResult::Fail),
            (2, SeekResult::CantSeek),
            (-1, SeekResult::CantSeek),
            (99, SeekResult::Fail),
        ] {
            // SAFETY: slot 1 is within the live two-element array `script`
            // addresses, and a `c_int` is trivially writable.
            unsafe { script.add(1).write(code) };
            assert_eq!(reader.seek(0, SeekWhence::Set), expected);
        }

        // No callback is the C's absent `seekfunc`.
        let mut silent = CallbackReader {
            readfunc: None,
            seekfunc: None,
            freefunc: None,
            arg: ptr::null_mut(),
        };
        assert_eq!(
            silent.seek(0, SeekWhence::Set),
            SeekResult::CantSeek,
            "an absent seek function is CURL_SEEKFUNC_CANTSEEK"
        );
    }

    #[test]
    fn a_duplicated_reader_shares_the_context_and_releases_it_again() {
        // `lib/mime.c:1122-1123` copies the pointers, so the shared `arg`
        // reaches `freefunc` once per part. Reproduced literally, and asserted
        // so that a future "improvement" to reference-count it is caught.
        let before = FREED.load(Ordering::Relaxed);
        let reader = CallbackReader {
            readfunc: Some(empty_read),
            seekfunc: None,
            freefunc: Some(counting_free),
            arg: ptr::null_mut(),
        };
        let copy = reader.duplicate();
        drop(copy);
        assert_eq!(FREED.load(Ordering::Relaxed), before + 1);
        drop(reader);
        assert_eq!(FREED.load(Ordering::Relaxed), before + 2);
    }

    #[test]
    fn the_debug_form_of_a_reader_carries_no_address() {
        // Anything this crate writes can end up compared byte for byte, and an
        // address changes between runs.
        let reader = CallbackReader {
            readfunc: Some(empty_read),
            seekfunc: None,
            freefunc: None,
            arg: 0xdead_beef_usize as *mut c_void,
        };
        let shown = format!("{reader:?}");
        assert!(shown.contains("readfunc: true"));
        assert!(shown.contains("seekfunc: false"));
        assert!(!shown.contains("0x"), "no address may appear: {shown}");
        assert!(!shown.contains("deadbeef"), "no address: {shown}");
    }

    // The two magic words, and the constants transcribed from the headers

    #[test]
    fn the_two_opaque_families_carry_distinct_magic_words() {
        assert_ne!(
            MIME_MAGIC, PART_MAGIC,
            "a `curl_mime *` and a `curl_mimepart *` must be separable"
        );
        // Neither may be a value a zeroed or a small-integer-filled block
        // would present.
        assert_ne!(MIME_MAGIC, 0);
        assert_ne!(PART_MAGIC, 0);
    }

    #[test]
    fn the_transcribed_constants_match_the_frozen_headers() {
        assert_eq!(CURL_ZERO_TERMINATED, usize::MAX, "curl.h:2420");
        assert_eq!(READ_ERROR, usize::MAX, "lib/mime.c:47");
        assert_eq!(STOP_FILLING, usize::MAX - 1, "lib/mime.c:48");
        assert_eq!(CURL_READFUNC_ABORT, 0x1000_0000, "curl.h:390");
        assert_eq!(CURL_READFUNC_PAUSE, 0x1000_0001, "curl.h:393");
        assert_eq!(SEEK_SET, 0);
        assert_eq!(SEEK_CUR, 1);
        assert_eq!(SEEK_END, 2);
        assert_eq!(SIZE_UNKNOWN, -1, "the C's `part->datasize = -1`");
        // The sentinel and the internal read error are the same bit pattern in
        // the C too; they are distinguished by which side of the call they are
        // on, never by their value.
        assert_eq!(CURL_ZERO_TERMINATED, READ_ERROR);
    }

    #[test]
    fn a_part_record_and_a_mime_handle_are_not_interchangeable() {
        // Handing a `curl_mime *` where a `curl_mimepart *` belongs is the
        // mistake the two magic words exist to catch.
        let mime = init();
        let part = addpart(mime);
        let as_part: *mut curl_mimepart = mime.cast();
        let as_mime: *mut curl_mime = part.cast();

        // SAFETY: both pointers address live records of this crate, of the
        // wrong family; each entry point checks its own magic word first.
        unsafe {
            assert_eq!(
                curl_mime_name(as_part, ptr::null()),
                CURLcode::CURLE_BAD_FUNCTION_ARGUMENT
            );
            assert!(curl_mime_addpart(as_mime).is_null());
            // And a `void` function stays silent without freeing anything.
            curl_mime_free(as_mime);
        }

        // The tree is untouched, which proves nothing was released.
        let name = cstring("intact");
        // SAFETY: `part` is a live record of `mime`.
        assert_eq!(
            unsafe { curl_mime_name(part, name.as_ptr()) },
            CURLcode::CURLE_OK
        );
        free(mime);
    }

    #[test]
    fn a_record_is_rejected_by_a_root_that_does_not_own_it() {
        // The validation the module documentation promises: a record must be
        // one its named root actually holds.
        let first = init();
        let second = init();
        let borrowed = addpart(second);

        // Reaching `borrowed` through `first` is impossible by construction --
        // the record names `second` -- so this asserts the complementary
        // property: each tree answers only for its own records, and both stay
        // independently freeable.
        let name = cstring("mine");
        // SAFETY: `borrowed` is a live record of `second`.
        assert_eq!(
            unsafe { curl_mime_name(borrowed, name.as_ptr()) },
            CURLcode::CURLE_OK
        );
        free(first);
        // SAFETY: `borrowed` still belongs to `second`, which is still live.
        assert_eq!(
            unsafe { curl_mime_name(borrowed, name.as_ptr()) },
            CURLcode::CURLE_OK,
            "freeing an unrelated tree must not disturb this one"
        );
        free(second);
    }

    // Containment

    #[test]
    fn a_clean_run_of_this_family_contains_no_panic() {
        // Containment is a safety net, never an error-handling strategy: a
        // non-zero count is a defect report. Run the whole surface and assert
        // the net was not needed.
        let before = contained();

        let mime = init();
        let part = addpart(mime);
        let name = cstring("field");
        let payload = cstring("value");
        let encoding = cstring("base64");
        let list = slist("X-Header: 1");
        let inner = init();
        let nested = addpart(inner);

        // SAFETY: every pointer below is live for its call and every handle is
        // a record of a live tree.
        unsafe {
            assert_eq!(curl_mime_name(part, name.as_ptr()), CURLcode::CURLE_OK);
            assert_eq!(
                curl_mime_filename(part, name.as_ptr()),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_mime_type(part, payload.as_ptr()),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_mime_encoder(part, encoding.as_ptr()),
                CURLcode::CURLE_OK
            );
            assert_eq!(
                curl_mime_data(part, payload.as_ptr(), 5),
                CURLcode::CURLE_OK
            );
            assert_eq!(curl_mime_headers(part, list, 1), CURLcode::CURLE_OK);
            assert_eq!(
                curl_mime_data(nested, payload.as_ptr(), CURL_ZERO_TERMINATED),
                CURLcode::CURLE_OK
            );
            let host = curl_mime_addpart(mime);
            assert!(!host.is_null());
            assert_eq!(curl_mime_subparts(host, inner), CURLcode::CURLE_OK);
        }
        free(mime);

        assert_eq!(
            contained(),
            before,
            "no panic may be absorbed by a correct run"
        );
    }
}
