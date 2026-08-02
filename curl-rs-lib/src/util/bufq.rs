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

//! The chunked byte queue -- supersedes `lib/bufq.c` (619 lines) and
//! `lib/bufq.h` (258 lines).
//!
//! # Read from the head, write to the tail
//!
//! Every function in this file follows from one sentence of `bufq.h:64-65`:
//! *"A queue of byte chunks for reading and writing. Reading is done from
//! `head`, writing is done to `tail`."* A queue is a list of fixed-size
//! chunks; bytes enter at the back and leave at the front, and a chunk that
//! has been read empty leaves the list from the front.
//!
//! # Why this module is behaviour rather than plumbing
//!
//! `bufq` is the buffering substrate of the connection-filter chain. The
//! HTTP/2 stream buffers, the HTTP/3 datagram staging area, the TLS filter's
//! plaintext and ciphertext staging, `cf-socket`'s send and receive queues
//! and the WebSocket frame assembler all sit on it. It is also where curl
//! expresses backpressure: `CURLE_AGAIN` out of a `bufq` is how "would
//! block" travels up the filter chain. Its full and empty predicates and its
//! partial-transfer semantics are therefore part of the frozen contract of
//! AAP 0.8.1, not an implementation detail this file is free to improve.
//!
//! One asymmetry deserves stating before anything else, because inverting it
//! deadlocks the filter chain: **a partial transfer is a success.**
//! `CURLE_AGAIN` is returned only when NOTHING moved. `Ok(n)` with
//! `n < buf.len()` means "some bytes moved, ask again later";
//! `Err(CURLcode::Again)` means "no byte moved at all".
//!
//! # What the migration removed, and why the removals are evidence
//!
//! AAP 0.6.9 names this file directly, and three of the four hazard classes
//! it enumerates are all present in this one translation unit. Each is
//! removed by construction rather than by care:
//!
//! * **Manual buffer arithmetic.** `struct buf_chunk` (`bufq.h:33-42`) ends
//!   in `union { uint8_t data[1]; void *dummy; }` -- C's flexible-array-member
//!   idiom with a pointer-sized alignment forcer -- and is allocated as
//!   `calloc(1, sizeof(*chunk) + chunk_size)`. Pointer, length and capacity
//!   are then tracked by hand across every `memcpy`. `Box<[u8]>` replaces the
//!   whole arrangement: one allocation, correct alignment, and a length the
//!   type carries. The `dlen` field disappears into `data.len()`.
//!
//!   Two consequences are worth recording as evidence rather than being left
//!   as silent omissions. The C carries an integer-overflow guard at
//!   `bufq.c:167-174` and again at `bufq.c:303-307` --
//!   `if(chunk_size > SIZE_MAX - sizeof(*chunk))` -- because it adds a header
//!   size to a caller-supplied payload size before allocating. **Both guards
//!   are gone from this file, because the addition they guard is gone.**
//!   There is no `sizeof(header) + payload` arithmetic left to overflow.
//!
//! * **An intrusive singly-linked list.** `struct buf_chunk` begins with
//!   `struct buf_chunk *next` and `struct bufq` carries `head`, `tail` and
//!   `spare` pointers into three separate chains threaded through the same
//!   field. `VecDeque<Chunk>` replaces the head-to-tail chain and `Vec<Chunk>`
//!   the spare list, so the `next` field disappears entirely and with it the
//!   "detach the head, and if the head WAS the tail move the tail too"
//!   bookkeeping of `bufq.c:323-326`. See [`BufQ::prune_head`].
//!
//! * **Two untyped callback contexts.** `Curl_bufq_writer` and
//!   `Curl_bufq_reader` (`bufq.h:206-208` and `:221-223`) each take a
//!   `void *ctx` that every implementation casts to its own type. AAP 0.6.9
//!   calls the untyped context *"the single largest source of unsound
//!   patterns in the C tree"* and design pattern P2 of AAP 0.3.3 mandates a
//!   typed one. Here both become generic closure bounds --
//!   `FnMut(&[u8]) -> CodeResult<usize>` for a writer and
//!   `FnMut(&mut [u8]) -> CodeResult<usize>` for a reader -- so the context
//!   is whatever the closure captured, checked by the compiler. No pointer
//!   crosses the boundary and no cast is written.
//!
//! `Curl_bufq_cwrite` (`bufq.c:394-399`) and `Curl_bufq_cread`
//! (`bufq.c:417-421`) have **no successor here.** Their entire bodies are a
//! cast between `char *` and `uint8_t *`, a distinction Rust does not have:
//! `&[u8]` is the byte type. Two identical wrappers would be noise, so
//! [`BufQ::write`] and [`BufQ::read`] stand for all four C entry points.
//!
//! # Why the chunk is `Box<[u8]>` and not `BytesMut`
//!
//! `docs/internals/BUFQ.md:256-259` describes the specified successor as
//! using *"`bytes::BytesMut` for a segment and an owned collection such as
//! `VecDeque` for the queue itself"*. The deque is used. The segment is
//! `Box<[u8]>`, and the same page states the reason two paragraphs later:
//! *"It copies wherever the C code copies and borrows wherever the C code
//! borrows: no copy that `lib/bufq.c` performs is claimed to disappear, and
//! none is added."*
//!
//! `BytesMut` earns its keep through cheap reference-counted splitting, which
//! is the one thing this module must not do -- a split segment changes WHEN a
//! chunk becomes reusable, and the spare-list and pool arithmetic that
//! `Self::prune_head` implements is observable through
//! `BufQ::is_full`. A chunk is also fixed size at creation, so the growth
//! `BytesMut` provides has nothing to grow. `Box<[u8]>` is exactly one
//! allocation of exactly the requested size, which is what
//! `calloc(1, sizeof(*chunk) + chunk_size)` was, and it adds no dependency.
//!
//! # The one thing that is deliberately NOT optimised
//!
//! [`BufQ::len`] walks the whole chain on every call, exactly as
//! `Curl_bufq_len` does at `bufq.c:255-264`. Caching a running total would be
//! faster and is refused: performance is an explicit non-goal of AAP 0.1.1,
//! and a cached total that one mutation path forgot to update would be a
//! silent correctness bug in the code that decides whether a transfer can
//! make progress. Faithfulness wins.
//!
//! # Panics
//!
//! None. Every offset is read through the clamping `Chunk::readable` and
//! `Chunk::written` accessors, so no slice range this file constructs can be
//! out of bounds; every accumulator uses a saturating form; and the shared
//! pool is reached through `try_borrow_mut` so that even a re-entrant caller
//! degrades to a fresh allocation rather than a panic.
//! The two `DEBUGASSERT` preconditions on chunk and queue sizes become value
//! clamps, which is strictly stronger -- see [`BufQ::with_opts`].

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::ops::BitOr;
use std::rc::Rc;

use crate::error::{CURLcode, CodeResult};

// EVERY `pub(crate)` ITEM IN THIS FILE CARRIES `#[allow(dead_code)]`, AND WHY
//
// `util` is the base of this crate's module graph, so its consumers are the
// last code to exist. Every consumer of this file named in AAP 0.4.1 --
// `conn/filters.rs`, `conn/socket.rs`, `protocols/http2.rs`,
// `protocols/http3.rs`, `protocols/ws.rs`, `tls/rustls_backend.rs`,
// `transfer/request.rs` and `transfer/sendf.rs` -- is a separate unit of work
// that has yet to land. Until then every item here is legitimately
// unreferenced outside the test module, and the zero-warnings build gate
// would otherwise fail on code that is correct.
//
// The allowance is written per item, never on the module and never as an
// inner attribute, because a lint level on a module root silences the NEXT
// item somebody adds instead of the ones inventoried today. That rule is
// enforced executably by the gate named
// `no_lint_level_for_dead_code_is_set_on_a_crate_or_module_root` in
// `src/lib.rs`, and the surrounding reasoning is recorded once in
// `util/mod.rs` rather than repeated here. Each attribute is deleted when its
// consumer lands.
//
// The private items -- `Chunk` and its methods, `BufQ::get_spare`,
// `BufQ::prune_head`, `BufQ::ensure_non_full_tail` and `BufQ::slurpn` -- carry
// no attribute and need none: rustc treats an item marked
// `#[allow(dead_code)]` as a live root, so everything those items reach is
// live too.

/// The queue behaviour flags -- supersedes the `BUFQ_OPT_*` macros of
/// `bufq.h:103-116`.
///
/// A newtype over `u32` rather than a bare integer, so that a queue option
/// and a byte count cannot be confused, and rather than a dependency on a
/// bitflag crate, because AAP 0.5.1 fixes the dependency set and three flags
/// do not justify adding to it.
///
/// `u32` rather than the C's `int opts` deliberately: the engine speaks in
/// fixed-width Rust integers and the C scalar widths live only in the FFI
/// island. That boundary is enforced executably by
/// `c_scalar_types_appear_only_inside_the_ffi_island` in `src/lib.rs`.
///
/// # The three flags, and exactly what each one changes
///
/// * [`BufqOpts::NONE`] is the default, and it makes `max_chunks` a **hard**
///   limit. From `bufq.h:103-106`: *"attempts to write more bytes than can be
///   hold in `max_chunks` is refused and will return -1, CURLE_AGAIN."*
///
/// * [`BufqOpts::SOFT_LIMIT`] makes the same limit soft. From
///   `bufq.h:108-111` the queue *"will report that it is 'full' when
///   `max_chunks` are used, but allows writing beyond this limit."* Two
///   consequences follow and both are reproduced: [`BufQ::is_full`] still
///   answers `true`, and [`BufQ::len`] can exceed
///   `max_chunks * chunk_size`. `bufq.h:80-83` gives the motive -- it exists
///   *"for situation where writes preferably never fail (except for memory
///   exhaustion)."*
///
/// * [`BufqOpts::NO_SPARES`] stops the queue retaining emptied chunks. From
///   `bufq.h:85-87`: by default *"a bufq will keep chunks that read empty in
///   its `spare` list"*, and this flag frees them the moment they empty.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct BufqOpts(u32);

impl BufqOpts {
    /// No option set: a hard chunk limit and retained spares.
    ///
    /// Supersedes `BUFQ_OPT_NONE` (`bufq.h:107`), whose value is `0`, which
    /// is also what `Default` produces for this newtype.
    #[allow(dead_code)]
    pub(crate) const NONE: Self = Self(0);

    /// Permit writing past `max_chunks` while still reporting "full".
    ///
    /// Supersedes `BUFQ_OPT_SOFT_LIMIT` (`bufq.h:112`), whose value is
    /// `1 << 0`.
    #[allow(dead_code)]
    pub(crate) const SOFT_LIMIT: Self = Self(1 << 0);

    /// Free an emptied chunk instead of keeping it as a spare.
    ///
    /// Supersedes `BUFQ_OPT_NO_SPARES` (`bufq.h:116`), whose value is
    /// `1 << 1`.
    #[allow(dead_code)]
    pub(crate) const NO_SPARES: Self = Self(1 << 1);

    /// True when every flag set in `other` is also set in `self`.
    ///
    /// Stands where the C writes `q->opts & BUFQ_OPT_SOFT_LIMIT` as a truth
    /// test, at `bufq.c:294` and `bufq.c:332` and `bufq.c:379`.
    #[allow(dead_code)]
    pub(crate) const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// The raw flag word, for the accessor that mirrors the C struct field.
    #[allow(dead_code)]
    pub(crate) const fn bits(self) -> u32 {
        self.0
    }
}

impl BitOr for BufqOpts {
    type Output = Self;

    /// Combines two flag sets, standing where C writes
    /// `BUFQ_OPT_SOFT_LIMIT | BUFQ_OPT_NO_SPARES`.
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// One fixed-size buffer -- supersedes `struct buf_chunk` (`bufq.h:33-42`).
///
/// Three of the C struct's five members survive. `dlen` becomes
/// `data.len()`, so the size cannot disagree with the allocation, and `next`
/// vanishes with the intrusive list. What remains is the pair of offsets that
/// define the readable span, and the invariant that binds them:
///
/// ```text
///   0 <= r_offset <= w_offset <= data.len()
///
///   data:  [ already read | readable | unwritten ]
///          0            r_offset   w_offset   len()
/// ```
///
/// The invariant holds on every path in this file, and the two accessors
/// `readable` and `written` enforce it a second time by clamping, so that a
/// slice range constructed from them is in bounds whether or not the
/// invariant held. That is the whole reason this file cannot panic.
struct Chunk {
    /// The buffer. One allocation of a fixed size, replacing the C's
    /// `calloc(1, sizeof(*chunk) + chunk_size)` over a flexible array member.
    data: Box<[u8]>,
    /// Offset of the first unread byte. `r_offset` in the C.
    r_offset: usize,
    /// Offset one past the last written byte. `w_offset` in the C.
    w_offset: usize,
}

impl fmt::Debug for Chunk {
    /// Reports the offsets and the capacity, never the bytes.
    ///
    /// Written by hand rather than derived because a derived `Debug` would
    /// dump the whole buffer into every failing assertion message, which for
    /// the 16 kilobyte chunks the connection filters use is unreadable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("len", &self.len())
            .field("r_offset", &self.r_offset)
            .field("w_offset", &self.w_offset)
            .field("dlen", &self.data.len())
            .finish()
    }
}

impl Chunk {
    /// Allocates a zeroed chunk of exactly `size` bytes.
    ///
    /// The C allocates with `calloc` at `bufq.c:176` and `bufq.c:309`, so the
    /// buffer starts zeroed; `vec![0; size]` matches that. Neither
    /// implementation depends on the zeroes -- the write offset is what makes
    /// a byte readable -- but matching the C costs nothing and keeps an
    /// uninitialised-read question from ever arising.
    fn new(size: usize) -> Self {
        Self {
            data: vec![0_u8; size].into_boxed_slice(),
            r_offset: 0,
            w_offset: 0,
        }
    }

    /// The write offset, clamped into the buffer.
    ///
    /// Every slice range in this file is built from this and [`Self::readable`]
    /// so that it is valid by construction. Under the struct invariant the
    /// clamp is the identity.
    fn written(&self) -> usize {
        self.w_offset.min(self.data.len())
    }

    /// The read offset, clamped to at most [`Self::written`].
    ///
    /// Clamping against the write offset rather than the buffer length is
    /// what makes `readable() <= written()` unconditional, so the subtraction
    /// in [`Self::len`] and the range `readable()..written()` are both always
    /// well formed.
    fn readable(&self) -> usize {
        self.r_offset.min(self.written())
    }

    /// The number of bytes available to read.
    ///
    /// Supersedes `chunk_len` (`bufq.c:38-41`), whose body is
    /// `w_offset - r_offset`.
    fn len(&self) -> usize {
        self.written().saturating_sub(self.readable())
    }

    /// True when nothing is available to read.
    ///
    /// Supersedes `chunk_is_empty` (`bufq.c:28-31`), whose body is
    /// `r_offset >= w_offset`. Written as that literal comparison rather than
    /// as `len() == 0`, which is the same predicate here but is not the same
    /// sentence.
    fn is_empty(&self) -> bool {
        self.r_offset >= self.w_offset
    }

    /// True when nothing more can be written.
    ///
    /// Supersedes `chunk_is_full` (`bufq.c:33-36`), whose body is
    /// `w_offset >= dlen`.
    fn is_full(&self) -> bool {
        self.w_offset >= self.data.len()
    }

    /// Returns the chunk to its freshly allocated state.
    ///
    /// Supersedes `chunk_reset` (`bufq.c:43-47`). The C also clears `next`,
    /// which has no successor. Note what it does NOT do: **the data bytes are
    /// not zeroed.** That is faithful and it is safe, because the offsets are
    /// the only thing that makes a byte readable and [`Self::len`] bounds
    /// every read to bytes that have been written since this reset.
    fn reset(&mut self) {
        self.r_offset = 0;
        self.w_offset = 0;
    }

    /// Copies as much of `buf` as fits and returns how much that was.
    ///
    /// Supersedes `chunk_append` (`bufq.c:49-61`), which copies
    /// `CURLMIN(dlen - w_offset, len)` bytes and advances `w_offset`. A zero
    /// return means the chunk is full, which is how the write loop learns to
    /// ask for another chunk.
    fn append(&mut self, buf: &[u8]) -> usize {
        let start = self.written();
        let free = self.data.len().saturating_sub(start);
        if free == 0 {
            return 0;
        }
        let n = free.min(buf.len());
        let end = start.saturating_add(n);
        self.data[start..end].copy_from_slice(&buf[..n]);
        self.w_offset = end;
        n
    }

    /// Copies out as much as `buf` holds and returns how much that was.
    ///
    /// Supersedes `chunk_read` (`bufq.c:63-82`), including the detail that is
    /// easy to lose: when the request drains the chunk completely the C sets
    /// **both** offsets back to zero (`bufq.c:74`) rather than only advancing
    /// the read offset. That matters twice over -- the chunk then answers
    /// `is_empty()`, so `prune_head` retires it, and it also answers
    /// `is_full() == false`, so a chunk that is still the tail becomes
    /// writable again from the start of its buffer.
    fn read_into(&mut self, buf: &mut [u8]) -> usize {
        let start = self.readable();
        let end = self.written();
        let available = end.saturating_sub(start);
        if available == 0 {
            return 0;
        }
        if available <= buf.len() {
            buf[..available].copy_from_slice(&self.data[start..end]);
            self.r_offset = 0;
            self.w_offset = 0;
            available
        } else {
            let taken = buf.len();
            let stop = start.saturating_add(taken);
            buf.copy_from_slice(&self.data[start..stop]);
            self.r_offset = stop;
            taken
        }
    }

    /// The readable span, without consuming it.
    ///
    /// Supersedes `chunk_peek` (`bufq.c:106-112`), which hands back
    /// `&data[r_offset]` and the length `w_offset - r_offset`. The two C
    /// out-parameters become one slice, which is the same information with
    /// the pointer and the length no longer able to disagree.
    fn peek(&self) -> &[u8] {
        &self.data[self.readable()..self.written()]
    }

    /// The readable span starting `offset` bytes in.
    ///
    /// Supersedes `chunk_peek_at` (`bufq.c:114-121`), which adds `offset` to
    /// `r_offset` and hands back the remainder of the written region. The
    /// caller guarantees `offset < len()`; the `min` keeps the range valid
    /// even if it does not.
    fn peek_at(&self, offset: usize) -> &[u8] {
        let end = self.written();
        let start = self.readable().saturating_add(offset).min(end);
        &self.data[start..end]
    }

    /// Discards up to `amount` readable bytes and returns how many.
    ///
    /// Supersedes `chunk_skip` (`bufq.c:123-134`), which advances `r_offset`
    /// by `CURLMIN(w_offset - r_offset, amount)` and then applies the same
    /// both-offsets-to-zero reset as `chunk_read` once the chunk is drained
    /// (`bufq.c:130-131`).
    fn skip(&mut self, amount: usize) -> usize {
        let available = self.len();
        if available == 0 {
            return 0;
        }
        let n = available.min(amount);
        self.r_offset = self.readable().saturating_add(n);
        if self.r_offset >= self.w_offset {
            self.r_offset = 0;
            self.w_offset = 0;
        }
        n
    }

    /// Calls `reader` once to fill the free space, and commits what it read.
    ///
    /// Supersedes `chunk_slurpn` (`bufq.c:84-104`). Three details are
    /// reproduced exactly:
    ///
    /// * no free space is `CURLE_AGAIN`, not `Ok(0)` (`bufq.c:94-95`);
    /// * a non-zero `max_len` caps the slice offered to the reader, while
    ///   `max_len == 0` offers all the free space (`bufq.c:96-97`);
    /// * the write offset advances **only** when the reader succeeded
    ///   (`bufq.c:99-102`), which the `?` operator gives for free.
    ///
    /// Where the C has `DEBUGASSERT(*pnread <= n)` this clamps instead: a
    /// reader that reports having filled more than the slice it was handed is
    /// a caller bug, and the clamp confines it to a wrong byte count rather
    /// than letting it push the write offset past the buffer.
    fn slurpn<R>(&mut self, max_len: usize, mut reader: R) -> CodeResult<usize>
    where
        R: FnMut(&mut [u8]) -> CodeResult<usize>,
    {
        let start = self.written();
        let free = self.data.len().saturating_sub(start);
        if free == 0 {
            return Err(CURLcode::Again);
        }
        let offered = if max_len == 0 {
            free
        } else {
            free.min(max_len)
        };
        let end = start.saturating_add(offered);
        let nread = reader(&mut self.data[start..end])?.min(offered);
        self.w_offset = start.saturating_add(nread);
        Ok(nread)
    }
}

/// A shared pool of same-sized chunks -- supersedes `struct bufc_pool`
/// (`bufq.h:51-56`).
///
/// # The threading contract, unchanged
///
/// Quoted from `bufq.h:47-49`: *"The same pool can be shared by many `bufq`
/// instances. However, a pool is not thread safe. All bufqs using it are
/// supposed to operate in the same thread."*
///
/// That contract is why the sharing handle is [`SharedPool`] and why
/// [`SharedPool`] is a single type alias. See its documentation for the
/// trade-off it isolates.
///
/// # This type has no observable behaviour
///
/// A pool is pure allocation reuse. Whether a chunk came from a pool, from a
/// queue's own spare list or straight from the allocator changes nothing a
/// caller of [`BufQ`] can detect: the bytes, the lengths, the predicates and
/// the error codes are all identical. It exists because `Curl_bufq_initp` is
/// part of the interface the HTTP/2 layer uses, and it is deliberately kept
/// out of the read and write paths -- the only two places that consult it are
/// [`BufQ::get_spare`] and [`BufQ::prune_head`], one call each.
///
/// # What the migration removed
///
/// The C's `spare_count` field is gone: it exists only because a singly
/// linked list has no length, and `Vec::len` is that length. The C's
/// `SIZE_MAX - sizeof(*chunk)` overflow guard at `bufq.c:167-174` is gone
/// with the flexible array member it protected.
#[derive(Debug)]
pub(crate) struct ChunkPool {
    /// Chunks available for reuse. `Vec` push and pop are both at the back,
    /// so reuse is last-in-first-out exactly as the C's push-at-head and
    /// pop-at-head list is.
    spare: Vec<Chunk>,
    /// The size of every chunk this pool hands out.
    chunk_size: usize,
    /// How many spares to keep before freeing rather than hoarding.
    spare_max: usize,
}

/// The handle by which several queues share one [`ChunkPool`].
///
/// # The one line to change, and what it would cost
///
/// `Rc<RefCell<..>>` is single-threaded sharing, which is exactly the
/// contract `bufq.h:47-49` states: a pool is not thread-safe and every queue
/// using it runs in one thread. It is spelled as an alias, in one place,
/// because AAP 0.8.3 specifies a **multi-thread** async runtime for the multi
/// handle beside a **current-thread** one for the command-line tool. If a
/// consumer on the multi-thread side ever needs a pool to be `Send`, this
/// single line becomes `Arc<Mutex<ChunkPool>>` and nothing else in the file
/// moves -- the two call sites already treat acquisition as fallible.
///
/// Naming the runtime crate here was avoided deliberately: this module is
/// synchronous and must stay that way, so the file carries no reference to an
/// async runtime at all, not even in prose.
///
/// Making that substitution now was rejected under the minimal-change
/// mandate: it would buy a capability nothing asks for, at the cost of a lock
/// on a hot allocation path and of overstating the contract the C documents.
/// Recording the trade-off is the point; hiding the choice inside a concrete
/// type at every use site would not have been a choice a reader could find.
#[allow(dead_code)]
pub(crate) type SharedPool = Rc<RefCell<ChunkPool>>;

impl ChunkPool {
    /// Creates a pool of `chunk_size` buffers keeping at most `spare_max`.
    ///
    /// Supersedes `Curl_bufcp_init` (`bufq.c:146-154`).
    ///
    /// The C opens with `DEBUGASSERT(chunk_size > 0)` and
    /// `DEBUGASSERT(spare_max > 0)`. Both become value clamps here, for the
    /// reason set out at [`BufQ::with_opts`]: an assertion that a release
    /// build removes leaves the hazard it was documenting, and the clamp is
    /// the identity for every caller that honours the precondition.
    #[allow(dead_code)]
    pub(crate) fn new(chunk_size: usize, spare_max: usize) -> Self {
        Self {
            spare: Vec::new(),
            chunk_size: chunk_size.max(1),
            spare_max: spare_max.max(1),
        }
    }

    /// The size of every chunk this pool hands out.
    ///
    /// Stands for the direct read of `pool->chunk_size` that
    /// `Curl_bufq_initp` performs at `bufq.c:232`.
    #[allow(dead_code)]
    pub(crate) fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// How many spare chunks are currently held.
    ///
    /// Stands for the C's `spare_count` field, which this implementation does
    /// not need to maintain because `Vec` knows its own length.
    #[allow(dead_code)]
    pub(crate) fn spare_count(&self) -> usize {
        self.spare.len()
    }

    /// The spare ceiling this pool was built with.
    #[allow(dead_code)]
    pub(crate) fn spare_max(&self) -> usize {
        self.spare_max
    }

    /// Hands out a chunk, reusing a spare when one is available.
    ///
    /// Supersedes `bufcp_take` (`bufq.c:156-184`), less its two failure
    /// paths. The C returns `CURLE_OUT_OF_MEMORY` for an overflowing size
    /// computation (`bufq.c:170-174`) and for a failed `calloc`
    /// (`bufq.c:177-180`). The first has no successor because the computation
    /// is gone; the second has none because a Rust allocation failure aborts
    /// the process rather than returning. What remains is infallible, so this
    /// returns a `Chunk` and not a `Result`.
    fn take(&mut self) -> Chunk {
        if let Some(mut chunk) = self.spare.pop() {
            chunk.reset();
            return chunk;
        }
        Chunk::new(self.chunk_size)
    }

    /// Takes a chunk back, keeping it only while under the spare ceiling.
    ///
    /// Supersedes `bufcp_put` (`bufq.c:186-198`). The branch that matters is
    /// the first: at or above `spare_max` the C **frees the chunk outright**
    /// (`bufq.c:189-191`) rather than growing the pool, so a burst of traffic
    /// cannot leave the pool holding memory for ever. Dropping `chunk` here is
    /// that `free`.
    fn put(&mut self, mut chunk: Chunk) {
        if self.spare.len() >= self.spare_max {
            drop(chunk);
            return;
        }
        chunk.reset();
        self.spare.push(chunk);
    }

    /// Releases every spare chunk.
    ///
    /// Supersedes `Curl_bufcp_free` (`bufq.c:200-204`), which frees the spare
    /// list and zeroes `spare_count`. Clearing the `Vec` does both. The pool
    /// stays usable afterwards and will allocate again on demand, exactly as
    /// the C does.
    #[allow(dead_code)]
    pub(crate) fn free(&mut self) {
        self.spare.clear();
    }
}

/// The chunked byte queue -- supersedes `struct bufq` (`bufq.h:92-101`).
///
/// Reading is from the front, writing is to the back. `VecDeque` names those
/// ends `front` and `back` where the C names them `head` and `tail`, and the
/// correspondence is exact:
///
/// ```text
///   C                       here
///   ------------------      --------------------------
///   q->head                 self.chunks.front()
///   q->tail                 self.chunks.back()
///   q->head == NULL         self.chunks.is_empty()
///   chunk->next             (gone: the deque holds the order)
///   q->spare                self.spare
///   q->chunk_count          self.chunk_count
/// ```
///
/// # The `chunk_count` invariant
///
/// `chunk_count` counts the chunks in the queue **plus** those on the spare
/// list -- the C's comment at `bufq.h:97` says so, and `prune_head` depends on
/// it: moving a chunk from the queue to the spare list leaves the count
/// untouched (`bufq.c:339-342`) while disposing of it decrements
/// (`bufq.c:329`, `:337`). Getting that wrong breaks the hard chunk limit in a
/// way that only shows after several fill-and-drain cycles, which is exactly
/// why the field is carried explicitly here rather than being recomputed:
/// this file mirrors the C's arithmetic step for step, and
/// `chunk_count_tracks_the_queue_and_the_spare_list` asserts after every
/// mutation that it still equals `chunks.len() + spare.len()`.
#[derive(Debug)]
pub(crate) struct BufQ {
    /// The head-to-tail chain: `front` is the head to read from, `back` is the
    /// tail to write to.
    chunks: VecDeque<Chunk>,
    /// Emptied chunks kept for reuse. Always empty when `pool` is `Some`,
    /// except immediately after [`Self::reset`], which returns chunks here
    /// rather than to the pool exactly as `bufq.c:243-253` does.
    spare: Vec<Chunk>,
    /// The optional shared pool. When present it owns chunk creation and
    /// spare handling, as `bufq.h:89-90` describes.
    pool: Option<SharedPool>,
    /// Chunks in `chunks` plus chunks in `spare`. See the type documentation.
    chunk_count: usize,
    /// The chunk ceiling, hard by default and soft under
    /// [`BufqOpts::SOFT_LIMIT`].
    max_chunks: usize,
    /// The size of every chunk this queue allocates.
    chunk_size: usize,
    /// The behaviour flags.
    opts: BufqOpts,
}

impl BufQ {
    /// Creates a queue of at most `max_chunks` chunks of `chunk_size` bytes,
    /// with a hard chunk limit.
    ///
    /// Supersedes `Curl_bufq_init` (`bufq.c:224-227`), which delegates to the
    /// shared initialiser with a null pool and `BUFQ_OPT_NONE`.
    #[allow(dead_code)]
    pub(crate) fn new(chunk_size: usize, max_chunks: usize) -> Self {
        Self::with_opts(chunk_size, max_chunks, BufqOpts::NONE)
    }

    /// Creates a queue with explicit options.
    ///
    /// Supersedes `Curl_bufq_init2` (`bufq.c:218-222`) and, with it, the
    /// shared `bufq_init` (`bufq.c:206-216`) that both C constructors call.
    ///
    /// # The two `DEBUGASSERT` preconditions, and why they became clamps
    ///
    /// `bufq_init` opens with `DEBUGASSERT(chunk_size > 0)` and
    /// `DEBUGASSERT(max_chunks > 0)` (`bufq.c:209-210`). A `debug_assert!`
    /// would be the literal translation and is not what this file does,
    /// because the literal translation keeps the hazard the assertion only
    /// documents. In a release build `DEBUGASSERT` compiles away, and a
    /// zero-size chunk then makes every chunk both empty and full at once: a
    /// queue carrying [`BufqOpts::SOFT_LIMIT`] never refuses a chunk, so
    /// [`Self::write`] allocates zero-length chunks for ever and the transfer
    /// hangs.
    ///
    /// Clamping to one removes that outcome in every build. It is not a
    /// behaviour change under AAP 0.8.1: for any caller that honours the
    /// precondition the C states, `max(1)` is the identity, so no observable
    /// behaviour of any correct caller moves. For a caller that does not, a
    /// defined outcome replaces an unbounded loop. That is the trade the
    /// migration exists to make.
    #[allow(dead_code)]
    pub(crate) fn with_opts(
        chunk_size: usize,
        max_chunks: usize,
        opts: BufqOpts,
    ) -> Self {
        Self {
            chunks: VecDeque::new(),
            spare: Vec::new(),
            pool: None,
            chunk_count: 0,
            max_chunks: max_chunks.max(1),
            chunk_size: chunk_size.max(1),
            opts,
        }
    }

    /// Creates a queue that draws its chunks from a shared pool.
    ///
    /// Supersedes `Curl_bufq_initp` (`bufq.c:229-233`). Note where the chunk
    /// size comes from: the C reads `pool->chunk_size` rather than taking a
    /// size parameter, so the pool decides and every queue sharing it agrees.
    #[allow(dead_code)]
    pub(crate) fn with_pool(
        pool: &SharedPool,
        max_chunks: usize,
        opts: BufqOpts,
    ) -> Self {
        // Borrowed only to read the size. Falling back to one on a contended
        // borrow rather than panicking is the same policy as the two other
        // pool call sites; see `Self::get_spare`.
        let chunk_size = match pool.try_borrow() {
            Ok(pool) => pool.chunk_size(),
            Err(_) => 1,
        };
        Self {
            chunks: VecDeque::new(),
            spare: Vec::new(),
            pool: Some(Rc::clone(pool)),
            chunk_count: 0,
            max_chunks: max_chunks.max(1),
            chunk_size: chunk_size.max(1),
            opts,
        }
    }

    /// The size of every chunk this queue allocates.
    ///
    /// An accessor rather than a field because `struct bufq` is a public C
    /// struct whose fields consumers read directly -- `lib/request.c:79` and
    /// `:387` and `lib/vquic/curl_ngtcp2.c:2040` all read
    /// `sendbuf.chunk_size` -- so a readable field is part of the contract
    /// being reproduced.
    #[allow(dead_code)]
    pub(crate) fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// The chunk ceiling this queue was built with.
    #[allow(dead_code)]
    pub(crate) fn max_chunks(&self) -> usize {
        self.max_chunks
    }

    /// Chunks held by the queue plus chunks held on its spare list.
    ///
    /// See the type documentation for why the two are counted together.
    #[allow(dead_code)]
    pub(crate) fn chunk_count(&self) -> usize {
        self.chunk_count
    }

    /// The behaviour flags this queue was built with.
    #[allow(dead_code)]
    pub(crate) fn opts(&self) -> BufqOpts {
        self.opts
    }

    /// Empties the queue while keeping its buffers.
    ///
    /// Supersedes `Curl_bufq_reset` (`bufq.c:243-253`), and it is worth
    /// contrasting with [`Self::free`] because the two look alike and are not:
    /// this one *"will keep any allocated buffer chunks around"*
    /// (`bufq.h:136-137`) so that the next write reuses them.
    ///
    /// Three details of the C are reproduced rather than tidied:
    ///
    /// * every chunk moves to the spare list **even when a pool is
    ///   attached** -- the C never consults `q->pool` here;
    /// * `chunk_count` is not touched, which is consistent because the count
    ///   spans the queue and the spare list and the chunks merely moved
    ///   between them;
    /// * the chunks are not reset. `Self::get_spare` resets on reuse
    ///   (`bufq.c:290`), so resetting here as well would be redundant.
    #[allow(dead_code)]
    pub(crate) fn reset(&mut self) {
        while let Some(chunk) = self.chunks.pop_front() {
            self.spare.push(chunk);
        }
    }

    /// Releases every buffer the queue holds.
    ///
    /// Supersedes `Curl_bufq_free` (`bufq.c:235-241`), which frees the head
    /// chain and the spare list and zeroes `chunk_count`. Note that the C does
    /// not hand chunks back to an attached pool here either; it frees them.
    ///
    /// This is an ordinary method and not a `Drop` implementation, because the
    /// C calls it mid-life -- `lib/request.c:80` frees a send buffer and
    /// immediately re-initialises it with a different chunk size -- so the
    /// queue has to stay usable afterwards, and it is. Dropping a `BufQ`
    /// releases the same memory with no code at all.
    #[allow(dead_code)]
    pub(crate) fn free(&mut self) {
        self.chunks.clear();
        self.spare.clear();
        self.chunk_count = 0;
    }

    /// The total number of bytes available to read.
    ///
    /// Supersedes `Curl_bufq_len` (`bufq.c:255-264`), which walks the whole
    /// head chain summing `chunk_len`. Linear in the number of chunks, and
    /// deliberately uncached -- see the module documentation.
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.chunks.iter().map(Chunk::len).sum()
    }

    /// True when the queue has no byte to read.
    ///
    /// Supersedes `Curl_bufq_is_empty` (`bufq.c:266-269`), whose body is
    /// `!q->head || chunk_is_empty(q->head)`.
    ///
    /// # This inspects the HEAD chunk only
    ///
    /// It is not `len() == 0`, and it is not rewritten to be. The two agree
    /// whenever `Self::prune_head` has run, which is on every path that can
    /// empty a chunk, so in every state a caller can observe they answer
    /// alike. They are still different sentences, and the C's is the one the
    /// filter chain was written against, so the C's is the one reproduced.
    /// `is_empty_reads_only_the_head_chunk` pins the distinction with a
    /// hand-built state in which the two differ.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        match self.chunks.front() {
            None => true,
            Some(head) => head.is_empty(),
        }
    }

    /// True when the queue has no room to write.
    ///
    /// Supersedes `Curl_bufq_is_full` (`bufq.c:271-281`). The C has four
    /// branches and the ORDER of the first is the part most easily lost, so
    /// each is transcribed below against its lines.
    #[allow(dead_code)]
    pub(crate) fn is_full(&self) -> bool {
        // Branch 1 (`bufq.c:273-274`): `if(!q->tail || q->spare)`. No tail
        // means nothing has been written yet, so there is room. A spare
        // chunk means room can be made WITHOUT allocating -- which is why
        // this test comes before any limit test and not after it.
        let Some(tail) = self.chunks.back() else {
            return false;
        };
        if !self.spare.is_empty() {
            return false;
        }
        // Branch 2 (`bufq.c:275-276`): under the ceiling, so another chunk
        // may still be created.
        if self.chunk_count < self.max_chunks {
            return false;
        }
        // Branch 3 (`bufq.c:277-278`): over the ceiling. Reachable only
        // under `BufqOpts::SOFT_LIMIT`, which is what allows the count past
        // the maximum in the first place.
        if self.chunk_count > self.max_chunks {
            return true;
        }
        // Branch 4 (`bufq.c:279-280`): exactly at the ceiling with no
        // spares, so the answer is whether the tail itself has room.
        tail.is_full()
    }

    /// Obtains a chunk to write into, or `None` when the limit refuses one.
    ///
    /// Supersedes `get_spare` (`bufq.c:283-316`). Four branches in the C's
    /// order:
    fn get_spare(&mut self) -> Option<Chunk> {
        // 1 (`bufq.c:287-292`): a local spare is free for the taking, and is
        // reset before reuse. `chunk_count` already counts it, so it is NOT
        // incremented here.
        if let Some(mut chunk) = self.spare.pop() {
            chunk.reset();
            return Some(chunk);
        }

        // 2 (`bufq.c:294-295`): THE HARD-LIMIT REFUSAL. At or above the
        // ceiling with no spare and no soft limit, the answer is no, and it
        // is this `None` that becomes `CURLE_AGAIN` in `Self::write`.
        if self.chunk_count >= self.max_chunks
            && !self.opts.contains(BufqOpts::SOFT_LIMIT)
        {
            return None;
        }

        // 3 (`bufq.c:297-302`) and 4 (`bufq.c:303-315`): take from the pool
        // when one is attached, otherwise allocate. Both increment the count.
        //
        // The pool is reached through `try_borrow_mut` rather than
        // `borrow_mut`. A contended borrow cannot arise from this file -- the
        // borrow lives for one non-reentrant call and no reader or writer
        // closure is invoked while it is held -- but a pool is shared, a
        // consumer could reach one from inside a closure, and allocating a
        // chunk directly is observationally identical to taking one from the
        // pool because the pool has no observable behaviour. A guaranteed
        // absence of panics is worth more than reusing one buffer.
        let chunk = match self.pool.as_ref().and_then(|pool| {
            pool.try_borrow_mut().ok().map(|mut pool| pool.take())
        }) {
            Some(chunk) => chunk,
            None => Chunk::new(self.chunk_size),
        };
        self.chunk_count = self.chunk_count.saturating_add(1);
        Some(chunk)
    }

    /// Retires empty chunks from the front of the queue.
    ///
    /// Supersedes `prune_head` (`bufq.c:318-344`), the most intricate function
    /// in the C file.
    ///
    /// # What `VecDeque` removed
    ///
    /// The C detaches the head and then repairs the tail pointer:
    /// `q->head = chunk->next; if(q->tail == chunk) q->tail = q->head;`
    /// (`bufq.c:324-326`). That second line exists only because `head` and
    /// `tail` are two independent pointers into one chain and the last chunk
    /// is pointed at by both. **`pop_front` subsumes both lines**, and with
    /// them the possibility of a tail left dangling at a freed chunk. The
    /// deque also makes the C's `head == NULL` and `tail == NULL` agree by
    /// construction rather than by discipline.
    ///
    /// # The three disposal routes, all preserved
    fn prune_head(&mut self) {
        // Hoisted out of the loop, and cloned rather than borrowed, so that
        // holding the pool handle does not conflict with assigning to
        // `self.chunk_count` below. Cloning an `Rc` is a counter bump.
        let pool = self.pool.clone();

        while self.chunks.front().is_some_and(Chunk::is_empty) {
            let Some(chunk) = self.chunks.pop_front() else {
                break;
            };
            if let Some(pool) = pool.as_ref() {
                // Route 1 (`bufq.c:327-330`): give it back to the pool. The
                // count drops whether or not the pool chose to keep it --
                // `ChunkPool::put` frees past `spare_max` -- because either
                // way this queue no longer holds it.
                if let Ok(mut pool) = pool.try_borrow_mut() {
                    pool.put(chunk);
                }
                self.chunk_count = self.chunk_count.saturating_sub(1);
            } else if self.chunk_count > self.max_chunks
                || self.opts.contains(BufqOpts::NO_SPARES)
            {
                // Route 2 (`bufq.c:331-338`): free it. The C's own comment
                // explains both halves of the test -- "SOFT_LIMIT allowed us
                // more than max. free spares until we are at max again. Or
                // free them if we are configured to not use spares."
                drop(chunk);
                self.chunk_count = self.chunk_count.saturating_sub(1);
            } else {
                // Route 3 (`bufq.c:339-342`): keep it as a spare. NOTE that
                // `chunk_count` is deliberately NOT decremented: the count
                // spans the queue and the spare list, and the chunk has only
                // moved between them.
                self.spare.push(chunk);
            }
        }
    }

    /// Makes sure the back of the queue is a chunk with room to write.
    ///
    /// Supersedes `get_non_full_tail` (`bufq.c:346-365`), returning whether it
    /// succeeded rather than a reference to the chunk. The C's "new tail, and
    /// possibly new head" splice (`bufq.c:354-362`) is `push_back`, and the
    /// `DEBUGASSERT(!q->head)` guarding its empty-queue case is unnecessary
    /// once one deque holds both ends.
    ///
    /// A `bool` rather than `Option<&mut Chunk>` on purpose: the caller needs
    /// `self.chunk_count` and `self.opts` on the failure path, and a returned
    /// mutable reference would keep the borrow of `self` alive across that
    /// branch.
    fn ensure_non_full_tail(&mut self) -> bool {
        // `bufq.c:350-351`: an existing tail with room is the tail.
        if self.chunks.back().is_some_and(|tail| !tail.is_full()) {
            return true;
        }
        // `bufq.c:352-364`: otherwise obtain a chunk and splice it on.
        match self.get_spare() {
            Some(chunk) => {
                self.chunks.push_back(chunk);
                true
            }
            None => false,
        }
    }

    /// Copies `buf` onto the end of the queue and reports how much was taken.
    ///
    /// Supersedes `Curl_bufq_write` (`bufq.c:367-392`) and, with it,
    /// `Curl_bufq_cwrite` (`bufq.c:394-399`), whose body is a cast.
    ///
    /// # Errors
    ///
    /// * `CURLcode::Again` when the queue was full and **not one byte** was
    ///   taken (`bufq.c:391`). A short write is `Ok`, never this.
    /// * `CURLcode::OutOfMemory` when a chunk was permitted but could not be
    ///   obtained (`bufq.c:379-381`) -- the C selects this over `Again` with
    ///   the test `chunk_count < max_chunks || SOFT_LIMIT`, meaning "we were
    ///   allowed another chunk and did not get one". It is reproduced because
    ///   callers match on it, and it is very nearly unreachable here: the two
    ///   C conditions that raise it are an overflowing size computation that
    ///   no longer exists and a `calloc` failure that in Rust aborts instead
    ///   of returning. Keeping it costs one branch and keeps the contract
    ///   whole.
    ///
    /// # Partial writes
    ///
    /// `Ok(n)` with `n < buf.len()` is the normal way a full queue reports
    /// itself, and callers depend on being able to retry with the remainder.
    /// Returning `Again` for a short write instead would stall the filter
    /// chain.
    ///
    /// Writing an empty slice is `Ok(0)`: the C's loop never runs and its
    /// final test needs a non-zero remaining length to choose `Again`
    /// (`bufq.c:391`). Contrast [`Self::read`], which is `Again` for an empty
    /// destination.
    ///
    /// # Termination
    ///
    /// Each turn of the loop either appends at least one byte, which shortens
    /// `remaining`, or breaks. There is no path that repeats without progress.
    #[allow(dead_code)]
    pub(crate) fn write(&mut self, buf: &[u8]) -> CodeResult<usize> {
        let mut written = 0_usize;
        let mut remaining = buf;

        while !remaining.is_empty() {
            if !self.ensure_non_full_tail() {
                // `bufq.c:378-383`.
                if self.chunk_count < self.max_chunks
                    || self.opts.contains(BufqOpts::SOFT_LIMIT)
                {
                    return Err(CURLcode::OutOfMemory);
                }
                break;
            }
            // `bufq.c:384-386`. The `None` arm cannot be taken -- the call
            // above just guaranteed a tail -- and yielding zero exits the
            // loop rather than assuming it.
            let n = match self.chunks.back_mut() {
                Some(tail) => tail.append(remaining),
                None => 0,
            };
            if n == 0 {
                break;
            }
            written = written.saturating_add(n);
            remaining = remaining.get(n..).unwrap_or(&[]);
        }

        // `bufq.c:391`.
        if written == 0 && !remaining.is_empty() {
            Err(CURLcode::Again)
        } else {
            Ok(written)
        }
    }

    /// Copies bytes off the front of the queue and reports how many.
    ///
    /// Supersedes `Curl_bufq_read` (`bufq.c:401-415`) and, with it,
    /// `Curl_bufq_cread` (`bufq.c:417-421`), whose body is a cast.
    ///
    /// # Errors
    ///
    /// `CURLcode::Again` when **nothing** was read (`bufq.c:414`). A short
    /// read is `Ok`, exactly as a short write is.
    ///
    /// Note the asymmetry with [`Self::write`], which is faithful and not an
    /// oversight: reading into an empty destination is `Err(Again)`, because
    /// the C's final test asks only whether anything was read and an empty
    /// destination guarantees nothing was.
    ///
    /// # Termination
    ///
    /// Each turn either advances `nread`, or reads zero -- which happens only
    /// when the front chunk is empty, and `Self::prune_head` then removes it.
    /// So `(buf.len() - nread) + self.chunks.len()` strictly decreases every
    /// turn and the loop cannot spin.
    #[allow(dead_code)]
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> CodeResult<usize> {
        let mut nread = 0_usize;

        // `bufq.c:405`: `while(len && q->head)`.
        while nread < buf.len() && !self.chunks.is_empty() {
            let n = match (self.chunks.front_mut(), buf.get_mut(nread..)) {
                (Some(head), Some(dest)) => head.read_into(dest),
                _ => 0,
            };
            nread = nread.saturating_add(n);
            // `bufq.c:412`: pruned every turn, not only when something moved.
            self.prune_head();
        }

        // `bufq.c:414`.
        if nread == 0 {
            Err(CURLcode::Again)
        } else {
            Ok(nread)
        }
    }

    /// Borrows the readable span of the head chunk without consuming it.
    ///
    /// Supersedes `Curl_bufq_peek` (`bufq.c:423-436`). `None` stands for the C
    /// returning `FALSE` with a null pointer and a zero length; a `Some` span
    /// is never empty.
    ///
    /// # This takes `&mut self`, and must keep doing so
    ///
    /// The C signature takes a non-const `struct bufq *` and the body earns
    /// it: an empty head is pruned first (`bufq.c:426-428`), so peeking can
    /// retire a chunk. Relaxing this to `&self` would be a lie about what the
    /// call does.
    ///
    /// # The head chunk only
    ///
    /// The span stops at the end of the head chunk even when later chunks
    /// hold more. Stitching the queue into one contiguous view would be a
    /// different function with a different cost, and callers that need to
    /// cross a boundary use [`Self::peek_at`].
    ///
    /// The C header promises that *"repeated calls return the same
    /// information until the buffer queue is modified, see
    /// `Curl_bufq_skip()`"* (`bufq.h:190-191`). Here the borrow checker
    /// enforces that promise instead of documenting it: the returned slice
    /// borrows the queue, so no call that could modify it compiles while the
    /// slice is alive.
    #[allow(dead_code)]
    pub(crate) fn peek(&mut self) -> Option<&[u8]> {
        // `bufq.c:426-428`.
        if self.chunks.front().is_some_and(Chunk::is_empty) {
            self.prune_head();
        }
        // `bufq.c:429-435`.
        match self.chunks.front() {
            Some(head) if !head.is_empty() => Some(head.peek()),
            _ => None,
        }
    }

    /// Borrows the readable span beginning `offset` bytes into the queue.
    ///
    /// Supersedes `Curl_bufq_peek_at` (`bufq.c:438-459`), which walks the
    /// chain subtracting each chunk's length until the offset falls inside
    /// one. The returned span still stops at that chunk's end.
    ///
    /// Takes `&self`, not `&mut self`: unlike [`Self::peek`] the C body does
    /// not prune, so nothing here needs to mutate. The C signature is
    /// non-const only because the two functions are declared alike.
    ///
    /// # The walk stops at the first empty chunk
    ///
    /// `if(!clen) break;` (`bufq.c:446-447`) leaves the loop at an empty
    /// chunk rather than stepping over it, so an offset that would have been
    /// satisfied by a later chunk reports `None`. That is reproduced
    /// literally. It is not reachable through the ordinary interface, where
    /// `Self::prune_head` keeps interior chunks non-empty, which is precisely
    /// why it must not be quietly "fixed": the behaviour is the specification
    /// and the state is one a future caller could construct.
    #[allow(dead_code)]
    pub(crate) fn peek_at(&self, offset: usize) -> Option<&[u8]> {
        let mut offset = offset;
        for chunk in &self.chunks {
            let clen = chunk.len();
            // `bufq.c:446-447`.
            if clen == 0 {
                break;
            }
            // `bufq.c:448-452`.
            if offset >= clen {
                offset = offset.saturating_sub(clen);
                continue;
            }
            // `bufq.c:453-454`.
            return Some(chunk.peek_at(offset));
        }
        // `bufq.c:456-458`.
        None
    }

    /// Discards up to `amount` bytes from the front of the queue.
    ///
    /// Supersedes `Curl_bufq_skip` (`bufq.c:461-470`). Per `bufq.h:200-202`,
    /// *"skipping more buf than is currently buffered will just empty the
    /// queue"* -- there is no error and no report of how much was skipped,
    /// matching the C's `void` return.
    ///
    /// # Termination
    ///
    /// The same argument as [`Self::read`]: a turn that skips nothing has an
    /// empty head chunk, which `Self::prune_head` then removes, so
    /// `amount + self.chunks.len()` strictly decreases and asking to skip
    /// more than is buffered cannot loop.
    #[allow(dead_code)]
    pub(crate) fn skip(&mut self, amount: usize) {
        let mut amount = amount;
        // `bufq.c:465`: `while(amount && q->head)`.
        while amount > 0 && !self.chunks.is_empty() {
            let n = match self.chunks.front_mut() {
                Some(head) => head.skip(amount),
                None => 0,
            };
            amount = amount.saturating_sub(n);
            self.prune_head();
        }
    }

    /// Hands the queue's contents to `writer` and reports how much it took.
    ///
    /// Supersedes `Curl_bufq_pass` (`bufq.c:472-502`).
    ///
    /// `writer` supersedes the `Curl_bufq_writer` typedef (`bufq.h:206-208`),
    /// whose first parameter is a `void *writer_ctx`. Here the context is
    /// whatever the closure captured, so it is typed by the compiler and no
    /// cast is written anywhere. It is called with successive head-chunk
    /// spans and returns how many bytes of each it accepted, or an error.
    ///
    /// # The one place this file rewrites an error code
    ///
    /// A writer signals "would block" with `CURLcode::Again`. If it does so
    /// **after** something has already been passed on, the code is rewritten
    /// to success and the total is returned (`bufq.c:485-488`, whose comment
    /// reads "blocked on subsequent write, report success"). If it does so on
    /// the very first call, `Again` propagates. That single rewrite is what
    /// makes partial progress visible to the caller as progress, and it is
    /// load bearing: without it a writer that accepts one chunk and then
    /// blocks would look like a writer that did nothing.
    ///
    /// A writer that accepts zero bytes without erroring is treated the same
    /// way (`bufq.c:491-497`): `Again` when nothing has moved yet, otherwise
    /// the total so far.
    ///
    /// # Errors
    ///
    /// Any other code the writer returns propagates unchanged.
    ///
    /// # Partial progress is not rolled back
    ///
    /// `bufq.h:215-216` warns that *"in case of a -1 chunks may have been
    /// written and the buffer queue will have different length than before"*.
    /// That is preserved: bytes the writer accepted before failing have
    /// already been skipped and are gone. No rollback is added, and none
    /// could be -- the writer has them.
    ///
    /// The C also stores a byte count on the error path. `Result` does not
    /// carry one, which loses nothing: the C's own contract is that the count
    /// is not meaningful once the call failed, and the queue's length is the
    /// observable record of what moved.
    #[allow(dead_code)]
    pub(crate) fn pass<W>(&mut self, mut writer: W) -> CodeResult<usize>
    where
        W: FnMut(&[u8]) -> CodeResult<usize>,
    {
        let mut written = 0_usize;

        loop {
            // `bufq.c:480`. The span is borrowed from `self`, so the writer
            // is called inside this block and the borrow ends with it,
            // leaving `self.skip` free to run below.
            let outcome = {
                let Some(span) = self.peek() else {
                    break;
                };
                writer(span)
            };

            match outcome {
                // `bufq.c:484-490`.
                Err(code) => {
                    if code == CURLcode::Again && written > 0 {
                        return Ok(written);
                    }
                    return Err(code);
                }
                // `bufq.c:491-497`.
                Ok(0) => {
                    if written == 0 {
                        return Err(CURLcode::Again);
                    }
                    break;
                }
                // `bufq.c:498-499`.
                Ok(n) => {
                    written = written.saturating_add(n);
                    self.skip(n);
                }
            }
        }

        Ok(written)
    }

    /// Writes `buf`, draining through `writer` when the queue is full.
    ///
    /// Supersedes `Curl_bufq_write_pass` (`bufq.c:504-551`).
    ///
    /// The header describes this as writing *"bufq content or passed `buf`
    /// directly using the `writer` callback when it sees fit"*
    /// (`bufq.h:247-251`). "When it sees fit" is not a specification, so the
    /// body is what is reproduced, and it is simpler than the prose suggests:
    /// **`buf` is never handed to the writer directly.** Every byte goes
    /// through the queue. The writer is called for one purpose only, to make
    /// room when [`Self::is_full`] says there is none.
    ///
    /// Per iteration (`bufq.c:513-548`):
    ///
    /// 1. if the queue is full, drain it with [`Self::pass`]. A real error
    ///    fails the call (`bufq.c:517-521`); `Again` means the writer is
    ///    blocked and the queue cannot grow, so the loop gives up
    ///    (`bufq.c:522-523`).
    /// 2. write as much of the remainder as the queue will take. A real error
    ///    fails the call; `Again` returns the running total as success when
    ///    anything was written earlier and as `Again` otherwise
    ///    (`bufq.c:529-538`).
    /// 3. a zero-length write breaks out rather than spinning -- the C's own
    ///    comment at `bufq.c:540-541` calls this the "edge case of writer
    ///    returning 0 (and len is >0) break or we might enter an infinite
    ///    loop here".
    ///
    /// # Errors
    ///
    /// `CURLcode::Again` when nothing at all was accepted and bytes remain
    /// (`bufq.c:550`), or any other code raised by the writer or by
    /// [`Self::write`].
    #[allow(dead_code)]
    pub(crate) fn write_pass<W>(
        &mut self,
        buf: &[u8],
        mut writer: W,
    ) -> CodeResult<usize>
    where
        W: FnMut(&[u8]) -> CodeResult<usize>,
    {
        let mut written = 0_usize;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // Step 1 (`bufq.c:514-525`).
            if self.is_full() {
                match self.pass(&mut writer) {
                    Ok(_) => {}
                    Err(CURLcode::Again) => break,
                    Err(code) => return Err(code),
                }
            }

            // Step 2 (`bufq.c:527-538`).
            let n = match self.write(remaining) {
                Ok(n) => n,
                Err(CURLcode::Again) => {
                    if written > 0 {
                        return Ok(written);
                    }
                    return Err(CURLcode::Again);
                }
                Err(code) => return Err(code),
            };

            // Step 3 (`bufq.c:539-542`).
            if n == 0 {
                break;
            }

            // `bufq.c:544-547`.
            remaining = remaining.get(n..).unwrap_or(&[]);
            written = written.saturating_add(n);
        }

        // `bufq.c:550`.
        if written == 0 && !remaining.is_empty() {
            Err(CURLcode::Again)
        } else {
            Ok(written)
        }
    }

    /// Calls `reader` **once** to append at most `max_len` bytes.
    ///
    /// Supersedes `Curl_bufq_sipn` (`bufq.c:553-569`). Per `bufq.h:237-238`,
    /// *"if `max_len` is 0, no limit is imposed besides the chunk space"* --
    /// and even with a limit the reader is never offered more than the free
    /// space in a single chunk, because the offered slice is a subslice of one
    /// chunk.
    ///
    /// `reader` supersedes the `Curl_bufq_reader` typedef (`bufq.h:221-223`),
    /// whose first parameter is a `void *reader_ctx`. As with the writer in
    /// [`Self::pass`], the context is the closure's own captures.
    ///
    /// # Errors
    ///
    /// * `CURLcode::OutOfMemory` when a chunk was permitted but not obtained
    ///   (`bufq.c:562-563`). **Note the difference from [`Self::write`]:** the
    ///   test here is `chunk_count < max_chunks` with **no** `SOFT_LIMIT`
    ///   disjunct, so a soft-limited queue that cannot obtain a chunk reports
    ///   `Again` where `write` would report `OutOfMemory`. That asymmetry is
    ///   in the C and is reproduced rather than levelled.
    /// * `CURLcode::Again` when the queue is full (`bufq.c:565`) or when the
    ///   tail turns out to have no free space (`bufq.c:94-95`).
    /// * Any code the reader returns, unchanged. The write offset does not
    ///   advance in that case.
    #[allow(dead_code)]
    pub(crate) fn sipn<R>(
        &mut self,
        max_len: usize,
        reader: R,
    ) -> CodeResult<usize>
    where
        R: FnMut(&mut [u8]) -> CodeResult<usize>,
    {
        if !self.ensure_non_full_tail() {
            // `bufq.c:561-566`.
            if self.chunk_count < self.max_chunks {
                return Err(CURLcode::OutOfMemory);
            }
            return Err(CURLcode::Again);
        }
        // `bufq.c:568`. The `None` arm cannot be taken, as in `Self::write`.
        match self.chunks.back_mut() {
            Some(tail) => tail.slurpn(max_len, reader),
            None => Err(CURLcode::Again),
        }
    }

    /// Reads repeatedly until the reader blocks, the queue fills, or `max_len`
    /// bytes have been appended.
    ///
    /// Supersedes the private `bufq_slurpn` (`bufq.c:579-613`). It stays
    /// private here because it is private there: `Curl_bufq_slurp` is the only
    /// exported entry, and it is [`Self::slurp`].
    ///
    /// Four exits, in the C's order:
    ///
    /// * an error from [`Self::sipn`]: propagated when nothing has been read
    ///   yet or when it is not `Again`, otherwise it ends the loop
    ///   successfully with the running total (`bufq.c:589-595`);
    /// * a zero-length read, which is end of input (`bufq.c:597-600`);
    /// * `max_len` exhausted (`bufq.c:602-607`);
    /// * a tail left with room, which means the reader returned less than it
    ///   was offered, so there is no point asking again (`bufq.c:608-610`).
    fn slurpn<R>(&mut self, max_len: usize, mut reader: R) -> CodeResult<usize>
    where
        R: FnMut(&mut [u8]) -> CodeResult<usize>,
    {
        let mut nread = 0_usize;
        let mut max_len = max_len;

        loop {
            match self.sipn(max_len, &mut reader) {
                Err(code) => {
                    // `bufq.c:589-595`.
                    if nread == 0 || code != CURLcode::Again {
                        return Err(code);
                    }
                    break;
                }
                // `bufq.c:597-600`.
                Ok(0) => break,
                Ok(n) => {
                    // `bufq.c:601`.
                    nread = nread.saturating_add(n);
                    // `bufq.c:602-607`.
                    if max_len != 0 {
                        max_len = max_len.saturating_sub(n);
                        if max_len == 0 {
                            break;
                        }
                    }
                    // `bufq.c:608-610`.
                    if self.chunks.back().is_some_and(|tail| !tail.is_full()) {
                        break;
                    }
                }
            }
        }

        Ok(nread)
    }

    /// Reads until the reader blocks or the queue is full.
    ///
    /// Supersedes `Curl_bufq_slurp` (`bufq.c:615-619`), which is
    /// `bufq_slurpn` with no limit. Per `bufq.h:229`, the total *"may be 0"*,
    /// which is a success and not an error.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::sipn`] raises on the first call, including
    /// `CURLcode::Again` for a queue that is already full, and any code the
    /// reader returns. Once one read has succeeded, a later `Again` becomes
    /// the running total instead.
    ///
    /// # Partial progress is not rolled back
    ///
    /// `bufq.h:230-231` gives the same warning as [`Self::pass`]: on an error
    /// *"chunks may have been read and the buffer queue will have different
    /// length than before"*. Preserved.
    #[allow(dead_code)]
    pub(crate) fn slurp<R>(&mut self, reader: R) -> CodeResult<usize>
    where
        R: FnMut(&mut [u8]) -> CodeResult<usize>,
    {
        self.slurpn(0, reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests hold the coverage that `tests/unit/unit1305.c` and its
    // siblings hold for the C, relocated here as AAP 0.8.7 requires: a Rust
    // static library does not export `pub(crate)` items, so those C programs
    // cannot link against this crate at any quality of implementation.
    // Relocating the assertions is the sanctioned answer; re-exporting
    // internals to make them link is not.
    //
    // Being a child module, `mod tests` sees the private fields, so a state
    // that the public interface cannot reach -- an empty chunk ahead of a full
    // one, for instance -- can be built directly and asserted on. Several of
    // the C's subtler predicates are only pinnable that way.

    /// A writer that accepts everything and records what it was handed.
    ///
    /// Stands in for the `Curl_bufq_writer` a connection filter supplies. The
    /// captured `Vec` is the typed context that replaced the C's `void *`:
    /// nothing is cast, and the compiler knows what the context is.
    fn accept_all<'a>(
        sink: &'a mut Vec<u8>,
    ) -> impl FnMut(&[u8]) -> CodeResult<usize> + 'a {
        move |span: &[u8]| {
            sink.extend_from_slice(span);
            Ok(span.len())
        }
    }

    /// A reader that fills whatever it is offered with an ascending pattern.
    ///
    /// Records the length of every slice it was handed, which is how the
    /// `max_len` tests observe what `sipn` actually offered rather than
    /// inferring it from the byte count.
    fn fill_pattern<'a>(
        offered: &'a mut Vec<usize>,
        next: &'a mut u8,
    ) -> impl FnMut(&mut [u8]) -> CodeResult<usize> + 'a {
        move |dest: &mut [u8]| {
            offered.push(dest.len());
            for slot in dest.iter_mut() {
                *slot = *next;
                *next = next.wrapping_add(1);
            }
            Ok(dest.len())
        }
    }

    /// Asserts the invariant documented on [`BufQ`].
    fn assert_count_invariant(q: &BufQ) {
        assert_eq!(
            q.chunk_count,
            q.chunks.len() + q.spare.len(),
            "chunk_count must span the queue and the spare list"
        );
    }

    // ---------------------------------------------------------------- options

    #[test]
    fn option_flags_carry_the_c_values_and_compose() {
        assert_eq!(BufqOpts::NONE.bits(), 0);
        assert_eq!(BufqOpts::SOFT_LIMIT.bits(), 1);
        assert_eq!(BufqOpts::NO_SPARES.bits(), 2);
        assert_eq!(BufqOpts::default(), BufqOpts::NONE);

        let both = BufqOpts::SOFT_LIMIT | BufqOpts::NO_SPARES;
        assert_eq!(both.bits(), 3);
        assert!(both.contains(BufqOpts::SOFT_LIMIT));
        assert!(both.contains(BufqOpts::NO_SPARES));
        assert!(both.contains(BufqOpts::NONE));

        assert!(!BufqOpts::NONE.contains(BufqOpts::SOFT_LIMIT));
        assert!(!BufqOpts::SOFT_LIMIT.contains(BufqOpts::NO_SPARES));
    }

    // ----------------------------------------------------------- construction

    #[test]
    fn zero_sizes_are_clamped_rather_than_asserted() {
        // The C's two `DEBUGASSERT`s become clamps; see `BufQ::with_opts`.
        let q = BufQ::new(0, 0);
        assert_eq!(q.chunk_size(), 1);
        assert_eq!(q.max_chunks(), 1);

        let pool = ChunkPool::new(0, 0);
        assert_eq!(pool.chunk_size(), 1);
        assert_eq!(pool.spare_max(), 1);
    }

    #[test]
    fn a_soft_limited_queue_with_a_clamped_size_still_terminates() {
        // This is the outcome the clamp exists to remove. With a zero chunk
        // size every chunk would be full on creation while `SOFT_LIMIT` never
        // refuses a new one, so the write loop would allocate for ever. The
        // clamp makes the same call terminate and report progress.
        let mut q = BufQ::with_opts(0, 1, BufqOpts::SOFT_LIMIT);
        assert_eq!(q.write(b"abc"), Ok(3));
        assert_eq!(q.len(), 3);
        assert_count_invariant(&q);
    }

    #[test]
    fn a_pooled_queue_takes_its_chunk_size_from_the_pool() {
        // `bufq.c:232` reads `pool->chunk_size` rather than taking a size.
        let pool = Rc::new(RefCell::new(ChunkPool::new(7, 4)));
        let q = BufQ::with_pool(&pool, 3, BufqOpts::NONE);
        assert_eq!(q.chunk_size(), 7);
        assert_eq!(q.max_chunks(), 3);
    }

    // ------------------------------------------------------------ write/read

    #[test]
    fn a_hard_limit_refuses_the_write_that_would_exceed_it() {
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));
        assert!(q.is_full());
        assert_eq!(q.write(b"8"), Err(CURLcode::Again));
        assert_eq!(q.len(), 8);
        assert_eq!(q.chunk_count(), 2);
        assert_count_invariant(&q);
    }

    #[test]
    fn a_partial_write_is_a_success_and_the_next_one_blocks() {
        // Eight bytes of capacity with two already buffered leaves six.
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NONE);
        assert_eq!(q.write(b"ab"), Ok(2));
        assert_eq!(q.write(b"0123456789"), Ok(6));
        assert_eq!(q.len(), 8);
        assert_eq!(q.write(b"x"), Err(CURLcode::Again));
        assert!(q.is_full());
        assert_count_invariant(&q);
    }

    #[test]
    fn reading_an_empty_queue_blocks_and_a_short_read_succeeds() {
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NONE);
        let mut out = [0_u8; 10];
        assert_eq!(q.read(&mut out), Err(CURLcode::Again));

        assert_eq!(q.write(b"01234"), Ok(5));
        assert_eq!(q.read(&mut out), Ok(5));
        assert_eq!(&out[..5], b"01234");
        assert_eq!(q.read(&mut out), Err(CURLcode::Again));
        assert_count_invariant(&q);
    }

    #[test]
    fn the_empty_slice_cases_are_asymmetric_exactly_as_in_c() {
        // `bufq.c:391` needs a non-zero remaining length to choose `Again`,
        // so an empty source is a successful write of nothing. `bufq.c:414`
        // asks only whether anything was read, so an empty destination is
        // always `Again`.
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NONE);
        assert_eq!(q.write(b""), Ok(0));

        assert_eq!(q.write(b"ab"), Ok(2));
        assert_eq!(q.read(&mut []), Err(CURLcode::Again));
        assert_eq!(q.len(), 2, "a blocked read consumes nothing");
    }

    #[test]
    fn bytes_survive_spanning_three_chunks_and_odd_sized_reads() {
        // The test that catches an offset bug: twelve bytes across three
        // four-byte chunks, read back in reads of 1, 3, 7 and 4.
        let mut q = BufQ::with_opts(4, 4, BufqOpts::NONE);
        assert_eq!(q.write(b"0123456789ab"), Ok(12));
        assert_eq!(q.len(), 12);
        assert_eq!(q.chunks.len(), 3);

        let mut seen = Vec::new();
        for size in [1_usize, 3, 7, 4] {
            let mut out = vec![0_u8; size];
            let n = q.read(&mut out).expect("bytes remain");
            seen.extend_from_slice(&out[..n]);
        }
        assert_eq!(seen, b"0123456789ab".to_vec());
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_count_invariant(&q);
    }

    // ---------------------------------------------------------- the options

    #[test]
    fn soft_limit_writes_past_the_maximum_and_still_reports_full() {
        let mut q = BufQ::with_opts(4, 2, BufqOpts::SOFT_LIMIT);
        assert_eq!(q.write(b"01234567"), Ok(8));
        assert!(q.is_full(), "full at the nominal maximum");

        // All three consequences the header promises, asserted together.
        assert_eq!(q.write(b"89abcd"), Ok(6), "writes past the limit");
        assert_eq!(q.len(), 14, "len exceeds max_chunks * chunk_size");
        assert!(q.is_full(), "and it STILL reports full");

        assert_eq!(q.chunk_count(), 4);
        assert_count_invariant(&q);
    }

    #[test]
    fn soft_limit_frees_the_excess_chunks_back_down_to_the_maximum() {
        // Route 2 of `prune_head`, first half: `chunk_count > max_chunks`.
        let mut q = BufQ::with_opts(4, 2, BufqOpts::SOFT_LIMIT);
        assert_eq!(q.write(b"0123456789abcd"), Ok(14));
        assert_eq!(q.chunk_count(), 4);

        let mut out = [0_u8; 14];
        assert_eq!(q.read(&mut out), Ok(14));
        // Two chunks were freed to get back to the maximum; the other two
        // became spares, which is why the count settles at exactly the
        // maximum rather than at zero.
        assert_eq!(q.chunk_count(), 2);
        assert_eq!(q.spare.len(), 2);
        assert_count_invariant(&q);
    }

    #[test]
    fn no_spares_frees_an_emptied_chunk_and_the_default_keeps_it() {
        // With the flag: route 2 of `prune_head`, second half.
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NO_SPARES);
        assert_eq!(q.write(b"01234567"), Ok(8));
        assert_eq!(q.chunk_count(), 2);
        let mut out = [0_u8; 8];
        assert_eq!(q.read(&mut out), Ok(8));
        assert_eq!(q.spare.len(), 0, "no chunk is retained");
        assert_eq!(q.chunk_count(), 0, "and the count drops with them");
        assert_count_invariant(&q);

        // Without it: route 3, which deliberately leaves the count alone.
        let mut kept = BufQ::with_opts(4, 2, BufqOpts::NONE);
        assert_eq!(kept.write(b"01234567"), Ok(8));
        assert_eq!(kept.read(&mut out), Ok(8));
        assert_eq!(kept.spare.len(), 2, "both chunks are retained");
        assert_eq!(kept.chunk_count(), 2, "so the count does NOT drop");
        assert_count_invariant(&kept);
    }

    // -------------------------------------------------------- the predicates

    #[test]
    fn is_empty_reads_only_the_head_chunk() {
        // Referenced from `BufQ::is_empty`. The distinction cannot be
        // reached through the public interface, because `prune_head` keeps
        // interior chunks non-empty, so the state is built directly.
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        q.chunks.push_back(Chunk::new(4));
        let mut second = Chunk::new(4);
        assert_eq!(second.append(b"abcd"), 4);
        q.chunks.push_back(second);
        q.chunk_count = 2;

        assert!(q.is_empty(), "the HEAD chunk is empty, so this is true");
        assert_eq!(q.len(), 4, "yet four bytes are queued behind it");
        assert_count_invariant(&q);
    }

    #[test]
    fn is_full_branch_one_no_tail_means_not_full() {
        // `bufq.c:273-274`, first half.
        let q = BufQ::with_opts(4, 1, BufqOpts::NONE);
        assert!(!q.is_full());
    }

    #[test]
    fn is_full_branch_one_a_spare_means_not_full() {
        // `bufq.c:273-274`, second half, and the counter-intuitive one: the
        // queue is at its ceiling with a full tail, and is still not full,
        // because room can be made without allocating.
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));
        assert!(q.is_full());

        let mut out = [0_u8; 4];
        assert_eq!(q.read(&mut out), Ok(4));
        assert_eq!(q.spare.len(), 1, "the drained chunk became a spare");
        assert_eq!(q.chunk_count(), 2, "still at the ceiling");
        assert!(
            q.chunks.back().is_some_and(Chunk::is_full),
            "and the tail is still full"
        );
        assert!(!q.is_full(), "yet not full, because a spare exists");
        assert_count_invariant(&q);
    }

    #[test]
    fn is_full_branch_two_under_the_ceiling_means_not_full() {
        // `bufq.c:275-276`.
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(q.write(b"0123"), Ok(4));
        assert_eq!(q.chunk_count(), 1);
        assert!(q.chunks.back().is_some_and(Chunk::is_full));
        assert!(!q.is_full());
    }

    #[test]
    fn is_full_branch_three_over_the_ceiling_means_full() {
        // `bufq.c:277-278`, reachable only under `SOFT_LIMIT`.
        let mut q = BufQ::with_opts(4, 1, BufqOpts::SOFT_LIMIT);
        assert_eq!(q.write(b"01234567"), Ok(8));
        assert_eq!(q.chunk_count(), 2);
        assert!(q.chunk_count() > q.max_chunks());
        assert!(q.spare.is_empty());
        assert!(q.is_full());
    }

    #[test]
    fn is_full_branch_four_asks_the_tail() {
        // `bufq.c:279-280`: at the ceiling with no spares, the tail decides.
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NONE);
        assert_eq!(q.write(b"01234"), Ok(5));
        assert_eq!(q.chunk_count(), 2, "at the ceiling");
        assert!(q.spare.is_empty(), "with no spares");
        assert!(!q.is_full(), "and a tail with room, so not full");

        assert_eq!(q.write(b"567"), Ok(3));
        assert!(q.is_full(), "the tail filled, so now it is");
    }

    // ---------------------------------------------------------- peek and skip

    #[test]
    fn peek_hands_back_the_head_chunk_and_never_a_stitched_view() {
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert!(q.peek().is_none(), "nothing to peek at yet");

        assert_eq!(q.write(b"01234567"), Ok(8));
        assert_eq!(q.peek(), Some(&b"0123"[..]), "the head chunk only");
        assert_eq!(q.len(), 8, "and peeking consumes nothing");

        // Repeated calls answer alike until the queue is modified. In C that
        // is a rule the caller has to remember; here the borrow checker makes
        // using a stale span a compile error, so the runtime check is only
        // that the answer is stable.
        assert_eq!(q.peek(), Some(&b"0123"[..]));

        q.skip(2);
        assert_eq!(q.peek(), Some(&b"23"[..]));
        q.skip(2);
        assert_eq!(q.peek(), Some(&b"4567"[..]), "on to the next chunk");
    }

    #[test]
    fn peek_prunes_an_empty_head_before_answering() {
        // The reason `peek` takes `&mut self` (`bufq.c:426-428`).
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        q.chunks.push_back(Chunk::new(4));
        let mut second = Chunk::new(4);
        assert_eq!(second.append(b"wxyz"), 4);
        q.chunks.push_back(second);
        q.chunk_count = 2;

        assert_eq!(q.peek(), Some(&b"wxyz"[..]));
        assert_eq!(q.chunks.len(), 1, "the empty head was retired");
        assert_eq!(q.spare.len(), 1, "and kept as a spare");
        assert_count_invariant(&q);
    }

    #[test]
    fn peek_at_crosses_chunk_boundaries_and_stops_at_the_end() {
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));

        assert_eq!(q.peek_at(0), Some(&b"0123"[..]));
        assert_eq!(q.peek_at(2), Some(&b"23"[..]));
        // Crossing into the second chunk: offset 4 is its first byte, and the
        // span still stops at that chunk's end rather than stitching.
        assert_eq!(q.peek_at(4), Some(&b"4567"[..]));
        assert_eq!(q.peek_at(6), Some(&b"67"[..]));
        assert_eq!(q.peek_at(8), None, "past the end");
        assert_eq!(q.peek_at(9), None);
        assert_eq!(q.peek_at(usize::MAX), None, "and no overflow");
        assert_eq!(q.len(), 8, "peek_at consumes nothing");
    }

    #[test]
    fn peek_at_stops_at_the_first_empty_chunk() {
        // `bufq.c:446-447`. The walk leaves the loop rather than stepping
        // over an empty chunk, so data behind one is unreachable.
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        q.chunks.push_back(Chunk::new(4));
        let mut second = Chunk::new(4);
        assert_eq!(second.append(b"wxyz"), 4);
        q.chunks.push_back(second);
        q.chunk_count = 2;

        assert_eq!(q.len(), 4, "four bytes are queued");
        assert_eq!(q.peek_at(0), None, "yet the walk stops before them");
    }

    #[test]
    fn skipping_more_than_is_buffered_just_empties_the_queue() {
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(q.write(b"0123456789"), Ok(10));

        // Terminates rather than spinning, which is the point of the test.
        q.skip(usize::MAX);
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
        assert!(q.chunks.is_empty());
        assert_count_invariant(&q);

        // Both degenerate cases are no-ops rather than hazards.
        q.skip(0);
        q.skip(7);
        assert!(q.is_empty());
    }

    #[test]
    fn skipping_part_of_the_head_leaves_the_rest_in_place() {
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));
        q.skip(5);
        assert_eq!(q.len(), 3);
        let mut out = [0_u8; 3];
        assert_eq!(q.read(&mut out), Ok(3));
        assert_eq!(&out, b"567");
    }

    // ------------------------------------------------------ reset versus free

    #[test]
    fn reset_keeps_the_buffers_so_a_full_queue_can_be_written_again() {
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));
        assert!(q.is_full());
        assert_eq!(q.chunk_count(), 2);

        q.reset();
        assert_eq!(q.len(), 0, "the queue is empty");
        assert!(q.is_empty());
        assert_eq!(q.spare.len(), 2, "but both buffers were kept");
        assert_eq!(q.chunk_count(), 2, "and the count is untouched");
        assert_count_invariant(&q);

        // The proof that the buffers are reused rather than reallocated: the
        // count is already AT the ceiling, so `get_spare` would refuse a new
        // chunk. This write can only succeed by taking a spare.
        assert_eq!(q.write(b"abcd"), Ok(4));
        assert_eq!(q.chunk_count(), 2, "no chunk was created");
        assert_eq!(q.spare.len(), 1);
        assert_eq!(q.peek(), Some(&b"abcd"[..]), "and it reads back clean");
    }

    #[test]
    fn free_releases_everything_and_leaves_the_queue_usable() {
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));

        q.free();
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
        assert!(!q.is_full());
        assert!(q.chunks.is_empty());
        assert!(q.spare.is_empty(), "spares are released too");
        assert_eq!(q.chunk_count(), 0);
        assert_count_invariant(&q);

        // Reusable afterwards, which is what `lib/request.c:80` relies on
        // when it frees a send buffer and re-initialises it.
        assert_eq!(q.write(b"wxyz"), Ok(4));
        assert_eq!(q.len(), 4);
        assert_count_invariant(&q);
    }

    // ------------------------------------------------------------------- pass

    #[test]
    fn pass_drains_the_queue_into_a_writer_that_accepts_everything() {
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(q.write(b"0123456789ab"), Ok(12));

        let mut sink = Vec::new();
        assert_eq!(q.pass(accept_all(&mut sink)), Ok(12));
        assert_eq!(sink, b"0123456789ab".to_vec());
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
        assert_count_invariant(&q);
    }

    #[test]
    fn pass_on_an_empty_queue_reports_no_progress() {
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        let mut calls = 0_usize;
        let result = q.pass(|_span| {
            calls += 1;
            Ok(0)
        });
        assert_eq!(result, Ok(0), "no span to offer, so nothing blocked");
        assert_eq!(calls, 0, "and the writer was never called");
    }

    #[test]
    fn pass_blocked_on_the_first_write_reports_again() {
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));

        assert_eq!(q.pass(|_span| Err(CURLcode::Again)), Err(CURLcode::Again));
        assert_eq!(q.len(), 8, "and nothing was consumed");
    }

    #[test]
    fn pass_blocked_on_a_later_write_reports_success() {
        // THE ONE PLACE THIS FILE REWRITES AN ERROR CODE (`bufq.c:485-488`).
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));

        let mut calls = 0_usize;
        let result = q.pass(|span: &[u8]| {
            calls += 1;
            if calls == 1 {
                Ok(span.len())
            } else {
                Err(CURLcode::Again)
            }
        });
        assert_eq!(
            result,
            Ok(4),
            "a SUBSEQUENT `Again` becomes success carrying the total"
        );
        assert_eq!(calls, 2);
        assert_eq!(q.len(), 4, "the accepted chunk is gone, the rest stays");
        assert_count_invariant(&q);
    }

    #[test]
    fn pass_propagates_a_real_error_and_keeps_the_partial_progress() {
        let mut q = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));

        let mut calls = 0_usize;
        let result = q.pass(|span: &[u8]| {
            calls += 1;
            if calls == 1 {
                Ok(span.len())
            } else {
                Err(CURLcode::WriteError)
            }
        });
        assert_eq!(
            result,
            Err(CURLcode::WriteError),
            "unchanged, not rewritten"
        );
        // `bufq.h:215-216` warns the length will differ. It does, and there
        // is deliberately no rollback: the writer already has those bytes.
        assert_eq!(q.len(), 4);
        assert_count_invariant(&q);
    }

    #[test]
    fn pass_treats_a_zero_length_write_as_blocking_only_on_no_progress() {
        // `bufq.c:491-497`, both halves.
        let mut first = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(first.write(b"01234567"), Ok(8));
        assert_eq!(first.pass(|_span| Ok(0)), Err(CURLcode::Again));
        assert_eq!(first.len(), 8);

        let mut later = BufQ::with_opts(4, 3, BufqOpts::NONE);
        assert_eq!(later.write(b"01234567"), Ok(8));
        let mut calls = 0_usize;
        let result = later.pass(|span: &[u8]| {
            calls += 1;
            if calls == 1 {
                Ok(span.len())
            } else {
                Ok(0)
            }
        });
        assert_eq!(result, Ok(4), "progress already made, so this is success");
        assert_eq!(later.len(), 4);
    }

    #[test]
    fn pass_accepts_a_writer_that_takes_only_part_of_a_span() {
        let mut q = BufQ::with_opts(4, 2, BufqOpts::NONE);
        assert_eq!(q.write(b"01234567"), Ok(8));

        // One byte per call, so the same head chunk is offered repeatedly at
        // an advancing offset. Eight calls take everything, and the ninth
        // finds the queue empty.
        let mut sink = Vec::new();
        let result = q.pass(|span: &[u8]| {
            sink.push(span[0]);
            Ok(1)
        });
        assert_eq!(result, Ok(8));
        assert_eq!(sink, b"01234567".to_vec());
        assert!(q.is_empty());
        assert_count_invariant(&q);
    }

    // ------------------------------------------------------------- write_pass

    #[test]
    fn write_pass_never_hands_the_caller_buffer_to_the_writer() {
        // The header's "when it sees fit" (`bufq.h:247-251`) reads as though
        // `buf` might bypass the queue. It never does: the writer exists only
        // to make room. A queue with room does not call it at all.
        let mut q = BufQ::new(8, 4);
        let mut calls = 0_usize;
        let result = q.write_pass(&[1, 2, 3], |_span: &[u8]| {
            calls += 1;
            Ok(0)
        });
        assert_eq!(result, Ok(3));
        assert_eq!(calls, 0, "the writer is called only to make room");
        assert_eq!(q.len(), 3);
        assert_count_invariant(&q);
    }

    #[test]
    fn write_pass_drains_a_full_queue_and_then_writes_the_rest() {
        // One chunk of four, and six bytes to place. Traced against
        // `bufq.c:513-548`: turn one writes four and fills the only chunk;
        // turn two finds the queue full, drains those four through the writer,
        // recycles the chunk and writes the last two.
        let mut q = BufQ::new(4, 1);
        let mut seen: Vec<u8> = Vec::new();
        let result = q.write_pass(&[0, 1, 2, 3, 4, 5], accept_all(&mut seen));

        assert_eq!(result, Ok(6), "every byte was placed");
        assert_eq!(seen, vec![0, 1, 2, 3], "only the drained chunk was passed");
        assert_eq!(q.len(), 2, "the last two bytes are still queued");
        assert_eq!(q.peek(), Some(&[4, 5][..]));
        assert_eq!(q.chunk_count(), 1, "the chunk was reused, not added to");
        assert_count_invariant(&q);
    }

    #[test]
    fn write_pass_reports_progress_when_the_later_write_blocks() {
        // The `Again`-with-progress arm at `bufq.c:529-534`. It is reachable
        // only when the drain frees less than a whole chunk, so the writer
        // here has a budget of two against a chunk of four: `pass` succeeds
        // having moved two bytes, the tail is still full, and the following
        // write can obtain nothing.
        let mut q = BufQ::new(4, 1);
        let mut budget = 2_usize;
        let mut seen: Vec<u8> = Vec::new();
        let result =
            q.write_pass(&[0, 1, 2, 3, 4, 5, 6, 7], |span: &[u8]| {
                let take = budget.min(span.len());
                budget = budget.saturating_sub(take);
                seen.extend_from_slice(span.get(..take).unwrap_or(&[]));
                Ok(take)
            });

        assert_eq!(result, Ok(4), "four bytes were buffered before the block");
        assert_eq!(seen, vec![0, 1], "the writer took only its budget");
        assert_eq!(q.len(), 2, "bytes 2 and 3 are still queued");
        assert_count_invariant(&q);
    }

    #[test]
    fn write_pass_blocked_on_a_full_queue_reports_again() {
        // `bufq.c:522-523`: the writer is blocked and the queue cannot grow,
        // so the loop gives up and `bufq.c:550` turns no progress into
        // `CURLE_AGAIN`.
        let mut q = BufQ::new(4, 1);
        assert_eq!(q.write(&[0, 1, 2, 3]), Ok(4));
        assert!(q.is_full());

        let mut calls = 0_usize;
        let result = q.write_pass(&[9], |_span: &[u8]| {
            calls += 1;
            Err(CURLcode::Again)
        });
        assert_eq!(result, Err(CURLcode::Again));
        assert_eq!(calls, 1);
        assert_eq!(q.len(), 4, "nothing moved");
        assert_count_invariant(&q);
    }

    #[test]
    fn write_pass_propagates_a_real_error_from_the_writer() {
        // `bufq.c:517-521`: anything other than `CURLE_AGAIN` fails the call
        // outright rather than ending the loop.
        let mut q = BufQ::new(4, 1);
        assert_eq!(q.write(&[0, 1, 2, 3]), Ok(4));

        let result =
            q.write_pass(&[9], |_span: &[u8]| Err(CURLcode::WriteError));
        assert_eq!(result, Err(CURLcode::WriteError));
        assert_eq!(q.len(), 4);
        assert_count_invariant(&q);
    }

    #[test]
    fn write_pass_with_an_empty_buffer_is_success_not_a_block() {
        // `bufq.c:550` asks for no progress AND bytes remaining. With nothing
        // to place there are no bytes remaining, so this matches
        // `Self::write`'s treatment of an empty slice rather than
        // `Self::read`'s.
        let mut q = BufQ::new(4, 1);
        let mut calls = 0_usize;
        let result = q.write_pass(&[], |_span: &[u8]| {
            calls += 1;
            Ok(0)
        });
        assert_eq!(result, Ok(0));
        assert_eq!(calls, 0);
        assert!(q.is_empty());
    }

    // ------------------------------------------------------------------- sipn

    #[test]
    fn sipn_with_no_limit_offers_the_whole_chunk_space() {
        // `bufq.h:237-238`: "if `max_len` is 0, no limit is imposed besides
        // the chunk space".
        let mut q = BufQ::new(4, 2);
        let mut offered: Vec<usize> = Vec::new();
        let mut next = 10_u8;
        let result = q.sipn(0, fill_pattern(&mut offered, &mut next));

        assert_eq!(result, Ok(4));
        assert_eq!(offered, vec![4], "the reader saw the whole chunk");
        assert_eq!(q.len(), 4);
        assert_eq!(q.peek(), Some(&[10, 11, 12, 13][..]));
        assert_count_invariant(&q);
    }

    #[test]
    fn sipn_caps_a_single_read_at_max_len() {
        // `bufq.c:96-97`: a non-zero `max_len` narrows the offered slice.
        let mut q = BufQ::new(8, 2);
        let mut offered: Vec<usize> = Vec::new();
        let mut next = 0_u8;
        let result = q.sipn(3, fill_pattern(&mut offered, &mut next));

        assert_eq!(result, Ok(3));
        assert_eq!(offered, vec![3], "the limit, not the free space");
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn sipn_offers_only_what_is_left_in_a_partly_written_tail() {
        // The slice handed to the reader is a subslice of ONE chunk, so a
        // single call can never span a chunk boundary however large `max_len`
        // is. Five bytes free in an eight-byte chunk holding three.
        let mut q = BufQ::new(8, 4);
        assert_eq!(q.write(&[1, 2, 3]), Ok(3));

        let mut offered: Vec<usize> = Vec::new();
        let mut next = 0_u8;
        let result = q.sipn(0, fill_pattern(&mut offered, &mut next));

        assert_eq!(result, Ok(5));
        assert_eq!(offered, vec![5], "one chunk is the ceiling on one read");
        assert_eq!(q.len(), 8);
        assert_eq!(q.chunk_count(), 1, "no second chunk was taken");
    }

    #[test]
    fn sipn_on_a_full_queue_blocks_without_calling_the_reader() {
        // `bufq.c:565`. Note which branch is taken: `chunk_count` is NOT below
        // `max_chunks`, so this is `Again` and not `OutOfMemory`.
        let mut q = BufQ::new(4, 1);
        assert_eq!(q.write(&[0, 1, 2, 3]), Ok(4));

        let mut calls = 0_usize;
        let result = q.sipn(0, |dest: &mut [u8]| {
            calls += 1;
            Ok(dest.len())
        });
        assert_eq!(result, Err(CURLcode::Again));
        assert_eq!(calls, 0);
        assert_eq!(q.len(), 4);
    }

    #[test]
    fn sipn_propagates_a_reader_error_and_leaves_the_offset_alone() {
        // `bufq.c:99-102`: the write offset advances only on success, so a
        // failed read cannot expose uninitialised or stale bytes.
        let mut q = BufQ::new(4, 2);
        assert_eq!(q.write(&[7]), Ok(1));

        let result = q.sipn(0, |dest: &mut [u8]| {
            // Scribble first, then fail. The bytes are in the buffer but must
            // stay outside the readable span.
            for slot in dest.iter_mut() {
                *slot = 0xFF;
            }
            Err(CURLcode::ReadError)
        });
        assert_eq!(result, Err(CURLcode::ReadError));
        assert_eq!(q.len(), 1, "the scribbled bytes are not readable");
        assert_eq!(q.peek(), Some(&[7][..]));
    }

    #[test]
    fn sipn_clamps_a_reader_that_overreports() {
        // Where the C has `DEBUGASSERT(*pnread <= n)` this clamps, so a
        // misbehaving reader cannot push the write offset past the buffer.
        let mut q = BufQ::new(4, 1);
        let result =
            q.sipn(2, |dest: &mut [u8]| Ok(dest.len().saturating_add(9)));

        assert_eq!(result, Ok(2), "clamped to what was offered");
        assert_eq!(q.len(), 2);
        assert!(!q.is_full(), "two of the four bytes are still free");
    }

    // ---------------------------------------------------------- slurp/slurpn

    #[test]
    fn slurp_stops_when_the_reader_blocks_and_reports_the_total() {
        // `bufq.c:589-595`: an `Again` after progress ends the loop
        // successfully with the running total. A budget of exactly two chunks
        // means the third `sipn` is the one that blocks.
        let mut q = BufQ::new(4, 4);
        let mut budget = 8_usize;
        let result = q.slurp(|dest: &mut [u8]| {
            if budget == 0 {
                return Err(CURLcode::Again);
            }
            let take = budget.min(dest.len());
            budget = budget.saturating_sub(take);
            for slot in dest.iter_mut().take(take) {
                *slot = 0xAB;
            }
            Ok(take)
        });

        assert_eq!(result, Ok(8), "the block is not an error after progress");
        assert_eq!(q.len(), 8);
        assert_count_invariant(&q);
    }

    #[test]
    fn slurp_fills_the_queue_and_stops_at_full() {
        // A reader that never blocks stops the loop a different way: the
        // queue runs out of chunks, `sipn` reports `Again` and the running
        // total is returned.
        let mut q = BufQ::new(4, 2);
        let mut offered: Vec<usize> = Vec::new();
        let mut next = 0_u8;
        let result = q.slurp(fill_pattern(&mut offered, &mut next));

        assert_eq!(result, Ok(8));
        assert_eq!(offered, vec![4, 4], "two chunks, one whole read each");
        assert!(q.is_full());
        assert_eq!(q.len(), 8);
        assert_eq!(q.chunk_count(), 2);
        assert_count_invariant(&q);
    }

    #[test]
    fn slurp_propagates_an_error_raised_on_the_first_call() {
        // `bufq.c:589-592`: with nothing read yet the code is propagated
        // whatever it is.
        let mut q = BufQ::new(4, 2);
        let result = q.slurp(|_dest: &mut [u8]| Err(CURLcode::ReadError));

        assert_eq!(result, Err(CURLcode::ReadError));
        assert!(q.is_empty());
    }

    #[test]
    fn slurp_on_a_full_queue_blocks_on_the_first_call() {
        // The same first-call rule applied to `Again`, which is how a caller
        // learns the queue has no room at all.
        let mut q = BufQ::new(4, 1);
        assert_eq!(q.write(&[0, 1, 2, 3]), Ok(4));

        let mut calls = 0_usize;
        let result = q.slurp(|dest: &mut [u8]| {
            calls += 1;
            Ok(dest.len())
        });
        assert_eq!(result, Err(CURLcode::Again));
        assert_eq!(calls, 0, "there was never any space to offer");
    }

    #[test]
    fn slurp_gives_up_when_the_reader_leaves_room_in_the_tail() {
        // `bufq.c:608-610`: a reader that returned less than it was offered
        // has nothing more to give, so there is no point asking again. One
        // call, not two.
        let mut q = BufQ::new(8, 4);
        let mut calls = 0_usize;
        let result = q.slurp(|dest: &mut [u8]| {
            calls += 1;
            let take = dest.len().min(3);
            for slot in dest.iter_mut().take(take) {
                *slot = 1;
            }
            Ok(take)
        });

        assert_eq!(result, Ok(3), "a short read is success, not a block");
        assert_eq!(calls, 1, "the tail still has room, so the loop stops");
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn slurp_treats_a_zero_length_read_as_end_of_input() {
        // `bufq.c:597-600`. The reader is offered space and declines it, which
        // is end of input and not an error, so the total is `Ok(0)`.
        let mut q = BufQ::new(4, 2);
        let mut calls = 0_usize;
        let result = q.slurp(|_dest: &mut [u8]| {
            calls += 1;
            Ok(0)
        });

        assert_eq!(result, Ok(0), "bufq.h:229: the total may be 0");
        assert_eq!(calls, 1);
        assert!(q.is_empty());
        assert_count_invariant(&q);
    }

    #[test]
    fn slurpn_stops_once_the_limit_is_exhausted() {
        // `bufq.c:602-607` counts `max_len` down across calls, so a limit of
        // six against chunks of four offers four and then two. Exercised
        // through the private entry because `Curl_bufq_slurp` is the only
        // exported one and it passes no limit.
        let mut q = BufQ::new(4, 4);
        let mut offered: Vec<usize> = Vec::new();
        let mut next = 0_u8;
        let result = q.slurpn(6, fill_pattern(&mut offered, &mut next));

        assert_eq!(result, Ok(6));
        assert_eq!(offered, vec![4, 2], "the limit narrowed the second read");
        assert_eq!(q.len(), 6);
        assert!(!q.is_full(), "the ceiling was the limit, not the chunks");
        assert_count_invariant(&q);
    }

    // ------------------------------------------------------------- the pool

    #[test]
    fn a_pool_recycles_chunks_between_two_queues() {
        let pool: SharedPool = Rc::new(RefCell::new(ChunkPool::new(4, 2)));
        let mut first = BufQ::with_pool(&pool, 2, BufqOpts::NONE);
        let mut second = BufQ::with_pool(&pool, 2, BufqOpts::NONE);

        // `bufq.c:232`: the queue takes its chunk size FROM the pool rather
        // than from a parameter, so every queue sharing one agrees.
        assert_eq!(first.chunk_size(), 4);
        assert_eq!(second.chunk_size(), 4);
        assert_eq!(pool.borrow().spare_count(), 0);

        // Fill the first queue and drain it. `prune_head`'s route 1 hands each
        // emptied chunk back to the pool and decrements the count.
        assert_eq!(first.write(&[0, 1, 2, 3, 4, 5, 6, 7]), Ok(8));
        assert_eq!(first.chunk_count(), 2);
        let mut sink = vec![0_u8; 8];
        assert_eq!(first.read(&mut sink), Ok(8));
        assert_eq!(sink, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            first.chunk_count(),
            0,
            "the queue kept no spares of its own"
        );
        assert_count_invariant(&first);
        assert_eq!(pool.borrow().spare_count(), 2, "both went to the pool");

        // The second queue now draws on them instead of allocating.
        assert_eq!(second.write(&[9, 9, 9, 9]), Ok(4));
        assert_eq!(pool.borrow().spare_count(), 1, "taken, not allocated");
        assert_eq!(second.chunk_count(), 1);
        assert_count_invariant(&second);
    }

    #[test]
    fn a_pool_frees_rather_than_hoards_past_spare_max() {
        // `bufq.c:189-191`: at or above the ceiling the chunk is freed
        // outright, so a burst cannot leave the pool holding memory for ever.
        let pool: SharedPool = Rc::new(RefCell::new(ChunkPool::new(4, 1)));
        let mut q = BufQ::with_pool(&pool, 3, BufqOpts::NONE);

        assert_eq!(q.write(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]), Ok(12));
        assert_eq!(q.chunk_count(), 3);

        let mut sink = vec![0_u8; 12];
        assert_eq!(q.read(&mut sink), Ok(12));
        assert_eq!(q.chunk_count(), 0);
        assert_eq!(pool.borrow().spare_max(), 1);
        assert_eq!(
            pool.borrow().spare_count(),
            1,
            "one kept, the other two freed"
        );
    }

    #[test]
    fn pool_free_releases_the_spares_and_the_pool_stays_usable() {
        // `bufq.c:200-204` frees the spare list and zeroes the count. The pool
        // is not poisoned by it and allocates again on demand.
        let pool: SharedPool = Rc::new(RefCell::new(ChunkPool::new(4, 4)));
        let mut q = BufQ::with_pool(&pool, 2, BufqOpts::NONE);

        assert_eq!(q.write(&[1, 2, 3, 4]), Ok(4));
        let mut sink = vec![0_u8; 4];
        assert_eq!(q.read(&mut sink), Ok(4));
        assert_eq!(pool.borrow().spare_count(), 1);

        pool.borrow_mut().free();
        assert_eq!(pool.borrow().spare_count(), 0);

        assert_eq!(q.write(&[5, 6]), Ok(2), "a fresh chunk was allocated");
        assert_eq!(q.len(), 2);
        assert_eq!(pool.borrow().spare_count(), 0);
        assert_count_invariant(&q);
    }

    #[test]
    fn pool_clamps_zero_parameters_rather_than_asserting() {
        // `bufq.c:150-151` has two `DEBUGASSERT`s that a release build
        // removes. Clamping is strictly stronger, and is the identity for
        // every caller that honours the precondition.
        let pool = ChunkPool::new(0, 0);
        assert_eq!(pool.chunk_size(), 1);
        assert_eq!(pool.spare_max(), 1);
        assert_eq!(pool.spare_count(), 0);
    }

    #[test]
    fn a_pooled_queue_still_honours_its_own_chunk_ceiling() {
        // A pool supplies chunks; it does not raise `max_chunks`. The hard
        // limit is the queue's, and `get_spare` tests it (`bufq.c:294-295`)
        // BEFORE consulting the pool (`bufq.c:297-302`).
        let pool: SharedPool = Rc::new(RefCell::new(ChunkPool::new(4, 8)));
        let mut q = BufQ::with_pool(&pool, 1, BufqOpts::NONE);

        assert_eq!(q.write(&[0, 1, 2, 3, 4, 5]), Ok(4), "one chunk only");
        assert_eq!(q.write(&[4, 5]), Err(CURLcode::Again));
        assert!(q.is_full());
        assert_eq!(q.chunk_count(), 1);
    }

    // ------------------------------------------------------- the count invariant

    #[test]
    fn the_chunk_count_invariant_survives_mixed_operations() {
        // `chunk_count` spans the queue and the spare list, which is why
        // `prune_head`'s spare route does not decrement it. Every mutation
        // path is exercised here in combination -- write, read, skip, reset --
        // because a miscount only shows up after several fill and drain
        // cycles, when the hard limit starts refusing writes too early or too
        // late.
        let mut q = BufQ::new(4, 3);
        let payload: Vec<u8> = (0..40_u8).collect();
        let mut sink = vec![0_u8; 5];
        let mut cursor = 0_usize;

        for round in 0..12_usize {
            assert_count_invariant(&q);

            let pending = payload.get(cursor..).unwrap_or(&[]);
            match q.write(pending) {
                Ok(n) => cursor = cursor.saturating_add(n),
                Err(CURLcode::Again) => {
                    assert!(
                        q.is_full(),
                        "only a full queue may refuse a write"
                    );
                }
                Err(other) => panic!("unexpected code from write: {other:?}"),
            }
            assert_count_invariant(&q);
            assert!(q.chunk_count() <= q.max_chunks(), "the hard limit holds");

            if round % 2 == 0 {
                match q.read(&mut sink) {
                    Ok(n) => {
                        assert!(n > 0, "a successful read moved something")
                    }
                    Err(CURLcode::Again) => assert!(q.is_empty()),
                    Err(other) => {
                        panic!("unexpected code from read: {other:?}")
                    }
                }
            } else {
                q.skip(3);
            }
            assert_count_invariant(&q);

            if round % 5 == 4 {
                q.reset();
                assert_count_invariant(&q);
                assert!(q.is_empty(), "reset empties the queue");
            }
        }

        q.free();
        assert_count_invariant(&q);
        assert_eq!(q.chunk_count(), 0);
        assert!(q.is_empty());
    }

    // ------------------------------------------------------ the chunk itself

    #[test]
    fn a_drained_chunk_resets_both_offsets() {
        // `bufq.c:74`: when the read takes everything, BOTH offsets go to
        // zero, which is what makes the chunk writable again rather than
        // merely empty.
        let mut chunk = Chunk::new(4);
        assert_eq!(chunk.append(&[1, 2, 3]), 3);
        assert_eq!(chunk.len(), 3);

        let mut sink = [0_u8; 3];
        assert_eq!(chunk.read_into(&mut sink), 3);
        assert_eq!(sink, [1, 2, 3]);
        assert_eq!(chunk.r_offset, 0);
        assert_eq!(chunk.w_offset, 0);
        assert!(chunk.is_empty());
        assert!(!chunk.is_full(), "and writable again");
    }

    #[test]
    fn a_partly_read_chunk_keeps_its_offsets_until_it_drains() {
        // `bufq.c:77-79` advances `r_offset` without resetting, and
        // `bufq.c:130-131` applies the same reset as the read once a skip
        // empties the chunk.
        let mut chunk = Chunk::new(4);
        assert_eq!(chunk.append(&[1, 2, 3, 4]), 4);
        assert!(chunk.is_full());

        let mut sink = [0_u8; 2];
        assert_eq!(chunk.read_into(&mut sink), 2);
        assert_eq!(sink, [1, 2]);
        assert_eq!(chunk.r_offset, 2);
        assert_eq!(chunk.w_offset, 4);
        assert_eq!(chunk.len(), 2);

        assert_eq!(chunk.skip(9), 2, "bufq.c:127 clamps to what is there");
        assert_eq!(chunk.r_offset, 0);
        assert_eq!(chunk.w_offset, 0);
        assert_eq!(chunk.skip(1), 0, "an empty chunk skips nothing");
    }

    #[test]
    fn chunk_append_clamps_to_the_free_space() {
        // `bufq.c:54`: `CURLMIN(len, dlen - w_offset)`.
        let mut chunk = Chunk::new(3);
        assert_eq!(chunk.append(&[1, 2, 3, 4, 5]), 3);
        assert!(chunk.is_full());
        assert_eq!(chunk.append(&[6]), 0, "a full chunk accepts nothing");
        assert_eq!(chunk.peek(), &[1, 2, 3]);
    }

    #[test]
    fn chunk_reset_zeroes_the_offsets_and_not_the_data() {
        // `bufq.c:43-47` does not clear the buffer, and it does not need to:
        // every read is bounded by `w_offset`, so a stale byte is unreachable.
        // Asserting both halves is what makes that argument checkable.
        let mut chunk = Chunk::new(4);
        assert_eq!(chunk.append(&[1, 2, 3, 4]), 4);
        chunk.reset();

        assert_eq!(chunk.r_offset, 0);
        assert_eq!(chunk.w_offset, 0);
        assert_eq!(chunk.data[0], 1, "the byte is still in the buffer");
        assert!(chunk.peek().is_empty(), "and is not readable");
        assert!(chunk.peek_at(0).is_empty());
    }

    #[test]
    fn chunk_peek_at_clamps_past_the_written_end() {
        let mut chunk = Chunk::new(4);
        assert_eq!(chunk.append(&[1, 2, 3]), 3);

        assert_eq!(chunk.peek(), &[1, 2, 3]);
        assert_eq!(chunk.peek_at(1), &[2, 3]);
        assert_eq!(chunk.peek_at(2), &[3]);
        assert!(chunk.peek_at(3).is_empty());
        assert!(
            chunk.peek_at(usize::MAX).is_empty(),
            "the clamp keeps the range valid rather than panicking"
        );
    }

    #[test]
    fn chunk_slurpn_blocks_when_there_is_no_free_space() {
        // `bufq.c:94-95`: no space is `CURLE_AGAIN`, not `Ok(0)`. The
        // distinction matters because `bufq_slurpn` reads `Ok(0)` as end of
        // input and `Again` as backpressure.
        let mut chunk = Chunk::new(2);
        assert_eq!(chunk.append(&[1, 2]), 2);

        let mut calls = 0_usize;
        let result = chunk.slurpn(0, |dest: &mut [u8]| {
            calls += 1;
            Ok(dest.len())
        });
        assert_eq!(result, Err(CURLcode::Again));
        assert_eq!(calls, 0);
    }
}
