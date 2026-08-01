<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# bufq

This is an internal module for managing I/O buffers. A `bufq` can be written
to and read from. It manages read and write positions and has a maximum size.

The C implementation in `lib/bufq.c`, together with its interface in
`lib/bufq.h`, is the reference oracle for this module: it defines the behavior
that the migration preserves. The observable contract is restated here because
it is precisely what the successor described at the end of this page maps one
for one, rather than reinterprets.

- **Ordering is first in, first out.** A read always takes from the head chunk
  and a write always appends to the tail chunk, so bytes leave the queue in
  the order they entered it.
- **Byte counts are exact.** `Curl_bufq_len` reports the sum of the data held
  in all of the chunks, and a partial write reports the number of bytes
  accepted rather than the number requested. That count arrives through a
  `size_t *` out-parameter, not through the return value.
- **Full and empty are signaled, not reported as failures.** The prototypes
  below return `CURLcode` directly, and `CURLE_AGAIN` is what a write to a
  full queue and a read from an empty queue produce. The distinction is
  precise: `CURLE_AGAIN` is returned only when **no** bytes moved at all
  (`lib/bufq.c:414` for a read, `lib/bufq.c:391` for a write), so a partial
  transfer of one or more bytes is `CURLE_OK` with a short count rather than
  `CURLE_AGAIN`. Neither is an ordinary error. The transfer layer depends on
  that distinction as its pause and back-pressure signal.
- **Full and non-empty are loosely coupled**, exactly as the worked example in
  the section on empty, full and overflow shows.
- `BUFQ_OPT_SOFT_LIMIT` permits a write beyond `max_chunks` while still
  reporting full. It exists so that a caller that cannot tolerate a partial
  write does not have to.
- `BUFQ_OPT_NO_SPARES` frees a chunk that reads empty right away, instead of
  returning it to the spare list.
- A pointer obtained from `Curl_bufq_peek` is valid only until the next
  operation on the queue.

## read/write

Its basic read/write functions have a similar signature and return code
handling as many internal curl read and write ones: the result is a `CURLcode`
and the byte count is an out-parameter.

```c
CURLcode Curl_bufq_write(struct bufq *q,
                         const uint8_t *buf, size_t len,
                         size_t *pnwritten);

CURLcode Curl_bufq_read(struct bufq *q, uint8_t *buf, size_t len,
                        size_t *pnread);
```

- Both set the out-parameter to 0 on entry and then report through it the
  number of bytes actually moved, which may be fewer than `len`.
- A write to a full `q` yields `CURLE_AGAIN`, but only when nothing at all was
  accepted: the return is
  `(!*pnwritten && len) ? CURLE_AGAIN : CURLE_OK` (`lib/bufq.c:391`).
- A read from an empty `q` yields `CURLE_AGAIN` on the same condition:
  `(!*pnread) ? CURLE_AGAIN : CURLE_OK` (`lib/bufq.c:414`).
- A write can also yield `CURLE_OUT_OF_MEMORY`, when a non-full tail chunk
  should have been available but could not be obtained (`lib/bufq.c:381`).
  That is a genuine failure, unlike `CURLE_AGAIN`.

`Curl_bufq_cwrite` and `Curl_bufq_cread` are the `char *` spellings of the same
two functions and simply delegate, so they share these semantics exactly.

Note that the doc comments above these prototypes in `lib/bufq.h` still say
"the amount of copied bytes is returned", which describes an older signature.
The prototypes are authoritative; the surrounding comment has not kept pace.

To pass data into a `bufq` without an extra copy, read callbacks can be used.

```c
typedef CURLcode Curl_bufq_reader(void *reader_ctx,
                                  uint8_t *buf, size_t len,
                                  size_t *pnread);

CURLcode Curl_bufq_slurp(struct bufq *q, Curl_bufq_reader *reader,
                         void *reader_ctx, size_t *pnread);

CURLcode Curl_bufq_sipn(struct bufq *q, size_t max_len,
                        Curl_bufq_reader *reader, void *reader_ctx,
                        size_t *pnread);
```

`Curl_bufq_slurp()` invokes the given `reader` callback, passing it its own
internal buffer memory to write to. It may invoke the `reader` several times,
as long as it has space and while the `reader` keeps reporting through `pnread`
the full length that was requested. `Curl_bufq_sipn()` is the variation that
calls the `reader` at most once, and it takes a `max_len` ceiling: when
`max_len` is 0 the only limit is the available chunk space.

The analog mechanism for write out buffer data is:

```c
typedef CURLcode Curl_bufq_writer(void *writer_ctx,
                                  const uint8_t *buf, size_t len,
                                  size_t *pwritten);

CURLcode Curl_bufq_pass(struct bufq *q, Curl_bufq_writer *writer,
                        void *writer_ctx, size_t *pwritten);

CURLcode Curl_bufq_write_pass(struct bufq *q,
                              const uint8_t *buf, size_t len,
                              Curl_bufq_writer *writer, void *writer_ctx,
                              size_t *pwritten);
```

`Curl_bufq_pass()` invokes the `writer`, passing its internal memory, and
removes the amount that `writer` reports through `pwritten`.
`Curl_bufq_write_pass()` is the combined form: it writes `buf` to the queue and
passes queued content on through the same `writer`.

The stale wording noted above is at its most visible here. The doc comments
over these prototypes still describe a writer that "may return -1 and
CURLE_AGAIN"
and say "-1 is returned on any other errors", which no longer matches a
`CURLcode` return with a `size_t *` out-parameter. Read the prototypes, not the
comments.

## peek and skip

It is possible to get access to the memory of data stored in a `bufq` with:

```c
bool Curl_bufq_peek(struct bufq *q, const uint8_t **pbuf, size_t *plen);
```

On returning TRUE, `pbuf` points to internal memory with `plen` bytes that one
may read. This is only valid until another operation on `bufq` is performed.
On returning FALSE it sets `pbuf` to NULL and `plen` to 0.

The `q` parameter is **not** `const`, and that is deliberate rather than an
oversight: the call prunes an exhausted head chunk before looking
(`lib/bufq.c:426-428`), so peeking can mutate the queue's chunk list even
though it does not consume any bytes.

Instead of reading `bufq` data, one may simply skip it:

```
void Curl_bufq_skip(struct bufq *q, size_t amount);
```

This removes `amount` number of bytes from the `bufq`.

## lifetime

`bufq` is initialized and freed similar to the `dynbuf` module. Code using
`bufq` holds a `struct bufq` somewhere. Before it uses it, it invokes:

```
void Curl_bufq_init(struct bufq *q, size_t chunk_size, size_t max_chunks);
```

The `bufq` is told how many "chunks" of data it shall hold at maximum and how
large those "chunks" should be. There are some variants of this, allowing for
more options. How "chunks" are handled in a `bufq` is presented in the section
about memory management.

The user of the `bufq` has the responsibility to call:

```
void Curl_bufq_free(struct bufq *q);
```
to free all resources held by `q`. It is possible to reset a `bufq` to empty via:

```
void Curl_bufq_reset(struct bufq *q);
```

## memory management

Internally, a `bufq` uses allocation of fixed size, e.g. the "chunk_size", up
to a maximum number, e.g. "max_chunks". These chunks are allocated on demand,
therefore writing to a `bufq` may return `CURLE_OUT_OF_MEMORY`. Once the max
number of chunks are used, the `bufq` reports that it is "full".

Each chunks has a `read` and `write` index. A `bufq` keeps its chunks in a
list. Reading happens always at the head chunk, writing always goes to the
tail chunk. When the head chunk becomes empty, it is removed. When the tail
chunk becomes full, another chunk is added to the end of the list, becoming
the new tail.

Chunks that are no longer used are returned to a `spare` list by default. If
the `bufq` is created with option `BUFQ_OPT_NO_SPARES` those chunks are freed
right away.

If a `bufq` is created with a `bufc_pool`, the no longer used chunks are
returned to the pool. Also `bufq` asks the pool for a chunk when it needs one.
More in section "pools".

## empty, full and overflow

One can ask about the state of a `bufq` with methods such as
`Curl_bufq_is_empty(q)`, `Curl_bufq_is_full(q)`, etc. The amount of data held
by a `bufq` is the sum of the data in all its chunks. This is what is reported
by `Curl_bufq_len(q)`.

Note that a `bufq` length and it being "full" are only loosely related. A
simple example:

* create a `bufq` with chunk_size=1000 and max_chunks=4.
* write 4000 bytes to it, it reports "full"
* read 1 bytes from it, it still reports "full"
* read 999 more bytes from it, and it is no longer "full"

The reason for this is that full really means: *bufq uses max_chunks and the
last one cannot be written to*.

When you read 1 byte from the head chunk in the example above, the head still
hold 999 unread bytes. Only when those are also read, can the head chunk be
removed and a new tail be added.

There is another variation to this. If you initialized a `bufq` with option
`BUFQ_OPT_SOFT_LIMIT`, it allows writes **beyond** the `max_chunks`. It
reports **full**, but one can **still** write. This option is necessary, if
partial writes need to be avoided. It means that you need other checks to keep
the `bufq` from growing ever larger and larger.

## pools

A `struct bufc_pool` may be used to create chunks for a `bufq` and keep spare
ones around. It is initialized and used via:

```
void Curl_bufcp_init(struct bufc_pool *pool, size_t chunk_size, size_t spare_max);

void Curl_bufq_initp(struct bufq *q, struct bufc_pool *pool, size_t max_chunks, int opts);
```

The pool gets the size and the mount of spares to keep. The `bufq` gets the
pool and the `max_chunks`. It no longer needs to know the chunk sizes, as
those are managed by the pool.

A pool can be shared between many `bufq`s, as long as all of them operate in
the same thread. In curl that would be true for all transfers using the same
multi handle. The advantages of a pool are:

* when all `bufq`s are empty, only memory for `max_spare` chunks in the pool
  is used. Empty `bufq`s holds no memory.
* the latest spare chunk is the first to be handed out again, no matter which
  `bufq` needs it. This keeps the footprint of "recently used" memory smaller.

## The specified `Rust` successor

The migration to the three-`crate` `Rust` `workspace` specifies a successor to
this module at `curl-rs-lib/src/util/bufq.rs`. That module does not exist in
the tree, so the path and the design below are the specified target state,
while `lib/bufq.c` and `lib/bufq.h` remain the reference oracle at runtime.

The shape of the transformation is that the queue holds owned buffer segments
instead of a hand-linked list of chunks. The specified design uses
`bytes::BytesMut` for a segment and an owned collection such as `VecDeque` for
the queue itself, so dropping the head and appending to the tail are
collection operations rather than pointer surgery. The three pointer chains
that C maintains, the chunk list, the spare list and the pool, become
questions of ownership that the type answers: a segment is held by the queue,
or held by the pool, or dropped.

Each part of the contract stated near the top of this page maps across as
follows.

- Ordering, byte counts and the head and tail discipline are preserved
  unchanged. Reads take from the head segment and writes append to the tail
  segment, a `VecDeque` of segments yields exactly the same observable
  sequence of bytes, and the reported length remains the sum across the
  segments held.
- The full and empty signaling is preserved, and `CURLE_AGAIN` remains
  observable. It is a public error code, and the transfer and
  connection-filter layers read it as back-pressure rather than as failure.
  Its internal expression may be a result type; the code that a caller sees
  does not change.
- Pause and resume behavior is preserved. A queue that reports full is how a
  paused reader or writer stops the flow, which ties this module to
  [curl client readers](CLIENT-READERS.md) and
  [curl client writers](CLIENT-WRITERS.md), where pausing is documented.
- The soft limit remains a distinct and explicit mode rather than something a
  caller reaches by accident, because a caller that must avoid a partial
  write depends on it.
- The `Curl_bufq_peek` validity window stops being a rule that a reader of
  this page has to remember. A borrow of the head segment is checked by the
  compiler, so using it after the next mutation of the queue is a compile
  error instead of a runtime hazard.
- `Curl_bufq_slurp` and `Curl_bufq_pass` exist so that a reader or a writer
  can work against the memory that the queue already holds. The specified
  design keeps that shape by handing the callback a mutable slice of the tail
  segment or an immutable slice of the head segment. It copies wherever the C
  code copies and borrows wherever the C code borrows: no copy that
  `lib/bufq.c` performs is claimed to disappear, and none is added.
- `struct bufc_pool` maps to a shared segment pool owned at the multi-handle
  level, which matches the existing constraint that a pool is shared only
  among queues operating in the same thread. A multi-thread runtime backs the
  multi handle; the CLI uses a current-thread `tokio` runtime. The
  single-thread assumption therefore becomes a statement about which value
  owns the pool, rather than a comment asking each caller to be careful.

The safety invariant at the root of `curl-rs-lib` is `#![deny(unsafe_code)]`
plus exactly one `#[allow(unsafe_code)]`, on `mod ffi` -- the single narrowly
allowed island under `curl-rs-lib/src/ffi/` for the operating system calls that
have no safe expression, where every `unsafe` block carries a mandatory
`// SAFETY:` comment. It is `deny` and not `forbid` because `forbid` cannot be
locally overridden (`error[E0453]: allow(unsafe_code) incompatible with
previous forbid`) and Agent Action Plan goal G1 permits only three crates, so
the island cannot move into a fourth; `deny` is no weaker, since a stray
`unsafe` block outside the island is a hard error rather than a warning. A
buffer queue has no business in that island. The manual chunk arithmetic of
the C version, its read and write offsets and its spare list bookkeeping, is
the class of code that the invariant removes.

For the sibling buffer modules, see [dynbuf](DYNBUF.md), the module that a
`bufq` follows for initialization and release, and [bufref](BUFREF.md).
[`curlx`](CURLX.md) covers how the wider `lib/curlx/` set maps.
