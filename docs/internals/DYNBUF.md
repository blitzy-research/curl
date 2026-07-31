<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# dynbuf

This is the internal module for creating and handling "dynamic buffers". This
means buffers that can be appended to, dynamically and grow to adapt.

There is always a terminating zero put at the end of the dynamic buffer.

The `struct dynbuf` is used to hold data for each instance of a dynamic
buffer. The members of that struct **MUST NOT** be accessed or modified
without using the dedicated dynbuf API.

The C implementation in `lib/curlx/dynbuf.c`, together with its interface in
`lib/curlx/dynbuf.h`, is the reference oracle for this module: it defines the
behavior that the migration preserves. The guarantees below are stated
explicitly because the successor described at the end of this page maps them
one for one.

- A terminating zero always follows the data, and it is not counted in the
  length that `curlx_dyn_len` reports.
- `toobig` caps growth: an append that needs to grow the buffer past that cap
  yields `CURLE_OUT_OF_MEMORY` instead of a larger allocation.
- A failing append calls `curlx_dyn_free` on the buffer.
- A pointer returned by `curlx_dyn_ptr` or `curlx_dyn_uptr` is invalidated by
  the next buffer manipulation call.
- `curlx_dyn_reset` keeps the allocation and clears the length.
- `curlx_dyn_take` transfers ownership of the allocation to the caller and
  returns the buffer to its initial state.

## `curlx_dyn_init`

```c
void curlx_dyn_init(struct dynbuf *s, size_t toobig);
```

This initializes a struct to use for dynbuf and it cannot fail. The `toobig`
value **must** be set to the maximum size we allow this buffer instance to
grow to. The functions below return `CURLE_OUT_OF_MEMORY` when hitting this
limit.

## `curlx_dyn_free`

```c
void curlx_dyn_free(struct dynbuf *s);
```

Free the associated memory and clean up. After a free, the `dynbuf` struct can
be reused to start appending new data to.

## `curlx_dyn_addn`

```c
CURLcode curlx_dyn_addn(struct dynbuf *s, const void *mem, size_t len);
```

Append arbitrary data of a given length to the end of the buffer.

If this function fails it calls `curlx_dyn_free` on `dynbuf`.

## `curlx_dyn_add`

```c
CURLcode curlx_dyn_add(struct dynbuf *s, const char *str);
```

Append a C string to the end of the buffer.

If this function fails it calls `curlx_dyn_free` on `dynbuf`.

## `curlx_dyn_addf`

```c
CURLcode curlx_dyn_addf(struct dynbuf *s, const char *fmt, ...);
```

Append a `printf()`-style string to the end of the buffer.

If this function fails it calls `curlx_dyn_free` on `dynbuf`.

## `curlx_dyn_vaddf`

```c
CURLcode curlx_dyn_vaddf(struct dynbuf *s, const char *fmt, va_list ap);
```

Append a `vprintf()`-style string to the end of the buffer.

If this function fails it calls `curlx_dyn_free` on `dynbuf`.

## `curlx_dyn_reset`

```c
void curlx_dyn_reset(struct dynbuf *s);
```

Reset the buffer length, but leave the allocation.

## `curlx_dyn_tail`

```c
CURLcode curlx_dyn_tail(struct dynbuf *s, size_t length);
```

Keep `length` bytes of the buffer tail (the last `length` bytes of the
buffer). The rest of the buffer is dropped. The specified `length` must not be
larger than the buffer length. To instead keep the leading part, see
`curlx_dyn_setlen()`.

## `curlx_dyn_ptr`

```c
char *curlx_dyn_ptr(const struct dynbuf *s);
```

Returns a `char *` to the buffer if it has a length, otherwise may return
NULL. Since the buffer may be reallocated, this pointer should not be trusted
or used anymore after the next buffer manipulation call.

## `curlx_dyn_uptr`

```c
unsigned char *curlx_dyn_uptr(const struct dynbuf *s);
```

Returns an `unsigned char *` to the buffer if it has a length, otherwise may
return NULL. Since the buffer may be reallocated, this pointer should not be
trusted or used anymore after the next buffer manipulation call.

## `curlx_dyn_len`

```c
size_t curlx_dyn_len(const struct dynbuf *s);
```

Returns the length of the buffer in bytes. Does not include the terminating
zero byte.

## `curlx_dyn_setlen`

```c
CURLcode curlx_dyn_setlen(struct dynbuf *s, size_t len);
```

Sets the new shorter length of the buffer in number of bytes. Keeps the
leftmost set number of bytes, discards the rest. To instead keep the tail part
of the buffer, see `curlx_dyn_tail()`.

## `curlx_dyn_take`

```c
char *curlx_dyn_take(struct dynbuf *s, size_t *plen);
```

Transfers ownership of the internal buffer to the caller. The dynbuf
resets to its initial state. The returned pointer may be `NULL` if the
dynbuf never allocated memory. The returned length is the amount of
data written to the buffer. The actual allocated memory might be larger.

## The specified `Rust` successor

The migration to the three-`crate` `Rust` `workspace` specifies a successor to
this module at `curl-rs-lib/src/util/dynbuf.rs`. No `Rust` source file exists
in the tree yet, so that path and the design below are the specified target
state, while `lib/curlx/dynbuf.c` remains the reference oracle at runtime.

The heart of the transformation is that the length and the capacity move into
the type instead of being tracked by hand. In C, `struct dynbuf` carries a
pointer, a length, an allocation size and the `toobig` cap, and every append
recomputes those numbers across a `malloc` or `realloc` boundary. The
specified design builds on `bytes::BytesMut` and `Vec<u8>`, where length and
capacity are the responsibility of the type, leaving no hand-written
arithmetic to get wrong and no reallocation for a caller to miss.

Each guarantee listed near the top of this page maps across as follows.

- The `toobig` cap stays an explicit, checked maximum. Callers depend on
  `CURLE_OUT_OF_MEMORY` at exactly that boundary, which makes the cap a
  behavioral contract rather than an implementation detail.
- The terminating zero stays observable wherever a caller reads the buffer as
  a C string. The specified design places the trailing zero at the boundary
  that produces a C string and keeps it out of the reported length.
- The pointer invalidation rule stops being a rule the reader has to
  remember. `curlx_dyn_ptr` hands back a pointer that the next manipulation
  may invalidate; under the specified design the borrow checker tracks that
  lifetime, which turns a stale reference into a compile error rather than a
  runtime hazard.
- `curlx_dyn_take` maps to returning the owned buffer by value: ordinary
  ownership transfer, expressed by the type rather than by a documented
  convention.
- `curlx_dyn_reset` maps to clearing the length while retaining the capacity.
- `curlx_dyn_addf` and `curlx_dyn_vaddf` append formatted output. The C
  versions route through the internal `printf` replacement of libcurl, while
  the specified design uses ordinary `Rust` formatting. The formatted
  **output** is what has to match, not the mechanism that produces it; where
  a public interface exposes the `printf` behavior itself, that behavior is
  reproduced in `curl-rs-ffi/src/ffi/printf.rs`.

`#![forbid(unsafe_code)]` is specified at the root of `curl-rs-lib`, with a
single narrowly allowed island under `curl-rs-lib/src/ffi/` for the operating
system calls that have no safe expression, and a mandatory `// SAFETY:`
comment on every `unsafe` block there. A buffer module has no business in that
island: the design above reaches for nothing that `bytes::BytesMut` or
`Vec<u8>` does not already provide safely.

For the sibling buffer modules, see [bufq](BUFQ.md), whose text notes that a
`bufq` is initialized and freed similar to the `dynbuf` module, and
[bufref](BUFREF.md). [`curlx`](CURLX.md) covers how the wider `lib/curlx/` set
maps.
