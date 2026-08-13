<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# bufref

This is an internal module for handling buffer references. A referenced
buffer is associated with its destructor function that is implicitly called
when the reference is invalidated. Once referenced, a buffer cannot be
reallocated.

A data length is stored within the reference for binary data handling
purposes; it is not used by the bufref API.

The `struct bufref` is used to hold data referencing a buffer. The members of
that structure **MUST NOT** be accessed or modified without using the dedicated
bufref API.

The C implementation in `lib/bufref.c`, together with its interface in
`lib/bufref.h`, is the reference oracle for this module: it defines the
behavior that the migration preserves. The guarantees below are stated
explicitly because the successor described at the end of this page maps them
one for one.

- A reference owns a destructor, and that destructor runs when the reference
  is invalidated.
- A buffer cannot be reallocated while it is referenced.
- The stored length is metadata carried for binary data handling. The bufref
  API does not interpret it.
- A `NULL` buffer implies a zero length, and the two never disagree.
- A static buffer is expressed by passing a `NULL` destructor, which leaves
  nothing to release.
- `Curl_bufref_memdup0` always allocates one byte beyond the copied data and
  sets that byte to zero, and it excludes the byte from the stored length.
- `Curl_bufref_dup` assumes the referenced buffer is null terminated.

## `init`

```c
void Curl_bufref_init(struct bufref *br);
```

Initializes a `bufref` structure. This function **MUST** be called before any
other operation is performed on the structure.

Upon completion, the referenced buffer is `NULL` and length is zero.

This function may also be called to bypass referenced buffer destruction while
invalidating the current reference.

## `free`

```c
void Curl_bufref_free(struct bufref *br);
```

Destroys the previously referenced buffer using its destructor and
reinitializes the structure for a possible subsequent reuse.

## `set`

```c
void Curl_bufref_set(struct bufref *br, const void *buffer, size_t length,
                     void (*destructor)(void *));
```

Releases the previously referenced buffer, then assigns the new `buffer` to
the structure, associated with its `destructor` function. The latter can be
specified as `NULL`: this is the case when the referenced buffer is static.

if `buffer` is NULL, `length` must be zero.

## `memdup0`

```c
CURLcode Curl_bufref_memdup0(struct bufref *br, const void *data,
                             size_t length);
```

Releases the previously referenced buffer, then duplicates the `length`-byte
`data` into a buffer allocated via `malloc()` and references the latter
associated with destructor `curl_free()`.

An additional trailing byte is allocated and set to zero as a possible string
null-terminator; it is not counted in the stored length.

Returns `CURLE_OK` if successful, else `CURLE_OUT_OF_MEMORY`.

## `ptr`

```c
const char *Curl_bufref_ptr(const struct bufref *br);
```

Returns a `const char *` to the referenced buffer.

## `uptr`

```c
const unsigned char *Curl_bufref_uptr(const struct bufref *br);
```

Returns a `const unsigned char *` to the referenced buffer.

## `len`

```c
size_t Curl_bufref_len(const struct bufref *br);
```

Returns the stored length of the referenced buffer.

## `dup`

```c
char *Curl_bufref_dup(const struct bufref *br);
```

Returns a strdup() version of the buffer. Note that this assumes that the
bufref is null terminated.

## The `Rust` successor

The successor to this module is **delivered** at
`curl-rs-lib/src/util/bufref.rs`, with its own tests, while `lib/bufref.c`
remains the reference oracle.

What shipped is a plain alias over the standard library's clone-on-write
container rather than a new struct, and the reason is worth recording: once the
destructor field and the signature field are gone, the C type has no invariant
left for a wrapper to protect, and a wrapper would have to forward length,
indexing, iteration, comparison and cloning to earn nothing. The alias keeps a
dereference to a byte slice, so reading the bytes is the C's pointer accessor
and asking for the length is its length accessor, with no new API to learn. The
lifetime parameter is what replaces the destructor field: a reference that owns
its allocation releases it on drop, exactly as a C reference holding the free
function does, and a borrowed one cannot outlive the bytes it points at, which
is a rule the C could only state in a comment. The C's `NULL`-pointer
"never set" state is not one of the alias's cases; it is an absent optional at
the field that needs it, because the difference is observable on the wire.

The transformation is that ownership becomes explicit in the type. A `bufref`
is needed in C because the language has no way to state that a pointer is
borrowed and to name who cleans it up, so the reference carries a function
pointer and the cleanup travels alongside the data. In the delivered design
that distinction belongs to the type, which separates the three cases the C
API expresses through a single structure.

- A borrowed, caller-owned buffer becomes a slice reference with an explicit
  lifetime. There is no destructor to carry, because the owner remains the
  owner.
- An owned buffer becomes an owned byte container. Its destructor is the
  ordinary drop behavior, which runs at the end of the scope without a stored
  function pointer.
- A statically allocated buffer is exactly the `NULL`-destructor case, and it
  becomes a reference with a static lifetime.

Each function on this page maps across as follows.

- `Curl_bufref_init` and `Curl_bufref_free` have no successor call to make.
  Initialization is the construction of the value and release is its drop, so
  neither step needs an entry point of its own. Stating that plainly is more
  accurate than inventing an equivalent for each one.
- `Curl_bufref_set` maps to constructing the borrowed or the owned variant.
  The rule that a `NULL` buffer requires a zero length is preserved by making
  the empty case a distinct state that the type can express, rather than a
  pointer and a length that can disagree.
- `Curl_bufref_memdup0` maps to an owned copy. The trailing zero byte, and its
  exclusion from the reported length, are behavioral and are preserved:
  callers hand the buffer on to code that reads it as a C string, so the byte
  belongs to the contract rather than to the implementation.
- `Curl_bufref_ptr` and `Curl_bufref_uptr` map to borrowing the bytes as a
  slice. The signed and unsigned character distinction is an artifact of C
  typing and has a single `Rust` representation.
- `Curl_bufref_len` maps to the length of that slice.
- `Curl_bufref_dup` maps to producing an owned, null-terminated copy. The
  assumption that the referenced buffer is null terminated remains a contract
  the caller upholds.

The successor copies wherever the C code copies and borrows wherever
the C code borrows. `Curl_bufref_memdup0` allocates and copies, and its
successor allocates and copies as well. Shapes such as `bytes::Bytes` are
available in the dependency set, and naming one here states only that the
shape is available: no copy that the C code performs is claimed to disappear.
Removing one would be a behavior change dressed as an improvement, which is
out of scope.

The safety invariant at the root of `curl-rs-lib` is `#![deny(unsafe_code)]`
plus exactly one `#[allow(unsafe_code)]`, on `mod ffi` -- the single narrowly
allowed island under `curl-rs-lib/src/ffi/` for the operating system calls that
have no safe expression, where every `unsafe` block carries a mandatory
`// SAFETY:` comment. It is `deny` and not `forbid` because `forbid` cannot be
locally overridden (`error[E0453]: allow(unsafe_code) incompatible with
previous forbid`) and Agent Action Plan goal G1 permits only three crates, so
the island cannot move into a fourth; `deny` is no weaker, since a stray
`unsafe` block outside the island is a hard error rather than a warning. A
buffer reference has no business in that island. The one place where a raw
pointer and a caller-supplied destructor genuinely survive is the public C ABI
surface, and that surface is confined to `curl-rs-ffi`.

For the sibling buffer modules, see [dynbuf](DYNBUF.md) and [bufq](BUFQ.md).
[`curlx`](CURLX.md) covers how the wider `lib/curlx/` set maps.
