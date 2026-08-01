<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl client writers

Client writers is a design in the internals of libcurl, not visible in its
public API. They were started in curl v8.5.0. This document describes the
concepts, its high level implementation and the motivations.

The C implementation is the reference oracle for this design. `lib/sendf.c`
holds the writer chain, `lib/cw-out.c` the client writer at the end of it and
the buffering that writer performs, `lib/cw-pause.c` the pause handling and
`lib/content_encoding.c` the decoders. Those four files define the behavior
that the migration preserves. The contract below is restated explicitly
because it is precisely what the successor described at the end of this page
maps one for one, rather than reinterprets.

- **Header and body ordering is observable.** The application sees headers
  before the body they belong to, and it sees them in the order they arrived.
  Interleaving or reordering them changes behavior.
- **The type bits are part of the contract.** Whether a write is a body, a
  header, an informational header, a status line, a CONNECT response, a 1xx
  response or a trailer decides which application callback receives it, and
  whether it is written at all.
- **`CLIENTWRITE_BODY`, `CLIENTWRITE_INFO` and `CLIENTWRITE_HEADER` are three
  mutually exclusive classes**, and at least one of them is always set.
  `CLIENTWRITE_INFO` is a class in its own right -- meta information that is
  not a header -- not a qualifier on `CLIENTWRITE_HEADER`. The three
  `DEBUGASSERT`s at `lib/sendf.c:380-388` state the rule exactly: one of the
  three is present; `BODY` may be accompanied only by `EOS`; and `INFO` may be
  accompanied only by `EOS`. The qualifier bits `CLIENTWRITE_STATUS`,
  `CLIENTWRITE_CONNECT`, `CLIENTWRITE_1XX` and `CLIENTWRITE_TRAILER` therefore
  qualify `CLIENTWRITE_HEADER` alone.
- **`CLIENTWRITE_EOS` and `CLIENTWRITE_0LEN` are orthogonal to the class
  bits.** `EOS` marks the end of the download stream and is the one bit that
  may accompany `BODY` or `INFO`; `0LEN` asks for the write to happen even
  when the buffer is empty.
- **None of these bits is part of the public ABI.** They are internal to
  `lib/sendf.h`: `CLIENTWRITE` appears zero times anywhere under `include/`.
  The application sees only the callback it registered, never a type bit.
- **Phase ordering is behavioral.** The protocol length check happens before
  content decoding, which makes the compared length the length received and
  not the length after decoding. Moving that check produces different errors
  on the same input.
- **Write chopping is observable.** A write larger than the maximum documented
  for `CURLOPT_WRITEFUNCTION` is split, and the application therefore sees a
  particular sequence of callback invocations.
- **Pausing is observable and must not lose bytes.** When an application
  callback returns `CURL_WRITEFUNC_PAUSE`, the bytes already produced are held
  and then delivered in the same order once the transfer is unpaused. That
  buffering is why `lib/cw-out.c` and `lib/cw-pause.c` exist as separate
  concerns.

## Naming

`libcurl` operates between clients and servers. A *client* is the application
using libcurl, like the command line tool `curl` itself. Data to be uploaded
to a server is **read** from the client and **send** to the server, the
servers response is **received** by `libcurl` and then **written** to the
client.

With this naming established, client writers are concerned with writing
responses from the server to the application. Applications register callbacks
via `CURLOPT_WRITEFUNCTION` and `CURLOPT_HEADERFUNCTION` to be invoked by
`libcurl` when the response is received.

## Invoking

All code in `libcurl` that handles response data is ultimately expected to
forward this data via `Curl_client_write()` to the application. The exact
prototype of this function is:

```
CURLcode Curl_client_write(struct Curl_easy *data, int type, const char *buf, size_t blen);
```

The `type` argument specifies what the bytes in `buf` actually are.
The following bits are defined:
```
#define CLIENTWRITE_BODY    (1 << 0) /* non-meta information, BODY */
#define CLIENTWRITE_INFO    (1 << 1) /* meta information, not a HEADER */
#define CLIENTWRITE_HEADER  (1 << 2) /* meta information, HEADER */
#define CLIENTWRITE_STATUS  (1 << 3) /* a special status HEADER */
#define CLIENTWRITE_CONNECT (1 << 4) /* a CONNECT related HEADER */
#define CLIENTWRITE_1XX     (1 << 5) /* a 1xx response related HEADER */
#define CLIENTWRITE_TRAILER (1 << 6) /* a trailer HEADER */
#define CLIENTWRITE_EOS     (1 << 7) /* End Of transfer download Stream */
#define CLIENTWRITE_0LEN    (1 << 8) /* write even 0-length buffers */
```

The class types here are `CLIENTWRITE_BODY`, `CLIENTWRITE_INFO` and
`CLIENTWRITE_HEADER`, and they are mutually exclusive: `BODY` is non-meta
information, `INFO` is meta information that is not a header, and `HEADER` is
meta information that is. `CLIENTWRITE_STATUS`, `CLIENTWRITE_CONNECT`,
`CLIENTWRITE_1XX` and `CLIENTWRITE_TRAILER` are enhancements to
`CLIENTWRITE_HEADER` alone, specifying what the header is about, and they are
only used in HTTP and related protocols (RTSP and WebSocket).

`CLIENTWRITE_EOS` and `CLIENTWRITE_0LEN` are not header enhancements. `EOS`
marks the end of the download stream and is the only bit permitted alongside
`BODY` or `INFO`; `0LEN` requests that the write happen even for an empty
buffer.

The implementation of `Curl_client_write()` uses a chain of *client writer*
instances to process the call and make sure that the bytes reach the proper
application callbacks. This is similar to the design of connection filters:
client writers can be chained to process the bytes written through them. The
definition is:

```
struct Curl_cwtype {
  const char *name;
  CURLcode (*do_init)(struct Curl_easy *data,
                      struct Curl_cwriter *writer);
  CURLcode (*do_write)(struct Curl_easy *data,
                       struct Curl_cwriter *writer, int type,
                       const char *buf, size_t nbytes);
  void (*do_close)(struct Curl_easy *data,
                   struct Curl_cwriter *writer);
};

struct Curl_cwriter {
  const struct Curl_cwtype *cwt;  /* type implementation */
  struct Curl_cwriter *next;  /* Downstream writer. */
  Curl_cwriter_phase phase; /* phase at which it operates */
};
```

`Curl_cwriter` is a writer instance with a `next` pointer to form the chain.
It has a type `cwt` which provides the implementation. The main callback is
`do_write()` that processes the data and calls then the `next` writer. The
others are for setup and tear down.

## Phases and Ordering

Since client writers may transform the bytes written through them, the order
in which the are called is relevant for the outcome. When a writer is created,
one property it gets is the `phase` in which it operates. Writer phases are
defined like:

```
typedef enum {
  CURL_CW_RAW,  /* raw data written, before any decoding */
  CURL_CW_TRANSFER_DECODE, /* remove transfer-encodings */
  CURL_CW_PROTOCOL, /* after transfer, but before content decoding */
  CURL_CW_CONTENT_DECODE, /* remove content-encodings */
  CURL_CW_CLIENT  /* data written to client */
} Curl_cwriter_phase;
```

If a writer for phase `PROTOCOL` is added to the chain, it is always added
*after* any `RAW` or `TRANSFER_DECODE` and *before* any `CONTENT_DECODE` and
`CLIENT` phase writer. If there is already a writer for the same phase
present, the new writer is inserted just before that one.

All transfers have a chain of 3 writers by default. A specific protocol
handler may alter that by adding additional writers. The 3 standard writers
are (name, phase):

1. `"raw", CURL_CW_RAW `: if the transfer is verbose, it forwards the body data
   to the debug function.
1. `"download", CURL_CW_PROTOCOL`: checks that protocol limits are kept and
   updates progress counters. When a download has a known length, it checks
   that it is not exceeded and errors otherwise.
1. `"client", CURL_CW_CLIENT`: the main work horse. It invokes the application
   callbacks or writes to the configured file handles. It chops large writes
   into smaller parts, as documented for `CURLOPT_WRITEFUNCTION`. If also
   handles *pausing* of transfers when the application callback returns
   `CURL_WRITEFUNC_PAUSE`.

With these writers always in place, libcurl's protocol handlers automatically
have these implemented.

## Enhanced Use

HTTP is the protocol in curl that makes use of the client writer chain by
adding writers to it. When the `libcurl` application set
`CURLOPT_ACCEPT_ENCODING` (as `curl` does with `--compressed`), the server is
offered an `Accept-Encoding` header with the algorithms supported. The server
then may choose to send the response body compressed. For example using `gzip`
or `brotli` or even both.

In the server's response, if there is a `Content-Encoding` header listing the
encoding applied. If supported by `libcurl` it then decompresses the content
before writing it out to the client. How does it do that?

The HTTP protocol adds client writers in phase `CURL_CW_CONTENT_DECODE` on
seeing such a header. For each encoding listed, it adds the corresponding
writer. The response from the server is then passed through
`Curl_client_write()` to the writers that decode it. If several encodings had
been applied the writer chain decodes them in the proper order, and that order
is the **reverse** of the order in which the writers were added. Each writer is
inserted *first* in its phase (`lib/sendf.c:464-469`), so the one added last
sits at the head of the chain and runs first.

That is exactly what decoding requires. A `Content-Encoding: gzip, br` response
was gzipped and then brotli-compressed, so the brotli layer has to come off
before the gzip layer. `lib/content_encoding.c:768-780` leans on the same
mechanism when it rejects a response whose `chunked` transfer coding is not
last, observing that `chunked` "must be the last added to be the first in its
phase".

When the server provides a `Content-Length` header, that value applies to the
*compressed* content. Length checks on the response bytes must happen *before*
it gets decoded. That is why this check happens in phase `CURL_CW_PROTOCOL`
which always is ordered before writers in phase `CURL_CW_CONTENT_DECODE`.

What else?

Well, HTTP servers may also apply a `Transfer-Encoding` to the body of a
response. The most well-known one is `chunked`, but algorithms like `gzip` and
friends could also be applied. The difference to content encodings is that
decoding needs to happen *before* protocol checks, for example on length, are
done.

That is why transfer decoding writers are added for phase
`CURL_CW_TRANSFER_DECODE`. Which makes their operation happen *before* phase
`CURL_CW_PROTOCOL` where length may be checked.

## Summary

By adding the common behavior of all protocols into `Curl_client_write()` we
make sure that they do apply everywhere. Protocol handler have less to worry
about. Changes to default behavior can be done without affecting handler
implementations.

Having a writer chain as implementation allows protocol handlers with extra
needs, like HTTP, to add to this for special behavior. The common way of
writing the actual response data stays the same.

## The specified `Rust` successor

The migration to the three-`crate` `Rust` `workspace` specifies successors to
the four C files named at the top of this page. The tree does already contain
`Rust` source, in all three `crates`, but no successor to any of those four
files has been delivered, so each path in the list below is specified target
state, while those C files remain the reference oracle at runtime. Two names
mentioned further down are exceptions and are marked as such where they appear:
`curl-rs/src/output/writeout.rs`, which is a different concern from this chain,
and `curl-rs/src/bin/curlinfo.rs`, both of which do exist.

- `curl-rs-lib/src/transfer/writeout.rs` succeeds `lib/cw-out.c` and
  `lib/cw-pause.c`: the client writer at the end of the chain, together with
  the pause handling.
- `curl-rs-lib/src/transfer/sendf.rs` succeeds `lib/sendf.c`: the shared send
  and write plumbing that builds the chain and drives it.
- `curl-rs-lib/src/transfer/content_encoding.rs` succeeds
  `lib/content_encoding.c`: the content coding decoders.
- On the tool side, `curl-rs/src/callbacks/write.rs` succeeds
  `src/tool_cb_wrt.c`, `curl-rs/src/callbacks/header.rs` succeeds
  `src/tool_cb_hdr.c` and `curl-rs/src/callbacks/debug.rs` succeeds
  `src/tool_cb_dbg.c`. Those three hold the callbacks that the curl tool
  installs, which puts them at the client end of everything described above.

One name invites confusion and is worth separating out here.
`curl-rs/src/output/writeout.rs` is the successor to `src/tool_writeout.c` and
`src/tool_writeout_json.c`, which format the `--write-out` report once a
transfer has finished; unlike the paths listed above, this one **is**
delivered. Despite the similar filename it is a **different** concern from the
client writer chain:
`curl-rs-lib/src/transfer/writeout.rs` is the chain, and
`curl-rs/src/output/writeout.rs` is the report.

Each part of the contract stated near the top of this page maps across as
follows.

- **The writer type becomes a trait.** `struct Curl_cwtype` is a name plus a
  table of function pointers, which is the strategy pattern written without
  language support for it. The specified design expresses it as a trait that
  each stage implements, so `do_init`, `do_write` and `do_close` become
  methods on that trait. The `next` pointer of `struct Curl_cwriter` becomes
  an owned chain of boxed trait objects: a stage owns its successor, and the
  chain is released with the transfer that holds it.
- **The phase enumeration is preserved as an explicit ordered enumeration**,
  with the insertion rule described above intact. The protocol length check
  stays at `CURL_CW_PROTOCOL`, ahead of `CURL_CW_CONTENT_DECODE`, and that
  ordering is a deliberate constraint rather than an accident of the C code: a
  check placed behind the decoders compares the decoded length instead of the
  received one, which changes the error that a truncated compressed response
  produces.
- **The type bits are preserved as an explicit set of flags.** Their numeric
  shape matters wherever it crosses the public C ABI, so those values stay
  pinned in `curl-rs-ffi`. Inside `curl-rs-lib` the same distinctions travel
  in a typed value, which turns the mutual exclusivity of body and header
  into a property of the type rather than a convention that every caller has
  to keep.
- **Header and body ordering is preserved.** The fixture corpus compares
  emitted bytes against a literal expectation, header order included, which is
  why the specified module for HTTP/1.1 at
  `curl-rs-lib/src/protocols/http1.rs` owns request line composition and
  header emission itself instead of delegating them to the `hyper` `crate`.
  The writer side is the mirror of that: what the application observes arrives
  in exactly the order it was received, with headers ahead of the body they
  belong to.
- **Pausing keeps its buffering.** The held bytes become an owned buffer,
  `bytes::BytesMut` or `Vec<u8>`, so the length and capacity bookkeeping that
  `lib/cw-out.c` performs by hand is carried by the type instead. The two
  buffer modules that those C files build on are described in
  [dynbuf](DYNBUF.md) and [bufq](BUFQ.md). Ordering across a pause does not
  change: what was held is played back to the callbacks in the order it
  arrived, with body and header buffers interleaved exactly as they were
  produced. The pause state is owned by the transfer rather than reached for
  through a shared mutable structure declared in `lib/urldata.h`.
- **Write chopping is preserved.** A write larger than the maximum documented
  for `CURLOPT_WRITEFUNCTION` is still split at that boundary, because the
  resulting sequence of callback invocations is observable.
- **The decoders change implementation, not behavior.** `gzip` and `deflate`
  map to the `flate2` `crate`, `br` to the `brotli` `crate` and `zstd` to the
  `zstd` `crate`, in place of the C libraries that `lib/content_encoding.c`
  calls. What stays fixed is the observable part: the coding names accepted,
  the `x-gzip` alias and the `identity` and `none` spellings among them; the
  order the decoders are applied in, which is the **reverse** of the order the
  header value lists them, because each writer is inserted first in its phase;
  the ceiling on how many of them may be stacked; and the errors
  produced on malformed input, `CURLE_BAD_CONTENT_ENCODING` among them. The
  matching `Cargo` features are `gzip`, `brotli` and `zstd`.
- **Progress accounting moves with the download writer.** The counters that
  the `"download"` writer updates are specified to live in
  `curl-rs-lib/src/transfer/progress.rs`, with the rate limiting that reads
  those same counters at `curl-rs-lib/src/transfer/ratelimit.rs`. See
  [Rate Limiting Transfers](RATELIMITS.md).

The safety invariant at the root of `curl-rs-lib` is `#![deny(unsafe_code)]`
plus exactly one `#[allow(unsafe_code)]`, on `mod ffi` -- the single narrowly
allowed island under `curl-rs-lib/src/ffi/` for the operating system calls that
have no safe expression, where every `unsafe` block carries a mandatory
`// SAFETY:` comment. It is `deny` and not `forbid` because `forbid` cannot be
locally overridden (`error[E0453]: allow(unsafe_code) incompatible with
previous forbid`) and Agent Action Plan goal G1 permits only three crates, so
the island cannot move into a fourth; `deny` is no weaker, since a stray
`unsafe` block outside the island is a hard error rather than a warning. In
`curl-rs` there is no island at all, so the delivered binary root
`curl-rs/src/bin/curlinfo.rs` does carry `#![forbid(unsafe_code)]` literally;
the crate root `curl-rs/src/main.rs` named in Agent Action Plan section 0.3.1
is not yet on disk. The writer chain has no business in that island: holding
bytes and handing them to a callback asks for nothing that the safe subset does
not already offer.

The application callbacks are reached across the public C ABI in
`curl-rs-ffi`, and that is where the pointer and length contract with the
caller is kept, exactly as `CURLOPT_WRITEFUNCTION` and
`CURLOPT_HEADERFUNCTION` document it. The value a callback returns is part of
that same contract, `CURL_WRITEFUNC_PAUSE` included, which is the reason
pausing is treated here as behavior visible across the ABI rather than as an
internal convenience.

One point in the retained text above deserves a note so that it is not
misread. The bits that refine `CLIENTWRITE_HEADER` are described there as
used by HTTP and related protocols, RTSP and WebSocket among them. WebSocket
is in scope, and its specified successor to `lib/ws.c` is
`curl-rs-lib/src/protocols/ws.rs`. RTSP is not in scope: it is one of the 24
schemes that route to `curl-rs-lib/src/protocols/stub.rs`, which returns
`CURLE_UNSUPPORTED_PROTOCOL`, and it is withheld from the protocol banner
that `curl --version` prints, so its fixtures skip rather than fail. The nine
schemes that carry transfers are FILE, FTP, FTPS, HTTP, HTTPS, SCP, SFTP, WS
and WSS.
