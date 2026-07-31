<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Code defines to disable features and protocols

Capability selection happens in two separate places in this repository, and
the two work differently.

The C tree remains in the repository as the reference oracle for the
migration, and it still configures itself through the preprocessor. Every
`CURL_DISABLE_*` define named below is live. `lib/curl_setup.h` reads them and
derives the internal `USE_*` switches from them, and both C build systems
still expose the matching command line switches: `configure.ac` carries 101
configuration knobs, and `CMakeLists.txt` mirrors them.

The `Rust` `workspace` moves that configuration out of the preprocessor and
into the build graph. A capability that the C build selects by defining a
macro is selected by a `cargo` feature instead. The features are declared once
for the whole `workspace`, in the root `Cargo.toml`, so a capability cannot be
enabled in one `crate` and disabled in another.

## `Cargo` features

| Feature | Default | Replaces |
|---|---|---|
| `http2` | on | `CURL_DISABLE_HTTP` in part, and `USE_NGHTTP2` |
| `http3` | on | `QUIC` backend selection |
| `ftp` | on | `CURL_DISABLE_FTP` |
| `ssh` | on | `libssh2` and `libssh` selection |
| `websockets` | on | `CURL_DISABLE_WEBSOCKETS` |
| `cookies` | on | `CURL_DISABLE_COOKIES` |
| `hsts` | on | `CURL_DISABLE_HSTS` |
| `altsvc` | on | `CURL_DISABLE_ALTSVC` |
| `doh` | on | `CURL_DISABLE_DOH` |
| `brotli` | on | `brotli` library selection |
| `zstd` | on | `zstd` library selection |
| `gzip` | on | `zlib` selection |
| `negotiate` | off | `CURL_DISABLE_NEGOTIATE_AUTH`, `CURL_DISABLE_KERBEROS_AUTH`, GSS-API |
| `hickory-dns` | off | `c-ares` resolver selection |
| `memdebug` | off | `MEMDEBUG` and `DEBUGBUILD` allocation tracking |

Twelve of the fifteen are on by default, because curl 8.x provides those
twelve capabilities out of the box and a drop-in replacement provides them out
of the box as well. The other three are off by default, each for a reason
worth stating:

- `negotiate` needs an operating system GSS-API library for Negotiate, SPNEGO
  and Kerberos authentication. Leaving the feature off keeps the default build
  free of any C security library.
- `hickory-dns` selects an in-process resolver as an alternative to the system
  resolver, which is what resolves names by default.
- `memdebug` selects allocation tracking, and it carries a cost that the
  section below states in full.

## The mapping is not one to one

The 46 defines named on this page do not become the 15 features above, and
reading the change as a rename gets it wrong. The counts diverge for two
independent reasons. Some features replace a `--with-<library>` choice that no
`CURL_DISABLE_*` define ever expressed, so they enter the map from outside
this page. In the other direction, a define stops having anything to switch
whenever its subject is unconditional, unimplemented, or absent. Each of the
46 therefore has one of four outcomes.

**It becomes a feature.** `CURL_DISABLE_ALTSVC`, `CURL_DISABLE_COOKIES`,
`CURL_DISABLE_DOH`, `CURL_DISABLE_FTP`, `CURL_DISABLE_HSTS` and
`CURL_DISABLE_WEBSOCKETS` map onto the feature that carries the same name.
`CURL_DISABLE_HTTP` maps across only in part, because HTTP itself is
unconditional and the `http2` and `http3` features select protocol versions
rather than the scheme. `CURL_DISABLE_NEGOTIATE_AUTH` and
`CURL_DISABLE_KERBEROS_AUTH` both map onto the single `negotiate` feature,
which follows the C tree: `lib/curl_setup.h` gates `USE_SPNEGO` and
`USE_KERBEROS5` on the same requirement for a GSS-API or SSPI implementation.

**Its subject is not implemented, so nothing is left to disable.**
`CURL_DISABLE_DICT`, `CURL_DISABLE_GOPHER`, `CURL_DISABLE_IMAP`,
`CURL_DISABLE_LDAP`, `CURL_DISABLE_LDAPS`, `CURL_DISABLE_MQTT`,
`CURL_DISABLE_POP3`, `CURL_DISABLE_RTSP`, `CURL_DISABLE_SMB`,
`CURL_DISABLE_SMTP`, `CURL_DISABLE_TELNET` and `CURL_DISABLE_TFTP` all name
schemes drawn from the 24 registered schemes for which no transfer is
implemented. Those schemes stay part of the public ABI. Their `CURLPROTO_*`
constants remain in `include/curl/curl.h`, a URL naming one of them still
parses, and a transfer request for one of them fails with
`CURLE_UNSUPPORTED_PROTOCOL`. The `Protocols:` line of the version output
names only the nine schemes that do perform transfers, which is what lets the
test suite skip the cases needing the others rather than fail them.

**Its subject is unconditional, so no switch exists.** `CURL_DISABLE_AWS`,
`CURL_DISABLE_BASIC_AUTH`, `CURL_DISABLE_BEARER_AUTH`,
`CURL_DISABLE_BINDLOCAL`, `CURL_DISABLE_DIGEST_AUTH`, `CURL_DISABLE_FILE`,
`CURL_DISABLE_FORM_API`, `CURL_DISABLE_GETOPTIONS`,
`CURL_DISABLE_HEADERS_API`, `CURL_DISABLE_HTTP_AUTH`, `CURL_DISABLE_IPFS`,
`CURL_DISABLE_LIBCURL_OPTION`, `CURL_DISABLE_MIME`, `CURL_DISABLE_NETRC`,
`CURL_DISABLE_NTLM`, `CURL_DISABLE_PARSEDATE`,
`CURL_DISABLE_PROGRESS_METER`, `CURL_DISABLE_PROXY`,
`CURL_DISABLE_SHA512_256`, `CURL_DISABLE_SHUFFLE_DNS`,
`CURL_DISABLE_SOCKETPAIR` and `CURL_DISABLE_VERBOSE_STRINGS` each describe a
capability that the default build provides at all times.
`CURL_DISABLE_PARSEDATE` is the clearest of them: `curl_getdate` is one of the
100 symbols `lib/libcurl.def` exports, so date parsing has to work in every
configuration, and a switch that removed it would break the exported surface.
No feature name covers any capability in this group, and inventing one would
advertise a choice that the build does not offer.

**It has no counterpart at all.** `CURL_DISABLE_CA_SEARCH` turns off an unsafe
CA bundle search along `PATH` on Windows, and Windows sits outside the four
supported targets, which are Linux and macOS on `x86_64` and `aarch64`.
`CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG` names behavior of the OpenSSL backend,
and no OpenSSL backend is left, because `rustls` is the only TLS
implementation. `CURL_DISABLE_TYPECHECK` is the one define in this group that
keeps its meaning, for the reason its own section gives below.

## The `memdebug` feature and the test suite

The `memdebug` feature is off by default, so a default build performs no
allocation tracking. That choice has a consequence for the test suite, and it
is recorded here rather than left for someone to rediscover.

`tests/runtests.pl` wraps its whole memory check in
`if($feature{"TrackMemory"})` at line 1759, and it sets that feature from one
place only: line 660 reads a `Debug` token out of the version banner. A binary
that does not advertise `Debug` therefore has every leak check and every
allocation cap check skipped, which leaves the 28 cases carrying a `<limits>`
block inert. Those caps are upper bounds rather than exact counts, so a
different allocation pattern would not fail them in any case.

The cost of that trade is stated here rather than left implicit. Of the 1,914
cases under `tests/data`, 98 name `Debug` among their required features and
skip while it is absent, and `make torture-test` requires the feature
outright, so it does not apply.

Should that trade prove unacceptable, the remedy is the reason the feature
name exists: a counting `GlobalAlloc` behind `memdebug`, reproducing the log
format of `lib/memdebug.c`. That format is fully specified by the C
implementation, which writes records of the form
`MEM <source>:<line> malloc(<n>) = <pointer>`, with parallel forms for
`calloc`, `strdup`, `wcsdup`, `realloc` and `free`, to the destination named
by the `CURL_MEMDEBUG` environment variable.

## The `CURL_DISABLE_*` defines

Each define below is described exactly as it behaves in the retained C
reference tree, where it remains in force. The `Rust` `workspace` reaches the
equivalent decisions through the feature map above instead.

## `CURL_DISABLE_ALTSVC`

Disable support for Alt-Svc: HTTP headers.

## `CURL_DISABLE_BINDLOCAL`

Disable support for binding the local end of connections.

## `CURL_DISABLE_COOKIES`

Disable support for HTTP cookies.

## `CURL_DISABLE_BASIC_AUTH`

Disable support for the Basic authentication methods.

## `CURL_DISABLE_BEARER_AUTH`

Disable support for the Bearer authentication methods.

## `CURL_DISABLE_DIGEST_AUTH`

Disable support for the Digest authentication methods.

## `CURL_DISABLE_KERBEROS_AUTH`

Disable support for the Kerberos authentication methods.

## `CURL_DISABLE_NEGOTIATE_AUTH`

Disable support for the negotiate authentication methods.

## `CURL_DISABLE_AWS`

Disable **aws-sigv4** support.

## `CURL_DISABLE_CA_SEARCH`

Disable unsafe CA bundle search in PATH on Windows.

## `CURL_DISABLE_DICT`

Disable the DICT protocol

## `CURL_DISABLE_DOH`

Disable DNS-over-HTTPS

## `CURL_DISABLE_FILE`

Disable the FILE protocol

## `CURL_DISABLE_FORM_API`

Disable the form API

## `CURL_DISABLE_FTP`

Disable the FTP (and FTPS) protocol

## `CURL_DISABLE_GETOPTIONS`

Disable the `curl_easy_options()` API calls that lets users get information
about existing options to `curl_easy_setopt()`.

## `CURL_DISABLE_GOPHER`

Disable the GOPHER protocol.

## `CURL_DISABLE_HEADERS_API`

Disable the HTTP header API.

## `CURL_DISABLE_HSTS`

Disable the HTTP Strict Transport Security support.

## `CURL_DISABLE_HTTP`

Disable the HTTP(S) protocols. Note that this then also disable HTTP proxy
support.

## `CURL_DISABLE_HTTP_AUTH`

Disable support for all HTTP authentication methods.

## `CURL_DISABLE_IMAP`

Disable the IMAP(S) protocols.

## `CURL_DISABLE_LDAP`

Disable the LDAP(S) protocols.

## `CURL_DISABLE_LDAPS`

Disable the LDAPS protocol.

## `CURL_DISABLE_LIBCURL_OPTION`

Disable the --libcurl option from the curl tool.

## `CURL_DISABLE_MIME`

Disable MIME support.

## `CURL_DISABLE_MQTT`

Disable MQTT support.

## `CURL_DISABLE_NETRC`

Disable the netrc parser.

## `CURL_DISABLE_NTLM`

Disable support for NTLM.

## `CURL_DISABLE_OPENSSL_AUTO_LOAD_CONFIG`

Disable the auto load config support in the OpenSSL backend.

## `CURL_DISABLE_PARSEDATE`

Disable date parsing

## `CURL_DISABLE_POP3`

Disable the POP3 protocol

## `CURL_DISABLE_PROGRESS_METER`

Disable the built-in progress meter

## `CURL_DISABLE_PROXY`

Disable support for proxies

## `CURL_DISABLE_IPFS`

Disable the IPFS/IPNS protocols. This affects the curl tool only, where
IPFS/IPNS protocol support is implemented.

## `CURL_DISABLE_RTSP`

Disable the RTSP protocol.

## `CURL_DISABLE_SHA512_256`

Disable the SHA-512/256 hash algorithm.

## `CURL_DISABLE_SHUFFLE_DNS`

Disable the shuffle DNS feature

## `CURL_DISABLE_SMB`

Disable the SMB(S) protocols

## `CURL_DISABLE_SMTP`

Disable the SMTP(S) protocols

## `CURL_DISABLE_SOCKETPAIR`

Disable the use of `socketpair()` internally to allow waking up and canceling
`curl_multi_poll()`.

## `CURL_DISABLE_TELNET`

Disable the TELNET protocol

## `CURL_DISABLE_TFTP`

Disable the TFTP protocol

## `CURL_DISABLE_TYPECHECK`

Disable `curl_easy_setopt()`/`curl_easy_getinfo()` type checking.

Useful to improve build performance for the `tests/libtest` test tool.

This define keeps its meaning after the migration. The type checking it turns
off lives in `include/curl/typecheck-gcc.h`, and that header is maintained by
hand rather than generated, because `cbindgen` has no way to express its 958
lines and 258 `curlcheck_` references. It ships verbatim beside the generated
`include/curl/curl.h`. The two header checks under `.github/scripts` treat the
define differently on purpose: `verify-synopsis.pl` compiles with
`-DCURL_DISABLE_TYPECHECK`, while `verify-examples.pl` does not, so the 129
example programs under `docs/examples` are compiled with the type checking
active and hold the declarations to it.

## `CURL_DISABLE_VERBOSE_STRINGS`

Disable verbose strings and error messages.

## `CURL_DISABLE_WEBSOCKETS`

Disable the WebSocket protocols.
