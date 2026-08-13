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
macro is selected by a `cargo` feature instead. One mechanical detail is worth
stating precisely, because the obvious reading of it is wrong: a virtual
`workspace` manifest has no `[features]` table, so the declarations cannot live
in the root `Cargo.toml` at all. They are defined once in
`curl-rs-lib/Cargo.toml`, which is where a feature name turns into an optional
dependency, and `curl-rs` and `curl-rs-ffi` each forward all fifteen to
`curl-rs-lib/<name>`. That pass-through, not a root declaration, is what keeps
the setting coherent: enabling a name on either leaf crate enables the same name
in the engine, so a capability cannot be enabled in one `crate` and disabled in
another. A plain `--features <list>` therefore reaches every member, and all
three manifests declare the same twelve features by default. The root manifest
does carry the same set once more, as `[workspace.metadata.curl-rs.features]`,
but that is an inventory for tooling to read rather than a `cargo` feature
table.

All fifteen names below are declared today. How much each one gates is bounded
by how much of the module behind it is on disk, and this page says which is
which rather than leaving the declaration to imply a capability.

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
twelve capabilities out of the box and a drop-in replacement is required to
provide them out of the box as well. The other three are off by default, each
for a reason worth stating:

- `negotiate` needs an operating system GSS-API library for Negotiate, SPNEGO
  and Kerberos authentication. Leaving the feature off keeps the default build
  free of any C security library.
- `hickory-dns` is a **reserved name with no dependency behind it**. It is
  declared, it is default-off, it **builds**, and it advertises nothing. It was
  intended to select an in-process resolver as an alternative to the system
  resolver, which is what resolves names by default. No version of
  `hickory-resolver` can currently back it: every release that satisfies the
  workspace minimum Rust version (0.24.0 through 0.25.2) requires a
  `hickory-proto` affected by RUSTSEC-2026-0119, and every release carrying that
  fix (0.26.0, 0.26.1) declares `rust-version 1.88` and breaks the minimum. The
  two sets are disjoint. Declaring the crate as an optional dependency would not
  have confined the advisory either, because `cargo deny` and `cargo audit` read
  `Cargo.lock` rather than the active feature set, so it would be reported for
  every build including default ones -- that was measured, not predicted. The
  name is kept because three self-description surfaces are written against the
  fifteen feature names -- the `Features:` line of `curl --version`, the
  capability table the FFI build script emits, and `curlinfo`'s table -- and the
  root `Cargo.toml` records the full measurement.

  What enabling it must not do is make `curl --version` name a resolver that is
  not in the build, since over-reporting a capability is the one failure mode
  the truthfulness rule forbids. Two ways of preventing that were rejected and
  one adopted. A bare `cfg` switch the banner still keys off would advertise
  `hickory-resolver` with nothing behind it, which is exactly the over-report.
  A `compile_error!` on the feature -- which this page previously described --
  turns a declared feature into an unbuildable one, makes `--all-features`
  impossible for a workspace whose own `deny.toml` sets `all-features = true`,
  and forces every feature-matrix job to enumerate fourteen names in lockstep.
  Neither is in force. The rule actually applied is the one every other
  capability already uses: advertise only when configured **and** the engine
  behind it is present. The resolver engine row is absent, so the token is
  withheld however the feature is set, the feature compiles to nothing
  observable, and continuous integration passes `--all-features` normally.
- `memdebug` selects allocation tracking, and it carries a cost that the
  section below states in full.

Which of the fifteen pull in a dependency is a separate question from which are
declared, and the answer divides them cleanly. Seven gate an optional
dependency today: `http2`, `http3`, `ssh`, `cookies`, `brotli`, `zstd` and
`gzip`. The other eight are declared with an empty definition -- `ftp`,
`websockets`, `hsts`, `altsvc`, `doh`, `negotiate`, `hickory-dns` and
`memdebug` -- and the reason is that none of them gates an external crate, not
that the code behind them is missing. `ftp` is the clearest case: the command
sequencing is this project's own and has to stay byte-exact, and FTPS reuses the
unconditional TLS stack, so there is no crate for the feature to switch on.

An empty definition is not an inert name, and reading it that way would be the
second obvious-but-wrong reading on this page: every one of the fifteen is
consulted by `cfg` in the sources today, several of them in dozens of places.
`negotiate` gates the build half of the `GSS-API`, `Kerberos` and `SPNEGO` rows
of the version banner, and `hickory-dns` gates the withheld resolver token
described above. What an empty definition does mean is that enabling one adds no
crate to the dependency graph.

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
constants remain in `include/curl/curl.h`, which is retained here at
8.19.0-DEV and is unmodified. Beyond the constants, the paragraph splits into a
part that is specified and a part that is delivered, and the two are worth
keeping apart.

Specified: a URL naming one of these schemes still parses, and a transfer
request for one fails with `CURLE_UNSUPPORTED_PROTOCOL` from the stub
registration. Delivered so far: `curl-rs-lib/src/protocols/mod.rs` is on disk
and carries the 33-row scheme registry, which is what records these 24 as
registered-but-unimplemented in the first place. What is not on disk is the stub
table that would return the error code, or any transfer engine for the other
nine, so neither half of the specified behavior is observable yet -- and the
executable honours no command-line option, so no URL of any scheme reaches the
registry.

The `Protocols:` line follows the same rule and currently withholds everything.
`curl-rs-lib/src/version.rs` conditions each of the nine transferable schemes on
the protocol engine being present, and that engine row is absent while
`protocols/` is incomplete, so the advertised list is empty rather than nine
names long. The 24 are withheld too, permanently and by a separate decision, and
tests assert that they never appear. Under-reporting is the safe direction: an
empty list makes fixtures skip, whereas naming a scheme this build cannot serve
would make them run and fail.

**Its subject is unconditional, so no switch exists.** `CURL_DISABLE_AWS`,
`CURL_DISABLE_BASIC_AUTH`, `CURL_DISABLE_BEARER_AUTH`,
`CURL_DISABLE_BINDLOCAL`, `CURL_DISABLE_DIGEST_AUTH`, `CURL_DISABLE_FILE`,
`CURL_DISABLE_FORM_API`, `CURL_DISABLE_GETOPTIONS`,
`CURL_DISABLE_HEADERS_API`, `CURL_DISABLE_HTTP_AUTH`, `CURL_DISABLE_IPFS`,
`CURL_DISABLE_LIBCURL_OPTION`, `CURL_DISABLE_MIME`, `CURL_DISABLE_NETRC`,
`CURL_DISABLE_NTLM`, `CURL_DISABLE_PARSEDATE`,
`CURL_DISABLE_PROGRESS_METER`, `CURL_DISABLE_PROXY`,
`CURL_DISABLE_SHA512_256`, `CURL_DISABLE_SHUFFLE_DNS`,
`CURL_DISABLE_SOCKETPAIR` and `CURL_DISABLE_VERBOSE_STRINGS` each name a
capability that no build configuration may switch off.
`CURL_DISABLE_PARSEDATE` is the clearest of them: `curl_getdate` is one of the
100 symbols `lib/libcurl.def` exports, so date parsing has to work in every
configuration, and a switch that removed it would break the exported surface.
No feature name covers any capability in this group, and inventing one would
advertise a choice that the build does not offer.

That is a statement about the feature vocabulary, and it must not be read as a
statement that the capabilities are present. "No switch removes it" and "the
build has it" are different claims, and for most of this group only the first
one holds today. Authentication (basic, bearer, digest, Negotiate, AWS SigV4 and
the HTTP-auth dispatch), the MIME and form APIs, the header API, `.netrc`,
proxying, cookies, DoH, `--libcurl` emission, TLS session import and export, the
certificate-status request and `bindlocal` are all still waiting on the engine
modules behind them, and each is withheld from the advertised feature set until
its module lands. Only a handful of the group is genuinely delivered: date
parsing, verbose diagnostic strings, extended attributes and the large-file and
large-time types.

Do not maintain that split by hand from this page. `curlinfo` prints one row per
capability with `ON` or `OFF` computed from the same engine table the banner
reads, so running it answers the question for the build in front of you:

    curlinfo

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

That trade is reversible, and the machinery for reversing it is implemented
rather than merely planned. Enabling `memdebug` installs a counting
`GlobalAlloc` as the crate `#[global_allocator]`, reproducing the log format of
`lib/memdebug.c`: records of the form
`MEM <source>:<line> malloc(<n>) = <pointer>`, with parallel forms for
`calloc`, `strdup`, `wcsdup`, `realloc` and `free`, written to the destination
named by the `CURL_MEMDEBUG` environment variable, which is what
`tests/memanalyzer.pm` parses. A `CURL_MEMLIMIT` value caps the number of
allocations, mirroring `curl_dbg_memlimit()` and its one-shot guard, and a
denied allocation writes the `LIMIT ... reached memlimit` record to both the
log and standard error before the allocation fails.

Two properties of that implementation are disclosed rather than smoothed over.
First, the cap arms on the first allocation rather than partway through
`main()` where the C arms it, so the allocations the `Rust` runtime performs
ahead of `main` are counted too. That offset measures as a constant two on this
platform, which makes `CURL_MEMLIMIT=1` and `CURL_MEMLIMIT=2` fail during
start-up, and a value of three or more behave as expected. Second, enabling
`memdebug` does not make the binary advertise `Debug`, and that is deliberate:
the feature supplies the allocation log alone, while the `Debug` token also
promises internal behavior changes this build does not make. The harness checks
described above therefore stay skipped even with `memdebug` on, because only
the `Debug` token governs them.

## The `CURL_DISABLE_*` defines

Each define below is described exactly as it behaves in the retained C
reference tree, where it remains in force. The `Rust` `workspace` is specified
to reach the equivalent decisions through the feature map above instead, to the
extent recorded there.

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
lines, across which `curlcheck_` is referenced 260 times on 258 distinct
lines. The two counts differ because two lines carry the token twice, and both
of those are comments rather than macro definitions, so neither count is the
number of macros. It ships verbatim beside the generated `include/curl/curl.h`.

The two header checks under `.github/scripts` treat the define differently on
purpose, and their scopes are easy to confuse.
`verify-synopsis.pl docs/libcurl/curl*.md` compiles the synopses in those
pages with `-DCURL_DISABLE_TYPECHECK`, so the type checking is off there.
`verify-examples.pl docs/libcurl/curl*.md docs/libcurl/opts/*.md` compiles
the examples embedded in those Markdown pages and does not pass the define,
so those embedded examples are compiled with the type checking active and
hold the declarations to it.

Neither script reads the 129 standalone programs under `docs/examples`. Both
take Markdown pages as their arguments. The standalone programs are compiled
separately by the build system and remain untouched, and in the target design
that separate compilation is the additional ABI gate recorded in
`docs/tests/TEST-SUITE.md`, which states the same distinction.

## `CURL_DISABLE_VERBOSE_STRINGS`

Disable verbose strings and error messages.

## `CURL_DISABLE_WEBSOCKETS`

Disable the WebSocket protocols.
