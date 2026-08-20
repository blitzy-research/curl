<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# [![curl logo](https://curl.se/logo/curl-logo.svg)](https://curl.se/)

curl is a command-line tool for transferring data from or to a server using
URLs.

**This tree is a partial milestone of the C-to-Rust rewrite and transfers
nothing yet.** It builds, it parses a full curl command line, and it then
returns `CURLE_NOT_BUILT_IN` for every operation, because no protocol executor
can be reached. Read the rest of this file as a description of where the work
stands, not of a working replacement -- every claim below is measured against
this checkout, and [Current state](#current-state) collects the measurements in
one place.

The nine URL schemes in scope are FILE, FTP, FTPS, HTTP, HTTPS, SCP, SFTP, WS
and WSS, with HTTP transfers to use HTTP/1.1, HTTP/2 or HTTP/3. Those nine are
the target and none of them is served today -- SFTP has an executor but no way
to receive its options -- so `curl --version` prints an empty `Protocols:` line
and `curl-config --protocols` prints nothing. That line
is generated from the same capability table the engine answers from, so it will
name each scheme as its executor lands, without an edit here.

Another 24 URL schemes stay registered so that the C ABI stays complete, and
they are out of scope for implementation permanently: DICT, GOPHER, GOPHERS,
IMAP, IMAPS, LDAP, LDAPS, MQTT, MQTTS, POP3, POP3S, RTMP and its variants,
RTSP, SMB, SMBS, SMTP, SMTPS, TELNET and TFTP. Their `CURLPROTO_*` constants
remain in the public header, and a request for one of them returns
`CURLE_UNSUPPORTED_PROTOCOL`. A scheme being absent from `Protocols:` is what
makes a test fixture that needs it skip rather than fail, which is why nothing
is named there before it works.

Learn how to use curl by reading [the
man page](https://curl.se/docs/manpage.html) or [everything
curl](https://everything.curl.dev/).

Find out how to build curl from source under [Build](#build), and how to place
the result under [Installing](#installing). [The INSTALL
document](docs/INSTALL.md) covers the **retained C build** -- `./configure`,
CMake, the TLS-backend choices and the platform notes that go with them. That
build is kept as the reference oracle this rewrite is measured against, so
read it as C-build reference documentation rather than as instructions for
building the Rust product; it does not describe Cargo, and by its own first
section it does not cover binary packages either.

libcurl is the library curl is using to do its job. It is readily available to
be used by your software. Read [the libcurl
man page](https://curl.se/libcurl/c/libcurl.html) to learn how.

## Current state

Every row below was measured against this checkout rather than estimated, and
each one names where the same fact is recorded in the tree so that this table
can be re-derived rather than trusted.

| what | state |
| ---- | ----- |
| Command line | Parses the full curl surface -- flags, arguments, `--next` chains -- and reproduces C's diagnostics and exit codes byte for byte. Verified against a stock curl 8.14.1 across nine invocations. The `.curlrc` and `-K` reader is written and tested (`curl-rs/src/config/parseconfig.rs`), but is not reached yet: `ParseHost::parse_config` does not take the configuration handle the re-entry needs, so no configuration file is loaded at run time. |
| Transfers | None. Every operation returns `CURLE_NOT_BUILT_IN`, and no transfer can be driven. Two schemes -- SFTP and SCP -- now carry *wired* protocol executors (`curl-rs-lib/src/protocols/sftp.rs`, which also hosts the shared SSH session core, and `curl-rs-lib/src/protocols/scp.rs`, the thin SCP-specific layer over it that differs in three vtable slots), and neither can yet be reached: nine of the eleven vtable slots need the transfer's options and `curl-rs-lib/src/easy/setopt.rs` is not on disk to supply them. `curl-rs-lib/src/protocols/file.rs` is written and tested -- the whole of `lib/file.c`, and the only scheme that needs no connection -- but no registry row can reach it, so nothing is served. `curl-rs-lib/src/protocols/http1.rs` carries the HTTP/1.x request writer and vtable of `lib/http.c` in full, and nothing constructs a request for it either: `easy/handle.rs` has landed, so a handle can be built and carries curl's frozen defaults, but `easy/setopt.rs` -- which is what would put a URL on it -- is still unwritten, so both HTTP registry rows keep `run: None`. `curl-rs-lib/src/protocols/ftp/mod.rs` carries the command sequencing of `lib/ftp.c` -- the 37-state machine, the wildcard driver and both data-channel modes -- over the request/response cadence of `lib/pingpong.c` in `curl-rs-lib/src/protocols/ftp/pingpong.rs`, and both FTP registry rows keep `run: None` for want of those same `easy/` modules. `curl-rs-lib/src/protocols/http2.rs` carries the HTTP/2 connection filter -- curl's SETTINGS and h2c upgrade bytes, HPACK-backed streams, flow control, trailers and push headers -- and it installs beneath the shared HTTP handler rather than owning a scheme row, so it is held by that same unwritten option setter. `curl-rs-lib/src/protocols/ws.rs` carries the whole of `lib/ws.c` -- handshake, frame encoder and decoder, masking, automatic PONG and the engine behind the four `curl_ws_*` exports -- and its handler delegates to `protocols/http1.rs`'s, so it is held by the same unwritten `easy/` module. `curl-rs-ffi/src/ffi/ws.rs` now defines all four exports, and answers `CURLE_NOT_BUILT_IN` from three of them and NULL from `curl_ws_meta` -- `lib/ws.c:1938-1980`, the branch a build without WebSocket support carries -- because `curl-rs-lib`'s WebSocket engine is not reachable from the ABI shim: `protocols` is `pub(crate)` and, although `easy/handle.rs` now provides the handle, no `easy/setopt.rs` exists to configure one. `curl-rs-lib/src/protocols/http3.rs` carries the HTTP/3 connection filter of `lib/vquic/curl_ngtcp2.c` over `quinn`, `h3` and `h3-quinn` -- `Curl_cft_http3`'s four type flags, all fifteen typed queries, the eight control events, the transport parameters `quic_settings` sets, the handshake deadline, `QLOGDIR` and the QUIC row of the transport registry -- and like HTTP/2 it installs beneath the shared HTTP handler, so it is held by that same unwritten option setter. Nothing opens a connection. |
| `Protocols:` in `curl --version` | Empty, and correctly so. |
| `Features:` in `curl --version` | The truthful subset. A capability is advertised only when the module that implements it exists *and* can be executed, which is why names like `SSL`, `HTTP2` and `NTLM` are withheld even though rustls, `h2` and the NTLM primitives are all linked and tested. Under-reporting makes a fixture skip; over-reporting makes it run and fail. |
| C ABI | 66 of the 100 symbols in `lib/libcurl.def` are exported, and nothing beyond them. |
| Public headers | Not regenerated. Generation is withheld until the export surface is complete; the headers in the tree remain the ABI contract. |
| Targets | Two of four build. See [Supported targets](#supported-targets). |
| Engine modules | 2 of the modules the target design assigns to `curl-rs-lib` are not written -- both are `easy/` modules, `setopt.rs` and `getinfo.rs`. `easy/handle.rs` was the third and has landed: the decomposed easy handle, carrying `struct Curl_easy`'s 24 members apportioned by ownership, `Curl_init_userdefined`'s frozen defaults with certificate verification on, the generational identity token and the four injected seams. **Neither a per-scheme executor nor a proxy mechanism is missing any more:** `curl-rs-lib/src/protocols/` and `curl-rs-lib/src/proxy/` both hold every file the design assigns, `protocols/file.rs` -- the first per-scheme executor -- `protocols/http1.rs`, `protocols/http2.rs`, `protocols/http3.rs`, `protocols/sftp.rs`, `protocols/scp.rs`, `protocols/ftp/pingpong.rs`, `protocols/ws.rs` and `proxy/http_connect.rs` -- the three HTTP `CONNECT` tunnel filters, which complete the `proxy/` directory -- included. One further module, `curl-rs-lib/src/proxy/socks_gss.rs`, is written but exists only when the non-default `negotiate` feature is on, which is the C's `#if defined(HAVE_GSSAPI)` rather than a gap. `curl-rs-lib/src/version.rs` records, per capability, whether its module is missing or merely uncalled, and a test in `curl-rs/src/bin/curlinfo.rs` checks every one of those claims against the filesystem. |
| Unwritten modules, all three crates | 16: the 2 above, 13 in `curl-rs` (the operation driver, the option-to-`setopt` mapping, one configuration stage, all seven transfer callbacks and the `--libcurl` emitter) and 1 in `curl-rs-ffi` (`ffi/multi.rs`, which carries 21 of the 34 undefined exports; the other 13 are the `curl_easy_*` core). Each crate root enumerates its own; `absent_target_gate` in `curl-rs/src/bin/curlinfo.rs` holds all 16 as data and fails, naming the file, when one lands. |
| IPFS and IPNS | `curl-rs/src/cli/ipfs.rs` implements the gateway discovery chain and the URL rewriting of `src/tool_ipfs.c`, including `--ipfs-gateway`, `IPFS_GATEWAY`, `IPFS_PATH` and the `~/.ipfs/gateway` file. The rewrite produces an ordinary `http` or `https` URL, so the eighteen fixtures that cover it need an HTTP executor in the engine before they can run. |
| Cargo features | Fifteen, twelve on by default because curl 8.x offers them out of the box. Exactly one -- `memdebug` -- is closed end to end. `curl-rs-lib/Cargo.toml` carries the per-feature state above its `[features]` table. |
| Publishing | Refused. `publish = false` on the workspace, and the artifacts are not substitutes for curl or libcurl yet. |

Three labels are used throughout this repository and in every option and
protocol page under `docs/`, because keeping them apart is the difference
between a plan and a claim:

- an **implemented primitive** is a module that exists and whose own tests
  pass;
- **wired product behaviour** is a primitive the shipped `curl` executable or
  `libcurl` actually reaches;
- the **target contract** is what the finished implementation owes its
  consumers, frozen from curl 8.19.0-DEV and not open to revision.

## Build

curl and libcurl are written in Rust, as a Cargo workspace of three crates.
Building them needs a Rust toolchain and a C compiler, the latter because a
few dependencies build C and assembly of their own. Cargo is the whole of the
product build: it runs neither Autotools nor CMake, and nothing under `m4/`,
`CMake/` or any `Makefile.am` participates. Those files are still in the tree
and still exercised, because the C implementation is retained as the reference
oracle this rewrite is measured against -- see [the INSTALL
document](docs/INSTALL.md) for how to build *that*. The edition is 2021 and the
minimum supported Rust version is 1.75.

`rust-toolchain.toml` pins the development channel to 1.97.1, so a contributor
who types `cargo build` gets that compiler and no other. Continuous integration
uses **three** toolchains rather than one, and the difference is the point of
two of them:

- **1.97.1**, the pinned channel, for every ordinary leg -- build, clippy, test,
  ABI, coverage, audit.
- **1.75.0**, in `rust-build.yml`, which exists solely to prove the declared
  minimum still compiles. A leg on the pinned channel cannot establish that.
- **nightly-2026-07-31**, in `rust-miri.yml` and `rust-asan.yml`, because Miri
  and `-Zsanitizer=address` with `-Zbuild-std` are nightly-only.

    cargo build --locked --release --workspace
    cargo test --locked --workspace

Pass `--locked` every time. `Cargo.lock` is committed, and the resolution it
records is what keeps Rust 1.75 reachable, so refreshing it is not a
maintenance step. The release build has to compile with no warnings, which is
how continuous integration runs it, under `RUSTFLAGS=-D warnings`, so any
diagnostic the compiler raises stops the build. That requirement is met on both
Linux targets today; the two Apple targets are covered under [Supported
targets](#supported-targets), and only one of the four is met in full. A
message the build script prints is a separate thing and reports state rather
than a defect -- two of them are printed on every build, and both are the
withheld-header notice described below.

### Artifacts

A native `cargo build --release` leaves these four artifacts in
`target/release`:

- `curl` and `curlinfo`, the two executables, from the `curl-rs` package
- `libcurl.so`, a `cdylib`, and `libcurl.a`, a `staticlib`, from the
  `curl-rs-ffi` package

Two details of that path are easy to get wrong. A build for an explicit target
puts them in `target/<triple>/release` instead, so a cross build has no
`target/release` at all; the shared library is also named by the platform
rather than by this project, `libcurl.so` on Linux and `libcurl.dylib` on Apple
targets. Write neither path as a constant in a packaging script.

`curl-config` and `libcurl.pc` are rendered by `curl-rs-ffi/build.rs` from the
`curl-config.in` and `libcurl.pc.in` templates in this tree. They land in the
build script output directory, both under their own names and again under
`staging/bin` and `staging/lib/pkgconfig`, laid out the way an install would
place them, so packaging copies one directory. Both answer the same queries as
before, so a build system that already asks them for a version, a link line or
a feature list needs no change. **Consumer metadata** is written outside that
output directory only when `CURL_RS_STAGING_DIR` names where, so no default
build stages metadata into the checkout. That scope is the metadata and nothing
else: the public headers are a second generated output, with a different
destination.

Eight of the public headers under `include/curl/` are generated rather than
written: `curl-rs-ffi/build.rs` drives `cbindgen` over the Rust source to
produce `curl.h`, `easy.h`, `multi.h`, `urlapi.h`, `options.h`, `header.h`,
`websockets.h` and `mprintf.h`. The direction of generation is the reverse of
the C build, where the header was the source of truth and the option table was
derived from it. Four headers are beyond a generator and are maintained by
hand beside them: `curlver.h`, `stdcheaders.h`, `system.h`, and
`typecheck-gcc.h`, which holds the `curlcheck_` macros that give the arguments
of `curl_easy_setopt` compile-time type checking.

Those eight are written **into the checkout**, at `include/curl/`, with no
environment variable involved -- they are tracked source, and they are the one
deliberate exception to a build leaving the tree alone. That is by design
rather than by oversight: a header that lived only under `target/` could not be
the ABI contract that the 129 programs under `docs/examples/` and every
external consumer compile against. Treat a build that rewrites them as a source
change and review the diff.

Generation is withheld while any symbol in `lib/libcurl.def` is still
undefined, and the build script says so on every build, which is why nothing is
written there at present. `cbindgen` renders only what exists, so a header
regenerated early would be short by exactly what is missing, and a header that
declares a symbol nothing exports is an undefined reference in every program
that calls it. The headers already in the tree are left alone and remain the
ABI contract until the export surface is complete, at which point generation
resumes on its own.

The shared library carries the SONAME `libcurl.so.4`, and on Apple targets the
install name `@rpath/libcurl.4.dylib`. That 4 is derived rather than chosen:
`lib/Makefile.soname` sets `VERSIONCHANGE=12`, `VERSIONADD=0` and
`VERSIONDEL=8`, which is libtool `-version-info 12:0:8`, and a libtool SONAME
major is current minus age. `curl-rs-ffi/build.rs` emits it as a link argument
scoped to the `cdylib`, so the executables do not carry it.

### Installing

There is no `cargo install` step and no `make install` equivalent that places
a complete package: Cargo builds the artifacts and renders the metadata, and
placing them is currently manual. Doing it by hand is four steps, and skipping
any of them leaves a consumer that either fails to link or silently resolves
the system libcurl instead.

1. **Choose the prefix before building.** The metadata is rendered at build
   time with the prefix baked in, defaulting to `/usr/local`. Set
   `CURL_RS_PREFIX` to the installation root when it is anywhere else;
   otherwise `curl-config --prefix`, `--libs` and `--cflags` and pkg-config's
   `libdir` and `includedir` all describe a location nothing was installed to:

       CURL_RS_PREFIX=/opt/curl-rs cargo build --locked --release --workspace

2. **Install the libraries under a versioned name, with the usual symlinks.**
   Cargo emits a single unversioned file whose SONAME is nonetheless
   `libcurl.so.4`, and a dynamic linker resolves the SONAME, not the file it
   was copied from. Install it as `libcurl.so.4.8.0` and add both links, the
   same three names an Autotools install leaves behind:

       install -Dm755 target/release/libcurl.so "$PREFIX/lib/libcurl.so.4.8.0"
       ln -sf libcurl.so.4.8.0 "$PREFIX/lib/libcurl.so.4"
       ln -sf libcurl.so.4     "$PREFIX/lib/libcurl.so"
       install -Dm644 target/release/libcurl.a "$PREFIX/lib/libcurl.a"

   On Apple targets the file is `libcurl.dylib` and the names are
   `libcurl.4.dylib` and `libcurl.dylib`.

3. **Install the executables and every public header.** The headers are not
   staged anywhere by the build; they are read from the checkout:

       install -Dm755 target/release/curl target/release/curlinfo "$PREFIX/bin/"
       install -Dm644 include/curl/*.h "$PREFIX/include/curl/"

4. **Install the rendered metadata from the staging directory**, which is the
   one part the build does lay out for you. Point `CURL_RS_STAGING_DIR` at a
   directory of your own and copy it in one move:

       cp -a "$STAGING/bin/curl-config" "$PREFIX/bin/"
       cp -a "$STAGING/lib/pkgconfig/libcurl.pc" "$PREFIX/lib/pkgconfig/"

Then check the result rather than assuming it: `curl-config --prefix` must
print the prefix you built with, `pkg-config --libs libcurl` must name that
prefix's `lib`, and `ldd` on a program you link must resolve `libcurl.so.4` to
your copy and not to the system one.

### Supported targets

Four targets are in scope, all 64-bit. Two of them build today. The state of
each was measured on a Linux host, and what a macOS host would report for the
Apple pair is a different question this tree cannot answer for itself.

| target | state |
| ------ | ----- |
| `x86_64-unknown-linux-gnu` | Builds and links under `RUSTFLAGS=-D warnings`. |
| `aarch64-unknown-linux-gnu` | Builds and links under `RUSTFLAGS=-D warnings`, cross-compiled with the GNU aarch64 toolchain `.cargo/config.toml` names. |
| `x86_64-apple-darwin` | Compiles warning-free; linking needs a macOS SDK, so it cannot be completed on a Linux host. |
| `aarch64-apple-darwin` | **Refused by the build script.** Not a defect to fix in passing: the C ABI shim reaches curl's four variadic entry points with a non-variadic `extern "C"` function taking one trailing pointer, which is ABI-valid where variadic arguments arrive in registers and wrong on Apple arm64, where they arrive on the stack. The remedy needs `c_variadic`, which is not stable at the 1.75 floor, so the minimum-version requirement and the four-target requirement cannot both be met. The refusal has no opt-in, because a build-time switch cannot make a memory-safety fault safe -- it can only produce the artifact that carries it. |

## Workspace layout

- `curl-rs-lib` is the protocol engine, and the only crate with protocol
  knowledge.
- `curl-rs` is a thin command-line interface over the engine, and builds the
  `curl` and `curlinfo` executables. Thin describes the design and holds today:
  it parses, validates and reports, and the engine call it would then make does
  not exist yet.
- `curl-rs-ffi` is a thin C ABI over the engine. The export set it has to
  match is the 100 symbols that `lib/libcurl.def` lists for curl 8.19.0-DEV,
  and a parity check against that file is one of the validation gates. It
  fails on a difference in either direction: a symbol that is missing breaks
  an existing consumer at link time, and one that is extra is a surface
  nobody agreed to keep. **66 of the 100 are defined today**, so that gate does
  not pass yet, and `libcurl.so.4` is not a drop-in substitute for anything.
  Nothing extra is exported: the leaked-symbol half of the check is clean.

Both `curl-rs-ffi` and `curl-rs` depend on `curl-rs-lib`, and on nothing else
in the workspace. The graph has no cycles, and neither leaf crate holds
protocol logic.

The absence of `unsafe` outside the C ABI is compiler-enforced rather than
promised. `curl-rs` carries `#![forbid(unsafe_code)]` on both of its roots,
with no exemption at all. `curl-rs-lib` and `curl-rs-ffi` carry
`#![deny(unsafe_code)]`, the strongest level that still admits the one
exemption each of them needs: a single `#[allow(unsafe_code)]` on its own
`mod ffi`. That directory holds the operating system calls in the engine and
the exported entry points in the C ABI crate, and it is the only place in
either crate where an `unsafe` block may appear. `forbid` cannot host that
exemption, because the compiler rejects an inner `allow` beneath an outer
`forbid`. Every `unsafe` block carries a `// SAFETY:` comment naming the
precondition it rests on, and a test walks all three crates and asserts both
the count of exemptions and the declaration each one sits on, so the number
cannot drift unnoticed.

rustls is the only TLS implementation, on every target and in every
configuration: no C TLS library is linked, and the protocol, the record layer
and certificate verification are all Rust. Its cryptographic provider is
`ring`, which carries some C and assembly of its own. That much is structural
and true of the build today -- no manifest in the workspace admits another TLS
library at any feature setting.

Certificate validation is on unless `--insecure` is given, and `--insecure`
emits a warning on stderr before proceeding. Both halves of that sentence are
**target contract**, and one of them cannot be exercised yet. The verifier
defaults to validating and the warning emitter is delivered -- it sits on the
pre-transfer path in the tool, and no verbosity option suppresses it, `--silent`
included -- but the executable cannot accept `--insecure` to reach it, and no
TLS session runs behind it. Do not read the guarantee as observable behaviour
until a command line can carry the flag.

## Known deviations

Places where this implementation cannot match the C tree, recorded here rather
than left to be discovered. The `aarch64-apple-darwin` refusal above is a fourth
and is described there.

The C programs under `tests/libtest` and `tests/unit` cannot be built against
this tree, and the reason is structural rather than a matter of effort. Both
sets compile against the C tree's internal headers -- 247 of the 249 `.c` files
under `tests/libtest`, and all 59 under `tests/unit`, include `first.h`, which
pulls in `curl_setup.h` and `curlx/curlx.h` -- and they link internal `Curl_*`
symbols. A Rust static library does not export `pub(crate)` items at all, so
those programs cannot link however the engine is written, and re-exporting
internals to make them link would dismantle the encapsulation the safety
guarantee rests on. Their coverage moves into the Rust crates as
`#[cfg(test)]` modules or behind a `testing` feature.

The 1,914 fixtures under `tests/data` are a separate matter, and they need no
modification at all: each one drives the command-line binary alone, through
documented flags, so nothing about the move to Rust reaches them. Read a suite
result as every fixture eligible under the advertised feature and protocol set
passing, rather than as the whole corpus. Roughly three quarters of them name
one of the nine in-scope schemes and roughly one in seven name only an
out-of-scope one; a complete build runs the former and skips the latter. This
build advertises no scheme at all, so **every fixture that transfers anything
skips today**, and the eligible set is correspondingly small. That number grows
as executors land, and it grows without touching a fixture.

Some fixtures will skip in a finished build too, and for a reason worth stating
rather than discovering: this build does not advertise `Debug`, and the harness
gates all allocation-cap and leak checking on that token. Withholding it makes
the 28 fixtures carrying a `<limits>` block inert, at the cost of the 98 that
require `Debug` skipping and `torture-test` not applying. That is a deliberate
trade, taken because a Rust allocator's allocation pattern cannot match a C
one's; a `memdebug` feature exists to reverse it if the trade is ever rejected.

Versioned symbol names of the form `name@@CURL_OPENSSL_4` are out of reach. A
linker version script handed through `-C link-arg` does not control what a
Rust `cdylib` exports, because the export list rustc computes takes
precedence; that was measured rather than assumed. An export set without
version tags is exactly what curl itself produces when configured with
`--disable-versioned-symbols`, which is a supported build mode.

## Open Source

curl is Open Source and is distributed under an MIT-like
[license](https://curl.se/docs/copyright.html).

## Contact

Contact us on a suitable [mailing list](https://curl.se/mail/) or
use GitHub [issues](https://github.com/curl/curl/issues)/
[pull requests](https://github.com/curl/curl/pulls)/
[discussions](https://github.com/curl/curl/discussions).

All contributors to the project are listed in [the THANKS
document](https://curl.se/docs/thanks.html).

## Commercial support

For commercial support, maybe private and dedicated help with your problems or
applications using (lib)curl visit [the support page](https://curl.se/support.html).

## Website

Visit the [curl website](https://curl.se/) for the latest news and downloads.

## Source code

Download the latest source from the Git server:

    git clone https://github.com/curl/curl

## Security problems

Report suspected security problems
[privately](https://curl.se/dev/vuln-disclosure.html) and not in public.

## Backers

Thank you to all our backers :pray: [Become a backer](https://opencollective.com/curl#section-contribute).

## Sponsors

Support this project by becoming a [sponsor](https://curl.se/sponsors.html).
