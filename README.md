<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# [![curl logo](https://curl.se/logo/curl-logo.svg)](https://curl.se/)

curl is a command-line tool for transferring data from or to a server using
URLs. It supports these protocols: FILE, FTP, FTPS, HTTP, HTTPS, SCP, SFTP,
WS and WSS. HTTP transfers use HTTP/1.1, HTTP/2 or HTTP/3.

Another 24 URL schemes stay registered so that the C ABI stays complete, but
they are not implemented: DICT, GOPHER, GOPHERS, IMAP, IMAPS, LDAP, LDAPS,
MQTT, MQTTS, POP3, POP3S, RTMP and its variants, RTSP, SMB, SMBS, SMTP,
SMTPS, TELNET and TFTP. Their `CURLPROTO_*` constants remain in the public
header, and a request for one of them returns `CURLE_UNSUPPORTED_PROTOCOL`.
The `Protocols:` line of `curl --version` names what a given build serves.

Learn how to use curl by reading [the
man page](https://curl.se/docs/manpage.html) or [everything
curl](https://everything.curl.dev/).

Find out how to build curl from source under [Build](#build). Binary packages
and platform-specific notes are covered in [the INSTALL
document](docs/INSTALL.md).

libcurl is the library curl is using to do its job. It is readily available to
be used by your software. Read [the libcurl
man page](https://curl.se/libcurl/c/libcurl.html) to learn how.

## Build

curl and libcurl are written in Rust, as a Cargo workspace of three crates.
Building them needs a Rust toolchain and a C compiler, the latter because a
few dependencies build C and assembly of their own. Autotools and CMake are no
longer part of it. The edition is 2021 and the minimum supported Rust version
is 1.75. `rust-toolchain.toml` pins the channel, so every contributor and
every continuous integration leg compiles with the same toolchain.

    cargo build --locked --release --workspace
    cargo test --locked --workspace

Pass `--locked` every time. `Cargo.lock` is committed, and the resolution it
records is what keeps Rust 1.75 reachable, so refreshing it is not a
maintenance step. The release build has to compile with no warnings, which is
how continuous integration runs it, under `RUSTFLAGS=-D warnings`, so any
diagnostic the compiler raises stops the build. A message the build script
prints is a separate thing and reports state rather than a defect.

### Artifacts

`cargo build --release` leaves these four artifacts in `target/release`:

- `curl` and `curlinfo`, the two executables, from the `curl-rs` package
- `libcurl.so`, a `cdylib`, and `libcurl.a`, a `staticlib`, from the
  `curl-rs-ffi` package

`curl-config` and `libcurl.pc` are rendered by `curl-rs-ffi/build.rs` from the
`curl-config.in` and `libcurl.pc.in` templates in this tree. They land in the
build script output directory, both under their own names and again under
`staging/bin` and `staging/lib/pkgconfig`, laid out the way an install would
place them, so packaging copies one directory. Both answer the same queries as
before, so a build system that already asks them for a version, a link line or
a feature list needs no change. A build writes outside its own output
directory only when `CURL_RS_STAGING_DIR` names where, which leaves the
default build unable to touch the source tree.

The shared library carries the SONAME `libcurl.so.4`, and on Apple targets the
install name `@rpath/libcurl.4.dylib`. That 4 is derived rather than chosen:
`lib/Makefile.soname` sets `VERSIONCHANGE=12`, `VERSIONADD=0` and
`VERSIONDEL=8`, which is libtool `-version-info 12:0:8`, and a libtool SONAME
major is current minus age. `curl-rs-ffi/build.rs` emits it as a link argument
scoped to the `cdylib`, so the executables do not carry it.

Eight of the public headers under `include/curl/` are generated rather than
written: `curl-rs-ffi/build.rs` drives `cbindgen` over the Rust source to
produce `curl.h`, `easy.h`, `multi.h`, `urlapi.h`, `options.h`, `header.h`,
`websockets.h` and `mprintf.h`. The direction of generation is the reverse of
the C build, where the header was the source of truth and the option table was
derived from it. Four headers are beyond a generator and are maintained by
hand beside them: `curlver.h`, `stdcheaders.h`, `system.h`, and
`typecheck-gcc.h`, which holds the `curlcheck_` macros that give the arguments
of `curl_easy_setopt` compile-time type checking.

Generation is withheld while any symbol in `lib/libcurl.def` is still
undefined, and the build script says so on every build. `cbindgen` renders
only what exists, so a header regenerated early would be short by exactly what
is missing, and a header that declares a symbol nothing exports is an
undefined reference in every program that calls it. The headers already in the
tree are left alone and remain the ABI contract until the export surface is
complete, at which point generation resumes on its own.

### Supported targets

All four are 64-bit:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

## Workspace layout

- `curl-rs-lib` is the protocol engine, and the only crate with protocol
  knowledge.
- `curl-rs` is a thin command-line interface over the engine, and builds the
  `curl` and `curlinfo` executables.
- `curl-rs-ffi` is a thin C ABI over the engine. The export set it has to
  match is the 100 symbols that `lib/libcurl.def` lists for curl 8.19.0-DEV,
  and a parity check against that file is one of the validation gates. It
  fails on a difference in either direction: a symbol that is missing breaks
  an existing consumer at link time, and one that is extra is a surface
  nobody agreed to keep.

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
`ring`, which carries some C and assembly of its own. Certificate validation
is on unless `--insecure` is given, and `--insecure` emits a warning on
stderr before proceeding.

## Known deviations

Two places where this implementation cannot match the C tree, recorded here
rather than left to be discovered.

The C programs under `tests/libtest` (235 of them) and `tests/unit` (59) link
against internal `Curl_*` symbols, and a Rust static library does not export
`pub(crate)` items at all, so those programs cannot link however the engine is
written. Their coverage moves into the Rust crates as `#[cfg(test)]` modules
or behind a `testing` feature.

The 1,914 fixtures under `tests/data` are a separate matter, and they need no
modification at all: each one drives the command-line binary alone, through
documented flags, so nothing about the move to Rust reaches them. Read a suite
result as every fixture eligible under the advertised feature and protocol set
passing, rather than as the whole corpus: roughly three quarters of the
fixtures name one of the nine served schemes, and roughly one in seven name
only a scheme this build does not serve, so those skip instead of failing.

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
