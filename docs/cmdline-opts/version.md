---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: version
Short: V
Help: Show version number and quit
Category: important curl
Added: 4.0
Multi: custom
See-also:
  - help
  - manual
Example:
  - --version
---

# `--version`

Display information about curl and the libcurl version it uses.

The first line includes the full version of curl, libcurl and other 3rd party
libraries linked with the executable.

This line may contain one or more TLS libraries. curl can be built to support
more than one TLS library which then makes curl - at start-up - select which
particular backend to use for this invocation. The ones that are *not*
selected are then listed within parentheses, and such a build also has
`MultiSSL` set as a feature.

Exactly one TLS implementation is specified for this rewrite, `rustls`, with no
C TLS library linked, so there is no start-up selection to make: nothing is
listed within parentheses, `MultiSSL` is withheld, and the `CURL_SSL_BACKEND`
environment variable has no other backend to name. The feature table that
withholds `MultiSSL` is delivered in `curl-rs-lib` and its tests assert the
withholding; the TLS backend itself, and with it the version line that would
report the backend, are not on disk yet.

Where a C build of curl names `c-ares` on this line, this build names nothing:
it resolves with the system resolver. A build that enables the optional,
default-off in-process resolver names `hickory-resolver` and its version in
that position instead, so the line always states which resolver is actually
compiled in.

The second line (starts with `Release-Date:`) shows the release date.

The third line (starts with `Protocols:`) shows all protocols that libcurl
reports to support. Nine schemes are named on it here: `file`, `ftp`, `ftps`,
`http`, `https`, `scp`, `sftp`, `ws` and `wss`. That list is delivered in
`curl-rs-lib`, and its tests assert both the list itself and the withholding
of every other scheme. curl registers 33 schemes in total; recognizing each of
the remaining 24 while parsing a URL, and failing a transfer request for one of
them with `CURLE_UNSUPPORTED_PROTOCOL`, is specified target behavior, because
the protocol modules are not on disk yet.

The fourth line (starts with `Features:`) shows specific features libcurl
reports to offer. The sections below document the feature tokens curl knows
about, and each one notes when this build does not report it. Available
features include:

## `alt-svc`
Support for the Alt-Svc: header is provided.

## `AsynchDNS`
This curl uses asynchronous name resolves. This build resolves names with the
system resolver, driven by the asynchronous runtime, rather than with c-ares.
The `hickory-dns` build feature that was intended to offer an in-process
alternative is a reserved name with no implementation: enabling it fails the
build deliberately, because no release of the resolver crate both satisfies the
project's minimum Rust version and carries the fix for RUSTSEC-2026-0119. The
system resolver is therefore the only resolver in every configuration. The
resolver modules themselves are not on disk yet, so this token is withheld from
the reported feature set until they land -- under-reporting a capability costs a
skipped fixture, while over-reporting one costs a failure.

## `brotli`
Support for automatic brotli compression over HTTP(S).

## `CharConv`
curl was built with support for character set conversions (like EBCDIC). This
build does not report this feature, because the platforms that need such
conversion fall outside its supported targets, which are Linux and macOS on
`x86_64` and `aarch64`.

## `Debug`
This curl uses a libcurl built with Debug. This enables more error-tracking
and memory debugging etc. For curl-developers only. This build never reports
this feature, in any configuration. The `memdebug` build feature supplies the
allocation log the test harness reads, but it deliberately does not turn this
token on, because the token also promises internal behavior changes that this
build does not make.

## `ECH`
This feature means ECH support is present. This build does not report it,
while the --ech option remains accepted and `CURLE_ECH_REQUIRED` keeps its
value.

## `gsasl`
The built-in SASL authentication includes extensions to support SCRAM because
libcurl was built with libgsasl. This build does not report this feature. It
uses no libgsasl, and the SASL protocols that library served are not
implemented.

## `GSS-API`
GSS-API is supported. This build reports this token only when both conditions
hold: it was built with its non-default `negotiate` feature, and a runtime
probe finds a usable GSS-API in the operating system. A host can have the
feature compiled in while the library itself is unusable, and reporting the
token in that case would promise a mechanism that cannot run.

## `HSTS`
HSTS support is present.

## `HTTP2`
HTTP/2 support has been built-in.

## `HTTP3`
HTTP/3 support has been built-in.

## `HTTPS-proxy`
This curl is built to support HTTPS proxy.

## `IDN`
This curl supports IDN - international domain names.

## `IPv6`
You can use IPv6 with this.

## `Kerberos`
Kerberos V5 authentication is supported. Kerberos is reached through GSS-API
here, so this token is reported only for a build made with the non-default
`negotiate` feature, exactly as `GSS-API` and `SPNEGO` are, and then only when
the runtime probe finds a usable GSS-API library -- one build condition and one
runtime probe, shared by all three tokens. The FTP Kerberos level is a separate
matter: it was removed in 8.17.0, which makes
`CURLOPT_KRBLEVEL` return `CURLE_NOT_BUILT_IN` and leaves --krb without
function.

## `Largefile`
This curl supports transfers of large files, files larger than 2GB.

## `libz`
Automatic decompression (via gzip, deflate) of compressed files over HTTP is
supported.

## `MultiSSL`
This feature means curl supports multiple TLS backends. Exactly one TLS
implementation is specified here, `rustls`, so this token is withheld
unconditionally and its withholding is asserted by test.

## `NTLM`
NTLM authentication is supported.

## `NTLM_WB`
NTLM delegation to winbind helper is supported.
This feature was removed from curl in 8.8.0.

## `PSL`
PSL is short for Public Suffix List and means that this curl has been built
with knowledge about "public suffixes".

## `SPNEGO`
SPNEGO authentication is supported. This build reports this token under exactly
the conditions described under `GSS-API`, because SPNEGO is reachable only
through GSS-API, so the two share one build condition and one runtime probe.

## `SSL`
SSL versions of various protocols are supported, such as HTTPS and FTPS. This
token is reported unconditionally, because TLS is not an optional part of
`curl-rs-lib`, while the backend that carries out those transfers is not on
disk yet.

## `SSLS-EXPORT`
This feature means the build supports TLS session export and import, like with
the --ssl-sessions option. This token is withheld here, matching the reference
build, where session export is off by default and documented as experimental.

## `SSPI`
SSPI is supported. SSPI is a Windows security interface, and Windows falls
outside the supported targets of this build, so this feature is never
reported.

## `TLS-SRP`
SRP (Secure Remote Password) authentication is supported for TLS. This build
has no TLS-SRP support and never reports this feature.

## `Unicode`
Unicode support on Windows. Windows falls outside the supported targets of
this build, so this feature is never reported.

## `UnixSockets`
Unix sockets support is provided.

## `zstd`
Automatic decompression (via zstd) of compressed files over HTTP is supported.
