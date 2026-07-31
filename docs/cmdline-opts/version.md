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

This line names the TLS library in use. This build links exactly one TLS
implementation, `rustls`, which means no C TLS library is linked and curl
performs no TLS backend selection at start-up.

Because a single implementation is linked, the line never lists an alternative
backend within parentheses, and the `CURL_SSL_BACKEND` environment variable
has no other backend to name.

The second line (starts with `Release-Date:`) shows the release date.

The third line (starts with `Protocols:`) shows all protocols that libcurl
reports to support. This build transfers nine schemes and names exactly those:
`file`, `ftp`, `ftps`, `http`, `https`, `scp`, `sftp`, `ws` and `wss`. curl
registers 33 schemes in total and recognizes each of the other 24 when it
parses a URL, yet withholds them from this line, and a transfer request for
one of those schemes fails with `CURLE_UNSUPPORTED_PROTOCOL`.

The fourth line (starts with `Features:`) shows specific features libcurl
reports to offer. The sections below document the feature tokens curl knows
about, and each one notes when this build does not report it. Available
features include:

## `alt-svc`
Support for the Alt-Svc: header is provided.

## `AsynchDNS`
This curl uses asynchronous name resolves. This build resolves names with the
system resolver, driven by the asynchronous runtime, rather than with c-ares,
and `hickory-dns` is an optional alternative that stays out of the default
build.

## `brotli`
Support for automatic brotli compression over HTTP(S).

## `CharConv`
curl was built with support for character set conversions (like EBCDIC). This
build does not report this feature, because the platforms that need such
conversion fall outside its supported targets, which are Linux and macOS on
`x86_64` and `aarch64`.

## `Debug`
This curl uses a libcurl built with Debug. This enables more error-tracking
and memory debugging etc. For curl-developers only. This build does not report
this feature by default.

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
GSS-API is supported. This build reports this token only when built with its
non-default `negotiate` feature against the GSS-API the operating system
provides.

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
Kerberos V5 authentication is supported. This build does not report this
feature. The FTP Kerberos level was removed in 8.17.0, which makes
`CURLOPT_KRBLEVEL` return `CURLE_NOT_BUILT_IN` and leaves --krb without
function. Kerberos through HTTP Negotiate is a separate feature, described
under `GSS-API` and `SPNEGO`.

## `Largefile`
This curl supports transfers of large files, files larger than 2GB.

## `libz`
Automatic decompression (via gzip, deflate) of compressed files over HTTP is
supported.

## `MultiSSL`
This feature means curl supports multiple TLS backends. This build links
exactly one TLS implementation, `rustls`, and therefore never reports it.

## `NTLM`
NTLM authentication is supported.

## `NTLM_WB`
NTLM delegation to winbind helper is supported.
This feature was removed from curl in 8.8.0.

## `PSL`
PSL is short for Public Suffix List and means that this curl has been built
with knowledge about "public suffixes".

## `SPNEGO`
SPNEGO authentication is supported. This build reports this token only when
built with its non-default `negotiate` feature against the GSS-API the
operating system provides.

## `SSL`
SSL versions of various protocols are supported, such as HTTPS and FTPS.

## `SSLS-EXPORT`
This build supports TLS session export/import, like with the --ssl-sessions.

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
