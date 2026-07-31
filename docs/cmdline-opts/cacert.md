---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: cacert
Arg: <file>
Help: CA certificate to verify peer against
Protocols: TLS
Category: tls
Added: 7.5
Multi: single
See-also:
  - capath
  - dump-ca-embed
  - insecure
Example:
  - --cacert CA-file.txt $URL
---

# `--cacert`

Use the specified certificate file to verify the peer. The file may contain
multiple CA certificates. The certificate(s) must be in PEM format. Normally
curl is built to use a default file for this, so this option is typically used
to alter that default file.

curl recognizes the environment variable named `CURL_CA_BUNDLE` if it is set,
and uses the given path as a path to a CA cert bundle. This option overrides
that variable.

The certificates in the file become the trust anchors used to verify the
server certificate. Without this option, curl verifies against the trust
anchors bundled through the `webpki-roots` crate, while --ca-native reads the
platform trust store through the `rustls-native-certs` crate instead. The file
named here is parsed with the `rustls-pemfile` crate.

Verification of the peer is on by default. --insecure is the only way to turn
it off, and it prints a warning on stderr before the transfer proceeds. A
revocation list given with --crlfile is applied to the trust anchors that this
option installs.
