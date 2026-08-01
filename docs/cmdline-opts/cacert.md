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

The certificates in the file become the trust anchors used to verify the server
certificate. Without this option, curl is specified to verify against the trust
anchors bundled through the `webpki-roots` crate, while --ca-native reads the
platform trust store through the `rustls-native-certs` crate instead. Those two
crates are both declared and are not alternatives to one another: the bundled
anchors back this embedded-bundle path and the platform store backs
--ca-native, so choosing between them is a runtime decision driven by these
options and never a build-time one. There is no unconditional fallback from one
to the other. The file named here is read with the PEM parser in the
`rustls-pki-types` crate, through its `PemObject` trait.

Verification of the peer is specified to be on by default, and --insecure is the
only way to turn it off. The warning that --insecure prints on stderr before the
transfer proceeds is delivered, and no verbosity option suppresses it, --silent
included. A revocation list given with --crlfile is specified to apply to the
trust anchors that this option installs.

The trust-anchor, key-matching and revocation behavior described above is
required target behavior rather than behavior a reader can exercise today: the
`curl-rs-lib` TLS backend and its certificate-verification module are not yet
on disk, and no
revocation implementation has been delivered.
