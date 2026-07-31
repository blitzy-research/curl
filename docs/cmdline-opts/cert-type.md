---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: cert-type
Protocols: TLS
Arg: <type>
Help: Certificate type (DER/PEM/ENG/PROV/P12)
Category: tls
Added: 7.9.3
Multi: single
See-also:
  - cert
  - key
  - key-type
Example:
  - --cert-type PEM --cert file $URL
---

# `--cert-type`

Set type of the provided client certificate. PEM, DER, ENG, PROV and P12 are
recognized types.

This build uses `PEM`, which is also the default. The certificate is read as
`PEM`, so a `DER` certificate is not loaded. `ENG` and `PROV` depend on the
OpenSSL engine or provider interface, which this build does not have. `P12` is
specific to the native Windows TLS library, which this build does not use.
