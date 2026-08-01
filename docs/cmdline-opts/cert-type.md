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

The specified target design uses `PEM`, which is also its default, and reads the
certificate as `PEM`, so a `DER` certificate is not loaded. `ENG` and `PROV`
depend on the OpenSSL engine or provider interface, which that design does not
include. `P12` is specific to the native Windows TLS library, which it does not
use either. None of this is observable yet: the `curl-rs-lib` TLS backend and
its certificate-verification module are not on disk, so the paragraph states a
required target
behavior rather than one a reader can exercise today.
