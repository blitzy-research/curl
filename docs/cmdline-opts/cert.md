---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: E
Long: cert
Arg: <certificate[:password]>
Help: Client certificate file and password
Protocols: TLS
Category: tls
Added: 5.0
Multi: single
See-also:
  - cert-type
  - key
  - key-type
Example:
  - --cert certfile --key keyfile $URL
---

# `--cert`

Use the specified client certificate file when getting a file with HTTPS, FTPS
or another SSL-based protocol. The certificate must be PEM format. If the
optional password is not specified, it is queried for on the terminal. This
option provides only the client certificate: the matching private key is read
from a separate file and is given with --key, which is required whenever this
option is used. Supplying one without the other, or supplying a certificate
and key that do not match each other, is rejected as a certificate problem.

In the \<certificate\> portion of the argument, you must escape the character
`:` as `\:` so that it is not recognized as the password delimiter. Similarly,
you must escape the double quote character as \" so that it is not recognized
as an escape character.

The certificate is read as `PEM`. The `PKCS#11`, `P12`, engine, provider and
certificate store forms are not available in this build.
