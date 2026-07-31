---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tlsauthtype
Arg: <type>
Help: TLS authentication type
Protocols: TLS
Added: 7.21.4
Category: tls auth
Multi: single
See-also:
  - tlsuser
Example:
  - --tlsauthtype SRP $URL
---

# `--tlsauthtype`

Set TLS authentication type. Currently, the only supported option is `SRP`,
for TLS-SRP (RFC 5054). If --tlsuser and --tlspassword are specified but
--tlsauthtype is not, then this option defaults to `SRP`.

This build has no TLS-SRP support, so this option and its companions
--tlsuser and --tlspassword have no usable effect. curl rejects each of them
because the installed libcurl reports no such support, and the `Features:`
line of the --version output accordingly omits `TLS-SRP`.
