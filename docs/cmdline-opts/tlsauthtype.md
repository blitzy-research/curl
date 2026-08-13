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

The option needs a libcurl built with TLS-SRP support. TLS-SRP is outside the
specified scope of this rewrite, so the `Features:` line of the --version
output withholds `TLS-SRP`, and on a build that withholds it curl rejects this
option and its companions --tlsuser and --tlspassword while parsing the
command line. That rejection is the frozen behavior of the options rather than
a new one, and it stays that way permanently: no configuration of this build
ever gains TLS-SRP. The withheld feature name is delivered, and so is the
rejection itself, which lives in the option module and is tested there. Neither
is observable yet, because the executable does not call the parser.
