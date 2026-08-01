---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: mail-from
Arg: <address>
Help: Mail from this address
Protocols: SMTP
Added: 7.20.0
Category: smtp
Multi: single
See-also:
  - mail-rcpt
  - mail-auth
Example:
  - --mail-from user@example.com -T mail smtp://example.com/
---

# `--mail-from`

Specify a single address that the given mail should get sent from.

Transfers for `SMTP` and `SMTPS` are outside the specified scope of this
rewrite, and neither scheme appears in the `Protocols:` line of the --version
output. Parsing and accepting this option are still specified, with a transfer
using either scheme then failing with `CURLE_UNSUPPORTED_PROTOCOL`.
