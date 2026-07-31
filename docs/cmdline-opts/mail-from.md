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

This build performs no `SMTP` or `SMTPS` transfers. curl still parses and
accepts this option, yet a transfer using either scheme fails with
`CURLE_UNSUPPORTED_PROTOCOL`, and neither scheme appears in the `Protocols:`
line of the --version output.
