---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: crlf
Help: Convert LF to CRLF in upload
Protocols: FTP SMTP
Category: ftp smtp
Added: 5.7
Multi: boolean
See-also:
  - use-ascii
Example:
  - --crlf -T file ftp://example.com/
---

# `--crlf`

Convert line feeds to carriage return plus line feeds in upload. Useful for
**MVS (OS/390)**.

Transfers for `SMTP` and `SMTPS` are outside the specified scope of this
rewrite, so the `Protocols:` line of the --version output withholds both
schemes and an SMTP transfer is specified to fail with
`CURLE_UNSUPPORTED_PROTOCOL` after this option parses. Line-ending conversion
is specified to be available for `FTP` and `FTPS` uploads.

No upload converts line endings in this build. The option, the configuration
field behind it and the engine primitive that rewrites the bytes each exist on
their own; nothing maps one to the next, no FTP upload engine drives it, and
the executable honours no command-line option yet.
