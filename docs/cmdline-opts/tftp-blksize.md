---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tftp-blksize
Arg: <value>
Help: Set TFTP BLKSIZE option
Protocols: TFTP
Added: 7.20.0
Category: tftp
Multi: single
See-also:
  - tftp-no-options
Example:
  - --tftp-blksize 1024 tftp://example.com/file
---

# `--tftp-blksize`

Set the TFTP **BLKSIZE** option (must be 512 or larger). This is the block
size that curl tries to use when transferring data to or from a TFTP
server. By default 512 bytes are used.

Transfers for TFTP are outside the specified scope of this rewrite, so a
transfer request for a TFTP URL is specified to fail with
`CURLE_UNSUPPORTED_PROTOCOL` even though the option itself is still accepted
and parsed. The `Protocols:` line of the --version output withholds the scheme.
