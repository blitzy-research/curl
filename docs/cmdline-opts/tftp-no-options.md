---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tftp-no-options
Help: Do not send any TFTP options
Protocols: TFTP
Added: 7.48.0
Category: tftp
Multi: boolean
See-also:
  - tftp-blksize
Example:
  - --tftp-no-options tftp://192.168.0.1/
---

# `--tftp-no-options`

Do not send TFTP options requests. This improves interop with some legacy
servers that do not acknowledge or properly implement TFTP options. When this
option is used --tftp-blksize is ignored.

Transfers for TFTP are outside the specified scope of this rewrite, so a
transfer request for a TFTP URL is specified to fail with
`CURLE_UNSUPPORTED_PROTOCOL` even though the option itself is still accepted
and parsed. The `Protocols:` line of the --version output withholds the scheme.
