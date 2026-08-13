---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: B
Long: use-ascii
Help: Use ASCII/text transfer
Protocols: FTP LDAP TFTP
Category: ftp output ldap tftp
Added: 5.0
Multi: boolean
See-also:
  - crlf
  - data-ascii
Example:
  - -B ftp://example.com/README
---

# `--use-ascii`

Enable ASCII transfer mode. For FTP, this can also be enforced by using a URL
that ends with `;type=A`. For TFTP, this can also be enforced by using a URL
that ends with `;mode=netascii`. This option causes data sent to stdout to be
in text mode for Win32 systems.

Transfers for `LDAP`, `LDAPS` and `TFTP` are outside the specified scope of
this rewrite. The `Protocols:` line of the --version output withholds all
three, and a request using any of them is specified to fail with
`CURLE_UNSUPPORTED_PROTOCOL` even though this option and the `;mode=netascii`
suffix are still accepted and parsed. ASCII mode for `FTP` and `FTPS`,
including the `;type=A` form, is specified to work exactly as described above.

ASCII mode is not deliverable in this build, and the halves are worth keeping
apart. The command-line flag exists, the configuration field that records it
exists, and so does the engine primitive that selects text mode; no mapping
connects the flag to that primitive, no FTP transfer engine invokes it, and the
executable honours no command-line option in the first place.
