---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: random-file
Arg: <file>
Help: File for reading random data from
Category: deprecated
Added: 7.7
Multi: single
See-also:
  - egd-file
Example:
  - --random-file rubbish $URL
---

# `--random-file`

Deprecated option. This option is ignored (added in 7.84.0). The TLS
implementation provides its own random data and consults no seed file.

The argument is the path name to a file containing random data. The data was
used to seed the random engine for SSL connections.
