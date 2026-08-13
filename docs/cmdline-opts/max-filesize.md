---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: max-filesize
Arg: <bytes>
Help: Maximum file size to download
Protocols: FTP HTTP MQTT
Category: connection
Added: 7.10.8
Multi: single
See-also:
  - limit-rate
Example:
  - --max-filesize 100K $URL
  - --max-filesize 2.6M $URL
---

# `--max-filesize`

When set to a non-zero value, it specifies the maximum size (in bytes) of a
file to download. If the file requested is larger than this value, the
transfer does not start and curl returns with exit code 63.

Setting the maximum value to zero disables the limit.

A unit suffix letter can be used. Appending 'k' or 'K' counts the number as
kilobytes, 'm' or 'M' makes it megabytes etc. The supported suffixes (k, M, G,
T, P) are 1024-based. Examples: 200K, 3m and 1G. (Added in 7.58.0)

**NOTE**: before curl 8.4.0, when the file size is not known prior to
download, for such files this option has no effect even if the file transfer
ends up being larger than this given limit.

Starting with curl 8.4.0, this option aborts the transfer if it reaches the
threshold during transfer.

Starting in curl 8.19.0, the maximum size can be specified using a fraction as
in `2.5M` for two and a half megabytes. It only works with a period (`.`)
delimiter, independent of what your locale might prefer.

Transfers for `MQTT` and `MQTTS` are outside the specified scope of this
rewrite, so the `Protocols:` line of the --version output withholds both
schemes and a request for either one is specified to fail with
`CURLE_UNSUPPORTED_PROTOCOL` even though the option and its byte value are
still accepted and parsed. The size limit is specified to apply to `FTP`,
`FTPS`, `HTTP` and `HTTPS`.

All of the above states specified behavior, and this build does not reach it
yet. The executable honours no command-line option, and no FTP or HTTP transfer
engine exists for a ceiling to act on. Three pieces are in place separately --
the option's row in the parser, the configuration field that records the byte
value, and the engine primitive that enforces the limit -- and what is missing
is the layer that connects them.
