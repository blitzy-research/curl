---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dns-interface
Arg: <interface>
Help: Interface to use for DNS requests
Protocols: DNS
Added: 7.33.0
Requires: c-ares
Category: dns
Multi: single
See-also:
  - dns-ipv4-addr
  - dns-ipv6-addr
Example:
  - --dns-interface eth0 $URL
---

# `--dns-interface`

Specify the interface for outgoing DNS requests. This option is a counterpart
to --interface (which does not affect DNS). The supplied string must be an
interface name (not an address).

Name resolution is specified to run through the system resolver rather than
c-ares, so `curl_version_info` reports no c-ares. On a build that reports
none, curl rejects this option while parsing the command line, with `the
installed libcurl version does not support this`, and that rejection is the
frozen behavior of the option rather than a new one. The resolver modules
that would give the option meaning are not on disk.
