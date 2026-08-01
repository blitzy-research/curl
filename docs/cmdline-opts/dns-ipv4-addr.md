---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dns-ipv4-addr
Arg: <address>
Help: IPv4 address to use for DNS requests
Protocols: DNS
Added: 7.33.0
Requires: c-ares
Category: dns
Multi: single
See-also:
  - dns-interface
  - dns-ipv6-addr
Example:
  - --dns-ipv4-addr 10.1.2.3 $URL
---

# `--dns-ipv4-addr`

Specify the source IP address for outgoing IPv4 DNS requests. The argument
should be a single IPv4 address.

Name resolution is specified to run through the system resolver rather than
c-ares, so `curl_version_info` reports no c-ares. On a build that reports
none, curl rejects this option while parsing the command line, with `the
installed libcurl version does not support this`, and that rejection is the
frozen behavior of the option rather than a new one. The resolver modules
that would give the option meaning are not on disk.
