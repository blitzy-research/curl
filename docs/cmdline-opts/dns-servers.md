---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dns-servers
Arg: <addresses>
Help: DNS server addrs to use
Protocols: DNS
Requires: c-ares
Added: 7.33.0
Category: dns
Multi: single
See-also:
  - dns-interface
  - dns-ipv4-addr
Example:
  - --dns-servers 192.168.0.1,192.168.0.2 $URL
  - --dns-servers 10.0.0.1:53 $URL
---

# `--dns-servers`

Specify the list of DNS servers to use instead of the system default. The
argument is a list of IP addresses separated with commas. Port numbers may
also optionally be given, appended to the IP address separated with a colon.

Name resolution is specified to run through the system resolver rather than
c-ares, so `curl_version_info` reports no c-ares. On a build that reports
none, curl rejects this option while parsing the command line, with `the
installed libcurl version does not support this`, and that rejection is the
frozen behavior of the option rather than a new one. The resolver modules
that would give the option meaning are not on disk.

To send name resolution over DNS-over-HTTPS to a server of your choosing,
consider the --doh-url option.
