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

This build resolves names with the system resolver and does not use c-ares, so
this option is accepted and has no effect. To send name resolution over
DNS-over-HTTPS to a server of your choosing, consider the --doh-url option.
