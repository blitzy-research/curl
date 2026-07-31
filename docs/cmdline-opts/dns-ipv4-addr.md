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

This build resolves names with the system resolver and does not use c-ares, so
this option is accepted and has no effect.
