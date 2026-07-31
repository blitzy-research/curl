---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dns-ipv6-addr
Arg: <address>
Help: IPv6 address to use for DNS requests
Protocols: DNS
Added: 7.33.0
Requires: c-ares
Category: dns
Multi: single
See-also:
  - dns-interface
  - dns-ipv4-addr
Example:
  - --dns-ipv6-addr 2a04:4e42::561 $URL
---

# `--dns-ipv6-addr`

Specify the source IP address for outgoing IPv6 DNS requests. The argument
should be a single IPv6 address.

This build resolves names with the system resolver and does not use c-ares, so
this option is accepted and has no effect.
