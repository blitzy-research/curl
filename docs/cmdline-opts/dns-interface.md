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

This build resolves names with the system resolver and does not use c-ares, so
this option is accepted and has no effect.
