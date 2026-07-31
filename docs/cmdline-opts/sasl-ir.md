---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: sasl-ir
Help: Initial response in SASL authentication
Protocols: LDAP IMAP POP3 SMTP
Added: 7.31.0
Category: auth
Multi: boolean
See-also:
  - sasl-authzid
Example:
  - --sasl-ir imap://example.com/
---

# `--sasl-ir`

Enable initial response in SASL authentication. Such an "initial response" is
a message sent by the client to the server after the client selects an
authentication mechanism.

This build implements no IMAP, IMAPS, POP3, POP3S, SMTP, SMTPS, LDAP or LDAPS
transfers, the schemes that carry SASL authentication. curl accepts and parses
this option, yet the transfer itself fails with `CURLE_UNSUPPORTED_PROTOCOL`,
and the `Protocols:` line in the --version output omits those schemes. HTTP
authentication is unaffected: Basic, Digest, Bearer and NTLM work as
documented.
