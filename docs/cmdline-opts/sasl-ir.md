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

Transfers for IMAP, IMAPS, POP3, POP3S, SMTP, SMTPS, LDAP and LDAPS, the
schemes that carry SASL authentication, are outside the specified scope of
this rewrite, and the `Protocols:` line of the --version output withholds all
eight. Accepting and parsing this option are still specified, with the
transfer itself then failing with `CURLE_UNSUPPORTED_PROTOCOL`. HTTP
authentication is untouched by that boundary: Basic, Digest, Bearer and NTLM
are all within the specified scope.
