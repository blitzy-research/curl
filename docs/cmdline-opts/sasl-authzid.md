---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: sasl-authzid
Arg: <identity>
Help: Identity for SASL PLAIN authentication
Protocols: LDAP IMAP POP3 SMTP
Added: 7.66.0
Category: auth
Multi: single
See-also:
  - login-options
Example:
  - --sasl-authzid zid imap://example.com/
---

# `--sasl-authzid`

Use this authorization identity (**authzid**), during SASL PLAIN
authentication, in addition to the authentication identity (**authcid**) as
specified by --user.

Transfers for IMAP, IMAPS, POP3, POP3S, SMTP, SMTPS, LDAP and LDAPS, the
schemes that carry SASL PLAIN authentication, are outside the specified scope
of this rewrite, and the `Protocols:` line of the --version output withholds
all eight. Accepting this option and parsing its argument are still specified,
with the transfer itself then failing with `CURLE_UNSUPPORTED_PROTOCOL`. HTTP
authentication is untouched by that boundary: Basic, Digest, Bearer and NTLM
are all within the specified scope, with --user supplying their credentials.

If the option is not specified, the server derives the **authzid** from the
**authcid**, but if specified, and depending on the server implementation, it
may be used to access another user's inbox, that the user has been granted
access to, or a shared mailbox for example.
