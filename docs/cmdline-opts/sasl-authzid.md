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

This build implements no IMAP, IMAPS, POP3, POP3S, SMTP, SMTPS, LDAP or LDAPS
transfers, the schemes that carry SASL PLAIN authentication. curl accepts this
option and parses its argument, yet the transfer itself fails with
`CURLE_UNSUPPORTED_PROTOCOL`, and the `Protocols:` line in the --version
output omits those schemes. HTTP authentication is unaffected: Basic, Digest,
Bearer and NTLM work as documented, and --user supplies their credentials.

If the option is not specified, the server derives the **authzid** from the
**authcid**, but if specified, and depending on the server implementation, it
may be used to access another user's inbox, that the user has been granted
access to, or a shared mailbox for example.
