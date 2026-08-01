---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: form-string
Help: Specify multipart MIME data
Protocols: HTTP SMTP IMAP
Arg: <name=string>
Category: http upload post smtp imap
Added: 7.13.2
Multi: append
See-also:
  - form
Example:
  - --form-string "name=data" $URL
---

# `--form-string`

Similar to --form except that the value string for the named parameter is used
literally. Leading @ and \< characters, and the `;type=` string in the value
have no special meaning. Use this in preference to --form if there is any
possibility that the string value may accidentally trigger the @ or \<
features of --form.

Transfers for SMTP, SMTPS, IMAP and IMAPS are outside the specified scope of
this rewrite, and those four schemes are withheld from the `Protocols:` line
of the --version output. The option is still specified to be accepted and the
MIME part composed from the given string, with an SMTP or IMAP transfer then
failing with `CURLE_UNSUPPORTED_PROTOCOL`. HTTP and HTTPS multipart form use
stays within the specified scope.
