---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: form-escape
Help: Escape form fields using backslash
Protocols: HTTP IMAP SMTP
Added: 7.81.0
Category: http upload post
Multi: single
See-also:
  - form
Example:
  - --form-escape -F 'field\name=curl' -F 'file=@load"this' $URL
---

# `--form-escape`

Pass on names of multipart form fields and files using backslash-escaping
instead of percent-encoding.

Transfers for SMTP, SMTPS, IMAP and IMAPS are outside the specified scope of
this rewrite, and those four schemes are withheld from the `Protocols:` line
of the --version output. The option is still specified to be accepted and its
backslash-escaping applied to the composed MIME part, with an SMTP or IMAP
transfer then failing with `CURLE_UNSUPPORTED_PROTOCOL`. HTTP and HTTPS
multipart form use stays within the specified scope.
