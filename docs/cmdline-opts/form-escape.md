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

This build performs no SMTP, SMTPS, IMAP or IMAPS transfers, and those schemes
are absent from the `Protocols:` line in the --version output. curl accepts
this option and applies the backslash-escaping to the composed MIME part, yet
an SMTP or IMAP transfer then fails with `CURLE_UNSUPPORTED_PROTOCOL`; HTTP
and HTTPS multipart form use is fully supported.
