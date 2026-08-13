//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// This software is licensed as described in the file COPYING, which
// you should have received as part of this distribution. The terms
// are also available at https://curl.se/docs/copyright.html.
//
// You may opt to use, copy, modify, merge, publish, distribute and/or sell
// copies of the Software, and permit persons to whom the Software is
// furnished to do so, under the terms of the COPYING file.
//
// This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
// KIND, either express or implied.
//
// SPDX-License-Identifier: curl
//
//***************************************************************************

//! Redaction adaptors for [`fmt::Debug`], so that a diagnostic cannot become
//! a credential disclosure.
//!
//! # Why this module exists
//!
//! `#[derive(Debug)]` renders every field, and a great many of this crate's
//! types hold bytes that arrived from a credential: a cookie value, an
//! `Authorization` header, a URL's userinfo, a multipart body, a DoH query.
//! Rust makes a derived formatter free to write, which is exactly why it is
//! easy to attach one to a secret-bearing type without noticing -- and once
//! attached, any `{:?}` anywhere, including one inside an error message or a
//! trace line a user pastes into a bug report, writes the secret out.
//!
//! The C tree has no equivalent hazard, because C has no derived formatter:
//! every diagnostic in `lib/` names the specific field it prints. So this is
//! not a parity repair. It is the safety property the derived formatter costs
//! us, restored explicitly, and it is confined to the *formatting* of a value
//! and never to the value itself. **Nothing here changes a byte that reaches
//! the wire, a file, or a callback.**
//!
//! # The shape, and why it is a length rather than a mask
//!
//! [`Redacted`] renders a byte count and no bytes. A fixed mask such as
//! `"***"` would lose the one piece of information a reader legitimately needs
//! from a redacted field -- whether it is set at all, and whether it is
//! plausibly the value they expected -- while a prefix such as `"abc..."` would
//! disclose the beginning of a secret, which for a short token is most of it.
//! A count discloses nothing that an attacker with the ciphertext does not
//! already have, and it is enough to tell an empty password from a missing one.
//!
//! [`RedactedOpt`] is the same for an optional field, so that `None` stays
//! distinguishable from `Some("")`; that distinction is behaviourally
//! significant throughout the C tree -- `lib/cookie.c` treats a cookie with no
//! value differently from one with an empty value -- and a formatter that
//! collapsed the two would mislead exactly when a reader most needs the truth.
//!
//! # Sensitive header names
//!
//! [`is_sensitive_header`] answers whether a header's *value* is a credential.
//! The list is deliberately short and deliberately closed: it names the fields
//! that carry an authenticator or a session identifier, matched
//! case-insensitively because HTTP field names are, per RFC 9110 section 5.1.
//! It is used by `crate::headers` and `crate::auth::aws_sigv4`, so one
//! judgement about what counts as a secret is made once.

use core::fmt;

/// Header field names whose value is a credential, lowercase.
///
/// Each entry is here because its value authenticates a request or identifies
/// a session, so printing it is equivalent to printing a password:
///
/// * `authorization`, `proxy-authorization` -- the credential itself, for
///   every scheme `crate::auth` implements. `lib/http.c` composes both.
/// * `cookie`, `set-cookie`, `set-cookie2` -- session identifiers.
///   `lib/cookie.c` is the whole of why this module exists.
/// * `www-authenticate`, `proxy-authenticate` -- a challenge rather than a
///   credential, but Digest challenges carry a nonce and NTLM challenges carry
///   a server challenge, both of which are inputs to an authenticator.
/// * `x-amz-security-token` -- an AWS temporary session credential, signed by
///   `crate::auth::aws_sigv4` and therefore reachable from its trace.
/// * `authentication-info`, `proxy-authentication-info` -- carry `rspauth`,
///   which is a MAC over the shared secret (`lib/vauth/digest.c`).
const SENSITIVE_HEADERS: &[&str] = &[
    "authentication-info",
    "authorization",
    "cookie",
    "proxy-authenticate",
    "proxy-authentication-info",
    "proxy-authorization",
    "set-cookie",
    "set-cookie2",
    "www-authenticate",
    "x-amz-security-token",
];

/// What replaces a redacted value's bytes in a formatted representation.
///
/// A single spelling, so a test can assert its absence and its presence
/// without embedding a literal in twenty places.
pub(crate) const MARKER: &str = "redacted";

/// Whether this header field name's value is a credential.
///
/// Case-insensitive, because HTTP field names are (RFC 9110 section 5.1), and
/// byte-oriented, because a header name arrives as bytes and a name that is
/// not valid UTF-8 must still be classified rather than rejected. A name that
/// matches nothing is not sensitive, which is the safe default here in the
/// only direction that matters: over-redacting costs a reader information,
/// while under-redacting costs a user a secret, so the list errs long.
pub(crate) fn is_sensitive_header(name: &[u8]) -> bool {
    SENSITIVE_HEADERS.iter().any(|candidate| {
        candidate.len() == name.len()
            && candidate
                .as_bytes()
                .iter()
                .zip(name)
                .all(|(want, got)| *want == got.to_ascii_lowercase())
    })
}

/// A [`fmt::Debug`] adaptor rendering a byte slice's length and none of it.
///
/// Wrap a secret-bearing field in this inside a hand-written formatter:
///
/// ```text
/// f.debug_struct("Credentials")
///     .field("user", &self.user)
///     .field("password", &Redacted(&self.password))
///     .finish()
/// ```
///
/// The output is `<redacted, N bytes>`, so a reader learns that the field is
/// set and how long it is, and nothing else. `N` is a byte count and not a
/// character count, matching every length in this crate.
pub(crate) struct Redacted<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{MARKER}, {} bytes>", self.0.len())
    }
}

/// [`Redacted`] for an optional field, keeping `None` distinct from `Some("")`.
///
/// `None` renders as `None` and `Some(bytes)` as `<redacted, N bytes>`. The
/// distinction is behaviourally significant -- a cookie with no value is not a
/// cookie with an empty value (`lib/cookie.c:1451`), and an unset password is
/// not an empty one -- so collapsing the two would mislead a reader precisely
/// where the truth matters.
pub(crate) struct RedactedOpt<'a>(pub(crate) Option<&'a [u8]>);

impl fmt::Debug for RedactedOpt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(bytes) => fmt::Debug::fmt(&Redacted(bytes), f),
            None => f.write_str("None"),
        }
    }
}

/// A [`fmt::Debug`] adaptor for a header value, redacting only when the header
/// name says the value is a credential.
///
/// Name-aware rather than blanket, because a header store holds mostly
/// ordinary fields -- `Content-Type`, `Location`, `Server` -- whose values are
/// what makes a trace useful. Redacting all of them would trade a real
/// debugging capability for no additional confidentiality, since a
/// non-sensitive value is already visible in `--trace` output.
pub(crate) struct HeaderValue<'a> {
    /// The field name, used only to classify.
    pub(crate) name: &'a [u8],
    /// The field value, rendered or redacted according to the name.
    pub(crate) value: &'a [u8],
}

impl fmt::Debug for HeaderValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if is_sensitive_header(self.name) {
            fmt::Debug::fmt(&Redacted(self.value), f)
        } else {
            fmt::Debug::fmt(&String::from_utf8_lossy(self.value), f)
        }
    }
}

/// A [`fmt::Debug`] adaptor for text that is safe to render, lossily.
///
/// Not a redaction: this is the counterpart used for the fields a redacting
/// formatter keeps, so that a hand-written `Debug` renders non-UTF-8 bytes
/// without the formatter itself becoming the thing that fails. Kept here so
/// the two adaptors read as a pair at every use site.
pub(crate) struct Lossy<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for Lossy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&String::from_utf8_lossy(self.0), f)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_sensitive_header, HeaderValue, Lossy, Redacted, RedactedOpt, MARKER,
    };

    /// The whole point, stated as one assertion: the bytes do not appear.
    #[test]
    fn a_redacted_value_discloses_its_length_and_nothing_else() {
        let secret = b"hunter2-and-then-some";
        let text = format!("{:?}", Redacted(secret));

        assert!(!text.contains("hunter2"), "{text}");
        assert_eq!(text, format!("<{MARKER}, {} bytes>", secret.len()));
    }

    /// An empty value is still reported as set, with a length of zero.
    #[test]
    fn an_empty_value_is_distinguishable_from_a_missing_one() {
        assert_eq!(
            format!("{:?}", RedactedOpt(Some(b""))),
            "<redacted, 0 bytes>"
        );
        assert_eq!(format!("{:?}", RedactedOpt(None)), "None");
    }

    /// Non-UTF-8 bytes are redacted like any other, without a lossy pass.
    #[test]
    fn invalid_utf8_is_redacted_by_length() {
        let text = format!("{:?}", Redacted(&[0xff, 0xfe, 0x00]));
        assert_eq!(text, "<redacted, 3 bytes>");
    }

    /// Every listed name matches in any case; nothing else matches.
    #[test]
    fn sensitive_header_names_match_case_insensitively() {
        for name in [
            "Authorization",
            "AUTHORIZATION",
            "authorization",
            "Cookie",
            "Set-Cookie",
            "set-cookie2",
            "Proxy-Authorization",
            "WWW-Authenticate",
            "Proxy-Authenticate",
            "X-Amz-Security-Token",
            "Authentication-Info",
            "Proxy-Authentication-Info",
        ] {
            assert!(is_sensitive_header(name.as_bytes()), "{name}");
        }

        for name in [
            "Content-Type",
            "Location",
            "Server",
            "Host",
            "User-Agent",
            // A prefix and a suffix of a listed name must not match.
            "Auth",
            "Authorizations",
            "X-Cookie",
            "",
        ] {
            assert!(!is_sensitive_header(name.as_bytes()), "{name}");
        }
    }

    /// A header value is redacted by its name, not by its content.
    #[test]
    fn a_header_value_is_redacted_only_when_its_name_says_so() {
        let credential = HeaderValue {
            name: b"Authorization",
            value: b"Bearer abc123",
        };
        let text = format!("{credential:?}");
        assert!(!text.contains("abc123"), "{text}");
        assert_eq!(text, "<redacted, 13 bytes>");

        let ordinary = HeaderValue {
            name: b"Content-Type",
            value: b"text/plain",
        };
        assert_eq!(format!("{ordinary:?}"), "\"text/plain\"");
    }

    /// The lossy adaptor renders rather than redacts, and cannot itself fail.
    ///
    /// The invalid byte becomes U+FFFD, which [`fmt::Debug`](core::fmt::Debug)
    /// for `str` emits literally rather than as an escape, because it is a
    /// printable character. What is being asserted is that the adaptor produced
    /// output at all instead of propagating a UTF-8 error.
    #[test]
    fn the_lossy_adaptor_renders_invalid_utf8_without_failing() {
        assert_eq!(format!("{:?}", Lossy(b"plain")), "\"plain\"");
        assert_eq!(format!("{:?}", Lossy(&[0xff])), "\"\u{fffd}\"");
    }
}
