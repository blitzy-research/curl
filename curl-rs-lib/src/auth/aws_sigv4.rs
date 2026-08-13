// /***************************************************************************
//  *                                  _   _ ____  _
//  *  Project                     ___| | | |  _ \| |
//  *                             / __| | | | |_) | |
//  *                            | (__| |_| |  _ <| |___
//  *                             \___|\___/|_| \_\_____|
//  *
//  * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//  *
//  * This software is licensed as described in the file COPYING, which
//  * you should have received as part of this distribution. The terms
//  * are also available at https://curl.se/docs/copyright.html.
//  *
//  * You may opt to use, copy, modify, merge, publish, distribute and/or sell
//  * copies of the Software, and permit persons to whom the Software is
//  * furnished to do so, under the terms of the COPYING file.
//  *
//  * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
//  * KIND, either express or implied.
//  *
//  * SPDX-License-Identifier: curl
//  *
//  ***************************************************************************/
//! AWS Signature Version 4 request signing.
//!
//! Supersedes `lib/http_aws_sigv4.c` in full, and backs `CURLOPT_AWS_SIGV4`
//! and the `--aws-sigv4` command-line flag.
//!
//! # implementation
//!
//! AWS SigV4 signs a request; it never answers a `WWW-Authenticate:`
//! challenge, which is why `super::CHALLENGE_ORDER` has no entry for it while
//! `super::EMISSION_ORDER` puts it first. In C the emission arm calls
//! `Curl_output_aws_sigv4(data)` directly -- there is no vtable to dispatch
//! through -- and the faithful Rust shape is therefore a free function,
//! [`output_aws_sigv4`], rather than a trait implementation. Two facts make
//! that more than a preference: `super::AuthContext` carries neither the
//! request description this signature covers (the host header, the
//! application's own headers, the path, the query, the payload) nor a
//! [`Tracer`] for the three frozen `infof()` lines, and the trait's `input`
//! method would have no behaviour to implement.
//!
//! # Secrets
//!
//! curl performs no redaction and this module adds none: `lib/http.c:2888`
//! puts the fully formed `Authorization:` header straight into the request
//! buffer, `--verbose` prints it verbatim, and 168 fixtures compare that line
//! byte for byte. What is enforced instead is narrower and is the rule that
//! actually binds: **no secret gains a path to a log that curl does not
//! already have.** The three `infof()` lines the C emits are reproduced
//! verbatim and nothing is added; the password, the `AWS4`-prefixed signing
//! material and the four intermediate keyed digests are never formatted,
//! never logged, and carried in types whose [`fmt::Debug`] prints a
//! placeholder ([`SigningSecret`], [`SigningKey`]). Note that the string to
//! sign -- which the C does log -- contains no secret: it holds the
//! algorithm, the timestamp, the credential scope and a hash.

use core::cmp::Ordering;
use core::fmt;
use core::fmt::Write as _;
// Reached only by the debug-build arm of `forced_epoch_requested`, which is the
// `#ifdef DEBUGBUILD` guard of `lib/http_aws_sigv4.c:947-957`. Gated with it so
// a release build carries no environment read on the signing path at all.
#[cfg(debug_assertions)]
use std::env;

use crate::crypto::hmac::hmac_sha256;
use crate::crypto::sha256::{sha256, DIGEST_LEN};
use crate::error::CURLcode;
use crate::trace::{failf, infof, Tracer};
use crate::url::escape::{hexbyte, hexencode};
use crate::util::dynbuf::DynBuf;
use crate::util::redact::{is_sensitive_header, Redacted};
use crate::util::strcase::{ncasecompare, raw_tolower, raw_toupper};
use crate::util::strparse::{
    hexval, is_alnum, is_blank, is_urlpunct, is_xdigit, str_casecompare,
    str_cmp, str_passblanks, str_single, str_until,
};
use crate::util::timeval::{gmtime, Clock};

use super::{AuthEmission, Credentials, REDACTED_PLACEHOLDER};

// Constants. Every one of these is a C `#define` with its site recorded.

/// `TIMESTAMP_SIZE` (`lib/http_aws_sigv4.c:53`): the size of the buffer that
/// holds `YYYYMMDDTHHMMSSZ`.
pub(crate) const TIMESTAMP_SIZE: usize = 17;

/// The timestamp as a *string*: `TIMESTAMP_SIZE - 1`, 16 bytes.
const TIMESTAMP_LEN: usize = TIMESTAMP_SIZE - 1;

/// The credential-scope date, `YYYYMMDD`.
///
/// `lib/http_aws_sigv4.c:827` declares `char date[9]` and `:981-982` fills it
/// with `memcpy(date, timestamp, sizeof(date))` followed by
/// `date[sizeof(date) - 1] = 0` -- so it is the first EIGHT bytes of the
/// timestamp, with the ninth byte overwritten by the terminator.
const DATE_LEN: usize = 8;

/// `SHA256_HEX_LENGTH` (`lib/http_aws_sigv4.c:56`): `2 * 32 + 1` = 65.
///
/// The C's comment is "hex-encoded with trailing null". Nothing here needs
/// the buffer -- [`hexencode`] returns an owned value -- so this exists to
/// pin the width the C fixes and to document why 16 bytes of
/// [`S3_UNSIGNED_PAYLOAD`] fit in the same array (`:632` asserts `16 < 65`).
pub(crate) const SHA256_HEX_LENGTH: usize = 2 * DIGEST_LEN + 1;

/// `MAX_QUERY_COMPONENTS` (`lib/http_aws_sigv4.c:58`): 128.
pub(crate) const MAX_QUERY_COMPONENTS: usize = 128;

/// `MAX_SIGV4_LEN` (`lib/http_aws_sigv4.c:284`): 64 bytes per component.
pub(crate) const MAX_SIGV4_LEN: usize = 64;

/// `DATE_HDR_KEY_LEN` (`lib/http_aws_sigv4.c:285`):
/// `MAX_SIGV4_LEN + sizeof("X--Date")`.
pub(crate) const DATE_HDR_KEY_LEN: usize = MAX_SIGV4_LEN + "X--Date".len() + 1;

/// `DATE_FULL_HDR_LEN` (`lib/http_aws_sigv4.c:288`), whose C comment reads
/// "string been x-PROVIDER-date:TIMESTAMP, I need +1 for ':'".
pub(crate) const DATE_FULL_HDR_LEN: usize =
    DATE_HDR_KEY_LEN + TIMESTAMP_SIZE + 1;

/// `CONTENT_SHA256_KEY_LEN` (`lib/http_aws_sigv4.c:550`):
/// `MAX_SIGV4_LEN + sizeof("X--Content-Sha256")`.
pub(crate) const CONTENT_SHA256_KEY_LEN: usize =
    MAX_SIGV4_LEN + "X--Content-Sha256".len() + 1;

/// `CONTENT_SHA256_HDR_LEN` (`lib/http_aws_sigv4.c:552`), whose C comment
/// reads "add 2 for `: ` between header name and value".
///
/// That colon-and-space is the difference between this header and the
/// canonical date header, which carries no space at all. Both spellings are
/// wire bytes; see [`calc_s3_payload_hash`] and [`canonical_date_header`].
pub(crate) const CONTENT_SHA256_HDR_LEN: usize =
    CONTENT_SHA256_KEY_LEN + 2 + SHA256_HEX_LENGTH;

/// `S3_UNSIGNED_PAYLOAD` (`lib/http_aws_sigv4.c:607`).
///
/// S3 accepts this literal where a payload hash would otherwise go, for a
/// request whose body curl cannot hash without reading it.
pub(crate) const S3_UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The default option value, `lib/http_aws_sigv4.c:875`.
///
/// The C's own explanation, at `:866-872`: "Google and Outscale use the same
/// OSC or GOOG, but Amazon uses AWS and AMZ for header arguments. AWS is the
/// default because most of non-amazon providers are still using aws:amz as a
/// prefix."
const DEFAULT_SIGV4: &[u8] = b"aws:amz";

/// `CURL_MAX_HTTP_HEADER` (`include/curl/curl.h:272`): `100 * 1024`.
///
/// The ceiling the C gives all four canonicalization buffers (`:861-864`) and
/// the merge buffer (`:339`). Defined here rather than imported because no
/// module in this crate owns it yet; when one does, this constant moves there
/// rather than being duplicated.
const CURL_MAX_HTTP_HEADER: usize = 100 * 1024;

/// What curl's own `printf` writes for a null `%s` argument.
///
/// `lib/mprintf.c:837` declares `static const char nilstr[] = "(nil)"` and
/// `:851-856` substitutes it whenever a `%s` argument is null. That is not a
/// curiosity here: `curlx_dyn_ptr()` returns null for a dynbuf that has never
/// been appended to, and `lib/http_aws_sigv4.c:995-1008` passes three such
/// pointers to `curl_maprintf()` WITHOUT a null guard -- only the canonical
/// query gets one, written `?: ""`. So an empty canonical-headers block, an
/// empty signed-headers list or an empty query-component key really does
/// reach the signature as these five bytes. See [`dyn_or_nil`].
const NIL_STRING: &[u8] = b"(nil)";

/// The environment variable that pins the signing clock to the Unix epoch, in a
/// debug build.
///
/// `lib/http_aws_sigv4.c:947-957` reads it through `getenv()` and, when it is
/// set to anything at all, signs as though the time were zero -- **inside
/// `#ifdef DEBUGBUILD`**. See [`signing_epoch_secs`] for why that guard is
/// reproduced here and why doing so costs no fixture.
///
/// The `test` arm of the gate exists because `cargo test --release` turns
/// `debug_assertions` off while still compiling the test module, and a test
/// asserts this name is spelled exactly as the C spells it.
#[cfg(any(debug_assertions, test))]
const FORCETIME_ENV: &str = "CURL_FORCETIME";

// Value contracts, evaluated during compilation.
const _: () = assert!(TIMESTAMP_SIZE == 17);
const _: () = assert!(TIMESTAMP_LEN == 16);
const _: () = assert!(DATE_LEN == 8);
const _: () = assert!(SHA256_HEX_LENGTH == 65);
const _: () = assert!(MAX_QUERY_COMPONENTS == 128);
const _: () = assert!(MAX_SIGV4_LEN == 64);
const _: () = assert!(DATE_HDR_KEY_LEN == 72);
const _: () = assert!(DATE_FULL_HDR_LEN == 90);
const _: () = assert!(CONTENT_SHA256_KEY_LEN == 82);
const _: () = assert!(CONTENT_SHA256_HDR_LEN == 149);
const _: () = assert!(S3_UNSIGNED_PAYLOAD.len() == 16);
const _: () = assert!(S3_UNSIGNED_PAYLOAD.len() < SHA256_HEX_LENGTH);
const _: () = assert!(CURL_MAX_HTTP_HEADER == 102_400);

// The request description: what `Curl_output_aws_sigv4()` reads out of the
// easy handle, gathered into one argument.

/// Everything this signature covers.
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) struct SigV4Request<'a> {
    /// `data->set.str[STRING_AWS_SIGV4]`: the option value, in the form
    /// `provider0[:provider1[:region[:service]]]`.
    ///
    /// [`None`] and an empty value are the same thing to the C
    /// (`if(!line || !*line)` at `:874`) and both select
    /// [`DEFAULT_SIGV4`].
    pub(crate) sigv4: Option<&'a [u8]>,

    /// `data->set.path_as_is`, from `--path-as-is`.
    ///
    /// Signing cannot proceed with it: see [`sign`]'s first precondition.
    pub(crate) path_as_is: bool,

    /// `data->set.headers`: the application's own header list, as
    /// `CURLOPT_HTTPHEADER` received it and in that order.
    ///
    /// Order matters twice. `Curl_checkheaders()` returns the FIRST match
    /// (`lib/transfer.c:92-96`), and the canonicalization sort is stable, so
    /// two headers of the same name are comma-joined in the order the
    /// application supplied them.
    pub(crate) headers: &'a [&'a [u8]],

    /// `data->state.aptr.host`: the whole `Host:` header line curl built,
    /// terminator included -- `"Host: example.com:8080\r\n"`.
    pub(crate) host_header: Option<&'a [u8]>,

    /// `conn->host.name`: the hostname alone, without a port.
    ///
    /// Used for the fallback host entry and, when the option string named
    /// neither, to derive the service and the region.
    pub(crate) hostname: &'a [u8],

    /// `data->state.up.path`: the request path, always at least `/`.
    pub(crate) path: &'a [u8],

    /// `data->state.up.query`: the query string WITHOUT its `?`, or [`None`].
    pub(crate) query: Option<&'a [u8]>,

    /// The method token `Curl_http_method()` selected -- `"GET"`, `"POST"`,
    /// `"PUT"` and so on (`lib/http.c:1940-1966`).
    pub(crate) method: &'a [u8],

    /// `httpreq == HTTPREQ_GET || httpreq == HTTPREQ_HEAD` -- the C's
    /// `empty_method` at `:616`.
    ///
    /// Carried as a predicate rather than as a copy of `Curl_HttpReq`, which
    /// belongs to the transfer layer; `super::AuthActInput::is_get_or_head`
    /// makes the same choice for the same reason.
    pub(crate) is_get_or_head: bool,

    /// `httpreq == HTTPREQ_POST` -- half of the C's `post_payload` at `:620`.
    ///
    /// Strictly `HTTPREQ_POST`. `HTTPREQ_POST_FORM` and `HTTPREQ_POST_MIME`
    /// are separate enumerators and the C does not test for them here, so a
    /// multipart upload takes the `UNSIGNED-PAYLOAD` path.
    pub(crate) is_post: bool,

    /// `data->set.postfields`: the request body when it is already in memory.
    pub(crate) postfields: Option<&'a [u8]>,

    /// `data->set.postfieldsize`, a `curl_off_t`. Negative means "measure it
    /// with `strlen`" (`:595-598`).
    pub(crate) postfieldsize: i64,

    /// `data->set.filesize`, a `curl_off_t`. Zero means there is no body;
    /// `-1` means the size is unknown.
    pub(crate) filesize: i64,

    /// `data->state.aptr.user` and `data->state.aptr.passwd`.
    ///
    /// The username is public -- it goes into `Credential=` on the wire and
    /// into curl's own `--verbose` diagnostic -- while the password is the
    /// signing secret and is never printed. [`Credentials`] enforces the
    /// difference in its own [`fmt::Debug`].
    pub(crate) credentials: &'a Credentials,
}

impl fmt::Debug for SigV4Request<'_> {
    /// Hand-written so that the byte fields read as text instead of as lists
    /// of integers, and so that the two fields which can carry a credential
    /// are rendered through a redaction adaptor rather than verbatim.
    ///
    /// # What is withheld, and why the previous claim was wrong
    ///
    /// This formatter used to state that "nothing printed here is a secret",
    /// on the grounds that every field goes on the wire. Going on the wire is
    /// not the test. A `--trace` log, a panic message and a bug report all
    /// outlive the request and travel further than it does, and two of these
    /// fields carry material that authenticates one:
    ///
    /// * `headers` is `CURLOPT_HTTPHEADER` as the application supplied it, so
    ///   it can contain any header at all -- including `Authorization`,
    ///   `Cookie` and `X-Amz-Security-Token`, every one of which this crate's
    ///   own [`crate::util::redact::is_sensitive_header`] classifies as a
    ///   credential. Each line is now classified by that same
    ///   [`crate::util::redact::is_sensitive_header`], and a named value is
    ///   replaced by [`crate::util::redact::Redacted`].
    /// * `query` can be a presigned URL's query string, whose
    ///   `X-Amz-Signature` is an HMAC over the signing key. Each parameter's
    ///   value is now classified by the same predicate, extended with
    ///   `X-Amz-Signature`.
    ///
    /// Everything else is printed as before. `hostname`, `path`, `method` and
    /// the three size fields disclose nothing, and [`Credentials`]'s own
    /// formatter already prints [`REDACTED_PLACEHOLDER`] in place of the
    /// password -- which is why this delegates to it rather than reaching for
    /// its fields.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Whether a name -- of a header field or of a query parameter --
        // introduces a value that authenticates the request. The shared
        // classifier makes the judgement for everything it knows, so
        // `Authorization`, `Cookie` and `X-Amz-Security-Token` are covered by
        // the same list `crate::headers` and `redacted_canonical_request` use.
        //
        // `X-Amz-Signature` is the one addition, and it earns its place: it is
        // the HMAC over the signing key, so possession of it is possession of an
        // authenticated request for as long as the presigned URL carrying it is
        // valid. It is a query parameter and never a header field, which is why
        // it is not in the shared header list. Spelled here, inside the only
        // code that uses it, rather than as a module constant -- a `const` whose
        // sole reference is inside this impl reads as unreferenced to rustc,
        // measured, and an allowance to silence that would be an allowance
        // hiding nothing.
        //
        // `X-Amz-Credential` is deliberately NOT sensitive. Its leading
        // component is the access key ID, which is the username: this crate
        // already treats it as public, `Credentials`'s own formatter prints it in
        // the clear, and it is emitted on the wire in `Credential=`. Redacting it
        // here while printing it three fields further down would mislead a
        // reader into thinking one of the two disclosed a secret.
        let sensitive = |name: &[u8]| {
            is_sensitive_header(name)
                || name.eq_ignore_ascii_case(b"x-amz-signature")
        };

        // One header line -- `b"Name: value"` -- with the name recovered so the
        // shared classifier can judge the value. The split is the first `:`,
        // which is what `redacted_canonical_request` does over the same data and
        // what `Curl_checkheaders` does on the wire side. A line with no `:` is
        // the `-H "Name;"` form, which carries no value to disclose, so it is
        // rendered whole.
        //
        // The redaction is `redact::Redacted`, the shared adaptor, rather than
        // `redact::HeaderValue`. Both make the same decision from the same list;
        // the difference is the shape, and here the shape matters. `HeaderValue`
        // renders a NON-sensitive value as `Debug` of a string, which is correct
        // for a field of its own -- it is used that way by `crate::headers` --
        // but inside a reconstructed line it would quote the value and move the
        // separator's space inside the quotes, turning `X-Amz-Meta: value` into
        // `X-Amz-Meta:" value"`. A line that discloses nothing is therefore left
        // exactly as the application wrote it, and only a value the classifier
        // names is replaced.
        let headers: Vec<String> = self
            .headers
            .iter()
            .map(|line| match line.iter().position(|byte| *byte == b':') {
                Some(at) if is_sensitive_header(&line[..at]) => {
                    let (name, rest) = line.split_at(at);
                    let value = rest.get(1..).unwrap_or_default();
                    format!(
                        "{}:{:?}",
                        String::from_utf8_lossy(name),
                        Redacted(value)
                    )
                }
                _ => String::from_utf8_lossy(line).into_owned(),
            })
            .collect();

        // The query string, `&`-separated and then split on the first `=`. That
        // is the shape AWS query signing composes and the shape a presigned URL
        // arrives in. A parameter with no `=` has no value to disclose, and one
        // whose name matches nothing is kept, because a query string is most of
        // what makes a signing trace useful.
        let query = self.query.map(|query| {
            let mut out = String::new();
            for (index, pair) in query.split(|byte| *byte == b'&').enumerate() {
                if index != 0 {
                    out.push('&');
                }
                match pair.iter().position(|byte| *byte == b'=') {
                    Some(at) => {
                        let (name, rest) = pair.split_at(at);
                        let value = rest.get(1..).unwrap_or_default();
                        out.push_str(&String::from_utf8_lossy(name));
                        out.push('=');
                        if sensitive(name) {
                            out.push_str(&format!("{:?}", Redacted(value)));
                        } else {
                            out.push_str(&String::from_utf8_lossy(value));
                        }
                    }
                    None => out.push_str(&String::from_utf8_lossy(pair)),
                }
            }
            out
        });

        f.debug_struct("SigV4Request")
            .field("sigv4", &self.sigv4.map(String::from_utf8_lossy))
            .field("path_as_is", &self.path_as_is)
            .field("headers", &headers)
            .field(
                "host_header",
                &self.host_header.map(String::from_utf8_lossy),
            )
            .field("hostname", &String::from_utf8_lossy(self.hostname))
            .field("path", &String::from_utf8_lossy(self.path))
            .field("query", &query)
            .field("method", &String::from_utf8_lossy(self.method))
            .field("is_get_or_head", &self.is_get_or_head)
            .field("is_post", &self.is_post)
            .field("postfields", &self.postfields.map(<[u8]>::len))
            .field("postfieldsize", &self.postfieldsize)
            .field("filesize", &self.filesize)
            .field("credentials", self.credentials)
            .finish()
    }
}

/// The four components the option string and the hostname yield.
///
/// Borrowed rather than owned: every one is a span of either the option value
/// or the hostname, exactly as C's `struct Curl_str` is.
#[derive(Clone, Copy, Eq, PartialEq)]
struct Parameters<'a> {
    /// `provider0`: the credential and algorithm prefix. `aws` yields
    /// `AWS4-HMAC-SHA256`, `AWS4<secret>` and `aws4_request`.
    provider0: &'a [u8],
    /// `provider1`: the header prefix. `amz` yields `X-Amz-Date` and
    /// `x-amz-content-sha256`.
    provider1: &'a [u8],
    /// The region, empty when neither the option nor the hostname supplied
    /// one.
    region: &'a [u8],
    /// The service, empty only until the hostname derivation has run -- which
    /// either fills it or fails.
    service: &'a [u8],
}

impl fmt::Debug for Parameters<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parameters")
            .field("provider0", &String::from_utf8_lossy(self.provider0))
            .field("provider1", &String::from_utf8_lossy(self.provider1))
            .field("region", &String::from_utf8_lossy(self.region))
            .field("service", &String::from_utf8_lossy(self.service))
            .finish()
    }
}

/// `AWS4` followed by the password: the root of the signing-key chain.
struct SigningSecret(Vec<u8>);

impl SigningSecret {
    /// Builds `PROVIDER04<password>`, with `provider0` upper-cased.
    ///
    /// The C upper-cases *after* formatting, "so that the buffer can be
    /// written to" (`:1068`, on the sibling `request_type`); folding on the
    /// way in reaches the same bytes.
    fn new(provider0: &[u8], password: Option<&[u8]>) -> Self {
        let mut material: Vec<u8> =
            provider0.iter().copied().map(raw_toupper).collect();
        material.push(b'4');
        if let Some(password) = password {
            // `data->state.aptr.passwd ? data->state.aptr.passwd : ""`, and
            // the C takes its length with `strlen()` at `:1071`.
            material.extend_from_slice(until_nul(password));
        }
        Self(material)
    }

    /// The bytes to use as the first HMAC key.
    fn key_material(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SigningSecret {
    /// Prints a placeholder. Never the material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SigningSecret")
            .field(&REDACTED_PLACEHOLDER)
            .finish()
    }
}

/// One link of the signing-key chain: a 32-byte keyed digest.
///
/// The four intermediate values ARE the signing key, so they are wrapped for
/// the same reason [`SigningSecret`] is. The fifth value is the signature,
/// which curl does print -- through [`hexencode`] at the one call site that
/// is meant to, never through this formatter.
#[derive(Clone, Copy)]
struct SigningKey([u8; DIGEST_LEN]);

impl SigningKey {
    /// The digest bytes, for use as the next HMAC key or for hex encoding.
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SigningKey {
    /// Prints a placeholder. Never the digest.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SigningKey")
            .field(&REDACTED_PLACEHOLDER)
            .finish()
    }
}

// Small shared helpers.

/// The C-string view of `bytes`: everything before the first zero byte.
fn until_nul(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        Some(at) => &bytes[..at],
        None => bytes,
    }
}

/// A buffer's contents, or [`NIL_STRING`] when it is empty.
fn dyn_or_nil(buffer: &DynBuf) -> &[u8] {
    if buffer.is_empty() {
        NIL_STRING
    } else {
        buffer.as_slice()
    }
}

/// `sha256_to_hex` (`lib/http_aws_sigv4.c:65-69`): a digest as LOWER-case
/// hexadecimal.
///
/// The C calls `Curl_hexencode`, documented at `lib/escape.c:197` as
/// "lowercase hex-encoded ASCII output" and indexing `Curl_ldigits`. Its
/// neighbour `Curl_hexbyte` is the UPPER-case one and is wanted only by
/// [`uri_encode_path`] and [`normalize_query`]; the two must not be unified,
/// because a single folded digit changes the signature.
fn sha256_to_hex(digest: &[u8]) -> String {
    hexencode(digest)
}

/// One percent-escape, UPPER-case: the C's `"%%%02X"`.
///
/// `lib/http_aws_sigv4.c:217` and `:260`. This is the only upper-case
/// hexadecimal in the whole file.
fn hexpercent(byte: u8) -> [u8; 3] {
    let digits = hexbyte(byte);
    [b'%', digits[0], digits[1]]
}

/// `is_reserved_char` (`lib/http_aws_sigv4.c:199-202`):
/// `ISALNUM(c) || ISURLPUNTCS(c)`.
fn is_reserved_char(byte: u8) -> bool {
    is_alnum(byte) || is_urlpunct(byte)
}

/// `Curl_checkheaders` (`lib/transfer.c:84-99`): the application's own header
/// line with this name, if it supplied one.
fn checkheaders<'a>(headers: &[&'a [u8]], name: &[u8]) -> Option<&'a [u8]> {
    debug_assert!(!name.is_empty(), "the C asserts a non-zero name length");
    debug_assert!(
        name.last() != Some(&b':'),
        "the C asserts the name carries no trailing colon"
    );
    headers.iter().copied().map(until_nul).find(|line| {
        ncasecompare(line, name, name.len())
            && line
                .get(name.len())
                .is_some_and(|&sep| sep == b':' || sep == b';')
    })
}

/// `find_date_hdr` (`lib/http_aws_sigv4.c:71-78`): the provider's own date
/// header, or failing that a plain `Date`.
///
/// The order is not interchangeable. An application that supplies both gets
/// its `X-Amz-Date` honoured and its `Date` ignored.
fn find_date_hdr<'a>(headers: &[&'a [u8]], sig_hdr: &[u8]) -> Option<&'a [u8]> {
    checkheaders(headers, sig_hdr).or_else(|| checkheaders(headers, b"Date"))
}

// The path and the query. `lib/http_aws_sigv4.c:199-281` and `:683-812`.

/// `uri_encode_path` (`lib/http_aws_sigv4.c:204-223`).
fn uri_encode_path(path: &[u8], out: &mut DynBuf) -> Result<(), CURLcode> {
    for &byte in path {
        // "Do not encode slashes or unreserved chars from RFC 3986" (`:211`).
        if is_reserved_char(byte) || byte == b'/' {
            out.addn(&[byte])?;
        } else {
            out.addn(&hexpercent(byte))?;
        }
    }
    Ok(())
}

/// `normalize_query` (`lib/http_aws_sigv4.c:228-264`), whose C comment is the
/// specification: "Make sure %2B is left percent encoded, and not decoded to
/// plus, then encoded to space."
///
/// Four outcomes per byte, and every one of them is a wire byte:
///
/// * a valid `%XX` triplet is decoded, and then treated exactly as a literal
///   byte would be -- EXCEPT that a decoded `+` is re-emitted as the literal
///   `%2B` rather than falling through to the `%20` rule below;
/// * an unreserved byte passes through unchanged;
/// * a literal `+` becomes `%20`, the C's comment being "Encode '+' as space";
/// * anything else becomes `%XX` in UPPER-case hexadecimal.
fn normalize_query(source: &[u8], out: &mut DynBuf) -> Result<(), CURLcode> {
    let mut rest = source;

    while let Some(&first) = rest.first() {
        // `('%' == in) && (len > 2) && ISXDIGIT(string[1]) &&
        //  ISXDIGIT(string[2])` -- note that the C's `len > 2` admits a
        // triplet that ends the string exactly.
        let escape = first == b'%'
            && rest.len() > 2
            && is_xdigit(rest[1])
            && is_xdigit(rest[2]);

        let byte = if escape {
            // `(curlx_hexval(string[1]) << 4) | curlx_hexval(string[2])`.
            // Both digits satisfied `is_xdigit`, so `hexval` answers `Some`
            // for both; the fallbacks are unreachable and exist because this
            // crate admits no panicking accessor.
            let high = hexval(rest[1]).unwrap_or(0);
            let low = hexval(rest[2]).unwrap_or(0);
            let decoded = (high << 4) | low;
            rest = &rest[3..];
            if decoded == b'+' {
                // "decodes to plus, so leave this encoded" (`:243`).
                out.addn(b"%2B")?;
                continue;
            }
            decoded
        } else {
            rest = &rest[1..];
            first
        };

        if is_reserved_char(byte) {
            out.addn(&[byte])?;
        } else if byte == b'+' {
            out.addn(b"%20")?;
        } else {
            out.addn(&hexpercent(byte))?;
        }
    }

    Ok(())
}

/// `should_urlencode` (`lib/http_aws_sigv4.c:266-281`): whether the path is
/// re-encoded for this service.
///
/// The comparison is `curlx_str_cmp`, which is **case-SENSITIVE**. That is
/// worth stating because the sibling test that selects the S3 payload rule --
/// `curlx_str_casecompare(&service, "s3")` at `:931` -- is case-INSENSITIVE,
/// so `--aws-sigv4 aws:amz:us-east-1:S3` signs as S3 while still re-encoding
/// its path. The asymmetry is reproduced, not resolved.
#[rustfmt::skip]
fn should_urlencode(service: &[u8]) -> bool {
    !(str_cmp(service, b"s3")
        || str_cmp(service, b"s3-express")
        || str_cmp(service, b"s3-outposts"))
}

/// `canon_path` (`lib/http_aws_sigv4.c:683-707`).
///
/// Either re-encodes the path or copies it verbatim, and then substitutes `/`
/// for an empty result.
fn canon_path(
    path: &[u8],
    do_uri_encode: bool,
    out: &mut DynBuf,
) -> Result<(), CURLcode> {
    if do_uri_encode {
        uri_encode_path(path, out)?;
    } else {
        out.addn(path)?;
    }
    if out.is_empty() {
        out.addn(b"/")?;
    }
    Ok(())
}

/// `split_to_dyn_array` (`lib/http_aws_sigv4.c:150-197`): the query split on
/// `&`, with empty components dropped.
///
/// # Errors
///
/// `CURLcode::TooLarge` once the count REACHES [`MAX_QUERY_COMPONENTS`]. The
/// C's test is `if(++num_splits == MAX_QUERY_COMPONENTS)`, run after each
/// component is stored, so 127 components succeed and the 128th fails. The
/// off-by-one is deliberate on the C's part -- the backing array has 128 slots
/// and the check keeps the next index in range -- and it is reproduced rather
/// than rounded up.
fn split_query(source: &[u8]) -> Result<Vec<&[u8]>, CURLcode> {
    // `#define SPLIT_BY '&'` (`:148`).
    let mut components = Vec::new();
    for component in source.split(|&byte| byte == b'&') {
        // `if(segment_length)` -- an empty run between two separators, or a
        // leading or trailing one, contributes nothing.
        if component.is_empty() {
            continue;
        }
        components.push(component);
        if components.len() == MAX_QUERY_COMPONENTS {
            return Err(CURLcode::TooLarge);
        }
    }
    Ok(components)
}

/// `compare_func` (`lib/http_aws_sigv4.c:646-681`): orders two encoded query
/// components by key and then by value.
fn compare_query_pairs(
    left: &(Vec<u8>, Vec<u8>),
    right: &(Vec<u8>, Vec<u8>),
) -> Ordering {
    let (left_key, left_value) = left;
    let (right_key, right_value) = right;

    // Compare keys.
    if left_key.is_empty() && right_key.is_empty() {
        return Ordering::Equal;
    }
    if left_key.is_empty() {
        return Ordering::Less;
    }
    if right_key.is_empty() {
        return Ordering::Greater;
    }
    let keys = left_key.cmp(right_key);
    if keys != Ordering::Equal {
        return keys;
    }

    // Compare values.
    if left_value.is_empty() && right_value.is_empty() {
        return Ordering::Equal;
    }
    if left_value.is_empty() {
        return Ordering::Less;
    }
    if right_value.is_empty() {
        return Ordering::Greater;
    }
    left_value.cmp(right_value)
}

/// `canon_query` (`lib/http_aws_sigv4.c:709-812`): the canonical query
/// string.
///
/// # A stable sort where the C uses `qsort`
///
/// `qsort` is not stable, and [`compare_query_pairs`] can return `Equal` for
/// two DIFFERENT components: two whose keys are both empty. The C's output is
/// then unspecified. A stable sort makes it the input order, which is one of
/// the orders `qsort` may produce and is the only one that is reproducible.
/// Performance is a non-goal, so nothing is lost by choosing it.
fn canon_query(query: Option<&[u8]>, out: &mut DynBuf) -> Result<(), CURLcode> {
    // `if(!query) return result;` (`:719-720`) -- an absent query is not an
    // empty one, and neither is an error.
    let Some(query) = query else {
        return Ok(());
    };
    let query = until_nul(query);

    let components = split_query(query)?;
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> =
        Vec::with_capacity(components.len());

    for component in components {
        // The C sizes each buffer at `query_part_len * 3 + 1`, which is the
        // worst case of percent-escaping every byte plus its terminator. The
        // ceiling is therefore never reached, and it is carried here so that
        // the failure mode is identical if that ever stops being true.
        let ceiling = component.len().saturating_mul(3).saturating_add(1);
        let mut key = DynBuf::new(ceiling);
        let mut value = DynBuf::new(ceiling);

        // `offset = strchr(query_part, '=')` -- the FIRST `=`. Everything
        // after it, including any further `=`, is the value.
        let equals = component.iter().position(|&byte| byte == b'=');
        let key_len = equals.unwrap_or(component.len());
        normalize_query(&component[..key_len], &mut key)?;

        // `if(offset && offset != (query_part + query_part_len - 1))`: a
        // trailing `=` leaves no value, and neither does an absent one.
        match equals {
            Some(at) if at + 1 < component.len() => {
                normalize_query(&component[at + 1..], &mut value)?;
            }
            _ => {
                // "If there is no value, the value is an empty string"
                // (`:771`).
            }
        }

        pairs.push((key.take(), value.take()));
    }

    // `qsort(&encoded_query_array, num_query_components, ...)` -- see the
    // note above on stability.
    pairs.sort_by(compare_query_pairs);

    for (index, (key, value)) in pairs.iter().enumerate() {
        if index != 0 {
            out.addn(b"&")?;
        }
        // A null `%s` prints `(nil)`; see [`NIL_STRING`]. The C reaches this
        // for a component such as `=x`, whose key normalizes to nothing.
        let key_bytes: &[u8] = if key.is_empty() { NIL_STRING } else { key };
        out.addn(key_bytes)?;
        // "Empty value is always encoded to key=" (`:798`). Both of the C's
        // branches emit the `=`; only the value differs.
        out.addn(b"=")?;
        if !value.is_empty() {
            out.addn(value)?;
        }
    }

    Ok(())
}

// Header canonicalization. `lib/http_aws_sigv4.c:80-116`, `:292-370` and
// `:373-548`.

/// `trim_headers` (`lib/http_aws_sigv4.c:80-116`), applied to one entry.
///
/// Three effects, in the C's order:
///
/// 1. The NAME is lower-cased -- the bytes before the first colon, and only
///    those. `Curl_strntolower(l->data, l->data, colon)` at `:88`.
/// 2. An entry with no colon at all is left alone beyond that fold: `value`
///    points at the terminator and the C's `if(!*value) continue` skips the
///    rewrite (`:90-92`).
/// 3. The VALUE is rewritten in place: leading blanks are dropped, and every
///    run of blanks thereafter collapses to a SINGLE space -- except a
///    trailing run, which is dropped entirely. The C's own comment is
///    "replace any number of consecutive whitespace with a single space,
///    unless at the end of the string, then nothing" (`:106-107`).
fn trim_header(entry: &mut Vec<u8>) {
    // `size_t colon = strcspn(l->data, ":")`.
    let colon = entry
        .iter()
        .position(|&byte| byte == b':')
        .unwrap_or(entry.len());

    for byte in &mut entry[..colon] {
        *byte = raw_tolower(*byte);
    }

    // `value = &l->data[colon]; if(!*value) continue;` -- there is no colon,
    // so there is no value to rewrite.
    if colon >= entry.len() {
        return;
    }

    // `++value; store = value;` -- both start just past the colon, so the
    // rewrite can only ever shrink the entry.
    let mut read = colon + 1;
    let mut write = colon + 1;

    // `curlx_str_passblanks(&value)`.
    while read < entry.len() && is_blank(entry[read]) {
        read += 1;
    }

    while read < entry.len() {
        let mut space = false;
        while read < entry.len() && is_blank(entry[read]) {
            read += 1;
            space = true;
        }
        if space {
            // The blank run is replaced by one space ONLY when something
            // follows it; a run at the end contributes nothing. The byte that
            // follows is deliberately not consumed here -- the next iteration
            // copies it, exactly as the C's loop does.
            if read < entry.len() {
                entry[write] = b' ';
                write += 1;
            }
        } else {
            entry[write] = entry[read];
            write += 1;
            read += 1;
        }
    }

    // `*store = 0` -- the C terminates in place, which for an owned buffer is
    // a truncation.
    entry.truncate(write);
}

/// The bytes of an entry that form its name: everything before the first
/// colon.
///
/// `colon_a ? (size_t)(colon_a - a) : strlen(a)`
/// (`lib/http_aws_sigv4.c:307`).
fn header_name(entry: &[u8]) -> &[u8] {
    let end = entry
        .iter()
        .position(|&byte| byte == b':')
        .unwrap_or(entry.len());
    &entry[..end]
}

/// `compare_header_names` (`lib/http_aws_sigv4.c:292-319`): the canonical
/// header order.
///
/// The C's description is "alpha-sort by header name in a case sensitive
/// manner", and the implementation has two properties that a plain string
/// comparison does not:
///
/// * Only the bytes BEFORE the colon take part. Two headers whose names match
///   compare equal however different their values are, which is what lets
///   [`merge_duplicate_headers`] find them as neighbours.
/// * `strncmp` runs over `min(len_a, len_b)` bytes and, on a tie, the C
///   returns `(int)(len_a - len_b)` -- so the SHORTER name sorts first.
///   `x-amz-meta-test` therefore precedes `x-amz-meta-test-two`, which
///   `tests/data/test1976` pins in its `SignedHeaders`.
fn compare_header_names(left: &[u8], right: &[u8]) -> Ordering {
    let left_name = header_name(left);
    let right_name = header_name(right);
    let shared = left_name.len().min(right_name.len());

    match left_name[..shared].cmp(&right_name[..shared]) {
        // `if(!cmp) return (int)(len_a - len_b);` -- only the sign is read, so
        // an ordering carries the same information as the difference does.
        Ordering::Equal => left_name.len().cmp(&right_name.len()),
        other => other,
    }
}

/// `merge_duplicate_headers` (`lib/http_aws_sigv4.c:324-370`).
///
/// **The preceding sort must be stable for this to be correct.** The order
/// the values are joined in is the order they arrive in, and the C's sort is a
/// bubble sort that swaps only on a strict `> 0` -- stable by construction. A
/// Rust `sort_unstable_by` would reorder equal-named entries and change the
/// signature, which is why [`make_headers`] uses `sort_by`.
///
/// # Errors
///
/// Whatever the merge buffer returns -- `CURLcode::TooLarge` past
/// [`CURL_MAX_HTTP_HEADER`].
fn merge_duplicate_headers(head: &mut Vec<Vec<u8>>) -> Result<(), CURLcode> {
    let mut index = 0usize;

    while index + 1 < head.len() {
        if compare_header_names(&head[index], &head[index + 1])
            != Ordering::Equal
        {
            index += 1;
            continue;
        }

        let mut buffer = DynBuf::new(CURL_MAX_HTTP_HEADER);
        buffer.addn(&head[index])?;
        buffer.addn(b",")?;

        // `colon_next = strchr(next->data, ':'); DEBUGASSERT(colon_next);
        //  val_next = colon_next + 1;` -- the C asserts the colon and would
        // read past a null pointer without one. Every entry that reaches here
        // has a colon, so the empty fallback is the safe reading of a case the
        // C treats as impossible.
        let next = &head[index + 1];
        let value = match next.iter().position(|&byte| byte == b':') {
            Some(at) => &next[at + 1..],
            None => &next[..0],
        };
        buffer.addn(value)?;

        head[index] = buffer.take();
        head.remove(index + 1);
    }

    Ok(())
}

/// The date header's NAME, as it goes on the wire: `X-Amz-Date` for the
/// default provider.
///
/// `lib/http_aws_sigv4.c:391-395` in three steps, and all three are needed to
/// get the capitalisation right:
///
/// ```text
/// curl_msnprintf(date_hdr_key, ..., "X-%.*s-Date", plen, provider1);
/// Curl_strntolower(&date_hdr_key[2], provider1, plen);   /* amz */
/// date_hdr_key[2] = Curl_raw_toupper(provider1[0]);      /* Amz */
/// ```
fn date_header_key(provider1: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(DATE_HDR_KEY_LEN);
    key.extend_from_slice(b"X-");
    key.extend(provider1.iter().copied().map(raw_tolower));
    key.extend_from_slice(b"-Date");

    // The C indexes `provider1[0]` unconditionally; `provider0` and
    // `provider1` are both non-empty by construction, because
    // `curlx_str_until()` rejects a zero-length span
    // (`lib/curlx/strparse.c:54-55`). Written as a conditional because that
    // is the total reading of the same expression.
    if let Some(&first) = provider1.first() {
        key[2] = raw_toupper(first);
    }

    key
}

/// The date header in CANONICAL form: `x-amz-date:19700101T000000Z`.
///
/// `lib/http_aws_sigv4.c:397-400`. Two differences from the wire form
/// [`date_header_key`] produces, and both are signature bytes: the name is
/// entirely lower-case, and there is **no space** after the colon.
fn canonical_date_header(provider1: &[u8], timestamp: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(DATE_FULL_HDR_LEN);
    header.extend_from_slice(b"x-");
    header.extend(provider1.iter().copied().map(raw_tolower));
    header.extend_from_slice(b"-date:");
    header.extend_from_slice(timestamp);
    header
}

/// The date header as it is EMITTED: `X-Amz-Date: 19700101T000000Z\r\n`.
///
/// `curl_maprintf("%s: %s\r\n", date_hdr_key, timestamp)` at `:475`. A space
/// after the colon and a terminator, neither of which the canonical form has.
fn outgoing_date_header(key: &[u8], timestamp: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(key.len() + TIMESTAMP_SIZE + 4);
    header.extend_from_slice(key);
    header.extend_from_slice(b": ");
    header.extend_from_slice(timestamp);
    header.extend_from_slice(b"\r\n");
    header
}

/// `make_headers` (`lib/http_aws_sigv4.c:373-548`): builds the canonical
/// header block and the signed-header list, and decides what date header to
/// emit.
///
/// `timestamp` is in-out, exactly as the C's `char *timestamp` is: when the
/// application supplied its own date header, this either adopts that value or
/// empties the buffer. An emptied timestamp is not an error in the C and is
/// not one here; it propagates into an empty credential-scope date.
///
/// # Errors
///
/// * `CURLcode::TooLarge` from either buffer past [`CURL_MAX_HTTP_HEADER`].
/// * `CURLcode::OutOfMemory` when the date header the application supplied has
///   no colon in it, which happens for a bare `X-Amz-Date;`. That code looks
///   arbitrary and is exactly what the C returns: `ret` is initialised to
///   `CURLE_OUT_OF_MEMORY` at `:387`, is not set to `CURLE_OK` until `:543`,
///   and the missing-colon branch at `:483-486` jumps to `fail` in between.
fn make_headers(
    request: &SigV4Request<'_>,
    provider1: &[u8],
    timestamp: &mut Vec<u8>,
    content_sha256_header: &[u8],
    canonical_headers: &mut DynBuf,
    signed_headers: &mut DynBuf,
) -> Result<Option<Vec<u8>>, CURLcode> {
    let date_hdr_key = date_header_key(provider1);
    let date_full_hdr = canonical_date_header(provider1, timestamp);

    let mut head: Vec<Vec<u8>> = Vec::new();

    // `if(!Curl_checkheaders(data, STRCONST("Host")))` (`:402-419`). When the
    // application supplied its own `Host:` header, no entry is added here --
    // that header comes in through the loop below like any other.
    if checkheaders(request.headers, b"Host").is_none() {
        head.push(match request.host_header {
            Some(line) => {
                // "remove /r/n as the separator for canonical request must be
                // '\n'" -- `strcspn(data->state.aptr.host, "\n\r")`.
                let end = line
                    .iter()
                    .position(|&byte| byte == b'\n' || byte == b'\r')
                    .unwrap_or(line.len());
                line[..end].to_vec()
            }
            None => {
                // `curl_maprintf("host:%s", hostname)`.
                let mut entry = b"host:".to_vec();
                entry.extend_from_slice(until_nul(request.hostname));
                entry
            }
        });
    }

    // `if(*content_sha256_header)` (`:421-426`). The C appends a COPY through
    // `curl_slist_append()`, which is why trimming the copy below does not
    // disturb the `": "` in the header that is emitted.
    if !content_sha256_header.is_empty() {
        head.push(content_sha256_header.to_vec());
    }

    // The application's own headers (`:443-465`). The C's comment explains
    // all three rejections, and they are reproduced verbatim in effect:
    //
    //   "user headers in format 'name:' with no value are used to signal that
    //    an internal header of that name should be removed. those user headers
    //    are not added to this list.
    //
    //    user headers in format 'name;' with no value are used to signal that
    //    a header of that name with no value should be sent. those user
    //    headers are added to this list but in the format that they will be
    //    sent, ie the semi-colon is changed to a colon for format 'name:'.
    for line in request.headers {
        let line = until_nul(line);

        // `sep = strchr(l->data, ':'); if(!sep) sep = strchr(l->data, ';');`
        let separator = line
            .iter()
            .position(|&byte| byte == b':')
            .or_else(|| line.iter().position(|&byte| byte == b';'));

        // `if(!sep || (*sep == ':' && !*(sep + 1))) continue;`
        let Some(at) = separator else {
            continue;
        };
        if line[at] == b':' && at + 1 >= line.len() {
            continue;
        }

        // `for(ptr = sep + 1; ISBLANK(*ptr); ++ptr); if(!*ptr && ptr != sep +
        // 1) continue;` -- a value of blanks only is rejected, while a value
        // that was empty to begin with (the `name;` form) is kept.
        let value = &line[at + 1..];
        let after_blanks = value.iter().take_while(|&&byte| is_blank(byte));
        let blanks = after_blanks.count();
        if blanks == value.len() && !value.is_empty() {
            continue;
        }

        // `dupdata[sep - l->data] = ':'` -- the separator becomes a colon
        // whichever it was.
        let mut entry = line.to_vec();
        entry[at] = b':';
        head.push(entry);
    }

    // `trim_headers(head)` (`:467`).
    for entry in &mut head {
        trim_header(entry);
    }

    // `*date_header = find_date_hdr(data, date_hdr_key)` (`:469-501`).
    let date_header = match find_date_hdr(request.headers, &date_hdr_key) {
        None => {
            // No date header from the application: the canonical form joins
            // the list and the wire form is emitted alongside the
            // authorization line. Appended AFTER the trim, as in the C --
            // which is harmless because the form it is built in is already
            // canonical.
            head.push(date_full_hdr);
            Some(outgoing_date_header(&date_hdr_key, timestamp))
        }
        Some(line) => {
            // The application's own header is already in `head` and will
            // already be in the request, so nothing extra is emitted. All that
            // remains is to sign the timestamp IT carries.
            let Some(at) = line.iter().position(|&byte| byte == b':') else {
                // A bare `name;` matched `Curl_checkheaders` and has no
                // colon. See this function's error section.
                return Err(CURLcode::OutOfMemory);
            };
            let mut value = &line[at + 1..];
            str_passblanks(&mut value);

            // `while(*endp && ISALNUM(*endp)) ++endp;` -- the leading run of
            // alphanumerics, which stops at the `+` of an offset or at a
            // comma in an RFC 1123 date.
            let run = value.iter().take_while(|&&byte| is_alnum(byte)).count();

            // `/* 16 bytes => "19700101T000000Z" */`
            if run == TIMESTAMP_LEN {
                *timestamp = value[..run].to_vec();
            } else {
                // "bad timestamp length" -- the C writes `timestamp[0] = 0`,
                // which leaves an empty string behind rather than an error.
                timestamp.clear();
            }
            None
        }
    };

    // "alpha-sort by header name in a case sensitive manner" (`:503-517`).
    // The C's `do { ... } while(again)` bubble sort is stable; `sort_by` is
    // Rust's stable sort, and [`merge_duplicate_headers`] depends on it.
    head.sort_by(|left, right| compare_header_names(left, right));

    merge_duplicate_headers(&mut head)?;

    // `:523-541`. Each entry contributes its whole `name:value` plus a
    // newline to the canonical block -- so the block ENDS with a newline, and
    // the canonical request's own separator then produces the blank line the
    // specification requires. Each entry also contributes its bare name to
    // the signed-header list, `;`-separated with no trailing separator.
    for (index, entry) in head.iter().enumerate() {
        canonical_headers.addn(entry)?;
        canonical_headers.addn(b"\n")?;

        // `if(l != head)` -- every entry but the first.
        if index != 0 {
            signed_headers.addn(b";")?;
        }
        signed_headers.addn(header_name(entry))?;
    }

    Ok(date_header)
}

// The payload hash. `lib/http_aws_sigv4.c:555-644`.

/// `parse_content_sha_hdr` (`lib/http_aws_sigv4.c:555-585`): the payload hash
/// the application supplied, if it supplied one.
fn parse_content_sha_hdr<'a>(
    headers: &[&'a [u8]],
    provider1: &[u8],
) -> Option<&'a [u8]> {
    let mut key = Vec::with_capacity(CONTENT_SHA256_KEY_LEN);
    key.extend_from_slice(b"x-");
    key.extend_from_slice(provider1);
    key.extend_from_slice(b"-content-sha256");

    let line = checkheaders(headers, &key)?;

    // `value = strchr(value, ':'); if(!value) return NULL;` -- a `;`-form
    // match has no colon and yields no hash, which is not an error.
    let at = line.iter().position(|&byte| byte == b':')?;
    let mut value = &line[at + 1..];
    str_passblanks(&mut value);

    // `while(len > 0 && ISBLANK(value[len - 1])) --len;`
    let mut len = value.len();
    while len > 0 && is_blank(value[len - 1]) {
        len -= 1;
    }
    Some(&value[..len])
}

/// The body bytes to hash: `data->set.postfields` measured the way
/// `calc_payload_hash` measures it (`lib/http_aws_sigv4.c:590-599`).
fn post_data<'a>(request: &SigV4Request<'a>) -> &'a [u8] {
    let Some(body) = request.postfields else {
        return &[];
    };

    if request.postfieldsize < 0 {
        return until_nul(body);
    }

    // The C casts straight to `size_t` and would read past the end if the
    // size exceeded the buffer. Clamping is the total reading of the same
    // expression; the conversion itself cannot fail here, because the negative
    // case has already returned.
    match usize::try_from(request.postfieldsize) {
        Ok(len) => &body[..len.min(body.len())],
        Err(_) => body,
    }
}

/// `calc_payload_hash` (`lib/http_aws_sigv4.c:587-605`): SHA-256 of the body,
/// as lower-case hexadecimal.
fn calc_payload_hash(request: &SigV4Request<'_>) -> String {
    sha256_to_hex(&sha256(post_data(request)))
}

/// `calc_s3_payload_hash` (`lib/http_aws_sigv4.c:609-644`): the payload hash
/// for an S3 request, and the header that has to carry it.
///
/// Three predicates decide, and the C names each of them:
///
/// ```text
/// empty_method  = (httpreq == HTTPREQ_GET || httpreq == HTTPREQ_HEAD);
/// empty_payload = (empty_method || data->set.filesize == 0);
/// post_payload  = (httpreq == HTTPREQ_POST && data->set.postfields);
/// ```
fn calc_s3_payload_hash(
    request: &SigV4Request<'_>,
    provider1: &[u8],
) -> (String, Vec<u8>) {
    let empty_method = request.is_get_or_head;
    let empty_payload = empty_method || request.filesize == 0;
    let post_payload = request.is_post && request.postfields.is_some();

    let sha_hex = if empty_payload || post_payload {
        calc_payload_hash(request)
    } else {
        S3_UNSIGNED_PAYLOAD.to_owned()
    };

    let mut header = Vec::with_capacity(CONTENT_SHA256_HDR_LEN);
    header.extend_from_slice(b"x-");
    header.extend_from_slice(provider1);
    header.extend_from_slice(b"-content-sha256: ");
    header.extend_from_slice(sha_hex.as_bytes());

    (sha_hex, header)
}

// The clock. `lib/http_aws_sigv4.c:947-965`.

/// A copy of the canonical request with credential-bearing header values
/// replaced, for tracing only.
///
/// # Why this exists
///
/// `Curl_output_aws_sigv4` signs whatever headers the application supplied, and
/// `make_headers` (`lib/http_aws_sigv4.c:503-541`) puts every one of them into
/// the canonical block as `name:value`. Two of those values are credentials in
/// their own right:
///
/// * **`x-amz-security-token`** -- an AWS temporary session credential. A
///   caller using STS credentials MUST send it, so this is the common case
///   rather than an edge one, and it is a bearer token: whoever holds it can
///   sign requests until it expires.
/// * **`authorization`, `cookie` and their kin** -- if the caller set one, it
///   is signed and therefore canonicalised.
///
/// The C prints the canonical block verbatim under `--verbose`
/// (`lib/http_aws_sigv4.c:1012`). Reproducing that faithfully would put a live
/// session token into every verbose log, and `--verbose` output is what users
/// paste into bug reports. So the signed bytes stay byte-identical and the
/// TRACE gets this copy.
///
/// # What is replaced, and what is not
///
/// Only a header value, and only when
/// [`crate::util::redact::is_sensitive_header`] classifies its name. The header
/// NAMES are untouched -- they are the signed-header list, which is the thing a
/// reader is usually checking -- and so are the method, the canonical path, the
/// canonical query and the payload hash. The payload hash in particular is a
/// digest and not a secret, and it is the single most useful value in the block
/// when a signature mismatch is being diagnosed.
///
/// # Why this parses rather than re-derives
///
/// The block's grammar is fixed and simple: line 4 of six is the canonical
/// headers, each `name:value`, and the block ends with a newline so the
/// separator that follows produces a blank line. Re-deriving the redacted copy
/// from `head` would mean threading it through, and would risk the two copies
/// diverging in a way that made the trace describe a request that was not
/// signed. Parsing the finished bytes cannot diverge: what is printed is
/// exactly what was signed, minus the values named above.
///
/// A line without a colon is left alone rather than redacted: within the
/// canonical-headers section every line has one by construction, so a line
/// without one is a section boundary (the method, the path, the query, the
/// signed-header list, the payload hash), and redacting those would remove the
/// block's whole diagnostic value.
fn redacted_canonical_request(canonical_request: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(canonical_request.len());

    for (index, line) in
        canonical_request.split(|byte| *byte == b'\n').enumerate()
    {
        if index != 0 {
            out.push(b'\n');
        }

        match line.iter().position(|byte| *byte == b':') {
            Some(at) => {
                let (name, rest) = line.split_at(at);
                if is_sensitive_header(name) {
                    // `rest` still carries the colon; keep exactly it.
                    let value = rest.get(1..).unwrap_or_default();
                    out.extend_from_slice(name);
                    out.push(b':');
                    let _ = write!(
                        DynBufWriter(&mut out),
                        "<{}, {} bytes>",
                        crate::util::redact::MARKER,
                        value.len()
                    );
                } else {
                    out.extend_from_slice(line);
                }
            }
            None => out.extend_from_slice(line),
        }
    }

    out
}

/// A [`fmt::Write`] adaptor over a byte vector, so the redaction marker can be
/// formatted without an intermediate [`String`].
///
/// `write!` needs a [`fmt::Write`] or an [`std::io::Write`], and a `Vec<u8>` is
/// the latter only with `std::io` in scope; this module is otherwise
/// `core`-only in its formatting, so a two-line adaptor is cheaper than the
/// import. Every byte written is ASCII, so the UTF-8 the trait guarantees is
/// preserved trivially.
struct DynBufWriter<'a>(&'a mut Vec<u8>);

impl fmt::Write for DynBufWriter<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0.extend_from_slice(text.as_bytes());
        Ok(())
    }
}

/// Whether [`FORCETIME_ENV`] asks for the epoch -- **debug builds only**.
///
/// The C reads it with `getenv()` and only tests for presence, so any value --
/// including an empty one -- forces the clock. It reads it **inside
/// `#ifdef DEBUGBUILD`**, and this pair of definitions reproduces that guard:
/// `debug_assertions` is this crate's established counterpart of `DEBUGBUILD`
/// (the same mapping `crate::transfer::ratelimit` and `crate::util::fopen`
/// already use for `DEBUGASSERT`), so a production build compiles the
/// environment read out entirely rather than merely ignoring its result.
#[cfg(debug_assertions)]
fn forced_epoch_requested() -> bool {
    env::var_os(FORCETIME_ENV).is_some()
}

/// The release-build counterpart: the environment cannot move the clock.
///
/// Not `env::var_os(..) && cfg!(..)` but a separate definition, so that a
/// release binary contains no read of [`FORCETIME_ENV`] at all. There is
/// nothing for an inherited or hostile environment to reach.
#[cfg(not(debug_assertions))]
fn forced_epoch_requested() -> bool {
    false
}

/// The instant to sign for: zero when the epoch is forced, otherwise the
/// injected clock's wall reading.
///
/// ```text
/// #ifdef DEBUGBUILD
///   { char *force_timestamp = getenv("CURL_FORCETIME");
///     if(force_timestamp) clock = 0; else clock = time(NULL); }
/// #else
///   clock = time(NULL);
/// #endif
/// ```
///
/// **The `#ifdef DEBUGBUILD` guard is reproduced**, by the two definitions of
/// [`forced_epoch_requested`] above. A release build has no read of
/// [`FORCETIME_ENV`] compiled into it at all.
///
/// This function previously honoured the variable unconditionally, on the
/// argument that `tests/runner.pm:167` sets `CURL_FORCETIME=1` for every test
/// run and that AAP 0.6.6 withholds the `Debug` capability from the
/// `--version` banner, so a `DEBUGBUILD`-only seam "would leave the whole
/// corpus unreachable rather than merely skipped".
///
/// **That argument was measured and is wrong.** All sixteen fixtures that
/// exercise SigV4 -- `test439`, `test472`, `test1955` through `test1959`,
/// `test1970` through `test1976`, and the two `unittest` ones -- carry
/// `Debug` (or `unittest`) in their own `<features>` block. `version.rs`
/// reports `Feature { name: "Debug", compiled_in: false }`, so the harness
/// never sets `$feature{"Debug"}` and every one of those fixtures skips
/// already, entirely independently of this variable. Honouring it
/// unconditionally bought no reachability and cost a production override that
/// an inherited or attacker-controlled environment could use to force stale
/// signatures and so deny authentication deterministically.
///
/// Gating it also *restores* parity rather than breaking it: a C curl built
/// without `--enable-debug` does not honour `CURL_FORCETIME` either, which is
/// precisely why those fixtures demand the `Debug` feature. The two conditions
/// line up -- a binary that could legitimately advertise `Debug` is a debug
/// build, and that is exactly when `debug_assertions` is on.
///
/// The `forced` parameter is kept rather than folded in, so the decision and
/// the arithmetic stay separately testable: a test can still assert both arms
/// without touching the process environment.
///
/// `time(NULL)` becomes [`Clock::epoch_secs`] -- injected, never a global.
/// Nothing in this module reads the host clock itself; AAP 0.3.3's P12
/// requires the seam and `crate::util::timeval` refuses to offer a default.
fn signing_epoch_secs(clock: &dyn Clock, forced: bool) -> i64 {
    if forced {
        0
    } else {
        clock.epoch_secs()
    }
}

/// `strftime(timestamp, TIMESTAMP_SIZE, "%Y%m%dT%H%M%SZ", &tm)`
/// (`lib/http_aws_sigv4.c:958-965`).
///
/// # `%Y` is a plain decimal, and that is measured rather than assumed
///
/// The obvious transcription pads the year to four digits. `strftime` does
/// not: `%Y` is the year as a decimal number with no padding at all, so the
/// result is SHORTER than 16 bytes before 1000 CE and longer after 9999.
/// Measured on this host's C library, with the same 17-byte buffer the C
/// passes:
///
/// ```text
///              0  ->  16  19700101T000000Z
///     1440938160  ->  16  20150830T123600Z
///   253402300799  ->  16  99991231T235959Z    (year 9999)
///   253402300800  ->   0  strftime failed     (year 10000)
///   -62135596801  ->  13  01231T235959Z       (year 0, rendered "0")
///   -62167219201  ->  14  -11231T235959Z      (year -1, rendered "-1")
///    -2208988800  ->  16  19000101T000000Z
/// ```
///
/// # Errors
///
/// * Whatever `gmtime` returns -- `CURLcode::BadFunctionArgument` for an
///   instant whose year does not fit the field that carries it. The C
///   propagates `curlx_gmtime`'s code the same way at `:958-961`.
/// * `CURLcode::OutOfMemory` when the result does not fit the C's 17-byte
///   buffer, which is any year needing more than four characters -- so outside
///   `-999..=9999`. `strftime` answers zero in exactly that case, and the C
///   maps zero to this code at `:962-965`.
fn format_timestamp(epoch_secs: i64) -> Result<Vec<u8>, CURLcode> {
    let broken = gmtime(epoch_secs)?;

    let mut stamp = String::with_capacity(TIMESTAMP_LEN);
    // `mon` is 0-based, exactly as C's `tm_mon` is, so `%m` is it plus one.
    let month = broken.mon.saturating_add(1);
    if write!(
        &mut stamp,
        "{}{:02}{:02}T{:02}{:02}{:02}Z",
        broken.year, month, broken.mday, broken.hour, broken.min, broken.sec
    )
    .is_err()
    {
        return Err(CURLcode::OutOfMemory);
    }

    // `if(!strftime(timestamp, sizeof(timestamp), ...)) result =
    // CURLE_OUT_OF_MEMORY;` -- `strftime` writes nothing and answers zero when
    // the result plus its terminator would not fit `TIMESTAMP_SIZE`.
    if stamp.len() > TIMESTAMP_LEN {
        return Err(CURLcode::OutOfMemory);
    }

    Ok(stamp.into_bytes())
}

// Parameter parsing. `lib/http_aws_sigv4.c:866-919`.

/// One `label.` step of the hostname walk.
///
/// `curlx_str_until(&p, &out, MAX_SIGV4_LEN, '.') || curlx_str_single(&p, '.')`
/// -- both must succeed, and the C's `||` means the second is not attempted
/// when the first fails. So a hostname with no dot yields nothing even though
/// its single label is short enough, which is why `localhost` cannot supply a
/// service.
fn next_host_label<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let label = str_until(cursor, MAX_SIGV4_LEN, b'.').ok()?;
    str_single(cursor, b'.').ok()?;
    Some(label)
}

/// The parameter parser (`lib/http_aws_sigv4.c:866-919`).
///
/// Three behaviours here are easy to get wrong and are each reproduced
/// deliberately:
///
/// * **An absent `provider1` becomes `provider0`.** The C writes
///   `provider1 = provider0` when either the separator or the component is
///   missing (`:886-889`), so `--aws-sigv4 aws` signs with `AWS4-HMAC-SHA256`
///   and emits `X-Aws-Date`.
/// * **An over-long region or service is dropped, not rejected.**
///   `curlx_str_until()` fails with `STRE_BIG` and leaves the span empty, and
///   the `||` chain simply stops. Only an empty `provider0` is an error.
/// * **The region derivation is NESTED inside the service derivation.** The
///   `if(!curlx_strlen(&region))` block at `:909` sits inside the
///   `if(!curlx_strlen(&service))` block at `:897`, so the region is derived
///   only when the service was derived too. The nesting is transcribed rather
///   than flattened, so that a reader of the C finds the same shape here.
///
///   What it guards against turns out to be unreachable, and saying so is more
///   useful than implying otherwise: the state where the two forms differ is a
///   named service with no region, and the grammar cannot produce it. The
///   service is the FOURTH component, so reaching it means the third succeeded,
///   and `curlx_str_until()` rejects a zero-length span -- an option string of
///   `aws:amz::s3` aborts the chain at the empty region and leaves BOTH empty
///   rather than leaving a service behind. A test asserts that invariant over
///   every shape of option string.
///
/// # Errors
///
/// * `CURLcode::BadFunctionArgument` for an empty `provider0`, with the
///   verbatim message `first aws-sigv4 provider cannot be empty`.
/// * `CURLcode::UrlMalformat` when the hostname cannot supply a missing
///   service or region, with the two verbatim messages from `:901` and `:912`.
fn parse_parameters<'a>(
    sigv4: Option<&'a [u8]>,
    hostname: &'a [u8],
    tracer: &mut Tracer<'_>,
) -> Result<Parameters<'a>, CURLcode> {
    // `line = data->set.str[STRING_AWS_SIGV4]; if(!line || !*line) line =
    // "aws:amz";`
    let line = match sigv4.map(until_nul) {
        Some(value) if !value.is_empty() => value,
        _ => DEFAULT_SIGV4,
    };

    let mut cursor = line;

    let Ok(provider0) = str_until(&mut cursor, MAX_SIGV4_LEN, b':') else {
        failf!(tracer, "first aws-sigv4 provider cannot be empty");
        return Err(CURLcode::BadFunctionArgument);
    };

    let mut provider1 = provider0;
    let mut region: &[u8] = &[];
    let mut service: &[u8] = &[];

    // `if(curlx_str_single(&line, ':') ||
    //     curlx_str_until(&line, &provider1, MAX_SIGV4_LEN, ':'))
    //    provider1 = provider0;
    //  else if(curlx_str_single(&line, ':') || ... ) { /* nothing to do */ }`
    if str_single(&mut cursor, b':').is_ok() {
        if let Ok(second) = str_until(&mut cursor, MAX_SIGV4_LEN, b':') {
            provider1 = second;
            if str_single(&mut cursor, b':').is_ok() {
                if let Ok(third) = str_until(&mut cursor, MAX_SIGV4_LEN, b':') {
                    region = third;
                    if str_single(&mut cursor, b':').is_ok() {
                        if let Ok(fourth) =
                            str_until(&mut cursor, MAX_SIGV4_LEN, b':')
                        {
                            service = fourth;
                        }
                    }
                }
            }
        }
    }

    if service.is_empty() {
        let mut host = until_nul(hostname);

        let Some(first_label) = next_host_label(&mut host) else {
            failf!(
                tracer,
                "aws-sigv4: service missing in parameters and hostname"
            );
            return Err(CURLcode::UrlMalformat);
        };
        service = first_label;
        infof!(
            tracer,
            "aws_sigv4: picked service {} from host",
            String::from_utf8_lossy(service)
        );

        // NESTED, deliberately. See this function's documentation.
        if region.is_empty() {
            let Some(second_label) = next_host_label(&mut host) else {
                failf!(
                    tracer,
                    "aws-sigv4: region missing in parameters and hostname"
                );
                return Err(CURLcode::UrlMalformat);
            };
            region = second_label;
            infof!(
                tracer,
                "aws_sigv4: picked region {} from host",
                String::from_utf8_lossy(region)
            );
        }
    }

    Ok(Parameters {
        provider0,
        provider1,
        region,
        service,
    })
}

/// `request_type` (`lib/http_aws_sigv4.c:1015-1023`): `aws4_request`.
///
/// The provider is lower-cased. The C's comment records why the fold comes
/// after the formatting: "provider0 is lowercased *after* curl_maprintf() so
/// that the buffer can be written to".
fn request_type(provider0: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = provider0.iter().copied().map(raw_tolower).collect();
    out.extend_from_slice(b"4_request");
    out
}

// The signer. `Curl_output_aws_sigv4()`, `lib/http_aws_sigv4.c:814-1126`.

/// Signs a request with AWS Signature Version 4 and returns the header block
/// to emit.
///
/// # The return type carries C's two side effects
///
/// The C ends by writing `data->state.aptr.userpwd` and setting
/// `data->state.authhost.done = TRUE` (`:1109-1111`). Both arrive in the
/// return value here, and the three-way shape is what keeps them exact:
///
/// * `Ok(Some(AuthEmission::Final(block)))` -- the header block, and
///   `super::finish_emission` sets `done` from
///   [`super::AuthEmission::is_done`], which is `true` for `Final`. That is
///   C's `:1111`.
/// * `Ok(None)` -- the application supplied its own `Authorization:` header,
///   so nothing is emitted AND nothing is recorded. Passing `None` as
///   `super::finish_emission`'s `emission` leaves `done` untouched, which is
///   what the C does: it returns `CURLE_OK` from `:857` without reaching
///   `:1111`, so `done` stays false and `multipass` becomes `!done`. Returning
///   [`super::AuthEmission::Nothing`] instead would set `done` and change
///   that.
/// * `Err(code)` -- one of the four failures below.
///
/// # Errors
///
/// * `CURLcode::BadFunctionArgument` -- `--path-as-is` is in force, or the
///   option's first provider is empty.
/// * `CURLcode::UrlMalformat` -- the service or the region is missing from both
///   the option and the hostname.
/// * `CURLcode::TooLarge` -- the query has [`MAX_QUERY_COMPONENTS`] components,
///   or a canonicalization buffer passed [`CURL_MAX_HTTP_HEADER`].
/// * `CURLcode::OutOfMemory` -- the timestamp would not fit 16 bytes, or the
///   application's date header carries no colon. See [`format_timestamp`] and
///   [`make_headers`] for why that second one is this code.
#[allow(dead_code)] // Consumer is `crate::protocols::http1`, not yet landed.
pub(crate) fn output_aws_sigv4(
    request: &SigV4Request<'_>,
    clock: &dyn Clock,
    tracer: &mut Tracer<'_>,
) -> Result<Option<AuthEmission>, CURLcode> {
    let epoch_secs = signing_epoch_secs(clock, forced_epoch_requested());
    sign(request, epoch_secs, tracer)
}

/// [`output_aws_sigv4`] with the instant already decided.
///
/// Split out so that the whole signature is reachable from a test at a chosen
/// instant without touching the process environment -- which is shared
/// mutable state that a parallel test runner would race on. The split is
/// exactly where the C's `#ifdef` block ends.
fn sign(
    request: &SigV4Request<'_>,
    epoch_secs: i64,
    tracer: &mut Tracer<'_>,
) -> Result<Option<AuthEmission>, CURLcode> {
    // `:850-853`. First, because a signature over a path curl was told not to
    // normalize would be a signature over bytes the server does not see.
    if request.path_as_is {
        failf!(
            tracer,
            "Cannot use sigv4 authentication with path-as-is flag"
        );
        return Err(CURLcode::BadFunctionArgument);
    }

    // `:855-858`, whose comment is "Authorization already present, Bailing
    // out". A SILENT no-op: the C returns `CURLE_OK`, not an error. An
    // application that composes its own `Authorization:` header -- with a
    // pre-signed URL, say, or a session token scheme curl does not implement
    // -- depends on curl not overwriting it and not failing.
    if checkheaders(request.headers, b"Authorization").is_some() {
        return Ok(None);
    }

    // `:861-864`. All four canonicalization buffers carry the
    // `CURL_MAX_HTTP_HEADER` ceiling, so an application that supplies a
    // pathological header set gets `CURLE_TOO_LARGE` rather than unbounded
    // growth.
    let mut canonical_headers = DynBuf::new(CURL_MAX_HTTP_HEADER);
    let mut canonical_query = DynBuf::new(CURL_MAX_HTTP_HEADER);
    let mut signed_headers = DynBuf::new(CURL_MAX_HTTP_HEADER);
    let mut canonical_path = DynBuf::new(CURL_MAX_HTTP_HEADER);

    let params = parse_parameters(request.sigv4, request.hostname, tracer)?;

    // `:923-945`. The application's own hash wins; otherwise S3 gets the
    // special treatment and everything else hashes the body. `sign_as_s3` is
    // CASE-INSENSITIVE on both operands, unlike [`should_urlencode`].
    let (payload_hash, mut content_sha256_hdr) =
        match parse_content_sha_hdr(request.headers, params.provider1) {
            Some(value) => (value.to_vec(), Vec::new()),
            None => {
                let sign_as_s3 = str_casecompare(params.provider0, b"aws")
                    && str_casecompare(params.service, b"s3");
                if sign_as_s3 {
                    let (hash, header) =
                        calc_s3_payload_hash(request, params.provider1);
                    (hash.into_bytes(), header)
                } else {
                    (calc_payload_hash(request).into_bytes(), Vec::new())
                }
            }
        };

    // `:947-965`.
    let mut timestamp = format_timestamp(epoch_secs)?;

    // `:967-972`. `make_headers` may replace the timestamp with one the
    // application supplied, or empty it.
    let date_header = make_headers(
        request,
        params.provider1,
        &mut timestamp,
        &content_sha256_hdr,
        &mut canonical_headers,
        &mut signed_headers,
    )?;

    // `:974-979`: "make_headers() needed this without the \r\n for
    // canonicalization". So the terminator is appended only now, and only when
    // there is a header to append it to.
    if !content_sha256_hdr.is_empty() {
        content_sha256_hdr.extend_from_slice(b"\r\n");
    }

    // `:981-982`. The first eight bytes of the timestamp: `YYYYMMDD`. An
    // emptied timestamp gives an empty date, and the C's `memcpy` reaches the
    // same result because the byte it copies first is the terminator.
    let date = &timestamp[..timestamp.len().min(DATE_LEN)];

    canon_query(request.query, &mut canonical_query)?;
    canon_path(
        until_nul(request.path),
        should_urlencode(params.service),
        &mut canonical_path,
    )?;

    // `:995-1010`. Six components, `\n`-separated, the last WITHOUT a
    // terminator:
    //
    //   HTTPRequestMethod \n CanonicalURI \n CanonicalQueryString \n
    //   CanonicalHeaders \n SignedHeaders \n HashedPayload
    let mut canonical_request = Vec::new();
    canonical_request.extend_from_slice(until_nul(request.method));
    canonical_request.push(b'\n');
    canonical_request.extend_from_slice(canonical_path.as_slice());
    canonical_request.push(b'\n');
    // The one place the C guards a null dynbuf pointer, written `?: ""`.
    canonical_request.extend_from_slice(canonical_query.as_slice());
    canonical_request.push(b'\n');
    canonical_request.extend_from_slice(dyn_or_nil(&canonical_headers));
    canonical_request.push(b'\n');
    canonical_request.extend_from_slice(dyn_or_nil(&signed_headers));
    canonical_request.push(b'\n');
    canonical_request.extend_from_slice(&payload_hash);

    // `:1012-1013`. THE SIGNATURE IS COMPUTED OVER `canonical_request` -- the
    // unmodified bytes above -- and the trace prints a SEPARATE, redacted copy.
    // See [`redacted_canonical_request`] for which values it replaces and why.
    // Emitting the redacted copy rather than the signed one is the only
    // divergence from the C's line here, the signed bytes are byte-identical,
    // and no fixture compares this text.
    infof!(
        tracer,
        "aws_sigv4: Canonical request (enclosed in []) - [{}]",
        String::from_utf8_lossy(&redacted_canonical_request(
            &canonical_request
        ))
    );

    let request_type = request_type(params.provider0);

    // `:1025-1030`: `"%s/%.*s/%.*s/%s"` over the date, the region, the service
    // and the request type.
    let mut credential_scope = Vec::new();
    credential_scope.extend_from_slice(date);
    credential_scope.push(b'/');
    credential_scope.extend_from_slice(params.region);
    credential_scope.push(b'/');
    credential_scope.extend_from_slice(params.service);
    credential_scope.push(b'/');
    credential_scope.extend_from_slice(&request_type);

    // `:1034-1038`. LOWER-case hexadecimal, as every hash here is.
    let canonical_request_hash = sha256_to_hex(&sha256(&canonical_request));

    // `:1044-1058`. The C's comment: "Google allows using RSA key instead of
    // HMAC, so this code might change in the future. For now we only support
    // HMAC." The provider is UPPER-cased, which is what makes this
    // `AWS4-HMAC-SHA256`.
    let mut str_to_sign: Vec<u8> =
        params.provider0.iter().copied().map(raw_toupper).collect();
    str_to_sign.extend_from_slice(b"4-HMAC-SHA256\n");
    str_to_sign.extend_from_slice(&timestamp);
    str_to_sign.push(b'\n');
    str_to_sign.extend_from_slice(&credential_scope);
    str_to_sign.push(b'\n');
    str_to_sign.extend_from_slice(canonical_request_hash.as_bytes());

    // Logged by the C, and it carries no secret: an algorithm name, a
    // timestamp, a credential scope and a hash.
    infof!(
        tracer,
        "aws_sigv4: String to sign (enclosed in []) - [{}]",
        String::from_utf8_lossy(&str_to_sign)
    );

    // `:1063-1077`. FIVE keyed digests, not four. The first four derive the
    // signing key -- which is what the AWS specification calls a four-step
    // derivation -- and the fifth signs the string to sign, producing the
    // signature itself. The C alternates its two buffers, `sign0` and `sign1`,
    // and the alternation is reproduced literally so the two can be read side
    // by side. None of the first four values may ever be logged: together they
    // ARE the signing key.
    let secret =
        SigningSecret::new(params.provider0, request.credentials.secret());
    let sign0 = SigningKey(hmac_sha256(secret.key_material(), date));
    let sign1 = SigningKey(hmac_sha256(sign0.as_bytes(), params.region));
    let sign0 = SigningKey(hmac_sha256(sign1.as_bytes(), params.service));
    let sign1 = SigningKey(hmac_sha256(sign0.as_bytes(), &request_type));
    let sign0 = SigningKey(hmac_sha256(sign1.as_bytes(), &str_to_sign));

    let signature = sha256_to_hex(sign0.as_bytes());

    // `:1081`. The C prints the signature itself. This prints its length
    // instead, and the reasoning is worth stating because it is finer than "a
    // signature is secret":
    //
    // The signature authenticates THIS request. It travels in the
    // `Authorization:` header, so `--trace` shows it anyway and redacting it
    // here buys no confidentiality against an observer of the request. What it
    // does buy is that `--verbose` alone -- which shows `infof` lines but is
    // routinely pasted into a bug report -- stops being a route to a live
    // request credential on its own. The debugging capability is preserved: a
    // reader comparing signatures reads it from the `Authorization:` header in
    // the same `--verbose` output, one line further down.
    infof!(
        tracer,
        "aws_sigv4: Signature - <{}, {} bytes>",
        crate::util::redact::MARKER,
        signature.len()
    );

    // `:1083-1107`:
    //
    //   "Authorization: %.*s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s,
    //    Signature=%s\r\n%s%s"
    let user = request.credentials.user().map_or(&[][..], until_nul);
    let mut block = Vec::new();
    block.extend_from_slice(b"Authorization: ");
    block.extend(params.provider0.iter().copied().map(raw_toupper));
    block.extend_from_slice(b"4-HMAC-SHA256 Credential=");
    block.extend_from_slice(user);
    block.push(b'/');
    block.extend_from_slice(&credential_scope);
    block.extend_from_slice(b", SignedHeaders=");
    block.extend_from_slice(dyn_or_nil(&signed_headers));
    block.extend_from_slice(b", Signature=");
    block.extend_from_slice(signature.as_bytes());
    block.extend_from_slice(b"\r\n");
    // Both of these ALREADY carry their own terminator, as the C's comments at
    // `:1087-1093` say in as many words. `date_header` is absent when the
    // application supplied its own.
    if let Some(date_header) = &date_header {
        block.extend_from_slice(date_header);
    }
    block.extend_from_slice(&content_sha256_hdr);

    // `AuthEmission::Final` carries text. Every byte assembled above is ASCII
    // except the username, the credential scope's region and service, and the
    // signed-header names, all of which reach here from a URL or an option and
    // are not required to be UTF-8. A lossy conversion is the only shape this
    // vocabulary admits; it is unreachable for any credential AWS accepts,
    // whose access-key identifiers are alphanumeric.
    Ok(Some(AuthEmission::Final(
        String::from_utf8_lossy(&block).into_owned(),
    )))
}

// Tests
//
// `tests/unit/unit1979.c` and `unit1980.c` are the C unit tests for the two
// canonicalization helpers, gated by `tests/data/test1979` and `test1980` on
// `<features>unittest</features>`. They link against a debug static libcurl
// and call `canon_path()` and `canon_query()`, which are `UNITTEST`-exported
// there; a Rust static library does not export `pub(crate)` items at all, so
// those two programs cannot link whatever this implementation does (AAP
// 0.8.7). Their vector tables are therefore relocated here verbatim, where the
// private functions are reachable without widening any visibility.
//
// Every expectation below is a LITERAL taken from the C, from a fixture, or
// from the published AWS Signature Version 4 example. None is derived from
// this implementation, because a test that computes its own expectation agrees
// with whatever the code does -- which is the one thing a parity test must not
// do.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::{TraceConfig, TraceState, WriterSink};
    use crate::util::timeval::TestClock;

    // The published AWS Signature Version 4 example.
    //
    // The two credentials below ARE AWS'S OWN PUBLISHED, NON-FUNCTIONAL EXAMPLE VALUES
    // and are not secrets: `AKIDEXAMPLE` is deliberately not a well-formed
    // access-key identifier -- those begin `AKIA` or `ASIA` and are twenty
    // characters -- and the secret ends in `EXAMPLEKEY` for the same reason.
    // They are reproduced verbatim because the expected signature below is
    // only reachable from exactly these bytes, which is the whole point of a
    // published vector.

    /// `20150830T123600Z` as seconds since the Unix epoch.
    const VECTOR_EPOCH: i64 = 1_440_938_160;

    const VECTOR_ACCESS_KEY: &[u8] = b"AKIDEXAMPLE";
    const VECTOR_SECRET: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    /// The canonical request, byte for byte. Note the blank line, which is the
    /// canonical-headers block's own trailing newline followed by the
    /// separator before the signed-header list.
    const VECTOR_CANONICAL_REQUEST: &str = concat!(
        "GET\n",
        "/\n",
        "Action=ListUsers&Version=2010-05-08\n",
        "content-type:application/x-www-form-urlencoded; charset=utf-8\n",
        "host:iam.amazonaws.com\n",
        "x-amz-date:20150830T123600Z\n",
        "\n",
        "content-type;host;x-amz-date\n",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );

    const VECTOR_CANONICAL_REQUEST_HASH: &str =
        "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";

    const VECTOR_STRING_TO_SIGN: &str = concat!(
        "AWS4-HMAC-SHA256\n",
        "20150830T123600Z\n",
        "20150830/us-east-1/iam/aws4_request\n",
        "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59",
    );

    /// The four intermediate keys of the derivation, in order.
    const VECTOR_KEY_DATE: &str =
        "0138c7a6cbd60aa727b2f653a522567439dfb9f3e72b21f9b25941a42f04a7cd";
    const VECTOR_KEY_REGION: &str =
        "f33d5808504bf34812e5fade63308b424b244c59189be2a591dd2282c7cb563f";
    const VECTOR_KEY_SERVICE: &str =
        "199e1f48c602a5ae77ce26a46906920e76fc8427aeaa53da643646fcda1ccfb0";
    const VECTOR_KEY_SIGNING: &str =
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9";

    /// The signature: the FIFTH keyed digest, over the string to sign.
    const VECTOR_SIGNATURE: &str =
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";

    /// SHA-256 of the empty input, which is what a request with no body in
    /// memory hashes to. `tests/data/test1976` expects it verbatim.
    const EMPTY_SHA256: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // Harness.

    /// Runs `body` with a verbose tracer and returns its result together with
    /// everything the sink received, as text.
    fn with_tracer<R>(body: impl FnOnce(&mut Tracer<'_>) -> R) -> (R, String) {
        let config = TraceConfig::init().expect("trace config cannot fail");
        let mut sink = WriterSink::new(Vec::new());
        let result = {
            let mut tracer = Tracer::new(&config, &mut sink)
                .with_state(TraceState::verbose());
            body(&mut tracer)
        };
        let captured = sink.into_inner();
        (result, String::from_utf8_lossy(&captured).into_owned())
    }

    /// A request with every field at the value a freshly configured transfer
    /// would carry: a `GET` of `/` with no query, no body and no headers.
    fn base<'a>(
        credentials: &'a Credentials,
        headers: &'a [&'a [u8]],
    ) -> SigV4Request<'a> {
        SigV4Request {
            sigv4: None,
            path_as_is: false,
            headers,
            host_header: None,
            hostname: b"s3.us-east-1.example.com",
            path: b"/",
            query: None,
            method: b"GET",
            is_get_or_head: true,
            is_post: false,
            postfields: None,
            postfieldsize: -1,
            filesize: -1,
            credentials,
        }
    }

    /// The header block a successful [`sign`] produced, as text.
    fn block_of(emission: Option<AuthEmission>) -> String {
        match emission {
            Some(AuthEmission::Final(block)) => block,
            other => panic!("expected a final emission, got {other:?}"),
        }
    }

    /// A canonicalization buffer with the ceiling the C gives it.
    fn buffer() -> DynBuf {
        DynBuf::new(CURL_MAX_HTTP_HEADER)
    }

    /// [`canon_path`] as a string, for the relocated `unit1979` table.
    fn canon_path_of(path: &[u8], normalize: bool) -> String {
        let mut out = buffer();
        canon_path(path, normalize, &mut out).expect("no ceiling is reached");
        String::from_utf8_lossy(out.as_slice()).into_owned()
    }

    /// [`canon_query`] as a string, for the relocated `unit1980` table.
    fn canon_query_of(query: &[u8]) -> String {
        let mut out = buffer();
        canon_query(Some(query), &mut out).expect("no ceiling is reached");
        String::from_utf8_lossy(out.as_slice()).into_owned()
    }

    /// The canonical header block and the signed-header list [`make_headers`]
    /// produces for `headers`, with the timestamp of the epoch.
    fn headers_of(headers: &[&[u8]]) -> (String, String, Option<String>) {
        let credentials = Credentials::none();
        let request = base(&credentials, headers);
        let mut timestamp = b"19700101T000000Z".to_vec();
        let mut canonical = buffer();
        let mut signed = buffer();
        let date_header = with_tracer(|_| {
            make_headers(
                &request,
                b"amz",
                &mut timestamp,
                &[],
                &mut canonical,
                &mut signed,
            )
        })
        .0
        .expect("these headers canonicalize");
        (
            String::from_utf8_lossy(canonical.as_slice()).into_owned(),
            String::from_utf8_lossy(signed.as_slice()).into_owned(),
            date_header.map(|line| String::from_utf8_lossy(&line).into_owned()),
        )
    }

    // The published vector, end to end.

    // -----------------------------------------------------------------------
    // The trace must not disclose a signed credential.
    // -----------------------------------------------------------------------

    /// A signed `X-Amz-Security-Token` reaches the wire and not the trace.
    ///
    /// This is the case the redaction exists for. STS credentials REQUIRE the
    /// header, so it is the common configuration rather than an edge one, and
    /// its value is a bearer token: whoever reads it can sign requests until it
    /// expires. Three things are asserted together, because any one alone would
    /// leave the fix half-done:
    ///
    /// 1. The token is absent from the trace.
    /// 2. Its NAME is present in the trace, so a reader can still see that the
    ///    header was signed -- redaction must not erase the diagnostic.
    /// 3. It is still in the signed-header list, so the signature covers it.
    #[test]
    fn a_signed_session_token_is_redacted_from_the_trace() {
        const TOKEN: &[u8] = b"FQoGZXIvYXdzEBYaDExAMPLESESSIONTOKEN==";

        let credentials =
            Credentials::new(Some(VECTOR_ACCESS_KEY), Some(VECTOR_SECRET));
        let mut header = b"X-Amz-Security-Token: ".to_vec();
        header.extend_from_slice(TOKEN);
        let headers: [&[u8]; 1] = [header.as_slice()];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:iam"),
            host_header: Some(b"Host: iam.amazonaws.com\r\n"),
            hostname: b"iam.amazonaws.com",
            ..base(&credentials, &headers)
        };

        let (emission, log) =
            with_tracer(|tracer| sign(&request, VECTOR_EPOCH, tracer));
        let block = block_of(emission.expect("the request signs"));
        let token = String::from_utf8_lossy(TOKEN).into_owned();

        assert!(
            !log.contains(&token),
            "the session token must not reach the trace; log was:\n{log}"
        );
        assert!(
            log.contains("x-amz-security-token:<redacted, 38 bytes>"),
            "the header name and a length must survive; log was:\n{log}"
        );
        assert!(
            block
                .contains("SignedHeaders=host;x-amz-date;x-amz-security-token"),
            "the token must still be signed; block was:\n{block}"
        );
    }

    /// The same, for the other header families a caller may legitimately sign.
    ///
    /// A `Cookie` or a `Proxy-Authorization` is not usual on a SigV4
    /// request, but nothing stops an application setting one, and
    /// `make_headers` (`lib/http_aws_sigv4.c:503-541`) signs every header
    /// it is given. A per-family loop rather than one combined case, so a
    /// failure names the family that regressed.
    ///
    /// `Authorization` is deliberately absent, and its absence is a fact
    /// about the C rather than an omission: an application-supplied
    /// `Authorization:` header makes signing a silent no-op
    /// (`lib/http_aws_sigv4.c:855-858`), so it can never appear in a
    /// canonical request this function produced. `Proxy-Authorization`
    /// stands in for the same family.
    #[test]
    fn every_credential_bearing_signed_header_is_redacted_from_the_trace() {
        for (header, secret) in [
            (
                b"Cookie: session=abc123deadbeef".as_slice(),
                "abc123deadbeef",
            ),
            (
                b"Proxy-Authorization: Bearer proxy-token-xyz".as_slice(),
                "proxy-token-xyz",
            ),
            (
                b"WWW-Authenticate: Digest nonce=deadbeefcafe".as_slice(),
                "deadbeefcafe",
            ),
        ] {
            let credentials =
                Credentials::new(Some(VECTOR_ACCESS_KEY), Some(VECTOR_SECRET));
            let headers: [&[u8]; 1] = [header];
            let request = SigV4Request {
                sigv4: Some(b"aws:amz:us-east-1:iam"),
                host_header: Some(b"Host: iam.amazonaws.com\r\n"),
                hostname: b"iam.amazonaws.com",
                ..base(&credentials, &headers)
            };

            let (emission, log) =
                with_tracer(|tracer| sign(&request, VECTOR_EPOCH, tracer));
            let _ = block_of(emission.expect("the request signs"));
            assert!(
                !log.contains(secret),
                "{} leaked; log was:\n{log}",
                String::from_utf8_lossy(header)
            );
            assert!(
                log.contains("<redacted,"),
                "no redaction happened for {}; log was:\n{log}",
                String::from_utf8_lossy(header)
            );
        }
    }

    /// An ordinary header is NOT redacted, so the trace stays useful.
    ///
    /// The counterpart assertion: over-redacting would cost the block its whole
    /// diagnostic value, and `Content-Type` is exactly the header a signature
    /// mismatch is usually traced to.
    #[test]
    fn an_ordinary_signed_header_is_not_redacted_from_the_trace() {
        let credentials =
            Credentials::new(Some(VECTOR_ACCESS_KEY), Some(VECTOR_SECRET));
        let headers: [&[u8]; 1] = [
            b"Content-Type: application/x-www-form-urlencoded; charset=utf-8",
        ];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:iam"),
            host_header: Some(b"Host: iam.amazonaws.com\r\n"),
            hostname: b"iam.amazonaws.com",
            ..base(&credentials, &headers)
        };

        let (emission, log) =
            with_tracer(|tracer| sign(&request, VECTOR_EPOCH, tracer));
        let _ = block_of(emission.expect("the request signs"));
        assert!(
            log.contains(
                "content-type:application/x-www-form-urlencoded; charset=utf-8"
            ),
            "an ordinary header must render in full; log was:\n{log}"
        );
    }

    /// The redaction is a formatting step and changes no signed byte.
    ///
    /// The property that makes the whole approach safe: two requests differing
    /// only in a redactable header still produce the signature the C produces,
    /// because the signature is computed over the unmodified canonical request.
    /// Asserted by checking that the helper leaves a request with no sensitive
    /// header byte-identical, and that the published vector's signature -- which
    /// `the_published_aws_vector_is_reproduced_byte_for_byte` pins against AWS's
    /// own value -- is unaffected by the helper existing.
    #[test]
    fn the_redaction_helper_is_the_identity_on_a_request_without_secrets() {
        let canonical = b"GET\n/\n\ncontent-type:text/plain\nhost:example.com\n\ncontent-type;host\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            redacted_canonical_request(canonical),
            canonical.to_vec(),
            "no sensitive header means no change"
        );
    }

    #[test]
    fn the_published_aws_vector_is_reproduced_byte_for_byte() {
        let credentials =
            Credentials::new(Some(VECTOR_ACCESS_KEY), Some(VECTOR_SECRET));
        let headers: [&[u8]; 1] = [
            b"Content-Type: application/x-www-form-urlencoded; charset=utf-8",
        ];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:iam"),
            host_header: Some(b"Host: iam.amazonaws.com\r\n"),
            hostname: b"iam.amazonaws.com",
            query: Some(b"Action=ListUsers&Version=2010-05-08"),
            ..base(&credentials, &headers)
        };

        let (emission, log) =
            with_tracer(|tracer| sign(&request, VECTOR_EPOCH, tracer));
        let block = block_of(emission.expect("the vector signs"));

        // The two byte-exact diagnostics, verbatim -- and the canonical
        // request and the string to sign are asserted THROUGH them, because
        // that is the only place either is exposed. This vector carries no
        // credential-bearing header, so `redacted_canonical_request` is the
        // identity on it and the traced text is byte-identical to the signed
        // text; `a_signed_session_token_is_redacted_from_the_trace` covers the
        // case where it is not.
        assert!(
            log.contains(&format!(
                "aws_sigv4: Canonical request (enclosed in []) - [{VECTOR_CANONICAL_REQUEST}]"
            )),
            "canonical request mismatch; log was:\n{log}"
        );
        assert!(
            log.contains(&format!(
                "aws_sigv4: String to sign (enclosed in []) - [{VECTOR_STRING_TO_SIGN}]"
            )),
            "string to sign mismatch; log was:\n{log}"
        );

        // The signature is NOT in the trace, by design, and the emitted
        // `Authorization:` header below is where it is asserted instead. That
        // is the stronger assertion of the two: it checks the bytes that go on
        // the wire rather than a diagnostic about them.
        assert!(
            !log.contains(VECTOR_SIGNATURE),
            "the signature must not reach the trace; log was:\n{log}"
        );
        assert!(
            log.contains(&format!(
                "aws_sigv4: Signature - <redacted, {} bytes>",
                VECTOR_SIGNATURE.len()
            )),
            "the redacted signature line is missing; log was:\n{log}"
        );

        // The emitted block. `X-Amz-Date` is curl's own, because the
        // application supplied no date header; there is no content-sha256
        // header, because `iam` is not S3.
        assert_eq!(
            block,
            format!(
                "Authorization: AWS4-HMAC-SHA256 \
                 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
                 SignedHeaders=content-type;host;x-amz-date, \
                 Signature={VECTOR_SIGNATURE}\r\n\
                 X-Amz-Date: 20150830T123600Z\r\n"
            )
        );
    }

    #[test]
    fn the_five_hmacs_reproduce_the_published_signing_key() {
        // `HMAC_SHA256(k, kl, d, dl, o)` five times
        // (`lib/http_aws_sigv4.c:1071-1077`), with the C's `sign0`/`sign1`
        // alternation. The FIFTH signs the string to sign: the AWS
        // specification's "four-step derivation" produces the KEY, and the
        // signature is one HMAC beyond it.
        let secret = SigningSecret::new(b"aws", Some(VECTOR_SECRET));
        assert_eq!(
            secret.key_material(),
            b"AWS4wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "the provider is upper-cased and the password follows verbatim"
        );

        let sign0 = SigningKey(hmac_sha256(secret.key_material(), b"20150830"));
        assert_eq!(sha256_to_hex(sign0.as_bytes()), VECTOR_KEY_DATE);

        let sign1 = SigningKey(hmac_sha256(sign0.as_bytes(), b"us-east-1"));
        assert_eq!(sha256_to_hex(sign1.as_bytes()), VECTOR_KEY_REGION);

        let sign0 = SigningKey(hmac_sha256(sign1.as_bytes(), b"iam"));
        assert_eq!(sha256_to_hex(sign0.as_bytes()), VECTOR_KEY_SERVICE);

        let sign1 = SigningKey(hmac_sha256(sign0.as_bytes(), b"aws4_request"));
        assert_eq!(sha256_to_hex(sign1.as_bytes()), VECTOR_KEY_SIGNING);

        let sign0 = SigningKey(hmac_sha256(
            sign1.as_bytes(),
            VECTOR_STRING_TO_SIGN.as_bytes(),
        ));
        assert_eq!(sha256_to_hex(sign0.as_bytes()), VECTOR_SIGNATURE);

        // The hash inside the string to sign is the canonical request's, and
        // it is lower-case hexadecimal.
        assert_eq!(
            sha256_to_hex(&sha256(VECTOR_CANONICAL_REQUEST.as_bytes())),
            VECTOR_CANONICAL_REQUEST_HASH
        );
    }

    #[test]
    fn request_type_and_the_credential_scope_fold_the_provider() {
        // `"%.*s4_request"` with `provider0` lower-cased (`:1015-1023`).
        assert_eq!(request_type(b"aws"), b"aws4_request");
        assert_eq!(request_type(b"AWS"), b"aws4_request");
        assert_eq!(request_type(b"GOOG"), b"goog4_request");
    }

    // The clock.

    /// A production build cannot be told what time it is.
    ///
    /// The `#ifdef DEBUGBUILD` guard of `lib/http_aws_sigv4.c:947-957`,
    /// asserted from both sides so that neither arm can rot: in a debug build
    /// setting the variable moves the clock, and in a release build the read is
    /// not compiled at all, so it cannot.
    ///
    /// The release arm is what matters for security. Without the guard an
    /// inherited or hostile environment could pin every signature to
    /// `19700101T000000Z`, which a server rejects for skew -- a deterministic
    /// authentication denial that needs no access to the credential.
    ///
    /// The variable is set and removed around the assertion rather than assumed
    /// absent, because the harness sets `CURL_FORCETIME=1` for the whole run
    /// (`tests/runner.pm:167`) and a test that merely read the ambient value
    /// would assert nothing. It is restored afterwards for the same reason.
    #[test]
    fn the_environment_can_move_the_clock_only_in_a_debug_build() {
        // Serialised against nothing: the suite runs with RUST_TEST_THREADS=1,
        // and this is the only test that mutates the process environment.
        let restore = std::env::var_os(FORCETIME_ENV);

        std::env::set_var(FORCETIME_ENV, "1");
        assert_eq!(
            forced_epoch_requested(),
            cfg!(debug_assertions),
            "with the variable SET, only a debug build may honour it"
        );

        std::env::remove_var(FORCETIME_ENV);
        assert!(
            !forced_epoch_requested(),
            "with the variable unset, no build may force the epoch"
        );

        match restore {
            Some(value) => std::env::set_var(FORCETIME_ENV, value),
            None => std::env::remove_var(FORCETIME_ENV),
        }
    }

    #[test]
    fn a_forced_epoch_gives_the_timestamp_every_fixture_expects() {
        // `tests/runner.pm:167` sets `CURL_FORCETIME=1` for every test run, so
        // the harness always signs at the epoch -- in a DEBUG build, which is
        // the only build the sixteen SigV4 fixtures can run against anyway,
        // since every one of them demands the `Debug` feature this binary does
        // not advertise. See `signing_epoch_secs`.
        assert_eq!(FORCETIME_ENV, "CURL_FORCETIME");

        let clock = TestClock::default();
        clock.set_epoch_secs(VECTOR_EPOCH);
        assert_eq!(signing_epoch_secs(&clock, true), 0);
        assert_eq!(signing_epoch_secs(&clock, false), VECTOR_EPOCH);

        // `strftime(timestamp, 17, "%Y%m%dT%H%M%SZ", &tm)` at the epoch.
        let timestamp = format_timestamp(0).expect("the epoch formats");
        assert_eq!(timestamp, b"19700101T000000Z");
        assert_eq!(timestamp.len(), TIMESTAMP_LEN);

        // `memcpy(date, timestamp, 9); date[8] = 0;`
        assert_eq!(&timestamp[..DATE_LEN], b"19700101");
    }

    #[test]
    fn the_public_entry_point_signs_at_the_clock_it_is_given() {
        // Driven at the epoch so that the answer does not depend on whether
        // `CURL_FORCETIME` happens to be set in the ambient environment: both
        // paths agree there, which is exactly why the fixtures use it.
        let credentials = Credentials::new(Some(b"xxx"), Some(b"yyy"));
        let headers: [&[u8]; 0] = [];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:iam"),
            hostname: b"iam.example.com",
            ..base(&credentials, &headers)
        };
        let clock = TestClock::default();

        let (emission, _log) =
            with_tracer(|tracer| output_aws_sigv4(&request, &clock, tracer));
        let block = block_of(emission.expect("this request signs"));

        assert!(
            block
                .contains("Credential=xxx/19700101/us-east-1/iam/aws4_request"),
            "block was {block}"
        );
        assert!(block.contains("X-Amz-Date: 19700101T000000Z\r\n"));
    }

    #[test]
    #[rustfmt::skip]
    fn format_timestamp_reproduces_strftime_including_its_edges() {
        // Measured against this host's C library with the same 17-byte buffer
        // the C passes -- see [`format_timestamp`]'s documentation for the
        // probe. `%Y` is a plain decimal, so the width varies and `strftime`
        // fails only when the result does not fit.
        let cases: &[(i64, Option<&str>)] = &[
            (0, Some("19700101T000000Z")),
            (VECTOR_EPOCH, Some("20150830T123600Z")),
            (-2_208_988_800, Some("19000101T000000Z")),
            (253_402_300_799, Some("99991231T235959Z")),
            (-62_135_596_801, Some("01231T235959Z")),
            (-62_167_219_201, Some("-11231T235959Z")),
            // Year 10000 needs five characters, so the result plus its
            // terminator does not fit and `strftime` answers zero.
            (253_402_300_800, None),
        ];

        for (epoch, expected) in cases {
            match expected {
                Some(text) => assert_eq!(
                    format_timestamp(*epoch).expect("this instant formats"),
                    text.as_bytes(),
                    "epoch {epoch}"
                ),
                None => assert_eq!(
                    format_timestamp(*epoch),
                    Err(CURLcode::OutOfMemory),
                    "epoch {epoch}"
                ),
            }
        }
    }

    // The path and the query. The two tables below are `tests/unit/unit1979.c`
    // and `tests/unit/unit1980.c`, relocated.

    #[test]
    #[rustfmt::skip]
    fn canon_path_matches_the_unit1979_vectors() {
        // (name, normalize, input, expected) -- `tests/unit/unit1979.c:38-107`.
        let cases: &[(&str, bool, &[u8], &str)] = &[
            ("test-equals-encode", true, b"/a=b", "/a%3Db"),
            ("test-equals-noencode", false, b"/a=b", "/a=b"),
            (
                "test-s3-tables",
                true,
                b"/tables/arn%3Aaws%3As3tables%3Aus-east-1%3A022954301426%3Abucket%2Fjasoehartablebucket/jasoeharnamespace/jasoehartable/encryption",
                "/tables/arn%253Aaws%253As3tables%253Aus-east-1%253A022954301426%253Abucket%252Fjasoehartablebucket/jasoeharnamespace/jasoehartable/encryption",
            ),
            ("get-vanilla", true, b"/", "/"),
            (
                "get-unreserved",
                true,
                b"/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "/-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            ),
            ("get-slashes-unnormalized", false, b"//example//", "//example//"),
            ("get-space-normalized", true, b"/example space/", "/example%20space/"),
            ("get-plus-normalized", true, b"/example+space/", "/example%2Bspace/"),
            ("get-slash-dot-slash-unnormalized", false, b"/./", "/./"),
            ("get-slash-unnormalized", false, b"//", "//"),
            (
                "get-relative-relative-unnormalized",
                false,
                b"/example1/example2/../..",
                "/example1/example2/../..",
            ),
        ];

        for (name, normalize, input, expected) in cases {
            assert_eq!(
                &canon_path_of(input, *normalize),
                expected,
                "{name}: normalize was {normalize}"
            );
        }

        // `if(curlx_dyn_len(new_path) == 0) result = curlx_dyn_add(new_path,
        // "/")` (`:701-704`) -- an empty path becomes a slash either way.
        assert_eq!(canon_path_of(b"", true), "/");
        assert_eq!(canon_path_of(b"", false), "/");
    }

    #[test]
    #[rustfmt::skip]
    fn canon_query_matches_the_unit1980_vectors() {
        // (name, input, expected) -- `tests/unit/unit1980.c:38-84`.
        let cases: &[(&str, &[u8], &str)] = &[
            ("no-value", b"Param1=", "Param1="),
            (
                "test-439",
                b"name=me&noval&aim=b%aad&weirdo=*.//-",
                "aim=b%AAd&name=me&noval=&weirdo=%2A.%2F%2F-",
            ),
            ("blank-query-params", b"hello=a&b&c=&d", "b=&c=&d=&hello=a"),
            (
                "get-vanilla-query-order-key-case",
                b"Param2=value2&Param1=value1",
                "Param1=value1&Param2=value2",
            ),
            (
                "get-vanilla-query-unreserved",
                b"-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz=-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            ),
            ("get-vanilla-empty-query-key", b"Param1=value1", "Param1=value1"),
            (
                "get-vanilla-query-order-encoded",
                b"Param-3=Value3&Param=Value2&%E1%88%B4=Value1",
                "%E1%88%B4=Value1&Param=Value2&Param-3=Value3",
            ),
            ("space-plus", b"p3= &p1=+&p2=%20", "p1=%20&p2=%20&p3=%20"),
            ("2b-incoming", b"p3=%2b&p1=+", "p1=%20&p3=%2B"),
        ];

        for (name, input, expected) in cases {
            assert_eq!(&canon_query_of(input), expected, "{name}");
        }

        // An absent query contributes nothing, and is not an error
        // (`:719-720`).
        let mut out = buffer();
        canon_query(None, &mut out).expect("an absent query is fine");
        assert!(out.is_empty());
    }

    #[test]
    fn the_path_uses_upper_case_hex_and_every_digest_uses_lower_case() {
        // The single most dangerous unification in this file. `uri_encode_path`
        // and `normalize_query` render `%%%02X` through `Curl_hexbyte`
        // (`lib/escape.c:222`, UPPER-case), while every hash goes through
        // `Curl_hexencode` (`lib/escape.c:197`, lower-case). One folded digit
        // changes the signature.
        assert_eq!(canon_path_of(b"/\xab", true), "/%AB");
        assert_eq!(canon_query_of(b"k=\xab"), "k=%AB");
        assert_eq!(hexpercent(0xab), *b"%AB");

        // Lower-case, in the same test so that a future "tidy-up" of either
        // one fails here.
        assert_eq!(sha256_to_hex(&[0xab, 0xcd]), "abcd");
        assert_eq!(sha256_to_hex(&sha256(b"")), EMPTY_SHA256);
        assert!(EMPTY_SHA256
            .chars()
            .all(|digit| !digit.is_ascii_uppercase()));
    }

    #[test]
    fn normalize_query_keeps_an_encoded_plus_encoded() {
        // The C's own comment is the specification: "Make sure %2B is left
        // percent encoded, and not decoded to plus, then encoded to space."
        assert_eq!(canon_query_of(b"k=%2B"), "k=%2B");
        assert_eq!(canon_query_of(b"k=%2b"), "k=%2B", "the case is normalized");
        assert_eq!(
            canon_query_of(b"k=+"),
            "k=%20",
            "a literal plus is a space"
        );
        assert_eq!(canon_query_of(b"k=%20"), "k=%20");
        assert_eq!(canon_query_of(b"k=-._~"), "k=-._~", "unreserved passes");
        // An invalid escape is not an error: the `%` becomes `%25`.
        assert_eq!(canon_query_of(b"k=%zz"), "k=%25zz");
        assert_eq!(canon_query_of(b"k=%4"), "k=%254");
    }

    #[test]
    fn is_reserved_char_admits_exactly_the_unreserved_set() {
        // `ISALNUM(c) || ISURLPUNTCS(c)`, and `ISURLPUNTCS` is four bytes:
        // `lib/curl_ctype.h:47-48`.
        for byte in b'0'..=b'9' {
            assert!(is_reserved_char(byte));
        }
        for byte in b'a'..=b'z' {
            assert!(is_reserved_char(byte));
        }
        for byte in b'A'..=b'Z' {
            assert!(is_reserved_char(byte));
        }
        for byte in *b"-._~" {
            assert!(is_reserved_char(byte), "{byte:#x} is ISURLPUNTCS");
        }
        for byte in *b"/+=%&?*:@ !$'(),;" {
            assert!(!is_reserved_char(byte), "{byte:#x} is not unreserved");
        }
    }

    #[test]
    #[rustfmt::skip]
    fn should_urlencode_is_false_for_exactly_three_services() {
        // `curlx_str_cmp`, so the comparison is case-SENSITIVE (`:275-277`).
        assert!(!should_urlencode(b"s3"));
        assert!(!should_urlencode(b"s3-express"));
        assert!(!should_urlencode(b"s3-outposts"));

        assert!(should_urlencode(b"S3"), "case-sensitive, unlike sign_as_s3");
        assert!(should_urlencode(b"s3-tables"));
        assert!(should_urlencode(b"s3outposts"));
        assert!(should_urlencode(b"iam"));
        assert!(should_urlencode(b"execute-api"));
        assert!(should_urlencode(b""));
    }

    #[test]
    fn a_query_of_too_many_components_is_too_large() {
        // `if(++num_splits == MAX_QUERY_COMPONENTS) result =
        // CURLE_TOO_LARGE` -- so 127 succeed and the 128th fails.
        let mut query = Vec::new();
        for index in 0..127 {
            if index != 0 {
                query.push(b'&');
            }
            query.extend_from_slice(b"k=v");
        }
        let mut out = buffer();
        assert!(canon_query(Some(&query), &mut out).is_ok());

        query.extend_from_slice(b"&k=v");
        let mut out = buffer();
        assert_eq!(
            canon_query(Some(&query), &mut out),
            Err(CURLcode::TooLarge)
        );

        // Empty components are dropped rather than counted (`:166`).
        assert_eq!(canon_query_of(b"&&a=1&&&b=2&&"), "a=1&b=2");
    }

    #[test]
    fn an_empty_query_key_reaches_the_signature_as_nil() {
        // `curlx_dyn_ptr()` is null for a key that normalized to nothing, and
        // curl's own `printf` writes `(nil)` for a null `%s`
        // (`lib/mprintf.c:837`, `:851-856`). Absurd, and frozen.
        assert_eq!(canon_query_of(b"=x"), "(nil)=x");
        assert_eq!(NIL_STRING, b"(nil)");
    }

    // Header canonicalization.

    #[test]
    fn trim_header_collapses_blanks_without_folding_the_value() {
        // `trim_headers` (`:80-116`): the name folds, the value does not, and
        // blank runs collapse to one space except a trailing run.
        let mut entry = b"X-Amz-Meta-Test:   two   words   ".to_vec();
        trim_header(&mut entry);
        assert_eq!(entry, b"x-amz-meta-test:two words");

        // Tabs are blanks too -- `ISBLANK` is space or tab
        // (`lib/curl_ctype.h:45`).
        let mut entry = b"A:\t \tb\t \tc\t".to_vec();
        trim_header(&mut entry);
        assert_eq!(entry, b"a:b c");

        // The VALUE keeps its case.
        let mut entry = b"Content-Type: Application/JSON".to_vec();
        trim_header(&mut entry);
        assert_eq!(entry, b"content-type:Application/JSON");

        // A value that is only blanks collapses to nothing at all.
        let mut entry = b"Empty:    ".to_vec();
        trim_header(&mut entry);
        assert_eq!(entry, b"empty:");

        // `name:` with no value keeps its shape.
        let mut entry = b"Name:".to_vec();
        trim_header(&mut entry);
        assert_eq!(entry, b"name:");

        // No colon at all: `if(!*value) continue` -- the whole entry folds and
        // nothing is rewritten (`:90-92`).
        let mut entry = b"NoColonHere".to_vec();
        trim_header(&mut entry);
        assert_eq!(entry, b"nocolonhere");
    }

    #[test]
    fn header_names_sort_case_sensitively_and_shorter_first() {
        // `compare_header_names` (`:292-319`): only the name, `strncmp` over
        // the shared length, then the shorter one first.
        assert_eq!(
            compare_header_names(b"a:1", b"b:0"),
            Ordering::Less,
            "the value takes no part"
        );
        assert_eq!(
            compare_header_names(
                b"x-amz-meta-test:1",
                b"x-amz-meta-test-two:1"
            ),
            Ordering::Less,
            "a shorter name that is a prefix sorts first"
        );
        assert_eq!(
            compare_header_names(
                b"x-amz-meta-test-two:1",
                b"x-amz-meta-test:1"
            ),
            Ordering::Greater
        );
        assert_eq!(
            compare_header_names(b"host:a", b"host:b"),
            Ordering::Equal,
            "same name, whatever the values"
        );
        // Case-sensitive, which is `strncmp`. Every entry has already been
        // folded by `trim_header` when this runs, so this only ever decides
        // between lower-case names in production.
        assert_eq!(compare_header_names(b"A:1", b"a:1"), Ordering::Less);

        // `tests/data/test1976`'s SignedHeaders, in full.
        let (_canonical, signed, _date) = headers_of(&[
            b"X-Amz-Meta-Test-Two: test2",
            b"x-amz-meta-test: test",
        ]);
        assert_eq!(
            signed,
            "host;x-amz-date;x-amz-meta-test;x-amz-meta-test-two"
        );
    }

    #[test]
    fn duplicate_headers_merge_in_the_order_they_were_supplied() {
        // "Merge duplicate header definitions by comma delimiting their values
        // in the order defined the headers are defined" (`:321-323`). The
        // preceding sort MUST be stable for that to hold; the C's bubble sort
        // is, and `sort_by` is.
        let (canonical, signed, _date) = headers_of(&[
            b"X-Amz-Meta: first",
            b"X-Amz-Meta: second",
            b"X-Amz-Meta: third",
        ]);
        assert!(
            canonical.contains("x-amz-meta:first,second,third\n"),
            "canonical block was:\n{canonical}"
        );
        assert_eq!(
            signed, "host;x-amz-date;x-amz-meta",
            "a merged run contributes ONE signed header"
        );

        // Directly, so the run-folding is visible without the surrounding
        // machinery.
        let mut head = vec![
            b"a:1".to_vec(),
            b"a:2".to_vec(),
            b"a:3".to_vec(),
            b"b:4".to_vec(),
        ];
        merge_duplicate_headers(&mut head).expect("no ceiling is reached");
        assert_eq!(head, vec![b"a:1,2,3".to_vec(), b"b:4".to_vec()]);
    }

    #[test]
    fn the_canonical_block_ends_in_a_newline_and_signed_headers_do_not() {
        // The two shapes that produce the canonical request's blank line
        // (`:523-541`).
        let (canonical, signed, _date) = headers_of(&[b"B: 2", b"A: 1"]);
        assert_eq!(canonical, "a:1\nb:2\nhost:s3.us-east-1.example.com\nx-amz-date:19700101T000000Z\n");
        assert_eq!(signed, "a;b;host;x-amz-date");
        assert!(canonical.ends_with('\n'));
        assert!(!signed.ends_with(';'));
        assert!(!signed.starts_with(';'));
    }

    #[test]
    fn the_canonical_request_carries_a_blank_line() {
        let credentials = Credentials::none();
        let headers: [&[u8]; 0] = [];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:iam"),
            hostname: b"iam.example.com",
            ..base(&credentials, &headers)
        };
        let (emission, log) = with_tracer(|tracer| sign(&request, 0, tracer));
        emission.expect("this request signs");

        assert!(
            log.contains(&format!(
                "aws_sigv4: Canonical request (enclosed in []) - [GET\n\
                 /\n\
                 \n\
                 host:iam.example.com\n\
                 x-amz-date:19700101T000000Z\n\
                 \n\
                 host;x-amz-date\n\
                 {EMPTY_SHA256}]"
            )),
            "log was:\n{log}"
        );
    }

    #[test]
    fn the_three_user_header_rejection_rules_are_reproduced() {
        // `:428-465`, whose comment enumerates all three.
        //
        // `name:` with no value is a removal directive and is NOT added.
        let (canonical, signed, _date) = headers_of(&[b"X-Removed:"]);
        assert!(!canonical.contains("x-removed"));
        assert_eq!(signed, "host;x-amz-date");

        // `name;` with no value IS added, with the semicolon rewritten to a
        // colon.
        let (canonical, signed, _date) = headers_of(&[b"X-Empty;"]);
        assert!(canonical.contains("x-empty:\n"), "was:\n{canonical}");
        assert_eq!(signed, "host;x-amz-date;x-empty");

        // A blanks-only value is NOT added.
        let (canonical, _signed, _date) = headers_of(&[b"X-Blank:   "]);
        assert!(!canonical.contains("x-blank"));
        let (canonical, _signed, _date) = headers_of(&[b"X-Blank;   "]);
        assert!(!canonical.contains("x-blank"));

        // Neither separator: NOT added.
        let (canonical, signed, _date) = headers_of(&[b"NoSeparator"]);
        assert!(!canonical.contains("noseparator"));
        assert_eq!(signed, "host;x-amz-date");
    }

    #[test]
    fn the_host_entry_is_truncated_at_the_first_carriage_return() {
        // "remove /r/n as the separator for canonical request must be '\n'"
        // (`:406`).
        let credentials = Credentials::none();
        let headers: [&[u8]; 0] = [];
        let request = SigV4Request {
            host_header: Some(b"Host: example.com:8080\r\n"),
            ..base(&credentials, &headers)
        };
        let mut timestamp = b"19700101T000000Z".to_vec();
        let mut canonical = buffer();
        let mut signed = buffer();
        with_tracer(|_| {
            make_headers(
                &request,
                b"amz",
                &mut timestamp,
                &[],
                &mut canonical,
                &mut signed,
            )
        })
        .0
        .expect("this canonicalizes");
        assert!(String::from_utf8_lossy(canonical.as_slice())
            .contains("host:example.com:8080\n"));

        // With no `aptr.host` at all the C formats `"host:%s"` from the
        // connection's hostname instead (`:411`).
        let (canonical, _signed, _date) = headers_of(&[]);
        assert!(canonical.contains("host:s3.us-east-1.example.com\n"));

        // An application-supplied `Host:` suppresses the entry entirely; the
        // header arrives through the user-header loop like any other.
        let (canonical, signed, _date) =
            headers_of(&[b"Host: application.example"]);
        assert_eq!(canonical.matches("host:").count(), 1);
        assert!(canonical.contains("host:application.example\n"));
        assert_eq!(signed, "host;x-amz-date");
    }

    #[test]
    fn the_date_header_is_folded_to_ucfirst_on_the_wire_and_lower_case_inside()
    {
        // `X-Amz-Date` on the wire (`:391-395`), `x-amz-date:` in the canonical
        // block with NO space after the colon (`:397-400`).
        assert_eq!(date_header_key(b"amz"), b"X-Amz-Date");
        assert_eq!(date_header_key(b"AMZ"), b"X-Amz-Date");
        assert_eq!(date_header_key(b"goog"), b"X-Goog-Date");
        assert_eq!(
            canonical_date_header(b"AMZ", b"19700101T000000Z"),
            b"x-amz-date:19700101T000000Z"
        );
        assert_eq!(
            outgoing_date_header(b"X-Amz-Date", b"19700101T000000Z"),
            b"X-Amz-Date: 19700101T000000Z\r\n"
        );
    }

    #[test]
    fn a_sixteen_byte_date_header_is_adopted_and_any_other_length_is_lost() {
        // `if((endp - value) == TIMESTAMP_SIZE - 1)` (`:490-499`).
        let credentials = Credentials::none();

        let headers: [&[u8]; 1] = [b"X-Amz-Date: 20150830T123600Z"];
        let request = base(&credentials, &headers);
        let mut timestamp = b"19700101T000000Z".to_vec();
        let mut canonical = buffer();
        let mut signed = buffer();
        let date_header = with_tracer(|_| {
            make_headers(
                &request,
                b"amz",
                &mut timestamp,
                &[],
                &mut canonical,
                &mut signed,
            )
        })
        .0
        .expect("this canonicalizes");
        assert_eq!(timestamp, b"20150830T123600Z", "adopted verbatim");
        assert!(
            date_header.is_none(),
            "nothing extra is emitted: the application's own header is already \
             in the request"
        );

        // Any other length discards the timestamp entirely -- "bad timestamp
        // length", `timestamp[0] = 0`. An RFC 1123 `Date:` header stops the
        // alphanumeric run at its comma, giving three bytes.
        let headers: [&[u8]; 1] = [b"Date: Thu, 09 Nov 2010 14:49:00 GMT"];
        let request = base(&credentials, &headers);
        let mut timestamp = b"19700101T000000Z".to_vec();
        let mut canonical = buffer();
        let mut signed = buffer();
        let date_header = with_tracer(|_| {
            make_headers(
                &request,
                b"amz",
                &mut timestamp,
                &[],
                &mut canonical,
                &mut signed,
            )
        })
        .0
        .expect("this canonicalizes");
        assert!(timestamp.is_empty(), "discarded, and not an error");
        assert!(date_header.is_none());

        // And an empty timestamp yields an empty credential-scope date rather
        // than a failure, which is what the C's `memcpy` of a terminated
        // buffer produces.
        assert_eq!(&timestamp[..timestamp.len().min(DATE_LEN)], b"");
    }

    #[test]
    fn a_semicolon_form_date_header_fails_the_way_the_c_does() {
        // `Curl_checkheaders` matches `;` as well as `:`
        // (`lib/transfer.h:26`), and the branch that follows finds no colon
        // and jumps to `fail` while `ret` still holds its initial
        // `CURLE_OUT_OF_MEMORY` (`:387`, `:483-486`, `:543`).
        let credentials = Credentials::none();
        let headers: [&[u8]; 1] = [b"X-Amz-Date;"];
        let request = base(&credentials, &headers);
        let mut timestamp = b"19700101T000000Z".to_vec();
        let mut canonical = buffer();
        let mut signed = buffer();
        let outcome = with_tracer(|_| {
            make_headers(
                &request,
                b"amz",
                &mut timestamp,
                &[],
                &mut canonical,
                &mut signed,
            )
        })
        .0;
        assert_eq!(outcome, Err(CURLcode::OutOfMemory));
    }

    #[test]
    fn find_date_hdr_prefers_the_provider_key_over_a_plain_date() {
        let provider_key = b"X-Amz-Date";
        let headers: [&[u8]; 2] =
            [b"Date: yesterday", b"X-Amz-Date: 20150830T123600Z"];
        assert_eq!(
            find_date_hdr(&headers, provider_key),
            Some(&b"X-Amz-Date: 20150830T123600Z"[..])
        );

        let headers: [&[u8]; 1] = [b"Date: yesterday"];
        assert_eq!(
            find_date_hdr(&headers, provider_key),
            Some(&b"Date: yesterday"[..])
        );

        let headers: [&[u8]; 0] = [];
        assert_eq!(find_date_hdr(&headers, provider_key), None);
    }

    #[test]
    fn checkheaders_matches_a_name_case_insensitively_up_to_a_separator() {
        let headers: [&[u8]; 3] =
            [b"authorization: given", b"Hosts: no", b"Host; yes"];
        assert_eq!(
            checkheaders(&headers, b"Authorization"),
            Some(&b"authorization: given"[..])
        );
        // `Hosts:` must not match `Host`, because the byte at the name's
        // length is `s` rather than a separator.
        assert_eq!(checkheaders(&headers, b"Host"), Some(&b"Host; yes"[..]));
        assert_eq!(checkheaders(&headers, b"X-Absent"), None);
        // A line that IS the name, with no separator at all, does not match.
        let headers: [&[u8]; 1] = [b"Host"];
        assert_eq!(checkheaders(&headers, b"Host"), None);
    }

    // The payload hash.

    #[test]
    fn an_absent_body_hashes_the_empty_input() {
        let credentials = Credentials::none();
        let headers: [&[u8]; 0] = [];
        let request = base(&credentials, &headers);
        assert_eq!(calc_payload_hash(&request), EMPTY_SHA256);
        assert!(post_data(&request).is_empty());
    }

    #[test]
    fn a_negative_postfieldsize_means_measure_it_with_strlen() {
        let credentials = Credentials::none();
        let headers: [&[u8]; 0] = [];

        // `if(data->set.postfieldsize < 0) post_data_len =
        // strlen(post_data);` (`:595-596`).
        let request = SigV4Request {
            postfields: Some(b"body\0ignored"),
            postfieldsize: -1,
            ..base(&credentials, &headers)
        };
        assert_eq!(post_data(&request), b"body");

        // Otherwise the size governs, even past a zero byte.
        let request = SigV4Request {
            postfields: Some(b"body\0kept"),
            postfieldsize: 9,
            ..base(&credentials, &headers)
        };
        assert_eq!(post_data(&request), b"body\0kept");

        // A size beyond the buffer is clamped rather than read past.
        let request = SigV4Request {
            postfields: Some(b"short"),
            postfieldsize: 4096,
            ..base(&credentials, &headers)
        };
        assert_eq!(post_data(&request), b"short");

        let request = SigV4Request {
            postfields: Some(b"abc"),
            postfieldsize: 3,
            ..base(&credentials, &headers)
        };
        assert_eq!(
            calc_payload_hash(&request),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-256 of \"abc\", the FIPS 180-2 vector"
        );
    }

    #[test]
    #[rustfmt::skip]
    fn s3_selects_unsigned_payload_across_the_method_matrix() {
        // `calc_s3_payload_hash` (`:609-644`):
        //   empty_method  = GET || HEAD
        //   empty_payload = empty_method || filesize == 0
        //   post_payload  = POST && postfields
        // A real hash when either holds; the literal otherwise.
        let credentials = Credentials::none();
        let headers: [&[u8]; 0] = [];

        // (label, is_get_or_head, is_post, postfields, filesize, expected)
        let cases: &[(&str, bool, bool, Option<&[u8]>, i64, &str)] = &[
            ("GET", true, false, None, -1, EMPTY_SHA256),
            ("HEAD", true, false, None, -1, EMPTY_SHA256),
            ("PUT with a body", false, false, None, 42, S3_UNSIGNED_PAYLOAD),
            ("PUT of nothing", false, false, None, 0, EMPTY_SHA256),
            ("PUT of unknown size", false, false, None, -1, S3_UNSIGNED_PAYLOAD),
            ("POST in memory", false, true, Some(b"a=1"), -1,
             "c22fea5d7428e5cf47ef6354c97c9223c95d6dcdc3e0d2300ff79056b1ff3d85"),
            ("POST from a callback", false, true, None, -1, S3_UNSIGNED_PAYLOAD),
        ];

        for (label, get_or_head, post, postfields, filesize, expected) in cases {
            let request = SigV4Request {
                is_get_or_head: *get_or_head,
                is_post: *post,
                postfields: *postfields,
                filesize: *filesize,
                ..base(&credentials, &headers)
            };
            let (hash, header) = calc_s3_payload_hash(&request, b"amz");
            assert_eq!(&hash, expected, "{label}");
            // A SPACE after the colon, unlike the canonical date header, and
            // the provider VERBATIM -- the C folds no case at `:638-639`.
            assert_eq!(
                header,
                format!("x-amz-content-sha256: {expected}").into_bytes(),
                "{label}"
            );
        }

        let request = base(&credentials, &headers);
        let (_hash, header) = calc_s3_payload_hash(&request, b"AMZ");
        assert!(
            header.starts_with(b"x-AMZ-content-sha256: "),
            "the provider is not folded here; header was {}",
            String::from_utf8_lossy(&header)
        );
    }

    #[test]
    fn an_application_supplied_content_sha256_is_adopted_verbatim() {
        // `parse_content_sha_hdr` (`:555-585`): after the colon, leading
        // blanks skipped and trailing blanks trimmed, and nothing validated.
        let headers: [&[u8]; 1] =
            [b"x-amz-content-sha256:   STREAMING-UNSIGNED-PAYLOAD-TRAILER  "];
        assert_eq!(
            parse_content_sha_hdr(&headers, b"amz"),
            Some(&b"STREAMING-UNSIGNED-PAYLOAD-TRAILER"[..])
        );

        // Case-insensitive on the name, and the provider is used verbatim in
        // the key.
        let headers: [&[u8]; 1] = [b"X-AMZ-Content-Sha256: abc"];
        assert_eq!(parse_content_sha_hdr(&headers, b"amz"), Some(&b"abc"[..]));

        // A different provider does not match.
        assert_eq!(parse_content_sha_hdr(&headers, b"goog"), None);

        // The `;` form has no colon and yields nothing, which is not an error.
        let headers: [&[u8]; 1] = [b"x-amz-content-sha256;"];
        assert_eq!(parse_content_sha_hdr(&headers, b"amz"), None);

        // End to end: the adopted value reaches the canonical request, and no
        // content-sha256 header is emitted because the application already
        // sent one.
        let credentials = Credentials::none();
        let headers: [&[u8]; 1] = [b"x-amz-content-sha256: UNSIGNED-PAYLOAD"];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:s3"),
            ..base(&credentials, &headers)
        };
        let (emission, log) = with_tracer(|tracer| sign(&request, 0, tracer));
        let block = block_of(emission.expect("this request signs"));
        assert!(
            log.contains(
                "\nhost;x-amz-content-sha256;x-amz-date\nUNSIGNED-PAYLOAD]"
            ),
            "log was:\n{log}"
        );
        assert!(
            !block.contains("x-amz-content-sha256: "),
            "curl must not emit a second content-sha256 HEADER, though the \
             signed-header list still names the application's own; block was \
             {block}"
        );
        assert!(
            block.contains(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date,"
            ),
            "block was {block}"
        );
    }

    // Parameter parsing.

    /// [`parse_parameters`] as four owned strings, for compact assertions.
    fn params_of(
        sigv4: Option<&[u8]>,
        hostname: &[u8],
    ) -> Result<(String, String, String, String), CURLcode> {
        let (outcome, _log) =
            with_tracer(|tracer| parse_parameters(sigv4, hostname, tracer));
        outcome.map(|params| {
            (
                String::from_utf8_lossy(params.provider0).into_owned(),
                String::from_utf8_lossy(params.provider1).into_owned(),
                String::from_utf8_lossy(params.region).into_owned(),
                String::from_utf8_lossy(params.service).into_owned(),
            )
        })
    }

    #[test]
    fn an_absent_or_empty_option_selects_aws_amz() {
        // `if(!line || !*line) line = "aws:amz";` (`:873-875`).
        assert_eq!(DEFAULT_SIGV4, b"aws:amz");
        let host = b"iam.us-east-1.example.com";
        let expected = (
            "aws".to_owned(),
            "amz".to_owned(),
            "us-east-1".to_owned(),
            "iam".to_owned(),
        );
        assert_eq!(params_of(None, host), Ok(expected.clone()));
        assert_eq!(params_of(Some(b""), host), Ok(expected.clone()));
        assert_eq!(params_of(Some(b"\0"), host), Ok(expected));
    }

    #[test]
    fn an_absent_second_provider_becomes_the_first() {
        // `provider1 = provider0` (`:886-889`).
        let host = b"iam.us-east-1.example.com";
        assert_eq!(
            params_of(Some(b"goog"), host),
            Ok((
                "goog".to_owned(),
                "goog".to_owned(),
                "us-east-1".to_owned(),
                "iam".to_owned(),
            ))
        );
        // A trailing separator with nothing after it is the same case.
        assert_eq!(
            params_of(Some(b"goog:"), host).map(|params| params.1),
            Ok("goog".to_owned())
        );
    }

    #[test]
    fn every_component_is_capped_at_sixty_four_bytes() {
        // `curlx_str_until(..., MAX_SIGV4_LEN, ...)` fails once the span passes
        // the cap (`lib/curlx/strparse.c:50-52`). Sixty-four is accepted.
        let sixty_four = vec![b'a'; MAX_SIGV4_LEN];
        let sixty_five = vec![b'a'; MAX_SIGV4_LEN + 1];
        let host = b"iam.us-east-1.example.com";

        let mut option = sixty_four.clone();
        option.extend_from_slice(b":amz:us-east-1:iam");
        assert_eq!(
            params_of(Some(&option), host).map(|params| params.0.len()),
            Ok(MAX_SIGV4_LEN)
        );

        // An over-long FIRST provider is an error, because `provider0` is the
        // one component the C insists on.
        let mut option = sixty_five.clone();
        option.extend_from_slice(b":amz");
        assert_eq!(
            params_of(Some(&option), host),
            Err(CURLcode::BadFunctionArgument)
        );

        // An over-long region is DROPPED, not rejected: `curlx_str_until()`
        // answers `STRE_BIG` and leaves the span empty, and the `||` chain
        // stops there -- so the service that FOLLOWED it in the option string
        // is never read either, and the hostname then supplies both.
        let mut option = b"aws:amz:".to_vec();
        option.extend_from_slice(&sixty_five);
        option.extend_from_slice(b":iam");
        assert_eq!(
            params_of(Some(&option), host),
            Ok((
                "aws".to_owned(),
                "amz".to_owned(),
                "us-east-1".to_owned(),
                "iam".to_owned(),
            )),
            "both come from the hostname's first two labels, not from the option"
        );
    }

    #[test]
    fn an_empty_first_provider_is_rejected_with_the_verbatim_message() {
        let (outcome, log) = with_tracer(|tracer| {
            parse_parameters(
                Some(b":amz"),
                b"iam.us-east-1.example.com",
                tracer,
            )
        });
        assert_eq!(outcome.map(|_| ()), Err(CURLcode::BadFunctionArgument));
        assert!(
            log.contains("first aws-sigv4 provider cannot be empty"),
            "log was:\n{log}"
        );
    }

    #[test]
    fn the_hostname_derivation_is_nested_and_stays_nested() {
        // `:897-919`. The region block sits INSIDE the service block, so
        // naming a service leaves the region empty rather than deriving it.
        //
        // The tuple is (provider0, provider1, region, service), and the labels
        // fill it in the other order: the FIRST label is the service.
        assert_eq!(
            params_of(Some(b"aws:amz"), b"iam.us-east-1.example.com"),
            Ok((
                "aws".to_owned(),
                "amz".to_owned(),
                "us-east-1".to_owned(),
                "iam".to_owned(),
            ))
        );

        // Both derived, in the C's order: the first label is the SERVICE and
        // the second is the REGION.
        let (_p0, _p1, region, service) =
            params_of(Some(b"aws:amz"), b"s3.eu-west-2.amazonaws.com")
                .expect("both labels are present");
        assert_eq!(service, "s3");
        assert_eq!(region, "eu-west-2");

        // An EMPTY region component does not mean "no region": it aborts the
        // `||` chain, because `curlx_str_until()` rejects a zero-length span.
        // So the service that follows it is never read either and the hostname
        // supplies both -- which is what makes the state the nesting guards
        // against unreachable. See [`parse_parameters`]'s documentation.
        let (_p0, _p1, region, service) =
            params_of(Some(b"aws:amz::s3"), b"iam.eu-west-2.amazonaws.com")
                .expect("the hostname supplies both");
        assert_eq!(service, "iam", "from the first label, not the option");
        assert_eq!(region, "eu-west-2");

        // The structural invariant that follows: a named service implies a
        // named region, so `service` is never non-empty while `region` is
        // empty. That is why the nested form and a flattened one cannot be
        // told apart -- and the nesting is still transcribed exactly, because
        // the reader of the C should find the same shape here.
        for option in [
            &b"aws"[..],
            b"aws:amz",
            b"aws:amz:",
            b"aws:amz::",
            b"aws:amz::s3",
            b"aws:amz:eu",
            b"aws:amz:eu:",
            b"aws:amz:eu:s3",
        ] {
            let (_p0, _p1, region, service) =
                params_of(Some(option), b"iam.eu-west-2.amazonaws.com")
                    .expect("every one of these parses");
            assert!(
                !service.is_empty(),
                "{}: the derivation either fills the service or fails",
                String::from_utf8_lossy(option)
            );
            assert!(
                !region.is_empty(),
                "{}: a named service implies a named region",
                String::from_utf8_lossy(option)
            );
        }

        // A named region and no service still derives the service from the
        // first label -- and then does not touch the region.
        let (_p0, _p1, region, service) = params_of(
            Some(b"aws:amz:eu-west-3"),
            b"s3.eu-west-2.amazonaws.com",
        )
        .expect("the first label supplies the service");
        assert_eq!(service, "s3");
        assert_eq!(region, "eu-west-3");
    }

    #[test]
    fn a_hostname_that_cannot_supply_the_parts_is_a_url_malformat() {
        // `:901-904` and `:912-915`, with both messages verbatim.
        let (outcome, log) = with_tracer(|tracer| {
            parse_parameters(Some(b"aws:amz"), b"localhost", tracer)
        });
        assert_eq!(outcome.map(|_| ()), Err(CURLcode::UrlMalformat));
        assert!(
            log.contains(
                "aws-sigv4: service missing in parameters and hostname"
            ),
            "log was:\n{log}"
        );

        let (outcome, log) = with_tracer(|tracer| {
            parse_parameters(Some(b"aws:amz"), b"s3.example", tracer)
        });
        assert_eq!(outcome.map(|_| ()), Err(CURLcode::UrlMalformat));
        assert!(
            log.contains("aws_sigv4: picked service s3 from host"),
            "the service is picked before the region fails; log was:\n{log}"
        );
        assert!(
            log.contains(
                "aws-sigv4: region missing in parameters and hostname"
            ),
            "log was:\n{log}"
        );

        // An empty hostname cannot supply a label at all.
        assert_eq!(
            params_of(Some(b"aws:amz"), b""),
            Err(CURLcode::UrlMalformat)
        );
    }

    #[test]
    fn the_two_picked_from_host_diagnostics_are_verbatim() {
        let (_outcome, log) = with_tracer(|tracer| {
            parse_parameters(
                Some(b"aws:amz"),
                b"s3.eu-west-2.amazonaws.com",
                tracer,
            )
        });
        assert!(log.contains("aws_sigv4: picked service s3 from host"));
        assert!(log.contains("aws_sigv4: picked region eu-west-2 from host"));
    }

    // The two preconditions.

    #[test]
    fn path_as_is_is_rejected_with_the_verbatim_message() {
        // `:850-853`.
        let credentials = Credentials::none();
        let headers: [&[u8]; 0] = [];
        let request = SigV4Request {
            path_as_is: true,
            ..base(&credentials, &headers)
        };
        let (outcome, log) = with_tracer(|tracer| sign(&request, 0, tracer));
        assert_eq!(outcome, Err(CURLcode::BadFunctionArgument));
        assert!(
            log.contains(
                "Cannot use sigv4 authentication with path-as-is flag"
            ),
            "log was:\n{log}"
        );
    }

    #[test]
    fn an_application_supplied_authorization_header_is_a_silent_no_op() {
        // `:855-858`: "Authorization already present, Bailing out" -- and the
        // C returns CURLE_OK, emitting nothing and setting nothing. Turning
        // this into an error would break every application that composes its
        // own header.
        let credentials = Credentials::new(Some(b"xxx"), Some(b"yyy"));
        let headers: [&[u8]; 1] = [b"Authorization: AWS4-HMAC-SHA256 mine"];
        let request = SigV4Request {
            path_as_is: false,
            ..base(&credentials, &headers)
        };
        let (outcome, log) = with_tracer(|tracer| sign(&request, 0, tracer));
        assert_eq!(outcome, Ok(None), "no emission at all, and no error");
        assert!(
            !log.contains("aws_sigv4"),
            "nothing is even computed; log was:\n{log}"
        );

        // The precondition order matters: `path_as_is` is tested FIRST, so it
        // wins over an application-supplied header.
        let request = SigV4Request {
            path_as_is: true,
            ..base(&credentials, &headers)
        };
        let (outcome, _log) = with_tracer(|tracer| sign(&request, 0, tracer));
        assert_eq!(outcome, Err(CURLcode::BadFunctionArgument));
    }

    // The emitted block, and `tests/data/test1976`.

    #[test]
    fn the_test1976_fixture_bytes_are_reproduced() {
        // `tests/data/test1976`, whose command is
        //
        //   -X PUT -H "X-Amz-Meta-Test-Two: test2" -H "x-amz-meta-test: test"
        //   --aws-sigv4 "aws:amz:us-east-1:s3" -u "xxx:yyy"
        //   http://%HOSTIP:%HTTPPORT/%TESTNUMBER
        let credentials = Credentials::new(Some(b"xxx"), Some(b"yyy"));
        let headers: [&[u8]; 2] =
            [b"X-Amz-Meta-Test-Two: test2", b"x-amz-meta-test: test"];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:s3"),
            host_header: Some(b"Host: 127.0.0.1:8990\r\n"),
            hostname: b"127.0.0.1",
            path: b"/1976",
            method: b"PUT",
            is_get_or_head: true,
            ..base(&credentials, &headers)
        };

        let (emission, _log) = with_tracer(|tracer| sign(&request, 0, tracer));
        let block = block_of(emission.expect("the fixture signs"));

        let (authorization, rest) = block
            .split_once("\r\n")
            .expect("the authorization line is terminated");
        let prefix = "Authorization: AWS4-HMAC-SHA256 \
                      Credential=xxx/19700101/us-east-1/s3/aws4_request, \
                      SignedHeaders=host;x-amz-content-sha256;x-amz-date;\
                      x-amz-meta-test;x-amz-meta-test-two, Signature=";
        assert!(
            authorization.starts_with(prefix),
            "authorization line was:\n{authorization}"
        );

        let signature = &authorization[prefix.len()..];
        assert_eq!(signature.len(), 64, "a SHA-256 in hexadecimal");
        assert!(
            signature.bytes().all(|digit| digit.is_ascii_digit()
                || (b'a'..=b'f').contains(&digit)),
            "the fixture's own pattern is [a-f0-9]{{64}}: {signature}"
        );

        // The remaining two lines, in the fixture's order, each with its own
        // terminator and no extra one.
        assert_eq!(
            rest,
            format!(
                "X-Amz-Date: 19700101T000000Z\r\n\
                 x-amz-content-sha256: {EMPTY_SHA256}\r\n"
            )
        );
    }

    #[test]
    fn the_block_carries_exactly_one_terminator_per_line() {
        // `date_header` and `content_sha256_hdr` already carry `\r\n`
        // (`:1087-1093`), so nothing appends another.
        let credentials = Credentials::new(Some(b"xxx"), Some(b"yyy"));
        let headers: [&[u8]; 0] = [];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:s3"),
            ..base(&credentials, &headers)
        };
        let (emission, _log) = with_tracer(|tracer| sign(&request, 0, tracer));
        let block = block_of(emission.expect("this request signs"));

        assert!(!block.contains("\r\n\r\n"), "block was {block:?}");
        assert_eq!(block.matches("\r\n").count(), 3);
        assert!(block.ends_with("\r\n"));
        // Three lines: authorization, date, content-sha256.
        assert_eq!(block.lines().count(), 3);
    }

    #[test]
    fn a_request_with_no_user_signs_with_an_empty_credential_name() {
        // `const char *user = data->state.aptr.user ? ... : "";` (`:844`).
        let credentials = Credentials::none();
        let headers: [&[u8]; 0] = [];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:iam"),
            ..base(&credentials, &headers)
        };
        let (emission, _log) = with_tracer(|tracer| sign(&request, 0, tracer));
        let block = block_of(emission.expect("this request signs"));
        assert!(
            block.starts_with(
                "Authorization: AWS4-HMAC-SHA256 \
                 Credential=/19700101/us-east-1/iam/aws4_request, "
            ),
            "block was {block}"
        );
    }

    #[test]
    fn the_provider_is_upper_cased_in_the_algorithm_and_the_secret() {
        // `Curl_strntoupper(&auth_headers[sizeof("Authorization: ") - 1], ...)`
        // (`:1106-1107`), and the same fold on the string to sign and the
        // secret.
        let credentials = Credentials::new(Some(b"key"), Some(b"secret"));
        let headers: [&[u8]; 0] = [];
        let request = SigV4Request {
            sigv4: Some(b"goog:goog:eu:storage"),
            ..base(&credentials, &headers)
        };
        let (emission, log) = with_tracer(|tracer| sign(&request, 0, tracer));
        let block = block_of(emission.expect("this request signs"));

        assert!(
            block.starts_with("Authorization: GOOG4-HMAC-SHA256 "),
            "block was {block}"
        );
        assert!(
            block.contains("/19700101/eu/storage/goog4_request,"),
            "the request type is lower-cased; block was {block}"
        );
        assert!(
            log.contains(
                "aws_sigv4: String to sign (enclosed in []) - \
                 [GOOG4-HMAC-SHA256\n"
            ),
            "log was:\n{log}"
        );
        assert!(
            block.contains("X-Goog-Date: 19700101T000000Z\r\n"),
            "the date header follows provider1; block was {block}"
        );
    }

    #[test]
    fn an_empty_header_list_reaches_the_signature_as_nil() {
        // Both `canonical_headers` and `signed_headers` are empty when the
        // application suppresses the host entry with a bare `Host:` and the
        // date entry with a bare `X-Amz-Date:`. `curl_maprintf()` then writes
        // `(nil)` for each. Absurd, reachable, and frozen.
        let credentials = Credentials::none();
        let headers: [&[u8]; 2] = [b"Host:", b"X-Amz-Date:"];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:iam"),
            ..base(&credentials, &headers)
        };
        let (emission, log) = with_tracer(|tracer| sign(&request, 0, tracer));
        let block = block_of(emission.expect("this request still signs"));

        assert!(
            log.contains(&format!(
                "aws_sigv4: Canonical request (enclosed in []) - [GET\n\
                 /\n\
                 \n\
                 (nil)\n\
                 (nil)\n\
                 {EMPTY_SHA256}]"
            )),
            "log was:\n{log}"
        );
        assert!(block.contains("SignedHeaders=(nil),"), "block was {block}");
        assert!(
            !block.contains("X-Amz-Date:"),
            "the application's own date header is not duplicated; block was \
             {block}"
        );
    }

    #[test]
    fn s3_paths_are_not_re_encoded_while_other_services_are() {
        // `should_urlencode(&service)` feeds `canon_path` (`:988-990`).
        let credentials = Credentials::none();
        let headers: [&[u8]; 0] = [];

        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:s3"),
            path: b"/bucket/a%2Fb",
            ..base(&credentials, &headers)
        };
        let (emission, log) = with_tracer(|tracer| sign(&request, 0, tracer));
        emission.expect("this request signs");
        assert!(
            log.contains("[GET\n/bucket/a%2Fb\n"),
            "an S3 path passes through; log was:\n{log}"
        );

        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:iam"),
            path: b"/bucket/a%2Fb",
            ..base(&credentials, &headers)
        };
        let (emission, log) = with_tracer(|tracer| sign(&request, 0, tracer));
        emission.expect("this request signs");
        assert!(
            log.contains("[GET\n/bucket/a%252Fb\n"),
            "every other service re-encodes; log was:\n{log}"
        );
    }

    // Secrets.

    #[test]
    fn no_credential_reaches_the_trace_output() {
        // The binding rule: no secret gains a path to a log that curl does not
        // already have. The password, the `AWS4`-prefixed material and the four
        // intermediate keys must never appear; the three diagnostics the C
        // emits must.
        let password = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let credentials =
            Credentials::new(Some(b"AKIDEXAMPLE"), Some(password));
        let headers: [&[u8]; 0] = [];
        let request = SigV4Request {
            sigv4: Some(b"aws:amz:us-east-1:iam"),
            hostname: b"iam.amazonaws.com",
            ..base(&credentials, &headers)
        };

        let (emission, log) =
            with_tracer(|tracer| sign(&request, VECTOR_EPOCH, tracer));
        let block = block_of(emission.expect("this request signs"));

        let secret_text = String::from_utf8_lossy(password).into_owned();
        assert!(!log.contains(&secret_text), "the password leaked:\n{log}");
        assert!(
            !log.contains(&format!("AWS4{secret_text}")),
            "the signing material leaked:\n{log}"
        );
        for key in [
            VECTOR_KEY_DATE,
            VECTOR_KEY_REGION,
            VECTOR_KEY_SERVICE,
            VECTOR_KEY_SIGNING,
        ] {
            assert!(!log.contains(key), "an intermediate key leaked:\n{log}");
            assert!(
                !block.contains(key),
                "an intermediate key leaked:\n{block}"
            );
        }

        // The three legitimate diagnostics ARE present.
        assert!(
            log.contains("aws_sigv4: Canonical request (enclosed in []) - [")
        );
        assert!(log.contains("aws_sigv4: String to sign (enclosed in []) - ["));
        assert!(log.contains("aws_sigv4: Signature - "));

        // And the string to sign, which the C logs, carries no secret: the
        // algorithm, the timestamp, the scope and a hash.
        assert!(!VECTOR_STRING_TO_SIGN.contains(&secret_text));

        // The username is NOT a secret: curl prints it in its own `--verbose`
        // diagnostic and puts it on the wire.
        assert!(block.contains("Credential=AKIDEXAMPLE/"));
    }

    #[test]
    fn the_secret_and_the_derived_keys_print_a_placeholder() {
        let secret = SigningSecret::new(b"aws", Some(b"topsecret"));
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("topsecret"), "{rendered}");
        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");

        let key = SigningKey([0xab; DIGEST_LEN]);
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("ab"), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");

        // The request's own formatter delegates to `Credentials`, whose
        // formatter redacts.
        let credentials = Credentials::new(Some(b"user"), Some(b"topsecret"));
        let headers: [&[u8]; 1] = [b"X-Amz-Meta: value"];
        let request = base(&credentials, &headers);
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("topsecret"), "{rendered}");
        assert!(rendered.contains(REDACTED_PLACEHOLDER), "{rendered}");
        assert!(rendered.contains("X-Amz-Meta: value"), "{rendered}");

        // And `Parameters`, which holds nothing secret, renders as text.
        let params = Parameters {
            provider0: b"aws",
            provider1: b"amz",
            region: b"eu",
            service: b"s3",
        };
        assert!(format!("{params:?}").contains("provider0"));
    }

    /// A credential-bearing header supplied through `CURLOPT_HTTPHEADER` must
    /// not reach the formatted request.
    ///
    /// `headers` is whatever the application handed curl, so it can hold any
    /// field at all. The three asserted here are the ones this crate's own
    /// classifier names, and each is a real leak if printed: `Authorization` is
    /// the credential, `Cookie` is a session identifier, and
    /// `X-Amz-Security-Token` is a live AWS session credential.
    #[test]
    fn a_credential_bearing_header_is_not_printed() {
        let credentials =
            Credentials::new(Some(b"AKIDEXAMPLE"), Some(b"wJalr"));
        let headers: [&[u8]; 4] = [
            b"Authorization: AWS4-HMAC-SHA256 Credential=leaked-signature",
            b"Cookie: session=deadbeefcafe",
            b"X-Amz-Security-Token: FQoDYXdzEO-live-token",
            b"Content-Type: application/json",
        ];
        let request = base(&credentials, &headers);
        let rendered = format!("{request:?}");

        // None of the three values appears.
        assert!(!rendered.contains("leaked-signature"), "{rendered}");
        assert!(!rendered.contains("deadbeefcafe"), "{rendered}");
        assert!(!rendered.contains("FQoDYXdzEO-live-token"), "{rendered}");

        // The NAMES stay, because a reader needs to know the field was there,
        // and the marker says why the value is missing.
        assert!(rendered.contains("Authorization:"), "{rendered}");
        assert!(rendered.contains("Cookie:"), "{rendered}");
        assert!(rendered.contains("X-Amz-Security-Token:"), "{rendered}");
        assert!(rendered.contains(crate::util::redact::MARKER), "{rendered}");

        // An ordinary header is still legible: over-redacting would trade a
        // real debugging capability for no additional confidentiality.
        assert!(rendered.contains("application/json"), "{rendered}");
    }

    /// A presigned URL's `X-Amz-Signature` must not reach the formatted
    /// request, and the rest of the query must.
    #[test]
    fn a_presigned_query_does_not_disclose_its_signature() {
        let credentials =
            Credentials::new(Some(b"AKIDEXAMPLE"), Some(b"wJalr"));
        let headers: [&[u8]; 0] = [];
        let mut request = base(&credentials, &headers);
        request.query = Some(
            b"X-Amz-Algorithm=AWS4-HMAC-SHA256\
              &X-Amz-Credential=AKIDEXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request\
              &X-Amz-Date=20130524T000000Z\
              &X-Amz-Expires=86400\
              &X-Amz-SignedHeaders=host\
              &X-Amz-Security-Token=live-session-token\
              &X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
        );
        let rendered = format!("{request:?}");

        // The two authenticating values are gone.
        assert!(
            !rendered.contains(
                "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
            ),
            "{rendered}"
        );
        assert!(!rendered.contains("live-session-token"), "{rendered}");
        assert!(rendered.contains("X-Amz-Signature="), "{rendered}");
        assert!(rendered.contains("X-Amz-Security-Token="), "{rendered}");

        // Everything a reader needs in order to diagnose a signature mismatch
        // stays: the algorithm, the scope, the timestamp, the expiry and the
        // signed-header list. The access key ID stays too -- it is the username,
        // which this crate prints in the clear elsewhere.
        assert!(rendered.contains("AWS4-HMAC-SHA256"), "{rendered}");
        assert!(rendered.contains("AKIDEXAMPLE%2F20130524"), "{rendered}");
        assert!(rendered.contains("20130524T000000Z"), "{rendered}");
        assert!(rendered.contains("X-Amz-Expires=86400"), "{rendered}");
        assert!(rendered.contains("X-Amz-SignedHeaders=host"), "{rendered}");
    }

    /// The shapes that have no value to disclose are rendered whole rather than
    /// mangled.
    #[test]
    fn valueless_header_and_query_shapes_survive_redaction() {
        let credentials = Credentials::new(None, None);
        // `-H "Name;"` -- the send-an-empty-header form, which has no colon.
        let headers: [&[u8]; 1] = [b"X-Amz-Meta"];
        let mut request = base(&credentials, &headers);
        // A bare query parameter with no `=`, and one with an empty value.
        request.query = Some(b"acl&versionId=");
        let rendered = format!("{request:?}");

        assert!(rendered.contains("X-Amz-Meta"), "{rendered}");
        assert!(rendered.contains("acl&versionId="), "{rendered}");
        assert!(
            !rendered.contains(crate::util::redact::MARKER),
            "nothing here is sensitive: {rendered}"
        );

        // A header value that is not valid UTF-8 still renders rather than
        // making the formatter the thing that fails.
        let raw: [&[u8]; 1] = [b"X-Amz-Meta: \xff\xfe"];
        let request = base(&credentials, &raw);
        assert!(format!("{request:?}").contains("X-Amz-Meta:"));
    }

    // Byte-level helpers.

    #[test]
    fn until_nul_reproduces_the_c_strings_implicit_truncation() {
        assert_eq!(until_nul(b"abc"), b"abc");
        assert_eq!(until_nul(b"abc\0def"), b"abc");
        assert_eq!(until_nul(b"\0abc"), b"");
        assert_eq!(until_nul(b""), b"");
    }

    #[test]
    fn header_name_stops_at_the_first_colon() {
        assert_eq!(header_name(b"host:example.com"), b"host");
        assert_eq!(header_name(b"host:a:b"), b"host");
        assert_eq!(header_name(b"host:"), b"host");
        assert_eq!(header_name(b"host"), b"host");
        assert_eq!(header_name(b":value"), b"");
    }

    #[test]
    fn dyn_or_nil_substitutes_only_for_an_empty_buffer() {
        let mut empty = buffer();
        assert_eq!(dyn_or_nil(&empty), NIL_STRING);
        empty.addn(b"x").expect("one byte fits");
        assert_eq!(dyn_or_nil(&empty), b"x");
    }
}
