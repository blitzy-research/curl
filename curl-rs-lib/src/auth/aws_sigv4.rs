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
//! Supersedes `lib/http_aws_sigv4.c` (1,128 lines) in full, and backs
//! `CURLOPT_AWS_SIGV4` and the `--aws-sigv4` command-line flag.
//!
//! Every artefact this module produces reaches the wire or the signature, so
//! all of it is frozen behaviour (AAP 0.8.1): the canonical request, the
//! string to sign, the five keyed digests, and the `Authorization:` header
//! line together with the two extra header lines that accompany it.
//! `tests/getpart.pm:351` joins a fixture's expectation and the observed
//! bytes into one string and compares them whole -- no per-line matching, no
//! normalization, no reordering -- so one wrong byte, one mis-sorted header
//! or one upper-case hexadecimal digit fails the comparison outright.
//!
//! # Where each behaviour comes from
//!
//! Line numbers are measured against `lib/http_aws_sigv4.c` as checked out at
//! commit `54cf587b9c`:
//!
//! | C site | What it fixes | Here |
//! |--------|---------------|------|
//! | `:41-51`     | the `HMAC_SHA256` macro over `Curl_hmacit` | [`sign`]'s five digests |
//! | `:53`        | `TIMESTAMP_SIZE 17` | [`TIMESTAMP_SIZE`] |
//! | `:56`        | `SHA256_HEX_LENGTH` | [`SHA256_HEX_LENGTH`] |
//! | `:58`        | `MAX_QUERY_COMPONENTS 128` | [`MAX_QUERY_COMPONENTS`] |
//! | `:65-69`     | `sha256_to_hex`, the LOWER-case encoder | [`sha256_to_hex`] |
//! | `:71-78`     | `find_date_hdr`, provider key then plain `Date` | [`find_date_hdr`] |
//! | `:80-116`    | `trim_headers`, the whitespace rules | [`trim_header`] |
//! | `:150-197`   | `split_to_dyn_array`, splitting on `&` | [`split_query`] |
//! | `:199-202`   | `is_reserved_char` | [`is_reserved_char`] |
//! | `:204-223`   | `uri_encode_path`, UPPER-case hexadecimal | [`uri_encode_path`] |
//! | `:228-264`   | `normalize_query`, the `%2B` rule | [`normalize_query`] |
//! | `:266-281`   | `should_urlencode`, the three S3 services | [`should_urlencode`] |
//! | `:284-288`   | `MAX_SIGV4_LEN` and the date-header lengths | [`MAX_SIGV4_LEN`] |
//! | `:292-319`   | `compare_header_names`, shorter name first | [`compare_header_names`] |
//! | `:324-370`   | `merge_duplicate_headers`, comma joining | [`merge_duplicate_headers`] |
//! | `:373-548`   | `make_headers`, canonicalization end to end | [`make_headers`] |
//! | `:550-552`   | the content-sha256 buffer lengths | [`CONTENT_SHA256_KEY_LEN`] |
//! | `:555-585`   | `parse_content_sha_hdr` | [`parse_content_sha_hdr`] |
//! | `:587-605`   | `calc_payload_hash` | [`calc_payload_hash`] |
//! | `:607`       | `S3_UNSIGNED_PAYLOAD` | [`S3_UNSIGNED_PAYLOAD`] |
//! | `:609-644`   | `calc_s3_payload_hash` | [`calc_s3_payload_hash`] |
//! | `:646-681`   | `compare_func`, the query-component order | [`compare_query_pairs`] |
//! | `:683-707`   | `canon_path` | [`canon_path`] |
//! | `:709-812`   | `canon_query` | [`canon_query`] |
//! | `:850-858`   | the two preconditions | [`sign`] |
//! | `:866-919`   | parameter parsing and hostname derivation | [`parse_parameters`] |
//! | `:947-965`   | the clock and `strftime` | [`format_timestamp`] |
//! | `:995-1010`  | the canonical request | [`sign`] |
//! | `:1015-1030` | `request_type` and the credential scope | [`request_type`] |
//! | `:1044-1058` | the string to sign | [`sign`] |
//! | `:1063-1077` | the secret and the five digests | [`SigningSecret`] |
//! | `:1083-1107` | the emitted header block | [`sign`] |
//!
//! Two further sites outside that file are load-bearing. `lib/escape.c:200`
//! documents `Curl_hexencode` as producing "lowercase hex-encoded ASCII" and
//! indexes `Curl_ldigits`, while `:222` documents `Curl_hexbyte` as "a
//! two-digit UPPERCASE hex number" and indexes `Curl_udigits`; this module
//! needs BOTH and must never unify them. And `lib/http.c:642-644` guards the
//! only call site with `&& !proxy`, commented "this method is never for
//! proxy".
//!
//! # AWS SigV4 is never used for a proxy, and that is an invariant here
//!
//! `Curl_output_aws_sigv4()` takes no `proxy` parameter, writes
//! `data->state.aptr.userpwd` unconditionally, and sets
//! `data->state.authhost.done` -- the origin state, never the proxy one
//! (`lib/http_aws_sigv4.c:1109-1111`). The guard that keeps it that way lives
//! in `super::select_emitter`, whose `AWS_SIGV4` arm carries `&& !proxy`. So
//! there is no `proxy` field in [`SigV4Request`] and no runtime test for it
//! anywhere below: the shape of this module's API makes
//! `Proxy-Authorization: AWS4-HMAC-SHA256` unrepresentable rather than
//! merely unreachable.
//!
//! # This module has no challenge handler, and no [`super::HttpAuthMechanism`]
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
//! # Bytes, not text
//!
//! Every internal buffer is `Vec<u8>` or `&[u8]`. The C works on
//! NUL-terminated byte strings whose contents come from a URL, a query string
//! and application-supplied headers -- all attacker-influenced -- and none of
//! it is required to be UTF-8. Byte slices also remove a hazard that text
//! would add: this module indexes a header at the offset of its colon and
//! rewrites the third byte of a key, and both operations panic on a `&str`
//! when the offset lands inside a multi-byte character. [`until_nul`]
//! reproduces the C's implicit `strlen`/`strchr` truncation at the points
//! where the C relies on it, and the only conversions to text are the three
//! diagnostics and the emitted header block, each of which is lossy and says
//! so.
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
use std::env;

use crate::crypto::hmac::hmac_sha256;
use crate::crypto::sha256::{sha256, DIGEST_LEN};
use crate::error::CURLcode;
use crate::trace::{failf, infof, Tracer};
use crate::url::escape::{hexbyte, hexencode};
use crate::util::dynbuf::DynBuf;
use crate::util::strcase::{ncasecompare, raw_tolower, raw_toupper};
use crate::util::strparse::{
    hexval, is_alnum, is_blank, is_urlpunct, is_xdigit, str_casecompare,
    str_cmp, str_passblanks, str_single, str_until,
};
use crate::util::timeval::{gmtime, Clock};

use super::{AuthEmission, Credentials, REDACTED_PLACEHOLDER};

// ---------------------------------------------------------------------------
// Constants. Every one of these is a C `#define` with its site recorded.
// ---------------------------------------------------------------------------

/// `TIMESTAMP_SIZE` (`lib/http_aws_sigv4.c:53`): the size of the buffer that
/// holds `YYYYMMDDTHHMMSSZ`.
///
/// Seventeen, because the C counts the terminator. The string itself is
/// [`TIMESTAMP_LEN`] = 16 bytes, and that 16 is load-bearing twice over: it
/// is the length `strftime` must produce, and it is the exact length an
/// application-supplied date header has to have before `make_headers()` will
/// adopt it (`:493`).
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
///
/// A security bound, not a capacity hint. The C declares
/// `struct dynbuf query_array[MAX_QUERY_COMPONENTS]` and errors with
/// `CURLE_TOO_LARGE` the moment the count REACHES this value (`:174-177` and
/// `:190-191`), so at most 127 components are ever accepted. See
/// [`split_query`], which reproduces the off-by-one exactly.
pub(crate) const MAX_QUERY_COMPONENTS: usize = 128;

/// `MAX_SIGV4_LEN` (`lib/http_aws_sigv4.c:284`): 64 bytes per component.
///
/// The C's own comment is "maximum length for the aws sivg4 parts". It caps
/// each of `provider0`, `provider1`, `region` and `service`, whether they
/// come from the option string or are derived from the hostname. A component
/// of exactly 64 bytes is accepted; 65 is not, because
/// `curlx_str_until()` fails once the count passes `max`
/// (`lib/curlx/strparse.c:50-52`).
pub(crate) const MAX_SIGV4_LEN: usize = 64;

/// `DATE_HDR_KEY_LEN` (`lib/http_aws_sigv4.c:285`):
/// `MAX_SIGV4_LEN + sizeof("X--Date")`.
///
/// C's `sizeof` on a string literal counts the terminator, which is why the
/// `+ 1` appears below. The widest key this admits is `X-` plus 64 bytes plus
/// `-Date` plus a terminator, which is exactly 72 -- so the C's buffer is
/// sized to the byte with nothing to spare.
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

/// The environment variable that pins the signing clock to the Unix epoch.
///
/// `lib/http_aws_sigv4.c:947-957` reads it through `getenv()` and, when it is
/// set to anything at all, signs as though the time were zero.
const FORCETIME_ENV: &str = "CURL_FORCETIME";

// Value contracts, evaluated during compilation.
//
// These pin what the C fixes, and they double as the reference that keeps
// every constant above referenced: a `pub(crate)` constant with no consumer
// is `dead_code`, and the build gate admits no warnings. A sibling that
// "simplifies" one of these values breaks the build here, beside the citation
// that explains why it cannot change.
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

// ---------------------------------------------------------------------------
// The request description: what `Curl_output_aws_sigv4()` reads out of the
// easy handle, gathered into one argument.
// ---------------------------------------------------------------------------

/// Everything this signature covers.
///
/// The C reads fourteen fields off `struct Curl_easy` and `struct
/// connectdata`; each becomes a field here, named for the C expression it
/// stands for so that a reader can check the two side by side. Passing them
/// as one structure rather than as fourteen parameters is not only a matter of
/// taste: `clippy.toml` sets `too-many-arguments-threshold = 9`.
///
/// There is deliberately no `proxy` field. See the module documentation.
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
    ///
    /// Passed as the complete line because that is what the C truncates:
    /// `strcspn(data->state.aptr.host, "\n\r")` at `:407`, with the comment
    /// "remove /r/n as the separator for canonical request must be '\n'".
    /// [`None`] is the state `http_set_aptr_host()` leaves behind when the
    /// application supplied a bare `Host:` (`lib/http.c:2044-2049`).
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
    ///
    /// This is NOT redundant with [`Self::is_get_or_head`]:
    /// `CURLOPT_CUSTOMREQUEST` replaces the token while leaving
    /// `data->state.httpreq` alone, so `curl -X PUT` with no body signs the
    /// method `PUT` with the empty-payload rule of a `GET`. `tests/data/test1976`
    /// depends on exactly that combination.
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
    /// of integers.
    ///
    /// Nothing printed here is a secret. The option string, the headers, the
    /// host, the path and the query all go on the wire, and
    /// [`Credentials`]'s own formatter prints
    /// [`REDACTED_PLACEHOLDER`] in place of the password -- which is why this
    /// delegates to it rather than reaching for its fields.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<String> = self
            .headers
            .iter()
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect();
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
            .field("query", &self.query.map(String::from_utf8_lossy))
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
///
/// `lib/http_aws_sigv4.c:1063-1069` builds it as `"%.*s4%s"` over
/// `provider0` and `data->state.aptr.passwd`, then upper-cases the
/// `provider0` part in place. It is a secret in its entirety -- it CONTAINS
/// the password -- so the type exists to make sure it cannot be printed by
/// accident. Nothing reads the material except [`Self::key_material`], and
/// its only caller is the first of the five keyed digests.
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

// ---------------------------------------------------------------------------
// Small shared helpers.
// ---------------------------------------------------------------------------

/// The C-string view of `bytes`: everything before the first zero byte.
///
/// The C reaches every one of these inputs through `strlen()`, `strchr()` or
/// `strcspn()`, all of which stop at the terminator. Applying that here keeps
/// a zero byte in an application-supplied header or URL from changing what is
/// signed relative to the C, and it costs nothing for the inputs that have no
/// zero byte -- which is all of them, since each arrives as a C string.
/// `crate::util::strparse`'s own `str_until` stops at zero for the same
/// reason (`lib/curlx/strparse.c:48`).
fn until_nul(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&byte| byte == 0) {
        Some(at) => &bytes[..at],
        None => bytes,
    }
}

/// A buffer's contents, or [`NIL_STRING`] when it is empty.
///
/// `curlx_dyn_ptr()` returns `s->bufr`, which is null until the first append,
/// and `lib/http_aws_sigv4.c:995-1008` hands three such pointers straight to
/// `curl_maprintf()`. Only the canonical query is guarded there, written
/// `curlx_dyn_ptr(&canonical_query) ? ... : ""`, so the other three print
/// `(nil)` when empty. Reachable: an application that supplies a bare `Host:`
/// AND a bare `X-Amz-Date:` has both suppressed as removal directives and
/// leaves the header list empty, whereupon the canonical request really does
/// contain `(nil)\n(nil)`. Faithfulness wins over tidiness here, because
/// those five bytes are inside a signature.
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
///
/// The C's macro name carries a typo -- `ISURLPUNTCS` -- and its definition
/// at `lib/curl_ctype.h:47-48` is exactly four bytes: `-`, `.`, `_` and `~`.
/// Together with the ASCII alphanumerics that is RFC 3986's unreserved set,
/// which is why the C's own comment at `:211` says "unreserved chars from RFC
/// 3986" even though the function is called `is_reserved_char`.
/// `crate::util::strparse::is_unreserved` is the same composition; the two
/// primitives are spelled out here so that this reads as the C does.
fn is_reserved_char(byte: u8) -> bool {
    is_alnum(byte) || is_urlpunct(byte)
}

/// `Curl_checkheaders` (`lib/transfer.c:84-99`): the application's own header
/// line with this name, if it supplied one.
///
/// The match is a case-insensitive comparison of `name.len()` bytes followed
/// by a separator test, and the separator is `:` OR `;` -- `Curl_headersep`
/// at `lib/transfer.h:26`. That second spelling matters here: a bare
/// `X-Amz-Date;` MATCHES, and [`make_headers`] then finds no colon in it and
/// fails the way the C does.
///
/// The FIRST match wins, as in the C.
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

// ---------------------------------------------------------------------------
// The path and the query. `lib/http_aws_sigv4.c:199-281` and `:683-812`.
// ---------------------------------------------------------------------------

/// `uri_encode_path` (`lib/http_aws_sigv4.c:204-223`).
///
/// Keeps a byte when it is unreserved or a slash, and percent-escapes
/// everything else with UPPER-case hexadecimal. It does NOT decode: a `%` is
/// not unreserved, so an already-escaped path is escaped again --
/// `%3A` becomes `%253A`, which `tests/unit/unit1979.c`'s "test-s3-tables"
/// case pins.
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
///
/// An INVALID escape is not an error: `%zz` fails the triplet test, so the
/// `%` is treated as an ordinary byte and becomes `%25`.
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
/// False for exactly three service names and true for everything else. The
/// C's comment records why: "These services require unmodified (not
/// additionally URL-encoded) URL paths. [...] Urls are already normalized by
/// the curl URL parser."
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
/// for an empty result. The C's comment on the sizing -- "Normalized path
/// will be either the same or shorter than the original path, plus trailing
/// slash" -- is about its buffer arithmetic and has no successor here.
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
///
/// The C's own comment is "If one element is empty, the other is always sorted
/// higher", and the four early exits it produces are reproduced exactly --
/// including the one that matters: when BOTH keys are empty the function
/// returns 0 **without looking at the values at all**.
///
/// Why the empty tests exist at all: `curlx_dyn_ptr()` is null for a buffer
/// that was never appended to, and `strcmp()` would dereference it. An empty
/// key is reachable -- the component `=x` has one -- so this is a real branch,
/// not defensive noise.
///
/// One representational note. The C gives a component with no value a buffer
/// holding a single zero byte (`:772-773`), so `aa_value_len == 0` never
/// actually fires there, and `strcmp()` compares that buffer as the empty
/// string. An empty `Vec` here reaches the same ordering by the empty-tests
/// route: empty sorts before anything, and two empties compare equal, which is
/// what `strcmp("", "")` and `strcmp("", "x")` answer.
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
/// Split on `&`, normalize each key and value independently, sort by key then
/// value, and re-join with `&` -- always as `key=value`, and always with the
/// `=` even when there is no value.
///
/// # A stable sort where the C uses `qsort`
///
/// `qsort` is not stable, and [`compare_query_pairs`] can return `Equal` for
/// two DIFFERENT components: two whose keys are both empty. The C's output is
/// then unspecified. A stable sort makes it the input order, which is one of
/// the orders `qsort` may produce and is the only one that is reproducible.
/// Performance is a non-goal (AAP 0.1.1), so nothing is lost by choosing it.
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

// ---------------------------------------------------------------------------
// Header canonicalization. `lib/http_aws_sigv4.c:80-116`, `:292-370` and
// `:373-548`.
// ---------------------------------------------------------------------------

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
///
/// The value is **not** case-folded. `Authorization` covers the value
/// verbatim, so folding it would change the signature and, for a header such
/// as `x-amz-meta-Test: Value`, would change what the server stores.
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
///
/// Case-sensitive is correct rather than incidental: every entry has already
/// been through [`trim_header`], so every name is lower-case by the time this
/// runs.
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
/// The C's comment is the specification: "Merge duplicate header definitions
/// by comma delimiting their values in the order defined the headers are
/// defined, expecting headers to be alpha-sorted and use ':' at this point."
///
/// The walk stays on a merged entry rather than advancing, so a run of three
/// or more same-named headers folds into one entry with two commas.
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
///
/// So the provider is lower-cased and then its first byte is upper-cased --
/// the C's comment calls it "provider1 ucfirst". `amz` gives `X-Amz-Date`
/// whatever case the option string used.
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
/// The entries are gathered in the C's order -- host, content-sha256, the
/// application's own headers, then the canonical date header -- trimmed,
/// sorted, merged, and finally rendered into the two buffers. The order they
/// are GATHERED in is what a stable sort preserves for same-named entries, so
/// it is part of the contract rather than an implementation detail.
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
    //
    //    user headers with a value of whitespace only, or without a colon or
    //    semi-colon, are not added to this list."
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

// ---------------------------------------------------------------------------
// The payload hash. `lib/http_aws_sigv4.c:555-644`.
// ---------------------------------------------------------------------------

/// `parse_content_sha_hdr` (`lib/http_aws_sigv4.c:555-585`): the payload hash
/// the application supplied, if it supplied one.
///
/// The key is `x-<provider1>-content-sha256`, built with the provider
/// VERBATIM -- the C applies no case folding here, and none is needed because
/// [`checkheaders`] compares case-insensitively.
///
/// The value is taken after the colon with leading blanks skipped and trailing
/// blanks trimmed, and is then used exactly as it stands: an application may
/// legitimately pass `UNSIGNED-PAYLOAD`, `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
/// or a hash of its own, so nothing about the shape is validated.
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
///
/// A negative `postfieldsize` means "measure it with `strlen`", which is how
/// `CURLOPT_POSTFIELDS` behaves when the application never set a size. An
/// absent body is an empty one: the C calls `Curl_sha256it(hash, NULL, 0)`,
/// which hashes nothing at all.
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
///
/// A request with no body in memory hashes the EMPTY input, which is
/// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` --
/// the value `tests/data/test1976` expects in its
/// `x-amz-content-sha256` header.
fn calc_payload_hash(request: &SigV4Request<'_>) -> String {
    sha256_to_hex(&sha256(post_data(request)))
}

/// `calc_s3_payload_hash` (`lib/http_aws_sigv4.c:609-644`): the payload hash
/// for an S3 request, and the header that has to carry it.
///
/// The C's comment explains why S3 is special: "AWS S3 requires a
/// x-amz-content-sha256 header, and supports special values like
/// UNSIGNED-PAYLOAD" (`:928-929`).
///
/// Three predicates decide, and the C names each of them:
///
/// ```text
/// empty_method  = (httpreq == HTTPREQ_GET || httpreq == HTTPREQ_HEAD);
/// empty_payload = (empty_method || data->set.filesize == 0);
/// post_payload  = (httpreq == HTTPREQ_POST && data->set.postfields);
/// ```
///
/// A real hash is computed when the payload is known to be empty or is a POST
/// body already in memory -- "Calculate a real hash when we know the request
/// payload". Everything else falls back to the literal
/// [`S3_UNSIGNED_PAYLOAD`], because hashing it would mean reading a body curl
/// is about to stream.
///
/// The header is `x-<provider1>-content-sha256: <hash>`, with a SPACE after
/// the colon and with the provider **verbatim** -- the C applies no case
/// folding at `:638-639`, unlike the date header, which folds twice.
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

// ---------------------------------------------------------------------------
// The clock. `lib/http_aws_sigv4.c:947-965`.
// ---------------------------------------------------------------------------

/// Whether [`FORCETIME_ENV`] asks for the epoch.
///
/// The C reads it with `getenv()` and only tests for presence, so any value --
/// including an empty one -- forces the clock.
fn forced_epoch_requested() -> bool {
    env::var_os(FORCETIME_ENV).is_some()
}

/// The instant to sign for: zero when the epoch is forced, otherwise the
/// injected clock's wall reading.
///
/// The C is
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
/// **The environment variable is honoured unconditionally here, not behind a
/// build flag,** and that is a deliberate, recorded decision rather than an
/// oversight. `tests/runner.pm:167` sets `CURL_FORCETIME=1` for every test run
/// -- its comment says "for debug NTLM magic", but it governs this code path
/// too -- so under the harness the timestamp is literally `19700101T000000Z`
/// and the credential-scope date is `19700101`. Every AWS SigV4 fixture
/// depends on that, `tests/data/test1976` included. AAP 0.6.6 deliberately
/// withholds the `Debug` capability from the `--version` banner, so a
/// `DEBUGBUILD`-only seam would leave the whole corpus unreachable rather than
/// merely skipped. Honouring the variable always is the minimal change that
/// keeps it reachable. Do not "harden" this into a feature gate without
/// replacing the fixtures' only route to a deterministic timestamp.
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
/// Sixteen bytes for any year this millennium: `19700101T000000Z`. The
/// conversion itself is `crate::util::timeval::gmtime`, which is this crate's
/// only calendar conversion and the successor of `curlx_gmtime`; its `mon` is
/// 0-based, as C's `tm_mon` is, and its `year` is absolute rather than C's
/// years-since-1900.
///
/// No date-formatting crate is used. `httpdate 1.0.3` is pinned in the
/// workspace but produces the HTTP date format, which is a different
/// specification, and nothing else in `[workspace.dependencies]` formats a
/// calendar date.
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
/// All seven are reproduced here. None of the exotic ones is reachable from
/// `time(NULL)` on a working host, but a signature is not the place to
/// approximate, and the difference is visible: a padded year would sign
/// `00001231T235959Z` where the C signs `01231T235959Z`.
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

// ---------------------------------------------------------------------------
// Parameter parsing. `lib/http_aws_sigv4.c:866-919`.
// ---------------------------------------------------------------------------

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
/// The grammar is `provider0[:provider1[:region[:service]]]`, and each
/// component is at most [`MAX_SIGV4_LEN`] bytes. An absent option value, or an
/// empty one, is [`DEFAULT_SIGV4`].
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
    //
    // Written as nesting because that is what the two `||` chains mean: each
    // step runs only if every step before it succeeded, and each successful
    // step has already stored its span.
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

// ---------------------------------------------------------------------------
// The signer. `Curl_output_aws_sigv4()`, `lib/http_aws_sigv4.c:814-1126`.
// ---------------------------------------------------------------------------

/// Signs a request with AWS Signature Version 4 and returns the header block
/// to emit.
///
/// Supersedes `Curl_output_aws_sigv4()` (`lib/http_aws_sigv4.c:814-1126`), the
/// whole of it. There is no proxy form of this signature; see the module
/// documentation.
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
/// # The header block is not one header
///
/// It is up to three lines, each already terminated: the `Authorization:`
/// line, then the date header when curl supplies it rather than the
/// application, then the S3 content-sha256 header when there is one. The C
/// assembles exactly this and hands it to the request writer as
/// `aptr.userpwd`, whose contents are inserted verbatim. Do not append a
/// further terminator.
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
    //
    // The canonical-headers block already ends in `\n`, so the separator after
    // it produces a BLANK LINE. That blank line is part of the specification;
    // trimming it changes the signature.
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

    infof!(
        tracer,
        "aws_sigv4: Canonical request (enclosed in []) - [{}]",
        String::from_utf8_lossy(&canonical_request)
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
    infof!(tracer, "aws_sigv4: Signature - {}", signature);

    // `:1083-1107`:
    //
    //   "Authorization: %.*s4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s,
    //    Signature=%s\r\n%s%s"
    //
    // with `provider0` upper-cased in place from
    // `sizeof("Authorization: ") - 1`. The separators are wire bytes: a `/`
    // between the user and the credential scope, `, ` -- comma and one space --
    // between the three components, and `=` with no space around it.
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

    // -----------------------------------------------------------------------
    // The published AWS Signature Version 4 example.
    //
    // Access key `AKIDEXAMPLE`, secret
    // `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, service `iam`, region
    // `us-east-1`, instant `20150830T123600Z`. Every value below is from that
    // published example and was additionally recomputed with an independent
    // HMAC-SHA-256 implementation before being written down.
    //
    // BOTH CREDENTIALS ARE AWS'S OWN PUBLISHED, NON-FUNCTIONAL EXAMPLE VALUES
    // and are not secrets: `AKIDEXAMPLE` is deliberately not a well-formed
    // access-key identifier -- those begin `AKIA` or `ASIA` and are twenty
    // characters -- and the secret ends in `EXAMPLEKEY` for the same reason.
    // They are reproduced verbatim because the expected signature below is
    // only reachable from exactly these bytes, which is the whole point of a
    // published vector.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Harness.
    // -----------------------------------------------------------------------

    /// Runs `body` with a verbose tracer and returns its result together with
    /// everything the sink received, as text.
    ///
    /// `WriterSink::new` rather than `new_for_terminal`: the byte-faithful
    /// form is what an assertion on exact text needs, because the terminal
    /// form escapes control bytes -- and the canonical request is full of
    /// newlines.
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

    // -----------------------------------------------------------------------
    // The published vector, end to end.
    // -----------------------------------------------------------------------

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

        // The three diagnostics, verbatim -- and the canonical request and the
        // string to sign are asserted THROUGH them, because that is the only
        // place the C exposes either.
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
        assert!(
            log.contains(&format!("aws_sigv4: Signature - {VECTOR_SIGNATURE}")),
            "signature mismatch; log was:\n{log}"
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

    // -----------------------------------------------------------------------
    // The clock.
    // -----------------------------------------------------------------------

    #[test]
    fn a_forced_epoch_gives_the_timestamp_every_fixture_expects() {
        // `tests/runner.pm:167` sets `CURL_FORCETIME=1` for every test run, so
        // the harness always signs at the epoch.
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

    // -----------------------------------------------------------------------
    // The path and the query. The two tables below are `tests/unit/unit1979.c`
    // and `tests/unit/unit1980.c`, relocated.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Header canonicalization.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // The payload hash.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Parameter parsing.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // The two preconditions.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // The emitted block, and `tests/data/test1976`.
    // -----------------------------------------------------------------------

    #[test]
    fn the_test1976_fixture_bytes_are_reproduced() {
        // `tests/data/test1976`, whose command is
        //
        //   -X PUT -H "X-Amz-Meta-Test-Two: test2" -H "x-amz-meta-test: test"
        //   --aws-sigv4 "aws:amz:us-east-1:s3" -u "xxx:yyy"
        //   http://%HOSTIP:%HTTPPORT/%TESTNUMBER
        //
        // and whose `<protocol>` block expects the three lines asserted below.
        // The fixture strips the signature with
        // `s/Signature=[a-f0-9]{64}/Signature=stripped/` -- "We only care
        // about header order in this test" -- so this asserts the shape of the
        // signature rather than its value, exactly as the fixture does. Note
        // that `-X PUT` leaves `httpreq` at `HTTPREQ_GET`, which is why the
        // payload hash is the empty one.
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

    // -----------------------------------------------------------------------
    // Secrets.
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Byte-level helpers.
    // -----------------------------------------------------------------------

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
