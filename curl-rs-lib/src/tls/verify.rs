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

//! Certificate trust, revocation, hostname checking and certificate
//! introspection: supersedes `lib/vtls/x509asn1.c` and
//! `lib/vtls/hostcheck.c`, plus the trust-and-client-auth half of
//! `lib/vtls/rustls.c`.
//!
//! Both halves of that sentence are expressed as types here rather than as
//! prose: [`VerifyPolicy::default`] enables the peer-chain and the hostname
//! check together, and the single private constructor named in the next
//! paragraph is the only way to reach a configuration that does not.
//!
//! One reachability fact belongs with that, because the code below implements a
//! commonName fallback and a reader will want to know when it runs. rustls
//! REQUIRES a subjectAltName, so a certificate carrying only a commonName fails
//! the handshake before this module's own check is consulted. That matches the
//! oracle rather than diverging from it: `Curl_verifyhost` occurs exactly once
//! in `lib/` -- a declaration at `lib/vtls/x509asn1.h:76` with no definition and
//! no caller -- `lib/vtls/rustls.c` hands the name to rustls at `:1091` and
//! keeps its answer, and the commonName fallback lives only in
//! `lib/vtls/openssl.c:2176-2246`, a backend section 0.2.2 drops. The arm here
//! is retained because this module owns the whole of that function's shape and
//! because the same parsing feeds `CURLINFO_CERTINFO`, not because a
//! commonName-only certificate can reach it through the rustls backend.
//!
//! # Certificate introspection is bounded, and the bounds are the C's
//!
//! `CURLINFO_CERTINFO` is built by a parser, not by a hex dump, and
//! `lib/vtls/x509asn1.c` fixes every limit it works under: an ASN.1 object
//! is at most `CURL_ASN1_MAX` = 256 KiB (`x509asn1.c:51`), recursion at most
//! `CURL_ASN1_MAX_RECURSIONS` = 16 (`x509asn1.c:167`), a rendered string at
//! most [`CURL_X509_STR_MAX`] = 100000 bytes (`vtls.h:167`) and a chain at
//! most [`MAX_ALLOWED_CERT_AMOUNT`] = 100 certificates (`vtls.h:168`,
//! enforced by `rustls.c:1201-1204`). Long tag numbers, lengths above 32
//! bits, truncation and constructed elements offered for string conversion
//! are all rejected, and every one of those rejections is a returned error.
//!
//! # Visibility
//!
//! `pub(crate)` throughout, with exactly one exception:
//! [`ServerVerification::peer_verification_disabled`] is `pub`, immutable
//! and read-only. `curl-rs/src/output/msgs.rs` has to print the
//! `--insecure` warning to standard error BEFORE the transfer proceeds, so
//! it needs to ask this question at configuration time; the answer is fixed
//! when the policy is turned into a verifier and cannot be changed
//! afterwards. Note that `crate::tls` is itself `pub(crate)`
//! (`lib.rs:729`), so the reachable path for the tool crate is a re-export
//! from a module that is already public, and this method being `pub` is what
//! lets that re-export exist without widening anything else here.
//!
//! # One deviation from the letter of the specification, stated plainly
//!
//! AAP 0.5.1 names `rustls-pemfile 2.2.0` for PEM parsing. That crate is
//! not among this workspace's dependencies -- neither
//! `[workspace.dependencies]` nor `curl-rs-lib/Cargo.toml` declares it --
//! and manifests are not this file's to change. PEM parsing therefore goes
//! through the [`PemObject`] trait of `rustls-pki-types 1.15.1`, which is
//! the same code: `rustls-pemfile 2.2.0` is a thin deprecated shim over it.
//! Nothing about the accepted inputs or the error mapping differs.
//!
//! The reason the crate is absent is not this file's choice and is not a
//! preference: `RUSTSEC-2025-0134` marks `rustls-pemfile` UNMAINTAINED with no
//! patched version, and `deny.toml` sets `unmaintained = "all"`, so declaring
//! it fails AAP 0.8.4's ninth gate -- measured, with `cargo deny check
//! advisories` reporting `error[unmaintained]` the moment it becomes a live
//! dependency. The row is therefore a **blocked gate**, declared as one under
//! `[workspace.metadata.curl-rs.blocked-aap-gates.rustls-pemfile]` in the root
//! manifest. The capability AAP 0.5.1 describes is delivered here in full; the
//! package it names is not present, and this file does not describe that as
//! compliance.

use core::fmt;
use std::borrow::Cow;
use std::fs;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::client::{
    VerifierBuilderError, WantsClientCert, WebPkiServerVerifier,
};
use rustls::crypto::{
    verify_tls12_signature, verify_tls13_signature, CryptoProvider,
};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{
    ClientConfig, ConfigBuilder, DigitallySignedStruct, RootCertStore,
    SignatureScheme, WantsVerifier,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, ServerName,
    UnixTime,
};

use crate::error::{CURLcode, CurlResult, Error};
use crate::tls::{SslPeerType, CURL_X509_STR_MAX, MAX_ALLOWED_CERT_AMOUNT};
use crate::util::base64;
use crate::util::dynbuf::DynBuf;
use crate::util::inet;
use crate::util::strcase;

// Constants: every one measured from the C, none chosen here

/// Largest ASN.1 structure the parser accepts: 256 KiB.
///
/// `#define CURL_ASN1_MAX ((size_t)0x40000)` (`lib/vtls/x509asn1.c:51`).
/// The guard is applied to the span offered to the parser, so an outer
/// object larger than this is refused before a single header byte is read.
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) const CURL_ASN1_MAX: usize = 0x40000;

/// Deepest nesting the parser follows: 16.
///
/// `#define CURL_ASN1_MAX_RECURSIONS 16` (`lib/vtls/x509asn1.c:167`). Only
/// the indefinite-length constructed form recurses, and this is what stops
/// a certificate built to nest without end.
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) const CURL_ASN1_MAX_RECURSIONS: usize = 16;

/// Ceiling for a client certificate read from a file: 100 KiB.
///
/// `DYN_CERTFILE_SIZE` (`lib/curlx/dynbuf.h:81`), the ceiling
/// `lib/vtls/rustls.c:855` gives the dynbuf that holds `--cert`.
const DYN_CERTFILE_SIZE: usize = 100 * 1024;

/// Ceiling for a private key read from a file: 100 KiB.
///
/// `DYN_KEYFILE_SIZE` (`lib/curlx/dynbuf.h:82`), from
/// `lib/vtls/rustls.c:856`.
const DYN_KEYFILE_SIZE: usize = 100 * 1024;

/// Ceiling for a revocation list read from a file: 400 MiB.
///
/// `DYN_CRLFILE_SIZE` (`lib/curlx/dynbuf.h:80`), from
/// `lib/vtls/rustls.c:677`. Larger than the others by three orders of
/// magnitude because a published CRL genuinely is.
const DYN_CRLFILE_SIZE: usize = 400 * 1024 * 1024;

/// Ceiling for a trust bundle read from a file: 400 MiB.
const DYN_CAFILE_SIZE: usize = 400 * 1024 * 1024;

/// Base64 characters per line of a PEM body.
///
/// `lib/vtls/x509asn1.c:1239` chunks at exactly 64, and
/// `lib/vtls/x509asn1.c:1222-1229` documents the shape the chunking
/// produces. RFC 7468 permits 64 as the maximum; curl emits exactly 64, and
/// a fixture comparing `CURLINFO_CERTINFO` output compares the text.
const PEM_LINE_WIDTH: usize = 64;

// ASN.1 universal tags, exactly the set `x509asn1.c:61-88` leaves enabled.

/// `CURL_ASN1_BOOLEAN` (`x509asn1.c:61`).
const ASN1_BOOLEAN: u8 = 1;
/// `CURL_ASN1_INTEGER` (`x509asn1.c:62`).
const ASN1_INTEGER: u8 = 2;
/// `CURL_ASN1_BIT_STRING` (`x509asn1.c:63`).
const ASN1_BIT_STRING: u8 = 3;
/// `CURL_ASN1_OCTET_STRING` (`x509asn1.c:64`).
const ASN1_OCTET_STRING: u8 = 4;
/// `CURL_ASN1_NULL` (`x509asn1.c:65`).
const ASN1_NULL: u8 = 5;
/// `CURL_ASN1_OBJECT_IDENTIFIER` (`x509asn1.c:66`).
const ASN1_OBJECT_IDENTIFIER: u8 = 6;
/// `CURL_ASN1_ENUMERATED` (`x509asn1.c:70`).
const ASN1_ENUMERATED: u8 = 10;
/// `CURL_ASN1_UTF8_STRING` (`x509asn1.c:72`).
const ASN1_UTF8_STRING: u8 = 12;
/// `CURL_ASN1_NUMERIC_STRING` (`x509asn1.c:76`).
const ASN1_NUMERIC_STRING: u8 = 18;
/// `CURL_ASN1_PRINTABLE_STRING` (`x509asn1.c:77`).
const ASN1_PRINTABLE_STRING: u8 = 19;
/// `CURL_ASN1_TELETEX_STRING` (`x509asn1.c:78`).
const ASN1_TELETEX_STRING: u8 = 20;
/// `CURL_ASN1_IA5_STRING` (`x509asn1.c:80`).
const ASN1_IA5_STRING: u8 = 22;
/// `CURL_ASN1_UTC_TIME` (`x509asn1.c:81`).
const ASN1_UTC_TIME: u8 = 23;
/// `CURL_ASN1_GENERALIZED_TIME` (`x509asn1.c:82`).
const ASN1_GENERALIZED_TIME: u8 = 24;
/// `CURL_ASN1_VISIBLE_STRING` (`x509asn1.c:84`).
const ASN1_VISIBLE_STRING: u8 = 26;
/// `CURL_ASN1_UNIVERSAL_STRING` (`x509asn1.c:86`).
const ASN1_UNIVERSAL_STRING: u8 = 28;
/// `CURL_ASN1_BMP_STRING` (`x509asn1.c:88`).
const ASN1_BMP_STRING: u8 = 30;

/// The ASN.1 OID table, in the C's order.
const OID_TABLE: &[(&str, &str)] = &[
    ("1.2.840.10040.4.1", "dsa"),
    ("1.2.840.10040.4.3", "dsa-with-sha1"),
    ("1.2.840.10045.2.1", "ecPublicKey"),
    ("1.2.840.10045.3.0.1", "c2pnb163v1"),
    ("1.2.840.10045.4.1", "ecdsa-with-SHA1"),
    ("1.2.840.10045.4.3.1", "ecdsa-with-SHA224"),
    ("1.2.840.10045.4.3.2", "ecdsa-with-SHA256"),
    ("1.2.840.10045.4.3.3", "ecdsa-with-SHA384"),
    ("1.2.840.10045.4.3.4", "ecdsa-with-SHA512"),
    ("1.2.840.10046.2.1", "dhpublicnumber"),
    ("1.2.840.113549.1.1.1", "rsaEncryption"),
    ("1.2.840.113549.1.1.2", "md2WithRSAEncryption"),
    ("1.2.840.113549.1.1.4", "md5WithRSAEncryption"),
    ("1.2.840.113549.1.1.5", "sha1WithRSAEncryption"),
    ("1.2.840.113549.1.1.10", "RSASSA-PSS"),
    ("1.2.840.113549.1.1.14", "sha224WithRSAEncryption"),
    ("1.2.840.113549.1.1.11", "sha256WithRSAEncryption"),
    ("1.2.840.113549.1.1.12", "sha384WithRSAEncryption"),
    ("1.2.840.113549.1.1.13", "sha512WithRSAEncryption"),
    ("1.2.840.113549.2.2", "md2"),
    ("1.2.840.113549.2.5", "md5"),
    ("1.3.14.3.2.26", "sha1"),
    ("2.5.4.3", "CN"),
    ("2.5.4.4", "SN"),
    ("2.5.4.5", "serialNumber"),
    ("2.5.4.6", "C"),
    ("2.5.4.7", "L"),
    ("2.5.4.8", "ST"),
    ("2.5.4.9", "streetAddress"),
    ("2.5.4.10", "O"),
    ("2.5.4.11", "OU"),
    ("2.5.4.12", "title"),
    ("2.5.4.13", "description"),
    ("2.5.4.17", "postalCode"),
    ("2.5.4.41", "name"),
    ("2.5.4.42", "givenName"),
    ("2.5.4.43", "initials"),
    ("2.5.4.44", "generationQualifier"),
    ("2.5.4.45", "X500UniqueIdentifier"),
    ("2.5.4.46", "dnQualifier"),
    ("2.5.4.65", "pseudonym"),
    ("1.2.840.113549.1.9.1", "emailAddress"),
    ("2.5.4.72", "role"),
    ("2.5.29.17", "subjectAltName"),
    ("2.5.29.18", "issuerAltName"),
    ("2.5.29.19", "basicConstraints"),
    ("2.16.840.1.101.3.4.2.4", "sha224"),
    ("2.16.840.1.101.3.4.2.1", "sha256"),
    ("2.16.840.1.101.3.4.2.2", "sha384"),
    ("2.16.840.1.101.3.4.2.3", "sha512"),
    ("1.2.840.113549.1.9.2", "unstructuredName"),
];

/// The dotted-numeric OID of the subjectAltName extension.
///
/// `{ "2.5.29.17", "subjectAltName" }` (`x509asn1.c:141`). Named separately
/// because [`verify_hostname`] looks the extension up by identity rather
/// than rendering it for display.
const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";

/// The dotted-numeric OID of the commonName attribute.
///
/// `{ "2.5.4.3", "CN" }` (`x509asn1.c:120`). The commonName fallback of
/// `lib/vtls/openssl.c:2189-2244` needs the attribute by identity, for the
/// same reason.
const OID_COMMON_NAME: &str = "2.5.4.3";

// Bounded ASN.1 parsing: supersedes `lib/vtls/x509asn1.c:163-240`

/// One parsed ASN.1 element.
///
/// Supersedes `struct Curl_asn1Element` (`lib/vtls/x509asn1.h:40-47`). The
/// C keeps three raw pointers -- `header`, `beg` and `end` -- where this
/// keeps one borrowed slice, so the two invariants the C maintains by hand
/// (`beg <= end`, and both inside the source buffer) are the slice's own and
/// cannot be violated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Asn1Element<'a> {
    /// The element's content octets: the C's `[beg, end)`.
    content: &'a [u8],
    /// The tag class, the C's `eclass`: 0 universal, 1 application,
    /// 2 context-specific, 3 private (`x509asn1.c:55-58`, commented out
    /// there because only the numeric value is ever compared).
    class: u8,
    /// The tag number, already known to be below `0x1F` because the parser
    /// rejects the long form.
    tag: u8,
    /// Whether bit 6 of the identifier octet was set.
    constructed: bool,
}

#[allow(dead_code)] // consumer: tls/rustls_backend.rs
impl<'a> Asn1Element<'a> {
    /// The empty element the C writes with `beg = end = ""`.
    ///
    /// `Curl_parseX509` initialises `issuerUniqueID`, `subjectUniqueID` and
    /// `extensions` this way (`x509asn1.c:849-855`) so that a certificate
    /// omitting them still yields a readable structure. Tag zero matches
    /// the C's `cert->extensions.tag = elem.tag = 0`.
    const EMPTY: Self = Self {
        content: &[],
        class: 0,
        tag: 0,
        constructed: false,
    };

    /// The element's content octets.
    pub(crate) const fn content(&self) -> &'a [u8] {
        self.content
    }

    /// The tag number.
    pub(crate) const fn tag(&self) -> u8 {
        self.tag
    }

    /// The tag class.
    pub(crate) const fn class(&self) -> u8 {
        self.class
    }

    /// Whether the element is constructed.
    pub(crate) const fn is_constructed(&self) -> bool {
        self.constructed
    }
}

/// Parses one ASN.1 element from the front of `src`.
///
/// The C's own description is worth keeping in view: this is a lightweight
/// parser that "does not check for syntactic/lexical errors"
/// (`x509asn1.c:155-160`). It is deliberately not a validating X.509
/// implementation -- validation is rustls's job -- and it exists so that
/// `CURLINFO_CERTINFO` can report sub-fields of a certificate a backend
/// hands over whole.
///
/// # Errors
///
/// [`None`] for every condition the C answers with `NULL`: an empty span, a
/// leading zero octet, a span above [`CURL_ASN1_MAX`], a long tag number, a
/// truncated header, a length above 32 bits, a length that does not fit the
/// span, and an indefinite length on a primitive element.
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) fn get_asn1_element(src: &[u8]) -> Option<(Asn1Element<'_>, &[u8])> {
    get_asn1_element_at(src, 0)
}

/// [`get_asn1_element`] with the recursion counter the C threads through.
fn get_asn1_element_at(
    src: &[u8],
    level: usize,
) -> Option<(Asn1Element<'_>, &[u8])> {
    // `x509asn1.c:181-184`, condition for condition. `!beg || !end` and
    // `beg >= end` are both "the span is empty" once the span is a slice,
    // and `!*beg` rejects a leading NUL -- which is not a valid identifier
    // octet, and which the indefinite-length scan below relies on being
    // rejected.
    if src.is_empty()
        || src[0] == 0
        || src.len() > CURL_ASN1_MAX
        || level >= CURL_ASN1_MAX_RECURSIONS
    {
        return None;
    }

    // Identifier octet (`x509asn1.c:186-194`).
    let identifier = src[0];
    let mut cursor = 1usize;
    let constructed = (identifier & 0x20) != 0;
    let class = (identifier >> 6) & 3;
    let tag = identifier & 0x1F;
    if tag == 0x1F {
        // "Long tag values not supported here" (`x509asn1.c:192-193`).
        return None;
    }

    // Length octets (`x509asn1.c:196-228`).
    let first_length = *src.get(cursor)?;
    cursor += 1;

    let content_length = if first_length & 0x80 == 0 {
        // Short form: the length is the octet itself.
        usize::from(first_length)
    } else if first_length & 0x7F == 0 {
        // Indefinite form (`x509asn1.c:202-217`). "Since we have all the
        // data, we can determine the effective length by skipping element
        // until an end element is found."
        if !constructed {
            return None;
        }
        let content_start = cursor;
        while cursor < src.len() && src[cursor] != 0 {
            let (_child, rest) =
                get_asn1_element_at(&src[cursor..], level + 1)?;
            // `rest` is a suffix of `src`, so its length gives the new
            // offset without any arithmetic on raw addresses.
            cursor = src.len() - rest.len();
        }
        if cursor >= src.len() {
            return None;
        }
        let element = Asn1Element {
            content: &src[content_start..cursor],
            class,
            tag,
            constructed,
        };
        // `return beg + 1` (`x509asn1.c:216`). The C steps over ONE octet
        // of the two-octet end-of-contents marker, and so does this: the
        // behaviour is reproduced rather than corrected, because a caller
        // that depends on where the C leaves the cursor must see the same
        // position.
        return Some((element, &src[cursor + 1..]));
    } else {
        // Long form. `x509asn1.c:218-219` checks the OCTET COUNT against
        // the bytes remaining before reading any of them.
        let octets = usize::from(first_length & 0x7F);
        if octets > src.len() - cursor {
            return None;
        }
        // `x509asn1.c:221-227`. The overflow guard is applied BEFORE each
        // shift, exactly as the C applies it, so a length needing more
        // than 32 bits is refused rather than truncated. A `u64`
        // accumulator under that guard cannot overflow.
        let mut accumulated: u64 = 0;
        for _ in 0..octets {
            if accumulated & 0xFF00_0000 != 0 {
                // "Lengths > 32 bits are not supported"
                // (`x509asn1.c:224-225`).
                return None;
            }
            accumulated = (accumulated << 8) | u64::from(src[cursor]);
            cursor += 1;
        }
        usize::try_from(accumulated).ok()?
    };

    // "Element data does not fit in source" (`x509asn1.c:229-230`).
    if content_length > src.len() - cursor {
        return None;
    }
    let end = cursor + content_length;
    let element = Asn1Element {
        content: &src[cursor..end],
        class,
        tag,
        constructed,
    };
    Some((element, &src[end..]))
}

/// Looks an OID up in [`OID_TABLE`] by its numeric or its text form.
///
/// Supersedes `searchOID` (`lib/vtls/x509asn1.c:248-256`), which compares
/// the numeric form case-sensitively with `strcmp` and the text form
/// case-insensitively with `curl_strequal`. Both halves are kept: a caller
/// may hold either spelling.
fn search_oid(oid: &str) -> Option<&'static (&'static str, &'static str)> {
    OID_TABLE.iter().find(|(numeric, text)| {
        *numeric == oid || strcase::casecompare(text.as_bytes(), oid.as_bytes())
    })
}

// ASN.1 to text: supersedes `lib/vtls/x509asn1.c:269-759`

/// A fresh accumulator with the C's ceiling on a rendered string.
///
/// Every `curlx_dyn_init` in `x509asn1.c` passes `CURL_X509_STR_MAX`
/// (lines 467, 689, 953 and 1096), so the ceiling belongs to the module
/// rather than to any one call site.
fn certinfo_buffer() -> DynBuf {
    DynBuf::new(CURL_X509_STR_MAX)
}

/// Lifts a [`DynBuf`] append failure into an [`Error`].
///
/// [`DynBuf`] reports crossing its ceiling as [`CURLcode::TooLarge`] and an
/// allocation failure as [`CURLcode::OutOfMemory`], which are the two codes
/// the C's `curlx_dyn_*` return. Neither is reinterpreted here.
fn append(result: Result<(), CURLcode>) -> CurlResult<()> {
    result.map_err(Error::new)
}

/// An ASN.1 Boolean as text.
///
/// Supersedes `bool2str` (`x509asn1.c:275-281`): the content must be exactly
/// one octet, and any non-zero value is `TRUE`.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] when the content is not one octet.
fn bool_to_str(store: &mut DynBuf, content: &[u8]) -> CurlResult<()> {
    if content.len() != 1 {
        return Err(Error::new(CURLcode::BadFunctionArgument));
    }
    append(store.add(if content[0] != 0 { "TRUE" } else { "FALSE" }))
}

/// An octet string as colon-separated hexadecimal.
///
/// Supersedes `octet2str` (`x509asn1.c:288-297`). The trailing colon the C
/// leaves after the last octet is part of the output a fixture compares, so
/// it is kept: `"%02x:"` per octet, with nothing stripped at the end.
fn octet_to_str(store: &mut DynBuf, content: &[u8]) -> CurlResult<()> {
    for byte in content {
        append(store.addf(format_args!("{byte:02x}:")))?;
    }
    Ok(())
}

/// A bit string as colon-separated hexadecimal.
fn bit_to_str(store: &mut DynBuf, content: &[u8]) -> CurlResult<()> {
    match content.split_first() {
        Some((_unused_bits, rest)) => octet_to_str(store, rest),
        // `++beg > end` is false for an empty span, so the C proceeds into
        // `octet2str` with `beg > end` and its `while(beg < end)` adds
        // nothing.
        None => Ok(()),
    }
}

/// An integer or enumerated value as text.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] when the content is empty.
fn int_to_str(store: &mut DynBuf, content: &[u8]) -> CurlResult<()> {
    if content.is_empty() {
        return Err(Error::new(CURLcode::BadFunctionArgument));
    }
    if content.len() > 4 {
        return octet_to_str(store, content);
    }

    // `if(*beg & 0x80) val = ~val;` -- sign extension into a 32-bit
    // accumulator, so a negative value prints as its two's complement in
    // exactly the width the C uses.
    let mut value: u32 = if content[0] & 0x80 != 0 { u32::MAX } else { 0 };
    for byte in content {
        value = (value << 8) | u32::from(*byte);
    }
    let prefix = if value >= 10 { "0x" } else { "" };
    append(store.addf(format_args!("{prefix}{value:x}")))
}

/// A typed ASN.1 string converted to UTF-8.
///
/// Supersedes `utf8asn1str` (`x509asn1.c:342-417`). The character width
/// comes from the tag -- 2 for BMPString, 4 for UniversalString, 1 for the
/// rest -- a UTF8String is copied verbatim, and everything else is decoded
/// big-endian and re-encoded by the C's own hand-written encoder, which is
/// reproduced here so that its one refusal is reproduced with it.
///
/// # Errors
///
/// * [`CURLcode::BadFunctionArgument`] for a tag this conversion does not
///   support, or a content length that is not a multiple of the character
///   width.
/// * [`CURLcode::WeirdServerReply`] for a code point at or above
///   `0x00200000`, which the C rejects as an "invalid char. size for target
///   encoding" (`x509asn1.c:396-399`).
fn utf8_asn1_str(
    store: &mut DynBuf,
    tag: u8,
    content: &[u8],
) -> CurlResult<()> {
    let width = match tag {
        ASN1_BMP_STRING => 2usize,
        ASN1_UNIVERSAL_STRING => 4,
        ASN1_NUMERIC_STRING
        | ASN1_PRINTABLE_STRING
        | ASN1_TELETEX_STRING
        | ASN1_IA5_STRING
        | ASN1_VISIBLE_STRING
        | ASN1_UTF8_STRING => 1,
        // "Conversion not supported" (`x509asn1.c:363-364`).
        _ => return Err(Error::new(CURLcode::BadFunctionArgument)),
    };

    if content.len() % width != 0 {
        // "Length inconsistent with character size" (`x509asn1.c:367-369`).
        return Err(Error::new(CURLcode::BadFunctionArgument));
    }

    if tag == ASN1_UTF8_STRING {
        // "Just copy" (`x509asn1.c:371-375`). No validation: the C does
        // none, and a certificate carrying invalid UTF-8 in a UTF8String
        // must render the same bytes here as there.
        return append(store.addn(content));
    }

    for chunk in content.chunks(width) {
        let mut code_point: u32 = 0;
        for byte in chunk {
            code_point = (code_point << 8) | u32::from(*byte);
        }

        // `x509asn1.c:393-413`, transcribed. Writing this out rather than
        // calling `char::encode_utf8` is deliberate: `char` rejects the
        // surrogate range and anything above `0x10FFFF`, where the C
        // encodes both, and the C's own limit is the higher `0x00200000`.
        // Substituting Rust's stricter rule would change the bytes a
        // fixture compares.
        let mut buf = [0u8; 4];
        let mut charsize = 1usize;
        let mut work = code_point;
        if work >= 0x0000_0080 {
            if work >= 0x0000_0800 {
                if work >= 0x0001_0000 {
                    if work >= 0x0020_0000 {
                        return Err(Error::new(CURLcode::WeirdServerReply));
                    }
                    buf[3] = 0x80 | u8::try_from(work & 0x3F).unwrap_or(0);
                    work = (work >> 6) | 0x0001_0000;
                    charsize += 1;
                }
                buf[2] = 0x80 | u8::try_from(work & 0x3F).unwrap_or(0);
                work = (work >> 6) | 0x0000_0800;
                charsize += 1;
            }
            buf[1] = 0x80 | u8::try_from(work & 0x3F).unwrap_or(0);
            work = (work >> 6) | 0x0000_00C0;
            charsize += 1;
        }
        buf[0] = u8::try_from(work & 0xFF).unwrap_or(0);
        append(store.addn(&buf[..charsize]))?;
    }
    Ok(())
}

/// An OID as its dotted-decimal form.
///
/// # Errors
///
/// Only an append failure. An empty content cannot reach here: the one
/// caller checks it first.
fn encode_oid(store: &mut DynBuf, content: &[u8]) -> CurlResult<()> {
    let Some((first, rest)) = content.split_first() else {
        return Ok(());
    };
    let first = u32::from(*first);
    let arc1 = first / 40;
    let arc2 = first - arc1 * 40;
    append(store.addf(format_args!("{arc1}.{arc2}")))?;

    let mut remaining = rest;
    while !remaining.is_empty() {
        let mut arc: u32 = 0;
        loop {
            if arc & 0xFF00_0000 != 0 {
                // "return CURLE_OK" from inside the loop
                // (`x509asn1.c:444-445`): stop, keep what was rendered.
                return Ok(());
            }
            let Some((byte, tail)) = remaining.split_first() else {
                // The C's `while(y & 0x80)` reads past `end` when the last
                // group has its continuation bit set; a slice cannot, so
                // the arc decoded so far is emitted and the loop ends.
                break;
            };
            remaining = tail;
            arc = (arc << 7) | u32::from(*byte & 0x7F);
            if *byte & 0x80 == 0 {
                break;
            }
        }
        append(store.addf(format_args!(".{arc}")))?;
    }
    Ok(())
}

/// An OID as its symbolic name when one is known, else numerically.
fn oid_to_str(
    store: &mut DynBuf,
    content: &[u8],
    symbolic: bool,
) -> CurlResult<()> {
    if content.is_empty() {
        return Ok(());
    }
    if !symbolic {
        return encode_oid(store, content);
    }

    let mut numeric = certinfo_buffer();
    encode_oid(&mut numeric, content)?;
    let rendered = String::from_utf8_lossy(numeric.as_slice()).into_owned();
    match search_oid(&rendered) {
        Some((_numeric, text)) => append(store.add(text)),
        None => append(store.add(&rendered)),
    }
}

/// The dotted-decimal form of an OID element, for identity comparisons.
///
/// # Errors
///
/// Propagates an append failure from [`encode_oid`].
fn oid_numeric(content: &[u8]) -> CurlResult<String> {
    let mut numeric = certinfo_buffer();
    encode_oid(&mut numeric, content)?;
    Ok(String::from_utf8_lossy(numeric.as_slice()).into_owned())
}

/// An ASN.1 GeneralizedTime as text.
///
/// Supersedes `GTime2str` (`x509asn1.c:485-561`), whose output shape is
/// `YYYY-MM-DD hh:mm:ss[.fff][ tz]`. Three details carry the behaviour and
/// each is reproduced rather than rationalised:
///
/// * The seconds field may be absent (12 digits), one digit (13) or two
///   (14); anything else is an error. A missing tens digit renders as `0`.
/// * Fractional seconds may be introduced by `.` or `,`, must be followed by
///   at least one digit, and have trailing zeroes stripped -- so `.500`
///   renders as `.5` and `.000` disappears.
/// * A `Z` renders as ` GMT`, a signed offset as ` UTC` followed by the
///   offset, and anything else as a space followed by the remaining text.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for a digit run that is not 12, 13 or
/// 14 long, or a fraction marker with no digit after it.
fn gtime_to_str(store: &mut DynBuf, content: &[u8]) -> CurlResult<()> {
    let digits = content.iter().take_while(|b| b.is_ascii_digit()).count();

    // `switch(fracp - beg - 12)` (`x509asn1.c:503-515`). A run shorter than
    // 12 makes the C's pointer difference negative, which its `default`
    // rejects; `checked_sub` is the same test.
    let (sec_tens, sec_units) = match digits.checked_sub(12) {
        Some(0) => (b'0', b'0'),
        Some(1) => (b'0', content[digits - 1]),
        Some(2) => (content[digits - 2], content[digits - 1]),
        _ => return Err(Error::new(CURLcode::BadFunctionArgument)),
    };

    // Fractional seconds (`x509asn1.c:517-534`).
    let mut cursor = digits;
    let mut fraction: &[u8] = &[];
    if content
        .get(cursor)
        .is_some_and(|b| *b == b'.' || *b == b',')
    {
        cursor += 1;
        let start = cursor;
        while content.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == start {
            // "never looped, no digit after [.,]" (`x509asn1.c:526-527`).
            return Err(Error::new(CURLcode::BadFunctionArgument));
        }
        let mut length = cursor - start;
        while length > 0 && content[start + length - 1] == b'0' {
            length -= 1;
        }
        fraction = &content[start..start + length];
    }

    // Timezone (`x509asn1.c:536-553`).
    let (separator, zone): (&str, &[u8]) = match content.get(cursor) {
        None => ("", &[]),
        Some(b'Z') => (" ", b"GMT"),
        Some(b'+' | b'-') => (" UTC", &content[cursor..]),
        Some(_) => (" ", &content[cursor..]),
    };

    append(store.addn(&content[0..4]))?;
    append(store.addn(b"-"))?;
    append(store.addn(&content[4..6]))?;
    append(store.addn(b"-"))?;
    append(store.addn(&content[6..8]))?;
    append(store.addn(b" "))?;
    append(store.addn(&content[8..10]))?;
    append(store.addn(b":"))?;
    append(store.addn(&content[10..12]))?;
    append(store.addn(b":"))?;
    append(store.addn(&[sec_tens, sec_units]))?;
    if !fraction.is_empty() {
        append(store.addn(b"."))?;
        append(store.addn(fraction))?;
    }
    append(store.add(separator))?;
    append(store.addn(zone))
}

/// An ASN.1 UTCTime as text.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for a digit run that is not 10 or 12
/// long, or a value whose digits run to the end with no timezone.
fn utime_to_str(store: &mut DynBuf, content: &[u8]) -> CurlResult<()> {
    let digits = content.iter().take_while(|b| b.is_ascii_digit()).count();

    // `switch(tzp - sec)` with `sec = beg + 10` (`x509asn1.c:587-596`).
    let seconds: &[u8] = match digits.checked_sub(10) {
        Some(0) => b"00",
        Some(2) => &content[10..12],
        _ => return Err(Error::new(CURLcode::BadFunctionArgument)),
    };

    // "Process timezone" (`x509asn1.c:598-608`).
    let zone: &[u8] = match content.get(digits) {
        None => return Err(Error::new(CURLcode::BadFunctionArgument)),
        Some(b'Z') => b"GMT",
        Some(_) => &content[digits + 1..],
    };

    let century = if content[0] >= b'5' { 19 } else { 20 };
    append(store.addf(format_args!("{century}")))?;
    append(store.addn(&content[0..2]))?;
    append(store.addn(b"-"))?;
    append(store.addn(&content[2..4]))?;
    append(store.addn(b"-"))?;
    append(store.addn(&content[4..6]))?;
    append(store.addn(b" "))?;
    append(store.addn(&content[6..8]))?;
    append(store.addn(b":"))?;
    append(store.addn(&content[8..10]))?;
    append(store.addn(b":"))?;
    append(store.addn(seconds))?;
    append(store.addn(b" "))?;
    append(store.addn(zone))
}

/// One ASN.1 element as text, dispatching on its tag.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for a constructed element or a tag with
/// no conversion, plus whatever the chosen conversion returns.
fn asn1_to_str(
    store: &mut DynBuf,
    element: &Asn1Element<'_>,
    forced_tag: u8,
) -> CurlResult<()> {
    if element.constructed {
        return Err(Error::new(CURLcode::BadFunctionArgument));
    }
    let tag = if forced_tag == 0 {
        element.tag
    } else {
        forced_tag
    };
    let content = element.content;

    match tag {
        ASN1_BOOLEAN => bool_to_str(store, content),
        ASN1_INTEGER | ASN1_ENUMERATED => int_to_str(store, content),
        ASN1_BIT_STRING => bit_to_str(store, content),
        ASN1_OCTET_STRING => octet_to_str(store, content),
        // `curlx_dyn_addn(store, "", 1)` (`x509asn1.c:645`) appends one
        // octet OF the empty string, which is its terminator: a NULL
        // renders as a single zero byte, not as nothing. Reproduced
        // exactly, because `CURLINFO_CERTINFO` carries a length.
        ASN1_NULL => append(store.addn(&[0])),
        ASN1_OBJECT_IDENTIFIER => oid_to_str(store, content, true),
        ASN1_UTC_TIME => utime_to_str(store, content),
        ASN1_GENERALIZED_TIME => gtime_to_str(store, content),
        ASN1_UTF8_STRING
        | ASN1_NUMERIC_STRING
        | ASN1_PRINTABLE_STRING
        | ASN1_TELETEX_STRING
        | ASN1_IA5_STRING
        | ASN1_VISIBLE_STRING
        | ASN1_UNIVERSAL_STRING
        | ASN1_BMP_STRING => utf8_asn1_str(store, tag, content),
        // The C's `switch` leaves `result` at its initial
        // `CURLE_BAD_FUNCTION_ARGUMENT` for an unmatched tag.
        _ => Err(Error::new(CURLcode::BadFunctionArgument)),
    }
}

/// A distinguished name as text.
///
/// Supersedes `encodeDN` (`x509asn1.c:676-759`). The structure is a sequence
/// of relative distinguished names, each a set of attribute-value pairs, and
/// each pair an OID followed by a value. Two behaviours matter to the
/// output and are reproduced literally:
///
/// * The delimiter is chosen from the name it PRECEDES, not from the one
///   before it: a run of leading uppercase letters longer than two selects
///   `/`, anything else selects `, `. So `C=SE, O=Example` uses commas
///   while a long mixed-case name such as `emailAddress` is introduced by a
///   slash. The C reads `str`, the attribute it is about to write, and so
///   does this.
/// * No delimiter precedes the first attribute.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for any malformed nesting, or for an
/// attribute whose OID renders as nothing -- the C's `if(!str)` test on a
/// dynbuf that received no bytes.
fn encode_dn(store: &mut DynBuf, dn: &Asn1Element<'_>) -> CurlResult<()> {
    let bad = || Error::new(CURLcode::BadFunctionArgument);
    let mut added = false;
    let mut rendered_oid = certinfo_buffer();

    let mut names = dn.content;
    while !names.is_empty() {
        let (rdn, rest) = get_asn1_element(names).ok_or_else(bad)?;
        names = rest;

        let mut pairs = rdn.content;
        while !pairs.is_empty() {
            let (attribute, rest) = get_asn1_element(pairs).ok_or_else(bad)?;
            pairs = rest;

            let (oid, after_oid) =
                get_asn1_element(attribute.content).ok_or_else(bad)?;
            let (value, _) = get_asn1_element(after_oid).ok_or_else(bad)?;

            rendered_oid.reset();
            asn1_to_str(&mut rendered_oid, &oid, 0)?;
            if rendered_oid.is_empty() {
                // `curlx_dyn_ptr` is NULL when nothing was appended
                // (`x509asn1.c:719-722`).
                return Err(bad());
            }

            // "If attribute has a short uppercase name, delimiter is ', '"
            // (`x509asn1.c:724-735`).
            let uppercase_run = rendered_oid
                .as_slice()
                .iter()
                .take_while(|b| b.is_ascii_uppercase())
                .count();
            if added {
                if uppercase_run > 2 {
                    append(store.addn(b"/"))?;
                } else {
                    append(store.addn(b", "))?;
                }
            }

            append(store.addn(rendered_oid.as_slice()))?;
            append(store.addn(b"="))?;
            asn1_to_str(store, &value, 0)?;
            added = true;
        }
    }
    Ok(())
}

// X.509 structure: supersedes `lib/vtls/x509asn1.c:769-881`

/// The version an X.509 certificate has when it omits the field: v1.
///
/// `static const char defaultVersion = 0;` (`x509asn1.c:775`), which
/// `Curl_parseX509` points `cert->version` at so that a v1 certificate
/// still reports a version.
const DEFAULT_VERSION: [u8; 1] = [0];

/// An X.509 certificate decomposed into its sub-fields.
///
/// Supersedes `struct Curl_X509certificate` (`lib/vtls/x509asn1.h:50-66`),
/// with the same fifteen members in the same roles. Every member borrows
/// from the DER the caller supplied, so the structure costs one parse and no
/// copying, and it cannot outlive the bytes it describes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct X509Certificate<'a> {
    /// The whole certificate, from the outer SEQUENCE header onward. This
    /// is what the PEM record is built from.
    certificate: &'a [u8],
    /// The optional `[0] EXPLICIT Version`, defaulting to [`DEFAULT_VERSION`].
    version: Asn1Element<'a>,
    /// `serialNumber`.
    serial_number: Asn1Element<'a>,
    /// `signatureAlgorithm`, an AlgorithmIdentifier.
    signature_algorithm: Asn1Element<'a>,
    /// `signatureValue`, a BIT STRING.
    signature: Asn1Element<'a>,
    /// `issuer`, a Name.
    issuer: Asn1Element<'a>,
    /// `validity.notBefore`.
    not_before: Asn1Element<'a>,
    /// `validity.notAfter`.
    not_after: Asn1Element<'a>,
    /// `subject`, a Name.
    subject: Asn1Element<'a>,
    /// `subjectPublicKeyInfo`, which holds the next two members.
    subject_public_key_info: Asn1Element<'a>,
    /// The algorithm half of `subjectPublicKeyInfo`.
    subject_public_key_algorithm: Asn1Element<'a>,
    /// The key half of `subjectPublicKeyInfo`, a BIT STRING.
    subject_public_key: Asn1Element<'a>,
    /// The optional `[1] issuerUniqueID`, empty when absent.
    issuer_unique_id: Asn1Element<'a>,
    /// The optional `[2] subjectUniqueID`, empty when absent.
    subject_unique_id: Asn1Element<'a>,
    /// The optional `[3] EXPLICIT Extensions`, empty when absent.
    extensions: Asn1Element<'a>,
}

#[allow(dead_code)] // consumer: tls/rustls_backend.rs
impl<'a> X509Certificate<'a> {
    /// The whole certificate as DER.
    pub(crate) const fn certificate(&self) -> &'a [u8] {
        self.certificate
    }

    /// The subject Name.
    pub(crate) const fn subject(&self) -> &Asn1Element<'a> {
        &self.subject
    }

    /// The issuer Name.
    pub(crate) const fn issuer(&self) -> &Asn1Element<'a> {
        &self.issuer
    }

    /// The extensions, empty when the certificate carries none.
    pub(crate) const fn extensions(&self) -> &Asn1Element<'a> {
        &self.extensions
    }

    /// The whole `subjectPublicKeyInfo`, algorithm and key together.
    pub(crate) const fn subject_public_key_info(&self) -> &Asn1Element<'a> {
        &self.subject_public_key_info
    }

    /// The optional `issuerUniqueID`, empty when absent.
    pub(crate) const fn issuer_unique_id(&self) -> &Asn1Element<'a> {
        &self.issuer_unique_id
    }

    /// The optional `subjectUniqueID`, empty when absent.
    pub(crate) const fn subject_unique_id(&self) -> &Asn1Element<'a> {
        &self.subject_unique_id
    }
}

/// Decomposes a DER certificate into its sub-fields.
///
/// Supersedes `Curl_parseX509` (`lib/vtls/x509asn1.c:769-881`), field for
/// field and in the same order, on the same premise the C states:
/// "Syntax is assumed to have already been checked by the SSL backend"
/// (`x509asn1.c:766`). This runs after rustls has accepted a certificate,
/// or against a certificate that is only being described, and it is not a
/// substitute for verification.
///
/// # Errors
///
/// [`CURLcode::PeerFailedVerification`], the code the C's one caller maps
/// its `-1` to (`x509asn1.c:1100-1101`), for any malformed structure.
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) fn parse_x509(der: &[u8]) -> CurlResult<X509Certificate<'_>> {
    let bad = || Error::new(CURLcode::PeerFailedVerification);

    // The outer SEQUENCE. `cert->certificate` spans the whole input.
    let (outer, _) = get_asn1_element(der).ok_or_else(bad)?;
    let body = outer.content;

    let (tbs_certificate, after_tbs) =
        get_asn1_element(body).ok_or_else(bad)?;
    let (outer_signature_algorithm, after_algorithm) =
        get_asn1_element(after_tbs).ok_or_else(bad)?;
    let (signature, _) = get_asn1_element(after_algorithm).ok_or_else(bad)?;

    // TBSCertificate (`x509asn1.c:799-847`).
    let mut remaining = tbs_certificate.content;
    let mut version = Asn1Element {
        content: &DEFAULT_VERSION,
        class: 0,
        tag: 0,
        constructed: false,
    };

    let (mut element, mut rest) =
        get_asn1_element(remaining).ok_or_else(bad)?;
    remaining = rest;
    if element.tag == 0 {
        // `[0] EXPLICIT Version` is present: unwrap it and take the next
        // element as the serial number.
        let (inner, _) = get_asn1_element(element.content).ok_or_else(bad)?;
        version = inner;
        (element, rest) = get_asn1_element(remaining).ok_or_else(bad)?;
        remaining = rest;
    }
    let serial_number = element;

    // The inner signature algorithm replaces the outer one, exactly as the
    // C overwrites `cert->signatureAlgorithm` at `x509asn1.c:818` having
    // already written it at `x509asn1.c:792`.
    let _ = outer_signature_algorithm;
    let (signature_algorithm, rest) =
        get_asn1_element(remaining).ok_or_else(bad)?;
    remaining = rest;

    let (issuer, rest) = get_asn1_element(remaining).ok_or_else(bad)?;
    remaining = rest;

    let (validity, rest) = get_asn1_element(remaining).ok_or_else(bad)?;
    remaining = rest;
    let (not_before, after_not_before) =
        get_asn1_element(validity.content).ok_or_else(bad)?;
    let (not_after, _) = get_asn1_element(after_not_before).ok_or_else(bad)?;

    let (subject, rest) = get_asn1_element(remaining).ok_or_else(bad)?;
    remaining = rest;

    let (subject_public_key_info, rest) =
        get_asn1_element(remaining).ok_or_else(bad)?;
    let mut remaining = rest;
    let (subject_public_key_algorithm, after_key_algorithm) =
        get_asn1_element(subject_public_key_info.content).ok_or_else(bad)?;
    let (subject_public_key, _) =
        get_asn1_element(after_key_algorithm).ok_or_else(bad)?;

    // The three optional trailing members (`x509asn1.c:848-879`). The C
    // resets `elem.tag` to zero first, so a certificate whose TBS ends here
    // matches none of the three tests.
    let mut issuer_unique_id = Asn1Element::EMPTY;
    let mut subject_unique_id = Asn1Element::EMPTY;
    let mut extensions = Asn1Element::EMPTY;
    let mut trailing = Asn1Element::EMPTY;

    if !remaining.is_empty() {
        let (element, rest) = get_asn1_element(remaining).ok_or_else(bad)?;
        trailing = element;
        remaining = rest;
    }
    if trailing.tag == 1 {
        issuer_unique_id = trailing;
        if !remaining.is_empty() {
            let (element, rest) =
                get_asn1_element(remaining).ok_or_else(bad)?;
            trailing = element;
            remaining = rest;
        }
    }
    if trailing.tag == 2 {
        subject_unique_id = trailing;
        if !remaining.is_empty() {
            let (element, _) = get_asn1_element(remaining).ok_or_else(bad)?;
            trailing = element;
        }
    }
    if trailing.tag == 3 {
        let (inner, _) = get_asn1_element(trailing.content).ok_or_else(bad)?;
        extensions = inner;
    }

    Ok(X509Certificate {
        certificate: der,
        version,
        serial_number,
        signature_algorithm,
        signature,
        issuer,
        not_before,
        not_after,
        subject,
        subject_public_key_info,
        subject_public_key_algorithm,
        subject_public_key,
        issuer_unique_id,
        subject_unique_id,
        extensions,
    })
}

// CURLINFO_CERTINFO: supersedes `lib/vtls/x509asn1.c:887-1258`

/// One `CURLINFO_CERTINFO` record: a label and its value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CertInfoRecord {
    /// The label, always one of the fixed set this module emits.
    label: &'static str,
    /// The value, exactly as rendered.
    value: Vec<u8>,
}

#[allow(dead_code)] // consumer: tls/rustls_backend.rs
impl CertInfoRecord {
    /// Builds a record from a label and the bytes rendered for it.
    fn new(label: &'static str, value: &[u8]) -> Self {
        Self {
            label,
            value: value.to_vec(),
        }
    }

    /// The record's label.
    pub(crate) const fn label(&self) -> &'static str {
        self.label
    }

    /// The record's value, as rendered.
    pub(crate) fn value(&self) -> &[u8] {
        &self.value
    }

    /// The value as text, replacing anything that is not UTF-8.
    ///
    /// For diagnostics and tests. The ABI boundary uses [`Self::value`],
    /// which does not substitute anything.
    pub(crate) fn value_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.value)
    }

    /// The `label:value` form the C's `curl_slist` entry holds.
    ///
    /// `curlx_dyn_add(&build, label)`, `":"`, then the value
    /// (`lib/vtls/vtls.c:664-666`).
    // The only caller is `easy/getinfo.rs`, which does not exist yet, so the
    // allowance is what keeps this shape next to the citation it comes from.
    #[allow(dead_code)]
    pub(crate) fn to_slist_entry(&self) -> Vec<u8> {
        let mut entry =
            Vec::with_capacity(self.label.len() + 1 + self.value.len());
        entry.extend_from_slice(self.label.as_bytes());
        entry.push(b':');
        entry.extend_from_slice(&self.value);
        entry
    }
}

/// Renders an AlgorithmIdentifier's name and returns its parameters.
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] when the OID or the parameters cannot
/// be parsed.
fn dump_algo<'a>(
    store: &mut DynBuf,
    content: &'a [u8],
) -> CurlResult<Asn1Element<'a>> {
    let bad = || Error::new(CURLcode::BadFunctionArgument);
    let (oid, after_oid) = get_asn1_element(content).ok_or_else(bad)?;

    let parameters = if after_oid.is_empty() {
        Asn1Element::EMPTY
    } else {
        let (parsed, _) = get_asn1_element(after_oid).ok_or_else(bad)?;
        parsed
    };

    oid_to_str(store, oid.content, true)?;
    Ok(parameters)
}

/// Renders one public-key field into a record.
///
/// # Errors
///
/// Whatever [`asn1_to_str`] returns for the element.
fn pubkey_field(
    records: &mut Vec<CertInfoRecord>,
    label: &'static str,
    element: &Asn1Element<'_>,
) -> CurlResult<()> {
    let mut out = certinfo_buffer();
    asn1_to_str(&mut out, element, 0)?;
    records.push(CertInfoRecord::new(label, out.as_slice()));
    Ok(())
}

/// Renders every record a public key contributes.
///
/// Supersedes `do_pubkey` (`lib/vtls/x509asn1.c:967-1066`), which branches
/// on the algorithm name and is reproduced branch for branch:
///
/// * `ecPublicKey` reports a key size and then the whole BIT STRING, because
///   "ECC public key is all the data ... and should not be parsed as an
///   ASN.1 value" (`x509asn1.c:978-981`).
/// * `rsaEncryption` reports the modulus size in bits with leading zero
///   octets discounted, then the modulus and the exponent.
/// * `dsa` reports p, q, g and the public value, taking the first three from
///   the algorithm parameters.
/// * `dhpublicnumber` reports p, g and the public value.
///
/// # Errors
///
/// Propagates a rendering failure. The caller maps every one of them to
/// [`CURLcode::OutOfMemory`], which is what `x509asn1.c:1198-1200` does with
/// this function's non-zero return.
fn do_pubkey(
    records: &mut Vec<CertInfoRecord>,
    algorithm: &[u8],
    parameters: &Asn1Element<'_>,
    public_key: &Asn1Element<'_>,
) -> CurlResult<()> {
    let bad = || Error::new(CURLcode::BadFunctionArgument);

    if strcase::casecompare(algorithm, b"ecPublicKey") {
        // `((pubkey->end - pubkey->beg - 2) * 4)` (`x509asn1.c:982`). The C
        // subtracts in `size_t`, so a content shorter than two octets wraps
        // to an enormous figure; `saturating_sub` reports zero instead,
        // which is the only difference in this module between the C's
        // arithmetic and this one, and it applies solely to a certificate
        // whose key is already malformed.
        let bits = public_key.content.len().saturating_sub(2) * 4;
        records.push(CertInfoRecord::new(
            "ECC Public Key",
            bits.to_string().as_bytes(),
        ));
        return pubkey_field(records, "ecPublicKey", public_key);
    }

    // Every other algorithm reads through the BIT STRING's unused-bits
    // octet: `getASN1Element(&pk, pubkey->beg + 1, pubkey->end)`
    // (`x509asn1.c:996`).
    let inner = public_key.content.get(1..).ok_or_else(bad)?;
    let (key, _) = get_asn1_element(inner).ok_or_else(bad)?;

    if strcase::casecompare(algorithm, b"rsaEncryption") {
        let (mut modulus, after_modulus) =
            get_asn1_element(key.content).ok_or_else(bad)?;

        // Key size in bits, leading zero octets discounted and the leading
        // zero BITS of the first significant octet discounted with them
        // (`x509asn1.c:1007-1017`).
        let significant = modulus
            .content
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(modulus.content.len());
        let stripped = &modulus.content[significant..];
        let mut bits = stripped.len() * 8;
        if bits > 0 {
            let mut leading = stripped[0];
            while leading & 0x80 == 0 {
                bits -= 1;
                leading <<= 1;
            }
        }
        if bits > 32 {
            // "Strip leading zero bytes" (`x509asn1.c:1016-1017`), which
            // the C does only above 32 bits so that a small value keeps
            // rendering as an integer.
            modulus = Asn1Element {
                content: stripped,
                ..modulus
            };
        }

        records.push(CertInfoRecord::new(
            "RSA Public Key",
            bits.to_string().as_bytes(),
        ));
        pubkey_field(records, "rsa(n)", &modulus)?;
        let (exponent, _) = get_asn1_element(after_modulus).ok_or_else(bad)?;
        pubkey_field(records, "rsa(e)", &exponent)?;
    } else if strcase::casecompare(algorithm, b"dsa") {
        if let Some((p, after_p)) = get_asn1_element(parameters.content) {
            pubkey_field(records, "dsa(p)", &p)?;
            if let Some((q, after_q)) = get_asn1_element(after_p) {
                pubkey_field(records, "dsa(q)", &q)?;
                if let Some((g, _)) = get_asn1_element(after_q) {
                    pubkey_field(records, "dsa(g)", &g)?;
                    pubkey_field(records, "dsa(pub_key)", &key)?;
                }
            }
        }
    } else if strcase::casecompare(algorithm, b"dhpublicnumber") {
        if let Some((p, _)) = get_asn1_element(parameters.content) {
            pubkey_field(records, "dh(p)", &p)?;
            // The C re-parses from `param->beg` here rather than from the
            // position after p (`x509asn1.c:1057`).
            if let Some((g, _)) = get_asn1_element(parameters.content) {
                pubkey_field(records, "dh(g)", &g)?;
                pubkey_field(records, "dh(pub_key)", &key)?;
            }
        }
    }

    Ok(())
}

/// A certificate as a PEM block.
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`] from the base64 encoder, or
/// [`CURLcode::TooLarge`] if the assembled block would cross
/// [`CURL_X509_STR_MAX`].
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) fn certificate_pem(der: &[u8]) -> CurlResult<Vec<u8>> {
    let encoded = base64::encode(der).map_err(Error::new)?;
    let mut out = certinfo_buffer();
    append(out.add("-----BEGIN CERTIFICATE-----\n"))?;
    for line in encoded.as_bytes().chunks(PEM_LINE_WIDTH) {
        append(out.addn(line))?;
        append(out.addn(b"\n"))?;
    }
    append(out.add("-----END CERTIFICATE-----\n"))?;
    Ok(out.take())
}

/// Every `CURLINFO_CERTINFO` record for one certificate, in the C's order.
///
/// Supersedes `Curl_extract_certinfo` (`lib/vtls/x509asn1.c:1077-1258`). The
/// labels and their order are contractual, because a consumer walks the
/// `curl_slist` in the order libcurl built it:
///
/// `Subject`, `Issuer`, `Version`, `Serial Number`, `Signature Algorithm`,
/// `Start Date`, `Expire Date`, `Public Key Algorithm`, the public-key
/// detail records that [`do_pubkey`] contributes for the algorithm in hand,
/// `Signature`, `Cert`.
///
/// # Errors
///
/// [`CURLcode::PeerFailedVerification`] when the certificate cannot be
/// parsed, [`CURLcode::OutOfMemory`] for a public-key rendering failure --
/// the C's own choice, which it labels "the most likely error"
/// (`x509asn1.c:1199`) -- and otherwise the specific code the failing
/// conversion returned. Every one of them carries the C's message,
/// "Failed extracting certificate chain" (`x509asn1.c:1255`).
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) fn extract_certinfo(der: &[u8]) -> CurlResult<Vec<CertInfoRecord>> {
    certinfo_records(der).map_err(|error| {
        error.context_with("Failed extracting certificate chain")
    })
}

/// [`extract_certinfo`] without the shared error message.
fn certinfo_records(der: &[u8]) -> CurlResult<Vec<CertInfoRecord>> {
    let cert = parse_x509(der)?;
    let mut records = Vec::new();
    let mut out = certinfo_buffer();

    encode_dn(&mut out, &cert.subject)?;
    records.push(CertInfoRecord::new("Subject", out.as_slice()));
    out.reset();

    encode_dn(&mut out, &cert.issuer)?;
    records.push(CertInfoRecord::new("Issuer", out.as_slice()));
    out.reset();

    // "Version (always fits in less than 32 bits)"
    // (`x509asn1.c:1125-1128`), rendered in hexadecimal with no prefix.
    let mut version: u32 = 0;
    for byte in cert.version.content {
        version = (version << 8) | u32::from(*byte);
    }
    append(out.addf(format_args!("{version:x}")))?;
    records.push(CertInfoRecord::new("Version", out.as_slice()));
    out.reset();

    asn1_to_str(&mut out, &cert.serial_number, 0)?;
    records.push(CertInfoRecord::new("Serial Number", out.as_slice()));
    out.reset();

    let _signature_parameters =
        dump_algo(&mut out, cert.signature_algorithm.content)?;
    records.push(CertInfoRecord::new("Signature Algorithm", out.as_slice()));
    out.reset();

    asn1_to_str(&mut out, &cert.not_before, 0)?;
    records.push(CertInfoRecord::new("Start Date", out.as_slice()));
    out.reset();

    asn1_to_str(&mut out, &cert.not_after, 0)?;
    records.push(CertInfoRecord::new("Expire Date", out.as_slice()));
    out.reset();

    // The C does NOT reset the buffer here: the rendered algorithm name is
    // both the record's value and the `algo` argument `do_pubkey` branches
    // on (`x509asn1.c:1184-1197`).
    let key_parameters =
        dump_algo(&mut out, cert.subject_public_key_algorithm.content)?;
    records.push(CertInfoRecord::new("Public Key Algorithm", out.as_slice()));
    let algorithm = out.as_slice().to_vec();
    do_pubkey(
        &mut records,
        &algorithm,
        &key_parameters,
        &cert.subject_public_key,
    )
    .map_err(|_| Error::new(CURLcode::OutOfMemory))?;
    out.reset();

    asn1_to_str(&mut out, &cert.signature, 0)?;
    records.push(CertInfoRecord::new("Signature", out.as_slice()));

    let pem = certificate_pem(cert.certificate)?;
    records.push(CertInfoRecord::new("Cert", &pem));

    Ok(records)
}

/// Every `CURLINFO_CERTINFO` record for a whole chain.
///
/// # Errors
///
/// [`CURLcode::SslConnectError`] for a chain above the ceiling
/// (`rustls.c:1201-1205`), or whatever [`extract_certinfo`] returns for a
/// member of the chain.
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) fn extract_certinfo_chain(
    chain: &[CertificateDer<'_>],
) -> CurlResult<Vec<Vec<CertInfoRecord>>> {
    if chain.len() > MAX_ALLOWED_CERT_AMOUNT {
        return Err(Error::with_context(
            CURLcode::SslConnectError,
            format!(
                "{} certificates is more than allowed ({})",
                chain.len(),
                MAX_ALLOWED_CERT_AMOUNT
            ),
        ));
    }
    chain
        .iter()
        .map(|certificate| extract_certinfo(certificate.as_ref()))
        .collect()
}

// Hostname matching: supersedes `lib/vtls/hostcheck.c:39-125`

/// True when `hostname` is an IPv4 or IPv6 literal.
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) fn host_is_ipnum(hostname: &[u8]) -> bool {
    inet::pton(hostname).is_some()
}

/// Compares two byte strings of a given length, case-insensitively.
fn pmatch(hostname: &[u8], pattern: &[u8]) -> bool {
    hostname.len() == pattern.len()
        && strcase::ncasecompare(hostname, pattern, hostname.len())
}

/// Matches a hostname against a certificate pattern, wildcards included.
///
/// Supersedes `hostmatch` (`lib/vtls/hostcheck.c:73-114`), which implements
/// RFC 6125 section 6.4.3 with three additions curl documents at
/// `hostcheck.c:49-71` and which are the parts a reader tends to guess
/// wrong:
///
/// * Trailing dots are ignored on BOTH sides, one each, "so that the names
///   are used normalized. This is what the browsers do."
/// * A wildcard never matches an IP literal, because "there are apparently
///   certificates being used with an IP address in the CN field", and a
///   hostname beginning with a dot never matches one either.
/// * "Only match on `*` being used for the leftmost label, not `a*`, `a*b`
///   nor `*b`" -- which follows from testing the pattern for the two-byte
///   prefix `*.` rather than searching it for a star.
fn hostmatch(hostname: &[u8], pattern: &[u8]) -> bool {
    // "normalize pattern and hostname by stripping off trailing dots"
    // (`hostcheck.c:85-89`).
    let host = match hostname.split_last() {
        Some((b'.', head)) => head,
        _ => hostname,
    };
    let pat = match pattern.split_last() {
        Some((b'.', head)) => head,
        _ => pattern,
    };

    if !pattern.starts_with(b"*.") {
        return pmatch(host, pat);
    }

    // "detect host as IP address or starting with a dot and fail if so"
    // (`hostcheck.c:94-96`).
    if host_is_ipnum(hostname) || hostname.first() == Some(&b'.') {
        return false;
    }

    // "We require at least 2 dots in the pattern to avoid too wide wildcard
    // match" (`hostcheck.c:98-103`). The C expresses "fewer than two" as
    // `memrchr(...) == memchr(...)`: the last dot being the first one.
    let Some(first_dot) = pat.iter().position(|byte| *byte == b'.') else {
        return pmatch(host, pat);
    };
    let last_dot = pat.iter().rposition(|byte| *byte == b'.');
    if last_dot == Some(first_dot) {
        return pmatch(host, pat);
    }

    // Compare from each side's first dot inclusive (`hostcheck.c:105-111`).
    match host.iter().position(|byte| *byte == b'.') {
        Some(host_dot) => pmatch(&host[host_dot..], &pat[first_dot..]),
        None => false,
    }
}

/// True when a certificate name matches a hostname.
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) fn cert_hostcheck(pattern: &[u8], hostname: &[u8]) -> bool {
    if matches!(pattern.first(), None | Some(0))
        || matches!(hostname.first(), None | Some(0))
    {
        return false;
    }
    hostmatch(hostname, pattern)
}

/// Which certificate field satisfied the hostname check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostMatch {
    /// A subjectAltName entry of the target's own kind matched.
    SubjectAltName,
    /// No subjectAltName of that kind existed and the commonName matched.
    CommonName,
}

/// A subjectAltName entry of a kind this module compares.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GeneralName<'a> {
    /// `dNSName`, context-specific tag 2.
    Dns(&'a [u8]),
    /// `iPAddress`, context-specific tag 7: raw address octets, four for
    /// IPv4 and sixteen for IPv6.
    IpAddress(&'a [u8]),
}

/// The context-specific tag of `dNSName` in a GeneralName.
const GENERAL_NAME_DNS: u8 = 2;

/// The context-specific tag of `iPAddress` in a GeneralName.
const GENERAL_NAME_IP: u8 = 7;

/// The ASN.1 class of a context-specific tag.
const ASN1_CLASS_CONTEXT: u8 = 2;

/// The subjectAltName entries a certificate carries.
fn subject_alt_names<'a>(cert: &X509Certificate<'a>) -> Vec<GeneralName<'a>> {
    decode_subject_alt_names(cert).unwrap_or_default()
}

/// [`subject_alt_names`] with its failures still visible.
///
/// Split out so that the "malformed is the same as absent" decision is made
/// in exactly one place, and so that a test can tell an empty extension from
/// an unparsable one.
fn decode_subject_alt_names<'a>(
    cert: &X509Certificate<'a>,
) -> Option<Vec<GeneralName<'a>>> {
    let mut remaining = cert.extensions.content;
    while !remaining.is_empty() {
        let (extension, rest) = get_asn1_element(remaining)?;
        remaining = rest;

        // Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE,
        //                          extnValue OCTET STRING }
        let (oid, after_oid) = get_asn1_element(extension.content)?;
        if oid.tag != ASN1_OBJECT_IDENTIFIER {
            continue;
        }
        if oid_numeric(oid.content).ok()? != OID_SUBJECT_ALT_NAME {
            continue;
        }

        let (mut value, after_value) = get_asn1_element(after_oid)?;
        if value.tag == ASN1_BOOLEAN {
            // The optional `critical` flag was present; the payload is the
            // element after it.
            (value, _) = get_asn1_element(after_value)?;
        }
        if value.tag != ASN1_OCTET_STRING {
            return None;
        }

        // The OCTET STRING wraps `GeneralNames ::= SEQUENCE OF GeneralName`.
        let (names, _) = get_asn1_element(value.content)?;
        let mut entries = Vec::new();
        let mut cursor = names.content;
        while !cursor.is_empty() {
            let (entry, rest) = get_asn1_element(cursor)?;
            cursor = rest;
            if entry.class != ASN1_CLASS_CONTEXT || entry.constructed {
                // A constructed alternative is `otherName`, `directoryName`
                // or another form this module does not compare.
                continue;
            }
            match entry.tag {
                GENERAL_NAME_DNS => {
                    entries.push(GeneralName::Dns(entry.content));
                }
                GENERAL_NAME_IP => {
                    entries.push(GeneralName::IpAddress(entry.content));
                }
                _ => {}
            }
        }
        return Some(entries);
    }
    Some(Vec::new())
}

/// The last commonName in a distinguished name, rendered.
///
/// # Errors
///
/// [`CURLcode::OutOfMemory`], which is what the C reports when
/// `ASN1_STRING_to_UTF8` fails (`lib/vtls/openssl.c:2216-2217`), if a
/// commonName is present but cannot be rendered.
fn last_common_name(dn: &Asn1Element<'_>) -> CurlResult<Option<Vec<u8>>> {
    let mut found: Option<Vec<u8>> = None;
    let mut names = dn.content;

    while !names.is_empty() {
        let Some((rdn, rest)) = get_asn1_element(names) else {
            break;
        };
        names = rest;

        let mut pairs = rdn.content;
        while !pairs.is_empty() {
            let Some((attribute, rest)) = get_asn1_element(pairs) else {
                break;
            };
            pairs = rest;

            let Some((oid, after_oid)) = get_asn1_element(attribute.content)
            else {
                break;
            };
            let Some((value, _)) = get_asn1_element(after_oid) else {
                break;
            };
            if oid.tag != ASN1_OBJECT_IDENTIFIER {
                continue;
            }
            if oid_numeric(oid.content)? != OID_COMMON_NAME {
                continue;
            }

            let mut rendered = certinfo_buffer();
            asn1_to_str(&mut rendered, &value, 0)
                .map_err(|_| Error::new(CURLcode::OutOfMemory))?;
            found = Some(rendered.take());
        }
    }
    Ok(found)
}

/// The noun the C uses for a target of each kind, for its messages.
///
/// `(peer->type == CURL_SSL_PEER_DNS) ? "hostname" : (peer->type ==
/// CURL_SSL_PEER_IPV4) ? "ipv4 address" : "ipv6 address"`
/// (`lib/vtls/openssl.c:2169-2171`). The text reaches standard error, so it
/// is frozen output rather than a formatting choice.
const fn target_noun(kind: SslPeerType) -> &'static str {
    match kind {
        SslPeerType::Dns => "hostname",
        SslPeerType::Ipv4 => "ipv4 address",
        SslPeerType::Ipv6 => "ipv6 address",
    }
}

/// Verifies a peer certificate's names against the hostname curl asked for.
///
/// Supersedes `ossl_verifyhost` (`lib/vtls/openssl.c:2053-2248`), which is
/// where curl's certificate-level policy lives, with [`cert_hostcheck`]
/// supplying the string comparison. The policy, in the order the C applies
/// it:
///
/// 1. The target is an address when the hostname is an IPv4 or IPv6 literal,
///    and a name otherwise. An address that will not parse is a
///    verification failure before the certificate is even read.
/// 2. Every subjectAltName entry is examined. Entries of the target's own
///    kind are compared -- names through [`cert_hostcheck`], so a wildcard
///    can match; addresses byte for byte, so a wildcard cannot.
/// 3. A dNSName entry carrying an embedded zero is skipped: the C requires
///    `altlen == strlen(altptr)` because "there was an embedded zero in the
///    name string and we cannot match it".
/// 4. If nothing matched but the certificate carried ANY dNSName or ANY
///    iPAddress, verification fails. The commonName is not consulted --
///    that is RFC 6125's rule and the C's.
/// 5. Only a certificate with neither reaches the commonName, and the LAST
///    one in the subject is the one compared.
///
/// # Errors
///
/// [`CURLcode::PeerFailedVerification`] for every mismatch, with the C's own
/// message text, and [`CURLcode::OutOfMemory`] for a commonName that cannot
/// be rendered.
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) fn verify_hostname(
    certificate: &[u8],
    hostname: &str,
    dispname: &str,
) -> CurlResult<HostMatch> {
    let kind = SslPeerType::classify(hostname);
    let noun = target_noun(kind);

    // `curlx_inet_pton` must succeed for a literal (`openssl.c:2075-2085`).
    let target_address = match kind {
        SslPeerType::Dns => None,
        SslPeerType::Ipv4 | SslPeerType::Ipv6 => {
            match inet::pton(hostname.as_bytes()) {
                Some(IpAddr::V4(address)) => Some(address.octets().to_vec()),
                Some(IpAddr::V6(address)) => Some(address.octets().to_vec()),
                None => {
                    return Err(Error::with_context(
                        CURLcode::PeerFailedVerification,
                        format!("SSL: could not parse target {noun}"),
                    ))
                }
            }
        }
    };

    let cert = parse_x509(certificate)?;
    let alt_names = subject_alt_names(&cert);

    let mut dns_present = false;
    let mut ip_present = false;
    let mut matched = false;

    for entry in &alt_names {
        match entry {
            GeneralName::Dns(_) => dns_present = true,
            GeneralName::IpAddress(_) => ip_present = true,
        }
        if matched {
            // The C's loop condition is `(i < numalts) && !matched`, so it
            // stops comparing once one matches -- but the flags above are
            // set before that test in this pass, which cannot change the
            // outcome: `matched` already decides it.
            continue;
        }
        match (entry, target_address.as_deref()) {
            (GeneralName::Dns(name), None) => {
                // "if this is not true, there was an embedded zero in the
                // name string and we cannot match it"
                // (`openssl.c:2141-2143`).
                if !name.contains(&0)
                    && cert_hostcheck(name, hostname.as_bytes())
                {
                    matched = true;
                }
            }
            (GeneralName::IpAddress(octets), Some(address))
                if *octets == address =>
            {
                matched = true;
            }
            _ => {}
        }
    }

    if matched {
        return Ok(HostMatch::SubjectAltName);
    }

    if dns_present || ip_present {
        return Err(Error::with_context(
            CURLcode::PeerFailedVerification,
            format!(
                "SSL: no alternative certificate subject name matches \
                 target {noun} '{dispname}'"
            ),
        ));
    }

    // The commonName fallback (`openssl.c:2176-2246`).
    let Some(common_name) = last_common_name(&cert.subject)? else {
        return Err(Error::with_context(
            CURLcode::PeerFailedVerification,
            "SSL: unable to obtain common name from peer certificate",
        ));
    };
    if common_name.contains(&0) {
        // "there was a terminating zero before the end of string, this
        // cannot match and we return failure!" (`openssl.c:2216-2220`).
        return Err(Error::with_context(
            CURLcode::PeerFailedVerification,
            "SSL: illegal cert name field",
        ));
    }
    if cert_hostcheck(&common_name, hostname.as_bytes()) {
        return Ok(HostMatch::CommonName);
    }
    Err(Error::with_context(
        CURLcode::PeerFailedVerification,
        format!(
            "SSL: certificate subject name '{}' does not match \
             target hostname '{dispname}'",
            String::from_utf8_lossy(&common_name)
        ),
    ))
}

// Trust sources: supersedes `lib/vtls/rustls.c:698-807` and `:1014-1017`

/// Reads a file into a buffer with a ceiling, or reports failure.
fn read_file_into(path: &Path, ceiling: usize) -> Option<Vec<u8>> {
    let mut file = fs::File::open(path).ok()?;
    let mut store = DynBuf::new(ceiling);
    let mut chunk = [0u8; 256];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => store.addn(&chunk[..read]).ok()?,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                // A signal arrived mid-read. The C's `fread` retries
                // internally; retrying here is the same behaviour.
            }
            Err(_) => return None,
        }
    }
    Some(store.take())
}

/// Where the trust anchors come from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TrustSource {
    /// The compiled-in Mozilla root program, from `webpki-roots 1.0.9`.
    BundledRoots,
    /// The platform's certificate store, read through
    /// `rustls-native-certs 0.8.4`.
    NativeRoots,
    /// `CURLOPT_CAINFO` / `--cacert`: a PEM bundle at a path.
    CaFile(PathBuf),
    /// `CURLOPT_CAINFO_BLOB`: a PEM bundle already in memory.
    CaBlob(Vec<u8>),
}

#[allow(dead_code)] // consumer: tls/rustls_backend.rs
impl TrustSource {
    /// Applies curl's precedence to the three options that select trust.
    pub(crate) fn from_curl_options(
        ca_info_blob: Option<Vec<u8>>,
        ca_file: Option<PathBuf>,
        native_ca_store: bool,
    ) -> Self {
        if let Some(blob) = ca_info_blob {
            return Self::CaBlob(blob);
        }
        if let Some(path) = ca_file {
            return Self::CaFile(path);
        }
        if native_ca_store {
            return Self::NativeRoots;
        }
        Self::BundledRoots
    }
}

/// Collects PEM certificates into a root store, strictly.
///
/// # Errors
///
/// [`CURLcode::SslCacertBadfile`] with `context` as its message, for an
/// unparsable PEM section, a certificate rustls refuses, or a bundle that
/// yields no anchors at all.
fn roots_from_pem(
    pem: &[u8],
    context: &'static str,
) -> CurlResult<RootCertStore> {
    let bad = || Error::with_context(CURLcode::SslCacertBadfile, context);
    let mut store = RootCertStore::empty();

    for item in CertificateDer::pem_slice_iter(pem) {
        let certificate = item.map_err(|_| bad())?;
        store.add(certificate).map_err(|_| bad())?;
    }

    if store.is_empty() {
        // `rustls_root_cert_store_builder_build` fails on an empty store,
        // which `lib/vtls/rustls.c:734-739` maps to this same code.
        return Err(bad());
    }
    Ok(store)
}

/// Builds the root store a policy asks for.
///
/// # Errors
///
/// * [`CURLcode::NotBuiltIn`] when a `--capath` reaches this module. The
///   rustls backend does not advertise `SSLSUPP_CA_PATH`
///   (`lib/vtls/rustls.c:1399-1405` lists what it does advertise), and
///   `lib/setopt.c:1821-1827` shows what curl does with an unsupported
///   capath: it refuses the option with `CURLE_NOT_BUILT_IN`. Silently
///   ignoring the directory, or quietly substituting the native store for
///   it, would leave the user trusting something they did not name.
/// * [`CURLcode::SslCacertBadfile`] for an unreadable, unparsable or empty
///   bundle, and for a platform store that cannot be read.
fn build_root_store(policy: &VerifyPolicy) -> CurlResult<RootCertStore> {
    if let Some(path) = policy.ca_path.as_deref() {
        return Err(Error::with_context(
            CURLcode::NotBuiltIn,
            format!(
                "rustls: CURLOPT_CAPATH is not supported by this backend, \
                 refusing to ignore '{}'",
                path.display()
            ),
        ));
    }

    match &policy.trust {
        TrustSource::BundledRoots => Ok(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }),
        TrustSource::NativeRoots => {
            // `load_native_certs` reports partial failure through `errors`
            // and offers `expect`/`unwrap` helpers that PANIC. Neither is
            // used: a certificate store that cannot be read is an error to
            // return, never a reason to abort the process.
            let loaded = rustls_native_certs::load_native_certs();
            if !loaded.errors.is_empty() || loaded.certs.is_empty() {
                return Err(Error::with_context(
                    CURLcode::SslCacertBadfile,
                    "rustls: failed to load the platform certificate store",
                ));
            }
            let mut store = RootCertStore::empty();
            for certificate in loaded.certs {
                store.add(certificate).map_err(|_| {
                    Error::with_context(
                        CURLcode::SslCacertBadfile,
                        "rustls: platform certificate store holds an \
                         unusable certificate",
                    )
                })?;
            }
            Ok(store)
        }
        TrustSource::CaFile(path) => {
            let pem =
                read_file_into(path, DYN_CAFILE_SIZE).ok_or_else(|| {
                    Error::with_context(
                        CURLcode::SslCacertBadfile,
                        "rustls: failed to load trusted certificates",
                    )
                })?;
            roots_from_pem(&pem, "rustls: failed to load trusted certificates")
        }
        TrustSource::CaBlob(blob) => roots_from_pem(
            blob,
            "rustls: failed to parse trusted certificates from blob",
        ),
    }
}

/// Loads the revocation lists a policy names.
///
/// # Errors
///
/// [`CURLcode::SslCrlBadfile`] when the file cannot be read, cannot be
/// parsed, or contains no revocation list. An empty file is refused rather
/// than treated as "revoke nothing": a caller who passed `--crlfile` asked
/// for revocation checking, and quietly performing none would be the wrong
/// answer to give them.
fn load_crls(
    path: &Path,
) -> CurlResult<Vec<CertificateRevocationListDer<'static>>> {
    let read = || {
        Error::with_context(
            CURLcode::SslCrlBadfile,
            "rustls: failed to read revocation list file",
        )
    };
    let parse = || {
        Error::with_context(
            CURLcode::SslCrlBadfile,
            "rustls: failed to parse revocation list",
        )
    };

    let pem = read_file_into(path, DYN_CRLFILE_SIZE).ok_or_else(read)?;
    let mut lists = Vec::new();
    for item in CertificateRevocationListDer::pem_slice_iter(&pem) {
        lists.push(item.map_err(|_| parse())?);
    }
    if lists.is_empty() {
        return Err(parse());
    }
    Ok(lists)
}

// The verification policy: supersedes `lib/vtls/rustls.c:1024-1053`

/// What verification a connection is to perform.
///
/// The successor of the members of `struct ssl_primary_config` that decide
/// verification -- `verifypeer`, `verifyhost`, `CAfile`, `CApath`,
/// `ca_info_blob` and `CRLfile` -- as a type whose [`Default`] is the secure
/// configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifyPolicy {
    /// `CURLOPT_SSL_VERIFYPEER`: check the chain to a trust anchor.
    verify_peer: bool,
    /// `CURLOPT_SSL_VERIFYHOST`: check the names in the certificate.
    verify_host: bool,
    /// Where the trust anchors come from.
    trust: TrustSource,
    /// `CURLOPT_CAPATH`, which this backend does not support and does not
    /// ignore either. Carried so that [`build_root_store`] can refuse it
    /// with a message naming the directory.
    ca_path: Option<PathBuf>,
    /// `CURLOPT_CRLFILE`.
    crl_file: Option<PathBuf>,
}

impl Default for VerifyPolicy {
    fn default() -> Self {
        Self {
            verify_peer: true,
            verify_host: true,
            trust: TrustSource::BundledRoots,
            ca_path: None,
            crl_file: None,
        }
    }
}

#[allow(dead_code)] // consumer: tls/rustls_backend.rs
impl VerifyPolicy {
    /// The default policy: both checks on, bundled roots.
    ///
    /// Named as well as derived because a reader of a call site should be
    /// able to see which policy is being built without looking the
    /// [`Default`] implementation up.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Selects the trust source.
    #[must_use]
    pub(crate) fn with_trust_source(mut self, trust: TrustSource) -> Self {
        self.trust = trust;
        self
    }

    /// Records a `--capath`, which this backend refuses rather than ignores.
    #[must_use]
    pub(crate) fn with_ca_path(mut self, path: Option<PathBuf>) -> Self {
        self.ca_path = path;
        self
    }

    /// Selects a revocation list.
    #[must_use]
    pub(crate) fn with_crl_file(mut self, path: Option<PathBuf>) -> Self {
        self.crl_file = path;
        self
    }

    /// Sets `CURLOPT_SSL_VERIFYPEER`.
    ///
    /// Passing `false` here is the ONLY way to reach the unverified path,
    /// and it is what `--insecure` does. Every other failure -- a missing
    /// root, an unparsable bundle, a hostname mismatch -- is an error
    /// instead.
    #[must_use]
    pub(crate) fn with_peer_verification(mut self, verify: bool) -> Self {
        self.verify_peer = verify;
        self
    }

    /// Sets `CURLOPT_SSL_VERIFYHOST`.
    #[must_use]
    pub(crate) fn with_host_verification(mut self, verify: bool) -> Self {
        self.verify_host = verify;
        self
    }

    /// Whether the peer chain is to be verified.
    pub(crate) const fn verify_peer(&self) -> bool {
        self.verify_peer
    }

    /// Whether the certificate's names are to be verified.
    pub(crate) const fn verify_host(&self) -> bool {
        self.verify_host
    }

    /// The selected trust source.
    pub(crate) const fn trust(&self) -> &TrustSource {
        &self.trust
    }

    /// The recorded `--capath`, if any.
    #[allow(dead_code)] // consumer: tls/rustls_backend.rs
    pub(crate) fn ca_path(&self) -> Option<&Path> {
        self.ca_path.as_deref()
    }

    /// The selected revocation list, if any.
    #[allow(dead_code)] // consumer: tls/rustls_backend.rs
    pub(crate) fn crl_file(&self) -> Option<&Path> {
        self.crl_file.as_deref()
    }
}

// The one dangerous path: supersedes `cr_verify_none`, rustls.c:377-385

/// Whether a rustls error is the name check, and only the name check.
///
/// `CURLOPT_SSL_VERIFYHOST` turns the subject-name check off while leaving the
/// chain check on, and rustls has no builder for that combination: its
/// `WebPkiServerVerifier` does both in one call. The combination is therefore
/// assembled by running that verifier and discarding exactly this one class of
/// failure -- which is safe only if the class is recognised precisely, so the
/// test is written against the two variants rustls defines and nothing wider.
///
/// [`rustls::CertificateError::NotValidForNameContext`] is documented as
/// *"semantically the same as `NotValidForName`, but includes extra
/// context"* (`rustls-0.23.42/src/error.rs:464-466`), so both are the name
/// check and both are discarded. `Other`, `Expired`, `Revoked`,
/// `UnknownIssuer`, `BadSignature` and every remaining variant are chain or
/// validity failures and are propagated: with `VERIFYPEER` on, an untrusted
/// issuer must still fail.
fn is_name_mismatch(error: &rustls::Error) -> bool {
    matches!(
        error,
        rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. }
        )
    )
}

/// The certificate verifier for the two states web-PKI cannot express.
///
/// `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` are independent in
/// the C -- `lib/setopt.c:723` writes `verifyhost` without consulting
/// `verifypeer`, and `lib/vtls/openssl.c`'s `Curl_ossl_check_peer_cert` runs
/// `ossl_verifyhost` under `if(conn_config->verifyhost)` alone -- so there are
/// four states, not two. Two of them are `WebPkiServerVerifier`'s business
/// (`verify_host` decides only whether the caller also runs
/// [`verify_hostname`] afterwards); the other two land here:
///
/// * `chain_only: None` -- verify nothing about the certificate. This is the
///   exact Rust equivalent of C `cr_verify_none`
///   (`lib/vtls/rustls.c:377-385`):
///
///   ```c
///   static uint32_t cr_verify_none(void *userdata,
///                                 const rustls_verify_server_cert_params *p)
///   {
///     (void)userdata;
///     (void)p;
///     return RUSTLS_RESULT_OK;
///   }
///   ```
///
/// * `chain_only: Some(verifier)` -- verify the chain and **not** the name.
///   The inner verifier is the very one the fully-verifying state uses, built
///   from the same trust anchors and the same revocation list, so the chain
///   verdict is identical in both states and `--crlfile` keeps working.
///   Only [`is_name_mismatch`] failures are discarded.
///
/// The handshake signature is verified in both modes, because neither option
/// disables it -- see [`Self::verify_tls12_signature`]. Those two methods and
/// [`Self::supported_verify_schemes`] read the injected provider directly,
/// which is what `WebPkiServerVerifier` does with the same provider, so the
/// chain-only mode agrees with the fully-verifying state there as well.
#[derive(Debug)]
struct RelaxedVerifier {
    provider: Arc<CryptoProvider>,
    /// `Some` for `VERIFYPEER=1, VERIFYHOST=0`; `None` for `VERIFYPEER=0`.
    chain_only: Option<Arc<WebPkiServerVerifier>>,
}

impl ServerCertVerifier for RelaxedVerifier {
    /// Verifies as much as the two options ask for, and no more.
    ///
    /// With `chain_only` unset: `return RUSTLS_RESULT_OK;`
    /// (`lib/vtls/rustls.c:384`), without looking at anything.
    ///
    /// With `chain_only` set: the inner web-PKI verifier's verdict, except
    /// that a name mismatch is not a failure -- which is what
    /// `CURLOPT_SSL_VERIFYHOST 0` means while `CURLOPT_SSL_VERIFYPEER` is 1.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(verifier) = self.chain_only.as_deref() {
            match verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                // The chain is trusted and the name matched as well. The
                // assertion the inner verifier returned is discarded rather
                // than forwarded so that this function has exactly one place
                // that produces one, which is what
                // `exactly_one_type_asserts_a_certificate_without_checking_it`
                // reads.
                Ok(_verified) => {}
                // The chain is trusted and the name did not match. That is
                // precisely the state `VERIFYHOST 0` describes, so it is not
                // an error here.
                Err(error) if is_name_mismatch(&error) => {}
                // Every other failure is a chain or validity failure and
                // `VERIFYPEER` is on, so it stands.
                Err(error) => return Err(error),
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    /// Verifies the TLS 1.2 handshake signature, which `--insecure` does
    /// not disable.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// Verifies the TLS 1.3 handshake signature, likewise.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    /// The schemes the injected provider supports.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Which verifier a [`ServerVerification`] holds.
///
/// Two variants, because rustls offers exactly two installation routes -- its
/// own web-PKI verifier, or a custom one behind `dangerous()` -- and making
/// them a closed enumeration is what lets [`ServerVerification::install`] hold
/// the only production `dangerous()` call: the choice is a `match` over a type
/// only this module can construct, not a boolean somebody could flip. Test
/// fixtures in `tls/rustls_backend.rs` call `dangerous()` too, so the claim
/// is about production paths, not about the whole crate.
///
/// Two variants, four states. The `VERIFYPEER`/`VERIFYHOST` pair has four
/// settings and [`RelaxedVerifier`] covers three of them between its two
/// modes; which state a `Relaxed` value represents is read from that
/// verifier's own `chain_only` field and from
/// [`ServerVerification::host_verification_enabled`], never inferred from the
/// variant.
#[derive(Debug)]
enum ServerVerifierKind {
    /// Full web-PKI verification, with revocation checking when configured.
    WebPki(Arc<WebPkiServerVerifier>),
    /// [`RelaxedVerifier`]: `VERIFYPEER 0`, or `VERIFYPEER 1` with
    /// `VERIFYHOST 0`.
    Relaxed(Arc<RelaxedVerifier>),
}

/// A built server-certificate verifier, plus what the caller must report.
#[derive(Debug)]
pub(crate) struct ServerVerification {
    /// The verifier itself.
    kind: ServerVerifierKind,
    /// Fixed at construction; see
    /// [`Self::peer_verification_disabled`].
    peer_verification_disabled: bool,
    /// Whether the caller is to apply [`verify_hostname`] once the peer
    /// certificate is available.
    verify_host: bool,
}

#[allow(dead_code)] // consumer: tls/rustls_backend.rs
impl ServerVerification {
    /// Builds the verifier a policy calls for.
    ///
    /// # Four states, not two
    ///
    /// `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` are independent
    /// options and the C keeps them independent. `lib/setopt.c:723` writes
    /// `verifyhost` without reading `verifypeer`, and `Curl_ossl_check_peer_cert`
    /// (`lib/vtls/openssl.c`) runs the chain verdict under `verifypeer` and
    /// `ossl_verifyhost` under `if(conn_config->verifyhost)`, each on its own.
    /// `lib/vtls/schannel.c:1469` goes further and spells the mixed case out as
    /// `if(!verifypeer && verifyhost)`. So all four combinations are reachable
    /// through the public API and each is answered here:
    ///
    /// | `VERIFYPEER` | `VERIFYHOST` | chain | name |
    /// |---|---|---|---|
    /// | 1 | 1 | web-PKI | web-PKI during the handshake, and [`verify_hostname`] after it |
    /// | 1 | 0 | web-PKI | not checked |
    /// | 0 | 1 | not checked | [`verify_hostname`] after the handshake |
    /// | 0 | 0 | not checked | not checked |
    ///
    /// The third row is the one that has no rustls builder at all and the one a
    /// two-state reading loses: switching the chain off must not switch the
    /// name check off with it, because `--insecure` and
    /// `--no-check-certificate`-style host relaxation are separate requests.
    ///
    /// `lib/vtls/rustls.c:1032-1053` is the C this supersedes:
    ///
    /// ```c
    /// if(!conn_config->verifypeer) {
    ///   rustls_client_config_builder_dangerous_set_certificate_verifier(
    ///     config_builder, cr_verify_none);
    /// }
    /// else if(...) { /* trust sources */ }
    /// ```
    ///
    /// That branch reads `verifypeer` only because the rustls-ffi backend has
    /// no way to express row two, and `lib/vtls/rustls.c` therefore leaves the
    /// name check to `Curl_ossl_check_peer_cert`'s equivalent in the shared
    /// layer. The shape here is the same: the chain decision is made at
    /// configuration time and the name decision is carried in
    /// [`Self::host_verification_enabled`] for the caller to act on.
    ///
    /// # Errors
    ///
    /// Whatever [`build_root_store`] or [`load_crls`] returns, plus
    /// [`CURLcode::SslCacertBadfile`] when rustls refuses to build a
    /// verifier from the assembled roots.
    pub(crate) fn build(
        policy: &VerifyPolicy,
        provider: &Arc<CryptoProvider>,
    ) -> CurlResult<Self> {
        match (policy.verify_peer, policy.verify_host) {
            (true, true) => Self::web_pki(policy, provider),
            (true, false) => Self::chain_without_name(policy, provider),
            // The name decision is carried through unchanged: with the chain
            // switched off, `verify_host` still decides whether the caller
            // runs `verify_hostname`.
            (false, verify_host) => Ok(
                Self::insecure_disable_peer_verification(provider, verify_host),
            ),
        }
    }

    /// The web-PKI verifier both verifying states share.
    ///
    /// Extracted so that `VERIFYPEER=1, VERIFYHOST=1` and
    /// `VERIFYPEER=1, VERIFYHOST=0` cannot diverge on trust anchors, on
    /// revocation, or on the codes a failed build reports: the chain verdict is
    /// the same object in both, and only the name check differs.
    fn web_pki_verifier(
        policy: &VerifyPolicy,
        provider: &Arc<CryptoProvider>,
    ) -> CurlResult<Arc<WebPkiServerVerifier>> {
        let roots = Arc::new(build_root_store(policy)?);
        let mut builder = WebPkiServerVerifier::builder_with_provider(
            roots,
            Arc::clone(provider),
        );
        if let Some(path) = policy.crl_file.as_deref() {
            builder = builder.with_crls(load_crls(path)?);
        }

        builder.build().map_err(|error| match error {
            VerifierBuilderError::InvalidCrl(_) => Error::with_context(
                CURLcode::SslCrlBadfile,
                "rustls: failed to parse revocation list",
            ),
            // `NoRootAnchors`, and anything a future rustls adds: the C
            // maps a failed verifier build to this code
            // (`lib/vtls/rustls.c:757-762`).
            _ => Error::with_context(
                CURLcode::SslCacertBadfile,
                "rustls: failed to build certificate verifier",
            ),
        })
    }

    /// The fully verifying path: web-PKI against the policy's trust anchors,
    /// with the name checked as well. `VERIFYPEER=1, VERIFYHOST=1`.
    fn web_pki(
        policy: &VerifyPolicy,
        provider: &Arc<CryptoProvider>,
    ) -> CurlResult<Self> {
        Ok(Self {
            kind: ServerVerifierKind::WebPki(Self::web_pki_verifier(
                policy, provider,
            )?),
            peer_verification_disabled: false,
            verify_host: policy.verify_host,
        })
    }

    /// The chain-only path: the same web-PKI verdict, with the subject name
    /// deliberately not checked. `VERIFYPEER=1, VERIFYHOST=0`.
    ///
    /// The inner verifier is built exactly as [`Self::web_pki`] builds it --
    /// same anchors, same `--crlfile` -- and wrapped so that a name mismatch,
    /// and only a name mismatch, is not a failure. An untrusted issuer, an
    /// expired certificate or a revoked one still fails, which is what keeps
    /// `VERIFYHOST 0` from quietly becoming `VERIFYPEER 0`.
    fn chain_without_name(
        policy: &VerifyPolicy,
        provider: &Arc<CryptoProvider>,
    ) -> CurlResult<Self> {
        let inner = Self::web_pki_verifier(policy, provider)?;
        Ok(Self {
            kind: ServerVerifierKind::Relaxed(Arc::new(RelaxedVerifier {
                provider: Arc::clone(provider),
                chain_only: Some(inner),
            })),
            peer_verification_disabled: false,
            verify_host: false,
        })
    }

    /// Builds the configuration whose chain is UNVERIFIED. `VERIFYPEER=0`.
    ///
    /// `verify_host` is the policy's own value, not `false`: `--insecure` in
    /// the tool sets both options together, but the library API can set either
    /// alone, and a caller that asked for the name to be checked gets the name
    /// checked. See [`Self::build`]'s table, row three.
    fn insecure_disable_peer_verification(
        provider: &Arc<CryptoProvider>,
        verify_host: bool,
    ) -> Self {
        Self {
            kind: ServerVerifierKind::Relaxed(Arc::new(RelaxedVerifier {
                provider: Arc::clone(provider),
                chain_only: None,
            })),
            peer_verification_disabled: true,
            verify_host,
        }
    }

    /// Whether peer verification is switched OFF for this connection.
    #[must_use]
    pub fn peer_verification_disabled(&self) -> bool {
        self.peer_verification_disabled
    }

    /// Whether the caller is to run [`verify_hostname`] on the peer
    /// certificate.
    ///
    /// This is `CURLOPT_SSL_VERIFYHOST` and nothing else. It is **independent**
    /// of [`Self::peer_verification_disabled`]: `VERIFYPEER 0` with
    /// `VERIFYHOST 1` reports `true` here, and that state is the whole reason
    /// the two are stored separately.
    pub(crate) const fn host_verification_enabled(&self) -> bool {
        self.verify_host
    }

    /// The verifier, for a caller assembling a configuration by hand.
    #[allow(dead_code)] // consumer: tls/rustls_backend.rs
    pub(crate) fn verifier(&self) -> Arc<dyn ServerCertVerifier> {
        match &self.kind {
            // The concrete `Arc` is cloned and then coerced to the trait
            // object by the match's own type. `Arc::clone` cannot infer
            // that target, which is why this is a method call.
            ServerVerifierKind::WebPki(verifier) => verifier.clone(),
            ServerVerifierKind::Relaxed(verifier) => verifier.clone(),
        }
    }

    /// Installs the verifier into a rustls client configuration builder.
    #[must_use]
    pub(crate) fn install(
        &self,
        builder: ConfigBuilder<ClientConfig, WantsVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        match &self.kind {
            ServerVerifierKind::WebPki(verifier) => {
                builder.with_webpki_verifier(Arc::clone(verifier))
            }
            ServerVerifierKind::Relaxed(verifier) => builder
                .dangerous()
                .with_custom_certificate_verifier(verifier.clone()),
        }
    }
}

// Client authentication: supersedes `lib/vtls/rustls.c:833-900`

/// A parsed and validated client certificate with its private key.
pub(crate) struct ClientAuth {
    /// The chain and its signing key, already checked for consistency by
    /// rustls.
    certified_key: Arc<CertifiedKey>,
}

impl fmt::Debug for ClientAuth {
    /// Prints the chain length and nothing else.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientAuth")
            .field("chain_length", &self.certified_key.cert.len())
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)] // consumer: tls/rustls_backend.rs
impl ClientAuth {
    /// Loads `--cert` and `--key`, which must be supplied together.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SslCertproblem`] for every failure: a one-sided pair, an
    /// unreadable file, an unparsable or absent certificate or key, an
    /// unsupported key format, and a key that does not match the
    /// certificate. No message includes key material -- only the path the
    /// user supplied, which is what the C prints.
    pub(crate) fn load(
        certificate: Option<&Path>,
        key: Option<&Path>,
        provider: &CryptoProvider,
    ) -> CurlResult<Option<Self>> {
        let problem = |message: String| {
            Error::with_context(CURLcode::SslCertproblem, message)
        };

        let (certificate, key) = match (certificate, key) {
            (None, None) => return Ok(None),
            (Some(certificate), None) => {
                return Err(problem(format!(
                    "rustls: must provide key with certificate '{}'",
                    certificate.display()
                )))
            }
            (None, Some(key)) => {
                return Err(problem(format!(
                    "rustls: must provide certificate with key '{}'",
                    key.display()
                )))
            }
            (Some(certificate), Some(key)) => (certificate, key),
        };

        let certificate_pem = read_file_into(certificate, DYN_CERTFILE_SIZE)
            .ok_or_else(|| {
                problem(format!(
                    "rustls: failed to read client certificate file: '{}'",
                    certificate.display()
                ))
            })?;
        let key_pem =
            read_file_into(key, DYN_KEYFILE_SIZE).ok_or_else(|| {
                problem(format!(
                    "rustls: failed to read key file: '{}'",
                    key.display()
                ))
            })?;

        let mut chain = Vec::new();
        for item in CertificateDer::pem_slice_iter(&certificate_pem) {
            chain.push(item.map_err(|_| {
                problem("rustls: failed to build certified key".to_owned())
            })?);
        }
        if chain.is_empty() {
            return Err(problem(
                "rustls: failed to build certified key".to_owned(),
            ));
        }

        // The key's bytes never reach a message, here or anywhere below:
        // every error in this function is built from a path or from a fixed
        // string.
        let private_key =
            PrivateKeyDer::from_pem_slice(&key_pem).map_err(|_| {
                problem("rustls: failed to build certified key".to_owned())
            })?;

        let certified_key =
            CertifiedKey::from_der(chain, private_key, provider).map_err(
                |_| {
                    problem(
                        "rustls: client certificate and keypair files do not \
                     match"
                            .to_owned(),
                    )
                },
            )?;

        Ok(Some(Self {
            certified_key: Arc::new(certified_key),
        }))
    }

    /// The chain this authentication presents, for diagnostics.
    ///
    /// Certificates are public; the key is not, and is not reachable through
    /// this type at all.
    #[allow(dead_code)] // consumer: tls/rustls_backend.rs
    pub(crate) fn chain(&self) -> &[CertificateDer<'static>] {
        &self.certified_key.cert
    }
}

/// Completes a client configuration with or without client authentication.
#[must_use]
#[allow(dead_code)] // consumer: tls/rustls_backend.rs
pub(crate) fn install_client_auth(
    builder: ConfigBuilder<ClientConfig, WantsClientCert>,
    client_auth: Option<&ClientAuth>,
) -> ClientConfig {
    match client_auth {
        Some(auth) => builder.with_client_cert_resolver(Arc::new(
            SingleCertAndKey::from(Arc::clone(&auth.certified_key)),
        )),
        None => builder.with_no_client_auth(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rustls::crypto::ring::default_provider;

    use super::*;

    // Test material
    //
    // NO PRIVATE KEY appears here, deliberately. Committing one would put a
    // real key in the repository, which the secret-hygiene requirement
    // rules out, and a placeholder key would be a lie in the one place a
    // reader is most likely to copy from. The consequence is stated rather
    // than hidden: the client-authentication tests below cover the pairing
    // rules, every read and parse failure, and the rejection of key
    // material that does not match the certificate, but NOT a successful
    // installation. That one path belongs to
    // `tests-rs/integration/tls_verify.rs`, which generates a keypair at
    // run time.

    /// A self-signed certificate authority, `CN=curl-rs test CA`.
    const CA_PEM: &str = "\
        -----BEGIN CERTIFICATE-----\n\
        MIIDTjCCAjagAwIBAgIUYqrYB2+zHil3QZE+L4b4DHlqxE8wDQYJKoZIhvcNAQEL\n\
        BQAwPjELMAkGA1UEBhMCU0UxFTATBgNVBAoMDGN1cmwtcnMgdGVzdDEYMBYGA1UE\n\
        AwwPY3VybC1ycyB0ZXN0IENBMCAXDTI2MDgwODAyMDM0M1oYDzIxMjYwNzE1MDIw\n\
        MzQzWjA+MQswCQYDVQQGEwJTRTEVMBMGA1UECgwMY3VybC1ycyB0ZXN0MRgwFgYD\n\
        VQQDDA9jdXJsLXJzIHRlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n\
        AoIBAQCIpYyOYXLai+L6ARScQrUpaEm50OyRvViB+iG7c30Wch5zYY7XwxSgqb3f\n\
        ODyBukXbPz73wbLnseP37cLOrbrm90Q8s+6ShrOZqDvRrplSXa63/oONWeILeEXx\n\
        BNyFLOhJUlYfEM0PgLgdR4GwTzlV5CAfJ2ulmCuiV2xfedsAi7EUA2xjiDBxybYR\n\
        Er2TBLJ5ZpBhzuLIYnQuqdgZcUKCee4LdvSljTXKYsr77K3jupaeujTaKM4CZeuP\n\
        9zVWRfdN5RWeRl3F11tWwOtg4eDtJg72ayZDpUh0SoVeLZ0e+kNrDcExodCuiR+k\n\
        n1Ly+NgPuBWZ7Jthj5OWbSgO5fgHAgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8w\n\
        DgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQvoLMOtxQm4L8Wk3Rf0047JgsR7DAN\n\
        BgkqhkiG9w0BAQsFAAOCAQEAdenJMxFcqqo5S5fVEOmazX19ZbMQssgSbDcOxrSU\n\
        ablKC7WUyNoef005/7nHp1L52TAhzNt7bkPd/+6rE3NfCyswzGlYW+gkseINMhzl\n\
        4PwZBE9zlOCs/b34v94aVR4ANQQfgpddTEN0A0O48L32Ey0caltqk2XFSK4ysLN2\n\
        mgQyYkZyyhUf8hoEL1UobSW9a0f24XmOddqGaFjU4LAHSYQy+rX09Zuf4uD+FyV5\n\
        WT3aF6Qux1K1LOo3jl600OVu48GpvCXtM5CG0KBICBiujgs+A6DTNGvW41BHSZ62\n\
        A9SyX/p4OyC1wvlkN88qnMtvvEC12Ehvbbe2Yx47FWV3OA==\n\
        -----END CERTIFICATE-----\n\
    ";

    /// An end-entity certificate issued by [`CA_PEM`], `CN=localhost`, with
    /// three subjectAltName entries: `DNS:localhost`, `DNS:*.example.com`
    /// and `IP:127.0.0.1`.
    const EE_PEM: &str = "\
        -----BEGIN CERTIFICATE-----\n\
        MIIDqDCCApCgAwIBAgIUFktTHCo/xeb7p8tu11EuWN5+ZecwDQYJKoZIhvcNAQEL\n\
        BQAwPjELMAkGA1UEBhMCU0UxFTATBgNVBAoMDGN1cmwtcnMgdGVzdDEYMBYGA1UE\n\
        AwwPY3VybC1ycyB0ZXN0IENBMCAXDTI2MDgwODAyMDM0M1oYDzIxMjYwNzE1MDIw\n\
        MzQzWjA4MQswCQYDVQQGEwJTRTEVMBMGA1UECgwMY3VybC1ycyB0ZXN0MRIwEAYD\n\
        VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDS\n\
        FRt8QX3FZapMuHudha6JVeOc82yLkHSqePJjUsoPbAy8ueYdJZWm40PJG2gs/HpC\n\
        2rilS4mERPWCOVlhBDqFy/c7pRyr6ZVTKQf4gAbKwI1vrIUyNKZyPyRWhA93OyPo\n\
        e7BZEKbneMU+U/eCSkilaebN+T1uSrPyT8kzzS1YjAq6JbQQq+XVrG3K4uU9p9yL\n\
        P3Q9yZbp0Xxiqv64Vze1UHhd+ffqbEt/BOwVXQ+8G5VGkgzzDjgY2ltAwHCUGn5a\n\
        aXopE3uhmjoQhrgmFqlTawr+TVHH5uAggE4/CJBQnx5p9n5MtTQK1rTsZf7BYM+H\n\
        jqcV8vHQuI4VXCmXmqt7AgMBAAGjgaEwgZ4wDAYDVR0TAQH/BAIwADAOBgNVHQ8B\n\
        Af8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwKQYDVR0RBCIwIIIJbG9jYWxo\n\
        b3N0gg0qLmV4YW1wbGUuY29thwR/AAABMB0GA1UdDgQWBBT+x12YUtoHGOXGDh4M\n\
        34HnGLnhzzAfBgNVHSMEGDAWgBQvoLMOtxQm4L8Wk3Rf0047JgsR7DANBgkqhkiG\n\
        9w0BAQsFAAOCAQEAarfG7cFcOOz1D/kvYkG10TZJTdIiFpHDvZJ+le360eyQVuWZ\n\
        fVu85niWPGrbbVZoFWnLup3W1zYKi+r0fw5cxv8qvTwGf66grx+JrwFnXHUleUpB\n\
        1539C3WMvY1UUpR4X3KTnH55Qrl7JmSEqETquhlIU9/ribkd1KC3W4VSKIMKJ6S+\n\
        7rd5xPIkrYDiA+O3kj13wufE7I3PVVPf5wdEZwSW/scGVwqVc1mCLDyFvUT8ZQgy\n\
        VFcoSp78F5id0eFzn31NAIK9bloagRMf9LL91dBkcsN2zAxPYn5u/cd651ZEQ89u\n\
        cwQuP+7se/lmuE/L6Ge3kxDGDbAsehTeyRIqEg==\n\
        -----END CERTIFICATE-----\n\
    ";

    /// A SELF-SIGNED certificate, `CN=localhost`, with the same three
    /// subjectAltName entries as [`EE_PEM`] and no issuer any public root
    /// program knows.
    const SELF_SIGNED_PEM: &str = "\
        -----BEGIN CERTIFICATE-----\n\
        MIIDfzCCAmegAwIBAgIUGAb0d2Nfy6YcaC8fxfd5OQl0KW4wDQYJKoZIhvcNAQEL\n\
        BQAwODELMAkGA1UEBhMCU0UxFTATBgNVBAoMDGN1cmwtcnMgdGVzdDESMBAGA1UE\n\
        AwwJbG9jYWxob3N0MCAXDTI2MDgwODAyMDM0M1oYDzIxMjYwNzE1MDIwMzQzWjA4\n\
        MQswCQYDVQQGEwJTRTEVMBMGA1UECgwMY3VybC1ycyB0ZXN0MRIwEAYDVQQDDAls\n\
        b2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfVFZ8Rwtr\n\
        MiCfXB/VnBvdKSsH0Shf5Nu7ZviApCihrIQd3l0LT/5jTKgKkyqY64UWc60X8Yc/\n\
        PQLHv7cHdykggND+h6qGEy/mtIo7NmtRqrmUEiwY6mHym69etJoHCyd8V9gbUP6D\n\
        MEbbZuM+KmPrilVsNEQRitJRXlwtckC3GFp6+I5aQWR8Sv0tdWDJt3uf++pCNTsC\n\
        iiB9970NYti3ETpxrhAI7/kqfjZ8Hrg4QSn6aUnEM6I2IHQQtAdIDlM60p8EvQbk\n\
        9OD1cOM0rsaxzLvvaB3p7X9r9ranNw5Xv40jRRdzMhXZSq00DFCECNb+p/R6Splg\n\
        LGJ3/FYA6/kjAgMBAAGjfzB9MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA\n\
        MBMGA1UdJQQMMAoGCCsGAQUFBwMBMCkGA1UdEQQiMCCCCWxvY2FsaG9zdIINKi5l\n\
        eGFtcGxlLmNvbYcEfwAAATAdBgNVHQ4EFgQUwmGU8RStnNY6AUu4mRdH17hcE6gw\n\
        DQYJKoZIhvcNAQELBQADggEBAHGKw5IxIe9w6Gj3ilUvuaTG66buuX7LttNclTA/\n\
        FhT8qLx+uHhuDNJPS6eBHkhf+F1tu0DR8NsZdtr9Es7AOJnumeUo6rh8k201SwSF\n\
        ZRKs0Njdsy6zdequlGRMCSEEqz7X99PoeFBfcreRRyjvXjWGurMmY+LQh7M3Yafe\n\
        DGANirfEpKoROBF5eBS93n1g1Y71yRoSjGZEw0z4ioY87KuHXSbsjcOllDroZDpM\n\
        rwaB2J++1KWRkxCaAbsjN5WjecIV754zTBUlnUwvPQa8mneyBNq6ens6JWvU3WmM\n\
        NUxWqJDeYu3HzSQALgj8hco9375daStJptA3Dgq8+TjUCBA=\n\
        -----END CERTIFICATE-----\n\
    ";

    /// An end-entity certificate issued by [`CA_PEM`] with `CN=localhost`
    /// and NO subjectAltName extension at all: the only shape that reaches
    /// the commonName fallback of `lib/vtls/openssl.c:2176-2246`.
    const CN_ONLY_PEM: &str = "\
        -----BEGIN CERTIFICATE-----\n\
        MIIDezCCAmOgAwIBAgIUeec6owXZHFzXxUQx7jQ6ixgniDgwDQYJKoZIhvcNAQEL\n\
        BQAwPjELMAkGA1UEBhMCU0UxFTATBgNVBAoMDGN1cmwtcnMgdGVzdDEYMBYGA1UE\n\
        AwwPY3VybC1ycyB0ZXN0IENBMCAXDTI2MDgwODAyMDUwOFoYDzIxMjYwNzE1MDIw\n\
        NTA4WjA4MQswCQYDVQQGEwJTRTEVMBMGA1UECgwMY3VybC1ycyB0ZXN0MRIwEAYD\n\
        VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu\n\
        CfTbCjlca0pGSobHNHZ3dxxbPISHo9vD6RyzbsxEtStuz+xcjiCOlSv0c1LYDQ36\n\
        Bs6Y9EFL4gkFYgg47gIm9epF2ruY9eXl8AoGk0Ut/gvaPqOezplPtgiCsyNBsIfx\n\
        /av8UAqX8QQLQtu5VfHcFfjD800dSs5B42AKJ9DM6+O1loRpK5zGmyKxYJoNkspj\n\
        p/u8DAHDmdwAHpZVhPDv9IwfDgWzwKvDwE2mE3NSTu8R6K/gKvMq+bYVTk751qgr\n\
        pARbE+itU0JLybC70wm69dczNaT77YEUNpsydshL/J2k8VhcERwnzsuzwe9P3hQ+\n\
        qHvTjOVFFOfeutS6Y1JjAgMBAAGjdTBzMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/\n\
        BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBSHJ+C6F8bZB0OG\n\
        mJF+8bKrWb4o/zAfBgNVHSMEGDAWgBQvoLMOtxQm4L8Wk3Rf0047JgsR7DANBgkq\n\
        hkiG9w0BAQsFAAOCAQEAWpJ//xZXytBawvcuFophpHbswfl+CRdZXAq0l9NV3+2s\n\
        PwSS8u4aHh9Z6mmxVGNBO4Pva46JcQPe7q2qWLpeK62MhlbM6w2Wh7T+su8Lgu4N\n\
        mvizMaCWRi5GZWvXsys9ZSIoGbFkUjTPEQ00dpj4PcR02BfM2yG/cC/66tbvfndl\n\
        gB2OnjvQDKlFOYpNTT9g4xWZ13UhbIzG6jZ8w24HQzSdfI0cmVdzgSdqierGzjKm\n\
        APdaENGyt6Fn8idcj6/C0Dfl6IgnPc6j2BvV2H2SvfppzeC6H7dllUK6hQEZXr9t\n\
        6KVXLw5l5jwZvq8adIAJ+UEnCsKN+e0tSmL3TpvzLw==\n\
        -----END CERTIFICATE-----\n\
    ";

    /// A certificate whose only subjectAltName is the wildcard
    /// `DNS:*.example.com`, for the wildcard path in isolation.
    const WILDCARD_PEM: &str = "\
        -----BEGIN CERTIFICATE-----\n\
        MIIDdzCCAl+gAwIBAgIUBR2x/uMOihHEz2VzYB/Xvv6IsyYwDQYJKoZIhvcNAQEL\n\
        BQAwPjELMAkGA1UEBhMCU0UxFTATBgNVBAoMDGN1cmwtcnMgdGVzdDEYMBYGA1UE\n\
        AwwPY3VybC1ycyB0ZXN0IENBMCAXDTI2MDgwODAyMDUwOFoYDzIxMjYwNzE1MDIw\n\
        NTA4WjAYMRYwFAYDVQQDDA0qLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEF\n\
        AAOCAQ8AMIIBCgKCAQEAqTNqGv1I9zGFY4h+2PR6FInKA8CQqW17kLSKgrco/N5o\n\
        tMpI4KfDVsHCH27oc9HxUtS5VWfYalmtBmd2m4s2bTZsJSnYBOBSrkI1S8M+HCJe\n\
        Mz5aApWfu5ybWa4klZQnGJzDnnPrCIe6tKm2eT9cenecBn/5HXxJuBn00/7QhYqq\n\
        PoIEwkOHg9gNxbuQOlwLJCZA1xZl9cO676UIj6HPLB10xrato8BJgNVYycPLKUmy\n\
        C9Jgo4BNUthcsg7i4dK28zHNoWcsmnsMxO10rfN0F8JwLhAixCaCPfG4TjzjCb+2\n\
        XDuAI5QHTJTI9pNtvBbjsS0TphI1zgrGG+XIBpMmYQIDAQABo4GQMIGNMAwGA1Ud\n\
        EwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBgG\n\
        A1UdEQQRMA+CDSouZXhhbXBsZS5jb20wHQYDVR0OBBYEFDGuipfrJGlpA1buAjxQ\n\
        ok/F1737MB8GA1UdIwQYMBaAFC+gsw63FCbgvxaTdF/TTjsmCxHsMA0GCSqGSIb3\n\
        DQEBCwUAA4IBAQAKQXU0pTHLykN09koG7L6/Aqwllpf8B+Xu2MKCwi9xzyaK4Css\n\
        y9kUBR13rRN1RDz0vVL0eh3RByFMvoNUt22wMknrXywbdHrNS8xFrsoojqt47p4v\n\
        pd4ub5TxXSgJlKblWH2CdvdKEg6XY4qhdteUO7KT9TumsL8bfMnI3VXP5T+Cuv3I\n\
        yUZocBfZi4QBcegpMfUE4wlJFQAeRMHDaCIYUuc9FHXL9fCuwQoycASXOGVJVSaR\n\
        yWg+QilDKQVwc/HHXPpVHkzOlt5DlgIy/1NXkymgrHHplyqRl/LjL+/73WbmuQsZ\n\
        fflU1DuKWwzc8eB0bOnLsxJ/0ppF8WenJSce\n\
        -----END CERTIFICATE-----\n\
    ";

    /// A revocation list issued by [`CA_PEM`] that revokes [`EE_PEM`].
    const CRL_PEM: &str = "\
        -----BEGIN X509 CRL-----\n\
        MIIB0TCBugIBATANBgkqhkiG9w0BAQsFADA+MQswCQYDVQQGEwJTRTEVMBMGA1UE\n\
        CgwMY3VybC1ycyB0ZXN0MRgwFgYDVQQDDA9jdXJsLXJzIHRlc3QgQ0EXDTI2MDgw\n\
        ODAyMDQxOFoYDzIxMjYwNzE1MDIwNDE4WjA1MDMCFBZLUxwqP8Xm+6fLbtdRLlje\n\
        fmXnFw0yNjA4MDgwMjA0MThaMAwwCgYDVR0VBAMKAQGgDzANMAsGA1UdFAQEAgIQ\n\
        ADANBgkqhkiG9w0BAQsFAAOCAQEAMcaEEAfP88YIWeW3dnN6aY4+oJDlJQXN6Fvx\n\
        Wy8ZvJT3c7Tbbf4MoDkkjp8XnXIpgvjC8Fec27sY4rbSyNtZwaFd3xWUdj1k5KVV\n\
        51sW7Htr6BoBFsf8ZyUsD6q0nchTYU9JK1Q3M5okMgpajkyZqw1LQ8wDiAJXgDHL\n\
        DHjgoeNPIQZEpw6V2X1G8Q0FJoBmBx0tJme2VlkNsa2QXm1KyXx2IPB0GlnkIpXp\n\
        8nqzqYc3xsUBvHYqee33QgBTyaPBLv+H6pS9HgJz8omByzjlrOtDtpgaJRP++wn2\n\
        qJhUukel3BNdiFJLAmwQrNruP0nFH4eGLKfq2fP8Lc6bwz51gw==\n\
        -----END X509 CRL-----\n\
    ";

    /// A moment inside every embedded certificate's validity window.
    ///
    /// 2030-01-01T00:00:00Z. Passed explicitly so that no test here depends
    /// on the wall clock: a verification test that reads the clock starts
    /// failing on the day a certificate expires, which is a test that
    /// reports the calendar rather than the code.
    fn instant() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(1_893_456_000))
    }

    /// The one certificate in a PEM string.
    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .next()
            .expect("the embedded PEM holds a certificate")
            .expect("the embedded PEM parses")
    }

    /// An injected `ring` provider.
    fn provider() -> Arc<CryptoProvider> {
        Arc::new(default_provider())
    }

    /// Runs a verifier against a certificate and a name at [`instant`].
    fn check(
        verification: &ServerVerification,
        pem: &str,
        name: &str,
    ) -> Result<(), rustls::Error> {
        let certificate = der(pem);
        let server_name = ServerName::try_from(name.to_owned())
            .expect("the test name is a valid server name");
        verification
            .verifier()
            .verify_server_cert(&certificate, &[], &server_name, &[], instant())
            .map(|_assertion| ())
    }

    /// Writes `contents` into a file inside `directory` and returns its path.
    fn scratch_file(
        directory: &tempfile::TempDir,
        name: &str,
        contents: &[u8],
    ) -> PathBuf {
        let path = directory.path().join(name);
        fs::write(&path, contents).expect("the scratch file is writable");
        path
    }

    /// A PKCS#8 PEM section whose payload is NOT a key.
    const NOT_A_KEY_PKCS8: &[u8] =
        b"-----BEGIN PRIVATE KEY-----\nMAMCAQA=\n-----END PRIVATE KEY-----\n";

    /// A second non-key payload, whose base64 decodes to the ASCII text
    /// `SECRETSECRET`.
    ///
    /// Used by the one test that proves an error message cannot quote what
    /// it read: the assertion looks for this recognisable text in the
    /// message and requires its absence.
    const NOT_A_KEY_MARKED: &[u8] = b"-----BEGIN PRIVATE KEY-----\n\
        U0VDUkVUU0VDUkVU\n-----END PRIVATE KEY-----\n";

    /// This module's own source, for the structural gates below.
    fn own_source() -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("tls")
            .join("verify.rs");
        fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    }

    /// `line` with its comment tail AND every string literal removed.
    fn code_only(line: &str) -> String {
        let without_comment = line.split("//").next().unwrap_or("");
        let mut kept = String::with_capacity(without_comment.len());
        let mut inside = false;
        let mut escaped = false;
        for character in without_comment.chars() {
            if inside {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    inside = false;
                }
            } else if character == '"' {
                inside = true;
            } else {
                kept.push(character);
            }
        }
        kept
    }

    /// True when `code` contains `word` delimited by non-identifier bytes.
    fn mentions_word(code: &str, word: &str) -> bool {
        let bytes = code.as_bytes();
        let identifier =
            |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
        code.match_indices(word).any(|(at, _)| {
            let before = at == 0 || !identifier(bytes[at - 1]);
            let end = at + word.len();
            let after = end == bytes.len() || !identifier(bytes[end]);
            before && after
        })
    }

    // Phase 2: the policy, and the single dangerous path

    #[test]
    fn the_default_policy_verifies_both_the_chain_and_the_hostname() {
        let policy = VerifyPolicy::default();
        assert!(
            policy.verify_peer(),
            "AAP 0.8.1: verification is ON by default"
        );
        assert!(
            policy.verify_host(),
            "AAP 0.8.1: the hostname check is ON by default"
        );
        assert_eq!(policy.trust(), &TrustSource::BundledRoots);
        assert_eq!(policy.ca_path(), None);
        assert_eq!(policy.crl_file(), None);
        // `new` and `default` must not drift apart.
        assert_eq!(VerifyPolicy::new(), policy);
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_default_verification_reports_peer_verification_enabled() {
        let built =
            ServerVerification::build(&VerifyPolicy::new(), &provider())
                .expect("the bundled roots build a verifier");
        assert!(
            !built.peer_verification_disabled(),
            "the default configuration verifies, so no warning is due"
        );
        assert!(built.host_verification_enabled());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn the_one_insecure_policy_reports_peer_verification_disabled() {
        let policy = VerifyPolicy::new().with_peer_verification(false);
        let built = ServerVerification::build(&policy, &provider())
            .expect("the insecure path cannot fail");
        assert!(
            built.peer_verification_disabled(),
            "`curl-rs/src/output/msgs.rs` prints the --insecure warning \
             from this answer, before the transfer proceeds"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn peer_verification_off_keeps_the_hostname_check_the_caller_asked_for() {
        // `CURLOPT_SSL_VERIFYPEER 0` with `CURLOPT_SSL_VERIFYHOST 1` (or 2).
        // `lib/setopt.c:723` writes `verifyhost` without consulting
        // `verifypeer`, and `lib/vtls/schannel.c:1469` spells this exact pair
        // out as `if(!verifypeer && verifyhost)`, so the state is reachable
        // through the public API and the name check must survive.
        let policy = VerifyPolicy::new()
            .with_peer_verification(false)
            .with_host_verification(true);
        let built = ServerVerification::build(&policy, &provider())
            .expect("the insecure path cannot fail");
        assert!(
            built.peer_verification_disabled(),
            "the chain is not verified in this state"
        );
        assert!(
            built.host_verification_enabled(),
            "VERIFYHOST is a separate option from VERIFYPEER: clearing it \
             with VERIFYPEER would silently ignore what the caller asked \
             for, and curl's own backends do not"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn both_options_off_checks_neither_the_chain_nor_the_name() {
        let policy = VerifyPolicy::new()
            .with_peer_verification(false)
            .with_host_verification(false);
        let built = ServerVerification::build(&policy, &provider())
            .expect("the insecure path cannot fail");
        assert!(built.peer_verification_disabled());
        assert!(!built.host_verification_enabled());
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn peer_verification_on_with_the_name_check_off_still_verifies_the_chain() {
        // `CURLOPT_SSL_VERIFYPEER 1` with `CURLOPT_SSL_VERIFYHOST 0`: the
        // fourth state, and the one rustls has no builder for. The chain must
        // still be verified, so this must NOT report peer verification
        // disabled -- reporting it would print the `--insecure` warning for a
        // connection that does verify its issuer.
        let policy = VerifyPolicy::new()
            .with_peer_verification(true)
            .with_host_verification(false);
        let built = ServerVerification::build(&policy, &provider())
            .expect("the bundled roots build a verifier");
        assert!(
            !built.peer_verification_disabled(),
            "the chain IS verified in this state, so no --insecure warning \
             is due"
        );
        assert!(
            !built.host_verification_enabled(),
            "the name is the one thing this state does not check"
        );
    }

    #[test]
    fn a_name_mismatch_is_recognised_and_nothing_wider_is() {
        use rustls::CertificateError;

        // The two variants that ARE the name check. `NotValidForNameContext`
        // is documented as semantically the same as `NotValidForName` with
        // extra context, so both must be recognised.
        for error in [
            rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName,
            ),
            rustls::Error::InvalidCertificate(
                CertificateError::NotValidForNameContext {
                    expected: ServerName::try_from("example.com")
                        .expect("a literal name parses")
                        .to_owned(),
                    presented: vec!["other.example".to_owned()],
                },
            ),
        ] {
            assert!(
                is_name_mismatch(&error),
                "VERIFYHOST 0 must discard this: {error:?}"
            );
        }

        // Everything else is a chain or validity failure and must stand,
        // because VERIFYPEER is on whenever `is_name_mismatch` is consulted.
        for error in [
            rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer),
            rustls::Error::InvalidCertificate(CertificateError::Expired),
            rustls::Error::InvalidCertificate(CertificateError::Revoked),
            rustls::Error::InvalidCertificate(CertificateError::BadSignature),
            rustls::Error::InvalidCertificate(CertificateError::BadEncoding),
            rustls::Error::InvalidCertificate(CertificateError::NotValidYet),
            rustls::Error::NoCertificatesPresented,
            rustls::Error::DecryptError,
        ] {
            assert!(
                !is_name_mismatch(&error),
                "VERIFYHOST 0 must NOT discard this: {error:?}"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn no_trust_failure_is_recovered_into_an_unverified_connection() {
        // Four ways to fail, none of which may report verification as
        // disabled: each must be an error instead.
        let directory =
            tempfile::tempdir().expect("a temporary directory is available");
        let empty = scratch_file(&directory, "empty.pem", b"");
        let garbage = scratch_file(&directory, "garbage.pem", b"not a pem");

        let failures = [
            VerifyPolicy::new()
                .with_trust_source(TrustSource::CaBlob(Vec::new())),
            VerifyPolicy::new().with_trust_source(TrustSource::CaFile(
                directory.path().join("absent.pem"),
            )),
            VerifyPolicy::new().with_trust_source(TrustSource::CaFile(empty)),
            VerifyPolicy::new().with_trust_source(TrustSource::CaFile(garbage)),
        ];
        for policy in failures {
            let error = ServerVerification::build(&policy, &provider())
                .expect_err("an unusable trust source is an error");
            assert_eq!(error.code(), CURLcode::SslCacertBadfile);
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn the_dangerous_api_is_called_exactly_once() {
        let source = own_source();
        let sites: Vec<usize> = source
            .lines()
            .enumerate()
            .filter(|(_number, line)| code_only(line).contains("dangerous()"))
            .map(|(number, _line)| number + 1)
            .collect();
        assert_eq!(
            sites.len(),
            1,
            "rustls's dangerous() API must have exactly one call site so \
             that auditing 'can this build skip verification' is reading \
             one match. Sites: {sites:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn exactly_one_type_asserts_a_certificate_without_checking_it() {
        let source = own_source();
        let assertions: Vec<usize> = source
            .lines()
            .enumerate()
            .filter(|(_number, line)| {
                code_only(line).contains("ServerCertVerified::assertion")
            })
            .map(|(number, _line)| number + 1)
            .collect();
        assert_eq!(
            assertions.len(),
            1,
            "only RelaxedVerifier may assert a certificate. Sites: \
             {assertions:?}"
        );

        // And the one implementation of the verifier trait besides it is
        // rustls's own, which this module does not write.
        let implementations = source
            .lines()
            .filter(|line| {
                code_only(line).contains("impl ServerCertVerifier for")
            })
            .count();
        assert_eq!(implementations, 1, "one custom verifier type, no more");
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn no_forbidden_provider_or_verifier_is_activated() {
        let source = own_source();
        for forbidden in [
            "platform_verifier",
            "platform-verifier",
            "aws_lc_rs",
            "aws-lc-rs",
            "prefer-post-quantum",
            "prefer_post_quantum",
        ] {
            let hits: Vec<usize> = source
                .lines()
                .enumerate()
                .filter(|(_number, line)| code_only(line).contains(forbidden))
                .map(|(number, _line)| number + 1)
                .collect();
            assert!(
                hits.is_empty(),
                "{forbidden} must not appear in code. Lines: {hits:?}"
            );
        }

        // The provider is injected, never taken from a process-global
        // default.
        for implicit in [
            "get_default_or_install_from_crate_features",
            "install_default",
        ] {
            assert!(
                !source
                    .lines()
                    .any(|line| code_only(line).contains(implicit)),
                "{implicit} selects a provider implicitly"
            );
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn tls_is_unconditional_and_this_module_holds_no_unsafe() {
        let source = own_source();
        assert!(
            !source.lines().any(|line| {
                let code = code_only(line);
                code.contains("feature = \"tls\"")
            }),
            "TLS is unconditional in this workspace: there is no `tls` \
             feature to gate on, so a cfg naming one would compile the \
             module out"
        );
        assert!(
            !source
                .lines()
                .any(|line| mentions_word(&code_only(line), "unsafe")),
            "the crate root denies unsafe outside src/ffi, and this module \
             must not be the exception that tests it"
        );
    }

    // Phase 3: trust sources, precedence and revocation

    #[test]
    fn a_ca_blob_overrides_a_ca_file() {
        // "CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO"
        // (`lib/vtls/rustls.c:1015-1017`).
        let chosen = TrustSource::from_curl_options(
            Some(b"blob".to_vec()),
            Some(PathBuf::from("/ignored.pem")),
            true,
        );
        assert_eq!(chosen, TrustSource::CaBlob(b"blob".to_vec()));
    }

    #[test]
    fn a_ca_file_is_chosen_when_no_blob_was_given() {
        let chosen = TrustSource::from_curl_options(
            None,
            Some(PathBuf::from("/roots.pem")),
            true,
        );
        assert_eq!(chosen, TrustSource::CaFile(PathBuf::from("/roots.pem")));
    }

    #[test]
    fn the_native_store_is_reached_only_when_asked_and_nothing_else_was() {
        assert_eq!(
            TrustSource::from_curl_options(None, None, true),
            TrustSource::NativeRoots
        );
        assert_eq!(
            TrustSource::from_curl_options(None, None, false),
            TrustSource::BundledRoots,
            "the bundled roots are what remains when nothing was asked for"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_capath_is_refused_rather_than_ignored() {
        let policy = VerifyPolicy::new()
            .with_ca_path(Some(PathBuf::from("/etc/ssl/certs")));
        let error = ServerVerification::build(&policy, &provider())
            .expect_err("an unsupported capath is an error");
        assert_eq!(
            error.code(),
            CURLcode::NotBuiltIn,
            "`lib/setopt.c:1821-1827` refuses an unsupported capath with \
             CURLE_NOT_BUILT_IN rather than ignoring the directory"
        );
        assert!(error.message().contains("/etc/ssl/certs"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_malformed_ca_blob_is_a_bad_ca_file() {
        let policy =
            VerifyPolicy::new().with_trust_source(TrustSource::CaBlob(
                b"-----BEGIN CERTIFICATE-----\nnope\n".to_vec(),
            ));
        let error = ServerVerification::build(&policy, &provider())
            .expect_err("a malformed blob is an error");
        assert_eq!(error.code(), CURLcode::SslCacertBadfile);
        assert!(error.message().contains("blob"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn the_bundled_roots_build_a_verifier() {
        let policy =
            VerifyPolicy::new().with_trust_source(TrustSource::BundledRoots);
        let built = ServerVerification::build(&policy, &provider())
            .expect("webpki-roots is not empty");
        assert!(!built.peer_verification_disabled());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_ca_file_and_a_ca_blob_reach_the_same_trust_decision() {
        let directory =
            tempfile::tempdir().expect("a temporary directory is available");
        let path = scratch_file(&directory, "ca.pem", CA_PEM.as_bytes());

        let from_file = ServerVerification::build(
            &VerifyPolicy::new().with_trust_source(TrustSource::CaFile(path)),
            &provider(),
        )
        .expect("the certificate authority loads from a file");
        let from_blob = ServerVerification::build(
            &VerifyPolicy::new().with_trust_source(TrustSource::CaBlob(
                CA_PEM.as_bytes().to_vec(),
            )),
            &provider(),
        )
        .expect("the certificate authority loads from a blob");

        assert!(check(&from_file, EE_PEM, "localhost").is_ok());
        assert!(check(&from_blob, EE_PEM, "localhost").is_ok());
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn a_revocation_list_is_installed_and_revokes_the_certificate() {
        let directory =
            tempfile::tempdir().expect("a temporary directory is available");
        let crl = scratch_file(&directory, "crl.pem", CRL_PEM.as_bytes());
        let trust = TrustSource::CaBlob(CA_PEM.as_bytes().to_vec());

        // Without the list the certificate verifies.
        let without = ServerVerification::build(
            &VerifyPolicy::new().with_trust_source(trust.clone()),
            &provider(),
        )
        .expect("the trust source is usable");
        assert!(check(&without, EE_PEM, "localhost").is_ok());

        // With it, the same certificate is refused, because the list
        // revokes it. This is what makes advertising CRLFILE honest.
        let with = ServerVerification::build(
            &VerifyPolicy::new()
                .with_trust_source(trust)
                .with_crl_file(Some(crl)),
            &provider(),
        )
        .expect("the revocation list parses");
        let error = check(&with, EE_PEM, "localhost")
            .expect_err("a revoked certificate is refused");
        assert!(
            matches!(
                error,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Revoked
                )
            ),
            "expected a revocation failure, found {error:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn every_unusable_revocation_list_is_a_bad_crl_file() {
        let directory =
            tempfile::tempdir().expect("a temporary directory is available");
        let empty = scratch_file(&directory, "empty.pem", b"");
        let garbage =
            scratch_file(&directory, "garbage.pem", b"-----BEGIN X509 CRL");
        let absent = directory.path().join("absent.pem");

        for path in [empty, garbage, absent] {
            let policy = VerifyPolicy::new()
                .with_trust_source(TrustSource::CaBlob(
                    CA_PEM.as_bytes().to_vec(),
                ))
                .with_crl_file(Some(path.clone()));
            let error = ServerVerification::build(&policy, &provider())
                .err()
                .unwrap_or_else(|| {
                    panic!("{} must not be accepted", path.display())
                });
            assert_eq!(error.code(), CURLcode::SslCrlBadfile);
        }
    }

    // Phase 8 gate ten: a self-signed certificate is refused by default

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_self_signed_certificate_is_refused_by_default() {
        let built =
            ServerVerification::build(&VerifyPolicy::new(), &provider())
                .expect("the bundled roots build a verifier");
        let error = check(&built, SELF_SIGNED_PEM, "localhost")
            .expect_err("gate ten of AAP 0.8.4: this MUST be refused");
        assert!(
            matches!(
                error,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer
                )
            ),
            "expected an unknown issuer, found {error:?}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_self_signed_certificate_is_accepted_when_explicitly_trusted() {
        let policy = VerifyPolicy::new().with_trust_source(
            TrustSource::CaBlob(SELF_SIGNED_PEM.as_bytes().to_vec()),
        );
        let built = ServerVerification::build(&policy, &provider())
            .expect("an explicitly named anchor is usable");
        assert!(
            check(&built, SELF_SIGNED_PEM, "localhost").is_ok(),
            "a user who named this certificate as their anchor gets it \
             trusted; that is --cacert working, not verification failing"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_self_signed_certificate_is_accepted_only_under_the_insecure_policy() {
        let policy = VerifyPolicy::new().with_peer_verification(false);
        let built = ServerVerification::build(&policy, &provider())
            .expect("the insecure path cannot fail");
        assert!(
            check(&built, SELF_SIGNED_PEM, "localhost").is_ok(),
            "--insecure accepts what verification refuses"
        );
        assert!(built.peer_verification_disabled());
    }

    // Phase 4: client authentication

    #[test]
    fn neither_a_certificate_nor_a_key_is_simply_no_client_auth() {
        let loaded = ClientAuth::load(None, None, &default_provider())
            .expect("omitting both is not an error");
        assert!(loaded.is_none());
    }

    #[test]
    fn a_certificate_without_a_key_is_a_certificate_problem() {
        let error = ClientAuth::load(
            Some(Path::new("/client.pem")),
            None,
            &default_provider(),
        )
        .expect_err("`lib/vtls/rustls.c:844-848` refuses this pairing");
        assert_eq!(error.code(), CURLcode::SslCertproblem);
        assert!(error
            .message()
            .contains("must provide key with certificate"));
    }

    #[test]
    fn a_key_without_a_certificate_is_a_certificate_problem() {
        let error = ClientAuth::load(
            None,
            Some(Path::new("/client.key")),
            &default_provider(),
        )
        .expect_err("`lib/vtls/rustls.c:849-853` refuses this pairing too");
        assert_eq!(error.code(), CURLcode::SslCertproblem);
        assert!(error
            .message()
            .contains("must provide certificate with key"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn an_unreadable_certificate_or_key_is_a_certificate_problem() {
        let directory =
            tempfile::tempdir().expect("a temporary directory is available");
        let present = scratch_file(&directory, "cert.pem", EE_PEM.as_bytes());
        let absent = directory.path().join("absent");

        let error = ClientAuth::load(
            Some(&absent),
            Some(&present),
            &default_provider(),
        )
        .expect_err("an unreadable certificate is an error");
        assert_eq!(error.code(), CURLcode::SslCertproblem);
        assert!(error.message().contains("client certificate file"));

        let error = ClientAuth::load(
            Some(&present),
            Some(&absent),
            &default_provider(),
        )
        .expect_err("an unreadable key is an error");
        assert_eq!(error.code(), CURLcode::SslCertproblem);
        assert!(error.message().contains("key file"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn an_unparsable_certificate_is_a_certificate_problem() {
        let directory =
            tempfile::tempdir().expect("a temporary directory is available");
        let certificate =
            scratch_file(&directory, "cert.pem", b"not a certificate");
        // A syntactically well-formed PKCS#8 section whose contents are NOT
        // a key: enough to pass the PEM reader and fail the provider. No
        // real key material appears anywhere in this file.
        let key = scratch_file(&directory, "key.pem", NOT_A_KEY_PKCS8);

        let error = ClientAuth::load(
            Some(&certificate),
            Some(&key),
            &default_provider(),
        )
        .expect_err("a certificate that does not parse is an error");
        assert_eq!(error.code(), CURLcode::SslCertproblem);
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn key_material_that_does_not_match_the_certificate_is_refused() {
        let directory =
            tempfile::tempdir().expect("a temporary directory is available");
        let certificate =
            scratch_file(&directory, "cert.pem", EE_PEM.as_bytes());
        let key = scratch_file(&directory, "key.pem", NOT_A_KEY_PKCS8);

        let error = ClientAuth::load(
            Some(&certificate),
            Some(&key),
            &default_provider(),
        )
        .expect_err("rustls refuses key material it cannot pair");
        assert_eq!(error.code(), CURLcode::SslCertproblem);
        // The message names the path and the failure, and NOTHING from the
        // key file's contents.
        assert!(!error.message().contains("MAMCAQA"));
        assert!(!error.message().contains("PRIVATE KEY"));
    }

    #[test]
    #[cfg_attr(miri, ignore = "Miri's isolation refuses the filesystem")]
    fn no_client_auth_message_can_carry_key_material() {
        let directory =
            tempfile::tempdir().expect("a temporary directory is available");
        let key = scratch_file(&directory, "key.pem", NOT_A_KEY_MARKED);
        let certificate =
            scratch_file(&directory, "cert.pem", EE_PEM.as_bytes());

        let error = ClientAuth::load(
            Some(&certificate),
            Some(&key),
            &default_provider(),
        )
        .expect_err("this key is not usable");
        assert!(
            !error.message().contains("U0VDUkVUU0VDUkVU"),
            "no error message in this module may quote key material"
        );
    }

    // Phase 5: the hostname matcher, `hostcheck.c:39-125`

    #[test]
    fn the_hostname_matcher_reproduces_the_c_s_table() {
        // (pattern, hostname, expected). Every row is a rule from
        // `lib/vtls/hostcheck.c:49-113` or from unit test 1397, which the C
        // names as this function's own test.
        let rows: &[(&str, &str, bool)] = &[
            // Exact matching, and it is case-insensitive.
            ("example.com", "example.com", true),
            ("EXAMPLE.com", "example.COM", true),
            ("example.com", "example.org", false),
            ("example.com", "www.example.com", false),
            // A trailing dot is discounted, once, on either side.
            ("example.com.", "example.com", true),
            ("example.com", "example.com.", true),
            ("example.com.", "example.com.", true),
            ("example.com..", "example.com", false),
            // A wildcard matches one label, and only the leftmost.
            ("*.example.com", "www.example.com", true),
            ("*.example.com", "WWW.EXAMPLE.COM", true),
            ("*.example.com", "example.com", false),
            ("*.example.com", "a.b.example.com", false),
            ("*.example.com", "www.example.org", false),
            ("*.example.com.", "www.example.com", true),
            ("*.example.com", "www.example.com.", true),
            // Fewer than two dots is too wide, so it is compared literally.
            ("*.com", "example.com", false),
            ("*.com", "*.com", true),
            // Partial wildcards are not wildcards at all.
            ("a*.example.com", "abc.example.com", false),
            ("a*b.example.com", "axxb.example.com", false),
            ("*b.example.com", "web.example.com", false),
            ("www*.example.com", "www1.example.com", false),
            // A hostname beginning with a dot never matches a wildcard.
            ("*.example.com", ".example.com", false),
            // Neither does an IP literal.
            ("*.0.0.1", "127.0.0.1", false),
            ("*.1", "127.0.0.1", false),
            ("*.db8::1", "2001:db8::1", false),
            // An IP literal still matches itself exactly.
            ("127.0.0.1", "127.0.0.1", true),
            ("2001:db8::1", "2001:db8::1", true),
            // Empty inputs never match.
            ("", "example.com", false),
            ("example.com", "", false),
            ("", "", false),
            ("*.example.com", "", false),
        ];

        for (pattern, hostname, expected) in rows {
            assert_eq!(
                cert_hostcheck(pattern.as_bytes(), hostname.as_bytes()),
                *expected,
                "pattern {pattern:?} against hostname {hostname:?}"
            );
        }
    }

    #[test]
    fn a_wildcard_pattern_of_two_octets_still_enters_the_wildcard_branch() {
        // The C tests `strncmp(pattern, "*.", 2)` on the ORIGINAL pointer,
        // so `*.` reaches the wildcard branch even though discounting its
        // trailing dot leaves one octet. It then finds no dot in the
        // remaining `*` and compares literally, which one octet of hostname
        // can satisfy.
        assert!(cert_hostcheck(b"*.", b"*"));
        assert!(!cert_hostcheck(b"*.", b"ab"));
    }

    #[test]
    fn an_embedded_zero_makes_a_pattern_or_hostname_empty() {
        assert!(!cert_hostcheck(b"\0example.com", b"example.com"));
        assert!(!cert_hostcheck(b"example.com", b"\0example.com"));
    }

    #[test]
    fn ip_literals_are_recognised_the_way_the_resolver_recognises_them() {
        assert!(host_is_ipnum(b"127.0.0.1"));
        assert!(host_is_ipnum(b"0.0.0.0"));
        assert!(host_is_ipnum(b"::1"));
        assert!(host_is_ipnum(b"2001:db8::1"));
        // A trailing dot is not an address, which is what makes the C's
        // untrimmed test observable.
        assert!(!host_is_ipnum(b"127.0.0.1."));
        assert!(!host_is_ipnum(b"127.1"));
        assert!(!host_is_ipnum(b"01.2.3.4"));
        assert!(!host_is_ipnum(b"example.com"));
        assert!(!host_is_ipnum(b""));
    }

    // Phase 5: certificate-level name semantics

    #[test]
    fn a_dns_alt_name_decides_the_outcome_and_the_common_name_does_not() {
        let certificate = der(EE_PEM);
        assert_eq!(
            verify_hostname(certificate.as_ref(), "localhost", "localhost")
                .expect("the DNS alt name matches"),
            HostMatch::SubjectAltName
        );

        // The subject is `CN=localhost`, so a certificate WITHOUT alt names
        // would accept `localhost` only. This one carries alt names, so a
        // name absent from them fails even though the commonName exists.
        let error =
            verify_hostname(certificate.as_ref(), "example.org", "example.org")
                .expect_err("RFC 6125: alt names displace the commonName");
        assert_eq!(error.code(), CURLcode::PeerFailedVerification);
        assert_eq!(
            error.message(),
            "SSL: no alternative certificate subject name matches target \
             hostname 'example.org'"
        );
    }

    #[test]
    fn a_wildcard_alt_name_matches_one_label() {
        let certificate = der(WILDCARD_PEM);
        assert_eq!(
            verify_hostname(
                certificate.as_ref(),
                "www.example.com",
                "www.example.com"
            )
            .expect("the wildcard alt name matches one label"),
            HostMatch::SubjectAltName
        );
        assert!(verify_hostname(
            certificate.as_ref(),
            "a.b.example.com",
            "a.b.example.com"
        )
        .is_err());
    }

    #[test]
    fn an_ip_target_matches_an_ip_alt_name_exactly_and_never_by_wildcard() {
        let certificate = der(EE_PEM);
        assert_eq!(
            verify_hostname(certificate.as_ref(), "127.0.0.1", "127.0.0.1")
                .expect("the IP alt name matches exactly"),
            HostMatch::SubjectAltName
        );

        // A different address of the same family does not match, and the
        // message names the target's kind.
        let error =
            verify_hostname(certificate.as_ref(), "127.0.0.2", "127.0.0.2")
                .expect_err("an address must match exactly");
        assert_eq!(
            error.message(),
            "SSL: no alternative certificate subject name matches target \
             ipv4 address '127.0.0.2'"
        );

        // An IPv6 target is not satisfied by an IPv4 entry.
        let error = verify_hostname(certificate.as_ref(), "::1", "::1")
            .expect_err("an IPv6 target needs an IPv6 entry");
        assert!(error.message().contains("ipv6 address"));
    }

    #[test]
    fn the_common_name_is_consulted_only_without_any_dns_or_ip_alt_name() {
        let certificate = der(CN_ONLY_PEM);
        assert_eq!(
            verify_hostname(certificate.as_ref(), "localhost", "localhost")
                .expect("the commonName matches"),
            HostMatch::CommonName,
            "a certificate with no alt names at all falls back to the \
             commonName, exactly as `openssl.c:2176-2246` does"
        );

        let error =
            verify_hostname(certificate.as_ref(), "elsewhere", "elsewhere")
                .expect_err("a commonName that does not match fails");
        assert_eq!(
            error.message(),
            "SSL: certificate subject name 'localhost' does not match \
             target hostname 'elsewhere'"
        );
    }

    #[test]
    fn a_certificate_that_will_not_parse_fails_verification() {
        let error =
            verify_hostname(b"\x30\x03not der", "localhost", "localhost")
                .expect_err("a malformed certificate cannot be verified");
        assert_eq!(error.code(), CURLcode::PeerFailedVerification);
    }

    // Phase 6: the ASN.1 parser and its bounds

    #[test]
    fn a_definite_length_element_parses_with_its_remainder() {
        // BOOLEAN TRUE followed by a second byte the caller keeps.
        let (element, rest) = get_asn1_element(&[0x01, 0x01, 0xFF, 0x2A])
            .expect("a two-octet element parses");
        assert_eq!(element.tag(), ASN1_BOOLEAN);
        assert_eq!(element.class(), 0);
        assert!(!element.is_constructed());
        assert_eq!(element.content(), &[0xFF]);
        assert_eq!(rest, &[0x2A]);
    }

    #[test]
    #[cfg_attr(miri, ignore = "fills a 128-octet element octet by octet")]
    fn a_long_form_length_parses() {
        let mut der = vec![0x04, 0x81, 0x80];
        der.extend(std::iter::repeat(0xAB).take(0x80));
        let (element, rest) =
            get_asn1_element(&der).expect("a long-form length parses");
        assert_eq!(element.content().len(), 0x80);
        assert!(rest.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "allocates 256 KiB twice to stand at the limit")]
    fn an_object_above_the_ceiling_is_refused() {
        // The guard is on the SPAN offered, so a span one octet above
        // `CURL_ASN1_MAX` is refused before the header is read.
        let too_big = vec![0x04u8; CURL_ASN1_MAX + 1];
        assert!(get_asn1_element(&too_big).is_none());
        // And a span exactly at the ceiling is not.
        let mut at_ceiling = vec![0u8; CURL_ASN1_MAX];
        at_ceiling[0] = 0x04;
        at_ceiling[1] = 0x01;
        assert!(get_asn1_element(&at_ceiling).is_some());
    }

    #[test]
    fn a_long_tag_number_is_refused() {
        assert!(get_asn1_element(&[0x1F, 0x01, 0x00]).is_none());
    }

    #[test]
    fn a_leading_zero_octet_is_refused() {
        assert!(get_asn1_element(&[0x00, 0x01, 0xFF]).is_none());
    }

    #[test]
    fn a_truncated_element_is_refused() {
        // Header only.
        assert!(get_asn1_element(&[0x04]).is_none());
        // A length that does not fit the span.
        assert!(get_asn1_element(&[0x04, 0x05, 0x01, 0x02]).is_none());
        // A long form whose octet count does not fit.
        assert!(get_asn1_element(&[0x04, 0x84, 0x00]).is_none());
        // Nothing at all.
        assert!(get_asn1_element(&[]).is_none());
    }

    #[test]
    fn a_length_above_thirty_two_bits_is_refused() {
        // Five length octets: the guard fires before the fifth shift.
        let der = [0x04, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(get_asn1_element(&der).is_none());
    }

    #[test]
    fn an_indefinite_length_needs_a_constructed_element() {
        // Primitive with an indefinite length: refused.
        assert!(get_asn1_element(&[0x04, 0x80, 0x00, 0x00]).is_none());
        // Constructed, holding one BOOLEAN, then the end marker.
        let (element, rest) =
            get_asn1_element(&[0x30, 0x80, 0x01, 0x01, 0xFF, 0x00, 0x00])
                .expect("a constructed indefinite element parses");
        assert!(element.is_constructed());
        assert_eq!(element.content(), &[0x01, 0x01, 0xFF]);
        // `return beg + 1` steps over ONE octet of the two-octet marker.
        assert_eq!(rest, &[0x00]);
    }

    #[test]
    fn an_unterminated_indefinite_length_is_refused() {
        assert!(get_asn1_element(&[0x30, 0x80, 0x01, 0x01, 0xFF]).is_none());
    }

    #[test]
    fn recursion_is_bounded_at_sixteen() {
        // Each level is a constructed indefinite-length element, which is
        // the only form that recurses. Sixteen levels are refused because
        // the innermost sees `lvl >= CURL_ASN1_MAX_RECURSIONS`.
        let nest = |depth: usize| -> Vec<u8> {
            let mut der = Vec::new();
            for _ in 0..depth {
                der.push(0x30);
                der.push(0x80);
            }
            der.push(0x01);
            der.push(0x01);
            der.push(0xFF);
            for _ in 0..depth {
                der.push(0x00);
                der.push(0x00);
            }
            der
        };
        assert!(
            get_asn1_element(&nest(3)).is_some(),
            "a shallow nesting parses"
        );
        assert!(
            get_asn1_element(&nest(CURL_ASN1_MAX_RECURSIONS + 4)).is_none(),
            "a nesting past {CURL_ASN1_MAX_RECURSIONS} levels is refused"
        );
    }

    // Phase 6: the conversions

    /// Renders one element the way `ASN1tostr` would, for the tests below.
    fn render(der: &[u8]) -> CurlResult<String> {
        let (element, _) = get_asn1_element(der)
            .ok_or_else(|| Error::new(CURLcode::BadFunctionArgument))?;
        let mut out = certinfo_buffer();
        asn1_to_str(&mut out, &element, 0)?;
        Ok(String::from_utf8_lossy(out.as_slice()).into_owned())
    }

    /// [`render`] for the cases that must succeed.
    ///
    /// [`Error`] deliberately implements neither [`PartialEq`] nor
    /// [`Eq`] -- it carries a message and a source, which are not values to
    /// compare -- so the tests below unwrap and compare the rendered text
    /// rather than comparing two [`Result`]s.
    fn rendered(der: &[u8]) -> String {
        render(der).expect("this element converts")
    }

    #[test]
    fn booleans_render_as_words() {
        assert_eq!(rendered(&[0x01, 0x01, 0xFF]), "TRUE");
        assert_eq!(rendered(&[0x01, 0x01, 0x00]), "FALSE");
        // Exactly one octet, or nothing.
        assert_eq!(
            render(&[0x01, 0x02, 0x00, 0x00])
                .err()
                .map(Error::into_code),
            Some(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn integers_render_as_the_c_renders_them() {
        // Below ten: no prefix.
        assert_eq!(rendered(&[0x02, 0x01, 0x09]), "9");
        // Ten and above: an `0x` prefix.
        assert_eq!(rendered(&[0x02, 0x01, 0x0A]), "0xa");
        assert_eq!(rendered(&[0x02, 0x03, 0x01, 0x00, 0x01]), "0x10001");
        // Sign extension into 32 bits.
        assert_eq!(rendered(&[0x02, 0x01, 0xFF]), "0xffffffff");
        // Above four octets: colon-separated hexadecimal instead.
        assert_eq!(
            rendered(&[0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]),
            "01:02:03:04:05:"
        );
        // Empty: refused.
        assert_eq!(
            render(&[0x02, 0x00]).err().map(Error::into_code),
            Some(CURLcode::BadFunctionArgument)
        );
        // ENUMERATED shares the conversion.
        assert_eq!(rendered(&[0x0A, 0x01, 0x02]), "2");
    }

    #[test]
    fn octet_and_bit_strings_render_as_colon_separated_hexadecimal() {
        assert_eq!(rendered(&[0x04, 0x03, 0xDE, 0xAD, 0xBE]), "de:ad:be:");
        // A bit string's first octet is its unused-bit count and is skipped.
        assert_eq!(rendered(&[0x03, 0x03, 0x00, 0xAB, 0xCD]), "ab:cd:");
        // An empty bit string renders as nothing rather than failing, which
        // is what the C's `if(++beg > end)` admits.
        assert_eq!(rendered(&[0x03, 0x00]), "");
    }

    #[test]
    fn a_null_renders_as_one_zero_octet() {
        let (element, _) =
            get_asn1_element(&[0x05, 0x00]).expect("NULL parses");
        let mut out = certinfo_buffer();
        asn1_to_str(&mut out, &element, 0).expect("NULL converts");
        assert_eq!(
            out.as_slice(),
            &[0u8],
            "`curlx_dyn_addn(store, \"\", 1)` appends the terminator, and \
             CURLINFO_CERTINFO carries a length that shows it"
        );
    }

    #[test]
    fn object_identifiers_render_by_name_and_fall_back_to_numbers() {
        // 1.2.840.113549.1.1.11 is in the table as sha256WithRSAEncryption.
        let sha256_rsa = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
        ];
        assert_eq!(rendered(&sha256_rsa), "sha256WithRSAEncryption");
        // 2.5.4.3 is CN.
        assert_eq!(rendered(&[0x06, 0x03, 0x55, 0x04, 0x03]), "CN");
        // An OID absent from the table renders numerically rather than
        // failing (`x509asn1.c:471-475`).
        assert_eq!(rendered(&[0x06, 0x03, 0x55, 0x04, 0x7B]), "2.5.4.123");
        // The arithmetic of the first octet: 42 = 1.2.
        assert_eq!(rendered(&[0x06, 0x01, 0x2A]), "1.2");
    }

    #[test]
    fn utc_time_renders_with_a_century_and_optional_seconds() {
        // 24 -> 2024, seconds present, Z.
        assert_eq!(
            rendered(b"\x17\x0d240102030405Z"),
            "2024-01-02 03:04:05 GMT"
        );
        // 50 and above -> the twentieth century.
        assert_eq!(
            rendered(b"\x17\x0d980102030405Z"),
            "1998-01-02 03:04:05 GMT"
        );
        // Ten digits: the seconds default to `00`.
        assert_eq!(rendered(b"\x17\x0b2401020304Z"), "2024-01-02 03:04:00 GMT");
        // An offset loses its sign, because the C steps over one octet
        // before measuring the remainder.
        assert_eq!(
            rendered(b"\x17\x11240102030405+0500"),
            "2024-01-02 03:04:05 0500"
        );
        // Eleven digits is neither ten nor twelve.
        assert_eq!(
            render(b"\x17\x0c24010203040Z").err().map(Error::into_code),
            Some(CURLcode::BadFunctionArgument)
        );
        // No timezone at all.
        assert_eq!(
            render(b"\x17\x0c240102030405").err().map(Error::into_code),
            Some(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn generalized_time_renders_with_fractions_and_zones() {
        assert_eq!(
            rendered(b"\x18\x0f20240102030405Z"),
            "2024-01-02 03:04:05 GMT"
        );
        // Twelve digits: no seconds at all.
        assert_eq!(
            rendered(b"\x18\x0d202401020304Z"),
            "2024-01-02 03:04:00 GMT"
        );
        // Thirteen: a units digit with a defaulted tens digit.
        assert_eq!(
            rendered(b"\x18\x0e2024010203047Z"),
            "2024-01-02 03:04:07 GMT"
        );
        // Fractional seconds, with trailing zeroes stripped.
        assert_eq!(
            rendered(b"\x18\x1320240102030405.500Z"),
            "2024-01-02 03:04:05.5 GMT"
        );
        // All-zero fractions disappear entirely.
        assert_eq!(
            rendered(b"\x18\x1320240102030405.000Z"),
            "2024-01-02 03:04:05 GMT"
        );
        // A comma introduces a fraction too.
        assert_eq!(
            rendered(b"\x18\x1120240102030405,5Z"),
            "2024-01-02 03:04:05.5 GMT"
        );
        // A signed offset is introduced by ` UTC`.
        assert_eq!(
            rendered(b"\x18\x1320240102030405+0100"),
            "2024-01-02 03:04:05 UTC+0100"
        );
        // No zone: nothing is appended.
        assert_eq!(rendered(b"\x18\x0e20240102030405"), "2024-01-02 03:04:05");
        // A fraction marker with no digit after it.
        assert_eq!(
            render(b"\x18\x0f20240102030405.")
                .err()
                .map(Error::into_code),
            Some(CURLcode::BadFunctionArgument)
        );
        // Fewer than twelve digits.
        assert_eq!(
            render(b"\x18\x0b2024010203Z").err().map(Error::into_code),
            Some(CURLcode::BadFunctionArgument)
        );
    }

    #[test]
    fn typed_strings_convert_to_utf8() {
        // A PrintableString is copied octet for octet.
        assert_eq!(rendered(b"\x13\x02hi"), "hi");
        // A UTF8String is copied verbatim, validation included -- which is
        // to say, not validated at all.
        assert_eq!(rendered(b"\x0c\x03\xc3\xa4x"), "\u{e4}x");
        // A BMPString is two octets per character, big-endian.
        assert_eq!(rendered(&[0x1E, 0x04, 0x00, 0x41, 0x00, 0xE4]), "A\u{e4}");
        // A UniversalString is four.
        assert_eq!(
            rendered(&[0x1C, 0x04, 0x00, 0x01, 0x03, 0x44]),
            "\u{10344}"
        );
        // A length inconsistent with the character width.
        assert_eq!(
            render(&[0x1E, 0x03, 0x00, 0x41, 0x00])
                .err()
                .map(Error::into_code),
            Some(CURLcode::BadFunctionArgument)
        );
        // A code point at or above 0x200000 is refused with the C's own
        // choice of code.
        assert_eq!(
            render(&[0x1C, 0x04, 0x00, 0x20, 0x00, 0x00])
                .err()
                .map(Error::into_code),
            Some(CURLcode::WeirdServerReply)
        );
    }

    #[test]
    fn an_unsupported_tag_and_a_constructed_element_are_refused() {
        // Tag 16 (SEQUENCE) is commented out of the C's table.
        let (element, _) =
            get_asn1_element(&[0x10, 0x01, 0x00]).expect("the header parses");
        let mut out = certinfo_buffer();
        assert_eq!(
            asn1_to_str(&mut out, &element, 0)
                .err()
                .map(Error::into_code),
            Some(CURLcode::BadFunctionArgument)
        );

        // "No conversion of structured elements" (`x509asn1.c:624-625`).
        let (element, _) =
            get_asn1_element(&[0x30, 0x00]).expect("the header parses");
        let mut out = certinfo_buffer();
        assert!(element.is_constructed());
        assert_eq!(
            asn1_to_str(&mut out, &element, 0)
                .err()
                .map(Error::into_code),
            Some(CURLcode::BadFunctionArgument)
        );
    }

    // Phase 6: certinfo, its labels and their order

    #[test]
    fn certinfo_reports_the_c_s_labels_in_the_c_s_order() {
        let certificate = der(EE_PEM);
        let records = extract_certinfo(certificate.as_ref())
            .expect("the embedded certificate parses");
        let labels: Vec<&str> =
            records.iter().map(CertInfoRecord::label).collect();
        assert_eq!(
            labels,
            vec![
                "Subject",
                "Issuer",
                "Version",
                "Serial Number",
                "Signature Algorithm",
                "Start Date",
                "Expire Date",
                "Public Key Algorithm",
                // `do_pubkey`'s contribution for an RSA key.
                "RSA Public Key",
                "rsa(n)",
                "rsa(e)",
                "Signature",
                "Cert",
            ],
            "a consumer walks the slist in the order libcurl built it, so \
             the order is contractual"
        );
    }

    #[test]
    fn certinfo_values_match_what_the_c_would_render() {
        let certificate = der(EE_PEM);
        let records = extract_certinfo(certificate.as_ref())
            .expect("the embedded certificate parses");
        let value = |label: &str| -> String {
            records
                .iter()
                .find(|record| record.label() == label)
                .unwrap_or_else(|| panic!("{label} is present"))
                .value_lossy()
                .into_owned()
        };

        // `encodeDN`'s delimiter rule: short uppercase names take ", ".
        assert_eq!(value("Subject"), "C=SE, O=curl-rs test, CN=localhost");
        assert_eq!(value("Issuer"), "C=SE, O=curl-rs test, CN=curl-rs test CA");
        // A v3 certificate carries version 2, rendered in hexadecimal.
        assert_eq!(value("Version"), "2");
        // A twenty-octet serial number exceeds four, so it renders as
        // colon-separated hexadecimal WITH its trailing colon.
        assert_eq!(
            value("Serial Number"),
            "16:4b:53:1c:2a:3f:c5:e6:fb:a7:cb:6e:d7:51:2e:58:de:7e:65:e7:"
        );
        assert_eq!(value("Signature Algorithm"), "sha256WithRSAEncryption");
        assert_eq!(value("Start Date"), "2026-08-08 02:03:43 GMT");
        assert_eq!(value("Expire Date"), "2126-07-15 02:03:43 GMT");
        assert_eq!(value("Public Key Algorithm"), "rsaEncryption");
        assert_eq!(value("RSA Public Key"), "2048");
        // The public exponent, 65537, is above ten and takes the prefix.
        assert_eq!(value("rsa(e)"), "0x10001");
        // The modulus is 256 octets, so it renders as hexadecimal pairs.
        assert!(value("rsa(n)").starts_with("d2:15:1b:7c:"));
        assert!(value("rsa(n)").ends_with(':'));
    }

    #[test]
    fn the_cert_record_is_pem_wrapped_at_exactly_sixty_four_characters() {
        let certificate = der(EE_PEM);
        let pem = certificate_pem(certificate.as_ref())
            .expect("the certificate re-encodes");
        let text = String::from_utf8(pem).expect("base64 is ASCII");

        assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(text.ends_with("-----END CERTIFICATE-----\n"));

        let body: Vec<&str> = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(!body.is_empty());
        for line in &body[..body.len() - 1] {
            assert_eq!(
                line.len(),
                PEM_LINE_WIDTH,
                "every line but the last is exactly 64 characters"
            );
        }
        assert!(body[body.len() - 1].len() <= PEM_LINE_WIDTH);
        assert!(!body[body.len() - 1].is_empty());

        // Round trip: the body decodes back to the certificate.
        let rejoined: String = body.concat();
        let decoded = base64::decode(rejoined.as_bytes())
            .expect("the body is valid base64");
        assert_eq!(decoded.as_slice(), certificate.as_ref());

        // And the record carries exactly this text.
        let records = extract_certinfo(certificate.as_ref())
            .expect("the certificate parses");
        let record = records.last().expect("Cert is the last record");
        assert_eq!(record.label(), "Cert");
        assert_eq!(record.value_lossy(), text);
    }

    #[test]
    #[cfg_attr(miri, ignore = "base64-encodes 80 KiB twice")]
    fn a_rendered_string_cannot_exceed_the_hundred_thousand_octet_ceiling() {
        // 80 KiB of input becomes about 107 KiB of base64, which crosses
        // `CURL_X509_STR_MAX` and must be refused rather than allocated.
        let oversized = vec![0xABu8; 80 * 1024];
        assert!(
            base64::encode(&oversized).expect("encoding succeeds").len()
                > CURL_X509_STR_MAX
        );
        assert_eq!(
            certificate_pem(&oversized).err().map(Error::into_code),
            Some(CURLcode::TooLarge)
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "renders a hundred certificates; minutes under Miri"
    )]
    fn a_chain_above_one_hundred_certificates_is_refused() {
        let certificate = der(EE_PEM);
        let chain = vec![certificate.clone(); MAX_ALLOWED_CERT_AMOUNT + 1];
        let error = extract_certinfo_chain(&chain)
            .expect_err("`rustls.c:1201-1205` refuses this");
        assert_eq!(error.code(), CURLcode::SslConnectError);
        assert_eq!(
            error.message(),
            "101 certificates is more than allowed (100)"
        );

        // Exactly one hundred is allowed: the C's test is `>`.
        let chain = vec![certificate; MAX_ALLOWED_CERT_AMOUNT];
        let extracted =
            extract_certinfo_chain(&chain).expect("one hundred is allowed");
        assert_eq!(extracted.len(), MAX_ALLOWED_CERT_AMOUNT);
        assert_eq!(extracted[0][0].label(), "Subject");
    }

    #[test]
    fn certinfo_failure_carries_the_c_s_message_and_never_partial_state() {
        let error = extract_certinfo(b"\x30\x03\x02\x01\x00")
            .expect_err("this is not a certificate");
        assert_eq!(error.code(), CURLcode::PeerFailedVerification);
        assert_eq!(error.message(), "Failed extracting certificate chain");
    }

    #[test]
    fn a_record_renders_as_the_slist_entry_the_c_builds() {
        let record = CertInfoRecord::new("Subject", b"CN=localhost");
        assert_eq!(record.label(), "Subject");
        assert_eq!(record.value(), b"CN=localhost");
        assert_eq!(record.to_slist_entry(), b"Subject:CN=localhost".to_vec());
    }

    #[test]
    fn a_certificate_s_structure_is_reachable_field_by_field() {
        let certificate = der(EE_PEM);
        let parsed =
            parse_x509(certificate.as_ref()).expect("the certificate parses");
        assert_eq!(parsed.certificate(), certificate.as_ref());
        assert!(parsed.subject().is_constructed());
        assert!(parsed.issuer().is_constructed());
        assert!(!parsed.extensions().content().is_empty());
        assert!(parsed.subject_public_key_info().is_constructed());
        // This certificate carries neither unique identifier.
        assert!(parsed.issuer_unique_id().content().is_empty());
        assert!(parsed.subject_unique_id().content().is_empty());

        // The commonName is the one the subject holds.
        assert_eq!(
            last_common_name(parsed.subject())
                .expect("the subject renders")
                .map(|name| String::from_utf8_lossy(&name).into_owned()),
            Some("localhost".to_owned())
        );
    }

    #[test]
    fn the_subject_alt_name_extension_is_decoded_by_kind() {
        let certificate = der(EE_PEM);
        let parsed =
            parse_x509(certificate.as_ref()).expect("the certificate parses");
        let names = subject_alt_names(&parsed);
        assert_eq!(
            names,
            vec![
                GeneralName::Dns(b"localhost"),
                GeneralName::Dns(b"*.example.com"),
                GeneralName::IpAddress(&[127, 0, 0, 1]),
            ]
        );

        // A certificate with no extension at all yields no names, which is
        // what sends the decision to the commonName.
        let cn_only = der(CN_ONLY_PEM);
        let parsed = parse_x509(cn_only.as_ref()).expect("it parses");
        assert!(subject_alt_names(&parsed).is_empty());
    }

    // Phase 7: error mapping and the narrow public surface

    #[test]
    fn every_failure_maps_to_a_curl_code_from_the_one_error_enumeration() {
        // No second ABI enumeration exists in this module: each of these is
        // `crate::error::CURLcode`, and the values are the C's.
        assert_eq!(CURLcode::PeerFailedVerification as i32, 60);
        assert_eq!(CURLcode::SslCertproblem as i32, 58);
        assert_eq!(CURLcode::SslCacertBadfile as i32, 77);
        assert_eq!(CURLcode::SslCrlBadfile as i32, 82);
        assert_eq!(CURLcode::BadFunctionArgument as i32, 43);
        assert_eq!(CURLcode::NotBuiltIn as i32, 4);
        assert_eq!(CURLcode::OutOfMemory as i32, 27);
        assert_eq!(CURLcode::TooLarge as i32, 100);
    }

    #[test]
    #[cfg_attr(miri, ignore = "this reads the source tree, not the program")]
    fn client_auth_debug_output_holds_no_key_material() {
        // The type cannot be built in this module without key material, so
        // the guarantee is checked on the format string itself: the manual
        // implementation names the two things it prints.
        let source = own_source();
        let debug_body: String = source
            .lines()
            .skip_while(|line| !line.contains("impl fmt::Debug for ClientAuth"))
            .take_while(|line| !line.contains("impl ClientAuth {"))
            .collect();
        assert!(debug_body.contains("chain_length"));
        assert!(
            !debug_body.contains("certified_key.key"),
            "the signing key must not reach a formatter"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_configuration_completes_with_and_without_client_auth() {
        let provider = provider();
        let verification =
            ServerVerification::build(&VerifyPolicy::new(), &provider)
                .expect("the bundled roots build a verifier");

        let builder =
            ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .expect("the provider offers protocol versions");
        let config = install_client_auth(verification.install(builder), None);
        assert!(!config.client_auth_cert_resolver.has_certs());

        // And the insecure configuration installs through the same seam.
        let insecure = ServerVerification::build(
            &VerifyPolicy::new().with_peer_verification(false),
            &provider,
        )
        .expect("the insecure path cannot fail");
        let builder = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("the provider offers protocol versions");
        let _config = install_client_auth(insecure.install(builder), None);
    }
}
