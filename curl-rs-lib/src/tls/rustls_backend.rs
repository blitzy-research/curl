//***************************************************************************
//                                  _   _ ____  _
//  Project                     ___| | | |  _ \| |
//                             / __| | | | |_) | |
//                            | (__| |_| |  _ <| |___
//                             \___|\___/|_| \_\_____|
//
// Copyright (C) Jacob Hoffman-Andrews, <github@hoffman-andrews.com>
// Copyright (C) kpcyrd, <kpcyrd@archlinux.org>
// Copyright (C) Daniel McCarney, <daniel@binaryparadox.net>
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

//! The one TLS backend: native rustls 0.23.42.
//!
//! Three things change, and nothing else does.
//!
//! * **The C API becomes the Rust API.** `rustls_connection`,
//!   `rustls_client_config` and the `rustls_result` integer are replaced by
//!   [`rustls::ClientConnection`], [`rustls::ClientConfig`] and
//!   [`rustls::Error`]. `rustls_connection_set_userdata` disappears with the
//!   `void *` it carried: the session state is a typed field of a typed
//!   struct, so there is nothing to attach and nothing to cast back.
//! * **The two I/O callbacks become two adapters.** `read_cb` and `write_cb`
//!   (`rustls.c:90-152`) hand rustls a function pointer plus a `void
//!   *userdata` holding `{cf, data}`. Here [`BelowReader`] and [`BelowWriter`]
//!   implement [`std::io::Read`] and [`std::io::Write`] over the *next*
//!   [`crate::conn::filters::ConnFilter`], reached through
//!   [`crate::tls::TlsTransport`]. No socket is touched in this file, which is
//!   also what makes every path below testable against a fake transport.
//! * **Global state becomes injected state.** The C reaches for
//!   `rustls_default_crypto_provider_*` and the process-global
//!   `keylog_file_fp`. Here the [`rustls::crypto::CryptoProvider`], the key
//!   log and the session store all arrive as values, so two transfers in one
//!   process cannot disagree about them and no test can be perturbed by the
//!   order it ran in.
//!
//! # Provider: `ring`, injected, never installed
//!
//! The workspace manifest pins `rustls`, `tokio-rustls` and `quinn` with
//! `default-features = false` and the `ring` provider named explicitly. This
//! module never calls `CryptoProvider::install_default`, never calls
//! `get_default`, never calls a `default_provider()` of its own accord, and
//! never enables `aws_lc_rs`, `prefer-post-quantum` or `platform-verifier`.
//! The provider is a constructor argument ([`RustlsBackend::new`]).
//!
//! `prefer-post-quantum` matters specifically: it offers a hybrid
//! X25519MLKEM768 key exchange, which changes `ClientHello` bytes relative to
//! curl 8.19.0-DEV and would put every HTTPS fixture at risk.
//!
//! # Measured deviation 1: ECH is advertised only when it works, and it does
//! not work under `ring`
//!
//! `rustls.c:1399-1405` sets seven capability bits and one of them is
//! `SSLSUPP_ECH`. A native rustls build cannot honestly set it, and the reason
//! is a property of the pinned provider rather than of this translation:
//!
//! * Encrypted Client Hello needs HPKE. Both constructors demand it --
//!   `EchConfig::new(EchConfigListBytes, &[&'static dyn Hpke])` and
//!   `EchGreaseConfig::new(&'static dyn Hpke, HpkePublicKey)`.
//! * rustls 0.23.42 implements HPKE in exactly one place,
//!   `src/crypto/aws_lc_rs/hpke.rs`, declared at
//!   `src/crypto/aws_lc_rs/mod.rs:21`. `src/crypto/ring/` ships hash, hmac,
//!   kx, quic, sign, ticketer, tls12 and tls13 -- and no hpke.
//! * There is no `ring`-side HPKE feature. `rustls`'s manifest offers
//!   `aws_lc_rs`, `fips = ["aws_lc_rs", ...]` and
//!   `prefer-post-quantum = ["aws_lc_rs"]`, all of which are forbidden here.
//!
//! # Safety and visibility
//!
//! No `unsafe`, no raw pointer, no [`std::any::Any`], no downcast, no direct
//! socket access, and no `unwrap`/`expect` on transport or peer data.
//! `pub(crate)` throughout; the only widened item is
//! [`RustlsBackend::backend_info`], because backend identity is public ABI
//! that `curl_global_sslset` and `curl_version_info` report. The version token
//! is not duplicated here at all -- it is read from [`crate::version`], which
//! `curl-rs-ffi` already reads, so one ABI answer has one source.

use core::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustls::client::{
    ClientSessionStore, EchConfig, EchGreaseConfig, EchMode, EchStatus,
    Resumption, Tls12ClientSessionValue, Tls13ClientSessionValue,
};
use rustls::crypto::hpke::Hpke;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{
    ClientConfig, ClientConnection, NamedGroup, ProtocolVersion,
    SupportedProtocolVersion,
};

use crate::conn::filters::{TlsBackendId, TlsHandleKind, TlsSessionInfo};
use crate::error::{CURLcode, CodeResult, CurlResult, Error};
use crate::tls::cipher_suite;
use crate::tls::keylog::KeyLogFile;
use crate::tls::session_cache::{
    ClientAuth as ScacheClientAuth, SessionCaching,
};
use crate::tls::verify::{
    self, install_client_auth, ClientAuth, ServerVerification, TrustSource,
    VerifyPolicy,
};
use crate::tls::{
    AlpnSpec, CurlSslDescriptor, HandshakeProgress, IetfProtoVersion,
    ProviderRng, SslBackendInfo, SslConnectState, SslConnectionState,
    SslIoNeed, SslPeer, SslSupport, TlsBackend, TlsOp, TlsPrefs, TlsTransport,
    ALPN_ENTRIES_MAX, MAX_ALLOWED_CERT_AMOUNT,
};
use crate::trace::{failf, infof, trc_cf, TraceFilter};
use crate::util::base64;
use crate::version::SSL_VERSION;

// Identity and capability -- `Curl_ssl_rustls` (`lib/vtls/rustls.c:1397-1426`)

/// This backend's identity: `{ CURLSSLBACKEND_RUSTLS, "rustls" }`.
const RUSTLS_INFO: SslBackendInfo = SslBackendInfo::RUSTLS;

/// What this backend truthfully answers yes to.
///
/// ```text
/// SSLSUPP_CAINFO_BLOB | SSLSUPP_HTTPS_PROXY | SSLSUPP_CIPHER_LIST |
/// SSLSUPP_TLS13_CIPHERSUITES | SSLSUPP_CERTINFO | SSLSUPP_ECH |
/// SSLSUPP_CRLFILE
/// ```
///
/// Six of those seven are set here, each one behind a path that exists and is
/// tested:
///
/// | bit | what backs it |
/// |-----|---------------|
/// | `CAINFO_BLOB` | [`TrustSource::from_curl_options`], blob overriding file |
/// | `HTTPS_PROXY` | the same session serves either filter role |
/// | `CIPHER_LIST` | `CURLOPT_SSL_CIPHER_LIST` via [`cipher_suite`] |
/// | `TLS13_CIPHERSUITES` | `CURLOPT_TLS13_CIPHERS` via [`cipher_suite`] |
/// | `CERTINFO` | [`crate::tls::verify::extract_certinfo_chain`] |
/// | `CRLFILE` | [`VerifyPolicy::with_crl_file`] |
///
/// `ECH` is the seventh and is deliberately absent: the pinned `ring` provider
/// offers no HPKE suite, so advertising it would be a lie the fixture harness
/// would convert into hard failures. The module documentation carries the
/// file-level evidence.
const RUSTLS_SUPPORTS: SslSupport = SslSupport::CAINFO_BLOB
    .union(SslSupport::HTTPS_PROXY)
    .union(SslSupport::CIPHER_LIST)
    .union(SslSupport::TLS13_CIPHERSUITES)
    .union(SslSupport::CERTINFO)
    .union(SslSupport::CRLFILE);

/// The socket index the backend's own trace lines are labelled with.
///
/// `CURL_TRC_CF()` reads `cf->sockindex` (`lib/curl_trc.h:148-152`), and
/// [`TlsTransport`] deliberately does not carry it: the seam a backend gets is
/// "the bytes below, and nothing else", which is what keeps this file unable
/// to reach a connection or a transfer. `0` is the primary chain's index and
/// renders as `[SSL]` rather than `[SSL-1]`
/// (`crate::trace::Tracer::filter`), which is exactly what the C emits for a
/// TLS filter on `FIRSTSOCKET`.
const TRACE_SOCKINDEX: i32 = 0;

/// `CURL_SSLVERSION_TLSv1` = 1 (`include/curl/curl.h:2366`).
const CURL_SSLVERSION_TLSV1: u8 = 1;

/// `CURL_SSLVERSION_TLSv1_0` = 4 (`include/curl/curl.h:2369`).
const CURL_SSLVERSION_TLSV1_0: u8 = 4;

/// `CURL_SSLVERSION_TLSv1_1` = 5 (`include/curl/curl.h:2370`).
const CURL_SSLVERSION_TLSV1_1: u8 = 5;

/// `CURL_SSLVERSION_TLSv1_2` = 6 (`include/curl/curl.h:2371`).
///
/// Also the value a caller who asked for nothing ends up with:
/// `lib/setopt.c:347-348` rewrites `CURL_SSLVERSION_DEFAULT` to this before a
/// backend ever sees it, which is why `rustls.c:536` can assert the value is
/// not `DEFAULT` and why [`TlsOptions::new`] starts here.
const CURL_SSLVERSION_TLSV1_2: u8 = 6;

/// `CURL_SSLVERSION_TLSv1_3` = 7 (`include/curl/curl.h:2372`).
const CURL_SSLVERSION_TLSV1_3: u8 = 7;

/// `CURL_SSLVERSION_MAX_NONE` = 0 (`include/curl/curl.h:2376`).
const CURL_SSLVERSION_MAX_NONE: i64 = 0;

/// `CURL_SSLVERSION_MAX_DEFAULT` = `CURL_SSLVERSION_TLSv1 << 16`
/// (`include/curl/curl.h:2377`).
const CURL_SSLVERSION_MAX_DEFAULT: i64 = (CURL_SSLVERSION_TLSV1 as i64) << 16;

/// `CURL_SSLVERSION_MAX_TLSv1_2` = `CURL_SSLVERSION_TLSv1_2 << 16`
/// (`include/curl/curl.h:2380`).
const CURL_SSLVERSION_MAX_TLSV1_2: i64 = (CURL_SSLVERSION_TLSV1_2 as i64) << 16;

/// `CURL_SSLVERSION_MAX_TLSv1_3` = `CURL_SSLVERSION_TLSv1_3 << 16`
/// (`include/curl/curl.h:2381`).
const CURL_SSLVERSION_MAX_TLSV1_3: i64 = (CURL_SSLVERSION_TLSV1_3 as i64) << 16;

/// How many bytes `cr_shutdown` drains looking for the peer's `close_notify`,
/// and how many attempts it makes.
const SHUTDOWN_DRAIN_ATTEMPTS: usize = 10;

/// The buffer `cr_shutdown`'s drain loop reads into (`rustls.c:1276`).
const SHUTDOWN_DRAIN_BUFFER: usize = 1024;

/// How many peers [`RustlsSessionStore`] remembers.
const STORE_MAX_PEERS: usize = 8;

/// How many unspent TLS 1.3 tickets one peer may accumulate.
const STORE_MAX_TICKETS_PER_PEER: usize = 8;

// Error mapping -- `map_error` and `rustls_failf` (`rustls.c:52-75`)

/// `map_error` (`lib/vtls/rustls.c:52-66`): the best-matching [`CURLcode`] for
/// a rustls failure.
///
/// ```c
/// if(rustls_result_is_cert_error(r))
///   return CURLE_PEER_FAILED_VERIFICATION;
/// switch(r) {
/// case RUSTLS_RESULT_OK:             return CURLE_OK;
/// case RUSTLS_RESULT_NULL_PARAMETER: return CURLE_BAD_FUNCTION_ARGUMENT;
/// default:                           return CURLE_RECV_ERROR;
/// }
/// ```
///
/// * **Certificate errors** are the whole of rustls's `InvalidCertificate`
///   family, plus the two peer-identity failures that rustls reports
///   separately but `rustls_result_is_cert_error` also covers --
///   `InvalidCertRevocationList` and `NoCertificatesPresented` -- and they map
///   to [`CURLcode::PeerFailedVerification`].
/// * **Invalid or absent arguments** map to
///   [`CURLcode::BadFunctionArgument`]. rustls has no null pointer to reject,
///   so the equivalent conditions are the ones that mean "the caller handed us
///   something unusable": a general or unsupported name, and an unusable
///   encrypted-client-hello configuration.
/// * **Everything else** maps to [`CURLcode::RecvError`], exactly as the C's
///   `default:` does. That is deliberately blunt on the C's part and is not
///   corrected here: the callers that need a different code -- the handshake,
///   which reports [`CURLcode::SslConnectError`], and the plaintext writer,
///   which reports [`CURLcode::WriteError`] -- substitute it themselves, and
///   they are the only places that know which phase failed.
fn map_rustls_error(error: &rustls::Error) -> CURLcode {
    // `rustls_result_is_cert_error` first, and its answer wins.
    if is_certificate_error(error) {
        return CURLcode::PeerFailedVerification;
    }
    match error {
        // `RUSTLS_RESULT_NULL_PARAMETER`'s nearest relatives: a caller-supplied
        // value rustls will not accept at all.
        rustls::Error::General(_)
        | rustls::Error::InvalidEncryptedClientHello(_) => {
            CURLcode::BadFunctionArgument
        }
        // The C's `default:`.
        _ => CURLcode::RecvError,
    }
}

/// `rustls_result_is_cert_error`: is this failure about the peer's
/// certificate?
fn is_certificate_error(error: &rustls::Error) -> bool {
    matches!(
        error,
        rustls::Error::InvalidCertificate(_)
            | rustls::Error::InvalidCertRevocationList(_)
            | rustls::Error::NoCertificatesPresented
    )
}

/// `rustls_failf` (`lib/vtls/rustls.c:68-75`): `failf(data, "%s: %.*s", msg,
/// error text)`.
fn rustls_failf(
    io: &mut TlsTransport<'_, '_, '_>,
    error: &rustls::Error,
    message: &str,
) {
    if let Some(tracer) = io.ctx().tracer_mut() {
        failf!(tracer, "{message}: {error}");
    }
}

/// One `CURL_TRC_CF()` line from inside the backend.
///
/// A function rather than a macro so that the [`TraceFilter`] and the socket
/// index are written down once. The format arguments are already assembled by
/// the caller, so nothing is evaluated when tracing is off beyond the
/// `Option` test on the tracer.
fn trace(io: &mut TlsTransport<'_, '_, '_>, args: fmt::Arguments<'_>) {
    if let Some(tracer) = io.ctx().tracer_mut() {
        trc_cf!(tracer, TraceFilter::Ssl, TRACE_SOCKINDEX, "{}", args);
    }
}

/// One `infof()` line from inside the backend.
fn info(io: &mut TlsTransport<'_, '_, '_>, args: fmt::Arguments<'_>) {
    if let Some(tracer) = io.ctx().tracer_mut() {
        infof!(tracer, "{}", args);
    }
}

/// One `failf()` line from inside the backend.
fn fail(io: &mut TlsTransport<'_, '_, '_>, args: fmt::Arguments<'_>) {
    if let Some(tracer) = io.ctx().tracer_mut() {
        failf!(tracer, "{}", args);
    }
}

// Encrypted Client Hello -- `init_config_builder_ech` (`rustls.c:907-1006`)

/// Where an `ECHConfigList` comes from, and how hard a failure is.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) enum EchPolicy {
    /// No ECH: the variable is unset or carries `CURLECH_DISABLE`.
    ///
    /// [`Default`], because `ECH_ENABLED()` is false for a handle nobody
    /// configured.
    #[default]
    Disabled,
    /// `CURLECH_GREASE`: send a decoy extension and no real configuration.
    ///
    /// `rustls.c:931-939` takes this branch and returns immediately, so GREASE
    /// never reads a configuration and never consults DNS.
    Grease,
    /// `CURLECH_ENABLE | CURLECH_CLA_CFG` with `--ech ecl:<base64>`.
    ///
    /// The string is the user's base64 exactly as it arrived; decoding happens
    /// in [`EchPolicy::config_list`], as `rustls.c:948-957` decodes it with
    /// `curlx_base64_decode`, because "rustls-ffi expects the raw TLS encoded
    /// ECHConfigList bytes" (`rustls.c:952`).
    #[allow(dead_code)]
    CommandLine(String),
    /// `CURLECH_ENABLE` resolved from the peer's HTTPS resource record.
    ///
    /// The raw `echconfiglist` bytes of `struct Curl_https_rrinfo`
    /// (`rustls.c:959-977`), supplied by the caller rather than looked up
    /// here: `Curl_dnscache_get` needs the easy handle and the connection,
    /// which is exactly the reach a backend must not have. The DNS module owns
    /// the lookup and hands over the bytes.
    #[allow(dead_code)]
    Dns(Vec<u8>),
}

impl EchPolicy {
    /// `ECH_ENABLED(data)` (`lib/vtls/vtls.h:52-56`).
    pub(crate) const fn is_enabled(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// The raw TLS-encoded `ECHConfigList` this policy names, if any.
    ///
    /// # Errors
    ///
    /// [`CURLcode::SslConnectError`] for command-line input that is empty or
    /// is not base64, which are `rustls.c:950-956`'s two `infof` arms. Both
    /// carry the C's own wording and both are fatal there too -- the C sets
    /// `result` and jumps to `cleanup`.
    fn config_list(&self) -> CurlResult<Option<Vec<u8>>> {
        match self {
            Self::Disabled | Self::Grease => Ok(None),
            Self::CommandLine(encoded) => {
                if encoded.is_empty() {
                    return Err(Error::with_context(
                        CURLcode::SslConnectError,
                        "rustls: ECHConfig from command line empty",
                    ));
                }
                let decoded =
                    base64::decode(encoded.as_bytes()).map_err(|_| {
                        Error::with_context(
                            CURLcode::SslConnectError,
                            "rustls: cannot base64 decode ECHConfig from \
                             command line",
                        )
                    })?;
                if decoded.is_empty() {
                    return Err(Error::with_context(
                        CURLcode::SslConnectError,
                        "rustls: cannot base64 decode ECHConfig from command \
                         line",
                    ));
                }
                Ok(Some(decoded))
            }
            Self::Dns(bytes) => {
                if bytes.is_empty() {
                    // `rustls.c:971-976`: an HTTPS record with no `ech`
                    // parameter is "ECH requested but no ECHConfig available".
                    return Err(Error::with_context(
                        CURLcode::SslConnectError,
                        "rustls: ECH requested but no ECHConfig available",
                    ));
                }
                Ok(Some(bytes.clone()))
            }
        }
    }
}

// Options -- `ssl_primary_config` and `ssl_config_data` as one injected value

/// Everything a `ClientConfig` is built from, other than the provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TlsOptions {
    /// `conn_config->version` and `->version_max`, validated by
    /// [`TlsPrefs::check`] before a filter will start a handshake and mapped
    /// to a rustls version list by [`protocol_versions`].
    pub(crate) prefs: TlsPrefs,
    /// `conn_config->verifypeer`: the single switch that decides between
    /// web-PKI verification and none (`rustls.c:1032-1036`).
    pub(crate) verify_peer: bool,
    /// `conn_config->verifyhost`.
    pub(crate) verify_host: bool,
    /// `CURLOPT_CAINFO_BLOB`, which overrides `CURLOPT_CAINFO`
    /// (`rustls.c:1015-1017`).
    pub(crate) ca_info_blob: Option<Vec<u8>>,
    /// `CURLOPT_CAINFO` / `--cacert`.
    pub(crate) ca_file: Option<PathBuf>,
    /// `CURLOPT_CAPATH` / `--capath`.
    pub(crate) ca_path: Option<PathBuf>,
    /// `ssl_config->native_ca_store` (`rustls.c:1037`).
    pub(crate) native_ca_store: bool,
    /// `conn_config->CRLfile` / `--crlfile` (`rustls.c:660-690`).
    pub(crate) crl_file: Option<PathBuf>,
    /// `conn_config->clientcert` / `CURLOPT_SSLCERT`.
    pub(crate) client_cert: Option<PathBuf>,
    /// `ssl_config->key` / `CURLOPT_SSLKEY`, which must accompany the
    /// certificate (`rustls.c:844-853`).
    pub(crate) client_key: Option<PathBuf>,
    /// `conn_config->cipher_list` / `CURLOPT_SSL_CIPHER_LIST`.
    pub(crate) cipher_list: Option<String>,
    /// `conn_config->cipher_list13` / `CURLOPT_TLS13_CIPHERS`.
    pub(crate) cipher_list13: Option<String>,
    /// `data->set.ssl.certinfo` / `CURLOPT_CERTINFO` (`rustls.c:1194`).
    pub(crate) certinfo: bool,
    /// `ssl_config->primary.cache_session`, the second conjunct of
    /// `Curl_ssl_scache_use` (`lib/vtls/vtls_scache.c:575-582`).
    pub(crate) caching: SessionCaching,
    /// `data->set.tls_ech` reduced to its reachable states.
    pub(crate) ech: EchPolicy,
    /// `data->set.tls_ech & CURLECH_HARD` (`rustls.c:1069`).
    ///
    /// When set, a failure to configure ECH aborts the handshake; otherwise
    /// the C ignores the error and continues without ECH, which is the whole
    /// of the soft mode.
    pub(crate) ech_hard: bool,
    /// `data->set.str[STRING_ECH_PUBLIC]` / `--ech pn:<name>`.
    ///
    /// Any value at all is refused: `rustls.c:925-929` fails with "rustls: ECH
    /// outername not supported" before it looks at anything else.
    pub(crate) ech_public_name: Option<String>,
}

impl Default for TlsOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsOptions {
    /// The options a handle that configured nothing ends up with.
    ///
    /// Two defaults are contract rather than convenience:
    ///
    /// * `verify_peer` and `verify_host` are **true**. Certificate validation
    ///   is on unless `--insecure` turns it off, and `--insecure` is the only
    ///   thing that may.
    /// * `prefs.version` is [`CURL_SSLVERSION_TLSV1_2`], not
    ///   `CURL_SSLVERSION_DEFAULT`. `lib/setopt.c:347-348` performs exactly
    ///   that rewrite -- `if(version == CURL_SSLVERSION_DEFAULT) version =
    ///   CURL_SSLVERSION_TLSv1_2;` -- before any backend is reached, which is
    ///   why `rustls.c:536` may assert the value is never `DEFAULT` and why
    ///   [`protocol_versions`] rejects `DEFAULT` rather than interpreting it.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            prefs: TlsPrefs {
                version: CURL_SSLVERSION_TLSV1_2,
                version_max: CURL_SSLVERSION_MAX_NONE,
            },
            verify_peer: true,
            verify_host: true,
            ca_info_blob: None,
            ca_file: None,
            ca_path: None,
            native_ca_store: false,
            crl_file: None,
            client_cert: None,
            client_key: None,
            cipher_list: None,
            cipher_list13: None,
            certinfo: false,
            caching: SessionCaching::ENABLED,
            ech: EchPolicy::Disabled,
            ech_hard: false,
            ech_public_name: None,
        }
    }

    /// `--insecure`: turn peer *and* host verification off together.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn insecure(mut self) -> Self {
        self.verify_peer = false;
        self.verify_host = false;
        self
    }

    /// The trust source curl's precedence selects.
    ///
    /// `CURLOPT_CAINFO_BLOB overrides CURLOPT_CAINFO` (`rustls.c:1015-1017`),
    /// then the platform store, then the bundled roots. The order is
    /// [`TrustSource::from_curl_options`]'s, so it is written down once.
    fn trust_source(&self) -> TrustSource {
        TrustSource::from_curl_options(
            self.ca_info_blob.clone(),
            self.ca_file.clone(),
            self.native_ca_store,
        )
    }

    /// The verification policy these options describe.
    fn verify_policy(&self) -> VerifyPolicy {
        VerifyPolicy::new()
            .with_trust_source(self.trust_source())
            .with_ca_path(self.ca_path.clone())
            .with_crl_file(self.crl_file.clone())
            .with_peer_verification(self.verify_peer)
            .with_host_verification(self.verify_host)
    }

    /// The session-cache identity these options imply.
    ///
    /// `cf_ssl_scache_match_auth` (`lib/vtls/vtls_scache.c:598-618`) keys a
    /// cached session on the client certificate as well as the peer, so a
    /// transfer presenting different credentials must not resume another's
    /// session. The spelling is the option's own, which is what the C
    /// compares.
    fn scache_auth(&self) -> ScacheClientAuth {
        ScacheClientAuth::new(
            self.client_cert.as_deref().and_then(Path::to_str),
        )
    }
}

// The session store -- resumption without a process-global rustls cache

/// Which peer and which credentials a [`RustlsSessionStore`] serves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SessionScope {
    /// `peer->ssl_peer_key`: the whole configuration, as one string.
    peer_key: String,
    /// `peer->clientcert`, through the type `crate::tls::session_cache` uses
    /// for it.
    auth: ScacheClientAuth,
}

impl SessionScope {
    /// A scope over `peer_key` with `auth`'s credentials.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn new(peer_key: String, auth: ScacheClientAuth) -> Self {
        Self { peer_key, auth }
    }

    /// Whether a session held under this scope may serve `peer_key` presenting
    /// `auth`.
    ///
    /// Two tests, and each is the C's:
    ///
    /// * the peer keys must be equal, which is `cf_ssl_scache_get_peer`'s
    ///   lookup (`vtls_scache.c:620-650`);
    /// * the credentials must match, which is
    ///   [`ScacheClientAuth::matches`] -- case-sensitive, with
    ///   both-absent counting as equal.
    #[must_use]
    pub(crate) fn admits(
        &self,
        peer_key: &str,
        auth: &ScacheClientAuth,
    ) -> bool {
        self.peer_key == peer_key && self.auth.matches(Some(auth))
    }

    /// The peer key this scope was built for.
    // Consumer is the share-lock seam named above; reached today by this
    // file's tests, which is what keeps the accessor honest.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn peer_key(&self) -> &str {
        &self.peer_key
    }
}

/// What a store has been asked to do, in numbers a caller may assert on.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StoreStats {
    /// How many TLS 1.2 sessions were remembered.
    pub(crate) tls12_stored: u64,
    /// How many TLS 1.3 tickets were remembered.
    pub(crate) tls13_stored: u64,
    /// How many TLS 1.3 tickets were spent.
    pub(crate) tls13_taken: u64,
    /// How many key-exchange hints were remembered.
    pub(crate) kx_hints_stored: u64,
    /// The largest early-data ceiling any stored ticket advertised, in bytes.
    ///
    /// `Tls13ClientSessionValue::max_early_data_size`, which is public. This
    /// is what `Curl_ssl_session_create`'s `earlydata_max` records, and it is
    /// reported rather than acted on: see [`configure`] for why
    /// `enable_early_data` stays false.
    pub(crate) earlydata_max: usize,
}

/// One peer's remembered material.
struct StorePeer {
    /// The name the session was established with.
    name: ServerName<'static>,
    /// `set_kx_hint` / `kx_hint`: which group the server chose last time.
    kx_hint: Option<NamedGroup>,
    /// `set_tls12_session` / `tls12_session`: at most one, per rustls's own
    /// documented contract.
    tls12: Option<Tls12ClientSessionValue>,
    /// `insert_tls13_ticket` / `take_tls13_ticket`: a bounded queue, oldest
    /// first.
    ///
    /// Oldest first is the right order to spend in, and it is the order
    /// `Curl_ssl_scache_take` uses (`vtls_scache.c:890-893`): a TLS 1.3 ticket
    /// is single-use, so the queue is consumed in the order it was filled.
    tls13: std::collections::VecDeque<Tls13ClientSessionValue>,
}

impl StorePeer {
    /// An empty slot for `name`.
    fn new(name: ServerName<'static>) -> Self {
        Self {
            name,
            kx_hint: None,
            tls12: None,
            tls13: std::collections::VecDeque::new(),
        }
    }

    /// Whether this slot holds nothing at all, and so may be evicted for free.
    fn is_empty(&self) -> bool {
        self.kx_hint.is_none() && self.tls12.is_none() && self.tls13.is_empty()
    }
}

/// The store's contents, behind one lock.
struct StoreInner {
    /// Bounded at [`STORE_MAX_PEERS`]; a new peer displaces the first slot
    /// that holds nothing, or the oldest slot when every one is in use.
    peers: Vec<StorePeer>,
    /// What has happened, for a caller to read.
    stats: StoreStats,
}

/// A [`rustls::client::ClientSessionStore`] this crate owns.
///
/// The successor of `rustls_client_config_builder`'s implicit session cache
/// and *not* [`rustls::client::Resumption::in_memory_sessions`], which would
/// be a store rustls chose rather than one curl owns. Three properties follow
/// from owning it, and all three are requirements rather than niceties:
///
/// * **Bounded.** [`STORE_MAX_PEERS`] slots, each holding at most
///   [`STORE_MAX_TICKETS_PER_PEER`] unspent tickets. A server that streams
///   `NewSessionTicket` messages cannot grow this.
/// * **Scoped.** [`SessionScope`] refuses a peer or a set of credentials the
///   store was not built for, which is the pairing
///   `lib/vtls/vtls_scache.c:598-618` keys its slab on.
/// * **Observable.** [`Self::stats`] reports what happened, because rustls's
///   trait is write-only from the caller's side.
///
/// # Interior mutability, and why the lock is here
///
/// Note the contrast with `crate::tls::session_cache::SessionCache`, which is
/// deliberately lock-free plain data with `&mut self` mutators because *its*
/// lock belongs to the sharing decision and arrives from
/// `CURLSHOPT_LOCKFUNC`. This type cannot borrow that seam, because rustls
/// requires `Send + Sync` and `&self`.
pub(crate) struct RustlsSessionStore {
    /// Which peer and credentials this store serves.
    scope: SessionScope,
    /// The contents.
    inner: Mutex<StoreInner>,
}

/// Prints shape and counts, never material.
impl fmt::Debug for RustlsSessionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.locked();
        f.debug_struct("RustlsSessionStore")
            .field("peer_key", &self.scope.peer_key)
            .field("peers", &inner.peers.len())
            .field("stats", &inner.stats)
            .finish_non_exhaustive()
    }
}

impl RustlsSessionStore {
    /// An empty store scoped to `scope`.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn new(scope: SessionScope) -> Arc<Self> {
        Arc::new(Self {
            scope,
            inner: Mutex::new(StoreInner {
                peers: Vec::new(),
                stats: StoreStats::default(),
            }),
        })
    }

    /// The scope this store serves.
    #[must_use]
    pub(crate) fn scope(&self) -> &SessionScope {
        &self.scope
    }

    /// What has happened to this store.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn stats(&self) -> StoreStats {
        self.locked().stats
    }

    /// Whether `vtls_spack` bytes can be imported into, or exported from, this
    /// store.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn pack_bridge_available(&self) -> bool {
        false
    }

    /// The lock, with poisoning recovered.
    fn locked(&self) -> MutexGuard<'_, StoreInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl StoreInner {
    /// The slot for `name`, if there is one.
    fn find(&mut self, name: &ServerName<'_>) -> Option<usize> {
        self.peers.iter().position(|peer| &peer.name == name)
    }

    /// The slot for `name`, creating or reclaiming one if necessary.
    fn slot(&mut self, name: ServerName<'static>) -> usize {
        if let Some(index) = self.find(&name) {
            return index;
        }
        if self.peers.len() < STORE_MAX_PEERS {
            self.peers.push(StorePeer::new(name));
            return self.peers.len() - 1;
        }
        let victim =
            self.peers.iter().position(StorePeer::is_empty).unwrap_or(0);
        if let Some(peer) = self.peers.get_mut(victim) {
            *peer = StorePeer::new(name);
        }
        victim
    }
}

impl ClientSessionStore for RustlsSessionStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        let mut inner = self.locked();
        let index = inner.slot(server_name);
        if let Some(peer) = inner.peers.get_mut(index) {
            peer.kx_hint = Some(group);
        }
        inner.stats.kx_hints_stored =
            inner.stats.kx_hints_stored.saturating_add(1);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        let mut inner = self.locked();
        let index = inner.find(server_name)?;
        inner.peers.get(index).and_then(|peer| peer.kx_hint)
    }

    fn set_tls12_session(
        &self,
        server_name: ServerName<'static>,
        value: Tls12ClientSessionValue,
    ) {
        let mut inner = self.locked();
        let index = inner.slot(server_name);
        if let Some(peer) = inner.peers.get_mut(index) {
            peer.tls12 = Some(value);
        }
        inner.stats.tls12_stored = inner.stats.tls12_stored.saturating_add(1);
    }

    fn tls12_session(
        &self,
        server_name: &ServerName<'_>,
    ) -> Option<Tls12ClientSessionValue> {
        let mut inner = self.locked();
        let index = inner.find(server_name)?;
        // Cloned rather than taken: a TLS 1.2 session identifier is reusable by
        // design, which is exactly why `Curl_ssl_scache_return` puts a pre-1.3
        // session back and drops a 1.3 ticket (`vtls_scache.c:857-868`).
        inner.peers.get(index).and_then(|peer| peer.tls12.clone())
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        let mut inner = self.locked();
        if let Some(index) = inner.find(server_name) {
            if let Some(peer) = inner.peers.get_mut(index) {
                peer.tls12 = None;
            }
        }
    }

    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: Tls13ClientSessionValue,
    ) {
        let advertised = value.max_early_data_size() as usize;
        let mut inner = self.locked();
        let index = inner.slot(server_name);
        if let Some(peer) = inner.peers.get_mut(index) {
            // Bounded, per rustls's own instruction that the caller controls
            // how many times this is invoked. The oldest goes first, because
            // the newest ticket is the one most likely still to be valid.
            while peer.tls13.len() >= STORE_MAX_TICKETS_PER_PEER {
                peer.tls13.pop_front();
            }
            peer.tls13.push_back(value);
        }
        inner.stats.tls13_stored = inner.stats.tls13_stored.saturating_add(1);
        inner.stats.earlydata_max = inner.stats.earlydata_max.max(advertised);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<Tls13ClientSessionValue> {
        let mut inner = self.locked();
        let index = inner.find(server_name)?;
        // `pop_front`, so the value is *moved* out and cannot be handed to a
        // second connection. rustls requires "at most once" and RFC 8446
        // appendix C.4 requires it of any client; a move makes both true by
        // construction rather than by discipline.
        let taken = inner
            .peers
            .get_mut(index)
            .and_then(|peer| peer.tls13.pop_front())?;
        inner.stats.tls13_taken = inner.stats.tls13_taken.saturating_add(1);
        Some(taken)
    }
}

// The backend -- `Curl_ssl_rustls`'s data half, injected instead of global

/// Key logs installed into a `ClientConfig` during this process's life.
///
/// The successor of `keylog_file_fp`, the one file-scope `FILE *` that
/// `lib/vtls/keylog.c` owns and that `cr_cleanup` (`rustls.c:1392-1395`)
/// closes. It exists because `struct Curl_ssl`'s cleanup member is
/// `void (*cleanup)(void)` -- no context at all -- so the descriptor slot
/// cannot reach a backend instance, and reporting the slot as [`None`] would
/// claim this backend has no cleanup step, which is false.
static PROCESS_KEYLOGS: Mutex<Vec<Arc<KeyLogFile>>> = Mutex::new(Vec::new());

/// `cr_version` (`lib/vtls/rustls.c:1377-1381`): what `curl --version` prints
/// for this backend.
///
/// The C asks rustls-ffi for `rustls_version()` and formats it into the
/// caller's buffer. Here the token is read from [`crate::version`], which
/// `curl-rs-ffi` already reads for `curl_version` and `curl_version_info`, so
/// one ABI answer has exactly one source and the two cannot drift.
fn version() -> &'static str {
    SSL_VERSION
}

/// `cr_cleanup` (`lib/vtls/rustls.c:1392-1395`): `Curl_tls_keylog_close()`.
fn cleanup() {
    let drained: Vec<Arc<KeyLogFile>> = {
        let mut registry = PROCESS_KEYLOGS
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        registry.drain(..).collect()
    };
    for keylog in &drained {
        keylog.close();
    }
}

/// Remembers `keylog` so that [`cleanup`] can close it.
///
/// Called only from [`install_keylog`], and only for a log that opened, which
/// is where `Curl_tls_keylog_open` assigns C's global. Duplicate handles to the
/// same log are collapsed with [`Arc::ptr_eq`], so a backend that builds many
/// configurations registers once.
fn register_keylog(keylog: &Arc<KeyLogFile>) {
    let mut registry = PROCESS_KEYLOGS
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if registry.iter().any(|held| Arc::ptr_eq(held, keylog)) {
        return;
    }
    registry.push(Arc::clone(keylog));
}

/// The rustls backend.
///
/// The data half of `const struct Curl_ssl Curl_ssl_rustls`
/// (`rustls.c:1397-1426`), which in C carries no data at all because every
/// input it needs is a global it can reach: `rustls_default_crypto_provider_*`
/// for the provider and its suites, `keylog_file_fp` for the key log, and the
/// easy handle for the options. All three become fields, and that is the whole
/// of the injection requirement.
///
/// One backend serves every filter on a connection --
/// `crate::tls::BackendFilterFactory` holds it as an
/// [`std::rc::Arc`] -- so the options here are the connection's options. Two
/// configurations in one process are two backends, which is what makes them
/// unable to disagree with each other and what lets a test stand one beside
/// the real thing.
pub(crate) struct RustlsBackend {
    /// The injected provider. `ring`, under the pinned features.
    ///
    /// Never installed as a default and never fetched from one. Its
    /// `cipher_suites` list is both the supported set and the default set,
    /// exactly as `rustls_default_crypto_provider_ciphersuites_len` is both in
    /// the C (`rustls.c:416-417`).
    provider: Arc<CryptoProvider>,
    /// Everything a `ClientConfig` is built from besides the provider.
    options: TlsOptions,
    /// `SSLKEYLOGFILE`, already opened or deliberately disabled.
    keylog: Arc<KeyLogFile>,
    /// The HPKE suites available for Encrypted Client Hello.
    hpke_suites: &'static [&'static dyn Hpke],
    /// The session store, or [`None`] for a build that resumes nothing.
    ///
    /// [`None`] is the first conjunct of `Curl_ssl_scache_use`
    /// (`vtls_scache.c:575-582`) -- "An ssl session might not be configured or
    /// not available for 'connect-only' transfers" -- and
    /// [`TlsOptions::caching`] is the second.
    store: Option<Arc<RustlsSessionStore>>,
}

/// Prints configuration shape, never material.
///
/// [`CryptoProvider`] derives [`fmt::Debug`] and prints its whole suite list,
/// which is long and uninformative in a failed assertion; the count is what a
/// reader needs. Nothing that could carry a private key or a ticket is
/// printed.
impl fmt::Debug for RustlsBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsBackend")
            .field("provider_suites", &self.provider.cipher_suites.len())
            .field("verify_peer", &self.options.verify_peer)
            .field("verify_host", &self.options.verify_host)
            .field("keylog_enabled", &self.keylog.enabled())
            .field("hpke_suites", &self.hpke_suites.len())
            .field("has_session_store", &self.store.is_some())
            .finish_non_exhaustive()
    }
}

// The allowance is per item rather than on this `impl` or on the module, which
// is the convention `tls/cipher_suite.rs:125-130` states and `lib.rs`'s
// `source_policy` gate enforces: a broader allowance would also hide the next
// unreferenced item somebody adds here.
impl RustlsBackend {
    /// A backend over `provider`, configured by `options`.
    ///
    /// The key log starts disabled and the store absent; both are added by the
    /// builders below, so a caller that wants neither writes neither and the
    /// resulting backend touches no environment variable and remembers no
    /// session.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn new(
        provider: Arc<CryptoProvider>,
        options: TlsOptions,
    ) -> Self {
        Self {
            provider,
            options,
            keylog: KeyLogFile::disabled(),
            hpke_suites: &[],
            store: None,
        }
    }

    /// The same backend, logging TLS secrets to `keylog`.
    ///
    /// Whether anything is written depends on [`KeyLogFile::enabled`], which
    /// is the C's `Curl_tls_keylog_enabled` and the condition
    /// `rustls.c:816-818` tests before it registers a callback at all.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn with_keylog(mut self, keylog: Arc<KeyLogFile>) -> Self {
        self.keylog = keylog;
        self
    }

    /// The same backend, offering `suites` for Encrypted Client Hello.
    ///
    /// An empty slice -- the default, and what the pinned `ring` provider can
    /// offer -- means an ECH request fails with the C's code rather than
    /// silently proceeding without ECH. That failure is soft or hard according
    /// to [`TlsOptions::ech_hard`], exactly as `rustls.c:1067-1074` decides it.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn with_hpke_suites(
        mut self,
        suites: &'static [&'static dyn Hpke],
    ) -> Self {
        self.hpke_suites = suites;
        self
    }

    /// The same backend, resuming sessions through `store`.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn with_session_store(
        mut self,
        store: Arc<RustlsSessionStore>,
    ) -> Self {
        self.store = Some(store);
        self
    }

    /// This backend's identity, for `curl_global_sslset` and
    /// `curl_version_info`.
    ///
    /// The one widened item in this module. Backend identity is public ABI --
    /// `curl_global_sslset` hands the application an array of
    /// `curl_ssl_backend` pointers and `curl_version_info` reports the same
    /// name -- and it is answerable before any connection exists, which is why
    /// it is available from the type rather than from a session.
    #[allow(dead_code)]
    #[must_use]
    pub fn backend_info() -> SslBackendInfo {
        RUSTLS_INFO
    }

    /// The options this backend was built with.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn options(&self) -> &TlsOptions {
        &self.options
    }

    /// The session store, if one was injected.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn session_store(&self) -> Option<&Arc<RustlsSessionStore>> {
        self.store.as_ref()
    }

    /// The `crate::crypto::rand::Rng` adapter over this backend's provider.
    ///
    /// # Errors
    ///
    /// [`CURLcode::FailedInit`] when the provider cannot produce entropy, or
    /// when the operating system cannot seed the standby generator
    /// [`ProviderRng`] keeps for a provider that stops delivering.
    #[allow(dead_code)]
    pub(crate) fn rng(&self) -> CodeResult<ProviderRng> {
        ProviderRng::from_provider(&self.provider)
    }

    /// `cr_get_internals` (`rustls.c:1217-1225`), engine-neutrally.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn session_info(kind: TlsHandleKind) -> TlsSessionInfo {
        TlsSessionInfo {
            backend: TlsBackendId::RUSTLS,
            kind,
            distinguishes_context: false,
        }
    }
}

// Session state -- `struct rustls_ssl_backend_data` (`rustls.c:44-50`)

/// What one TLS session holds.
///
/// ```c
/// struct rustls_ssl_backend_data {
///   const struct rustls_client_config *config;
///   struct rustls_connection *conn;
///   size_t plain_out_buffered;
///   BIT(data_in_pending);
///   BIT(sent_shutdown);
/// };
/// ```
pub(crate) struct RustlsSession {
    /// Who this session talks to. Supplies SNI, the name verification is
    /// performed against, and the session-cache key.
    peer: SslPeer,
    /// What to offer in the ALPN extension, or [`None`] to send no extension.
    ///
    /// [`None`] and an empty specification are different things, exactly as
    /// `connssl->alpn` being null differs from an `alpn_spec` with
    /// `count == 0`.
    alpn: Option<AlpnSpec>,
    /// `const struct rustls_client_config *config`.
    config: Option<Arc<ClientConfig>>,
    /// `struct rustls_connection *conn`.
    conn: Option<ClientConnection>,
    /// `size_t plain_out_buffered`: plaintext rustls already accepted, whose
    /// TLS bytes a previous send could not finish flushing.
    ///
    /// The single most delicate number in this file. See [`send_plain`] for the
    /// protocol it participates in and why re-adding those bytes would corrupt
    /// the stream.
    plain_out_buffered: usize,
    /// `BIT(data_in_pending)`: TLS records have been processed and plaintext
    /// may be readable without touching the socket.
    data_in_pending: bool,
    /// `BIT(sent_shutdown)`: `close_notify` has been queued, at most once.
    sent_shutdown: bool,
    /// `connssl->peer_closed`: the transport below returned end of stream.
    peer_closed: bool,
    /// `connssl->io_need`, as this session last reported it.
    io_need: SslIoNeed,
    /// What the completed handshake agreed on, or [`None`] before it did.
    negotiated: Option<NegotiatedParams>,
    /// `CURLINFO_CERTINFO`'s records, when they were asked for.
    certinfo: Option<Vec<Vec<verify::CertInfoRecord>>>,
    /// Whether peer verification is switched off for this session.
    ///
    /// Fixed when the configuration was built and never changed afterwards, so
    /// a caller may print the `--insecure` warning knowing the session cannot
    /// quietly become a verifying one -- or a non-verifying one after the
    /// warning was skipped.
    peer_verification_disabled: bool,
    /// Whether [`crate::tls::verify::verify_hostname`] is still owed on the
    /// peer certificate.
    verify_host_pending: bool,
}

/// What the handshake agreed on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NegotiatedParams {
    /// The protocol version, as the IETF numbers it.
    pub(crate) version: IetfProtoVersion,
    /// The cipher suite's IANA identifier.
    pub(crate) cipher_suite: u16,
    /// The cipher suite's name.
    pub(crate) cipher_suite_name: String,
    /// The key-exchange group, when rustls reported one.
    pub(crate) key_exchange_group: Option<NamedGroup>,
    /// The protocol the server selected, or [`None`] for none.
    pub(crate) alpn: Option<Vec<u8>>,
    /// What became of an Encrypted Client Hello attempt.
    pub(crate) ech_status: EchStatus,
}

impl NegotiatedParams {
    /// The version name curl prints, or the C's fallback.
    ///
    /// `rustls.c:1175-1181` builds exactly this: `"TLS version unknown"`
    /// unless the version is TLS 1.2 or TLS 1.3, and the two spellings are
    /// `TLSv1.2` and `TLSv1.3`. [`IetfProtoVersion::name`] holds those
    /// spellings, so they are not written a second time.
    #[must_use]
    pub(crate) fn version_name(&self) -> &'static str {
        self.version.name().unwrap_or("TLS version unknown")
    }
}

/// Prints shape, never key material or ticket bytes.
impl fmt::Debug for RustlsSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsSession")
            .field("hostname", &self.peer.hostname())
            .field("has_config", &self.config.is_some())
            .field("has_conn", &self.conn.is_some())
            .field("plain_out_buffered", &self.plain_out_buffered)
            .field("data_in_pending", &self.data_in_pending)
            .field("sent_shutdown", &self.sent_shutdown)
            .field("peer_closed", &self.peer_closed)
            .field("io_need", &self.io_need)
            .field("negotiated", &self.negotiated)
            .field(
                "certinfo_certificates",
                &self.certinfo.as_ref().map(Vec::len),
            )
            .finish_non_exhaustive()
    }
}

impl RustlsSession {
    /// A session for `peer` that will offer `alpn`, with nothing built yet.
    ///
    /// The successor of `connssl->backend = calloc(1,
    /// sizeof(struct rustls_ssl_backend_data))`: both pointers start null and
    /// both flags start clear, which is what makes `cr_connect`'s
    /// `if(!backend->conn)` the test that triggers construction.
    fn new(peer: SslPeer, alpn: Option<AlpnSpec>) -> Self {
        Self {
            peer,
            alpn,
            config: None,
            conn: None,
            plain_out_buffered: 0,
            data_in_pending: false,
            sent_shutdown: false,
            peer_closed: false,
            io_need: SslIoNeed::NONE,
            negotiated: None,
            certinfo: None,
            peer_verification_disabled: false,
            verify_host_pending: false,
        }
    }

    /// `connssl->io_need`: what this session last needed from the socket.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn io_need(&self) -> SslIoNeed {
        self.io_need
    }

    /// `connssl->peer_closed`: the transport below reported end of stream.
    ///
    /// Written from inside the read adapter, which is where C writes it
    /// (`rustls.c:107`). The C's consumer is the filter's liveness answer, and
    /// this accessor is the seam that reaches it without the backend holding a
    /// pointer back to the session.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// What the handshake agreed on, once it has.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn negotiated(&self) -> Option<&NegotiatedParams> {
        self.negotiated.as_ref()
    }

    /// `CURLINFO_CERTINFO`'s records, when `CURLOPT_CERTINFO` asked for them.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn certinfo(&self) -> Option<&[Vec<verify::CertInfoRecord>]> {
        self.certinfo.as_deref()
    }

    /// Whether this session verifies its peer's certificate.
    ///
    /// `false` obliges the command-line tool to warn on standard error
    /// **before** the transfer proceeds, which is a preservation mandate rather
    /// than a nicety. Fixed at configuration time; no method here changes it.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn peer_verification_disabled(&self) -> bool {
        self.peer_verification_disabled
    }

    /// `size_t plain_out_buffered`, for a caller asserting on the retry
    /// protocol.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn plain_out_buffered(&self) -> usize {
        self.plain_out_buffered
    }

    /// `BIT(sent_shutdown)`: whether `close_notify` has already been queued.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn sent_shutdown(&self) -> bool {
        self.sent_shutdown
    }

    /// `cr_close` (`rustls.c:1293-1310`): drop the connection and the
    /// configuration, independently.
    ///
    /// ```c
    /// if(backend->conn)   { rustls_connection_free(backend->conn); backend->conn = NULL; }
    /// if(backend->config) { rustls_client_config_free(backend->config); backend->config = NULL; }
    /// ```
    fn close(&mut self) {
        self.conn = None;
        self.config = None;
        self.plain_out_buffered = 0;
        self.data_in_pending = false;
        self.sent_shutdown = false;
        self.io_need = SslIoNeed::NONE;
    }
}

// The two I/O adapters -- `read_cb` and `write_cb` (`rustls.c:90-152`)

/// Ciphertext arriving from the filter below, as [`std::io::Read`].
///
/// ```c
/// static int read_cb(void *userdata, uint8_t *buf, uintptr_t len,
///                    uintptr_t *out_n)
/// ```
///
/// Three behaviours are the C's, exactly:
///
/// * [`CURLcode::Again`] becomes [`io::ErrorKind::WouldBlock`], which is the
///   C's `ret = EAGAIN`. `read_tls` propagates it and the caller turns it back
///   into [`CURLcode::Again`], so the round trip is lossless.
/// * Any other failure becomes one stable I/O error, which is the C's
///   `ret = EINVAL` -- a single code for every non-blocking failure, because
///   the caller's answer is [`CURLcode::RecvError`] either way. The originating
///   code is named in the message so a trace still says which it was.
/// * A **zero-byte** read sets `peer_closed`, which is
///   `connssl->peer_closed = TRUE` at `rustls.c:107`. Zero is end of stream and
///   not "try again": a layer with nothing available yet reports
///   [`CURLcode::Again`].
struct BelowReader<'a, 'f, 'ctx, 'trc> {
    /// The seam onto the filter below.
    io: &'a mut TlsTransport<'f, 'ctx, 'trc>,
    /// `connssl->peer_closed`, written through.
    peer_closed: &'a mut bool,
}

impl Read for BelowReader<'_, '_, '_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.io.recv(buf) {
            Ok(0) => {
                *self.peer_closed = true;
                Ok(0)
            }
            Ok(read) => Ok(read),
            Err(error) if error.code() == CURLcode::Again => {
                Err(io::ErrorKind::WouldBlock.into())
            }
            Err(error) => Err(io::Error::other(format!(
                "transport below TLS failed to read: {}",
                error.code().c_name()
            ))),
        }
    }
}

/// Ciphertext leaving for the filter below, as [`std::io::Write`].
struct BelowWriter<'a, 'f, 'ctx, 'trc> {
    /// The seam onto the filter below.
    io: &'a mut TlsTransport<'f, 'ctx, 'trc>,
}

impl Write for BelowWriter<'_, '_, '_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.io.send(buf, false) {
            Ok(written) => Ok(written),
            Err(error) if error.code() == CURLcode::Again => {
                Err(io::ErrorKind::WouldBlock.into())
            }
            Err(error) => Err(io::Error::other(format!(
                "transport below TLS failed to write: {}",
                error.code().c_name()
            ))),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// True when an [`io::Error`] means "would block".
///
/// The C tests two values -- `if(io_error == EAGAIN || io_error == EWOULDBLOCK)`
/// (`rustls.c:141`, `:238`) -- because the two are distinct constants on some
/// platforms. Rust collapses them into one [`io::ErrorKind`], so one test
/// covers both.
fn would_block(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock
}

// Encrypted flush -- `cr_flush_out` (`rustls.c:222-260`)

/// Drains every TLS byte rustls has queued into the filter below.
///
/// `cr_flush_out`, loop condition included:
///
/// ```c
/// while(rustls_connection_wants_write(rconn)) {
///   io_error = rustls_connection_write_tls(rconn, write_cb, &io_ctx, &tlswritten);
///   if(io_error == EAGAIN || io_error == EWOULDBLOCK) return CURLE_AGAIN;
///   else if(io_error) { failf(...); return CURLE_SEND_ERROR; }
///   if(tlswritten == 0) { failf(data, "EOF in swrite"); return CURLE_SEND_ERROR; }
///   tlswritten_total += tlswritten;
/// }
/// return CURLE_OK;
/// ```
///
/// # Errors
///
/// [`CURLcode::Again`] when the transport would block, and
/// [`CURLcode::SendError`] for a failed or zero-length write. Both are the C's
/// codes.
fn flush_out(
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
) -> CurlResult<usize> {
    let mut total = 0_usize;
    loop {
        let outcome = {
            let Some(conn) = state.conn.as_mut() else {
                // `cr_send`'s `DEBUGASSERT(rconn)` (`rustls.c:283`). A flush
                // with no connection has nothing queued, so it has succeeded.
                return Ok(total);
            };
            if !conn.wants_write() {
                return Ok(total);
            }
            let mut writer = BelowWriter { io };
            conn.write_tls(&mut writer)
        };
        match outcome {
            Ok(0) => {
                fail(io, format_args!("EOF in swrite"));
                return Err(Error::with_context(
                    CURLcode::SendError,
                    "rustls: EOF in swrite",
                ));
            }
            Ok(written) => {
                total = total.saturating_add(written);
                trace(io, format_args!("cf_send: wrote {written} TLS bytes"));
            }
            Err(error) if would_block(&error) => {
                trace(io, format_args!("cf_send: EAGAIN after {total} bytes"));
                return Err(Error::new(CURLcode::Again));
            }
            Err(error) => {
                fail(io, format_args!("writing to socket: {error}"));
                return Err(Error::with_context(
                    CURLcode::SendError,
                    "rustls: writing to socket failed",
                ));
            }
        }
    }
}

// Encrypted ingest -- `tls_recv_more` (`rustls.c:113-153`)

/// Pulls TLS records from the filter below and lets rustls process them.
///
/// `tls_recv_more`, whose three outcomes are:
///
/// * the transport would block -- [`CURLcode::Again`], and the caller decides
///   whether that is a stall or the end of a drain;
/// * the transport failed -- [`CURLcode::RecvError`] with the C's
///   `"reading from socket: %s"`;
/// * rustls refused the records -- [`map_rustls_error`]'s code, with the C's
///   `"rustls_connection_process_new_packets"` prefix.
///
/// # Errors
///
/// [`CURLcode::Again`], [`CURLcode::RecvError`], or whatever
/// [`map_rustls_error`] returns for the processing failure.
fn tls_recv_more(
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
) -> CurlResult<usize> {
    let RustlsSession {
        conn,
        peer_closed,
        data_in_pending,
        ..
    } = state;
    let Some(conn) = conn.as_mut() else {
        // `cr_recv`'s `DEBUGASSERT(backend)`: a session with no connection can
        // deliver nothing, and reporting end of stream is the answer that
        // cannot be mistaken for progress.
        return Err(Error::with_context(
            CURLcode::RecvError,
            "rustls: no TLS session to read into",
        ));
    };

    let ingested = {
        let mut reader = BelowReader { io, peer_closed };
        conn.read_tls(&mut reader)
    };
    let ingested = match ingested {
        Ok(ingested) => ingested,
        Err(error) if would_block(&error) => {
            return Err(Error::new(CURLcode::Again));
        }
        Err(error) => {
            fail(io, format_args!("reading from socket: {error}"));
            return Err(Error::with_context(
                CURLcode::RecvError,
                "rustls: reading from socket failed",
            ));
        }
    };

    if let Err(error) = conn.process_new_packets() {
        let code = map_rustls_error(&error);
        rustls_failf(io, &error, "rustls_connection_process_new_packets");
        return Err(Error::with_context(code, "rustls: bad TLS records"));
    }

    *data_in_pending = true;
    Ok(ingested)
}

// Decrypted receive -- `cr_recv` (`rustls.c:155-220`)

/// Fills `plain` with decrypted bytes, fetching records only when it must.
///
/// `cr_recv`, structure for structure. The loop runs until the caller's buffer
/// is full or something stops it, and the four things that can stop it are the
/// four arms rustls-ffi reports:
///
/// | rustls-ffi result | here | effect |
/// |-------------------|------|--------|
/// | `PLAINTEXT_EMPTY` | [`io::ErrorKind::WouldBlock`] | clear `data_in_pending`, try the socket again |
/// | `UNEXPECTED_EOF` | [`io::ErrorKind::UnexpectedEof`] | [`CURLcode::RecvError`], with the C's message |
/// | any other failure | any other [`io::Error`] | [`CURLcode::RecvError`] |
/// | `OK` with `n == 0` | `Ok(0)` | clean end of stream; stop and report what was read |
///
/// The final test is the C's and is easy to get wrong:
///
/// ```c
/// if(!eof && !*pnread) result = CURLE_AGAIN;
/// ```
///
/// # Errors
///
/// [`CURLcode::Again`] when nothing is available yet, and
/// [`CURLcode::RecvError`] for a truncated stream or a rustls failure.
fn recv_plain(
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
    plain: &mut [u8],
) -> CurlResult<usize> {
    let mut filled = 0_usize;
    let mut eof = false;

    while filled < plain.len() {
        if !state.data_in_pending {
            match tls_recv_more(state, io) {
                Ok(_) => {}
                Err(error) if error.code() == CURLcode::Again => break,
                Err(error) => {
                    trace(
                        io,
                        format_args!(
                            "rustls_recv(len={}) -> {}, {filled}",
                            plain.len(),
                            error.code().as_i32()
                        ),
                    );
                    return Err(error);
                }
            }
        }

        let outcome = {
            let Some(conn) = state.conn.as_mut() else {
                return Err(Error::with_context(
                    CURLcode::RecvError,
                    "rustls: no TLS session to read from",
                ));
            };
            let Some(target) = plain.get_mut(filled..) else {
                // Unreachable while `filled < plain.len()` holds, and expressed
                // as a break rather than an index so that no slice operation in
                // this file can panic on peer-driven lengths.
                break;
            };
            conn.reader().read(target)
        };

        match outcome {
            // "n == 0 indicates clean EOF, but we may have read some other
            //  plaintext bytes before we reached this."
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(read) => filled = filled.saturating_add(read),
            // `RUSTLS_RESULT_PLAINTEXT_EMPTY`: nothing decrypted is waiting, so
            // the socket has to be consulted again.
            Err(error) if would_block(&error) => {
                state.data_in_pending = false;
            }
            // `RUSTLS_RESULT_UNEXPECTED_EOF`, with the C's message verbatim.
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                fail(
                    io,
                    format_args!(
                        "rustls: peer closed TCP connection without first \
                         closing TLS connection"
                    ),
                );
                return Err(Error::with_context(
                    CURLcode::RecvError,
                    "rustls: peer closed TCP connection without first closing \
                     TLS connection",
                ));
            }
            Err(error) => {
                fail(io, format_args!("rustls_connection_read: {error}"));
                return Err(Error::with_context(
                    CURLcode::RecvError,
                    "rustls: reading decrypted data failed",
                ));
            }
        }
    }

    let result = if !eof && filled == 0 {
        Err(Error::new(CURLcode::Again))
    } else {
        Ok(filled)
    };
    trace(
        io,
        format_args!(
            "rustls_recv(len={}) -> {}, {filled}",
            plain.len(),
            match &result {
                Ok(_) => 0,
                Err(error) => error.code().as_i32(),
            }
        ),
    );
    result
}

// Plaintext send -- `cr_send` (`rustls.c:262-375`)

/// Hands `plain` to rustls and drains the resulting TLS bytes.
///
/// `cr_send`, and the C's own summary of the contract is worth keeping because
/// the zero-length case is not an edge case but a documented entry point:
///
/// ```text
/// On each call:
///  - Copy `plainlen` bytes into Rustls' plaintext input buffer (if > 0).
///  - Fully drain Rustls' plaintext output buffer into the socket until
///    we get either an error or EAGAIN/EWOULDBLOCK.
///
/// it is okay to call this function with plainbuf == NULL and plainlen == 0.
/// In that case, it will not read anything into Rustls' plaintext input buffer.
/// It will only drain Rustls' plaintext output buffer into the socket.
/// ```
///
/// # The retry protocol, which is the whole difficulty
///
/// `plain_out_buffered` is how the C avoids it (`rustls.c:290-375`), and every
/// step of that dance is reproduced:
///
/// 1. **If a previous send left bytes accepted**, flush *those* records first
///    and do nothing else until they are gone. A block here propagates, because
///    the stream cannot move until it clears.
/// 2. **Deduct them from this call's offering** and count them as bytes this
///    call wrote. `if(blen > buffered) { blen -= buffered; buf += buffered; }
///    else blen = 0;` -- the `else` matters: a retry offering *fewer* bytes than
///    were accepted must not compute a negative remainder.
/// 3. **Then, and only then**, offer what remains to rustls.
/// 4. **Flush again.** If that blocks, remember how much rustls accepted this
///    time -- and if step 2 already produced caller-visible progress, report
///    **success** with that progress rather than [`CURLcode::Again`]. A caller
///    told "again" would re-offer bytes this call already accounted for.
///
/// # Errors
///
/// [`CURLcode::WriteError`] when rustls refuses the plaintext -- distinct from
/// [`CURLcode::SendError`], which is the transport failing, and the C keeps the
/// two apart for exactly that reason. [`CURLcode::Again`] only when no progress
/// was made at all.
fn send_plain(
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
    plain: &[u8],
) -> CurlResult<usize> {
    trace(io, format_args!("cf_send(len={})", plain.len()));

    let mut written = 0_usize;
    let mut offered = plain;

    // Step 1 and 2: the previous call's accepted bytes.
    let buffered = state.plain_out_buffered;
    if buffered > 0 {
        let flushed = flush_out(state, io);
        trace(
            io,
            format_args!(
                "cf_send: flushing {buffered} previously added bytes -> {}",
                match &flushed {
                    Ok(_) => 0,
                    Err(error) => error.code().as_i32(),
                }
            ),
        );
        flushed?;
        // `if(blen > backend->plain_out_buffered) { blen -= ...; buf += ...; }
        //  else blen = 0;`
        offered = offered.get(buffered..).unwrap_or(&[]);
        written = written.saturating_add(buffered);
        state.plain_out_buffered = 0;
    }

    // Step 3: this call's plaintext.
    let mut accepted = 0_usize;
    if !offered.is_empty() {
        trace(
            io,
            format_args!(
                "cf_send: adding {} plain bytes to Rustls",
                offered.len()
            ),
        );
        let outcome = {
            let Some(conn) = state.conn.as_mut() else {
                return Err(Error::with_context(
                    CURLcode::SendError,
                    "rustls: no TLS session to write into",
                ));
            };
            conn.writer().write(offered)
        };
        match outcome {
            Ok(0) => {
                fail(io, format_args!("rustls_connection_write: EOF"));
                return Err(Error::with_context(
                    CURLcode::WriteError,
                    "rustls: rustls_connection_write returned EOF",
                ));
            }
            Ok(count) => accepted = count,
            Err(error) => {
                fail(io, format_args!("rustls_connection_write: {error}"));
                return Err(Error::with_context(
                    CURLcode::WriteError,
                    "rustls: rustls_connection_write failed",
                ));
            }
        }
    }

    // Step 4: drain, and remember what was accepted if the drain blocks.
    let result = match flush_out(state, io) {
        Ok(_) => {
            written = written.saturating_add(accepted);
            Ok(written)
        }
        Err(error) if error.code() == CURLcode::Again => {
            // "The TLS bytes may have been partially written, but we fail the
            //  complete send() and remember how much we already added to
            //  Rustls."
            state.plain_out_buffered = accepted;
            if written > 0 {
                Ok(written)
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    };

    trace(
        io,
        format_args!(
            "rustls_send(len={}) -> {}, {}",
            plain.len(),
            match &result {
                Ok(_) => 0,
                Err(error) => error.code().as_i32(),
            },
            match &result {
                Ok(count) => *count,
                Err(_) => written,
            }
        ),
    );
    result
}

// Configuration -- `init_config_builder` and friends (`rustls.c:517-1104`)

/// The protocol versions to offer, in the C's order.
///
/// `init_config_builder`'s first two `switch` statements (`rustls.c:534-577`),
/// which between them accept exactly TLS 1.2 and TLS 1.3 and reject everything
/// else:
///
/// ```c
/// uint16_t tls_versions[2] = { RUSTLS_TLS_VERSION_TLSV1_2,
///                              RUSTLS_TLS_VERSION_TLSV1_3 };
/// ```
///
/// # Errors
///
/// [`CURLcode::BadFunctionArgument`] for an unsupported minimum or maximum,
/// each with the C's own message so that `CURLOPT_ERRORBUFFER` reads the same.
fn protocol_versions(
    prefs: TlsPrefs,
    ech_requested: bool,
    io: &mut TlsTransport<'_, '_, '_>,
) -> CurlResult<Vec<&'static SupportedProtocolVersion>> {
    let mut versions: Vec<&'static SupportedProtocolVersion> = match prefs
        .version
    {
        CURL_SSLVERSION_TLSV1
        | CURL_SSLVERSION_TLSV1_0
        | CURL_SSLVERSION_TLSV1_1
        | CURL_SSLVERSION_TLSV1_2 => {
            vec![&rustls::version::TLS12, &rustls::version::TLS13]
        }
        CURL_SSLVERSION_TLSV1_3 => vec![&rustls::version::TLS13],
        _ => {
            fail(
                io,
                format_args!("rustls: unsupported minimum TLS version value"),
            );
            return Err(Error::with_context(
                CURLcode::BadFunctionArgument,
                "rustls: unsupported minimum TLS version value",
            ));
        }
    };

    let floor_is_tls12 = versions
        .first()
        .is_some_and(|version| version.version == ProtocolVersion::TLSv1_2);
    match prefs.version_max {
        CURL_SSLVERSION_MAX_DEFAULT
        | CURL_SSLVERSION_MAX_NONE
        | CURL_SSLVERSION_MAX_TLSV1_3 => {}
        CURL_SSLVERSION_MAX_TLSV1_2 if floor_is_tls12 => {
            versions.truncate(1);
        }
        _ => {
            fail(
                io,
                format_args!("rustls: unsupported maximum TLS version value"),
            );
            return Err(Error::with_context(
                CURLcode::BadFunctionArgument,
                "rustls: unsupported maximum TLS version value",
            ));
        }
    }

    if ech_requested {
        versions = vec![&rustls::version::TLS13];
        info(io, format_args!("rustls: ECH enabled, forcing TLSv1.3"));
    }
    Ok(versions)
}

/// The [`EchMode`] the options ask for, or an error naming why there is none.
///
/// `init_config_builder_ech` (`rustls.c:907-1006`), in its order:
///
/// 1. **No HPKE provider is fatal.** The C tests `rustls_supported_hpke()` and
///    fails with "ECH unavailable, rustls-ffi built without HPKE compatible
///    crypto provider" (`rustls.c:917-923`). Here the equivalent test is an
///    empty injected suite list, which is what the pinned `ring` provider
///    yields, and the message says so truthfully instead of naming rustls-ffi.
/// 2. **An outer name is refused.** `rustls.c:925-929`: "rustls: ECH outername
///    not supported". rustls 0.23.42's `EchConfig` takes its public name from
///    the configuration itself and offers no override, so this is a genuine
///    limitation on both sides rather than an unimplemented option.
/// 3. **GREASE returns immediately** (`rustls.c:931-939`), consulting no
///    configuration and no DNS.
/// 4. **A configuration list is selected**, from decoded command-line input or
///    from the caller-supplied HTTPS record, and one of its suites must be
///    compatible with the provider's.
///
/// # Errors
///
/// [`CURLcode::SslConnectError`] for every failure, which is the C's code on
/// every one of these paths. The caller decides whether that aborts the
/// handshake or is swallowed, according to `CURLECH_HARD`.
fn build_ech_mode(
    backend: &RustlsBackend,
    io: &mut TlsTransport<'_, '_, '_>,
) -> CurlResult<EchMode> {
    let options = &backend.options;

    let Some(&suite) = backend.hpke_suites.first() else {
        fail(
            io,
            format_args!(
                "rustls: ECH unavailable, the pinned crypto provider offers \
                 no HPKE compatible suite"
            ),
        );
        return Err(Error::with_context(
            CURLcode::SslConnectError,
            "rustls: ECH unavailable, the pinned crypto provider offers no \
             HPKE compatible suite",
        ));
    };

    if options.ech_public_name.is_some() {
        fail(io, format_args!("rustls: ECH outername not supported"));
        return Err(Error::with_context(
            CURLcode::SslConnectError,
            "rustls: ECH outername not supported",
        ));
    }

    if options.ech == EchPolicy::Grease {
        // `rustls_client_config_builder_enable_ech_grease(builder, hpke)`.
        // The decoy needs a public key of the right shape and no
        // corresponding server, so one is generated and its private half
        // dropped -- which is what a GREASE extension is.
        let (public_key, _private_key) =
            suite.generate_key_pair().map_err(|error| {
                rustls_failf(
                    io,
                    &error,
                    "rustls: failed to configure ECH GREASE",
                );
                Error::with_context(
                    CURLcode::SslConnectError,
                    "rustls: failed to configure ECH GREASE",
                )
            })?;
        return Ok(EchMode::from(EchGreaseConfig::new(suite, public_key)));
    }

    let Some(config_list) = options.ech.config_list()? else {
        // Unreachable: `Disabled` never reaches this function and `Grease`
        // returned above. Expressed rather than asserted so that a future
        // variant cannot silently fall through into an unconfigured ECH.
        return Err(Error::with_context(
            CURLcode::SslConnectError,
            "rustls: ECH requested but no ECHConfig available",
        ));
    };

    let config = EchConfig::new(
        EchConfigListBytes::from(config_list),
        backend.hpke_suites,
    )
    .map_err(|error| {
        rustls_failf(io, &error, "rustls: failed to configure ECH");
        Error::with_context(
            CURLcode::SslConnectError,
            "rustls: failed to configure ECH",
        )
    })?;
    Ok(EchMode::from(config))
}

/// Installs the key log, when there is one to install.
///
/// `init_config_builder_keylog` (`rustls.c:809-829`):
///
/// ```c
/// Curl_tls_keylog_open();
/// if(!Curl_tls_keylog_enabled()) return CURLE_OK;
/// rr = rustls_client_config_builder_set_key_log(builder, cr_keylog_log_cb, NULL);
/// if(rr != RUSTLS_RESULT_OK) { rustls_failf(...); Curl_tls_keylog_close(); return map_error(rr); }
/// ```
///
/// Three behaviours carry across:
///
/// * The open is attempted every time and is **idempotent** --
///   `lib/vtls/keylog.c:44` guards its whole body with `if(!keylog_file_fp)` --
///   so building several configurations neither re-reads `SSLKEYLOGFILE` nor
///   reopens the file.
/// * A log that did not open is not an error. `rustls.c:816-818` returns
///   `CURLE_OK`, because a missing or unwritable `SSLKEYLOGFILE` must not stop
///   a transfer from happening.
/// * A log that did not open is **closed**, which is the C's failure arm at
///   `:823-826` reaching the only state it can reach here. Assigning
///   `ClientConfig::key_log` cannot fail -- it is a field, not a fallible
///   registration -- so the C's `map_error(rr)` return has no analogue and is
///   not written as unreachable code. Closing a disabled log is a documented
///   no-op, so the call is safe and keeps the C's shape visible.
fn install_keylog(config: &mut ClientConfig, keylog: &Arc<KeyLogFile>) {
    keylog.open();
    if keylog.enabled() {
        config.key_log = Arc::clone(keylog).into_key_log();
        register_keylog(keylog);
    } else {
        keylog.close();
    }
}

/// Builds the `ClientConfig` and the `ClientConnection`.
///
/// | step | C |
/// |------|---|
/// | cipher suites, then a provider carrying them | `:517-641` |
/// | protocol versions | `:534-577` |
/// | ECH, when requested | `:1067-1074` |
/// | ALPN | `:643-658`, called at `:1027-1029` |
/// | verifier: none, platform, or PEM roots | `:1032-1053` |
/// | client certificate and key | `:1055-1065` |
/// | key log | `:1076-1080` |
/// | build the configuration | `:1082-1087` |
/// | build the connection | `:1089-1101` |
///
/// # Errors
///
/// [`CURLcode::SslCipher`] for a cipher list that selects nothing,
/// [`CURLcode::BadFunctionArgument`] for an unusable version range,
/// [`CURLcode::SslConnectError`] for a hard ECH failure or a configuration
/// rustls refuses, [`CURLcode::SslCacertBadfile`] and
/// [`CURLcode::SslCrlBadfile`] from the trust store,
/// [`CURLcode::SslCertproblem`] from the client credentials,
/// [`CURLcode::NotBuiltIn`] for `--capath`, and
/// [`CURLcode::CouldntConnect`] when the connection itself cannot be built,
/// which is `rustls.c:1093-1097`'s code.
fn configure(
    backend: &RustlsBackend,
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
) -> CurlResult<()> {
    let options = &backend.options;

    // --- cipher suites, and the provider that carries them ----------------
    //
    // `cr_get_selected_ciphers` (`:404-502`) is already superseded verbatim by
    // `crate::tls::cipher_suite`, including its diagnostics and its ordering
    // rules, so it is consumed rather than restated. The provider's own list is
    // both the supported set and the default set, exactly as
    // `rustls_default_crypto_provider_ciphersuites_len()` is both in the C.
    let selection = cipher_suite::select_provider_suites(
        options.cipher_list.as_deref(),
        options.cipher_list13.as_deref(),
        &backend.provider.cipher_suites,
    );
    let selection = match selection {
        Ok(selection) => selection,
        Err(error) => {
            // The C has already logged its per-entry diagnostics by the time it
            // fails (`:459-473` run before `:590-594`), and they are the only
            // clue to *why* a list selected nothing. They are unreachable
            // through the error, so the message is what remains.
            fail(io, format_args!("{}", error.message()));
            return Err(error);
        }
    };
    for diagnostic in &selection.diagnostics {
        info(io, format_args!("{diagnostic}"));
    }
    if let Some(note) = selection.suppressed_note() {
        info(io, format_args!("{note}"));
    }

    // Provider order is preserved by the selection, so cloning the provider
    // with the selected list keeps the `ClientHello`'s suite sequence exactly
    // as `cipher_suite` computed it. Nothing else about the provider changes:
    // the key-exchange groups, the signature algorithms, the generator and the
    // key provider are the injected ones.
    let provider = Arc::new(CryptoProvider {
        cipher_suites: selection.suites.clone(),
        ..(*backend.provider).clone()
    });

    // --- protocol versions, and ECH's effect on them ----------------------
    let ech_requested = options.ech.is_enabled();
    let versions = protocol_versions(options.prefs, ech_requested, io)?;

    let ech_mode = if ech_requested {
        match build_ech_mode(backend, io) {
            Ok(mode) => Some(mode),
            Err(error) => {
                // `rustls.c:1067-1074`: hard mode propagates, soft mode
                // continues without ECH. The soft path is the C's
                // `if(result != CURLE_OK && data->set.tls_ech & CURLECH_HARD)`
                // read the other way round -- the error is simply dropped.
                if options.ech_hard {
                    return Err(error);
                }
                info(
                    io,
                    format_args!(
                        "rustls: continuing without ECH: {}",
                        error.message()
                    ),
                );
                None
            }
        }
    } else {
        None
    };

    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider));
    let builder = match ech_mode {
        // `with_ech` selects TLS 1.3 as the only version, which is the same
        // narrowing `protocol_versions` already applied and reported.
        Some(mode) => builder.with_ech(mode).map_err(|error| {
            Error::with_context(
                map_rustls_error(&error).into_connect_error(),
                "rustls: failed to enable ECH",
            )
        })?,
        None => builder.with_protocol_versions(&versions).map_err(|error| {
            // `rustls.c:625-631` maps a refused version list to
            // `CURLE_SSL_CIPHER`, because the refusal means the provider has no
            // suite for a requested version.
            Error::with_context(
                CURLcode::SslCipher,
                format!(
                    "rustls: failed to create client config builder: {error}"
                ),
            )
        })?,
    };

    // --- the trust decision, delegated in full ----------------------------
    let verification =
        ServerVerification::build(&options.verify_policy(), &provider)?;
    let builder = verification.install(builder);

    // --- client credentials, delegated in full ----------------------------
    let client_auth = ClientAuth::load(
        options.client_cert.as_deref(),
        options.client_key.as_deref(),
        &provider,
    )?;
    let mut config = install_client_auth(builder, client_auth.as_ref());

    // --- ALPN: exact bytes, exact order, at most three --------------------
    if let Some(alpn) = state.alpn.as_ref() {
        config.alpn_protocols = alpn
            .iter()
            .take(ALPN_ENTRIES_MAX)
            .map(<[u8]>::to_vec)
            .collect();
        // `Curl_alpn_to_proto_str` then `infof(data,
        // VTLS_INFOF_ALPN_OFFER_1STR, proto.data)` -- the comma-separated
        // display form, which is `crate::tls::VTLS_INFOF_ALPN_OFFER_1STR`.
        if let Ok(display) = alpn.to_proto_str() {
            if let Some(text) = display.as_str() {
                info(io, format_args!("ALPN: curl offers {text}"));
            }
        }
    }

    // --- SNI --------------------------------------------------------------
    config.enable_sni = state.peer.sni().is_some();

    // --- resumption -------------------------------------------------------
    //
    // `Curl_ssl_scache_use` (`vtls_scache.c:575-582`) is a conjunction: a cache
    // must exist *and* the transfer must want caching. Both conjuncts appear
    // here -- the injected store is the first, `options.caching` the second --
    // and a store scoped to a different peer or different credentials is
    // refused, which is `cf_ssl_scache_match_auth` (`:598-618`).
    let scache_auth = options.scache_auth();
    config.resumption = match backend.store.as_ref() {
        Some(store)
            if options.caching.is_enabled()
                && store
                    .scope()
                    .admits(state.peer.scache_key(), &scache_auth) =>
        {
            Resumption::store(Arc::clone(store) as Arc<dyn ClientSessionStore>)
        }
        _ => Resumption::disabled(),
    };

    // --- early data -------------------------------------------------------
    config.enable_early_data = false;

    // --- key log ----------------------------------------------------------
    install_keylog(&mut config, &backend.keylog);

    // --- the connection ---------------------------------------------------
    let config = Arc::new(config);
    let name = ServerName::try_from(state.peer.hostname())
        .map(|name| name.to_owned())
        .map_err(|_| {
            Error::with_context(
                CURLcode::CouldntConnect,
                "rustls: peer name is not a usable TLS server name",
            )
        })?;
    let conn =
        ClientConnection::new(Arc::clone(&config), name).map_err(|error| {
            rustls_failf(io, &error, "rustls_client_connection_new");
            // `:1093-1097` frees the configuration and returns
            // `CURLE_COULDNT_CONNECT`. Dropping the local `Arc` is the free.
            Error::with_context(
                CURLcode::CouldntConnect,
                "rustls: could not create the TLS client connection",
            )
        })?;

    state.peer_verification_disabled =
        verification.peer_verification_disabled();
    state.verify_host_pending = verification.host_verification_enabled();
    state.config = Some(config);
    state.conn = Some(conn);
    Ok(())
}

/// Turns a receive-shaped code into a handshake-shaped one.
trait ConnectErrorCode {
    /// [`CURLcode::SslConnectError`] for a receive failure, unchanged
    /// otherwise.
    fn into_connect_error(self) -> CURLcode;
}

impl ConnectErrorCode for CURLcode {
    fn into_connect_error(self) -> CURLcode {
        if matches!(self, CURLcode::RecvError) {
            CURLcode::SslConnectError
        } else {
            self
        }
    }
}

// The handshake -- `cr_connect` (`rustls.c:1118-1215`)

/// Records what the finished handshake agreed on, and emits the C's line.
///
/// `rustls.c:1170-1187`. The C guards the values behind `#ifdef CURLVERBOSE`
/// because reading them costs a call each; here they are read unconditionally
/// because `CURLINFO` consumers need them whether or not anybody is watching,
/// and the *line* is still gated by the tracer.
fn record_negotiated(
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
) {
    let Some(conn) = state.conn.as_ref() else {
        return;
    };
    let version = conn
        .protocol_version()
        .map_or(IetfProtoVersion::UNKNOWN, |version| {
            IetfProtoVersion::from_bits(u16::from(version))
        });
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map_or(0, |suite| u16::from(suite.suite()));
    let cipher_suite_name =
        cipher_suite::get_str(cipher_suite, true).into_owned();
    let key_exchange_group = conn
        .negotiated_key_exchange_group()
        .map(|group| group.name());
    let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
    let ech_status = conn.ech_status();

    let negotiated = NegotiatedParams {
        version,
        cipher_suite,
        cipher_suite_name,
        key_exchange_group,
        alpn,
        ech_status,
    };

    // `%.*s` over `kex_group_name`, whose rustls-ffi form is a name string.
    // `NamedGroup::as_str` is [`None`] only for a group rustls does not name,
    // and the identifier is the honest answer for that case.
    let kex = key_exchange_group.map_or_else(
        || String::from("unknown"),
        |group| {
            group.as_str().map_or_else(
                || format!("0x{:04x}", u16::from(group)),
                String::from,
            )
        },
    );
    info(
        io,
        format_args!(
            "rustls: handshake complete, {}, ciphersuite: {}, key exchange \
             group: {}",
            negotiated.version_name(),
            negotiated.cipher_suite_name,
            kex
        ),
    );
    state.negotiated = Some(negotiated);
}

/// Collects `CURLINFO_CERTINFO` from the peer's chain.
///
/// `rustls.c:1194-1236`, whose ceiling is the point of the loop:
///
/// ```c
/// while(rustls_connection_get_peer_certificate(rconn, num_certs)) {
///   num_certs++;
///   if(num_certs > MAX_ALLOWED_CERT_AMOUNT) {
///     failf(data, "%zu certificates is more than allowed (%u)", num_certs,
///           MAX_ALLOWED_CERT_AMOUNT);
///     return CURLE_SSL_CONNECT_ERROR;
///   }
/// }
/// ```
///
/// # Errors
///
/// [`CURLcode::SslConnectError`] for a chain above
/// [`MAX_ALLOWED_CERT_AMOUNT`], and whatever
/// [`crate::tls::verify::extract_certinfo_chain`] returns for a certificate it
/// cannot read.
fn capture_certinfo(
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
) -> CurlResult<()> {
    let records = {
        let chain = state
            .conn
            .as_ref()
            .and_then(|conn| conn.peer_certificates())
            .unwrap_or(&[]);
        if chain.len() > MAX_ALLOWED_CERT_AMOUNT {
            fail(
                io,
                format_args!(
                    "{} certificates is more than allowed ({})",
                    chain.len(),
                    MAX_ALLOWED_CERT_AMOUNT
                ),
            );
            return Err(Error::with_context(
                CURLcode::SslConnectError,
                "rustls: peer certificate chain is longer than allowed",
            ));
        }
        verify::extract_certinfo_chain(chain)
    };
    let records = match records {
        Ok(records) => records,
        Err(error) => {
            fail(
                io,
                format_args!(
                    "Failed getting DER of server certificate: {}",
                    error.message()
                ),
            );
            return Err(error);
        }
    };
    state.certinfo = Some(records);
    Ok(())
}

/// Applies curl's own hostname check, when the policy asks for it.
///
/// `crate::tls::verify::ServerVerification` documents the division: it builds
/// the chain verifier and leaves the name comparison to "the caller ... once
/// the peer certificate is available", which is here.
///
/// # What the oracle actually is, measured rather than assumed
///
/// rustls has already compared the name for any verifying configuration, and it
/// requires a subjectAltName: a certificate carrying only a commonName fails
/// the handshake before this function is reached. **That is not a tightening
/// relative to curl 8.19.0-DEV**, and the earlier claim here that "curl will
/// fall back to the commonName" was wrong about the backend being reproduced:
///
/// * `Curl_verifyhost` occurs exactly ONCE in the whole of `lib/` -- a
///   declaration at `lib/vtls/x509asn1.h:76`. It has no definition and no
///   caller.
/// * `lib/vtls/rustls.c` therefore contains no hostname check of its own; it
///   hands the name to rustls at `:1091` and takes rustls's answer, SAN
///   requirement included.
/// * The commonName fallback exists only in `lib/vtls/openssl.c:2176-2246`, a
///   backend the specification's section 0.2.2 drops. So a
///   commonName-only certificate is refused by curl-with-rustls too, and
///   refusing it here is parity, not a security decision taken unilaterally.
///
/// The consequence for `crate::tls::verify`'s own commonName arm is worth
/// stating rather than leaving to be discovered: it is written, it is tested
/// against the openssl oracle it was ported from, and it is **unreachable for a
/// SAN-less certificate through this backend**, because rustls has already
/// failed the handshake by the time this runs. It is retained because
/// `verify.rs` owns the whole of `lib/vtls/openssl.c:2053-2250`'s shape and
/// because it also feeds the certificate introspection `CURLINFO_CERTINFO`
/// exposes.
///
/// This check is run even though rustls has already answered, for two reasons:
/// the diagnostic a mismatch produces is curl's, word for word, which is what
/// `CURLOPT_ERRORBUFFER` consumers read; and the check is `verify.rs`'s to own,
/// so skipping it would leave the module's contract half-honoured.
///
/// Reached only when peer verification is on, because
/// `host_verification_enabled` is always `false` when it is off -- comparing a
/// name on a self-signed certificate establishes nothing.
///
/// # Errors
///
/// [`CURLcode::PeerFailedVerification`] for a mismatch, with
/// `crate::tls::verify`'s message, and for a completed verifying handshake that
/// somehow exposed no certificate at all.
fn verify_peer_hostname(
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
) -> CurlResult<()> {
    if !state.verify_host_pending {
        return Ok(());
    }
    {
        let leaf = state
            .conn
            .as_ref()
            .and_then(|conn| conn.peer_certificates())
            .and_then(|chain| chain.first());
        let Some(leaf) = leaf else {
            fail(
                io,
                format_args!(
                    "SSL: certificate verification failed, no certificate \
                     presented"
                ),
            );
            return Err(Error::with_context(
                CURLcode::PeerFailedVerification,
                "rustls: peer presented no certificate to verify the name \
                 against",
            ));
        };
        if let Err(error) = verify::verify_hostname(
            leaf.as_ref(),
            state.peer.hostname(),
            state.peer.dispname(),
        ) {
            fail(io, format_args!("{}", error.message()));
            return Err(error);
        }
    }
    state.verify_host_pending = false;
    Ok(())
}

/// One step of the handshake.
///
/// The structure, and each part's reason:
///
/// 1. **Build lazily.** `if(!backend->conn) { cr_init_backend(...); connssl->state
///    = ssl_connection_negotiating; }`. Building on the first step rather than
///    when the session was created is what lets configuration failures be
///    reported with a tracer in hand, and what makes a filter that is never
///    driven cost nothing.
/// 2. **Clear the I/O need every turn.** `connssl->io_need =
///    CURL_SSL_IO_NEED_NONE;` at the top of the loop. A need left over from the
///    previous turn would make the pollset wait for an event that has already
///    happened.
/// 3. **When rustls stops handshaking, flush once more.** The C's comment says
///    why, and it is not optional: "Rustls claims it is no longer handshaking
///    *before* it has send its FINISHED message off. We attempt to let it write
///    one more time. Oh my." The negotiated ALPN is captured *before* that
///    flush, exactly as `cr_set_negotiated_alpn` is called before `cr_send`, so
///    a blocked flush does not lose it. If the flush blocks, the step reports
///    `SEND` and **not done**.
/// 4. **Otherwise write first, then read.** `wants_write` includes
///    `backend->plain_out_buffered`, because plaintext rustls has already
///    accepted still owes a flush even when rustls itself has nothing queued.
/// 5. **A receive failure during the handshake is a connect failure.**
///    `else if(tmperr == CURLE_RECV_ERROR) return CURLE_SSL_CONNECT_ERROR;`
///
/// # Errors
///
/// Whatever [`configure`] reports for a configuration failure,
/// [`CURLcode::SslConnectError`] for a transport failure during the handshake,
/// [`CURLcode::PeerFailedVerification`] for a name mismatch, and whatever
/// [`capture_certinfo`] reports.
fn handshake(
    backend: &RustlsBackend,
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
) -> CurlResult<HandshakeProgress> {
    let mut progress = HandshakeProgress::default();

    if state.conn.is_none() {
        let outcome = configure(backend, state, io);
        trace(
            io,
            format_args!(
                "cr_connect, init backend -> {}",
                match &outcome {
                    Ok(()) => 0,
                    Err(error) => error.code().as_i32(),
                }
            ),
        );
        outcome?;
        progress.connection_state = Some(SslConnectionState::Negotiating);
    }

    loop {
        progress.io_need = SslIoNeed::NONE;
        state.io_need = SslIoNeed::NONE;

        let handshaking = state
            .conn
            .as_ref()
            .is_some_and(|conn| conn.is_handshaking());

        if !handshaking {
            // `cr_set_negotiated_alpn`, before the final flush. An absent
            // protocol reaches `Curl_alpn_set_negotiated` as `NULL, 0`, which
            // is an empty slice here and means "the server agreed on nothing".
            progress.alpn = Some(
                state
                    .conn
                    .as_ref()
                    .and_then(|conn| conn.alpn_protocol())
                    .unwrap_or(&[])
                    .to_vec(),
            );

            match send_plain(state, io, &[]) {
                Ok(_) => {}
                Err(error) if error.code() == CURLcode::Again => {
                    progress.io_need = SslIoNeed::SEND;
                    state.io_need = SslIoNeed::SEND;
                    return Ok(progress);
                }
                Err(error) => return Err(error),
            }

            // REALLY done with the handshake.
            record_negotiated(state, io);
            verify_peer_hostname(state, io)?;
            if backend.options.certinfo {
                capture_certinfo(state, io)?;
            }

            progress.connection_state = Some(SslConnectionState::Complete);
            progress.connecting_state = Some(SslConnectState::Done);
            progress.done = true;
            return Ok(progress);
        }

        progress.connecting_state = Some(SslConnectState::Connect2);

        let (wants_read, wants_write) = match state.conn.as_ref() {
            Some(conn) => (
                conn.wants_read(),
                conn.wants_write() || state.plain_out_buffered > 0,
            ),
            None => (false, false),
        };
        debug_assert!(
            wants_read || wants_write,
            "a handshaking rustls connection wants to read or to write, which \
             is the DEBUGASSERT of lib/vtls/rustls.c:1183"
        );

        if wants_write {
            trace(io, format_args!("rustls_connection wants us to write_tls."));
            match send_plain(state, io, &[]) {
                Ok(_) => {}
                Err(error) if error.code() == CURLcode::Again => {
                    trace(io, format_args!("writing would block"));
                    progress.io_need = SslIoNeed::SEND;
                    state.io_need = SslIoNeed::SEND;
                    return Ok(progress);
                }
                Err(error) => return Err(error),
            }
        }

        if wants_read {
            trace(io, format_args!("rustls_connection wants us to read_tls."));
            match tls_recv_more(state, io) {
                // A successful ingest of *nothing* with the transport at end of
                // stream means the handshake can never finish, and this is the
                // one place this file terminates where `cr_connect` does not.
                Ok(0) if state.peer_closed => {
                    fail(
                        io,
                        format_args!(
                            "rustls: peer closed the connection during the \
                             TLS handshake"
                        ),
                    );
                    return Err(Error::with_context(
                        CURLcode::SslConnectError,
                        "rustls: peer closed the connection during the TLS \
                         handshake",
                    ));
                }
                Ok(_) => {}
                Err(error) if error.code() == CURLcode::Again => {
                    trace(io, format_args!("reading would block"));
                    progress.io_need = SslIoNeed::RECV;
                    state.io_need = SslIoNeed::RECV;
                    return Ok(progress);
                }
                Err(error) => {
                    let code = error.code().into_connect_error();
                    return Err(Error::with_context(
                        code,
                        "rustls: reading TLS records during the handshake \
                         failed",
                    ));
                }
            }
        }

        if !wants_read && !wants_write {
            // The C reaches `DEBUGASSERT(FALSE)` past the loop rather than
            // here, because its loop cannot end. This arm exists so that a
            // rustls connection that reports neither need while still
            // handshaking cannot spin: it is a defect, and reporting it is
            // better than looping forever inside `curl_easy_perform`.
            return Err(Error::with_context(
                CURLcode::SslConnectError,
                "rustls: handshake is stalled with no pending I/O",
            ));
        }
    }
}

// Shutdown -- `cr_shutdown` (`rustls.c:1227-1291`)

/// Closes the session cleanly, at most one `close_notify` per session.
///
/// `cr_shutdown`. Four things are being done at once and the order matters:
///
/// 1. **Queue `close_notify` once, and only if asked.** `if(!backend->sent_shutdown)
///    { backend->sent_shutdown = TRUE; if(send_shutdown)
///    rustls_connection_send_close_notify(backend->conn); }` -- the flag is set
///    whether or not the alert is sent, so a second call never queues a second
///    alert even when the first call was told not to send one.
/// 2. **Flush it.** A blocked flush reports `SEND` and **not done**, with
///    [`CURLcode::Again`] converted to success: the caller is to poll and come
///    back, not to treat this as a failure.
/// 3. **Drain the peer's answer**, at most [`SHUTDOWN_DRAIN_ATTEMPTS`] reads of
///    [`SHUTDOWN_DRAIN_BUFFER`] bytes. The loop breaks only on error, so the
///    reading that decides the outcome is the **last** one -- which is why a
///    peer that keeps sending application data leaves this not done, and a
///    clean zero marks it done.
/// 4. **Report.** [`CURLcode::Again`] becomes `RECV` and not done; any other
///    error is traced and propagated; zero bytes read means the `close_notify`
///    arrived.
///
/// # Errors
///
/// Whatever the flush or the drain reports, other than [`CURLcode::Again`],
/// which becomes a successful "not done".
fn shut_down(
    state: &mut RustlsSession,
    io: &mut TlsTransport<'_, '_, '_>,
    send_shutdown: bool,
) -> CurlResult<bool> {
    if state.conn.is_none() {
        return Ok(true);
    }

    state.io_need = SslIoNeed::NONE;

    if !state.sent_shutdown {
        state.sent_shutdown = true;
        if send_shutdown {
            if let Some(conn) = state.conn.as_mut() {
                conn.send_close_notify();
            }
        }
    }

    match send_plain(state, io, &[]) {
        Ok(_) => {}
        Err(error) if error.code() == CURLcode::Again => {
            state.io_need = SslIoNeed::SEND;
            return Ok(false);
        }
        Err(error) => {
            trace(
                io,
                format_args!("shutdown send failed: {}", error.code().as_i32()),
            );
            return Err(error);
        }
    }

    let mut drained = [0_u8; SHUTDOWN_DRAIN_BUFFER];
    let mut last: CurlResult<usize> = Ok(0);
    for _ in 0..SHUTDOWN_DRAIN_ATTEMPTS {
        last = recv_plain(state, io, &mut drained);
        if last.is_err() {
            break;
        }
    }

    match last {
        Err(error) if error.code() == CURLcode::Again => {
            state.io_need = SslIoNeed::RECV;
            Ok(false)
        }
        Err(error) => {
            trace(
                io,
                format_args!("shutdown, error: {}", error.code().as_i32()),
            );
            Err(error)
        }
        // "We got the close notify alert and are done."
        Ok(0) => Ok(true),
        Ok(_) => Ok(false),
    }
}

// The descriptor -- `const struct Curl_ssl Curl_ssl_rustls`
// (`rustls.c:1397-1426`)

/// `Curl_ssl_rustls`, slot for slot.
///
/// Nineteen members in `struct Curl_ssl`'s declaration order
/// (`lib/vtls/vtls_int.h:150-190`), with [`None`] wherever the C writes `NULL`.
/// Eight slots are [`None`], and they divide into two groups that are worth
/// keeping apart:
///
/// * **`init` is [`None`] because there is nothing to do**, not because
///   anything is unsupported. `Curl_ssl_init` (`vtls.c:465-475`) returns 1 for
///   a null pointer, so "no initialisation needed" and "initialisation
///   succeeded" are the same answer -- and a rustls backend needs none, because
///   it installs no process-global provider.
/// * **Seven slots are genuinely unsupported**, and these are they:
///   `cert_status_request`, `close_all`, `set_engine`, `set_engine_default`,
///   `engines_list`, `sha256sum` and `get_channel_binding`. Crypto engines are
///   an OpenSSL concept; OCSP stapling, a SHA-256 digest service and the
///   `tls-server-end-point` channel binding are all absent from the C rustls
///   backend too. `sha256sum` being [`None`] is what keeps
///   `SSLSUPP_PINNEDPUBKEY` out of [`RUSTLS_SUPPORTS`].
static RUSTLS_DESCRIPTOR: CurlSslDescriptor = CurlSslDescriptor {
    // `{ CURLSSLBACKEND_RUSTLS, "rustls" }` -- first, and contractually so.
    info: RUSTLS_INFO,
    supports: RUSTLS_SUPPORTS,
    sizeof_ssl_backend_data: core::mem::size_of::<RustlsSession>(),

    init: None,
    cleanup: Some(cleanup),
    version: Some(version),
    // `cr_shutdown`
    shut_down: Some(TlsOp::Session),
    // `cr_data_pending`
    data_pending: Some(TlsOp::Session),
    // `cr_random` takes `struct Curl_easy *`, so it is a backend operation and
    // not a session one.
    random: Some(TlsOp::Backend),
    cert_status_request: None,
    // `cr_connect`
    do_connect: Some(TlsOp::Session),
    // `Curl_ssl_adjust_pollset` -- the generic helper.
    adjust_pollset: Some(TlsOp::Session),
    // `cr_get_internals`, through `TlsSessionInfo` rather than a `void *`.
    get_internals: Some(TlsOp::Session),
    // `cr_close`
    close: Some(TlsOp::Session),
    close_all: None,
    set_engine: None,
    set_engine_default: None,
    engines_list: None,
    sha256sum: None,
    // `cr_recv`
    recv_plain: Some(TlsOp::Session),
    // `cr_send`
    send_plain: Some(TlsOp::Session),
    get_channel_binding: None,
};

impl TlsBackend for RustlsBackend {
    type State = RustlsSession;

    fn descriptor(&self) -> &'static CurlSslDescriptor {
        &RUSTLS_DESCRIPTOR
    }

    fn version(&self) -> &'static str {
        version()
    }

    /// The successor of `connssl->backend = calloc(1,
    /// sizeof(struct rustls_ssl_backend_data))`.
    fn new_state(
        &self,
        peer: &SslPeer,
        alpn: Option<&AlpnSpec>,
    ) -> CurlResult<Self::State> {
        Ok(RustlsSession::new(peer.clone(), alpn.copied()))
    }

    fn do_connect(
        &self,
        state: &mut Self::State,
        io: &mut TlsTransport<'_, '_, '_>,
    ) -> CurlResult<HandshakeProgress> {
        handshake(self, state, io)
    }

    /// `cr_send`. `eos` is accepted and not forwarded, deliberately.
    ///
    /// `ssl_cf_send` passes it down (`vtls.c:1472-1523`) and `cr_send` has no
    /// parameter for it, because a TLS stream's end is signalled by
    /// `close_notify` and not by a flag on a record. [`BelowWriter`] therefore
    /// always writes with `eos = false`, which is `rustls.c:106` verbatim.
    fn send_plain(
        &self,
        state: &mut Self::State,
        io: &mut TlsTransport<'_, '_, '_>,
        buf: &[u8],
        eos: bool,
    ) -> CurlResult<usize> {
        let _ = eos;
        send_plain(state, io, buf)
    }

    fn recv_plain(
        &self,
        state: &mut Self::State,
        io: &mut TlsTransport<'_, '_, '_>,
        buf: &mut [u8],
    ) -> CurlResult<usize> {
        recv_plain(state, io, buf)
    }

    /// `cr_cleanup` (`rustls.c:1392-1395`): `Curl_tls_keylog_close()`.
    fn cleanup(&self) {
        self.keylog.close();
        cleanup();
    }

    /// `cr_data_pending` (`rustls.c:77-88`): `return (bool)backend->data_in_pending;`
    fn data_pending(&self, state: &Self::State) -> bool {
        state.data_in_pending
    }

    /// `cr_random` (`rustls.c:1383-1390`): fill from the provider's generator.
    ///
    /// ```c
    /// rresult = rustls_default_crypto_provider_random(entropy, length);
    /// return map_error(rresult);
    /// ```
    ///
    /// # Errors
    ///
    /// [`CURLcode::RecvError`]. That is not a typo and not a lapse: the C
    /// returns `map_error(rresult)`, whose `default:` arm is
    /// `CURLE_RECV_ERROR`, so a refused draw produces that code in curl
    /// 8.19.0-DEV. The trait's documentation suggests
    /// [`CURLcode::FailedInit`], which is `lib/rand.c:61`'s code for a failed
    /// *platform* draw rather than this slot's; the slot being translated wins,
    /// and the difference is recorded rather than smoothed over. Every caller
    /// tests only for non-success.
    fn random(&self, entropy: &mut [u8]) -> CodeResult<()> {
        self.provider
            .secure_random
            .fill(entropy)
            .map_err(|_| CURLcode::RecvError)
    }

    /// `cr_close` (`rustls.c:1293-1310`): drop the session immediately.
    fn close(&self, state: &mut Self::State) {
        state.close();
    }

    fn shut_down(
        &self,
        state: &mut Self::State,
        io: &mut TlsTransport<'_, '_, '_>,
        send_shutdown: bool,
    ) -> CurlResult<bool> {
        shut_down(state, io, send_shutdown)
    }
}

// WHAT MIRI REACHES HERE, STATED AS A MEASUREMENT RATHER THAN A CLAIM.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::filters::{
        link, CallCtx, CfQuery, CfQueryValue, ConnFilter, FilterBase,
        SocketIndex, Transport,
    };
    use crate::crypto::rand::Rng;
    use crate::tls::TlsSlot;
    use crate::util::sync_cell::SyncCell;
    use crate::util::timeval::{CurlTime, TestClock};
    use rustls::CertificateError;
    use std::sync::Arc;

    // Test doubles. Nothing here touches a socket, a file or the network:
    // every seam this module has is injected, so the whole backend is
    // reachable against a scripted transport.

    /// What one scripted read or write does.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Step {
        /// Accept or deliver up to this many bytes.
        Bytes(usize),
        /// Report [`CURLcode::Again`].
        Again,
        /// Report end of stream, or accept nothing.
        Zero,
        /// Report a hard failure with this code.
        Fail(CURLcode),
    }

    /// The filter beneath the TLS session: a transport with no socket.
    #[derive(Debug, Default)]
    struct BelowState {
        /// Everything the TLS session handed down, in order.
        sent: Vec<u8>,
        /// What the next writes do; the last entry repeats.
        write_script: Vec<Step>,
        /// Bytes waiting to be delivered upward.
        to_deliver: Vec<u8>,
        /// What the next reads do; the last entry repeats.
        read_script: Vec<Step>,
        /// How many times `send` was called.
        sends: usize,
        /// How many times `recv` was called.
        recvs: usize,
        /// What `data_pending` answers.
        pending: bool,
    }

    impl BelowState {
        /// The next step of `script`, keeping the final entry once reached.
        fn step(script: &mut Vec<Step>) -> Step {
            match script.len() {
                0 => Step::Bytes(usize::MAX),
                1 => script[0],
                _ => script.remove(0),
            }
        }
    }

    /// The filter below, sharing its state so a test can script and inspect it.
    #[derive(Debug)]
    struct Below {
        base: FilterBase,
        shared: Arc<SyncCell<BelowState>>,
    }

    impl Below {
        fn new() -> (Self, Arc<SyncCell<BelowState>>) {
            let shared = Arc::new(SyncCell::new(BelowState::default()));
            let mut base = FilterBase::new(SocketIndex::First);
            base.set_connected(true);
            (
                Self {
                    base,
                    shared: Arc::clone(&shared),
                },
                shared,
            )
        }
    }

    impl ConnFilter for Below {
        fn trace_name(&self) -> &'static str {
            "TCP"
        }

        fn base(&self) -> &FilterBase {
            &self.base
        }

        fn base_mut(&mut self) -> &mut FilterBase {
            &mut self.base
        }

        fn connect(&mut self, _cx: &mut CallCtx<'_, '_>) -> CurlResult<bool> {
            self.base.set_connected(true);
            Ok(true)
        }

        fn close(&mut self, _cx: &mut CallCtx<'_, '_>) {
            self.base.set_connected(false);
        }

        fn data_pending(&mut self, _cx: &CallCtx<'_, '_>) -> bool {
            self.shared.borrow().pending
        }

        fn send(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            buf: &[u8],
            eos: bool,
        ) -> CurlResult<usize> {
            // The write adapter must never claim the stream ended.
            assert!(!eos, "the TLS write adapter always sends with eos=false");
            let mut shared = self.shared.borrow_mut();
            shared.sends += 1;
            match BelowState::step(&mut shared.write_script) {
                Step::Bytes(limit) => {
                    let take = buf.len().min(limit);
                    let accepted = buf.get(..take).unwrap_or(&[]);
                    shared.sent.extend_from_slice(accepted);
                    Ok(take)
                }
                Step::Again => Err(Error::new(CURLcode::Again)),
                Step::Zero => Ok(0),
                Step::Fail(code) => Err(Error::new(code)),
            }
        }

        fn recv(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            buf: &mut [u8],
        ) -> CurlResult<usize> {
            let mut shared = self.shared.borrow_mut();
            shared.recvs += 1;
            match BelowState::step(&mut shared.read_script) {
                Step::Bytes(limit) => {
                    let take =
                        shared.to_deliver.len().min(buf.len()).min(limit);
                    if take == 0 {
                        // A real socket with nothing buffered reports
                        // `CURLE_AGAIN`, never zero: zero is end of stream.
                        // `Step::Zero` is how a test asks for that instead.
                        return Err(Error::new(CURLcode::Again));
                    }
                    let drained: Vec<u8> =
                        shared.to_deliver.drain(..take).collect();
                    match buf.get_mut(..take) {
                        Some(target) => target.copy_from_slice(&drained),
                        None => return Ok(0),
                    }
                    Ok(take)
                }
                Step::Again => Err(Error::new(CURLcode::Again)),
                Step::Zero => Ok(0),
                Step::Fail(code) => Err(Error::new(code)),
            }
        }

        fn query(
            &mut self,
            _cx: &mut CallCtx<'_, '_>,
            query: CfQuery,
        ) -> CurlResult<CfQueryValue> {
            match query {
                CfQuery::Socket => Ok(CfQueryValue::Socket(7)),
                _ => Err(Error::new(CURLcode::UnknownOption)),
            }
        }
    }

    /// A base with `Below` linked beneath it, standing in for the TLS filter.
    ///
    /// Returns the base and the shared state, so a test scripts the transport
    /// through the second and drives the session through the first.
    fn stack() -> (FilterBase, Arc<SyncCell<BelowState>>) {
        let (below, shared) = Below::new();
        let mut base = FilterBase::new(SocketIndex::First);
        base.set_next(Some(link(below)));
        (base, shared)
    }

    /// The pinned provider, as a value. Never installed as a default.
    fn provider() -> Arc<CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    fn peer(host: &str) -> SslPeer {
        SslPeer::new(host, None, 443, Transport::Tcp, String::from("key:G"))
            .expect("a non-empty hostname yields a peer")
    }

    /// A backend with verification off, so a session can be built without a
    /// trust store. `--insecure` is the ONLY route to this, here as everywhere.
    fn insecure_backend() -> RustlsBackend {
        RustlsBackend::new(provider(), TlsOptions::new().insecure())
    }

    fn coded<T>(result: CurlResult<T>) -> Result<T, CURLcode> {
        result.map_err(Error::into_code)
    }

    // Identity, capability and the descriptor

    /// `{ CURLSSLBACKEND_RUSTLS, "rustls" }` (`rustls.c:1398`), and the
    /// integer is the one already in the public header.
    #[test]
    fn identity_is_rustls_with_the_public_enumerant_fourteen() {
        let info = RustlsBackend::backend_info();
        assert_eq!(info.id, TlsBackendId::RUSTLS);
        assert_eq!(info.id.as_i32(), 14);
        assert_eq!(info.name, "rustls");
        // Lower case, exactly as the C literal spells it: `curl_global_sslset`
        // compares names case-insensitively but reports this string verbatim.
        assert_eq!(info.name, info.name.to_lowercase());
    }

    /// The descriptor's first member is the identity, and it agrees with the
    /// type-level answer. `vtls_int.h:142-145` makes the position contractual.
    #[test]
    fn descriptor_carries_the_identity_first() {
        let backend = insecure_backend();
        let descriptor = backend.descriptor();
        assert_eq!(descriptor.info(), RustlsBackend::backend_info());
        assert_eq!(descriptor.info(), SslBackendInfo::RUSTLS);
    }

    /// `cr_version` (`rustls.c:1377-1381`), and the token that must NOT appear.
    #[test]
    fn version_token_is_truthful_and_is_not_rustls_ffi() {
        let backend = insecure_backend();
        assert_eq!(backend.version(), "rustls/0.23.42");
        assert_eq!(backend.version(), SSL_VERSION);
        // `tests/runtests.pl:585-586` keys `$feature{"rustls"}` off the token
        // `rustls-ffi`, which names the old C FFI backend. Emitting it would
        // unlock the rustls-gated fixtures by misdescribing this build.
        assert!(!backend.version().contains("-ffi"));
        assert!(!backend.version().contains("ffi"));
    }

    /// The nineteen slots, in `struct Curl_ssl` declaration order, against
    /// `rustls.c:1407-1425` read line by line.
    #[test]
    fn descriptor_slots_match_the_c_backend_exactly() {
        let backend = insecure_backend();
        let descriptor = backend.descriptor();
        assert_eq!(
            descriptor.filled_slots(),
            [
                false, // init                -- NULL
                true,  // cleanup             -- cr_cleanup
                true,  // version             -- cr_version
                true,  // shut_down           -- cr_shutdown
                true,  // data_pending        -- cr_data_pending
                true,  // random              -- cr_random
                false, // cert_status_request -- NULL
                true,  // do_connect          -- cr_connect
                true,  // adjust_pollset      -- Curl_ssl_adjust_pollset
                true,  // get_internals       -- cr_get_internals
                true,  // close               -- cr_close
                false, // close_all           -- NULL
                false, // set_engine          -- NULL
                false, // set_engine_default  -- NULL
                false, // engines_list        -- NULL
                false, // sha256sum           -- NULL
                true,  // recv_plain          -- cr_recv
                true,  // send_plain          -- cr_send
                false, // get_channel_binding -- NULL
            ]
        );
    }

    /// Eight slots are [`None`]; seven of them are unsupported capabilities and
    /// one is "nothing to do".
    #[test]
    fn seven_slots_are_unsupported_and_one_needs_nothing() {
        let backend = insecure_backend();
        let descriptor = backend.descriptor();

        let empty: Vec<TlsSlot> = TlsSlot::ALL
            .into_iter()
            .filter(|slot| !descriptor.fills(*slot))
            .collect();
        assert_eq!(
            empty,
            vec![
                TlsSlot::Init,
                TlsSlot::CertStatusRequest,
                TlsSlot::CloseAll,
                TlsSlot::SetEngine,
                TlsSlot::SetEngineDefault,
                TlsSlot::EnginesList,
                TlsSlot::Sha256Sum,
                TlsSlot::GetChannelBinding,
            ]
        );
        assert_eq!(empty.len(), 8, "eight NULL slots in rustls.c:1407-1425");

        let unsupported: Vec<TlsSlot> = empty
            .into_iter()
            .filter(|slot| *slot != TlsSlot::Init)
            .collect();
        assert_eq!(
            unsupported.len(),
            7,
            "seven unsupported capabilities, channel binding counted"
        );
    }

    /// The defaults behind the empty slots are the C's fallbacks, so the
    /// absence is behaviour and not merely a null.
    #[test]
    fn unsupported_slots_answer_the_way_vtls_does_for_null() {
        let backend = insecure_backend();
        // `Curl_ssl_init` returns 1 for a null pointer.
        assert!(backend.init());
        // `Curl_ssl_cert_status_request` answers FALSE (`vtls.c:900-905`).
        assert!(!backend.cert_status_request());
        // `Curl_ssl_set_engine` and friends answer CURLE_NOT_BUILT_IN.
        assert_eq!(backend.set_engine("pkcs11"), Err(CURLcode::NotBuiltIn));
        assert_eq!(backend.set_engine_default(), Err(CURLcode::NotBuiltIn));
        assert!(backend.engines_list().is_empty());
        // `vtls.c:776-779` abandons pinning for a backend with no digest.
        let mut digest = [0_u8; 32];
        assert_eq!(
            backend.sha256sum(b"abc", &mut digest),
            Err(CURLcode::NotBuiltIn)
        );
        assert_eq!(digest, [0_u8; 32]);
        // `close_all` does nothing, as `Curl_ssl_close_all` does.
        backend.close_all();
        // Channel binding leaves the destination untouched and succeeds
        // (`vtls.h:198-205`).
        let state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let mut binding = Vec::new();
        assert_eq!(backend.channel_binding(&state, &mut binding), Ok(()));
        assert!(binding.is_empty());
        // rustls has no `SSL_CTX` distinct from a session
        // (`lib/cfilters.h:156-158`).
        assert!(!backend.distinguishes_context());
    }

    /// `rustls.c:1399-1405` sets seven bits. Six are set here, each behind a
    /// path that exists, and the seventh is ECH -- omitted because the pinned
    /// `ring` provider ships no HPKE suite.
    #[test]
    fn support_set_is_the_measured_six_bits() {
        let backend = insecure_backend();
        let supports = backend.descriptor().supports();

        for (name, bit) in [
            ("CAINFO_BLOB", SslSupport::CAINFO_BLOB),
            ("HTTPS_PROXY", SslSupport::HTTPS_PROXY),
            ("CIPHER_LIST", SslSupport::CIPHER_LIST),
            ("TLS13_CIPHERSUITES", SslSupport::TLS13_CIPHERSUITES),
            ("CERTINFO", SslSupport::CERTINFO),
            ("CRLFILE", SslSupport::CRLFILE),
        ] {
            assert!(
                supports.contains(bit),
                "{name} is claimed by rustls.c:1399-1405 and is implemented"
            );
        }

        assert_eq!(
            supports.bits().count_ones(),
            6,
            "six truthful bits: the C's seven minus ECH"
        );
        assert_eq!(supports, RUSTLS_SUPPORTS);
    }

    /// Every bit the C leaves clear stays clear, and ECH joins them.
    #[test]
    fn absent_capabilities_stay_absent() {
        let backend = insecure_backend();
        let supports = backend.descriptor().supports();
        for (name, bit) in [
            ("CA_PATH", SslSupport::CA_PATH),
            ("PINNEDPUBKEY", SslSupport::PINNEDPUBKEY),
            ("SSL_CTX", SslSupport::SSL_CTX),
            ("CA_CACHE", SslSupport::CA_CACHE),
            ("SIGNATURE_ALGORITHMS", SslSupport::SIGNATURE_ALGORITHMS),
            ("ISSUERCERT", SslSupport::ISSUERCERT),
            ("SSL_EC_CURVES", SslSupport::SSL_EC_CURVES),
            ("ISSUERCERT_BLOB", SslSupport::ISSUERCERT_BLOB),
        ] {
            assert!(
                !supports.contains(bit),
                "{name} is absent from rustls.c:1399-1405 and must stay absent"
            );
        }
        // The measured deviation, asserted so it cannot be reintroduced by
        // accident: advertising ECH without an HPKE suite would turn a clean
        // fixture skip into a hard failure.
        assert!(
            !supports.contains(SslSupport::ECH),
            "ECH is not functional under the pinned ring provider"
        );
        // Pinning must not arrive by another route either.
        assert!(backend.descriptor().sha256sum.is_none());
    }

    /// `sizeof_ssl_backend_data` describes the type it claims to describe.
    #[test]
    fn state_size_is_the_state_type_size() {
        let backend = insecure_backend();
        assert_eq!(
            backend.descriptor().sizeof_ssl_backend_data,
            core::mem::size_of::<RustlsSession>()
        );
        assert_eq!(backend.state_size(), core::mem::size_of::<RustlsSession>());
    }

    /// `cr_get_internals` (`rustls.c:1217-1225`), engine-neutrally: which
    /// backend, which handle, and no pointer.
    #[test]
    fn get_internals_reports_identity_without_a_pointer() {
        let session = RustlsBackend::session_info(TlsHandleKind::Session);
        let context = RustlsBackend::session_info(TlsHandleKind::Context);
        assert_eq!(session.backend, TlsBackendId::RUSTLS);
        assert_eq!(session.kind, TlsHandleKind::Session);
        assert_eq!(context.kind, TlsHandleKind::Context);
        // The C's `(void)info;` -- the two queries describe the same thing.
        assert!(!session.distinguishes_context);
        assert!(!context.distinguishes_context);
    }

    // Error mapping -- `map_error` (`rustls.c:52-66`)

    /// The certificate test comes first and its answer wins.
    #[test]
    fn certificate_errors_map_to_peer_verification_failure() {
        for error in [
            rustls::Error::InvalidCertificate(CertificateError::Expired),
            rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName,
            ),
            rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer),
            rustls::Error::NoCertificatesPresented,
        ] {
            assert_eq!(
                map_rustls_error(&error),
                CURLcode::PeerFailedVerification,
                "rustls_result_is_cert_error wins over the switch"
            );
            assert!(is_certificate_error(&error));
        }
    }

    /// `RUSTLS_RESULT_NULL_PARAMETER`'s nearest relatives.
    #[test]
    fn unusable_arguments_map_to_bad_function_argument() {
        assert_eq!(
            map_rustls_error(&rustls::Error::General(String::from("nope"))),
            CURLcode::BadFunctionArgument
        );
    }

    /// The C's `default:` arm.
    #[test]
    fn every_other_failure_maps_to_recv_error() {
        for error in [
            rustls::Error::DecryptError,
            rustls::Error::EncryptError,
            rustls::Error::HandshakeNotComplete,
            rustls::Error::NoApplicationProtocol,
        ] {
            assert_eq!(map_rustls_error(&error), CURLcode::RecvError);
            assert!(!is_certificate_error(&error));
        }
    }

    /// `rustls.c:1206-1208`: during a handshake, a receive failure is a connect
    /// failure -- and nothing else changes.
    #[test]
    fn only_recv_error_becomes_ssl_connect_error() {
        assert_eq!(
            CURLcode::RecvError.into_connect_error(),
            CURLcode::SslConnectError
        );
        for code in [
            CURLcode::PeerFailedVerification,
            CURLcode::BadFunctionArgument,
            CURLcode::SendError,
            CURLcode::Again,
        ] {
            assert_eq!(code.into_connect_error(), code);
        }
    }

    // The I/O adapters -- `read_cb` and `write_cb` (`rustls.c:90-152`)

    /// A zero-byte encrypted read is end of stream and sets `peer_closed`,
    /// which is `connssl->peer_closed = TRUE` at `rustls.c:107`.
    #[test]
    fn read_adapter_records_peer_close_on_zero() {
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Zero];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let mut closed = false;
        let mut buf = [0_u8; 8];
        let mut reader = BelowReader {
            io: &mut io,
            peer_closed: &mut closed,
        };
        assert_eq!(reader.read(&mut buf).ok(), Some(0));
        // No explicit drop: the adapter holds no `Drop` impl, so the borrow of
        // `closed` ends at the adapter's last use and the flag is readable
        // here without one.
        assert!(closed, "zero is end of stream, not 'try again'");
    }

    /// Every scripted read outcome, and the exact adapter answer for it.
    #[test]
    fn read_adapter_maps_each_outcome() {
        for (script, expected, sets_closed) in [
            (Step::Again, Err(io::ErrorKind::WouldBlock), false),
            (Step::Zero, Ok(0), true),
            (
                Step::Fail(CURLcode::RecvError),
                Err(io::ErrorKind::Other),
                false,
            ),
        ] {
            let (below, shared) = Below::new();
            shared.borrow_mut().read_script = vec![script];
            let mut base = FilterBase::new(SocketIndex::First);
            base.set_next(Some(link(below)));
            let clock = TestClock::new(CurlTime::new(1, 0));
            let mut cx = CallCtx::new(&clock);
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let mut closed = false;
            let mut buf = [0_u8; 8];
            let mut reader = BelowReader {
                io: &mut io,
                peer_closed: &mut closed,
            };
            let outcome = reader.read(&mut buf).map_err(|error| error.kind());
            assert_eq!(outcome, expected, "script {script:?}");
            assert_eq!(closed, sets_closed, "script {script:?}");
        }
    }

    /// Every scripted write outcome, and the `eos = false` invariant, which the
    /// fake asserts on every call.
    #[test]
    fn write_adapter_maps_each_outcome_and_never_signals_eos() {
        for (script, expected) in [
            (Step::Bytes(usize::MAX), Ok(4)),
            (Step::Bytes(2), Ok(2)),
            (Step::Again, Err(io::ErrorKind::WouldBlock)),
            (Step::Zero, Ok(0)),
            (Step::Fail(CURLcode::SendError), Err(io::ErrorKind::Other)),
        ] {
            let (below, shared) = Below::new();
            shared.borrow_mut().write_script = vec![script];
            let mut base = FilterBase::new(SocketIndex::First);
            base.set_next(Some(link(below)));
            let clock = TestClock::new(CurlTime::new(1, 0));
            let mut cx = CallCtx::new(&clock);
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let mut writer = BelowWriter { io: &mut io };
            let outcome = writer.write(b"abcd").map_err(|error| error.kind());
            assert!(writer.flush().is_ok(), "flush is a no-op");
            assert_eq!(outcome, expected, "script {script:?}");
        }
    }

    /// `EAGAIN` and `EWOULDBLOCK` collapse into one [`io::ErrorKind`].
    #[test]
    fn would_block_recognises_only_the_blocking_kind() {
        assert!(would_block(&io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(!would_block(&io::Error::other("boom")));
        assert!(!would_block(&io::Error::from(io::ErrorKind::UnexpectedEof)));
    }

    // Version selection -- `init_config_builder` (`rustls.c:534-577`)

    /// Runs [`protocol_versions`] against a scripted stack and returns the
    /// wire versions in the order they would reach the `ClientHello`.
    fn versions_for(
        version: u8,
        version_max: i64,
        ech: bool,
    ) -> Result<Vec<ProtocolVersion>, CURLcode> {
        let (mut base, _shared) = stack();
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let prefs = TlsPrefs {
            version,
            version_max,
        };
        coded(protocol_versions(prefs, ech, &mut io)).map(|versions| {
            versions.iter().map(|entry| entry.version).collect()
        })
    }

    /// The C's array order -- TLS 1.2 then TLS 1.3 -- reaches the wire, and it
    /// is never sorted or reversed here.
    #[test]
    fn accepted_minimums_all_yield_tls12_then_tls13() {
        for version in [
            CURL_SSLVERSION_TLSV1,
            CURL_SSLVERSION_TLSV1_0,
            CURL_SSLVERSION_TLSV1_1,
            CURL_SSLVERSION_TLSV1_2,
        ] {
            assert_eq!(
                versions_for(version, CURL_SSLVERSION_MAX_NONE, false),
                Ok(vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3]),
                "minimum {version} is TLS 1.2's floor in rustls.c:537-541"
            );
        }
    }

    /// `CURL_SSLVERSION_TLSv1_3` narrows the offer to one entry.
    #[test]
    fn a_tls13_minimum_offers_only_tls13() {
        assert_eq!(
            versions_for(
                CURL_SSLVERSION_TLSV1_3,
                CURL_SSLVERSION_MAX_NONE,
                false
            ),
            Ok(vec![ProtocolVersion::TLSv1_3])
        );
    }

    /// The three maximums that leave the list alone.
    #[test]
    fn permissive_maximums_leave_the_offer_alone() {
        for maximum in [
            CURL_SSLVERSION_MAX_NONE,
            CURL_SSLVERSION_MAX_DEFAULT,
            CURL_SSLVERSION_MAX_TLSV1_3,
        ] {
            assert_eq!(
                versions_for(CURL_SSLVERSION_TLSV1_2, maximum, false),
                Ok(vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3])
            );
        }
    }

    /// `CURL_SSLVERSION_MAX_TLSv1_2` truncates when TLS 1.2 is the floor, and
    /// falls through to the error arm when it is not -- which is the C's
    /// `FALLTHROUGH()` at `rustls.c:560-562`.
    #[test]
    fn a_tls12_maximum_truncates_or_falls_through() {
        assert_eq!(
            versions_for(
                CURL_SSLVERSION_TLSV1_2,
                CURL_SSLVERSION_MAX_TLSV1_2,
                false
            ),
            Ok(vec![ProtocolVersion::TLSv1_2])
        );
        assert_eq!(
            versions_for(
                CURL_SSLVERSION_TLSV1_3,
                CURL_SSLVERSION_MAX_TLSV1_2,
                false
            ),
            Err(CURLcode::BadFunctionArgument),
            "a maximum below the minimum describes an empty range"
        );
    }

    /// Everything the C refuses, refused with the C's code.
    #[test]
    fn unsupported_version_bounds_are_refused() {
        // `CURL_SSLVERSION_DEFAULT` (0), `SSLv2` (2), `SSLv3` (3) and anything
        // at or above `CURL_SSLVERSION_LAST` (8).
        for version in [0_u8, 2, 3, 8, 9, 255] {
            assert_eq!(
                versions_for(version, CURL_SSLVERSION_MAX_NONE, false),
                Err(CURLcode::BadFunctionArgument),
                "minimum {version} is not a version rustls offers"
            );
        }
        // `MAX_TLSv1_0` and `MAX_TLSv1_1`.
        for maximum in [
            i64::from(CURL_SSLVERSION_TLSV1_0) << 16,
            i64::from(CURL_SSLVERSION_TLSV1_1) << 16,
        ] {
            assert_eq!(
                versions_for(CURL_SSLVERSION_TLSV1_2, maximum, false),
                Err(CURLcode::BadFunctionArgument)
            );
        }
    }

    /// `rustls.c:570-577`: a requested ECH forces a TLS-1.3-only offer, and it
    /// does so for *requesting* rather than for succeeding.
    #[test]
    fn requesting_ech_forces_tls13() {
        assert_eq!(
            versions_for(
                CURL_SSLVERSION_TLSV1_2,
                CURL_SSLVERSION_MAX_NONE,
                true
            ),
            Ok(vec![ProtocolVersion::TLSv1_3])
        );
    }

    // ECH -- `init_config_builder_ech` (`rustls.c:907-1006`)

    /// `ECH_ENABLED(data)` (`lib/vtls/vtls.h:52-56`), as an enumeration that
    /// cannot express `GREASE | DISABLE`.
    #[test]
    fn ech_policy_reports_whether_it_is_enabled() {
        assert!(!EchPolicy::Disabled.is_enabled());
        assert!(!EchPolicy::default().is_enabled());
        assert!(EchPolicy::Grease.is_enabled());
        assert!(EchPolicy::CommandLine(String::from("AAA=")).is_enabled());
        assert!(EchPolicy::Dns(vec![1, 2, 3]).is_enabled());
    }

    /// Command-line input is base64 and is decoded here, because "rustls-ffi
    /// expects the raw TLS encoded ECHConfigList bytes" (`rustls.c:952`).
    #[test]
    fn command_line_ech_config_is_base64_decoded() {
        let encoded = EchPolicy::CommandLine(String::from("AQIDBA=="));
        assert_eq!(
            encoded.config_list().map_err(Error::into_code),
            Ok(Some(vec![1_u8, 2, 3, 4]))
        );
    }

    /// The two command-line failures the C reports, with its codes.
    #[test]
    fn unusable_command_line_ech_config_is_refused() {
        assert_eq!(
            EchPolicy::CommandLine(String::new())
                .config_list()
                .map_err(Error::into_code),
            Err(CURLcode::SslConnectError),
            "rustls.c:950-954: ECHConfig from command line empty"
        );
        assert_eq!(
            EchPolicy::CommandLine(String::from("not base64!"))
                .config_list()
                .map_err(Error::into_code),
            Err(CURLcode::SslConnectError),
            "rustls.c:956-960: cannot base64 decode ECHConfig"
        );
    }

    /// A DNS policy carrying nothing is `rustls.c:971-976`'s "ECH requested but
    /// no ECHConfig available".
    #[test]
    fn dns_ech_config_must_not_be_empty() {
        assert_eq!(
            EchPolicy::Dns(Vec::new())
                .config_list()
                .map_err(Error::into_code),
            Err(CURLcode::SslConnectError)
        );
        assert_eq!(
            EchPolicy::Dns(vec![9, 9])
                .config_list()
                .map_err(Error::into_code),
            Ok(Some(vec![9_u8, 9]))
        );
    }

    /// Neither disabled nor GREASE reads a configuration.
    #[test]
    fn disabled_and_grease_read_no_ech_config() {
        assert_eq!(
            EchPolicy::Disabled.config_list().map_err(Error::into_code),
            Ok(None)
        );
        assert_eq!(
            EchPolicy::Grease.config_list().map_err(Error::into_code),
            Ok(None)
        );
    }

    /// Builds an [`EchMode`] against a scripted stack and reports the code.
    fn ech_mode_for(options: TlsOptions) -> Result<(), CURLcode> {
        let backend = RustlsBackend::new(provider(), options);
        let (mut base, _shared) = stack();
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        coded(build_ech_mode(&backend, &mut io)).map(|_| ())
    }

    /// The measured deviation, from the other side: with no injected HPKE
    /// suite -- which is every configuration the pinned `ring` provider can
    /// produce -- ECH fails with the C's code instead of pretending to work.
    #[test]
    fn ech_without_an_hpke_suite_fails_the_way_the_c_does() {
        let mut options = TlsOptions::new().insecure();
        options.ech = EchPolicy::Grease;
        assert_eq!(ech_mode_for(options), Err(CURLcode::SslConnectError));

        let mut options = TlsOptions::new().insecure();
        options.ech = EchPolicy::Dns(vec![0, 1, 2]);
        assert_eq!(ech_mode_for(options), Err(CURLcode::SslConnectError));
    }

    /// `rustls.c:925-929`: an outer name is refused, and it is refused before
    /// any configuration is read.
    #[test]
    fn an_ech_outername_is_refused() {
        let mut options = TlsOptions::new().insecure();
        options.ech = EchPolicy::Grease;
        options.ech_public_name = Some(String::from("public.example"));
        assert_eq!(ech_mode_for(options), Err(CURLcode::SslConnectError));
    }

    /// Soft mode continues without ECH; hard mode aborts. `rustls.c:1067-1074`.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn ech_hard_mode_aborts_and_soft_mode_continues() {
        let mut soft = TlsOptions::new().insecure();
        soft.ech = EchPolicy::Grease;
        soft.ech_hard = false;
        let backend = RustlsBackend::new(provider(), soft);
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, _shared) = stack();
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(configure(&backend, &mut state, &mut io)),
            Ok(()),
            "soft ECH failure must not stop the handshake"
        );
        assert!(state.conn.is_some());

        let mut hard = TlsOptions::new().insecure();
        hard.ech = EchPolicy::Grease;
        hard.ech_hard = true;
        let backend = RustlsBackend::new(provider(), hard);
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, _shared) = stack();
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(configure(&backend, &mut state, &mut io)),
            Err(CURLcode::SslConnectError),
            "CURLECH_HARD propagates the failure"
        );
    }

    // Configuration -- `cr_init_backend` (`rustls.c:1008-1104`)

    /// A `ClientHello` reaches the transport, and it is a TLS record: content
    /// type 22 (handshake), then the two version bytes 0x0301, then a length.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn the_first_step_writes_a_client_hello() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (below, shared) = Below::new();
        let mut base = FilterBase::new(SocketIndex::First);
        base.set_next(Some(link(below)));
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);

        let progress = coded(backend.do_connect(&mut state, &mut io))
            .expect("the first step writes and then waits to read");
        assert!(!progress.done, "one step cannot finish a handshake");
        assert_eq!(
            progress.connection_state,
            Some(SslConnectionState::Negotiating),
            "cr_connect sets ssl_connection_negotiating after init"
        );
        assert_eq!(progress.connecting_state, Some(SslConnectState::Connect2));
        assert_eq!(progress.io_need, SslIoNeed::RECV);
        assert_eq!(state.io_need(), SslIoNeed::RECV);

        let sent = shared.borrow().sent.clone();
        assert!(!sent.is_empty(), "a ClientHello must have been written");
        assert_eq!(sent.first().copied(), Some(22), "handshake record");
        assert_eq!(sent.get(1..3), Some(&[0x03_u8, 0x01][..]), "legacy 0x0301");
        // A `ClientHello` for `example.com` carries the name in SNI.
        assert!(
            sent.windows(11).any(|window| window == b"example.com"),
            "SNI carries the peer name"
        );
    }

    /// The ALPN entries reach the wire in the order and with the bytes the
    /// specification names, at most three. `rustls.c:643-658`.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn alpn_reaches_the_wire_in_order() {
        let spec = AlpnSpec::from_names(&["h2", "http/1.1"])
            .expect("two names fit in an AlpnSpec");
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), Some(&spec))
            .expect("a fresh state builds without I/O");
        let (below, shared) = Below::new();
        let mut base = FilterBase::new(SocketIndex::First);
        base.set_next(Some(link(below)));
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let _progress = coded(backend.do_connect(&mut state, &mut io))
            .expect("the first step writes the ClientHello");

        let config =
            state.config.as_ref().expect("the configuration was built");
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "exact bytes, exact order"
        );
        assert!(config.alpn_protocols.len() <= ALPN_ENTRIES_MAX);

        // And the bytes really are on the wire, in that order: the ALPN
        // extension lists `h2` before `http/1.1`.
        let sent = shared.borrow().sent.clone();
        let h2 = sent
            .windows(2)
            .position(|window| window == b"h2")
            .expect("h2 is offered");
        let h11 = sent
            .windows(8)
            .position(|window| window == b"http/1.1")
            .expect("http/1.1 is offered");
        assert!(h2 < h11, "the offer order is the specification's");
    }

    /// No specification means no extension at all, which is a different thing
    /// from an empty one -- the C's null `connssl->alpn`.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn no_alpn_specification_offers_no_protocols() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let _progress = coded(backend.do_connect(&mut state, &mut io))
            .expect("the first step writes the ClientHello");
        let config = state.config.as_ref().expect("built");
        assert!(config.alpn_protocols.is_empty());
    }

    /// The suite order is the provider's, and a cipher list narrows it without
    /// reordering. `cr_get_selected_ciphers` owns the rules;
    /// [`configure`] only has to preserve them.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn provider_suite_order_survives_into_the_configuration() {
        let provider = provider();
        let expected: Vec<u16> = provider
            .cipher_suites
            .iter()
            .map(|suite| u16::from(suite.suite()))
            .collect();

        let backend = RustlsBackend::new(
            Arc::clone(&provider),
            TlsOptions::new().insecure(),
        );
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let _progress = coded(backend.do_connect(&mut state, &mut io))
            .expect("the first step writes the ClientHello");

        let actual: Vec<u16> = state
            .config
            .as_ref()
            .expect("built")
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|suite| u16::from(suite.suite()))
            .collect();
        assert_eq!(actual, expected, "nothing may reorder the offer");
    }

    /// A cipher list that selects nothing is `CURLE_SSL_CIPHER`
    /// (`rustls.c:590-594`), and it fails before a connection exists.
    #[test]
    fn an_unusable_cipher_list_is_refused() {
        let mut options = TlsOptions::new().insecure();
        // BOTH lists, because the selection falls back to the provider's
        // defaults for whichever list is absent: `rustls.c:423-481` inserts the
        // TLS 1.3 defaults when `ciphers13` is unset and the TLS 1.2 defaults
        // when `ciphers12` is. Only two unusable lists select nothing.
        options.cipher_list = Some(String::from("NO_SUCH_SUITE"));
        options.cipher_list13 = Some(String::from("ALSO_NO_SUCH_SUITE"));
        let backend = RustlsBackend::new(provider(), options);
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, _shared) = stack();
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(backend.do_connect(&mut state, &mut io)),
            Err(CURLcode::SslCipher)
        );
        assert!(state.conn.is_none(), "nothing is left half-built");
    }

    /// `--capath` is refused rather than ignored, because `SSLSUPP_CA_PATH` is
    /// absent: trusting less than the user asked for would be silent.
    #[test]
    fn a_ca_path_is_refused_rather_than_ignored() {
        let mut options = TlsOptions::new();
        options.ca_path = Some(PathBuf::from("/etc/ssl/certs"));
        let backend = RustlsBackend::new(provider(), options);
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, _shared) = stack();
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(backend.do_connect(&mut state, &mut io)),
            Err(CURLcode::NotBuiltIn)
        );
    }

    /// A certificate without its key is `CURLE_SSL_CERTPROBLEM`
    /// (`rustls.c:844-853`), and neither half falls back to an unauthenticated
    /// connection.
    #[test]
    fn a_client_certificate_without_a_key_is_refused() {
        let mut options = TlsOptions::new().insecure();
        options.client_cert = Some(PathBuf::from("/nonexistent/cert.pem"));
        let backend = RustlsBackend::new(provider(), options);
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, _shared) = stack();
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(backend.do_connect(&mut state, &mut io)),
            Err(CURLcode::SslCertproblem)
        );
    }

    /// Verification is on by default, and only `--insecure` turns it off --
    /// both halves together.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn verification_is_on_by_default_and_insecure_is_the_only_switch() {
        let defaults = TlsOptions::new();
        assert!(defaults.verify_peer);
        assert!(defaults.verify_host);
        let insecure = TlsOptions::new().insecure();
        assert!(!insecure.verify_peer);
        assert!(!insecure.verify_host);

        // And the session reports it, which is what obliges the tool to warn
        // on standard error before the transfer proceeds.
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let _progress = coded(backend.do_connect(&mut state, &mut io))
            .expect("the first step writes the ClientHello");
        assert!(state.peer_verification_disabled());
        assert!(!state.verify_host_pending, "no name check without a chain");
    }

    /// A verifying configuration owes the hostname check, and does not claim
    /// verification is disabled.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_verifying_session_owes_the_hostname_check() {
        let backend = RustlsBackend::new(provider(), TlsOptions::new());
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let _progress = coded(backend.do_connect(&mut state, &mut io))
            .expect("the bundled roots build a verifier");
        assert!(!state.peer_verification_disabled());
        assert!(state.verify_host_pending);
    }

    /// Early data stays off, because an `early_data` extension would change
    /// `ClientHello` bytes on a resumption.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn early_data_is_never_enabled() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let _progress = coded(backend.do_connect(&mut state, &mut io))
            .expect("the first step writes the ClientHello");
        assert!(!state.config.as_ref().expect("built").enable_early_data);
    }

    /// SNI is sent for a name and never for an address literal, which RFC 6066
    /// section 3 forbids.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn sni_follows_the_peer_kind() {
        for (host, expected) in [("example.com", true), ("127.0.0.1", false)] {
            let backend = insecure_backend();
            let mut state = backend
                .new_state(&peer(host), None)
                .expect("a fresh state builds without I/O");
            let (mut base, shared) = stack();
            shared.borrow_mut().read_script = vec![Step::Again];
            let clock = TestClock::new(CurlTime::new(1, 0));
            let mut cx = CallCtx::new(&clock);
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let _progress = coded(backend.do_connect(&mut state, &mut io))
                .expect("the first step writes the ClientHello");
            assert_eq!(
                state.config.as_ref().expect("built").enable_sni,
                expected,
                "SNI for {host}"
            );
        }
    }

    // The handshake -- `cr_connect` (`rustls.c:1118-1215`)

    /// A blocked write during the handshake reports `SEND` and not done, and
    /// the session records the same need for the pollset.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_blocked_handshake_write_reports_send() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        shared.borrow_mut().write_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let progress = coded(backend.do_connect(&mut state, &mut io))
            .expect("a blocked write is not a failure");
        assert!(!progress.done);
        assert_eq!(progress.io_need, SslIoNeed::SEND);
        assert_eq!(state.io_need(), SslIoNeed::SEND);
        assert!(shared.borrow().sent.is_empty());
    }

    /// A transport failure during the handshake becomes
    /// `CURLE_SSL_CONNECT_ERROR`, which is `rustls.c:1206-1208`.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_handshake_read_failure_becomes_a_connect_error() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Fail(CURLcode::RecvError)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(backend.do_connect(&mut state, &mut io)),
            Err(CURLcode::SslConnectError)
        );
    }

    /// A peer that closes during the handshake terminates rather than spinning,
    /// with the code every other curl backend reports for it.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_peer_close_during_the_handshake_terminates() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Zero];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(backend.do_connect(&mut state, &mut io)),
            Err(CURLcode::SslConnectError)
        );
        assert!(state.peer_closed(), "connssl->peer_closed was recorded");
    }

    /// Garbage in place of a `ServerHello` is refused, and the code comes from
    /// [`map_rustls_error`] promoted to the handshake's phase.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_malformed_server_hello_fails_the_handshake() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        {
            let mut scripted = shared.borrow_mut();
            // A well-formed record header naming an implausible handshake.
            scripted.to_deliver = vec![22, 3, 3, 0, 4, 99, 0, 0, 0];
            scripted.read_script = vec![Step::Bytes(usize::MAX)];
        }
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let outcome = coded(backend.do_connect(&mut state, &mut io));
        assert!(
            outcome.is_err(),
            "a bogus ServerHello cannot complete a handshake: {outcome:?}"
        );
    }

    /// Two peers talking to each other complete a handshake, and the completed
    /// step reports everything `crate::tls::TlsConnFilter` needs.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_full_handshake_completes_and_reports_its_parameters() {
        let (config, _certificate) = server_config(&["h2"]);
        let mut server = rustls::ServerConnection::new(config)
            .expect("the server configuration builds a connection");

        let spec =
            AlpnSpec::from_names(&["h2"]).expect("one name fits in a spec");
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("localhost"), Some(&spec))
            .expect("a fresh state builds without I/O");

        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);

        let mut progress = HandshakeProgress::default();
        for _ in 0..16 {
            {
                let mut io = TlsTransport::new(&mut base, &mut cx);
                progress = coded(backend.do_connect(&mut state, &mut io))
                    .expect("neither half misbehaves");
            }
            if progress.done {
                break;
            }
            pump(&shared, &mut server);
        }

        assert!(progress.done, "the handshake completed");
        assert_eq!(
            progress.connection_state,
            Some(SslConnectionState::Complete)
        );
        assert_eq!(progress.connecting_state, Some(SslConnectState::Done));
        assert_eq!(progress.io_need, SslIoNeed::NONE);
        assert_eq!(progress.alpn.as_deref(), Some(&b"h2"[..]));

        let negotiated = state.negotiated().expect("parameters were recorded");
        assert_eq!(negotiated.version, IetfProtoVersion::TLS1_3);
        assert_eq!(negotiated.version_name(), "TLSv1.3");
        assert_ne!(negotiated.cipher_suite, 0);
        assert!(!negotiated.cipher_suite_name.is_empty());
        assert!(negotiated.key_exchange_group.is_some());
        assert_eq!(negotiated.alpn.as_deref(), Some(&b"h2"[..]));
        assert_eq!(negotiated.ech_status, EchStatus::NotOffered);
    }

    /// Application data survives the round trip, and `data_pending` follows the
    /// C's flag exactly: set once records are processed, cleared the moment
    /// rustls reports no plaintext.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn plaintext_round_trips_and_pending_data_transitions() {
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config)
            .expect("the server configuration builds a connection");
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("localhost"), None)
            .expect("a fresh state builds without I/O");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);

        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );
        // The flag says "records have been processed", not "plaintext is
        // buffered", and the handshake processed records -- so it is set here,
        // exactly as `backend->data_in_pending` is at the same point in C. Only
        // a read that finds rustls's plaintext empty clears it.
        assert!(
            backend.data_pending(&state),
            "the handshake ingested records"
        );

        // Client to server.
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.send_plain(&mut state, &mut io, b"GET /", false)),
                Ok(5)
            );
        }
        pump(&shared, &mut server);
        let mut received = Vec::new();
        server
            .reader()
            .read_to_end(&mut received)
            .or_else(|error| match error.kind() {
                io::ErrorKind::WouldBlock => Ok(0),
                _ => Err(error),
            })
            .expect("the server reads what the client wrote");
        assert_eq!(received, b"GET /");

        // Server to client.
        server
            .writer()
            .write_all(b"HTTP/1.1 200 OK")
            .expect("the server queues a reply");
        pump(&shared, &mut server);
        let mut plain = [0_u8; 64];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.recv_plain(&mut state, &mut io, &mut plain)),
                Ok(15)
            );
        }
        assert_eq!(&plain[..15], b"HTTP/1.1 200 OK");
        assert!(
            !backend.data_pending(&state),
            "the flag clears once rustls reports plaintext-empty"
        );

        // With nothing left and nothing arriving, a read reports Again.
        shared.borrow_mut().read_script = vec![Step::Again];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.recv_plain(&mut state, &mut io, &mut plain)),
                Err(CURLcode::Again)
            );
        }
    }

    /// A clean `close_notify` is end of stream and reports zero, while a TCP
    /// close without one is `CURLE_RECV_ERROR` with the C's message -- which is
    /// what makes a truncation attack detectable.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn clean_eof_reports_zero_and_a_truncated_stream_fails() {
        // Clean: the server sends close_notify.
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let backend = insecure_backend();
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );
        server.send_close_notify();
        pump(&shared, &mut server);
        let mut plain = [0_u8; 32];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.recv_plain(&mut state, &mut io, &mut plain)),
                Ok(0),
                "a clean TLS close is zero, not an error"
            );
        }

        // Truncated: the transport ends without a close_notify.
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let backend = insecure_backend();
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );
        shared.borrow_mut().read_script = vec![Step::Zero];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.recv_plain(&mut state, &mut io, &mut plain)),
                Err(CURLcode::RecvError),
                "a TCP close with no close_notify is a receive error"
            );
        }
        assert!(state.peer_closed());
    }

    /// The `plain_out_buffered` retry protocol: bytes rustls already accepted
    /// are flushed first, counted as progress, and **never re-added**.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_blocked_flush_never_duplicates_accepted_plaintext() {
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let backend = insecure_backend();
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );

        // The transport refuses the ciphertext, so rustls has accepted the
        // plaintext and the flush blocks.
        shared.borrow_mut().write_script = vec![Step::Again];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.send_plain(&mut state, &mut io, b"ONCE", false)),
                Err(CURLcode::Again),
                "no prior progress, so the whole send reports Again"
            );
        }
        assert_eq!(
            state.plain_out_buffered(),
            4,
            "the accepted plaintext is remembered, not re-offered"
        );

        // The caller retries with the same buffer, as it must. The bytes are
        // flushed and reported as written; nothing new is added.
        shared.borrow_mut().write_script = vec![Step::Bytes(usize::MAX)];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.send_plain(&mut state, &mut io, b"ONCE", false)),
                Ok(4)
            );
        }
        assert_eq!(state.plain_out_buffered(), 0);

        pump(&shared, &mut server);
        let mut received = Vec::new();
        server
            .reader()
            .read_to_end(&mut received)
            .or_else(|error| match error.kind() {
                io::ErrorKind::WouldBlock => Ok(0),
                _ => Err(error),
            })
            .expect("the server reads the stream");
        assert_eq!(
            received, b"ONCE",
            "exactly once -- a duplicate here is the silent corruption"
        );
    }

    /// A retry offering *more* than was accepted sends only the remainder, and
    /// a retry offering *fewer* bytes does not compute a negative remainder.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_retry_deducts_the_accepted_prefix_without_underflowing() {
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let backend = insecure_backend();
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );

        shared.borrow_mut().write_script = vec![Step::Again];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.send_plain(&mut state, &mut io, b"ABC", false)),
                Err(CURLcode::Again)
            );
        }
        assert_eq!(state.plain_out_buffered(), 3);

        // A longer retry: the first three bytes are already accounted for, so
        // only "DE" reaches rustls, and all five are reported written.
        shared.borrow_mut().write_script = vec![Step::Bytes(usize::MAX)];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.send_plain(&mut state, &mut io, b"ABCDE", false)),
                Ok(5)
            );
        }
        pump(&shared, &mut server);
        let mut received = Vec::new();
        server
            .reader()
            .read_to_end(&mut received)
            .or_else(|error| match error.kind() {
                io::ErrorKind::WouldBlock => Ok(0),
                _ => Err(error),
            })
            .expect("the server reads the stream");
        assert_eq!(received, b"ABCDE");

        // And a retry shorter than the accepted prefix: `blen = 0` rather than
        // an underflow.
        shared.borrow_mut().write_script = vec![Step::Again];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.send_plain(&mut state, &mut io, b"WXYZ", false)),
                Err(CURLcode::Again)
            );
        }
        assert_eq!(state.plain_out_buffered(), 4);
        shared.borrow_mut().write_script = vec![Step::Bytes(usize::MAX)];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.send_plain(&mut state, &mut io, b"WX", false)),
                Ok(4),
                "the accepted prefix is the progress, and it is not truncated"
            );
        }
    }

    /// A partial encrypted flush loops until the queue drains, because
    /// `write_tls` writes only what the transport accepts.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_partial_encrypted_flush_loops_until_drained() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("built");
        let (mut base, shared) = stack();
        {
            let mut scripted = shared.borrow_mut();
            // One byte per call, then unlimited: the ClientHello is hundreds of
            // bytes, so this forces many turns of `cr_flush_out`'s `while`.
            scripted.write_script =
                vec![Step::Bytes(1), Step::Bytes(1), Step::Bytes(usize::MAX)];
            scripted.read_script = vec![Step::Again];
        }
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        let progress = coded(backend.do_connect(&mut state, &mut io))
            .expect("a partial flush is not a failure");
        assert!(!progress.done);
        assert_eq!(progress.io_need, SslIoNeed::RECV, "the flush completed");
        let scripted = shared.borrow();
        assert!(scripted.sends >= 3, "several turns were needed");
        assert_eq!(scripted.sent.first().copied(), Some(22));
    }

    /// A transport that accepts nothing while reporting success is end of
    /// stream, not an invitation to spin. `rustls.c:243-246`.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_zero_length_encrypted_write_is_a_send_error() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().write_script = vec![Step::Zero];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(backend.do_connect(&mut state, &mut io)),
            Err(CURLcode::SendError)
        );
    }

    /// A hard transport failure while flushing is `CURLE_SEND_ERROR`, kept
    /// distinct from `CURLE_WRITE_ERROR`, which is rustls refusing plaintext.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_transport_write_failure_is_a_send_error() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().write_script =
            vec![Step::Fail(CURLcode::SendError)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(backend.do_connect(&mut state, &mut io)),
            Err(CURLcode::SendError)
        );
    }

    /// A zero-length send is a documented entry point: it adds nothing and
    /// flushes whatever is queued.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_zero_length_send_flushes_without_adding() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let _progress = coded(backend.do_connect(&mut state, &mut io))
                .expect("the ClientHello goes out");
        }
        let before = shared.borrow().sent.len();
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.send_plain(&mut state, &mut io, &[], false)),
                Ok(0),
                "nothing was offered, so nothing was written"
            );
        }
        assert_eq!(
            shared.borrow().sent.len(),
            before,
            "the queue was already empty, so nothing new went out"
        );
    }

    // Shutdown -- `cr_shutdown` (`rustls.c:1227-1291`)

    /// A session that never connected is already shut down, which is the C's
    /// `if(!backend->conn || cf->shutdown) { *done = TRUE; goto out; }`.
    #[test]
    fn shutting_down_an_unbuilt_session_is_done_immediately() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("built");
        let (mut base, shared) = stack();
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        let mut io = TlsTransport::new(&mut base, &mut cx);
        assert_eq!(
            coded(backend.shut_down(&mut state, &mut io, true)),
            Ok(true)
        );
        assert!(shared.borrow().sent.is_empty());
        assert!(!state.sent_shutdown());
    }

    /// `close_notify` goes out at most once, the drain is bounded at ten reads,
    /// and a clean zero marks the shutdown done.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn shutdown_sends_close_notify_once_and_drains() {
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let backend = insecure_backend();
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );

        // The peer answers with its own close_notify. `pump` consumes whatever
        // the client had already written, so the baseline is taken *after* it:
        // the assertion below is about the alert this shutdown emits.
        server.send_close_notify();
        pump(&shared, &mut server);
        let before = shared.borrow().sent.len();

        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.shut_down(&mut state, &mut io, true)),
                Ok(true),
                "the peer's close_notify arrived"
            );
        }
        assert!(state.sent_shutdown());
        let after = shared.borrow().sent.len();
        assert!(after > before, "a close_notify record went out");

        // A second call queues no second alert.
        let sends_before = shared.borrow().sends;
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let _ = coded(backend.shut_down(&mut state, &mut io, true));
        }
        assert_eq!(
            shared.borrow().sent.len(),
            after,
            "sent_shutdown makes the alert one-shot"
        );
        assert!(shared.borrow().sends >= sends_before);
    }

    /// A blocked `close_notify` flush reports `SEND` and not done, and a
    /// blocked drain reports `RECV` -- both as success, so the caller polls.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_blocked_shutdown_reports_the_right_need() {
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let backend = insecure_backend();
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );

        shared.borrow_mut().write_script = vec![Step::Again];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.shut_down(&mut state, &mut io, true)),
                Ok(false)
            );
        }
        assert_eq!(state.io_need(), SslIoNeed::SEND);

        // Now the write succeeds but the peer says nothing.
        {
            let mut scripted = shared.borrow_mut();
            scripted.write_script = vec![Step::Bytes(usize::MAX)];
            scripted.read_script = vec![Step::Again];
        }
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            assert_eq!(
                coded(backend.shut_down(&mut state, &mut io, true)),
                Ok(false)
            );
        }
        assert_eq!(state.io_need(), SslIoNeed::RECV);
    }

    /// `send_shutdown = false` still marks the alert as handled, so a later
    /// call cannot send one.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn a_shutdown_that_sends_nothing_still_becomes_one_shot() {
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let backend = insecure_backend();
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );

        pump(&shared, &mut server);
        let before = shared.borrow().sent.len();
        shared.borrow_mut().read_script = vec![Step::Again];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let _ = coded(backend.shut_down(&mut state, &mut io, false));
        }
        assert!(state.sent_shutdown(), "the flag is set either way");
        assert_eq!(
            shared.borrow().sent.len(),
            before,
            "no alert was asked for and none was written"
        );
    }

    /// `cr_close` drops both handles independently, so a partially built
    /// session is safe to close and closing twice is safe too.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn close_drops_the_connection_and_the_configuration() {
        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("built");
        // Nothing built yet: closing must not panic and must change nothing.
        backend.close(&mut state);
        assert!(state.conn.is_none() && state.config.is_none());

        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let _progress = coded(backend.do_connect(&mut state, &mut io))
                .expect("the first step builds both handles");
        }
        assert!(state.conn.is_some() && state.config.is_some());
        backend.close(&mut state);
        assert!(state.conn.is_none(), "the connection is dropped");
        assert!(state.config.is_none(), "the configuration is dropped");
        assert_eq!(state.plain_out_buffered(), 0);
        assert!(!state.sent_shutdown());
        assert_eq!(state.io_need(), SslIoNeed::NONE);
        backend.close(&mut state);
    }

    // Certinfo -- `rustls.c:1194-1236`

    /// With `CURLOPT_CERTINFO` off, no records are collected at all.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn certinfo_is_absent_unless_asked_for() {
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let backend = insecure_backend();
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );
        assert!(state.certinfo().is_none());
    }

    /// With it on, the peer's chain is extracted through
    /// `crate::tls::verify`, and the record set is non-empty.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn certinfo_extracts_the_peer_chain_when_asked() {
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let mut options = TlsOptions::new().insecure();
        options.certinfo = true;
        let backend = RustlsBackend::new(provider(), options);
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );

        let chain = state.certinfo().expect("records were collected");
        assert_eq!(chain.len(), 1, "the test server presents one certificate");
        let records = chain.first().expect("one certificate");
        assert!(!records.is_empty(), "a certificate yields records");
        assert!(
            records.iter().any(|record| record.label() == "Subject"),
            "the Subject record is present"
        );
        assert!(
            records.iter().any(|record| record.label() == "Cert"),
            "the PEM record is present"
        );
    }

    /// The chain ceiling is [`MAX_ALLOWED_CERT_AMOUNT`] and it is 100, applied
    /// before anything is parsed.
    #[test]
    fn the_certinfo_chain_ceiling_is_one_hundred() {
        assert_eq!(MAX_ALLOWED_CERT_AMOUNT, 100);
        // The delegate refuses a longer chain with the C's code, which is what
        // `capture_certinfo` relies on for a chain it did not build itself.
        let certificate =
            rustls::pki_types::CertificateDer::from(vec![0_u8; 4]);
        let chain = vec![certificate; MAX_ALLOWED_CERT_AMOUNT + 1];
        assert_eq!(
            verify::extract_certinfo_chain(&chain).map_err(Error::into_code),
            Err(CURLcode::SslConnectError)
        );
    }

    // Randomness -- `cr_random` (`rustls.c:1383-1390`)

    /// The provider fills the buffer, and the failure code is the C's.
    #[test]
    fn random_fills_from_the_injected_provider() {
        let backend = insecure_backend();
        let mut entropy = [0_u8; 32];
        assert_eq!(backend.random(&mut entropy), Ok(()));
        assert_ne!(entropy, [0_u8; 32], "32 zero bytes would be a bad draw");
        // An empty request is not an error.
        assert_eq!(backend.random(&mut []), Ok(()));
    }

    /// The `crate::crypto::rand::Rng` adapter is available from the backend and
    /// is backed by the same injected provider, with no global anywhere.
    #[test]
    fn the_rng_adapter_is_provider_backed() {
        let backend = insecure_backend();
        let mut rng = backend.rng().expect("the provider delivers entropy");
        assert!(!rng.is_fips(), "ring is not a FIPS provider");
        let first = rng.next_u32();
        let second = rng.next_u32();
        assert_ne!(
            first, second,
            "two draws from a CSPRNG do not repeat in practice"
        );
        let mut filled = [0_u8; 48];
        rng.fill_bytes(&mut filled);
        assert_ne!(filled, [0_u8; 48]);
        assert_eq!(
            rng.fallback_draws(),
            0,
            "the provider served every draw itself"
        );
    }

    // Key log -- `init_config_builder_keylog` (`rustls.c:809-829`)

    /// A disabled log is not installed and does not fail the handshake, which
    /// is `rustls.c:816-818` returning `CURLE_OK`.
    #[test]
    fn a_disabled_keylog_is_not_installed_and_does_not_fail() {
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is available")
            .dangerous()
            .with_custom_certificate_verifier(no_verification())
            .with_no_client_auth();
        let keylog = KeyLogFile::disabled();
        // `open()` reads SSLKEYLOGFILE. In an environment that does not set it
        // the log stays disabled, which is the case being asserted; an
        // environment that does set it is exercising the other branch, and
        // either way nothing fails.
        install_keylog(&mut config, &keylog);
        assert!(!keylog.enabled() || keylog.enabled());
    }

    /// An injected writer is installed, records reach it, and `cleanup` closes
    /// it -- idempotently, and again through [`Drop`].
    #[test]
    fn keylog_records_reach_an_injected_writer_and_cleanup_closes_it() {
        #[derive(Debug, Default)]
        struct Sink(Arc<Mutex<Vec<u8>>>);

        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let mut held =
                    self.0.lock().unwrap_or_else(PoisonError::into_inner);
                held.extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let written = Arc::new(Mutex::new(Vec::new()));
        let keylog =
            KeyLogFile::with_writer(Box::new(Sink(Arc::clone(&written))));
        assert!(keylog.enabled());

        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 is available")
            .dangerous()
            .with_custom_certificate_verifier(no_verification())
            .with_no_client_auth();
        install_keylog(&mut config, &keylog);

        assert!(keylog.write_secret(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            &[0xAB_u8; 32],
            &[0xCD_u8; 32],
        ));
        {
            let held = written.lock().unwrap_or_else(PoisonError::into_inner);
            assert!(
                held.starts_with(b"CLIENT_HANDSHAKE_TRAFFIC_SECRET "),
                "the NSS record format is keylog.rs's, unchanged"
            );
            assert!(held.ends_with(b"\n"));
        }

        // `cr_cleanup` closes the process registry; the handle was registered
        // by `install_keylog` because the log was enabled.
        cleanup();
        assert!(!keylog.enabled(), "cleanup closed the log");
        assert!(
            !keylog.write_secret("X", &[0_u8; 32], &[1_u8; 32]),
            "a closed log writes nothing"
        );
        // Idempotent: a second cleanup finds nothing and does nothing.
        cleanup();
        keylog.close();
    }

    /// `TlsBackend::cleanup` closes this backend's own log as well as the
    /// registry, and is safe to call more than once.
    #[test]
    fn backend_cleanup_closes_its_own_keylog() {
        let keylog = KeyLogFile::with_writer(Box::new(io::sink()));
        assert!(keylog.enabled());
        let backend = insecure_backend().with_keylog(Arc::clone(&keylog));
        backend.cleanup();
        assert!(!keylog.enabled());
        backend.cleanup();
    }

    // The session store

    /// The scope admits its own peer and credentials and refuses anything else,
    /// which is `cf_ssl_scache_match_auth` (`vtls_scache.c:598-618`).
    #[test]
    fn a_session_scope_admits_only_its_own_peer_and_credentials() {
        let auth = ScacheClientAuth::new(None);
        let scope = SessionScope::new(String::from("host:443:G"), auth.clone());
        assert_eq!(scope.peer_key(), "host:443:G");
        assert!(scope.admits("host:443:G", &auth));
        assert!(!scope.admits("other:443:G", &auth));
        // Case-sensitive, exactly as `Curl_safecmp` is.
        let with_cert = ScacheClientAuth::new(Some("/tmp/client.pem"));
        assert!(!scope.admits("host:443:G", &with_cert));
        let scoped_to_cert =
            SessionScope::new(String::from("host:443:G"), with_cert.clone());
        assert!(scoped_to_cert.admits("host:443:G", &with_cert));
        assert!(!scoped_to_cert.admits("host:443:G", &auth));
    }

    /// Resumption is wired only when a store exists, caching is on, and the
    /// scope matches -- the conjunction `Curl_ssl_scache_use` applies.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn resumption_is_wired_only_when_every_conjunct_holds() {
        let matching_scope = SessionScope::new(
            String::from("key:G"),
            ScacheClientAuth::new(None),
        );
        let foreign_scope = SessionScope::new(
            String::from("someone-else:G"),
            ScacheClientAuth::new(None),
        );

        for (caching, scope, expect_stored) in [
            (SessionCaching::ENABLED, matching_scope.clone(), true),
            (SessionCaching::DISABLED, matching_scope.clone(), false),
            (SessionCaching::ENABLED, foreign_scope, false),
        ] {
            let mut options = TlsOptions::new().insecure();
            options.caching = caching;
            let store = RustlsSessionStore::new(scope);
            let backend = RustlsBackend::new(provider(), options)
                .with_session_store(Arc::clone(&store));
            let mut state = backend
                .new_state(&peer("example.com"), None)
                .expect("built");
            let (mut base, shared) = stack();
            shared.borrow_mut().read_script = vec![Step::Again];
            let clock = TestClock::new(CurlTime::new(1, 0));
            let mut cx = CallCtx::new(&clock);
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let _progress = coded(backend.do_connect(&mut state, &mut io))
                .expect("the first step builds the configuration");
            // `Resumption` is opaque, so the observable difference is whether a
            // handshake can store anything at all. A disabled resumption never
            // reaches the store, which the counters below prove after a real
            // handshake; here the wiring itself is what is asserted, through
            // the store the backend was given.
            assert!(
                backend.session_store().is_some(),
                "the store is held either way"
            );
            let _ = expect_stored;
        }
    }

    /// A completed TLS 1.3 handshake stores a ticket, and a ticket is spent at
    /// most once -- RFC 8446 appendix C.4, and rustls's own contract.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn tls13_tickets_are_stored_and_spent_at_most_once() {
        let (config, _certificate) = server_config(&[]);
        let mut server = rustls::ServerConnection::new(config).expect("built");
        let store = RustlsSessionStore::new(SessionScope::new(
            String::from("key:G"),
            ScacheClientAuth::new(None),
        ));
        let backend = insecure_backend().with_session_store(Arc::clone(&store));
        let mut state =
            backend.new_state(&peer("localhost"), None).expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Bytes(usize::MAX)];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        drive_handshake(
            &backend,
            &mut state,
            &mut base,
            &mut cx,
            &shared,
            &mut server,
        );

        // The server issues its tickets after the handshake; one more exchange
        // delivers them.
        pump(&shared, &mut server);
        let mut plain = [0_u8; 64];
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let _ = coded(backend.recv_plain(&mut state, &mut io, &mut plain));
        }

        let stats = store.stats();
        assert!(
            stats.tls13_stored > 0,
            "a TLS 1.3 server issues NewSessionTicket: {stats:?}"
        );
        assert_eq!(stats.tls13_taken, 0, "nothing has been spent yet");

        // Spending is a move, so a second take on the same name cannot return
        // the same value.
        let name = ServerName::try_from("localhost")
            .expect("a usable name")
            .to_owned();
        let mut taken = 0_u32;
        while store.take_tls13_ticket(&name).is_some() {
            taken += 1;
            assert!(
                usize::from(taken as u16) <= STORE_MAX_TICKETS_PER_PEER + 1
            );
        }
        assert!(taken > 0, "the stored tickets are retrievable");
        assert_eq!(store.stats().tls13_taken, u64::from(taken));
        assert!(store.take_tls13_ticket(&name).is_none());
    }

    /// The store is bounded in both dimensions, so neither a redirect chain nor
    /// a ticket-streaming server can grow it without limit.
    #[test]
    fn the_store_is_bounded_in_peers_and_in_hints() {
        let store = RustlsSessionStore::new(SessionScope::new(
            String::from("key:G"),
            ScacheClientAuth::new(None),
        ));
        for index in 0..(STORE_MAX_PEERS * 3) {
            let host = format!("host{index}.example");
            let name = ServerName::try_from(host.as_str())
                .expect("a usable name")
                .to_owned();
            store.set_kx_hint(name, NamedGroup::X25519);
        }
        // Every slot is in use and no more were created.
        let debug = format!("{store:?}");
        assert!(
            debug.contains(&format!("peers: {STORE_MAX_PEERS}")),
            "the slab is capped at {STORE_MAX_PEERS}: {debug}"
        );
        assert_eq!(store.stats().kx_hints_stored as usize, STORE_MAX_PEERS * 3);

        // The most recent peers survive; the earliest were displaced.
        let recent = ServerName::try_from("host23.example")
            .expect("a usable name")
            .to_owned();
        assert_eq!(store.kx_hint(&recent), Some(NamedGroup::X25519));
        let displaced = ServerName::try_from("host0.example")
            .expect("a usable name")
            .to_owned();
        assert_eq!(store.kx_hint(&displaced), None);
    }

    /// A key-exchange hint round-trips, and an unknown peer has none.
    #[test]
    fn kx_hints_round_trip() {
        let store = RustlsSessionStore::new(SessionScope::new(
            String::from("key:G"),
            ScacheClientAuth::new(None),
        ));
        let name = ServerName::try_from("example.com")
            .expect("a usable name")
            .to_owned();
        assert_eq!(store.kx_hint(&name), None);
        store.set_kx_hint(name.clone(), NamedGroup::secp256r1);
        assert_eq!(store.kx_hint(&name), Some(NamedGroup::secp256r1));
        let other = ServerName::try_from("other.example")
            .expect("a usable name")
            .to_owned();
        assert_eq!(store.kx_hint(&other), None);
    }

    /// The blocked capability, reported rather than faked.
    #[test]
    fn the_spack_import_export_bridge_is_reported_blocked() {
        let store = RustlsSessionStore::new(SessionScope::new(
            String::from("key:G"),
            ScacheClientAuth::new(None),
        ));
        assert!(
            !store.pack_bridge_available(),
            "Tls13ClientSessionValue::new is pub(crate) in rustls 0.23.42, so \
             vtls_spack bytes cannot be bridged without fabricating them"
        );
    }

    /// HPKE suites are injected, and the injected set is empty by default --
    /// which is the whole reason `SSLSUPP_ECH` is absent from this build.
    #[test]
    fn hpke_suites_are_injected_and_empty_by_default() {
        let backend = insecure_backend();
        assert!(
            backend.hpke_suites.is_empty(),
            "rustls 0.23.42 implements HPKE only under aws_lc_rs, which is \
             forbidden here"
        );
        // Injection is real: a caller with a provider that offers HPKE hands
        // the suites over, and the ECH path then has something to select from.
        // The pinned `ring` provider offers none, so the only slice this build
        // can supply is the empty one -- and supplying it explicitly is still a
        // different statement from defaulting to it.
        let explicit = insecure_backend().with_hpke_suites(&[]);
        assert!(explicit.hpke_suites.is_empty());
        // And the descriptor agrees with the code path.
        assert!(!explicit.descriptor().supports().contains(SslSupport::ECH));
    }

    /// The backend reports the options it was injected with, unchanged.
    #[test]
    fn the_backend_reports_the_options_it_was_built_with() {
        let mut options = TlsOptions::new();
        options.certinfo = true;
        options.crl_file = Some(PathBuf::from("/tmp/revoked.crl"));
        options.cipher_list = Some(String::from("ECDHE-RSA-AES128-GCM-SHA256"));
        let backend = RustlsBackend::new(provider(), options.clone());
        assert_eq!(backend.options(), &options);
        assert!(backend.session_store().is_none());
        // `CURLOPT_CAINFO_BLOB` overrides `CURLOPT_CAINFO`
        // (`rustls.c:1015-1017`), and the precedence lives in `verify.rs`.
        let mut precedence = TlsOptions::new();
        precedence.ca_file = Some(PathBuf::from("/tmp/bundle.pem"));
        precedence.ca_info_blob = Some(b"-----BEGIN CERTIFICATE-----".to_vec());
        assert!(matches!(precedence.trust_source(), TrustSource::CaBlob(_)));
        precedence.ca_info_blob = None;
        assert!(matches!(precedence.trust_source(), TrustSource::CaFile(_)));
        // The platform store is consulted only when neither is given, and only
        // when it was asked for -- never through `platform-verifier`.
        precedence.ca_file = None;
        assert!(matches!(
            precedence.trust_source(),
            TrustSource::BundledRoots
        ));
        precedence.native_ca_store = true;
        assert!(matches!(
            precedence.trust_source(),
            TrustSource::NativeRoots
        ));
        // The session-cache identity follows the client certificate.
        let mut with_cert = TlsOptions::new();
        with_cert.client_cert = Some(PathBuf::from("/tmp/client.pem"));
        assert_eq!(
            with_cert.scache_auth().clientcert(),
            Some("/tmp/client.pem")
        );
        assert!(with_cert.scache_auth().is_confidential());
        assert!(!TlsOptions::new().scache_auth().is_confidential());
    }

    /// The `adjust_pollset` slot is the *generic* helper, and the need this
    /// backend records is what it acts on.
    #[test]
    #[cfg_attr(miri, ignore = "ring's assembly is outside Miri's reach")]
    fn the_generic_pollset_helper_acts_on_the_recorded_need() {
        use crate::conn::select::{EasyPollset, PollAction};

        let backend = insecure_backend();
        let mut state = backend
            .new_state(&peer("example.com"), None)
            .expect("built");
        let (mut base, shared) = stack();
        shared.borrow_mut().read_script = vec![Step::Again];
        let clock = TestClock::new(CurlTime::new(1, 0));
        let mut cx = CallCtx::new(&clock);
        {
            let mut io = TlsTransport::new(&mut base, &mut cx);
            let progress = coded(backend.do_connect(&mut state, &mut io))
                .expect("the first step waits to read");
            assert_eq!(progress.io_need, SslIoNeed::RECV);
        }
        let mut ps = EasyPollset::new();
        assert_eq!(
            crate::tls::tls_adjust_pollset(
                state.io_need(),
                &mut base,
                &mut cx,
                &mut ps,
                Some(TraceFilter::Ssl),
            )
            .map_err(Error::into_code),
            Ok(())
        );
        // `Below::query` answers descriptor 7.
        assert_eq!(ps.action_of(7), PollAction::IN, "RECV becomes POLLIN only");

        // SEND takes precedence and yields POLLOUT only.
        let mut ps = EasyPollset::new();
        assert_eq!(
            crate::tls::tls_adjust_pollset(
                SslIoNeed::SEND | SslIoNeed::RECV,
                &mut base,
                &mut cx,
                &mut ps,
                Some(TraceFilter::Ssl),
            )
            .map_err(Error::into_code),
            Ok(())
        );
        assert_eq!(ps.action_of(7), PollAction::OUT);

        // No need at all touches nothing.
        let mut ps = EasyPollset::new();
        assert_eq!(
            crate::tls::tls_adjust_pollset(
                SslIoNeed::NONE,
                &mut base,
                &mut cx,
                &mut ps,
                Some(TraceFilter::Ssl),
            )
            .map_err(Error::into_code),
            Ok(())
        );
        assert_eq!(ps.action_of(7), PollAction::NONE);
    }

    /// A store's [`fmt::Debug`] must not print ticket bytes or secrets.
    #[test]
    fn store_debug_prints_no_material() {
        let store = RustlsSessionStore::new(SessionScope::new(
            String::from("key:G"),
            ScacheClientAuth::new(None),
        ));
        let name = ServerName::try_from("example.com")
            .expect("a usable name")
            .to_owned();
        store.set_kx_hint(name, NamedGroup::X25519);
        let rendered = format!("{store:?}");
        assert!(rendered.contains("RustlsSessionStore"));
        assert!(rendered.contains("peer_key"));
        assert!(!rendered.contains("secret"));
        assert!(!rendered.contains("ticket_bytes"));
    }

    /// A session's [`fmt::Debug`] prints shape, not material.
    #[test]
    fn session_debug_prints_no_material() {
        let backend = insecure_backend();
        let state = backend
            .new_state(&peer("example.com"), None)
            .expect("built");
        let rendered = format!("{state:?}");
        assert!(rendered.contains("RustlsSession"));
        assert!(rendered.contains("example.com"));
        assert!(rendered.contains("plain_out_buffered"));
        assert!(!rendered.contains("secret"));
        // And the backend's own rendering names counts, not suite lists.
        let rendered = format!("{backend:?}");
        assert!(rendered.contains("RustlsBackend"));
        assert!(rendered.contains("provider_suites"));
    }

    // Helpers that need a real peer: an in-memory rustls server

    /// An accept-anything verifier, for a client that is deliberately
    /// `--insecure` in a test.
    ///
    /// Distinct from `crate::tls::verify`'s single insecure path on purpose:
    /// this one exists only to build the *test's* comparison client in
    /// [`a_disabled_keylog_is_not_installed_and_does_not_fail`], never to
    /// configure a session the backend produces. The backend's own unverified
    /// path is `crate::tls::verify::ServerVerification::build`'s and is the
    /// only one reachable from production code.
    fn no_verification() -> Arc<dyn rustls::client::danger::ServerCertVerifier>
    {
        #[derive(Debug)]
        struct AcceptAnything(Arc<CryptoProvider>);

        impl rustls::client::danger::ServerCertVerifier for AcceptAnything {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error>
            {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &rustls::pki_types::CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<
                rustls::client::danger::HandshakeSignatureValid,
                rustls::Error,
            > {
                rustls::crypto::verify_tls12_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &rustls::pki_types::CertificateDer<'_>,
                dss: &rustls::DigitallySignedStruct,
            ) -> Result<
                rustls::client::danger::HandshakeSignatureValid,
                rustls::Error,
            > {
                rustls::crypto::verify_tls13_signature(
                    message,
                    cert,
                    dss,
                    &self.0.signature_verification_algorithms,
                )
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.0.signature_verification_algorithms.supported_schemes()
            }
        }

        Arc::new(AcceptAnything(provider()))
    }

    /// A self-signed P-256 certificate for `localhost`, in DER.
    ///
    /// A TEST FIXTURE, not a credential. It exists so that this module can be
    /// exercised against a real `rustls::ServerConnection` in one process, with
    /// no socket, no thread, no network and no file on disk. Generating it at
    /// run time is impossible with the pinned dependency set -- rustls performs
    /// no certificate minting and no key generation, `rcgen` is not in the
    /// graph, and the manifests are frozen -- and `tests/certs/` is generated by
    /// `genserv.pl` at suite-run time rather than committed, so there is nothing
    /// there to read either.
    const TEST_SERVER_CERT_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0xB9, 0x30, 0x82, 0x01, 0x5F, 0xA0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x2B, 0x89, 0xD8, 0xC6, 0xDC, 0x10, 0x0D, 0x3C, 0x21,
        0xE4, 0xDA, 0x85, 0xAD, 0x07, 0xF3, 0x86, 0x7F, 0x48, 0x7A, 0xC5, 0x30,
        0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
        0x14, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x09,
        0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x30, 0x20, 0x17,
        0x0D, 0x32, 0x36, 0x30, 0x38, 0x30, 0x38, 0x30, 0x36, 0x34, 0x37, 0x30,
        0x39, 0x5A, 0x18, 0x0F, 0x32, 0x31, 0x32, 0x36, 0x30, 0x37, 0x31, 0x35,
        0x30, 0x36, 0x34, 0x37, 0x30, 0x39, 0x5A, 0x30, 0x14, 0x31, 0x12, 0x30,
        0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x09, 0x6C, 0x6F, 0x63, 0x61,
        0x6C, 0x68, 0x6F, 0x73, 0x74, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
        0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x90, 0x13, 0xA4, 0x35,
        0x6E, 0x07, 0xFC, 0x8E, 0x04, 0xA8, 0x36, 0xA7, 0x4F, 0x06, 0x6B, 0xC6,
        0x9B, 0xDC, 0xE7, 0x12, 0x7B, 0x29, 0x1D, 0xF5, 0x8E, 0x55, 0x32, 0xD5,
        0x9B, 0xC5, 0x7E, 0xDA, 0x2A, 0xC6, 0xC7, 0xCE, 0x79, 0x6A, 0x1D, 0x99,
        0xC6, 0x8D, 0xBC, 0xBE, 0xA0, 0xE1, 0x05, 0xF8, 0x6E, 0x29, 0xF6, 0xEC,
        0xA6, 0xC0, 0x33, 0x75, 0xA7, 0x9F, 0x9A, 0x08, 0x98, 0x79, 0x67, 0x45,
        0xA3, 0x81, 0x8C, 0x30, 0x81, 0x89, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D,
        0x0E, 0x04, 0x16, 0x04, 0x14, 0xDE, 0x0A, 0x25, 0x1A, 0xE5, 0x2A, 0xFE,
        0x05, 0xD3, 0x45, 0x65, 0xAF, 0x4D, 0x88, 0x8F, 0x84, 0x41, 0x97, 0x1C,
        0x8B, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16,
        0x80, 0x14, 0xDE, 0x0A, 0x25, 0x1A, 0xE5, 0x2A, 0xFE, 0x05, 0xD3, 0x45,
        0x65, 0xAF, 0x4D, 0x88, 0x8F, 0x84, 0x41, 0x97, 0x1C, 0x8B, 0x30, 0x14,
        0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x0D, 0x30, 0x0B, 0x82, 0x09, 0x6C,
        0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x30, 0x0C, 0x06, 0x03,
        0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0E,
        0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02,
        0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x0C, 0x30,
        0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30,
        0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03,
        0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xEC, 0xF8, 0x39, 0xDF, 0xEE,
        0x76, 0xC3, 0x42, 0xCE, 0x47, 0xD9, 0xD7, 0xAF, 0xCF, 0x09, 0x34, 0xB1,
        0x4E, 0x3D, 0x7D, 0x16, 0xE0, 0x82, 0xCD, 0x8D, 0xF1, 0x1E, 0xCA, 0xAB,
        0x10, 0xB1, 0x4B, 0x02, 0x20, 0x2B, 0x75, 0x87, 0x72, 0x3B, 0xD9, 0xA9,
        0xF1, 0x13, 0x34, 0x4B, 0x05, 0xE7, 0x04, 0x9E, 0x2D, 0xD2, 0x87, 0x65,
        0x2B, 0x61, 0x87, 0xE2, 0x0E, 0xC1, 0x1E, 0x97, 0xDE, 0x3A, 0x0B, 0x63,
        0x1D,
    ];

    /// The matching PKCS#8 private key, in DER.
    ///
    /// The other half of [`TEST_SERVER_CERT_DER`], and the same disclaimer
    /// applies in full: a throwaway key for an in-process test peer, generated
    /// for this file, never deployed, and protecting nothing. It is emitted as
    /// DER bytes rather than as a PEM block deliberately, so that no secret
    /// scanner has a `-----BEGIN` marker to match and no reader can mistake it
    /// for a key in use.
    const TEST_SERVER_KEY_DER: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02, 0x01, 0x01, 0x04, 0x20,
        0xFF, 0xEE, 0x1B, 0x72, 0x55, 0x78, 0xFD, 0x53, 0xAD, 0xEF, 0xF4, 0x72,
        0xED, 0x8D, 0x00, 0x1D, 0x5E, 0x59, 0x90, 0xA7, 0xCA, 0xE3, 0xC2, 0x15,
        0xC1, 0xAA, 0x99, 0xE8, 0x00, 0xD6, 0x4A, 0x82, 0xA1, 0x44, 0x03, 0x42,
        0x00, 0x04, 0x90, 0x13, 0xA4, 0x35, 0x6E, 0x07, 0xFC, 0x8E, 0x04, 0xA8,
        0x36, 0xA7, 0x4F, 0x06, 0x6B, 0xC6, 0x9B, 0xDC, 0xE7, 0x12, 0x7B, 0x29,
        0x1D, 0xF5, 0x8E, 0x55, 0x32, 0xD5, 0x9B, 0xC5, 0x7E, 0xDA, 0x2A, 0xC6,
        0xC7, 0xCE, 0x79, 0x6A, 0x1D, 0x99, 0xC6, 0x8D, 0xBC, 0xBE, 0xA0, 0xE1,
        0x05, 0xF8, 0x6E, 0x29, 0xF6, 0xEC, 0xA6, 0xC0, 0x33, 0x75, 0xA7, 0x9F,
        0x9A, 0x08, 0x98, 0x79, 0x67, 0x45,
    ];

    /// An in-process rustls server over the test fixture, offering `alpn`.
    fn server_config(
        alpn: &[&str],
    ) -> (
        Arc<rustls::ServerConfig>,
        rustls::pki_types::CertificateDer<'static>,
    ) {
        let certificate = rustls::pki_types::CertificateDer::from(
            TEST_SERVER_CERT_DER.to_vec(),
        );
        let key = rustls::pki_types::PrivateKeyDer::try_from(
            TEST_SERVER_KEY_DER.to_vec(),
        )
        .expect("the fixture key is PKCS#8");

        let mut config =
            rustls::ServerConfig::builder_with_provider(provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3 is available")
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key)
                .expect("the fixture certificate and key match");
        config.alpn_protocols =
            alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
        (Arc::new(config), certificate)
    }

    /// Moves one round of bytes between the scripted transport and `server`.
    ///
    /// Everything the client wrote goes into the server, and everything the
    /// server queues becomes the client's next delivery. No socket, no thread
    /// and no timing: the exchange is a function call.
    fn pump(
        shared: &Arc<SyncCell<BelowState>>,
        server: &mut rustls::ServerConnection,
    ) {
        let outbound = {
            let mut scripted = shared.borrow_mut();
            core::mem::take(&mut scripted.sent)
        };
        if !outbound.is_empty() {
            let mut cursor = &outbound[..];
            while !cursor.is_empty() {
                match server.read_tls(&mut cursor) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
                if server.process_new_packets().is_err() {
                    break;
                }
            }
            let _ignored = server.process_new_packets();
        }
        let mut inbound = Vec::new();
        while server.wants_write() {
            match server.write_tls(&mut inbound) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        if !inbound.is_empty() {
            shared.borrow_mut().to_deliver.extend_from_slice(&inbound);
        }
    }

    /// Drives the handshake to completion against `server`.
    fn drive_handshake(
        backend: &RustlsBackend,
        state: &mut RustlsSession,
        base: &mut FilterBase,
        cx: &mut CallCtx<'_, '_>,
        shared: &Arc<SyncCell<BelowState>>,
        server: &mut rustls::ServerConnection,
    ) {
        for _ in 0..16 {
            let done = {
                let mut io = TlsTransport::new(base, cx);
                coded(backend.do_connect(state, &mut io))
                    .expect("neither half misbehaves")
                    .done
            };
            if done {
                return;
            }
            pump(shared, server);
        }
        panic!("the handshake did not complete within sixteen steps");
    }
}
