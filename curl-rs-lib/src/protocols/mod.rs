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

//! The protocol implementations and the scheme registry.
//!
//! Supersedes `lib/url.c`'s scheme lookup -- `Curl_get_scheme` (`lib/url.c:1469`)
//! and `Curl_getn_scheme` (`lib/url.c:1477`) over the table registered at
//! `lib/url.c:1488` -- together with `lib/cf-https-connect.c`'s ALPN version
//! negotiation, and, as its children land, `lib/http.c` with `lib/http1.c`,
//! `lib/http2.c`, `lib/vquic/*`, `lib/ftp.c` with `lib/pingpong.c`,
//! `lib/ftplistparser.c` and `lib/fileinfo.c`, `lib/vssh/*`, `lib/file.c` and
//! `lib/ws.c`.
//!
//! # Declared unconditionally; the gates are inside
//!
//! The per-protocol capability names -- `http2`, `http3`, `ftp`, `ssh` and
//! `websockets` -- belong on the child declarations in this file, NOT on the
//! declaration of this module in `curl-rs-lib/src/lib.rs`, so that the registry
//! itself always exists. A build with every protocol feature switched off still
//! has to answer `curl_easy_setopt(CURLOPT_URL, "smtp://...")` with
//! `CURLE_UNSUPPORTED_PROTOCOL` rather than fail to compile, and it still has to
//! report a truthful `Protocols:` line.
//!
//! # The registry is wider than the implementation, deliberately
//!
//! The C tree defines and registers 33 URL schemes. Nine are implemented here;
//! the other 24 are registered for ABI completeness, return
//! `CURLE_UNSUPPORTED_PROTOCOL`, and are deliberately WITHHELD from the
//! `Protocols:` banner so that the 283 fixtures targeting them skip cleanly
//! instead of running and failing. Under-reporting a capability makes a fixture
//! skip; over-reporting makes it run and fail, so truthful advertisement is the
//! optimal strategy and not merely the honest one.
//!
//! A note for anyone reading the C: the backing array is declared
//! `all_schemes[67]` at `lib/url.c:1488` but only 33 entries are defined and
//! registered. The array is over-allocated, and 67 must not be read as a count.
//!
//! # Serialization is ours, not a library's
//!
//! When the HTTP/1.1 module lands it owns request-line composition and header
//! emission in curl's exact order, using `hyper` only for connection
//! management, keep-alive and framing. That is a design constraint rather than
//! a preference: 1,476 of the 1,914 fixtures compare full request bytes as a
//! single joined string with no per-line matching and no reordering, so
//! delegating serialization would fail a large fraction of them for reasons
//! unrelated to correctness. The same principle governs FTP command sequencing
//! below.
//!
//! # Partially delivered
//!
//! Of this directory's planned modules the FTP directory-listing parser and the
//! scheme registry below exist; `http1`, `http2`, `http3`, `sftp`, `scp`,
//! `file`, `ws` and the 13-scheme stub table arrive with their own files. This
//! file is the module root and declares exactly the one child that exists: a
//! `mod` line without its file is `error[E0583]`, which no attribute can
//! suppress, so each declaration lands with the file it names -- the convention
//! `curl-rs-lib/src/lib.rs` states for the whole crate and that `url`, `tls`,
//! `multi`, `easy`, `conn`, `cookies`, `auth` and `transfer` already follow.
//!
//! `pub(crate)`: a scheme is selected by URL, never named by a caller, so no
//! exported symbol of `lib/libcurl.def` resolves a name in this directory. The
//! ONE exception is [`scheme_registry`], and it is re-exported at the crate
//! root rather than made reachable by path -- see its own documentation.

use crate::url::{SchemeInfo, SchemeRegistry};

/// FTP and FTPS -- `lib/ftp.c`, `lib/pingpong.c`, `lib/ftplistparser.c` and
/// `lib/fileinfo.c`.
///
/// Gated on `ftp`, matching the C's `CURL_DISABLE_FTP`. The gate sits here
/// rather than on this module's own declaration for the reason recorded above.
///
/// **Partially delivered**: only the directory-listing parser exists yet.
#[cfg(feature = "ftp")]
pub(crate) mod ftp;

// ---------------------------------------------------------------------------
// The scheme registry -- `lib/url.c:1469-1541` over the table at `:1488`.
// ---------------------------------------------------------------------------

/// One row of the table: name, default port, `PROTOPT_URLOPTIONS`, and whether
/// this rewrite implements the scheme at all.
///
/// `(name, defport, url_options, in_core_scope)`. The fourth column is NOT the
/// value handed to [`SchemeInfo::runnable`]: a scheme in core scope is still
/// unrunnable when its Cargo feature is off, which is what [`runnable`] applies
/// on top.
type Row = (&'static str, u16, bool, bool);

/// All 33 schemes the C tree defines and registers.
///
/// Transcribed from `lib/url.c:1488-1522`, whose array is `all_schemes[67]` --
/// 67 is the modulus of the hash at `:1536`, **not a count**. The ports are
/// `lib/urldata.h:29-53` and the `url_options` column is `PROTOPT_URLOPTIONS`
/// (`lib/urldata.h:545`) read off each `struct Curl_scheme` registration:
/// `lib/imap.c:2341` and `:2359`, `lib/pop3.c:1730` and `:1747`, and
/// `lib/smtp.c:2022` and `:2039` -- six entries, and no others.
///
/// **Four names are upper case in the C and are reproduced exactly**: `"WS"`
/// (`lib/ws.c:1985`), `"WSS"` (`:2000`), `"SFTP"` (`lib/vssh/vssh.c:339`) and
/// `"SCP"` (`:353`). `struct Curl_scheme`'s own comment claims "URL scheme name
/// in lowercase" and is wrong for these four; the table works only because
/// `Curl_getn_scheme` folds case on both sides (`lib/url.c:1523-1538`). Never
/// compare this column case-sensitively.
///
/// `file` carries a literal `0` defport (`lib/file.c:635`), not a `PORT_*`
/// macro, because the scheme has no network endpoint.
const SCHEMES: &[Row] = &[
    // The nine schemes AAP section 0.2.1 puts in core scope.
    ("http", 80, false, true),
    ("https", 443, false, true),
    ("ftp", 21, false, true),
    ("ftps", 990, false, true),
    ("SFTP", 22, false, true),
    ("SCP", 22, false, true),
    ("file", 0, false, true),
    ("WS", 80, false, true),
    ("WSS", 443, false, true),
    // The 24 registered for ABI completeness. Every one answers
    // `CURLE_UNSUPPORTED_PROTOCOL` on transfer and is withheld from the
    // `Protocols:` banner, and every one still resolves here so that URL
    // parsing, `guess_scheme`'s host-name prefixes and the default-port
    // lookups keep behaving as they do in curl 8.19.0-DEV.
    ("smtp", 25, true, false),
    ("smtps", 465, true, false),
    ("imap", 143, true, false),
    ("imaps", 993, true, false),
    ("pop3", 110, true, false),
    ("pop3s", 995, true, false),
    ("telnet", 23, false, false),
    ("tftp", 69, false, false),
    ("dict", 2628, false, false),
    ("ldap", 389, false, false),
    ("ldaps", 636, false, false),
    ("gopher", 70, false, false),
    ("gophers", 70, false, false),
    ("mqtt", 1883, false, false),
    ("mqtts", 8883, false, false),
    ("rtsp", 554, false, false),
    ("smb", 445, false, false),
    ("smbs", 445, false, false),
    ("rtmp", 1935, false, false),
    ("rtmpt", 80, false, false),
    ("rtmpe", 1935, false, false),
    ("rtmpte", 80, false, false),
    ("rtmps", 443, false, false),
    ("rtmpts", 443, false, false),
];

/// The longest scheme name `Curl_getn_scheme` can ever resolve.
///
/// `if(len && (len <= 7))` (`lib/url.c:1524`) gates the whole lookup, so a
/// name of eight bytes or more misses the table however long
/// `MAX_SCHEME_LEN` admits on the way in. Reproduced rather than "fixed": the
/// forty-byte-scheme rows of the ported `set_parts_list` fixtures depend on
/// falling through to the syntax check instead of resolving.
const MAX_RESOLVABLE_SCHEME_LEN: usize = 7;

/// Whether this build carries an implementation of `name`.
///
/// The counterpart of `h->run != NULL` (`lib/url.c:1473-1475`). A protocol
/// disabled at build time stays in the table with `run = ZERO_NULL` -- measured
/// at `lib/file.c:626-629`, `lib/ftp.c:4348-4351` and `:4367-4370`,
/// `lib/http.c:5011-5014` and `:5028-5031`, `lib/ws.c:1984-1987` and
/// `:1999-2002`, `lib/vssh/vssh.c:338-341` and `:352-355` -- so a Cargo feature
/// that is off is the exact analogue of a `CURL_DISABLE_<PROTO>` build and must
/// answer `false` here.
///
/// HTTP and HTTPS have no gate because there is no `http1` feature: HTTP/1.1
/// and TLS are unconditional in this crate, which `curl-rs-lib/Cargo.toml`
/// records and justifies. `file` has no gate for the same structural reason --
/// AAP section 0.5.2's feature vocabulary is fifteen names and none of them is
/// `file`.
///
/// The 24 out-of-scope schemes answer `false` unconditionally. That is what
/// keeps the C's **parse-versus-set asymmetry** observable:
/// `curl_url_set(u, CURLUPART_URL, "smtp://host/", 0)` succeeds because
/// `parse_scheme` accepts any scheme in the table (`lib/urlapi.c:951`) while
/// `curl_url_set(u, CURLUPART_SCHEME, "smtp", 0)` fails because
/// `set_url_scheme` additionally requires an implementation (`:1646`).
fn runnable(name: &str, in_core_scope: bool) -> bool {
    if !in_core_scope {
        return false;
    }
    match name {
        "ftp" | "ftps" => cfg!(feature = "ftp"),
        "SFTP" | "SCP" => cfg!(feature = "ssh"),
        "WS" | "WSS" => cfg!(feature = "websockets"),
        // "http", "https" and "file": unconditional, per the note above.
        _ => true,
    }
}

/// The 33-entry table, as a [`SchemeRegistry`].
///
/// Zero-sized: the rows are a `const`, so an instance carries nothing and a
/// `&'static` reference to one costs no allocation and no initialisation.
struct AllSchemes;

impl SchemeRegistry for AllSchemes {
    /// `Curl_getn_scheme` (`lib/url.c:1477-1541`), reproduced behaviourally
    /// rather than structurally.
    ///
    /// The C reaches its answer through a hash into `all_schemes[67]`; this is a
    /// linear scan over 33 rows. The two are indistinguishable to every caller,
    /// which is the only property that matters here -- the hash exists to make
    /// the lookup cheap and performance is an explicit non-goal (AAP section
    /// 0.1.1). What IS reproduced exactly is the pair of predicates the C
    /// applies: the length gate at `:1524`, and the case-insensitive
    /// whole-name comparison at `:1537` (`curl_strnequal(scheme, h->name, len)
    /// && !h->name[len]`), whose second half is what stops `"htt"` matching
    /// `"http"`.
    fn lookup(&self, scheme: &[u8]) -> Option<SchemeInfo> {
        if scheme.is_empty() || scheme.len() > MAX_RESOLVABLE_SCHEME_LEN {
            return None;
        }
        SCHEMES
            .iter()
            .find(|(name, _, _, _)| {
                // ASCII-only folding, because `Curl_raw_tolower` is
                // ASCII-only. `eq_ignore_ascii_case` on the byte slices is
                // exactly that, and it compares the lengths too, which is the
                // `!h->name[len]` half of the C's test.
                name.as_bytes().eq_ignore_ascii_case(scheme)
            })
            .map(|&(name, default_port, url_options, in_core_scope)| {
                SchemeInfo {
                    name,
                    default_port,
                    url_options,
                    runnable: runnable(name, in_core_scope),
                }
            })
    }
}

/// The one instance, `'static` because [`crate::url::Url`] holds the borrow.
static REGISTRY: AllSchemes = AllSchemes;

/// The scheme table every URL handle resolves against.
///
/// This is the wiring contract `crate::url::SchemeRegistry` states and
/// `curl-rs-lib/src/lib.rs` repeats: `curl_url()` takes no arguments
/// (`include/curl/urlapi.h:113`), so `curl-rs-ffi/src/ffi/url.rs` has to obtain
/// a registry without being handed one, and this function is where it gets it.
///
/// The direction of the dependency is the point. `url` declares the
/// [`SchemeRegistry`] trait and `protocols` implements it, never the reverse, so
/// the URL API does not depend on the transfer engine and the module graph stays
/// acyclic (AAP section 0.4.2, and pattern P12's injected-rather-than-global
/// rule). There is deliberately no global to reach for instead: no `static mut`,
/// no lazily-initialised singleton and no registration side effect. The registry
/// is a constructor argument and [`crate::url::Url`] holds the borrow.
///
/// # Why this returns a table wider than the `Protocols:` banner
///
/// All 33 schemes resolve; only nine are [`SchemeInfo::runnable`]. Nothing here
/// contradicts `crate::version`'s empty protocol banner, and the distinction is
/// load-bearing rather than pedantic: resolving a scheme is what URL PARSING
/// needs, while the banner describes what a TRANSFER can do. The transfer
/// modules are unwritten, so `crate::version::ENGINE_PROTOCOLS` stays absent and
/// the banner stays empty -- under-reporting, which makes a fixture skip, rather
/// than over-reporting, which makes it run and fail.
///
/// # Examples
///
/// ```
/// use curl_rs_lib::url::{Url, UrlFlags, UrlPart};
///
/// let mut url = Url::new(curl_rs_lib::scheme_registry());
/// url.set(UrlPart::Url, Some(b"https://example.com/a"), UrlFlags::NONE)?;
/// let port = url.get(UrlPart::Port, UrlFlags::DEFAULT_PORT)?;
/// assert_eq!(port, b"443".to_vec());
/// # Ok::<(), curl_rs_lib::CURLUcode>(())
/// ```
#[must_use]
pub fn scheme_registry() -> &'static dyn SchemeRegistry {
    &REGISTRY
}

#[cfg(test)]
mod tests {
    use super::{scheme_registry, SCHEMES};

    #[test]
    fn the_table_holds_the_thirty_three_schemes_the_c_registers() {
        // `lib/url.c:1488-1522` defines and registers 33 entries. The array's
        // declared length of 67 is the hash modulus and is not a count.
        assert_eq!(SCHEMES.len(), 33);

        // And no name appears twice, folded, which a hand-transcribed table is
        // exactly the kind of thing to get wrong.
        for (index, (name, _, _, _)) in SCHEMES.iter().enumerate() {
            for (other, _, _, _) in &SCHEMES[index + 1..] {
                assert!(
                    !name.eq_ignore_ascii_case(other),
                    "{name} and {other} collide when folded"
                );
            }
        }
    }

    #[test]
    fn lookup_folds_case_and_requires_the_whole_name() {
        let registry = scheme_registry();

        // The four upper-case rows resolve from either spelling, which is the
        // whole reason `Curl_getn_scheme` folds both sides.
        for spelling in [&b"SFTP"[..], b"sftp", b"Sftp"] {
            let found = registry.lookup(spelling).expect("sftp resolves");
            assert_eq!(found.name, "SFTP");
            assert_eq!(found.default_port, 22);
        }

        // A prefix must NOT match: the C's second predicate is `!h->name[len]`.
        assert!(registry.lookup(b"htt").is_none());
        assert!(registry.lookup(b"").is_none());
        assert!(registry.lookup(b"nosuchscheme").is_none());
    }

    #[test]
    fn nothing_longer_than_seven_bytes_can_resolve() {
        // `if(len && (len <= 7))` at `lib/url.c:1524`. `gophers` is exactly
        // seven and resolves; nothing longer is in the table, so the gate is
        // asserted against a synthetic name of eight bytes.
        assert_eq!(
            scheme_registry().lookup(b"gophers").map(|s| s.default_port),
            Some(70)
        );
        assert!(scheme_registry().lookup(b"gophers1").is_none());
        for (name, _, _, _) in SCHEMES {
            assert!(
                name.len() <= 7,
                "{name} is longer than the C's lookup can resolve"
            );
        }
    }

    #[test]
    fn url_options_is_set_for_exactly_the_six_sasl_schemes() {
        let expected = ["smtp", "smtps", "imap", "imaps", "pop3", "pop3s"];
        for (name, _, url_options, _) in SCHEMES {
            assert_eq!(
                *url_options,
                expected.contains(name),
                "{name}'s PROTOPT_URLOPTIONS column disagrees with \
                 lib/imap.c, lib/pop3.c and lib/smtp.c"
            );
        }
    }

    #[test]
    fn only_the_nine_in_scope_schemes_can_ever_be_runnable() {
        let in_scope = [
            "http", "https", "ftp", "ftps", "SFTP", "SCP", "file", "WS", "WSS",
        ];
        let registry = scheme_registry();
        let mut runnable = 0usize;
        for (name, _, _, _) in SCHEMES {
            let found = registry
                .lookup(name.as_bytes())
                .expect("every row resolves by its own name");
            if found.runnable {
                assert!(
                    in_scope.contains(name),
                    "{name} is out of core scope and must never be runnable"
                );
                runnable += 1;
            }
        }
        // With the default feature set every one of the nine is runnable; with
        // `--no-default-features` the ftp, ssh and websockets rows drop out.
        // Both are correct, so the assertion is the bound rather than the
        // count -- and http, https and file are ungated, hence the floor.
        assert!(runnable >= 3, "http, https and file are never gated");
        assert!(runnable <= in_scope.len());
    }

    #[test]
    fn the_registry_is_zero_sized_and_stable() {
        assert_eq!(core::mem::size_of::<super::AllSchemes>(), 0);
        // Two calls name one table; nothing is allocated per call.
        let first: *const dyn super::SchemeRegistry = scheme_registry();
        let second: *const dyn super::SchemeRegistry = scheme_registry();
        assert_eq!(first.cast::<u8>(), second.cast::<u8>());
    }
}
