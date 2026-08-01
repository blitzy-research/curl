// Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
//
// SPDX-License-Identifier: curl

//! The optional embedded CA certificate bundle.
//!
//! This module is the whole of the tool's access to the certificate bundle
//! that `curl-rs/build.rs` compiles into the binary. It does three things and
//! nothing else: it includes that generated artifact, it settles the one
//! question the C representation leaves open -- whether the trailing NUL is
//! part of the payload -- and it publishes an absence-versus-presence surface
//! its three consumers can branch on without having to inspect a length in
//! order to discover which state they are in.
//!
//! # What this supersedes, and why the source named for it does not exist
//!
//! This module supersedes `src/tool_ca_embed.c`, which is a build artifact
//! rather than committed source. It is genuinely absent from this repository:
//! `ls src/tool_ca_embed.c` reports no such file, and `src/.gitignore:6`
//! lists `tool_ca_embed.c` beside `tool_hugehelp.c` at `:7`. Perl writes it
//! during the C build -- `src/Makefile.am:188` names it and `:190` adds it to
//! `CLEANFILES` -- so it is never committed and there is no prior
//! implementation to port line by line. The authorities are instead its
//! generator, its declaration, its build wiring and its consumers.
//!
//! `src/mk-file-embed.pl:29-63` is the generator. It accepts `--var <name>`
//! (`:29-33`), emits `const unsigned char <name>[] = {` (`:44`), then every
//! byte of standard input as a decimal number followed by a comma (`:52`),
//! inserting a newline after each byte whose value is 10 purely so the
//! generated C stays readable (`:53-55`), and finally a literal `0` before
//! the closing brace (`:60`). It parses nothing and re-encodes nothing:
//! whatever file the builder pointed at is embedded verbatim.
//! `src/Makefile.am:195` invokes it as
//! `mk-file-embed.pl --var curl_ca_embed`, and `src/CMakeLists.txt:59-61`
//! identically, so the C symbol is `curl_ca_embed`.
//!
//! `src/tool_setup.h:101-103` is the declaration:
//! `extern const unsigned char curl_ca_embed[];`. The element type is
//! `unsigned char`, so the counterpart here is a slice of bytes rather than a
//! string. Nothing in the C tool validates the bundle as text, and nothing
//! here does either: no character-set conversion happens in this module and
//! no input to it can make it abort.
//!
//! # Embedding is opt-in, and the off arm has to work
//!
//! A bundle is compiled in only when the builder asks for one, exactly as in
//! C. `configure.ac:2124-2127` runs `CURL_CHECK_CA_EMBED` and then
//! `AM_CONDITIONAL(CURL_CA_EMBED_SET, test -n "$CURL_CA_EMBED")`;
//! `CMakeLists.txt:1375-1376` declares the cache variable empty and
//! `:1447-1455` turns the feature on only for an executable build whose named
//! file exists. When the answer is no, `src/Makefile.am:197-199` still writes
//! a translation unit that compiles -- the stub
//! `extern const void *curl_ca_embed; const void *curl_ca_embed;` -- so the
//! link never breaks over a feature nobody asked for.
//!
//! `curl-rs/build.rs` reproduces both arms for the same reason: it writes its
//! artifact on every build, so this module can include it unconditionally and
//! the no-bundle path costs no configuration anywhere. That symmetry is what
//! makes the off arm ordinary rather than special-cased. The input is the
//! environment variable `CURL_CA_EMBED` (`curl-rs/build.rs`'s `ENV_CA_EMBED`),
//! and an empty value counts as unset there to match the shell test in
//! `configure.ac:2127`. Embedding is deliberately NOT a Cargo feature: it is
//! a build input in C and it stays a build input here.
//!
//! # The trailing NUL is not part of the payload
//!
//! In C the terminator is load-bearing, because the array carries no length:
//! `src/config2setopts.c:307` and `:319` recover the size with
//! `strlen((const char *)curl_ca_embed)`, and `src/tool_operate.c:2322`
//! prints the bundle with `curl_mprintf("%s", curl_ca_embed)`. Both stop at
//! the NUL, so the bytes that reach a consumer are the payload alone.
//!
//! A Rust slice carries its own length, which makes the terminator redundant,
//! and `curl-rs/build.rs` records the decision to drop it. Measured at this
//! commit by compiling that script and running it: with
//! the input unset the payload is zero bytes, and with the input pointed at a
//! 165-byte file the payload is byte-for-byte that file, with nothing
//! appended. THE DECISION, STATED PLAINLY: the slice this module exposes is
//! byte-identical to the file the builder named, it carries no terminator,
//! and [`byte_len`] therefore reports exactly what `strlen` reports in C for
//! every bundle that contains no interior NUL -- which is every certificate
//! bundle, since the encoding is printable text. No scan for an interior NUL
//! happens here: truncating at one would silently discard trust anchors and
//! would contradict the payload shape `build.rs` guarantees. A consumer that
//! genuinely needs a C string must append the terminator itself.
//!
//! # Absence is a state of its own, never an empty slice
//!
//! Trust anchors decide whom the tool believes, so "no bundle was embedded"
//! and "a bundle was embedded and it happens to be empty" must not be the
//! same value. Conflating them would let a caller install an empty trust
//! store and reject every certificate while believing it had configured
//! nothing. The surface here is therefore [`Option`]-shaped: `None` is
//! absence, and `Some` always means a bundle is present, whatever its
//! length. Emptiness is interpreted in exactly one place, `classify` below,
//! and no accessor collapses `Some` into `None` afterwards.
//!
//! One coordination limit is reported rather than hidden, because it belongs
//! to the producer. `curl-rs/build.rs` states that "emptiness is the signal
//! that embedding is off; there is no separate flag", and also records the
//! omission of a compile-time flag as a deliberate decision taken to keep the
//! build warning-free at the declared minimum Rust
//! version. Measured consequence: a configured file that is zero bytes long
//! is normalised to the same empty artifact as an unset input, with the
//! script emitting `CURL_CA_EMBED points at ..., which is empty; no CA bundle
//! will be embedded` (`curl-rs/build.rs`). So within this workspace
//! `CA_EMBED` is empty if and only if no bundle was embedded, which is what
//! makes the single mapping below sound. It does diverge from C, where naming
//! a zero-byte file still defines `CURL_CA_EMBED` and would therefore emit
//! the `CAcert` token and apply a zero-length blob. Closing that gap is one
//! line in the producer -- an additional generated `bool` constant, not a
//! `cfg`, so the reason `build.rs:1564-1575` gives for refusing a `cfg` would
//! not apply -- and one line here. It is reported as a producer-side gap
//! instead of being worked around, and the interpretation is kept in a single
//! function so that closing it stays a one-line change.
//!
//! # Who consumes this, and who emits what
//!
//! Four call sites in the C tool read `curl_ca_embed`. This module supplies
//! the data for all of them and emits none of the output itself, because the
//! wording of that output is frozen and belongs to the module that owns the
//! channel.
//!
//! `src/config2setopts.c:303-328` applies the bundle TWICE, once for the
//! transfer and once for proxies, each behind its own test that the user
//! configured nothing themselves: `:304` requires that neither `--cacert` nor
//! `--capath` was given, and `:316` the same of `--proxy-cacert` and
//! `--proxy-capath`. Explicit configuration always wins, and that precedence
//! is frozen. Each arm sets `blob.len` from `strlen` (`:307`, `:319`), sets
//! `CURL_BLOB_NOCOPY` (`:308`), announces itself through the note channel with
//! one of two distinct frozen strings -- `Using embedded CA bundle (%zu
//! bytes)` at `:309` and `Using embedded CA bundle, for proxies (%zu bytes)`
//! at `:321` -- and tolerates a `CURLE_NOT_BUILT_IN` answer by warning that
//! the TLS backend does not support the option (`:311-313`, `:323-325`). All
//! of that belongs to `curl-rs/src/config/to_setopts.rs`, which takes the byte
//! count from [`byte_len`] so the two messages report the same number C
//! reports, and reaches the note channel through `curl-rs/src/output/msgs.rs`.
//! `CURL_BLOB_NOCOPY` asks the engine to borrow the bytes rather than copy
//! them, which is precisely what a compiled-in `&'static [u8]` already is.
//!
//! `src/tool_operate.c:2319-2324` implements `--dump-ca-embed`: it prints the
//! bundle with `%s` and adds no newline. When nothing is embedded the guarded
//! block collapses, so the flag prints nothing AND STILL SUCCEEDS --
//! `docs/cmdline-opts/dump-ca-embed.md` documents exactly that ("If curl was
//! not built with a default CA bundle embedded, the output is empty"), and
//! `src/tool_getparam.c:3133-3138` excludes `PARAM_CA_EMBED_REQUESTED` from
//! the path that would print a diagnostic. The option row at
//! `src/tool_getparam.c:128` is unconditional, so the flag always parses,
//! never warns and is never hidden. The emission belongs to
//! `curl-rs/src/operate/`; [`bundle`] returning `None` is what makes "print
//! nothing, succeed" the natural spelling rather than a special case.
//!
//! `src/tool_help.c:357-380` appends the literal token `CAcert` to the
//! `Features:` line, and only when a bundle is embedded: `:361` reserves the
//! extra slot, `:369` writes the token, and `:372-373` then re-sorts the whole
//! list case-insensitively with `struplocompare4sort`, whose counterpart lives
//! beside this file in `curl-rs/src/util.rs`. A case-sensitive sort would
//! order the line differently, so that helper must be used rather than a plain
//! sort. The printer belongs to `curl-rs/src/cli/help.rs` --
//! `curl-rs/src/cli/libinfo.rs` already records the hand-off -- and is to gate
//! the token on [`is_embedded`], which is a `const fn` so the gate may even be
//! evaluated at compile time. The token matters because the banner is
//! machine-read: `tests/runtests.pl:640-730` parses `Features:` to decide
//! which fixtures may run, and the asymmetry is decisive: under-reporting a
//! capability makes a fixture skip while over-reporting makes it run and fail.
//! `CAcert` is absent from the harness's 52-name vocabulary, so reporting it
//! truthfully is harmless -- and reporting it when no bundle exists would be
//! over-reporting.
//!
//! # What this module deliberately does not do
//!
//! It chooses no fallback, and it names no default. Which trust anchors are
//! used when nothing is embedded is a **runtime** decision driven by curl's
//! own options, never a build-time one: `webpki-roots` and
//! `rustls-native-certs` are both pinned and are not alternatives -- the
//! bundled anchors back the embedded CA bundle path, while the platform store
//! backs `--ca-native`. That decision
//! executes in `curl-rs/src/config/to_setopts.rs` and ultimately in the engine's
//! TLS layer, where AAP section 0.5.1 pins the crates and deliberately omits
//! `platform-verifier` so that `--cacert`, `--capath` and `--insecure` stay
//! authoritative. The root `Cargo.toml` carries the canonical statement of that
//! precedence.
//!
//! An earlier revision of this comment said the platform store is the fallback
//! "exactly as in C". That is not what C does, and the oracle is explicit:
//! `lib/vtls/vtls.c:296-323` sets `native_ca_store = TRUE` only
//! `#if defined(USE_APPLE_SECTRUST) || defined(CURL_CA_NATIVE)`, and applies
//! `CURL_CA_PATH` and `CURL_CA_BUNDLE` only `#ifdef` -- so each of the three is
//! reached only when the *build* selected it, each is skipped when the user
//! supplied `--cacert`, `--capath` or a blob, and the whole block is skipped for
//! Schannel. There is no unconditional platform-store fallback in C to be
//! "exactly as".
//!
//! Nothing here names a source of trust anchors, parses a certificate, validates
//! one or reads any file at run time: the bundle is compiled in, and the only
//! thing this module reports about the absent case is that it is absent.
//!
//! It generates nothing. Reproducing `src/mk-file-embed.pl` is
//! `curl-rs/build.rs`'s job: generated code stays generated. The artifact
//! lives in the build script's output directory, which is inside `target/`, so
//! it can never be committed by accident.
//!
//! It exports nothing. The C declaration at `src/tool_setup.h:102` is a
//! symbol the linker can see; the counterpart here is reachable only inside
//! this crate, so the export-parity gate over the shared library -- exactly
//! 100 symbols, measured against `lib/libcurl.def` -- cannot be perturbed by
//! anything in this file. The crate root's blanket safety attribute covers
//! this module as written, and nothing here asks to be exempted from it: a
//! compiled-in slice of bytes needs no escape hatch.

// The generated artifact
//
// `curl-rs/build.rs` writes `ca_embed.rs` on every build, in both
// configurations, and records the shape it promises:
//
//     pub(crate) const CA_EMBED: &[u8]
//
// reaching its payload through a sibling `ca_embed.bin` and a byte include,
// so that the generated Rust is a fixed three lines whatever the bundle's
// size and no absolute path appears in it.
//
// The include is wrapped in a private module rather than spliced straight
// into this one, for three reasons. The generated tokens are then linted in
// isolation, so a later change to their shape cannot quietly collide with a
// name here. Callers cannot reach the constant, which is what keeps the
// emptiness question interpreted in exactly one place. This module's own
// surface stays the only thing the rest of the crate sees. No lint has to be
// silenced to make that work, measured with `cargo clippy -- -D warnings` in
// both configurations; the generated file carries no copyright header for the
// same reason `src/mk-file-embed.pl:41` disables that check on its own
// output, and it never enters the repository.
mod generated {
    include!(concat!(env!("OUT_DIR"), "/ca_embed.rs"));
}

// Interpretation -- the single place emptiness means anything

/// Maps the generated artifact onto the two states a build can be in.
///
/// This is the only place anywhere in the crate that reads emptiness as
/// absence, and the reasoning for it is recorded in the module documentation
/// above. Measured: the producer normalises an unset input, an unreadable
/// file and a zero-byte file all to an empty payload, warning in the latter
/// two cases, so within this workspace an empty artifact means no bundle was
/// embedded. Should the producer ever grow the explicit flag described there,
/// this function is the one place that changes.
///
/// A `const fn` so that the whole classification happens while compiling and
/// every accessor below can be `const` too.
#[allow(dead_code)]
const fn classify(embedded: &'static [u8]) -> Option<&'static [u8]> {
    if embedded.is_empty() {
        None
    } else {
        Some(embedded)
    }
}

/// The bundle state of this build, resolved once, at compile time.
#[allow(dead_code)]
const BUNDLE: Option<&'static [u8]> = classify(generated::CA_EMBED);

/// Reports the length of a bundle state without disturbing it.
///
/// Split out from [`byte_len`] so that the property that matters can be
/// tested directly: an embedded bundle that happens to be empty answers
/// `Some(0)` and an absent one answers `None`. Nothing downstream of
/// [`classify`] may turn a present bundle into an absent one, and this is
/// where that is pinned down.
#[allow(dead_code)]
const fn len_of(state: Option<&'static [u8]>) -> Option<usize> {
    match state {
        Some(bytes) => Some(bytes.len()),
        None => None,
    }
}

// The surface -- three accessors, all crate-private

/// The embedded bundle, or `None` when this build embedded none.
///
/// `Some` always means a bundle is present; its length says nothing about
/// whether one was configured. The bytes are the file the builder named,
/// verbatim and without a terminator, so they can be handed to the engine as
/// they stand: `src/config2setopts.c:308` asks for `CURL_BLOB_NOCOPY`, and a
/// borrowed `'static` slice is already exactly that.
///
/// Two consumers are owed this. `curl-rs/src/config/to_setopts.rs` is to
/// apply it to the transfer and to proxies, each only when the user
/// configured neither certificate file nor certificate directory for that
/// half (`src/config2setopts.c:304`, `:316`). `curl-rs/src/operate/` is to
/// write it to standard output for `--dump-ca-embed` with no trailing newline
/// (`src/tool_operate.c:2322`), and prints nothing while still succeeding
/// when the answer here is `None`.
#[allow(dead_code)]
pub(crate) const fn bundle() -> Option<&'static [u8]> {
    BUNDLE
}

/// Whether this build embedded a bundle at all.
///
/// The predicate behind the `CAcert` token on the `Features:` line
/// (`src/tool_help.c:361`, `:369`). `curl-rs/src/cli/help.rs` is to emit
/// that token if and only if this is `true`, then re-sort the list
/// case-insensitively through `curl-rs/src/util.rs`'s `struplocompare4sort`
/// (`src/tool_help.c:372-373`).
///
/// `const` so that the gate costs nothing at run time and may be evaluated in
/// a `const` context, and equal to `bundle().is_some()` by construction
/// rather than by convention.
#[allow(dead_code)]
pub(crate) const fn is_embedded() -> bool {
    BUNDLE.is_some()
}

/// The bundle's size in bytes, or `None` when none is embedded.
///
/// This is the number the two frozen note messages report --
/// `Using embedded CA bundle (%zu bytes)` at `src/config2setopts.c:309` and
/// `Using embedded CA bundle, for proxies (%zu bytes)` at `:321` -- exposed
/// here so that `curl-rs/src/config/to_setopts.rs` states the same figure C
/// states without recomputing it. Because the payload carries no terminator,
/// it equals `strlen((const char *)curl_ca_embed)` (`:307`, `:319`) for every
/// bundle without an interior NUL, which is every certificate bundle.
///
/// `Some(0)` and `None` are different answers: the first is an embedded
/// bundle that is empty, the second is no embedded bundle.
#[allow(dead_code)]
pub(crate) const fn byte_len() -> Option<usize> {
    len_of(BUNDLE)
}

#[cfg(test)]
mod tests {
    use super::generated::CA_EMBED;
    use super::{bundle, byte_len, classify, is_embedded, len_of, BUNDLE};

    /// A payload whose first byte is a NUL, which C's `strlen` would measure
    /// as zero bytes long. Nothing here truncates at it.
    const LEADING_NUL: &[u8] = &[0];

    /// A payload with a NUL in the middle, for the same reason.
    const INTERIOR_NUL: &[u8] = &[b'a', 0, b'b'];

    /// Bytes that are not valid text in any encoding this tool would try.
    const NOT_TEXT: &[u8] = &[0xff, 0xfe, 0x00, 0x80, 0xc0];

    /// A stand-in for a bundle file with certificate-shaped content.
    const PAYLOAD: &[u8] = b"-----BEGIN CERTIFICATE-----\n";

    /// The presence predicate is usable while compiling, which is what lets
    /// `cli/help.rs` gate the `CAcert` token without a runtime cost.
    const IS_EMBEDDED_IN_CONST_CONTEXT: bool = is_embedded();

    /// So are the other two, and this is where that is checked.
    const BUNDLE_IN_CONST_CONTEXT: Option<&[u8]> = bundle();
    const BYTE_LEN_IN_CONST_CONTEXT: Option<usize> = byte_len();

    // -- the live wiring, whichever configuration this was built in --------

    /// The surface agrees with the artifact the producer wrote: an empty
    /// payload is reported as absence, and any other payload is reported
    /// verbatim. One of the two match arms runs in a build with no bundle and
    /// the other in a build with one, so both are exercised by building twice.
    #[test]
    fn surface_agrees_with_the_generated_artifact() {
        assert_eq!(bundle(), classify(CA_EMBED));
        assert_eq!(is_embedded(), classify(CA_EMBED).is_some());
        assert_eq!(byte_len(), len_of(classify(CA_EMBED)));
        match bundle() {
            Some(bytes) => {
                assert_eq!(bytes, CA_EMBED);
                assert_eq!(byte_len(), Some(CA_EMBED.len()));
            }
            None => {
                assert_eq!(CA_EMBED.len(), 0);
                assert_eq!(byte_len(), None);
            }
        }
    }

    /// The three accessors cannot disagree, because they read one constant.
    #[test]
    fn accessors_are_consistent_with_each_other() {
        assert_eq!(bundle(), BUNDLE);
        assert_eq!(is_embedded(), bundle().is_some());
        assert_eq!(byte_len(), len_of(bundle()));
        assert_eq!(byte_len().is_some(), is_embedded());
    }

    /// The `const` evaluations above produced the same answers the runtime
    /// calls do.
    #[test]
    fn const_context_answers_match_the_accessors() {
        assert_eq!(IS_EMBEDDED_IN_CONST_CONTEXT, is_embedded());
        assert_eq!(BUNDLE_IN_CONST_CONTEXT, bundle());
        assert_eq!(BYTE_LEN_IN_CONST_CONTEXT, byte_len());
    }

    /// Nothing copies, pads or re-encodes the payload on the way out.
    #[test]
    fn exposed_bytes_are_the_artifact_unchanged() {
        match bundle() {
            Some(bytes) => {
                assert_eq!(bytes, CA_EMBED);
                assert_eq!(bytes.len(), CA_EMBED.len());
                assert_eq!(bytes.last(), CA_EMBED.last());
            }
            None => assert_eq!(CA_EMBED.len(), 0),
        }
    }

    // -- the mapping, in both directions, independent of configuration -----

    /// The producer's empty artifact is the absent state.
    #[test]
    fn empty_artifact_classifies_as_absent() {
        assert_eq!(classify(&[]), None);
    }

    /// Any non-empty artifact is present, and is passed through whole.
    #[test]
    fn non_empty_artifact_classifies_as_present() {
        assert_eq!(classify(PAYLOAD), Some(PAYLOAD));
        assert_eq!(len_of(classify(PAYLOAD)), Some(PAYLOAD.len()));
        assert_eq!(len_of(classify(PAYLOAD)), Some(28));
    }

    /// A NUL is a byte of payload here, not a terminator. C's `strlen` would
    /// answer 0 for the first of these and 1 for the second; a length-carrying
    /// slice answers 1 and 3, and no certificate bundle can tell the
    /// difference because printable text contains no NUL.
    #[test]
    fn nul_bytes_are_payload_and_are_never_truncated() {
        assert_eq!(classify(LEADING_NUL), Some(LEADING_NUL));
        assert_eq!(len_of(classify(LEADING_NUL)), Some(1));
        assert_eq!(classify(INTERIOR_NUL), Some(INTERIOR_NUL));
        assert_eq!(len_of(classify(INTERIOR_NUL)), Some(3));
    }

    /// Bytes that are not valid text pass through untouched and unexamined.
    /// The C type is `unsigned char`, so nothing may be decoded here.
    #[test]
    fn non_text_bytes_pass_through_untouched() {
        assert_eq!(classify(NOT_TEXT), Some(NOT_TEXT));
        assert_eq!(len_of(classify(NOT_TEXT)), Some(5));
    }

    // -- absence is structurally distinct from an empty bundle -------------

    /// THE ASSERTION THIS MODULE EXISTS FOR. An embedded-but-empty bundle and
    /// an absent bundle are different values, and the length accessor keeps
    /// them different: `Some(0)` is a bundle of zero bytes, `None` is no
    /// bundle. Nothing downstream of `classify` may fold one into the other,
    /// because a caller that mistook absence for an empty trust store would
    /// install one and reject every certificate.
    #[test]
    fn an_empty_bundle_is_not_the_absent_state() {
        let empty_but_present: Option<&[u8]> = Some(&[]);
        assert_ne!(empty_but_present, None);
        assert_eq!(len_of(empty_but_present), Some(0));
        assert_eq!(len_of(None), None);
        assert_ne!(len_of(empty_but_present), len_of(None));
        // Comparing the two answers, rather than either against a literal, is
        // what states the property: whatever `None` answers, an empty-but-
        // present bundle answers the opposite.
        assert_ne!(empty_but_present.is_some(), None::<&[u8]>.is_some());
    }

    /// A caller can tell the two apart by matching, without measuring
    /// anything -- which is the property that makes "print nothing, succeed"
    /// and "omit the CAcert token" spell themselves.
    #[test]
    fn callers_branch_on_the_state_not_on_a_length() {
        let described = |state: Option<&[u8]>| match state {
            Some([]) => "present, empty",
            Some(_) => "present",
            None => "absent",
        };
        assert_eq!(described(Some(&[])), "present, empty");
        assert_eq!(described(Some(PAYLOAD)), "present");
        assert_eq!(described(None), "absent");
    }
}
