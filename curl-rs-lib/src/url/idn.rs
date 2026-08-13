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

//! IDN conversions.
//!
//! This module supersedes `lib/idn.c` (376 lines) and `lib/idn.h` (39
//! lines). libidn2 is replaced by the pure-Rust `idna` crate, pinned at
//! 1.1.0, on all four target triples uniformly.
//!
//! There are exactly two conversions, and one predicate that decides
//! whether either of them applies:
//!
//! | this module | C original | direction |
//! |---|---|---|
//! | `is_ascii_name` | `Curl_is_ASCII_name` | a test, not a conversion |
//! | `to_ascii` | `Curl_idn_decode` | Unicode host -> A-label |
//! | `to_unicode` | `Curl_idn_encode` | A-label -> U-label |
//!
//! The C originals are at `lib/idn.c:223-236`, `:302-325` and `:327-344`
//! respectively.
//!
//! # READ FIRST: curl's names are inverted
//!
//! **In curl, "decode" means TO ASCII and "encode" means TO UNICODE.** That
//! is backwards from every intuition and backwards from the `idna` crate's
//! own vocabulary (`domain_to_ascii` / `domain_to_unicode`), so the two
//! entry points here are named for their *direction* rather than
//! transliterated:
//!
//! * `Curl_idn_decode` (`lib/idn.c:302-325`) takes a Unicode/UTF-8 host and
//!   produces the **A-label**, i.e. the punycode `xn--...` form. It is
//!   `to_ascii` here.
//! * `Curl_idn_encode` (`lib/idn.c:327-344`) takes punycode and produces the
//!   **U-label**, i.e. the Unicode form. It is `to_unicode` here.
//!
//! Wiring them the other way round silently swaps the meaning of the
//! `CURLU_PUNYCODE` and `CURLU_PUNY2IDN` flags, and nothing in the type
//! system would object, because both functions map bytes to a `String`.
//!
//! # Who calls this, and how the error type changes on the way out
//!
//! The two callers live in the sibling `super` module and reproduce
//! `host_decode` (`lib/urlapi.c:1338-1345`) and `host_encode`
//! (`lib/urlapi.c:1347-1354`). They are reached from `urlget_format`
//! (`lib/urlapi.c:1357-1423`) through the `CURLU_PUNYCODE` and
//! `CURLU_PUNY2IDN` flags respectively, and both branches gate on the
//! *stored* host rather than on the part being converted
//! (`lib/urlapi.c:1401-1420`):
//!
//! ```text
//!   else if(punycode) {                       /* CURLU_PUNYCODE  */
//!     if(!Curl_is_ASCII_name(u->host)) {      /* <- u->host      */
//!       uc = host_decode(part, &punyversion);
//!   else if(depunyfy) {                       /* CURLU_PUNY2IDN  */
//!     if(Curl_is_ASCII_name(u->host)) {       /* <- u->host      */
//!       uc = host_encode(part, &unpunified);
//! ```
//!
//! Exactly as `lib/idn.c` does, this module reports
//! [`CURLcode`] and **not** `CURLUcode`. Translating
//! `CURLE_URL_MALFORMAT` into `CURLUE_BAD_HOSTNAME` is the caller's job, and
//! keeping that translation in one place is what stops the URL API's error
//! vocabulary from leaking into a conversion primitive.
//!
//! `CURLUE_LACKS_IDN` is *not* producible here, and that is deliberate. In C
//! it comes from `lib/urlapi.c:1335-1336`, which redefines both wrappers to
//! that constant when `USE_IDN` is undefined. `idna` is a plain, non-optional
//! dependency of this crate and the workspace's feature vocabulary is closed
//! at fifteen names with no `idn` among them, so there is no build of this
//! workspace in which an IDN implementation is absent. The
//! `CURLUcode::LacksIdn` variant nevertheless stays in `crate::error`,
//! because it is ABI (`include/curl/urlapi.h:65`, value 30) and a C consumer
//! holds that integer. Do not delete the variant, and do not invent a
//! feature gate in order to reach it.
//!
//! # What is not here
//!
//! * **The Windows arm** (`lib/idn.c:143-218`): the two Win32 IDN entry
//!   points, the wide-character recoding helper and the 255-character cap
//!   they share. Windows is not a target, and no conditional arm for it
//!   appears below "for completeness".
//! * **The Apple/ICU arm** (`lib/idn.c:45-141`): the ICU UTS-46 handle, the
//!   locale-to-UTF-8 recoding helper and the codeset query. Excluded even
//!   though two targets are Darwin -- `idna` is used on all four targets, so
//!   the implementation is uniform and carries no per-target arm at all.
//! * **The Apple arm's 512-byte host cap.** It is defined at `lib/idn.c:50`,
//!   which is *inside* the `#ifdef USE_APPLE_IDN` block opened at
//!   `lib/idn.c:45`, and it is referenced only at `:86`, `:87`, `:98`, `:120`
//!   and `:126` -- all within that arm. The libidn2 path, which is the path
//!   this module supersedes, has no such cap, so applying one here would
//!   reject hostnames curl accepts. The only length policies in force are
//!   libidn2's own, reproduced by [`dns_bounds_ok`] for the A-label direction
//!   and inline in [`idn_to_unicode`] for the U-label direction, both from
//!   measurement.
//! * **`Curl_idnconvert_hostname` (`lib/idn.c:359-376`) and
//!   `Curl_free_idnconverted_hostname` (`lib/idn.c:349-352`)**. Those
//!   operate on `struct hostname` -- `host->name`, `host->dispname`,
//!   `host->encalloc` -- and serve the *connection* path by way of
//!   `lib/hostip.c`, which maps to `crate::dns` and `crate::conn`, not to
//!   the URL API. Note in passing that `Curl_idnconvert_hostname` assigns
//!   `host->dispname = host->name` (`lib/idn.c:362`) *before* any
//!   conversion; reproducing that is the resolver's business, not this
//!   module's.
//! * **`CURLE_NOT_BUILT_IN`**. `lib/idn.c:252` guards the conversion with
//!   `idn2_check_version(IDN2_VERSION)` and reports `CURLE_NOT_BUILT_IN` at
//!   `:271` for "a too old libidn2 version". There is no analogue: `idna` is
//!   compiled in at a version pinned by `Cargo.lock`, so a runtime
//!   version-skew check has nothing to check. The branch is omitted rather
//!   than faked, and no code path here yields `CURLcode::NotBuiltIn`.
//! * **Most of the out-of-memory branch**. `lib/idn.c:288` maps
//!   `IDNA_MALLOC_ERROR` to `CURLE_OUT_OF_MEMORY`, and `:313`/`:338` do the
//!   same for a failed `strdup`. Two of those three have no counterpart: the
//!   A-label direction's allocation happens inside the `idna` crate, which
//!   offers no fallible entry point, and the two `strdup`s duplicate a host
//!   name already resident -- bounded by 253 bytes, so not externally sized in
//!   the sense `crate::util::fallible` addresses. The third *is* reproduced:
//!   [`idn_to_unicode`] owns its accumulator, reserves it through
//!   `crate::util::fallible`, and therefore reports
//!   `CURLcode::OutOfMemory` exactly where `lib/idn.c:288` does. Every other
//!   failure in this module is `CURLcode::UrlMalformat`.
//!
//! # UTF-8 is validated here, and that is a fixture-backed requirement
//!
//! On every non-Windows target -- which is all four of them --
//! `lib/idn.c:39-40` selects
//!
//! ```text
//!   #define IDN2_LOOKUP(name, host, flags)                          \
//!     idn2_lookup_ul((const char *)(name), (char **)(host), flags)
//! ```
//!
//! and `idn2_lookup_ul` takes its input in the *locale* encoding, converting
//! internally and failing on ill-formed input. What arrives here from the
//! URL parser is arbitrary bytes, so both entry points take `&[u8]` and
//! validate UTF-8 themselves, returning `CURLcode::UrlMalformat` on
//! ill-formed input. A lossy conversion would be a defect, not a
//! convenience: `tests/data/test1034` ("HTTP over proxy with malformatted
//! IDN hostname", keyword `FAILURE`) feeds the host
//! `invalid-utf8-%hex[%e2%90]hex%.local`, whose `\xe2\x90` is a deliberately
//! *incomplete* UTF-8 sequence, and expects exit code 3. Substituting
//! U+FFFD would turn that expected failure into a pass.
//!
//! The one genuine divergence from C follows from the same line: curl on
//! Linux and macOS is **locale-sensitive** here, whereas this module treats
//! input as UTF-8 unconditionally. In practice the two agree, because the
//! harness pins `LC_ALL=C.UTF-8` on the IDN fixtures and gates them on a
//! `codeset-utf8` feature derived from `is_utf8_supported()`
//! (`tests/runtests.pl:836`). It is recorded rather than hidden.
//!
//! # The UTS-46 parameters, and why each one is what it is
//!
//! `idna 1.1.0` offers convenience wrappers, but they hard-code their
//! parameters -- `domain_to_ascii` uses `DnsLength::Ignore`, and
//! `domain_to_ascii_strict` uses `AsciiDenyList::STD3` with
//! `Hyphens::Check`. Neither matches curl. This module therefore drives the
//! explicit `idna::uts46::Uts46` entry points and states every knob, in
//! keeping with the standing obligation that security-relevant
//! configuration be explicit rather than defaulted.
//!
//! The values below were not reasoned out; they were **measured** against
//! libidn2 2.3.8 driven exactly as `lib/idn.c:247-268` drives it -- see the
//! divergence section below for the harness -- and compared against all four
//! plausible knob combinations. They apply to the A-label direction only:
//! since the U-label direction is a per-label punycode decode rather than
//! UTS-46 _ToUnicode_ (see [`idn_to_unicode`]), it takes no UTS-46 parameters
//! at all and none of these constants reaches it.
//!
//! * **`AsciiDenyList::EMPTY`** (_UseSTD3ASCIIRules=false_). curl does not
//!   pass `IDN2_USE_STD3_ASCII_RULES`, and the oracle accordingly accepts
//!   `_<U+00E5>.se`, yielding `xn--_-2fa.se`. `AsciiDenyList::STD3` would
//!   reject the underscore, and `AsciiDenyList::URL` would additionally
//!   deny the URL-forbidden set that curl's own parser has already split
//!   off. Faithfulness wins over strictness.
//! * **`Hyphens::Check`** for `to_ascii` (_CheckHyphens=true_). The oracle
//!   rejects `-<U+00E5>.se`, `<U+00E5>-.se`, `a<U+00E5>--b.se` and
//!   `<U+00E5>.-.se`, all with `CURLUE_BAD_HOSTNAME`. Only `Hyphens::Check`
//!   reproduces all four; `Hyphens::CheckFirstLast` lets the third/fourth
//!   position case through and `Hyphens::Allow` lets all four through. An
//!   input that is already an A-label still passes: UTS-46 decodes the
//!   `xn--` prefix before the hyphen test runs, so `xn--4cab6c.se` survives
//!   unchanged.
//!   No hyphen policy reaches the U-label direction at all, and that
//!   asymmetry mirrors an asymmetry in C: the A-label direction goes through
//!   libidn2's *lookup* API, which validates, while the U-label direction
//!   goes through `idn2_to_unicode_8z8z` (`lib/idn.c:286`), which validates
//!   almost nothing. Measured -- the oracle returns `foo--bar.example`,
//!   `-foo.se`, `foo-.se` and `a.-.se` unchanged, and `Hyphens::Check`
//!   rejects all four.
//! * **`DnsLength::Ignore`** for `to_ascii`, with libidn2's own bound applied
//!   by [`dns_bounds_ok`] instead. The bound is not optional:
//!   `tests/data/test1035` ("HTTP over proxy with too long IDN hostname",
//!   exit code 3) depends on it, and with no bound at all that host converts
//!   and the fixture fails. What is wrong with `idna`'s spelling of it is
//!   one clause -- [`idna::uts46::verify_dns_length`] also rejects an empty
//!   label, and libidn2 does not, so `.se`, `a..b`, `<U+00E5>..b` and
//!   `<U+00E5>.se..` were being refused where the oracle converts them.
//!   `dns_bounds_ok` is that function minus that clause, so the root-dot
//!   discount survives: the oracle converts `<U+00E5><U+00E4><U+00F6>.se.` to
//!   `xn--4cab6c.se.`, which is what rules out `DnsLength::Verify`.
//!
//! Normalization needs no separate step. `lib/idn.c:253` passes
//! `IDN2_NFC_INPUT` ("Normalize input string using normalization form C"),
//! and UTS-46 performs NFC as part of its own mapping stage -- measured:
//! `a` followed by U+030A COMBINING RING ABOVE and precomposed U+00E5 both
//! convert to `xn--5ca.se`.
//!
//! # Two attempts, in this order, and the fallback is load-bearing
//!
//! `lib/idn.c:251-268` tries non-transitional processing first and falls
//! back to transitional processing, with the C comment stating why:
//!
//! ```text
//!   int flags = IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL;
//!   int rc = IDN2_LOOKUP(input, &decoded, flags);
//!   if(rc != IDN2_OK)
//!     /* fallback to TR46 Transitional mode for better IDNA2003
//!        compatibility */
//!     rc = IDN2_LOOKUP(input, &decoded, IDN2_TRANSITIONAL);
//!   if(rc != IDN2_OK)
//!     result = CURLE_URL_MALFORMAT;
//! ```
//!
//! `idna 1.1.0` exposes no transitional switch: `uts46.rs:20` records that
//! _Transitional_Processing_ is "always _false_ but could be implemented as
//! a preprocessing step", and the crate's own deprecated compatibility layer
//! does exactly that in `deprecated.rs:25-62`. `transitional_map`
//! reimplements that preprocessing rather than calling the `#[deprecated]`
//! `Idna`/`Config` pair, which would not survive `clippy -D warnings`.
//!
//! Dropping the fallback would narrow the set of accepted hostnames
//! observably, so it is exercised by test rather than assumed: `a<U+200C>b`
//! and `a<U+200D>b` both *fail* non-transitional UTS-46 -- ZWNJ and ZWJ are
//! CONTEXTJ and neither sits in a permitted joining context -- and both
//! succeed once the deviation characters are mapped away, giving `ab.se`,
//! byte-identically to the C oracle.
//!
//! # One deliberate asymmetry: the empty-result check
//!
//! `Curl_idn_decode` rejects an empty conversion result
//! (`lib/idn.c:317-320`):
//!
//! ```text
//!   if(!d[0]) { /* ended up zero length, not acceptable */
//!     result = CURLE_URL_MALFORMAT;
//! ```
//!
//! `Curl_idn_encode` has no such check -- `lib/idn.c:341-342` simply
//! assigns. **The asymmetry is deliberate fidelity, not an oversight**, and
//! it is observable on the empty host, which `to_unicode` converts to
//! `Ok("")` while `to_ascii` returns `Err(UrlMalformat)` -- measured, the
//! oracle agrees in both directions. `tests/data/test763` ("Unicode hostname
//! ending up in a blank name") is the fixture that names the `to_ascii` half.
//!
//! The witness used to be U+200B ZERO WIDTH SPACE, on the grounds that
//! `Uts46::to_unicode` maps it away and succeeds with an empty output. That
//! was a divergence rather than a demonstration: the oracle returns U+200B
//! unchanged, because `idn2_to_unicode_8z8z` maps nothing. The empty host is
//! the honest witness and U+200B is now a passthrough test.
//!
//! # Divergences from the C oracle that remain, all measured
//!
//! The check is mechanical rather than anecdotal, and it is reproducible: a
//! C driver linked against the installed libidn2 2.3.8 reproduces
//! `idn_decode` (`lib/idn.c:247-280`) and `idn_encode` (`lib/idn.c:282-300`)
//! statement for statement -- `idn2_lookup_ul` twice with
//! `IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL` then `IDN2_TRANSITIONAL`, and
//! `idn2_to_unicode_8z8z` with flags `0` -- under `LC_ALL=C.UTF-8` and with
//! `setlocale(LC_ALL, "")` called first, which `idn2_lookup_ul` requires in
//! order to see a UTF-8 codeset. A **165-host corpus** was driven through both
//! it and this module, hex-encoded on both sides and diffed: **325 of 330
//! comparisons are byte-identical.**
//!
//! Of the five that are not, two are an artefact of the C string interface
//! rather than a behavioural difference, and the remaining three share a
//! single cause.
//!
//! **The one behavioural divergence: UTS-46 _CheckBidi_, in the A-label
//! direction only.** Three corpus hosts differ, all of them names that mix
//! writing directions inside one label:
//! `<U+05E9><U+05DC><U+05D5><U+05DD>abc.se` and its A-label form
//! `xn--abc-9pe8ah5f.se`, which open right-to-left and close with a Latin
//! run, and `<U+00E5><U+05E9>.se`, which does the reverse. The oracle
//! converts all three; this module rejects them, because RFC 5893's
//! conditions on a bidi label forbid them and `idna 1.1.0` applies _CheckBidi_
//! to every name. **The pin is what makes this irreducible**, and every public
//! entry point was checked rather than assumed: the crate states at
//! `idna-1.1.0/src/uts46.rs:17` that _CheckBidi_ is "Always _true_; cannot be
//! configured"; `Uts46::to_ascii` exposes no fourth knob for it; and dropping
//! to the low-level `Uts46::process` with `ErrorPolicy::MarkErrors` does not
//! help either, because `ProcessingError::ValidityError` is documented at
//! `uts46.rs:425-427` as producing **no output at all** for the _ToASCII_
//! operation -- unlike _ToUnicode_, which does get a U+FFFD-marked string. The
//! mapping and normalization stages one would have to drive instead are
//! private (`Uts46::data`), so closing this would mean reimplementing UTS-46
//! and NFC inside this crate rather than configuring the dependency.
//! `Cargo.toml` freezes `idna` at exactly 1.1.0 under AAP section 0.5.1, and
//! section 0.8.2 forbids substituting a dependency for one. The
//! divergence is in the stricter direction and is confined to the mixed case:
//! a well-formed right-to-left name such as `<U+05E9><U+05DC><U+05D5><U+05DD>.se`
//! satisfies _CheckBidi_ and yields `xn--9dbne9b.se` in both implementations.
//! It is also unreachable from the eligible fixture corpus -- `CURLU_PUNYCODE`
//! and `CURLU_PUNY2IDN` are referenced only by `lib/urlapi.c` itself and by
//! `tests/libtest/lib1560.c`, and no `tests/data` fixture carries a
//! right-to-left hostname.
//!
//! **The two comparisons that are an interface artefact**, on the host
//! `<U+0000>.se`: libidn2 takes a `const char *`, so it sees an empty string
//! and converts it to nothing -- which `Curl_idn_decode`'s own zero-length
//! check (`lib/idn.c:317-320`) then rejects, and which the U direction returns
//! as `""` -- while this module takes `&[u8]` and converts all four bytes.
//! The C loop in `Curl_is_ASCII_name` stops at the same terminator, and the
//! difference is unobservable for the real callers, whose hosts come from
//! NUL-terminated storage: an interior NUL cannot reach here. Recorded, not
//! reproduced -- truncating a Rust slice at a NUL byte in order to match a C
//! measurement artefact would be a defect, not fidelity.
//!
//! **Two further comparisons that are not about IDN at all**, recorded
//! because they are a cross-file obligation rather than a defect here: driven
//! through `curl_url_get` rather than through libidn2 directly, the host
//! `1234567890` comes back as `73.150.2.210` in both directions. That is
//! `curl_url_set` reading the label as the 32-bit integer 0x499602D2 and
//! re-spelling it in dotted-quad form, which happens in the URL parser before
//! any IDN code is reached. `lib/idn.c` has no part in it. Whoever writes the
//! sibling `super` module owns that normalization; this module correctly
//! leaves such a host alone, because `is_ascii_name` reports it as ASCII and
//! no conversion applies.
//!
//! Four divergence classes recorded by an earlier revision of this file have
//! since been closed, and they are named here so that a reader who finds the
//! old text in the history knows it is superseded rather than mistaken: the
//! empty-label rejection (now [`dns_bounds_ok`]), and -- all three from
//! replacing `Uts46::to_unicode` with a per-label punycode decode -- the
//! case folding of ASCII labels, the missing length rule, and the rejection
//! of a control-character payload such as `xn--a.se`, which the oracle
//! decodes to U+0080 followed by `.se` and this module now does too.
//!
//! # Feature advertisement
//!
//! [`available`] is the Rust counterpart of `idn_present`
//! (`lib/version.c:407-416`), registered in the feature table at
//! `lib/version.c:496` as `FEATURE("IDN", idn_present, CURL_VERSION_IDN)`
//! with `CURL_VERSION_IDN` defined as `(1<<10)` at
//! `include/curl/curl.h:3187`. It exists as a *predicate* rather than a
//! constant so that the `Features:` banner stays computed, which is what
//! keeps the coupling auditable; the C table calls through a function
//! pointer for the same reason.
//!
//! Two traps for whoever maintains `crate::version`:
//!
//! * In C, `idn_present` *is* `info->libidn != NULL` for libidn2 builds
//!   (`lib/version.c:413`), so the `IDN` feature bit and the `libidn`
//!   version field are coupled. On an `idna`-backed build there is no
//!   libidn2, so **the truthful answer decouples them**: advertise `IDN`,
//!   because the capability genuinely exists, while reporting `libidn` as
//!   absent. [`version_string`] returns the `idna` crate's version for the
//!   banner, and it is emphatically not a libidn2 version.
//! * Never emit `WinIDN` or `AppleIDN` (`lib/version.c:128` and `:130`) and
//!   never emit a `libidn2/...` token. `tests/runtests.pl:670` derives
//!   `$feature{"IDN"}` by case-insensitive substring match over the whole
//!   `Features:` line, so the plain `IDN` name is sufficient, and
//!   `tests/runtests.pl:625-626` would set `$feature{"libidn2"}` from a
//!   token this build has no right to claim.
//!
//! # Visibility, and why it is split
//!
//! `is_ascii_name`, `to_ascii` and `to_unicode` are `pub(crate)`. Their
//! consumers are the sibling `super` module, which backs the six exported
//! `curl_url_*` symbols, and the resolver, which reproduces
//! `Curl_idnconvert_hostname`. Neither is outside this crate, and in C the
//! corresponding symbols are internal too -- `Curl_`-prefixed and declared
//! only in `lib/idn.h`.
//!
//! [`available`] and [`version_string`] are `pub`, which is wider than
//! `crate::version` alone requires, and the reason is deliberate:
//! `curl_version_info` populates the `features` bitmask and the `libidn`
//! field from `curl-rs-ffi`, which is a *separate crate* and therefore cannot
//! see a `pub(crate)` item. Making the capability queryable from there is the
//! whole point of having a predicate, so the two reporting functions are
//! public and the three conversion primitives are not.
//!
//! What must *not* happen is widening `to_ascii` or `to_unicode` in order
//! to make `tests/unit` or `tests/libtest` link. Those are C programs calling
//! internal symbols; a Rust static library genuinely does not export
//! `pub(crate)` items, their coverage is relocated into this file's test
//! module instead, and re-exporting internals would dismantle the
//! encapsulation the crate's safety guarantee rests on.
//!
//! Nothing here is exported to C -- no symbol in this module carries an
//! unmangled name or a C calling convention. The public C ABI belongs
//! to `curl-rs-ffi/src/ffi/`, and a stray exported symbol in this crate would
//! break the symbol-parity gate against `lib/libcurl.def`.
//!
//! Advertising `IDN` puts fifteen fixtures in play and makes three skip.
//! That trade is measured and correct, and the skip is not a regression:
//! `test959`, `test960` and `test961` require `!IDN` and cannot run
//! alongside the fifteen that require `IDN`. Of the fifteen, `test962`
//! through `test969` additionally require the `smtp` server, which this
//! workspace does not implement, so they skip on the `Protocols:` line
//! regardless. The seven that genuinely exercise this module are
//! `test165`, `test763`, `test1034`, `test1035`, `test1448`, `test2046` and
//! `test2047`.

// `dead_code` is NOT allowed for this module as a whole. Every item below that
// has no consumer yet carries its own `#[allow(dead_code)]`, written at the
// item, so the suppression reads as an inventory rather than a blanket: each
// one is load-bearing, deleting any one of them restores a warning, and an
// item added later with no consumer is still reported. Each is removed when
// its consumer lands. A module- or crate-scoped `#![allow(dead_code)]` would
// instead silence the NEXT item somebody adds, which hides incomplete
// scaffolding rather than recording it; the rule and the executable gate that
// enforces it across the workspace live in `curl-rs-lib/src/lib.rs`
// (`mod source_policy`).
//
// Every consumer of these primitives lives in another module -- the sibling
// `super` module, which backs the six exported `curl_url_*` symbols, and the
// resolver, which reproduces `Curl_idnconvert_hostname` -- so until those
// land each primitive is legitimately unreferenced inside the crate, and the
// zero-warnings gate would otherwise fail on code that is correct. Compiling
// this file as a test target, where the module's own tests supply the
// missing consumer, reports nothing at all, which is why the allowances are
// `allow` and not `expect`: an `expect` would go unfulfilled in that build.
//
// No level for the `unsafe_code` lint is set here, at any level, by design:
// the crate root denies it and this module contains no `unsafe`, so the
// crate-wide guarantee must stay in force.

use crate::error::CURLcode;
use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
use std::borrow::Cow;

// The UTS-46 parameters.
//
// Named constants rather than inline arguments so that the two call sites
// cannot drift apart, and so that a reader auditing this module against
// `lib/idn.c` sees the whole policy in one place. Every value is justified
// against a measurement in the module documentation above; none of them is a
// convenience default, and none of them may be "tidied" into an `idna`
// wrapper function, because every wrapper hard-codes at least one knob to a
// value curl does not use.

/// _UseSTD3ASCIIRules=false_, and no URL-forbidden set either.
///
/// curl passes neither `IDN2_USE_STD3_ASCII_RULES` nor anything equivalent,
/// so ASCII characters that STD3 would reject -- the underscore above all --
/// must survive. Shared by both directions.
#[allow(dead_code)]
const DENY_LIST: AsciiDenyList = AsciiDenyList::EMPTY;

/// _CheckHyphens=true_ for the A-label direction.
///
/// Reproduces libidn2's *lookup* validation, which rejects a hyphen in the
/// first, third, fourth or last position of a label.
#[allow(dead_code)]
const TO_ASCII_HYPHENS: Hyphens = Hyphens::Check;

/// _VerifyDNSLength=false_, because the length rule is applied by
/// [`dns_bounds_ok`] instead.
///
/// The bound itself is not abandoned -- `tests/data/test1035` depends on it,
/// and [`uts46_to_ascii`] still enforces it on the A-label that comes out.
/// What is abandoned is `idna`'s *spelling* of the rule, because
/// [`idna::uts46::verify_dns_length`] additionally rejects an empty label
/// and libidn2 does not. Measured: the oracle converts `<U+00E5>..b` to
/// `xn--5ca..b`, `.se` and `a..b` to themselves, and `<U+00E5>.se..` to
/// `xn--5ca.se..`; with [`DnsLength::VerifyAllowRootDot`] all four are
/// rejected. See [`dns_bounds_ok`] for the rule that replaces it.
#[allow(dead_code)]
const TO_ASCII_DNS_LENGTH: DnsLength = DnsLength::Ignore;

/// The DNS label bound, `IDN2_LABEL_MAX_LENGTH` (`/usr/include/idn2.h:162`).
///
/// Counted in *bytes* for an A-label, which is ASCII, and in *code points*
/// for a U-label. That is libidn2's own asymmetry rather than a convenience:
/// `idn2_to_unicode_8z8z` works on UTF-32 internally, so its label bound is
/// a code-point count. Measured -- a 40-code-point, 80-byte label converts,
/// a 64-code-point, 128-byte one is `IDN2_TOO_BIG_LABEL`.
const MAX_LABEL: usize = 63;

/// The A-label name bound: 253 bytes once a single root dot is discounted.
///
/// Measured against libidn2 2.3.8: a 253-byte ASCII name converts, 254 is
/// `IDN2_TOO_BIG_DOMAIN`, and a 254-byte name *ending in a dot* converts
/// while 255 does not. Note this is not `IDN2_DOMAIN_MAX_LENGTH` (255): the
/// lookup direction is stricter than the conversion direction, and 253 is
/// the figure `idna`'s own [`idna::uts46::verify_dns_length`] uses.
const MAX_ALABEL_NAME: usize = 253;

/// The U-label name bound: 255 code points, `IDN2_DOMAIN_MAX_LENGTH`
/// (`/usr/include/idn2.h:173`), with label separators counted and no root-dot
/// discount.
///
/// Measured: 255 code points convert, 256 is `IDN2_TOO_BIG_DOMAIN`, and a
/// 254-code-point/443-byte name converts -- so the count is code points, not
/// bytes. The bound applies to the *decoded* result and not to the input: a
/// 277-byte punycode host decoding to 102 code points converts.
const MAX_ULABEL_NAME: usize = 255;

/// The largest U-label result in bytes, and therefore the accumulator's
/// capacity.
///
/// [`MAX_ULABEL_NAME`] code points of at most four UTF-8 bytes each. Because
/// [`idn_to_unicode`] checks the running count *before* appending, the output
/// never exceeds this, so a single reservation of it makes every subsequent
/// `push_str` incapable of reallocating -- which is what keeps that function's
/// only allocation fallible without a fallible `push_str`.
const MAX_ULABEL_NAME_BYTES: usize = MAX_ULABEL_NAME * 4;

/// The ACE prefix that marks a punycode label, `xn--`.
///
/// Matched case-insensitively. Measured: `XN--4CAB6C.se`, `Xn--4cab6c.se` and
/// `xN--4cab6c.se` all decode, while `xn-4cab6c.se` and `xn4cab6c.se` are
/// copied through untouched.
const ACE_PREFIX: &str = "xn--";

/// The `idna` version this module is compiled against.
///
/// Kept as a literal because `Cargo.toml` pins the crate exactly
/// (`idna = "=1.1.0"`), and because a `String` built from
/// `env!("CARGO_PKG_VERSION")` would report *this* crate's version rather
/// than the dependency's. `crate::version` carries the same literal for the
/// `Features:` banner, and the pair is kept honest by a test there.
const IDNA_VERSION: &str = "1.1.0";

// Curl_is_ASCII_name -- lib/idn.c:223-236

/// Whether a hostname is plain ASCII, and therefore needs no conversion.
///
/// Reproduces `Curl_is_ASCII_name` (`lib/idn.c:223-236`) exactly:
///
/// ```text
///   bool Curl_is_ASCII_name(const char *hostname)
///   {
///     const unsigned char *ch = (const unsigned char *)hostname;
///     if(!hostname) /* bad input, consider it ASCII! */
///       return TRUE;
///     while(*ch) {
///       if(*ch++ & 0x80)
///         return FALSE;
///     }
///     return TRUE;
///   }
/// ```
///
/// Two properties of that C body are load-bearing and are preserved here:
///
/// * **An absent host is ASCII.** The C comment is explicit -- "bad input,
///   consider it ASCII!" -- so `None` yields `true`. A caller that has no
///   host at all must take the no-conversion path, not the error path.
/// * **Any byte with the high bit set makes it non-ASCII.** The test is
///   bitwise, not a UTF-8 decode, so it answers "does this need IDN
///   processing at all?" without caring whether the bytes are well-formed.
///   An empty host is ASCII, `0x7f` is ASCII, and `0x80` is not.
///
/// This function is **not** inside the `#ifdef USE_IDN` block, which opens
/// two lines later at `lib/idn.c:238`; `lib/idn.h:26` declares it
/// unconditionally. It is therefore unconditional here too.
///
/// One consequence of the slice signature deserves recording: the C loop
/// stops at the NUL terminator, whereas this scans the whole slice. The
/// difference is unobservable for the callers, whose hosts come from
/// NUL-terminated storage and so contain no interior NUL.
///
/// # Examples
///
/// ```text
///   is_ascii_name(None)                 == true   // "bad input"
///   is_ascii_name(Some(b""))            == true
///   is_ascii_name(Some(b"example.com")) == true
///   is_ascii_name(Some(b"\xc3\xa4.com")) == false // U+00E4 in UTF-8
/// ```
#[must_use]
#[allow(dead_code)]
pub(crate) fn is_ascii_name(host: Option<&[u8]>) -> bool {
    match host {
        // lib/idn.c:228-229 -- "bad input, consider it ASCII!"
        None => true,
        Some(bytes) => !bytes.iter().any(|byte| byte & 0x80 != 0),
    }
}

// Shared input validation

/// Validates that a host is well-formed UTF-8, or fails the conversion.
///
/// This is the Rust stand-in for the locale-to-UTF-8 conversion that
/// `idn2_lookup_ul` (`lib/idn.c:39-40`) performs internally and that fails
/// on ill-formed input. It must reject rather than repair: a lossy decode
/// would substitute U+FFFD for the offending bytes and *succeed* where curl
/// fails, converting `tests/data/test1034`'s expected exit code 3 into a
/// pass. `std::str::from_utf8` is therefore the only decoder used here, and
/// its error is discarded rather than inspected because the C original
/// distinguishes no sub-cases either.
///
/// `Uts46::to_ascii` and `Uts46::to_unicode` also check UTF-8 well-formedness
/// themselves, so this is nominally redundant for the happy path. It is kept
/// because it makes the requirement explicit and local, because it gives both
/// directions the identical failure mode, and because `Uts46::to_unicode`
/// signals its failures through a value that also carries a lossy string --
/// exactly the value that must never be returned to a caller.
#[allow(dead_code)]
fn validated_utf8(host: &[u8]) -> Result<&str, CURLcode> {
    std::str::from_utf8(host).map_err(|_| CURLcode::UrlMalformat)
}

// Transitional processing -- the fallback of lib/idn.c:263-265

/// Whether a character is one of UTS-46's *deviation* characters.
///
/// These are the four code points whose treatment differs between
/// transitional and non-transitional processing, plus U+1E9E, which
/// case-folds onto U+00DF and so shares its fate.
#[allow(dead_code)]
fn is_deviation(c: char) -> bool {
    matches!(
        c,
        '\u{df}' | '\u{1e9e}' | '\u{3c2}' | '\u{200C}' | '\u{200D}'
    )
}

/// Applies UTS-46 transitional processing as a preprocessing step.
///
/// `idna 1.1.0` implements non-transitional processing only. `uts46.rs:20`
/// states the position plainly -- _Transitional_Processing_ is "always
/// _false_ but could be implemented as a preprocessing step" -- and the
/// crate's own deprecated compatibility layer takes exactly that route in
/// `deprecated.rs:25-62`. The mapping below is that function's mapping, and
/// the crate authors' definition is followed rather than a fresh one
/// invented:
///
/// | input | transitional output |
/// |---|---|
/// | U+00DF, U+1E9E (sharp s) | `ss` |
/// | U+03C2 (final sigma) | U+03C3 |
/// | U+200C ZWNJ, U+200D ZWJ | removed |
///
/// The deprecated `Idna`/`Config` pair is deliberately *not* called: it is
/// `#[deprecated]`, and a deprecation warning does not survive
/// `cargo clippy -- -D warnings`.
///
/// Borrowing is preserved when there is nothing to map, so the common case
/// -- the overwhelming majority of hostnames -- allocates nothing. That is a
/// side effect of the shape, not an optimization being pursued.
#[allow(dead_code)]
fn transitional_map(input: &str) -> Cow<'_, str> {
    if !input.chars().any(is_deviation) {
        return Cow::Borrowed(input);
    }

    let mut mapped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\u{df}' | '\u{1e9e}' => mapped.push_str("ss"),
            '\u{3c2}' => mapped.push('\u{3c3}'),
            '\u{200C}' | '\u{200D}' => {}
            other => mapped.push(other),
        }
    }
    Cow::Owned(mapped)
}

// idn_decode / Curl_idn_decode -- Unicode host to A-label

/// libidn2's DNS length rule for an A-label, which tolerates empty labels.
///
/// Derived from [`idna::uts46::verify_dns_length`]
/// (`idna-1.1.0/src/uts46.rs:463-487`) with one clause removed: that function
/// returns `false` for an empty label, and libidn2's lookup has no such rule.
/// Everything else is identical, including the root-dot discount, so this is
/// a narrowing of `idna`'s rule rather than a reimplementation of DNS.
///
/// The three clauses, each measured against libidn2 2.3.8 driven exactly as
/// `lib/idn.c:247-268` drives it:
///
/// * One trailing dot is discounted. `<U+00E5><U+00E4><U+00F6>.se.` converts
///   to `xn--4cab6c.se.`, so a rooted name is legal, and the 253-byte bound
///   is measured on the name *without* that dot -- 254 bytes ending in a dot
///   converts, 255 does not.
/// * The name, so discounted, is at most [`MAX_ALABEL_NAME`] bytes.
/// * Every label is at most [`MAX_LABEL`] bytes. An empty label satisfies
///   this, which is the whole point.
///
/// Applied to the *output* of the conversion rather than the input, because
/// that is where libidn2 applies it: twenty `<U+00E5><U+00E4><U+00F6>` labels
/// are 142 input bytes and 222 A-label bytes and convert, while thirty are
/// 212 input bytes and 332 A-label bytes and are `IDN2_TOO_BIG_DOMAIN`.
#[allow(dead_code)]
fn dns_bounds_ok(alabel: &str) -> bool {
    let bytes = alabel.as_bytes();
    let without_root_dot = bytes.strip_suffix(b".").unwrap_or(bytes);
    if without_root_dot.len() > MAX_ALABEL_NAME {
        return false;
    }
    without_root_dot
        .split(|byte| *byte == b'.')
        .all(|label| label.len() <= MAX_LABEL)
}

/// One UTS-46 _ToASCII_ attempt with this module's fixed parameters.
///
/// `None` on any validity error, which is all `idn_to_ascii` needs in order
/// to decide whether to make its second attempt. `idna::Errors` carries no
/// discriminated detail in 1.1.0, so nothing is lost by collapsing it.
///
/// The length rule is applied here rather than inside `Uts46::to_ascii` -- see
/// [`TO_ASCII_DNS_LENGTH`] and [`dns_bounds_ok`] -- and it is applied to the
/// A-label that came out, so a name that is short in Unicode but long once
/// encoded is still rejected.
#[allow(dead_code)]
fn uts46_to_ascii(input: &str) -> Option<String> {
    Uts46::new()
        .to_ascii(
            input.as_bytes(),
            DENY_LIST,
            TO_ASCII_HYPHENS,
            TO_ASCII_DNS_LENGTH,
        )
        .ok()
        .map(Cow::into_owned)
        .filter(|alabel| dns_bounds_ok(alabel))
}

/// The two-attempt conversion of `idn_decode` (`lib/idn.c:247-280`).
///
/// Non-transitional processing first, then transitional processing as a
/// fallback "for better IDNA2003 compatibility" (`lib/idn.c:263-264`), and
/// `CURLE_URL_MALFORMAT` only once both have failed (`lib/idn.c:266-267`).
/// The order matters, and so does the fact that there are two: the fallback
/// widens the accepted hostname set observably, and `a<U+200C>b.se` is a
/// concrete input that reaches the wire only because of it.
///
/// Kept separate from [`to_ascii`] so that the C file's two-function split
/// survives the translation -- the retry belongs to `idn_decode`, and the
/// empty-result rejection belongs to `Curl_idn_decode`. Collapsing them
/// would make a successful-but-empty first attempt trigger a retry, which
/// the C code does not do.
#[allow(dead_code)]
fn idn_to_ascii(input: &str) -> Result<String, CURLcode> {
    // Attempt 1 -- IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL (lib/idn.c:253-261).
    // NFC is supplied by UTS-46's own mapping stage.
    if let Some(alabel) = uts46_to_ascii(input) {
        return Ok(alabel);
    }

    // Attempt 2 -- IDN2_TRANSITIONAL (lib/idn.c:265).
    uts46_to_ascii(&transitional_map(input)).ok_or(CURLcode::UrlMalformat)
}

/// Converts a Unicode hostname to its A-label (punycode) form.
///
/// **This is curl's `Curl_idn_decode` (`lib/idn.c:302-325`), despite the
/// direction.** In curl's vocabulary "decode" means *to ASCII*; see the
/// module documentation.
///
/// Reached from the sibling module's `host_decode`
/// (`lib/urlapi.c:1338-1345`) when `CURLU_PUNYCODE` is set and the stored
/// host is not already ASCII (`lib/urlapi.c:1401-1409`), and from the
/// resolver when it reproduces `Curl_idnconvert_hostname`
/// (`lib/idn.c:359-376`).
///
/// # Behaviour
///
/// 1. Ill-formed UTF-8 is rejected outright -- see [`validated_utf8`].
/// 2. UTS-46 _ToASCII_ is attempted non-transitionally, then transitionally.
/// 3. **An empty result is rejected** (`lib/idn.c:317-320`: "ended up zero
///    length, not acceptable"). [`to_unicode`] deliberately has no
///    counterpart to this step.
///
/// # Errors
///
/// [`CURLcode::UrlMalformat`] -- value 3 -- for ill-formed UTF-8, for a host
/// both processing modes reject, and for a host whose conversion is empty.
/// It is the only error this function can produce; the caller turns it into
/// `CURLUE_BAD_HOSTNAME`.
///
/// # Examples
///
/// Hosts are shown as Rust literals; every one is passed as `&[u8]`.
///
/// ```text
///   to_ascii "www.\u{e5}\u{e4}\u{f6}.se" -> Ok("www.xn--4cab6c.se")
///   to_ascii "www.gro\u{df}e.de"         -> Ok("www.xn--groe-xna.de")
///   to_ascii "xn--4cab6c.se"             -> Ok("xn--4cab6c.se")
///   to_ascii b"invalid-\xe2\x90.local"   -> Err(UrlMalformat)
/// ```
#[allow(dead_code)]
pub(crate) fn to_ascii(host: &[u8]) -> Result<String, CURLcode> {
    let input = validated_utf8(host)?;
    let decoded = idn_to_ascii(input)?;

    // lib/idn.c:317-320 -- an empty A-label is not acceptable.
    if decoded.is_empty() {
        return Err(CURLcode::UrlMalformat);
    }
    Ok(decoded)
}

// idn_encode / Curl_idn_encode -- A-label to U-label

/// The punycode payload of an ACE label, or `None` if the label is not one.
///
/// The prefix test is case-insensitive and exact-width: measured against
/// libidn2 2.3.8, `XN--4CAB6C.se`, `Xn--4cab6c.se` and `xN--4cab6c.se` all
/// decode to `<U+00E5><U+00E4><U+00F6>.se`, while `xn-4cab6c.se` and
/// `xn4cab6c.se` are copied through untouched. An empty payload is returned
/// as `Some("")` rather than treated as a non-ACE label, because the oracle
/// rejects `xn--.se` outright instead of passing it through.
///
/// Indexing at [`ACE_PREFIX`]`.len()` cannot split a character: the bytes
/// before that point have just been compared against ASCII, so byte 4 is a
/// character boundary whenever the comparison succeeded.
#[allow(dead_code)]
fn ace_payload(label: &str) -> Option<&str> {
    let bytes = label.as_bytes();
    if bytes.len() >= ACE_PREFIX.len()
        && bytes[..ACE_PREFIX.len()].eq_ignore_ascii_case(ACE_PREFIX.as_bytes())
    {
        Some(&label[ACE_PREFIX.len()..])
    } else {
        None
    }
}

/// One label of the U-label direction: punycode-decoded, or copied verbatim.
///
/// Borrowed for a non-ACE label so that the overwhelmingly common case --
/// an ASCII label that needs nothing done to it -- copies once into the
/// accumulator rather than twice.
///
/// The `is_ascii` rejection is the rule that makes `xn--ab-`, `xn--abc-`,
/// `xn----` and `xn--AB-` errors rather than the labels `ab`, `abc`, `-` and
/// `AB`. All four are `IDN2_PUNYCODE_BAD_INPUT` from the oracle, and all four
/// decode successfully as far as RFC 3492 is concerned -- what they have in
/// common is that nothing was inserted, so the label was never a legitimate
/// A-label in the first place. RFC 5891 section 4.2 says as much: an A-label
/// must decode to a U-label, and a pure-ASCII string is not one.
#[allow(dead_code)]
fn decode_label(label: &str) -> Result<Cow<'_, str>, CURLcode> {
    match ace_payload(label) {
        Some(payload) => {
            let decoded = idna::punycode::decode_to_string(payload)
                .ok_or(CURLcode::UrlMalformat)?;
            if decoded.is_ascii() {
                return Err(CURLcode::UrlMalformat);
            }
            Ok(Cow::Owned(decoded))
        }
        None => Ok(Cow::Borrowed(label)),
    }
}

/// The conversion of `idn_encode` (`lib/idn.c:282-300`).
///
/// The C body is a single call with no flags:
///
/// ```text
///   int rc = idn2_to_unicode_8z8z(puny, &enc, 0);
///   if(rc != IDNA_SUCCESS)
///     return rc == IDNA_MALLOC_ERROR ? CURLE_OUT_OF_MEMORY
///                                    : CURLE_URL_MALFORMAT;
/// ```
///
/// There is no retry here, in either implementation -- transitional
/// processing is a property of the *lookup* direction only.
///
/// # Why this is not `Uts46::to_unicode`
///
/// `idn2_to_unicode_8z8z` is not UTS-46 _ToUnicode_. It is a **per-label
/// punycode decode**: a label carrying the `xn--` prefix is decoded, every
/// other label is copied byte for byte, and no mapping, case folding,
/// normalization or validity check is applied to either kind. Driving
/// `Uts46::to_unicode` instead diverges on four measurable classes of input,
/// all of them reachable through `curl_url_get(CURLU_PUNY2IDN)`:
///
/// * **Case.** `EXAMPLE.COM` comes back unchanged from the oracle; UTS-46
///   folds it to `example.com`.
/// * **Mapping.** U+200B ZERO WIDTH SPACE and U+00AD SOFT HYPHEN come back
///   unchanged; UTS-46 maps both away and yields the empty string.
/// * **Validity.** `a<U+200C>b.se` comes back unchanged; UTS-46 rejects the
///   label because ZWNJ is CONTEXTJ outside a joining context. `xn--a.se`
///   decodes to U+0080 followed by `.se`; UTS-46 rejects U+0080 as
///   disallowed.
/// * **Length.** The bounds apply to the decoded result in code points, and
///   `Uts46::to_unicode` takes no _DnsLength_ parameter at all, so a 64-byte
///   label that the oracle calls `IDN2_TOO_BIG_LABEL` would be accepted.
///
/// So the direction is spelled out here, using the crate's punycode decoder
/// -- `idna::punycode::decode_to_string`, public at
/// `idna-1.1.0/src/punycode.rs:48` -- for the only step that needs an
/// implementation. The decoder is the right one to the byte: it emits the
/// basic code points verbatim rather than lower-casing them, so
/// `xn--BCHER-kva.de` yields `B<U+00FC>CHER.de` exactly as the oracle does,
/// and it accepts an upper-case payload, so `xn--4CAB6C.se` decodes.
///
/// # Ordering
///
/// Both bounds are checked *before* the label is appended, which is what
/// keeps the accumulator inside its one reservation -- see
/// [`MAX_ULABEL_NAME_BYTES`]. It also bounds the work: a host of a million
/// dots is refused after the 256th rather than copied.
#[allow(dead_code)]
fn idn_to_unicode(puny: &str) -> Result<String, CURLcode> {
    let mut out =
        crate::util::fallible::string_with_capacity(MAX_ULABEL_NAME_BYTES)
            .map_err(crate::util::fallible::oom)?;
    let mut total = 0usize;
    let mut first = true;

    for label in puny.split('.') {
        let needs_separator = !first;
        first = false;

        let decoded = decode_label(label)?;
        let code_points = decoded.chars().count();
        if code_points > MAX_LABEL {
            return Err(CURLcode::UrlMalformat);
        }
        total += usize::from(needs_separator) + code_points;
        if total > MAX_ULABEL_NAME {
            return Err(CURLcode::UrlMalformat);
        }

        if needs_separator {
            out.push('.');
        }
        out.push_str(&decoded);
    }

    debug_assert!(
        out.len() <= MAX_ULABEL_NAME_BYTES,
        "the reservation must be an upper bound on the result"
    );
    Ok(out)
}

/// Converts an A-label (punycode) hostname to its Unicode U-label form.
///
/// **This is curl's `Curl_idn_encode` (`lib/idn.c:327-344`), despite the
/// direction.** In curl's vocabulary "encode" means *to Unicode*; see the
/// module documentation.
///
/// Reached from the sibling module's `host_encode`
/// (`lib/urlapi.c:1347-1354`) when `CURLU_PUNY2IDN` is set and the stored
/// host *is* already ASCII (`lib/urlapi.c:1411-1419`).
///
/// # Behaviour
///
/// 1. Ill-formed UTF-8 is rejected outright, as in [`to_ascii`]. The input
///    is expected to be an A-label and therefore ASCII, but nothing
///    guarantees it, and the same failure mode in both directions is worth
///    more than a saved check.
/// 2. Each label is punycode-decoded if it carries the `xn--` prefix and
///    copied verbatim otherwise, with no transitional fallback -- see
///    [`idn_to_unicode`] for why this is a decode rather than UTS-46
///    _ToUnicode_.
/// 3. **An empty result is *not* rejected.** `lib/idn.c:341-342` assigns
///    unconditionally, and that asymmetry against [`to_ascii`] is preserved
///    on purpose. It is reachable: an empty host converts to `Ok("")` here
///    and to `Err` there.
///
/// # Errors
///
/// [`CURLcode::UrlMalformat`] for ill-formed UTF-8, for an `xn--` label whose
/// payload is not decodable punycode or decodes to pure ASCII, and for a
/// decoded label or name over its length bound. The caller turns it into
/// `CURLUE_BAD_HOSTNAME`. [`CURLcode::OutOfMemory`] if the accumulator cannot
/// be reserved, which is the `IDNA_MALLOC_ERROR` arm of `lib/idn.c:288`.
///
/// # Examples
///
/// ```text
///   to_unicode(b"xn--4cab6c.se")     == Ok("<U+00E5><U+00E4><U+00F6>.se")
///   to_unicode(b"XN--4CAB6C.se")     == Ok("<U+00E5><U+00E4><U+00F6>.se")
///   to_unicode(b"EXAMPLE.COM")       == Ok("EXAMPLE.COM")   // case kept
///   to_unicode(b"xn--zzzzzz.se")     == Err(UrlMalformat)
/// ```
#[allow(dead_code)]
pub(crate) fn to_unicode(host: &[u8]) -> Result<String, CURLcode> {
    let puny = validated_utf8(host)?;
    idn_to_unicode(puny)
}

// Capability reporting -- idn_present, lib/version.c:407-416 and :496

/// Whether an internationalised-domain-name implementation is present.
///
/// The Rust counterpart of `idn_present` (`lib/version.c:407-416`), which
/// the feature table registers at `lib/version.c:496` as
/// `FEATURE("IDN", idn_present, CURL_VERSION_IDN)`, with
/// `CURL_VERSION_IDN` defined as `(1<<10)` at `include/curl/curl.h:3187`.
///
/// It answers `true`, and it does so as a *function* rather than a constant
/// on purpose: the C table dispatches through a function pointer, and
/// keeping the shape means the `Features:` banner is computed from the
/// capability rather than hard-coded beside it. If `idna` were ever made an
/// optional dependency, this is the single place that would have to change,
/// and the banner would follow.
///
/// Total and non-panicking, as a predicate consumed by the version banner
/// must be -- `curl --version` is the first thing the test harness runs, and
/// a panic here would unwind toward a C caller through `curl-rs-ffi`.
#[must_use]
pub fn available() -> bool {
    true
}

/// The version of the IDN implementation, for the version banner.
///
/// Returns the pinned `idna` version. `Option` mirrors the nullability of
/// `curl_version_info_data`'s `libidn` field, which is what
/// `lib/version.c:413` tests, so a build without an IDN backend would report
/// `None` here without any signature change.
///
/// **This is not a libidn2 version, and it must never be published as one.**
/// In C the `IDN` feature bit and the `libidn` field are coupled, because
/// `idn_present` *is* `info->libidn != NULL`. On an `idna`-backed build the
/// truthful answer decouples them: the capability exists, so `IDN` is
/// advertised, while `libidn` stays absent because libidn2 is not what is
/// linked. Emitting a `libidn2/...` token would additionally set
/// `$feature{"libidn2"}` in the harness (`tests/runtests.pl:625-626`) on a
/// false premise.
#[must_use]
pub fn version_string() -> Option<&'static str> {
    Some(IDNA_VERSION)
}

// Tests
//
// `tests/unit/*.c` and `tests/libtest/*.c` are C programs that link a debug
// static libcurl and call internal `Curl_*` symbols. A Rust static library
// does not export `pub(crate)` items -- they are genuinely absent from the
// symbol table, not merely hidden -- so those programs cannot link no matter
// how good the implementation is, and their coverage is relocated here
// instead. Widening the visibility of the items below in order to make them
// link is precisely what must not be done.
//
// Every expectation is anchored to something outside this file:
//
//   * `tests/data/test*` -- the behavioural specification.
//   * `tests/libtest/lib1560.c:206-239` -- the URL API's own IDN corpus.
//   * A mechanical diff against libidn2 2.3.8, driven exactly as
//     `lib/idn.c:247-300` drives it: a 165-host corpus, hex-encoded on both
//     sides, 325 of 330 comparisons byte-identical. Every expectation below
//     that cites "the oracle" is a row of that diff and not an inference.
//     Three of the five differences are the one surviving divergence,
//     _CheckBidi_, which `divergence_a_mixed_direction_label_is_rejected`
//     asserts so that an `idna` upgrade changing the behaviour fails loudly
//     here rather than silently on the wire; the other two are the
//     interior-NUL interface artefact, covered by
//     `an_interior_nul_is_not_a_c_string_terminator`.
//
// Nothing below touches the network, the filesystem, the clock or the
// environment, so the whole module runs under Miri.

#[cfg(test)]
mod tests {
    use super::*;

    /// The A-label of `<U+00E5><U+00E4><U+00F6>.se`, which five fixtures
    /// expect verbatim.
    const AAO_SE_ALABEL: &str = "xn--4cab6c.se";

    // Curl_is_ASCII_name -- lib/idn.c:223-236

    #[test]
    fn absent_host_is_ascii() {
        // lib/idn.c:228-229 -- "bad input, consider it ASCII!". A caller
        // with no host must take the no-conversion path.
        assert!(is_ascii_name(None));
    }

    #[test]
    fn empty_host_is_ascii() {
        // The C loop body never executes, so it falls through to TRUE.
        assert!(is_ascii_name(Some(b"")));
    }

    #[test]
    fn plain_ascii_host_is_ascii() {
        assert!(is_ascii_name(Some(b"example.com")));
        assert!(is_ascii_name(Some(AAO_SE_ALABEL.as_bytes())));
        assert!(is_ascii_name(Some(b"_under-score.example.")));
    }

    #[test]
    fn high_bit_makes_a_host_non_ascii() {
        // U+00E4 in UTF-8 is 0xc3 0xa4; both bytes have the high bit set.
        assert!(!is_ascii_name(Some(b"\xc3\xa4.com")));
        // Ill-formed UTF-8 is still detected: the test is bitwise, not a
        // decode. This is the tests/data/test1034 host.
        assert!(!is_ascii_name(Some(b"invalid-utf8-\xe2\x90.local")));
    }

    #[test]
    fn the_boundary_byte_is_exactly_0x80() {
        // 0x7f is the last ASCII byte, 0x80 the first non-ASCII one.
        assert!(is_ascii_name(Some(&[0x7f])));
        assert!(!is_ascii_name(Some(&[0x80])));
        // And every byte is examined, not just the first.
        assert!(!is_ascii_name(Some(b"aaaaaaaa\x80")));
        assert!(is_ascii_name(Some(b"aaaaaaaa\x7f")));
    }

    #[test]
    fn is_ascii_name_examines_the_whole_range() {
        for byte in 0u8..=0x7f {
            assert!(
                is_ascii_name(Some(&[byte])),
                "0x{byte:02x} must count as ASCII"
            );
        }
        for byte in 0x80u8..=0xff {
            assert!(
                !is_ascii_name(Some(&[byte])),
                "0x{byte:02x} must count as non-ASCII"
            );
        }
    }

    // Fixture-derived acceptance -- these are the real gate

    #[test]
    fn test165_converts_both_of_its_hosts() {
        // tests/data/test165 expects, byte for byte:
        //   Host: www.xn--4cab6c.se
        //   Host: www.xn--groe-xna.de
        assert_eq!(
            to_ascii("www.\u{e5}\u{e4}\u{f6}.se".as_bytes()),
            Ok("www.xn--4cab6c.se".to_string())
        );
        // U+00DF is PRESERVED, which is what proves the first attempt is
        // non-transitional: transitional processing would map it to "ss"
        // and yield the all-ASCII `www.grosse.de`.
        assert_eq!(
            to_ascii("www.gro\u{df}e.de".as_bytes()),
            Ok("www.xn--groe-xna.de".to_string())
        );
    }

    #[test]
    fn test1448_2046_2047_share_one_expectation() {
        // All three fixtures send `Host: xn--4cab6c.se`, with and without a
        // port and with and without a proxy.
        assert_eq!(
            to_ascii("\u{e5}\u{e4}\u{f6}.se".as_bytes()),
            Ok(AAO_SE_ALABEL.to_string())
        );
    }

    #[test]
    fn test1034_rejects_an_incomplete_utf8_sequence() {
        // tests/data/test1034, keyword FAILURE, expects exit code 3. The
        // harness expands %hex[%e2%90]hex% to the raw bytes below, which are
        // the first two bytes of a three-byte sequence. A lossy conversion
        // would substitute U+FFFD and succeed, turning the expected failure
        // into a pass.
        assert_eq!(
            to_ascii(b"invalid-utf8-\xe2\x90.local"),
            Err(CURLcode::UrlMalformat)
        );
        assert_eq!(CURLcode::UrlMalformat.as_i32(), 3);
    }

    #[test]
    fn test1035_rejects_a_too_long_idn_hostname() {
        // tests/data/test1035, keyword FAILURE, expects exit code 3. The
        // host below is the fixture's, with %hex[...]hex% expanded. Its
        // A-label exceeds the 63-byte label bound, so this is the assertion
        // dns_bounds_ok exists for: with no length rule at all the
        // conversion succeeds and the fixture fails. Measured -- the oracle
        // answers IDN2_TOO_BIG_LABEL for this host.
        let host = "too-long-IDN-name-c\u{fc}rl-r\u{fc}le\u{df}\
                    -la-la-la-dee-da-flooby-nooby.local";
        assert_eq!(to_ascii(host.as_bytes()), Err(CURLcode::UrlMalformat));
    }

    #[test]
    fn test763_rejects_a_hostname_that_maps_to_nothing() {
        // tests/data/test763, "Unicode hostname ending up in a blank name",
        // expects exit code 3. U+200B ZERO WIDTH SPACE followed by U+200C
        // ZERO WIDTH NON-JOINER.
        assert_eq!(
            to_ascii("\u{200b}\u{200c}".as_bytes()),
            Err(CURLcode::UrlMalformat)
        );
    }

    // tests/libtest/lib1560.c:206-239 -- the URL API's own corpus

    #[test]
    fn lib1560_round_trips_raksmorgas() {
        // lib1560.c:207-209 (CURLU_PUNYCODE) and :210-215 (CURLU_PUNY2IDN).
        assert_eq!(
            to_ascii("r\u{e4}ksm\u{f6}rg\u{e5}s.se".as_bytes()),
            Ok("xn--rksmrgs-5wao1o.se".to_string())
        );
        assert_eq!(
            to_unicode(b"xn--rksmrgs-5wao1o.se"),
            Ok("r\u{e4}ksm\u{f6}rg\u{e5}s.se".to_string())
        );
        assert_eq!(
            to_unicode(b"www.xn--rksmrgs-5wao1o.se"),
            Ok("www.r\u{e4}ksm\u{f6}rg\u{e5}s.se".to_string())
        );
    }

    #[test]
    fn lib1560_folds_the_compatibility_spelling_of_curl_se() {
        // lib1560.c:224-239: U+2102 DOUBLE-STRUCK CAPITAL C, U+1D64 LATIN
        // SUBSCRIPT SMALL LETTER U, U+24C7 CIRCLED LATIN CAPITAL LETTER R,
        // U+2112 SCRIPT CAPITAL L, U+3002 IDEOGRAPHIC FULL STOP, U+1D412
        // MATHEMATICAL BOLD CAPITAL S, U+1F134 SQUARED LATIN CAPITAL
        // LETTER E. UTS-46 mapping folds all of it down to plain ASCII,
        // including the ideographic full stop becoming a label separator.
        let fancy =
            "\u{2102}\u{1d64}\u{24c7}\u{2112}\u{3002}\u{1d412}\u{1f134}";
        assert_eq!(to_ascii(fancy.as_bytes()), Ok("curl.se".to_string()));
    }

    // Round-trips across scripts

    #[test]
    fn latin_round_trip() {
        assert_eq!(
            to_ascii("b\u{fc}cher.example".as_bytes()),
            Ok("xn--bcher-kva.example".to_string())
        );
        assert_eq!(
            to_unicode(b"xn--bcher-kva.example"),
            Ok("b\u{fc}cher.example".to_string())
        );
    }

    #[test]
    fn cyrillic_round_trip() {
        // "primer.ispytanie" spelled in Cyrillic.
        let unicode = "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\
                       \u{438}\u{441}\u{43f}\u{44b}\u{442}\u{430}\u{43d}\
                       \u{438}\u{435}";
        let alabel = "xn--e1afmkfd.xn--80akhbyknj4f";
        assert_eq!(to_ascii(unicode.as_bytes()), Ok(alabel.to_string()));
        assert_eq!(to_unicode(alabel.as_bytes()), Ok(unicode.to_string()));
    }

    #[test]
    fn cjk_round_trip() {
        let unicode = "\u{4f8b}.\u{30c6}\u{30b9}\u{30c8}";
        let alabel = "xn--fsq.xn--zckzah";
        assert_eq!(to_ascii(unicode.as_bytes()), Ok(alabel.to_string()));
        assert_eq!(to_unicode(alabel.as_bytes()), Ok(unicode.to_string()));
    }

    #[test]
    fn mixed_script_multi_label_round_trip() {
        // An ASCII label, a Latin-with-diacritics label and a CJK label in
        // one name, so that per-label conversion is exercised rather than
        // whole-string conversion.
        let unicode = "www.\u{e5}\u{e4}\u{f6}.\u{4f8b}.se";
        let alabel = "www.xn--4cab6c.xn--fsq.se";
        assert_eq!(to_ascii(unicode.as_bytes()), Ok(alabel.to_string()));
        assert_eq!(to_unicode(alabel.as_bytes()), Ok(unicode.to_string()));
    }

    #[test]
    fn an_a_label_passes_through_to_ascii_unchanged() {
        // In curl's own flow this never happens -- `Curl_is_ASCII_name`
        // short-circuits an ASCII host before host_decode is reached
        // (lib/urlapi.c:1401-1402) -- but the function must still be total,
        // and Hyphens::Check must not reject the `xn--` prefix's own
        // third-and-fourth-position hyphens. UTS-46 decodes the A-label
        // before applying the hyphen rule, which is why this holds.
        assert_eq!(
            to_ascii(AAO_SE_ALABEL.as_bytes()),
            Ok(AAO_SE_ALABEL.to_string())
        );
        assert_eq!(
            to_ascii(b"www.xn--rksmrgs-5wao1o.se"),
            Ok("www.xn--rksmrgs-5wao1o.se".to_string())
        );
        assert_eq!(to_ascii(b"example.com"), Ok("example.com".to_string()));
    }

    #[test]
    fn an_uppercase_a_label_is_recognised_by_to_unicode() {
        // Measured against the oracle: XN--4CAB6C.se yields
        // <U+00E5><U+00E4><U+00F6>.se, so the ACE prefix match is
        // case-insensitive.
        assert_eq!(
            to_unicode(b"XN--4CAB6C.se"),
            Ok("\u{e5}\u{e4}\u{f6}.se".to_string())
        );
    }

    // The empty-result asymmetry -- lib/idn.c:317-320 vs :341-342

    #[test]
    fn an_empty_host_shows_the_asymmetry_between_the_two_directions() {
        // The deliberate asymmetry between the two C functions:
        // Curl_idn_decode rejects a zero-length result (lib/idn.c:317-320,
        // "ended up zero length, not acceptable") while Curl_idn_encode
        // assigns unconditionally (lib/idn.c:341-342). Measured: the oracle
        // agrees in both directions on this host.
        assert_eq!(to_ascii(b""), Err(CURLcode::UrlMalformat));
        assert_eq!(to_unicode(b""), Ok(String::new()));
    }

    #[test]
    fn characters_uts46_maps_away_survive_the_u_label_direction() {
        // U+200B ZERO WIDTH SPACE and U+00AD SOFT HYPHEN are mapped away
        // entirely by UTS-46, which is why they used to demonstrate the
        // asymmetry above -- Uts46::to_unicode returned Ok(""). That was a
        // divergence: idn2_to_unicode_8z8z maps nothing, and the oracle
        // returns both hosts unchanged (measured, C2 AD and E2 80 8B
        // respectively). The A-label direction still rejects them, because
        // there the mapping does run and the result is empty.
        for host in ["\u{200b}", "\u{ad}"] {
            assert_eq!(
                to_unicode(host.as_bytes()),
                Ok(host.to_string()),
                "{host:?} must pass through the U-label direction"
            );
            assert_eq!(
                to_ascii(host.as_bytes()),
                Err(CURLcode::UrlMalformat),
                "{host:?} must fail the A-label direction"
            );
        }
    }

    // UTF-8 validation -- rejected, never repaired

    #[test]
    fn ill_formed_utf8_is_rejected_in_both_directions() {
        // A lone continuation-range byte, a truncated two-byte sequence, a
        // three-byte sequence with an invalid continuation, a bare
        // continuation byte, and an over-long encoding of U+0000.
        for bad in [
            &b"\xff"[..],
            &b"\xc3"[..],
            &b"\xe2\x28\xa1"[..],
            &b"\x80"[..],
            &b"\xc0\x80"[..],
            &b"host\xed\xa0\x80.example"[..],
            &b"invalid-utf8-\xe2\x90.local"[..],
        ] {
            assert_eq!(
                to_ascii(bad),
                Err(CURLcode::UrlMalformat),
                "to_ascii must reject {bad:?}"
            );
            assert_eq!(
                to_unicode(bad),
                Err(CURLcode::UrlMalformat),
                "to_unicode must reject {bad:?}"
            );
        }
    }

    #[test]
    fn ill_formed_utf8_is_not_silently_repaired() {
        // The failure mode that matters is not "returns an error" but
        // "does not invent a replacement character". If a lossy conversion
        // ever crept in, the result would be Ok and would contain U+FFFD.
        match to_ascii(b"invalid-utf8-\xe2\x90.local") {
            Err(CURLcode::UrlMalformat) => {}
            other => panic!("expected UrlMalformat, got {other:?}"),
        }
        assert!(validated_utf8(b"\xe2\x90").is_err());
        assert_eq!(validated_utf8(b"ok"), Ok("ok"));
    }

    // The transitional fallback -- lib/idn.c:263-265

    #[test]
    fn the_transitional_fallback_is_reached_and_is_necessary() {
        // ZWNJ and ZWJ are CONTEXTJ characters. In `a<ZWNJ>b` neither sits
        // in a permitted joining context, so non-transitional UTS-46
        // rejects the label outright; transitional processing removes the
        // character and the label becomes plain `ab`.
        //
        // Both halves are asserted, so this documents that the fallback is
        // load-bearing rather than decorative: without it these inputs would
        // fail, and the C oracle accepts them as `ab.se`.
        for host in ["a\u{200c}b.se", "a\u{200d}b.se"] {
            assert!(
                uts46_to_ascii(host).is_none(),
                "{host:?} must fail non-transitional processing"
            );
            assert_eq!(
                to_ascii(host.as_bytes()),
                Ok("ab.se".to_string()),
                "{host:?} must succeed through the transitional fallback"
            );
        }
    }

    #[test]
    fn the_first_attempt_is_non_transitional() {
        // The converse of the test above: for the other three deviation
        // characters the non-transitional attempt succeeds, so the fallback
        // is never reached and the deviation character survives into the
        // A-label. If the order were reversed, U+00DF would become "ss" and
        // tests/data/test165's second host would come out as
        // `www.grosse.de`.
        assert_eq!(
            to_ascii("\u{df}.de".as_bytes()),
            Ok("xn--zca.de".to_string())
        );
        assert_eq!(
            to_ascii("\u{3c2}.gr".as_bytes()),
            Ok("xn--3xa.gr".to_string())
        );
        assert_eq!(
            to_ascii("\u{1e9e}.de".as_bytes()),
            Ok("xn--zca.de".to_string())
        );
    }

    #[test]
    fn transitional_map_reproduces_the_crate_authors_mapping() {
        // idna-1.1.0/src/deprecated.rs:25-62.
        assert_eq!(transitional_map("\u{df}"), "ss");
        assert_eq!(transitional_map("\u{1e9e}"), "ss");
        assert_eq!(transitional_map("\u{3c2}"), "\u{3c3}");
        assert_eq!(transitional_map("\u{200c}"), "");
        assert_eq!(transitional_map("\u{200d}"), "");
        assert_eq!(transitional_map("stra\u{df}e.de"), "strasse.de");
        // Everything else is passed through untouched, and untouched input
        // is returned borrowed rather than copied.
        let untouched = transitional_map("example.com");
        assert_eq!(untouched, "example.com");
        assert!(matches!(untouched, Cow::Borrowed(_)));
        assert!(matches!(transitional_map("\u{df}.de"), Cow::Owned(_)));
    }

    #[test]
    fn is_deviation_covers_exactly_the_deviation_characters() {
        for c in ['\u{df}', '\u{1e9e}', '\u{3c2}', '\u{200c}', '\u{200d}'] {
            assert!(is_deviation(c), "{c:?} is a deviation character");
        }
        for c in [
            'a', '\u{e5}', '\u{3c3}', '\u{3a3}', '\u{200b}', '.', '-', '\u{ad}',
        ] {
            assert!(!is_deviation(c), "{c:?} is not a deviation character");
        }
    }

    // The UTS-46 parameters, each pinned by the measurement that chose it

    #[test]
    fn the_deny_list_is_empty_so_std3_characters_survive() {
        // Oracle: `_<U+00E5>.se` converts to `xn--_-2fa.se`. The variant
        // AsciiDenyList::STD3 would reject the underscore, and
        // AsciiDenyList::URL would reject a further nine characters; in both
        // cases narrowing the set of hostnames curl accepts.
        assert_eq!(
            to_ascii("_\u{e5}.se".as_bytes()),
            Ok("xn--_-2fa.se".to_string())
        );
    }

    #[test]
    fn hyphen_positions_are_checked_in_the_a_label_direction() {
        // Oracle: all four of these yield CURLUE_BAD_HOSTNAME. Only
        // Hyphens::Check reproduces all four.
        for host in ["-\u{e5}.se", "\u{e5}-.se", "a\u{e5}--b.se", "\u{e5}.-.se"]
        {
            assert_eq!(
                to_ascii(host.as_bytes()),
                Err(CURLcode::UrlMalformat),
                "{host:?} must be rejected"
            );
        }
    }

    #[test]
    fn hyphen_positions_are_not_checked_in_the_u_label_direction() {
        // Oracle: the conversion API leaves all of these alone. This is the
        // asymmetry with the test above, and it is faithful --
        // idn2_to_unicode_8z8z validates almost nothing. `foo--bar.example`
        // in particular is an ordinary real-world name that Hyphens::Check
        // would reject.
        for host in ["foo--bar.example", "-foo.se", "foo-.se", "a.-.se"] {
            assert_eq!(
                to_unicode(host.as_bytes()),
                Ok(host.to_string()),
                "{host:?} must pass through unchanged"
            );
        }
    }

    #[test]
    fn the_dns_length_rule_is_verified_but_tolerates_the_root_dot() {
        // A 51-character label converts to a 61-byte A-label: accepted.
        let ok = format!("\u{e5}{}.se", "a".repeat(50));
        assert!(to_ascii(ok.as_bytes()).is_ok());

        // Five 49-character labels exceed the 253-byte name bound.
        let label = format!("\u{e5}{}", "a".repeat(48));
        let too_long = format!("{label}.{label}.{label}.{label}.{label}.se");
        assert_eq!(to_ascii(too_long.as_bytes()), Err(CURLcode::UrlMalformat));

        // A single label over 63 bytes once encoded.
        let long_label = format!("\u{e5}{}.se", "a".repeat(80));
        assert_eq!(
            to_ascii(long_label.as_bytes()),
            Err(CURLcode::UrlMalformat)
        );

        // The trailing root dot survives, which is what rules out
        // DnsLength::Verify: the oracle converts the rooted host
        // `<U+00E5><U+00E4><U+00F6>.se.` to `xn--4cab6c.se.`.
        assert_eq!(
            to_ascii("\u{e5}\u{e4}\u{f6}.se.".as_bytes()),
            Ok("xn--4cab6c.se.".to_string())
        );
        assert_eq!(to_ascii("\u{e5}.".as_bytes()), Ok("xn--5ca.".to_string()));
    }

    #[test]
    fn normalization_form_c_is_applied_by_the_mapping_stage() {
        // lib/idn.c:253 passes IDN2_NFC_INPUT. Decomposed `a` + U+030A
        // COMBINING RING ABOVE and precomposed U+00E5 must agree, which
        // they only do if NFC runs. No separate normalization step is
        // therefore needed.
        assert_eq!(
            to_ascii("a\u{30a}.se".as_bytes()),
            to_ascii("\u{e5}.se".as_bytes())
        );
        assert_eq!(
            to_ascii("\u{e5}.se".as_bytes()),
            Ok("xn--5ca.se".to_string())
        );
    }

    #[test]
    fn case_is_folded_before_conversion() {
        // Oracle: `<U+00C4><U+00D6>.se` converts to `xn--4ca0b.se`.
        assert_eq!(
            to_ascii("\u{c4}\u{d6}.se".as_bytes()),
            Ok("xn--4ca0b.se".to_string())
        );
    }

    // Failure paths in the U-label direction

    #[test]
    fn invalid_punycode_is_rejected_by_to_unicode() {
        // Oracle: every one of these yields CURLUE_BAD_HOSTNAME, which is
        // the documented contract of CURLU_PUNY2IDN
        // (docs/libcurl/curl_url_get.md:104-114).
        for host in ["xn--.se", "xn---.se", "xn--zzzzzz.se", "xn--0.se"] {
            assert_eq!(
                to_unicode(host.as_bytes()),
                Err(CURLcode::UrlMalformat),
                "{host:?} must be rejected"
            );
        }
    }

    #[test]
    fn to_unicode_never_invents_a_replacement_character() {
        // This used to guard against Uts46::to_unicode's failure mode, which
        // returns a lossy string alongside the error verdict -- a string the
        // crate documents as unusable in a network protocol. That mode is
        // gone with the function: a per-label punycode decode either produces
        // the label or reports an error, and has no lossy path to leak. What
        // remains worth asserting is that U+FFFD never appears in an output
        // unless the caller put it in the input.
        for host in [
            "xn--zzzzzz.se",
            "a\u{200c}b.se",
            "xn--a.se",
            "xn--ab-.se",
            "\u{e5}\u{e4}\u{f6}.se",
            "example.com",
        ] {
            if let Ok(value) = to_unicode(host.as_bytes()) {
                assert!(
                    !value.contains('\u{fffd}'),
                    "{host:?} produced a replacement character: {value:?}"
                );
            }
        }
        // And an input that does carry one keeps it, verbatim, because a
        // non-ACE label is copied rather than validated.
        assert_eq!(
            to_unicode("\u{fffd}.se".as_bytes()),
            Ok("\u{fffd}.se".to_string())
        );
    }

    // Totality: nothing here may panic, whatever arrives

    #[test]
    fn no_input_causes_a_panic() {
        let long_label = "a".repeat(300);
        let long_unicode_label = "\u{e5}".repeat(300);
        let many_dots = ".".repeat(64);
        let deep = vec!["\u{e5}"; 100].join(".");
        let inputs: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b".".to_vec(),
            b"..".to_vec(),
            b"example.com.".to_vec(),
            b"a..b".to_vec(),
            "\u{e5}..b".as_bytes().to_vec(),
            b"-".to_vec(),
            b"-a.se".to_vec(),
            b"a-.se".to_vec(),
            b"--".to_vec(),
            b"1234567890".to_vec(),
            b"123.456.789.0".to_vec(),
            b"[::1]".to_vec(),
            b"xn--".to_vec(),
            b"xn--xn--xn--".to_vec(),
            long_label.into_bytes(),
            long_unicode_label.into_bytes(),
            many_dots.into_bytes(),
            deep.into_bytes(),
            "\u{1f600}.se".as_bytes().to_vec(),
            "\u{fffd}.se".as_bytes().to_vec(),
            "\u{0}.se".as_bytes().to_vec(),
            vec![0x80; 16],
            vec![0xff; 16],
            (0u8..=0xff).collect(),
        ];
        for input in &inputs {
            // The only requirement is that both calls return. Neither
            // result is asserted, because the point is totality: a panic
            // here could unwind toward a C caller through curl-rs-ffi.
            let _ = to_ascii(input);
            let _ = to_unicode(input);
            let _ = is_ascii_name(Some(input));
        }
    }

    #[test]
    fn every_malformed_host_is_reported_as_url_malformat() {
        // UrlMalformat is the only code a *malformed host* produces here. The
        // one other reachable code is CURLE_OUT_OF_MEMORY, from the single
        // reservation in idn_to_unicode, which reproduces lib/idn.c:288 and
        // cannot be provoked by any of the inputs below. CURLE_NOT_BUILT_IN
        // stays unreachable, because there is no runtime version check to
        // fail. This asserts it over every failing input the suite knows
        // about.
        let failing: Vec<Vec<u8>> = vec![
            b"\xff".to_vec(),
            b"invalid-utf8-\xe2\x90.local".to_vec(),
            "\u{200b}".as_bytes().to_vec(),
            "\u{200b}\u{200c}".as_bytes().to_vec(),
            "-\u{e5}.se".as_bytes().to_vec(),
            b"xn--zzzzzz.se".to_vec(),
            format!("\u{e5}{}.se", "a".repeat(80)).into_bytes(),
        ];
        for input in &failing {
            for outcome in [to_ascii(input), to_unicode(input)] {
                if let Err(code) = outcome {
                    assert_eq!(
                        code,
                        CURLcode::UrlMalformat,
                        "unexpected code for {input:?}"
                    );
                    assert_ne!(code, CURLcode::OutOfMemory);
                    assert_ne!(code, CURLcode::NotBuiltIn);
                }
            }
        }
    }

    // Parity with the C oracle on the cases that used to diverge

    #[test]
    fn an_empty_label_converts_rather_than_failing_the_length_rule() {
        // Measured, all six rows: the oracle converts `<U+00E5>..b` to
        // `xn--5ca..b` and leaves the rest alone, because libidn2's lookup
        // checks only the 63- and 253-byte bounds. idna's own
        // verify_dns_length (idna-1.1.0/src/uts46.rs:463-487) additionally
        // counts an empty label as a violation, which is the one clause
        // dns_bounds_ok drops.
        for (host, expected) in [
            ("\u{e5}..b", "xn--5ca..b"),
            (".se", ".se"),
            ("a..b", "a..b"),
            ("\u{e5}.se..", "xn--5ca.se.."),
            (".", "."),
            ("...", "..."),
        ] {
            assert_eq!(
                to_ascii(host.as_bytes()),
                Ok(expected.to_string()),
                "to_ascii({host:?})"
            );
        }
        // The U-label direction never had a DnsLength parameter to get
        // wrong, and agrees.
        assert_eq!(to_unicode(b"a..b"), Ok("a..b".to_string()));
        assert_eq!(to_unicode(b"."), Ok(".".to_string()));
    }

    #[test]
    fn dns_bounds_ok_is_verify_dns_length_without_the_empty_label_clause() {
        // The three clauses, each at its boundary. Bytes, because an A-label
        // is ASCII.
        assert!(dns_bounds_ok(&"a".repeat(MAX_LABEL)));
        assert!(!dns_bounds_ok(&"a".repeat(MAX_LABEL + 1)));
        let name = |total: usize| {
            let mut out = String::new();
            while out.len() < total {
                let chunk = (total - out.len()).min(50);
                out.push_str(&"a".repeat(chunk));
                out.push('.');
            }
            out.truncate(total);
            if out.ends_with('.') {
                out.pop();
                out.push('a');
            }
            out
        };
        assert!(dns_bounds_ok(&name(MAX_ALABEL_NAME)));
        assert!(!dns_bounds_ok(&name(MAX_ALABEL_NAME + 1)));
        // One trailing dot is discounted, so 254 bytes ending in a dot pass
        // and 255 do not. Measured against the oracle at both boundaries.
        assert!(dns_bounds_ok(&format!("{}.", name(MAX_ALABEL_NAME))));
        assert!(!dns_bounds_ok(&format!("{}.", name(MAX_ALABEL_NAME + 1))));
        // And the dropped clause: empty labels are accepted anywhere.
        for host in ["", ".", "..", "a..b", "xn--5ca..b", ".a", "a."] {
            assert!(dns_bounds_ok(host), "{host:?} must satisfy the bounds");
        }
    }

    // The one surviving divergence

    #[test]
    fn divergence_a_mixed_direction_label_is_rejected() {
        // THE ONE DIVERGENCE FROM THE ORACLE THAT REMAINS. Measured: the host
        // `<U+05E9><U+05DC><U+05D5><U+05DD>abc.se` converts to
        // `xn--abc-9pe8ah5f.se`, its A-label form converts to itself, and
        // `<U+00E5><U+05E9>.se` converts to `xn--5ca28w.se`. Each label mixes
        // writing directions, which violates the conditions RFC 5893 places
        // on a bidi label, and idna 1.1.0 applies UTS-46 CheckBidi to every
        // name: `idna-1.1.0/src/uts46.rs:17` states it is "Always _true_;
        // cannot be configured", and Uts46::to_ascii exposes no knob for it.
        // Cargo.toml freezes idna at exactly 1.1.0 under AAP section 0.5.1,
        // so this is irreducible rather than unfinished. Stricter, and
        // unreachable from the fixture corpus: no `tests/data` fixture
        // carries a right-to-left hostname.
        for host in [
            "\u{5e9}\u{5dc}\u{5d5}\u{5dd}abc.se",
            "xn--abc-9pe8ah5f.se",
            "\u{e5}\u{5e9}.se",
        ] {
            assert_eq!(
                to_ascii(host.as_bytes()),
                Err(CURLcode::UrlMalformat),
                "{host:?} is the CheckBidi divergence"
            );
        }
        // The U-label direction is unaffected, because it no longer runs
        // UTS-46 at all: both spellings decode exactly as the oracle does.
        assert_eq!(
            to_unicode(b"xn--abc-9pe8ah5f.se"),
            Ok("\u{5e9}\u{5dc}\u{5d5}\u{5dd}abc.se".to_string())
        );
        // The divergence is confined to the mixed-direction case. A
        // well-formed RTL name satisfies CheckBidi and converts to the same
        // A-label the oracle produces, so this is a narrower divergence
        // than "bidi names are rejected".
        assert_eq!(
            to_ascii("\u{5e9}\u{5dc}\u{5d5}\u{5dd}.se".as_bytes()),
            Ok("xn--9dbne9b.se".to_string())
        );
        assert_eq!(
            to_unicode(b"xn--9dbne9b.se"),
            Ok("\u{5e9}\u{5dc}\u{5d5}\u{5dd}.se".to_string())
        );
    }

    #[test]
    fn the_u_label_direction_preserves_case_and_maps_nothing() {
        // Measured: the oracle returns `EXAMPLE.COM` and `Foo.Example.COM`
        // unchanged, because idn2_to_unicode_8z8z rewrites only labels
        // carrying an `xn--` prefix. UTS-46 ToUnicode folded every label,
        // which is why this was a divergence.
        assert_eq!(to_unicode(b"EXAMPLE.COM"), Ok("EXAMPLE.COM".to_string()));
        assert_eq!(
            to_unicode(b"Foo.Example.COM"),
            Ok("Foo.Example.COM".to_string())
        );
        // Inside a decoded label the punycode decoder keeps the case of the
        // basic code points too: `xn--BCHER-kva.de` is `B<U+00FC>CHER.de`,
        // not `b<U+00FC>cher.de`, exactly as the oracle has it.
        assert_eq!(
            to_unicode(b"xn--BCHER-kva.de"),
            Ok("B\u{fc}CHER.de".to_string())
        );
        assert_eq!(
            to_unicode(b"xn--bcher-kva.de"),
            Ok("b\u{fc}cher.de".to_string())
        );
        // The A-label direction folds case in both implementations.
        assert_eq!(to_ascii(b"EXAMPLE.COM"), Ok("example.com".to_string()));
    }

    #[test]
    fn a_control_character_payload_decodes_exactly_as_the_oracle_does() {
        // Measured: `xn--a.se` decodes to the bytes C2 80 2E 73 65, i.e.
        // U+0080 followed by `.se` -- a C1 control character presented as a
        // hostname label. libidn2's conversion entry point is a bare punycode
        // decode with no validity check, so it emits whatever the payload
        // decodes to, and this module now does the same. UTS-46 ToUnicode
        // classified U+0080 as disallowed and rejected it, which was the
        // divergence.
        assert_eq!(to_unicode(b"xn--a.se"), Ok("\u{80}.se".to_string()));
        assert_eq!(to_unicode(b"xn--a"), Ok("\u{80}".to_string()));
        // The prefix match is case-insensitive and the remaining labels are
        // copied verbatim, so the suffix keeps its case.
        assert_eq!(to_unicode(b"XN--A.SE"), Ok("\u{80}.SE".to_string()));
        // The A-label direction still refuses it, in both implementations:
        // the oracle answers IDN2_INVALID_NONTRANSITIONAL.
        assert_eq!(to_ascii(b"xn--a.se"), Err(CURLcode::UrlMalformat));
    }

    #[test]
    fn the_u_label_direction_bounds_the_decoded_length_in_code_points() {
        // Measured, and every row is a boundary. The bound applies to the
        // decoded result rather than the input, and counts code points rather
        // than bytes -- which is why replacing Uts46::to_unicode, a function
        // with no DnsLength parameter at all, needed the rule spelled out.

        // A 64-byte ASCII label is IDN2_TOO_BIG_LABEL in both directions;
        // 63 converts.
        let long = format!("{}.se", "a".repeat(MAX_LABEL + 1));
        assert_eq!(to_unicode(long.as_bytes()), Err(CURLcode::UrlMalformat));
        assert_eq!(to_ascii(long.as_bytes()), Err(CURLcode::UrlMalformat));
        let ok = format!("{}.se", "a".repeat(MAX_LABEL));
        assert_eq!(to_unicode(ok.as_bytes()), Ok(ok.clone()));

        // Code points, not bytes: 63 U+00E5 is 126 bytes and converts, 64 is
        // IDN2_TOO_BIG_LABEL.
        let wide_ok = format!("{}.se", "\u{e5}".repeat(MAX_LABEL));
        assert_eq!(to_unicode(wide_ok.as_bytes()), Ok(wide_ok.clone()));
        let wide_bad = format!("{}.se", "\u{e5}".repeat(MAX_LABEL + 1));
        assert_eq!(
            to_unicode(wide_bad.as_bytes()),
            Err(CURLcode::UrlMalformat)
        );

        // The decoded length is what counts, not the input's: `xn--` plus
        // sixty `a` is a 64-byte input label and decodes to sixty U+0080.
        let sixty = format!("xn--{}.se", "a".repeat(60));
        assert_eq!(
            to_unicode(sixty.as_bytes()),
            Ok(format!("{}.se", "\u{80}".repeat(60)))
        );

        // The name bound is 255 code points with separators counted and no
        // root-dot discount: 63 A-labels of `<U+00E5><U+00E4><U+00F6>` plus
        // `se` decode to 254 code points and convert, 64 exceed it. Note the
        // 254-code-point result is 443 bytes, so a byte count would refuse it.
        let within = format!("{}.se", ["xn--4cab6c"; 63].join("."));
        let decoded = to_unicode(within.as_bytes()).expect("254 code points");
        assert_eq!(decoded.chars().count(), 254);
        assert_eq!(decoded.len(), 443);
        let beyond = format!("{}.se", ["xn--4cab6c"; 64].join("."));
        assert_eq!(to_unicode(beyond.as_bytes()), Err(CURLcode::UrlMalformat));

        // And the input is not bounded: 25 A-labels are 277 input bytes and
        // decode to 102 code points, which the oracle accepts.
        let long_input = format!("{}.se", ["xn--4cab6c"; 25].join("."));
        assert_eq!(long_input.len(), 277);
        assert_eq!(
            to_unicode(long_input.as_bytes()).map(|out| out.chars().count()),
            Ok(102)
        );
    }

    #[test]
    fn an_ace_label_that_decodes_to_pure_ascii_is_bad_input() {
        // Measured: all four are IDN2_PUNYCODE_BAD_INPUT, and all four decode
        // successfully as far as RFC 3492 is concerned -- to `ab`, `abc`, `-`
        // and `AB`. What they have in common is that nothing was inserted, so
        // the label was never a legitimate A-label. RFC 5891 section 4.2 makes
        // the same point: an A-label must decode to a U-label.
        for host in ["xn--ab-.se", "xn--abc-.se", "xn----.se", "xn--AB-.se"] {
            assert_eq!(
                to_unicode(host.as_bytes()),
                Err(CURLcode::UrlMalformat),
                "{host:?} decodes to pure ASCII and must be refused"
            );
        }
        // An empty payload is refused by the same rule rather than passed
        // through as the label `xn--`, which is what the oracle does too.
        for host in ["xn--.se", "xn--", "xn--."] {
            assert_eq!(
                to_unicode(host.as_bytes()),
                Err(CURLcode::UrlMalformat),
                "{host:?} must be refused"
            );
        }
        // One inserted character is enough, and it need not be the whole
        // label: `xn--abc-a` is `<U+0080>abc`.
        assert_eq!(to_unicode(b"xn--abc-a.se"), Ok("\u{80}abc.se".to_string()));
    }

    #[test]
    fn ace_payload_matches_the_prefix_exactly_and_case_insensitively() {
        assert_eq!(ace_payload("xn--4cab6c"), Some("4cab6c"));
        assert_eq!(ace_payload("XN--4CAB6C"), Some("4CAB6C"));
        assert_eq!(ace_payload("Xn--4cab6c"), Some("4cab6c"));
        assert_eq!(ace_payload("xN--4cab6c"), Some("4cab6c"));
        assert_eq!(ace_payload("xn--"), Some(""));
        // Not the prefix: too short, or the wrong number of hyphens.
        for label in ["xn-", "xn", "x", "", "xn-4cab6c", "xn4cab6c", "-xn--a"] {
            assert_eq!(ace_payload(label), None, "{label:?} is not an A-label");
        }
        // Measured: the oracle copies `xn-.se` and `xn.se` through untouched.
        assert_eq!(to_unicode(b"xn-.se"), Ok("xn-.se".to_string()));
        assert_eq!(to_unicode(b"xn.se"), Ok("xn.se".to_string()));
    }

    #[test]
    fn non_ace_labels_are_copied_verbatim_whatever_they_contain() {
        // idn2_to_unicode_8z8z applies no mapping, no case folding, no
        // normalization and no validity check to a label without the prefix.
        // Every row is measured: the oracle returns each of these unchanged.
        for host in [
            "a\u{200c}b.se",
            "a\u{200d}b.se",
            "a\u{30a}.se",
            "\u{c5}\u{c4}\u{d6}.se",
            "\u{80}.se",
            "\u{7f}.se",
            "a b.se",
            "a@b.se",
            "1234567890",
            "[::1]",
            "\u{1f600}.se",
            "\u{df}.de",
            "\u{131}.se",
        ] {
            assert_eq!(
                to_unicode(host.as_bytes()),
                Ok(host.to_string()),
                "{host:?} must be copied verbatim"
            );
        }
    }

    #[test]
    fn an_interior_nul_is_not_a_c_string_terminator() {
        // The two corpus comparisons that differ for a reason that is not a
        // behavioural difference. libidn2 takes a `const char *`, so for the
        // host `<U+0000>.se` it sees an empty string: the A direction ends up
        // with a zero-length result that lib/idn.c:317-320 rejects, and the U
        // direction returns "". This module takes `&[u8]` and converts all
        // four bytes, which is the answer the slice signature demands.
        //
        // Unobservable for the real callers -- hosts arrive from
        // NUL-terminated storage, so an interior NUL cannot reach here -- and
        // truncating at the NUL in order to match the measurement artefact
        // would be a defect rather than fidelity. U+0000 is
        // disallowed_STD3_valid, so with AsciiDenyList::EMPTY it survives
        // even the A-label direction.
        assert_eq!(to_unicode(b"\0.se"), Ok("\0.se".to_string()));
        assert_eq!(to_ascii(b"\0.se"), Ok("\0.se".to_string()));
    }

    #[test]
    fn numeric_hosts_pass_through_untouched() {
        // The two of seven oracle comparisons that are NOT this module's
        // behaviour. curl 8.19.0-DEV returns `73.150.2.210` for the host
        // `1234567890` in both flag directions, because `curl_url_set` reads
        // the label as the 32-bit integer 0x499602D2 and re-spells it in
        // dotted-quad form before any IDN code runs. `lib/idn.c` has no part
        // in it: the label is ASCII, so the `lib/urlapi.c:1401-1420` gate
        // never reaches a conversion, and calling one anyway is a no-op.
        assert!(is_ascii_name(Some(b"1234567890")));
        assert_eq!(to_ascii(b"1234567890"), Ok("1234567890".to_string()));
        assert_eq!(to_unicode(b"1234567890"), Ok("1234567890".to_string()));
        // The dotted-quad spelling is never synthesised here; the sibling
        // `super` module owns that normalization.
        for host in [&b"1234567890"[..], &b"123.456.789.0"[..]] {
            // Both directions must SUCCEED and return the input verbatim.
            // Asserting the whole `Result` rather than inspecting an `Ok` arm
            // matters: a version that skipped the `Err` case would pass
            // vacuously if a future change started rejecting these hosts, and
            // "is not rewritten" is exactly the claim being made. Measured:
            // both hosts yield `Ok` with the identical string in both
            // directions.
            let expected = Ok(String::from_utf8_lossy(host).into_owned());
            assert_eq!(to_ascii(host), expected, "to_ascii rewrote {host:?}");
            assert_eq!(
                to_unicode(host),
                expected,
                "to_unicode rewrote {host:?}"
            );
        }
    }

    // Capability reporting

    #[test]
    fn idn_is_available_and_the_predicate_is_total() {
        // The Rust counterpart of idn_present (lib/version.c:407-416). It
        // must be callable repeatedly without panicking, because
        // `curl --version` is the first thing the test harness runs.
        assert!(available());
        assert!(available());
        assert!(available());
    }

    #[test]
    fn the_version_string_is_the_idna_version_not_a_libidn2_version() {
        assert_eq!(version_string(), Some("1.1.0"));
        let reported = version_string().unwrap_or_default();
        assert!(
            !reported.contains("libidn"),
            "the banner must never claim libidn2"
        );
        // The literal has to agree with the exact pin in Cargo.toml, which
        // crate::version repeats for the Features: banner.
        assert_eq!(IDNA_VERSION, "1.1.0");
    }

    #[test]
    fn availability_and_the_conversions_agree() {
        // If the predicate says the capability is present, the conversions
        // must actually work. This is the coupling that keeps the
        // `Features:` banner truthful: over-reporting makes a gated fixture
        // run and fail instead of skipping.
        assert!(available());
        assert!(to_ascii("\u{e5}\u{e4}\u{f6}.se".as_bytes()).is_ok());
        assert!(to_unicode(AAO_SE_ALABEL.as_bytes()).is_ok());
    }
}
